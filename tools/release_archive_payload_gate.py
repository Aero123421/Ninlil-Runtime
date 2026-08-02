#!/usr/bin/env python3
"""Release archive payload gate — validate generated tar/zip, not only the tree.

Fail-closed checks on **expanded** source archives (and on freshly built
worktree archives):

  - required legal/security/docs payload present
  - exact SHA-256 for LICENSE / NOTICE / THIRD-PARTY-NOTICES.md / SECURITY.md
  - public README / install / release / traceability documents present
  - compatibility-matrix.json + dependency-inventory.json present once
  - no symlinks, no absolute members, no path traversal (``..``)
  - canonical tar/gzip/zip metadata (0644 data / 0755 shebang scripts) and
    full tar↔zip path/byte equivalence
  - every text member has zero hits of the forbidden-vocabulary denylist
    (case/space/typo family of the banned k+guard token; same authority as
    ``release_forbidden_vocabulary_gate``)
  - closed required-manifest inventory (every required path present; no
    duplicate required members)
  - HIL evidence layer payload (``spec/hil/**``, ``docs/hil-evidence.md``,
    ``tools/ninlil_hil/**``, ``ports/esp-idf/storage/hil/host_powercut_runner.py``
    + storage HIL bridge docs) present with closed exact set; no HIL_VERIFIED
    promotion claim required or asserted
  - optional two-run reproducibility of freshly built archives
  - clean-room CTest allowlist includes HIL evidence/runner self-tests

Usage:
  check [--tar PATH --zip PATH --prefix NAME]
  self-test
  build-and-check [--out-dir DIR] [--two-run]
  cleanroom
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile
from typing import Callable, Iterable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Import shared denylist (fragment-assembled; alnum-bounded).
sys.path.insert(0, str(REPO_ROOT / "tools"))
from release_forbidden_vocabulary_gate import (  # noqa: E402
    FORBIDDEN_RE,
    SKIP_SUFFIXES as VOCAB_SKIP_SUFFIXES,
)

# Canonical legal/security pins (must match repository root files).
LICENSE_SHA256 = (
    "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
)
NOTICE_SHA256 = (
    "7fe5c13ffc658808747eb361dd14ed17ea912a5e5fe4d8f7a5405bfbb6185319"
)
THIRD_PARTY_NOTICES_SHA256 = (
    "b0007162a8c8dcf322698d63a74be1047e44ca17fb74c690a568dbea95576ac1"
)
SECURITY_SHA256 = (
    "b634aad6c4fdc87a4d3ca8d0bb474240d079a4a0e320dafd2159b43d929a7589"
)

# Closed required inventory relative to archive prefix (no leading slash).
REQUIRED_HASHED_FILES: dict[str, str] = {
    "LICENSE": LICENSE_SHA256,
    "NOTICE": NOTICE_SHA256,
    "THIRD-PARTY-NOTICES.md": THIRD_PARTY_NOTICES_SHA256,
    "SECURITY.md": SECURITY_SHA256,
}
REQUIRED_EXISTENCE_FILES: tuple[str, ...] = (
    "CMakeLists.txt",
    "README.md",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "compatibility-matrix.json",
    "dependency-inventory.json",
    "requirements-traceability.yaml",
    "cmake/NinlilConfig.cmake.in",
    "docs/README.md",
    "docs/host-runtime-sdk.md",
    "docs/releasing.md",
    "docs/sdk-distribution-manifest.md",
    "tests/cmake/installed_host_runtime_consumer/CMakeLists.txt",
    "tests/cmake/installed_host_runtime_consumer/consumer.c",
    "tests/cmake/installed_host_runtime_consumer/memory_storage.c",
    "tests/cmake/installed_host_runtime_consumer/memory_storage.h",
)
REQUIRED_DIRS: tuple[str, ...] = ("docs",)
CANONICAL_FILE_MODE = 0o644
CANONICAL_EXECUTABLE_MODE = 0o755
CANONICAL_DIR_MODE = 0o755
CANONICAL_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
CANONICAL_GZIP_XFL = 2  # maximum-compression marker
CANONICAL_GZIP_OS = 255  # platform-neutral / unknown
CANONICAL_ZIP_VERSION = 20  # DEFLATE
ARCHIVE_PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")

# HIL evidence layer (release archive required payload). Exact closed set is
# discovered from the live tree at capture/check time so concurrent root
# updates to schemas/runner/docs are picked up. Presence is required; this
# does *not* claim HIL_VERIFIED or physical HIL execution.
HIL_FIXED_FILES: tuple[str, ...] = (
    "docs/hil-evidence.md",
    "ports/esp-idf/storage/hil/host_powercut_runner.py",
    "ports/esp-idf/storage/hil/README.md",
    "ports/esp-idf/storage/hil/run_hil_scenarios.md",
)
HIL_DIR_PREFIXES: tuple[str, ...] = (
    "spec/hil/",
    "tools/ninlil_hil/",
    "ports/esp-idf/storage/hil/",
)
HIL_MIN_SCHEMA_FILES = 6
HIL_MIN_TOOL_PY_FILES = 6

# Documented denylist intent is assembled from fragments so this tracked
# source never embeds a contiguous forbidden token (archive scan would RED).
# Runtime authority is FORBIDDEN_RE (alnum-bounded; same as vocabulary gate).
_K = "k"
_GUARD = "guard"
_TYPO_TAIL = "gurad"
DENYLIST_DOC = (
    f"(?i){_K}" + r"\s*[-_ ]?" + _GUARD + f"|{_K}{_TYPO_TAIL}"
)

# Always force these release-authority tools into worktree archives even when
# still untracked, so untracked exclusion cannot false-green the denylist.
FORCE_ARCHIVE_RELS = (
    "tools/release_archive_payload_gate.py",
    "tools/release_forbidden_vocabulary_gate.py",
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def require_git_release_source(source: str) -> None:
    """Bind build-from-git to immutable commit-tree bytes."""
    if source != "git":
        fail(
            "build-from-git requires --source git; worktree bytes "
            "cannot serve as commit-tree release authority"
        )


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_file_mode(data: bytes) -> int:
    """Content-derived mode: scripts remain runnable; all other files are 0644."""
    return CANONICAL_EXECUTABLE_MODE if data.startswith(b"#!") else CANONICAL_FILE_MODE


def canonical_zip_file_mode(data: bytes) -> int:
    return stat.S_IFREG | canonical_file_mode(data)


def compute_members_snapshot_sha(members: dict[str, bytes]) -> str:
    """Canonical content-addressed snapshot id for archive member maps.

    Path order is sorted; each entry contributes path, length, and content
    digest so the id is independent of dict insertion order and of archive
    container encoding (tar vs zip).
    """
    h = hashlib.sha256()
    h.update(b"ninlil-archive-content-snapshot-v1\n")
    for rel in sorted(members.keys()):
        data = members[rel]
        h.update(rel.encode("utf-8", "surrogateescape"))
        h.update(b"\0")
        h.update(len(data).to_bytes(8, "little"))
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()


class ArchiveContentSnapshot:
    """Immutable captured archive input (manifest + file bytes).

    Two-run reproducibility must pack *this* object twice — never re-read a
    moving worktree between runs. Live-source drift after capture is a hard
    failure when re-verified, not a silent second tree compare.
    """

    __slots__ = ("members", "source_label", "snapshot_sha256")

    def __init__(self, members: dict[str, bytes], source_label: str) -> None:
        # Defensive copy: outer code cannot mutate our captured bytes later.
        self.members: dict[str, bytes] = {
            str(k): bytes(v) for k, v in members.items()
        }
        self.source_label = source_label
        self.snapshot_sha256 = compute_members_snapshot_sha(self.members)
        if len(self.members) < 1:
            fail("archive content snapshot is empty")

    def assert_intact(self, where: str = "snapshot") -> None:
        got = compute_members_snapshot_sha(self.members)
        if got != self.snapshot_sha256:
            fail(
                f"{where}: archive content snapshot was mutated after capture "
                f"(expected {self.snapshot_sha256}, got {got})"
            )

    def assert_matches_members(
        self, other: dict[str, bytes], where: str = "live source"
    ) -> None:
        other_sha = compute_members_snapshot_sha(other)
        if other_sha != self.snapshot_sha256:
            only_snap = sorted(set(self.members) - set(other))
            only_other = sorted(set(other) - set(self.members))
            changed = sorted(
                rel
                for rel in set(self.members) & set(other)
                if self.members[rel] != other[rel]
            )
            fail(
                f"{where} diverged from captured snapshot "
                f"snapshot_sha={self.snapshot_sha256} live_sha={other_sha} "
                f"only_in_snapshot={only_snap[:8]} only_in_live={only_other[:8]} "
                f"content_changed={changed[:8]}"
            )


def git_tracked_relpaths() -> list[str]:
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files", "-z"],
        check=False,
        capture_output=True,
    )
    if proc.returncode != 0:
        fail(f"git ls-files failed: {proc.stderr.decode('utf-8', 'replace')}")
    out: list[str] = []
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        out.append(raw.decode("utf-8", "surrogateescape"))
    if len(out) < 50:
        fail(f"tracked set unexpectedly small: {len(out)}")
    return out


def archive_member_relpaths() -> list[str]:
    """Tracked paths plus forced release-gate tools present on disk.

    Untracked exclusion of this gate must not yield a false-green archive.
    """
    rels = set(git_tracked_relpaths())
    for rel in FORCE_ARCHIVE_RELS:
        if (REPO_ROOT / rel).is_file():
            rels.add(rel)
    return sorted(rels)


def assert_gate_sources_denylist_clean() -> None:
    """scan_text_denylist on gate sources must be 0 (tracked-ready)."""
    for rel in FORCE_ARCHIVE_RELS:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        hits = scan_text_denylist(path.read_bytes(), rel)
        if hits:
            preview = "\n".join(hits[:10])
            fail(
                f"gate source denylist unclean (would RED once tracked):\n{preview}"
            )


def validate_archive_prefix(prefix: str) -> None:
    if not ARCHIVE_PREFIX_RE.fullmatch(prefix):
        fail(
            "archive prefix must be one portable path component containing "
            f"only ASCII letters, digits, '.', '_', '+', or '-': {prefix!r}"
        )


def normalize_member(name: str, prefix: str) -> str | None:
    """Return path relative to prefix, or None for the prefix directory itself."""
    validate_archive_prefix(prefix)
    if "\\" in name:
        fail(f"backslash archive member spelling forbidden: {name!r}")
    if name.startswith("/"):
        fail(f"absolute archive member forbidden: {name!r}")
    if name.startswith("./"):
        fail(f"non-canonical './' archive member spelling forbidden: {name!r}")
    if name in (prefix, prefix + "/"):
        return None
    parts = name.split("/")
    if any(p == ".." for p in parts):
        fail(f"path traversal in archive member forbidden: {name!r}")
    if any(p in ("", ".") for p in parts):
        fail(f"non-canonical archive member spelling forbidden: {name!r}")
    if parts[0] != prefix:
        fail(f"archive member outside prefix {prefix!r}: {name!r}")
    rel_parts = parts[1:]
    if not rel_parts:
        return None
    return "/".join(rel_parts)


def is_probably_text(data: bytes, rel: str) -> bool:
    suffix = pathlib.Path(rel).suffix.lower()
    if suffix in VOCAB_SKIP_SUFFIXES:
        return False
    if b"\0" in data[:8192]:
        return False
    return True


def scan_text_denylist(data: bytes, where: str) -> list[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if FORBIDDEN_RE.search(line):
            hits.append(f"{where}:{lineno}:{line.rstrip()[:160]}")
    return hits


def _is_hil_payload_path(rel: str) -> bool:
    if rel in HIL_FIXED_FILES:
        return True
    return any(rel.startswith(prefix) for prefix in HIL_DIR_PREFIXES)


def discover_hil_required_files(root: pathlib.Path = REPO_ROOT) -> list[str]:
    """Exact closed HIL payload paths from the live tree (latest concurrent bytes)."""
    paths: list[str] = []
    for rel in HIL_FIXED_FILES:
        path = root / rel
        if not path.is_file():
            fail(f"missing required HIL payload on disk: {rel}")
        paths.append(rel)

    for base in ("spec/hil", "tools/ninlil_hil"):
        directory = root / base
        if not directory.is_dir():
            fail(f"missing required HIL directory on disk: {base}/")
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            paths.append(path.relative_to(root).as_posix())

    # Dedup preserve order
    seen: set[str] = set()
    ordered: list[str] = []
    for rel in paths:
        if rel not in seen:
            seen.add(rel)
            ordered.append(rel)

    schemas = [
        p
        for p in ordered
        if p.startswith("spec/hil/") and p.endswith(".schema.json")
    ]
    tool_py = [
        p for p in ordered if p.startswith("tools/ninlil_hil/") and p.endswith(".py")
    ]
    if len(schemas) < HIL_MIN_SCHEMA_FILES:
        fail(
            f"HIL schema surface too small: {len(schemas)} < {HIL_MIN_SCHEMA_FILES} "
            f"under spec/hil/"
        )
    if len(tool_py) < HIL_MIN_TOOL_PY_FILES:
        fail(
            f"HIL tool surface too small: {len(tool_py)} < {HIL_MIN_TOOL_PY_FILES} "
            f"under tools/ninlil_hil/"
        )
    if "tools/ninlil_hil/selftest.py" not in ordered:
        fail("HIL tool surface missing tools/ninlil_hil/selftest.py")
    if "tools/ninlil_hil/runner.py" not in ordered:
        fail("HIL tool surface missing tools/ninlil_hil/runner.py")
    return ordered


def load_hil_payload_from_disk(root: pathlib.Path = REPO_ROOT) -> dict[str, bytes]:
    """Read latest HIL payload bytes (for snapshot capture / self-test fixtures)."""
    out: dict[str, bytes] = {}
    for rel in discover_hil_required_files(root):
        out[rel] = (root / rel).read_bytes()
        if len(out[rel]) == 0:
            fail(f"HIL payload file is empty on disk: {rel}")
    return out


def load_live_cmake_modules(root: pathlib.Path = REPO_ROOT) -> dict[str, bytes]:
    """Inject live cmake/*.cmake so concurrent untracked modules are in the archive.

    CMakeLists may ``include()`` modules that are still untracked during parallel
    root work; clean-room configure must see the same latest modules as the
    live tree without packing arbitrary untracked noise.
    """
    out: dict[str, bytes] = {}
    cmake_dir = root / "cmake"
    if not cmake_dir.is_dir():
        return out
    for path in sorted(cmake_dir.glob("*.cmake")):
        rel = f"cmake/{path.name}"
        out[rel] = path.read_bytes()
    return out


def load_live_source_overlays(root: pathlib.Path = REPO_ROOT) -> dict[str, bytes]:
    """Inject live source trees so concurrent untracked TUs are in the archive.

    Parallel workers may add sources under src/drivers/tests/ports that CMake
    already references; clean-room must pack those latest bytes without a full
    untracked noise sweep (no __pycache__, no build dirs).
    """
    out: dict[str, bytes] = {}
    for base in (
        "src",
        "drivers",
        "tests",
        "include",
        "ports",
        "examples",
        "spec",
        "docs",
        "tools",
        "cmake",
    ):
        directory = root / base
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file():
                continue
            if (
                "__pycache__" in path.parts
                or "managed_components" in path.parts
                or any(part.startswith("build") for part in path.parts)
                or path.name in {"sdkconfig", "sdkconfig.old", ".DS_Store"}
                or path.suffix
                in {
                    ".pyc",
                    ".o",
                    ".a",
                    ".so",
                    ".dylib",
                    ".elf",
                    ".bin",
                    ".map",
                    ".log",
                }
            ):
                continue
            rel = path.relative_to(root).as_posix()
            out[rel] = path.read_bytes()
    return out


def assert_hil_payload(
    members: dict[str, bytes],
    *,
    live_root: pathlib.Path = REPO_ROOT,
    content_authority: dict[str, bytes] | None = None,
) -> None:
    """Require exact closed HIL evidence set; optional content authority match.

    Path inventory is discovered from ``live_root`` at call time (latest
    concurrent schema/runner/docs set). When ``content_authority`` is set
    (self-test / snapshot check), each required path's bytes must match that
    authority map — detecting 改変. Production archive validate uses
    presence+closed-set only so concurrent live edits after packing do not
    false-red a correctly sealed archive.

    Does not claim physical HIL execution or HIL_VERIFIED promotion.
    """
    required = discover_hil_required_files(live_root)
    required_set = set(required)
    missing = [rel for rel in required if rel not in members]
    if missing:
        fail(f"archive missing required HIL payload entries: {missing}")

    extras = sorted(
        rel
        for rel in members
        if _is_hil_payload_path(rel)
        and rel not in required_set
        and "__pycache__" not in rel
        and not rel.endswith(".pyc")
    )
    if extras:
        fail(f"archive has unexpected extra HIL payload files: {extras}")

    for rel in required:
        data = members[rel]
        if len(data) == 0:
            fail(f"archive HIL payload is empty: {rel}")
        if content_authority is not None:
            if rel not in content_authority:
                fail(f"HIL content authority missing path: {rel}")
            if data != content_authority[rel]:
                fail(
                    f"archive HIL payload modified vs content authority: {rel} "
                    f"(archive_sha={sha256_bytes(data)} "
                    f"authority_sha={sha256_bytes(content_authority[rel])})"
                )


def assert_required_inventory(members: dict[str, bytes], dirs: set[str]) -> None:
    missing: list[str] = []
    for rel, expected in REQUIRED_HASHED_FILES.items():
        if rel not in members:
            missing.append(rel)
            continue
        digest = sha256_bytes(members[rel])
        if digest != expected:
            fail(
                f"archive {rel}: sha256 mismatch got={digest} expected={expected}"
            )
    for rel in REQUIRED_EXISTENCE_FILES:
        if rel not in members:
            missing.append(rel)
    for d in REQUIRED_DIRS:
        # directory may appear as member prefix via files under docs/
        has_dir = d in dirs or any(
            key == d or key.startswith(d + "/") for key in members
        )
        if not has_dir:
            missing.append(d + "/")
    if missing:
        fail(f"archive missing required inventory entries: {missing}")
    # HIL evidence layer is required release payload (not HIL_VERIFIED claim).
    assert_hil_payload(members, live_root=REPO_ROOT, content_authority=None)


def validate_member_collection(
    members: dict[str, bytes],
    dirs: set[str],
    label: str,
) -> None:
    assert_required_inventory(members, dirs)
    # Exact inventory: required keys appear once (dict already de-dupes; counts checked by callers).
    denylist_hits: list[str] = []
    for rel, data in sorted(members.items()):
        if not is_probably_text(data, rel):
            continue
        denylist_hits.extend(scan_text_denylist(data, f"{label}:{rel}"))
    if denylist_hits:
        preview = "\n".join(denylist_hits[:20])
        more = (
            ""
            if len(denylist_hits) <= 20
            else f"\n... +{len(denylist_hits) - 20} more"
        )
        fail(
            f"{label}: forbidden vocabulary denylist hits "
            f"({len(denylist_hits)}; pattern intent {DENYLIST_DOC!r}):\n"
            f"{preview}{more}"
        )


def _validate_tar_metadata(
    info: tarfile.TarInfo,
    *,
    expected_mode: int,
    label: str,
) -> None:
    if info.uid != 0 or info.gid != 0:
        fail(f"{label}: tar uid/gid must be 0/0, got {info.uid}/{info.gid}")
    if info.uname != "" or info.gname != "":
        fail(
            f"{label}: tar uname/gname must be empty, "
            f"got {info.uname!r}/{info.gname!r}"
        )
    if info.mtime != 0:
        fail(f"{label}: tar mtime must be 0, got {info.mtime!r}")
    if info.mode != expected_mode:
        fail(
            f"{label}: tar mode must be {oct(expected_mode)}, "
            f"got {oct(info.mode)}"
        )


def _validate_gzip_metadata(path: pathlib.Path) -> None:
    header = path.read_bytes()[:10]
    if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
        fail(f"{path.name}: invalid gzip header")
    # No optional filename/comment/extra/header-CRC fields; fixed epoch mtime.
    if header[3] != 0:
        fail(f"{path.name}: gzip flags must be 0, got 0x{header[3]:02x}")
    if header[4:8] != b"\0\0\0\0":
        fail(f"{path.name}: gzip mtime must be 0")
    if header[8] != CANONICAL_GZIP_XFL:
        fail(
            f"{path.name}: gzip XFL must be {CANONICAL_GZIP_XFL}, "
            f"got {header[8]}"
        )
    if header[9] != CANONICAL_GZIP_OS:
        fail(
            f"{path.name}: gzip OS must be {CANONICAL_GZIP_OS}, "
            f"got {header[9]}"
        )


def read_tar_gz(path: pathlib.Path, prefix: str) -> tuple[dict[str, bytes], set[str]]:
    members: dict[str, bytes] = {}
    dirs: set[str] = set()
    counts: dict[str, int] = {}
    order: list[str] = []
    _validate_gzip_metadata(path)
    with tarfile.open(path, "r:gz") as tf:
        infos = tf.getmembers()
        if not infos:
            fail(f"{path.name}: tar archive is empty")
        root = infos[0]
        if root.name.replace("\\", "/").rstrip("/") != prefix or not root.isdir():
            fail(
                f"{path.name}: first tar member must be canonical prefix "
                f"directory {prefix!r}"
            )
        _validate_tar_metadata(
            root,
            expected_mode=CANONICAL_DIR_MODE,
            label=f"tar:{root.name}",
        )
        for index, info in enumerate(infos):
            if info.issym() or info.islnk():
                fail(f"tar symlink/hardlink forbidden: {info.name!r}")
            if stat.S_ISLNK(info.mode):
                fail(f"tar link mode forbidden: {info.name!r}")
            rel = normalize_member(info.name, prefix)
            if rel is None:
                if index != 0:
                    fail(f"tar duplicate/non-canonical prefix member: {info.name!r}")
                continue
            if info.isdir():
                fail(
                    "tar nested directory entries are non-canonical; "
                    f"files alone define directories: {info.name!r}"
                )
            if not info.isreg():
                fail(f"tar non-regular member forbidden: {info.name!r} type={info.type!r}")
            if info.name.endswith("/") and info.size == 0:
                fail(f"tar file has directory spelling: {info.name!r}")
            counts[rel] = counts.get(rel, 0) + 1
            order.append(rel)
            extracted = tf.extractfile(info)
            if extracted is None:
                fail(f"tar cannot extract: {info.name!r}")
            data = extracted.read()
            if len(data) != info.size:
                fail(
                    f"tar extracted size mismatch for {info.name!r}: "
                    f"header={info.size} bytes={len(data)}"
                )
            _validate_tar_metadata(
                info,
                expected_mode=canonical_file_mode(data),
                label=f"tar:{info.name}",
            )
            members[rel] = data
    for rel, n in counts.items():
        if n != 1:
            fail(f"tar duplicate member {rel!r}: count={n}")
    if order != sorted(order):
        fail("tar regular members are not in canonical lexical order")
    return members, dirs


def read_zip(path: pathlib.Path, prefix: str) -> tuple[dict[str, bytes], set[str]]:
    members: dict[str, bytes] = {}
    dirs: set[str] = set()
    counts: dict[str, int] = {}
    with zipfile.ZipFile(path, "r") as zf:
        if zf.comment:
            fail(f"{path.name}: zip archive comment must be empty")
        order: list[str] = []
        for info in zf.infolist():
            if info.create_system != 3:
                fail(
                    f"zip member must use canonical Unix metadata: "
                    f"{info.filename!r} create_system={info.create_system}"
                )
            if (
                info.create_version != CANONICAL_ZIP_VERSION
                or info.extract_version != CANONICAL_ZIP_VERSION
            ):
                fail(
                    f"zip member version must be "
                    f"{CANONICAL_ZIP_VERSION}/{CANONICAL_ZIP_VERSION}: "
                    f"{info.filename!r} got="
                    f"{info.create_version}/{info.extract_version}"
                )
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                fail(f"zip symlink forbidden: {info.filename!r}")
            if info.date_time != CANONICAL_ZIP_TIME:
                fail(
                    f"zip member timestamp must be {CANONICAL_ZIP_TIME}: "
                    f"{info.filename!r} got={info.date_time!r}"
                )
            if info.extra or info.comment:
                fail(
                    f"zip member extra/comment metadata must be empty: "
                    f"{info.filename!r}"
                )
            try:
                info.filename.encode("ascii")
                expected_flags = 0
            except UnicodeEncodeError:
                expected_flags = 0x800
            if info.flag_bits != expected_flags:
                fail(
                    f"zip member flags must be canonical for its filename: "
                    f"{info.filename!r} got=0x{info.flag_bits:04x} "
                    f"expected=0x{expected_flags:04x}"
                )
            if info.compress_type != zipfile.ZIP_DEFLATED:
                fail(
                    f"zip member compression must be DEFLATED: "
                    f"{info.filename!r}"
                )
            name = info.filename
            if name.endswith("/"):
                fail(
                    "zip directory entries are non-canonical; "
                    f"files alone define directories: {name!r}"
                )
            rel = normalize_member(name, prefix)
            if rel is None:
                fail(f"zip prefix directory must not be an explicit member: {name!r}")
            data = zf.read(info)
            expected_mode = canonical_zip_file_mode(data)
            if mode != expected_mode:
                fail(
                    f"zip file mode must be {oct(expected_mode)}: "
                    f"{name!r} got={oct(mode)}"
                )
            if (info.external_attr & 0xFFFF) != 0:
                fail(f"zip DOS attributes must be 0: {name!r}")
            if info.internal_attr != 0 or info.volume != 0:
                fail(
                    f"zip internal attributes/volume must be 0/0: "
                    f"{name!r} got={info.internal_attr}/{info.volume}"
                )
            counts[rel] = counts.get(rel, 0) + 1
            order.append(rel)
            members[rel] = data
        for rel, n in counts.items():
            if n != 1:
                fail(f"zip duplicate member {rel!r}: count={n}")
        if order != sorted(order):
            fail("zip members are not in canonical lexical order")
    return members, dirs


def validate_archives(
    tar_path: pathlib.Path,
    zip_path: pathlib.Path,
    prefix: str,
) -> None:
    if not tar_path.is_file():
        fail(f"missing tar archive: {tar_path}")
    if not zip_path.is_file():
        fail(f"missing zip archive: {zip_path}")
    tar_members, tar_dirs = read_tar_gz(tar_path, prefix)
    zip_members, zip_dirs = read_zip(zip_path, prefix)
    validate_member_collection(tar_members, tar_dirs, f"tar:{tar_path.name}")
    validate_member_collection(zip_members, zip_dirs, f"zip:{zip_path.name}")
    if set(tar_members) != set(zip_members):
        fail(
            "tar/zip member set mismatch: "
            f"tar_only={sorted(set(tar_members) - set(zip_members))[:20]} "
            f"zip_only={sorted(set(zip_members) - set(tar_members))[:20]}"
        )
    changed = [
        rel
        for rel in sorted(tar_members)
        if tar_members[rel] != zip_members[rel]
    ]
    if changed:
        fail(f"tar/zip payload mismatch: changed={changed[:20]}")
    print(
        "release_archive_payload_gate OK: "
        f"prefix={prefix} tar_members={len(tar_members)} "
        f"zip_members={len(zip_members)} full_equivalence=OK "
        f"canonical_metadata=OK required_hashed="
        f"{len(REQUIRED_HASHED_FILES)} denylist=0"
    )


def _tarinfo(arcname: str, data: bytes, is_dir: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name=arcname)
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    if is_dir:
        info.type = tarfile.DIRTYPE
        info.mode = CANONICAL_DIR_MODE
        info.size = 0
    else:
        info.type = tarfile.REGTYPE
        info.mode = canonical_file_mode(data)
        info.size = len(data)
    return info


def build_archives_from_worktree(
    out_dir: pathlib.Path,
    prefix: str,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Build deterministic tar.gz + zip from worktree (tracked + forced gates)."""
    return build_archives_from_git(
        out_dir,
        prefix,
        "HEAD",
        source="worktree",
        force_release_gates=True,
    )


def pack_sorted_members(
    members: dict[str, bytes],
    out_dir: pathlib.Path,
    prefix: str,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Pack members with canonical uid/gid/mode/mtime and sorted path order."""
    out_dir.mkdir(parents=True, exist_ok=True)
    tar_path = out_dir / f"{prefix}.tar.gz"
    zip_path = out_dir / f"{prefix}.zip"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        tf.addfile(_tarinfo(f"{prefix}/", b"", is_dir=True))
        for rel in sorted(members):
            data = members[rel]
            info = _tarinfo(f"{prefix}/{rel}", data)
            tf.addfile(info, io.BytesIO(data))
    with open(tar_path, "wb") as fh:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=fh,
            compresslevel=9,
            mtime=0,
        ) as gz:
            gz.write(raw.getvalue())
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in sorted(members):
            data = members[rel]
            zinfo = zipfile.ZipInfo(filename=f"{prefix}/{rel}")
            zinfo.create_system = 3
            zinfo.date_time = CANONICAL_ZIP_TIME
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.external_attr = (
                canonical_zip_file_mode(data) & 0xFFFF
            ) << 16
            zf.writestr(zinfo, data)
    return tar_path, zip_path


def require_clean_worktree() -> None:
    """Fail if the worktree has staged/unstaged changes (release CI invariant)."""
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        fail(f"git status failed: {proc.stderr}")
    if proc.stdout.strip():
        fail(
            "worktree is dirty; release archive packing requires a clean tree "
            "(or omit --require-clean-worktree for local dirty validation)"
        )


def tracked_worktree_members(
    *,
    force_release_gates: bool = False,
    include_untracked: bool = False,
) -> dict[str, bytes]:
    """Load bytes from the live worktree for archive packing.

    - Default: git-tracked paths only (release shipping surface).
    - include_untracked: also include non-ignored untracked files
      (``git ls-files -co --exclude-standard``) so local clean-room can
      exercise concurrent worktree files without false configure gaps.
    - force_release_gates: always include release gate tools if present on disk.
    """
    if include_untracked:
        proc = subprocess.run(
            [
                "git",
                "-C",
                str(REPO_ROOT),
                "ls-files",
                "-co",
                "--exclude-standard",
                "-z",
            ],
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            fail(f"git ls-files -co failed: {proc.stderr.decode('utf-8', 'replace')}")
        rels = {
            raw.decode("utf-8", "surrogateescape")
            for raw in proc.stdout.split(b"\0")
            if raw
        }
    else:
        rels = set(git_tracked_relpaths())
    if force_release_gates:
        for rel in FORCE_ARCHIVE_RELS:
            if (REPO_ROOT / rel).is_file():
                rels.add(rel)
    members: dict[str, bytes] = {}
    for rel in sorted(rels):
        path = REPO_ROOT / rel
        if path.is_symlink():
            fail(f"worktree symlink forbidden in release archive: {rel}")
        if not path.is_file():
            continue
        members[rel] = path.read_bytes()
    # Always inject latest HIL evidence payload from disk (concurrent root
    # updates to schemas/runner/docs are captured at this moment).
    members.update(load_hil_payload_from_disk(REPO_ROOT))
    # Latest cmake modules (may be untracked during parallel root work).
    members.update(load_live_cmake_modules(REPO_ROOT))
    # Latest source overlays (concurrent untracked TUs referenced by CMake).
    members.update(load_live_source_overlays(REPO_ROOT))
    if len(members) < 50:
        fail(f"worktree member set unexpectedly small: {len(members)}")
    return members


def git_tree_blob_members(treeish: str = "HEAD") -> dict[str, bytes]:
    """Load regular-file blobs from a git tree (pure commit; no worktree)."""
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-tree", "-r", treeish],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        fail(f"git ls-tree failed: {proc.stderr}")
    members: dict[str, bytes] = {}
    for line in proc.stdout.splitlines():
        try:
            meta, rel = line.split("\t", 1)
        except ValueError:
            fail(f"unexpected ls-tree line: {line!r}")
        parts = meta.split()
        if len(parts) < 3:
            fail(f"unexpected ls-tree meta: {meta!r}")
        mode, kind = parts[0], parts[1]
        if kind != "blob":
            continue
        if mode == "120000":
            fail(f"git tree symlink forbidden in release archive: {rel}")
        if not mode.startswith("100"):
            fail(f"unsupported git blob mode {mode} for {rel}")
        show = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "show", f"{treeish}:{rel}"],
            capture_output=True,
            check=False,
        )
        if show.returncode != 0:
            fail(f"git show failed for {treeish}:{rel}")
        members[rel] = show.stdout
    if len(members) < 50:
        fail(f"git tree member set unexpectedly small: {len(members)}")
    return members


def _load_source_members(
    *,
    source: str,
    treeish: str = "HEAD",
    force_release_gates: bool = True,
    include_untracked: bool = False,
) -> tuple[dict[str, bytes], str]:
    if source == "git":
        return git_tree_blob_members(treeish), f"git:{treeish}"
    if source == "worktree":
        label = "worktree"
        if force_release_gates:
            label += "+force_gates"
        if include_untracked:
            label += "+untracked"
        return (
            tracked_worktree_members(
                force_release_gates=force_release_gates,
                include_untracked=include_untracked,
            ),
            label,
        )
    fail(f"unknown archive source {source!r}")


def capture_content_snapshot(
    *,
    source: str = "worktree",
    treeish: str = "HEAD",
    force_release_gates: bool = True,
    include_untracked: bool = False,
    stable_reads: int = 2,
) -> ArchiveContentSnapshot:
    """Capture one immutable content snapshot for packaging.

    When stable_reads > 1, load the source that many times and require identical
    snapshot SHAs so a concurrent writer during capture fails closed instead of
    producing a half-updated member map.
    """
    if stable_reads < 1:
        fail("stable_reads must be >= 1")
    members, label = _load_source_members(
        source=source,
        treeish=treeish,
        force_release_gates=force_release_gates,
        include_untracked=include_untracked,
    )
    snap = ArchiveContentSnapshot(members, label)
    for i in range(1, stable_reads):
        members_i, _label_i = _load_source_members(
            source=source,
            treeish=treeish,
            force_release_gates=force_release_gates,
            include_untracked=include_untracked,
        )
        sha_i = compute_members_snapshot_sha(members_i)
        if sha_i != snap.snapshot_sha256:
            fail(
                f"source changed during snapshot capture (read 0 vs read {i}): "
                f"snapshot_sha={snap.snapshot_sha256} later_sha={sha_i} "
                f"source={snap.source_label}"
            )
    print(
        f"release_archive_payload_gate snapshot: "
        f"source={snap.source_label} files={len(snap.members)} "
        f"snapshot_sha={snap.snapshot_sha256} stable_reads={stable_reads}"
    )
    return snap


def reverify_live_matches_snapshot(
    snap: ArchiveContentSnapshot,
    *,
    source: str,
    treeish: str = "HEAD",
    force_release_gates: bool = True,
    include_untracked: bool = False,
) -> None:
    """Fail if the live input diverged from the captured snapshot."""
    live, _label = _load_source_members(
        source=source,
        treeish=treeish,
        force_release_gates=force_release_gates,
        include_untracked=include_untracked,
    )
    snap.assert_matches_members(live, where=f"live {source}")


def two_run_pack_from_snapshot(
    snap: ArchiveContentSnapshot,
    out_dir: pathlib.Path,
    prefix: str,
) -> tuple[pathlib.Path, pathlib.Path, pathlib.Path, pathlib.Path]:
    """Pack the same immutable snapshot twice; enforce byte equality.

    Both runs consume only ``snap.members`` (never re-read the worktree).
    Live-source drift after capture is detected by capture stable_reads and by
    explicit reverify_live_matches_snapshot / mutation self-tests — not by
    packing two different trees.
    """
    snap.assert_intact("pre-pack")
    tar1, zip1 = pack_sorted_members(snap.members, out_dir / "run1", prefix)
    snap.assert_intact("between-pack-runs")
    tar2, zip2 = pack_sorted_members(snap.members, out_dir / "run2", prefix)
    snap.assert_intact("post-pack")
    for a, b, label in ((tar1, tar2, "tar.gz"), (zip1, zip2, "zip")):
        ha = sha256_bytes(a.read_bytes())
        hb = sha256_bytes(b.read_bytes())
        if ha != hb:
            fail(
                f"two-run reproducibility failed for {label}: {ha} != {hb} "
                f"(snapshot_sha={snap.snapshot_sha256} source={snap.source_label})"
            )
    print(
        "release_archive_payload_gate two-run reproducibility OK: "
        f"source={snap.source_label} snapshot_sha={snap.snapshot_sha256} "
        f"tar={sha256_bytes(tar1.read_bytes())} zip={sha256_bytes(zip1.read_bytes())}"
    )
    return tar1, zip1, tar2, zip2


def build_archives_from_git(
    out_dir: pathlib.Path,
    prefix: str,
    treeish: str = "HEAD",
    *,
    source: str = "worktree",
    force_release_gates: bool = True,
    include_untracked: bool = False,
) -> tuple[pathlib.Path, pathlib.Path]:
    """Deterministic tar.gz+zip from one captured snapshot (single pack)."""
    snap = capture_content_snapshot(
        source=source,
        treeish=treeish,
        force_release_gates=force_release_gates,
        include_untracked=include_untracked,
    )
    snap.assert_intact("build_archives_from_git")
    return pack_sorted_members(snap.members, out_dir, prefix)


def extract_tar_validated(tar_path: pathlib.Path, dest: pathlib.Path, prefix: str) -> pathlib.Path:
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:gz") as tf:
        # Re-validate members while extracting.
        for info in tf.getmembers():
            if info.issym() or info.islnk():
                fail(f"extract: symlink forbidden: {info.name!r}")
            normalize_member(info.name, prefix)
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest, filter="data")  # type: ignore[arg-type]
        else:
            tf.extractall(dest)
    root = dest / prefix
    if not root.is_dir():
        fail(f"extracted prefix root missing: {root}")
    return root


def run_cleanroom(
    *,
    treeish: str = "HEAD",
    out_dir: pathlib.Path | None = None,
    profile: str = "host",
    tar_path: pathlib.Path | None = None,
    zip_path: pathlib.Path | None = None,
    archive_prefix: str | None = None,
) -> None:
    """From-release-archive clean-room: unpack → configure → build → package surface.

    profile=host: tests-ON smoke + tests-OFF install/export no tests/support.
    """
    if profile != "host":
        fail(f"unsupported cleanroom profile {profile!r}; only 'host' is defined")
    pin_live_hashes_match_repo()
    assert_gate_sources_denylist_clean()
    work = out_dir or pathlib.Path(tempfile.mkdtemp(prefix="ninlil-cleanroom-"))
    work.mkdir(parents=True, exist_ok=True)
    supplied = tar_path is not None or zip_path is not None or archive_prefix is not None
    if supplied:
        if tar_path is None or zip_path is None or not archive_prefix:
            fail("cleanroom external archive requires --tar, --zip, and --prefix")
        prefix = archive_prefix
        validate_archives(tar_path, zip_path, prefix)
        selected_tar = tar_path
        cleanroom_source = "supplied-release-archive"
    else:
        prefix = "ninlil-runtime-cleanroom"
        # No-argument clean-room still uses immutable commit-tree bytes. The
        # treeish argument must never be ignored in favor of live worktree.
        snap = capture_content_snapshot(
            source="git",
            treeish=treeish,
            force_release_gates=False,
            include_untracked=False,
            stable_reads=2,
        )
        selected_tar, selected_zip, _tar2, _zip2 = two_run_pack_from_snapshot(
            snap,
            work / "archives",
            prefix,
        )
        validate_archives(selected_tar, selected_zip, prefix)
        cleanroom_source = f"git:{treeish}"

    src_root = extract_tar_validated(selected_tar, work / "extract", prefix)
    # Gate sources in the *archive* must also be denylist-clean.
    for rel in FORCE_ARCHIVE_RELS:
        p = src_root / rel
        if p.is_file():
            hits = scan_text_denylist(p.read_bytes(), f"cleanroom-archive:{rel}")
            if hits:
                fail(f"cleanroom archive gate denylist unclean:\n" + "\n".join(hits[:10]))

    # --- HIL evidence from archive first (mandatory; not HIL_VERIFIED) ---
    for rel in discover_hil_required_files(REPO_ROOT):
        if not (src_root / rel).is_file():
            fail(f"cleanroom extract missing HIL payload file: {rel}")
    hil_mod = subprocess.run(
        [sys.executable, "-B", "-m", "tools.ninlil_hil", "self-test"],
        cwd=str(src_root),
        capture_output=True,
        text=True,
    )
    if hil_mod.returncode != 0:
        fail(
            "cleanroom archive ninlil_hil self-test failed "
            f"(ninlil_hil_evidence_self_test equivalent):\n"
            f"{hil_mod.stdout}\n{hil_mod.stderr}"
        )
    runner = src_root / "ports/esp-idf/storage/hil/host_powercut_runner.py"
    if not runner.is_file():
        fail("cleanroom archive missing host_powercut_runner.py")
    hil_runner = subprocess.run(
        [sys.executable, str(runner), "--self-test"],
        cwd=str(src_root),
        capture_output=True,
        text=True,
    )
    if hil_runner.returncode != 0:
        fail(
            "cleanroom archive host_powercut_runner self-test failed "
            f"(esp_storage_hil_runner_selftest equivalent):\n"
            f"{hil_runner.stdout}\n{hil_runner.stderr}"
        )
    print(
        "release_archive_payload_gate cleanroom HIL self-tests OK "
        "(ninlil_hil_evidence_self_test + esp_storage_hil_runner_selftest "
        "from archive; not HIL_VERIFIED)"
    )
    markdown = subprocess.run(
        [
            sys.executable,
            str(src_root / "tools/markdown_link_gate.py"),
            "check",
            "--root",
            str(src_root),
            "--all-markdown",
        ],
        cwd=str(src_root),
        capture_output=True,
        text=True,
    )
    if markdown.returncode != 0:
        fail(
            "cleanroom archive Markdown link gate failed:\n"
            f"{markdown.stdout}\n{markdown.stderr}"
        )

    cmake = shutil.which("cmake")
    ctest = shutil.which("ctest")
    if not cmake or not ctest:
        fail("cmake/ctest required for cleanroom")

    openssl_root = os.environ.get("OPENSSL_ROOT_DIR") or os.environ.get("OPENSSL_ROOT")
    conf_extra: list[str] = []
    if openssl_root:
        conf_extra.append(f"-DOPENSSL_ROOT_DIR={openssl_root}")

    # --- tests-ON focused smoke (+ CTest HIL names when configure succeeds) ---
    build_on = work / "build-tests-on"
    conf_on = [
        cmake, "-S", str(src_root), "-B", str(build_on),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DNINLIL_BUILD_TESTS=ON",
        "-DNINLIL_ENABLE_STRICT_WARNINGS=ON",
        "-DNINLIL_BUILD_HOST_RUNTIME=ON",
        "-DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON",
        *conf_extra,
    ]
    proc = subprocess.run(conf_on, capture_output=True, text=True)
    if proc.returncode != 0:
        fail(
            "cleanroom tests-ON configure failed (HIL archive self-tests were "
            f"already green):\n{proc.stdout}\n{proc.stderr}"
        )
    # Build smoke executables needed for the focused allowlist.
    build_proc = subprocess.run(
        [
            cmake,
            "--build",
            str(build_on),
            "--config",
            "Release",
            "-j",
            "--target",
            "ninlil_smoke_c11",
            "ninlil_smoke_cxx17",
            "ninlil_self_contained_byte_stream_c11",
            "ninlil_traceability_tool",
        ],
        capture_output=True,
        text=True,
    )
    if build_proc.returncode != 0:
        fail(
            f"cleanroom tests-ON focused build failed:\n"
            f"{build_proc.stdout}\n{build_proc.stderr}"
        )
    # CTest allowlist: smoke + public boundary + traceability honesty + HIL
    # evidence layer self-tests.
    # HIL names are also proven by direct python -m / runner above from the
    # extracted archive (authoritative path when CMake registration differs).
    for test_name in (
        "smoke_c11",
        "smoke_cxx17",
        "esp_idf_sdk_public_boundary_gate",
        "self_contained_byte_stream_c11",
        "traceability_check",
        "ninlil_hil_evidence_self_test",
        "esp_storage_hil_runner_selftest",
    ):
        t = subprocess.run(
            [
                ctest,
                "--test-dir",
                str(build_on),
                "-C",
                "Release",
                "-R",
                f"^{test_name}$",
                "--output-on-failure",
            ],
            capture_output=True,
            text=True,
            cwd=str(src_root),
        )
        blob = t.stdout + t.stderr
        if "No tests were found." in blob or "0% tests passed, 0 tests failed out of 0" in blob:
            fail(f"cleanroom required ctest {test_name!r} not registered")
        if t.returncode != 0:
            fail(f"cleanroom ctest {test_name} failed:\n{blob}")

    smoke_ok = 0
    for exe in ("ninlil_smoke_c11", "ninlil_smoke_cxx17"):
        candidates = [
            p
            for p in build_on.rglob(exe)
            if p.is_file() and "CMakeFiles" not in p.parts
        ]
        if not candidates:
            fail(f"cleanroom missing smoke executable {exe}")
        # Prefer Release/ when multi-config generators create several paths.
        preferred = [p for p in candidates if "Release" in p.parts] or candidates
        r = subprocess.run([str(preferred[0])], capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"cleanroom {exe} failed: {r.stdout}\n{r.stderr}")
        smoke_ok += 1
    if smoke_ok != 2:
        fail(f"cleanroom expected 2 smoke executables, ran {smoke_ok}")

    # --- tests-OFF package surface ---
    build_off = work / "build-tests-off"
    prefix_install = work / "prefix"
    conf_off = [
        cmake, "-S", str(src_root), "-B", str(build_off),
        "-DCMAKE_BUILD_TYPE=Release",
        "-DNINLIL_BUILD_TESTS=OFF",
        "-DNINLIL_ENABLE_STRICT_WARNINGS=ON",
        "-DNINLIL_BUILD_HOST_RUNTIME=ON",
        "-DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON",
        f"-DCMAKE_INSTALL_PREFIX={prefix_install}",
        *conf_extra,
    ]
    proc = subprocess.run(conf_off, capture_output=True, text=True)
    if proc.returncode != 0:
        fail(f"cleanroom tests-OFF configure failed:\n{proc.stdout}\n{proc.stderr}")
    if "POSIX LAB platform: enabled" in (proc.stdout + proc.stderr):
        fail("cleanroom tests-OFF still enables POSIX LAB platform")
    b = subprocess.run(
        [cmake, "--build", str(build_off), "--config", "Release", "-j"],
        capture_output=True, text=True,
    )
    if b.returncode != 0:
        fail(f"cleanroom tests-OFF build failed:\n{b.stdout}\n{b.stderr}")
    # no tests/support objects
    for dirpath, _, files in os.walk(build_off):
        for name in files:
            s = str(pathlib.Path(dirpath) / name)
            if "tests/support" in s and s.endswith((".o", ".obj", ".c.o", ".a")):
                fail(f"cleanroom tests-OFF has tests/support artifact: {s}")
            if "lab_platform" in name and s.endswith((".a", ".o", ".obj")):
                fail(f"cleanroom tests-OFF has lab_platform artifact: {s}")
    inst = subprocess.run(
        [cmake, "--install", str(build_off), "--config", "Release"],
        capture_output=True, text=True,
    )
    if inst.returncode != 0:
        fail(f"cleanroom install failed:\n{inst.stdout}\n{inst.stderr}")
    for dirpath, _, files in os.walk(prefix_install):
        for name in files:
            s = str(pathlib.Path(dirpath) / name)
            if "lab_platform" in name or "tests/support" in s:
                fail(f"cleanroom install leaks test surface: {s}")
            if s.endswith(".cmake"):
                try:
                    ct = pathlib.Path(s).read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "ninlil_posix_lab_platform" in ct:
                    fail(f"cleanroom export mentions lab_platform: {s}")

    # Independent public-API-only consumer against the tests-OFF install.
    # Use a different consumer build type to exercise installed config mapping;
    # SQLite remains optional to this lifecycle proof.
    consumer_source = (
        src_root / "tests/cmake/installed_host_runtime_consumer"
    )
    consumer_build = work / "installed-consumer"
    consumer_conf = [
        cmake,
        "-S",
        str(consumer_source),
        "-B",
        str(consumer_build),
        "-DCMAKE_BUILD_TYPE=Debug",
        f"-DCMAKE_PREFIX_PATH={prefix_install}",
        "-DCMAKE_MAP_IMPORTED_CONFIG_DEBUG=DEBUG",
        "-DNINLIL_CONSUMER_EXPECT_SQLITE=OFF",
        *conf_extra,
    ]
    consumer_configure = subprocess.run(
        consumer_conf,
        capture_output=True,
        text=True,
    )
    if consumer_configure.returncode != 0:
        fail(
            "cleanroom installed consumer configure failed:\n"
            f"{consumer_configure.stdout}\n{consumer_configure.stderr}"
        )
    consumer_compile = subprocess.run(
        [cmake, "--build", str(consumer_build), "--config", "Debug", "-j"],
        capture_output=True,
        text=True,
    )
    if consumer_compile.returncode != 0:
        fail(
            "cleanroom installed consumer build failed:\n"
            f"{consumer_compile.stdout}\n{consumer_compile.stderr}"
        )
    consumer_run = subprocess.run(
        [
            ctest,
            "--test-dir",
            str(consumer_build),
            "-C",
            "Debug",
            "--output-on-failure",
            "--no-tests=error",
        ],
        capture_output=True,
        text=True,
    )
    if consumer_run.returncode != 0:
        fail(
            "cleanroom installed consumer create/step/destroy failed:\n"
            f"{consumer_run.stdout}\n{consumer_run.stderr}"
        )

    print(
        f"release_archive_payload_gate cleanroom OK: profile={profile} "
        f"source={cleanroom_source} two-run=OK tests-ON-smoke=OK "
        f"markdown-links=OK traceability=OK "
        f"hil-self-tests=OK(not HIL_VERIFIED) tests-OFF-package=OK "
        f"installed-consumer-create-step-destroy=OK"
    )


def pin_live_hashes_match_repo() -> None:
    """Pins must equal the live repository legal/security files."""
    mapping = {
        "LICENSE": LICENSE_SHA256,
        "NOTICE": NOTICE_SHA256,
        "THIRD-PARTY-NOTICES.md": THIRD_PARTY_NOTICES_SHA256,
        "SECURITY.md": SECURITY_SHA256,
    }
    for rel, expected in mapping.items():
        path = REPO_ROOT / rel
        if not path.is_file():
            fail(f"missing required repo file for pin: {rel}")
        digest = sha256_bytes(path.read_bytes())
        if digest != expected:
            fail(
                f"pin drift for {rel}: live={digest} pin={expected} "
                f"(update gate pins only with deliberate legal review)"
            )


def check_with_paths(
    tar_path: pathlib.Path | None,
    zip_path: pathlib.Path | None,
    prefix: str | None,
    out_dir: pathlib.Path | None,
    two_run: bool,
) -> None:
    pin_live_hashes_match_repo()
    assert_gate_sources_denylist_clean()
    if tar_path is not None or zip_path is not None:
        if tar_path is None or zip_path is None or not prefix:
            fail("--tar and --zip and --prefix must be provided together")
        validate_archives(tar_path, zip_path, prefix)
        return

    prefix = prefix or "ninlil-runtime-archive-check"
    out = out_dir or pathlib.Path(tempfile.mkdtemp(prefix="ninlil-archive-gate-"))
    snap = capture_content_snapshot(
        source="worktree",
        force_release_gates=True,
        include_untracked=False,
        stable_reads=2,
    )
    if two_run:
        tar1, zip1, tar2, zip2 = two_run_pack_from_snapshot(snap, out, prefix)
        validate_archives(tar1, zip1, prefix)
        validate_archives(tar2, zip2, prefix)
    else:
        snap.assert_intact("single-pack")
        tar1, zip1 = pack_sorted_members(snap.members, out / "run1", prefix)
        validate_archives(tar1, zip1, prefix)


def _expect_fail(label: str, mutator: Callable[[], None]) -> None:
    try:
        mutator()
    except GateFailure as e:
        print(f"  self-test mutation {label!r} correctly failed: {e}")
        return
    fail(f"self-test mutation {label!r} did not fail (false green)")


def self_test() -> None:
    pin_live_hashes_match_repo()
    assert_gate_sources_denylist_clean()

    # Minimal valid synthetic archive payload (includes full HIL evidence set).
    def good_members() -> dict[str, bytes]:
        m: dict[str, bytes] = {}
        for rel, digest in REQUIRED_HASHED_FILES.items():
            data = (REPO_ROOT / rel).read_bytes()
            assert sha256_bytes(data) == digest
            m[rel] = data
        for rel in REQUIRED_EXISTENCE_FILES:
            m[rel] = (REPO_ROOT / rel).read_bytes()
        # minimal docs tree
        m["docs/README_PLACEHOLDER.md"] = b"# docs\n"
        # Source archives must preserve runnable script semantics.
        m["tools/release-mode-smoke.sh"] = b"#!/bin/sh\nexit 0\n"
        # Latest HIL evidence layer from live tree (schemas/runner/docs).
        m.update(load_hil_payload_from_disk(REPO_ROOT))
        return m

    def write_tar_zip(
        root: pathlib.Path,
        prefix: str,
        members: dict[str, bytes],
        *,
        symlink: bool = False,
        tar_mode_override: tuple[str, int] | None = None,
        zip_time_override: tuple[str, tuple[int, int, int, int, int, int]]
        | None = None,
        zip_payload_override: tuple[str, bytes] | None = None,
    ) -> tuple[pathlib.Path, pathlib.Path]:
        root.mkdir(parents=True, exist_ok=True)
        tar_path = root / f"{prefix}.tar.gz"
        zip_path = root / f"{prefix}.zip"
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as tf:
            tf.addfile(_tarinfo(f"{prefix}/", b"", is_dir=True))
            if symlink:
                info = tarfile.TarInfo(name=f"{prefix}/evil_link")
                info.type = tarfile.SYMTYPE
                info.linkname = "../outside"
                info.mtime = 0
                tf.addfile(info)
            for rel, data in sorted(members.items()):
                info = _tarinfo(f"{prefix}/{rel}", data)
                if tar_mode_override is not None and rel == tar_mode_override[0]:
                    info.mode = tar_mode_override[1]
                tf.addfile(info, io.BytesIO(data))
        with open(tar_path, "wb") as fh:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=fh,
                compresslevel=9,
                mtime=0,
            ) as gz:
                gz.write(raw.getvalue())
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for rel, data in sorted(members.items()):
                zinfo = zipfile.ZipInfo(filename=f"{prefix}/{rel}")
                zinfo.create_system = 3
                zinfo.date_time = (
                    zip_time_override[1]
                    if zip_time_override is not None
                    and rel == zip_time_override[0]
                    else CANONICAL_ZIP_TIME
                )
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                payload = (
                    zip_payload_override[1]
                    if zip_payload_override is not None
                    and rel == zip_payload_override[0]
                    else data
                )
                zinfo.external_attr = (
                    canonical_zip_file_mode(payload) & 0xFFFF
                ) << 16
                zf.writestr(zinfo, payload)
        return tar_path, zip_path

    with tempfile.TemporaryDirectory(prefix="ninlil-arch-st-") as td:
        root = pathlib.Path(td)
        prefix = "pkg"

        # Live overlays may contribute concurrent, not-yet-tracked source
        # files, but must never turn an ESP-IDF/CMake working directory into
        # release payload.  Exercise the exclusion on real directory names so
        # a future broad rglob cannot silently ship toolchain output.
        overlay_root = root / "overlay"
        overlay_good = overlay_root / "ports/esp-idf/app/main/main.c"
        overlay_good.parent.mkdir(parents=True)
        overlay_good.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        overlay_defaults = overlay_root / "ports/esp-idf/app/sdkconfig.defaults"
        overlay_defaults.write_text("CONFIG_IDF_TARGET_ESP32S3=y\n", encoding="utf-8")
        overlay_noise = (
            overlay_root
            / "ports/esp-idf/app/managed_components/vendor/component.c"
        )
        overlay_noise.parent.mkdir(parents=True)
        overlay_noise.write_text("generated\n", encoding="utf-8")
        overlay_build = overlay_root / "ports/esp-idf/app/build/app.elf"
        overlay_build.parent.mkdir(parents=True)
        overlay_build.write_bytes(b"generated-elf")
        (overlay_root / "ports/esp-idf/app/sdkconfig").write_text(
            "generated\n", encoding="utf-8"
        )
        overlay_members = load_live_source_overlays(overlay_root)
        expected_overlay = {
            "ports/esp-idf/app/main/main.c",
            "ports/esp-idf/app/sdkconfig.defaults",
        }
        if set(overlay_members) != expected_overlay:
            fail(
                "live source overlay admitted generated files: "
                f"got={sorted(overlay_members)} expected={sorted(expected_overlay)}"
            )

        members = good_members()
        tar_path, zip_path = write_tar_zip(root, prefix, members)
        validate_archives(tar_path, zip_path, prefix)

        def mut_missing_license() -> None:
            m = good_members()
            del m["LICENSE"]
            t, z = write_tar_zip(root / "m1", prefix, m)
            validate_archives(t, z, prefix)

        _expect_fail("missing_LICENSE", mut_missing_license)

        def mut_license_hash() -> None:
            m = good_members()
            m["LICENSE"] = b"not the apache license\n"
            t, z = write_tar_zip(root / "m2", prefix, m)
            validate_archives(t, z, prefix)

        _expect_fail("LICENSE_hash", mut_license_hash)

        def mut_vocab() -> None:
            m = good_members()
            # assemble forbidden token without embedding it in this source file
            token = "K" + "Guard"
            m["README.md"] = f"# bad\n{token} product\n".encode()
            t, z = write_tar_zip(root / "m3", prefix, m)
            validate_archives(t, z, prefix)

        _expect_fail("forbidden_vocabulary", mut_vocab)

        def mut_traversal() -> None:
            # Directly craft a tar with .. member
            bad_tar = root / "trav.tar.gz"
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as tf:
                tf.addfile(_tarinfo(f"{prefix}/", b"", is_dir=True))
                info = _tarinfo(f"{prefix}/../evil.txt", b"x\n")
                tf.addfile(info, io.BytesIO(b"x\n"))
            with open(bad_tar, "wb") as fh:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=fh,
                    compresslevel=9,
                    mtime=0,
                ) as gz:
                    gz.write(raw.getvalue())
            read_tar_gz(bad_tar, prefix)

        _expect_fail("path_traversal", mut_traversal)

        def mut_noncanonical_member_spelling() -> None:
            bad_tar = root / "dot-member.tar.gz"
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as tf:
                tf.addfile(_tarinfo(f"{prefix}/", b"", is_dir=True))
                info = _tarinfo(f"{prefix}/./evil.txt", b"x\n")
                tf.addfile(info, io.BytesIO(b"x\n"))
            with open(bad_tar, "wb") as fh:
                with gzip.GzipFile(
                    filename="",
                    mode="wb",
                    fileobj=fh,
                    compresslevel=9,
                    mtime=0,
                ) as gz:
                    gz.write(raw.getvalue())
            read_tar_gz(bad_tar, prefix)

        _expect_fail(
            "noncanonical_member_spelling",
            mut_noncanonical_member_spelling,
        )
        _expect_fail(
            "nonportable_archive_prefix",
            lambda: validate_archive_prefix("../pkg"),
        )
        _expect_fail(
            "undefined_cleanroom_profile",
            lambda: run_cleanroom(
                out_dir=root / "undefined-profile",
                profile="target",
            ),
        )

        def mut_symlink() -> None:
            m = good_members()
            t, z = write_tar_zip(root / "m4", prefix, m, symlink=True)
            validate_archives(t, z, prefix)

        _expect_fail("symlink", mut_symlink)

        def mut_tar_mode() -> None:
            m = good_members()
            t, z = write_tar_zip(
                root / "m-mode",
                prefix,
                m,
                tar_mode_override=("README.md", 0o600),
            )
            validate_archives(t, z, prefix)

        _expect_fail("noncanonical_tar_mode", mut_tar_mode)

        def mut_executable_tar_mode() -> None:
            m = good_members()
            t, z = write_tar_zip(
                root / "m-exec-mode",
                prefix,
                m,
                tar_mode_override=("tools/release-mode-smoke.sh", 0o644),
            )
            validate_archives(t, z, prefix)

        _expect_fail(
            "noncanonical_executable_tar_mode",
            mut_executable_tar_mode,
        )

        def mut_gzip_os() -> None:
            m = good_members()
            t, z = write_tar_zip(root / "m-gzip-os", prefix, m)
            payload = bytearray(t.read_bytes())
            payload[9] = 3  # Unix instead of canonical platform-neutral value.
            t.write_bytes(payload)
            validate_archives(t, z, prefix)

        _expect_fail("noncanonical_gzip_os", mut_gzip_os)

        def mut_gzip_xfl() -> None:
            m = good_members()
            t, z = write_tar_zip(root / "m-gzip-xfl", prefix, m)
            payload = bytearray(t.read_bytes())
            payload[8] = 0  # No compression hint instead of maximum-compression.
            t.write_bytes(payload)
            validate_archives(t, z, prefix)

        _expect_fail("noncanonical_gzip_xfl", mut_gzip_xfl)

        def mut_zip_time() -> None:
            m = good_members()
            t, z = write_tar_zip(
                root / "m-zip-time",
                prefix,
                m,
                zip_time_override=("README.md", (2026, 7, 29, 0, 0, 0)),
            )
            validate_archives(t, z, prefix)

        _expect_fail("noncanonical_zip_timestamp", mut_zip_time)

        def mut_cross_archive_payload() -> None:
            m = good_members()
            t, z = write_tar_zip(
                root / "m-cross-payload",
                prefix,
                m,
                zip_payload_override=(
                    "README.md",
                    m["README.md"] + b"\narchive-only mutation\n",
                ),
            )
            validate_archives(t, z, prefix)

        _expect_fail("tar_zip_nonrequired_payload_mismatch", mut_cross_archive_payload)

        _expect_fail(
            "build_from_git_worktree_source",
            lambda: require_git_release_source("worktree"),
        )
        require_git_release_source("git")

        def mut_missing_docs() -> None:
            m = good_members()
            del m["docs/README_PLACEHOLDER.md"]
            # Keep docs/hil-evidence.md so only generic docs/ tree emptiness
            # is not the only path; remove the placeholder but retain HIL doc.
            # validate still needs some docs/ member beyond HIL — ensure fail
            # by removing entire docs/ except we still have hil-evidence.
            # Remove hil-evidence too so docs/ only presence fails? REQUIRED_DIRS
            # is satisfied by docs/hil-evidence.md. So mut_missing_docs must
            # remove all docs/* to fail REQUIRED_DIRS.
            for key in list(m):
                if key.startswith("docs/"):
                    del m[key]
            t, z = write_tar_zip(root / "m5", prefix, m)
            validate_archives(t, z, prefix)

        _expect_fail("missing_docs", mut_missing_docs)

        def mut_missing_hil_schema() -> None:
            m = good_members()
            schemas = [
                k
                for k in m
                if k.startswith("spec/hil/") and k.endswith(".schema.json")
            ]
            if not schemas:
                fail("mutator setup: no HIL schemas in good_members")
            del m[schemas[0]]
            t, z = write_tar_zip(root / "m-hil-miss", prefix, m)
            validate_archives(t, z, prefix)

        _expect_fail("missing_hil_schema", mut_missing_hil_schema)

        def mut_missing_hil_runner() -> None:
            m = good_members()
            del m["ports/esp-idf/storage/hil/host_powercut_runner.py"]
            t, z = write_tar_zip(root / "m-hil-runner", prefix, m)
            validate_archives(t, z, prefix)

        _expect_fail("missing_hil_host_powercut_runner", mut_missing_hil_runner)

        def mut_extra_hil_file() -> None:
            m = good_members()
            m["spec/hil/unexpected-extra.json"] = b'{"extra":true}\n'
            t, z = write_tar_zip(root / "m-hil-extra", prefix, m)
            validate_archives(t, z, prefix)

        _expect_fail("extra_hil_file", mut_extra_hil_file)

        def mut_modified_hil_doc() -> None:
            authority = good_members()
            m = dict(authority)
            m["docs/hil-evidence.md"] = (
                m["docs/hil-evidence.md"] + b"\n# tampered\n"
            )
            # Presence/closed-set alone would still pass; content authority
            # detects 改変 (self-test path).
            assert_hil_payload(m, content_authority=authority)

        _expect_fail("modified_hil_evidence_doc", mut_modified_hil_doc)

        # Positive: good_members HIL closed set + content authority match.
        authority = good_members()
        assert_hil_payload(authority, content_authority=authority)
        print(
            f"  HIL payload inventory OK: files={len(discover_hil_required_files())} "
            f"(not HIL_VERIFIED)"
        )

        # Snapshot integrity: mutating captured members after capture fails.
        def mut_snapshot_members_tamper() -> None:
            snap = ArchiveContentSnapshot(good_members(), "synthetic")
            # External mutation of the snapshot map must be detected.
            key = next(iter(snap.members))
            snap.members[key] = snap.members[key] + b"\n#tamper\n"
            snap.assert_intact("self-test-tamper")

        _expect_fail("snapshot_members_tamper", mut_snapshot_members_tamper)

        # Race: live source changes after capture → reverify fails closed.
        def mut_live_source_race() -> None:
            base = good_members()
            snap = ArchiveContentSnapshot(base, "synthetic-race")
            live = dict(base)
            live["README.md"] = live["README.md"] + b"\n# concurrent writer\n"
            snap.assert_matches_members(live, where="self-test concurrent live")

        _expect_fail("live_source_race_after_capture", mut_live_source_race)

        # Two-run from one snapshot remains equal even if a parallel "live"
        # tree would have changed (packs never re-read live input).
        snap = ArchiveContentSnapshot(good_members(), "synthetic-two-run")
        t1, z1, t2, z2 = two_run_pack_from_snapshot(snap, root / "snap-two-run", prefix)
        if sha256_bytes(t1.read_bytes()) != sha256_bytes(t2.read_bytes()):
            fail("synthetic snapshot two-run tar inequality")
        if sha256_bytes(z1.read_bytes()) != sha256_bytes(z2.read_bytes()):
            fail("synthetic snapshot two-run zip inequality")

        # Capture-time race: two loads disagree → fail closed.
        def mut_capture_unstable() -> None:
            reads = {"n": 0}
            real_load = _load_source_members

            def flaky_load(**kwargs):  # type: ignore[no-untyped-def]
                members, label = real_load(**kwargs)
                reads["n"] += 1
                if reads["n"] == 2:
                    # Simulate concurrent writer between stable reads.
                    key = sorted(members.keys())[0]
                    members = dict(members)
                    members[key] = members[key] + b"\n#race\n"
                return members, label

            import sys

            mod = sys.modules[__name__]
            saved = mod._load_source_members
            try:
                mod._load_source_members = flaky_load  # type: ignore[method-assign]
                capture_content_snapshot(
                    source="worktree",
                    force_release_gates=False,
                    include_untracked=False,
                    stable_reads=2,
                )
            finally:
                mod._load_source_members = saved  # type: ignore[method-assign]

        _expect_fail("capture_unstable_race", mut_capture_unstable)

    # Live worktree: stable capture once → pack twice from that snapshot only.
    check_with_paths(None, None, None, None, two_run=True)

    # Explicit snapshot two-run (no re-read of trees between packs).
    with tempfile.TemporaryDirectory(prefix="ninlil-git-arch-st-") as td:
        root = pathlib.Path(td)
        prefix = "gitpkg"
        snap = capture_content_snapshot(
            source="worktree",
            force_release_gates=True,
            include_untracked=False,
            stable_reads=2,
        )
        t1, z1, t2, z2 = two_run_pack_from_snapshot(snap, root, prefix)
        validate_archives(t1, z1, prefix)
        if sha256_bytes(t1.read_bytes()) != sha256_bytes(t2.read_bytes()):
            fail("self-test snapshot tar two-run mismatch")
        if sha256_bytes(z1.read_bytes()) != sha256_bytes(z2.read_bytes()):
            fail("self-test snapshot zip two-run mismatch")
    print("release_archive_payload_gate self-test OK")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("check", "self-test", "build-and-check", "build-from-git", "cleanroom"),
    )
    parser.add_argument("--tar", type=pathlib.Path, default=None)
    parser.add_argument("--zip", type=pathlib.Path, default=None)
    parser.add_argument("--prefix", type=str, default=None)
    parser.add_argument("--out-dir", type=pathlib.Path, default=None)
    parser.add_argument("--two-run", action="store_true")
    parser.add_argument("--treeish", type=str, default="HEAD")
    parser.add_argument("--profile", type=str, default="host")
    parser.add_argument(
        "--source",
        choices=("worktree", "git"),
        default="worktree",
        help="worktree=tracked disk bytes; git=pure treeish blobs",
    )
    parser.add_argument(
        "--require-clean-worktree",
        action="store_true",
        help="fail if git status is dirty (release CI)",
    )
    parser.add_argument(
        "--no-force-release-gates",
        action="store_true",
        help="do not force-include untracked release gate sources",
    )
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="include non-ignored untracked files (local clean-room)",
    )
    args = parser.parse_args(argv[1:])
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "build-and-check":
            check_with_paths(
                None,
                None,
                args.prefix,
                args.out_dir,
                two_run=True,
            )
        elif args.command == "build-from-git":
            pin_live_hashes_match_repo()
            assert_gate_sources_denylist_clean()
            require_git_release_source(args.source)
            if args.require_clean_worktree:
                require_clean_worktree()
            prefix = args.prefix or "ninlil-runtime-archive"
            out = args.out_dir or pathlib.Path(tempfile.mkdtemp(prefix="ninlil-git-arch-"))
            force_gates = not args.no_force_release_gates
            snap = capture_content_snapshot(
                source=args.source,
                treeish=args.treeish,
                force_release_gates=force_gates,
                include_untracked=args.include_untracked,
                stable_reads=2,
            )
            if args.two_run:
                tar1, zip1, _t2, _z2 = two_run_pack_from_snapshot(snap, out, prefix)
            else:
                snap.assert_intact("build-from-git")
                tar1, zip1 = pack_sorted_members(snap.members, out / "run1", prefix)
            validate_archives(tar1, zip1, prefix)
            print(f"ARCHIVE_TAR={tar1}")
            print(f"ARCHIVE_ZIP={zip1}")
            print(f"ARCHIVE_PREFIX={prefix}")
            print(f"ARCHIVE_SNAPSHOT_SHA={snap.snapshot_sha256}")
        elif args.command == "cleanroom":
            run_cleanroom(
                treeish=args.treeish,
                out_dir=args.out_dir,
                profile=args.profile,
                tar_path=args.tar,
                zip_path=args.zip,
                archive_prefix=args.prefix,
            )
        else:
            # check: either external archives or build-from-worktree
            if args.tar or args.zip:
                check_with_paths(
                    args.tar, args.zip, args.prefix, args.out_dir, two_run=False
                )
            else:
                check_with_paths(
                    None,
                    None,
                    args.prefix,
                    args.out_dir,
                    two_run=args.two_run,
                )
    except GateFailure as e:
        print(f"release_archive_payload_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
