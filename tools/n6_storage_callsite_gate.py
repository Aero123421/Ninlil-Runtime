#!/usr/bin/env python3
"""N6 storage callsite gate — accepted source byte SHA-256 pin authority.

Authority is fail-closed exact path/hash pins of accepted production source
bytes (and the Normative accepted-manifest table in docs/07). This is NOT a
C semantic analyser, NOT human review, and NOT product GO.

Commands: check [--src-root PATH] | self-test [--src-root PATH]
self-test corpus: n6_storage_callsite_gate_selftest.py. PASS ≠ product GO.

Import surface (stable): check_store_text / check_tree / run_check / self_test /
main. check_store_text is a non-authoritative diagnostic helper only.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat as stat_mod
import sys
from pathlib import Path
from typing import Mapping, Sequence

# ---------------------------------------------------------------------------
# Accepted source manifest (code pin). Must match docs/07 Normative table.
# Any byte / comment / format change of a pinned file is RED until human
# review, production tests, and simultaneous docs+code pin updates land.
# ---------------------------------------------------------------------------

# Ordered exact set: path → lowercase SHA-256 hex.
ACCEPTED_SOURCE_MANIFEST: tuple[tuple[str, str], ...] = (
    (
        "src/radio/n6_context_store.c",
        "4686edcb01f5d16aa5b1649db938e80eccbef9ded8add1b62ab3c8ddb97c267d",
    ),
    (
        "src/radio/n6_context_store.h",
        "1901a595b29e91af938cfa1f9acc0cc7eaf8151698eb44885c08b8d38833844c",
    ),
    (
        "src/radio/n6_crypto_host.c",
        "bdbb9a2bf2cc860101da41d2425192904c12c7f42fd2fcf77b3c42716bdc71b2",
    ),
)

STORE_REL = Path("src/radio/n6_context_store.c")
HEADER_REL = Path("src/radio/n6_context_store.h")
CRYPTO_REL = Path("src/radio/n6_crypto_host.c")

DOCS07_REL = Path("docs/07-testing-and-quality.md")
DOCS_MANIFEST_BEGIN = "<!-- n6-storage-accepted-manifest:begin -->"
DOCS_MANIFEST_END = "<!-- n6-storage-accepted-manifest:end -->"

# Hard bound: reject oversized / sparse surprise files before full read.
# Production pins are well under this; self-test uses a smaller inject bound.
MAX_PINNED_FILE_BYTES = 2_000_000
# Diagnostic helper only (check_store_text); not authority.
MAX_DIAGNOSTIC_TEXT_BYTES = 4_000_000

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_TABLE_ROW = re.compile(
    r"^\|\s*`(?P<path>[^`]+)`\s*\|\s*`(?P<hash>[0-9a-f]{64})`\s*\|\s*$"
)


def accepted_manifest_map(
    manifest: Sequence[tuple[str, str]] | None = None,
) -> dict[str, str]:
    src = ACCEPTED_SOURCE_MANIFEST if manifest is None else manifest
    out: dict[str, str] = {}
    for path, digest in src:
        if path in out:
            raise ValueError(f"duplicate manifest path: {path}")
        if not _HEX64.fullmatch(digest):
            raise ValueError(f"manifest hash must be 64 lowercase hex: {path}")
        out[path] = digest
    return out


# Back-compat alias (dict view of code pins). Not a second authority.
PRODUCTION_HASHES: dict[str, str] = accepted_manifest_map()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _err(msg: str) -> str:
    return msg


def safe_relpath(root: Path, rel: str, where: str) -> tuple[Path | None, str | None]:
    """Resolve repo-relative path with fail-closed symlink / traversal policy.

    Every path component is lstat'd *before* resolve(); symlinks are RED even
    when content bytes would match a pin. Leaf must be a regular file.
    Returns (path, None) on success or (None, error).
    """
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        return None, f"{where}: absolute path forbidden: {rel!r}"
    if "\\" in rel:
        return None, f"{where}: backslash path forbidden: {rel!r}"
    parts = Path(rel).as_posix().split("/")
    if ".." in parts or any(p in ("", ".") for p in parts):
        return None, f"{where}: path traversal/empty segment forbidden: {rel!r}"

    try:
        if root.is_symlink():
            return None, f"{where}: root path is a symlink"
    except OSError as e:
        return None, f"{where}: cannot inspect root: {e}"

    cur = root
    for part in parts:
        cur = cur / part
        try:
            st = os.lstat(cur)
        except FileNotFoundError:
            return None, f"{where}: missing path: {rel!r}"
        except OSError as e:
            return None, f"{where}: lstat failed for {rel!r}: {e}"
        if stat_mod.S_ISLNK(st.st_mode):
            return None, f"{where}: symlink forbidden: {rel!r}"

    try:
        st_leaf = os.lstat(cur)
    except OSError as e:
        return None, f"{where}: lstat failed for {rel!r}: {e}"
    if not stat_mod.S_ISREG(st_leaf.st_mode):
        return None, f"{where}: not a regular file: {rel!r}"

    try:
        root_res = root.resolve(strict=True)
        path_res = cur.resolve(strict=True)
    except (FileNotFoundError, OSError) as e:
        return None, f"{where}: resolve failed for {rel!r}: {e}"
    try:
        common = os.path.commonpath([str(root_res), str(path_res)])
    except ValueError:
        return None, f"{where}: path escapes repo root: {rel!r}"
    if os.path.normcase(common) != os.path.normcase(str(root_res)):
        return None, f"{where}: path escapes repo root: {rel!r}"
    try:
        path_res.relative_to(root_res)
    except ValueError:
        return None, f"{where}: path escapes repo root: {rel!r}"
    return cur, None


def read_bytes_bounded(
    path: Path,
    *,
    max_bytes: int,
    where: str,
) -> tuple[bytes | None, str | None]:
    """Bound-before-read: size check via lstat, then hard max+1 byte read."""
    try:
        st = os.lstat(path)
    except OSError as e:
        return None, f"{where}: lstat failed: {e}"
    if stat_mod.S_ISLNK(st.st_mode):
        return None, f"{where}: symlink forbidden"
    if not stat_mod.S_ISREG(st.st_mode):
        return None, f"{where}: not a regular file"
    if st.st_size > max_bytes:
        return None, f"{where}: file too large ({st.st_size} > {max_bytes})"
    try:
        with open(path, "rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError as e:
        return None, f"{where}: read failed: {e}"
    if len(data) > max_bytes:
        return None, f"{where}: file grew past bound ({max_bytes})"
    return data, None


def parse_docs_manifest_table(docs_text: str) -> tuple[dict[str, str] | None, str | None]:
    """Parse the Normative accepted-manifest table between HTML markers in docs/07."""
    if docs_text.count(DOCS_MANIFEST_BEGIN) != 1:
        return None, "docs/07: accepted-manifest begin marker must occur exactly once"
    if docs_text.count(DOCS_MANIFEST_END) != 1:
        return None, "docs/07: accepted-manifest end marker must occur exactly once"
    begin = docs_text.find(DOCS_MANIFEST_BEGIN)
    if begin < 0:
        return None, "docs/07: missing accepted-manifest begin marker"
    end = docs_text.find(DOCS_MANIFEST_END, begin + len(DOCS_MANIFEST_BEGIN))
    if end < 0:
        return None, "docs/07: missing accepted-manifest end marker"
    block = docs_text[begin + len(DOCS_MANIFEST_BEGIN) : end]
    rows: dict[str, str] = {}
    for line in block.splitlines():
        m = _TABLE_ROW.match(line.strip())
        if not m:
            continue
        path = m.group("path").strip()
        digest = m.group("hash").strip()
        if not _HEX64.fullmatch(digest):
            return None, f"docs/07: invalid hash for {path!r}"
        if path in rows:
            return None, f"docs/07: duplicate manifest path {path!r}"
        rows[path] = digest
    if not rows:
        return None, "docs/07: accepted-manifest table has no path/hash rows"
    return rows, None


def check_manifest_pair_exact(
    code_map: Mapping[str, str],
    docs_map: Mapping[str, str],
) -> list[str]:
    """Require exact set+hash equality between code pins and docs table."""
    errs: list[str] = []
    code_keys = set(code_map)
    docs_keys = set(docs_map)
    if code_keys != docs_keys:
        only_code = sorted(code_keys - docs_keys)
        only_docs = sorted(docs_keys - code_keys)
        if only_code:
            errs.append(
                "manifest set mismatch: path(s) only in code pin: "
                + ", ".join(only_code)
            )
        if only_docs:
            errs.append(
                "manifest set mismatch: path(s) only in docs table: "
                + ", ".join(only_docs)
            )
    for path in sorted(code_keys & docs_keys):
        if code_map[path] != docs_map[path]:
            errs.append(
                f"manifest hash mismatch for {path}: "
                f"code={code_map[path]} docs={docs_map[path]}"
            )
    return errs


def verify_pinned_file(
    root: Path,
    rel: str,
    expected_hash: str,
    *,
    max_bytes: int = MAX_PINNED_FILE_BYTES,
) -> list[str]:
    """Verify one pinned path: policy + bounded read + exact SHA-256."""
    errs: list[str] = []
    path_or_none, err = safe_relpath(root, rel, rel)
    if err is not None:
        return [err]
    assert path_or_none is not None
    path = path_or_none

    data, rerr = read_bytes_bounded(path, max_bytes=max_bytes, where=rel)
    if rerr is not None:
        return [rerr]
    assert data is not None
    got = sha256_bytes(data)
    if got != expected_hash:
        errs.append(
            f"{rel}: sha256 mismatch got={got} expected={expected_hash} "
            f"(1-byte/comment/format change is RED; update requires human review "
            f"+ production tests + simultaneous docs/code pin)"
        )
    return errs


def _check_tree_with_policy(
    src_root: Path,
    *,
    manifest: Sequence[tuple[str, str]] | None = None,
    docs_path: Path | None = None,
    max_bytes: int = MAX_PINNED_FILE_BYTES,
    skip_docs: bool = False,
) -> list[str]:
    """Private policy-injection seam for the deterministic self-test corpus."""
    errs: list[str] = []
    root = Path(src_root)
    try:
        code_map = accepted_manifest_map(manifest)
    except ValueError as e:
        return [f"invalid code manifest: {e}"]

    if not skip_docs:
        dpath = docs_path if docs_path is not None else (root / DOCS07_REL)
        if docs_path is None:
            resolved, derr = safe_relpath(root, DOCS07_REL.as_posix(), "docs/07")
            if derr is not None:
                errs.append(derr)
                # Still report pin/disk issues when possible.
                dpath = None  # type: ignore[assignment]
            else:
                dpath = resolved
        if dpath is not None:
            raw, rerr = read_bytes_bounded(
                dpath, max_bytes=MAX_PINNED_FILE_BYTES, where="docs/07"
            )
            if rerr is not None:
                errs.append(rerr)
            else:
                assert raw is not None
                try:
                    docs_text = raw.decode("utf-8")
                except UnicodeDecodeError as e:
                    errs.append(f"docs/07: not UTF-8: {e}")
                else:
                    docs_map, perr = parse_docs_manifest_table(docs_text)
                    if perr is not None:
                        errs.append(perr)
                    else:
                        assert docs_map is not None
                        errs.extend(check_manifest_pair_exact(code_map, docs_map))

    for rel, expected in code_map.items():
        errs.extend(
            verify_pinned_file(
                root,
                rel,
                expected,
                max_bytes=max_bytes,
            )
        )
    return errs


def check_tree(
    src_root: Path,
    store_path: Path | None = None,
) -> list[str]:
    """Fail-closed authority check: docs table ≡ code pins ≡ disk bytes.

    ``store_path`` remains in the import signature for compatibility but any
    override is fail-closed: authority always reads the exact manifest paths
    below ``src_root``. Policy injection is unavailable through this public
    authority surface.
    """
    if store_path is not None:
        return [
            "store_path override is forbidden by accepted-source authority; "
            "check the exact manifest path under src_root"
        ]
    return _check_tree_with_policy(Path(src_root))


def check_store_text(
    text: str,
    *,
    src_root: Path | None = None,  # noqa: ARG001 — stable signature
    store_dir: Path | None = None,  # noqa: ARG001 — stable signature
) -> list[str]:
    """Non-authoritative diagnostic helper (hash pin does not apply to free text).

    Not C semantic analysis. Not GO. Callers that need authority must use
    ``check_tree`` / ``run_check`` against pinned paths on disk.
    """
    errs: list[str] = []
    if not isinstance(text, str):
        return ["check_store_text diagnostic: text must be str"]
    # Bound by character count as a cheap stand-in for byte size of UTF-8 text.
    if len(text.encode("utf-8", errors="replace")) > MAX_DIAGNOSTIC_TEXT_BYTES:
        errs.append(
            f"check_store_text diagnostic: text exceeds "
            f"{MAX_DIAGNOSTIC_TEXT_BYTES} bytes (bounded diagnostic only)"
        )
    # Empty / whitespace-only is a weak smell, not authority.
    if not text.strip():
        errs.append("check_store_text diagnostic: empty text")
    return errs


def run_check(src_root: Path, store_path: Path | None = None) -> int:
    errs = check_tree(src_root, store_path=store_path)
    if errs:
        print("n6_storage_callsite_gate FAIL:")
        for e in errs:
            print(" ", e)
        return 1
    n = len(ACCEPTED_SOURCE_MANIFEST)
    print(
        "n6_storage_callsite_gate: OK "
        f"(accepted source SHA-256 pin authority; {n} path(s); "
        "docs/07 manifest table exact set/hash match; "
        "regular-file + no-symlink + bounded-read policy; "
        "PASS is not C semantic proof / human review / product GO)"
    )
    return 0


def self_test(src_root: Path) -> int:
    """Load mutation self-test corpus (fail-closed if module missing)."""
    # Register under the stable import name when executed as __main__ or
    # loaded via importlib under a temporary module name.
    this_mod = sys.modules.get(__name__)
    if this_mod is not None:
        sys.modules.setdefault("n6_storage_callsite_gate", this_mod)
    st_path = Path(__file__).with_name("n6_storage_callsite_gate_selftest.py")
    try:
        import n6_storage_callsite_gate_selftest as _st
    except ImportError:
        if not st_path.is_file():
            print(
                "SELF-TEST FAIL: missing tools/n6_storage_callsite_gate_selftest.py "
                "(fail closed)"
            )
            return 1
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "n6_storage_callsite_gate_selftest", st_path
        )
        if spec is None or spec.loader is None:
            print("SELF-TEST FAIL: cannot load n6_storage_callsite_gate_selftest")
            return 1
        _st = importlib.util.module_from_spec(spec)
        sys.modules["n6_storage_callsite_gate_selftest"] = _st
        try:
            spec.loader.exec_module(_st)
        except Exception as ex:  # noqa: BLE001
            print(f"SELF-TEST FAIL: selftest module load error: {ex}")
            return 1
    if not hasattr(_st, "run_self_test"):
        print("SELF-TEST FAIL: selftest module missing run_self_test")
        return 1
    return int(_st.run_self_test(src_root))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="n6_storage_callsite_gate",
        description=(
            "N6 storage accepted-source SHA-256 pin gate "
            "(not C semantic analysis; PASS ≠ product GO)"
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser(
        "check",
        help="Verify accepted source pins + docs/07 manifest table",
    )
    c.add_argument(
        "--src-root",
        type=Path,
        default=None,
        help="Repository root (default: parent of tools/)",
    )
    s = sub.add_parser(
        "self-test",
        help="Deterministic pin/mutation self-test (temp trees; fast)",
    )
    s.add_argument(
        "--src-root",
        type=Path,
        default=None,
        help="Repository root (default: parent of tools/)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if e.code is not None else 1

    default_root = Path(__file__).resolve().parents[1]
    src_root = Path(args.src_root) if args.src_root is not None else default_root
    src_root = src_root.resolve()

    if args.command == "check":
        return run_check(src_root)
    if args.command == "self-test":
        return self_test(src_root)
    print(f"unknown command {args.command!r}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
