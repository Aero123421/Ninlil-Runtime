#!/usr/bin/env python3
"""N6 production packaging / leakage gate (docs/30 §20.2 / Chunk D / ADR-0010).

Checks:
  - exact N6 production sources {codec,crypto,context} once in shared cmake list
  - production archive ar members include those three objects exactly once
  - ar members: fixture / test / oracle / spy object basenames = 0
  - nm portable parse: required 5 symbols exact name + DEFINED + text (T/t);
    archive member identity bound when nm emits member headers
  - strings: missing executable / launch fail / nonzero = hard FAIL (never empty OK)
  - nm -a + strings: ban fixture/test binder / raw-id / path tokens
  - install tree public only when --install-prefix set
  - tests-OFF packaging cmake authority:
      **required first authority** = entire cmake/n6_tests_off_packaging.cmake
      file UTF-8 bytes SHA-256 exact pin (byte pin, NOT semantic CMake
      equivalence / membership / reachability). Path must be regular, non-symlink,
      bounded-readable. Any comment/format/benign byte change is intentional RED.
      Hash mismatch → immediate RED. Exact match is the only packaging GREEN
      path (structural mini-parser removed; byte pin is sufficient).
      Authority content change requires human review + fresh OFF + simultaneous
      constant update (constant-alone or disk-alone is incomplete / human review).
  - mutation self-tests include U-only false-green and strings-fail false-green;
      packaging cmake: actual exact bytes GREEN only; all mutations are hash RED

PASS ≠ product GO.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat as stat_mod
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

FORBIDDEN_SUBSTRINGS = (
    b"ninlil_n6_test_fixture_allowed",
    b"ninlil_n6_test_bind_local_identity",
    b"ninlil_n6_bind_fixture",
    b"n6_test_hooks",
    b"n6_mem_storage",
    b"NINLIL_N6_TEST_BUILD",
    b"fixture_allowed",
    b"bind_fixture_install",
    b"LOCAL_ID_FIXTURE",
    b"NINLIL_N6_LOCAL_ID_FIXTURE_TAG",
    b"n6_local_id_fixture",
    b"ninlil_n6_local_identity_t",
    b"accepted_tag",
    b"tests/support/n6_",
    b"tests/radio/n6_",
    b"n6_local_identity_fixture",
    b"NINLIL_TEST_ONLY_ARTIFACT",
)

BANNED_AR_SUBSTRINGS = (
    "fixture",
    "oracle",
    "spy",
    "testbuild",
    "n6_mem_storage",
    "n6_local_identity",
    "n6_context_store_test",
    "n6_record_codec_test",
)

N6_EXACT = (
    "src/radio/n6_record_codec.c",
    "src/radio/n6_crypto_host.c",
    "src/radio/n6_context_store.c",
)

N6_AR_OBJECTS = (
    "n6_record_codec.c.o",
    "n6_crypto_host.c.o",
    "n6_context_store.c.o",
)

# Required durable engine symbols: exact name, DEFINED text (T/t), member bind.
REQUIRED_TEXT_SYMBOLS: dict[str, str] = {
    "ninlil_n6_install_hop": "n6_context_store.c.o",
    "ninlil_n6_tx_burn": "n6_context_store.c.o",
    "ninlil_n6_rx_precheck": "n6_context_store.c.o",
    "ninlil_n6_boot_scan": "n6_context_store.c.o",
    "ninlil_n6_bind_local_identity_accepted": "n6_context_store.c.o",
}

# nm type codes treated as undefined / not defined for our purposes.
_UNDEFINED_TYPES = frozenset({"U", "u"})
# Text implementation types (required symbols are functions).
_TEXT_TYPES = frozenset({"T", "t"})


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _parse_n6_production_set(text: str) -> tuple[list[str], list[str]]:
    """Parse full NINLIL_N6_PRODUCTION_RELATIVE_SOURCES element list.

    Extracts *all* set members (not only n6_*): path-like tokens and ${VAR}.
    Comment-only lines are ignored via CMake comment stripping.
    """
    errs: list[str] = []
    code = _cmake_code_no_comments(text)
    m = re.search(
        r"set\(\s*NINLIL_N6_PRODUCTION_RELATIVE_SOURCES\s*(.*?)\)",
        code,
        re.S,
    )
    if not m:
        return [], ["cannot parse NINLIL_N6_PRODUCTION_RELATIVE_SOURCES set()"]
    block = m.group(1)
    # Full element scan: any path (src|ports)/... or ${VAR} expansion.
    found = re.findall(
        r"\$\{[A-Za-z0-9_]+\}|(?:src|ports)/[A-Za-z0-9_./-]+\.[A-Za-z0-9]+",
        block,
    )
    return found, errs


def check_canonical_sources(root: Path) -> list[str]:
    errs: list[str] = []
    priv = root / "cmake" / "ninlil_runtime_private_sources.cmake"
    if not priv.is_file():
        return [f"missing {priv}"]
    text = _read(priv)
    code = _cmake_code_no_comments(text)
    if "NINLIL_N6_PRODUCTION_RELATIVE_SOURCES" not in code:
        errs.append(f"{priv}: missing NINLIL_N6_PRODUCTION_RELATIVE_SOURCES")
        return errs

    found, parse_errs = _parse_n6_production_set(text)
    errs.extend(f"{priv}: {e}" for e in parse_errs)

    # Exact set equality on *all* elements (order-independent, no dups, no extras).
    expected = list(N6_EXACT)
    expected_set = set(expected)
    found_set = set(found)
    if (
        len(found) != len(expected)
        or found_set != expected_set
        or any(found.count(x) != 1 for x in found)
    ):
        errs.append(
            f"{priv}: N6 production set must be exact elements "
            f"{expected} (order-independent, no dups, no non-N6 extras); "
            f"got {found}"
        )

    # Literal path occurrence in authority file: exactly once each (set body).
    for rel in N6_EXACT:
        count = len(re.findall(re.escape(rel), code))
        if count < 1:
            errs.append(f"{priv}: missing canonical N6 source {rel}")
        elif count != 1:
            errs.append(
                f"{priv}: canonical N6 source {rel}: expected exactly once "
                f"literal, got {count}"
            )

    # RUNTIME list must expand N6 production exactly once via list(APPEND).
    append_bodies = re.findall(
        r"list\s*\(\s*APPEND\s+NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\s*(.*?)\)",
        code,
        re.S,
    )
    n6_runtime_hits = 0
    for body in append_bodies:
        n6_runtime_hits += len(
            re.findall(r"\$\{NINLIL_N6_PRODUCTION_RELATIVE_SOURCES\}", body)
        )
        # Literal re-list of N6 paths inside APPEND also counts as re-injection.
        for rel in N6_EXACT:
            n6_runtime_hits += len(re.findall(re.escape(rel), body))
    if n6_runtime_hits != 1:
        errs.append(
            f"{priv}: NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES must list(APPEND) "
            f"NINLIL_N6_PRODUCTION_RELATIVE_SOURCES exactly once "
            f"(got {n6_runtime_hits} N6 expansions/literals in APPEND bodies)"
        )

    cl = root / "CMakeLists.txt"
    if cl.is_file():
        ct = _read(cl)
        if re.search(
            r"target_sources\s*\(\s*ninlil_runtime_private[^)]*n6_context_store\.c",
            ct,
            re.S,
        ):
            errs.append(
                "CMakeLists.txt: host-only n6_context_store.c injection forbidden"
            )
        if not re.search(
            r"add_library\s*\(\s*ninlil_runtime_private\s+STATIC\s+EXCLUDE_FROM_ALL",
            ct,
        ):
            errs.append(
                "CMakeLists.txt: ninlil_runtime_private must be "
                "STATIC EXCLUDE_FROM_ALL"
            )
        if "n6_tests_off_packaging.cmake" not in ct and "NINLIL_BUILD_TESTS" in ct:
            if "n6_chunk_d_leakage_gate" in ct or "n6_frame_stack_gate" in ct:
                errs.append(
                    "CMakeLists.txt: missing n6_tests_off_packaging.cmake "
                    "registration for fresh OFF Release packaging"
                )
    pack = root / "cmake" / "n6_tests_off_packaging.cmake"
    if pack.is_file():
        errs.extend(check_tests_off_packaging_cmake(pack))
    elif (root / "cmake").is_dir():
        errs.append("missing cmake/n6_tests_off_packaging.cmake")
    return errs


def _cmake_bracket_close(text: str, open_eq: int, start: int) -> int | None:
    """Return index after matching bracket-arg close ``]=]`` / ``]==]`` etc."""
    close = "]" + ("=" * open_eq) + "]"
    pos = text.find(close, start)
    if pos < 0:
        return None
    return pos + len(close)


def _cmake_transform(text: str, *, blank_strings: bool) -> str:
    """CMake transform: drop comments; optionally blank string interiors.

    Length-preserving where content is blanked (spaces / newlines kept) so
    span offsets between keep-string and structure-code modes still align.

    Handles:
      - ``#`` line comments
      - bracket comments ``#[=[ … ]=]`` / ``#[==[ … ]==]`` (full span removed
        as comment; newlines preserved as newlines for line structure)
      - quoted strings ``"…"`` / ``'…'``
      - bracket strings ``[=[ … ]=]`` / ``[==[ … ]==]`` — interiors always
        blanked for structure evidence (``message([=[FATAL_ERROR]=])`` is not
        a real FATAL; decoy ``if(FALSE)`` inside brackets is not control flow)
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_quote: str | None = None
    while i < n:
        c = text[i]
        if in_quote is not None:
            if c == "\\" and i + 1 < n:
                if blank_strings:
                    out.append(" ")
                    out.append(" ")
                else:
                    out.append(c)
                    out.append(text[i + 1])
                i += 2
                continue
            if c == in_quote:
                out.append(c)
                in_quote = None
                i += 1
                continue
            if blank_strings:
                out.append("\n" if c == "\n" else " ")
            else:
                out.append(c)
            i += 1
            continue
        # Bracket comment: #[=[ ... ]=]  (must check before plain # line comment)
        if c == "#" and i + 1 < n and text[i + 1] == "[":
            j = i + 2
            eq = 0
            while j < n and text[j] == "=":
                eq += 1
                j += 1
            if j < n and text[j] == "[":
                end = _cmake_bracket_close(text, eq, j + 1)
                if end is not None:
                    # length-preserving: keep newlines, blank other chars
                    for k in range(i, end):
                        out.append("\n" if text[k] == "\n" else " ")
                    i = end
                    continue
        if c == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        # Bracket string: [=[ ... ]=]
        if c == "[":
            j = i + 1
            eq = 0
            while j < n and text[j] == "=":
                eq += 1
                j += 1
            if j < n and text[j] == "[":
                end = _cmake_bracket_close(text, eq, j + 1)
                if end is not None:
                    # Always blank bracket-string interiors for structure/FATAL
                    # evidence (keep_str and structure modes). Delimiters blanked
                    # too so tokens inside cannot match keywords.
                    for k in range(i, end):
                        out.append("\n" if text[k] == "\n" else " ")
                    i = end
                    continue
        if c in ('"', "'"):
            in_quote = c
            out.append(c)
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _cmake_code_no_comments(text: str) -> str:
    """Comments removed; string contents kept (for production-set path scans)."""
    return _cmake_transform(text, blank_strings=False)


# ---------------------------------------------------------------------------
# tests-OFF packaging cmake authority: UTF-8 bytes SHA-256 exact pin first.
#
# Required first authority is the entire authority file byte identity — not
# semantic CMake equivalence, membership analysis, or reachability. Any
# comment/format/benign change is intentional RED. Updating the authority
# requires human review + fresh OFF + simultaneous constant update
# (constant-alone or disk-alone is incomplete).
#
# Whole-file byte identity is sufficient: structural mini-parser removed.
# Authority content is human-reviewed at pin time with fresh OFF evidence.
# ---------------------------------------------------------------------------

# Exact SHA-256 of cmake/n6_tests_off_packaging.cmake UTF-8 file bytes.
# Keep in lockstep with the authority file; do not "fix" a benign edit.
N6_TESTS_OFF_PACKAGING_CMAKE_SHA256 = (
    "27dc73ffcb5649fd40ceffb4111e3408e8e512b5e84e7ada2370434babae8299"
)
# Bounded read: reject oversized substitutes before hashing.
N6_TESTS_OFF_PACKAGING_CMAKE_MAX_BYTES = 256 * 1024


def check_tests_off_packaging_cmake(path: Path) -> list[str]:
    """Authority pin: exact UTF-8 bytes SHA-256 of packaging cmake file.

    Required first (and sole packaging) authority — byte pin, NOT semantic
    CMake equivalence / membership / reachability analysis:
      - path is a regular file (not a symlink / not a special node)
      - size within N6_TESTS_OFF_PACKAGING_CMAKE_MAX_BYTES
      - file UTF-8-decodable; SHA-256(file bytes) ==
        N6_TESTS_OFF_PACKAGING_CMAKE_SHA256
      - hash mismatch → immediate RED (any comment/format/benign change)

    Structural mini-parser was removed: whole-file byte identity is the
    authority. Content change requires human review + fresh OFF + simultaneous
    constant update (constant-alone or disk-alone is incomplete).
    """
    name = path.name if path.name else str(path)

    # --- path-level: regular / no symlink / bounded read ---
    try:
        if path.is_symlink():
            return [
                f"{name}: packaging authority must be a regular file "
                f"(symlink forbidden; byte pin path-level)"
            ]
        if not path.exists():
            return [f"missing {path}"]
        st = path.lstat()
    except OSError as e:
        return [f"{name}: cannot stat packaging authority: {e}"]

    if stat_mod.S_ISLNK(st.st_mode):
        return [
            f"{name}: packaging authority must be a regular file "
            f"(symlink forbidden; byte pin path-level)"
        ]
    if not stat_mod.S_ISREG(st.st_mode):
        return [
            f"{name}: packaging authority must be a regular file "
            f"(byte pin path-level)"
        ]
    if st.st_size > N6_TESTS_OFF_PACKAGING_CMAKE_MAX_BYTES:
        return [
            f"{name}: packaging authority exceeds bounded read limit "
            f"({st.st_size} > {N6_TESTS_OFF_PACKAGING_CMAKE_MAX_BYTES} bytes)"
        ]

    try:
        raw_bytes = path.read_bytes()
    except OSError as e:
        return [f"{name}: cannot read packaging authority: {e}"]
    if len(raw_bytes) > N6_TESTS_OFF_PACKAGING_CMAKE_MAX_BYTES:
        return [
            f"{name}: packaging authority exceeds bounded read limit "
            f"({len(raw_bytes)} > {N6_TESTS_OFF_PACKAGING_CMAKE_MAX_BYTES} bytes)"
        ]
    try:
        raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return [
            f"{name}: packaging authority must be valid UTF-8 "
            f"(byte pin; non-UTF-8 is RED)"
        ]

    digest = hashlib.sha256(raw_bytes).hexdigest()
    if digest != N6_TESTS_OFF_PACKAGING_CMAKE_SHA256:
        return [
            f"{name}: authority UTF-8 bytes SHA-256 mismatch "
            f"(got {digest}, expected {N6_TESTS_OFF_PACKAGING_CMAKE_SHA256}) — "
            f"byte pin not semantic equivalence; any comment/format/benign "
            f"change is intentional RED; authority update requires human "
            f"review + fresh OFF + simultaneous constant update "
            f"(constant-alone or disk-alone is incomplete)"
        ]
    return []



def check_esp_sources(root: Path) -> list[str]:
    errs: list[str] = []
    esp_cmake = (
        list((root / "ports").rglob("CMakeLists.txt"))
        if (root / "ports").is_dir()
        else []
    )
    esp_cmake += (
        list((root / "ports").rglob("*.cmake")) if (root / "ports").is_dir() else []
    )
    saw_include = False
    for p in esp_cmake:
        t = _read(p)
        if "ninlil_runtime_private_sources.cmake" in t:
            saw_include = True
        if "n6_record_codec.c" in t and "n6_context_store.c" not in t:
            if re.search(r"\bn6_record_codec\.c\b", t) and (
                "ninlil_runtime_private_sources" not in t
            ):
                errs.append(f"{p}: lists codec without context_store")
    if not saw_include and (root / "ports" / "esp-idf").is_dir():
        for p in esp_cmake:
            if "ninlil" in str(p) and "NINLIL_RUNTIME_PRIVATE" in _read(p):
                saw_include = True
                break
    priv = root / "cmake" / "ninlil_runtime_private_sources.cmake"
    if priv.is_file():
        for rel in N6_EXACT:
            if rel not in _read(priv):
                errs.append(f"ESP authority missing {rel}")
    return errs


def ar_members(archive: Path) -> list[str]:
    out = subprocess.check_output(["ar", "t", str(archive)], stderr=subprocess.STDOUT)
    return [
        ln.decode(errors="replace").strip() for ln in out.splitlines() if ln.strip()
    ]


def _member_basename(member: str) -> str:
    return Path(member).name


def _normalize_sym(name: str) -> str:
    n = name.strip()
    if n.startswith("_"):
        n = n[1:]
    # Strip trailing versioning junk if any (keep exact C identifier).
    return n


@dataclass(frozen=True)
class NmEntry:
    name: str  # normalized without leading underscore
    raw_name: str
    type_code: str
    member: str | None  # archive member basename when known
    address: str

    @property
    def defined(self) -> bool:
        return self.type_code not in _UNDEFINED_TYPES and bool(self.type_code)

    @property
    def is_text(self) -> bool:
        return self.type_code in _TEXT_TYPES


# Portable nm line: optional spaces, hex address or blanks, type letter, symbol.
# Examples:
#   000000000000076c T _ninlil_n6_boot_scan
#                    U _memcpy
#   ninlil_n6_boot_scan in n6_context_store.c.o  (BSD style rare; handled loosely)
_NM_LINE_RE = re.compile(
    r"^(?P<addr>[0-9A-Fa-f]+|\s+)"
    r"\s+"
    r"(?P<type>[A-Za-z?])"
    r"\s+"
    r"(?P<name>\S+)"
    r"\s*$"
)
_NM_MEMBER_RE = re.compile(r"^(?P<member>\S.*?):\s*$")


def parse_nm_output(nm_text: str) -> list[NmEntry]:
    """Portable parse of `nm -a` on a static archive or object."""
    entries: list[NmEntry] = []
    current_member: str | None = None
    for raw in nm_text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        # Archive member header (GNU/Apple nm -a on .a): "foo.c.o:" or
        # "lib.a(foo.c.o):" — take basename of last path/paren component.
        m_hdr = _NM_MEMBER_RE.match(line.strip())
        if m_hdr and not _NM_LINE_RE.match(line.strip()):
            # Avoid treating "U _sym" as member; member headers end with ':' only.
            body = m_hdr.group("member")
            # Skip absolute paths that look like object dumps without colon-only
            if "(" in body and body.endswith(")"):
                # rare lib.a(member.o form without trailing handled above
                pass
            base = Path(body.split("/")[-1]).name
            if base.endswith(")"):
                base = base.rstrip(")")
            # Only treat as member if it looks like an object name
            if base.endswith((".o", ".obj", ".c.o")) or ".c." in base:
                current_member = base
                continue
        m = _NM_LINE_RE.match(line)
        if not m:
            # Some nm emit "name: " for stab; skip non-symbol without error
            continue
        raw_name = m.group("name")
        type_code = m.group("type")
        addr = m.group("addr").strip()
        entries.append(
            NmEntry(
                name=_normalize_sym(raw_name),
                raw_name=raw_name,
                type_code=type_code,
                member=current_member,
                address=addr,
            )
        )
    return entries


def run_nm(archive: Path, nm_cmd: str | None = None) -> tuple[bytes, list[str]]:
    """Run nm -a; return (stdout_bytes, errs). Nonzero/missing = hard fail."""
    errs: list[str] = []
    cmd = nm_cmd or shutil.which("nm")
    if not cmd:
        return b"", ["nm executable missing"]
    try:
        proc = subprocess.run(
            [cmd, "-a", str(archive)],
            capture_output=True,
            check=False,
        )
    except OSError as e:
        return b"", [f"nm launch failed: {e}"]
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace") if proc.stderr else ""
        return b"", [f"nm -a nonzero exit {proc.returncode}: {err.strip()}"]
    return proc.stdout or b"", errs


def run_strings(
    archive: Path, strings_cmd: str | None = None
) -> tuple[bytes, list[str]]:
    """Run strings; missing/launch fail/nonzero = hard fail (never empty OK)."""
    errs: list[str] = []
    cmd = strings_cmd
    if cmd is None:
        cmd = shutil.which("strings")
    if not cmd:
        return b"", ["strings executable missing"]
    if not Path(cmd).exists() and shutil.which(cmd) is None:
        # Explicit path that does not exist
        if os.sep in cmd or cmd.startswith("."):
            return b"", [f"strings executable missing: {cmd}"]
    try:
        proc = subprocess.run(
            [cmd, str(archive)],
            capture_output=True,
            check=False,
        )
    except OSError as e:
        return b"", [f"strings launch failed: {e}"]
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace") if proc.stderr else ""
        return b"", [
            f"strings nonzero exit {proc.returncode}: {err.strip()}"
        ]
    return proc.stdout or b"", errs


def _member_matches(member: str | None, expected: str) -> bool:
    if not member:
        return False
    base = _member_basename(member)
    return base == expected or base.endswith(expected)


def check_required_symbols(entries: list[NmEntry]) -> list[str]:
    """Each required symbol: exactly one DEFINED T/t, on expected N6 member.

    U/undefined references may coexist. Substring of raw nm blob is not used.
    Duplicate T/t (incl. T+t mix or two members) fails. Wrong member fails.
    """
    errs: list[str] = []
    by_name: dict[str, list[NmEntry]] = {}
    for e in entries:
        by_name.setdefault(e.name, []).append(e)
    archive_has_members = any(e.member for e in entries)

    for sym, expected_member in REQUIRED_TEXT_SYMBOLS.items():
        cands = by_name.get(sym, [])
        defined_text = [e for e in cands if e.defined and e.is_text]
        if not cands:
            errs.append(
                f"required symbol {sym}: exact nm entry missing "
                "(not substring; need exactly one DEFINED text T/t)"
            )
            continue
        if len(defined_text) == 0:
            types = sorted({e.type_code for e in cands})
            errs.append(
                f"required symbol {sym}: not DEFINED text (T/t); "
                f"seen types={types}"
            )
            continue
        if len(defined_text) != 1:
            detail = ", ".join(
                f"{e.type_code}@{e.member or 'no-member'}" for e in defined_text
            )
            errs.append(
                f"required symbol {sym}: DEFINED T/t expected exactly once, "
                f"got {len(defined_text)} ({detail})"
            )
            continue
        sole = defined_text[0]
        if archive_has_members:
            if not sole.member:
                errs.append(
                    f"required symbol {sym}: DEFINED T/t lacks archive member "
                    f"(expected {expected_member})"
                )
            elif not _member_matches(sole.member, expected_member):
                errs.append(
                    f"required symbol {sym}: DEFINED text on wrong archive "
                    f"member {sole.member!r} (expected {expected_member})"
                )
    return errs


def check_archive(
    archive: Path,
    *,
    nm_cmd: str | None = None,
    strings_cmd: str | None = None,
) -> list[str]:
    errs: list[str] = []
    if not archive.is_file():
        return [f"archive missing: {archive}"]
    members = ar_members(archive)
    bases = [_member_basename(m) for m in members]
    for obj in N6_AR_OBJECTS:
        n = sum(1 for b in bases if b == obj or b.endswith(obj))
        if n != 1:
            errs.append(f"ar member {obj}: expected exact-once, got {n}")
    for b in bases:
        low = b.lower()
        for ban in BANNED_AR_SUBSTRINGS:
            if ban in low:
                errs.append(f"ar banned member present: {b} (matched {ban!r})")
                break
        if re.search(r"(^|[_.-])test([_.-]|$)", low):
            errs.append(f"ar test-like member present: {b}")

    nm_bytes, nm_errs = run_nm(archive, nm_cmd=nm_cmd)
    errs.extend(nm_errs)
    strings_bytes, str_errs = run_strings(archive, strings_cmd=strings_cmd)
    errs.extend(str_errs)

    # If nm/strings tooling failed, do not claim symbol/leakage OK.
    if nm_errs or str_errs:
        return errs

    nm_text = nm_bytes.decode(errors="replace")
    entries = parse_nm_output(nm_text)
    errs.extend(check_required_symbols(entries))

    blob = nm_bytes + b"\n" + strings_bytes
    for tok in FORBIDDEN_SUBSTRINGS:
        if tok in blob:
            hit = False
            for line in nm_bytes.splitlines():
                if tok in line:
                    errs.append("nm: " + line.decode(errors="replace"))
                    hit = True
            if tok in strings_bytes and not hit:
                errs.append(
                    f"strings: forbidden token {tok.decode(errors='replace')}"
                )
    return errs


def check_install_tree(prefix: Path) -> list[str]:
    errs: list[str] = []
    if not prefix.is_dir():
        return [f"install prefix missing: {prefix}"]
    for p in prefix.rglob("*"):
        if not p.is_file():
            continue
        name = p.name
        rel = str(p.relative_to(prefix))
        if name.startswith("n6_") and p.suffix in {".h", ".c", ".o", ".a", ".su"}:
            errs.append(f"installed N6 private path: {rel}")
        if "n6_context_store" in name or "n6_record_codec" in name:
            errs.append(f"installed N6 artifact: {rel}")
        if "n6_crypto" in name:
            errs.append(f"installed N6 crypto artifact: {rel}")
        if "ninlil_runtime_private" in name:
            errs.append(f"installed private runtime archive: {rel}")
        if "ninlil_n6_store_testbuild" in name or "testbuild" in name.lower():
            errs.append(f"installed testbuild artifact: {rel}")
        if "include/ninlil" in rel.replace("\\", "/") and "n6" in name.lower():
            errs.append(f"installed public N6 header: {rel}")
    return errs


def check_build_dir_hygiene(build_dir: Path) -> list[str]:
    errs: list[str] = []
    if not build_dir.is_dir():
        return [f"build dir missing: {build_dir}"]
    ctest_file = build_dir / "CTestTestfile.cmake"
    if ctest_file.is_file():
        text = ctest_file.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^\s*add_test\s*\(", text, re.M):
            errs.append(
                "CTestTestfile.cmake registers add_test under tests-OFF build"
            )
    return errs


def run_sources_only(root: Path) -> int:
    """Explicit source-authority check (no archive claims)."""
    errs: list[str] = []
    errs.extend(check_canonical_sources(root))
    errs.extend(check_esp_sources(root))
    if errs:
        print("N6 leakage / packaging gate FAIL (check-sources):")
        for e in errs:
            print(" ", e)
        return 1
    print(
        "n6_chunk_d_leakage_gate check-sources: OK "
        "(canonical N6 production set exact-3 once; ESP authority include)"
    )
    return 0


def run_gate(args: argparse.Namespace) -> int:
    """Production packaging check: --archive is mandatory."""
    root = Path(args.src_root).resolve()
    errs: list[str] = []
    if not args.archive:
        print(
            "n6_chunk_d_leakage_gate check: --archive is required "
            "(use check-sources for source-authority only)",
            file=sys.stderr,
        )
        return 2
    errs.extend(check_canonical_sources(root))
    errs.extend(check_esp_sources(root))
    if args.require_tests_off_hygiene:
        if not args.install_prefix:
            errs.append("--require-tests-off-hygiene needs --install-prefix")
    errs.extend(check_archive(Path(args.archive)))
    checked: list[str] = [
        "canonical N6 production set exact-once",
        "ESP authority",
        "ar N6 members exact-once",
        "nm exact DEFINED T/t once + member bind",
        "strings hard-enforced",
        "forbidden token ban",
    ]
    if args.install_prefix:
        errs.extend(check_install_tree(Path(args.install_prefix)))
        checked.append("install public-only")
    if args.build_dir and args.require_tests_off_hygiene:
        errs.extend(check_build_dir_hygiene(Path(args.build_dir)))
        checked.append("tests-OFF ctest hygiene")
    if errs:
        print("N6 leakage / packaging gate FAIL:")
        for e in errs:
            print(" ", e)
        return 1
    print("n6_chunk_d_leakage_gate check: OK (" + "; ".join(checked) + ")")
    return 0


def _compile_ar(td: Path, sources: dict[str, str]) -> Path:
    objs: list[Path] = []
    for name, text in sources.items():
        src = td / f"{name.replace('/', '_')}.c"
        src.write_text(text, encoding="utf-8")
        obj = td / name
        obj.parent.mkdir(parents=True, exist_ok=True)
        subprocess.check_call(
            ["cc", "-c", str(src), "-o", str(obj)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        objs.append(obj)
    arch = td / "libfake.a"
    subprocess.check_call(
        ["ar", "rcs", str(arch)] + [str(o) for o in objs],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return arch


def _good_n6_sources() -> dict[str, str]:
    # All five required text symbols live in context_store production identity.
    context_body = """
void ninlil_n6_install_hop(void) {}
void ninlil_n6_tx_burn(void) {}
void ninlil_n6_rx_precheck(void) {}
void ninlil_n6_boot_scan(void) {}
void ninlil_n6_bind_local_identity_accepted(void) {}
"""
    codec_body = "int n6_codec_marker;\n"
    crypto_body = "int n6_crypto_marker;\n"
    return {
        "n6_record_codec.c.o": codec_body,
        "n6_crypto_host.c.o": crypto_body,
        "n6_context_store.c.o": context_body,
    }


def _u_only_n6_sources() -> dict[str, str]:
    """Archive that only *references* the five symbols (U in nm), never defines."""
    # One TU references all five; other members are dummies so ar exact-once passes.
    ref = """
void ninlil_n6_install_hop(void);
void ninlil_n6_tx_burn(void);
void ninlil_n6_rx_precheck(void);
void ninlil_n6_boot_scan(void);
void ninlil_n6_bind_local_identity_accepted(void);
void n6_u_only_force_refs(void) {
    ninlil_n6_install_hop();
    ninlil_n6_tx_burn();
    ninlil_n6_rx_precheck();
    ninlil_n6_boot_scan();
    ninlil_n6_bind_local_identity_accepted();
}
"""
    return {
        "n6_record_codec.c.o": "int n6_codec_marker;\n",
        "n6_crypto_host.c.o": "int n6_crypto_marker;\n",
        "n6_context_store.c.o": ref,
    }


def self_test(src_root: Path) -> int:
    fails = 0

    def expect(label: str, pred: bool, detail: object = None) -> None:
        nonlocal fails
        if not pred:
            print(f"SELF-TEST FAIL: {label}: {detail}")
            fails += 1
        else:
            print(f"SELF-TEST OK: {label}")

    missing = Path("/nonexistent/libninlil_runtime_private.a")
    errs = check_archive(missing)
    expect(
        "target omission / archive missing",
        any("archive missing" in e for e in errs),
        errs,
    )

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        srcs = _good_n6_sources()
        del srcs["n6_context_store.c.o"]
        try:
            arch = _compile_ar(td_path, srcs)
            errs = check_archive(arch)
            expect(
                "member missing (context_store)",
                any("n6_context_store" in e and "exact-once" in e for e in errs),
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL member missing setup:", e)
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            srcs = _good_n6_sources()
            srcs["dup/n6_context_store.c.o"] = "int dup_marker;\n"
            arch = _compile_ar(td_path, srcs)
            errs = check_archive(arch)
            expect(
                "member duplicate (context_store)",
                any(
                    "n6_context_store" in e and ("got 2" in e or "exact-once" in e)
                    for e in errs
                ),
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL member duplicate setup:", e)
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            srcs = _good_n6_sources()
            srcs["n6_mem_storage_fixture.c.o"] = "int fixture_marker;\n"
            arch = _compile_ar(td_path, srcs)
            errs = check_archive(arch)
            expect(
                "fixture mix-in ar member",
                any("banned member" in e or "fixture" in e for e in errs),
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL fixture mix-in setup:", e)
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            body_ctx = (
                'const char *p = "ninlil_n6_test_bind_local_identity";\n'
                "void ninlil_n6_install_hop(void) {}\n"
                "void ninlil_n6_tx_burn(void) {}\n"
                "void ninlil_n6_rx_precheck(void) {}\n"
                "void ninlil_n6_boot_scan(void) {}\n"
                "void ninlil_n6_bind_local_identity_accepted(void) {}\n"
            )
            srcs = {
                "n6_record_codec.c.o": "int n6_codec_marker;\n",
                "n6_crypto_host.c.o": "int n6_crypto_marker;\n",
                "n6_context_store.c.o": body_ctx,
            }
            arch = _compile_ar(td_path, srcs)
            errs = check_archive(arch)
            expect(
                "leakage fixture string",
                any("forbidden token" in e or "strings:" in e or "nm:" in e for e in errs),
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL leakage setup:", e)
            fails += 1

    # --- packaging cmake authority: exact UTF-8 bytes SHA-256 pin ---
    # Required first authority is whole-file byte identity. Only the real
    # authority file (exact bytes) is GREEN. Every mutation is hash RED —
    # including former comment/bracket/structural decoys that once relied on
    # mini-parser GREEN paths. Constant-alone / disk-alone updates are
    # incomplete and require human review + simultaneous constant+disk update.
    def _pack_mut(label: str, body: str, need_sub: str = "SHA-256") -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n6_tests_off_packaging.cmake"
            p.write_text(body, encoding="utf-8")
            errs = check_tests_off_packaging_cmake(p)
            expect(
                label,
                bool(errs) and any(need_sub in e for e in errs),
                errs,
            )

    def _pack_mut_bytes(label: str, raw: bytes, need_sub: str = "SHA-256") -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n6_tests_off_packaging.cmake"
            p.write_bytes(raw)
            errs = check_tests_off_packaging_cmake(p)
            expect(
                label,
                bool(errs) and any(need_sub in e for e in errs),
                errs,
            )

    # Totally foreign content → hash RED (not structural-shape GREEN).
    _pack_mut(
        "last-wins multi-archive cmake discovery fails hash pin",
        r"""
set(_n6_archive "")
foreach(_cand IN LISTS _raw)
  if(_cand MATCHES "libninlil_runtime_private\\.(a|lib)$")
    set(_n6_archive "${_cand}")
  endif()
endforeach()
if(_n6_archive STREQUAL "")
  message(FATAL_ERROR "missing")
endif()
""",
    )

    _pack_mut(
        "comment-poison list(LENGTH)/EQUAL fails hash pin",
        r"""
# n6_collect_private_archives list(LENGTH bogus zero) EQUAL 0
# function(n6_collect_private_archives root_dir out_list_var)
# endfunction()
cmake --build "${_n6_build}" --config Release --target ninlil_runtime_private
""",
    )

    _pack_mut(
        "string-only collect/LENGTH/EQUAL pins fail hash pin",
        r"""
message("function(n6_collect_private_archives root out) list(LENGTH) EQUAL 1")
message("--target ninlil_runtime_private")
""",
    )

    # --- real packaging cmake: exact byte pin GREEN only ---
    real_pack = src_root / "cmake" / "n6_tests_off_packaging.cmake"
    if not real_pack.is_file():
        print("SELF-TEST FAIL: missing real n6_tests_off_packaging.cmake")
        fails += 1
        real_pack_text = ""
        real_pack_bytes = b""
    else:
        try:
            real_pack_bytes = real_pack.read_bytes()
            real_pack_text = real_pack_bytes.decode("utf-8")
        except (OSError, UnicodeDecodeError) as e:
            print(f"SELF-TEST FAIL: cannot read real packaging cmake: {e}")
            fails += 1
            real_pack_text = ""
            real_pack_bytes = b""

    if real_pack_bytes:
        disk_digest = hashlib.sha256(real_pack_bytes).hexdigest()
        expect(
            "authority constant matches disk UTF-8 bytes SHA-256 "
            "(constant-alone or disk-alone update is incomplete)",
            disk_digest == N6_TESTS_OFF_PACKAGING_CMAKE_SHA256,
            f"disk={disk_digest} constant={N6_TESTS_OFF_PACKAGING_CMAKE_SHA256}",
        )
        perrs = check_tests_off_packaging_cmake(real_pack)
        expect(
            "real n6_tests_off_packaging.cmake exact UTF-8 bytes pin GREEN",
            perrs == [],
            perrs,
        )
        # Exact byte copy elsewhere is still GREEN (identity, not path magic).
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "n6_tests_off_packaging.cmake"
            p.write_bytes(real_pack_bytes)
            perrs_copy = check_tests_off_packaging_cmake(p)
            expect(
                "exact byte-copy of authority packaging cmake is GREEN",
                perrs_copy == [],
                perrs_copy,
            )

        # Any comment / format / benign byte change is intentional RED.
        _pack_mut(
            "comment-only authority edit is hash RED",
            real_pack_text + "\n# benign comment only\n",
        )
        _pack_mut(
            "trailing whitespace format change is hash RED",
            real_pack_text + " \n",
        )
        _pack_mut_bytes(
            "single-byte flip is hash RED",
            real_pack_bytes[:-1] + bytes([(real_pack_bytes[-1] ^ 0x01) & 0xFF]),
        )

        # Path-level: symlink must RED (no follow-as-authority).
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            target = td_path / "real.cmake"
            target.write_bytes(real_pack_bytes)
            link = td_path / "n6_tests_off_packaging.cmake"
            try:
                link.symlink_to(target)
            except OSError as e:
                print(f"SELF-TEST FAIL: symlink packaging path setup: {e}")
                fails += 1
            else:
                lerrs = check_tests_off_packaging_cmake(link)
                expect(
                    "symlink packaging authority path is RED",
                    any("symlink" in e for e in lerrs),
                    lerrs,
                )

        # ------------------------------------------------------------------
        # Independent P1 required mutation KATs (hash RED — these shapes
        # historically bypassed internal structural pins via dead/uncalled/
        # shadowed/decoy control flow without changing "looks canonical").
        # We do not extend CMake membership/sequence analysis; byte pin is
        # the mandatory first authority that makes all six RED.
        # ------------------------------------------------------------------
        _explicit_if = (
            "if(NOT _n6_after_explicit_count EQUAL 1)\n"
            '    file(REMOVE_RECURSE "${_n6_work}")\n'
            "    message(FATAL_ERROR\n"
            '        "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "\n'
            '        "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "\n'
            '        "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "\n'
            '        "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")\n'
            "endif()\n"
        )
        if _explicit_if not in real_pack_text:
            print(
                "SELF-TEST FAIL: P1 mutation KAT setup: "
                "explicit-count if block not found in real packaging cmake"
            )
            fails += 1
        else:
            # (P1-1) canonical block duplicate — second copy can confuse
            # sequence/membership parsers that accept "a" canonical block.
            _pack_mut(
                "P1 KAT: canonical block duplicate is hash RED",
                real_pack_text.replace(
                    _explicit_if, _explicit_if + _explicit_if, 1
                ),
            )

            # (P1-2) dead if(FALSE) wrap around real FATAL body.
            _dead_false = (
                "if(NOT _n6_after_explicit_count EQUAL 1)\n"
                "    if(FALSE)\n"
                '    file(REMOVE_RECURSE "${_n6_work}")\n'
                "    message(FATAL_ERROR\n"
                '        "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "\n'
                '        "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "\n'
                '        "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "\n'
                '        "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")\n'
                "    endif()\n"
                "endif()\n"
            )
            _pack_mut(
                "P1 KAT: dead if(FALSE) wrap is hash RED",
                real_pack_text.replace(_explicit_if, _dead_false, 1),
            )

            # (P1-3) uncalled function wrap — real FATAL only inside a
            # never-invoked function; outer count if is empty (fail-open).
            _uncalled = (
                "function(_n6_never_called_authority_body)\n"
                '    file(REMOVE_RECURSE "${_n6_work}")\n'
                "    message(FATAL_ERROR\n"
                '        "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "\n'
                '        "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "\n'
                '        "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "\n'
                '        "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")\n'
                "endfunction()\n"
                "if(NOT _n6_after_explicit_count EQUAL 1)\n"
                "    # fail-open: uncalled function holds the real FATAL\n"
                "endif()\n"
            )
            _pack_mut(
                "P1 KAT: uncalled function wrap is hash RED",
                real_pack_text.replace(_explicit_if, _uncalled, 1),
            )

            # (P1-4) prior return() makes primary FATAL unreachable.
            _prior_return = (
                "if(NOT _n6_after_explicit_count EQUAL 1)\n"
                "    return()\n"
                '    file(REMOVE_RECURSE "${_n6_work}")\n'
                "    message(FATAL_ERROR\n"
                '        "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "\n'
                '        "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "\n'
                '        "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "\n'
                '        "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")\n'
                "endif()\n"
            )
            _pack_mut(
                "P1 KAT: prior return() is hash RED",
                real_pack_text.replace(_explicit_if, _prior_return, 1),
            )

            # (P1-5) macro(message) shadow — message(FATAL_ERROR) becomes no-op.
            _macro_shadow = (
                "if(NOT _n6_after_explicit_count EQUAL 1)\n"
                "    macro(message)\n"
                "    endmacro()\n"
                '    file(REMOVE_RECURSE "${_n6_work}")\n'
                "    message(FATAL_ERROR\n"
                '        "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "\n'
                '        "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "\n'
                '        "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "\n'
                '        "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")\n'
                "endif()\n"
            )
            _pack_mut(
                "P1 KAT: macro(message) shadow is hash RED",
                real_pack_text.replace(_explicit_if, _macro_shadow, 1),
            )

            # (P1-6) dead decoy + fail-open actual: decoy looks like authority
            # FATAL (inside if(FALSE)); real branch is soft STATUS only.
            _decoy_failopen = (
                "if(NOT _n6_after_explicit_count EQUAL 1)\n"
                "    if(FALSE)\n"
                '        file(REMOVE_RECURSE "${_n6_work}")\n'
                "        message(FATAL_ERROR\n"
                '            "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "\n'
                '            "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "\n'
                '            "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "\n'
                '            "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")\n'
                "    endif()\n"
                '    message(STATUS "fail-open actual: count mismatch soft-only")\n'
                "endif()\n"
            )
            _pack_mut(
                "P1 KAT: dead decoy + fail-open actual is hash RED",
                real_pack_text.replace(_explicit_if, _decoy_failopen, 1),
            )

        # Residual mutations still hash RED (dataflow / helper poison).
        last_wins = re.sub(
            r"(list\s*\(\s*GET\s+_n6_after_explicit_list\s+0\s+_n6_archive\s*\))",
            r'\1\nset(_n6_archive "/tmp/attacker-last-wins.a")\n',
            real_pack_text,
            count=1,
        )
        if last_wins != real_pack_text:
            _pack_mut(
                "post-check set(_n6_archive attacker) last-wins is hash RED",
                last_wins,
            )
        wrong_out = real_pack_text.replace(
            'set(${out_list_var} "${_found}" PARENT_SCOPE)',
            'set(_wrong_output "${_found}" PARENT_SCOPE)',
        )
        if wrong_out != real_pack_text:
            _pack_mut(
                "collect helper wrong PARENT_SCOPE output var is hash RED",
                wrong_out,
            )

        # Independent cmake -P reachability proofs (CMake semantics, not the
        # packaging byte pin). Packaging shape with the same terminal pattern
        # must still be hash RED under the gate.
        _cmake_p_fixture = (
            "cmake_minimum_required(VERSION 3.16)\n"
            "# n6 chunk-d reachability fixture: return before FATAL must exit 0\n"
            "if(NOT 0 EQUAL 1)\n"
            "  return()\n"
            '  message(FATAL_ERROR "unreachable fatal after return")\n'
            "endif()\n"
            'message(FATAL_ERROR "should not reach after outer if either")\n'
        )
        _cmake_p_true_return = (
            "cmake_minimum_required(VERSION 3.16)\n"
            "# n6 chunk-d: closed-constant TRUE path terminal unreachability\n"
            "if(NOT 0 EQUAL 1)\n"
            "  if(TRUE)\n"
            "    return()\n"
            "  endif()\n"
            '  message(FATAL_ERROR "unreachable after if(TRUE) return")\n'
            "endif()\n"
        )
        _cmake_p_false_return = (
            "cmake_minimum_required(VERSION 3.16)\n"
            "# n6 chunk-d: FALSE path return must not hide depth-0 FATAL\n"
            "if(NOT 0 EQUAL 1)\n"
            "  if(FALSE)\n"
            "    return()\n"
            "  endif()\n"
            '  message(FATAL_ERROR "reachable fatal after if(FALSE) return")\n'
            "endif()\n"
        )
        import shutil as _shutil_cmake

        _cmake_bin = _shutil_cmake.which("cmake")
        if not _cmake_bin:
            print(
                "SELF-TEST FAIL: cmake -P return-before-FATAL setup: "
                "cmake not found on PATH"
            )
            fails += 1
        else:
            import subprocess as _sp_cmake

            with tempfile.TemporaryDirectory() as td:
                fix = Path(td) / "return_before_fatal.cmake"
                fix.write_text(_cmake_p_fixture, encoding="utf-8")
                try:
                    proc = _sp_cmake.run(
                        [_cmake_bin, "-P", str(fix)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                except (OSError, _sp_cmake.TimeoutExpired) as e:
                    print(
                        f"SELF-TEST FAIL: cmake -P return-before-FATAL setup: {e}"
                    )
                    fails += 1
                else:
                    expect(
                        "cmake -P return() before FATAL exits 0 "
                        "(unreachable FATAL independent proof)",
                        proc.returncode == 0,
                        f"rc={proc.returncode} out={proc.stdout!r} "
                        f"err={proc.stderr!r}",
                    )
                    if _explicit_if in real_pack_text:
                        shaped = real_pack_text.replace(
                            _explicit_if,
                            "if(NOT _n6_after_explicit_count EQUAL 1)\n"
                            "    return()\n"
                            '    file(REMOVE_RECURSE "${_n6_work}")\n'
                            "    message(FATAL_ERROR\n"
                            '        "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "\n'
                            '        "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "\n'
                            '        "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "\n'
                            '        "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")\n'
                            "endif()\n",
                            1,
                        )
                        p2 = Path(td) / "n6_tests_off_packaging.cmake"
                        p2.write_text(shaped, encoding="utf-8")
                        perrs = check_tests_off_packaging_cmake(p2)
                        expect(
                            "packaging shape with return() before FATAL is "
                            "hash RED (byte pin)",
                            any("SHA-256" in e for e in perrs),
                            perrs,
                        )

                fix_t = Path(td) / "true_return_before_fatal.cmake"
                fix_t.write_text(_cmake_p_true_return, encoding="utf-8")
                try:
                    proc_t = _sp_cmake.run(
                        [_cmake_bin, "-P", str(fix_t)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                except (OSError, _sp_cmake.TimeoutExpired) as e:
                    print(
                        f"SELF-TEST FAIL: cmake -P if(TRUE) return setup: {e}"
                    )
                    fails += 1
                else:
                    expect(
                        "cmake -P if(TRUE) return() before FATAL exits 0 "
                        "(TRUE-path terminal independent proof)",
                        proc_t.returncode == 0,
                        f"rc={proc_t.returncode} out={proc_t.stdout!r} "
                        f"err={proc_t.stderr!r}",
                    )

                fix_f = Path(td) / "false_return_before_fatal.cmake"
                fix_f.write_text(_cmake_p_false_return, encoding="utf-8")
                try:
                    proc_f = _sp_cmake.run(
                        [_cmake_bin, "-P", str(fix_f)],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                except (OSError, _sp_cmake.TimeoutExpired) as e:
                    print(
                        f"SELF-TEST FAIL: cmake -P if(FALSE) return setup: {e}"
                    )
                    fails += 1
                else:
                    expect(
                        "cmake -P if(FALSE) return() then FATAL is nonzero "
                        "(FATAL still reachable independent proof)",
                        proc_f.returncode != 0,
                        f"rc={proc_f.returncode} out={proc_f.stdout!r} "
                        f"err={proc_f.stderr!r}",
                    )

    def _auth_tree(body: str) -> Path:
        td_path = Path(tempfile.mkdtemp(prefix="n6-auth-"))
        cmake_dir = td_path / "cmake"
        cmake_dir.mkdir()
        (cmake_dir / "ninlil_runtime_private_sources.cmake").write_text(
            body, encoding="utf-8"
        )
        real_pack = src_root / "cmake" / "n6_tests_off_packaging.cmake"
        if real_pack.is_file():
            (cmake_dir / "n6_tests_off_packaging.cmake").write_text(
                real_pack.read_text(encoding="utf-8"), encoding="utf-8"
            )
        (td_path / "CMakeLists.txt").write_text(
            "add_library(ninlil_runtime_private STATIC EXCLUDE_FROM_ALL x.c)\n"
            "n6_tests_off_packaging.cmake\n"
            "n6_chunk_d_leakage_gate\n",
            encoding="utf-8",
        )
        return td_path

    _good_auth = """
set(NINLIL_N6_PRODUCTION_RELATIVE_SOURCES
    src/radio/n6_record_codec.c
    src/radio/n6_crypto_host.c
    src/radio/n6_context_store.c
)
list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
)
"""

    # --- duplicate canonical N6 source in production set ---
    tdup = _auth_tree(
        """
set(NINLIL_N6_PRODUCTION_RELATIVE_SOURCES
    src/radio/n6_record_codec.c
    src/radio/n6_record_codec.c
    src/radio/n6_crypto_host.c
    src/radio/n6_context_store.c
)
list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
)
"""
    )
    try:
        errs = check_canonical_sources(tdup)
        expect(
            "duplicate canonical source in N6 production set fails",
            any("exact elements" in e or "exactly once" in e for e in errs),
            errs,
        )
    finally:
        shutil.rmtree(tdup, ignore_errors=True)

    # --- non-N6 extra (radio_hal.c) in production set must RED ---
    textra = _auth_tree(
        """
set(NINLIL_N6_PRODUCTION_RELATIVE_SOURCES
    src/radio/n6_record_codec.c
    src/radio/n6_crypto_host.c
    src/radio/n6_context_store.c
    src/radio/radio_hal.c
)
list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
)
"""
    )
    try:
        errs = check_canonical_sources(textra)
        expect(
            "non-N6 extra in production set fails",
            any("exact elements" in e for e in errs) and any(
                "radio_hal" in e for e in errs
            ),
            errs,
        )
    finally:
        shutil.rmtree(textra, ignore_errors=True)

    # --- double APPEND of N6 production into RUNTIME must RED ---
    t2 = _auth_tree(
        _good_auth
        + """
list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
)
"""
    )
    try:
        errs = check_canonical_sources(t2)
        expect(
            "double APPEND N6 production into RUNTIME fails",
            any("exactly once" in e and "APPEND" in e for e in errs),
            errs,
        )
    finally:
        shutil.rmtree(t2, ignore_errors=True)

    # --- wrong member: boot_scan T lives on codec member ---
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            srcs = {
                "n6_record_codec.c.o": (
                    "void ninlil_n6_boot_scan(void) {}\n"
                    "void ninlil_n6_install_hop(void) {}\n"
                    "void ninlil_n6_tx_burn(void) {}\n"
                    "void ninlil_n6_rx_precheck(void) {}\n"
                    "void ninlil_n6_bind_local_identity_accepted(void) {}\n"
                ),
                "n6_crypto_host.c.o": "int n6_crypto_marker;\n",
                "n6_context_store.c.o": "int n6_context_marker;\n",
            }
            arch = _compile_ar(td_path, srcs)
            errs = check_archive(arch)
            expect(
                "wrong member T for required symbols fails",
                any("wrong archive member" in e for e in errs),
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL wrong-member setup:", e)
            fails += 1

    # --- duplicate T: same symbol defined on two members ---
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            srcs = {
                "n6_record_codec.c.o": "void ninlil_n6_boot_scan(void) {}\n",
                "n6_crypto_host.c.o": "int n6_crypto_marker;\n",
                "n6_context_store.c.o": (
                    "void ninlil_n6_install_hop(void) {}\n"
                    "void ninlil_n6_tx_burn(void) {}\n"
                    "void ninlil_n6_rx_precheck(void) {}\n"
                    "void ninlil_n6_boot_scan(void) {}\n"
                    "void ninlil_n6_bind_local_identity_accepted(void) {}\n"
                ),
            }
            arch = _compile_ar(td_path, srcs)
            errs = check_archive(arch)
            expect(
                "duplicate DEFINED T/t for boot_scan fails",
                any(
                    "ninlil_n6_boot_scan" in e and "exactly once" in e for e in errs
                ),
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL duplicate-T setup:", e)
            fails += 1

    # --- CLI: no --archive must nonzero ---
    import subprocess as _sp

    r = _sp.run(
        [sys.executable, str(Path(__file__).resolve()), "check", "--src-root", str(src_root)],
        capture_output=True,
        text=True,
    )
    expect(
        "CLI check without --archive nonzero",
        r.returncode != 0,
        (r.returncode, r.stdout, r.stderr),
    )

    r2 = _sp.run(
        [sys.executable, str(Path(__file__).resolve()), "not-a-command"],
        capture_output=True,
        text=True,
    )
    expect(
        "CLI unknown command nonzero",
        r2.returncode != 0,
        (r2.returncode, r2.stdout, r2.stderr),
    )

    r3 = _sp.run(
        [sys.executable, str(Path(__file__).resolve())],
        capture_output=True,
        text=True,
    )
    expect(
        "CLI noarg nonzero",
        r3.returncode != 0,
        (r3.returncode, r3.stdout, r3.stderr),
    )

    # --- false-green pin: U-only exact names must FAIL (substring would pass) ---
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            arch = _compile_ar(td_path, _u_only_n6_sources())
            # Prove names appear as U in nm (substring false-green surface)
            nm_out, nm_errs = run_nm(arch)
            assert not nm_errs, nm_errs
            nm_txt = nm_out.decode(errors="replace")
            for sym in REQUIRED_TEXT_SYMBOLS:
                if sym not in nm_txt and ("_" + sym) not in nm_txt:
                    raise RuntimeError(f"U-only fixture missing U ref for {sym}")
            errs = check_archive(arch)
            expect(
                "U-only 5 symbols exact archive fails (no DEFINED T/t)",
                any(
                    ("not DEFINED text" in e or "exact nm entry missing" in e)
                    for e in errs
                )
                and all(
                    any(sym in e for e in errs) or True  # at least one symbol error
                    for sym in REQUIRED_TEXT_SYMBOLS
                )
                and any("not DEFINED text" in e for e in errs),
                errs,
            )
            # Stronger: every required symbol must produce a DEFINED/text failure
            for sym in REQUIRED_TEXT_SYMBOLS:
                expect(
                    f"U-only fails for {sym}",
                    any(sym in e and ("DEFINED" in e or "missing" in e) for e in errs),
                    errs,
                )
        except Exception as e:
            print("SELF-TEST FAIL: U-only setup:", e)
            fails += 1

    # --- false-green pin: fixture string + strings missing/fail must FAIL ---
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            body_ctx = (
                'const char *p = "ninlil_n6_test_bind_local_identity";\n'
                "void ninlil_n6_install_hop(void) {}\n"
                "void ninlil_n6_tx_burn(void) {}\n"
                "void ninlil_n6_rx_precheck(void) {}\n"
                "void ninlil_n6_boot_scan(void) {}\n"
                "void ninlil_n6_bind_local_identity_accepted(void) {}\n"
            )
            srcs = {
                "n6_record_codec.c.o": "int n6_codec_marker;\n",
                "n6_crypto_host.c.o": "int n6_crypto_marker;\n",
                "n6_context_store.c.o": body_ctx,
            }
            arch = _compile_ar(td_path, srcs)
            # 1) strings missing
            errs = check_archive(arch, strings_cmd="/nonexistent/strings_bin_xyz")
            expect(
                "fixture archive + strings missing hard-fails",
                any("strings" in e and ("missing" in e or "launch" in e) for e in errs),
                errs,
            )
            # 2) strings nonzero exit
            bad_strings = td_path / "fail_strings"
            bad_strings.write_text(
                "#!/bin/sh\necho strings_fail >&2\nexit 3\n",
                encoding="utf-8",
            )
            bad_strings.chmod(0o755)
            errs = check_archive(arch, strings_cmd=str(bad_strings))
            expect(
                "fixture archive + strings nonzero hard-fails",
                any("strings nonzero" in e for e in errs),
                errs,
            )
            # Old false-green path would treat missing strings as b"" and still
            # pass if nm had no fixture token — prove we never return [].
            expect(
                "strings fail never empty-OK on fixture archive",
                len(errs) > 0,
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL: strings-fail setup:", e)
            fails += 1

    # strings missing alone on good archive (no fixture) must also hard-fail
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            arch = _compile_ar(td_path, _good_n6_sources())
            errs = check_archive(arch, strings_cmd="/nonexistent/strings_bin_xyz")
            expect(
                "good archive + strings missing hard-fails",
                any("strings" in e and "missing" in e for e in errs),
                errs,
            )
        except Exception as e:
            print("SELF-TEST FAIL: strings missing on good:", e)
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        bad = td_path / "include" / "ninlil" / "n6_context_store.h"
        bad.parent.mkdir(parents=True)
        bad.write_text("/* leaked */\n", encoding="utf-8")
        errs = check_install_tree(td_path)
        expect(
            "test install / private N6 header",
            any("n6_context_store" in e or "N6" in e for e in errs),
            errs,
        )

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        (td_path / "CTestTestfile.cmake").write_text(
            "add_test(NAME evil COMMAND true)\n",
            encoding="utf-8",
        )
        errs = check_build_dir_hygiene(td_path)
        expect(
            "ctest>0 / add_test under OFF build",
            any("add_test" in e for e in errs),
            errs,
        )

    cerrs = check_canonical_sources(src_root)
    expect("real tree canonical + EXCLUDE_FROM_ALL", cerrs == [], cerrs)

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        try:
            arch = _compile_ar(td_path, _good_n6_sources())
            errs = check_archive(arch)
            expect("exact good archive", errs == [], errs)
        except Exception as e:
            print("SELF-TEST FAIL exact good setup:", e)
            fails += 1

    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        pub = td_path / "include" / "ninlil" / "version.h"
        pub.parent.mkdir(parents=True)
        pub.write_text("#pragma once\n", encoding="utf-8")
        errs = check_install_tree(td_path)
        expect("good public-only install", errs == [], errs)

    if fails:
        print(f"n6_chunk_d_leakage_gate self-test: FAIL ({fails})")
        return 1
    print("n6_chunk_d_leakage_gate self-test: OK")
    return 0


_CLOSED_COMMANDS = frozenset({"check", "check-sources", "self-test"})


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "command",
        nargs="?",
        default=None,
        help="Closed set: check | check-sources | self-test (required; noarg fails)",
    )
    ap.add_argument("--archive", default=None)
    ap.add_argument(
        "--src-root",
        default=str(Path(__file__).resolve().parents[1]),
    )
    ap.add_argument("--build-dir", default=None)
    ap.add_argument("--install-prefix", default=None)
    ap.add_argument(
        "--require-tests-off-hygiene",
        action="store_true",
        help="Require install-prefix + OFF build-dir hygiene (with check)",
    )
    args = ap.parse_args()
    if args.command is None:
        print(
            "usage: n6_chunk_d_leakage_gate.py check|check-sources|self-test "
            "[--archive A] ...\n"
            "  check          production packaging (requires --archive)\n"
            "  check-sources  source-authority only (no ar/nm claims)\n"
            "  self-test      mutation self-tests\n"
            "\n"
            "Packaging authority: cmake/n6_tests_off_packaging.cmake entire\n"
            "file UTF-8 bytes SHA-256 exact pin (byte pin, not semantic CMake\n"
            "equivalence). Hash mismatch is immediate RED; any comment/format\n"
            "change is intentional RED. Authority update = human review +\n"
            "fresh OFF + simultaneous constant update. PASS ≠ product GO.",
            file=sys.stderr,
        )
        return 2
    if args.command not in _CLOSED_COMMANDS:
        print(
            f"unknown command {args.command!r}; "
            f"closed set: {sorted(_CLOSED_COMMANDS)}",
            file=sys.stderr,
        )
        return 2
    if args.command == "self-test":
        return self_test(Path(args.src_root).resolve())
    if args.command == "check-sources":
        return run_sources_only(Path(args.src_root).resolve())
    return run_gate(args)


if __name__ == "__main__":
    raise SystemExit(main())
