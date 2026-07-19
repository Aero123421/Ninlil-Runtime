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
        "bc8633657a1033fb16cc473794ad8cfab54b17ec00a741814682194d5c7789f6",
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

# Structural RX/TX lane-index errata markers (docs/30 §20.12).
# Not NLP/C semantic proof: exact required substrings after pin match.
# Removing/relaxing any marker makes check_tree RED even if pins are co-updated.
RX_INDEX_ERRATA_STRUCTURAL_MARKERS: tuple[str, ...] = (
    "SEMANTIC: N6_PRIVATE_NAMED_LANE_COUNT_STATIC_ASSERT",
    "SEMANTIC: N6_RX_PRECHECK_WINDOW_LANE_IDX_GUARD",
    "SEMANTIC: N6_RX_PRECHECK_LANE_IDX_GUARD",
    "SEMANTIC: N6_RX_ADMIT_LANE_RANGE_LAYER_GUARD",
    "SEMANTIC: N6_TX_BURN_LANE_IDX_GUARD",
    "N6_PRIVATE_NAMED_LANE_COUNT",
    "n6_lane_idx_in_range",
    "n6_lane_ok_for_slot",
)

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


def _mask_c_lexical(text: str) -> str:
    """Length-preserving mask: blank comments + string/char literals.

    Replaces lexically non-code with spaces (newlines kept). Escape sequences
    inside strings/chars are consumed. Structural brace/paren/token checks MUST
    use this masked view so markers only in comments/strings cannot greenwash.
    """
    out: list[str] = [" "] * len(text)
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        # Newline always preserved for line structure.
        if ch == "\n":
            out[i] = "\n"
            i += 1
            continue
        # Line comment
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue
        # Block comment
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            out[i] = " "
            out[i + 1] = " "
            i += 2
            while i < n:
                if text[i] == "\n":
                    out[i] = "\n"
                    i += 1
                    continue
                if i + 1 < n and text[i] == "*" and text[i + 1] == "/":
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    break
                out[i] = " "
                i += 1
            continue
        # String literal
        if ch == '"':
            out[i] = " "
            i += 1
            while i < n:
                if text[i] == "\n":
                    out[i] = "\n"
                    i += 1
                    break
                if text[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == '"':
                    out[i] = " "
                    i += 1
                    break
                out[i] = " "
                i += 1
            continue
        # Char literal
        if ch == "'":
            out[i] = " "
            i += 1
            while i < n:
                if text[i] == "\n":
                    out[i] = "\n"
                    i += 1
                    break
                if text[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == "'":
                    out[i] = " "
                    i += 1
                    break
                out[i] = " "
                i += 1
            continue
        out[i] = ch
        i += 1
    return "".join(out)


def _strip_c_comments(text: str) -> str:
    """Backward-compat: comment strip only (prefer ``_mask_c_lexical``)."""
    return _mask_c_lexical(text)  # full lexical mask is a strict superset


def _extract_c_function_body(text: str, signature: str) -> str | None:
    """Brace-aware extraction of one *definition* body after ``signature``.

    Operates on already-masked text when possible. Skips forward declarations
    (signature followed by ';'). Brace matching ignores masked (blanked) regions
    because string/comment braces are already spaces.
    """
    pos = 0
    n = len(text)
    while True:
        pos = text.find(signature, pos)
        if pos < 0:
            return None
        # Walk to the parameter list of this hit.
        p0 = text.find("(", pos)
        if p0 < 0 or p0 > pos + len(signature) + 80:
            pos += 1
            continue
        p1 = _balanced_paren_end(text, p0)
        if p1 < 0:
            pos += 1
            continue
        j = p1 + 1
        while j < n and text[j] in " \t\r\n":
            j += 1
        if j < n and text[j] == ";":
            # Forward declaration — keep searching.
            pos = j + 1
            continue
        if j >= n or text[j] != "{":
            pos += 1
            continue
        brace = j
        depth = 0
        i = brace
        while i < n:
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[brace : i + 1]
            i += 1
        return None


def _balanced_paren_end(text: str, open_idx: int) -> int:
    """open_idx points at '('; return index of matching ')' or -1."""
    if open_idx < 0 or open_idx >= len(text) or text[open_idx] != "(":
        return -1
    depth = 0
    i = open_idx
    while i < len(text):
        ch = text[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _balanced_brace_end(text: str, open_idx: int) -> int:
    if open_idx < 0 or open_idx >= len(text) or text[open_idx] != "{":
        return -1
    depth = 0
    i = open_idx
    while i < len(text):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _norm_expr(expr: str) -> str:
    """Collapse whitespace for exact C expression comparison."""
    return re.sub(r"\s+", "", expr)


# Exact live if-conditions (no prefix 0&& / inverted / parenthesized variants).
_RE_RANGE_GUARD = re.compile(
    r"if\s*\(\s*!n6_lane_idx_in_range\s*\(\s*idx\s*\)\s*\)"
)
_RE_LAYER_GUARD = re.compile(
    r"if\s*\(\s*!n6_lane_ok_for_slot\s*\(\s*slot\s*,\s*tok\.lane_kind\s*\)\s*\)"
)
_RE_IDX_LANE = re.compile(r"idx\s*=\s*n6_lane_idx\s*\(\s*lane_kind\s*\)")
_RE_IDX_TOK = re.compile(r"idx\s*=\s*n6_lane_idx\s*\(\s*tok\.lane_kind\s*\)")
_RE_IF0 = re.compile(r"if\s*\(\s*0\s*\)")
# Dead condition prefix: if (0 && ...) — body never runs; call not live.
_RE_IF0_AND = re.compile(r"if\s*\(\s*0\s*&&")
# Exact n6_lane_idx_in_range return (idx>=0, not idx>=-1).
_RE_IN_RANGE_RETURN = re.compile(
    r"return\s+idx\s*>=\s*0\s*&&\s*idx\s*<\s*\(\s*int\s*\)\s*"
    r"N6_PRIVATE_NAMED_LANE_COUNT\s*;"
)
# Live CU validate call in apply (exact; 0&& form must not count).
_RE_CU_VALIDATE_IF = re.compile(
    r"if\s*\(\s*n6_cu_validate_array_posts\s*\(\s*n6\s*\)\s*!=\s*"
    r"NINLIL_N6_OK\s*\)"
)
_RE_CU_RANGE_GUARD = re.compile(
    r"if\s*\(\s*!n6_lane_idx_in_range\s*\(\s*expected\s*\)\s*\)"
)
_RE_CU_LAYER_GUARD = re.compile(
    r"if\s*\(\s*!n6_lane_ok_for_slot\s*\(\s*s\s*,\s*e->lane_kind\s*\)\s*\)"
)
_RE_CU_PREFLIGHT_IF = re.compile(
    r"if\s*\(\s*n6_cu_preflight_plan\s*\(\s*n6\s*\)\s*!=\s*NINLIL_N6_OK\s*\)"
)
# True no-CU only: exact conjunction (docs/30 §20.12; live=1 n_keys=0 → preflight).
_RE_RECOVER_TRUE_NO_CU = re.compile(
    r"if\s*\(\s*n6->cu\.live\s*==\s*0\s*&&\s*n6->cu\.n_keys\s*==\s*0u?\s*\)"
)
# Forbidden bypass: OR short-circuits preflight for live=1/n_keys=0 corrupt plans.
_RE_RECOVER_NO_CU_OR = re.compile(
    r"if\s*\(\s*n6->cu\.live\s*==\s*0\s*\|\|\s*n6->cu\.n_keys\s*==\s*0u?\s*\)"
)
_LANE_ARRAYS: tuple[str, ...] = (
    "tx_ram_next",
    "tx_ram_limit",
    "rx_live_reserved",
    "rx_boot_floor",
    "rx_ram_highest",
    "rx_bitmap",
)


def _norm_c_body(body: str) -> str:
    """Comment/string-masked body with whitespace collapsed for predicate pins."""
    return _norm_expr(_strip_c_comments(body))


def _if0_spans(body: str) -> list[tuple[int, int]]:
    """Spans of dead if(0){...} and if(0 && ...){...} (start inclusive, end exclusive)."""
    spans: list[tuple[int, int]] = []
    for m in _RE_IF0.finditer(body):
        # Skip bare if(0) that is really if(0 && ...) — handled below with wider span.
        rest = body[m.end() :]
        if rest.lstrip().startswith("&&"):
            continue
        i = m.end()
        while i < len(body) and body[i] in " \t\r\n":
            i += 1
        if i < len(body) and body[i] == "{":
            j = _balanced_brace_end(body, i)
            if j >= 0:
                spans.append((m.start(), j + 1))
    for m in _RE_IF0_AND.finditer(body):
        # Span covers the whole dead if-statement: condition + optional brace body.
        cond_open = body.find("(", m.start())
        cond_close = _balanced_paren_end(body, cond_open) if cond_open >= 0 else -1
        if cond_close < 0:
            continue
        i = cond_close + 1
        while i < len(body) and body[i] in " \t\r\n":
            i += 1
        if i < len(body) and body[i] == "{":
            j = _balanced_brace_end(body, i)
            if j >= 0:
                spans.append((m.start(), j + 1))
            else:
                spans.append((m.start(), cond_close + 1))
        else:
            # if (0 && ...) stmt; — treat condition as dead span
            semi = body.find(";", cond_close)
            end = semi + 1 if semi >= 0 else cond_close + 1
            spans.append((m.start(), end))
    return spans


def _is_live_pos(pos: int, dead_spans: Sequence[tuple[int, int]]) -> bool:
    return not any(a <= pos < b for a, b in dead_spans)


def _guard_block_after(body: str, match: re.Match[str]) -> str:
    """Return the brace-balanced block starting at the first { after match end."""
    i = match.end()
    while i < len(body) and body[i] in " \t\r\n":
        i += 1
    if i >= len(body) or body[i] != "{":
        return ""
    j = _balanced_brace_end(body, i)
    if j < 0:
        return ""
    return body[i : j + 1]


def _first_index(hay: str, needles: Sequence[str]) -> int:
    best = -1
    for n in needles:
        p = hay.find(n)
        if p >= 0 and (best < 0 or p < best):
            best = p
    return best


def _find_live_match(
    body: str, pattern: re.Pattern[str]
) -> re.Match[str] | None:
    """First regex match not nested inside if(0){...}."""
    dead = _if0_spans(body)
    for m in pattern.finditer(body):
        if _is_live_pos(m.start(), dead):
            return m
    return None


def _live_if_conditions(body: str) -> set[str]:
    """Return whitespace-normalized conditions from live ``if`` statements.

    Conditions nested inside ``if (0)`` or headed by ``if (0 && ...)`` are
    excluded.  This lets the structural authority pin an entire predicate,
    rather than accepting the desired tokens when they only survive inside a
    dead or weakened condition.
    """
    dead = _if0_spans(body)
    out: set[str] = set()
    for m in re.finditer(r"\bif\s*\(", body):
        if not _is_live_pos(m.start(), dead):
            continue
        p0 = body.find("(", m.start(), m.end())
        if p0 < 0:
            continue
        p1 = _balanced_paren_end(body, p0)
        if p1 < 0:
            continue
        out.add(_norm_expr(body[p0 + 1 : p1]))
    return out


def _live_if_then_else_blocks(body: str) -> list[tuple[str, str, str]]:
    """Live ``if (cond) { then } [else { else }]`` in source order.

    Returns ``(cond_norm, then_inner, else_inner)`` for each live brace-bodied
    ``if``. ``else_inner`` is ``""`` when no brace ``else`` follows. Nested
    ``if (0)`` / ``if (0 && ...)`` heads are excluded (same dead spans as
    :func:`_live_if_conditions`). Used to pin *each* occurrence of a repeated
    predicate to its intended brace-balanced role — set membership alone is
    insufficient when two sites share the same normalized condition.
    """
    dead = _if0_spans(body)
    out: list[tuple[str, str, str]] = []
    for m in re.finditer(r"\bif\s*\(", body):
        if not _is_live_pos(m.start(), dead):
            continue
        p0 = body.find("(", m.start(), m.end())
        if p0 < 0:
            continue
        p1 = _balanced_paren_end(body, p0)
        if p1 < 0:
            continue
        k = p1 + 1
        while k < len(body) and body[k] in " \t\r\n":
            k += 1
        if k >= len(body) or body[k] != "{":
            continue
        b1 = _balanced_brace_end(body, k)
        if b1 < 0:
            continue
        then_inner = body[k + 1 : b1]
        else_inner = ""
        j = b1 + 1
        while j < len(body) and body[j] in " \t\r\n":
            j += 1
        if (
            j + 4 <= len(body)
            and body.startswith("else", j)
            and (
                j + 4 >= len(body)
                or not (body[j + 4].isalnum() or body[j + 4] == "_")
            )
        ):
            j2 = j + 4
            while j2 < len(body) and body[j2] in " \t\r\n":
                j2 += 1
            if j2 < len(body) and body[j2] == "{":
                b2 = _balanced_brace_end(body, j2)
                if b2 >= 0:
                    else_inner = body[j2 + 1 : b2]
        out.append((_norm_expr(body[p0 + 1 : p1]), then_inner, else_inner))
    return out


def _static_assert_allowed_expr(arr: str) -> set[str]:
    """Normalized first-arg expressions allowed for named-lane array asserts."""
    base = f"((n6_slot_t*)0)->{arr}"
    # sizeof(array)/sizeof(array[0]) form and uint64_t element-size equivalent.
    return {
        f"sizeof({base})/sizeof({base}[0])==(size_t)N6_PRIVATE_NAMED_LANE_COUNT",
        f"(sizeof({base})/sizeof({base}[0]))==(size_t)N6_PRIVATE_NAMED_LANE_COUNT",
        f"sizeof({base})/sizeof(uint64_t)==(size_t)N6_PRIVATE_NAMED_LANE_COUNT",
        f"(sizeof({base})/sizeof(uint64_t))==(size_t)N6_PRIVATE_NAMED_LANE_COUNT",
    }


def _parse_lane_static_asserts(masked: str) -> dict[str, str]:
    """Map array name -> normalized first-arg expr for live top-level asserts.

    Requires exact allowed form (no ``1||expr`` / other tautologies).
    """
    found: dict[str, str] = {}
    bad: dict[str, str] = {}
    depth = 0
    i = 0
    n = len(masked)
    while i < n:
        if masked.startswith("_Static_assert", i) and depth == 0:
            if i > 0 and (masked[i - 1].isalnum() or masked[i - 1] == "_"):
                i += 1
                continue
            p0 = masked.find("(", i)
            if p0 < 0:
                i += 1
                continue
            p1 = _balanced_paren_end(masked, p0)
            if p1 < 0:
                i += 1
                continue
            j = p1 + 1
            while j < n and masked[j] in " \t\r\n":
                j += 1
            if j >= n or masked[j] != ";":
                i += 1
                continue
            # First argument only (before top-level comma at paren depth 1).
            inner = masked[p0 + 1 : p1]
            arg0 = ""
            d = 0
            for ch in inner:
                if ch == "(":
                    d += 1
                elif ch == ")":
                    d -= 1
                elif ch == "," and d == 0:
                    break
                arg0 += ch
            norm = _norm_expr(arg0)
            # Reject tautologies / short-circuit false-greens.
            if (
                norm.startswith("1||")
                or norm.startswith("1|")
                or "||" in norm
                or norm.startswith("0&&")
            ):
                for arr in _LANE_ARRAYS:
                    if arr in norm:
                        bad[arr] = norm
                i = j + 1
                continue
            for arr in _LANE_ARRAYS:
                if arr not in norm:
                    continue
                if norm in _static_assert_allowed_expr(arr):
                    found[arr] = norm
                else:
                    bad[arr] = norm
            i = j + 1
            continue
        ch = masked[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        i += 1
    # Stash bad forms via attribute for caller messaging
    _parse_lane_static_asserts.last_bad = bad  # type: ignore[attr-defined]
    return found


def _top_level_if_blocks(body: str) -> list[tuple[str, str, int, int]]:
    """Brace-aware top-level ``if (pred) { ... }`` inside a function body.

    ``body`` is the full ``{...}`` of a function (already lexically masked).
    Returns list of (predicate_norm, inner_block, if_start, after_block_end).
    Only ifs at brace-depth 1 (direct children of the function body) count.
    """
    out: list[tuple[str, str, int, int]] = []
    if not body or body[0] != "{":
        return out
    depth = 0
    i = 0
    n = len(body)
    while i < n:
        ch = body[i]
        if ch == "{":
            depth += 1
            i += 1
            continue
        if ch == "}":
            depth -= 1
            i += 1
            continue
        if (
            depth == 1
            and body.startswith("if", i)
            and (i == 0 or not (body[i - 1].isalnum() or body[i - 1] == "_"))
        ):
            j = i + 2
            if j < n and (body[j].isalnum() or body[j] == "_"):
                i += 1
                continue
            while j < n and body[j] in " \t\r\n":
                j += 1
            if j >= n or body[j] != "(":
                i += 1
                continue
            p1 = _balanced_paren_end(body, j)
            if p1 < 0:
                i += 1
                continue
            pred = body[j + 1 : p1]
            k = p1 + 1
            while k < n and body[k] in " \t\r\n":
                k += 1
            if k >= n or body[k] != "{":
                # Non-brace if body not allowed for this authority.
                out.append((_norm_expr(pred), "", i, p1 + 1))
                i = p1 + 1
                continue
            b1 = _balanced_brace_end(body, k)
            if b1 < 0:
                i += 1
                continue
            inner = body[k + 1 : b1]
            out.append((_norm_expr(pred), inner, i, b1 + 1))
            i = b1 + 1
            continue
        i += 1
    return out


def _block_is_only_return(inner: str, expected: str) -> bool:
    """True iff block body is solely ``return <expected>;`` (whitespace ok)."""
    # No other statements: after norm, must be exactly returnEXPECTED;
    return _norm_expr(inner) == f"return{expected};"


def _check_n6_lane_idx_helper(masked: str) -> list[str]:
    """Exact mapping with branch association (not independent return counts).

    DATA/E2E exact predicate block → only ``return 0;``
    ACK exact predicate block → only ``return 1;``
    default top-level tail → only ``return -1;``
    No extra ifs/returns/statements.
    """
    errs: list[str] = []
    body = _extract_c_function_body(masked, "static int n6_lane_idx(")
    if body is None:
        body = _extract_c_function_body(masked, "n6_lane_idx(")
    if body is None:
        return ["rx-index-errata structural: n6_lane_idx body missing"]

    data_e2e = {
        "lane_kind==NINLIL_N6_LANE_HOP_DATA||lane_kind==NINLIL_N6_LANE_E2E",
        "lane_kind==NINLIL_N6_LANE_E2E||lane_kind==NINLIL_N6_LANE_HOP_DATA",
    }
    ack = "lane_kind==NINLIL_N6_LANE_HOP_ACK"

    blocks = _top_level_if_blocks(body)
    if len(blocks) != 2:
        errs.append(
            "rx-index-errata structural: n6_lane_idx must have exactly two "
            f"top-level if branches (found {len(blocks)})"
        )
        return errs

    (p0, inner0, _s0, end0), (p1, inner1, _s1, end1) = blocks[0], blocks[1]

    if p0 not in data_e2e:
        errs.append(
            "rx-index-errata structural: n6_lane_idx first if must be exact "
            f"HOP_DATA||E2E (or reverse); got {p0!r}"
        )
    if p1 != ack:
        errs.append(
            "rx-index-errata structural: n6_lane_idx second if must be exact "
            f"HOP_ACK; got {p1!r}"
        )

    # Branch association: predicate → exact sole return (swap is RED).
    if p0 in data_e2e:
        if not _block_is_only_return(inner0, "0"):
            errs.append(
                "rx-index-errata structural: n6_lane_idx DATA/E2E branch must "
                f"contain only 'return 0;' (got block {_norm_expr(inner0)!r})"
            )
    if p1 == ack:
        if not _block_is_only_return(inner1, "1"):
            errs.append(
                "rx-index-errata structural: n6_lane_idx ACK branch must "
                f"contain only 'return 1;' (got block {_norm_expr(inner1)!r})"
            )

    # Default tail after last if: only return -1; (no extra if/return/stmt).
    # Function body is { ... }; strip outer braces for tail scan.
    if not body.startswith("{") or not body.endswith("}"):
        errs.append(
            "rx-index-errata structural: n6_lane_idx body missing outer braces"
        )
        return errs
    # Tail is from end of last if block to before final closing brace of function.
    tail = body[end1 : len(body) - 1]
    if not _block_is_only_return(tail, "-1"):
        errs.append(
            "rx-index-errata structural: n6_lane_idx default top-level tail "
            f"must be only 'return -1;' (got {_norm_expr(tail)!r})"
        )

    # No material code before first if (only whitespace).
    prefix = body[1:blocks[0][2]]
    if _norm_expr(prefix) != "":
        errs.append(
            "rx-index-errata structural: n6_lane_idx forbids statements before "
            f"first if (got {_norm_expr(prefix)!r})"
        )

    # Between the two ifs: only whitespace.
    mid = body[end0:blocks[1][2]]
    if _norm_expr(mid) != "":
        errs.append(
            "rx-index-errata structural: n6_lane_idx forbids statements between "
            f"if branches (got {_norm_expr(mid)!r})"
        )

    # Global: exactly three return statements total, associated as above.
    rets = re.findall(r"return\s+[^;]+;", body)
    if len(rets) != 3:
        errs.append(
            "rx-index-errata structural: n6_lane_idx must have exactly three "
            f"returns (DATA/E2E→0, ACK→1, default→-1); found {len(rets)}"
        )
    return errs


def _check_lane_idx_in_range_helper(masked: str) -> list[str]:
    errs: list[str] = []
    body = _extract_c_function_body(masked, "static int n6_lane_idx_in_range(")
    if body is None:
        body = _extract_c_function_body(masked, "n6_lane_idx_in_range(")
    if body is None:
        return ["rx-index-errata structural: n6_lane_idx_in_range body missing"]
    if not _RE_IN_RANGE_RETURN.search(body):
        errs.append(
            "rx-index-errata structural: n6_lane_idx_in_range must "
            "return (idx >= 0 && idx < (int)N6_PRIVATE_NAMED_LANE_COUNT) exactly "
            "(idx>=-1 / other relaxations forbidden)"
        )
    returns = re.findall(r"return\s+[^;]+;", body)
    if len(returns) != 1:
        errs.append(
            "rx-index-errata structural: n6_lane_idx_in_range must have "
            f"exactly one return (found {len(returns)})"
        )
    if re.search(r"idx\s*>=\s*-\s*1", body) or "idx>=-1" in body.replace(" ", ""):
        errs.append(
            "rx-index-errata structural: n6_lane_idx_in_range forbids idx>=-1"
        )
    return errs


def _check_lane_ok_for_slot_helper(masked: str) -> list[str]:
    """Exact branch predicates: HOP→DATA|ACK only; E2E→E2E only; default 0."""
    errs: list[str] = []
    body = _extract_c_function_body(masked, "static int n6_lane_ok_for_slot(")
    if body is None:
        body = _extract_c_function_body(masked, "n6_lane_ok_for_slot(")
    if body is None:
        return ["rx-index-errata structural: n6_lane_ok_for_slot body missing"]

    hop_ret_ok = {
        "lane_kind==NINLIL_N6_LANE_HOP_DATA||lane_kind==NINLIL_N6_LANE_HOP_ACK",
        "lane_kind==NINLIL_N6_LANE_HOP_ACK||lane_kind==NINLIL_N6_LANE_HOP_DATA",
    }
    e2e_ret_ok = {"lane_kind==NINLIL_N6_LANE_E2E"}

    # Extract if (s->layer_code == LAYER_*) { return ...; }
    blocks = re.findall(
        r"if\s*\(\s*s\s*->\s*layer_code\s*==\s*(NINLIL_N6_LAYER_\w+)\s*\)\s*"
        r"\{\s*return\s+([^;]+);\s*\}",
        body,
        flags=re.DOTALL,
    )
    if len(blocks) != 2:
        errs.append(
            "rx-index-errata structural: n6_lane_ok_for_slot must have exact "
            "two layer_code branches (HOP and E2E) with single return each "
            f"(found {len(blocks)})"
        )
        return errs
    by_layer = {_norm_expr(layer): _norm_expr(ret) for layer, ret in blocks}
    hop_ret = by_layer.get("NINLIL_N6_LAYER_HOP")
    e2e_ret = by_layer.get("NINLIL_N6_LAYER_E2E")
    if hop_ret is None:
        errs.append(
            "rx-index-errata structural: n6_lane_ok_for_slot missing "
            "exact HOP layer_code branch"
        )
    elif hop_ret not in hop_ret_ok:
        errs.append(
            "rx-index-errata structural: n6_lane_ok_for_slot HOP predicate must "
            "be lane_kind==HOP_DATA||lane_kind==HOP_ACK exact "
            f"(got {hop_ret!r}); E2E must not be admitted on HOP"
        )
    if e2e_ret is None:
        errs.append(
            "rx-index-errata structural: n6_lane_ok_for_slot missing "
            "exact E2E layer_code branch"
        )
    elif e2e_ret not in e2e_ret_ok:
        errs.append(
            "rx-index-errata structural: n6_lane_ok_for_slot E2E predicate must "
            f"be lane_kind==LANE_E2E exact (got {e2e_ret!r})"
        )
    # HOP must not mention E2E lane.
    if hop_ret is not None and "NINLIL_N6_LANE_E2E" in hop_ret:
        errs.append(
            "rx-index-errata structural: n6_lane_ok_for_slot HOP branch must "
            "not admit LANE_E2E"
        )
    returns = re.findall(r"return\s+[^;]+;", body)
    if len(returns) != 3:
        errs.append(
            "rx-index-errata structural: n6_lane_ok_for_slot must have exactly "
            f"three returns (HOP, E2E, default0); found {len(returns)}"
        )
    if not returns or _norm_expr(returns[-1].replace("return", "").rstrip(";")) != "0":
        # last return statement
        last = returns[-1] if returns else ""
        if _norm_expr(last) != "return0;":
            errs.append(
                "rx-index-errata structural: n6_lane_ok_for_slot default must "
                f"be return 0; last was {last!r}"
            )
    return errs


def check_rx_index_errata_structural(store_text: str) -> list[str]:
    """Brace-aware live-guard structural authority for lane-index errata.

    Uses C lexical masking (comments + string/char literals blanked) so
    markers in non-code cannot greenwash. Exact helper semantics + live
    (non-if(0)) guards + exact top-level _Static_assert exprs. PASS ≠ GO.
    """
    errs: list[str] = []
    if not isinstance(store_text, str) or not store_text:
        return ["rx-index-errata structural: empty store text"]

    masked = _mask_c_lexical(store_text)

    # Named count dimensions in live code (not comments/strings).
    for arr in _LANE_ARRAYS:
        if f"{arr}[N6_PRIVATE_NAMED_LANE_COUNT]" not in masked:
            errs.append(
                f"rx-index-errata structural: {arr} must use "
                f"N6_PRIVATE_NAMED_LANE_COUNT dimension (not bare 3)"
            )

    # Six exact top-level _Static_assert expressions.
    asserts = _parse_lane_static_asserts(masked)
    bad = getattr(_parse_lane_static_asserts, "last_bad", {})
    for arr in _LANE_ARRAYS:
        if arr not in asserts:
            if arr in bad:
                errs.append(
                    f"rx-index-errata structural: _Static_assert for {arr} "
                    f"has non-allowed expr {bad[arr]!r} "
                    f"(need sizeof(arr)/sizeof(arr[0])==(size_t)"
                    f"N6_PRIVATE_NAMED_LANE_COUNT or uint64_t equivalent; "
                    f"1||expr forbidden)"
                )
            else:
                errs.append(
                    f"rx-index-errata structural: missing live top-level "
                    f"_Static_assert for {arr} (comment/string-only does not count)"
                )

    errs.extend(_check_n6_lane_idx_helper(masked))
    errs.extend(_check_lane_idx_in_range_helper(masked))
    errs.extend(_check_lane_ok_for_slot_helper(masked))

    # --- n6_rx_precheck_window ---
    win_body = _extract_c_function_body(
        masked, "static int n6_rx_precheck_window("
    )
    if win_body is None:
        errs.append("rx-index-errata structural: n6_rx_precheck_window body missing")
    else:
        m = _find_live_match(win_body, _RE_RANGE_GUARD)
        if m is None:
            errs.append(
                "rx-index-errata structural: window missing exact live "
                "if (!n6_lane_idx_in_range(idx)) (dead if(0){...} does not count)"
            )
        else:
            blk = _guard_block_after(win_body, m)
            if "return 0" not in blk:
                errs.append(
                    "rx-index-errata structural: window range-fail block "
                    "must return 0"
                )
            arr_pos = _first_index(
                win_body,
                ("rx_boot_floor[idx]", "rx_ram_highest[idx]", "rx_bitmap[idx]"),
            )
            if arr_pos < 0:
                errs.append(
                    "rx-index-errata structural: window missing rx_*[idx] load"
                )
            elif m.start() >= arr_pos:
                errs.append(
                    "rx-index-errata structural: window range guard must precede "
                    "first rx array access"
                )

    # --- ninlil_n6_rx_precheck ---
    pre_body = _extract_c_function_body(
        masked, "ninlil_n6_status_t ninlil_n6_rx_precheck("
    )
    if pre_body is None:
        errs.append("rx-index-errata structural: ninlil_n6_rx_precheck body missing")
    else:
        m_idx = _find_live_match(pre_body, _RE_IDX_LANE)
        m_g = _find_live_match(pre_body, _RE_RANGE_GUARD)
        if m_idx is None:
            errs.append(
                "rx-index-errata structural: rx_precheck missing live "
                "idx = n6_lane_idx(lane_kind)"
            )
        if m_g is None:
            errs.append(
                "rx-index-errata structural: rx_precheck missing exact live "
                "if (!n6_lane_idx_in_range(idx)) (dead if(0){...} does not count)"
            )
        elif m_idx is not None and m_idx.start() >= m_g.start():
            errs.append(
                "rx-index-errata structural: rx_precheck idx conversion must "
                "precede range guard"
            )
        if m_g is not None:
            blk = _guard_block_after(pre_body, m_g)
            if "NINLIL_N6_INVALID_ARGUMENT" not in blk:
                errs.append(
                    "rx-index-errata structural: rx_precheck range-fail must "
                    "return INVALID_ARGUMENT"
                )
            wpos = pre_body.find("n6_rx_precheck_window(")
            if wpos < 0 or m_g.start() >= wpos:
                errs.append(
                    "rx-index-errata structural: rx_precheck range guard must "
                    "precede n6_rx_precheck_window"
                )

    # --- ninlil_n6_tx_burn ---
    tx_body = _extract_c_function_body(
        masked, "ninlil_n6_status_t ninlil_n6_tx_burn("
    )
    if tx_body is None:
        errs.append("rx-index-errata structural: ninlil_n6_tx_burn body missing")
    else:
        m_idx = _find_live_match(tx_body, _RE_IDX_LANE)
        m_g = _find_live_match(tx_body, _RE_RANGE_GUARD)
        if m_idx is None:
            errs.append(
                "rx-index-errata structural: tx_burn missing live "
                "idx = n6_lane_idx(lane_kind)"
            )
        if m_g is None:
            errs.append(
                "rx-index-errata structural: tx_burn missing exact live "
                "if (!n6_lane_idx_in_range(idx)) (dead if(0){...} does not count)"
            )
        elif m_idx is not None and m_idx.start() >= m_g.start():
            errs.append(
                "rx-index-errata structural: tx_burn idx conversion must "
                "precede range guard"
            )
        if m_g is not None:
            blk = _guard_block_after(tx_body, m_g)
            if "NINLIL_N6_INVALID_ARGUMENT" not in blk:
                errs.append(
                    "rx-index-errata structural: tx_burn range-fail must "
                    "return INVALID_ARGUMENT"
                )
            arr_pos = _first_index(
                tx_body, ("tx_ram_next[idx]", "tx_ram_limit[idx]")
            )
            if arr_pos < 0:
                errs.append(
                    "rx-index-errata structural: tx_burn missing tx_ram_*[idx]"
                )
            elif m_g.start() >= arr_pos:
                errs.append(
                    "rx-index-errata structural: tx_burn range guard must "
                    "precede first tx array access"
                )

    # --- ninlil_n6_rx_admit_after_aead ---
    adm_body = _extract_c_function_body(
        masked, "ninlil_n6_status_t ninlil_n6_rx_admit_after_aead("
    )
    if adm_body is None:
        errs.append(
            "rx-index-errata structural: ninlil_n6_rx_admit_after_aead body missing"
        )
    else:
        m_idx = _find_live_match(adm_body, _RE_IDX_TOK)
        m_g = _find_live_match(adm_body, _RE_RANGE_GUARD)
        if m_idx is None:
            errs.append(
                "rx-index-errata structural: admit missing live "
                "idx = n6_lane_idx(tok.lane_kind)"
            )
        if m_g is None:
            errs.append(
                "rx-index-errata structural: admit missing exact live "
                "if (!n6_lane_idx_in_range(idx)) (dead if(0){...} does not count)"
            )
        elif m_idx is not None and m_idx.start() >= m_g.start():
            errs.append(
                "rx-index-errata structural: admit idx conversion must "
                "precede range guard"
            )
        if m_g is not None:
            blk = _guard_block_after(adm_body, m_g)
            for need in (
                "n6_enter_fenced",
                "n6_rx_consume_ticket_pair",
                "n6_set_err",
                "NINLIL_N6_CORRUPT",
                "return NINLIL_N6_CORRUPT",
            ):
                if need not in blk:
                    errs.append(
                        f"rx-index-errata structural: admit range-fail block "
                        f"missing {need}"
                    )
            arr_pos = _first_index(
                adm_body,
                (
                    "rx_boot_floor[idx]",
                    "rx_ram_highest[idx]",
                    "rx_bitmap[idx]",
                    "rx_live_reserved[idx]",
                    "n6_rx_precheck_window(",
                    "n6_rx_mark_bitmap(",
                ),
            )
            if arr_pos < 0:
                errs.append(
                    "rx-index-errata structural: admit missing window/array use"
                )
            elif m_g.start() >= arr_pos:
                errs.append(
                    "rx-index-errata structural: admit range guard must precede "
                    "first rx array/window access"
                )
        m_l = _find_live_match(adm_body, _RE_LAYER_GUARD)
        if m_l is None:
            errs.append(
                "rx-index-errata structural: admit missing exact live "
                "if (!n6_lane_ok_for_slot(slot, tok.lane_kind)) "
                "(dead if(0){...} does not count)"
            )
        else:
            lblk = _guard_block_after(adm_body, m_l)
            for need in (
                "n6_enter_fenced",
                "n6_rx_consume_ticket_pair",
                "n6_set_err",
                "NINLIL_N6_CORRUPT",
                "return NINLIL_N6_CORRUPT",
            ):
                if need not in lblk:
                    errs.append(
                        f"rx-index-errata structural: admit layer-fail block "
                        f"missing {need}"
                    )
            wpos = adm_body.find("n6_rx_precheck_window(")
            if wpos < 0 or m_l.start() >= wpos:
                errs.append(
                    "rx-index-errata structural: admit layer guard must precede "
                    "n6_rx_precheck_window"
                )

    # --- CU plan envelope preflight (docs/30 §20.12 rule 7a) ---
    # Brace-aware exact-predicate pins (not token presence alone).
    # Not full C semantic proof: representative invert/relax/drop must RED.
    pf_body = _extract_c_function_body(
        masked, "static ninlil_n6_status_t n6_cu_preflight_plan("
    )
    if pf_body is None:
        pf_body = _extract_c_function_body(masked, "n6_cu_preflight_plan(")
    if pf_body is None:
        errs.append(
            "rx-index-errata structural: n6_cu_preflight_plan body missing"
        )
    else:
        pf_bare = _strip_c_comments(pf_body)
        pf_live_conds = _live_if_conditions(pf_body)
        for need in (
            "NINLIL_N6_CU_PLAN_MAX_KEYS",
            "N6_CU_OP_PUT",
            "N6_CU_OP_DELETE",
            "N6_CU_POST_NONE",
            "N6_CU_POST_INSTALL_HANDLE",
            "N6_CU_POST_TX_LIMIT",
            "N6_CU_POST_RX_ACCEPT",
            "NINLIL_N6_LANE_KEY_BYTES",
            "NINLIL_N6_TX_VALUE_BYTES",
            "pending_install",
            "old_present",
            "NINLIL_N6_CORRUPT",
        ):
            if need not in pf_bare:
                errs.append(
                    f"rx-index-errata structural: CU preflight missing {need}"
                )
        # Exact live closed-domain / bound predicates.  Requiring the complete
        # if-condition rejects inversion, relaxation and deadening such as
        # if (0 && original_predicate), even though all desired tokens remain.
        pf_exact: list[tuple[str, str]] = [
            (
                "live==1",
                "n6==NULL||n6->cu.live!=1",
            ),
            (
                "1<=n_keys<=MAX",
                "n6->cu.n_keys<1u||n6->cu.n_keys>NINLIL_N6_CU_PLAN_MAX_KEYS",
            ),
            (
                "phase closed domain",
                "n6->cu.phase!=N6_CU_PHASE_NONE"
                "&&n6->cu.phase!=N6_CU_PHASE_NEED_CLOSE_OLD"
                "&&n6->cu.phase!=N6_CU_PHASE_NEED_OPEN"
                "&&n6->cu.phase!=N6_CU_PHASE_READ_CLASSIFY",
            ),
            (
                "pending_install boolean",
                "n6->cu.pending_install!=0&&n6->cu.pending_install!=1",
            ),
            (
                "old_present boolean",
                "e->old_present!=0&&e->old_present!=1",
            ),
            (
                "op closed domain",
                "e->op!=N6_CU_OP_PUT&&e->op!=N6_CU_OP_DELETE",
            ),
            (
                "post closed domain",
                "e->post!=N6_CU_POST_NONE&&e->post!=N6_CU_POST_INSTALL_HANDLE"
                "&&e->post!=N6_CU_POST_TX_LIMIT&&e->post!=N6_CU_POST_RX_ACCEPT",
            ),
            (
                "klen bound",
                "e->klen>NINLIL_N6_LANE_KEY_BYTES",
            ),
            (
                "vlen bounds",
                "e->old_vlen>NINLIL_N6_TX_VALUE_BYTES"
                "||e->prop_vlen>NINLIL_N6_TX_VALUE_BYTES",
            ),
        ]
        for label, pred in pf_exact:
            if pred not in pf_live_conds:
                errs.append(
                    f"rx-index-errata structural: CU preflight missing exact "
                    f"live predicate ({label})"
                )

    # --- CU array-post integrity (docs/30 §20.12 rule 7b) ---
    if "n6_cu_validate_array_posts" not in masked:
        errs.append(
            "rx-index-errata structural: n6_cu_validate_array_posts missing"
        )
    else:
        cu_body = _extract_c_function_body(
            masked, "static ninlil_n6_status_t n6_cu_validate_array_posts("
        )
        if cu_body is None:
            cu_body = _extract_c_function_body(
                masked, "n6_cu_validate_array_posts("
            )
        if cu_body is None:
            errs.append(
                "rx-index-errata structural: n6_cu_validate_array_posts body missing"
            )
        else:
            cu_bare = _strip_c_comments(cu_body)
            cu_live_conds = _live_if_conditions(cu_body)
            # Exact-token / call-form requirements (substring-of-renamed forbidden).
            token_needs: list[tuple[str, re.Pattern[str]]] = [
                ("n6_lane_idx(e->lane_kind)", re.compile(r"n6_lane_idx\s*\(\s*e->lane_kind\s*\)")),
                ("n6_lane_idx_in_range", re.compile(r"\bn6_lane_idx_in_range\b")),
                ("e->lane_idx", re.compile(r"\be->lane_idx\b")),
                ("n6_lane_ok_for_slot", re.compile(r"\bn6_lane_ok_for_slot\b")),
                ("N6_CU_POST_TX_LIMIT", re.compile(r"\bN6_CU_POST_TX_LIMIT\b")),
                ("N6_CU_POST_RX_ACCEPT", re.compile(r"\bN6_CU_POST_RX_ACCEPT\b")),
                ("NINLIL_N6_ALLOC_OUTBOUND_TX", re.compile(r"\bNINLIL_N6_ALLOC_OUTBOUND_TX\b")),
                ("NINLIL_N6_ALLOC_INBOUND_RX", re.compile(r"\bNINLIL_N6_ALLOC_INBOUND_RX\b")),
                (
                    "ninlil_n6_encode_lane_key(",
                    re.compile(r"\bninlil_n6_encode_lane_key\s*\("),
                ),
                ("NINLIL_N6_LANE_KEY_BYTES", re.compile(r"\bNINLIL_N6_LANE_KEY_BYTES\b")),
                # Both old and prop must be decoded (count ≥ 2 each).
                (
                    "ninlil_n6_decode_n6tx_value( x2",
                    re.compile(r"\bninlil_n6_decode_n6tx_value\s*\("),
                ),
                (
                    "ninlil_n6_decode_n6rx_value( x2",
                    re.compile(r"\bninlil_n6_decode_n6rx_value\s*\("),
                ),
                ("reserved_exclusive", re.compile(r"\breserved_exclusive\b")),
                ("accept_reserved_through", re.compile(r"\baccept_reserved_through\b")),
                ("post_u64_a", re.compile(r"\bpost_u64_a\b")),
                ("post_u64_b", re.compile(r"\bpost_u64_b\b")),
                ("key_generation", re.compile(r"\bkey_generation\b")),
                ("binding_digest_prefix16", re.compile(r"\bbinding_digest_prefix16\b")),
                ("membership_epoch", re.compile(r"\bmembership_epoch\b")),
                ("ns_fingerprint12", re.compile(r"\bns_fingerprint12\b")),
            ]
            for label, pat in token_needs:
                hits = pat.findall(cu_bare)
                need_n = 2 if " x2" in label else 1
                if len(hits) < need_n:
                    errs.append(
                        f"rx-index-errata structural: CU validate missing {label} "
                        f"(found {len(hits)}, need>={need_n})"
                    )
            # Live range / layer guards (dead if(0 && ...) does not count).
            if _find_live_match(cu_body, _RE_CU_RANGE_GUARD) is None:
                errs.append(
                    "rx-index-errata structural: CU validate missing live "
                    "if (!n6_lane_idx_in_range(expected)) "
                    "(dead if(0&&...) does not count)"
                )
            if _find_live_match(cu_body, _RE_CU_LAYER_GUARD) is None:
                errs.append(
                    "rx-index-errata structural: CU validate missing live "
                    "if (!n6_lane_ok_for_slot(s, e->lane_kind)) "
                    "(dead if(0&&...) does not count)"
                )
            # Exact live if-predicates for docs/30 §20.12 rule 7b — full
            # enumeration (not representatives).  Whitespace-normalized
            # complete conditions are required so pin+docs co-update cannot
            # greenwash invert / relax / if(0) / if(0 && ...) / drop.
            # Conditions nested in if(0){...} or headed by if(0 && ...) are
            # excluded by _live_if_conditions (brace-aware dead spans).
            cu_exact: list[tuple[str, str]] = [
                # Post filter / op+old_present / exact lengths
                (
                    "post filter",
                    "e->post!=N6_CU_POST_TX_LIMIT&&e->post!=N6_CU_POST_RX_ACCEPT",
                ),
                (
                    "op+old_present",
                    "e->op!=N6_CU_OP_PUT||e->old_present!=1",
                ),
                (
                    "exact 68B vlen",
                    "e->old_vlen!=NINLIL_N6_TX_VALUE_BYTES"
                    "||e->prop_vlen!=NINLIL_N6_TX_VALUE_BYTES",
                ),
                # Slot / canary / live / side
                (
                    "slot_index range",
                    "e->slot_index>=n6->slot_count",
                ),
                (
                    "canary",
                    "s->canary0!=N6_CANARY||s->canary1!=N6_CANARY",
                ),
                (
                    "live==0",
                    "s->live==0u",
                ),
                (
                    "post TX branch",
                    "e->post==N6_CU_POST_TX_LIMIT",
                ),
                (
                    "TX slot side",
                    "s->alloc_side!=NINLIL_N6_ALLOC_OUTBOUND_TX",
                ),
                (
                    "RX slot side",
                    "s->alloc_side!=NINLIL_N6_ALLOC_INBOUND_RX",
                ),
                # Range / lane / layer
                (
                    "range",
                    "!n6_lane_idx_in_range(expected)",
                ),
                (
                    "lane_idx==expected",
                    "(int)e->lane_idx!=expected",
                ),
                (
                    "layer",
                    "!n6_lane_ok_for_slot(s,e->lane_kind)",
                ),
                # Encode + canonical key length + memcmp
                (
                    "encode lane key",
                    "ninlil_n6_encode_lane_key(&lk,canon_key,sizeof(canon_key),"
                    "&canon_klen)!=NINLIL_N6_CODEC_OK",
                ),
                (
                    "canonical key length",
                    "canon_klen!=NINLIL_N6_LANE_KEY_BYTES"
                    "||e->klen!=NINLIL_N6_LANE_KEY_BYTES",
                ),
                (
                    "key memcmp exact",
                    "memcmp(e->key,canon_key,NINLIL_N6_LANE_KEY_BYTES)!=0",
                ),
                # TX decode + full identity + post_u64 + order
                (
                    "TX old decode",
                    "ninlil_n6_decode_n6tx_value(e->old_val,e->old_vlen,&old_tv)"
                    "!=NINLIL_N6_CODEC_OK",
                ),
                (
                    "TX prop decode",
                    "ninlil_n6_decode_n6tx_value(e->prop_val,e->prop_vlen,"
                    "&prop_tv)!=NINLIL_N6_CODEC_OK",
                ),
                (
                    "TX identity key_generation",
                    "old_tv.key_generation!=s->key_generation"
                    "||prop_tv.key_generation!=s->key_generation",
                ),
                (
                    "TX identity binding",
                    "memcmp(old_tv.binding_digest_prefix16,s->binding_digest32,"
                    "16u)!=0||memcmp(prop_tv.binding_digest_prefix16,"
                    "s->binding_digest32,16u)!=0",
                ),
                (
                    "TX identity membership_epoch",
                    "old_tv.membership_epoch!=s->membership_epoch"
                    "||prop_tv.membership_epoch!=s->membership_epoch",
                ),
                (
                    "TX identity ns",
                    "memcmp(old_tv.ns_fingerprint12,s->ns_fingerprint12,12u)!=0"
                    "||memcmp(prop_tv.ns_fingerprint12,s->ns_fingerprint12,"
                    "12u)!=0",
                ),
                (
                    "TX identity alloc_side",
                    "old_tv.alloc_side!=NINLIL_N6_ALLOC_OUTBOUND_TX"
                    "||prop_tv.alloc_side!=NINLIL_N6_ALLOC_OUTBOUND_TX",
                ),
                (
                    "TX post_u64 exclusive",
                    "old_tv.reserved_exclusive!=e->post_u64_b"
                    "||prop_tv.reserved_exclusive!=e->post_u64_a",
                ),
                (
                    "TX post_u64 order",
                    "!(e->post_u64_b<e->post_u64_a)",
                ),
                # RX decode + full identity + post_u64 + order
                (
                    "RX old decode",
                    "ninlil_n6_decode_n6rx_value(e->old_val,e->old_vlen,&old_rv)"
                    "!=NINLIL_N6_CODEC_OK",
                ),
                (
                    "RX prop decode",
                    "ninlil_n6_decode_n6rx_value(e->prop_val,e->prop_vlen,"
                    "&prop_rv)!=NINLIL_N6_CODEC_OK",
                ),
                (
                    "RX identity key_generation",
                    "old_rv.key_generation!=s->key_generation"
                    "||prop_rv.key_generation!=s->key_generation",
                ),
                (
                    "RX identity binding",
                    "memcmp(old_rv.binding_digest_prefix16,s->binding_digest32,"
                    "16u)!=0||memcmp(prop_rv.binding_digest_prefix16,"
                    "s->binding_digest32,16u)!=0",
                ),
                (
                    "RX identity membership_epoch",
                    "old_rv.membership_epoch!=s->membership_epoch"
                    "||prop_rv.membership_epoch!=s->membership_epoch",
                ),
                (
                    "RX identity ns",
                    "memcmp(old_rv.ns_fingerprint12,s->ns_fingerprint12,12u)!=0"
                    "||memcmp(prop_rv.ns_fingerprint12,s->ns_fingerprint12,"
                    "12u)!=0",
                ),
                (
                    "RX identity alloc_side",
                    "old_rv.alloc_side!=NINLIL_N6_ALLOC_INBOUND_RX"
                    "||prop_rv.alloc_side!=NINLIL_N6_ALLOC_INBOUND_RX",
                ),
                (
                    "RX post_u64",
                    "prop_rv.accept_reserved_through!=e->post_u64_a"
                    "||e->post_u64_b!=0u",
                ),
                (
                    "RX order",
                    "old_rv.accept_reserved_through"
                    ">prop_rv.accept_reserved_through",
                ),
            ]
            for label, pred in cu_exact:
                if pred not in cu_live_conds:
                    errs.append(
                        f"rx-index-errata structural: CU validate missing exact "
                        f"live predicate ({label})"
                    )
            # Dual live post-TX selectors: set membership of
            # e->post==N6_CU_POST_TX_LIMIT is insufficient — either of the two
            # sites can be inverted while the other keeps the set GREEN.
            # Require exactly two live brace-bodied occurrences, in order:
            # (1) slot-side selector whose then/else hold TX/RX alloc_side pins;
            # (2) decode+identity selector whose then/else hold the full TX/RX
            # decode / identity / post_u64 / order pins.
            _POST_TX_SEL = "e->post==N6_CU_POST_TX_LIMIT"
            post_tx_sites = [
                (then_b, else_b)
                for cond, then_b, else_b in _live_if_then_else_blocks(cu_body)
                if cond == _POST_TX_SEL
            ]
            if len(post_tx_sites) != 2:
                errs.append(
                    "rx-index-errata structural: CU validate must have exactly "
                    "2 live if (e->post == N6_CU_POST_TX_LIMIT) selectors "
                    "(slot-side + decode/identity); "
                    f"found {len(post_tx_sites)} (single-site invert/drop RED)"
                )
            else:
                slot_then, slot_else = post_tx_sites[0]
                dec_then, dec_else = post_tx_sites[1]
                slot_then_conds = _live_if_conditions(slot_then)
                slot_else_conds = _live_if_conditions(slot_else)
                if (
                    "s->alloc_side!=NINLIL_N6_ALLOC_OUTBOUND_TX"
                    not in slot_then_conds
                ):
                    errs.append(
                        "rx-index-errata structural: CU validate slot-side "
                        "selector then-block missing exact live TX slot side "
                        "(s->alloc_side!=NINLIL_N6_ALLOC_OUTBOUND_TX)"
                    )
                if (
                    "s->alloc_side!=NINLIL_N6_ALLOC_INBOUND_RX"
                    not in slot_else_conds
                ):
                    errs.append(
                        "rx-index-errata structural: CU validate slot-side "
                        "selector else-block missing exact live RX slot side "
                        "(s->alloc_side!=NINLIL_N6_ALLOC_INBOUND_RX)"
                    )
                dec_then_conds = _live_if_conditions(dec_then)
                dec_else_conds = _live_if_conditions(dec_else)
                dec_tx_exact: list[tuple[str, str]] = [
                    (
                        "TX old decode",
                        "ninlil_n6_decode_n6tx_value(e->old_val,e->old_vlen,"
                        "&old_tv)!=NINLIL_N6_CODEC_OK",
                    ),
                    (
                        "TX prop decode",
                        "ninlil_n6_decode_n6tx_value(e->prop_val,e->prop_vlen,"
                        "&prop_tv)!=NINLIL_N6_CODEC_OK",
                    ),
                    (
                        "TX identity key_generation",
                        "old_tv.key_generation!=s->key_generation"
                        "||prop_tv.key_generation!=s->key_generation",
                    ),
                    (
                        "TX identity binding",
                        "memcmp(old_tv.binding_digest_prefix16,"
                        "s->binding_digest32,16u)!=0"
                        "||memcmp(prop_tv.binding_digest_prefix16,"
                        "s->binding_digest32,16u)!=0",
                    ),
                    (
                        "TX identity membership_epoch",
                        "old_tv.membership_epoch!=s->membership_epoch"
                        "||prop_tv.membership_epoch!=s->membership_epoch",
                    ),
                    (
                        "TX identity ns",
                        "memcmp(old_tv.ns_fingerprint12,s->ns_fingerprint12,"
                        "12u)!=0||memcmp(prop_tv.ns_fingerprint12,"
                        "s->ns_fingerprint12,12u)!=0",
                    ),
                    (
                        "TX identity alloc_side",
                        "old_tv.alloc_side!=NINLIL_N6_ALLOC_OUTBOUND_TX"
                        "||prop_tv.alloc_side!=NINLIL_N6_ALLOC_OUTBOUND_TX",
                    ),
                    (
                        "TX post_u64 exclusive",
                        "old_tv.reserved_exclusive!=e->post_u64_b"
                        "||prop_tv.reserved_exclusive!=e->post_u64_a",
                    ),
                    (
                        "TX post_u64 order",
                        "!(e->post_u64_b<e->post_u64_a)",
                    ),
                ]
                dec_rx_exact: list[tuple[str, str]] = [
                    (
                        "RX old decode",
                        "ninlil_n6_decode_n6rx_value(e->old_val,e->old_vlen,"
                        "&old_rv)!=NINLIL_N6_CODEC_OK",
                    ),
                    (
                        "RX prop decode",
                        "ninlil_n6_decode_n6rx_value(e->prop_val,e->prop_vlen,"
                        "&prop_rv)!=NINLIL_N6_CODEC_OK",
                    ),
                    (
                        "RX identity key_generation",
                        "old_rv.key_generation!=s->key_generation"
                        "||prop_rv.key_generation!=s->key_generation",
                    ),
                    (
                        "RX identity binding",
                        "memcmp(old_rv.binding_digest_prefix16,"
                        "s->binding_digest32,16u)!=0"
                        "||memcmp(prop_rv.binding_digest_prefix16,"
                        "s->binding_digest32,16u)!=0",
                    ),
                    (
                        "RX identity membership_epoch",
                        "old_rv.membership_epoch!=s->membership_epoch"
                        "||prop_rv.membership_epoch!=s->membership_epoch",
                    ),
                    (
                        "RX identity ns",
                        "memcmp(old_rv.ns_fingerprint12,s->ns_fingerprint12,"
                        "12u)!=0||memcmp(prop_rv.ns_fingerprint12,"
                        "s->ns_fingerprint12,12u)!=0",
                    ),
                    (
                        "RX identity alloc_side",
                        "old_rv.alloc_side!=NINLIL_N6_ALLOC_INBOUND_RX"
                        "||prop_rv.alloc_side!=NINLIL_N6_ALLOC_INBOUND_RX",
                    ),
                    (
                        "RX post_u64",
                        "prop_rv.accept_reserved_through!=e->post_u64_a"
                        "||e->post_u64_b!=0u",
                    ),
                    (
                        "RX order",
                        "old_rv.accept_reserved_through"
                        ">prop_rv.accept_reserved_through",
                    ),
                ]
                for label, pred in dec_tx_exact:
                    if pred not in dec_then_conds:
                        errs.append(
                            "rx-index-errata structural: CU validate decode "
                            "selector then-block missing exact live predicate "
                            f"({label})"
                        )
                for label, pred in dec_rx_exact:
                    if pred not in dec_else_conds:
                        errs.append(
                            "rx-index-errata structural: CU validate decode "
                            "selector else-block missing exact live predicate "
                            f"({label})"
                        )

    apply_body = _extract_c_function_body(
        masked, "static ninlil_n6_status_t n6_apply_cu_post("
    )
    if apply_body is None:
        apply_body = _extract_c_function_body(masked, "n6_apply_cu_post(")
    if apply_body is None:
        errs.append("rx-index-errata structural: n6_apply_cu_post body missing")
    else:
        m_v = _find_live_match(apply_body, _RE_CU_VALIDATE_IF)
        if m_v is None:
            errs.append(
                "rx-index-errata structural: apply_cu_post missing live "
                "if (n6_cu_validate_array_posts(n6) != NINLIL_N6_OK) "
                "(if(0 && ...) does not count)"
            )
        else:
            apos = _first_index(
                apply_body,
                (
                    "tx_ram_next[",
                    "tx_ram_limit[",
                    "rx_live_reserved[",
                    "rx_boot_floor[",
                    "rx_ram_highest[",
                    "rx_bitmap[",
                ),
            )
            if apos >= 0 and m_v.start() >= apos:
                errs.append(
                    "rx-index-errata structural: CU validate must precede "
                    "array post mutation"
                )
        if (
            "n6_cu_fail_corrupt" not in apply_body
            and "n6_enter_fenced" not in apply_body
        ):
            errs.append(
                "rx-index-errata structural: apply_cu_post fail path must "
                "fence via n6_cu_fail_corrupt or n6_enter_fenced"
            )
        if "lane_idx < 3" in apply_body or "lane_idx < 3u" in apply_body:
            errs.append(
                "rx-index-errata structural: bare lane_idx < 3 forbidden in "
                "apply_cu_post"
            )

    # recover_cu: true no-CU AND + preflight/validate before any classify open/begin
    rec_body = _extract_c_function_body(
        masked, "ninlil_n6_status_t ninlil_n6_recover_cu("
    )
    if rec_body is None:
        errs.append(
            "rx-index-errata structural: ninlil_n6_recover_cu body missing"
        )
    else:
        # True no-CU exact conjunction (live==0 && n_keys==0 only).
        m_no = _find_live_match(rec_body, _RE_RECOVER_TRUE_NO_CU)
        if m_no is None:
            errs.append(
                "rx-index-errata structural: recover_cu missing live exact "
                "true no-CU conjunction "
                "if (n6->cu.live == 0 && n6->cu.n_keys == 0u) "
                "(OR / single-arm / if(0&&) does not count)"
            )
        else:
            no_block = _guard_block_after(rec_body, m_no)
            tail = rec_body[m_no.end() : m_no.end() + 200]
            if (
                "NINLIL_N6_INVALID_STATE" not in no_block
                and "NINLIL_N6_INVALID_STATE" not in tail
            ):
                errs.append(
                    "rx-index-errata structural: recover true no-CU arm "
                    "must return NINLIL_N6_INVALID_STATE"
                )
        # Forbidden OR bypass (even if co-present with AND).
        if _find_live_match(rec_body, _RE_RECOVER_NO_CU_OR) is not None:
            errs.append(
                "rx-index-errata structural: recover_cu forbids live "
                "if (n6->cu.live == 0 || n6->cu.n_keys == 0u) "
                "(bypasses preflight for live=1 n_keys=0)"
            )
        m_pf = _find_live_match(rec_body, _RE_CU_PREFLIGHT_IF)
        if m_pf is None:
            errs.append(
                "rx-index-errata structural: recover_cu missing live "
                "if (n6_cu_preflight_plan(n6) != NINLIL_N6_OK) "
                "(if(0 && ...) does not count)"
            )
        m_va = _find_live_match(
            rec_body,
            re.compile(
                r"if\s*\(\s*n6_cu_validate_array_posts\s*\(\s*n6\s*\)\s*!=\s*"
                r"NINLIL_N6_OK\s*\)"
            ),
        )
        if m_va is None:
            errs.append(
                "rx-index-errata structural: recover_cu missing live "
                "array-post validate before classify I/O"
            )
        open_pos = rec_body.find("n6_cu_open_storage")
        begin_pos = rec_body.find("n6_cu_begin_ro")
        # force-close of NEED_CLOSE_OLD is allowed before classify open; the
        # classify open itself must still follow preflight.
        if m_pf is not None and open_pos >= 0 and m_pf.start() >= open_pos:
            errs.append(
                "rx-index-errata structural: recover preflight must precede "
                "n6_cu_open_storage"
            )
        if m_va is not None and begin_pos >= 0 and m_va.start() >= begin_pos:
            errs.append(
                "rx-index-errata structural: recover array-post validate must "
                "precede n6_cu_begin_ro"
            )
        if m_pf is not None and m_va is not None and m_pf.start() >= m_va.start():
            errs.append(
                "rx-index-errata structural: recover preflight must precede "
                "array-post validate"
            )
        # True no-CU gate must precede preflight (order pin).
        if m_no is not None and m_pf is not None and m_no.start() >= m_pf.start():
            errs.append(
                "rx-index-errata structural: recover true no-CU check must "
                "precede preflight"
            )
        # Preflight fail arm must fence/corrupt (not bare leave/INVALID_STATE).
        if m_pf is not None:
            pf_block = _guard_block_after(rec_body, m_pf)
            if "n6_cu_fail_corrupt" not in pf_block and (
                "n6_enter_fenced" not in pf_block
            ):
                errs.append(
                    "rx-index-errata structural: recover preflight fail path "
                    "must call n6_cu_fail_corrupt or n6_enter_fenced"
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
    # Structural errata markers: run on store even when hash matches (and also
    # when hash mismatches, so self-test co-update without markers stays RED).
    if rel == STORE_REL.as_posix() or rel.endswith("n6_context_store.c"):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            errs.append(f"{rel}: not UTF-8 for structural check: {e}")
        else:
            errs.extend(check_rx_index_errata_structural(text))
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
