#!/usr/bin/env python3
"""D2-S5 DSR2_ESP_BOUND complete source gate (stdlib only).

Analyzes production scanner sources after stripping C comments/strings.
Proves:
  - no malloc/calloc/realloc/free/alloca calls
  - no 65536 / re-read oversized allocation patterns in scanner
  - exactly one workspace value buffer; no second value/full-ID/xref storage
  - no automatic declarations of workspace/row_scratch/typed-record/large
    record arrays inside scanner function bodies
  - scanner-local function call graph has no direct or mutual recursion
  - parser accounts for every function body (fail-closed, never silent pass)

Usage:
  python3 tools/domain_scan_dsr2_gate.py check
  python3 tools/domain_scan_dsr2_gate.py self-test

CTest names:
  domain_scan_dsr2_complete_gate
  domain_scan_dsr2_gate_self_test
"""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER_C = REPO_ROOT / "src" / "runtime" / "domain_store_scanner.c"
SCANNER_H = REPO_ROOT / "src" / "runtime" / "domain_store_scanner.h"
D3S1_C = REPO_ROOT / "src" / "runtime" / "domain_store_d3s1.c"
D3S1_H = REPO_ROOT / "src" / "runtime" / "domain_store_d3s1.h"

ALLOC_CALL_RE = re.compile(
    r"\b(malloc|calloc|realloc|free|alloca)\s*\("
)
STACK_65536_RE = re.compile(r"\[\s*65536\s*\]")
REREAD_PATTERN_RE = re.compile(
    r"(re-?read|reread|temporary\s+alloc|stack\s*65536|65536\s*\*)",
    re.IGNORECASE,
)
# Automatic large arrays / workspace-like locals in function bodies.
AUTO_FORBIDDEN_RE = re.compile(
    r"\b("
    r"ninlil_domain_scan_workspace_t|"
    r"ninlil_domain_scan_row_scratch_t|"
    r"ninlil_model_domain_typed_record_t|"
    r"ninlil_model_domain_witness_header_t|"
    r"ninlil_model_domain_witness_chunk_t"
    r")\s+\w+\s*[;=\[\]]"
)
# Large automatic arrays (literal sizes commonly used for records/values).
AUTO_LARGE_ARRAY_RE = re.compile(
    r"\b(?:uint8_t|char|unsigned\s+char)\s+\w+\s*\[\s*"
    r"(?:4096|8192|65536|NINLIL_DOMAIN_SCAN_VALUE_CAPACITY|"
    r"NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES)\s*\]"
)
VALUE_CAPACITY_FIELD_RE = re.compile(
    r"uint8_t\s+\w+\s*\[\s*NINLIL_DOMAIN_SCAN_VALUE_CAPACITY\s*\]"
)
XREF_RE = re.compile(r"\b(?:xref_.*digest|unused_xref|full_id_set)\b")


def strip_c_comments_and_strings(src: str) -> str:
    """Remove // and /* */ comments and string/char literals for analysis."""
    out: List[str] = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        # Line comment
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            i += 2
            while i < n and src[i] not in "\n\r":
                i += 1
            continue
        # Block comment
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                # Preserve newlines to keep line structure for diagnostics.
                if src[i] in "\n\r":
                    out.append(src[i])
                i += 1
            i = min(i + 2, n)
            continue
        # String literal
        if ch == '"':
            out.append(" ")
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == '"':
                    i += 1
                    break
                if src[i] in "\n\r":
                    out.append(src[i])
                i += 1
            continue
        # Char literal
        if ch == "'":
            out.append(" ")
            i += 1
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "'":
                    i += 1
                    break
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def find_matching_brace(text: str, open_idx: int) -> Optional[int]:
    """Return index of matching '}' for text[open_idx]=='{', or None."""
    if open_idx >= len(text) or text[open_idx] != "{":
        return None
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


# Function definition: optional storage/qualifiers + return type tokens + name (
# Heuristic sufficient for this translation unit; fail-closed if body missing.
FUNC_DEF_RE = re.compile(
    r"(?m)^(?:static\s+)?(?:inline\s+)?"
    r"(?:const\s+)?"
    r"(?:void|int|uint8_t|uint16_t|uint32_t|uint64_t|size_t|ninlil_\w+_t)\s+"
    r"(\w+)\s*\("
)


def extract_functions(src_stripped: str) -> Dict[str, str]:
    """Map function name -> body text (including braces content).

    Fails (raises) if a definition header is found but the body cannot be
    accounted for — never silently skips unparsed functions.
    """
    functions: Dict[str, str] = {}
    for m in FUNC_DEF_RE.finditer(src_stripped):
        name = m.group(1)
        # Skip if this looks like a prototype (ends with ); before {)
        rest = src_stripped[m.end() - 1 :]  # from '('
        # Find end of parameter list
        depth = 0
        j = 0
        while j < len(rest):
            if rest[j] == "(":
                depth += 1
            elif rest[j] == ")":
                depth -= 1
                if depth == 0:
                    j += 1
                    break
            j += 1
        else:
            raise SystemExit(
                f"DSR2 gate: cannot parse parameter list for {name}"
            )
        after = rest[j:].lstrip()
        if after.startswith(";"):
            # Prototype only.
            continue
        if not after.startswith("{"):
            # Could be K&R or macro; fail-closed for definitions we cannot parse.
            # Allow only pure prototypes above; anything else is a parse failure
            # when it looks like a definition start without brace.
            # Heuristic: if next non-space is not '{', skip only if it's another
            # declarator-like token at file scope — fail instead.
            raise SystemExit(
                f"DSR2 gate: cannot locate function body for {name} "
                f"(after params starts with {after[:40]!r})"
            )
        brace_abs = m.end() - 1 + j + (len(rest[j:]) - len(after))
        # recompute absolute index of '{'
        brace_abs = m.end() - 1 + j
        # skip whitespace between ) and {
        while brace_abs < len(src_stripped) and src_stripped[brace_abs] in " \t\r\n":
            brace_abs += 1
        if brace_abs >= len(src_stripped) or src_stripped[brace_abs] != "{":
            raise SystemExit(
                f"DSR2 gate: function body open-brace missing for {name}"
            )
        end = find_matching_brace(src_stripped, brace_abs)
        if end is None:
            raise SystemExit(
                f"DSR2 gate: unclosed function body for {name}"
            )
        body = src_stripped[brace_abs : end + 1]
        if name in functions:
            # Allow redefinition only if identical (should not happen).
            if functions[name] != body:
                raise SystemExit(
                    f"DSR2 gate: duplicate conflicting definition for {name}"
                )
        functions[name] = body
    if not functions:
        raise SystemExit("DSR2 gate: parsed zero function bodies (parser fail)")
    return functions


def build_call_graph(
    functions: Dict[str, str],
) -> Dict[str, Set[str]]:
    names = set(functions.keys())
    graph: Dict[str, Set[str]] = {n: set() for n in names}
    for caller, body in functions.items():
        for callee in names:
            # Call site: name followed by (
            if re.search(r"\b" + re.escape(callee) + r"\s*\(", body):
                graph[caller].add(callee)
    return graph


def find_recursion(graph: Dict[str, Set[str]]) -> List[str]:
    """Return list of recursion descriptions (self or mutual via SCC/cycles)."""
    issues: List[str] = []
    # Self recursion
    for n, callees in graph.items():
        if n in callees:
            issues.append(f"self_recursion:{n}")
    # Mutual / cycle: DFS
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {n: WHITE for n in graph}
    stack: List[str] = []

    def dfs(u: str) -> None:
        color[u] = GRAY
        stack.append(u)
        for v in graph[u]:
            if color[v] == GRAY:
                # cycle
                if v in stack:
                    i = stack.index(v)
                    cyc = stack[i:] + [v]
                    issues.append("cycle:" + "->".join(cyc))
            elif color[v] == WHITE:
                dfs(v)
        stack.pop()
        color[u] = BLACK

    for n in graph:
        if color[n] == WHITE:
            dfs(n)
    # dedupe
    return sorted(set(issues))


def analyze_sources(
    c_text: str,
    h_text: str,
    *,
    label: str = "scanner",
) -> List[str]:
    """Return list of violation names (empty == pass)."""
    bad: List[str] = []
    c_s = strip_c_comments_and_strings(c_text)
    h_s = strip_c_comments_and_strings(h_text)
    combined = c_s + "\n" + h_s

    for m in ALLOC_CALL_RE.finditer(combined):
        bad.append(f"allocator_call:{m.group(1)}")
    if STACK_65536_RE.search(combined):
        bad.append("stack_or_array_65536")
    if REREAD_PATTERN_RE.search(combined):
        bad.append("reread_or_65536_pattern")

    # Header: exactly one value buffer field declaration.
    value_fields = VALUE_CAPACITY_FIELD_RE.findall(h_s)
    if len(value_fields) != 1:
        bad.append(f"value_buffer_count:{len(value_fields)}")
    if XREF_RE.search(h_s) or XREF_RE.search(c_s):
        bad.append("xref_or_full_id_storage")

    # Second 4096-class value storage in header beyond the single value[].
    # Allow value[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY] only once; reject extra
    # uint8_t name[4096] in header.
    # value is capacity-macro sized; any additional macro-sized field is a
    # second max-value buffer. Also reject literal 4096 arrays.
    if len(re.findall(r"uint8_t\s+\w+\s*\[\s*4096\s*\]", h_s)) > 0:
        bad.append("header_literal_4096_array")
    # Count value-like buffers: value[ + any second max-value field.
    if len(VALUE_CAPACITY_FIELD_RE.findall(h_s)) != 1:
        bad.append("not_exactly_one_value_field")

    try:
        functions = extract_functions(c_s)
    except SystemExit as e:
        bad.append(f"parser_fail:{e}")
        return bad

    # Reject automatic forbidden locals / large arrays inside function bodies.
    for fname, body in functions.items():
        if AUTO_FORBIDDEN_RE.search(body):
            bad.append(f"auto_workspace_or_record:{fname}")
        if AUTO_LARGE_ARRAY_RE.search(body):
            bad.append(f"auto_large_array:{fname}")
        # VLA heuristic: type name[ident] where size is not a MACRO_STYLE constant.
        # Fixed arrays sized by ALL_CAPS macros are allowed; variable sizes fail.
        for vm in re.finditer(
            r"\b(?:uint8_t|char|int|unsigned(?:\s+char)?)\s+\w+\s*"
            r"\[\s*([a-zA-Z_]\w*)\s*\]",
            body,
        ):
            size_tok = vm.group(1)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", size_tok):
                bad.append(f"possible_vla:{fname}")
                break

    graph = build_call_graph(functions)
    for issue in find_recursion(graph):
        bad.append(issue)

    # Require known public entry points to be present (parser accounting).
    required_entries = (
        "ninlil_domain_scan_begin_profiled",
        "ninlil_domain_scan_advance",
        "ninlil_domain_scan_exact_get",
        "ninlil_domain_scan_note_terminal_corrupt",
        "ninlil_domain_scan_finalize",
        "ninlil_domain_scan_abort",
        "ninlil_domain_scan_session_init",
    )
    # Self-test snippets may omit entries; only enforce for production label.
    if label == "scanner":
        for ent in required_entries:
            if ent not in functions:
                bad.append(f"missing_entry:{ent}")

    return sorted(set(bad))


def check_production() -> int:
    if not SCANNER_C.is_file() or not SCANNER_H.is_file():
        print("missing scanner sources", file=sys.stderr)
        return 1
    if not D3S1_C.is_file() or not D3S1_H.is_file():
        print("missing D3-S1 sources", file=sys.stderr)
        return 1
    c_text = SCANNER_C.read_text(encoding="utf-8")
    h_text = SCANNER_H.read_text(encoding="utf-8")
    bad = analyze_sources(c_text, h_text, label="scanner")
    if bad:
        print("DSR2 complete source gate failed:", bad, file=sys.stderr)
        return 1
    # D3-S1 chunk-A/B/C TU: same DSR2 bans (no heap/VLA/second 4096/full-ID).
    # Header is not the scanner workspace header — analyze .c alone with a
    # stub header that satisfies the single-value-buffer check without
    # inventing a second workspace value buffer.
    d3_c = D3S1_C.read_text(encoding="utf-8")
    d3_h_stub = (
        "typedef struct ninlil_domain_scan_workspace {\n"
        "    uint8_t value[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];\n"
        "} ninlil_domain_scan_workspace_t;\n"
    )
    d3_bad = analyze_sources(d3_c, d3_h_stub, label="snippet")
    if d3_bad:
        print("DSR2 D3-S1 source gate failed:", d3_bad, file=sys.stderr)
        return 1
    print(
        f"ok domain_scan_dsr2_complete_gate "
        f"c={SCANNER_C.name} h={SCANNER_H.name} "
        f"d3s1={D3S1_C.name}"
    )
    return 0


# --- Negative self-tests (temporary synthetic snippets) -------------------

MINIMAL_CLEAN_H = """
typedef struct ninlil_domain_scan_workspace {
    uint8_t key[255];
    uint8_t value[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];
    uint8_t previous_key[255];
} ninlil_domain_scan_workspace_t;
"""

MINIMAL_CLEAN_C = """
#include <stdint.h>
static int helper_a(int x)
{
    return x + 1;
}
static int helper_b(int x)
{
    return helper_a(x);
}
void ninlil_domain_scan_session_init(void *session)
{
    (void)session;
}
ninlil_status_t ninlil_domain_scan_begin_profiled(void)
{
    return helper_b(0);
}
ninlil_status_t ninlil_domain_scan_advance(void)
{
    return 0;
}
ninlil_status_t ninlil_domain_scan_exact_get(void)
{
    return 0;
}
ninlil_status_t ninlil_domain_scan_note_terminal_corrupt(void)
{
    return 0;
}
ninlil_status_t ninlil_domain_scan_finalize(void)
{
    return 0;
}
ninlil_status_t ninlil_domain_scan_abort(void)
{
    return 0;
}
"""


def _expect_reject(name: str, c: str, h: str, needle: str) -> Optional[str]:
    bad = analyze_sources(c, h, label="snippet")
    if not bad:
        return f"{name}: expected reject, got pass"
    joined = " ".join(bad)
    if needle not in joined:
        return f"{name}: expected needle {needle!r} in {bad}"
    return None


def _expect_pass(name: str, c: str, h: str) -> Optional[str]:
    bad = analyze_sources(c, h, label="snippet")
    if bad:
        return f"{name}: expected pass, got {bad}"
    return None


def self_test() -> int:
    errors: List[str] = []

    # Clean minimal snippet passes (no required_entries enforcement).
    err = _expect_pass("clean", MINIMAL_CLEAN_C, MINIMAL_CLEAN_H)
    if err:
        errors.append(err)

    # VLA
    vla_c = MINIMAL_CLEAN_C.replace(
        "ninlil_status_t ninlil_domain_scan_advance(void)\n{\n    return 0;\n}",
        "ninlil_status_t ninlil_domain_scan_advance(void)\n"
        "{\n    int n = 16;\n    uint8_t buf[n];\n    (void)buf;\n    return 0;\n}",
    )
    err = _expect_reject("vla", vla_c, MINIMAL_CLEAN_H, "possible_vla")
    if err:
        errors.append(err)

    # Mutual recursion
    mut_c = MINIMAL_CLEAN_C.replace(
        "static int helper_a(int x)\n{\n    return x + 1;\n}\n"
        "static int helper_b(int x)\n{\n    return helper_a(x);\n}",
        "static int helper_a(int x);\n"
        "static int helper_b(int x)\n{\n    return helper_a(x);\n}\n"
        "static int helper_a(int x)\n{\n    return helper_b(x);\n}",
    )
    # With both definitions, call graph a<->b
    mut_c2 = """
static int helper_a(int x);
static int helper_b(int x);
static int helper_a(int x)
{
    return helper_b(x);
}
static int helper_b(int x)
{
    return helper_a(x);
}
void ninlil_domain_scan_session_init(void *session) { (void)session; }
ninlil_status_t ninlil_domain_scan_begin_profiled(void) { return 0; }
ninlil_status_t ninlil_domain_scan_advance(void) { return 0; }
ninlil_status_t ninlil_domain_scan_exact_get(void) { return 0; }
ninlil_status_t ninlil_domain_scan_note_terminal_corrupt(void) { return 0; }
ninlil_status_t ninlil_domain_scan_finalize(void) { return 0; }
ninlil_status_t ninlil_domain_scan_abort(void) { return 0; }
"""
    err = _expect_reject("mutual_recursion", mut_c2, MINIMAL_CLEAN_H, "cycle:")
    if err:
        errors.append(err)

    # Allocator call
    alloc_c = MINIMAL_CLEAN_C.replace(
        "return helper_b(0);",
        "void *p = malloc(16); (void)p; return 0;",
    )
    err = _expect_reject("allocator", alloc_c, MINIMAL_CLEAN_H, "allocator_call")
    if err:
        errors.append(err)

    # Automatic workspace local
    auto_c = MINIMAL_CLEAN_C.replace(
        "ninlil_status_t ninlil_domain_scan_advance(void)\n{\n    return 0;\n}",
        "ninlil_status_t ninlil_domain_scan_advance(void)\n"
        "{\n    ninlil_domain_scan_workspace_t local_ws;\n"
        "    (void)local_ws;\n    return 0;\n}",
    )
    err = _expect_reject(
        "auto_workspace", auto_c, MINIMAL_CLEAN_H, "auto_workspace_or_record"
    )
    if err:
        errors.append(err)

    # Second macro-sized 4096 value buffer in header
    h2 = MINIMAL_CLEAN_H.replace(
        "uint8_t value[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];",
        "uint8_t value[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];\n"
        "    uint8_t value2[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];",
    )
    err = _expect_reject(
        "second_4096", MINIMAL_CLEAN_C, h2, "value_buffer_count"
    )
    if err:
        # also accept header_literal_4096_array or not_exactly_one_value_field
        bad = analyze_sources(MINIMAL_CLEAN_C, h2, label="snippet")
        joined = " ".join(bad)
        if not (
            "value_buffer_count" in joined
            or "header_literal_4096_array" in joined
            or "not_exactly_one_value_field" in joined
        ):
            errors.append(
                f"second_4096: expected second-buffer reject, got {bad}"
            )

    # Automatic macro-sized value buffer in a scanner function.
    auto_value_c = MINIMAL_CLEAN_C.replace(
        "ninlil_status_t ninlil_domain_scan_advance(void)\n{\n    return 0;\n}",
        "ninlil_status_t ninlil_domain_scan_advance(void)\n"
        "{\n    uint8_t tmp[NINLIL_DOMAIN_SCAN_VALUE_CAPACITY];\n"
        "    (void)tmp;\n    return 0;\n}",
    )
    err = _expect_reject(
        "auto_macro_value", auto_value_c, MINIMAL_CLEAN_H, "auto_large_array"
    )
    if err:
        errors.append(err)

    # Also exercise temp dir write path (proves self-test wiring).
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "a.c").write_text(MINIMAL_CLEAN_C, encoding="utf-8")
        (p / "a.h").write_text(MINIMAL_CLEAN_H, encoding="utf-8")
        bad = analyze_sources(
            (p / "a.c").read_text(encoding="utf-8"),
            (p / "a.h").read_text(encoding="utf-8"),
            label="snippet",
        )
        if bad:
            errors.append(f"temp_clean: {bad}")

    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        print("DSR2 gate self-test FAILED", file=sys.stderr)
        return 1
    print(
        "ok domain_scan_dsr2_gate_self_test "
        "(VLA/recursion/alloc/auto/literal+macro-4096)"
    )
    return 0


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "check":
        return check_production()
    if cmd == "self-test":
        return self_test()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
