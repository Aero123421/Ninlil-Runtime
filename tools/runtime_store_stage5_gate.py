#!/usr/bin/env python3
"""D2-S6 private Stage 5 seam source gate (stdlib only).

Analyzes production stage5 seam + L2b1 orchestrator sources after stripping
C comments/strings. Fail-closed on parse gaps.

Proves:
  - no malloc/calloc/realloc/free/alloca
  - no 65536 / allocator reread in L2b1 orchestrator
  - ban VLA / large automatic stage5/L2b1/scanner workspaces in seam+orch
  - seam calls begin_profiled exactly once; bare TEST begin 0; note 0;
    finalize exactly once; abort 0
  - storage_recovery_complete never assigned nonzero
  - orchestrator BTS has no second iter_next/reread path
  - public header leak absent
  - seam hookup does not declare workspace automatic locals

Usage:
  python3 tools/runtime_store_stage5_gate.py check
  python3 tools/runtime_store_stage5_gate.py self-test

CTest names:
  runtime_store_stage5_seam_source_gate
  runtime_store_stage5_gate_self_test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
SEAM_C = REPO_ROOT / "src" / "runtime" / "runtime_store_stage5_seam.c"
SEAM_H = REPO_ROOT / "src" / "runtime" / "runtime_store_stage5_seam.h"
ORCH_C = REPO_ROOT / "src" / "runtime" / "runtime_store_orchestrator.c"
PUBLIC_LEAK = REPO_ROOT / "include" / "ninlil" / "runtime_store_stage5_seam.h"

ALLOC_CALL_RE = re.compile(r"\b(malloc|calloc|realloc|free|alloca)\s*\(")
STACK_65536_RE = re.compile(r"\[\s*65536\s*\]|M1A_MAX_STORAGE_VALUE_BYTES|65536")
REREAD_PATTERN_RE = re.compile(
    r"(re-?read|reread|temporary\s+alloc|allocator\s*->\s*allocate|"
    r"temporary\s*=)",
    re.IGNORECASE,
)
# Automatic large / phase workspace locals inside function bodies.
AUTO_FORBIDDEN_RE = re.compile(
    r"\b("
    r"ninlil_runtime_store_stage5_workspace_t|"
    r"ninlil_runtime_store_bootstrap_workspace_t|"
    r"ninlil_domain_scan_workspace_t|"
    r"ninlil_domain_scan_session_t"
    r")\s+\w+\s*[;=\[\]]"
)
AUTO_LARGE_ARRAY_RE = re.compile(
    r"\b(?:uint8_t|char|unsigned\s+char)\s+\w+\s*\[\s*"
    r"(?:4096|8192|65536|8704|"
    r"NINLIL_DOMAIN_SCAN_VALUE_CAPACITY|"
    r"NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES|"
    r"NINLIL_RUNTIME_STORE_L2B1_SCAN_VALUE_CAPACITY|"
    r"NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES)\s*\]"
)
VLA_RE = re.compile(
    r"\b(?:uint8_t|char|int|unsigned(?:\s+char)?)\s+\w+\s*"
    r"\[\s*([a-zA-Z_]\w*)\s*\]"
)
# BTS path that immediately re-calls iter_next (legacy reread).
BTS_REREAD_RE = re.compile(
    r"BUFFER_TOO_SMALL[\s\S]{0,240}iter_next",
    re.IGNORECASE,
)
RECOVERY_ASSIGN_RE = re.compile(
    r"storage_recovery_complete\s*=\s*([^;]+);"
)


def strip_c_comments_and_strings(src: str) -> str:
    """Remove // and /* */ comments and string/char literals for analysis."""
    out: List[str] = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            i += 2
            while i < n and src[i] not in "\n\r":
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] in "\n\r":
                    out.append(src[i])
                i += 1
            i = min(i + 2, n)
            continue
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


FUNC_DEF_RE = re.compile(
    r"(?m)^(?:static\s+)?(?:inline\s+)?"
    r"(?:const\s+)?"
    r"(?:void|int|uint8_t|uint16_t|uint32_t|uint64_t|size_t|ninlil_\w+_t)\s+"
    r"(\w+)\s*\("
)


def extract_functions(src_stripped: str) -> Dict[str, str]:
    functions: Dict[str, str] = {}
    for m in FUNC_DEF_RE.finditer(src_stripped):
        name = m.group(1)
        rest = src_stripped[m.end() - 1 :]
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
            raise SystemExit(f"stage5 gate: cannot parse parameter list for {name}")
        after = rest[j:].lstrip()
        if after.startswith(";"):
            continue
        if not after.startswith("{"):
            raise SystemExit(
                f"stage5 gate: cannot locate function body for {name} "
                f"(after params starts with {after[:40]!r})"
            )
        brace_abs = m.end() - 1 + j
        while brace_abs < len(src_stripped) and src_stripped[brace_abs] in " \t\r\n":
            brace_abs += 1
        if brace_abs >= len(src_stripped) or src_stripped[brace_abs] != "{":
            raise SystemExit(
                f"stage5 gate: function body open-brace missing for {name}"
            )
        end = find_matching_brace(src_stripped, brace_abs)
        if end is None:
            raise SystemExit(f"stage5 gate: unclosed function body for {name}")
        body = src_stripped[brace_abs : end + 1]
        if name in functions and functions[name] != body:
            raise SystemExit(
                f"stage5 gate: duplicate conflicting definition for {name}"
            )
        functions[name] = body
    if not functions:
        raise SystemExit("stage5 gate: parsed zero function bodies (parser fail)")
    return functions


def count_calls(body: str, name: str) -> int:
    return len(re.findall(r"\b" + re.escape(name) + r"\s*\(", body))


def analyze_sources(
    seam_c: str,
    seam_h: str,
    orch_c: str,
    *,
    label: str = "production",
    public_leak_exists: bool = False,
) -> List[str]:
    bad: List[str] = []
    seam_cs = strip_c_comments_and_strings(seam_c)
    seam_hs = strip_c_comments_and_strings(seam_h)
    orch_cs = strip_c_comments_and_strings(orch_c)
    combined = seam_cs + "\n" + seam_hs + "\n" + orch_cs

    for m in ALLOC_CALL_RE.finditer(combined):
        bad.append(f"allocator_call:{m.group(1)}")
    if STACK_65536_RE.search(orch_cs):
        bad.append("orch_65536_or_abi_max_value")
    if REREAD_PATTERN_RE.search(orch_cs):
        bad.append("orch_reread_or_allocate_pattern")
    if BTS_REREAD_RE.search(orch_cs):
        bad.append("orch_bts_second_iter_next_reread")

    if public_leak_exists:
        bad.append("public_include_leak")

    if "NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES" not in seam_hs:
        bad.append("missing_ceiling")

    try:
        seam_funcs = extract_functions(seam_cs)
        orch_funcs = extract_functions(orch_cs)
    except SystemExit as e:
        bad.append(f"parser_fail:{e}")
        return sorted(set(bad))

    if label == "production":
        if "ninlil_runtime_store_stage5_private_hookup" not in seam_funcs:
            bad.append("missing_entry:ninlil_runtime_store_stage5_private_hookup")
        if "ninlil_runtime_store_orchestrate_bootstrap" not in orch_funcs:
            bad.append("missing_entry:ninlil_runtime_store_orchestrate_bootstrap")

    # Seam TU function-body bans.
    for fname, body in seam_funcs.items():
        if AUTO_FORBIDDEN_RE.search(body):
            bad.append(f"auto_workspace:{fname}")
        if AUTO_LARGE_ARRAY_RE.search(body):
            bad.append(f"auto_large_array:{fname}")
        for vm in VLA_RE.finditer(body):
            size_tok = vm.group(1)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", size_tok):
                bad.append(f"possible_vla:{fname}")
                break

    for fname, body in orch_funcs.items():
        if AUTO_FORBIDDEN_RE.search(body):
            # L2b1 accepts workspace pointer only; no automatic workspace.
            bad.append(f"orch_auto_workspace:{fname}")
        if AUTO_LARGE_ARRAY_RE.search(body):
            bad.append(f"orch_auto_large_array:{fname}")
        for vm in VLA_RE.finditer(body):
            size_tok = vm.group(1)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]*", size_tok):
                bad.append(f"orch_possible_vla:{fname}")
                break

    # Seam call-site contract across the translation unit body text.
    begin_profiled = count_calls(seam_cs, "ninlil_domain_scan_begin_profiled")
    # Bare begin: ninlil_domain_scan_begin( not followed by _profiled
    bare_begin = len(
        re.findall(r"(?<!_profiled)ninlil_domain_scan_begin\s*\(", seam_cs)
    )
    # The lookbehind above still matches begin_profiled if written as
    # ninlil_domain_scan_begin_profiled — fix by subtracting profiled.
    # Safer: count exact non-profiled.
    bare_begin = len(
        [
            m
            for m in re.finditer(r"\bninlil_domain_scan_begin\s*\(", seam_cs)
            if not seam_cs[m.end() : m.end() + 10].startswith("_profiled")
            and not seam_cs[m.start() : m.end()].endswith("_profiled")
        ]
    )
    # Even safer: only count identifiers that are exactly begin not begin_profiled.
    bare_begin = 0
    for m in re.finditer(r"\bninlil_domain_scan_begin(_profiled)?\s*\(", seam_cs):
        if m.group(1) is None:
            bare_begin += 1
    finalize_n = count_calls(seam_cs, "ninlil_domain_scan_finalize")
    abort_n = count_calls(seam_cs, "ninlil_domain_scan_abort")
    note_n = count_calls(seam_cs, "ninlil_domain_scan_note_terminal_corrupt")
    # Also ban note by name without call paren.
    if "note_terminal_corrupt" in seam_cs:
        note_n = max(note_n, 1)

    if label == "production":
        if begin_profiled != 1:
            bad.append(f"begin_profiled_count:{begin_profiled}")
        if bare_begin != 0:
            bad.append(f"bare_test_begin_count:{bare_begin}")
        if finalize_n != 1:
            bad.append(f"finalize_count:{finalize_n}")
        if abort_n != 0:
            bad.append(f"abort_count:{abort_n}")
        if note_n != 0:
            bad.append(f"note_terminal_corrupt_present")

    # storage_recovery_complete never assigned nonzero.
    for m in RECOVERY_ASSIGN_RE.finditer(seam_cs):
        rhs = m.group(1).strip()
        if rhs not in ("0", "0u", "0U", "(uint32_t)0", "(uint32_t)0u"):
            bad.append(f"storage_recovery_complete_nonzero_assign:{rhs}")

    return sorted(set(bad))


def check_production() -> int:
    if not SEAM_C.is_file() or not SEAM_H.is_file() or not ORCH_C.is_file():
        print("missing stage5/orchestrator sources", file=sys.stderr)
        return 1
    bad = analyze_sources(
        SEAM_C.read_text(encoding="utf-8"),
        SEAM_H.read_text(encoding="utf-8"),
        ORCH_C.read_text(encoding="utf-8"),
        label="production",
        public_leak_exists=PUBLIC_LEAK.exists(),
    )
    if bad:
        print("stage5 seam source gate failed:", bad, file=sys.stderr)
        return 1
    print(
        "ok runtime_store_stage5_seam_source_gate "
        f"seam={SEAM_C.name} orch={ORCH_C.name}"
    )
    return 0


# --- Synthetic snippets for negative self-tests ---------------------------

CLEAN_SEAM_H = """
#define NINLIL_RUNTIME_STORE_STAGE5_WORKSPACE_CEILING_BYTES ((uint32_t)8704u)
typedef struct ninlil_runtime_store_stage5_workspace {
    int dummy;
} ninlil_runtime_store_stage5_workspace_t;
"""

CLEAN_SEAM_C = """
#include <stdint.h>
static int ranges_are_disjoint(void) { return 1; }
static ninlil_status_t run_existing_profile_scan(void)
{
    ninlil_domain_scan_begin_profiled();
    ninlil_domain_scan_finalize();
    return 0;
}
ninlil_status_t ninlil_runtime_store_stage5_private_hookup(void)
{
    return run_existing_profile_scan();
}
"""

CLEAN_ORCH_C = """
#include <stdint.h>
ninlil_status_t ninlil_runtime_store_orchestrate_bootstrap(void)
{
    if (status == BUFFER_TOO_SMALL) {
        return CORRUPT;
    }
    return 0;
}
"""


def _expect_reject(
    name: str,
    seam_c: str,
    seam_h: str,
    orch_c: str,
    needle: str,
    *,
    public_leak: bool = False,
) -> Optional[str]:
    bad = analyze_sources(
        seam_c, seam_h, orch_c, label="snippet", public_leak_exists=public_leak
    )
    if not bad:
        return f"{name}: expected reject, got pass"
    joined = " ".join(bad)
    if needle not in joined:
        return f"{name}: expected needle {needle!r} in {bad}"
    return None


def _expect_pass(
    name: str, seam_c: str, seam_h: str, orch_c: str
) -> Optional[str]:
    bad = analyze_sources(seam_c, seam_h, orch_c, label="snippet")
    if bad:
        return f"{name}: expected pass, got {bad}"
    return None


def self_test() -> int:
    errors: List[str] = []

    err = _expect_pass("clean", CLEAN_SEAM_C, CLEAN_SEAM_H, CLEAN_ORCH_C)
    if err:
        errors.append(err)

    # Allocator
    alloc_c = CLEAN_SEAM_C.replace(
        "return run_existing_profile_scan();",
        "void *p = malloc(8); (void)p; return run_existing_profile_scan();",
    )
    err = _expect_reject(
        "allocator", alloc_c, CLEAN_SEAM_H, CLEAN_ORCH_C, "allocator_call"
    )
    if err:
        errors.append(err)

    # Bare TEST begin is only enforced under label="production".
    # Snippet-label _expect_reject would always false-pass/discard; check
    # the production-label path and require the needle in every failure path.
    bare_c = CLEAN_SEAM_C.replace(
        "ninlil_domain_scan_begin_profiled();",
        "ninlil_domain_scan_begin();",
    )
    bare_prod = analyze_sources(
        bare_c, CLEAN_SEAM_H, CLEAN_ORCH_C, label="production"
    )
    if not bare_prod:
        errors.append("bare_begin: expected reject, got pass")
    elif not any("bare_test_begin" in x for x in bare_prod):
        errors.append(f"bare_begin: expected bare_test_begin in {bare_prod}")

    # Double finalize
    dbl_fin = CLEAN_SEAM_C.replace(
        "ninlil_domain_scan_finalize();",
        "ninlil_domain_scan_finalize(); ninlil_domain_scan_finalize();",
    )
    dbl = analyze_sources(dbl_fin, CLEAN_SEAM_H, CLEAN_ORCH_C, label="production")
    if not any("finalize_count" in x for x in dbl):
        errors.append(f"double_finalize: expected finalize_count in {dbl}")

    # Nonzero recovery complete
    rec_c = CLEAN_SEAM_C.replace(
        "return run_existing_profile_scan();",
        "out->storage_recovery_complete = 1u; return run_existing_profile_scan();",
    )
    err = _expect_reject(
        "nonzero_recovery",
        rec_c,
        CLEAN_SEAM_H,
        CLEAN_ORCH_C,
        "storage_recovery_complete_nonzero",
    )
    if err:
        errors.append(err)

    # VLA / auto workspace
    vla_c = CLEAN_SEAM_C.replace(
        "static ninlil_status_t run_existing_profile_scan(void)\n{\n"
        "    ninlil_domain_scan_begin_profiled();\n"
        "    ninlil_domain_scan_finalize();\n"
        "    return 0;\n}",
        "static ninlil_status_t run_existing_profile_scan(void)\n{\n"
        "    int n = 32;\n"
        "    uint8_t buf[n];\n"
        "    (void)buf;\n"
        "    ninlil_domain_scan_begin_profiled();\n"
        "    ninlil_domain_scan_finalize();\n"
        "    return 0;\n}",
    )
    err = _expect_reject("vla", vla_c, CLEAN_SEAM_H, CLEAN_ORCH_C, "possible_vla")
    if err:
        errors.append(err)

    auto_c = CLEAN_SEAM_C.replace(
        "static ninlil_status_t run_existing_profile_scan(void)\n{\n"
        "    ninlil_domain_scan_begin_profiled();\n"
        "    ninlil_domain_scan_finalize();\n"
        "    return 0;\n}",
        "static ninlil_status_t run_existing_profile_scan(void)\n{\n"
        "    ninlil_runtime_store_stage5_workspace_t local_ws;\n"
        "    (void)local_ws;\n"
        "    ninlil_domain_scan_begin_profiled();\n"
        "    ninlil_domain_scan_finalize();\n"
        "    return 0;\n}",
    )
    err = _expect_reject(
        "auto_workspace", auto_c, CLEAN_SEAM_H, CLEAN_ORCH_C, "auto_workspace"
    )
    if err:
        errors.append(err)

    # Legacy reread in orchestrator
    reread_orch = """
ninlil_status_t ninlil_runtime_store_orchestrate_bootstrap(void)
{
    if (status == BUFFER_TOO_SMALL) {
        temporary = allocator->allocate(65536);
        iter_next(it, &k, &v);
    }
    return 0;
}
"""
    err = _expect_reject(
        "legacy_reread",
        CLEAN_SEAM_C,
        CLEAN_SEAM_H,
        reread_orch,
        "orch_",
    )
    if err:
        errors.append(err)

    if errors:
        for e in errors:
            print("self-test fail:", e, file=sys.stderr)
        return 1
    print("ok runtime_store_stage5_gate_self_test")
    return 0


def main(argv: List[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: runtime_store_stage5_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    if argv[1] == "check":
        return check_production()
    return self_test()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
