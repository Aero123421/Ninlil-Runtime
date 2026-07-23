#!/usr/bin/env python3
"""V1-LAB durable allowlist structural gate (unit 1a).

Ensures production durable puts flow only through v1_durable_allowlist.c and
that the closed allowlist table count matches the header constant.

Usage:
  python3 tools/v1_durable_allowlist_gate.py check
  python3 tools/v1_durable_allowlist_gate.py self-test

CTest names:
  v1_durable_allowlist_source_gate
  v1_durable_allowlist_gate_self_test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_C = REPO_ROOT / "src" / "runtime" / "v1_durable_allowlist.c"
ALLOWLIST_H = REPO_ROOT / "src" / "runtime" / "v1_durable_allowlist.h"
STAGE5_C = REPO_ROOT / "src" / "runtime" / "stage5_empty_metadata.c"
CANONICAL_C = REPO_ROOT / "src" / "runtime" / "storage_canonical_plan.c"
PUBLIC_LEAK = REPO_ROOT / "include" / "ninlil" / "v1_durable_allowlist.h"

DIRECT_PUT_RE = re.compile(r"storage\s*->\s*put\s*\(")
STORAGE_PUT_RE = re.compile(r"ninlil_v1_durable_storage_put\s*\(")
GATE_CHECK_RE = re.compile(r"ninlil_v1_durable_writer_gate_check\s*\(")
TABLE_ROW_RE = re.compile(
    r"\{NINLIL_V1_DURABLE_KIND_[A-Z0-9_]+,\s*NINLIL_V1_DURABLE_OWNER_[A-Z0-9]+,"
)
KIND_COUNT_RE = re.compile(
    r"#define\s+NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT\s+\(\(uint32_t\)(\d+)u\)"
)


def strip_c_comments_and_strings(src: str) -> str:
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
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i = min(i + 1, n)
            continue
        if ch == "'":
            out.append(" ")
            i += 1
            while i < n and src[i] != "'":
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i = min(i + 1, n)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def count_table_rows(c_src: str) -> int:
    return len(TABLE_ROW_RE.findall(c_src))


def check() -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    if PUBLIC_LEAK.is_file():
        errors.append(f"public header leak: {PUBLIC_LEAK}")

    h_text = read_text(ALLOWLIST_H)
    c_text = read_text(ALLOWLIST_C)
    m = KIND_COUNT_RE.search(h_text)
    if not m:
        errors.append("missing NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT in header")
        declared = 0
    else:
        declared = int(m.group(1))

    actual = count_table_rows(c_text)
    if actual != declared:
        errors.append(
            f"allowlist table row count {actual} != header constant {declared}"
        )

    stage5_stripped = strip_c_comments_and_strings(read_text(STAGE5_C))
    if not STORAGE_PUT_RE.search(stage5_stripped):
        errors.append("stage5_empty_metadata.c missing ninlil_v1_durable_storage_put")
    stage5_puts = list(DIRECT_PUT_RE.finditer(stage5_stripped))
    if len(stage5_puts) != 0:
        errors.append(
            f"stage5_empty_metadata.c: expected 0 direct storage->put "
            f"(use ninlil_v1_durable_storage_put), found {len(stage5_puts)}"
        )
    elif "put_encoded" not in stage5_stripped:
        errors.append("stage5_empty_metadata.c: durable put outside put_encoded")

    # allowlist.c may call storage->put inside ninlil_v1_durable_storage_put only
    allowlist_stripped = strip_c_comments_and_strings(c_text)
    puts = list(DIRECT_PUT_RE.finditer(allowlist_stripped))
    if len(puts) != 1:
        errors.append(
            f"v1_durable_allowlist.c: expected exactly 1 storage->put, found {len(puts)}"
        )

    if "ninlil_v1_durable_writer_gate_check" not in read_text(
        REPO_ROOT / "src" / "runtime" / "runtime_store_orchestrator.c"
    ):
        errors.append(
            "runtime_store_orchestrator.c missing bootstrap writer gate check"
        )
    if "ninlil_v1_durable_storage_put" not in read_text(STAGE5_C):
        errors.append("stage5_empty_metadata.c missing domain storage_put wiring")

    return errors, warnings


def self_test() -> None:
    errors, _ = check()
    if errors:
        print("self-test precondition failed:", *errors, sep="\n  ")
        sys.exit(1)

    orig = read_text(STAGE5_C)

    def mut_bypass_gate() -> None:
        STAGE5_C.write_text(
            orig.replace(
                "gate_status = ninlil_v1_durable_storage_put(\n"
                "        operation, storage, txn, k, v, inout_fence);",
                "gate_status = NINLIL_OK; /* storage_put removed for mutation */",
                1,
            ),
            encoding="utf-8",
        )

    try:
        mut_bypass_gate()
        e, _ = check()
        if not any("storage_put" in x for x in e):
            print("mutation: storage_put bypass in stage5 did not go red")
            sys.exit(1)
    finally:
        STAGE5_C.write_text(orig, encoding="utf-8")

    orig_h = read_text(ALLOWLIST_H)
    try:
        ALLOWLIST_H.write_text(
            orig_h.replace(
                "NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT ((uint32_t)29u)",
                "NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT ((uint32_t)99u)",
            ),
            encoding="utf-8",
        )
        e, _ = check()
        if not any("table row count" in x for x in e):
            print("mutation: kind count mismatch did not go red")
            sys.exit(1)
    finally:
        ALLOWLIST_H.write_text(orig_h, encoding="utf-8")

    print("ok v1_durable_allowlist_gate_self_test")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "self-test"):
        print("usage: v1_durable_allowlist_gate.py check|self-test", file=sys.stderr)
        sys.exit(2)
    if sys.argv[1] == "self-test":
        self_test()
        return
    errors, warnings = check()
    for w in warnings:
        print(f"warning: {w}")
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    print("ok v1_durable_allowlist_source_gate")


if __name__ == "__main__":
    main()
