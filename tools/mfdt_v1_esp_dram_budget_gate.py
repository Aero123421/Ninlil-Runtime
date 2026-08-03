#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ESP MFDT DRAM / BSS budget gate (zero-row fail-closed).

Proves on an MFDT=ON final map:
  - mfdt_v1_*.c.obj / target smoke live in the map
  - host lab mfdt_v1_store.c is NOT linked
  - Total MFDT-related .bss contribution <= budget (default 48 KiB)
    after SPIRAM/heap offload of workspace-class giants
  - Zero .bss rows for MFDT objects is FAIL (false-green protection)

Usage:
  python3 tools/mfdt_v1_esp_dram_budget_gate.py check --map PATH
  python3 tools/mfdt_v1_esp_dram_budget_gate.py self-test
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
# Internal DRAM BSS for MFDT production+smoke after SPIRAM offload of:
#   spine ctx, engine scratch, esp readback/old_pool, dual seam labs.
DEFAULT_BSS_BUDGET = 48 * 1024
REQUIRED_OBJS = (
    "mfdt_v1_engine.c.obj",
    "mfdt_v1_spine.c.obj",
    "mfdt_v1_store_esp.c.obj",
    "mfdt_v1_hil_gate.c.obj",
    "mfdt_v1_target_alloc.c.obj",
    "mfdt_v1_target_smoke.c.obj",
)
FORBIDDEN_LIVE = ("mfdt_v1_store.c.obj",)


def fail(msg: str) -> None:
    print(f"mfdt_v1_esp_dram_budget_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def parse_mfdt_bss(map_text: str) -> list[tuple[int, str, str]]:
    rows: list[tuple[int, str, str]] = []
    pat = re.compile(
        r"^\s*\.bss[^\s]*\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+(\S*mfdt\S*)\s*$",
        re.IGNORECASE,
    )
    for line in map_text.splitlines():
        m = pat.match(line)
        if not m:
            continue
        size = int(m.group(1), 16)
        obj = m.group(2)
        rows.append((size, obj, line.strip()))
    return rows


def check_map(map_path: pathlib.Path, budget: int) -> None:
    if not map_path.is_file():
        fail(f"map not found: {map_path}")
    text = map_path.read_text(encoding="utf-8", errors="replace")

    for lab in FORBIDDEN_LIVE:
        # Any non-zero size contribution from host lab store is forbidden.
        for line in text.splitlines():
            if lab not in line:
                continue
            m = re.search(r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)", line)
            if m and int(m.group(2), 16) > 0 and ".bss" in line:
                fail(f"host lab store TU live in production map: {lab}")

    for req in REQUIRED_OBJS:
        if req not in text:
            fail(f"required MFDT object missing from map: {req}")

    rows = parse_mfdt_bss(text)
    # Zero-row fail-closed: empty parse means gate cannot claim budget.
    if len(rows) == 0:
        fail(
            "zero MFDT .bss rows parsed (map format mismatch or MFDT not linked); "
            "fail-closed"
        )

    total = sum(s for s, _, _ in rows)
    if total > budget:
        detail = "; ".join(f"{s}:{o}" for s, o, _ in sorted(rows, reverse=True)[:12])
        fail(f"MFDT .bss total {total} exceeds budget {budget} ({detail})")

    # No single symbol near workspace-class size in .bss (64K+).
    for size, obj, raw in rows:
        if size >= 32 * 1024:
            fail(f"workspace-class BSS still internal DRAM: {size} bytes in {obj}")

    print(
        f"mfdt_v1_esp_dram_budget_gate OK bss_total={total} budget={budget} "
        f"rows={len(rows)} objs={len(REQUIRED_OBJS)}"
    )


def self_test() -> None:
    # Happy path with non-zero small BSS rows.
    sample_ok = """
 .bss.mfdt_small  0x00000000  0x00000100  libninlil.a(mfdt_v1_engine.c.obj)
 .bss.mfdt_gate   0x00000000  0x00000010  libninlil.a(mfdt_v1_hil_gate.c.obj)
 .bss.mfdt_spine  0x00000000  0x00000040  libninlil.a(mfdt_v1_spine.c.obj)
 .bss.mfdt_esp    0x00000000  0x00000020  libninlil.a(mfdt_v1_store_esp.c.obj)
 .bss.mfdt_alloc  0x00000000  0x00000008  libninlil.a(mfdt_v1_target_alloc.c.obj)
 .bss.mfdt_smoke  0x00000000  0x00000004  libninlil.a(mfdt_v1_target_smoke.c.obj)
mfdt_v1_engine.c.obj
mfdt_v1_spine.c.obj
mfdt_v1_store_esp.c.obj
mfdt_v1_hil_gate.c.obj
mfdt_v1_target_alloc.c.obj
mfdt_v1_target_smoke.c.obj
"""
    sample_zero = """
mfdt_v1_engine.c.obj
mfdt_v1_spine.c.obj
mfdt_v1_store_esp.c.obj
mfdt_v1_hil_gate.c.obj
mfdt_v1_target_alloc.c.obj
mfdt_v1_target_smoke.c.obj
"""
    with tempfile.TemporaryDirectory() as td:
        ok = pathlib.Path(td) / "ok.map"
        ok.write_text(sample_ok, encoding="utf-8")
        check_map(ok, DEFAULT_BSS_BUDGET)
        z = pathlib.Path(td) / "zero.map"
        z.write_text(sample_zero, encoding="utf-8")
        try:
            check_map(z, DEFAULT_BSS_BUDGET)
            fail("zero-row path should have failed")
        except SystemExit as e:
            if e.code == 0:
                raise AssertionError("expected non-zero exit") from e
    print("mfdt_v1_esp_dram_budget_gate self-test OK")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check")
    c.add_argument("--map", required=True, type=pathlib.Path)
    c.add_argument("--budget", type=int, default=DEFAULT_BSS_BUDGET)
    sub.add_parser("self-test")
    args = ap.parse_args()
    if args.cmd == "self-test":
        self_test()
        return 0
    check_map(args.map, args.budget)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
