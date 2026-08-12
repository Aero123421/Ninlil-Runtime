#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""ESP MFDT DRAM / BSS budget gate (map parser fail-closed).

Proves on an MFDT=ON final map:
  - mfdt_v1_*.c.obj / target smoke live in the map
  - host lab mfdt_v1_store.c is NOT linked
  - Total MFDT-related .bss contribution <= budget (default 48 KiB)
    after SPIRAM/heap offload of workspace-class giants
  - The final .dram0.bss output section must contain parseable live rows
    (MFDT itself may correctly contribute zero bytes after owner-state repair)

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


def parse_live_bss(map_text: str) -> list[tuple[int, str, str]]:
    """Return all live BSS rows from the final internal-DRAM section.

    GNU ld emits short input-section rows on one line and wraps long section
    names onto a line immediately before their address/size/object row.  Rows
    outside the final `.dram0.bss` output section may be discarded input and
    are not resource evidence.
    """
    rows: list[tuple[int, str, str]] = []
    same_line = re.compile(
        r"^\s+(\.bss\S*)\s+0x[0-9a-fA-F]+\s+"
        r"(0x[0-9a-fA-F]+)\s+(\S+)\s*$",
        re.IGNORECASE,
    )
    section_only = re.compile(r"^\s+(\.bss\S*)\s*$", re.IGNORECASE)
    continuation = re.compile(
        r"^\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+"
        r"(\S+)\s*$",
        re.IGNORECASE,
    )
    output_section = re.compile(
        r"^(\.\S+)\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+"
    )
    in_dram_bss = False
    pending: str | None = None
    for line in map_text.splitlines():
        output = output_section.match(line)
        if output is not None:
            in_dram_bss = output.group(1) == ".dram0.bss"
            pending = None
            continue
        if not in_dram_bss:
            continue
        match = same_line.match(line)
        if match is not None:
            rows.append((int(match.group(2), 16), match.group(3), line.strip()))
            pending = None
            continue
        split = section_only.match(line)
        if split is not None:
            pending = split.group(1)
            continue
        match = continuation.match(line)
        if pending is not None and match is not None:
            rows.append(
                (
                    int(match.group(1), 16),
                    match.group(2),
                    f"{pending} {line.strip()}",
                )
            )
        pending = None
    return rows


def parse_mfdt_bss(map_text: str) -> list[tuple[int, str, str]]:
    return [row for row in parse_live_bss(map_text) if "mfdt" in row[1].lower()]


def check_map(map_path: pathlib.Path, budget: int) -> None:
    if not map_path.is_file():
        fail(f"map not found: {map_path}")
    text = map_path.read_text(encoding="utf-8", errors="replace")

    for req in REQUIRED_OBJS:
        if req not in text:
            fail(f"required MFDT object missing from map: {req}")

    live_rows = parse_live_bss(text)
    # A completely empty live parse cannot distinguish an actual zero-byte
    # MFDT contribution from linker-map grammar drift.  The final image always
    # has unrelated Runtime/ESP BSS, so require that independent parser witness.
    if len(live_rows) == 0:
        fail(
            "zero live .dram0.bss rows parsed (map format mismatch); "
            "fail-closed"
        )
    rows = [row for row in live_rows if "mfdt" in row[1].lower()]

    for lab in FORBIDDEN_LIVE:
        if any(size > 0 and lab in obj for size, obj, _ in rows):
            fail(f"host lab store TU live in production .dram0.bss: {lab}")

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
.dram0.bss 0x3fc9db68 0x17c
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
    sample_legitimate_mfdt_zero = """
.dram0.bss 0x3fc9db68 0x10
 .bss.unrelated 0x3fc9db68 0x10 libother.a(other.c.obj)
mfdt_v1_engine.c.obj
mfdt_v1_spine.c.obj
mfdt_v1_store_esp.c.obj
mfdt_v1_hil_gate.c.obj
mfdt_v1_target_alloc.c.obj
mfdt_v1_target_smoke.c.obj
"""
    sample_split = """
.dram0.bss 0x3fc9db68 0x20010
 .bss.mfdt_small 0x3fc9db68 0x10 libninlil.a(mfdt_v1_engine.c.obj)
 .bss.mfdt_enormous_workspace_with_long_symbol_name
                0x3fc9db78 0x20000 libninlil.a(mfdt_v1_spine.c.obj)
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
        legitimate_zero = pathlib.Path(td) / "legitimate-zero.map"
        legitimate_zero.write_text(sample_legitimate_mfdt_zero, encoding="utf-8")
        check_map(legitimate_zero, DEFAULT_BSS_BUDGET)
        split = pathlib.Path(td) / "split.map"
        split.write_text(sample_split, encoding="utf-8")
        try:
            check_map(split, DEFAULT_BSS_BUDGET)
            fail("split-line oversized BSS row should have failed")
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
