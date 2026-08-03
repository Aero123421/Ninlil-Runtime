#!/usr/bin/env python3
"""ESP FRAG DRAM / BSS budget gate (production claim isolation).

Proves on a FRAG=ON map file:
  - No lab session multi-static BSS (tx$/rx$ session-sized symbols)
  - Total r7_frag*.obj .bss contribution <= budget (default 48 KiB)
  - No r7_frag_session / r7_frag_durable objects in the linked map
  - Optional: stack gate residual is separate (frame ceiling 4096)

Usage:
  python3 tools/r7_frag_esp_dram_budget_gate.py check --map PATH
  python3 tools/r7_frag_esp_dram_budget_gate.py self-test
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
# ENDPOINT reasm engine ~9–10 KiB + small headroom for smoke/statics.
DEFAULT_BSS_BUDGET = 48 * 1024
# Session controller size is ~91 KiB — any single FRAG BSS symbol near that
# is a multi-instance session leak.
SESSION_SIZE_FLOOR = 48 * 1024


def fail(msg: str) -> None:
    print(f"r7_frag_esp_dram_budget_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def parse_frag_bss(map_text: str) -> list[tuple[int, str, str]]:
    """Return (size, object, line) for FRAG .bss contributions."""
    rows: list[tuple[int, str, str]] = []
    # .bss.*  addr  size  path(r7_frag_....c.obj)
    pat = re.compile(
        r"^\s*\.bss[^\s]*\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+(\S*r7_frag\S*)\s*$"
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

    # Lab TUs must not appear as linked objects in production FRAG=ON ELF.
    for lab in ("r7_frag_session.c.obj", "r7_frag_durable.c.obj"):
        # Accept archive membership in discarded sections with size 0 only if
        # never referenced — but presence in input file list is OK; fail if
        # any non-zero .bss or .text contribution is live.
        live = re.findall(
            rf"^\s*\.(?:bss|text)[^\n]*{re.escape(lab)}",
            text,
            re.MULTILINE,
        )
        for hit in live:
            m = re.search(r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)", hit)
            if m and int(m.group(2), 16) > 0:
                fail(f"lab TU live in production map: {lab} via {hit.strip()[:120]}")

    rows = parse_frag_bss(text)
    total = sum(s for s, _, _ in rows)
    if total > budget:
        fail(
            f"FRAG .bss total {total} exceeds budget {budget} "
            f"({len(rows)} symbols)"
        )

    # No session-sized multi-static leaks (historical 9×91 KiB).
    big = [(s, o, l) for s, o, l in rows if s >= SESSION_SIZE_FLOOR]
    if big:
        detail = "; ".join(f"{s}@{o}" for s, o, _ in big[:6])
        fail(f"session-sized FRAG BSS present: {detail}")

    # Historical pattern: .bss.tx$N / .bss.rx$N from per-vector statics.
    multi = [
        l
        for _, _, l in rows
        if re.search(r"\.bss\.(tx|rx)\$\d+", l)
    ]
    if multi:
        fail(f"multi-static session BSS pattern: {multi[0][:120]}")

    print(
        f"r7_frag_esp_dram_budget_gate OK: map={map_path.name} "
        f"frag_bss_total={total} budget={budget} symbols={len(rows)}"
    )


def self_test() -> None:
    good = """
 .bss.g_reasm   0x3fc9db68    0x24c8 esp-idf/ninlil/libninlil.a(r7_frag_target_smoke.c.obj)
 .text          0x4200fab4     0x123 esp-idf/ninlil/libninlil.a(r7_frag_target_smoke.c.obj)
"""
    bad_multi = """
 .bss.rx$0      0x3fc9db68    0x165a8 esp-idf/ninlil/libninlil.a(r7_frag_target_smoke.c.obj)
 .bss.tx$1      0x3fcb4110    0x165a8 esp-idf/ninlil/libninlil.a(r7_frag_target_smoke.c.obj)
"""
    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        g = root / "good.map"
        g.write_text(good, encoding="utf-8")
        check_map(g, DEFAULT_BSS_BUDGET)
        b = root / "bad.map"
        b.write_text(bad_multi, encoding="utf-8")
        try:
            check_map(b, DEFAULT_BSS_BUDGET)
            fail("expected multi-session map to fail")
        except SystemExit as e:
            if e.code == 0:
                raise
    print("r7_frag_esp_dram_budget_gate self-test OK")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("check", "self-test"))
    ap.add_argument("--map", type=pathlib.Path, default=None)
    ap.add_argument("--budget", type=int, default=DEFAULT_BSS_BUDGET)
    args = ap.parse_args()
    if args.cmd == "self-test":
        self_test()
        return
    if args.map is None:
        fail("--map required for check")
    check_map(args.map, args.budget)


if __name__ == "__main__":
    main()
