#!/usr/bin/env python3
"""
RRMP frame stack gate: reject 4 KiB validate/page copy frames.

Scans RRMP sources for stack-resident 4096-byte page temps (the ESP
-Wframe-larger-than=2048 failure class). Does not raise the ceiling.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RRMP = ROOT / "src" / "runtime" / "route_relay_v1"
CEILING = 2048

# Patterns that put full 4 KiB pages on the stack (forbidden).
FORBIDDEN = [
    re.compile(r"uint8_t\s+tmp\s*\[\s*NINLIL_RRMP_(?:NRP1|NEP1|NPP1|NPA1|NPT1)_BYTES\s*\]"),
    re.compile(r"uint8_t\s+tmp\s*\[\s*4096\s*u?\s*\]"),
    re.compile(
        r"uint8_t\s+packed\s*\[\s*NINLIL_RRMP_NEP1_SLOTS\s*\*\s*NINLIL_RRMP_NEV1_BYTES\s*\]"
    ),
]


def main() -> int:
    bad: list[str] = []
    for path in sorted(RRMP.glob("*.c")):
        text = path.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("/*") or stripped.startswith("*") or stripped.startswith("//"):
                continue
            for pat in FORBIDDEN:
                if pat.search(line):
                    bad.append(f"{path.relative_to(ROOT)}:{i}: {stripped}")
    if bad:
        print("FAIL: RRMP stack page temps (ceiling remains %d):" % CEILING, file=sys.stderr)
        for b in bad:
            print("  " + b, file=sys.stderr)
        return 1
    # Positive: zeroed-field CRC helper must exist (in-place validate path).
    util = (RRMP / "rrmp_util.c").read_text(encoding="utf-8")
    if "ninlil_rrmp_crc32c_zeroed_u32_be_field" not in util:
        print("FAIL: missing in-place CRC helper", file=sys.stderr)
        return 1
    codec = (RRMP / "rrmp_codec.c").read_text(encoding="utf-8")
    for name in (
        "validate_nrp1",
        "validate_nep1",
        "validate_npp1",
        "validate_npa1",
        "validate_npt1",
    ):
        if f"ninlil_rrmp_{name}" not in codec:
            print(f"FAIL: missing {name}", file=sys.stderr)
            return 1
        # Each must call zeroed-field helper (no full page tmp).
    uses = codec.count("ninlil_rrmp_crc32c_zeroed_u32_be_field")
    if uses < 5:
        print(f"FAIL: expected >=5 zeroed-field CRC uses, got {uses}", file=sys.stderr)
        return 1
    print(f"rrmp_frame_stack_gate OK ceiling={CEILING} zeroed_crc_uses={uses}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
