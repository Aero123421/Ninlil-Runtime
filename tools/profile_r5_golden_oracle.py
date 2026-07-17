#!/usr/bin/env python3
"""Independent CRC/offset oracle for R5 golden profile fixtures."""
from __future__ import annotations
import pathlib, re, sys

def crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
    return crc ^ 0xFFFFFFFF

def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    h = (root / "tests/radio/profile_r5_golden_profiles.h").read_text()
    def arr(name: str) -> bytes:
        m = re.search(rf"static const uint8_t {name}\[(\d+)\] = \{{([^}}]+)\}}", h)
        if not m:
            raise SystemExit(f"missing {name}")
        n = int(m.group(1))
        vals = [int(x.strip().rstrip("u"), 0) for x in m.group(2).split(",") if x.strip()]
        if len(vals) != n:
            raise SystemExit(f"count {name}")
        return bytes(vals)
    hw = arr("k_r5_golden_hw_v1")
    reg = arr("k_r5_golden_reg_v1")
    if len(hw) != 128 or len(reg) != 160:
        raise SystemExit("size")
    if int.from_bytes(hw[0:4], "little") != 0x31504857:
        raise SystemExit("hw magic")
    if int.from_bytes(reg[0:4], "little") != 0x31505247:
        raise SystemExit("reg magic")
    if reg[6] != 1:
        raise SystemExit("not LAB_ONLY")
    if crc32(hw[:124]) != int.from_bytes(hw[124:128], "little"):
        raise SystemExit("hw crc")
    if crc32(reg[:156]) != int.from_bytes(reg[156:160], "little"):
        raise SystemExit("reg crc")
    print("profile_r5_golden_oracle: OK")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
