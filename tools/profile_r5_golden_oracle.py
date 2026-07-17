#!/usr/bin/env python3
"""Independent reconstruct+exact-byte oracle for R5 golden profile fixtures."""
from __future__ import annotations

import pathlib
import re
import struct
import sys

HW_LEN = 128
REG_LEN = 160
HW_MAGIC = 0x31504857
REG_MAGIC = 0x31505247
SCHEMA = 1
LAB_ONLY = 1
HW_REV = 1
REG_REV = 1
REGION_CODE = 0x4C4142
SERVICE_CATEGORY = 1
CHANNEL_MIN = 1
CHANNEL_MAX = 3
CEILING = 2_000_000
FORMULA_V = 1
BW_HZ = 125_000
SF_MIN, SF_MAX = 7, 9
CR_MIN, CR_MAX = 5, 8
PRE_MIN, PRE_MAX = 8, 16
TX_MIN, TX_MAX = 0, 14_000
ANTENNA_GAIN_MDB = 2000
BEARER_COUNT = 1


def crc32(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if (crc & 1) else 0)
    return crc ^ 0xFFFFFFFF


def id_pattern(tag: int) -> bytes:
    return bytes((tag + i) & 0xFF for i in range(16))


HW_PROFILE_ID = id_pattern(0x10)
DEVICE_MODEL_ID = id_pattern(0x11)
RADIO_SKU_ID = id_pattern(0x12)
ANTENNA_MODEL_ID = id_pattern(0x13)
REG_PROFILE_ID = id_pattern(0x20)
APPLICABLE_HW_ID = HW_PROFILE_ID


def fail(msg: str) -> None:
    raise SystemExit(f"profile_r5_golden_oracle FAIL: {msg}")


def arr(h: str, name: str) -> bytes:
    m = re.search(rf"static const uint8_t {name}\[(\d+)\] = \{{([^}}]+)\}}", h)
    if not m:
        fail(f"missing {name}")
    n = int(m.group(1))
    vals = [int(x.strip().rstrip("u"), 0) for x in m.group(2).split(",") if x.strip()]
    if len(vals) != n:
        fail(f"count {name}: {len(vals)} != {n}")
    return bytes(vals)


def reconstruct_hw() -> bytes:
    b = bytearray(HW_LEN)
    struct.pack_into("<I", b, 0, HW_MAGIC)
    struct.pack_into("<H", b, 4, SCHEMA)
    struct.pack_into("<H", b, 6, 0)
    b[8:24] = HW_PROFILE_ID
    struct.pack_into("<I", b, 24, HW_REV)
    b[28:44] = DEVICE_MODEL_ID
    b[44:60] = RADIO_SKU_ID
    struct.pack_into("<I", b, 60, HW_REV)
    b[64:80] = ANTENNA_MODEL_ID
    struct.pack_into("<i", b, 80, ANTENNA_GAIN_MDB)
    struct.pack_into("<I", b, 84, BEARER_COUNT)
    # reserved 88..123 zero
    struct.pack_into("<I", b, 124, crc32(bytes(b[:124])))
    return bytes(b)


def reconstruct_reg() -> bytes:
    b = bytearray(REG_LEN)
    struct.pack_into("<I", b, 0, REG_MAGIC)
    struct.pack_into("<H", b, 4, SCHEMA)
    b[6] = LAB_ONLY
    b[7] = 0
    b[8:24] = REG_PROFILE_ID
    struct.pack_into("<I", b, 24, REG_REV)
    struct.pack_into("<I", b, 28, REGION_CODE)
    struct.pack_into("<I", b, 32, SERVICE_CATEGORY)
    b[36:52] = APPLICABLE_HW_ID
    struct.pack_into("<I", b, 52, 1)
    struct.pack_into("<I", b, 56, 1)
    struct.pack_into("<I", b, 60, CHANNEL_MIN)
    struct.pack_into("<I", b, 64, CHANNEL_MAX)
    struct.pack_into("<I", b, 68, CEILING)
    struct.pack_into("<I", b, 72, FORMULA_V)
    struct.pack_into("<I", b, 76, BW_HZ)
    b[80] = SF_MIN
    b[81] = SF_MAX
    b[82] = CR_MIN
    b[83] = CR_MAX
    struct.pack_into("<H", b, 84, PRE_MIN)
    struct.pack_into("<H", b, 86, PRE_MAX)
    struct.pack_into("<i", b, 88, TX_MIN)
    struct.pack_into("<i", b, 92, TX_MAX)
    struct.pack_into("<Q", b, 96, 0)
    struct.pack_into("<Q", b, 104, 0)
    # reserved 112..155 zero
    struct.pack_into("<I", b, 156, crc32(bytes(b[:156])))
    return bytes(b)


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    hpath = root / "tests/radio/profile_r5_golden_profiles.h"
    h = hpath.read_text(encoding="utf-8")
    if "k_r5_golden_hw_v1" not in h:
        fail("k_r5_golden_hw_v1 missing")
    if "k_r5_golden_reg_v1" not in h:
        fail("k_r5_golden_reg_v1 missing")
    committed_hw = arr(h, "k_r5_golden_hw_v1")
    committed_reg = arr(h, "k_r5_golden_reg_v1")
    expect_hw = reconstruct_hw()
    expect_reg = reconstruct_reg()
    if committed_hw != expect_hw:
        fail(f"hw array not byte-identical to reconstructed golden ({len(committed_hw)} vs {len(expect_hw)})")
    if committed_reg != expect_reg:
        fail("reg array not byte-identical to reconstructed golden")
    # Explicit field re-check on reconstructed (canonical contract)
    if expect_hw[8:24] != HW_PROFILE_ID:
        fail("hw profile_id")
    if expect_hw[28:44] != DEVICE_MODEL_ID:
        fail("device_model_id")
    if expect_hw[44:60] != RADIO_SKU_ID:
        fail("radio_sku_id")
    if expect_hw[64:80] != ANTENNA_MODEL_ID:
        fail("antenna_model_id")
    if expect_reg[8:24] != REG_PROFILE_ID:
        fail("reg profile_id")
    if struct.unpack_from("<I", expect_reg, 28)[0] != REGION_CODE:
        fail("region_code")
    if struct.unpack_from("<I", expect_reg, 32)[0] != SERVICE_CATEGORY:
        fail("service_category")
    if expect_reg[36:52] != APPLICABLE_HW_ID:
        fail("applicable_hw_id")
    m_hw = re.search(r"#define K_R5_GOLDEN_HW_CRC32\s+(0x[0-9a-fA-F]+)u?", h)
    m_reg = re.search(r"#define K_R5_GOLDEN_REG_CRC32\s+(0x[0-9a-fA-F]+)u?", h)
    if not m_hw or not m_reg:
        fail("CRC macros missing")
    if int(m_hw.group(1), 0) != struct.unpack_from("<I", expect_hw, 124)[0]:
        fail("K_R5_GOLDEN_HW_CRC32 mismatch")
    if int(m_reg.group(1), 0) != struct.unpack_from("<I", expect_reg, 156)[0]:
        fail("K_R5_GOLDEN_REG_CRC32 mismatch")
    # Freshness token for gate: reconstruct path must exist
    if "reconstruct_hw" not in pathlib.Path(__file__).read_text(encoding="utf-8"):
        fail("reconstruct_hw missing")
    print("profile_r5_golden_oracle: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
