#!/usr/bin/env python3
"""Fail if RRMP storage bind uses non-existent MODE_ storage constants."""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE = ROOT / "src" / "runtime" / "route_relay_v1" / "rrmp_core.c"
PLATFORM = ROOT / "include" / "ninlil" / "platform.h"

FORBIDDEN = (
    "NINLIL_STORAGE_MODE_READ_WRITE",
    "NINLIL_STORAGE_MODE_READ_ONLY",
)
REQUIRED = (
    "NINLIL_STORAGE_READ_WRITE",
    "NINLIL_STORAGE_READ_ONLY",
    "NINLIL_DURABILITY_FULL",
)


def main() -> int:
    core = CORE.read_text(encoding="utf-8")
    plat = PLATFORM.read_text(encoding="utf-8")
    for bad in FORBIDDEN:
        # Allow #ifdef/#error guards that ban the obsolete names.
        for i, line in enumerate(core.splitlines(), 1):
            s = line.strip()
            if bad not in line:
                continue
            if s.startswith("#ifdef") or s.startswith("#ifndef") or s.startswith("#error"):
                continue
            if s.startswith("/*") or s.startswith("*") or s.startswith("//"):
                continue
            print(
                f"FAIL: {CORE.relative_to(ROOT)}:{i} uses forbidden {bad}",
                file=sys.stderr,
            )
            return 1
        if re.search(rf"#define\s+{bad}\b", plat):
            print(f"FAIL: platform defines obsolete {bad}", file=sys.stderr)
            return 1
    for need in REQUIRED:
        if need not in core:
            print(f"FAIL: {CORE} missing required {need}", file=sys.stderr)
            return 1
        if not re.search(rf"#define\s+{need}\b", plat):
            print(f"FAIL: platform missing {need}", file=sys.stderr)
            return 1
    # Production begin() must use actual mode constants (not MODE_ prefix).
    if not re.search(r"NINLIL_STORAGE_READ_WRITE\b", core):
        print("FAIL: missing READ_WRITE begin path", file=sys.stderr)
        return 1
    if not re.search(r"NINLIL_STORAGE_READ_ONLY\b", core):
        print("FAIL: missing READ_ONLY begin path", file=sys.stderr)
        return 1
    print("rrmp_storage_abi_gate OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
