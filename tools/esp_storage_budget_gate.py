#!/usr/bin/env python3
"""Budget gate for ESP dual-slot storage workspace sizes.

Checks compile-time ceilings in headers against docs/21 production profile
and that 65536-byte single value remains representable.
Does not claim ESP map file HIL evidence.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
HEADER = REPO / "ports/esp-idf/storage/include/ninlil_port/esp_storage.h"
DOCS = REPO / "docs/21-m3-esp-idf-durable-storage.md"


def fail(msg: str) -> None:
    print(f"esp_storage_budget_gate FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def macro_u32(text: str, name: str) -> int:
    m = re.search(
        rf"#define\s+{re.escape(name)}\s+\(\(uint32_t\)(\d+)u\)", text
    )
    if not m:
        # try size_t ceiling form
        m = re.search(
            rf"#define\s+{re.escape(name)}\s+\(\(size_t\)(\d+)u\)", text
        )
    if not m:
        fail(f"missing macro {name}")
    return int(m.group(1))


def main() -> None:
    text = HEADER.read_text(encoding="utf-8")
    docs = DOCS.read_text(encoding="utf-8")
    logical = macro_u32(text, "NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES")
    prod_logical = macro_u32(
        text, "NINLIL_PORT_ESP_STORAGE_PROD_MAX_LOGICAL_BYTES"
    )
    persisted_logical = macro_u32(
        text, "NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_LOGICAL_BYTES"
    )
    staged_entries = macro_u32(text, "NINLIL_PORT_ESP_STORAGE_HARD_MAX_ENTRIES")
    persisted_entries = macro_u32(
        text, "NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES"
    )
    obj_ceil = macro_u32(text, "NINLIL_PORT_ESP_STORAGE_OBJECT_SIZEOF_CEILING")
    view_ceil = macro_u32(text, "NINLIL_PORT_ESP_STORAGE_VIEW_SIZEOF_CEILING")

    min_for_max_value = 16 + 1 + 65536
    if logical < min_for_max_value:
        fail(f"HARD logical bytes {logical} < {min_for_max_value}")
    if prod_logical < min_for_max_value:
        fail(f"PROD logical bytes {prod_logical} < {min_for_max_value}")
    if persisted_logical != prod_logical:
        fail("persisted and production logical ceilings must match this profile")
    if logical < 2 * prod_logical:
        fail("staging logical ceiling must hold production old+new final views")
    if persisted_entries != 32 or staged_entries < 2 * persisted_entries:
        fail("staging entry ceiling must hold full put-before-erase profile")
    if obj_ceil < 400000:
        fail("object ceiling too small for dual work views + txn pool")
    stack_m = re.search(
        r"#define\s+NINLIL_PORT_ESP_STORAGE_MAX_STACK_FRAME_BYTES\s+"
        r"\(\(size_t\)(\d+)u\)",
        text,
    )
    if not stack_m:
        fail("missing MAX_STACK_FRAME_BYTES")
    if int(stack_m.group(1)) > 2048:
        fail("MAX_STACK_FRAME_BYTES must be <= 2048 for FreeRTOS tasks")
    if view_ceil < min_for_max_value:
        fail("view ceiling too small for max value")
    if "PSRAM" not in docs:
        fail("docs/21 must document PSRAM requirement")
    if "HIL" not in docs:
        fail("docs/21 must document HIL status")
    if "directory" not in docs.lower() and "Directory" not in docs:
        fail("docs/21 must document durable directory")

    print(
        "esp_storage_budget_gate OK: "
        f"logical={logical} prod_logical={prod_logical} "
        f"obj_ceil={obj_ceil} view_ceil={view_ceil}"
    )


if __name__ == "__main__":
    main()
