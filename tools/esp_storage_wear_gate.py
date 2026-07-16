#!/usr/bin/env python3
"""Fail closed if the ESP storage wear contract or budget silently regresses."""

from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
HEADER = REPO / "ports/esp-idf/storage/include/ninlil_port/esp_storage.h"
PARTITIONS = REPO / "ports/esp-idf/partitions/ninlil_storage.csv"
FLASH = REPO / "ports/esp-idf/storage/esp/esp_storage_flash_media.c"
MODEL = REPO / "ports/esp-idf/storage/model/esp_storage_model.c"
TESTS = REPO / "tests/port/esp_storage_conformance_test.c"
SDKCONFIG = REPO / "ports/esp-idf/smoke_app/sdkconfig.defaults"
DOCS = REPO / "docs/21-m3-esp-idf-durable-storage.md"


def macro(text: str, name: str) -> int:
    found = re.search(
        rf"#define\s+{re.escape(name)}\s+\(\(uint32_t\)(\d+)u\)", text
    )
    if not found:
        raise SystemExit(f"esp_storage_wear_gate FAIL: missing {name}")
    return int(found.group(1))


def main() -> None:
    header = HEADER.read_text(encoding="utf-8")
    flash = FLASH.read_text(encoding="utf-8")
    model = MODEL.read_text(encoding="utf-8")
    tests = TESTS.read_text(encoding="utf-8")
    sdkconfig = SDKCONFIG.read_text(encoding="utf-8")
    docs = DOCS.read_text(encoding="utf-8")
    partition = PARTITIONS.read_text(encoding="utf-8")

    required_calls = (
        "wl_mount(",
        "wl_read(",
        "wl_write(",
        "wl_erase_range(",
        "wl_unmount(",
    )
    missing = [call for call in required_calls if call not in flash]
    if missing:
        raise SystemExit(f"esp_storage_wear_gate FAIL: missing target WL calls {missing}")
    if "esp_partition_write(" in flash or "esp_partition_erase_range(" in flash:
        raise SystemExit("esp_storage_wear_gate FAIL: raw write/erase is a second authority")
    for needle in (
        "logical_size = wl_size(wl)",
        "sector_size = wl_sector_size(wl)",
        "admitted_config.wl_usable_sector_count",
    ):
        if needle not in flash:
            raise SystemExit(f"esp_storage_wear_gate FAIL: target admission missing {needle}")
    if "CONFIG_WL_SECTOR_SIZE_4096=y" not in sdkconfig:
        raise SystemExit("esp_storage_wear_gate FAIL: target WL sector must be 4096")
    if macro(header, "NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION") != 4:
        raise SystemExit("esp_storage_wear_gate FAIL: persistent format must remain 4")

    row = next((line for line in partition.splitlines() if line.startswith("ninlil_st,")), "")
    if "0x400000" not in row:
        raise SystemExit("esp_storage_wear_gate FAIL: reference WL partition must be 4 MiB")

    physical = macro(header, "NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT")
    erase_align = macro(header, "NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN")
    if physical != (0x400000 // erase_align):
        raise SystemExit("esp_storage_wear_gate FAIL: host physical sector mirror drift")

    # Conservative usable-sector reserve for WL metadata/rotation: 20%.
    usable = physical * 80 // 100
    slot_raw = 320 + 69632 + 32 * 6
    slot_sectors = (slot_raw + erase_align - 1) // erase_align
    endurance = 10_000
    setup_sector_reserve = 2 * (2 * slot_sectors + 2)
    conservative_commits = (usable * endurance - setup_sector_reserve) // slot_sectors
    if slot_sectors != 18 or conservative_commits != 454_995:
        raise SystemExit(
            "esp_storage_wear_gate FAIL: conservative budget regression "
            f"slot_sectors={slot_sectors} commits={conservative_commits}"
        )
    for needle in (
        "planned_full_commits_per_day",
        "planned_service_days",
        "planned <= budget",
    ):
        if needle not in model:
            raise SystemExit(f"esp_storage_wear_gate FAIL: model admission missing {needle}")
    for needle in ("113329u", "227218u", "454995u"):
        if needle not in tests:
            raise SystemExit(f"esp_storage_wear_gate FAIL: 1/2/4 MiB test missing {needle}")
    # Public header contract: domain-total FULL commits, not per-instance.
    header_contract_needles = (
        "physical WL partition",
        "wear-budget domain",
        "all storage instances and namespaces",
        "Do not double-count the same traffic",
        "Separate physical partitions",
    )
    for needle in header_contract_needles:
        if needle not in header:
            raise SystemExit(
                f"esp_storage_wear_gate FAIL: public header wear contract missing {needle!r}"
            )
    for needle in (
        "4096-byte",
        "wear_levelling",
        "454995",
        "COMMIT_UNKNOWN",
        "HIL",
        "wear-budget domain",
        "FULL commit 合計",
        "二重加算",
        "別 physical partition",
    ):
        if needle not in docs:
            raise SystemExit(f"esp_storage_wear_gate FAIL: docs missing {needle}")

    print(
        "esp_storage_wear_gate OK (estimate under declared assumptions): "
        f"physical={physical} usable_conservative={usable} "
        f"slot_sectors={slot_sectors} estimated_commits_at_10k={conservative_commits}"
    )


if __name__ == "__main__":
    main()
