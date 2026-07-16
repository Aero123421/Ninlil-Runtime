#!/usr/bin/env python3
"""Map-file / placement gate for ESP durable storage workspace.

Modes:
1) No map (host): smoke/sdkconfig static checks + partition path resolve.
2) With map file (target CI): parse linker map and fail if:
   - large storage symbols land in internal DRAM/BSS (.dram0.bss etc.)
   - internal .dram0.bss grows past the explicit 64 KiB firmware budget
   - required section/symbol parse count is 0

Self-test: `python3 tools/esp_storage_map_gate.py self-test`
  - official smoke/HIL maps positive (when present under ports/esp-idf/*/build)
  - synthetic missing/overbudget/malformed/0-match negative cases

Does not claim HIL. Pointer external-RAM checks remain in the port runtime.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
SMOKE_MAIN = REPO / "ports/esp-idf/smoke_app/main/main.c"
FLASH_BINDER = REPO / "ports/esp-idf/storage/esp/esp_storage_flash_media.c"
SMOKE_SDK = REPO / "ports/esp-idf/smoke_app/sdkconfig.defaults"
SMOKE_DIR = REPO / "ports/esp-idf/smoke_app"
PARTITIONS = REPO / "ports/esp-idf/partitions/ninlil_storage.csv"
HEADER = REPO / "ports/esp-idf/storage/include/ninlil_port/esp_storage.h"
OFFICIAL_MAP_CANDIDATES = (
    REPO / "ports/esp-idf/smoke_app/build/ninlil_m3_combined_smoke.map",
    REPO / "ports/esp-idf/hil_app/build/ninlil_storage_powercut_hil.map",
)

# Internal DRAM BSS must not hold the multi-100KB storage object.
# Default task+heap leave little headroom; 64 KiB is a fail-closed ceiling for
# accidental internal placement of the port object.
INTERNAL_BSS_BYTES_CEILING = 64 * 1024

# Only flag storage-related symbols whose map size is large enough to be a
# workspace (not a 4-byte pointer such as `.bss.g_storage`).
LARGE_SYM_BYTES = 4096

INTERNAL_SEC_RE = re.compile(
    r"\.(?:dram0\.bss|dram0\.data|bss|data|noinit)\b", re.IGNORECASE
)
EXTERNAL_SEC_RE = re.compile(
    r"(?:ext_ram|spiram|extram|\.ext_ram\.|rtc_slow)", re.IGNORECASE
)
STORAGE_SYM_RE = re.compile(
    r"(ninlil_port_esp_storage|g_storage|work_view_|pack_scratch)",
    re.IGNORECASE,
)
# GNU ld map memory config lines, e.g. "dram0_0_seg ... 0x00050000"
MEM_CFG_RE = re.compile(
    r"(?P<name>dram0_0_seg|dram0_bss|DRAM|dram0\.bss)\s+\S+\s+\S+\s+(?P<size>0x[0-9A-Fa-f]+)",
    re.IGNORECASE,
)
# Section size summaries: single-line or multiline output from GNU ld maps.
# Examples:
#   .dram0.bss      0x3fc95390      0xa10
#   .dram0.bss
#                   0x3fc95390      0xa10
SEC_SIZE_RE = re.compile(
    r"(?m)^\s*\.dram0\.bss(?:\s*\n\s*|\s+)"
    r"0x[0-9A-Fa-f]+\s+(0x[0-9A-Fa-f]+)",
    re.IGNORECASE,
)
# Per-symbol map lines with size in the second hex column when present.
SYM_SIZE_RE = re.compile(
    r"0x[0-9A-Fa-f]+\s+(0x[0-9A-Fa-f]+)\b",
    re.IGNORECASE,
)


class MapGateError(Exception):
    pass


def fail(msg: str) -> None:
    print(f"esp_storage_map_gate FAIL: {msg}", file=sys.stderr)
    raise MapGateError(msg)


def object_ceiling() -> int:
    text = HEADER.read_text(encoding="utf-8")
    m = re.search(
        r"#define\s+NINLIL_PORT_ESP_STORAGE_OBJECT_SIZEOF_CEILING\s+"
        r"\(\(size_t\)(\d+)u\)",
        text,
    )
    if not m:
        fail("missing storage object sizeof ceiling")
    return int(m.group(1))


def check_smoke_source() -> None:
    text = SMOKE_MAIN.read_text(encoding="utf-8")
    if re.search(
        r"static\s+ninlil_port_esp_storage_t\s+\w+",
        text,
    ):
        fail(
            "smoke must not place ninlil_port_esp_storage_t in static internal BSS"
        )
    if "ninlil_port_esp_storage_flash_bind" not in text:
        fail("smoke must construct storage through the opaque flash binder")
    if "sizeof(*storage)" in text or "sizeof(ninlil_port_esp_storage_t)" in text:
        fail("smoke must not know the concrete storage workspace size")
    binder = FLASH_BINDER.read_text(encoding="utf-8")
    if "heap_caps_calloc" not in binder or "MALLOC_CAP_SPIRAM" not in binder:
        fail("opaque flash binder must allocate its workspace from PSRAM")


def check_sdkconfig() -> None:
    text = SMOKE_SDK.read_text(encoding="utf-8")
    for item in (
        "CONFIG_SPIRAM=y",
        "CONFIG_SPIRAM_USE_CAPS_ALLOC=y",
        "CONFIG_PARTITION_TABLE_CUSTOM=y",
    ):
        if item not in text:
            fail(f"sdkconfig.defaults missing {item}")
    m = re.search(
        r'CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="([^"]+)"', text
    )
    if not m:
        fail("sdkconfig.defaults missing CONFIG_PARTITION_TABLE_CUSTOM_FILENAME")
    rel = m.group(1)
    if rel.startswith("../../"):
        fail(f"partition path must be project-relative ../ not ../../ ({rel})")
    resolved = (SMOKE_DIR / rel).resolve()
    if not resolved.is_file():
        fail(f"partition CSV not found from smoke_app: {rel} -> {resolved}")
    if not PARTITIONS.is_file():
        fail(f"missing {PARTITIONS}")


def _symbol_size_from_context(text: str, match_start: int) -> int | None:
    """Best-effort size parse for a storage-related map match."""
    window = text[match_start : match_start + 240]
    for line in window.splitlines()[:4]:
        m = SYM_SIZE_RE.search(line)
        if m:
            return int(m.group(1), 16)
    return None


def check_map_file(map_path: pathlib.Path) -> None:
    text = map_path.read_text(encoding="utf-8", errors="replace")
    ceil = object_ceiling()
    saw_storage_symbol = 0
    large_internal = []

    for m in STORAGE_SYM_RE.finditer(text):
        # Capture a small line window for section classification.
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        if line_end < 0:
            line_end = len(text)
        # Include previous line (section name often alone) and next lines.
        prev_start = text.rfind("\n", 0, max(0, line_start - 1)) + 1
        next_end = text.find("\n", line_end + 1)
        if next_end < 0:
            next_end = len(text)
        window = text[prev_start:next_end]
        saw_storage_symbol += 1
        size = _symbol_size_from_context(text, m.start())
        # Only fail when size is known and large. Unknown-size code symbols
        # (e.g. .text.ninlil_port_esp_storage_flash_bind) and small pointers
        # (.bss.g_storage size 4) are not placement violations.
        if (
            size is not None
            and size >= LARGE_SYM_BYTES
            and INTERNAL_SEC_RE.search(window)
            and not EXTERNAL_SEC_RE.search(window)
        ):
            large_internal.append(window.strip().replace("\n", " ")[:200])
    if saw_storage_symbol == 0:
        fail(
            "map has no durable-storage symbol evidence; pass the application "
            "map, not a bootloader or unrelated map"
        )
    if large_internal:
        fail(
            "map places large storage-related symbol in internal DRAM/BSS: "
            + large_internal[0]
        )

    # Parse .dram0.bss occupied size; required parse count must be > 0.
    dram_matches = list(SEC_SIZE_RE.finditer(text))
    if len(dram_matches) == 0:
        fail(
            "map .dram0.bss section size parse count is 0; "
            "section regex failed on this map"
        )
    dram_bss = max(int(m.group(1), 16) for m in dram_matches)
    if dram_bss >= ceil:
        fail(
            f"map .dram0.bss size {dram_bss} >= object ceiling {ceil}; "
            "storage object must not live in internal DRAM"
        )
    if dram_bss > INTERNAL_BSS_BYTES_CEILING:
        fail(
            f"map .dram0.bss size {dram_bss} exceeds hard internal budget "
            f"{INTERNAL_BSS_BYTES_CEILING}"
        )

    print(
        f"esp_storage_map_gate OK: map={map_path.name} "
        f"dram0_bss_parse={dram_bss} section_matches={len(dram_matches)} "
        f"storage_sym={saw_storage_symbol} object_ceil={ceil}"
    )


def check_host_only() -> None:
    check_smoke_source()
    check_sdkconfig()
    print(
        "esp_storage_map_gate OK: smoke/sdkconfig placement rules "
        "(provide map path or ESP_STORAGE_MAP_FILE for linker map parse)"
    )


def _write_temp_map(content: str) -> pathlib.Path:
    fd, name = tempfile.mkstemp(prefix="esp-map-gate-", suffix=".map")
    os.close(fd)
    path = pathlib.Path(name)
    path.write_text(content, encoding="utf-8")
    return path


def self_test() -> None:
    check_smoke_source()
    check_sdkconfig()

    # Positive: official target maps when present (from local ESP-IDF builds).
    official_ok = 0
    for candidate in OFFICIAL_MAP_CANDIDATES:
        if candidate.is_file():
            check_map_file(candidate)
            official_ok += 1
    if official_ok == 0:
        # Synthetic positive when no local map artifacts exist.
        positive = _write_temp_map(
            """
Memory Configuration
dram0_0_seg      0x3fc88000         0x00053700         rw

.dram0.bss      0x3fc95d80      0x9b8
                0x3fc95d80                        _bss_start = ABSOLUTE (.)
 .text.ninlil_port_esp_storage_flash_bind
                0x4200aa4c                ninlil_port_esp_storage_flash_bind
.ext_ram.bss    0x3c180000      0x100
"""
        )
        try:
            check_map_file(positive)
        finally:
            positive.unlink(missing_ok=True)

    def expect_fail(content: str, needle: str) -> None:
        path = _write_temp_map(content)
        try:
            try:
                check_map_file(path)
            except MapGateError as exc:
                if needle not in str(exc):
                    raise SystemExit(
                        f"self-test expected {needle!r} in {exc}"
                    ) from exc
                return
            raise SystemExit(f"self-test expected failure containing {needle!r}")
        finally:
            path.unlink(missing_ok=True)

    # Negative: missing storage symbol evidence (0-match symbols).
    expect_fail(
        """
.dram0.bss      0x3fc95d80      0x9b8
 .text.unrelated
                0x42000000                unrelated
""",
        "no durable-storage symbol",
    )

    # Negative: section parse count 0 (malformed / missing .dram0.bss size).
    expect_fail(
        """
.dram0.bss
 ninlil_port_esp_storage_flash_bind
                0x4200aa4c                ninlil_port_esp_storage_flash_bind
""",
        "section size parse count is 0",
    )

    # Negative: overbudget internal BSS.
    over = INTERNAL_BSS_BYTES_CEILING + 1
    expect_fail(
        f"""
.dram0.bss      0x3fc95d80      0x{over:x}
 .text.ninlil_port_esp_storage_flash_bind
                0x4200aa4c                ninlil_port_esp_storage_flash_bind
""",
        "exceeds hard internal budget",
    )

    # Negative: large storage symbol in internal BSS.
    expect_fail(
        f"""
.dram0.bss      0x3fc95d80      0x100
 .bss.work_view_a
                0x3fc96000        0x{LARGE_SYM_BYTES:x} main.o
                0x3fc96000                work_view_a
""",
        "large storage-related symbol",
    )

    # Multiline section form still parses (positive synthetic).
    multi = _write_temp_map(
        """
.dram0.bss
                0x3fc95d80      0x200
 .text.ninlil_port_esp_storage_flash_bind
                0x4200aa4c                ninlil_port_esp_storage_flash_bind
"""
    )
    try:
        check_map_file(multi)
    finally:
        multi.unlink(missing_ok=True)

    print("esp_storage_map_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "self-test":
        try:
            self_test()
        except MapGateError:
            return 1
        return 0

    try:
        check_smoke_source()
        check_sdkconfig()
        map_arg = None
        if len(argv) > 1:
            map_arg = pathlib.Path(argv[1])
        elif os.environ.get("ESP_STORAGE_MAP_FILE"):
            map_arg = pathlib.Path(os.environ["ESP_STORAGE_MAP_FILE"])
        if map_arg is not None:
            if not map_arg.is_file():
                fail(f"map file not found: {map_arg}")
            check_map_file(map_arg)
        else:
            print(
                "esp_storage_map_gate OK: smoke/sdkconfig placement rules "
                "(provide map path or ESP_STORAGE_MAP_FILE for linker map parse)"
            )
    except MapGateError:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
