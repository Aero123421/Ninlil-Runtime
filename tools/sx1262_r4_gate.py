#!/usr/bin/env python3
"""R4 structural gate: SX1262 control-plane only; SetTx/RF path absent.

docs/28 + ADR-0008. Mutation self-test on temporary trees.
Does not claim R4 complete / RF / HIL / legal / R1/R2/R9 complete.
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import tempfile
from typing import Callable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

BACKEND_H = REPO_ROOT / "drivers" / "sx126x" / "ninlil_sx1262_backend.h"
BACKEND_C = REPO_ROOT / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
CMD_H = REPO_ROOT / "drivers" / "sx126x" / "ninlil_sx1262_cmd.h"
BUS_H = REPO_ROOT / "drivers" / "sx126x" / "ninlil_sx1262_bus.h"
ESP_BUS_C = REPO_ROOT / "ports" / "esp-idf" / "src" / "esp_idf_sx1262_bus.c"
ESP_BUS_H = (
    REPO_ROOT / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "sx1262_bus.h"
)
SPY_H = REPO_ROOT / "tests" / "support" / "sx1262_bus_spy.h"
SPY_C = REPO_ROOT / "tests" / "support" / "sx1262_bus_spy.c"
TEST_C = REPO_ROOT / "tests" / "radio" / "sx1262_r4_test.c"
AUTH = REPO_ROOT / "cmake" / "ninlil_sx1262_sources.cmake"
CMAKE_LISTS = REPO_ROOT / "CMakeLists.txt"
DOC28 = REPO_ROOT / "docs" / "28-r4-sx1262-control-plane-backend.md"
ADR8 = REPO_ROOT / "docs" / "adr" / "0008-r4-sx1262-control-plane-backend.md"
DOC_README = REPO_ROOT / "docs" / "README.md"
ADR_README = REPO_ROOT / "docs" / "adr" / "README.md"
PUBLIC_INCLUDE = REPO_ROOT / "include" / "ninlil"
COMPONENT_CMAKE = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
)

BANNED_INCLUDES_PORTABLE = (
    "esp_",
    "freertos/",
    "driver/spi",
    "driver/gpio",
    "RadioLib",
    "termios.h",
    "tinyusb",
)

# Any of these in production R4 paths → unconditional reject (no exceptions).
ALT_TX_SYMBOLS = (
    "ninlil_sx1262_tx(",
    "ninlil_sx1262_send(",
    "ninlil_sx1262_transmit(",
    "RadioLib",
    "sx126x_set_tx(",
    "sx126x_set_tx ",
)

REQUIRED_DOC_TOKENS = (
    "docs/28",
    "ADR-0008",
    "STBY_RC",
    "SetTx",
    "TX_DENIED",
    "DS.SX1261-2.W.APP",
    "Rev 2.2",
    "Required HIL",
    "Seeed",
    "allowlist",
    "CAL_ALL",
    "SetRegulatorMode",
    "GetDeviceErrors",
    "post_spi_busy_guard",
    "STATUS_INVALID",
    "XOSC_START",
    "IMG_CALIB_ERR",
    "§9.2.1",
    "15.625",
    "1000 µs",
    "9636dc4660ada4eeddf91eb7b3f7f241000bf202",
    "5cf9794ea62edd092025ea437353db820df6c796",
    "reserved0",
    "ANT_SW",
    "RFU",
    "TX_DONE",
    "Table 10-1",
    "rx[1]",
    "miso_rfu_byte",
    "TIMEOUT_HELD",
    "REBOOT_REQUIRED",
    "1..16",
    "trans_storage",
    "immutable",
    "test_null_args",
    "test_spi_pending_ownership_sm",
)

REQUIRED_HEADER_TOKENS = (
    "docs/28-r4-sx1262-control-plane-backend.md",
    "docs/adr/0008-r4-sx1262-control-plane-backend.md",
    "ninlil_sx1262_request_transmit",
    "NINLIL_SX1262_TX_DENIED",
    "NINLIL_SX1262_STATUS_INVALID",
    "Not R4 complete",
    "NINLIL_SX1262_PIN_UNSET",
    "ninlil_sx1262_validate_board_config",
    "regulator_mode",
    "post_spi_busy_guard_us",
    "tcxo_delay_rtc_steps",
    "vdd_op_mv",
    "busy_poll_interval_us",
    "ninlil_sx1262_calc_busy_max_polls",
    "ninlil_sx1262_busy_deadline_reached",
    "expected_cold_errors_seen",
    "reserved0",
)

REQUIRED_SOURCE_TOKENS = (
    "ninlil_sx1262_cmd_is_allowlisted",
    "ninlil_sx1262_cmd_is_rf_banned",
    "ninlil_sx1262_cmd_frame_valid",
    "NINLIL_SX1262_CMD_SET_TX",
    "NINLIL_SX1262_CMD_SET_REGULATOR_MODE",
    "NINLIL_SX1262_CMD_CALIBRATE",
    "NINLIL_SX1262_CAL_ALL",
    "STBY_RC",
    "request_transmit",
    "R4 control-plane: physical TX denied",
    "opcode/schema denied",
    "post_spi_busy_guard",
    "cmd_status 3/4/5",
    "ninlil_sx1262_calc_busy_max_polls",
    "ninlil_sx1262_busy_deadline_reached",
    "verify_prev_cmd_status",
    "cmd_status_accepted_mid",
    "NINLIL_SX1262_ERR_TCXO_COLD_EXPECTED",
    "NINLIL_SX1262_RESET_PULSE_US_R4",
    "ANT_SW safe level",
    "reserved0 nonzero",
    "local_rx[1]",
    "Table 10-1",
    "interval_us > timeout_us",
    "after BUSY",
)

INCLUDE_LINE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]')


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def strip_c_comments_and_strings(text: str) -> str:
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        if text[i : i + 2] == "//":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text[i : i + 2] == "/*":
            i += 2
            while i + 1 < n and text[i : i + 2] != "*/":
                i += 1
            i = min(i + 2, n)
            continue
        if text[i] == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('""')
            continue
        if text[i] == "'":
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == "'":
                    i += 1
                    break
                i += 1
            out.append("''")
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def check_includes_portable(path: pathlib.Path) -> None:
    text = read_text(path)
    for line in text.splitlines():
        m = INCLUDE_LINE.match(line)
        if not m:
            continue
        inc = m.group(1)
        for banned in BANNED_INCLUDES_PORTABLE:
            if banned in inc:
                fail(f"{path}: banned include {inc}")


def check_no_heap(path: pathlib.Path) -> None:
    code = strip_c_comments_and_strings(read_text(path))
    for token in ("malloc(", "calloc(", "realloc(", "alloca("):
        if token in code:
            fail(f"{path}: heap token {token}")
    # Standalone free( only — not spi_bus_free / freeRTOS names.
    if re.search(r"(?<![A-Za-z0-9_])free\s*\(", code):
        fail(f"{path}: heap token free(")


def check_settx_not_sent(path: pathlib.Path) -> None:
    """Banlist constant 0x83 may exist only as named ban pin / _Static_assert."""
    raw = read_text(path)
    code = strip_c_comments_and_strings(raw)
    if re.search(
        r"tx\s*\[\s*0\s*\]\s*=\s*NINLIL_SX1262_CMD_SET_TX",
        code,
    ):
        fail(f"{path}: assigns SET_TX into SPI buffer")
    if re.search(r"\{\s*NINLIL_SX1262_CMD_SET_TX\b", code):
        fail(f"{path}: SPI buffer init with SET_TX")
    # Literal 0x83 outside ban-pin static assert / CMD_SET_TX define is forbidden.
    for m in re.finditer(r"0x83\b", code):
        window = code[max(0, m.start() - 80) : m.end() + 40]
        if "CMD_SET_TX" not in window and "SetTx ban" not in window:
            fail(f"{path}: bare 0x83 literal outside ban pin")
    # Unconditional reject of all alternate TX symbols (no path exceptions).
    for alt in ALT_TX_SYMBOLS:
        if alt in code:
            fail(f"{path}: alternate TX symbol {alt}")
    # Only allowlisted production .c under drivers/sx126x
    if path.name.endswith(".c") and "drivers/sx126x" in str(path):
        allowed = {"ninlil_sx1262_backend.c"}
        if path.name not in allowed:
            fail(f"unexpected production TU {path.name}")


def parse_cmake_source_list(auth_text: str, var_name: str) -> list[str]:
    """Extract relative paths from set(VAR ... )."""
    m = re.search(
        rf"set\s*\(\s*{re.escape(var_name)}\s*(.*?)\n\s*\)",
        auth_text,
        re.S,
    )
    if not m:
        return []
    body = m.group(1)
    out: list[str] = []
    for line in body.splitlines():
        code = line.split("#", 1)[0].strip()
        if code.endswith(".c") or code.endswith(".h"):
            out.append(code)
    return out


def check_esp_sx1262_authority_tus(base: pathlib.Path) -> None:
    """
    R4 ESP production TUs closed by cmake authority allowlist (not fixed 2-file).
    Unexpected *sx1262* .c under ports/esp-idf/src is fail.
    """
    auth = read_text(base / "cmake" / "ninlil_sx1262_sources.cmake")
    allowed = set(parse_cmake_source_list(auth, "NINLIL_SX1262_ESP_BUS_RELATIVE_SOURCES"))
    if not allowed:
        fail("NINLIL_SX1262_ESP_BUS_RELATIVE_SOURCES empty/missing")
    if "ports/esp-idf/src/esp_idf_sx1262_bus.c" not in allowed:
        fail("ESP bus adapter missing from ESP_BUS authority")
    port_src = base / "ports" / "esp-idf" / "src"
    if not port_src.is_dir():
        fail("ports/esp-idf/src missing")
    for p in sorted(port_src.glob("*.c")):
        rel = str(p.relative_to(base)).replace("\\", "/")
        if "sx1262" in p.name.lower():
            if rel not in allowed:
                fail(f"unexpected sx1262 production TU not in authority: {rel}")
        # RF alt symbols banned in any authority-listed file
        if rel in allowed:
            check_settx_not_sent(p)
            check_no_heap(p)


def check_public_abi() -> None:
    for p in PUBLIC_INCLUDE.glob("*.h"):
        text = read_text(p)
        for needle in ("sx1262", "SX1262", "ninlil_sx1262", "RadioLib"):
            if needle in text:
                fail(f"public header leaks R4 token {needle}: {p}")


def check_authority() -> None:
    text = read_text(AUTH)
    if "drivers/sx126x/ninlil_sx1262_backend.c" not in text:
        fail("sx1262 backend missing from ninlil_sx1262_sources.cmake")
    if "sx1262_bus_spy" in text or "tests/" in text:
        fail("spy/tests must not be in sx1262 production authority")
    # Production .c allowlist under drivers/sx126x in authority.
    for line in text.splitlines():
        code = line.split("#", 1)[0].strip()
        if "RadioLib" in code or "radiolib" in code.lower():
            fail("RadioLib in production authority sources")
        m = re.match(r"(drivers/sx126x/[A-Za-z0-9_./-]+\.c)$", code)
        if m and m.group(1) != "drivers/sx126x/ninlil_sx1262_backend.c":
            fail(f"unexpected sx126x production source {m.group(1)}")


def check_cmake() -> None:
    text = read_text(CMAKE_LISTS)
    for tok in (
        "ninlil_sx1262_sources.cmake",
        "sx1262_r4",
        "sx1262_r4_gate",
        "ninlil_sx1262",
    ):
        if tok not in text:
            fail(f"CMakeLists missing {tok}")


def check_docs() -> None:
    doc = read_text(DOC28)
    adr = read_text(ADR8)
    for tok in REQUIRED_DOC_TOKENS:
        if tok not in doc and tok not in adr:
            fail(f"docs missing token: {tok}")
    if "web 取得不可" in doc or "web取得不可" in doc:
        fail("docs must not claim datasheet unavailable")
    if "BLOCKER-DOC-DS" in doc:
        fail("BLOCKER-DOC-DS retired; DS is pinned")
    if "CHIP_MISMATCH" in doc and "改名" not in doc and "SKU" not in doc:
        fail("CHIP_MISMATCH SKU claim must be retired/renamed")
    if "# 28." not in doc and "# 28 " not in doc:
        fail("doc chapter number must be 28")
    if "ADR-0008" not in adr:
        fail("ADR must be 0008")
    # Old false framing: status on rx[0] (P1 regression).
    if "各 xfer の **rx[0]**" in doc and "RFU" not in doc.split("各 xfer の **rx[0]**", 1)[-1][:80]:
        fail("docs/28 must not treat rx[0] as status without RFU correction")
    if re.search(r"rx\[0\].*直前 command の status", doc):
        fail("docs/28 must not claim rx[0] is previous-command status")
    if "byte0 = RFU" not in doc and "rx[0]=RFU" not in doc:
        fail("docs/28 must pin DS Table 10-1 byte0=RFU")
    readme = read_text(DOC_README)
    if "28-r4-sx1262-control-plane-backend.md" not in readme:
        fail("docs/README must list chapter 28")
    adr_idx = read_text(ADR_README)
    if "0008-r4-sx1262" not in adr_idx:
        fail("adr/README must list ADR-0008")


def check_component() -> None:
    text = read_text(COMPONENT_CMAKE)
    if "ninlil_sx1262_sources.cmake" not in text:
        fail("ESP component CMake must include sx1262 source authority")


def check_header() -> None:
    text = read_text(BACKEND_H)
    for tok in REQUIRED_HEADER_TOKENS:
        if tok not in text:
            fail(f"backend.h missing {tok}")
    for alt in ("ninlil_sx1262_tx(", "ninlil_sx1262_send("):
        if alt in text:
            fail(f"backend.h must not declare {alt}")
    check_includes_portable(BACKEND_H)
    check_includes_portable(CMD_H)
    check_includes_portable(BUS_H)


def check_miso_status_rx1(path: pathlib.Path) -> None:
    """DS Table 10-1/13-85: status is rx[1]; decoding rx[0] is a P1 regression."""
    text = read_text(path)
    code = strip_c_comments_and_strings(text)
    if "local_rx[1]" not in text:
        fail(f"{path}: must inspect local_rx[1] for DS status byte")
    # status_cmd_status / chip_mode must not take local_rx[0]
    if re.search(
        r"ninlil_sx1262_status_(?:cmd_status|chip_mode)\s*\(\s*local_rx\s*\[\s*0\s*\]",
        code,
    ):
        fail(f"{path}: decodes status from local_rx[0] (must be local_rx[1])")
    if re.search(
        r"last_status_byte\s*=\s*local_rx\s*\[\s*0\s*\]",
        code,
    ):
        fail(f"{path}: last_status_byte assigned from local_rx[0]")
    # GetStatus path must keep decoding rx[1]
    if "rx[1]" not in text:
        fail(f"{path}: GetStatus/path must reference rx[1]")


def check_source() -> None:
    text = read_text(BACKEND_C)
    for tok in REQUIRED_SOURCE_TOKENS:
        if tok not in text:
            fail(f"backend.c missing {tok}")
    check_includes_portable(BACKEND_C)
    check_no_heap(BACKEND_C)
    check_settx_not_sent(BACKEND_C)
    check_miso_status_rx1(BACKEND_C)
    # Deadline predicate must use >= (exact elapsed==timeout is TIMEOUT, not OK).
    code_dl = strip_c_comments_and_strings(text)
    if not re.search(
        r"now_ms\s*-\s*start_ms\)\s*>=\s*\(uint64_t\)timeout_ms",
        code_dl,
    ):
        fail("busy_deadline_reached must use elapsed >= timeout_ms")
    code = strip_c_comments_and_strings(text)
    # Must reference ban constant for structural presence of deny list.
    if "NINLIL_SX1262_CMD_SET_TX" not in text:
        fail("backend must mention SET_TX ban constant")
    # Must not call spi with 0x83 literal as first byte assignment beyond comparisons.
    if re.search(r"=\s*0x83\s*;", code):
        # allow only in comments already stripped; assignment of ban const is via macro name
        pass


def check_esp_bus() -> None:
    text = read_text(ESP_BUS_C)
    code = strip_c_comments_and_strings(text)
    hdr = read_text(ESP_BUS_H)
    if "ninlil_sx1262_cmd_is_rf_banned" not in text:
        fail("ESP bus must refuse RF-banned opcodes")
    if "spi_device_polling_transmit" in code:
        fail("ESP bus must not use spi_device_polling_transmit (portMAX_DELAY)")
    if "spi_device_queue_trans" not in code or "spi_device_get_trans_result" not in code:
        fail("ESP bus must use queue_trans + get_trans_result")
    if "spi_timeout_ms" not in text:
        fail("ESP bus config must include spi_timeout_ms")
    if "GPIO_IS_VALID_OUTPUT_GPIO" not in code or "GPIO_IS_VALID_GPIO" not in code:
        fail("ESP bus must validate pins with GPIO_IS_VALID_*")
    if "poisoned" not in text:
        fail("ESP bus must poison on SPI timeout")
    # P1-3: pending ownership — never clear pending_trans on get_result timeout.
    if "ninlil_sx1262_spi_own_on_result_timeout" not in text:
        fail("ESP bus must use pure pending SM on result timeout")
    if "ninlil_esp_idf_sx1262_bus_drain" not in text:
        fail("ESP bus must implement drain after timeout")
    if "NINLIL_ESP_IDF_SX1262_BUS_SHUTDOWN_REBOOT_REQUIRED" not in hdr:
        fail("ESP bus header must define REBOOT_REQUIRED shutdown status")
    if "immutable" not in hdr and "MUST NOT free" not in hdr:
        if "reboot completes" not in hdr.lower() and "device reboot" not in hdr:
            fail("ESP bus header must document REBOOT_REQUIRED object lifetime MUST")
    if "1..16" not in hdr:
        fail("ESP bus header must document spi_drain_max_attempts 1..16")
    if "normalize_max_drain" not in text:
        fail("ESP bus init must validate spi_drain_max_attempts via normalize")
    if "device reboot" not in hdr and "reboot completes" not in hdr:
        fail("ESP bus header must document REBOOT_REQUIRED object lifetime")
    if "spi_bus_remove_device" not in text:
        fail("ESP bus must call remove_device")
    # Detect regression: assign pending_trans = NULL immediately before timeout poison path
    # without drain (heuristic: on_result_timeout must appear before any free of pending).
    if "ninlil_sx1262_spi_own_on_result_timeout" in text:
        # After timeout handler, pending_trans must not be nulled in same block.
        # Fail if pattern: on_result_timeout ... pending_trans = NULL without drain_ok.
        pass
    if re.search(
        r"spi_own_on_result_timeout[\s\S]{0,200}pending_trans\s*=\s*NULL",
        code,
    ):
        fail("ESP bus must not null pending_trans on result timeout")
    if "NINLIL_ESP_IDF_SX1262_BUS_OBJECT_INIT" not in hdr:
        fail("ESP bus header must define OBJECT_INIT")
    if "NINLIL_ESP_IDF_SX1262_BUS_MAGIC" not in hdr:
        fail("ESP bus header must define MAGIC for lifecycle trust")
    # P1-2: aligned transaction storage without ESP type leak in portable header.
    hdr_code = strip_c_comments_and_strings(hdr)
    if not re.search(
        r"_Alignas\s*\(\s*max_align_t\s*\)\s*uint8_t\s+trans_storage\b"
        r"|_Alignas\s*\(\s*max_align_t\s*\)\s*uint8_t\s*\n\s*trans_storage\b",
        hdr_code,
    ):
        fail("ESP bus header must declare _Alignas(max_align_t) trans_storage")
    if "trans_storage" not in hdr:
        fail("ESP bus header must declare trans_storage")
    if "spi_transaction_t" in hdr_code:
        fail("portable ESP bus header must not leak spi_transaction_t")
    if "driver/spi" in hdr:
        fail("portable ESP bus header must not include driver/spi")
    if "_Alignof(spi_transaction_t)" not in text:
        fail("ESP bus .c must static-assert spi_transaction_t alignment")
    if "NINLIL_ESP_IDF_SX1262_TRANS_STORAGE_BYTES" not in hdr:
        fail("ESP bus header must define TRANS_STORAGE_BYTES")
    if "offsetof(ninlil_esp_idf_sx1262_bus_t, trans_storage)" not in hdr:
        fail("ESP bus header must static-assert trans_storage offsetof alignment")
    if "us_to_ticks_ceil" not in text and "us_to_ticks_ceil" not in read_text(
        REPO_ROOT / "ports" / "esp-idf" / "src" / "sx1262_spi_timeout_logic.c"
    ):
        fail("ESP delay path must use us_to_ticks_ceil")
    if "DELAY_US_BUSY_WAIT_MAX" not in text and "esp_rom_delay_us" not in code:
        fail("ESP short delay must busy-wait (NRESET)")
    if "drive_safe_output_levels" not in text:
        fail("ESP bus must drive safe RESET/ANT levels after output config")
    if "ant_sw_active_high" not in hdr:
        fail("ESP bus config must expose ant_sw_active_high polarity")
    if "sx126x_set_tx" in text or "RadioLib" in text:
        fail("ESP bus must not call TX helpers")
    check_no_heap(ESP_BUS_C)
    # base for authority TU scan is parent of ports/esp-idf/...
    check_esp_sx1262_authority_tus(ESP_BUS_C.parents[3])

    # Production source allowlist for R4 D1 / ESP bus TUs only.
    auth = read_text(AUTH)
    for banned in ("RadioLib", "sx126x_set_tx", "tests/support"):
        if banned in auth.split("#")[0] if False else auth:
            if banned in [
                ln.split("#", 1)[0]
                for ln in auth.splitlines()
                if banned in ln.split("#", 1)[0]
            ]:
                fail(f"authority lists banned path {banned}")


def check_spy_not_in_production() -> None:
    for p in (BACKEND_C, BACKEND_H, ESP_BUS_C, AUTH):
        text = read_text(p)
        if "sx1262_bus_spy" in text or "NINLIL_SX1262_SPY" in text:
            fail(f"production file must not reference spy: {p}")


# Semtech DS primary opcodes (allowlist 8 + SetTx ban + params).
# Gate pins these as independent hex in both production cmd.h and test golden.
GOLDEN_OPCODE_PINS: tuple[tuple[str, str], ...] = (
    ("SX126X_GOLDEN_GET_STATUS", "0xC0"),
    ("SX126X_GOLDEN_SET_STANDBY", "0x80"),
    ("SX126X_GOLDEN_GET_DEVICE_ERRORS", "0x17"),
    ("SX126X_GOLDEN_CLR_DEVICE_ERRORS", "0x07"),
    ("SX126X_GOLDEN_SET_REGULATOR_MODE", "0x96"),
    ("SX126X_GOLDEN_CALIBRATE", "0x89"),
    ("SX126X_GOLDEN_SET_DIO2_RF_SWITCH", "0x9D"),
    ("SX126X_GOLDEN_SET_DIO3_TCXO", "0x97"),
    ("SX126X_GOLDEN_SET_TX_BAN", "0x83"),
    ("SX126X_GOLDEN_CAL_ALL", "0x7F"),
    ("SX126X_GOLDEN_TCXO_1_8V", "0x02"),
)

PROD_OPCODE_PINS: tuple[tuple[str, str], ...] = (
    ("NINLIL_SX1262_CMD_GET_STATUS", "0xC0"),
    ("NINLIL_SX1262_CMD_SET_STANDBY", "0x80"),
    ("NINLIL_SX1262_CMD_GET_DEVICE_ERRORS", "0x17"),
    ("NINLIL_SX1262_CMD_CLR_DEVICE_ERRORS", "0x07"),
    ("NINLIL_SX1262_CMD_SET_REGULATOR_MODE", "0x96"),
    ("NINLIL_SX1262_CMD_CALIBRATE", "0x89"),
    ("NINLIL_SX1262_CMD_SET_DIO2_AS_RF_SWITCH_CTRL", "0x9D"),
    ("NINLIL_SX1262_CMD_SET_DIO3_AS_TCXO_CTRL", "0x97"),
    ("NINLIL_SX1262_CMD_SET_TX", "0x83"),
    ("NINLIL_SX1262_CAL_ALL", "0x7F"),
)


def _macro_hex_value(text: str, name: str) -> str | None:
    """Return hex digits (e.g. 'C0') for `#define NAME ... 0xNNu` / enum assign."""
    # enum: NAME = 0xC0u
    m = re.search(
        rf"\b{re.escape(name)}\s*=\s*0x([0-9A-Fa-f]+)u?\b",
        text,
    )
    if m:
        return m.group(1).upper()
    # #define NAME ((uint8_t)0xC0u) or #define NAME 0xC0u
    m = re.search(
        rf"#\s*define\s+{re.escape(name)}\s+.*?\b0x([0-9A-Fa-f]+)u?\b",
        text,
    )
    if m:
        return m.group(1).upper()
    return None


def check_independent_opcode_golden(test_text: str) -> None:
    """docs/28 §12.2: expected opcodes are test-side hex pins, not production macros."""
    for name, hexv in GOLDEN_OPCODE_PINS:
        got = _macro_hex_value(test_text, name)
        if got is None:
            fail(f"test missing independent golden pin {name}")
        expect = hexv.replace("0x", "").replace("0X", "").upper()
        if got != expect:
            fail(f"golden {name} must be {hexv}, got 0x{got}")

    # Sequence vectors must not use production CMD macros as element builders.
    # Extract k_xtal_ok / k_tcxo bodies and ban NINLIL_SX1262_CMD_ inside them.
    for vec in ("k_xtal_ok", "k_tcxo_dio2_xosc"):
        m = re.search(
            rf"static\s+const\s+uint8_t\s+{vec}\s*\[\s*\]\s*=\s*\{{(.*?)\}};",
            test_text,
            re.S,
        )
        if not m:
            fail(f"test missing golden sequence vector {vec}")
        body = m.group(1)
        if "NINLIL_SX1262_CMD_" in body:
            fail(
                f"{vec} must not use production NINLIL_SX1262_CMD_* "
                "(independent golden false-green ban)"
            )
        if "SX126X_GOLDEN_" not in body and "0x" not in body:
            fail(f"{vec} must be built from SX126X_GOLDEN_* or hex literals")

    # test_cmd_frame_schema must build frames from golden, not production macros.
    schema_m = re.search(
        r"static\s+int\s+test_cmd_frame_schema\s*\(\s*void\s*\)\s*\{(.*?)\n\}",
        test_text,
        re.S,
    )
    if not schema_m:
        fail("test_cmd_frame_schema missing")
    schema_body = schema_m.group(1)
    if "NINLIL_SX1262_CMD_" in schema_body:
        fail(
            "test_cmd_frame_schema must not use production NINLIL_SX1262_CMD_* "
            "for frame bytes"
        )
    if "SX126X_GOLDEN_" not in schema_body:
        fail("test_cmd_frame_schema must use SX126X_GOLDEN_* for frame bytes")

    # Production cmd.h independently pinned to same Semtech hex.
    cmd = read_text(CMD_H)
    for name, hexv in PROD_OPCODE_PINS:
        got = _macro_hex_value(cmd, name)
        expect = hexv.replace("0x", "").replace("0X", "").upper()
        if got is None:
            fail(f"cmd.h missing production pin {name}")
        if got != expect:
            fail(f"cmd.h {name} must be {hexv}, got 0x{got}")


def check_test_present() -> None:
    text = read_text(TEST_C)
    for tok in (
        "k_xtal_ok",
        "test_error_before_clear",
        "test_cmd_status_fail_first",
        "test_cmd_status_fail_after_write",
        "test_frozen_clock_poll_cap",
        "test_clock_wrap",
        "test_delayed_busy",
        "test_calc_polls_overflow",
        "test_esp_ticks_overflow",
        "test_rfu_and_tx_done_reject",
        "test_miso_status_byte_position",
        "test_esp_bus_trans_storage_align",
        "test_tcxo_cold_img_only",
        "test_tcxo_cold_both",
        "test_tcxo_cold_mixed_negative",
        "test_ant_sw_contracts",
        # docs/28 §12.1 T02–T15
        "test_null_args",
        "test_each_required_pin_unset",
        "test_pin_duplicate",
        "test_feature_mismatches",
        "test_bus_faults_matrix",
        "test_timeout_boundary_exact",
        "test_initing_reentry",
        "test_failed_shutdown_reinit",
        "test_tx_deny_all_lifecycles",
        "test_object_size_align",
        "test_spi_pending_ownership_sm",
        "NINLIL_SX1262_SPI_PEND_TIMEOUT_HELD",
        "NINLIL_SX1262_SPI_OWN_LIFE_REBOOT_REQUIRED",
        "ninlil_sx1262_spi_own_normalize_max_drain",
        "ninlil_sx1262_spi_own_max_drain_wait_ms",
        "ninlil_sx1262_spi_own_may_release_object_storage",
        "us_to_ticks_ceil",
        "tcxo_delay_rtc_steps = 0u",
        "NINLIL_SX1262_CMD_CALIBRATE",
        "NINLIL_SX1262_ERR_TCXO_COLD_EXPECTED",
        "reset_pulse_us = 100u",
        "reserved0 = 1u",
        "busy_poll_interval_us = 1000000u",
        "miso_rfu_byte",
        "fail_status_after_n_spi",
        "reenter_tx_on_delay",
        "test_mid_status_closed_set_after_busy",
        "test_fail_busy_read_positions",
        "test_delay_fail_positions",
        "test_now_fail_positions",
        "test_monotonic_deadline_boundary",
        "test_busy_deadline_helper",
        "ninlil_sx1262_busy_deadline_reached",
        "hold_delay_clock_until_busy",
        "elapsed == (uint64_t)timeout",
        "elapsed > 5u",
        "ops.reset_assert = NULL",
        "ops.now_ms = NULL",
        "fail_busy_on_call_n",
        "fail_delay_us_eq",
        "fail_now_on_call_n",
        "busy_low_when_now_ge",
        "freeze_delay_clock",
        "nth_spi_index",
        "k_tcxo_dio2_xosc",
        "test_cmd_frame_schema",
        "test_primary_opcode_pin",
        "test_esp_gpio_safe_init_sm",
        "ninlil_sx1262_cmd_frame_valid",
        "SX126X_GOLDEN_GET_STATUS",
        "SX126X_GOLDEN_SET_STANDBY",
        "SX126X_GOLDEN_GET_DEVICE_ERRORS",
        "SX126X_GOLDEN_CLR_DEVICE_ERRORS",
        "SX126X_GOLDEN_SET_REGULATOR_MODE",
        "SX126X_GOLDEN_CALIBRATE",
        "SX126X_GOLDEN_SET_DIO2_RF_SWITCH",
        "SX126X_GOLDEN_SET_DIO3_TCXO",
        "SX126X_GOLDEN_SET_TX_BAN",
        "SX126X_GOLDEN_CAL_ALL",
        "Not R4 complete",
        "STATUS_INVALID",
        "last_ant_sw_active == 0",
    ):
        if tok not in text:
            fail(f"test missing {tok}")
    if "1001u" not in text:
        fail("test must use opaque board-local pin ids")
    # Ops NULL matrix must not use void** strict-aliasing cast.
    if "void **" in text or "(void **)&ops." in text:
        fail("ops NULL matrix must not cast function pointers via void**")
    # §12.2 independent golden: Semtech hex pin + no production macros in vectors
    check_independent_opcode_golden(text)
    # §12.1 traceability table in docs
    doc = read_text(DOC28)
    for tok in (
        "test_null_args",
        "test_each_required_pin_unset",
        "test_pin_duplicate",
        "test_feature_mismatches",
        "test_bus_faults_matrix",
        "test_initing_reentry",
        "test_failed_shutdown_reinit",
        "test_tx_deny_all_lifecycles",
        "test_object_size_align",
        "test_spi_pending_ownership_sm",
        "test_fail_busy_read_positions",
        "test_delay_fail_positions",
        "test_now_fail_positions",
        "test_monotonic_deadline_boundary",
        "test_mid_status_closed_set_after_busy",
        "test_primary_opcode_pin",
        "SX126X_GOLDEN_",
        "T01",
        "T07a",
        "T08d",
        "T16",
        "verify + final",
        "OBJECT_INIT sentinel",
    ):
        if tok not in doc:
            fail(f"docs/28 §12.1 missing tracking token {tok}")
    spy = read_text(SPY_C)
    if "miso_rfu_byte" not in spy:
        fail("spy must model independent MISO RFU byte")
    if re.search(r"rx\s*\[\s*0\s*\]\s*=\s*spy->status_byte", strip_c_comments_and_strings(spy)):
        fail("spy must not inject status_byte into rx[0]")
    cmd = read_text(CMD_H)
    for tok in (
        "NINLIL_SX1262_ERR_TCXO_COLD_EXPECTED",
        "NINLIL_SX1262_ERR_XOSC_START",
        "NINLIL_SX1262_ERR_IMG_CAL",
        "NINLIL_SX1262_RESET_PULSE_US_R4",
        "1000u",
        "§9.2.1",
    ):
        if tok not in cmd:
            fail(f"cmd.h missing {tok}")
    pend = REPO_ROOT / "ports" / "esp-idf" / "src" / "sx1262_spi_pending_logic.c"
    if "TIMEOUT_HELD" not in read_text(pend) and "SPI_PEND_TIMEOUT_HELD" not in read_text(
        pend
    ):
        # constant is in header; .c must call on_result_timeout path
        if "on_result_timeout" not in read_text(pend):
            fail("pending_logic.c missing result timeout path")
    if "sx1262_spi_pending_logic.c" not in read_text(AUTH):
        fail("authority must list sx1262_spi_pending_logic.c pure source")
    # AUTH is set to base/cmake/... for mutation trees.
    pend_base = AUTH.parents[1] / "ports" / "esp-idf" / "src"
    pend_c = read_text(pend_base / "sx1262_spi_pending_logic.c")
    pend_h = read_text(pend_base / "sx1262_spi_pending_logic.h")
    if "#include <stddef.h>" not in pend_c:
        fail("pending_logic.c must include stddef.h for NULL")
    if "#include <stddef.h>" not in pend_h:
        fail("pending_logic.h must include stddef.h (single-TU compile)")
    for tok in (
        "NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MAX",
        "NINLIL_SX1262_SPI_OWN_MAX_DRAIN_MIN",
        "ninlil_sx1262_spi_own_normalize_max_drain",
        "ninlil_sx1262_spi_own_max_drain_wait_ms",
        "ninlil_sx1262_spi_own_may_release_object_storage",
    ):
        if tok not in pend_h:
            fail(f"pending_logic.h missing {tok}")
    if "may_release_object_storage" not in read_text(TEST_C):
        fail("test must cover object-storage ban under REBOOT_REQUIRED")
    if "normalize_max_drain" not in read_text(TEST_C):
        fail("test must cover drain budget 0/1..16/17")


def check(root: pathlib.Path | None = None) -> None:
    global BACKEND_H, BACKEND_C, CMD_H, BUS_H, ESP_BUS_C, ESP_BUS_H
    global SPY_H, SPY_C, TEST_C, AUTH, CMAKE_LISTS, DOC28, ADR8
    global DOC_README, ADR_README, PUBLIC_INCLUDE, COMPONENT_CMAKE

    base = root if root is not None else REPO_ROOT
    BACKEND_H = base / "drivers" / "sx126x" / "ninlil_sx1262_backend.h"
    BACKEND_C = base / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
    CMD_H = base / "drivers" / "sx126x" / "ninlil_sx1262_cmd.h"
    BUS_H = base / "drivers" / "sx126x" / "ninlil_sx1262_bus.h"
    ESP_BUS_C = base / "ports" / "esp-idf" / "src" / "esp_idf_sx1262_bus.c"
    ESP_BUS_H = (
        base / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "sx1262_bus.h"
    )
    SPY_H = base / "tests" / "support" / "sx1262_bus_spy.h"
    SPY_C = base / "tests" / "support" / "sx1262_bus_spy.c"
    TEST_C = base / "tests" / "radio" / "sx1262_r4_test.c"
    AUTH = base / "cmake" / "ninlil_sx1262_sources.cmake"
    CMAKE_LISTS = base / "CMakeLists.txt"
    DOC28 = base / "docs" / "28-r4-sx1262-control-plane-backend.md"
    ADR8 = base / "docs" / "adr" / "0008-r4-sx1262-control-plane-backend.md"
    DOC_README = base / "docs" / "README.md"
    ADR_README = base / "docs" / "adr" / "README.md"
    PUBLIC_INCLUDE = base / "include" / "ninlil"
    COMPONENT_CMAKE = (
        base / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
    )

    check_docs()
    check_authority()
    check_cmake()
    check_component()
    check_header()
    check_source()
    check_esp_bus()
    check_public_abi()
    check_spy_not_in_production()
    check_test_present()
    # Backend must not decode status before post-BUSY (ordering heuristic).
    be = read_text(BACKEND_C)
    # After SPI success, post guard / wait_busy must appear before STATUS_INVALID
    # for mid-init rx[1] path.
    if "after BUSY" not in be and "after BUSY" not in be:
        if "post_spi_busy_guard" not in be:
            fail("backend missing post_spi_busy_guard")
    idx_guard = be.find("post_spi_busy_guard_us")
    idx_decode = be.find("rx[1] cmd_status not in mid-init accepted")
    if idx_guard < 0 or idx_decode < 0 or idx_decode < idx_guard:
        # soft: require busy wait call before mid-init accepted error string region
        if "mid-init accepted {0,2} after BUSY" not in be:
            fail("backend must decode mid-init status only after BUSY sync")
    # Single-TU C11 -Werror compile of pending_logic (stddef/NULL).
    import subprocess
    import tempfile as _tf

    pend_src = (
        base
        / "ports"
        / "esp-idf"
        / "src"
        / "sx1262_spi_pending_logic.c"
    )
    with _tf.TemporaryDirectory() as td:
        out_o = pathlib.Path(td) / "pending_strict.o"
        cmd = [
            "cc",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-c",
            str(pend_src),
            f"-I{pend_src.parent}",
            "-o",
            str(out_o),
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            detail = getattr(exc, "stderr", str(exc))
            fail(f"pending_logic single-TU strict compile failed: {detail}")
    print("sx1262_r4_gate: OK")


def _copy_tree(dst: pathlib.Path) -> None:
    paths = [
        "drivers/sx126x",
        "ports/esp-idf/src/esp_idf_sx1262_bus.c",
        "ports/esp-idf/src/sx1262_spi_timeout_logic.c",
        "ports/esp-idf/src/sx1262_spi_pending_logic.c",
        "ports/esp-idf/src/sx1262_spi_pending_logic.h",
        "ports/esp-idf/src/sx1262_esp_gpio_init_logic.c",
        "ports/esp-idf/src/sx1262_esp_gpio_init_logic.h",
        "ports/esp-idf/include/ninlil_esp_idf/sx1262_bus.h",
        "ports/esp-idf/components/ninlil/CMakeLists.txt",
        "cmake/ninlil_sx1262_sources.cmake",
        "CMakeLists.txt",
        "docs/28-r4-sx1262-control-plane-backend.md",
        "docs/adr/0008-r4-sx1262-control-plane-backend.md",
        "docs/README.md",
        "docs/adr/README.md",
        "tests/support/sx1262_bus_spy.h",
        "tests/support/sx1262_bus_spy.c",
        "tests/radio/sx1262_r4_test.c",
        "include/ninlil",
    ]
    for rel in paths:
        src = REPO_ROOT / rel
        target = dst / rel
        if src.is_dir():
            shutil.copytree(src, target)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)


def self_test() -> None:
    def mut_drop_allowlist(root: pathlib.Path) -> None:
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("ninlil_sx1262_cmd_is_allowlisted", "ninlil_sx1262_cmd_ALLOW_REMOVED"),
            encoding="utf-8",
        )

    def mut_inject_settx_send(root: pathlib.Path) -> None:
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        needle = "ninlil_sx1262_status_t ninlil_sx1262_request_transmit("
        inject = (
            "static void evil_settx(ninlil_sx1262_backend_t *be) {\n"
            "  uint8_t tx[1];\n"
            "  tx[0] = NINLIL_SX1262_CMD_SET_TX;\n"
            "  (void)be; (void)tx;\n"
            "}\n"
        )
        if needle not in text:
            raise RuntimeError("request_transmit missing")
        p.write_text(text.replace(needle, inject + needle, 1), encoding="utf-8")

    def mut_literal_settx(root: pathlib.Path) -> None:
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text + "\nstatic const uint8_t evil_op = 0x83;\n",
            encoding="utf-8",
        )

    def mut_extra_production_c(root: pathlib.Path) -> None:
        p = root / "drivers" / "sx126x" / "evil_tx.c"
        p.write_text("void ninlil_sx1262_raw_send(void) {}\n", encoding="utf-8")
        auth = root / "cmake" / "ninlil_sx1262_sources.cmake"
        t = auth.read_text(encoding="utf-8")
        auth.write_text(
            t + "\n    drivers/sx126x/evil_tx.c\n", encoding="utf-8"
        )

    def mut_polling_transmit(root: pathlib.Path) -> None:
        p = root / "ports" / "esp-idf" / "src" / "esp_idf_sx1262_bus.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace(
                "spi_device_queue_trans",
                "spi_device_polling_transmit",
                1,
            ),
            encoding="utf-8",
        )

    def mut_drop_cmake_gate(root: pathlib.Path) -> None:
        p = root / "CMakeLists.txt"
        text = p.read_text(encoding="utf-8")
        p.write_text(text.replace("sx1262_r4_gate", "sx1262_r4_GATE_REMOVED"), encoding="utf-8")

    def mut_spy_in_authority(root: pathlib.Path) -> None:
        p = root / "cmake" / "ninlil_sx1262_sources.cmake"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text + "\n    tests/support/sx1262_bus_spy.c\n",
            encoding="utf-8",
        )

    def mut_radiolib(root: pathlib.Path) -> None:
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        p.write_text('#include "RadioLib.h"\n' + text, encoding="utf-8")

    def mut_public_leak(root: pathlib.Path) -> None:
        p = root / "include" / "ninlil" / "version.h"
        text = p.read_text(encoding="utf-8")
        p.write_text(text + "\n/* sx1262 leak */\n", encoding="utf-8")

    def mut_drop_doc28(root: pathlib.Path) -> None:
        p = root / "docs" / "README.md"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("28-r4-sx1262-control-plane-backend.md", "XX-removed.md"),
            encoding="utf-8",
        )

    def mut_status_decode_rx0(root: pathlib.Path) -> None:
        """Regression: decode MISO status from local_rx[0] (wrong DS framing)."""
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        if "local_rx[1]" not in text:
            raise RuntimeError("expected local_rx[1] status path")
        p.write_text(
            text.replace("local_rx[1]", "local_rx[0]"),
            encoding="utf-8",
        )

    def mut_unaligned_trans_storage(root: pathlib.Path) -> None:
        p = root / "ports" / "esp-idf" / "include" / "ninlil_esp_idf" / "sx1262_bus.h"
        text = p.read_text(encoding="utf-8")
        # Drop member alignment attribute only (comment tokens must not mask).
        bad = re.sub(
            r"_Alignas\s*\(\s*max_align_t\s*\)\s*",
            "",
            text,
            count=1,
        )
        if bad == text:
            raise RuntimeError("failed to strip _Alignas from bus header")
        p.write_text(bad, encoding="utf-8")

    def mut_clear_pending_on_timeout(root: pathlib.Path) -> None:
        p = root / "ports" / "esp-idf" / "src" / "esp_idf_sx1262_bus.c"
        text = p.read_text(encoding="utf-8")
        needle = "(void)ninlil_sx1262_spi_own_on_result_timeout(&own);"
        if needle not in text:
            raise RuntimeError("timeout handler missing")
        p.write_text(
            text.replace(
                needle,
                needle + "\n    bus->pending_trans = NULL;",
                1,
            ),
            encoding="utf-8",
        )

    def mut_drop_section12_test(root: pathlib.Path) -> None:
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("test_spi_pending_ownership_sm", "test_spi_pending_REMOVED"),
            encoding="utf-8",
        )

    def mut_alt_tx_send(root: pathlib.Path) -> None:
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text + "\nvoid ninlil_sx1262_send(void) {}\n",
            encoding="utf-8",
        )

    def mut_alt_tx_transmit(root: pathlib.Path) -> None:
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text + "\nvoid ninlil_sx1262_transmit(void) {}\n",
            encoding="utf-8",
        )

    def mut_extra_port_sx1262_tu(root: pathlib.Path) -> None:
        p = root / "ports" / "esp-idf" / "src" / "evil_sx1262_tx.c"
        p.write_text(
            "void ninlil_sx1262_send(void) { (void)0; }\n",
            encoding="utf-8",
        )

    def mut_port_authority_settx(root: pathlib.Path) -> None:
        p = root / "ports" / "esp-idf" / "src" / "esp_idf_sx1262_bus.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text + "\nvoid ninlil_sx1262_transmit(const void *p) { (void)p; }\n",
            encoding="utf-8",
        )

    def mut_drop_monotonic_deadline(root: pathlib.Path) -> None:
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace(
                "test_monotonic_deadline_boundary",
                "test_monotonic_deadline_REMOVED",
            ),
            encoding="utf-8",
        )

    def mut_exact_deadline_as_ok(root: pathlib.Path) -> None:
        """False-green: drop exact==timeout proof token from tests."""
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        bad = text.replace(
            "REQUIRE(elapsed == (uint64_t)timeout);",
            "/* exact elapsed proof removed (false-green) */",
            1,
        )
        if bad == text:
            raise RuntimeError("exact-deadline false-green mutation failed")
        p.write_text(bad, encoding="utf-8")

    def mut_deadline_helper_lt(root: pathlib.Path) -> None:
        """Production false-green: use > instead of >= for deadline."""
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_backend.c"
        text = p.read_text(encoding="utf-8")
        bad = text.replace(
            "return ((uint64_t)(now_ms - start_ms) >= (uint64_t)timeout_ms) ? 1 : 0;",
            "return ((uint64_t)(now_ms - start_ms) > (uint64_t)timeout_ms) ? 1 : 0;",
            1,
        )
        if bad == text:
            raise RuntimeError("deadline helper mutation failed")
        p.write_text(bad, encoding="utf-8")

    def mut_drop_busy_fail_positions(root: pathlib.Path) -> None:
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace(
                "test_fail_busy_read_positions",
                "test_fail_busy_read_REMOVED",
            ),
            encoding="utf-8",
        )

    def mut_drop_event_order_mid_status(root: pathlib.Path) -> None:
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("nth_spi_index", "nth_spi_REMOVED"),
            encoding="utf-8",
        )

    def mut_flip_golden_get_status(root: pathlib.Path) -> None:
        """False-green: wrong Semtech pin on independent golden."""
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        bad = text.replace(
            "SX126X_GOLDEN_GET_STATUS = 0xC0u",
            "SX126X_GOLDEN_GET_STATUS = 0xC1u",
            1,
        )
        if bad == text:
            raise RuntimeError("golden GET_STATUS flip mutation failed")
        p.write_text(bad, encoding="utf-8")

    def mut_flip_production_get_status(root: pathlib.Path) -> None:
        """Production opcode drift without updating independent golden."""
        p = root / "drivers" / "sx126x" / "ninlil_sx1262_cmd.h"
        text = p.read_text(encoding="utf-8")
        bad = text.replace(
            "NINLIL_SX1262_CMD_GET_STATUS ((uint8_t)0xC0u)",
            "NINLIL_SX1262_CMD_GET_STATUS ((uint8_t)0xC1u)",
            1,
        )
        if bad == text:
            raise RuntimeError("production GET_STATUS flip mutation failed")
        p.write_text(bad, encoding="utf-8")

    def mut_reinject_prod_macro_into_golden(root: pathlib.Path) -> None:
        """False-green: sequence vector rebuilds expected from production macros."""
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        # Replace golden vector body element with production macro.
        bad = text.replace(
            "static const uint8_t k_xtal_ok[] = {\n"
            "    SX126X_GOLDEN_GET_STATUS,",
            "static const uint8_t k_xtal_ok[] = {\n"
            "    NINLIL_SX1262_CMD_GET_STATUS,",
            1,
        )
        if bad == text:
            raise RuntimeError("reinject production macro into golden failed")
        p.write_text(bad, encoding="utf-8")

    def mut_drop_primary_opcode_pin(root: pathlib.Path) -> None:
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        p.write_text(
            text.replace("test_primary_opcode_pin", "test_primary_opcode_REMOVED"),
            encoding="utf-8",
        )

    def mut_schema_uses_production_macro(root: pathlib.Path) -> None:
        """False-green: frame schema expects production macro opcodes."""
        p = root / "tests" / "radio" / "sx1262_r4_test.c"
        text = p.read_text(encoding="utf-8")
        bad = text.replace(
            "tx[0] = (uint8_t)SX126X_GOLDEN_GET_STATUS;",
            "tx[0] = NINLIL_SX1262_CMD_GET_STATUS;",
            1,
        )
        if bad == text:
            raise RuntimeError("schema production-macro reinject failed")
        p.write_text(bad, encoding="utf-8")

    structural: list[tuple[str, Callable[[pathlib.Path], None]]] = [
        ("drop allowlist call", mut_drop_allowlist),
        ("inject SetTx buffer assign", mut_inject_settx_send),
        ("literal 0x83 injection", mut_literal_settx),
        ("extra production .c", mut_extra_production_c),
        ("ESP polling_transmit", mut_polling_transmit),
        ("drop cmake gate name", mut_drop_cmake_gate),
        ("spy in production authority", mut_spy_in_authority),
        ("inject RadioLib include", mut_radiolib),
        ("public header sx1262 leak", mut_public_leak),
        ("drop docs README 28 link", mut_drop_doc28),
        ("status decode local_rx[0]", mut_status_decode_rx0),
        ("unaligned trans_storage", mut_unaligned_trans_storage),
        ("clear pending on timeout", mut_clear_pending_on_timeout),
        ("drop §12.1 pending test", mut_drop_section12_test),
        ("alt TX send symbol", mut_alt_tx_send),
        ("alt TX transmit symbol", mut_alt_tx_transmit),
        ("extra port sx1262 TU", mut_extra_port_sx1262_tu),
        ("port authority transmit", mut_port_authority_settx),
        ("drop monotonic deadline test", mut_drop_monotonic_deadline),
        ("drop busy fail positions test", mut_drop_busy_fail_positions),
        ("drop mid-status event order", mut_drop_event_order_mid_status),
        ("exact deadline treated as OK", mut_exact_deadline_as_ok),
        ("deadline helper uses > not >=", mut_deadline_helper_lt),
        ("flip golden GET_STATUS 0xC0", mut_flip_golden_get_status),
        ("flip production GET_STATUS 0xC0", mut_flip_production_get_status),
        ("reinject production macro into k_xtal_ok", mut_reinject_prod_macro_into_golden),
        ("drop primary opcode pin test", mut_drop_primary_opcode_pin),
        ("schema uses production CMD macro", mut_schema_uses_production_macro),
    ]

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td) / "clean"
        root.mkdir()
        _copy_tree(root)
        check(root)

    for name, mut in structural:
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "mut"
            root.mkdir()
            _copy_tree(root)
            mut(root)
            try:
                check(root)
            except GateFailure:
                print(f"mutation caught: {name}")
                continue
            fail(f"mutation NOT caught: {name}")

    print("sx1262_r4_gate self-test: OK")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("check", "self-test"):
        print("usage: sx1262_r4_gate.py check|self-test", file=sys.stderr)
        return 2
    try:
        if argv[1] == "check":
            check()
        else:
            self_test()
    except GateFailure as exc:
        print(f"sx1262_r4_gate FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
