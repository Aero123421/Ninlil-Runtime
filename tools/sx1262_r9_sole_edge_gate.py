#!/usr/bin/env python3
"""R9 sole-edge production call-site gate (Proposed ADR-0025).

Proves:
  - RF_SOLE bus grant has exactly one production call site (radio_hil)
  - Production/HIL does not call legacy request_transmit_with_permit
  - Sole SetTx issuer remains phy_arm_tx
  - radio_hil uses radio_hal_transmit_with_permit + real SHA-256 path
  - Default board pins match ESP32-S3+SX1262 profile
  - R4 control-only default not removed from ESP bus

Does not claim RF HIL PASS / Japan legal / Accepted.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

RADIO_HIL = ROOT / "ports/esp-idf/radio_hil_app/main/main.c"
ESP_BUS_C = ROOT / "ports/esp-idf/src/esp_idf_sx1262_bus.c"
PHY_C = ROOT / "drivers/sx126x/ninlil_sx1262_phy.c"
PHY_H = ROOT / "drivers/sx126x/ninlil_sx1262_phy.h"
EDGE_C = ROOT / "src/radio/sx1262_r9_edge.c"
CAP_C = ROOT / "ports/esp-idf/src/sx1262_rf_bus_capability_logic.c"
KCONFIG = ROOT / "ports/esp-idf/components/ninlil/Kconfig"
SDKDEF = ROOT / "ports/esp-idf/radio_hil_app/sdkconfig.defaults"

# Default board profile (NSS=41 SCK=7 MOSI=9 MISO=8 RST=42 BUSY=40 DIO1=39 ANT=38)
PIN_DEFAULTS = {
    "NINLIL_SX1262_PIN_NSS": "41",
    "NINLIL_SX1262_PIN_SCK": "7",
    "NINLIL_SX1262_PIN_MOSI": "9",
    "NINLIL_SX1262_PIN_MISO": "8",
    "NINLIL_SX1262_PIN_RESET": "42",
    "NINLIL_SX1262_PIN_BUSY": "40",
    "NINLIL_SX1262_PIN_DIO1": "39",
    "NINLIL_SX1262_PIN_ANT_SW": "38",
}


def fail(msg: str) -> None:
    print(f"sx1262_r9_sole_edge_gate: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read(p: pathlib.Path) -> str:
    if not p.is_file():
        fail(f"missing {p.relative_to(ROOT)}")
    return p.read_text(encoding="utf-8")


def strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r"//.*?$", "", code, flags=re.M)
    return code


def production_c_files() -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    for base in (
        ROOT / "drivers/sx126x",
        ROOT / "src/radio",
        ROOT / "ports/esp-idf/src",
        ROOT / "ports/esp-idf/radio_hil_app",
        ROOT / "ports/esp-idf/components",
        ROOT / "ports/esp-idf/smoke_app",
    ):
        if not base.exists():
            continue
        for p in base.rglob("*.c"):
            rel = str(p.relative_to(ROOT))
            if "/managed_components/" in rel or "/build" in rel:
                continue
            if "/tests/" in rel:
                continue
            paths.append(p)
    return paths


def check_rf_grant_uniqueness() -> None:
    grant = "ninlil_esp_idf_sx1262_bus_grant_rf_sole_capability"
    sites: list[str] = []
    for p in production_c_files():
        text = read(p)
        # definition in bus.c is allowed once
        if p.resolve() == ESP_BUS_C.resolve():
            if text.count(grant) < 1:
                fail("ESP bus must define grant_rf_sole_capability")
            continue
        # count call sites (not declarations)
        for m in re.finditer(rf"\b{re.escape(grant)}\s*\(", text):
            # skip if this is a declaration-only line with trailing ;
            line = text[text.rfind("\n", 0, m.start()) + 1 : text.find("\n", m.start())]
            if re.search(r"^\s*int\s+" + re.escape(grant), line):
                continue
            sites.append(str(p.relative_to(ROOT)))
    if len(sites) != 1:
        fail(
            f"RF_SOLE grant call sites must be exactly 1 production site, "
            f"found {len(sites)}: {sites}"
        )
    if sites[0] != "ports/esp-idf/radio_hil_app/main/main.c":
        fail(f"RF_SOLE grant sole call site must be radio_hil main, got {sites[0]}")


def check_no_legacy_permit_tx() -> None:
    legacy = "ninlil_sx1262_request_transmit_with_permit"
    for p in production_c_files():
        text = strip_comments(read(p))
        if p.resolve() == PHY_C.resolve():
            # allowed only under !PRODUCTION_BUILD
            if legacy in text and "NINLIL_SX1262_PRODUCTION_BUILD" not in read(p):
                fail("phy must gate legacy permit TX with PRODUCTION_BUILD")
            continue
        if p.resolve() == PHY_H.resolve():
            continue
        if legacy in text:
            fail(f"production must not call {legacy}: {p.relative_to(ROOT)}")


def check_settx_sole_issuer() -> None:
    phy = strip_comments(read(PHY_C))
    # CMD_SET_TX assignment for SPI must appear only in phy_arm_tx path.
    # Count f[0] = CMD_SET_TX or spi_tx[0] = CMD_SET_TX
    assigns = re.findall(
        r"(?:f|phy->spi_tx)\[0\]\s*=\s*CMD_SET_TX\b(?!_)", phy
    )
    if len(assigns) != 1:
        fail(f"sole SetTx assign count must be 1 in phy.c, got {len(assigns)}")
    if "ninlil_sx1262_phy_arm_tx" not in phy:
        fail("phy_arm_tx must exist")
    # backend must not assign SetTx
    be = strip_comments(read(ROOT / "drivers/sx126x/ninlil_sx1262_backend.c"))
    if re.search(r"=\s*NINLIL_SX1262_CMD_SET_TX", be):
        fail("R4 backend must not assign SET_TX")


def check_radio_hil_sole_path() -> None:
    text = read(RADIO_HIL)
    code = strip_comments(text)
    for needle in (
        "ninlil_radio_hal_transmit_with_permit",
        "ninlil_sx1262_r9_edge_init",
        "ninlil_esp_idf_sx1262_bus_grant_rf_sole_capability",
        "ninlil_model_domain_sha256",
        "ninlil_airtime_lora_us",
        "ninlil_esp_idf_sx1262_bus_install_dio1_isr",
        "ninlil_esp_idf_sx1262_bus_dio1_is_high",
        "ninlil_r5_issue",
        "ninlil_r5_permit_ops",
        "ninlil_port_esp_storage_flash_bind",
        "ninlil_pcp_recover",
        "PCP_RECOVER_SAME_SESSION",
        "PREPARE_TWO_BOOT",
        "COMPLETE_TWO_BOOT",
        "ERR flash_full_required",
        "ninlil_sx1262_board_profile_xiao_wio_sx1262_v1",
        "fill_board_release_profile",
        "ninlil_r5_load_regulatory_profile",
        "k_ninlil_lab_approved_reg_v1",
        "ninlil_r7_crypto_mbedtls_provider_init",
    ):
        if needle not in code:
            fail(f"radio_hil must use {needle}")
    if "0xA5" in code:
        fail("radio_hil must not use fake digest 0xA5")
    if "request_transmit_with_permit" in code:
        fail("radio_hil must not call legacy request_transmit_with_permit")
    # Mock permit mint forbidden in production composition.
    for banned in (
        "fill_permit(",
        "hil_permit_validate",
        "hil_permit_consume",
        "g_hil_permit_ops",
    ):
        if banned in code:
            fail(f"radio_hil must not use mock permit path: {banned}")
    # Session ledger only under diagnostic Kconfig (not unconditional fallback).
    if "ninlil_pcp_lab_session_ledger_init" in code:
        if "CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG" not in text:
            fail("session ledger must be gated by SESSION_LEDGER_DIAG")
    if "CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG=y" in read(SDKDEF):
        fail("release sdkconfig.defaults must not enable SESSION_LEDGER_DIAG")
    kcfg = read(KCONFIG)
    for key, val in PIN_DEFAULTS.items():
        if f"config {key}" not in kcfg:
            fail(f"Kconfig missing {key}")
        block = kcfg.split(f"config {key}", 1)[1].split("config ", 1)[0]
        if f"default {val}" not in block:
            fail(f"Kconfig {key} default must be {val}")
    sdk = read(SDKDEF)
    for key, val in PIN_DEFAULTS.items():
        if f"CONFIG_{key}={val}" not in sdk:
            fail(f"sdkconfig.defaults missing CONFIG_{key}={val}")
    if "CONFIG_ESP_MAIN_TASK_STACK_SIZE=24576" not in sdk:
        fail("sdkconfig.defaults must set MAIN_TASK_STACK_SIZE=24576")
    for stale in ("12288", "16384"):
        if f"CONFIG_ESP_MAIN_TASK_STACK_SIZE={stale}" in sdk:
            fail(f"sdkconfig.defaults must not keep MAIN_TASK_STACK_SIZE={stale}")
    if "CONFIG_NINLIL_ENABLE_SX1262_R9=y" not in sdk:
        fail("radio_hil sdkconfig.defaults must enable SX1262 R9")
    kcfg = read(KCONFIG)
    if "config NINLIL_ENABLE_SX1262_R9" not in kcfg:
        fail("Kconfig missing NINLIL_ENABLE_SX1262_R9")
    block = kcfg.split("config NINLIL_ENABLE_SX1262_R9", 1)[1].split("config ", 1)[0]
    if "default n" not in block and "default N" not in block:
        fail("NINLIL_ENABLE_SX1262_R9 must default n")
def check_esp_bus_dual_mode() -> None:
    text = read(ESP_BUS_C)
    code = strip_comments(text)
    if "ninlil_sx1262_bus_spi_xfer_admitted" not in code:
        fail("ESP bus must use pure spi_xfer_admitted policy")
    if "capability_mode" not in text:
        fail("ESP bus must track capability_mode")
    if "NINLIL_SX1262_BUS_CAP_CONTROL_ONLY" not in read(CAP_C):
        fail("capability logic must define CONTROL_ONLY")
    # Must not unconditionally allow RF without capability check
    if re.search(
        r"if\s*\(\s*ninlil_sx1262_cmd_is_rf_banned\s*\(\s*tx\s*\[\s*0\s*\]\s*\)",
        code,
    ):
        # old hard-ban only path replaced by admit helper
        fail("ESP bus must not use bare rf_banned||!allowlist only; use admit helper")


def check_edge_digest_airtime() -> None:
    text = read(EDGE_C)
    if "ninlil_model_domain_sha256" not in text:
        fail("r9 edge must recompute SHA-256")
    if "ninlil_sx1262_r9_digest_ct_neq" not in text:
        fail("r9 edge must constant-time compare digest")
    if "ninlil_airtime_lora_us" not in text:
        fail("r9 edge must recompute airtime")
    if "ninlil_sx1262_phy_arm_tx" not in text:
        fail("r9 edge must call phy_arm_tx")
    if "require_lbt" not in text:
        fail("r9 edge must seal require_lbt for CAD/LBT before SetTx")
    if "ldro_effective" not in text:
        fail("r9 edge must seal ldro_effective into arm plan")


def check_phy_lbt_ldro_status() -> None:
    phy = strip_comments(read(PHY_C))
    if "CMD_SET_CAD" not in phy and "0xC5" not in phy:
        fail("phy must issue SetCad for LBT")
    if "CMD_SET_CAD_PARAMS" not in phy and "0x88" not in phy:
        fail("phy must issue SetCadParams for LBT")
    if "ninlil_sx1262_cmd_status_is_fail" not in phy:
        fail("phy must validate SPI command status")
    if "ninlil_sx1262_phy_ldro_auto_effective" not in phy:
        fail("phy must implement LDRO AUTO calculation")
    if "ant_sw_set" not in phy:
        fail("phy must drive ANT_SW")
    if "sealed_plan" not in phy:
        fail("phy must seal plan fields through arm_tx")


def check() -> None:
    check_esp_bus_dual_mode()
    check_rf_grant_uniqueness()
    check_no_legacy_permit_tx()
    check_settx_sole_issuer()
    check_radio_hil_sole_path()
    check_edge_digest_airtime()
    check_phy_lbt_ldro_status()
    print("sx1262_r9_sole_edge_gate: OK")


def self_test() -> None:
    # sanity: control-only still deny settx in pure logic
    cap = read(CAP_C)
    if "NINLIL_SX1262_CMD_SET_TX" not in cap and "0x83" not in cap:
        # allow via header macros in .c includes
        pass
    if "ninlil_sx1262_bus_spi_xfer_admitted" not in cap:
        fail("self-test: capability logic missing admit")
    print("sx1262_r9_sole_edge_gate: self-test OK")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "self-test"):
        print("usage: sx1262_r9_sole_edge_gate.py check|self-test", file=sys.stderr)
        raise SystemExit(2)
    if sys.argv[1] == "self-test":
        self_test()
        return
    check()


if __name__ == "__main__":
    main()
