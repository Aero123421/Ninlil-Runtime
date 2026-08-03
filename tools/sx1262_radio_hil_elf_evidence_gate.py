#!/usr/bin/env python3
"""Validate SX1262 radio_hil ESP final-ELF / map / pin / authority evidence.

Rejects false-green: requires real PCP/R5/R7/ledger/LBT path symbols present
and mock permit mint absent. Does not claim RF HIL PASS.
Does not alter CI docker amd64 authority.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]

REQUIRED_ELF_SYMS = (
    "ninlil_radio_hal_transmit_with_permit",
    "ninlil_sx1262_phy_arm_tx",
    "ninlil_sx1262_r9_edge_init",
    "ninlil_sx1262_request_transmit",
    "ninlil_esp_idf_sx1262_bus_grant_rf_sole_capability",
    "ninlil_model_domain_sha256",
    "ninlil_airtime_lora_us",
    # Real authority path (must not be dead-stripped)
    "ninlil_pcp_issue",
    "ninlil_pcp_validate",
    "ninlil_pcp_consume",
    "ninlil_pcp_recover",
    "ninlil_r5_issue",
    "ninlil_r5_load_regulatory_profile",
    "ninlil_r5_activate_profiles",
    "ninlil_r5_permit_ops",
    # V1 release HIL: flash FULL adapter + recovery (not session RAM ledger)
    "ninlil_port_esp_storage_flash_bind",
    "ninlil_port_esp_storage_config_production",
    "ninlil_r7_crypto_mbedtls_provider_init",
    "ninlil_sx1262_phy_ldro_auto_effective",
    # Immutable XIAO+Wio board profile (DIO2/DIO3 TCXO/CAL path live)
    "ninlil_sx1262_board_profile_xiao_wio_sx1262_v1",
    "ninlil_sx1262_board_profile_copy_xiao_wio_sx1262_v1",
)

FORBIDDEN_ELF_SYMS = (
    "ninlil_sx1262_request_transmit_with_permit",
    "fill_permit",  # local mock mint
    "hil_permit_validate",  # mock R2 seam
    "hil_permit_consume",
    # Session RAM ledger must be absent from V1 release HIL ELF
    "ninlil_pcp_lab_session_ledger_init",
    "ninlil_pcp_lab_session_ledger_shutdown",
)

REQUIRED_ARCHIVE_MEMBERS = (
    "ninlil_sx1262_board_profiles",
    "ninlil_sx1262_backend",
    "esp_storage_flash_media",
)

FORBIDDEN_ARCHIVE_MEMBERS = (
    "pcp_lab_session_ledger",
)

FORBIDDEN_ARCHIVE_SYMS = (
    "ninlil_sx1262_request_transmit_with_permit",
    "ninlil_pcp_lab_session_ledger_init",
    "ninlil_pcp_lab_session_ledger_shutdown",
)

# Map/callgraph needles proving live authority + board TCXO path placement.
REQUIRED_MAP_NEEDLES = (
    "radio_hal",
    "ninlil_sx1262_phy",
    "sx1262_r9_edge",
    "pcp_authority",
    "profile_loader",
    "esp_storage_flash",
    "r7_crypto_mbedtls",
    "ninlil_sx1262_board_profiles",
    "ninlil_sx1262_backend",
)

PIN_KV = {
    "CONFIG_NINLIL_SX1262_PIN_NSS": "41",
    "CONFIG_NINLIL_SX1262_PIN_SCK": "7",
    "CONFIG_NINLIL_SX1262_PIN_MOSI": "9",
    "CONFIG_NINLIL_SX1262_PIN_MISO": "8",
    "CONFIG_NINLIL_SX1262_PIN_RESET": "42",
    "CONFIG_NINLIL_SX1262_PIN_BUSY": "40",
    "CONFIG_NINLIL_SX1262_PIN_DIO1": "39",
    "CONFIG_NINLIL_SX1262_PIN_ANT_SW": "38",
}

# Sol xhigh re-audit: gate MAX of all retained main-task call-chains
# (INIT / TX-new-epoch / recovery / RX), not INIT-only (false-green at 16 KiB).
# Fresh ESP-IDF GCC .su (Xtensa) TX chain sum = 18256 B; margin ≥4 KiB → 24 KiB.
MIN_MAIN_STACK = 24576
STACK_MARGIN_BYTES = 4096

# Order: outer → leaf. ELF-retained, live .su frames.
RETAINED_INIT_CALL_CHAIN = (
    "app_main",
    "handle_line",
    "cmd_init",
    "authority_init",
    "ninlil_pcp_publish_initial_meta",
    "pcp_scan_namespace",
)
# Release TX / new-epoch path (worst measured retained chain).
RETAINED_TX_CALL_CHAIN = (
    "app_main",
    "handle_line",
    "cmd_tx_data",
    "ninlil_r5_issue",
    "ninlil_r5_issue_with_bind",
    "ninlil_pcp_issue",
    "pcp_algorithm_e_body",
    "pcp_rw_scan_check",
    "pcp_scan_namespace",
)
# Same-session PCP recover (not physical restart claim).
RETAINED_RECOVERY_CALL_CHAIN = (
    "app_main",
    "handle_line",
    "cmd_pcp_recover_same_session",
    "ninlil_pcp_recover",
    "ninlil_pcp_recover_storage",
    "pcp_scan_namespace",
)
# RX path on main task (serial RX_START / POLL / RX_TAKE).
RETAINED_RX_CALL_CHAIN = (
    "app_main",
    "handle_line",
    "ninlil_sx1262_phy_start_rx",
    "ninlil_sx1262_phy_poll",
    "ninlil_sx1262_phy_take_rx",
)

RETAINED_CALL_CHAINS: dict[str, tuple[str, ...]] = {
    "init": RETAINED_INIT_CALL_CHAIN,
    "tx_new_epoch": RETAINED_TX_CALL_CHAIN,
    "recovery_same_session": RETAINED_RECOVERY_CALL_CHAIN,
    "rx": RETAINED_RX_CALL_CHAIN,
}

# .su basenames covering all chains.
REQUIRED_SU_BASENAMES = (
    "main.c.su",
    "pcp_authority.c.su",
    "profile_loader.c.su",
    "ninlil_sx1262_phy.c.su",
)

SU_LINE_RE = re.compile(
    r"^(?P<path>[^:]+):(?P<line>\d+):(?:\d+:)?(?P<func>[^\t]+)\t"
    r"(?P<size>\d+)\t(?P<qual>.*)$"
)

CI_AMD64_DIGEST = (
    "sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"
)
LOCAL_ARM64_DIGEST = (
    "sha256:c4a92762d44103ea341c097894b6df45f22e7898a97a065b6b5b87ccf49dbfc1"
)


def fail(msg: str) -> None:
    print(f"sx1262_radio_hil_elf_evidence_gate: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def read_text(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def nm_has_sym(nm_text: str, sym: str) -> bool:
    # Global (T) or local retained (t) — both prove ELF callgraph placement.
    return re.search(rf" [Tt] {re.escape(sym)}$", nm_text, re.M) is not None


def archive_is_nonempty_file(archive: pathlib.Path) -> bool:
    return archive.is_file() and archive.stat().st_size > 0


def check_archive(archive: pathlib.Path) -> None:
    if not archive_is_nonempty_file(archive):
        fail(f"archive missing/empty: {archive}")

    ar_tool = shutil.which("xtensa-esp32s3-elf-ar") or shutil.which("ar")
    nm_tool = shutil.which("xtensa-esp32s3-elf-nm") or shutil.which("nm")
    if ar_tool is None or nm_tool is None:
        fail("archive validation requires ar and nm tools")

    try:
        members = subprocess.run(
            [ar_tool, "t", str(archive)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        archive_nm = subprocess.run(
            [nm_tool, str(archive)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"archive inspection failed: {exc}")

    for member in REQUIRED_ARCHIVE_MEMBERS:
        if member not in members:
            fail(f"archive missing required member: {member}")
    for member in FORBIDDEN_ARCHIVE_MEMBERS:
        if member in members:
            fail(f"archive contains forbidden member: {member}")
    for sym in FORBIDDEN_ARCHIVE_SYMS:
        if re.search(rf"(?:^|\s){re.escape(sym)}$", archive_nm, re.M):
            fail(f"archive contains forbidden symbol: {sym}")


def parse_su_frames(su_path: pathlib.Path) -> dict[str, int]:
    """Return max static frame size per function name from one .su file."""
    frames: dict[str, int] = {}
    text = su_path.read_text(encoding="utf-8", errors="replace")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = SU_LINE_RE.match(line)
        if m:
            func = m.group("func").strip()
            size = int(m.group("size"))
        else:
            parts = line.split("\t")
            if len(parts) < 2 or not parts[1].isdigit():
                continue
            func = parts[0].rsplit(":", 1)[-1].strip()
            size = int(parts[1])
        # Strip C++-style or file-local noise; keep plain C names.
        func = func.split("(")[0].strip()
        prev = frames.get(func, 0)
        if size > prev:
            frames[func] = size
    return frames


def collect_su_index(su_dir: pathlib.Path) -> dict[str, dict[str, int]]:
    """Map basename → {func: max_frame} for all .su under su_dir."""
    if not su_dir.is_dir():
        fail(f"su-dir missing or not a directory: {su_dir}")
    index: dict[str, dict[str, int]] = {}
    for p in sorted(su_dir.rglob("*.su")):
        if not p.is_file() or p.stat().st_size == 0:
            continue
        frames = parse_su_frames(p)
        base = p.name
        if base not in index:
            index[base] = {}
        for func, size in frames.items():
            if size > index[base].get(func, 0):
                index[base][func] = size
    return index


def lookup_frame(su_index: dict[str, dict[str, int]], func: str) -> int | None:
    best: int | None = None
    for frames in su_index.values():
        if func in frames:
            size = frames[func]
            if best is None or size > best:
                best = size
    return best


def evaluate_call_chain(
    frames: dict[str, int],
    stack_bytes: int,
    margin: int = STACK_MARGIN_BYTES,
    chain: tuple[str, ...] = RETAINED_INIT_CALL_CHAIN,
    chain_name: str = "init",
) -> dict:
    """Fail-closed for one chain: sum(frames) + margin must fit stack_bytes."""
    missing = [f for f in chain if f not in frames]
    if missing:
        return {
            "ok": False,
            "reason": f"missing_chain_frames:{chain_name}:{','.join(missing)}",
            "chain_name": chain_name,
            "frames": dict(frames),
            "chain_sum": None,
            "required": None,
            "stack_bytes": stack_bytes,
            "margin": margin,
        }
    ordered = [(f, int(frames[f])) for f in chain]
    chain_sum = sum(sz for _, sz in ordered)
    required = chain_sum + margin
    max_single = max(sz for _, sz in ordered)
    # Per-chain: only sum+margin (MIN_MAIN_STACK is enforced on multi-chain result).
    ok = stack_bytes >= required
    return {
        "ok": ok,
        "reason": None if ok else "stack_insufficient_for_call_chain_plus_margin",
        "chain_name": chain_name,
        "frames": {f: sz for f, sz in ordered},
        "chain": list(chain),
        "chain_sum": chain_sum,
        "max_single_frame": max_single,
        "margin": margin,
        "required": required,
        "stack_bytes": stack_bytes,
        "min_main_stack": MIN_MAIN_STACK,
        "headroom": stack_bytes - required,
    }


def evaluate_all_call_chains(
    frames: dict[str, int],
    stack_bytes: int,
    margin: int = STACK_MARGIN_BYTES,
    chains: dict[str, tuple[str, ...]] | None = None,
) -> dict:
    """Fail-closed: max(chain_sum) + margin must fit stack (not INIT-only)."""
    chains = chains if chains is not None else RETAINED_CALL_CHAINS
    per: dict[str, dict] = {}
    worst: dict | None = None
    for name, chain in chains.items():
        # Collect only frames needed for this chain.
        sub = {f: frames[f] for f in chain if f in frames}
        ev = evaluate_call_chain(
            sub, stack_bytes, margin=margin, chain=chain, chain_name=name
        )
        per[name] = ev
        if ev.get("chain_sum") is None:
            return {
                "ok": False,
                "reason": ev.get("reason"),
                "worst_chain": name,
                "chains": per,
                "margin": margin,
                "stack_bytes": stack_bytes,
            }
        if worst is None or int(ev["chain_sum"]) > int(worst["chain_sum"]):
            worst = ev
    assert worst is not None
    ok = all(c.get("ok") for c in per.values()) and stack_bytes >= MIN_MAIN_STACK
    return {
        "ok": ok,
        "reason": None if ok else "stack_insufficient_for_worst_call_chain",
        "worst_chain": worst["chain_name"],
        "worst_chain_sum": worst["chain_sum"],
        "worst_required": worst["required"],
        "worst_max_single": worst["max_single_frame"],
        "worst_frames": worst["frames"],
        "worst_chain_funcs": worst["chain"],
        "margin": margin,
        "stack_bytes": stack_bytes,
        "min_main_stack": MIN_MAIN_STACK,
        "headroom": stack_bytes - int(worst["required"]),
        "chains": {
            k: {
                "chain_sum": v.get("chain_sum"),
                "required": v.get("required"),
                "ok": v.get("ok"),
                "frames": v.get("frames"),
            }
            for k, v in per.items()
        },
    }


def check_stack_call_chain(
    su_dir: pathlib.Path,
    nm_text: str,
    map_text: str,
    stack_bytes: int,
) -> dict:
    su_index = collect_su_index(su_dir)
    for base in REQUIRED_SU_BASENAMES:
        if base not in su_index:
            fail(f"required .su missing under su-dir: {base}")
    # Union of all chain functions.
    all_funcs: list[str] = []
    seen: set[str] = set()
    for chain in RETAINED_CALL_CHAINS.values():
        for func in chain:
            if func not in seen:
                seen.add(func)
                all_funcs.append(func)
    frames: dict[str, int] = {}
    for func in all_funcs:
        size = lookup_frame(su_index, func)
        if size is None:
            fail(f"call-chain function missing from .su: {func}")
        frames[func] = size
        if not nm_has_sym(nm_text, func):
            fail(f"ELF nm dump missing retained call-chain symbol {func}")
        if f".text.{func}" not in map_text and f" {func}\n" not in map_text:
            if func not in map_text:
                fail(f"map missing call-chain placement for {func}")
    result = evaluate_all_call_chains(frames, stack_bytes)
    if not result["ok"]:
        fail(
            "retained call-chain stack budget exceeded: "
            f"worst={result.get('worst_chain')} "
            f"sum={result.get('worst_chain_sum')} + margin={result['margin']} "
            f"= required {result.get('worst_required')} > "
            f"CONFIG_ESP_MAIN_TASK_STACK_SIZE={stack_bytes} "
            f"(max_single={result.get('worst_max_single')}; "
            f"INIT-only or max-single-only gate is false-green)"
        )
    if stack_bytes < MIN_MAIN_STACK:
        fail(
            f"CONFIG_ESP_MAIN_TASK_STACK_SIZE={stack_bytes} < "
            f"minimum {MIN_MAIN_STACK}"
        )
    # Present a stable shape for evidence JSON (worst chain + all chains).
    return {
        "ok": True,
        "chain": result["worst_chain_funcs"],
        "chain_name": result["worst_chain"],
        "frames": result["worst_frames"],
        "chain_sum": result["worst_chain_sum"],
        "max_single_frame": result["worst_max_single"],
        "margin": result["margin"],
        "required": result["worst_required"],
        "headroom": result["headroom"],
        "all_chains": result["chains"],
        "all_frames": frames,
    }


def check_source_no_mock() -> None:
    main = ROOT / "ports/esp-idf/radio_hil_app/main/main.c"
    text = read_text(main)
    # Production composition must not mint mock permits.
    for banned in (
        "static void fill_permit",
        "static ninlil_radio_hal_status_t hil_permit_validate",
        "static ninlil_radio_hal_status_t hil_permit_consume",
        "g_hil_permit_ops",
    ):
        if banned in text:
            fail(f"radio_hil main still contains mock permit surface: {banned}")
    if "ninlil_r5_issue" not in text:
        fail("radio_hil main must call ninlil_r5_issue")
    if "ninlil_r5_permit_ops" not in text:
        fail("radio_hil main must bind ninlil_r5_permit_ops")
    if "ninlil_port_esp_storage_flash_bind" not in text:
        fail("radio_hil main must bind flash FULL storage")
    if "ERR flash_full_required" not in text:
        fail("radio_hil main must fail closed without flash FULL")
    if "ninlil_pcp_recover" not in text:
        fail("radio_hil main must call ninlil_pcp_recover")
    if "PCP_RECOVER_SAME_SESSION" not in text:
        fail("radio_hil main must expose PCP_RECOVER_SAME_SESSION")
    if "PREPARE_TWO_BOOT" not in text or "COMPLETE_TWO_BOOT" not in text:
        fail("radio_hil main must expose two-boot recovery protocol")
    if "same_session_not_restart" not in text:
        fail("same-session recover must declare not_restart claim")
    if "ninlil_sx1262_board_profile_xiao_wio_sx1262_v1" not in text:
        fail("radio_hil main must bind XIAO+Wio board profile")
    if "NINLIL_SX1262_FEATURE_TCXO_PRESENT" not in text and "XIAO_WIO_FEATURE" not in text:
        # profile header macros via board_profiles bind
        if "board_profile_xiao_wio" not in text:
            fail("radio_hil must reference XIAO+Wio TCXO board profile")
    if "fill_board_release_profile" not in text:
        fail("radio_hil must use fill_board_release_profile (not ANT_SW-only)")
    # Session fallback only under diagnostic Kconfig, not unconditional.
    if "ninlil_pcp_lab_session_ledger_init" in text:
        if "CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG" not in text:
            fail("session ledger must be gated by SESSION_LEDGER_DIAG")
    if "k_ninlil_lab_approved_reg_v1" not in text:
        fail("radio_hil main must load approved regulatory profile")
    if "NINLIL_RADIO_HIL_DIAG_MOCK" in text and "NINLIL_SX1262_PRODUCTION_BUILD" not in text:
        fail("diag mock gate must mention PRODUCTION_BUILD exclusion")
    if "CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG" in text:
        if "NINLIL_SX1262_PRODUCTION_BUILD" not in text:
            fail(
                "session DIAG must be excluded under "
                "NINLIL_SX1262_PRODUCTION_BUILD"
            )
        if "impossible under" not in text and "#error" not in text:
            fail("session DIAG must hard-fail under PRODUCTION_BUILD")

    # Backend must implement Dio2/Dio3/CAL command path (live when flags set).
    be = read_text(ROOT / "drivers/sx126x/ninlil_sx1262_backend.c")
    for needle in (
        "NINLIL_SX1262_CMD_SET_DIO2_AS_RF_SWITCH_CTRL",
        "NINLIL_SX1262_CMD_SET_DIO3_AS_TCXO_CTRL",
        "NINLIL_SX1262_CAL_ALL",
        "NINLIL_SX1262_FEATURE_DIO2_RF_SWITCH",
        "NINLIL_SX1262_FEATURE_TCXO_PRESENT",
    ):
        if needle not in be:
            fail(f"backend missing live TCXO path token: {needle}")
    prof = read_text(ROOT / "drivers/sx126x/ninlil_sx1262_board_profiles.c")
    if "NINLIL_SX1262_TCXO_3_0V" not in prof and "0x06" not in prof:
        # profile uses TCXO_3_0V macro via header constant assignment
        if "XIAO_WIO_TCXO_VOLTAGE" not in read_text(
            ROOT / "drivers/sx126x/ninlil_sx1262_board_profiles.h"
        ):
            fail("board profile must pin TCXO 3.0V")
    hdr = read_text(ROOT / "drivers/sx126x/ninlil_sx1262_board_profiles.h")
    for needle in (
        "NINLIL_SX1262_TCXO_3_0V",
        "NINLIL_SX1262_FEATURE_DIO2_RF_SWITCH",
        "NINLIL_SX1262_FEATURE_TCXO_PRESENT",
        "NINLIL_SX1262_FEATURE_ANT_SW_PRESENT",
        "xiao_esp32s3_wio_sx1262_v1",
        # Primary-source identity (informative; not physical PASS)
        "Wio-SX1262",
        "version 1.0",
        "200 mV",
        "3.3 V",
        "internally connected",
    ):
        if needle not in hdr:
            fail(f"board profile header missing {needle}")


def check(
    elf: pathlib.Path,
    map_path: pathlib.Path,
    sdkconfig: pathlib.Path,
    nm_dump: pathlib.Path,
    archive: pathlib.Path | None,
    out_json: pathlib.Path | None,
    su_dir: pathlib.Path | None,
) -> None:
    check_source_no_mock()

    if not elf.is_file() or elf.stat().st_size == 0:
        fail(f"ELF missing/empty: {elf}")
    if not map_path.is_file() or map_path.stat().st_size == 0:
        fail(f"map missing/empty: {map_path}")

    nm_text = read_text(nm_dump)
    present = []
    for sym in REQUIRED_ELF_SYMS:
        if not nm_has_sym(nm_text, sym):
            fail(f"ELF nm dump missing symbol {sym}")
        present.append(sym)
    for sym in FORBIDDEN_ELF_SYMS:
        if nm_has_sym(nm_text, sym):
            fail(f"forbidden production symbol present: {sym}")

    if archive is not None:
        check_archive(archive)

    sdk = read_text(sdkconfig)
    for k, v in PIN_KV.items():
        if f"{k}={v}" not in sdk:
            fail(f"sdkconfig missing {k}={v}")
    if "CONFIG_NINLIL_SX1262_ANT_SW_ACTIVE_HIGH=y" not in sdk:
        fail("sdkconfig missing ANT_SW active-high")
    if "CONFIG_NINLIL_ENABLE_SX1262_R9=y" not in sdk:
        fail("radio_hil sdkconfig must enable CONFIG_NINLIL_ENABLE_SX1262_R9")
    # V1 release HIL: session diagnostic must be OFF
    if re.search(
        r"^CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG=y\s*$", sdk, re.M
    ):
        fail(
            "release radio_hil must not enable "
            "CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG"
        )
    m = re.search(r"^CONFIG_ESP_MAIN_TASK_STACK_SIZE=(\d+)\s*$", sdk, re.M)
    if not m:
        fail("sdkconfig missing CONFIG_ESP_MAIN_TASK_STACK_SIZE")
    stack = int(m.group(1))
    if stack < MIN_MAIN_STACK:
        fail(
            f"CONFIG_ESP_MAIN_TASK_STACK_SIZE={stack} < minimum {MIN_MAIN_STACK} "
            f"(retained INIT call-chain + margin requires ≥16 KiB)"
        )

    map_text = read_text(map_path)
    for needle in REQUIRED_MAP_NEEDLES:
        if needle not in map_text:
            fail(f"map missing placement needle {needle}")

    if su_dir is None:
        # Default: radio_hil build tree next to ELF (fresh ESP build).
        cand = elf.parent
        if (cand / "esp-idf").is_dir():
            su_dir = cand
        else:
            fail(
                "su-dir required: pass --su-dir <radio_hil build or collected "
                ".su directory> for call-chain stack gate"
            )
    stack_eval = check_stack_call_chain(su_dir, nm_text, map_text, stack)

    evidence = {
        "schema": "ninlil-sx1262-radio-hil-elf-evidence-v2",
        "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "claims": {
            "rf_hil_pass": False,
            "japan_legal": False,
            "adr_0025_accepted": False,
            "compile_link_radio_hil": True,
            "sole_edge_r1_r2_r5_r9": True,
            "mock_permit_absent": True,
            "lbt_cad_path_linked": True,
            "flash_full_ledger_linked": True,
            "session_ledger_absent": True,
            "xiao_wio_board_profile_linked": True,
            "tcxo_dio2_cal_path_linked": True,
            # Layered recovery honesty:
            "same_session_pcp_recover_linked": True,
            "physical_two_boot_recovery": False,
            "restart_recovery_protocol": False,
            "physical_powercut_pass": False,
            "physical_stack_watermark_pass": False,
        },
        "claim_layers": {
            "compile_link": True,
            "same_session_pcp_recover": "linked (PCP_RECOVER_SAME_SESSION)",
            "physical_two_boot_recovery": "linked protocol; physical NOT_RUN here",
            "physical_powercut": False,
            "physical_stack_watermark": (
                "NOT_RUN without device watermark measurement; "
                "static .su call-chain gate is compile/link only"
            ),
            "rf_hil_legal": False,
        },
        "esp_idf": {
            "version_pin": "v5.5.3",
            "ci_amd64_authority_digest": CI_AMD64_DIGEST,
            "local_arm64_digest": LOCAL_ARM64_DIGEST,
            "local_arm64_is_ci_authority": False,
        },
        "board_profile": {
            "id": "xiao_esp32s3_wio_sx1262_v1",
            "pins": dict(PIN_KV),
            "features": [
                "TCXO_PRESENT",
                "DIO2_RF_SWITCH",
                "ANT_SW_PRESENT",
            ],
            "tcxo_voltage_code": "0x06 (3.0V)",
            "tcxo_delay_rtc_steps": 5000,
            "vdd_op_mv": 3300,
            "init_opcodes": [
                "SetDio2AsRfSwitchCtrl",
                "SetDio3AsTcxoCtrl",
                "CAL_ALL",
            ],
            "primary_source": {
                "document": "Seeed Studio Wio-SX1262 datasheet",
                "version": "v1.0",
                "statements_encoded": [
                    "module_supply_3v3_typical",
                    "tcxo_powered_by_dio3_at_least_200mv_below_vcc",
                    "dio2_internally_connected_to_rf_switch",
                    "external_rf_sw_gpio_as_ant_sw_on_carrier",
                ],
                "physical_pass_claim": False,
                "rf_hil_pass_claim": False,
                "note": (
                    "Source identity justifies release encode only; "
                    "not bench RF verification."
                ),
            },
        },
        "stack": {
            "main_task_bytes": stack,
            "min_required_bytes": MIN_MAIN_STACK,
            "method": "max_retained_call_chain_sum_plus_margin",
            "false_green_rejected": [
                "max_single_frame_only",
                "init_chain_only",
            ],
            "worst_chain": stack_eval["chain_name"],
            "call_chain": stack_eval["chain"],
            "frames_bytes": stack_eval["frames"],
            "chain_sum_bytes": stack_eval["chain_sum"],
            "max_single_frame_bytes": stack_eval["max_single_frame"],
            "margin_bytes": stack_eval["margin"],
            "required_bytes": stack_eval["required"],
            "headroom_bytes": stack_eval["headroom"],
            "all_chains": stack_eval.get("all_chains"),
            "physical_stack_watermark_pass": False,
            "physical_stack_watermark_status": "NOT_RUN",
            "note": (
                "Static -fstack-usage + ELF-retained chains "
                "(init/tx_new_epoch/recovery/rx); gate uses max sum. "
                "Runtime FreeRTOS watermark on device remains NOT_RUN."
            ),
        },
        "artifacts": {
            "elf": str(elf.as_posix()),
            "elf_bytes": elf.stat().st_size,
            "map": str(map_path.as_posix()),
            "map_bytes": map_path.stat().st_size,
            "sdkconfig": str(sdkconfig.as_posix()),
            "nm_dump": str(nm_dump.as_posix()),
        },
        "symbols_required_present": present,
        "symbols_forbidden_absent": list(FORBIDDEN_ELF_SYMS),
        "path": {
            "order": [
                "xiao_wio_board_profile (DIO2/DIO3@3V/CAL_ALL)",
                "approved_lab_profile",
                "flash_full_bind",
                "ninlil_pcp_recover (boot/INIT or two-boot reconstruct)",
                "ninlil_r5_issue",
                "ninlil_pcp_validate/consume",
                "ninlil_radio_hal_transmit_with_permit",
                "sx1262_r9_edge",
                "ninlil_sx1262_phy_arm_tx (CAD/LBT + SetTx)",
            ],
            "bare_r4_request_transmit": "present_as_TX_DENIED_symbol",
            "legacy_permit_tx": "absent_under_PRODUCTION_BUILD",
            "mock_fill_permit": "absent",
            "session_ram_ledger": "absent_from_release_elf",
            "same_session_protocol": "PCP_RECOVER_SAME_SESSION",
            "two_boot_protocol": "PREPARE_TWO_BOOT/REBOOT/COMPLETE_TWO_BOOT",
            "restart_protocol_deprecated_alias": "false (not same-session)",
        },
    }

    if out_json is not None:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"wrote {out_json}")

    print("sx1262_radio_hil_elf_evidence_gate: OK")


def self_test() -> None:
    """Host self-test: multi-chain max+margin; INIT-only / max-single false-green."""
    # Auditor INIT chain.
    init_frames = {
        "app_main": 336,
        "handle_line": 352,
        "cmd_init": 912,
        "authority_init": 736,
        "ninlil_pcp_publish_initial_meta": 9040,
        "pcp_scan_namespace": 672,
    }
    if sum(init_frames[f] for f in RETAINED_INIT_CALL_CHAIN) != 12048:
        fail("self-test: INIT sum fixture drifted")

    # Auditor TX / new-epoch chain (18256).
    tx_frames = {
        "app_main": 336,
        "handle_line": 352,
        "cmd_tx_data": 1168,
        "ninlil_r5_issue": 288,
        "ninlil_r5_issue_with_bind": 1088,
        "ninlil_pcp_issue": 5152,
        "pcp_algorithm_e_body": 9152,
        "pcp_rw_scan_check": 48,
        "pcp_scan_namespace": 672,
    }
    tx_sum = sum(tx_frames[f] for f in RETAINED_TX_CALL_CHAIN)
    if tx_sum != 18256:
        fail(f"self-test: TX sum fixture drifted: {tx_sum} != 18256")

    union = dict(init_frames)
    union.update(tx_frames)
    union.update(
        {
            "cmd_pcp_recover_same_session": 256,
            "ninlil_pcp_recover": 32,
            "ninlil_pcp_recover_storage": 8928,
            "ninlil_sx1262_phy_start_rx": 176,
            "ninlil_sx1262_phy_poll": 64,
            "ninlil_sx1262_phy_take_rx": 32,
        }
    )

    # False-green #1: 16 KiB fits INIT+2KiB margin but not TX+4KiB margin.
    init_only_ok = evaluate_call_chain(
        init_frames, stack_bytes=16384, margin=2048, chain_name="init"
    )
    if not init_only_ok["ok"]:
        fail("self-test: INIT alone at 16KiB/2KiB margin should still fit")
    multi_16 = evaluate_all_call_chains(union, stack_bytes=16384, margin=4096)
    if multi_16["ok"]:
        fail("self-test: 16KiB must FAIL under TX chain + 4KiB margin")
    if multi_16.get("worst_chain") != "tx_new_epoch":
        fail(f"self-test: worst must be tx_new_epoch got {multi_16}")
    if multi_16.get("worst_chain_sum") != 18256:
        fail(f"self-test: worst sum {multi_16.get('worst_chain_sum')}")

    # False-green #2: max-single 9152 << 16384 but multi-chain fails.
    if multi_16.get("worst_max_single") != 9152:
        fail("self-test: max_single expected 9152")

    # 24 KiB + 4 KiB margin: required 18256+4096=22352 ≤ 24576.
    multi_24 = evaluate_all_call_chains(union, stack_bytes=24576, margin=4096)
    if not multi_24["ok"]:
        fail(f"self-test: 24KiB must PASS: {multi_24}")
    if multi_24["worst_required"] != 22352:
        fail(f"self-test: required expected 22352 got {multi_24['worst_required']}")
    if multi_24["headroom"] != 24576 - 22352:
        fail(f"self-test: headroom mismatch {multi_24['headroom']}")

    # Missing TX leaf fails closed.
    incomplete = dict(union)
    del incomplete["pcp_algorithm_e_body"]
    miss = evaluate_all_call_chains(incomplete, stack_bytes=24576, margin=4096)
    if miss["ok"] or "missing_chain_frames" not in str(miss.get("reason")):
        fail(f"self-test: missing TX frame must fail: {miss}")

    # Parse .su round-trip for TX + INIT symbols.
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        root = pathlib.Path(td)
        if archive_is_nonempty_file(root / "definitely-missing.a"):
            fail("self-test: missing archive must not pass presence gate")
        (root / "main.c.su").write_text(
            "main.c:1:0:app_main\t336\tstatic\n"
            "main.c:2:0:handle_line\t352\tstatic\n"
            "main.c:3:0:cmd_init\t912\tstatic\n"
            "main.c:4:0:authority_init\t736\tstatic\n"
            "main.c:5:0:cmd_tx_data\t1168\tstatic\n"
            "main.c:6:0:cmd_pcp_recover_same_session\t256\tstatic\n",
            encoding="utf-8",
        )
        (root / "pcp_authority.c.su").write_text(
            "pcp_authority.c:1:0:ninlil_pcp_publish_initial_meta\t9040\tstatic\n"
            "pcp_authority.c:2:0:pcp_scan_namespace\t672\tstatic\n"
            "pcp_authority.c:3:0:pcp_algorithm_e_body\t9152\tstatic\n"
            "pcp_authority.c:4:0:ninlil_pcp_issue\t5152\tstatic\n"
            "pcp_authority.c:5:0:pcp_rw_scan_check\t48\tstatic\n"
            "pcp_authority.c:6:0:ninlil_pcp_recover\t32\tstatic\n"
            "pcp_authority.c:7:0:ninlil_pcp_recover_storage\t8928\tstatic\n",
            encoding="utf-8",
        )
        (root / "profile_loader.c.su").write_text(
            "profile_loader.c:1:0:ninlil_r5_issue\t288\tstatic\n"
            "profile_loader.c:2:0:ninlil_r5_issue_with_bind\t1088\tstatic\n",
            encoding="utf-8",
        )
        (root / "ninlil_sx1262_phy.c.su").write_text(
            "phy.c:1:0:ninlil_sx1262_phy_start_rx\t176\tstatic\n"
            "phy.c:2:0:ninlil_sx1262_phy_poll\t64\tstatic\n"
            "phy.c:3:0:ninlil_sx1262_phy_take_rx\t32\tstatic\n",
            encoding="utf-8",
        )
        idx = collect_su_index(root)
        for base in REQUIRED_SU_BASENAMES:
            if base not in idx:
                fail(f"self-test: missing su basename {base}")
        parsed = {
            f: lookup_frame(idx, f)
            for chain in RETAINED_CALL_CHAINS.values()
            for f in chain
        }
        if any(v is None for v in parsed.values()):
            fail(f"self-test: incomplete parse {parsed}")
        frames_i = {k: int(v) for k, v in parsed.items()}  # type: ignore[arg-type]
        e16 = evaluate_all_call_chains(frames_i, 16384, margin=4096)
        if e16["ok"]:
            fail("self-test: parsed multi-chain must fail 16KiB")
        e24 = evaluate_all_call_chains(frames_i, 24576, margin=4096)
        if not e24["ok"]:
            fail(f"self-test: parsed multi-chain must pass 24KiB: {e24}")

    sdkdef = read_text(
        ROOT / "ports/esp-idf/radio_hil_app/sdkconfig.defaults"
    )
    if "CONFIG_ESP_MAIN_TASK_STACK_SIZE=24576" not in sdkdef:
        fail("self-test: sdkconfig.defaults must set MAIN stack 24576")
    for stale in ("12288", "16384"):
        if f"CONFIG_ESP_MAIN_TASK_STACK_SIZE={stale}" in sdkdef:
            fail(f"self-test: sdkconfig.defaults must not keep {stale}")

    print("sx1262_radio_hil_elf_evidence_gate: self-test OK")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("check", "self-test"))
    ap.add_argument("--elf", type=pathlib.Path, default=None)
    ap.add_argument("--map", type=pathlib.Path, default=None)
    ap.add_argument("--sdkconfig", type=pathlib.Path, default=None)
    ap.add_argument("--nm-dump", type=pathlib.Path, default=None)
    ap.add_argument("--archive", type=pathlib.Path, default=None)
    ap.add_argument("--su-dir", type=pathlib.Path, default=None)
    ap.add_argument("--out-json", type=pathlib.Path, default=None)
    args = ap.parse_args()
    if args.cmd == "self-test":
        self_test()
        return
    if args.cmd == "check":
        for req, name in (
            (args.elf, "--elf"),
            (args.map, "--map"),
            (args.sdkconfig, "--sdkconfig"),
            (args.nm_dump, "--nm-dump"),
        ):
            if req is None:
                fail(f"check requires {name}")
        check(
            args.elf.resolve(),  # type: ignore[union-attr]
            args.map.resolve(),  # type: ignore[union-attr]
            args.sdkconfig.resolve(),  # type: ignore[union-attr]
            args.nm_dump.resolve(),  # type: ignore[union-attr]
            args.archive.resolve() if args.archive else None,
            args.out_json.resolve() if args.out_json else None,
            args.su_dir.resolve() if args.su_dir else None,
        )


if __name__ == "__main__":
    main()
