#!/usr/bin/env python3
"""Executable SX1262 radio_hil serial protocol + honest layered evidence.

Claim layers (never collapsed):
  - compile_link_radio_hil: ELF/map evidence only (other tool)
  - same_session_pcp_recover: in-process recover on live g_pcp
  - physical_two_boot_recovery: PREPARE_TWO_BOOT → REBOOT → COMPLETE_TWO_BOOT
  - rf_hil_pass: two distinct boards exchange exact payloads in both directions
  - physical_powercut_pass: remains NOT_RUN without power-cut fixture
  - japan_legal / telec: always false here

Same-session PCP recover is NEVER counted as restart recovery.
When no device is connected, records physical_status=NOT_RUN (exit 0).
Physical FAIL or post-response exceptions exit nonzero.  The pair runner proves
the raw R1/R2/R5/R9 radio path only; it does not claim Fabric/ApplicationData,
Join, relay, field SLO, or regulatory acceptance.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]

SCHEMA = "ninlil-sx1262-radio-hil-physical-v2"

TWO_BOOT_STEPS = (
    "1. Connect XIAO ESP32-S3 + Wio-SX1262; open serial",
    "2. Wait for READY; note boot_id=A",
    "3. INIT (must report board=xiao_esp32s3_wio_sx1262_v1, features=tcxo_dio2_ant)",
    "4. BOOT_IDENTITY → record boot_id_A",
    "5. PREPARE_TWO_BOOT → receipt=valid fence=F class=old",
    "6. REBOOT (target calls esp_restart)",
    "7. Wait for READY with boot_id=B (must differ from A)",
    "8. COMPLETE_TWO_BOOT <boot_id_A> → class=old/new/fenced reconstruct=fresh_authority",
    "9. Reject if boot_id unchanged or RAM authority reused without reconstruct",
)


def fail(msg: str) -> None:
    print(f"sx1262_radio_hil_protocol: FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_evidence(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {path}")


def base_claims() -> dict:
    return {
        "compile_link_radio_hil": False,  # set by ELF gate, not this tool
        "same_session_pcp_recover": False,
        "physical_two_boot_recovery": False,
        "physical_powercut_pass": False,
        "physical_stack_watermark_pass": False,
        "restart_recovery_protocol": False,  # deprecated alias; always false
        "rf_hil_pass": False,  # pair-run only
        "japan_legal": False,
        "telec_certification": False,
        "adr_0025_accepted": False,
        "over_the_air_verified": False,  # pair-run only
    }


def base_payload() -> dict:
    return {
        "schema": SCHEMA,
        "generated_utc": utc_now(),
        "claims": base_claims(),
        "claim_layers": {
            "compile_link": "tools/sx1262_radio_hil_elf_evidence_gate.py",
            "same_session_pcp_recover": "PCP_RECOVER_SAME_SESSION (in-process)",
            "physical_two_boot_recovery": "PREPARE_TWO_BOOT/REBOOT/COMPLETE_TWO_BOOT",
            "rf_hil_pass": "pair-run with two distinct physical boards",
            "physical_powercut": "NOT_RUN without power-cut fixture",
            "rf_hil_legal": "never claimed by this protocol",
        },
        "executable_two_boot_steps": list(TWO_BOOT_STEPS),
    }


def probe_port(port: str | None, baud: int) -> tuple[str, str | None]:
    """Return (physical_status, detail). Never fabricates PASS."""
    if not port:
        return "NOT_RUN", "no --port provided"
    try:
        import serial  # type: ignore
    except ImportError:
        return "NOT_RUN", "pyserial not installed"
    try:
        ser = serial.Serial(port, baudrate=baud, timeout=2.0)
    except Exception as exc:  # noqa: BLE001
        return "NOT_RUN", f"open failed: {exc}"
    try:
        time.sleep(0.2)
        pending = ser.read(ser.in_waiting or 1)
        text = pending.decode("utf-8", errors="replace")
        ser.write(b"PING\n")
        ser.flush()
        line = ser.readline().decode("utf-8", errors="replace").strip()
        if "OK pong" in line or "READY" in text:
            return "DEVICE_RESPONSIVE", line or text[:120]
        return "NOT_RUN", f"no READY/pong (got {line!r})"
    finally:
        ser.close()


def _require_ok(resp: str, prefix: str, steps: list) -> None:
    if not resp.startswith(prefix):
        raise RuntimeError(
            f"expected {prefix!r}, got {resp!r} steps={steps[-3:]}"
        )


def classify_two_boot(old_boot_id: str, new_boot_id: str, fence: str) -> dict:
    """Host-side classification used by self-tests and two-boot runner."""
    if not old_boot_id or not new_boot_id or not fence:
        return {
            "ok": False,
            "reason": "missing_identity_or_fence",
            "class": None,
        }
    if old_boot_id == new_boot_id:
        return {
            "ok": False,
            "reason": "boot_id_unchanged_not_restart",
            "class": None,
        }
    if len(old_boot_id) != 32 or len(new_boot_id) != 32:
        return {"ok": False, "reason": "boot_id_width", "class": None}
    return {
        "ok": True,
        "reason": "old_new_fenced",
        "class": "old/new/fenced",
        "old_boot_id": old_boot_id,
        "new_boot_id": new_boot_id,
        "fence": fence,
    }


def reject_same_session_as_restart(claims: dict) -> None:
    """Self-check: same-session must never set restart/two-boot true."""
    if claims.get("same_session_pcp_recover") and (
        claims.get("physical_two_boot_recovery")
        or claims.get("restart_recovery_protocol")
    ):
        raise AssertionError(
            "same-session recover must not imply restart/two-boot recovery"
        )
    if claims.get("restart_recovery_protocol"):
        raise AssertionError(
            "restart_recovery_protocol is deprecated and must stay false"
        )


def parse_rx_take(line: str) -> dict | None:
    """Parse the stable RX_TAKE response without accepting partial matches."""
    match = re.fullmatch(
        r"OK rx_take class=(\d+) len=(\d+) rssi=(-?\d+) snr=(-?\d+) "
        r"irq=0x([0-9a-fA-F]+) gen=(\d+) payload=([0-9a-fA-F]*)",
        line,
    )
    if match is None:
        return None
    payload_hex = match.group(7)
    declared_len = int(match.group(2))
    if len(payload_hex) != declared_len * 2:
        return None
    return {
        "class": int(match.group(1)),
        "length": declared_len,
        "rssi_dbm": int(match.group(3)),
        "snr_db": int(match.group(4)),
        "irq_status": int(match.group(5), 16),
        "generation": int(match.group(6)),
        "payload": bytes.fromhex(payload_hex),
    }


def pair_payload(direction: int, sequence: int, size: int) -> bytes:
    """Deterministic non-secret payload used by the physical pair runner."""
    if direction not in (0, 1) or sequence < 0 or size < 8 or size > 64:
        raise ValueError("invalid pair payload parameters")
    prefix = bytes((0xA5, 0x5A, 0xC3, 0x3C, direction)) + sequence.to_bytes(
        2, "big"
    )
    body = bytes(((sequence + direction + i) & 0xFF) for i in range(size - 7))
    return prefix + body


def self_test() -> None:
    """CLI self-tests: reject false restart claims without hardware."""
    # 1) unchanged boot id is not a restart
    bad = classify_two_boot("a" * 32, "a" * 32, "c0ffee00")
    if bad.get("ok"):
        fail("self-test: unchanged boot_id must be rejected")
    if bad.get("reason") != "boot_id_unchanged_not_restart":
        fail(f"self-test: unexpected reason {bad}")

    # 2) changed boot id + fence is classifiable
    good = classify_two_boot("a" * 32, "b" * 32, "c0ffee00")
    if not good.get("ok") or good.get("class") != "old/new/fenced":
        fail(f"self-test: expected old/new/fenced got {good}")

    # 3) same-session claim must not raise restart flags
    claims = base_claims()
    claims["same_session_pcp_recover"] = True
    reject_same_session_as_restart(claims)

    # 4) reused RAM authority (same boot_id) cannot complete two-boot
    reused = classify_two_boot("deadbeef" * 4, "deadbeef" * 4, "1")
    if reused.get("ok"):
        fail("self-test: reused boot identity must fail")

    # 5) protocol source must not set restart_recovery_protocol True
    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    if re.search(
        r'["\']restart_recovery_protocol["\']\s*:\s*True', src
    ):
        fail("self-test: source must not claim restart_recovery_protocol=True")

    # 6) Exact RX parser rejects truncation and length mismatches.
    parsed = parse_rx_take(
        "OK rx_take class=0 len=4 rssi=-71 snr=9 irq=0x2 gen=3 "
        "payload=0102a0ff"
    )
    if parsed is None or parsed["payload"] != bytes.fromhex("0102a0ff"):
        fail("self-test: valid RX_TAKE response rejected")
    if parse_rx_take(
        "OK rx_take class=0 len=5 rssi=-71 snr=9 irq=0x2 gen=3 "
        "payload=0102a0ff"
    ) is not None:
        fail("self-test: RX_TAKE length mismatch accepted")

    # 7) Pair payloads are exact, bounded, and direction-separated.
    a = pair_payload(0, 7, 64)
    b = pair_payload(1, 7, 64)
    if len(a) != 64 or len(b) != 64 or a == b or a[:4] != bytes(
        (0xA5, 0x5A, 0xC3, 0x3C)
    ):
        fail("self-test: pair payload contract")

    print("sx1262_radio_hil_protocol: self-test OK")


def run_protocol(port: str, baud: int, timeout_s: float) -> dict:
    import serial  # type: ignore

    steps: list[dict] = []
    ser = serial.Serial(port, baudrate=baud, timeout=timeout_s)
    try:

        def cmd(line: str) -> str:
            ser.write((line + "\n").encode("ascii"))
            ser.flush()
            resp = ser.readline().decode("utf-8", errors="replace").strip()
            steps.append({"cmd": line, "resp": resp})
            if resp.startswith("ERR "):
                raise RuntimeError(f"target error for {line}: {resp}")
            return resp

        ready = ser.readline().decode("utf-8", errors="replace").strip()
        steps.append({"cmd": "(banner)", "resp": ready})
        r = cmd("PING")
        _require_ok(r, "OK pong", steps)
        r = cmd("BOOT_IDENTITY")
        _require_ok(r, "OK boot_identity", steps)
        r = cmd("INIT")
        _require_ok(r, "OK init", steps)
        if "board=xiao_esp32s3_wio_sx1262_v1" not in r:
            raise RuntimeError(f"INIT missing XIAO+Wio board profile: {r}")
        if "features=tcxo_dio2_ant" not in r:
            raise RuntimeError(f"INIT missing tcxo_dio2_ant features: {r}")
        if "dio2_rf_switch=1" not in r or "cal_all=1" not in r:
            raise RuntimeError(f"INIT missing DIO2/CAL flags: {r}")
        if "spi_max=" in r and "spi_max=280" not in r:
            raise RuntimeError(f"spi_max not 280: {r}")
        if "ledger=flash_full" not in r:
            raise RuntimeError(f"INIT must use flash_full ledger: {r}")
        r = cmd("TX_DATA 01020304")
        _require_ok(r, "OK tx_armed", steps)
        r = cmd("POLL")
        _require_ok(r, "OK poll", steps)
        if not re.search(r"state=\d+", r) or not re.search(r"gen=\d+", r):
            raise RuntimeError(f"POLL missing state/gen fields: {r}")
        r = cmd("STATS")
        _require_ok(r, "OK stats", steps)
        for needle in ("edge_ok=", "pcp_issue=", "pcp_consume=", "ledger="):
            if needle not in r:
                raise RuntimeError(f"STATS missing {needle}: {r}")
        r = cmd("RX_START")
        _require_ok(r, "OK rx_start", steps)
        r = cmd("POLL")
        _require_ok(r, "OK poll", steps)
        r = cmd("RX_TAKE")
        _require_ok(r, "OK rx_take", steps)
        for needle in ("class=", "len=", "rssi=", "snr=", "irq=", "payload="):
            if needle not in r:
                raise RuntimeError(f"RX_TAKE missing {needle}: {r}")
        r = cmd("RECOVER")
        _require_ok(r, "OK recover", steps)
        # Same-session only — not restart recovery.
        r = cmd("PCP_RECOVER_SAME_SESSION")
        _require_ok(r, "OK pcp_recover_same_session", steps)
        if "claim=same_session_not_restart" not in r:
            raise RuntimeError(f"same-session claim missing: {r}")
        if "ledger=flash_full" not in r:
            raise RuntimeError(f"same-session recover must use flash_full: {r}")

        claims = base_claims()
        claims["same_session_pcp_recover"] = True
        claims["physical_two_boot_recovery"] = False
        claims["restart_recovery_protocol"] = False
        reject_same_session_as_restart(claims)

        return {
            "physical_status": "DEVICE_PROTOCOL_OK",
            "steps": steps,
            "claims": claims,
            "note": (
                "Same-session protocol only. "
                "physical_two_boot_recovery remains false until "
                "tools/sx1262_radio_hil_protocol.py two-boot-run completes "
                "across a real device reboot. "
                "physical_powercut_pass remains NOT_RUN. "
                "RF / legal nonclaims hold."
            ),
        }
    finally:
        ser.close()


def run_two_boot(port: str, baud: int, timeout_s: float) -> dict:
    """Physical two-boot recovery across esp_restart (not power-cut)."""
    import serial  # type: ignore

    steps: list[dict] = []
    ser = serial.Serial(port, baudrate=baud, timeout=timeout_s)
    try:

        def cmd(line: str) -> str:
            ser.write((line + "\n").encode("ascii"))
            ser.flush()
            resp = ser.readline().decode("utf-8", errors="replace").strip()
            steps.append({"cmd": line, "resp": resp})
            if resp.startswith("ERR "):
                raise RuntimeError(f"target error for {line}: {resp}")
            return resp

        ready = ser.readline().decode("utf-8", errors="replace").strip()
        steps.append({"cmd": "(banner1)", "resp": ready})
        r = cmd("INIT")
        _require_ok(r, "OK init", steps)
        m = re.search(r"boot_id=([0-9a-fA-F]{32})", r)
        if not m:
            # fall back to BOOT_IDENTITY
            r = cmd("BOOT_IDENTITY")
            _require_ok(r, "OK boot_identity", steps)
            m = re.search(r"boot_id=([0-9a-fA-F]{32})", r)
        if not m:
            raise RuntimeError("cannot parse boot_id before reboot")
        boot_a = m.group(1).lower()
        r = cmd("PREPARE_TWO_BOOT")
        _require_ok(r, "OK prepare_two_boot", steps)
        if "receipt=valid" not in r:
            raise RuntimeError(f"prepare missing receipt: {r}")
        fm = re.search(r"fence=([0-9a-fA-F]+)", r)
        fence = fm.group(1).lower() if fm else ""
        r = cmd("REBOOT")
        _require_ok(r, "OK reboot", steps)
    finally:
        ser.close()
    return _complete_two_boot(port, baud, timeout_s, steps, boot_a, fence)


def run_pair(
    first_port: str,
    second_port: str,
    baud: int,
    timeout_s: float,
    count: int,
    interval_ms: int,
    payload_bytes: int,
) -> dict:
    """Exchange exact raw frames over RF using two physical radio_hil boards."""
    import serial  # type: ignore

    if first_port == second_port:
        raise ValueError("pair-run requires two distinct serial ports")
    if count < 1 or count > 100:
        raise ValueError("count must be in 1..100")
    if interval_ms < 0 or interval_ms > 60000:
        raise ValueError("interval-ms must be in 0..60000")
    if payload_bytes < 8 or payload_bytes > 64:
        raise ValueError("payload-bytes must be in 8..64")

    steps: list[dict] = []
    first = serial.Serial(first_port, baudrate=baud, timeout=0.2)
    try:
        second = serial.Serial(second_port, baudrate=baud, timeout=0.2)
    except Exception:
        first.close()
        raise

    def command(port, label: str, line: str, deadline_s: float = 8.0) -> str:
        port.write((line + "\n").encode("ascii"))
        port.flush()
        deadline = time.monotonic() + deadline_s
        while time.monotonic() < deadline:
            response = port.readline().decode("utf-8", errors="replace").strip()
            if not response:
                continue
            steps.append({"board": label, "cmd": line, "resp": response})
            if response.startswith("ERR "):
                raise RuntimeError(f"{label} error for {line}: {response}")
            if response.startswith("OK "):
                return response
        raise RuntimeError(f"{label} timeout for {line}")

    def initialize(port, label: str) -> None:
        port.reset_input_buffer()
        _require_ok(command(port, label, "PING"), "OK pong", steps)
        response = command(port, label, "INIT", deadline_s=max(timeout_s, 15.0))
        _require_ok(response, "OK init", steps)
        if "board=xiao_esp32s3_wio_sx1262_v1" not in response:
            raise RuntimeError(f"{label} board profile mismatch: {response}")
        if "ledger=flash_full" not in response:
            raise RuntimeError(f"{label} does not use flash_full: {response}")

    def exchange(
        tx_port,
        tx_label: str,
        rx_port,
        rx_label: str,
        direction: int,
        sequence: int,
    ) -> dict:
        payload = pair_payload(direction, sequence, payload_bytes)
        _require_ok(command(rx_port, rx_label, "RX_START"), "OK rx_start", steps)
        _require_ok(
            command(tx_port, tx_label, f"TX_DATA {payload.hex()}"),
            "OK tx_armed",
            steps,
        )
        deadline = time.monotonic() + max(timeout_s, 8.0)
        last_rx: dict | None = None
        while time.monotonic() < deadline:
            _require_ok(command(tx_port, tx_label, "POLL"), "OK poll", steps)
            _require_ok(command(rx_port, rx_label, "POLL"), "OK poll", steps)
            response = command(rx_port, rx_label, "RX_TAKE")
            parsed = parse_rx_take(response)
            if parsed is None:
                raise RuntimeError(f"{rx_label} malformed RX_TAKE: {response}")
            last_rx = parsed
            if parsed["class"] == 0:
                if parsed["payload"] != payload:
                    raise RuntimeError(
                        f"{rx_label} payload mismatch for sequence {sequence}"
                    )
                while time.monotonic() < deadline:
                    tx_state = command(tx_port, tx_label, "POLL")
                    state_match = re.search(r"\bstate=(\d+)\b", tx_state)
                    if state_match is None:
                        raise RuntimeError(
                            f"{tx_label} malformed POLL response: {tx_state}"
                        )
                    state = int(state_match.group(1))
                    if state == 0:
                        break
                    if state == 6:
                        raise RuntimeError(
                            f"{tx_label} radio fault after sequence {sequence}"
                        )
                    time.sleep(0.02)
                else:
                    raise RuntimeError(
                        f"{tx_label} TX completion timeout sequence={sequence}"
                    )
                return {
                    "direction": f"{tx_label}_to_{rx_label}",
                    "sequence": sequence,
                    "length": len(payload),
                    "payload_hex": payload.hex(),
                    "rssi_dbm": parsed["rssi_dbm"],
                    "snr_db": parsed["snr_db"],
                    "radio_generation": parsed["generation"],
                }
            if parsed["class"] not in (6,):
                raise RuntimeError(
                    f"{rx_label} RX failed class={parsed['class']} "
                    f"sequence={sequence}"
                )
            time.sleep(0.02)
        raise RuntimeError(
            f"{rx_label} RF receive timeout sequence={sequence} last={last_rx}"
        )

    observations: list[dict] = []
    try:
        initialize(first, "first")
        initialize(second, "second")
        for sequence in range(count):
            observations.append(
                exchange(first, "first", second, "second", 0, sequence)
            )
            if interval_ms:
                time.sleep(interval_ms / 1000.0)
        for sequence in range(count):
            observations.append(
                exchange(second, "second", first, "first", 1, sequence)
            )
            if interval_ms:
                time.sleep(interval_ms / 1000.0)
    finally:
        first.close()
        second.close()

    claims = base_claims()
    claims["rf_hil_pass"] = True
    claims["over_the_air_verified"] = True
    return {
        "physical_status": "DEVICE_RF_PAIR_OK",
        "ports": [first_port, second_port],
        "message_count_per_direction": count,
        "payload_bytes": payload_bytes,
        "interval_ms": interval_ms,
        "observations": observations,
        "steps": steps,
        "claims": claims,
        "note": (
            "Two-board bidirectional raw RF HIL only. "
            "Fabric/ApplicationData, Join, relay, field SLO, Japan legal, "
            "TELEC, and physical power-cut remain unproven."
        ),
    }


def _complete_two_boot(
    port: str,
    baud: int,
    timeout_s: float,
    steps: list[dict],
    boot_a: str,
    fence: str,
) -> dict:
    """Reopen after esp_restart and finish the physical two-boot proof."""
    import serial  # type: ignore

    # Device reboots — reopen and complete.
    time.sleep(2.0)
    ser = serial.Serial(port, baudrate=baud, timeout=max(timeout_s, 5.0))
    try:

        def cmd2(line: str) -> str:
            ser.write((line + "\n").encode("ascii"))
            ser.flush()
            resp = ser.readline().decode("utf-8", errors="replace").strip()
            steps.append({"cmd": line, "resp": resp})
            if resp.startswith("ERR "):
                raise RuntimeError(f"target error for {line}: {resp}")
            return resp

        # Drain READY
        deadline = time.time() + 15.0
        ready2 = ""
        while time.time() < deadline:
            line = ser.readline().decode("utf-8", errors="replace").strip()
            if line:
                steps.append({"cmd": "(banner2)", "resp": line})
                if line.startswith("READY"):
                    ready2 = line
                    break
        if not ready2:
            raise RuntimeError("no READY after reboot")
        m2 = re.search(r"boot_id=([0-9a-fA-F]{32})", ready2)
        if not m2:
            bi = cmd2("BOOT_IDENTITY")
            _require_ok(bi, "OK boot_identity", steps)
            m2 = re.search(r"boot_id=([0-9a-fA-F]{32})", bi)
        if not m2:
            raise RuntimeError("cannot parse boot_id after reboot")
        boot_b = m2.group(1).lower()
        clf = classify_two_boot(boot_a, boot_b, fence or "0")
        if not clf.get("ok"):
            raise RuntimeError(f"two-boot classification failed: {clf}")
        r = cmd2(f"COMPLETE_TWO_BOOT {boot_a}")
        _require_ok(r, "OK complete_two_boot", steps)
        if "class=old/new/fenced" not in r:
            raise RuntimeError(f"complete missing classification: {r}")
        if "reconstruct=fresh_authority" not in r:
            raise RuntimeError(f"complete missing reconstruct: {r}")
        claims = base_claims()
        claims["physical_two_boot_recovery"] = True
        claims["same_session_pcp_recover"] = False
        claims["restart_recovery_protocol"] = False
        claims["physical_powercut_pass"] = False
        return {
            "physical_status": "DEVICE_TWO_BOOT_OK",
            "steps": steps,
            "classification": clf,
            "claims": claims,
            "note": (
                "Software reboot two-boot recovery only. "
                "physical_powercut_pass remains false. "
                "RF / legal nonclaims hold."
            ),
        }
    finally:
        ser.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "cmd",
        choices=(
            "probe",
            "run",
            "two-boot-run",
            "pair-run",
            "not-run-evidence",
            "self-test",
        ),
        help=(
            "probe/run: device protocol; two-boot-run: real reboot recovery; "
            "pair-run: bidirectional raw RF HIL using two boards; "
            "not-run-evidence: seal NOT_RUN; self-test: host checks"
        ),
    )
    ap.add_argument(
        "--port", default=None, help="serial device e.g. /dev/cu.usbserial-*"
    )
    ap.add_argument(
        "--peer-port",
        default=None,
        help="second serial device for pair-run",
    )
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--count", type=int, default=1)
    ap.add_argument("--interval-ms", type=int, default=100)
    ap.add_argument("--payload-bytes", type=int, default=32)
    ap.add_argument(
        "--out-json",
        type=pathlib.Path,
        default=ROOT
        / "ports/esp-idf/radio_hil_app/build/ninlil_radio_hil_physical.json",
    )
    args = ap.parse_args()

    if args.cmd == "self-test":
        self_test()
        return

    base = base_payload()

    if args.cmd == "not-run-evidence":
        payload = {
            **base,
            "physical_status": "NOT_RUN",
            "reason": "no device connected / protocol not executed",
            "executable_protocol": (
                "tools/sx1262_radio_hil_protocol.py run --port <dev>"
            ),
            "executable_two_boot_protocol": (
                "tools/sx1262_radio_hil_protocol.py two-boot-run --port <dev>"
            ),
            "executable_pair_protocol": (
                "tools/sx1262_radio_hil_protocol.py pair-run "
                "--port <first-dev> --peer-port <second-dev>"
            ),
            "same_session_command": "PCP_RECOVER_SAME_SESSION",
            "physical_two_boot_recovery": False,
            "physical_powercut_pass": False,
            "restart_recovery_protocol": False,
        }
        payload["claims"]["same_session_pcp_recover"] = False
        payload["claims"]["physical_two_boot_recovery"] = False
        payload["claims"]["restart_recovery_protocol"] = False
        write_evidence(args.out_json, payload)
        print(
            "sx1262_radio_hil_protocol: NOT_RUN evidence sealed "
            "(two-boot + power-cut unproven)"
        )
        return

    if args.cmd == "probe":
        status, detail = probe_port(args.port, args.baud)
        payload = {
            **base,
            "physical_status": status,
            "detail": detail,
            "port": args.port,
        }
        write_evidence(args.out_json, payload)
        print(f"sx1262_radio_hil_protocol: probe {status}")
        return

    if args.cmd == "pair-run":
        if not args.port or not args.peer_port:
            payload = {
                **base,
                "physical_status": "NOT_RUN",
                "reason": "pair-run requires --port and --peer-port",
            }
            write_evidence(args.out_json, payload)
            print("sx1262_radio_hil_protocol: NOT_RUN (two ports required)")
            raise SystemExit(0)
        try:
            result = run_pair(
                args.port,
                args.peer_port,
                args.baud,
                args.timeout,
                args.count,
                args.interval_ms,
                args.payload_bytes,
            )
        except Exception as exc:  # noqa: BLE001
            payload = {
                **base,
                "physical_status": "FAIL",
                "error": str(exc),
                "ports": [args.port, args.peer_port],
            }
            write_evidence(args.out_json, payload)
            print(f"sx1262_radio_hil_protocol: FAIL: {exc}", file=sys.stderr)
            raise SystemExit(1)
        payload = {**base, **result}
        merged = base_claims()
        merged.update(result["claims"])
        payload["claims"] = merged
        write_evidence(args.out_json, payload)
        print("sx1262_radio_hil_protocol: DEVICE_RF_PAIR_OK")
        return

    if args.cmd in ("run", "two-boot-run"):
        if not args.port:
            payload = {
                **base,
                "physical_status": "NOT_RUN",
                "reason": f"{args.cmd} requested without --port",
            }
            write_evidence(args.out_json, payload)
            print("sx1262_radio_hil_protocol: NOT_RUN (no port)")
            raise SystemExit(0)
        status, detail = probe_port(args.port, args.baud)
        if status == "NOT_RUN":
            payload = {
                **base,
                "physical_status": "NOT_RUN",
                "reason": detail,
                "port": args.port,
            }
            write_evidence(args.out_json, payload)
            print("sx1262_radio_hil_protocol: NOT_RUN")
            raise SystemExit(0)
        try:
            if args.cmd == "run":
                result = run_protocol(args.port, args.baud, args.timeout)
            else:
                result = run_two_boot(args.port, args.baud, args.timeout)
        except Exception as exc:  # noqa: BLE001
            payload = {
                **base,
                "physical_status": "FAIL",
                "error": str(exc),
                "port": args.port,
            }
            write_evidence(args.out_json, payload)
            print(f"sx1262_radio_hil_protocol: FAIL: {exc}", file=sys.stderr)
            raise SystemExit(1)
        payload = {**base, **result, "port": args.port}
        # Merge claims carefully
        if "claims" in result:
            merged = base_claims()
            merged.update(result["claims"])
            payload["claims"] = merged
        write_evidence(args.out_json, payload)
        if payload.get("physical_status") == "FAIL":
            print("sx1262_radio_hil_protocol: FAIL", file=sys.stderr)
            raise SystemExit(1)
        print(f"sx1262_radio_hil_protocol: {payload.get('physical_status')}")
        return

    fail("unreachable")


if __name__ == "__main__":
    main()
