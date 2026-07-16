#!/usr/bin/env python3
"""Strict serial/power runner for Ninlil ESP32-S3 storage power-cut HIL.

Requires pyserial and externally supplied argv-array power/reset commands. The
runner never marks HIL attested; archived hardware evidence remains a release
input reviewed outside this program.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import threading
import time


SCENARIO_EVENTS = {
    "D0": "DIR_BEFORE_ERASE",
    "D1": "DIR_BEFORE_WRITE",
    "D2": "DIR_BEFORE_SEAL",
    "S0": "DATA_BEFORE_ERASE",
    "S1": "DATA_BEFORE_WRITE",
    "S2": "DATA_AFTER_SYNC_BEFORE_RETURN",
}
SNAPSHOT_DOMAIN = b"NINLIL-HIL-SNAPSHOT-V1"
DIRECTORY_DOMAIN = b"NINLIL-HIL-DIRECTORY-V1"
HEX256_RE = re.compile(r"^[0-9a-f]{64}$")
READY_RE = re.compile(
    r"^HIL_READY format=4 policy=ESP_UNPROVEN protocol=3 "
    r"boot_nonce=([0-9a-fA-F]{16}) reset_reason=([0-9]+)$"
)
MAX_DELAY_MS = 5000.0
MAX_BOOT_SECONDS = 120.0
MIN_BAUD = 1200
MAX_BAUD = 4_000_000
COMMAND_TIMEOUT_SECONDS = 30.0
# S2 holds the target after durable sync for 10 seconds. With the maximum
# 5-second delay, bounding the relay command below 4 seconds keeps an attempted
# cut inside that target-side observation window (with scheduling margin).
POWER_OFF_TIMEOUT_SECONDS = 4.0


def wait_line(port: object, needle: str, timeout: float) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = port.readline().decode("utf-8", errors="replace").strip()
        if line:
            print(line, flush=True)
        if needle in line:
            return line
    raise TimeoutError(f"timeout waiting for {needle!r}")


def parse_ready(line: str) -> tuple[int, int]:
    matched = READY_RE.fullmatch(line)
    if matched is None:
        raise ValueError(f"malformed HIL_READY: {line!r}")
    nonce = int(matched.group(1), 16)
    reason = int(matched.group(2), 10)
    if nonce == 0 or reason < 0:
        raise ValueError("HIL_READY boot identity must be non-zero/canonical")
    return nonce, reason


def parse_argv(raw: str) -> list[str]:
    value = json.loads(raw)
    if not isinstance(value, list) or not value:
        raise ValueError("command must be a non-empty JSON argv array")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError("every command argv item must be a non-empty string")
    return value


def checked_float(name: str, value: float, maximum: float) -> float:
    if not math.isfinite(value) or value < 0.0 or value > maximum:
        raise ValueError(f"{name} must be finite and in [0, {maximum}]")
    return value


def checked_baud(value: int) -> int:
    if value < MIN_BAUD or value > MAX_BAUD:
        raise ValueError(f"baud must be in [{MIN_BAUD}, {MAX_BAUD}]")
    return value


def canonical_record(key: bytes, value: bytes) -> bytes:
    return (
        len(key).to_bytes(2, "big")
        + key
        + len(value).to_bytes(4, "big")
        + value
    )


def expected_data_digest(state: str) -> str:
    if state == "OLD":
        records = ((b"a", b"old-A"), (b"b", b"old-B"))
    elif state == "NEW":
        records = ((b"a", b"new-A-long"), (b"c", b"new-C"))
    else:
        raise ValueError(f"unknown snapshot state: {state!r}")
    canonical = SNAPSHOT_DOMAIN + bytes((len(records),))
    canonical += b"".join(canonical_record(key, value) for key, value in records)
    return hashlib.sha256(canonical).hexdigest()


def expected_digest(scenario: str, state: str) -> str:
    if scenario.startswith("S"):
        return expected_data_digest(state)
    if scenario.startswith("D"):
        canonical = (
            DIRECTORY_DOMAIN
            + scenario.encode("ascii")
            + bytes((1 if state == "OLD" else 2,))
            + bytes.fromhex(expected_data_digest("OLD"))
        )
        return hashlib.sha256(canonical).hexdigest()
    raise ValueError(f"unknown scenario: {scenario!r}")


def parse_boundary(line: str, scenario: str, expected_event: str) -> None:
    parts = line.split()
    expected = ["HIL_BOUNDARY", scenario, expected_event]
    if parts != expected:
        raise ValueError(
            f"malformed/wrong boundary: got {parts!r}, expected {expected!r}"
        )


def continue_command(scenario: str, expected_event: str) -> bytes:
    if SCENARIO_EVENTS.get(scenario) != expected_event:
        raise ValueError("cannot continue a mismatched scenario/event")
    return f"CONTINUE {scenario} {expected_event}\n".encode("ascii")


def delayed_power_off(
    argv: list[str],
    delay_seconds: float,
    armed: threading.Event,
    release: threading.Event,
    attempted: threading.Event,
    errors: list[BaseException],
    run_command: object = subprocess.run,
) -> None:
    try:
        armed.set()
        if not release.wait(timeout=5.0):
            raise TimeoutError("power-cut timer was armed but never released")
        deadline = time.monotonic() + delay_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.0:
                break
            time.sleep(min(remaining, 0.05))
        attempted.set()
        run_command(
            argv,
            shell=False,
            check=True,
            timeout=POWER_OFF_TIMEOUT_SECONDS,
        )
    except BaseException as error:
        errors.append(error)


def parse_baseline(line: str) -> str:
    parts = line.split()
    if len(parts) != 4 or parts[0:2] != ["HIL_BASELINE", "OLD"]:
        raise ValueError(f"malformed baseline: {line!r}")
    if parts[3] != "COMMIT_UNKNOWN" or not HEX256_RE.fullmatch(parts[2]):
        raise ValueError(f"invalid baseline proof: {line!r}")
    expected = expected_data_digest("OLD")
    if parts[2] != expected:
        raise ValueError(
            f"wrong baseline digest: got {parts[2]!r}, expected {expected!r}"
        )
    return parts[2]


def parse_result(
    line: str, scenario: str, expected_event: str
) -> tuple[str, str]:
    parts = line.split()
    if (
        len(parts) != 5
        or parts[0] != "HIL_RESULT"
        or parts[1] != scenario
        or parts[2] != expected_event
    ):
        raise ValueError(f"malformed or wrong-scenario/event result: {line!r}")
    state, digest = parts[3], parts[4]
    if state not in ("OLD", "NEW"):
        raise ValueError(f"non-atomic recovery result: {line!r}")
    if not HEX256_RE.fullmatch(digest):
        raise ValueError(f"invalid snapshot digest: {line!r}")
    expected = expected_digest(scenario, state)
    if digest != expected:
        raise ValueError(
            f"snapshot digest mismatch: got {digest!r}, expected {expected!r}"
        )
    return state, digest


def self_test() -> None:
    assert parse_argv('["relay", "off"]') == ["relay", "off"]
    for bad in ("[]", '"relay off"', '["relay", ""]'):
        try:
            parse_argv(bad)
        except (ValueError, json.JSONDecodeError):
            pass
        else:
            raise AssertionError(f"accepted bad argv: {bad}")

    for value in (0.0, 1.5, MAX_DELAY_MS):
        assert checked_float("delay-ms", value, MAX_DELAY_MS) == value
    for bad in (-1.0, math.inf, -math.inf, math.nan, MAX_DELAY_MS + 0.1):
        try:
            checked_float("delay-ms", bad, MAX_DELAY_MS)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted bad float: {bad}")
    assert checked_baud(115200) == 115200
    for bad in (MIN_BAUD - 1, MAX_BAUD + 1):
        try:
            checked_baud(bad)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted bad baud: {bad}")

    assert parse_ready(
        "HIL_READY format=4 policy=ESP_UNPROVEN protocol=3 "
        "boot_nonce=012345671234abcd reset_reason=1"
    ) == (0x012345671234ABCD, 1)
    old_digest = expected_data_digest("OLD")
    new_digest = expected_data_digest("NEW")
    assert old_digest != new_digest
    assert parse_baseline(
        f"HIL_BASELINE OLD {old_digest} COMMIT_UNKNOWN"
    ) == old_digest
    parse_boundary("HIL_BOUNDARY S1 DATA_BEFORE_WRITE", "S1", "DATA_BEFORE_WRITE")
    assert continue_command("S1", "DATA_BEFORE_WRITE") == (
        b"CONTINUE S1 DATA_BEFORE_WRITE\n"
    )
    try:
        continue_command("S1", "DATA_BEFORE_ERASE")
    except ValueError:
        pass
    else:
        raise AssertionError("accepted mismatched CONTINUE")
    assert parse_result(
        f"HIL_RESULT S1 DATA_BEFORE_WRITE OLD {old_digest}",
        "S1",
        "DATA_BEFORE_WRITE",
    ) == ("OLD", old_digest)
    assert parse_result(
        f"HIL_RESULT S1 DATA_BEFORE_WRITE NEW {new_digest}",
        "S1",
        "DATA_BEFORE_WRITE",
    ) == ("NEW", new_digest)

    bad_boundaries = (
        "HIL_BOUNDARY S2 DATA_BEFORE_WRITE",
        "HIL_BOUNDARY S1 DATA_BEFORE_ERASE",
        "HIL_BOUNDARY S1 DATA_BEFORE_WRITE trailing",
    )
    for bad in bad_boundaries:
        try:
            parse_boundary(bad, "S1", "DATA_BEFORE_WRITE")
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted bad boundary: {bad}")

    bad_results = (
        f"HIL_RESULT S2 DATA_BEFORE_WRITE OLD {old_digest}",
        f"HIL_RESULT S1 DATA_BEFORE_ERASE OLD {old_digest}",
        "HIL_RESULT S1 DATA_BEFORE_WRITE INVALID -",
        f"HIL_RESULT S1 DATA_BEFORE_WRITE OLD {new_digest}",
        f"HIL_RESULT S1 DATA_BEFORE_WRITE OLD {old_digest} trailing",
    )
    for bad in bad_results:
        try:
            parse_result(bad, "S1", "DATA_BEFORE_WRITE")
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted bad result: {bad}")

    # The power command must not execute merely because the worker exists. It
    # may execute only after the main serial path releases the timer immediately
    # before sending CONTINUE to the target.
    timer_armed = threading.Event()
    timer_release = threading.Event()
    attempted = threading.Event()
    timer_errors: list[BaseException] = []
    command_called = threading.Event()

    def fake_run(
        argv: list[str], *, shell: bool, check: bool, timeout: float
    ) -> None:
        assert argv == ["fake-relay", "off"]
        assert shell is False
        assert check is True
        assert timeout == POWER_OFF_TIMEOUT_SECONDS
        command_called.set()

    timer_thread = threading.Thread(
        target=delayed_power_off,
        args=(
            ["fake-relay", "off"],
            0.0,
            timer_armed,
            timer_release,
            attempted,
            timer_errors,
            fake_run,
        ),
    )
    timer_thread.start()
    assert timer_armed.wait(timeout=1.0)
    assert not command_called.wait(timeout=0.05)
    assert not attempted.is_set()
    timer_release.set()
    timer_thread.join(timeout=1.0)
    assert not timer_thread.is_alive()
    assert attempted.is_set()
    assert command_called.is_set()
    assert not timer_errors
    print("host_powercut_runner self-test OK")


def main() -> None:
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        return

    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True)
    parser.add_argument("--scenario", required=True, choices=tuple(SCENARIO_EVENTS))
    parser.add_argument("--delay-ms", required=True, type=float)
    parser.add_argument("--power-off-json", required=True)
    parser.add_argument("--power-on-json", required=True)
    parser.add_argument(
        "--prepare-json",
        required=True,
        help="JSON argv that erases/resets the HIL partition before every atomic run",
    )
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--boot-seconds", type=float, default=3.0)
    args = parser.parse_args()

    try:
        args.delay_ms = checked_float("delay-ms", args.delay_ms, MAX_DELAY_MS)
        args.boot_seconds = checked_float(
            "boot-seconds", args.boot_seconds, MAX_BOOT_SECONDS
        )
        args.baud = checked_baud(args.baud)
        power_off = parse_argv(args.power_off_json)
        power_on = parse_argv(args.power_on_json)
        prepare = parse_argv(args.prepare_json)
    except (ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))

    try:
        import serial  # type: ignore[import-not-found]
    except ModuleNotFoundError:
        parser.error(
            "pyserial is required for hardware execution "
            "(python3 -m pip install pyserial)"
        )

    expected_event = SCENARIO_EVENTS[args.scenario]
    subprocess.run(
        prepare,
        shell=False,
        check=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
    )

    power_off_attempted = threading.Event()
    timer_armed = threading.Event()
    timer_release = threading.Event()
    timer_errors: list[BaseException] = []
    power_thread: threading.Thread | None = None
    try:
        with serial.Serial(args.port, args.baud, timeout=0.2) as port:
            first_boot, _ = parse_ready(wait_line(port, "HIL_READY", 15.0))
            port.write(b"BASELINE\n")
            baseline = wait_line(port, "HIL_BASELINE", 20.0)
            parse_baseline(baseline)
            port.write(f"ARM {args.scenario}\n".encode())
            boundary = wait_line(port, "HIL_BOUNDARY", 20.0)
            parse_boundary(boundary, args.scenario, expected_event)
            power_thread = threading.Thread(
                target=delayed_power_off,
                args=(
                    power_off,
                    args.delay_ms / 1000.0,
                    timer_armed,
                    timer_release,
                    power_off_attempted,
                    timer_errors,
                ),
                name="ninlil-hil-powercut",
                daemon=False,
            )
            power_thread.start()
            if not timer_armed.wait(timeout=5.0):
                raise TimeoutError("power-cut timer failed to arm")
            # Start the host-side delay clock immediately before releasing the
            # target. delay=0 may therefore cut before the target flash call;
            # positive sweeps cross the call instead of starting too late.
            timer_release.set()
            port.write(continue_command(args.scenario, expected_event))
            port.flush()
            power_thread.join(timeout=MAX_DELAY_MS / 1000.0 + 30.0)
            if power_thread.is_alive():
                raise TimeoutError("power-off command did not finish")
            if timer_errors:
                raise timer_errors[0]
            time.sleep(1.0)
    finally:
        timer_release.set()
        if power_thread is not None and power_thread.is_alive():
            power_thread.join(timeout=5.0)
        if power_off_attempted.is_set():
            subprocess.run(
                power_on,
                shell=False,
                check=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
            )

    time.sleep(args.boot_seconds)
    with serial.Serial(args.port, args.baud, timeout=0.2) as port:
        second_boot, _ = parse_ready(wait_line(port, "HIL_READY", 15.0))
        if second_boot == first_boot:
            raise RuntimeError(
                "boot nonce did not change; reset/power fixture is unproven"
            )
        port.write(f"VERIFY {args.scenario}\n".encode())
        result = wait_line(port, "HIL_RESULT", 20.0)
        state, digest = parse_result(
            result, args.scenario, expected_event
        )
        print(
            f"HIL PASS scenario={args.scenario} event={expected_event} "
            f"delay_ms={args.delay_ms} state={state} digest={digest}"
        )


if __name__ == "__main__":
    main()
