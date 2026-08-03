#!/usr/bin/env python3
"""Verify the compact radio body's exact NRW1 byte and R3 airtime budget."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from airtime_r3_oracle import Input, LDRO_OFF, OK, compute


ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "src/transport/fabric_v1/nra1_codec.h"
WIRE_HEADER = ROOT / "src/radio/r7_wire_codec.h"
WINDOW_SUBMISSIONS = 10
WINDOW_AIRTIME_LIMIT_US = 6_000_000


class GateError(RuntimeError):
    pass


def define_size(text: str, name: str) -> int:
    match = re.search(
        rf"^#define\s+{re.escape(name)}\s+\(\(size_t\)(\d+)u\)"
        r"(?:\s*/\*.*\*/)?\s*$",
        text,
        re.MULTILINE,
    )
    if match is None:
        raise GateError(f"missing exact size macro {name}")
    return int(match.group(1))


def airtime(payload_bytes: int) -> int:
    result = compute(
        Input(
            sf=7,
            cr=1,
            header_implicit=0,
            crc_on=1,
            ldro=LDRO_OFF,
            payload_len_bytes=payload_bytes,
            preamble_len_symbols=8,
            bw_hz=125000,
            reserved_zero=0,
        )
    )
    if result.status != OK:
        raise GateError(f"R3 rejected payload length {payload_bytes}")
    return result.airtime_us


def check() -> None:
    text = HEADER.read_text(encoding="utf-8")
    wire_text = WIRE_HEADER.read_text(encoding="utf-8")
    app_header = define_size(text, "NINLIL_NRA1_APPLICATION_HEADER_BYTES")
    app_min = define_size(text, "NINLIL_NRA1_APPLICATION_PAYLOAD_MIN")
    app_max = define_size(text, "NINLIL_NRA1_APPLICATION_PAYLOAD_MAX")
    body_min = define_size(text, "NINLIL_NRA1_APPLICATION_BODY_MIN")
    body_max = define_size(text, "NINLIL_NRA1_APPLICATION_BODY_MAX")
    receipt_body = define_size(text, "NINLIL_NRA1_RECEIPT_BODY_BYTES")
    wire_app_max = define_size(wire_text, "NINLIL_R7_WIRE_APP_MAX")
    wire_frame_min = define_size(wire_text, "NINLIL_R7_WIRE_FRAME_MIN")
    wire_frame_max = define_size(wire_text, "NINLIL_R7_WIRE_FRAME_MAX")
    nrw1_overhead = wire_frame_max - wire_app_max

    if (app_header, app_min, app_max, body_min, body_max, receipt_body) != (
        62,
        1,
        128,
        63,
        190,
        46,
    ):
        raise GateError("compact body constants drifted")
    if body_min != app_header + app_min or body_max != app_header + app_max:
        raise GateError("application body arithmetic")
    if body_max > wire_app_max:
        raise GateError("application body exceeds NRW1 SINGLE plaintext")
    if nrw1_overhead != 65 or wire_frame_min != nrw1_overhead + 1:
        raise GateError("NRW1 SINGLE overhead constants drifted")

    cases = {
        "application_1": (body_min + nrw1_overhead, 215_296),
        "application_32": (app_header + 32 + nrw1_overhead, 256_256),
        "application_128": (body_max + nrw1_overhead, 399_616),
        "receipt": (receipt_body + nrw1_overhead, 189_696),
    }
    for name, (frame_bytes, expected_us) in cases.items():
        if frame_bytes > 255:
            raise GateError(f"{name}: NRW1 frame exceeds SX1262 packet")
        actual_us = airtime(frame_bytes)
        if actual_us != expected_us:
            raise GateError(f"{name}: airtime {actual_us} != {expected_us}")

    worst_pair = cases["application_128"][1] + cases["receipt"][1]
    hil_pair = cases["application_32"][1] + cases["receipt"][1]
    if worst_pair != 589_312:
        raise GateError("worst request/receipt pair drifted")
    if worst_pair * WINDOW_SUBMISSIONS > WINDOW_AIRTIME_LIMIT_US:
        raise GateError("ten worst-case pairs exceed the six-second budget")
    if hil_pair * WINDOW_SUBMISSIONS != 4_459_520:
        raise GateError("32-byte HIL schedule drifted")

    print(
        "nra1 mapping gate passed: "
        f"worst_10={worst_pair * WINDOW_SUBMISSIONS}us "
        f"hil_10={hil_pair * WINDOW_SUBMISSIONS}us"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check",))
    parser.parse_args()
    try:
        check()
    except (GateError, OSError, UnicodeError) as exc:
        print(f"nra1 mapping gate failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
