#!/usr/bin/env python3
"""V1-LAB item 10b integration gate structural check."""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]

BYPASS_SYMBOL = "ninlil_c6_lab_spi_tx_bypass_direct"
INTEGRATION_TEST = REPO / "tests" / "runtime" / "v1_integration_gate_e2e_test.c"
TOPOLOGY_C = REPO / "tests" / "support" / "v1_lab_integration_topology.c"
PRIVATE = REPO / "cmake" / "ninlil_runtime_private_sources.cmake"
SPI_C = REPO / "src" / "radio" / "c6_lab_spi_tx_sim.c"

PRODUCTION_SOURCES_ALLOW_BYPASS = (
    "src/radio/c6_lab_spi_tx_sim.c",
    "src/radio/c6_lab_spi_tx_sim.h",
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def read(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path}")
    return path.read_text(encoding="utf-8")


def strip_c_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//.*?$", "", text, flags=re.M)
    return text


def count_calls(code: str, symbol: str) -> int:
    return len(re.findall(r"\b" + re.escape(symbol) + r"\s*\(", code))


def check_bypass_hygiene() -> None:
    auth = read(PRIVATE)
    sources = re.findall(
        r"^\s*((?:src|ports)/[A-Za-z0-9_./-]+\.c)\s*$",
        auth,
        re.M,
    )
    for rel in sources:
        path = REPO / rel
        if not path.is_file():
            continue
        code = strip_c_comments(path.read_text(encoding="utf-8"))
        if BYPASS_SYMBOL not in code:
            continue
        if rel not in PRODUCTION_SOURCES_ALLOW_BYPASS:
            fail(f"bypass symbol in production source: {rel}")


def check_integration_test_absent_bypass() -> None:
    for rel in (
        "tests/runtime/v1_integration_gate_e2e_test.c",
        "tests/support/v1_lab_integration_topology.c",
    ):
        code = strip_c_comments(read(REPO / rel))
        if count_calls(code, BYPASS_SYMBOL) > 0:
            fail(f"integration gate must not call bypass symbol: {rel}")


def check_ctest_registration() -> None:
    cmake = read(REPO / "cmake" / "ninlil_v1_integration_gate_ctest.cmake")
    root = read(REPO / "CMakeLists.txt")
    if "v1_integration_gate_e2e" not in cmake:
        fail("missing v1_integration_gate_e2e test registration")
    if "ninlil_v1_integration_gate_register_tests" not in root:
        fail("CMakeLists must call ninlil_v1_integration_gate_register_tests")


def check() -> None:
    check_bypass_hygiene()
    check_integration_test_absent_bypass()
    check_ctest_registration()
    spi = strip_c_comments(read(SPI_C))
    if BYPASS_SYMBOL not in spi:
        fail("missing bypass symbol definition in spi sim")
    print("v1_integration_gate structural check ok")
    print(f"bypass_symbol={BYPASS_SYMBOL}")
    print(f"production_call_sites_outside_allowlist=0")


def main() -> int:
    try:
        if len(sys.argv) < 2 or sys.argv[1] != "check":
            fail("usage: v1_integration_gate.py check")
        check()
        return 0
    except GateFailure as exc:
        print(f"v1_integration_gate FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
