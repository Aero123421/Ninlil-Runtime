#!/usr/bin/env python3
"""C6-LAB enforcement structural gate (V1 item 10a).

Checks frame manifest exact-set, sole-edge R5->R2->R1->R9 markers,
bypass symbol hygiene, and LAB_ONLY nonclaims. Does not claim RF/HIL/legal.
"""

from __future__ import annotations

import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]

MANIFEST_H = REPO / "src" / "radio" / "v1_frame_manifest.h"
MANIFEST_C = REPO / "src" / "radio" / "v1_frame_manifest.c"
ENF_H = REPO / "src" / "radio" / "c6_lab_enforcement.h"
ENF_C = REPO / "src" / "radio" / "c6_lab_enforcement.c"
SPI_C = REPO / "src" / "radio" / "c6_lab_spi_tx_sim.c"
TEST_C = REPO / "tests" / "radio" / "c6_lab_enforcement_test.c"
DOC_MANIFEST = REPO / "docs" / "work" / "2026-07-23-v1-frame-manifest.md"
DOC05 = REPO / "docs" / "05-security-and-compliance.md"
DOC09 = REPO / "docs" / "09-roadmap.md"
CMAKE = REPO / "cmake" / "ninlil_c6_lab_ctest.cmake"
CMAKELISTS = REPO / "CMakeLists.txt"
PRIVATE = REPO / "cmake" / "ninlil_runtime_private_sources.cmake"

BYPASS_SYMBOL = "ninlil_c6_lab_spi_tx_bypass_direct"
SOLE_TX = "ninlil_radio_hal_transmit_with_permit"
C6_TRANSMIT = "ninlil_c6_lab_transmit"
SPI_EDGE = "ninlil_c6_lab_spi_tx_sim_edge"
SOLE_MARKER = "C6_LAB_SOLE_EDGE_R5_R2_R1_R9"

EXPECTED_FRAME_TYPES = (
    "NINLIL_V1_FRAME_M4_JOIN_REQUEST",
    "NINLIL_V1_FRAME_M4_JOIN_CHALLENGE",
    "NINLIL_V1_FRAME_M4_JOIN_RESPONSE",
    "NINLIL_V1_FRAME_M4_JOIN_INSTALL",
    "NINLIL_V1_FRAME_M4_JOIN_REJECT",
    "NINLIL_V1_FRAME_R7_HOP_DATA",
    "NINLIL_V1_FRAME_R7_HOP_ACK",
)

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


def check_manifest() -> None:
    hdr = read(MANIFEST_H)
    src = read(MANIFEST_C)
    doc = read(DOC_MANIFEST)
    if "NINLIL_V1_FRAME_MANIFEST_COUNT" not in hdr:
        fail("manifest header missing COUNT")
    m = re.search(
        r"#define\s+NINLIL_V1_FRAME_MANIFEST_COUNT\s+\(\(uint32_t\)(\d+)u\)",
        hdr,
    )
    if not m:
        fail("manifest COUNT macro malformed")
    count = int(m.group(1))
    if count != len(EXPECTED_FRAME_TYPES):
        fail(f"manifest count {count} != expected {len(EXPECTED_FRAME_TYPES)}")
    for tok in EXPECTED_FRAME_TYPES:
        if tok not in hdr or tok not in src:
            fail(f"manifest missing frame type token: {tok}")
        if tok not in doc:
            fail(f"manifest doc missing frame type: {tok}")
    if "beacon" in doc.lower() and "V2" not in doc and "除外" not in doc:
        fail("manifest doc must exclude beacon for V1")
    if "国内実運用" not in doc and "LAB_ONLY" not in doc:
        fail("manifest doc must state LAB_ONLY scope")


def check_enforcement() -> None:
    hdr = read(ENF_H)
    src = read(ENF_C)
    for tok in (
        "SEMANTIC: C6_LAB_HOST_CANDIDATE_ONLY",
        "SEMANTIC: LAB_ONLY_FAIL_CLOSED",
        "SEMANTIC: SOLE_EDGE_R5_R2_R1_R9",
        "SEMANTIC: NO_JAPAN_PRODUCTION_CLAIM",
        C6_TRANSMIT,
        "ninlil_v1_frame_type_is_transmittable",
        "ninlil_r5_issue",
        SOLE_TX,
    ):
        if tok not in hdr and tok not in src:
            fail(f"enforcement missing token: {tok}")
    if SOLE_MARKER not in src:
        fail("missing sole-edge marker in enforcement.c")
    code = strip_c_comments(src)
    if count_calls(code, SOLE_TX) != 1:
        fail("enforcement.c must call transmit_with_permit exactly once")
    if count_calls(code, SPI_EDGE) != 0:
        fail("enforcement.c must not call spi edge directly (HAL binds it)")


def check_spi_sim() -> None:
    spi = read(SPI_C)
    code = strip_c_comments(spi)
    if count_calls(code, SPI_EDGE) != 1:
        fail("spi sim must define edge callback once")
    if BYPASS_SYMBOL not in spi:
        fail("missing bypass symbol definition")


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


def check_tests() -> None:
    test = read(TEST_C)
    for name in (
        "test_manifest_exact_set",
        "test_happy_transmit_all_manifest_types",
        "test_out_of_scope_profile_spi_tx_zero",
        "test_expired_assignment_spi_tx_zero",
        "test_clock_uncertainty_spi_tx_zero",
        "test_permit_failure_spi_tx_zero",
        "test_unknown_frame_type_spi_tx_zero",
        "test_bypass_symbol_not_authorized_path",
        BYPASS_SYMBOL,
    ):
        if name not in test:
            fail(f"c6 test missing: {name}")


def check_docs() -> None:
    d05 = read(DOC05)
    d09 = read(DOC09)
    if "国内実運用可能" not in d05 and "国内実運用" not in d05:
        fail("docs/05 must state domestic production nonclaim")
    if "LAB_ONLY" not in d05:
        fail("docs/05 must mention LAB_ONLY")
    if "国内実運用可能" not in d09:
        fail("docs/09 must state domestic production nonclaim")


def check_cmake() -> None:
    cmake = read(CMAKE)
    lists = read(CMAKELISTS)
    if "c6_lab_enforcement" not in cmake:
        fail("c6 cmake must register enforcement test")
    if "ninlil_c6_lab_ctest.cmake" not in lists:
        fail("CMakeLists must include c6_lab cmake")
    if "c6_lab_enforcement_gate" not in lists:
        fail("CMakeLists must register c6_lab_enforcement_gate")


def check(root: pathlib.Path | None = None) -> None:
    global MANIFEST_H, MANIFEST_C, ENF_H, ENF_C, SPI_C, TEST_C
    global DOC_MANIFEST, DOC05, DOC09, CMAKE, CMAKELISTS, PRIVATE
    if root is not None:
        MANIFEST_H = root / "src" / "radio" / "v1_frame_manifest.h"
        MANIFEST_C = root / "src" / "radio" / "v1_frame_manifest.c"
        ENF_H = root / "src" / "radio" / "c6_lab_enforcement.h"
        ENF_C = root / "src" / "radio" / "c6_lab_enforcement.c"
        SPI_C = root / "src" / "radio" / "c6_lab_spi_tx_sim.c"
        TEST_C = root / "tests" / "radio" / "c6_lab_enforcement_test.c"
        DOC_MANIFEST = root / "docs" / "work" / "2026-07-23-v1-frame-manifest.md"
        DOC05 = root / "docs" / "05-security-and-compliance.md"
        DOC09 = root / "docs" / "09-roadmap.md"
        CMAKE = root / "cmake" / "ninlil_c6_lab_ctest.cmake"
        CMAKELISTS = root / "CMakeLists.txt"
        PRIVATE = root / "cmake" / "ninlil_runtime_private_sources.cmake"
    check_manifest()
    check_enforcement()
    check_spi_sim()
    check_bypass_hygiene()
    check_tests()
    check_docs()
    check_cmake()
    print("c6_lab_enforcement_gate: OK")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("check",):
        print("usage: c6_lab_enforcement_gate.py check", file=sys.stderr)
        return 2
    try:
        check()
    except GateFailure as exc:
        print(f"c6_lab_enforcement_gate FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
