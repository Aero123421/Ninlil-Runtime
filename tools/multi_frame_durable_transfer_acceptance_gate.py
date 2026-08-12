#!/usr/bin/env python3
"""Independent manifest gate for the ADR-0021 accepted baseline and amendment.

Binds baseline and amendment work-record status, ADR accepted language, artifact digests,
exactly four authority tool systems, and the dedicated MFDT CMake authority
surface (not whole-repo CMakeLists.txt).

CMake authority design:
  - Live inventory is extracted from cmake/ninlil_mfdt_ctest.cmake only.
  - cmake/ninlil_ctest.cmake is checked for the include of that dedicated file;
    root CMakeLists.txt is checked only for the tests-ON umbrella include.
    Neither shared file's whole-file SHA is pinned.
  - Unrelated legitimate CMakeLists edits must not invalidate MFDT.

Does not claim implementation completion or release support. Does not import the vector generator.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

# ---- Hard-pinned acceptance authority (not learned from mutable work body) -

PINNED_BASELINE_WORK_STATUS_TOKEN = "SPEC_ACCEPTED design authority"
PINNED_AMENDMENT_WORK_STATUS_TOKEN = (
    "SPEC_ACCEPTED — specification repair complete; implementation remains incomplete"
)
PINNED_VECTOR_STATUS = "SPEC_ACCEPTED"
PINNED_ADR_TOKEN = "Accepted baseline / Application-handoff amendment SPEC_ACCEPTED"

PINNED_AUTHORITY_TOOLS: tuple[tuple[str, str], ...] = (
    ("generator", "tools/multi_frame_durable_transfer_spec_vector_gen.py"),
    ("python_gate", "tools/multi_frame_durable_transfer_spec_gate.py"),
    ("node_gate", "tools/multi_frame_durable_transfer_spec_gate.mjs"),
    ("c_gate", "tests/model/multi_frame_durable_transfer_c_gate_test.c"),
)

# Dedicated MFDT CMake authority (pinable). Root CMakeLists.txt is shared and
# is NOT content-pinned.
MFDT_CMAKE_AUTHORITY_REL = "cmake/ninlil_mfdt_ctest.cmake"
MFDT_CMAKE_INCLUDE_SNIPPET = (
    "include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_mfdt_ctest.cmake)"
)
TEST_CMAKE_AUTHORITY_REL = "cmake/ninlil_ctest.cmake"
TEST_CMAKE_INCLUDE_SNIPPET = (
    "include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_ctest.cmake)"
)

# MFDT-owned artifacts only (no shared monorepo files).
# This gate file itself is existence-only (self-circular avoidance).
PINNED_ARTIFACTS: tuple[str, ...] = (
    "docs/adr/0021-multi-frame-durable-custody.md",
    "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md",
    "docs/work/2026-08-01-mfdt-application-handoff-spec-repair.md",
    "docs/reviews/2026-08-01-mfdt-application-handoff-spec-accepted.md",
    "spec/vectors/multi-frame-durable-transfer-spec-v1.json",
    "tools/multi_frame_durable_transfer_spec_vector_gen.py",
    "tools/multi_frame_durable_transfer_spec_gate.py",
    "tools/multi_frame_durable_transfer_spec_gate.mjs",
    "tools/multi_frame_durable_transfer_acceptance_gate.py",
    "tests/model/multi_frame_durable_transfer_c_gate_test.c",
    "tests/model/multi_frame_durable_transfer_c_authority.h",
    MFDT_CMAKE_AUTHORITY_REL,
)

# Content-digest pins for MFDT-owned files (filled by authority_resync / freeze).
PINNED_ARTIFACT_SHA256: dict[str, str] = {
    "docs/adr/0021-multi-frame-durable-custody.md":
        "15bd999eb3240672f65089aa2ba12ba481c552688fda262aa221ebf4f2ed4ac9",
    "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md":
        "013acbc8659669347d913e273fce91e04c9b594f6afe98839445597fb9d70345",
    "docs/work/2026-08-01-mfdt-application-handoff-spec-repair.md":
        "fe96fb7c8bff8c55dc18eccb446c7eac18f86292fa09428b0174f574d5923217",
    "docs/work/2026-08-02-mfdt-deadline-sentinel-record-safety-erratum.md":
        "fc4db2e612a1e05e15f92f24cafc45fd87141f4f58e4fc62ef80b1b2f249b518",
    "docs/reviews/2026-08-01-mfdt-application-handoff-spec-accepted.md":
        "fbf1e9382e08a0225eb32640b9d282a0dba3fc9b17cb12755cf94bbfbde69433",
    "spec/vectors/multi-frame-durable-transfer-spec-v1.json":
        "7e8b84159481c458ed441c0c9fc50ac0da6336cf93f471d8550a31bbb2d291c0",
    "tools/multi_frame_durable_transfer_spec_vector_gen.py":
        "5517ef34707ff18b9623c69dd6c88b9af495940274b326208991769c7b69c8d3",
    "tools/multi_frame_durable_transfer_spec_gate.py":
        "72118084815150794fd596002c41e5408f937453a03f205c550271dec5525a45",
    "tools/multi_frame_durable_transfer_spec_gate.mjs":
        "51fe9aec16f25a76dd3ff1dd6ef3cd495cbf26b17daae0d9ce32d0ed2227ad85",
    "tests/model/multi_frame_durable_transfer_c_gate_test.c":
        "6a79b9378b41eff2990d3be09b1dfbb7ead2e96ede1be97297e06f8d79c8e271",
    "tests/model/multi_frame_durable_transfer_c_authority.h":
        "d36c038ea94d0c13e22d3dffd725d65a0a55f5c44a233edf82200c1ba7f789ef",
    "cmake/ninlil_mfdt_ctest.cmake":
        "f14fe596ddc17ba92cf00f38fb3e9798273bd29708cc5cf5f698122a8837e795",
}

# Exact CMake test inventory for MFDT (check + self-test × 4 systems + acceptance).
PINNED_CMAKE_TESTS: tuple[str, ...] = (
    "multi_frame_durable_transfer_vector_oracle",
    "multi_frame_durable_transfer_vector_oracle_self_test",
    "multi_frame_durable_transfer_python_gate",
    "multi_frame_durable_transfer_python_gate_self_test",
    "multi_frame_durable_transfer_node_gate",
    "multi_frame_durable_transfer_node_gate_self_test",
    "multi_frame_durable_transfer_c_gate",
    "multi_frame_durable_transfer_c_gate_self_test",
    "multi_frame_durable_transfer_acceptance_gate",
    "multi_frame_durable_transfer_acceptance_gate_self_test",
)

PINNED_CMAKE_TEST_COUNT = 10
PINNED_AUTHORITY_SYSTEM_COUNT = 4

PINNED_C_EXECUTABLE = "ninlil_multi_frame_durable_transfer_c_gate_test"
PINNED_C_SOURCE = "tests/model/multi_frame_durable_transfer_c_gate_test.c"
PINNED_C_STANDARD = "11"

# Canonical semantic inventory SHA (stable JSON of extracted MFDT CMake facts).
# Filled by freeze/resync from extract_mfdt_cmake_inventory().
PINNED_CMAKE_INVENTORY_SHA256 = (
    "b7c7b3750da5d3507a3d167950d2ffaae1d322a32f2742c1225a46f1a211a6cd"
)


class GateError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GateError(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_pins() -> dict[str, str]:
    return dict(PINNED_ARTIFACT_SHA256)


def extract_mfdt_cmake_inventory(cmake_authority_text: str) -> dict[str, object]:
    """Canonical semantic extraction of MFDT-only CMake authority properties."""

    tests = re.findall(r"NAME\s+(multi_frame_durable_transfer_[A-Za-z0-9_]+)\b", cmake_authority_text)
    if len(tests) != len(set(tests)):
        fail("duplicate MFDT test names in cmake authority")
    exe_match = re.search(
        r"add_executable\s*\(\s*(ninlil_multi_frame_durable_transfer_c_gate_test)\s+"
        r"([^\s)]+\.c)",
        cmake_authority_text,
        flags=re.S,
    )
    if not exe_match:
        fail("C gate executable/source missing from MFDT cmake authority")
    c_source = re.sub(r"\s+", "", exe_match.group(2))
    c_std = re.search(
        r"set_target_properties\s*\(\s*ninlil_multi_frame_durable_transfer_c_gate_test\s+"
        r"PROPERTIES[\s\S]*?C_STANDARD\s+(\d+)",
        cmake_authority_text,
    )
    if not c_std:
        fail("C_STANDARD missing on MFDT C gate target")
    default_off_guard = "if(NOT NINLIL_BUILD_TESTS)" in cmake_authority_text and (
        "return()" in cmake_authority_text
    )
    noninstall = "install(" not in cmake_authority_text.lower().replace(" ", "")
    # Soft check: no install( token with multi_frame
    if re.search(r"install\s*\(", cmake_authority_text, flags=re.I):
        fail("MFDT cmake authority must not install() targets")
    depends = sorted(
        set(
            re.findall(
                r"PROPERTIES\s+DEPENDS\s+(multi_frame_durable_transfer_[A-Za-z0-9_]+)",
                cmake_authority_text,
            )
        )
    )
    inventory = {
        "authority_relpath": MFDT_CMAKE_AUTHORITY_REL,
        "tests": tests,
        "test_count": len(tests),
        "c_executable": exe_match.group(1),
        "c_source": c_source,
        "c_standard": c_std.group(1),
        "default_off_guard": default_off_guard,
        "noninstall": noninstall,
        "depends_oracle": depends,
        "has_node_self_test": "multi_frame_durable_transfer_node_gate_self_test" in tests,
        "has_c_gate": "multi_frame_durable_transfer_c_gate" in tests,
        "has_acceptance": "multi_frame_durable_transfer_acceptance_gate" in tests,
    }
    return inventory


def inventory_canonical_json(inventory: dict[str, object]) -> str:
    return json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_work_and_adr(
    baseline_work_text: str | None = None,
    amendment_work_text: str | None = None,
    adr_text: str | None = None,
    vector_text: str | None = None,
) -> None:
    baseline_work = ROOT / "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md"
    amendment_work = ROOT / "docs/work/2026-08-01-mfdt-application-handoff-spec-repair.md"
    adr = ROOT / "docs/adr/0021-multi-frame-durable-custody.md"
    vector = ROOT / "spec/vectors/multi-frame-durable-transfer-spec-v1.json"
    if baseline_work_text is None and not baseline_work.is_file():
        fail("baseline work record missing")
    if amendment_work_text is None and not amendment_work.is_file():
        fail("amendment work record missing")
    if adr_text is None and not adr.is_file():
        fail("ADR missing")
    if vector_text is None and not vector.is_file():
        fail("vector missing")
    if baseline_work_text is None:
        baseline_work_text = baseline_work.read_text(encoding="utf-8")
    if amendment_work_text is None:
        amendment_work_text = amendment_work.read_text(encoding="utf-8")
    if adr_text is None:
        adr_text = adr.read_text(encoding="utf-8")
    if vector_text is None:
        vector_text = vector.read_text(encoding="utf-8")
    if PINNED_BASELINE_WORK_STATUS_TOKEN not in baseline_work_text:
        fail("baseline record lost SPEC_ACCEPTED history")
    baseline_status_line = ""
    for line in baseline_work_text.splitlines():
        if line.startswith("Status:"):
            baseline_status_line = line
            break
    if PINNED_BASELINE_WORK_STATUS_TOKEN not in baseline_status_line:
        fail("baseline Status line is not accepted history")
    amendment_status_line = ""
    for line in amendment_work_text.splitlines():
        if line.startswith("Status:"):
            amendment_status_line = line
            break
    if PINNED_AMENDMENT_WORK_STATUS_TOKEN not in amendment_status_line:
        fail("amendment Status line must remain SPEC_ACCEPTED with implementation incomplete")
    if PINNED_ADR_TOKEN not in adr_text[:2000]:
        fail("ADR missing accepted amendment token near header")
    if f'"status": "{PINNED_VECTOR_STATUS}"' not in vector_text:
        fail("vector status is not SPEC_ACCEPTED")


def validate_cmake_mfdt_authority(
    authority_text: str | None = None,
    root_cmake_text: str | None = None,
    test_cmake_text: str | None = None,
) -> dict[str, object]:
    """Validate dedicated MFDT authority and the two-step include chain."""

    auth_path = ROOT / MFDT_CMAKE_AUTHORITY_REL
    if authority_text is None and not auth_path.is_file():
        fail(f"missing MFDT cmake authority: {MFDT_CMAKE_AUTHORITY_REL}")
    if authority_text is None:
        authority_text = auth_path.read_text(encoding="utf-8")
    inventory = extract_mfdt_cmake_inventory(authority_text)

    if inventory["tests"] != list(PINNED_CMAKE_TESTS):
        fail(
            "MFDT cmake test inventory mismatch: "
            f"got={inventory['tests']} want={list(PINNED_CMAKE_TESTS)}"
        )
    if inventory["test_count"] != PINNED_CMAKE_TEST_COUNT:
        fail("MFDT cmake test count mismatch")
    if inventory["c_executable"] != PINNED_C_EXECUTABLE:
        fail("C executable name mismatch")
    if inventory["c_source"] != PINNED_C_SOURCE:
        fail("C source path mismatch")
    if inventory["c_standard"] != PINNED_C_STANDARD:
        fail("C_STANDARD mismatch")
    if not inventory["default_off_guard"]:
        fail("MFDT cmake authority missing NINLIL_BUILD_TESTS default-OFF guard")
    if not inventory["noninstall"]:
        fail("MFDT cmake authority must remain noninstall")
    if not inventory["has_node_self_test"]:
        fail("node self-test missing from MFDT cmake authority")
    if not inventory["has_c_gate"]:
        fail("c gate missing from MFDT cmake authority")

    inv_sha = sha256_text(inventory_canonical_json(inventory))
    if PINNED_CMAKE_INVENTORY_SHA256.startswith("0000"):
        # Allow first-run freeze tooling; still fail closed if pin is zero in check
        # after freeze. Resync must fill a real pin.
        fail("PINNED_CMAKE_INVENTORY_SHA256 not frozen")
    if inv_sha != PINNED_CMAKE_INVENTORY_SHA256:
        fail(f"MFDT cmake inventory sha drift: got {inv_sha}")

    # Root owns only the tests-ON umbrella. The umbrella owns the dedicated
    # MFDT authority include; neither shared file is content-pinned.
    if root_cmake_text is None:
        root_cmake_text = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    if test_cmake_text is None:
        test_cmake_text = (ROOT / TEST_CMAKE_AUTHORITY_REL).read_text(
            encoding="utf-8"
        )
    if TEST_CMAKE_INCLUDE_SNIPPET not in root_cmake_text:
        fail("root CMakeLists missing tests-ON cmake authority include")
    if MFDT_CMAKE_INCLUDE_SNIPPET not in test_cmake_text:
        fail("test CMake authority missing dedicated MFDT cmake include")
    # Ensure no leftover inlined multi_frame add_test bodies in either shared
    # dispatcher. The dedicated file above remains the sole registration body.
    for name in PINNED_CMAKE_TESTS:
        if re.search(rf"NAME\s+{re.escape(name)}\b", root_cmake_text):
            fail(f"root CMakeLists still inlines MFDT test {name}")
        if re.search(rf"NAME\s+{re.escape(name)}\b", test_cmake_text):
            fail(f"test CMake authority still inlines MFDT test {name}")
    install_blocks = re.findall(
        r"install\s*\((.*?)\)", root_cmake_text, flags=re.S | re.I
    )
    for block in install_blocks:
        if "multi_frame_durable_transfer" in block:
            fail("MFDT artifacts must not be install()-exported from root CMake")
    return inventory


def validate_authority_tools(pins: dict[str, str]) -> None:
    if len(PINNED_AUTHORITY_TOOLS) != PINNED_AUTHORITY_SYSTEM_COUNT:
        fail("authority system count")
    for _name, rel in PINNED_AUTHORITY_TOOLS:
        path = ROOT / rel
        if not path.is_file():
            fail(f"missing authority tool: {rel}")
        live = sha256_file(path)
        if rel in pins and pins[rel] != live:
            fail(f"authority tool sha drift: {rel}")
    hdr = ROOT / "tests/model/multi_frame_durable_transfer_c_authority.h"
    if not hdr.is_file():
        fail("missing C authority header")


def validate_artifact_hashes(pins: dict[str, str]) -> None:
    for rel in PINNED_ARTIFACTS:
        path = ROOT / rel
        if not path.is_file():
            fail(f"missing artifact: {rel}")
        if rel.endswith("multi_frame_durable_transfer_acceptance_gate.py"):
            continue
        # Shared monorepo root CMake is never a digest pin (dedicated file only).
        if rel.endswith("CMakeLists.txt") and "/" not in rel:
            fail("root CMakeLists must not be content-pinned")
        live = sha256_file(path)
        if rel not in pins:
            fail(f"missing pin for artifact: {rel}")
        if pins[rel].startswith("0000"):
            fail(f"artifact pin not frozen: {rel}")
        if pins[rel] != live:
            fail(f"artifact sha drift: {rel}")


def validate() -> None:
    pins = load_pins()
    validate_work_and_adr()
    validate_cmake_mfdt_authority()
    validate_authority_tools(pins)
    validate_artifact_hashes(pins)
    print(
        "MFDT acceptance gate OK "
        f"systems={PINNED_AUTHORITY_SYSTEM_COUNT} "
        f"cmake_tests={PINNED_CMAKE_TEST_COUNT} "
        f"cmake_authority={MFDT_CMAKE_AUTHORITY_REL} "
        f"artifacts={len(PINNED_ARTIFACTS)}"
    )


def self_test() -> None:
    validate()

    work = ROOT / "docs/work/2026-08-01-mfdt-application-handoff-spec-repair.md"
    original = work.read_text(encoding="utf-8")
    mutant = re.sub(
        r"(?m)^Status:.*$",
        "Status: **Proposed — false underclaim**",
        original,
        count=1,
    )
    if mutant == original:
        raise SystemExit("self-test: could not mutate Status")
    try:
        validate_work_and_adr(amendment_work_text=mutant)
        raise SystemExit("self-test failed: demoted amendment Status accepted")
    except GateError:
        pass

    # Mutant A: MFDT cmake authority block change must reject.
    auth_path = ROOT / MFDT_CMAKE_AUTHORITY_REL
    auth_original = auth_path.read_text(encoding="utf-8")
    if "multi_frame_durable_transfer_node_gate_self_test" not in auth_original:
        raise SystemExit("self-test: node self-test not in MFDT cmake authority")
    auth_mut = auth_original.replace(
        "multi_frame_durable_transfer_node_gate_self_test",
        "multi_frame_durable_transfer_node_gate_self_test_REMOVED",
    )
    try:
        validate_cmake_mfdt_authority(authority_text=auth_mut)
        raise SystemExit(
            "self-test failed: MFDT cmake authority node self-test removal accepted"
        )
    except GateError:
        pass

    # Mutant B: unrelated root CMakeLists edit must still accept.
    root_cmake = ROOT / "CMakeLists.txt"
    root_original = root_cmake.read_text(encoding="utf-8")
    root_mutant = (
        root_original
        + "\n# unrelated legitimate feature marker (must not break MFDT)\n"
    )
    validate_cmake_mfdt_authority(root_cmake_text=root_mutant)

    # Mutant C: tool content sha donor.
    pins = load_pins()
    bad = dict(pins)
    tool_rel = PINNED_AUTHORITY_TOOLS[0][1]
    if tool_rel in bad:
        bad[tool_rel] = "00" * 32
        try:
            validate_authority_tools(bad)
            raise SystemExit("self-test failed: tool sha donor accepted")
        except GateError:
            pass

    print(
        "MFDT acceptance self-test OK "
        "mutants=amendment_work_status+mfdt_cmake_block+unrelated_cmake_ok "
        f"systems={PINNED_AUTHORITY_SYSTEM_COUNT}"
    )


def freeze_pins() -> None:
    """Print freeze values for PINNED_ARTIFACT_SHA256 and inventory sha."""

    auth = (ROOT / MFDT_CMAKE_AUTHORITY_REL).read_text(encoding="utf-8")
    inv = extract_mfdt_cmake_inventory(auth)
    print(f"PINNED_CMAKE_INVENTORY_SHA256 = \"{sha256_text(inventory_canonical_json(inv))}\"")
    print("PINNED_ARTIFACT_SHA256 = {")
    for rel in PINNED_ARTIFACTS:
        if rel.endswith("multi_frame_durable_transfer_acceptance_gate.py"):
            continue
        path = ROOT / rel
        print(f'    "{rel}":')
        print(f'        "{sha256_file(path)}",')
    print("}")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--print-pins", action="store_true")
    args = parser.parse_args()
    try:
        if args.print_pins:
            freeze_pins()
            return 0
        if args.self_test:
            self_test()
            return 0
        validate()
        return 0
    except GateError as error:
        print(f"ACCEPTANCE GATE FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
