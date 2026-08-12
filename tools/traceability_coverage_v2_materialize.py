#!/usr/bin/env python3
"""Bootstrap/update the reviewed V2 coverage manifest.

V1 input receives an initial stable-ID assignment.  V2 input preserves every
existing path-to-ID binding, so document reordering never changes IDs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

import traceability_complete_coverage_gate as gate


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / gate.MANIFEST

DOMAIN_NOT_READY_DISABLED_TESTS = {
    "v1_event_mgmt_ledger",
    "v1_runtime_spine",
    "v1_runtime_delivery",
    "v1_runtime_capability",
    "v1_runtime_family",
    "v1_posix_platform_restart_e2e",
    "v1_direct_1hop_e2e",
}

FND_TESTS: dict[str, list[str]] = {
    "STO": ["in_memory_storage_conformance", "posix_sqlite_storage"],
    "LIF": ["runtime_lifecycle_model", "v1_posix_platform_restart_e2e"],
    "BER": ["typed_simulated_bearer_fixture", "v1_direct_1hop_e2e"],
    "AUTH": ["canonical_origin_authorization_fixture", "v1_runtime_family"],
    "ADM": ["submission_admission_model", "v1_runtime_spine"],
    "CLK": ["deadline_projection_model", "platform_basic_fixtures"],
    "ENT": ["deterministic_entropy_v1", "v1_runtime_spine"],
    "SIM": ["v1_direct_1hop_e2e", "v1_posix_platform_restart_e2e"],
    "SCH": ["scheduler_candidate_model", "v1_runtime_spine"],
    "RET": ["v1_runtime_delivery", "v1_runtime_spine"],
    "MET": ["v1_runtime_spine", "resource_ledger_model"],
    "QRY": ["v1_runtime_spine", "v1_runtime_family"],
    "ABI": ["abi_contract_header", "v1_runtime_family"],
    "CFG": ["runtime_lifecycle_model", "v1_runtime_spine"],
    "CAP": ["resource_ledger_model", "resource_ledger_batch_model"],
    "APP": ["v1_runtime_delivery", "v1_runtime_family"],
    "RTY": ["v1_runtime_delivery", "v1_posix_platform_restart_e2e"],
    "EVT": ["v1_event_mgmt_ledger", "v1_runtime_family"],
    "AUD": ["v1_event_mgmt_ledger", "v1_runtime_delivery"],
    "FLT": ["hook_registry_mirror_check", "hook_registry_mirror_negative"],
    "CAN": ["submission_preflight_model", "v1_transaction_codec"],
}


GENERIC_INVARIANT: dict[str, tuple[str, list[str], list[str]]] = {
    "NIN-INV-001": (
        "tests/model/required_receipt_transition_test.c",
        ["REQUIRE(result.next.state == expected->state);"],
        ["required_receipt_transition_model", "v1_runtime_family"],
    ),
    "NIN-INV-002": (
        "tests/model/required_receipt_transition_test.c",
        ["REQUIRE(result.next.state == input.current.state);"],
        ["required_receipt_transition_model", "v1_runtime_family"],
    ),
    "NIN-INV-003": (
        "tests/model/submission_admission_test.c",
        [
            "REQUIRE(result.recovery_action\n"
            "        == NINLIL_MODEL_ADMISSION_RECOVERY_FENCE_AND_REOPEN_JOURNAL);"
        ],
        ["submission_admission_model", "resource_ledger_batch_model"],
    ),
    "NIN-INV-004": (
        "tests/runtime/v1_direct_1hop_e2e_test.c",
        ["REQUIRE(ninlil_posix_lab_platform_restart(platform) == 1);"],
        ["v1_direct_1hop_e2e", "v1_runtime_delivery"],
    ),
    "NIN-INV-006": (
        "tests/runtime/v1_event_mgmt_ledger_test.c",
        [
            "REQUIRE(run_commit_unknown_case(0) == 0);",
            "REQUIRE(run_commit_unknown_case(1) == 0);",
        ],
        ["v1_event_mgmt_ledger", "v1_direct_1hop_e2e"],
    ),
    "NIN-INV-007": (
        "tests/runtime/v1_event_mgmt_ledger_test.c",
        ["REQUIRE(result.kind == NINLIL_EVENT_RESUME_ALREADY_RELEASED);"],
        ["v1_event_mgmt_ledger", "v1_posix_sqlite_restart_e2e"],
    ),
    "NIN-INV-008": (
        "tests/runtime/v1_runtime_delivery_test.c",
        ["REQUIRE(transaction->reason == NINLIL_REASON_APPLICATION_FAILED);"],
        ["v1_runtime_delivery", "v1_runtime_family"],
    ),
    "NIN-INV-009": (
        "tests/runtime/v1_runtime_family_test.c",
        [
            "REQUIRE(ninlil_rt_v1_family_latest_state_apply("
            "&ws, &app_id, 11u, &result) == 0);\n"
            "    REQUIRE(result.disposition == NINLIL_DISPOSITION_STALE_NOT_APPLIED);"
        ],
        ["v1_runtime_family", "v1_runtime_capability"],
    ),
    "NIN-INV-011": (
        "tests/runtime/v1_runtime_spine_test.c",
        [
            "REQUIRE(metrics.submission_calls == 2u);",
            "REQUIRE(metrics.rejected == 1u);",
        ],
        ["v1_runtime_spine", "submission_preflight_model"],
    ),
    "NIN-INV-013": (
        "tests/radio/c3_lab_secure_wire_test.c",
        [
            "REQUIRE(ninlil_c3_lab_install_from_token(\n"
            "                &controller, &ctrl_hs.install_token, &install_result)\n"
            "        == NINLIL_C3_LAB_STALE);"
        ],
        ["c3_lab_secure_wire", "n6_context_store"],
    ),
    "NIN-INV-014": (
        "tests/model/submission_preflight_test.c",
        [
            "input.submission.target.reserved_zero = 1u;\n"
            "    REQUIRE(expect_model_invalid(&input));"
        ],
        ["submission_preflight_model", "required_receipt_transition_model"],
    ),
}


def both(tests: list[str]) -> dict[str, list[str]]:
    return {
        "baseline": list(tests),
        "all-private": [
            test for test in tests if test not in DOMAIN_NOT_READY_DISABLED_TESTS
        ],
    }


def applicable_profiles(tests: dict[str, list[str]]) -> list[str]:
    return [profile for profile in gate.EXPECTED_PROFILES if tests[profile]]


def prof(
    baseline: list[str] | None = None,
    all_private: list[str] | None = None,
) -> dict[str, list[str]]:
    return {
        "baseline": list(baseline or []),
        "all-private": list(all_private or []),
    }


def evidence(
    source: str,
    anchors: list[str],
    baseline: list[str] | None = None,
    all_private: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "source": source,
        "anchors": anchors,
        "tests_by_profile": prof(baseline, all_private),
    }


def parse_authority() -> dict[str, Any]:
    value = json.loads(OUTPUT.read_text(encoding="utf-8"))
    if value.get("format") not in {
        "NINLIL_TRACEABILITY_COVERAGE_V1",
        gate.FORMAT,
    }:
        raise RuntimeError("materializer requires a reviewed V1/V2 manifest")
    return value


def assigned_heading_units(
    source: str,
    text: str,
    authority_source: dict[str, Any],
) -> list[dict[str, Any]]:
    parsed = gate._heading_units(text, source)
    if "heading_units" in authority_source:
        existing = {
            tuple(row["path"]): row for row in authority_source["heading_units"]
        }
        if set(existing) != set(parsed):
            raise RuntimeError(
                f"V2 path set changed for {source}; assign/review IDs explicitly"
            )
        return [
            {
                "id": existing[full_path]["id"],
                "level": metadata["level"],
                "path": list(full_path),
                "profiles": applicable_profiles(
                    both(existing[full_path]["tests_by_profile"]["baseline"])
                ),
                "tests_by_profile": both(
                    existing[full_path]["tests_by_profile"]["baseline"]
                ),
            }
            for full_path, metadata in sorted(
                parsed.items(), key=lambda item: item[1]["line"]
            )
        ]

    h2_rows = {
        tuple([row["heading"]]): row for row in authority_source["sections"]
    }
    current_h2_id = ""
    h3_counter = 0
    h4_counter = 0
    units: list[dict[str, Any]] = []
    for full_path, metadata in sorted(
        parsed.items(), key=lambda item: item[1]["line"]
    ):
        level = metadata["level"]
        if level == 2:
            row = h2_rows.get(full_path)
            if row is None:
                raise RuntimeError(f"V1 has no H2 row for {source}: {full_path}")
            stable_id = row["id"]
            tests = row["tests"]
            current_h2_id = stable_id
            h3_counter = 0
            h4_counter = 0
        elif level == 3:
            h3_counter += 1
            h4_counter = 0
            stable_id = f"{current_h2_id}-S{h3_counter:03d}"
            tests = h2_rows[(full_path[0],)]["tests"]
        else:
            h4_counter += 1
            stable_id = (
                f"{current_h2_id}-S{h3_counter:03d}-D{h4_counter:03d}"
            )
            tests = h2_rows[(full_path[0],)]["tests"]
        tests_by_profile = both(tests)
        units.append({
            "id": stable_id,
            "level": level,
            "path": list(full_path),
            "profiles": applicable_profiles(tests_by_profile),
            "tests_by_profile": tests_by_profile,
        })
    return units


def fnd_tests(identity: str) -> list[str]:
    match = re.fullmatch(r"NIN-FND-([A-Z]+)-[0-9]+", identity)
    if match is None or match.group(1) not in FND_TESTS:
        raise RuntimeError(f"no reviewed test family for {identity}")
    return FND_TESTS[match.group(1)]


def generic_subclaim(identity: str) -> list[dict[str, Any]]:
    source, anchors, tests = GENERIC_INVARIANT[identity]
    tests_by_profile = both(tests)
    return [
        {
            "id": "whole",
            "profiles": applicable_profiles(tests_by_profile),
            "evidence": [
                evidence(
                    source,
                    anchors,
                    tests_by_profile["baseline"],
                    tests_by_profile["all-private"],
                ),
            ],
        }
    ]


def focused_subclaims(identity: str) -> list[dict[str, Any]]:
    if identity == "NIN-INV-005":
        return [
            {
                "id": "transaction-id-stable",
                "profiles": ["baseline"],
                "evidence": [
                    evidence(
                        "tests/runtime/v1_runtime_delivery_test.c",
                        [
                            "REQUIRE(memcmp(\n"
                            "                    &original_transaction_id,\n"
                            "                    &submit_result.transaction_id,\n"
                            "                    sizeof(original_transaction_id))\n"
                            "            == 0);"
                        ],
                        ["v1_runtime_delivery"],
                        [],
                    )
                ],
            },
            {
                "id": "logical-retry-fresh-attempt",
                "profiles": ["baseline"],
                "evidence": [
                    evidence(
                        "tests/runtime/v1_runtime_delivery_test.c",
                        [
                            "REQUIRE(memcmp(\n"
                            "                    &transaction->attempt_ids[1],\n"
                            "                    &first_attempt_id,\n"
                            "                    sizeof(first_attempt_id))\n"
                            "            != 0);"
                        ],
                        ["v1_runtime_delivery"],
                        [],
                    )
                ],
            },
            {
                "id": "crash-replay-same-attempt",
                "profiles": ["baseline"],
                "evidence": [
                    evidence(
                        "tests/runtime/v1_runtime_delivery_test.c",
                        [
                            "REQUIRE(memcmp(\n"
                            "                    &transaction->attempt_id,\n"
                            "                    &transaction->attempt_ids[0],\n"
                            "                    sizeof(transaction->attempt_id))\n"
                            "            == 0);"
                        ],
                        ["v1_runtime_delivery"],
                        [],
                    )
                ],
            },
            {
                "id": "protected-wire-fresh-nonce",
                "profiles": ["all-private"],
                "evidence": [
                    evidence(
                        "tests/radio/r7_frag/r7_frag_prod_integration_test.c",
                        [
                            'expect_t("hop counter strict fresh", '
                            "hop_retry != 0u && hop_retry != hop0);",
                            'expect_t("§8.6 nonces differ c1!=c2", '
                            "memcmp(n1, n2, 12u) != 0);",
                        ],
                        [],
                        ["nrw1_frag_prod_integration_private"],
                    )
                ],
            },
        ]
    if identity == "NIN-INV-010":
        definitions = [
            (
                "queue",
                "tests/port/typed_simulated_bearer_test.c",
                [
                    "REQUIRE(entries == 2u && bytes == 1021u);",
                    "REQUIRE(send_message(&context, context.a, &c1, &permit, &result)\n"
                    "        == NINLIL_BEARER_WOULD_BLOCK);",
                ],
                ["typed_simulated_bearer_fixture"],
                ["typed_simulated_bearer_fixture", "wifi_v1_queue_drop_wrap_test"],
            ),
            (
                "retry",
                "tests/runtime/v1_runtime_capability_test.c",
                [
                    "REQUIRE(descriptor.max_attempts_per_target_per_cycle\n"
                    "        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);",
                    "descriptor.max_attempts_per_target_per_cycle =\n"
                    "        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE + 1u;\n"
                    "    service = NULL;\n"
                    "    REQUIRE(ninlil_service_register(\n"
                    "                env.runtime, &descriptor, &callbacks, &service)\n"
                    "        == NINLIL_E_UNSUPPORTED);",
                ],
                ["v1_runtime_capability"],
                ["nrw1_frag_session_private"],
            ),
            (
                "dedup",
                "tests/runtime/v1_runtime_capability_test.c",
                [
                    "descriptor = desired_descriptor(0x8au);\n"
                    "    descriptor.required_dedup_window_ms =\n"
                    "        env.config.result_cache_retention_ms;\n"
                    "    /*\n"
                    "     * TRACE-INV010-RETRY-BOUNDARY\n"
                    "     * The profile's exact attempt limit is accepted; "
                    "limit+1 is rejected.\n"
                    "     */\n"
                    "    REQUIRE(descriptor.max_attempts_per_target_per_cycle\n"
                    "        == NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE);\n"
                    "    REQUIRE(ninlil_service_register(\n"
                    "                env.runtime, &descriptor, &callbacks, &service)\n"
                    "        == NINLIL_OK);",
                    "descriptor.required_dedup_window_ms =\n"
                    "        env.config.result_cache_retention_ms + 1u;\n"
                    "    service = NULL;\n"
                    "    REQUIRE(ninlil_service_register(\n"
                    "                env.runtime, &descriptor, &callbacks, &service)\n"
                    "        == NINLIL_E_UNSUPPORTED);",
                ],
                ["v1_runtime_capability", "v1_direct_1hop_e2e"],
                ["nrw1_frag_prod_integration_private"],
            ),
            (
                "reassembly",
                "tests/radio/r7_frag/r7_frag_state_test.c",
                [
                    'expect_u64("plan max sum", sum, 2048u);',
                    'expect_st("plan oversize", st, '
                    "NINLIL_R7_FRAG_STATE_LENGTH);",
                ],
                [],
                ["nrw1_frag_state_private", "nrw1_frag_prod_integration_private"],
            ),
            (
                "journal",
                "tests/transport/wifi_v1/wifi_v1_journal_test.c",
                [
                    "CHECK(ninlil_wifi_journal_put_attempt(&journal, &attempt)\n"
                    "            == NINLIL_WIFI_OK);",
                    "CHECK(ninlil_wifi_journal_put_attempt(&journal, &attempt)\n"
                    "            == NINLIL_WIFI_CAPACITY);",
                ],
                [],
                ["wifi_v1_journal_test"],
            ),
        ]
        return [
            {
                "id": name,
                "profiles": (
                    ["baseline", "all-private"] if baseline else ["all-private"]
                ),
                "evidence": [
                    evidence(source, anchors, baseline, all_private)
                ],
            }
            for name, source, anchors, baseline, all_private in definitions
        ]
    if identity == "NIN-INV-012":
        return [
            {
                "id": "physical-tx-sole-permit-edge",
                "profiles": ["baseline", "all-private"],
                "evidence": [
                    evidence(
                        "tests/radio/radio_hal_r1_test.c",
                        [
                            "REQUIRE(\n"
                            "        ninlil_radio_hal_transmit_with_permit("
                            "rh, &permit, &frame, &err)\n"
                            "        == NINLIL_RADIO_HAL_DEFAULT_DENY);\n"
                            "    REQUIRE(spy.edge_calls == 0u);\n"
                            "    REQUIRE(spy.validate_calls == 0u);"
                        ],
                        ["radio_hal_r1", "sx1262_r9", "sx1262_r9_sole_edge_gate"],
                        ["radio_hal_r1", "sx1262_r9", "sx1262_r9_sole_edge_gate"],
                    )
                ],
            }
        ]
    return generic_subclaim(identity)


def materialize() -> dict[str, Any]:
    authority = parse_authority()
    authority_by_path = {
        source["path"]: source for source in authority["normative_sources"]
    }
    normative_sources: list[dict[str, Any]] = []
    all_fnd: set[str] = set()
    for relative in gate.EXPECTED_SOURCES:
        path = ROOT / relative
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        all_fnd.update(gate._explicit_fnd_ids(text))
        normative_sources.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "heading_units": assigned_heading_units(
                    relative, text, authority_by_path[relative]
                ),
            }
        )

    invariant_text = (
        ROOT / "docs/07-testing-and-quality.md"
    ).read_text(encoding="utf-8")
    invariant_lines = gate._invariant_section(
        invariant_text, "## 常時検査するinvariant"
    )
    invariants = [
        {
            "id": identity,
            "line_sha256": hashlib.sha256(
                invariant_lines[identity].encode("utf-8")
            ).hexdigest(),
            "subclaims": focused_subclaims(identity),
        }
        for identity in gate.EXPECTED_INVARIANTS
    ]
    return {
        "format": gate.FORMAT,
        "schema_version": 2,
        "normative_sources": normative_sources,
        "explicit_requirement_sets": [
            {
                "id": identity,
                "source": "docs/14-foundation-ports-and-simulator.md",
                "tests_by_profile": both(
                    fnd_tests(identity)
                    + ["vector_inventory_check", "vector_reference_check"]
                ),
            }
            for identity in sorted(all_fnd)
        ],
        "delegated_authorities": [
            {
                "id": "NIN-PR1-VECTOR-303",
                "kind": "foundation-vector-inventory-and-reference",
                "expected_items": 303,
                "tests_by_profile": both(
                    ["vector_inventory_check", "vector_reference_check"]
                ),
            }
        ],
        "invariant_source": {
            "path": "docs/07-testing-and-quality.md",
            "heading": "## 常時検査するinvariant",
            "invariants": invariants,
        },
    }


def canonical_text(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def validate_generated(value: dict[str, Any]) -> None:
    all_tests = gate._all_manifest_tests(value)
    registries = {
        profile: set(all_tests) for profile in gate.EXPECTED_PROFILES
    }
    gate.validate(ROOT, value, registries)


def require_fresh(value: dict[str, Any], actual: str) -> None:
    if actual != canonical_text(value):
        raise RuntimeError(
            f"{gate.MANIFEST} is stale; run "
            "tools/traceability_coverage_v2_materialize.py --write"
        )


def self_test() -> None:
    first = materialize()
    second = materialize()
    if canonical_text(first) != canonical_text(second):
        raise RuntimeError("materializer is not deterministic")
    validate_generated(first)
    require_fresh(first, OUTPUT.read_text(encoding="utf-8"))

    stale = copy.deepcopy(first)
    stale["invariant_source"]["invariants"][0]["subclaims"][0][
        "evidence"
    ][0]["anchors"] = ["static int test_active_matrix(void)"]
    try:
        validate_generated(stale)
    except gate.CoverageError as exc:
        if "not an active assertion-bearing anchor" not in str(exc):
            raise
    else:
        raise RuntimeError("legacy function anchor was accepted")
    try:
        require_fresh(first, canonical_text(stale))
    except RuntimeError as exc:
        if "is stale" not in str(exc):
            raise
    else:
        raise RuntimeError("stale generated manifest was accepted")

    with tempfile.TemporaryDirectory() as raw_temp:
        generated = Path(raw_temp) / gate.MANIFEST
        generated.write_text(canonical_text(first), encoding="utf-8")
        if generated.read_bytes() != OUTPUT.read_bytes():
            raise RuntimeError("fresh generated bytes differ from checked manifest")


def summary(value: dict[str, Any], action: str) -> str:
    return (
        f"traceability coverage V2 {action}: "
        f"headings={sum(len(s['heading_units']) for s in value['normative_sources'])} "
        f"requirements={len(value['explicit_requirement_sets'])} "
        f"invariants={len(value['invariant_source']['invariants'])}"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            self_test()
            print("traceability coverage V2 materializer self-test ok")
            return 0
        value = materialize()
        validate_generated(value)
        if args.write:
            OUTPUT.write_text(canonical_text(value), encoding="utf-8")
            print(summary(value, "materialized"))
        else:
            require_fresh(value, OUTPUT.read_text(encoding="utf-8"))
            print(summary(value, "freshness ok"))
    except (gate.CoverageError, OSError, RuntimeError, UnicodeError) as exc:
        print(f"traceability coverage V2 materializer error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
