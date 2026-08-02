#!/usr/bin/env python3
"""Bootstrap/update the reviewed V2 coverage manifest.

V1 input receives an initial stable-ID assignment.  V2 input preserves every
existing path-to-ID binding, so document reordering never changes IDs.
"""

from __future__ import annotations

import hashlib
import json
import re
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


GENERIC_INVARIANT: dict[str, tuple[str, str, list[str]]] = {
    "NIN-INV-001": (
        "tests/model/required_receipt_transition_test.c",
        "static int test_active_matrix(void)",
        ["required_receipt_transition_model", "v1_runtime_family"],
    ),
    "NIN-INV-002": (
        "tests/model/required_receipt_transition_test.c",
        "static int test_terminal_is_immutable(void)",
        ["required_receipt_transition_model", "v1_runtime_family"],
    ),
    "NIN-INV-003": (
        "tests/model/submission_admission_test.c",
        "static int test_commit_ok_and_unknown(void)",
        ["submission_admission_model", "resource_ledger_batch_model"],
    ),
    "NIN-INV-004": (
        "tests/runtime/v1_direct_1hop_e2e_test.c",
        "#define SCENARIO_RESTART 5u",
        ["v1_direct_1hop_e2e", "v1_runtime_delivery"],
    ),
    "NIN-INV-006": (
        "tests/runtime/v1_event_mgmt_ledger_test.c",
        "static int test_commit_unknown_hidden_truths(void)",
        ["v1_event_mgmt_ledger", "v1_direct_1hop_e2e"],
    ),
    "NIN-INV-007": (
        "tests/runtime/v1_event_mgmt_ledger_test.c",
        "static int test_catch_up_required_receipt_after_restart(void)",
        ["v1_event_mgmt_ledger", "v1_posix_sqlite_restart_e2e"],
    ),
    "NIN-INV-008": (
        "tests/runtime/v1_runtime_delivery_test.c",
        "static int test_callback_failure_no_false_success(void)",
        ["v1_runtime_delivery", "v1_runtime_family"],
    ),
    "NIN-INV-009": (
        "tests/runtime/v1_runtime_family_test.c",
        "static int test_latest_state_apply_and_stale(void)",
        ["v1_runtime_family", "v1_runtime_capability"],
    ),
    "NIN-INV-011": (
        "tests/runtime/v1_runtime_spine_test.c",
        "NIN-INV-011: a rejected, otherwise-valid submission remains visible",
        ["v1_runtime_spine", "submission_preflight_model"],
    ),
    "NIN-INV-013": (
        "tests/radio/c3_lab_secure_wire_test.c",
        "static int run_reject_stale_token(void)",
        ["c3_lab_secure_wire", "n6_context_store"],
    ),
    "NIN-INV-014": (
        "tests/model/submission_preflight_test.c",
        "static int test_target_identity_validation(void)",
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
    source, anchor, tests = GENERIC_INVARIANT[identity]
    tests_by_profile = both(tests)
    return [
        {
            "id": "whole",
            "profiles": applicable_profiles(tests_by_profile),
            "evidence": [
                evidence(
                    source,
                    [anchor],
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
                        ["TRACE-INV005-TXID-STABLE"],
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
                        ["TRACE-INV005-LOGICAL-RETRY-FRESH-ATTEMPT"],
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
                        ["TRACE-INV005-CRASH-REPLAY-SAME-ATTEMPT"],
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
                            'expect_t("hop counter strict fresh"',
                            'expect_t("§8.6 nonces differ c1!=c2"',
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
                ["TRACE-INV010-QUEUE-BOUNDARY"],
                ["typed_simulated_bearer_fixture"],
                ["typed_simulated_bearer_fixture", "wifi_v1_queue_drop_wrap_test"],
            ),
            (
                "retry",
                "tests/runtime/v1_runtime_capability_test.c",
                ["TRACE-INV010-RETRY-BOUNDARY"],
                ["v1_runtime_capability"],
                ["nrw1_frag_session_private"],
            ),
            (
                "dedup",
                "tests/runtime/v1_runtime_capability_test.c",
                ["TRACE-INV010-DEDUP-BOUNDARY"],
                ["v1_runtime_capability", "v1_direct_1hop_e2e"],
                ["nrw1_frag_prod_integration_private"],
            ),
            (
                "reassembly",
                "tests/radio/r7_frag/r7_frag_state_test.c",
                ["TRACE-INV010-REASSEMBLY-BOUNDARY"],
                [],
                ["nrw1_frag_state_private", "nrw1_frag_prod_integration_private"],
            ),
            (
                "journal",
                "tests/transport/wifi_v1/wifi_v1_journal_test.c",
                ["TRACE-INV010-JOURNAL-BOUNDARY"],
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
                        ["static int test_default_deny(void)"],
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


def main() -> int:
    value = materialize()
    OUTPUT.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(
        "traceability coverage V2 materialized: "
        f"headings={sum(len(s['heading_units']) for s in value['normative_sources'])} "
        f"requirements={len(value['explicit_requirement_sets'])} "
        f"invariants={len(value['invariant_source']['invariants'])}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
