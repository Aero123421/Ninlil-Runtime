"""Manifest constructors for the existing ESP storage HIL campaigns."""

from __future__ import annotations

from typing import Any

from .model import ATOMIC_EVENTS, ORIGIN, expected_atomic_digest, validate_manifest


def atomic_cases(delays_ms: list[float]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for scenario, event in ATOMIC_EVENTS.items():
        for index, delay in enumerate(delays_ms, 1):
            cases.append(
                {
                    "case_id": f"HIL-{scenario}-{index:03d}",
                    "phase": f"ATOMIC_{scenario}",
                    "expected": {
                        "scenario": scenario,
                        "event": event,
                        "delay_ms": delay,
                        "boot_nonce_changed": True,
                        "power_command_succeeded": True,
                        # Existing runner cannot prove physical interruption.
                        "physical_power_interruption_verified": False,
                    },
                    "allowed": {
                        "state": ["OLD", "NEW"],
                        "digest": [
                            expected_atomic_digest(scenario, "OLD"),
                            expected_atomic_digest(scenario, "NEW"),
                        ],
                    },
                }
            )
    return cases


def _index_choices(namespaces: list[str]) -> list[dict[str, int]]:
    if len(namespaces) == 1:
        return [{namespaces[0]: index} for index in range(4)]
    return [
        {namespaces[0]: first, namespaces[1]: second}
        for first in range(4)
        for second in range(4)
        if first != second
    ]


def namespace_cases() -> list[dict[str, Any]]:
    snapshot_a = {
        "entry_count": 2,
        "logical_bytes": 47,
        "values": {"a": "A-old", "b": "A-stable", "c": None},
    }
    snapshot_b = {
        "entry_count": 2,
        "logical_bytes": 47,
        "values": {"a": "B-stable", "b": None, "c": "B-new"},
    }
    phases = (
        ("NS-AB-01", "AB_CREATE_A", "AB", "CREATE_VERIFY", "NS-A",
         ["NS-A"], {"NS-A": snapshot_a}),
        ("NS-AB-02", "AB_REBOOT_A", "AB", "COLD_REBOOT_VERIFY", None,
         ["NS-A"], {"NS-A": snapshot_a}),
        ("NS-AB-03", "AB_CREATE_B", "AB", "CREATE_VERIFY", "NS-B",
         ["NS-A", "NS-B"], {"NS-A": snapshot_a, "NS-B": snapshot_b}),
        ("NS-AB-04", "AB_REBOOT_B", "AB", "COLD_REBOOT_VERIFY", None,
         ["NS-A", "NS-B"], {"NS-A": snapshot_a, "NS-B": snapshot_b}),
        ("NS-BA-01", "BA_CREATE_B", "BA", "CREATE_VERIFY", "NS-B",
         ["NS-B"], {"NS-B": snapshot_b}),
        ("NS-BA-02", "BA_REBOOT_B", "BA", "COLD_REBOOT_VERIFY", None,
         ["NS-B"], {"NS-B": snapshot_b}),
        ("NS-BA-03", "BA_CREATE_A", "BA", "CREATE_VERIFY", "NS-A",
         ["NS-B", "NS-A"], {"NS-B": snapshot_b, "NS-A": snapshot_a}),
        ("NS-BA-04", "BA_REBOOT_A", "BA", "COLD_REBOOT_VERIFY", None,
         ["NS-B", "NS-A"], {"NS-B": snapshot_b, "NS-A": snapshot_a}),
    )
    cases: list[dict[str, Any]] = []
    for case_id, phase, campaign, action, created, names, snapshots in phases:
        cases.append(
            {
                "case_id": case_id,
                "phase": phase,
                "expected": {
                    "campaign": campaign,
                    "action": action,
                    "created_namespace": created,
                    "cold_boot_nonce_changed": action == "COLD_REBOOT_VERIFY",
                    "partition_erased_before_phase": phase
                    in {"AB_CREATE_A", "BA_CREATE_B"},
                    "unexpected_namespace": False,
                },
                "allowed": {
                    "directory_indices": _index_choices(names),
                    "snapshots": [snapshots],
                },
            }
        )
    return cases


def create_manifest(
    *,
    profile: str,
    campaign_id: str,
    run_id: str,
    repository_commit: str,
    tree_state: str,
    firmware_sha256: str,
    firmware_build_id: str,
    idf_version: str,
    resources: list[dict[str, Any]],
    requested: str,
    delays_ms: list[float],
) -> dict[str, Any]:
    if profile == "esp-storage-atomic-v1":
        cases = atomic_cases(delays_ms)
    elif profile == "esp-storage-namespace-v1":
        cases = namespace_cases()
    else:
        raise ValueError("templates are available only for ESP storage HIL profiles")
    manifest = {
        "schema": "ninlil-hil-manifest-v1",
        "campaign_id": campaign_id,
        "run_id": run_id,
        "profile": profile,
        "source": {
            "repository_commit": repository_commit,
            "tree_state": tree_state,
            "firmware_sha256": firmware_sha256,
            "firmware_build_id": firmware_build_id,
            "idf_version": idf_version,
        },
        "resources": resources,
        "cases": cases,
        "attestation": {"requested": requested, "evidence_origin": ORIGIN},
    }
    return validate_manifest(manifest)
