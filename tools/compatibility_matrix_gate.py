#!/usr/bin/env python3
"""Fail-closed completion authority for compatibility-matrix.json."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "compatibility-matrix.json"
STATES = [
    "UNALLOCATED",
    "PROPOSED",
    "SPEC_ACCEPTED",
    "HOST_CANDIDATE",
    "TARGET_CANDIDATE",
    "HIL_VERIFIED",
    "RELEASE_SUPPORTED",
]
TRANSITIONS = {
    "UNALLOCATED": ["PROPOSED"],
    "PROPOSED": ["SPEC_ACCEPTED"],
    "SPEC_ACCEPTED": ["HOST_CANDIDATE", "TARGET_CANDIDATE"],
    "HOST_CANDIDATE": ["TARGET_CANDIDATE", "HIL_VERIFIED", "RELEASE_SUPPORTED"],
    "TARGET_CANDIDATE": ["HIL_VERIFIED"],
    "HIL_VERIFIED": ["RELEASE_SUPPORTED"],
    "RELEASE_SUPPORTED": [],
}


def ev(evidence_class: str, path: str, contains: str) -> dict[str, str]:
    return {"class": evidence_class, "path": path, "contains": contains}


PLATFORM_AUTHORITY = {
    "linux-x86_64": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "runner": "ubuntu-24.04",
        "architecture": "x86_64",
        "evidence": [
            ev("ci-workflow", ".github/workflows/ci.yml", "runs-on: ubuntu-24.04")
        ],
    },
    "macos-arm64": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "runner": "macos-15",
        "architecture": "arm64",
        "evidence": [
            ev(
                "ci-workflow",
                ".github/workflows/ci.yml",
                'test "$(uname -m)" = "arm64"',
            )
        ],
    },
    "esp32s3-esp-idf": {
        "required_hil": True,
        "state_ceiling": "TARGET_CANDIDATE",
        "runner": "ubuntu-24.04",
        "architecture": "xtensa-esp32s3",
        "evidence": [
            ev(
                "target-ci-workflow",
                ".github/workflows/esp-idf.yml",
                "sha256:3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb",
            )
        ],
    },
}

FEATURE_AUTHORITY = {
    "portable-core-host-runtime": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "depends_on": [],
        "evidence": [
            ev("status", "README.md", "HOST_CANDIDATE"),
            ev("sdk-guide", "docs/host-runtime-sdk.md", "Host Runtime"),
            ev("ci-workflow", ".github/workflows/ci.yml", "name: CI"),
        ],
    },
    "canonical-domain-store": {
        "required_hil": True,
        "state_ceiling": "PROPOSED",
        "depends_on": ["portable-core-host-runtime"],
        "evidence": [
            ev(
                "proposed-adr",
                "docs/adr/0022-domain-store-schema1-runtime-binding.md",
                "Proposed",
            )
        ],
    },
    "identity-attachment-session-install": {
        "required_hil": True,
        "state_ceiling": "PROPOSED",
        "depends_on": ["portable-core-host-runtime", "canonical-domain-store"],
        "evidence": [
            ev("normative-spec", "docs/03-identity-and-join.md", "Identity"),
            ev("roadmap", "docs/09-roadmap.md", "Roadmap"),
            ev("normative-spec", "docs/30-r6-secure-radio-wire.md", "Secure"),
        ],
    },
    "fabric-bearer-nfl1-path-registry": {
        "required_hil": False,
        "state_ceiling": "PROPOSED",
        "depends_on": [
            "portable-core-host-runtime",
            "canonical-domain-store",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev(
                "proposed-adr",
                "docs/adr/0017-bearer-registry-path-selection.md",
                "Proposed",
            )
        ],
    },
    "posix-tcp-tls-wifi-reference": {
        "required_hil": False,
        "state_ceiling": "UNALLOCATED",
        "depends_on": [
            "fabric-bearer-nfl1-path-registry",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev("proposed-adr", "docs/adr/0018-wifi-bearer.md", "Proposed")
        ],
    },
    "esp32s3-wifi-sta-tcp-tls": {
        "required_hil": True,
        "state_ceiling": "UNALLOCATED",
        "depends_on": [
            "posix-tcp-tls-wifi-reference",
            "fabric-bearer-nfl1-path-registry",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev("proposed-adr", "docs/adr/0018-wifi-bearer.md", "Proposed")
        ],
    },
    "nrw1-link-frag-reassembly": {
        "required_hil": True,
        "state_ceiling": "SPEC_ACCEPTED",
        "depends_on": [
            "canonical-domain-store",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev("normative-spec", "docs/30-r6-secure-radio-wire.md", "Secure"),
            ev(
                "accepted-adr",
                "docs/adr/0010-r6-secure-radio-wire.md",
                "Accepted",
            ),
        ],
    },
    "relay": {
        "required_hil": True,
        "state_ceiling": "PROPOSED",
        "depends_on": [
            "fabric-bearer-nfl1-path-registry",
            "nrw1-link-frag-reassembly",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev("proposed-adr", "docs/adr/0019-route-relay.md", "Proposed")
        ],
    },
    "multi-parent-multi-controller": {
        "required_hil": True,
        "state_ceiling": "PROPOSED",
        "depends_on": ["relay", "identity-attachment-session-install"],
        "evidence": [
            ev("proposed-adr", "docs/adr/0020-multi-parent.md", "Proposed")
        ],
    },
    "multi-frame-durable-transfer": {
        "required_hil": True,
        "state_ceiling": "PROPOSED",
        "depends_on": [
            "portable-core-host-runtime",
            "canonical-domain-store",
            "identity-attachment-session-install",
        ],
        "evidence": [
            ev(
                "proposed-adr",
                "docs/adr/0021-multi-frame-durable-custody.md",
                "Proposed",
            )
        ],
    },
    "oss-package-docs-release-ci": {
        "required_hil": False,
        "state_ceiling": "HOST_CANDIDATE",
        "depends_on": [],
        "evidence": [
            ev("license", "LICENSE", "Apache License"),
            ev("notice", "NOTICE", "Ninlil"),
            ev(
                "dependency-inventory",
                "dependency-inventory.json",
                "ninlil-dependency-inventory-v1",
            ),
            ev(
                "work-record",
                "docs/work/2026-07-28-oss-compatibility-authority.md",
                "compatibility",
            ),
            ev("release-guide", "docs/releasing.md", "Release Guide"),
            ev(
                "release-workflow",
                ".github/workflows/release.yml",
                "name: Release",
            ),
        ],
    },
}


class GateError(RuntimeError):
    """A deterministic compatibility authority failure."""


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc


def load_matrix() -> dict[str, Any]:
    try:
        value = json.loads(read_text(MATRIX_PATH))
    except json.JSONDecodeError as exc:
        raise GateError(f"compatibility-matrix.json is invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError("compatibility matrix must be an object")
    return value


def exact_regex(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise GateError(f"{label}: expected exactly one match, got {len(matches)}")
    value = matches[0]
    if isinstance(value, tuple):
        raise GateError(f"{label}: internal regex must have one capture")
    return value


def check_evidence(
    value: Any,
    expected: list[dict[str, str]],
    label: str,
) -> None:
    if value != expected:
        raise GateError(f"{label}: evidence class/path/content authority drift")
    for index, item in enumerate(expected):
        path_text = item["path"]
        path = ROOT / path_text
        if not path.is_file():
            raise GateError(f"{label}[{index}]: evidence file absent: {path_text}")
        if item["contains"] not in read_text(path):
            raise GateError(
                f"{label}[{index}]: required content absent from {path_text}: "
                f"{item['contains']!r}"
            )


def check_attestation(
    value: Any,
    label: str,
    expected_class: str,
    allowed_platforms: set[str],
) -> None:
    if not isinstance(value, list) or len(value) < 1:
        raise GateError(f"{label}: at least one attestation reference is required")
    for index, reference in enumerate(value):
        if not isinstance(reference, dict) or set(reference) != {
            "class",
            "path",
            "sha256",
        }:
            raise GateError(f"{label}[{index}]: reference fields are not closed")
        if reference["class"] != expected_class:
            raise GateError(f"{label}[{index}]: evidence class mismatch")
        path_text = reference["path"]
        prefix = f"evidence/{'hil' if expected_class == 'hil-result' else 'release'}/"
        if not isinstance(path_text, str) or not path_text.startswith(prefix):
            raise GateError(f"{label}[{index}]: evidence path outside {prefix}")
        digest = reference["sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise GateError(f"{label}[{index}]: invalid sha256")
        path = ROOT / path_text
        payload = path.read_bytes() if path.is_file() else None
        if payload is None or hashlib.sha256(payload).hexdigest() != digest:
            raise GateError(f"{label}[{index}]: absent or digest-mismatched artifact")
        try:
            record = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise GateError(f"{label}[{index}]: invalid JSON artifact: {exc}") from exc
        expected_fields = {
            "schema",
            "commit",
            "test_id",
            "platform_id",
            "result",
            "timestamp",
        }
        if not isinstance(record, dict) or set(record) != expected_fields:
            raise GateError(f"{label}[{index}]: artifact fields are not closed")
        if record["schema"] != "ninlil-verification-evidence-v1":
            raise GateError(f"{label}[{index}]: artifact schema mismatch")
        if not re.fullmatch(r"[0-9a-f]{40}", str(record["commit"])):
            raise GateError(f"{label}[{index}]: commit must be a full SHA")
        if not isinstance(record["test_id"], str) or not record["test_id"]:
            raise GateError(f"{label}[{index}]: test_id is required")
        if record["platform_id"] not in allowed_platforms:
            raise GateError(f"{label}[{index}]: platform_id mismatch")
        if record["result"] != "PASS":
            raise GateError(f"{label}[{index}]: result must be PASS")
        if not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            str(record["timestamp"]),
        ):
            raise GateError(f"{label}[{index}]: timestamp must be UTC RFC3339")


def check_versions(matrix: dict[str, Any]) -> None:
    cmake = read_text(ROOT / "CMakeLists.txt")
    version = exact_regex(
        cmake,
        r"^project\(ninlil VERSION ([0-9]+\.[0-9]+\.[0-9]+) LANGUAGES C CXX\)$",
        "CMake project version",
    )
    if matrix.get("runtime_release") != version:
        raise GateError("runtime_release/CMake version drift")
    inventory = json.loads(read_text(ROOT / "dependency-inventory.json"))
    if inventory["project"]["version"] != version:
        raise GateError("dependency inventory project version drift")
    component = read_text(ROOT / "ports/esp-idf/components/ninlil/idf_component.yml")
    if exact_regex(
        component,
        r'^version: "([0-9]+\.[0-9]+\.[0-9]+)"$',
        "ESP component version",
    ) != version:
        raise GateError("ESP component/CMake version drift")
    header = read_text(ROOT / "include/ninlil/version.h")
    abi = int(
        exact_regex(
            header,
            r"^#define NINLIL_ABI_VERSION\s+\(\(uint16_t\)0x([0-9A-Fa-f]{4})u\)$",
            "public ABI version",
        ),
        16,
    )
    storage = int(
        exact_regex(
            header,
            r"^#define NINLIL_STORAGE_SCHEMA_M1A\s+\(\(uint32_t\)([0-9]+)u\)$",
            "storage schema",
        )
    )
    domains = matrix.get("version_domains")
    if not isinstance(domains, dict):
        raise GateError("version_domains must be an object")
    if domains.get("public_c_abi", {}).get("minimum") != abi:
        raise GateError("public ABI minimum drift")
    if domains.get("public_c_abi", {}).get("maximum") != abi:
        raise GateError("public ABI maximum drift")
    if domains.get("foundation_storage_schema", {}).get("minimum") != storage:
        raise GateError("storage schema minimum drift")
    if domains.get("foundation_storage_schema", {}).get("maximum") != storage:
        raise GateError("storage schema maximum drift")


def check_platforms(matrix: dict[str, Any]) -> None:
    platforms = matrix.get("platforms")
    if not isinstance(platforms, list):
        raise GateError("platforms must be an array")
    ids = [item.get("id") if isinstance(item, dict) else None for item in platforms]
    if ids != list(PLATFORM_AUTHORITY):
        raise GateError("platform ID/order authority drift")
    for item in platforms:
        platform_id = item["id"]
        authority = PLATFORM_AUTHORITY[platform_id]
        allowed_fields = {
            "id",
            "os",
            "architecture",
            "state",
            "state_ceiling",
            "toolchain_version",
            "ci_workflow",
            "ci_runner",
            "required_hil",
            "hil_verified",
            "evidence",
            "hil_evidence",
            "release_evidence",
        }
        if set(item) - allowed_fields:
            raise GateError(f"{platform_id}: unknown platform fields")
        if item.get("required_hil") is not authority["required_hil"]:
            raise GateError(f"{platform_id}: required_hil authority drift")
        if item.get("state_ceiling") != authority["state_ceiling"]:
            raise GateError(f"{platform_id}: state ceiling authority drift")
        if item.get("architecture") != authority["architecture"]:
            raise GateError(f"{platform_id}: architecture authority drift")
        if item.get("ci_runner") != authority["runner"]:
            raise GateError(f"{platform_id}: CI runner authority drift")
        state = item.get("state")
        if state not in STATES or STATES.index(state) > STATES.index(
            authority["state_ceiling"]
        ):
            raise GateError(f"{platform_id}: state exceeds accepted ceiling")
        check_evidence(item.get("evidence"), authority["evidence"], platform_id)
        if authority["runner"] not in read_text(ROOT / item["ci_workflow"]):
            raise GateError(f"{platform_id}: runner absent from workflow")
        if authority["required_hil"]:
            reached_hil = STATES.index(state) >= STATES.index("HIL_VERIFIED")
            if item.get("hil_verified") is not reached_hil:
                raise GateError(f"{platform_id}: hil_verified/state mismatch")
            if not reached_hil and "hil_evidence" in item:
                raise GateError(f"{platform_id}: HIL evidence forbidden while false")
        if state == "HIL_VERIFIED":
            check_attestation(
                item.get("hil_evidence"),
                f"{platform_id}.hil_evidence",
                "hil-result",
                {platform_id},
            )
        if state == "RELEASE_SUPPORTED":
            check_attestation(
                item.get("release_evidence"),
                f"{platform_id}.release_evidence",
                "release-result",
                {platform_id},
            )


def check_features(matrix: dict[str, Any]) -> None:
    features = matrix.get("features")
    if not isinstance(features, list):
        raise GateError("features must be an array")
    ids = [item.get("id") if isinstance(item, dict) else None for item in features]
    if ids != list(FEATURE_AUTHORITY):
        raise GateError("feature ID/order authority drift")
    by_id = {item["id"]: item for item in features}
    for item in features:
        feature_id = item["id"]
        authority = FEATURE_AUTHORITY[feature_id]
        allowed_fields = {
            "id",
            "state",
            "state_ceiling",
            "required_hil",
            "hil_verified",
            "depends_on",
            "evidence",
            "hil_evidence",
            "release_evidence",
        }
        if set(item) - allowed_fields:
            raise GateError(f"{feature_id}: unknown feature fields")
        if item.get("required_hil") is not authority["required_hil"]:
            raise GateError(f"{feature_id}: required_hil authority drift")
        if item.get("state_ceiling") != authority["state_ceiling"]:
            raise GateError(f"{feature_id}: state ceiling authority drift")
        if item.get("depends_on") != authority["depends_on"]:
            raise GateError(f"{feature_id}: dependency authority drift")
        state = item.get("state")
        if state not in STATES or STATES.index(state) > STATES.index(
            authority["state_ceiling"]
        ):
            raise GateError(f"{feature_id}: state exceeds accepted ceiling")
        check_evidence(item.get("evidence"), authority["evidence"], feature_id)
        if authority["required_hil"]:
            reached_hil = STATES.index(state) >= STATES.index("HIL_VERIFIED")
            if item.get("hil_verified") is not reached_hil:
                raise GateError(f"{feature_id}: hil_verified/state mismatch")
            if not reached_hil and "hil_evidence" in item:
                raise GateError(f"{feature_id}: HIL evidence forbidden while false")
        if state == "HIL_VERIFIED":
            check_attestation(
                item.get("hil_evidence"),
                f"{feature_id}.hil_evidence",
                "hil-result",
                set(PLATFORM_AUTHORITY),
            )
        if state == "RELEASE_SUPPORTED":
            for dependency in authority["depends_on"]:
                if by_id[dependency]["state"] != "RELEASE_SUPPORTED":
                    raise GateError(
                        f"{feature_id}: dependency {dependency} is not release-supported"
                    )
            check_attestation(
                item.get("release_evidence"),
                f"{feature_id}.release_evidence",
                "release-result",
                set(PLATFORM_AUTHORITY),
            )


def check(matrix: dict[str, Any]) -> None:
    expected_top = {
        "schema",
        "runtime_release",
        "completion_states",
        "allowed_transitions",
        "version_domains",
        "platforms",
        "features",
        "legacy_adapters",
        "hardware_regulatory_claim",
    }
    if set(matrix) != expected_top:
        raise GateError("top-level fields are not closed")
    if matrix.get("schema") != "ninlil-compatibility-matrix-v1":
        raise GateError("schema mismatch")
    if matrix.get("completion_states") != STATES:
        raise GateError("completion state order drift")
    if matrix.get("allowed_transitions") != TRANSITIONS:
        raise GateError("allowed transition graph drift")
    if matrix.get("hardware_regulatory_claim") != "LAB_ONLY":
        raise GateError("hardware regulatory claim exceeds accepted scope")
    check_versions(matrix)
    check_platforms(matrix)
    check_features(matrix)
    cmake = read_text(ROOT / "CMakeLists.txt")
    for install_rule in (
        "install(FILES compatibility-matrix.json\n"
        "    DESTINATION ${CMAKE_INSTALL_DATADIR}/ninlil)",
        "install(FILES dependency-inventory.json\n"
        "    DESTINATION ${CMAKE_INSTALL_DATADIR}/ninlil)",
    ):
        if cmake.count(install_rule) != 1:
            raise GateError(f"missing exact install rule: {install_rule}")


def self_test() -> None:
    baseline = load_matrix()
    check(baseline)

    def reject(label: str, mutation: dict[str, Any]) -> None:
        try:
            check(mutation)
        except GateError:
            return
        raise GateError(f"self-test mutation was accepted: {label}")

    state = copy.deepcopy(baseline)
    state["features"][0]["state"] = "RELEASE_SUPPORTED"
    reject("state above accepted ceiling", state)

    hil = copy.deepcopy(baseline)
    hil["features"][5]["required_hil"] = False
    hil["features"][5]["state"] = "RELEASE_SUPPORTED"
    hil["features"][5].pop("hil_verified")
    reject("required_hil boolean bypass", hil)

    evidence = copy.deepcopy(baseline)
    evidence["features"][0]["evidence"] = [
        ev("status", "LICENSE", "Apache License")
    ]
    reject("arbitrary existing evidence", evidence)

    ceiling = copy.deepcopy(baseline)
    ceiling["features"][5]["state_ceiling"] = "RELEASE_SUPPORTED"
    reject("editable state ceiling", ceiling)

    transitions = copy.deepcopy(baseline)
    transitions["allowed_transitions"]["UNALLOCATED"].append("RELEASE_SUPPORTED")
    reject("direct completion transition", transitions)

    platform = copy.deepcopy(baseline)
    platform["platforms"][2]["required_hil"] = False
    platform["platforms"][2]["state"] = "RELEASE_SUPPORTED"
    platform["platforms"][2].pop("hil_verified")
    reject("platform HIL bypass", platform)

    runner = copy.deepcopy(baseline)
    runner["platforms"][1]["ci_runner"] = "macos-14"
    reject("deprecated/wrong runner", runner)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    try:
        if args.command == "check":
            check(load_matrix())
        else:
            self_test()
    except (GateError, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"compatibility matrix gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"compatibility matrix gate {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
