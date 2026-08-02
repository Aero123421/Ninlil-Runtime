#!/usr/bin/env python3
"""Validate RRMP software/HIL claim boundaries against their authorities."""

from __future__ import annotations

import argparse
import json
import pathlib
import tempfile
from typing import Any


REPO = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO / "tools" / "rrmp_software_hil_manifest.json"
DEFAULT_TEMPLATE = REPO / "tools" / "rrmp_hil_evidence_template.json"
DEFAULT_VECTOR = (
    REPO / "spec" / "vectors" / "route-relay-multiparent-spec-v1.json"
)
DEFAULT_MATRIX = REPO / "compatibility-matrix.json"

EXPECTED_CLAIMS = {
    "spec_accepted": 1,
    "physical_2hop_hil": 0,
    "physical_3hop_hil": 0,
    "physical_multiparent_hil": 0,
    "host_software_hil": 1,
    "implementation_candidate": 1,
    "esp_idf_map_proof": 1,
    "physical_rf_powercut_hil": 0,
}

EXPECTED_SPEC_CLAIMS = {
    "spec_accepted": 1,
    "implementation": 0,
    "hil": 0,
    "release_supported": 0,
    "public_abi": 0,
}


class GateError(ValueError):
    """Closed validation failure."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise GateError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"{path}: root must be an object")
    return value


def require_object(parent: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise GateError(f"{where}.{key} must be an object")
    return value


def require_list(parent: dict[str, Any], key: str, where: str) -> list[Any]:
    value = parent.get(key)
    if not isinstance(value, list):
        raise GateError(f"{where}.{key} must be an array")
    return value


def require_exact(actual: Any, expected: Any, where: str) -> None:
    if actual != expected or isinstance(actual, bool) != isinstance(expected, bool):
        raise GateError(f"{where}: {actual!r} != {expected!r}")


def check_authorities(
    manifest_path: pathlib.Path,
    template_path: pathlib.Path,
    vector_path: pathlib.Path,
    matrix_path: pathlib.Path,
) -> None:
    manifest = read_json(manifest_path)
    template = read_json(template_path)
    vector = read_json(vector_path)
    matrix = read_json(matrix_path)

    require_exact(
        manifest.get("id"),
        "rrmp-software-hil-manifest-v1",
        "manifest.id",
    )
    require_exact(
        manifest.get("software_acceptance"),
        "GO_PRIVATE_SOFTWARE_CANDIDATE",
        "manifest.software_acceptance",
    )
    claims = require_object(manifest, "claims", "manifest")
    if set(claims) != set(EXPECTED_CLAIMS):
        raise GateError("manifest.claims has missing or extra keys")
    for key, expected in EXPECTED_CLAIMS.items():
        require_exact(claims.get(key), expected, f"manifest.claims.{key}")

    open_repairs = require_list(manifest, "open_p1_repairs", "manifest")
    if open_repairs:
        raise GateError("manifest.open_p1_repairs must be empty after repair GO")
    nonclaims = require_list(manifest, "nonclaims", "manifest")
    if "SPEC_ACCEPTED" in nonclaims:
        raise GateError("SPEC_ACCEPTED must not remain a manifest nonclaim")

    authority = require_object(manifest, "authority", "manifest")
    require_exact(authority.get("status"), "SPEC_ACCEPTED", "authority.status")
    require_exact(
        authority.get("vector"),
        "spec/vectors/route-relay-multiparent-spec-v1.json",
        "authority.vector",
    )
    require_exact(
        authority.get("adr"),
        ["docs/adr/0019-route-relay.md", "docs/adr/0020-multi-parent.md"],
        "authority.adr",
    )

    physical_hil = require_object(manifest, "physical_hil", "manifest")
    require_exact(physical_hil.get("status"), "NOT_RUN", "physical_hil.status")
    require_exact(
        physical_hil.get("template"),
        "tools/rrmp_hil_evidence_template.json",
        "physical_hil.template",
    )

    vector_spec = require_object(vector, "spec", "vector")
    require_exact(vector_spec.get("status"), "SPEC_ACCEPTED", "vector.spec.status")
    vector_claims = require_object(vector_spec, "claims", "vector.spec")
    if set(vector_claims) != set(EXPECTED_SPEC_CLAIMS):
        raise GateError("vector.spec.claims has missing or extra keys")
    for key, expected in EXPECTED_SPEC_CLAIMS.items():
        require_exact(
            vector_claims.get(key),
            expected,
            f"vector.spec.claims.{key}",
        )
    require_exact(
        claims["spec_accepted"],
        vector_claims["spec_accepted"],
        "manifest/vector spec_accepted",
    )

    features = matrix.get("features")
    if not isinstance(features, list):
        raise GateError("compatibility-matrix.features must be an array")
    feature_by_id = {
        row.get("id"): row
        for row in features
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    for feature_id in ("relay", "multi-parent-multi-controller"):
        feature = feature_by_id.get(feature_id)
        if not isinstance(feature, dict):
            raise GateError(f"compatibility matrix missing {feature_id}")
        require_exact(
            feature.get("state"),
            "SPEC_ACCEPTED",
            f"compatibility.{feature_id}.state",
        )
        require_exact(
            feature.get("state_ceiling"),
            "SPEC_ACCEPTED",
            f"compatibility.{feature_id}.state_ceiling",
        )
        require_exact(
            feature.get("hil_verified"),
            False,
            f"compatibility.{feature_id}.hil_verified",
        )

    require_exact(template.get("status"), "NOT_RUN", "template.status")
    prerequisites = require_object(
        template, "software_prerequisites", "template"
    )
    require_exact(
        prerequisites.get("spec_accepted"),
        True,
        "template.software_prerequisites.spec_accepted",
    )
    require_exact(
        prerequisites.get("private_implementation_candidate"),
        True,
        "template.software_prerequisites.private_implementation_candidate",
    )
    physical_claims = require_object(template, "physical_claims", "template")
    if not physical_claims or any(value != "NOT_RUN" for value in physical_claims.values()):
        raise GateError("template physical claims must all remain NOT_RUN")
    template_nonclaims = require_list(template, "nonclaims", "template")
    if "SPEC_ACCEPTED without hardware campaign" in template_nonclaims:
        raise GateError("template contains obsolete SPEC_ACCEPTED nonclaim")

    stale_markers = (
        "NO_GO_P1_REPAIR_REQUIRED",
        "P1 repair is open",
        "six software P1 repair",
        '"status": "Proposed"',
    )
    serialized = json.dumps(manifest, sort_keys=True)
    for marker in stale_markers:
        if marker in serialized:
            raise GateError(f"stale manifest marker remains: {marker}")


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )


def expect_rejection(action: Any, label: str) -> None:
    try:
        action()
    except GateError:
        return
    raise GateError(f"self-test accepted mutant: {label}")


def self_test() -> None:
    check_authorities(
        DEFAULT_MANIFEST,
        DEFAULT_TEMPLATE,
        DEFAULT_VECTOR,
        DEFAULT_MATRIX,
    )
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        manifest = read_json(DEFAULT_MANIFEST)
        template = read_json(DEFAULT_TEMPLATE)
        vector = read_json(DEFAULT_VECTOR)
        matrix = read_json(DEFAULT_MATRIX)

        manifest_path = root / "manifest.json"
        template_path = root / "template.json"
        vector_path = root / "vector.json"
        matrix_path = root / "matrix.json"
        write_json(template_path, template)
        write_json(vector_path, vector)
        write_json(matrix_path, matrix)

        mutant = json.loads(json.dumps(manifest))
        mutant["claims"]["spec_accepted"] = 0
        write_json(manifest_path, mutant)
        expect_rejection(
            lambda: check_authorities(
                manifest_path, template_path, vector_path, matrix_path
            ),
            "manifest spec_accepted rollback",
        )

        mutant = json.loads(json.dumps(manifest))
        mutant["open_p1_repairs"] = ["stale repair"]
        write_json(manifest_path, mutant)
        expect_rejection(
            lambda: check_authorities(
                manifest_path, template_path, vector_path, matrix_path
            ),
            "open P1 repair",
        )

        write_json(manifest_path, manifest)
        matrix_mutant = json.loads(json.dumps(matrix))
        for row in matrix_mutant["features"]:
            if row.get("id") == "relay":
                row["state"] = "PROPOSED"
        write_json(matrix_path, matrix_mutant)
        expect_rejection(
            lambda: check_authorities(
                manifest_path, template_path, vector_path, matrix_path
            ),
            "matrix state rollback",
        )

        write_json(matrix_path, matrix)
        template_mutant = json.loads(json.dumps(template))
        template_mutant["physical_claims"]["rf_3hop"] = "PASS"
        write_json(template_path, template_mutant)
        expect_rejection(
            lambda: check_authorities(
                manifest_path, template_path, vector_path, matrix_path
            ),
            "false physical HIL PASS",
        )

    print("rrmp_software_manifest_gate self-test OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("check", "self-test"))
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--template", type=pathlib.Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--vector", type=pathlib.Path, default=DEFAULT_VECTOR)
    parser.add_argument("--matrix", type=pathlib.Path, default=DEFAULT_MATRIX)
    args = parser.parse_args()

    if args.mode == "self-test":
        self_test()
        return 0
    check_authorities(args.manifest, args.template, args.vector, args.matrix)
    print("rrmp_software_manifest_gate OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print(f"rrmp_software_manifest_gate FAIL: {exc}")
        raise SystemExit(1) from exc
