#!/usr/bin/env python3
"""Deterministically enrich and validate the source-release SPDX 2.3 SBOM."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import re
import sys
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "dependency-inventory.json"
TOOL_CREATOR = "Tool: ninlil-spdx-release-sbom-v1"


class SbomError(RuntimeError):
    """A deterministic release-SBOM failure."""


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SbomError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SbomError(f"{path}: top-level JSON value must be an object")
    return value


def inventory_packages(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        packages = [
            inventory["project"],
            *inventory["host_dependencies"],
            *inventory["esp_idf"]["lock_components"],
            *inventory["esp_idf"]["bundled_dependencies"],
        ]
    except (KeyError, TypeError) as exc:
        raise SbomError(f"invalid dependency inventory: {exc}") from exc
    if not all(isinstance(item, dict) for item in packages):
        raise SbomError("dependency inventory packages must be objects")
    return packages


def spdx_id(package_id: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9.-]+", "-", package_id).strip("-")
    if not sanitized:
        raise SbomError(f"invalid package id: {package_id!r}")
    return f"SPDXRef-Ninlil-{sanitized}"


def canonical_package(item: dict[str, Any]) -> dict[str, Any]:
    package_id = str(item["id"])
    package = {
        "SPDXID": spdx_id(package_id),
        "name": str(item["name"]),
        "versionInfo": str(item["version"]),
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": str(item["spdx_license"]),
        "licenseDeclared": str(item["spdx_license"]),
        "copyrightText": "NOASSERTION",
        "supplier": str(item.get("supplier", "NOASSERTION")),
        "primaryPackagePurpose": (
            "SOURCE" if package_id == "ninlil-runtime" else "LIBRARY"
        ),
        "comment": (
            f"Ninlil dependency inventory ID: {package_id}; "
            f"relationship: {item.get('relationship', 'PROJECT')}"
        ),
    }
    component_hash = item.get("component_hash")
    if component_hash is not None:
        package["checksums"] = [
            {
                "algorithm": "SHA256",
                "checksumValue": str(component_hash),
            }
        ]
    requirement = item.get("version_requirement")
    if requirement is not None:
        package["sourceInfo"] = f"Declared version requirement: {requirement}"
    return package


def canonical_relationships(
    inventory: dict[str, Any],
    document_id: str,
) -> list[dict[str, str]]:
    packages = inventory_packages(inventory)
    project_id = spdx_id(str(inventory["project"]["id"]))
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": document_id,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": project_id,
        }
    ]
    for item in packages:
        package_id = str(item["id"])
        if package_id == str(inventory["project"]["id"]):
            continue
        relationships.append(
            {
                "spdxElementId": project_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id(package_id),
            }
        )
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    return relationships


def enrich(raw: dict[str, Any], inventory: dict[str, Any]) -> dict[str, Any]:
    if raw.get("spdxVersion") != "SPDX-2.3":
        raise SbomError("Syft input must be SPDX-2.3")
    document_id = str(raw.get("SPDXID", ""))
    if document_id != "SPDXRef-DOCUMENT":
        raise SbomError("Syft input SPDXID must be SPDXRef-DOCUMENT")
    result = copy.deepcopy(raw)
    canonical = inventory_packages(inventory)
    names = {str(item["name"]) for item in canonical}
    ids = {spdx_id(str(item["id"])) for item in canonical}

    existing_packages = result.get("packages")
    if not isinstance(existing_packages, list):
        raise SbomError("Syft input packages must be an array")
    removed_ids = {
        str(item.get("SPDXID"))
        for item in existing_packages
        if isinstance(item, dict)
        and (
            str(item.get("name")) in names
            or str(item.get("SPDXID")) in ids
        )
    }
    result["packages"] = [
        item
        for item in existing_packages
        if isinstance(item, dict) and str(item.get("SPDXID")) not in removed_ids
    ]
    result["packages"].extend(canonical_package(item) for item in canonical)
    result["packages"].sort(key=lambda item: str(item.get("SPDXID", "")))

    raw_relationships = result.get("relationships", [])
    if not isinstance(raw_relationships, list):
        raise SbomError("Syft input relationships must be an array")
    result["relationships"] = [
        item
        for item in raw_relationships
        if isinstance(item, dict)
        and str(item.get("spdxElementId")) not in removed_ids
        and str(item.get("relatedSpdxElement")) not in removed_ids
        and str(item.get("spdxElementId")) not in ids
        and str(item.get("relatedSpdxElement")) not in ids
    ]
    result["relationships"].extend(canonical_relationships(inventory, document_id))
    result["relationships"].sort(
        key=lambda item: (
            str(item.get("spdxElementId", "")),
            str(item.get("relationshipType", "")),
            str(item.get("relatedSpdxElement", "")),
        )
    )

    creation = result.get("creationInfo")
    if not isinstance(creation, dict):
        raise SbomError("Syft input creationInfo must be an object")
    creators = creation.get("creators")
    if not isinstance(creators, list):
        raise SbomError("Syft input creationInfo.creators must be an array")
    creators = [str(item) for item in creators if str(item) != TOOL_CREATOR]
    creators.append(TOOL_CREATOR)
    creation["creators"] = sorted(creators)
    result["name"] = "ninlil-runtime-source-release"
    return result


def validate(sbom: dict[str, Any], inventory: dict[str, Any]) -> None:
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise SbomError("release SBOM must use SPDX-2.3")
    if sbom.get("dataLicense") != "CC0-1.0":
        raise SbomError("release SBOM dataLicense must be CC0-1.0")
    if sbom.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SbomError("release SBOM document ID mismatch")
    creation = sbom.get("creationInfo")
    if not isinstance(creation, dict) or TOOL_CREATOR not in creation.get("creators", []):
        raise SbomError("release SBOM enrichment creator is absent")
    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise SbomError("release SBOM packages must be an array")
    by_id: dict[str, list[dict[str, Any]]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise SbomError("release SBOM package entry must be an object")
        by_id.setdefault(str(package.get("SPDXID")), []).append(package)

    for item in inventory_packages(inventory):
        expected = canonical_package(item)
        package_id = expected["SPDXID"]
        matches = by_id.get(package_id, [])
        if len(matches) != 1:
            raise SbomError(f"{package_id}: expected exactly one package, got {len(matches)}")
        actual = matches[0]
        for field in (
            "name",
            "versionInfo",
            "licenseDeclared",
            "licenseConcluded",
            "supplier",
            "primaryPackagePurpose",
        ):
            if actual.get(field) != expected.get(field):
                raise SbomError(
                    f"{package_id}: {field} mismatch: "
                    f"{actual.get(field)!r} != {expected.get(field)!r}"
                )
        if actual.get("licenseDeclared") == "NOASSERTION":
            raise SbomError(f"{package_id}: licenseDeclared must not be NOASSERTION")
        if actual.get("licenseConcluded") == "NOASSERTION":
            raise SbomError(f"{package_id}: licenseConcluded must not be NOASSERTION")
        if item.get("component_hash") is not None:
            if actual.get("checksums") != expected.get("checksums"):
                raise SbomError(f"{package_id}: component checksum mismatch")

    relationships = sbom.get("relationships")
    if not isinstance(relationships, list):
        raise SbomError("release SBOM relationships must be an array")
    expected_relationships = canonical_relationships(inventory, "SPDXRef-DOCUMENT")
    for expected in expected_relationships:
        if relationships.count(expected) != 1:
            raise SbomError(f"missing or duplicate canonical relationship: {expected}")


def write_json_atomic(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(payload)
        temp_path = pathlib.Path(handle.name)
    temp_path.replace(path)


def self_test(inventory: dict[str, Any]) -> None:
    raw = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "raw",
        "documentNamespace": "https://example.invalid/raw",
        "creationInfo": {
            "created": "2026-01-01T00:00:00Z",
            "creators": ["Tool: syft-v1.49.0"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-raw-project",
                "name": "Ninlil Runtime",
                "versionInfo": "UNKNOWN",
                "licenseDeclared": "NOASSERTION",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-raw-project",
            }
        ],
    }
    baseline = enrich(raw, inventory)
    validate(baseline, inventory)

    def expect_failure(label: str, mutation: dict[str, Any]) -> None:
        try:
            validate(mutation, inventory)
        except SbomError:
            return
        raise SbomError(f"self-test mutation was accepted: {label}")

    missing = copy.deepcopy(baseline)
    missing["packages"] = [
        item
        for item in missing["packages"]
        if item["SPDXID"] != "SPDXRef-Ninlil-openssl"
    ]
    expect_failure("missing dependency package", missing)

    noassertion = copy.deepcopy(baseline)
    project = next(
        item
        for item in noassertion["packages"]
        if item["SPDXID"] == "SPDXRef-Ninlil-ninlil-runtime"
    )
    project["licenseDeclared"] = "NOASSERTION"
    expect_failure("project license NOASSERTION", noassertion)

    version = copy.deepcopy(baseline)
    sqlite = next(
        item
        for item in version["packages"]
        if item["SPDXID"] == "SPDXRef-Ninlil-sqlite3"
    )
    sqlite["versionInfo"] = "UNKNOWN"
    expect_failure("dependency version drift", version)

    relation = copy.deepcopy(baseline)
    relation["relationships"] = relation["relationships"][:-1]
    expect_failure("missing dependency relationship", relation)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    enrich_parser = subparsers.add_parser("enrich")
    enrich_parser.add_argument("raw_sbom", type=pathlib.Path)
    enrich_parser.add_argument("output_sbom", type=pathlib.Path)
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("sbom", type=pathlib.Path)
    subparsers.add_parser("self-test")
    args = parser.parse_args()
    try:
        inventory = load_json(INVENTORY_PATH)
        if args.command == "enrich":
            value = enrich(load_json(args.raw_sbom), inventory)
            validate(value, inventory)
            write_json_atomic(args.output_sbom, value)
        elif args.command == "check":
            validate(load_json(args.sbom), inventory)
        else:
            self_test(inventory)
    except SbomError as exc:
        print(f"release SPDX SBOM: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"release SPDX SBOM {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
