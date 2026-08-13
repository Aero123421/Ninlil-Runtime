#!/usr/bin/env python3
"""Deterministically enrich and validate the source-release SPDX 2.3 SBOM.

Identical source + inventory must produce byte-identical SPDX JSON across time
and Syft nondeterminism: timestamps, documentNamespace / random IDs, and volatile
source metadata are stripped or replaced with closed constants; arrays are sorted.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import sys
import tempfile
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "dependency-inventory.json"
TOOL_CREATOR = "Tool: ninlil-spdx-release-sbom-v1"
# Closed deterministic document identity (not Syft wall-clock / random namespace).
# Namespace embeds the canonical project core plus a deterministic digest of
# the exact release source identity. Different tags/commits must never identify
# two different SPDX documents with the same namespace.
DOCUMENT_NAMESPACE_PREFIX = "https://spdx.ninlil.invalid/ninlil-runtime"
DOCUMENT_NAMESPACE_SUFFIX = "spdx-2.3"
DOCUMENT_CREATED = "1970-01-01T00:00:00Z"


def document_namespace_for(project_version: str, source_version: str) -> str:
    identity = (
        "ninlil-spdx-document-namespace-v1\0"
        f"{project_version}\0{source_version}"
    ).encode("utf-8")
    source_digest = hashlib.sha256(identity).hexdigest()
    return (
        f"{DOCUMENT_NAMESPACE_PREFIX}/{project_version}/"
        f"{source_digest}/{DOCUMENT_NAMESPACE_SUFFIX}"
    )


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
        vendored = inventory.get("vendored_dependencies", [])
        if not isinstance(vendored, list):
            raise SbomError("vendored_dependencies must be an array")
        project = inventory["project"]
        source_scope = inventory["source_license_scope"]
        if not isinstance(project, dict) or not isinstance(source_scope, dict):
            raise SbomError("project and source_license_scope must be objects")
        if source_scope.get("license_expression") != project.get("spdx_license"):
            raise SbomError("source license scope/project SPDX license mismatch")
        copyright_text = source_scope.get("copyright_text")
        if not isinstance(copyright_text, str) or not copyright_text:
            raise SbomError("source license scope copyright_text must be explicit")
        project_package = dict(project)
        project_package["copyright_text"] = copyright_text
        packages = [
            project_package,
            *inventory["host_dependencies"],
            *inventory.get("host_tooling", []),
            *vendored,
            *inventory["esp_idf"]["lock_components"],
            *inventory["esp_idf"]["bundled_dependencies"],
        ]
    except (KeyError, TypeError) as exc:
        raise SbomError(f"invalid dependency inventory: {exc}") from exc
    if not all(isinstance(item, dict) for item in packages):
        raise SbomError("dependency inventory packages must be objects")
    return packages


def _casefold_names(item: dict[str, Any]) -> set[str]:
    names = {str(item.get("id", "")).casefold(), str(item.get("name", "")).casefold()}
    for alias in item.get("syft_names", []) or []:
        names.add(str(alias).casefold())
    names.discard("")
    return names


def inventory_name_index(inventory: dict[str, Any]) -> dict[str, str]:
    """Map casefolded Syft-visible names → inventory package id."""
    index: dict[str, str] = {}
    for item in inventory_packages(inventory):
        package_id = str(item["id"])
        for name in _casefold_names(item):
            prior = index.get(name)
            if prior is not None and prior != package_id:
                raise SbomError(
                    "ambiguous Syft package alias in dependency inventory: "
                    f"{name!r} maps to both {prior!r} and {package_id!r}"
                )
            index[name] = package_id
    return index


def justified_exclusion_names(inventory: dict[str, Any]) -> dict[str, str]:
    recon = inventory.get("syft_reconciliation", {})
    if recon is None:
        recon = {}
    if not isinstance(recon, dict):
        raise SbomError("syft_reconciliation must be an object")
    raw = recon.get("justified_exclusions", [])
    if not isinstance(raw, list):
        raise SbomError("syft_reconciliation.justified_exclusions must be an array")
    out: dict[str, str] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise SbomError(f"justified_exclusions[{index}] must be an object")
        name = item.get("name")
        reason = item.get("reason")
        if not isinstance(name, str) or not name.strip():
            raise SbomError(f"justified_exclusions[{index}].name must be a string")
        if not isinstance(reason, str) or not reason.strip():
            raise SbomError(
                f"justified_exclusions[{index}].reason must be a non-empty string"
            )
        out[name.casefold()] = reason.strip()
    return out


def reconcile_syft_packages(
    raw_packages: list[Any],
    inventory: dict[str, Any],
    source_version: str,
) -> None:
    """Fail closed unless every Syft source discovery has an exact identity."""
    name_index = inventory_name_index(inventory)
    packages_by_id = {
        str(item["id"]): item for item in inventory_packages(inventory)
    }
    exclusions = justified_exclusion_names(inventory)
    project_id = str(inventory["project"]["id"])
    expected_project_spdx_id = "SPDXRef-DocumentRoot-Directory-ninlil-runtime"
    project_roots = 0

    for index, package in enumerate(raw_packages):
        if not isinstance(package, dict):
            raise SbomError(f"Syft packages[{index}] must be an object")
        name = str(package.get("name", "")).strip()
        if not name:
            raise SbomError(f"Syft packages[{index}].name must be a non-empty string")
        name_key = name.casefold()
        inventory_id = name_index.get(name_key)
        if inventory_id is not None:
            item = packages_by_id[inventory_id]
            if inventory_id == project_id:
                # The pinned directory scan emits one synthetic source root.
                # A package manager may also discover a dependency with the
                # project name, so name equality alone is never sufficient.
                raw_spdx_id = str(package.get("SPDXID", ""))
                raw_version = str(package.get("versionInfo", "")).strip()
                raw_source = str(package.get("sourceInfo") or "").strip()
                raw_refs = package.get("externalRefs")
                if (
                    raw_spdx_id != expected_project_spdx_id
                    or raw_version != source_version
                    or raw_source
                    or raw_refs not in (None, [])
                ):
                    raise SbomError(
                        "Syft package collides with project name without the "
                        "exact synthetic source-root identity: "
                        f"name={name!r} SPDXID={raw_spdx_id!r} "
                        f"version={raw_version!r} sourceInfo={raw_source!r}"
                    )
                project_roots += 1
                continue

            source_path = item.get("source_path")
            if not isinstance(source_path, str) or not source_path.strip():
                raise SbomError(
                    "Syft source discovery matched a non-vendored inventory "
                    f"package: name={name!r} inventory_id={inventory_id!r}"
                )
            raw_version = str(package.get("versionInfo", "")).strip()
            expected_version = str(item.get("version", "")).strip()
            if raw_version != expected_version:
                raise SbomError(
                    "Syft vendored package version does not match inventory: "
                    f"name={name!r} raw={raw_version!r} "
                    f"expected={expected_version!r}"
                )
            raw_source = str(package.get("sourceInfo", "")).strip().replace("\\", "/")
            expected_source = source_path.strip().replace("\\", "/").rstrip("/")
            source_root_pattern = re.compile(
                rf"(?:^|[\s,:])/?{re.escape(expected_source)}(?:/|$)"
            )
            if not raw_source or source_root_pattern.search(raw_source) is None:
                raise SbomError(
                    "Syft vendored package source path does not match inventory: "
                    f"name={name!r} raw={raw_source!r} "
                    f"expected_root={expected_source!r}"
                )
            continue
        if name_key in exclusions:
            continue
        raise SbomError(
            "Syft package discarded without inventory entry or exact "
            f"justified exclusion: name={name!r} version="
            f"{package.get('versionInfo')!r}"
        )
    if project_roots != 1:
        raise SbomError(
            "Syft source scan must contain exactly one synthetic project root: "
            f"got {project_roots}"
        )


def spdx_id(package_id: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9.-]+", "-", package_id).strip("-")
    if not sanitized:
        raise SbomError(f"invalid package id: {package_id!r}")
    return f"SPDXRef-Ninlil-{sanitized}"


def canonical_package(item: dict[str, Any]) -> dict[str, Any]:
    package_id = str(item["id"])
    relationship = str(item.get("relationship", "PROJECT"))
    package = {
        "SPDXID": spdx_id(package_id),
        "name": str(item["name"]),
        "versionInfo": str(item["version"]),
        "downloadLocation": str(
            item.get("download_location", "NOASSERTION")
        ),
        "filesAnalyzed": False,
        "licenseConcluded": str(item["spdx_license"]),
        "licenseDeclared": str(item["spdx_license"]),
        "copyrightText": str(item.get("copyright_text", "NOASSERTION")),
        "supplier": str(item.get("supplier", "NOASSERTION")),
        "primaryPackagePurpose": (
            "SOURCE"
            if package_id == "ninlil-runtime"
            else "APPLICATION"
            if relationship == "BUILD_TOOL"
            else "LIBRARY"
        ),
        "comment": (
            f"Ninlil dependency inventory ID: {package_id}; "
            f"relationship: {relationship}"
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
        package_spdx_id = spdx_id(package_id)
        if str(item.get("relationship", "")) == "BUILD_TOOL":
            relationships.append(
                {
                    "spdxElementId": package_spdx_id,
                    "relationshipType": "BUILD_TOOL_OF",
                    "relatedSpdxElement": project_id,
                }
            )
        else:
            relationships.append(
                {
                    "spdxElementId": project_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package_spdx_id,
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


def _canonicalize_package_entry(package: dict[str, Any]) -> dict[str, Any]:
    """Drop volatile Syft source metadata; keep stable identity/license fields."""
    stable = copy.deepcopy(package)
    # Keep filesAnalyzed if present on inventory packages; strip Syft noise keys
    # that vary across runs (random IDs already handled via SPDXID filter).
    for key in (
        "annotations",
        "attributionTexts",
        "externalRefs",
        "hasFiles",
        "packageVerificationCode",
        "sourceInfo",
    ):
        # Inventory packages may intentionally set sourceInfo for version
        # requirements; only strip non-canonical Syft leftovers later.
        if key == "sourceInfo" and str(stable.get("SPDXID", "")).startswith(
            "SPDXRef-Ninlil-"
        ):
            continue
        stable.pop(key, None)
    # Sort nested arrays for byte-identity.
    if isinstance(stable.get("checksums"), list):
        stable["checksums"] = sorted(
            stable["checksums"],
            key=lambda item: (
                str(item.get("algorithm", "")) if isinstance(item, dict) else "",
                str(item.get("checksumValue", "")) if isinstance(item, dict) else "",
            ),
        )
    if isinstance(stable.get("licenseInfoFromFiles"), list):
        stable["licenseInfoFromFiles"] = sorted(
            str(item) for item in stable["licenseInfoFromFiles"]
        )
    return stable


def enrich(
    raw: dict[str, Any],
    inventory: dict[str, Any],
    *,
    project_version: str | None = None,
    source_version: str | None = None,
) -> dict[str, Any]:
    if raw.get("spdxVersion") != "SPDX-2.3":
        raise SbomError("Syft input must be SPDX-2.3")
    document_id = str(raw.get("SPDXID", ""))
    if document_id != "SPDXRef-DOCUMENT":
        raise SbomError("Syft input SPDXID must be SPDXRef-DOCUMENT")
    raw_packages = raw.get("packages")
    if not isinstance(raw_packages, list):
        raise SbomError("Syft input packages must be an array")
    if not isinstance(raw.get("relationships", []), list):
        raise SbomError("Syft input relationships must be an array")

    inv_version = str(inventory["project"]["version"])
    if project_version is None:
        project_version = inv_version
    if project_version != inv_version:
        raise SbomError(
            f"project_version {project_version!r} must equal inventory "
            f"project.version {inv_version!r}"
        )
    # Preserve Syft --source-version (tag or commit) when provided; otherwise
    # fall back to project core so identity is never empty.
    if source_version is None or not str(source_version).strip():
        # Prefer the pinned Syft synthetic directory-root identity. A package
        # manager discovery with the project name must not select the source
        # version used for reconciliation.
        syft_source = None
        for pkg in raw_packages:
            if (
                isinstance(pkg, dict)
                and pkg.get("SPDXID")
                == "SPDXRef-DocumentRoot-Directory-ninlil-runtime"
            ):
                syft_source = pkg.get("versionInfo")
                break
        source_version = (
            str(syft_source).strip()
            if syft_source and str(syft_source).strip() not in {"", "UNKNOWN"}
            else project_version
        )
    source_version = str(source_version).strip()
    if not source_version:
        raise SbomError("source_version must be non-empty")

    # Reconcile every Syft discovery before emitting the closed inventory set.
    # No discovery may be dropped without an inventory entry or an exact,
    # machine-readable justified exclusion.
    reconcile_syft_packages(raw_packages, inventory, source_version)

    # Emit canonical inventory packages only (deterministic; includes vendored).
    packages = [
        _canonicalize_package_entry(canonical_package(item))
        for item in inventory_packages(inventory)
    ]
    # Bind project package to release identity (core + preserved source version).
    project_spdx = spdx_id(str(inventory["project"]["id"]))
    for package in packages:
        if package.get("SPDXID") == project_spdx:
            package["versionInfo"] = project_version
            package["sourceInfo"] = (
                f"Ninlil release identity: project_version={project_version}; "
                f"source_version={source_version}"
            )
            package["comment"] = (
                f"Ninlil dependency inventory ID: {inventory['project']['id']}; "
                f"relationship: PROJECT; source_version={source_version}"
            )
    packages.sort(key=lambda item: str(item.get("SPDXID", "")))
    relationships = canonical_relationships(inventory, "SPDXRef-DOCUMENT")

    creators_raw = raw.get("creationInfo", {})
    if not isinstance(creators_raw, dict):
        raise SbomError("Syft input creationInfo must be an object")
    creators_in = creators_raw.get("creators")
    if not isinstance(creators_in, list):
        raise SbomError("Syft input creationInfo.creators must be an array")
    creators = [
        str(item)
        for item in creators_in
        if str(item) != TOOL_CREATOR
        and not str(item).startswith("Person:")
        and not str(item).startswith("Organization:")
    ]
    creators.append(TOOL_CREATOR)
    # Keep only Tool: creators for determinism.
    creators = sorted({c for c in creators if c.startswith("Tool:")})

    result: dict[str, Any] = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": f"ninlil-runtime-source-release-{project_version}",
        "documentNamespace": document_namespace_for(project_version, source_version),
        "creationInfo": {
            "created": DOCUMENT_CREATED,
            "creators": creators,
        },
        "packages": packages,
        "relationships": relationships,
    }
    return result


def validate(
    sbom: dict[str, Any],
    inventory: dict[str, Any],
    *,
    project_version: str | None = None,
    source_version: str | None = None,
) -> None:
    # Minimal SPDX-2.3 document schema (closed field set for release SBOM).
    allowed_top = {
        "SPDXID",
        "spdxVersion",
        "dataLicense",
        "name",
        "documentNamespace",
        "creationInfo",
        "packages",
        "relationships",
    }
    if not isinstance(sbom, dict) or set(sbom) != allowed_top:
        raise SbomError(
            f"release SBOM top-level fields are not closed: {sorted(sbom) if isinstance(sbom, dict) else type(sbom)}"
        )
    if sbom.get("spdxVersion") != "SPDX-2.3":
        raise SbomError("release SBOM must use SPDX-2.3")
    if sbom.get("dataLicense") != "CC0-1.0":
        raise SbomError("release SBOM dataLicense must be CC0-1.0")
    if sbom.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise SbomError("release SBOM document ID mismatch")
    inv_version = str(inventory["project"]["version"])
    if project_version is None:
        project_version = inv_version
    if project_version != inv_version:
        raise SbomError(
            f"project_version {project_version!r} must equal inventory "
            f"project.version {inv_version!r}"
        )
    if source_version is None:
        project_spdx = spdx_id(str(inventory["project"]["id"]))
        raw_packages = sbom.get("packages")
        if not isinstance(raw_packages, list):
            raise SbomError("release SBOM packages must be an array")
        project_candidates = [
            package
            for package in raw_packages
            if isinstance(package, dict) and package.get("SPDXID") == project_spdx
        ]
        if len(project_candidates) != 1:
            raise SbomError(
                "release SBOM must contain exactly one project package before "
                "document namespace validation"
            )
        source_info = str(project_candidates[0].get("sourceInfo", ""))
        match = re.search(r"(?:^|;\s*)source_version=([^;]+)(?:;|$)", source_info)
        if match is None or not match.group(1).strip():
            raise SbomError(
                "release SBOM project sourceInfo cannot supply source_version "
                "for document namespace"
            )
        source_version = match.group(1).strip()
    else:
        source_version = str(source_version).strip()
    if not source_version:
        raise SbomError("source_version must be non-empty for document namespace")
    expected_namespace = document_namespace_for(project_version, source_version)
    if sbom.get("documentNamespace") != expected_namespace:
        raise SbomError(
            "release SBOM documentNamespace is not canonical for project/source "
            f"identity {project_version!r}/{source_version!r}: "
            f"{sbom.get('documentNamespace')!r}"
        )
    expected_name = f"ninlil-runtime-source-release-{project_version}"
    if sbom.get("name") != expected_name:
        raise SbomError(
            f"release SBOM name is not canonical: {sbom.get('name')!r} "
            f"!= {expected_name!r}"
        )
    # Reject volatile leftovers if present via non-closed schema already handled.
    for volatile in ("builtDate", "comment", "annotations", "files"):
        if volatile in sbom:
            raise SbomError(f"release SBOM must not carry volatile field {volatile}")

    creation = sbom.get("creationInfo")
    if not isinstance(creation, dict) or set(creation) != {"created", "creators"}:
        raise SbomError("release SBOM creationInfo fields are not closed")
    if TOOL_CREATOR not in creation.get("creators", []):
        raise SbomError("release SBOM enrichment creator is absent")
    if creation.get("created") != DOCUMENT_CREATED:
        raise SbomError("release SBOM creationInfo.created is not canonical")

    packages = sbom.get("packages")
    if not isinstance(packages, list):
        raise SbomError("release SBOM packages must be an array")
    by_id: dict[str, list[dict[str, Any]]] = {}
    for package in packages:
        if not isinstance(package, dict):
            raise SbomError("release SBOM package entry must be an object")
        pid = str(package.get("SPDXID", ""))
        if not pid:
            raise SbomError("release SBOM package missing SPDXID")
        by_id.setdefault(pid, []).append(package)

    # Global SPDXID uniqueness (including document id).
    if "SPDXRef-DOCUMENT" in by_id:
        raise SbomError("package SPDXID collides with SPDXRef-DOCUMENT")
    for pid, matches in by_id.items():
        if len(matches) != 1:
            raise SbomError(f"duplicate SPDXID {pid!r}: count={len(matches)}")

    expected_packages = inventory_packages(inventory)
    expected_ids = {spdx_id(str(item["id"])) for item in expected_packages}
    actual_ids = set(by_id)
    if actual_ids != expected_ids:
        raise SbomError(
            "release SBOM package set is not closed inventory: "
            f"extra={sorted(actual_ids - expected_ids)} "
            f"missing={sorted(expected_ids - actual_ids)}"
        )

    project_spdx = spdx_id(str(inventory["project"]["id"]))
    for item in expected_packages:
        expected = canonical_package(item)
        package_id = expected["SPDXID"]
        actual = by_id[package_id][0]
        # Project package version is the release core identity.
        if package_id == project_spdx:
            expected = copy.deepcopy(expected)
            expected["versionInfo"] = project_version
        for field in (
            "name",
            "versionInfo",
            "downloadLocation",
            "licenseDeclared",
            "licenseConcluded",
            "filesAnalyzed",
            "copyrightText",
            "supplier",
            "primaryPackagePurpose",
        ):
            if actual.get(field) != expected.get(field):
                raise SbomError(
                    f"{package_id}: {field} mismatch: "
                    f"{actual.get(field)!r} != {expected.get(field)!r}"
                )
        if package_id == project_spdx:
            source_info = str(actual.get("sourceInfo", ""))
            if f"project_version={project_version}" not in source_info:
                raise SbomError(
                    f"{package_id}: sourceInfo missing project_version identity"
                )
            if source_version is not None:
                if f"source_version={source_version}" not in source_info:
                    raise SbomError(
                        f"{package_id}: sourceInfo missing source_version="
                        f"{source_version!r}"
                    )
            elif "source_version=" not in source_info:
                raise SbomError(f"{package_id}: sourceInfo missing source_version")
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
    if relationships != expected_relationships:
        raise SbomError("release SBOM relationships are not the closed canonical set")
    # All local relationship endpoints must resolve.
    known = {"SPDXRef-DOCUMENT"} | expected_ids
    for rel in relationships:
        if not isinstance(rel, dict):
            raise SbomError("relationship entry must be an object")
        left = str(rel.get("spdxElementId", ""))
        right = str(rel.get("relatedSpdxElement", ""))
        if left not in known:
            raise SbomError(f"dangling relationship spdxElementId: {left!r}")
        if right not in known:
            raise SbomError(f"dangling relationship relatedSpdxElement: {right!r}")


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


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


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
                "SPDXID": "SPDXRef-DocumentRoot-Directory-ninlil-runtime",
                "name": "ninlil-runtime",
                "versionInfo": str(inventory["project"]["version"]),
                "licenseDeclared": "NOASSERTION",
            },
            {
                "SPDXID": "SPDXRef-syft-pyyaml",
                "name": "pyyaml",
                "versionInfo": "6.0.2",
                "licenseDeclared": "MIT",
                "downloadLocation": "https://pypi.org/project/PyYAML/6.0.2/",
                "sourceInfo": (
                    "acquired package info from installed python package manifest "
                    "file: /tools/_vendor/pyyaml-6.0.2.dist-info/METADATA"
                ),
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-DocumentRoot-Directory-ninlil-runtime",
            }
        ],
    }
    baseline = enrich(raw, inventory)
    validate(baseline, inventory)
    pyyaml_ids = [
        p["SPDXID"] for p in baseline["packages"] if p.get("name") == "PyYAML"
    ]
    if pyyaml_ids != ["SPDXRef-Ninlil-pyyaml"]:
        raise SbomError(f"enriched SBOM missing vendored PyYAML package: {pyyaml_ids!r}")
    node_build_relationship = {
        "spdxElementId": "SPDXRef-Ninlil-nodejs",
        "relationshipType": "BUILD_TOOL_OF",
        "relatedSpdxElement": "SPDXRef-Ninlil-ninlil-runtime",
    }
    node = next(
        package
        for package in baseline["packages"]
        if package.get("SPDXID") == "SPDXRef-Ninlil-nodejs"
    )
    if node.get("primaryPackagePurpose") != "APPLICATION":
        raise SbomError("Node.js host tooling is not classified as an APPLICATION")
    if node_build_relationship not in baseline["relationships"]:
        raise SbomError("Node.js BUILD_TOOL_OF project relationship is absent")

    # Two-run determinism: mutated Syft timestamp/namespace must yield byte-identical
    # enriched SPDX JSON for identical source inventory.
    raw_b = copy.deepcopy(raw)
    raw_b["documentNamespace"] = "https://example.invalid/raw-" + ("a" * 32)
    raw_b["creationInfo"]["created"] = "2099-12-31T23:59:59Z"
    raw_b["creationInfo"]["creators"] = [
        "Tool: syft-v1.49.0",
        "Person: nondeterministic",
    ]
    raw_b["comment"] = "volatile syft comment"
    second = enrich(raw_b, inventory)
    validate(second, inventory)
    if canonical_json_bytes(baseline) != canonical_json_bytes(second):
        raise SbomError(
            "self-test two-run determinism failed: mutated timestamp/namespace "
            "changed enriched SBOM bytes"
        )

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

    guessed_holder = copy.deepcopy(baseline)
    guessed_project = next(
        item
        for item in guessed_holder["packages"]
        if item["SPDXID"] == "SPDXRef-Ninlil-ninlil-runtime"
    )
    guessed_project["copyrightText"] = "Copyright guessed-holder"
    expect_failure("project copyright differs from source inventory", guessed_holder)

    version = copy.deepcopy(baseline)
    sqlite = next(
        item
        for item in version["packages"]
        if item["SPDXID"] == "SPDXRef-Ninlil-sqlite3"
    )
    sqlite["versionInfo"] = "UNKNOWN"
    expect_failure("dependency version drift", version)

    node_purpose = copy.deepcopy(baseline)
    node_package = next(
        item
        for item in node_purpose["packages"]
        if item["SPDXID"] == "SPDXRef-Ninlil-nodejs"
    )
    node_package["primaryPackagePurpose"] = "LIBRARY"
    expect_failure("Node.js build tool misclassified as library", node_purpose)

    node_relation = copy.deepcopy(baseline)
    node_relation["relationships"] = [
        {
            "spdxElementId": "SPDXRef-Ninlil-ninlil-runtime",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-Ninlil-nodejs",
        }
        if item == node_build_relationship
        else item
        for item in node_relation["relationships"]
    ]
    node_relation["relationships"].sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    expect_failure("Node.js dependency relation is not BUILD_TOOL_OF", node_relation)

    duplicate = copy.deepcopy(baseline)
    duplicate["packages"].append(
        {
            "SPDXID": "SPDXRef-duplicate-project",
            "name": "ninlil-runtime",
            "versionInfo": "UNKNOWN",
            "licenseDeclared": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
        }
    )
    expect_failure("duplicate project alias with NOASSERTION", duplicate)

    relation = copy.deepcopy(baseline)
    relation["relationships"] = relation["relationships"][:-1]
    expect_failure("missing dependency relationship", relation)

    nondet_ns = copy.deepcopy(baseline)
    nondet_ns["documentNamespace"] = "https://example.invalid/drift"
    expect_failure("noncanonical documentNamespace", nondet_ns)

    nondet_ts = copy.deepcopy(baseline)
    nondet_ts["creationInfo"]["created"] = "2026-07-29T00:00:00Z"
    expect_failure("noncanonical creation timestamp", nondet_ts)

    dangling = copy.deepcopy(baseline)
    dangling["relationships"] = list(dangling["relationships"]) + [
        {
            "spdxElementId": "SPDXRef-missing",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-ghost",
        }
    ]
    expect_failure("dangling relationship", dangling)

    dup_id = copy.deepcopy(baseline)
    dup_id["packages"] = list(dup_id["packages"]) + [
        {
            "SPDXID": "SPDXRef-Ninlil-openssl",
            "name": "dup",
            "versionInfo": "x",
            "licenseDeclared": "MIT",
            "licenseConcluded": "MIT",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "comment": "dup",
        }
    ]
    expect_failure("duplicate non-inventory-colliding SPDXID", dup_id)

    extra_pkg = copy.deepcopy(baseline)
    extra_pkg["packages"] = list(extra_pkg["packages"]) + [
        {
            "SPDXID": "SPDXRef-random-xyz",
            "name": "random",
            "versionInfo": "1",
            "licenseDeclared": "MIT",
            "licenseConcluded": "MIT",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "copyrightText": "NOASSERTION",
            "supplier": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "comment": "noise",
        }
    ]
    expect_failure("extra random package ID outside inventory", extra_pkg)

    built = copy.deepcopy(baseline)
    built["builtDate"] = "2026-07-29T00:00:00Z"
    expect_failure("builtDate nondeterminism field", built)

    # Enrich must drop dangling relationships and volatile builtDate metadata.
    raw_noise = copy.deepcopy(raw)
    raw_noise["builtDate"] = "2026-07-29T00:00:00Z"
    raw_noise["relationships"].append(
        {
            "spdxElementId": "SPDXRef-missing",
            "relationshipType": "DEPENDS_ON",
            "relatedSpdxElement": "SPDXRef-ghost",
        }
    )
    cleaned = enrich(raw_noise, inventory)
    validate(cleaned, inventory)
    if "builtDate" in cleaned:
        raise SbomError("enrich left builtDate")

    # Every newly discovered package is closed-world: unknown packages may not
    # be silently classified as noise and omitted from the release SBOM.
    raw_unknown = copy.deepcopy(raw)
    raw_unknown["packages"].append(
        {
            "SPDXID": "SPDXRef-surprise-vendored-library",
            "name": "surprise-vendored-library",
            "versionInfo": "9.8.7",
            "licenseDeclared": "MIT",
            "sourceInfo": "vendor/surprise/package.json",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/surprise-vendored-library@9.8.7",
                }
            ],
        }
    )
    try:
        enrich(raw_unknown, inventory)
    except SbomError:
        pass
    else:
        raise SbomError("self-test silently dropped an unknown Syft package")

    # A familiar name may not launder a different version or source identity.
    raw_wrong_pyyaml_version = copy.deepcopy(raw)
    raw_wrong_pyyaml_version["packages"][1]["versionInfo"] = "999.0.0"
    raw_wrong_pyyaml_version["packages"][1]["sourceInfo"] = (
        "tools/_vendor/pyyaml-999.0.0.dist-info"
    )
    try:
        enrich(raw_wrong_pyyaml_version, inventory)
    except SbomError:
        pass
    else:
        raise SbomError("self-test accepted mismatched vendored PyYAML version")

    raw_wrong_pyyaml_source = copy.deepcopy(raw)
    raw_wrong_pyyaml_source["packages"][1]["sourceInfo"] = (
        "vendor/unrelated/pyyaml/package.json"
    )
    try:
        enrich(raw_wrong_pyyaml_source, inventory)
    except SbomError:
        pass
    else:
        raise SbomError("self-test accepted mismatched vendored PyYAML source path")

    raw_source_openssl = copy.deepcopy(raw)
    raw_source_openssl["packages"].append(
        {
            "SPDXID": "SPDXRef-source-openssl",
            "name": "OpenSSL",
            "versionInfo": "evil-9",
            "licenseDeclared": "Apache-2.0",
            "sourceInfo": "vendor/unrelated/package.json",
        }
    )
    try:
        enrich(raw_source_openssl, inventory)
    except SbomError:
        pass
    else:
        raise SbomError("self-test accepted source package posing as host OpenSSL")

    raw_project_collision = copy.deepcopy(raw)
    raw_project_collision["packages"].insert(
        0,
        {
            "SPDXID": "SPDXRef-Package-npm-ninlil-runtime-collision",
            "name": "ninlil-runtime",
            "versionInfo": "99.9.9",
            "licenseDeclared": "MIT",
            "sourceInfo": (
                "acquired package info from installed node module manifest "
                "file: /package-lock.json"
            ),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:npm/ninlil-runtime@99.9.9",
                }
            ],
        },
    )
    try:
        enrich(raw_project_collision, inventory)
    except SbomError:
        pass
    else:
        raise SbomError("self-test accepted npm package posing as project root")

    raw_project_version = copy.deepcopy(raw)
    raw_project_version["packages"][0]["versionInfo"] = "wrong-source-version"
    try:
        enrich(
            raw_project_version,
            inventory,
            source_version=str(inventory["project"]["version"]),
        )
    except SbomError:
        pass
    else:
        raise SbomError("self-test accepted project root source-version drift")

    # In-scope Syft PyYAML without inventory entry must fail (no silent drop).
    inv_no_pyyaml = copy.deepcopy(inventory)
    inv_no_pyyaml["vendored_dependencies"] = [
        item
        for item in inv_no_pyyaml.get("vendored_dependencies", [])
        if str(item.get("id")) != "pyyaml"
    ]
    try:
        enrich(raw, inv_no_pyyaml)
    except SbomError:
        pass
    else:
        raise SbomError(
            "self-test accepted Syft pyyaml with inventory missing vendored PyYAML"
        )

    # Explicit justified exclusion may drop an in-scope Syft package not in inventory.
    inv_excluded = copy.deepcopy(inv_no_pyyaml)
    inv_excluded["syft_reconciliation"] = {
        "justified_exclusions": [
            {
                "name": "pyyaml",
                "reason": "test-only exclusion; production inventory must list PyYAML",
            }
        ]
    }
    excluded = enrich(raw, inv_excluded)
    validate(excluded, inv_excluded)
    if any(p.get("name") == "PyYAML" for p in excluded["packages"]):
        raise SbomError("justified exclusion path still emitted PyYAML package")

    # validate() must reject enriched SBOM that lost the inventory PyYAML entry.
    missing_pyyaml = copy.deepcopy(baseline)
    missing_pyyaml["packages"] = [
        p for p in missing_pyyaml["packages"] if p.get("SPDXID") != "SPDXRef-Ninlil-pyyaml"
    ]
    expect_failure("discarded vendored PyYAML package from SBOM", missing_pyyaml)

    pyyaml_download_drift = copy.deepcopy(baseline)
    pyyaml_package = next(
        package
        for package in pyyaml_download_drift["packages"]
        if package.get("SPDXID") == "SPDXRef-Ninlil-pyyaml"
    )
    pyyaml_package["downloadLocation"] = "NOASSERTION"
    expect_failure(
        "vendored PyYAML download location drift",
        pyyaml_download_drift,
    )

    # Release identity: wrong project core must fail; source_version must be kept.
    core = str(inventory["project"]["version"])
    raw_bound = copy.deepcopy(raw)
    raw_bound["packages"][0]["versionInfo"] = f"v{core}-rc.1"
    bound = enrich(
        raw_bound,
        inventory,
        project_version=core,
        source_version=f"v{core}-rc.1",
    )
    validate(bound, inventory, project_version=core, source_version=f"v{core}-rc.1")
    raw_bound_other = copy.deepcopy(raw)
    raw_bound_other["packages"][0]["versionInfo"] = f"v{core}-rc.2"
    bound_other_source = enrich(
        raw_bound_other,
        inventory,
        project_version=core,
        source_version=f"v{core}-rc.2",
    )
    validate(
        bound_other_source,
        inventory,
        project_version=core,
        source_version=f"v{core}-rc.2",
    )
    if bound_other_source["documentNamespace"] == bound["documentNamespace"]:
        raise SbomError(
            "different source identities produced the same SPDX documentNamespace"
        )
    if canonical_json_bytes(bound_other_source) == canonical_json_bytes(bound):
        raise SbomError("different source identities produced identical SPDX bytes")
    project = next(
        p for p in bound["packages"] if p["SPDXID"] == "SPDXRef-Ninlil-ninlil-runtime"
    )
    if project.get("versionInfo") != core:
        raise SbomError("project versionInfo not bound to core")
    if f"source_version=v{core}-rc.1" not in str(project.get("sourceInfo", "")):
        raise SbomError("Syft/source_version not preserved in project sourceInfo")
    try:
        enrich(raw, inventory, project_version="9.9.9")
    except SbomError:
        pass
    else:
        raise SbomError("self-test accepted wrong project_version vs inventory")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    enrich_parser = subparsers.add_parser("enrich")
    enrich_parser.add_argument("raw_sbom", type=pathlib.Path)
    enrich_parser.add_argument("output_sbom", type=pathlib.Path)
    enrich_parser.add_argument(
        "--project-version",
        default=None,
        help="Canonical core project version (must match inventory)",
    )
    enrich_parser.add_argument(
        "--source-version",
        default=None,
        help="Syft/source identity (tag or commit); preserved in project sourceInfo",
    )
    check_parser = subparsers.add_parser("check")
    check_parser.add_argument("sbom", type=pathlib.Path)
    check_parser.add_argument("--project-version", default=None)
    check_parser.add_argument("--source-version", default=None)
    subparsers.add_parser("self-test")
    args = parser.parse_args()
    try:
        inventory = load_json(INVENTORY_PATH)
        if args.command == "enrich":
            value = enrich(
                load_json(args.raw_sbom),
                inventory,
                project_version=args.project_version,
                source_version=args.source_version,
            )
            validate(
                value,
                inventory,
                project_version=args.project_version,
                source_version=args.source_version,
            )
            write_json_atomic(args.output_sbom, value)
        elif args.command == "check":
            validate(
                load_json(args.sbom),
                inventory,
                project_version=args.project_version,
                source_version=args.source_version,
            )
        else:
            self_test(inventory)
    except SbomError as exc:
        print(f"release SPDX SBOM: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"release SPDX SBOM {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
