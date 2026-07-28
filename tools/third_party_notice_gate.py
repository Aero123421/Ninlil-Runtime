#!/usr/bin/env python3
"""Validate the closed direct/transitive dependency and notice inventory."""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import re
import sys
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "dependency-inventory.json"


class GateError(RuntimeError):
    """A deterministic dependency-inventory validation failure."""


@dataclass
class Inputs:
    cmake: str
    sqlite_cmake: str
    component: str
    smoke_lock: str
    hil_lock: str
    notices: str
    release_workflow: str
    inventory: dict[str, Any]


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc


def load() -> Inputs:
    try:
        inventory = json.loads(read("dependency-inventory.json"))
    except json.JSONDecodeError as exc:
        raise GateError(f"dependency-inventory.json is invalid JSON: {exc}") from exc
    if not isinstance(inventory, dict):
        raise GateError("dependency inventory must be an object")
    return Inputs(
        cmake=read("CMakeLists.txt"),
        sqlite_cmake=read("cmake/ninlil_posix_sqlite_sqlite3.cmake"),
        component=read("ports/esp-idf/components/ninlil/idf_component.yml"),
        smoke_lock=read("ports/esp-idf/smoke_app/dependencies.lock"),
        hil_lock=read("ports/esp-idf/hil_app/dependencies.lock"),
        notices=read("THIRD-PARTY-NOTICES.md"),
        release_workflow=read(".github/workflows/release.yml"),
        inventory=inventory,
    )


def exact(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise GateError(f"{label}: expected one match, got {len(matches)}")
    value = matches[0]
    if isinstance(value, tuple):
        raise GateError(f"{label}: internal pattern must have one capture")
    return value


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError(f"{label} must be an object")
    return value


def require_array(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise GateError(f"{label} must be an array")
    return value


def parse_lock(lock: str, label: str) -> tuple[dict[str, dict[str, str | None]], list[str]]:
    dependency_section = exact(
        lock,
        r"(?ms)^dependencies:\s*$\n(.*?)(?=^direct_dependencies:)",
        f"{label} dependencies section",
    )
    headers = list(
        re.finditer(r"(?m)^  ([^\s][^:]*):\s*$", dependency_section)
    )
    components: dict[str, dict[str, str | None]] = {}
    for index, match in enumerate(headers):
        component_id = match.group(1)
        end = headers[index + 1].start() if index + 1 < len(headers) else len(
            dependency_section
        )
        block = dependency_section[match.end() : end]
        version = exact(
            block,
            r"(?m)^\s{4}version:\s+'?([^'\s]+)'?\s*$",
            f"{label} {component_id} version",
        )
        hashes = re.findall(
            r"(?m)^\s{4}component_hash:\s*([0-9a-f]{64})\s*$",
            block,
        )
        if len(hashes) > 1:
            raise GateError(f"{label} {component_id}: duplicate component_hash")
        components[component_id] = {
            "version": version,
            "component_hash": hashes[0] if hashes else None,
        }
    direct_block = exact(
        lock,
        r"(?ms)^direct_dependencies:\s*$\n(.*?)(?=^manifest_hash:)",
        f"{label} direct dependencies",
    )
    direct = re.findall(r"(?m)^-\s+([^\s]+)\s*$", direct_block)
    if len(direct) != len(set(direct)):
        raise GateError(f"{label}: duplicate direct dependency")
    return components, direct


def validate_inventory_shape(inventory: dict[str, Any]) -> None:
    expected_top = {"schema", "project", "host_dependencies", "esp_idf"}
    if set(inventory) != expected_top:
        raise GateError("dependency inventory top-level fields are not closed")
    if inventory.get("schema") != "ninlil-dependency-inventory-v1":
        raise GateError("dependency inventory schema mismatch")
    project = require_object(inventory.get("project"), "project")
    if project != {
        "id": "ninlil-runtime",
        "name": "Ninlil Runtime",
        "version": "0.1.0",
        "spdx_license": "Apache-2.0",
        "supplier": "Organization: Ninlil project",
    }:
        raise GateError("project package identity/license drift")

    host = require_array(inventory.get("host_dependencies"), "host_dependencies")
    expected_host = [
        {
            "id": "sqlite3",
            "name": "SQLite3",
            "version": "system-provided",
            "version_requirement": "unversioned system provider",
            "spdx_license": "blessing",
            "relationship": "OPTIONAL_DIRECT",
        },
        {
            "id": "openssl",
            "name": "OpenSSL",
            "version": "3.x",
            "version_requirement": ">=3.0.0 <4.0.0",
            "spdx_license": "Apache-2.0",
            "relationship": "DIRECT",
        },
    ]
    if host != expected_host:
        raise GateError("host dependency set/order/version/license drift")

    esp = require_object(inventory.get("esp_idf"), "esp_idf")
    if set(esp) != {"container", "lock_components", "bundled_dependencies"}:
        raise GateError("esp_idf inventory fields are not closed")
    expected_container = {
        "repository": "docker.io/espressif/idf",
        "tag": "v5.5.3",
        "platform": "linux/amd64",
        "digest": (
            "sha256:"
            "3e77b709e0ba7f0e9a711039231103be822736b4105790b8e33339a3bf4e47fb"
        ),
    }
    if esp.get("container") != expected_container:
        raise GateError("ESP-IDF container tag/platform/digest drift")
    bundled = require_array(esp.get("bundled_dependencies"), "bundled_dependencies")
    if bundled != [
        {
            "id": "mbedtls",
            "name": "Mbed TLS",
            "version": "ESP-IDF-5.5.3",
            "spdx_license": "Apache-2.0 OR GPL-2.0-or-later",
            "relationship": "TRANSITIVE",
        }
    ]:
        raise GateError("ESP-IDF bundled dependency set/version/license drift")


def validate(inputs: Inputs) -> None:
    validate_inventory_shape(inputs.inventory)
    if inputs.smoke_lock != inputs.hil_lock:
        raise GateError("smoke and HIL dependency locks must be byte-identical")
    if inputs.cmake.count("find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)") != 1:
        raise GateError("OpenSSL 3 Crypto dependency authority drift")
    if inputs.sqlite_cmake.count("find_package(SQLite3 QUIET)") != 1:
        raise GateError("SQLite3 dependency authority is absent")

    esp = require_object(inputs.inventory["esp_idf"], "esp_idf")
    raw_components = require_array(esp["lock_components"], "lock_components")
    inventory_components: dict[str, dict[str, Any]] = {}
    inventory_direct: list[str] = []
    for index, raw in enumerate(raw_components):
        item = require_object(raw, f"lock_components[{index}]")
        expected_fields = {
            "id",
            "name",
            "version",
            "component_hash",
            "spdx_license",
            "relationship",
        }
        if set(item) != expected_fields:
            raise GateError(f"lock_components[{index}] fields are not closed")
        component_id = item.get("id")
        if not isinstance(component_id, str) or component_id in inventory_components:
            raise GateError("lock component IDs must be unique strings")
        if item.get("relationship") not in ("DIRECT", "TRANSITIVE"):
            raise GateError(f"{component_id}: invalid relationship")
        inventory_components[component_id] = item
        if item["relationship"] == "DIRECT":
            inventory_direct.append(component_id)

    lock_components, lock_direct = parse_lock(inputs.smoke_lock, "ESP lock")
    if set(lock_components) != set(inventory_components):
        raise GateError(
            "closed ESP lock component set drift: "
            f"lock={sorted(lock_components)} inventory={sorted(inventory_components)}"
        )
    if lock_direct != inventory_direct:
        raise GateError(
            f"direct dependency order drift: {lock_direct} != {inventory_direct}"
        )
    for component_id, actual in lock_components.items():
        expected = inventory_components[component_id]
        if actual["version"] != expected["version"]:
            raise GateError(f"{component_id}: lock version drift")
        if actual["component_hash"] != expected["component_hash"]:
            raise GateError(f"{component_id}: component hash drift")

    component_version = exact(
        inputs.component,
        r'(?ms)^  idf:\s*$\n^\s{4}version: "==([0-9]+\.[0-9]+\.[0-9]+)"$',
        "ESP-IDF component manifest version",
    )
    tinyusb_version = exact(
        inputs.component,
        r'(?ms)^  espressif/esp_tinyusb:\s*$\n'
        r'^\s{4}version: "==([0-9]+\.[0-9]+\.[0-9]+)"$',
        "esp_tinyusb component manifest version",
    )
    if component_version != inventory_components["idf"]["version"]:
        raise GateError("ESP-IDF manifest/inventory version drift")
    if tinyusb_version != inventory_components["espressif/esp_tinyusb"]["version"]:
        raise GateError("esp_tinyusb manifest/inventory version drift")

    all_packages = (
        [inputs.inventory["project"]]
        + require_array(inputs.inventory["host_dependencies"], "host dependencies")
        + raw_components
        + require_array(esp["bundled_dependencies"], "bundled dependencies")
    )
    for package in all_packages:
        package_id = str(package["id"])
        version = str(package["version"])
        license_id = str(package["spdx_license"])
        for token in (
            f"**Machine ID:** `{package_id}`",
            f"**Version:** `{version}`",
        ):
            if package_id == "ninlil-runtime":
                continue
            if inputs.notices.count(token) != 1:
                raise GateError(
                    f"{package_id}: notice token expected once, got "
                    f"{inputs.notices.count(token)}: {token}"
                )
        license_token = f"**License:** `{license_id}`"
        if package_id != "ninlil-runtime" and license_token not in inputs.notices:
            raise GateError(f"{package_id}: notice license token absent")
        component_hash = package.get("component_hash")
        if component_hash is not None:
            token = f"**Component hash:** `{component_hash}`"
            if inputs.notices.count(token) != 1:
                raise GateError(f"{package_id}: notice component hash drift")

    required_release_tokens = (
        "syft-version: v1.49.0",
        '--output "spdx-json=${RAW_SBOM}"',
        "python3 tools/spdx_release_sbom.py enrich",
        "python3 tools/spdx_release_sbom.py check",
        "python3 tools/spdx_release_sbom.py self-test",
    )
    for token in required_release_tokens:
        if token not in inputs.release_workflow:
            raise GateError(f"release SBOM authority missing: {token}")


def expect_failure(label: str, inputs: Inputs) -> None:
    try:
        validate(inputs)
    except GateError:
        return
    raise GateError(f"self-test mutation was accepted: {label}")


def self_test() -> None:
    baseline = load()
    validate(baseline)

    unknown = copy.deepcopy(baseline)
    injected = (
        "  attacker/new_transitive:\n"
        f"    component_hash: {'0' * 64}\n"
        "    dependencies: []\n"
        "    source:\n"
        "      registry_url: https://invalid.example\n"
        "      type: service\n"
        "    version: 9.9.9\n"
    )
    unknown.smoke_lock = unknown.smoke_lock.replace(
        "direct_dependencies:",
        injected + "direct_dependencies:",
        1,
    )
    unknown.hil_lock = unknown.smoke_lock
    expect_failure("unknown locked transitive dependency", unknown)

    hash_drift = copy.deepcopy(baseline)
    hash_drift.inventory["esp_idf"]["lock_components"][1]["component_hash"] = "0" * 64
    expect_failure("component hash drift", hash_drift)

    notice_missing = copy.deepcopy(baseline)
    notice_missing.notices = notice_missing.notices.replace(
        "**Machine ID:** `espressif/tinyusb`",
        "**Machine ID:** `removed`",
        1,
    )
    expect_failure("missing notice package", notice_missing)

    floating_sbom = copy.deepcopy(baseline)
    floating_sbom.release_workflow = floating_sbom.release_workflow.replace(
        "syft-version: v1.49.0",
        "syft-version: latest",
        1,
    )
    expect_failure("floating SBOM generator", floating_sbom)

    mutable_container = copy.deepcopy(baseline)
    mutable_container.inventory["esp_idf"]["container"]["digest"] = "sha256:" + "0" * 64
    expect_failure("mutable or changed ESP container", mutable_container)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    try:
        if args.command == "check":
            validate(load())
        else:
            self_test()
    except GateError as exc:
        print(f"third-party notice gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"third-party notice gate {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
