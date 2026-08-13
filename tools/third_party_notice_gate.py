#!/usr/bin/env python3
"""Validate the closed direct/transitive dependency and notice inventory.

Release SBOM tooling identity is bound to the *executed* workflow mapping
values (comments do not count). Syft must be the exact immutable download-syft
Action SHA plus the exact `syft-version` pin — no floating tags, no comment
smuggling, no dynamic indirection.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import re
import shlex
import sys
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "dependency-inventory.json"
SYFT_ACTION = (
    "anchore/sbom-action/download-syft@"
    "e22c389904149dbc22b58101806040fa8d37a610"
)
SYFT_VERSION = "v1.49.0"
PYYAML_VENDOR_PATH = "tools/_vendor"
PYYAML_TREE_SHA256 = (
    "00e9d5acfbcd65db22fb7ebc0637cd5920cf7ef43d512d059168026f72cc693a"
)
EXPECTED_VENDORED = [
    {
        "id": "pyyaml",
        "name": "PyYAML",
        "version": "6.0.2",
        "spdx_license": "MIT",
        "relationship": "DIRECT",
        "source_path": PYYAML_VENDOR_PATH,
        "download_location": "https://pypi.org/project/PyYAML/6.0.2/",
        "component_hash": PYYAML_TREE_SHA256,
        "supplier": "Organization: PyYAML project",
        "syft_names": ["PyYAML", "pyyaml", "yaml"],
        "comment": (
            "Vendored pure-Python PyYAML for release workflow YAML semantic "
            "gates (tools/_vendor)."
        ),
    }
]
EXPECTED_SOURCE_LICENSE_SCOPE = {
    "scope": "repository-first-party-files",
    "license_expression": "Apache-2.0",
    "license_file": "LICENSE",
    "copyright_text": "NOASSERTION",
    "excluded_paths": [
        {
            "path": PYYAML_VENDOR_PATH,
            "inventory_id": "pyyaml",
        }
    ],
}
PUBLIC_HEADER_PATHS = (
    "include/ninlil/byte_stream.h",
    "include/ninlil/composition_v1.h",
    "include/ninlil/fabric_v1.h",
    "include/ninlil/platform.h",
    "include/ninlil/posix_tls_v1.h",
    "include/ninlil/posix_usb_serial_v1.h",
    "include/ninlil/runtime.h",
    "include/ninlil/service.h",
    "include/ninlil/transaction.h",
    "include/ninlil/version.h",
)
PUBLIC_HEADER_SPDX = "/* SPDX-License-Identifier: Apache-2.0 */\n"
EXPECTED_LOCK_COMPONENTS = [
    {
        "id": "espressif/esp_tinyusb",
        "name": "esp_tinyusb",
        "version": "2.1.1",
        "component_hash": (
            "fa0c96d7bdc3fe37383d735e2839a9007200a0b6bc039458d45d004b50146e81"
        ),
        "spdx_license": "Apache-2.0",
        "relationship": "DIRECT",
    },
    {
        "id": "espressif/tinyusb",
        "name": "TinyUSB",
        "version": "0.21.0~1",
        "component_hash": (
            "a72b7d67472914ab76309340fd50d578b31e310963d45ad0f81144bde3314752"
        ),
        "spdx_license": "MIT",
        "relationship": "TRANSITIVE",
    },
    {
        "id": "idf",
        "name": "ESP-IDF",
        "version": "5.5.3",
        "component_hash": None,
        "spdx_license": "Apache-2.0",
        "relationship": "DIRECT",
    },
]


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
    public_headers: dict[str, str]
    first_party_c_headers: dict[str, str]


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc


def load() -> Inputs:
    import subprocess

    try:
        inventory = json.loads(read("dependency-inventory.json"))
    except json.JSONDecodeError as exc:
        raise GateError(f"dependency-inventory.json is invalid JSON: {exc}") from exc
    if not isinstance(inventory, dict):
        raise GateError("dependency inventory must be an object")
    public_header_paths = sorted((ROOT / "include" / "ninlil").glob("*.h"))
    public_headers = {
        path.relative_to(ROOT).as_posix(): read(path.relative_to(ROOT).as_posix())
        for path in public_header_paths
    }
    try:
        listed = subprocess.check_output(
            [
                "git", "ls-files", "--cached", "--others",
                "--exclude-standard", "--", "*.c", "*.h",
            ],
            cwd=ROOT,
            text=True,
        ).splitlines()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(f"cannot enumerate first-party C/header files: {exc}") from exc
    first_party_paths = sorted(
        path for path in listed
        if path and not path.startswith("tools/_vendor/") and (ROOT / path).is_file()
    )
    first_party_c_headers = {path: read(path) for path in first_party_paths}
    return Inputs(
        cmake=read("CMakeLists.txt"),
        sqlite_cmake=read("cmake/ninlil_posix_sqlite_sqlite3.cmake"),
        component=read("ports/esp-idf/components/ninlil/idf_component.yml"),
        smoke_lock=read("ports/esp-idf/smoke_app/dependencies.lock"),
        hil_lock=read("ports/esp-idf/hil_app/dependencies.lock"),
        notices=read("THIRD-PARTY-NOTICES.md"),
        release_workflow=read(".github/workflows/release.yml"),
        inventory=inventory,
        public_headers=public_headers,
        first_party_c_headers=first_party_c_headers,
    )


def exact(text: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, text, flags=re.MULTILINE)
    if len(matches) != 1:
        raise GateError(f"{label}: expected one match, got {len(matches)}")
    value = matches[0]
    if isinstance(value, tuple):
        raise GateError(f"{label}: internal pattern must have one capture")
    return value



_TOOLS = pathlib.Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
from yaml_semantic import (  # type: ignore  # noqa: E402
    load_yaml_document,
    step_uses,
    step_with,
    walk_job_steps,
)


def logical_shell_commands(script: str) -> list[str]:
    commands: list[str] = []
    current = ""
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        piece = line[:-1].rstrip() if continued else line
        current = f"{current} {piece}".strip()
        if not continued:
            commands.append(current)
            current = ""
    if current:
        raise GateError("release workflow has unterminated shell continuation")
    return commands


def active_commands_with_marker(
    doc: Any, marker: str
) -> list[tuple[str, int, list[str]]]:
    found: list[tuple[str, int, list[str]]] = []
    from yaml_semantic import step_run  # type: ignore

    for job_id, step_index, step in walk_job_steps(doc):
        if step_index is None:
            continue
        run = step_run(step)
        if not run:
            continue
        for command in logical_shell_commands(run):
            if marker not in command:
                continue
            try:
                words = shlex.split(command, comments=True, posix=True)
            except ValueError as exc:
                raise GateError(
                    f"release job={job_id} step[{step_index}] invalid marked "
                    f"shell command: {exc}"
                ) from exc
            if marker in " ".join(words):
                found.append((job_id, step_index, words))
    return found


def validate_syft_tool_identity(release_workflow: str) -> None:
    """Bind exact executed Syft identity on the download-syft step only.

    `with.syft-version` on any non-download-syft step (e.g. checkout decoy) is
    ignored as authority and, if present, rejected as smuggling. Unicode-escaped
    keys resolve via YAML semantics before binding.
    """
    try:
        doc = load_yaml_document(release_workflow)
    except ValueError as exc:
        raise GateError(f"release workflow YAML: {exc}") from exc

    syft_steps: list[tuple[str, int, object, object]] = []
    smuggled: list[str] = []
    for job_id, step_index, step in walk_job_steps(doc):
        if step_index is None:
            continue
        uses = step_uses(step)
        with_map = step_with(step)
        if uses is not None and str(uses).startswith("anchore/sbom-action/download-syft"):
            syft_steps.append((job_id, step_index, uses, with_map))
            continue
        # syft-version on any other step is a decoy / smuggle channel.
        if "syft-version" in with_map:
            smuggled.append(
                f"job={job_id} step[{step_index}] uses={uses!r} "
                f"syft-version={with_map.get('syft-version')!r}"
            )

    if smuggled:
        raise GateError(
            "syft-version must only appear on the download-syft step; "
            f"decoy/smuggle found: {smuggled}"
        )
    if len(syft_steps) != 1:
        raise GateError(
            "release workflow must contain exactly one download-syft step, "
            f"got {len(syft_steps)}"
        )
    job_id, step_index, uses, with_map = syft_steps[0]
    if uses != SYFT_ACTION:
        raise GateError(
            f"download-syft step uses must be exact {SYFT_ACTION!r}, got {uses!r}"
        )
    if set(with_map) != {"syft-version"}:
        raise GateError(
            f"download-syft with: fields must be exactly {{syft-version}}, got {sorted(with_map)}"
        )
    version = with_map.get("syft-version")
    if version != SYFT_VERSION:
        raise GateError(
            f"download-syft with.syft-version must be exact {SYFT_VERSION!r}, "
            f"got {version!r}"
        )

    # Remaining SBOM pipeline authority must be active shell commands. Full-line
    # and inline comments are removed by semantic YAML + shlex before matching.
    syft_scan = active_commands_with_marker(doc, "spdx-json=${RAW_SBOM}")
    if len(syft_scan) != 1:
        raise GateError(f"release Syft scan command count must be 1, got {len(syft_scan)}")
    scan_words = syft_scan[0][2]
    required_scan = (
        "${SYFT_CMD}",
        "scan",
        "dir:.",
        "--source-name",
        "ninlil-runtime",
        "--source-version",
        "${SOURCE_VERSION}",
        "--select-catalogers=-github-actions-usage-cataloger,-github-action-workflow-usage-cataloger",
        "--output",
        "spdx-json=${RAW_SBOM}",
    )
    if tuple(scan_words) != required_scan:
        raise GateError(f"release Syft scan argv mismatch: {scan_words!r}")

    expected_tools = (
        (
            "enrich",
            [
                "python3",
                "tools/spdx_release_sbom.py",
                "enrich",
                "${RAW_SBOM}",
                "${SBOM}",
                "--project-version",
                "${PROJECT_VERSION}",
                "--source-version",
                "${SOURCE_VERSION}",
            ],
        ),
        (
            "check",
            [
                "python3",
                "tools/spdx_release_sbom.py",
                "check",
                "${SBOM}",
                "--project-version",
                "${PROJECT_VERSION}",
                "--source-version",
                "${SOURCE_VERSION}",
            ],
        ),
        (
            "self-test",
            ["python3", "tools/spdx_release_sbom.py", "self-test"],
        ),
    )
    for subcommand, expected_words in expected_tools:
        matches = active_commands_with_marker(
            doc, f"tools/spdx_release_sbom.py {subcommand}"
        )
        exact_matches = [words for _job, _step, words in matches if words == expected_words]
        if len(exact_matches) != 1:
            raise GateError(
                f"release SPDX {subcommand} active argv mismatch: "
                f"candidates={[words for _job, _step, words in matches]!r}"
            )


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


def vendor_tree_sha256(rel_path: str) -> str:
    import hashlib

    root = ROOT / rel_path
    if not root.is_dir():
        raise GateError(f"vendored dependency path missing: {rel_path}")
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def assert_vendored_git_tracked(rel_path: str, package_id: str) -> None:
    """Fail closed when vendored files would be omitted from `git archive`."""
    import subprocess

    git_dir = ROOT / ".git"
    if not git_dir.exists():
        return
    try:
        listed = subprocess.check_output(
            ["git", "-C", str(ROOT), "ls-files", "--", rel_path],
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise GateError(
            f"{package_id}: cannot list git-tracked files under {rel_path}: {exc}"
        ) from exc
    tracked = [line for line in listed.splitlines() if line.strip()]
    if not tracked:
        raise GateError(
            f"{package_id}: {rel_path} must be git-tracked so source archives "
            f"(git archive) include the vendored tree; currently untracked"
        )
    # Require pure-Python yaml package + license for PyYAML.
    if package_id == "pyyaml":
        required_suffixes = (
            "yaml/__init__.py",
            "pyyaml-6.0.2.dist-info/licenses/LICENSE",
            "pyyaml-6.0.2.dist-info/METADATA",
        )
        joined = "\n".join(tracked)
        for suffix in required_suffixes:
            if not any(path.endswith(suffix) for path in tracked):
                raise GateError(
                    f"pyyaml: git-tracked vendor tree missing required path "
                    f"ending with {suffix!r}"
                )



def validate_inventory_shape(inventory: dict[str, Any]) -> None:
    expected_top = {
        "schema",
        "project",
        "source_license_scope",
        "host_dependencies",
        "host_tooling",
        "vendored_dependencies",
        "syft_reconciliation",
        "esp_idf",
    }
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

    source_scope = require_object(
        inventory.get("source_license_scope"), "source_license_scope"
    )
    if source_scope != EXPECTED_SOURCE_LICENSE_SCOPE:
        raise GateError("first-party source license scope/NOASSERTION drift")
    if source_scope["license_expression"] != project["spdx_license"]:
        raise GateError("source license scope must equal the project SPDX license")
    if not (ROOT / str(source_scope["license_file"])).is_file():
        raise GateError("source license scope points to a missing license file")

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

    tooling = require_array(inventory.get("host_tooling"), "host_tooling")
    expected_tooling = [
        {
            "id": "nodejs",
            "name": "Node.js",
            "version": ">=18",
            "version_requirement": ">=18.0.0",
            "spdx_license": "MIT",
            "relationship": "BUILD_TOOL",
        }
    ]
    if tooling != expected_tooling:
        raise GateError("host tooling set/order/version/license drift")

    vendored = require_array(inventory.get("vendored_dependencies"), "vendored_dependencies")
    if vendored != EXPECTED_VENDORED:
        raise GateError("vendored dependency set/version/license/path/hash drift")
    for item in vendored:
        source_path = str(item["source_path"])
        actual_hash = vendor_tree_sha256(source_path)
        if actual_hash != item["component_hash"]:
            raise GateError(
                f"{item['id']}: vendored tree hash drift at {source_path}: "
                f"{actual_hash} != {item['component_hash']}"
            )
        license_file = ROOT / source_path / "pyyaml-6.0.2.dist-info" / "licenses" / "LICENSE"
        if item["id"] == "pyyaml" and not license_file.is_file():
            raise GateError("vendored PyYAML LICENSE file missing under dist-info")
        # Source tag archives use `git archive`; untracked vendor trees are omitted.
        assert_vendored_git_tracked(source_path, str(item["id"]))

    recon = require_object(inventory.get("syft_reconciliation"), "syft_reconciliation")
    if set(recon) != {"justified_exclusions"}:
        raise GateError("syft_reconciliation fields are not closed")
    exclusions = require_array(recon.get("justified_exclusions"), "justified_exclusions")
    if exclusions != []:
        raise GateError(
            "syft_reconciliation.justified_exclusions must be empty for current tree "
            f"(got {exclusions!r})"
        )

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
    if esp.get("lock_components") != EXPECTED_LOCK_COMPONENTS:
        raise GateError("ESP lock component name/version/hash/license/relationship drift")
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
    if set(inputs.public_headers) != set(PUBLIC_HEADER_PATHS):
        raise GateError(
            "public header SPDX inventory drift: "
            f"expected={list(PUBLIC_HEADER_PATHS)!r} "
            f"actual={sorted(inputs.public_headers)!r}"
        )
    for path in PUBLIC_HEADER_PATHS:
        if not inputs.public_headers[path].startswith(PUBLIC_HEADER_SPDX):
            raise GateError(
                f"{path}: first line must be the exact Apache-2.0 SPDX identifier"
            )
    if not inputs.first_party_c_headers:
        raise GateError("first-party C/header SPDX inventory is empty")
    for path, source in inputs.first_party_c_headers.items():
        first_line = source.splitlines()[0] if source else ""
        if first_line != PUBLIC_HEADER_SPDX.rstrip("\n"):
            raise GateError(
                f"{path}: first line must be the exact Apache-2.0 SPDX identifier"
            )
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
        + require_array(inputs.inventory["host_tooling"], "host tooling")
        + require_array(
            inputs.inventory["vendored_dependencies"], "vendored dependencies"
        )
        + raw_components
        + require_array(esp["bundled_dependencies"], "bundled dependencies")
    )
    for package in all_packages:
        package_id = str(package["id"])
        version = str(package["version"])
        license_id = str(package["spdx_license"])
        if package_id == "ninlil-runtime":
            continue
        machine_token = f"**Machine ID:** `{package_id}`"
        if inputs.notices.count(machine_token) != 1:
            raise GateError(f"{package_id}: notice machine ID expected once")
        block = exact(
            inputs.notices,
            re.escape(machine_token)
            + r"(?s:(.*?))(?=\n- \*\*Machine ID:\*\*|\n## |\Z)",
            f"{package_id} notice block",
        )
        for token in (
            f"**Version:** `{version}`",
            f"**License:** `{license_id}`",
        ):
            if block.count(token) != 1:
                raise GateError(
                    f"{package_id}: notice block token expected once: {token}"
                )
        component_hash = package.get("component_hash")
        if component_hash is not None:
            token = f"**Component hash:** `{component_hash}`"
            if block.count(token) != 1:
                raise GateError(f"{package_id}: notice component hash drift")

    validate_syft_tool_identity(inputs.release_workflow)


def expect_failure(label: str, inputs: Inputs) -> None:
    try:
        validate(inputs)
    except GateError:
        return
    raise GateError(f"self-test mutation was accepted: {label}")


def self_test() -> None:
    baseline = load()
    validate(baseline)

    source_license_drift = copy.deepcopy(baseline)
    source_license_drift.inventory["source_license_scope"][
        "license_expression"
    ] = "NOASSERTION"
    expect_failure("first-party source license scope drift", source_license_drift)

    claimed_holder = copy.deepcopy(baseline)
    claimed_holder.inventory["source_license_scope"]["copyright_text"] = (
        "Copyright guessed-holder"
    )
    expect_failure("unverified copyright holder in inventory", claimed_holder)

    missing_public_header = copy.deepcopy(baseline)
    del missing_public_header.public_headers[PUBLIC_HEADER_PATHS[-1]]
    expect_failure("public header omitted from SPDX inventory", missing_public_header)

    missing_public_spdx = copy.deepcopy(baseline)
    first_header = PUBLIC_HEADER_PATHS[0]
    missing_public_spdx.public_headers[first_header] = missing_public_spdx.public_headers[
        first_header
    ].removeprefix(PUBLIC_HEADER_SPDX)
    expect_failure("public header missing exact SPDX first line", missing_public_spdx)

    missing_source_spdx = copy.deepcopy(baseline)
    source_path = next(
        path for path in missing_source_spdx.first_party_c_headers
        if path not in PUBLIC_HEADER_PATHS
    )
    source_lines = missing_source_spdx.first_party_c_headers[source_path].splitlines(
        keepends=True
    )
    missing_source_spdx.first_party_c_headers[source_path] = "".join(source_lines[1:])
    expect_failure("first-party source missing first-line SPDX", missing_source_spdx)

    for label, first_line in (
        ("compound SPDX expression", "/* SPDX-License-Identifier: Apache-2.0 OR MIT */"),
        (
            "SPDX exception expression",
            "/* SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception */",
        ),
        (
            "non-SPDX lookalike",
            "/* not-an-SPDX-License-Identifier: Apache-2.0 */",
        ),
    ):
        expression_drift = copy.deepcopy(baseline)
        lines = expression_drift.first_party_c_headers[source_path].splitlines(
            keepends=True
        )
        newline = "\n" if lines and lines[0].endswith("\n") else ""
        lines[0] = first_line + newline
        expression_drift.first_party_c_headers[source_path] = "".join(lines)
        expect_failure(label, expression_drift)

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

    license_drift = copy.deepcopy(baseline)
    license_drift.inventory["esp_idf"]["lock_components"][1]["spdx_license"] = (
        "Apache-2.0"
    )
    license_drift.notices = license_drift.notices.replace(
        "**License:** `MIT`",
        "**License:** `Apache-2.0`",
        1,
    )
    expect_failure("component license authority drift", license_drift)

    misplaced_license = copy.deepcopy(baseline)
    misplaced_license.notices = misplaced_license.notices.replace(
        "- **License:** `Apache-2.0`\n"
        "  ([Espressif Component Registry]",
        "- **License:** `MIT`\n"
        "  ([Espressif Component Registry]",
        1,
    )
    expect_failure("license token in wrong package block", misplaced_license)

    notice_missing = copy.deepcopy(baseline)
    notice_missing.notices = notice_missing.notices.replace(
        "**Machine ID:** `espressif/tinyusb`",
        "**Machine ID:** `removed`",
        1,
    )
    expect_failure("missing notice package", notice_missing)

    no_node = copy.deepcopy(baseline)
    no_node.inventory["host_tooling"] = []
    expect_failure("missing Node.js host tooling inventory entry", no_node)

    node_notice_missing = copy.deepcopy(baseline)
    node_notice_missing.notices = node_notice_missing.notices.replace(
        "**Machine ID:** `nodejs`",
        "**Machine ID:** `removed-nodejs`",
        1,
    )
    expect_failure("missing Node.js host tooling notice", node_notice_missing)

    # Vendored PyYAML must remain in inventory + notices (no silent omission).
    no_pyyaml = copy.deepcopy(baseline)
    no_pyyaml.inventory["vendored_dependencies"] = []
    expect_failure("missing vendored PyYAML inventory entry", no_pyyaml)

    pyyaml_hash_drift = copy.deepcopy(baseline)
    pyyaml_hash_drift.inventory["vendored_dependencies"][0]["component_hash"] = "0" * 64
    expect_failure("vendored PyYAML tree hash drift", pyyaml_hash_drift)

    pyyaml_notice_missing = copy.deepcopy(baseline)
    pyyaml_notice_missing.notices = pyyaml_notice_missing.notices.replace(
        "**Machine ID:** `pyyaml`",
        "**Machine ID:** `removed-pyyaml`",
        1,
    )
    expect_failure("missing PyYAML notice machine ID", pyyaml_notice_missing)

    floating_sbom = copy.deepcopy(baseline)
    floating_sbom.release_workflow = floating_sbom.release_workflow.replace(
        "syft-version: v1.49.0",
        "syft-version: latest",
        1,
    )
    expect_failure("floating SBOM generator", floating_sbom)

    # Independent audit mutant: executed pin floats while old pin stays in comment.
    comment_smuggle = copy.deepcopy(baseline)
    comment_smuggle.release_workflow = comment_smuggle.release_workflow.replace(
        "syft-version: v1.49.0",
        "syft-version: latest  # syft-version: v1.49.0",
        1,
    )
    expect_failure("syft latest with old pin in comment", comment_smuggle)

    for label, live_line in (
        ("commented Syft scan", '          "${SYFT_CMD}" scan dir:. \\'),
        (
            "commented SPDX enrich",
            "          python3 tools/spdx_release_sbom.py enrich \\",
        ),
        (
            "commented SPDX check",
            "          python3 tools/spdx_release_sbom.py check \\",
        ),
        (
            "commented SPDX self-test",
            "          python3 tools/spdx_release_sbom.py self-test",
        ),
    ):
        commented_pipeline = copy.deepcopy(baseline)
        commented_pipeline.release_workflow = (
            commented_pipeline.release_workflow.replace(
                live_line,
                live_line.replace("          ", "          # ", 1),
                1,
            )
        )
        expect_failure(label, commented_pipeline)

    # Extra / alternate syft identities.
    extra_syft = copy.deepcopy(baseline)
    extra_syft.release_workflow = extra_syft.release_workflow + (
        "\n      - uses: anchore/sbom-action/download-syft@main\n"
        "        with:\n"
        "          syft-version: latest\n"
    )
    expect_failure("extra floating syft Action", extra_syft)

    dynamic_syft = copy.deepcopy(baseline)
    dynamic_syft.release_workflow = dynamic_syft.release_workflow.replace(
        "syft-version: v1.49.0",
        "syft-version: ${{ vars.SYFT_VERSION }}",
        1,
    )
    expect_failure("dynamic syft-version expression", dynamic_syft)

    # Unicode-escaped key on the real download-syft step → latest, plus decoy.
    unicode_latest = copy.deepcopy(baseline)
    unicode_latest.release_workflow = unicode_latest.release_workflow.replace(
        "syft-version: v1.49.0",
        r'"syft-\u0076ersion": latest',
        1,
    )
    unicode_latest.release_workflow += (
        "\n      - uses: actions/checkout@"
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
        "        with:\n"
        "          syft-version: v1.49.0\n"
    )
    expect_failure(
        r"syft-\u0076ersion latest with checkout decoy v1.49.0",
        unicode_latest,
    )

    # Decoy alone with good pin still fails (syft-version only on download-syft).
    decoy_only = copy.deepcopy(baseline)
    decoy_only.release_workflow += (
        "\n      - uses: actions/checkout@"
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
        "        with:\n"
        "          syft-version: v1.49.0\n"
    )
    expect_failure("checkout step syft-version decoy", decoy_only)

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
