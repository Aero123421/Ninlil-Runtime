#!/usr/bin/env python3
"""Fail-closed authority gate for composable public Runtime modules.

This tool is intentionally independent of the implementation build.  It validates
the T0 public-module authority, the orthogonal completion/module state domains,
dependency closure, package metadata, instance/namespace policy, and the exact
acceptance/evidence/HIL ledger.  `self-test` mutates only in-memory copies.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Any, Callable
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]

MODULE_STATES = [
    "PRIVATE_CANDIDATE",
    "PUBLIC_API_SPEC_ACCEPTED",
    "PACKAGE_EXPERIMENTAL",
    "RELEASE_SUPPORTED",
]
MODULE_TRANSITIONS = {
    "PRIVATE_CANDIDATE": ["PUBLIC_API_SPEC_ACCEPTED"],
    "PUBLIC_API_SPEC_ACCEPTED": ["PACKAGE_EXPERIMENTAL"],
    "PACKAGE_EXPERIMENTAL": ["RELEASE_SUPPORTED"],
    "RELEASE_SUPPORTED": [],
}
COMPLETION_STATES = [
    "UNALLOCATED",
    "PROPOSED",
    "SPEC_ACCEPTED",
    "HOST_CANDIDATE",
    "TARGET_CANDIDATE",
    "HIL_VERIFIED",
    "RELEASE_SUPPORTED",
]
RESULT_STATES = {"NOT_RUN", "FAIL", "PASS"}
MANIFEST_BOOLEAN_PATH_PATTERNS = (
    r"/version_coexistence_contract/v1_v2_same_process_claim",
    r"/modules/[0-9]+/coinstallability/multiple_v1_instances",
    r"/modules/[0-9]+/instance_policy/immutable_module_instance_id",
    r"/modules/[0-9]+/instance_policy/stale_handle_rejection",
    r"/modules/[0-9]+/instance_policy/cross_instance_rejection",
    r"/modules/[0-9]+/abi_contract/layout_invariant_across_compile_definitions",
    r"/(?:cross_module_acceptance|acceptance)/[0-9]+/hil/required",
    r"/identity_attachment_precondition_contract/restart_checkpoint_contract"
    r"/crc32c/(?:refin|refout)",
)
MATRIX_BOOLEAN_PATH_PATTERNS = (
    r"/platforms/[0-9]+/(?:required_hil|hil_verified)",
    r"/features/[0-9]+/(?:required_hil|hil_verified)",
)
METADATA_VARIABLES = [
    "FOUND",
    "API_VERSION",
    "MODULE_API_STATE",
    "COMPLETION_STATE",
    "COMPLETION_STATE_BY_PLATFORM",
    "PLATFORMS",
    "WIRE_PROFILES",
    "STORAGE_SCHEMAS",
    "DEPENDENCIES",
]
EXPECTED_AUTHORITY = {
    "adr_path": "docs/adr/0028-composable-public-runtime-modules.md",
    "completion_contract_path": "docs/34-v2-runtime-fabric-completion.md",
    "compatibility_matrix_path": "compatibility-matrix.json",
    "schema_path": "spec/public-module-manifest-v1.schema.json",
    "gate_path": "tools/public_module_manifest_gate.py",
}
EXPECTED_EXACT_CONTRACT_DIGESTS = {
    "module_wire_storage_namespace_sha256": (
        "4c5b9aed0cd3fceb4e1e35287ba3f60e8f4cdfaa75247222630fdbb8ee32119b"
    ),
    "acceptance_ledger_sha256": (
        "6977db32075ed1fa3ad47b7fd6b6c588d9a6bde7bddb7901530f9c356abab673"
    ),
}
EXPECTED_COMPLETION_DOMAIN = {
    "matrix_path": "compatibility-matrix.json",
    "states_pointer": "/completion_states",
    "features_pointer": "/features",
    "supplemental_features_pointer": (
        "/module_api_domain/supplemental_completion_features"
    ),
}
EXPECTED_CMAKE_CONTRACT = {
    "variable_pattern": "Ninlil_<component>_<VARIABLE>",
    "variables": METADATA_VARIABLES,
    "semantics": {
        "required_requested_absent": (
            "Ninlil_FOUND_FALSE_AND_CONFIGURE_FAIL_WHEN_FIND_PACKAGE_IS_REQUIRED"
        ),
        "optional_requested_absent": (
            "COMPONENT_FOUND_FALSE_AND_Ninlil_FOUND_REMAINS_TRUE"
        ),
        "unrequested_absent": "COMPONENT_FOUND_FALSE_WITHOUT_PACKAGE_FAILURE",
        "required_component_flag_source": (
            "Ninlil_FIND_REQUIRED_<component>"
        ),
        "requested_target_creation": "ONLY_WHEN_COMPONENT_FOUND_TRUE",
        "dependency_resolution": "TRANSITIVE_TOPOLOGICAL_NO_SILENT_ENABLE",
        "dependency_absent": (
            "REQUESTED_COMPONENT_FOUND_FALSE_WITH_EXACT_MISSING_DEPENDENCY"
        ),
        "platform_mismatch": (
            "REQUESTED_COMPONENT_FOUND_FALSE_WITH_EXACT_PLATFORM_MISMATCH"
        ),
        "esp_only_component_on_host": (
            "COMPONENT_FOUND_FALSE_WITH_EXACT_PLATFORM_MISMATCH"
        ),
        "found_true_condition": (
            "TARGET_HEADER_METADATA_PLATFORM_AND_TRANSITIVE_DEPENDENCIES_ALL_PRESENT"
        ),
        "platform_completion_state_reducer": (
            "MINIMUM_OF_PLATFORM_AND_FEATURES_MAPPED_TO_THAT_PLATFORM"
        ),
        "aggregate_completion_state_reducer": (
            "MINIMUM_OF_ALL_DECLARED_PLATFORM_ENTRIES"
        ),
        "completion_state_by_platform_format": (
            "DECLARED_PLATFORM_ORDER_PLATFORM_EQUALS_STATE_SEMICOLON_LIST"
        ),
    },
}
EXPECTED_MODULE_API_COMPLETION_MAPPING = {
    "PRIVATE_CANDIDATE": {
        "completion_floor": None,
        "package_availability": "ABSENT",
        "acceptance_requirement": "NONE",
    },
    "PUBLIC_API_SPEC_ACCEPTED": {
        "completion_floor": "SPEC_ACCEPTED",
        "package_availability": "ABSENT",
        "acceptance_requirement": (
            "MODULE_SPEC_ACCEPTED_INDEPENDENT_REVIEW_GO_P0_P1_P2_ZERO_"
            "AND_TRANSITIVE_DEPENDENCY_CLOSURE"
        ),
    },
    "PACKAGE_EXPERIMENTAL": {
        "completion_floor": "SPEC_ACCEPTED",
        "package_availability": "PRESENT",
        "acceptance_requirement": "ALL_NON_HIL_ACCEPTANCE_PASS",
    },
    "RELEASE_SUPPORTED": {
        "completion_floor": "RELEASE_SUPPORTED",
        "package_availability": "PRESENT",
        "acceptance_requirement": "ALL_ACCEPTANCE_AND_REQUIRED_HIL_PASS",
    },
}
EXPECTED_INTER_MODULE_PORT_CONTRACT = {
    "id": "ninlil_fabric_observer_v1",
    "abi_version": 1,
    "input_compatibility": "PREFIX_COMPATIBLE_STRUCT_SIZE",
    "event_field_order": [
        "uint32_t abi_version",
        "uint32_t struct_size",
        "uint8_t owner_instance_id[16]",
        "uint64_t owner_generation",
        "uint8_t subject_instance_id[16]",
        "uint64_t subject_generation",
        "uint32_t event_kind",
        "uint32_t flags",
        "const uint8_t *payload",
        "size_t payload_size",
    ],
    "observer_field_order": [
        "uint32_t abi_version",
        "uint32_t struct_size",
        "void *context",
        "ninlil_fabric_observer_on_event_v1_fn on_event",
    ],
    "callback_signature": (
        "ninlil_status_t (*)(void *context,"
        "const ninlil_fabric_observer_event_v1_t *event)"
    ),
    "registration_ownership": (
        "COPY_AND_BIND_OWNER_INSTANCE_ID_PLUS_GENERATION"
    ),
    "callback_data_lifetime": "CALL_ONLY_NO_RETAIN",
    "reentrancy": "SAME_INSTANCE_FORBIDDEN_RETURNS_BUSY",
    "unknown_event": "IGNORE_WITHOUT_MUTATION",
    "unregister": "DRAIN_THEN_INVALIDATE_GENERATION",
    "selection_port": "ninlil_fabric_selection_port_v1",
    "selection_port_contract_pointer": "/fabric_selection_port_contract",
}
EXPECTED_MULTI_INSTANCE_CONTRACT = {
    "runtime_instance_count": 2,
    "module_instance_count_per_module": 2,
    "positive_bindings": ["R0-M0", "R1-M1"],
    "negative_bindings": [
        "R0-M1",
        "R1-M0",
        "DESTROYED_GENERATION",
        "SAME_ID_DIFFERENT_GENERATION",
    ],
    "storage_identity_fields": [
        "realm_id[16]",
        "physical_namespace",
        "partition_prefix",
        "module_instance_id[16]",
        "module_generation",
    ],
    "storage_collision_policy": (
        "REJECT_BEFORE_OPEN_NO_DEFAULT_REALM_OR_AUTO_PREFIX"
    ),
    "physical_driver_owner_count": 1,
    "driver_child_minimum_for_acceptance": 2,
    "driver_demux_key": "OWNER_AND_CHILD_INSTANCE_ID_PLUS_GENERATION",
    "aggregate_protocol": "RESERVE_ALL_THEN_COMMIT_OR_RELEASE_ALL",
    "aggregate_visibility": "NO_CHILD_VISIBLE_BEFORE_PARENT_COMMIT",
    "fairness": "STRICT_ROUND_ROBIN_ONE_QUANTUM",
    "acceptance_id": "PM-COMPOSITION-2X2-01",
}
EXPECTED_ABI_LAYOUT_GATE_CONTRACT = {
    "macro_matrix": [
        "DEFAULT",
        "OPTIONAL_MACROS_UNDEFINED",
        "ALL_OPTIONAL_MACROS_ZERO",
        "ALL_OPTIONAL_MACROS_ONE",
    ],
    "languages": ["C11", "CXX"],
    "comparisons": [
        "SIZEOF",
        "ALIGNOF",
        "PUBLIC_FIELD_OFFSETS",
        "SYMBOL_MANIFEST",
    ],
    "positive_rule": "ALL_CONFIGURATIONS_EQUAL_DEFAULT_GOLDEN",
    "negative_probe": (
        "INJECT_CONDITIONAL_PUBLIC_FIELD_AND_REQUIRE_COMPILE_FAILURE"
    ),
    "negative_runner_rule": "NEGATIVE_FIXTURE_MUST_RUN_AND_EXIT_NONZERO",
    "acceptance_id_pointer": (
        "/modules/*/abi_contract/compile_time_layout_negative_acceptance_id"
    ),
}
EXPECTED_VERSION_COINSTALL_CONTRACT = {
    "current": "V2_NOT_ALLOCATED",
    "v1_v2_same_process_claim": False,
    "future_v2_requires": [
        "DISTINCT_COMPONENT_AND_TARGET",
        "DISTINCT_HEADER_ROOT",
        "DISTINCT_SYMBOL_PREFIX",
        "DISTINCT_STORAGE_NAMESPACE_OR_PREFIX",
        "DISTINCT_WIRE_PROFILE",
        "ACCEPTED_COINSTALLABILITY_ADR_AND_NEGATIVE_TESTS",
    ],
    "v1_as_v2_reinterpretation": "FORBIDDEN",
}
IDENTITY_PRECONDITION_ID = "ninlil_identity_attachment_precondition_v1"
IDENTITY_PRECONDITION_MODULES = [
    "wifi_v1",
    "wifi_posix_v1",
    "wifi_esp_v1",
    "route_relay_v1",
    "radio_fabric_adapter_v1",
    "mfdt_v1",
]
IDENTITY_ACCEPTANCE_MODULES = ["fabric_v1", *IDENTITY_PRECONDITION_MODULES]
IDENTITY_ACCEPTANCE_ID = "PM-IDENTITY-PRECONDITION-2X2-01"
IDENTITY_PRECONDITION_ADR_PATH = (
    "docs/adr/0039-identity-attachment-precondition-gate.md"
)
IDENTITY_PRECONDITION_ADR_H1 = (
    "# ADR-0039: Identity / Attachment precondition gate"
)
EXPECTED_IDENTITY_ATTACHMENT_PRECONDITION_SHA256 = (
    "d13789404303a839e3b27fc7493ad3db209f2c54b0e21e1dfb6a4f4af895c599"
)
EXPECTED_FABRIC_SELECTION_PORT_SHA256 = (
    "a09bdb413788773f95a495a1c3b45156921bb9b05e85bbe1a964a3a780f98d30"
)
EXPECTED_ACCEPTANCE_EVIDENCE_CONTRACT_SHA256 = (
    "931f2cdd77cb25fc9d59357ecf9270c25f57c89595458fe3351ab85836137e9e"
)
EXPECTED_INDEPENDENT_REVIEW_CONTRACT_SHA256 = (
    "26ff8b721094481cf74929fc9498fee25e11962866b04c3949a76766005ecab4"
)


def platform_profile_index() -> dict[str, dict[str, Any]]:
    """Return the immutable receipt matrix, rejecting duplicate IDs early."""
    # The manifest/schema const is checked before this helper is used.
    return {
        item["id"]: item
        for item in EXPECTED_PLATFORM_PROFILE_MATRIX
    }


EXPECTED_PLATFORM_PROFILE_MATRIX = [
    {"id": "linux-x86_64-gcc-debug", "platform_id": "linux-x86_64", "os": "Linux", "architecture": "x86_64", "toolchain_family": "GNU", "build_type": "Debug", "sanitizer_profile": "NONE", "esp_target": None},
    {"id": "linux-x86_64-clang-debug-asan-ubsan", "platform_id": "linux-x86_64", "os": "Linux", "architecture": "x86_64", "toolchain_family": "Clang", "build_type": "Debug", "sanitizer_profile": "ASAN_UBSAN", "esp_target": None},
    {"id": "linux-x86_64-gcc-release", "platform_id": "linux-x86_64", "os": "Linux", "architecture": "x86_64", "toolchain_family": "GNU", "build_type": "Release", "sanitizer_profile": "NONE", "esp_target": None},
    {"id": "linux-x86_64-clang-release", "platform_id": "linux-x86_64", "os": "Linux", "architecture": "x86_64", "toolchain_family": "Clang", "build_type": "Release", "sanitizer_profile": "NONE", "esp_target": None},
    {"id": "macos-arm64-appleclang-debug", "platform_id": "macos-arm64", "os": "Darwin", "architecture": "arm64", "toolchain_family": "AppleClang", "build_type": "Debug", "sanitizer_profile": "NONE", "esp_target": None},
    {"id": "macos-arm64-appleclang-release", "platform_id": "macos-arm64", "os": "Darwin", "architecture": "arm64", "toolchain_family": "AppleClang", "build_type": "Release", "sanitizer_profile": "NONE", "esp_target": None},
    {"id": "esp32s3-esp-idf-release", "platform_id": "esp32s3-esp-idf", "os": "ESP-IDF", "architecture": "xtensa", "toolchain_family": "ESP-IDF", "build_type": "Release", "sanitizer_profile": "NONE", "esp_target": "esp32s3"},
]


SUPPLEMENTAL_RF_FEATURE = {
    "id": "nfl1-r7-nrw1-rf-mapping",
    "state": "PROPOSED",
    "state_ceiling": "HIL_VERIFIED",
    "depends_on": [
        "fabric-bearer-nfl1-path-registry",
        "nrw1-link-frag-reassembly",
        "identity-attachment-session-install",
    ],
    "authority": "docs/adr/0035-v1-compact-radio-mapping.md",
}


def package(
    component: str,
    host_target: str | None,
    esp_component: str | None,
    artifact_kind: str,
    header_root: str,
    dependencies: list[str],
) -> dict[str, Any]:
    return {
        "component": component,
        "host_cmake_target": host_target,
        "esp_idf_component": esp_component,
        "artifact_kind": artifact_kind,
        "public_header_root": header_root,
        "install_availability": "ABSENT",
        "dependencies": dependencies,
        "exported_metadata_variables": METADATA_VARIABLES,
    }


EXPECTED_MODULES: dict[str, dict[str, Any]] = {
    "fabric_v1": {
        "package": {
            "component": "fabric_v1",
            "host_cmake_target": "Ninlil::fabric_v1",
            "esp_idf_component": None,
            "artifact_kind": "STATIC_ARCHIVE",
            "public_header_root": "ninlil/fabric_v1.h",
            "install_availability": "ABSENT",
            "dependencies": [],
            "exported_metadata_variables": [],
        },
        "platforms": ["linux-x86_64", "macos-arm64"],
        "mapping_features": ["fabric-bearer-nfl1-path-registry"],
        "dependency_features": [],
        "symbol_prefix": "ninlil_fabric_v1_",
        "acceptance_ids": ["PM-FAB-ABI-01", "PM-FAB-INSTANCE-01"],
    },
    "wifi_v1": {
        "package": package(
            "wifi_v1",
            "Ninlil::wifi_v1",
            "ninlil_wifi_common_v1",
            "STATIC_ARCHIVE",
            "ninlil/wifi/v1/",
            ["fabric_v1"],
        ),
        "platforms": ["linux-x86_64", "macos-arm64", "esp32s3-esp-idf"],
        "mapping_features": [
            "posix-tcp-tls-wifi-reference",
            "esp32s3-wifi-sta-tcp-tls",
        ],
        "dependency_features": [
            "fabric-bearer-nfl1-path-registry",
            "identity-attachment-session-install",
        ],
        "symbol_prefix": "ninlil_wifi_v1_",
        "acceptance_ids": ["PM-WIFI-COMMON-ABI-01"],
    },
    "wifi_posix_v1": {
        "package": package(
            "wifi_posix_v1",
            "Ninlil::wifi_posix_v1",
            None,
            "STATIC_ARCHIVE",
            "ninlil/wifi/v1/posix/",
            ["fabric_v1", "wifi_v1"],
        ),
        "platforms": ["linux-x86_64", "macos-arm64"],
        "mapping_features": ["posix-tcp-tls-wifi-reference"],
        "dependency_features": [
            "posix-tcp-tls-wifi-reference",
            "fabric-bearer-nfl1-path-registry",
            "identity-attachment-session-install",
        ],
        "symbol_prefix": "ninlil_wifi_posix_v1_",
        "acceptance_ids": [
            "PM-WIFI-POSIX-ABI-01",
            "PM-WIFI-POSIX-E2E-01",
        ],
    },
    "wifi_esp_v1": {
        "package": package(
            "wifi_esp_v1",
            None,
            "ninlil_wifi_v1",
            "ESP_IDF_COMPONENT",
            "ninlil_esp_idf/wifi/v1/",
            ["fabric_v1", "wifi_v1"],
        ),
        "platforms": ["esp32s3-esp-idf"],
        "mapping_features": ["esp32s3-wifi-sta-tcp-tls"],
        "dependency_features": [
            "esp32s3-wifi-sta-tcp-tls",
            "fabric-bearer-nfl1-path-registry",
            "identity-attachment-session-install",
        ],
        "symbol_prefix": "ninlil_wifi_esp_v1_",
        "acceptance_ids": ["PM-WIFI-ESP-ABI-01", "PM-WIFI-ESP-HIL-01"],
    },
    "route_relay_v1": {
        "package": package(
            "route_relay_v1",
            "Ninlil::route_relay_v1",
            "ninlil_route_relay_v1",
            "STATIC_ARCHIVE",
            "ninlil/route/v1/",
            ["fabric_v1"],
        ),
        "platforms": ["linux-x86_64", "macos-arm64", "esp32s3-esp-idf"],
        "mapping_features": ["relay", "multi-parent-multi-controller"],
        "dependency_features": [
            "fabric-bearer-nfl1-path-registry",
            "relay",
            "multi-parent-multi-controller",
            "identity-attachment-session-install",
        ],
        "symbol_prefix": "ninlil_route_relay_v1_",
        "acceptance_ids": [
            "PM-RR-ABI-01",
            "PM-RR-FAILOVER-01",
            "PM-RR-HIL-01",
        ],
    },
    "radio_frag_v1": {
        "package": package(
            "radio_frag_v1",
            "Ninlil::radio_frag_v1",
            "ninlil_radio_frag_v1",
            "STATIC_ARCHIVE",
            "ninlil/radio/frag/v1/",
            [],
        ),
        "platforms": ["linux-x86_64", "macos-arm64", "esp32s3-esp-idf"],
        "mapping_features": ["nrw1-link-frag-reassembly"],
        "dependency_features": ["portable-core-host-runtime"],
        "symbol_prefix": "ninlil_radio_frag_v1_",
        "acceptance_ids": ["PM-R7-FRAG-ABI-01", "PM-R7-FRAG-PURE-01"],
    },
    "radio_fabric_adapter_v1": {
        "package": package(
            "radio_fabric_adapter_v1",
            "Ninlil::radio_fabric_adapter_v1",
            "ninlil_radio_fabric_adapter_v1",
            "STATIC_ARCHIVE",
            "ninlil/radio/fabric/v1/",
            ["fabric_v1", "radio_frag_v1"],
        ),
        "platforms": ["linux-x86_64", "macos-arm64", "esp32s3-esp-idf"],
        "mapping_features": ["nfl1-r7-nrw1-rf-mapping"],
        "dependency_features": [
            "nfl1-r7-nrw1-rf-mapping",
            "fabric-bearer-nfl1-path-registry",
            "nrw1-link-frag-reassembly",
            "identity-attachment-session-install",
        ],
        "symbol_prefix": "ninlil_radio_fabric_adapter_v1_",
        "acceptance_ids": [
            "PM-R7-ADAPTER-ABI-01",
            "PM-R7-ADAPTER-HIL-01",
        ],
    },
    "mfdt_v1": {
        "package": package(
            "mfdt_v1",
            "Ninlil::mfdt_v1",
            "ninlil_mfdt_v1",
            "STATIC_ARCHIVE",
            "ninlil/mfdt/v1/",
            [],
        ),
        "platforms": ["linux-x86_64", "macos-arm64", "esp32s3-esp-idf"],
        "mapping_features": ["multi-frame-durable-transfer"],
        "dependency_features": [
            "portable-core-host-runtime",
            "canonical-domain-store",
            "multi-frame-durable-transfer",
            "identity-attachment-session-install",
        ],
        "symbol_prefix": "ninlil_mfdt_v1_",
        "acceptance_ids": [
            "PM-MFDT-ABI-01",
            "PM-MFDT-CARRIER-01",
            "PM-MFDT-HIL-01",
        ],
    },
}

# This is deliberately duplicated authority, rather than values inferred from
# the candidate manifest.  A future author must make a reviewable change here
# (and to the normative manifest) to alter wire/storage ownership.  Generic
# shape validation alone is not an authority for a protocol profile.
EXPECTED_MODULE_STORAGE_AND_WIRE: dict[str, dict[str, Any]] = {
    "fabric_v1": {
        "wire_profiles": ["NFL1-v1"],
        "storage_schemas": ["ninlil.fabric.v1/schema1-candidate"],
        "namespace_policy": {
            "mode": "CALLER_SUPPLIED_REALM_DEDICATED",
            "physical_namespaces": ["ninlil.fabric.v1"],
            "partition_prefixes": ["fabric_v1"],
            "single_writer": "REQUIRED",
            "writer_owner": "fabric_v1_instance",
        },
    },
    "wifi_v1": {
        "wire_profiles": ["NWB1-v1-candidate"],
        "storage_schemas": ["NINLIL-WIFI-CREDENTIAL-STORE-V1-candidate"],
        "namespace_policy": {
            "mode": "CALLER_SUPPLIED_REALM_DEDICATED",
            "physical_namespaces": ["ninlil.wifi.v1"],
            "partition_prefixes": ["credential_store_v1"],
            "single_writer": "REQUIRED",
            "writer_owner": "wifi_v1_instance",
        },
    },
    "wifi_posix_v1": {
        "wire_profiles": ["NWB1-v1-candidate"],
        "storage_schemas": [],
        "namespace_policy": {"mode": "NONE", "physical_namespaces": [], "partition_prefixes": [], "single_writer": "NOT_APPLICABLE", "writer_owner": None},
    },
    "wifi_esp_v1": {
        "wire_profiles": ["NWB1-v1-candidate"],
        "storage_schemas": [],
        "namespace_policy": {"mode": "NONE", "physical_namespaces": [], "partition_prefixes": [], "single_writer": "NOT_APPLICABLE", "writer_owner": None},
    },
    "route_relay_v1": {
        "wire_profiles": ["NRW1-0x11-existing"],
        "storage_schemas": ["ninlil.route.v1/schema1-candidate", "ninlil.parent.v1/schema1-candidate"],
        "namespace_policy": {
            "mode": "CALLER_SUPPLIED_REALM_DEDICATED",
            "physical_namespaces": ["ninlil.route.v1", "ninlil.parent.v1"],
            "partition_prefixes": ["route_v1", "parent_v1"],
            "single_writer": "REQUIRED",
            "writer_owner": "route_relay_v1_instance",
        },
    },
    "radio_frag_v1": {
        "wire_profiles": ["R7-FRAG-v1-pure"],
        "storage_schemas": [],
        "namespace_policy": {"mode": "NONE", "physical_namespaces": [], "partition_prefixes": [], "single_writer": "NOT_APPLICABLE", "writer_owner": None},
    },
    "radio_fabric_adapter_v1": {
        "wire_profiles": ["NFL1-R7-NRW1-mapping-unallocated"],
        "storage_schemas": [],
        "namespace_policy": {"mode": "NONE", "physical_namespaces": [], "partition_prefixes": [], "single_writer": "NOT_APPLICABLE", "writer_owner": None},
    },
    "mfdt_v1": {
        "wire_profiles": ["MFDT-v1-candidate", "NCL1-v1-existing"],
        "storage_schemas": ["ninlil.ctl.v1/mfdt-v1-candidate"],
        "namespace_policy": {
            "mode": "CALLER_SUPPLIED_REALM_SHARED_PREFIX",
            "physical_namespaces": ["ninlil.ctl.v1"],
            "partition_prefixes": ["mfdt_v1"],
            "single_writer": "REQUIRED",
            "writer_owner": "foundation_control_store_owner",
        },
    },
}

# The acceptance IDs are not enough: an unchanged ID must not silently point
# at a weaker requirement or another test source.  This keyed ledger is an
# exact, independent pin for all 17 module rows.
EXPECTED_ACCEPTANCE_LEDGER: dict[str, tuple[str, str, bool]] = {
    "PM-FAB-ABI-01": ("fabric_v1", "public fabric_v1.h 10 value-type sizeof/align/offsetof golden coverage, exact 19-function API/status surface, C11/C++ header smoke, and tests-OFF Ninlil::fabric_v1 install surface", False),
    "PM-FAB-INSTANCE-01": ("fabric_v1", "two Runtime plus two distinct Fabric instances complete public submit to peer callback and reverse Receipt, with wrong-thread/re-entry zero effects and bounded close", False),
    "PM-WIFI-COMMON-ABI-01": ("wifi_v1", "portable static archive only, no POSIX or ESP dependency, invariant public ABI, exact component metadata, two Runtime plus two distinct common module instances, and Identity/Attachment provider 2x2 binding negatives", False),
    "PM-WIFI-POSIX-ABI-01": ("wifi_posix_v1", "tests-OFF install consumer, exact common plus Fabric dependencies, header closure and layout invariant negative probes", False),
    "PM-WIFI-POSIX-E2E-01": ("wifi_posix_v1", "two Runtime plus two distinct real localhost TLS/NFL1 adapter instances with Identity/Attachment provider 2x2 binding negatives, disconnect, reconnect, bounded backpressure and no custody advertisement", False),
    "PM-WIFI-ESP-ABI-01": ("wifi_esp_v1", "ESP component public-header closure, final ELF map path, no POSIX dependency, compile-definition layout invariance, two Runtime plus two distinct ESP adapter workspaces, and Identity/Attachment provider 2x2 binding negatives", False),
    "PM-WIFI-ESP-HIL-01": ("wifi_esp_v1", "ESP32-S3 real AP and peer TLS/NFL1 path, forced disconnect, sleep and wake, resource profile and soak evidence", True),
    "PM-RR-ABI-01": ("route_relay_v1", "public observer-only dependency direction, invariant ABI, two-instance package and namespace isolation negative probes", False),
    "PM-RR-FAILOVER-01": ("route_relay_v1", "two Runtime, two distinct Route/Relay owners and two Fabric instances, Identity/Attachment provider 2x2 binding negatives, failover, restart, split-brain fencing, bounded fairness and no process-global owner", False),
    "PM-RR-HIL-01": ("route_relay_v1", "three physical RF nodes, parent loss, relay drain, power interruption and soak with raw evidence", True),
    "PM-R7-FRAG-ABI-01": ("radio_frag_v1", "pure fragmentation API with opaque workspace and compile-definition invariant layout; RF mapping, crypto and driver symbols absent", False),
    "PM-R7-FRAG-PURE-01": ("radio_frag_v1", "two Runtime plus two distinct engines, reorder, duplicate, loss, conflict, exhaustion and reassembly without an RF mapping dependency", False),
    "PM-R7-ADAPTER-ABI-01": ("radio_fabric_adapter_v1", "separate Fabric adapter package, exact Accepted RF mapping dependency, compile-definition invariant ABI, two Runtime plus two distinct adapter instances, and Identity/Attachment provider 2x2 binding negatives", False),
    "PM-R7-ADAPTER-HIL-01": ("radio_fabric_adapter_v1", "Accepted NFL1 to R7 FRAG to NRW1 mapping KAT plus two-device physical RF loss injection", True),
    "PM-MFDT-ABI-01": ("mfdt_v1", "public manager ABI, caller-owned storage realm and MFDT prefix isolation with compile-definition layout negative probes", False),
    "PM-MFDT-CARRIER-01": ("mfdt_v1", "two Runtime plus two distinct manager instances with Identity/Attachment provider 2x2 binding negatives, carrying 4 KiB and 32 KiB over actual Foundation to Fabric to Wi-Fi, with restart, resume and replay", False),
    "PM-MFDT-HIL-01": ("mfdt_v1", "real transport transfer with sender and receiver power interruption, durable resume and no partial apply", True),
}
EXPECTED_ACCEPTANCE_TEST_PATHS = {
    "PM-FAB-ABI-01": "tests/transport/fabric_v1/fabric_v1_public_api_test.c",
    "PM-FAB-INSTANCE-01": "tests/cmake/installed_fabric_v1_consumer/consumer.c",
    "PM-WIFI-COMMON-ABI-01": "tests/public_modules/wifi_v1_common_abi_negative.c",
    "PM-WIFI-POSIX-ABI-01": "tests/public_modules/wifi_posix_v1_abi_negative.c",
    "PM-WIFI-POSIX-E2E-01": "tests/public_modules/wifi_posix_v1_actual_e2e.c",
    "PM-WIFI-ESP-ABI-01": "tests/public_modules/wifi_esp_v1_abi_negative.c",
    "PM-WIFI-ESP-HIL-01": "tools/public_modules/run_wifi_esp_v1_hil.py",
    "PM-RR-ABI-01": "tests/public_modules/route_relay_v1_abi_negative.c",
    "PM-RR-FAILOVER-01": "tests/public_modules/route_relay_v1_failover.c",
    "PM-RR-HIL-01": "tools/public_modules/run_route_relay_v1_hil.py",
    "PM-R7-FRAG-ABI-01": "tests/public_modules/radio_frag_v1_abi_negative.c",
    "PM-R7-FRAG-PURE-01": "tests/public_modules/radio_frag_v1_pure.c",
    "PM-R7-ADAPTER-ABI-01": "tests/public_modules/radio_fabric_adapter_v1_abi_negative.c",
    "PM-R7-ADAPTER-HIL-01": "tools/public_modules/run_radio_fabric_adapter_v1_hil.py",
    "PM-MFDT-ABI-01": "tests/public_modules/mfdt_v1_abi_negative.c",
    "PM-MFDT-CARRIER-01": "tests/public_modules/mfdt_v1_actual_carrier_e2e.c",
    "PM-MFDT-HIL-01": "tools/public_modules/run_mfdt_v1_hil.py",
}

EXPECTED_HIL_IDS = {
    "PM-WIFI-ESP-HIL-01",
    "PM-RR-HIL-01",
    "PM-R7-ADAPTER-HIL-01",
    "PM-MFDT-HIL-01",
}
EXPECTED_PROMOTION_PATHS = {
    "fabric_v1": (
        "docs/adr/0029-v1-lean-public-composition.md",
        "docs/reviews/2026-08-02-v1-lean-public-composition-rereview.md",
    ),
    "wifi_v1": (
        "docs/modules/wifi-common-v1.md",
        "docs/reviews/wifi-common-v1-public-api-spec-review.md",
    ),
    "wifi_posix_v1": (
        "docs/modules/wifi-posix-v1.md",
        "docs/reviews/wifi-posix-v1-public-api-spec-review.md",
    ),
    "wifi_esp_v1": (
        "docs/modules/wifi-esp-v1.md",
        "docs/reviews/wifi-esp-v1-public-api-spec-review.md",
    ),
    "route_relay_v1": (
        "docs/modules/route-relay-v1.md",
        "docs/reviews/route-relay-v1-public-api-spec-review.md",
    ),
    "radio_frag_v1": (
        "docs/modules/radio-frag-v1.md",
        "docs/reviews/radio-frag-v1-public-api-spec-review.md",
    ),
    "radio_fabric_adapter_v1": (
        "docs/modules/radio-fabric-adapter-v1.md",
        "docs/reviews/radio-fabric-adapter-v1-public-api-spec-review.md",
    ),
    "mfdt_v1": (
        "docs/modules/mfdt-v1.md",
        "docs/reviews/mfdt-v1-public-api-spec-review.md",
    ),
}


class GateError(RuntimeError):
    """A deterministic public-module authority failure."""


def require_offline_verified_independent_review(
    review_status: str,
    separation_verification: str,
    label: str,
) -> None:
    if review_status != "GO":
        return
    if separation_verification != "VERIFIED":
        raise GateError(f"{label}: GO requires verified implementer separation")
    raise GateError(
        f"{label}: independent reviewer provenance offline verifier "
        "unavailable; GO promotion is fail closed"
    )


def _reject_constant(value: str) -> None:
    raise GateError(f"non-finite JSON constant rejected: {value}")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise GateError(f"duplicate JSON key rejected: {key}")
        out[key] = value
    return out


def load_json_strict(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot parse {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"{path}: root must be an object")
    return value


def closed(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError(f"{label}: must be an object")
    if set(value) != fields:
        missing = sorted(fields - set(value))
        unknown = sorted(set(value) - fields)
        raise GateError(
            f"{label}: closed fields mismatch missing={missing} unknown={unknown}"
        )
    return value


def string(value: Any, label: str, pattern: str | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise GateError(f"{label}: non-empty string required")
    if pattern is not None and re.fullmatch(pattern, value) is None:
        raise GateError(f"{label}: invalid value {value!r}")
    return value


def list_unique_strings(value: Any, label: str, allow_empty: bool = True) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise GateError(f"{label}: string array required")
    if any(not isinstance(item, str) or not item for item in value):
        raise GateError(f"{label}: all entries must be non-empty strings")
    if len(set(value)) != len(value):
        raise GateError(f"{label}: duplicate entry")
    return value


def strict_integer(
    value: Any,
    label: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        raise GateError(f"{label}: exact JSON integer required")
    if minimum is not None and value < minimum:
        raise GateError(f"{label}: integer below minimum")
    if maximum is not None and value > maximum:
        raise GateError(f"{label}: integer above maximum")
    return value


def validate_boolean_locations(
    value: Any,
    label: str,
    allowed_patterns: tuple[str, ...],
) -> None:
    compiled = tuple(re.compile(pattern) for pattern in allowed_patterns)

    def walk(current: Any, path: str) -> None:
        if isinstance(current, bool):
            if not any(pattern.fullmatch(path) for pattern in compiled):
                raise GateError(
                    f"{label}{path}: boolean supplied to non-boolean field"
                )
            return
        if isinstance(current, dict):
            for key, child in current.items():
                walk(child, f"{path}/{key}")
        elif isinstance(current, list):
            for index, child in enumerate(current):
                walk(child, f"{path}/{index}")

    walk(value, "")


def repo_path(
    value: Any,
    label: str,
    *,
    require_exists: bool = False,
    require_file: bool = False,
    require_directory: bool = False,
) -> pathlib.Path:
    path_value = string(value, label)
    pure = pathlib.PurePosixPath(path_value)
    if (
        pure.is_absolute()
        or "\\" in path_value
        or "\x00" in path_value
        or ".." in pure.parts
        or pure.as_posix() != path_value
    ):
        raise GateError(f"{label}: non-canonical or unsafe repository path")
    root_resolved = ROOT.resolve(strict=True)
    candidate = ROOT.joinpath(*pure.parts)
    current = ROOT
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise GateError(f"{label}: symlink path component rejected")
    try:
        resolved = candidate.resolve(strict=require_exists)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise GateError(f"{label}: path escapes repository root") from exc
    if require_file and (not candidate.is_file() or candidate.is_symlink()):
        raise GateError(f"{label}: regular file required")
    if require_directory and (
        not candidate.is_dir() or candidate.is_symlink()
    ):
        raise GateError(f"{label}: regular directory required")
    return candidate


def state_index(state: str, states: list[str], label: str) -> int:
    if state not in states:
        raise GateError(f"{label}: unknown state {state!r}")
    return states.index(state)


def canonical_json_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def exact_contract_digests(manifest: dict[str, Any]) -> dict[str, str]:
    module_contract = {
        module["id"]: {
            field: module[field]
            for field in ("wire_profiles", "storage_schemas", "namespace_policy")
        }
        for module in manifest["modules"]
    }
    acceptance_contract: list[dict[str, Any]] = []
    for collection in ("cross_module_acceptance", "acceptance"):
        for item in manifest[collection]:
            record = {
                "id": item["id"],
                "requirement": item["requirement"],
                "test_path": item["test"]["path"],
                "hil_required": item["hil"]["required"],
            }
            if "module_id" in item:
                record["module_id"] = item["module_id"]
            else:
                record["covered_module_ids"] = item["covered_module_ids"]
            acceptance_contract.append(record)
    return {
        "module_wire_storage_namespace_sha256": canonical_json_sha256(module_contract),
        "acceptance_ledger_sha256": canonical_json_sha256(acceptance_contract),
    }


def canonical_markdown_status(
    text: str,
    label: str,
    *,
    expected_h1: str | None = None,
) -> str:
    if "\x00" in text or text.startswith("\ufeff"):
        raise GateError(f"{label}: invalid text encoding marker")
    lines = text.splitlines()
    if len(lines) < 3 or not lines[0].startswith("# ") or lines[1] != "":
        raise GateError(f"{label}: canonical heading/status preamble required")
    if expected_h1 is not None and lines[0] != expected_h1:
        raise GateError(f"{label}: exact H1 title mismatch")
    match = re.fullmatch(
        r"- Status: \*\*(Proposed|Accepted|Rejected|Superseded)\*\*",
        lines[2],
    )
    if match is None:
        raise GateError(f"{label}: canonical status line missing")
    for index, line in enumerate(lines):
        if index != 2 and "Status:" in line:
            raise GateError(
                f"{label}: duplicate/comment/code-fence status smuggling rejected"
            )
    return match.group(1)


def canonical_single_metadata(
    text: str,
    label: str,
    field: str,
    pattern: str,
) -> str:
    matches = [
        re.fullmatch(pattern, line)
        for line in text.splitlines()
        if field in line
    ]
    values = [match.group(1) for match in matches if match is not None]
    if len(matches) != 1 or len(values) != 1:
        raise GateError(f"{label}: canonical {field} line required exactly once")
    return values[0]


def canonical_identity_attachment_precondition_review_result(text: str) -> None:
    """Require the small, live-only review record that permits ADR-0039."""
    label = "ADR-0039 independent review"
    lines = text.splitlines()
    if (
        len(lines) < 2
        or lines[0] != "# Identity / Attachment precondition specification review"
        or lines[1] != ""
    ):
        raise GateError(f"{label}: canonical H1/preamble required")

    live_indexes: set[int] = set()
    in_fence = False
    in_comment = False
    for index, line in enumerate(lines):
        if re.match(r"^[ \t]*(`{3,}|~{3,})", line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if in_comment:
            if "-->" in line:
                in_comment = False
            continue
        if "<!--" in line:
            if "-->" not in line:
                in_comment = True
            continue
        live_indexes.add(index)
    if in_fence or in_comment:
        raise GateError(f"{label}: unterminated comment/code fence")

    required = [
        ("Reviewer:", r"(- Reviewer: \*\*Independent\*\*)"),
        (
            "Scope:",
            r"(- Scope: \*\*ADR-0039 S1-S6 specification acceptance\*\*)",
        ),
        *[
            (f"S{index}:", rf"(- S{index}: \*\*CONFIRMED\*\*)")
            for index in range(1, 7)
        ],
        ("Result:", r"- Result: \*\*(GO — P0=0 / P1=0 / P2=0 / P3=0)\*\*"),
    ]
    for field, pattern in required:
        canonical_single_metadata(text, label, field, pattern)
        matching_index = next(
            index for index, line in enumerate(lines) if re.fullmatch(pattern, line)
        )
        if matching_index not in live_indexes:
            raise GateError(f"{label}: {field} must be a live Markdown line")


def executable_text_without_comments(text: str, *, cmake: bool) -> str:
    if cmake:
        text = re.sub(
            r"#\[(=*)\[(?:.|\n)*?\]\1\]",
            "",
            text,
            flags=re.MULTILINE,
        )
    uncommented_lines: list[str] = []
    for line in text.splitlines():
        in_single_quote = False
        in_double_quote = False
        escaped = False
        end = len(line)
        for index, character in enumerate(line):
            if escaped:
                escaped = False
                continue
            if character == "\\" and in_double_quote:
                escaped = True
                continue
            if character == "'" and not cmake and not in_double_quote:
                in_single_quote = not in_single_quote
                continue
            if character == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
                continue
            if (
                character == "#"
                and not in_single_quote
                and not in_double_quote
            ):
                end = index
                break
        uncommented_lines.append(line[:end])
    return "\n".join(uncommented_lines)


def has_ctest_registration(executable_text: str, acceptance_id: str) -> bool:
    runner_id = re.escape(acceptance_id)
    return (
        re.search(
            rf"(?m)^[ \t]*add_test\s*\(\s*NAME\s+{runner_id}(?:\s|\))",
            executable_text,
        )
        is not None
    )


def current_single_parent_sha(label: str) -> str:
    try:
        parent_line = subprocess.run(
            ["git", "rev-list", "--parents", "-n", "1", "HEAD"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"{label}: Git parent authority unavailable") from exc
    commit_tokens = parent_line.split()
    if len(commit_tokens) != 2:
        raise GateError(
            f"{label}: administrative promotion must have exact single parent"
        )
    return commit_tokens[1]


def validate_tested_parent_commit(commit_sha: str, label: str) -> None:
    if current_single_parent_sha(label) != commit_sha:
        raise GateError(
            f"{label}: tested/reviewed commit must be exact single first parent"
        )
    try:
        changed_output = subprocess.run(
            ["git", "diff", "--name-only", commit_sha, "HEAD", "--"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"{label}: administrative promotion diff unavailable") from exc
    changed_paths = [line for line in changed_output.splitlines() if line]
    allowed_exact = {
        "public-module-manifest.json",
        "compatibility-matrix.json",
    }
    for changed_path in changed_paths:
        if (
            changed_path not in allowed_exact
            and not changed_path.startswith("docs/reviews/")
            and not changed_path.startswith("evidence/")
        ):
            raise GateError(
                f"{label}: non-administrative change after tested commit "
                f"{changed_path}"
            )
    try:
        dirty_output = subprocess.run(
            [
                "git",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"{label}: clean worktree authority unavailable") from exc
    if dirty_output:
        raise GateError(
            f"{label}: promotion/evidence verification requires clean worktree"
        )


def git_blob_at_commit(
    commit_sha: str,
    path_value: str,
    label: str,
) -> bytes:
    repo_path(path_value, f"{label}.commit_bound_path")
    try:
        completed = subprocess.run(
            ["git", "show", f"{commit_sha}:{path_value}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(
            f"{label}: path is not present in exact tested commit"
        ) from exc
    return completed.stdout


def validate_schema(schema: dict[str, Any]) -> None:
    expected_top = {
        "$schema",
        "$id",
        "title",
        "type",
        "additionalProperties",
        "required",
        "properties",
        "$defs",
    }
    closed(schema, expected_top, "schema")
    if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema":
        raise GateError("schema: unknown JSON Schema version")
    if schema["$id"] != (
        "https://ninlil.dev/spec/public-module-manifest-v1.schema.json"
    ):
        raise GateError("schema: $id drift")
    if schema["type"] != "object" or schema["additionalProperties"] is not False:
        raise GateError("schema: root must be a closed object")
    required = {
        "$schema",
        "schema",
        "schema_version",
        "authority",
        "exact_contract_digests",
        "module_api_states",
        "allowed_module_api_transitions",
        "completion_state_domain",
        "cmake_component_contract",
        "module_api_completion_mapping",
        "inter_module_port_contract",
        "fabric_selection_port_contract",
        "acceptance_evidence_contract",
        "independent_review_contract",
        "multi_instance_acceptance_contract",
        "abi_layout_gate_contract",
        "version_coexistence_contract",
        "identity_attachment_precondition_contract",
        "modules",
        "cross_module_acceptance",
        "acceptance",
    }
    if set(schema["required"]) != required or set(schema["properties"]) != required:
        raise GateError("schema: top-level required/properties drift")
    if schema["properties"].get("exact_contract_digests") != {
        "const": EXPECTED_EXACT_CONTRACT_DIGESTS
    }:
        raise GateError("schema: exact module/acceptance contract digests drift")
    defs = schema["$defs"]
    if not isinstance(defs, dict):
        raise GateError("schema: $defs must be an object")
    for name in (
        "authority",
        "moduleTransitions",
        "completionStateDomain",
        "cmakeComponentContract",
        "moduleApiCompletionMapping",
        "interModulePortContract",
        "multiInstanceAcceptanceContract",
        "abiLayoutGateContract",
        "versionCoexistenceContract",
        "featureMapping",
        "package",
        "namespacePolicy",
        "coinstallability",
        "dependency",
        "instancePolicy",
        "abiContract",
        "promotionAuthority",
        "module",
        "testMapping",
        "evidenceProfileReceipt",
        "evidenceMapping",
        "hilMapping",
        "crossModuleAcceptance",
        "acceptance",
    ):
        item = defs.get(name)
        if not isinstance(item, dict) or item.get("type") != "object":
            raise GateError(f"schema: missing object definition {name}")
        if item.get("additionalProperties") is not False:
            raise GateError(f"schema: {name} is not fail-closed")
        if set(item.get("required", [])) != set(item.get("properties", {})):
            raise GateError(f"schema: {name} required/properties drift")
    for name, digest in (
        (
            "identityAttachmentPreconditionContract",
            EXPECTED_IDENTITY_ATTACHMENT_PRECONDITION_SHA256,
        ),
        (
            "fabricSelectionPortContract",
            EXPECTED_FABRIC_SELECTION_PORT_SHA256,
        ),
        (
            "acceptanceEvidenceContract",
            EXPECTED_ACCEPTANCE_EVIDENCE_CONTRACT_SHA256,
        ),
        (
            "independentReviewContract",
            EXPECTED_INDEPENDENT_REVIEW_CONTRACT_SHA256,
        ),
    ):
        item = defs.get(name)
        if not isinstance(item, dict) or set(item) != {"const"}:
            raise GateError(f"schema: {name} must be one exact const")
        if canonical_json_sha256(item["const"]) != digest:
            raise GateError(f"schema: {name} const digest drift")
    if defs.get("moduleState", {}).get("enum") != MODULE_STATES:
        raise GateError("schema: module state enum drift")
    if defs.get("completionState", {}).get("enum") != COMPLETION_STATES:
        raise GateError("schema: completion state enum drift")
    if defs.get("resultState", {}).get("enum") != [
        "NOT_RUN",
        "FAIL",
        "PASS",
    ]:
        raise GateError("schema: result state enum drift")

    expected_root_refs = {
        "authority": "#/$defs/authority",
        "allowed_module_api_transitions": "#/$defs/moduleTransitions",
        "completion_state_domain": "#/$defs/completionStateDomain",
        "cmake_component_contract": "#/$defs/cmakeComponentContract",
        "module_api_completion_mapping": "#/$defs/moduleApiCompletionMapping",
        "inter_module_port_contract": "#/$defs/interModulePortContract",
        "fabric_selection_port_contract": (
            "#/$defs/fabricSelectionPortContract"
        ),
        "acceptance_evidence_contract": (
            "#/$defs/acceptanceEvidenceContract"
        ),
        "independent_review_contract": (
            "#/$defs/independentReviewContract"
        ),
        "multi_instance_acceptance_contract": (
            "#/$defs/multiInstanceAcceptanceContract"
        ),
        "abi_layout_gate_contract": "#/$defs/abiLayoutGateContract",
        "version_coexistence_contract": "#/$defs/versionCoexistenceContract",
        "identity_attachment_precondition_contract": (
            "#/$defs/identityAttachmentPreconditionContract"
        ),
    }
    for property_name, reference in expected_root_refs.items():
        if schema["properties"].get(property_name) != {"$ref": reference}:
            raise GateError(f"schema: root ref drift at {property_name}")

    def const_object(definition_name: str) -> dict[str, Any]:
        properties = defs[definition_name]["properties"]
        if not all(
            isinstance(value, dict) and set(value) == {"const"}
            for value in properties.values()
        ):
            raise GateError(
                f"schema: {definition_name} must use exact const properties"
            )
        return {key: value["const"] for key, value in properties.items()}

    if const_object("moduleApiCompletionMapping") != (
        EXPECTED_MODULE_API_COMPLETION_MAPPING
    ):
        raise GateError("schema: module/completion mapping const drift")
    if const_object("interModulePortContract") != (
        EXPECTED_INTER_MODULE_PORT_CONTRACT
    ):
        raise GateError("schema: inter-module port C ABI const drift")
    if const_object("multiInstanceAcceptanceContract") != (
        EXPECTED_MULTI_INSTANCE_CONTRACT
    ):
        raise GateError("schema: 2x2 instance contract const drift")
    if const_object("abiLayoutGateContract") != (
        EXPECTED_ABI_LAYOUT_GATE_CONTRACT
    ):
        raise GateError("schema: ABI layout gate const drift")
    if const_object("versionCoexistenceContract") != (
        EXPECTED_VERSION_COINSTALL_CONTRACT
    ):
        raise GateError("schema: version coexistence const drift")
    cmake_schema = defs["cmakeComponentContract"]["properties"]
    if cmake_schema.get("variable_pattern") != {
        "const": EXPECTED_CMAKE_CONTRACT["variable_pattern"]
    }:
        raise GateError("schema: CMake variable pattern drift")
    if cmake_schema.get("variables") != {
        "const": EXPECTED_CMAKE_CONTRACT["variables"]
    }:
        raise GateError("schema: CMake metadata variables drift")
    semantics_schema = cmake_schema.get("semantics", {})
    semantics_properties = semantics_schema.get("properties")
    if not isinstance(semantics_properties, dict):
        raise GateError("schema: CMake semantics properties absent")
    if {
        key: value.get("const") if isinstance(value, dict) else None
        for key, value in semantics_properties.items()
    } != EXPECTED_CMAKE_CONTRACT["semantics"]:
        raise GateError("schema: CMake component semantics const drift")

    package_metadata_schema = (
        defs["package"]["properties"].get("exported_metadata_variables")
    )
    if package_metadata_schema != {
        "oneOf": [{"const": []}, {"const": METADATA_VARIABLES}]
    }:
        raise GateError("schema: package exported metadata drift")
    cross_schema = schema["properties"].get("cross_module_acceptance", {})
    if (
        cross_schema.get("minItems") != 2
        or cross_schema.get("maxItems") != 2
        or cross_schema.get("items")
        != {"$ref": "#/$defs/crossModuleAcceptance"}
    ):
        raise GateError("schema: cross-module acceptance cardinality/ref drift")
    cross_definition = defs["crossModuleAcceptance"]["properties"]
    if cross_definition.get("id") != {
        "enum": [
            "PM-COMPOSITION-2X2-01",
            "PM-IDENTITY-PRECONDITION-2X2-01",
        ]
    }:
        raise GateError("schema: cross-module acceptance ID domain drift")
    if (
        cross_definition.get("covered_module_ids", {}).get("minItems") != 6
        or cross_definition.get("covered_module_ids", {}).get("maxItems") != 8
    ):
        raise GateError("schema: cross-module coverage bound drift")


def compatibility_authority(matrix: dict[str, Any]) -> tuple[
    dict[str, dict[str, Any]], dict[str, dict[str, Any]]
]:
    if matrix.get("completion_states") != COMPLETION_STATES:
        raise GateError("compatibility matrix completion-state domain drift")
    module_domain = closed(
        matrix.get("module_api_domain"),
        {
            "manifest_path",
            "schema_path",
            "schema",
            "schema_version",
            "completion_mapping_path",
            "completion_mapping_pointer",
            "identity_attachment_precondition_path",
            "identity_attachment_precondition_pointer",
            "fabric_selection_port_path",
            "fabric_selection_port_pointer",
            "acceptance_evidence_contract_path",
            "acceptance_evidence_contract_pointer",
            "independent_review_contract_path",
            "independent_review_contract_pointer",
            "module_promotion_authority_pointer",
            "states",
            "allowed_transitions",
            "supplemental_completion_features",
        },
        "compatibility.module_api_domain",
    )
    if module_domain["manifest_path"] != "public-module-manifest.json":
        raise GateError("compatibility module manifest path drift")
    if module_domain["schema_path"] != (
        "spec/public-module-manifest-v1.schema.json"
    ):
        raise GateError("compatibility module schema path drift")
    if module_domain["schema"] != "ninlil-public-module-manifest-v1":
        raise GateError("compatibility module schema id drift")
    if module_domain["schema_version"] != 1:
        raise GateError("compatibility module schema version drift")
    if module_domain["completion_mapping_path"] != "public-module-manifest.json":
        raise GateError("compatibility module/completion mapping path drift")
    if (
        module_domain["completion_mapping_pointer"]
        != "/module_api_completion_mapping"
    ):
        raise GateError("compatibility module/completion mapping pointer drift")
    if (
        module_domain["identity_attachment_precondition_path"]
        != "public-module-manifest.json"
    ):
        raise GateError(
            "compatibility Identity/Attachment precondition path drift"
        )
    if (
        module_domain["identity_attachment_precondition_pointer"]
        != "/identity_attachment_precondition_contract"
    ):
        raise GateError(
            "compatibility Identity/Attachment precondition pointer drift"
        )
    if (
        module_domain["fabric_selection_port_path"]
        != "public-module-manifest.json"
        or module_domain["fabric_selection_port_pointer"]
        != "/fabric_selection_port_contract"
    ):
        raise GateError("compatibility Fabric selection port authority drift")
    if (
        module_domain["acceptance_evidence_contract_path"]
        != "public-module-manifest.json"
        or module_domain["acceptance_evidence_contract_pointer"]
        != "/acceptance_evidence_contract"
    ):
        raise GateError("compatibility acceptance evidence authority drift")
    if (
        module_domain["independent_review_contract_path"]
        != "public-module-manifest.json"
        or module_domain["independent_review_contract_pointer"]
        != "/independent_review_contract"
    ):
        raise GateError("compatibility independent review authority drift")
    if (
        module_domain["module_promotion_authority_pointer"]
        != "/modules/*/promotion_authority"
    ):
        raise GateError("compatibility module promotion authority pointer drift")
    if module_domain["states"] != MODULE_STATES:
        raise GateError("compatibility module state domain drift")
    if module_domain["allowed_transitions"] != MODULE_TRANSITIONS:
        raise GateError("compatibility module transitions drift")
    if module_domain["supplemental_completion_features"] != [
        SUPPLEMENTAL_RF_FEATURE
    ]:
        raise GateError("compatibility supplemental completion feature drift")

    feature_items = matrix.get("features")
    platform_items = matrix.get("platforms")
    if not isinstance(feature_items, list) or not isinstance(platform_items, list):
        raise GateError("compatibility features/platforms must be arrays")
    features: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(
        feature_items + module_domain["supplemental_completion_features"]
    ):
        if not isinstance(item, dict):
            raise GateError(f"compatibility feature[{index}] must be an object")
        feature_id = string(item.get("id"), f"compatibility feature[{index}].id")
        if feature_id in features:
            raise GateError(f"duplicate completion feature id {feature_id}")
        state_index(
            item.get("state"),
            COMPLETION_STATES,
            f"compatibility feature {feature_id}",
        )
        depends = item.get("depends_on")
        list_unique_strings(
            depends, f"compatibility feature {feature_id}.depends_on"
        )
        features[feature_id] = item
    for feature_id, item in features.items():
        for dependency in item["depends_on"]:
            if dependency not in features:
                raise GateError(
                    f"completion feature {feature_id}: unknown dependency {dependency}"
                )

    platforms: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(platform_items):
        if not isinstance(item, dict):
            raise GateError(f"compatibility platform[{index}] must be an object")
        platform_id = string(item.get("id"), f"platform[{index}].id")
        if platform_id in platforms:
            raise GateError(f"duplicate platform id {platform_id}")
        state_index(
            item.get("state"), COMPLETION_STATES, f"platform {platform_id}"
        )
        platforms[platform_id] = item
    return features, platforms


def feature_closure(
    feature_id: str, features: dict[str, dict[str, Any]]
) -> list[str]:
    ordered: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(current: str) -> None:
        if current in visiting:
            raise GateError(f"completion dependency cycle at {current}")
        if current in visited:
            return
        visiting.add(current)
        for dependency in features[current]["depends_on"]:
            visit(dependency)
        visiting.remove(current)
        visited.add(current)
        ordered.append(current)

    visit(feature_id)
    return ordered


def validate_module_promotion_authority(
    module_id: str,
    module_state: str,
    value: Any,
) -> None:
    authority = closed(
        value,
        {
            "normative_spec_path",
            "normative_spec_status",
            "independent_review_path",
            "independent_review_status",
            "reviewed_commit_sha",
            "review_artifact_sha256",
            "reviewer_identity",
            "reviewer_provenance_kind",
            "reviewer_provenance_path",
            "reviewer_provenance_sha256",
            "implementer_identities",
            "separation_verification",
        },
        f"module {module_id}.promotion_authority",
    )
    expected_spec, expected_review = EXPECTED_PROMOTION_PATHS[module_id]
    if authority["normative_spec_path"] != expected_spec:
        raise GateError(f"module {module_id}: normative spec path drift")
    if authority["independent_review_path"] != expected_review:
        raise GateError(f"module {module_id}: independent review path drift")

    if module_id == "fabric_v1" and module_state == "PACKAGE_EXPERIMENTAL":
        # ADR-0029 deliberately uses the small V1 specification review, not
        # ADR-0028's future eight-module GitHub promotion-receipt process.
        # Validate that exact, local authority without manufacturing a commit,
        # reviewer identity, or implementation-review claim that does not exist.
        spec_path = repo_path(
            expected_spec,
            "module fabric_v1.normative_spec_path",
            require_exists=True,
            require_file=True,
        )
        if authority["normative_spec_status"] != "ACCEPTED":
            raise GateError("module fabric_v1: ADR-0029 must remain Accepted")
        spec_text = spec_path.read_text(encoding="utf-8")
        if canonical_markdown_status(spec_text, "module fabric_v1 normative spec") != "Accepted":
            raise GateError("module fabric_v1: ADR-0029 status mismatch")

        review_path = repo_path(
            expected_review,
            "module fabric_v1.independent_review_path",
            require_exists=True,
            require_file=True,
        )
        review_bytes = review_path.read_bytes()
        review_text = review_bytes.decode("utf-8")
        if authority["independent_review_status"] != "GO":
            raise GateError("module fabric_v1: specification review is not GO")
        if "Decision: **GO — P0=0 / P1=0 / P2=0**" not in review_text:
            raise GateError("module fabric_v1: specification review verdict drift")
        if "ADR-0029 is accepted as the V1 public boundary" not in review_text:
            raise GateError("module fabric_v1: specification review scope drift")
        review_digest = authority["review_artifact_sha256"]
        if (
            not isinstance(review_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", review_digest) is None
            or hashlib.sha256(review_bytes).hexdigest() != review_digest
        ):
            raise GateError("module fabric_v1: specification review digest mismatch")
        if (
            authority["reviewed_commit_sha"] is not None
            or authority["reviewer_identity"] is not None
            or authority["reviewer_provenance_kind"] is not None
            or authority["reviewer_provenance_path"] is not None
            or authority["reviewer_provenance_sha256"] is not None
            or authority["implementer_identities"] != []
            or authority["separation_verification"] != "UNVERIFIED"
        ):
            raise GateError(
                "module fabric_v1: unavailable review provenance must not be inferred"
            )
        return

    spec_status = authority["normative_spec_status"]
    if spec_status not in {"NOT_CREATED", "PROPOSED", "ACCEPTED", "REJECTED"}:
        raise GateError(f"module {module_id}: unknown normative spec status")
    spec_path = repo_path(expected_spec, f"module {module_id}.normative_spec_path")
    if spec_status == "NOT_CREATED":
        if spec_path.exists():
            raise GateError(
                f"module {module_id}: untracked normative spec status false green"
            )
    else:
        if not spec_path.is_file() or spec_path.stat().st_size == 0:
            raise GateError(f"module {module_id}: normative spec absent or empty")
        spec_text = spec_path.read_text(encoding="utf-8")
        parsed_status = canonical_markdown_status(
            spec_text, f"module {module_id} normative spec"
        ).upper()
        if parsed_status != spec_status:
            raise GateError(f"module {module_id}: normative spec status mismatch")
        parsed_module_id = canonical_single_metadata(
            spec_text,
            f"module {module_id} normative spec",
            "Module ID:",
            r"- Module ID: `([a-z][a-z0-9_]*)`",
        )
        if parsed_module_id != module_id:
            raise GateError(f"module {module_id}: normative spec identity mismatch")

    review_status = authority["independent_review_status"]
    if review_status not in {"NOT_RUN", "NO_GO", "GO"}:
        raise GateError(f"module {module_id}: unknown independent review status")
    review_path = repo_path(
        expected_review,
        f"module {module_id}.independent_review_path",
    )
    reviewed_commit = authority["reviewed_commit_sha"]
    review_digest = authority["review_artifact_sha256"]
    reviewer_identity = authority["reviewer_identity"]
    provenance_kind = authority["reviewer_provenance_kind"]
    provenance_path_value = authority["reviewer_provenance_path"]
    provenance_digest = authority["reviewer_provenance_sha256"]
    implementer_identities = authority["implementer_identities"]
    separation_verification = authority["separation_verification"]
    if review_status == "NOT_RUN":
        if (
            reviewed_commit is not None
            or review_digest is not None
            or reviewer_identity is not None
            or provenance_kind is not None
            or provenance_path_value is not None
            or provenance_digest is not None
            or implementer_identities != []
            or separation_verification != "NOT_RUN"
        ):
            raise GateError(
                f"module {module_id}: NOT_RUN review/provenance must be null"
            )
        if review_path.exists():
            raise GateError(
                f"module {module_id}: review artifact exists while NOT_RUN"
            )
    else:
        if not review_path.is_file() or review_path.stat().st_size == 0:
            raise GateError(f"module {module_id}: review artifact absent or empty")
        if (
            not isinstance(reviewed_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", reviewed_commit) is None
        ):
            raise GateError(f"module {module_id}: reviewed commit SHA missing")
        if (
            not isinstance(review_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", review_digest) is None
            or hashlib.sha256(review_path.read_bytes()).hexdigest()
            != review_digest
        ):
            raise GateError(f"module {module_id}: review artifact digest mismatch")
        review_text = review_path.read_text(encoding="utf-8")
        reviewed_module = canonical_single_metadata(
            review_text,
            f"module {module_id} independent review",
            "Module ID:",
            r"- Module ID: `([a-z][a-z0-9_]*)`",
        )
        verdict = canonical_single_metadata(
            review_text,
            f"module {module_id} independent review",
            "Verdict:",
            r"- Verdict: \*\*(GO|NO-GO)\*\*",
        )
        artifact_commit = canonical_single_metadata(
            review_text,
            f"module {module_id} independent review",
            "Reviewed commit:",
            r"- Reviewed commit: `([0-9a-f]{40})`",
        )
        artifact_reviewer = canonical_single_metadata(
            review_text,
            f"module {module_id} independent review",
            "Reviewer identity:",
            (
                r"- Reviewer identity: "
                r"`(github-node:[A-Za-z0-9_-]+@login:[A-Za-z0-9-]+)`"
            ),
        )
        artifact_provenance_path = canonical_single_metadata(
            review_text,
            f"module {module_id} independent review",
            "Reviewer provenance path:",
            (
                r"- Reviewer provenance path: "
                r"`(evidence/public-modules/reviews/[A-Za-z0-9_.-]+\.json)`"
            ),
        )
        artifact_separation = canonical_single_metadata(
            review_text,
            f"module {module_id} independent review",
            "Separation verdict:",
            r"- Separation verdict: \*\*(UNVERIFIED|VERIFIED)\*\*",
        )
        if reviewed_module != module_id or artifact_commit != reviewed_commit:
            raise GateError(f"module {module_id}: review authority binding mismatch")
        if (
            artifact_reviewer != reviewer_identity
            or artifact_provenance_path != provenance_path_value
            or artifact_separation != separation_verification
        ):
            raise GateError(
                f"module {module_id}: review provenance metadata mismatch"
            )
        expected_verdict = "GO" if review_status == "GO" else "NO-GO"
        if verdict != expected_verdict:
            raise GateError(f"module {module_id}: review verdict mismatch")
        identity_pattern = r"github-node:[A-Za-z0-9_-]+@login:[A-Za-z0-9-]+"
        string(
            reviewer_identity,
            f"module {module_id}.reviewer_identity",
            identity_pattern,
        )
        if provenance_kind != (
            "GITHUB_PR_REVIEW_API_RECEIPT_WITH_OIDC_ATTESTATION_V1"
        ):
            raise GateError(
                f"module {module_id}: unknown reviewer provenance kind"
            )
        provenance_path = repo_path(
            provenance_path_value,
            f"module {module_id}.reviewer_provenance_path",
            require_exists=True,
            require_file=True,
        )
        if (
            not isinstance(provenance_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", provenance_digest) is None
            or hashlib.sha256(provenance_path.read_bytes()).hexdigest()
            != provenance_digest
        ):
            raise GateError(
                f"module {module_id}: reviewer provenance digest mismatch"
            )
        provenance_receipt = load_json_strict(provenance_path)
        validate_boolean_locations(
            provenance_receipt,
            f"module {module_id}.reviewer_provenance",
            (),
        )
        closed(
            provenance_receipt,
            {
                "schema",
                "schema_version",
                "provider",
                "repository",
                "review_id",
                "pull_request_number",
                "reviewer_node_id",
                "reviewer_login",
                "reviewed_commit_sha",
                "review_state",
                "submitted_at_utc",
                "oidc_issuer",
                "oidc_subject",
                "attestation_bundle_sha256",
                "implementer_identities",
            },
            f"module {module_id}.reviewer_provenance",
        )
        if (
            provenance_receipt["schema"]
            != "ninlil_public_module_github_review_receipt_v1"
            or strict_integer(
                provenance_receipt["schema_version"],
                f"module {module_id}.reviewer_provenance.schema_version",
            )
            != 1
            or provenance_receipt["provider"] != "GITHUB"
            or provenance_receipt["review_state"] != "APPROVED"
            or provenance_receipt["oidc_issuer"]
            != "https://token.actions.githubusercontent.com"
        ):
            raise GateError(
                f"module {module_id}: reviewer provenance domain mismatch"
            )
        strict_integer(
            provenance_receipt["review_id"],
            f"module {module_id}.reviewer_provenance.review_id",
            minimum=1,
        )
        strict_integer(
            provenance_receipt["pull_request_number"],
            f"module {module_id}.reviewer_provenance.pull_request_number",
            minimum=1,
        )
        reviewer_node = string(
            provenance_receipt["reviewer_node_id"],
            f"module {module_id}.reviewer_provenance.reviewer_node_id",
            r"[A-Za-z0-9_-]+",
        )
        reviewer_login = string(
            provenance_receipt["reviewer_login"],
            f"module {module_id}.reviewer_provenance.reviewer_login",
            r"[A-Za-z0-9-]+",
        )
        if (
            reviewer_identity
            != f"github-node:{reviewer_node}@login:{reviewer_login}"
            or provenance_receipt["reviewed_commit_sha"] != reviewed_commit
        ):
            raise GateError(
                f"module {module_id}: reviewer provenance identity/commit mismatch"
            )
        for field, pattern in (
            ("repository", r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"),
            (
                "submitted_at_utc",
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            ),
            (
                "oidc_subject",
                r"repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:.+",
            ),
            ("attestation_bundle_sha256", r"[0-9a-f]{64}"),
        ):
            string(
                provenance_receipt[field],
                f"module {module_id}.reviewer_provenance.{field}",
                pattern,
            )
        implementers = list_unique_strings(
            implementer_identities,
            f"module {module_id}.implementer_identities",
            allow_empty=False,
        )
        if any(
            re.fullmatch(identity_pattern, identity) is None
            for identity in implementers
        ):
            raise GateError(
                f"module {module_id}: malformed implementer identity"
            )
        if reviewer_identity in implementers:
            raise GateError(
                f"module {module_id}: reviewer/implementer identity collision"
            )
        if provenance_receipt["implementer_identities"] != implementers:
            raise GateError(
                f"module {module_id}: provenance implementer roster mismatch"
            )
        if separation_verification not in {"UNVERIFIED", "VERIFIED"}:
            raise GateError(
                f"module {module_id}: unknown separation verification"
            )
        severities = {
            level: canonical_single_metadata(
                review_text,
                f"module {module_id} independent review",
                f"{level}:",
                rf"- {level}: \*\*([0-9]+)\*\*",
            )
            for level in ("P0", "P1", "P2")
        }
        if review_status == "GO":
            if any(value != "0" for value in severities.values()):
                raise GateError(
                    f"module {module_id}: GO requires P0/P1/P2 all zero"
                )
            require_offline_verified_independent_review(
                review_status,
                separation_verification,
                f"module {module_id}",
            )

    if module_state != "PRIVATE_CANDIDATE":
        if spec_status != "ACCEPTED" or review_status != "GO":
            raise GateError(
                f"module {module_id}: PUBLIC_API_SPEC_ACCEPTED promotion requires "
                "module-specific Accepted normative spec and independent GO "
                "with P0/P1/P2 zero"
            )


def validate_module(
    module: dict[str, Any],
    expected: dict[str, Any],
    features: dict[str, dict[str, Any]],
    platforms: dict[str, dict[str, Any]],
    modules_by_id: dict[str, dict[str, Any]],
) -> None:
    module_id = module["id"]
    closed(
        module,
        {
            "id",
            "api_version",
            "module_api_state",
            "state_history",
            "promotion_authority",
            "completion_feature_mappings",
            "platforms",
            "package",
            "symbol_prefix",
            "wire_profiles",
            "storage_schemas",
            "namespace_policy",
            "coinstallability",
            "dependencies",
            "instance_policy",
            "abi_contract",
            "acceptance_ids",
        },
        f"module {module_id}",
    )
    if module.get("api_version") != "1.0.0":
        raise GateError(f"module {module_id}: API version drift")
    current_index = state_index(
        module.get("module_api_state"), MODULE_STATES, f"module {module_id}"
    )
    history = list_unique_strings(
        module.get("state_history"), f"module {module_id}.state_history", False
    )
    if history[0] != "PRIVATE_CANDIDATE":
        raise GateError(f"module {module_id}: history must start PRIVATE_CANDIDATE")
    if history[-1] != module["module_api_state"]:
        raise GateError(f"module {module_id}: history/current state mismatch")
    for previous, current in zip(history, history[1:]):
        state_index(previous, MODULE_STATES, f"module {module_id}.history")
        state_index(current, MODULE_STATES, f"module {module_id}.history")
        if current not in MODULE_TRANSITIONS[previous]:
            raise GateError(
                f"module {module_id}: illegal state jump {previous}->{current}"
            )
    if module.get("platforms") != expected["platforms"]:
        raise GateError(f"module {module_id}: platform roster drift")
    for platform_id in module["platforms"]:
        if platform_id not in platforms:
            raise GateError(f"module {module_id}: unknown platform {platform_id}")

    mappings = module.get("completion_feature_mappings")
    if not isinstance(mappings, list) or not mappings:
        raise GateError(f"module {module_id}: completion mapping required")
    mapped_features: list[str] = []
    covered_platforms: set[str] = set()
    for index, mapping in enumerate(mappings):
        closed(
            mapping,
            {"feature_id", "platforms"},
            f"module {module_id}.mapping[{index}]",
        )
        feature_id = string(
            mapping["feature_id"], f"module {module_id}.mapping[{index}].feature_id"
        )
        if feature_id in mapped_features or feature_id not in features:
            raise GateError(
                f"module {module_id}: duplicate/unknown mapped feature {feature_id}"
            )
        mapped_features.append(feature_id)
        mapping_platforms = list_unique_strings(
            mapping["platforms"],
            f"module {module_id}.mapping[{index}].platforms",
            False,
        )
        if not set(mapping_platforms).issubset(set(module["platforms"])):
            raise GateError(f"module {module_id}: mapping platform outside roster")
        covered_platforms.update(mapping_platforms)
    if mapped_features != expected["mapping_features"]:
        raise GateError(f"module {module_id}: completion feature mapping drift")
    if covered_platforms != set(module["platforms"]):
        raise GateError(f"module {module_id}: platform lacks completion mapping")

    package_value = closed(
        module.get("package"),
        {
            "component",
            "host_cmake_target",
            "esp_idf_component",
            "artifact_kind",
            "public_header_root",
            "install_availability",
            "dependencies",
            "exported_metadata_variables",
        },
        f"module {module_id}.package",
    )
    fabric_experimental = (
        module_id == "fabric_v1"
        and module["module_api_state"] == "PACKAGE_EXPERIMENTAL"
    )
    expected_metadata = [] if fabric_experimental else METADATA_VARIABLES
    expected_package = copy.deepcopy(expected["package"])
    expected_package["exported_metadata_variables"] = expected_metadata
    if current_index >= MODULE_STATES.index("PACKAGE_EXPERIMENTAL"):
        expected_package["install_availability"] = "PRESENT"
    if package_value != expected_package:
        raise GateError(
            f"module {module_id}: package target/header/metadata mismatch"
        )
    if package_value["artifact_kind"] == "STATIC_ARCHIVE":
        if not isinstance(package_value["host_cmake_target"], str):
            raise GateError(f"module {module_id}: static archive target missing")
    elif package_value["artifact_kind"] == "ESP_IDF_COMPONENT":
        if (
            package_value["host_cmake_target"] is not None
            or not isinstance(package_value["esp_idf_component"], str)
        ):
            raise GateError(f"module {module_id}: ESP package surface mismatch")
    else:
        raise GateError(f"module {module_id}: unknown package artifact kind")
    if package_value["exported_metadata_variables"] != expected_metadata:
        raise GateError(f"module {module_id}: exported metadata mismatch")
    if module_id == "fabric_v1":
        source_header = repo_path(
            f"include/{package_value['public_header_root']}",
            "module fabric_v1.package.source_header",
            require_exists=True,
            require_file=True,
        )
        if source_header.stat().st_size == 0:
            raise GateError("module fabric_v1: public header is empty")
        cmake_text = executable_text_without_comments(
            repo_path("CMakeLists.txt", "module fabric_v1.CMakeLists", require_file=True)
            .read_text(encoding="utf-8"),
            cmake=True,
        )
        for pattern, label in (
            (r"add_library\s*\(\s*ninlil_fabric_v1\s+STATIC", "static target"),
            (
                r"add_library\s*\(\s*Ninlil::fabric_v1\s+ALIAS\s+ninlil_fabric_v1",
                "export alias",
            ),
            (r"install\s*\(\s*TARGETS\s+ninlil_fabric_v1", "install target"),
            (
                r"target_link_libraries\s*\(\s*ninlil_fabric_v1\s+PUBLIC\s+ninlil",
                "Foundation header dependency",
            ),
        ):
            if re.search(pattern, cmake_text) is None:
                raise GateError(f"module fabric_v1: {label} missing")
    for dependency_id in package_value["dependencies"]:
        if dependency_id not in modules_by_id or dependency_id == module_id:
            raise GateError(
                f"module {module_id}: missing package dependency {dependency_id}"
            )

    if module.get("symbol_prefix") != expected["symbol_prefix"]:
        raise GateError(f"module {module_id}: symbol prefix drift")
    storage_and_wire = EXPECTED_MODULE_STORAGE_AND_WIRE[module_id]
    if module.get("wire_profiles") != storage_and_wire["wire_profiles"]:
        raise GateError(f"module {module_id}: wire profile roster drift")
    if module.get("storage_schemas") != storage_and_wire["storage_schemas"]:
        raise GateError(f"module {module_id}: storage schema roster drift")

    namespace = closed(
        module.get("namespace_policy"),
        {
            "mode",
            "physical_namespaces",
            "partition_prefixes",
            "single_writer",
            "writer_owner",
        },
        f"module {module_id}.namespace_policy",
    )
    if namespace != storage_and_wire["namespace_policy"]:
        raise GateError(f"module {module_id}: namespace/writer policy drift")
    physical = list_unique_strings(
        namespace["physical_namespaces"],
        f"module {module_id}.physical_namespaces",
    )
    partitions = list_unique_strings(
        namespace["partition_prefixes"],
        f"module {module_id}.partition_prefixes",
    )
    if namespace["mode"] == "NONE":
        if (
            physical
            or partitions
            or namespace["single_writer"] != "NOT_APPLICABLE"
            or namespace["writer_owner"] is not None
        ):
            raise GateError(f"module {module_id}: NONE namespace policy mismatch")
    elif namespace["mode"] in {
        "CALLER_SUPPLIED_REALM_DEDICATED",
        "CALLER_SUPPLIED_REALM_SHARED_PREFIX",
    }:
        if (
            not physical
            or len(physical) != len(partitions)
            or namespace["single_writer"] != "REQUIRED"
            or not isinstance(namespace["writer_owner"], str)
        ):
            raise GateError(f"module {module_id}: durable namespace policy mismatch")
    else:
        raise GateError(f"module {module_id}: unknown namespace mode")

    coinstall = closed(
        module.get("coinstallability"),
        {
            "multiple_v1_instances",
            "v1_v2_same_process",
            "symbol_prefix_isolation",
            "storage_namespace_isolation",
            "wire_profile_isolation",
        },
        f"module {module_id}.coinstallability",
    )
    if coinstall != {
        "multiple_v1_instances": True,
        "v1_v2_same_process": "V2_NOT_ALLOCATED",
        "symbol_prefix_isolation": "REQUIRED",
        "storage_namespace_isolation": "REQUIRED_WHEN_APPLICABLE",
        "wire_profile_isolation": "REQUIRED_WHEN_APPLICABLE",
    }:
        raise GateError(f"module {module_id}: coinstallability metadata drift")

    dependencies = module.get("dependencies")
    if not isinstance(dependencies, list):
        raise GateError(f"module {module_id}: dependencies array required")
    dependency_features: list[str] = []
    for index, dependency in enumerate(dependencies):
        closed(
            dependency,
            {
                "depends_on_feature_id",
                "precondition_contract_id",
                "minimum_completion_state",
                "enforced_from_owner_module_state",
            },
            f"module {module_id}.dependency[{index}]",
        )
        feature_id = string(
            dependency["depends_on_feature_id"],
            f"module {module_id}.dependency[{index}].feature_id",
        )
        if feature_id in dependency_features or feature_id not in features:
            raise GateError(
                f"module {module_id}: duplicate/missing dependency {feature_id}"
            )
        dependency_features.append(feature_id)
        precondition_id = dependency["precondition_contract_id"]
        if feature_id == "identity-attachment-session-install":
            if precondition_id != IDENTITY_PRECONDITION_ID:
                raise GateError(
                    f"module {module_id}: Identity/Attachment dependency missing "
                    "versioned Core/Foundation precondition contract"
                )
        elif precondition_id is not None:
            raise GateError(
                f"module {module_id}: unrelated dependency carries precondition "
                f"contract {feature_id}"
            )
        minimum_completion = state_index(
            dependency["minimum_completion_state"],
            COMPLETION_STATES,
            f"module {module_id}.dependency[{index}]",
        )
        enforcement_state = state_index(
            dependency["enforced_from_owner_module_state"],
            MODULE_STATES,
            f"module {module_id}.dependency[{index}]",
        )
        if enforcement_state == 0:
            raise GateError(
                f"module {module_id}: dependency threshold cannot be private"
            )
        if current_index >= enforcement_state:
            for closure_id in feature_closure(feature_id, features):
                actual = state_index(
                    features[closure_id]["state"],
                    COMPLETION_STATES,
                    f"completion feature {closure_id}",
                )
                if actual < minimum_completion:
                    raise GateError(
                        f"module {module_id}: transitively insufficient dependency "
                        f"{closure_id}={features[closure_id]['state']} requires "
                        f"{dependency['minimum_completion_state']}"
                    )
    if (
        module_id == "radio_frag_v1"
        and "nfl1-r7-nrw1-rf-mapping" in dependency_features
    ):
        raise GateError("pure frag must not require RF mapping")
    if (
        module_id == "radio_fabric_adapter_v1"
        and "nfl1-r7-nrw1-rf-mapping" not in dependency_features
    ):
        raise GateError("radio adapter missing Accepted RF mapping dependency")
    if dependency_features != expected["dependency_features"]:
        raise GateError(f"module {module_id}: required dependency set drift")
    if module_id in IDENTITY_PRECONDITION_MODULES:
        if "identity-attachment-session-install" not in dependency_features:
            raise GateError(
                f"module {module_id}: Core/Foundation precondition dependency absent"
            )
    elif module_id == "radio_frag_v1":
        if "identity-attachment-session-install" in dependency_features:
            raise GateError(
                "pure fragmentation must remain free of identity/session authority"
            )
    elif module_id == "fabric_v1":
        if dependency_features:
            raise GateError("module fabric_v1: ADR-0029 has no public module dependency")
    else:
        raise GateError(
            f"module {module_id}: missing Identity/Attachment precondition class"
        )

    state_mapping = EXPECTED_MODULE_API_COMPLETION_MAPPING[
        module["module_api_state"]
    ]
    completion_floor = state_mapping["completion_floor"]
    if module_id == "fabric_v1" and module["module_api_state"] == "PACKAGE_EXPERIMENTAL":
        # Package presence is proven on Host without promoting ESP/HIL or the
        # broader completion feature beyond its current specification state.
        completion_floor = "SPEC_ACCEPTED"
    if completion_floor is not None:
        floor_index = state_index(
            completion_floor,
            COMPLETION_STATES,
            f"module {module_id}.completion_floor",
        )
        closure_roots = list(dict.fromkeys(mapped_features + dependency_features))
        for closure_root in closure_roots:
            closure_ids = (
                [closure_root]
                if module_id == "fabric_v1"
                and module["module_api_state"] == "PACKAGE_EXPERIMENTAL"
                else feature_closure(closure_root, features)
            )
            for closure_id in closure_ids:
                actual_index = state_index(
                    features[closure_id]["state"],
                    COMPLETION_STATES,
                    f"completion feature {closure_id}",
                )
                if actual_index < floor_index:
                    raise GateError(
                        f"module {module_id}: module/completion mapping requires "
                        f"{closure_id}>={completion_floor}, got "
                        f"{features[closure_id]['state']}"
                    )

    instance = closed(
        module.get("instance_policy"),
        {
            "immutable_module_instance_id",
            "module_instance_id_shape",
            "runtime_binding",
            "storage_locator",
            "single_writer",
            "driver_access",
            "driver_child_limit_source",
            "demux_identity",
            "aggregate_protocol",
            "fairness",
            "stale_handle_rejection",
            "cross_instance_rejection",
        },
        f"module {module_id}.instance_policy",
    )
    common_instance = {
        "immutable_module_instance_id": True,
        "module_instance_id_shape": "U128_NONZERO",
        "runtime_binding": "EXPLICIT_HANDLE_AND_GENERATION",
        "driver_child_limit_source": "PROFILE_BOUND_OR_NOT_APPLICABLE",
        "demux_identity": "OWNER_AND_CHILD_INSTANCE_ID_PLUS_GENERATION",
        "aggregate_protocol": "RESERVE_COMMIT_RELEASE",
        "fairness": "STRICT_ROUND_ROBIN_ONE_QUANTUM",
        "stale_handle_rejection": True,
        "cross_instance_rejection": True,
    }
    for key, value in common_instance.items():
        if instance.get(key) != value:
            raise GateError(f"module {module_id}: instance policy drift at {key}")
    if namespace["mode"] == "NONE":
        if (
            instance["storage_locator"] != "NOT_APPLICABLE"
            or instance["single_writer"] != "NOT_APPLICABLE"
        ):
            raise GateError(f"module {module_id}: storage instance policy mismatch")
    else:
        if (
            instance["storage_locator"]
            != "CALLER_SUPPLIED_REALM_AND_PARTITION"
            or instance["single_writer"] != "REQUIRED"
        ):
            raise GateError(f"module {module_id}: storage locator/writer mismatch")
    if instance["driver_access"] not in {
        "BOUNDED_CHILD_HANDLE",
        "NOT_APPLICABLE",
    }:
        raise GateError(f"module {module_id}: invalid driver access policy")

    acceptance_ids = list_unique_strings(
        module.get("acceptance_ids"),
        f"module {module_id}.acceptance_ids",
        False,
    )
    if acceptance_ids != expected["acceptance_ids"]:
        raise GateError(f"module {module_id}: acceptance mapping drift")
    abi = closed(
        module.get("abi_contract"),
        {
            "public_surface",
            "layout_invariant_across_compile_definitions",
            "compile_time_layout_negative_acceptance_id",
            "v1_v2_metadata",
        },
        f"module {module_id}.abi_contract",
    )
    if (
        abi["public_surface"]
        != "OPAQUE_HANDLE_OR_CALLER_OWNED_OPAQUE_WORKSPACE"
        or abi["layout_invariant_across_compile_definitions"] is not True
        or abi["v1_v2_metadata"] != "V2_NOT_ALLOCATED"
        or abi["compile_time_layout_negative_acceptance_id"]
        not in acceptance_ids
    ):
        raise GateError(f"module {module_id}: public ABI invariant policy drift")

    if current_index >= MODULE_STATES.index("PUBLIC_API_SPEC_ACCEPTED"):
        for package_dependency in package_value["dependencies"]:
            dependency_state = modules_by_id[package_dependency]["module_api_state"]
            if state_index(
                dependency_state,
                MODULE_STATES,
                f"module {module_id}.package dependency {package_dependency}",
            ) < MODULE_STATES.index("PUBLIC_API_SPEC_ACCEPTED"):
                raise GateError(
                    f"module {module_id}: insufficient module dependency "
                    f"{package_dependency}={dependency_state}"
                )

    if module["module_api_state"] == "RELEASE_SUPPORTED":
        for platform_id in module["platforms"]:
            if platforms[platform_id]["state"] != "RELEASE_SUPPORTED":
                raise GateError(
                    f"module {module_id}: module release without platform release "
                    f"{platform_id}={platforms[platform_id]['state']}"
                )
        for feature_id in mapped_features:
            if features[feature_id]["state"] != "RELEASE_SUPPORTED":
                raise GateError(
                    f"module {module_id}: release without mapped feature release "
                    f"{feature_id}={features[feature_id]['state']}"
                )
    validate_module_promotion_authority(
        module_id,
        module["module_api_state"],
        module.get("promotion_authority"),
    )


def validate_cross_module_acceptance(
    manifest: dict[str, Any],
    modules_by_id: dict[str, dict[str, Any]],
) -> None:
    values = manifest.get("cross_module_acceptance")
    if not isinstance(values, list) or len(values) != 2:
        raise GateError("cross-module acceptance must contain exact two records")
    expected = {
        EXPECTED_MULTI_INSTANCE_CONTRACT["acceptance_id"]: {
            "covered": list(EXPECTED_MODULES),
            "test_path": "tests/public_modules/composition_2x2.c",
            "requirement": "for every module, two Runtime plus two distinct module instances; exact positive and negative bindings, realm and writer isolation, sole physical driver owner with bounded children, aggregate all-or-none reservation and strict fairness",
            "tokens": (
                "two Runtime",
                "two distinct module instances",
                "realm and writer isolation",
                "sole physical driver owner",
                "aggregate all-or-none reservation",
            ),
        },
        IDENTITY_ACCEPTANCE_ID: {
            "covered": IDENTITY_ACCEPTANCE_MODULES,
            "test_path": (
                "tests/public_modules/identity_attachment_precondition_2x2.c"
            ),
            "requirement": "for Fabric and every identity/session-dependent module, two Runtime plus two distinct module and provider instances; valid binding success plus cross/stale/expired/revoked/rollback/restart-old-handle, unknown key usage or flag bits, subscribe failure release order, unsubscribe drain order, and torn/corrupt/ambiguous checkpoint fail-closed negatives with no key export",
            "tokens": (
                "two Runtime",
                "two distinct module and provider instances",
                "cross/stale/expired/revoked/rollback/restart-old-handle",
                "unknown key usage or flag bits",
                "subscribe failure release order",
                "unsubscribe drain order",
                "torn/corrupt/ambiguous checkpoint",
                "no key export",
            ),
        },
    }
    by_id: dict[str, dict[str, Any]] = {}
    evidence_paths: set[str] = set()
    for index, raw in enumerate(values):
        item = closed(
            raw,
            {"id", "covered_module_ids", "requirement", "test", "evidence", "hil"},
            f"cross-module acceptance[{index}]",
        )
        acceptance_id = string(
            item["id"], f"cross-module acceptance[{index}].id"
        )
        if acceptance_id not in expected or acceptance_id in by_id:
            raise GateError(
                f"cross-module acceptance duplicate/unknown ID {acceptance_id}"
            )
        by_id[acceptance_id] = item
        contract = expected[acceptance_id]
        covered = list_unique_strings(
            item["covered_module_ids"],
            f"cross-module acceptance {acceptance_id}.covered_module_ids",
            False,
        )
        if covered != contract["covered"]:
            raise GateError(
                f"cross-module acceptance {acceptance_id} module coverage drift"
            )
        if not set(covered).issubset(set(modules_by_id)):
            raise GateError(
                f"cross-module acceptance {acceptance_id} unknown module"
            )
        requirement = string(
            item["requirement"],
            f"cross-module acceptance {acceptance_id}.requirement",
        )
        if requirement != contract["requirement"]:
            raise GateError(
                f"cross-module acceptance {acceptance_id} exact requirement drift"
            )
        test = closed(
            item["test"],
            {"path", "state"},
            f"cross-module acceptance {acceptance_id}.test",
        )
        if test["path"] != contract["test_path"]:
            raise GateError(
                f"cross-module acceptance {acceptance_id} test path drift"
            )
        if test["state"] not in RESULT_STATES:
            raise GateError(
                f"cross-module acceptance {acceptance_id} test state invalid"
            )
        evidence = closed(
            item["evidence"],
            {"profile_receipts", "path", "sha256", "state"},
            f"cross-module acceptance {acceptance_id}.evidence",
        )
        if evidence["state"] != test["state"]:
            raise GateError(
                f"cross-module acceptance {acceptance_id} state mismatch"
            )
        validate_evidence_mapping(
            evidence,
            f"cross-module acceptance {acceptance_id}.evidence",
            "evidence/",
            evidence_paths,
            acceptance_id=acceptance_id,
            test=test,
            allowed_platforms={
                platform_id
                for module_id in covered
                for platform_id in modules_by_id[module_id]["platforms"]
            },
            module_id=None,
            module_api_state=None,
        )
        hil = closed(
            item["hil"],
            {"required", "state", "evidence_path", "sha256"},
            f"cross-module acceptance {acceptance_id}.hil",
        )
        if (
            hil["required"] is not False
            or hil["state"] != "NOT_RUN"
            or hil["evidence_path"] is not None
            or hil["sha256"] is not None
        ):
            raise GateError(
                f"cross-module acceptance {acceptance_id} must be non-HIL"
            )
        test_path = repo_path(
            test["path"],
            f"cross-module acceptance {acceptance_id}.test.path",
        )
        if test["state"] != "NOT_RUN" and not test_path.is_file():
            raise GateError(
                f"cross-module acceptance {acceptance_id} test path absent"
            )
    if set(by_id) != set(expected):
        raise GateError("cross-module acceptance ID closure drift")
    identity_acceptance = by_id[
        IDENTITY_ACCEPTANCE_ID
    ]
    if any(
        modules_by_id[module_id]["module_api_state"] == "RELEASE_SUPPORTED"
        for module_id in IDENTITY_PRECONDITION_MODULES
    ):
        if (
            identity_acceptance["test"]["state"] != "PASS"
            or identity_acceptance["evidence"]["state"] != "PASS"
        ):
            raise GateError(
                "Identity/Attachment-dependent release without global 2x2 PASS"
            )


def validate_acceptance(
    manifest: dict[str, Any],
    modules_by_id: dict[str, dict[str, Any]],
) -> None:
    values = manifest.get("acceptance")
    if not isinstance(values, list) or not values:
        raise GateError("acceptance ledger required")
    by_id: dict[str, dict[str, Any]] = {}
    test_paths: set[str] = set()
    evidence_paths: set[str] = set()
    hil_paths: set[str] = set()
    for index, item in enumerate(values):
        closed(
            item,
            {"id", "module_id", "requirement", "test", "evidence", "hil"},
            f"acceptance[{index}]",
        )
        acceptance_id = string(
            item["id"],
            f"acceptance[{index}].id",
            r"PM-(FAB|WIFI|RR|R7|MFDT)-[A-Z0-9-]+",
        )
        if acceptance_id in by_id:
            raise GateError(f"duplicate acceptance id {acceptance_id}")
        module_id = string(item["module_id"], f"acceptance {acceptance_id}.module")
        if module_id not in modules_by_id:
            raise GateError(
                f"acceptance {acceptance_id}: unknown module {module_id}"
            )
        expected_ledger = EXPECTED_ACCEPTANCE_LEDGER.get(acceptance_id)
        if expected_ledger is None:
            raise GateError(f"acceptance {acceptance_id}: unknown exact ledger ID")
        expected_module, expected_requirement, expected_hil = expected_ledger
        if module_id != expected_module:
            raise GateError(f"acceptance {acceptance_id}: exact module binding drift")
        if item["requirement"] != expected_requirement:
            raise GateError(f"acceptance {acceptance_id}: exact requirement drift")
        test = closed(
            item["test"], {"path", "state"}, f"acceptance {acceptance_id}.test"
        )
        test_path = string(
            test["path"],
            f"acceptance {acceptance_id}.test.path",
            r"(tests|tools)/[A-Za-z0-9_./-]+",
        )
        if test_path != EXPECTED_ACCEPTANCE_TEST_PATHS[acceptance_id]:
            raise GateError(f"acceptance {acceptance_id}: exact test path drift")
        if test_path in test_paths:
            raise GateError(f"acceptance {acceptance_id}: duplicate test mapping")
        test_paths.add(test_path)
        module_state = modules_by_id[module_id]["module_api_state"]
        abi_acceptance_id = modules_by_id[module_id]["abi_contract"][
            "compile_time_layout_negative_acceptance_id"
        ]
        fabric_experimental = (
            module_id == "fabric_v1"
            and module_state == "PACKAGE_EXPERIMENTAL"
        )
        if (
            acceptance_id == abi_acceptance_id
            and not fabric_experimental
            and not test_path.endswith("_abi_negative.c")
        ):
            raise GateError(
                f"module {module_id}: compile-time layout negative gate missing"
            )
        if test["state"] not in RESULT_STATES:
            raise GateError(
                f"acceptance {acceptance_id}: unknown test state {test['state']}"
            )

        evidence = closed(
            item["evidence"],
            {"profile_receipts", "path", "sha256", "state"},
            f"acceptance {acceptance_id}.evidence",
        )
        if evidence["state"] not in RESULT_STATES:
            raise GateError(f"acceptance {acceptance_id}: unknown evidence state")
        if evidence["state"] != test["state"]:
            raise GateError(
                f"acceptance {acceptance_id}: test/evidence state mismatch"
            )
        validate_evidence_mapping(
            evidence,
            f"acceptance {acceptance_id}.evidence",
            "evidence/",
            evidence_paths,
            acceptance_id=acceptance_id,
            test=test,
            allowed_platforms=set(modules_by_id[module_id]["platforms"]),
            module_id=module_id,
            module_api_state=modules_by_id[module_id]["module_api_state"],
        )

        hil = closed(
            item["hil"],
            {"required", "state", "evidence_path", "sha256"},
            f"acceptance {acceptance_id}.hil",
        )
        if not isinstance(hil["required"], bool) or hil["state"] not in RESULT_STATES:
            raise GateError(f"acceptance {acceptance_id}: invalid HIL state")
        if hil["required"] is not (acceptance_id in EXPECTED_HIL_IDS):
            raise GateError(f"acceptance {acceptance_id}: HIL required mapping drift")
        if hil["required"] is not expected_hil:
            raise GateError(f"acceptance {acceptance_id}: exact HIL classification drift")
        hil_evidence = {
            "profile_receipts": [],
            "path": hil["evidence_path"],
            "sha256": hil["sha256"],
            "state": hil["state"],
        }
        validate_evidence_mapping(
            hil_evidence,
            f"acceptance {acceptance_id}.hil",
            "evidence/hil/",
            hil_paths,
            acceptance_id=acceptance_id,
            test=test,
            allowed_platforms=set(modules_by_id[module_id]["platforms"]),
            module_id=module_id,
            module_api_state=modules_by_id[module_id]["module_api_state"],
        )
        if hil["required"] and hil["state"] != test["state"]:
            raise GateError(
                f"acceptance {acceptance_id}: HIL/test state mismatch"
            )
        by_id[acceptance_id] = item

    referenced: list[str] = []
    for module_id, module in modules_by_id.items():
        for acceptance_id in module["acceptance_ids"]:
            if acceptance_id not in by_id:
                raise GateError(
                    f"module {module_id}: missing acceptance/evidence mapping "
                    f"{acceptance_id}"
                )
            if by_id[acceptance_id]["module_id"] != module_id:
                raise GateError(
                    f"module {module_id}: cross-module acceptance mapping "
                    f"{acceptance_id}"
                )
            referenced.append(acceptance_id)
        instance_requirements = [
            by_id[acceptance_id]["requirement"]
            for acceptance_id in module["acceptance_ids"]
        ]
        if not any(
            "two Runtime" in requirement
            and "two distinct" in requirement
            for requirement in instance_requirements
        ):
            raise GateError(
                f"module {module_id}: exact 2 Runtime + 2 module acceptance missing"
            )
        has_identity_provider_gate = any(
            "Identity/Attachment provider 2x2 binding negatives" in requirement
            for requirement in instance_requirements
        )
        if module_id in IDENTITY_PRECONDITION_MODULES:
            if not has_identity_provider_gate:
                raise GateError(
                    f"module {module_id}: package acceptance omits "
                    "Identity/Attachment provider 2x2 negatives"
                )
        elif has_identity_provider_gate:
            raise GateError(
                "pure fragmentation acceptance must not depend on "
                "Identity/Attachment provider"
            )
    if len(referenced) != len(set(referenced)) or set(referenced) != set(by_id):
        raise GateError("acceptance manifest/test/evidence mapping is not 1:1")
    if set(by_id) != set(EXPECTED_ACCEPTANCE_LEDGER):
        raise GateError("acceptance exact ledger closure drift")

    for module_id, module in modules_by_id.items():
        state = module["module_api_state"]
        if state in {"PACKAGE_EXPERIMENTAL", "RELEASE_SUPPORTED"}:
            for acceptance_id in module["acceptance_ids"]:
                record = by_id[acceptance_id]
                if not record["hil"]["required"]:
                    if record["test"]["state"] != "PASS":
                        raise GateError(
                            f"module {module_id}: package promotion without PASS "
                            f"{acceptance_id}"
                        )
                    if not repo_path(
                        record["test"]["path"],
                        f"acceptance {acceptance_id}.test.path",
                    ).is_file():
                        raise GateError(
                            f"module {module_id}: accepted test path absent "
                            f"{record['test']['path']}"
                        )
        if state == "RELEASE_SUPPORTED":
            for acceptance_id in module["acceptance_ids"]:
                record = by_id[acceptance_id]
                if record["test"]["state"] != "PASS":
                    raise GateError(
                        f"module {module_id}: release acceptance not PASS "
                        f"{acceptance_id}"
                    )
                if (
                    record["hil"]["required"]
                    and record["hil"]["state"] != "PASS"
                ):
                    raise GateError(
                        f"module {module_id}: required HIL not PASS {acceptance_id}"
                    )


def validate_replay_receipt_claim(
    artifact: dict[str, Any],
    *,
    observed_exit_code: int,
    observed_stdout: bytes,
    observed_stderr: bytes,
    label: str,
) -> None:
    if observed_exit_code != artifact["runner_exit_code"]:
        raise GateError(f"{label}: self-reported exit code differs from replay")
    for stream, observed in (
        ("stdout", observed_stdout),
        ("stderr", observed_stderr),
    ):
        if len(observed) != artifact[f"{stream}_size"]:
            raise GateError(f"{label}: {stream} size differs from replay")
        if (
            hashlib.sha256(observed).hexdigest()
            != artifact[f"{stream}_sha256"]
        ):
            raise GateError(f"{label}: {stream} digest differs from replay")


def validate_codemodel_target_source_ownership(
    codemodel: dict[str, Any],
    *,
    build_dir: pathlib.Path,
    target_name: str,
    test_path: str,
    executable_path: pathlib.Path,
    label: str,
) -> None:
    """Prove a CTest executable is built from the declared acceptance source.

    CTest's command catalog intentionally does not expose source ownership.  A
    same-name registration that runs an unrelated zero-exit executable is
    therefore rejected by this separate CMake File API codemodel check.
    """
    configurations = codemodel.get("configurations")
    if not isinstance(configurations, list) or len(configurations) != 1:
        raise GateError(f"{label}: CMake File API configuration ambiguity")
    targets = configurations[0].get("targets")
    if not isinstance(targets, list):
        raise GateError(f"{label}: CMake File API target catalog malformed")
    matches = [item for item in targets if isinstance(item, dict) and item.get("name") == target_name]
    if len(matches) != 1:
        raise GateError(f"{label}: declared CTest target must exist exactly once")
    json_file = matches[0].get("jsonFile")
    if not isinstance(json_file, str) or not json_file:
        raise GateError(f"{label}: CMake File API target detail absent")
    target_path = build_dir / ".cmake" / "api" / "v1" / "reply" / json_file
    try:
        target = load_json_strict(target_path)
    except (GateError, OSError) as exc:
        raise GateError(f"{label}: CMake File API target detail unreadable") from exc
    expected_source = repo_path(test_path, f"{label}.test_path", require_exists=True, require_file=True)
    sources = target.get("sources")
    if not isinstance(sources, list):
        raise GateError(f"{label}: CMake target sources absent")
    owned = False
    for source in sources:
        if not isinstance(source, dict) or source.get("isGenerated") is True:
            continue
        path_value = source.get("path")
        if not isinstance(path_value, str) or not path_value:
            continue
        candidate = pathlib.Path(path_value)
        candidate = candidate if candidate.is_absolute() else ROOT / candidate
        try:
            if candidate.resolve(strict=True) == expected_source.resolve(strict=True):
                owned = True
                break
        except OSError:
            continue
    if not owned:
        raise GateError(f"{label}: CTest target does not own declared test source")
    artifacts = target.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise GateError(f"{label}: CMake target executable artifact absent")
    artifact_paths: set[pathlib.Path] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str):
            continue
        item = pathlib.Path(artifact["path"])
        item = item if item.is_absolute() else build_dir / item
        try:
            artifact_paths.add(item.resolve(strict=True))
        except OSError:
            continue
    if executable_path.resolve(strict=True) not in artifact_paths:
        raise GateError(f"{label}: CTest command executable is not target artifact")


def load_cmake_codemodel(build_dir: pathlib.Path, label: str) -> dict[str, Any]:
    """Request a fresh File API codemodel without trusting stale reply bytes."""
    query = build_dir / ".cmake" / "api" / "v1" / "query" / "codemodel-v2"
    query.parent.mkdir(parents=True, exist_ok=True)
    query.touch(exist_ok=True)
    try:
        subprocess.run(
            ["cmake", "-S", str(ROOT), "-B", str(build_dir)],
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"{label}: File API reconfigure failed") from exc
    reply_dir = build_dir / ".cmake" / "api" / "v1" / "reply"
    indexes = sorted(reply_dir.glob("index-*.json"), key=lambda item: item.stat().st_mtime_ns)
    if not indexes:
        raise GateError(f"{label}: CMake File API index absent")
    index = load_json_strict(indexes[-1])
    try:
        codemodel_file = index["reply"]["codemodel-v2"]["jsonFile"]
    except (KeyError, TypeError) as exc:
        raise GateError(f"{label}: CMake File API codemodel reply absent") from exc
    if not isinstance(codemodel_file, str):
        raise GateError(f"{label}: CMake File API codemodel reply malformed")
    return load_json_strict(reply_dir / codemodel_file)


def validate_evidence_artifact_payload(
    payload: dict[str, Any],
    *,
    label: str,
    acceptance_id: str,
    expected_state: str,
    test_path: str,
    allowed_platforms: set[str],
) -> None:
    validate_boolean_locations(payload, label, ())
    expected_fields = {
        "schema",
        "schema_version",
        "acceptance_id",
        "test_id",
        "platform_id",
        "platform_profile_id",
        "os",
        "architecture",
        "toolchain_family",
        "toolchain_id",
        "compiler_id",
        "compiler_version",
        "build_type",
        "sanitizer_profile",
        "cmake_cache_path",
        "cmake_cache_sha256",
        "esp_target",
        "esp_idf_version",
        "esp_elf_path",
        "esp_elf_sha256",
        "esp_map_path",
        "esp_map_sha256",
        "result",
        "tested_commit_sha",
        "tested_tree_sha",
        "runner_kind",
        "runner_registration_path",
        "runner_id",
        "runner_target",
        "runner_source_path",
        "runner_build_dir",
        "runner_working_directory",
        "runner_command_argv",
        "runner_exit_code",
        "stdout_path",
        "stdout_size",
        "stdout_sha256",
        "stderr_path",
        "stderr_size",
        "stderr_sha256",
        "started_at_utc",
        "finished_at_utc",
    }
    artifact = closed(payload, expected_fields, f"{label}.artifact")
    if artifact["schema"] != "ninlil_public_module_acceptance_evidence_v1":
        raise GateError(f"{label}: unknown evidence artifact schema")
    if strict_integer(
        artifact["schema_version"],
        f"{label}.schema_version",
    ) != 1:
        raise GateError(f"{label}: unknown evidence artifact schema")
    if (
        artifact["acceptance_id"] != acceptance_id
        or artifact["test_id"] != acceptance_id
        or artifact["runner_id"] != acceptance_id
    ):
        raise GateError(f"{label}: test/acceptance/runner ID binding mismatch")
    if artifact["runner_source_path"] != test_path:
        raise GateError(f"{label}: runner source/declared test path mismatch")
    if (
        not isinstance(artifact["runner_target"], str)
        or re.fullmatch(r"ninlil_public_module_[a-z0-9_]+", artifact["runner_target"])
        is None
    ):
        raise GateError(f"{label}: canonical runner target required")
    if artifact["platform_id"] not in allowed_platforms:
        raise GateError(f"{label}: undeclared evidence platform")
    if artifact["runner_kind"] != "LOCAL_CTEST_REPLAYABLE_RECEIPT":
        raise GateError(
            f"{label}: CI/HIL or unknown receipt has no offline verifier; "
            "ledger must remain NOT_RUN"
        )
    profile_id = artifact["platform_profile_id"]
    profiles = platform_profile_index()
    profile = profiles.get(profile_id)
    if profile is None or profile["platform_id"] != artifact["platform_id"]:
        raise GateError(f"{label}: platform/profile receipt mismatch")
    for field in ("os", "architecture", "toolchain_family", "build_type", "sanitizer_profile"):
        if artifact[field] != profile[field]:
            raise GateError(f"{label}: platform/profile {field} mismatch")
    for field in ("toolchain_id", "compiler_id", "compiler_version"):
        if not isinstance(artifact[field], str) or not artifact[field]:
            raise GateError(f"{label}: toolchain receipt field absent {field}")
    if artifact["result"] != expected_state or expected_state not in {"PASS", "FAIL"}:
        raise GateError(f"{label}: result binding mismatch")
    if (
        not isinstance(artifact["tested_commit_sha"], str)
        or re.fullmatch(r"[0-9a-f]{40}", artifact["tested_commit_sha"]) is None
    ):
        raise GateError(f"{label}: evidence commit SHA malformed")
    if (
        not isinstance(artifact["tested_tree_sha"], str)
        or re.fullmatch(r"[0-9a-f]{40}", artifact["tested_tree_sha"]) is None
    ):
        raise GateError(f"{label}: tested tree SHA malformed")
    strict_integer(
        artifact["runner_exit_code"],
        f"{label}.runner_exit_code",
        minimum=0,
        maximum=255,
    )
    if (
        expected_state == "PASS" and artifact["runner_exit_code"] != 0
    ) or (
        expected_state == "FAIL" and artifact["runner_exit_code"] == 0
    ):
        raise GateError(f"{label}: result/exit-code contradiction")
    for timestamp_field in ("started_at_utc", "finished_at_utc"):
        if (
            not isinstance(artifact[timestamp_field], str)
            or re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
                r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                artifact[timestamp_field],
            )
            is None
        ):
            raise GateError(f"{label}: canonical UTC timestamp required")
    if artifact["finished_at_utc"] < artifact["started_at_utc"]:
        raise GateError(f"{label}: evidence time interval reversed")

    registration_path_value = string(
        artifact["runner_registration_path"],
        f"{label}.runner_registration_path",
        r"(CMakeLists\.txt|cmake/[A-Za-z0-9_./-]+\.cmake|"
        r"tests/[A-Za-z0-9_./-]+/CMakeLists\.txt)",
    )
    registration_path = repo_path(
        registration_path_value,
        f"{label}.runner_registration_path",
        require_exists=True,
        require_file=True,
    )
    build_dir_value = string(
        artifact["runner_build_dir"],
        f"{label}.runner_build_dir",
        r"build/[A-Za-z0-9_.-]+",
    )
    if registration_path.stat().st_size == 0:
        raise GateError(f"{label}: runner registration absent or empty")
    registration_text = registration_path.read_text(encoding="utf-8")
    registration_executable_text = executable_text_without_comments(
        registration_text,
        cmake=True,
    )
    if not has_ctest_registration(
        registration_executable_text,
        acceptance_id,
    ):
        raise GateError(f"{label}: CTest runner ID is not machine registered")
    build_dir = repo_path(
        build_dir_value,
        f"{label}.runner_build_dir",
        require_exists=True,
        require_directory=True,
    )
    cache_path = build_dir / "CMakeCache.txt"
    if (
        not cache_path.is_file()
        or cache_path.is_symlink()
        or f"CMAKE_HOME_DIRECTORY:INTERNAL={ROOT.resolve()}"
        not in cache_path.read_text(encoding="utf-8").splitlines()
    ):
        raise GateError(f"{label}: runner build tree source root mismatch")
    if artifact["cmake_cache_path"] != build_dir_value + "/CMakeCache.txt":
        raise GateError(f"{label}: receipt CMake cache path mismatch")
    if (
        not isinstance(artifact["cmake_cache_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", artifact["cmake_cache_sha256"]) is None
        or hashlib.sha256(cache_path.read_bytes()).hexdigest()
        != artifact["cmake_cache_sha256"]
    ):
        raise GateError(f"{label}: CMake cache/toolchain digest mismatch")
    if profile["esp_target"] is None:
        if any(artifact[field] is not None for field in ("esp_target", "esp_idf_version", "esp_elf_path", "esp_elf_sha256", "esp_map_path", "esp_map_sha256")):
            raise GateError(f"{label}: host receipt must not claim ESP artifact")
    else:
        if artifact["esp_target"] != profile["esp_target"] or not isinstance(artifact["esp_idf_version"], str) or not artifact["esp_idf_version"]:
            raise GateError(f"{label}: ESP target/IDF receipt mismatch")
        for stem in ("esp_elf", "esp_map"):
            path = repo_path(
                string(artifact[f"{stem}_path"], f"{label}.{stem}_path", r"build/[A-Za-z0-9_./-]+"),
                f"{label}.{stem}_path", require_exists=True, require_file=True,
            )
            digest = string(artifact[f"{stem}_sha256"], f"{label}.{stem}_sha256", r"[0-9a-f]{64}")
            if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise GateError(f"{label}: ESP {stem} digest mismatch")
    try:
        subprocess.run(
            [
                "cmake",
                "--build",
                str(build_dir),
                "--parallel",
                "2",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(
            f"{label}: runner build failed before receipt replay"
        ) from exc
    codemodel = load_cmake_codemodel(build_dir, label)
    try:
        catalog_process = subprocess.run(
            [
                "ctest",
                "--test-dir",
                str(build_dir),
                "--show-only=json-v1",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        catalog = json.loads(
            catalog_process.stdout,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        raise GateError(f"{label}: active CTest catalog unavailable") from exc
    tests = catalog.get("tests") if isinstance(catalog, dict) else None
    if not isinstance(tests, list):
        raise GateError(f"{label}: active CTest catalog malformed")
    entries = [
        entry
        for entry in tests
        if isinstance(entry, dict) and entry.get("name") == acceptance_id
    ]
    if len(entries) != 1:
        raise GateError(f"{label}: CTest runner must be active exact once")
    entry = entries[0]
    properties = entry.get("properties")
    if not isinstance(properties, list):
        raise GateError(f"{label}: active CTest properties malformed")
    for prop in properties:
        if (
            isinstance(prop, dict)
            and prop.get("name") == "DISABLED"
            and str(prop.get("value", "")).strip().lower()
            in {"1", "true", "on", "yes"}
        ):
            raise GateError(f"{label}: CTest runner is disabled")

    entry_command = entry.get("command")
    if (
        not isinstance(entry_command, list)
        or not entry_command
        or any(not isinstance(item, str) or not item for item in entry_command)
    ):
        raise GateError(f"{label}: active CTest command malformed")
    try:
        executable_absolute = pathlib.Path(entry_command[0]).resolve(strict=True)
        executable_relative = executable_absolute.relative_to(ROOT.resolve())
    except (OSError, ValueError) as exc:
        raise GateError(
            f"{label}: CTest executable is not a root-confined built runner"
        ) from exc
    executable_path = repo_path(
        executable_relative.as_posix(),
        f"{label}.runner_executable",
        require_exists=True,
        require_file=True,
    )
    if executable_path.name in {"echo", "true", "false"}:
        raise GateError(f"{label}: no-op CTest command rejected")
    expected_command = [
        executable_relative.as_posix(),
        *entry_command[1:],
    ]
    if artifact["runner_command_argv"] != expected_command:
        raise GateError(f"{label}: exact active CTest command mismatch")
    validate_codemodel_target_source_ownership(
        codemodel,
        build_dir=build_dir,
        target_name=artifact["runner_target"],
        test_path=test_path,
        executable_path=executable_path,
        label=label,
    )
    working_values = [
        prop.get("value")
        for prop in properties
        if isinstance(prop, dict) and prop.get("name") == "WORKING_DIRECTORY"
    ]
    if len(working_values) != 1 or not isinstance(working_values[0], str):
        raise GateError(f"{label}: CTest working directory must be exact once")
    try:
        working_absolute = pathlib.Path(working_values[0]).resolve(strict=True)
        working_relative = working_absolute.relative_to(ROOT.resolve()).as_posix()
    except (OSError, ValueError) as exc:
        raise GateError(
            f"{label}: CTest working directory escapes repository"
        ) from exc
    working_path = repo_path(
        working_relative,
        f"{label}.runner_working_directory",
        require_exists=True,
        require_directory=True,
    )
    if artifact["runner_working_directory"] != working_relative:
        raise GateError(f"{label}: CTest working directory receipt mismatch")

    tested_commit = artifact["tested_commit_sha"]
    validate_tested_parent_commit(tested_commit, label)
    try:
        tree_process = subprocess.run(
            ["git", "rev-parse", f"{tested_commit}^{{tree}}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"{label}: tested tree unavailable") from exc
    if tree_process.stdout.strip() != artifact["tested_tree_sha"]:
        raise GateError(f"{label}: tested commit/tree binding mismatch")

    for committed_path, working_path in (
        (
            test_path,
            repo_path(test_path, f"{label}.test_path"),
        ),
        (registration_path_value, registration_path),
    ):
        if (
            git_blob_at_commit(
                tested_commit,
                committed_path,
                label,
            )
            != working_path.read_bytes()
        ):
            raise GateError(
                f"{label}: test/runner bytes differ from tested commit"
            )

    receipt_files: dict[str, tuple[pathlib.Path, int, str]] = {}
    for stream in ("stdout", "stderr"):
        path_value = string(
            artifact[f"{stream}_path"],
            f"{label}.{stream}_path",
            r"evidence/public-modules/receipts/[A-Za-z0-9_.-]+\.(?:stdout|stderr)",
        )
        path = repo_path(
            path_value,
            f"{label}.{stream}_path",
            require_exists=True,
            require_file=True,
        )
        size = strict_integer(
            artifact[f"{stream}_size"],
            f"{label}.{stream}_size",
            minimum=0,
            maximum=16 * 1024 * 1024,
        )
        digest = string(
            artifact[f"{stream}_sha256"],
            f"{label}.{stream}_sha256",
            r"[0-9a-f]{64}",
        )
        content = path.read_bytes()
        if len(content) != size or hashlib.sha256(content).hexdigest() != digest:
            raise GateError(f"{label}: {stream} receipt size/digest mismatch")
        receipt_files[stream] = (path, size, digest)

    try:
        replay = subprocess.run(
            [str(executable_path), *entry_command[1:]],
            cwd=working_path,
            check=False,
            capture_output=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"{label}: receipt replay failed") from exc
    validate_replay_receipt_claim(
        artifact,
        observed_exit_code=replay.returncode,
        observed_stdout=replay.stdout,
        observed_stderr=replay.stderr,
        label=label,
    )
    if replay.stdout != receipt_files["stdout"][0].read_bytes():
        raise GateError(f"{label}: stdout receipt differs from replay")
    if replay.stderr != receipt_files["stderr"][0].read_bytes():
        raise GateError(f"{label}: stderr receipt differs from replay")


def validate_evidence_mapping(
    value: dict[str, Any],
    label: str,
    prefix: str,
    seen_paths: set[str],
    *,
    acceptance_id: str,
    test: dict[str, Any],
    allowed_platforms: set[str],
    module_id: str | None,
    module_api_state: str | None,
) -> None:
    state = value["state"]
    path_value = value["path"]
    digest = value["sha256"]
    receipts = value["profile_receipts"]
    if not isinstance(receipts, list):
        raise GateError(f"{label}: profile receipts array required")
    if (
        prefix == "evidence/"
        and module_id == "fabric_v1"
        and module_api_state == "PACKAGE_EXPERIMENTAL"
        and acceptance_id in {"PM-FAB-ABI-01", "PM-FAB-INSTANCE-01"}
    ):
        # ADR-0029's first tranche predates the future ADR-0028 immutable
        # multi-platform receipt promotion.  PACKAGE_EXPERIMENTAL may cite the
        # scoped work record, but never RELEASE_SUPPORTED or physical/HIL.
        expected_note = "docs/work/2026-08-02-public-fabric-v1-first-tranche.md"
        if state != "PASS" or receipts or path_value != expected_note:
            raise GateError(f"{label}: exact Fabric experimental evidence required")
        if path_value not in seen_paths:
            seen_paths.add(path_value)
        note_path = repo_path(
            path_value,
            f"{label}.path",
            require_exists=True,
            require_file=True,
        )
        note_bytes = note_path.read_bytes()
        if (
            not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or hashlib.sha256(note_bytes).hexdigest() != digest
        ):
            raise GateError(f"{label}: Fabric work-note digest mismatch")
        test_path_value = test["path"]
        test_path = repo_path(
            test_path_value,
            f"{label}.test_path",
            require_exists=True,
            require_file=True,
        )
        if test_path.stat().st_size == 0:
            raise GateError(f"{label}: Fabric test source is empty")
        note_text = note_bytes.decode("utf-8")
        cmake_text = executable_text_without_comments(
            repo_path("CMakeLists.txt", f"{label}.CMakeLists", require_file=True)
            .read_text(encoding="utf-8"),
            cmake=True,
        )
        required_ctests = {
            "PM-FAB-ABI-01": (
                "abi_contract_header",
                "abi_contract_output",
                "abi_contract_enum",
                "abi_manifest_golden",
                "abi_manifest_coverage",
                "fabric_v1_public_api",
            ),
            "PM-FAB-INSTANCE-01": (
                "fabric_v1_tests_off_installed_consumer",
                "fabric_v1_public_behavior",
            ),
        }[acceptance_id]
        for test_name in required_ctests:
            if not has_ctest_registration(cmake_text, test_name):
                raise GateError(f"{label}: CTest registration missing {test_name}")
            if f"`{test_name}`" not in note_text or "PASS" not in note_text:
                raise GateError(f"{label}: work note omits PASS result {test_name}")
        if acceptance_id == "PM-FAB-ABI-01" and re.search(
            r"set\s*\(\s*NINLIL_PUBLIC_HEADERS[^)]*\bfabric_v1\b",
            cmake_text,
        ) is None:
            raise GateError(f"{label}: Fabric C/C++ self-contained header smoke missing")
        return
    if state == "NOT_RUN":
        if path_value is not None or digest is not None or receipts:
            raise GateError(f"{label}: NOT_RUN must have null evidence")
        return
    if prefix == "evidence/hil/":
        raise GateError(
            f"{label}: HIL receipt has no offline verifier; state must remain NOT_RUN"
        )
    test_path_value = test["path"]
    test_path = repo_path(test_path_value, f"{label}.test_path")
    if not test_path.is_file():
        raise GateError(f"{label}: PASS/FAIL test file absent")
    if test_path.stat().st_size == 0:
        raise GateError(f"{label}: PASS/FAIL test file is empty")
    # v1 formerly had one path/SHA slot, which allowed one Host run to stand in
    # for the whole platform/toolchain/profile matrix.  It stays present only
    # as a closed-schema tombstone and must be null for aggregate receipts.
    if path_value is not None or digest is not None:
        raise GateError(f"{label}: legacy single receipt cannot prove profile matrix")
    expected_profile_ids = [
        profile["id"]
        for profile in EXPECTED_PLATFORM_PROFILE_MATRIX
        if profile["platform_id"] in allowed_platforms
    ]
    observed_profile_ids: list[str] = []
    for index, raw in enumerate(receipts):
        receipt = closed(
            raw,
            {"platform_profile_id", "path", "sha256"},
            f"{label}.profile_receipts[{index}]",
        )
        profile_id = string(
            receipt["platform_profile_id"],
            f"{label}.profile_receipts[{index}].platform_profile_id",
        )
        if profile_id in observed_profile_ids:
            raise GateError(f"{label}: duplicate platform/profile receipt")
        observed_profile_ids.append(profile_id)
        path_value = string(
            receipt["path"],
            f"{label}.profile_receipts[{index}].path",
            r"evidence/public-modules/[A-Za-z0-9_./-]+\.json",
        )
        if path_value in seen_paths:
            raise GateError(f"{label}: duplicate evidence path")
        seen_paths.add(path_value)
        receipt_digest = string(
            receipt["sha256"],
            f"{label}.profile_receipts[{index}].sha256",
            r"[0-9a-f]{64}",
        )
        path = repo_path(
            path_value,
            f"{label}.profile_receipts[{index}].path",
            require_exists=True,
            require_file=True,
        )
        content = path.read_bytes()
        if not content or hashlib.sha256(content).hexdigest() != receipt_digest:
            raise GateError(f"{label}: profile evidence absent or digest mismatch")
        payload = load_json_strict(path)
        if payload.get("platform_profile_id") != profile_id:
            raise GateError(f"{label}: receipt wrapper/profile mismatch")
        validate_evidence_artifact_payload(
            payload,
            label=f"{label}.{profile_id}",
            acceptance_id=acceptance_id,
            expected_state=state,
            test_path=test_path_value,
            allowed_platforms=allowed_platforms,
        )
    if observed_profile_ids != expected_profile_ids:
        raise GateError(f"{label}: exact platform/profile receipt matrix incomplete")


def validate_global_uniqueness(modules: list[dict[str, Any]]) -> None:
    prefixes: set[str] = set()
    components: set[str] = set()
    host_targets: set[str] = set()
    headers: set[str] = set()
    namespace_pairs: set[tuple[str, str]] = set()
    for module in modules:
        module_id = module["id"]
        prefix = module["symbol_prefix"]
        if prefix in prefixes:
            raise GateError(f"duplicate symbol prefix {prefix}")
        prefixes.add(prefix)
        package_value = module["package"]
        component = package_value["component"]
        if component in components:
            raise GateError(f"duplicate component metadata {component}")
        components.add(component)
        target = package_value["host_cmake_target"]
        if target is not None:
            if target in host_targets:
                raise GateError(f"duplicate public target {target}")
            host_targets.add(target)
        header = package_value["public_header_root"]
        if header in headers:
            raise GateError(f"duplicate public header root {header}")
        headers.add(header)
        namespace = module["namespace_policy"]
        for physical, partition in zip(
            namespace["physical_namespaces"], namespace["partition_prefixes"]
        ):
            pair = (physical, partition)
            if pair in namespace_pairs:
                raise GateError(
                    f"duplicate namespace/partition policy {physical}/{partition}"
                )
            namespace_pairs.add(pair)
        if module_id == "radio_frag_v1":
            dependency_ids = {
                item["depends_on_feature_id"] for item in module["dependencies"]
            }
            if "nfl1-r7-nrw1-rf-mapping" in dependency_ids:
                raise GateError("pure frag must not require RF mapping")
            if package_value["dependencies"]:
                raise GateError("pure frag must not depend on Fabric adapter")
        if module_id == "radio_fabric_adapter_v1":
            dependency_ids = {
                item["depends_on_feature_id"] for item in module["dependencies"]
            }
            if "nfl1-r7-nrw1-rf-mapping" not in dependency_ids:
                raise GateError("radio adapter missing Accepted RF mapping dependency")
        if module_id == "wifi_v1":
            if package_value["artifact_kind"] != "STATIC_ARCHIVE":
                raise GateError("Wi-Fi common must be a portable static archive")
        if module_id == "wifi_posix_v1":
            if package_value["dependencies"] != ["fabric_v1", "wifi_v1"]:
                raise GateError("Wi-Fi POSIX common/Fabric dependency drift")
            if package_value["esp_idf_component"] is not None:
                raise GateError("Wi-Fi POSIX must not depend on ESP packaging")


def check(
    manifest: dict[str, Any],
    matrix: dict[str, Any],
    schema: dict[str, Any],
    adr_text: str | None = None,
    identity_precondition_adr_text: str | None = None,
    identity_precondition_review_text: str | None = None,
) -> None:
    validate_boolean_locations(
        manifest,
        "manifest",
        MANIFEST_BOOLEAN_PATH_PATTERNS,
    )
    validate_boolean_locations(
        matrix,
        "compatibility",
        MATRIX_BOOLEAN_PATH_PATTERNS,
    )
    validate_schema(schema)
    closed(
        manifest,
        {
            "$schema",
            "schema",
            "schema_version",
            "authority",
            "exact_contract_digests",
            "module_api_states",
            "allowed_module_api_transitions",
            "completion_state_domain",
            "cmake_component_contract",
            "module_api_completion_mapping",
            "inter_module_port_contract",
            "fabric_selection_port_contract",
            "acceptance_evidence_contract",
            "independent_review_contract",
            "multi_instance_acceptance_contract",
            "abi_layout_gate_contract",
            "version_coexistence_contract",
            "identity_attachment_precondition_contract",
            "modules",
            "cross_module_acceptance",
            "acceptance",
        },
        "manifest",
    )
    if manifest["$schema"] != "spec/public-module-manifest-v1.schema.json":
        raise GateError("manifest schema path drift")
    if manifest["schema"] != "ninlil-public-module-manifest-v1":
        raise GateError("manifest unknown schema")
    if manifest["schema_version"] != 1:
        raise GateError("manifest unknown schema version")
    if manifest["authority"] != EXPECTED_AUTHORITY:
        raise GateError("manifest authority drift")
    if manifest["exact_contract_digests"] != EXPECTED_EXACT_CONTRACT_DIGESTS:
        raise GateError("manifest exact module/acceptance contract digests drift")
    if manifest["module_api_states"] != MODULE_STATES:
        raise GateError("manifest module API state domain drift")
    if manifest["allowed_module_api_transitions"] != MODULE_TRANSITIONS:
        raise GateError("manifest allowed transitions drift")
    if manifest["completion_state_domain"] != EXPECTED_COMPLETION_DOMAIN:
        raise GateError("manifest completion state authority drift")
    if manifest["cmake_component_contract"] != EXPECTED_CMAKE_CONTRACT:
        raise GateError("manifest CMake component semantics drift")
    if (
        manifest["module_api_completion_mapping"]
        != EXPECTED_MODULE_API_COMPLETION_MAPPING
    ):
        raise GateError("manifest module/completion state mapping drift")
    if (
        manifest["inter_module_port_contract"]
        != EXPECTED_INTER_MODULE_PORT_CONTRACT
    ):
        raise GateError("manifest inter-module port C ABI drift")
    if canonical_json_sha256(manifest["fabric_selection_port_contract"]) != (
        EXPECTED_FABRIC_SELECTION_PORT_SHA256
    ):
        raise GateError("manifest Fabric selection port contract drift")
    if canonical_json_sha256(manifest["acceptance_evidence_contract"]) != (
        EXPECTED_ACCEPTANCE_EVIDENCE_CONTRACT_SHA256
    ):
        raise GateError("manifest acceptance evidence contract drift")
    if manifest["acceptance_evidence_contract"].get("platform_profile_matrix") != (
        EXPECTED_PLATFORM_PROFILE_MATRIX
    ):
        raise GateError("manifest platform/profile receipt matrix drift")
    if canonical_json_sha256(manifest["independent_review_contract"]) != (
        EXPECTED_INDEPENDENT_REVIEW_CONTRACT_SHA256
    ):
        raise GateError("manifest independent review contract drift")
    if (
        manifest["multi_instance_acceptance_contract"]
        != EXPECTED_MULTI_INSTANCE_CONTRACT
    ):
        raise GateError("manifest 2x2 instance/resource authority drift")
    if (
        manifest["abi_layout_gate_contract"]
        != EXPECTED_ABI_LAYOUT_GATE_CONTRACT
    ):
        raise GateError("manifest ABI layout negative-gate contract drift")
    if (
        manifest["version_coexistence_contract"]
        != EXPECTED_VERSION_COINSTALL_CONTRACT
    ):
        raise GateError("manifest v1/v2 coexistence contract drift")
    if canonical_json_sha256(
        manifest["identity_attachment_precondition_contract"]
    ) != EXPECTED_IDENTITY_ATTACHMENT_PRECONDITION_SHA256:
        raise GateError("manifest Identity/Attachment precondition drift")
    schema_defs = schema["$defs"]
    for manifest_key, schema_key in (
        (
            "fabric_selection_port_contract",
            "fabricSelectionPortContract",
        ),
        (
            "acceptance_evidence_contract",
            "acceptanceEvidenceContract",
        ),
        (
            "independent_review_contract",
            "independentReviewContract",
        ),
        (
            "identity_attachment_precondition_contract",
            "identityAttachmentPreconditionContract",
        ),
    ):
        if schema_defs[schema_key]["const"] != manifest[manifest_key]:
            raise GateError(
                f"manifest/schema exact contract mismatch at {manifest_key}"
            )

    features, platforms = compatibility_authority(matrix)
    modules = manifest.get("modules")
    if not isinstance(modules, list):
        raise GateError("manifest modules must be an array")
    module_ids = [
        item.get("id") if isinstance(item, dict) else None for item in modules
    ]
    if module_ids != list(EXPECTED_MODULES):
        raise GateError("module ID/order authority drift")
    modules_by_id = {module["id"]: module for module in modules}
    for module in modules:
        validate_module(
            module,
            EXPECTED_MODULES[module["id"]],
            features,
            platforms,
            modules_by_id,
        )
    validate_global_uniqueness(modules)
    validate_cross_module_acceptance(manifest, modules_by_id)
    validate_acceptance(manifest, modules_by_id)
    if exact_contract_digests(manifest) != manifest["exact_contract_digests"]:
        raise GateError("manifest immutable module/acceptance bytes do not match schema pins")

    adr = (
        repo_path(
            "docs/adr/0028-composable-public-runtime-modules.md",
            "ADR-0028 path",
            require_exists=True,
            require_file=True,
        ).read_text(encoding="utf-8")
        if adr_text is None
        else adr_text
    )
    adr_status = canonical_markdown_status(
        adr,
        "ADR-0028",
        expected_h1="# ADR-0028: Composable Public Runtime Modules",
    )
    if adr_status == "Proposed":
        # Accepted ADR-0029 supersedes this future eight-module fence only for
        # Fabric's current Host experimental tranche. Release promotion and
        # every other module remain governed by the ordinary ADR-0028 fence.
        promoted = [
            module["id"]
            for module in modules
            if module["module_api_state"] != "PRIVATE_CANDIDATE"
            and not (
                module["id"] == "fabric_v1"
                and module["module_api_state"] == "PACKAGE_EXPERIMENTAL"
            )
        ]
        if promoted:
            raise GateError(
                f"ADR-0028 Proposed fence: promoted modules forbidden {promoted}"
            )
    elif adr_status != "Accepted":
        raise GateError(f"ADR-0028 decision status {adr_status} forbids publication")

    identity_adr = (
        repo_path(
            IDENTITY_PRECONDITION_ADR_PATH,
            "ADR-0039 path",
            require_exists=True,
            require_file=True,
        ).read_text(encoding="utf-8")
        if identity_precondition_adr_text is None
        else identity_precondition_adr_text
    )
    identity_status = canonical_markdown_status(
        identity_adr,
        "ADR-0039",
        expected_h1=IDENTITY_PRECONDITION_ADR_H1,
    )
    if identity_status not in ("Proposed", "Accepted"):
        raise GateError(f"ADR-0039 status {identity_status} is unsupported")
    if identity_status == "Accepted":
        if identity_precondition_review_text is None:
            review_path = ROOT / "docs/reviews/2026-08-10-identity-attachment-precondition-spec-review.md"
            if not review_path.is_file():
                raise GateError("ADR-0039 Accepted requires an independent review artifact")
            review = review_path.read_text(encoding="utf-8")
        else:
            review = identity_precondition_review_text
        canonical_identity_attachment_precondition_review_result(review)
    for token in (
        "public-module-manifest.json#/identity_attachment_precondition_contract",
        "identity-attachment-session-install` at `PROPOSED`",
        "Extracts/accepts only: ADR-0028 section 1.1 exact contract",
        "Related: ADR-0022, ADR-0023, ADR-0032, ADR-0038",
        "already-manifested provider ABI as specification only",
        "`resolve -> validate -> subscribe -> publish`",
        "`NIAF` schema-1, 308-byte FULL checkpoint",
        "`PM-IDENTITY-PRECONDITION-2X2-01`",
        "No PA-S item is complete merely because this ADR exists.",
        "leaves `identity-attachment-session-install` **PROPOSED**",
    ):
        if token not in identity_adr:
            raise GateError(f"ADR-0039 missing required precondition fence: {token}")


def self_test(
    manifest: dict[str, Any],
    matrix: dict[str, Any],
    schema: dict[str, Any],
) -> None:
    check(copy.deepcopy(manifest), copy.deepcopy(matrix), copy.deepcopy(schema))
    for separation, expected_reason in (
        ("UNVERIFIED", "verified implementer separation"),
        ("VERIFIED", "offline verifier unavailable"),
    ):
        try:
            require_offline_verified_independent_review(
                "GO",
                separation,
                "self-test fabricated reviewer provenance",
            )
        except GateError as exc:
            if expected_reason not in str(exc):
                raise GateError(
                    "self-test fabricated reviewer provenance rejected for "
                    f"wrong reason: {exc}"
                ) from exc
        else:
            raise GateError(
                "self-test fabricated reviewer provenance accepted"
            )

    def reject(
        label: str,
        mutate_manifest: Callable[[dict[str, Any]], None] | None = None,
        mutate_matrix: Callable[[dict[str, Any]], None] | None = None,
        mutate_schema: Callable[[dict[str, Any]], None] | None = None,
        mutate_adr: Callable[[str], str] | None = None,
        reason: str | None = None,
    ) -> None:
        candidate_manifest = copy.deepcopy(manifest)
        candidate_matrix = copy.deepcopy(matrix)
        candidate_schema = copy.deepcopy(schema)
        candidate_adr = repo_path(
            "docs/adr/0028-composable-public-runtime-modules.md",
            "self-test ADR path",
            require_exists=True,
            require_file=True,
        ).read_text(encoding="utf-8")
        if mutate_manifest is not None:
            mutate_manifest(candidate_manifest)
        if mutate_matrix is not None:
            mutate_matrix(candidate_matrix)
        if mutate_schema is not None:
            mutate_schema(candidate_schema)
        if mutate_adr is not None:
            candidate_adr = mutate_adr(candidate_adr)
        try:
            check(
                candidate_manifest,
                candidate_matrix,
                candidate_schema,
                candidate_adr,
            )
        except GateError as exc:
            if reason is not None and reason not in str(exc):
                raise GateError(
                    f"self-test {label}: rejected for wrong reason: {exc}"
                ) from exc
            return
        raise GateError(f"self-test mutation accepted: {label}")

    def module_at(value: dict[str, Any], module_id: str) -> dict[str, Any]:
        return next(item for item in value["modules"] if item["id"] == module_id)

    reject(
        "illegal state jump",
        lambda value: (
            module_at(value, "fabric_v1").__setitem__(
                "state_history", ["PRIVATE_CANDIDATE", "PACKAGE_EXPERIMENTAL"]
            ),
            module_at(value, "fabric_v1").__setitem__(
                "module_api_state", "PACKAGE_EXPERIMENTAL"
            ),
        ),
        reason="illegal state jump",
    )

    reject(
        "module/completion state mapping drift",
        lambda value: value["module_api_completion_mapping"][
            "PACKAGE_EXPERIMENTAL"
        ].__setitem__("completion_floor", "HOST_CANDIDATE"),
        reason="module/completion state mapping drift",
    )
    reject(
        "observer C ABI field reorder",
        lambda value: value["inter_module_port_contract"][
            "observer_field_order"
        ].reverse(),
        reason="inter-module port C ABI drift",
    )
    reject(
        "Fabric selection stale fail-closed weakened",
        lambda value: value["fabric_selection_port_contract"].__setitem__(
            "stale_policy", "USE_LAST_KNOWN_PATH"
        ),
        reason="Fabric selection port contract drift",
    )
    reject(
        "Fabric selection cross-instance fallback enabled",
        lambda value: value["fabric_selection_port_contract"].__setitem__(
            "cross_instance_policy", "FALLBACK_TO_DEFAULT"
        ),
        reason="Fabric selection port contract drift",
    )
    reject(
        "Fabric security profile domain weakened",
        lambda value: value["fabric_selection_port_contract"][
            "security_profile_values"
        ].__setitem__("NINLIL_FABRIC_SECURITY_UNKNOWN", 4),
        reason="Fabric selection port contract drift",
    )
    reject(
        "Fabric path kind domain weakened",
        lambda value: value["fabric_selection_port_contract"][
            "path_kind_values"
        ].__setitem__("NINLIL_FABRIC_PATH_ARBITRARY", 99),
        reason="Fabric selection port contract drift",
    )
    reject(
        "Fabric health unknown accepted",
        lambda value: value["fabric_selection_port_contract"].__setitem__(
            "health_eligibility",
            "ANY_UINT32",
        ),
        reason="Fabric selection port contract drift",
    )
    reject(
        "Fabric result flags enabled",
        lambda value: value["fabric_selection_port_contract"].__setitem__(
            "result_flags_allowed_mask",
            1,
        ),
        reason="Fabric selection port contract drift",
    )
    reject(
        "Fabric score adjustment bound removed",
        lambda value: value["fabric_selection_port_contract"].__setitem__(
            "score_adjustment_max",
            2147483647,
        ),
        reason="Fabric selection port contract drift",
    )
    reject(
        "acceptance evidence CI binding weakened",
        lambda value: value["acceptance_evidence_contract"][
            "pass_requirements"
        ].remove(
            "GATE_REPLAYS_COMMAND_AND_OBSERVED_EXIT_STDOUT_STDERR_MATCH_RECEIPT"
        ),
        reason="acceptance evidence contract drift",
    )
    reject(
        "independent review self-report permitted",
        lambda value: value["independent_review_contract"].__setitem__(
            "self_report_policy",
            "REVIEWER_NAME_IS_SUFFICIENT",
        ),
        reason="independent review contract drift",
    )
    reject(
        "2x2 runtime count weakened",
        lambda value: value["multi_instance_acceptance_contract"].__setitem__(
            "runtime_instance_count", 1
        ),
        reason="2x2 instance/resource authority drift",
    )
    reject(
        "compile-time negative runner disabled",
        lambda value: value["abi_layout_gate_contract"].__setitem__(
            "negative_runner_rule", "OPTIONAL"
        ),
        reason="ABI layout negative-gate contract drift",
    )
    reject(
        "v1/v2 coexistence claimed before allocation",
        lambda value: value["version_coexistence_contract"].__setitem__(
            "v1_v2_same_process_claim", True
        ),
        reason="v1/v2 coexistence contract drift",
    )
    reject(
        "Identity/Attachment precondition contract omitted",
        lambda value: value.pop("identity_attachment_precondition_contract"),
        reason="identity_attachment_precondition_contract",
    )
    reject(
        "Identity/Attachment key export false green",
        lambda value: value["identity_attachment_precondition_contract"][
            "binding_rules"
        ].__setitem__("key_policy", "RAW_KEY_EXPORT_ALLOWED"),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "Identity/Attachment stale negative omitted",
        lambda value: value["identity_attachment_precondition_contract"][
            "multi_instance_acceptance"
        ]["negative_bindings"].remove(
            "STALE_PROVIDER_RUNTIME_MODULE_OR_BINDING_GENERATION"
        ),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "Identity callback signature loses request type",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ]["callback_signatures"].__setitem__(
            "resolve_binding", "ninlil_status_t (*)(void *,void *,void *)"
        ),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "unknown key usage bit accepted",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ].__setitem__("key_usage_allowed_mask", 127),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "unknown key handle flag ignored",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ].__setitem__("key_handle_unknown_bits_policy", "IGNORE"),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "opaque handle prefix extension allowed",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ]["struct_policy"].__setitem__(
            "opaque_handle_size", "PREFIX_COMPATIBLE"
        ),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "verified uint32 boolean accepts arbitrary value",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ]["uint32_boolean_values"].__setitem__("NINLIL_TRUE", 2),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "changed floor unknown bit accepted",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ].__setitem__("changed_floor_allowed_mask", 2047),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "key operation shape weakened",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ]["key_operation_shapes"].__setitem__(
            "NINLIL_KEY_OPERATION_VERIFY_DIGEST",
            "ANY_POINTER_AND_SIZE",
        ),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "restart checkpoint atomicity weakened",
        lambda value: value["identity_attachment_precondition_contract"][
            "restart_checkpoint_contract"
        ].__setitem__("atomic_write", "BEST_EFFORT_MULTI_KEY"),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "torn checkpoint accepted",
        lambda value: value["identity_attachment_precondition_contract"][
            "restart_checkpoint_contract"
        ].__setitem__("torn_or_corrupt_policy", "USE_PARTIAL"),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "checkpoint record size drift",
        lambda value: value["identity_attachment_precondition_contract"][
            "restart_checkpoint_contract"
        ].__setitem__("record_size_bytes", 307),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "checkpoint digest coverage drift",
        lambda value: value["identity_attachment_precondition_contract"][
            "restart_checkpoint_contract"
        ]["payload_digest"].__setitem__("coverage_size", 304),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "checkpoint CRC32C polynomial drift",
        lambda value: value["identity_attachment_precondition_contract"][
            "restart_checkpoint_contract"
        ]["crc32c"].__setitem__("polynomial_normal", "0x04C11DB7"),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "subscribe failure publishes availability",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ]["subscribe_lifecycle"].__setitem__(
            "subscribe_failure", "PUBLISH_AVAILABLE_AND_RETRY"
        ),
        reason="Identity/Attachment precondition drift",
    )
    reject(
        "unsubscribe releases binding before drain",
        lambda value: value["identity_attachment_precondition_contract"][
            "provider_port"
        ]["subscribe_lifecycle"].__setitem__(
            "shutdown_sequence",
            "RELEASE_BINDING_THEN_UNSUBSCRIBE",
        ),
        reason="Identity/Attachment precondition drift",
    )

    def use_old_ambiguous_dependency_field(value: dict[str, Any]) -> None:
        dependency = module_at(value, "wifi_v1")["dependencies"][0]
        dependency["minimum_module_api_state"] = dependency.pop(
            "enforced_from_owner_module_state"
        )

    reject(
        "old ambiguous dependency field",
        use_old_ambiguous_dependency_field,
        reason="minimum_module_api_state",
    )

    def omit_identity_precondition_id(value: dict[str, Any]) -> None:
        dependency = next(
            item
            for item in module_at(value, "wifi_v1")["dependencies"]
            if item["depends_on_feature_id"]
            == "identity-attachment-session-install"
        )
        dependency["precondition_contract_id"] = None

    reject(
        "identity feature without versioned provider precondition",
        omit_identity_precondition_id,
        reason="missing versioned Core/Foundation precondition contract",
    )
    reject(
        "identity 2x2 evidence record omitted",
        lambda value: value["cross_module_acceptance"].pop(1),
        reason="exact two records",
    )
    reject(
        "module package acceptance omits identity provider negatives",
        lambda value: next(
            item
            for item in value["acceptance"]
            if item["id"] == "PM-WIFI-COMMON-ABI-01"
        ).__setitem__(
            "requirement",
            next(
                item
                for item in value["acceptance"]
                if item["id"] == "PM-WIFI-COMMON-ABI-01"
            )["requirement"].replace(
                "and Identity/Attachment provider 2x2 binding negatives", ""
            ),
        ),
        reason="exact requirement drift",
    )
    reject(
        "cross-module 2x2 coverage omitted",
        lambda value: value["cross_module_acceptance"][0][
            "covered_module_ids"
        ].pop(),
        reason="module coverage drift",
    )
    # Fresh-review P1-1 regressions: each was accepted by the former generic
    # list/string checks.  Keep the probes close to the immutable ledger.
    reject(
        "Fabric bogus wire profile",
        lambda value: module_at(value, "fabric_v1")["wire_profiles"].append(
            "BOGUS-WIRE"
        ),
        reason="wire profile roster drift",
    )
    reject(
        "MFDT bogus storage schema",
        lambda value: module_at(value, "mfdt_v1")["storage_schemas"].append(
            "BOGUS-STORAGE"
        ),
        reason="storage schema roster drift",
    )
    reject(
        "Fabric physical namespace substitution",
        lambda value: module_at(value, "fabric_v1")["namespace_policy"].update(
            {
                "physical_namespaces": ["unrelated.fabric.namespace"],
                "partition_prefixes": ["unrelated_partition"],
            }
        ),
        reason="namespace/writer policy drift",
    )
    reject(
        "Fabric substantive acceptance weakened",
        lambda value: next(
            item for item in value["acceptance"] if item["id"] == "PM-FAB-INSTANCE-01"
        ).__setitem__("requirement", "two Runtime"),
        reason="exact requirement drift",
    )
    reject(
        "Fabric ABI acceptance retargeted",
        lambda value: next(
            item for item in value["acceptance"] if item["id"] == "PM-FAB-ABI-01"
        )["test"].__setitem__("path", "tests/public_modules/trivial_abi_negative.c"),
        reason="exact test path drift",
    )

    def promote_wifi_spec(value: dict[str, Any]) -> None:
        item = module_at(value, "wifi_v1")
        item["state_history"] = [
            "PRIVATE_CANDIDATE",
            "PUBLIC_API_SPEC_ACCEPTED",
        ]
        item["module_api_state"] = "PUBLIC_API_SPEC_ACCEPTED"

    def mapped_fabric_below_spec(value: dict[str, Any]) -> None:
        next(
            item
            for item in value["features"]
            if item["id"] == "fabric-bearer-nfl1-path-registry"
        )["state"] = "PROPOSED"
        next(
            item
            for item in value["features"]
            if item["id"] == "identity-attachment-session-install"
        )["state"] = "SPEC_ACCEPTED"

    def wifi_dependencies_spec_ready(value: dict[str, Any]) -> None:
        for feature_id in (
            "identity-attachment-session-install",
            "posix-tcp-tls-wifi-reference",
            "esp32s3-wifi-sta-tcp-tls",
        ):
            feature = next(
                item for item in value["features"] if item["id"] == feature_id
            )
            feature["state"] = "SPEC_ACCEPTED"
            feature["state_ceiling"] = "SPEC_ACCEPTED"

    reject(
        "public module without module-specific Accepted spec and GO review",
        promote_wifi_spec,
        wifi_dependencies_spec_ready,
        reason=(
            "PUBLIC_API_SPEC_ACCEPTED promotion requires module-specific "
            "Accepted normative spec"
        ),
    )
    reject(
        "public module with mapped completion below spec",
        None,
        mapped_fabric_below_spec,
        reason="module/completion mapping requires",
    )

    def release_fabric(value: dict[str, Any]) -> None:
        item = module_at(value, "fabric_v1")
        item["state_history"] = MODULE_STATES.copy()
        item["module_api_state"] = "RELEASE_SUPPORTED"
        item["package"]["install_availability"] = "PRESENT"

    reject(
        "Fabric release cannot reuse experimental empty metadata",
        release_fabric,
        reason="package target/header/metadata mismatch",
    )

    release_fixture = copy.deepcopy(manifest)
    release_fabric(release_fixture)
    release_modules = {
        item["id"]: item for item in release_fixture["modules"]
    }
    try:
        validate_acceptance(release_fixture, release_modules)
    except GateError as exc:
        if "compile-time layout negative gate missing" not in str(exc):
            raise GateError(
                "self-test Fabric release ABI exception rejected for wrong "
                f"reason: {exc}"
            ) from exc
    else:
        raise GateError(
            "self-test Fabric release reused experimental ABI exception"
        )

    for release_acceptance_id in (
        "PM-FAB-ABI-01",
        "PM-FAB-INSTANCE-01",
    ):
        release_record = next(
            item
            for item in release_fixture["acceptance"]
            if item["id"] == release_acceptance_id
        )
        try:
            validate_evidence_mapping(
                release_record["evidence"],
                f"self-test {release_acceptance_id} release evidence",
                "evidence/",
                set(),
                acceptance_id=release_acceptance_id,
                test=release_record["test"],
                allowed_platforms={"linux-x86_64", "macos-arm64"},
                module_id="fabric_v1",
                module_api_state="RELEASE_SUPPORTED",
            )
        except GateError as exc:
            if "legacy single receipt cannot prove profile matrix" not in str(exc):
                raise GateError(
                    "self-test Fabric release evidence exception rejected for "
                    f"wrong reason: {exc}"
                ) from exc
        else:
            raise GateError(
                "self-test Fabric release reused experimental work-note evidence"
            )

    def release_fabric_with_release_metadata(value: dict[str, Any]) -> None:
        release_fabric(value)
        module_at(value, "fabric_v1")["package"][
            "exported_metadata_variables"
        ] = METADATA_VARIABLES.copy()

    def all_release_except_linux(value: dict[str, Any]) -> None:
        for feature in value["features"]:
            feature["state"] = "RELEASE_SUPPORTED"
        for platform in value["platforms"]:
            platform["state"] = "RELEASE_SUPPORTED"
        next(
            item for item in value["platforms"] if item["id"] == "linux-x86_64"
        )["state"] = "HOST_CANDIDATE"

    reject(
        "module release without platform release",
        release_fabric_with_release_metadata,
        all_release_except_linux,
        reason="module release without platform release",
    )
    reject(
        "missing dependency",
        lambda value: module_at(value, "radio_fabric_adapter_v1")[
            "dependencies"
        ].pop(0),
        reason="radio adapter missing Accepted RF mapping dependency",
    )

    def transitive_insufficient_manifest(value: dict[str, Any]) -> None:
        item = module_at(value, "fabric_v1")
        item["state_history"] = [
            "PRIVATE_CANDIDATE",
            "PUBLIC_API_SPEC_ACCEPTED",
        ]
        item["module_api_state"] = "PUBLIC_API_SPEC_ACCEPTED"
        item["dependencies"] = [
            {
                "depends_on_feature_id": "fabric-bearer-nfl1-path-registry",
                "precondition_contract_id": None,
                "minimum_completion_state": "SPEC_ACCEPTED",
                "enforced_from_owner_module_state": "PUBLIC_API_SPEC_ACCEPTED",
            }
        ]

    def transitive_insufficient_matrix(value: dict[str, Any]) -> None:
        fabric = next(
            item
            for item in value["features"]
            if item["id"] == "fabric-bearer-nfl1-path-registry"
        )
        fabric["state"] = "SPEC_ACCEPTED"
        identity = next(
            item
            for item in value["features"]
            if item["id"] == "identity-attachment-session-install"
        )
        identity["state"] = "PROPOSED"

    # Exercise the closure helper directly so the fixed direct dependency roster
    # cannot mask the transitive-state mutation.
    transitive_matrix = copy.deepcopy(matrix)
    transitive_insufficient_matrix(transitive_matrix)
    features, _ = compatibility_authority(transitive_matrix)
    closure = feature_closure("fabric-bearer-nfl1-path-registry", features)
    if "identity-attachment-session-install" not in closure:
        raise GateError("self-test transitive closure omitted Identity/Attachment")
    if features["identity-attachment-session-install"]["state"] != "PROPOSED":
        raise GateError("self-test transitive insufficiency fixture drift")
    if (
        COMPLETION_STATES.index(
            features["identity-attachment-session-install"]["state"]
        )
        >= COMPLETION_STATES.index("SPEC_ACCEPTED")
    ):
        raise GateError("self-test transitive insufficiency was not insufficient")

    reject(
        "pure frag accidentally requires RF mapping",
        lambda value: module_at(value, "radio_frag_v1")["dependencies"].append(
            {
                "depends_on_feature_id": "nfl1-r7-nrw1-rf-mapping",
                "precondition_contract_id": None,
                "minimum_completion_state": "SPEC_ACCEPTED",
                "enforced_from_owner_module_state": "PUBLIC_API_SPEC_ACCEPTED",
            }
        ),
        reason="pure frag must not require RF mapping",
    )
    reject(
        "duplicate symbol prefix",
        lambda value: module_at(value, "wifi_v1").__setitem__(
            "symbol_prefix", module_at(value, "fabric_v1")["symbol_prefix"]
        ),
        reason="symbol prefix",
    )
    reject(
        "duplicate namespace",
        lambda value: module_at(value, "wifi_v1")["namespace_policy"].update(
            {
                "physical_namespaces": ["ninlil.fabric.v1"],
                "partition_prefixes": ["fabric_v1"],
            }
        ),
        reason="namespace/writer policy drift",
    )
    reject(
        "missing instance policy",
        lambda value: module_at(value, "fabric_v1").pop("instance_policy"),
        reason="closed fields mismatch",
    )
    reject(
        "missing acceptance/evidence mapping",
        lambda value: value["acceptance"].pop(0),
        reason="missing acceptance/evidence mapping",
    )

    def claim_pass_without_artifacts(value: dict[str, Any]) -> None:
        record = next(
            item
            for item in value["acceptance"]
            if item["id"] == "PM-WIFI-COMMON-ABI-01"
        )
        record["test"]["state"] = "PASS"
        record["evidence"]["state"] = "PASS"

    reject(
        "PASS claim with absent test and evidence",
        claim_pass_without_artifacts,
        reason="PASS/FAIL test file absent",
    )

    def claim_pass_with_empty_test(value: dict[str, Any]) -> None:
        record = next(
            item
            for item in value["acceptance"]
            if item["id"] == "PM-WIFI-COMMON-ABI-01"
        )
        record["test"]["path"] = (
            "tools/_vendor/pyyaml-6.0.2.dist-info/REQUESTED"
        )
        record["test"]["state"] = "PASS"
        record["evidence"]["state"] = "PASS"

    reject(
        "PASS claim with empty test file",
        claim_pass_with_empty_test,
        reason="exact test path drift",
    )
    reject(
        "package target mismatch",
        lambda value: module_at(value, "fabric_v1")["package"].__setitem__(
            "host_cmake_target", "Ninlil::wrong_v1"
        ),
        reason="package target/header/metadata mismatch",
    )
    reject(
        "package header mismatch",
        lambda value: module_at(value, "fabric_v1")["package"].__setitem__(
            "public_header_root", "ninlil/wrong/v1/"
        ),
        reason="package target/header/metadata mismatch",
    )
    reject(
        "package metadata mismatch",
        lambda value: module_at(value, "fabric_v1")["package"][
            "exported_metadata_variables"
        ].append("BOGUS_METADATA"),
        reason="package target/header/metadata mismatch",
    )
    reject(
        "Wi-Fi platform completion metadata omitted",
        lambda value: module_at(value, "wifi_v1")["package"][
            "exported_metadata_variables"
        ].remove("COMPLETION_STATE_BY_PLATFORM"),
        reason="package target/header/metadata mismatch",
    )
    reject(
        "Wi-Fi common interface drift",
        lambda value: module_at(value, "wifi_v1")["package"].__setitem__(
            "artifact_kind", "INTERFACE"
        ),
        reason="package target/header/metadata mismatch",
    )
    reject(
        "Wi-Fi POSIX missing common dependency",
        lambda value: module_at(value, "wifi_posix_v1")["package"].__setitem__(
            "dependencies", ["fabric_v1"]
        ),
        reason="package target/header/metadata mismatch",
    )
    reject(
        "public ABI layout invariant disabled",
        lambda value: module_at(value, "fabric_v1")["abi_contract"].__setitem__(
            "layout_invariant_across_compile_definitions", False
        ),
        reason="public ABI invariant",
    )
    reject(
        "unknown manifest key",
        lambda value: value.__setitem__("future", {}),
        reason="unknown=['future']",
    )
    reject(
        "unknown module state",
        lambda value: module_at(value, "fabric_v1").__setitem__(
            "module_api_state", "MAGIC_SUPPORTED"
        ),
        reason="unknown state",
    )
    reject(
        "unknown manifest version",
        lambda value: value.__setitem__("schema_version", 2),
        reason="unknown schema version",
    )
    reject(
        "manifest numeric field replaced by boolean",
        lambda value: value.__setitem__("schema_version", True),
        reason="boolean supplied to non-boolean field",
    )
    reject(
        "matrix numeric field replaced by boolean",
        mutate_matrix=lambda value: value["module_api_domain"].__setitem__(
            "schema_version",
            True,
        ),
        reason="boolean supplied to non-boolean field",
    )
    reject(
        "unknown schema version",
        mutate_schema=lambda value: value.__setitem__(
            "$schema", "https://json-schema.org/draft/2099-01/schema"
        ),
        reason="unknown JSON Schema version",
    )
    reject(
        "schema observer C ABI const drift",
        mutate_schema=lambda value: value["$defs"]["interModulePortContract"][
            "properties"
        ]["abi_version"].__setitem__("const", 2),
        reason="inter-module port C ABI const drift",
    )
    reject(
        "schema Identity/Attachment provider ABI const drift",
        mutate_schema=lambda value: value["$defs"][
            "identityAttachmentPreconditionContract"
        ]["const"]["provider_port"].__setitem__(
            "abi_version", 2
        ),
        reason="identityAttachmentPreconditionContract const digest drift",
    )
    reject(
        "schema Fabric selection authority const drift",
        mutate_schema=lambda value: value["$defs"][
            "fabricSelectionPortContract"
        ]["const"].__setitem__("stale_policy", "USE_STALE"),
        reason="fabricSelectionPortContract const digest drift",
    )
    reject(
        "schema evidence authority const drift",
        mutate_schema=lambda value: value["$defs"][
            "acceptanceEvidenceContract"
        ]["const"].__setitem__(
            "arbitrary_file_policy", "ANY_FILE_IS_EVIDENCE"
        ),
        reason="acceptanceEvidenceContract const digest drift",
    )
    reject(
        "platform receipt matrix weakened",
        lambda value: value["acceptance_evidence_contract"][
            "platform_profile_matrix"
        ].pop(),
        reason="manifest acceptance evidence contract drift",
    )
    reject(
        "schema independent review authority const drift",
        mutate_schema=lambda value: value["$defs"][
            "independentReviewContract"
        ]["const"].__setitem__(
            "self_report_policy",
            "SELF_REPORT_ALLOWED",
        ),
        reason="independentReviewContract const digest drift",
    )
    reject(
        "schema Wi-Fi per-platform metadata drift",
        mutate_schema=lambda value: value["$defs"]["package"]["properties"][
            "exported_metadata_variables"
        ]["oneOf"][1]["const"].remove("COMPLETION_STATE_BY_PLATFORM"),
        reason="package exported metadata drift",
    )
    reject(
        "module transition graph state jump",
        lambda value: value["allowed_module_api_transitions"][
            "PRIVATE_CANDIDATE"
        ].append("PACKAGE_EXPERIMENTAL"),
        reason="allowed transitions drift",
    )

    try:
        validate_evidence_artifact_payload(
            {"arbitrary": "not-an-evidence-receipt"},
            label="self-test arbitrary evidence",
            acceptance_id="PM-FAB-ABI-01",
            expected_state="PASS",
            test_path="tools/public_module_manifest_gate.py",
            allowed_platforms={"linux-x86_64"},
        )
    except GateError as exc:
        if "closed fields mismatch" not in str(exc):
            raise GateError(
                f"self-test arbitrary evidence rejected for wrong reason: {exc}"
            ) from exc
    else:
        raise GateError("self-test arbitrary JSON evidence accepted")

    for commented_registration in (
        "# add_test(NAME PM-FAB-ABI-01 COMMAND false)\n",
        "#[[\nadd_test(NAME PM-FAB-ABI-01 COMMAND false)\n]]\n",
    ):
        if has_ctest_registration(
            executable_text_without_comments(
                commented_registration,
                cmake=True,
            ),
            "PM-FAB-ABI-01",
        ):
            raise GateError(
                "self-test commented CTest registration false green"
            )
    commented_workflow = (
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: echo no-test # ctest\n"
    )
    if "ctest" in executable_text_without_comments(
        commented_workflow,
        cmake=False,
    ):
        raise GateError("self-test commented CI invocation false green")
    try:
        repo_path("../outside-evidence.json", "self-test escaped path")
    except GateError as exc:
        if "unsafe repository path" not in str(exc):
            raise GateError(
                f"self-test escaped path rejected for wrong reason: {exc}"
            ) from exc
    else:
        raise GateError("self-test escaped repository path accepted")
    with mock.patch.object(
        pathlib.Path,
        "is_symlink",
        new=lambda value: value.name == "synthetic-link",
    ):
        try:
            repo_path(
                "synthetic-link/outside-evidence.json",
                "self-test symlink path",
            )
        except GateError as exc:
            if "symlink path component rejected" not in str(exc):
                raise GateError(
                    "self-test symlink path rejected for wrong reason: "
                    f"{exc}"
                ) from exc
        else:
            raise GateError(
                "self-test repository symlink path component accepted"
            )
    try:
        validate_evidence_mapping(
            {
                "state": "PASS",
                "profile_receipts": [],
                "path": "evidence/hil/fabricated.json",
                "sha256": "0" * 64,
            },
            "self-test unverifiable HIL receipt",
            "evidence/hil/",
            set(),
            acceptance_id="PM-R7-HIL-01",
            test={
                "path": "tests/public_modules/radio_frag_v1_hil.c",
                "state": "PASS",
            },
            allowed_platforms={"esp32s3-esp-idf"},
            module_id=None,
            module_api_state=None,
        )
    except GateError as exc:
        if "state must remain NOT_RUN" not in str(exc):
            raise GateError(
                f"self-test HIL receipt rejected for wrong reason: {exc}"
            ) from exc
    else:
        raise GateError("self-test unverifiable HIL receipt accepted")

    unregistered_runner_artifact = {
        "schema": "ninlil_public_module_acceptance_evidence_v1",
        "schema_version": 1,
        "acceptance_id": "PM-FAB-ABI-01",
        "test_id": "PM-FAB-ABI-01",
        "platform_id": "linux-x86_64",
        "platform_profile_id": "linux-x86_64-gcc-debug",
        "os": "Linux",
        "architecture": "x86_64",
        "toolchain_family": "GNU",
        "toolchain_id": "fixture-gcc",
        "compiler_id": "GNU",
        "compiler_version": "fixture",
        "build_type": "Debug",
        "sanitizer_profile": "NONE",
        "cmake_cache_path": "build/public-module-receipt/CMakeCache.txt",
        "cmake_cache_sha256": "0" * 64,
        "esp_target": None,
        "esp_idf_version": None,
        "esp_elf_path": None,
        "esp_elf_sha256": None,
        "esp_map_path": None,
        "esp_map_sha256": None,
        "result": "PASS",
        # This fixture is rejected at runner registration before lineage is
        # inspected.  Keep it independent of GitHub's two-parent PR checkout;
        # production evidence still uses validate_tested_parent_commit().
        "tested_commit_sha": "0" * 40,
        "tested_tree_sha": "a" * 40,
        "runner_kind": "LOCAL_CTEST_REPLAYABLE_RECEIPT",
        "runner_registration_path": "CMakeLists.txt",
        "runner_id": "PM-FAB-ABI-01",
        "runner_target": "ninlil_public_module_fabric_v1_abi_negative",
        "runner_source_path": "tools/public_module_manifest_gate.py",
        "runner_build_dir": "build/public-module-receipt",
        "runner_working_directory": "build/public-module-receipt",
        "runner_command_argv": [
            "build/public-module-receipt/PM-FAB-ABI-01",
        ],
        "runner_exit_code": 0,
        "stdout_path": (
            "evidence/public-modules/receipts/PM-FAB-ABI-01.stdout"
        ),
        "stdout_size": 0,
        "stdout_sha256": hashlib.sha256(b"").hexdigest(),
        "stderr_path": (
            "evidence/public-modules/receipts/PM-FAB-ABI-01.stderr"
        ),
        "stderr_size": 0,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "started_at_utc": "2026-07-31T00:00:00Z",
        "finished_at_utc": "2026-07-31T00:00:01Z",
    }
    boolean_exit_artifact = copy.deepcopy(unregistered_runner_artifact)
    boolean_exit_artifact["runner_exit_code"] = False
    try:
        validate_evidence_artifact_payload(
            boolean_exit_artifact,
            label="self-test boolean evidence exit",
            acceptance_id="PM-FAB-ABI-01",
            expected_state="PASS",
            test_path="tools/public_module_manifest_gate.py",
            allowed_platforms={"linux-x86_64"},
        )
    except GateError as exc:
        if "boolean supplied to non-boolean field" not in str(exc):
            raise GateError(
                "self-test boolean evidence exit rejected for wrong reason: "
                f"{exc}"
            ) from exc
    else:
        raise GateError("self-test boolean evidence exit accepted")
    fabricated_ci_artifact = copy.deepcopy(unregistered_runner_artifact)
    fabricated_ci_artifact["runner_kind"] = "GITHUB_ACTIONS_SELF_REPORTED"
    try:
        validate_evidence_artifact_payload(
            fabricated_ci_artifact,
            label="self-test fabricated CI receipt",
            acceptance_id="PM-FAB-ABI-01",
            expected_state="PASS",
            test_path="tools/public_module_manifest_gate.py",
            allowed_platforms={"linux-x86_64"},
        )
    except GateError as exc:
        if "no offline verifier" not in str(exc):
            raise GateError(
                f"self-test fabricated CI receipt rejected for wrong reason: {exc}"
            ) from exc
    else:
        raise GateError("self-test fabricated CI receipt accepted")
    validate_replay_receipt_claim(
        unregistered_runner_artifact,
        observed_exit_code=0,
        observed_stdout=b"",
        observed_stderr=b"",
        label="self-test valid replay receipt claim",
    )
    try:
        validate_replay_receipt_claim(
            unregistered_runner_artifact,
            observed_exit_code=1,
            observed_stdout=b"",
            observed_stderr=b"",
            label="self-test fabricated exit receipt",
        )
    except GateError as exc:
        if "self-reported exit code differs from replay" not in str(exc):
            raise GateError(
                f"self-test fabricated exit rejected for wrong reason: {exc}"
            ) from exc
    else:
        raise GateError("self-test fabricated exit receipt accepted")
    try:
        validate_replay_receipt_claim(
            unregistered_runner_artifact,
            observed_exit_code=0,
            observed_stdout=b"fabricated stdout",
            observed_stderr=b"",
            label="self-test fabricated stream receipt",
        )
    except GateError as exc:
        if "stdout size differs from replay" not in str(exc):
            raise GateError(
                f"self-test fabricated stream rejected for wrong reason: {exc}"
            ) from exc
    else:
        raise GateError("self-test fabricated stream receipt accepted")
    try:
        validate_evidence_artifact_payload(
            unregistered_runner_artifact,
            label="self-test unregistered runner",
            acceptance_id="PM-FAB-ABI-01",
            expected_state="PASS",
            test_path="tools/public_module_manifest_gate.py",
            allowed_platforms={"linux-x86_64"},
        )
    except GateError as exc:
        if "CTest runner ID is not machine registered" not in str(exc):
            raise GateError(
                f"self-test unregistered runner rejected for wrong reason: {exc}"
            ) from exc
    else:
        raise GateError("self-test unregistered runner accepted")

    for profile_field, bad_value in (
        ("toolchain_family", "ESP-IDF"),
        ("platform_profile_id", "esp32s3-esp-idf-release"),
    ):
        malformed_profile = copy.deepcopy(unregistered_runner_artifact)
        malformed_profile[profile_field] = bad_value
        try:
            validate_evidence_artifact_payload(
                malformed_profile,
                label=f"self-test profile field {profile_field}",
                acceptance_id="PM-FAB-ABI-01",
                expected_state="PASS",
                test_path="tools/public_module_manifest_gate.py",
                allowed_platforms={"linux-x86_64"},
            )
        except GateError as exc:
            if "platform/profile" not in str(exc):
                raise GateError(
                    f"self-test profile field {profile_field} rejected for wrong reason: {exc}"
                ) from exc
        else:
            raise GateError(f"self-test profile field {profile_field} accepted")

    # P1-2: a root-confined executable is still invalid if its codemodel target
    # is built from an unrelated always-pass source.
    with __import__("tempfile").TemporaryDirectory() as temporary:
        build = pathlib.Path(temporary)
        reply = build / ".cmake/api/v1/reply"
        reply.mkdir(parents=True)
        executable = build / "unrelated_always_pass"
        executable.write_bytes(b"fixture")
        source = ROOT / "tools/public_module_manifest_gate.py"
        target_detail = {
            "sources": [{"path": str(source), "isGenerated": False}],
            "artifacts": [{"path": str(executable)}],
        }
        (reply / "target.json").write_text(json.dumps(target_detail), encoding="utf-8")
        codemodel = {
            "configurations": [{"targets": [{"name": "ninlil_public_module_fabric_v1_abi_negative", "jsonFile": "target.json"}]}]
        }
        validate_codemodel_target_source_ownership(
            codemodel,
            build_dir=build,
            target_name="ninlil_public_module_fabric_v1_abi_negative",
            test_path="tools/public_module_manifest_gate.py",
            executable_path=executable,
            label="self-test owned runner",
        )
        try:
            validate_codemodel_target_source_ownership(
                codemodel,
                build_dir=build,
                target_name="ninlil_public_module_fabric_v1_abi_negative",
                test_path="README.md",
                executable_path=executable,
                label="self-test unrelated always-pass",
            )
        except GateError as exc:
            if "does not own declared test source" not in str(exc):
                raise GateError(
                    f"self-test unrelated always-pass rejected for wrong reason: {exc}"
                ) from exc
        else:
            raise GateError("self-test unrelated always-pass executable accepted")

    gate_path = str((ROOT / "tools/public_module_manifest_gate.py").resolve())
    active_catalog = {
        "tests": [
            {
                "name": "public_module_manifest_gate",
                "command": [sys.executable, gate_path, "check"],
                "properties": [],
            },
            {
                "name": "public_module_manifest_gate_self_test",
                "command": [sys.executable, gate_path, "self-test"],
                "properties": [],
            },
        ]
    }
    validate_ctest_catalog(
        active_catalog,
        python_executable=pathlib.Path(sys.executable),
    )
    ctest_catalog_mutations = [
        (
            "if(FALSE) omitted registration",
            {"tests": active_catalog["tests"][1:]},
            "must be active exact once",
        ),
        (
            "echo ctest command substitution",
            {
                "tests": [
                    {
                        **active_catalog["tests"][0],
                        "command": ["echo", "ctest", "check"],
                    },
                    active_catalog["tests"][1],
                ]
            },
            "exact command mismatch",
        ),
        (
            "disabled registration",
            {
                "tests": [
                    {
                        **active_catalog["tests"][0],
                        "properties": [
                            {"name": "DISABLED", "value": True}
                        ],
                    },
                    active_catalog["tests"][1],
                ]
            },
            "is disabled",
        ),
    ]
    for label, catalog, expected_reason in ctest_catalog_mutations:
        try:
            validate_ctest_catalog(
                catalog,
                python_executable=pathlib.Path(sys.executable),
            )
        except GateError as exc:
            if expected_reason not in str(exc):
                raise GateError(
                    f"self-test {label}: rejected for wrong reason: {exc}"
                ) from exc
        else:
            raise GateError(f"self-test {label}: false green")

    reject(
        "ADR status smuggled through fenced code",
        mutate_adr=lambda value: (
            value + "\n```text\n- Status: **Accepted**\n```\n"
        ),
        reason="status smuggling rejected",
    )
    reject(
        "ADR status smuggled through HTML comment",
        mutate_adr=lambda value: (
            value + "\n<!-- - Status: **Accepted** -->\n"
        ),
        reason="status smuggling rejected",
    )
    reject(
        "ADR duplicate live status line",
        mutate_adr=lambda value: value + "\n- Status: **Accepted**\n",
        reason="status smuggling rejected",
    )
    reject(
        "ADR canonical status line removed",
        mutate_adr=lambda value: value.replace(
            "- Status: **Proposed**",
            "`- Status: **Proposed**`",
            1,
        ),
        reason="canonical status line missing",
    )
    reject(
        "ADR H1 title substitution",
        mutate_adr=lambda value: value.replace(
            "# ADR-0028: Composable Public Runtime Modules",
            "# ADR-9999: Lookalike Accepted Decision",
            1,
        ),
        reason="exact H1 title mismatch",
    )

    identity_adr = repo_path(
        IDENTITY_PRECONDITION_ADR_PATH,
        "ADR-0039 path",
        require_exists=True,
        require_file=True,
    ).read_text(encoding="utf-8")
    accepted_identity_adr = identity_adr.replace(
        "- Status: **Proposed**",
        "- Status: **Accepted**",
        1,
    )
    exact_review = (
        "# Identity / Attachment precondition specification review\n\n"
        "- Reviewer: **Independent**\n"
        "- Scope: **ADR-0039 S1-S6 specification acceptance**\n"
        "- S1: **CONFIRMED**\n"
        "- S2: **CONFIRMED**\n"
        "- S3: **CONFIRMED**\n"
        "- S4: **CONFIRMED**\n"
        "- S5: **CONFIRMED**\n"
        "- S6: **CONFIRMED**\n"
        "- Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**\n"
    )
    check(
        copy.deepcopy(manifest),
        copy.deepcopy(matrix),
        copy.deepcopy(schema),
        identity_precondition_adr_text=accepted_identity_adr,
        identity_precondition_review_text=exact_review,
    )
    for name, review in (
        (
            "NO-GO with zero counts",
            exact_review.replace("**GO —", "**NO-GO —", 1),
        ),
        ("duplicate GO", exact_review + exact_review),
        (
            "stale GO",
            exact_review
            + "- Historical Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**\n",
        ),
        (
            "HTML comment GO",
            exact_review.replace(
                "- Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**",
                "<!-- - Result: **GO — P0=0 / P1=0 / P2=0 / P3=0** -->",
                1,
            ),
        ),
        (
            "sole code-fence GO",
            exact_review.replace(
                "- Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**",
                "```markdown\n- Result: **GO — P0=0 / P1=0 / P2=0 / P3=0**\n```",
                1,
            ),
        ),
    ):
        try:
            check(
                copy.deepcopy(manifest),
                copy.deepcopy(matrix),
                copy.deepcopy(schema),
                identity_precondition_adr_text=accepted_identity_adr,
                identity_precondition_review_text=review,
            )
        except GateError:
            pass
        else:
            raise GateError(
                f"self-test ADR-0039 Accepted {name} false green"
            )


def validate_ctest_catalog(
    catalog: Any,
    *,
    python_executable: pathlib.Path,
) -> None:
    tests = catalog.get("tests") if isinstance(catalog, dict) else None
    if not isinstance(tests, list):
        raise GateError("CTest registration: tests array absent")
    expected = {
        "public_module_manifest_gate": "check",
        "public_module_manifest_gate_self_test": "self-test",
    }
    matches: dict[str, list[dict[str, Any]]] = {
        name: [] for name in expected
    }
    for test in tests:
        if not isinstance(test, dict):
            raise GateError("CTest registration: non-object test")
        name = test.get("name")
        if name in matches:
            matches[name].append(test)
    gate_path = (ROOT / "tools/public_module_manifest_gate.py").resolve()
    python_path = python_executable.resolve()
    for name, argument in expected.items():
        entries = matches[name]
        if len(entries) != 1:
            raise GateError(
                f"CTest registration: {name} must be active exact once"
            )
        entry = entries[0]
        command = entry.get("command")
        if (
            not isinstance(command, list)
            or len(command) != 3
            or pathlib.Path(command[0]).resolve() != python_path
            or pathlib.Path(command[1]).resolve() != gate_path
            or command[2] != argument
        ):
            raise GateError(
                f"CTest registration: {name} exact command mismatch"
            )
        properties = entry.get("properties")
        if not isinstance(properties, list):
            raise GateError(f"CTest registration: {name} properties absent")
        for prop in properties:
            if not isinstance(prop, dict):
                raise GateError(
                    f"CTest registration: {name} malformed property"
                )
            if (
                prop.get("name") == "DISABLED"
                and str(prop.get("value", "")).strip().lower()
                in {"1", "true", "on", "yes"}
            ):
                raise GateError(f"CTest registration: {name} is disabled")


def verify_ctest_registration(build_dir_value: str) -> None:
    build_dir = repo_path(
        build_dir_value,
        "CTest build directory",
        require_exists=True,
        require_directory=True,
    )
    cache_path = build_dir / "CMakeCache.txt"
    if not cache_path.is_file() or cache_path.is_symlink():
        raise GateError("CTest registration: CMakeCache.txt absent")
    cache_text = cache_path.read_text(encoding="utf-8")
    expected_home = f"CMAKE_HOME_DIRECTORY:INTERNAL={ROOT.resolve()}"
    if expected_home not in cache_text.splitlines():
        raise GateError("CTest registration: build tree source root mismatch")
    try:
        completed = subprocess.run(
            [
                "ctest",
                "--test-dir",
                str(build_dir),
                "--show-only=json-v1",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        catalog = json.loads(
            completed.stdout,
            object_pairs_hook=_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as exc:
        raise GateError("CTest registration: active catalog unavailable") from exc
    validate_ctest_catalog(
        catalog,
        python_executable=pathlib.Path(sys.executable),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("check", "self-test", "verify-ctest-registration"),
    )
    parser.add_argument("--build-dir")
    args = parser.parse_args()
    try:
        if args.command == "verify-ctest-registration":
            if args.build_dir is None:
                raise GateError(
                    "verify-ctest-registration requires --build-dir"
                )
            verify_ctest_registration(args.build_dir)
        else:
            if args.build_dir is not None:
                raise GateError("--build-dir is valid only for CTest verification")
            manifest = load_json_strict(
                repo_path(
                    "public-module-manifest.json",
                    "manifest path",
                    require_exists=True,
                    require_file=True,
                )
            )
            matrix = load_json_strict(
                repo_path(
                    "compatibility-matrix.json",
                    "compatibility matrix path",
                    require_exists=True,
                    require_file=True,
                )
            )
            schema = load_json_strict(
                repo_path(
                    "spec/public-module-manifest-v1.schema.json",
                    "manifest schema path",
                    require_exists=True,
                    require_file=True,
                )
            )
            if args.command == "check":
                check(manifest, matrix, schema)
            else:
                self_test(manifest, matrix, schema)
    except (GateError, KeyError, OSError, TypeError, ValueError) as exc:
        print(f"public module manifest gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"public module manifest gate {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
