#!/usr/bin/env python3
"""ESP wifi_v1 resource gate — measured ELF/map only (no declared-constant pass).

Requires:
  --map, --elf present and non-empty
  --expect-symbols: real HIL call-graph symbols retained in final ELF/map
  --component-archive: component-only paths are defined in the ESP archive
  --max-owner-bytes: target-ELF sizeof probe must be <= this (default 12288)
  optional --su-dir: each .su stack frame <= --max-stack-bytes (default 8192)
  optional --sdkconfig / --sdkconfig-h: require KEYING_MATERIAL_EXPORT=y
  optional --defaults: require wifi_hil_app sdkconfig.defaults pin
  optional --expect-export-symbol: require mbedtls_ssl_export_keying_material

Fails closed on missing artifacts. No soft-pass.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
WIFI_HIL_DEFAULTS = (
    REPO_ROOT / "ports" / "esp-idf" / "wifi_hil_app" / "sdkconfig.defaults"
)
TLS_MBEDTLS_C = (
    REPO_ROOT / "src" / "transport" / "wifi_v1" / "wifi_esp_tls_mbedtls.c"
)
TLS_ALLOCATOR_C = (
    REPO_ROOT / "src" / "transport" / "wifi_v1" / "wifi_esp_tls_allocator.c"
)
TLS_RESOURCE_POLICY_H = (
    REPO_ROOT
    / "src"
    / "transport"
    / "wifi_v1"
    / "wifi_tls_resource_policy.h"
)
R7_MBEDTLS_C = REPO_ROOT / "ports" / "esp-idf" / "src" / "r7_crypto_mbedtls.c"
WIFI_HIL_MAIN_C = (
    REPO_ROOT / "ports" / "esp-idf" / "wifi_hil_app" / "main" / "main.c"
)
COMPONENT_CMAKE = (
    REPO_ROOT / "ports" / "esp-idf" / "components" / "ninlil" / "CMakeLists.txt"
)

KEYING_CONFIG = "CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT=y"
KEYING_MACRO = "MBEDTLS_SSL_KEYING_MATERIAL_EXPORT"
EXPORT_SYM = "mbedtls_ssl_export_keying_material"
OWNER_SIZE_SYMBOL = "ninlil_wifi_esp_owner_target_size_probe"

ESP_HIL_REQUIRED_SYMBOLS = (
    "wifi_create_v1",
    "wifi_step_v1",
    "wifi_packet_link_descriptor_v1",
    "wifi_packet_link_ops_v1",
    "ninlil_wifi_esp_owner_init",
    "ninlil_wifi_esp_owner_step",
    "ninlil_wifi_esp_owner_connect",
    "ninlil_wifi_esp_owner_configure_tls",
    "ninlil_wifi_esp_owner_send_payload",
    "ninlil_wifi_esp_owner_recv_record",
    "ninlil_wifi_esp_owner_enqueue_event_ip",
    "ninlil_wifi_esp_tls_handshake",
    "ninlil_wifi_esp_tls_write",
    "ninlil_wifi_esp_tls_read",
    "ninlil_wifi_esp_tls_verified_identity",
    "ninlil_wifi_esp_tls_export_peer_session_id",
    "ninlil_wifi_esp_tls_export_attached_session_id",
    "ninlil_wifi_esp_tcp_connect",
    "ninlil_wifi_esp_tcp_listen",
    "ninlil_wifi_esp_tls_allocator_bootstrap",
    "ninlil_wifi_esp_tls_allocator_other_register",
    "ninlil_wifi_esp_tls_allocator_other_snapshot",
    "ninlil_wifi_esp_tls_allocator_aggregate_snapshot",
    "ninlil_wifi_esp_tls_allocator_trace_at",
    "ninlil_wifi_esp_tls_allocator_owner_enter",
    "ninlil_wifi_esp_tls_allocator_owner_leave_checked",
    "ninlil_r7_crypto_mbedtls_provider_init",
    "ninlil_r7_crypto_hkdf_extract_sha256",
    "ninlil_r7_crypto_hkdf_expand_sha256",
    "ninlil_r7_crypto_aes128_gcm_seal",
    "ninlil_r7_crypto_aes128_gcm_open",
    "ninlil_r7_mbedtls_hkdf_extract_sha256",
    "ninlil_r7_mbedtls_hkdf_expand_sha256",
    "ninlil_r7_mbedtls_aes128_gcm_seal",
    "ninlil_r7_mbedtls_aes128_gcm_open",
    "ninlil_wifi_esp_fabric_packet_link_ops_init",
    "ninlil_wifi_nwb1_encode",
    "ninlil_wifi_esp_sta_init",
    "ninlil_wifi_m4_evidence_ready_for_attach",
    "ninlil_wifi_leaf_binding_decode",
)

# These paths are intentionally not retained by the HIL application when its
# final call graph does not use them.  Their ESP target compilation is proved
# against the component archive; Host execution is proved by their CTest
# targets.  Requiring them in the final ELF would encourage false keep-alive
# references and defeat section garbage collection.
ESP_COMPONENT_REQUIRED_SYMBOLS = (
    "ninlil_wifi_journal_attempt_encode_le",
    "ninlil_wifi_fabric_link_init",
    "ninlil_wifi_tls_arena_free_owned_pair",
    "ninlil_wifi_tls_arena_validate_live_allocation",
    "ninlil_wifi_esp_tls_allocator_other_release",
    "ninlil_wifi_esp_tls_allocator_trace_at",
    "ninlil_r7_crypto_mbedtls_provider_close",
)

# Exact ESP production closure for the Wi-Fi + Fabric composition image.
# Symbols alone cannot prove that a Host-only translation unit was not also
# compiled into the component archive and later discarded by the final link.
# The target `ar t` inventory therefore forms a separate fail-closed boundary.
ESP_COMPONENT_REQUIRED_MEMBERS = (
    "wifi_nwb1.c.obj",
    "wifi_nfl1_min.c.obj",
    "wifi_stream.c.obj",
    "wifi_queues.c.obj",
    "wifi_tls_arena.c.obj",
    "wifi_tls_resource_policy.c.obj",
    "wifi_sha256_mbedtls.c.obj",
    "wifi_reconnect.c.obj",
    "wifi_storage_cu.c.obj",
    "wifi_credentials.c.obj",
    "wifi_journal.c.obj",
    "wifi_attachment_m4.c.obj",
    "wifi_tls_leaf_binding.c.obj",
    "wifi_tls_export.c.obj",
    "wifi_fabric_adapter.c.obj",
    "wifi_esp_sta.c.obj",
    "wifi_esp_tcp.c.obj",
    "wifi_esp_mbedtls_profile_probe.c.obj",
    "wifi_esp_tls_allocator.c.obj",
    "wifi_esp_tls_mbedtls.c.obj",
    "wifi_esp_owner.c.obj",
    "nfl1_codec.c.obj",
    "fabric_private_util.c.obj",
    "fabric_workspace.c.obj",
    "fabric_private_records.c.obj",
    "fabric_private_select.c.obj",
    "fabric_private_core.c.obj",
    "wifi_esp_fabric_link_ops.c.obj",
    "wifi_adapter_v1_esp.c.obj",
    "r7_crypto_mbedtls.c.obj",
    "r7_crypto_portable.c.obj",
)

ESP_COMPONENT_FORBIDDEN_MEMBERS = (
    "wifi_sha256_host.c.obj",
    "wifi_tcp_posix.c.obj",
    "wifi_tls_host.c.obj",
    "wifi_session.c.obj",
    "wifi_fabric_link_ops.c.obj",
    "wifi_adapter_v1.c.obj",
    "r7_crypto_openssl3.c.obj",
)

ESP_MBEDTLS_PROFILE_PROBE_SYMBOLS = (
    "ninlil_wifi_esp_tls_target_in_buffer_bytes",
    "ninlil_wifi_esp_tls_target_out_buffer_bytes",
    "ninlil_wifi_esp_tls_target_max_align_size_probe",
    "ninlil_wifi_esp_tls_target_max_align_alignment_probe",
    "ninlil_wifi_esp_tls_target_r7_sha_context_size_probe",
    "ninlil_wifi_esp_tls_target_r7_sha_charge_probe",
    "ninlil_wifi_esp_tls_target_r7_hmac_charge_probe",
    "ninlil_wifi_esp_tls_target_r7_aes_context_size_probe",
    "ninlil_wifi_esp_tls_target_r7_gcm_charge_probe",
    "ninlil_wifi_esp_tls_target_r7_reservation_probe",
)

ESP_TARGET_EXACT_PROBE_SIZES = {
    "ninlil_wifi_esp_tls_target_max_align_size_probe": 16,
    "ninlil_wifi_esp_tls_target_max_align_alignment_probe": 8,
    "ninlil_wifi_esp_tls_target_r7_sha_context_size_probe": 108,
    "ninlil_wifi_esp_tls_target_r7_sha_charge_probe": 128,
    "ninlil_wifi_esp_tls_target_r7_hmac_charge_probe": 152,
    "ninlil_wifi_esp_tls_target_r7_aes_context_size_probe": 280,
    "ninlil_wifi_esp_tls_target_r7_gcm_charge_probe": 304,
    "ninlil_wifi_esp_tls_target_r7_reservation_probe": 304,
}

REQUIRED_Y = (
    "CONFIG_SPIRAM",
    "CONFIG_SPIRAM_USE_CAPS_ALLOC",
    "CONFIG_ESP_TLS_USING_MBEDTLS",
    "CONFIG_MBEDTLS_SSL_PROTO_TLS1_3",
    "CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_EPHEMERAL",
    "CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT",
    "CONFIG_MBEDTLS_SSL_KEEP_PEER_CERTIFICATE",
    "CONFIG_MBEDTLS_ASYMMETRIC_CONTENT_LEN",
    "CONFIG_MBEDTLS_TLS_SERVER_AND_CLIENT",
    "CONFIG_MBEDTLS_ECP_C",
    "CONFIG_MBEDTLS_ECDH_C",
    "CONFIG_MBEDTLS_ECDSA_C",
    "CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED",
    "CONFIG_MBEDTLS_AES_C",
    "CONFIG_MBEDTLS_GCM_C",
    "CONFIG_MBEDTLS_HKDF_C",
    "CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC",
)

REQUIRED_VALUES = {
    "CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN": "16384",
    "CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN": "4114",
}

REQUIRED_N = (
    "CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_PSK",
    "CONFIG_MBEDTLS_SSL_TLS1_3_KEXM_PSK_EPHEMERAL",
    "CONFIG_MBEDTLS_CLIENT_SSL_SESSION_TICKETS",
    "CONFIG_MBEDTLS_SERVER_SSL_SESSION_TICKETS",
    "CONFIG_ESP_TLS_CLIENT_SESSION_TICKETS",
    "CONFIG_ESP_TLS_SERVER_SESSION_TICKETS",
    "CONFIG_MBEDTLS_DYNAMIC_BUFFER",
    "CONFIG_MBEDTLS_SSL_VARIABLE_BUFFER_LENGTH",
    "CONFIG_MBEDTLS_SSL_RENEGOTIATION",
    "CONFIG_MBEDTLS_SSL_PROTO_TLS1_2",
    "CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC",
    "CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC",
    "CONFIG_MBEDTLS_DEFAULT_MEM_ALLOC",
    "CONFIG_MBEDTLS_IRAM_8BIT_MEM_ALLOC",
    "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE",
    "CONFIG_MBEDTLS_ECP_RESTARTABLE",
    "CONFIG_MBEDTLS_THREADING_C",
    "CONFIG_MBEDTLS_THREADING_ALT",
    "CONFIG_MBEDTLS_THREADING_PTHREAD",
    "CONFIG_MBEDTLS_HARDWARE_AES",
    "CONFIG_MBEDTLS_AES_USE_INTERRUPT",
    "CONFIG_MBEDTLS_AES_USE_PSEUDO_ROUND_FUNC",
    "CONFIG_MBEDTLS_HARDWARE_GCM",
    "CONFIG_MBEDTLS_GCM_SUPPORT_NON_AES_CIPHER",
    "CONFIG_MBEDTLS_HARDWARE_MPI",
    "CONFIG_MBEDTLS_LARGE_KEY_SOFTWARE_MPI",
    "CONFIG_MBEDTLS_MPI_USE_INTERRUPT",
    "CONFIG_MBEDTLS_HARDWARE_SHA",
    "CONFIG_MBEDTLS_HARDWARE_ECC",
    "CONFIG_MBEDTLS_ECC_OTHER_CURVES_SOFT_FALLBACK",
    "CONFIG_MBEDTLS_ROM_MD5",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN",
    "CONFIG_MBEDTLS_TEE_SEC_STG_ECDSA_SIGN",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN_MASKING_CM",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_SIGN_CONSTANT_TIME_CM",
    "CONFIG_MBEDTLS_HARDWARE_ECDSA_VERIFY",
    "CONFIG_MBEDTLS_ATCA_HW_ECDSA_SIGN",
    "CONFIG_MBEDTLS_ATCA_HW_ECDSA_VERIFY",
    "CONFIG_MBEDTLS_USE_CRYPTO_ROM_IMPL",
    "CONFIG_MBEDTLS_USE_CRYPTO_ROM_IMPL_BOOTLOADER",
    "CONFIG_ESP_TLS_USE_SECURE_ELEMENT",
    "CONFIG_ESP_TLS_USE_DS_PERIPHERAL",
)


def fail(msg: str) -> int:
    print(f"FAIL: {msg}", file=sys.stderr)
    return 1


def _config_values(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def _header_defines(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        parts = raw.strip().split(None, 2)
        if len(parts) >= 2 and parts[0] == "#define":
            values[parts[1]] = parts[2] if len(parts) == 3 else "1"
    return values


def _parse_nm_sized_symbols(text: str) -> dict[str, tuple[int, int, str]]:
    """Parse `nm -S` rows as exact symbol-name -> (address, size, kind)."""
    symbols: dict[str, tuple[int, int, str]] = {}
    for raw in text.splitlines():
        parts = raw.split()
        if len(parts) < 4:
            continue
        address_text, size_text, kind, name = parts[-4:]
        if len(kind) != 1:
            continue
        try:
            address = int(address_text, 16)
            size = int(size_text, 16)
        except ValueError:
            continue
        symbols[name] = (address, size, kind)
    return symbols


def _target_owner_size(
    nm_symbols: dict[str, tuple[int, int, str]], symbol: str
) -> int | None:
    row = nm_symbols.get(symbol)
    if row is None:
        return None
    address, size, kind = row
    if address == 0 or size == 0 or kind.upper() == "U":
        return None
    return size


def _archive_symbol_is_defined(
    nm_symbols: dict[str, tuple[int, int, str]], symbol: str
) -> bool:
    row = nm_symbols.get(symbol)
    if row is None:
        return False
    _address, size, kind = row
    # Relocatable archive members legitimately use address zero.  A concrete
    # non-zero definition size and a non-undefined kind are the authority here.
    return size > 0 and kind.upper() != "U"


def _component_member_errors(members: list[str]) -> list[str]:
    member_set = set(members)
    errors: list[str] = []
    missing = [
        member
        for member in ESP_COMPONENT_REQUIRED_MEMBERS
        if member not in member_set
    ]
    forbidden = [
        member
        for member in ESP_COMPONENT_FORBIDDEN_MEMBERS
        if member in member_set
    ]
    if missing:
        errors.append(f"required ESP production members missing: {missing}")
    if forbidden:
        errors.append(f"Host-only members present in ESP archive: {forbidden}")
    return errors


def check_tls_profile_defaults(path: Path) -> int | None:
    if not path.is_file():
        return fail(f"sdkconfig.defaults missing {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = {line.strip() for line in text.splitlines()}
    for key in REQUIRED_Y:
        if f"{key}=y" not in lines:
            return fail(f"{path} missing exact enabled pin {key}=y")
    for key, value in REQUIRED_VALUES.items():
        if f"{key}={value}" not in lines:
            return fail(f"{path} missing exact value pin {key}={value}")
    for key in REQUIRED_N:
        if f"# {key} is not set" not in lines:
            return fail(f"{path} missing exact disabled pin: # {key} is not set")
    print(
        "OK defaults exact TLS profile "
        f"enabled={len(REQUIRED_Y)} disabled={len(REQUIRED_N)}"
    )
    return None


def check_tls_profile_sdkconfig(path: Path) -> int | None:
    if not path.is_file():
        return fail(f"sdkconfig missing {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    values = _config_values(text)
    for key in REQUIRED_Y:
        if values.get(key) != "y":
            return fail(f"{path}: required {key}=y, got {values.get(key)!r}")
    for key, value in REQUIRED_VALUES.items():
        if values.get(key) != value:
            return fail(
                f"{path}: required {key}={value}, got {values.get(key)!r}"
            )
    for key in REQUIRED_N:
        if key in values:
            return fail(f"{path}: forbidden effective config {key}={values[key]}")
    print(
        "OK generated sdkconfig exact TLS profile "
        f"enabled={len(REQUIRED_Y)} disabled={len(REQUIRED_N)}"
    )
    return None


def check_tls_profile_sdkconfig_h(path: Path) -> int | None:
    if not path.is_file():
        return fail(f"sdkconfig.h missing {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    values = _header_defines(text)
    for key in REQUIRED_Y:
        if values.get(key) != "1":
            return fail(f"{path}: required #define {key} 1")
    for key, value in REQUIRED_VALUES.items():
        if values.get(key) != value:
            return fail(f"{path}: required #define {key} {value}")
    for key in REQUIRED_N:
        if key in values:
            return fail(f"{path}: forbidden macro is defined: {key}={values[key]}")
    print("OK sdkconfig.h exact TLS profile macros")
    return None


def check_source_fail_closed() -> int | None:
    if not TLS_MBEDTLS_C.is_file():
        return fail(f"missing {TLS_MBEDTLS_C}")
    text = TLS_MBEDTLS_C.read_text(encoding="utf-8", errors="replace")
    if EXPORT_SYM not in text:
        return fail(f"{TLS_MBEDTLS_C.name} must call {EXPORT_SYM}")
    if f"defined({KEYING_MACRO})" not in text and f"defined {KEYING_MACRO}" not in text:
        # Accept #if defined(MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
        if f"#if defined({KEYING_MACRO})" not in text:
            return fail(
                f"{TLS_MBEDTLS_C.name} must guard {EXPORT_SYM} with "
                f"#if defined({KEYING_MACRO})"
            )
    # No unguarded call: every export call must sit after a KEYING #if in file.
    # Heuristic: count #if defined(KEYING) blocks and export calls.
    if text.count(EXPORT_SYM) < 2:
        return fail(f"{TLS_MBEDTLS_C.name} must call {EXPORT_SYM} for peer+attached")
    if "return NINLIL_WIFI_TLS_FAILED" not in text:
        return fail(
            f"{TLS_MBEDTLS_C.name} must fail closed (TLS_FAILED) when export OFF"
        )
    # Forbidden: synthetic / fake session id helpers in this TU.
    forbidden = (
        "fake_session",
        "synthetic_session",
        "random_session_id",
        "generate_session_id",
    )
    low = text.lower()
    for tok in forbidden:
        if tok in low:
            return fail(f"{TLS_MBEDTLS_C.name} forbids synthetic session path: {tok}")
    print(f"OK source fail-closed guard for {EXPORT_SYM}")
    return None


def check_component_acceptance() -> int | None:
    if not COMPONENT_CMAKE.is_file():
        return fail(f"missing {COMPONENT_CMAKE}")
    text = COMPONENT_CMAKE.read_text(encoding="utf-8", errors="replace")
    if "CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT" not in text:
        return fail(
            "component CMakeLists must accept KEYING_MATERIAL_EXPORT when "
            "PRIVATE_WIFI_V1 is ON"
        )
    if "FATAL_ERROR" not in text or "KEYING_MATERIAL_EXPORT" not in text:
        return fail(
            "component must FATAL_ERROR when WIFI_V1 ON without KEYING export"
        )
    print("OK component acceptance requires KEYING_MATERIAL_EXPORT with WIFI_V1")
    return None


def check_tiered_allocator_source() -> int | None:
    for path in (
        TLS_ALLOCATOR_C,
        TLS_RESOURCE_POLICY_H,
        R7_MBEDTLS_C,
        WIFI_HIL_MAIN_C,
    ):
        if not path.is_file():
            return fail(f"missing tiered allocator source {path}")
    allocator = TLS_ALLOCATOR_C.read_text(encoding="utf-8", errors="replace")
    policy = TLS_RESOURCE_POLICY_H.read_text(
        encoding="utf-8", errors="replace"
    )
    tls = TLS_MBEDTLS_C.read_text(encoding="utf-8", errors="replace")
    r7 = R7_MBEDTLS_C.read_text(encoding="utf-8", errors="replace")
    hil_main = WIFI_HIL_MAIN_C.read_text(encoding="utf-8", errors="replace")
    profile_probe = (
        TLS_MBEDTLS_C.parent / "wifi_esp_mbedtls_profile_probe.c"
    ).read_text(encoding="utf-8", errors="replace")
    required_allocator = (
        "MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT",
        "MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT",
        "esp_psram_is_initialized",
        "esp_ptr_internal",
        "esp_ptr_external_ram",
        "heap_caps_get_free_size",
        "heap_caps_get_largest_free_block",
        "ninlil_wifi_tls_resource_admit",
        "ninlil_wifi_tls_io_classifier_route",
        "ninlil_wifi_tls_arena_free_owned_pair",
        "ninlil_wifi_tls_arena_validate_live_allocation",
        "ninlil_wifi_tls_arena_zeroize",
        "allocation_oom",
        "contract_failed",
        "NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1",
        "ninlil_wifi_esp_tls_allocator_other_register",
        "ninlil_wifi_esp_tls_allocator_other_release",
        "ninlil_wifi_esp_tls_allocator_owner_leave_checked",
        "NINLIL_WIFI_ESP_TLS_ALLOC_TRACE_CAPACITY",
    )
    for token in required_allocator:
        if token not in allocator:
            return fail(f"tiered allocator missing token {token}")
    free_start = allocator.find("static void wifi_tls_profile_free")
    free_end = allocator.find("static void bootstrap_rollback", free_start)
    if free_start < 0 or free_end <= free_start:
        return fail("tiered allocator owner-scoped free body not found")
    free_body = allocator[free_start:free_end]
    for token in (
        "s_allocator.current_owner == WIFI_TLS_GLOBAL_OWNER",
        "s_allocator.current_owner < WIFI_TLS_ALLOC_OWNER_COUNT",
        "ninlil_wifi_tls_arena_free_owned_pair",
    ):
        if token not in free_body:
            return fail(f"owner-scoped free missing token {token}")
    if "for (" in free_body or "owners[index]" in free_body:
        return fail("free callback must not scan or free across owners")
    required_policy = (
        "#define NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET 12288u",
        "#define NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET 86016u",
        "#define NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET 65536u",
        "#define NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP 65536u",
        "#define NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES 327680u",
        "#define NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES 16685u",
        "#define NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES 4415u",
        "#define NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET 304u",
        "#define NINLIL_WIFI_ESP_TLS_WIFI_R7_COMPOSITION_TOTAL_BUDGET 262448u",
        "#define NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ENVELOPE 164144u",
        "#define NINLIL_WIFI_ESP_TLS_WIFI_R7_INTERNAL_ONLY_REQUIREMENT_BYTES 327984u",
    )
    for token in required_policy:
        if token not in policy:
            return fail(f"tiered allocator policy drift: {token}")
    for token in (
        "ninlil_wifi_esp_tls_allocator_io_begin",
        "ninlil_wifi_esp_tls_allocator_io_finish",
        "NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES",
        "NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES",
    ):
        if token not in tls:
            return fail(f"TLS setup classification seam missing {token}")
    for token in (
        "#define MBEDTLS_ALLOW_PRIVATE_ACCESS",
        "MBEDTLS_SSL_IN_BUFFER_LEN == NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES",
        "MBEDTLS_SSL_OUT_BUFFER_LEN == NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES",
        "#if defined(MBEDTLS_BLOCK_CIPHER_C)",
        "#if defined(MBEDTLS_MD_SHA256_VIA_PSA)",
        "sizeof(mbedtls_aes_context) == 280u",
        "ninlil_wifi_esp_tls_target_r7_gcm_charge_probe",
    ):
        if token not in profile_probe:
            return fail(f"target mbedTLS profile probe missing {token}")
    required_r7 = (
        "ninlil_r7_mbedtls_owner_begin",
        "ninlil_r7_mbedtls_owner_finish",
        "ninlil_wifi_esp_tls_allocator_bootstrap",
        "ninlil_wifi_esp_tls_allocator_other_register",
        "NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET",
        "ninlil_wifi_esp_tls_allocator_other_release",
        "ninlil_r7_crypto_mbedtls_provider_close",
    )
    for token in required_r7:
        if token not in r7:
            return fail(f"R7 OTHER_REGISTERED wrapper missing {token}")
    for root in (
        "ninlil_r7_mbedtls_sha256_raw",
        "ninlil_r7_mbedtls_hkdf_extract_sha256_raw",
        "ninlil_r7_mbedtls_hkdf_expand_sha256_raw",
        "ninlil_r7_mbedtls_aes128_gcm_seal_raw",
        "ninlil_r7_mbedtls_aes128_gcm_open_raw",
    ):
        if root not in r7:
            return fail(f"R7 raw callback root missing {root}")
    for token in (
        "r7_cotenant_start",
        "ninlil_r7_crypto_mbedtls_provider_init",
        "ninlil_r7_crypto_hkdf_extract_sha256",
        "ninlil_r7_crypto_hkdf_expand_sha256",
        "ninlil_r7_crypto_aes128_gcm_seal",
        "ninlil_r7_crypto_aes128_gcm_open",
        "NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET",
        "R7_ALLOC_TRACE",
        "scope=runtime_observation",
        "physical_ap_hil=NOT_RUN",
    ):
        if token not in hil_main:
            return fail(f"Wi-Fi HIL R7 instrumentation missing {token}")
    if allocator.count("heap_caps_calloc(") != 4:
        return fail("tiered allocator must have exact 4 raw reservation callsites")
    if allocator.count("heap_caps_free(") != 1:
        return fail("tiered allocator must have exact 1 raw release callsite")
    wifi_dir = TLS_ALLOCATOR_C.parent
    direct_heap = re.compile(r"\bheap_caps_(?:calloc|malloc|realloc|free)\s*\(")
    generic_heap = re.compile(
        r"(?<![A-Za-z0-9_])(?:malloc|calloc|realloc|free)\s*\("
    )
    for source in sorted(wifi_dir.glob("*.c")):
        source_text = source.read_text(encoding="utf-8", errors="replace")
        if source != TLS_ALLOCATOR_C and direct_heap.search(source_text):
            return fail(f"raw capability heap escaped allocator: {source.name}")
        if generic_heap.search(source_text):
            return fail(f"generic/default heap call forbidden: {source.name}")
    print(
        "OK tiered allocator source: global/internal/PSRAM/R7 exact "
        "reservation, classification scope, no generic spill"
    )
    return None


def check_size_json(path: Path) -> int | None:
    if not path.is_file() or path.stat().st_size == 0:
        return fail(f"ESP size json missing/empty {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return fail(f"ESP size json invalid {path}: {exc}")
    layout = document.get("layout")
    if not isinstance(layout, list):
        return fail("ESP size json missing layout")
    diram = next(
        (
            row
            for row in layout
            if isinstance(row, dict) and row.get("name") == "DIRAM"
        ),
        None,
    )
    if diram is None:
        return fail("ESP size json missing DIRAM row")
    total = diram.get("total")
    used = diram.get("used")
    free = diram.get("free")
    if not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in (total, used, free)
    ):
        return fail("ESP size json DIRAM values must be exact integers")
    if total != 341760 or used + free != total:
        return fail(
            f"ESP DIRAM arithmetic invalid total={total} used={used} free={free}"
        )
    envelope = 164144
    if free < envelope:
        return fail(
            f"ESP DIRAM free {free} < target-software envelope {envelope}"
        )
    print(
        "OK ESP final-map DIRAM arithmetic "
        f"used={used} total={total} free={free} "
        f"candidate_envelope={envelope} link_slack={free - envelope} "
        "(not runtime/HIL proof)"
    )
    return None


def self_test() -> int:
    def rejects(checker) -> bool:
        sink = io.StringIO()
        with contextlib.redirect_stderr(sink):
            return checker() is not None

    with tempfile.TemporaryDirectory(prefix="ninlil-wifi-resource-gate-") as td:
        root = Path(td)
        defaults = root / "sdkconfig.defaults"
        sdkconfig = root / "sdkconfig"
        sdkconfig_h = root / "sdkconfig.h"
        defaults_lines = [f"{key}=y" for key in REQUIRED_Y]
        defaults_lines.extend(
            f"{key}={value}" for key, value in REQUIRED_VALUES.items()
        )
        defaults_lines.extend(f"# {key} is not set" for key in REQUIRED_N)
        defaults.write_text("\n".join(defaults_lines) + "\n", encoding="utf-8")
        sdk_lines = [f"{key}=y" for key in REQUIRED_Y]
        sdk_lines.extend(
            f"{key}={value}" for key, value in REQUIRED_VALUES.items()
        )
        sdkconfig.write_text("\n".join(sdk_lines) + "\n", encoding="utf-8")
        header_lines = [f"#define {key} 1" for key in REQUIRED_Y]
        header_lines.extend(
            f"#define {key} {value}" for key, value in REQUIRED_VALUES.items()
        )
        sdkconfig_h.write_text("\n".join(header_lines) + "\n", encoding="utf-8")

        if check_tls_profile_defaults(defaults) is not None:
            return fail("self-test valid defaults rejected")
        if check_tls_profile_sdkconfig(sdkconfig) is not None:
            return fail("self-test valid sdkconfig rejected")
        if check_tls_profile_sdkconfig_h(sdkconfig_h) is not None:
            return fail("self-test valid sdkconfig.h rejected")

        bad = root / "bad"
        bad.write_text(
            defaults.read_text(encoding="utf-8").replace(
                f"{REQUIRED_Y[0]}=y\n", "", 1
            ),
            encoding="utf-8",
        )
        if not rejects(lambda: check_tls_profile_defaults(bad)):
            return fail("self-test missing enabled default false-green")

        bad.write_text(
            sdkconfig.read_text(encoding="utf-8")
            + f"{REQUIRED_N[0]}=y\n",
            encoding="utf-8",
        )
        if not rejects(lambda: check_tls_profile_sdkconfig(bad)):
            return fail("self-test forbidden generated config false-green")

        first_value = next(iter(REQUIRED_VALUES))
        bad.write_text(
            sdkconfig.read_text(encoding="utf-8").replace(
                f"{first_value}={REQUIRED_VALUES[first_value]}",
                f"{first_value}=1",
                1,
            ),
            encoding="utf-8",
        )
        if not rejects(lambda: check_tls_profile_sdkconfig(bad)):
            return fail("self-test wrong numeric config false-green")

        bad.write_text(
            sdkconfig_h.read_text(encoding="utf-8")
            + f"#define {REQUIRED_N[-1]} 1\n",
            encoding="utf-8",
        )
        if not rejects(lambda: check_tls_profile_sdkconfig_h(bad)):
            return fail("self-test forbidden generated macro false-green")

        sample_nm = (
            "3c010000 00002380 D ninlil_wifi_esp_owner_target_size_probe\n"
            "42000000 00000024 T ninlil_wifi_esp_owner_step\n"
        )
        parsed = _parse_nm_sized_symbols(sample_nm)
        if _target_owner_size(parsed, OWNER_SIZE_SYMBOL) != 0x2380:
            return fail("self-test target ELF owner-size probe was not measured")
        if _target_owner_size(parsed, "missing") is not None:
            return fail("self-test missing target owner-size probe false-green")
        zero_nm = _parse_nm_sized_symbols(
            "00000000 00002380 D ninlil_wifi_esp_owner_target_size_probe\n"
        )
        if _target_owner_size(zero_nm, OWNER_SIZE_SYMBOL) is not None:
            return fail("self-test discarded target owner-size probe false-green")
        archive_nm = _parse_nm_sized_symbols(
            "00000000 0000010b T ninlil_wifi_journal_attempt_encode_le\n"
        )
        if not _archive_symbol_is_defined(
            archive_nm, "ninlil_wifi_journal_attempt_encode_le"
        ):
            return fail("self-test valid relocatable archive definition rejected")
        if _archive_symbol_is_defined(archive_nm, "missing"):
            return fail("self-test missing archive definition false-green")
        zero_size_archive_nm = _parse_nm_sized_symbols(
            "00000000 00000000 T ninlil_wifi_journal_attempt_encode_le\n"
        )
        if _archive_symbol_is_defined(
            zero_size_archive_nm, "ninlil_wifi_journal_attempt_encode_le"
        ):
            return fail("self-test zero-sized archive definition false-green")
        if _component_member_errors(
            list(ESP_COMPONENT_REQUIRED_MEMBERS)
        ):
            return fail("self-test valid ESP component inventory rejected")
        if not _component_member_errors(
            list(ESP_COMPONENT_REQUIRED_MEMBERS)[1:]
        ):
            return fail("self-test missing ESP production member false-green")
        if not _component_member_errors(
            list(ESP_COMPONENT_REQUIRED_MEMBERS)
            + [ESP_COMPONENT_FORBIDDEN_MEMBERS[0]]
        ):
            return fail("self-test Host-only ESP member false-green")

        size_json = root / "size.json"
        size_json.write_text(
            json.dumps(
                {
                    "version": "1.1",
                    "layout": [
                        {
                            "name": "DIRAM",
                            "total": 341760,
                            "used": 169935,
                            "free": 171825,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        if check_size_json(size_json) is not None:
            return fail("self-test valid final-map arithmetic rejected")
        size_json.write_text(
            json.dumps(
                {
                    "version": "1.1",
                    "layout": [
                        {
                            "name": "DIRAM",
                            "total": 341760,
                            "used": 177617,
                            "free": 164143,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        if not rejects(lambda: check_size_json(size_json)):
            return fail("self-test undersized DIRAM envelope false-green")

    print("OK wifi_v1_esp_resource_gate self-test")
    return 0


def main() -> int:
    if sys.argv[1:] == ["self-test"]:
        return self_test()
    ap = argparse.ArgumentParser()
    ap.add_argument("--map", required=True)
    ap.add_argument("--elf", required=True)
    ap.add_argument(
        "--component-archive",
        default="",
        help=(
            "ESP target component archive; mandatory with --expect-symbols "
            "to prove component-only journal and Fabric definitions"
        ),
    )
    ap.add_argument("--su-dir", default="")
    ap.add_argument("--expect-symbols", action="store_true")
    ap.add_argument("--max-owner-bytes", type=int, default=12288)
    ap.add_argument("--max-stack-bytes", type=int, default=8192)
    ap.add_argument(
        "--nm-tool",
        default="xtensa-esp32s3-elf-nm",
        help="Target toolchain nm executable used for final-ELF retention and size proof",
    )
    ap.add_argument(
        "--ar-tool",
        default="xtensa-esp32s3-elf-ar",
        help=(
            "Target toolchain ar executable used to prove exact ESP production "
            "members and Host-only exclusion"
        ),
    )
    ap.add_argument(
        "--owner-size-symbol",
        default=OWNER_SIZE_SYMBOL,
        help="Retained target-ELF array whose symbol size equals sizeof(owner)",
    )
    ap.add_argument(
        "--sdkconfig",
        default="",
        help="Generated sdkconfig; require CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT=y",
    )
    ap.add_argument(
        "--sdkconfig-h",
        default="",
        help="Generated sdkconfig.h; require KEYING define enabled",
    )
    ap.add_argument(
        "--defaults",
        default="",
        help="sdkconfig.defaults path (default: wifi_hil_app when --check-acceptance)",
    )
    ap.add_argument(
        "--check-acceptance",
        action="store_true",
        help="Verify defaults pin + component CMake + source fail-closed guards",
    )
    ap.add_argument(
        "--expect-export-symbol",
        action="store_true",
        help="Require mbedtls_ssl_export_keying_material in map",
    )
    ap.add_argument(
        "--size-json",
        default="",
        help="ESP-IDF idf_size.py --format json2 final-map artifact",
    )
    args = ap.parse_args()

    map_path = Path(args.map)
    elf_path = Path(args.elf)
    if not map_path.is_file() or map_path.stat().st_size == 0:
        return fail(f"map missing/empty {map_path}")
    if not elf_path.is_file() or elf_path.stat().st_size == 0:
        return fail(f"elf missing/empty {elf_path}")

    if args.check_acceptance:
        defaults = Path(args.defaults) if args.defaults else WIFI_HIL_DEFAULTS
        for checker in (
            lambda: check_tls_profile_defaults(defaults),
            check_component_acceptance,
            check_source_fail_closed,
            check_tiered_allocator_source,
        ):
            err = checker()
            if err is not None:
                return err

    if args.sdkconfig:
        err = check_tls_profile_sdkconfig(Path(args.sdkconfig))
        if err is not None:
            return err
    if args.sdkconfig_h:
        err = check_tls_profile_sdkconfig_h(Path(args.sdkconfig_h))
        if err is not None:
            return err
    if args.size_json:
        err = check_size_json(Path(args.size_json))
        if err is not None:
            return err

    text = map_path.read_text(errors="replace")
    symbols = ESP_HIL_REQUIRED_SYMBOLS
    if args.expect_symbols:
        if not args.component_archive:
            return fail("--component-archive is mandatory with --expect-symbols")
        missing = [s for s in symbols if s not in text]
        if missing:
            return fail(f"missing symbols in map: {missing}")
        # Reject discarded map entries that only show address 0 (not retained).
        for s in symbols:
            live = False
            for line in text.splitlines():
                if s not in line:
                    continue
                # map lines typically: "0x42.... symbol" or " .text.symbol"
                if "0x0 " in line or line.strip().startswith("0x0\t"):
                    continue
                if "0x00000000" in line and s in line:
                    # still allow if another live line exists
                    continue
                if "0x" in line:
                    live = True
                    break
                if ".text." in line or ".literal." in line:
                    live = True
                    break
            if not live:
                print(
                    f"NOTE map is ambiguous for {s}; "
                    "defined/non-zero ELF nm proof is still mandatory"
                )
        print(f"OK symbols present (retained): {symbols}")

    if args.expect_export_symbol:
        if EXPORT_SYM not in text:
            return fail(
                f"map missing {EXPORT_SYM} "
                "(KEYING_MATERIAL_EXPORT must compile the real exporter)"
            )
        print(f"OK export symbol present: {EXPORT_SYM}")

    # Final-ELF authority: exact retained symbols and target sizeof are read from
    # the target toolchain's `nm -S`, never from a header or host build.
    try:
        nm = subprocess.run(
            [args.nm_tool, "-S", str(elf_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return fail(
            f"{args.nm_tool} is required; map/header-only evidence is not proof"
        )
    nm_out = nm.stdout + nm.stderr
    if nm.returncode != 0 or not nm_out.strip():
        return fail(f"{args.nm_tool} -S failed for {elf_path}: {nm_out.strip()}")
    nm_symbols = _parse_nm_sized_symbols(nm_out)

    if args.expect_symbols:
        for symbol in symbols:
            row = nm_symbols.get(symbol)
            if row is None or row[0] == 0 or row[2].upper() == "U":
                return fail(
                    f"ELF nm -S: symbol {symbol} missing, undefined, or discarded"
                )
        print("OK ELF nm -S: required symbols are exact, defined, and retained")

        component_archive = Path(args.component_archive)
        if (
            not component_archive.is_file()
            or component_archive.stat().st_size == 0
        ):
            return fail(f"component archive missing/empty {component_archive}")
        archive_nm = subprocess.run(
            [
                args.nm_tool,
                "-S",
                "--defined-only",
                str(component_archive),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        archive_nm_out = archive_nm.stdout + archive_nm.stderr
        if archive_nm.returncode != 0 or not archive_nm_out.strip():
            return fail(
                f"{args.nm_tool} -S --defined-only failed for "
                f"{component_archive}: {archive_nm_out.strip()}"
            )
        archive_symbols = _parse_nm_sized_symbols(archive_nm_out)
        missing_component_symbols = [
            symbol
            for symbol in ESP_COMPONENT_REQUIRED_SYMBOLS
            if not _archive_symbol_is_defined(archive_symbols, symbol)
        ]
        if missing_component_symbols:
            return fail(
                "ESP component archive symbols missing, undefined, or "
                f"zero-sized: {missing_component_symbols}"
            )
        print(
            "OK ESP component archive: component-only paths are exact and "
            f"defined: {ESP_COMPONENT_REQUIRED_SYMBOLS}"
        )
        missing_profile_probe_symbols = [
            symbol
            for symbol in ESP_MBEDTLS_PROFILE_PROBE_SYMBOLS
            if not _archive_symbol_is_defined(archive_symbols, symbol)
        ]
        if missing_profile_probe_symbols:
            return fail(
                "ESP mbedTLS target profile probe symbols missing, undefined, "
                f"or zero-sized: {missing_profile_probe_symbols}"
            )
        print(
            "OK ESP mbedTLS target profile probe: exact record-buffer sizes "
            "compiled against pinned SDK/config"
        )
        try:
            archive_ar = subprocess.run(
                [args.ar_tool, "t", str(component_archive)],
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            return fail(
                f"{args.ar_tool} is required; component member exclusion "
                "cannot be inferred from final-link garbage collection"
            )
        archive_ar_out = archive_ar.stdout + archive_ar.stderr
        if archive_ar.returncode != 0 or not archive_ar_out.strip():
            return fail(
                f"{args.ar_tool} t failed for {component_archive}: "
                f"{archive_ar_out.strip()}"
            )
        component_members = [
            line.strip()
            for line in archive_ar.stdout.splitlines()
            if line.strip()
        ]
        member_errors = _component_member_errors(component_members)
        if member_errors:
            return fail("; ".join(member_errors))
        print(
            "OK ESP component members: production closure present="
            f"{len(ESP_COMPONENT_REQUIRED_MEMBERS)} Host-only present=0"
        )

    if args.expect_export_symbol:
        row = nm_symbols.get(EXPORT_SYM)
        if row is None or row[0] == 0 or row[2].upper() == "U":
            return fail(
                f"ELF nm -S: {EXPORT_SYM} is not defined and retained"
            )
        print(f"OK ELF nm -S export symbol retained: {EXPORT_SYM}")

    measured_owner_bytes = _target_owner_size(
        nm_symbols, args.owner_size_symbol
    )
    if measured_owner_bytes is None:
        return fail(
            f"ELF nm -S: target owner-size probe {args.owner_size_symbol} "
            "missing, zero-sized, or discarded"
        )
    if measured_owner_bytes > args.max_owner_bytes:
        return fail(
            f"target-ELF owner {measured_owner_bytes} > "
            f"{args.max_owner_bytes} (12KiB contract)"
        )
    print(
        f"OK target-ELF owner workspace {measured_owner_bytes} "
        f"<= {args.max_owner_bytes}"
    )

    if args.expect_symbols:
        for symbol, expected_size in ESP_TARGET_EXACT_PROBE_SIZES.items():
            measured_size = _target_owner_size(nm_symbols, symbol)
            if measured_size != expected_size:
                return fail(
                    f"ELF nm -S: target probe {symbol} measured "
                    f"{measured_size!r}, expected {expected_size}"
                )
        print(
            "OK target-ELF R7 allocator ABI/charge probes exact "
            f"{ESP_TARGET_EXACT_PROBE_SIZES}"
        )

    if args.su_dir:
        su_dir = Path(args.su_dir)
        if not su_dir.is_dir():
            return fail(f"su-dir missing {su_dir}")
        found = 0
        for su in sorted(su_dir.glob("**/*.su")):
            for line in su.read_text(errors="replace").splitlines():
                parts = line.split("\t")
                if len(parts) >= 2 and parts[1].isdigit():
                    found += 1
                    stack = int(parts[1])
                    if stack > args.max_stack_bytes:
                        return fail(
                            f"{su} stack {stack} > {args.max_stack_bytes}"
                        )
        if found == 0:
            return fail("no .su frame entries found")
        print(f"OK su frames checked={found} ceiling={args.max_stack_bytes}")

    print("OK wifi_v1_esp_resource_gate")
    print("claim=wifi_r7_composition_target_software_candidate")
    print("r7_other_registered=IMPLEMENTED_PROPOSED")
    print("C7=RED C8=RED physical_hil=NOT_RUN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
