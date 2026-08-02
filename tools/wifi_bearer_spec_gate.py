#!/usr/bin/env python3
"""Independent Python gate for ADR-0018 Wi-Fi bearer candidate vectors.

Does not import the vector generator or production Ninlil code.
Every acceptance ID has a hard-coded semantic contract; assertions do not
derive expected outcomes solely from mutable vector fields. An executed
ledger is marked only after each ID's assertions pass.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "spec/vectors/wifi-bearer-spec-v1.json"

# Closed inventory — order is normative for required_acceptance_ids.
REQUIRED_ACCEPTANCE_IDS: tuple[str, ...] = (
    "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE",
    "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE",
    "WIFI-ASSOC-SAME-SSID-CHANNEL-CHANGE-FENCE",
    "WIFI-ASSOC-PROFILE-DIGEST-CHANGE-FENCE",
    "WIFI-ASSOC-SAME-TUPLE-NO-EPOCH",
    "WIFI-ASSOC-SESSION-FENCE-AVAILABILITY-PLUS-ONE",
    "WIFI-LIVENESS-KEEPALIVE-EXCLUSIVE-TIMER",
    "WIFI-LIVENESS-MISSED-RESPONSE-THRESHOLD",
    "WIFI-LIVENESS-BLACKHOLE-DETECTION",
    "WIFI-LIVENESS-TCP-HALF-OPEN",
    "WIFI-LIVENESS-AP-DEAD-BACKHAUL",
    "WIFI-LIVENESS-AVAILABILITY-EPOCH-CHANGE",
    "WIFI-NETCRED-FULL-OLD",
    "WIFI-NETCRED-FULL-NEW",
    "WIFI-NETCRED-FULL-ABSENT",
    "WIFI-NETCRED-FULL-BOTH",
    "WIFI-NETCRED-PARTIAL",
    "WIFI-NETCRED-EXTRA",
    "WIFI-NETCRED-THIRD",
    "WIFI-NETCRED-DUPLICATE-KEY",
    "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY",
    "WIFI-NETCRED-ROLLBACK-REJECT",
    "WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT",
    "WIFI-NETCRED-NO-PLAINTEXT-SECRET",
    "WIFI-ENDPOINT-IPV4-SCOPE",
    "WIFI-ENDPOINT-IPV6-SCOPE",
    "WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID",
    "WIFI-ENDPOINT-DNS-MDNS-NON-AUTHORITY",
    "WIFI-ENDPOINT-ADDRESS-CHANGE-FENCE",
    "WIFI-NWB1-HEADER-40",
    "WIFI-NWB1-PAYLOAD-586-REJECT",
    "WIFI-NWB1-PAYLOAD-587-ACCEPT",
    "WIFI-NWB1-PAYLOAD-1925-ACCEPT",
    "WIFI-NWB1-PAYLOAD-1926-REJECT",
    "WIFI-NWB1-TOTAL-626-REJECT",
    "WIFI-NWB1-TOTAL-627-ACCEPT",
    "WIFI-NWB1-TOTAL-1965-ACCEPT",
    "WIFI-NWB1-TOTAL-1966-REJECT",
    "WIFI-NWB1-CRC32C-INDEPENDENT",
    "WIFI-NWB1-PARTIAL-HEADER",
    "WIFI-NWB1-PARTIAL-BODY",
    "WIFI-NWB1-COALESCED-RECORDS",
    "WIFI-NWB1-READ-AHEAD-BOUND",
    "WIFI-NWB1-WRONG-SESSION",
    "WIFI-NWB1-SEQUENCE-0",
    "WIFI-NWB1-SEQUENCE-MAX-MINUS-ONE",
    "WIFI-NWB1-SEQUENCE-UINT32-MAX-REJECT",
    "WIFI-NWB1-DUPLICATE",
    "WIFI-NWB1-GAP",
    "WIFI-NWB1-OUT-OF-ORDER",
    "WIFI-NWB1-WRAP-REJECT",
    "WIFI-NWB1-INVALID-NFL1",
    "WIFI-TLS-SUITE-GROUP-SIGNATURE-EXACT",
    "WIFI-TLS-X509-ROLE-RUNTIME-ATTACHMENT",
    "WIFI-TLS-EXPORTER-PEER-CONTEXT-62",
    "WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64",
    "WIFI-TLS-AUTHORITY-ALL-ZERO-GROUP",
    "WIFI-TLS-AUTHORITY-MIXED-REJECT",
    "WIFI-TLS-TICKET-0RTT-RENEGOTIATION-FENCE",
    "WIFI-TLS-REVOCATION-CLOCK-RULES",
    "WIFI-TLS-R7-OPENSSL-GENERIC-NON-AUTHORITY",
    "WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY",
    "WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY",
    "WIFI-PREATTACH-CARRIER-NOT-NWB1",
    "WIFI-PREATTACH-PEER-SESSION-ONLY-NO-NWB1",
    "WIFI-PREATTACH-NWB1-REQUIRES-PA-FULL",
    "WIFI-RESOURCE-ESP-CAPACITY",
    "WIFI-RESOURCE-HOST-CAPACITY",
    "WIFI-RESOURCE-PRIORITY-ISOLATION",
    "WIFI-RESOURCE-RETAINED-TOKEN-PARTIAL-WRITE",
    "WIFI-RESOURCE-RELEASE-SEMANTICS",
    "WIFI-RESOURCE-NO-FALSE-CUSTODY",
    "WIFI-RESOURCE-STORAGE-ARITHMETIC",
    "WIFI-ROLE-HOST-POSIX-TCP-TLS",
    "WIFI-ROLE-ESP32S3-STA-LWIP-MBEDTLS",
    "WIFI-RACE-DISCONNECT-RECONNECT",
    "WIFI-RACE-SLEEP-DRAIN",
    "WIFI-RACE-EVENT-OVERFLOW",
    "WIFI-BACKOFF-DETERMINISTIC",
)

VECTOR_GROUPS = (
    "association_authority_vectors",
    "liveness_vectors",
    "network_credential_rotation_vectors",
    "endpoint_vectors",
    "nwb1_vectors",
    "tls_profile_vectors",
    "preattachment_boundary_vectors",
    "resource_queue_vectors",
    "role_responsibility_vectors",
    "race_backoff_vectors",
)

# Independent normative pins (not taken from mutable vector trust alone).
PIN_HOST_OPENSSL_TAG = "openssl-3.5.7"
PIN_HOST_OPENSSL_PEELED = "8cf17aaeb4599f8af87fefd810b5b5fee90fe69e"
PIN_ESP_IDF = "2c211b236707889e8400c4dc5644dd5c4ee071e0"
PIN_ESP_MBEDTLS = "ffb280bb63c78bfec1e1ab55040671768c85c923"
PIN_TLS_SUITE_ID = 0x1301
PIN_TLS_GROUP_ID = 0x0017
PIN_TLS_SIG_ID = 0x0403
PIN_KEEPALIVE_MS = 15000
PIN_MISSED = 3
PIN_BLACKHOLE_MS = 45000
PIN_NWB_HEADER = 40
PIN_PAYLOAD_MIN = 587
PIN_PAYLOAD_MAX = 1925
PIN_TOTAL_MIN = 627
PIN_TOTAL_MAX = 1965
PIN_PEER_CTX = 62
PIN_ATTACHED_CTX = 64
PIN_NWD1_RECORD = 160
PIN_NWD1_KEYS = 8
PIN_COMMITTED_CU = 1280
PIN_STAGING_CU = 2560
PIN_ESP_EVENT_Q = 8
PIN_BACKOFF = (1000, 2000, 4000, 8000, 16000, 32000)
PIN_ASSOC_TAG = b"NINLIL-WIFI-ASSOC-AUTHORITY-V1"
PIN_NWD1_COMPLETE_TAG = b"NINLIL-WIFI-NWD1-COMPLETE-V1"
PIN_NWD1_AUTH_TAG = b"NINLIL-WIFI-NWD1-AUTH-V1"
PIN_NFL1_HEADER = 584
PIN_NFL1_VERSION = 1
ASSOC_INPUT_LEN = 80
PIN_ACCEPTANCE_ID_COUNT = 79
PIN_SESSION_LIFETIME_MS = 3_600_000
PIN_KEEPALIVE_EXCLUSIVE_DEADLINE_MS = 15000
PIN_RECORD_BYTES_FIXED = 1965
PIN_ESP_TLS_SESSION_TOTAL = 98_304
PIN_ESP_TLS_SESSION_INTERNAL = 12_288
PIN_ESP_TLS_SESSION_PSRAM = 86_016
PIN_ESP_TLS_CRYPTO_GLOBAL_INTERNAL = 65_536
PIN_ESP_TLS_INTERNAL_FLOOR = 65_536
PIN_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT = 327_680
PIN_ESP_TLS_EXECUTION_STACK = 8_192
PIN_ESP_TLS_INTERNAL_ENVELOPE = 163_840
PIN_ESP_TLS_MAP_REMAINDER_OBS = 171_825
PIN_ESP_TLS_MAP_SLACK_OBS = 7_985
PIN_ESP_TLS_IN_BUFFER = 16_685
PIN_ESP_TLS_OUT_BUFFER = 4_415
PIN_NETWORK_NAMESPACE = "ninlil.wifi.network.v1"
PIN_ASSOC_TAG_ASCII = "NINLIL-WIFI-ASSOC-AUTHORITY-V1"
# Exact all-machine-field model: canonical JSON (indent=2, sort_keys, trailing NL).
PIN_VECTOR_DOCUMENT_SHA256 = (
    "38d8050206d8de832dfe9395f6f39b99e1119eb06fa60ee2112af2cd375b25ff"
)
# Descriptive-only fields that may differ without machine authority impact.
# Empty for wifi-bearer-spec-v1 — every scalar is machine-normative.
DESCRIPTIVE_SCALAR_ALLOWLIST: frozenset[str] = frozenset()
PIN_NONCLAIMS = (
    "SPEC_ACCEPTED",
    "implementation",
    "HIL",
    "RELEASE_SUPPORTED",
    "public_API",
    "production_support",
    "target_execution",
    "P0_closure",
    "independent_review_GO",
)
PIN_PASSWORD_SUBSTRINGS = ("hunter2", "p@ssw0rd", "correct-horse-battery")
# Independent NWD1 KAT hardpins (literal; not learned from mutable vector trust).
PIN_NWD1_KAT_VALUE_HEX = (
    "4e57443100010080000000a00102030405060708090a0b0c0d0e0f10"
    "0000000000000007"
    "3030303030303030303030303030303030303030303030303030303030303030"
    "1112131415161718191a1b1c1d1e1f20"
    "0e4b41542d4e5744312d4649584544"
    "000000000000000000000000000000000000"
    "010b01aabbccddeeff0000"
    "4040404040404040404040404040404040404040404040404040404040404040"
)
PIN_NWD1_KAT_HEADER_CRC = 0xE1A712FA
PIN_NWD1_KAT_AUTH_HEX = (
    "147db4b100c073732c8a837f88cd9e3b2600f2c1cb5f64b237e91bf234c45f04"
)
PIN_NWD1_KAT_COMPLETE_HEX = (
    "479d037f00eac79ab4c4b14f91d60b7d7b50830e4bfb82c47ed1acad828cb744"
)
# Hard-pinned source metadata / tool paths (existence + coherent drift reject).
PIN_SCHEMA = "ninlil.wifi.bearer.spec.v1"
PIN_STATUS = "PROPOSED_CANDIDATE_NOT_SPEC_ACCEPTED"
PIN_ADR = "docs/adr/0018-wifi-bearer.md"
PIN_GENERATOR = "tools/wifi_bearer_spec_vector_gen.py"
PIN_GATE_PY = "tools/wifi_bearer_spec_gate.py"
PIN_GATE_MJS = "tools/wifi_bearer_spec_gate.mjs"
PIN_VECTOR = "spec/vectors/wifi-bearer-spec-v1.json"
PIN_C_TEST = "tests/transport/wifi_bearer_spec_vector_test.c"
PIN_TOOL_PATHS = (
    PIN_ADR,
    PIN_GENERATOR,
    PIN_GATE_PY,
    PIN_GATE_MJS,
    PIN_VECTOR,
    PIN_C_TEST,
)
CLOSED_COMMIT_SET = (
    "OLD",
    "NEW",
    "BOTH",
    "PARTIAL",
    "EXTRA",
    "THIRD",
    "ABSENT",
    "CORRUPT",
)
# Closed top-level document keys (unknown keys rejected).
CLOSED_ROOT_KEYS = frozenset(
    {
        "acceptance_id_count",
        "acceptance_ids_emitted",
        "adr",
        "association_authority_vectors",
        "constants",
        "endpoint_vectors",
        "generator",
        "liveness_vectors",
        "network_credential_rotation_vectors",
        "nonclaims",
        "nwb1_vectors",
        "pins",
        "preattachment_boundary_vectors",
        "race_backoff_vectors",
        "required_acceptance_ids",
        "resource_queue_vectors",
        "role_responsibility_vectors",
        "schema",
        "source_vector_restoration",
        "status",
        "storage_arithmetic",
        "tls_profile_vectors",
    }
)
CLOSED_CONSTANTS_KEYS = frozenset(
    {
        "attached_context_bytes",
        "blackhole_detect_ms",
        "esp_tls_crypto_dma_bytes",
        "esp_tls_crypto_global_internal_bytes",
        "esp_tls_canary_corruption_is_global_fatal",
        "esp_tls_contract_null_spill_allowed",
        "esp_tls_cross_owner_free_allowed",
        "esp_tls_execution_stack_bytes",
        "esp_tls_generic_spill_allowed",
        "esp_tls_in_buffer_bytes",
        "esp_tls_map_observation_slack_bytes",
        "esp_tls_map_remainder_observation_bytes",
        "esp_tls_out_buffer_bytes",
        "esp_tls_ordinary_oom_is_global_fatal",
        "esp_tls_post_admission_internal_floor_bytes",
        "esp_tls_original_internal_only_requirement_bytes",
        "esp_tls_psram_exact_live_allocation_required",
        "esp_tls_psram_free_pointer_allowed",
        "esp_tls_psram_interior_pointer_allowed",
        "esp_tls_psram_required",
        "esp_tls_psram_wrong_size_allowed",
        "esp_tls_session_internal_bytes",
        "esp_tls_session_psram_bytes",
        "esp_tls_session_total_bytes",
        "esp_tls_two_session_internal_envelope_bytes",
        "keepalive_exclusive_deadline_ms",
        "keepalive_interval_ms",
        "missed_response_threshold",
        "network_namespace",
        "nwb1_header_bytes",
        "nwb1_payload_max",
        "nwb1_payload_min",
        "nwb1_payload_reject_high",
        "nwb1_payload_reject_low",
        "nwb1_total_max",
        "nwb1_total_min",
        "nwb1_total_reject_high",
        "nwb1_total_reject_low",
        "nwd1_committed_cu_bytes",
        "nwd1_record_bytes",
        "nwd1_staging_cu_bytes",
        "peer_context_bytes",
        "record_bytes_fixed",
        "session_lifetime_ms",
        "tls_ciphersuite_id",
        "tls_group_id",
        "tls_signature_id",
    }
)
CLOSED_PINS_KEYS = frozenset(
    {
        "assoc_authority_a_hex",
        "assoc_authority_input_a_hex",
        "assoc_authority_tag_ascii",
        "attached_context_sha256_hex",
        "esp_idf_commit",
        "esp_mbedtls_commit",
        "host_openssl_peeled",
        "host_openssl_tag",
        "instance_id_hex",
        "network_profile_digest_a_hex",
        "nfl1_header_bytes",
        "nfl1_version",
        "nwb1_max_record_sha256_hex",
        "nwb1_min_record_sha256_hex",
        "nwd1_new_complete_sha256_hex",
        "nwd1_old_complete_sha256_hex",
        "peer_context_sha256_hex",
        "session_id_hex",
    }
)
CLOSED_STORAGE_KEYS = frozenset(
    {
        "committed_cu_bytes",
        "committed_formula",
        "esp_nwd1_active_profiles_max",
        "host_nwd1_active_profiles_max",
        "nwd1_keys_max",
        "nwd1_record_bytes",
        "plaintext_password_in_storage",
        "plaintext_password_in_vectors",
        "secret_ref_digest_only",
        "staging_cu_bytes",
        "staging_formula",
    }
)
CLOSED_RESTORATION_KEYS = frozenset(
    {
        "absent_row_id",
        "acceptance_id_count",
        "adr",
        "c_test",
        "commit_unknown_includes_corrupt",
        "digest_leaf_count",
        "digest_leaf_paths_sha256_hex",
        "duplicate_expected_sequence_rule",
        "gate_mjs",
        "gate_py",
        "generator",
        "independent_nwd1_kat_auth_digest_hex",
        "independent_nwd1_kat_complete_digest_hex",
        "independent_nwd1_kat_header_crc32c",
        "independent_nwd1_kat_value_hex",
        "integer_leaf_count",
        "integer_leaf_paths_sha256_hex",
        "nwb1_max_total",
        "nwb1_min_total",
        "object_path_count",
        "release_before_terminal_forbidden",
        "schema",
        "string_leaf_count",
        "string_leaf_paths_sha256_hex",
        "tool_paths",
        "vector",
    }
)
# Hard-pinned leaf inventories (recomputed after restoration inventory fields).
# Regenerated by generator --write; gates reject drift. Updated by sync script.
PIN_OBJECT_PATH_COUNT = 117
PIN_INTEGER_LEAF_COUNT = 386
PIN_STRING_LEAF_COUNT = 692
PIN_DIGEST_LEAF_COUNT = 96
PIN_INTEGER_LEAF_PATHS_SHA256 = (
    "2f3294d2c15bd5f670c4e770dc1b9523974fc27bd462168eb015b399576082bb"
)
PIN_STRING_LEAF_PATHS_SHA256 = (
    "7014fc9b3e73e0b74223c85f039f15d27e87e8478d899def03f0830133de1ece"
)
PIN_DIGEST_LEAF_PATHS_SHA256 = (
    "f874aa983793212f5f0ef07422d0338d558f08e27e13c00262fb1ab89fa05da0"
)
CLOSED_ON_LIVENESS_FAIL = frozenset(
    {
        "availability_epoch_delta",
        "connection_close",
        "double_add_forbidden",
        "nwb1_delivery",
        "session_fence",
    }
)
CLOSED_NWD1_ITEM = frozenset(
    {
        "auth_digest_hex",
        "complete_digest_hex",
        "header_crc32c",
        "key_hex",
        "value_hex",
    }
)
CLOSED_SAMPLE = frozenset(
    {
        "backoff_ms",
        "failure_generation",
        "jitter_ms",
        "not_before_offset_ms",
    }
)
FORBIDDEN_KEYS = frozenset({"authority_override"})
DISCONNECT_ORDER = (
    "DISCONNECT_EVENT",
    "FENCE_SESSIONS",
    "AVAILABILITY_PLUS_ONE",
    "CLOSE_SOCKETS",
    "BACKOFF_NOT_BEFORE",
    "RECONNECT_ATTEMPT",
)


class GateError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GateError(message)


def hx(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        fail(f"{field}: non-even hex")
    if value.lower() != value or any(c not in "0123456789abcdef" for c in value):
        fail(f"{field}: non-canonical hex")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise GateError(f"{field}: invalid hex") from error


def exact_int(value: Any, field: str) -> int:
    """Reject bool and non-int coercions (bool is a subclass of int in Python)."""
    if type(value) is not int:
        fail(f"{field}: expected exact int, got {type(value).__name__}")
    return value


def sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def u16(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 2], "big")


def u32(buf: bytes, offset: int) -> int:
    return int.from_bytes(buf[offset : offset + 4], "big")


def load_json_strict(path: Path) -> dict[str, Any]:
    """Parse JSON rejecting duplicate object keys (last-wins is forbidden)."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                fail(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    try:
        text = path.read_text(encoding="utf-8")
        document = json.loads(text, object_pairs_hook=object_pairs)
    except json.JSONDecodeError as error:
        raise GateError(f"json: {error}") from error
    if not isinstance(document, dict):
        fail("root object")
    return document


def classify_nfl1_structural(packet: bytes) -> str:
    """Independent full structural NFL1 validation (not magic-only)."""
    if len(packet) < PIN_NFL1_HEADER:
        return "INVALID_NFL1"
    if packet[0:4] != b"NFL1":
        return "INVALID_NFL1"
    version = u16(packet, 4)
    header_length = u16(packet, 6)
    total_length = u32(packet, 8)
    stored_crc = u32(packet, 12)
    if header_length != PIN_NFL1_HEADER or total_length != len(packet):
        return "INVALID_NFL1"
    if not (587 <= total_length <= 1925):
        return "INVALID_NFL1"
    if version != PIN_NFL1_VERSION:
        return "INVALID_NFL1"
    scratch = bytearray(packet)
    scratch[12:16] = bytes(4)
    if crc32c(bytes(scratch)) != stored_crc:
        return "INVALID_NFL1"
    ns_len = u16(packet, 570)
    svc_len = u16(packet, 572)
    schema_len = u16(packet, 574)
    payload_len = u32(packet, 576)
    evidence_len = u32(packet, 580)
    if ns_len > 63 or svc_len > 63 or schema_len > 63:
        return "INVALID_NFL1"
    if (
        PIN_NFL1_HEADER + ns_len + svc_len + schema_len + payload_len + evidence_len
        != total_length
    ):
        return "INVALID_NFL1"
    if u32(packet, 20) & 0xFFFF0000:
        return "INVALID_NFL1"
    return "OK"


def classify_nwb1(
    record: bytes,
    *,
    expected_session: bytes | None = None,
    expected_sequence: int | None = None,
) -> str:
    if len(record) < 40 or record[0:4] != b"NWB1":
        return "CORRUPT"
    version = u16(record, 4)
    header_length = u16(record, 6)
    total_length = u32(record, 8)
    payload_length = u32(record, 12)
    session_id = record[16:32]
    sequence = u32(record, 32)
    stored_crc = u32(record, 36)
    if header_length != 40:
        return "CORRUPT"
    if total_length != len(record) or payload_length != len(record) - 40:
        return "CORRUPT"
    if not (587 <= payload_length <= 1925):
        return "CORRUPT"
    if not (627 <= total_length <= 1965):
        return "CORRUPT"
    scratch = bytearray(record)
    scratch[36:40] = bytes(4)
    if crc32c(bytes(scratch)) != stored_crc:
        return "CORRUPT"
    if version > 1:
        return "UNSUPPORTED"
    if version != 1:
        return "CORRUPT"
    if not any(session_id):
        return "CORRUPT"
    if expected_session is not None and session_id != expected_session:
        return "WRONG_SESSION"
    if sequence == 0xFFFFFFFF:
        return "SEQUENCE_REJECT"
    if expected_sequence is not None and sequence != expected_sequence:
        return "SEQUENCE_REJECT"
    payload = record[40:]
    if classify_nfl1_structural(payload) != "OK":
        return "INVALID_NFL1"
    return "OK"


def validate_nwd1_record(record: bytes) -> str:
    if len(record) != 160:
        return "CORRUPT"
    if record[0:4] != b"NWD1":
        return "CORRUPT"
    if u16(record, 4) != 1 or u16(record, 6) != 128 or u32(record, 8) != 160:
        return "CORRUPT"
    if record[126:128] != bytes(2):
        return "CORRUPT"
    if not 1 <= record[84] <= 32:
        return "CORRUPT"
    if not any(record[12:28]):
        return "CORRUPT"
    if int.from_bytes(record[28:36], "big") == 0:
        return "CORRUPT"
    if not any(record[36:68]) or not any(record[68:84]) or not any(record[128:160]):
        return "CORRUPT"
    return "OK"


def nwd1_header_crc32c(record: bytes) -> int:
    return crc32c(record[0:128])


def nwd1_auth_digest(record: bytes) -> bytes:
    return sha(PIN_NWD1_AUTH_TAG + record[0:128] + record[128:160])


def nwd1_complete_digest(record: bytes) -> bytes:
    return sha(PIN_NWD1_COMPLETE_TAG + record)


def verify_nwd1_authority_row(item: dict[str, Any], field: str) -> bytes:
    """Recompute CRC/auth/complete and bind to emitted authority fields."""
    value = hx(item["value_hex"], f"{field}.value")
    if validate_nwd1_record(value) != "OK":
        fail(f"{field}: nwd1 framing")
    header_crc = exact_int(item.get("header_crc32c"), f"{field}.header_crc32c")
    require(header_crc == nwd1_header_crc32c(value), f"{field}: header crc")
    require(
        hx(item["auth_digest_hex"], f"{field}.auth") == nwd1_auth_digest(value),
        f"{field}: auth digest",
    )
    require(
        hx(item["complete_digest_hex"], f"{field}.complete")
        == nwd1_complete_digest(value),
        f"{field}: complete digest",
    )
    return value


def classify_commit_unknown(
    old_rows: list[tuple[bytes, bytes]],
    new_rows: list[tuple[bytes, bytes]],
    observed_rows: list[tuple[bytes, bytes]],
) -> str:
    def as_map(rows: list[tuple[bytes, bytes]]) -> dict[bytes, bytes] | None:
        out: dict[bytes, bytes] = {}
        for key, value in rows:
            if key in out:
                return None
            if validate_nwd1_record(value) != "OK":
                return None
            out[key] = value
        return out

    old_map = as_map(old_rows)
    new_map = as_map(new_rows)
    obs_map = as_map(observed_rows)
    if old_map is None or new_map is None or obs_map is None:
        return "CORRUPT"
    old_keys = set(old_map)
    new_keys = set(new_map)
    obs_keys = set(obs_map)
    if not old_keys and not obs_keys and new_keys:
        return "ABSENT"
    if obs_map == old_map and old_keys:
        return "OLD"
    if obs_map == new_map and new_keys:
        return "NEW"
    if (
        old_keys
        and new_keys
        and old_map != new_map
        and old_keys.isdisjoint(new_keys)
        and old_keys <= obs_keys
        and new_keys <= obs_keys
        and all(obs_map[k] == old_map[k] for k in old_keys)
        and all(obs_map[k] == new_map[k] for k in new_keys)
    ):
        return "BOTH"
    if obs_keys and obs_keys < new_keys and all(
        obs_map[k] == new_map[k] for k in obs_keys
    ):
        return "PARTIAL"
    if new_keys and new_keys < obs_keys and all(
        obs_map[k] == new_map[k] for k in new_keys
    ):
        return "EXTRA"
    return "THIRD"


def parse_assoc_input(canonical: bytes) -> dict[str, Any]:
    if len(canonical) != ASSOC_INPUT_LEN:
        fail("assoc input length")
    return {
        "profile_id": canonical[0:16],
        "association_epoch": int.from_bytes(canonical[16:24], "big"),
        "profile_digest": canonical[24:56],
        "binding_id": canonical[56:72],
        "bssid": canonical[72:78],
        "channel": canonical[78],
        "auth_mode": canonical[79],
    }


def verify_assoc_digest(row: dict[str, Any], digest_field: str, input_field: str) -> None:
    """Recompute association digest with hard-coded tag domain + full field bind.

    old_/new_ prefixes are fully bound to the matching canonical input. Mutating
    only a surface field (e.g. old_bssid_hex) without the input must fail.
    """
    if input_field not in row or digest_field not in row:
        fail(f"missing assoc fields {input_field}/{digest_field}")
    ain = hx(row[input_field], input_field)
    digest = hx(row[digest_field], digest_field)
    recomputed = sha(PIN_ASSOC_TAG + ain)
    require(recomputed == digest, f"assoc digest tag domain {digest_field}")
    require(
        sha(b"NINLIL-WIFI-ASSOC-AUTHORITY-X1" + ain) != digest,
        "wrong assoc tag collision",
    )
    parsed = parse_assoc_input(ain)
    if input_field.startswith("old_"):
        prefix = "old_"
    elif input_field.startswith("new_"):
        prefix = "new_"
    else:
        prefix = ""

    def bind_hex(field: str, expected: bytes) -> None:
        key = f"{prefix}{field}" if prefix else field
        if prefix:
            if key not in row:
                fail(f"missing required assoc bind field {key}")
            require(row[key] == expected.hex(), f"{key} bind")
        elif key in row:
            require(row[key] == expected.hex(), f"{key} bind")

    def bind_int(field: str, expected: int) -> None:
        key = f"{prefix}{field}" if prefix else field
        if prefix:
            if key not in row:
                fail(f"missing required assoc bind field {key}")
            require(exact_int(row[key], key) == expected, f"{key} bind")
        elif key in row:
            require(exact_int(row[key], key) == expected, f"{key} bind")

    bind_hex("profile_id_hex", parsed["profile_id"])
    bind_int("association_epoch", parsed["association_epoch"])
    # profile_revision is the same u64 as association_epoch when present.
    rev_key = f"{prefix}profile_revision" if prefix else "profile_revision"
    if rev_key in row:
        require(
            exact_int(row[rev_key], rev_key) == parsed["association_epoch"],
            f"{rev_key} bind",
        )
    bind_hex("profile_digest_hex", parsed["profile_digest"])
    bind_hex("binding_id_hex", parsed["binding_id"])
    bind_hex("bssid_hex", parsed["bssid"])
    bind_int("channel", parsed["channel"])
    bind_int("auth_mode", parsed["auth_mode"])
    # Unprefixed baseline also binds profile_id / channel when present.
    if not prefix:
        if "profile_id_hex" in row:
            require(
                row["profile_id_hex"] == parsed["profile_id"].hex(), "profile_id bind"
            )
        if "channel" in row:
            require(exact_int(row["channel"], "channel") == parsed["channel"], "ch")
        if "bssid_hex" in row:
            require(row["bssid_hex"] == parsed["bssid"].hex(), "bssid")
        if "association_epoch" in row:
            require(
                exact_int(row["association_epoch"], "association_epoch")
                == parsed["association_epoch"],
                "epoch",
            )
        if "auth_mode" in row:
            require(exact_int(row["auth_mode"], "auth_mode") == parsed["auth_mode"], "auth")
        if "profile_digest_hex" in row:
            require(
                row["profile_digest_hex"] == parsed["profile_digest"].hex(),
                "profile digest",
            )
        if "binding_id_hex" in row:
            require(
                row["binding_id_hex"] == parsed["binding_id"].hex(), "binding"
            )


def _assert_exact_keys(obj: dict[str, Any], allowed: frozenset[str], path: str) -> None:
    if not isinstance(obj, dict):
        fail(f"{path}: object required")
    unknown = set(obj.keys()) - allowed
    missing_forbidden = FORBIDDEN_KEYS & set(obj.keys())
    if missing_forbidden:
        fail(f"{path}: forbidden keys {sorted(missing_forbidden)}")
    if unknown:
        fail(f"{path}: unknown keys {sorted(unknown)}")


def assert_closed_typed_tree(
    value: Any,
    path: str = "$",
    *,
    row_keys: frozenset[str] | None = None,
) -> None:
    """Recursive closed/typed walk: unknown keys, bool-as-int, authority_override.

    Normative machine authority uses 0/1 integers, never JSON booleans.
    Any bool leaf is rejected at every object path (not sample-only exact_int).
    """
    # bool is a subclass of int in Python — must be rejected before int.
    if isinstance(value, bool):
        fail(f"{path}: bool forbidden (normative integers are 0/1, not JSON bool)")
    if isinstance(value, int):
        return
    if isinstance(value, float):
        fail(f"{path}: float forbidden")
    if isinstance(value, str):
        return
    if value is None:
        fail(f"{path}: null forbidden")
    if isinstance(value, list):
        for index, item in enumerate(value):
            assert_closed_typed_tree(
                item, f"{path}[{index}]", row_keys=row_keys
            )
        return
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                fail(f"{path}: non-string key")
            if key in FORBIDDEN_KEYS:
                fail(f"{path}: forbidden key {key}")
        # Structural closed schemas for known nested objects.
        if path == "$.constants":
            _assert_exact_keys(value, CLOSED_CONSTANTS_KEYS, path)
        elif path == "$.pins":
            _assert_exact_keys(value, CLOSED_PINS_KEYS, path)
        elif path == "$.storage_arithmetic":
            _assert_exact_keys(value, CLOSED_STORAGE_KEYS, path)
        elif path == "$.source_vector_restoration":
            _assert_exact_keys(value, CLOSED_RESTORATION_KEYS, path)
        elif path.endswith(".on_liveness_fail"):
            _assert_exact_keys(value, CLOSED_ON_LIVENESS_FAIL, path)
        elif re_match_nwd1_item_path(path):
            _assert_exact_keys(value, CLOSED_NWD1_ITEM, path)
        elif re_match_sample_path(path):
            _assert_exact_keys(value, CLOSED_SAMPLE, path)
        elif row_keys is not None and is_vector_row_path(path):
            unknown = set(value.keys()) - row_keys
            if unknown:
                fail(f"{path}: unknown row keys {sorted(unknown)}")
            if FORBIDDEN_KEYS & set(value.keys()):
                fail(f"{path}: forbidden row key")
        for key, item in value.items():
            assert_closed_typed_tree(
                item, f"{path}.{key}", row_keys=row_keys
            )
        return
    fail(f"{path}: unsupported type {type(value).__name__}")


def assert_document_structure(document: dict[str, Any]) -> None:
    """Closed root + recursive closed/typed tree (shared by validate + exhaustive)."""
    if not isinstance(document, dict):
        fail("root object")
    unknown = set(document.keys()) - CLOSED_ROOT_KEYS
    require(not unknown, f"unknown root keys {sorted(unknown)}")
    if FORBIDDEN_KEYS & set(document.keys()):
        fail("forbidden root key")
    if "adr" in document:
        require(isinstance(document["adr"], str), "adr must be string path")
        require(
            document["adr"] is not True and document["adr"] is not False,
            "adr bool",
        )
    assert_closed_typed_tree(document, row_keys=CLOSED_ROW_KEYS)


def iter_object_paths(value: Any, path: str = "$") -> list[str]:
    """All object (dict) paths in document order — exhaustive unknown-key surface."""
    out: list[str] = []
    if isinstance(value, dict):
        out.append(path)
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            out.extend(iter_object_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(iter_object_paths(item, f"{path}[{index}]"))
    return out


def iter_integer_leaf_paths(value: Any, path: str = "$") -> list[str]:
    """All normative integer leaf paths (bool excluded — clean vector has none)."""
    out: list[str] = []
    if isinstance(value, bool):
        return out
    if isinstance(value, int):
        out.append(path)
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            out.extend(iter_integer_leaf_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(iter_integer_leaf_paths(item, f"{path}[{index}]"))
    return out


def _navigate_set(document: dict[str, Any], path: str, key: str, value: Any) -> None:
    """Set document[path][key]=value for path like $.a.b[0].c"""
    import re

    if not path.startswith("$"):
        fail(f"bad path {path}")
    cur: Any = document
    s = path[1:]
    i = 0
    segs: list[Any] = []
    while i < len(s):
        if s[i] == ".":
            i += 1
            m = re.match(r"([A-Za-z0-9_]+)", s[i:])
            if not m:
                fail(f"bad path segment {path}")
            segs.append(m.group(1))
            i += m.end()
        elif s[i] == "[":
            m = re.match(r"\[(\d+)\]", s[i:])
            if not m:
                fail(f"bad index {path}")
            segs.append(int(m.group(1)))
            i += m.end()
        else:
            fail(f"bad path char {path}")
    for seg in segs:
        cur = cur[seg]
    if not isinstance(cur, dict):
        fail(f"{path}: not object for set")
    cur[key] = value


def _navigate_assign_leaf(document: dict[str, Any], path: str, value: Any) -> None:
    """Assign leaf at path (last segment) to value."""
    import re

    if not path.startswith("$"):
        fail(f"bad path {path}")
    if path == "$":
        fail("cannot assign root")
    s = path[1:]
    i = 0
    segs: list[Any] = []
    while i < len(s):
        if s[i] == ".":
            i += 1
            m = re.match(r"([A-Za-z0-9_]+)", s[i:])
            if not m:
                fail(f"bad path segment {path}")
            segs.append(m.group(1))
            i += m.end()
        elif s[i] == "[":
            m = re.match(r"\[(\d+)\]", s[i:])
            if not m:
                fail(f"bad index {path}")
            segs.append(int(m.group(1)))
            i += m.end()
        else:
            fail(f"bad path char {path}")
    cur: Any = document
    for seg in segs[:-1]:
        cur = cur[seg]
    last = segs[-1]
    cur[last] = value


def iter_string_leaf_paths(value: Any, path: str = "$") -> list[str]:
    out: list[str] = []
    if isinstance(value, bool):
        return out
    if isinstance(value, str):
        out.append(path)
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            out.extend(iter_string_leaf_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(iter_string_leaf_paths(item, f"{path}[{index}]"))
    return out


def iter_digest_leaf_paths(value: Any, path: str = "$") -> list[str]:
    """Paths whose leaf name is *digest_hex or *sha256_hex."""
    out: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            if isinstance(item, str) and (
                key.endswith("digest_hex") or key.endswith("sha256_hex")
            ):
                out.append(child)
            out.extend(iter_digest_leaf_paths(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(iter_digest_leaf_paths(item, f"{path}[{index}]"))
    return out


def _paths_sha256(paths: list[str]) -> str:
    return hashlib.sha256(("\n".join(paths) + "\n").encode("utf-8")).hexdigest()


def assert_type_inventory(document: dict[str, Any]) -> None:
    """Reject int↔str type lies via hard-pinned path-set inventory."""
    objects = iter_object_paths(document)
    ints = sorted(iter_integer_leaf_paths(document))
    strs = sorted(iter_string_leaf_paths(document))
    digs = sorted(iter_digest_leaf_paths(document))
    require(len(objects) == PIN_OBJECT_PATH_COUNT, f"object_path_count {len(objects)}")
    require(len(ints) == PIN_INTEGER_LEAF_COUNT, f"integer_leaf_count {len(ints)}")
    require(len(strs) == PIN_STRING_LEAF_COUNT, f"string_leaf_count {len(strs)}")
    require(len(digs) == PIN_DIGEST_LEAF_COUNT, f"digest_leaf_count {len(digs)}")
    require(
        _paths_sha256(ints) == PIN_INTEGER_LEAF_PATHS_SHA256,
        "integer leaf paths sha",
    )
    require(
        _paths_sha256(strs) == PIN_STRING_LEAF_PATHS_SHA256,
        "string leaf paths sha",
    )
    require(
        _paths_sha256(digs) == PIN_DIGEST_LEAF_PATHS_SHA256,
        "digest leaf paths sha",
    )
    rest = document.get("source_vector_restoration") or {}
    require(exact_int(rest.get("object_path_count"), "opc") == PIN_OBJECT_PATH_COUNT, "rest opc")
    require(
        exact_int(rest.get("integer_leaf_count"), "ilc") == PIN_INTEGER_LEAF_COUNT,
        "rest ilc",
    )
    require(
        exact_int(rest.get("string_leaf_count"), "slc") == PIN_STRING_LEAF_COUNT,
        "rest slc",
    )
    require(
        exact_int(rest.get("digest_leaf_count"), "dlc") == PIN_DIGEST_LEAF_COUNT,
        "rest dlc",
    )
    require(
        rest.get("integer_leaf_paths_sha256_hex") == PIN_INTEGER_LEAF_PATHS_SHA256,
        "rest int sha",
    )
    require(
        rest.get("string_leaf_paths_sha256_hex") == PIN_STRING_LEAF_PATHS_SHA256,
        "rest str sha",
    )
    require(
        rest.get("digest_leaf_paths_sha256_hex") == PIN_DIGEST_LEAF_PATHS_SHA256,
        "rest dig sha",
    )


def assert_all_digest_preimages(document: dict[str, Any]) -> None:
    """Every *digest_hex/*sha256_hex field binds to an independent preimage recompute."""
    pins = document["pins"]
    # Global pins vs recomputed vector material.
    for group in VECTOR_GROUPS:
        for row in document[group]:
            if not isinstance(row, dict):
                continue
            rid = row.get("id", "?")
            # Association digests: covered by verify_assoc_digest when asserters run;
            # also bind here for exhaustive flip coverage independent of ID dispatch.
            for prefix in ("", "old_", "new_"):
                dig_f = f"{prefix}association_authority_digest_hex"
                in_f = f"{prefix}association_authority_input_hex"
                if dig_f in row and in_f in row:
                    ain = hx(row[in_f], in_f)
                    dig = hx(row[dig_f], dig_f)
                    require(sha(PIN_ASSOC_TAG + ain) == dig, f"{rid} {dig_f} preimage")
                    parsed = parse_assoc_input(ain)
                    # Full tuple surface fields bind to the same canonical preimage.
                    for field, expected in (
                        (f"{prefix}profile_id_hex", parsed["profile_id"].hex()),
                        (f"{prefix}profile_digest_hex", parsed["profile_digest"].hex()),
                        (f"{prefix}binding_id_hex", parsed["binding_id"].hex()),
                        (f"{prefix}bssid_hex", parsed["bssid"].hex()),
                    ):
                        if field in row:
                            require(row[field] == expected, f"{rid} {field} preimage bind")
                    if f"{prefix}association_epoch" in row:
                        require(
                            exact_int(row[f"{prefix}association_epoch"], "epoch")
                            == parsed["association_epoch"],
                            f"{rid} {prefix}epoch preimage bind",
                        )
                    if f"{prefix}channel" in row:
                        require(
                            exact_int(row[f"{prefix}channel"], "ch")
                            == parsed["channel"],
                            f"{rid} {prefix}channel preimage bind",
                        )
                    if f"{prefix}auth_mode" in row:
                        require(
                            exact_int(row[f"{prefix}auth_mode"], "auth")
                            == parsed["auth_mode"],
                            f"{rid} {prefix}auth preimage bind",
                        )
            # NWD1 value + auth/complete pairs (row-level old/new/observed/canonical...).
            pairs = (
                ("old_value_hex", "old_auth_digest_hex", "old_complete_digest_hex", "old_header_crc32c"),
                ("new_value_hex", "new_auth_digest_hex", "new_complete_digest_hex", "new_header_crc32c"),
                ("observed_value_hex", "observed_auth_digest_hex", "observed_complete_digest_hex", "observed_header_crc32c"),
                ("canonical_value_hex", None, "canonical_complete_digest_hex", None),
                ("conflicting_value_hex", None, "conflicting_complete_digest_hex", None),
                ("nwd1_kat_value_hex", "nwd1_kat_auth_digest_hex", "nwd1_kat_complete_digest_hex", "nwd1_kat_header_crc32c"),
            )
            for value_f, auth_f, complete_f, crc_f in pairs:
                if value_f not in row:
                    continue
                raw = hx(row[value_f], value_f)
                if complete_f and complete_f in row:
                    require(
                        nwd1_complete_digest(raw) == hx(row[complete_f], complete_f),
                        f"{rid} {complete_f} preimage",
                    )
                if auth_f and auth_f in row:
                    require(
                        nwd1_auth_digest(raw) == hx(row[auth_f], auth_f),
                        f"{rid} {auth_f} preimage",
                    )
                if crc_f and crc_f in row:
                    require(
                        nwd1_header_crc32c(raw) == exact_int(row[crc_f], crc_f),
                        f"{rid} {crc_f} preimage",
                    )
            if "secret_ref_digest_hex" in row and "old_value_hex" in row:
                old_v = hx(row["old_value_hex"], "old_value")
                require(len(old_v) == PIN_NWD1_RECORD, "secret_ref old len")
                require(
                    old_v[128:160] == hx(row["secret_ref_digest_hex"], "secret_ref"),
                    f"{rid} secret_ref preimage from old_value",
                )
            # Nested NWD1 row items
            for field in ("old_rows", "new_rows", "observed_rows"):
                for index, item in enumerate(row.get(field) or []):
                    if not isinstance(item, dict) or "value_hex" not in item:
                        continue
                    verify_nwd1_authority_row(item, f"{rid}.{field}[{index}]")
            # NWB1 record sha
            if "record_sha256_hex" in row and "record_hex" in row:
                require(
                    sha(hx(row["record_hex"], "record"))
                    == hx(row["record_sha256_hex"], "record_sha"),
                    f"{rid} record_sha preimage",
                )
            # TLS exporter context sha
            if "context_sha256_hex" in row and "context_hex" in row:
                require(
                    sha(hx(row["context_hex"], "ctx"))
                    == hx(row["context_sha256_hex"], "ctx_sha"),
                    f"{rid} context_sha preimage",
                )
            # digests_equal cross-field
            if "digests_equal" in row and "old_association_authority_digest_hex" in row:
                old_d = row["old_association_authority_digest_hex"]
                new_d = row["new_association_authority_digest_hex"]
                require(
                    exact_int(row["digests_equal"], "digests_equal")
                    == int(old_d == new_d),
                    f"{rid} digests_equal cross-field",
                )
            if "digests_equal" in row and "canonical_value_hex" in row:
                a = hx(row["canonical_value_hex"], "can")
                b = hx(row["conflicting_value_hex"], "conf")
                require(
                    exact_int(row["digests_equal"], "digests_equal") == int(a == b),
                    f"{rid} value digests_equal cross-field",
                )
    # Pins recomputed from vectors / independent material
    min_row = require_row(document, "WIFI-NWB1-PAYLOAD-587-ACCEPT")
    max_row = require_row(document, "WIFI-NWB1-PAYLOAD-1925-ACCEPT")
    require(
        sha(hx(min_row["record_hex"], "min"))
        == hx(pins["nwb1_min_record_sha256_hex"], "pin min"),
        "pin nwb1_min preimage",
    )
    require(
        sha(hx(max_row["record_hex"], "max"))
        == hx(pins["nwb1_max_record_sha256_hex"], "pin max"),
        "pin nwb1_max preimage",
    )
    peer = require_row(document, "WIFI-TLS-EXPORTER-PEER-CONTEXT-62")
    att = require_row(document, "WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64")
    require(
        sha(hx(peer["context_hex"], "peer"))
        == hx(pins["peer_context_sha256_hex"], "pin peer"),
        "pin peer preimage",
    )
    require(
        sha(hx(att["context_hex"], "att"))
        == hx(pins["attached_context_sha256_hex"], "pin att"),
        "pin attached preimage",
    )
    # NWD1 old/new complete pins
    old_nc = require_row(document, "WIFI-NETCRED-FULL-OLD")
    new_nc = require_row(document, "WIFI-NETCRED-FULL-NEW")
    old_val = hx(old_nc["observed_rows"][0]["value_hex"], "old obs")
    new_val = hx(new_nc["observed_rows"][0]["value_hex"], "new obs")
    require(
        nwd1_complete_digest(old_val)
        == hx(pins["nwd1_old_complete_sha256_hex"], "pin nwd1 old"),
        "pin nwd1_old complete",
    )
    require(
        nwd1_complete_digest(new_val)
        == hx(pins["nwd1_new_complete_sha256_hex"], "pin nwd1 new"),
        "pin nwd1_new complete",
    )
    # Assoc pin
    base = require_row(document, "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE")
    require(
        base["association_authority_digest_hex"] == pins["assoc_authority_a_hex"],
        "assoc pin digest",
    )
    require(
        base["association_authority_input_hex"] == pins["assoc_authority_input_a_hex"],
        "assoc pin input",
    )
    require(
        base["profile_digest_hex"] == pins["network_profile_digest_a_hex"],
        "profile digest pin",
    )
    # Restoration independent KAT digests
    rest = document["source_vector_restoration"]
    require(
        rest["independent_nwd1_kat_auth_digest_hex"] == PIN_NWD1_KAT_AUTH_HEX,
        "rest kat auth",
    )
    require(
        rest["independent_nwd1_kat_complete_digest_hex"] == PIN_NWD1_KAT_COMPLETE_HEX,
        "rest kat complete",
    )


def run_exhaustive_structure_self_test(document: dict[str, Any]) -> None:
    """Permanent counterexamples: unknown-key, bool-as-int, int↔str, digest preimage."""
    object_paths = iter_object_paths(document)
    int_leaves = iter_integer_leaf_paths(document)
    str_leaves = iter_string_leaf_paths(document)
    dig_leaves = iter_digest_leaf_paths(document)
    assert_document_structure(document)
    assert_type_inventory(document)
    assert_all_digest_preimages(document)

    unknown_accepted = 0
    for path in object_paths:
        candidate = copy.deepcopy(document)
        _navigate_set(candidate, path, "__audit_unknown__", 1)
        try:
            assert_document_structure(candidate)
            unknown_accepted += 1
        except (GateError, KeyError, TypeError, ValueError, AssertionError):
            pass
    if unknown_accepted != 0:
        fail(
            f"exhaustive unknown-key: accepted={unknown_accepted}/{len(object_paths)}"
        )

    bool_accepted = 0
    for path in int_leaves:
        candidate = copy.deepcopy(document)
        _navigate_assign_leaf(candidate, path, True)
        try:
            assert_document_structure(candidate)
            assert_type_inventory(candidate)
            bool_accepted += 1
        except (GateError, KeyError, TypeError, ValueError, AssertionError):
            pass
    if bool_accepted != 0:
        fail(f"exhaustive bool-as-int: accepted={bool_accepted}/{len(int_leaves)}")

    int_as_str_accepted = 0
    for path in int_leaves:
        candidate = copy.deepcopy(document)
        _navigate_assign_leaf(candidate, path, "0")
        try:
            assert_document_structure(candidate)
            assert_type_inventory(candidate)
            int_as_str_accepted += 1
        except (GateError, KeyError, TypeError, ValueError, AssertionError):
            pass
    if int_as_str_accepted != 0:
        fail(
            f"exhaustive int-as-str: accepted={int_as_str_accepted}/{len(int_leaves)}"
        )

    str_as_int_accepted = 0
    for path in str_leaves:
        candidate = copy.deepcopy(document)
        _navigate_assign_leaf(candidate, path, 0)
        try:
            assert_document_structure(candidate)
            assert_type_inventory(candidate)
            str_as_int_accepted += 1
        except (GateError, KeyError, TypeError, ValueError, AssertionError):
            pass
    if str_as_int_accepted != 0:
        fail(
            f"exhaustive str-as-int: accepted={str_as_int_accepted}/{len(str_leaves)}"
        )

    digest_flip_accepted = 0
    for path in dig_leaves:
        candidate = copy.deepcopy(document)
        # Flip first hex nibble; keep valid hex string type.
        def flip(v: str) -> str:
            return ("0" if v[0] != "0" else "1") + v[1:]

        cur_path = path
        # read current
        import re

        s = cur_path[1:]
        i = 0
        segs: list[Any] = []
        while i < len(s):
            if s[i] == ".":
                i += 1
                m = re.match(r"([A-Za-z0-9_]+)", s[i:])
                segs.append(m.group(1))  # type: ignore[union-attr]
                i += m.end()  # type: ignore[union-attr]
            elif s[i] == "[":
                m = re.match(r"\[(\d+)\]", s[i:])
                segs.append(int(m.group(1)))  # type: ignore[union-attr]
                i += m.end()  # type: ignore[union-attr]
        node: Any = candidate
        for seg in segs[:-1]:
            node = node[seg]
        node[segs[-1]] = flip(node[segs[-1]])
        try:
            assert_document_structure(candidate)
            assert_type_inventory(candidate)
            assert_all_digest_preimages(candidate)
            digest_flip_accepted += 1
        except (GateError, KeyError, TypeError, ValueError, AssertionError):
            pass
    if digest_flip_accepted != 0:
        fail(
            f"exhaustive digest-flip: accepted={digest_flip_accepted}/{len(dig_leaves)}"
        )

    print(
        "wifi bearer Python gate exhaustive structure: OK "
        f"object_paths={len(object_paths)} unknown_accepted=0 "
        f"integer_leaves={len(int_leaves)} bool_accepted=0 "
        f"int_as_str_accepted=0 string_leaves={len(str_leaves)} "
        f"str_as_int_accepted=0 digest_leaves={len(dig_leaves)} "
        f"digest_flip_accepted=0"
    )


def re_match_nwd1_item_path(path: str) -> bool:
    # Match leaf item paths: $.….old_rows[0] (not deeper fields).
    for field in ("old_rows", "new_rows", "observed_rows"):
        marker = f".{field}["
        if marker not in path:
            continue
        # path ends with .field[N]
        if path.rsplit(".", 1)[-1].startswith(f"{field}[") and path.endswith("]"):
            return True
    return False


def re_match_sample_path(path: str) -> bool:
    return path.rsplit(".", 1)[-1].startswith("samples[") and path.endswith("]")


def is_vector_row_path(path: str) -> bool:
    for group in VECTOR_GROUPS:
        # $.association_authority_vectors[0] only (not nested under the row).
        prefix = f"$.{group}["
        if path.startswith(prefix) and path.count("[") == 1 and path.endswith("]"):
            return True
    return False


CLOSED_ROW_KEYS = frozenset({
    "absent_example_classification",
    "active_binding_match",
    "adapter_kind",
    "adapter_max",
    "address_hex",
    "address_kind",
    "age_300000_ok",
    "age_300001_reject",
    "allowed_only_if_controllerless_profile_explicit",
    "application_publish",
    "association_authority_digest_hex",
    "association_authority_input_hex",
    "association_epoch",
    "attached_stable_reset_ms",
    "attachment_authority_match",
    "auth_mode",
    "authority_clock_only",
    "authority_endpoint_change_requires_config_revision",
    "availability",
    "availability_epoch_delta",
    "availability_epoch_delta_on_sleep",
    "bad_classification",
    "binding_id_hex",
    "binding_length",
    "blackhole_detect_ms",
    "both_example_classification",
    "bound_profile_rejects_all_zero",
    "bssid_hex",
    "buffer_bytes",
    "bulk_may_starve_critical",
    "bytes_available",
    "canonical_complete_digest_hex",
    "canonical_value_hex",
    "cap_ms",
    "channel",
    "ciphersuite",
    "ciphersuite_id",
    "classification",
    "classifications_allowed_on_reopen",
    "client_binding_hex",
    "client_role",
    "closed_classification_set",
    "committed_cu_bytes",
    "committed_formula",
    "condition",
    "conflicting_complete_digest_hex",
    "conflicting_value_hex",
    "connect_attempt_max",
    "connection_close",
    "context_hex",
    "context_length",
    "context_sha256_hex",
    "crc_init",
    "crc_polynomial",
    "crc_xorout",
    "create_result",
    "credential_provider_null_required",
    "credential_provider_required",
    "current_revision",
    "deliverable",
    "delivery",
    "depends_on_m4_full",
    "digests_equal",
    "direct_mbedtls_only",
    "dns_authority",
    "dns_name",
    "double_count_forbidden",
    "drain_blocks_new_send_retention",
    "duplicate_old_key_classification",
    "early_data_bytes_publish",
    "emit_forbidden",
    "entropy_forbidden",
    "esp_idf_commit",
    "esp_nwd1_active_profiles_max",
    "esp_tls_public_api_forbidden",
    "event",
    "event_queue_max",
    "event_queue_overflow_at",
    "exclusive_deadline_ms",
    "expected",
    "expected_bad",
    "expected_class",
    "expected_classification",
    "expected_duplicate_old_key_classification",
    "expected_first",
    "expected_good",
    "expected_length",
    "expected_observed_complete_digests",
    "expected_second",
    "expected_sequence",
    "expected_session_hex",
    "fabric_availability",
    "fabric_cap_custody_advertised",
    "fake_available_while_asleep",
    "first_classification",
    "first_sequence",
    "formula",
    "fresh_session_sequence",
    "good_classification",
    "group",
    "group_class",
    "group_id",
    "header_length",
    "host_nwd1_active_profiles_max",
    "id",
    "instance_id_hex",
    "ip_ready",
    "is_duplicate_of_prior",
    "is_gap",
    "is_out_of_order",
    "keepalive_interval_ms",
    "key_update_local_emit",
    "label",
    "last_known_address_authority",
    "last_sent_sequence",
    "m4_carrier_required",
    "m4_full_durable",
    "m4_missing_nwb1_allowed",
    "max_records_read_ahead",
    "may_use_system_openssl_3",
    "mbedtls_commit",
    "mdns_browse",
    "missed_count_at_fail",
    "missed_count_still_ok",
    "missed_response_threshold",
    "mutated_record_hex",
    "need_bytes",
    "network_profile_nonzero_required",
    "network_profile_zero_required",
    "new_association_authority_digest_hex",
    "new_association_authority_input_hex",
    "new_association_epoch",
    "new_auth_digest_hex",
    "new_auth_mode",
    "new_binding_id_hex",
    "new_bssid_hex",
    "new_channel",
    "new_complete_digest_hex",
    "new_header_crc32c",
    "new_profile_digest_hex",
    "new_profile_id_hex",
    "new_profile_revision",
    "new_revision",
    "new_rows",
    "new_value_hex",
    "next_action",
    "next_sequence_same_session_forbidden",
    "now_equals_valid_until_reject",
    "nwb1_allowed",
    "nwb1_as_attachment_carrier",
    "nwb1_or_probe_response_required",
    "nwb1_publish",
    "nwb1_receive",
    "nwb1_send",
    "nwb1_socket_write_is_custody",
    "nwd1_kat_auth_digest_hex",
    "nwd1_kat_complete_digest_hex",
    "nwd1_kat_header_crc32c",
    "nwd1_kat_value_hex",
    "nwd1_keys_max",
    "nwd1_record_bytes",
    "observed_auth_digest_hex",
    "observed_complete_digest_hex",
    "observed_header_crc32c",
    "observed_revision",
    "observed_rows",
    "observed_value_hex",
    "old_association_authority_digest_hex",
    "old_association_authority_input_hex",
    "old_association_epoch",
    "old_auth_digest_hex",
    "old_auth_mode",
    "old_binding_id_hex",
    "old_bssid_hex",
    "old_channel",
    "old_complete_digest_hex",
    "old_header_crc32c",
    "old_profile_digest_hex",
    "old_profile_id_hex",
    "old_profile_revision",
    "old_revision",
    "old_rows",
    "old_value_hex",
    "on_liveness_fail",
    "order",
    "os_random_forbidden",
    "os_tcp_keepalive_is_authority",
    "os_wall_clock_authority",
    "overflow_count",
    "partial_tcp_tls_write_outer_would_block",
    "password_substrings_forbidden",
    "payload_length",
    "peeled_commit",
    "peer_kernel_ack_is_custody",
    "peer_probe_ok",
    "peer_session_id_nonzero",
    "physical_events_observed",
    "plaintext_password_in_storage",
    "plaintext_password_in_vectors",
    "poll_send_internal",
    "port",
    "post_handshake_auth",
    "power_cut_after",
    "prior_delivered_sequence",
    "profile_digest_hex",
    "profile_id_hex",
    "profile_revision",
    "protocol",
    "publish",
    "publish_before_reclassify",
    "queues",
    "r7_rule",
    "received_sequence",
    "reconnect_before_fence_forbidden",
    "record_bytes",
    "record_count",
    "record_hex",
    "record_sha256_hex",
    "release_before_terminal_forbidden",
    "release_send_exact_count_after_terminal",
    "renegotiation",
    "reobserve_same_tuple",
    "requires_fresh_association",
    "result",
    "result_state",
    "reuse_old_socket_forbidden",
    "revision",
    "rx_loan_max",
    "rx_record_max",
    "rx_record_per_session",
    "samples",
    "satisfies_wifi_host_pin",
    "schedule_ms",
    "scope_id_required",
    "scope_id_u32",
    "scope_id_zero_rejected",
    "scope_id_zero_result",
    "second_classification",
    "second_exporter_ok",
    "second_sequence",
    "secret_field",
    "secret_ref_digest_hex",
    "secret_ref_digest_only",
    "sequence",
    "server_binding_hex",
    "server_role",
    "session_established",
    "session_fence",
    "session_fence_generation",
    "session_max",
    "session_tickets",
    "shared_leaf_forbidden",
    "signature_id",
    "signature_scheme",
    "silent_fallback_forbidden",
    "sleep_marks_unavailable",
    "slice_hex",
    "snapshot_age_max_ms",
    "sockets_closed",
    "ssid_hex",
    "staging_cu_bytes",
    "staging_formula",
    "start_send_full_copy_own",
    "state",
    "static_only",
    "stream_hex",
    "tag",
    "targets",
    "tcp_ack_alone_not_liveness",
    "timer_shares_phase_deadline",
    "tls_backend",
    "tls_record_success_is_custody",
    "token_null_means_retain_0",
    "total_length",
    "transport",
    "tx_token_max",
    "tx_token_per_session",
    "unlimited_read_ahead_forbidden",
    "unused_tail_must_be_zero",
    "wifi_associated",
    "wifi_driver_owner",
    "wifi_driver_sole_owner",
    "wifi_storage_ram",
    "wrap_to_zero_same_session_forbidden",
})


def collect_row_key_union(document: dict[str, Any]) -> frozenset[str]:
    """Return hard-pinned closed row key allowlist (document must not expand it)."""
    del document  # unused; allowlist is frozen independent of input
    return CLOSED_ROW_KEYS


def rows_from(doc_rows: Any, field: str) -> list[tuple[bytes, bytes]]:
    if not isinstance(doc_rows, list):
        fail(f"{field}: not a list")
    out: list[tuple[bytes, bytes]] = []
    for index, row in enumerate(doc_rows):
        if not isinstance(row, dict):
            fail(f"{field}[{index}]: not object")
        # When authority fields present, independently recompute integrity.
        if "header_crc32c" in row:
            value = verify_nwd1_authority_row(row, f"{field}[{index}]")
            out.append((hx(row.get("key_hex"), f"{field}[{index}].key"), value))
        else:
            out.append(
                (
                    hx(row.get("key_hex"), f"{field}[{index}].key"),
                    hx(row.get("value_hex"), f"{field}[{index}].value"),
                )
            )
    return out


def require(cond: bool, message: str) -> None:
    if not cond:
        fail(message)


def index_rows(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for group in VECTOR_GROUPS:
        if group not in document or not isinstance(document[group], list):
            fail(f"missing group {group}")
        for row in document[group]:
            if not isinstance(row, dict) or "id" not in row:
                fail(f"{group}: bad row")
            rid = row["id"]
            if rid in by_id:
                fail(f"duplicate id emission {rid}")
            by_id[rid] = row
    return by_id


class SemanticLedger:
    def __init__(self) -> None:
        self.executed: set[str] = set()

    def mark(self, acceptance_id: str) -> None:
        if acceptance_id in self.executed:
            fail(f"double mark {acceptance_id}")
        self.executed.add(acceptance_id)


def assert_assoc_baseline(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("result") == "OK_ATTACHED_ELIGIBLE", "assoc baseline result")
    require(exact_int(row.get("session_fence"), "session_fence") == 0, "fence")
    require(
        exact_int(row.get("availability_epoch_delta"), "epoch") == 0, "epoch"
    )
    require(exact_int(row.get("profile_revision"), "rev") == 1, "rev")
    verify_assoc_digest(
        row,
        "association_authority_digest_hex",
        "association_authority_input_hex",
    )
    # Independent pin vs document pins (hard tag already applied).
    require(
        row["association_authority_digest_hex"]
        == document["pins"]["assoc_authority_a_hex"],
        "assoc pin",
    )
    require(
        row["association_authority_input_hex"]
        == document["pins"]["assoc_authority_input_a_hex"],
        "assoc input pin",
    )


def assert_assoc_bssid(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_STALE_SESSION", "bssid result")
    require(exact_int(row.get("session_fence"), "session_fence") == 1, "fence")
    require(exact_int(row.get("availability_epoch_delta"), "epoch") == 1, "epoch")
    require(exact_int(row.get("nwb1_publish"), "nwb1") == 0, "nwb1")
    require(exact_int(row.get("digests_equal"), "digests_equal") == 0, "digests")
    # All old_/new_ tuple fields must be present for full bind.
    for prefix in ("old_", "new_"):
        for field in (
            "profile_id_hex",
            "association_epoch",
            "profile_digest_hex",
            "binding_id_hex",
            "bssid_hex",
            "channel",
            "auth_mode",
            "association_authority_input_hex",
            "association_authority_digest_hex",
        ):
            require(f"{prefix}{field}" in row, f"missing {prefix}{field}")
    old_b = hx(row["old_bssid_hex"], "old bssid")
    new_b = hx(row["new_bssid_hex"], "new bssid")
    require(len(old_b) == 6 and len(new_b) == 6 and old_b != new_b, "bssid bytes")
    verify_assoc_digest(
        row,
        "old_association_authority_digest_hex",
        "old_association_authority_input_hex",
    )
    verify_assoc_digest(
        row,
        "new_association_authority_digest_hex",
        "new_association_authority_input_hex",
    )
    require(
        row["old_association_authority_digest_hex"]
        != row["new_association_authority_digest_hex"],
        "bssid auth digests",
    )
    # Cross-tuple: only BSSID (and dependent profile digest) may differ.
    require(row["old_profile_id_hex"] == row["new_profile_id_hex"], "same profile_id")
    require(row["old_binding_id_hex"] == row["new_binding_id_hex"], "same binding")
    require(
        exact_int(row["old_channel"], "old_channel")
        == exact_int(row["new_channel"], "new_channel"),
        "same channel on bssid change",
    )


def assert_assoc_channel(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_STALE_SESSION", "ch result")
    require(exact_int(row.get("session_fence"), "session_fence") == 1, "fence")
    require(exact_int(row.get("availability_epoch_delta"), "epoch") == 1, "epoch")
    require(exact_int(row.get("nwb1_publish"), "nwb1") == 0, "nwb1")
    require(exact_int(row.get("digests_equal"), "digests_equal") == 0, "digests")
    require(
        exact_int(row.get("old_channel"), "old_channel") == 6
        and exact_int(row.get("new_channel"), "new_channel") == 11,
        "channels",
    )
    verify_assoc_digest(
        row,
        "old_association_authority_digest_hex",
        "old_association_authority_input_hex",
    )
    verify_assoc_digest(
        row,
        "new_association_authority_digest_hex",
        "new_association_authority_input_hex",
    )


def assert_assoc_profile(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_STALE_SESSION", "prof result")
    require(exact_int(row.get("session_fence"), "session_fence") == 1, "fence")
    require(exact_int(row.get("availability_epoch_delta"), "epoch") == 1, "epoch")
    require(
        exact_int(row.get("old_revision"), "old_revision") == 1
        and exact_int(row.get("new_revision"), "new_revision") == 2,
        "revs",
    )
    require(
        row["old_profile_digest_hex"] != row["new_profile_digest_hex"],
        "profile digests",
    )
    verify_assoc_digest(
        row,
        "old_association_authority_digest_hex",
        "old_association_authority_input_hex",
    )
    verify_assoc_digest(
        row,
        "new_association_authority_digest_hex",
        "new_association_authority_input_hex",
    )


def assert_assoc_same(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK_NO_FENCE", "same result")
    require(exact_int(row.get("session_fence"), "session_fence") == 0, "fence")
    require(exact_int(row.get("availability_epoch_delta"), "epoch") == 0, "epoch")
    require(exact_int(row.get("reobserve_same_tuple"), "reobserve") == 1, "reobserve")
    verify_assoc_digest(
        row,
        "association_authority_digest_hex",
        "association_authority_input_hex",
    )


def assert_assoc_plus_one(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "AVAILABILITY_PLUS_ONE_ONCE", "plus1 result")
    require(exact_int(row.get("availability_epoch_delta"), "epoch") == 1, "delta")
    require(exact_int(row.get("double_count_forbidden"), "double") == 1, "double")
    require(row.get("event") == "ASSOCIATION_AUTHORITY_DIGEST_CHANGED", "event")
    require(exact_int(row.get("physical_events_observed"), "phys") == 2, "phys")
    require(exact_int(row.get("session_fence_generation"), "gen") == 1, "gen")


def assert_live_keepalive(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK_EXCLUSIVE", "ka result")
    require(row.get("state") == "ATTACHED", "ka state")
    require(row.get("keepalive_interval_ms") == PIN_KEEPALIVE_MS, "ka interval")
    require(row.get("exclusive_deadline_ms") == PIN_KEEPALIVE_MS, "ka deadline")
    require(row.get("timer_shares_phase_deadline") == 0, "ka exclusive")


def assert_live_missed(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FAIL_AT_THRESHOLD", "miss result")
    require(row.get("missed_response_threshold") == PIN_MISSED, "miss thr")
    require(row.get("missed_count_at_fail") == PIN_MISSED, "miss fail")
    require(row.get("missed_count_still_ok") == PIN_MISSED - 1, "miss ok")


def assert_live_blackhole(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_ON_BLACKHOLE", "bh result")
    require(row.get("blackhole_detect_ms") == PIN_BLACKHOLE_MS, "bh ms")
    require(row.get("tcp_ack_alone_not_liveness") == 1, "bh tcp")
    require(
        row.get("formula")
        == "keepalive_interval_ms * missed_response_threshold",
        "bh formula",
    )


def assert_live_half_open(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_HALF_OPEN", "ho result")
    require(
        row.get("condition") == "PEER_SILENT_TCP_STILL_WRITABLE",
        "ho condition",
    )
    require(row.get("os_tcp_keepalive_is_authority") == 0, "ho os")
    require(row.get("nwb1_or_probe_response_required") == 1, "ho probe")


def assert_live_backhaul(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_DEAD_BACKHAUL", "bh result")
    require(row.get("wifi_associated") == 1, "assoc")
    require(row.get("ip_ready") == 1, "ip")
    require(row.get("peer_probe_ok") == 0, "probe")
    require(row.get("nwb1_publish") == 0, "nwb1")


def assert_live_epoch(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "AVAILABILITY_PLUS_ONE", "le result")
    fail_block = row.get("on_liveness_fail")
    require(isinstance(fail_block, dict), "on_liveness_fail")
    require(fail_block.get("session_fence") == 1, "lf fence")
    require(fail_block.get("nwb1_delivery") == 0, "lf del")
    require(fail_block.get("connection_close") == 1, "lf close")
    require(fail_block.get("availability_epoch_delta") == 1, "lf epoch")
    require(fail_block.get("double_add_forbidden") == 1, "lf double")


def assert_netcred_class(
    row: dict[str, Any],
    expected: str,
    *,
    require_fresh: bool = False,
    result: str | None = None,
) -> None:
    got = classify_commit_unknown(
        rows_from(row.get("old_rows"), "old"),
        rows_from(row.get("new_rows"), "new"),
        rows_from(row.get("observed_rows"), "obs"),
    )
    require(got == expected, f"class recompute {got}!={expected}")
    require(row.get("classification") == expected, "class field")
    require(row.get("expected_classification") == expected, "expected class")
    require(exact_int(row.get("publish"), "publish") == 0, "publish")
    if require_fresh:
        require(
            exact_int(row.get("requires_fresh_association"), "fresh") == 1,
            "fresh assoc",
        )
    if result is not None:
        require(row.get("result") == result, f"result {result}")
    # expected_observed_complete_digests pin when present
    if "expected_observed_complete_digests" in row:
        obs = row.get("observed_rows") or []
        digs = [
            nwd1_complete_digest(hx(item["value_hex"], "ov")).hex() for item in obs
        ]
        require(
            digs == row["expected_observed_complete_digests"],
            "observed complete digests",
        )


def assert_netcred_old(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(row, "OLD")


def assert_netcred_new(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(row, "NEW", require_fresh=True)


def assert_netcred_absent(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(row, "ABSENT", result="ABSENT_RECLASSIFY_ONLY")
    require(row.get("create_result") == "COMMIT_UNKNOWN_NO_PUBLISH", "create")
    require(row.get("old_rows") == [], "old empty")
    require(row.get("observed_rows") == [], "obs empty")
    require(isinstance(row.get("new_rows"), list) and len(row["new_rows"]) >= 1, "new")


def assert_netcred_both(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(row, "BOTH", result="BOTH_OLD_AND_NEW_PRESENT")


def assert_netcred_partial(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(
        row, "PARTIAL", result="CORRUPT_OR_COMMIT_UNKNOWN_NO_PUBLISH"
    )


def assert_netcred_extra(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(row, "EXTRA")


def assert_netcred_third(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(row, "THIRD")


def assert_netcred_dup(row: dict[str, Any], _: dict[str, Any]) -> None:
    assert_netcred_class(row, "CORRUPT", result="CORRUPT_DUPLICATE_KEY")
    # Independent old-key duplicate path must also be CORRUPT (parity).
    require(
        row.get("expected_duplicate_old_key_classification") == "CORRUPT",
        "dup old expected",
    )
    require(
        row.get("duplicate_old_key_classification") == "CORRUPT",
        "dup old class",
    )
    # Recompute old-key duplicate using old_rows with intentional duplicate.
    old = rows_from(row.get("old_rows"), "old")
    new = rows_from(row.get("new_rows"), "new")
    if not old:
        fail("dup needs old")
    dup_old = [old[0], old[0]]
    require(
        classify_commit_unknown(dup_old, new, old) == "CORRUPT",
        "dup old recompute",
    )


def assert_netcred_recovery(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "RECLASSIFY_ONLY", "recovery result")
    require(row.get("silent_fallback_forbidden") == 1, "silent")
    require(row.get("publish_before_reclassify") == 0, "publish")
    allowed = row.get("classifications_allowed_on_reopen")
    closed = row.get("closed_classification_set")
    require(isinstance(allowed, list) and isinstance(closed, list), "lists")
    require(set(allowed) == set(CLOSED_COMMIT_SET), "allowed set")
    require(set(closed) == set(CLOSED_COMMIT_SET), "closed set")
    require("CORRUPT" in allowed, "corrupt allowed")
    require(row.get("absent_example_classification") == "ABSENT", "absent ex")
    require(
        row.get("power_cut_after") == "FULL_STAGE_BEFORE_COMMIT_ACK",
        "power cut",
    )


def assert_netcred_rollback(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_ROLLBACK", "rollback result")
    require(row.get("current_revision") == 2, "cur rev")
    require(row.get("observed_revision") == 1, "obs rev")
    require(row.get("publish") == 0, "publish")
    require(row["current_revision"] > row["observed_revision"], "rollback dir")
    raw = hx(row["observed_value_hex"], "rollback value")
    require(len(raw) == PIN_NWD1_RECORD, "nwd1 len")
    require(raw[0:4] == b"NWD1", "nwd1 magic")


def assert_netcred_conflict(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_DIGEST_CONFLICT", "conflict result")
    require(row.get("revision") == 2, "rev")
    require(row.get("digests_equal") == 0, "digests")
    require(row.get("publish") == 0, "publish")
    a = hx(row["canonical_value_hex"], "canon")
    b = hx(row["conflicting_value_hex"], "conf")
    require(a != b and len(a) == PIN_NWD1_RECORD and len(b) == PIN_NWD1_RECORD, "vals")
    require(sha(b"NINLIL-WIFI-NWD1-COMPLETE-V1" + a) != sha(
        b"NINLIL-WIFI-NWD1-COMPLETE-V1" + b
    ), "complete digests")


def assert_netcred_secret(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK_NO_PLAINTEXT", "secret result")
    require(row.get("secret_field") == "secret_ref_digest_only", "field")
    for prefix in ("old", "new"):
        raw = hx(row[f"{prefix}_value_hex"], prefix)
        require(len(raw) == PIN_NWD1_RECORD, f"{prefix} len")
        require(validate_nwd1_record(raw) == "OK", f"{prefix} framing")
        require(
            nwd1_header_crc32c(raw)
            == exact_int(row[f"{prefix}_header_crc32c"], f"{prefix}_crc"),
            f"{prefix} crc",
        )
        require(
            nwd1_auth_digest(raw)
            == hx(row[f"{prefix}_auth_digest_hex"], f"{prefix}_auth"),
            f"{prefix} auth",
        )
        require(
            nwd1_complete_digest(raw)
            == hx(row[f"{prefix}_complete_digest_hex"], f"{prefix}_complete"),
            f"{prefix} complete",
        )
        for forbidden in (b"hunter2", b"p@ssw0rd", b"password"):
            require(forbidden not in raw.lower(), f"{prefix} plaintext")
    # Independent hard-coded KAT pins (generator-self-ref rejected).
    require(row.get("nwd1_kat_value_hex") == PIN_NWD1_KAT_VALUE_HEX, "kat value pin")
    require(
        exact_int(row.get("nwd1_kat_header_crc32c"), "kat crc")
        == PIN_NWD1_KAT_HEADER_CRC,
        "kat crc pin",
    )
    require(
        row.get("nwd1_kat_auth_digest_hex") == PIN_NWD1_KAT_AUTH_HEX, "kat auth pin"
    )
    require(
        row.get("nwd1_kat_complete_digest_hex") == PIN_NWD1_KAT_COMPLETE_HEX,
        "kat complete pin",
    )
    kat = hx(PIN_NWD1_KAT_VALUE_HEX, "kat pin")
    require(len(kat) == PIN_NWD1_RECORD, "kat len")
    require(validate_nwd1_record(kat) == "OK", "kat framing")
    require(nwd1_header_crc32c(kat) == PIN_NWD1_KAT_HEADER_CRC, "kat crc recompute")
    require(nwd1_auth_digest(kat).hex() == PIN_NWD1_KAT_AUTH_HEX, "kat auth recompute")
    require(
        nwd1_complete_digest(kat).hex() == PIN_NWD1_KAT_COMPLETE_HEX,
        "kat complete recompute",
    )
    require(b"ninlil-lab-ssid" not in kat, "kat not lab ssid")
    require(b"KAT-NWD1-FIXED" in kat, "kat fixed ssid")
    # Vector fields must still equal independent pin (coherent drift reject).
    require(
        nwd1_complete_digest(kat)
        == hx(row["nwd1_kat_complete_digest_hex"], "kat complete"),
        "kat complete field",
    )
    require(
        nwd1_auth_digest(kat) == hx(row["nwd1_kat_auth_digest_hex"], "kat auth"),
        "kat auth field",
    )
    require(len(hx(row["secret_ref_digest_hex"], "sref")) == 32, "sref")


def assert_ep_ipv4(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK", "v4 result")
    require(row.get("address_kind") == 1, "kind")
    require(row.get("dns_authority") == 0, "dns")
    require(row.get("unused_tail_must_be_zero") == 1, "tail flag")
    require(row.get("port") == 8443, "port")
    addr = hx(row["address_hex"], "v4 addr")
    require(len(addr) == 16, "v4 len")
    require(addr[4:] == bytes(12), "v4 tail zero")
    # Malformed length must be rejectable by contract (not silently accepted).
    require(addr[0:4] != bytes(4), "v4 non-zero prefix")


def assert_ep_ipv6(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK", "v6 result")
    require(row.get("address_kind") == 2, "kind")
    require(row.get("dns_authority") == 0, "dns")
    require(row.get("port") == 8443, "port")
    addr = hx(row["address_hex"], "v6")
    require(len(addr) == 16, "v6 len")


def assert_ep_ll(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK_WITH_SCOPE_ID", "ll result")
    require(row.get("scope_id_required") == 1, "scope req")
    require(row.get("scope_id_zero_rejected") == 1, "scope0")
    require(row.get("scope_id_zero_result") == "REJECT", "scope0 result")
    scope = row.get("scope_id_u32")
    require(isinstance(scope, int) and 1 <= scope <= 0xFFFFFFFF, "scope range")
    # Overflow guard: values outside u32 must not appear.
    require(scope < 2**32, "scope overflow")
    addr = hx(row["address_hex"], "ll")
    require(len(addr) == 16, "ll len")
    require(addr[0] == 0xFE and (addr[1] & 0xC0) == 0x80, "fe80")


def assert_ep_dns(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "AUXILIARY_ONLY", "dns result")
    require(row.get("last_known_address_authority") == 0, "last known")
    require(row.get("mdns_browse") == 1, "mdns")
    require(
        row.get("authority_endpoint_change_requires_config_revision") == 1,
        "rev",
    )


def assert_ep_addr_change(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED", "ip change result")
    require(row.get("session_fence") == 1, "fence")
    require(row.get("availability_epoch_delta") == 1, "epoch")
    require(row.get("reuse_old_socket_forbidden") == 1, "reuse")
    require(row.get("nwb1_publish") == 0, "nwb1")
    require(
        row.get("event") == "IP_EVENT_STA_GOT_IP_CHANGE_OR_LOST",
        "event",
    )


def _nwb_expect(
    row: dict[str, Any],
    document: dict[str, Any],
    expected: str,
    *,
    bind_session: bool = False,
    sequence: int | None = None,
) -> None:
    record = hx(row["record_hex"], "record")
    session = hx(document["pins"]["session_id_hex"], "session")
    if bind_session:
        got = classify_nwb1(
            record, expected_session=session, expected_sequence=sequence
        )
    else:
        got = classify_nwb1(record)
    require(got == expected, f"nwb class {got}!={expected}")
    require(row.get("classification", expected) == expected, "class field")
    require(row.get("expected", expected) == expected, "expected field")


def assert_nwb_header(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("header_length") == PIN_NWB_HEADER, "hdr")
    _nwb_expect(row, document, "OK", bind_session=True, sequence=0)
    record = hx(row["record_hex"], "r")
    require(u16(record, 6) == 40, "hdr field")


def assert_nwb_586(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("payload_length") == 586, "pl")
    _nwb_expect(row, document, "CORRUPT")


def assert_nwb_587(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("payload_length") == PIN_PAYLOAD_MIN, "pl")
    require(row.get("total_length") == PIN_TOTAL_MIN, "tl")
    _nwb_expect(row, document, "OK", bind_session=True, sequence=0)
    record = hx(row["record_hex"], "r")
    require(len(record) == PIN_TOTAL_MIN, "len")
    require(
        sha(record)
        == hx(document["pins"]["nwb1_min_record_sha256_hex"], "pin"),
        "min pin",
    )


def assert_nwb_1925(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("payload_length") == PIN_PAYLOAD_MAX, "pl")
    require(row.get("total_length") == PIN_TOTAL_MAX, "tl")
    _nwb_expect(row, document, "OK", bind_session=True, sequence=0)
    require(len(hx(row["record_hex"], "r")) == PIN_TOTAL_MAX, "len")


def assert_nwb_1926(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("payload_length") == 1926, "pl")
    _nwb_expect(row, document, "CORRUPT")


def assert_nwb_626(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("total_length") == 626, "tl")
    _nwb_expect(row, document, "CORRUPT")


def assert_nwb_627(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("total_length") == PIN_TOTAL_MIN, "tl")
    _nwb_expect(row, document, "OK")


def assert_nwb_1965(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("total_length") == PIN_TOTAL_MAX, "tl")
    _nwb_expect(row, document, "OK")


def assert_nwb_1966(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("total_length") == 1966, "tl")
    _nwb_expect(row, document, "CORRUPT")


def assert_nwb_crc(row: dict[str, Any], document: dict[str, Any]) -> None:
    good = hx(row["record_hex"], "good")
    bad = hx(row["mutated_record_hex"], "bad")
    require(classify_nwb1(good) == "OK", "good")
    require(classify_nwb1(bad) == "CORRUPT", "bad")
    require(row.get("expected_good") == "OK", "eg")
    require(row.get("expected_bad") == "CORRUPT", "eb")
    require(row.get("good_classification") == "OK", "gc")
    require(row.get("bad_classification") == "CORRUPT", "bc")
    require(row.get("crc_polynomial") == "0x82F63B78", "poly")
    repaired = bytearray(bad)
    repaired[36:40] = bytes(4)
    repaired[36:40] = crc32c(bytes(repaired)).to_bytes(4, "big")
    require(bytes(repaired) == good, "repair bytes")
    require(sha(bytes(repaired)) == sha(good), "restoration hash")
    # Integrity-repaired malformed wire: flip magic after CRC repair → CORRUPT.
    mal = bytearray(good)
    mal[0] ^= 0x01
    mal[36:40] = bytes(4)
    mal[36:40] = crc32c(bytes(mal)).to_bytes(4, "big")
    require(classify_nwb1(bytes(mal)) == "CORRUPT", "repaired malformed")


def assert_nwb_partial_header(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "WANT_READ_NO_DELIVERY", "ph result")
    require(row.get("deliverable") == 0, "del")
    require(row.get("need_bytes") == PIN_NWB_HEADER, "need")
    require(row.get("bytes_available") < PIN_NWB_HEADER, "avail")
    sl = hx(row["slice_hex"], "slice")
    require(len(sl) == row["bytes_available"], "slice len")
    require(sl[0:4] == b"NWB1", "magic prefix")


def assert_nwb_partial_body(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "WANT_READ_NO_DELIVERY", "pb result")
    require(row.get("deliverable") == 0, "del")
    require(row.get("need_bytes") == PIN_TOTAL_MIN, "need")
    require(row.get("bytes_available") < PIN_TOTAL_MIN, "avail")
    require(row["bytes_available"] > PIN_NWB_HEADER, "partial body")


def assert_nwb_coalesced(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("record_count") == 2, "count")
    require(row.get("first_sequence") == 0, "seq0")
    require(row.get("second_sequence") == 1, "seq1")
    require(row.get("expected_first") == "OK", "ef")
    require(row.get("expected_second") == "OK", "es")
    stream = hx(row["stream_hex"], "stream")
    session = hx(document["pins"]["session_id_hex"], "session")
    first = stream[:PIN_TOTAL_MIN]
    second = stream[PIN_TOTAL_MIN : 2 * PIN_TOTAL_MIN]
    require(
        classify_nwb1(first, expected_session=session, expected_sequence=0)
        == "OK",
        "first",
    )
    require(
        classify_nwb1(second, expected_session=session, expected_sequence=1)
        == "OK",
        "second",
    )


def assert_nwb_readahead(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "BOUND_OK", "ra result")
    require(row.get("max_records_read_ahead") == 1, "max")
    require(row.get("unlimited_read_ahead_forbidden") == 1, "unlim")
    require(row.get("buffer_bytes") == 1965, "buf")


def assert_nwb_wrong_session(row: dict[str, Any], document: dict[str, Any]) -> None:
    session = hx(document["pins"]["session_id_hex"], "session")
    record = hx(row["record_hex"], "r")
    require(
        classify_nwb1(record, expected_session=session) == "WRONG_SESSION",
        "wrong",
    )
    require(row.get("expected") == "WRONG_SESSION", "exp")
    require(row.get("connection_close") == 1, "close")
    require(row.get("delivery") == 0, "del")
    require(hx(row["expected_session_hex"], "es") == session, "es pin")


def assert_nwb_seq0(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("sequence") == 0, "seq")
    _nwb_expect(row, document, "OK", bind_session=True, sequence=0)


def assert_nwb_seq_max(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("sequence") == 0xFFFFFFFE, "seq")
    _nwb_expect(row, document, "OK", bind_session=True, sequence=0xFFFFFFFE)
    require(
        row.get("next_action") == "CLEAN_CLOSE_THEN_FRESH_SESSION",
        "next",
    )


def assert_nwb_u32max(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("sequence") == 0xFFFFFFFF, "seq")
    require(row.get("emit_forbidden") == 1, "emit")
    _nwb_expect(row, document, "SEQUENCE_REJECT")
    # Overflow: sequence field is u32; values > 2^32-1 cannot be encoded.
    require(row["sequence"] < 2**32, "no overflow encode")


def assert_nwb_duplicate(row: dict[str, Any], _: dict[str, Any]) -> None:
    # After prior delivered N, expected next is N+1; receiving N is duplicate.
    require(row.get("prior_delivered_sequence") == 1, "prior")
    require(row.get("expected_sequence") == 2, "expected next")
    require(row.get("received_sequence") == 1, "recv")
    require(row.get("is_duplicate_of_prior") == 1, "dup flag")
    require(row.get("result") == "CLOSE_NO_DELIVERY", "result")
    require(row.get("delivery") == 0, "del")
    require(row.get("connection_close") == 1, "close")
    require(
        row["received_sequence"] == row["prior_delivered_sequence"],
        "recv==prior",
    )
    require(
        row["expected_sequence"] == row["prior_delivered_sequence"] + 1,
        "expected=prior+1",
    )
    require(row["received_sequence"] != row["expected_sequence"], "not expected")
    record = hx(row["record_hex"], "r")
    require(u32(record, 32) == 1, "wire seq")


def assert_nwb_gap(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("prior_delivered_sequence") == 0, "prior")
    require(row.get("expected_sequence") == 1, "expected")
    require(row.get("received_sequence") == 2, "recv")
    require(row.get("is_gap") == 1, "gap")
    require(row.get("result") == "CLOSE_NO_DELIVERY", "result")
    require(row.get("delivery") == 0, "del")
    require(row.get("connection_close") == 1, "close")
    require(row["received_sequence"] > row["expected_sequence"], "gap dir")
    require(u32(hx(row["record_hex"], "r"), 32) == 2, "wire")


def assert_nwb_ooo(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("prior_delivered_sequence") == 1, "prior")
    require(row.get("expected_sequence") == 2, "expected")
    require(row.get("received_sequence") == 1, "recv")
    require(row.get("is_out_of_order") == 1, "ooo")
    require(row.get("result") == "CLOSE_NO_DELIVERY", "result")
    require(row.get("delivery") == 0, "del")
    require(row.get("connection_close") == 1, "close")
    require(row["received_sequence"] < row["expected_sequence"], "ooo dir")


def assert_nwb_wrap(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "CLEAN_CLOSE_FRESH_HANDSHAKE", "wrap result")
    require(row.get("last_sent_sequence") == 0xFFFFFFFE, "last")
    require(row.get("wrap_to_zero_same_session_forbidden") == 1, "wrap0")
    require(row.get("fresh_session_sequence") == 0, "fresh0")


def assert_nwb_invalid_nfl1(row: dict[str, Any], document: dict[str, Any]) -> None:
    _nwb_expect(row, document, "INVALID_NFL1", bind_session=True, sequence=0)
    require(row.get("delivery") == 0, "del")
    require(row.get("connection_close") == 1, "close")
    record = hx(row["record_hex"], "r")
    require(record[40:44] != b"NFL1", "bad magic")


def assert_tls_suite(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK_EXACT", "suite result")
    require(row.get("protocol") == "TLS1.3", "proto")
    require(row.get("ciphersuite") == "TLS_AES_128_GCM_SHA256", "cs")
    require(row.get("ciphersuite_id") == PIN_TLS_SUITE_ID, "cs id")
    require(row.get("group") == "secp256r1", "group")
    require(row.get("group_id") == PIN_TLS_GROUP_ID, "g id")
    require(row.get("signature_scheme") == "ecdsa_secp256r1_sha256", "sig")
    require(row.get("signature_id") == PIN_TLS_SIG_ID, "sig id")


def assert_tls_x509(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK", "x509 result")
    require(row.get("binding_length") == 82, "len")
    require(row.get("client_role") == 1, "cr")
    require(row.get("server_role") == 2, "sr")
    require(row.get("shared_leaf_forbidden") == 1, "shared")
    c = hx(row["client_binding_hex"], "c")
    s = hx(row["server_binding_hex"], "s")
    require(len(c) == 82 and len(s) == 82, "bind lens")
    require(c[0] == 0x01 and s[0] == 0x01, "ver")
    require(c[1] == 0x01 and s[1] == 0x02, "roles")
    require(c != s, "distinct leaves")


def assert_tls_peer_ctx(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("result") == "OK", "peer result")
    require(row.get("label") == "EXPORTER-Ninlil-PeerSession-v1", "label")
    require(row.get("expected_length") == PIN_PEER_CTX, "elen")
    ctx = hx(row["context_hex"], "ctx")
    require(len(ctx) == PIN_PEER_CTX, "len")
    require(row.get("context_length") == PIN_PEER_CTX, "clen")
    require(ctx[28] == 0x01 and ctx[45] == 0x02, "roles")
    require(sha(ctx) == hx(row["context_sha256_hex"], "sha"), "sha")
    require(
        sha(ctx) == hx(document["pins"]["peer_context_sha256_hex"], "pin"),
        "pin",
    )


def assert_tls_attached_ctx(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("result") == "OK", "att result")
    require(row.get("label") == "EXPORTER-Ninlil-NWB1-Attached-v1", "label")
    require(row.get("depends_on_m4_full") == 1, "m4")
    ctx = hx(row["context_hex"], "ctx")
    require(len(ctx) == PIN_ATTACHED_CTX, "len")
    require(sha(ctx) == hx(row["context_sha256_hex"], "sha"), "sha")
    require(
        sha(ctx) == hx(document["pins"]["attached_context_sha256_hex"], "pin"),
        "pin",
    )


def assert_tls_all_zero(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "PROFILE_CONDITIONAL", "az result")
    require(row.get("group_class") == "ALL_ZERO", "class")
    require(row.get("expected_class") == "ALL_ZERO", "exp")
    require(row.get("bound_profile_rejects_all_zero") == 1, "bound")
    require(
        row.get("allowed_only_if_controllerless_profile_explicit") == 1,
        "ctrl",
    )
    ctx = hx(row["context_hex"], "ctx")
    require(len(ctx) == PIN_PEER_CTX, "len")
    require(ctx[0:16] == bytes(16), "auth zero")
    require(int.from_bytes(ctx[16:24], "big") == 0, "term0")
    require(int.from_bytes(ctx[24:28], "big") == 0, "epoch0")


def assert_tls_mixed(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "REJECT", "mixed result")
    require(row.get("group_class") == "MIXED", "class")
    require(row.get("expected_class") == "MIXED", "exp")
    require(row.get("session_established") == 0, "session")
    ctx = hx(row["context_hex"], "ctx")
    require(any(ctx[0:16]) and int.from_bytes(ctx[16:24], "big") == 0, "mixed")


def assert_tls_ticket(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "FENCED_IF_OBSERVED", "ticket result")
    require(row.get("session_tickets") == 0, "tickets")
    require(row.get("early_data_bytes_publish") == 0, "0rtt")
    require(row.get("renegotiation") == 0, "reneg")
    require(row.get("post_handshake_auth") == 0, "pha")
    require(row.get("key_update_local_emit") == 0, "ku")


def assert_tls_revocation(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK_RULES", "rev result")
    require(row.get("authority_clock_only") == 1, "auth clock")
    require(row.get("os_wall_clock_authority") == 0, "os")
    require(row.get("snapshot_age_max_ms") == 300000, "age max")
    require(row.get("age_300000_ok") == 1, "300k ok")
    require(row.get("age_300001_reject") == 1, "300k1")
    require(row.get("now_equals_valid_until_reject") == 1, "eq until")


def assert_tls_r7(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(
        row.get("result") == "NON_AUTHORITY_FOR_WIFI_PROFILE",
        "r7 result",
    )
    require(row.get("satisfies_wifi_host_pin") == 0, "not pin")
    require(row.get("may_use_system_openssl_3") == 1, "system ok for r7")
    require("OpenSSL major version exactly 3" in row.get("r7_rule", ""), "rule")


def assert_tls_host(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "HOST_WIFI_AUTHORITY", "host result")
    require(row.get("tag") == PIN_HOST_OPENSSL_TAG, "tag")
    require(row.get("peeled_commit") == PIN_HOST_OPENSSL_PEELED, "peeled")
    require(row.get("static_only") == 1, "static")
    targets = row.get("targets")
    require(isinstance(targets, list) and len(targets) == 2, "targets")
    require(any("0x01" in t for t in targets), "t1")
    require(any("0x02" in t for t in targets), "t2")


def assert_tls_esp(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "ESP_WIFI_AUTHORITY", "esp result")
    require(row.get("esp_idf_commit") == PIN_ESP_IDF, "idf")
    require(row.get("mbedtls_commit") == PIN_ESP_MBEDTLS, "mbed")
    require(row.get("esp_tls_public_api_forbidden") == 1, "esp-tls")
    require(row.get("direct_mbedtls_only") == 1, "direct")


def assert_pre_carrier(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "BOUNDARY_OK", "pre result")
    require(row.get("nwb1_as_attachment_carrier") == 0, "nwb1 carrier")
    require(row.get("m4_carrier_required") == 1, "m4")


def assert_pre_peer(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "NO_NWB1", "peer result")
    require(row.get("state") == "PEER_SESSION", "state")
    require(row.get("peer_session_id_nonzero") == 1, "ps")
    require(row.get("nwb1_send") == 0, "send")
    require(row.get("nwb1_receive") == 0, "recv")
    require(row.get("fabric_availability") == 0, "fab")
    require(row.get("application_publish") == 0, "app")


def assert_pre_pa(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK_POST_ATTACHMENT", "pa result")
    require(row.get("state") == "ATTACHED", "state")
    require(row.get("m4_full_durable") == 1, "m4")
    require(row.get("attachment_authority_match") == 1, "auth")
    require(row.get("active_binding_match") == 1, "bind")
    require(row.get("second_exporter_ok") == 1, "exp2")
    require(row.get("nwb1_allowed") == 1, "nwb1")
    require(row.get("m4_missing_nwb1_allowed") == 0, "missing")


def assert_res_esp(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("result") == "ESP_BOUNDS", "esp result")
    require(row.get("adapter_max") == 1, "ad")
    require(row.get("session_max") == 2, "sess")
    require(row.get("connect_attempt_max") == 1, "conn")
    require(row.get("event_queue_max") == PIN_ESP_EVENT_Q, "eq")
    require(row.get("event_queue_overflow_at") == PIN_ESP_EVENT_Q + 1, "ov")
    require(row.get("tx_token_max") == 8, "tx")
    require(row.get("rx_record_max") == 8, "rx")
    require(row.get("rx_loan_max") == 1, "loan")
    require(row.get("record_bytes") == 1965, "rec")
    constants = document["constants"]
    require(
        constants["esp_tls_session_total_bytes"] == PIN_ESP_TLS_SESSION_TOTAL,
        "tls total",
    )
    require(
        constants["esp_tls_session_internal_bytes"]
        == PIN_ESP_TLS_SESSION_INTERNAL,
        "tls internal",
    )
    require(
        constants["esp_tls_session_psram_bytes"] == PIN_ESP_TLS_SESSION_PSRAM,
        "tls psram",
    )
    require(
        constants["esp_tls_session_internal_bytes"]
        + constants["esp_tls_session_psram_bytes"]
        == constants["esp_tls_session_total_bytes"],
        "tls tier sum",
    )
    require(
        constants["esp_tls_crypto_global_internal_bytes"]
        == PIN_ESP_TLS_CRYPTO_GLOBAL_INTERNAL,
        "tls global",
    )
    require(
        constants["esp_tls_post_admission_internal_floor_bytes"]
        == PIN_ESP_TLS_INTERNAL_FLOOR,
        "tls floor",
    )
    require(
        constants["esp_tls_original_internal_only_requirement_bytes"]
        == PIN_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT,
        "tls original internal-only requirement",
    )
    require(
        constants["esp_tls_session_total_bytes"] * 2
            + constants["esp_tls_crypto_global_internal_bytes"]
            + constants["esp_tls_post_admission_internal_floor_bytes"]
        == constants["esp_tls_original_internal_only_requirement_bytes"],
        "tls original internal-only arithmetic",
    )
    require(
        constants["esp_tls_execution_stack_bytes"]
        == PIN_ESP_TLS_EXECUTION_STACK,
        "tls stack",
    )
    require(constants["esp_tls_crypto_dma_bytes"] == 0, "tls dma")
    envelope = (
        constants["esp_tls_crypto_global_internal_bytes"]
        + 2 * constants["esp_tls_session_internal_bytes"]
        + constants["esp_tls_post_admission_internal_floor_bytes"]
        + constants["esp_tls_execution_stack_bytes"]
        + constants["esp_tls_crypto_dma_bytes"]
    )
    require(envelope == PIN_ESP_TLS_INTERNAL_ENVELOPE, "tls envelope")
    require(
        constants["esp_tls_two_session_internal_envelope_bytes"] == envelope,
        "tls envelope pin",
    )
    require(
        constants["esp_tls_map_remainder_observation_bytes"]
        == PIN_ESP_TLS_MAP_REMAINDER_OBS,
        "map observation",
    )
    require(
        constants["esp_tls_map_remainder_observation_bytes"] - envelope
        == PIN_ESP_TLS_MAP_SLACK_OBS,
        "map slack arithmetic",
    )
    require(
        constants["esp_tls_map_observation_slack_bytes"]
        == PIN_ESP_TLS_MAP_SLACK_OBS,
        "map slack pin",
    )
    require(constants["esp_tls_in_buffer_bytes"] == PIN_ESP_TLS_IN_BUFFER, "in")
    require(
        constants["esp_tls_out_buffer_bytes"] == PIN_ESP_TLS_OUT_BUFFER,
        "out",
    )
    require(constants["esp_tls_psram_required"] == 1, "psram required")
    require(constants["esp_tls_generic_spill_allowed"] == 0, "spill")
    require(
        constants["esp_tls_psram_exact_live_allocation_required"] == 1,
        "exact live allocation",
    )
    require(constants["esp_tls_psram_interior_pointer_allowed"] == 0, "interior")
    require(constants["esp_tls_psram_free_pointer_allowed"] == 0, "free pointer")
    require(constants["esp_tls_psram_wrong_size_allowed"] == 0, "wrong size")
    require(constants["esp_tls_cross_owner_free_allowed"] == 0, "cross owner")
    require(constants["esp_tls_contract_null_spill_allowed"] == 0, "null spill")
    require(
        constants["esp_tls_ordinary_oom_is_global_fatal"] == 0,
        "ordinary oom scope",
    )
    require(
        constants["esp_tls_canary_corruption_is_global_fatal"] == 1,
        "canary fatal",
    )


def assert_res_host(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "HOST_BOUNDS", "host result")
    require(row.get("adapter_max") == 64, "ad")
    require(row.get("session_max") == 64, "sess")
    require(row.get("connect_attempt_max") == 8, "conn")
    require(row.get("tx_token_per_session") == 8, "tx")
    require(row.get("rx_record_per_session") == 8, "rx")
    require(row.get("record_bytes") == 1965, "rec")


def assert_res_priority(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "ISOLATED", "pri result")
    require(row.get("bulk_may_starve_critical") == 0, "starve")
    require(
        row.get("queues")
        == ["critical_control", "application_data", "management_bulk"],
        "queues",
    )


def assert_res_retained(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK", "ret result")
    require(row.get("start_send_full_copy_own") == 1, "copy")
    require(row.get("partial_tcp_tls_write_outer_would_block") == 0, "outer")
    require(row.get("poll_send_internal") == 1, "poll")
    require(row.get("token_null_means_retain_0") == 1, "token")


def assert_res_release(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OK", "rel result")
    require(row.get("release_send_exact_count_after_terminal") == 1, "exact")
    # ADR: release before terminal is forbidden.
    require(row.get("release_before_terminal_forbidden") == 1, "before forbidden")


def assert_res_custody(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "NO_CUSTODY", "custody result")
    require(row.get("nwb1_socket_write_is_custody") == 0, "sock")
    require(row.get("tls_record_success_is_custody") == 0, "tls")
    require(row.get("peer_kernel_ack_is_custody") == 0, "ack")
    require(row.get("fabric_cap_custody_advertised") == 0, "cap")


def assert_res_storage(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "ARITHMETIC_OK", "stor result")
    require(row.get("nwd1_record_bytes") == PIN_NWD1_RECORD, "rec")
    require(row.get("nwd1_keys_max") == PIN_NWD1_KEYS, "keys")
    require(row.get("committed_cu_bytes") == PIN_COMMITTED_CU, "cu")
    require(row.get("staging_cu_bytes") == PIN_STAGING_CU, "st")
    require(
        row["committed_cu_bytes"] == row["nwd1_keys_max"] * row["nwd1_record_bytes"],
        "cu formula",
    )
    require(
        row["staging_cu_bytes"] == row["committed_cu_bytes"] * 2,
        "st formula",
    )
    require(row.get("plaintext_password_in_storage") == 0, "pw stor")
    require(row.get("plaintext_password_in_vectors") == 0, "pw vec")
    require(row.get("secret_ref_digest_only") == 1, "sref")


def assert_role_host(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "HOST_RESPONSIBILITY", "host result")
    require(row.get("adapter_kind") == 1, "kind")
    require(row.get("transport") == "POSIX_TCP", "tr")
    require(row.get("tls_backend") == "PINNED_OPENSSL_3_5_7_STATIC", "tls")
    require(row.get("network_profile_zero_required") == 1, "np0")
    require(row.get("credential_provider_null_required") == 1, "prov")
    require(row.get("wifi_driver_owner") == 0, "wifi")


def assert_role_esp(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "ESP_RESPONSIBILITY", "esp result")
    require(row.get("adapter_kind") == 2, "kind")
    require(row.get("transport") == "ESP_IDF_WIFI_STA_TCP_LWIP", "tr")
    require(row.get("tls_backend") == "ESP_IDF_SUPPLIED_MBEDTLS_DIRECT", "tls")
    require(row.get("network_profile_nonzero_required") == 1, "np")
    require(row.get("credential_provider_required") == 1, "prov")
    require(row.get("wifi_driver_sole_owner") == 1, "sole")
    require(row.get("wifi_storage_ram") == 1, "ram")


def assert_race_disconnect(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "DETERMINISTIC", "disc result")
    require(row.get("reconnect_before_fence_forbidden") == 1, "order fence")
    require(row.get("order") == list(DISCONNECT_ORDER), "order exact")


def assert_race_sleep(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "DETERMINISTIC", "sleep result")
    require(row.get("sleep_marks_unavailable") == 1, "unavail")
    require(row.get("availability_epoch_delta_on_sleep") == 1, "epoch")
    require(row.get("fake_available_while_asleep") == 0, "fake")
    require(row.get("drain_blocks_new_send_retention") == 1, "drain")


def assert_race_overflow(row: dict[str, Any], _: dict[str, Any]) -> None:
    require(row.get("result") == "OVERFLOW_FENCE", "ov result")
    require(row.get("event_queue_max") == PIN_ESP_EVENT_Q, "max")
    require(row.get("overflow_count") == PIN_ESP_EVENT_Q + 1, "ov")
    require(row.get("result_state") == "FENCED", "state")
    require(row.get("availability") == 0, "avail")
    require(row.get("sockets_closed") == 1, "socks")


def assert_race_backoff(row: dict[str, Any], document: dict[str, Any]) -> None:
    require(row.get("result") == "DETERMINISTIC", "bo result")
    require(row.get("schedule_ms") == list(PIN_BACKOFF), "sched")
    require(row.get("cap_ms") == 32000, "cap")
    require(row.get("entropy_forbidden") == 1, "entropy")
    require(row.get("os_random_forbidden") == 1, "osrand")
    require(row.get("attached_stable_reset_ms") == 60000, "stable")
    instance = hx(row["instance_id_hex"], "inst")
    require(
        instance == hx(document["pins"]["instance_id_hex"], "pin"),
        "inst pin",
    )
    for sample in row["samples"]:
        gen = sample["failure_generation"]
        expected_backoff = PIN_BACKOFF[gen - 1] if gen <= 6 else 32000
        digest = sha(instance + gen.to_bytes(8, "big"))
        expected_jitter = int.from_bytes(digest[0:2], "big") % 1000
        require(sample["backoff_ms"] == expected_backoff, f"bo {gen}")
        require(sample["jitter_ms"] == expected_jitter, f"j {gen}")
        require(
            sample["not_before_offset_ms"] == expected_backoff + expected_jitter,
            f"nb {gen}",
        )


# Independent ID -> assertion map (canonical semantic contract).
SEMANTIC_ASSERTIONS: dict[str, Callable[[dict[str, Any], dict[str, Any]], None]] = {
    "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE": assert_assoc_baseline,
    "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE": assert_assoc_bssid,
    "WIFI-ASSOC-SAME-SSID-CHANNEL-CHANGE-FENCE": assert_assoc_channel,
    "WIFI-ASSOC-PROFILE-DIGEST-CHANGE-FENCE": assert_assoc_profile,
    "WIFI-ASSOC-SAME-TUPLE-NO-EPOCH": assert_assoc_same,
    "WIFI-ASSOC-SESSION-FENCE-AVAILABILITY-PLUS-ONE": assert_assoc_plus_one,
    "WIFI-LIVENESS-KEEPALIVE-EXCLUSIVE-TIMER": assert_live_keepalive,
    "WIFI-LIVENESS-MISSED-RESPONSE-THRESHOLD": assert_live_missed,
    "WIFI-LIVENESS-BLACKHOLE-DETECTION": assert_live_blackhole,
    "WIFI-LIVENESS-TCP-HALF-OPEN": assert_live_half_open,
    "WIFI-LIVENESS-AP-DEAD-BACKHAUL": assert_live_backhaul,
    "WIFI-LIVENESS-AVAILABILITY-EPOCH-CHANGE": assert_live_epoch,
    "WIFI-NETCRED-FULL-OLD": assert_netcred_old,
    "WIFI-NETCRED-FULL-NEW": assert_netcred_new,
    "WIFI-NETCRED-FULL-ABSENT": assert_netcred_absent,
    "WIFI-NETCRED-FULL-BOTH": assert_netcred_both,
    "WIFI-NETCRED-PARTIAL": assert_netcred_partial,
    "WIFI-NETCRED-EXTRA": assert_netcred_extra,
    "WIFI-NETCRED-THIRD": assert_netcred_third,
    "WIFI-NETCRED-DUPLICATE-KEY": assert_netcred_dup,
    "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY": assert_netcred_recovery,
    "WIFI-NETCRED-ROLLBACK-REJECT": assert_netcred_rollback,
    "WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT": assert_netcred_conflict,
    "WIFI-NETCRED-NO-PLAINTEXT-SECRET": assert_netcred_secret,
    "WIFI-ENDPOINT-IPV4-SCOPE": assert_ep_ipv4,
    "WIFI-ENDPOINT-IPV6-SCOPE": assert_ep_ipv6,
    "WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID": assert_ep_ll,
    "WIFI-ENDPOINT-DNS-MDNS-NON-AUTHORITY": assert_ep_dns,
    "WIFI-ENDPOINT-ADDRESS-CHANGE-FENCE": assert_ep_addr_change,
    "WIFI-NWB1-HEADER-40": assert_nwb_header,
    "WIFI-NWB1-PAYLOAD-586-REJECT": assert_nwb_586,
    "WIFI-NWB1-PAYLOAD-587-ACCEPT": assert_nwb_587,
    "WIFI-NWB1-PAYLOAD-1925-ACCEPT": assert_nwb_1925,
    "WIFI-NWB1-PAYLOAD-1926-REJECT": assert_nwb_1926,
    "WIFI-NWB1-TOTAL-626-REJECT": assert_nwb_626,
    "WIFI-NWB1-TOTAL-627-ACCEPT": assert_nwb_627,
    "WIFI-NWB1-TOTAL-1965-ACCEPT": assert_nwb_1965,
    "WIFI-NWB1-TOTAL-1966-REJECT": assert_nwb_1966,
    "WIFI-NWB1-CRC32C-INDEPENDENT": assert_nwb_crc,
    "WIFI-NWB1-PARTIAL-HEADER": assert_nwb_partial_header,
    "WIFI-NWB1-PARTIAL-BODY": assert_nwb_partial_body,
    "WIFI-NWB1-COALESCED-RECORDS": assert_nwb_coalesced,
    "WIFI-NWB1-READ-AHEAD-BOUND": assert_nwb_readahead,
    "WIFI-NWB1-WRONG-SESSION": assert_nwb_wrong_session,
    "WIFI-NWB1-SEQUENCE-0": assert_nwb_seq0,
    "WIFI-NWB1-SEQUENCE-MAX-MINUS-ONE": assert_nwb_seq_max,
    "WIFI-NWB1-SEQUENCE-UINT32-MAX-REJECT": assert_nwb_u32max,
    "WIFI-NWB1-DUPLICATE": assert_nwb_duplicate,
    "WIFI-NWB1-GAP": assert_nwb_gap,
    "WIFI-NWB1-OUT-OF-ORDER": assert_nwb_ooo,
    "WIFI-NWB1-WRAP-REJECT": assert_nwb_wrap,
    "WIFI-NWB1-INVALID-NFL1": assert_nwb_invalid_nfl1,
    "WIFI-TLS-SUITE-GROUP-SIGNATURE-EXACT": assert_tls_suite,
    "WIFI-TLS-X509-ROLE-RUNTIME-ATTACHMENT": assert_tls_x509,
    "WIFI-TLS-EXPORTER-PEER-CONTEXT-62": assert_tls_peer_ctx,
    "WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64": assert_tls_attached_ctx,
    "WIFI-TLS-AUTHORITY-ALL-ZERO-GROUP": assert_tls_all_zero,
    "WIFI-TLS-AUTHORITY-MIXED-REJECT": assert_tls_mixed,
    "WIFI-TLS-TICKET-0RTT-RENEGOTIATION-FENCE": assert_tls_ticket,
    "WIFI-TLS-REVOCATION-CLOCK-RULES": assert_tls_revocation,
    "WIFI-TLS-R7-OPENSSL-GENERIC-NON-AUTHORITY": assert_tls_r7,
    "WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY": assert_tls_host,
    "WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY": assert_tls_esp,
    "WIFI-PREATTACH-CARRIER-NOT-NWB1": assert_pre_carrier,
    "WIFI-PREATTACH-PEER-SESSION-ONLY-NO-NWB1": assert_pre_peer,
    "WIFI-PREATTACH-NWB1-REQUIRES-PA-FULL": assert_pre_pa,
    "WIFI-RESOURCE-ESP-CAPACITY": assert_res_esp,
    "WIFI-RESOURCE-HOST-CAPACITY": assert_res_host,
    "WIFI-RESOURCE-PRIORITY-ISOLATION": assert_res_priority,
    "WIFI-RESOURCE-RETAINED-TOKEN-PARTIAL-WRITE": assert_res_retained,
    "WIFI-RESOURCE-RELEASE-SEMANTICS": assert_res_release,
    "WIFI-RESOURCE-NO-FALSE-CUSTODY": assert_res_custody,
    "WIFI-RESOURCE-STORAGE-ARITHMETIC": assert_res_storage,
    "WIFI-ROLE-HOST-POSIX-TCP-TLS": assert_role_host,
    "WIFI-ROLE-ESP32S3-STA-LWIP-MBEDTLS": assert_role_esp,
    "WIFI-RACE-DISCONNECT-RECONNECT": assert_race_disconnect,
    "WIFI-RACE-SLEEP-DRAIN": assert_race_sleep,
    "WIFI-RACE-EVENT-OVERFLOW": assert_race_overflow,
    "WIFI-BACKOFF-DETERMINISTIC": assert_race_backoff,
}


def canonical_document_bytes(document: dict[str, Any]) -> bytes:
    """Bit-stable machine model serialization (matches vector generator)."""
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def assert_canonical_document_model(document: dict[str, Any]) -> None:
    """Exact all-machine-field equality vs hard-pinned golden model SHA-256."""
    rendered = canonical_document_bytes(document)
    got = hashlib.sha256(rendered).hexdigest()
    require(got == PIN_VECTOR_DOCUMENT_SHA256, f"document model sha {got}")


def require_row(document: dict[str, Any], acceptance_id: str) -> dict[str, Any]:
    for group in VECTOR_GROUPS:
        for row in document.get(group, []):
            if isinstance(row, dict) and row.get("id") == acceptance_id:
                return row
    fail(f"missing required row {acceptance_id}")


def assert_machine_field_pins(document: dict[str, Any]) -> None:
    """Explicit pin every normative top-level machine object (clear error paths)."""
    require(
        exact_int(document.get("acceptance_id_count"), "acceptance_id_count")
        == PIN_ACCEPTANCE_ID_COUNT,
        "acceptance_id_count",
    )
    require(document.get("nonclaims") == list(PIN_NONCLAIMS), "nonclaims exact")
    constants = document["constants"]
    expected_constants = {
        "nwb1_header_bytes": PIN_NWB_HEADER,
        "nwb1_payload_min": PIN_PAYLOAD_MIN,
        "nwb1_payload_max": PIN_PAYLOAD_MAX,
        "nwb1_total_min": PIN_TOTAL_MIN,
        "nwb1_total_max": PIN_TOTAL_MAX,
        "nwb1_payload_reject_low": 586,
        "nwb1_payload_reject_high": 1926,
        "nwb1_total_reject_low": 626,
        "nwb1_total_reject_high": 1966,
        "peer_context_bytes": PIN_PEER_CTX,
        "attached_context_bytes": PIN_ATTACHED_CTX,
        "keepalive_interval_ms": PIN_KEEPALIVE_MS,
        "keepalive_exclusive_deadline_ms": PIN_KEEPALIVE_EXCLUSIVE_DEADLINE_MS,
        "missed_response_threshold": PIN_MISSED,
        "blackhole_detect_ms": PIN_BLACKHOLE_MS,
        "session_lifetime_ms": PIN_SESSION_LIFETIME_MS,
        "nwd1_record_bytes": PIN_NWD1_RECORD,
        "nwd1_committed_cu_bytes": PIN_COMMITTED_CU,
        "nwd1_staging_cu_bytes": PIN_STAGING_CU,
        "record_bytes_fixed": PIN_RECORD_BYTES_FIXED,
        "esp_tls_session_total_bytes": PIN_ESP_TLS_SESSION_TOTAL,
        "esp_tls_session_internal_bytes": PIN_ESP_TLS_SESSION_INTERNAL,
        "esp_tls_session_psram_bytes": PIN_ESP_TLS_SESSION_PSRAM,
        "esp_tls_crypto_global_internal_bytes": (
            PIN_ESP_TLS_CRYPTO_GLOBAL_INTERNAL
        ),
        "esp_tls_post_admission_internal_floor_bytes": PIN_ESP_TLS_INTERNAL_FLOOR,
        "esp_tls_original_internal_only_requirement_bytes": (
            PIN_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT
        ),
        "esp_tls_execution_stack_bytes": PIN_ESP_TLS_EXECUTION_STACK,
        "esp_tls_crypto_dma_bytes": 0,
        "esp_tls_two_session_internal_envelope_bytes": (
            PIN_ESP_TLS_INTERNAL_ENVELOPE
        ),
        "esp_tls_map_remainder_observation_bytes": (
            PIN_ESP_TLS_MAP_REMAINDER_OBS
        ),
        "esp_tls_map_observation_slack_bytes": PIN_ESP_TLS_MAP_SLACK_OBS,
        "esp_tls_in_buffer_bytes": PIN_ESP_TLS_IN_BUFFER,
        "esp_tls_out_buffer_bytes": PIN_ESP_TLS_OUT_BUFFER,
        "esp_tls_psram_required": 1,
        "esp_tls_generic_spill_allowed": 0,
        "esp_tls_psram_exact_live_allocation_required": 1,
        "esp_tls_psram_interior_pointer_allowed": 0,
        "esp_tls_psram_free_pointer_allowed": 0,
        "esp_tls_psram_wrong_size_allowed": 0,
        "esp_tls_cross_owner_free_allowed": 0,
        "esp_tls_contract_null_spill_allowed": 0,
        "esp_tls_ordinary_oom_is_global_fatal": 0,
        "esp_tls_canary_corruption_is_global_fatal": 1,
        "tls_ciphersuite_id": PIN_TLS_SUITE_ID,
        "tls_group_id": PIN_TLS_GROUP_ID,
        "tls_signature_id": PIN_TLS_SIG_ID,
        "network_namespace": PIN_NETWORK_NAMESPACE,
    }
    for key, expected in expected_constants.items():
        require(constants.get(key) == expected, f"constants.{key}")

    pins = document["pins"]
    require(pins.get("host_openssl_tag") == PIN_HOST_OPENSSL_TAG, "pins.host tag")
    require(
        pins.get("host_openssl_peeled") == PIN_HOST_OPENSSL_PEELED, "pins.host peeled"
    )
    require(pins.get("esp_idf_commit") == PIN_ESP_IDF, "pins.esp_idf")
    require(pins.get("esp_mbedtls_commit") == PIN_ESP_MBEDTLS, "pins.esp_mbed")
    require(pins.get("assoc_authority_tag_ascii") == PIN_ASSOC_TAG_ASCII, "pins.tag")
    require(exact_int(pins.get("nfl1_header_bytes"), "nfl1_hdr") == PIN_NFL1_HEADER, "pins.nfl1_hdr")
    require(exact_int(pins.get("nfl1_version"), "nfl1_ver") == PIN_NFL1_VERSION, "pins.nfl1_ver")

    storage = document["storage_arithmetic"]
    require(exact_int(storage.get("nwd1_record_bytes"), "s.rec") == PIN_NWD1_RECORD, "st.rec")
    require(exact_int(storage.get("nwd1_keys_max"), "s.keys") == PIN_NWD1_KEYS, "st.keys")
    require(
        exact_int(storage.get("committed_cu_bytes"), "s.cu") == PIN_COMMITTED_CU, "st.cu"
    )
    require(
        exact_int(storage.get("staging_cu_bytes"), "s.st") == PIN_STAGING_CU, "st.st"
    )
    require(storage.get("committed_formula") == "keys_max * record_bytes", "st.cf")
    require(storage.get("staging_formula") == "committed_cu_bytes * 2", "st.sf")
    require(exact_int(storage.get("esp_nwd1_active_profiles_max"), "esp_p") == 1, "st.esp")
    require(exact_int(storage.get("host_nwd1_active_profiles_max"), "host_p") == 8, "st.host")
    require(exact_int(storage.get("plaintext_password_in_storage"), "pps") == 0, "st.pps")
    require(exact_int(storage.get("plaintext_password_in_vectors"), "ppv") == 0, "st.ppv")
    require(exact_int(storage.get("secret_ref_digest_only"), "sref") == 1, "st.sref")

    rest = document["source_vector_restoration"]
    require(rest.get("schema") == PIN_SCHEMA, "rest.schema")
    require(rest.get("adr") == PIN_ADR, "rest.adr")
    require(rest.get("generator") == PIN_GENERATOR, "rest.gen")
    require(rest.get("gate_py") == PIN_GATE_PY, "rest.gate_py")
    require(rest.get("gate_mjs") == PIN_GATE_MJS, "rest.gate_mjs")
    require(rest.get("vector") == PIN_VECTOR, "rest.vector")
    require(rest.get("c_test") == PIN_C_TEST, "rest.c_test")
    require(rest.get("tool_paths") == list(PIN_TOOL_PATHS), "rest.tools")
    require(rest.get("absent_row_id") == "WIFI-NETCRED-FULL-ABSENT", "rest.absent")
    require(
        rest.get("duplicate_expected_sequence_rule") == "prior_delivered + 1",
        "rest.dup_rule",
    )
    require(
        exact_int(rest.get("acceptance_id_count"), "rest.count") == PIN_ACCEPTANCE_ID_COUNT,
        "rest.count",
    )
    require(exact_int(rest.get("nwb1_min_total"), "rest.tmin") == PIN_TOTAL_MIN, "rest.tmin")
    require(exact_int(rest.get("nwb1_max_total"), "rest.tmax") == PIN_TOTAL_MAX, "rest.tmax")
    require(
        exact_int(rest.get("commit_unknown_includes_corrupt"), "rest.cu") == 1,
        "rest.cu",
    )
    require(
        exact_int(rest.get("release_before_terminal_forbidden"), "rest.rel") == 1,
        "rest.rel",
    )
    require(
        rest.get("independent_nwd1_kat_value_hex") == PIN_NWD1_KAT_VALUE_HEX,
        "rest kat value",
    )
    require(
        exact_int(rest.get("independent_nwd1_kat_header_crc32c"), "rest kat crc")
        == PIN_NWD1_KAT_HEADER_CRC,
        "rest kat crc",
    )
    require(
        rest.get("independent_nwd1_kat_auth_digest_hex") == PIN_NWD1_KAT_AUTH_HEX,
        "rest kat auth",
    )
    require(
        rest.get("independent_nwd1_kat_complete_digest_hex")
        == PIN_NWD1_KAT_COMPLETE_HEX,
        "rest kat complete",
    )
    # Row-level machine strings that previously drifted under partial contracts.
    secret = require_row(document, "WIFI-NETCRED-NO-PLAINTEXT-SECRET")
    require(
        secret.get("password_substrings_forbidden") == list(PIN_PASSWORD_SUBSTRINGS),
        "password substrings",
    )
    recovery = require_row(document, "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY")
    require(recovery.get("both_example_classification") == "BOTH", "both example")
    storage_row = require_row(document, "WIFI-RESOURCE-STORAGE-ARITHMETIC")
    require(storage_row.get("committed_formula") == "keys_max * record_bytes", "row cf")
    require(storage_row.get("staging_formula") == "committed_cu_bytes * 2", "row sf")
    require(
        exact_int(storage_row.get("esp_nwd1_active_profiles_max"), "row esp") == 1,
        "row esp",
    )
    require(
        exact_int(storage_row.get("host_nwd1_active_profiles_max"), "row host") == 8,
        "row host",
    )


def iter_scalar_leaves(value: Any, path: str = "$") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(value, bool):
        return out
    if isinstance(value, (int, str)):
        out.append((path, value))
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            out.extend(iter_scalar_leaves(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(iter_scalar_leaves(item, f"{path}[{index}]"))
    return out


def type_preserving_mutate(value: Any) -> Any:
    """Type-preserving scalar mutation used by independent audit campaign."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        if value and all(c in "0123456789abcdef" for c in value) and len(value) % 2 == 0:
            # hex: flip first nibble (same campaign as audit).
            return ("0" if value[0] != "0" else "1") + value[1:]
        return value + "_DRIFT"
    return value


def run_exhaustive_scalar_value_self_test(document: dict[str, Any]) -> None:
    """Type-preserving scalar campaign: every leaf must fail when drifted."""
    leaves = iter_scalar_leaves(document)
    require(len(leaves) == 1078, f"scalar leaf inventory {len(leaves)} (want 1078)")
    accepted = 0
    for path, original in leaves:
        if path in DESCRIPTIVE_SCALAR_ALLOWLIST:
            continue
        candidate = copy.deepcopy(document)
        _navigate_assign_leaf(candidate, path, type_preserving_mutate(original))
        try:
            # Full machine model: structure + inventory + digests + exact model.
            assert_document_structure(candidate)
            assert_type_inventory(candidate)
            assert_all_digest_preimages(candidate)
            assert_machine_field_pins(candidate)
            assert_canonical_document_model(candidate)
            accepted += 1
        except (GateError, KeyError, TypeError, ValueError, AssertionError, StopIteration):
            pass
    if accepted != 0:
        fail(f"exhaustive scalar-value: accepted={accepted}/{len(leaves)} (want 0)")
    print(
        "wifi bearer Python gate exhaustive scalar-value: OK "
        f"leaves={len(leaves)} accepted=0 allowlist={len(DESCRIPTIVE_SCALAR_ALLOWLIST)}"
    )


def validate(document: dict[str, Any]) -> int:
    if len(SEMANTIC_ASSERTIONS) != len(REQUIRED_ACCEPTANCE_IDS):
        fail("assertion map size")
    if set(SEMANTIC_ASSERTIONS) != set(REQUIRED_ACCEPTANCE_IDS):
        fail("assertion map keys")

    # Closed root keys + recursive nested closed/typed tree (bool ban, row keys).
    assert_document_structure(document)
    assert_type_inventory(document)
    assert_all_digest_preimages(document)
    assert_machine_field_pins(document)
    assert_canonical_document_model(document)

    if document.get("schema") != PIN_SCHEMA:
        fail("schema")
    if document.get("status") != PIN_STATUS:
        fail("status")
    # Hard-pinned source metadata + path existence.
    require(document.get("adr") == PIN_ADR, "adr pin")
    require(document.get("generator") == PIN_GENERATOR, "generator pin")
    rest = document.get("source_vector_restoration")
    require(isinstance(rest, dict), "restoration object")
    for rel in PIN_TOOL_PATHS:
        if not (ROOT / rel).is_file():
            fail(f"missing pinned path {rel}")
    for banned in PIN_NONCLAIMS[:5]:
        if banned not in document.get("nonclaims", []):
            fail(f"nonclaims {banned}")

    constants = document["constants"]
    require(constants["nwb1_header_bytes"] == PIN_NWB_HEADER, "c header")
    require(constants["nwb1_payload_min"] == PIN_PAYLOAD_MIN, "c pmin")
    require(constants["nwb1_payload_max"] == PIN_PAYLOAD_MAX, "c pmax")
    require(constants["nwb1_total_min"] == PIN_TOTAL_MIN, "c tmin")
    require(constants["nwb1_total_max"] == PIN_TOTAL_MAX, "c tmax")
    require(constants["nwb1_payload_reject_low"] == 586, "c 586")
    require(constants["nwb1_payload_reject_high"] == 1926, "c 1926")
    require(constants["nwb1_total_reject_low"] == 626, "c 626")
    require(constants["nwb1_total_reject_high"] == 1966, "c 1966")
    require(constants["peer_context_bytes"] == PIN_PEER_CTX, "c peer")
    require(constants["attached_context_bytes"] == PIN_ATTACHED_CTX, "c att")
    require(constants["keepalive_interval_ms"] == PIN_KEEPALIVE_MS, "c ka")
    require(constants["missed_response_threshold"] == PIN_MISSED, "c miss")
    require(constants["blackhole_detect_ms"] == PIN_BLACKHOLE_MS, "c bh")
    require(constants["nwd1_committed_cu_bytes"] == PIN_COMMITTED_CU, "c cu")
    require(constants["nwd1_staging_cu_bytes"] == PIN_STAGING_CU, "c st")

    listed = document.get("required_acceptance_ids")
    require(listed == list(REQUIRED_ACCEPTANCE_IDS), "required list")
    by_id = index_rows(document)
    require(
        sorted(by_id) == sorted(REQUIRED_ACCEPTANCE_IDS),
        "emitted set",
    )
    require(
        document.get("acceptance_ids_emitted") == list(by_id.keys())
        or sorted(document.get("acceptance_ids_emitted", []))
        == sorted(REQUIRED_ACCEPTANCE_IDS),
        "emitted list",
    )
    # Prefer exact emission order matching required when present.
    if document.get("acceptance_ids_emitted") != list(REQUIRED_ACCEPTANCE_IDS):
        # Allow only if set-equal; still require all IDs present in rows.
        require(
            sorted(document.get("acceptance_ids_emitted", []))
            == sorted(REQUIRED_ACCEPTANCE_IDS),
            "emitted order/set",
        )

    ledger = SemanticLedger()
    for acceptance_id in REQUIRED_ACCEPTANCE_IDS:
        row = by_id.get(acceptance_id)
        if row is None:
            fail(f"missing row {acceptance_id}")
        SEMANTIC_ASSERTIONS[acceptance_id](row, document)
        ledger.mark(acceptance_id)

    require(ledger.executed == set(REQUIRED_ACCEPTANCE_IDS), "ledger complete")
    return len(ledger.executed)


def mutation_must_fail(
    document: dict[str, Any],
    label: str,
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    candidate = copy.deepcopy(document)
    mutate(candidate)
    try:
        validate(candidate)
    except (GateError, KeyError, TypeError, ValueError, AssertionError):
        # Missing donor fields, type lies, and contract failures all count as reject.
        return
    fail(f"self-test mutation survived: {label}")


def run_self_test(document: dict[str, Any]) -> None:
    executed = validate(document)
    by_id = index_rows(document)
    ids = list(REQUIRED_ACCEPTANCE_IDS)
    # Full-row donor under same original ID must reject for EVERY ID.
    donor_rejects = 0
    for victim in ids:
        donor = next(d for d in ids if d != victim)
        def mutate(doc: dict[str, Any], v: str = victim, d: str = donor) -> None:
            victim_row = None
            donor_row = None
            victim_group = None
            for group in VECTOR_GROUPS:
                for index, row in enumerate(doc[group]):
                    if row["id"] == v:
                        victim_row = row
                        victim_group = (group, index)
                    if row["id"] == d:
                        donor_row = row
            if victim_row is None or donor_row is None or victim_group is None:
                fail("donor setup")
            body = copy.deepcopy(donor_row)
            body["id"] = v  # keep victim ID, donor semantics
            group, index = victim_group
            doc[group][index] = body

        mutation_must_fail(document, f"donor {donor}->id {victim}", mutate)
        donor_rejects += 1

    # Targeted defect mutations.
    mutation_must_fail(
        document,
        "duplicate expected_sequence lie",
        lambda doc: by_id_mut(doc, "WIFI-NWB1-DUPLICATE").__setitem__(
            "expected_sequence", 1
        ),
    )
    mutation_must_fail(
        document,
        "release_before_terminal lie",
        lambda doc: by_id_mut(doc, "WIFI-RESOURCE-RELEASE-SEMANTICS").__setitem__(
            "release_before_terminal_forbidden", 0
        ),
    )
    mutation_must_fail(
        document,
        "commit set omit CORRUPT",
        lambda doc: by_id_mut(doc, "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY").__setitem__(
            "classifications_allowed_on_reopen",
            ["OLD", "NEW", "ABSENT", "PARTIAL", "EXTRA", "THIRD"],
        ),
    )
    mutation_must_fail(
        document,
        "absent class lie",
        lambda doc: by_id_mut(doc, "WIFI-NETCRED-FULL-ABSENT").__setitem__(
            "classification", "OLD"
        ),
    )
    mutation_must_fail(
        document,
        "host pin lie",
        lambda doc: by_id_mut(doc, "WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY").__setitem__(
            "tag", "openssl-3.0.0"
        ),
    )
    mutation_must_fail(
        document,
        "esp pin lie",
        lambda doc: by_id_mut(doc, "WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY").__setitem__(
            "esp_tls_public_api_forbidden", 0
        ),
    )
    mutation_must_fail(
        document,
        "half-open donor-style result",
        lambda doc: by_id_mut(doc, "WIFI-LIVENESS-TCP-HALF-OPEN").__setitem__(
            "result", "OK_EXCLUSIVE"
        ),
    )
    mutation_must_fail(
        document,
        "conflict digests_equal lie",
        lambda doc: by_id_mut(
            doc, "WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT"
        ).__setitem__("digests_equal", 1),
    )
    mutation_must_fail(
        document,
        "bad ipv4 tail",
        lambda doc: by_id_mut(doc, "WIFI-ENDPOINT-IPV4-SCOPE").__setitem__(
            "address_hex",
            (bytes([192, 0, 2, 10]) + bytes([1]) + bytes(11)).hex(),
        ),
    )
    mutation_must_fail(
        document,
        "scope overflow",
        lambda doc: by_id_mut(doc, "WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID").__setitem__(
            "scope_id_u32", 2**32
        ),
    )
    mutation_must_fail(
        document,
        "status claim",
        lambda doc: doc.__setitem__("status", "SPEC_ACCEPTED"),
    )
    mutation_must_fail(
        document,
        "dup key class lie",
        lambda doc: by_id_mut(doc, "WIFI-NETCRED-DUPLICATE-KEY").__setitem__(
            "classification", "THIRD"
        ),
    )

    # CRC repair restoration still holds.
    crc_row = by_id["WIFI-NWB1-CRC32C-INDEPENDENT"]
    good = hx(crc_row["record_hex"], "good")
    repaired = bytearray(hx(crc_row["mutated_record_hex"], "bad"))
    repaired[36:40] = bytes(4)
    repaired[36:40] = crc32c(bytes(repaired)).to_bytes(4, "big")
    require(sha(bytes(repaired)) == sha(good), "restoration")

    print(
        "wifi bearer Python gate self-test: OK "
        f"ids={executed} donor_rejects={donor_rejects} "
        f"extra_mutations=12"
    )


def by_id_mut(document: dict[str, Any], acceptance_id: str) -> dict[str, Any]:
    for group in VECTOR_GROUPS:
        for row in document[group]:
            if row["id"] == acceptance_id:
                return row
    fail(f"missing {acceptance_id}")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--vector", type=Path, default=VECTOR)
    args = parser.parse_args()
    try:
        document = load_json_strict(args.vector)
        if args.self_test:
            run_self_test(document)
            run_exhaustive_structure_self_test(document)
            run_exhaustive_scalar_value_self_test(document)
            # Extra mutations: NFL1 version, XWD1, bool type, duplicate keys.
            mutation_must_fail(
                document,
                "nfl1 version repaired",
                lambda doc: _mutate_nfl1_version(doc),
            )
            mutation_must_fail(
                document,
                "xwd1 coherent",
                lambda doc: _mutate_xwd1(doc),
            )
            mutation_must_fail(
                document,
                "session_fence bool",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE"
                ).__setitem__("session_fence", True),
            )
            mutation_must_fail(
                document,
                "assoc input desync",
                lambda doc: _mutate_assoc_input_desync(doc),
            )
            mutation_must_fail(
                document,
                "secret_ref coherent swap",
                lambda doc: _mutate_secret_ref(doc),
            )
            mutation_must_fail(
                document,
                "adr bool",
                lambda doc: doc.__setitem__("adr", True),
            )
            mutation_must_fail(
                document,
                "unknown root",
                lambda doc: doc.__setitem__("unknown_field", 1),
            )
            mutation_must_fail(
                document,
                "old_bssid surface desync",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                ).__setitem__(
                    "old_bssid_hex",
                    by_id_mut(
                        doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                    )["new_bssid_hex"],
                ),
            )
            mutation_must_fail(
                document,
                "old_profile_id surface desync",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                ).__setitem__("old_profile_id_hex", "00" * 16),
            )
            mutation_must_fail(
                document,
                "old_epoch surface desync",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                ).__setitem__("old_association_epoch", 99),
            )
            mutation_must_fail(
                document,
                "old_digest surface desync",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                ).__setitem__("old_profile_digest_hex", "11" * 32),
            )
            mutation_must_fail(
                document,
                "old_binding surface desync",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                ).__setitem__("old_binding_id_hex", "22" * 16),
            )
            mutation_must_fail(
                document,
                "old_channel surface desync",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                ).__setitem__("old_channel", 99),
            )
            mutation_must_fail(
                document,
                "old_auth surface desync",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
                ).__setitem__("old_auth_mode", 99),
            )
            mutation_must_fail(
                document,
                "independent kat value drift",
                lambda doc: by_id_mut(
                    doc, "WIFI-NETCRED-NO-PLAINTEXT-SECRET"
                ).__setitem__(
                    "nwd1_kat_value_hex",
                    "00" * PIN_NWD1_RECORD,
                ),
            )
            mutation_must_fail(
                document,
                "independent kat crc drift",
                lambda doc: by_id_mut(
                    doc, "WIFI-NETCRED-NO-PLAINTEXT-SECRET"
                ).__setitem__("nwd1_kat_header_crc32c", 0),
            )
            mutation_must_fail(
                document,
                "nested authority_override",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE"
                ).__setitem__("authority_override", 1),
            )
            mutation_must_fail(
                document,
                "nested unknown row key",
                lambda doc: by_id_mut(
                    doc, "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE"
                ).__setitem__("unexpected_nested_key", 1),
            )
            mutation_must_fail(
                document,
                "constants unknown key",
                lambda doc: doc["constants"].__setitem__("authority_override", 1),
            )
            mutation_must_fail(
                document,
                "metadata adr drift",
                lambda doc: doc.__setitem__("adr", "docs/adr/does-not-exist.md"),
            )
            mutation_must_fail(
                document,
                "tool path missing mutation",
                lambda doc: doc["source_vector_restoration"].__setitem__(
                    "tool_paths",
                    list(PIN_TOOL_PATHS)[:-1] + ["tools/missing_wifi_gate.py"],
                ),
            )
            mutation_must_fail(
                document,
                "restoration kat coherent drift",
                lambda doc: doc["source_vector_restoration"].__setitem__(
                    "independent_nwd1_kat_value_hex", "ff" * PIN_NWD1_RECORD
                ),
            )
            # Duplicate JSON keys must be rejected at parse time.
            raw = args.vector.read_text(encoding="utf-8")
            # Inject a duplicate top-level key near the end before final brace.
            injected = raw.rstrip()
            if not injected.endswith("}"):
                fail("vector shape")
            injected = injected[:-1] + ',\n  "schema": "dup-key-attack"\n}\n'
            tmp = args.vector.with_suffix(".dup.json")
            try:
                tmp.write_text(injected, encoding="utf-8")
                try:
                    load_json_strict(tmp)
                    fail("duplicate key parse accepted")
                except GateError:
                    pass
            finally:
                if tmp.exists():
                    tmp.unlink()
            # Semantic unicode-escape duplicate: "schema" and "\u0073chema"
            unicode_dup = raw.rstrip()
            if not unicode_dup.endswith("}"):
                fail("vector shape")
            unicode_dup = (
                unicode_dup[:-1] + ',\n  "\\u0073chema": "unicode-dup"\n}\n'
            )
            tmp_u = args.vector.with_suffix(".udup.json")
            try:
                tmp_u.write_text(unicode_dup, encoding="utf-8")
                try:
                    load_json_strict(tmp_u)
                    fail("unicode semantic duplicate key accepted")
                except GateError:
                    pass
            finally:
                if tmp_u.exists():
                    tmp_u.unlink()
            print(
                "wifi bearer Python gate self-test extra: "
                "nfl1/xwd1/bool/dup-key/assoc-bind/kat/meta/nested OK"
            )
        else:
            count = validate(document)
            print(f"wifi bearer Python gate: PASS executed={count}")
    except (GateError, OSError, json.JSONDecodeError, KeyError, TypeError) as exc:
        print(f"wifi bearer Python gate: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


def _mutate_nfl1_version(doc: dict[str, Any]) -> None:
    row = by_id_mut(doc, "WIFI-NWB1-PAYLOAD-587-ACCEPT")
    raw = bytearray(hx(row["record_hex"], "r"))
    # NFL1 version at payload offset 4 => record[44:46]
    raw[44:46] = (0x00FF).to_bytes(2, "big")
    raw[36:40] = bytes(4)
    raw[36:40] = crc32c(bytes(raw)).to_bytes(4, "big")
    row["record_hex"] = raw.hex()
    row["classification"] = "OK"
    row["expected"] = "OK"
    row["record_sha256_hex"] = sha(bytes(raw)).hex()
    doc["pins"]["nwb1_min_record_sha256_hex"] = sha(bytes(raw)).hex()


def _mutate_xwd1(doc: dict[str, Any]) -> None:
    row = by_id_mut(doc, "WIFI-NETCRED-FULL-OLD")
    val = bytearray(hx(row["observed_rows"][0]["value_hex"], "v"))
    val[0:4] = b"XWD1"
    hexv = val.hex()
    for field in ("old_rows", "new_rows", "observed_rows"):
        for item in row[field]:
            item["value_hex"] = hexv
            # keep authority fields coherent with broken magic still fails framing
            item["complete_digest_hex"] = nwd1_complete_digest(bytes(val)).hex()
            item["auth_digest_hex"] = nwd1_auth_digest(bytes(val)).hex()
            item["header_crc32c"] = nwd1_header_crc32c(bytes(val))
    row["classification"] = "OLD"
    row["expected_classification"] = "OLD"


def _mutate_assoc_input_desync(doc: dict[str, Any]) -> None:
    row = by_id_mut(doc, "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE")
    raw = bytearray(hx(row["association_authority_input_hex"], "ain"))
    raw[0] ^= 0x01
    row["association_authority_input_hex"] = raw.hex()
    # Keep digest and bound fields unchanged so schema bind fails.


def _mutate_secret_ref(doc: dict[str, Any]) -> None:
    row = by_id_mut(doc, "WIFI-NETCRED-FULL-OLD")
    for field in ("old_rows", "observed_rows"):
        for item in row[field]:
            val = bytearray(hx(item["value_hex"], "v"))
            val[128:160] = sha(b"coherent-secret-ref-swap")
            item["value_hex"] = val.hex()
            # Coherently recompute digests — still fail expected_observed pin.
            item["complete_digest_hex"] = nwd1_complete_digest(bytes(val)).hex()
            item["auth_digest_hex"] = nwd1_auth_digest(bytes(val)).hex()
            item["header_crc32c"] = nwd1_header_crc32c(bytes(val))
    row["expected_observed_complete_digests"] = [
        # keep original expected digests so coherent swap is rejected
        row["expected_observed_complete_digests"][0]
    ]


if __name__ == "__main__":
    raise SystemExit(main())
