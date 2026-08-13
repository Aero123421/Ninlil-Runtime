#!/usr/bin/env python3
"""Independent ADR-0021 multi-frame durable transfer design-authority generator.

Specification oracle only. Uses the Python standard library. Does not import
Ninlil production code or the independent gates.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spec/vectors/multi-frame-durable-transfer-spec-v1.json"

SCHEMA = "ninlil.multi-frame-durable-transfer.spec.v1"
STATUS = "SPEC_ACCEPTED"

# Independently hard-pinned machine authority metadata (not learned from vector).
PINNED_ADR = "ADR-0021"
PINNED_ADR_PATH = "docs/adr/0021-multi-frame-durable-custody.md"
PINNED_TITLE = (
    "Multi-frame Durable Transfer / full fragmentation design authority"
)
PINNED_NONCLAIMS: tuple[str, ...] = (
    "implementation",
    "HIL",
    "RELEASE_SUPPORTED",
    "public_abi",
    "compact_rf_mapping",
    "wifi_mapping",
    "docs_25_26_refreeze_done",
    "application_handoff_implementation",
    "nts3_schema_1_2_implementation",
)
# Exact ordered existing-file source set. Authority includes path order + existence.
# ADR content SHA is hard-pinned here. Generator self-SHA is NOT pinned inside this
# file (avoids self-circular authority); independent gates pin generator content SHA.
PINNED_SOURCES: tuple[str, ...] = (
    PINNED_ADR_PATH,
    "tools/multi_frame_durable_transfer_spec_vector_gen.py",
)
PINNED_ADR_SHA256_HEX = (
    "15bd999eb3240672f65089aa2ba12ba481c552688fda262aa221ebf4f2ed4ac9"
)

# Fixed limits (ADR-0021 candidate).
MAX_CONTENT = 32768
CHUNK_SIZE = 896
MAX_CHUNKS = 37
ENTRY_BYTES = 40
ENTRIES_PER_PAGE = 22
MAX_PAGES = 2
OPEN_BASE_FIXED = 234
APPLICATION_BINDING_BYTES = 228
OPEN_FIXED = OPEN_BASE_FIXED + APPLICATION_BINDING_BYTES  # 462
OPEN_MIN = OPEN_FIXED + 3
OPEN_MAX = OPEN_FIXED + 3 * 63
HEADER_BYTES = 308
ACTIVE_VALUE_MAX = HEADER_BYTES + OPEN_MAX + MAX_CHUNKS * ENTRY_BYTES + MAX_CONTENT + 4
ACTIVE_RECORD_SCHEMA = 2
NM30_BYTES = 180
NM30_LEGACY_SCHEMA1_BYTES = 164
KEY_BYTES = 20
NCL1_BODY_MAX = 998
WORKSPACE_BYTES = 65536
HOST_SLOT_COUNT = 4
HOST_COORDINATOR_BYTES = 512
HOST_TERMINAL_CATALOG_ENTRIES = 16
HOST_TERMINAL_CATALOG_ENTRY_BYTES = 64
HOST_TERMINAL_CATALOG_BYTES = (
    HOST_TERMINAL_CATALOG_ENTRIES * HOST_TERMINAL_CATALOG_ENTRY_BYTES
)
HOST_CONTROL_OUTBOX_METADATA_BYTES = 64
HOST_CONTROL_OUTBOX_BYTES = 1024
HOST_CONTROL_NRC1_SCRATCH_BYTES = 15024
HOST_CONTROL_NM30_SCRATCH_BYTES = 184
HOST_CONTROL_RECOVERY_RESERVED_BYTES = 88
HOST_CONTROL_ARENA_BYTES = (
    HOST_COORDINATOR_BYTES
    + HOST_TERMINAL_CATALOG_BYTES
    + HOST_CONTROL_OUTBOX_METADATA_BYTES
    + HOST_CONTROL_OUTBOX_BYTES
    + HOST_CONTROL_NRC1_SCRATCH_BYTES
    + HOST_CONTROL_NM30_SCRATCH_BYTES
    + HOST_CONTROL_RECOVERY_RESERVED_BYTES
)
HOST_OWNER_WORKSPACE_BYTES = HOST_SLOT_COUNT * WORKSPACE_BYTES + HOST_CONTROL_ARENA_BYTES
HOST_CONTROL_ROUTE_SENTINEL = 0xFF
MFDT_STORAGE_NAMESPACE_DOMAIN = b"NINLIL-MFDT-STORAGE-NAMESPACE-V1"
MFDT_BASE_NAMESPACE_DOMAIN = b"NINLIL-MFDT-BASE-NAMESPACE-V1"
MFDT_STORAGE_NAMESPACE_MAGIC = b"NMF1"
MFDT_STORAGE_BINDING_MAGIC = b"NMS1"
MFDT_STORAGE_BINDING_KEY = MFDT_STORAGE_BINDING_MAGIC + bytes(16)
MFDT_STORAGE_BINDING_HEADER_BYTES = 48
MFDT_STORAGE_BINDING_FIXED_BYTES = 52
MFDT_STORAGE_BINDING_SCHEMA = 1
MFDT_STORAGE_EXPECTED_SCHEMA = 1
RESERVATION_LIFETIME_MS = 300000
RETENTION_MS = 86400000
RESUME_MAX = 8
ABORT_GEN_MAX = 8
# Closed timeout new-ID budget (active header retry_budget_remaining 0..8).
# Alias kept for older vector field names; SM name is RETRY_BUDGET_MAX.
RETRY_BUDGET_MAX = 8
TIMEOUT_RETRY_MAX = RETRY_BUDGET_MAX

# Max *distinct consecutive generation values* that may occur during one
# transfer lifetime.  This is deliberately not a numeric ceiling: the initial
# session_generation is any non-zero u32 (for example 7), followed by at most
# its exact successor (for example 8).  RESUME budget is per generation
# (RESUME_MAX=8), while peak NRC1 occupancy reclaims prior-gen RESUME-class
# slots on durable session-gen advance (see reachable_request_id_counts).
SESSION_GEN_MAX_PER_TRANSFER = 2

# Max-ID COMPLETE path FULL counts.
# Base co-located 44/42 + RESUME 8/8 + REQID_CACHE 16/8 + RETRY_BUDGET owner FULL 8/8
# + SESSION_GEN advance FULL (SESSION_GEN_MAX-1)=1 → receiver 77 / sender 67.
RECEIVER_FULLS_BASE = 44  # OPEN+PAGE+CHUNK+CONTENT+ACCEPT+HANDOFF+TERMINAL
SENDER_FULLS_BASE = 42  # OPEN+OPEN_RX+MANIFEST+CHUNK+ACCEPT+TERMINAL
RECEIVER_FULLS_RESUME = RESUME_MAX  # 8 (peak one gen; multi-gen via reclaim)
SENDER_FULLS_RESUME = RESUME_MAX  # 8
RECEIVER_FULLS_REQID_CACHE = ABORT_GEN_MAX + RETRY_BUDGET_MAX  # 8+8 = 16
SENDER_FULLS_REQID_CACHE = RETRY_BUDGET_MAX  # 8 sender-as-responder NRC1-only
# Owner-side FULL that commits retry_budget_remaining decrement (missing in 58).
RECEIVER_FULLS_RETRY_BUDGET = RETRY_BUDGET_MAX  # 8
SENDER_FULLS_RETRY_BUDGET = RETRY_BUDGET_MAX  # 8
# Durable session-generation advance + RESUME-slot reclaim (gen 1→2 ...).
RECEIVER_FULLS_SESSION_GEN = SESSION_GEN_MAX_PER_TRANSFER - 1  # 1
SENDER_FULLS_SESSION_GEN = SESSION_GEN_MAX_PER_TRANSFER - 1  # 1
RECEIVER_FULLS_MAX = (
    RECEIVER_FULLS_BASE
    + RECEIVER_FULLS_RESUME
    + RECEIVER_FULLS_REQID_CACHE
    + RECEIVER_FULLS_RETRY_BUDGET
    + RECEIVER_FULLS_SESSION_GEN
)  # 44+8+16+8+1 = 77
SENDER_FULLS_MAX = (
    SENDER_FULLS_BASE
    + SENDER_FULLS_RESUME
    + SENDER_FULLS_REQID_CACHE
    + SENDER_FULLS_RETRY_BUDGET
    + SENDER_FULLS_SESSION_GEN
)  # 42+8+8+8+1 = 67
RECEIVER_FULLS_EMPTY = 5
SENDER_FULLS_EMPTY = 5
OBSOLETE_FULLS_DAY = 80
REF_MAXSIZE_TRANSFERS_DAY = 2

ZERO16 = bytes(16)
ZERO32 = bytes(32)
UINT64_MAX = (1 << 64) - 1
MFDT_ADMISSION_PROFILE_REVISION = 2
MFDT_OFFER_DIGEST_DOMAIN = b"NINLIL-MFDT-OFFER-V2"
MFDT_ACCEPT_DIGEST_DOMAIN = b"NINLIL-MFDT-ACCEPT-V2"
APPLICATION_EVIDENCE_DOMAIN = b"NINLIL-MFDT-APPLICATION-EVIDENCE-V1"
NTS3_CURRENT_SCHEMA_MAJOR = 1
NTS3_CURRENT_SCHEMA_MINOR = 1
NTS3_FUTURE_SCHEMA_MINOR = 2
NTS3_SCHEMA11_RECORD_MAX_BYTES = 4031
NTS3_INLINE_PAYLOAD_MAX_BYTES = 926
NTS3_MFDT_TARGET_SUFFIX_BYTES = 20
NTS3_TARGET_COUNT_MAX = 4
NTS3_MFDT_RECORD_MAX_BYTES = (
    NTS3_SCHEMA11_RECORD_MAX_BYTES
    - NTS3_INLINE_PAYLOAD_MAX_BYTES
    + NTS3_TARGET_COUNT_MAX * NTS3_MFDT_TARGET_SUFFIX_BYTES
)
NTS3_RECORD_CEILING_BYTES = 4096

NM30_STATE = {
    "COMPLETE": 1,
    "ABORTED": 2,
    "CORRUPT_FENCED": 3,
}

NM30_REASON = {
    "COMPLETE": 0,
    "OPERATOR": 1,
    "SUPERSEDED": 2,
    "DEADLINE": 3,
    "POLICY": 4,
    "EXPIRED": 5,  # terminal-only; never valid in TRANSFER_ABORT
    "STORE_CORRUPT": 0x8001,
    "EPOCH_CHANGED": 0x8002,
}

MSG = {
    "TRANSFER_OPEN": 0x36,
    "TRANSFER_OPEN_ACCEPT": 0x37,
    "MANIFEST_PAGE": 0x38,
    "MANIFEST_PAGE_ACCEPT": 0x39,
    "TRANSFER_REJECT": 0x3A,
    "TRANSFER_BUSY": 0x3B,
    "CHUNK_OFFER": 0x3C,
    "CHUNK_ACCEPT": 0x3D,
    "RESUME_QUERY": 0x3E,
    "RESUME_STATE": 0x3F,
    "TRANSFER_FINALIZE": 0x40,
    "TRANSFER_ACCEPT": 0x41,
    "TRANSFER_ABORT": 0x42,
    "TRANSFER_ABORT_ACK": 0x43,
}

STAGE = {
    "OPEN": 1,
    "MANIFEST": 2,
    "CHUNK": 3,
    "FINAL": 4,
    "RESUME": 5,
    "ABORT": 6,
}

REJECT = {
    "LAYOUT": 1,
    "DIGEST": 2,
    "DUPLICATE": 3,
    "UNSUPPORTED": 4,
    "CAPACITY": 5,
    "STORAGE": 6,
    "EXPIRED": 7,
    "STATE": 8,
    "AUTHORITY": 9,
    "ABORT_DENIED": 10,
}

# Exact required vector IDs — gate inventories reject missing/extra/dup/sub.
REQUIRED_VECTOR_IDS: tuple[str, ...] = (
    "MF-CONSTANTS-PINNED",
    "MF-VERSION-CATALOG-INHERITANCE",
    "MF-CARRIER-MAPPING-MATRIX",
    "MF-PUBLICATION-OWNER-MATRIX",
    "MF-ROLE-BOUNDARIES",
    "MF-PRIVATE-API-SURFACE",
    "MF-FSM-STORAGE-SIDECAR-PROFILE",
    "MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT",
    "MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION",
    "MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL",
    "MF-NEG-ADMISSION-REV1-REV2-MIXED",
    "MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT",
    "MF-BUDGET-ARITHMETIC-REFERENCE",
    "MF-BUDGET-EMPTY-TRANSFER",
    "MF-BUDGET-OBSOLETE-80-REJECTED",
    "MF-BUDGET-RESTORATION-HASH",
    "MF-BUDGET-NRC1-LOGICAL-BYTES",
    "MF-BUDGET-FULL-MAX-WITH-REQID",
    "MF-POS-EMPTY-PAYLOAD",
    "MF-POS-ONE-BYTE",
    "MF-POS-EXACT-MULTIPLE-FINAL",
    "MF-POS-ONE-BYTE-FINAL",
    "MF-POS-MAX-PAYLOAD-37-CHUNKS",
    "MF-POS-TWO-PAGE-MANIFEST",
    "MF-POS-COMPLETION-RECEIPT-REPLAY",
    "MF-POS-REQID-CACHE-SAME-ID-STABLE",
    "MF-POS-REQID-NEW-ID-CURRENT-COMPLETE",
    "MF-POS-REQID-NRC1-LAYOUT-KAT",
    "MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41",
    "MF-POS-REQID-RETRY-BUDGET-SM",
    "MF-POS-REQID-REACHABLE-MAX-COUNT",
    "MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM",
    "MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY",
    "MF-POS-REQID-MAX-RETRY-TRACE",
    "MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX",
    "MF-POS-NM30-SCHEMA2-LAYOUT-KAT",
    "MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY",
    "MF-TX-HOST-TERMINAL-COLD-REBIND-HIT",
    "MF-NEG-HOST-TERMINAL-BIND-MATRIX",
    "MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT",
    "MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY",
    "MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE",
    "MF-NEG-PREADMISSION-POLICY-STATELESS",
    "MF-NEG-PREADMISSION-DEADLINE-STATELESS",
    "MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED",
    "MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE",
    "MF-TRACE-S1-S6-HAPPY-PATH",
    "MF-NEG-STALE-GENERATION",
    "MF-NEG-STALE-VERSION-SELECTED-2",
    "MF-NEG-MIXED-VERSION-PEER",
    "MF-NEG-RF-MAPPING-UNAVAILABLE",
    "MF-NEG-WIFI-MAPPING-UNAVAILABLE",
    "MF-NEG-NFL1-CONTROL-FORBIDDEN",
    "MF-NEG-DUPLICATE-CHUNK-CONFLICT",
    "MF-NEG-REORDER-GAP",
    "MF-NEG-DIGEST-CORRUPTION-REPAIRED",
    "MF-NEG-WHOLE-DIGEST-MISMATCH",
    "MF-NEG-EXPIRY-BOUNDARY-EQ",
    "MF-NEG-EXPIRY-BOUNDARY-BEFORE",
    "MF-NEG-ABORT-AFTER-CONTENT-VERIFIED",
    "MF-NEG-ABORT-RACE-FINALIZE-FIRST",
    "MF-NEG-ABORT-RACE-ABORT-FIRST",
    "MF-NEG-PARTIAL-APPLY-FORBIDDEN",
    "MF-NEG-FALSE-CUSTODY-BITMAP",
    "MF-NEG-RESOURCE-EXHAUSTION-KEYS",
    "MF-NEG-RESOURCE-EXHAUSTION-BYTES",
    "MF-NEG-FAIRNESS-TWO-OUTSTANDING",
    "MF-NEG-MAX-CHUNKS-PLUS-ONE",
    "MF-NEG-DEFAULT-OFF-POLICY",
    "MF-NEG-STORAGE-SIDECAR-COLLISION",
    "MF-NEG-REQID-BODY-CONFLICT",
    "MF-NEG-REQID-CACHE-FULL",
    "MF-NEG-REQID-DIGEST-OPEN-PREIMAGE",
    "MF-NEG-REQID-POST-RETENTION-EXPIRED",
    "MF-NEG-EPOCH-CHANGE-MID-TRANSFER",
    "MF-CU-STORAGE-BINDING-NEW",
    "MF-CU-STORAGE-BINDING-PARTIAL",
    "MF-CU-STORAGE-BINDING-EXTRA",
    "MF-CU-STORAGE-BINDING-THIRD",
    "MF-CU-STORAGE-BINDING-ABSENT",
    "MF-CU-RECEIVER-CHUNK-OLD",
    "MF-CU-RECEIVER-CHUNK-NEW",
    "MF-CU-RECEIVER-CHUNK-PARTIAL",
    "MF-CU-RECEIVER-CHUNK-EXTRA",
    "MF-CU-RECEIVER-CHUNK-THIRD",
    "MF-CU-RECEIVER-CHUNK-ABSENT",
    "MF-CU-TERMINAL-GROUP-OLD",
    "MF-CU-TERMINAL-GROUP-NEW",
    "MF-CU-TERMINAL-GROUP-PARTIAL",
    "MF-CU-TERMINAL-GROUP-EXTRA",
    "MF-CU-TERMINAL-GROUP-THIRD",
    "MF-CU-TERMINAL-GROUP-ABSENT",
    "MF-CU-TERMINAL-GROUP-BOTH",
    "MF-CU-NRC1-ABSENT-MID-TRANSFER",
    "MF-CU-NRC1-OLD",
    "MF-CU-NRC1-NEW",
    "MF-CU-NRC1-PARTIAL",
    "MF-CU-NRC1-EXTRA",
    "MF-CU-NRC1-THIRD",
    "MF-CU-NRC1-ABSENT-POST-TERMINAL",
    "MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX",
    "MF-TX-EXPIRY-MANDATORY-TOMBSTONE",
    "MF-POS-EXPIRY-SLOT-REUSE",
    "MF-TX-POWER-CUT-AFTER-CHUNK-FULL",
    "MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED",
    "MF-TX-POWER-CUT-DURING-TERMINAL",
    "MF-TX-RESUME-AFTER-RESTART",
    "MF-TX-CLEANUP-RETENTION-GC",
    "MF-TX-ROLLBACK-POLICY-OFF",
    "MF-TX-TERMINAL-CRASH-ACTIVE-ONLY",
    "MF-TX-TERMINAL-CRASH-NM30-ONLY",
    "MF-TX-EPOCH-CHANGE-TERMINAL",
    "MF-TX-REQID-CACHE-CRASH-RESTART",
    "MF-TX-REQID-TERMINAL-RESTART-LATE-DUP",
    "MF-INV-REQUIRED-IDS-INTEGRITY",
    "MF-GATE-SELF-TEST-PIN",
)

REQUIRED_GATE_CASES: tuple[str, ...] = REQUIRED_VECTOR_IDS


def u8(v: int) -> bytes:
    return struct.pack(">B", v)


def u16(v: int) -> bytes:
    return struct.pack(">H", v)


def u32(v: int) -> bytes:
    return struct.pack(">I", v)


def u64(v: int) -> bytes:
    return struct.pack(">Q", v)


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def derive_mfdt_storage_namespace(base_namespace: bytes) -> bytes:
    if not 1 <= len(base_namespace) <= 255:
        raise ValueError("base namespace")
    return MFDT_STORAGE_NAMESPACE_MAGIC + sha256(
        MFDT_STORAGE_NAMESPACE_DOMAIN
        + u16(len(base_namespace))
        + base_namespace
    )


def build_mfdt_storage_binding(base_namespace: bytes) -> bytes:
    if not 1 <= len(base_namespace) <= 255:
        raise ValueError("base namespace")
    total_length = MFDT_STORAGE_BINDING_FIXED_BYTES + len(base_namespace)
    value = (
        MFDT_STORAGE_BINDING_MAGIC
        + u16(MFDT_STORAGE_BINDING_SCHEMA)
        + u16(MFDT_STORAGE_BINDING_HEADER_BYTES)
        + u32(total_length)
        + u16(len(base_namespace))
        + u16(0)
        + sha256(
            MFDT_BASE_NAMESPACE_DOMAIN
            + u16(len(base_namespace))
            + base_namespace
        )
        + base_namespace
    )
    if len(value) != total_length - 4:
        raise AssertionError("binding framing")
    value += u32(crc32c(value))
    if len(value) != total_length:
        raise AssertionError("binding total")
    return value


def storage_sidecar_profile() -> dict[str, Any]:
    base = b"mfdt-runtime-owner-a"
    derived = derive_mfdt_storage_namespace(base)
    binding = build_mfdt_storage_binding(base)
    collision_base = derived
    collision_binding = build_mfdt_storage_binding(collision_base)
    return {
        "base_namespace_hex": hx(base),
        "base_namespace_length": len(base),
        "derived_namespace_hex": hx(derived),
        "derived_namespace_length": len(derived),
        "namespace_magic": MFDT_STORAGE_NAMESPACE_MAGIC.decode("ascii"),
        "namespace_derivation_domain":
            MFDT_STORAGE_NAMESPACE_DOMAIN.decode("ascii"),
        "namespace_preimage":
            "domain_ascii||base_length_u16be||base_namespace_exact",
        "storage_expected_schema": MFDT_STORAGE_EXPECTED_SCHEMA,
        "foundation_scanner_value_max": 4096,
        "sidecar_single_value_max": 65536,
        "binding_key_hex": hx(MFDT_STORAGE_BINDING_KEY),
        "binding_magic": MFDT_STORAGE_BINDING_MAGIC.decode("ascii"),
        "binding_schema": MFDT_STORAGE_BINDING_SCHEMA,
        "binding_header_bytes": MFDT_STORAGE_BINDING_HEADER_BYTES,
        "binding_fixed_bytes": MFDT_STORAGE_BINDING_FIXED_BYTES,
        "binding_value_hex": hx(binding),
        "binding_value_length": len(binding),
        "binding_crc32c_hex": f"{crc32c(binding[:-4]):08x}",
        "binding_base_digest_domain":
            MFDT_BASE_NAMESPACE_DOMAIN.decode("ascii"),
        "binding_base_digest_hex": hx(
            sha256(
                MFDT_BASE_NAMESPACE_DOMAIN
                + u16(len(base))
                + base
            )
        ),
        "collision_base_namespace_hex": hx(collision_base),
        "collision_binding_value_hex": hx(collision_binding),
        "collision_binding_differs": binding != collision_binding,
        "known_key_magics": ["NMS1", "NM3S", "NM3R", "NM30", "NRC1"],
        "active_record_schema": ACTIVE_RECORD_SCHEMA,
        "active_schema1_replay_eligible": False,
        "foreign_key_policy": "CORRUPT_FENCE",
        "missing_binding_policy": "CREATE_ONLY_IF_NAMESPACE_EMPTY",
        "host_transfer_keys_hard_max": 32,
        "host_total_keys_hard_max": 33,
        "esp_total_keys_hard_max": 32,
        "esp_total_logical_bytes_hard_max": 69632,
        "production_open_phase": "BEFORE_BEARER",
        "destroy_close_order": [
            "BEARER",
            "MFDT_SIDECAR",
            "FOUNDATION_STORAGE",
        ],
        "cross_namespace_atomic_commit_claimed": False,
        "foundation_large_value_skip_forbidden": True,
    }


def pattern(start: int, length: int) -> bytes:
    return bytes((start + i) & 0xFF for i in range(length))


def hx(value: bytes) -> str:
    return value.hex()


def checked_ceil_div(num: int, den: int) -> int:
    if den <= 0 or num < 0:
        raise ValueError("ceil_div")
    if num == 0:
        return 0
    return (num + den - 1) // den


def derive_geometry(total_length: int) -> dict[str, int]:
    if not 0 <= total_length <= MAX_CONTENT:
        raise ValueError("total_length")
    if total_length == 0:
        return {
            "total_length": 0,
            "chunk_count": 0,
            "manifest_page_count": 0,
            "chunk_size": CHUNK_SIZE,
        }
    chunk_count = checked_ceil_div(total_length, CHUNK_SIZE)
    if chunk_count > MAX_CHUNKS:
        raise ValueError("chunk_count")
    page_count = checked_ceil_div(chunk_count, ENTRIES_PER_PAGE)
    if page_count > MAX_PAGES:
        raise ValueError("page_count")
    return {
        "total_length": total_length,
        "chunk_count": chunk_count,
        "manifest_page_count": page_count,
        "chunk_size": CHUNK_SIZE,
    }


def chunk_range(total_length: int, index: int) -> tuple[int, int]:
    offset = CHUNK_SIZE * index
    length = min(CHUNK_SIZE, total_length - offset)
    if length <= 0:
        raise ValueError("chunk range")
    return offset, length


def content_bytes(total_length: int, seed: int = 0x40) -> bytes:
    return pattern(seed, total_length)


def build_entries(content: bytes) -> list[bytes]:
    total = len(content)
    if total == 0:
        return []
    geo = derive_geometry(total)
    entries: list[bytes] = []
    for index in range(geo["chunk_count"]):
        offset, length = chunk_range(total, index)
        chunk = content[offset : offset + length]
        entries.append(u16(index) + u16(length) + u32(offset) + sha256(chunk))
        assert len(entries[-1]) == ENTRY_BYTES
    return entries


DEFAULT_TARGET_ORDINAL = 3
DEFAULT_SOURCE_BINDING_EPOCH = 11
DEFAULT_SOURCE_MEMBERSHIP_EPOCH = 12
DEFAULT_TARGET_BINDING_EPOCH = 21
DEFAULT_TARGET_MEMBERSHIP_EPOCH = 22
DEFAULT_IDENTITY_FLAGS = 0x00000007
DEFAULT_SCHEMA_MAJOR = 1
DEFAULT_SCHEMA_MINOR = 0
DEFAULT_SERVICE_FAMILY = 2  # DESIRED_STATE
DEFAULT_APPLICATION_GENERATION = 7
DEFAULT_EVIDENCE_GRACE_MS = 5000
DEFAULT_REQUIRED_EVIDENCE = 3  # APPLIED

APPLICATION_BINDING_LAYOUT: tuple[tuple[str, int, int], ...] = (
    ("original_attempt_id", 234, 16),
    ("target_ordinal_u32", 250, 4),
    ("source_application_instance_id", 254, 16),
    ("source_device_id", 270, 16),
    ("source_installation_id", 286, 16),
    ("source_site_domain_id", 302, 16),
    ("source_binding_epoch_u64", 318, 8),
    ("source_membership_epoch_u64", 326, 8),
    ("source_identity_flags_u32", 334, 4),
    ("source_reserved_u32", 338, 4),
    ("target_application_instance_id", 342, 16),
    ("target_device_id", 358, 16),
    ("target_installation_id", 374, 16),
    ("target_site_domain_id", 390, 16),
    ("target_binding_epoch_u64", 406, 8),
    ("target_membership_epoch_u64", 414, 8),
    ("target_identity_flags_u32", 422, 4),
    ("target_reserved_u32", 426, 4),
    ("service_schema_major_u16", 430, 2),
    ("service_schema_minor_u16", 432, 2),
    ("service_family_u32", 434, 4),
    ("application_generation_u64", 438, 8),
    ("evidence_grace_ms_u64", 446, 8),
    ("required_evidence_u32", 454, 4),
    ("application_binding_flags_u32", 458, 4),
)


def derive_transfer_id(
    origin_transaction_id: bytes,
    target_runtime_id: bytes,
    target_ordinal: int,
) -> bytes:
    if len(origin_transaction_id) != 16 or len(target_runtime_id) != 16:
        raise ValueError("transfer id bind")
    result = bytearray(
        sha256(
            origin_transaction_id
            + target_runtime_id
            + u32(target_ordinal)
            + b"ninlil-mfdt-v1id"
        )[:16]
    )
    if result == ZERO16:
        result[15] = 1
    return bytes(result)


def transfer_ids(salt: int = 0) -> dict[str, bytes]:
    ids = {
        "origin_transaction_id": pattern(0x20 + salt, 16),
        "original_attempt_id": pattern(0x30 + salt, 16),
        "origin_event_id": ZERO16,
        "source_runtime_id": pattern(0x40 + salt, 16),
        "source_application_instance_id": pattern(0x50 + salt, 16),
        "source_device_id": pattern(0x60 + salt, 16),
        "source_installation_id": pattern(0x70 + salt, 16),
        "source_site_domain_id": pattern(0x80 + salt, 16),
        "target_runtime_id": pattern(0x90 + salt, 16),
        "target_application_instance_id": pattern(0xA0 + salt, 16),
        "target_device_id": pattern(0xB0 + salt, 16),
        "target_installation_id": pattern(0xC0 + salt, 16),
        "target_site_domain_id": pattern(0xD0 + salt, 16),
        "service_descriptor_digest": sha256(b"mfdt-service-descriptor" + bytes([salt])),
        "deadline_clock_epoch_id": pattern(0xE1 + salt, 16),
        "reservation_id": pattern(0x11 + salt, 16),
        "reservation_clock_epoch_id": pattern(0x31 + salt, 16),
        "receiver_evidence_id": pattern(0x51 + salt, 16),
        "authority_actor_id": pattern(0x71 + salt, 16),
    }
    ids["transfer_id"] = derive_transfer_id(
        ids["origin_transaction_id"],
        ids["target_runtime_id"],
        DEFAULT_TARGET_ORDINAL,
    )
    return ids


def encode_application_binding(
    ids: dict[str, bytes],
    *,
    service_family: int = DEFAULT_SERVICE_FAMILY,
    application_generation: int = DEFAULT_APPLICATION_GENERATION,
    evidence_grace_ms: int = DEFAULT_EVIDENCE_GRACE_MS,
) -> bytes:
    binding = (
        ids["original_attempt_id"]
        + u32(DEFAULT_TARGET_ORDINAL)
        + ids["source_application_instance_id"]
        + ids["source_device_id"]
        + ids["source_installation_id"]
        + ids["source_site_domain_id"]
        + u64(DEFAULT_SOURCE_BINDING_EPOCH)
        + u64(DEFAULT_SOURCE_MEMBERSHIP_EPOCH)
        + u32(DEFAULT_IDENTITY_FLAGS)
        + u32(0)
        + ids["target_application_instance_id"]
        + ids["target_device_id"]
        + ids["target_installation_id"]
        + ids["target_site_domain_id"]
        + u64(DEFAULT_TARGET_BINDING_EPOCH)
        + u64(DEFAULT_TARGET_MEMBERSHIP_EPOCH)
        + u32(DEFAULT_IDENTITY_FLAGS)
        + u32(0)
        + u16(DEFAULT_SCHEMA_MAJOR)
        + u16(DEFAULT_SCHEMA_MINOR)
        + u32(service_family)
        + u64(application_generation)
        + u64(evidence_grace_ms)
        + u32(DEFAULT_REQUIRED_EVIDENCE)
        + u32(0)
    )
    if len(binding) != APPLICATION_BINDING_BYTES:
        raise AssertionError("application binding")
    return binding


def encode_open(
    *,
    content: bytes,
    ids: dict[str, bytes],
    manifest_revision: int = 1,
    namespace: bytes = b"n",
    service: bytes = b"s",
    schema: bytes = b"x",
    absolute_effect_deadline_ms: int = 200000,
    deadline_clock_epoch_id: bytes | None = None,
    service_family: int = DEFAULT_SERVICE_FAMILY,
    application_generation: int = DEFAULT_APPLICATION_GENERATION,
    evidence_grace_ms: int = DEFAULT_EVIDENCE_GRACE_MS,
) -> tuple[bytes, bytes, list[bytes], dict[str, Any]]:
    geo = derive_geometry(len(content))
    entries = build_entries(content)
    whole = sha256(content)
    epoch = (
        deadline_clock_epoch_id
        if deadline_clock_epoch_id is not None
        else ids["deadline_clock_epoch_id"]
    )
    head = (
        ids["transfer_id"]
        + u32(manifest_revision)
        + u32(geo["total_length"])
        + u16(geo["chunk_size"])
        + u16(geo["chunk_count"])
        + u16(geo["manifest_page_count"])
        + u16(ENTRIES_PER_PAGE)
        + whole
        + ids["origin_transaction_id"]
        + ids["origin_event_id"]
        + ids["source_runtime_id"]
        + ids["target_runtime_id"]
        + u64(1)
        + u16(1)
        + ids["service_descriptor_digest"]
        + u16(len(namespace))
        + u16(len(service))
        + u16(len(schema))
        + u16(0)
        + epoch
        + u64(absolute_effect_deadline_ms)
    )
    assert len(head) == 202
    binding = encode_application_binding(
        ids,
        service_family=service_family,
        application_generation=application_generation,
        evidence_grace_ms=evidence_grace_ms,
    )
    text = namespace + service + schema
    digest_input = b"NM3-MANIFEST-V1" + head + binding + text + b"".join(entries)
    manifest_digest = sha256(digest_input)
    open_body = head + manifest_digest + binding + text
    assert OPEN_FIXED + len(text) == len(open_body)
    facts = {
        "total_length": geo["total_length"],
        "chunk_count": geo["chunk_count"],
        "manifest_page_count": geo["manifest_page_count"],
        "chunk_size": geo["chunk_size"],
        "open_body_length": len(open_body),
        "whole_content_sha256_hex": hx(whole),
        "manifest_digest_hex": hx(manifest_digest),
        "namespace": namespace.decode("ascii"),
        "service": service.decode("ascii"),
        "schema": schema.decode("ascii"),
        "manifest_revision": manifest_revision,
        "application_binding_hex": hx(binding),
        "application_binding_offset": OPEN_BASE_FIXED,
        "application_binding_length": APPLICATION_BINDING_BYTES,
        "text_offset": OPEN_FIXED,
        "target_ordinal": DEFAULT_TARGET_ORDINAL,
        "service_schema_major": DEFAULT_SCHEMA_MAJOR,
        "service_schema_minor": DEFAULT_SCHEMA_MINOR,
        "service_family": service_family,
        "application_generation": application_generation,
        "evidence_grace_ms": evidence_grace_ms,
        "required_evidence": DEFAULT_REQUIRED_EVIDENCE,
    }
    return open_body, manifest_digest, entries, facts


def bind52(transfer_id: bytes, revision: int, manifest_digest: bytes) -> bytes:
    return transfer_id + u32(revision) + manifest_digest


def encode_page(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    page_index: int,
    page_count: int,
    entries: list[bytes],
) -> tuple[bytes, bytes, dict[str, Any]]:
    first = page_index * ENTRIES_PER_PAGE
    if page_index + 1 < page_count:
        page_entries = entries[first : first + ENTRIES_PER_PAGE]
    else:
        page_entries = entries[first:]
    entry_count = len(page_entries)
    if page_count == 0 or entry_count == 0:
        raise ValueError("empty page")
    entry_bytes = b"".join(page_entries)
    pre = (
        transfer_id
        + u32(revision)
        + manifest_digest
        + u16(page_index)
        + u16(page_count)
        + u16(first)
        + u16(entry_count)
    )
    page_digest = sha256(
        b"NM3-PAGE-V1"
        + transfer_id
        + u32(revision)
        + manifest_digest
        + u16(page_index)
        + u16(page_count)
        + u16(first)
        + u16(entry_count)
        + entry_bytes
    )
    body = pre + page_digest + entry_bytes
    assert len(body) == 92 + 40 * entry_count
    return body, page_digest, {
        "page_index": page_index,
        "page_count": page_count,
        "first_chunk_index": first,
        "entry_count": entry_count,
        "page_digest_hex": hx(page_digest),
        "body_length": len(body),
    }


def encode_chunk_offer(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    content: bytes,
    chunk_index: int,
    chunk_count: int,
) -> tuple[bytes, dict[str, Any]]:
    offset, length = chunk_range(len(content), chunk_index)
    chunk = content[offset : offset + length]
    digest = sha256(chunk)
    body = (
        bind52(transfer_id, revision, manifest_digest)
        + u16(chunk_index)
        + u16(chunk_count)
        + u32(offset)
        + u16(length)
        + u16(0)
        + digest
        + chunk
    )
    assert len(body) == 96 + length
    return body, {
        "chunk_index": chunk_index,
        "chunk_count": chunk_count,
        "chunk_offset": offset,
        "chunk_length": length,
        "chunk_sha256_hex": hx(digest),
        "body_length": len(body),
        "chunk_bytes_hex": hx(chunk),
    }


def encode_open_accept(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    reservation_id: bytes,
    total_length: int,
    reservation_clock_epoch_id: bytes,
    reservation_not_after_ms: int,
    manifest_complete: int,
) -> bytes:
    return (
        bind52(transfer_id, revision, manifest_digest)
        + reservation_id
        + u32(total_length)
        + reservation_clock_epoch_id
        + u64(reservation_not_after_ms)
        + u8(manifest_complete)
        + bytes(3)
    )


def encode_page_accept(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    page_index: int,
    received_page_count: int,
    page_digest: bytes,
    reservation_id: bytes,
    manifest_complete: int,
) -> bytes:
    return (
        bind52(transfer_id, revision, manifest_digest)
        + u16(page_index)
        + u16(received_page_count)
        + page_digest
        + reservation_id
        + u8(manifest_complete)
        + bytes(3)
    )


def encode_chunk_accept(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    chunk_index: int,
    chunk_sha256: bytes,
) -> bytes:
    return (
        bind52(transfer_id, revision, manifest_digest)
        + u16(chunk_index)
        + u16(0)
        + chunk_sha256
    )


def encode_finalize(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    whole: bytes,
    total_length: int,
) -> bytes:
    return (
        bind52(transfer_id, revision, manifest_digest)
        + whole
        + u32(total_length)
        + u32(0)
    )


def encode_accept(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    whole: bytes,
    total_length: int,
    receiver_evidence_id: bytes,
    acceptance_record_generation: int,
    reservation_id: bytes,
) -> tuple[bytes, bytes]:
    pre = (
        bind52(transfer_id, revision, manifest_digest)
        + whole
        + u32(total_length)
        + receiver_evidence_id
        + u64(acceptance_record_generation)
        + reservation_id
    )
    digest = sha256(b"NM3-ACCEPT-V1" + pre)
    return pre + digest, digest


def encode_abort(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    reason: int,
    authority_actor_id: bytes,
    abort_generation: int,
) -> bytes:
    return (
        bind52(transfer_id, revision, manifest_digest)
        + u16(reason)
        + u16(0)
        + authority_actor_id
        + u32(abort_generation)
    )


def encode_abort_ack(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    abort_generation: int,
    final_state: int,
    tombstone_digest: bytes,
) -> bytes:
    return (
        bind52(transfer_id, revision, manifest_digest)
        + u32(abort_generation)
        + u16(final_state)
        + u16(0)
        + tombstone_digest
    )


def encode_resume_query(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    query_generation: int,
) -> bytes:
    return bind52(transfer_id, revision, manifest_digest) + u32(query_generation) + u32(0)


def encode_resume_state(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    query_generation: int,
    receiver_record_generation: int,
    bitmap: int,
    transfer_state: int,
) -> tuple[bytes, bytes]:
    pre = (
        bind52(transfer_id, revision, manifest_digest)
        + u32(query_generation)
        + u64(receiver_record_generation)
        + u64(bitmap)
        + u16(transfer_state)
        + u16(0)
    )
    assert len(pre) == 76
    digest = sha256(b"NM3-RESUME-V1" + pre)
    return pre + digest, digest


def encode_reject(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    stage: int,
    code: int,
    detail: int = 0,
) -> bytes:
    return bind52(transfer_id, revision, manifest_digest) + u16(stage) + u16(code) + u32(detail)


def publication_token(
    *,
    transfer_id: bytes,
    revision: int,
    manifest_digest: bytes,
    whole: bytes,
    total_length: int,
    receiver_evidence_id: bytes,
) -> bytes:
    return sha256(
        b"NM3-PUBLISH-V1"
        + bind52(transfer_id, revision, manifest_digest)
        + whole
        + u32(total_length)
        + receiver_evidence_id
    )[:16]


def application_evidence_digest(
    *,
    publication_token_v: bytes,
    origin_transaction_id: bytes,
    original_attempt_id: bytes,
    target_ordinal: int,
    evidence_stage: int,
    evidence_bytes: bytes,
) -> tuple[bytes, bytes]:
    if (
        len(publication_token_v) != 16
        or len(origin_transaction_id) != 16
        or len(original_attempt_id) != 16
    ):
        raise ValueError("application evidence bind")
    preimage = (
        APPLICATION_EVIDENCE_DOMAIN
        + publication_token_v
        + origin_transaction_id
        + original_attempt_id
        + u32(target_ordinal)
        + u32(evidence_stage)
        + u32(len(evidence_bytes))
        + evidence_bytes
    )
    return preimage, sha256(preimage)


def storage_key(kind: bytes, transfer_id: bytes) -> bytes:
    assert len(kind) == 4 and len(transfer_id) == 16
    return kind + transfer_id


def build_active_record(
    *,
    kind: bytes,
    owner_side: int,
    state_code: int,
    open_body: bytes,
    entries: list[bytes],
    content: bytes,
    ids: dict[str, bytes],
    manifest_digest: bytes,
    revision: int,
    record_generation: int,
    chunk_bitmap: int,
    page_bitmap: int,
    publication_state: int = 0,
    handoff_state: int = 0,
    accept_notified: int = 0,
    acceptance_record_generation: int = 0,
    acceptance_record_digest: bytes = ZERO32,
    publication_token_v: bytes = ZERO16,
    publication_evidence_digest: bytes = ZERO32,
    reservation_not_after_ms: int = 0,
    abort_generation: int = 0,
    abort_reason: int = 0,
    local_mono_ms: int = 100000,
    session_generation: int = 1,
) -> bytes:
    geo = derive_geometry(len(content))
    entry_blob = b"".join(entries)
    if len(entry_blob) != ENTRY_BYTES * geo["chunk_count"]:
        # Pad missing entries with zeros for partial manifest states.
        need = ENTRY_BYTES * geo["chunk_count"] - len(entry_blob)
        entry_blob = entry_blob + bytes(need)
    content_slots = content + bytes(geo["total_length"] - len(content))
    open_len = len(open_body)
    total_record = (
        HEADER_BYTES + open_len + len(entry_blob) + geo["total_length"] + 4
    )
    reservation_id = (
        ids["reservation_id"] if state_code not in (1,) or owner_side == 2 else ZERO16
    )
    if owner_side == 1 and state_code == 1:
        reservation_id = ZERO16
        res_epoch = ZERO16
        res_exp = 0
    else:
        res_epoch = ids["reservation_clock_epoch_id"] if reservation_id != ZERO16 else ZERO16
        res_exp = reservation_not_after_ms if reservation_id != ZERO16 else 0
    receiver_evidence = (
        ids["receiver_evidence_id"]
        if acceptance_record_generation != 0 or publication_state >= 1
        else ZERO16
    )
    if publication_state == 0 and acceptance_record_generation == 0:
        receiver_evidence = ZERO16
    header = bytearray(HEADER_BYTES)
    header[0:4] = kind
    header[4:6] = u16(ACTIVE_RECORD_SCHEMA)
    header[6:8] = u16(HEADER_BYTES)
    header[8:12] = u32(total_record)
    header[12] = owner_side
    header[13] = state_code
    header[14:16] = u16(0)
    header[16:32] = ids["transfer_id"]
    header[32:36] = u32(revision)
    header[36:68] = manifest_digest
    header[68:76] = u64(record_generation)
    header[76:84] = u64(acceptance_record_generation)
    header[84:86] = u16(open_len)
    header[86:88] = u16(ENTRY_BYTES * geo["chunk_count"])
    header[88:92] = u32(geo["total_length"])
    header[92:94] = u16(geo["chunk_count"])
    header[94:96] = u16(geo["manifest_page_count"])
    header[96:104] = u64(chunk_bitmap)
    header[104] = page_bitmap & 0xFF
    header[105] = 8
    header[106] = 1  # AFTER_RETENTION
    header[107] = publication_state
    header[108] = handoff_state
    header[109] = accept_notified
    header[110:112] = u16(0)
    header[112:128] = reservation_id
    header[128:144] = res_epoch
    header[144:152] = u64(res_exp)
    header[152:168] = receiver_evidence
    header[168:200] = acceptance_record_digest
    header[200:216] = ids["reservation_clock_epoch_id"]
    header[216:224] = u64(local_mono_ms)
    header[224:228] = u32(abort_generation)
    header[228:230] = u16(abort_reason)
    header[230:232] = u16(0)
    header[232:248] = ids["authority_actor_id"] if abort_generation else ZERO16
    header[248:264] = publication_token_v
    header[264:296] = publication_evidence_digest
    header[296:300] = u32(0)
    if not 1 <= session_generation <= 0xFFFFFFFF:
        raise ValueError("session_generation")
    header[300:304] = u32(session_generation)
    header[304:308] = u32(crc32c(bytes(header[0:304])))
    record = bytes(header) + open_body + entry_blob + content_slots
    record = record + u32(crc32c(record))
    assert len(record) == total_record
    return record


def build_nm30(
    *,
    ids: dict[str, bytes],
    revision: int,
    manifest_digest: bytes,
    terminal_state: int,
    terminal_reason: int,
    abort_generation: int,
    receiver_evidence_id: bytes,
    acceptance_record_digest: bytes,
    authority_actor_id: bytes,
    peer_endpoint_id: bytes | None = None,
    owner_role: int = 2,
    retention_ms: int = 500000,
) -> tuple[bytes, bytes]:
    if peer_endpoint_id is None:
        peer_endpoint_id = ids["source_runtime_id"]
    if len(peer_endpoint_id) != 16 or peer_endpoint_id == ZERO16:
        raise ValueError("peer_endpoint_id")
    if owner_role not in (1, 2):
        raise ValueError("owner_role")
    body = bytearray(NM30_BYTES)
    body[0:4] = b"NM30"
    body[4:6] = u16(2)
    body[6:8] = u16(NM30_BYTES)
    body[8:24] = ids["transfer_id"]
    body[24:28] = u32(revision)
    body[28:60] = manifest_digest
    body[60:62] = u16(terminal_state)
    body[62:64] = u16(terminal_reason)
    body[64:68] = u32(abort_generation)
    body[68:84] = receiver_evidence_id
    body[84:116] = acceptance_record_digest
    body[116:132] = authority_actor_id
    body[132:148] = ids["reservation_clock_epoch_id"]
    body[148:156] = u64(retention_ms)
    body[156:172] = peer_endpoint_id
    body[172] = owner_role
    body[173:176] = bytes(3)
    body[176:180] = u32(crc32c(bytes(body[0:176])))
    digest = sha256(bytes(body))
    return bytes(body), digest


def build_nm30_legacy_schema1(
    *,
    ids: dict[str, bytes],
    revision: int,
    manifest_digest: bytes,
    terminal_state: int,
    terminal_reason: int,
    abort_generation: int,
    receiver_evidence_id: bytes,
    acceptance_record_digest: bytes,
    authority_actor_id: bytes,
    retention_ms: int = 500000,
) -> bytes:
    """Legacy media fixture only; the canonical writer never calls this helper."""

    body = bytearray(NM30_LEGACY_SCHEMA1_BYTES)
    body[0:4] = b"NM30"
    body[4:6] = u16(1)
    body[6:8] = u16(NM30_LEGACY_SCHEMA1_BYTES)
    body[8:24] = ids["transfer_id"]
    body[24:28] = u32(revision)
    body[28:60] = manifest_digest
    body[60:62] = u16(terminal_state)
    body[62:64] = u16(terminal_reason)
    body[64:68] = u32(abort_generation)
    body[68:84] = receiver_evidence_id
    body[84:116] = acceptance_record_digest
    body[116:132] = authority_actor_id
    body[132:148] = ids["reservation_clock_epoch_id"]
    body[148:156] = u64(retention_ms)
    body[156:160] = bytes(4)
    body[160:164] = u32(crc32c(bytes(body[0:160])))
    return bytes(body)


def repair_record_crc(record: bytes) -> bytes:
    if len(record) < HEADER_BYTES + 4:
        raise ValueError("record")
    mutable = bytearray(record)
    # header crc
    mutable[304:308] = u32(crc32c(bytes(mutable[0:304])))
    # record crc
    mutable[-4:] = u32(crc32c(bytes(mutable[:-4])))
    return bytes(mutable)


def repair_nm30_crc(value: bytes) -> bytes:
    mutable = bytearray(value)
    if len(mutable) == NM30_BYTES and mutable[4:8] == u16(2) + u16(NM30_BYTES):
        mutable[176:180] = u32(crc32c(bytes(mutable[0:176])))
    elif (
        len(mutable) == NM30_LEGACY_SCHEMA1_BYTES
        and mutable[4:8] == u16(1) + u16(NM30_LEGACY_SCHEMA1_BYTES)
    ):
        mutable[160:164] = u32(crc32c(bytes(mutable[0:160])))
    else:
        raise ValueError("nm30 schema/length")
    return bytes(mutable)


NRC1_SLOT_BYTES = 208


def repair_nrc1_crc(value: bytes) -> bytes:
    if len(value) != NRC1_VALUE_BYTES:
        raise ValueError("nrc1 value length")
    mutable = bytearray(value)
    mutable[36:40] = u32(crc32c(bytes(mutable[0:36])))
    mutable[-4:] = u32(crc32c(bytes(mutable[:-4])))
    return bytes(mutable)


def retry_budget_sm() -> dict[str, Any]:
    """Normative retry_budget_remaining state machine (per-transfer, per-owner-side)."""

    return {
        "field": "retry_budget_remaining",
        "header_offset": 105,
        "scope": "per_transfer_per_owner_side",
        "not_scope": ["per_request_id", "per_stage", "cross_transfer"],
        "owner": "requestor_of_outbound_mfdt_control",
        "owner_sender_record": "NM3S",
        "owner_receiver_record": "NM3R",
        "initial_value": RETRY_BUDGET_MAX,
        "max_value": RETRY_BUDGET_MAX,
        "min_value": 0,
        "range_inclusive": [0, RETRY_BUDGET_MAX],
        "decrement_event": "timeout_retry_with_new_request_id",
        "decrement_requires_full_before_wire": True,
        "does_not_decrement": [
            "first_attempt_of_semantic_unit",
            "same_request_id_retransmit",
            "response_messages",
            "responder_hit_retransmit",
            "new_first_attempt_of_unfinished_stage",
        ],
        "exhaustion_remaining_eq_0": {
            "forbidden": ["new_request_id_timeout_retry"],
            "allowed": [
                "same_request_id_retransmit",
                "first_attempt_remaining_semantic_units",
                "first_attempt_new_abort_generation",
            ],
            "is_terminal": False,
            "is_nrc1_eviction": False,
            "is_automatic_abort": False,
        },
        "terminal_erase_with_active": True,
    }


def reachable_request_id_counts() -> dict[str, Any]:
    """Worst-case **peak** distinct request-ID occupancy in one NRC1 row.

    RESUME first-attempts are **per session generation** (RESUME_MAX=8). Reconnect is a
    fresh session generation. Without reclaim, two generations would need 73 slots
    (P0). Normative peak bound:

    - Every NRC1 slot binds `session_generation`.
    - Advancing session generation is a durable FULL that **reclaims RESUME-class
      slots** of all prior generations before admitting new RESUME first-attempts.
    - Non-RESUME slots (OPEN/PAGE/CHUNK/FINALIZE/ABORT/RETRY) are retained for the
      whole transfer lifetime including post-terminal until retention GC.
    - Peak occupancy = NON_RESUME + RESUME_MAX (one gen at a time) ≤ 72.

    The initial value is any non-zero u32. Lifetime may use at most
    SESSION_GEN_MAX_PER_TRANSFER distinct consecutive values; total RESUME
    first-attempts across lifetime ≤ SESSION_GEN_MAX_PER_TRANSFER * RESUME_MAX,
    but peak ≤ 65.
    """

    first_open = 1
    first_pages = MAX_PAGES
    first_chunks = MAX_CHUNKS
    first_resume_per_gen = RESUME_MAX
    first_finalize = 1
    first_abort = ABORT_GEN_MAX
    retry_new_ids = RETRY_BUDGET_MAX
    non_resume = (
        first_open
        + first_pages
        + first_chunks
        + first_finalize
        + first_abort
        + retry_new_ids
    )  # 57
    # Peak (with reclaim): one RESUME gen at a time.
    n_complete_peak = non_resume + first_resume_per_gen  # 65
    n_abort_peak = (
        first_open
        + first_pages
        + first_chunks
        + first_abort
        + retry_new_ids
        + first_resume_per_gen
    )  # 64
    # Illegal no-reclaim 2-gen envelope (must be rejected by capacity gate).
    illegal_two_gen_no_reclaim = non_resume + first_resume_per_gen * SESSION_GEN_MAX_PER_TRANSFER
    happy_first = first_open + first_pages + first_chunks + first_finalize
    naive_union = (
        first_open
        + first_pages
        + first_chunks
        + first_resume_per_gen
        + first_finalize
        + first_abort
    )
    reachable = max(n_complete_peak, n_abort_peak)
    return {
        "first_open": first_open,
        "first_pages": first_pages,
        "first_chunks": first_chunks,
        "first_resume_per_session_generation": first_resume_per_gen,
        "first_resume": first_resume_per_gen,  # alias: peak one gen
        "first_finalize": first_finalize,
        "first_abort": first_abort,
        "retry_new_ids": retry_new_ids,
        "retry_budget_max": RETRY_BUDGET_MAX,
        "session_gen_max_per_transfer": SESSION_GEN_MAX_PER_TRANSFER,
        "session_generation_initial_domain": "u32_nonzero",
        "session_generation_numeric_max": 0xFFFFFFFF,
        "session_generation_advance": "current_plus_1_no_wrap",
        "session_generation_anchor": "initial_non_resume_open_accept_slot",
        "session_generation_allowed_slot_window": "current_or_exact_prior",
        "non_resume_ids": non_resume,
        "n_complete": n_complete_peak,
        "n_abort": n_abort_peak,
        "n_complete_peak": n_complete_peak,
        "n_abort_peak": n_abort_peak,
        "illegal_two_gen_no_reclaim": illegal_two_gen_no_reclaim,
        "illegal_two_gen_exceeds_72": illegal_two_gen_no_reclaim > 72,
        "resume_reclaim_on_session_gen_advance": True,
        "session_generation_bound_on_slot": True,
        "reachable_max": reachable,
        "happy_first": happy_first,
        "naive_union": naive_union,
        "naive_union_is_single_path": False,
        "finalize_abort_success_exclusive": True,
        "denied_abort_after_content_verified_consumes_slot": True,
        "formula_complete_peak": "NON_RESUME(57)+RESUME_PER_GEN(8)=65",
        "formula_lifetime_resume_attempts": "SESSION_GEN_MAX*RESUME_MAX (peak still 65 with reclaim)",
        "formula_complete": "1+MAX_PAGES+MAX_CHUNKS+RESUME_PER_GEN+FINALIZE+ABORT_GEN+RETRY",
        "formula_abort": "1+MAX_PAGES+MAX_CHUNKS+RESUME_PER_GEN+ABORT_GEN+RETRY",
    }


# Capacity derived from peak occupancy (with session-gen RESUME reclaim).
_REACH = reachable_request_id_counts()
NRC1_HAPPY_PATH_MAX_IDS = int(_REACH["happy_first"])  # 41
NRC1_N_COMPLETE = int(_REACH["n_complete"])  # 65 peak
NRC1_N_ABORT = int(_REACH["n_abort"])  # 64 peak
NRC1_REACHABLE_MAX_IDS = int(_REACH["reachable_max"])  # 65 peak
NRC1_NAIVE_UNION_IDS = int(_REACH["naive_union"])
NRC1_SLOT_COUNT = 72
NRC1_VALUE_BYTES = 40 + NRC1_SLOT_BYTES * NRC1_SLOT_COUNT + 4  # 15020
NRC1_MAX_RESPONSE = 160
NRC1_LOGICAL_BYTES = 16 + 20 + NRC1_VALUE_BYTES  # 15056
NRC1_CAPACITY_SPARE = NRC1_SLOT_COUNT - NRC1_REACHABLE_MAX_IDS  # 7
NRC1_MIN_LIFECYCLE_IDS = NRC1_REACHABLE_MAX_IDS
ACTIVE_ROW_LOGICAL_BYTES_MAX = 16 + KEY_BYTES + ACTIVE_VALUE_MAX  # 35247
ACTIVE_REPLACEMENT_BEGIN_FINAL_LOGICAL_BYTES_MAX = (
    2 * ACTIVE_ROW_LOGICAL_BYTES_MAX
)  # 70494
TERMINAL_ROW_LOGICAL_BYTES = 16 + KEY_BYTES + NM30_BYTES  # 216
ACTIVE_GROUP_LOGICAL_BYTES = ACTIVE_ROW_LOGICAL_BYTES_MAX + NRC1_LOGICAL_BYTES  # 50303
TERMINAL_GROUP_LOGICAL_BYTES = TERMINAL_ROW_LOGICAL_BYTES + NRC1_LOGICAL_BYTES  # 15272
ADMISSION_RESERVED_LOGICAL_BYTES = (
    ACTIVE_ROW_LOGICAL_BYTES_MAX
    + NRC1_LOGICAL_BYTES
    + TERMINAL_ROW_LOGICAL_BYTES
)  # 50519
HOST_FOUR_ACTIVE_COMMITTED_LOGICAL_BYTES = (
    HOST_SLOT_COUNT * ACTIVE_GROUP_LOGICAL_BYTES
)  # 201212
HOST_COMMITTED_LOGICAL_BYTES_HARD_MAX = (
    HOST_FOUR_ACTIVE_COMMITTED_LOGICAL_BYTES
    + (16 - HOST_SLOT_COUNT) * TERMINAL_GROUP_LOGICAL_BYTES
)  # 384476
HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_HARD_MAX = (
    HOST_COMMITTED_LOGICAL_BYTES_HARD_MAX + ACTIVE_GROUP_LOGICAL_BYTES
)  # 434779
assert NRC1_SLOT_COUNT >= NRC1_REACHABLE_MAX_IDS
assert NRC1_N_COMPLETE == 65 and NRC1_N_ABORT == 64 and NRC1_REACHABLE_MAX_IDS == 65
assert int(_REACH["illegal_two_gen_no_reclaim"]) == 73
assert int(_REACH["illegal_two_gen_no_reclaim"]) > NRC1_SLOT_COUNT


def request_body_digest(message_type: int, body: bytes) -> bytes:
    """Exact preimage: type_u8 || body_len_u16be || body (OPEN included; no BIND52 strip)."""

    if message_type < 0 or message_type > 0xFF:
        raise ValueError("type")
    if len(body) > 0xFFFF:
        raise ValueError("body")
    return sha256(bytes([message_type & 0xFF]) + u16(len(body)) + body)


def nrc1_key(transfer_id: bytes) -> bytes:
    assert len(transfer_id) == 16
    return b"NRC1" + transfer_id


def nrc1_empty_slot() -> bytes:
    return bytes(NRC1_SLOT_BYTES)


def nrc1_slot(
    *,
    request_id: int,
    session_generation: int,
    request_body_digest: bytes,
    response_type: int,
    response_body: bytes,
) -> bytes:
    if not 1 <= request_id <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("request_id")
    if len(request_body_digest) != 32:
        raise ValueError("digest")
    if not 1 <= session_generation <= 0xFFFFFFFF:
        raise ValueError("session_generation")
    if len(response_body) == 0 or len(response_body) > NRC1_MAX_RESPONSE:
        raise ValueError("response length")
    body = response_body + bytes(NRC1_MAX_RESPONSE - len(response_body))
    return (
        struct.pack(">Q", request_id)
        + u32(session_generation)
        + request_body_digest
        + u16(response_type)
        + u16(len(response_body))
        + body
    )


def build_nrc1_value(
    *,
    transfer_id: bytes,
    session_generation: int,
    slots: list[bytes],
    next_insert_seq: int,
) -> bytes:
    if len(transfer_id) != 16:
        raise ValueError("tid")
    if len(slots) > NRC1_SLOT_COUNT:
        raise ValueError("slots")
    filled = list(slots) + [nrc1_empty_slot() for _ in range(NRC1_SLOT_COUNT - len(slots))]
    occupied = sum(1 for s in filled if s[0:8] != bytes(8))
    head = (
        b"NRC1"
        + u16(1)
        + u16(NRC1_VALUE_BYTES)
        + transfer_id
        + u32(session_generation)
        + u16(NRC1_SLOT_COUNT)
        + u16(occupied)
        + u32(next_insert_seq)
    )
    assert len(head) == 36
    head = head + u32(crc32c(head))
    assert len(head) == 40
    value = head + b"".join(filled)
    value = value + u32(crc32c(value))
    assert len(value) == NRC1_VALUE_BYTES
    return value


def family_of(vector_id: str) -> str:
    if vector_id.startswith("MF-POS-"):
        return "positive"
    if vector_id.startswith("MF-NEG-"):
        return "negative"
    if vector_id.startswith("MF-CU-"):
        return "commit_unknown"
    if vector_id.startswith("MF-TX-"):
        return "transcript"
    if vector_id.startswith("MF-BUDGET-"):
        return "budget"
    if vector_id.startswith("MF-FSM-") or vector_id.startswith("MF-TRACE-"):
        return "catalog"
    if vector_id in {
        "MF-CONSTANTS-PINNED",
        "MF-VERSION-CATALOG-INHERITANCE",
        "MF-CARRIER-MAPPING-MATRIX",
        "MF-PUBLICATION-OWNER-MATRIX",
        "MF-ROLE-BOUNDARIES",
        "MF-PRIVATE-API-SURFACE",
        "MF-INV-REQUIRED-IDS-INTEGRITY",
        "MF-GATE-SELF-TEST-PIN",
    }:
        return "catalog"
    return "other"


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def authority_material(entry: dict[str, Any]) -> dict[str, Any]:
    """Canonical ID↔semantics binding material (shared with independent gates)."""

    material: dict[str, Any] = {
        "id": entry["id"],
        "family": family_of(entry["id"]),
        "expected": entry["expected"],
    }
    if "fixture" in entry:
        # Complete fixture binding: every byte artifact participates in the
        # authority fingerprint (not digest pins alone).
        material["fixture"] = entry["fixture"]
    if "old_rows" in entry:
        material["commit_unknown"] = {
            "group": entry.get("group"),
            "old_rows": entry.get("old_rows"),
            "new_rows": entry.get("new_rows"),
            "observed_rows": entry.get("observed_rows"),
        }
    skip = {
        "id",
        "expected",
        "fixture",
        "old_rows",
        "new_rows",
        "observed_rows",
        "authority_fingerprint_hex",
        "family",
    }
    for key in sorted(entry.keys()):
        if key in skip:
            continue
        material[key] = entry[key]
    return material


def authority_fingerprint(entry: dict[str, Any]) -> str:
    return hx(sha256(stable_json(authority_material(entry)).encode("utf-8")))


def vector(
    vector_id: str,
    *,
    expected: dict[str, Any],
    **fields: Any,
) -> dict[str, Any]:
    entry = {"id": vector_id, "family": family_of(vector_id), "expected": expected}
    entry.update(fields)
    entry["authority_fingerprint_hex"] = authority_fingerprint(entry)
    return entry


def transfer_fixture(total_length: int, salt: int = 0) -> dict[str, Any]:
    ids = transfer_ids(salt)
    content = content_bytes(total_length, seed=0x40 + salt)
    open_body, manifest_digest, entries, facts = encode_open(content=content, ids=ids)
    pages: list[dict[str, Any]] = []
    page_count = facts["manifest_page_count"]
    for page_index in range(page_count):
        body, page_digest, page_facts = encode_page(
            transfer_id=ids["transfer_id"],
            revision=1,
            manifest_digest=manifest_digest,
            page_index=page_index,
            page_count=page_count,
            entries=entries,
        )
        pages.append(
            {
                "body_hex": hx(body),
                "page_digest_hex": hx(page_digest),
                **page_facts,
            }
        )
    chunks: list[dict[str, Any]] = []
    for index in range(facts["chunk_count"]):
        body, chunk_facts = encode_chunk_offer(
            transfer_id=ids["transfer_id"],
            revision=1,
            manifest_digest=manifest_digest,
            content=content,
            chunk_index=index,
            chunk_count=facts["chunk_count"],
        )
        chunks.append({"body_hex": hx(body), **chunk_facts})
    whole = bytes.fromhex(facts["whole_content_sha256_hex"])
    reservation_not_after = 100000 + RESERVATION_LIFETIME_MS
    open_accept = encode_open_accept(
        transfer_id=ids["transfer_id"],
        revision=1,
        manifest_digest=manifest_digest,
        reservation_id=ids["reservation_id"],
        total_length=total_length,
        reservation_clock_epoch_id=ids["reservation_clock_epoch_id"],
        reservation_not_after_ms=reservation_not_after,
        manifest_complete=1 if total_length == 0 else 0,
    )
    page_accepts: list[dict[str, Any]] = []
    for page in pages:
        complete = 1 if page["page_index"] + 1 == page_count else 0
        body = encode_page_accept(
            transfer_id=ids["transfer_id"],
            revision=1,
            manifest_digest=manifest_digest,
            page_index=page["page_index"],
            received_page_count=page["page_index"] + 1,
            page_digest=bytes.fromhex(page["page_digest_hex"]),
            reservation_id=ids["reservation_id"],
            manifest_complete=complete,
        )
        page_accepts.append(
            {
                "body_hex": hx(body),
                "page_index": page["page_index"],
                "manifest_complete": complete,
                "body_length": len(body),
            }
        )
    chunk_accepts: list[dict[str, Any]] = []
    for chunk in chunks:
        body = encode_chunk_accept(
            transfer_id=ids["transfer_id"],
            revision=1,
            manifest_digest=manifest_digest,
            chunk_index=chunk["chunk_index"],
            chunk_sha256=bytes.fromhex(chunk["chunk_sha256_hex"]),
        )
        chunk_accepts.append(
            {
                "body_hex": hx(body),
                "chunk_index": chunk["chunk_index"],
                "body_length": len(body),
            }
        )
    finalize = encode_finalize(
        transfer_id=ids["transfer_id"],
        revision=1,
        manifest_digest=manifest_digest,
        whole=whole,
        total_length=total_length,
    )
    accept_body, accept_digest = encode_accept(
        transfer_id=ids["transfer_id"],
        revision=1,
        manifest_digest=manifest_digest,
        whole=whole,
        total_length=total_length,
        receiver_evidence_id=ids["receiver_evidence_id"],
        acceptance_record_generation=100,
        reservation_id=ids["reservation_id"],
    )
    pub = publication_token(
        transfer_id=ids["transfer_id"],
        revision=1,
        manifest_digest=manifest_digest,
        whole=whole,
        total_length=total_length,
        receiver_evidence_id=ids["receiver_evidence_id"],
    )
    full_bitmap = (1 << facts["chunk_count"]) - 1 if facts["chunk_count"] else 0
    full_page_bitmap = (1 << page_count) - 1 if page_count else 0
    receiver_verified = build_active_record(
        kind=b"NM3R",
        owner_side=2,
        state_code=36,
        open_body=open_body,
        entries=entries,
        content=content,
        ids=ids,
        manifest_digest=manifest_digest,
        revision=1,
        record_generation=100,
        chunk_bitmap=full_bitmap,
        page_bitmap=full_page_bitmap,
        publication_state=1,
        acceptance_record_generation=100,
        acceptance_record_digest=accept_digest,
        publication_token_v=pub,
        reservation_not_after_ms=reservation_not_after,
    )
    nm30, tombstone_digest = build_nm30(
        ids=ids,
        revision=1,
        manifest_digest=manifest_digest,
        terminal_state=1,
        terminal_reason=0,
        abort_generation=0,
        receiver_evidence_id=ids["receiver_evidence_id"],
        acceptance_record_digest=accept_digest,
        authority_actor_id=ZERO16,
    )
    return {
        "ids": {k: hx(v) for k, v in ids.items()},
        "content_hex": hx(content),
        "content_sha256_hex": hx(whole),
        "open_body_hex": hx(open_body),
        "manifest_digest_hex": hx(manifest_digest),
        "entries_hex": [hx(e) for e in entries],
        "facts": facts,
        "pages": pages,
        "page_accepts": page_accepts,
        "chunks": chunks,
        "chunk_accepts": chunk_accepts,
        "open_accept_hex": hx(open_accept),
        "open_accept_length": len(open_accept),
        "finalize_hex": hx(finalize),
        "finalize_length": len(finalize),
        "transfer_accept_hex": hx(accept_body),
        "transfer_accept_length": len(accept_body),
        "acceptance_record_digest_hex": hx(accept_digest),
        "publication_token_hex": hx(pub),
        "receiver_content_verified_key_hex": hx(storage_key(b"NM3R", ids["transfer_id"])),
        "receiver_content_verified_value_hex": hx(receiver_verified),
        "receiver_content_verified_sha256_hex": hx(sha256(receiver_verified)),
        "nm30_key_hex": hx(storage_key(b"NM30", ids["transfer_id"])),
        "nm30_value_hex": hx(nm30),
        "tombstone_digest_hex": hx(tombstone_digest),
        "reservation_not_after_ms": reservation_not_after,
        "full_chunk_bitmap": full_bitmap,
        "full_page_bitmap": full_page_bitmap,
    }


def budget_block() -> dict[str, Any]:
    required_rx = RECEIVER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY
    required_tx = SENDER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY
    groups = {
        "receiver": {
            "G_R_OPEN": 1,
            "G_R_PAGE": 2,
            "G_R_CHUNK": 37,
            "G_R_CONTENT": 1,
            "G_R_ACCEPT": 1,
            "G_R_HANDOFF": 1,
            "G_R_TERMINAL": 1,  # active erase + NM30 put; NRC1 retained whole lifetime
            "G_R_RESUME": RECEIVER_FULLS_RESUME,
            "G_R_REQID_CACHE": RECEIVER_FULLS_REQID_CACHE,
            "G_R_RETRY_BUDGET": RECEIVER_FULLS_RETRY_BUDGET,
            "G_R_SESSION_GEN": RECEIVER_FULLS_SESSION_GEN,
        },
        "sender": {
            "G_S_OPEN": 1,
            "G_S_OPEN_RX": 1,
            "G_S_MANIFEST": 1,
            "G_S_CHUNK": 37,
            "G_S_ACCEPT": 1,
            "G_S_TERMINAL": 1,  # active erase + NM30 put; NRC1 retained whole lifetime
            "G_S_RESUME": SENDER_FULLS_RESUME,
            "G_S_REQID_CACHE": SENDER_FULLS_REQID_CACHE,
            "G_S_RETRY_BUDGET": SENDER_FULLS_RETRY_BUDGET,
            "G_S_SESSION_GEN": SENDER_FULLS_SESSION_GEN,
        },
        "empty_receiver": {
            "G_R_OPEN": 1,
            "G_R_CONTENT": 1,
            "G_R_ACCEPT": 1,
            "G_R_HANDOFF": 1,
            "G_R_TERMINAL": 1,
        },
        "empty_sender": {
            "G_S_OPEN": 1,
            "G_S_OPEN_RX": 1,
            "G_S_MANIFEST": 1,
            "G_S_ACCEPT": 1,
            "G_S_TERMINAL": 1,
        },
    }
    assert sum(groups["receiver"].values()) == RECEIVER_FULLS_MAX
    assert sum(groups["sender"].values()) == SENDER_FULLS_MAX
    assert sum(groups["empty_receiver"].values()) == RECEIVER_FULLS_EMPTY
    assert sum(groups["empty_sender"].values()) == SENDER_FULLS_EMPTY
    restoration = {
        "receiver_groups": groups["receiver"],
        "sender_groups": groups["sender"],
        "receiver_fulls_max": RECEIVER_FULLS_MAX,
        "sender_fulls_max": SENDER_FULLS_MAX,
        "obsolete_fulls_day": OBSOLETE_FULLS_DAY,
        "reference_transfers_day": REF_MAXSIZE_TRANSFERS_DAY,
        "required_receiver_fulls_reference": required_rx,
        "required_sender_fulls_reference": required_tx,
        "obsolete_infeasible": required_rx > OBSOLETE_FULLS_DAY,
    }
    restoration_canonical = json.dumps(
        restoration, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "groups": groups,
        "receiver_fulls_max_transfer": RECEIVER_FULLS_MAX,
        "sender_fulls_max_transfer": SENDER_FULLS_MAX,
        "receiver_fulls_empty_transfer": RECEIVER_FULLS_EMPTY,
        "sender_fulls_empty_transfer": SENDER_FULLS_EMPTY,
        "obsolete_rejected_mf_fulls_per_day": OBSOLETE_FULLS_DAY,
        "planned_mf_maxsize_transfers_per_day_reference": REF_MAXSIZE_TRANSFERS_DAY,
        "required_receiver_fulls_for_reference": required_rx,
        "required_sender_fulls_for_reference": required_tx,
        "obsolete_80_feasible_for_reference_receiver": False,
        "restoration_object": restoration,
        "restoration_sha256_hex": hx(sha256(restoration_canonical)),
        "active_row_logical_bytes_max": ACTIVE_ROW_LOGICAL_BYTES_MAX,
        "active_replacement_begin_final_logical_bytes_max":
            ACTIVE_REPLACEMENT_BEGIN_FINAL_LOGICAL_BYTES_MAX,
        "nrc1_row_logical_bytes": NRC1_LOGICAL_BYTES,  # 15056
        "terminal_row_logical_bytes": TERMINAL_ROW_LOGICAL_BYTES,
        "admission_reserved_entries": 3,  # active + NRC1 + terminal staging
        "admission_reserved_logical_bytes": ADMISSION_RESERVED_LOGICAL_BYTES,
        "post_terminal_retained_entries": 2,  # NM30 + NRC1 until GC
        "post_terminal_retained_logical_bytes": TERMINAL_GROUP_LOGICAL_BYTES,
        "nrc1_value_bytes": NRC1_VALUE_BYTES,
        "nrc1_slot_count": NRC1_SLOT_COUNT,
        "nrc1_reachable_max_ids": NRC1_REACHABLE_MAX_IDS,
        "nrc1_n_complete": NRC1_N_COMPLETE,
        "nrc1_n_abort": NRC1_N_ABORT,
        "nrc1_timeout_retry_max": TIMEOUT_RETRY_MAX,
        "nrc1_capacity_spare": NRC1_CAPACITY_SPARE,
        "nrc1_happy_path_max_ids": NRC1_HAPPY_PATH_MAX_IDS,
        "nrc1_retained_until_gc": True,
        "receiver_fulls_base": RECEIVER_FULLS_BASE,
        "receiver_fulls_resume": RECEIVER_FULLS_RESUME,
        "receiver_fulls_reqid_cache": RECEIVER_FULLS_REQID_CACHE,
        "receiver_fulls_retry_budget": RECEIVER_FULLS_RETRY_BUDGET,
        "receiver_fulls_session_gen": RECEIVER_FULLS_SESSION_GEN,
        "sender_fulls_base": SENDER_FULLS_BASE,
        "sender_fulls_resume": SENDER_FULLS_RESUME,
        "sender_fulls_reqid_cache": SENDER_FULLS_REQID_CACHE,
        "sender_fulls_retry_budget": SENDER_FULLS_RETRY_BUDGET,
        "sender_fulls_session_gen": SENDER_FULLS_SESSION_GEN,
        "session_gen_max_per_transfer": SESSION_GEN_MAX_PER_TRANSFER,
        "namespace_keys_hard_max": 32,
        "namespace_logical_bytes_hard_max": 69632,
        "host_slot_count": HOST_SLOT_COUNT,
        "host_active_group_logical_bytes": ACTIVE_GROUP_LOGICAL_BYTES,
        "host_terminal_group_logical_bytes": TERMINAL_GROUP_LOGICAL_BYTES,
        "host_four_active_committed_logical_bytes":
            HOST_FOUR_ACTIVE_COMMITTED_LOGICAL_BYTES,
        "host_tracked_transfer_groups_max": HOST_TERMINAL_CATALOG_ENTRIES,
        "host_committed_logical_bytes_hard_max":
            HOST_COMMITTED_LOGICAL_BYTES_HARD_MAX,
        "host_serialized_full_staging_logical_bytes_max":
            ACTIVE_GROUP_LOGICAL_BYTES,
        "host_begin_final_union_logical_bytes_hard_max":
            HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_HARD_MAX,
        "host_committed_keys_hard_max": 32,
        "host_serialized_full_staging_row_images_max": 2,
    }


def constants_block() -> dict[str, Any]:
    return {
        "max_content_bytes": MAX_CONTENT,
        "chunk_size": CHUNK_SIZE,
        "max_chunk_count": MAX_CHUNKS,
        "manifest_entry_bytes": ENTRY_BYTES,
        "entries_per_page": ENTRIES_PER_PAGE,
        "max_manifest_pages": MAX_PAGES,
        "open_base_fixed_bytes": OPEN_BASE_FIXED,
        "application_binding_bytes": APPLICATION_BINDING_BYTES,
        "open_fixed_bytes": OPEN_FIXED,
        "open_text_offset": OPEN_FIXED,
        "open_body_min": OPEN_MIN,
        "open_body_max": OPEN_MAX,
        "active_header_bytes": HEADER_BYTES,
        "active_record_schema": ACTIVE_RECORD_SCHEMA,
        "active_schema1_replay_eligible": False,
        "active_value_max": ACTIVE_VALUE_MAX,
        "nm30_value_bytes": NM30_BYTES,
        "nm30_schema": 2,
        "nm30_peer_endpoint_id_offset": 156,
        "nm30_peer_endpoint_id_bytes": 16,
        "nm30_owner_role_offset": 172,
        "nm30_reserved_offset": 173,
        "nm30_reserved_bytes": 3,
        "nm30_crc_offset": 176,
        "nm30_crc_preimage_bytes": 176,
        "nm30_session_cookie_durable": False,
        "nm30_legacy_schema1_value_bytes": NM30_LEGACY_SCHEMA1_BYTES,
        "nm30_legacy_schema1_replay_eligible": False,
        "storage_key_bytes": KEY_BYTES,
        "ncl1_body_max": NCL1_BODY_MAX,
        "workspace_bytes": WORKSPACE_BYTES,
        "workspace_scope": "per_active_transfer_slot",
        "host_slot_count": HOST_SLOT_COUNT,
        "host_coordinator_bytes": HOST_COORDINATOR_BYTES,
        "host_terminal_catalog_entries": HOST_TERMINAL_CATALOG_ENTRIES,
        "host_terminal_catalog_entry_bytes": HOST_TERMINAL_CATALOG_ENTRY_BYTES,
        "host_terminal_catalog_bytes": HOST_TERMINAL_CATALOG_BYTES,
        "host_control_outbox_metadata_bytes": HOST_CONTROL_OUTBOX_METADATA_BYTES,
        "host_control_outbox_bytes": HOST_CONTROL_OUTBOX_BYTES,
        "host_control_nrc1_scratch_bytes": HOST_CONTROL_NRC1_SCRATCH_BYTES,
        "host_control_nm30_scratch_bytes": HOST_CONTROL_NM30_SCRATCH_BYTES,
        "host_control_recovery_reserved_bytes": HOST_CONTROL_RECOVERY_RESERVED_BYTES,
        "host_control_arena_bytes": HOST_CONTROL_ARENA_BYTES,
        "host_control_route_sentinel": HOST_CONTROL_ROUTE_SENTINEL,
        "host_owner_workspace_bytes": HOST_OWNER_WORKSPACE_BYTES,
        "active_record_schema": ACTIVE_RECORD_SCHEMA,
        "active_schema1_replay_eligible": False,
        "open_growth_bytes_redistributed_within_each_slot": APPLICATION_BINDING_BYTES,
        "workspace_growth_bytes": 0,
        "reservation_lifetime_ms": RESERVATION_LIFETIME_MS,
        "retention_ms": RETENTION_MS,
        "resume_query_max": RESUME_MAX,
        "abort_generation_max": ABORT_GEN_MAX,
        "timeout_retry_max": TIMEOUT_RETRY_MAX,
        "retry_budget_remaining_max": RETRY_BUDGET_MAX,
        "retry_budget_remaining_min": 0,
        "retry_budget_scope": "per_transfer_per_owner_side",
        "retry_budget_owner": "requestor_of_outbound_mfdt_control",
        "retry_budget_initial": RETRY_BUDGET_MAX,
        "retry_budget_decrement_event": "timeout_retry_with_new_request_id",
        "retry_budget_header_offset": 105,
        "esp_active_transfers_max": 1,
        "host_active_transfers_max": 4,
        "host_owner_full_transactions_max": 1,
        "host_scheduler_next_slot_initial": 0,
        "host_scheduler_scan_bound": 4,
        "host_peer_unpaid_chunk_offer_max": 1,
        "host_fair_selection_bound": 4,
        "active_header_session_generation_offset": 300,
        "nrc1_header_session_generation_offset": 24,
        "terminal_session_generation_authority": "NRC1_header_offset_24",
        "message_types": MSG,
        "stages": STAGE,
        "reject_codes": REJECT,
        "nm30_terminal_states": NM30_STATE,
        "nm30_terminal_reasons": NM30_REASON,
        "wire_abort_reasons": {
            "OPERATOR": 1,
            "SUPERSEDED": 2,
            "DEADLINE": 3,
            "POLICY": 4,
        },
        "nm30_expired_reason_terminal_only": 5,
        "reservation_add_overflow_threshold_u64_hex":
            f"{UINT64_MAX - RESERVATION_LIFETIME_MS:016x}",
        "no_deadline_u64_hex": f"{UINT64_MAX:016x}",
        "finite_downlink_deadline_min_u64_hex": "0000000000000001",
        "finite_downlink_deadline_max_u64_hex": f"{UINT64_MAX - 1:016x}",
        "uplink_eventfact_deadline_shape": (
            "epoch_zero__absolute_no_deadline__grace_zero"
        ),
        "finite_downlink_deadline_shape": (
            "epoch_nonzero__absolute_1_to_uint64_max_minus_1"
        ),
        "original_application_open_deadline_mapping": (
            "bit_exact_no_normalization"
        ),
        "different_epoch_numeric_deadline_compare_forbidden": True,
        "retention_requires_same_trusted_epoch": True,
        "restart_requires_full_semantic_validation_before_install": True,
        "digest_domains": {
            "manifest": "NM3-MANIFEST-V1",
            "page": "NM3-PAGE-V1",
            "resume": "NM3-RESUME-V1",
            "accept": "NM3-ACCEPT-V1",
            "publish": "NM3-PUBLISH-V1",
            "application_evidence": APPLICATION_EVIDENCE_DOMAIN.decode("ascii"),
        },
        "storage_kinds": ["NM3S", "NM3R", "NM30", "NRC1"],
        "nrc1_value_bytes": NRC1_VALUE_BYTES,
        "nrc1_slot_count": NRC1_SLOT_COUNT,
        "nrc1_slot_bytes": NRC1_SLOT_BYTES,
        "nrc1_slot_session_generation_offset": 8,
        "nrc1_slot_lookup_identity": "session_generation_plus_request_id",
        "nrc1_occupied_response_length_min": 1,
        "nrc1_occupied_response_length_max": 160,
        "nrc1_empty_slot_all_zero": True,
        "nrc1_logical_bytes": NRC1_LOGICAL_BYTES,
        "nrc1_reachable_max_ids": NRC1_REACHABLE_MAX_IDS,
        "nrc1_n_complete": NRC1_N_COMPLETE,
        "nrc1_n_abort": NRC1_N_ABORT,
        "nrc1_capacity_spare": NRC1_CAPACITY_SPARE,
        "nrc1_happy_path_max_ids": NRC1_HAPPY_PATH_MAX_IDS,
        "nrc1_naive_union_ids_rejected_as_single_path": NRC1_NAIVE_UNION_IDS,
        "nrc1_session_gen_max_per_transfer": SESSION_GEN_MAX_PER_TRANSFER,
        "nrc1_resume_reclaim_on_session_gen_advance": True,
        "nrc1_illegal_two_gen_no_reclaim": int(_REACH["illegal_two_gen_no_reclaim"]),
        "request_body_digest_preimage": "type_u8||len_u16be||full_body",
        "manifest_digest_preimage": (
            "NM3-MANIFEST-V1(15 ascii no NUL)||open[0,202)||"
            "open[234,462)||open[462,open_body_length)||entries"
        ),
        "application_binding_layout": [
            {"field": field, "offset": offset, "bytes": size}
            for field, offset, size in APPLICATION_BINDING_LAYOUT
        ],
        "mfdt_admission_profile_revision": MFDT_ADMISSION_PROFILE_REVISION,
        "nts3_current_schema_major": NTS3_CURRENT_SCHEMA_MAJOR,
        "nts3_current_schema_minor": NTS3_CURRENT_SCHEMA_MINOR,
        "nts3_future_schema_minor": NTS3_FUTURE_SCHEMA_MINOR,
        "nts3_future_fields": ["mfdt_transfer_id[16]", "mfdt_target_ordinal_u32"],
        "nts3_future_target_suffix_placement": "canonical_target_encoding_tail",
        "nts3_future_target_suffix_presence": "bearer_route_eq_MFDT_V1_3",
        "nts3_future_target_suffix_bytes": NTS3_MFDT_TARGET_SUFFIX_BYTES,
        "nts3_future_target_count_max": NTS3_TARGET_COUNT_MAX,
        "nts3_future_mfdt_target_rule": (
            "transfer_id_nonzero__sender_ordinal_eq_bound_target_index__"
            "receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be"
        ),
        "nts3_future_non_mfdt_suffix_bytes": 0,
        "nts3_future_non_mfdt_memory_rule": "transfer_id_zero16_and_ordinal_zero",
        "nts3_schema11_record_max_bytes": NTS3_SCHEMA11_RECORD_MAX_BYTES,
        "nts3_schema11_inline_payload_max_bytes": NTS3_INLINE_PAYLOAD_MAX_BYTES,
        "nts3_future_mfdt_record_max_bytes": NTS3_MFDT_RECORD_MAX_BYTES,
        "nts3_record_ceiling_bytes": NTS3_RECORD_CEILING_BYTES,
        "public_callback_context_id": "foundation_transaction_id",
        "publication_token_scope": "private_mfdt_handoff_dedupe_only",
        "manifest_entry_layout": "chunk_index_u16|chunk_length_u16|chunk_offset_u32|chunk_sha256[32]",
        "sha256_empty_hex": hx(sha256(b"")),
    }


def version_catalog() -> dict[str, Any]:
    """Bound MFN1 admission independent of the Accepted U5/U6 version domain."""

    return {
        "hello_body_bytes": 8,
        "accepted_control_selected_values": [1, 2],
        "selected_control_version_3": "REJECT",
        "accepted_u5_u6_selected_exact": 2,
        "accepted_freeze_docs_untouched": [
            "docs/23-usb-radio-boundary.md",
            "docs/25-u5-cell-operating-assignment.md",
            "docs/26-u6-transport-custody.md",
        ],
        "mfdt_negotiation_domain": "private_mfdt_admission_v2",
        "mfdt_negotiation_version": MFDT_ADMISSION_PROFILE_REVISION,
        "mfdt_offer_type": 0x34,
        "mfdt_accept_type": 0x35,
        "mfdt_offer_body_bytes": 112,
        "mfdt_accept_body_bytes": 160,
        "mfdt_offer_digest_preimage": (
            "NINLIL-MFDT-OFFER-V2||request_id_u32be||offer_body[0,80)"
        ),
        "mfdt_accept_digest_preimage": (
            "NINLIL-MFDT-ACCEPT-V2||request_id_u32be||accept_body[0,128)"
        ),
        "mfdt_base_control_versions": [1, 2],
        "mfdt_negotiation_independent_of_selected_control_version": True,
        "mfdt_does_not_claim_selected_3_includes_u5_u6": True,
        "mfdt_admission_requires": [
            "local_policy_ON",
            "capability_bits_exact_0x00000003",
            "peer_capability_bits_exact_0x00000003",
            "session_generation_and_cookie_bound",
            "endpoint_ids_bound",
            "request_and_responder_nonces_nonzero",
            "offer_and_accept_digests_valid",
            "ncl1_data_carrier_exact",
        ],
        "accepted_ncl1_type_values": [
            0x01, 0x02, 0x03, 0x10, 0x11, 0x12,
            0x20, 0x21, 0x22, 0x30, 0x31, 0x32, 0x33,
        ],
        "mfdt_candidate_type_values": list(range(0x34, 0x44)),
        "mfdt_message_types":
            "0x34..0x35_negotiation_and_0x36..0x43_transfer_private_only",
        "mfdt_candidate_contiguous_minimal_after_accepted": True,
        "mfdt_candidate_type_count": 16,
        "mfdt_transfer_type_count": 14,
        "void_old_proposed_type_values":
            [0x3E, 0x3F] + list(range(0x40, 0x4E)),
        "accepted_wire_changed": False,
        "u5_u6_wire_body": "bit_exact_accepted_v2_unchanged",
        "silent_ge2_forbidden": True,
        "docs_25_26_current_selected_exact_2": True,
        "docs_25_26_refreeze_forbidden_in_this_candidate": True,
        "mf_o01_status": "SPEC_ACCEPTED_GREEN_BASELINE_HISTORY",
        "mf_o09_status": "SPEC_ACCEPTED_CLOSED",
        "mf_o01_false_close_forbidden": True,
        "mixed_version_fail_closed": True,
        "revision1_revision2_interop": "REJECT_MUTATION_ZERO",
        "default_policy": "OFF",
        "target_promotion_on": "UNALLOCATED_UNSUPPORTED",
        "target_promotion_off": "ONLY_ALLOCATED_TARGET_PROFILE",
        "private_admission_without_policy": "no_transfer_admission",
        # Legacy observation only (not normative inheritance claim):
        "obsolete_selected_3_inheritance_table": "void_contradicts_accepted_freeze",
    }


def carrier_mapping() -> dict[str, Any]:
    return {
        "ncg1_ncl1": {
            "status": "MAPPING_CANDIDATE",
            "carries_control": True,
            "carries_application_data_as_chunk_payload": True,
        },
        "generic_fabric_control_plane": {
            "status": "MAPPING_CANDIDATE",
            "mapping": "FOUNDATION_TRANSFER_RESERVED_APPLICATION",
            "namespace_id": "org.ninlil.private",
            "service_id": "mfdt-control",
            "schema_id": "ncl1-mfdt-v1",
            "mfdt_admission_profile_revision": MFDT_ADMISSION_PROFILE_REVISION,
            "open_layout_revision": MFDT_ADMISSION_PROFILE_REVISION,
            "descriptor_revision": 1,
            "descriptor_digest_domain":
                "NINLIL-MFDT-FOUNDATION-CARRIER-V1",
            "schema_major": 1,
            "schema_minor": 0,
            "family": "TRANSFER_RESERVED",
            "payload": "exact_ncl1_data_bytes_26_to_1024",
            "transaction_id_domain":
                "NINLIL-MFDT-FABRIC-TRANSACTION-V1",
            "attempt_id_domain": "NINLIL-MFDT-FABRIC-ATTEMPT-V1",
            "ingress_rederives_transaction_and_attempt_ids": True,
            "tx_permit_required": True,
            "public_service_registration": False,
            "note": "private owner-plane only; bearer-neutral Fabric mapping",
        },
        "nfl1_application_packet": {
            "status": "BOUND_ONLY",
            "carries_control": False,
            "may_bind_identity_into_open": True,
            "note": "ordinary public application service; exact private "
                    "TRANSFER_RESERVED owner-plane mapping is separate",
        },
        "compact_rf_nrw1": {
            "status": "MAPPING_UNAVAILABLE",
            "carries_control": False,
        },
        "wifi_nwb1": {
            "status": "MAPPING_UNAVAILABLE",
            "carries_control": False,
        },
    }


def publication_owner() -> dict[str, Any]:
    return {
        "sole_publication_token_owner": "receiver_multi_frame_owner",
        "sole_prepare_caller": "foundation_runtime_callback_reconcile_owner",
        "sole_application_effect_owner": "upper_application_handoff_port",
        "forbidden_prepare_callers": [
            "sender_multi_frame_owner",
            "relay_neutral_bearer",
            "controller_u5",
            "compact_rf_driver",
            "wifi_driver",
            "fabric_path_selector",
        ],
    }


def role_boundaries() -> dict[str, Any]:
    return {
        "sender": {
            "may_claim_complete_before_accept_full": False,
            "may_release_on_chunk_accept_only": False,
            "may_publish": False,
        },
        "receiver": {
            "may_publish": True,
            "may_partial_apply": False,
            "responsibility_ends_on": ["handoff_full", "authority_abort_full"],
        },
        "relay_neutral_bearer": {
            "custody_authority": False,
            "completion_authority": False,
        },
        "controller": {
            "multi_frame_messages": False,
            "assignment_only": True,
        },
    }


def private_api() -> dict[str, Any]:
    return {
        "prefix": "ninlil_mfdt_v1_",
        "public_abi": False,
        "default_off": True,
        "workspace_bytes": WORKSPACE_BYTES,
        "workspace_scope": "per_active_transfer_slot",
        "host_slot_count": HOST_SLOT_COUNT,
        "host_coordinator_bytes": HOST_COORDINATOR_BYTES,
        "host_control_arena_bytes": HOST_CONTROL_ARENA_BYTES,
        "host_terminal_catalog_entries": HOST_TERMINAL_CATALOG_ENTRIES,
        "host_terminal_catalog_entry_bytes": HOST_TERMINAL_CATALOG_ENTRY_BYTES,
        "host_control_outbox_count": 1,
        "host_control_outbox_bytes": HOST_CONTROL_OUTBOX_BYTES,
        "host_control_route_sentinel": HOST_CONTROL_ROUTE_SENTINEL,
        "host_owner_workspace_bytes": HOST_OWNER_WORKSPACE_BYTES,
        "active_record_schema": ACTIVE_RECORD_SCHEMA,
        "active_schema1_replay_eligible": False,
        "open_growth_bytes_redistributed_within_each_slot": APPLICATION_BINDING_BYTES,
        "workspace_growth_bytes": 0,
        "host_slot_allocation": "lowest_free",
        "host_restart_slot_allocation": "transfer_id_unsigned_lexicographic",
        "host_transfer_route_key": "transfer_id_exact",
        "host_fifth_active": "CAPACITY_BUSY_control_outbox_state_mutation_0",
        "host_terminal_route_without_active_slot": True,
        "host_terminal_catalog_rebind":
            "peer_role_generation_exact_fresh_nonzero_cookie",
        "host_schema1_terminal_replay_eligible": False,
        "host_control_outbox_backpressure": "ERR_BUSY_no_overwrite",
        "host_control_traffic_advances_scheduler": False,
        "host_full_transaction_parallelism": 1,
        "host_scheduler": "cyclic_next_slot_0_to_3",
        "host_peer_unpaid_chunk_offer_max": 1,
        "host_fair_selection_bound": 4,
        "heap_growth": False,
        "borrow_until_full": True,
        "copy_owned_after_full": True,
        "operations": [
            "sender_open",
            "receiver_on_open",
            "sender_offer_manifest_page",
            "receiver_on_manifest_page",
            "sender_offer_chunk",
            "receiver_on_chunk",
            "sender_finalize",
            "receiver_on_finalize",
            "sender_on_accept",
            "owner_abort",
            "peer_on_abort",
            "sender_resume_query",
            "receiver_on_resume_query",
            "receiver_poll_publication",
            "receiver_complete_handoff",
            "classify_commit_unknown",
            "gc_tombstones",
        ],
    }


def build_vectors() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    constants = constants_block()
    budget = budget_block()
    catalog = version_catalog()
    carriers = carrier_mapping()
    pub_owner = publication_owner()
    roles = role_boundaries()
    api = private_api()
    sidecar = storage_sidecar_profile()

    out.append(
        vector(
            "MF-CONSTANTS-PINNED",
            expected={"status": "OK", "branch": "constants"},
            constants=constants,
        )
    )
    out.append(
        vector(
            "MF-VERSION-CATALOG-INHERITANCE",
            expected={
                "status": "OK",
                "selected_3_includes_u5_u6_mf": False,
                "accepted_control_selected_values": [1, 2],
                "selected_control_version_3": "REJECT",
                "mfdt_negotiation_independent_of_selected_control_version": True,
                "mf_o01_status": "SPEC_ACCEPTED_GREEN_BASELINE_HISTORY",
                "mf_o09_status": "SPEC_ACCEPTED_CLOSED",
                "mfdt_offer_type": 0x34,
                "mfdt_accept_type": 0x35,
                "mfdt_candidate_type_range": "0x34..0x43",
                "mfdt_candidate_type_count": 16,
                "mfdt_transfer_type_count": 14,
                "accepted_wire_changed": False,
                "target_promotion_on": "UNALLOCATED_UNSUPPORTED",
                "silent_ge2_forbidden": True,
                "docs_25_26_refreeze_forbidden_in_this_candidate": True,
            },
            version_catalog=catalog,
        )
    )
    out.append(
        vector(
            "MF-CARRIER-MAPPING-MATRIX",
            expected={
                "status": "OK",
                "rf": "MAPPING_UNAVAILABLE",
                "wifi": "MAPPING_UNAVAILABLE",
                "ncl1": "MAPPING_CANDIDATE",
                "fabric": "MAPPING_CANDIDATE",
            },
            carrier_mapping=carriers,
        )
    )
    out.append(
        vector(
            "MF-PUBLICATION-OWNER-MATRIX",
            expected={
                "status": "OK",
                "sole_prepare_caller": "receiver_multi_frame_owner",
            },
            publication_owner=pub_owner,
        )
    )
    out.append(
        vector(
            "MF-ROLE-BOUNDARIES",
            expected={"status": "OK", "false_custody": False},
            role_boundaries=roles,
        )
    )
    out.append(
        vector(
            "MF-PRIVATE-API-SURFACE",
            expected={
                "status": "OK",
                "public_abi": False,
                "default_off": True,
                "per_slot_workspace_bytes": WORKSPACE_BYTES,
                "host_slot_count": HOST_SLOT_COUNT,
                "host_owner_workspace_bytes": HOST_OWNER_WORKSPACE_BYTES,
                "host_fifth_active": "CAPACITY_BUSY_control_outbox_state_mutation_0",
            },
            private_api=api,
        )
    )
    out.append(
        vector(
            "MF-FSM-STORAGE-SIDECAR-PROFILE",
            expected={
                "status": "OK",
                "branch": "derived_sidecar_binding_profile",
                "derived_namespace_length": 36,
                "binding_value_min": 53,
                "binding_value_max": 307,
                "foundation_scanner_value_max": 4096,
                "mfdt_active_value_max": ACTIVE_VALUE_MAX,
                "mfdt_active_record_schema": ACTIVE_RECORD_SCHEMA,
                "active_schema1_replay_eligible": False,
                "nrc1_value_bytes": 15020,
                "same_handle_forbidden": True,
                "collision_fail_closed": True,
                "cross_namespace_atomic_commit_claimed": False,
                "destroy_close_order": [
                    "BEARER",
                    "MFDT_SIDECAR",
                    "FOUNDATION_STORAGE",
                ],
            },
            storage_profile=sidecar,
        )
    )

    # Application handoff amendment: exactly five focused authorities.
    layout_ids = transfer_ids(60)
    event_layout_ids = dict(layout_ids)
    event_layout_ids["origin_event_id"] = pattern(0x7B, 16)
    min_open, min_manifest, min_entries, min_facts = encode_open(
        content=b"",
        ids=event_layout_ids,
        absolute_effect_deadline_ms=UINT64_MAX,
        deadline_clock_epoch_id=ZERO16,
        service_family=1,
        application_generation=0,
        evidence_grace_ms=0,
    )
    max_open, max_manifest, _max_entries, max_facts = encode_open(
        content=b"",
        ids=layout_ids,
        namespace=b"n" * 63,
        service=b"s" * 63,
        schema=b"x" * 63,
    )
    layout = [
        {"field": field, "offset": offset, "bytes": size}
        for field, offset, size in APPLICATION_BINDING_LAYOUT
    ]
    out.append(
        vector(
            "MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT",
            expected={
                "status": "OK",
                "branch": "open_application_binding_revision2",
                "admission_profile_revision": MFDT_ADMISSION_PROFILE_REVISION,
                "active_record_schema": ACTIVE_RECORD_SCHEMA,
                "active_schema1_replay_eligible": False,
                "base_fixed_bytes": OPEN_BASE_FIXED,
                "application_binding_bytes": APPLICATION_BINDING_BYTES,
                "text_offset": OPEN_FIXED,
                "open_body_min": OPEN_MIN,
                "open_body_max": OPEN_MAX,
                "manifest_binds_entire_application_binding": True,
                "public_callback_context_id": "foundation_transaction_id",
                "publication_token_scope": "private_mfdt_handoff_dedupe_only",
                "deadline_sentinel_erratum": "foundation_canonical_bit_exact",
                "no_deadline_u64_hex": f"{UINT64_MAX:016x}",
                "finite_downlink_deadline_min_u64_hex": "0000000000000001",
                "finite_downlink_deadline_max_u64_hex": f"{UINT64_MAX - 1:016x}",
                "deadline_zero_rejected": True,
                "downlink_no_deadline_rejected": True,
                "deadline_normalization_forbidden": True,
                "nts3_future_schema": "1.2",
                "nts3_future_fields": [
                    "mfdt_transfer_id[16]",
                    "mfdt_target_ordinal_u32",
                ],
                "nts3_future_target_suffix_placement": (
                    "canonical_target_encoding_tail"
                ),
                "nts3_future_target_suffix_presence": "bearer_route_eq_MFDT_V1_3",
                "nts3_future_target_suffix_bytes": NTS3_MFDT_TARGET_SUFFIX_BYTES,
                "nts3_future_target_count_max": NTS3_TARGET_COUNT_MAX,
                "nts3_future_mfdt_target_rule": (
                    "transfer_id_nonzero__sender_ordinal_eq_bound_target_index__"
                    "receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be"
                ),
                "nts3_future_non_mfdt_suffix_bytes": 0,
                "nts3_future_non_mfdt_memory_rule": (
                    "transfer_id_zero16_and_ordinal_zero"
                ),
                "nts3_schema11_record_max_bytes": NTS3_SCHEMA11_RECORD_MAX_BYTES,
                "nts3_schema11_inline_payload_max_bytes": (
                    NTS3_INLINE_PAYLOAD_MAX_BYTES
                ),
                "nts3_future_mfdt_record_max_bytes": NTS3_MFDT_RECORD_MAX_BYTES,
                "nts3_record_ceiling_bytes": NTS3_RECORD_CEILING_BYTES,
            },
            application_binding_layout=layout,
            minimum_open_body_hex=hx(min_open),
            minimum_manifest_digest_hex=hx(min_manifest),
            minimum_facts=min_facts,
            maximum_open_body_hex=hx(max_open),
            maximum_manifest_digest_hex=hx(max_manifest),
            maximum_facts=max_facts,
            deadline_shape_cases=[
                {
                    "case": "uplink_eventfact_no_deadline",
                    "service_family": 1,
                    "deadline_epoch_hex": "00" * 16,
                    "absolute_effect_deadline_ms_u64_hex": f"{UINT64_MAX:016x}",
                    "evidence_grace_ms_u64_hex": "0000000000000000",
                    "status": "OK",
                },
                {
                    "case": "uplink_eventfact_deadline_zero",
                    "service_family": 1,
                    "deadline_epoch_hex": "00" * 16,
                    "absolute_effect_deadline_ms_u64_hex": "0000000000000000",
                    "evidence_grace_ms_u64_hex": "0000000000000000",
                    "status": "REJECT",
                },
                {
                    "case": "finite_downlink_min",
                    "service_family": 2,
                    "deadline_epoch_hex": hx(layout_ids["deadline_clock_epoch_id"]),
                    "absolute_effect_deadline_ms_u64_hex": "0000000000000001",
                    "status": "OK",
                },
                {
                    "case": "finite_downlink_max",
                    "service_family": 2,
                    "deadline_epoch_hex": hx(layout_ids["deadline_clock_epoch_id"]),
                    "absolute_effect_deadline_ms_u64_hex": f"{UINT64_MAX - 1:016x}",
                    "status": "OK",
                },
                {
                    "case": "downlink_no_deadline",
                    "service_family": 2,
                    "deadline_epoch_hex": hx(layout_ids["deadline_clock_epoch_id"]),
                    "absolute_effect_deadline_ms_u64_hex": f"{UINT64_MAX:016x}",
                    "status": "REJECT",
                },
            ],
        )
    )

    mutation_fixture = transfer_fixture(16, salt=61)
    out.append(
        vector(
            "MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["DIGEST"],
                "stage": STAGE["OPEN"],
                "reason": "every_binding_field_is_manifest_bound",
                "mutation_count": len(APPLICATION_BINDING_LAYOUT),
                "durable_state_mutation": 0,
            },
            open_body_hex=mutation_fixture["open_body_hex"],
            manifest_entries_hex=mutation_fixture["entries_hex"],
            manifest_digest_hex=mutation_fixture["manifest_digest_hex"],
            mutations=[
                {
                    "field": field,
                    "offset": offset,
                    "bytes": size,
                    "xor_first_byte": 1,
                }
                for field, offset, size in APPLICATION_BINDING_LAYOUT
            ],
        )
    )

    out.append(
        vector(
            "MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["AUTHORITY"],
                "stage": STAGE["OPEN"],
                "reason": "pre_full_application_handoff_boundary_reject",
                "full_count": 0,
                "durable_rows_created": 0,
                "durable_state_mutation": 0,
                "callback_count": 0,
                "receipt_count": 0,
            },
            open_body_hex=mutation_fixture["open_body_hex"],
            mismatch_fields=[
                "sender_original_application_exact.origin_transaction_attempt_event",
                "sender_original_application_exact.source_runtime_application_instance_identity_epochs_flags",
                "sender_original_application_exact.target_runtime_application_instance_identity_epochs_flags",
                "sender_original_application_exact.service_text_revision_digest_schema_family",
                "sender_original_application_exact.content_length_and_digest",
                "sender_original_application_exact.application_generation",
                "sender_original_application_exact.deadline_and_evidence",
                "sender_original_application_exact.target_ordinal",
                "receiver_private_carrier_exact.source_runtime_application_instance_identity_epochs_flags",
                "receiver_private_carrier_exact.target_runtime_application_instance_identity_epochs_flags",
                "receiver_open_canonical_validation.original_application_fields",
                "receiver_open_canonical_validation.target_ordinal_lt4_and_local_target_identity",
                "receiver_open_canonical_validation.transfer_id_rederivation",
            ],
            validation_boundary=(
                "sender_before_G_S_OPEN_full_original_exact__"
                "receiver_before_G_R_OPEN_party_target_subset_exact_"
                "canonical_open_no_private_control_equality"
            ),
        )
    )

    out.append(
        vector(
            "MF-NEG-ADMISSION-REV1-REV2-MIXED",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["UNSUPPORTED"],
                "reason": "admission_profile_or_active_schema_revision_mismatch",
                "full_count": 0,
                "durable_state_mutation": 0,
                "migration_attempted": False,
            },
            cases=[
                {
                    "local_admission_revision": 2,
                    "peer_admission_revision": 1,
                    "open_layout_revision": 1,
                    "active_record_schema": 1,
                },
                {
                    "local_admission_revision": 1,
                    "peer_admission_revision": 2,
                    "open_layout_revision": 2,
                    "active_record_schema": 2,
                },
                {
                    "local_admission_revision": 2,
                    "peer_admission_revision": 2,
                    "open_layout_revision": 1,
                    "active_record_schema": 1,
                },
            ],
        )
    )

    evidence_bytes = b"applied:ok"
    evidence_token = bytes.fromhex(mutation_fixture["publication_token_hex"])
    evidence_ids = {
        key: bytes.fromhex(value)
        for key, value in mutation_fixture["ids"].items()
    }
    evidence_preimage, evidence_digest = application_evidence_digest(
        publication_token_v=evidence_token,
        origin_transaction_id=evidence_ids["origin_transaction_id"],
        original_attempt_id=evidence_ids["original_attempt_id"],
        target_ordinal=DEFAULT_TARGET_ORDINAL,
        evidence_stage=DEFAULT_REQUIRED_EVIDENCE,
        evidence_bytes=evidence_bytes,
    )
    out.append(
        vector(
            "MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT",
            expected={
                "status": "OK",
                "branch": "positive_required_evidence_handoff",
                "evidence_stage": DEFAULT_REQUIRED_EVIDENCE,
                "required_evidence": DEFAULT_REQUIRED_EVIDENCE,
                "evidence_length": len(evidence_bytes),
                "application_evidence_digest_hex": hx(evidence_digest),
                "handoff_may_advance": True,
                "receipt_may_advance_after_handoff_full": True,
                "disposition_fatal_recovery_may_advance": False,
            },
            domain_ascii=APPLICATION_EVIDENCE_DOMAIN.decode("ascii"),
            publication_token_hex=hx(evidence_token),
            origin_transaction_id_hex=hx(evidence_ids["origin_transaction_id"]),
            original_attempt_id_hex=hx(evidence_ids["original_attempt_id"]),
            target_ordinal=DEFAULT_TARGET_ORDINAL,
            evidence_stage=DEFAULT_REQUIRED_EVIDENCE,
            evidence_bytes_hex=hx(evidence_bytes),
            evidence_preimage_hex=hx(evidence_preimage),
            application_evidence_digest_hex=hx(evidence_digest),
            callback_context_id_hex=hx(evidence_ids["origin_transaction_id"]),
            callback_context_authority="foundation_transaction_id",
            publication_token_scope="private_mfdt_handoff_dedupe_only",
        )
    )

    out.append(
        vector(
            "MF-BUDGET-ARITHMETIC-REFERENCE",
            expected={
                "status": "OK",
                "receiver_fulls": RECEIVER_FULLS_MAX,
                "sender_fulls": SENDER_FULLS_MAX,
                "required_receiver_reference": RECEIVER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY,
                "required_sender_reference": SENDER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY,
            },
            budget=budget,
        )
    )
    out.append(
        vector(
            "MF-BUDGET-EMPTY-TRANSFER",
            expected={
                "status": "OK",
                "receiver_fulls": RECEIVER_FULLS_EMPTY,
                "sender_fulls": SENDER_FULLS_EMPTY,
            },
            receiver_fulls=RECEIVER_FULLS_EMPTY,
            sender_fulls=SENDER_FULLS_EMPTY,
            groups=budget["groups"]["empty_receiver"]
            | {"sender": budget["groups"]["empty_sender"]},
        )
    )
    out.append(
        vector(
            "MF-BUDGET-OBSOLETE-80-REJECTED",
            expected={
                "status": "REJECT",
                "reason": "OBSOLETE_80_INFEASIBLE",
                "required_receiver_fulls": RECEIVER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY,
                "obsolete_cap": 80,
            },
            obsolete_cap=OBSOLETE_FULLS_DAY,
            required_receiver_fulls=RECEIVER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY,
            feasible=False,
        )
    )
    out.append(
        vector(
            "MF-BUDGET-RESTORATION-HASH",
            expected={
                "status": "OK",
                "restoration_sha256_hex": budget["restoration_sha256_hex"],
            },
            restoration_sha256_hex=budget["restoration_sha256_hex"],
            restoration_object=budget["restoration_object"],
        )
    )
    out.append(
        vector(
            "MF-BUDGET-NRC1-LOGICAL-BYTES",
            expected={
                "status": "OK",
                "branch": "nrc1_budget",
                "value_bytes": NRC1_VALUE_BYTES,
                "logical_bytes": NRC1_LOGICAL_BYTES,
                "slot_bytes": NRC1_SLOT_BYTES,
                "slot_count": NRC1_SLOT_COUNT,
                "reachable_max_ids": NRC1_REACHABLE_MAX_IDS,
                "n_complete": NRC1_N_COMPLETE,
                "n_abort": NRC1_N_ABORT,
                "timeout_retry_max": TIMEOUT_RETRY_MAX,
                "capacity_spare": NRC1_CAPACITY_SPARE,
                "happy_path_max_ids": NRC1_HAPPY_PATH_MAX_IDS,
                "fixed16_rejected": True,
                "naive_union_not_single_path": NRC1_NAIVE_UNION_IDS,
                "slot_count_ge_reachable": True,
                "admission_reserved_entries": 3,
                "admission_reserved_logical_bytes": ADMISSION_RESERVED_LOGICAL_BYTES,
                "esp_active_transfers_max": 1,
                "host_active_transfers_max": HOST_SLOT_COUNT,
                "host_four_active_committed_logical_bytes":
                    HOST_SLOT_COUNT * ACTIVE_GROUP_LOGICAL_BYTES,
                "host_committed_logical_bytes_hard_max":
                    budget["host_committed_logical_bytes_hard_max"],
                "host_begin_final_union_logical_bytes_hard_max":
                    budget["host_begin_final_union_logical_bytes_hard_max"],
            },
            value_bytes=NRC1_VALUE_BYTES,
            logical_bytes=NRC1_LOGICAL_BYTES,
            slot_count=NRC1_SLOT_COUNT,
            reachable_max_ids=NRC1_REACHABLE_MAX_IDS,
            n_complete=NRC1_N_COMPLETE,
            n_abort=NRC1_N_ABORT,
            timeout_retry_max=TIMEOUT_RETRY_MAX,
            capacity_spare=NRC1_CAPACITY_SPARE,
            happy_path_max_ids=NRC1_HAPPY_PATH_MAX_IDS,
            admission_reserved_entries=3,
            admission_reserved_logical_bytes=ADMISSION_RESERVED_LOGICAL_BYTES,
            host_four_active_committed_logical_bytes=
                HOST_SLOT_COUNT * ACTIVE_GROUP_LOGICAL_BYTES,
            host_committed_logical_bytes_hard_max=
                budget["host_committed_logical_bytes_hard_max"],
            host_begin_final_union_logical_bytes_hard_max=
                budget["host_begin_final_union_logical_bytes_hard_max"],
            note=(
                "reachable max from retry-budget SM (N_complete=65, N_abort=64); "
                "capacity 72; naive union 57 is not a single-path bound; "
                "NRC1 retained until NM30 retention GC"
            ),
            nrc1_retained_until_gc=True,
            terminal_erases_nrc1=False,
        )
    )
    out.append(
        vector(
            "MF-BUDGET-FULL-MAX-WITH-REQID",
            expected={
                "status": "OK",
                "branch": "full_max_with_reqid",
                "receiver_fulls": RECEIVER_FULLS_MAX,
                "sender_fulls": SENDER_FULLS_MAX,
                "receiver_base": RECEIVER_FULLS_BASE,
                "receiver_resume": RECEIVER_FULLS_RESUME,
                "receiver_reqid_cache": RECEIVER_FULLS_REQID_CACHE,
                "sender_base": SENDER_FULLS_BASE,
                "sender_resume": SENDER_FULLS_RESUME,
                "sender_reqid_cache": SENDER_FULLS_REQID_CACHE,
                "required_receiver_reference": RECEIVER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY,
                "required_sender_reference": SENDER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY,
                "obsolete_80_infeasible": True,
                "nrc1_retained_until_gc": True,
                "terminal_erases_nrc1": False,
            },
            receiver_fulls=RECEIVER_FULLS_MAX,
            sender_fulls=SENDER_FULLS_MAX,
            receiver_base=RECEIVER_FULLS_BASE,
            receiver_resume=RECEIVER_FULLS_RESUME,
            receiver_reqid_cache=RECEIVER_FULLS_REQID_CACHE,
            sender_base=SENDER_FULLS_BASE,
            sender_resume=SENDER_FULLS_RESUME,
            sender_reqid_cache=SENDER_FULLS_REQID_CACHE,
            groups=budget["groups"]["receiver"] | {"sender_groups": budget["groups"]["sender"]},
            note=(
                "max-ID path: 44+8+16+8+1=77 receiver, 42+8+8+8+1=67 sender; "
                "daily 2× = 154/134; obsolete 80 rejected"
            ),
        )
    )

    # Positive payload geometries.
    for vector_id, length, salt in (
        ("MF-POS-EMPTY-PAYLOAD", 0, 0),
        ("MF-POS-ONE-BYTE", 1, 1),
        ("MF-POS-EXACT-MULTIPLE-FINAL", CHUNK_SIZE * 2, 2),  # final length 896
        ("MF-POS-ONE-BYTE-FINAL", CHUNK_SIZE + 1, 3),
        ("MF-POS-MAX-PAYLOAD-37-CHUNKS", MAX_CONTENT, 4),
        ("MF-POS-TWO-PAGE-MANIFEST", CHUNK_SIZE * 23, 5),  # 23 chunks => 2 pages
    ):
        fx = transfer_fixture(length, salt=salt)
        final_len = 0
        if fx["facts"]["chunk_count"] > 0:
            final_len = fx["chunks"][-1]["chunk_length"]
        out.append(
            vector(
                vector_id,
                expected={
                    "status": "OK",
                    "branch": "positive_transfer",
                    "total_length": length,
                    "chunk_count": fx["facts"]["chunk_count"],
                    "manifest_page_count": fx["facts"]["manifest_page_count"],
                    "final_chunk_length": final_len,
                    "whole_content_sha256_hex": fx["content_sha256_hex"],
                    "manifest_digest_hex": fx["manifest_digest_hex"],
                    "publication_token_hex": fx["publication_token_hex"],
                    "open_accept_length": 100,
                    "transfer_accept_length": 160,
                },
                fixture=fx,
            )
        )

    # Completion / receipt replay (idempotent accept).
    fx_replay = transfer_fixture(16, salt=6)
    out.append(
        vector(
            "MF-POS-COMPLETION-RECEIPT-REPLAY",
            expected={
                "status": "OK",
                "branch": "idempotent_accept_replay",
                "state_mutation_on_replay": 0,
                "transfer_accept_hex": fx_replay["transfer_accept_hex"],
            },
            first_accept_hex=fx_replay["transfer_accept_hex"],
            replay_accept_hex=fx_replay["transfer_accept_hex"],
            fixture_ids=fx_replay["ids"],
        )
    )

    # Request-ID response cache — durable NRC1.
    fx_req2 = transfer_fixture(CHUNK_SIZE * 23, salt=22)
    tid_req = bytes.fromhex(fx_req2["ids"]["transfer_id"])
    p0 = fx_req2["page_accepts"][0]
    p0_body = bytearray(bytes.fromhex(p0["body_hex"]))
    # PAGE_ACCEPT: BIND52(52)+idx_u16+count_u16+digest32+reservation16+complete_u8+pad3
    # complete at offset 104
    assert len(p0_body) >= 108
    p0_complete0 = bytearray(p0_body)
    p0_complete0[104] = 0
    p0_complete1 = bytearray(p0_body)
    p0_complete1[104] = 1
    # Full page-request bodies (include BIND52); digest uses type||len||body preimage.
    page_req_a = bytes.fromhex(fx_req2["pages"][0]["body_hex"])
    page_req_b = bytes.fromhex(fx_req2["pages"][0]["body_hex"])  # same bind; different type path
    dig_a = request_body_digest(MSG["MANIFEST_PAGE"], page_req_a)
    dig_b = request_body_digest(MSG["MANIFEST_PAGE"], page_req_b + b"\x00")  # distinct preimage
    slot0 = nrc1_slot(
        request_id=7,
        session_generation=1,
        request_body_digest=dig_a,
        response_type=MSG["MANIFEST_PAGE_ACCEPT"],
        response_body=bytes(p0_complete0),
    )
    nrc1_after_first = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=1,
        slots=[slot0],
        next_insert_seq=1,
    )
    slot1 = nrc1_slot(
        request_id=8,
        session_generation=1,
        request_body_digest=dig_b,
        response_type=MSG["MANIFEST_PAGE_ACCEPT"],
        response_body=bytes(p0_complete1),
    )
    nrc1_after_second = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=1,
        slots=[slot0, slot1],
        next_insert_seq=2,
    )
    nrc1_key_hex = hx(nrc1_key(tid_req))
    nrc1_l0_mutant = bytearray(nrc1_after_first)
    first_slot_offset = 40
    nrc1_l0_mutant[first_slot_offset + 46 : first_slot_offset + 48] = u16(0)
    nrc1_l0_mutant = bytearray(repair_nrc1_crc(bytes(nrc1_l0_mutant)))
    out.append(
        vector(
            "MF-POS-REQID-CACHE-SAME-ID-STABLE",
            expected={
                "status": "OK",
                "branch": "request_id_cache_hit",
                "first_manifest_complete": 0,
                "cached_manifest_complete": 0,
                "state_mutation_on_same_request_id": 0,
                "request_id": 7,
                "nrc1_kind": "NRC1",
                "durable_cache": True,
                "storage_profile": "HOST_FULL_CAPABLE",
                "target_unattested_replay_forbidden": True,
            },
            request_id=7,
            first_page_accept_hex=hx(bytes(p0_complete0)),
            cached_retry_page_accept_hex=hx(bytes(p0_complete0)),
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_after_first),
            request_body_digest_hex=hx(dig_a),
            note="same request_id retransmit reads durable NRC1 slot bit-exact",
        )
    )
    out.append(
        vector(
            "MF-POS-REQID-NEW-ID-CURRENT-COMPLETE",
            expected={
                "status": "OK",
                "branch": "new_request_id_current_state",
                "first_manifest_complete": 0,
                "second_manifest_complete": 1,
                "first_request_id": 7,
                "second_request_id": 8,
                "nrc1_occupied_after": 2,
            },
            first_request_id=7,
            second_request_id=8,
            first_page_accept_hex=hx(bytes(p0_complete0)),
            second_page_accept_hex=hx(bytes(p0_complete1)),
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_after_second_hex=hx(nrc1_after_second),
            note="new request_id miss path inserts second NRC1 slot with current complete=1",
        )
    )
    out.append(
        vector(
            "MF-POS-REQID-NRC1-LAYOUT-KAT",
            expected={
                "status": "OK",
                "branch": "nrc1_layout",
                "value_length": NRC1_VALUE_BYTES,
                "slot_count": NRC1_SLOT_COUNT,
                "slot_bytes": NRC1_SLOT_BYTES,
                "key_length": 20,
                "reachable_max_ids": NRC1_REACHABLE_MAX_IDS,
                "happy_path_max_ids": NRC1_HAPPY_PATH_MAX_IDS,
                "logical_bytes": NRC1_LOGICAL_BYTES,
                "timeout_retry_max": TIMEOUT_RETRY_MAX,
                "slot_session_generation_offset": 8,
                "first_slot_session_generation": 1,
                "lookup_identity": "session_generation_plus_request_id",
                "occupied_response_length_min": 1,
                "occupied_l0_mutant": "REJECT_SEMANTIC",
                "empty_slot": "ALL_ZERO_ACCEPTED",
            },
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_after_first),
            first_slot_hex=hx(slot0),
            first_slot_session_generation_hex=hx(slot0[8:12]),
            empty_slot_hex=hx(nrc1_empty_slot()),
            occupied_l0_repaired_crc_mutant_hex=hx(bytes(nrc1_l0_mutant)),
            nrc1_magic="NRC1",
            header_crc_ok=True,
            record_crc_ok=True,
        )
    )
    # Max-size path: 1 OPEN + 2 PAGE + 37 CHUNK + 1 FINALIZE = 41 distinct IDs < 64.
    # Slot kinds follow lifecycle order so occupancy is not synthetic-only CHUNK fills.
    max_slot_plan: list[tuple[int, int, int, int]] = []
    # (request_id, req_type, resp_type, body_len)
    max_slot_plan.append(
        (1000, MSG["TRANSFER_OPEN"], MSG["TRANSFER_OPEN_ACCEPT"], 100)
    )
    for p in range(MAX_PAGES):
        max_slot_plan.append(
            (
                1001 + p,
                MSG["MANIFEST_PAGE"],
                MSG["MANIFEST_PAGE_ACCEPT"],
                108,
            )
        )
    for c in range(MAX_CHUNKS):
        max_slot_plan.append(
            (
                1003 + c,
                MSG["CHUNK_OFFER"],
                MSG["CHUNK_ACCEPT"],
                88,
            )
        )
    max_slot_plan.append(
        (1003 + MAX_CHUNKS, MSG["TRANSFER_FINALIZE"], MSG["TRANSFER_ACCEPT"], 160)
    )
    assert len(max_slot_plan) == NRC1_HAPPY_PATH_MAX_IDS
    max_slots = []
    for idx, (rid, req_t, resp_t, rlen) in enumerate(max_slot_plan):
        # Distinct request preimages (type||len||body); OPEN has no BIND52 strip.
        req_body = bytes([(idx + 1) & 0xFF]) * (OPEN_MIN if req_t == MSG["TRANSFER_OPEN"] else 96)
        max_slots.append(
            nrc1_slot(
                request_id=rid,
                session_generation=1,
                request_body_digest=request_body_digest(req_t, req_body),
                response_type=resp_t,
                response_body=bytes([(idx + 7) & 0xFF]) * rlen,
            )
        )
    nrc1_max_happy = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=1,
        slots=max_slots,
        next_insert_seq=NRC1_HAPPY_PATH_MAX_IDS,
    )
    out.append(
        vector(
            "MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41",
            expected={
                "status": "OK",
                "branch": "max_transfer_nrc1_occupancy",
                "occupied_count": NRC1_HAPPY_PATH_MAX_IDS,
                "slot_count": NRC1_SLOT_COUNT,
                "fits": True,
                "cache_full": False,
                "exceeds_obsolete_fixed16": True,
                "open_ids": 1,
                "page_ids": MAX_PAGES,
                "chunk_ids": MAX_CHUNKS,
                "finalize_ids": 1,
            },
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_max_happy),
            occupied_count=NRC1_HAPPY_PATH_MAX_IDS,
            exceeds_obsolete_fixed16=True,
            note="41 distinct happy-path IDs fit in 72; obsolete fixed-16 cannot complete max transfer",
        )
    )
    sm = retry_budget_sm()
    reach = reachable_request_id_counts()
    out.append(
        vector(
            "MF-POS-REQID-RETRY-BUDGET-SM",
            expected={
                "status": "OK",
                "branch": "retry_budget_sm",
                "scope": sm["scope"],
                "owner": sm["owner"],
                "initial_value": sm["initial_value"],
                "max_value": sm["max_value"],
                "min_value": sm["min_value"],
                "header_offset": sm["header_offset"],
                "decrement_event": sm["decrement_event"],
                "decrement_requires_full_before_wire": True,
                "exhaustion_is_terminal": False,
                "exhaustion_is_nrc1_eviction": False,
                "exhaustion_forbids_new_request_id_timeout_retry": True,
                "not_per_request_id": True,
                "not_per_stage": True,
            },
            retry_budget_sm=sm,
            note="normative owner/init/decrement/exhaustion for retry_budget_remaining 0..8",
        )
    )
    # Reachable max IDs generated from SM (peak with session-gen RESUME reclaim).
    out.append(
        vector(
            "MF-POS-REQID-REACHABLE-MAX-COUNT",
            expected={
                "status": "OK",
                "branch": "nrc1_reachable_max",
                "happy_first": reach["happy_first"],
                "n_complete": reach["n_complete"],
                "n_abort": reach["n_abort"],
                "reachable_max": reach["reachable_max"],
                "timeout_retry_max": reach["retry_budget_max"],
                "resume_reclaim_on_session_gen_advance": True,
                "illegal_two_gen_no_reclaim": reach["illegal_two_gen_no_reclaim"],
                "illegal_two_gen_exceeds_72": True,
                "resume_max": RESUME_MAX,
                "abort_gen_max": ABORT_GEN_MAX,
                "slot_count": NRC1_SLOT_COUNT,
                "slot_count_ge_reachable": NRC1_SLOT_COUNT >= reach["reachable_max"],
                "capacity_spare": NRC1_CAPACITY_SPARE,
                "naive_union": reach["naive_union"],
                "naive_union_is_single_path": False,
                "terminal_outcomes_exclusive": True,
                "finalize_abort_success_exclusive": True,
                "denied_abort_after_content_verified_consumes_slot": True,
                "derived_from_retry_budget_sm": True,
            },
            happy_first=reach["happy_first"],
            n_complete=reach["n_complete"],
            n_abort=reach["n_abort"],
            reachable_max=reach["reachable_max"],
            timeout_retry_max=reach["retry_budget_max"],
            resume_max=RESUME_MAX,
            abort_gen_max=ABORT_GEN_MAX,
            slot_count=NRC1_SLOT_COUNT,
            capacity_spare=NRC1_CAPACITY_SPARE,
            naive_union=reach["naive_union"],
            formula_complete=reach["formula_complete"],
            formula_abort=reach["formula_abort"],
            first_units={
                "open": reach["first_open"],
                "pages": reach["first_pages"],
                "chunks": reach["first_chunks"],
                "resume": reach["first_resume"],
                "finalize": reach["first_finalize"],
                "abort": reach["first_abort"],
                "retry_new_ids": reach["retry_new_ids"],
            },
            note=(
                "Peak IDs with session-gen RESUME reclaim; 2-gen without reclaim=73>72 is illegal; "
                "FINALIZE success excludes ABORT success"
            ),
        )
    )
    initial_generation = 7
    successor_generation = 8
    gen1_nonresume_slot = nrc1_slot(
        request_id=9000,
        session_generation=initial_generation,
        request_body_digest=request_body_digest(
            MSG["TRANSFER_OPEN"], bytes([0x31]) * OPEN_MIN
        ),
        response_type=MSG["TRANSFER_OPEN_ACCEPT"],
        response_body=bytes([0x41]) * 100,
    )
    gen1_resume_slot = nrc1_slot(
        request_id=9001,
        session_generation=initial_generation,
        request_body_digest=request_body_digest(
            MSG["RESUME_QUERY"], bytes([0x32]) * 60
        ),
        response_type=MSG["RESUME_STATE"],
        response_body=bytes([0x42]) * 108,
    )
    nrc1_gen1 = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=initial_generation,
        slots=[gen1_nonresume_slot, gen1_resume_slot],
        next_insert_seq=2,
    )
    # The same numeric request ID is legal in a fresh session generation because lookup
    # identity is the pair (generation, request_id). Prior-generation RESUME slots are
    # reclaimed; the non-RESUME OPEN slot remains byte-exact with generation=1.
    gen2_resume_same_request_id_slot = nrc1_slot(
        request_id=9001,
        session_generation=successor_generation,
        request_body_digest=request_body_digest(
            MSG["RESUME_QUERY"], bytes([0x33]) * 60
        ),
        response_type=MSG["RESUME_STATE"],
        response_body=bytes([0x43]) * 108,
    )
    nrc1_gen2_after_reclaim = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=successor_generation,
        slots=[gen1_nonresume_slot, gen2_resume_same_request_id_slot],
        next_insert_seq=3,
    )
    future_generation_nrc1 = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=initial_generation,
        slots=[
            nrc1_slot(
                request_id=9002,
                session_generation=successor_generation,
                request_body_digest=request_body_digest(
                    MSG["TRANSFER_OPEN"], bytes([0x34]) * OPEN_MIN
                ),
                response_type=MSG["TRANSFER_OPEN_ACCEPT"],
                response_body=bytes([0x44]) * 100,
            )
        ],
        next_insert_seq=1,
    )
    gap_generation_nrc1 = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=successor_generation + 1,
        slots=[gen1_nonresume_slot],
        next_insert_seq=1,
    )
    third_generation_slot = nrc1_slot(
        request_id=9002,
        session_generation=initial_generation - 1,
        request_body_digest=request_body_digest(
            MSG["MANIFEST_PAGE"], bytes([0x35]) * 94
        ),
        response_type=MSG["MANIFEST_PAGE_ACCEPT"],
        response_body=bytes([0x45]) * 108,
    )
    third_generation_nrc1 = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=successor_generation,
        slots=[
            gen1_nonresume_slot,
            gen2_resume_same_request_id_slot,
            third_generation_slot,
        ],
        next_insert_seq=4,
    )
    out.append(
        vector(
            "MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM",
            expected={
                "status": "OK",
                "branch": "session_gen_resume_reclaim",
                "session_gen_max": SESSION_GEN_MAX_PER_TRANSFER,
                "session_gen_is_distinct_count_not_numeric_max": True,
                "initial_session_generation": initial_generation,
                "successor_session_generation": successor_generation,
                "initial_session_generation_domain": "u32_nonzero",
                "advance_rule": "current_plus_1_no_wrap",
                "anchor": "initial_non_resume_open_accept_slot",
                "allowed_slot_generations": "current_or_exact_prior",
                "resume_per_gen": RESUME_MAX,
                "peak_with_reclaim": NRC1_REACHABLE_MAX_IDS,
                "lifetime_resume_attempts_max": SESSION_GEN_MAX_PER_TRANSFER * RESUME_MAX,
                "slot_bound_session_generation": True,
                "lookup_identity": "session_generation_plus_request_id",
                "same_request_id_across_generation_distinct": True,
                "reclaim_resume_class_only": True,
                "non_resume_retained_whole_lifetime": True,
                "active_header_session_generation_offset": 300,
                "session_advance_full_members": ["ACTIVE", "NRC1"],
                "resume_counter_reset": True,
                "initial_occupied": 2,
                "successor_occupied_after_reclaim": 2,
                "future_generation_record_status": "CORRUPT",
                "gap_generation_record_status": "CORRUPT",
                "third_generation_record_status": "CORRUPT",
                "second_advance_status": "CAPACITY",
                "uint32_max_advance_status": "CAPACITY",
            },
            session_gen_max=SESSION_GEN_MAX_PER_TRANSFER,
            resume_per_gen=RESUME_MAX,
            peak_with_reclaim=NRC1_REACHABLE_MAX_IDS,
            request_id_reused_across_generation=9001,
            initial_session_generation=initial_generation,
            successor_session_generation=successor_generation,
            generation_1_nrc1_value_hex=hx(nrc1_gen1),
            generation_2_nrc1_value_hex=hx(nrc1_gen2_after_reclaim),
            retained_non_resume_slot_hex=hx(gen1_nonresume_slot),
            reclaimed_generation_1_resume_slot_hex=hx(gen1_resume_slot),
            admitted_generation_2_resume_slot_hex=hx(gen2_resume_same_request_id_slot),
            future_generation_nrc1_value_hex=hx(future_generation_nrc1),
            gap_generation_nrc1_value_hex=hx(gap_generation_nrc1),
            third_generation_nrc1_value_hex=hx(third_generation_nrc1),
            note=(
                "initial generation is arbitrary non-zero u32; reconnect uses its exact "
                "successor; prior RESUME slots are reclaimed while non-RESUME anchor remains"
            ),
        )
    )
    out.append(
        vector(
            "MF-NEG-REQID-TWO-GEN-NO-RECLAIM-CAPACITY",
            expected={
                "status": "REJECT",
                "code": REJECT["CAPACITY"],
                "branch": "two_gen_resume_without_reclaim",
                "illegal_occupancy": 73,
                "slot_count": NRC1_SLOT_COUNT,
                "exceeds": True,
            },
            illegal_occupancy=73,
            slot_count=NRC1_SLOT_COUNT,
            note="2 session gens of RESUME without reclaim would need 73>72 slots",
        )
    )
    # Max timeout-retry positive trace: first ID then TIMEOUT_RETRY_MAX new IDs for same stage.
    retry_slots = []
    for i in range(1 + TIMEOUT_RETRY_MAX):
        retry_slots.append(
            nrc1_slot(
                request_id=7000 + i,
                session_generation=1,
                request_body_digest=request_body_digest(
                    MSG["MANIFEST_PAGE"], bytes([0xA0 + (i & 0x0F)]) * 96
                ),
                response_type=MSG["MANIFEST_PAGE_ACCEPT"],
                response_body=bytes([0xB0 + (i & 0x0F)]) * 108,
            )
        )
    nrc1_retry_trace = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=1,
        slots=retry_slots,
        next_insert_seq=1 + TIMEOUT_RETRY_MAX,
    )
    out.append(
        vector(
            "MF-POS-REQID-MAX-RETRY-TRACE",
            expected={
                "status": "OK",
                "branch": "max_timeout_retry_trace",
                "first_attempts": 1,
                "timeout_retries": TIMEOUT_RETRY_MAX,
                "occupied_count": 1 + TIMEOUT_RETRY_MAX,
                "timeout_retry_max": TIMEOUT_RETRY_MAX,
                "new_request_id_each_retry": True,
                "fits_in_capacity": True,
                "slot_count": NRC1_SLOT_COUNT,
            },
            first_request_id=7000,
            retry_request_ids=[7000 + i for i in range(1, 1 + TIMEOUT_RETRY_MAX)],
            occupied_count=1 + TIMEOUT_RETRY_MAX,
            timeout_retry_max=TIMEOUT_RETRY_MAX,
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_retry_trace),
            transcript=[
                "FIRST_PAGE_REQ_ID_7000",
                *[f"TIMEOUT_RETRY_NEW_ID_{7000 + i}" for i in range(1, 1 + TIMEOUT_RETRY_MAX)],
                "OCCUPIED_9_LE_72",
            ],
            note=(
                "timeout retries use distinct request IDs; each decrements "
                "retry_budget_remaining; max 8 = RETRY_BUDGET_MAX"
            ),
        )
    )
    # Post-terminal late-duplicate: NRC1 retained with NM30 until GC; bit-exact hit.
    late_kinds = [
        ("OPEN_ACCEPT", MSG["TRANSFER_OPEN"], MSG["TRANSFER_OPEN_ACCEPT"], 100),
        ("PAGE_ACCEPT", MSG["MANIFEST_PAGE"], MSG["MANIFEST_PAGE_ACCEPT"], 108),
        ("CHUNK_ACCEPT", MSG["CHUNK_OFFER"], MSG["CHUNK_ACCEPT"], 88),
        ("RESUME_STATE", MSG["RESUME_QUERY"], MSG["RESUME_STATE"], 108),
        ("TRANSFER_ACCEPT", MSG["TRANSFER_FINALIZE"], MSG["TRANSFER_ACCEPT"], 160),
        ("ABORT_DENIED", MSG["TRANSFER_ABORT"], MSG["TRANSFER_REJECT"], 60),
    ]
    late_slots = []
    late_matrix = []
    for i, (name, req_t, resp_t, rlen) in enumerate(late_kinds):
        rid = 8000 + i
        req_body = bytes([(0x10 + i) & 0xFF]) * 96
        resp_body = bytes([(0x80 + i) & 0xFF]) * rlen
        dig = request_body_digest(req_t, req_body)
        late_slots.append(
            nrc1_slot(
                request_id=rid,
                session_generation=1,
                request_body_digest=dig,
                response_type=resp_t,
                response_body=resp_body,
            )
        )
        late_matrix.append(
            {
                "operation": name,
                "request_id": rid,
                "request_type": req_t,
                "response_type": resp_t,
                "response_body_hex": hx(resp_body),
                "request_body_digest_hex": hx(dig),
                "post_terminal_hit": True,
                "bit_exact": True,
            }
        )
    nrc1_post_terminal = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=1,
        slots=late_slots,
        next_insert_seq=len(late_slots),
    )
    ids_post = {k: bytes.fromhex(v) for k, v in fx_req2["ids"].items()}
    md_post = bytes.fromhex(fx_req2["manifest_digest_hex"])
    nm30_post, _tomb = build_nm30(
        ids=ids_post,
        revision=1,
        manifest_digest=md_post,
        terminal_state=1,
        terminal_reason=0,
        abort_generation=0,
        receiver_evidence_id=ids_post["receiver_evidence_id"],
        acceptance_record_digest=bytes.fromhex(fx_req2["acceptance_record_digest_hex"]),
        authority_actor_id=ZERO16,
        retention_ms=RETENTION_MS,
    )
    out.append(
        vector(
            "MF-POS-REQID-TERMINAL-LATE-DUP-MATRIX",
            expected={
                "status": "OK",
                "branch": "terminal_late_dup_matrix",
                "nrc1_retained_with_nm30": True,
                "terminal_erases_nrc1": False,
                "operation_count": len(late_kinds),
                "all_bit_exact": True,
                "state_mutation_on_hit": 0,
            },
            phase="post_terminal_pre_gc",
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_post_terminal),
            nm30_key_hex=hx(b"NM30" + tid_req),
            nm30_value_hex=hx(nm30_post),
            operations=late_matrix,
            note="after G_*_TERMINAL: NM30+NRC1 present; late dups for all response kinds bit-exact",
        )
    )

    # Host terminal/control contract. These vectors deliberately keep the
    # storage authority (NM30/NRC1) separate from the volatile session cookie.
    nm30_schema1_legacy = build_nm30_legacy_schema1(
        ids=ids_post,
        revision=1,
        manifest_digest=md_post,
        terminal_state=NM30_STATE["COMPLETE"],
        terminal_reason=NM30_REASON["COMPLETE"],
        abort_generation=0,
        receiver_evidence_id=ids_post["receiver_evidence_id"],
        acceptance_record_digest=bytes.fromhex(fx_req2["acceptance_record_digest_hex"]),
        authority_actor_id=ZERO16,
        retention_ms=RETENTION_MS,
    )
    terminal_cookie = 0x0102030405060708
    terminal_peer = ids_post["source_runtime_id"]
    other_peer = ids_post["target_runtime_id"]
    terminal_hit = late_matrix[1]  # PAGE_ACCEPT, request_id 8001.
    post_terminal_miss_request_id = 8999
    post_terminal_miss_request_body = (
        bind52(tid_req, 1, md_post) + u32(99) + u32(0)
    )
    post_terminal_miss_response = encode_reject(
        transfer_id=tid_req,
        revision=1,
        manifest_digest=md_post,
        stage=STAGE["RESUME"],
        code=REJECT["STATE"],
    )
    post_terminal_miss_slot = nrc1_slot(
        request_id=post_terminal_miss_request_id,
        session_generation=1,
        request_body_digest=request_body_digest(
            MSG["RESUME_QUERY"], post_terminal_miss_request_body
        ),
        response_type=MSG["TRANSFER_REJECT"],
        response_body=post_terminal_miss_response,
    )
    capacity_busy_body = (
        bind52(tid_req, 1, md_post)
        + u16(STAGE["OPEN"])
        + u16(0)
        + u32(0)
    )
    policy_reject_body = encode_reject(
        transfer_id=tid_req,
        revision=1,
        manifest_digest=md_post,
        stage=STAGE["OPEN"],
        code=REJECT["UNSUPPORTED"],
    )
    deadline_reject_body = encode_reject(
        transfer_id=tid_req,
        revision=1,
        manifest_digest=md_post,
        stage=STAGE["OPEN"],
        code=REJECT["EXPIRED"],
    )
    active_semantic_request_id = 9100
    active_semantic_request = (
        bind52(tid_req, 1, md_post) + u32(0) + u32(0)
    )
    active_semantic_reject = encode_reject(
        transfer_id=tid_req,
        revision=1,
        manifest_digest=md_post,
        stage=STAGE["RESUME"],
        code=REJECT["STATE"],
    )
    active_semantic_slot = nrc1_slot(
        request_id=active_semantic_request_id,
        session_generation=1,
        request_body_digest=request_body_digest(
            MSG["RESUME_QUERY"], active_semantic_request
        ),
        response_type=MSG["TRANSFER_REJECT"],
        response_body=active_semantic_reject,
    )

    out.append(
        vector(
            "MF-POS-NM30-SCHEMA2-LAYOUT-KAT",
            expected={
                "status": "OK",
                "branch": "nm30_schema2_layout",
                "schema": 2,
                "value_length": 180,
                "peer_endpoint_id_offset": 156,
                "peer_endpoint_id_bytes": 16,
                "peer_endpoint_id_nonzero": True,
                "owner_role_offset": 172,
                "owner_role": 2,
                "reserved_offset": 173,
                "reserved_bytes": 3,
                "reserved_zero": True,
                "crc_offset": 176,
                "crc_preimage_bytes": 176,
                "session_cookie_durable": False,
                "session_generation_authority": "NRC1_header_offset_24",
            },
            nm30_value_hex=hx(nm30_post),
            nm30_sha256_hex=hx(sha256(nm30_post)),
            transfer_id_hex=hx(tid_req),
            peer_endpoint_id_hex=hx(terminal_peer),
            owner_role_name="RECEIVER",
            durable_fields_exclude=["session_cookie", "session_generation"],
        )
    )
    out.append(
        vector(
            "MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY",
            expected={
                "status": "REJECT",
                "branch": "legacy_nm30_schema1_replay_ineligible",
                "schema": 1,
                "value_length": 164,
                "canonical_legacy_validation": True,
                "accounting_allowed": True,
                "retention_gc_allowed": True,
                "replay_eligible": False,
                "rebind_allowed": False,
                "wire_response_count": 0,
                "transport_ok": False,
                "peer_role_cookie_inference_forbidden": True,
            },
            legacy_nm30_value_hex=hx(nm30_schema1_legacy),
            catalog_state="replay_ineligible",
            permitted_actions=["charge_actual_row", "retention_gc"],
            forbidden_actions=[
                "cold_replay",
                "rebind",
                "wire_response",
                "infer_peer",
                "infer_role",
                "infer_cookie",
            ],
        )
    )
    out.append(
        vector(
            "MF-TX-HOST-TERMINAL-COLD-REBIND-HIT",
            expected={
                "status": "OK",
                "branch": "host_terminal_cold_rebind_hit",
                "control_route": HOST_CONTROL_ROUTE_SENTINEL,
                "active_slots_consumed": 0,
                "catalog_schema": 2,
                "peer_exact": True,
                "role_exact": True,
                "generation_exact": True,
                "fresh_nonzero_cookie": True,
                "cookie_restored_from_storage": False,
                "nrc1_generation_offset": 24,
                "cacheable": True,
                "nrc1_hit": True,
                "full_count": 0,
                "transfer_state_mutation": 0,
                "response_bit_exact": True,
                "owned_control_outbox": True,
                "transport_status": "OK",
                "post_terminal_miss_cacheable": True,
                "post_terminal_miss_full_count": 1,
                "post_terminal_miss_transfer_state_mutation": 0,
            },
            recovered_catalog_entry={
                "transfer_id_hex": hx(tid_req),
                "peer_endpoint_id_hex": hx(terminal_peer),
                "owner_role": 2,
                "nrc1_session_generation": 1,
                "nm30_schema": 2,
                "replay_eligible": True,
                "session_cookie": 0,
                "bind_valid": False,
            },
            rebind={
                "peer_endpoint_id_hex": hx(terminal_peer),
                "owner_role": 2,
                "session_generation": 1,
                "session_cookie_hex": f"{terminal_cookie:016x}",
                "result": "OK",
            },
            hit={
                "request_id": terminal_hit["request_id"],
                "request_type": terminal_hit["request_type"],
                "request_body_digest_hex": terminal_hit["request_body_digest_hex"],
                "response_type": terminal_hit["response_type"],
                "response_body_hex": terminal_hit["response_body_hex"],
            },
            post_terminal_miss={
                "request_id": post_terminal_miss_request_id,
                "request_type": MSG["RESUME_QUERY"],
                "request_body_hex": hx(post_terminal_miss_request_body),
                "nrc1_slot_hex": hx(post_terminal_miss_slot),
                "response_type": MSG["TRANSFER_REJECT"],
                "response_body_hex": hx(post_terminal_miss_response),
                "reject_code": REJECT["STATE"],
                "full_group": "G_R_REQID_CACHE",
                "wire_after_full_only": True,
            },
            nm30_value_hex=hx(nm30_post),
            nrc1_value_hex=hx(nrc1_post_terminal),
        )
    )
    out.append(
        vector(
            "MF-NEG-HOST-TERMINAL-BIND-MATRIX",
            expected={
                "status": "REJECT",
                "branch": "host_terminal_bind_matrix",
                "exact_initial_rebind": "OK",
                "same_cookie_after_bind": "OK",
                "peer_mismatch": "ERR_STATE",
                "role_mismatch": "ERR_STATE",
                "generation_mismatch": "ERR_STATE",
                "zero_cookie": "ERR_STATE",
                "cookie_swap": "ERR_STATE",
                "mismatch_wire_response_count": 0,
                "mismatch_state_mutation": 0,
                "mismatch_store_mutation": 0,
                "mismatch_outbox_mutation": 0,
            },
            authority={
                "peer_endpoint_id_hex": hx(terminal_peer),
                "owner_role": 2,
                "nrc1_session_generation": 1,
                "cookie_at_recovery": 0,
            },
            cases=[
                {
                    "name": "exact_initial_rebind",
                    "peer_endpoint_id_hex": hx(terminal_peer),
                    "owner_role": 2,
                    "session_generation": 1,
                    "session_cookie_hex": f"{terminal_cookie:016x}",
                    "result": "OK",
                },
                {
                    "name": "same_cookie_after_bind",
                    "peer_endpoint_id_hex": hx(terminal_peer),
                    "owner_role": 2,
                    "session_generation": 1,
                    "session_cookie_hex": f"{terminal_cookie:016x}",
                    "result": "OK",
                },
                {
                    "name": "peer_mismatch",
                    "peer_endpoint_id_hex": hx(other_peer),
                    "owner_role": 2,
                    "session_generation": 1,
                    "session_cookie_hex": f"{terminal_cookie:016x}",
                    "result": "ERR_STATE",
                },
                {
                    "name": "role_mismatch",
                    "peer_endpoint_id_hex": hx(terminal_peer),
                    "owner_role": 1,
                    "session_generation": 1,
                    "session_cookie_hex": f"{terminal_cookie:016x}",
                    "result": "ERR_STATE",
                },
                {
                    "name": "generation_mismatch",
                    "peer_endpoint_id_hex": hx(terminal_peer),
                    "owner_role": 2,
                    "session_generation": 2,
                    "session_cookie_hex": f"{terminal_cookie:016x}",
                    "result": "ERR_STATE",
                },
                {
                    "name": "zero_cookie",
                    "peer_endpoint_id_hex": hx(terminal_peer),
                    "owner_role": 2,
                    "session_generation": 1,
                    "session_cookie_hex": "0000000000000000",
                    "result": "ERR_STATE",
                },
                {
                    "name": "cookie_swap",
                    "peer_endpoint_id_hex": hx(terminal_peer),
                    "owner_role": 2,
                    "session_generation": 1,
                    "session_cookie_hex": "1112131415161718",
                    "result": "ERR_STATE",
                },
            ],
        )
    )
    out.append(
        vector(
            "MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT",
            expected={
                "status": "OK",
                "branch": "four_active_terminal_hit_control_route",
                "active_before": 4,
                "active_after": 4,
                "terminal_catalog_count": 1,
                "active_slot_allocations": 0,
                "control_route": HOST_CONTROL_ROUTE_SENTINEL,
                "nrc1_hit": True,
                "full_count": 0,
                "store_mutation": 0,
                "owned_control_outbox": True,
                "transport_status": "OK",
                "scheduler_cursor_unchanged": True,
                "peer_unpaid_fence_unchanged": True,
            },
            active_transfer_ids=[
                f"{i:032x}" for i in range(1, HOST_SLOT_COUNT + 1)
            ],
            terminal_transfer_id_hex=hx(tid_req),
            terminal_request_id=terminal_hit["request_id"],
            terminal_response_body_hex=terminal_hit["response_body_hex"],
        )
    )
    out.append(
        vector(
            "MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY",
            expected={
                "status": "OK",
                "branch": "four_active_fresh_open_capacity_busy",
                "semantic_response_type": MSG["TRANSFER_BUSY"],
                "reject_code_sidecar": REJECT["CAPACITY"],
                "response_body_length": 60,
                "cacheable": False,
                "stateless": True,
                "full_count": 0,
                "durable_state_mutation": 0,
                "active_before": 4,
                "active_after": 4,
                "owned_control_outbox": True,
                "control_route": HOST_CONTROL_ROUTE_SENTINEL,
                "transport_status": "OK",
                "store_unchanged": True,
                "catalog_unchanged": True,
                "scheduler_cursor_unchanged": True,
            },
            fresh_open_body_hex=fx_req2["open_body_hex"],
            busy_body_hex=hx(capacity_busy_body),
            busy_layout={
                "bind52_bytes": 52,
                "busy_stage_u16": STAGE["OPEN"],
                "reserved_u16": 0,
                "retry_after_ms_u32": 0,
            },
        )
    )
    out.append(
        vector(
            "MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE",
            expected={
                "status": "ERR_BUSY",
                "branch": "control_outbox_no_overwrite",
                "control_outbox_capacity_frames": 1,
                "first_frame_retained_bit_exact": True,
                "second_frame_enqueued": False,
                "second_wire_response_count": 0,
                "full_count": 0,
                "state_mutation": 0,
                "store_mutation": 0,
                "catalog_mutation": 0,
                "scheduler_cursor_unchanged": True,
                "active_fairness_blocked": False,
            },
            first_owned_frame={
                "route": HOST_CONTROL_ROUTE_SENTINEL,
                "message_type": MSG["TRANSFER_BUSY"],
                "body_hex": hx(capacity_busy_body),
            },
            blocked_second_frame={
                "message_type": MSG["TRANSFER_REJECT"],
                "body_hex": hx(policy_reject_body),
                "result": "ERR_BUSY",
            },
        )
    )
    out.append(
        vector(
            "MF-NEG-PREADMISSION-POLICY-STATELESS",
            expected={
                "status": "OK",
                "branch": "preadmission_policy_stateless",
                "semantic_response_type": MSG["TRANSFER_REJECT"],
                "reject_code": REJECT["UNSUPPORTED"],
                "response_body_length": 60,
                "bind52_safe": True,
                "cacheable": False,
                "full_count": 0,
                "durable_rows_created": 0,
                "durable_state_mutation": 0,
                "owned_control_outbox": True,
                "control_route": HOST_CONTROL_ROUTE_SENTINEL,
                "transport_status": "OK",
                "late_duplicate_may_be_reevaluated": True,
                "retry_requires_fresh_nonzero_request_id": True,
            },
            fresh_open_body_hex=fx_req2["open_body_hex"],
            response_body_hex=hx(policy_reject_body),
            admission_policy="OFF",
            g_r_open_started=False,
        )
    )
    out.append(
        vector(
            "MF-NEG-PREADMISSION-DEADLINE-STATELESS",
            expected={
                "status": "OK",
                "branch": "preadmission_deadline_stateless",
                "semantic_response_type": MSG["TRANSFER_REJECT"],
                "reject_code": REJECT["EXPIRED"],
                "response_body_length": 60,
                "bind52_safe": True,
                "cacheable": False,
                "full_count": 0,
                "durable_rows_created": 0,
                "durable_state_mutation": 0,
                "owned_control_outbox": True,
                "control_route": HOST_CONTROL_ROUTE_SENTINEL,
                "transport_status": "OK",
                "late_duplicate_may_be_reevaluated": True,
                "retry_requires_fresh_nonzero_request_id": True,
            },
            fresh_open_body_hex=fx_req2["open_body_hex"],
            response_body_hex=hx(deadline_reject_body),
            deadline_relation="now_ge_absolute_effect_deadline",
            g_r_open_started=False,
        )
    )
    out.append(
        vector(
            "MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED",
            expected={
                "status": "OK",
                "branch": "active_semantic_reject_cached",
                "semantic_response_type": MSG["TRANSFER_REJECT"],
                "reject_code": REJECT["STATE"],
                "response_body_length": 60,
                "active_group_present": True,
                "cacheable": True,
                "nrc1_miss": True,
                "nrc1_full_count": 1,
                "transfer_state_mutation": 0,
                "durable_cache_mutation": 1,
                "wire_after_full_only": True,
                "owned_active_slot_outbox": True,
                "uses_control_outbox": False,
                "transport_status": "OK",
            },
            request_id=active_semantic_request_id,
            request_type=MSG["RESUME_QUERY"],
            request_body_hex=hx(active_semantic_request),
            nrc1_slot_hex=hx(active_semantic_slot),
            response_body_hex=hx(active_semantic_reject),
            active_slot=2,
            full_group="G_R_REQID_CACHE",
        )
    )
    out.append(
        vector(
            "MF-FSM-TERMINAL-ACTIVE-CODES-UNREACHABLE",
            expected={
                "status": "OK",
                "branch": "fsm_terminal_active_removed",
                "durable_active_forbidden_codes": [7, 9, 39],
                "durable_terminal_kind": "NM30_ONLY",
                "both_active_and_nm30": "CORRUPT",
            },
            forbidden_active_state_codes=[7, 9, 39],
            allowed_pre_terminal_active_codes={
                "sender": [6, 8],
                "receiver": [38, 41],
            },
        )
    )
    out.append(
        vector(
            "MF-TRACE-S1-S6-HAPPY-PATH",
            expected={
                "status": "OK",
                "branch": "s1_s6_trace",
                "stages": ["S1", "S2", "S3", "S4", "S5", "S6"],
                "s6_durable": "NM30_ONLY",
            },
            stages=[
                "S1_OPEN",
                "S2_MANIFEST",
                "S3_CHUNKS",
                "S4_FINALIZE_ACCEPT",
                "S5_HANDOFF",
                "S6_TERMINAL_NM30",
            ],
        )
    )

    # Negatives: version / generation / mapping.
    fx_v = transfer_fixture(32, salt=7)
    ids_v = {k: bytes.fromhex(v) for k, v in fx_v["ids"].items()}
    md = bytes.fromhex(fx_v["manifest_digest_hex"])
    stale_resume = encode_resume_query(
        transfer_id=ids_v["transfer_id"],
        revision=1,
        manifest_digest=md,
        query_generation=3,
    )
    out.append(
        vector(
            "MF-NEG-STALE-GENERATION",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["STATE"],
                "stage": STAGE["RESUME"],
                "reason": "query_generation_gap_or_rollback",
            },
            last_query_generation=1,
            offered_query_generation=3,
            resume_query_hex=hx(stale_resume),
        )
    )
    out.append(
        vector(
            "MF-NEG-STALE-VERSION-SELECTED-2",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["UNSUPPORTED"],
                "reason": "mfn1_not_established",
            },
            base_selected_control_version=2,
            mfdt_admission_version=0,
            message_type=MSG["TRANSFER_OPEN"],
        )
    )
    out.append(
        vector(
            "MF-NEG-MIXED-VERSION-PEER",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["UNSUPPORTED"],
                "reason": "stale_or_unbound_mfn1_session",
            },
            base_selected_control_version=2,
            mfn1_session_generation=7,
            active_session_generation=8,
        )
    )
    out.append(
        vector(
            "MF-NEG-RF-MAPPING-UNAVAILABLE",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["UNSUPPORTED"],
                "carrier": "compact_rf_nrw1",
                "mapping": "MAPPING_UNAVAILABLE",
            },
            carrier="compact_rf_nrw1",
        )
    )
    out.append(
        vector(
            "MF-NEG-WIFI-MAPPING-UNAVAILABLE",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["UNSUPPORTED"],
                "carrier": "wifi_nwb1",
                "mapping": "MAPPING_UNAVAILABLE",
            },
            carrier="wifi_nwb1",
        )
    )
    out.append(
        vector(
            "MF-NEG-NFL1-CONTROL-FORBIDDEN",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["UNSUPPORTED"],
                "reason":
                    "ordinary_public_nfl1_must_not_carry_raw_mf_control",
            },
            carrier="nfl1_application_packet",
            attempted_message_type=MSG["TRANSFER_OPEN"],
        )
    )

    # Duplicate / reorder / gap / digest.
    fx_c = transfer_fixture(CHUNK_SIZE + 10, salt=8)
    c0 = fx_c["chunks"][0]
    c1 = fx_c["chunks"][1]
    conflict = bytearray(bytes.fromhex(c0["body_hex"]))
    # Flip one payload byte and repair outer message is body-only; recompute chunk digest
    # inside offer so CRC-less body reaches digest-conflict semantic branch after repair.
    payload_off = 96
    conflict[payload_off] ^= 0x01
    new_chunk = bytes(conflict[payload_off:])
    new_digest = sha256(new_chunk)
    conflict[64:96] = new_digest  # chunk_sha256 field in offer
    out.append(
        vector(
            "MF-NEG-DUPLICATE-CHUNK-CONFLICT",
            expected={
                "status": "TERMINAL_CONFLICT",
                "reject_code": REJECT["DIGEST"],
                "stage": STAGE["CHUNK"],
                "reason": "same_index_different_bytes",
            },
            first_offer_hex=c0["body_hex"],
            second_offer_hex=hx(bytes(conflict)),
            first_digest_hex=c0["chunk_sha256_hex"],
            second_digest_hex=hx(new_digest),
            chunk_index=0,
        )
    )
    out.append(
        vector(
            "MF-NEG-REORDER-GAP",
            expected={
                "status": "OK_REORDER_ACCEPT",
                "bitmap_after": 0b10,
                "missing_indices": [0],
                "gap_does_not_imply_complete": True,
            },
            offers_in_order=[1, 0],
            offer_1_hex=c1["body_hex"],
            offer_0_hex=c0["body_hex"],
            note="receiver accepts out-of-order FULL per index; completion still requires all bits",
        )
    )

    # Whole digest corruption repaired to intended branch.
    fx_d = transfer_fixture(64, salt=9)
    ids_d = {k: bytes.fromhex(v) for k, v in fx_d["ids"].items()}
    bad_whole = bytearray(bytes.fromhex(fx_d["content_sha256_hex"]))
    bad_whole[0] ^= 0x01
    # Rebuild OPEN with mutated whole then recompute manifest digest (repair).
    open_bad = bytearray(bytes.fromhex(fx_d["open_body_hex"]))
    open_bad[32:64] = bytes(bad_whole)
    # recompute manifest digest with corrupted whole in head
    content_d = bytes.fromhex(fx_d["content_hex"])
    entries_d = [bytes.fromhex(e) for e in fx_d["entries_hex"]]
    head = bytes(open_bad[0:202])
    binding = bytes(open_bad[OPEN_BASE_FIXED:OPEN_FIXED])
    text = bytes(open_bad[OPEN_FIXED:])
    repaired_md = sha256(
        b"NM3-MANIFEST-V1" + head + binding + text + b"".join(entries_d)
    )
    open_bad[202:234] = repaired_md
    out.append(
        vector(
            "MF-NEG-DIGEST-CORRUPTION-REPAIRED",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["DIGEST"],
                "reason": "whole_content_digest_mismatch_vs_bytes",
                "manifest_digest_hex": hx(repaired_md),
            },
            open_body_hex=hx(bytes(open_bad)),
            content_hex=fx_d["content_hex"],
            claimed_whole_hex=hx(bytes(bad_whole)),
            actual_whole_hex=fx_d["content_sha256_hex"],
        )
    )
    finalize_bad = encode_finalize(
        transfer_id=ids_d["transfer_id"],
        revision=1,
        manifest_digest=bytes.fromhex(fx_d["manifest_digest_hex"]),
        whole=bytes(bad_whole),
        total_length=64,
    )
    out.append(
        vector(
            "MF-NEG-WHOLE-DIGEST-MISMATCH",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["DIGEST"],
                "stage": STAGE["FINAL"],
            },
            finalize_hex=hx(finalize_bad),
            expected_whole_hex=fx_d["content_sha256_hex"],
        )
    )

    # Expiry boundary: not_after = 400000; now==not_after expired; now==not_after-1 ok.
    out.append(
        vector(
            "MF-NEG-EXPIRY-BOUNDARY-EQ",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["EXPIRED"],
                "reason": "now_ge_not_after",
                "deadline_matrix_all_exact": True,
                "overflow_reject_mutation_zero": True,
                "different_epoch_direct_compare_forbidden": True,
            },
            reservation_not_after_ms=400000,
            now_ms=400000,
            same_epoch=True,
            reservation_deadline_matrix=[
                {
                    "case": "no_deadline",
                    "now_ms": 1000,
                    "deadline_epoch": "ZERO",
                    "deadline_ms_u64_hex": f"{UINT64_MAX:016x}",
                    "status": "OK",
                    "not_after_ms": 301000,
                },
                {
                    "case": "same_epoch_before_now",
                    "now_ms": 1000,
                    "deadline_epoch": "LOCAL",
                    "deadline_ms": 999,
                    "status": "REJECT",
                    "reject_code": REJECT["EXPIRED"],
                    "state_mutation": 0,
                },
                {
                    "case": "same_epoch_equal_now",
                    "now_ms": 1000,
                    "deadline_epoch": "LOCAL",
                    "deadline_ms": 1000,
                    "status": "REJECT",
                    "reject_code": REJECT["EXPIRED"],
                    "state_mutation": 0,
                },
                {
                    "case": "same_epoch_earlier_bound",
                    "now_ms": 1000,
                    "deadline_epoch": "LOCAL",
                    "deadline_ms": 2000,
                    "status": "OK",
                    "not_after_ms": 2000,
                },
                {
                    "case": "same_epoch_later_bound",
                    "now_ms": 1000,
                    "deadline_epoch": "LOCAL",
                    "deadline_ms": 999999,
                    "status": "OK",
                    "not_after_ms": 301000,
                },
                {
                    "case": "different_epoch_without_projection",
                    "now_ms": 1000,
                    "deadline_epoch": "OTHER",
                    "deadline_ms": 1,
                    "status": "REJECT",
                    "reject_code": REJECT["STATE"],
                    "state_mutation": 0,
                    "numeric_compare_performed": False,
                },
                {
                    "case": "reservation_add_overflow",
                    "now_ms_u64_hex":
                        f"{UINT64_MAX - RESERVATION_LIFETIME_MS + 1:016x}",
                    "deadline_epoch": "ZERO",
                    "deadline_ms_u64_hex": f"{UINT64_MAX:016x}",
                    "status": "REJECT",
                    "reject_code": REJECT["EXPIRED"],
                    "state_mutation": 0,
                },
            ],
        )
    )
    out.append(
        vector(
            "MF-NEG-EXPIRY-BOUNDARY-BEFORE",
            expected={
                "status": "OK",
                "branch": "reservation_valid",
            },
            reservation_not_after_ms=400000,
            now_ms=399999,
            same_epoch=True,
        )
    )

    # Abort races.
    fx_a = transfer_fixture(128, salt=10)
    ids_a = {k: bytes.fromhex(v) for k, v in fx_a["ids"].items()}
    md_a = bytes.fromhex(fx_a["manifest_digest_hex"])
    abort_body = encode_abort(
        transfer_id=ids_a["transfer_id"],
        revision=1,
        manifest_digest=md_a,
        reason=1,
        authority_actor_id=ids_a["authority_actor_id"],
        abort_generation=1,
    )
    out.append(
        vector(
            "MF-NEG-ABORT-AFTER-CONTENT-VERIFIED",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["ABORT_DENIED"],
                "stage": STAGE["ABORT"],
                "reason": "receiver_already_content_verified",
            },
            receiver_state=36,
            abort_hex=hx(abort_body),
        )
    )
    nm30_abort, tomb_d = build_nm30(
        ids=ids_a,
        revision=1,
        manifest_digest=md_a,
        terminal_state=2,
        terminal_reason=1,
        abort_generation=1,
        receiver_evidence_id=ZERO16,
        acceptance_record_digest=ZERO32,
        authority_actor_id=ids_a["authority_actor_id"],
    )
    abort_ack = encode_abort_ack(
        transfer_id=ids_a["transfer_id"],
        revision=1,
        manifest_digest=md_a,
        abort_generation=1,
        final_state=2,
        tombstone_digest=tomb_d,
    )
    out.append(
        vector(
            "MF-NEG-ABORT-RACE-FINALIZE-FIRST",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["ABORT_DENIED"],
                "winner": "FINALIZE_FULL",
            },
            first_full="FINALIZE_ACCEPT",
            second="ABORT",
            abort_hex=hx(abort_body),
        )
    )
    out.append(
        vector(
            "MF-NEG-ABORT-RACE-ABORT-FIRST",
            expected={
                "status": "OK",
                "branch": "aborted_terminal",
                "winner": "ABORT_FULL",
                "tombstone_digest_hex": hx(tomb_d),
                "abort_ack_hex": hx(abort_ack),
            },
            first_full="ABORT",
            second="FINALIZE",
            nm30_hex=hx(nm30_abort),
            abort_ack_hex=hx(abort_ack),
        )
    )

    out.append(
        vector(
            "MF-NEG-PARTIAL-APPLY-FORBIDDEN",
            expected={
                "status": "REJECT",
                "reason": "publication_before_content_verified",
                "publication_state": 0,
            },
            receiver_state=35,
            chunk_bitmap=0b01,
            chunk_count=2,
            may_prepare=False,
        )
    )
    out.append(
        vector(
            "MF-NEG-FALSE-CUSTODY-BITMAP",
            expected={
                "status": "REJECT",
                "reason": "resume_bitmap_is_hint_not_custody_completion",
                "sender_may_release_payload": False,
            },
            resume_bitmap=0b11,
            transfer_accept_received=False,
        )
    )
    out.append(
        vector(
            "MF-NEG-RESOURCE-EXHAUSTION-KEYS",
            expected={
                "status": "OK",
                "branch": "bounded_host_and_esp_admission",
                "reject_code": REJECT["CAPACITY"],
                "state_mutation": 0,
                "host_first_four_admitted": True,
                "host_fifth_rejected": True,
                "host_active_after_fifth": 4,
                "host_slot_order": [0, 1, 2, 3],
                "esp_first_admitted": True,
                "esp_second_rejected": True,
                "esp_active_after_second": 1,
            },
            namespace_keys_in_use=30,
            keys_hard_max=32,
            mfdt_requires_keys=3,  # active + NRC1 + terminal staging
            admission=False,
            host_admission_trace=[
                {"transfer_id": "00000000000000000000000000000001", "slot": 0, "status": "ADMITTED"},
                {"transfer_id": "00000000000000000000000000000002", "slot": 1, "status": "ADMITTED"},
                {"transfer_id": "00000000000000000000000000000003", "slot": 2, "status": "ADMITTED"},
                {"transfer_id": "00000000000000000000000000000004", "slot": 3, "status": "ADMITTED"},
                {
                    "transfer_id": "00000000000000000000000000000005",
                    "slot": None,
                    "status": "REJECT_CAPACITY",
                    "state_mutation": 0,
                },
            ],
            host_restart_input_transfer_ids=[
                "00000000000000000000000000000004",
                "00000000000000000000000000000001",
                "00000000000000000000000000000003",
                "00000000000000000000000000000002",
            ],
            host_restart_canonical_slot_transfer_ids=[
                "00000000000000000000000000000001",
                "00000000000000000000000000000002",
                "00000000000000000000000000000003",
                "00000000000000000000000000000004",
            ],
            esp_admission_trace=[
                {"transfer_id": "00000000000000000000000000000011", "status": "ADMITTED"},
                {
                    "transfer_id": "00000000000000000000000000000012",
                    "status": "REJECT_CAPACITY",
                    "state_mutation": 0,
                },
            ],
        )
    )
    out.append(
        vector(
            "MF-NEG-RESOURCE-EXHAUSTION-BYTES",
            expected={
                "status": "BUSY_OR_REJECT",
                "reject_code": REJECT["CAPACITY"],
                "state_mutation": 0,
            },
            # 50519 = 35247 (active) + 15056 (NRC1) + 216 (NM30 staging row)
            namespace_logical_bytes_in_use=69632 - ADMISSION_RESERVED_LOGICAL_BYTES + 1,
            bytes_hard_max=69632,
            mfdt_requires_bytes=ADMISSION_RESERVED_LOGICAL_BYTES,
            admission=False,
            host_bounds={
                "slot_count": HOST_SLOT_COUNT,
                "per_slot_workspace_bytes": WORKSPACE_BYTES,
                "coordinator_bytes": HOST_COORDINATOR_BYTES,
                "aggregate_workspace_bytes": HOST_OWNER_WORKSPACE_BYTES,
                "active_group_logical_bytes": ACTIVE_GROUP_LOGICAL_BYTES,
                "terminal_group_logical_bytes": TERMINAL_GROUP_LOGICAL_BYTES,
                "four_active_committed_logical_bytes":
                    HOST_SLOT_COUNT * ACTIVE_GROUP_LOGICAL_BYTES,
                "tracked_transfer_groups_max": 16,
                "committed_logical_bytes_hard_max":
                    budget["host_committed_logical_bytes_hard_max"],
                "serialized_full_staging_logical_bytes_max":
                    budget["host_serialized_full_staging_logical_bytes_max"],
                "begin_final_union_logical_bytes_hard_max":
                    budget["host_begin_final_union_logical_bytes_hard_max"],
            },
        )
    )
    out.append(
        vector(
            "MF-NEG-FAIRNESS-TWO-OUTSTANDING",
            expected={
                "status": "OK",
                "branch": "host_deterministic_round_robin_and_peer_backpressure",
                "reason": "more_than_one_unpaid_chunk_offer_per_peer_forbidden",
                "max_outstanding": 1,
                "selection_trace": [0, 1, 2, 3, 0, 1, 2, 3],
                "fair_selection_bound": 4,
                "restart_next_slot": 0,
                "blocked_peer_slots_skipped": [0, 2],
                "different_peer_slot_selected": 1,
            },
            outstanding_unpaid_offers=2,
            initial_next_slot=0,
            continuously_eligible_slots=[0, 1, 2, 3],
            successful_selection_trace=[0, 1, 2, 3, 0, 1, 2, 3],
            peer_assignment_by_slot=["peer-a", "peer-b", "peer-a", "peer-c"],
            peer_a_has_unpaid_offer=True,
            scan_from_slot=0,
            selected_slot_with_peer_a_blocked=1,
            next_slot_after_selection=2,
            restart_next_slot=0,
        )
    )
    out.append(
        vector(
            "MF-NEG-MAX-CHUNKS-PLUS-ONE",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["LAYOUT"],
                "reason": "chunk_count_exceeds_37",
            },
            claimed_total_length=MAX_CONTENT + 1,
            max_content=MAX_CONTENT,
        )
    )
    out.append(
        vector(
            "MF-NEG-DEFAULT-OFF-POLICY",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["UNSUPPORTED"],
                "reason": "mf_policy_default_off",
            },
            base_selected_control_version=2,
            mfdt_admission_version=MFDT_ADMISSION_PROFILE_REVISION,
            local_policy="OFF",
        )
    )
    out.append(
        vector(
            "MF-NEG-STORAGE-SIDECAR-COLLISION",
            expected={
                "status": "REJECT",
                "branch": "derived_namespace_collision_binding_mismatch",
                "reason": "base_namespace_binding_mismatch",
                "existing_rows_overwritten": False,
                "foundation_scan_relaxed": False,
                "wire_or_apply": 0,
            },
            cases=[
                "caller_base_equals_derived_namespace",
                "different_base_same_derived_namespace_simulation",
                "binding_missing_with_foreign_rows",
                "binding_wrong_base_digest",
                "binding_wrong_full_base_bytes",
                "binding_wrong_crc32c",
                "foreign_key_present",
            ],
            authority=sidecar,
            note="collision is detected by exact NMS1 binding, not assumed impossible",
        )
    )
    out.append(
        vector(
            "MF-NEG-REQID-BODY-CONFLICT",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["DUPLICATE"],
                "reason": "request_id_body_digest_conflict",
                "state_mutation": 0,
            },
            request_id=9,
            first_request_body_digest_hex=hx(sha256(b"NM3-REQ-BODY-A")),
            second_request_body_digest_hex=hx(sha256(b"NM3-REQ-BODY-B")),
            nrc1_slot_occupied=True,
        )
    )
    full_slots = [
        nrc1_slot(
            request_id=100 + i,
            session_generation=1,
            request_body_digest=request_body_digest(
                MSG["CHUNK_OFFER"], bytes([i & 0xFF]) * 96
            ),
            response_type=MSG["CHUNK_ACCEPT"],
            response_body=bytes([i & 0xFF]) * 88,
        )
        for i in range(NRC1_SLOT_COUNT)
    ]
    nrc1_full = build_nrc1_value(
        transfer_id=tid_req,
        session_generation=1,
        slots=full_slots,
        next_insert_seq=NRC1_SLOT_COUNT,
    )
    out.append(
        vector(
            "MF-NEG-REQID-CACHE-FULL",
            expected={
                "status": "BUSY_OR_REJECT",
                "reject_code": REJECT["CAPACITY"],
                "reason": "request_id_cache_full",
                "state_mutation": 0,
                "no_silent_eviction": True,
                "slot_count": NRC1_SLOT_COUNT,
            },
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_full),
            occupied_count=NRC1_SLOT_COUNT,
            new_request_id=999,
        )
    )
    fx_open = transfer_fixture(1, salt=33)
    open_body_sample = bytes.fromhex(fx_open["open_body_hex"])
    open_preimage = (
        bytes([MSG["TRANSFER_OPEN"] & 0xFF]) + u16(len(open_body_sample)) + open_body_sample
    )
    open_dig = sha256(open_preimage)
    # Alternate wrong preimage "body after BIND52" is undefined for OPEN (no BIND52).
    wrong_bind52_strip = open_body_sample[52:] if len(open_body_sample) > 52 else b""
    wrong_dig = sha256(
        bytes([MSG["TRANSFER_OPEN"] & 0xFF])
        + u16(len(wrong_bind52_strip))
        + wrong_bind52_strip
    )
    out.append(
        vector(
            "MF-NEG-REQID-DIGEST-OPEN-PREIMAGE",
            expected={
                "status": "OK",
                "branch": "open_digest_preimage",
                "includes_bind52_strip": False,
                "preimage": "type_u8||len_u16be||full_open_body",
                "message_type": MSG["TRANSFER_OPEN"],
                "bind52_strip_digest_differs": True,
            },
            message_type=MSG["TRANSFER_OPEN"],
            open_body_hex=hx(open_body_sample),
            request_body_digest_hex=hx(open_dig),
            open_preimage_hex=hx(open_preimage),
            wrong_bind52_strip_digest_hex=hx(wrong_dig),
            note="TRANSFER_OPEN has no BIND52; digest is SHA-256(type||len||full body), not after-BIND52",
        )
    )
    out.append(
        vector(
            "MF-NEG-REQID-POST-RETENTION-EXPIRED",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["EXPIRED"],
                "reason": "transfer_expired",
                "state_mutation": 0,
                "nrc1_present": False,
                "nm30_present": False,
                "bit_exact_replay_forbidden": True,
            },
            phase="post_retention_gc",
            nrc1_present=False,
            nm30_present=False,
            request_id=8000,
            note="after G_*_RETENTION_GC both NM30 and NRC1 absent; closed EXPIRED, not body replay",
        )
    )
    out.append(
        vector(
            "MF-NEG-EPOCH-CHANGE-MID-TRANSFER",
            expected={
                "status": "REJECT",
                "reject_code": REJECT["STATE"],
                "reason": "local_clock_epoch_changed",
                "publication_after": "NONE",
                "prepare_forbidden": True,
            },
            epoch_before_hex="a1a2a3a4a5a6a7a8a9aaabacadaeafb0",
            epoch_after_hex="b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
            transfer_state_before="R_CHUNKS_PARTIAL",
        )
    )

    # COMMIT_UNKNOWN matrices for receiver chunk group and terminal group.
    fx_cu = transfer_fixture(40, salt=11)
    ids_cu = {k: bytes.fromhex(v) for k, v in fx_cu["ids"].items()}
    md_cu = bytes.fromhex(fx_cu["manifest_digest_hex"])
    open_cu = bytes.fromhex(fx_cu["open_body_hex"])
    entries_cu = [bytes.fromhex(e) for e in fx_cu["entries_hex"]]
    content_cu = bytes.fromhex(fx_cu["content_hex"])
    old_rec = build_active_record(
        kind=b"NM3R",
        owner_side=2,
        state_code=34,
        open_body=open_cu,
        entries=entries_cu,
        content=bytes(len(content_cu)),  # slots zero until chunks
        ids=ids_cu,
        manifest_digest=md_cu,
        revision=1,
        record_generation=5,
        chunk_bitmap=0,
        page_bitmap=fx_cu["full_page_bitmap"],
        reservation_not_after_ms=fx_cu["reservation_not_after_ms"],
    )
    # NEW: first chunk committed
    new_content = bytearray(len(content_cu))
    off0, len0 = chunk_range(len(content_cu), 0)
    new_content[off0 : off0 + len0] = content_cu[off0 : off0 + len0]
    new_rec = build_active_record(
        kind=b"NM3R",
        owner_side=2,
        state_code=35,
        open_body=open_cu,
        entries=entries_cu,
        content=bytes(new_content),
        ids=ids_cu,
        manifest_digest=md_cu,
        revision=1,
        record_generation=6,
        chunk_bitmap=0b1,
        page_bitmap=fx_cu["full_page_bitmap"],
        reservation_not_after_ms=fx_cu["reservation_not_after_ms"],
    )
    partial = new_rec[: len(new_rec) // 2]
    third = bytearray(new_rec)
    third[13] = 33  # wrong state
    third = bytearray(repair_record_crc(bytes(third)))
    third[100] ^= 0x01  # mutate after repair => neither old nor new
    third = repair_record_crc(bytes(third))
    # ensure third differs from both
    if bytes(third) in (old_rec, new_rec):
        third = bytearray(new_rec)
        third[216] ^= 0xFF
        third = repair_record_crc(bytes(third))
    key_cu = storage_key(b"NM3R", ids_cu["transfer_id"])
    extra_key = storage_key(b"NM3S", ids_cu["transfer_id"])

    binding_key = bytes.fromhex(sidecar["binding_key_hex"])
    binding_new = bytes.fromhex(sidecar["binding_value_hex"])
    binding_partial = binding_new[: len(binding_new) // 2]
    binding_third = bytearray(binding_new)
    binding_third[16] ^= 0x01
    binding_third[-4:] = u32(crc32c(binding_third[:-4]))
    binding_extra_key = b"NM3S" + pattern(0x90, 16)

    def binding_cu_case(
        vector_id: str,
        classification: str,
        observed_rows: list[dict[str, str]],
    ) -> dict[str, Any]:
        return vector(
            vector_id,
            expected={
                "status": "COMMIT_UNKNOWN_CLASSIFIED",
                "classification": classification,
                "wire_success": 0,
                "foundation_mutation": 0,
            },
            group="MFDT_NAMESPACE_BINDING_BOOTSTRAP",
            old_rows=[],
            new_rows=[
                {
                    "key_hex": hx(binding_key),
                    "value_hex": hx(binding_new),
                }
            ],
            observed_rows=observed_rows,
            note="reopen sidecar before classify; only ABSENT or exact NEW is recoverable",
        )

    out.append(
        binding_cu_case(
            "MF-CU-STORAGE-BINDING-NEW",
            "NEW",
            [{"key_hex": hx(binding_key), "value_hex": hx(binding_new)}],
        )
    )
    out.append(
        binding_cu_case(
            "MF-CU-STORAGE-BINDING-PARTIAL",
            "PARTIAL",
            [{"key_hex": hx(binding_key), "value_hex": hx(binding_partial)}],
        )
    )
    out.append(
        binding_cu_case(
            "MF-CU-STORAGE-BINDING-EXTRA",
            "EXTRA",
            [
                {"key_hex": hx(binding_key), "value_hex": hx(binding_new)},
                {"key_hex": hx(binding_extra_key), "value_hex": "00"},
            ],
        )
    )
    out.append(
        binding_cu_case(
            "MF-CU-STORAGE-BINDING-THIRD",
            "THIRD",
            [{"key_hex": hx(binding_key), "value_hex": hx(bytes(binding_third))}],
        )
    )
    out.append(
        binding_cu_case(
            "MF-CU-STORAGE-BINDING-ABSENT",
            "ABSENT",
            [],
        )
    )

    def cu_case(
        vector_id: str,
        classification: str,
        observed_rows: list[dict[str, str]],
        wire_success: int = 0,
    ) -> dict[str, Any]:
        return vector(
            vector_id,
            expected={
                "status": "COMMIT_UNKNOWN_CLASSIFIED",
                "classification": classification,
                "wire_success": wire_success,
                "send_or_accept": 0,
            },
            group="G_R_CHUNK",
            old_rows=[{"key_hex": hx(key_cu), "value_hex": hx(old_rec)}],
            new_rows=[{"key_hex": hx(key_cu), "value_hex": hx(new_rec)}],
            observed_rows=observed_rows,
        )

    out.append(
        cu_case(
            "MF-CU-RECEIVER-CHUNK-OLD",
            "OLD",
            [{"key_hex": hx(key_cu), "value_hex": hx(old_rec)}],
        )
    )
    out.append(
        cu_case(
            "MF-CU-RECEIVER-CHUNK-NEW",
            "NEW",
            [{"key_hex": hx(key_cu), "value_hex": hx(new_rec)}],
        )
    )
    out.append(
        cu_case(
            "MF-CU-RECEIVER-CHUNK-PARTIAL",
            "PARTIAL",
            [{"key_hex": hx(key_cu), "value_hex": hx(partial)}],
        )
    )
    out.append(
        cu_case(
            "MF-CU-RECEIVER-CHUNK-EXTRA",
            "EXTRA",
            [
                {"key_hex": hx(key_cu), "value_hex": hx(new_rec)},
                {
                    "key_hex": hx(extra_key),
                    "value_hex": hx(old_rec),  # unexpected extra key
                },
            ],
        )
    )
    out.append(
        cu_case(
            "MF-CU-RECEIVER-CHUNK-THIRD",
            "THIRD",
            [{"key_hex": hx(key_cu), "value_hex": hx(bytes(third))}],
        )
    )
    out.append(
        cu_case(
            "MF-CU-RECEIVER-CHUNK-ABSENT",
            "ABSENT",
            [],
        )
    )

    # Terminal group: active erase + NM30 put
    active_pre = build_active_record(
        kind=b"NM3R",
        owner_side=2,
        state_code=38,
        open_body=open_cu,
        entries=entries_cu,
        content=content_cu,
        ids=ids_cu,
        manifest_digest=md_cu,
        revision=1,
        record_generation=50,
        chunk_bitmap=fx_cu["full_chunk_bitmap"],
        page_bitmap=fx_cu["full_page_bitmap"],
        publication_state=2,
        handoff_state=1,
        accept_notified=1,
        acceptance_record_generation=100,
        acceptance_record_digest=bytes.fromhex(fx_cu["acceptance_record_digest_hex"]),
        publication_token_v=bytes.fromhex(fx_cu["publication_token_hex"]),
        publication_evidence_digest=sha256(b"handoff-evidence"),
        reservation_not_after_ms=fx_cu["reservation_not_after_ms"],
    )
    nm30_term = bytes.fromhex(fx_cu["nm30_value_hex"])
    k_active = storage_key(b"NM3R", ids_cu["transfer_id"])
    k_term = storage_key(b"NM30", ids_cu["transfer_id"])
    old_term_rows = [{"key_hex": hx(k_active), "value_hex": hx(active_pre)}]
    new_term_rows = [{"key_hex": hx(k_term), "value_hex": hx(nm30_term)}]

    def term_cu(
        vector_id: str,
        classification: str,
        observed: list[dict[str, str]],
    ) -> dict[str, Any]:
        return vector(
            vector_id,
            expected={
                "status": "COMMIT_UNKNOWN_CLASSIFIED",
                "classification": classification,
                "wire_success": 0,
                "send_or_accept": 0,
            },
            group="G_R_TERMINAL",
            old_rows=old_term_rows,
            new_rows=new_term_rows,
            observed_rows=observed,
        )

    out.append(term_cu("MF-CU-TERMINAL-GROUP-OLD", "OLD", old_term_rows))
    out.append(term_cu("MF-CU-TERMINAL-GROUP-NEW", "NEW", new_term_rows))
    out.append(
        term_cu(
            "MF-CU-TERMINAL-GROUP-PARTIAL",
            "PARTIAL",
            [{"key_hex": hx(k_term), "value_hex": hx(nm30_term[:80])}],
        )
    )
    out.append(
        term_cu(
            "MF-CU-TERMINAL-GROUP-EXTRA",
            "EXTRA",
            old_term_rows
            + new_term_rows
            + [{"key_hex": hx(extra_key), "value_hex": hx(active_pre)}],
        )
    )
    third_nm30 = bytearray(nm30_term)
    third_nm30[60] = 3
    third_nm30 = repair_nm30_crc(bytes(third_nm30))
    out.append(
        term_cu(
            "MF-CU-TERMINAL-GROUP-THIRD",
            "THIRD",
            [{"key_hex": hx(k_term), "value_hex": hx(third_nm30)}],
        )
    )
    out.append(term_cu("MF-CU-TERMINAL-GROUP-ABSENT", "ABSENT", []))
    out.append(
        term_cu(
            "MF-CU-TERMINAL-GROUP-BOTH",
            "BOTH",
            old_term_rows + new_term_rows,
        )
    )
    # NRC1 mid-transfer ABSENT (cache lost without terminal) — uses REQID fixture symbols.
    out.append(
        vector(
            "MF-CU-NRC1-ABSENT-MID-TRANSFER",
            expected={
                "status": "COMMIT_UNKNOWN_CLASSIFIED",
                "classification": "ABSENT",
                "wire_success": 0,
                "send_or_accept": 0,
                "action": "CORRUPT_fence",
                "reason": "nrc1_missing_after_prior_success",
            },
            group="G_R_REQID_CACHE",
            old_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            new_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            observed_rows=[],
        )
    )

    def nrc1_cu(
        vid: str,
        classification: str,
        *,
        old_rows: list[dict[str, str]],
        new_rows: list[dict[str, str]],
        observed_rows: list[dict[str, str]],
        action: str,
        note: str,
    ) -> dict[str, Any]:
        return vector(
            vid,
            expected={
                "status": "COMMIT_UNKNOWN_CLASSIFIED",
                "classification": classification,
                "wire_success": 0,
                "action": action,
                "nrc1_retained_post_terminal": True,
                "nm30_alone_cannot_synthesize_response": True,
            },
            group="G_R_REQID_CACHE",
            old_rows=old_rows,
            new_rows=new_rows,
            observed_rows=observed_rows,
            note=note,
        )

    # Whole-lifetime NRC1 CU: post-terminal retention is still NRC1 hit path (OLD),
    # not "NM30 only = NEW". NM30 alone never classifies as NEW for a prior success body.
    out.append(
        nrc1_cu(
            "MF-CU-NRC1-OLD",
            "OLD",
            old_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            new_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            observed_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            action="replay_bit_exact_from_nrc1",
            note="observed==intended OLD (active or post-terminal pre-GC)",
        )
    )
    out.append(
        nrc1_cu(
            "MF-CU-NRC1-NEW",
            "NEW",
            old_rows=[],
            new_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            observed_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            action="adopt_new_state_no_target_replay_before_attestation",
            note=(
                "NEW may be adopted for recovery, but unattested ESP same-ID and "
                "cold-restart NRC1 replay remain COMMIT_UNKNOWN; Host FULL-capable "
                "STORAGE_OK replay remains functional"
            ),
        )
    )
    out[-1]["expected"].update(
        {
            "target_same_id_retry": "COMMIT_UNKNOWN",
            "target_cold_restart_retry": "COMMIT_UNKNOWN",
            "target_active_plus_nrc1_replay": "COMMIT_UNKNOWN",
            "target_nrc1_only_replay": "COMMIT_UNKNOWN",
            "host_full_capable_replay": "OK",
            "attestation_magic_only_accepted": False,
        }
    )
    partial_nrc1 = nrc1_after_first[: len(nrc1_after_first) // 2]
    out.append(
        nrc1_cu(
            "MF-CU-NRC1-PARTIAL",
            "PARTIAL",
            old_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            new_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            observed_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(partial_nrc1)}],
            action="CORRUPT_fence",
            note="truncated NRC1 value",
        )
    )
    out.append(
        nrc1_cu(
            "MF-CU-NRC1-EXTRA",
            "EXTRA",
            old_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            new_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            observed_rows=[
                {"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)},
                {
                    "key_hex": hx(storage_key(b"NRC1", pattern(0xEE, 16))),
                    "value_hex": hx(nrc1_after_first),
                },
            ],
            action="CORRUPT_fence",
            note="extra NRC1 key for transfer group",
        )
    )
    third_body = bytearray(nrc1_after_first)
    # Repaired-CRC semantic mutant: occupied slot loses its per-slot generation.
    third_body[48:52] = bytes(4)
    third_body = bytearray(repair_nrc1_crc(bytes(third_body)))
    out.append(
        nrc1_cu(
            "MF-CU-NRC1-THIRD",
            "THIRD",
            old_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            new_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            observed_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(bytes(third_body))}],
            action="CORRUPT_fence",
            note="third distinct NRC1 value neither old nor new",
        )
    )
    out.append(
        nrc1_cu(
            "MF-CU-NRC1-ABSENT-POST-TERMINAL",
            "ABSENT",
            old_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            new_rows=[{"key_hex": nrc1_key_hex, "value_hex": hx(nrc1_after_first)}],
            observed_rows=[],  # NRC1 missing while NM30 still present (pre-GC) is CORRUPT
            action="CORRUPT_fence",
            note="post-terminal ABSENT of NRC1 while NM30 present is fence, not NM30-only NEW",
        )
    )

    # Expiry: REJECT alone is insufficient — mandatory tombstone FULL frees active slot.
    # The catalog below is a byte-exact terminal cross-product oracle. EXPIRED=5 is
    # terminal-only; wire TRANSFER_ABORT continues to accept only reasons 1..4.
    nm30_expiry, nm30_expiry_digest = build_nm30(
        ids=ids_a,
        revision=1,
        manifest_digest=md_a,
        terminal_state=NM30_STATE["ABORTED"],
        terminal_reason=NM30_REASON["EXPIRED"],
        abort_generation=0,
        receiver_evidence_id=ZERO16,
        acceptance_record_digest=ZERO32,
        authority_actor_id=ZERO16,
        retention_ms=RETENTION_MS,
    )
    terminal_catalog: list[dict[str, Any]] = []
    nm30_complete, _ = build_nm30(
        ids=ids_a,
        revision=1,
        manifest_digest=md_a,
        terminal_state=NM30_STATE["COMPLETE"],
        terminal_reason=NM30_REASON["COMPLETE"],
        abort_generation=0,
        receiver_evidence_id=ids_a["receiver_evidence_id"],
        acceptance_record_digest=bytes.fromhex(fx_a["acceptance_record_digest_hex"]),
        authority_actor_id=ZERO16,
        retention_ms=RETENTION_MS,
    )
    terminal_catalog.append(
        {
            "class": "COMPLETE",
            "terminal_state": NM30_STATE["COMPLETE"],
            "terminal_reason": NM30_REASON["COMPLETE"],
            "abort_generation": 0,
            "authority_actor_zero": True,
            "evidence_nonzero_pair": True,
            "nm30_hex": hx(nm30_complete),
        }
    )
    for reason_name in ("OPERATOR", "SUPERSEDED", "DEADLINE", "POLICY"):
        reason = NM30_REASON[reason_name]
        nm30_authority_abort, _ = build_nm30(
            ids=ids_a,
            revision=1,
            manifest_digest=md_a,
            terminal_state=NM30_STATE["ABORTED"],
            terminal_reason=reason,
            abort_generation=reason,
            receiver_evidence_id=ZERO16,
            acceptance_record_digest=ZERO32,
            authority_actor_id=ids_a["authority_actor_id"],
            retention_ms=RETENTION_MS,
        )
        terminal_catalog.append(
            {
                "class": f"ABORTED_{reason_name}",
                "terminal_state": NM30_STATE["ABORTED"],
                "terminal_reason": reason,
                "abort_generation": reason,
                "authority_actor_zero": False,
                "evidence_zero_pair": True,
                "nm30_hex": hx(nm30_authority_abort),
            }
        )
    terminal_catalog.append(
        {
            "class": "ABORTED_EXPIRED",
            "terminal_state": NM30_STATE["ABORTED"],
            "terminal_reason": NM30_REASON["EXPIRED"],
            "abort_generation": 0,
            "authority_actor_zero": True,
            "evidence_zero_pair": True,
            "nm30_hex": hx(nm30_expiry),
        }
    )
    for reason_name in ("STORE_CORRUPT", "EPOCH_CHANGED"):
        reason = NM30_REASON[reason_name]
        nm30_corrupt, _ = build_nm30(
            ids=ids_a,
            revision=1,
            manifest_digest=md_a,
            terminal_state=NM30_STATE["CORRUPT_FENCED"],
            terminal_reason=reason,
            abort_generation=0,
            receiver_evidence_id=ZERO16,
            acceptance_record_digest=ZERO32,
            authority_actor_id=ZERO16,
            retention_ms=RETENTION_MS,
        )
        terminal_catalog.append(
            {
                "class": f"CORRUPT_{reason_name}",
                "terminal_state": NM30_STATE["CORRUPT_FENCED"],
                "terminal_reason": reason,
                "abort_generation": 0,
                "authority_actor_zero": True,
                "evidence_zero_pair": True,
                "nm30_hex": hx(nm30_corrupt),
            }
        )
    out.append(
        vector(
            "MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX",
            expected={
                "status": "OK",
                "branch": (
                    "canonical_roster_target_attempt_prearm_"
                    "foundation_full_reconcile"
                ),
                "target_count_min": 1,
                "target_count_max": 4,
                "runtime_uniqueness_scope": "MFDT_V1_ONLY",
                "target_runtime_unique_within_origin": True,
                "same_runtime_different_application_instance_rejected": True,
                "duplicate_runtime_api_status": "NINLIL_OK",
                "duplicate_runtime_submission_state": "REJECTED",
                "duplicate_runtime_reason": "TARGET_COUNT_UNSUPPORTED",
                "duplicate_runtime_entropy_draws": 0,
                "duplicate_runtime_sidecar_mutations": 0,
                "duplicate_runtime_foundation_mutations": 0,
                "compound_receiver_key_created": False,
                "nts3_target_local_suffix_rule_changed": False,
                "attempt_draw_order": "canonical_target_order",
                "attempt_draws_max_per_target": 4,
                "attempt_collision_set": (
                    "durable_active_retained_plus_prior_same_admission_candidates"
                ),
                "attempt_candidate_nonzero": True,
                "attempt_candidate_bound_to_target_open": True,
                "attempt_consumed_claim_before_foundation_full": 0,
                "sidecar_prearm_before_foundation_full": True,
                "wire_txgate_callback_before_foundation_full": 0,
                "foundation_admission_full_count": 1,
                "foundation_admission_atomic_members": [
                    "exact_target_roster",
                    "per_target_attempt_index_and_binding",
                    "attempt_budget_and_counters",
                    "ATTEMPT_PREPARED_and_pending_state",
                    "per_target_mfdt_transfer_id_and_origin_ordinal",
                ],
                "admission_execution_scope": "owner_thread_call",
                "restart_reconcile_before_bearer_open": True,
                "new_durable_state_added": False,
                "foundation_commit_unknown_deletes_sidecar": False,
                "blind_attempt_redraw_forbidden": True,
                "orphan_cleanup_before_wire_or_apply": True,
                "missing_sidecar_for_durable_mfdt": "CORRUPT_FENCE",
                "matching_both": "RESUME_ELIGIBLE",
                "wire_or_apply_before_match": 0,
            },
            steps=[
                "OWNER_THREAD_CANONICALIZE_ROSTER_AND_REJECT_DUPLICATE_RUNTIME",
                "DRAW_NONZERO_UNIQUE_ATTEMPT_MAX4_PER_TARGET_CANONICAL_ORDER",
                "COLLISION_SET_INCLUDES_PRIOR_SAME_ADMISSION_CANDIDATES",
                "BIND_EACH_ATTEMPT_TO_ITS_TARGET_OPEN",
                "FULL_SIDECAR_ARM_EACH_TARGET_WITH_WIRE_TXGATE_CALLBACK_ZERO",
                "FULL_FOUNDATION_ADMISSION_ONCE_ONLY_AFTER_ALL_ARMS_NEW",
                "FOUNDATION_FULL_ATOMIC_ROSTER_ATTEMPTS_BUDGET_COUNTERS_PREPARED_PENDING_MFDT_BINDING",
                "DEFINITE_CANDIDATE_OR_ARM_FAILURE_CLEAN_CREATED_ARMS_FOUNDATION_FULL_ZERO",
                "DEFINITE_FOUNDATION_FAILURE_CLEAN_ALL_ARMS",
                "ARM_OR_CLEANUP_COMMIT_UNKNOWN_FENCE_FOR_COLD_RECONCILE",
                "FOUNDATION_COMMIT_UNKNOWN_KEEP_ARMS_FENCE_RECONCILE_NO_REDRAW",
                "RESTART_RECONCILE_BEFORE_BEARER_OPEN_WITHOUT_NEW_STATE",
                "ONLY_MATCHED_ROWS_MAY_DISPATCH_OR_APPLY",
            ],
            boundary_matrix=[
                {
                    "case": "four_unique_runtime_targets",
                    "result": "ADMIT_AFTER_FOUNDATION_FULL",
                    "attempt_draws": "ONE_TO_FOUR_EACH_CANONICAL_ORDER",
                    "collision_set": (
                        "DURABLE_ACTIVE_RETAINED_PLUS_PRIOR_SAME_ADMISSION"
                    ),
                    "sidecar_arms_full": 4,
                    "foundation_full_attempts": 1,
                    "wire_txgate_callback_before_foundation_ok": 0,
                },
                {
                    "case": "duplicate_runtime_same_application_instance",
                    "api_status": "NINLIL_OK",
                    "submission_state": "REJECTED",
                    "reason": "TARGET_COUNT_UNSUPPORTED",
                    "entropy_draws": 0,
                    "sidecar_mutations": 0,
                    "foundation_mutations": 0,
                    "compound_receiver_key": False,
                },
                {
                    "case": "duplicate_runtime_different_application_instance",
                    "api_status": "NINLIL_OK",
                    "submission_state": "REJECTED",
                    "reason": "TARGET_COUNT_UNSUPPORTED",
                    "entropy_draws": 0,
                    "sidecar_mutations": 0,
                    "foundation_mutations": 0,
                    "compound_receiver_key": False,
                },
                {
                    "case": "candidate_max4_exhausted_after_prior_arm",
                    "result": "NINLIL_E_ENTROPY",
                    "foundation_full_attempts": 0,
                    "cleanup": "CREATED_ARMS_BOUNDED_FULL",
                    "wire_txgate_callback": 0,
                    "attempt_redraw_while_unresolved": 0,
                },
                {
                    "case": "sidecar_arm_definite_failure",
                    "foundation_full_attempts": 0,
                    "cleanup": "CREATED_ARMS_BOUNDED_FULL",
                    "wire_txgate_callback": 0,
                },
                {
                    "case": "arm_or_cleanup_commit_unknown",
                    "result": "FENCE_COLD_RECONCILE",
                    "foundation_full_attempts": 0,
                    "sidecar_delete_claim": False,
                    "attempt_redraw": 0,
                    "wire_txgate_callback": 0,
                },
                {
                    "case": "foundation_full_definite_failure",
                    "foundation_full_attempts": 1,
                    "foundation_committed": False,
                    "cleanup": "ALL_ARMS_BOUNDED_FULL",
                    "wire_txgate_callback": 0,
                },
                {
                    "case": "foundation_full_commit_unknown",
                    "foundation_full_attempts": 1,
                    "result": "KEEP_ARMS_FENCE_COLD_RECONCILE",
                    "sidecar_delete_claim": False,
                    "attempt_redraw": 0,
                    "wire_txgate_callback": 0,
                },
                {
                    "case": "restart_matching_foundation_and_arms",
                    "result": "RESUME_SAME_ATTEMPTS",
                    "reconcile_before": "BEARER_OPEN",
                    "new_state": False,
                    "attempt_redraw": 0,
                },
            ],
            observed_kinds=["NMS1", "NM3S", "NRC1", "FOUNDATION_TX"],
            note=(
                "candidate-only; no cross-namespace atomic commit or "
                "production implementation claim"
            ),
        )
    )
    out.append(
        vector(
            "MF-TX-EXPIRY-MANDATORY-TOMBSTONE",
            expected={
                "status": "OK",
                "branch": "expiry_mandatory_tombstone",
                "reject_code": REJECT["EXPIRED"],
                "mandatory_full": "G_R_EXPIRY",
                "terminal_state": NM30_STATE["ABORTED"],
                "terminal_reason": NM30_REASON["EXPIRED"],
                "abort_generation": 0,
                "authority_actor_zero": True,
                "active_slot_freed": True,
                "nrc1_retained_until_gc": True,
                "nm30_present": True,
                "nm30_value_bytes": NM30_BYTES,
                "terminal_catalog_count": 8,
                "terminal_catalog_all_canonical": True,
                "wire_abort_reason_min": 1,
                "wire_abort_reason_max": 4,
                "wire_abort_reason_5_forbidden": True,
            },
            nm30_key_hex=hx(storage_key(b"NM30", ids_a["transfer_id"])),
            nm30_value_hex=hx(nm30_expiry),
            tombstone_digest_hex=hx(nm30_expiry_digest),
            terminal_catalog=terminal_catalog,
            transcript=[
                "OPEN_ACCEPT_FULL",
                "CLOCK_PAST_RESERVATION_NOT_AFTER",
                "G_R_EXPIRY_FULL",
                "ACTIVE_ERASE",
                "NM30_ABORTED_EXPIRED",
                "NRC1_RETAIN",
                "REJECT_EXPIRED",
            ],
            note="expiry must not leave active slot permanently occupied",
        )
    )
    out.append(
        vector(
            "MF-POS-EXPIRY-SLOT-REUSE",
            expected={
                "status": "OK",
                "branch": "expiry_slot_reuse",
                "reuse_after": "G_R_EXPIRY_or_G_RETENTION_GC",
                "active_count_after_expiry": 0,
                "new_transfer_open_admitted": True,
                "esp_active_max": 1,
            },
            transcript=[
                "EXPIRY_TOMBSTONE",
                "ACTIVE_COUNT_0",
                "NEW_TRANSFER_OPEN",
                "OPEN_ACCEPT",
            ],
            note="after expiry tombstone, host/ESP active slot may admit a new transfer_id",
        )
    )

    # Power-cut / resume / cleanup / rollback transcripts.
    fx_t = transfer_fixture(CHUNK_SIZE + 5, salt=12)
    out.append(
        vector(
            "MF-TX-POWER-CUT-AFTER-CHUNK-FULL",
            expected={
                "status": "RECOVER",
                "branch": "resume_from_bitmap",
                "wire_success_at_cut": 0,
                "sender_release": False,
            },
            last_full_group="G_R_CHUNK",
            committed_chunk_bitmap=0b1,
            transcript=[
                "OPEN_FULL",
                "PAGE_FULL",
                "CHUNK0_FULL",
                "POWER_CUT",
                "RESTART",
                "RESUME_QUERY",
                "RESUME_STATE_BITMAP_1",
                "REOFFER_MISSING",
            ],
            fixture_ids=fx_t["ids"],
        )
    )
    out.append(
        vector(
            "MF-TX-POWER-CUT-AFTER-CONTENT-VERIFIED",
            expected={
                "status": "RECOVER",
                "branch": "ready_token_reprompt",
                "publication_state": 1,
                "accept_notified": 0,
            },
            last_full_group="G_R_CONTENT",
            publication_token_hex=fx_t["publication_token_hex"],
            transcript=[
                "CONTENT_VERIFIED_FULL",
                "POWER_CUT",
                "RESTART",
                "POLL_PUBLICATION_READY",
                "FINALIZE_OR_WAIT",
            ],
        )
    )
    out.append(
        vector(
            "MF-TX-POWER-CUT-DURING-TERMINAL",
            expected={
                "status": "COMMIT_UNKNOWN",
                "group": "G_R_TERMINAL",
                "classify": True,
            },
            transcript=[
                "HANDOFF_FULL",
                "BEGIN_TERMINAL_FULL",
                "POWER_CUT",
                "RESTART",
                "CLASSIFY_OLD_NEW_PARTIAL_EXTRA_THIRD",
            ],
        )
    )
    resume_body, resume_digest = encode_resume_state(
        transfer_id=bytes.fromhex(fx_t["ids"]["transfer_id"]),
        revision=1,
        manifest_digest=bytes.fromhex(fx_t["manifest_digest_hex"]),
        query_generation=1,
        receiver_record_generation=9,
        bitmap=0b1,
        transfer_state=35,
    )
    out.append(
        vector(
            "MF-TX-RESUME-AFTER-RESTART",
            expected={
                "status": "OK",
                "branch": "resume_state",
                "bitmap": 1,
                "state_digest_hex": hx(resume_digest),
                "sender_may_release": False,
            },
            resume_state_hex=hx(resume_body),
            resume_state_length=108,
        )
    )
    out.append(
        vector(
            "MF-TX-CLEANUP-RETENTION-GC",
            expected={
                "status": "OK",
                "branch": "gc_after_retention",
                "active_eviction_forbidden": True,
                "nrc1_deleted_with_nm30": True,
                "group": "G_R_RETENTION_GC",
                "before_boundary": "REJECT_NOT_ELAPSED",
                "equal_boundary": "OK_DELETE",
                "after_boundary": "OK_DELETE",
                "epoch_mismatch": "REJECT_STATE",
            },
            retention_epoch_id_hex=hx(ids_a["reservation_clock_epoch_id"]),
            retention_anchor_ms=500000,
            retention_duration_ms=RETENTION_MS,
            retention_boundary_ms=500000 + RETENTION_MS,
            boundary_matrix=[
                {
                    "case": "before",
                    "now_ms": 500000 + RETENTION_MS - 1,
                    "same_epoch": True,
                    "delete": False,
                },
                {
                    "case": "equal",
                    "now_ms": 500000 + RETENTION_MS,
                    "same_epoch": True,
                    "delete": True,
                },
                {
                    "case": "after",
                    "now_ms": 500000 + RETENTION_MS + 1,
                    "same_epoch": True,
                    "delete": True,
                },
                {
                    "case": "epoch_mismatch",
                    "now_ms": 500000 + RETENTION_MS + 1,
                    "same_epoch": False,
                    "delete": False,
                },
            ],
            tombstone_present_before=True,
            tombstone_present_after=False,
            nrc1_present_before=True,
            nrc1_present_after=False,
            transcript=[
                "RETENTION_ELAPSED",
                "G_R_RETENTION_GC_DELETE_NM30_AND_NRC1",
                "BOTH_ABSENT",
            ],
        )
    )
    out.append(
        vector(
            "MF-TX-ROLLBACK-POLICY-OFF",
            expected={
                "status": "OK",
                "branch": "rollback",
                "in_place_v3_to_v2_conversion": False,
                "rehello_max_control_version": 2,
            },
            steps=[
                "policy_off",
                "complete_or_abort_inflight",
                "rehello_max_2",
                "retain_nm3_keys_until_gc",
            ],
        )
    )
    out.append(
        vector(
            "MF-TX-TERMINAL-CRASH-ACTIVE-ONLY",
            expected={
                "status": "COMMIT_UNKNOWN",
                "group": "G_R_TERMINAL",
                "classification": "OLD",
                "action": "retry_terminal_full",
                "durable_kinds": ["NM3R"],
            },
            observed_kinds=["NM3R"],
            pre_terminal_state=38,
            transcript=["BEGIN_G_R_TERMINAL", "POWER_CUT", "OBSERVE_ACTIVE_ONLY"],
        )
    )
    out.append(
        vector(
            "MF-TX-TERMINAL-CRASH-NM30-ONLY",
            expected={
                "status": "COMMIT_UNKNOWN",
                "group": "G_R_TERMINAL",
                "classification": "NEW",
                "action": "adopt_nm30",
                "durable_kinds": ["NM30"],
            },
            observed_kinds=["NM30"],
            nm30_terminal_state=1,
            transcript=["BEGIN_G_R_TERMINAL", "POWER_CUT", "OBSERVE_NM30_ONLY"],
        )
    )
    out.append(
        vector(
            "MF-TX-EPOCH-CHANGE-TERMINAL",
            expected={
                "status": "OK",
                "branch": "epoch_changed_terminal",
                "nm30_terminal_state": 3,
                "nm30_terminal_reason": 0x8002,
                "active_erased": True,
                "publish_forbidden": True,
            },
            terminal_reason=0x8002,
            transcript=[
                "R_CHUNKS_PARTIAL",
                "LOCAL_EPOCH_CHANGE",
                "FENCE_NO_PUBLISH",
                "G_R_TERMINAL_CORRUPT_FENCED",
                "NM30_ONLY",
            ],
        )
    )
    out.append(
        vector(
            "MF-TX-REQID-CACHE-CRASH-RESTART",
            expected={
                "status": "OK",
                "branch": "nrc1_restart_hit",
                "state_mutation_on_restart_hit": 0,
                "response_bodies_equal": True,
                "re_evaluation_forbidden": True,
            },
            request_id=7,
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_after_first),
            first_page_accept_hex=hx(bytes(p0_complete0)),
            post_restart_page_accept_hex=hx(bytes(p0_complete0)),
            transcript=[
                "PAGE_FULL_WITH_NRC1_SLOT",
                "POWER_CUT_BEFORE_WIRE",
                "RESTART_LOAD_NRC1",
                "SAME_REQUEST_ID_HIT_BIT_EXACT",
            ],
        )
    )
    out.append(
        vector(
            "MF-TX-REQID-TERMINAL-RESTART-LATE-DUP",
            expected={
                "status": "OK",
                "branch": "terminal_restart_late_dup",
                "nrc1_retained_with_nm30": True,
                "state_mutation_on_hit": 0,
                "response_bodies_equal": True,
                "re_evaluation_forbidden": True,
            },
            phase="post_terminal_pre_gc",
            request_id=8001,
            nrc1_key_hex=nrc1_key_hex,
            nrc1_value_hex=hx(nrc1_post_terminal),
            nm30_key_hex=hx(b"NM30" + tid_req),
            nm30_value_hex=hx(nm30_post),
            first_page_accept_hex=late_matrix[1]["response_body_hex"],
            post_restart_page_accept_hex=late_matrix[1]["response_body_hex"],
            transcript=[
                "G_R_TERMINAL_ACTIVE_ERASE_NM30_PUT_NRC1_RETAINED",
                "POWER_CUT_OR_RESTART",
                "LOAD_NM30_AND_NRC1",
                "LATE_DUP_PAGE_ACCEPT_BIT_EXACT",
            ],
        )
    )

    # Inventory integrity pin.
    out.append(
        vector(
            "MF-INV-REQUIRED-IDS-INTEGRITY",
            expected={
                "status": "OK",
                "required_count": len(REQUIRED_VECTOR_IDS),
                "duplicate_count": 0,
            },
            required_vector_ids=list(REQUIRED_VECTOR_IDS),
        )
    )
    out.append(
        vector(
            "MF-GATE-SELF-TEST-PIN",
            expected={
                "status": "OK",
                "gate_must_reject_missing_id": True,
                "gate_must_reject_extra_id": True,
                "gate_must_reject_duplicate_id": True,
                "gate_must_reject_substituted_id": True,
                "mutations_repair_digest": True,
            },
            pin="independent-gates-no-generator-import",
        )
    )

    ids_present = [v["id"] for v in out]
    if ids_present != list(REQUIRED_VECTOR_IDS):
        missing = set(REQUIRED_VECTOR_IDS) - set(ids_present)
        extra = set(ids_present) - set(REQUIRED_VECTOR_IDS)
        raise RuntimeError(f"vector id mismatch missing={missing} extra={extra} order")
    if len(ids_present) != len(set(ids_present)):
        raise RuntimeError("duplicate vector ids")
    return out


def compute_source_digests() -> dict[str, str]:
    """Hash pinned source files. Reject missing/dup paths and ADR content drift.

    Generator does not hard-pin its own content SHA (self-circular). Gates do.
    """

    if len(PINNED_SOURCES) != len(set(PINNED_SOURCES)):
        raise RuntimeError("PINNED_SOURCES has duplicates")
    digests: dict[str, str] = {}
    for rel in PINNED_SOURCES:
        path = ROOT / rel
        if not path.is_file():
            raise RuntimeError(f"missing authority source file: {rel}")
        digests[rel] = sha256(path.read_bytes()).hex()
    if digests[PINNED_ADR_PATH] != PINNED_ADR_SHA256_HEX:
        raise RuntimeError(
            f"ADR source sha drift: got {digests[PINNED_ADR_PATH]} "
            f"want {PINNED_ADR_SHA256_HEX}"
        )
    return digests


def authority_seal_material(
    authority_index: dict[str, Any], source_digests: dict[str, str]
) -> dict[str, Any]:
    """Seal includes hard-pinned metadata + source digests + per-ID index."""

    ordered_sources = {rel: source_digests[rel] for rel in PINNED_SOURCES}
    return {
        "metadata": {
            "schema": SCHEMA,
            "status": STATUS,
            "adr": PINNED_ADR,
            "title": PINNED_TITLE,
            "nonclaims": list(PINNED_NONCLAIMS),
            "sources": list(PINNED_SOURCES),
        },
        "source_sha256_hex": ordered_sources,
        "authority_index": authority_index,
    }


def authority_map_sha256(
    authority_index: dict[str, Any], source_digests: dict[str, str]
) -> str:
    return hx(
        sha256(
            stable_json(
                authority_seal_material(authority_index, source_digests)
            ).encode("utf-8")
        )
    )


def assert_pinned_metadata(
    document: dict[str, Any], *, source_digests: dict[str, str] | None = None
) -> None:
    """Reject wrong/missing/extra metadata against hard pins (not vector-taught)."""

    if document.get("schema") != SCHEMA:
        raise RuntimeError("schema pin")
    if document.get("status") != STATUS:
        raise RuntimeError("status pin")
    if document.get("adr") != PINNED_ADR:
        raise RuntimeError(f"adr pin: {document.get('adr')!r}")
    if document.get("title") != PINNED_TITLE:
        raise RuntimeError(f"title pin: {document.get('title')!r}")
    if document.get("nonclaims") != list(PINNED_NONCLAIMS):
        raise RuntimeError("nonclaims exact closed set pin")
    if document.get("sources") != list(PINNED_SOURCES):
        raise RuntimeError("sources exact ordered set pin")
    if not isinstance(document.get("source_sha256_hex"), dict):
        raise RuntimeError("source_sha256_hex missing")
    digests = source_digests if source_digests is not None else compute_source_digests()
    expected = {rel: digests[rel] for rel in PINNED_SOURCES}
    if document["source_sha256_hex"] != expected:
        raise RuntimeError("source_sha256_hex pin")
    if set(document["source_sha256_hex"]) != set(PINNED_SOURCES):
        raise RuntimeError("source_sha256_hex key set")


def build_document() -> dict[str, Any]:
    vectors = build_vectors()
    # Re-seal fingerprints after full materialization (defensive).
    for entry in vectors:
        entry["family"] = family_of(entry["id"])
        entry["authority_fingerprint_hex"] = authority_fingerprint(entry)
    budget = budget_block()
    authority_index = {
        entry["id"]: {
            "family": entry["family"],
            "expected": entry["expected"],
            "authority_fingerprint_hex": entry["authority_fingerprint_hex"],
        }
        for entry in vectors
    }
    source_digests = compute_source_digests()
    authority_map_sha = authority_map_sha256(authority_index, source_digests)
    document = {
        "schema": SCHEMA,
        "status": STATUS,
        "adr": PINNED_ADR,
        "title": PINNED_TITLE,
        "nonclaims": list(PINNED_NONCLAIMS),
        "constants": constants_block(),
        "version_catalog": version_catalog(),
        "carrier_mapping": carrier_mapping(),
        "publication_owner": publication_owner(),
        "role_boundaries": role_boundaries(),
        "private_api": private_api(),
        "budget": budget,
        "required_vector_ids": list(REQUIRED_VECTOR_IDS),
        "required_gate_cases": list(REQUIRED_GATE_CASES),
        "authority_map_sha256_hex": authority_map_sha,
        "authority_index": authority_index,
        "vectors": vectors,
        "sources": list(PINNED_SOURCES),
        "source_sha256_hex": {rel: source_digests[rel] for rel in PINNED_SOURCES},
    }
    assert_pinned_metadata(document, source_digests=source_digests)
    return document


def canonical_json(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    document = build_document()
    rendered = canonical_json(document)

    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(rendered)
        print(f"wrote {OUTPUT} sha256={sha256(rendered).hex()} bytes={len(rendered)}")
        return 0

    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != rendered:
            print(f"stale or missing: {OUTPUT}")
            return 1
        print(f"fresh {OUTPUT} sha256={sha256(rendered).hex()}")
        return 0

    # self-test
    baseline = build_document()
    altered = build_document()
    altered["budget"]["receiver_fulls_max_transfer"] += 1
    if canonical_json(baseline) == canonical_json(altered):
        print("self-test failed: mutation not observed")
        return 1
    if sum(baseline["budget"]["groups"]["receiver"].values()) != RECEIVER_FULLS_MAX:
        print("self-test failed: receiver fulls")
        return 1
    if baseline["budget"]["required_receiver_fulls_for_reference"] != RECEIVER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY:
        print("self-test failed: reference arithmetic")
        return 1
    if baseline["budget"]["required_sender_fulls_for_reference"] != SENDER_FULLS_MAX * REF_MAXSIZE_TRANSFERS_DAY:
        print("self-test failed: sender reference arithmetic")
        return 1
    if RECEIVER_FULLS_MAX != 77 or SENDER_FULLS_MAX != 67:
        print("self-test failed: full max with reqid")
        return 1
    if (
        RECEIVER_FULLS_BASE
        + RECEIVER_FULLS_RESUME
        + RECEIVER_FULLS_REQID_CACHE
        + RECEIVER_FULLS_RETRY_BUDGET
        + RECEIVER_FULLS_SESSION_GEN
        != 77
    ):
        print("self-test failed: receiver full breakdown")
        return 1
    if baseline["budget"]["obsolete_80_feasible_for_reference_receiver"] is not False:
        print("self-test failed: obsolete 80 must be infeasible")
        return 1
    empty = next(v for v in baseline["vectors"] if v["id"] == "MF-POS-EMPTY-PAYLOAD")
    if empty["expected"]["chunk_count"] != 0:
        print("self-test failed: empty chunk count")
        return 1
    if empty["fixture"]["facts"]["whole_content_sha256_hex"] != hx(sha256(b"")):
        print("self-test failed: empty digest")
        return 1
    one_final = next(
        v for v in baseline["vectors"] if v["id"] == "MF-POS-ONE-BYTE-FINAL"
    )
    if one_final["expected"]["final_chunk_length"] != 1:
        print("self-test failed: one-byte final")
        return 1
    exact = next(
        v for v in baseline["vectors"] if v["id"] == "MF-POS-EXACT-MULTIPLE-FINAL"
    )
    if exact["expected"]["final_chunk_length"] != CHUNK_SIZE:
        print("self-test failed: exact multiple final")
        return 1
    maxv = next(
        v for v in baseline["vectors"] if v["id"] == "MF-POS-MAX-PAYLOAD-37-CHUNKS"
    )
    if maxv["expected"]["chunk_count"] != 37:
        print("self-test failed: max chunks")
        return 1
    ids = [v["id"] for v in baseline["vectors"]]
    if ids != list(REQUIRED_VECTOR_IDS):
        print("self-test failed: required id order")
        return 1
    layout_v = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-POS-OPEN-APPLICATION-BINDING-LAYOUT-KAT"
    )
    min_open = bytes.fromhex(layout_v["minimum_open_body_hex"])
    max_open = bytes.fromhex(layout_v["maximum_open_body_hex"])
    if (
        len(min_open) != OPEN_MIN
        or len(max_open) != OPEN_MAX
        or OPEN_BASE_FIXED != 234
        or APPLICATION_BINDING_BYTES != 228
        or OPEN_FIXED != 462
        or ACTIVE_VALUE_MAX != 35211
        or ACTIVE_RECORD_SCHEMA != 2
        or layout_v["expected"]["nts3_future_schema"] != "1.2"
        or layout_v["expected"]["nts3_future_fields"]
        != ["mfdt_transfer_id[16]", "mfdt_target_ordinal_u32"]
        or layout_v["expected"]["nts3_future_target_suffix_placement"]
        != "canonical_target_encoding_tail"
        or layout_v["expected"]["nts3_future_target_suffix_presence"]
        != "bearer_route_eq_MFDT_V1_3"
        or layout_v["expected"]["nts3_future_target_suffix_bytes"] != 20
        or layout_v["expected"]["nts3_future_target_count_max"] != 4
        or layout_v["expected"]["nts3_future_mfdt_target_rule"]
        != (
            "transfer_id_nonzero__sender_ordinal_eq_bound_target_index__"
            "receiver_ordinal_eq_open_origin_ordinal_lt4_u32_be"
        )
        or layout_v["expected"]["nts3_future_non_mfdt_suffix_bytes"] != 0
        or layout_v["expected"]["nts3_future_non_mfdt_memory_rule"]
        != "transfer_id_zero16_and_ordinal_zero"
        or layout_v["expected"]["nts3_schema11_record_max_bytes"] != 4031
        or layout_v["expected"]["nts3_schema11_inline_payload_max_bytes"] != 926
        or layout_v["expected"]["nts3_future_mfdt_record_max_bytes"] != 3185
        or layout_v["expected"]["nts3_record_ceiling_bytes"] != 4096
        or NTS3_MFDT_RECORD_MAX_BYTES
        != NTS3_SCHEMA11_RECORD_MAX_BYTES
        - NTS3_INLINE_PAYLOAD_MAX_BYTES
        + NTS3_TARGET_COUNT_MAX * NTS3_MFDT_TARGET_SUFFIX_BYTES
        or NTS3_MFDT_RECORD_MAX_BYTES > NTS3_RECORD_CEILING_BYTES
    ):
        print("self-test failed: amended OPEN/schema geometry")
        return 1
    deadline_cases = layout_v.get("deadline_shape_cases")
    if (
        min_open[80:96] == ZERO16
        or min_open[178:194] != ZERO16
        or min_open[194:202] != UINT64_MAX.to_bytes(8, "big")
        or int.from_bytes(min_open[434:438], "big") != 1
        or int.from_bytes(min_open[438:446], "big") != 0
        or int.from_bytes(min_open[446:454], "big") != 0
        or max_open[80:96] != ZERO16
        or max_open[178:194] == ZERO16
        or not 1 <= int.from_bytes(max_open[194:202], "big") < UINT64_MAX
        or int.from_bytes(max_open[434:438], "big") != 2
        or int.from_bytes(max_open[438:446], "big") == 0
        or layout_v["expected"].get("no_deadline_u64_hex") != "ffffffffffffffff"
        or layout_v["expected"].get("finite_downlink_deadline_min_u64_hex")
        != "0000000000000001"
        or layout_v["expected"].get("finite_downlink_deadline_max_u64_hex")
        != "fffffffffffffffe"
        or layout_v["expected"].get("deadline_normalization_forbidden") is not True
        or not isinstance(deadline_cases, list)
        or [row.get("status") for row in deadline_cases]
        != ["OK", "REJECT", "OK", "OK", "REJECT"]
        or [row.get("absolute_effect_deadline_ms_u64_hex") for row in deadline_cases]
        != [
            "ffffffffffffffff",
            "0000000000000000",
            "0000000000000001",
            "fffffffffffffffe",
            "ffffffffffffffff",
        ]
    ):
        print("self-test failed: Foundation deadline sentinel erratum")
        return 1
    for raw_open, digest_hex in (
        (min_open, layout_v["minimum_manifest_digest_hex"]),
        (max_open, layout_v["maximum_manifest_digest_hex"]),
    ):
        got = sha256(
            b"NM3-MANIFEST-V1"
            + raw_open[:202]
            + raw_open[OPEN_BASE_FIXED:OPEN_FIXED]
            + raw_open[OPEN_FIXED:]
        )
        if hx(got) != digest_hex or raw_open[202:234] != got:
            print("self-test failed: amended OPEN manifest preimage")
            return 1
    mutation_v = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-OPEN-APPLICATION-BINDING-FIELD-MUTATION"
    )
    original_open = bytes.fromhex(mutation_v["open_body_hex"])
    original_digest = bytes.fromhex(mutation_v["manifest_digest_hex"])
    mutation_entries = b"".join(
        bytes.fromhex(item) for item in mutation_v["manifest_entries_hex"]
    )
    for mutation in mutation_v["mutations"]:
        changed = bytearray(original_open)
        changed[mutation["offset"]] ^= mutation["xor_first_byte"]
        mutated_digest = sha256(
            b"NM3-MANIFEST-V1"
            + bytes(changed[:202])
            + bytes(changed[OPEN_BASE_FIXED:OPEN_FIXED])
            + bytes(changed[OPEN_FIXED:])
            + mutation_entries
        )
        if mutated_digest == original_digest:
            print(f"self-test failed: unbound application field {mutation['field']}")
            return 1
    prefull_v = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-CARRIER-OPEN-BINDING-MISMATCH-PREFULL"
    )
    if (
        prefull_v["expected"]["full_count"] != 0
        or prefull_v["expected"]["durable_state_mutation"] != 0
        or prefull_v["validation_boundary"]
        != (
            "sender_before_G_S_OPEN_full_original_exact__"
            "receiver_before_G_R_OPEN_party_target_subset_exact_"
            "canonical_open_no_private_control_equality"
        )
        or prefull_v["mismatch_fields"]
        != [
            "sender_original_application_exact.origin_transaction_attempt_event",
            "sender_original_application_exact.source_runtime_application_instance_identity_epochs_flags",
            "sender_original_application_exact.target_runtime_application_instance_identity_epochs_flags",
            "sender_original_application_exact.service_text_revision_digest_schema_family",
            "sender_original_application_exact.content_length_and_digest",
            "sender_original_application_exact.application_generation",
            "sender_original_application_exact.deadline_and_evidence",
            "sender_original_application_exact.target_ordinal",
            "receiver_private_carrier_exact.source_runtime_application_instance_identity_epochs_flags",
            "receiver_private_carrier_exact.target_runtime_application_instance_identity_epochs_flags",
            "receiver_open_canonical_validation.original_application_fields",
            "receiver_open_canonical_validation.target_ordinal_lt4_and_local_target_identity",
            "receiver_open_canonical_validation.transfer_id_rederivation",
        ]
    ):
        print("self-test failed: carrier/OPEN pre-FULL fence")
        return 1
    mixed_v = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-ADMISSION-REV1-REV2-MIXED"
    )
    if (
        len(mixed_v["cases"]) != 3
        or mixed_v["expected"]["reject_code"] != REJECT["UNSUPPORTED"]
        or mixed_v["expected"]["migration_attempted"] is not False
    ):
        print("self-test failed: revision1/revision2 fail closed")
        return 1
    evidence_v = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-POS-APPLICATION-EVIDENCE-DIGEST-KAT"
    )
    evidence_preimage, evidence_digest = application_evidence_digest(
        publication_token_v=bytes.fromhex(evidence_v["publication_token_hex"]),
        origin_transaction_id=bytes.fromhex(evidence_v["origin_transaction_id_hex"]),
        original_attempt_id=bytes.fromhex(evidence_v["original_attempt_id_hex"]),
        target_ordinal=evidence_v["target_ordinal"],
        evidence_stage=evidence_v["evidence_stage"],
        evidence_bytes=bytes.fromhex(evidence_v["evidence_bytes_hex"]),
    )
    if (
        hx(evidence_preimage) != evidence_v["evidence_preimage_hex"]
        or hx(evidence_digest) != evidence_v["application_evidence_digest_hex"]
        or evidence_v["callback_context_authority"] != "foundation_transaction_id"
        or evidence_v["expected"]["disposition_fatal_recovery_may_advance"] is not False
    ):
        print("self-test failed: Application evidence handoff KAT")
        return 1
    # digest repair path: mutated whole must not match actual content digest
    dig = next(
        v for v in baseline["vectors"] if v["id"] == "MF-NEG-DIGEST-CORRUPTION-REPAIRED"
    )
    if dig["claimed_whole_hex"] == dig["actual_whole_hex"]:
        print("self-test failed: digest mutation not applied")
        return 1
    for entry in baseline["vectors"]:
        if authority_fingerprint(entry) != entry["authority_fingerprint_hex"]:
            print(f"self-test failed: fingerprint drift {entry['id']}")
            return 1
        if entry["family"] != family_of(entry["id"]):
            print(f"self-test failed: family {entry['id']}")
            return 1
    if len(baseline["authority_index"]) != len(REQUIRED_VECTOR_IDS):
        print("self-test failed: authority index size")
        return 1
    # Donor substitution must change fingerprint while preserving id field.
    donor = next(v for v in baseline["vectors"] if v["id"] == "MF-POS-ONE-BYTE")
    target = next(v for v in baseline["vectors"] if v["id"] == "MF-POS-EMPTY-PAYLOAD")
    swapped = dict(donor)
    swapped["id"] = target["id"]
    swapped["family"] = family_of(target["id"])
    if authority_fingerprint(swapped) == target["authority_fingerprint_hex"]:
        print("self-test failed: donor substitution fingerprint collision")
        return 1
    # Independent hard-coded byte KATs for MF-POS-ONE-BYTE page / open_accept /
    # transfer_accept. Expected bytes are literal constants — not produced by
    # calling encode_* for the expected side (avoids self-referential encoder KAT).
    KAT_ONE_BYTE_PAGE_BODY_HEX = (
        "a34ed374841ce22bf08716a2628be99f00000001e536bbd435a20beaffc8bd0bf37aa23dcd3b3875"
        "2283327e480b9d35b404a19e000000010000000180db54818c4f98ce5d8b371e4c5063313c907a37"
        "451014a46ebc239418f814510000000100000000559aead08264d5795d3909718cdd05abd49572e8"
        "4fe55590eef31a88a08fdffd"
    )
    KAT_ONE_BYTE_OPEN_ACCEPT_HEX = (
        "a34ed374841ce22bf08716a2628be99f00000001e536bbd435a20beaffc8bd0bf37aa23d"
        "cd3b38752283327e480b9d35b404a19e12131415161718191a1b1c1d1e1f202100000001"
        "32333435363738393a3b3c3d3e3f40410000000000061a8000000000"
    )
    KAT_ONE_BYTE_TRANSFER_ACCEPT_HEX = (
        "a34ed374841ce22bf08716a2628be99f00000001e536bbd435a20beaffc8bd0bf37aa23d"
        "cd3b38752283327e480b9d35b404a19e559aead08264d5795d3909718cdd05abd49572e8"
        "4fe55590eef31a88a08fdffd0000000152535455565758595a5b5c5d5e5f606100000000"
        "0000006412131415161718191a1b1c1d1e1f2021b54932f972cf4a86a380aaefae7f0bad"
        "871b0ad0f39b6ba06334d6d5e22549ff"
    )
    one = next(v for v in baseline["vectors"] if v["id"] == "MF-POS-ONE-BYTE")
    sealed_page = one["fixture"]["pages"][0]["body_hex"]
    sealed_open_accept = one["fixture"]["open_accept_hex"]
    sealed_transfer_accept = one["fixture"]["transfer_accept_hex"]
    if sealed_page != KAT_ONE_BYTE_PAGE_BODY_HEX:
        print("self-test failed: ONE-BYTE page body diverges from hard-coded KAT")
        return 1
    if sealed_open_accept != KAT_ONE_BYTE_OPEN_ACCEPT_HEX:
        print("self-test failed: ONE-BYTE open_accept diverges from hard-coded KAT")
        return 1
    if sealed_transfer_accept != KAT_ONE_BYTE_TRANSFER_ACCEPT_HEX:
        print("self-test failed: ONE-BYTE transfer_accept diverges from hard-coded KAT")
        return 1
    if len(bytes.fromhex(KAT_ONE_BYTE_PAGE_BODY_HEX)) != 132:
        print("self-test failed: page KAT length")
        return 1
    if len(bytes.fromhex(KAT_ONE_BYTE_OPEN_ACCEPT_HEX)) != 100:
        print("self-test failed: open_accept KAT length")
        return 1
    if len(bytes.fromhex(KAT_ONE_BYTE_TRANSFER_ACCEPT_HEX)) != 160:
        print("self-test failed: transfer_accept KAT length")
        return 1
    # Coherent mutation: flip page body byte0 → authority fingerprint must change.
    mut_one = dict(one)
    mut_fx = dict(one["fixture"])
    pages = list(mut_fx["pages"])
    p0 = dict(pages[0])
    raw = bytearray(bytes.fromhex(p0["body_hex"]))
    raw[0] ^= 0x01
    p0["body_hex"] = raw.hex()
    pages[0] = p0
    mut_fx["pages"] = pages
    mut_one["fixture"] = mut_fx
    if authority_fingerprint(mut_one) == one["authority_fingerprint_hex"]:
        print("self-test failed: complete-fixture fingerprint ignores page byte0")
        return 1
    # Independent constants drift detection against sealed document.
    if baseline["constants"]["chunk_size"] != CHUNK_SIZE:
        print("self-test failed: constant drift chunk_size")
        return 1
    if baseline["constants"]["max_content_bytes"] != MAX_CONTENT:
        print("self-test failed: constant drift max_content")
        return 1
    if baseline["budget"]["receiver_fulls_max_transfer"] != RECEIVER_FULLS_MAX:
        print("self-test failed: budget drift")
        return 1
    # Retry-budget SM + SM-derived reachable capacity.
    sm0 = retry_budget_sm()
    r0 = reachable_request_id_counts()
    if sm0["initial_value"] != 8 or sm0["max_value"] != 8 or sm0["scope"] != "per_transfer_per_owner_side":
        print("self-test failed: retry budget SM pins")
        return 1
    if sm0["decrement_event"] != "timeout_retry_with_new_request_id":
        print("self-test failed: decrement event")
        return 1
    if sm0["exhaustion_remaining_eq_0"]["is_terminal"] is not False:
        print("self-test failed: exhaustion not terminal")
        return 1
    if r0["n_complete"] != 65 or r0["n_abort"] != 64 or r0["reachable_max"] != 65:
        print("self-test failed: SM-derived reachable arithmetic")
        return 1
    if r0["finalize_abort_success_exclusive"] is not True:
        print("self-test failed: exclusivity")
        return 1
    if r0["naive_union_is_single_path"] is not False or r0["naive_union"] != 57:
        print("self-test failed: naive union")
        return 1
    if (
        NRC1_SLOT_COUNT != 72
        or NRC1_SLOT_BYTES != 208
        or NRC1_VALUE_BYTES != 15020
        or NRC1_LOGICAL_BYTES != 15056
    ):
        print("self-test failed: NRC1 layout sizes")
        return 1
    if RETRY_BUDGET_MAX != 8 or TIMEOUT_RETRY_MAX != 8 or RESUME_MAX != 8 or ABORT_GEN_MAX != 8:
        print("self-test failed: retry/resume/abort budgets")
        return 1
    if NRC1_N_COMPLETE != r0["n_complete"] or NRC1_N_ABORT != r0["n_abort"]:
        print("self-test failed: module constants not SM-derived")
        return 1
    if NRC1_HAPPY_PATH_MAX_IDS != 41:
        print("self-test failed: happy path 41")
        return 1
    if NRC1_REACHABLE_MAX_IDS > NRC1_SLOT_COUNT:
        print("self-test failed: capacity < reachable max")
        return 1
    if NRC1_CAPACITY_SPARE != NRC1_SLOT_COUNT - NRC1_REACHABLE_MAX_IDS:
        print("self-test failed: capacity spare")
        return 1
    if 16 >= NRC1_HAPPY_PATH_MAX_IDS:
        print("self-test failed: obsolete fixed-16 must be below happy-path max")
        return 1
    # Static budget asserts: slot formula, admission, single-value limit.
    if NRC1_VALUE_BYTES != 40 + NRC1_SLOT_BYTES * NRC1_SLOT_COUNT + 4:
        print("self-test failed: value_bytes static formula")
        return 1
    if NRC1_LOGICAL_BYTES != 16 + 20 + NRC1_VALUE_BYTES:
        print("self-test failed: logical_bytes static formula")
        return 1
    if NRC1_VALUE_BYTES >= 65536:
        print("self-test failed: single-value limit")
        return 1
    adm = ACTIVE_ROW_LOGICAL_BYTES_MAX + NRC1_LOGICAL_BYTES + TERMINAL_ROW_LOGICAL_BYTES
    if baseline["budget"]["admission_reserved_logical_bytes"] != adm or adm != 50519:
        print("self-test failed: admission reserved bytes")
        return 1
    if baseline["budget"]["admission_reserved_entries"] != 3:
        print("self-test failed: admission reserved entries")
        return 1
    if baseline["constants"]["storage_kinds"] != ["NM3S", "NM3R", "NM30", "NRC1"]:
        print("self-test failed: storage kinds missing NRC1")
        return 1
    if baseline["constants"]["request_body_digest_preimage"] != "type_u8||len_u16be||full_body":
        print("self-test failed: digest preimage label")
        return 1
    if baseline["constants"]["timeout_retry_max"] != 8:
        print("self-test failed: timeout_retry_max constant")
        return 1
    if baseline["constants"]["retry_budget_owner"] != "requestor_of_outbound_mfdt_control":
        print("self-test failed: retry budget owner constant")
        return 1
    if baseline["constants"]["retry_budget_scope"] != "per_transfer_per_owner_side":
        print("self-test failed: retry budget scope constant")
        return 1
    # Required NRC1 constants keys must be present (closes gate schema reds).
    for key in (
        "nrc1_happy_path_max_ids",
        "nrc1_logical_bytes",
        "nrc1_slot_bytes",
        "nrc1_slot_count",
        "nrc1_value_bytes",
        "request_body_digest_preimage",
        "retry_budget_remaining_max",
        "retry_budget_remaining_min",
        "retry_budget_scope",
        "retry_budget_owner",
        "retry_budget_initial",
        "retry_budget_decrement_event",
        "retry_budget_header_offset",
    ):
        if key not in baseline["constants"]:
            print(f"self-test failed: missing constants key {key}")
            return 1
    if "nrc1_min_lifecycle_ids" in baseline["constants"]:
        print("self-test failed: obsolete nrc1_min_lifecycle_ids must not be emitted")
        return 1
    max41 = next(
        v for v in baseline["vectors"] if v["id"] == "MF-POS-REQID-MAX-TRANSFER-OCCUPIED-41"
    )
    if max41["expected"]["occupied_count"] != 41 or max41["expected"]["fits"] is not True:
        print("self-test failed: max41 occupancy")
        return 1
    if max41["expected"]["exceeds_obsolete_fixed16"] is not True:
        print("self-test failed: max41 fixed16 flag")
        return 1
    smv = next(v for v in baseline["vectors"] if v["id"] == "MF-POS-REQID-RETRY-BUDGET-SM")
    if smv["expected"]["initial_value"] != 8 or smv["expected"]["scope"] != "per_transfer_per_owner_side":
        print("self-test failed: SM vector")
        return 1
    if smv["retry_budget_sm"] != sm0:
        print("self-test failed: SM body drift")
        return 1
    reach = next(
        v for v in baseline["vectors"] if v["id"] == "MF-POS-REQID-REACHABLE-MAX-COUNT"
    )
    if reach["expected"]["reachable_max"] != 65:
        print("self-test failed: reachable max vector")
        return 1
    if reach["expected"]["n_complete"] != 65 or reach["expected"]["n_abort"] != 64:
        print("self-test failed: path counts")
        return 1
    if reach["expected"]["derived_from_retry_budget_sm"] is not True:
        print("self-test failed: derived_from_retry_budget_sm")
        return 1
    if reach["expected"]["naive_union_is_single_path"] is not False:
        print("self-test failed: naive union must not be single path")
        return 1
    if reach["expected"]["slot_count_ge_reachable"] is not True:
        print("self-test failed: slot_count_ge_reachable")
        return 1
    if reach["first_units"]["retry_new_ids"] != 8:
        print("self-test failed: first_units retry")
        return 1
    rtry = next(v for v in baseline["vectors"] if v["id"] == "MF-POS-REQID-MAX-RETRY-TRACE")
    if rtry["expected"]["timeout_retries"] != 8 or rtry["expected"]["occupied_count"] != 9:
        print("self-test failed: max retry trace")
        return 1
    if len(rtry["retry_request_ids"]) != 8:
        print("self-test failed: retry id list")
        return 1
    fullc = next(v for v in baseline["vectors"] if v["id"] == "MF-NEG-REQID-CACHE-FULL")
    if fullc["occupied_count"] != 72 or fullc["expected"]["no_silent_eviction"] is not True:
        print("self-test failed: cache-full at 72")
        return 1
    odig = next(
        v for v in baseline["vectors"] if v["id"] == "MF-NEG-REQID-DIGEST-OPEN-PREIMAGE"
    )
    open_body = bytes.fromhex(odig["open_body_hex"])
    pre = bytes.fromhex(odig["open_preimage_hex"])
    if pre != bytes([0x36]) + u16(len(open_body)) + open_body:
        print("self-test failed: OPEN digest preimage bytes")
        return 1
    if hx(sha256(pre)) != odig["request_body_digest_hex"]:
        print("self-test failed: OPEN digest recompute")
        return 1
    if odig["request_body_digest_hex"] == odig["wrong_bind52_strip_digest_hex"]:
        print("self-test failed: BIND52-strip wrong preimage collides")
        return 1
    if odig["expected"]["includes_bind52_strip"] is not False:
        print("self-test failed: OPEN must not strip BIND52")
        return 1
    nrc_layout = next(
        v for v in baseline["vectors"] if v["id"] == "MF-POS-REQID-NRC1-LAYOUT-KAT"
    )
    slot = bytes.fromhex(nrc_layout["first_slot_hex"])
    if len(slot) != 208 or slot[8:12] != u32(1):
        print("self-test failed: NRC1 per-slot generation KAT")
        return 1
    if bytes.fromhex(nrc_layout["empty_slot_hex"]) != bytes(208):
        print("self-test failed: NRC1 empty slot is not all-zero")
        return 1
    l0 = bytes.fromhex(nrc_layout["occupied_l0_repaired_crc_mutant_hex"])
    if len(l0) != 15020 or l0[86:88] != b"\x00\x00":
        print("self-test failed: NRC1 repaired-CRC L=0 mutant")
        return 1
    genv = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-POS-REQID-SESSION-GEN-RESUME-RECLAIM"
    )
    gen2 = bytes.fromhex(genv["generation_2_nrc1_value_hex"])
    if (
        genv["initial_session_generation"] != 7
        or genv["successor_session_generation"] != 8
        or gen2[24:28] != u32(8)
    ):
        print("self-test failed: NRC1 arbitrary initial/successor generation")
        return 1
    if gen2[40 + 8 : 40 + 12] != u32(7):
        print("self-test failed: retained non-RESUME slot generation changed")
        return 1
    if gen2[40 + 208 + 8 : 40 + 208 + 12] != u32(8):
        print("self-test failed: successor-generation RESUME slot missing")
        return 1
    for field in (
        "future_generation_nrc1_value_hex",
        "gap_generation_nrc1_value_hex",
        "third_generation_nrc1_value_hex",
    ):
        if len(bytes.fromhex(genv[field])) != NRC1_VALUE_BYTES:
            print(f"self-test failed: {field} length")
            return 1
    if genv["expected"]["second_advance_status"] != "CAPACITY":
        print("self-test failed: second session generation advance")
        return 1
    if genv["expected"]["uint32_max_advance_status"] != "CAPACITY":
        print("self-test failed: UINT32_MAX session generation wrap")
        return 1
    cross = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-TX-CROSS-NAMESPACE-ADMISSION-MATRIX"
    )
    cross_cases = {
        row["case"]: row
        for row in cross["boundary_matrix"]
        if isinstance(row, dict) and isinstance(row.get("case"), str)
    }
    for duplicate_case in (
        "duplicate_runtime_same_application_instance",
        "duplicate_runtime_different_application_instance",
    ):
        row = cross_cases.get(duplicate_case, {})
        if (
            row.get("api_status") != "NINLIL_OK"
            or row.get("submission_state") != "REJECTED"
            or row.get("reason") != "TARGET_COUNT_UNSUPPORTED"
            or row.get("entropy_draws") != 0
            or row.get("sidecar_mutations") != 0
            or row.get("foundation_mutations") != 0
            or row.get("compound_receiver_key") is not False
        ):
            print("self-test failed: duplicate Runtime roster guard")
            return 1
    if (
        len(cross["boundary_matrix"]) != 9
        or cross["expected"]["runtime_uniqueness_scope"] != "MFDT_V1_ONLY"
        or cross["expected"]["nts3_target_local_suffix_rule_changed"] is not False
        or cross["expected"]["attempt_draws_max_per_target"] != 4
        or cross["expected"]["attempt_draw_order"] != "canonical_target_order"
        or cross["expected"]["attempt_collision_set"]
        != "durable_active_retained_plus_prior_same_admission_candidates"
        or cross["expected"]["attempt_consumed_claim_before_foundation_full"] != 0
        or cross["expected"]["wire_txgate_callback_before_foundation_full"] != 0
        or cross["expected"]["foundation_admission_full_count"] != 1
        or cross["expected"]["blind_attempt_redraw_forbidden"] is not True
        or cross["expected"]["new_durable_state_added"] is not False
        or cross_cases.get("candidate_max4_exhausted_after_prior_arm", {}).get(
            "cleanup"
        )
        != "CREATED_ARMS_BOUNDED_FULL"
        or cross_cases.get("foundation_full_definite_failure", {}).get("cleanup")
        != "ALL_ARMS_BOUNDED_FULL"
        or cross_cases.get("foundation_full_commit_unknown", {}).get(
            "attempt_redraw"
        )
        != 0
    ):
        print("self-test failed: target attempt pre-arm admission matrix")
        return 1

    expiry = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-TX-EXPIRY-MANDATORY-TOMBSTONE"
    )
    expiry_nm30 = bytes.fromhex(expiry["nm30_value_hex"])
    if (
        len(expiry_nm30) != 180
        or struct.unpack(">H", expiry_nm30[4:6])[0] != 2
        or struct.unpack(">H", expiry_nm30[6:8])[0] != 180
        or struct.unpack(">H", expiry_nm30[60:62])[0] != 2
        or struct.unpack(">H", expiry_nm30[62:64])[0] != 5
        or expiry_nm30[64:68] != bytes(4)
        or expiry_nm30[116:132] != ZERO16
        or expiry_nm30[156:172] == ZERO16
        or expiry_nm30[172] != 2
        or expiry_nm30[173:176] != bytes(3)
        or crc32c(expiry_nm30[:176]) != struct.unpack(">I", expiry_nm30[176:180])[0]
    ):
        print("self-test failed: canonical expiry NM30 KAT")
        return 1
    if len(expiry["terminal_catalog"]) != 8:
        print("self-test failed: terminal cross-product count")
        return 1
    if (
        HOST_CONTROL_ARENA_BYTES != 17920
        or HOST_OWNER_WORKSPACE_BYTES != 280064
        or baseline["constants"]["host_control_arena_bytes"] != 17920
        or baseline["constants"]["host_owner_workspace_bytes"] != 280064
    ):
        print("self-test failed: Host control/owner workspace geometry")
        return 1
    if (
        TERMINAL_ROW_LOGICAL_BYTES != 216
        or TERMINAL_GROUP_LOGICAL_BYTES != 15272
        or HOST_COMMITTED_LOGICAL_BYTES_HARD_MAX != 384476
        or HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_HARD_MAX != 434779
    ):
        print("self-test failed: terminal/Host durable arithmetic")
        return 1
    nm30v = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-POS-NM30-SCHEMA2-LAYOUT-KAT"
    )
    nm30_raw = bytes.fromhex(nm30v["nm30_value_hex"])
    if (
        len(nm30_raw) != 180
        or nm30_raw[0:4] != b"NM30"
        or nm30_raw[4:6] != u16(2)
        or nm30_raw[6:8] != u16(180)
        or nm30_raw[156:172] == ZERO16
        or nm30_raw[172] != 2
        or nm30_raw[173:176] != bytes(3)
        or crc32c(nm30_raw[:176]) != struct.unpack(">I", nm30_raw[176:180])[0]
        or nm30v["expected"]["session_cookie_durable"] is not False
        or nm30v["expected"]["session_generation_authority"]
        != "NRC1_header_offset_24"
    ):
        print("self-test failed: NM30 schema-2 layout")
        return 1
    legacy = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY"
    )
    legacy_raw = bytes.fromhex(legacy["legacy_nm30_value_hex"])
    if (
        len(legacy_raw) != 164
        or legacy_raw[4:8] != u16(1) + u16(164)
        or legacy_raw[156:160] != bytes(4)
        or crc32c(legacy_raw[:160]) != struct.unpack(">I", legacy_raw[160:164])[0]
        or legacy["expected"]["replay_eligible"] is not False
        or legacy["expected"]["retention_gc_allowed"] is not True
        or legacy["expected"]["wire_response_count"] != 0
    ):
        print("self-test failed: schema-1 replay denial")
        return 1
    cold = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-TX-HOST-TERMINAL-COLD-REBIND-HIT"
    )
    if (
        cold["expected"]["control_route"] != 0xFF
        or cold["expected"]["active_slots_consumed"] != 0
        or cold["expected"]["full_count"] != 0
        or cold["expected"]["post_terminal_miss_full_count"] != 1
        or cold["recovered_catalog_entry"]["session_cookie"] != 0
        or cold["rebind"]["session_cookie_hex"] == "0000000000000000"
    ):
        print("self-test failed: terminal cold rebind/hit")
        return 1
    bindv = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-HOST-TERMINAL-BIND-MATRIX"
    )
    bind_results = {case["name"]: case["result"] for case in bindv["cases"]}
    if bind_results != {
        "exact_initial_rebind": "OK",
        "same_cookie_after_bind": "OK",
        "peer_mismatch": "ERR_STATE",
        "role_mismatch": "ERR_STATE",
        "generation_mismatch": "ERR_STATE",
        "zero_cookie": "ERR_STATE",
        "cookie_swap": "ERR_STATE",
    }:
        print("self-test failed: terminal bind matrix")
        return 1
    four_hit = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-POS-HOST-FOUR-ACTIVE-TERMINAL-HIT"
    )
    four_busy = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-HOST-FOUR-ACTIVE-FRESH-OPEN-BUSY"
    )
    if (
        four_hit["expected"]["active_before"] != 4
        or four_hit["expected"]["active_after"] != 4
        or four_hit["expected"]["active_slot_allocations"] != 0
        or four_busy["expected"]["full_count"] != 0
        or four_busy["expected"]["cacheable"] is not False
        or len(bytes.fromhex(four_busy["busy_body_hex"])) != 60
    ):
        print("self-test failed: all-four-active control routes")
        return 1
    backpressure = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-HOST-CONTROL-OUTBOX-BACKPRESSURE"
    )
    if (
        backpressure["expected"]["status"] != "ERR_BUSY"
        or backpressure["expected"]["first_frame_retained_bit_exact"] is not True
        or backpressure["expected"]["second_frame_enqueued"] is not False
    ):
        print("self-test failed: control outbox backpressure")
        return 1
    for pre_id, code in (
        ("MF-NEG-PREADMISSION-POLICY-STATELESS", REJECT["UNSUPPORTED"]),
        ("MF-NEG-PREADMISSION-DEADLINE-STATELESS", REJECT["EXPIRED"]),
    ):
        pre = next(v for v in baseline["vectors"] if v["id"] == pre_id)
        if (
            pre["expected"]["status"] != "OK"
            or pre["expected"]["reject_code"] != code
            or pre["expected"]["cacheable"] is not False
            or pre["expected"]["full_count"] != 0
            or pre["expected"]["durable_rows_created"] != 0
            or len(bytes.fromhex(pre["response_body_hex"])) != 60
        ):
            print(f"self-test failed: stateless pre-admission {pre_id}")
            return 1
    active_reject = next(
        v for v in baseline["vectors"]
        if v["id"] == "MF-NEG-ACTIVE-SEMANTIC-REJECT-CACHED"
    )
    if (
        active_reject["expected"]["status"] != "OK"
        or active_reject["expected"]["cacheable"] is not True
        or active_reject["expected"]["nrc1_full_count"] != 1
        or active_reject["expected"]["owned_active_slot_outbox"] is not True
        or active_reject["expected"]["uses_control_outbox"] is not False
    ):
        print("self-test failed: active semantic reject caching")
        return 1
    host = next(
        v for v in baseline["vectors"] if v["id"] == "MF-NEG-RESOURCE-EXHAUSTION-KEYS"
    )
    if [e["slot"] for e in host["host_admission_trace"][:4]] != [0, 1, 2, 3]:
        print("self-test failed: Host four-slot admission trace")
        return 1
    if host["host_admission_trace"][4]["state_mutation"] != 0:
        print("self-test failed: Host fifth admission mutation")
        return 1
    fairness = next(
        v for v in baseline["vectors"] if v["id"] == "MF-NEG-FAIRNESS-TWO-OUTSTANDING"
    )
    if fairness["successful_selection_trace"] != [0, 1, 2, 3, 0, 1, 2, 3]:
        print("self-test failed: Host scheduler trace")
        return 1
    daily = next(
        v for v in baseline["vectors"] if v["id"] == "MF-BUDGET-FULL-MAX-WITH-REQID"
    )
    if "154/134" not in daily["note"] or "136/116" in daily["note"]:
        print("self-test failed: daily explanatory arithmetic")
        return 1

    # Permanent metadata authority counterexamples (hard pins; not vector-taught).
    def expect_meta_fail(doc: dict[str, Any], label: str) -> int:
        try:
            assert_pinned_metadata(doc)
            print(f"self-test failed: metadata mutant accepted: {label}")
            return 1
        except RuntimeError:
            return 0

    mut = dict(baseline)
    mut["adr"] = "ADR-9999"
    if expect_meta_fail(mut, "adr=ADR-9999"):
        return 1
    mut = dict(baseline)
    mut["title"] = "UNRELATED AUTHORITY"
    if expect_meta_fail(mut, "title=UNRELATED AUTHORITY"):
        return 1
    mut = dict(baseline)
    mut["sources"] = list(PINNED_SOURCES) + ["docs/adr/does-not-exist-9999.md"]
    mut["source_sha256_hex"] = dict(baseline["source_sha256_hex"])
    mut["source_sha256_hex"]["docs/adr/does-not-exist-9999.md"] = "00" * 32
    if expect_meta_fail(mut, "nonexistent sources path"):
        return 1
    mut = dict(baseline)
    mut["sources"] = ["docs/adr/does-not-exist-9999.md"]
    mut["source_sha256_hex"] = {"docs/adr/does-not-exist-9999.md": "00" * 32}
    if expect_meta_fail(mut, "sources replaced by nonexistent"):
        return 1
    mut = dict(baseline)
    mut["nonclaims"] = [
        "SPEC_ACCEPTED",
        "implementation",
        "HIL",
        "RELEASE_SUPPORTED",
    ]
    if expect_meta_fail(mut, "nonclaims only 4 items"):
        return 1
    mut = dict(baseline)
    mut["nonclaims"] = list(PINNED_NONCLAIMS) + ["EXTRA_NONCLAIM"]
    if expect_meta_fail(mut, "nonclaims extra"):
        return 1
    mut = dict(baseline)
    mut["nonclaims"] = list(reversed(PINNED_NONCLAIMS))
    if expect_meta_fail(mut, "nonclaims order swapped"):
        return 1
    mut = dict(baseline)
    mut["adr"] = True  # type: ignore[assignment]
    if expect_meta_fail(mut, "adr bool type"):
        return 1
    # Seal must include metadata: mutating seal inputs changes map sha.
    alt_index = dict(baseline["authority_index"])
    live = compute_source_digests()
    base_seal = authority_map_sha256(alt_index, live)
    if baseline["authority_map_sha256_hex"] != base_seal:
        print("self-test failed: authority map seal mismatch")
        return 1
    bad_meta_index = alt_index  # same index
    bad_digests = dict(live)
    bad_digests[PINNED_ADR_PATH] = "11" * 32
    if authority_map_sha256(bad_meta_index, bad_digests) == base_seal:
        print("self-test failed: seal ignores source digest mutation")
        return 1
    # Donor-style metadata: wrong sources order (duplicate path) rejected.
    mut = dict(baseline)
    mut["sources"] = [PINNED_SOURCES[1], PINNED_SOURCES[0]]
    if expect_meta_fail(mut, "sources order donor"):
        return 1
    try:
        assert_pinned_metadata(baseline)
    except RuntimeError as error:
        print(f"self-test failed: baseline metadata rejected: {error}")
        return 1
    print("self-test OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
