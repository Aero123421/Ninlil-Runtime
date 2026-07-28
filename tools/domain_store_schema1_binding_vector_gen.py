#!/usr/bin/env python3
"""Independent ADR-0022 allocation, namespace, and kind-1 KAT generator.

This generator deliberately does not import or execute Ninlil production C
code.  It implements only the byte formulas frozen by docs/12, docs/17, and
ADR-0022 using Python's standard library.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


ROOT = bytes.fromhex("4e494e4c494c0001")
ZERO16 = bytes(16)
ZERO32 = bytes(32)
U64_MAX = (1 << 64) - 1
EXPORT_MAGIC = b"NLEXP001"
EXPORT_COMPLETION_MAGIC = b"NLEXDONE"
EXPORT_PROVIDER_DOMAIN = b"NINLIL-LAB-EXPORT-PROVIDER-V1"
EXPORT_ROW_DOMAIN = b"NINLIL-LAB-EXPORT-ROW-V1"
EXPORT_CONTENT_DOMAIN = b"NINLIL-LAB-EXPORT-V1"
KIND1_FIXTURE_MAGIC = b"NINLIL-DOMAIN-KIND1-FIXTURE-V1"
ALTERNATE_KIND1_FIXTURE_OVERRIDES = {
    "local_application_instance_id_hex": "12" * 16,
    "service": "valve",
    "descriptor_digest_hex": "23" * 32,
}
OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "spec/vectors/domain-store-schema1-runtime-binding-v1.json"
)


def u8(value: int) -> bytes:
    return struct.pack(">B", value)


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def raw16(value: bytes) -> bytes:
    return u16(len(value)) + value


def text_id(value: str) -> bytes:
    encoded = value.encode("ascii")
    return u8(len(encoded)) + encoded


def composite(subtype: int, components: bytes) -> bytes:
    return sha256(b"NINLIL-DOMAIN-KEY-V1" + u8(subtype) + components)


def domain_key(subtype: int, identity: bytes) -> bytes:
    return ROOT + b"\x06" + u8(subtype) + b"\x01\x05\x20" + identity


def key_digest(key: bytes) -> bytes:
    return sha256(b"NINLIL-DOMAIN-ENCODED-KEY-V1" + key)


def nlr1(record_type: int, payload: bytes) -> bytes:
    framed = b"NLR1" + u16(record_type) + u16(1) + u32(len(payload)) + payload
    return framed + u32(crc32c(framed))


def domain_value(
    subtype: int,
    revision: int,
    primary_id: bytes,
    head: bytes,
    pvd: bytes,
    body: bytes,
) -> bytes:
    common = (
        u16(1)
        + u8(subtype)
        + b"\x00"
        + u64(revision)
        + primary_id
        + head
        + pvd
        + u32(len(body))
    )
    assert len(common) == 96
    return nlr1(6, common + body)


def runtime_capacity_value(
    kind: int,
    limit: int,
    used: int,
    reserved: int,
    high_water: int,
    epoch: int,
    blocked: int = 0,
    exhausted: int = 0,
) -> bytes:
    payload = (
        u32(kind)
        + u64(limit)
        + u64(used)
        + u64(reserved)
        + u64(high_water)
        + u64(epoch)
        + u32(blocked)
        + u32(exhausted)
    )
    assert len(payload) == 52
    return nlr1(4, payload)


def witness_index_body(
    state: int,
    member_key: bytes,
    member_value_digest: bytes,
    member_head: bytes,
) -> bytes:
    body = (
        u16(state)
        + u16(0)
        + key_digest(member_key)
        + u16(len(member_key))
        + u16(0)
        + member_key
        + member_value_digest
        + member_head
    )
    assert len(body) == 114
    return body


def encode_service_body(
    service_raw: bytes,
    fixture: dict[str, Any],
    quota_key_digest: bytes,
    reservation_key_digest: bytes,
) -> bytes:
    return (
        raw16(service_raw)
        + u64(fixture["descriptor_revision"])
        + bytes.fromhex(fixture["descriptor_digest_hex"])
        + bytes.fromhex(fixture["local_application_instance_id_hex"])
        + text_id(fixture["namespace"])
        + text_id(fixture["service"])
        + text_id(fixture["schema"])
        + u16(fixture["schema_major"])
        + u16(fixture["schema_minor_min"])
        + u16(fixture["schema_minor_max"])
        + u32(fixture["family"])
        + u32(fixture["direction"])
        + u32(fixture["admission_authority"])
        + u32(fixture["apply_contract"])
        + u32(fixture["custody_policy"])
        + u32(fixture["supported_evidence_mask"])
        + u32(fixture["logical_payload_limit"])
        + u32(fixture["target_limit"])
        + u32(fixture["inflight_limit"])
        + u32(fixture["attempts_per_cycle"])
        + u32(fixture["admission_window_ms"])
        + u32(fixture["max_admissions_window"])
        + u32(fixture["max_payload_window"])
        + u64(fixture["minimum_deadline_ms"])
        + u64(fixture["maximum_deadline_ms"])
        + u64(fixture["maximum_evidence_grace_ms"])
        + u64(fixture["attempt_receipt_timeout_ms"])
        + u64(fixture["retry_backoff_ms"])
        + u64(fixture["application_completion_timeout_ms"])
        + u64(fixture["required_dedup_window_ms"])
        + quota_key_digest
        + reservation_key_digest
    )


def encode_quota_body(
    service_raw: bytes,
    service_key_digest: bytes,
    clock_epoch: bytes,
    window_start_ms: int,
) -> bytes:
    return (
        raw16(service_raw)
        + service_key_digest
        + clock_epoch
        + u64(window_start_ms)
        + u32(0)
        + u64(0)
        + u32(0)
        + u32(0)
        + u64(0)
    )


def encode_resource_vector() -> bytes:
    rows = []
    for kind in range(1, 12):
        rows.append(u64(1 if kind == 1 else 0) + u64(0))
    result = b"".join(rows)
    assert len(result) == 176
    return result


def encode_reservation_body(
    service_raw: bytes,
    service_key_digest: bytes,
) -> bytes:
    return (
        u16(1)
        + u16(0)
        + raw16(service_raw)
        + service_key_digest
        + encode_resource_vector()
        + u32(0)
        + u32(0)
        + u64(0)
        + u32(0)
    )


def witness_entry(
    role: int,
    action: int,
    key: bytes,
    old_present: int,
    new_present: int,
    prior_head: bytes,
    old_digest: bytes,
    new_digest: bytes,
) -> bytes:
    return (
        u16(role)
        + u8(action)
        + b"\x00"
        + u16(len(key))
        + u16(0)
        + key
        + u8(old_present)
        + u8(new_present)
        + u16(0)
        + prior_head
        + old_digest
        + new_digest
    )


def record_object(name: str, key: bytes, value: bytes) -> dict[str, Any]:
    return {
        "name": name,
        "key_length": len(key),
        "key_hex": key.hex(),
        "value_length": len(value),
        "value_hex": value.hex(),
        "key_sha256": sha256(key).hex(),
        "value_sha256": sha256(value).hex(),
    }


def export_provider_identity_digest(
    provider_kind: int,
    provider_schema: int,
    provider_config: bytes,
) -> bytes:
    return sha256(
        EXPORT_PROVIDER_DOMAIN
        + u16(provider_kind)
        + u16(provider_schema)
        + raw16(provider_config)
    )


def encode_export_artifact(
    namespace: bytes,
    rows: list[tuple[bytes, bytes]],
    provider_kind: int,
    provider_schema: int,
    provider_config: bytes,
    *,
    format_version: int = 1,
    source_profile: int = 1,
    flags: int = 0,
    provider_digest: bytes | None = None,
) -> bytes:
    if not 1 <= len(namespace) <= 255:
        raise ValueError("namespace length out of range")
    if provider_digest is None:
        provider_digest = export_provider_identity_digest(
            provider_kind,
            provider_schema,
            provider_config,
        )
    if len(provider_digest) != 32:
        raise ValueError("provider digest must be 32 bytes")
    artifact = (
        EXPORT_MAGIC
        + u16(format_version)
        + u16(source_profile)
        + u32(flags)
        + u16(provider_kind)
        + u16(provider_schema)
        + provider_digest
        + u16(len(namespace))
        + namespace
        + u32(len(rows))
    )
    for key, value in rows:
        if not 1 <= len(key) <= 255:
            raise ValueError("export key length out of range")
        if not 1 <= len(value) <= 65536:
            raise ValueError("export value length out of range")
        row_prefix = u16(len(key)) + key + u32(len(value)) + value
        artifact += (
            u16(len(key))
            + u16(0)
            + u32(len(value))
            + key
            + value
            + sha256(EXPORT_ROW_DOMAIN + row_prefix)
        )
    return (
        artifact
        + sha256(EXPORT_CONTENT_DOMAIN + artifact)
        + EXPORT_COMPLETION_MAGIC
    )


def export_artifact_layout(artifact: bytes) -> dict[str, Any]:
    """Return offsets for a known-well-formed export fixture."""
    assert artifact[:8] == EXPORT_MAGIC
    namespace_length = int.from_bytes(artifact[52:54], "big")
    cursor = 54 + namespace_length
    record_count = int.from_bytes(artifact[cursor : cursor + 4], "big")
    cursor += 4
    rows = []
    for _ in range(record_count):
        key_length_offset = cursor
        key_length = int.from_bytes(artifact[cursor : cursor + 2], "big")
        value_length = int.from_bytes(
            artifact[cursor + 4 : cursor + 8], "big"
        )
        key_start = cursor + 8
        value_start = key_start + key_length
        digest_start = value_start + value_length
        rows.append(
            {
                "key_length_offset": key_length_offset,
                "reserved_offset": cursor + 2,
                "value_length_offset": cursor + 4,
                "key_start": key_start,
                "value_start": value_start,
                "digest_start": digest_start,
            }
        )
        cursor = digest_start + 32
    assert artifact[cursor + 32 : cursor + 40] == EXPORT_COMPLETION_MAGIC
    assert cursor + 40 == len(artifact)
    return {
        "rows": rows,
        "content_digest_offset": cursor,
    }


def refresh_export_content_digest(artifact: bytes) -> bytes:
    if len(artifact) < 40:
        raise ValueError("artifact too short to refresh")
    prefix = artifact[:-40]
    return (
        prefix
        + sha256(EXPORT_CONTENT_DOMAIN + prefix)
        + artifact[-8:]
    )


def patch_export_artifact(
    artifact: bytes,
    replacements: list[tuple[int, bytes]],
    *,
    refresh_content_digest: bool = True,
) -> bytes:
    patched = bytearray(artifact)
    for offset, value in replacements:
        patched[offset : offset + len(value)] = value
    result = bytes(patched)
    if refresh_content_digest:
        result = refresh_export_content_digest(result)
    return result


def classify_export_artifact(
    artifact: bytes,
    known_provider_kind: int,
    known_provider_schema: int,
    known_provider_config: bytes,
) -> dict[str, Any]:
    """Independent fail-closed parser for the exact export fixtures."""

    def rejected(
        reason: str,
        status: str = "NINLIL_E_STORAGE_CORRUPT",
    ) -> dict[str, Any]:
        return {
            "status": status,
            "rejection": reason,
        }

    if len(artifact) < 54:
        return rejected("TRUNCATED_HEADER")
    if artifact[:8] != EXPORT_MAGIC:
        return rejected("MAGIC")
    format_version = int.from_bytes(artifact[8:10], "big")
    source_profile = int.from_bytes(artifact[10:12], "big")
    flags = int.from_bytes(artifact[12:16], "big")
    provider_kind = int.from_bytes(artifact[16:18], "big")
    provider_schema = int.from_bytes(artifact[18:20], "big")
    provider_digest = artifact[20:52]
    namespace_length = int.from_bytes(artifact[52:54], "big")
    if format_version != 1:
        return rejected("FORMAT_VERSION", "NINLIL_E_UNSUPPORTED")
    if source_profile != 1:
        return rejected("SOURCE_PROFILE", "NINLIL_E_UNSUPPORTED")
    if flags != 0:
        return rejected("FLAGS", "NINLIL_E_UNSUPPORTED")
    if provider_kind == 0:
        return rejected("ZERO_PROVIDER_KIND")
    if provider_schema == 0:
        return rejected("ZERO_PROVIDER_SCHEMA")
    if provider_digest == ZERO32:
        return rejected("ZERO_PROVIDER_IDENTITY_DIGEST")
    if provider_kind != known_provider_kind:
        return rejected("UNKNOWN_PROVIDER_KIND", "NINLIL_E_UNSUPPORTED")
    if provider_schema != known_provider_schema:
        return rejected("UNKNOWN_PROVIDER_SCHEMA", "NINLIL_E_UNSUPPORTED")
    expected_provider_digest = export_provider_identity_digest(
        provider_kind,
        provider_schema,
        known_provider_config,
    )
    if provider_digest != expected_provider_digest:
        return rejected("PROVIDER_IDENTITY_DIGEST")
    if not 1 <= namespace_length <= 255:
        return rejected("NAMESPACE_LENGTH")
    cursor = 54
    if len(artifact) < cursor + namespace_length + 4:
        return rejected("TRUNCATED_NAMESPACE")
    namespace = artifact[cursor : cursor + namespace_length]
    cursor += namespace_length
    record_count = int.from_bytes(artifact[cursor : cursor + 4], "big")
    cursor += 4
    previous_key: bytes | None = None
    row_digests = []
    for _ in range(record_count):
        if len(artifact) < cursor + 8:
            return rejected("TRUNCATED_ROW_HEADER")
        key_length = int.from_bytes(artifact[cursor : cursor + 2], "big")
        reserved = int.from_bytes(artifact[cursor + 2 : cursor + 4], "big")
        value_length = int.from_bytes(
            artifact[cursor + 4 : cursor + 8], "big"
        )
        cursor += 8
        if not 1 <= key_length <= 255:
            return rejected("KEY_LENGTH")
        if reserved != 0:
            return rejected("ROW_RESERVED")
        if not 1 <= value_length <= 65536:
            return rejected("VALUE_LENGTH")
        if len(artifact) < cursor + key_length + value_length + 32:
            return rejected("TRUNCATED_ROW")
        key = artifact[cursor : cursor + key_length]
        cursor += key_length
        value = artifact[cursor : cursor + value_length]
        cursor += value_length
        actual_row_digest = artifact[cursor : cursor + 32]
        cursor += 32
        expected_row_digest = sha256(
            EXPORT_ROW_DOMAIN
            + u16(key_length)
            + key
            + u32(value_length)
            + value
        )
        if actual_row_digest != expected_row_digest:
            return rejected("ROW_DIGEST")
        if previous_key is not None and key == previous_key:
            return rejected("DUPLICATE_KEY")
        if previous_key is not None and key < previous_key:
            return rejected("ROW_ORDER")
        previous_key = key
        row_digests.append(actual_row_digest.hex())
    if len(artifact) == cursor + 32:
        return rejected("MISSING_COMPLETION")
    if len(artifact) < cursor + 40:
        return rejected("TRUNCATED_FOOTER")
    actual_content_digest = artifact[cursor : cursor + 32]
    expected_content_digest = sha256(
        EXPORT_CONTENT_DOMAIN + artifact[:cursor]
    )
    if actual_content_digest != expected_content_digest:
        return rejected("CONTENT_DIGEST")
    if artifact[cursor + 32 : cursor + 40] != EXPORT_COMPLETION_MAGIC:
        return rejected("COMPLETION_MAGIC")
    if len(artifact) != cursor + 40:
        return rejected("TRAILING_BYTES")
    return {
        "status": "NINLIL_OK",
        "rejection": None,
        "namespace_hex": namespace.hex(),
        "record_count": record_count,
        "unique_key_count": record_count,
        "row_digests": row_digests,
        "content_digest": actual_content_digest.hex(),
    }


def build_export_artifact_vectors() -> dict[str, Any]:
    min_context = {
        "provider_kind": 1,
        "provider_schema": 1,
        "provider_config": b"m",
    }
    max_context = {
        "provider_kind": 65535,
        "provider_schema": 65535,
        "provider_config": bytes(range(256)),
    }
    mutation_context = {
        "provider_kind": 7,
        "provider_schema": 3,
        "provider_config": b"sqlite:path=:memory:",
    }

    def encoded(
        namespace: bytes,
        rows: list[tuple[bytes, bytes]],
        context: dict[str, Any],
    ) -> bytes:
        return encode_export_artifact(
            namespace,
            rows,
            context["provider_kind"],
            context["provider_schema"],
            context["provider_config"],
        )

    positive_min = encoded(b"m", [(b"k", b"v")], min_context)
    positive_max = encoded(
        b"n" * 255,
        [(b"k" * 255, bytes(range(256)) * 256)],
        max_context,
    )
    base = encoded(
        b"lab",
        [(b"a", b"A"), (b"b", b"B")],
        mutation_context,
    )
    layout = export_artifact_layout(base)

    duplicate = encoded(
        b"lab",
        [(b"a", b"A"), (b"a", b"B")],
        mutation_context,
    )
    reordered = encoded(
        b"lab",
        [(b"b", b"B"), (b"a", b"A")],
        mutation_context,
    )
    row_digest = bytearray(base)
    row_digest[layout["rows"][0]["digest_start"]] ^= 0x01
    row_digest_mismatch = refresh_export_content_digest(bytes(row_digest))
    content_digest = bytearray(base)
    content_digest[layout["content_digest_offset"]] ^= 0x01
    content_digest_mismatch = bytes(content_digest)
    declared_length = int.from_bytes(
        base[
            layout["rows"][0]["value_length_offset"] :
            layout["rows"][0]["value_length_offset"] + 4
        ],
        "big",
    )
    length_mismatch = patch_export_artifact(
        base,
        [
            (
                layout["rows"][0]["value_length_offset"],
                u32(declared_length + 1),
            )
        ],
    )
    unknown_kind = 8
    unknown_schema = 4
    unknown_kind_digest = export_provider_identity_digest(
        unknown_kind,
        mutation_context["provider_schema"],
        mutation_context["provider_config"],
    )
    unknown_schema_digest = export_provider_identity_digest(
        mutation_context["provider_kind"],
        unknown_schema,
        mutation_context["provider_config"],
    )

    fixtures: list[
        tuple[str, str, bytes, dict[str, Any], str]
    ] = [
        (
            "EXPORT_POSITIVE_MIN",
            "positive",
            positive_min,
            min_context,
            "NINLIL_OK",
        ),
        (
            "EXPORT_POSITIVE_MAX",
            "positive",
            positive_max,
            max_context,
            "NINLIL_OK",
        ),
        (
            "EXPORT_TRUNCATED",
            "mutation",
            base[: layout["rows"][1]["value_start"]],
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_MISSING_COMPLETION",
            "mutation",
            base[:-8],
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_DUPLICATE_KEY",
            "mutation",
            duplicate,
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_REORDERED_KEY",
            "mutation",
            reordered,
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_ROW_DIGEST_MISMATCH",
            "mutation",
            row_digest_mismatch,
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_CONTENT_DIGEST_MISMATCH",
            "mutation",
            content_digest_mismatch,
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_DECLARED_LENGTH_MISMATCH",
            "mutation",
            length_mismatch,
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_TRAILING_BYTES",
            "mutation",
            base + b"\x00",
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_UNKNOWN_FORMAT_VERSION",
            "mutation",
            patch_export_artifact(base, [(8, u16(2))]),
            mutation_context,
            "NINLIL_E_UNSUPPORTED",
        ),
        (
            "EXPORT_UNKNOWN_SOURCE_PROFILE",
            "mutation",
            patch_export_artifact(base, [(10, u16(2))]),
            mutation_context,
            "NINLIL_E_UNSUPPORTED",
        ),
        (
            "EXPORT_UNKNOWN_FLAG",
            "mutation",
            patch_export_artifact(base, [(12, u32(1))]),
            mutation_context,
            "NINLIL_E_UNSUPPORTED",
        ),
        (
            "EXPORT_ROW_RESERVED_NONZERO",
            "mutation",
            patch_export_artifact(
                base,
                [(layout["rows"][0]["reserved_offset"], u16(1))],
            ),
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_ZERO_PROVIDER_KIND",
            "mutation",
            patch_export_artifact(base, [(16, u16(0))]),
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_UNKNOWN_PROVIDER_KIND",
            "mutation",
            patch_export_artifact(
                base,
                [(16, u16(unknown_kind)), (20, unknown_kind_digest)],
            ),
            mutation_context,
            "NINLIL_E_UNSUPPORTED",
        ),
        (
            "EXPORT_ZERO_PROVIDER_SCHEMA",
            "mutation",
            patch_export_artifact(base, [(18, u16(0))]),
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_UNKNOWN_PROVIDER_SCHEMA",
            "mutation",
            patch_export_artifact(
                base,
                [(18, u16(unknown_schema)), (20, unknown_schema_digest)],
            ),
            mutation_context,
            "NINLIL_E_UNSUPPORTED",
        ),
        (
            "EXPORT_ZERO_PROVIDER_IDENTITY_DIGEST",
            "mutation",
            patch_export_artifact(base, [(20, ZERO32)]),
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "EXPORT_PROVIDER_IDENTITY_DIGEST_MISMATCH",
            "mutation",
            patch_export_artifact(
                base,
                [(20, bytes([base[20] ^ 0x01]) + base[21:52])],
            ),
            mutation_context,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
    ]
    vectors = []
    aggregate = b"NINLIL-LAB-EXPORT-VECTOR-SET-V1"
    for vector_id, fixture_kind, artifact, context, expected_status in fixtures:
        computed = classify_export_artifact(
            artifact,
            context["provider_kind"],
            context["provider_schema"],
            context["provider_config"],
        )
        assert computed["status"] == expected_status, (
            vector_id,
            computed,
        )
        vector = {
            "id": vector_id,
            "fixture_kind": fixture_kind,
            "artifact_length": len(artifact),
            "artifact_hex": artifact.hex(),
            "artifact_sha256": sha256(artifact).hex(),
            "known_provider": {
                "kind": context["provider_kind"],
                "schema": context["provider_schema"],
                "config_hex": context["provider_config"].hex(),
                "identity_digest": export_provider_identity_digest(
                    context["provider_kind"],
                    context["provider_schema"],
                    context["provider_config"],
                ).hex(),
            },
            "expected_status": expected_status,
            "computed_status": computed["status"],
            "computed_rejection": computed["rejection"],
            "oracle": "generator classify_export_artifact",
        }
        if computed["status"] == "NINLIL_OK":
            vector["computed"] = {
                key: value
                for key, value in computed.items()
                if key not in {"status", "rejection"}
            }
        vectors.append(vector)
        encoded_id = vector_id.encode("ascii")
        encoded_status = expected_status.encode("ascii")
        aggregate += (
            u16(len(encoded_id))
            + encoded_id
            + u16(len(encoded_status))
            + encoded_status
            + u32(len(artifact))
            + artifact
        )
    return {
        "fixture_count": len(vectors),
        "positive_count": sum(
            vector["fixture_kind"] == "positive" for vector in vectors
        ),
        "mutation_count": sum(
            vector["fixture_kind"] == "mutation" for vector in vectors
        ),
        "fixture_aggregate_preimage": (
            "ASCII(NINLIL-LAB-EXPORT-VECTOR-SET-V1)||each "
            "(id_length:u16||id||status_length:u16||status||"
            "artifact_length:u32||artifact)"
        ),
        "fixture_aggregate_sha256": sha256(aggregate).hex(),
        "vectors": vectors,
    }


def bootstrap_fixture() -> dict[str, Any]:
    return {
        "storage_schema": 1,
        "role": 1,
        "environment": 1,
        "runtime_id_hex": "44" * 16,
        "limits": {
            "max_services": 16,
            "max_nonterminal_transactions": 32,
            "max_targets_per_transaction": 4,
            "max_logical_payload_bytes": 256,
            "max_durable_outbox_payload_bytes": 8192,
            "max_attempts_per_target_per_cycle": 8,
            "max_cancel_attempts_per_transaction": 4,
            "max_evidence_per_target": 3,
            "max_retained_terminal_transactions": 64,
            "max_nonterminal_deliveries": 32,
            "max_event_spool_count": 32,
            "max_event_spool_bytes": 8192,
            "max_result_cache_entries": 32,
            "max_retained_dispositions": 64,
            "max_ingress_per_step": 8,
            "max_callbacks_per_step": 8,
            "max_state_transitions_per_step": 16,
            "max_bearer_sends_per_step": 8,
            "max_deferred_tokens": 16,
        },
        "terminal_retention_ms": 1000,
        "result_cache_retention_ms": 2000,
        "observation_retention_ms": 3000,
        "identity": {
            "flags": 7,
            "device_id_hex": "55" * 16,
            "installation_id_hex": "66" * 16,
            "site_domain_id_hex": "77" * 16,
            "binding_epoch": 1,
            "membership_epoch": 1,
        },
    }


def encode_binding_payload(binding_format: int, fixture: dict[str, Any]) -> bytes:
    profile = b"NINLIL-FOUNDATION-SMALL-1"
    limits = fixture["limits"]
    payload = u32(binding_format) + raw16(profile)
    if binding_format == 2:
        storage_profile_id = b"NINLIL-DOMAIN-S1"
        assert len(storage_profile_id) == 16
        payload += (
            storage_profile_id
            + u32(1)
            + u32(2)
            + u64(1)
        )
    elif binding_format != 1:
        raise ValueError("binding_format must be 1 or 2")
    payload += (
        u32(fixture["storage_schema"])
        + u32(fixture["role"])
        + u32(fixture["environment"])
        + bytes.fromhex(fixture["runtime_id_hex"])
        + u32(limits["max_services"])
        + u32(limits["max_nonterminal_transactions"])
        + u32(limits["max_targets_per_transaction"])
        + u32(limits["max_logical_payload_bytes"])
        + u64(limits["max_durable_outbox_payload_bytes"])
        + u32(limits["max_attempts_per_target_per_cycle"])
        + u32(limits["max_cancel_attempts_per_transaction"])
        + u32(limits["max_evidence_per_target"])
        + u32(limits["max_retained_terminal_transactions"])
        + u32(limits["max_nonterminal_deliveries"])
        + u32(limits["max_event_spool_count"])
        + u64(limits["max_event_spool_bytes"])
        + u32(limits["max_result_cache_entries"])
        + u32(limits["max_retained_dispositions"])
        + u32(limits["max_ingress_per_step"])
        + u32(limits["max_callbacks_per_step"])
        + u32(limits["max_state_transitions_per_step"])
        + u32(limits["max_bearer_sends_per_step"])
        + u32(limits["max_deferred_tokens"])
        + u64(fixture["terminal_retention_ms"])
        + u64(fixture["result_cache_retention_ms"])
        + u64(fixture["observation_retention_ms"])
    )
    assert len(payload) == (167 if binding_format == 1 else 199)
    return payload


def derive_capacity_limits(limits: dict[str, int]) -> list[int]:
    transaction = (
        limits["max_nonterminal_transactions"]
        + limits["max_retained_terminal_transactions"]
    )
    target = transaction * limits["max_targets_per_transaction"]
    return [
        limits["max_services"],
        transaction,
        target,
        limits["max_durable_outbox_payload_bytes"],
        limits["max_nonterminal_deliveries"],
        limits["max_event_spool_count"],
        limits["max_event_spool_bytes"],
        (
            limits["max_result_cache_entries"]
            + limits["max_retained_dispositions"]
        ),
        target * (limits["max_evidence_per_target"] + 1),
        limits["max_ingress_per_step"],
        limits["max_deferred_tokens"],
    ]


def build_bootstrap_vector(binding_format: int) -> dict[str, Any]:
    fixture = bootstrap_fixture()
    if binding_format == 2:
        fixture.update(
            {
                "storage_profile_id_ascii": "NINLIL-DOMAIN-S1",
                "storage_profile_revision": 1,
                "minimum_writer_generation": 2,
                "rollback_epoch": 1,
            }
        )
    binding_value = nlr1(1, encode_binding_payload(binding_format, fixture))
    identity = fixture["identity"]
    identity_payload = (
        u32(identity["flags"])
        + bytes.fromhex(identity["device_id_hex"])
        + bytes.fromhex(identity["installation_id_hex"])
        + bytes.fromhex(identity["site_domain_id_hex"])
        + u64(identity["binding_epoch"])
        + u64(identity["membership_epoch"])
    )
    assert len(identity_payload) == 68
    identity_value = nlr1(2, identity_payload)
    records = [
        record_object("RS_BINDING", ROOT + b"\x01", binding_value),
        record_object("RS_IDENTITY", ROOT + b"\x02", identity_value),
    ]
    for kind, name in enumerate(
        [
            "RS_COUNTER_TRANSACTION",
            "RS_COUNTER_ORDERED_INPUT",
            "RS_COUNTER_ASSIGNED_OWNER",
            "RS_COUNTER_VISITED_OWNER",
        ],
        1,
    ):
        value = nlr1(3, u32(kind) + u64(0) + u32(0))
        records.append(
            record_object(name, ROOT + b"\x03" + u8(kind), value)
        )
    capacity_names = [
        "RS_CAPACITY_SERVICE",
        "RS_CAPACITY_TRANSACTION",
        "RS_CAPACITY_TARGET",
        "RS_CAPACITY_OUTBOX_BYTES",
        "RS_CAPACITY_DELIVERY",
        "RS_CAPACITY_EVENT_SPOOL_COUNT",
        "RS_CAPACITY_EVENT_SPOOL_BYTES",
        "RS_CAPACITY_RESULT_CACHE",
        "RS_CAPACITY_EVIDENCE",
        "RS_CAPACITY_INGRESS",
        "RS_CAPACITY_DEFERRED_TOKEN",
    ]
    capacity_limits = derive_capacity_limits(fixture["limits"])
    for kind, (name, limit) in enumerate(
        zip(capacity_names, capacity_limits, strict=True), 1
    ):
        value = runtime_capacity_value(kind, limit, 0, 0, 0, 1)
        records.append(
            record_object(name, ROOT + b"\x04" + u8(kind), value)
        )

    keys = [bytes.fromhex(row["key_hex"]) for row in records]
    assert len(records) == 17
    assert keys == sorted(keys)
    encoded_key_value_bytes = sum(
        row["key_length"] + row["value_length"] for row in records
    )
    encoded_value_bytes = sum(row["value_length"] for row in records)
    logical_bytes = sum(
        16 + row["key_length"] + row["value_length"] for row in records
    )
    expected_encoded = 1311 + (32 if binding_format == 2 else 0)
    expected_values = 1143 + (32 if binding_format == 2 else 0)
    expected_logical = 1583 + (32 if binding_format == 2 else 0)
    assert encoded_key_value_bytes == expected_encoded
    assert encoded_value_bytes == expected_values
    assert logical_bytes == expected_logical
    return {
        "binding_format": binding_format,
        "fixture": fixture,
        "record_count": len(records),
        "binding_payload_bytes": len(encode_binding_payload(
            binding_format, fixture
        )),
        "binding_value_bytes": len(binding_value),
        "encoded_key_bytes": sum(row["key_length"] for row in records),
        "encoded_value_bytes": encoded_value_bytes,
        "encoded_key_value_bytes": encoded_key_value_bytes,
        "portable_logical_bytes": logical_bytes,
        "records_unsigned_key_order": records,
    }


def tagged_id(tag: int) -> bytes:
    return bytes((tag + index) & 0xFF for index in range(16))


def digest256(tag: int) -> bytes:
    return u16(1) + bytes(31) + u8(tag)


def encode_nts3_transaction(
    txid: bytes,
    payload: bytes = b"",
    bearer_route: int = 1,
) -> bytes:
    """Encode one minimal valid V1-LAB NTS3 desired-state snapshot."""
    assert len(txid) == 16 and any(txid)
    zero_id = bytes(16)
    body = bytearray()
    body += u32(1) + u32(0) + u32(1) + u32(0)
    body += txid + zero_id
    body += u32(0) + u32(0)
    body += tagged_id(0x11) + zero_id

    # source PARTY: runtime/app IDs plus absent local identity.
    body += tagged_id(0x21) + tagged_id(0x31)
    body += zero_id + zero_id + zero_id + u64(0) + u64(0) + u32(0)

    # SERVICE identity matching the production V1-LAB fixture.
    body += text_id("org.ninlil")
    body += text_id("test")
    body += text_id("test-v1")
    body += u64(1) + digest256(0x41) + u16(1) + u16(0) + u32(2)
    body += digest256(0x42)

    # Family/result/deadline state.
    body += (
        u32(2)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u64(0)
        + u32(0)
        + u32(0)
        + u64(1)
        + u64(1)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(1)
        + u64(0)
        + u32(0)
        + u32(0)
        + zero_id
        + u64(0)
        + u64(0)
        + u64(0)
        + u64(0)
        + u64(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u64(0)
        + u32(0)
        + u64(0)
        + u32(0)
    )

    # Four fixed retry-summary slots, all absent/zero.
    for _ in range(4):
        body += u64(0) + u32(0) + u32(0) + u32(0) + zero_id + u64(0)

    body += (
        u64(0)
        + u64(0)
        + u32(0)
        + u32(0)
        + zero_id
        + u64(0)
        + u64(0)
        + zero_id
        + u64(1000)
        + u64(0)
        + zero_id
        + tagged_id(0x43)
        + u64(1)
        + u32(0)
        + zero_id
        + u32(0)
        + u32(0)
        + u32(len(payload))
        + u8(0)
        + u8(bearer_route)
        + u32(0)
        + u32(0)
        + u64(0)
        + u64(0)
        + u64(0)
        + zero_id
        + u64(0)
        + u64(0)
        + u64(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u32(0)
        + u64(0)
    )

    body += payload

    # Admission assurance: profile + thirteen boolean fields.
    body += bytes(14 * 4)

    # One bound target with only runtime/application IDs present.
    body += u32(1)
    body += u8(1) + u8(0) + u8(0)
    body += tagged_id(0x51) + tagged_id(0x61)
    body += zero_id + zero_id + zero_id
    body += u64(0) + u64(0) + u32(0) + u32(0) + u32(0)

    header = b"NTS3" + u16(1) + u16(0) + u32(len(body)) + u32(0)
    value = header + bytes(body)
    value += u32(crc32c(value))
    assert 20 <= len(value) <= 3072
    return value


def encode_nel1(kind: int) -> tuple[bytes, bytes]:
    assert kind in (1, 2)
    if kind == 1:
        prefix = b"ER"
        txid = tagged_id(0x91)
        event_id = tagged_id(0x92)
        operation_id = tagged_id(0x93)
        actor_id = tagged_id(0x94)
        metadata = b"resume"
        spool_revision = 7
        request_reason = 5
        expected_event_id = bytes(16)
        expected_algorithm = 0
        expected_digest = bytes(32)
        acknowledge = 0
        audit_clock = bytes(16)
        audit_at = 0
        replay_result_kind = 2
        replay_reason = 0
        retry_cycle = 1
        released = 0
        digest_preimage = (
            b"NINLIL-M1A-EVENT-RESUME"
            + txid
            + operation_id
            + actor_id
            + u64(spool_revision)
            + u32(request_reason)
            + u32(len(metadata))
            + metadata
        )
    else:
        prefix = b"ED"
        txid = tagged_id(0xA1)
        event_id = tagged_id(0xA2)
        operation_id = tagged_id(0xA3)
        actor_id = tagged_id(0xA4)
        metadata = b"discard"
        spool_revision = 7
        request_reason = 4
        expected_event_id = event_id
        expected_algorithm = 1
        expected_digest = bytes([0xA5]) * 32
        acknowledge = 1
        audit_clock = tagged_id(0xA6)
        audit_at = 123
        replay_result_kind = 2
        replay_reason = 80
        retry_cycle = 0
        released = 1
        digest_preimage = (
            b"NINLIL-M1A-EVENT-DISCARD"
            + txid
            + operation_id
            + actor_id
            + expected_event_id
            + u16(expected_algorithm)
            + expected_digest
            + u64(spool_revision)
            + u32(request_reason)
            + u32(acknowledge)
            + u32(len(metadata))
            + metadata
        )
    request_digest = sha256(digest_preimage)
    total_length = 256 + len(metadata) + 4
    fixed = (
        b"NEL1"
        + u16(1)
        + u16(0)
        + u32(total_length)
        + u16(kind)
        + u16(0)
        + u64(1)
        + u64(1)
        + txid
        + event_id
        + operation_id
        + actor_id
        + request_digest
        + u64(spool_revision)
        + expected_event_id
        + u16(expected_algorithm)
        + u16(0)
        + expected_digest
        + u32(request_reason)
        + u32(acknowledge)
        + u32(len(metadata))
        + audit_clock
        + u64(audit_at)
        + u32(replay_result_kind)
        + u32(replay_reason)
        + u64(retry_cycle)
        + u64(spool_revision + 1)
        + u32(released)
        + u32(0)
    )
    assert len(fixed) == 256
    value = fixed + metadata
    value += u32(crc32c(value))
    assert len(value) == total_length
    return prefix + txid + operation_id, value


def encode_nrv1() -> tuple[bytes, bytes]:
    txid = tagged_id(0xB1)
    key = b"RV" + txid
    value = b"NRV1" + u16(1) + u16(0) + u32(64) + u8(1) + u8(1)
    value += bytes(14)
    value += u32(crc32c(value))
    assert len(value) == 32
    return key, value


def encode_m4t() -> tuple[bytes, bytes]:
    session_id = 1
    fingerprint = bytes((0xC1 + index) & 0xFF for index in range(32))
    key = b"M4T" + u32(session_id) + fingerprint[:9]
    value = (
        u8(1)
        + u8(1)
        + u16(0)
        + u32(session_id)
        + u64(1)
        + u64(2)
        + u32(3)
        + u64(4)
        + fingerprint
    )
    value += u32(crc32c(value))
    assert len(key) == 16 and len(value) == 72
    return key, value


def encode_c3r() -> tuple[bytes, bytes]:
    hop_context_id = 3
    lane = 0
    layer_e2e = 1
    counter = 5
    key = (
        b"C3R"
        + u32(hop_context_id)
        + u8(lane)
        + u8(layer_e2e)
        + u32(counter & 0xFFFFFFFF)
        + bytes(3)
    )
    value = (
        u8(1)
        + u8(1)
        + u16(0)
        + u32(hop_context_id)
        + u64(9)
        + u8(lane)
        + u8(layer_e2e)
        + u16(0)
        + u64(counter)
        + bytes(16)
    )
    value += u32(crc32c(value))
    assert len(key) == 16 and len(value) == 48
    return key, value


def encode_nbs1(runtime_id: bytes) -> tuple[bytes, bytes]:
    assert len(runtime_id) == 16 and any(runtime_id)
    clock_epoch = tagged_id(0xE1)
    key = b"BS" + runtime_id
    value = (
        bytes.fromhex("4e42533100010000")
        + u64(1)
        + bytes(3)
        + u8(1)
        + bytes(4)
        + clock_epoch
        + u64(123)
    )
    assert len(key) == 18 and len(value) == 48
    return key, value


def domain_singleton_key(subtype: int) -> bytes:
    return ROOT + b"\x06" + u8(subtype) + b"\x01\x01\x00"


def build_legacy_metadata_group(
    format1_bootstrap: dict[str, Any],
) -> dict[str, Any]:
    metadata_records = []
    bootstrap_records = format1_bootstrap["records_unsigned_key_order"]
    indexed_records = [
        row
        for row in bootstrap_records
        if row["name"].startswith("RS_COUNTER_")
        or row["name"].startswith("RS_CAPACITY_")
    ]
    assert len(indexed_records) == 15
    for member in indexed_records:
        member_key = bytes.fromhex(member["key_hex"])
        member_value = bytes.fromhex(member["value_hex"])
        identity = composite(0x7D, key_digest(member_key))
        index_key = domain_key(0x7D, identity)
        index_body = witness_index_body(
            1, member_key, sha256(member_value), ZERO32
        )
        index_value = domain_value(
            0x7D, 1, identity[:16], ZERO32, ZERO32, index_body
        )
        metadata_records.append(
            record_object(
                f"DOM_WITNESS_HEAD_INDEX_{member['name']}",
                index_key,
                index_value,
            )
        )

    clock_key = domain_singleton_key(0x62)
    clock_body = u32(1) + u32(0) + ZERO16 + u64(0) + u64(0)
    clock_value = domain_value(
        0x62, 1, ZERO16, ZERO32, ZERO32, clock_body
    )
    uninitialized_clock = record_object(
        "DOM_CLOCK_BASELINE_UNINITIALIZED", clock_key, clock_value
    )
    trusted_clock_body = (
        u32(2)
        + u32(0)
        + tagged_id(0xD1)
        + u64(123)
        + u64(1)
    )
    trusted_clock_value = domain_value(
        0x62, 2, ZERO16, ZERO32, ZERO32, trusted_clock_body
    )
    trusted_clock = record_object(
        "DOM_CLOCK_BASELINE_TRUSTED", clock_key, trusted_clock_value
    )
    metadata_records.append(uninitialized_clock)
    metadata_records.sort(key=lambda row: bytes.fromhex(row["key_hex"]))
    assert len(metadata_records) == 16
    assert len({row["key_hex"] for row in metadata_records}) == 16
    return {
        "record_count": 16,
        "commit_mode": "FULL",
        "index_state": "BASELINE",
        "clock_state": "UNINITIALIZED fixture; TRUSTED is also valid",
        "valid_clock_variants": [
            uninitialized_clock,
            trusted_clock,
        ],
        "records_unsigned_key_order": metadata_records,
    }


def build_lab_positive_vectors(
    format1_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    positives = {
        row["name"]: row
        for row in format1_bootstrap["records_unsigned_key_order"]
    }

    metadata_records = legacy_metadata_group["records_unsigned_key_order"]
    positives["DOM_WITNESS_HEAD_INDEX"] = {
        **next(
            record
            for record in metadata_records
            if record["name"]
            == "DOM_WITNESS_HEAD_INDEX_RS_CAPACITY_SERVICE"
        ),
        "name": "DOM_WITNESS_HEAD_INDEX",
    }
    positives["DOM_CLOCK_BASELINE"] = {
        **next(
            record
            for record in metadata_records
            if record["name"] == "DOM_CLOCK_BASELINE_UNINITIALIZED"
        ),
        "name": "DOM_CLOCK_BASELINE",
    }

    positives["SPINE_SERVICE_MARKER"] = record_object(
        "SPINE_SERVICE_MARKER", b"NRS\x00", bytes([0xA1]) * 16
    )
    nts3_rows = [
        ("SPINE_TXN_ADMISSION", b"TX", 0x71),
        ("SPINE_CANCEL_ADMISSION", b"CN", 0x72),
        ("SPINE_DELIVERY_STARTED", b"DS", 0x73),
        ("SPINE_DELIVERY_EVIDENCE", b"EV", 0x74),
        ("SPINE_DELIVERY_OUTCOME", b"OC", 0x75),
        ("SPINE_EVENT_SPOOL", b"ES", 0x76),
        ("SPINE_RETRY_STATE", b"RT", 0x77),
        ("SPINE_ATTEMPT_PREPARE", b"AP", 0x78),
    ]
    for name, prefix, tag in nts3_rows:
        txid = tagged_id(tag)
        positives[name] = record_object(
            name, prefix + txid, encode_nts3_transaction(txid)
        )

    resume_key, resume_value = encode_nel1(1)
    positives["SPINE_EVENT_RESUME"] = record_object(
        "SPINE_EVENT_RESUME", resume_key, resume_value
    )
    discard_key, discard_value = encode_nel1(2)
    positives["SPINE_EVENT_DISCARD"] = record_object(
        "SPINE_EVENT_DISCARD", discard_key, discard_value
    )
    nrv_key, nrv_value = encode_nrv1()
    positives["SPINE_RESERVATION"] = record_object(
        "SPINE_RESERVATION", nrv_key, nrv_value
    )
    m4_key, m4_value = encode_m4t()
    positives["M4_INSTALL_TOKEN"] = record_object(
        "M4_INSTALL_TOKEN", m4_key, m4_value
    )
    c3_key, c3_value = encode_c3r()
    positives["C3_REPLAY_ADMISSION"] = record_object(
        "C3_REPLAY_ADMISSION", c3_key, c3_value
    )
    runtime_id = bytes.fromhex(
        format1_bootstrap["fixture"]["runtime_id_hex"]
    )
    nbs_key, nbs_value = encode_nbs1(runtime_id)
    positives["SPINE_BEARER_STATE"] = record_object(
        "SPINE_BEARER_STATE", nbs_key, nbs_value
    )
    assert len(positives) == 34
    return positives


def mutation_object(
    mutation_id: str,
    key: bytes,
    value: bytes,
) -> dict[str, Any]:
    return {
        "id": mutation_id,
        "key_length": len(key),
        "key_hex": key.hex(),
        "value_length": len(value),
        "value_hex": value.hex(),
        "expected_row_status": "NINLIL_E_STORAGE_CORRUPT",
        "expected_namespace_status": "CORRUPT",
        "canonical_publish": False,
    }


def build_lab_mutations(
    positive: dict[str, Any],
) -> list[dict[str, Any]]:
    key = bytes.fromhex(positive["key_hex"])
    value = bytes.fromhex(positive["value_hex"])
    corrupt_value = bytearray(value)
    if positive["name"] == "SPINE_BEARER_STATE":
        corrupt_value[19] = 2
    elif positive["name"] == "SPINE_SERVICE_MARKER":
        corrupt_value[0] ^= 1
    else:
        corrupt_value[-1] ^= 1
    mutations = [
        mutation_object("key_short", key[:-1], value),
        mutation_object("key_long", key + b"\x00", value),
        mutation_object("value_short", key, value[:-1]),
        mutation_object("value_integrity", key, bytes(corrupt_value)),
    ]
    by_id = {row["id"]: row for row in mutations}
    assert bytes.fromhex(by_id["key_short"]["key_hex"]) == key[:-1]
    assert bytes.fromhex(by_id["key_long"]["key_hex"]) == key + b"\x00"
    assert bytes.fromhex(by_id["value_short"]["value_hex"]) == value[:-1]
    integrity_value = bytes.fromhex(by_id["value_integrity"]["value_hex"])
    if positive["name"] == "SPINE_BEARER_STATE":
        assert integrity_value[19] == 2
    elif positive["name"] == "SPINE_SERVICE_MARKER":
        assert integrity_value[0] != 0xA1
    else:
        assert int.from_bytes(integrity_value[-4:], "big") != crc32c(
            integrity_value[:-4]
        )
    return mutations


def build_kind30_matching_transaction(
    positives: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    reservation_key = bytes.fromhex(
        positives["SPINE_RESERVATION"]["key_hex"]
    )
    assert reservation_key[:2] == b"RV"
    txid = reservation_key[2:]
    payload = bytes([0x5A]) * 64
    row = record_object(
        "SPINE_TXN_ADMISSION_KIND30_COMPANION",
        b"TX" + txid,
        encode_nts3_transaction(txid, payload=payload, bearer_route=1),
    )
    row["cross_row_binding"] = {
        "transaction_id_hex": txid.hex(),
        "payload_length": len(payload),
        "bearer_route": 1,
        "matches_lab_kind": 30,
    }
    return row


def namespace_row_set_sha256(rows: dict[bytes, bytes]) -> str:
    transcript = b"".join(
        u16(len(key)) + key + u32(len(rows[key])) + rows[key]
        for key in sorted(rows)
    )
    return sha256(
        b"NINLIL-LAB-NAMESPACE-FIXTURE-V1"
        + u32(len(rows))
        + transcript
    ).hex()


def decode_nlr1_payload(value: bytes, expected_type: int) -> bytes:
    assert len(value) >= 16
    assert value[:4] == b"NLR1"
    assert int.from_bytes(value[4:6], "big") == expected_type
    assert int.from_bytes(value[6:8], "big") == 1
    payload_length = int.from_bytes(value[8:12], "big")
    assert len(value) == 12 + payload_length + 4
    assert int.from_bytes(value[-4:], "big") == crc32c(value[:-4])
    return value[12:-4]


def inspect_nlr1_envelope(
    value: bytes,
    expected_type: int,
) -> dict[str, Any]:
    """Separate malformed current framing from a valid future version."""

    if len(value) < 16:
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "NLR1_LENGTH",
        }
    if value[:4] != b"NLR1":
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "NLR1_MAGIC",
        }
    if int.from_bytes(value[4:6], "big") != expected_type:
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "NLR1_RECORD_TYPE",
        }
    payload_length = int.from_bytes(value[8:12], "big")
    if len(value) != 12 + payload_length + 4:
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "NLR1_DECLARED_LENGTH",
        }
    if int.from_bytes(value[-4:], "big") != crc32c(value[:-4]):
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "NLR1_CRC32C",
        }
    record_version = int.from_bytes(value[6:8], "big")
    if record_version > 1:
        return {
            "status": "NINLIL_E_UNSUPPORTED",
            "reason": "NLR1_FUTURE_RECORD_VERSION",
        }
    if record_version != 1:
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "NLR1_RECORD_VERSION_ZERO",
        }
    return {
        "status": "NINLIL_OK",
        "reason": None,
        "payload": value[12:-4],
    }


def decode_binding_authority(
    rows: dict[bytes, bytes],
) -> dict[str, Any] | None:
    value = rows.get(ROOT + b"\x01")
    if value is None:
        return None
    payload = decode_nlr1_payload(value, 1)
    binding_format = int.from_bytes(payload[:4], "big")
    profile_length = int.from_bytes(payload[4:6], "big")
    assert profile_length == 25
    assert payload[6:31] == b"NINLIL-FOUNDATION-SMALL-1"
    if binding_format == 1:
        suffix_offset = 31
        assert len(payload) == 167
    elif binding_format == 2:
        suffix_offset = 63
        assert len(payload) == 199
        assert payload[31:47] == b"NINLIL-DOMAIN-S1"
        assert int.from_bytes(payload[47:51], "big") == 1
        assert int.from_bytes(payload[51:55], "big") == 2
        assert int.from_bytes(payload[55:63], "big") == 1
    else:
        raise AssertionError("fixture binding format must be 1 or 2")
    return {
        "binding_format": binding_format,
        "runtime_id": payload[suffix_offset + 12 : suffix_offset + 28],
        "max_services": int.from_bytes(
            payload[suffix_offset + 28 : suffix_offset + 32], "big"
        ),
    }


def has_distinct_lab_row(rows: dict[bytes, bytes]) -> bool:
    prefixes = (
        b"NRS",
        b"TX",
        b"CN",
        b"DS",
        b"EV",
        b"OC",
        b"ES",
        b"ER",
        b"ED",
        b"RT",
        b"RV",
        b"M4T",
        b"C3R",
        b"BS",
        b"AP",
    )
    return any(key.startswith(prefixes) for key in rows)


def namespace_cross_row_failures(
    rows: dict[bytes, bytes],
    legacy_metadata_group: dict[str, Any],
    *,
    ignore_profile_mismatch: bool = False,
    ignore_legacy_metadata_mismatch: bool = False,
) -> list[str]:
    failures: list[str] = []
    binding = decode_binding_authority(rows)
    metadata_expected = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in legacy_metadata_group["records_unsigned_key_order"]
    }
    clock_key = domain_singleton_key(0x62)
    valid_clock_values = {
        bytes.fromhex(record["value_hex"])
        for record in legacy_metadata_group["valid_clock_variants"]
    }
    metadata_keys = {
        key
        for key in rows
        if key.startswith(ROOT + b"\x06\x7d")
        or key == domain_singleton_key(0x62)
    }
    distinct_lab = has_distinct_lab_row(rows)

    if binding is None:
        if distinct_lab or metadata_keys:
            failures.append("FORMAT1_AUTHORITY_ABSENT")
        return failures

    if binding["binding_format"] == 2 and distinct_lab:
        if not ignore_profile_mismatch:
            failures.append("FORMAT1_AUTHORITY_WRONG_FORMAT2")
            return failures

    if binding["binding_format"] not in (1, 2):
        return failures

    if metadata_keys and not ignore_legacy_metadata_mismatch:
        observed_metadata = {
            key: rows[key]
            for key in metadata_keys
        }
        if set(observed_metadata) != set(metadata_expected):
            failures.append("LEGACY_METADATA_INCOMPLETE")
        elif (
            any(
                observed_metadata[key] != metadata_expected[key]
                for key in metadata_expected
                if key != clock_key
            )
            or observed_metadata[clock_key] not in valid_clock_values
        ):
            failures.append("LEGACY_METADATA_MEMBER_MISMATCH")

    for key in rows:
        if key.startswith(b"NRS") and len(key) == 4:
            if key[3] >= binding["max_services"]:
                failures.append("KIND20_SLOT_OUT_OF_RANGE")

    tx_rows = {
        key[2:]: value
        for key, value in rows.items()
        if key.startswith(b"TX") and len(key) == 18
    }
    for key, value in rows.items():
        if not (key.startswith(b"RV") and len(key) == 18):
            continue
        assert value[:4] == b"NRV1" and len(value) == 32
        assert int.from_bytes(value[-4:], "big") == crc32c(value[:-4])
        reservation_txid = key[2:]
        reservation_payload = int.from_bytes(value[8:12], "big")
        reservation_route = value[12]
        transaction = tx_rows.get(reservation_txid)
        if transaction is None:
            failures.append(
                "KIND30_TXID_MISMATCH"
                if tx_rows
                else "KIND30_MATCHING_NTS3_MISSING"
            )
            continue
        assert transaction[:4] == b"NTS3"
        assert len(transaction) >= 842
        assert int.from_bytes(transaction[-4:], "big") == crc32c(
            transaction[:-4]
        )
        assert transaction[32:48] == reservation_txid
        transaction_payload = int.from_bytes(transaction[836:840], "big")
        transaction_route = transaction[841]
        if transaction_payload != reservation_payload:
            failures.append("KIND30_PAYLOAD_MISMATCH")
        if transaction_route != reservation_route:
            failures.append("KIND30_ROUTE_MISMATCH")

    for key in rows:
        if key.startswith(b"BS") and len(key) == 18:
            if key[2:] != binding["runtime_id"]:
                failures.append("KIND33_RUNTIME_ID_MISMATCH")

    return failures


def decode_binding_payload_fields(value: bytes) -> dict[str, Any]:
    payload = decode_nlr1_payload(value, 1)
    if len(payload) < 6:
        raise ValueError("binding payload short")
    binding_format = int.from_bytes(payload[0:4], "big")
    profile, cursor = parse_raw16_at(payload, 4)
    result: dict[str, Any] = {
        "binding_format": binding_format,
        "resource_profile_name": profile,
    }
    if binding_format == 2:
        if len(payload) - cursor < 32:
            raise ValueError("format2 discriminator short")
        result.update(
            {
                "storage_profile_id": payload[cursor : cursor + 16],
                "storage_profile_revision": int.from_bytes(
                    payload[cursor + 16 : cursor + 20], "big"
                ),
                "minimum_writer_generation": int.from_bytes(
                    payload[cursor + 20 : cursor + 24], "big"
                ),
                "rollback_epoch": int.from_bytes(
                    payload[cursor + 24 : cursor + 32], "big"
                ),
            }
        )
        cursor += 32
    if len(payload) - cursor != 136:
        raise ValueError("binding common tail length")
    result.update(
        {
            "storage_schema": int.from_bytes(
                payload[cursor : cursor + 4], "big"
            ),
            "role": int.from_bytes(payload[cursor + 4 : cursor + 8], "big"),
            "environment": int.from_bytes(
                payload[cursor + 8 : cursor + 12], "big"
            ),
            "runtime_id": payload[cursor + 12 : cursor + 28],
            "payload": payload,
        }
    )
    return result


def classify_lab_row(
    key: bytes,
    value: bytes,
    format1_bootstrap: dict[str, Any],
) -> dict[str, Any]:
    """Production-independent closed row classifier for ADR-0022 KAT bytes."""

    def ok(kind: int | None, row_class: str) -> dict[str, Any]:
        return {
            "status": "NINLIL_OK",
            "kind": kind,
            "row_class": row_class,
            "reason": None,
        }

    def corrupt(reason: str) -> dict[str, Any]:
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "kind": None,
            "row_class": "CORRUPT",
            "reason": reason,
        }

    def unsupported(reason: str) -> dict[str, Any]:
        return {
            "status": "NINLIL_E_UNSUPPORTED",
            "kind": None,
            "row_class": "FUTURE",
            "reason": reason,
        }

    base_by_key = {
        bytes.fromhex(row["key_hex"]): (index + 1, row)
        for index, row in enumerate(
            format1_bootstrap["records_unsigned_key_order"]
        )
    }
    if key in base_by_key:
        kind, positive = base_by_key[key]
        expected_record_type = (
            1 if kind == 1 else 2 if kind == 2 else 3 if kind <= 6 else 4
        )
        envelope = inspect_nlr1_envelope(value, expected_record_type)
        if envelope["status"] == "NINLIL_E_STORAGE_CORRUPT":
            return corrupt(envelope["reason"])
        if envelope["status"] == "NINLIL_E_UNSUPPORTED":
            return unsupported(envelope["reason"])
        if kind == 1:
            payload = envelope["payload"]
            if len(payload) < 4:
                return corrupt("RS1_FORMAT_LENGTH")
            if int.from_bytes(payload[:4], "big") not in (1, 2):
                return unsupported("RS1_FUTURE_BINDING_FORMAT")
        try:
            if kind == 1:
                binding = decode_binding_payload_fields(value)
                expected_payload = encode_binding_payload(
                    binding["binding_format"],
                    format1_bootstrap["fixture"],
                )
                if binding["payload"] != expected_payload:
                    return corrupt("RS1_PROFILE")
                if binding["binding_format"] == 1:
                    return ok(1, "LAB")
                if binding["binding_format"] == 2:
                    return ok(None, "DOMAIN")
                raise AssertionError("closed binding format")
            if kind == 2:
                payload = decode_nlr1_payload(value, 2)
                flags = int.from_bytes(payload[0:4], "big")
                device = payload[4:20]
                installation = payload[20:36]
                site = payload[36:52]
                binding_epoch = int.from_bytes(payload[52:60], "big")
                membership_epoch = int.from_bytes(payload[60:68], "big")
                if (
                    len(payload) != 68
                    or flags & ~0x07
                    or bool(flags & 0x01) != bool(any(device))
                    or bool(flags & 0x02) != bool(any(installation))
                    or bool(flags & 0x04) != bool(any(site))
                    or bool(flags & 0x03) != bool(binding_epoch)
                    or bool(flags & 0x04) != bool(membership_epoch)
                ):
                    return corrupt("RS2_BODY")
                return ok(2, "LAB")
            if 3 <= kind <= 6:
                payload = decode_nlr1_payload(value, 3)
                expected_counter_kind = kind - 2
                counter_value = int.from_bytes(payload[4:12], "big")
                exhausted = int.from_bytes(payload[12:16], "big")
                if (
                    len(payload) != 16
                    or int.from_bytes(payload[0:4], "big")
                    != expected_counter_kind
                    or exhausted not in (0, 1)
                    or (expected_counter_kind == 4 and exhausted != 0)
                    or (exhausted == 1 and counter_value != U64_MAX)
                ):
                    return corrupt("RS3_BODY")
                return ok(kind, "LAB")
            capacity = decode_runtime_capacity_semantics(value)
            expected_capacity = decode_runtime_capacity_semantics(
                bytes.fromhex(positive["value_hex"])
            )
            expected_capacity_kind = kind - 6
            if (
                capacity["kind"] != expected_capacity_kind
                or capacity["limit"] != expected_capacity["limit"]
                or capacity["used"] > capacity["limit"]
                or capacity["reserved"] > capacity["limit"]
                or capacity["used"] + capacity["reserved"]
                > capacity["limit"]
                or capacity["high_water"]
                < capacity["used"] + capacity["reserved"]
                or capacity["high_water"] > capacity["limit"]
                or capacity["epoch"] == 0
                or capacity["blocked"] not in (0, 1)
                or capacity["exhausted"] not in (0, 1)
                or (
                    capacity["exhausted"] == 1
                    and (
                        capacity["epoch"] != U64_MAX
                        or capacity["blocked"] != 0
                    )
                )
            ):
                return corrupt("RS4_BODY")
            return ok(kind, "LAB")
        except (AssertionError, KeyError, ValueError):
            return corrupt("RS_CODEC")

    if key == domain_singleton_key(0x62):
        envelope = inspect_nlr1_envelope(value, 6)
        if envelope["status"] == "NINLIL_E_STORAGE_CORRUPT":
            return corrupt(envelope["reason"])
        if envelope["status"] == "NINLIL_E_UNSUPPORTED":
            return unsupported(envelope["reason"])
        try:
            decoded = decode_domain_record_value(value)
            body = decoded["body"]
            state = int.from_bytes(body[0:4], "big")
            reserved = int.from_bytes(body[4:8], "big")
            epoch = body[8:24]
            now_ms = int.from_bytes(body[24:32], "big")
            generation = int.from_bytes(body[32:40], "big")
            if (
                decoded["subtype"] != 0x62
                or len(body) != 40
                or reserved != 0
                or decoded["primary_id"] != ZERO16
                or decoded["head"] != ZERO32
                or decoded["pvd"] != ZERO32
                or (
                    state == 1
                    and (
                        decoded["revision"] != 1
                        or any(epoch)
                        or now_ms != 0
                        or generation != 0
                    )
                )
                or (
                    state == 2
                    and (
                        decoded["revision"] < 2
                        or not any(epoch)
                        or generation == 0
                    )
                )
                or state not in (1, 2)
            ):
                return corrupt("DS_CLOCK")
        except (AssertionError, IndexError, ValueError):
            return corrupt("DS_CLOCK_CODEC")
        return ok(19, "LAB")

    subtype = domain_key_subtype(key)
    if subtype is not None:
        envelope = inspect_nlr1_envelope(value, 6)
        if envelope["status"] == "NINLIL_E_STORAGE_CORRUPT":
            return corrupt(envelope["reason"])
        if envelope["status"] == "NINLIL_E_UNSUPPORTED":
            return unsupported(envelope["reason"])
        if subtype in (0x7E, 0x7F):
            try:
                decoded = decode_domain_record_value(value)
                if (
                    decoded["subtype"] != subtype
                    or decoded["revision"] != 1
                    or decoded["head"] != ZERO32
                    or decoded["pvd"] != ZERO32
                    or not decoded["body"]
                ):
                    return corrupt("DOMAIN_WITNESS_COMMON")
            except ValueError:
                return corrupt("DOMAIN_WITNESS_CODEC")
            return ok(None, "DOMAIN")
        reason = independent_kind1_d1_row_local_reason(key, value)
        if reason is not None:
            return corrupt(f"DOMAIN_{reason}")
        if subtype == 0x7D:
            try:
                decoded = decode_kind1_head_semantics(value)
            except ValueError:
                return corrupt("DS_HEAD_INDEX")
            if (
                decoded["state"] != 1
                or decoded["member_key"][: len(ROOT)] != ROOT
                or len(decoded["member_key"]) != 10
                or decoded["member_key"][8] not in (3, 4)
            ):
                return ok(None, "DOMAIN")
            return ok(18, "LAB")
        if subtype == 0x62:
            return ok(19, "LAB")
        return ok(None, "DOMAIN")

    if key.startswith(ROOT) or ROOT.startswith(key):
        return corrupt("CURRENT_ROOT_KEY_SHAPE")

    if key.startswith(b"NRS") or b"NRS".startswith(key):
        if len(key) != 4 or len(value) != 16 or value != bytes([0xA1]) * 16:
            return corrupt("NRS_SHAPE")
        return ok(20, "LAB")

    nts3_kinds = {
        b"TX": 21,
        b"CN": 22,
        b"DS": 23,
        b"EV": 24,
        b"OC": 25,
        b"ES": 26,
        b"RT": 29,
        b"AP": 34,
    }
    if key[:2] in nts3_kinds or any(
        prefix.startswith(key) for prefix in nts3_kinds
    ):
        if len(key) != 18 or not any(key[2:]):
            return corrupt("NTS3_KEY")
        if len(value) < 20:
            return corrupt("NTS3_LENGTH")
        if value[:4] != b"NTS3":
            return corrupt("NTS3_MAGIC")
        declared_body_length = int.from_bytes(value[8:12], "big")
        if len(value) != 16 + declared_body_length + 4:
            return corrupt("NTS3_DECLARED_LENGTH")
        if int.from_bytes(value[-4:], "big") != crc32c(value[:-4]):
            return corrupt("NTS3_CRC32C")
        if value[32:48] != key[2:]:
            return corrupt("NTS3_KEY_BODY_BINDING")
        schema_major = int.from_bytes(value[4:6], "big")
        if schema_major > 1:
            return unsupported("NTS3_FUTURE_SCHEMA")
        if schema_major != 1:
            return corrupt("NTS3_SCHEMA_ZERO")
        try:
            if (
                len(value) < 842
                or int.from_bytes(value[6:8], "big") != 0
                or int.from_bytes(value[12:16], "big") != 0
            ):
                return corrupt("NTS3_VALUE")
            payload_length = int.from_bytes(value[836:840], "big")
            route = value[841]
            if value != encode_nts3_transaction(
                key[2:],
                value[938 : 938 + payload_length],
                route,
            ):
                return corrupt("NTS3_CANONICAL")
        except (AssertionError, ValueError):
            return corrupt("NTS3_CODEC")
        return ok(nts3_kinds[key[:2]], "LAB")

    nel1_kinds = {b"ER": (27, 1), b"ED": (28, 2)}
    if key[:2] in nel1_kinds or any(
        prefix.startswith(key) for prefix in nel1_kinds
    ):
        if len(key) != 34 or not any(key[2:18]) or not any(key[18:34]):
            return corrupt("NEL1_KEY")
        kind, operation_kind = nel1_kinds[key[:2]]
        expected_key, expected_value = encode_nel1(operation_kind)
        if key != expected_key or value != expected_value:
            return corrupt("NEL1_CANONICAL")
        return ok(kind, "LAB")

    if key.startswith(b"RV") or b"RV".startswith(key):
        if (
            len(key) != 18
            or not any(key[2:])
            or len(value) != 32
            or value[:4] != b"NRV1"
            or int.from_bytes(value[4:6], "big") != 1
            or int.from_bytes(value[6:8], "big") != 0
            or value[12] not in (1,)
            or value[13] != 1
            or any(value[14:28])
            or int.from_bytes(value[28:32], "big") != crc32c(value[:28])
        ):
            return corrupt("NRV1_SHAPE")
        return ok(30, "LAB")

    if key.startswith(b"M4T") or b"M4T".startswith(key):
        if len(key) != 16:
            return corrupt("M4T_KEY")
        if len(value) != 72:
            return corrupt("M4T_LENGTH")
        if int.from_bytes(value[68:72], "big") != crc32c(value[:68]):
            return corrupt("M4T_CRC32C")
        if key[3:7] != value[4:8] or key[7:16] != value[36:45]:
            return corrupt("M4T_KEY_BODY_BINDING")
        if value[0] > 1:
            return unsupported("M4T_FUTURE_VERSION")
        if value[0] != 1:
            return corrupt("M4T_VERSION_ZERO")
        if (
            value[1] not in (1, 2)
            or any(value[2:4])
            or int.from_bytes(value[8:16], "big") == 0
            or int.from_bytes(value[16:24], "big") == 0
            or int.from_bytes(value[24:28], "big") == 0
            or int.from_bytes(value[28:36], "big") == 0
            or not any(value[36:68])
        ):
            return corrupt("M4T_SHAPE")
        return ok(31, "LAB")

    if key.startswith(b"C3R") or b"C3R".startswith(key):
        if (
            len(key) != 16
            or len(value) != 48
            or value[0:2] != b"\x01\x01"
            or any(value[2:4])
            or key[3:7] != value[4:8]
            or int.from_bytes(value[4:8], "big") == 0
            or int.from_bytes(value[8:16], "big") == 0
            or key[7] != value[16]
            or key[8] != value[17]
            or value[16] not in (0, 1)
            or value[17] not in (0, 1)
            or any(value[18:20])
            or key[9:13] != value[24:28]
            or any(key[13:16])
            or int.from_bytes(value[20:28], "big") == 0
            or any(value[28:44])
            or int.from_bytes(value[44:48], "big") != crc32c(value[:44])
        ):
            return corrupt("C3R_SHAPE")
        return ok(32, "LAB")

    if key.startswith(b"BS") or b"BS".startswith(key):
        if (
            len(key) != 18
            or not any(key[2:])
            or len(value) != 48
            or value[:8] != bytes.fromhex("4e42533100010000")
            or int.from_bytes(value[8:16], "big") == 0
            or any(value[16:19])
            or value[19] not in (0, 1)
            or any(value[20:24])
            or not any(value[24:40])
        ):
            return corrupt("NBS1_SHAPE")
        return ok(33, "LAB")

    return {
        "status": "NINLIL_E_UNSUPPORTED",
        "kind": None,
        "row_class": "FOREIGN",
        "reason": "UNKNOWN_ROW",
    }


def classify_lab_namespace(
    records: list[tuple[bytes, bytes]],
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
) -> dict[str, Any]:
    """Classify a complete fixture snapshot from row bytes and cross-row truth."""

    keys = [key for key, _ in records]
    if len(keys) != len(set(keys)):
        return {
            "status": "CORRUPT",
            "reason": "DUPLICATE_COMPLETE_KEY",
            "row_results": [],
        }
    rows = dict(records)
    if not rows:
        return {"status": "EMPTY", "reason": None, "row_results": []}
    row_results = [
        {
            "key_sha256": sha256(key).hex(),
            **classify_lab_row(key, value, format1_bootstrap),
        }
        for key, value in sorted(rows.items())
    ]
    corrupt_rows = [
        row
        for row in row_results
        if row["status"] == "NINLIL_E_STORAGE_CORRUPT"
    ]
    if corrupt_rows:
        return {
            "status": "CORRUPT",
            "reason": corrupt_rows[0]["reason"],
            "row_results": row_results,
        }
    future_rows = [
        row for row in row_results if row["row_class"] == "FUTURE"
    ]
    if future_rows:
        return {
            "status": "UNSUPPORTED",
            "reason": future_rows[0]["reason"],
            "row_results": row_results,
        }

    preliminary_binding = decode_binding_authority(rows)
    contains_domain_semantic = any(
        row["row_class"] == "DOMAIN" for row in row_results
    )
    failures = namespace_cross_row_failures(
        rows,
        legacy_metadata_group,
        ignore_legacy_metadata_mismatch=(
            preliminary_binding is not None
            and preliminary_binding["binding_format"] == 1
            and contains_domain_semantic
        ),
    )
    if failures:
        if failures == ["FORMAT1_AUTHORITY_ABSENT"]:
            status = "UNSUPPORTED"
        elif failures == ["FORMAT1_AUTHORITY_WRONG_FORMAT2"]:
            status = "MIXED"
        else:
            status = "CORRUPT"
        return {
            "status": status,
            "reason": failures[0],
            "row_results": row_results,
        }

    binding = preliminary_binding
    if binding is None:
        return {
            "status": "UNSUPPORTED",
            "reason": "BINDING_ABSENT",
            "row_results": row_results,
        }
    format1_rows = {
        bytes.fromhex(row["key_hex"]): bytes.fromhex(row["value_hex"])
        for row in format1_bootstrap["records_unsigned_key_order"]
    }
    format2_rows = {
        bytes.fromhex(row["key_hex"]): bytes.fromhex(row["value_hex"])
        for row in format2_bootstrap["records_unsigned_key_order"]
    }
    expected_bootstrap = (
        format1_rows if binding["binding_format"] == 1 else format2_rows
    )
    bootstrap_mismatches = [
        key
        for key, value in expected_bootstrap.items()
        if rows.get(key) != value
    ]
    allowed_domain_overlay_keys = (
        {ROOT + b"\x04\x01"}
        if binding["binding_format"] == 1 and contains_domain_semantic
        else set()
    )
    if any(
        key not in allowed_domain_overlay_keys for key in bootstrap_mismatches
    ):
        return {
            "status": "CORRUPT",
            "reason": "BOOTSTRAP_INCOMPLETE_OR_MISMATCH",
            "row_results": row_results,
        }
    non_bootstrap_results = [
        result
        for (key, _), result in zip(sorted(rows.items()), row_results, strict=True)
        if key not in expected_bootstrap
    ]
    has_foreign = any(
        result["row_class"] == "FOREIGN"
        for result in non_bootstrap_results
    )
    has_distinct_lab = any(
        result["row_class"] == "LAB"
        and result["kind"] is not None
        and result["kind"] >= 20
        for result in non_bootstrap_results
    )
    has_domain_semantic = any(
        result["row_class"] == "DOMAIN"
        for result in non_bootstrap_results
    )
    if binding["binding_format"] == 1:
        status = (
            "MIXED"
            if has_foreign or has_domain_semantic
            else "EXACT_LAB"
        )
    elif binding["binding_format"] == 2:
        status = "MIXED" if has_foreign or has_distinct_lab else "EXACT_DOMAIN"
    else:
        status = "UNSUPPORTED"
    return {"status": status, "reason": None, "row_results": row_results}


def build_metadata_namespace_boundary_vectors(
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
) -> list[dict[str, Any]]:
    format1_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in format1_bootstrap["records_unsigned_key_order"]
    }
    format2_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in format2_bootstrap["records_unsigned_key_order"]
    }
    metadata_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in legacy_metadata_group["records_unsigned_key_order"]
    }
    trusted_clock = next(
        record
        for record in legacy_metadata_group["valid_clock_variants"]
        if record["name"] == "DOM_CLOCK_BASELINE_TRUSTED"
    )
    trusted_metadata_rows = dict(metadata_rows)
    trusted_metadata_rows[bytes.fromhex(trusted_clock["key_hex"])] = (
        bytes.fromhex(trusted_clock["value_hex"])
    )
    missing_key = bytes.fromhex(
        next(
            record["key_hex"]
            for record in legacy_metadata_group["records_unsigned_key_order"]
            if record["name"]
            == "DOM_WITNESS_HEAD_INDEX_RS_CAPACITY_SERVICE"
        )
    )
    cases: list[tuple[str, dict[bytes, bytes], list[str], str]] = []
    cases.append(
        (
            "FORMAT1_METADATA_ALL_OLD_ZERO_OF_16",
            dict(format1_rows),
            [],
            "EXACT_LAB",
        )
    )
    rows = dict(format1_rows)
    rows.update(metadata_rows)
    cases.append(
        (
            "FORMAT1_METADATA_ALL_NEW_16_OF_16",
            rows,
            [],
            "EXACT_LAB",
        )
    )
    rows = dict(format1_rows)
    rows.update(trusted_metadata_rows)
    cases.append(
        (
            "FORMAT1_METADATA_TRUSTED_16_OF_16",
            rows,
            [],
            "EXACT_LAB",
        )
    )
    cases.append(
        (
            "FORMAT2_METADATA_ALL_OLD_ZERO_OF_16",
            dict(format2_rows),
            [],
            "EXACT_DOMAIN",
        )
    )
    rows = dict(format2_rows)
    rows.update(metadata_rows)
    cases.append(
        (
            "FORMAT2_METADATA_ALL_NEW_16_OF_16",
            rows,
            [],
            "EXACT_DOMAIN",
        )
    )
    rows = dict(format2_rows)
    rows.update(trusted_metadata_rows)
    cases.append(
        (
            "FORMAT2_METADATA_TRUSTED_16_OF_16",
            rows,
            [],
            "EXACT_DOMAIN",
        )
    )
    rows = dict(format2_rows)
    rows.update(metadata_rows)
    rows.pop(missing_key)
    cases.append(
        (
            "FORMAT2_METADATA_PARTIAL_15_OF_16",
            rows,
            ["LEGACY_METADATA_INCOMPLETE"],
            "CORRUPT",
        )
    )
    vectors = []
    for vector_id, rows, expected_failures, expected_status in cases:
        failures = namespace_cross_row_failures(rows, legacy_metadata_group)
        assert failures == expected_failures
        computed_namespace = classify_lab_namespace(
            sorted(rows.items()),
            format1_bootstrap,
            format2_bootstrap,
            legacy_metadata_group,
        )
        assert computed_namespace["status"] == expected_status, (
            vector_id,
            computed_namespace,
        )
        vectors.append(
            {
                "id": vector_id,
                "records_unsigned_key_order": namespace_records_from_map(rows),
                "resolved_unique_key_count": len(rows),
                "resolved_namespace_sha256": namespace_row_set_sha256(rows),
                "oracle": "generator namespace_cross_row_failures",
                "computed_cross_row_failures": failures,
                "expected_namespace_status": expected_status,
                "computed_namespace_status": computed_namespace["status"],
                "namespace_oracle": "classify_lab_namespace",
                "transient": (
                    vector_id
                    == "FORMAT2_METADATA_ALL_OLD_ZERO_OF_16"
                ),
                "canonical_publish": False,
            }
        )
    return vectors


def build_kind1_kat(
    fixture_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fixture: dict[str, Any] = {
        "local_application_instance_id_hex": "11" * 16,
        "namespace": "acme",
        "service": "pump",
        "schema": "v",
        "descriptor_revision": 1,
        "descriptor_digest_hex": "22" * 32,
        "schema_major": 1,
        "schema_minor_min": 1,
        "schema_minor_max": 1,
        "family": 2,
        "direction": 2,
        "admission_authority": 1,
        "apply_contract": 1,
        "custody_policy": 1,
        "supported_evidence_mask": 8,
        "logical_payload_limit": 64,
        "target_limit": 1,
        "inflight_limit": 2,
        "attempts_per_cycle": 8,
        "admission_window_ms": 1000,
        "max_admissions_window": 10,
        "max_payload_window": 640,
        "minimum_deadline_ms": 100,
        "maximum_deadline_ms": 10000,
        "maximum_evidence_grace_ms": 1000,
        "attempt_receipt_timeout_ms": 1000,
        "retry_backoff_ms": 100,
        "application_completion_timeout_ms": 2000,
        "required_dedup_window_ms": 86400000,
        "trusted_clock_epoch_hex": "33" * 16,
        "trusted_now_ms": 123456,
        "service_capacity_limit": 16,
    }
    if fixture_overrides is not None:
        fixture.update(fixture_overrides)

    app_id = bytes.fromhex(fixture["local_application_instance_id_hex"])
    descriptor_digest = bytes.fromhex(fixture["descriptor_digest_hex"])
    service_raw = (
        app_id
        + text_id(fixture["namespace"])
        + text_id(fixture["service"])
        + u64(fixture["descriptor_revision"])
        + descriptor_digest
    )
    service_components = raw16(service_raw)
    service_identity = composite(0x10, service_components)
    quota_identity = composite(0x11, service_components)
    reservation_components = u16(1) + raw16(service_raw)
    reservation_identity = composite(0x23, reservation_components)
    service_key = domain_key(0x10, service_identity)
    quota_key = domain_key(0x11, quota_identity)
    reservation_key = domain_key(0x23, reservation_identity)
    service_kd = key_digest(service_key)
    quota_kd = key_digest(quota_key)
    reservation_kd = key_digest(reservation_key)

    operation_identity = service_kd
    witness = composite(0x7F, u16(1) + raw16(operation_identity))
    witness_header_key = domain_key(0x7F, witness)
    witness_chunk_identity = composite(0x7E, witness + u16(0))
    witness_chunk_key = domain_key(0x7E, witness_chunk_identity)

    capacity_key = ROOT + b"\x04\x01"
    old_capacity_value = runtime_capacity_value(
        1, fixture["service_capacity_limit"], 0, 0, 0, 1
    )
    new_capacity_value = runtime_capacity_value(
        1, fixture["service_capacity_limit"], 1, 0, 1, 2
    )
    capacity_kd = key_digest(capacity_key)
    head_identity = composite(0x7D, capacity_kd)
    head_key = domain_key(0x7D, head_identity)
    old_head_body = witness_index_body(
        1, capacity_key, sha256(old_capacity_value), ZERO32
    )
    old_head_value = domain_value(
        0x7D, 1, head_identity[:16], ZERO32, ZERO32, old_head_body
    )

    service_body = encode_service_body(
        service_raw, fixture, quota_kd, reservation_kd
    )
    service_value = domain_value(
        0x10, 1, service_identity[:16], witness, ZERO32, service_body
    )
    service_pvd = sha256(service_value)
    window_start = (
        fixture["trusted_now_ms"] // fixture["admission_window_ms"]
    ) * fixture["admission_window_ms"]
    quota_body = encode_quota_body(
        service_raw,
        service_kd,
        bytes.fromhex(fixture["trusted_clock_epoch_hex"]),
        window_start,
    )
    quota_value = domain_value(
        0x11, 1, service_identity[:16], witness, service_pvd, quota_body
    )
    reservation_body = encode_reservation_body(service_raw, service_kd)
    reservation_value = domain_value(
        0x23,
        1,
        service_identity[:16],
        witness,
        service_pvd,
        reservation_body,
    )
    new_head_body = witness_index_body(
        2, capacity_key, sha256(new_capacity_value), witness
    )
    new_head_value = domain_value(
        0x7D, 2, head_identity[:16], witness, ZERO32, new_head_body
    )

    entries = [
        (
            "capacity_service",
            witness_entry(
                0x0400,
                2,
                capacity_key,
                1,
                1,
                ZERO32,
                sha256(old_capacity_value),
                sha256(new_capacity_value),
            ),
        ),
        (
            "service",
            witness_entry(
                0x0610,
                1,
                service_key,
                0,
                1,
                ZERO32,
                ZERO32,
                sha256(service_value),
            ),
        ),
        (
            "service_quota",
            witness_entry(
                0x0611,
                1,
                quota_key,
                0,
                1,
                ZERO32,
                ZERO32,
                sha256(quota_value),
            ),
        ),
        (
            "service_reservation",
            witness_entry(
                0x0623,
                1,
                reservation_key,
                0,
                1,
                ZERO32,
                ZERO32,
                sha256(reservation_value),
            ),
        ),
        (
            "capacity_head_index",
            witness_entry(
                0x067D,
                2,
                head_key,
                1,
                1,
                ZERO32,
                sha256(old_head_value),
                sha256(new_head_value),
            ),
        ),
    ]
    assert [
        capacity_key,
        service_key,
        quota_key,
        reservation_key,
        head_key,
    ] == sorted(
        [capacity_key, service_key, quota_key, reservation_key, head_key]
    )

    chunk_body = (
        witness
        + u16(0)
        + u16(1)
        + u16(5)
        + u16(0)
        + b"".join(encoded for _, encoded in entries)
    )
    manifest_digest = sha256(b"NINLIL-DOMAIN-MANIFEST-V1" + chunk_body)
    canonical_digest = sha256(
        b"NINLIL-DOMAIN-OPERATION-V1"
        + u16(1)
        + raw16(operation_identity)
        + service_kd[:16]
        + manifest_digest
        + u16(0)
        + ZERO32
    )
    header_body = (
        u16(1)
        + u16(1)
        + raw16(operation_identity)
        + service_kd[:16]
        + canonical_digest
        + u16(5)
        + u16(1)
        + manifest_digest
        + u16(0)
        + u16(0)
        + ZERO32
        + ZERO32
    )
    header_value = domain_value(
        0x7F, 1, witness[:16], ZERO32, ZERO32, header_body
    )
    chunk_value = domain_value(
        0x7E, 1, witness[:16], ZERO32, ZERO32, chunk_body
    )

    records = [
        record_object("capacity_service", capacity_key, new_capacity_value),
        record_object("service", service_key, service_value),
        record_object("service_quota", quota_key, quota_value),
        record_object("service_reservation", reservation_key, reservation_value),
        record_object("capacity_head_index", head_key, new_head_value),
        record_object("witness_manifest_chunk", witness_chunk_key, chunk_value),
        record_object("witness_header", witness_header_key, header_value),
    ]
    assert [bytes.fromhex(row["key_hex"]) for row in records] == sorted(
        bytes.fromhex(row["key_hex"]) for row in records
    )
    transcript = b"".join(
        u16(row["key_length"])
        + bytes.fromhex(row["key_hex"])
        + u32(row["value_length"])
        + bytes.fromhex(row["value_hex"])
        for row in records
    )
    return {
        "fixture": fixture,
        "derived": {
            "service_key_raw_hex": service_raw.hex(),
            "service_complete_key_digest": service_kd.hex(),
            "quota_complete_key_digest": quota_kd.hex(),
            "reservation_complete_key_digest": reservation_kd.hex(),
            "capacity_complete_key_digest": capacity_kd.hex(),
            "witness_digest": witness.hex(),
            "manifest_digest": manifest_digest.hex(),
            "canonical_operation_digest": canonical_digest.hex(),
            "quota_window_start_ms": window_start,
        },
        "pre_state": {
            "capacity": record_object(
                "capacity_service_old", capacity_key, old_capacity_value
            ),
            "head_index": record_object(
                "capacity_head_index_old", head_key, old_head_value
            ),
        },
        "manifest_entries": [
            {
                "ordinal": index + 1,
                "name": name,
                "encoded_length": len(encoded),
                "encoded_hex": encoded.hex(),
                "encoded_sha256": sha256(encoded).hex(),
            }
            for index, (name, encoded) in enumerate(entries)
        ],
        "post_records_full_stage_order": records,
        "aggregate_preimage": (
            "ASCII(NINLIL-DOMAIN-KIND1-KAT-V1) || "
            "each stage row(key_length:u16||key||value_length:u32||value)"
        ),
        "aggregate_sha256": sha256(
            b"NINLIL-DOMAIN-KIND1-KAT-V1" + transcript
        ).hex(),
    }


def kind1_row_frame(record: dict[str, Any]) -> bytes:
    key = bytes.fromhex(record["key_hex"])
    value = bytes.fromhex(record["value_hex"])
    assert len(key) == record["key_length"]
    assert len(value) == record["value_length"]
    return u16(len(key)) + key + u32(len(value)) + value


def encode_kind1_fixture(
    entries: list[bytes],
    pre_records: list[dict[str, Any]],
    post_records: list[dict[str, Any]],
) -> bytes:
    artifact = KIND1_FIXTURE_MAGIC + u16(len(entries))
    for entry in entries:
        artifact += u16(len(entry)) + entry
    artifact += u16(len(pre_records))
    artifact += b"".join(kind1_row_frame(row) for row in pre_records)
    artifact += u16(len(post_records))
    artifact += b"".join(kind1_row_frame(row) for row in post_records)
    return artifact


def parse_kind1_fixture(
    artifact: bytes,
) -> tuple[list[bytes], list[tuple[bytes, bytes]], list[tuple[bytes, bytes]]]:
    cursor = 0

    def take(length: int) -> bytes:
        nonlocal cursor
        if length < 0 or len(artifact) - cursor < length:
            raise ValueError("fixture truncated")
        result = artifact[cursor : cursor + length]
        cursor += length
        return result

    def take_u16() -> int:
        return int.from_bytes(take(2), "big")

    def take_u32() -> int:
        return int.from_bytes(take(4), "big")

    if take(len(KIND1_FIXTURE_MAGIC)) != KIND1_FIXTURE_MAGIC:
        raise ValueError("fixture magic")
    entries = [take(take_u16()) for _ in range(take_u16())]

    def take_records() -> list[tuple[bytes, bytes]]:
        rows = []
        for _ in range(take_u16()):
            key = take(take_u16())
            value = take(take_u32())
            rows.append((key, value))
        return rows

    pre_records = take_records()
    post_records = take_records()
    if cursor != len(artifact):
        raise ValueError("fixture trailing bytes")
    return entries, pre_records, post_records


def decode_witness_entry(entry: bytes) -> dict[str, Any]:
    if len(entry) < 108:
        raise ValueError("witness entry short")
    role = int.from_bytes(entry[0:2], "big")
    action = entry[2]
    if entry[3] != 0:
        raise ValueError("witness entry action reserved")
    key_length = int.from_bytes(entry[4:6], "big")
    if int.from_bytes(entry[6:8], "big") != 0:
        raise ValueError("witness entry key reserved")
    if len(entry) != 108 + key_length:
        raise ValueError("witness entry length")
    cursor = 8
    key = entry[cursor : cursor + key_length]
    cursor += key_length
    old_present = entry[cursor]
    new_present = entry[cursor + 1]
    if int.from_bytes(entry[cursor + 2 : cursor + 4], "big") != 0:
        raise ValueError("witness entry state reserved")
    cursor += 4
    prior_head = entry[cursor : cursor + 32]
    old_digest = entry[cursor + 32 : cursor + 64]
    new_digest = entry[cursor + 64 : cursor + 96]
    return {
        "role": role,
        "action": action,
        "key": key,
        "old_present": old_present,
        "new_present": new_present,
        "prior_head": prior_head,
        "old_digest": old_digest,
        "new_digest": new_digest,
    }


def decode_domain_record_value(value: bytes) -> dict[str, Any]:
    if len(value) < 16 or value[:4] != b"NLR1":
        raise ValueError("domain envelope")
    record_type = int.from_bytes(value[4:6], "big")
    record_version = int.from_bytes(value[6:8], "big")
    payload_length = int.from_bytes(value[8:12], "big")
    if record_type != 6 or record_version != 1:
        raise ValueError("domain envelope type/version")
    if len(value) != 12 + payload_length + 4:
        raise ValueError("domain envelope length")
    if int.from_bytes(value[-4:], "big") != crc32c(value[:-4]):
        raise ValueError("domain envelope crc")
    payload = value[12:-4]
    if len(payload) < 96:
        raise ValueError("domain common short")
    storage_schema = int.from_bytes(payload[0:2], "big")
    subtype = payload[2]
    flags = payload[3]
    revision = int.from_bytes(payload[4:12], "big")
    primary_id = payload[12:28]
    head = payload[28:60]
    pvd = payload[60:92]
    body_length = int.from_bytes(payload[92:96], "big")
    body = payload[96:]
    if storage_schema != 1 or flags != 0 or len(body) != body_length:
        raise ValueError("domain common")
    return {
        "subtype": subtype,
        "revision": revision,
        "primary_id": primary_id,
        "head": head,
        "pvd": pvd,
        "body": body,
    }


def parse_raw16_at(value: bytes, cursor: int) -> tuple[bytes, int]:
    if len(value) - cursor < 2:
        raise ValueError("raw16 length")
    length = int.from_bytes(value[cursor : cursor + 2], "big")
    cursor += 2
    if len(value) - cursor < length:
        raise ValueError("raw16 contents")
    return value[cursor : cursor + length], cursor + length


def parse_text_id_at(value: bytes, cursor: int) -> tuple[bytes, int]:
    if len(value) - cursor < 1:
        raise ValueError("text id length")
    length = value[cursor]
    cursor += 1
    if length == 0 or length > 63 or len(value) - cursor < length:
        raise ValueError("text id length")
    text = value[cursor : cursor + length]
    cursor += length
    try:
        decoded = text.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("text id utf8") from error
    if decoded.encode("utf-8") != text:
        raise ValueError("text id canonical")
    return text, cursor


def decode_kind1_service_semantics(body: bytes) -> dict[str, Any]:
    service_raw, cursor = parse_raw16_at(body, 0)
    if len(body) - cursor < 8 + 32 + 16:
        raise ValueError("service descriptor prefix")
    descriptor_revision = int.from_bytes(body[cursor : cursor + 8], "big")
    cursor += 8
    descriptor_digest = body[cursor : cursor + 32]
    cursor += 32
    application_id = body[cursor : cursor + 16]
    cursor += 16
    namespace, cursor = parse_text_id_at(body, cursor)
    service, cursor = parse_text_id_at(body, cursor)
    schema, cursor = parse_text_id_at(body, cursor)
    if len(body) - cursor != 6 + (13 * 4) + (7 * 8) + 64:
        raise ValueError("service descriptor length")
    schema_major = int.from_bytes(body[cursor : cursor + 2], "big")
    schema_minor_min = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
    schema_minor_max = int.from_bytes(body[cursor + 4 : cursor + 6], "big")
    cursor += 6
    u32_fields = [
        int.from_bytes(body[cursor + offset : cursor + offset + 4], "big")
        for offset in range(0, 13 * 4, 4)
    ]
    cursor += 13 * 4
    u64_fields = [
        int.from_bytes(body[cursor + offset : cursor + offset + 8], "big")
        for offset in range(0, 7 * 8, 8)
    ]
    cursor += 7 * 8
    quota_key_digest = body[cursor : cursor + 32]
    reservation_key_digest = body[cursor + 32 : cursor + 64]
    cursor += 64
    if cursor != len(body):
        raise ValueError("service descriptor trailing")
    return {
        "service_raw": service_raw,
        "descriptor_revision": descriptor_revision,
        "descriptor_digest": descriptor_digest,
        "application_id": application_id,
        "namespace": namespace,
        "service": service,
        "schema": schema,
        "schema_major": schema_major,
        "schema_minor_min": schema_minor_min,
        "schema_minor_max": schema_minor_max,
        "admission_window_ms": u32_fields[10],
        "u32_fields": u32_fields,
        "u64_fields": u64_fields,
        "quota_key_digest": quota_key_digest,
        "reservation_key_digest": reservation_key_digest,
    }


def decode_kind1_quota_semantics(body: bytes) -> dict[str, Any]:
    service_raw, cursor = parse_raw16_at(body, 0)
    if len(body) - cursor != 84:
        raise ValueError("quota body length")
    result = {
        "service_raw": service_raw,
        "service_key_digest": body[cursor : cursor + 32],
        "clock_epoch": body[cursor + 32 : cursor + 48],
        "window_start_ms": int.from_bytes(
            body[cursor + 48 : cursor + 56], "big"
        ),
        "admissions": int.from_bytes(
            body[cursor + 56 : cursor + 60], "big"
        ),
        "payload_bytes": int.from_bytes(
            body[cursor + 60 : cursor + 68], "big"
        ),
        "active_transactions": int.from_bytes(
            body[cursor + 68 : cursor + 72], "big"
        ),
        "active_spool_count": int.from_bytes(
            body[cursor + 72 : cursor + 76], "big"
        ),
        "active_spool_bytes": int.from_bytes(
            body[cursor + 76 : cursor + 84], "big"
        ),
    }
    return result


def decode_kind1_reservation_semantics(body: bytes) -> dict[str, Any]:
    if len(body) < 4:
        raise ValueError("reservation body prefix")
    owner_kind = int.from_bytes(body[0:2], "big")
    owner_reserved = int.from_bytes(body[2:4], "big")
    owner_raw, cursor = parse_raw16_at(body, 4)
    if len(body) - cursor != 32 + 176 + 20:
        raise ValueError("reservation body length")
    primary_key_digest = body[cursor : cursor + 32]
    cursor += 32
    resources = []
    for _ in range(11):
        resources.append(
            (
                int.from_bytes(body[cursor : cursor + 8], "big"),
                int.from_bytes(body[cursor + 8 : cursor + 16], "big"),
            )
        )
        cursor += 16
    service_inflight = int.from_bytes(body[cursor : cursor + 4], "big")
    grant_count = int.from_bytes(body[cursor + 4 : cursor + 8], "big")
    grant_bytes = int.from_bytes(body[cursor + 8 : cursor + 16], "big")
    released_mask = int.from_bytes(body[cursor + 16 : cursor + 20], "big")
    cursor += 20
    if cursor != len(body):
        raise ValueError("reservation body trailing")
    return {
        "owner_kind": owner_kind,
        "owner_reserved": owner_reserved,
        "owner_raw": owner_raw,
        "primary_key_digest": primary_key_digest,
        "resources": resources,
        "service_inflight": service_inflight,
        "grant_count": grant_count,
        "grant_bytes": grant_bytes,
        "released_mask": released_mask,
    }


def decode_runtime_capacity_semantics(value: bytes) -> dict[str, int]:
    payload = decode_nlr1_payload(value, 4)
    if len(payload) != 52:
        raise ValueError("capacity payload length")
    return {
        "kind": int.from_bytes(payload[0:4], "big"),
        "limit": int.from_bytes(payload[4:12], "big"),
        "used": int.from_bytes(payload[12:20], "big"),
        "reserved": int.from_bytes(payload[20:28], "big"),
        "high_water": int.from_bytes(payload[28:36], "big"),
        "epoch": int.from_bytes(payload[36:44], "big"),
        "blocked": int.from_bytes(payload[44:48], "big"),
        "exhausted": int.from_bytes(payload[48:52], "big"),
    }


def decode_kind1_head_semantics(value: bytes) -> dict[str, Any]:
    decoded = decode_domain_record_value(value)
    body = decoded["body"]
    if decoded["subtype"] != 0x7D or len(body) != 114:
        raise ValueError("head index shape")
    member_length = int.from_bytes(body[36:38], "big")
    if member_length != 10 or int.from_bytes(body[38:40], "big") != 0:
        raise ValueError("head index member length")
    return {
        **decoded,
        "state": int.from_bytes(body[0:2], "big"),
        "state_reserved": int.from_bytes(body[2:4], "big"),
        "member_key_digest": body[4:36],
        "member_key": body[40:50],
        "member_value_digest": body[50:82],
        "member_head": body[82:114],
    }


def independent_kind1_group_semantic_reason(
    pre_rows: list[tuple[bytes, bytes]],
    post_rows: list[tuple[bytes, bytes]],
    positive_kat: dict[str, Any],
) -> str | None:
    """Validate kind-1 cross-row truth from fixture bytes plus pinned clock input."""

    try:
        pre = kind1_rows_to_map(pre_rows)
        post = kind1_rows_to_map(post_rows)
        capacity_key = ROOT + b"\x04\x01"
        service_rows = [
            (key, value)
            for key, value in post.items()
            if domain_key_subtype(key) == 0x10
        ]
        quota_rows = [
            (key, value)
            for key, value in post.items()
            if domain_key_subtype(key) == 0x11
        ]
        reservation_rows = [
            (key, value)
            for key, value in post.items()
            if domain_key_subtype(key) == 0x23
        ]
        head_rows = [
            (key, value)
            for key, value in post.items()
            if domain_key_subtype(key) == 0x7D
        ]
        if not (
            len(service_rows)
            == len(quota_rows)
            == len(reservation_rows)
            == len(head_rows)
            == 1
        ):
            return "KIND1_GROUP_CARDINALITY"
        service_key, service_value = service_rows[0]
        quota_key, quota_value = quota_rows[0]
        reservation_key, reservation_value = reservation_rows[0]
        head_key, head_value = head_rows[0]
        if capacity_key not in pre or capacity_key not in post or head_key not in pre:
            return "KIND1_GROUP_PRE_POST_SET"

        service_record = decode_domain_record_value(service_value)
        quota_record = decode_domain_record_value(quota_value)
        reservation_record = decode_domain_record_value(reservation_value)
        service = decode_kind1_service_semantics(service_record["body"])
        quota = decode_kind1_quota_semantics(quota_record["body"])
        reservation = decode_kind1_reservation_semantics(
            reservation_record["body"]
        )
        old_capacity = decode_runtime_capacity_semantics(pre[capacity_key])
        new_capacity = decode_runtime_capacity_semantics(post[capacity_key])
        old_head = decode_kind1_head_semantics(pre[head_key])
        new_head = decode_kind1_head_semantics(head_value)
    except (KeyError, ValueError):
        return "KIND1_GROUP_DECODE"

    service_raw = service["service_raw"]
    service_components = raw16(service_raw)
    expected_service_key = domain_key(
        0x10, composite(0x10, service_components)
    )
    expected_quota_key = domain_key(0x11, composite(0x11, service_components))
    expected_reservation_key = domain_key(
        0x23, composite(0x23, u16(1) + service_components)
    )
    if (
        service_key != expected_service_key
        or quota_key != expected_quota_key
        or reservation_key != expected_reservation_key
    ):
        return "KIND1_SERVICE_KEY_RELATION"
    service_key_digest = key_digest(service_key)
    expected_witness = composite(
        0x7F, u16(1) + raw16(service_key_digest)
    )
    if (
        service_record["head"] != expected_witness
        or quota_record["head"] != expected_witness
        or reservation_record["head"] != expected_witness
        or new_head["head"] != expected_witness
    ):
        return "KIND1_COMMON_WITNESS_RELATION"
    if service_record["pvd"] != ZERO32:
        return "KIND1_SERVICE_PRIMARY_VALUE_DIGEST"
    if quota_record["pvd"] != sha256(service_value):
        return "KIND1_QUOTA_PRIMARY_VALUE_DIGEST"
    if reservation_record["pvd"] != sha256(service_value):
        return "KIND1_RESERVATION_PRIMARY_VALUE_DIGEST"
    if (
        service["quota_key_digest"] != key_digest(quota_key)
        or service["reservation_key_digest"] != key_digest(reservation_key)
    ):
        return "KIND1_SERVICE_SECONDARY_KEY_DIGEST_RELATION"

    expected_clock_epoch = bytes.fromhex(
        positive_kat["fixture"]["trusted_clock_epoch_hex"]
    )
    admission_window_ms = service["admission_window_ms"]
    trusted_now_ms = positive_kat["fixture"]["trusted_now_ms"]
    if admission_window_ms == 0:
        return "KIND1_QUOTA_WINDOW"
    expected_window_start = (
        trusted_now_ms // admission_window_ms
    ) * admission_window_ms
    if (
        quota["service_raw"] != service_raw
        or quota["service_key_digest"] != service_key_digest
        or quota["clock_epoch"] != expected_clock_epoch
        or quota["window_start_ms"] != expected_window_start
    ):
        return "KIND1_QUOTA_WINDOW"
    if any(
        quota[field] != 0
        for field in (
            "admissions",
            "payload_bytes",
            "active_transactions",
            "active_spool_count",
            "active_spool_bytes",
        )
    ):
        return "KIND1_QUOTA_INITIAL_COUNTER"

    expected_resources = [(1, 0)] + [(0, 0)] * 10
    if (
        reservation["owner_kind"] != 1
        or reservation["owner_reserved"] != 0
        or reservation["owner_raw"] != service_raw
        or reservation["primary_key_digest"] != service_key_digest
    ):
        return "KIND1_RESERVATION_OWNER_RELATION"
    if (
        reservation["resources"] != expected_resources
        or reservation["service_inflight"] != 0
        or reservation["grant_count"] != 0
        or reservation["grant_bytes"] != 0
        or reservation["released_mask"] != 0
    ):
        return "KIND1_RESERVATION_RESOURCE_VECTOR"

    if (
        old_capacity
        != {
            "kind": 1,
            "limit": old_capacity["limit"],
            "used": 0,
            "reserved": 0,
            "high_water": 0,
            "epoch": 1,
            "blocked": 0,
            "exhausted": 0,
        }
        or new_capacity
        != {
            "kind": 1,
            "limit": old_capacity["limit"],
            "used": 1,
            "reserved": 0,
            "high_water": 1,
            "epoch": 2,
            "blocked": 0,
            "exhausted": 0,
        }
    ):
        return "KIND1_CAPACITY_POST_INCREMENT"

    capacity_digest = key_digest(capacity_key)
    expected_head_key = domain_key(
        0x7D, composite(0x7D, capacity_digest)
    )
    if head_key != expected_head_key:
        return "KIND1_HEAD_INDEX_KEY_RELATION"
    if (
        old_head["state"] != 1
        or old_head["revision"] != 1
        or old_head["head"] != ZERO32
        or old_head["pvd"] != ZERO32
        or old_head["member_key"] != capacity_key
        or old_head["member_key_digest"] != capacity_digest
        or old_head["member_value_digest"] != sha256(pre[capacity_key])
        or old_head["member_head"] != ZERO32
        or new_head["state"] != 2
        or new_head["revision"] != 2
        or new_head["pvd"] != ZERO32
        or new_head["member_key"] != capacity_key
        or new_head["member_key_digest"] != capacity_digest
        or new_head["member_value_digest"] != sha256(post[capacity_key])
        or new_head["member_head"] != expected_witness
    ):
        return "KIND1_HEAD_INDEX_RELATION"
    return None


def domain_key_subtype(key: bytes) -> int | None:
    if (
        len(key) == 45
        and key[:8] == ROOT
        and key[8] == 6
        and key[10:13] == b"\x01\x05\x20"
    ):
        return key[9]
    return None


def independent_kind1_d1_row_local_reason(
    key: bytes,
    value: bytes,
) -> str | None:
    """Validate every semantic row used by the kind-1 fixture from bytes."""

    def nonzero(raw: bytes) -> bool:
        return any(raw)

    def parse_raw16(
        data: bytes,
        offset: int,
        maximum: int = 255,
    ) -> tuple[bytes, int]:
        if len(data) - offset < 2:
            raise ValueError("RAW16_PREFIX")
        length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        if length == 0 or length > maximum or len(data) - offset < length:
            raise ValueError("RAW16_LENGTH")
        return data[offset : offset + length], offset + length

    def parse_text_id(
        data: bytes,
        offset: int,
        *,
        namespace_grammar: bool,
    ) -> tuple[bytes, bytes, int]:
        if offset >= len(data):
            raise ValueError("TEXT_ID_PREFIX")
        length = data[offset]
        end = offset + 1 + length
        if length == 0 or length > 63 or end > len(data):
            raise ValueError("TEXT_ID_LENGTH")
        raw = data[offset + 1 : end]
        first = raw[0]
        if not (
            ord("a") <= first <= ord("z")
            or ord("0") <= first <= ord("9")
        ):
            raise ValueError("TEXT_ID_GRAMMAR")
        for byte in raw[1:]:
            if (
                ord("a") <= byte <= ord("z")
                or ord("0") <= byte <= ord("9")
                or byte in {ord("."), ord("-")}
                or (not namespace_grammar and byte == ord("_"))
            ):
                continue
            raise ValueError("TEXT_ID_GRAMMAR")
        return raw, data[offset:end], end

    def parse_service_raw(raw: bytes) -> None:
        if len(raw) < 60 or not nonzero(raw[:16]):
            raise ValueError("SERVICE_RAW_SHAPE")
        cursor = 16
        _, _, cursor = parse_text_id(
            raw,
            cursor,
            namespace_grammar=True,
        )
        _, _, cursor = parse_text_id(
            raw,
            cursor,
            namespace_grammar=False,
        )
        if len(raw) - cursor != 40:
            raise ValueError("SERVICE_RAW_LENGTH")
        if int.from_bytes(raw[cursor : cursor + 8], "big") == 0:
            raise ValueError("SERVICE_RAW_REVISION")
        if not nonzero(raw[cursor + 8 : cursor + 40]):
            raise ValueError("SERVICE_RAW_DIGEST")

    def composite_identity(subtype: int, components: bytes) -> bytes:
        return sha256(
            b"NINLIL-DOMAIN-KEY-V1" + bytes([subtype]) + components
        )

    def complete_domain_key(subtype: int, identity: bytes) -> bytes:
        return ROOT + bytes([6, subtype, 1, 5, 32]) + identity

    def complete_key_digest(key_bytes: bytes) -> bytes:
        return sha256(
            b"NINLIL-DOMAIN-ENCODED-KEY-V1" + key_bytes
        )

    def parse_nlr1(expected_type: int) -> bytes:
        if len(value) < 16 or value[:4] != b"NLR1":
            raise ValueError("NLR1_MAGIC")
        if int.from_bytes(value[4:6], "big") != expected_type:
            raise ValueError("NLR1_TYPE")
        if int.from_bytes(value[6:8], "big") != 1:
            raise ValueError("NLR1_VERSION")
        payload_length = int.from_bytes(value[8:12], "big")
        if len(value) != 12 + payload_length + 4:
            raise ValueError("NLR1_LENGTH")
        if int.from_bytes(value[-4:], "big") != crc32c(value[:-4]):
            raise ValueError("NLR1_CRC")
        return value[12:-4]

    try:
        if (
            len(key) == 10
            and key[:8] == ROOT
            and key[8] == 4
        ):
            resource_kind = key[9]
            if not 1 <= resource_kind <= 11:
                return "CAPACITY_KEY_KIND"
            payload = parse_nlr1(4)
            if len(payload) != 52:
                return "CAPACITY_BODY_LENGTH"
            stored_kind = int.from_bytes(payload[0:4], "big")
            limit = int.from_bytes(payload[4:12], "big")
            used = int.from_bytes(payload[12:20], "big")
            reserved = int.from_bytes(payload[20:28], "big")
            high_water = int.from_bytes(payload[28:36], "big")
            epoch = int.from_bytes(payload[36:44], "big")
            blocked = int.from_bytes(payload[44:48], "big")
            exhausted = int.from_bytes(payload[48:52], "big")
            if stored_kind != resource_kind:
                return "CAPACITY_KEY_BODY_KIND"
            if blocked not in {0, 1} or exhausted not in {0, 1}:
                return "CAPACITY_BOOLEAN"
            if epoch == 0 or used + reserved > high_water or high_water > limit:
                return "CAPACITY_ARITHMETIC"
            if exhausted == 1 and (
                epoch != (1 << 64) - 1 or blocked != 0
            ):
                return "CAPACITY_EXHAUSTED"
            return None

        if (
            len(key) != 45
            or key[:8] != ROOT
            or key[8] != 6
            or key[10:13] != b"\x01\x05\x20"
        ):
            return "DOMAIN_KEY_GRAMMAR"
        subtype = key[9]
        identity = key[13:45]
        if subtype not in {0x10, 0x11, 0x23, 0x7D}:
            return "DOMAIN_SUBTYPE"
        payload = parse_nlr1(6)
        if len(payload) < 96:
            return "DOMAIN_COMMON_LENGTH"
        domain_format = int.from_bytes(payload[0:2], "big")
        value_subtype = payload[2]
        flags = payload[3]
        revision = int.from_bytes(payload[4:12], "big")
        primary_id = payload[12:28]
        head = payload[28:60]
        pvd = payload[60:92]
        body_length = int.from_bytes(payload[92:96], "big")
        body = payload[96:]
        if (
            domain_format != 1
            or value_subtype != subtype
            or flags != 0
            or revision == 0
            or body_length != len(body)
        ):
            return "DOMAIN_COMMON"

        if subtype == 0x10:
            if len(body) == 0 or len(body) > 768:
                return "SERVICE_BODY_LENGTH"
            cursor = 0
            service_raw, cursor = parse_raw16(body, cursor)
            if len(body) - cursor < 56:
                return "SERVICE_FIXED_PREFIX"
            descriptor_revision = int.from_bytes(
                body[cursor : cursor + 8],
                "big",
            )
            cursor += 8
            descriptor_digest = body[cursor : cursor + 32]
            cursor += 32
            application_id = body[cursor : cursor + 16]
            cursor += 16
            _, namespace_encoded, cursor = parse_text_id(
                body,
                cursor,
                namespace_grammar=True,
            )
            _, service_encoded, cursor = parse_text_id(
                body,
                cursor,
                namespace_grammar=False,
            )
            _, _, cursor = parse_text_id(
                body,
                cursor,
                namespace_grammar=False,
            )
            if len(body) - cursor != 6 + 52 + 56 + 64:
                return "SERVICE_BODY_TRAILING"
            schema_major = int.from_bytes(body[cursor : cursor + 2], "big")
            minor_min = int.from_bytes(body[cursor + 2 : cursor + 4], "big")
            minor_max = int.from_bytes(body[cursor + 4 : cursor + 6], "big")
            cursor += 6
            scalars = [
                int.from_bytes(body[cursor + i : cursor + i + 4], "big")
                for i in range(0, 52, 4)
            ]
            cursor += 52
            times = [
                int.from_bytes(body[cursor + i : cursor + i + 8], "big")
                for i in range(0, 56, 8)
            ]
            cursor += 56
            quota_digest = body[cursor : cursor + 32]
            reservation_digest = body[cursor + 32 : cursor + 64]
            cursor += 64
            if cursor != len(body):
                return "SERVICE_BODY_TRAILING"
            (
                family,
                direction,
                authority,
                apply_contract,
                custody,
                evidence_mask,
                logical_payload_limit,
                target_limit,
                inflight_limit,
                attempts_per_cycle,
                admission_window_ms,
                max_admissions_window,
                max_payload_window,
            ) = scalars
            (
                minimum_deadline_ms,
                maximum_deadline_ms,
                maximum_evidence_grace_ms,
                attempt_receipt_timeout_ms,
                retry_backoff_ms,
                application_completion_timeout_ms,
                required_dedup_window_ms,
            ) = times
            expected_raw = (
                application_id
                + namespace_encoded
                + service_encoded
                + descriptor_revision.to_bytes(8, "big")
                + descriptor_digest
            )
            if (
                schema_major > 0xFFFF
                or service_raw != expected_raw
                or descriptor_revision == 0
                or not nonzero(descriptor_digest)
                or not nonzero(application_id)
                or minor_min > minor_max
                or family not in {1, 2}
                or custody != 1
                or evidence_mask == 0
                or evidence_mask & ~0x1E
                or logical_payload_limit == 0
                or target_limit != 1
                or inflight_limit == 0
                or not 1 <= attempts_per_cycle <= 8
                or not 1 <= admission_window_ms <= 600000
                or max_admissions_window == 0
                or max_payload_window < logical_payload_limit
                or not 1 <= attempt_receipt_timeout_ms <= 600000
                or not 1 <= retry_backoff_ms <= 60000
                or not 1 <= application_completion_timeout_ms <= 60000
                or required_dedup_window_ms == 0
            ):
                return "SERVICE_DESCRIPTOR"
            if family == 1:
                if (
                    attempts_per_cycle != 8
                    or direction != 1
                    or authority != 2
                    or apply_contract != 2
                    or minimum_deadline_ms != (1 << 64) - 1
                    or maximum_deadline_ms != (1 << 64) - 1
                    or maximum_evidence_grace_ms != 0
                ):
                    return "SERVICE_EVENT_CONTRACT"
            elif (
                direction != 2
                or authority != 1
                or apply_contract not in {1, 2}
                or minimum_deadline_ms < 1
                or minimum_deadline_ms > maximum_deadline_ms
                or maximum_deadline_ms >= (1 << 64) - 1
            ):
                return "SERVICE_DESIRED_CONTRACT"
            raw16_encoded = len(service_raw).to_bytes(2, "big") + service_raw
            expected_identity = composite_identity(0x10, raw16_encoded)
            quota_identity = composite_identity(0x11, raw16_encoded)
            reservation_components = b"\x00\x01" + raw16_encoded
            reservation_identity = composite_identity(
                0x23,
                reservation_components,
            )
            if (
                identity != expected_identity
                or primary_id != expected_identity[:16]
                or revision != 1
                or not nonzero(head)
                or nonzero(pvd)
                or quota_digest
                != complete_key_digest(
                    complete_domain_key(0x11, quota_identity)
                )
                or reservation_digest
                != complete_key_digest(
                    complete_domain_key(0x23, reservation_identity)
                )
            ):
                return "SERVICE_KEY_HEADER"
            return None

        if subtype == 0x11:
            if len(body) == 0 or len(body) > 512:
                return "QUOTA_BODY_LENGTH"
            service_raw, cursor = parse_raw16(body, 0)
            parse_service_raw(service_raw)
            if len(body) - cursor != 84:
                return "QUOTA_BODY_TRAILING"
            service_digest = body[cursor : cursor + 32]
            clock_epoch = body[cursor + 32 : cursor + 48]
            raw16_encoded = len(service_raw).to_bytes(2, "big") + service_raw
            service_identity = composite_identity(0x10, raw16_encoded)
            quota_identity = composite_identity(0x11, raw16_encoded)
            if (
                not nonzero(clock_epoch)
                or service_digest
                != complete_key_digest(
                    complete_domain_key(0x10, service_identity)
                )
                or identity != quota_identity
                or primary_id != service_identity[:16]
                or not nonzero(head)
                or not nonzero(pvd)
            ):
                return "QUOTA_KEY_HEADER"
            return None

        if subtype == 0x23:
            if len(body) < 6 or len(body) > 512:
                return "RESERVATION_BODY_LENGTH"
            owner_kind = int.from_bytes(body[0:2], "big")
            reserved0 = int.from_bytes(body[2:4], "big")
            owner_raw, cursor = parse_raw16(body, 4)
            if owner_kind != 1 or reserved0 != 0:
                return "RESERVATION_OWNER"
            parse_service_raw(owner_raw)
            if len(body) - cursor != 32 + 176 + 20:
                return "RESERVATION_BODY_TRAILING"
            primary_key_digest = body[cursor : cursor + 32]
            cursor += 32
            resources = []
            for _ in range(11):
                used = int.from_bytes(body[cursor : cursor + 8], "big")
                reserved = int.from_bytes(
                    body[cursor + 8 : cursor + 16],
                    "big",
                )
                resources.append((used, reserved))
                cursor += 16
            cursor += 16
            released_mask = int.from_bytes(body[cursor : cursor + 4], "big")
            cursor += 4
            if cursor != len(body) or released_mask & ~0x7FF:
                return "RESERVATION_RESOURCE_SHAPE"
            for index, (used, reserved) in enumerate(resources):
                if (
                    released_mask & (1 << index)
                    and (used != 0 or reserved != 0)
                ):
                    return "RESERVATION_RELEASED_RESOURCE"
            raw16_encoded = len(owner_raw).to_bytes(2, "big") + owner_raw
            service_identity = composite_identity(0x10, raw16_encoded)
            reservation_components = b"\x00\x01" + raw16_encoded
            reservation_identity = composite_identity(
                0x23,
                reservation_components,
            )
            if (
                primary_key_digest
                != complete_key_digest(
                    complete_domain_key(0x10, service_identity)
                )
                or identity != reservation_identity
                or primary_id != service_identity[:16]
                or not nonzero(head)
                or not nonzero(pvd)
            ):
                return "RESERVATION_KEY_HEADER"
            return None

        if len(body) != 114:
            return "HEAD_INDEX_BODY_LENGTH"
        state = int.from_bytes(body[0:2], "big")
        reserved0 = int.from_bytes(body[2:4], "big")
        member_key_digest = body[4:36]
        member_key_length = int.from_bytes(body[36:38], "big")
        reserved1 = int.from_bytes(body[38:40], "big")
        member_key = body[40:50]
        member_value_digest = body[50:82]
        member_head = body[82:114]
        if (
            state not in {1, 2}
            or reserved0 != 0
            or reserved1 != 0
            or member_key_length != 10
            or member_key[:8] != ROOT
            or member_key[8] not in {3, 4}
            or (
                member_key[8] == 3
                and not 1 <= member_key[9] <= 4
            )
            or (
                member_key[8] == 4
                and not 1 <= member_key[9] <= 11
            )
            or member_key_digest != complete_key_digest(member_key)
            or not nonzero(member_value_digest)
        ):
            return "HEAD_INDEX_BODY"
        expected_identity = composite_identity(0x7D, member_key_digest)
        if (
            identity != expected_identity
            or primary_id != expected_identity[:16]
            or nonzero(pvd)
        ):
            return "HEAD_INDEX_KEY_HEADER"
        if state == 1:
            if revision != 1 or nonzero(head) or nonzero(member_head):
                return "HEAD_INDEX_BASELINE"
        elif (
            revision < 2
            or not nonzero(head)
            or head != member_head
        ):
            return "HEAD_INDEX_WITNESSED"
        return None
    except ValueError as error:
        return str(error)


def kind1_rows_to_map(
    rows: list[tuple[bytes, bytes]],
) -> dict[bytes, bytes]:
    result: dict[bytes, bytes] = {}
    for key, value in rows:
        if key in result:
            raise ValueError("duplicate fixture row")
        result[key] = value
    return result


def kind1_semantic_row_local_checks(
    pre_rows: list[tuple[bytes, bytes]],
    post_rows: list[tuple[bytes, bytes]],
) -> list[dict[str, Any]]:
    checks = []
    for phase, rows in (("pre", pre_rows), ("post", post_rows)):
        for key, value in rows:
            if (
                phase == "post"
                and domain_key_subtype(key) in {0x7E, 0x7F}
            ):
                continue
            reason = independent_kind1_d1_row_local_reason(key, value)
            checks.append(
                {
                    "phase": phase,
                    "key_sha256": sha256(key).hex(),
                    "value_sha256": sha256(value).hex(),
                    "status": (
                        "NINLIL_OK"
                        if reason is None
                        else "NINLIL_E_STORAGE_CORRUPT"
                    ),
                    "reason": reason,
                }
            )
    return checks


def classify_kind1_fixture(
    artifact: bytes,
    positive_kat: dict[str, Any],
) -> dict[str, Any]:
    """Reparse exact entry/row bytes and classify the kind-1 contract."""

    def rejected(reason: str) -> dict[str, Any]:
        return {
            "status": "NINLIL_E_STORAGE_CORRUPT",
            "rejection": reason,
        }

    try:
        entries_raw, pre_rows, post_rows = parse_kind1_fixture(artifact)
        entries = [decode_witness_entry(entry) for entry in entries_raw]
        pre_map = kind1_rows_to_map(pre_rows)
        post_map = kind1_rows_to_map(post_rows)
        positive_entries = [
            decode_witness_entry(bytes.fromhex(entry["encoded_hex"]))
            for entry in positive_kat["manifest_entries"]
        ]
        positive_pre = {
            bytes.fromhex(record["key_hex"]): bytes.fromhex(
                record["value_hex"]
            )
            for record in positive_kat["pre_state"].values()
        }
    except (KeyError, ValueError):
        return rejected("KIND1_FIXTURE_FRAMING")

    header_rows = [
        (key, value)
        for key, value in post_rows
        if domain_key_subtype(key) == 0x7F
    ]
    chunk_rows = [
        (key, value)
        for key, value in post_rows
        if domain_key_subtype(key) == 0x7E
    ]
    if len(header_rows) != 1 or len(chunk_rows) != 1:
        return rejected("KIND1_WITNESS_RECORD_COUNT")
    header_key, header_value = header_rows[0]
    chunk_key, chunk_value = chunk_rows[0]
    try:
        header = decode_domain_record_value(header_value)
        chunk = decode_domain_record_value(chunk_value)
    except ValueError:
        return rejected("KIND1_WITNESS_RECORD_CODEC")
    header_body = header["body"]
    chunk_body = chunk["body"]
    if len(header_body) != 190 or len(chunk_body) < 40:
        return rejected("KIND1_WITNESS_BODY_LENGTH")
    if (
        int.from_bytes(header_body[0:2], "big") != 1
        or int.from_bytes(header_body[2:4], "big") != 1
        or int.from_bytes(header_body[4:6], "big") != 32
    ):
        return rejected("KIND1_WITNESS_HEADER_FIXED")
    operation_identity = header_body[6:38]
    subject = header_body[38:54]
    canonical_digest = header_body[54:86]
    member_count = int.from_bytes(header_body[86:88], "big")
    chunk_count = int.from_bytes(header_body[88:90], "big")
    manifest_digest = header_body[90:122]
    retention_kind = int.from_bytes(header_body[122:124], "big")
    retention_reserved = int.from_bytes(header_body[124:126], "big")
    retention_digest = header_body[126:158]
    successor = header_body[158:190]
    witness = composite(0x7F, u16(1) + raw16(operation_identity))
    expected_chunk_key = domain_key(
        0x7E,
        composite(0x7E, witness + u16(0)),
    )
    if (
        subject != operation_identity[:16]
        or chunk_count != 1
        or retention_kind != 0
        or retention_reserved != 0
        or retention_digest != ZERO32
        or successor != ZERO32
        or header_key != domain_key(0x7F, witness)
        or chunk_key != expected_chunk_key
    ):
        return rejected("KIND1_WITNESS_IDENTITY")
    if (
        header["subtype"] != 0x7F
        or header["revision"] != 1
        or header["primary_id"] != witness[:16]
        or header["head"] != ZERO32
        or header["pvd"] != ZERO32
        or chunk["subtype"] != 0x7E
        or chunk["revision"] != 1
        or chunk["primary_id"] != witness[:16]
        or chunk["head"] != ZERO32
        or chunk["pvd"] != ZERO32
    ):
        return rejected("KIND1_WITNESS_COMMON")
    if (
        chunk_body[:32] != witness
        or int.from_bytes(chunk_body[32:34], "big") != 0
        or int.from_bytes(chunk_body[34:36], "big") != 1
        or int.from_bytes(chunk_body[36:38], "big") != len(entries_raw)
        or int.from_bytes(chunk_body[38:40], "big") != 0
        or chunk_body[40:] != b"".join(entries_raw)
    ):
        return rejected("KIND1_MANIFEST_CHUNK")
    expected_manifest_digest = sha256(
        b"NINLIL-DOMAIN-MANIFEST-V1" + chunk_body
    )
    expected_canonical_digest = sha256(
        b"NINLIL-DOMAIN-OPERATION-V1"
        + u16(1)
        + raw16(operation_identity)
        + subject
        + expected_manifest_digest
        + u16(0)
        + ZERO32
    )
    if (
        manifest_digest != expected_manifest_digest
        or canonical_digest != expected_canonical_digest
    ):
        return rejected("KIND1_MANIFEST_DIGEST")
    keys = [entry["key"] for entry in entries]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        return rejected("KIND1_MANIFEST_ORDER")
    row_local_checks = kind1_semantic_row_local_checks(pre_rows, post_rows)
    if any(check["status"] != "NINLIL_OK" for check in row_local_checks):
        return rejected("KIND1_MEMBER_ROW_CODEC")
    if member_count != 5 or len(entries) != 5:
        return rejected("KIND1_MEMBER_COUNT")
    positive_signature = [
        (entry["role"], entry["action"], entry["key"])
        for entry in positive_entries
    ]
    signature = [
        (entry["role"], entry["action"], entry["key"])
        for entry in entries
    ]
    if signature != positive_signature:
        return rejected("KIND1_MEMBER_CONTRACT")
    if pre_map != positive_pre:
        return rejected("KIND1_PRE_STATE")
    member_post_map = {
        key: value
        for key, value in post_map.items()
        if domain_key_subtype(key) not in {0x7E, 0x7F}
    }
    if set(member_post_map) != set(keys):
        return rejected("KIND1_POST_MEMBER_SET")
    for entry in entries:
        key = entry["key"]
        if entry["prior_head"] != ZERO32:
            return rejected("KIND1_PRIOR_HEAD")
        if entry["action"] == 1:
            if (
                entry["old_present"] != 0
                or entry["new_present"] != 1
                or entry["old_digest"] != ZERO32
                or key in pre_map
            ):
                return rejected("KIND1_CREATE_STATE")
        elif entry["action"] == 2:
            if (
                entry["old_present"] != 1
                or entry["new_present"] != 1
                or key not in pre_map
            ):
                return rejected("KIND1_REPLACE_STATE")
            if entry["old_digest"] != sha256(pre_map[key]):
                return rejected("KIND1_REPLACE_OLD_DIGEST")
            if entry["old_digest"] == entry["new_digest"]:
                return rejected("KIND1_REPLACE_NO_OP")
        else:
            return rejected("KIND1_ACTION")
        if entry["new_digest"] != sha256(member_post_map[key]):
            return rejected("KIND1_NEW_DIGEST")
    group_reason = independent_kind1_group_semantic_reason(
        pre_rows,
        post_rows,
        positive_kat,
    )
    if group_reason is not None:
        return rejected(group_reason)
    return {
        "status": "NINLIL_OK",
        "rejection": None,
        "member_count": len(entries),
        "pre_record_count": len(pre_rows),
        "post_record_count": len(post_rows),
        "semantic_row_local_check_count": len(row_local_checks),
        "manifest_digest": expected_manifest_digest.hex(),
        "canonical_operation_digest": expected_canonical_digest.hex(),
    }


def rebuild_kind1_material(
    positive_kat: dict[str, Any],
    entries: list[tuple[str, bytes]],
    member_records: list[dict[str, Any]],
) -> tuple[list[bytes], list[dict[str, Any]], list[dict[str, Any]]]:
    witness = bytes.fromhex(positive_kat["derived"]["witness_digest"])
    operation_identity = bytes.fromhex(
        positive_kat["derived"]["service_complete_key_digest"]
    )
    encoded_entries = [entry for _, entry in entries]
    chunk_body = (
        witness
        + u16(0)
        + u16(1)
        + u16(len(encoded_entries))
        + u16(0)
        + b"".join(encoded_entries)
    )
    manifest_digest = sha256(b"NINLIL-DOMAIN-MANIFEST-V1" + chunk_body)
    subject = operation_identity[:16]
    canonical_digest = sha256(
        b"NINLIL-DOMAIN-OPERATION-V1"
        + u16(1)
        + raw16(operation_identity)
        + subject
        + manifest_digest
        + u16(0)
        + ZERO32
    )
    header_body = (
        u16(1)
        + u16(1)
        + raw16(operation_identity)
        + subject
        + canonical_digest
        + u16(len(encoded_entries))
        + u16(1)
        + manifest_digest
        + u16(0)
        + u16(0)
        + ZERO32
        + ZERO32
    )
    header_key = domain_key(0x7F, witness)
    chunk_key = domain_key(
        0x7E,
        composite(0x7E, witness + u16(0)),
    )
    post_records = list(member_records)
    post_records.extend(
        [
            record_object(
                "witness_manifest_chunk",
                chunk_key,
                domain_value(
                    0x7E,
                    1,
                    witness[:16],
                    ZERO32,
                    ZERO32,
                    chunk_body,
                ),
            ),
            record_object(
                "witness_header",
                header_key,
                domain_value(
                    0x7F,
                    1,
                    witness[:16],
                    ZERO32,
                    ZERO32,
                    header_body,
                ),
            ),
        ]
    )
    post_records.sort(key=lambda row: bytes.fromhex(row["key_hex"]))
    pre_records = sorted(
        positive_kat["pre_state"].values(),
        key=lambda row: bytes.fromhex(row["key_hex"]),
    )
    return encoded_entries, pre_records, post_records


def build_kind1_validation_vectors(
    positive_kat: dict[str, Any],
) -> dict[str, Any]:
    base_entries = [
        (entry["name"], bytes.fromhex(entry["encoded_hex"]))
        for entry in positive_kat["manifest_entries"]
    ]
    base_member_records = [
        record
        for record in positive_kat["post_records_full_stage_order"]
        if record["name"] not in {"witness_manifest_chunk", "witness_header"}
    ]
    positive_material = rebuild_kind1_material(
        positive_kat,
        base_entries,
        base_member_records,
    )
    assert positive_material[2] == positive_kat["post_records_full_stage_order"]

    missing_entries = [
        entry
        for entry in base_entries
        if entry[0] != "service_reservation"
    ]
    missing_records = [
        record
        for record in base_member_records
        if record["name"] != "service_reservation"
    ]
    missing_material = rebuild_kind1_material(
        positive_kat,
        missing_entries,
        missing_records,
    )

    witness = bytes.fromhex(positive_kat["derived"]["witness_digest"])
    alternate_kind1_kat = build_kind1_kat(
        ALTERNATE_KIND1_FIXTURE_OVERRIDES
    )
    alternate_service_record = next(
        record
        for record in alternate_kind1_kat["post_records_full_stage_order"]
        if record["name"] == "service"
    )
    extra_key = bytes.fromhex(alternate_service_record["key_hex"])
    alternate_service_value = decode_domain_record_value(
        bytes.fromhex(alternate_service_record["value_hex"])
    )
    assert alternate_service_value["subtype"] == 0x10
    extra_value = domain_value(
        0x10,
        1,
        alternate_service_value["primary_id"],
        witness,
        ZERO32,
        alternate_service_value["body"],
    )
    assert independent_kind1_d1_row_local_reason(
        extra_key,
        extra_value,
    ) is None
    extra_entry = witness_entry(
        0x0610,
        1,
        extra_key,
        0,
        1,
        ZERO32,
        ZERO32,
        sha256(extra_value),
    )
    extra_entries = base_entries + [("extra_service", extra_entry)]
    extra_entries.sort(key=lambda item: decode_witness_entry(item[1])["key"])
    extra_records = base_member_records + [
        record_object("extra_service", extra_key, extra_value)
    ]
    extra_material = rebuild_kind1_material(
        positive_kat,
        extra_entries,
        extra_records,
    )

    wrong_order_entries = list(base_entries)
    wrong_order_entries[1], wrong_order_entries[2] = (
        wrong_order_entries[2],
        wrong_order_entries[1],
    )
    wrong_order_material = rebuild_kind1_material(
        positive_kat,
        wrong_order_entries,
        base_member_records,
    )

    old_capacity_record = positive_kat["pre_state"]["capacity"]
    old_capacity_key = bytes.fromhex(old_capacity_record["key_hex"])
    old_capacity_value = bytes.fromhex(old_capacity_record["value_hex"])
    old_head_record = positive_kat["pre_state"]["head_index"]
    old_head_value = bytes.fromhex(old_head_record["value_hex"])
    head_identity = composite(0x7D, key_digest(old_capacity_key))
    no_op_head_value = domain_value(
        0x7D,
        2,
        head_identity[:16],
        witness,
        ZERO32,
        witness_index_body(
            2,
            old_capacity_key,
            sha256(old_capacity_value),
            witness,
        ),
    )
    no_op_records = []
    for record in base_member_records:
        if record["name"] == "capacity_service":
            no_op_records.append(
                record_object(
                    "capacity_service",
                    old_capacity_key,
                    old_capacity_value,
                )
            )
        elif record["name"] == "capacity_head_index":
            no_op_records.append(
                record_object(
                    "capacity_head_index",
                    bytes.fromhex(record["key_hex"]),
                    no_op_head_value,
                )
            )
        else:
            no_op_records.append(record)
    no_op_entries = []
    for name, entry in base_entries:
        decoded = decode_witness_entry(entry)
        if name == "capacity_service":
            entry = witness_entry(
                decoded["role"],
                decoded["action"],
                decoded["key"],
                1,
                1,
                ZERO32,
                sha256(old_capacity_value),
                sha256(old_capacity_value),
            )
        elif name == "capacity_head_index":
            entry = witness_entry(
                decoded["role"],
                decoded["action"],
                decoded["key"],
                1,
                1,
                ZERO32,
                sha256(old_head_value),
                sha256(no_op_head_value),
            )
        no_op_entries.append((name, entry))
    no_op_material = rebuild_kind1_material(
        positive_kat,
        no_op_entries,
        no_op_records,
    )

    def semantic_material(
        updates: dict[str, bytes],
    ) -> tuple[list[bytes], list[dict[str, Any]], list[dict[str, Any]]]:
        records = []
        values_by_key: dict[bytes, bytes] = {}
        for record in base_member_records:
            key = bytes.fromhex(record["key_hex"])
            value = updates.get(
                record["name"],
                bytes.fromhex(record["value_hex"]),
            )
            records.append(record_object(record["name"], key, value))
            values_by_key[key] = value
        entries = []
        for name, encoded in base_entries:
            decoded = decode_witness_entry(encoded)
            entries.append(
                (
                    name,
                    witness_entry(
                        decoded["role"],
                        decoded["action"],
                        decoded["key"],
                        decoded["old_present"],
                        decoded["new_present"],
                        decoded["prior_head"],
                        decoded["old_digest"],
                        sha256(values_by_key[decoded["key"]]),
                    ),
                )
            )
        return rebuild_kind1_material(positive_kat, entries, records)

    quota_record = next(
        record
        for record in base_member_records
        if record["name"] == "service_quota"
    )
    quota_key = bytes.fromhex(quota_record["key_hex"])
    quota_decoded = decode_domain_record_value(
        bytes.fromhex(quota_record["value_hex"])
    )
    quota_body = bytearray(quota_decoded["body"])
    quota_service_raw, quota_cursor = parse_raw16_at(quota_body, 0)
    assert quota_service_raw

    quota_pvd_value = domain_value(
        0x11,
        quota_decoded["revision"],
        quota_decoded["primary_id"],
        quota_decoded["head"],
        bytes.fromhex("99" * 32),
        bytes(quota_body),
    )
    quota_pvd_material = semantic_material(
        {"service_quota": quota_pvd_value}
    )

    quota_counter_body = bytearray(quota_body)
    quota_counter_body[quota_cursor + 56 : quota_cursor + 60] = u32(1)
    quota_counter_value = domain_value(
        0x11,
        quota_decoded["revision"],
        quota_decoded["primary_id"],
        quota_decoded["head"],
        quota_decoded["pvd"],
        bytes(quota_counter_body),
    )
    quota_counter_material = semantic_material(
        {"service_quota": quota_counter_value}
    )

    quota_window_body = bytearray(quota_body)
    original_window = int.from_bytes(
        quota_window_body[quota_cursor + 48 : quota_cursor + 56],
        "big",
    )
    quota_window_body[quota_cursor + 48 : quota_cursor + 56] = u64(
        original_window + 1
    )
    quota_window_value = domain_value(
        0x11,
        quota_decoded["revision"],
        quota_decoded["primary_id"],
        quota_decoded["head"],
        quota_decoded["pvd"],
        bytes(quota_window_body),
    )
    quota_window_material = semantic_material(
        {"service_quota": quota_window_value}
    )

    reservation_record = next(
        record
        for record in base_member_records
        if record["name"] == "service_reservation"
    )
    reservation_decoded = decode_domain_record_value(
        bytes.fromhex(reservation_record["value_hex"])
    )
    reservation_body = bytearray(reservation_decoded["body"])
    reservation_pvd_value = domain_value(
        0x23,
        reservation_decoded["revision"],
        reservation_decoded["primary_id"],
        reservation_decoded["head"],
        bytes.fromhex("98" * 32),
        bytes(reservation_body),
    )
    reservation_pvd_material = semantic_material(
        {"service_reservation": reservation_pvd_value}
    )

    _, reservation_cursor = parse_raw16_at(reservation_body, 4)
    reservation_vector_body = bytearray(reservation_body)
    second_resource_used = reservation_cursor + 32 + 16
    reservation_vector_body[
        second_resource_used : second_resource_used + 8
    ] = u64(1)
    reservation_vector_value = domain_value(
        0x23,
        reservation_decoded["revision"],
        reservation_decoded["primary_id"],
        reservation_decoded["head"],
        reservation_decoded["pvd"],
        bytes(reservation_vector_body),
    )
    reservation_vector_material = semantic_material(
        {"service_reservation": reservation_vector_value}
    )

    capacity_record = next(
        record
        for record in base_member_records
        if record["name"] == "capacity_service"
    )
    capacity_key = bytes.fromhex(capacity_record["key_hex"])
    capacity_decoded = decode_runtime_capacity_semantics(
        bytes.fromhex(capacity_record["value_hex"])
    )
    capacity_increment_value = runtime_capacity_value(
        1,
        capacity_decoded["limit"],
        2,
        0,
        2,
        2,
    )
    head_record = next(
        record
        for record in base_member_records
        if record["name"] == "capacity_head_index"
    )
    head_decoded = decode_domain_record_value(
        bytes.fromhex(head_record["value_hex"])
    )
    capacity_increment_head_value = domain_value(
        0x7D,
        head_decoded["revision"],
        head_decoded["primary_id"],
        head_decoded["head"],
        head_decoded["pvd"],
        witness_index_body(
            2,
            capacity_key,
            sha256(capacity_increment_value),
            head_decoded["head"],
        ),
    )
    capacity_increment_material = semantic_material(
        {
            "capacity_service": capacity_increment_value,
            "capacity_head_index": capacity_increment_head_value,
        }
    )

    head_digest_mismatch_value = domain_value(
        0x7D,
        head_decoded["revision"],
        head_decoded["primary_id"],
        head_decoded["head"],
        head_decoded["pvd"],
        witness_index_body(
            2,
            capacity_key,
            bytes.fromhex("97" * 32),
            head_decoded["head"],
        ),
    )
    head_digest_mismatch_material = semantic_material(
        {"capacity_head_index": head_digest_mismatch_value}
    )

    fixtures = [
        (
            "KIND1_POSITIVE_EXACT",
            "positive",
            positive_material,
            "NINLIL_OK",
            None,
        ),
        (
            "KIND1_MISSING_MEMBER",
            "mutation",
            missing_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_MEMBER_COUNT",
        ),
        (
            "KIND1_EXTRA_MEMBER",
            "mutation",
            extra_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_MEMBER_COUNT",
        ),
        (
            "KIND1_NO_OP_REPLACE",
            "mutation",
            no_op_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_REPLACE_NO_OP",
        ),
        (
            "KIND1_WRONG_MANIFEST_ORDER",
            "mutation",
            wrong_order_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_MANIFEST_ORDER",
        ),
        (
            "KIND1_QUOTA_PRIMARY_VALUE_DIGEST_MISMATCH",
            "mutation",
            quota_pvd_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_QUOTA_PRIMARY_VALUE_DIGEST",
        ),
        (
            "KIND1_QUOTA_INITIAL_COUNTER_NONZERO",
            "mutation",
            quota_counter_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_QUOTA_INITIAL_COUNTER",
        ),
        (
            "KIND1_QUOTA_WINDOW_MISMATCH",
            "mutation",
            quota_window_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_QUOTA_WINDOW",
        ),
        (
            "KIND1_RESERVATION_PRIMARY_VALUE_DIGEST_MISMATCH",
            "mutation",
            reservation_pvd_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_RESERVATION_PRIMARY_VALUE_DIGEST",
        ),
        (
            "KIND1_RESERVATION_RESOURCE_VECTOR_MISMATCH",
            "mutation",
            reservation_vector_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_RESERVATION_RESOURCE_VECTOR",
        ),
        (
            "KIND1_CAPACITY_POST_INCREMENT_MISMATCH",
            "mutation",
            capacity_increment_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_CAPACITY_POST_INCREMENT",
        ),
        (
            "KIND1_HEAD_INDEX_MEMBER_VALUE_DIGEST_MISMATCH",
            "mutation",
            head_digest_mismatch_material,
            "NINLIL_E_STORAGE_CORRUPT",
            "KIND1_HEAD_INDEX_RELATION",
        ),
    ]
    vectors = []
    aggregate = b"NINLIL-DOMAIN-KIND1-VECTOR-SET-V1"
    for (
        vector_id,
        fixture_kind,
        material,
        expected_status,
        expected_rejection,
    ) in fixtures:
        entries, pre_records, post_records = material
        artifact = encode_kind1_fixture(
            entries,
            pre_records,
            post_records,
        )
        _, parsed_pre_rows, parsed_post_rows = parse_kind1_fixture(artifact)
        row_local_checks = kind1_semantic_row_local_checks(
            parsed_pre_rows,
            parsed_post_rows,
        )
        assert row_local_checks
        assert all(
            check["status"] == "NINLIL_OK"
            for check in row_local_checks
        ), (vector_id, row_local_checks)
        computed = classify_kind1_fixture(artifact, positive_kat)
        assert computed["status"] == expected_status, (
            vector_id,
            computed,
        )
        assert computed["rejection"] == expected_rejection, (
            vector_id,
            computed,
        )
        vectors.append(
            {
                "id": vector_id,
                "fixture_kind": fixture_kind,
                "fixture_length": len(artifact),
                "fixture_hex": artifact.hex(),
                "fixture_sha256": sha256(artifact).hex(),
                "manifest_entry_count": len(entries),
                "pre_record_count": len(pre_records),
                "post_record_count": len(post_records),
                "expected_status": expected_status,
                "expected_rejection": expected_rejection,
                "computed_status": computed["status"],
                "computed_rejection": computed["rejection"],
                "oracle": "generator classify_kind1_fixture",
                "row_local_oracle": (
                    "generator "
                    "independent_kind1_d1_row_local_reason"
                ),
                "row_local_semantic_record_count": len(row_local_checks),
                "row_local_all_ok": True,
            }
        )
        encoded_id = vector_id.encode("ascii")
        encoded_status = expected_status.encode("ascii")
        aggregate += (
            u16(len(encoded_id))
            + encoded_id
            + u16(len(encoded_status))
            + encoded_status
            + u32(len(artifact))
            + artifact
        )
    return {
        "fixture_format": (
            "ASCII(NINLIL-DOMAIN-KIND1-FIXTURE-V1)||"
            "manifest_entry_count:u16||each(entry_length:u16||entry)||"
            "pre_record_count:u16||each(key_length:u16||key||"
            "value_length:u32||value)||post_record_count:u16||same rows"
        ),
        "fixture_count": len(vectors),
        "positive_count": sum(
            vector["fixture_kind"] == "positive" for vector in vectors
        ),
        "mutation_count": sum(
            vector["fixture_kind"] == "mutation" for vector in vectors
        ),
        "fixture_aggregate_preimage": (
            "ASCII(NINLIL-DOMAIN-KIND1-VECTOR-SET-V1)||each "
            "(id_length:u16||id||status_length:u16||status||"
            "fixture_length:u32||fixture)"
        ),
        "fixture_aggregate_sha256": sha256(aggregate).hex(),
        "vectors": vectors,
    }


def lab_catalog(
    positives: dict[str, dict[str, Any]],
    kind30_companion: dict[str, Any],
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
) -> list[dict[str, Any]]:
    names = [
        "RS_BINDING",
        "RS_IDENTITY",
        "RS_COUNTER_TRANSACTION",
        "RS_COUNTER_ORDERED_INPUT",
        "RS_COUNTER_ASSIGNED_OWNER",
        "RS_COUNTER_VISITED_OWNER",
        "RS_CAPACITY_SERVICE",
        "RS_CAPACITY_TRANSACTION",
        "RS_CAPACITY_TARGET",
        "RS_CAPACITY_OUTBOX_BYTES",
        "RS_CAPACITY_DELIVERY",
        "RS_CAPACITY_EVENT_SPOOL_COUNT",
        "RS_CAPACITY_EVENT_SPOOL_BYTES",
        "RS_CAPACITY_RESULT_CACHE",
        "RS_CAPACITY_EVIDENCE",
        "RS_CAPACITY_INGRESS",
        "RS_CAPACITY_DEFERRED_TOKEN",
        "DOM_WITNESS_HEAD_INDEX",
        "DOM_CLOCK_BASELINE",
        "SPINE_SERVICE_MARKER",
        "SPINE_TXN_ADMISSION",
        "SPINE_CANCEL_ADMISSION",
        "SPINE_DELIVERY_STARTED",
        "SPINE_DELIVERY_EVIDENCE",
        "SPINE_DELIVERY_OUTCOME",
        "SPINE_EVENT_SPOOL",
        "SPINE_EVENT_RESUME",
        "SPINE_EVENT_DISCARD",
        "SPINE_RETRY_STATE",
        "SPINE_RESERVATION",
        "M4_INSTALL_TOKEN",
        "C3_REPLAY_ADMISSION",
        "SPINE_BEARER_STATE",
        "SPINE_ATTEMPT_PREPARE",
    ]
    predicate_ids = [
        "RS1_FORMAT1",
        "RS2",
        "RS3_KIND1",
        "RS3_KIND2",
        "RS3_KIND3",
        "RS3_KIND4",
        "RS4_KIND1",
        "RS4_KIND2",
        "RS4_KIND3",
        "RS4_KIND4",
        "RS4_KIND5",
        "RS4_KIND6",
        "RS4_KIND7",
        "RS4_KIND8",
        "RS4_KIND9",
        "RS4_KIND10",
        "RS4_KIND11",
        "DS_HEAD_INDEX",
        "DS_CLOCK",
        "NRS",
        "NTS3_TX",
        "NTS3_CN",
        "NTS3_DS",
        "NTS3_EV",
        "NTS3_OC",
        "NTS3_ES",
        "NEL1_RESUME",
        "NEL1_DISCARD",
        "NTS3_RT",
        "NRV1",
        "M4T",
        "C3R",
        "NBS1",
        "NTS3_AP",
    ]
    rows = [
        {
            "kind": index + 1,
            "name": name,
            "predicate_id": predicate_ids[index],
            "isolated_expected_row_status": "NINLIL_OK",
            "isolated_expected_row_kind": index + 1,
            "canonical_publish": False,
        }
        for index, name in enumerate(names)
    ]
    for row in rows:
        positive = positives[row["name"]]
        row["isolated_positive"] = positive
        kind = row["kind"]
        computed_row = classify_lab_row(
            bytes.fromhex(positive["key_hex"]),
            bytes.fromhex(positive["value_hex"]),
            format1_bootstrap,
        )
        assert computed_row["status"] == "NINLIL_OK", (
            kind,
            computed_row,
        )
        assert computed_row["kind"] == kind, (kind, computed_row)
        row["isolated_computed_row_status"] = computed_row["status"]
        row["isolated_computed_row_kind"] = computed_row["kind"]
        row["isolated_row_oracle"] = "classify_lab_row"
        additional_refs = []
        if kind == 30:
            additional_refs.append("KIND_30_MATCHING_NTS3_TRANSACTION")
        if kind in (18, 19):
            additional_refs.append("LEGACY_METADATA_GROUP_ALL")
        elif kind > 17:
            additional_refs.append(f"LAB_KIND_{kind}_ISOLATED_POSITIVE")
        namespace_rows = {
            bytes.fromhex(record["key_hex"]): bytes.fromhex(
                record["value_hex"]
            )
            for record in format1_bootstrap[
                "records_unsigned_key_order"
            ]
        }
        if kind == 30:
            companion_key = bytes.fromhex(kind30_companion["key_hex"])
            assert companion_key not in namespace_rows
            namespace_rows[companion_key] = bytes.fromhex(
                kind30_companion["value_hex"]
            )
        if kind in (18, 19):
            for metadata_record in legacy_metadata_group[
                "records_unsigned_key_order"
            ]:
                metadata_key = bytes.fromhex(metadata_record["key_hex"])
                metadata_value = bytes.fromhex(metadata_record["value_hex"])
                assert metadata_key not in namespace_rows
                namespace_rows[metadata_key] = metadata_value
        positive_key = bytes.fromhex(positive["key_hex"])
        positive_value = bytes.fromhex(positive["value_hex"])
        if kind in (18, 19):
            assert namespace_rows[positive_key] == positive_value
        elif kind > 17:
            assert positive_key not in namespace_rows
            namespace_rows[positive_key] = positive_value
        else:
            assert namespace_rows[positive_key] == positive_value
        cross_row_failures = namespace_cross_row_failures(
            namespace_rows, legacy_metadata_group
        )
        assert cross_row_failures == []
        computed_namespace = classify_lab_namespace(
            sorted(namespace_rows.items()),
            format1_bootstrap,
            format2_bootstrap,
            legacy_metadata_group,
        )
        assert computed_namespace["status"] == "EXACT_LAB", (
            kind,
            computed_namespace,
        )
        resolved_count = len(namespace_rows)
        row["namespace_positive"] = {
            "id": f"LAB_KIND_{kind}_NAMESPACE_EXACT",
            "base_row_set_ref": "FORMAT1_BOOTSTRAP_ALL",
            "additional_row_refs": additional_refs,
            "resolved_record_count": resolved_count,
            "resolved_unique_key_count": resolved_count,
            "resolved_namespace_sha256": namespace_row_set_sha256(
                namespace_rows
            ),
            "format1_binding_present": True,
            "cross_row_validation": {
                "oracle": "generator namespace_cross_row_failures",
                "evaluated": True,
                "failures": cross_row_failures,
            },
            "expected_namespace_status": "EXACT_LAB",
            "computed_namespace_status": computed_namespace["status"],
            "namespace_oracle": "classify_lab_namespace",
            "canonical_publish": False,
        }
        mutations = build_lab_mutations(positive)
        for mutation in mutations:
            mutation["base_namespace_positive_id"] = (
                f"LAB_KIND_{kind}_NAMESPACE_EXACT"
            )
            mutation["mutation_semantics"] = (
                "replace target isolated-positive row at the same logical "
                "catalog slot; retain format-1 bootstrap and companions"
            )
            mutated_rows = dict(namespace_rows)
            assert mutated_rows.pop(positive_key) == positive_value
            mutated_key = bytes.fromhex(mutation["key_hex"])
            assert mutated_key not in mutated_rows
            mutated_rows[mutated_key] = bytes.fromhex(
                mutation["value_hex"]
            )
            mutation["resolved_unique_key_count"] = len(mutated_rows)
            mutation["resolved_namespace_sha256"] = (
                namespace_row_set_sha256(mutated_rows)
            )
            computed_mutation_row = classify_lab_row(
                mutated_key,
                bytes.fromhex(mutation["value_hex"]),
                format1_bootstrap,
            )
            assert (
                computed_mutation_row["status"]
                == mutation["expected_row_status"]
            ), (kind, mutation["id"], computed_mutation_row)
            computed_mutation_namespace = classify_lab_namespace(
                sorted(mutated_rows.items()),
                format1_bootstrap,
                format2_bootstrap,
                legacy_metadata_group,
            )
            assert (
                computed_mutation_namespace["status"]
                == mutation["expected_namespace_status"]
            ), (kind, mutation["id"], computed_mutation_namespace)
            mutation["computed_row_status"] = computed_mutation_row["status"]
            mutation["computed_row_reason"] = computed_mutation_row["reason"]
            mutation["computed_namespace_status"] = (
                computed_mutation_namespace["status"]
            )
            mutation["row_oracle"] = "classify_lab_row"
            mutation["namespace_oracle"] = "classify_lab_namespace"
        row["mutations"] = mutations
    assert kind30_companion["key_hex"].startswith("5458")
    return rows


def namespace_records_from_map(
    rows: dict[bytes, bytes],
) -> list[dict[str, Any]]:
    return [
        record_object("NAMESPACE_FIXTURE_ROW", key, rows[key])
        for key in sorted(rows)
    ]


def build_namespace_cross_row_negative_vectors(
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
    positives: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    format1_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in format1_bootstrap["records_unsigned_key_order"]
    }
    format2_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in format2_bootstrap["records_unsigned_key_order"]
    }
    metadata_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in legacy_metadata_group["records_unsigned_key_order"]
    }
    kind20 = positives["SPINE_SERVICE_MARKER"]
    kind20_key = bytes.fromhex(kind20["key_hex"])
    kind20_value = bytes.fromhex(kind20["value_hex"])
    kind30 = positives["SPINE_RESERVATION"]
    kind30_key = bytes.fromhex(kind30["key_hex"])
    kind30_value = bytes.fromhex(kind30["value_hex"])

    metadata_target = next(
        record
        for record in legacy_metadata_group["records_unsigned_key_order"]
        if record["name"]
        == "DOM_WITNESS_HEAD_INDEX_RS_CAPACITY_SERVICE"
    )
    metadata_target_key = bytes.fromhex(metadata_target["key_hex"])
    capacity_record = next(
        record
        for record in format1_bootstrap["records_unsigned_key_order"]
        if record["name"] == "RS_CAPACITY_SERVICE"
    )
    capacity_key = bytes.fromhex(capacity_record["key_hex"])
    metadata_identity = composite(0x7D, key_digest(capacity_key))
    mismatched_metadata_value = domain_value(
        0x7D,
        1,
        metadata_identity[:16],
        ZERO32,
        ZERO32,
        witness_index_body(1, capacity_key, bytes([0x5A]) * 32, ZERO32),
    )

    max_services = format1_bootstrap["fixture"]["limits"]["max_services"]
    boundary_kind20_key = b"NRS" + u8(max_services)
    boundary_kind20_value = bytes([0xA1]) * 16

    reservation_txid = kind30_key[2:]
    txid_mismatch = tagged_id(0xB2)
    nts3_txid_mismatch_key = b"TX" + txid_mismatch
    nts3_txid_mismatch_value = encode_nts3_transaction(
        txid_mismatch, payload=bytes(64), bearer_route=1
    )
    nts3_payload_mismatch_key = b"TX" + reservation_txid
    nts3_payload_mismatch_value = encode_nts3_transaction(
        reservation_txid, payload=bytes(63), bearer_route=1
    )
    nts3_route_mismatch_key = b"TX" + reservation_txid
    nts3_route_mismatch_value = encode_nts3_transaction(
        reservation_txid, payload=bytes(64), bearer_route=2
    )

    mismatched_runtime_id = bytes([0x45]) * 16
    kind33_mismatch_key, kind33_mismatch_value = encode_nbs1(
        mismatched_runtime_id
    )

    candidates: list[tuple[str, dict[bytes, bytes], str, str]] = []

    candidates.append(
        (
            "FORMAT1_AUTHORITY_ABSENT_KIND20",
            {kind20_key: kind20_value},
            "FORMAT1_AUTHORITY_ABSENT",
            "UNSUPPORTED",
        )
    )
    rows = dict(format2_rows)
    rows[kind20_key] = kind20_value
    candidates.append(
        (
            "FORMAT1_AUTHORITY_WRONG_FORMAT2_KIND20",
            rows,
            "FORMAT1_AUTHORITY_WRONG_FORMAT2",
            "MIXED",
        )
    )
    rows = dict(format1_rows)
    rows.update(metadata_rows)
    rows.pop(metadata_target_key)
    candidates.append(
        (
            "KIND18_LEGACY_METADATA_MEMBER_MISSING",
            rows,
            "LEGACY_METADATA_INCOMPLETE",
            "CORRUPT",
        )
    )
    rows = dict(format1_rows)
    rows.update(metadata_rows)
    rows[metadata_target_key] = mismatched_metadata_value
    candidates.append(
        (
            "KIND18_LEGACY_METADATA_MEMBER_DIGEST_MISMATCH",
            rows,
            "LEGACY_METADATA_MEMBER_MISMATCH",
            "CORRUPT",
        )
    )
    rows = dict(format1_rows)
    rows[boundary_kind20_key] = boundary_kind20_value
    candidates.append(
        (
            "KIND20_SLOT_EQUALS_MAX_SERVICES",
            rows,
            "KIND20_SLOT_OUT_OF_RANGE",
            "CORRUPT",
        )
    )
    rows = dict(format1_rows)
    rows[kind30_key] = kind30_value
    candidates.append(
        (
            "KIND30_MATCHING_NTS3_MISSING",
            rows,
            "KIND30_MATCHING_NTS3_MISSING",
            "CORRUPT",
        )
    )
    rows = dict(format1_rows)
    rows[kind30_key] = kind30_value
    rows[nts3_txid_mismatch_key] = nts3_txid_mismatch_value
    candidates.append(
        (
            "KIND30_NTS3_TRANSACTION_ID_MISMATCH",
            rows,
            "KIND30_TXID_MISMATCH",
            "CORRUPT",
        )
    )
    rows = dict(format1_rows)
    rows[kind30_key] = kind30_value
    rows[nts3_payload_mismatch_key] = nts3_payload_mismatch_value
    candidates.append(
        (
            "KIND30_NTS3_PAYLOAD_LENGTH_MISMATCH",
            rows,
            "KIND30_PAYLOAD_MISMATCH",
            "CORRUPT",
        )
    )
    rows = dict(format1_rows)
    rows[kind30_key] = kind30_value
    rows[nts3_route_mismatch_key] = nts3_route_mismatch_value
    candidates.append(
        (
            "KIND30_NTS3_ROUTE_MISMATCH",
            rows,
            "KIND30_ROUTE_MISMATCH",
            "CORRUPT",
        )
    )
    rows = dict(format1_rows)
    rows[kind33_mismatch_key] = kind33_mismatch_value
    candidates.append(
        (
            "KIND33_RUNTIME_ID_MISMATCH",
            rows,
            "KIND33_RUNTIME_ID_MISMATCH",
            "CORRUPT",
        )
    )

    vectors = []
    for vector_id, rows, expected_failure, expected_status in candidates:
        failures = namespace_cross_row_failures(
            rows, legacy_metadata_group
        )
        assert failures == [expected_failure]
        computed_namespace = classify_lab_namespace(
            sorted(rows.items()),
            format1_bootstrap,
            format2_bootstrap,
            legacy_metadata_group,
        )
        assert computed_namespace["status"] == expected_status, (
            vector_id,
            computed_namespace,
        )
        vectors.append(
            {
                "id": vector_id,
                "records_unsigned_key_order": namespace_records_from_map(rows),
                "resolved_unique_key_count": len(rows),
                "resolved_namespace_sha256": namespace_row_set_sha256(rows),
                "oracle": "generator namespace_cross_row_failures",
                "computed_cross_row_failures": failures,
                "expected_present_row_status": "NINLIL_OK",
                "expected_namespace_status": expected_status,
                "computed_namespace_status": computed_namespace["status"],
                "namespace_oracle": "classify_lab_namespace",
                "canonical_publish": False,
            }
        )
    assert len(vectors) == 10
    return vectors


def mixed_vector_plan(
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
    positives: dict[str, dict[str, Any]],
    kind30_companion: dict[str, Any],
    kind1_kat: dict[str, Any],
    alternate_kind1_kat: dict[str, Any],
) -> dict[str, Any]:
    catalog_names = [
        "RS_BINDING",
        "RS_IDENTITY",
        "RS_COUNTER_TRANSACTION",
        "RS_COUNTER_ORDERED_INPUT",
        "RS_COUNTER_ASSIGNED_OWNER",
        "RS_COUNTER_VISITED_OWNER",
        "RS_CAPACITY_SERVICE",
        "RS_CAPACITY_TRANSACTION",
        "RS_CAPACITY_TARGET",
        "RS_CAPACITY_OUTBOX_BYTES",
        "RS_CAPACITY_DELIVERY",
        "RS_CAPACITY_EVENT_SPOOL_COUNT",
        "RS_CAPACITY_EVENT_SPOOL_BYTES",
        "RS_CAPACITY_RESULT_CACHE",
        "RS_CAPACITY_EVIDENCE",
        "RS_CAPACITY_INGRESS",
        "RS_CAPACITY_DEFERRED_TOKEN",
        "DOM_WITNESS_HEAD_INDEX",
        "DOM_CLOCK_BASELINE",
        "SPINE_SERVICE_MARKER",
        "SPINE_TXN_ADMISSION",
        "SPINE_CANCEL_ADMISSION",
        "SPINE_DELIVERY_STARTED",
        "SPINE_DELIVERY_EVIDENCE",
        "SPINE_DELIVERY_OUTCOME",
        "SPINE_EVENT_SPOOL",
        "SPINE_EVENT_RESUME",
        "SPINE_EVENT_DISCARD",
        "SPINE_RETRY_STATE",
        "SPINE_RESERVATION",
        "M4_INSTALL_TOKEN",
        "C3_REPLAY_ADMISSION",
        "SPINE_BEARER_STATE",
        "SPINE_ATTEMPT_PREPARE",
    ]
    references = {
        "FORMAT1_BOOTSTRAP_ALL": (
            "bootstrap_format_1_lab_arithmetic."
            "records_unsigned_key_order"
        ),
        "FORMAT2_BOOTSTRAP_ALL": (
            "bootstrap_format_2_domain_arithmetic."
            "records_unsigned_key_order"
        ),
        "FORMAT1_WITH_COMPLETE_DOMAIN_KIND1_POST": {
            "base_row_set_ref": "FORMAT1_BOOTSTRAP_ALL",
            "overlay_row_set_ref": (
                "kind1_service_register_kat."
                "post_records_full_stage_order"
            ),
            "overlay_semantics": (
                "use the format-1 binding/bootstrap row set as the base, "
                "overlay the same-key capacity-service row with its post "
                "value, then insert the six distinct Domain post rows; "
                "unique-key map"
            ),
            "resolved_unique_key_count": 23,
        },
        "FORMAT1_WITH_ALTERNATE_DOMAIN_KIND1_POST": {
            "base_row_set_ref": "FORMAT1_BOOTSTRAP_ALL",
            "overlay_row_set_ref": (
                "mixed_support_fixtures."
                "alternate_kind1_complete_post_records"
            ),
            "overlay_semantics": (
                "use the format-1 binding/bootstrap row set as the base, "
                "overlay the same-key capacity-service row with its post "
                "value, then insert the six distinct alternate Domain post "
                "rows; unique-key map"
            ),
            "resolved_unique_key_count": 23,
        },
        "KIND_30_MATCHING_NTS3_TRANSACTION": (
            "namespace_fixture_reference_index."
            "KIND_30_MATCHING_NTS3_TRANSACTION"
        ),
        "FOREIGN_ROW": {
            "key_hex": "deadbeef",
            "value_hex": "00",
        },
    }
    for kind in range(20, 35):
        references[f"LAB_KIND_{kind}_POSITIVE"] = (
            f"lab_catalog_34[kind={kind}].isolated_positive"
        )
    format2_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in format2_bootstrap["records_unsigned_key_order"]
    }
    vectors = []
    for kind in range(20, 35):
        rows = dict(format2_rows)
        if kind == 30:
            companion_key = bytes.fromhex(kind30_companion["key_hex"])
            rows[companion_key] = bytes.fromhex(
                kind30_companion["value_hex"]
            )
        positive = positives[catalog_names[kind - 1]]
        rows[bytes.fromhex(positive["key_hex"])] = bytes.fromhex(
            positive["value_hex"]
        )
        local_failures = namespace_cross_row_failures(
            rows,
            legacy_metadata_group,
            ignore_profile_mismatch=True,
        )
        assert local_failures == []
        computed_namespace = classify_lab_namespace(
            sorted(rows.items()),
            format1_bootstrap,
            format2_bootstrap,
            legacy_metadata_group,
        )
        assert computed_namespace["status"] == "MIXED", (
            kind,
            computed_namespace,
        )
        vectors.append(
            {
            "id": f"DOMAIN_FORMAT2_PLUS_LAB_KIND_{kind}",
            "base_row_set_ref": "FORMAT2_BOOTSTRAP_ALL",
            "additional_row_refs": (
                ["KIND_30_MATCHING_NTS3_TRANSACTION"]
                if kind == 30
                else []
            )
            + [f"LAB_KIND_{kind}_POSITIVE"],
            "resolved_unique_key_count": len(rows),
            "local_cross_row_validation": {
                "oracle": "generator namespace_cross_row_failures",
                "profile_mismatch_ignored_for_local_check": True,
                "evaluated": True,
                "failures": local_failures,
            },
            "expected_namespace_status": "MIXED",
            "computed_namespace_status": computed_namespace["status"],
            "namespace_oracle": "classify_lab_namespace",
            "canonical_publish": False,
            }
        )

    format1_rows = {
        bytes.fromhex(record["key_hex"]): bytes.fromhex(record["value_hex"])
        for record in format1_bootstrap["records_unsigned_key_order"]
    }
    complete_rows = dict(format1_rows)
    for record in kind1_kat["post_records_full_stage_order"]:
        complete_rows[bytes.fromhex(record["key_hex"])] = bytes.fromhex(
            record["value_hex"]
        )
    alternate_rows = dict(format1_rows)
    for record in alternate_kind1_kat["post_records_full_stage_order"]:
        alternate_rows[bytes.fromhex(record["key_hex"])] = bytes.fromhex(
            record["value_hex"]
        )
    complete_failures = namespace_cross_row_failures(
        complete_rows,
        legacy_metadata_group,
        ignore_legacy_metadata_mismatch=True,
    )
    alternate_failures = namespace_cross_row_failures(
        alternate_rows,
        legacy_metadata_group,
        ignore_legacy_metadata_mismatch=True,
    )
    assert complete_failures == [] and alternate_failures == []
    complete_computed = classify_lab_namespace(
        sorted(complete_rows.items()),
        format1_bootstrap,
        format2_bootstrap,
        legacy_metadata_group,
    )
    alternate_computed = classify_lab_namespace(
        sorted(alternate_rows.items()),
        format1_bootstrap,
        format2_bootstrap,
        legacy_metadata_group,
    )
    foreign_rows = dict(format1_rows)
    foreign_rows[bytes.fromhex("deadbeef")] = b"\x00"
    foreign_computed = classify_lab_namespace(
        sorted(foreign_rows.items()),
        format1_bootstrap,
        format2_bootstrap,
        legacy_metadata_group,
    )
    assert complete_computed["status"] == "MIXED"
    assert alternate_computed["status"] == "MIXED"
    assert foreign_computed["status"] == "MIXED"
    vectors.extend(
        [
            {
                "id": "FORMAT1_PLUS_COMPLETE_DOMAIN_KIND1_POST",
                "base_row_set_ref": (
                    "FORMAT1_WITH_COMPLETE_DOMAIN_KIND1_POST"
                ),
                "additional_row_refs": [],
                "resolved_unique_key_count": len(complete_rows),
                "local_cross_row_validation": {
                    "oracle": "generator namespace_cross_row_failures",
                    "evaluated": True,
                    "failures": complete_failures,
                },
                "expected_namespace_status": "MIXED",
                "computed_namespace_status": complete_computed["status"],
                "namespace_oracle": "classify_lab_namespace",
                "canonical_publish": False,
            },
            {
                "id": "FORMAT1_PLUS_ALTERNATE_DOMAIN_KIND1_POST",
                "base_row_set_ref": (
                    "FORMAT1_WITH_ALTERNATE_DOMAIN_KIND1_POST"
                ),
                "additional_row_refs": [],
                "resolved_unique_key_count": len(alternate_rows),
                "local_cross_row_validation": {
                    "oracle": "generator namespace_cross_row_failures",
                    "evaluated": True,
                    "failures": alternate_failures,
                },
                "expected_namespace_status": "MIXED",
                "computed_namespace_status": alternate_computed["status"],
                "namespace_oracle": "classify_lab_namespace",
                "canonical_publish": False,
            },
            {
                "id": "LAB_PLUS_FOREIGN",
                "base_row_set_ref": "FORMAT1_BOOTSTRAP_ALL",
                "additional_row_refs": ["FOREIGN_ROW"],
                "resolved_unique_key_count": 18,
                "expected_namespace_status": "MIXED",
                "computed_namespace_status": foreign_computed["status"],
                "namespace_oracle": "classify_lab_namespace",
                "canonical_publish": False,
            },
        ]
    )
    return {
        "reference_index": references,
        "vectors": vectors,
    }


def provider_contract_corruption_vectors(
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
) -> list[dict[str, Any]]:
    format1_binding = next(
        row
        for row in format1_bootstrap["records_unsigned_key_order"]
        if row["name"] == "RS_BINDING"
    )
    format2_binding = next(
        row
        for row in format2_bootstrap["records_unsigned_key_order"]
        if row["name"] == "RS_BINDING"
    )
    duplicate_records = [
        (
            bytes.fromhex(format1_binding["key_hex"]),
            bytes.fromhex(format1_binding["value_hex"]),
        ),
        (
            bytes.fromhex(format2_binding["key_hex"]),
            bytes.fromhex(format2_binding["value_hex"]),
        ),
    ]
    computed = classify_lab_namespace(
        duplicate_records,
        format1_bootstrap,
        format2_bootstrap,
        legacy_metadata_group,
    )
    assert computed["status"] == "CORRUPT"
    assert computed["reason"] == "DUPLICATE_COMPLETE_KEY"
    return [
        {
            "id": "DUPLICATE_TYPE1_BINDING_KEY_FORMAT1_FORMAT2",
            "row_refs": [
                (
                    "bootstrap_format_1_lab_arithmetic."
                    "records_unsigned_key_order[name=RS_BINDING]"
                ),
                (
                    "bootstrap_format_2_domain_arithmetic."
                    "records_unsigned_key_order[name=RS_BINDING]"
                ),
            ],
            "same_complete_key_required": True,
            "constructible_namespace_map": False,
            "provider_contract_violation": (
                "iterator returned one complete key twice"
            ),
            "expected_row_status": "NINLIL_E_STORAGE_CORRUPT",
            "expected_namespace_status": "CORRUPT",
            "computed_namespace_status": computed["status"],
            "computed_namespace_reason": computed["reason"],
            "namespace_oracle": "classify_lab_namespace",
            "canonical_publish": False,
        }
    ]


def classify_canonical_binding(
    value: bytes,
    *,
    writer_generation: int = 2,
    consumer: str = "CANONICAL_DOMAIN",
) -> dict[str, Any]:
    def rejected(
        reason: str,
        status: str = "NINLIL_E_UNSUPPORTED",
    ) -> dict[str, Any]:
        return {"status": status, "reason": reason}

    envelope = inspect_nlr1_envelope(value, 1)
    if envelope["status"] != "NINLIL_OK":
        return rejected(envelope["reason"], envelope["status"])
    payload = envelope["payload"]
    if len(payload) < 4:
        return rejected(
            "BINDING_FORMAT_LENGTH",
            "NINLIL_E_STORAGE_CORRUPT",
        )
    binding_format = int.from_bytes(payload[0:4], "big")
    if consumer == "LAST_LAB_BINARY":
        if binding_format != 1:
            return rejected("LAST_LAB_BINARY_FORMAT2_DOWNGRADE_FENCE")
        return {"status": "NINLIL_OK", "reason": None}
    if binding_format != 2:
        return rejected("BINDING_FORMAT")
    try:
        fields = decode_binding_payload_fields(value)
    except (AssertionError, ValueError):
        return rejected(
            "BINDING_CURRENT_PAYLOAD",
            "NINLIL_E_STORAGE_CORRUPT",
        )
    if fields["resource_profile_name"] != b"NINLIL-FOUNDATION-SMALL-1":
        return rejected("RESOURCE_PROFILE_NAME")
    if fields["storage_profile_id"] != b"NINLIL-DOMAIN-S1":
        return rejected("STORAGE_PROFILE_ID")
    if fields["storage_profile_revision"] != 1:
        return rejected("STORAGE_PROFILE_REVISION")
    if writer_generation < fields["minimum_writer_generation"]:
        return rejected("WRITER_GENERATION_INSUFFICIENT")
    if fields["minimum_writer_generation"] != 2:
        return rejected("MINIMUM_WRITER_GENERATION")
    if fields["rollback_epoch"] != 1:
        return rejected("ROLLBACK_EPOCH")
    if fields["storage_schema"] != 1:
        return rejected("STORAGE_SCHEMA")
    expected_payload = encode_binding_payload(2, bootstrap_fixture())
    if fields["payload"] != expected_payload:
        return rejected("BINDING_COMMON_FIELD")
    return {"status": "NINLIL_OK", "reason": None}


def build_binding_compatibility_vectors(
    format2_bootstrap: dict[str, Any],
) -> dict[str, Any]:
    binding_record = next(
        row
        for row in format2_bootstrap["records_unsigned_key_order"]
        if row["name"] == "RS_BINDING"
    )
    key = bytes.fromhex(binding_record["key_hex"])
    positive_value = bytes.fromhex(binding_record["value_hex"])
    positive_payload = bytearray(decode_nlr1_payload(positive_value, 1))

    def mutated(offset: int, replacement: bytes) -> bytes:
        payload = bytearray(positive_payload)
        payload[offset : offset + len(replacement)] = replacement
        return nlr1(1, bytes(payload))

    candidates = [
        (
            "BINDING_FORMAT2_POSITIVE_EXACT",
            positive_value,
            "CANONICAL_DOMAIN",
            "NINLIL_OK",
            None,
        ),
        (
            "BINDING_FORMAT2_UNKNOWN_FORMAT",
            mutated(0, u32(3)),
            "CANONICAL_DOMAIN",
            "NINLIL_E_UNSUPPORTED",
            "BINDING_FORMAT",
        ),
        (
            "BINDING_FORMAT2_UNKNOWN_PROFILE_ID",
            mutated(31, b"NINLIL-DOMAIN-S2"),
            "CANONICAL_DOMAIN",
            "NINLIL_E_UNSUPPORTED",
            "STORAGE_PROFILE_ID",
        ),
        (
            "BINDING_FORMAT2_PROFILE_REVISION_ROLLBACK",
            mutated(47, u32(0)),
            "CANONICAL_DOMAIN",
            "NINLIL_E_UNSUPPORTED",
            "STORAGE_PROFILE_REVISION",
        ),
        (
            "BINDING_FORMAT2_WRITER_GENERATION_INSUFFICIENT",
            mutated(51, u32(3)),
            "CANONICAL_DOMAIN",
            "NINLIL_E_UNSUPPORTED",
            "WRITER_GENERATION_INSUFFICIENT",
        ),
        (
            "BINDING_FORMAT2_ROLLBACK_EPOCH_REGRESSION",
            mutated(55, u64(0)),
            "CANONICAL_DOMAIN",
            "NINLIL_E_UNSUPPORTED",
            "ROLLBACK_EPOCH",
        ),
        (
            "BINDING_FORMAT2_SCHEMA_MISMATCH",
            mutated(63, u32(2)),
            "CANONICAL_DOMAIN",
            "NINLIL_E_UNSUPPORTED",
            "STORAGE_SCHEMA",
        ),
        (
            "BINDING_FORMAT2_LAST_LAB_BINARY_DOWNGRADE_REJECT",
            positive_value,
            "LAST_LAB_BINARY",
            "NINLIL_E_UNSUPPORTED",
            "LAST_LAB_BINARY_FORMAT2_DOWNGRADE_FENCE",
        ),
    ]
    vectors = []
    aggregate = b"NINLIL-DOMAIN-BINDING-COMPAT-V1"
    for vector_id, value, consumer, expected_status, expected_reason in candidates:
        computed = classify_canonical_binding(value, consumer=consumer)
        assert computed["status"] == expected_status, (vector_id, computed)
        assert computed["reason"] == expected_reason, (vector_id, computed)
        transcript = {
            "storage_read_only_begin": 1,
            "storage_read_write_begin": 0,
            "storage_put": 0,
            "storage_erase": 0,
            "storage_commit": 0,
            "bearer_open": 0,
            "callback": 0,
            "public_handle": 0,
            "publish": 0,
        }
        vector = {
            "id": vector_id,
            "consumer": consumer,
            "key_hex": key.hex(),
            "value_hex": value.hex(),
            "value_sha256": sha256(value).hex(),
            "expected_status": expected_status,
            "expected_reason": expected_reason,
            "computed_status": computed["status"],
            "computed_reason": computed["reason"],
            "transcript": transcript,
        }
        vectors.append(vector)
        encoded_id = vector_id.encode("ascii")
        aggregate += (
            u16(len(encoded_id))
            + encoded_id
            + u32(len(value))
            + value
            + u16(len(expected_status))
            + expected_status.encode("ascii")
        )
    return {
        "fixture_count": len(vectors),
        "positive_count": 1,
        "mutation_count": len(vectors) - 1,
        "aggregate_sha256": sha256(aggregate).hex(),
        "vectors": vectors,
    }


def build_closed_status_oracle_vectors(
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    lab_positives: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Raw KATs for malformed-current vs framing-valid-future status."""

    binding_record = next(
        row
        for row in format2_bootstrap["records_unsigned_key_order"]
        if row["name"] == "RS_BINDING"
    )
    binding_key = bytes.fromhex(binding_record["key_hex"])
    binding_current = bytes.fromhex(binding_record["value_hex"])
    binding_payload = bytearray(decode_nlr1_payload(binding_current, 1))
    binding_format3_payload = bytearray(binding_payload)
    binding_format3_payload[0:4] = u32(3)
    binding_format3 = nlr1(1, bytes(binding_format3_payload))
    binding_record_v2 = bytearray(binding_current)
    binding_record_v2[6:8] = u16(2)
    binding_record_v2[-4:] = u32(crc32c(binding_record_v2[:-4]))
    binding_bad_crc = bytearray(binding_current)
    binding_bad_crc[-1] ^= 1

    nts3_record = lab_positives["SPINE_TXN_ADMISSION"]
    nts3_key = bytes.fromhex(nts3_record["key_hex"])
    nts3_current = bytes.fromhex(nts3_record["value_hex"])
    nts3_schema2 = bytearray(nts3_current)
    nts3_schema2[4:6] = u16(2)
    nts3_schema2[-4:] = u32(crc32c(nts3_schema2[:-4]))
    nts3_bad_crc = bytearray(nts3_current)
    nts3_bad_crc[-1] ^= 1

    m4t_record = lab_positives["M4_INSTALL_TOKEN"]
    m4t_key = bytes.fromhex(m4t_record["key_hex"])
    m4t_current = bytes.fromhex(m4t_record["value_hex"])
    m4t_version2 = bytearray(m4t_current)
    m4t_version2[0] = 2
    m4t_version2[-4:] = u32(crc32c(m4t_version2[:-4]))
    m4t_bad_crc = bytearray(m4t_current)
    m4t_bad_crc[-1] ^= 1

    candidates = [
        (
            "S4_BINDING_CURRENT_POSITIVE",
            "NLR1_BINDING",
            binding_key,
            binding_current,
            "NINLIL_OK",
            "CURRENT",
        ),
        (
            "S4_BINDING_FORMAT3_FUTURE",
            "NLR1_BINDING",
            binding_key,
            binding_format3,
            "NINLIL_E_UNSUPPORTED",
            "FRAMING_VALID_FUTURE",
        ),
        (
            "S4_NLR1_RECORD_VERSION2_FUTURE",
            "NLR1_BINDING",
            binding_key,
            bytes(binding_record_v2),
            "NINLIL_E_UNSUPPORTED",
            "FRAMING_VALID_FUTURE",
        ),
        (
            "S4_NLR1_BINDING_CRC_MISMATCH",
            "NLR1_BINDING",
            binding_key,
            bytes(binding_bad_crc),
            "NINLIL_E_STORAGE_CORRUPT",
            "MALFORMED_CURRENT",
        ),
        (
            "S4_NLR1_BINDING_SHORT",
            "NLR1_BINDING",
            binding_key,
            binding_current[:-1],
            "NINLIL_E_STORAGE_CORRUPT",
            "MALFORMED_CURRENT",
        ),
        (
            "S4_NTS3_CURRENT_POSITIVE",
            "NTS3",
            nts3_key,
            nts3_current,
            "NINLIL_OK",
            "CURRENT",
        ),
        (
            "S4_NTS3_SCHEMA2_FUTURE",
            "NTS3",
            nts3_key,
            bytes(nts3_schema2),
            "NINLIL_E_UNSUPPORTED",
            "FRAMING_VALID_FUTURE",
        ),
        (
            "S4_NTS3_CRC_MISMATCH",
            "NTS3",
            nts3_key,
            bytes(nts3_bad_crc),
            "NINLIL_E_STORAGE_CORRUPT",
            "MALFORMED_CURRENT",
        ),
        (
            "S4_NTS3_SHORT",
            "NTS3",
            nts3_key,
            nts3_current[:-1],
            "NINLIL_E_STORAGE_CORRUPT",
            "MALFORMED_CURRENT",
        ),
        (
            "S4_M4T_CURRENT_POSITIVE",
            "M4T",
            m4t_key,
            m4t_current,
            "NINLIL_OK",
            "CURRENT",
        ),
        (
            "S4_M4T_VERSION2_FUTURE",
            "M4T",
            m4t_key,
            bytes(m4t_version2),
            "NINLIL_E_UNSUPPORTED",
            "FRAMING_VALID_FUTURE",
        ),
        (
            "S4_M4T_CRC_MISMATCH",
            "M4T",
            m4t_key,
            bytes(m4t_bad_crc),
            "NINLIL_E_STORAGE_CORRUPT",
            "MALFORMED_CURRENT",
        ),
        (
            "S4_M4T_SHORT",
            "M4T",
            m4t_key,
            m4t_current[:-1],
            "NINLIL_E_STORAGE_CORRUPT",
            "MALFORMED_CURRENT",
        ),
    ]
    vectors = []
    aggregate = b"NINLIL-DOMAIN-S4-CLOSED-STATUS-V1"
    for (
        vector_id,
        parser,
        key,
        value,
        expected_status,
        category,
    ) in candidates:
        if parser == "NLR1_BINDING":
            computed = classify_canonical_binding(value)
            secondary = classify_lab_row(
                key,
                value,
                format1_bootstrap,
            )
            assert secondary["status"] == expected_status, (
                vector_id,
                secondary,
            )
        else:
            computed = classify_lab_row(
                key,
                value,
                format1_bootstrap,
            )
            secondary = computed
        assert computed["status"] == expected_status, (
            vector_id,
            computed,
        )
        vectors.append(
            {
                "id": vector_id,
                "parser": parser,
                "category": category,
                "key_hex": key.hex(),
                "value_hex": value.hex(),
                "value_sha256": sha256(value).hex(),
                "expected_status": expected_status,
                "generator_computed_status": computed["status"],
                "generator_computed_reason": computed["reason"],
                "secondary_row_computed_status": secondary["status"],
                "canonical_publish": False,
            }
        )
        encoded_id = vector_id.encode("ascii")
        encoded_status = expected_status.encode("ascii")
        aggregate += (
            u16(len(encoded_id))
            + encoded_id
            + u16(len(parser))
            + parser.encode("ascii")
            + u32(len(key))
            + key
            + u32(len(value))
            + value
            + u16(len(encoded_status))
            + encoded_status
        )
    return {
        "fixture_count": len(vectors),
        "current_positive_count": sum(
            vector["category"] == "CURRENT" for vector in vectors
        ),
        "framing_valid_future_count": sum(
            vector["category"] == "FRAMING_VALID_FUTURE"
            for vector in vectors
        ),
        "malformed_current_count": sum(
            vector["category"] == "MALFORMED_CURRENT"
            for vector in vectors
        ),
        "aggregate_sha256": sha256(aggregate).hex(),
        "vectors": vectors,
    }


def snapshot_sha256(rows: dict[bytes, bytes]) -> str:
    transcript = b"".join(
        u16(len(key)) + key + u32(len(rows[key])) + rows[key]
        for key in sorted(rows)
    )
    return sha256(
        b"NINLIL-DOMAIN-INIT-SNAPSHOT-V1"
        + u32(len(rows))
        + transcript
    ).hex()


def initialization_classification_transcript() -> dict[str, Any]:
    return {
        "transaction_mode": "READ_ONLY",
        "storage_read_only_begin": 1,
        "iterator_open": 1,
        "iterator_exhausted": 1,
        "iterator_close": 1,
        "rollback": 1,
        "storage_read_write_begin": 0,
        "storage_put": 0,
        "storage_erase": 0,
        "storage_commit": 0,
        "bearer_open": 0,
        "callback": 0,
        "public_handle": 0,
        "publish": 0,
    }


def classify_initialization_snapshot(
    group: str,
    rows: dict[bytes, bytes],
    *,
    format2_rows: dict[bytes, bytes],
    metadata_uninitialized: dict[bytes, bytes],
    trusted_clock_value: bytes,
) -> dict[str, str | None]:
    clock_key = domain_singleton_key(0x62)
    if group == "T1A":
        if not rows:
            return {"classification": "OLD", "reason": None}
        if rows == format2_rows:
            return {"classification": "NEW", "reason": None}
        return {
            "classification": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "T1A_PARTIAL_EXTRA_OR_FORMAT_MISMATCH",
        }
    bootstrap_keys = set(format2_rows)
    if any(rows.get(key) != value for key, value in format2_rows.items()):
        return {
            "classification": "NINLIL_E_STORAGE_CORRUPT",
            "reason": f"{group}_BOOTSTRAP_MISMATCH",
        }
    metadata_observed = {
        key: value for key, value in rows.items() if key not in bootstrap_keys
    }
    if group == "T1B":
        if not metadata_observed:
            return {"classification": "OLD", "reason": None}
        if metadata_observed == metadata_uninitialized:
            return {"classification": "NEW", "reason": None}
        return {
            "classification": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "T1B_PARTIAL_EXTRA_OR_TRUSTED",
        }
    if group != "T5":
        raise ValueError("unknown initialization group")
    expected_non_clock = {
        key: value
        for key, value in metadata_uninitialized.items()
        if key != clock_key
    }
    observed_non_clock = {
        key: value
        for key, value in metadata_observed.items()
        if key != clock_key
    }
    if observed_non_clock != expected_non_clock or set(metadata_observed) != set(
        metadata_uninitialized
    ):
        return {
            "classification": "NINLIL_E_STORAGE_CORRUPT",
            "reason": "T5_METADATA_OR_CLOCK_MISSING",
        }
    if metadata_observed[clock_key] == metadata_uninitialized[clock_key]:
        return {"classification": "OLD", "reason": None}
    if metadata_observed[clock_key] == trusted_clock_value:
        return {"classification": "NEW", "reason": None}
    return {
        "classification": "NINLIL_E_STORAGE_CORRUPT",
        "reason": "T5_THIRD_CLOCK_VALUE",
    }


def build_initialization_transition_vectors(
    format1_bootstrap: dict[str, Any],
    format2_bootstrap: dict[str, Any],
    legacy_metadata_group: dict[str, Any],
) -> dict[str, Any]:
    format1_rows = {
        bytes.fromhex(row["key_hex"]): bytes.fromhex(row["value_hex"])
        for row in format1_bootstrap["records_unsigned_key_order"]
    }
    format2_rows = {
        bytes.fromhex(row["key_hex"]): bytes.fromhex(row["value_hex"])
        for row in format2_bootstrap["records_unsigned_key_order"]
    }
    metadata_rows = {
        bytes.fromhex(row["key_hex"]): bytes.fromhex(row["value_hex"])
        for row in legacy_metadata_group["records_unsigned_key_order"]
    }
    clock_key = domain_singleton_key(0x62)
    pinned_epoch = bytes.fromhex("33" * 16)
    pinned_now_ms = 123456
    trusted_clock_value = domain_value(
        0x62,
        2,
        ZERO16,
        ZERO32,
        ZERO32,
        u32(2) + u32(0) + pinned_epoch + u64(pinned_now_ms) + u64(1),
    )
    third_epoch_clock = domain_value(
        0x62,
        2,
        ZERO16,
        ZERO32,
        ZERO32,
        u32(2) + u32(0) + bytes.fromhex("34" * 16)
        + u64(pinned_now_ms)
        + u64(1),
    )
    third_sample_clock = domain_value(
        0x62,
        2,
        ZERO16,
        ZERO32,
        ZERO32,
        u32(2) + u32(0) + pinned_epoch + u64(pinned_now_ms + 1) + u64(1),
    )

    t1a_candidates: list[tuple[str, dict[bytes, bytes], str]] = [
        ("T1A_COMMIT_UNKNOWN_ALL_OLD_0_OF_17", {}, "OLD"),
        ("T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17", dict(format2_rows), "NEW"),
        (
            "T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17",
            dict(list(sorted(format2_rows.items()))[:1]),
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T1A_COMMIT_UNKNOWN_PARTIAL_16_OF_17",
            dict(list(sorted(format2_rows.items()))[:16]),
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T1A_COMMIT_UNKNOWN_EXTRA_ROW",
            {**format2_rows, b"\xde\xad\xbe\xef": b"\x00"},
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T1A_COMMIT_UNKNOWN_FORMAT_MISMATCH",
            dict(format1_rows),
            "NINLIL_E_STORAGE_CORRUPT",
        ),
    ]
    metadata_sorted = list(sorted(metadata_rows.items()))
    t1b_new = {**format2_rows, **metadata_rows}
    trusted_metadata = dict(metadata_rows)
    trusted_metadata[clock_key] = trusted_clock_value
    t1b_candidates: list[tuple[str, dict[bytes, bytes], str]] = [
        ("T1B_COMMIT_UNKNOWN_ALL_OLD_0_OF_16", dict(format2_rows), "OLD"),
        ("T1B_COMMIT_UNKNOWN_ALL_NEW_16_OF_16", t1b_new, "NEW"),
        (
            "T1B_COMMIT_UNKNOWN_PARTIAL_1_OF_16",
            {**format2_rows, **dict(metadata_sorted[:1])},
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T1B_COMMIT_UNKNOWN_PARTIAL_15_OF_16",
            {**format2_rows, **dict(metadata_sorted[:15])},
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T1B_COMMIT_UNKNOWN_EXTRA_ROW",
            {**t1b_new, b"\xde\xad\xbe\xef": b"\x00"},
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T1B_COMMIT_UNKNOWN_TRUSTED_MIX",
            {**format2_rows, **trusted_metadata},
            "NINLIL_E_STORAGE_CORRUPT",
        ),
    ]
    t5_old = {**format2_rows, **metadata_rows}
    t5_new = {**format2_rows, **trusted_metadata}
    t5_missing = dict(t5_old)
    t5_missing.pop(clock_key)
    t5_third_epoch = dict(t5_old)
    t5_third_epoch[clock_key] = third_epoch_clock
    t5_third_sample = dict(t5_old)
    t5_third_sample[clock_key] = third_sample_clock
    t5_candidates: list[tuple[str, dict[bytes, bytes], str]] = [
        ("T5_COMMIT_UNKNOWN_OLD_UNINITIALIZED", t5_old, "OLD"),
        ("T5_COMMIT_UNKNOWN_NEW_TRUSTED", t5_new, "NEW"),
        (
            "T5_COMMIT_UNKNOWN_MISSING",
            t5_missing,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T5_COMMIT_UNKNOWN_THIRD_EPOCH",
            t5_third_epoch,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "T5_COMMIT_UNKNOWN_THIRD_SAMPLE",
            t5_third_sample,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
    ]

    def materialize(
        group: str,
        candidates: list[tuple[str, dict[bytes, bytes], str]],
    ) -> list[dict[str, Any]]:
        vectors = []
        for vector_id, rows, expected in candidates:
            computed = classify_initialization_snapshot(
                group,
                rows,
                format2_rows=format2_rows,
                metadata_uninitialized=metadata_rows,
                trusted_clock_value=trusted_clock_value,
            )
            assert computed["classification"] == expected, (
                vector_id,
                computed,
            )
            vectors.append(
                {
                    "id": vector_id,
                    "snapshot_records_unsigned_key_order": (
                        namespace_records_from_map(rows)
                    ),
                    "snapshot_record_count": len(rows),
                    "snapshot_sha256": snapshot_sha256(rows),
                    "expected_classification": expected,
                    "computed_classification": computed["classification"],
                    "computed_reason": computed["reason"],
                    "classification_oracle": (
                        "classify_initialization_snapshot"
                    ),
                    "transcript": initialization_classification_transcript(),
                }
            )
        return vectors

    return {
        "trusted_clock_input": {
            "clock_epoch_hex": pinned_epoch.hex(),
            "now_ms": pinned_now_ms,
            "trusted_clock_value_hex": trusted_clock_value.hex(),
        },
        "T1a": materialize("T1A", t1a_candidates),
        "T1b": materialize("T1B", t1b_candidates),
        "T5": materialize("T5", t5_candidates),
    }


def build_startup_lifecycle_fault_vectors() -> dict[str, Any]:
    stages = [
        "T0_same_rw_zero_row_scan",
        "T1a_format2_bootstrap_full",
        "T1b_uninitialized_metadata_full",
        "T2_d3_s4_s12_cross_row_validation",
        "T3_d4_recovery_full_and_rescan",
        "T4_identity_recovery",
        "T5_trusted_clock_sample",
        "T5_clock_full_commit_and_rescan",
        "T6_durable_health_reconstruction",
        "bearer_open",
        "metrics_entropy",
        "T7_publication_gate",
        "public_runtime_publish",
    ]
    candidates = [
        ("STARTUP_T0_ZERO_ROW_SCAN_FAULT", 0, "NINLIL_E_STORAGE"),
        (
            "STARTUP_T1A_BOOTSTRAP_COMMIT_UNKNOWN",
            1,
            "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
        ),
        (
            "STARTUP_T1B_METADATA_COMMIT_UNKNOWN",
            2,
            "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
        ),
        (
            "STARTUP_T2_CROSS_ROW_VALIDATION_FAULT",
            3,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        (
            "STARTUP_T3_D4_RECOVERY_COMMIT_UNKNOWN",
            4,
            "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
        ),
        (
            "STARTUP_T4_IDENTITY_CONFLICT",
            5,
            "NINLIL_E_CONFLICT",
        ),
        (
            "STARTUP_T5_TRUSTED_CLOCK_FAULT",
            6,
            "NINLIL_E_CLOCK_UNCERTAIN",
        ),
        (
            "STARTUP_T5_COMMIT_UNKNOWN",
            7,
            "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
        ),
        (
            "STARTUP_T6_HEALTH_FAULT",
            8,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        ("STARTUP_BEARER_OPEN_FAULT", 9, "NINLIL_E_WOULD_BLOCK"),
        ("STARTUP_ENTROPY_FAULT", 10, "NINLIL_E_ENTROPY"),
        (
            "STARTUP_T7_PUBLICATION_GATE_FAULT",
            11,
            "NINLIL_E_STORAGE_CORRUPT",
        ),
        ("STARTUP_SUCCESS", None, "NINLIL_OK"),
    ]
    vectors = []
    for vector_id, fault_stage_index, expected_status in candidates:
        if fault_stage_index is None:
            attempted = list(stages)
            completed = list(stages)
        else:
            attempted = stages[: fault_stage_index + 1]
            completed = stages[:fault_stage_index]
        bearer_open = int("bearer_open" in attempted)
        published = int("public_runtime_publish" in completed)
        t2_complete = (
            "T2_d3_s4_s12_cross_row_validation" in completed
        )
        t3_complete = "T3_d4_recovery_full_and_rescan" in completed
        t4_complete = "T4_identity_recovery" in completed
        t5_complete = "T5_clock_full_commit_and_rescan" in completed
        t6_complete = "T6_durable_health_reconstruction" in completed
        t7_complete = "T7_publication_gate" in completed
        if not (t5_complete and t6_complete):
            assert bearer_open == 0
            assert published == 0
        if not t7_complete:
            assert published == 0
        transcript = {
            "ordered_attempted_stages": attempted,
            "ordered_completed_stages": completed,
            "T0_complete": int("T0_same_rw_zero_row_scan" in completed),
            "T1a_complete": int(
                "T1a_format2_bootstrap_full" in completed
            ),
            "T1b_complete": int(
                "T1b_uninitialized_metadata_full" in completed
            ),
            "T2_complete": int(t2_complete),
            "T3_complete": int(t3_complete),
            "T4_complete": int(t4_complete),
            "storage_recovery_complete": int(
                t2_complete and t3_complete and t4_complete
            ),
            "trusted_clock_sample_count": int(
                "T5_trusted_clock_sample" in attempted
            ),
            "T5_commit_attempt_count": int(
                "T5_clock_full_commit_and_rescan" in attempted
            ),
            "T6_health_attempt_count": int(
                "T6_durable_health_reconstruction" in attempted
            ),
            "T5_complete": int(t5_complete),
            "T6_complete": int(t6_complete),
            "T7_complete": int(t7_complete),
            "bearer_open": bearer_open,
            "metrics_entropy": int("metrics_entropy" in attempted),
            "callback": 0,
            "public_handle": published,
            "publish": published,
        }
        vectors.append(
            {
                "id": vector_id,
                "fault_stage_index": fault_stage_index,
                "expected_status": expected_status,
                "transcript": transcript,
            }
        )
    return {
        "canonical_order": stages,
        "invariant": (
            "T0..T4 are separate fault boundaries; before T5 and T6 are "
            "both complete bearer_open is zero; before T7 completes "
            "callback/public_handle/publish are exact zero"
        ),
        "vectors": vectors,
    }


def build_document() -> dict[str, Any]:
    format1_bootstrap = build_bootstrap_vector(1)
    format2_bootstrap = build_bootstrap_vector(2)
    legacy_metadata_group = build_legacy_metadata_group(format1_bootstrap)
    lab_positives = build_lab_positive_vectors(
        format1_bootstrap, legacy_metadata_group
    )
    kind30_companion = build_kind30_matching_transaction(lab_positives)
    kind1_kat = build_kind1_kat()
    kind1_kat["validation_vectors"] = build_kind1_validation_vectors(
        kind1_kat
    )
    export_vectors = build_export_artifact_vectors()
    binding_compatibility_vectors = build_binding_compatibility_vectors(
        format2_bootstrap
    )
    closed_status_oracle_vectors = build_closed_status_oracle_vectors(
        format1_bootstrap,
        format2_bootstrap,
        lab_positives,
    )
    initialization_transition_vectors = (
        build_initialization_transition_vectors(
            format1_bootstrap,
            format2_bootstrap,
            legacy_metadata_group,
        )
    )
    startup_lifecycle_vectors = build_startup_lifecycle_fault_vectors()
    alternate_kind1_kat = build_kind1_kat(
        ALTERNATE_KIND1_FIXTURE_OVERRIDES
    )
    base: dict[str, Any] = {
        "format": "ninlil-domain-store-schema1-runtime-binding-v1",
        "status": "PROPOSED_DOCS_ONLY",
        "authority": {
            "adr": "docs/adr/0022-domain-store-schema1-runtime-binding.md",
            "foundation_abi": "docs/12-foundation-abi.md",
            "domain_store": "docs/17-foundation-domain-store.md",
            "generator": "tools/domain_store_schema1_binding_vector_gen.py",
            "oracle_dependency": "python-standard-library-only; no production C",
        },
        "binding_format_2": {
            "binding_format": 2,
            "payload_bytes": format2_bootstrap["binding_payload_bytes"],
            "value_bytes": format2_bootstrap["binding_value_bytes"],
            "resource_profile_name_ascii": "NINLIL-FOUNDATION-SMALL-1",
            "storage_profile_id_ascii": "NINLIL-DOMAIN-S1",
            "storage_profile_id_hex": "4e494e4c494c2d444f4d41494e2d5331",
            "storage_profile_revision": 1,
            "minimum_writer_generation": 2,
            "rollback_epoch": 1,
            "storage_schema": 1,
            "bootstrap_record_count": format2_bootstrap["record_count"],
            "bootstrap_encoded_key_value_bytes": (
                format2_bootstrap["encoded_key_value_bytes"]
            ),
            "bootstrap_logical_bytes": (
                format2_bootstrap["portable_logical_bytes"]
            ),
            "compatibility_vectors": binding_compatibility_vectors,
        },
        "bootstrap_format_1_lab_arithmetic": format1_bootstrap,
        "bootstrap_format_2_domain_arithmetic": format2_bootstrap,
        "legacy_metadata_group_format_1": legacy_metadata_group,
        "metadata_namespace_boundary_vectors": (
            build_metadata_namespace_boundary_vectors(
                format1_bootstrap,
                format2_bootstrap,
                legacy_metadata_group,
            )
        ),
        "initialization_transitions": [
            {
                "node": "T0",
                "authority": (
                    "fresh READ_WRITE transaction pre-mutation full scan "
                    "namespace row_count == 0"
                ),
                "same_transaction_continuation": "T1a",
                "read_only_upgrade_forbidden": True,
                "mutation_count": 0,
            },
            {
                "node": "T1a",
                "record_count": 17,
                "transaction": (
                    "same READ_WRITE transaction and pre-mutation snapshot "
                    "as T0"
                ),
                "commit_unknown_old": "namespace row_count == 0",
                "commit_unknown_new": "exact format-2 17/17",
            },
            {
                "node": "T1b",
                "record_count": 16,
                "clock_state": "UNINITIALIZED",
                "commit_unknown_old": "metadata 0/16 with exact bootstrap",
                "commit_unknown_new": "metadata exact 16/16 UNINITIALIZED",
            },
            {
                "node": "T5",
                "record_count": 1,
                "old": "exact UNINITIALIZED CLOCK_BASELINE",
                "new": "request-pinned exact TRUSTED CLOCK_BASELINE",
            },
        ],
        "initialization_transition_byte_kats": (
            initialization_transition_vectors
        ),
        "startup_lifecycle_fault_transcripts": startup_lifecycle_vectors,
        "closed_status_oracle_vectors": closed_status_oracle_vectors,
        "namespace_fixture_reference_index": {
            "FORMAT1_BOOTSTRAP_ALL": (
                "bootstrap_format_1_lab_arithmetic."
                "records_unsigned_key_order"
            ),
            "KIND_30_MATCHING_NTS3_TRANSACTION": kind30_companion,
            "LEGACY_METADATA_GROUP_ALL": (
                "legacy_metadata_group_format_1."
                "records_unsigned_key_order"
            ),
            "namespace_row_set_rule": (
                "resolve base row set plus additional refs as a unique-key "
                "map, then sort complete keys unsigned-byte lexicographic; "
                "same-key different-value input is provider corruption"
            ),
            "namespace_row_set_sha256_preimage": (
                "ASCII(NINLIL-LAB-NAMESPACE-FIXTURE-V1)||"
                "record_count:u32||each sorted "
                "(key_length:u16||key||value_length:u32||value)"
            ),
            **{
                f"LAB_KIND_{kind}_ISOLATED_POSITIVE": (
                    f"lab_catalog_34[kind={kind}].isolated_positive"
                )
                for kind in range(18, 35)
            },
        },
        "lab_catalog_34": lab_catalog(
            lab_positives,
            kind30_companion,
            format1_bootstrap,
            format2_bootstrap,
            legacy_metadata_group,
        ),
        "row_mutation_plan": {
            "materialized_for_each_kind": [
                "key_short",
                "key_long",
                "value_short",
                "value_integrity",
            ],
            "future_implementation_extended_acceptance": [
                "value_long",
                "magic_or_prefix",
                "current_version",
                "reserved_nonzero",
                "crc_mismatch",
                "key_body_binding_mismatch",
            ],
            "current_prefix_malformed_expected": "NINLIL_E_STORAGE_CORRUPT",
            "framing_valid_future_expected": "NINLIL_E_UNSUPPORTED",
        },
        "mixed_vector_plan": mixed_vector_plan(
            format1_bootstrap,
            format2_bootstrap,
            legacy_metadata_group,
            lab_positives,
            kind30_companion,
            kind1_kat,
            alternate_kind1_kat,
        ),
        "mixed_support_fixtures": {
            "alternate_kind1_complete_post_records": (
                alternate_kind1_kat["post_records_full_stage_order"]
            ),
            "alternate_kind1_derived": alternate_kind1_kat["derived"],
            "alternate_kind1_aggregate_sha256": (
                alternate_kind1_kat["aggregate_sha256"]
            ),
        },
        "provider_contract_corruption_vectors": (
            provider_contract_corruption_vectors(
                format1_bootstrap,
                format2_bootstrap,
                legacy_metadata_group,
            )
        ),
        "namespace_cross_row_negative_vectors": (
            build_namespace_cross_row_negative_vectors(
                format1_bootstrap,
                format2_bootstrap,
                legacy_metadata_group,
                lab_positives,
            )
        ),
        "status_precedence": [
            "COMMIT_UNKNOWN",
            "CORRUPT",
            "MIXED",
            "UNSUPPORTED",
            "EXACT_LAB",
            "EXACT_DOMAIN",
            "EMPTY",
        ],
        "export_artifact_v1": {
            "magic_hex": EXPORT_MAGIC.hex(),
            "format_version": 1,
            "source_profile": 1,
            "flags": 0,
            "provider_kind": "u16, 1..65535; integration-fixed public identity",
            "provider_schema": "u16, 1..65535; integration-fixed public identity",
            "provider_identity_digest": (
                "32-byte nonzero SHA-256 of canonical "
                "provider-kind/schema/config identity"
            ),
            "provider_identity_digest_preimage": (
                "ASCII(NINLIL-LAB-EXPORT-PROVIDER-V1)||"
                "provider_kind:u16||provider_schema:u16||"
                "provider_config_length:u16||provider_config"
            ),
            "row_order": "strict unsigned-byte lexicographic key order",
            "row_digest_preimage": (
                "ASCII(NINLIL-LAB-EXPORT-ROW-V1)||"
                "key_length:u16||key||value_length:u32||value"
            ),
            "content_digest_preimage": (
                "ASCII(NINLIL-LAB-EXPORT-V1)||all preceding artifact bytes"
            ),
            "completion_magic_hex": EXPORT_COMPLETION_MAGIC.hex(),
            "negative_test_vector_ids": [
                vector["id"]
                for vector in export_vectors["vectors"]
                if vector["fixture_kind"] == "mutation"
            ],
            "exact_vectors": export_vectors,
        },
        "kind1_service_register_kat": kind1_kat,
    }
    canonical = json.dumps(
        base, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    base["integrity"] = {
        "scope": "canonical JSON of this document with integrity omitted",
        "sha256": sha256(canonical).hex(),
    }
    return base


def rendered() -> bytes:
    return (
        json.dumps(
            build_document(), ensure_ascii=False, sort_keys=True, indent=2
        )
        + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        document = build_document()
        catalog = document["lab_catalog_34"]
        assert len(catalog) == 34
        assert sum(len(row["mutations"]) for row in catalog) == 136
        assert all(
            row["isolated_computed_row_status"] == "NINLIL_OK"
            and row["namespace_positive"]["computed_namespace_status"]
            == "EXACT_LAB"
            and all(
                mutation["computed_row_status"]
                == mutation["expected_row_status"]
                and mutation["computed_namespace_status"]
                == mutation["expected_namespace_status"]
                for mutation in row["mutations"]
            )
            for row in catalog
        )
        for collection_name in (
            "metadata_namespace_boundary_vectors",
            "namespace_cross_row_negative_vectors",
        ):
            assert all(
                vector["computed_namespace_status"]
                == vector["expected_namespace_status"]
                for vector in document[collection_name]
            )
        assert all(
            vector["computed_namespace_status"]
            == vector["expected_namespace_status"]
            for vector in document["mixed_vector_plan"]["vectors"]
        )
        assert all(
            vector["computed_namespace_status"]
            == vector["expected_namespace_status"]
            for vector in document["provider_contract_corruption_vectors"]
        )
        kind1_vectors = document["kind1_service_register_kat"][
            "validation_vectors"
        ]["vectors"]
        required_kind1 = {
            "KIND1_QUOTA_PRIMARY_VALUE_DIGEST_MISMATCH",
            "KIND1_QUOTA_INITIAL_COUNTER_NONZERO",
            "KIND1_QUOTA_WINDOW_MISMATCH",
            "KIND1_RESERVATION_PRIMARY_VALUE_DIGEST_MISMATCH",
            "KIND1_RESERVATION_RESOURCE_VECTOR_MISMATCH",
            "KIND1_CAPACITY_POST_INCREMENT_MISMATCH",
            "KIND1_HEAD_INDEX_MEMBER_VALUE_DIGEST_MISMATCH",
        }
        assert required_kind1 <= {vector["id"] for vector in kind1_vectors}
        assert all(vector["row_local_all_ok"] for vector in kind1_vectors)
        transitions = document["initialization_transition_byte_kats"]
        assert len(transitions["T1a"]) == 6
        assert len(transitions["T1b"]) == 6
        assert len(transitions["T5"]) == 5
        for transition_group in ("T1a", "T1b", "T5"):
            assert all(
                vector["computed_classification"]
                == vector["expected_classification"]
                and vector["transcript"]["storage_read_write_begin"] == 0
                and vector["transcript"]["storage_put"] == 0
                and vector["transcript"]["storage_erase"] == 0
                and vector["transcript"]["storage_commit"] == 0
                and vector["transcript"]["bearer_open"] == 0
                and vector["transcript"]["callback"] == 0
                and vector["transcript"]["public_handle"] == 0
                and vector["transcript"]["publish"] == 0
                for vector in transitions[transition_group]
            )
        binding_vectors = document["binding_format_2"][
            "compatibility_vectors"
        ]["vectors"]
        assert len(binding_vectors) == 8
        assert all(
            vector["computed_status"] == vector["expected_status"]
            and vector["computed_reason"] == vector["expected_reason"]
            and vector["transcript"]["storage_read_write_begin"] == 0
            and vector["transcript"]["storage_put"] == 0
            and vector["transcript"]["storage_erase"] == 0
            and vector["transcript"]["storage_commit"] == 0
            and vector["transcript"]["bearer_open"] == 0
            and vector["transcript"]["callback"] == 0
            and vector["transcript"]["public_handle"] == 0
            and vector["transcript"]["publish"] == 0
            for vector in binding_vectors
        )
        format1_bootstrap = document["bootstrap_format_1_lab_arithmetic"]

        def catalog_row(kind: int) -> tuple[bytes, bytes]:
            row = catalog[kind - 1]["isolated_positive"]
            return bytes.fromhex(row["key_hex"]), bytes.fromhex(
                row["value_hex"]
            )

        identity_key, identity_value = catalog_row(2)
        identity_payload = bytearray(decode_nlr1_payload(identity_value, 2))
        identity_payload[0:4] = u32(0x08)
        counter_key, _ = catalog_row(3)
        capacity_key, capacity_value = catalog_row(7)
        capacity = decode_runtime_capacity_semantics(capacity_value)
        m4t_key, m4t_value = catalog_row(31)
        m4t_zero_membership = bytearray(m4t_value)
        m4t_zero_membership[8:16] = bytes(8)
        m4t_zero_membership[-4:] = u32(
            crc32c(m4t_zero_membership[:-4])
        )
        classifier_hardening_negatives = [
            (identity_key, nlr1(2, bytes(identity_payload))),
            (counter_key, nlr1(3, u32(1) + u64(0) + u32(1))),
            (
                capacity_key,
                runtime_capacity_value(
                    1,
                    capacity["limit"],
                    0,
                    0,
                    capacity["limit"] + 1,
                    1,
                ),
            ),
            (m4t_key, bytes(m4t_zero_membership)),
        ]
        assert all(
            classify_lab_row(key, value, format1_bootstrap)["status"]
            == "NINLIL_E_STORAGE_CORRUPT"
            for key, value in classifier_hardening_negatives
        )
        assert (
            classify_lab_row(
                counter_key,
                nlr1(3, u32(1) + u64(U64_MAX) + u32(1)),
                format1_bootstrap,
            )["status"]
            == "NINLIL_OK"
        )
        for vector in document["startup_lifecycle_fault_transcripts"][
            "vectors"
        ]:
            transcript = vector["transcript"]
            canonical_order = document[
                "startup_lifecycle_fault_transcripts"
            ]["canonical_order"]
            fault_index = vector["fault_stage_index"]
            expected_attempted = (
                canonical_order
                if fault_index is None
                else canonical_order[: fault_index + 1]
            )
            expected_completed = (
                canonical_order
                if fault_index is None
                else canonical_order[:fault_index]
            )
            assert (
                transcript["ordered_attempted_stages"]
                == expected_attempted
            )
            assert (
                transcript["ordered_completed_stages"]
                == expected_completed
            )
            assert transcript["T2_complete"] == int(
                "T2_d3_s4_s12_cross_row_validation"
                in expected_completed
            )
            assert transcript["T3_complete"] == int(
                "T3_d4_recovery_full_and_rescan" in expected_completed
            )
            assert transcript["T4_complete"] == int(
                "T4_identity_recovery" in expected_completed
            )
            assert transcript["storage_recovery_complete"] == int(
                transcript["T2_complete"]
                and transcript["T3_complete"]
                and transcript["T4_complete"]
            )
            assert transcript["T7_complete"] == int(
                "T7_publication_gate" in expected_completed
            )
            if not (transcript["T5_complete"] and transcript["T6_complete"]):
                assert transcript["bearer_open"] == 0
                assert transcript["callback"] == 0
                assert transcript["public_handle"] == 0
                assert transcript["publish"] == 0
            if not transcript["T7_complete"]:
                assert transcript["callback"] == 0
                assert transcript["public_handle"] == 0
                assert transcript["publish"] == 0
        startup = document["startup_lifecycle_fault_transcripts"]
        assert startup["canonical_order"] == [
            "T0_same_rw_zero_row_scan",
            "T1a_format2_bootstrap_full",
            "T1b_uninitialized_metadata_full",
            "T2_d3_s4_s12_cross_row_validation",
            "T3_d4_recovery_full_and_rescan",
            "T4_identity_recovery",
            "T5_trusted_clock_sample",
            "T5_clock_full_commit_and_rescan",
            "T6_durable_health_reconstruction",
            "bearer_open",
            "metrics_entropy",
            "T7_publication_gate",
            "public_runtime_publish",
        ]
        expected_startup_ids = {
            "STARTUP_T0_ZERO_ROW_SCAN_FAULT",
            "STARTUP_T1A_BOOTSTRAP_COMMIT_UNKNOWN",
            "STARTUP_T1B_METADATA_COMMIT_UNKNOWN",
            "STARTUP_T2_CROSS_ROW_VALIDATION_FAULT",
            "STARTUP_T3_D4_RECOVERY_COMMIT_UNKNOWN",
            "STARTUP_T4_IDENTITY_CONFLICT",
            "STARTUP_T5_TRUSTED_CLOCK_FAULT",
            "STARTUP_T5_COMMIT_UNKNOWN",
            "STARTUP_T6_HEALTH_FAULT",
            "STARTUP_BEARER_OPEN_FAULT",
            "STARTUP_ENTROPY_FAULT",
            "STARTUP_T7_PUBLICATION_GATE_FAULT",
            "STARTUP_SUCCESS",
        }
        assert len(startup["vectors"]) == 13
        assert {
            vector["id"] for vector in startup["vectors"]
        } == expected_startup_ids
        success = next(
            vector
            for vector in startup["vectors"]
            if vector["id"] == "STARTUP_SUCCESS"
        )
        assert success["transcript"]["T7_complete"] == 1
        assert success["transcript"]["public_handle"] == 1
        assert success["transcript"]["publish"] == 1
        closed_status = document["closed_status_oracle_vectors"]
        assert closed_status["fixture_count"] == 13
        assert closed_status["current_positive_count"] == 3
        assert closed_status["framing_valid_future_count"] == 4
        assert closed_status["malformed_current_count"] == 6
        assert all(
            vector["generator_computed_status"]
            == vector["expected_status"]
            and vector["secondary_row_computed_status"]
            == vector["expected_status"]
            and vector["canonical_publish"] is False
            for vector in closed_status["vectors"]
        )
        for vector_id in (
            "S4_NTS3_SCHEMA2_FUTURE",
            "S4_M4T_VERSION2_FUTURE",
        ):
            vector = next(
                row
                for row in closed_status["vectors"]
                if row["id"] == vector_id
            )
            mutated_key = bytearray.fromhex(vector["key_hex"])
            mutated_key[-1] ^= 1
            assert any(mutated_key)
            assert (
                classify_lab_row(
                    bytes(mutated_key),
                    bytes.fromhex(vector["value_hex"]),
                    format1_bootstrap,
                )["status"]
                == "NINLIL_E_STORAGE_CORRUPT"
            )
        print(
            "self-test ok "
            "lab=34 mutations=136 kind1=12 binding=8 "
            "T1a=6 T1b=6 T5=5 startup=13 closed-status=13 "
            "future-key-binding-mutations=2"
        )
        return 0
    expected = rendered()
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(expected)
        print(f"wrote {OUTPUT}")
        return 0
    if not OUTPUT.exists():
        print(f"missing {OUTPUT}")
        return 1
    actual = OUTPUT.read_bytes()
    if actual != expected:
        print(f"drift {OUTPUT}")
        return 1
    print(
        "ok "
        f"{OUTPUT} sha256={hashlib.sha256(actual).hexdigest()} "
        f"bytes={len(actual)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
