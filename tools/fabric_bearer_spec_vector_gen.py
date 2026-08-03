#!/usr/bin/env python3
"""Independent ADR-0017 Fabric Bearer candidate vector generator.

This file is a specification oracle, not a production codec.  It uses only
Python's standard library and deliberately does not import Ninlil C code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "spec/vectors/fabric-bearer-spec-v1.json"
)

NFL1_HEADER = 584
NFL1_CODEC_CEILING = 2048
NFL1_STRUCTURAL_MIN = 587
NFL1_STRUCTURAL_MAX = 1925
NFL1_SEMANTIC_MAX = 1797
FABRIC_WORKSPACE_BYTES = 198656
REGISTRY_MAX = 16
POLICY_MAX = 64
AUTHORITY_MAX = 64
ATTEMPT_MAX = 64
TRIGGER_MAX = 64

ZERO16 = bytes(16)
ZERO32 = bytes(32)


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


def tagged_digest(tag: bytes, value: bytes) -> bytes:
    return sha256(tag + value)


def pattern(start: int, length: int) -> bytes:
    return bytes((start + index) & 0xFF for index in range(length))


def write_at(buffer: bytearray, offset: int, value: bytes) -> None:
    buffer[offset : offset + len(value)] = value


def common_nfl1_fields() -> dict[str, Any]:
    return {
        "message_kind": 1,
        "message_flags": 0,
        "transaction_id": pattern(0x10, 16),
        "attempt_id": pattern(0x20, 16),
        "event_id": ZERO16,
        "source_runtime_id": pattern(0x30, 16),
        "source_application_id": pattern(0x40, 16),
        "source_device_id": pattern(0x50, 16),
        "source_installation_id": pattern(0x60, 16),
        "source_site_id": pattern(0x70, 16),
        "source_binding_epoch": 7,
        "source_membership_epoch": 9,
        "source_flags": 7,
        "target_runtime_id": pattern(0x80, 16),
        "target_application_id": pattern(0x90, 16),
        "target_device_id": pattern(0xA0, 16),
        "target_installation_id": pattern(0xB0, 16),
        "target_site_id": pattern(0xC0, 16),
        "target_binding_epoch": 11,
        "target_membership_epoch": 13,
        "target_flags": 7,
        "authority_id": pattern(0xD0, 16),
        "authority_term": 17,
        "assignment_epoch": 19,
        "descriptor_revision": 23,
        "descriptor_digest": sha256(b"fabric-vector-descriptor"),
        "schema_major": 1,
        "schema_minor": 0,
        "family": 2,
        "content_digest": sha256(b"fabric-vector-content"),
        "generation": 29,
        "deadline_clock_epoch_id": pattern(0xA1, 16),
        "absolute_effect_deadline_ms": 200000,
        "evidence_grace_ms": 5000,
        "required_evidence": 3,
        "receipt_stage": 0,
        "disposition": 0,
        "effect_certainty": 0,
        "retry_guidance": 0,
        "cancel_kind": 0,
        "retry_delay_ms": 0,
        "evidence_time_clock_epoch_id": ZERO16,
        "evidence_time_now_ms": 0,
        "evidence_time_trust": 0,
        "route_policy_id": pattern(0xF0, 16),
        "route_policy_revision": 31,
        "route_policy_digest": sha256(b"fabric-vector-route-policy"),
        "selected_path_id": pattern(0x01, 16),
        "path_selection_epoch": 37,
        "route_flags": 0,
        "namespace": b"n",
        "service": b"s",
        "schema": b"x",
        "payload": b"",
        "evidence": b"",
    }


def service_identity_digest(fields: dict[str, Any]) -> bytes:
    canonical = (
        u16(len(fields["namespace"]))
        + fields["namespace"]
        + u16(len(fields["service"]))
        + fields["service"]
        + u16(len(fields["schema"]))
        + fields["schema"]
        + u64(fields["descriptor_revision"])
        + u16(1)
        + fields["descriptor_digest"]
        + u16(fields["schema_major"])
        + u16(fields["schema_minor"])
        + u32(fields["family"])
    )
    return tagged_digest(b"NINLIL-FABRIC-SERVICE-IDENTITY-V1", canonical)


def policy_direction_and_traffic(kind: int) -> tuple[int, int]:
    direction = 1 if kind in (1, 4) else 2
    traffic = 2 if kind in (4, 6) else 1
    return direction, traffic


def encode_nfl1(fields: dict[str, Any]) -> bytes:
    namespace = fields["namespace"]
    service = fields["service"]
    schema = fields["schema"]
    payload = fields["payload"]
    evidence = fields["evidence"]
    total_length = NFL1_HEADER + sum(
        len(value) for value in (namespace, service, schema, payload, evidence)
    )
    header = bytearray(NFL1_HEADER)
    write_at(header, 0, b"NFL1")
    write_at(header, 4, u16(1))
    write_at(header, 6, u16(NFL1_HEADER))
    write_at(header, 8, u32(total_length))
    write_at(header, 12, u32(0))
    write_at(header, 16, u32(fields["message_kind"]))
    write_at(header, 20, u32(fields["message_flags"]))
    write_at(header, 24, fields["transaction_id"])
    write_at(header, 40, fields["attempt_id"])
    write_at(header, 56, fields["event_id"])
    write_at(header, 72, fields["source_runtime_id"])
    write_at(header, 88, fields["source_application_id"])
    write_at(header, 104, fields["source_device_id"])
    write_at(header, 120, fields["source_installation_id"])
    write_at(header, 136, fields["source_site_id"])
    write_at(header, 152, u64(fields["source_binding_epoch"]))
    write_at(header, 160, u64(fields["source_membership_epoch"]))
    write_at(header, 168, u32(fields["source_flags"]))
    write_at(header, 172, fields["target_runtime_id"])
    write_at(header, 188, fields["target_application_id"])
    write_at(header, 204, fields["target_device_id"])
    write_at(header, 220, fields["target_installation_id"])
    write_at(header, 236, fields["target_site_id"])
    write_at(header, 252, u64(fields["target_binding_epoch"]))
    write_at(header, 260, u64(fields["target_membership_epoch"]))
    write_at(header, 268, u32(fields["target_flags"]))
    write_at(header, 272, fields["authority_id"])
    write_at(header, 288, u64(fields["authority_term"]))
    write_at(header, 296, u32(fields["assignment_epoch"]))
    write_at(header, 300, u64(fields["descriptor_revision"]))
    write_at(header, 308, u16(1))
    write_at(header, 310, fields["descriptor_digest"])
    write_at(header, 342, u16(fields["schema_major"]))
    write_at(header, 344, u16(fields["schema_minor"]))
    write_at(header, 346, u32(fields["family"]))
    write_at(header, 350, u16(1))
    write_at(header, 352, fields["content_digest"])
    write_at(header, 384, u64(fields["generation"]))
    write_at(header, 392, fields["deadline_clock_epoch_id"])
    write_at(header, 408, u64(fields["absolute_effect_deadline_ms"]))
    write_at(header, 416, u64(fields["evidence_grace_ms"]))
    write_at(header, 424, u32(fields["required_evidence"]))
    write_at(header, 428, u32(fields["receipt_stage"]))
    write_at(header, 432, u32(fields["disposition"]))
    write_at(header, 436, u32(fields["effect_certainty"]))
    write_at(header, 440, u32(fields["retry_guidance"]))
    write_at(header, 444, u32(fields["cancel_kind"]))
    write_at(header, 448, u64(fields["retry_delay_ms"]))
    write_at(header, 456, fields["evidence_time_clock_epoch_id"])
    write_at(header, 472, u64(fields["evidence_time_now_ms"]))
    write_at(header, 480, u32(fields["evidence_time_trust"]))
    write_at(header, 484, fields["route_policy_id"])
    write_at(header, 500, u64(fields["route_policy_revision"]))
    write_at(header, 508, u16(1))
    write_at(header, 510, fields["route_policy_digest"])
    write_at(header, 542, fields["selected_path_id"])
    write_at(header, 558, u64(fields["path_selection_epoch"]))
    write_at(header, 566, u32(fields["route_flags"]))
    write_at(header, 570, u16(len(namespace)))
    write_at(header, 572, u16(len(service)))
    write_at(header, 574, u16(len(schema)))
    write_at(header, 576, u32(len(payload)))
    write_at(header, 580, u32(len(evidence)))
    packet = bytes(header) + namespace + service + schema + payload + evidence
    mutable = bytearray(packet)
    write_at(mutable, 12, u32(crc32c(packet)))
    return bytes(mutable)


def apply_reverse_orientation(fields: dict[str, Any]) -> None:
    original = dict(fields)
    fields["source_runtime_id"] = original["target_runtime_id"]
    fields["source_application_id"] = original["target_application_id"]
    fields["source_device_id"] = original["target_device_id"]
    fields["source_installation_id"] = original["target_installation_id"]
    fields["source_site_id"] = original["target_site_id"]
    fields["source_binding_epoch"] = original["target_binding_epoch"]
    fields["source_membership_epoch"] = original["target_membership_epoch"]
    fields["source_flags"] = original["target_flags"]
    fields["target_runtime_id"] = original["source_runtime_id"]
    fields["target_application_id"] = original["source_application_id"]
    fields["target_device_id"] = original["source_device_id"]
    fields["target_installation_id"] = original["source_installation_id"]
    fields["target_site_id"] = original["source_site_id"]
    fields["target_binding_epoch"] = original["source_binding_epoch"]
    fields["target_membership_epoch"] = original["source_membership_epoch"]
    fields["target_flags"] = original["source_flags"]


def nfl1_case(
    kind: int,
    maximal: bool = False,
    receipt_stage: int = 3,
) -> tuple[dict[str, Any], bytes]:
    fields = common_nfl1_fields()
    fields["message_kind"] = kind
    if kind in (4, 6):
        fields["attempt_id"] = pattern(0x28, 16)
    if maximal:
        fields["namespace"] = b"n" * 63
        fields["service"] = b"s" * 63
        fields["schema"] = b"x" * 63
    if kind == 1:
        fields["payload"] = pattern(0x41, 1024) if maximal else b""
    elif kind == 2:
        fields["receipt_stage"] = receipt_stage
        fields["evidence_time_clock_epoch_id"] = pattern(0x11, 16)
        fields["evidence_time_now_ms"] = 199000
        fields["evidence_time_trust"] = 1
        fields["evidence"] = pattern(0x21, 128) if maximal else b""
    elif kind == 3:
        fields["disposition"] = 1
        fields["effect_certainty"] = 1
        fields["retry_guidance"] = 1
        fields["retry_delay_ms"] = 250
    elif kind == 4:
        pass
    elif kind == 5:
        pass
    elif kind == 6:
        fields["cancel_kind"] = 1
    else:
        raise ValueError("unknown message kind")
    if kind in (2, 3, 5, 6):
        apply_reverse_orientation(fields)
    packet = encode_nfl1(fields)
    return fields, packet


def projected_foundation(fields: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": fields["message_kind"],
        "message_flags": fields["message_flags"],
        "transaction_id_hex": fields["transaction_id"].hex(),
        "attempt_id_hex": fields["attempt_id"].hex(),
        "event_id_hex": fields["event_id"].hex(),
        "source_runtime_id_hex": fields["source_runtime_id"].hex(),
        "source_application_id_hex": fields["source_application_id"].hex(),
        "source_device_id_hex": fields["source_device_id"].hex(),
        "source_installation_id_hex": fields["source_installation_id"].hex(),
        "source_site_id_hex": fields["source_site_id"].hex(),
        "source_binding_epoch": fields["source_binding_epoch"],
        "source_membership_epoch": fields["source_membership_epoch"],
        "source_flags": fields["source_flags"],
        "target_runtime_id_hex": fields["target_runtime_id"].hex(),
        "target_application_id_hex": fields["target_application_id"].hex(),
        "target_device_id_hex": fields["target_device_id"].hex(),
        "target_installation_id_hex": fields["target_installation_id"].hex(),
        "target_site_id_hex": fields["target_site_id"].hex(),
        "target_binding_epoch": fields["target_binding_epoch"],
        "target_membership_epoch": fields["target_membership_epoch"],
        "target_flags": fields["target_flags"],
        "descriptor_revision": fields["descriptor_revision"],
        "descriptor_digest_algorithm": 1,
        "descriptor_digest_hex": fields["descriptor_digest"].hex(),
        "schema_major": fields["schema_major"],
        "schema_minor": fields["schema_minor"],
        "family": fields["family"],
        "content_digest_algorithm": 1,
        "content_digest_hex": fields["content_digest"].hex(),
        "generation": fields["generation"],
        "deadline_clock_epoch_id_hex": fields[
            "deadline_clock_epoch_id"
        ].hex(),
        "absolute_effect_deadline_ms": fields[
            "absolute_effect_deadline_ms"
        ],
        "evidence_grace_ms": fields["evidence_grace_ms"],
        "required_evidence": fields["required_evidence"],
        "receipt_stage": fields["receipt_stage"],
        "disposition": fields["disposition"],
        "effect_certainty": fields["effect_certainty"],
        "retry_guidance": fields["retry_guidance"],
        "cancel_kind": fields["cancel_kind"],
        "retry_delay_ms": fields["retry_delay_ms"],
        "evidence_time_clock_epoch_id_hex": fields[
            "evidence_time_clock_epoch_id"
        ].hex(),
        "evidence_time_now_ms": fields["evidence_time_now_ms"],
        "evidence_time_trust": fields["evidence_time_trust"],
        "namespace_ascii": fields["namespace"].decode("ascii"),
        "service_ascii": fields["service"].decode("ascii"),
        "schema_ascii": fields["schema"].decode("ascii"),
        "payload_hex": fields["payload"].hex(),
        "evidence_hex": fields["evidence"].hex(),
    }


def record_value(magic: bytes, revision: int, payload: bytes) -> bytes:
    header = magic + u16(1) + u16(24) + u32(24 + len(payload)) + u64(revision) + u32(0)
    value = header + payload
    mutable = bytearray(value)
    write_at(mutable, 20, u32(crc32c(value)))
    return bytes(mutable)


def registry_record() -> tuple[bytes, bytes, dict[str, Any]]:
    instance_id = pattern(0x61, 16)
    descriptor_digest = sha256(b"fabric-registry-descriptor-v1")
    config_digest = sha256(b"fabric-registry-config-v1")
    payload = (
        instance_id
        + u32(2)
        + u32(3)
        + u32(0x0000006F)
        + u64(1)
        + descriptor_digest
        + pattern(0x21, 16)
        + u32(0x0000000F)
        + sha256(b"fabric-security-binding-v1")
        + u64(5)
        + pattern(0xA1, 16)
        + u64(300000)
        + sha256(b"fabric-security-attestation-v1")
        + pattern(0x31, 16)
        + pattern(0x41, 16)
        + sha256(b"fabric-attachment-binding-v1")
        + u32(1925)
        + u32(1925)
        + u16(10)
        + u16(20)
        + u16(8)
        + u16(0)
        + u64(7)
        + pattern(0xA1, 16)
        + u8(1)
        + u8(1)
        + u16(0)
        + u64(250000)
        + u16(1)
        + u16(0)
        + u32(1)
        + u64(1)
        + config_digest
    )
    assert len(payload) == 348
    key = b"FBR1" + instance_id
    value = record_value(b"FBR1", 1, payload)
    return key, value, {
        "payload_bytes": 348,
        "value_bytes": 372,
        "descriptor_digest_hex": descriptor_digest.hex(),
        "peer_nfl1_version": 1,
        "peer_fabric_capability_flags": 1,
        "configuration_digest_hex": config_digest.hex(),
    }


def policy_payload_with_zero_digest(
    scope_selector: int = 2,
    policy_id_start: int = 0x71,
    authority_mode: int = 1,
    revision: int = 3,
    candidates: tuple[tuple[bytes, int, int, int], ...] | None = None,
) -> bytes:
    selector_fields = common_nfl1_fields()
    if candidates is None:
        candidates = (
            (pattern(0x01, 16), 20, 0, 1),
            (pattern(0x61, 16), 10, 0, 1),
        )
    entries = []
    for instance_id, rank, flags, units in candidates:
        entries.append(
            instance_id + u16(rank) + u16(flags) + u16(units) + u16(0)
        )
    entries.extend([bytes(24)] * (8 - len(entries)))
    payload = (
        pattern(policy_id_start, 16)
        + u64(revision)
        + ZERO32
        + service_identity_digest(selector_fields)
        + u32(2)
        + u32(1)
        + u16(1)
        + u16(scope_selector)
        + u32(0x00000002)
        + u32(0x0000000F)
        + u16(50)
        + u16(50)
        + u32(587)
        + u8(authority_mode)
        + bytes(3)
        + u64(100)
        + u16(len(candidates))
        + u16(0)
        + u32(0)
        + b"".join(entries)
    )
    assert len(payload) == 328
    return payload


def owner_tuple_canonical() -> bytes:
    value = (
        pattern(0x81, 16)
        + u64(11)
        + pattern(0x91, 16)
        + pattern(0xA1, 16)
        + u32(1)
        + pattern(0xB1, 16)
        + u64(13)
        + pattern(0xC1, 16)
        + u64(17)
        + sha256(b"fabric-owner-e2e-binding-v1")
        + pattern(0xD1, 16)
        + u64(300000)
        + sha256(b"fabric-owner-handoff-v1")
        + u32(0)
    )
    assert len(value) == 200
    return value


def owner_tuple_digest() -> bytes:
    return tagged_digest(
        b"NINLIL-FABRIC-OWNER-TUPLE-V1", owner_tuple_canonical()
    )


def authority_record(
    policy_digest: bytes,
    scope_selector: int = 2,
    authority_state: int = 1,
    binding_start: int = 0xB8,
    policy_id_start: int = 0x71,
    policy_revision: int = 3,
) -> tuple[bytes, bytes, dict[str, Any]]:
    fields = common_nfl1_fields()
    binding_id = pattern(binding_start, 16)
    if scope_selector == 1:
        endpoint_runtime_id = fields["source_runtime_id"]
    elif scope_selector == 2:
        endpoint_runtime_id = fields["target_runtime_id"]
    else:
        raise ValueError("unknown scope selector")
    if authority_state == 0:
        authority_id = ZERO16
        authority_term = 0
        assignment_epoch = 0
        owner_scope_id = ZERO16
        tuple_digest = ZERO32
        tuple_canonical = bytes(200)
        authority_clock_epoch_id = ZERO16
        lease_expires_at_ms = 0
    elif authority_state == 1:
        authority_id = fields["authority_id"]
        authority_term = fields["authority_term"]
        assignment_epoch = fields["assignment_epoch"]
        owner_scope_id = pattern(0x81, 16)
        tuple_digest = owner_tuple_digest()
        tuple_canonical = owner_tuple_canonical()
        authority_clock_epoch_id = pattern(0xD1, 16)
        lease_expires_at_ms = 300000
    else:
        raise ValueError("unknown authority state")
    payload = (
        binding_id
        + service_identity_digest(fields)
        + u32(fields["family"])
        + u32(1)
        + u16(1)
        + u16(scope_selector)
        + endpoint_runtime_id
        + fields["target_runtime_id"]
        + fields["target_application_id"]
        + pattern(policy_id_start, 16)
        + u64(policy_revision)
        + policy_digest
        + u32(authority_state)
        + authority_id
        + u64(authority_term)
        + u32(assignment_epoch)
        + u32(0)
        + owner_scope_id
        + tuple_digest
        + tuple_canonical
        + authority_clock_epoch_id
        + u64(lease_expires_at_ms)
        + u64(11)
        + u64(0)
    )
    assert len(payload) == 488
    key = b"FBC1" + binding_id
    value = record_value(b"FBC1", 11, payload)
    return key, value, {
        "payload_bytes": 488,
        "value_bytes": 512,
        "service_identity_digest_hex": service_identity_digest(fields).hex(),
        "scope_selector": scope_selector,
        "endpoint_runtime_id_hex": endpoint_runtime_id.hex(),
        "target_runtime_id_hex": fields["target_runtime_id"].hex(),
        "authority_state": "ABSENT" if authority_state == 0 else "BOUND",
        "owner_tuple_canonical_hex": tuple_canonical.hex(),
        "owner_tuple_digest_hex": tuple_digest.hex(),
        "assignment_revision": 11,
    }


def policy_record(
    scope_selector: int = 2,
    policy_id_start: int = 0x71,
    authority_mode: int = 1,
    revision: int = 3,
    candidates: tuple[tuple[bytes, int, int, int], ...] | None = None,
) -> tuple[bytes, bytes, dict[str, Any]]:
    payload = bytearray(
        policy_payload_with_zero_digest(
            scope_selector,
            policy_id_start,
            authority_mode,
            revision,
            candidates,
        )
    )
    digest = tagged_digest(b"NINLIL-FABRIC-POLICY-V1", bytes(payload))
    write_at(payload, 24, digest)
    key = b"FBP1" + pattern(policy_id_start, 16) + u64(revision)
    value = record_value(b"FBP1", 1, bytes(payload))
    return key, value, {
        "payload_bytes": 328,
        "value_bytes": 352,
        "canonical_digest_hex": digest.hex(),
        "scope_selector": scope_selector,
        "authority_mode": (
            "ABSENT_ALLOWED" if authority_mode == 0 else "BOUND_REQUIRED"
        ),
        "revision": revision,
        "candidate_count": (
            2 if candidates is None else len(candidates)
        ),
        "selected_sort_key": [
            10,
            10,
            20,
            pattern(0x61, 16).hex(),
        ],
        "selected_instance_id_hex": pattern(0x61, 16).hex(),
    }


def foundation_message_digest(nfl1_packet: bytes) -> bytes:
    normalized = bytearray(nfl1_packet)
    write_at(normalized, 12, u32(0))
    write_at(normalized, 272, bytes(28))
    write_at(normalized, 484, bytes(86))
    return sha256(b"NINLIL-FABRIC-FOUNDATION-MESSAGE-V1" + bytes(normalized))


def local_dispatch_id(key: bytes) -> bytes:
    return tagged_digest(b"NINLIL-FABRIC-LOCAL-DISPATCH-V1", key)


def attempt_record(
    nfl1_packet: bytes,
    policy_digest: bytes,
    registry_record_digest: bytes,
    state: int = 2,
    record_revision: int = 3,
    terminal_revision: int = 0,
    retry_expires_at_ms: int = 200000,
    permit_generation: int = 0,
    permit_expires_at_ms: int = 450000,
    permit_claim_state: int = 1,
) -> tuple[bytes, bytes, dict[str, Any]]:
    fields = decode_nfl1_identity(nfl1_packet)
    transaction_id = fields["transaction_id"]
    attempt_id = fields["attempt_id"]
    message_kind = fields["message_kind"]
    slot = fields["response_slot"]
    deadline_clock_epoch_id = nfl1_packet[392:408]
    message_deadline_ms = struct.unpack(">Q", nfl1_packet[408:416])[0]
    message_digest = foundation_message_digest(nfl1_packet)
    key = (
        b"FBA1"
        + transaction_id
        + attempt_id
        + u32(message_kind)
        + u32(slot)
        + message_digest
    )
    permit_id = sha256(
        b"NINLIL-FABRIC-PERMIT-V1" + key + u32(permit_generation)
    )[:16]
    payload = (
        transaction_id
        + attempt_id
        + u32(message_kind)
        + u32(slot)
        + u32(state)
        + message_digest
        + pattern(0x71, 16)
        + u64(3)
        + policy_digest
        + pattern(0x61, 16)
        + u64(37)
        + u32(0)
        + u32(1)
        + pattern(0xD0, 16)
        + u64(17)
        + u32(19)
        + pattern(0x81, 16)
        + owner_tuple_digest()
        + u64(1)
        + registry_record_digest
        + sha256(b"fabric-registry-descriptor-v1")
        + pattern(0x21, 16)
        + u64(5)
        + pattern(0xA1, 16)
        + sha256(b"fabric-security-attestation-v1")
        + u64(300000)
        + pattern(0x31, 16)
        + pattern(0x41, 16)
        + sha256(b"fabric-attachment-binding-v1")
        + u64(7)
        + pattern(0xA1, 16)
        + u8(1)
        + bytes(7)
        + u64(250000)
        + attempt_id
        + deadline_clock_epoch_id
        + u64(message_deadline_ms)
        + u32(len(nfl1_packet))
        + sha256(nfl1_packet)
        + pattern(0xA1, 16)
        + u64(400000)
        + deadline_clock_epoch_id
        + u64(retry_expires_at_ms)
        + local_dispatch_id(key)
        + u64(terminal_revision)
        + permit_id
        + u64(permit_expires_at_ms)
        + u32(permit_claim_state)
    )
    assert len(payload) == 688
    value = record_value(b"FBA1", record_revision, payload)
    return key, value, {
        "payload_bytes": 688,
        "value_bytes": 712,
        "message_kind": message_kind,
        "response_slot": slot,
        "state": state,
        "record_revision": record_revision,
        "terminal_revision": terminal_revision,
        "foundation_message_digest_hex": message_digest.hex(),
        "local_dispatch_id_hex": local_dispatch_id(key).hex(),
        "registry_record_digest_hex": registry_record_digest.hex(),
        "reservation_id_hex": attempt_id.hex(),
        "first_admit_ms": 170000,
        "retry_lifetime_cap_ms": 30000,
        "message_deadline_ms": message_deadline_ms,
        "availability_expires_at_ms": 250000,
        "retry_lifetime_clock_epoch_id_hex": deadline_clock_epoch_id.hex(),
        "retry_expires_at_ms": retry_expires_at_ms,
        "permit_clock_epoch_id_hex": deadline_clock_epoch_id.hex(),
        "permit_id_hex": permit_id.hex(),
        "permit_expires_at_ms": permit_expires_at_ms,
        "permit_claim_state": permit_claim_state,
        "nfl1_encoded_hex": nfl1_packet.hex(),
        "nfl1_length": len(nfl1_packet),
        "nfl1_sha256_hex": sha256(nfl1_packet).hex(),
    }


def decode_nfl1_identity(nfl1_packet: bytes) -> dict[str, Any]:
    kind = struct.unpack(">I", nfl1_packet[16:20])[0]
    slot = 0
    if kind == 2:
        slot = struct.unpack(">I", nfl1_packet[428:432])[0]
    elif kind == 3:
        slot = struct.unpack(">I", nfl1_packet[432:436])[0]
    elif kind == 6:
        slot = struct.unpack(">I", nfl1_packet[444:448])[0]
    return {
        "message_kind": kind,
        "response_slot": slot,
        "transaction_id": nfl1_packet[24:40],
        "attempt_id": nfl1_packet[40:56],
    }


def trigger_record(kind: int = 1) -> tuple[bytes, bytes, dict[str, Any]]:
    transaction_id = pattern(0x10, 16)
    triggering_attempt = pattern(0x28 if kind == 4 else 0x20, 16)
    payload = (
        transaction_id
        + triggering_attempt
        + u32(kind)
        + u32(1)
        + pattern(0x80, 16)
        + pattern(0x81, 16)
        + pattern(0xD0, 16)
        + u64(17)
        + u32(19)
        + u32(0)
        + owner_tuple_digest()
        + pattern(0x71, 16)
        + u64(3)
        + sha256(b"NINLIL-FABRIC-POLICY-V1" + policy_payload_with_zero_digest())
        + pattern(0xA1, 16)
        + u64(400000)
        + u64(0)
    )
    assert len(payload) == 224
    key = b"FBT1" + transaction_id + triggering_attempt + u32(kind)
    value = record_value(b"FBT1", 1, payload)
    return key, value, {
        "payload_bytes": 224,
        "value_bytes": 248,
        "triggering_kind": kind,
        "terminal_revision": 0,
    }


def meta_record(
    record_revision: int = 1,
    outer_epoch: int = 1,
    outer_available: int = 0,
) -> tuple[bytes, bytes, dict[str, Any]]:
    payload = (
        u16(1)
        + u16(1)
        + u16(1)
        + u16(0)
        + u64(1)
        + u64(0)
        + u64(outer_epoch)
        + u32(outer_available)
        + u32(0)
    )
    assert len(payload) == 40
    key = b"FBM1"
    value = record_value(b"FBM1", record_revision, payload)
    return key, value, {
        "payload_bytes": 40,
        "value_bytes": 64,
        "outer_availability_epoch": outer_epoch,
        "outer_available": outer_available,
    }


def vector_entry(vector_id: str, key: bytes, value: bytes, facts: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": vector_id,
        "key_hex": key.hex(),
        "key_bytes": len(key),
        "value_hex": value.hex(),
        "value_bytes": len(value),
        "crc32c_hex": value[20:24].hex(),
        "sha256_hex": sha256(key + value).hex(),
        "facts": facts,
    }


def mutate(packet: bytes, offset: int, replacement: bytes) -> bytes:
    value = bytearray(packet)
    write_at(value, offset, replacement)
    return bytes(value)


def repair_record_crc(value: bytes) -> bytes:
    mutable = bytearray(value)
    write_at(mutable, 20, u32(0))
    write_at(mutable, 20, u32(crc32c(bytes(mutable))))
    return bytes(mutable)


def repair_policy_canonical_digest(value: bytes) -> bytes:
    mutable = bytearray(value)
    write_at(mutable, 24 + 24, ZERO32)
    digest = tagged_digest(
        b"NINLIL-FABRIC-POLICY-V1", bytes(mutable[24:])
    )
    write_at(mutable, 24 + 24, digest)
    return repair_record_crc(bytes(mutable))


def negative_entry(
    vector_id: str,
    value: bytes,
    expected: str,
    recompute_crc: bool = False,
) -> dict[str, Any]:
    if recompute_crc and len(value) >= NFL1_HEADER:
        mutable = bytearray(value)
        write_at(mutable, 12, u32(0))
        write_at(mutable, 12, u32(crc32c(bytes(mutable))))
        value = bytes(mutable)
    return {
        "id": vector_id,
        "encoded_hex": value.hex(),
        "encoded_length": len(value),
        "expected": expected,
        "sha256_hex": sha256(value).hex(),
    }


def selection_policy_rows(
    *,
    scope_selector: int = 2,
    policy_id_start: int = 0x71,
    authority_mode: int = 1,
    revision_chain: tuple[int, ...] = (1, 2, 3),
    candidates: tuple[tuple[bytes, int, int, int], ...],
) -> tuple[dict[str, dict[str, str]], bytes]:
    rows: dict[str, dict[str, str]] = {}
    current_digest = ZERO32
    for revision in revision_chain:
        key, value, facts = policy_record(
            scope_selector=scope_selector,
            policy_id_start=policy_id_start,
            authority_mode=authority_mode,
            revision=revision,
            candidates=candidates,
        )
        rows[f"FBP1-REVISION-{revision}"] = {
            "key_hex": key.hex(),
            "value_hex": value.hex(),
        }
        current_digest = bytes.fromhex(facts["canonical_digest_hex"])
    return rows, current_digest


def replace_selection_policy_rows(
    snapshot: dict[str, Any],
    *,
    scope_selector: int,
    policy_id_start: int,
    authority_mode: int,
    revision_chain: tuple[int, ...],
    candidates: tuple[tuple[bytes, int, int, int], ...],
) -> bytes:
    for name in tuple(snapshot["durable_rows"]):
        if name.startswith("FBP1"):
            del snapshot["durable_rows"][name]
    rows, digest = selection_policy_rows(
        scope_selector=scope_selector,
        policy_id_start=policy_id_start,
        authority_mode=authority_mode,
        revision_chain=revision_chain,
        candidates=candidates,
    )
    snapshot["durable_rows"].update(rows)
    return digest


def rewrite_selection_registry(
    durable: dict[str, str], registry: dict[str, Any]
) -> dict[str, str]:
    key = bytearray.fromhex(durable["key_hex"])
    value = bytearray.fromhex(durable["value_hex"])
    instance_id = bytes.fromhex(registry["instance_id_hex"])
    key[4:20] = instance_id
    value[12:20] = u64(registry["record_revision"])
    value[24:40] = instance_id
    value[40:44] = u32(
        {"LOOPBACK": 1, "WIFI": 2, "USB": 3, "RF": 4}[
            registry["link_kind"]
        ]
    )
    value[44:48] = u32(registry["direction_mask"])
    value[48:52] = u32(registry["capability_flags"])
    value[108:112] = u32(registry["security_capability_flags"])
    value[144:152] = u64(registry["attestation_epoch"])
    value[152:168] = bytes.fromhex(
        registry["attestation_clock_epoch_id_hex"]
    )
    value[168:176] = u64(registry["attestation_expires_at_ms"])
    value[208:224] = bytes.fromhex(
        registry["authenticated_peer_runtime_id_hex"]
    )
    value[224:240] = bytes.fromhex(
        registry["attachment_authority_id_hex"]
    )
    value[240:272] = bytes.fromhex(
        registry["attachment_binding_digest_hex"]
    )
    value[272:276] = u32(registry["maximum_packet_bytes"])
    value[276:280] = u32(registry["maximum_transfer_bytes"])
    value[280:282] = u16(registry["latency_class"])
    value[282:284] = u16(registry["cost_class"])
    value[284:286] = u16(registry["reservation_capacity"])
    value[288:296] = u64(registry["availability_epoch"])
    value[296:312] = bytes.fromhex(
        registry["availability_clock_epoch_id_hex"]
    )
    value[312] = registry["availability_state"]
    value[313] = {"ACTIVE": 1, "DRAINING": 2}[registry["lifecycle"]]
    value[316:324] = u64(registry["availability_expires_at_ms"])
    value[324:326] = u16(registry["peer_nfl1_version"])
    value[328:332] = u32(registry["peer_fabric_capability_flags"])
    value = bytearray(repair_record_crc(bytes(value)))
    return {"key_hex": key.hex(), "value_hex": value.hex()}


def rewrite_selection_authority_policy(
    durable: dict[str, str],
    *,
    policy_id: bytes,
    policy_revision: int,
    policy_digest: bytes,
) -> dict[str, str]:
    value = bytearray.fromhex(durable["value_hex"])
    value[132:148] = policy_id
    value[148:156] = u64(policy_revision)
    value[156:188] = policy_digest
    value = bytearray(repair_record_crc(bytes(value)))
    return {
        "key_hex": durable["key_hex"],
        "value_hex": value.hex(),
    }


def selection_baseline() -> dict[str, Any]:
    fields = common_nfl1_fields()
    service_digest_hex = service_identity_digest(fields).hex()
    meta_key, meta_value, _ = meta_record(
        record_revision=2, outer_epoch=2, outer_available=1
    )
    registry_key, registry_value, _ = registry_record()
    selected_candidates = ((pattern(0x61, 16), 10, 0, 1),)
    policy_rows, policy_digest = selection_policy_rows(
        candidates=selected_candidates
    )
    policy_digest_hex = policy_digest.hex()
    authority_key, authority_value, _ = authority_record(
        policy_digest, scope_selector=2
    )
    instance_id_hex = pattern(0x61, 16).hex()
    snapshot = {
        "durable_rows": {
            "FBM1": {
                "key_hex": meta_key.hex(),
                "value_hex": meta_value.hex(),
            },
            "FBR1": {
                "key_hex": registry_key.hex(),
                "value_hex": registry_value.hex(),
            },
            **policy_rows,
            "FBC1": {
                "key_hex": authority_key.hex(),
                "value_hex": authority_value.hex(),
            },
        },
        "projection_rule": (
            "decode exact durable_rows, then apply only the declared "
            "single semantic mutation"
        ),
        "meta": {
            "source_record_id": "FABRIC-STORE-META-AVAILABLE",
            "record_revision": 2,
            "outer_availability_epoch": 2,
            "outer_available": 1,
        },
        "query": {
            "service_identity_digest_hex": service_digest_hex,
            "family": fields["family"],
            "direction": 1,
            "traffic_class": 1,
            "source_runtime_id_hex": fields["source_runtime_id"].hex(),
            "target_runtime_id_hex": fields["target_runtime_id"].hex(),
            "target_application_id_hex": fields["target_application_id"].hex(),
            "packet_bytes": NFL1_STRUCTURAL_MIN,
            "transfer_bytes": NFL1_STRUCTURAL_MIN,
            "deadline_clock_epoch_id_hex": pattern(0xA1, 16).hex(),
            "admission_clock_epoch_id_hex": pattern(0xA1, 16).hex(),
            "deadline_ms": 200000,
            "now_ms": 100000,
            "required_capability_flags": 0x00000002,
            "requires_sleep_compatible": True,
            "required_security_flags": 0x0000000F,
            "requires_custody": True,
            "requires_evidence": True,
            "authenticated_peer_runtime_id_hex": pattern(0x31, 16).hex(),
            "attachment_authority_id_hex": pattern(0x41, 16).hex(),
            "attachment_binding_digest_hex": sha256(
                b"fabric-attachment-binding-v1"
            ).hex(),
            "attestation_clock_epoch_id_hex": pattern(0xA1, 16).hex(),
            "availability_clock_epoch_id_hex": pattern(0xA1, 16).hex(),
            "authority_clock_epoch_id_hex": pattern(0xD1, 16).hex(),
            "rf_permit_valid": True,
            "rf_mapping_accepted": True,
        },
        "policies": [
            {
                "source_record_id": "FABRIC-STORE-POLICY-1",
                "policy_id_hex": pattern(0x71, 16).hex(),
                "revision": 3,
                "revision_chain": [1, 2, 3],
                "canonical_digest_hex": policy_digest_hex,
                "service_identity_digest_hex": service_digest_hex,
                "family": fields["family"],
                "direction": 1,
                "traffic_class": 1,
                "scope_selector": "TARGET_RUNTIME",
                "required_capability_flags": 0x00000002,
                "required_security_flags": 0x0000000F,
                "maximum_latency_class": 50,
                "maximum_cost_class": 50,
                "minimum_packet_bytes": NFL1_STRUCTURAL_MIN,
                "authority_mode": "BOUND_REQUIRED",
                "deadline_guard_ms": 100,
                "candidates": [
                    {
                        "instance_id_hex": instance_id_hex,
                        "rank": 10,
                        "reservation_units": 1,
                    }
                ],
            }
        ],
        "registry": [
            {
                "source_record_id": "FABRIC-STORE-REGISTRY-1",
                "instance_id_hex": instance_id_hex,
                "record_revision": 1,
                "lifecycle": "ACTIVE",
                "direction_mask": 3,
                "link_kind": "LOOPBACK",
                "capability_flags": 0x0000006F,
                "maximum_packet_bytes": NFL1_STRUCTURAL_MAX,
                "maximum_transfer_bytes": NFL1_STRUCTURAL_MAX,
                "latency_class": 10,
                "cost_class": 20,
                "reservation_capacity": 8,
                "security_capability_flags": 0x0000000F,
                "peer_nfl1_version": 1,
                "peer_fabric_capability_flags": 1,
                "authenticated_peer_runtime_id_hex": pattern(0x31, 16).hex(),
                "attachment_authority_id_hex": pattern(0x41, 16).hex(),
                "attachment_binding_digest_hex": sha256(
                    b"fabric-attachment-binding-v1"
                ).hex(),
                "attestation_epoch": 5,
                "attestation_clock_epoch_id_hex": pattern(0xA1, 16).hex(),
                "attestation_expires_at_ms": 300000,
                "availability_epoch": 7,
                "availability_clock_epoch_id_hex": pattern(0xA1, 16).hex(),
                "availability_state": 1,
                "availability_expires_at_ms": 250000,
            }
        ],
        "authorities": [
            {
                "source_record_id": "FABRIC-STORE-AUTHORITY-TARGET-RUNTIME",
                "binding_id_hex": pattern(0xB8, 16).hex(),
                "service_identity_digest_hex": service_digest_hex,
                "family": fields["family"],
                "direction": 1,
                "traffic_class": 1,
                "scope_selector": "TARGET_RUNTIME",
                "endpoint_runtime_id_hex": fields["target_runtime_id"].hex(),
                "target_runtime_id_hex": fields["target_runtime_id"].hex(),
                "target_application_id_hex": fields[
                    "target_application_id"
                ].hex(),
                "policy_id_hex": pattern(0x71, 16).hex(),
                "policy_revision": 3,
                "policy_digest_hex": policy_digest_hex,
                "authority_state": "BOUND",
                "authority_clock_epoch_id_hex": pattern(0xD1, 16).hex(),
                "lease_expires_at_ms": 300000,
            }
        ],
        "active_attempts": [],
    }
    snapshot["durable_rows"]["FBR1"] = rewrite_selection_registry(
        snapshot["durable_rows"]["FBR1"],
        snapshot["registry"][0],
    )
    return snapshot


def select_candidate(snapshot: dict[str, Any]) -> dict[str, Any]:
    query = snapshot["query"]
    if snapshot["meta"]["outer_available"] != 1:
        return {
            "resolution": "NO_ELIGIBLE_PATH",
            "primary_rejection": "META_OUTER_UNAVAILABLE",
            "evaluated": [],
            "eligible_instance_ids_hex": [],
            "selected_instance_id_hex": None,
        }

    for policy in snapshot["policies"]:
        chain = policy["revision_chain"]
        if (
            not chain
            or chain[-1] != policy["revision"]
            or any(right != left + 1 for left, right in zip(chain, chain[1:]))
        ):
            return {
                "resolution": "CORRUPT",
                "primary_rejection": "POLICY_REVISION_GAP",
                "evaluated": [],
                "eligible_instance_ids_hex": [],
                "selected_instance_id_hex": None,
            }

    matches = [
        policy
        for policy in snapshot["policies"]
        if (
            policy["service_identity_digest_hex"]
            == query["service_identity_digest_hex"]
            and policy["family"] == query["family"]
            and policy["direction"] == query["direction"]
            and policy["traffic_class"] == query["traffic_class"]
        )
    ]
    if not matches:
        return {
            "resolution": "NO_POLICY",
            "primary_rejection": "POLICY_NO_MATCH",
            "evaluated": [],
            "eligible_instance_ids_hex": [],
            "selected_instance_id_hex": None,
        }
    if len(matches) != 1:
        return {
            "resolution": "CORRUPT",
            "primary_rejection": "POLICY_AMBIGUOUS",
            "evaluated": [],
            "eligible_instance_ids_hex": [],
            "selected_instance_id_hex": None,
        }

    policy = matches[0]
    selector = policy["scope_selector"]
    endpoint_hex = (
        query["source_runtime_id_hex"]
        if selector == "SOURCE_RUNTIME"
        else query["target_runtime_id_hex"]
    )
    evaluated = []
    eligible = []
    for policy_candidate in policy["candidates"]:
        instance_id_hex = policy_candidate["instance_id_hex"]
        reasons = []
        registry_matches = [
            row
            for row in snapshot["registry"]
            if row["instance_id_hex"] == instance_id_hex
        ]
        registry = registry_matches[0] if len(registry_matches) == 1 else None
        if registry is None:
            reasons.append(
                "REGISTRY_JOIN_MISSING"
                if not registry_matches
                else "REGISTRY_JOIN_AMBIGUOUS"
            )

        authority_matches = [
            row
            for row in snapshot["authorities"]
            if (
                row["service_identity_digest_hex"]
                == query["service_identity_digest_hex"]
                and row["family"] == query["family"]
                and row["direction"] == query["direction"]
                and row["traffic_class"] == query["traffic_class"]
                and row["scope_selector"] == selector
                and row["endpoint_runtime_id_hex"] == endpoint_hex
                and row["target_runtime_id_hex"]
                == query["target_runtime_id_hex"]
                and row["target_application_id_hex"]
                == query["target_application_id_hex"]
                and row["policy_id_hex"] == policy["policy_id_hex"]
                and row["policy_revision"] == policy["revision"]
                and row["policy_digest_hex"]
                == policy["canonical_digest_hex"]
            )
        ]
        authority = (
            authority_matches[0] if len(authority_matches) == 1 else None
        )
        if authority is None:
            reasons.append(
                "AUTHORITY_JOIN_MISSING"
                if not authority_matches
                else "AUTHORITY_JOIN_AMBIGUOUS"
            )

        if registry is not None:
            # Hard-filter chain (join already done). Order is Normative.
            if registry["lifecycle"] != "ACTIVE":
                reasons.append("LIFECYCLE_DRAINING")
            if registry["direction_mask"] & 1 == 0:
                reasons.append("DIRECTION_MISMATCH")
            if query["packet_bytes"] < NFL1_STRUCTURAL_MIN:
                reasons.append("STRUCTURAL_LENGTH_FLOOR")
            if query["packet_bytes"] > NFL1_STRUCTURAL_MAX:
                reasons.append("STRUCTURAL_LENGTH_CEILING")
            if query["packet_bytes"] < policy["minimum_packet_bytes"]:
                reasons.append("PACKET_MINIMUM")
            if query["packet_bytes"] > registry["maximum_packet_bytes"]:
                reasons.append("PACKET_MTU")
            if query["transfer_bytes"] > registry["maximum_transfer_bytes"]:
                reasons.append("TRANSFER_MTU")
            if registry["latency_class"] > policy["maximum_latency_class"]:
                reasons.append("LATENCY_CLASS")
            if registry["cost_class"] > policy["maximum_cost_class"]:
                reasons.append("COST_CLASS")
            if (
                query["deadline_ms"] - query["now_ms"]
                < policy["deadline_guard_ms"]
            ):
                reasons.append("DEADLINE_GUARD")
            if (
                query["deadline_clock_epoch_id_hex"]
                != query["admission_clock_epoch_id_hex"]
                or query["deadline_clock_epoch_id_hex"]
                != query["availability_clock_epoch_id_hex"]
            ):
                reasons.append("RETRY_LIFETIME_CLOCK_EPOCH")
            used = sum(
                row["reservation_units"]
                for row in snapshot["active_attempts"]
                if row["instance_id_hex"] == instance_id_hex
                and row["state"] in ("PREPARED", "LINK_RETAINED")
            )
            if (
                used + policy_candidate["reservation_units"]
                > registry["reservation_capacity"]
            ):
                reasons.append("RESERVATION_CAPACITY")
            required_caps = (
                policy["required_capability_flags"]
                | query["required_capability_flags"]
            )
            if registry["capability_flags"] & required_caps != required_caps:
                reasons.append("CAPABILITY_MISSING")
            if (
                query["requires_sleep_compatible"]
                and registry["capability_flags"] & 0x01 == 0
            ):
                reasons.append("ENERGY_SLEEP_CAPABILITY_MISSING")
            required_security = (
                policy["required_security_flags"]
                | query["required_security_flags"]
            )
            if (
                registry["security_capability_flags"] & required_security
                != required_security
            ):
                reasons.append("SECURITY_MISSING")
            if (
                query["requires_custody"]
                and (
                    registry["link_kind"] == "WIFI"
                    or registry["capability_flags"] & 0x20 == 0
                )
            ):
                reasons.append("CUSTODY_MISSING")
            if (
                query["requires_evidence"]
                and registry["capability_flags"] & 0x40 == 0
            ):
                reasons.append("EVIDENCE_MISSING")
            if (
                registry["peer_nfl1_version"] != 1
                or registry["peer_fabric_capability_flags"] & 1 == 0
            ):
                reasons.append("PEER_NFL1")
            if (
                registry["authenticated_peer_runtime_id_hex"]
                != query["authenticated_peer_runtime_id_hex"]
            ):
                reasons.append("AUTHENTICATED_PEER_MISMATCH")
            if (
                registry["attachment_authority_id_hex"]
                != query["attachment_authority_id_hex"]
            ):
                reasons.append("ATTACHMENT_AUTHORITY_MISMATCH")
            if (
                registry["attachment_binding_digest_hex"]
                != query["attachment_binding_digest_hex"]
            ):
                reasons.append("ATTACHMENT_BINDING_MISMATCH")
            if (
                registry["attestation_clock_epoch_id_hex"]
                != query["attestation_clock_epoch_id_hex"]
            ):
                reasons.append("ATTESTATION_EPOCH")
            elif query["now_ms"] >= registry["attestation_expires_at_ms"]:
                reasons.append("ATTESTATION_EXPIRED")
            if (
                registry["availability_clock_epoch_id_hex"]
                != query["availability_clock_epoch_id_hex"]
            ):
                reasons.append("AVAILABILITY_EPOCH")
            elif registry["availability_state"] != 1:
                reasons.append("AVAILABILITY_STATE")
            elif query["now_ms"] >= registry["availability_expires_at_ms"]:
                reasons.append("AVAILABILITY_EXPIRED")

        if authority is not None:
            if (
                policy["authority_mode"] == "BOUND_REQUIRED"
                and authority["authority_state"] != "BOUND"
            ):
                reasons.append("BOUND_REQUIRED_ABSENT")
            elif authority["authority_state"] == "BOUND":
                if (
                    authority["authority_clock_epoch_id_hex"]
                    != query["authority_clock_epoch_id_hex"]
                ):
                    reasons.append("AUTHORITY_CLOCK_EPOCH")
                elif query["now_ms"] >= authority["lease_expires_at_ms"]:
                    reasons.append("AUTHORITY_LEASE_EXPIRED")

        if registry is not None and registry["link_kind"] == "RF":
            if not query["rf_permit_valid"]:
                reasons.append("RF_PERMIT")
            if not query["rf_mapping_accepted"]:
                reasons.append("RF_MAPPING_UNSUPPORTED")

        sort_key = (
            [
                policy_candidate["rank"],
                registry["latency_class"],
                registry["cost_class"],
                instance_id_hex,
            ]
            if registry is not None
            else None
        )
        evaluated.append(
            {
                "instance_id_hex": instance_id_hex,
                "eligible": not reasons,
                "primary_rejection": reasons[0] if reasons else None,
                "rejection_reasons": reasons,
                "sort_key": sort_key,
            }
        )
        if not reasons and sort_key is not None:
            eligible.append((sort_key, instance_id_hex))
    eligible.sort()
    primary = next(
        (
            row["primary_rejection"]
            for row in evaluated
            if row["primary_rejection"] is not None
        ),
        None,
    )
    return {
        "resolution": "SELECTED" if eligible else "NO_ELIGIBLE_PATH",
        "primary_rejection": primary,
        "evaluated": evaluated,
        "eligible_instance_ids_hex": [row[1] for row in eligible],
        "selected_instance_id_hex": eligible[0][1] if eligible else None,
    }


def set_selection_path(
    value: dict[str, Any], path: list[Any], replacement: Any
) -> Any:
    cursor: Any = value
    for part in path[:-1]:
        cursor = cursor[part]
    old = cursor[path[-1]]
    cursor[path[-1]] = replacement
    return old


def selection_vector(
    vector_id: str,
    snapshot: dict[str, Any],
    mutation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "id": vector_id,
        "mutation": mutation,
        "inputs": snapshot,
        "model": select_candidate(snapshot),
    }


def selection_mutation_vector(
    vector_id: str,
    path: list[Any],
    replacement: Any,
) -> dict[str, Any]:
    import copy

    snapshot = copy.deepcopy(selection_baseline())
    old = set_selection_path(snapshot, path, replacement)
    return selection_vector(
        vector_id,
        snapshot,
        {
            "operation": "replace",
            "path": path,
            "old": old,
            "new": replacement,
        },
    )


def selection_collection_mutation_vector(
    vector_id: str,
    path: list[Any],
    operation: str,
    item: Any = None,
) -> dict[str, Any]:
    import copy

    snapshot = copy.deepcopy(selection_baseline())
    cursor: Any = snapshot
    for part in path:
        cursor = cursor[part]
    if operation == "append":
        cursor.append(item)
        old = None
        new = item
    elif operation == "remove":
        old = cursor.pop(item)
        new = None
    else:
        raise ValueError("unknown collection mutation")
    return selection_vector(
        vector_id,
        snapshot,
        {
            "operation": operation,
            "path": path,
            "old": old,
            "new": new,
        },
    )


def selection_vectors() -> list[dict[str, Any]]:
    import copy

    baseline = selection_baseline()
    vectors = [
        selection_vector("FABRIC-SELECT-ACTUAL-JOIN-BASELINE", baseline),
        selection_mutation_vector(
            "FABRIC-SELECT-POLICY-NO-MATCH",
            ["query", "service_identity_digest_hex"],
            sha256(b"no-policy").hex(),
        ),
    ]

    ambiguous_policy = copy.deepcopy(baseline["policies"][0])
    ambiguous_policy["policy_id_hex"] = pattern(0x72, 16).hex()
    ambiguous_policy["canonical_digest_hex"] = sha256(
        b"ambiguous-policy"
    ).hex()
    vectors.extend(
        [
            selection_collection_mutation_vector(
                "FABRIC-SELECT-POLICY-AMBIGUOUS",
                ["policies"],
                "append",
                ambiguous_policy,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-POLICY-REVISION-GAP",
                ["policies", 0, "revision_chain"],
                [1, 3],
            ),
            selection_collection_mutation_vector(
                "FABRIC-SELECT-REGISTRY-JOIN-MISSING",
                ["registry"],
                "remove",
                0,
            ),
            selection_collection_mutation_vector(
                "FABRIC-SELECT-AUTHORITY-JOIN-MISSING",
                ["authorities"],
                "remove",
                0,
            ),
            selection_collection_mutation_vector(
                "FABRIC-SELECT-AUTHORITY-JOIN-AMBIGUOUS",
                ["authorities"],
                "append",
                {
                    **copy.deepcopy(baseline["authorities"][0]),
                    "binding_id_hex": pattern(0xB9, 16).hex(),
                    "source_record_id": "SYNTHETIC-FBC1-AMBIGUOUS-JOIN",
                },
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-LIFECYCLE-DRAINING",
                ["registry", 0, "lifecycle"],
                "DRAINING",
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-DIRECTION-MISMATCH",
                ["registry", 0, "direction_mask"],
                2,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR",
                ["query", "packet_bytes"],
                NFL1_STRUCTURAL_MIN - 1,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-STRUCTURAL-LENGTH-CEILING",
                ["query", "packet_bytes"],
                NFL1_STRUCTURAL_MAX + 1,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-LATENCY-CLASS",
                ["registry", 0, "latency_class"],
                51,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-COST-CLASS",
                ["registry", 0, "cost_class"],
                51,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-DEADLINE-GUARD",
                ["query", "deadline_ms"],
                100099,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-RETRY-LIFETIME-CLOCK-EPOCH",
                ["query", "admission_clock_epoch_id_hex"],
                pattern(0xA2, 16).hex(),
            ),
            selection_collection_mutation_vector(
                "FABRIC-SELECT-RESERVATION-CAPACITY",
                ["active_attempts"],
                "append",
                {
                    "instance_id_hex": pattern(0x61, 16).hex(),
                    "state": "PREPARED",
                    "reservation_units": 8,
                },
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-CAPABILITY-MISSING",
                ["registry", 0, "capability_flags"],
                0x0000006D,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-ENERGY-SLEEP-CAPABILITY-MISSING",
                ["registry", 0, "capability_flags"],
                0x0000006E,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-SECURITY-MISSING",
                ["registry", 0, "security_capability_flags"],
                0x00000007,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-CUSTODY-MISSING",
                ["registry", 0, "capability_flags"],
                0x0000004F,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-EVIDENCE-MISSING",
                ["registry", 0, "capability_flags"],
                0x0000002F,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-PEER-NFL1-UNSUPPORTED",
                ["registry", 0, "peer_nfl1_version"],
                2,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-AUTHENTICATED-PEER-MISMATCH",
                ["registry", 0, "authenticated_peer_runtime_id_hex"],
                pattern(0x32, 16).hex(),
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-ATTACHMENT-AUTHORITY-MISMATCH",
                ["registry", 0, "attachment_authority_id_hex"],
                pattern(0x42, 16).hex(),
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-ATTACHMENT-BINDING-MISMATCH",
                ["registry", 0, "attachment_binding_digest_hex"],
                sha256(b"wrong-attachment-binding").hex(),
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-ATTESTATION-EPOCH",
                ["registry", 0, "attestation_clock_epoch_id_hex"],
                pattern(0xA2, 16).hex(),
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-ATTESTATION-EXPIRED",
                ["registry", 0, "attestation_expires_at_ms"],
                100000,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-AVAILABILITY-EPOCH",
                ["registry", 0, "availability_clock_epoch_id_hex"],
                pattern(0xA2, 16).hex(),
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-AVAILABILITY-STATE",
                ["registry", 0, "availability_state"],
                0,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-AVAILABILITY-EXPIRED",
                ["registry", 0, "availability_expires_at_ms"],
                100000,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-AUTHORITY-CLOCK-EPOCH",
                ["authorities", 0, "authority_clock_epoch_id_hex"],
                pattern(0xD2, 16).hex(),
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-AUTHORITY-LEASE-EXPIRED",
                ["authorities", 0, "lease_expires_at_ms"],
                100000,
            ),
            selection_mutation_vector(
                "FABRIC-SELECT-META-OUTER-UNAVAILABLE",
                ["meta", "outer_available"],
                0,
            ),
        ]
    )

    source_snapshot = copy.deepcopy(baseline)
    source_snapshot["policies"][0]["scope_selector"] = "SOURCE_RUNTIME"
    source_snapshot["authorities"][0]["scope_selector"] = "SOURCE_RUNTIME"
    source_snapshot["authorities"][0]["endpoint_runtime_id_hex"] = (
        source_snapshot["query"]["source_runtime_id_hex"]
    )
    source_snapshot["policies"][0][
        "source_record_id"
    ] = "FABRIC-STORE-POLICY-SOURCE-RUNTIME"
    source_snapshot["authorities"][0][
        "source_record_id"
    ] = "FABRIC-STORE-AUTHORITY-SOURCE-RUNTIME"
    source_policy_rows, source_policy_digest = selection_policy_rows(
        scope_selector=1,
        policy_id_start=0x72,
        candidates=((pattern(0x61, 16), 10, 0, 1),),
    )
    source_authority_key, source_authority_value, _ = authority_record(
        source_policy_digest,
        scope_selector=1,
        binding_start=0xC8,
        policy_id_start=0x72,
    )
    source_snapshot["policies"][0]["policy_id_hex"] = pattern(
        0x72, 16
    ).hex()
    source_snapshot["policies"][0]["canonical_digest_hex"] = (
        source_policy_digest.hex()
    )
    source_snapshot["authorities"][0]["policy_id_hex"] = pattern(
        0x72, 16
    ).hex()
    source_snapshot["authorities"][0]["binding_id_hex"] = pattern(
        0xC8, 16
    ).hex()
    source_snapshot["authorities"][0]["policy_digest_hex"] = (
        source_policy_digest.hex()
    )
    for name in tuple(source_snapshot["durable_rows"]):
        if name.startswith("FBP1"):
            del source_snapshot["durable_rows"][name]
    source_snapshot["durable_rows"].update(source_policy_rows)
    source_snapshot["durable_rows"]["FBC1"] = {
        "key_hex": source_authority_key.hex(),
        "value_hex": source_authority_value.hex(),
    }
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-SOURCE-RUNTIME-ENDPOINT", source_snapshot
        )
    )

    absent_snapshot = copy.deepcopy(baseline)
    absent_policy_rows, absent_policy_digest = selection_policy_rows(
        policy_id_start=0x73,
        authority_mode=0,
        candidates=((pattern(0x61, 16), 10, 0, 1),),
    )
    absent_digest = absent_policy_digest.hex()
    absent_authority_key, absent_authority_value, _ = authority_record(
        bytes.fromhex(absent_digest),
        authority_state=0,
        binding_start=0xD8,
        policy_id_start=0x73,
    )
    absent_snapshot["policies"][0]["policy_id_hex"] = pattern(
        0x73, 16
    ).hex()
    absent_snapshot["policies"][0]["canonical_digest_hex"] = absent_digest
    absent_snapshot["policies"][0]["authority_mode"] = "ABSENT_ALLOWED"
    absent_snapshot["policies"][0][
        "source_record_id"
    ] = "FABRIC-STORE-POLICY-ABSENT-ALLOWED"
    absent_snapshot["authorities"][0]["binding_id_hex"] = pattern(
        0xD8, 16
    ).hex()
    absent_snapshot["authorities"][0]["policy_id_hex"] = pattern(
        0x73, 16
    ).hex()
    absent_snapshot["authorities"][0]["policy_digest_hex"] = absent_digest
    absent_snapshot["authorities"][0]["authority_state"] = "ABSENT"
    absent_snapshot["authorities"][0][
        "authority_clock_epoch_id_hex"
    ] = ZERO16.hex()
    absent_snapshot["authorities"][0]["lease_expires_at_ms"] = 0
    absent_snapshot["authorities"][0][
        "source_record_id"
    ] = "FABRIC-STORE-AUTHORITY-ABSENT"
    for name in tuple(absent_snapshot["durable_rows"]):
        if name.startswith("FBP1"):
            del absent_snapshot["durable_rows"][name]
    absent_snapshot["durable_rows"].update(absent_policy_rows)
    absent_snapshot["durable_rows"]["FBC1"] = {
        "key_hex": absent_authority_key.hex(),
        "value_hex": absent_authority_value.hex(),
    }
    vectors.append(
        selection_vector("FABRIC-SELECT-ABSENT-ALLOWED", absent_snapshot)
    )
    bound_required_absent = copy.deepcopy(absent_snapshot)
    old_authority_mode = bound_required_absent["policies"][0][
        "authority_mode"
    ]
    bound_required_absent["policies"][0][
        "authority_mode"
    ] = "BOUND_REQUIRED"
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-BOUND-REQUIRED-ABSENT",
            bound_required_absent,
            {
                "operation": "replace",
                "baseline_id": "FABRIC-SELECT-ABSENT-ALLOWED",
                "path": ["policies", 0, "authority_mode"],
                "old": old_authority_mode,
                "new": "BOUND_REQUIRED",
            },
        )
    )

    mtu_baseline = copy.deepcopy(baseline)
    mtu_baseline["registry"][0][
        "maximum_packet_bytes"
    ] = NFL1_STRUCTURAL_MIN
    mtu_baseline["registry"][0][
        "maximum_transfer_bytes"
    ] = NFL1_STRUCTURAL_MIN
    mtu_baseline["durable_rows"]["FBR1"] = rewrite_selection_registry(
        mtu_baseline["durable_rows"]["FBR1"],
        mtu_baseline["registry"][0],
    )
    vectors.append(
        selection_vector("FABRIC-SELECT-MTU-BASELINE", mtu_baseline)
    )
    packet_mtu = copy.deepcopy(mtu_baseline)
    packet_mtu["query"]["packet_bytes"] = NFL1_STRUCTURAL_MIN + 1
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-PACKET-MTU",
            packet_mtu,
            {
                "operation": "replace",
                "baseline_id": "FABRIC-SELECT-MTU-BASELINE",
                "path": ["query", "packet_bytes"],
                "old": NFL1_STRUCTURAL_MIN,
                "new": NFL1_STRUCTURAL_MIN + 1,
            },
        )
    )
    transfer_mtu = copy.deepcopy(mtu_baseline)
    transfer_mtu["query"]["transfer_bytes"] = NFL1_STRUCTURAL_MIN + 1
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-TRANSFER-MTU",
            transfer_mtu,
            {
                "operation": "replace",
                "baseline_id": "FABRIC-SELECT-MTU-BASELINE",
                "path": ["query", "transfer_bytes"],
                "old": NFL1_STRUCTURAL_MIN,
                "new": NFL1_STRUCTURAL_MIN + 1,
            },
        )
    )

    # Policy minimum is distinct from absolute structural 587 floor.
    # packet_bytes remains structural-legal (587); policy requires 600.
    vectors.append(
        selection_mutation_vector(
            "FABRIC-SELECT-PACKET-MINIMUM",
            ["policies", 0, "minimum_packet_bytes"],
            600,
        )
    )

    rf_baseline = copy.deepcopy(baseline)
    rf_baseline["registry"][0]["link_kind"] = "RF"
    rf_baseline["registry"][0]["capability_flags"] = 0x0000007F
    rf_baseline["durable_rows"]["FBR1"] = rewrite_selection_registry(
        rf_baseline["durable_rows"]["FBR1"],
        rf_baseline["registry"][0],
    )
    vectors.append(
        selection_vector("FABRIC-SELECT-RF-MAPPING-BASELINE", rf_baseline)
    )
    rf_mapping = copy.deepcopy(rf_baseline)
    old_mapping = rf_mapping["query"]["rf_mapping_accepted"]
    rf_mapping["query"]["rf_mapping_accepted"] = False
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-RF-MAPPING-UNSUPPORTED",
            rf_mapping,
            {
                "operation": "replace",
                "baseline_id": "FABRIC-SELECT-RF-MAPPING-BASELINE",
                "path": ["query", "rf_mapping_accepted"],
                "old": old_mapping,
                "new": False,
            },
        )
    )
    rf_permit = copy.deepcopy(rf_baseline)
    old_permit = rf_permit["query"]["rf_permit_valid"]
    rf_permit["query"]["rf_permit_valid"] = False
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-RF-NO-PERMIT",
            rf_permit,
            {
                "operation": "replace",
                "baseline_id": "FABRIC-SELECT-RF-MAPPING-BASELINE",
                "path": ["query", "rf_permit_valid"],
                "old": old_permit,
                "new": False,
            },
        )
    )

    same_kind = copy.deepcopy(baseline)
    second_registry = copy.deepcopy(same_kind["registry"][0])
    second_registry["instance_id_hex"] = pattern(0x01, 16).hex()
    second_registry["source_record_id"] = "SYNTHETIC-FBR1-SECOND-WIFI"
    same_kind["registry"].append(second_registry)
    same_kind["policies"][0]["candidates"].insert(
        0,
        {
            "instance_id_hex": pattern(0x01, 16).hex(),
            "rank": 20,
            "reservation_units": 1,
        },
    )
    same_kind["durable_rows"]["FBR1-SECOND"] = (
        rewrite_selection_registry(
            same_kind["durable_rows"]["FBR1"],
            second_registry,
        )
    )
    same_kind_policy_digest = replace_selection_policy_rows(
        same_kind,
        scope_selector=2,
        policy_id_start=0x71,
        authority_mode=1,
        revision_chain=(1, 2, 3),
        candidates=tuple(
            (
                bytes.fromhex(candidate["instance_id_hex"]),
                candidate["rank"],
                0,
                candidate["reservation_units"],
            )
            for candidate in same_kind["policies"][0]["candidates"]
        ),
    )
    same_kind["policies"][0][
        "canonical_digest_hex"
    ] = same_kind_policy_digest.hex()
    same_kind["authorities"][0][
        "policy_digest_hex"
    ] = same_kind_policy_digest.hex()
    same_kind["durable_rows"]["FBC1"] = rewrite_selection_authority_policy(
        same_kind["durable_rows"]["FBC1"],
        policy_id=pattern(0x71, 16),
        policy_revision=3,
        policy_digest=same_kind_policy_digest,
    )
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-SAME-KIND-TWO-INSTANCES", same_kind
        )
    )
    tied = copy.deepcopy(same_kind)
    tied["policies"][0]["candidates"][0]["rank"] = 10
    tied_policy_digest = replace_selection_policy_rows(
        tied,
        scope_selector=2,
        policy_id_start=0x71,
        authority_mode=1,
        revision_chain=(1, 2, 3),
        candidates=tuple(
            (
                bytes.fromhex(candidate["instance_id_hex"]),
                candidate["rank"],
                0,
                candidate["reservation_units"],
            )
            for candidate in tied["policies"][0]["candidates"]
        ),
    )
    tied["policies"][0]["canonical_digest_hex"] = tied_policy_digest.hex()
    tied["authorities"][0]["policy_digest_hex"] = tied_policy_digest.hex()
    tied["durable_rows"]["FBC1"] = rewrite_selection_authority_policy(
        tied["durable_rows"]["FBC1"],
        policy_id=pattern(0x71, 16),
        policy_revision=3,
        policy_digest=tied_policy_digest,
    )
    vectors.append(
        selection_vector("FABRIC-SELECT-STABLE-ID-TIEBREAK", tied)
    )

    # Multiple concurrent hard failures: primary must be earliest in chain
    # (lifecycle before direction before structural before policy-min before security).
    # packet_bytes=586 also fails policy minimum 587 (distinct codes, structural first).
    precedence = copy.deepcopy(baseline)
    precedence["registry"][0]["lifecycle"] = "DRAINING"
    precedence["registry"][0]["direction_mask"] = 2
    precedence["registry"][0]["maximum_packet_bytes"] = NFL1_STRUCTURAL_MIN
    precedence["registry"][0]["security_capability_flags"] = 0
    precedence["query"]["packet_bytes"] = NFL1_STRUCTURAL_MIN - 1
    precedence["durable_rows"]["FBR1"] = rewrite_selection_registry(
        precedence["durable_rows"]["FBR1"],
        precedence["registry"][0],
    )
    vectors.append(
        selection_vector(
            "FABRIC-SELECT-HARD-FILTER-PRECEDENCE", precedence
        )
    )
    return vectors


def selection_race_vectors() -> list[dict[str, Any]]:
    return [
        {
            "id": "FABRIC-SELECT-AVAILABILITY-EPOCH-RACE",
            "event": "AVAILABILITY_EPOCH_CHANGED_BEFORE_PROVIDER_RETAIN",
            "admission_epoch": 7,
            "pre_retain_epoch": 8,
            "provider_retained": 0,
            "provider_start_calls": 0,
            "same_attempt_reselect_calls": 0,
            "closed_full_replacement": 1,
            "result": "UNAVAILABLE_NO_RETAIN_NO_SAME_ATTEMPT_RESELECT",
        },
        {
            "id": "FABRIC-SELECT-POST-RETAIN-EPOCH-RACE",
            "event": "AVAILABILITY_EPOCH_CHANGED_AFTER_PROVIDER_RETAIN",
            "fabric_retained_epoch": 7,
            "post_provider_retain_epoch": 8,
            "provider_retained": 1,
            "provider_start_calls": 1,
            "same_attempt_reselect_calls": 0,
            "track_provider_token_to_terminal": 1,
            "result": "ACCEPTED_TRACK_PROVIDER_TOKEN_TO_TERMINAL",
        },
    ]


def observed_rows(rows: list[tuple[bytes, bytes]]) -> list[dict[str, str]]:
    return [
        {"key_hex": key.hex(), "value_hex": value.hex()}
        for key, value in rows
    ]


def build() -> dict[str, Any]:
    kinds = {
        1: "APPLICATION",
        2: "RECEIPT",
        3: "DISPOSITION",
        4: "CANCEL_REQUEST",
        5: "CUSTODY_ACCEPTED",
        6: "CANCEL_RESULT",
    }
    positives = []
    packets: dict[int, bytes] = {}
    for kind, name in kinds.items():
        fields, packet = nfl1_case(kind)
        packets[kind] = packet
        assert len(packet) == NFL1_STRUCTURAL_MIN
        positives.append(
            {
                "id": f"FABRIC-NFL1-{name}-MIN",
                "kind": kind,
                "encoded_hex": packet.hex(),
                "encoded_length": len(packet),
                "crc32c_hex": packet[12:16].hex(),
                "sha256_hex": sha256(packet).hex(),
                "enrichment": {
                    "authority_binding": "BOUND",
                    "service_identity_digest_hex": service_identity_digest(
                        fields
                    ).hex(),
                    "policy_direction": policy_direction_and_traffic(kind)[0],
                    "traffic_class": policy_direction_and_traffic(kind)[1],
                    "route_policy_id_hex": fields["route_policy_id"].hex(),
                    "route_policy_revision": fields["route_policy_revision"],
                    "route_policy_digest_hex": fields["route_policy_digest"].hex(),
                    "selected_path_id_hex": fields["selected_path_id"].hex(),
                    "path_selection_epoch": fields["path_selection_epoch"],
                },
                "projected_foundation": projected_foundation(fields),
            }
        )

    absent_fields, _ = nfl1_case(1)
    absent_fields["authority_id"] = ZERO16
    absent_fields["authority_term"] = 0
    absent_fields["assignment_epoch"] = 0
    absent_packet = encode_nfl1(absent_fields)
    positives.append(
        {
            "id": "FABRIC-NFL1-ABSENT-AUTHORITY-MIN",
            "kind": 1,
            "encoded_hex": absent_packet.hex(),
            "encoded_length": len(absent_packet),
            "crc32c_hex": absent_packet[12:16].hex(),
            "sha256_hex": sha256(absent_packet).hex(),
            "enrichment": {
                "authority_binding": "ABSENT",
                "authority_id_hex": ZERO16.hex(),
                "authority_term": 0,
                "assignment_epoch": 0,
            },
            "projected_foundation": projected_foundation(absent_fields),
        }
    )

    app_fields, app_max = nfl1_case(1, maximal=True)
    receipt_fields, receipt_max = nfl1_case(2, maximal=True)
    assert len(app_max) == NFL1_SEMANTIC_MAX
    assert len(receipt_max) == 901
    positives.extend(
        [
            {
                "id": "FABRIC-NFL1-APPLICATION-SEMANTIC-MAX",
                "kind": 1,
                "encoded_hex": app_max.hex(),
                "encoded_length": len(app_max),
                "crc32c_hex": app_max[12:16].hex(),
                "sha256_hex": sha256(app_max).hex(),
                "projected_foundation": projected_foundation(app_fields),
            },
            {
                "id": "FABRIC-NFL1-RECEIPT-MAX-EVIDENCE",
                "kind": 2,
                "encoded_hex": receipt_max.hex(),
                "encoded_length": len(receipt_max),
                "crc32c_hex": receipt_max[12:16].hex(),
                "sha256_hex": sha256(receipt_max).hex(),
                "projected_foundation": projected_foundation(receipt_fields),
            },
        ]
    )

    structural_fields, _ = nfl1_case(1, maximal=True)
    structural_fields["evidence"] = pattern(0x91, 128)
    structural_ceiling = encode_nfl1(structural_fields)
    assert len(structural_ceiling) == NFL1_STRUCTURAL_MAX
    over_structural_fields = dict(structural_fields)
    over_structural_fields["evidence"] = pattern(0x91, 129)
    over_structural_ceiling = encode_nfl1(over_structural_fields)
    assert len(over_structural_ceiling) == 1926
    over_codec_fields = dict(structural_fields)
    over_codec_fields["evidence"] = pattern(0x91, 252)
    over_codec_ceiling = encode_nfl1(over_codec_fields)
    assert len(over_codec_ceiling) == 2049
    below_min_fields = common_nfl1_fields()
    below_min_fields["namespace"] = b""
    below_min = encode_nfl1(below_min_fields)
    assert len(below_min) == 586

    negatives = [
        negative_entry(
            "FABRIC-NFL1-STRUCTURAL-1925-SEMANTIC-REJECT",
            structural_ceiling,
            "REJECT_KIND_MATRIX_PAYLOAD_AND_EVIDENCE",
        ),
        negative_entry(
            "FABRIC-NFL1-STRUCTURAL-LENGTH-1926",
            over_structural_ceiling,
            "REJECT_STRUCTURAL_LENGTH_CEILING",
        ),
        negative_entry(
            "FABRIC-NFL1-CODEC-BUFFER-2049",
            over_codec_ceiling,
            "REJECT_CODEC_BUFFER_CEILING",
        ),
        negative_entry(
            "FABRIC-NFL1-STRUCTURAL-LENGTH-586",
            below_min,
            "REJECT_STRUCTURAL_LENGTH_FLOOR",
        ),
        negative_entry(
            "FABRIC-NFL1-VERSION-0",
            mutate(packets[1], 4, u16(0)),
            "REJECT_UNKNOWN_VERSION",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-VERSION-2",
            mutate(packets[1], 4, u16(2)),
            "REJECT_UNKNOWN_VERSION",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-KIND-7",
            mutate(packets[1], 16, u32(7)),
            "REJECT_UNKNOWN_MESSAGE_KIND",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-MAGIC-NFL2",
            mutate(packets[1], 0, b"NFL2"),
            "REJECT_UNKNOWN_MAGIC",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-HEADER-LENGTH-583",
            mutate(packets[1], 6, u16(583)),
            "REJECT_HEADER_LENGTH",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-DECLARED-TOTAL-U32-MAX",
            mutate(packets[1], 8, u32(0xFFFFFFFF)),
            "REJECT_TOTAL_LENGTH_OR_OVERFLOW",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-NONZERO-MESSAGE-FLAGS",
            mutate(packets[1], 20, u32(1)),
            "REJECT_RESERVED_MESSAGE_FLAGS",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-SOURCE-IDENTITY-FLAG",
            mutate(packets[1], 168, u32(8)),
            "REJECT_SOURCE_IDENTITY_FLAGS",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-TARGET-IDENTITY-FLAG",
            mutate(packets[1], 268, u32(8)),
            "REJECT_TARGET_IDENTITY_FLAGS",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-NONZERO-ROUTE-FLAGS",
            mutate(packets[1], 566, u32(1)),
            "REJECT_RESERVED_ROUTE_FLAGS",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-MIXED-AUTHORITY",
            mutate(packets[1], 272, ZERO16),
            "REJECT_MIXED_AUTHORITY_BINDING",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-ZERO-TEXT-LENGTH",
            mutate(packets[1], 570, u16(0)),
            "REJECT_TEXT_ID_LENGTH",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-TRUNCATED",
            packets[1][:-1],
            "REJECT_TOTAL_LENGTH",
        ),
        negative_entry(
            "FABRIC-NFL1-TRAILING",
            packets[1] + b"\x00",
            "REJECT_TRAILING_BYTE",
        ),
        negative_entry(
            "FABRIC-NFL1-CRC-BIT-FLIP",
            mutate(packets[1], 24, bytes([packets[1][24] ^ 1])),
            "REJECT_CRC32C",
        ),
        negative_entry(
            "FABRIC-NFL1-RECEIPT-WITH-PAYLOAD",
            encode_nfl1({**nfl1_case(2)[0], "payload": b"x"}),
            "REJECT_KIND_MATRIX_PAYLOAD",
        ),
        negative_entry(
            "FABRIC-NFL1-APPLICATION-WITH-EVIDENCE",
            encode_nfl1({**nfl1_case(1)[0], "evidence": b"x"}),
            "REJECT_KIND_MATRIX_EVIDENCE",
        ),
        negative_entry(
            "FABRIC-NFL1-DISPOSITION-WITH-EVIDENCE",
            encode_nfl1({**nfl1_case(3)[0], "evidence": b"x"}),
            "REJECT_KIND_MATRIX_EVIDENCE",
        ),
        negative_entry(
            "FABRIC-NFL1-CANCEL-REQUEST-WITH-PAYLOAD",
            encode_nfl1({**nfl1_case(4)[0], "payload": b"x"}),
            "REJECT_KIND_MATRIX_PAYLOAD",
        ),
        negative_entry(
            "FABRIC-NFL1-CUSTODY-WITH-EVIDENCE",
            encode_nfl1({**nfl1_case(5)[0], "evidence": b"x"}),
            "REJECT_KIND_MATRIX_EVIDENCE",
        ),
        negative_entry(
            "FABRIC-NFL1-CANCEL-RESULT-WITH-PAYLOAD",
            encode_nfl1({**nfl1_case(6)[0], "payload": b"x"}),
            "REJECT_KIND_MATRIX_PAYLOAD",
        ),
        negative_entry(
            "FABRIC-NFL1-CANCEL-RESULT-ZERO-KIND",
            mutate(packets[6], 444, u32(0)),
            "REJECT_KIND_MATRIX_CANCEL_KIND",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-RECEIPT-STAGE",
            mutate(packets[2], 428, u32(0xFFFFFFFF)),
            "REJECT_UNKNOWN_RECEIPT_STAGE",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-DISPOSITION",
            mutate(packets[3], 432, u32(0xFFFFFFFF)),
            "REJECT_UNKNOWN_DISPOSITION",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-EFFECT-CERTAINTY",
            mutate(packets[3], 436, u32(0xFFFFFFFF)),
            "REJECT_UNKNOWN_EFFECT_CERTAINTY",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-RETRY-GUIDANCE",
            mutate(packets[3], 440, u32(0xFFFFFFFF)),
            "REJECT_UNKNOWN_RETRY_GUIDANCE",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-CANCEL-KIND",
            mutate(packets[6], 444, u32(0xFFFFFFFF)),
            "REJECT_UNKNOWN_CANCEL_KIND",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-FAMILY",
            mutate(packets[1], 346, u32(0xFFFFFFFF)),
            "REJECT_UNKNOWN_FAMILY",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-EVIDENCE-TRUST",
            mutate(packets[2], 480, u32(0xFFFFFFFF)),
            "REJECT_UNKNOWN_EVIDENCE_TIME_TRUST",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-DESCRIPTOR-DIGEST-ALGORITHM",
            mutate(packets[1], 308, u16(2)),
            "REJECT_UNKNOWN_DESCRIPTOR_DIGEST_ALGORITHM",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-CONTENT-DIGEST-ALGORITHM",
            mutate(packets[1], 350, u16(2)),
            "REJECT_UNKNOWN_CONTENT_DIGEST_ALGORITHM",
            True,
        ),
        negative_entry(
            "FABRIC-NFL1-UNKNOWN-ROUTE-DIGEST-ALGORITHM",
            mutate(packets[1], 508, u16(2)),
            "REJECT_UNKNOWN_ROUTE_DIGEST_ALGORITHM",
            True,
        ),
    ]
    for kind, name in kinds.items():
        if kind == 1:
            continue
        negatives.append(
            negative_entry(
                f"FABRIC-NFL1-{name}-UNKNOWN-VERSION-2",
                mutate(packets[kind], 4, u16(2)),
                "REJECT_UNKNOWN_VERSION",
                True,
            )
        )

    registry_key, registry_value, registry_facts = registry_record()
    policy_key, policy_value, policy_facts = policy_record()
    policy_digest = bytes.fromhex(policy_facts["canonical_digest_hex"])
    source_policy_key, source_policy_value, source_policy_facts = (
        policy_record(scope_selector=1, policy_id_start=0x72)
    )
    source_policy_digest = bytes.fromhex(
        source_policy_facts["canonical_digest_hex"]
    )
    absent_policy_key, absent_policy_value, absent_policy_facts = (
        policy_record(policy_id_start=0x73, authority_mode=0)
    )
    absent_policy_digest = bytes.fromhex(
        absent_policy_facts["canonical_digest_hex"]
    )
    authority_key, authority_value, authority_facts = authority_record(
        policy_digest, scope_selector=2
    )
    (
        source_authority_key,
        source_authority_value,
        source_authority_facts,
    ) = authority_record(
        source_policy_digest,
        scope_selector=1,
        binding_start=0xC8,
        policy_id_start=0x72,
    )
    absent_authority_key, absent_authority_value, absent_authority_facts = (
        authority_record(
            absent_policy_digest,
            scope_selector=2,
            authority_state=0,
            binding_start=0xD8,
            policy_id_start=0x73,
        )
    )

    def pinned_packet(kind: int, receipt_stage: int = 3) -> bytes:
        attempt_fields, _ = nfl1_case(
            kind, receipt_stage=receipt_stage
        )
        attempt_fields["route_policy_id"] = pattern(0x71, 16)
        attempt_fields["route_policy_revision"] = 3
        attempt_fields["route_policy_digest"] = policy_digest
        attempt_fields["selected_path_id"] = pattern(0x61, 16)
        attempt_fields["path_selection_epoch"] = 37
        return encode_nfl1(attempt_fields)

    attempt_nfl1_packet = pinned_packet(1)
    registry_record_digest = sha256(
        b"NINLIL-FABRIC-REGISTRY-RECORD-V1"
        + registry_key
        + registry_value
    )
    attempt_key, attempt_value, attempt_facts = attempt_record(
        attempt_nfl1_packet, policy_digest, registry_record_digest
    )
    _, attempt_prepared_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=1,
        record_revision=1,
        permit_claim_state=0,
    )
    _, attempt_claimed_prepared_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=1,
        record_revision=2,
        permit_claim_state=1,
    )
    _, attempt_retryable_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=3,
        record_revision=3,
        permit_claim_state=0,
    )
    _, attempt_reprepared_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=1,
        record_revision=4,
        permit_generation=1,
        permit_expires_at_ms=450001,
        permit_claim_state=1,
    )
    _, attempt_prestart_closed_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=4,
        record_revision=2,
        permit_claim_state=0,
    )
    _, attempt_closed_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=4,
        record_revision=4,
        permit_claim_state=1,
    )
    _, attempt_fenced_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=5,
        record_revision=4,
        permit_claim_state=1,
    )
    _, attempt_prepared_fenced_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=5,
        record_revision=2,
        permit_claim_state=0,
    )
    _, attempt_retry_expired_closed_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=4,
        record_revision=4,
        permit_claim_state=0,
    )
    _, attempt_drained_value, _ = attempt_record(
        attempt_nfl1_packet,
        policy_digest,
        registry_record_digest,
        state=6,
        record_revision=5,
        terminal_revision=41,
        permit_claim_state=1,
    )
    receipt1_packet = pinned_packet(2, receipt_stage=1)
    receipt3_packet = pinned_packet(2, receipt_stage=3)
    receipt1_key, receipt1_value, receipt1_facts = attempt_record(
        receipt1_packet, policy_digest, registry_record_digest
    )
    receipt3_key, receipt3_value, receipt3_facts = attempt_record(
        receipt3_packet, policy_digest, registry_record_digest
    )
    cancel_packet = pinned_packet(4)
    cancel_key, cancel_value, cancel_facts = attempt_record(
        cancel_packet, policy_digest, registry_record_digest
    )
    assert registry_key[4:20] == pattern(0x61, 16)
    assert authority_value[24 + 58 : 24 + 60] == u16(2)
    assert (
        authority_value[24 + 60 : 24 + 76]
        == common_nfl1_fields()["target_runtime_id"]
    )
    assert source_authority_value[24 + 58 : 24 + 60] == u16(1)
    assert (
        source_authority_value[24 + 60 : 24 + 76]
        == common_nfl1_fields()["source_runtime_id"]
    )
    assert absent_authority_value[24 + 164 : 24 + 472] == bytes(308)
    assert policy_key[4:20] == attempt_value[24 + 76 : 24 + 92]
    assert attempt_value[24 + 100 : 24 + 132] == policy_digest
    assert attempt_value[24 + 132 : 24 + 148] == registry_key[4:20]
    assert attempt_value[24 + 248 : 24 + 280] == registry_record_digest
    assert attempt_value[24 + 496 : 24 + 512] == attempt_key[20:36]
    assert attempt_key[4:20] == attempt_value[24:40]
    assert attempt_key[20:36] == attempt_value[40:56]
    assert attempt_key[36:40] == attempt_value[56:60]
    assert attempt_key[40:44] == attempt_value[60:64]
    assert attempt_key[44:76] == attempt_value[68:100]
    assert attempt_value[24 + 620 : 24 + 652] == local_dispatch_id(
        attempt_key
    )
    assert receipt1_key != receipt3_key
    assert receipt1_key[4:36] == receipt3_key[4:36]
    assert receipt1_key[36:40] == receipt3_key[36:40] == u32(2)
    assert receipt1_key[40:44] == u32(1)
    assert receipt3_key[40:44] == u32(3)
    assert cancel_key[20:36] != attempt_key[20:36]
    assert attempt_nfl1_packet[484:500] == policy_key[4:20]
    assert attempt_nfl1_packet[500:508] == u64(3)
    assert attempt_nfl1_packet[510:542] == policy_digest
    assert attempt_nfl1_packet[542:558] == registry_key[4:20]
    trigger_key, trigger_value, trigger_facts = trigger_record(1)
    cancel_trigger_key, cancel_trigger_value, cancel_trigger_facts = (
        trigger_record(4)
    )
    meta_key, meta_value, meta_facts = meta_record()
    (
        meta_available_key,
        meta_available_value,
        meta_available_facts,
    ) = meta_record(record_revision=2, outer_epoch=2, outer_available=1)
    records = [
        vector_entry("FABRIC-STORE-META-1", meta_key, meta_value, meta_facts),
        vector_entry(
            "FABRIC-STORE-META-AVAILABLE",
            meta_available_key,
            meta_available_value,
            meta_available_facts,
        ),
        vector_entry(
            "FABRIC-STORE-REGISTRY-1",
            registry_key,
            registry_value,
            registry_facts,
        ),
        vector_entry(
            "FABRIC-STORE-POLICY-1",
            policy_key,
            policy_value,
            policy_facts,
        ),
        vector_entry(
            "FABRIC-STORE-POLICY-SOURCE-RUNTIME",
            source_policy_key,
            source_policy_value,
            source_policy_facts,
        ),
        vector_entry(
            "FABRIC-STORE-POLICY-ABSENT-ALLOWED",
            absent_policy_key,
            absent_policy_value,
            absent_policy_facts,
        ),
        vector_entry(
            "FABRIC-STORE-AUTHORITY-TARGET-RUNTIME",
            authority_key,
            authority_value,
            authority_facts,
        ),
        vector_entry(
            "FABRIC-STORE-AUTHORITY-SOURCE-RUNTIME",
            source_authority_key,
            source_authority_value,
            source_authority_facts,
        ),
        vector_entry(
            "FABRIC-STORE-AUTHORITY-ABSENT",
            absent_authority_key,
            absent_authority_value,
            absent_authority_facts,
        ),
        vector_entry(
            "FABRIC-STORE-ATTEMPT-1",
            attempt_key,
            attempt_value,
            attempt_facts,
        ),
        vector_entry(
            "FABRIC-STORE-ATTEMPT-RECEIPT-STAGE-1",
            receipt1_key,
            receipt1_value,
            receipt1_facts,
        ),
        vector_entry(
            "FABRIC-STORE-ATTEMPT-RECEIPT-STAGE-3",
            receipt3_key,
            receipt3_value,
            receipt3_facts,
        ),
        vector_entry(
            "FABRIC-STORE-ATTEMPT-CANCEL-REQUEST",
            cancel_key,
            cancel_value,
            cancel_facts,
        ),
        vector_entry(
            "FABRIC-STORE-TRIGGER-1",
            trigger_key,
            trigger_value,
            trigger_facts,
        ),
        vector_entry(
            "FABRIC-STORE-TRIGGER-CANCEL-REQUEST",
            cancel_trigger_key,
            cancel_trigger_value,
            cancel_trigger_facts,
        ),
    ]
    record_negatives = []
    for row in records:
        value = bytes.fromhex(row["value_hex"])
        record_negatives.append(
            {
                "id": row["id"] + "-CRC-BIT-FLIP",
                "key_hex": row["key_hex"],
                "value_hex": mutate(value, len(value) - 1, bytes([value[-1] ^ 1])).hex(),
                "expected": "REJECT_RECORD_CRC32C",
            }
        )
    record_negatives.extend(
        [
            {
                "id": "FABRIC-STORE-UNKNOWN-SCHEMA",
                "key_hex": meta_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(meta_value, 4, u16(2))
                ).hex(),
                "expected": "REJECT_UNSUPPORTED_SCHEMA_BEFORE_MUTATION",
            },
            {
                "id": "FABRIC-STORE-POLICY-DIGEST-CONFLICT",
                "key_hex": policy_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(
                        policy_value,
                        24 + 24,
                        bytes([policy_value[48] ^ 1]),
                    )
                ).hex(),
                "expected": "REJECT_POLICY_CANONICAL_DIGEST",
            },
            {
                "id": "FABRIC-STORE-REGISTRY-PEER-NFL1-V2",
                "key_hex": registry_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(registry_value, 24 + 300, u16(2))
                ).hex(),
                "expected": "REJECT_UNSUPPORTED_PEER_NFL1_VERSION",
            },
            {
                "id": "FABRIC-STORE-AUTHORITY-OWNER-DIGEST-CONFLICT",
                "key_hex": authority_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(
                        authority_value,
                        24 + 216,
                        bytes([authority_value[24 + 216] ^ 1]),
                    )
                ).hex(),
                "expected": "REJECT_OWNER_TUPLE_CANONICAL_DIGEST",
            },
            {
                "id": "FABRIC-STORE-AUTHORITY-ENDPOINT-SELECTOR-MISMATCH",
                "key_hex": authority_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(
                        authority_value,
                        24 + 60,
                        bytes([authority_value[24 + 60] ^ 1]),
                    )
                ).hex(),
                "expected": "REJECT_ENDPOINT_SELECTOR_MISMATCH",
            },
            {
                "id": "FABRIC-STORE-AUTHORITY-SCOPE-SELECTOR-UNKNOWN",
                "key_hex": authority_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(authority_value, 24 + 58, u16(3))
                ).hex(),
                "expected": "REJECT_UNKNOWN_SCOPE_SELECTOR",
            },
            {
                "id": "FABRIC-STORE-AUTHORITY-SERVICE-DIRECTION-TRAFFIC-MISMATCH",
                "key_hex": authority_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(authority_value, 24 + 52, u32(2))
                ).hex(),
                "expected": "REJECT_POLICY_LOOKUP_TUPLE_MISMATCH",
            },
            {
                "id": "FABRIC-STORE-ATTEMPT-RESPONSE-SLOT-KEY-CONFLICT",
                "key_hex": mutate(attempt_key, 40, u32(1)).hex(),
                "value_hex": attempt_value.hex(),
                "expected": "REJECT_KEY_PAYLOAD_IDENTITY",
            },
            {
                "id": "FABRIC-STORE-ATTEMPT-LOCAL-DISPATCH-CONFLICT",
                "key_hex": attempt_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(
                        attempt_value,
                        24 + 620,
                        bytes([attempt_value[24 + 620] ^ 1]),
                    )
                ).hex(),
                "expected": "REJECT_LOCAL_DISPATCH_DIGEST",
            },
            {
                "id": "FABRIC-STORE-META-TOTAL-LENGTH-CONFLICT",
                "key_hex": meta_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(meta_value, 8, u32(len(meta_value) + 1))
                ).hex(),
                "expected": "REJECT_RECORD_TOTAL_LENGTH",
            },
            {
                "id": "FABRIC-STORE-UNKNOWN-MAGIC",
                "key_hex": meta_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(meta_value, 0, b"FBZ1")
                ).hex(),
                "expected": "REJECT_UNKNOWN_RECORD_MAGIC",
            },
            {
                "id": "FABRIC-STORE-ZERO-RECORD-REVISION",
                "key_hex": meta_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(meta_value, 12, u64(0))
                ).hex(),
                "expected": "REJECT_ZERO_RECORD_REVISION",
            },
            {
                "id": "FABRIC-STORE-META-NONZERO-RESERVED",
                "key_hex": meta_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(meta_value, 24 + 36, u32(1))
                ).hex(),
                "expected": "REJECT_NONZERO_RESERVED",
            },
            {
                "id": "FABRIC-STORE-META-UNKNOWN-MIGRATION-STATE",
                "key_hex": meta_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(meta_value, 24 + 4, u16(3))
                ).hex(),
                "expected": "REJECT_UNKNOWN_MIGRATION_STATE",
            },
            {
                "id": "FABRIC-STORE-REGISTRY-UNKNOWN-LINK-KIND",
                "key_hex": registry_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(registry_value, 24 + 16, u32(0xFFFFFFFF))
                ).hex(),
                "expected": "REJECT_UNKNOWN_LINK_KIND",
            },
            {
                "id": "FABRIC-STORE-REGISTRY-UNKNOWN-AVAILABILITY-STATE",
                "key_hex": registry_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(registry_value, 24 + 288, u8(2))
                ).hex(),
                "expected": "REJECT_UNKNOWN_AVAILABILITY_STATE",
            },
            {
                "id": "FABRIC-STORE-REGISTRY-UNKNOWN-LIFECYCLE",
                "key_hex": registry_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(registry_value, 24 + 289, u8(3))
                ).hex(),
                "expected": "REJECT_UNKNOWN_REGISTRY_LIFECYCLE",
            },
            {
                "id": "FABRIC-STORE-POLICY-UNKNOWN-FAMILY",
                "key_hex": policy_key.hex(),
                "value_hex": repair_policy_canonical_digest(
                    mutate(policy_value, 24 + 88, u32(0xFFFFFFFF))
                ).hex(),
                "expected": "REJECT_UNKNOWN_POLICY_FAMILY",
            },
            {
                "id": "FABRIC-STORE-POLICY-UNKNOWN-DIRECTION",
                "key_hex": policy_key.hex(),
                "value_hex": repair_policy_canonical_digest(
                    mutate(policy_value, 24 + 92, u32(3))
                ).hex(),
                "expected": "REJECT_UNKNOWN_POLICY_DIRECTION",
            },
            {
                "id": "FABRIC-STORE-POLICY-UNKNOWN-SCOPE-SELECTOR",
                "key_hex": policy_key.hex(),
                "value_hex": repair_policy_canonical_digest(
                    mutate(policy_value, 24 + 98, u16(3))
                ).hex(),
                "expected": "REJECT_UNKNOWN_SCOPE_SELECTOR",
            },
            {
                "id": "FABRIC-STORE-POLICY-UNKNOWN-AUTHORITY-MODE",
                "key_hex": policy_key.hex(),
                "value_hex": repair_policy_canonical_digest(
                    mutate(policy_value, 24 + 116, u8(2))
                ).hex(),
                "expected": "REJECT_UNKNOWN_AUTHORITY_MODE",
            },
            {
                "id": "FABRIC-STORE-AUTHORITY-UNKNOWN-STATE",
                "key_hex": authority_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(authority_value, 24 + 164, u32(2))
                ).hex(),
                "expected": "REJECT_UNKNOWN_AUTHORITY_STATE",
            },
            {
                "id": "FABRIC-STORE-ATTEMPT-UNKNOWN-STATE",
                "key_hex": attempt_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(attempt_value, 24 + 40, u32(7))
                ).hex(),
                "expected": "REJECT_UNKNOWN_ATTEMPT_STATE",
            },
            {
                "id": "FABRIC-STORE-TRIGGER-UNKNOWN-KIND",
                "key_hex": trigger_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(trigger_value, 24 + 32, u32(7))
                ).hex(),
                "expected": "REJECT_UNKNOWN_TRIGGER_KIND",
            },
            {
                "id": "FABRIC-STORE-TRIGGER-UNKNOWN-AUTHORITY-STATE",
                "key_hex": trigger_key.hex(),
                "value_hex": repair_record_crc(
                    mutate(trigger_value, 24 + 36, u32(2))
                ).hex(),
                "expected": "REJECT_UNKNOWN_AUTHORITY_STATE",
            },
        ]
    )
    durable_entries = (
        1
        + REGISTRY_MAX
        + POLICY_MAX
        + AUTHORITY_MAX
        + ATTEMPT_MAX
        + TRIGGER_MAX
    )
    durable_key_value_bytes = (
        4 + 64
        + REGISTRY_MAX * (20 + 372)
        + POLICY_MAX * (28 + 352)
        + AUTHORITY_MAX * (20 + 512)
        + ATTEMPT_MAX * (76 + 712)
        + TRIGGER_MAX * (40 + 248)
    )
    durable_storage_cu_bytes = (
        durable_key_value_bytes + 16 * durable_entries
    )
    assert durable_entries == 273
    assert durable_key_value_bytes == 133572
    assert durable_storage_cu_bytes == 137940
    next_meta_value = meta_available_value
    _, third_meta_value, _ = meta_record(
        record_revision=3, outer_epoch=3, outer_available=0
    )
    old_group = [(meta_key, meta_value)]
    new_group = [(meta_key, next_meta_value)]
    mixed_group = [
        (meta_key, meta_value),
        (authority_key, authority_value),
    ]
    overflow_policy_rows = []
    for index in range(POLICY_MAX + 1):
        overflow_key, overflow_value, _ = policy_record(
            policy_id_start=1 + index,
            revision=1,
        )
        overflow_policy_rows.append((overflow_key, overflow_value))
    (
        existing_policy_key,
        existing_policy_value,
        existing_policy_facts,
    ) = policy_record(policy_id_start=0x75, revision=1)
    existing_authority_key, existing_authority_value, _ = authority_record(
        bytes.fromhex(existing_policy_facts["canonical_digest_hex"]),
        binding_start=0xE8,
        policy_id_start=0x75,
        policy_revision=1,
    )
    complete_existing_rows = sorted(
        [
            (meta_key, meta_value),
            (registry_key, registry_value),
            (existing_policy_key, existing_policy_value),
            (existing_authority_key, existing_authority_value),
        ]
    )
    out_of_order_existing_rows = list(complete_existing_rows)
    out_of_order_existing_rows[0], out_of_order_existing_rows[1] = (
        out_of_order_existing_rows[1],
        out_of_order_existing_rows[0],
    )

    return {
        "schema": "ninlil.fabric-bearer-spec-v1",
        "generator": "tools/fabric_bearer_spec_vector_gen.py",
        "status": "ADR-0017 Proposed candidate; not public/install ABI",
        "constants": {
            "nfl1_version": 1,
            "nfl1_header_bytes": NFL1_HEADER,
            "nfl1_structural_length_min": NFL1_STRUCTURAL_MIN,
            "nfl1_structural_length_max": NFL1_STRUCTURAL_MAX,
            "nfl1_kind_semantic_length_max": NFL1_SEMANTIC_MAX,
            "nfl1_codec_buffer_ceiling": NFL1_CODEC_CEILING,
            "fabric_storage_schema": 1,
            "fabric_api_candidate_version": 1,
            "fabric_workspace_bytes": FABRIC_WORKSPACE_BYTES,
            "fabric_attempt_region_bytes": 52224,
            "fabric_attempt_slot_bytes": 816,
            "fba1_payload_bytes": 688,
            "fba1_value_bytes": 712,
            "registry_max": REGISTRY_MAX,
            "policy_max": POLICY_MAX,
            "policy_candidates_max": 8,
            "authority_binding_max": AUTHORITY_MAX,
            "attempt_max": ATTEMPT_MAX,
            "trigger_context_max": TRIGGER_MAX,
            "shared_send_receive_queue_items_max": 32,
            "per_link_queue_items_max": 8,
            "timers_max": 64,
            "durable_entries_max": durable_entries,
            "durable_key_value_bytes_max": durable_key_value_bytes,
            "durable_storage_cu_overhead_bytes": 16 * durable_entries,
            "durable_storage_cu_bytes_max": durable_storage_cu_bytes,
            "full_staging_entries_required": 2 * durable_entries,
            "full_staging_key_value_bytes_required": (
                2 * durable_key_value_bytes
            ),
            "full_staging_storage_cu_bytes_required": (
                2 * durable_storage_cu_bytes
            ),
        },
        "nfl1_positive_vectors": positives,
        "nfl1_negative_vectors": negatives,
        "mixed_version": [
            {
                "id": f"FABRIC-MIXED-{name}-V1-V1",
                "kind": kind,
                "local": 1,
                "peer": 1,
                "peer_capability_flags": 1,
                "result": "NFL1_EXACT_ONLY",
            }
            for kind, name in kinds.items()
        ]
        + [
            {
                "id": f"FABRIC-MIXED-{name}-V1-{peer}",
                "kind": kind,
                "local": 1,
                "peer": peer,
                "peer_capability_flags": 1,
                "result": result,
            }
            for kind, name in kinds.items()
            for peer, result in (
                (0, "UNSUPPORTED_NO_RAW_STRUCT_FALLBACK"),
                (2, "UNSUPPORTED_NO_DOWNGRADE"),
            )
        ]
        + [
            {
                "id": f"FABRIC-MIXED-{name}-V0-V1",
                "kind": kind,
                "local": 0,
                "peer": 1,
                "peer_capability_flags": 1,
                "result": "UNSUPPORTED_NO_SILENT_ENRICHMENT",
            }
            for kind, name in kinds.items()
        ]
        + [
            {
                "id": f"FABRIC-MIXED-{name}-V1-V1-NO-CAP",
                "kind": kind,
                "local": 1,
                "peer": 1,
                "peer_capability_flags": 0,
                "result": "UNSUPPORTED_NO_RAW_STRUCT_FALLBACK",
            }
            for kind, name in kinds.items()
        ],
        "selection_vectors": selection_vectors() + selection_race_vectors(),
        "outer_bearer_vectors": [
            {
                "id": "FABRIC-OUTER-NO-RETAIN-CAPACITY",
                "fabric_retained_bytes": 0,
                "provider_retained_bytes": 0,
                "result": "NINLIL_BEARER_WOULD_BLOCK",
            },
            {
                "id": "FABRIC-OUTER-PROVIDER-WOULD-BLOCK",
                "tentative_fabric_bytes_before_release": NFL1_STRUCTURAL_MIN,
                "provider_retained_bytes": 0,
                "provider_start_calls": 1,
                "provider_result": "WOULD_BLOCK",
                "fba_terminal_state": "RETRYABLE_NO_ACCEPT",
                "fabric_retained_bytes_on_return": 0,
                "result": "NINLIL_BEARER_WOULD_BLOCK",
                "permit_consumed": 0,
            },
            {
                "id": "FABRIC-OUTER-PROVIDER-PARTIAL-TLS",
                "fabric_retained_bytes": NFL1_STRUCTURAL_MIN,
                "provider_retained_bytes": NFL1_STRUCTURAL_MIN,
                "provider_start_calls": 1,
                "provider_partial_wire_bytes": 41,
                "fba_state": "LINK_RETAINED",
                "result": "NINLIL_BEARER_OK/NINLIL_BEARER_SEND_ACCEPTED",
                "retry_owner": "PACKET_LINK",
                "upper_duplicate": 0,
            },
            {
                "id": "FABRIC-OUTER-COMMIT-UNKNOWN",
                "fabric_retained_bytes": 0,
                "provider_start_calls": 0,
                "read_classify_required": 1,
                "result": "NINLIL_BEARER_LOST_UNKNOWN",
            },
            {
                "id": "FABRIC-OUTER-LINK-RETAINED-COMMIT-UNKNOWN",
                "provider_start_calls": 1,
                "provider_retained_bytes": NFL1_STRUCTURAL_MIN,
                "automatic_duplicate": 0,
                "result": "NINLIL_BEARER_LOST_UNKNOWN",
            },
            {
                "id": "FABRIC-OUTER-SAME-ATTEMPT-MESSAGE-CONFLICT",
                "first_message_digest": sha256(b"message-a").hex(),
                "second_message_digest": sha256(b"message-b").hex(),
                "provider_start_calls": 0,
                "result": "NINLIL_BEARER_CORRUPT",
            },
            {
                "id": "FABRIC-OUTER-RECEIVE-VALID-PROJECTION",
                "link_receive_token_releases": 1,
                "trigger_full_commit": 1,
                "outer_result": "NINLIL_BEARER_OK",
                "outer_receive_loans": 1,
            },
            {
                "id": "FABRIC-OUTER-RECEIVE-TRIGGER-COMMIT-UNKNOWN",
                "link_receive_token_releases": 1,
                "outer_result": "NINLIL_BEARER_LOST_UNKNOWN",
                "runtime_reducer_inputs": 0,
            },
        ],
        "fba_state_transition_vectors": [
            {
                "id": "FABRIC-FBA-PREPARED-TO-LINK-RETAINED",
                "cause": "PROVIDER_RETAINED",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_claimed_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_value)]
                ),
                "outer_result": "OK_SEND_ACCEPTED",
                "permit_claim_before": 1,
                "permit_claim_after": 1,
            },
            {
                "id": "FABRIC-FBA-PREPARED-TO-RETRYABLE",
                "cause": "PROVIDER_WOULD_BLOCK",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_claimed_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_retryable_value)]
                ),
                "release_tentative_resources": 1,
                "outer_result": "WOULD_BLOCK",
                "permit_claim_before": 1,
                "permit_claim_after": 0,
            },
            {
                "id": "FABRIC-FBA-RETRYABLE-TO-PREPARED",
                "cause": "EXACT_RETRY_BEFORE_DURABLE_EXPIRY",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_retryable_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_reprepared_value)]
                ),
                "registry_authority_snapshot_match": 1,
                "retry_now_ms": 199999,
                "retry_expires_at_ms": 200000,
                "provider_start_calls_after_commit": 1,
                "permit_claim_before": 0,
                "permit_claim_after": 1,
                "fresh_permit_pair": 1,
            },
            {
                "id": "FABRIC-FBA-PREPARED-TO-CLOSED-HARD-RACE",
                "cause": "PRE_START_HARD_GATE_CHANGED",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prestart_closed_value)]
                ),
                "provider_start_calls": 0,
                "outer_result": "UNAVAILABLE_OR_DENIED",
                "permit_claim_before": 0,
                "permit_claim_after": 0,
            },
            {
                "id": "FABRIC-FBA-PREPARED-TO-CLOSED-RELEASE",
                "cause": "RUNTIME_DISPATCH_RELEASE_BEFORE_START",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prestart_closed_value)]
                ),
                "provider_start_calls": 0,
                "followup_transition": "CLOSED_TO_DRAINED",
                "permit_claim_before": 0,
                "permit_claim_after": 0,
            },
            {
                "id": "FABRIC-FBA-LINK-RETAINED-TO-CLOSED",
                "cause": "PROVIDER_TERMINAL",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_closed_value)]
                ),
                "automatic_duplicate": 0,
                "permit_claim_before": 1,
                "permit_claim_after": 1,
            },
            {
                "id": "FABRIC-FBA-PREPARED-TO-FENCED-RESTART",
                "cause": "RESTART_VOLATILE_QUEUE_LOST",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prepared_fenced_value)]
                ),
                "provider_start_calls": 0,
                "automatic_duplicate": 0,
                "permit_claim_before": 0,
                "permit_claim_after": 0,
            },
            {
                "id": "FABRIC-FBA-LINK-RETAINED-TO-FENCED-RESTART",
                "cause": "RESTART_PROVIDER_TOKEN_LOST",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_fenced_value)]
                ),
                "provider_start_calls": 0,
                "automatic_duplicate": 0,
                "permit_claim_before": 1,
                "permit_claim_after": 1,
            },
            {
                "id": "FABRIC-FBA-RETRYABLE-RESTART-BEFORE-EXPIRY",
                "cause": "RESTART_DURABLE_RETRY_LIFETIME_VALID",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_retryable_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_retryable_value)]
                ),
                "retry_now_ms": 199999,
                "retry_expires_at_ms": 200000,
                "storage_mutations": 0,
                "provider_start_calls": 0,
                "permit_claim_before": 0,
                "permit_claim_after": 0,
            },
            {
                "id": "FABRIC-FBA-RETRYABLE-RESTART-AT-EXPIRY",
                "cause": "RESTART_DURABLE_RETRY_LIFETIME_EXPIRED",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_retryable_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_retry_expired_closed_value)]
                ),
                "retry_now_ms": 200000,
                "retry_expires_at_ms": 200000,
                "provider_start_calls": 0,
                "permit_claim_before": 0,
                "permit_claim_after": 0,
            },
            {
                "id": "FABRIC-FBA-CLOSED-TO-DRAINED",
                "cause": "RUNTIME_DISPATCH_RELEASE",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_closed_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_drained_value)]
                ),
                "runtime_terminal_revision": 41,
                "permit_claim_before": 1,
                "permit_claim_after": 1,
            },
            {
                "id": "FABRIC-FBA-FENCED-TO-DRAINED",
                "cause": "RUNTIME_DISPATCH_RELEASE_AFTER_RECONCILE",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_fenced_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_drained_value)]
                ),
                "runtime_terminal_revision": 41,
                "permit_claim_before": 1,
                "permit_claim_after": 1,
            },
        ],
        "fba_commit_unknown_vectors": [
            {
                "id": "FABRIC-FBA-CLOSED-CU-OLD",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prestart_closed_value)]
                ),
                "observed_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "classification": "OLD",
                "outer_result": "LOST_UNKNOWN",
                "provider_start_calls": 0,
            },
            {
                "id": "FABRIC-FBA-CLOSED-CU-NEW",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prestart_closed_value)]
                ),
                "observed_rows": observed_rows(
                    [(attempt_key, attempt_prestart_closed_value)]
                ),
                "classification": "NEW",
                "outer_result": "LOST_UNKNOWN",
                "provider_start_calls": 0,
            },
            {
                "id": "FABRIC-FBA-CLOSED-CU-THIRD",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prestart_closed_value)]
                ),
                "observed_rows": observed_rows(
                    [(attempt_key, attempt_retryable_value)]
                ),
                "classification": "CORRUPT",
                "outer_result": "CORRUPT",
                "provider_start_calls": 0,
            },
            {
                "id": "FABRIC-FBA-RESTART-FENCE-CU-OLD",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prepared_fenced_value)]
                ),
                "observed_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "classification": "OLD",
                "outer_result": "LOST_UNKNOWN",
                "provider_start_calls": 0,
            },
            {
                "id": "FABRIC-FBA-RESTART-FENCE-CU-NEW",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prepared_fenced_value)]
                ),
                "observed_rows": observed_rows(
                    [(attempt_key, attempt_prepared_fenced_value)]
                ),
                "classification": "NEW",
                "outer_result": "LOST_UNKNOWN",
                "provider_start_calls": 0,
            },
            {
                "id": "FABRIC-FBA-RESTART-FENCE-CU-THIRD",
                "old_rows": observed_rows(
                    [(attempt_key, attempt_prepared_value)]
                ),
                "new_rows": observed_rows(
                    [(attempt_key, attempt_prepared_fenced_value)]
                ),
                "observed_rows": observed_rows(
                    [(attempt_key, attempt_prestart_closed_value)]
                ),
                "classification": "CORRUPT",
                "outer_result": "CORRUPT",
                "provider_start_calls": 0,
            },
        ],
        "storage_records": records,
        "storage_negative_vectors": record_negatives,
        "fresh_adoption_vectors": [
            {
                "id": "FABRIC-FRESH-READ-ONLY-ZERO-ROWS",
                "phase": "READ_ONLY_SCAN",
                "observed_rows": [],
                "result": "ROLLBACK_OK_THEN_OPEN_READ_WRITE",
            },
            {
                "id": "FABRIC-FRESH-READ-WRITE-ZERO-ROWS",
                "phase": "READ_WRITE_RESCAN",
                "observed_rows": [],
                "put_rows": observed_rows(old_group),
                "result": "PUT_CANONICAL_FBM1_REVISION_1_FULL",
            },
            {
                "id": "FABRIC-FRESH-READ-WRITE-RACE",
                "phase": "READ_WRITE_RESCAN",
                "observed_rows": observed_rows(old_group),
                "put_rows": [],
                "result": "CORRUPT_MUTATION_ZERO",
            },
            {
                "id": "FABRIC-FRESH-COMMIT-OK-REOPEN-EXISTING",
                "phase": "REOPEN_READ_ONLY_EXISTING_SCAN",
                "commit_result": "OK",
                "observed_rows": observed_rows(old_group),
                "classification": "EXISTING",
                "registry_publish": 1,
            },
            {
                "id": "FABRIC-EXISTING-WITHOUT-META",
                "phase": "READ_ONLY_EXISTING_SCAN",
                "observed_rows": observed_rows(
                    [(registry_key, registry_value)]
                ),
                "classification": "CORRUPT",
                "registry_publish": 0,
            },
            {
                "id": "FABRIC-EXISTING-DUPLICATE-KEY",
                "phase": "READ_ONLY_EXISTING_SCAN",
                "observed_rows": observed_rows(old_group + old_group),
                "classification": "CORRUPT",
                "registry_publish": 0,
            },
            {
                "id": "FABRIC-EXISTING-OUT-OF-ORDER",
                "phase": "READ_ONLY_EXISTING_SCAN",
                "observed_rows": observed_rows(out_of_order_existing_rows),
                "classification": "CORRUPT",
                "registry_publish": 0,
            },
            {
                "id": "FABRIC-EXISTING-COUNT-OVERFLOW",
                "phase": "READ_ONLY_EXISTING_SCAN",
                "observed_rows": observed_rows(
                    sorted(old_group + overflow_policy_rows)
                ),
                "overflow_prefix": "FBP1",
                "observed_count": POLICY_MAX + 1,
                "maximum_count": POLICY_MAX,
                "classification": "CORRUPT",
                "registry_publish": 0,
            },
            {
                "id": "FABRIC-FRESH-COMMIT-UNKNOWN-ABSENT",
                "phase": "REOPEN_READ_CLASSIFY",
                "old_rows": [],
                "new_rows": observed_rows(old_group),
                "observed_rows": [],
                "classification": "ABSENT",
                "create_result": "COMMIT_UNKNOWN_NO_PUBLISH",
            },
            {
                "id": "FABRIC-FRESH-COMMIT-UNKNOWN-NEW",
                "phase": "REOPEN_READ_CLASSIFY",
                "old_rows": [],
                "new_rows": observed_rows(old_group),
                "observed_rows": observed_rows(old_group),
                "classification": "NEW",
                "create_result": "COMMIT_UNKNOWN_NO_PUBLISH",
            },
            {
                "id": "FABRIC-FRESH-COMMIT-UNKNOWN-THIRD",
                "phase": "REOPEN_READ_CLASSIFY",
                "old_rows": [],
                "new_rows": observed_rows(old_group),
                "observed_rows": observed_rows(
                    [(meta_key, third_meta_value)]
                ),
                "classification": "CORRUPT",
                "create_result": "COMMIT_UNKNOWN_NO_PUBLISH",
            },
        ],
        "commit_unknown_matrix": [
            {
                "id": "FABRIC-COMMIT-UNKNOWN-OLD",
                "old_rows": observed_rows(old_group),
                "new_rows": observed_rows(new_group),
                "observed_rows": observed_rows(old_group),
                "classification": "OLD",
                "send_or_reselect": 0,
            },
            {
                "id": "FABRIC-COMMIT-UNKNOWN-NEW",
                "old_rows": observed_rows(old_group),
                "new_rows": observed_rows(new_group),
                "observed_rows": observed_rows(new_group),
                "classification": "NEW",
                "send_or_reselect": 0,
            },
            {
                "id": "FABRIC-COMMIT-UNKNOWN-ABSENT",
                "old_rows": [],
                "new_rows": observed_rows(old_group),
                "observed_rows": [],
                "classification": "ABSENT",
                "send_or_reselect": 0,
            },
            {
                "id": "FABRIC-COMMIT-UNKNOWN-THIRD",
                "old_rows": observed_rows(old_group),
                "new_rows": observed_rows(new_group),
                "observed_rows": observed_rows(
                    [(meta_key, third_meta_value)]
                ),
                "classification": "CORRUPT",
                "send_or_reselect": 0,
            },
            {
                "id": "FABRIC-COMMIT-UNKNOWN-MIXED-GROUP",
                "old_rows": observed_rows(old_group),
                "new_rows": observed_rows(
                    new_group + [(authority_key, authority_value)]
                ),
                "observed_rows": observed_rows(mixed_group),
                "classification": "CORRUPT",
                "send_or_reselect": 0,
            },
        ],
    }


def serialized() -> bytes:
    return (json.dumps(build(), indent=2, sort_keys=True) + "\n").encode("utf-8")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def self_test() -> int:
    """Deterministic generator self-test with adversarial inventory mutations.

    The source-tree vector is read-only. Adversarial candidates are written
    only below a private temporary directory so concurrent CTest/build trees
    cannot observe an in-flight mutation. tests-OFF safe (pure Python).
    """
    import copy
    import tempfile

    expected = serialized()
    expected_hash = _sha256(expected)
    # Deterministic double serialization.
    if serialized() != expected or _sha256(serialized()) != expected_hash:
        print("self-test FAIL: non-deterministic serialization")
        return 1

    if not OUTPUT.exists():
        print(f"self-test FAIL: missing {OUTPUT}")
        return 1
    before = OUTPUT.read_bytes()
    before_hash = _sha256(before)
    if before != expected:
        print(f"self-test FAIL: stale output before test {OUTPUT}")
        return 1

    def fail(msg: str) -> int:
        print(f"self-test FAIL: {msg}")
        return 1

    # Adversarial semantic source mutation: poison selection baseline packet.
    real_baseline = selection_baseline

    def poisoned_baseline() -> dict[str, Any]:
        snapshot = real_baseline()
        snapshot = copy.deepcopy(snapshot)
        snapshot["query"]["packet_bytes"] = 9999
        return snapshot

    globals()["selection_baseline"] = poisoned_baseline  # type: ignore[assignment]
    try:
        poisoned = serialized()
    finally:
        globals()["selection_baseline"] = real_baseline  # type: ignore[assignment]
    if poisoned == expected:
        return fail("semantic source mutation not observed")
    if serialized() != expected:
        return fail("baseline not restored after semantic poison")

    # Inventory mutations against on-disk output must diverge from generator.
    doc = json.loads(before.decode("utf-8"))
    inventory_cases: list[tuple[str, Any]] = []

    missing = copy.deepcopy(doc)
    missing["selection_vectors"] = [
        row
        for row in missing["selection_vectors"]
        if row["id"] != "FABRIC-SELECT-LATENCY-CLASS"
    ]
    inventory_cases.append(("missing", missing))

    extra = copy.deepcopy(doc)
    forged = copy.deepcopy(
        next(
            row
            for row in extra["selection_vectors"]
            if row["id"] == "FABRIC-SELECT-ACTUAL-JOIN-BASELINE"
        )
    )
    forged["id"] = "FABRIC-SELECT-VALID-UNKNOWN-EXTRA"
    extra["selection_vectors"].append(forged)
    inventory_cases.append(("extra", extra))

    duplicate = copy.deepcopy(doc)
    duplicate["selection_vectors"].append(
        copy.deepcopy(
            next(
                row
                for row in duplicate["selection_vectors"]
                if row["id"] == "FABRIC-SELECT-PACKET-MINIMUM"
            )
        )
    )
    inventory_cases.append(("duplicate", duplicate))

    substituted = copy.deepcopy(doc)
    for index, row in enumerate(substituted["selection_vectors"]):
        if row["id"] == "FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR":
            donor = copy.deepcopy(
                next(
                    item
                    for item in substituted["selection_vectors"]
                    if item["id"] == "FABRIC-SELECT-ACTUAL-JOIN-BASELINE"
                )
            )
            donor["id"] = "FABRIC-SELECT-STRUCTURAL-LENGTH-FLOOR"
            substituted["selection_vectors"][index] = donor
            break
    inventory_cases.append(("substituted", substituted))

    with tempfile.TemporaryDirectory(
        prefix="ninlil-fabric-vector-self-test-"
    ) as temporary_directory:
        candidate = Path(temporary_directory) / OUTPUT.name
        for label, mutated in inventory_cases:
            payload = (
                json.dumps(mutated, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            if payload == expected:
                return fail(f"inventory {label} mutation was invisible")
            candidate.write_bytes(payload)
            if candidate.read_bytes() == expected:
                return fail(f"inventory {label} still matched expected")
            if candidate.read_bytes() == serialized():
                return fail(f"inventory {label} matched live generator")
            # Stale rejection: --check contract.
            if candidate.read_bytes() == serialized():
                return fail(f"stale rejection failed for {label}")

    after = OUTPUT.read_bytes()
    after_hash = _sha256(after)
    if after != before or after_hash != before_hash:
        print("self-test FAIL: output not restored to before hash")
        return 1
    if after_hash != expected_hash or after != expected:
        print("self-test FAIL: restoration hash mismatch")
        return 1
    # Final live generator still matches restored bytes.
    if serialized() != after:
        print("self-test FAIL: restored file drifted from generator")
        return 1
    print(
        "fabric_bearer_spec_vector_gen self-test OK "
        f"sha256={after_hash}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    action.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    expected = serialized()
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
        print(f"stale {OUTPUT}")
        return 1
    print(f"ok {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
