#!/usr/bin/env python3
"""docs/30 R6 pure oracle for PA-S0 N6 keys/values (stdlib only).

Authority: Accepted docs/30-r6-secure-radio-wire.md
  §994–1001 node-id / ns_fingerprint
  §1012–1044 lane key + N6TX/N6RX values (TX reserved_exclusive=1, RX accept=0)
  §1046–1069 N6HW scope + value
  §1305–1314 N6AL post-image floor = context_id+1; lane initial counters
  §8.3 hop_context_binding_digest (HOP_BINDS_ATTACHMENT)
  §8.4 e2e_context_binding_digest (E2E_SECURITY_ID_NOT_ATTACHMENT)

This module has no PA document knowledge and does not import vector_gen.
Emission and independent verifiers both bind to these formulas; verifiers
must not treat emitted JSON as the formula authority.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any

WIRE_PROFILE_ID = 0x11
ENVIRONMENT_FIELD = 2
ALLOWED_KIND_MASK_HOP = 0x0003

N6_MAGIC_TX = 0x4E365458  # "N6TX"
N6_MAGIC_RX = 0x4E365258  # "N6RX"
N6_MAGIC_HW = 0x4E364857  # "N6HW"
N6_MAGIC_AL = 0x4E36414C  # "N6AL"
N6_SCHEMA_LANE = 2
N6_SCHEMA_HW = 1
N6_SCHEMA_AL = 2


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def opaque_len_prefix(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("opaque too long")
    return struct.pack(">H", len(value)) + value


def node_id16(stable_id_bytes: bytes) -> bytes:
    """docs/30 §994–996."""
    return sha256(b"NINLIL-R6-NODE-ID-v1" + opaque_len_prefix(stable_id_bytes))[:16]


def ns_fingerprint12(
    *,
    receiver_node_id: bytes,
    layer_code: int,
    membership_epoch: int,
    alloc_side: int,
) -> bytes:
    """docs/30 §999: receiver||layer||epoch||alloc_side (no direction)."""
    if len(receiver_node_id) != 16:
        raise ValueError("receiver_node_id")
    if alloc_side not in (1, 2):
        raise ValueError("alloc_side")
    return sha256(
        receiver_node_id
        + bytes([layer_code & 0xFF])
        + struct.pack(">Q", membership_epoch)
        + bytes([alloc_side & 0xFF])
    )[:12]


def scope_digest28(
    *,
    local_node_id: bytes,
    layer_code: int,
    direction: int,
    membership_epoch: int,
    receiver_node_id: bytes,
) -> bytes:
    """docs/30 §1056."""
    return sha256(
        local_node_id
        + bytes([layer_code & 0xFF, direction & 0xFF])
        + struct.pack(">Q", membership_epoch)
        + receiver_node_id
    )[:28]


def encode_hop_binding_input(
    *,
    environment_code: int,
    site_domain: bytes,
    membership_epoch: int,
    attachment_id: bytes,
    attachment_epoch: int,
    initiator_stable_id: bytes,
    responder_stable_id: bytes,
    controller_authority_id: bytes,
    controller_term: int,
    hop_context_id: int,
    direction_code: int,
) -> bytes:
    """docs/30 §8.3 encode_canon (HOP_BINDS_ATTACHMENT)."""
    return b"".join(
        (
            b"NINLIL-R6-HOP-CTX-v1",
            bytes([WIRE_PROFILE_ID, environment_code & 0xFF]),
            opaque_len_prefix(site_domain),
            struct.pack(">Q", membership_epoch),
            opaque_len_prefix(attachment_id),
            struct.pack(">Q", attachment_epoch),
            opaque_len_prefix(initiator_stable_id),
            opaque_len_prefix(responder_stable_id),
            opaque_len_prefix(controller_authority_id),
            struct.pack(">Q", controller_term),
            struct.pack(">I", hop_context_id),
            bytes([direction_code & 0xFF]),
            struct.pack(">H", ALLOWED_KIND_MASK_HOP),
        )
    )


def encode_e2e_binding_input(
    *,
    environment_code: int,
    site_domain: bytes,
    membership_epoch: int,
    e2e_security_id: bytes,
    e2e_security_epoch: int,
    sender_stable_id: bytes,
    receiver_stable_id: bytes,
    authority_id: bytes,
    authority_term: int,
    e2e_context_id: int,
    direction_code: int,
) -> bytes:
    """docs/30 §8.4 — MUST NOT include attachment_id / attachment_epoch."""
    if e2e_security_epoch < 1:
        raise ValueError("e2e_security_epoch domain")
    return b"".join(
        (
            b"NINLIL-R6-E2E-CTX-v1",
            bytes([WIRE_PROFILE_ID, environment_code & 0xFF]),
            opaque_len_prefix(site_domain),
            struct.pack(">Q", membership_epoch),
            opaque_len_prefix(e2e_security_id),
            struct.pack(">Q", e2e_security_epoch),
            opaque_len_prefix(sender_stable_id),
            opaque_len_prefix(receiver_stable_id),
            opaque_len_prefix(authority_id),
            struct.pack(">Q", authority_term),
            struct.pack(">I", e2e_context_id),
            bytes([direction_code & 0xFF]),
        )
    )


def hop_context_binding_digest(
    *,
    site_domain: bytes,
    membership_epoch: int,
    attachment_id: bytes,
    attachment_epoch: int,
    initiator_stable_id: bytes,
    responder_stable_id: bytes,
    authority_id: bytes,
    authority_term: int,
    hop_context_id: int,
    direction_code: int,
    environment_code: int = ENVIRONMENT_FIELD,
) -> bytes:
    return sha256(
        encode_hop_binding_input(
            environment_code=environment_code,
            site_domain=site_domain,
            membership_epoch=membership_epoch,
            attachment_id=attachment_id,
            attachment_epoch=attachment_epoch,
            initiator_stable_id=initiator_stable_id,
            responder_stable_id=responder_stable_id,
            controller_authority_id=authority_id,
            controller_term=authority_term,
            hop_context_id=hop_context_id,
            direction_code=direction_code,
        )
    )


def e2e_context_binding_digest(
    *,
    site_domain: bytes,
    membership_epoch: int,
    e2e_security_id: bytes,
    e2e_security_epoch: int,
    sender_stable_id: bytes,
    receiver_stable_id: bytes,
    authority_id: bytes,
    authority_term: int,
    e2e_context_id: int,
    direction_code: int,
    environment_code: int = ENVIRONMENT_FIELD,
) -> bytes:
    return sha256(
        encode_e2e_binding_input(
            environment_code=environment_code,
            site_domain=site_domain,
            membership_epoch=membership_epoch,
            e2e_security_id=e2e_security_id,
            e2e_security_epoch=e2e_security_epoch,
            sender_stable_id=sender_stable_id,
            receiver_stable_id=receiver_stable_id,
            authority_id=authority_id,
            authority_term=authority_term,
            e2e_context_id=e2e_context_id,
            direction_code=direction_code,
        )
    )


def lane_complete_key(
    *,
    layer_code: int,
    lane: int,
    direction: int,
    context_id: int,
    key_generation: int,
    binding_digest32: bytes,
) -> bytes:
    """docs/30 §5.3.0.1 canonical lane key 48B."""
    if len(binding_digest32) != 32:
        raise ValueError("binding_digest32")
    if context_id < 1 or key_generation < 1:
        raise ValueError("context/kgen domain")
    return (
        bytes([layer_code & 0xFF, lane & 0xFF, direction & 0xFF, 0])
        + struct.pack(">I", context_id)
        + binding_digest32
        + struct.pack(">Q", key_generation)
    )


def n6al_complete_key(
    *,
    layer_code: int,
    local_side: int,
    membership_epoch: int,
    receiver_node_id: bytes,
) -> bytes:
    """docs/30 N6AL key 24B."""
    fp = ns_fingerprint12(
        receiver_node_id=receiver_node_id,
        layer_code=layer_code,
        membership_epoch=membership_epoch,
        alloc_side=local_side,
    )
    return (
        bytes([2, layer_code & 0xFF, local_side & 0xFF, 0])
        + struct.pack(">Q", membership_epoch)
        + fp
    )


def n6hw_complete_key(
    *,
    layer_code: int,
    direction: int,
    membership_epoch: int,
    local_node_id: bytes,
    receiver_node_id: bytes,
) -> bytes:
    """docs/30 N6HW key 32B."""
    scope = scope_digest28(
        local_node_id=local_node_id,
        layer_code=layer_code,
        direction=direction,
        membership_epoch=membership_epoch,
        receiver_node_id=receiver_node_id,
    )
    return bytes([1, layer_code & 0xFF, direction & 0xFF, 0]) + scope


def encode_lane_value(
    *,
    local_side: int,
    key_generation: int,
    binding_prefix16: bytes,
    membership_epoch: int,
    ns_fingerprint: bytes,
) -> bytes:
    """docs/30 §1031–1044: TX reserved_exclusive=1; RX accept_reserved_through=0."""
    if local_side not in (1, 2) or key_generation == 0 or membership_epoch < 1:
        raise ValueError("lane value domain")
    if len(binding_prefix16) != 16 or len(ns_fingerprint) != 12:
        raise ValueError("lane prefixes")
    out = bytearray(68)
    magic = N6_MAGIC_TX if local_side == 2 else N6_MAGIC_RX
    counter = 1 if local_side == 2 else 0  # TX=1 / RX=0 exact
    out[0:4] = struct.pack(">I", magic)
    out[4:6] = struct.pack(">H", N6_SCHEMA_LANE)
    out[6:8] = struct.pack(">H", 0)
    out[8:16] = struct.pack(">Q", counter)
    out[16:24] = struct.pack(">Q", key_generation)
    out[24:40] = binding_prefix16
    out[40:48] = struct.pack(">Q", membership_epoch)
    out[48] = local_side
    out[49:52] = bytes(3)
    out[52:64] = ns_fingerprint
    out[64:68] = struct.pack(">I", crc32c(bytes(out[:64])))
    return bytes(out)


def encode_hw_value(*, high_water_key_generation: int, authority_now_ms: int) -> bytes:
    if high_water_key_generation == 0:
        raise ValueError("hw high-water domain")
    out = bytearray(28)
    out[0:4] = struct.pack(">I", N6_MAGIC_HW)
    out[4:6] = struct.pack(">H", N6_SCHEMA_HW)
    out[6:8] = struct.pack(">H", 0)
    out[8:16] = struct.pack(">Q", high_water_key_generation)
    out[16:24] = struct.pack(">Q", authority_now_ms)
    out[24:28] = struct.pack(">I", crc32c(bytes(out[:24])))
    return bytes(out)


def encode_al_value(
    *,
    next_free_or_peer_floor: int,
    active_count: int,
    retired_tombstone_count: int,
    membership_epoch: int,
    authority_now_ms: int,
    receiver_node_id: bytes,
) -> bytes:
    """docs/30: floor domain >= 1; post-image floor = context_id+1 on install."""
    if next_free_or_peer_floor == 0 or membership_epoch < 1 or len(receiver_node_id) != 16:
        raise ValueError("al value domain")
    out = bytearray(56)
    out[0:4] = struct.pack(">I", N6_MAGIC_AL)
    out[4:6] = struct.pack(">H", N6_SCHEMA_AL)
    out[6:8] = struct.pack(">H", 0)
    out[8:12] = struct.pack(">I", next_free_or_peer_floor)
    out[12:14] = struct.pack(">H", active_count)
    out[14:16] = struct.pack(">H", retired_tombstone_count)
    out[16:20] = struct.pack(">I", 0)
    out[20:28] = struct.pack(">Q", membership_epoch)
    out[28:36] = struct.pack(">Q", authority_now_ms)
    out[36:52] = receiver_node_id
    out[52:56] = struct.pack(">I", crc32c(bytes(out[:52])))
    return bytes(out)


def al_floor_after_install(context_id: int) -> int:
    """docs/30 §1309–1312: next_free/peer_floor' = context_id + 1."""
    if context_id < 1:
        raise ValueError("context_id")
    return context_id + 1


def fresh_lane_counter(local_side: int) -> int:
    """docs/30 §1314: TX=1, RX=0."""
    if local_side == 2:
        return 1
    if local_side == 1:
        return 0
    raise ValueError("local_side")


def binding_for_lane(
    *,
    layer_code: int,
    direction: int,
    context_id: int,
    fields: dict[str, Any],
) -> bytes:
    """Select hop vs e2e binding. E2E never uses attachment_id."""
    if layer_code == 1:
        return hop_context_binding_digest(
            site_domain=fields["site_domain"],
            membership_epoch=int(fields["membership_epoch"]),
            attachment_id=fields["attachment_id"],
            attachment_epoch=int(fields["attachment_epoch"]),
            initiator_stable_id=fields["initiator_stable_digest"],
            responder_stable_id=fields["responder_stable_digest"],
            authority_id=fields["authority_id"],
            authority_term=int(fields["authority_term"]),
            hop_context_id=context_id,
            direction_code=direction,
        )
    if layer_code == 2:
        if direction == 0:
            sender = fields["initiator_stable_digest"]
            receiver = fields["responder_stable_digest"]
        else:
            sender = fields["responder_stable_digest"]
            receiver = fields["initiator_stable_digest"]
        return e2e_context_binding_digest(
            site_domain=fields["site_domain"],
            membership_epoch=int(fields["membership_epoch"]),
            e2e_security_id=fields["e2e_security_id"],
            e2e_security_epoch=int(fields["e2e_security_epoch"]),
            sender_stable_id=sender,
            receiver_stable_id=receiver,
            authority_id=fields["authority_id"],
            authority_term=int(fields["authority_term"]),
            e2e_context_id=context_id,
            direction_code=direction,
        )
    raise ValueError("layer_code")


def materialize_complete_key(
    *,
    member_kind: int,
    direction: int,
    lane: int,
    local_side: int,
    local_role: int,
    context_id: int,
    key_generation: int,
    layer_code: int,
    fields: dict[str, Any],
    attachment_id: bytes,
    local_node_id: bytes,
    peer_node_id: bytes,
) -> bytes:
    """Materialize complete keys per docs/30 layouts used by PA 15-key FULL."""
    if member_kind == 1:
        binding = binding_for_lane(
            layer_code=layer_code,
            direction=direction,
            context_id=context_id,
            fields=fields,
        )
        return lane_complete_key(
            layer_code=layer_code,
            lane=lane,
            direction=direction,
            context_id=context_id,
            key_generation=key_generation,
            binding_digest32=binding,
        )
    if member_kind == 2:
        receiver = peer_node_id if local_side == 2 else local_node_id
        return n6al_complete_key(
            layer_code=layer_code,
            local_side=local_side,
            membership_epoch=int(fields["membership_epoch"]),
            receiver_node_id=receiver,
        )
    if member_kind == 3:
        receiver = peer_node_id if local_side == 2 else local_node_id
        return n6hw_complete_key(
            layer_code=layer_code,
            direction=direction,
            membership_epoch=int(fields["membership_epoch"]),
            local_node_id=local_node_id,
            receiver_node_id=receiver,
        )
    if member_kind == 4:
        return struct.pack(">BBBB16s", 5, local_role, 1, 0, attachment_id)
    raise ValueError("member_kind")


def materialize_member_value(
    *,
    member_kind: int,
    complete_key: bytes,
    value_length: int,
    marker_value: bytes | None,
    local_side: int,
    key_generation: int,
    membership_epoch: int,
    phase: str,
    peer_node_id: bytes | None,
    local_node_id: bytes | None,
    context_id: int,
    layer_code: int,
) -> bytes:
    """Canonical NEW/observed-OLD value wire.

    A write-set row can legally observe a pre-existing lane at the same
    complete key (for example while recovering a prior candidate).  The lane
    bytes remain a valid N6TX/N6RX image; the PA transaction context digest,
    not an invented lane codec, distinguishes that OLD image from the proposed
    NEW image.
    """
    if member_kind == 4:
        if phase == "old":
            raise ValueError("marker OLD-absent")
        if marker_value is None or len(marker_value) != value_length:
            raise ValueError("marker value")
        return marker_value
    authority_now = 1_000_000 if phase == "old" else 1_300_000
    if member_kind == 1:
        receiver = peer_node_id if local_side == 2 else local_node_id
        if receiver is None or len(receiver) != 16 or len(complete_key) != 48:
            raise ValueError("lane domain")
        ns_fp = ns_fingerprint12(
            receiver_node_id=receiver,
            layer_code=layer_code,
            membership_epoch=membership_epoch,
            alloc_side=local_side,
        )
        value = encode_lane_value(
            local_side=local_side,
            key_generation=key_generation,
            binding_prefix16=complete_key[8:24],
            membership_epoch=membership_epoch,
            ns_fingerprint=ns_fp,
        )
        if len(value) != value_length:
            raise AssertionError("lane value length")
        return value
    if member_kind == 3:
        hw = 1 if phase == "old" else max(1, key_generation)
        value = encode_hw_value(
            high_water_key_generation=hw, authority_now_ms=authority_now
        )
        if len(value) != value_length:
            raise AssertionError("hw value length")
        return value
    if member_kind == 2:
        receiver = peer_node_id if local_side == 2 else local_node_id
        if receiver is None or len(receiver) != 16:
            raise ValueError("al receiver")
        if phase == "old":
            floor, active = 1, 0
        else:
            floor = al_floor_after_install(context_id)
            active = 1
        value = encode_al_value(
            next_free_or_peer_floor=floor,
            active_count=active,
            retired_tombstone_count=0,
            membership_epoch=membership_epoch,
            authority_now_ms=authority_now,
            receiver_node_id=receiver,
        )
        if len(value) != value_length:
            raise AssertionError("al value length")
        return value
    raise ValueError("member_kind")
