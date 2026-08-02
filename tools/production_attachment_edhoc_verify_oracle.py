#!/usr/bin/env python3
"""Independent PA verify oracle (docs/30) — gate/expected ONLY.

MUST NOT be imported by production_attachment_edhoc_vector_gen.py or
production_attachment_edhoc_r6_oracle.py. Formulas are reimplemented here
for split-authority verification (emission uses r6_oracle separately).

Authority: Accepted docs/30-r6-secure-radio-wire.md §994–1314, §8.3–8.4.
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
    """Independently encode canonical NEW/observed-OLD value wire."""
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


# --- PA FULL post-image context digest (docs/35 write-set binding) ---
CTX_DIGEST_LABEL = b"NINLIL-PA-N6-CTX-DIGEST-V1"


def context_digest32(
    *,
    member_kind: int,
    complete_key: bytes,
    install_digest: bytes,
    attachment_id: bytes,
) -> bytes:
    if member_kind == 4:
        return bytes(32)
    return sha256(
        CTX_DIGEST_LABEL
        + bytes([member_kind & 0xFF])
        + complete_key
        + install_digest
        + attachment_id
    )


def classify_write_set(
    *,
    present: list[tuple[bytes, bytes, bytes]],  # key, value, ctx
    old: list[tuple[bytes, bytes, bytes]],
    new: list[tuple[bytes, bytes, bytes]],
    write_set_keys: list[bytes],
    marker_key: bytes,
) -> str:
    """Value+context image CU class (not key-count / key-presence)."""
    if len(write_set_keys) != 15 or len(set(write_set_keys)) != 15:
        return "UNCLASSIFIED_CORRUPT"
    present_map: dict[bytes, tuple[bytes, bytes]] = {}
    for k, v, c in present:
        if k in present_map:
            return "DUPLICATE_KEYS_CORRUPT"
        present_map[k] = (v, c)
    for k in present_map:
        if k not in set(write_set_keys):
            return "FOREIGN_OR_EXTRA_CORRUPT"
    old_map = {k: (v, c) for k, v, c in old}
    new_map = {k: (v, c) for k, v, c in new}
    if len(new_map) != 15:
        return "UNCLASSIFIED_CORRUPT"
    pure_new = pure_old = third = 0
    for k in write_set_keys:
        old_v = old_map.get(k)  # None => absent
        new_v = new_map[k]
        got = present_map.get(k)
        match_old = got == old_v  # both None or equal
        match_new = got is not None and got == new_v
        if match_old and match_new:
            continue
        if match_new:
            pure_new += 1
        elif match_old:
            pure_old += 1
        else:
            third += 1
    if third:
        return "THIRD_OR_MISMATCH_CORRUPT"
    if pure_new == 0:
        return "EXACT_OLD"
    if pure_old == 0:
        mp = present_map.get(marker_key)
        if mp is None:
            return "MISSING_MARKER_CORRUPT"
        st = mp[0][8]
        if st == 1:
            return "EXACT_NEW_PENDING_15"
        if st == 2:
            return "EXACT_NEW_ACTIVE_MARKER_IN_15"
        if st == 3:
            return "THIRD_OR_MISMATCH_CORRUPT"
        return "UNKNOWN_MARKER_STATE_CORRUPT"
    if 1 <= pure_new <= 14:
        return f"PARTIAL_{pure_new}_CORRUPT"
    return "UNCLASSIFIED_CORRUPT"


def local_side_for(local_role: int, direction: int, member_kind: int) -> int:
    if member_kind == 4:
        return 0
    return 2 if (local_role == 1) == (direction == 0) else 1


def rebuild_role_inventory(
    *,
    local_role: int,
    fields: dict[str, Any],
    install_digest: bytes,
    marker_value: bytes,
) -> list[dict[str, Any]]:
    """Exact 15-member inventory: complete_key + value + context (NEW phase)."""
    attachment_id = fields["attachment_id"]
    local_node = node_id16(
        fields["initiator_stable_digest"]
        if local_role == 1
        else fields["responder_stable_digest"]
    )
    peer_node = node_id16(
        fields["responder_stable_digest"]
        if local_role == 1
        else fields["initiator_stable_digest"]
    )
    raw: list[dict[str, Any]] = []

    def add(
        member_kind: int,
        direction: int,
        lane: int,
        context_id: int,
        key_generation: int,
        key_length: int,
        value_length: int,
        identity: str,
        layer_code: int,
    ) -> None:
        ls = local_side_for(local_role, direction, member_kind)
        ck = materialize_complete_key(
            member_kind=member_kind,
            direction=direction,
            lane=lane,
            local_side=ls,
            local_role=local_role,
            context_id=context_id,
            key_generation=key_generation,
            layer_code=layer_code,
            fields=fields,
            attachment_id=attachment_id,
            local_node_id=local_node,
            peer_node_id=peer_node,
        )
        if len(ck) != key_length:
            raise AssertionError(identity)
        val = materialize_member_value(
            member_kind=member_kind,
            complete_key=ck,
            value_length=value_length,
            marker_value=marker_value if member_kind == 4 else None,
            local_side=ls,
            key_generation=key_generation,
            membership_epoch=int(fields["membership_epoch"]),
            phase="new",
            peer_node_id=peer_node,
            local_node_id=local_node,
            context_id=context_id,
            layer_code=layer_code,
        )
        ctx = context_digest32(
            member_kind=member_kind,
            complete_key=ck,
            install_digest=install_digest,
            attachment_id=attachment_id,
        )
        raw.append(
            {
                "identity": identity,
                "member_kind": member_kind,
                "direction": direction,
                "lane": lane,
                "local_side": ls,
                "context_id": context_id,
                "key_generation": key_generation,
                "key_bytes": key_length,
                "value_bytes": value_length,
                "layer_code": layer_code,
                "complete_key": ck,
                "complete_key_hex": ck.hex(),
                "complete_key_length": len(ck),
                "value": val,
                "value_hex": val.hex(),
                "value_sha256": sha256(val).hex(),
                "context_digest": ctx,
                "context_digest_hex": ctx.hex(),
            }
        )

    for direction, ctx_n, gen_n, tag in (
        (0, "hop_context_ir", "hop_key_generation_ir", "hop_ir"),
        (1, "hop_context_ri", "hop_key_generation_ri", "hop_ri"),
    ):
        add(1, direction, 1, fields[ctx_n], fields[gen_n], 48, 68, f"{tag}_lane1", 1)
        add(1, direction, 2, fields[ctx_n], fields[gen_n], 48, 68, f"{tag}_lane2", 1)
        add(2, direction, 0, fields[ctx_n], fields[gen_n], 24, 56, f"{tag}_n6al", 1)
        add(3, direction, 0, fields[ctx_n], fields[gen_n], 32, 28, f"{tag}_n6hw", 1)
    for direction, ctx_n, gen_n, tag in (
        (0, "e2e_context_ir", "e2e_key_generation_ir", "e2e_ir"),
        (1, "e2e_context_ri", "e2e_key_generation_ri", "e2e_ri"),
    ):
        add(1, direction, 3, fields[ctx_n], fields[gen_n], 48, 68, f"{tag}_lane3", 2)
        add(2, direction, 0, fields[ctx_n], fields[gen_n], 24, 56, f"{tag}_n6al", 2)
        add(3, direction, 0, fields[ctx_n], fields[gen_n], 32, 28, f"{tag}_n6hw", 2)
    add(4, 0, 0, 0, 0, 20, 120, "attachment_marker", 0)
    raw.sort(key=lambda e: e["complete_key"])
    for i, e in enumerate(raw):
        e["index"] = i
    return raw


def rebuild_old_members(
    inventory: list[dict[str, Any]],
    *,
    membership_epoch: int,
    local_node: bytes,
    peer_node: bytes,
    attachment_id: bytes,
) -> list[dict[str, Any]]:
    """Rebuild the fixture's legal, non-empty per-row OLD image."""
    out: list[dict[str, Any]] = []
    for entry in inventory:
        if entry["member_kind"] == 4:
            continue
        val = materialize_member_value(
            member_kind=entry["member_kind"],
            complete_key=entry["complete_key"],
            value_length=entry["value_bytes"],
            marker_value=None,
            local_side=entry["local_side"],
            key_generation=entry["key_generation"],
            membership_epoch=membership_epoch,
            phase="old",
            peer_node_id=peer_node,
            local_node_id=local_node,
            context_id=entry["context_id"],
            layer_code=entry["layer_code"],
        )
        old_ctx = sha256(
            b"NINLIL-PA-N6-OLD-CTX-DIGEST-V1"
            + bytes([entry["member_kind"]])
            + entry["complete_key"]
            + attachment_id
        )
        out.append(
            {
                **{k: entry[k] for k in (
                    "index", "identity", "member_kind", "complete_key_hex",
                    "complete_key_length", "value_bytes", "complete_key",
                )},
                "value": val,
                "value_hex": val.hex(),
                "value_sha256": sha256(val).hex(),
                "context_digest": old_ctx,
                "context_digest_hex": old_ctx.hex(),
            }
        )
    if len(out) != 14 or not any(m["member_kind"] == 1 for m in out):
        raise AssertionError(f"fixture OLD shape {len(out)}")
    return out


def full_image(members: list[dict[str, Any]]) -> bytes:
    return b"".join(
        (m["complete_key"] if isinstance(m.get("complete_key"), bytes)
         else bytes.fromhex(m["complete_key_hex"]))
        + (m["value"] if isinstance(m.get("value"), bytes)
           else bytes.fromhex(m["value_hex"]))
        + (m["context_digest"] if isinstance(m.get("context_digest"), bytes)
           else bytes.fromhex(m["context_digest_hex"]))
        for m in members
    )


def build_class_images(
    inventory: list[dict[str, Any]],
    old_members: list[dict[str, Any]],
    *,
    marker_key: bytes,
    marker_pending: bytes,
    marker_active: bytes,
    marker_third: bytes,
) -> dict[str, Any]:
    """Literal complete-key/value/context images for every CU class."""
    ordered = [e["complete_key"] for e in inventory]
    new_members = [
        {
            "complete_key": e["complete_key"],
            "value": e["value"],
            "context_digest": e["context_digest"],
            "member_kind": e["member_kind"],
            "identity": e["identity"],
            "index": e["index"],
            "complete_key_hex": e["complete_key_hex"],
            "value_hex": e["value_hex"],
            "value_sha256": e["value_sha256"],
            "context_digest_hex": e["context_digest_hex"],
            "value_bytes": e["value_bytes"],
            "complete_key_length": e["complete_key_length"],
        }
        for e in inventory
    ]
    # Ensure marker pending in NEW
    for m in new_members:
        if m["member_kind"] == 4:
            m["value"] = marker_pending
            m["value_hex"] = marker_pending.hex()
            m["value_sha256"] = sha256(marker_pending).hex()

    def triples(members: list[dict[str, Any]]) -> list[tuple[bytes, bytes, bytes]]:
        return [
            (
                m["complete_key"] if isinstance(m["complete_key"], bytes)
                else bytes.fromhex(m["complete_key_hex"]),
                m["value"] if isinstance(m["value"], bytes)
                else bytes.fromhex(m["value_hex"]),
                m["context_digest"] if isinstance(m["context_digest"], bytes)
                else bytes.fromhex(m["context_digest_hex"]),
            )
            for m in members
        ]

    old_t = triples(old_members)
    new_t = triples(new_members)
    old_by = {m["complete_key_hex"]: m for m in old_members}
    images: dict[str, Any] = {}

    def pack(members: list[dict[str, Any]], cls: str, **extra: Any) -> dict[str, Any]:
        img = full_image(members)
        return {
            "member_count": len(members),
            "present_complete_keys_hex": [
                m["complete_key_hex"] if "complete_key_hex" in m
                else m["complete_key"].hex()
                for m in members
            ],
            "members": [
                {
                    "index": m.get("index", i),
                    "identity": m.get("identity", ""),
                    "member_kind": m["member_kind"] if "member_kind" in m else 0,
                    "complete_key_hex": m["complete_key_hex"]
                    if "complete_key_hex" in m
                    else m["complete_key"].hex(),
                    "complete_key_length": m.get(
                        "complete_key_length",
                        len(m["complete_key"] if isinstance(m.get("complete_key"), bytes)
                            else bytes.fromhex(m["complete_key_hex"])),
                    ),
                    "value_hex": m["value_hex"] if "value_hex" in m else m["value"].hex(),
                    "value_sha256": m["value_sha256"]
                    if "value_sha256" in m
                    else sha256(
                        m["value"] if isinstance(m.get("value"), bytes)
                        else bytes.fromhex(m["value_hex"])
                    ).hex(),
                    "value_bytes": m.get(
                        "value_bytes",
                        len(m["value"] if isinstance(m.get("value"), bytes)
                            else bytes.fromhex(m["value_hex"])),
                    ),
                    "context_digest_hex": m["context_digest_hex"]
                    if "context_digest_hex" in m
                    else m["context_digest"].hex(),
                }
                for i, m in enumerate(members)
            ],
            "full_image_sha256": sha256(img).hex(),
            "classification": cls,
            **extra,
        }

    cls = classify_write_set(
        present=old_t, old=old_t, new=new_t,
        write_set_keys=ordered, marker_key=marker_key,
    )
    images["exact_old"] = pack(
        old_members, cls,
        commit_unknown_accepted=True,
        observed_old_non_absent_count=len(old_members),
        marker_absent=True,
    )

    for n in range(1, 15):
        mixed: list[dict[str, Any]] = []
        for i, nm in enumerate(new_members):
            kh = nm["complete_key_hex"]
            if i < n:
                mixed.append(nm)
            elif kh in old_by:
                mixed.append(old_by[kh])
        pcls = classify_write_set(
            present=triples(mixed), old=old_t, new=new_t,
            write_set_keys=ordered, marker_key=marker_key,
        )
        images[f"partial_{n}"] = pack(
            mixed, pcls, commit_unknown_accepted=False, advanced_to_new_count=n,
        )

    ncls = classify_write_set(
        present=new_t, old=old_t, new=new_t,
        write_set_keys=ordered, marker_key=marker_key,
    )
    images["exact_new_pending_15"] = pack(
        new_members, ncls, commit_unknown_accepted=True,
    )

    # value substitution
    subst_idx = next(i for i, m in enumerate(new_members) if m["member_kind"] != 4)
    vsub = [dict(m) for m in new_members]
    vb = bytearray(vsub[subst_idx]["value"])
    vb[0] ^= 1
    # recompute CRC if N6
    if vsub[subst_idx]["member_kind"] in (1, 2, 3):
        # leave CRC broken intentionally for THIRD classification via value mismatch
        pass
    vsub[subst_idx]["value"] = bytes(vb)
    vsub[subst_idx]["value_hex"] = bytes(vb).hex()
    vsub[subst_idx]["value_sha256"] = sha256(bytes(vb)).hex()
    images["value_substitution"] = pack(
        vsub,
        classify_write_set(
            present=triples(vsub), old=old_t, new=new_t,
            write_set_keys=ordered, marker_key=marker_key,
        ),
        commit_unknown_accepted=False,
    )

    # context substitution
    csub = [dict(m) for m in new_members]
    cb = bytearray(csub[subst_idx]["context_digest"])
    cb[0] ^= 1
    csub[subst_idx]["context_digest"] = bytes(cb)
    csub[subst_idx]["context_digest_hex"] = bytes(cb).hex()
    images["context_substitution"] = pack(
        csub,
        classify_write_set(
            present=triples(csub), old=old_t, new=new_t,
            write_set_keys=ordered, marker_key=marker_key,
        ),
        commit_unknown_accepted=False,
    )

    # foreign/extra: 16th key outside write-set
    foreign_key = bytearray(new_members[0]["complete_key"])
    foreign_key[0] ^= 0x80
    foreign_present = triples(new_members) + [
        (bytes(foreign_key), new_members[0]["value"], new_members[0]["context_digest"])
    ]
    # classify_write_set sees foreign in present
    fcls = classify_write_set(
        present=foreign_present, old=old_t, new=new_t,
        write_set_keys=ordered, marker_key=marker_key,
    )
    images["extra_16"] = {
        "member_count": 16,
        "classification": fcls,
        "foreign_complete_key_hex": bytes(foreign_key).hex(),
        "commit_unknown_accepted": False,
        "present_complete_keys_hex": [
            m["complete_key_hex"] for m in new_members
        ] + [bytes(foreign_key).hex()],
        "members": images["exact_new_pending_15"]["members"] + [
            {
                "index": 15,
                "identity": "foreign",
                "member_kind": 1,
                "complete_key_hex": bytes(foreign_key).hex(),
                "complete_key_length": len(foreign_key),
                "value_hex": new_members[0]["value_hex"],
                "value_sha256": new_members[0]["value_sha256"],
                "value_bytes": new_members[0]["value_bytes"],
                "context_digest_hex": new_members[0]["context_digest_hex"],
            }
        ],
        "full_image_sha256": sha256(
            full_image(new_members) + bytes(foreign_key)
            + new_members[0]["value"] + new_members[0]["context_digest"]
        ).hex(),
    }

    # third: marker fenced
    third_m = [dict(m) for m in new_members]
    for m in third_m:
        if m["member_kind"] == 4:
            m["value"] = marker_third
            m["value_hex"] = marker_third.hex()
            m["value_sha256"] = sha256(marker_third).hex()
    images["third_mismatch"] = pack(
        third_m,
        classify_write_set(
            present=triples(third_m), old=old_t, new=new_t,
            write_set_keys=ordered, marker_key=marker_key,
        ),
        commit_unknown_accepted=False,
    )

    # active marker NEW
    active_m = [dict(m) for m in new_members]
    for m in active_m:
        if m["member_kind"] == 4:
            m["value"] = marker_active
            m["value_hex"] = marker_active.hex()
            m["value_sha256"] = sha256(marker_active).hex()
    images["exact_new_active"] = pack(
        active_m,
        classify_write_set(
            present=triples(active_m), old=old_t, new=new_t,
            write_set_keys=ordered, marker_key=marker_key,
        ),
        commit_unknown_accepted=True,
    )

    images["commit_unknown"] = {
        "accepted_classifications": [
            "EXACT_OLD",
            "EXACT_NEW_PENDING_15",
            "EXACT_NEW_ACTIVE_MARKER",
        ],
        "accepted_snapshots": ["exact_old", "exact_new_pending_15"],
        "active_marker_only": {
            "classification": "EXACT_NEW_ACTIVE_MARKER",
        },
        "rejected_snapshot_kinds": [
            f"PARTIAL_{n}_CORRUPT" for n in range(1, 15)
        ]
        + [
            "FOREIGN_OR_EXTRA_CORRUPT",
            "THIRD_OR_MISMATCH_CORRUPT",
            "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT",
        ],
    }
    return images
