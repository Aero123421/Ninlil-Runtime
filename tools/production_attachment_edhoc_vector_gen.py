#!/usr/bin/env python3
"""Independent vectors for the Proposed production Attachment/EDHOC profile.

This is a specification oracle.  It deliberately uses only the Python
standard library and does not import the Ninlil runtime, an EDHOC library, or
any production codec.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spec/vectors/production-attachment-edhoc-v1.json"

NPA1_VERSION = 1
NPA1_HEADER_BYTES = 88
NPA1_PAYLOAD_MAX = 512
NPA1_RECORD_MAX = NPA1_HEADER_BYTES + NPA1_PAYLOAD_MAX

NPR1_PROFILE = 0x12
NPR1_VERSION = 1
NPR1_HEADER_BYTES = 68
NPR1_PACKET_MAX = 192
NPR1_PAYLOAD_MAX = NPR1_PACKET_MAX - NPR1_HEADER_BYTES
NPR1_FRAGMENT_MAX = 5

METHOD_STATIC_DH_BOTH = 3
SUITE_2 = 2
SUITE_3 = 3

KIND_COOKIE_CHALLENGE = 1
KIND_COOKIE_RESPONSE = 2
KIND_EDHOC_ERROR = 3
KIND_EDHOC_MESSAGE_1 = 4
KIND_EDHOC_MESSAGE_2 = 5
KIND_EDHOC_MESSAGE_3 = 6
KIND_EDHOC_MESSAGE_4 = 7
KIND_ATTACH_INSTALL = 8
KIND_ATTACH_CONFIRM_DEVICE = 9
KIND_ATTACH_CONFIRM_AUTHORITY = 10

EXPORTER_LABELS = {
    "attach_i2r_key16": 32768,
    "attach_r2i_key16": 32769,
    "attach_i2r_iv13": 32770,
    "attach_r2i_iv13": 32771,
    "hop_ir_secret32": 32772,
    "hop_ri_secret32": 32773,
    "e2e_ir_secret32": 32774,
    "e2e_ri_secret32": 32775,
}


def sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def pattern(start: int, length: int) -> bytes:
    return bytes((start + index) & 0xFF for index in range(length))


def hex_bytes(value: bytes) -> str:
    return value.hex()


def encode_npa1(
    *,
    kind: int,
    carrier_class: int,
    session_id: bytes,
    exchange_generation: int,
    record_sequence: int,
    carrier_binding_digest: bytes,
    payload: bytes,
) -> bytes:
    if len(session_id) != 16 or not any(session_id):
        raise ValueError("NPA1 session_id")
    if len(carrier_binding_digest) != 32 or not any(carrier_binding_digest):
        raise ValueError("NPA1 carrier binding")
    if not 1 <= kind <= 10:
        raise ValueError("NPA1 kind")
    if carrier_class not in (1, 2, 3):
        raise ValueError("NPA1 carrier")
    if not 1 <= exchange_generation <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("NPA1 generation")
    if len(payload) > NPA1_PAYLOAD_MAX:
        raise ValueError("NPA1 payload")
    total = NPA1_HEADER_BYTES + len(payload)
    header = struct.pack(
        ">4sHHIIBBBB16sQII32sI",
        b"NPA1",
        NPA1_VERSION,
        NPA1_HEADER_BYTES,
        total,
        len(payload),
        kind,
        0,
        carrier_class,
        0,
        session_id,
        exchange_generation,
        record_sequence,
        0,
        carrier_binding_digest,
        0,
    )
    record = bytearray(header + payload)
    record[84:88] = struct.pack(">I", crc32c(bytes(record)))
    return bytes(record)


def fragment_npr1(record: bytes) -> list[bytes]:
    if not NPA1_HEADER_BYTES <= len(record) <= NPA1_RECORD_MAX:
        raise ValueError("NPR1 record length")
    session_id = record[20:36]
    exchange_generation = struct.unpack(">Q", record[36:44])[0]
    record_sequence = struct.unpack(">I", record[44:48])[0]
    digest16 = sha256(record)[:16]
    count = (len(record) + NPR1_PAYLOAD_MAX - 1) // NPR1_PAYLOAD_MAX
    if not 1 <= count <= NPR1_FRAGMENT_MAX:
        raise ValueError("NPR1 fragment count")
    packets: list[bytes] = []
    for index in range(count):
        offset = index * NPR1_PAYLOAD_MAX
        payload = record[offset : offset + NPR1_PAYLOAD_MAX]
        total = NPR1_HEADER_BYTES + len(payload)
        header = struct.pack(
            ">4sBBHHH16sQIHBB16sII",
            b"NPR1",
            NPR1_PROFILE,
            NPR1_VERSION,
            NPR1_HEADER_BYTES,
            total,
            len(payload),
            session_id,
            exchange_generation,
            record_sequence,
            len(record),
            index,
            count,
            digest16,
            offset,
            0,
        )
        packet = bytearray(header + payload)
        packet[64:68] = struct.pack(">I", crc32c(bytes(packet)))
        packets.append(bytes(packet))
    return packets


def make_nax1(
    *,
    suite: int,
    session_id: bytes,
    exchange_generation: int,
    initiator_credential_digest: bytes,
    responder_credential_digest: bytes,
    carrier_transcript_digest: bytes,
    authority_id: bytes,
    authority_term: int,
) -> bytes:
    return struct.pack(
        ">4sHHBBH16sQ32s32s32s16sQI",
        b"NAX1",
        1,
        160,
        METHOD_STATIC_DH_BOTH,
        suite,
        0,
        session_id,
        exchange_generation,
        initiator_credential_digest,
        responder_credential_digest,
        carrier_transcript_digest,
        authority_id,
        authority_term,
        0,
    )


def make_nai1() -> tuple[bytes, dict[str, Any]]:
    descriptor = bytearray(384)
    fields: dict[str, Any] = {
        "attachment_id": pattern(0x10, 16),
        "initiator_stable_digest": sha256(b"initiator-stable-id"),
        "responder_stable_digest": sha256(b"responder-stable-id"),
        "site_domain": pattern(0x20, 16),
        "authority_id": pattern(0x30, 16),
        "authority_term": 7,
        "membership_epoch": 11,
        "attachment_epoch": 13,
        "lease_epoch": 17,
        "lease_clock_epoch": pattern(0x40, 16),
        "lease_not_before_ms": 1_000_000,
        "lease_expires_at_ms": 1_300_000,
        "credential_set_revision": 19,
        "initiator_credential_generation": 23,
        "responder_credential_generation": 29,
        "revocation_generation": 31,
        "assignment_epoch": 37,
        "hop_context_ir": 41,
        "hop_context_ri": 43,
        "e2e_context_ir": 47,
        "e2e_context_ri": 53,
        "hop_key_generation_ir": 59,
        "hop_key_generation_ri": 61,
        "e2e_key_generation_ir": 67,
        "e2e_key_generation_ri": 71,
        "e2e_security_id": pattern(0x50, 16),
        "e2e_security_epoch": 73,
        "route_policy_digest": sha256(b"route-policy"),
        "membership_grant_digest": sha256(b"membership-grant"),
        "carrier_transcript_digest": sha256(b"carrier-transcript"),
    }
    descriptor[0:4] = b"NAI1"
    descriptor[4:6] = struct.pack(">H", 1)
    descriptor[6:8] = struct.pack(">H", 384)
    descriptor[8:12] = struct.pack(">I", 0)
    descriptor[12] = SUITE_2
    descriptor[13] = METHOD_STATIC_DH_BOTH
    descriptor[14] = 4
    descriptor[15] = 0
    descriptor[16:32] = fields["attachment_id"]
    descriptor[32:64] = fields["initiator_stable_digest"]
    descriptor[64:96] = fields["responder_stable_digest"]
    descriptor[96:112] = fields["site_domain"]
    descriptor[112:128] = fields["authority_id"]
    descriptor[128:136] = struct.pack(">Q", fields["authority_term"])
    descriptor[136:144] = struct.pack(">Q", fields["membership_epoch"])
    descriptor[144:152] = struct.pack(">Q", fields["attachment_epoch"])
    descriptor[152:160] = struct.pack(">Q", fields["lease_epoch"])
    descriptor[160:176] = fields["lease_clock_epoch"]
    descriptor[176:184] = struct.pack(">Q", fields["lease_not_before_ms"])
    descriptor[184:192] = struct.pack(">Q", fields["lease_expires_at_ms"])
    descriptor[192:200] = struct.pack(">Q", fields["credential_set_revision"])
    descriptor[200:204] = struct.pack(
        ">I", fields["initiator_credential_generation"]
    )
    descriptor[204:208] = struct.pack(
        ">I", fields["responder_credential_generation"]
    )
    descriptor[208:212] = struct.pack(">I", fields["revocation_generation"])
    descriptor[212:216] = struct.pack(">I", fields["assignment_epoch"])
    descriptor[216:220] = struct.pack(">I", fields["hop_context_ir"])
    descriptor[220:224] = struct.pack(">I", fields["hop_context_ri"])
    descriptor[224:228] = struct.pack(">I", fields["e2e_context_ir"])
    descriptor[228:232] = struct.pack(">I", fields["e2e_context_ri"])
    descriptor[232:240] = struct.pack(">Q", fields["hop_key_generation_ir"])
    descriptor[240:248] = struct.pack(">Q", fields["hop_key_generation_ri"])
    descriptor[248:256] = struct.pack(">Q", fields["e2e_key_generation_ir"])
    descriptor[256:264] = struct.pack(">Q", fields["e2e_key_generation_ri"])
    descriptor[264:280] = fields["e2e_security_id"]
    descriptor[280:288] = struct.pack(">Q", fields["e2e_security_epoch"])
    descriptor[288:320] = fields["route_policy_digest"]
    descriptor[320:352] = fields["membership_grant_digest"]
    descriptor[352:384] = fields["carrier_transcript_digest"]
    return bytes(descriptor), fields


def make_nat1(
    *,
    install_digest: bytes,
    attachment_id: bytes,
    membership_epoch: int,
    attachment_epoch: int,
    e2e_security_epoch: int,
    lease_epoch: int,
    assignment_epoch: int,
) -> bytes:
    return struct.pack(
        ">4sHH32s16sQQQQII",
        b"NAT1",
        1,
        96,
        install_digest,
        attachment_id,
        membership_epoch,
        attachment_epoch,
        e2e_security_epoch,
        lease_epoch,
        assignment_epoch,
        0,
    )


def make_n6at(
    *,
    local_role: int,
    state: int,
    attachment_id: bytes,
    membership_epoch: int,
    attachment_epoch: int,
    install_digest: bytes,
    authority_term: int,
) -> tuple[bytes, bytes]:
    key = struct.pack(">BBBB16s", 5, local_role, 1, 0, attachment_id)
    value = bytearray(
        struct.pack(
            ">4sHBBQQ32sQI",
            b"N6AT",
            1,
            state,
            local_role,
            membership_epoch,
            attachment_epoch,
            install_digest,
            authority_term,
            0,
        )
    )
    value[64:68] = struct.pack(">I", crc32c(bytes(value)))
    return key, bytes(value)


def carrier_binding_vectors() -> dict[str, Any]:
    instance = pattern(0x60, 16)
    peer = pattern(0x70, 16)
    config_digest = sha256(b"carrier-config")
    usb_input = (
        b"NINLIL-NPA1-USB-BINDING-V1"
        + instance
        + peer
        + struct.pack(">Q", 5)
        + config_digest
    )
    wifi_peer_session = pattern(0x80, 16)
    wifi_input = (
        b"NINLIL-NPA1-WIFI-BINDING-V1"
        + instance
        + wifi_peer_session
        + peer
        + pattern(0x90, 16)
        + struct.pack(">Q", 7)
        + struct.pack(">I", 11)
        + config_digest
    )
    radio_input = (
        b"NINLIL-NPA1-RADIO-BINDING-V1"
        + instance
        + sha256(b"radio-channel-plan")
        + struct.pack(">Q", 13)
        + config_digest
    )
    return {
        "usb": {
            "carrier_class": 1,
            "canonical_input_hex": hex_bytes(usb_input),
            "digest_hex": hex_bytes(sha256(usb_input)),
        },
        "wifi": {
            "carrier_class": 2,
            "canonical_input_hex": hex_bytes(wifi_input),
            "digest_hex": hex_bytes(sha256(wifi_input)),
        },
        "compact_radio": {
            "carrier_class": 3,
            "canonical_input_hex": hex_bytes(radio_input),
            "digest_hex": hex_bytes(sha256(radio_input)),
        },
    }


def rfc9529_reference() -> dict[str, Any]:
    messages = {
        "message_1": bytes.fromhex(
            "03 82 06 02 58 20 8a f6 f4 30 eb e1 8d 34 18 40 17 a9 "
            "a1 1b f5 11 c8 df f8 f8 34 73 0b 96 c1 b7 c8 db ca 2f c3 b6 37"
        ),
        "message_2": bytes.fromhex(
            "58 2b 41 97 01 d7 f0 0a 26 c2 dc 58 7a 36 dd 75 25 49 f3 37 "
            "63 c8 93 42 2c 8e a0 f9 55 a1 3a 4f f5 d5 98 62 a1 ee f9 "
            "e0 e7 e1 88 6f cd"
        ),
        "message_3": bytes.fromhex(
            "52 e5 62 09 7b c4 17 dd 59 19 48 5a c7 89 1f fd 90 a9 fc"
        ),
        "message_4": bytes.fromhex("48 28 c9 66 b7 ca 30 4f 83"),
    }
    return {
        "source": "RFC 9529 section 3",
        "method": 3,
        "selected_suite": 2,
        "profile_acceptance": False,
        "reason": (
            "The RFC trace begins with suite 6 and retries with [6,2]; this "
            "profile forbids automatic suite downgrade and pins suite 2 or 3."
        ),
        "messages": {
            name: {
                "length": len(value),
                "hex": hex_bytes(value),
                "sha256": hex_bytes(sha256(value)),
            }
            for name, value in messages.items()
        },
    }


def build_document() -> dict[str, Any]:
    carriers = carrier_binding_vectors()
    session_id = pattern(0xA0, 16)
    exchange_generation = 101
    radio_binding = bytes.fromhex(carriers["compact_radio"]["digest_hex"])

    message_1_suite2 = (
        bytes([METHOD_STATIC_DH_BOTH, SUITE_2, 0x58, 0x20])
        + pattern(0x01, 32)
        + bytes([0x00])
    )
    message_1_suite3 = (
        bytes([METHOD_STATIC_DH_BOTH, SUITE_3, 0x58, 0x20])
        + pattern(0x21, 32)
        + bytes([0x01])
    )
    npa_m1_suite2 = encode_npa1(
        kind=KIND_EDHOC_MESSAGE_1,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=1,
        carrier_binding_digest=radio_binding,
        payload=message_1_suite2,
    )
    npa_m1_suite3 = encode_npa1(
        kind=KIND_EDHOC_MESSAGE_1,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation + 1,
        record_sequence=1,
        carrier_binding_digest=radio_binding,
        payload=message_1_suite3,
    )

    descriptor, descriptor_fields = make_nai1()
    install_digest = sha256(
        b"NINLIL-PRODUCTION-ATTACH-INSTALL-V1" + descriptor
    )
    carrier_transcript_digest = descriptor_fields["carrier_transcript_digest"]
    initiator_credential_digest = sha256(b"initiator-ccs")
    responder_credential_digest = sha256(b"responder-ccs")
    nax1 = make_nax1(
        suite=SUITE_2,
        session_id=session_id,
        exchange_generation=exchange_generation,
        initiator_credential_digest=initiator_credential_digest,
        responder_credential_digest=responder_credential_digest,
        carrier_transcript_digest=carrier_transcript_digest,
        authority_id=descriptor_fields["authority_id"],
        authority_term=descriptor_fields["authority_term"],
    )
    nat1 = make_nat1(
        install_digest=install_digest,
        attachment_id=descriptor_fields["attachment_id"],
        membership_epoch=descriptor_fields["membership_epoch"],
        attachment_epoch=descriptor_fields["attachment_epoch"],
        e2e_security_epoch=descriptor_fields["e2e_security_epoch"],
        lease_epoch=descriptor_fields["lease_epoch"],
        assignment_epoch=descriptor_fields["assignment_epoch"],
    )
    protect_context_digest = sha256(
        b"NINLIL-ATTACH-PROTECT-CONTEXT-V1" + nax1
    )
    traffic_context_digest = sha256(
        b"NINLIL-ATTACH-TRAFFIC-CONTEXT-V1" + nax1 + nat1
    )

    # The Proposed design does not claim an AEAD implementation.  This
    # transport vector uses deterministic opaque bytes of the exact required
    # ciphertext+8-byte-tag length; descriptor vectors separately pin the
    # cleartext and exporter inputs.
    opaque_install_ciphertext_and_tag = pattern(0x90, len(descriptor) + 8)
    npa_install = encode_npa1(
        kind=KIND_ATTACH_INSTALL,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=5,
        carrier_binding_digest=radio_binding,
        payload=opaque_install_ciphertext_and_tag,
    )
    radio_fragments = fragment_npr1(npa_install)

    n6at_key, n6at_value = make_n6at(
        local_role=1,
        state=1,
        attachment_id=descriptor_fields["attachment_id"],
        membership_epoch=descriptor_fields["membership_epoch"],
        attachment_epoch=descriptor_fields["attachment_epoch"],
        install_digest=install_digest,
        authority_term=descriptor_fields["authority_term"],
    )

    descriptor_json = {
        key: (hex_bytes(value) if isinstance(value, bytes) else value)
        for key, value in descriptor_fields.items()
    }

    return {
        "schema": "ninlil.production-attachment-edhoc.vector.v1",
        "status": "PROPOSED_SPEC_ONLY",
        "sources": [
            "RFC 9528",
            "RFC 9529",
            "docs/03-identity-and-join.md",
            "docs/30-r6-secure-radio-wire.md",
            "docs/34-r7-t1c-authenticated-hop-fresh-install-owner.md",
            "docs/adr/0017-bearer-registry-path-selection.md",
            "docs/adr/0018-wifi-bearer.md",
            "docs/adr/0022-domain-store-schema1-runtime-binding.md",
        ],
        "profile": {
            "method": METHOD_STATIC_DH_BOTH,
            "mandatory_suites": {
                "2": [10, -16, 8, 1, -7, 10, -16],
                "3": [30, -16, 16, 1, -7, 10, -16],
            },
            "credential": "RPK carried by CCS, resolved by kid",
            "message_4_required": True,
            "ead_allowed": False,
            "automatic_suite_downgrade_allowed": False,
            "exporter_labels": EXPORTER_LABELS,
        },
        "limits": {
            "npa1_header_bytes": NPA1_HEADER_BYTES,
            "npa1_payload_max": NPA1_PAYLOAD_MAX,
            "npa1_record_max": NPA1_RECORD_MAX,
            "npr1_profile": NPR1_PROFILE,
            "npr1_header_bytes": NPR1_HEADER_BYTES,
            "npr1_packet_max": NPR1_PACKET_MAX,
            "npr1_fragment_payload_max": NPR1_PAYLOAD_MAX,
            "npr1_fragment_count_max": NPR1_FRAGMENT_MAX,
        },
        "carrier_bindings": carriers,
        "edhoc_message_1": {
            "suite_2": {
                "hex": hex_bytes(message_1_suite2),
                "length": len(message_1_suite2),
                "sha256": hex_bytes(sha256(message_1_suite2)),
                "npa1_hex": hex_bytes(npa_m1_suite2),
            },
            "suite_3": {
                "hex": hex_bytes(message_1_suite3),
                "length": len(message_1_suite3),
                "sha256": hex_bytes(sha256(message_1_suite3)),
                "npa1_hex": hex_bytes(npa_m1_suite3),
            },
        },
        "rfc9529_method3_suite2_reference": rfc9529_reference(),
        "attachment_install": {
            "nai1_length": len(descriptor),
            "nai1_hex": hex_bytes(descriptor),
            "nai1_sha256": hex_bytes(sha256(descriptor)),
            "fields": descriptor_json,
            "install_digest": hex_bytes(install_digest),
            "nax1_length": len(nax1),
            "nax1_hex": hex_bytes(nax1),
            "nat1_length": len(nat1),
            "nat1_hex": hex_bytes(nat1),
            "protection_exporter_context_digest": hex_bytes(
                protect_context_digest
            ),
            "traffic_exporter_context_digest": hex_bytes(
                traffic_context_digest
            ),
            "aead_vector_status": "INPUTS_PINNED_CIPHERTEXT_NOT_CLAIMED",
            "opaque_ciphertext_and_tag_length": len(
                opaque_install_ciphertext_and_tag
            ),
            "npa1_hex": hex_bytes(npa_install),
        },
        "compact_radio_fragments": [
            {
                "index": index,
                "length": len(fragment),
                "hex": hex_bytes(fragment),
                "sha256": hex_bytes(sha256(fragment)),
            }
            for index, fragment in enumerate(radio_fragments)
        ],
        "n6_attachment_marker": {
            "key_hex": hex_bytes(n6at_key),
            "key_length": len(n6at_key),
            "value_hex": hex_bytes(n6at_value),
            "value_length": len(n6at_value),
            "value_sha256": hex_bytes(sha256(n6at_value)),
        },
        "required_gate_cases": [
            "NPA1-SUITE2-MESSAGE1",
            "NPA1-SUITE3-MESSAGE1",
            "NPA1-INSTALL-MAX-RADIO-FRAGMENTATION",
            "NPA1-CRC-MUTATION",
            "NPA1-RESERVED-MUTATION",
            "NPA1-LENGTH-MUTATION",
            "NPR1-CRC-MUTATION",
            "NPR1-INDEX-MUTATION",
            "NPR1-OFFSET-MUTATION",
            "NPR1-DIGEST-MUTATION",
            "NPR1-REORDER-DUPLICATE-LOSS",
            "N6AT-CRC-MUTATION",
            "N6AT-ROLE-KEY-VALUE-MISMATCH",
            "N6AT-UNKNOWN-STATE",
            "EXPORTER-LABEL-SET-EXACT",
            "EXPORTER-CONTEXT-ONE-BYTE-MUTATION",
            "RFC9529-REFERENCE-DIGESTS",
            "GATE-SELF-TEST",
        ],
    }


def canonical_json(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
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

    rendered = canonical_json(build_document())
    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(rendered)
        print(f"wrote {OUTPUT}")
        return 0
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != rendered:
            print(f"stale or missing: {OUTPUT}")
            return 1
        print(f"fresh {OUTPUT} sha256={sha256(rendered).hex()}")
        return 0

    baseline = build_document()
    altered = build_document()
    altered["limits"]["npa1_record_max"] += 1
    if canonical_json(baseline) == canonical_json(altered):
        print("self-test failed: mutation was not observed")
        return 1
    install = bytes.fromhex(
        baseline["attachment_install"]["npa1_hex"]
    )
    corrupted = bytearray(install)
    corrupted[-1] ^= 1
    stored = struct.unpack(">I", corrupted[84:88])[0]
    corrupted[84:88] = b"\0" * 4
    if crc32c(bytes(corrupted)) == stored:
        print("self-test failed: CRC mutation survived")
        return 1
    print("self-test OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
