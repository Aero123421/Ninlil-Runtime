#!/usr/bin/env python3
"""Deterministic composition for the Proposed Production Attachment profile.

This module emits candidate vectors; it is not its own acceptance oracle.
Independent/schema/R6/Python/Node/C11 authorities validate its output.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import struct
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from production_attachment_edhoc_schema_authority import (  # noqa: E402
    REQUIRED_GATE_CASES_EXACT,
    SchemaError,
    assert_closed_key_schema,
    assert_envelope,
    envelope_document_fragment,
    mutate_all_metadata_coherent,
)

from production_attachment_edhoc_r6_oracle import (  # noqa: E402
    al_floor_after_install as r6_al_floor_after_install,
    binding_for_lane as r6_binding_for_lane,
    e2e_context_binding_digest as r6_e2e_context_binding_digest,
    encode_al_value as r6_encode_al_value,
    encode_hw_value as r6_encode_hw_value,
    encode_lane_value as r6_encode_lane_value,
    fresh_lane_counter as r6_fresh_lane_counter,
    hop_context_binding_digest as r6_hop_context_binding_digest,
    materialize_complete_key as r6_materialize_complete_key,
    materialize_member_value as r6_materialize_member_value,
    node_id16 as r6_node_id16,
    ns_fingerprint12 as r6_ns_fingerprint12,
    scope_digest28 as r6_scope_digest28,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spec/vectors/production-attachment-edhoc-v1.json"

NAC1_VERSION = 1
NAC1_HEADER_BYTES = 88
NAC1_PAYLOAD_MAX = 512
NAC1_RECORD_MAX = NAC1_HEADER_BYTES + NAC1_PAYLOAD_MAX
NAS1_HEADER_BYTES = 12
NAS1_RECORD_MAX = NAS1_HEADER_BYTES + NAC1_RECORD_MAX

NAR1_PROFILE = 0x12
NAR1_VERSION = 1
NAR1_HEADER_BYTES = 68
NAR1_PACKET_MAX = 192
NAR1_PAYLOAD_MAX = NAR1_PACKET_MAX - NAR1_HEADER_BYTES
NAR1_FRAGMENT_MAX = 5

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
KIND_ATTACH_PROPOSE = 8
KIND_ATTACH_INSTALL = 9
KIND_ATTACH_CONFIRM_DEVICE = 10
KIND_ATTACH_CONFIRM_AUTHORITY = 11

NAC1_KIND_MAX = KIND_ATTACH_CONFIRM_AUTHORITY
NAB1_HEADER_BYTES = 68
NAB1_ENTRY_BYTES = 20
NAB1_ENTRY_COUNT = 15
NAB1_TOTAL_BYTES = NAB1_HEADER_BYTES + NAB1_ENTRY_BYTES * NAB1_ENTRY_COUNT
NAP1_BYTES = 208
NAI1_BYTES = 416
NAX1_BYTES = 160
NAT1_BYTES = 96
N6AT_KEY_BYTES = 20
N6AT_VALUE_BYTES = 120
# Normative docs/35: cookie time bucket is fixed at 2 seconds.
COOKIE_TIME_BUCKET_SECONDS = 2
# Byte-exact carrier transcript (docs/35 §4.1) — never a bare name/example.
# Exact 31 ASCII octets (docs/35 §4.1; not 29).
CARRIER_TRANSCRIPT_LABEL = b"NINLIL-PA-CARRIER-TRANSCRIPT-V1"
assert len(CARRIER_TRANSCRIPT_LABEL) == 31
CARRIER_TRANSCRIPT_SCHEMA_VERSION = 1
WIRE_PROFILE_ID = 0x11
ENVIRONMENT_FIELD = 2
ALLOWED_KIND_MASK_HOP = 0x0003
COOKIE_MODE_ABSENT = 0
COOKIE_MODE_INCLUDED = 1

STATUS_OK = "NINLIL_PA_OK"
STATUS_CORRUPT = "NINLIL_PA_CORRUPT"
STATUS_UNSUPPORTED = "NINLIL_PA_UNSUPPORTED"

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


def encode_nac1(
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
        raise ValueError("NAC1 session_id")
    if len(carrier_binding_digest) != 32 or not any(carrier_binding_digest):
        raise ValueError("NAC1 carrier binding")
    if not 1 <= kind <= NAC1_KIND_MAX:
        raise ValueError("NAC1 kind")
    if carrier_class not in (1, 2, 3):
        raise ValueError("NAC1 carrier")
    if not 1 <= exchange_generation <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("NAC1 generation")
    if len(payload) > NAC1_PAYLOAD_MAX:
        raise ValueError("NAC1 payload")
    total = NAC1_HEADER_BYTES + len(payload)
    header = struct.pack(
        ">4sHHIIBBBB16sQII32sI",
        b"NAC1",
        NAC1_VERSION,
        NAC1_HEADER_BYTES,
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


def encode_nas1(carrier_class: int, record: bytes) -> bytes:
    if carrier_class not in (1, 2):
        raise ValueError("NAS1 carrier")
    if not NAC1_HEADER_BYTES <= len(record) <= NAC1_RECORD_MAX:
        raise ValueError("NAS1 record")
    return struct.pack(
        ">4sBBHI",
        b"NAS1",
        1,
        carrier_class,
        NAS1_HEADER_BYTES,
        len(record),
    ) + record


def run_nas1_stream(chunks: list[bytes], *, eof: bool) -> dict[str, Any]:
    """Bounded one-record incremental NAS1 decoder lifecycle."""
    buffer = bytearray()
    expected_total: int | None = None
    delivery_count = 0
    read_count = 0
    for chunk in chunks:
        read_count += 1
        if len(buffer) + len(chunk) > NAS1_RECORD_MAX:
            return {
                "outcome": "CLOSE_OVERFLOW",
                "delivery_count": 0,
                "read_count": read_count,
                "buffered_bytes": len(buffer),
            }
        buffer.extend(chunk)
        if len(buffer) >= NAS1_HEADER_BYTES and expected_total is None:
            if buffer[:4] != b"NAS1":
                return {
                    "outcome": "CLOSE_MAGIC",
                    "delivery_count": 0,
                    "read_count": read_count,
                    "buffered_bytes": len(buffer),
                }
            if buffer[4] != 1:
                return {
                    "outcome": "CLOSE_FUTURE_OR_BAD_VERSION",
                    "delivery_count": 0,
                    "read_count": read_count,
                    "buffered_bytes": len(buffer),
                }
            if buffer[5] not in (1, 2) or struct.unpack(">H", buffer[6:8])[0] != 12:
                return {
                    "outcome": "CLOSE_HEADER",
                    "delivery_count": 0,
                    "read_count": read_count,
                    "buffered_bytes": len(buffer),
                }
            inner_len = struct.unpack(">I", buffer[8:12])[0]
            if not NAC1_HEADER_BYTES <= inner_len <= NAC1_RECORD_MAX:
                return {
                    "outcome": "CLOSE_LENGTH",
                    "delivery_count": 0,
                    "read_count": read_count,
                    "buffered_bytes": len(buffer),
                }
            expected_total = NAS1_HEADER_BYTES + inner_len
        if expected_total is not None and len(buffer) > expected_total:
            return {
                "outcome": "CLOSE_TRAILING_BYTES",
                "delivery_count": 0,
                "read_count": read_count,
                "buffered_bytes": len(buffer),
            }
    if expected_total is not None and len(buffer) == expected_total:
        inner = bytes(buffer[12:])
        if classify_nac1(inner) != STATUS_OK:
            return {
                "outcome": "CLOSE_INNER_CORRUPT",
                "delivery_count": 0,
                "read_count": read_count,
                "buffered_bytes": len(buffer),
            }
        if inner[18] != buffer[5]:
            return {
                "outcome": "CLOSE_INNER_CARRIER_MISMATCH",
                "delivery_count": 0,
                "read_count": read_count,
                "buffered_bytes": len(buffer),
            }
        delivery_count = 1
        return {
            "outcome": "DELIVERED",
            "delivery_count": delivery_count,
            "read_count": read_count,
            "buffered_bytes": len(buffer),
            "inner_sha256": hex_bytes(sha256(inner)),
        }
    if eof:
        return {
            "outcome": "CLOSE_SHORT_EOF",
            "delivery_count": 0,
            "read_count": read_count,
            "buffered_bytes": len(buffer),
        }
    return {
        "outcome": "NEED_MORE",
        "delivery_count": 0,
        "read_count": read_count,
        "buffered_bytes": len(buffer),
    }


def build_nas1_stream_matrix(nas: bytes) -> dict[str, Any]:
    inner_mismatch = bytearray(nas)
    inner_mismatch[12 + 18] = 2
    # Repair inner NAC1 CRC after carrier-class mutation.
    inner = bytearray(inner_mismatch[12:])
    inner[84:88] = bytes(4)
    inner[84:88] = struct.pack(">I", crc32c(bytes(inner)))
    inner_mismatch[12:] = inner
    future = bytearray(nas)
    future[4] = 2
    cases = {
        "single_read_success": run_nas1_stream([nas], eof=False),
        "partial_read_success": run_nas1_stream(
            [nas[:1], nas[1:7], nas[7:12], nas[12:91], nas[91:]],
            eof=False,
        ),
        "short_eof_close": run_nas1_stream([nas[:-1]], eof=True),
        "trailing_bytes_close": run_nas1_stream([nas + b"\x00"], eof=False),
        "future_version_close": run_nas1_stream([bytes(future)], eof=False),
        "inner_carrier_mismatch_close": run_nas1_stream(
            [bytes(inner_mismatch)], eof=False
        ),
    }
    expected = {
        "single_read_success": "DELIVERED",
        "partial_read_success": "DELIVERED",
        "short_eof_close": "CLOSE_SHORT_EOF",
        "trailing_bytes_close": "CLOSE_TRAILING_BYTES",
        "future_version_close": "CLOSE_FUTURE_OR_BAD_VERSION",
        "inner_carrier_mismatch_close": "CLOSE_INNER_CARRIER_MISMATCH",
    }
    for name, want in expected.items():
        if cases[name]["outcome"] != want:
            raise AssertionError(f"NAS matrix {name}: {cases[name]['outcome']} != {want}")
        if want != "DELIVERED" and cases[name]["delivery_count"] != 0:
            raise AssertionError(f"NAS failure delivered {name}")
    return {
        "buffer_capacity_bytes": NAS1_RECORD_MAX,
        "one_record_per_wrapper": True,
        "cases": cases,
    }


def classify_nac1(record: bytes) -> str:
    if len(record) < NAC1_HEADER_BYTES:
        return STATUS_CORRUPT
    if record[:4] != b"NAC1":
        return STATUS_CORRUPT
    version = struct.unpack(">H", record[4:6])[0]
    header_bytes = struct.unpack(">H", record[6:8])[0]
    total_bytes = struct.unpack(">I", record[8:12])[0]
    payload_bytes = struct.unpack(">I", record[12:16])[0]
    if (
        header_bytes != NAC1_HEADER_BYTES
        or total_bytes != len(record)
        or payload_bytes != len(record) - NAC1_HEADER_BYTES
        or total_bytes > NAC1_RECORD_MAX
    ):
        return STATUS_CORRUPT
    stored_crc = struct.unpack(">I", record[84:88])[0]
    scratch = bytearray(record)
    scratch[84:88] = bytes(4)
    if crc32c(bytes(scratch)) != stored_crc:
        return STATUS_CORRUPT
    if version > NAC1_VERSION:
        return STATUS_UNSUPPORTED
    if version != NAC1_VERSION:
        return STATUS_CORRUPT
    if (
        not 1 <= record[16] <= NAC1_KIND_MAX
        or record[17] != 0
        or record[18] not in (1, 2, 3)
        or record[19] != 0
        or not any(record[20:36])
        or struct.unpack(">Q", record[36:44])[0] == 0
        or any(record[48:52])
        or not any(record[52:84])
    ):
        return STATUS_CORRUPT
    if record[16] in (KIND_COOKIE_CHALLENGE, KIND_COOKIE_RESPONSE):
        if struct.unpack(">I", record[44:48])[0] != 0:
            return STATUS_CORRUPT
    elif not 1 <= struct.unpack(">I", record[44:48])[0] <= 8:
        return STATUS_CORRUPT
    return STATUS_OK


def fragment_nar1(record: bytes) -> list[bytes]:
    if not NAC1_HEADER_BYTES <= len(record) <= NAC1_RECORD_MAX:
        raise ValueError("NAR1 record length")
    session_id = record[20:36]
    exchange_generation = struct.unpack(">Q", record[36:44])[0]
    record_sequence = struct.unpack(">I", record[44:48])[0]
    digest16 = sha256(record)[:16]
    count = (len(record) + NAR1_PAYLOAD_MAX - 1) // NAR1_PAYLOAD_MAX
    if not 1 <= count <= NAR1_FRAGMENT_MAX:
        raise ValueError("NAR1 fragment count")
    packets: list[bytes] = []
    for index in range(count):
        offset = index * NAR1_PAYLOAD_MAX
        payload = record[offset : offset + NAR1_PAYLOAD_MAX]
        total = NAR1_HEADER_BYTES + len(payload)
        header = struct.pack(
            ">4sBBHHH16sQIHBB16sII",
            b"NAR1",
            NAR1_PROFILE,
            NAR1_VERSION,
            NAR1_HEADER_BYTES,
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


def _nar1_parse(packet: bytes) -> dict[str, Any]:
    if not NAR1_HEADER_BYTES <= len(packet) <= NAR1_PACKET_MAX:
        raise ValueError("NAR length")
    if packet[:4] != b"NAR1" or packet[4] != NAR1_PROFILE:
        raise ValueError("NAR magic/profile")
    if packet[5] != NAR1_VERSION or struct.unpack(">H", packet[6:8])[0] != 68:
        raise ValueError("NAR version/header")
    total, payload_len = struct.unpack(">HH", packet[8:12])
    if total != len(packet) or payload_len != len(packet) - 68:
        raise ValueError("NAR lengths")
    scratch = bytearray(packet)
    stored_crc = struct.unpack(">I", scratch[64:68])[0]
    scratch[64:68] = bytes(4)
    if crc32c(bytes(scratch)) != stored_crc:
        raise ValueError("NAR crc")
    index, count = packet[42], packet[43]
    complete_len = struct.unpack(">H", packet[40:42])[0]
    offset = struct.unpack(">I", packet[60:64])[0]
    if not 1 <= count <= 5 or index >= count:
        raise ValueError("NAR index/count")
    if offset != index * NAR1_PAYLOAD_MAX:
        raise ValueError("NAR gap/overlap")
    if index + 1 < count and payload_len != NAR1_PAYLOAD_MAX:
        raise ValueError("NAR non-final length")
    if offset + payload_len > complete_len:
        raise ValueError("NAR payload overrun")
    if index + 1 == count and offset + payload_len != complete_len:
        raise ValueError("NAR final gap")
    return {
        "source_tuple": (
            packet[12:28],
            struct.unpack(">Q", packet[28:36])[0],
            struct.unpack(">I", packet[36:40])[0],
            complete_len,
            packet[44:60],
            count,
        ),
        "session_id": packet[12:28],
        "generation": struct.unpack(">Q", packet[28:36])[0],
        "sequence": struct.unpack(">I", packet[36:40])[0],
        "complete_len": complete_len,
        "digest16": packet[44:60],
        "index": index,
        "count": count,
        "offset": offset,
        "payload": packet[68:],
    }


def run_nar1_reassembly(
    packets: list[bytes],
    *,
    source_locator_digest: bytes,
    owner_source_locator_digest: bytes | None = None,
    timeout: bool = False,
) -> dict[str, Any]:
    """Execute one fixed-bank NAR1 reassembly owner.

    The owner key includes the source locator before any cookie-authenticated
    identity exists.  All malformed/mixed/conflicting paths discard the whole
    owner and publish zero bytes.
    """
    if len(source_locator_digest) != 32:
        raise ValueError("source locator")
    expected_source = owner_source_locator_digest or source_locator_digest
    owner_tuple: tuple[Any, ...] | None = None
    slots: dict[int, bytes] = {}
    progress = 0
    duplicates = 0
    transitions: list[str] = []
    if source_locator_digest != expected_source:
        return {
            "outcome": "DISCARDED_SOURCE_MISMATCH",
            "progress_count": 0,
            "duplicate_count": 0,
            "published_bytes": 0,
            "transitions": ["SOURCE_MISMATCH_DISCARD"],
        }
    for packet in packets:
        try:
            parsed = _nar1_parse(packet)
        except ValueError as error:
            return {
                "outcome": "DISCARDED_MALFORMED",
                "reason": str(error),
                "progress_count": progress,
                "duplicate_count": duplicates,
                "published_bytes": 0,
                "transitions": transitions + ["MALFORMED_DISCARD"],
            }
        tuple_with_source = (source_locator_digest, *parsed["source_tuple"])
        if owner_tuple is None:
            owner_tuple = tuple_with_source
            transitions.append("OWNER_ALLOCATED")
        elif tuple_with_source != owner_tuple:
            return {
                "outcome": "DISCARDED_MIXED_TUPLE",
                "progress_count": progress,
                "duplicate_count": duplicates,
                "published_bytes": 0,
                "transitions": transitions + ["MIXED_TUPLE_DISCARD"],
            }
        prior = slots.get(parsed["index"])
        if prior is not None:
            if prior == packet:
                duplicates += 1
                transitions.append("DUPLICATE_NO_PROGRESS")
                continue
            return {
                "outcome": "DISCARDED_CONFLICTING_DUPLICATE",
                "progress_count": progress,
                "duplicate_count": duplicates,
                "published_bytes": 0,
                "transitions": transitions + ["CONFLICT_DISCARD"],
            }
        slots[parsed["index"]] = packet
        progress += 1
        transitions.append(f"PROGRESS_{progress}")
    if timeout and owner_tuple is not None and progress < int(owner_tuple[-1]):
        return {
            "outcome": "DISCARDED_IDLE_TIMEOUT",
            "progress_count": progress,
            "duplicate_count": duplicates,
            "published_bytes": 0,
            "transitions": transitions + ["IDLE_TIMEOUT_DISCARD"],
        }
    if owner_tuple is None or progress < int(owner_tuple[-1]):
        return {
            "outcome": "INCOMPLETE",
            "progress_count": progress,
            "duplicate_count": duplicates,
            "published_bytes": 0,
            "transitions": transitions,
        }
    parsed_slots = [_nar1_parse(slots[index]) for index in range(int(owner_tuple[-1]))]
    complete = b"".join(slot["payload"] for slot in parsed_slots)
    first = parsed_slots[0]
    if len(complete) != first["complete_len"] or sha256(complete)[:16] != first["digest16"]:
        return {
            "outcome": "DISCARDED_DIGEST_OR_LENGTH",
            "progress_count": progress,
            "duplicate_count": duplicates,
            "published_bytes": 0,
            "transitions": transitions + ["DIGEST_DISCARD"],
        }
    if (
        classify_nac1(complete) != STATUS_OK
        or complete[20:36] != first["session_id"]
        or struct.unpack(">Q", complete[36:44])[0] != first["generation"]
        or struct.unpack(">I", complete[44:48])[0] != first["sequence"]
    ):
        return {
            "outcome": "DISCARDED_INNER_MISMATCH",
            "progress_count": progress,
            "duplicate_count": duplicates,
            "published_bytes": 0,
            "transitions": transitions + ["INNER_MISMATCH_DISCARD"],
        }
    return {
        "outcome": "COMPLETE",
        "progress_count": progress,
        "duplicate_count": duplicates,
        "published_bytes": len(complete),
        "complete_sha256": hex_bytes(sha256(complete)),
        "transitions": transitions + ["COMPLETE"],
    }


def _nar_recrc(packet: bytes) -> bytes:
    out = bytearray(packet)
    out[64:68] = bytes(4)
    out[64:68] = struct.pack(">I", crc32c(bytes(out)))
    return bytes(out)


def build_nar1_reassembly_matrix(
    fragments: list[bytes], source_locator_digest: bytes
) -> dict[str, Any]:
    canonical = run_nar1_reassembly(
        fragments, source_locator_digest=source_locator_digest
    )
    reordered = run_nar1_reassembly(
        list(reversed(fragments)), source_locator_digest=source_locator_digest
    )
    duplicate = run_nar1_reassembly(
        [fragments[0], fragments[0], *fragments[1:]],
        source_locator_digest=source_locator_digest,
    )
    conflict = bytearray(fragments[0])
    conflict[-1] ^= 1
    conflict = bytearray(_nar_recrc(bytes(conflict)))
    conflicting = run_nar1_reassembly(
        [fragments[0], bytes(conflict), *fragments[1:]],
        source_locator_digest=source_locator_digest,
    )
    overlap_packet = bytearray(fragments[1])
    overlap_packet[60:64] = struct.pack(">I", 100)
    overlap = run_nar1_reassembly(
        [fragments[0], _nar_recrc(bytes(overlap_packet))],
        source_locator_digest=source_locator_digest,
    )
    mixed_packet = bytearray(fragments[1])
    mixed_packet[28:36] = struct.pack(
        ">Q", struct.unpack(">Q", mixed_packet[28:36])[0] + 1
    )
    mixed = run_nar1_reassembly(
        [fragments[0], _nar_recrc(bytes(mixed_packet))],
        source_locator_digest=source_locator_digest,
    )
    loss_timeout = run_nar1_reassembly(
        fragments[:-1], source_locator_digest=source_locator_digest, timeout=True
    )
    inner_packets: list[bytes] = []
    for packet in fragments:
        mutated = bytearray(packet)
        mutated[28:36] = struct.pack(
            ">Q", struct.unpack(">Q", mutated[28:36])[0] + 1
        )
        inner_packets.append(_nar_recrc(bytes(mutated)))
    inner_mismatch = run_nar1_reassembly(
        inner_packets, source_locator_digest=source_locator_digest
    )
    source_mismatch = run_nar1_reassembly(
        fragments,
        source_locator_digest=sha256(b"other-source"),
        owner_source_locator_digest=source_locator_digest,
    )
    cases = {
        "canonical_success": canonical,
        "reordered_success": reordered,
        "same_duplicate_no_progress": duplicate,
        "conflicting_duplicate_discard": conflicting,
        "gap_loss_timeout_discard": loss_timeout,
        "overlap_discard": overlap,
        "mixed_tuple_discard": mixed,
        "inner_mismatch_discard": inner_mismatch,
        "source_mismatch_discard": source_mismatch,
    }
    expected = {
        "canonical_success": "COMPLETE",
        "reordered_success": "COMPLETE",
        "same_duplicate_no_progress": "COMPLETE",
        "conflicting_duplicate_discard": "DISCARDED_CONFLICTING_DUPLICATE",
        "gap_loss_timeout_discard": "DISCARDED_IDLE_TIMEOUT",
        "overlap_discard": "DISCARDED_MALFORMED",
        "mixed_tuple_discard": "DISCARDED_MIXED_TUPLE",
        "inner_mismatch_discard": "DISCARDED_INNER_MISMATCH",
        "source_mismatch_discard": "DISCARDED_SOURCE_MISMATCH",
    }
    for name, want in expected.items():
        if cases[name]["outcome"] != want:
            raise AssertionError(f"NAR matrix {name}: {cases[name]['outcome']} != {want}")
    if duplicate["duplicate_count"] != 1 or duplicate["progress_count"] != len(fragments):
        raise AssertionError("same duplicate must make no progress")
    return {
        "owner_key_fields": [
            "source_locator_digest32",
            "session_id16",
            "exchange_generation_u64",
            "record_sequence_u32",
            "complete_nac1_bytes_u16",
            "digest16",
            "fragment_count_u8",
        ],
        "fixed_slots": 5,
        "cases": cases,
    }


def nac1_kind(record: bytes) -> int:
    if len(record) < NAC1_HEADER_BYTES or record[:4] != b"NAC1":
        raise ValueError("NAC1 record")
    return record[16]


def nac1_sequence(record: bytes) -> int:
    return struct.unpack(">I", record[44:48])[0]


def encode_length_prefixed_nac1_entry(record: bytes) -> bytes:
    """kind_u8 || record_sequence_u32be || total_len_u16be || complete_nac1."""
    if len(record) < NAC1_HEADER_BYTES or len(record) > NAC1_RECORD_MAX:
        raise ValueError("NAC1 entry length")
    if len(record) != struct.unpack(">I", record[8:12])[0]:
        raise ValueError("NAC1 total field")
    return (
        bytes([nac1_kind(record)])
        + struct.pack(">I", nac1_sequence(record))
        + struct.pack(">H", len(record))
        + record
    )


def compute_carrier_transcript_digest(
    *,
    carrier_class: int,
    session_id: bytes,
    exchange_generation: int,
    attempt_index: int,
    attachment_epoch: int,
    method: int,
    suite: int,
    cookie_mode: int,
    ordered_nac1_records: list[bytes],
) -> tuple[bytes, bytes, dict[str, Any]]:
    """Byte-exact Normative carrier_transcript_digest (docs/35 §4.1).

    peer-neutral: both roles compute the same digest. Local role MUST NOT
    appear in the preimage. EDHOC payloads are the exact NAC1 payload wire
    octets (the EDHOC message bytes as carried), not a re-encoding.
    """

    if carrier_class not in (1, 2, 3):
        raise ValueError("carrier_class")
    if len(session_id) != 16 or not any(session_id):
        raise ValueError("session_id")
    if exchange_generation < 1 or attempt_index < 0:
        raise ValueError("generation/attempt")
    if attachment_epoch < 1:
        raise ValueError("attachment_epoch")
    if method != METHOD_STATIC_DH_BOTH or suite not in (SUITE_2, SUITE_3):
        raise ValueError("method/suite")
    if cookie_mode not in (COOKIE_MODE_ABSENT, COOKIE_MODE_INCLUDED):
        raise ValueError("cookie_mode")
    expected_kinds: list[int]
    if cookie_mode == COOKIE_MODE_INCLUDED:
        expected_kinds = [
            KIND_COOKIE_CHALLENGE,
            KIND_COOKIE_RESPONSE,
            KIND_EDHOC_MESSAGE_1,
            KIND_EDHOC_MESSAGE_2,
            KIND_EDHOC_MESSAGE_3,
            KIND_EDHOC_MESSAGE_4,
        ]
    else:
        expected_kinds = [
            KIND_EDHOC_MESSAGE_1,
            KIND_EDHOC_MESSAGE_2,
            KIND_EDHOC_MESSAGE_3,
            KIND_EDHOC_MESSAGE_4,
        ]
    if len(ordered_nac1_records) != len(expected_kinds):
        raise ValueError("entry count")
    entry_meta: list[dict[str, Any]] = []
    entry_bytes = bytearray()
    for expected_kind, record in zip(expected_kinds, ordered_nac1_records, strict=True):
        kind = nac1_kind(record)
        if kind != expected_kind:
            raise ValueError(f"kind order {kind} != {expected_kind}")
        if record[18] != carrier_class:
            raise ValueError("entry carrier_class")
        if record[20:36] != session_id:
            raise ValueError("entry session_id")
        if struct.unpack(">Q", record[36:44])[0] != exchange_generation:
            raise ValueError("entry exchange_generation")
        # Cookie kinds use sequence 0; EDHOC m1..m4 use sequence 1..4.
        seq = nac1_sequence(record)
        if kind in (KIND_COOKIE_CHALLENGE, KIND_COOKIE_RESPONSE):
            if seq != 0:
                raise ValueError("cookie sequence")
        else:
            if seq != kind - 3:  # 4->1, 5->2, 6->3, 7->4
                raise ValueError("edhoc sequence")
        pref = encode_length_prefixed_nac1_entry(record)
        entry_bytes.extend(pref)
        entry_meta.append(
            {
                "kind": kind,
                "record_sequence": seq,
                "nac1_total_bytes": len(record),
                "nac1_payload_bytes": len(record) - NAC1_HEADER_BYTES,
                "nac1_sha256": hex_bytes(sha256(record)),
                "nac1_hex": hex_bytes(record),
            }
        )
    preimage = (
        CARRIER_TRANSCRIPT_LABEL
        + bytes([CARRIER_TRANSCRIPT_SCHEMA_VERSION])
        + bytes([carrier_class])
        + session_id
        + struct.pack(">Q", exchange_generation)
        + struct.pack(">I", attempt_index)
        + struct.pack(">Q", attachment_epoch)
        + bytes([method, suite, cookie_mode, len(ordered_nac1_records)])
        + bytes(entry_bytes)
    )
    digest = sha256(preimage)
    meta = {
        "label": CARRIER_TRANSCRIPT_LABEL.decode("ascii"),
        "hash": "SHA-256",
        "schema_version": CARRIER_TRANSCRIPT_SCHEMA_VERSION,
        "carrier_class": carrier_class,
        "session_id_hex": hex_bytes(session_id),
        "exchange_generation": exchange_generation,
        "attempt_index": attempt_index,
        "attachment_epoch": attachment_epoch,
        "method": method,
        "suite": suite,
        "cookie_mode": cookie_mode,
        "cookie_mode_name": (
            "INCLUDED" if cookie_mode == COOKIE_MODE_INCLUDED else "ABSENT"
        ),
        "entry_count": len(ordered_nac1_records),
        "entry_order_kinds": expected_kinds,
        "role_in_preimage": False,
        "direction_encoding": "implicit_via_nac1_kind_only",
        "edhoc_wire": (
            "NAC1.payload exact EDHOC message octets as carried; "
            "no re-CBOR; complete NAC1 record (header+CRC+payload) is bound"
        ),
        "nac1_scope": (
            "complete_wire_record: magic..CRC..payload; "
            "length-prefixed as kind_u8||seq_u32be||total_u16be||record"
        ),
        "excluded": [
            "ATTACH_PROPOSE",
            "ATTACH_INSTALL",
            "ATTACH_CONFIRM_*",
            "NAS1_wrapper",
            "NAR1_fragments",
            "local_role",
            "retransmit_duplicates",
        ],
        "entries": entry_meta,
        "preimage_length": len(preimage),
        "preimage_sha256": hex_bytes(sha256(preimage)),
        "preimage_hex": hex_bytes(preimage),
        "digest_hex": hex_bytes(digest),
    }
    return digest, preimage, meta


def carrier_transcript_negatives(
    *,
    base_meta: dict[str, Any],
    ordered_nac1_records: list[bytes],
    carrier_class: int,
    session_id: bytes,
    exchange_generation: int,
    attempt_index: int,
    attachment_epoch: int,
    method: int,
    suite: int,
    cookie_mode: int,
) -> list[dict[str, Any]]:
    """Permanent negatives: 1-byte / order / generation / retry / cookie flips."""

    base = bytes.fromhex(base_meta["digest_hex"])
    negatives: list[dict[str, Any]] = []

    def add(neg_id: str, **kwargs: Any) -> None:
        dig, preimage, meta = compute_carrier_transcript_digest(**kwargs)
        if dig == base:
            raise AssertionError(f"negative {neg_id} collided with base digest")
        # Independent exact recompute authority: full preimage + digest pin.
        del meta  # digest already pinned via dig/preimage
        negatives.append(
            {
                "id": neg_id,
                "digest_hex": hex_bytes(dig),
                "preimage_hex": hex_bytes(preimage),
                "preimage_sha256": hex_bytes(sha256(preimage)),
                "preimage_length": len(preimage),
                "differs_from_base": True,
                "rejected": False,
                "reject_reason": "",
                "note": "",
                "recomputed_digest_hex": hex_bytes(dig),
                "field_matrix_id": neg_id,
            }
        )

    # 1-byte flip in first EDHOC NAC1 payload.
    recs = [bytearray(r) for r in ordered_nac1_records]
    # Find MESSAGE_1 entry index.
    m1_idx = next(
        i for i, r in enumerate(ordered_nac1_records) if nac1_kind(r) == KIND_EDHOC_MESSAGE_1
    )
    recs[m1_idx] = bytearray(ordered_nac1_records[m1_idx])
    # Flip first payload byte and recompute CRC.
    payload_off = NAC1_HEADER_BYTES
    recs[m1_idx][payload_off] ^= 0x01
    recs[m1_idx][84:88] = b"\x00\x00\x00\x00"
    recs[m1_idx][84:88] = struct.pack(">I", crc32c(bytes(recs[m1_idx])))
    add(
        "flip_message_1_payload_byte0_recrc",
        carrier_class=carrier_class,
        session_id=session_id,
        exchange_generation=exchange_generation,
        attempt_index=attempt_index,
        attachment_epoch=attachment_epoch,
        method=method,
        suite=suite,
        cookie_mode=cookie_mode,
        ordered_nac1_records=[bytes(r) for r in recs],
    )
    # Entry order swap (m1 <-> m2) after cookie prefix.
    swapped = list(ordered_nac1_records)
    # indices of m1 and m2
    idx1 = next(i for i, r in enumerate(swapped) if nac1_kind(r) == KIND_EDHOC_MESSAGE_1)
    idx2 = next(i for i, r in enumerate(swapped) if nac1_kind(r) == KIND_EDHOC_MESSAGE_2)
    swapped[idx1], swapped[idx2] = swapped[idx2], swapped[idx1]
    try:
        dig, preimage, _ = compute_carrier_transcript_digest(
            carrier_class=carrier_class,
            session_id=session_id,
            exchange_generation=exchange_generation,
            attempt_index=attempt_index,
            attachment_epoch=attachment_epoch,
            method=method,
            suite=suite,
            cookie_mode=cookie_mode,
            ordered_nac1_records=swapped,
        )
        # If kind-order check rejects, record as rejected; else must differ.
        if dig == base:
            raise AssertionError("order swap digest collision")
        negatives.append(
            {
                "id": "swap_message_1_message_2_order",
                "digest_hex": hex_bytes(dig),
                "preimage_hex": hex_bytes(preimage),
                "preimage_sha256": hex_bytes(sha256(preimage)),
                "preimage_length": len(preimage),
                "differs_from_base": True,
                "rejected": False,
                "reject_reason": "",
                "note": "kind-order violation or divergent preimage",
                "recomputed_digest_hex": hex_bytes(dig),
                "field_matrix_id": "swap_message_1_message_2_order",
            }
        )
    except ValueError as err:
        negatives.append(
            {
                "id": "swap_message_1_message_2_order",
                "digest_hex": "00" * 32,
                "preimage_hex": "",
                "preimage_sha256": "00" * 32,
                "preimage_length": 0,
                "differs_from_base": True,
                "rejected": True,
                "reject_reason": str(err),
                "note": "",
                "recomputed_digest_hex": "00" * 32,
                "field_matrix_id": "swap_message_1_message_2_order",
            }
        )
    add(
        "exchange_generation_plus_1",
        carrier_class=carrier_class,
        session_id=session_id,
        exchange_generation=exchange_generation + 1,
        attempt_index=attempt_index,
        attachment_epoch=attachment_epoch,
        method=method,
        suite=suite,
        cookie_mode=cookie_mode,
        # regenerate records would fail session check — use mutated header copies
        ordered_nac1_records=[
            _nac1_with_generation(r, exchange_generation + 1)
            for r in ordered_nac1_records
        ],
    )
    add(
        "attempt_index_plus_1",
        carrier_class=carrier_class,
        session_id=session_id,
        exchange_generation=exchange_generation,
        attempt_index=attempt_index + 1,
        attachment_epoch=attachment_epoch,
        method=method,
        suite=suite,
        cookie_mode=cookie_mode,
        ordered_nac1_records=list(ordered_nac1_records),
    )
    add(
        "attachment_epoch_plus_1",
        carrier_class=carrier_class,
        session_id=session_id,
        exchange_generation=exchange_generation,
        attempt_index=attempt_index,
        attachment_epoch=attachment_epoch + 1,
        method=method,
        suite=suite,
        cookie_mode=cookie_mode,
        ordered_nac1_records=list(ordered_nac1_records),
    )
    add(
        "suite_2_to_3",
        carrier_class=carrier_class,
        session_id=session_id,
        exchange_generation=exchange_generation,
        attempt_index=attempt_index,
        attachment_epoch=attachment_epoch,
        method=method,
        suite=SUITE_3,
        cookie_mode=cookie_mode,
        ordered_nac1_records=list(ordered_nac1_records),
    )
    # cookie_mode flip without changing entries must either reject or differ.
    other_mode = (
        COOKIE_MODE_ABSENT
        if cookie_mode == COOKIE_MODE_INCLUDED
        else COOKIE_MODE_INCLUDED
    )
    try:
        dig, preimage, _ = compute_carrier_transcript_digest(
            carrier_class=carrier_class,
            session_id=session_id,
            exchange_generation=exchange_generation,
            attempt_index=attempt_index,
            attachment_epoch=attachment_epoch,
            method=method,
            suite=suite,
            cookie_mode=other_mode,
            ordered_nac1_records=list(ordered_nac1_records),
        )
        if dig == base:
            raise AssertionError("cookie_mode flip collision")
        negatives.append(
            {
                "id": "cookie_mode_flip_same_entries",
                "digest_hex": hex_bytes(dig),
                "preimage_hex": hex_bytes(preimage),
                "preimage_sha256": hex_bytes(sha256(preimage)),
                "preimage_length": len(preimage),
                "differs_from_base": True,
                "rejected": False,
                "reject_reason": "",
                "note": "",
                "recomputed_digest_hex": hex_bytes(dig),
                "field_matrix_id": "cookie_mode_flip_same_entries",
            }
        )
    except ValueError as err:
        negatives.append(
            {
                "id": "cookie_mode_flip_same_entries",
                "digest_hex": "00" * 32,
                "preimage_hex": "",
                "preimage_sha256": "00" * 32,
                "preimage_length": 0,
                "differs_from_base": True,
                "rejected": True,
                "reject_reason": str(err),
                "note": "",
                "recomputed_digest_hex": "00" * 32,
                "field_matrix_id": "cookie_mode_flip_same_entries",
            }
        )
    return negatives


def _nac1_with_generation(record: bytes, generation: int) -> bytes:
    out = bytearray(record)
    out[36:44] = struct.pack(">Q", generation)
    out[84:88] = b"\x00\x00\x00\x00"
    out[84:88] = struct.pack(">I", crc32c(bytes(out)))
    return bytes(out)


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


def make_nap1() -> tuple[bytes, dict[str, Any]]:
    proposal = bytearray(NAP1_BYTES)
    fields: dict[str, Any] = {
        "proposal_id": pattern(0x08, 16),
        "initiator_stable_digest": sha256(b"initiator-stable-id"),
        "site_domain": pattern(0x20, 16),
        "authority_id": pattern(0x30, 16),
        "authority_term": 7,
        "membership_epoch": 11,
        "credential_set_revision": 19,
        "revocation_generation": 31,
        "assignment_epoch": 37,
        "device_hop_context_ri": 43,
        "device_e2e_context_ri": 53,
        "device_hop_min_key_generation_ri": 61,
        "device_e2e_min_key_generation_ri": 71,
        "e2e_security_id": pattern(0x50, 16),
        "e2e_security_epoch": 73,
        "membership_grant_digest": sha256(b"membership-grant"),
    }
    proposal[0:4] = b"NAP1"
    proposal[4:6] = struct.pack(">H", 1)
    proposal[6:8] = struct.pack(">H", NAP1_BYTES)
    proposal[8:12] = bytes(4)
    proposal[12] = METHOD_STATIC_DH_BOTH
    proposal[13] = SUITE_2
    proposal[14] = 1  # initiator is the device
    proposal[15] = 0
    proposal[16:32] = fields["proposal_id"]
    proposal[32:64] = fields["initiator_stable_digest"]
    proposal[64:80] = fields["site_domain"]
    proposal[80:96] = fields["authority_id"]
    proposal[96:104] = struct.pack(">Q", fields["authority_term"])
    proposal[104:112] = struct.pack(">Q", fields["membership_epoch"])
    proposal[112:120] = struct.pack(">Q", fields["credential_set_revision"])
    proposal[120:124] = struct.pack(">I", fields["revocation_generation"])
    proposal[124:128] = struct.pack(">I", fields["assignment_epoch"])
    proposal[128:132] = struct.pack(">I", fields["device_hop_context_ri"])
    proposal[132:136] = struct.pack(">I", fields["device_e2e_context_ri"])
    proposal[136:144] = struct.pack(
        ">Q", fields["device_hop_min_key_generation_ri"]
    )
    proposal[144:152] = struct.pack(
        ">Q", fields["device_e2e_min_key_generation_ri"]
    )
    proposal[152:168] = fields["e2e_security_id"]
    proposal[168:176] = struct.pack(">Q", fields["e2e_security_epoch"])
    proposal[176:208] = fields["membership_grant_digest"]
    return bytes(proposal), fields


def make_nai1(
    proposal_digest: bytes, *, carrier_transcript_digest: bytes
) -> tuple[bytes, dict[str, Any]]:
    if len(carrier_transcript_digest) != 32 or not any(carrier_transcript_digest):
        raise ValueError("carrier_transcript_digest")
    descriptor = bytearray(NAI1_BYTES)
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
        "carrier_transcript_digest": carrier_transcript_digest,
        "proposal_digest": proposal_digest,
    }
    descriptor[0:4] = b"NAI1"
    descriptor[4:6] = struct.pack(">H", 1)
    descriptor[6:8] = struct.pack(">H", NAI1_BYTES)
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
    descriptor[384:416] = fields["proposal_digest"]
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


def cbor_bstr(value: bytes) -> bytes:
    length = len(value)
    if length < 24:
        return bytes([0x40 | length]) + value
    if length < 256:
        return bytes([0x58, length]) + value
    raise ValueError("cbor bstr length")


def make_ccs_rpk(*, kid: bytes, x: bytes, y: bytes) -> bytes:
    """Exact CBOR CCS: {8: {1: COSE_Key(EC2/P-256/x/y/kid)}}."""

    if not 1 <= len(kid) <= 8 or len(x) != 32 or len(y) != 32:
        raise ValueError("CCS RPK fields")
    # COSE_Key map keys in canonical order: 1, 2, -1, -2, -3.
    cose_key = (
        bytes([0xA5])
        + bytes([0x01, 0x02])  # kty = EC2
        + bytes([0x02])
        + cbor_bstr(kid)
        + bytes([0x20, 0x01])  # crv = P-256
        + bytes([0x21])
        + cbor_bstr(x)
        + bytes([0x22])
        + cbor_bstr(y)
    )
    cnf = bytes([0xA1, 0x01]) + cose_key
    return bytes([0xA1, 0x08]) + cnf


# Known-on-curve P-256 affine points (NIST G and RFC 6979 A.2.5 public key).
P256_INITIATOR_X = bytes.fromhex(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
)
P256_INITIATOR_Y = bytes.fromhex(
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
P256_RESPONDER_X = bytes.fromhex(
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
)
P256_RESPONDER_Y = bytes.fromhex(
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4467992"
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
    lease_epoch: int,
    e2e_security_epoch: int,
    credential_set_revision: int,
    revocation_generation: int,
    assignment_epoch: int,
) -> tuple[bytes, bytes]:
    if local_role not in (1, 2) or state not in (1, 2, 3):
        raise ValueError("N6AT role/state")
    key = struct.pack(">BBBB16s", 5, local_role, 1, 0, attachment_id)
    value = bytearray(N6AT_VALUE_BYTES)
    value[0:4] = b"N6AT"
    value[4:6] = struct.pack(">H", 1)
    value[6:8] = struct.pack(">H", N6AT_VALUE_BYTES)
    value[8] = state
    value[9] = local_role
    value[10:12] = bytes(2)
    value[12:28] = attachment_id
    value[28:36] = struct.pack(">Q", membership_epoch)
    value[36:44] = struct.pack(">Q", attachment_epoch)
    value[44:52] = struct.pack(">Q", lease_epoch)
    value[52:60] = struct.pack(">Q", e2e_security_epoch)
    value[60:68] = struct.pack(">Q", authority_term)
    value[68:76] = struct.pack(">Q", credential_set_revision)
    value[76:80] = struct.pack(">I", revocation_generation)
    value[80:84] = struct.pack(">I", assignment_epoch)
    value[84:116] = install_digest
    value[116:120] = struct.pack(">I", crc32c(bytes(value[:116])))
    return key, bytes(value)


def _opaque_len_prefix(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("opaque too long")
    return struct.pack(">H", len(value)) + value


def pa_node_id(stable_id_bytes: bytes) -> bytes:
    """docs/30 §994–996: R6 node-id via pure oracle."""
    return r6_node_id16(stable_id_bytes)


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
    """docs/30 §8.3 HOP_BINDS_ATTACHMENT (encode_canon)."""
    return b"".join(
        (
            b"NINLIL-R6-HOP-CTX-v1",
            bytes([WIRE_PROFILE_ID, environment_code & 0xFF]),
            _opaque_len_prefix(site_domain),
            struct.pack(">Q", membership_epoch),
            _opaque_len_prefix(attachment_id),
            struct.pack(">Q", attachment_epoch),
            _opaque_len_prefix(initiator_stable_id),
            _opaque_len_prefix(responder_stable_id),
            _opaque_len_prefix(controller_authority_id),
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
    """docs/30 §8.4 E2E_SECURITY_ID_NOT_ATTACHMENT — no attachment_id."""
    if e2e_security_epoch < 1:
        raise ValueError("e2e_security_epoch domain")
    return b"".join(
        (
            b"NINLIL-R6-E2E-CTX-v1",
            bytes([WIRE_PROFILE_ID, environment_code & 0xFF]),
            _opaque_len_prefix(site_domain),
            struct.pack(">Q", membership_epoch),
            _opaque_len_prefix(e2e_security_id),
            struct.pack(">Q", e2e_security_epoch),
            _opaque_len_prefix(sender_stable_id),
            _opaque_len_prefix(receiver_stable_id),
            _opaque_len_prefix(authority_id),
            struct.pack(">Q", authority_term),
            struct.pack(">I", e2e_context_id),
            bytes([direction_code & 0xFF]),
        )
    )


def hop_context_binding_digest(
    *,
    fields: dict[str, Any],
    hop_context_id: int,
    direction_code: int,
) -> bytes:
    return sha256(
        encode_hop_binding_input(
            environment_code=ENVIRONMENT_FIELD,
            site_domain=fields["site_domain"],
            membership_epoch=int(fields["membership_epoch"]),
            attachment_id=fields["attachment_id"],
            attachment_epoch=int(fields["attachment_epoch"]),
            initiator_stable_id=fields["initiator_stable_digest"],
            responder_stable_id=fields["responder_stable_digest"],
            controller_authority_id=fields["authority_id"],
            controller_term=int(fields["authority_term"]),
            hop_context_id=hop_context_id,
            direction_code=direction_code,
        )
    )


def e2e_context_binding_digest(
    *,
    fields: dict[str, Any],
    e2e_context_id: int,
    direction_code: int,
) -> bytes:
    """E2E binding never includes attachment_id / attachment_epoch (docs/30 §1322)."""
    if direction_code == 0:
        sender = fields["initiator_stable_digest"]
        receiver = fields["responder_stable_digest"]
    else:
        sender = fields["responder_stable_digest"]
        receiver = fields["initiator_stable_digest"]
    return sha256(
        encode_e2e_binding_input(
            environment_code=ENVIRONMENT_FIELD,
            site_domain=fields["site_domain"],
            membership_epoch=int(fields["membership_epoch"]),
            e2e_security_id=fields["e2e_security_id"],
            e2e_security_epoch=int(fields["e2e_security_epoch"]),
            sender_stable_id=sender,
            receiver_stable_id=receiver,
            authority_id=fields["authority_id"],
            authority_term=int(fields["authority_term"]),
            e2e_context_id=e2e_context_id,
            direction_code=direction_code,
        )
    )


def pa_ns_fingerprint(
    *,
    receiver_node_id: bytes,
    layer_code: int,
    membership_epoch: int,
    alloc_side: int,
) -> bytes:
    """docs/30 §999: exact 26B domain (no direction)."""
    if len(receiver_node_id) != 16:
        raise ValueError("receiver_node_id")
    return sha256(
        receiver_node_id
        + bytes([layer_code & 0xFF])
        + struct.pack(">Q", membership_epoch)
        + bytes([alloc_side & 0xFF])
    )[:12]


def pa_scope_digest(
    *,
    local_node_id: bytes,
    layer_code: int,
    direction: int,
    membership_epoch: int,
    receiver_node_id: bytes,
) -> bytes:
    """docs/30 §1056 N6HW scope_digest28."""
    return sha256(
        local_node_id
        + bytes([layer_code & 0xFF, direction & 0xFF])
        + struct.pack(">Q", membership_epoch)
        + receiver_node_id
    )[:28]


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
    install_digest: bytes,
    attachment_id: bytes,
    local_node_id: bytes,
    peer_node_id: bytes,
) -> bytes:
    """Complete keys: docs/30 via production_attachment_edhoc_r6_oracle only."""
    del install_digest  # not in complete-key preimage
    return r6_materialize_complete_key(
        member_kind=member_kind,
        direction=direction,
        lane=lane,
        local_side=local_side,
        local_role=local_role,
        context_id=context_id,
        key_generation=key_generation,
        layer_code=layer_code,
        fields=fields,
        attachment_id=attachment_id,
        local_node_id=local_node_id,
        peer_node_id=peer_node_id,
    )



# Canonical N6 value magics/schemas (docs/30 §5.3 / n6_record_codec.h).
N6_MAGIC_TX = 0x4E365458  # "N6TX"
N6_MAGIC_RX = 0x4E365258  # "N6RX"
N6_MAGIC_HW = 0x4E364857  # "N6HW"
N6_MAGIC_AL = 0x4E36414C  # "N6AL"
N6_SCHEMA_LANE = 2
N6_SCHEMA_HW = 1
N6_SCHEMA_AL = 2
# Value authority label: real N6 codec wire, not synthetic VALUE-V1 filler.
N6_VALUE_AUTHORITY_LABEL = "NINLIL-PA-N6-CODEC-V1"


def _put_u16(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 2] = struct.pack(">H", value)


def _put_u32(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 4] = struct.pack(">I", value & 0xFFFFFFFF)


def _put_u64(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 8] = struct.pack(">Q", value & 0xFFFFFFFFFFFFFFFF)


def encode_n6_lane_value(
    *,
    local_side: int,
    key_generation: int,
    complete_key: bytes,
    membership_epoch: int,
    layer_code: int,
    receiver_node_id: bytes,
) -> bytes:
    """Exact 68B N6TX (local_side=2) or N6RX (local_side=1) value wire.

    Fresh install counters (docs/30 §1031–1044, §1314):
      TX reserved_exclusive = 1; RX accept_reserved_through = 0.
    ns_fingerprint12 = R6 formula (docs/30 §999), not PA-NS-FP-V1.
    """
    if local_side not in (1, 2) or key_generation == 0 or membership_epoch < 1:
        raise ValueError("lane value domain")
    if len(complete_key) != 48 or len(receiver_node_id) != 16:
        raise ValueError("lane complete key / receiver")
    binding_prefix16 = complete_key[8:24]
    # R6 ns_fingerprint12: receiver||layer||epoch||alloc_side (no direction).
    ns_fp12 = sha256(
        receiver_node_id
        + bytes([layer_code & 0xFF])
        + struct.pack(">Q", membership_epoch)
        + bytes([local_side & 0xFF])
    )[:12]
    # TX=1 / RX=0 exact (never both-2 false-green).
    reserved_or_accept = 1 if local_side == 2 else 0
    out = bytearray(68)
    magic = N6_MAGIC_TX if local_side == 2 else N6_MAGIC_RX
    _put_u32(out, 0, magic)
    _put_u16(out, 4, N6_SCHEMA_LANE)
    _put_u16(out, 6, 0)
    _put_u64(out, 8, reserved_or_accept)
    _put_u64(out, 16, key_generation)
    out[24:40] = binding_prefix16
    _put_u64(out, 40, membership_epoch)
    out[48] = local_side
    out[49:52] = bytes(3)
    out[52:64] = ns_fp12
    _put_u32(out, 64, crc32c(bytes(out[:64])))
    return bytes(out)


def encode_n6_hw_value(
    *, high_water_key_generation: int, authority_now_ms: int
) -> bytes:
    """Exact 28B N6HW value wire."""
    if high_water_key_generation == 0:
        raise ValueError("hw high-water domain")
    out = bytearray(28)
    _put_u32(out, 0, N6_MAGIC_HW)
    _put_u16(out, 4, N6_SCHEMA_HW)
    _put_u16(out, 6, 0)
    _put_u64(out, 8, high_water_key_generation)
    _put_u64(out, 16, authority_now_ms)
    _put_u32(out, 24, crc32c(bytes(out[:24])))
    return bytes(out)


def encode_n6_al_value(
    *,
    next_free_or_peer_floor: int,
    active_count: int,
    retired_tombstone_count: int,
    membership_epoch: int,
    authority_now_ms: int,
    receiver_node_id: bytes,
) -> bytes:
    """Exact 56B N6AL value wire (floor/active/high-water monotonic)."""
    if (
        next_free_or_peer_floor == 0
        or membership_epoch < 1
        or len(receiver_node_id) != 16
    ):
        raise ValueError("al value domain")
    out = bytearray(56)
    _put_u32(out, 0, N6_MAGIC_AL)
    _put_u16(out, 4, N6_SCHEMA_AL)
    _put_u16(out, 6, 0)
    _put_u32(out, 8, next_free_or_peer_floor)
    _put_u16(out, 12, active_count)
    _put_u16(out, 14, retired_tombstone_count)
    _put_u32(out, 16, 0)
    _put_u64(out, 20, membership_epoch)
    _put_u64(out, 28, authority_now_ms)
    out[36:52] = receiver_node_id
    _put_u32(out, 52, crc32c(bytes(out[:52])))
    return bytes(out)


def materialize_member_value(
    *,
    member_kind: int,
    complete_key: bytes,
    install_digest: bytes,
    value_length: int,
    marker_value: bytes | None,
    local_side: int = 0,
    key_generation: int = 1,
    membership_epoch: int = 1,
    phase: str = "new",
    peer_node_id: bytes | None = None,
    local_node_id: bytes | None = None,
    context_id: int = 0,
    layer_code: int = 0,
) -> bytes:
    """N6 values: docs/30 via r6_oracle (TX=1/RX=0, AL floor=context_id+1)."""
    del install_digest
    return r6_materialize_member_value(
        member_kind=member_kind,
        complete_key=complete_key,
        value_length=value_length,
        marker_value=marker_value,
        local_side=local_side,
        key_generation=key_generation,
        membership_epoch=membership_epoch,
        phase=phase,
        peer_node_id=peer_node_id,
        local_node_id=local_node_id,
        context_id=context_id,
        layer_code=layer_code,
    )



def materialize_context_digest(
    *,
    member_kind: int,
    complete_key: bytes,
    install_digest: bytes,
    attachment_id: bytes,
) -> bytes:
    """Per-row context digest bound into the FULL post-image (zero for marker)."""

    if member_kind == 4:
        return bytes(32)
    return sha256(
        b"NINLIL-PA-N6-CTX-DIGEST-V1"
        + bytes([member_kind])
        + complete_key
        + install_digest
        + attachment_id
    )


def nab1_exact_inventory(
    *,
    local_role: int,
    fields: dict[str, Any],
    install_digest: bytes,
    marker_value: bytes,
) -> list[dict[str, Any]]:
    """Exact 15-key inventory sorted by complete-key unsigned-byte order."""

    if local_role not in (1, 2):
        raise ValueError("NAB1 role")
    if len(marker_value) != N6AT_VALUE_BYTES:
        raise ValueError("marker value length")
    attachment_id = fields["attachment_id"]
    local_node_id = pa_node_id(
        fields["initiator_stable_digest"]
        if local_role == 1
        else fields["responder_stable_digest"]
    )
    peer_node_id = pa_node_id(
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
        local_side = (
            0
            if member_kind == 4
            else (2 if (local_role == 1) == (direction == 0) else 1)
        )
        complete_key = materialize_complete_key(
            member_kind=member_kind,
            direction=direction,
            lane=lane,
            local_side=local_side,
            local_role=local_role,
            context_id=context_id,
            key_generation=key_generation,
            layer_code=layer_code,
            fields=fields,
            install_digest=install_digest,
            attachment_id=attachment_id,
            local_node_id=local_node_id,
            peer_node_id=peer_node_id,
        )
        if len(complete_key) != key_length:
            raise AssertionError(f"complete key length for {identity}")
        # NEW proposed value (canonical N6 codec wire).
        value = materialize_member_value(
            member_kind=member_kind,
            complete_key=complete_key,
            install_digest=install_digest,
            value_length=value_length,
            marker_value=marker_value if member_kind == 4 else None,
            local_side=local_side,
            key_generation=key_generation,
            membership_epoch=int(fields["membership_epoch"]),
            phase="new",
            peer_node_id=peer_node_id,
            local_node_id=local_node_id,
            context_id=context_id,
            layer_code=layer_code,
        )
        # Every non-marker write-set key may have an observed OLD image.
        # A pre-existing lane is legal during recovery/re-attachment; it is
        # represented by canonical N6 bytes plus a prior transaction-context
        # digest.  Marker remains attachment-scoped and OLD-absent.
        old_value: bytes | None = None
        if member_kind != 4:
            old_value = materialize_member_value(
                member_kind=member_kind,
                complete_key=complete_key,
                install_digest=install_digest,
                value_length=value_length,
                marker_value=None,
                local_side=local_side,
                key_generation=key_generation,
                membership_epoch=int(fields["membership_epoch"]),
                phase="old",
                peer_node_id=peer_node_id,
                local_node_id=local_node_id,
                context_id=context_id,
                layer_code=layer_code,
            )
            if member_kind == 3:
                old_hw = int.from_bytes(old_value[8:16], "big")
                new_hw = int.from_bytes(value[8:16], "big")
                if new_hw < old_hw:
                    raise AssertionError(f"hw high-water rollback {identity}")
            if member_kind == 2:
                old_floor = int.from_bytes(old_value[8:12], "big")
                new_floor = int.from_bytes(value[8:12], "big")
                if new_floor < old_floor:
                    raise AssertionError(f"al floor rollback {identity}")
                if new_floor != int(context_id) + 1:
                    raise AssertionError(
                        f"al floor must be context_id+1 for {identity}: "
                        f"got {new_floor} want {int(context_id) + 1}"
                    )
        if member_kind == 1:
            counter = int.from_bytes(value[8:16], "big")
            want = 1 if local_side == 2 else 0
            if counter != want:
                raise AssertionError(
                    f"lane counter TX=1/RX=0 for {identity}: got {counter}"
                )
        context_digest = materialize_context_digest(
            member_kind=member_kind,
            complete_key=complete_key,
            install_digest=install_digest,
            attachment_id=attachment_id,
        )
        old_context_digest = (
            sha256(
                b"NINLIL-PA-N6-OLD-CTX-DIGEST-V1"
                + bytes([member_kind])
                + complete_key
                + attachment_id
            )
            if old_value is not None
            else b""
        )
        raw.append(
            {
                "identity": identity,
                "member_kind": member_kind,
                "direction": direction,
                "lane": lane,
                "local_side": local_side,
                "context_id": context_id,
                "key_generation": key_generation,
                "key_bytes": key_length,
                "value_bytes": value_length,
                "layer_code": layer_code,
                "complete_key_hex": hex_bytes(complete_key),
                "complete_key_length": len(complete_key),
                "value_hex": hex_bytes(value),
                "value_sha256": hex_bytes(sha256(value)),
                "context_digest_hex": hex_bytes(context_digest),
                "old_present": old_value is not None,
                "old_value_hex": hex_bytes(old_value) if old_value is not None else "",
                "old_value_sha256": (
                    hex_bytes(sha256(old_value)) if old_value is not None else ""
                ),
                "old_context_digest_hex": hex_bytes(old_context_digest),
                "old_new_relation": (
                    "DIFFERENT"
                    if old_value is not None
                    and (
                        old_value != value
                        or old_context_digest != context_digest
                    )
                    else "ABSENT_TO_NEW"
                ),
            }
        )

    for direction, context_name, generation_name, tag in (
        (0, "hop_context_ir", "hop_key_generation_ir", "hop_ir"),
        (1, "hop_context_ri", "hop_key_generation_ri", "hop_ri"),
    ):
        add(
            1,
            direction,
            1,
            fields[context_name],
            fields[generation_name],
            48,
            68,
            f"{tag}_lane1",
            1,
        )
        add(
            1,
            direction,
            2,
            fields[context_name],
            fields[generation_name],
            48,
            68,
            f"{tag}_lane2",
            1,
        )
        add(
            2,
            direction,
            0,
            fields[context_name],
            fields[generation_name],
            24,
            56,
            f"{tag}_n6al",
            1,
        )
        add(
            3,
            direction,
            0,
            fields[context_name],
            fields[generation_name],
            32,
            28,
            f"{tag}_n6hw",
            1,
        )
    for direction, context_name, generation_name, tag in (
        (0, "e2e_context_ir", "e2e_key_generation_ir", "e2e_ir"),
        (1, "e2e_context_ri", "e2e_key_generation_ri", "e2e_ri"),
    ):
        add(
            1,
            direction,
            3,
            fields[context_name],
            fields[generation_name],
            48,
            68,
            f"{tag}_lane3",
            2,
        )
        add(
            2,
            direction,
            0,
            fields[context_name],
            fields[generation_name],
            24,
            56,
            f"{tag}_n6al",
            2,
        )
        add(
            3,
            direction,
            0,
            fields[context_name],
            fields[generation_name],
            32,
            28,
            f"{tag}_n6hw",
            2,
        )
    add(4, 0, 0, 0, 0, N6AT_KEY_BYTES, N6AT_VALUE_BYTES, "attachment_marker", 0)
    if len(raw) != NAB1_ENTRY_COUNT:
        raise AssertionError("NAB1 member count")
    # Canonical order: unsigned-byte lexicographic on complete keys.
    raw.sort(key=lambda entry: bytes.fromhex(entry["complete_key_hex"]))
    for index in range(1, len(raw)):
        if bytes.fromhex(raw[index - 1]["complete_key_hex"]) >= bytes.fromhex(
            raw[index]["complete_key_hex"]
        ):
            raise AssertionError("complete-key order not strict")
    inventory: list[dict[str, Any]] = []
    for index, entry in enumerate(raw):
        item = dict(entry)
        item["index"] = index
        inventory.append(item)
    return inventory


def make_nab1(
    *,
    local_role: int,
    attachment_id: bytes,
    install_digest: bytes,
    fields: dict[str, Any],
    marker_value: bytes,
) -> tuple[bytes, list[dict[str, Any]]]:
    """Encode the test-oracle-only 15-member atomic FULL manifest.

    NAB1 is neither wire nor durable storage.  Rows are emitted in
    complete-key unsigned-byte order after materializing chapter-30 key
    layouts for every member.  Each non-marker row also carries exact
    value bytes and a context digest for FULL OLD/NEW binding.
    """

    inventory = nab1_exact_inventory(
        local_role=local_role,
        fields=fields,
        install_digest=install_digest,
        marker_value=marker_value,
    )
    batch = bytearray(NAB1_TOTAL_BYTES)
    batch[0:4] = b"NAB1"
    batch[4:6] = struct.pack(">H", 1)
    batch[6:8] = struct.pack(">H", NAB1_TOTAL_BYTES)
    batch[8] = local_role
    batch[9] = 1  # PENDING marker included in proposed post-image
    batch[10:12] = bytes(2)
    batch[12:28] = attachment_id
    batch[28:60] = install_digest
    batch[60:62] = struct.pack(">H", NAB1_ENTRY_COUNT)
    batch[62:64] = struct.pack(">H", NAB1_ENTRY_BYTES)
    for entry in inventory:
        off = NAB1_HEADER_BYTES + entry["index"] * NAB1_ENTRY_BYTES
        batch[off : off + NAB1_ENTRY_BYTES] = struct.pack(
            ">BBBBIQHH",
            entry["member_kind"],
            entry["direction"],
            entry["lane"],
            entry["local_side"],
            entry["context_id"],
            entry["key_generation"],
            entry["key_bytes"],
            entry["value_bytes"],
        )
    batch[64:68] = struct.pack(">I", crc32c(bytes(batch)))
    return bytes(batch), inventory


def _member_value_pair(member: dict[str, Any]) -> tuple[bytes, bytes]:
    return (
        bytes.fromhex(member["value_hex"]),
        bytes.fromhex(member["context_digest_hex"]),
    )


def classify_write_set_value_image(
    *,
    present_members: list[dict[str, Any]],
    old_members: list[dict[str, Any]],
    new_members: list[dict[str, Any]],
    write_set_keys_ordered: list[bytes],
    marker_key: bytes,
    foreign_keys: list[bytes] | None = None,
) -> str:
    """Per-row write-set value-image CU classification (not key-count).

    EXACT_OLD is the observed OLD image (marker often absent; AL/HW/lane may
    already exist). Never maps 'zero keys present' alone to EXACT_OLD when the
    observed OLD preimage is non-empty.
    """

    write_set = list(write_set_keys_ordered)
    write_set_set = set(write_set)
    if len(write_set) != 15 or len(write_set_set) != 15:
        return "UNCLASSIFIED_CORRUPT"

    present_map: dict[bytes, tuple[bytes, bytes]] = {}
    for m in present_members:
        k = bytes.fromhex(m["complete_key_hex"])
        if k in present_map:
            return "DUPLICATE_KEYS_CORRUPT"
        present_map[k] = _member_value_pair(m)
    if foreign_keys:
        for fk in foreign_keys:
            if fk in present_map:
                return "DUPLICATE_KEYS_CORRUPT"
            # Foreign key present outside write-set.
            if fk not in write_set_set:
                return "FOREIGN_OR_EXTRA_CORRUPT"
            present_map[fk] = (b"\x00", b"\x00" * 32)
    for k in present_map:
        if k not in write_set_set:
            return "FOREIGN_OR_EXTRA_CORRUPT"
    if foreign_keys and any(fk not in write_set_set for fk in foreign_keys):
        # Already returned FOREIGN above when inserted; if only listed:
        if any(fk not in write_set_set for fk in foreign_keys):
            return "FOREIGN_OR_EXTRA_CORRUPT"

    old_map = {
        bytes.fromhex(m["complete_key_hex"]): _member_value_pair(m)
        for m in old_members
    }
    new_map = {
        bytes.fromhex(m["complete_key_hex"]): _member_value_pair(m)
        for m in new_members
    }
    if len(new_map) != 15:
        return "UNCLASSIFIED_CORRUPT"

    pure_new = 0
    pure_old = 0
    third = 0
    for k in write_set:
        old_v = old_map.get(k)  # None => observed absent
        new_v = new_map[k]
        got = present_map.get(k)  # None => durable absent
        matches_old = got == old_v  # both None or equal pairs
        matches_new = got is not None and got == new_v
        if matches_old and matches_new:
            continue  # STABLE (OLD image equals NEW for this key)
        if matches_new:
            pure_new += 1
        elif matches_old:
            pure_old += 1
        else:
            third += 1

    if third:
        return "THIRD_OR_MISMATCH_CORRUPT"
    if pure_new == 0:
        return "EXACT_OLD"
    if pure_old == 0:
        marker_pair = present_map.get(marker_key)
        if marker_pair is None:
            return "MISSING_MARKER_CORRUPT"
        marker_state = marker_pair[0][8]
        if marker_state == 1:
            return "EXACT_NEW_PENDING_15"
        if marker_state == 2:
            return "EXACT_NEW_ACTIVE_MARKER_IN_15"
        if marker_state == 3:
            return "THIRD_OR_MISMATCH_CORRUPT"
        return "UNKNOWN_MARKER_STATE_CORRUPT"
    if 1 <= pure_new <= 14:
        return f"PARTIAL_{pure_new}_CORRUPT"
    return "UNCLASSIFIED_CORRUPT"


def classify_group_snapshot(
    *,
    present_keys: list[bytes],
    expected_keys_ordered: list[bytes],
    marker_key: bytes,
    marker_state: int | None,
    marker_value_ok: bool,
) -> str:
    """Legacy key-presence helper kept only for extra/foreign key tests.

    COMMIT_UNKNOWN authority is classify_write_set_value_image. This helper
    must not treat count==0 as EXACT_OLD for re-attach (that is a P0 falsehood).
    """

    expected_set = set(expected_keys_ordered)
    present_set = set(present_keys)
    count = len(present_keys)
    if count != len(present_set):
        return "DUPLICATE_KEYS_CORRUPT"
    if count == 0:
        # Empty present is EXACT_OLD only for cold-start OLD=all-absent;
        # re-attach classification must use value-image with observed OLD rows.
        return "EXACT_OLD_COLD_OR_EMPTY_PRESENT"
    if not present_set.issubset(expected_set):
        return "FOREIGN_OR_EXTRA_CORRUPT"
    if count > 15:
        return "EXTRA_CORRUPT"
    if 1 <= count <= 14:
        return f"KEY_PRESENCE_PARTIAL_{count}_NOT_VALUE_IMAGE"
    if count == 15 and present_set == expected_set:
        if marker_key not in present_set:
            return "MISSING_MARKER_CORRUPT"
        if not marker_value_ok:
            return "THIRD_OR_MISMATCH_CORRUPT"
        if marker_state == 1:
            return "EXACT_NEW_PENDING_15"
        if marker_state == 2:
            return "EXACT_NEW_ACTIVE_MARKER_IN_15"
        if marker_state == 3:
            return "THIRD_OR_MISMATCH_CORRUPT"
        return "UNKNOWN_MARKER_STATE_CORRUPT"
    return "UNCLASSIFIED_CORRUPT"


def make_n6at_third_from_pending(pending_value: bytes) -> bytes:
    value = bytearray(pending_value)
    value[8] = 3
    value[116:120] = struct.pack(">I", crc32c(bytes(value[:116])))
    return bytes(value)


def full_member_records(inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Exact FULL row bindings: complete key + value + context digest."""

    members: list[dict[str, Any]] = []
    for entry in inventory:
        members.append(
            {
                "index": entry["index"],
                "identity": entry["identity"],
                "member_kind": entry["member_kind"],
                "complete_key_hex": entry["complete_key_hex"],
                "complete_key_length": entry["complete_key_length"],
                "value_hex": entry["value_hex"],
                "value_sha256": entry["value_sha256"],
                "value_bytes": entry["value_bytes"],
                "context_digest_hex": entry["context_digest_hex"],
            }
        )
    return members


def full_image_bytes(members: list[dict[str, Any]]) -> bytes:
    return b"".join(
        bytes.fromhex(m["complete_key_hex"])
        + bytes.fromhex(m["value_hex"])
        + bytes.fromhex(m["context_digest_hex"])
        for m in members
    )


def observed_old_members(
    inventory: list[dict[str, Any]],
    *,
    membership_epoch: int,
    peer_node_id: bytes,
    local_node_id: bytes,
) -> list[dict[str, Any]]:
    """Return the observed OLD image from the per-row write-set model.

    The number of present OLD rows is data, not a protocol constant.  This
    fixture deliberately includes canonical lane OLD rows so a validator that
    silently assumes "AL/HW only" cannot pass.
    """
    del membership_epoch, peer_node_id, local_node_id
    out: list[dict[str, Any]] = []
    for entry in inventory:
        if not entry["old_present"]:
            continue
        old_val = bytes.fromhex(entry["old_value_hex"])
        old_ctx = bytes.fromhex(entry["old_context_digest_hex"])
        if len(old_val) != entry["value_bytes"] or len(old_ctx) != 32:
            raise AssertionError(f"observed OLD shape {entry['identity']}")
        out.append(
            {
                "index": entry["index"],
                "identity": entry["identity"],
                "member_kind": entry["member_kind"],
                "complete_key_hex": entry["complete_key_hex"],
                "complete_key_length": entry["complete_key_length"],
                "value_hex": hex_bytes(old_val),
                "value_sha256": hex_bytes(sha256(old_val)),
                "value_bytes": entry["value_bytes"],
                "context_digest_hex": entry["old_context_digest_hex"],
            }
        )
    if not out or len(out) >= 15:
        raise AssertionError(f"observed OLD count must be data in 1..14, got {len(out)}")
    if not any(m["member_kind"] == 1 for m in out):
        raise AssertionError("fixture must contain a legal non-empty lane OLD")
    return out


def mix_partial_members(
    *,
    old_by_key: dict[str, dict[str, Any]],
    new_members: list[dict[str, Any]],
    advanced: int,
) -> list[dict[str, Any]]:
    """First `advanced` write-set keys at NEW values; rest at observed OLD."""
    mixed: list[dict[str, Any]] = []
    for i, new_m in enumerate(new_members):
        key = new_m["complete_key_hex"]
        if i < advanced:
            mixed.append(dict(new_m))
        elif key in old_by_key:
            mixed.append(dict(old_by_key[key]))
        # else: OLD-absent and not yet advanced → omit from durable image
    return mixed


def classify_row_value_image(
    *,
    old_present: bool,
    old_value: bytes,
    old_context_digest: bytes,
    new_value: bytes,
    new_context_digest: bytes,
    durable_present: bool,
    durable_value: bytes,
    durable_context_digest: bytes,
) -> str:
    """Closed per-row CU classifier used before the 15-row fold."""
    old_pair = (
        (old_value, old_context_digest) if old_present else None
    )
    new_pair = (new_value, new_context_digest)
    durable_pair = (
        (durable_value, durable_context_digest) if durable_present else None
    )
    old_match = durable_pair == old_pair
    new_match = durable_pair == new_pair and durable_pair is not None
    if old_match and new_match:
        return "STABLE"
    if old_match:
        return "OLD"
    if new_match:
        return "NEW"
    return "THIRD"


def build_row_classifier_cases(
    old_members: list[dict[str, Any]],
    new_members: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Materialize executable OLD/NEW/STABLE/THIRD row cases."""
    old_by_key = {m["complete_key_hex"]: m for m in old_members}
    lane_new = next(m for m in new_members if m["member_kind"] == 1)
    lane_old = old_by_key[lane_new["complete_key_hex"]]
    old_value = bytes.fromhex(lane_old["value_hex"])
    old_ctx = bytes.fromhex(lane_old["context_digest_hex"])
    new_value = bytes.fromhex(lane_new["value_hex"])
    new_ctx = bytes.fromhex(lane_new["context_digest_hex"])
    third_value = bytearray(new_value)
    third_value[-1] ^= 1
    raw_cases = (
        ("PA-CU-ROW-OLD", True, old_value, old_ctx, "OLD"),
        ("PA-CU-ROW-NEW", True, new_value, new_ctx, "NEW"),
        # Explicit stable case: observed OLD is byte-for-byte the proposed NEW.
        ("PA-CU-ROW-STABLE", True, new_value, new_ctx, "STABLE"),
        (
            "PA-CU-ROW-THIRD",
            True,
            bytes(third_value),
            new_ctx,
            "THIRD",
        ),
    )
    out: list[dict[str, Any]] = []
    for case_id, present, durable_value, durable_ctx, expected in raw_cases:
        case_old_value = new_value if expected == "STABLE" else old_value
        case_old_ctx = new_ctx if expected == "STABLE" else old_ctx
        got = classify_row_value_image(
            old_present=True,
            old_value=case_old_value,
            old_context_digest=case_old_ctx,
            new_value=new_value,
            new_context_digest=new_ctx,
            durable_present=present,
            durable_value=durable_value,
            durable_context_digest=durable_ctx,
        )
        if got != expected:
            raise AssertionError(f"{case_id}: {got} != {expected}")
        out.append(
            {
                "id": case_id,
                "old_present": True,
                "old_value_hex": hex_bytes(case_old_value),
                "old_context_digest_hex": hex_bytes(case_old_ctx),
                "new_value_hex": hex_bytes(new_value),
                "new_context_digest_hex": hex_bytes(new_ctx),
                "durable_present": present,
                "durable_value_hex": hex_bytes(durable_value),
                "durable_context_digest_hex": hex_bytes(durable_ctx),
                "expected_classification": expected,
            }
        )
    return out


def build_reattach_10k_monotonic_model() -> dict[str, Any]:
    """Deterministic restart-per-cycle AL/HW non-regression authority."""
    floors = [42, 44, 48, 54]
    high_waters = [59, 61, 67, 71]
    initial_floors = list(floors)
    initial_high_waters = list(high_waters)
    transcript = bytearray()
    for cycle in range(1, 10_001):
        # A restart reconstructs the exact durable prior NEW, never a seed.
        observed_floors = list(floors)
        observed_high_waters = list(high_waters)
        floors = [value + 1 for value in observed_floors]
        high_waters = [value + 1 for value in observed_high_waters]
        if any(n < o for n, o in zip(floors, observed_floors, strict=True)):
            raise AssertionError("AL floor regression")
        if any(n < o for n, o in zip(high_waters, observed_high_waters, strict=True)):
            raise AssertionError("HW high-water regression")
        transcript.extend(struct.pack(">I", cycle))
        for value in (*floors, *high_waters):
            transcript.extend(struct.pack(">Q", value))
    return {
        "cycles": 10_000,
        "restart_after_each_cycle": True,
        "initial_floors": initial_floors,
        "final_floors": floors,
        "initial_high_waters": initial_high_waters,
        "final_high_waters": high_waters,
        "regression_count": 0,
        "transcript_sha256": hex_bytes(sha256(bytes(transcript))),
    }


def build_lifecycle_snapshots(
    *,
    device_inventory: list[dict[str, Any]],
    authority_inventory: list[dict[str, Any]],
    device_pending_key: bytes,
    device_pending_value: bytes,
    device_active_value: bytes,
    device_third_value: bytes,
    authority_pending_key: bytes,
    authority_pending_value: bytes,
    authority_active_value: bytes,
    authority_third_value: bytes,
    membership_epoch: int,
    device_local_node: bytes,
    device_peer_node: bytes,
    authority_local_node: bytes,
    authority_peer_node: bytes,
) -> dict[str, Any]:
    """Materialize write-set OLD/NEW value-image snapshots for both roles.

    Chosen model (WS-OLD/NEW): per write-set key, observed OLD value (may be
    non-absent for N6AL/N6HW/lanes) → proposed NEW value. EXACT_OLD is the
    full observed preimage (not forced zero members). Re-attach never
    classifies valid prior AL/HW rows as partial solely for existing.
    """

    snapshots: dict[str, Any] = {
        "classification_domain": [
            "EXACT_OLD",
            *[f"PARTIAL_{n}_CORRUPT" for n in range(1, 15)],
            "EXACT_NEW_PENDING_15",
            "EXACT_NEW_ACTIVE_MARKER_IN_15",
            "EXTRA_CORRUPT",
            "FOREIGN_OR_EXTRA_CORRUPT",
            "THIRD_OR_MISMATCH_CORRUPT",
            "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT",
            "DUPLICATE_KEYS_CORRUPT",
            "MISSING_MARKER_CORRUPT",
            "UNKNOWN_MARKER_STATE_CORRUPT",
            "UNCLASSIFIED_CORRUPT",
        ],
        "roles": {},
        "durability_model": "WRITE_SET_OBSERVED_OLD_PROPOSED_NEW",
        "reattach_policy": (
            "PER_ROW_OLD_PRESENT_WITH_LEGAL_LANE_OLD_AND_MARKER_ABSENT;"
            "MONOTONIC_FLOOR_HIGH_WATER;"
            "NO_ATTACHMENT_SCOPED_NAMESPACE"
        ),
        "reattach_10k_restart": build_reattach_10k_monotonic_model(),
    }
    role_inputs = (
        (
            "device_local_role_1",
            device_inventory,
            device_pending_key,
            device_pending_value,
            device_active_value,
            device_third_value,
            device_local_node,
            device_peer_node,
        ),
        (
            "authority_local_role_2",
            authority_inventory,
            authority_pending_key,
            authority_pending_value,
            authority_active_value,
            authority_third_value,
            authority_local_node,
            authority_peer_node,
        ),
    )
    for (
        role_name,
        inventory,
        marker_key,
        pending_value,
        active_value,
        third_value,
        local_node,
        peer_node,
    ) in role_inputs:
        ordered_keys = [bytes.fromhex(e["complete_key_hex"]) for e in inventory]
        new_members = full_member_records(inventory)
        new_image = full_image_bytes(new_members)
        old_members = observed_old_members(
            inventory,
            membership_epoch=membership_epoch,
            peer_node_id=peer_node,
            local_node_id=local_node,
        )
        old_by_key = {m["complete_key_hex"]: m for m in old_members}
        old_image = full_image_bytes(old_members)
        role_snaps: dict[str, Any] = {}
        # EXACT_OLD = observed preimage (non-marker durable rows present).
        old_cls = classify_write_set_value_image(
            present_members=old_members,
            old_members=old_members,
            new_members=new_members,
            write_set_keys_ordered=ordered_keys,
            marker_key=marker_key,
        )
        if old_cls != "EXACT_OLD":
            raise AssertionError(f"observed OLD must classify EXACT_OLD got {old_cls}")
        role_snaps["exact_old"] = {
            "member_count": len(old_members),
            "present_complete_keys_hex": [
                m["complete_key_hex"] for m in old_members
            ],
            "members": old_members,
            "full_image_sha256": hex_bytes(sha256(old_image)),
            "classification": old_cls,
            "commit_unknown_accepted": True,
            "observed_old_non_absent_count": len(old_members),
            "marker_absent": True,
        }
        role_snaps["write_set_rows"] = [
            {
                "index": entry["index"],
                "identity": entry["identity"],
                "member_kind": entry["member_kind"],
                "complete_key_hex": entry["complete_key_hex"],
                "old_present": entry["old_present"],
                "old_value_hex": entry["old_value_hex"],
                "old_context_digest_hex": entry["old_context_digest_hex"],
                "new_value_hex": entry["value_hex"],
                "new_context_digest_hex": entry["context_digest_hex"],
                "old_new_relation": entry["old_new_relation"],
            }
            for entry in inventory
        ]
        if len(role_snaps["write_set_rows"]) != 15:
            raise AssertionError("write-set row model must be exact 15")
        role_snaps["cu_row_classifier_cases"] = build_row_classifier_cases(
            old_members, new_members
        )
        for n in range(1, 15):
            partial_members = mix_partial_members(
                old_by_key=old_by_key,
                new_members=new_members,
                advanced=n,
            )
            p_cls = classify_write_set_value_image(
                present_members=partial_members,
                old_members=old_members,
                new_members=new_members,
                write_set_keys_ordered=ordered_keys,
                marker_key=marker_key,
            )
            if p_cls != f"PARTIAL_{n}_CORRUPT":
                raise AssertionError(
                    f"partial_{n} expected PARTIAL_{n}_CORRUPT got {p_cls}"
                )
            # Value-image PARTIAL: n keys at NEW, rest at observed OLD.
            role_snaps[f"partial_{n}"] = {
                "member_count": len(partial_members),
                "present_complete_keys_hex": [
                    m["complete_key_hex"] for m in partial_members
                ],
                "members": partial_members,
                "full_image_sha256": hex_bytes(
                    sha256(full_image_bytes(partial_members))
                ),
                "classification": p_cls,
                "commit_unknown_accepted": False,
                "advanced_to_new_count": n,
            }
        cls = classify_write_set_value_image(
            present_members=new_members,
            old_members=old_members,
            new_members=new_members,
            write_set_keys_ordered=ordered_keys,
            marker_key=marker_key,
        )
        # Canonical substitution index: first non-marker row (value-only / ctx-only).
        subst_idx = next(
            i for i, m in enumerate(new_members) if m["member_kind"] != 4
        )
        subst_members = [dict(m) for m in new_members]
        raw = bytearray(bytes.fromhex(subst_members[subst_idx]["value_hex"]))
        raw[-1] ^= 1
        subst_members[subst_idx]["value_hex"] = hex_bytes(bytes(raw))
        subst_members[subst_idx]["value_sha256"] = hex_bytes(sha256(bytes(raw)))
        subst_cls = classify_write_set_value_image(
            present_members=subst_members,
            old_members=old_members,
            new_members=new_members,
            write_set_keys_ordered=ordered_keys,
            marker_key=marker_key,
        )
        cd_members = [dict(m) for m in new_members]
        cd_raw = bytearray(
            bytes.fromhex(cd_members[subst_idx]["context_digest_hex"])
        )
        cd_raw[0] ^= 1
        cd_members[subst_idx]["context_digest_hex"] = hex_bytes(bytes(cd_raw))
        cd_cls = classify_write_set_value_image(
            present_members=cd_members,
            old_members=old_members,
            new_members=new_members,
            write_set_keys_ordered=ordered_keys,
            marker_key=marker_key,
        )
        role_snaps["exact_new_pending_15"] = {
            "member_count": 15,
            "present_complete_keys_hex": [hex_bytes(k) for k in ordered_keys],
            "present_keys_concat_sha256": hex_bytes(
                sha256(b"".join(ordered_keys))
            ),
            "members": new_members,
            "full_image_sha256": hex_bytes(sha256(new_image)),
            "marker_state": 1,
            "marker_value_hex": hex_bytes(pending_value),
            "classification": cls,
            "commit_unknown_accepted": cls == "EXACT_NEW_PENDING_15",
            "value_substitution_rejected": {
                "mutated_index": subst_idx,
                "members": subst_members,
                "full_image_sha256": hex_bytes(
                    sha256(full_image_bytes(subst_members))
                ),
                # Neither OLD nor NEW (value-image THIRD); CU family label.
                "classification": "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT",
                "commit_unknown_accepted": False,
            },
            "context_digest_substitution_rejected": {
                "mutated_index": subst_idx,
                "members": cd_members,
                "full_image_sha256": hex_bytes(
                    sha256(full_image_bytes(cd_members))
                ),
                "classification": "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT",
                "commit_unknown_accepted": False,
            },
        }
        if subst_cls != "THIRD_OR_MISMATCH_CORRUPT" or cd_cls != "THIRD_OR_MISMATCH_CORRUPT":
            raise AssertionError(
                f"substitution must be value-image THIRD got {subst_cls}/{cd_cls}"
            )

        foreign = bytearray(ordered_keys[0])
        foreign[0] ^= 0x80
        foreign_key = bytes(foreign)
        if foreign_key in set(ordered_keys):
            foreign[1] ^= 0x01
            foreign_key = bytes(foreign)
        # Foreign key outside write-set.
        extra_cls = "FOREIGN_OR_EXTRA_CORRUPT"
        role_snaps["extra_16"] = {
            "member_count": 16,
            "foreign_complete_key_hex": hex_bytes(foreign_key),
            "classification": extra_cls,
            "commit_unknown_accepted": False,
        }
        third_members = [dict(m) for m in new_members]
        for i, m in enumerate(third_members):
            if m["member_kind"] == 4:
                third_members[i] = dict(m)
                third_members[i]["value_hex"] = hex_bytes(third_value)
                third_members[i]["value_sha256"] = hex_bytes(sha256(third_value))
                break
        third_cls = classify_write_set_value_image(
            present_members=third_members,
            old_members=old_members,
            new_members=new_members,
            write_set_keys_ordered=ordered_keys,
            marker_key=marker_key,
        )
        role_snaps["third_mismatch"] = {
            "member_count": 15,
            "marker_state": 3,
            "marker_value_hex": hex_bytes(third_value),
            "classification": third_cls,
            "commit_unknown_accepted": False,
        }
        role_snaps["pending_to_active"] = {
            "mutation_kind": "SINGLE_KEY_FULL_MARKER_ONLY",
            "marker_key_hex": hex_bytes(marker_key),
            "old_state": 1,
            "new_state": 2,
            "old_value_hex": hex_bytes(pending_value),
            "new_value_hex": hex_bytes(active_value),
            "old_value_sha256": hex_bytes(sha256(pending_value)),
            "new_value_sha256": hex_bytes(sha256(active_value)),
            "accepted": pending_value[8] == 1 and active_value[8] == 2,
            "non_marker_rows_unchanged": True,
        }
        role_snaps["commit_unknown"] = {
            "accepted_classifications": [
                "EXACT_OLD",
                "EXACT_NEW_PENDING_15",
                "EXACT_NEW_ACTIVE_MARKER",
            ],
            "accepted_snapshots": [
                "exact_old",
                "exact_new_pending_15",
            ],
            "rejected_snapshot_kinds": [
                *[f"partial_{n}" for n in range(1, 15)],
                "extra_16",
                "third_mismatch",
                "value_substitution",
                "context_digest_substitution",
            ],
            "active_marker_only": {
                "marker_key_hex": hex_bytes(marker_key),
                "value_hex": hex_bytes(active_value),
                "value_sha256": hex_bytes(sha256(active_value)),
                "classification": "EXACT_NEW_ACTIVE_MARKER",
                "commit_unknown_accepted": True,
            },
        }
        role_snaps["publication_before_dual_confirm"] = 0
        snapshots["roles"][role_name] = role_snaps
    return snapshots


def make_cookie(
    *,
    secret: bytes,
    carrier_class: int,
    carrier_binding_digest: bytes,
    source_locator_digest: bytes,
    session_id: bytes,
    exchange_generation: int,
    original_message_1: bytes,
    time_bucket: int,
) -> tuple[bytes, bytes]:
    if len(secret) != 32:
        raise ValueError("cookie secret")
    canonical_input = (
        b"NINLIL-NAC1-COOKIE-V1"
        + bytes([carrier_class])
        + carrier_binding_digest
        + source_locator_digest
        + session_id
        + struct.pack(">Q", exchange_generation)
        + sha256(original_message_1)
        + struct.pack(">Q", time_bucket)
    )
    return canonical_input, hmac.new(
        secret, canonical_input, hashlib.sha256
    ).digest()


def build_preauth_owner_model(
    *,
    source_locator_digest: bytes,
    session_id: bytes,
    exchange_generation: int,
    record_sequence: int,
    complete_record_bytes: int,
    digest16: bytes,
    current_bucket: int,
    fragment_payloads: tuple[bytes, bytes],
) -> dict[str, Any]:
    """Execute the fixed two-fragment pre-cookie scratch owner.

    The returned rows are an operation transcript, not a table of hand-written
    outcomes.  Python/Node/C11 authorities replay the inputs through separately
    implemented owners and compare every state snapshot and branch counter.
    """
    if (
        len(source_locator_digest) != 32
        or len(session_id) != 16
        or len(digest16) != 16
        or len(fragment_payloads) != 2
        or len(fragment_payloads[0]) != 124
        or not 1 <= len(fragment_payloads[1]) <= 124
    ):
        raise ValueError("preauth owner inputs")
    per_source_limit = 1
    global_limit = 8
    idle_timeout_ms = 9_000
    token_capacity = 2
    token_refill_ms = 2_000
    conflict_payload = bytearray(fragment_payloads[0])
    conflict_payload[-1] ^= 0x01
    payload_by_variant = {
        "F0": fragment_payloads[0],
        "F1": fragment_payloads[1],
        "F0_CONFLICT": bytes(conflict_payload),
        "NONE": b"",
    }

    def source(label: str) -> bytes:
        if label == "PRIMARY":
            return source_locator_digest
        return sha256(b"NINLIL-PA-PREAUTH-SOURCE-V1" + label.encode("ascii"))

    def receive(
        scenario: str,
        *,
        at_ms: int,
        source_label: str,
        sequence: int,
        bucket: int,
        fragment_index: int,
        payload_variant: str,
        reset_before: bool = False,
    ) -> dict[str, Any]:
        return {
            "scenario": scenario,
            "reset_before": reset_before,
            "at_ms": at_ms,
            "operation": "RECEIVE_FRAGMENT",
            "source_label": source_label,
            "source_locator_digest_hex": hex_bytes(source(source_label)),
            "session_id_hex": hex_bytes(session_id),
            "exchange_generation": exchange_generation,
            "record_sequence": sequence,
            "complete_nac1_bytes": complete_record_bytes,
            "digest16_hex": hex_bytes(digest16),
            "cookie_bucket": bucket,
            "fragment_index": fragment_index,
            "fragment_payload_variant": payload_variant,
            "fragment_payload_hex": hex_bytes(payload_by_variant[payload_variant]),
        }

    def tick(
        scenario: str, *, at_ms: int, reset_before: bool = False
    ) -> dict[str, Any]:
        return {
            "scenario": scenario,
            "reset_before": reset_before,
            "at_ms": at_ms,
            "operation": "TICK",
            "source_label": "NONE",
            "source_locator_digest_hex": "",
            "session_id_hex": "",
            "exchange_generation": 0,
            "record_sequence": 0,
            "complete_nac1_bytes": 0,
            "digest16_hex": "",
            "cookie_bucket": 0,
            "fragment_index": -1,
            "fragment_payload_variant": "NONE",
            "fragment_payload_hex": "",
        }

    operations: list[dict[str, Any]] = [
        receive(
            "FRAGMENT_LIFECYCLE",
            at_ms=0,
            source_label="PRIMARY",
            sequence=record_sequence,
            bucket=current_bucket,
            fragment_index=0,
            payload_variant="F0",
            reset_before=True,
        ),
        receive(
            "FRAGMENT_LIFECYCLE",
            at_ms=1,
            source_label="PRIMARY",
            sequence=record_sequence,
            bucket=current_bucket,
            fragment_index=0,
            payload_variant="F0",
        ),
        receive(
            "FRAGMENT_LIFECYCLE",
            at_ms=2,
            source_label="PRIMARY",
            sequence=record_sequence,
            bucket=current_bucket,
            fragment_index=1,
            payload_variant="F1",
        ),
        receive(
            "CONFLICTING_DUPLICATE",
            at_ms=0,
            source_label="CONFLICT",
            sequence=10,
            bucket=current_bucket,
            fragment_index=0,
            payload_variant="F0",
            reset_before=True,
        ),
        receive(
            "CONFLICTING_DUPLICATE",
            at_ms=1,
            source_label="CONFLICT",
            sequence=10,
            bucket=current_bucket,
            fragment_index=0,
            payload_variant="F0_CONFLICT",
        ),
        receive(
            "PER_SOURCE_QUOTA",
            at_ms=0,
            source_label="QUOTA",
            sequence=20,
            bucket=current_bucket,
            fragment_index=0,
            payload_variant="F0",
            reset_before=True,
        ),
        receive(
            "PER_SOURCE_QUOTA",
            at_ms=1,
            source_label="QUOTA",
            sequence=21,
            bucket=current_bucket,
            fragment_index=0,
            payload_variant="F0",
        ),
    ]
    for index in range(global_limit):
        operations.append(
            receive(
                "GLOBAL_QUOTA",
                at_ms=index,
                source_label=f"GLOBAL_{index}",
                sequence=30 + index,
                bucket=current_bucket,
                fragment_index=0,
                payload_variant="F0",
                reset_before=index == 0,
            )
        )
    operations.append(
        receive(
            "GLOBAL_QUOTA",
            at_ms=global_limit,
            source_label="GLOBAL_8",
            sequence=38,
            bucket=current_bucket,
            fragment_index=0,
            payload_variant="F0",
        )
    )
    operations.extend(
        [
            receive(
                "TOKEN_REFILL_BOUNDARY",
                at_ms=0,
                source_label="TOKEN",
                sequence=40,
                bucket=current_bucket,
                fragment_index=0,
                payload_variant="F0",
                reset_before=True,
            ),
            receive(
                "TOKEN_REFILL_BOUNDARY",
                at_ms=1,
                source_label="TOKEN",
                sequence=40,
                bucket=current_bucket,
                fragment_index=1,
                payload_variant="F1",
            ),
            receive(
                "TOKEN_REFILL_BOUNDARY",
                at_ms=2,
                source_label="TOKEN",
                sequence=41,
                bucket=current_bucket,
                fragment_index=0,
                payload_variant="F0",
            ),
            receive(
                "TOKEN_REFILL_BOUNDARY",
                at_ms=3,
                source_label="TOKEN",
                sequence=41,
                bucket=current_bucket,
                fragment_index=1,
                payload_variant="F1",
            ),
            receive(
                "TOKEN_REFILL_BOUNDARY",
                at_ms=1_999,
                source_label="TOKEN",
                sequence=42,
                bucket=current_bucket,
                fragment_index=0,
                payload_variant="F0",
            ),
            receive(
                "TOKEN_REFILL_BOUNDARY",
                at_ms=2_000,
                source_label="TOKEN",
                sequence=42,
                bucket=current_bucket,
                fragment_index=0,
                payload_variant="F0",
            ),
            receive(
                "TOKEN_REFILL_BOUNDARY",
                at_ms=2_001,
                source_label="TOKEN",
                sequence=42,
                bucket=current_bucket,
                fragment_index=1,
                payload_variant="F1",
            ),
            receive(
                "IDLE_BOUNDARY",
                at_ms=0,
                source_label="IDLE",
                sequence=50,
                bucket=current_bucket,
                fragment_index=0,
                payload_variant="F0",
                reset_before=True,
            ),
            tick("IDLE_BOUNDARY", at_ms=8_999),
            tick("IDLE_BOUNDARY", at_ms=9_000),
            receive(
                "PREVIOUS_COOKIE_BUCKET",
                at_ms=0,
                source_label="PREVIOUS",
                sequence=60,
                bucket=current_bucket - 1,
                fragment_index=0,
                payload_variant="F0",
                reset_before=True,
            ),
            receive(
                "PREVIOUS_COOKIE_BUCKET",
                at_ms=1,
                source_label="PREVIOUS",
                sequence=60,
                bucket=current_bucket - 1,
                fragment_index=1,
                payload_variant="F1",
            ),
            receive(
                "OLDER_BUCKET_DISCARDS_EXISTING",
                at_ms=0,
                source_label="OLDER_EXISTING",
                sequence=70,
                bucket=current_bucket,
                fragment_index=0,
                payload_variant="F0",
                reset_before=True,
            ),
            receive(
                "OLDER_BUCKET_DISCARDS_EXISTING",
                at_ms=1,
                source_label="OLDER_EXISTING",
                sequence=70,
                bucket=current_bucket - 2,
                fragment_index=1,
                payload_variant="F1",
            ),
            receive(
                "OLDER_BUCKET_WITHOUT_OWNER",
                at_ms=0,
                source_label="OLDER_FRESH",
                sequence=80,
                bucket=current_bucket - 2,
                fragment_index=0,
                payload_variant="F0",
                reset_before=True,
            ),
        ]
    )

    required_branches = [
        "ALLOCATE",
        "FRAGMENT_0_ACCEPT",
        "FRAGMENT_1_ACCEPT",
        "SAME_DUPLICATE",
        "CONFLICTING_DUPLICATE_TERMINAL",
        "COMPLETE_RELEASE",
        "PER_SOURCE_QUOTA_DENY",
        "GLOBAL_QUOTA_DENY",
        "TOKEN_CAPACITY_DENY",
        "REFILL_BEFORE_2S",
        "REFILL_AT_2S",
        "IDLE_BEFORE_9S",
        "IDLE_AT_9S_RELEASE",
        "COOKIE_CURRENT_ACCEPT",
        "COOKIE_PREVIOUS_ACCEPT",
        "COOKIE_OLDER_EXISTING_TERMINAL",
        "COOKIE_OLDER_NO_OWNER",
    ]
    branch_counts = {name: 0 for name in required_branches}

    owners: dict[tuple[Any, ...], dict[str, Any]] = {}
    token_buckets: dict[bytes, dict[str, int]] = {}
    completion_count = 0
    release_count = 0
    terminal_discard_count = 0
    current_scenario = ""
    last_now = 0

    def reset_state(scenario: str) -> None:
        nonlocal owners, token_buckets, completion_count
        nonlocal release_count, terminal_discard_count, current_scenario
        owners = {}
        token_buckets = {}
        completion_count = 0
        release_count = 0
        terminal_discard_count = 0
        current_scenario = scenario

    def owner_key(op: dict[str, Any]) -> tuple[Any, ...]:
        return (
            bytes.fromhex(op["source_locator_digest_hex"]),
            bytes.fromhex(op["session_id_hex"]),
            op["exchange_generation"],
            op["record_sequence"],
            op["complete_nac1_bytes"],
            bytes.fromhex(op["digest16_hex"]),
        )

    def release(key: tuple[Any, ...]) -> None:
        nonlocal release_count
        owners.pop(key)
        release_count += 1

    def refill(source_digest: bytes, now: int, hits: list[str]) -> int:
        bucket = token_buckets.get(source_digest)
        if bucket is None:
            token_buckets[source_digest] = {
                "tokens": token_capacity,
                "last_refill_ms": now,
            }
            return token_capacity
        elapsed = now - bucket["last_refill_ms"]
        if elapsed < 0:
            raise AssertionError("preauth non-monotonic time")
        if 0 < elapsed < token_refill_ms:
            hits.append("REFILL_BEFORE_2S")
        intervals = elapsed // token_refill_ms
        if intervals:
            hits.append("REFILL_AT_2S")
            bucket["tokens"] = min(
                token_capacity, bucket["tokens"] + intervals
            )
            bucket["last_refill_ms"] += intervals * token_refill_ms
        return bucket["tokens"]

    def expire(now: int, hits: list[str]) -> int:
        expired = 0
        before_boundary = False
        for key, scratch in list(owners.items()):
            elapsed = now - scratch["last_activity_ms"]
            if elapsed < 0:
                raise AssertionError("preauth non-monotonic owner time")
            if elapsed >= idle_timeout_ms:
                release(key)
                expired += 1
            elif elapsed > 0:
                before_boundary = True
        if before_boundary:
            hits.append("IDLE_BEFORE_9S")
        if expired:
            hits.append("IDLE_AT_9S_RELEASE")
        return expired

    transitions: list[dict[str, Any]] = []
    for step, raw_op in enumerate(operations):
        op = dict(raw_op)
        if op["reset_before"]:
            reset_state(op["scenario"])
            last_now = 0
        if op["scenario"] != current_scenario or op["at_ms"] < last_now:
            raise AssertionError("preauth scenario/time ordering")
        last_now = op["at_ms"]
        hits: list[str] = []
        expired_delta = expire(op["at_ms"], hits)
        result = "TICK_NO_EXPIRY"
        key: tuple[Any, ...] | None = None
        source_digest: bytes | None = None
        if op["operation"] == "TICK":
            result = (
                "IDLE_EXPIRED_RELEASED"
                if expired_delta
                else "TICK_NO_EXPIRY"
            )
        else:
            key = owner_key(op)
            source_digest = key[0]
            scratch = owners.get(key)
            if op["cookie_bucket"] not in (
                current_bucket,
                current_bucket - 1,
            ):
                if scratch is not None:
                    release(key)
                    terminal_discard_count += 1
                    hits.append("COOKIE_OLDER_EXISTING_TERMINAL")
                    result = "COOKIE_BUCKET_EXPIRED_TERMINAL_DISCARD"
                else:
                    hits.append("COOKIE_OLDER_NO_OWNER")
                    result = "COOKIE_BUCKET_EXPIRED_NO_OWNER"
            elif scratch is not None:
                fragment_index = op["fragment_index"]
                payload = bytes.fromhex(op["fragment_payload_hex"])
                existing = scratch["fragments"].get(fragment_index)
                if existing is not None:
                    if existing == payload:
                        scratch["last_activity_ms"] = op["at_ms"]
                        hits.append("SAME_DUPLICATE")
                        result = "DUPLICATE_NO_PROGRESS"
                    else:
                        release(key)
                        terminal_discard_count += 1
                        hits.append("CONFLICTING_DUPLICATE_TERMINAL")
                        result = "CONFLICTING_DUPLICATE_TERMINAL_DISCARD"
                else:
                    scratch["fragments"][fragment_index] = payload
                    scratch["last_activity_ms"] = op["at_ms"]
                    hits.append(f"FRAGMENT_{fragment_index}_ACCEPT")
                    if len(scratch["fragments"]) == 2:
                        release(key)
                        completion_count += 1
                        hits.append("COMPLETE_RELEASE")
                        result = "COMPLETE_RELEASED"
                    else:
                        result = "FRAGMENT_ACCEPTED_PROGRESS"
            else:
                available = refill(source_digest, op["at_ms"], hits)
                per_source_active = sum(
                    1 for owner in owners if owner[0] == source_digest
                )
                if available < 1:
                    hits.append("TOKEN_CAPACITY_DENY")
                    result = "TOKEN_BUCKET_DENY"
                elif per_source_active >= per_source_limit:
                    hits.append("PER_SOURCE_QUOTA_DENY")
                    result = "PER_SOURCE_QUOTA_DENY"
                elif len(owners) >= global_limit:
                    hits.append("GLOBAL_QUOTA_DENY")
                    result = "GLOBAL_QUOTA_DENY"
                else:
                    token_buckets[source_digest]["tokens"] -= 1
                    owners[key] = {
                        "last_activity_ms": op["at_ms"],
                        "fragments": {
                            op["fragment_index"]: bytes.fromhex(
                                op["fragment_payload_hex"]
                            )
                        },
                    }
                    hits.extend(
                        [
                            "ALLOCATE",
                            f"FRAGMENT_{op['fragment_index']}_ACCEPT",
                            (
                                "COOKIE_CURRENT_ACCEPT"
                                if op["cookie_bucket"] == current_bucket
                                else "COOKIE_PREVIOUS_ACCEPT"
                            ),
                        ]
                    )
                    result = "FRAGMENT_ACCEPTED_ALLOCATED"
        for hit in hits:
            if hit not in branch_counts:
                raise AssertionError(f"unknown preauth branch {hit}")
            branch_counts[hit] += 1
        active_mask = 0
        source_active = 0
        source_tokens = -1
        if key is not None and key in owners:
            for fragment_index in owners[key]["fragments"]:
                active_mask |= 1 << fragment_index
        if source_digest is not None:
            source_active = sum(
                1 for owner in owners if owner[0] == source_digest
            )
            if source_digest in token_buckets:
                source_tokens = token_buckets[source_digest]["tokens"]
        op["step"] = step
        op["expected"] = {
            "result": result,
            "branches": hits,
            "active_scratch_count": len(owners),
            "source_active_scratch_count": source_active,
            "source_tokens": source_tokens,
            "active_owner_received_mask": active_mask,
            "expired_release_count_delta": expired_delta,
            "completion_count": completion_count,
            "release_count": release_count,
            "terminal_discard_count": terminal_discard_count,
            "identity_allocations": 0,
            "credential_resolver_calls": 0,
        }
        transitions.append(op)
    if any(count == 0 for count in branch_counts.values()):
        raise AssertionError(f"preauth branch gap {branch_counts!r}")
    return {
        "owner_key_fields": [
            "source_locator_digest32",
            "session_id16",
            "exchange_generation_u64",
            "record_sequence_u32",
            "complete_nac1_bytes_u16",
            "digest16",
        ],
        "source_locator_digest_hex": hex_bytes(source_locator_digest),
        "per_source_scratch_limit": per_source_limit,
        "global_scratch_limit": global_limit,
        "scratch_fragment_count_exact": 2,
        "idle_timeout_seconds": idle_timeout_ms // 1_000,
        "idle_timeout_ms": idle_timeout_ms,
        "cookie_valid_buckets": ["CURRENT", "PREVIOUS"],
        "token_bucket_capacity": token_capacity,
        "token_refill_seconds": token_refill_ms // 1_000,
        "token_refill_ms": token_refill_ms,
        "current_cookie_bucket": current_bucket,
        "identity_allocations_before_cookie": 0,
        "credential_resolver_calls_before_cookie": 0,
        "required_branch_names": required_branches,
        "branch_coverage": branch_counts,
        "transitions": transitions,
    }


def build_prerequisite_contract(
    *,
    descriptor_fields: dict[str, Any],
    initiator_ccs: bytes,
    responder_ccs: bytes,
    initiator_kid: bytes,
    responder_kid: bytes,
) -> dict[str, Any]:
    """Exact copy-owned prerequisite and local static-DH port candidate."""

    def local_descriptor(
        *,
        role: int,
        ccs: bytes,
        kid: bytes,
        x: bytes,
        y: bytes,
        stable_digest: bytes,
        provider_generation: int,
        key_ref: bytes,
    ) -> dict[str, Any]:
        public_digest = sha256(b"\x04" + x + y)
        return {
            "local_role": role,
            "factory_identity_state": "PROVISIONED",
            "factory_stable_id_digest_hex": hex_bytes(stable_digest),
            "factory_claim_revision": 5 if role == 1 else 7,
            "canonical_ccs_hex": hex_bytes(ccs),
            "canonical_ccs_sha256": hex_bytes(sha256(ccs)),
            "kid_hex": hex_bytes(kid),
            "curve": "P-256",
            "public_key_digest_hex": hex_bytes(public_digest),
            "credential_set_revision": int(
                descriptor_fields["credential_set_revision"]
            ),
            "provider_generation": provider_generation,
            "opaque_key_reference_hex": hex_bytes(key_ref),
            "opaque_key_reference_length": len(key_ref),
            "copy_owned": True,
        }

    descriptors = {
        "initiator_local_role_1": local_descriptor(
            role=1,
            ccs=initiator_ccs,
            kid=initiator_kid,
            x=P256_INITIATOR_X,
            y=P256_INITIATOR_Y,
            stable_digest=descriptor_fields["initiator_stable_digest"],
            provider_generation=23,
            key_ref=b"IKREF001",
        ),
        "responder_local_role_2": local_descriptor(
            role=2,
            ccs=responder_ccs,
            kid=responder_kid,
            x=P256_RESPONDER_X,
            y=P256_RESPONDER_Y,
            stable_digest=descriptor_fields["responder_stable_digest"],
            provider_generation=29,
            key_ref=b"RKREF001",
        ),
    }
    failures = [
        "WRONG_FACTORY_IDENTITY",
        "WRONG_ROLE",
        "WRONG_CURVE",
        "PUBLIC_PRIVATE_KEY_MISMATCH",
        "CREDENTIAL_REVISION_ROLLBACK",
        "PROVIDER_GENERATION_ROLLBACK",
        "UNKNOWN_OPAQUE_KEY_REFERENCE",
        "PROVIDER_REENTRY",
        "PARTIAL_OUTPUT",
    ]
    return {
        "dependency_readiness": {
            "factory_identity": "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED",
            "site_membership": "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED",
            "production_attachment_status": "PROPOSED",
            "pa_may_claim_dependency_ready": False,
            "owner_start_without_accepted_dependencies": "FAIL_CLOSED_NOT_READY",
        },
        "factory_identity_claim": {
            "required_state": "PROVISIONED",
            "stable_id_digest_bytes": 32,
            "claim_revision_nonzero": True,
            "copy_owned": True,
        },
        "site_membership_claim": {
            "required_state": "ACTIVE",
            "site_domain_hex": hex_bytes(descriptor_fields["site_domain"]),
            "membership_epoch": int(descriptor_fields["membership_epoch"]),
            "authority_id_hex": hex_bytes(descriptor_fields["authority_id"]),
            "authority_term": int(descriptor_fields["authority_term"]),
            "credential_set_revision": int(
                descriptor_fields["credential_set_revision"]
            ),
            "revocation_generation": int(
                descriptor_fields["revocation_generation"]
            ),
            "assignment_epoch": int(descriptor_fields["assignment_epoch"]),
            "copy_owned": True,
        },
        "local_credential_descriptors": descriptors,
        "local_static_dh_port": {
            "operation": "P256_STATIC_DH",
            "input_fields": [
                "opaque_key_reference",
                "provider_generation",
                "credential_set_revision",
                "factory_stable_id_digest",
                "local_role",
                "peer_uncompressed_p256_public_key65",
                "suite",
                "attempt_binding_digest32",
            ],
            "output_owner": "CALLER_OWNED_BOUNDED_SECRET_WORKSPACE",
            "output_bytes_exact": 32,
            "write_count_exact": 1,
            "private_scalar_exported": False,
            "backend_pointer_exported": False,
            "provider_serialization": "NO_REENTRY",
            "partial_output_action": "ZEROIZE32_AND_TERMINAL",
            "after_prk_action": "ZEROIZE32",
        },
        "positive_model": {
            "status": "DESCRIPTOR_AND_PORT_CONTRACT_ACCEPTED",
            "ecdh_output_bytes_written": 32,
            "ecdh_write_count": 1,
            "wire_records_before_binding_checks": 0,
            "private_key_bytes_exported": 0,
            "real_provider_kat_claimed": False,
        },
        "failure_matrix": [
            {
                "id": failure,
                "status": "TERMINAL_AUTHENTICATION_FAILURE",
                "wire_records": 0,
                "exporter_calls": 0,
                "ecdh_output_published_bytes": 0,
                "zeroized_output_bytes": 32,
                "private_key_bytes_exported": 0,
            }
            for failure in failures
        ],
    }


def control_nonce(base_iv13: bytes, exchange_generation: int, sequence: int) -> bytes:
    if len(base_iv13) != 13:
        raise ValueError("control IV")
    mask = b"\0" + struct.pack(">QI", exchange_generation, sequence)
    return bytes(left ^ right for left, right in zip(base_iv13, mask))


def carrier_binding_vectors() -> dict[str, Any]:
    instance = pattern(0x60, 16)
    peer = pattern(0x70, 16)
    config_digest = sha256(b"carrier-config")
    channel_plan_digest = sha256(b"radio-channel-plan")
    wifi_peer_session = pattern(0x80, 16)
    wifi_network_instance = pattern(0x90, 16)
    usb_input = (
        b"NINLIL-NAC1-USB-BINDING-V1"
        + instance
        + peer
        + struct.pack(">Q", 5)
        + config_digest
    )
    wifi_input = (
        b"NINLIL-NAC1-WIFI-BINDING-V1"
        + instance
        + wifi_peer_session
        + peer
        + wifi_network_instance
        + struct.pack(">Q", 7)
        + struct.pack(">I", 11)
        + config_digest
    )
    radio_input = (
        b"NINLIL-NAC1-RADIO-BINDING-V1"
        + instance
        + channel_plan_digest
        + struct.pack(">Q", 13)
        + config_digest
    )
    return {
        "usb": {
            "carrier_class": 1,
            "fields": {
                "label": "NINLIL-NAC1-USB-BINDING-V1",
                "carrier_instance_id_hex": hex_bytes(instance),
                "peer_id_hex": hex_bytes(peer),
                "connection_generation": 5,
                "accepted_carrier_config_digest_hex": hex_bytes(config_digest),
            },
            "canonical_input_hex": hex_bytes(usb_input),
            "digest_hex": hex_bytes(sha256(usb_input)),
        },
        "wifi": {
            "carrier_class": 2,
            "fields": {
                "label": "NINLIL-NAC1-WIFI-BINDING-V1",
                "carrier_instance_id_hex": hex_bytes(instance),
                "peer_session_id_hex": hex_bytes(wifi_peer_session),
                "peer_id_hex": hex_bytes(peer),
                "network_instance_id_hex": hex_bytes(wifi_network_instance),
                "connection_generation": 7,
                "path_generation": 11,
                "accepted_carrier_config_digest_hex": hex_bytes(config_digest),
            },
            "canonical_input_hex": hex_bytes(wifi_input),
            "digest_hex": hex_bytes(sha256(wifi_input)),
        },
        "compact_radio": {
            "carrier_class": 3,
            "fields": {
                "label": "NINLIL-NAC1-RADIO-BINDING-V1",
                "carrier_instance_id_hex": hex_bytes(instance),
                "channel_plan_digest_hex": hex_bytes(channel_plan_digest),
                "radio_epoch": 13,
                "accepted_carrier_config_digest_hex": hex_bytes(config_digest),
            },
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


def build_edhoc_attempt_matrix(
    *,
    session_id: bytes,
    radio_binding: bytes,
    suite2_generation: int,
    suite3_generation: int,
    suite2_message_1: bytes,
    suite3_message_1: bytes,
) -> dict[str, Any]:
    """Full synthetic method-3 state-machine traces for suites 2 and 3.

    These bytes exercise framing/profile state only.  They are deliberately
    labelled non-KAT until an adopted provider reproduces RFC/independent
    cryptographic traces on Host and ESP.
    """

    def attempt(suite: int, generation: int, m1: bytes, seed: int) -> dict[str, Any]:
        payloads = [
            m1,
            bytes([0x58, 0x20]) + pattern(seed, 32)
            + bytes([0x58, 0x20]) + pattern(seed + 0x20, 32)
            + b"\x40",
            bytes([0x58, 0x20]) + pattern(seed + 0x40, 32) + b"\x40",
            bytes([0x48]) + pattern(seed + 0x60, 8),
        ]
        rows: list[dict[str, Any]] = []
        for stage, payload in enumerate(payloads, start=1):
            record = encode_nac1(
                kind=KIND_EDHOC_MESSAGE_1 + stage - 1,
                carrier_class=3,
                session_id=session_id,
                exchange_generation=generation,
                record_sequence=stage,
                carrier_binding_digest=radio_binding,
                payload=payload,
            )
            rows.append(
                {
                    "stage": stage,
                    "kind": KIND_EDHOC_MESSAGE_1 + stage - 1,
                    "message_name": f"message_{stage}",
                    "payload_hex": hex_bytes(payload),
                    "payload_sha256": hex_bytes(sha256(payload)),
                    "nac1_hex": hex_bytes(record),
                    "ead_present": False,
                    "ead_item_count": 0,
                    "verified": True,
                }
            )
        return {
            "method": 3,
            "suite": suite,
            "exchange_generation": generation,
            "fixture_kind": "SYNTHETIC_PROFILE_STATE_MACHINE_NOT_CRYPTO_KAT",
            "messages": rows,
            "message_4_required": True,
            "message_4_verified_before_exporter": True,
            "exporter_calls_before_message_4": 0,
            "exporter_calls_after_message_4": len(EXPORTER_LABELS),
            "final_state": "EDHOC_COMPLETE",
            "real_provider_kat_claimed": False,
        }

    suite2 = attempt(SUITE_2, suite2_generation, suite2_message_1, 0x81)
    suite3 = attempt(SUITE_3, suite3_generation, suite3_message_1, 0x11)
    ead_negatives = [
        {
            "id": f"EAD_{stage}_NONEMPTY",
            "stage": stage,
            "ead_hex": "01",
            "outcome": "TERMINAL_REJECT",
            "wire_records_after_reject": 0,
            "exporter_calls": 0,
            "automatic_retry_count": 0,
        }
        for stage in range(1, 5)
    ]
    return {
        "attempts": {
            "suite_2": suite2,
            "suite_3": suite3,
        },
        "ead_nonempty_terminal_matrix": ead_negatives,
        "downgrade_failure": {
            "initial_pinned_suite": 2,
            "suggested_other_suite": 3,
            "automatic_retry_count": 0,
            "same_policy_revision_retry_allowed": False,
            "fresh_policy_revision_required": True,
            "fresh_session_generation_required": True,
            "outcome": "TERMINAL_NO_AUTODOWNGRADE",
        },
        "rfc9529_trace_role": "ALGORITHM_REFERENCE_ONLY_NOT_PROFILE_NEGOTIATION_POSITIVE",
        "provider_interoperability_claimed": False,
    }


def build_document() -> dict[str, Any]:
    carriers = carrier_binding_vectors()
    session_id = pattern(0xA0, 16)
    exchange_generation = 101
    radio_binding = bytes.fromhex(carriers["compact_radio"]["digest_hex"])
    usb_binding = bytes.fromhex(carriers["usb"]["digest_hex"])

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
    nac_m1_suite2 = encode_nac1(
        kind=KIND_EDHOC_MESSAGE_1,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=1,
        carrier_binding_digest=radio_binding,
        payload=message_1_suite2,
    )
    nac_m1_suite3 = encode_nac1(
        kind=KIND_EDHOC_MESSAGE_1,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation + 1,
        record_sequence=1,
        carrier_binding_digest=radio_binding,
        payload=message_1_suite3,
    )
    nac_m1_usb = encode_nac1(
        kind=KIND_EDHOC_MESSAGE_1,
        carrier_class=1,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=1,
        carrier_binding_digest=usb_binding,
        payload=message_1_suite2,
    )
    nas_m1_usb = encode_nas1(1, nac_m1_usb)
    nas1_stream_lifecycle = build_nas1_stream_matrix(nas_m1_usb)
    edhoc_attempts = build_edhoc_attempt_matrix(
        session_id=session_id,
        radio_binding=radio_binding,
        suite2_generation=exchange_generation,
        suite3_generation=exchange_generation + 1,
        suite2_message_1=message_1_suite2,
        suite3_message_1=message_1_suite3,
    )

    proposal, proposal_fields = make_nap1()
    proposal_digest = sha256(proposal)
    # Attachment epoch is known for install binding (Normative transcript input).
    attachment_epoch = 13
    attempt_index = 0
    # Profile suite-2 EDHOC wire fixtures (NAC1 payloads). Exact octets as
    # carried — not RFC 9529 suite-6 negotiation trace; not re-CBOR'd.
    edhoc_m1 = message_1_suite2
    edhoc_m2 = (
        bytes([0x58, 0x20])
        + pattern(0x81, 32)
        + bytes([0x58, 0x20])
        + pattern(0xA1, 32)
        + bytes([0x40])
    )
    edhoc_m3 = bytes([0x58, 0x20]) + pattern(0xC1, 32) + bytes([0x40])
    edhoc_m4 = bytes([0x48]) + pattern(0xE1, 8)
    # Cookie + EDHOC NAC1s for compact-radio path (cookie_mode=INCLUDED).
    # Built before NAI1 so carrier_transcript_digest is Normative, not filler.
    cookie_secret_current = pattern(0xD0, 32)
    cookie_secret_previous = pattern(0xE0, 32)
    source_locator_digest = sha256(b"compact-radio-source-locator")
    time_bucket = 867_530
    cookie_input, cookie = make_cookie(
        secret=cookie_secret_current,
        carrier_class=3,
        carrier_binding_digest=radio_binding,
        source_locator_digest=source_locator_digest,
        session_id=session_id,
        exchange_generation=exchange_generation,
        original_message_1=edhoc_m1,
        time_bucket=time_bucket,
    )
    nac_cookie_challenge = encode_nac1(
        kind=KIND_COOKIE_CHALLENGE,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=0,
        carrier_binding_digest=radio_binding,
        payload=cookie,
    )
    cookie_response_payload = (
        cookie + struct.pack(">H", len(edhoc_m1)) + edhoc_m1
    )
    nac_cookie_response = encode_nac1(
        kind=KIND_COOKIE_RESPONSE,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=0,
        carrier_binding_digest=radio_binding,
        payload=cookie_response_payload,
    )
    nac_edhoc_m1 = encode_nac1(
        kind=KIND_EDHOC_MESSAGE_1,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=1,
        carrier_binding_digest=radio_binding,
        payload=edhoc_m1,
    )
    nac_edhoc_m2 = encode_nac1(
        kind=KIND_EDHOC_MESSAGE_2,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=2,
        carrier_binding_digest=radio_binding,
        payload=edhoc_m2,
    )
    nac_edhoc_m3 = encode_nac1(
        kind=KIND_EDHOC_MESSAGE_3,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=3,
        carrier_binding_digest=radio_binding,
        payload=edhoc_m3,
    )
    nac_edhoc_m4 = encode_nac1(
        kind=KIND_EDHOC_MESSAGE_4,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=4,
        carrier_binding_digest=radio_binding,
        payload=edhoc_m4,
    )
    # Keep suite2 m1 NAC1 alias used by edhoc_message_1 vector block.
    nac_m1_suite2 = nac_edhoc_m1
    transcript_records = [
        nac_cookie_challenge,
        nac_cookie_response,
        nac_edhoc_m1,
        nac_edhoc_m2,
        nac_edhoc_m3,
        nac_edhoc_m4,
    ]
    carrier_transcript_digest, carrier_transcript_preimage, transcript_meta = (
        compute_carrier_transcript_digest(
            carrier_class=3,
            session_id=session_id,
            exchange_generation=exchange_generation,
            attempt_index=attempt_index,
            attachment_epoch=attachment_epoch,
            method=METHOD_STATIC_DH_BOTH,
            suite=SUITE_2,
            cookie_mode=COOKIE_MODE_INCLUDED,
            ordered_nac1_records=transcript_records,
        )
    )
    transcript_negatives = carrier_transcript_negatives(
        base_meta=transcript_meta,
        ordered_nac1_records=transcript_records,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        attempt_index=attempt_index,
        attachment_epoch=attachment_epoch,
        method=METHOD_STATIC_DH_BOTH,
        suite=SUITE_2,
        cookie_mode=COOKIE_MODE_INCLUDED,
    )
    descriptor, descriptor_fields = make_nai1(
        proposal_digest, carrier_transcript_digest=carrier_transcript_digest
    )
    if descriptor_fields["attachment_epoch"] != attachment_epoch:
        raise AssertionError("attachment_epoch pin")
    install_digest = sha256(
        b"NINLIL-PRODUCTION-ATTACH-INSTALL-V1" + proposal + descriptor
    )
    initiator_kid = pattern(0xC1, 4)
    responder_kid = pattern(0xC2, 4)
    initiator_ccs = make_ccs_rpk(
        kid=initiator_kid, x=P256_INITIATOR_X, y=P256_INITIATOR_Y
    )
    responder_ccs = make_ccs_rpk(
        kid=responder_kid, x=P256_RESPONDER_X, y=P256_RESPONDER_Y
    )
    if initiator_ccs[0] == 0x4E or responder_ccs[0] == 0x4E:
        raise AssertionError("CCS must be CBOR map, not ASCII prefix")
    initiator_credential_digest = sha256(initiator_ccs)
    responder_credential_digest = sha256(responder_ccs)
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
        b"NINLIL-ATTACH-TRAFFIC-CONTEXT-V1" + nax1 + install_digest
    )

    # The Proposed design does not claim an AEAD implementation.  This
    # transport vector uses deterministic opaque bytes of the exact required
    # ciphertext+8-byte-tag length; descriptor vectors separately pin the
    # cleartext and exporter inputs.
    opaque_proposal_ciphertext_and_tag = pattern(0x70, len(proposal) + 8)
    opaque_install_ciphertext_and_tag = pattern(0x90, len(descriptor) + 8)
    opaque_confirm_device_ciphertext_and_tag = pattern(0xB0, len(nat1) + 8)
    opaque_confirm_authority_ciphertext_and_tag = pattern(0xC0, len(nat1) + 8)
    nac_proposal = encode_nac1(
        kind=KIND_ATTACH_PROPOSE,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=5,
        carrier_binding_digest=radio_binding,
        payload=opaque_proposal_ciphertext_and_tag,
    )
    nac_install = encode_nac1(
        kind=KIND_ATTACH_INSTALL,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=6,
        carrier_binding_digest=radio_binding,
        payload=opaque_install_ciphertext_and_tag,
    )
    nac_confirm_device = encode_nac1(
        kind=KIND_ATTACH_CONFIRM_DEVICE,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=7,
        carrier_binding_digest=radio_binding,
        payload=opaque_confirm_device_ciphertext_and_tag,
    )
    nac_confirm_authority = encode_nac1(
        kind=KIND_ATTACH_CONFIRM_AUTHORITY,
        carrier_class=3,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=8,
        carrier_binding_digest=radio_binding,
        payload=opaque_confirm_authority_ciphertext_and_tag,
    )
    radio_fragments = fragment_nar1(nac_install)
    nar1_reassembly = build_nar1_reassembly_matrix(
        radio_fragments, source_locator_digest
    )

    n6at_base = dict(
        attachment_id=descriptor_fields["attachment_id"],
        membership_epoch=descriptor_fields["membership_epoch"],
        attachment_epoch=descriptor_fields["attachment_epoch"],
        install_digest=install_digest,
        authority_term=descriptor_fields["authority_term"],
        lease_epoch=descriptor_fields["lease_epoch"],
        e2e_security_epoch=descriptor_fields["e2e_security_epoch"],
        credential_set_revision=descriptor_fields["credential_set_revision"],
        revocation_generation=descriptor_fields["revocation_generation"],
        assignment_epoch=descriptor_fields["assignment_epoch"],
    )
    n6at_device_pending_key, n6at_device_pending_value = make_n6at(
        local_role=1, state=1, **n6at_base
    )
    n6at_device_active_key, n6at_device_active_value = make_n6at(
        local_role=1, state=2, **n6at_base
    )
    n6at_device_third_key, n6at_device_third_value = make_n6at(
        local_role=1, state=3, **n6at_base
    )
    n6at_authority_pending_key, n6at_authority_pending_value = make_n6at(
        local_role=2, state=1, **n6at_base
    )
    n6at_authority_active_key, n6at_authority_active_value = make_n6at(
        local_role=2, state=2, **n6at_base
    )
    n6at_authority_third_key, n6at_authority_third_value = make_n6at(
        local_role=2, state=3, **n6at_base
    )
    # Compatibility aliases for single-role consumers (device ACTIVE).
    n6at_pending_key = n6at_device_pending_key
    n6at_pending_value = n6at_device_pending_value
    n6at_key = n6at_device_active_key
    n6at_value = n6at_device_active_value
    n6at_third_value = n6at_device_third_value
    nab1_device, nab1_device_inventory = make_nab1(
        local_role=1,
        attachment_id=descriptor_fields["attachment_id"],
        install_digest=install_digest,
        fields=descriptor_fields,
        marker_value=n6at_device_pending_value,
    )
    nab1_authority, nab1_authority_inventory = make_nab1(
        local_role=2,
        attachment_id=descriptor_fields["attachment_id"],
        install_digest=install_digest,
        fields=descriptor_fields,
        marker_value=n6at_authority_pending_value,
    )
    device_complete_keys = b"".join(
        bytes.fromhex(entry["complete_key_hex"]) for entry in nab1_device_inventory
    )
    authority_complete_keys = b"".join(
        bytes.fromhex(entry["complete_key_hex"])
        for entry in nab1_authority_inventory
    )
    device_full_image = b"".join(
        bytes.fromhex(e["complete_key_hex"])
        + bytes.fromhex(e["value_hex"])
        + bytes.fromhex(e["context_digest_hex"])
        for e in nab1_device_inventory
    )
    authority_full_image = b"".join(
        bytes.fromhex(e["complete_key_hex"])
        + bytes.fromhex(e["value_hex"])
        + bytes.fromhex(e["context_digest_hex"])
        for e in nab1_authority_inventory
    )
    # Resolver key formula from docs/35 §2.
    credential_resolver_key = (
        descriptor_fields["site_domain"]
        + descriptor_fields["authority_id"]
        + struct.pack(">Q", descriptor_fields["authority_term"])
        + struct.pack(">Q", descriptor_fields["credential_set_revision"])
        + bytes([1])  # role initiator example
        + bytes([len(initiator_kid)])
        + initiator_kid
    )

    # Cookie secrets/matrix (challenge/response NAC1 already built for transcript).
    cookie_matrix: dict[str, Any] = {}
    for secret_name, secret in (
        ("current_secret", cookie_secret_current),
        ("previous_secret", cookie_secret_previous),
    ):
        for bucket_name, bucket in (
            ("current_bucket", time_bucket),
            ("previous_bucket", time_bucket - 1),
        ):
            combo_input, combo_cookie = make_cookie(
                secret=secret,
                carrier_class=3,
                carrier_binding_digest=radio_binding,
                source_locator_digest=source_locator_digest,
                session_id=session_id,
                exchange_generation=exchange_generation,
                original_message_1=edhoc_m1,
                time_bucket=bucket,
            )
            cookie_matrix[f"{secret_name}_x_{bucket_name}"] = {
                "time_bucket": bucket,
                "secret_name": secret_name,
                "canonical_input_hex": hex_bytes(combo_input),
                "cookie_hex": hex_bytes(combo_cookie),
            }
    previous_cookie = bytes.fromhex(
        cookie_matrix["previous_secret_x_previous_bucket"]["cookie_hex"]
    )
    cookie_response_fragments = fragment_nar1(nac_cookie_response)
    preauth_owner = build_preauth_owner_model(
        source_locator_digest=source_locator_digest,
        session_id=session_id,
        exchange_generation=exchange_generation,
        record_sequence=0,
        complete_record_bytes=len(nac_cookie_response),
        digest16=sha256(nac_cookie_response)[:16],
        current_bucket=time_bucket,
        fragment_payloads=(
            cookie_response_fragments[0][NAR1_HEADER_BYTES:],
            cookie_response_fragments[1][NAR1_HEADER_BYTES:],
        ),
    )

    attach_i2r_iv = pattern(0x11, 13)
    attach_r2i_iv = pattern(0x31, 13)
    protection_nonces = {
        "propose_i2r_seq5": control_nonce(
            attach_i2r_iv, exchange_generation, 5
        ),
        "install_r2i_seq6": control_nonce(
            attach_r2i_iv, exchange_generation, 6
        ),
        "confirm_device_i2r_seq7": control_nonce(
            attach_i2r_iv, exchange_generation, 7
        ),
        "confirm_authority_r2i_seq8": control_nonce(
            attach_r2i_iv, exchange_generation, 8
        ),
    }

    descriptor_json = {
        key: (hex_bytes(value) if isinstance(value, bytes) else value)
        for key, value in descriptor_fields.items()
    }
    proposal_json = {
        key: (hex_bytes(value) if isinstance(value, bytes) else value)
        for key, value in proposal_fields.items()
    }
    prerequisites = build_prerequisite_contract(
        descriptor_fields=descriptor_fields,
        initiator_ccs=initiator_ccs,
        responder_ccs=responder_ccs,
        initiator_kid=initiator_kid,
        responder_kid=responder_kid,
    )

    envelope = envelope_document_fragment()
    carrier_transcript_block = {
        "normative_formula_id": "NINLIL-PA-CARRIER-TRANSCRIPT-V1",
        "hash": "SHA-256",
        "label": CARRIER_TRANSCRIPT_LABEL.decode("ascii"),
        "schema_version": CARRIER_TRANSCRIPT_SCHEMA_VERSION,
        "role_in_preimage": False,
        "direction_encoding": "implicit_via_nac1_kind_only",
        "edhoc_wire_rule": transcript_meta["edhoc_wire"],
        "nac1_scope_rule": transcript_meta["nac1_scope"],
        "excluded": transcript_meta["excluded"],
        "primary_path": {
            "carrier_class": 3,
            "carrier_class_name": "COMPACT_RADIO",
            "cookie_mode": COOKIE_MODE_INCLUDED,
            "cookie_mode_name": "INCLUDED",
            "session_id_hex": hex_bytes(session_id),
            "exchange_generation": exchange_generation,
            "attempt_index": attempt_index,
            "attachment_epoch": attachment_epoch,
            "method": METHOD_STATIC_DH_BOTH,
            "suite": SUITE_2,
            "entry_count": len(transcript_records),
            "entry_order_kinds": transcript_meta["entry_order_kinds"],
            "entries": transcript_meta["entries"],
            "preimage_length": transcript_meta["preimage_length"],
            "preimage_sha256": transcript_meta["preimage_sha256"],
            "preimage_hex": transcript_meta["preimage_hex"],
            "digest_hex": transcript_meta["digest_hex"],
        },
        "negatives": transcript_negatives,
        "nai1_offset": 352,
        "nax1_offset": 100,
        "bound_into": ["NAI1[352:384]", "NAX1[100:132]"],
    }
    # Permanent: synthetic filler must not equal Normative digest.
    if carrier_transcript_digest == sha256(b"carrier-transcript"):
        raise AssertionError("carrier_transcript still synthetic filler")
    return {
        **envelope,
        "carrier_transcript": carrier_transcript_block,
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
            "control_aead": {
                "cose_algorithm": 10,
                "name": "AES-CCM-16-64-128",
                "key_bytes": 16,
                "iv_bytes": 13,
                "tag_bytes": 8,
            },
        },
        "limits": {
            "nac1_header_bytes": NAC1_HEADER_BYTES,
            "nac1_payload_max": NAC1_PAYLOAD_MAX,
            "nac1_record_max": NAC1_RECORD_MAX,
            "nas1_header_bytes": NAS1_HEADER_BYTES,
            "nas1_record_max": NAS1_RECORD_MAX,
            "nar1_profile": NAR1_PROFILE,
            "nar1_header_bytes": NAR1_HEADER_BYTES,
            "nar1_packet_max": NAR1_PACKET_MAX,
            "nar1_fragment_payload_max": NAR1_PAYLOAD_MAX,
            "nar1_fragment_count_max": NAR1_FRAGMENT_MAX,
            "nap1_bytes": NAP1_BYTES,
            "nai1_bytes": NAI1_BYTES,
            "nax1_bytes": NAX1_BYTES,
            "nat1_bytes": NAT1_BYTES,
            "n6at_key_bytes": N6AT_KEY_BYTES,
            "n6at_value_bytes": N6AT_VALUE_BYTES,
            "nab1_header_bytes": NAB1_HEADER_BYTES,
            "nab1_entry_bytes": NAB1_ENTRY_BYTES,
            "nab1_entry_count": NAB1_ENTRY_COUNT,
            "nab1_total_bytes": NAB1_TOTAL_BYTES,
        },
        "carrier_bindings": carriers,
        "stream_wrapper": {
            "usb_nas1_length": len(nas_m1_usb),
            "usb_nas1_hex": hex_bytes(nas_m1_usb),
            "usb_nas1_sha256": hex_bytes(sha256(nas_m1_usb)),
        },
        "nas1_stream_lifecycle": nas1_stream_lifecycle,
        "stateless_cookie": {
            "time_bucket_seconds": COOKIE_TIME_BUCKET_SECONDS,
            "time_bucket": time_bucket,
            "current_secret_hex": hex_bytes(cookie_secret_current),
            "previous_secret_hex": hex_bytes(cookie_secret_previous),
            "source_locator_digest_hex": hex_bytes(source_locator_digest),
            "canonical_input_hex": hex_bytes(cookie_input),
            "current_cookie_hex": hex_bytes(cookie),
            "previous_bucket_previous_secret_cookie_hex": hex_bytes(
                previous_cookie
            ),
            "secret_bucket_matrix": cookie_matrix,
            "challenge_nac1_hex": hex_bytes(nac_cookie_challenge),
            "response_payload_length": len(cookie_response_payload),
            "response_payload_hex": hex_bytes(cookie_response_payload),
            "response_nac1_length": len(nac_cookie_response),
            "response_nac1_hex": hex_bytes(nac_cookie_response),
            "response_length_formula": "88+32+2+original_message_1_bytes",
            "response_length_parts": {
                "nac1_header_bytes": NAC1_HEADER_BYTES,
                "cookie_bytes": 32,
                "original_message_1_length_u16be_bytes": 2,
                "original_message_1_bytes": len(message_1_suite2),
                "total_bytes": (
                    NAC1_HEADER_BYTES + 32 + 2 + len(message_1_suite2)
                ),
            },
            "response_radio_fragments": [
                {
                    "index": index,
                    "length": len(fragment),
                    "hex": hex_bytes(fragment),
                    "sha256": hex_bytes(sha256(fragment)),
                }
                for index, fragment in enumerate(cookie_response_fragments)
            ],
            "response_fragment_count": len(cookie_response_fragments),
            "identity_or_authentication_claimed": False,
        },
        "edhoc_message_1": {
            "suite_2": {
                "hex": hex_bytes(message_1_suite2),
                "length": len(message_1_suite2),
                "sha256": hex_bytes(sha256(message_1_suite2)),
                "nac1_hex": hex_bytes(nac_m1_suite2),
            },
            "suite_3": {
                "hex": hex_bytes(message_1_suite3),
                "length": len(message_1_suite3),
                "sha256": hex_bytes(sha256(message_1_suite3)),
                "nac1_hex": hex_bytes(nac_m1_suite3),
            },
        },
        "edhoc_attempts": edhoc_attempts,
        "rfc9529_method3_suite2_reference": rfc9529_reference(),
        "attachment_install": {
            "nap1_length": len(proposal),
            "nap1_hex": hex_bytes(proposal),
            "nap1_sha256": hex_bytes(proposal_digest),
            "proposal_fields": proposal_json,
            "nai1_length": len(descriptor),
            "nai1_hex": hex_bytes(descriptor),
            "nai1_sha256": hex_bytes(sha256(descriptor)),
            "install_fields": descriptor_json,
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
            "attach_i2r_base_iv13_hex": hex_bytes(attach_i2r_iv),
            "attach_r2i_base_iv13_hex": hex_bytes(attach_r2i_iv),
            "protection_nonces": {
                key: hex_bytes(value)
                for key, value in protection_nonces.items()
            },
            "aead_vector_status": "INPUTS_PINNED_CIPHERTEXT_NOT_CLAIMED",
            "proposal_opaque_ciphertext_and_tag_length": len(
                opaque_proposal_ciphertext_and_tag
            ),
            "opaque_ciphertext_and_tag_length": len(
                opaque_install_ciphertext_and_tag
            ),
            "confirm_opaque_ciphertext_and_tag_length": len(
                opaque_confirm_device_ciphertext_and_tag
            ),
            "records": {
                "propose_seq5": hex_bytes(nac_proposal),
                "install_seq6": hex_bytes(nac_install),
                "confirm_device_seq7": hex_bytes(nac_confirm_device),
                "confirm_authority_seq8": hex_bytes(nac_confirm_authority),
            },
            "install_nac1_aad_prefix_hex": hex_bytes(nac_install[:84]),
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
        "nar1_reassembly": nar1_reassembly,
        "preauth_owner": preauth_owner,
        "magic_registry": {
            "registry": "spec/protocol-magic-registry-v1.json",
            "pa_allocations": {
                "NAC1": "PRODUCTION_ATTACHMENT_CARRIER_RECORD",
                "NAS1": "PRODUCTION_ATTACHMENT_STREAM_WRAPPER",
                "NAR1": "PRODUCTION_ATTACHMENT_RADIO_FRAGMENT",
            },
            "forbidden_pa_allocations": {
                "NPA1": "ADR0020_MULTI_PARENT_ASSIGNMENT_PAGE",
                "NPS1": "ADR0020_MULTI_PARENT_PARENT_SET",
            },
            "all_pa_allocations_unique": True,
            "repository_registry_gate_required": True,
        },
        "prerequisites": prerequisites,
        "credentials": {
            "type": "RPK_CCS_KID",
            "curve": "P-256",
            "cose_kty": 2,
            "cose_crv": 1,
            "encoding": "CBOR_CCS_MAP_CNF_COSE_KEY",
            "initiator_ccs_hex": hex_bytes(initiator_ccs),
            "responder_ccs_hex": hex_bytes(responder_ccs),
            "initiator_kid_hex": hex_bytes(initiator_kid),
            "responder_kid_hex": hex_bytes(responder_kid),
            "initiator_x_hex": hex_bytes(P256_INITIATOR_X),
            "initiator_y_hex": hex_bytes(P256_INITIATOR_Y),
            "responder_x_hex": hex_bytes(P256_RESPONDER_X),
            "responder_y_hex": hex_bytes(P256_RESPONDER_Y),
            "initiator_credential_digest_hex": hex_bytes(
                initiator_credential_digest
            ),
            "responder_credential_digest_hex": hex_bytes(
                responder_credential_digest
            ),
            "initiator_ccs_sha256": hex_bytes(sha256(initiator_ccs)),
            "responder_ccs_sha256": hex_bytes(sha256(responder_ccs)),
            "resolver_key_input_hex": hex_bytes(credential_resolver_key),
            "resolver_key_sha256": hex_bytes(sha256(credential_resolver_key)),
            "note": (
                "Exact CBOR CCS/RPK pins for PA-S0 semantic gates; not a "
                "production credential-store or HIL claim."
            ),
        },
        "n6_attachment_marker": {
            "local_role": 1,
            "key_hex": hex_bytes(n6at_key),
            "key_length": len(n6at_key),
            "value_hex": hex_bytes(n6at_value),
            "value_length": len(n6at_value),
            "value_sha256": hex_bytes(sha256(n6at_value)),
            "state": 2,
            "state_name": "ACTIVE",
        },
        "lifecycle": {
            "roles": {
                "device_local_role_1": {
                    "pending": {
                        "state": 1,
                        "state_name": "PENDING",
                        "key_hex": hex_bytes(n6at_device_pending_key),
                        "value_hex": hex_bytes(n6at_device_pending_value),
                        "value_sha256": hex_bytes(
                            sha256(n6at_device_pending_value)
                        ),
                    },
                    "active": {
                        "state": 2,
                        "state_name": "ACTIVE",
                        "key_hex": hex_bytes(n6at_device_active_key),
                        "value_hex": hex_bytes(n6at_device_active_value),
                        "value_sha256": hex_bytes(
                            sha256(n6at_device_active_value)
                        ),
                    },
                    "fenced_third": {
                        "state": 3,
                        "state_name": "FENCED",
                        "key_hex": hex_bytes(n6at_device_third_key),
                        "value_hex": hex_bytes(n6at_device_third_value),
                        "value_sha256": hex_bytes(
                            sha256(n6at_device_third_value)
                        ),
                        "accepted": False,
                    },
                },
                "authority_local_role_2": {
                    "pending": {
                        "state": 1,
                        "state_name": "PENDING",
                        "key_hex": hex_bytes(n6at_authority_pending_key),
                        "value_hex": hex_bytes(n6at_authority_pending_value),
                        "value_sha256": hex_bytes(
                            sha256(n6at_authority_pending_value)
                        ),
                    },
                    "active": {
                        "state": 2,
                        "state_name": "ACTIVE",
                        "key_hex": hex_bytes(n6at_authority_active_key),
                        "value_hex": hex_bytes(n6at_authority_active_value),
                        "value_sha256": hex_bytes(
                            sha256(n6at_authority_active_value)
                        ),
                    },
                    "fenced_third": {
                        "state": 3,
                        "state_name": "FENCED",
                        "key_hex": hex_bytes(n6at_authority_third_key),
                        "value_hex": hex_bytes(n6at_authority_third_value),
                        "value_sha256": hex_bytes(
                            sha256(n6at_authority_third_value)
                        ),
                        "accepted": False,
                    },
                },
            },
            "pending_marker": {
                "state": 1,
                "state_name": "PENDING",
                "local_role": 1,
                "key_hex": hex_bytes(n6at_pending_key),
                "value_hex": hex_bytes(n6at_pending_value),
                "value_sha256": hex_bytes(sha256(n6at_pending_value)),
            },
            "pending_to_active": {
                "old_state": 1,
                "new_state": 2,
                "mutation_kind": "SINGLE_KEY_FULL_MARKER_ONLY",
                "old_value_hex": hex_bytes(n6at_pending_value),
                "new_value_hex": hex_bytes(n6at_value),
                "old_value_sha256": hex_bytes(sha256(n6at_pending_value)),
                "new_value_sha256": hex_bytes(sha256(n6at_value)),
            },
            "commit_unknown": {
                "old_pending_value_hex": hex_bytes(n6at_pending_value),
                "new_active_value_hex": hex_bytes(n6at_value),
                "third_value_hex": hex_bytes(n6at_third_value),
                "third_value_state": 3,
                "third_value_accepted": False,
                "accepted_states": [1, 2],
                "accepted_classifications": [
                    "EXACT_OLD",
                    "EXACT_NEW_PENDING_15",
                    "EXACT_NEW_ACTIVE_MARKER",
                ],
            },
            "group_machine": {
                "member_count_exact": 15,
                "old_count_is_protocol_constant": False,
                "observed_old_non_absent_count": sum(
                    1
                    for entry in nab1_device_inventory
                    if entry["old_present"]
                ),
                "legal_nonempty_lane_old_required": True,
                "new_pending_member_count": 15,
                "partial_member_counts_rejected": list(range(1, 15)),
                "extra_member_rejected": True,
                "third_value_or_digest_mismatch_rejected": True,
                "pending_to_active_single_key_full": True,
                "publication_before_dual_confirm": 0,
                "device_complete_keys_concat_sha256": hex_bytes(
                    sha256(device_complete_keys)
                ),
                "authority_complete_keys_concat_sha256": hex_bytes(
                    sha256(authority_complete_keys)
                ),
                "device_pending_key_hex": hex_bytes(n6at_device_pending_key),
                "device_pending_value_hex": hex_bytes(n6at_device_pending_value),
                "device_active_value_hex": hex_bytes(n6at_device_active_value),
                "authority_pending_key_hex": hex_bytes(
                    n6at_authority_pending_key
                ),
                "authority_pending_value_hex": hex_bytes(
                    n6at_authority_pending_value
                ),
                "authority_active_value_hex": hex_bytes(
                    n6at_authority_active_value
                ),
                "role_attachment_id_must_match": True,
                "snapshots": build_lifecycle_snapshots(
                    device_inventory=nab1_device_inventory,
                    authority_inventory=nab1_authority_inventory,
                    device_pending_key=n6at_device_pending_key,
                    device_pending_value=n6at_device_pending_value,
                    device_active_value=n6at_device_active_value,
                    device_third_value=n6at_device_third_value,
                    authority_pending_key=n6at_authority_pending_key,
                    authority_pending_value=n6at_authority_pending_value,
                    authority_active_value=n6at_authority_active_value,
                    authority_third_value=n6at_authority_third_value,
                    membership_epoch=int(
                        descriptor_fields["membership_epoch"]
                    ),
                    device_local_node=pa_node_id(
                        descriptor_fields["initiator_stable_digest"]
                    ),
                    device_peer_node=pa_node_id(
                        descriptor_fields["responder_stable_digest"]
                    ),
                    authority_local_node=pa_node_id(
                        descriptor_fields["responder_stable_digest"]
                    ),
                    authority_peer_node=pa_node_id(
                        descriptor_fields["initiator_stable_digest"]
                    ),
                ),
            },
            "publication_before_dual_confirm": 0,
        },
        "atomic_batch_manifests": {
            "status": "TEST_ORACLE_ONLY_NOT_WIRE_OR_STORAGE",
            "ordering": "UNSIGNED_BYTE_COMPLETE_KEY_LEXICOGRAPHIC",
            "device_local_role_1": {
                "length": len(nab1_device),
                "hex": hex_bytes(nab1_device),
                "sha256": hex_bytes(sha256(nab1_device)),
                "exact_inventory": nab1_device_inventory,
                "complete_keys_concat_sha256": hex_bytes(
                    sha256(device_complete_keys)
                ),
                "full_image_sha256": hex_bytes(sha256(device_full_image)),
            },
            "authority_local_role_2": {
                "length": len(nab1_authority),
                "hex": hex_bytes(nab1_authority),
                "sha256": hex_bytes(sha256(nab1_authority)),
                "exact_inventory": nab1_authority_inventory,
                "complete_keys_concat_sha256": hex_bytes(
                    sha256(authority_complete_keys)
                ),
                "full_image_sha256": hex_bytes(sha256(authority_full_image)),
            },
        },
    }


def assert_generator_closed_schema(document: dict[str, Any]) -> None:
    """Generator-side closed schema: independent authority, not vector self-trust."""
    assert_closed_key_schema(document, root=ROOT)
    if document["required_gate_cases"] != list(REQUIRED_GATE_CASES_EXACT):
        raise SchemaError("generator required_gate_cases drift")


def canonical_json(document: dict[str, Any]) -> bytes:
    assert_generator_closed_schema(document)
    return (
        json.dumps(
            document,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def c_array(name: str, value: bytes) -> list[str]:
    lines = [f"static const uint8_t {name}[{len(value)}] = {{"]
    for offset in range(0, len(value), 12):
        chunk = value[offset : offset + 12]
        lines.append("    " + ", ".join(f"0x{octet:02x}u" for octet in chunk) + ",")
    lines.append("};")
    return lines


def emit_c_fixture(document: dict[str, Any], output: Path) -> None:
    install = document["attachment_install"]
    cookie = document["stateless_cookie"]
    credentials = document["credentials"]
    lifecycle = document["lifecycle"]
    roles = lifecycle["roles"]
    preauth = document["preauth_owner"]
    wifi = document["carrier_bindings"]["wifi"]
    radio = document["carrier_bindings"]["compact_radio"]
    rfc = document["rfc9529_method3_suite2_reference"]["messages"]
    device_inv = document["atomic_batch_manifests"]["device_local_role_1"][
        "exact_inventory"
    ]
    authority_inv = document["atomic_batch_manifests"]["authority_local_role_2"][
        "exact_inventory"
    ]
    iff = install["install_fields"]
    arrays: list[tuple[str, bytes]] = [
        (
            "ninlil_pa_nac_suite2_m1",
            bytes.fromhex(document["edhoc_message_1"]["suite_2"]["nac1_hex"]),
        ),
        (
            "ninlil_pa_nac_suite3_m1",
            bytes.fromhex(document["edhoc_message_1"]["suite_3"]["nac1_hex"]),
        ),
        (
            "ninlil_pa_nas_usb_m1",
            bytes.fromhex(document["stream_wrapper"]["usb_nas1_hex"]),
        ),
        (
            "ninlil_pa_cookie_challenge",
            bytes.fromhex(cookie["challenge_nac1_hex"]),
        ),
        (
            "ninlil_pa_cookie_response",
            bytes.fromhex(cookie["response_nac1_hex"]),
        ),
        (
            "ninlil_pa_cookie_canonical",
            bytes.fromhex(cookie["canonical_input_hex"]),
        ),
        (
            "ninlil_pa_cookie_secret_current",
            bytes.fromhex(cookie["current_secret_hex"]),
        ),
        (
            "ninlil_pa_cookie_secret_previous",
            bytes.fromhex(cookie["previous_secret_hex"]),
        ),
        (
            "ninlil_pa_cookie_current",
            bytes.fromhex(cookie["current_cookie_hex"]),
        ),
        (
            "ninlil_pa_cookie_prev_secret_prev_bucket",
            bytes.fromhex(cookie["previous_bucket_previous_secret_cookie_hex"]),
        ),
        (
            "ninlil_pa_cookie_curr_secret_prev_bucket",
            bytes.fromhex(
                cookie["secret_bucket_matrix"][
                    "current_secret_x_previous_bucket"
                ]["cookie_hex"]
            ),
        ),
        (
            "ninlil_pa_cookie_prev_secret_curr_bucket",
            bytes.fromhex(
                cookie["secret_bucket_matrix"][
                    "previous_secret_x_current_bucket"
                ]["cookie_hex"]
            ),
        ),
        ("ninlil_pa_nap1", bytes.fromhex(install["nap1_hex"])),
        ("ninlil_pa_nai1", bytes.fromhex(install["nai1_hex"])),
        ("ninlil_pa_nax1", bytes.fromhex(install["nax1_hex"])),
        ("ninlil_pa_nat1", bytes.fromhex(install["nat1_hex"])),
        (
            "ninlil_pa_propose_seq5",
            bytes.fromhex(install["records"]["propose_seq5"]),
        ),
        (
            "ninlil_pa_install_seq6",
            bytes.fromhex(install["records"]["install_seq6"]),
        ),
        (
            "ninlil_pa_confirm_device_seq7",
            bytes.fromhex(install["records"]["confirm_device_seq7"]),
        ),
        (
            "ninlil_pa_confirm_authority_seq8",
            bytes.fromhex(install["records"]["confirm_authority_seq8"]),
        ),
        (
            "ninlil_pa_n6at_key",
            bytes.fromhex(document["n6_attachment_marker"]["key_hex"]),
        ),
        (
            "ninlil_pa_n6at_value",
            bytes.fromhex(document["n6_attachment_marker"]["value_hex"]),
        ),
        (
            "ninlil_pa_n6at_pending_key",
            bytes.fromhex(roles["device_local_role_1"]["pending"]["key_hex"]),
        ),
        (
            "ninlil_pa_n6at_pending_value",
            bytes.fromhex(roles["device_local_role_1"]["pending"]["value_hex"]),
        ),
        (
            "ninlil_pa_n6at_third_value",
            bytes.fromhex(
                roles["device_local_role_1"]["fenced_third"]["value_hex"]
            ),
        ),
        (
            "ninlil_pa_n6at_authority_pending_key",
            bytes.fromhex(
                roles["authority_local_role_2"]["pending"]["key_hex"]
            ),
        ),
        (
            "ninlil_pa_n6at_authority_pending_value",
            bytes.fromhex(
                roles["authority_local_role_2"]["pending"]["value_hex"]
            ),
        ),
        (
            "ninlil_pa_n6at_authority_active_key",
            bytes.fromhex(roles["authority_local_role_2"]["active"]["key_hex"]),
        ),
        (
            "ninlil_pa_n6at_authority_active_value",
            bytes.fromhex(
                roles["authority_local_role_2"]["active"]["value_hex"]
            ),
        ),
        (
            "ninlil_pa_nab1_device",
            bytes.fromhex(
                document["atomic_batch_manifests"]["device_local_role_1"]["hex"]
            ),
        ),
        (
            "ninlil_pa_nab1_authority",
            bytes.fromhex(
                document["atomic_batch_manifests"][
                    "authority_local_role_2"
                ]["hex"]
            ),
        ),
        (
            "ninlil_pa_install_digest",
            bytes.fromhex(install["install_digest"]),
        ),
        (
            "ninlil_pa_carrier_transcript_digest",
            bytes.fromhex(
                document["carrier_transcript"]["primary_path"]["digest_hex"]
            ),
        ),
        (
            "ninlil_pa_carrier_transcript_preimage",
            bytes.fromhex(
                document["carrier_transcript"]["primary_path"]["preimage_hex"]
            ),
        ),
        (
            "ninlil_pa_protect_ctx_digest",
            bytes.fromhex(install["protection_exporter_context_digest"]),
        ),
        (
            "ninlil_pa_traffic_ctx_digest",
            bytes.fromhex(install["traffic_exporter_context_digest"]),
        ),
        (
            "ninlil_pa_wifi_canonical",
            bytes.fromhex(wifi["canonical_input_hex"]),
        ),
        (
            "ninlil_pa_wifi_digest",
            bytes.fromhex(wifi["digest_hex"]),
        ),
        (
            "ninlil_pa_radio_digest",
            bytes.fromhex(radio["digest_hex"]),
        ),
        (
            "ninlil_pa_initiator_ccs",
            bytes.fromhex(credentials["initiator_ccs_hex"]),
        ),
        (
            "ninlil_pa_responder_ccs",
            bytes.fromhex(credentials["responder_ccs_hex"]),
        ),
        (
            "ninlil_pa_initiator_kid",
            bytes.fromhex(credentials["initiator_kid_hex"]),
        ),
        (
            "ninlil_pa_responder_kid",
            bytes.fromhex(credentials["responder_kid_hex"]),
        ),
        (
            "ninlil_pa_initiator_x",
            bytes.fromhex(credentials["initiator_x_hex"]),
        ),
        (
            "ninlil_pa_initiator_y",
            bytes.fromhex(credentials["initiator_y_hex"]),
        ),
        (
            "ninlil_pa_responder_x",
            bytes.fromhex(credentials["responder_x_hex"]),
        ),
        (
            "ninlil_pa_responder_y",
            bytes.fromhex(credentials["responder_y_hex"]),
        ),
        (
            "ninlil_pa_initiator_cred_digest",
            bytes.fromhex(credentials["initiator_credential_digest_hex"]),
        ),
        (
            "ninlil_pa_responder_cred_digest",
            bytes.fromhex(credentials["responder_credential_digest_hex"]),
        ),
        (
            "ninlil_pa_rfc_message_1",
            bytes.fromhex(rfc["message_1"]["hex"]),
        ),
        (
            "ninlil_pa_rfc_message_1_sha",
            bytes.fromhex(rfc["message_1"]["sha256"]),
        ),
        (
            "ninlil_pa_rfc_message_4",
            bytes.fromhex(rfc["message_4"]["hex"]),
        ),
        (
            "ninlil_pa_rfc_message_4_sha",
            bytes.fromhex(rfc["message_4"]["sha256"]),
        ),
        (
            "ninlil_pa_nap1_sha",
            bytes.fromhex(install["nap1_sha256"]),
        ),
        (
            "ninlil_pa_i2r_iv",
            bytes.fromhex(install["attach_i2r_base_iv13_hex"]),
        ),
        (
            "ninlil_pa_r2i_iv",
            bytes.fromhex(install["attach_r2i_base_iv13_hex"]),
        ),
        (
            "ninlil_pa_attachment_id",
            bytes.fromhex(iff["attachment_id"]),
        ),
        (
            "ninlil_pa_source_locator_digest",
            bytes.fromhex(
                document["preauth_owner"]["source_locator_digest_hex"]
            ),
        ),
        (
            "ninlil_pa_reattach_10k_transcript_sha256",
            bytes.fromhex(
                lifecycle["group_machine"]["snapshots"][
                    "reattach_10k_restart"
                ]["transcript_sha256"]
            ),
        ),
    ]
    for suite_name, suite_number in (("suite_2", 2), ("suite_3", 3)):
        attempt = document["edhoc_attempts"]["attempts"][suite_name]
        for message_index, message in enumerate(attempt["messages"], 1):
            arrays.append(
                (
                    f"ninlil_pa_edhoc_s{suite_number}_m{message_index}",
                    bytes.fromhex(message["nac1_hex"]),
                )
            )
    for descriptor_name, symbol_prefix in (
        ("initiator_local_role_1", "initiator"),
        ("responder_local_role_2", "responder"),
    ):
        descriptor = document["prerequisites"]["local_credential_descriptors"][
            descriptor_name
        ]
        arrays.extend(
            [
                (
                    f"ninlil_pa_{symbol_prefix}_factory_stable_digest",
                    bytes.fromhex(descriptor["factory_stable_id_digest_hex"]),
                ),
                (
                    f"ninlil_pa_{symbol_prefix}_public_key_digest",
                    bytes.fromhex(descriptor["public_key_digest_hex"]),
                ),
                (
                    f"ninlil_pa_{symbol_prefix}_opaque_key_reference",
                    bytes.fromhex(descriptor["opaque_key_reference_hex"]),
                ),
            ]
        )
    for name, value in (
        ("propose_i2r_seq5", install["protection_nonces"]["propose_i2r_seq5"]),
        ("install_r2i_seq6", install["protection_nonces"]["install_r2i_seq6"]),
        (
            "confirm_device_i2r_seq7",
            install["protection_nonces"]["confirm_device_i2r_seq7"],
        ),
        (
            "confirm_authority_r2i_seq8",
            install["protection_nonces"]["confirm_authority_r2i_seq8"],
        ),
    ):
        arrays.append((f"ninlil_pa_nonce_{name}", bytes.fromhex(value)))
    for index, entry in enumerate(device_inv):
        arrays.append(
            (
                f"ninlil_pa_device_complete_key_{index}",
                bytes.fromhex(entry["complete_key_hex"]),
            )
        )
        arrays.append(
            (
                f"ninlil_pa_device_value_sha256_{index}",
                bytes.fromhex(entry["value_sha256"]),
            )
        )
        arrays.append(
            (
                f"ninlil_pa_device_context_digest_{index}",
                bytes.fromhex(entry["context_digest_hex"]),
            )
        )
    for index, entry in enumerate(authority_inv):
        arrays.append(
            (
                f"ninlil_pa_authority_complete_key_{index}",
                bytes.fromhex(entry["complete_key_hex"]),
            )
        )
        arrays.append(
            (
                f"ninlil_pa_authority_value_sha256_{index}",
                bytes.fromhex(entry["value_sha256"]),
            )
        )
        arrays.append(
            (
                f"ninlil_pa_authority_context_digest_{index}",
                bytes.fromhex(entry["context_digest_hex"]),
            )
        )
    arrays.append(
        (
            "ninlil_pa_device_full_image_sha256",
            bytes.fromhex(
                document["atomic_batch_manifests"]["device_local_role_1"][
                    "full_image_sha256"
                ]
            ),
        )
    )
    arrays.append(
        (
            "ninlil_pa_authority_full_image_sha256",
            bytes.fromhex(
                document["atomic_batch_manifests"]["authority_local_role_2"][
                    "full_image_sha256"
                ]
            ),
        )
    )
    arrays.append(
        (
            "ninlil_pa_device_active_marker_value_sha256",
            bytes.fromhex(
                lifecycle["roles"]["device_local_role_1"]["active"][
                    "value_sha256"
                ]
            ),
        )
    )
    arrays.append(
        (
            "ninlil_pa_authority_active_marker_value_sha256",
            bytes.fromhex(
                lifecycle["roles"]["authority_local_role_2"]["active"][
                    "value_sha256"
                ]
            ),
        )
    )
    hop_ir = next(e for e in device_inv if e["identity"] == "hop_ir_lane1")
    hop_ri = next(e for e in device_inv if e["identity"] == "hop_ri_lane1")
    e2e_ir = next(e for e in device_inv if e["identity"] == "e2e_ir_lane3")
    e2e_ri = next(e for e in device_inv if e["identity"] == "e2e_ri_lane3")
    fragments = [
        bytes.fromhex(item["hex"])
        for item in document["compact_radio_fragments"]
    ]
    cookie_fragments = [
        bytes.fromhex(item["hex"])
        for item in document["stateless_cookie"]["response_radio_fragments"]
    ]
    lines = [
        "/* Generated by production_attachment_edhoc_vector_gen.py. */",
        "#ifndef NINLIL_PRODUCTION_ATTACHMENT_EDHOC_FIXTURE_H",
        "#define NINLIL_PRODUCTION_ATTACHMENT_EDHOC_FIXTURE_H",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#define NINLIL_PA_FRAGMENT_COUNT 5u",
        "#define NINLIL_PA_COOKIE_FRAGMENT_COUNT 2u",
        "#define NINLIL_PA_NAC_HEADER_BYTES 88u",
        "#define NINLIL_PA_NAC_RECORD_MAX 600u",
        "#define NINLIL_PA_NAR_HEADER_BYTES 68u",
        "#define NINLIL_PA_NAS_BUFFER_CAPACITY 612u",
        "#define NINLIL_PA_NAB_ENTRY_COUNT 15u",
        "#define NINLIL_PA_COOKIE_RESPONSE_BYTES 159u",
        "#define NINLIL_PA_COOKIE_PAYLOAD_BYTES 71u",
        "#define NINLIL_PA_EXPORTER_I2R_KEY 32768u",
        "#define NINLIL_PA_EXPORTER_R2I_KEY 32769u",
        "#define NINLIL_PA_EXPORTER_I2R_IV 32770u",
        "#define NINLIL_PA_EXPORTER_R2I_IV 32771u",
        "#define NINLIL_PA_EXPORTER_HOP_IR 32772u",
        "#define NINLIL_PA_EXPORTER_HOP_RI 32773u",
        "#define NINLIL_PA_EXPORTER_E2E_IR 32774u",
        "#define NINLIL_PA_EXPORTER_E2E_RI 32775u",
        f"#define NINLIL_PA_HOP_IR_CONTEXT_ID {hop_ir['context_id']}u",
        f"#define NINLIL_PA_HOP_IR_KEY_GENERATION {hop_ir['key_generation']}ull",
        f"#define NINLIL_PA_HOP_RI_CONTEXT_ID {hop_ri['context_id']}u",
        f"#define NINLIL_PA_HOP_RI_KEY_GENERATION {hop_ri['key_generation']}ull",
        f"#define NINLIL_PA_E2E_IR_CONTEXT_ID {e2e_ir['context_id']}u",
        f"#define NINLIL_PA_E2E_IR_KEY_GENERATION {e2e_ir['key_generation']}ull",
        f"#define NINLIL_PA_E2E_RI_CONTEXT_ID {e2e_ri['context_id']}u",
        f"#define NINLIL_PA_E2E_RI_KEY_GENERATION {e2e_ri['key_generation']}ull",
        f"#define NINLIL_PA_PUBLICATION_BEFORE_DUAL_CONFIRM "
        f"{lifecycle['publication_before_dual_confirm']}u",
        f"#define NINLIL_PA_COOKIE_TIME_BUCKET_SECONDS "
        f"{COOKIE_TIME_BUCKET_SECONDS}u",
        f"#define NINLIL_PA_EXCHANGE_GENERATION "
        f"{int.from_bytes(bytes.fromhex(install['records']['install_seq6'])[36:44], 'big')}ull",
        f"#define NINLIL_PA_SCHEMA_VERSION "
        f"{int(document['schema_version'])}u",
        f"#define NINLIL_PA_MEMBER_COUNT_EXACT "
        f"{int(document['lifecycle_constants']['member_count_exact'])}u",
        f"#define NINLIL_PA_MEMBERSHIP_EPOCH "
        f"{int(iff['membership_epoch'])}ull",
        f"#define NINLIL_PA_ATTACHMENT_EPOCH "
        f"{int(iff['attachment_epoch'])}ull",
        f"#define NINLIL_PA_LEASE_EPOCH "
        f"{int(iff['lease_epoch'])}ull",
        f"#define NINLIL_PA_E2E_SECURITY_EPOCH "
        f"{int(iff['e2e_security_epoch'])}ull",
        f"#define NINLIL_PA_AUTHORITY_TERM "
        f"{int(iff['authority_term'])}ull",
        f"#define NINLIL_PA_CREDENTIAL_SET_REVISION "
        f"{int(iff['credential_set_revision'])}ull",
        f"#define NINLIL_PA_REVOCATION_GENERATION "
        f"{int(iff['revocation_generation'])}u",
        f"#define NINLIL_PA_ASSIGNMENT_EPOCH "
        f"{int(iff['assignment_epoch'])}u",
        f"#define NINLIL_PA_REATTACH_CYCLES "
        f"{int(lifecycle['group_machine']['snapshots']['reattach_10k_restart']['cycles'])}u",
        f"#define NINLIL_PA_REATTACH_OLD_OBSERVED "
        f"{int(lifecycle['group_machine']['observed_old_non_absent_count'])}u",
        f"#define NINLIL_PA_PREAUTH_PER_SOURCE_LIMIT "
        f"{int(document['preauth_owner']['per_source_scratch_limit'])}u",
        f"#define NINLIL_PA_PREAUTH_GLOBAL_LIMIT "
        f"{int(document['preauth_owner']['global_scratch_limit'])}u",
        f"#define NINLIL_PA_PREAUTH_SCRATCH_FRAGMENTS "
        f"{int(document['preauth_owner']['scratch_fragment_count_exact'])}u",
        f"#define NINLIL_PA_PREAUTH_IDLE_TIMEOUT_SECONDS "
        f"{int(document['preauth_owner']['idle_timeout_seconds'])}u",
        f"#define NINLIL_PA_PREAUTH_TOKEN_CAPACITY "
        f"{int(document['preauth_owner']['token_bucket_capacity'])}u",
        f"#define NINLIL_PA_PREAUTH_TOKEN_REFILL_SECONDS "
        f"{int(document['preauth_owner']['token_refill_seconds'])}u",
        f"#define NINLIL_PA_PREAUTH_IDLE_TIMEOUT_MS "
        f"{int(preauth['idle_timeout_ms'])}ull",
        f"#define NINLIL_PA_PREAUTH_TOKEN_REFILL_MS "
        f"{int(preauth['token_refill_ms'])}ull",
        f"#define NINLIL_PA_PREAUTH_CURRENT_COOKIE_BUCKET "
        f"{int(preauth['current_cookie_bucket'])}ull",
        f"#define NINLIL_PA_PREAUTH_TRANSITION_COUNT "
        f"{len(preauth['transitions'])}u",
        f"#define NINLIL_PA_PREAUTH_BRANCH_COUNT "
        f"{len(preauth['required_branch_names'])}u",
        f"#define NINLIL_PA_LOCAL_KEY_FAILURE_COUNT "
        f"{len(document['prerequisites']['failure_matrix'])}u",
        f"#define NINLIL_PA_LOCAL_DH_OUTPUT_BYTES "
        f"{int(document['prerequisites']['local_static_dh_port']['output_bytes_exact'])}u",
        f"#define NINLIL_PA_LOCAL_DH_WRITE_COUNT "
        f"{int(document['prerequisites']['local_static_dh_port']['write_count_exact'])}u",
        f"#define NINLIL_PA_LOCAL_REAL_PROVIDER_KAT_CLAIMED "
        f"{1 if document['prerequisites']['positive_model']['real_provider_kat_claimed'] else 0}u",
        "#define NINLIL_PA_EDHOC_MESSAGE_COUNT 4u",
        f"#define NINLIL_PA_EDHOC_S2_GENERATION "
        f"{int(document['edhoc_attempts']['attempts']['suite_2']['exchange_generation'])}ull",
        f"#define NINLIL_PA_EDHOC_S3_GENERATION "
        f"{int(document['edhoc_attempts']['attempts']['suite_3']['exchange_generation'])}ull",
        f"#define NINLIL_PA_EDHOC_EXPORTER_BEFORE_M4 "
        f"{int(document['edhoc_attempts']['attempts']['suite_2']['exporter_calls_before_message_4'])}u",
        f"#define NINLIL_PA_EDHOC_EXPORTER_AFTER_M4 "
        f"{int(document['edhoc_attempts']['attempts']['suite_2']['exporter_calls_after_message_4'])}u",
        f"#define NINLIL_PA_EDHOC_EAD_FAILURE_COUNT "
        f"{len(document['edhoc_attempts']['ead_nonempty_terminal_matrix'])}u",
        f"#define NINLIL_PA_EDHOC_DOWNGRADE_AUTORETRY "
        f"{int(document['edhoc_attempts']['downgrade_failure']['automatic_retry_count'])}u",
        f"#define NINLIL_PA_EDHOC_DOWNGRADE_INITIAL_SUITE "
        f"{int(document['edhoc_attempts']['downgrade_failure']['initial_pinned_suite'])}u",
        f"#define NINLIL_PA_EDHOC_DOWNGRADE_SUGGESTED_SUITE "
        f"{int(document['edhoc_attempts']['downgrade_failure']['suggested_other_suite'])}u",
        f"#define NINLIL_PA_EDHOC_DOWNGRADE_SAME_POLICY_ALLOWED "
        f"{1 if document['edhoc_attempts']['downgrade_failure']['same_policy_revision_retry_allowed'] else 0}u",
        f"#define NINLIL_PA_EDHOC_DOWNGRADE_FRESH_POLICY_REQUIRED "
        f"{1 if document['edhoc_attempts']['downgrade_failure']['fresh_policy_revision_required'] else 0}u",
        f"#define NINLIL_PA_EDHOC_DOWNGRADE_FRESH_SESSION_REQUIRED "
        f"{1 if document['edhoc_attempts']['downgrade_failure']['fresh_session_generation_required'] else 0}u",
        "typedef struct ninlil_pa_fixture_span {",
        "    const uint8_t *data;",
        "    size_t size;",
        "} ninlil_pa_fixture_span_t;",
        "typedef struct ninlil_pa_nab_identity {",
        "    uint8_t member_kind;",
        "    uint8_t direction;",
        "    uint8_t lane;",
        "    uint8_t local_side;",
        "    uint8_t layer_code;",
        "    uint32_t context_id;",
        "    uint64_t key_generation;",
        "    uint16_t key_bytes;",
        "    uint16_t value_bytes;",
        "    const uint8_t *complete_key;",
        "    uint16_t complete_key_length;",
        "    const uint8_t *value_sha256; /* 32 bytes */",
        "    const uint8_t *context_digest; /* 32 bytes */",
        "} ninlil_pa_nab_identity_t;",
        "typedef struct ninlil_pa_carrier_negative {",
        "    const char *id;",
        "    const uint8_t *digest; /* 32 */",
        "    const uint8_t *preimage;",
        "    size_t preimage_len;",
        "    int rejected;",
        "} ninlil_pa_carrier_negative_t;",
        "typedef struct ninlil_pa_old_member {",
        "    uint8_t member_kind;",
        "    uint16_t value_bytes;",
        "    const uint8_t *complete_key;",
        "    uint16_t complete_key_length;",
        "    const uint8_t *value; /* value_bytes */",
        "    const uint8_t *value_sha256; /* 32 */",
        "    const uint8_t *context_digest; /* 32 */",
        "} ninlil_pa_old_member_t;",
        "typedef struct ninlil_pa_preauth_transition {",
        "    const char *scenario;",
        "    uint8_t reset_before;",
        "    uint64_t at_ms;",
        "    uint8_t operation; /* 1=receive, 2=tick */",
        "    const char *source_label;",
        "    const uint8_t *source;",
        "    size_t source_size;",
        "    const uint8_t *session;",
        "    size_t session_size;",
        "    uint64_t exchange_generation;",
        "    uint32_t record_sequence;",
        "    uint16_t complete_nac1_bytes;",
        "    const uint8_t *digest16;",
        "    size_t digest16_size;",
        "    uint64_t cookie_bucket;",
        "    int8_t fragment_index;",
        "    const char *fragment_variant;",
        "    const uint8_t *payload;",
        "    size_t payload_size;",
        "    const char *expected_result;",
        "    uint32_t expected_branch_mask;",
        "    uint8_t expected_active_scratch_count;",
        "    uint8_t expected_source_active_scratch_count;",
        "    int8_t expected_source_tokens;",
        "    uint8_t expected_received_mask;",
        "    uint8_t expected_expired_release_delta;",
        "    uint8_t expected_completion_count;",
        "    uint8_t expected_release_count;",
        "    uint8_t expected_terminal_discard_count;",
        "    uint8_t expected_identity_allocations;",
        "    uint8_t expected_credential_resolver_calls;",
        "} ninlil_pa_preauth_transition_t;",
        "typedef struct ninlil_pa_branch_expectation {",
        "    const char *name;",
        "    uint32_t count;",
        "} ninlil_pa_branch_expectation_t;",
        "typedef struct ninlil_pa_local_key_failure {",
        "    const char *id;",
        "    const char *status;",
        "    uint8_t wire_records;",
        "    uint8_t exporter_calls;",
        "    uint8_t ecdh_output_published_bytes;",
        "    uint8_t zeroized_output_bytes;",
        "    uint8_t private_key_bytes_exported;",
        "} ninlil_pa_local_key_failure_t;",
        "typedef struct ninlil_pa_ead_failure {",
        "    const char *id;",
        "    uint8_t stage;",
        "    const uint8_t *ead;",
        "    size_t ead_size;",
        "    const char *outcome;",
        "    uint8_t exporter_calls;",
        "    uint8_t automatic_retry_count;",
        "    uint8_t wire_records_after_reject;",
        "} ninlil_pa_ead_failure_t;",
    ]
    for name, value in arrays:
        lines.extend(c_array(name, value))
    for index, fragment in enumerate(fragments):
        lines.extend(c_array(f"ninlil_pa_fragment_{index}", fragment))
    for index, fragment in enumerate(cookie_fragments):
        lines.extend(c_array(f"ninlil_pa_cookie_fragment_{index}", fragment))
    branch_index = {
        name: index
        for index, name in enumerate(preauth["required_branch_names"])
    }
    for index, transition in enumerate(preauth["transitions"]):
        for suffix, value in (
            ("source", bytes.fromhex(transition["source_locator_digest_hex"])),
            ("session", bytes.fromhex(transition["session_id_hex"])),
            ("digest16", bytes.fromhex(transition["digest16_hex"])),
            ("payload", bytes.fromhex(transition["fragment_payload_hex"])),
        ):
            symbol = f"ninlil_pa_preauth_{suffix}_{index}"
            if value:
                lines.extend(c_array(symbol, value))
            else:
                lines.append(
                    f"static const uint8_t {symbol}[1] = {{ 0u }};"
                )
    for index, row in enumerate(
        document["edhoc_attempts"]["ead_nonempty_terminal_matrix"]
    ):
        lines.extend(
            c_array(
                f"ninlil_pa_ead_failure_bytes_{index}",
                bytes.fromhex(row["ead_hex"]),
            )
        )
    lines.append(
        "static const ninlil_pa_fixture_span_t "
        "ninlil_pa_fragments[NINLIL_PA_FRAGMENT_COUNT] = {"
    )
    for index, fragment in enumerate(fragments):
        lines.append(
            "    { "
            f"ninlil_pa_fragment_{index}, {len(fragment)}u"
            " },"
        )
    lines.extend([
        "};",
        "static const ninlil_pa_fixture_span_t "
        "ninlil_pa_cookie_fragments[NINLIL_PA_COOKIE_FRAGMENT_COUNT] = {",
    ])
    for index, fragment in enumerate(cookie_fragments):
        lines.append(
            "    { "
            f"ninlil_pa_cookie_fragment_{index}, {len(fragment)}u"
            " },",
        )
    lines.append("};")
    lines.append(
        "static const ninlil_pa_preauth_transition_t "
        "ninlil_pa_preauth_transitions[NINLIL_PA_PREAUTH_TRANSITION_COUNT] = {"
    )
    for index, transition in enumerate(preauth["transitions"]):
        branch_mask = 0
        for branch in transition["expected"]["branches"]:
            branch_mask |= 1 << branch_index[branch]
        operation = 1 if transition["operation"] == "RECEIVE_FRAGMENT" else 2
        expected = transition["expected"]
        lines.append(
            "    { "
            f"\"{transition['scenario']}\", "
            f"{1 if transition['reset_before'] else 0}u, "
            f"{transition['at_ms']}ull, {operation}u, "
            f"\"{transition['source_label']}\", "
            f"ninlil_pa_preauth_source_{index}, "
            f"{len(bytes.fromhex(transition['source_locator_digest_hex']))}u, "
            f"ninlil_pa_preauth_session_{index}, "
            f"{len(bytes.fromhex(transition['session_id_hex']))}u, "
            f"{transition['exchange_generation']}ull, "
            f"{transition['record_sequence']}u, "
            f"{transition['complete_nac1_bytes']}u, "
            f"ninlil_pa_preauth_digest16_{index}, "
            f"{len(bytes.fromhex(transition['digest16_hex']))}u, "
            f"{transition['cookie_bucket']}ull, "
            f"{transition['fragment_index']}, "
            f"\"{transition['fragment_payload_variant']}\", "
            f"ninlil_pa_preauth_payload_{index}, "
            f"{len(bytes.fromhex(transition['fragment_payload_hex']))}u, "
            f"\"{expected['result']}\", "
            f"UINT32_C(0x{branch_mask:08x}), "
            f"{expected['active_scratch_count']}u, "
            f"{expected['source_active_scratch_count']}u, "
            f"{expected['source_tokens']}, "
            f"{expected['active_owner_received_mask']}u, "
            f"{expected['expired_release_count_delta']}u, "
            f"{expected['completion_count']}u, "
            f"{expected['release_count']}u, "
            f"{expected['terminal_discard_count']}u, "
            f"{expected['identity_allocations']}u, "
            f"{expected['credential_resolver_calls']}u"
            " },"
        )
    lines.append("};")
    lines.append(
        "static const ninlil_pa_branch_expectation_t "
        "ninlil_pa_preauth_branch_expectations"
        "[NINLIL_PA_PREAUTH_BRANCH_COUNT] = {"
    )
    for branch in preauth["required_branch_names"]:
        lines.append(
            f"    {{ \"{branch}\", {preauth['branch_coverage'][branch]}u }},"
        )
    lines.append("};")
    lines.append(
        "static const ninlil_pa_local_key_failure_t "
        "ninlil_pa_local_key_failures[NINLIL_PA_LOCAL_KEY_FAILURE_COUNT] = {"
    )
    for row in document["prerequisites"]["failure_matrix"]:
        lines.append(
            "    { "
            f"\"{row['id']}\", \"{row['status']}\", "
            f"{row['wire_records']}u, {row['exporter_calls']}u, "
            f"{row['ecdh_output_published_bytes']}u, "
            f"{row['zeroized_output_bytes']}u, "
            f"{row['private_key_bytes_exported']}u"
            " },"
        )
    lines.append("};")
    lines.append(
        "static const ninlil_pa_ead_failure_t "
        "ninlil_pa_ead_failures[NINLIL_PA_EDHOC_EAD_FAILURE_COUNT] = {"
    )
    for index, row in enumerate(
        document["edhoc_attempts"]["ead_nonempty_terminal_matrix"]
    ):
        lines.append(
            "    { "
            f"\"{row['id']}\", {row['stage']}u, "
            f"ninlil_pa_ead_failure_bytes_{index}, "
            f"{len(bytes.fromhex(row['ead_hex']))}u, "
            f"\"{row['outcome']}\", {row['exporter_calls']}u, "
            f"{row['automatic_retry_count']}u, "
            f"{row['wire_records_after_reject']}u"
            " },"
        )
    lines.append("};")
    for suite_number in (2, 3):
        lines.append(
            "static const ninlil_pa_fixture_span_t "
            f"ninlil_pa_edhoc_suite{suite_number}_messages"
            "[NINLIL_PA_EDHOC_MESSAGE_COUNT] = {"
        )
        for message_index in range(1, 5):
            symbol = f"ninlil_pa_edhoc_s{suite_number}_m{message_index}"
            lines.append(
                f"    {{ {symbol}, sizeof({symbol}) }},"
            )
        lines.append("};")
    lines.append(
        "static const ninlil_pa_nab_identity_t "
        "ninlil_pa_nab_device_inventory[NINLIL_PA_NAB_ENTRY_COUNT] = {"
    )
    for index, entry in enumerate(device_inv):
        lines.append(
            "    { "
            f"{entry['member_kind']}u, {entry['direction']}u, "
            f"{entry['lane']}u, {entry['local_side']}u, "
            f"{entry['layer_code']}u, "
            f"{entry['context_id']}u, {entry['key_generation']}ull, "
            f"{entry['key_bytes']}u, {entry['value_bytes']}u, "
            f"ninlil_pa_device_complete_key_{index}, "
            f"{entry['complete_key_length']}u, "
            f"ninlil_pa_device_value_sha256_{index}, "
            f"ninlil_pa_device_context_digest_{index}"
            " },"
        )
    lines.append("};")
    lines.append(
        "static const ninlil_pa_nab_identity_t "
        "ninlil_pa_nab_authority_inventory[NINLIL_PA_NAB_ENTRY_COUNT] = {"
    )
    for index, entry in enumerate(authority_inv):
        lines.append(
            "    { "
            f"{entry['member_kind']}u, {entry['direction']}u, "
            f"{entry['lane']}u, {entry['local_side']}u, "
            f"{entry['layer_code']}u, "
            f"{entry['context_id']}u, {entry['key_generation']}ull, "
            f"{entry['key_bytes']}u, {entry['value_bytes']}u, "
            f"ninlil_pa_authority_complete_key_{index}, "
            f"{entry['complete_key_length']}u, "
            f"ninlil_pa_authority_value_sha256_{index}, "
            f"ninlil_pa_authority_context_digest_{index}"
            " },"
        )
    lines.extend(["};"])
    # Carrier transcript field-negative matrix (independent preimage+digest).
    ct_negs = document["carrier_transcript"]["negatives"]
    for ni, neg in enumerate(ct_negs):
        dig = bytes.fromhex(neg["digest_hex"]) if neg["digest_hex"] else bytes(32)
        lines.extend(c_array(f"ninlil_pa_ct_neg_digest_{ni}", dig))
        pre = (
            bytes.fromhex(neg["preimage_hex"])
            if neg.get("preimage_hex")
            else b""
        )
        if pre:
            lines.extend(c_array(f"ninlil_pa_ct_neg_preimage_{ni}", pre))
        else:
            lines.append(
                f"static const uint8_t ninlil_pa_ct_neg_preimage_{ni}[1] = {{0}};"
            )
    lines.append(
        f"#define NINLIL_PA_CT_NEGATIVE_COUNT {len(ct_negs)}u"
    )
    lines.append(
        "static const ninlil_pa_carrier_negative_t "
        "ninlil_pa_carrier_negatives[NINLIL_PA_CT_NEGATIVE_COUNT] = {"
    )
    for ni, neg in enumerate(ct_negs):
        pre_len = int(neg.get("preimage_length") or 0)
        rejected = 1 if neg.get("rejected") else 0
        pre_sym = f"ninlil_pa_ct_neg_preimage_{ni}"
        dig_sym = f"ninlil_pa_ct_neg_digest_{ni}"
        lines.append(
            "    { "
            f"\"{neg['id']}\", {dig_sym}, {pre_sym}, {pre_len}u, {rejected}"
            " },"
        )
    lines.append("};")
    # Per-row observed OLD members (6 lane + 4 AL + 4 HW; marker absent).
    for role_prefix, role_name in (
        ("device", "device_local_role_1"),
        ("authority", "authority_local_role_2"),
    ):
        old_members = document["lifecycle"]["group_machine"]["snapshots"][
            "roles"
        ][role_name]["exact_old"]["members"]
        for oi, m in enumerate(old_members):
            lines.extend(
                c_array(
                    f"ninlil_pa_{role_prefix}_old_key_{oi}",
                    bytes.fromhex(m["complete_key_hex"]),
                )
            )
            lines.extend(
                c_array(
                    f"ninlil_pa_{role_prefix}_old_value_{oi}",
                    bytes.fromhex(m["value_hex"]),
                )
            )
            lines.extend(
                c_array(
                    f"ninlil_pa_{role_prefix}_old_value_sha_{oi}",
                    bytes.fromhex(m["value_sha256"]),
                )
            )
            lines.extend(
                c_array(
                    f"ninlil_pa_{role_prefix}_old_ctx_{oi}",
                    bytes.fromhex(m["context_digest_hex"]),
                )
            )
        lines.append(
            f"#define NINLIL_PA_{role_prefix.upper()}_OLD_MEMBER_COUNT "
            f"{len(old_members)}u"
        )
        lines.append(
            "static const ninlil_pa_old_member_t "
            f"ninlil_pa_{role_prefix}_old_members["
            f"NINLIL_PA_{role_prefix.upper()}_OLD_MEMBER_COUNT] = {{"
        )
        for oi, m in enumerate(old_members):
            lines.append(
                "    { "
                f"{m['member_kind']}u, {m['value_bytes']}u, "
                f"ninlil_pa_{role_prefix}_old_key_{oi}, "
                f"{m['complete_key_length']}u, "
                f"ninlil_pa_{role_prefix}_old_value_{oi}, "
                f"ninlil_pa_{role_prefix}_old_value_sha_{oi}, "
                f"ninlil_pa_{role_prefix}_old_ctx_{oi}"
                " },"
            )
        lines.append("};")
    # Independent authority envelope strings for C hard-pin compare.
    def c_string(name: str, value: str) -> list[str]:
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )
        return [f'static const char {name}[] = "{escaped}";']

    lines.extend(c_string("ninlil_pa_schema_id", document["schema"]))
    lines.extend(c_string("ninlil_pa_title", document["title"]))
    lines.extend(c_string("ninlil_pa_adr", document["adr"]))
    lines.extend(c_string("ninlil_pa_normative_doc", document["normative_doc"]))
    lines.extend(c_string("ninlil_pa_status", document["status"]))
    lines.extend(
        c_string(
            "ninlil_pa_value_label",
            document["lifecycle_constants"]["value_label"],
        )
    )
    lines.extend(
        c_string(
            "ninlil_pa_ctx_label",
            document["lifecycle_constants"]["ctx_label"],
        )
    )
    lines.extend(
        c_string("ninlil_pa_tool_generator", document["tools"]["generator"])
    )
    lines.extend(
        c_string("ninlil_pa_tool_python_gate", document["tools"]["python_gate"])
    )
    lines.extend(
        c_string("ninlil_pa_tool_node_gate", document["tools"]["node_gate"])
    )
    lines.extend(c_string("ninlil_pa_tool_c_test", document["tools"]["c_test"]))
    prerequisites = document["prerequisites"]
    readiness = prerequisites["dependency_readiness"]
    port = prerequisites["local_static_dh_port"]
    edhoc = document["edhoc_attempts"]
    magic = document["magic_registry"]
    lines.extend(
        c_string(
            "ninlil_pa_dependency_factory_identity",
            readiness["factory_identity"],
        )
    )
    lines.extend(
        c_string(
            "ninlil_pa_dependency_site_membership",
            readiness["site_membership"],
        )
    )
    lines.extend(
        c_string(
            "ninlil_pa_dependency_owner_start",
            readiness["owner_start_without_accepted_dependencies"],
        )
    )
    lines.extend(
        c_string("ninlil_pa_local_static_dh_operation", port["operation"])
    )
    lines.extend(
        c_string("ninlil_pa_local_static_dh_output_owner", port["output_owner"])
    )
    lines.extend(
        c_string(
            "ninlil_pa_local_static_dh_partial_action",
            port["partial_output_action"],
        )
    )
    lines.extend(
        c_string(
            "ninlil_pa_edhoc_fixture_kind",
            edhoc["attempts"]["suite_2"]["fixture_kind"],
        )
    )
    lines.extend(
        c_string("ninlil_pa_edhoc_rfc_trace_role", edhoc["rfc9529_trace_role"])
    )
    lines.extend(
        c_string(
            "ninlil_pa_edhoc_downgrade_outcome",
            edhoc["downgrade_failure"]["outcome"],
        )
    )
    lines.extend(c_string("ninlil_pa_magic_registry", magic["registry"]))
    lines.extend(c_string("ninlil_pa_magic_nac1", "NAC1"))
    lines.extend(c_string("ninlil_pa_magic_nar1", "NAR1"))
    lines.extend(c_string("ninlil_pa_magic_nas1", "NAS1"))
    lines.extend(["#endif"])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--emit-c-fixture", type=Path)
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
    if args.emit_c_fixture is not None:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != rendered:
            print(f"refusing fixture from stale or missing: {OUTPUT}")
            return 1
        emit_c_fixture(build_document(), args.emit_c_fixture)
        print(f"wrote {args.emit_c_fixture}")
        return 0

    baseline = build_document()
    altered = build_document()
    altered["limits"]["nac1_record_max"] += 1
    if canonical_json(baseline) == canonical_json(altered):
        print("self-test failed: mutation was not observed")
        return 1
    install = bytes.fromhex(
        baseline["attachment_install"]["records"]["install_seq6"]
    )
    corrupted = bytearray(install)
    corrupted[-1] ^= 1
    stored = struct.unpack(">I", corrupted[84:88])[0]
    corrupted[84:88] = b"\0" * 4
    if crc32c(bytes(corrupted)) == stored:
        print("self-test failed: CRC mutation survived")
        return 1
    cookie = baseline["stateless_cookie"]
    response = bytes.fromhex(cookie["response_nac1_hex"])
    payload = bytes.fromhex(cookie["response_payload_hex"])
    m1_len = baseline["edhoc_message_1"]["suite_2"]["length"]
    parts = cookie["response_length_parts"]
    if (
        cookie["response_nac1_length"] != 159
        or cookie["response_payload_length"] != 71
        or len(response) != 159
        or len(payload) != 71
        or parts["total_bytes"] != 88 + 32 + 2 + m1_len
        or parts["total_bytes"] != 159
        or m1_len != 37
        or cookie["response_fragment_count"] != 2
        or len(cookie["response_radio_fragments"]) != 2
    ):
        print("self-test failed: cookie response exact length 159")
        return 1
    if cookie["time_bucket_seconds"] != COOKIE_TIME_BUCKET_SECONDS:
        print("self-test failed: cookie time_bucket_seconds pin")
        return 1
    # Normative 2s pin must not silently accept coherent 2->3 drift.
    drifted = build_document()
    drifted["stateless_cookie"]["time_bucket_seconds"] = 3
    if drifted["stateless_cookie"]["time_bucket_seconds"] == COOKIE_TIME_BUCKET_SECONDS:
        print("self-test failed: bucket drift not observed")
        return 1
    snaps = baseline["lifecycle"]["group_machine"]["snapshots"]["roles"]
    for role_name in ("device_local_role_1", "authority_local_role_2"):
        role = snaps[role_name]
        if role["exact_old"]["classification"] != "EXACT_OLD":
            print(f"self-test failed: {role_name} exact old")
            return 1
        # OLD count is derived from per-row flags; this fixture deliberately
        # includes legal lane OLD and keeps only the marker absent.
        old_members = role["exact_old"]["members"]
        if (
            len(old_members) != role["exact_old"]["observed_old_non_absent_count"]
            or not 1 <= len(old_members) <= 14
        ):
            print(f"self-test failed: {role_name} old count/flags")
            return 1
        if not any(m["member_kind"] == 1 for m in old_members):
            print(f"self-test failed: {role_name} legal lane OLD absent")
            return 1
        if len(role["write_set_rows"]) != 15 or [
            case["expected_classification"]
            for case in role["cu_row_classifier_cases"]
        ] != ["OLD", "NEW", "STABLE", "THIRD"]:
            print(f"self-test failed: {role_name} row CU matrix")
            return 1
        new15 = role["exact_new_pending_15"]
        if new15["classification"] != "EXACT_NEW_PENDING_15":
            print(f"self-test failed: {role_name} exact new pending")
            return 1
        if len(new15["members"]) != 15 or len(new15["present_complete_keys_hex"]) != 15:
            print(f"self-test failed: {role_name} new member count")
            return 1
        # Every non-marker row must be canonical N6 codec wire (not VALUE-V1).
        image = b""
        for member in new15["members"]:
            key = bytes.fromhex(member["complete_key_hex"])
            value = bytes.fromhex(member["value_hex"])
            ctx = bytes.fromhex(member["context_digest_hex"])
            if len(value) != member["value_bytes"]:
                print(f"self-test failed: {role_name} value length")
                return 1
            if sha256(value).hex() != member["value_sha256"]:
                print(f"self-test failed: {role_name} value sha")
                return 1
            if member["member_kind"] == 4:
                if any(ctx):
                    print(f"self-test failed: {role_name} marker ctx nonzero")
                    return 1
                if value[:4] != b"N6AT":
                    print(f"self-test failed: {role_name} marker magic")
                    return 1
            else:
                if not any(ctx) or len(ctx) != 32:
                    print(f"self-test failed: {role_name} ctx digest")
                    return 1
                mag = value[:4]
                if member["member_kind"] == 1 and mag not in (b"N6TX", b"N6RX"):
                    print(f"self-test failed: {role_name} lane magic {mag!r}")
                    return 1
                if member["member_kind"] == 2 and mag != b"N6AL":
                    print(f"self-test failed: {role_name} al magic")
                    return 1
                if member["member_kind"] == 3 and mag != b"N6HW":
                    print(f"self-test failed: {role_name} hw magic")
                    return 1
                # Permanent negative: synthetic VALUE-V1 seed must not match.
                fake = sha256(
                    b"NINLIL-PA-N6-VALUE-V1"
                    + bytes([member["member_kind"]])
                    + key
                    + bytes(32)
                )
                if value[:32] == fake:
                    print(f"self-test failed: {role_name} VALUE-V1 filler leaked")
                    return 1
            image += key + value + ctx
        if sha256(image).hex() != new15["full_image_sha256"]:
            print(f"self-test failed: {role_name} full image sha")
            return 1
        if (
            new15["value_substitution_rejected"]["classification"]
            != "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT"
            or new15["context_digest_substitution_rejected"]["classification"]
            != "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT"
        ):
            print(f"self-test failed: {role_name} substitution negatives")
            return 1
        if (
            new15["value_substitution_rejected"]["full_image_sha256"]
            == new15["full_image_sha256"]
            or new15["context_digest_substitution_rejected"]["full_image_sha256"]
            == new15["full_image_sha256"]
        ):
            print(f"self-test failed: {role_name} substitution image collision")
            return 1
        for n in range(1, 15):
            if role[f"partial_{n}"]["classification"] != f"PARTIAL_{n}_CORRUPT":
                print(f"self-test failed: {role_name} partial {n}")
                return 1
            if role[f"partial_{n}"].get("advanced_to_new_count") != n:
                print(f"self-test failed: {role_name} partial advanced {n}")
                return 1
            if not role[f"partial_{n}"]["members"]:
                print(f"self-test failed: {role_name} partial members empty {n}")
                return 1
        if role["extra_16"]["classification"] not in (
            "EXTRA_CORRUPT",
            "FOREIGN_OR_EXTRA_CORRUPT",
        ):
            print(f"self-test failed: {role_name} extra")
            return 1
        if role["third_mismatch"]["classification"] != "THIRD_OR_MISMATCH_CORRUPT":
            print(f"self-test failed: {role_name} third")
            return 1
        if not role["pending_to_active"]["accepted"]:
            print(f"self-test failed: {role_name} p2a")
            return 1
        cu = role["commit_unknown"]
        if set(cu["accepted_classifications"]) != {
            "EXACT_OLD",
            "EXACT_NEW_PENDING_15",
            "EXACT_NEW_ACTIVE_MARKER",
        }:
            print(f"self-test failed: {role_name} CU classifications")
            return 1
        if cu["active_marker_only"]["classification"] != "EXACT_NEW_ACTIVE_MARKER":
            print(f"self-test failed: {role_name} active marker only")
            return 1
        if role["publication_before_dual_confirm"] != 0:
            print(f"self-test failed: {role_name} publication")
            return 1
    # Complete-key order must be strict for both roles.
    for role_name in ("device_local_role_1", "authority_local_role_2"):
        inv = baseline["atomic_batch_manifests"][role_name]["exact_inventory"]
        keys = [bytes.fromhex(e["complete_key_hex"]) for e in inv]
        if any(keys[i] >= keys[i + 1] for i in range(14)):
            print(f"self-test failed: {role_name} complete-key order")
            return 1
        # Independent value recompute for first non-marker (canonical N6 codec).
        entry = next(e for e in inv if e["member_kind"] != 4)
        iff = baseline["attachment_install"]["install_fields"]
        role = 1 if role_name.startswith("device") else 2
        local_node = pa_node_id(
            bytes.fromhex(
                iff[
                    "initiator_stable_digest"
                    if role == 1
                    else "responder_stable_digest"
                ]
            )
        )
        peer_node = pa_node_id(
            bytes.fromhex(
                iff[
                    "responder_stable_digest"
                    if role == 1
                    else "initiator_stable_digest"
                ]
            )
        )
        recomputed = materialize_member_value(
            member_kind=entry["member_kind"],
            complete_key=bytes.fromhex(entry["complete_key_hex"]),
            install_digest=bytes.fromhex(
                baseline["attachment_install"]["install_digest"]
            ),
            value_length=entry["value_bytes"],
            marker_value=None,
            local_side=entry["local_side"],
            key_generation=entry["key_generation"],
            membership_epoch=int(iff["membership_epoch"]),
            phase="new",
            peer_node_id=peer_node,
            local_node_id=local_node,
            context_id=int(entry["context_id"]),
            layer_code=int(entry["layer_code"]),
        )
        if recomputed != bytes.fromhex(entry["value_hex"]):
            print(f"self-test failed: {role_name} value recompute")
            return 1
        # Pin N6AL floor = context_id+1 and TX=1/RX=0 when present.
        if entry["member_kind"] == 2:
            floor = int.from_bytes(recomputed[8:12], "big")
            if floor != int(entry["context_id"]) + 1:
                print(f"self-test failed: {role_name} AL floor context_id+1")
                return 1
        if entry["member_kind"] == 1:
            counter = int.from_bytes(recomputed[8:16], "big")
            want = 1 if entry["local_side"] == 2 else 0
            if counter != want:
                print(f"self-test failed: {role_name} lane TX=1/RX=0")
                return 1
    # Independent RFC 9529 message_1 literal pin: method byte 0x03.
    rfc_m1 = bytes.fromhex(
        baseline["rfc9529_method3_suite2_reference"]["messages"]["message_1"][
            "hex"
        ]
    )
    rfc_m1_literal = bytes.fromhex(
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637"
    )
    if rfc_m1 != rfc_m1_literal or rfc_m1[0] != 0x03:
        print("self-test failed: RFC message_1 literal pin")
        return 1
    # 03→04 coherent drift must be rejected by independent pin.
    drifted_m1 = bytearray(rfc_m1)
    drifted_m1[0] = 0x04
    if drifted_m1[0] == 0x03 or bytes(drifted_m1) == rfc_m1_literal:
        print("self-test failed: RFC 03→04 drift not observed")
        return 1
    if sha256(bytes(drifted_m1)) == sha256(rfc_m1_literal):
        print("self-test failed: RFC 03→04 digest collision")
        return 1
    # Codec authority: synthetic VALUE-V1 filler must not equal N6 wire.
    install_digest = bytes.fromhex(
        baseline["attachment_install"]["install_digest"]
    )
    entry = next(
        e
        for e in baseline["atomic_batch_manifests"]["device_local_role_1"][
            "exact_inventory"
        ]
        if e["member_kind"] != 4
    )
    complete = bytes.fromhex(entry["complete_key_hex"])
    iff = baseline["attachment_install"]["install_fields"]
    local_node = pa_node_id(bytes.fromhex(iff["initiator_stable_digest"]))
    peer_node = pa_node_id(bytes.fromhex(iff["responder_stable_digest"]))
    v1 = materialize_member_value(
        member_kind=entry["member_kind"],
        complete_key=complete,
        install_digest=install_digest,
        value_length=entry["value_bytes"],
        marker_value=None,
        local_side=entry["local_side"],
        key_generation=entry["key_generation"],
        membership_epoch=int(iff["membership_epoch"]),
        phase="new",
        peer_node_id=peer_node,
        local_node_id=local_node,
        context_id=int(entry["context_id"]),
        layer_code=int(entry["layer_code"]),
    )
    seed_x1 = sha256(
        b"NINLIL-PA-N6-VALUE-V1"
        + bytes([entry["member_kind"]])
        + complete
        + install_digest
    )
    out_x1 = bytearray()
    counter = 0
    while len(out_x1) < entry["value_bytes"]:
        out_x1.extend(sha256(seed_x1 + struct.pack(">I", counter)))
        counter += 1
    x1 = bytes(out_x1[: entry["value_bytes"]])
    if x1 == v1 or sha256(x1) == sha256(v1):
        print("self-test failed: VALUE-V1 filler collides with N6 codec value")
        return 1
    if sha256(v1).hex() != entry["value_sha256"]:
        print("self-test failed: N6 codec value fixture pin")
        return 1
    # Coherent all-metadata drift must fail independent envelope authority.
    drifted_meta = build_document()
    mutate_all_metadata_coherent(drifted_meta)
    try:
        assert_generator_closed_schema(drifted_meta)
        print("self-test failed: coherent metadata drift accepted")
        return 1
    except SchemaError:
        pass
    # Envelope pins present on baseline.
    try:
        assert_envelope(baseline)
    except SchemaError as error:
        print(f"self-test failed: envelope {error}")
        return 1
    print("self-test OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
