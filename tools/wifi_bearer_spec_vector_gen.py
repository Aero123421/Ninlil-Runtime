#!/usr/bin/env python3
"""Independent ADR-0018 Wi-Fi real-path authority candidate vector generator.

Specification oracle only. Uses the Python standard library exclusively.
Does not import Ninlil C production code, TLS backends, or other gates.
Does not claim SPEC_ACCEPTED, implementation, HIL, or RELEASE_SUPPORTED.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "spec/vectors/wifi-bearer-spec-v1.json"

SCHEMA = "ninlil.wifi.bearer.spec.v1"
STATUS = "PROPOSED_CANDIDATE_NOT_SPEC_ACCEPTED"

NWB1_MAGIC = b"NWB1"
NWB1_VERSION = 1
NWB1_HEADER = 40
NWB1_PAYLOAD_MIN = 587
NWB1_PAYLOAD_MAX = 1925
NWB1_TOTAL_MIN = 627  # 40 + 587
NWB1_TOTAL_MAX = 1965  # 40 + 1925
NWB1_CRC_OFFSET = 36

NFL1_MAGIC = b"NFL1"
NFL1_VERSION = 1
NFL1_HEADER = 584
NFL1_CRC_OFFSET = 12

# Independent association authority KAT pin (not learned from vectors).
# Inputs match generator baseline profile_id/binding/bssid/channel/auth/revision.
ASSOC_AUTHORITY_TAG = b"NINLIL-WIFI-ASSOC-AUTHORITY-V1"
NWD1_COMPLETE_TAG = b"NINLIL-WIFI-NWD1-COMPLETE-V1"
NWD1_AUTH_TAG = b"NINLIL-WIFI-NWD1-AUTH-V1"
NETWORK_PROFILE_TAG = b"NINLIL-WIFI-NETWORK-PROFILE-V1"
# Association authority input schema (exact 80 bytes, big-endian).
ASSOC_INPUT_LEN = 80
ASSOC_OFF_PROFILE_ID = 0
ASSOC_OFF_EPOCH = 16  # network profile revision / association epoch u64
ASSOC_OFF_PROFILE_DIGEST = 24
ASSOC_OFF_BINDING_ID = 56
ASSOC_OFF_BSSID = 72
ASSOC_OFF_CHANNEL = 78
ASSOC_OFF_AUTH_MODE = 79

# Independent NWD1 KAT — fixed canonical bytes hardcoded in gen/gates/C.
# NOT derived from runtime encode_nwd1() of mutable SSID/profile defaults.
# Material: fixed profile/binding/bssid/ssid/digest/secret (see audit repair).
# Fixed independent NWD1 KAT (160 bytes). Material is literal, not derived from
# encode_nwd1(lab defaults). Layout matches encode_nwd1 field order:
# auth_mode@117, channel@118, bssid_present@119.
INDEPENDENT_NWD1_KAT_VALUE_HEX = (
    "4e57443100010080000000a00102030405060708090a0b0c0d0e0f10"
    "0000000000000007"
    "3030303030303030303030303030303030303030303030303030303030303030"
    "1112131415161718191a1b1c1d1e1f20"
    "0e4b41542d4e5744312d4649584544"
    "000000000000000000000000000000000000"  # 18-byte SSID pad (32-14)
    "010b01aabbccddeeff0000"
    "4040404040404040404040404040404040404040404040404040404040404040"
)
INDEPENDENT_NWD1_KAT_HEADER_CRC = 0xE1A712FA
INDEPENDENT_NWD1_KAT_AUTH_HEX = (
    "147db4b100c073732c8a837f88cd9e3b2600f2c1cb5f64b237e91bf234c45f04"
)
INDEPENDENT_NWD1_KAT_COMPLETE_HEX = (
    "479d037f00eac79ab4c4b14f91d60b7d7b50830e4bfb82c47ed1acad828cb744"
)

# Hard-pinned source metadata (gates reject drift / missing paths).
PINNED_SCHEMA = "ninlil.wifi.bearer.spec.v1"
PINNED_STATUS = "PROPOSED_CANDIDATE_NOT_SPEC_ACCEPTED"
PINNED_ADR = "docs/adr/0018-wifi-bearer.md"
PINNED_GENERATOR = "tools/wifi_bearer_spec_vector_gen.py"
PINNED_GATE_PY = "tools/wifi_bearer_spec_gate.py"
PINNED_GATE_MJS = "tools/wifi_bearer_spec_gate.mjs"
PINNED_VECTOR = "spec/vectors/wifi-bearer-spec-v1.json"
PINNED_C_TEST = "tests/transport/wifi_bearer_spec_vector_test.c"
PINNED_TOOL_PATHS = (
    PINNED_ADR,
    PINNED_GENERATOR,
    PINNED_GATE_PY,
    PINNED_GATE_MJS,
    PINNED_VECTOR,
    PINNED_C_TEST,
)

# Structural boundary rejects (exact edge KATs).
PAYLOAD_REJECT_LOW = 586
PAYLOAD_REJECT_HIGH = 1926
TOTAL_REJECT_LOW = 626
TOTAL_REJECT_HIGH = 1966

PEER_CONTEXT_LEN = 62
ATTACHED_CONTEXT_LEN = 64

KEEPALIVE_INTERVAL_MS = 15000
KEEPALIVE_EXCLUSIVE_DEADLINE_MS = 15000
MISSED_RESPONSE_THRESHOLD = 3
BLACKHOLE_DETECT_MS = 45000  # interval * threshold
SESSION_LIFETIME_MS = 3_600_000
ATTACHED_STABLE_RESET_MS = 60_000

BACKOFF_MS = (1000, 2000, 4000, 8000, 16000, 32000)
BACKOFF_CAP_MS = 32000

# Resource profile 1 (Proposed candidate; not RELEASE_SUPPORTED).
ESP_ADAPTER_MAX = 1
ESP_SESSION_MAX = 2
ESP_CONNECT_ATTEMPT_MAX = 1
ESP_EVENT_QUEUE_MAX = 8
ESP_TX_TOKEN_MAX = 8
ESP_RX_RECORD_MAX = 8
ESP_RX_LOAN_MAX = 1
HOST_ADAPTER_MAX = 64
HOST_SESSION_MAX = 64
HOST_CONNECT_ATTEMPT_MAX = 8
HOST_TX_TOKEN_PER_SESSION = 8
HOST_RX_RECORD_PER_SESSION = 8
RECORD_BYTES_FIXED = 1965

# ESP32-S3 TLS target-software-candidate fail-closed envelope (ADR-0018
# §14.1.1).  These are reservation bounds, not physical-HIL evidence.
ESP_TLS_SESSION_TOTAL_BYTES = 98_304
ESP_TLS_SESSION_INTERNAL_BYTES = 12_288
ESP_TLS_SESSION_PSRAM_BYTES = 86_016
ESP_TLS_CRYPTO_GLOBAL_INTERNAL_BYTES = 65_536
ESP_TLS_POST_ADMISSION_INTERNAL_FLOOR_BYTES = 65_536
ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES = 327_680
ESP_TLS_EXECUTION_STACK_BYTES = 8_192
ESP_TLS_CRYPTO_DMA_BYTES = 0
ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE_BYTES = 163_840
ESP_TLS_MAP_REMAINDER_OBSERVATION_BYTES = 171_825
ESP_TLS_MAP_OBSERVATION_SLACK_BYTES = 7_985
ESP_TLS_IN_BUFFER_BYTES = 16_685
ESP_TLS_OUT_BUFFER_BYTES = 4_415

# Network durable authority (SSID/password rotation metadata; no plaintext secret).
NWD1_MAGIC = b"NWD1"
NWD1_VERSION = 1
NWD1_HEADER = 128
NWD1_RECORD_BYTES = 160  # header 128 + trailing digest 32
NETWORK_NAMESPACE = "ninlil.wifi.network.v1"
NETWORK_KEY_PREFIX = b"NWN1"

# Storage arithmetic for network durable authority (role-shared schema, role caps differ).
NWD1_KEYS_MAX = 8
NWD1_COMMITTED_CU = NWD1_KEYS_MAX * NWD1_RECORD_BYTES  # 1280
NWD1_STAGING_CU = NWD1_COMMITTED_CU * 2  # 2560

TLS_SUITE = "TLS_AES_128_GCM_SHA256"
TLS_SUITE_ID = 0x1301
TLS_GROUP = "secp256r1"
TLS_GROUP_ID = 0x0017
TLS_SIG = "ecdsa_secp256r1_sha256"
TLS_SIG_ID = 0x0403
TLS_PROTOCOL = "TLS1.3"

# Host OpenSSL pin vs generic R7 (must not conflate).
HOST_OPENSSL_TAG = "openssl-3.5.7"
HOST_OPENSSL_PEELED = "8cf17aaeb4599f8af87fefd810b5b5fee90fe69e"
R7_GENERIC_OPENSSL_RULE = "OpenSSL major version exactly 3 (find_package OpenSSL 3)"
ESP_IDF_COMMIT = "2c211b236707889e8400c4dc5644dd5c4ee071e0"
ESP_MBEDTLS_COMMIT = "ffb280bb63c78bfec1e1ab55040671768c85c923"

EXPORTER_PEER_LABEL = "EXPORTER-Ninlil-PeerSession-v1"
EXPORTER_ATTACHED_LABEL = "EXPORTER-Ninlil-NWB1-Attached-v1"

REQUIRED_ACCEPTANCE_IDS: tuple[str, ...] = (
    # 1 association / BSSID / channel / network-profile authority
    "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE",
    "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE",
    "WIFI-ASSOC-SAME-SSID-CHANNEL-CHANGE-FENCE",
    "WIFI-ASSOC-PROFILE-DIGEST-CHANGE-FENCE",
    "WIFI-ASSOC-SAME-TUPLE-NO-EPOCH",
    "WIFI-ASSOC-SESSION-FENCE-AVAILABILITY-PLUS-ONE",
    # 2 post-ATTACHED liveness
    "WIFI-LIVENESS-KEEPALIVE-EXCLUSIVE-TIMER",
    "WIFI-LIVENESS-MISSED-RESPONSE-THRESHOLD",
    "WIFI-LIVENESS-BLACKHOLE-DETECTION",
    "WIFI-LIVENESS-TCP-HALF-OPEN",
    "WIFI-LIVENESS-AP-DEAD-BACKHAUL",
    "WIFI-LIVENESS-AVAILABILITY-EPOCH-CHANGE",
    # 3 network credential rotation durable authority
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
    # 4 endpoint scope
    "WIFI-ENDPOINT-IPV4-SCOPE",
    "WIFI-ENDPOINT-IPV6-SCOPE",
    "WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID",
    "WIFI-ENDPOINT-DNS-MDNS-NON-AUTHORITY",
    "WIFI-ENDPOINT-ADDRESS-CHANGE-FENCE",
    # 5 NWB1 framing / sequence / CRC
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
    # 6 TLS profile
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
    # 7 pre-attachment vs NWB1
    "WIFI-PREATTACH-CARRIER-NOT-NWB1",
    "WIFI-PREATTACH-PEER-SESSION-ONLY-NO-NWB1",
    "WIFI-PREATTACH-NWB1-REQUIRES-PA-FULL",
    # 8 queues / resources
    "WIFI-RESOURCE-ESP-CAPACITY",
    "WIFI-RESOURCE-HOST-CAPACITY",
    "WIFI-RESOURCE-PRIORITY-ISOLATION",
    "WIFI-RESOURCE-RETAINED-TOKEN-PARTIAL-WRITE",
    "WIFI-RESOURCE-RELEASE-SEMANTICS",
    "WIFI-RESOURCE-NO-FALSE-CUSTODY",
    "WIFI-RESOURCE-STORAGE-ARITHMETIC",
    # 9 role responsibilities
    "WIFI-ROLE-HOST-POSIX-TCP-TLS",
    "WIFI-ROLE-ESP32S3-STA-LWIP-MBEDTLS",
    # 10 races / backoff
    "WIFI-RACE-DISCONNECT-RECONNECT",
    "WIFI-RACE-SLEEP-DRAIN",
    "WIFI-RACE-EVENT-OVERFLOW",
    "WIFI-BACKOFF-DETERMINISTIC",
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


def hex_of(value: bytes) -> str:
    return value.hex()


def pattern(start: int, length: int) -> bytes:
    return bytes((start + index) & 0xFF for index in range(length))


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def any_nonzero(value: bytes) -> bool:
    return any(value)


def all_zero(value: bytes) -> bool:
    return not any(value)


def encode_nfl1_structural(
    total_length: int,
    *,
    valid: bool = True,
    version: int = NFL1_VERSION,
) -> bytes:
    """Exact structurally valid NFL1 of `total_length` (587..1925) or invalid variant.

    Layout matches ADR-0017/Fabric NFL1: header 584, CRC32C at offset 12 over
    the full packet with the CRC field zeroed, tail = ns|svc|schema|payload|evidence.
    """
    if total_length < NFL1_HEADER:
        raise ValueError("nfl1 too short")
    body_len = total_length - NFL1_HEADER
    # Min structural: 1+1+1 byte names, rest payload (evidence empty).
    if body_len < 3 and valid:
        raise ValueError("nfl1 body")
    if valid:
        ns = b"n"
        svc = b"s"
        schema = b"x"
        payload = pattern(0x41, max(0, body_len - 3))
        evidence = b""
        if len(ns) + len(svc) + len(schema) + len(payload) + len(evidence) != body_len:
            # Adjust payload exactly.
            payload = pattern(0x41, body_len - 3)
    else:
        ns = b"n"
        svc = b"s"
        schema = b"x"
        payload = pattern(0x41, max(0, body_len - 3))
        evidence = b""
        if body_len >= 3:
            payload = pattern(0x41, body_len - 3)

    header = bytearray(NFL1_HEADER)
    header[0:4] = NFL1_MAGIC if valid else b"BAD1"
    header[4:6] = u16(version)
    header[6:8] = u16(NFL1_HEADER)
    header[8:12] = u32(total_length)
    header[12:16] = bytes(4)  # CRC placeholder
    header[16:20] = u32(1)  # message_kind APPLICATION
    header[20:24] = u32(0)  # message_flags
    header[24:40] = pattern(0x10, 16)  # transaction_id
    header[40:56] = pattern(0x20, 16)
    header[56:72] = bytes(16)
    header[72:88] = pattern(0x30, 16)
    header[88:104] = pattern(0x40, 16)
    header[104:120] = pattern(0x50, 16)
    header[120:136] = pattern(0x60, 16)
    header[136:152] = pattern(0x70, 16)
    header[152:160] = u64(1)
    header[160:168] = u64(1)
    header[168:172] = u32(7)
    header[172:188] = pattern(0x80, 16)
    header[188:204] = pattern(0x90, 16)
    header[204:220] = pattern(0xA0, 16)
    header[220:236] = pattern(0xB0, 16)
    header[236:252] = pattern(0xC0, 16)
    header[252:260] = u64(1)
    header[260:268] = u64(1)
    header[268:272] = u32(7)
    header[272:288] = pattern(0xD0, 16)
    header[288:296] = u64(1)
    header[296:300] = u32(1)
    header[300:308] = u64(1)
    header[308:310] = u16(1)
    header[310:342] = sha256(b"wifi-nfl1-descriptor")
    header[342:344] = u16(1)
    header[344:346] = u16(0)
    header[346:350] = u32(2)
    header[350:352] = u16(1)
    header[352:384] = sha256(b"wifi-nfl1-content")
    header[384:392] = u64(1)
    header[392:408] = pattern(0xA1, 16)
    header[408:416] = u64(200000)
    header[416:424] = u64(5000)
    header[424:428] = u32(0)
    header[428:432] = u32(0)
    header[432:436] = u32(0)
    header[436:440] = u32(0)
    header[440:444] = u32(0)
    header[444:448] = u32(0)
    header[448:456] = u64(0)
    header[456:472] = bytes(16)
    header[472:480] = u64(0)
    header[480:484] = u32(0)
    header[484:500] = pattern(0xF0, 16)
    header[500:508] = u64(1)
    header[508:510] = u16(1)
    header[510:542] = sha256(b"wifi-nfl1-route")
    header[542:558] = pattern(0x01, 16)
    header[558:566] = u64(1)
    header[566:570] = u32(0)
    header[570:572] = u16(len(ns))
    header[572:574] = u16(len(svc))
    header[574:576] = u16(len(schema))
    header[576:580] = u32(len(payload))
    header[580:584] = u32(len(evidence))
    packet = bytes(header) + ns + svc + schema + payload + evidence
    if len(packet) != total_length:
        raise AssertionError(f"nfl1 length {len(packet)} != {total_length}")
    out = bytearray(packet)
    out[NFL1_CRC_OFFSET : NFL1_CRC_OFFSET + 4] = u32(crc32c(packet))
    return bytes(out)


def classify_nfl1_structural(packet: bytes) -> str:
    """Full structural NFL1 validation (version/header/total/CRC/body bounds)."""
    if len(packet) < NFL1_HEADER:
        return "INVALID_NFL1"
    if packet[0:4] != NFL1_MAGIC:
        return "INVALID_NFL1"
    version = struct.unpack(">H", packet[4:6])[0]
    header_length = struct.unpack(">H", packet[6:8])[0]
    total_length = struct.unpack(">I", packet[8:12])[0]
    stored_crc = struct.unpack(">I", packet[12:16])[0]
    if header_length != NFL1_HEADER:
        return "INVALID_NFL1"
    if total_length != len(packet):
        return "INVALID_NFL1"
    if not (NWB1_PAYLOAD_MIN <= total_length <= NWB1_PAYLOAD_MAX):
        # When embedded in NWB1, structural NFL1 is 587..1925.
        return "INVALID_NFL1"
    if version != NFL1_VERSION:
        return "INVALID_NFL1"
    scratch = bytearray(packet)
    scratch[12:16] = bytes(4)
    if crc32c(bytes(scratch)) != stored_crc:
        return "INVALID_NFL1"
    ns_len = struct.unpack(">H", packet[570:572])[0]
    svc_len = struct.unpack(">H", packet[572:574])[0]
    schema_len = struct.unpack(">H", packet[574:576])[0]
    payload_len = struct.unpack(">I", packet[576:580])[0]
    evidence_len = struct.unpack(">I", packet[580:584])[0]
    if ns_len > 63 or svc_len > 63 or schema_len > 63:
        return "INVALID_NFL1"
    if payload_len > 65535 or evidence_len > 65535:
        return "INVALID_NFL1"
    if NFL1_HEADER + ns_len + svc_len + schema_len + payload_len + evidence_len != total_length:
        return "INVALID_NFL1"
    # message_flags reserved high bits must be zero for v1 structural accept.
    message_flags = struct.unpack(">I", packet[20:24])[0]
    if message_flags & 0xFFFF0000:
        return "INVALID_NFL1"
    return "OK"


def synthetic_nfl1_payload(length: int, *, valid_magic: bool = True) -> bytes:
    """Build NFL1 payload of exact `length` for NWB1 KATs."""
    if length < NWB1_PAYLOAD_MIN or length > NWB1_PAYLOAD_MAX:
        # Out-of-range NWB1 payload boundary samples need only exact length.
        body = bytearray(length)
        body[0:4] = b"NFL1" if valid_magic else b"BAD1"
        for index in range(4, length):
            body[index] = (0x40 + index) & 0xFF
        return bytes(body)
    if valid_magic:
        return encode_nfl1_structural(length, valid=True)
    # Invalid magic: keep length but break NFL1 magic only (CRC self-consistent).
    good = encode_nfl1_structural(length, valid=True)
    bad = bytearray(good)
    bad[0:4] = b"BAD1"
    bad[12:16] = bytes(4)
    bad[12:16] = u32(crc32c(bytes(bad)))
    return bytes(bad)


def encode_nwb1(
    *,
    session_id: bytes,
    sequence: int,
    payload: bytes,
    version: int = NWB1_VERSION,
    header_length: int = NWB1_HEADER,
    force_total: int | None = None,
    force_payload_length: int | None = None,
    force_crc: int | None = None,
) -> bytes:
    if len(session_id) != 16:
        raise ValueError("session_id")
    payload_length = (
        force_payload_length if force_payload_length is not None else len(payload)
    )
    total_length = (
        force_total if force_total is not None else NWB1_HEADER + len(payload)
    )
    record = bytearray(NWB1_HEADER + len(payload))
    record[0:4] = NWB1_MAGIC
    record[4:6] = u16(version)
    record[6:8] = u16(header_length)
    record[8:12] = u32(total_length)
    record[12:16] = u32(payload_length)
    record[16:32] = session_id
    record[32:36] = u32(sequence & 0xFFFFFFFF)
    record[36:40] = bytes(4)
    record[40:] = payload
    if force_crc is None:
        crc = crc32c(bytes(record))
    else:
        crc = force_crc & 0xFFFFFFFF
    record[36:40] = u32(crc)
    return bytes(record)


def classify_nwb1_framing(
    record: bytes,
    *,
    expected_session: bytes | None = None,
    expected_sequence: int | None = None,
) -> str:
    """Independent structural classifier for NWB1 framing.

    Returns one of: OK, CORRUPT, UNSUPPORTED, WRONG_SESSION, SEQUENCE_REJECT,
    INVALID_NFL1. Semantic 6-kind NFL1 matrix is out of scope; INVALID_NFL1
    only checks NFL1 magic at payload[0:4] after framing OK.
    """
    if len(record) < NWB1_HEADER:
        return "CORRUPT"
    if record[0:4] != NWB1_MAGIC:
        return "CORRUPT"
    version = struct.unpack(">H", record[4:6])[0]
    header_length = struct.unpack(">H", record[6:8])[0]
    total_length = struct.unpack(">I", record[8:12])[0]
    payload_length = struct.unpack(">I", record[12:16])[0]
    session_id = record[16:32]
    sequence = struct.unpack(">I", record[32:36])[0]
    stored_crc = struct.unpack(">I", record[36:40])[0]
    if header_length != NWB1_HEADER:
        return "CORRUPT"
    if total_length != len(record):
        return "CORRUPT"
    if payload_length != len(record) - NWB1_HEADER:
        return "CORRUPT"
    if not (NWB1_PAYLOAD_MIN <= payload_length <= NWB1_PAYLOAD_MAX):
        return "CORRUPT"
    if not (NWB1_TOTAL_MIN <= total_length <= NWB1_TOTAL_MAX):
        return "CORRUPT"
    scratch = bytearray(record)
    scratch[36:40] = bytes(4)
    if crc32c(bytes(scratch)) != stored_crc:
        return "CORRUPT"
    if version > NWB1_VERSION:
        return "UNSUPPORTED"
    if version != NWB1_VERSION:
        return "CORRUPT"
    if all_zero(session_id):
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


def network_profile_digest(
    *,
    profile_id: bytes,
    revision: int,
    binding_id: bytes,
    ssid: bytes,
    auth_mode: int,
    password_length: int,
    pmf_required: int,
    bssid_present: int,
    bssid: bytes,
    channel: int,
) -> bytes:
    """Digest excludes password bytes; password length only as metadata."""
    if not (1 <= len(ssid) <= 32):
        raise ValueError("ssid")
    if len(profile_id) != 16 or len(binding_id) != 16 or len(bssid) != 6:
        raise ValueError("ids")
    ssid_field = ssid + bytes(32 - len(ssid))
    meta = (
        profile_id
        + u64(revision)
        + bytes(32)  # digest zero while hashing
        + binding_id
        + u8(len(ssid))
        + ssid_field
        + u8(auth_mode)
        + u8(password_length)
        + u8(pmf_required)
        + u8(bssid_present)
        + bssid
        + u8(channel)
        + bytes(7)
    )
    return sha256(NETWORK_PROFILE_TAG + meta)


def association_authority_input(
    *,
    profile_id: bytes,
    revision: int,
    profile_digest: bytes,
    binding_id: bytes,
    bssid: bytes,
    channel: int,
    auth_mode: int,
) -> bytes:
    if (
        len(profile_id) != 16
        or len(profile_digest) != 32
        or len(binding_id) != 16
        or len(bssid) != 6
    ):
        raise ValueError("assoc field sizes")
    out = (
        profile_id
        + u64(revision)
        + profile_digest
        + binding_id
        + bssid
        + u8(channel)
        + u8(auth_mode)
    )
    if len(out) != ASSOC_INPUT_LEN:
        raise AssertionError(len(out))
    return out


def parse_association_authority_input(canonical: bytes) -> dict[str, Any]:
    """Hard-coded schema parse of association authority input (not opaque hash)."""
    if len(canonical) != ASSOC_INPUT_LEN:
        raise ValueError("assoc input length")
    return {
        "profile_id": canonical[ASSOC_OFF_PROFILE_ID : ASSOC_OFF_PROFILE_ID + 16],
        "association_epoch": struct.unpack(
            ">Q", canonical[ASSOC_OFF_EPOCH : ASSOC_OFF_EPOCH + 8]
        )[0],
        "profile_digest": canonical[
            ASSOC_OFF_PROFILE_DIGEST : ASSOC_OFF_PROFILE_DIGEST + 32
        ],
        "binding_id": canonical[ASSOC_OFF_BINDING_ID : ASSOC_OFF_BINDING_ID + 16],
        "bssid": canonical[ASSOC_OFF_BSSID : ASSOC_OFF_BSSID + 6],
        "channel": canonical[ASSOC_OFF_CHANNEL],
        "auth_mode": canonical[ASSOC_OFF_AUTH_MODE],
    }


def association_authority_digest_from_input(canonical: bytes) -> bytes:
    if len(canonical) != ASSOC_INPUT_LEN:
        raise ValueError("assoc input")
    return sha256(ASSOC_AUTHORITY_TAG + canonical)


def association_authority_digest(
    *,
    profile_id: bytes,
    revision: int,
    profile_digest: bytes,
    binding_id: bytes,
    bssid: bytes,
    channel: int,
    auth_mode: int,
) -> bytes:
    canonical = association_authority_input(
        profile_id=profile_id,
        revision=revision,
        profile_digest=profile_digest,
        binding_id=binding_id,
        bssid=bssid,
        channel=channel,
        auth_mode=auth_mode,
    )
    return association_authority_digest_from_input(canonical)


def assoc_row_fields_from_input(
    canonical: bytes, *, prefix: str = ""
) -> dict[str, Any]:
    """Emit fully-bound authority fields, optionally with old_/new_ prefix."""
    parsed = parse_association_authority_input(canonical)
    p = prefix
    return {
        f"{p}profile_id_hex": hex_of(parsed["profile_id"]),
        f"{p}association_epoch": parsed["association_epoch"],
        f"{p}profile_revision": parsed["association_epoch"],
        f"{p}profile_digest_hex": hex_of(parsed["profile_digest"]),
        f"{p}binding_id_hex": hex_of(parsed["binding_id"]),
        f"{p}bssid_hex": hex_of(parsed["bssid"]),
        f"{p}channel": parsed["channel"],
        f"{p}auth_mode": parsed["auth_mode"],
        f"{p}association_authority_input_hex": hex_of(canonical),
        f"{p}association_authority_digest_hex": hex_of(
            association_authority_digest_from_input(canonical)
        ),
    }


def encode_nwd1(
    *,
    profile_id: bytes,
    revision: int,
    profile_digest: bytes,
    binding_id: bytes,
    ssid: bytes,
    auth_mode: int,
    channel: int,
    bssid_present: int,
    bssid: bytes,
    secret_ref_digest: bytes,
) -> bytes:
    """Durable network metadata record. Never stores password plaintext."""
    if len(secret_ref_digest) != 32:
        raise ValueError("secret_ref")
    if not (1 <= len(ssid) <= 32):
        raise ValueError("ssid")
    body = bytearray(NWD1_HEADER)
    body[0:4] = NWD1_MAGIC
    body[4:6] = u16(NWD1_VERSION)
    body[6:8] = u16(NWD1_HEADER)
    body[8:12] = u32(NWD1_RECORD_BYTES)
    body[12:28] = profile_id
    body[28:36] = u64(revision)
    body[36:68] = profile_digest
    body[68:84] = binding_id
    body[84] = len(ssid)
    body[85:117] = ssid + bytes(32 - len(ssid))
    body[117] = auth_mode
    body[118] = channel
    body[119] = bssid_present
    body[120:126] = bssid
    body[126:128] = bytes(2)
    record = bytes(body + secret_ref_digest)
    return record


def nwd1_complete_digest(record: bytes) -> bytes:
    return sha256(NWD1_COMPLETE_TAG + record)


def nwd1_header_crc32c(record: bytes) -> int:
    """CRC32C over exact 128-byte header (independent integrity, not tautology)."""
    if len(record) < NWD1_HEADER:
        raise ValueError("nwd1 short")
    return crc32c(record[0:NWD1_HEADER])


def nwd1_auth_digest(record: bytes) -> bytes:
    """Auth tag over header || secret_ref (independent of complete digest tag)."""
    if len(record) != NWD1_RECORD_BYTES:
        raise ValueError("nwd1")
    return sha256(NWD1_AUTH_TAG + record[0:NWD1_HEADER] + record[NWD1_HEADER:])


def validate_nwd1_record(record: bytes) -> str:
    """Exact NWD1 framing before any OLD/NEW equality classification."""
    if len(record) != NWD1_RECORD_BYTES:
        return "CORRUPT"
    if record[0:4] != NWD1_MAGIC:
        return "CORRUPT"
    if struct.unpack(">H", record[4:6])[0] != NWD1_VERSION:
        return "CORRUPT"
    if struct.unpack(">H", record[6:8])[0] != NWD1_HEADER:
        return "CORRUPT"
    if struct.unpack(">I", record[8:12])[0] != NWD1_RECORD_BYTES:
        return "CORRUPT"
    if record[126:128] != bytes(2):
        return "CORRUPT"
    ssid_len = record[84]
    if not 1 <= ssid_len <= 32:
        return "CORRUPT"
    if not any(record[12:28]):
        return "CORRUPT"
    if struct.unpack(">Q", record[28:36])[0] == 0:
        return "CORRUPT"
    if not any(record[36:68]):
        return "CORRUPT"
    if not any(record[68:84]):
        return "CORRUPT"
    if not any(record[128:160]):
        return "CORRUPT"
    return "OK"


def nwd1_value_authority(record: bytes) -> dict[str, Any]:
    """Independent integrity transcript for one NWD1 value."""
    if validate_nwd1_record(record) != "OK":
        raise ValueError("nwd1 framing")
    return {
        "value_hex": hex_of(record),
        "header_crc32c": nwd1_header_crc32c(record),
        "auth_digest_hex": hex_of(nwd1_auth_digest(record)),
        "complete_digest_hex": hex_of(nwd1_complete_digest(record)),
    }


def peer_context(
    *,
    authority_id: bytes,
    authority_term: int,
    assignment_epoch: int,
    client_runtime_id: bytes,
    server_runtime_id: bytes,
) -> bytes:
    if not (
        len(authority_id) == 16
        and len(client_runtime_id) == 16
        and len(server_runtime_id) == 16
    ):
        raise ValueError("peer_context ids")
    ctx = (
        authority_id
        + u64(authority_term)
        + u32(assignment_epoch)
        + u8(0x01)
        + client_runtime_id
        + u8(0x02)
        + server_runtime_id
    )
    if len(ctx) != PEER_CONTEXT_LEN:
        raise AssertionError(len(ctx))
    return ctx


def attached_context(
    *,
    peer_session_id: bytes,
    attachment_authority_id: bytes,
    active_attachment_binding_digest: bytes,
) -> bytes:
    if not (
        len(peer_session_id) == 16
        and len(attachment_authority_id) == 16
        and len(active_attachment_binding_digest) == 32
    ):
        raise ValueError("attached_context ids")
    ctx = (
        peer_session_id
        + attachment_authority_id
        + active_attachment_binding_digest
    )
    if len(ctx) != ATTACHED_CONTEXT_LEN:
        raise AssertionError(len(ctx))
    return ctx


def authority_group_class(
    authority_id: bytes, authority_term: int, assignment_epoch: int
) -> str:
    zeros = all_zero(authority_id) and authority_term == 0 and assignment_epoch == 0
    nonzeros = (
        any_nonzero(authority_id) and authority_term != 0 and assignment_epoch != 0
    )
    if zeros:
        return "ALL_ZERO"
    if nonzeros:
        return "ALL_NONZERO"
    return "MIXED"


def backoff_ms(failure_generation: int) -> int:
    if failure_generation < 1:
        raise ValueError("failure_generation")
    if failure_generation <= len(BACKOFF_MS):
        return BACKOFF_MS[failure_generation - 1]
    return BACKOFF_CAP_MS


def jitter_ms(instance_id: bytes, failure_generation: int) -> int:
    digest = sha256(instance_id + u64(failure_generation))
    return struct.unpack(">H", digest[0:2])[0] % 1000


def classify_commit_unknown(
    *,
    old_rows: list[tuple[bytes, bytes]],
    new_rows: list[tuple[bytes, bytes]],
    observed_rows: list[tuple[bytes, bytes]],
) -> str:
    """FULL old/new/partial/extra/third/absent/corrupt for network durable group.

    Duplicate keys in any of old/new/observed are CORRUPT (Python/Node parity).
    Every non-empty value must pass validate_nwd1_record before equality classes.
    """
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
    # BOTH: observed contains full OLD and full NEW as disjoint authority images.
    # Requires old≠new; each key appears once so old/new keys must not conflict.
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


def leaf_binding_value(
    *,
    role: int,
    runtime_id: bytes,
    attachment_candidate_digest: bytes,
    authority_id: bytes,
    authority_term: int,
    credential_generation: int,
    revocation_generation: int,
) -> bytes:
    if role not in (1, 2):
        raise ValueError("role")
    value = (
        u8(0x01)
        + u8(role)
        + runtime_id
        + attachment_candidate_digest
        + authority_id
        + u64(authority_term)
        + u32(credential_generation)
        + u32(revocation_generation)
    )
    if len(value) != 82:
        raise AssertionError(len(value))
    return value


def build_document() -> dict[str, Any]:
    session_id = pattern(0x10, 16)
    other_session = pattern(0x90, 16)
    instance_id = pattern(0xA0, 16)
    profile_id = pattern(0xB0, 16)
    binding_id = pattern(0xC0, 16)
    binding_id_rotated = pattern(0xC1, 16)
    ssid = b"ninlil-lab-ssid"
    bssid_a = bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])
    bssid_b = bytes([0x02, 0x11, 0x22, 0x33, 0x44, 0x66])
    auth_mode = 2  # WPA3_SAE
    channel_a = 6
    channel_b = 11
    password_length = 16  # metadata only; no password bytes
    secret_ref = sha256(b"synthetic-secret-ref-not-password")
    secret_ref_rotated = sha256(b"synthetic-secret-ref-rotated")

    digest_a = network_profile_digest(
        profile_id=profile_id,
        revision=1,
        binding_id=binding_id,
        ssid=ssid,
        auth_mode=auth_mode,
        password_length=password_length,
        pmf_required=1,
        bssid_present=1,
        bssid=bssid_a,
        channel=channel_a,
    )
    digest_b_bssid = network_profile_digest(
        profile_id=profile_id,
        revision=1,
        binding_id=binding_id,
        ssid=ssid,
        auth_mode=auth_mode,
        password_length=password_length,
        pmf_required=1,
        bssid_present=1,
        bssid=bssid_b,
        channel=channel_a,
    )
    # BSSID is in profile metadata; digest changes when BSSID present tuple changes.
    digest_channel = network_profile_digest(
        profile_id=profile_id,
        revision=1,
        binding_id=binding_id,
        ssid=ssid,
        auth_mode=auth_mode,
        password_length=password_length,
        pmf_required=1,
        bssid_present=1,
        bssid=bssid_a,
        channel=channel_b,
    )
    digest_rotated = network_profile_digest(
        profile_id=profile_id,
        revision=2,
        binding_id=binding_id_rotated,
        ssid=ssid,
        auth_mode=auth_mode,
        password_length=password_length,
        pmf_required=1,
        bssid_present=1,
        bssid=bssid_a,
        channel=channel_a,
    )

    assoc_input_a = association_authority_input(
        profile_id=profile_id,
        revision=1,
        profile_digest=digest_a,
        binding_id=binding_id,
        bssid=bssid_a,
        channel=channel_a,
        auth_mode=auth_mode,
    )
    assoc_a = sha256(ASSOC_AUTHORITY_TAG + assoc_input_a)
    assoc_input_bssid = association_authority_input(
        profile_id=profile_id,
        revision=1,
        profile_digest=digest_b_bssid,
        binding_id=binding_id,
        bssid=bssid_b,
        channel=channel_a,
        auth_mode=auth_mode,
    )
    assoc_bssid = sha256(ASSOC_AUTHORITY_TAG + assoc_input_bssid)
    assoc_input_channel = association_authority_input(
        profile_id=profile_id,
        revision=1,
        profile_digest=digest_channel,
        binding_id=binding_id,
        bssid=bssid_a,
        channel=channel_b,
        auth_mode=auth_mode,
    )
    assoc_channel = sha256(ASSOC_AUTHORITY_TAG + assoc_input_channel)
    assoc_input_profile = association_authority_input(
        profile_id=profile_id,
        revision=2,
        profile_digest=digest_rotated,
        binding_id=binding_id_rotated,
        bssid=bssid_a,
        channel=channel_a,
        auth_mode=auth_mode,
    )
    assoc_profile = sha256(ASSOC_AUTHORITY_TAG + assoc_input_profile)

    payload_min = synthetic_nfl1_payload(NWB1_PAYLOAD_MIN)
    payload_max = synthetic_nfl1_payload(NWB1_PAYLOAD_MAX)
    payload_invalid = synthetic_nfl1_payload(NWB1_PAYLOAD_MIN, valid_magic=False)
    nwb1_min = encode_nwb1(session_id=session_id, sequence=0, payload=payload_min)
    nwb1_max = encode_nwb1(session_id=session_id, sequence=0, payload=payload_max)
    nwb1_seq_max = encode_nwb1(
        session_id=session_id, sequence=0xFFFFFFFE, payload=payload_min
    )
    nwb1_seq_u32max = encode_nwb1(
        session_id=session_id, sequence=0xFFFFFFFF, payload=payload_min
    )
    nwb1_wrong_session = encode_nwb1(
        session_id=other_session, sequence=0, payload=payload_min
    )
    nwb1_invalid_nfl1 = encode_nwb1(
        session_id=session_id, sequence=0, payload=payload_invalid
    )
    nwb1_seq1 = encode_nwb1(session_id=session_id, sequence=1, payload=payload_min)
    nwb1_seq2 = encode_nwb1(session_id=session_id, sequence=2, payload=payload_min)
    nwb1_bad_crc = bytearray(nwb1_min)
    nwb1_bad_crc[36] ^= 0x01
    nwb1_bad_crc = bytes(nwb1_bad_crc)

    # Forced length rejects (may have inconsistent fields by construction).
    short_payload = synthetic_nfl1_payload(PAYLOAD_REJECT_LOW)
    nwb1_payload_586 = encode_nwb1(
        session_id=session_id, sequence=0, payload=short_payload
    )
    long_payload = synthetic_nfl1_payload(PAYLOAD_REJECT_HIGH)
    nwb1_payload_1926 = encode_nwb1(
        session_id=session_id, sequence=0, payload=long_payload
    )

    # total 626 with claimed total field force (still payload 586 body).
    nwb1_total_626 = encode_nwb1(
        session_id=session_id,
        sequence=0,
        payload=short_payload,
        force_total=TOTAL_REJECT_LOW,
    )
    nwb1_total_1966 = encode_nwb1(
        session_id=session_id,
        sequence=0,
        payload=long_payload,
        force_total=TOTAL_REJECT_HIGH,
    )

    nwd1_old = encode_nwd1(
        profile_id=profile_id,
        revision=1,
        profile_digest=digest_a,
        binding_id=binding_id,
        ssid=ssid,
        auth_mode=auth_mode,
        channel=channel_a,
        bssid_present=1,
        bssid=bssid_a,
        secret_ref_digest=secret_ref,
    )
    nwd1_new = encode_nwd1(
        profile_id=profile_id,
        revision=2,
        profile_digest=digest_rotated,
        binding_id=binding_id_rotated,
        ssid=ssid,
        auth_mode=auth_mode,
        channel=channel_a,
        bssid_present=1,
        bssid=bssid_a,
        secret_ref_digest=secret_ref_rotated,
    )
    nwd1_third = encode_nwd1(
        profile_id=profile_id,
        revision=9,
        profile_digest=sha256(b"third-profile"),
        binding_id=pattern(0xEE, 16),
        ssid=ssid,
        auth_mode=auth_mode,
        channel=1,
        bssid_present=0,
        bssid=bytes(6),
        secret_ref_digest=sha256(b"third-secret-ref"),
    )
    # Same revision, conflicting digest (rollback / conflict).
    nwd1_conflict = encode_nwd1(
        profile_id=profile_id,
        revision=2,
        profile_digest=sha256(b"conflict-digest"),
        binding_id=binding_id_rotated,
        ssid=ssid,
        auth_mode=auth_mode,
        channel=channel_a,
        bssid_present=1,
        bssid=bssid_a,
        secret_ref_digest=secret_ref_rotated,
    )
    nwd1_rollback = encode_nwd1(
        profile_id=profile_id,
        revision=1,
        profile_digest=digest_a,
        binding_id=binding_id,
        ssid=ssid,
        auth_mode=auth_mode,
        channel=channel_a,
        bssid_present=1,
        bssid=bssid_a,
        secret_ref_digest=secret_ref,
    )

    key_old = NETWORK_KEY_PREFIX + b"\x00" + profile_id[:11]
    key_new = NETWORK_KEY_PREFIX + b"\x01" + profile_id[:11]
    # Keep keys distinct fixed 16-byte style
    key_old = (NETWORK_KEY_PREFIX + b"OLD1" + profile_id)[:16]
    key_new = (NETWORK_KEY_PREFIX + b"NEW1" + profile_id)[:16]
    key_extra = (NETWORK_KEY_PREFIX + b"XTRA" + profile_id)[:16]
    if len(key_old) != 16 or len(key_new) != 16:
        key_old = (NETWORK_KEY_PREFIX + b"OLD" + profile_id)[:16]
        key_new = (NETWORK_KEY_PREFIX + b"NEW" + profile_id)[:16]
        key_extra = (NETWORK_KEY_PREFIX + b"XTR" + profile_id)[:16]

    old_rows = [(key_old, nwd1_old)]
    new_rows = [(key_old, nwd1_new)]  # same key, new value FULL replace
    partial_rows = []  # empty subset after intending new
    extra_rows = [(key_old, nwd1_new), (key_extra, nwd1_third)]
    third_rows = [(key_old, nwd1_third)]

    cu_old = classify_commit_unknown(
        old_rows=old_rows, new_rows=new_rows, observed_rows=old_rows
    )
    cu_new = classify_commit_unknown(
        old_rows=old_rows, new_rows=new_rows, observed_rows=new_rows
    )
    cu_partial = classify_commit_unknown(
        old_rows=old_rows, new_rows=new_rows, observed_rows=partial_rows
    )
    # For partial of multi-key new group:
    multi_new = [(key_old, nwd1_new), (key_new, nwd1_new)]
    multi_old = [(key_old, nwd1_old), (key_new, nwd1_old)]
    cu_partial = classify_commit_unknown(
        old_rows=multi_old,
        new_rows=multi_new,
        observed_rows=[(key_old, nwd1_new)],
    )
    cu_extra = classify_commit_unknown(
        old_rows=old_rows, new_rows=new_rows, observed_rows=extra_rows
    )
    cu_third = classify_commit_unknown(
        old_rows=old_rows, new_rows=new_rows, observed_rows=third_rows
    )
    cu_absent = classify_commit_unknown(
        old_rows=[], new_rows=new_rows, observed_rows=[]
    )
    # Duplicate key in observed (and independently old) is CORRUPT.
    dup_observed = [(key_old, nwd1_old), (key_old, nwd1_new)]
    cu_dup = classify_commit_unknown(
        old_rows=old_rows, new_rows=new_rows, observed_rows=dup_observed
    )
    cu_dup_old = classify_commit_unknown(
        old_rows=[(key_old, nwd1_old), (key_old, nwd1_old)],
        new_rows=new_rows,
        observed_rows=old_rows,
    )

    # Exporter contexts
    authority_id = pattern(0xD0, 16)
    client_runtime = pattern(0x31, 16)
    server_runtime = pattern(0x32, 16)
    peer_ctx = peer_context(
        authority_id=authority_id,
        authority_term=7,
        assignment_epoch=11,
        client_runtime_id=client_runtime,
        server_runtime_id=server_runtime,
    )
    # Simulated non-zero peer_session_id material (exporter KAT context only).
    peer_session_id = sha256(b"sim-peer-session" + peer_ctx)[:16]
    if all_zero(peer_session_id):
        peer_session_id = pattern(0x51, 16)
    attach_authority = pattern(0xE0, 16)
    attach_binding = sha256(b"active-attachment-binding")
    attached_ctx = attached_context(
        peer_session_id=peer_session_id,
        attachment_authority_id=attach_authority,
        active_attachment_binding_digest=attach_binding,
    )
    zero_ctx = peer_context(
        authority_id=bytes(16),
        authority_term=0,
        assignment_epoch=0,
        client_runtime_id=client_runtime,
        server_runtime_id=server_runtime,
    )
    mixed_ctx = peer_context(
        authority_id=authority_id,
        authority_term=0,  # mixed
        assignment_epoch=11,
        client_runtime_id=client_runtime,
        server_runtime_id=server_runtime,
    )

    leaf_client = leaf_binding_value(
        role=1,
        runtime_id=client_runtime,
        attachment_candidate_digest=attach_binding,
        authority_id=authority_id,
        authority_term=7,
        credential_generation=3,
        revocation_generation=5,
    )
    leaf_server = leaf_binding_value(
        role=2,
        runtime_id=server_runtime,
        attachment_candidate_digest=attach_binding,
        authority_id=authority_id,
        authority_term=7,
        credential_generation=3,
        revocation_generation=5,
    )

    # Coalesced two records
    coalesced = nwb1_min + nwb1_seq1
    # Partial header / body slices
    partial_header = nwb1_min[:20]
    partial_body = nwb1_min[:100]

    # Storage arithmetic verification
    storage_arithmetic = {
        "nwd1_record_bytes": NWD1_RECORD_BYTES,
        "nwd1_keys_max": NWD1_KEYS_MAX,
        "committed_cu_bytes": NWD1_COMMITTED_CU,
        "staging_cu_bytes": NWD1_STAGING_CU,
        "committed_formula": "keys_max * record_bytes",
        "staging_formula": "committed_cu_bytes * 2",
        "esp_nwd1_active_profiles_max": 1,
        "host_nwd1_active_profiles_max": 8,
        "plaintext_password_in_storage": 0,
        "plaintext_password_in_vectors": 0,
        "secret_ref_digest_only": 1,
    }

    def assoc_bound(canonical: bytes, **extra: Any) -> dict[str, Any]:
        fields = assoc_row_fields_from_input(canonical)
        fields["ssid_hex"] = hex_of(ssid)
        fields.update(extra)
        return fields

    association_vectors = [
        assoc_bound(
            assoc_input_a,
            id="WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE",
            availability_epoch_delta=0,
            session_fence=0,
            result="OK_ATTACHED_ELIGIBLE",
        ),
        {
            "id": "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE",
            "ssid_hex": hex_of(ssid),
            **assoc_row_fields_from_input(assoc_input_a, prefix="old_"),
            **assoc_row_fields_from_input(assoc_input_bssid, prefix="new_"),
            "digests_equal": int(assoc_a == assoc_bssid),
            "availability_epoch_delta": 1,
            "session_fence": 1,
            "nwb1_publish": 0,
            "result": "FENCED_STALE_SESSION",
        },
        {
            "id": "WIFI-ASSOC-SAME-SSID-CHANNEL-CHANGE-FENCE",
            "ssid_hex": hex_of(ssid),
            **assoc_row_fields_from_input(assoc_input_a, prefix="old_"),
            **assoc_row_fields_from_input(assoc_input_channel, prefix="new_"),
            "digests_equal": int(assoc_a == assoc_channel),
            "availability_epoch_delta": 1,
            "session_fence": 1,
            "nwb1_publish": 0,
            "result": "FENCED_STALE_SESSION",
        },
        {
            "id": "WIFI-ASSOC-PROFILE-DIGEST-CHANGE-FENCE",
            "ssid_hex": hex_of(ssid),
            **assoc_row_fields_from_input(assoc_input_a, prefix="old_"),
            **assoc_row_fields_from_input(assoc_input_profile, prefix="new_"),
            "old_revision": 1,
            "new_revision": 2,
            "availability_epoch_delta": 1,
            "session_fence": 1,
            "result": "FENCED_STALE_SESSION",
        },
        assoc_bound(
            assoc_input_a,
            id="WIFI-ASSOC-SAME-TUPLE-NO-EPOCH",
            reobserve_same_tuple=1,
            availability_epoch_delta=0,
            session_fence=0,
            result="OK_NO_FENCE",
        ),
        {
            "id": "WIFI-ASSOC-SESSION-FENCE-AVAILABILITY-PLUS-ONE",
            "event": "ASSOCIATION_AUTHORITY_DIGEST_CHANGED",
            "physical_events_observed": 2,
            "session_fence_generation": 1,
            "availability_epoch_delta": 1,
            "double_count_forbidden": 1,
            "result": "AVAILABILITY_PLUS_ONE_ONCE",
        },
    ]

    liveness_vectors = [
        {
            "id": "WIFI-LIVENESS-KEEPALIVE-EXCLUSIVE-TIMER",
            "state": "ATTACHED",
            "keepalive_interval_ms": KEEPALIVE_INTERVAL_MS,
            "exclusive_deadline_ms": KEEPALIVE_EXCLUSIVE_DEADLINE_MS,
            "timer_shares_phase_deadline": 0,
            "result": "OK_EXCLUSIVE",
        },
        {
            "id": "WIFI-LIVENESS-MISSED-RESPONSE-THRESHOLD",
            "missed_response_threshold": MISSED_RESPONSE_THRESHOLD,
            "missed_count_at_fail": MISSED_RESPONSE_THRESHOLD,
            "missed_count_still_ok": MISSED_RESPONSE_THRESHOLD - 1,
            "result": "FAIL_AT_THRESHOLD",
        },
        {
            "id": "WIFI-LIVENESS-BLACKHOLE-DETECTION",
            "blackhole_detect_ms": BLACKHOLE_DETECT_MS,
            "formula": "keepalive_interval_ms * missed_response_threshold",
            "tcp_ack_alone_not_liveness": 1,
            "result": "FENCED_ON_BLACKHOLE",
        },
        {
            "id": "WIFI-LIVENESS-TCP-HALF-OPEN",
            "condition": "PEER_SILENT_TCP_STILL_WRITABLE",
            "os_tcp_keepalive_is_authority": 0,
            "nwb1_or_probe_response_required": 1,
            "result": "FENCED_HALF_OPEN",
        },
        {
            "id": "WIFI-LIVENESS-AP-DEAD-BACKHAUL",
            "wifi_associated": 1,
            "ip_ready": 1,
            "peer_probe_ok": 0,
            "result": "FENCED_DEAD_BACKHAUL",
            "nwb1_publish": 0,
        },
        {
            "id": "WIFI-LIVENESS-AVAILABILITY-EPOCH-CHANGE",
            "on_liveness_fail": {
                "session_fence": 1,
                "nwb1_delivery": 0,
                "connection_close": 1,
                "availability_epoch_delta": 1,
                "double_add_forbidden": 1,
            },
            "result": "AVAILABILITY_PLUS_ONE",
        },
    ]

    def row_hex(rows: list[tuple[bytes, bytes]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key, value in rows:
            auth = nwd1_value_authority(value)
            out.append(
                {
                    "key_hex": hex_of(key),
                    "value_hex": auth["value_hex"],
                    "header_crc32c": auth["header_crc32c"],
                    "auth_digest_hex": auth["auth_digest_hex"],
                    "complete_digest_hex": auth["complete_digest_hex"],
                }
            )
        return out

    # BOTH: disjoint keys — old key keeps old value, new key holds new value.
    both_old = [(key_old, nwd1_old)]
    both_new = [(key_new, nwd1_new)]
    both_obs = [(key_old, nwd1_old), (key_new, nwd1_new)]
    cu_both = classify_commit_unknown(
        old_rows=both_old, new_rows=both_new, observed_rows=both_obs
    )

    # Hard-coded NWD1 KAT (literal; recomputed only for verification in self-test).
    nwd1_kat = nwd1_value_authority(nwd1_old)

    network_cred_vectors = [
        {
            "id": "WIFI-NETCRED-FULL-OLD",
            "old_rows": row_hex(old_rows),
            "new_rows": row_hex(new_rows),
            "observed_rows": row_hex(old_rows),
            "classification": cu_old,
            "expected_classification": "OLD",
            "publish": 0,
            "expected_observed_complete_digests": [
                nwd1_complete_digest(nwd1_old).hex()
            ],
        },
        {
            "id": "WIFI-NETCRED-FULL-NEW",
            "old_rows": row_hex(old_rows),
            "new_rows": row_hex(new_rows),
            "observed_rows": row_hex(new_rows),
            "classification": cu_new,
            "expected_classification": "NEW",
            "publish": 0,
            "requires_fresh_association": 1,
            "expected_observed_complete_digests": [
                nwd1_complete_digest(nwd1_new).hex()
            ],
        },
        {
            "id": "WIFI-NETCRED-FULL-ABSENT",
            "old_rows": [],
            "new_rows": row_hex(new_rows),
            "observed_rows": [],
            "classification": cu_absent,
            "expected_classification": "ABSENT",
            "publish": 0,
            "create_result": "COMMIT_UNKNOWN_NO_PUBLISH",
            "result": "ABSENT_RECLASSIFY_ONLY",
        },
        {
            "id": "WIFI-NETCRED-FULL-BOTH",
            "old_rows": row_hex(both_old),
            "new_rows": row_hex(both_new),
            "observed_rows": row_hex(both_obs),
            "classification": cu_both,
            "expected_classification": "BOTH",
            "publish": 0,
            "result": "BOTH_OLD_AND_NEW_PRESENT",
            "expected_observed_complete_digests": [
                nwd1_complete_digest(nwd1_old).hex(),
                nwd1_complete_digest(nwd1_new).hex(),
            ],
        },
        {
            "id": "WIFI-NETCRED-PARTIAL",
            "old_rows": row_hex(multi_old),
            "new_rows": row_hex(multi_new),
            "observed_rows": row_hex([(key_old, nwd1_new)]),
            "classification": cu_partial,
            "expected_classification": "PARTIAL",
            "publish": 0,
            "result": "CORRUPT_OR_COMMIT_UNKNOWN_NO_PUBLISH",
        },
        {
            "id": "WIFI-NETCRED-EXTRA",
            "old_rows": row_hex(old_rows),
            "new_rows": row_hex(new_rows),
            "observed_rows": row_hex(extra_rows),
            "classification": cu_extra,
            "expected_classification": "EXTRA",
            "publish": 0,
        },
        {
            "id": "WIFI-NETCRED-THIRD",
            "old_rows": row_hex(old_rows),
            "new_rows": row_hex(new_rows),
            "observed_rows": row_hex(third_rows),
            "classification": cu_third,
            "expected_classification": "THIRD",
            "publish": 0,
        },
        {
            "id": "WIFI-NETCRED-DUPLICATE-KEY",
            "old_rows": row_hex(old_rows),
            "new_rows": row_hex(new_rows),
            "observed_rows": row_hex(dup_observed),
            "classification": "CORRUPT",
            "expected_classification": "CORRUPT",
            "duplicate_old_key_classification": cu_dup_old,
            "expected_duplicate_old_key_classification": "CORRUPT",
            "publish": 0,
            "result": "CORRUPT_DUPLICATE_KEY",
        },
        {
            "id": "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY",
            "power_cut_after": "FULL_STAGE_BEFORE_COMMIT_ACK",
            "classifications_allowed_on_reopen": [
                "OLD",
                "NEW",
                "BOTH",
                "ABSENT",
                "PARTIAL",
                "EXTRA",
                "THIRD",
                "CORRUPT",
            ],
            "closed_classification_set": [
                "OLD",
                "NEW",
                "BOTH",
                "PARTIAL",
                "EXTRA",
                "THIRD",
                "ABSENT",
                "CORRUPT",
            ],
            "silent_fallback_forbidden": 1,
            "publish_before_reclassify": 0,
            "absent_example_classification": cu_absent,
            "both_example_classification": cu_both,
            "result": "RECLASSIFY_ONLY",
        },
        {
            "id": "WIFI-NETCRED-ROLLBACK-REJECT",
            "current_revision": 2,
            "observed_revision": 1,
            "observed_value_hex": hex_of(nwd1_rollback),
            "observed_complete_digest_hex": hex_of(nwd1_complete_digest(nwd1_rollback)),
            "observed_auth_digest_hex": hex_of(nwd1_auth_digest(nwd1_rollback)),
            "observed_header_crc32c": nwd1_header_crc32c(nwd1_rollback),
            "result": "FENCED_ROLLBACK",
            "publish": 0,
        },
        {
            "id": "WIFI-NETCRED-SAME-REVISION-DIGEST-CONFLICT",
            "revision": 2,
            "canonical_value_hex": hex_of(nwd1_new),
            "conflicting_value_hex": hex_of(nwd1_conflict),
            "canonical_complete_digest_hex": hex_of(nwd1_complete_digest(nwd1_new)),
            "conflicting_complete_digest_hex": hex_of(
                nwd1_complete_digest(nwd1_conflict)
            ),
            "digests_equal": int(
                nwd1_complete_digest(nwd1_new)
                == nwd1_complete_digest(nwd1_conflict)
            ),
            "result": "FENCED_DIGEST_CONFLICT",
            "publish": 0,
        },
        {
            "id": "WIFI-NETCRED-NO-PLAINTEXT-SECRET",
            "old_value_hex": hex_of(nwd1_old),
            "new_value_hex": hex_of(nwd1_new),
            "old_complete_digest_hex": hex_of(nwd1_complete_digest(nwd1_old)),
            "new_complete_digest_hex": hex_of(nwd1_complete_digest(nwd1_new)),
            "old_auth_digest_hex": hex_of(nwd1_auth_digest(nwd1_old)),
            "new_auth_digest_hex": hex_of(nwd1_auth_digest(nwd1_new)),
            "old_header_crc32c": nwd1_header_crc32c(nwd1_old),
            "new_header_crc32c": nwd1_header_crc32c(nwd1_new),
            "password_substrings_forbidden": [
                "hunter2",
                "p@ssw0rd",
                "correct-horse-battery",
            ],
            "secret_field": "secret_ref_digest_only",
            "secret_ref_digest_hex": hex_of(secret_ref),
            # Independent fixed KAT (literal constants; not runtime encode of SSID).
            "nwd1_kat_value_hex": INDEPENDENT_NWD1_KAT_VALUE_HEX,
            "nwd1_kat_complete_digest_hex": INDEPENDENT_NWD1_KAT_COMPLETE_HEX,
            "nwd1_kat_auth_digest_hex": INDEPENDENT_NWD1_KAT_AUTH_HEX,
            "nwd1_kat_header_crc32c": INDEPENDENT_NWD1_KAT_HEADER_CRC,
            "result": "OK_NO_PLAINTEXT",
        },
    ]
    # Drop unused runtime kat variable reference path.
    del nwd1_kat

    endpoint_vectors = [
        {
            "id": "WIFI-ENDPOINT-IPV4-SCOPE",
            "address_kind": 1,
            "address_hex": hex_of(bytes([192, 0, 2, 10]) + bytes(12)),
            "unused_tail_must_be_zero": 1,
            "port": 8443,
            "dns_authority": 0,
            "result": "OK",
        },
        {
            "id": "WIFI-ENDPOINT-IPV6-SCOPE",
            "address_kind": 2,
            "address_hex": hex_of(
                bytes.fromhex("20010db8000000000000000000000001")
            ),
            "port": 8443,
            "dns_authority": 0,
            "result": "OK",
        },
        {
            "id": "WIFI-ENDPOINT-LINK-LOCAL-SCOPE-ID",
            "address_kind": 2,
            "address_hex": hex_of(
                bytes.fromhex("fe800000000000000000000000000001")
            ),
            "scope_id_required": 1,
            "scope_id_u32": 3,
            "scope_id_zero_rejected": 1,
            "result": "OK_WITH_SCOPE_ID",
            "scope_id_zero_result": "REJECT",
        },
        {
            "id": "WIFI-ENDPOINT-DNS-MDNS-NON-AUTHORITY",
            "dns_name": "peer.local",
            "mdns_browse": 1,
            "last_known_address_authority": 0,
            "authority_endpoint_change_requires_config_revision": 1,
            "result": "AUXILIARY_ONLY",
        },
        {
            "id": "WIFI-ENDPOINT-ADDRESS-CHANGE-FENCE",
            "event": "IP_EVENT_STA_GOT_IP_CHANGE_OR_LOST",
            "session_fence": 1,
            "availability_epoch_delta": 1,
            "reuse_old_socket_forbidden": 1,
            "nwb1_publish": 0,
            "result": "FENCED",
        },
    ]

    nwb1_vectors = [
        {
            "id": "WIFI-NWB1-HEADER-40",
            "header_length": NWB1_HEADER,
            "record_hex": hex_of(nwb1_min),
            "classification": classify_nwb1_framing(
                nwb1_min, expected_session=session_id, expected_sequence=0
            ),
            "expected": "OK",
        },
        {
            "id": "WIFI-NWB1-PAYLOAD-586-REJECT",
            "payload_length": PAYLOAD_REJECT_LOW,
            "record_hex": hex_of(nwb1_payload_586),
            "classification": classify_nwb1_framing(nwb1_payload_586),
            "expected": "CORRUPT",
        },
        {
            "id": "WIFI-NWB1-PAYLOAD-587-ACCEPT",
            "payload_length": NWB1_PAYLOAD_MIN,
            "total_length": NWB1_TOTAL_MIN,
            "record_hex": hex_of(nwb1_min),
            "record_sha256_hex": hex_of(sha256(nwb1_min)),
            "classification": classify_nwb1_framing(
                nwb1_min, expected_session=session_id, expected_sequence=0
            ),
            "expected": "OK",
        },
        {
            "id": "WIFI-NWB1-PAYLOAD-1925-ACCEPT",
            "payload_length": NWB1_PAYLOAD_MAX,
            "total_length": NWB1_TOTAL_MAX,
            "record_hex": hex_of(nwb1_max),
            "record_sha256_hex": hex_of(sha256(nwb1_max)),
            "classification": classify_nwb1_framing(
                nwb1_max, expected_session=session_id, expected_sequence=0
            ),
            "expected": "OK",
        },
        {
            "id": "WIFI-NWB1-PAYLOAD-1926-REJECT",
            "payload_length": PAYLOAD_REJECT_HIGH,
            "record_hex": hex_of(nwb1_payload_1926),
            "classification": classify_nwb1_framing(nwb1_payload_1926),
            "expected": "CORRUPT",
        },
        {
            "id": "WIFI-NWB1-TOTAL-626-REJECT",
            "total_length": TOTAL_REJECT_LOW,
            "record_hex": hex_of(nwb1_total_626),
            "classification": classify_nwb1_framing(nwb1_total_626),
            "expected": "CORRUPT",
        },
        {
            "id": "WIFI-NWB1-TOTAL-627-ACCEPT",
            "total_length": NWB1_TOTAL_MIN,
            "record_hex": hex_of(nwb1_min),
            "classification": classify_nwb1_framing(nwb1_min),
            "expected": "OK",
        },
        {
            "id": "WIFI-NWB1-TOTAL-1965-ACCEPT",
            "total_length": NWB1_TOTAL_MAX,
            "record_hex": hex_of(nwb1_max),
            "classification": classify_nwb1_framing(nwb1_max),
            "expected": "OK",
        },
        {
            "id": "WIFI-NWB1-TOTAL-1966-REJECT",
            "total_length": TOTAL_REJECT_HIGH,
            "record_hex": hex_of(nwb1_total_1966),
            "classification": classify_nwb1_framing(nwb1_total_1966),
            "expected": "CORRUPT",
        },
        {
            "id": "WIFI-NWB1-CRC32C-INDEPENDENT",
            "record_hex": hex_of(nwb1_min),
            "mutated_record_hex": hex_of(nwb1_bad_crc),
            "good_classification": classify_nwb1_framing(nwb1_min),
            "bad_classification": classify_nwb1_framing(nwb1_bad_crc),
            "crc_polynomial": "0x82F63B78",
            "crc_init": "0xffffffff",
            "crc_xorout": "0xffffffff",
            "expected_good": "OK",
            "expected_bad": "CORRUPT",
        },
        {
            "id": "WIFI-NWB1-PARTIAL-HEADER",
            "bytes_available": len(partial_header),
            "need_bytes": NWB1_HEADER,
            "slice_hex": hex_of(partial_header),
            "deliverable": 0,
            "result": "WANT_READ_NO_DELIVERY",
        },
        {
            "id": "WIFI-NWB1-PARTIAL-BODY",
            "bytes_available": len(partial_body),
            "need_bytes": len(nwb1_min),
            "slice_hex": hex_of(partial_body),
            "deliverable": 0,
            "result": "WANT_READ_NO_DELIVERY",
        },
        {
            "id": "WIFI-NWB1-COALESCED-RECORDS",
            "stream_hex": hex_of(coalesced),
            "record_count": 2,
            "first_sequence": 0,
            "second_sequence": 1,
            "first_classification": classify_nwb1_framing(
                nwb1_min, expected_session=session_id, expected_sequence=0
            ),
            "second_classification": classify_nwb1_framing(
                nwb1_seq1, expected_session=session_id, expected_sequence=1
            ),
            "expected_first": "OK",
            "expected_second": "OK",
        },
        {
            "id": "WIFI-NWB1-READ-AHEAD-BOUND",
            "max_records_read_ahead": 1,
            "unlimited_read_ahead_forbidden": 1,
            "buffer_bytes": RECORD_BYTES_FIXED,
            "result": "BOUND_OK",
        },
        {
            "id": "WIFI-NWB1-WRONG-SESSION",
            "record_hex": hex_of(nwb1_wrong_session),
            "expected_session_hex": hex_of(session_id),
            "classification": classify_nwb1_framing(
                nwb1_wrong_session, expected_session=session_id
            ),
            "expected": "WRONG_SESSION",
            "connection_close": 1,
            "delivery": 0,
        },
        {
            "id": "WIFI-NWB1-SEQUENCE-0",
            "record_hex": hex_of(nwb1_min),
            "sequence": 0,
            "classification": classify_nwb1_framing(
                nwb1_min, expected_session=session_id, expected_sequence=0
            ),
            "expected": "OK",
        },
        {
            "id": "WIFI-NWB1-SEQUENCE-MAX-MINUS-ONE",
            "record_hex": hex_of(nwb1_seq_max),
            "sequence": 0xFFFFFFFE,
            "classification": classify_nwb1_framing(
                nwb1_seq_max,
                expected_session=session_id,
                expected_sequence=0xFFFFFFFE,
            ),
            "expected": "OK",
            "next_action": "CLEAN_CLOSE_THEN_FRESH_SESSION",
        },
        {
            "id": "WIFI-NWB1-SEQUENCE-UINT32-MAX-REJECT",
            "record_hex": hex_of(nwb1_seq_u32max),
            "sequence": 0xFFFFFFFF,
            "classification": classify_nwb1_framing(
                nwb1_seq_u32max, expected_session=session_id
            ),
            "expected": "SEQUENCE_REJECT",
            "emit_forbidden": 1,
        },
        {
            "id": "WIFI-NWB1-DUPLICATE",
            # After prior delivered sequence N, exact next expected is N+1.
            "prior_delivered_sequence": 1,
            "expected_sequence": 2,
            "received_sequence": 1,
            "is_duplicate_of_prior": 1,
            "record_hex": hex_of(nwb1_seq1),
            "result": "CLOSE_NO_DELIVERY",
            "delivery": 0,
            "connection_close": 1,
        },
        {
            "id": "WIFI-NWB1-GAP",
            "prior_delivered_sequence": 0,
            "expected_sequence": 1,
            "received_sequence": 2,
            "is_gap": 1,
            "record_hex": hex_of(nwb1_seq2),
            "result": "CLOSE_NO_DELIVERY",
            "delivery": 0,
            "connection_close": 1,
        },
        {
            "id": "WIFI-NWB1-OUT-OF-ORDER",
            "prior_delivered_sequence": 1,
            "expected_sequence": 2,
            "received_sequence": 1,
            "is_out_of_order": 1,
            "record_hex": hex_of(nwb1_seq1),
            "result": "CLOSE_NO_DELIVERY",
            "delivery": 0,
            "connection_close": 1,
        },
        {
            "id": "WIFI-NWB1-WRAP-REJECT",
            "last_sent_sequence": 0xFFFFFFFE,
            "wrap_to_zero_same_session_forbidden": 1,
            "next_sequence_same_session_forbidden": 0,
            "result": "CLEAN_CLOSE_FRESH_HANDSHAKE",
            "fresh_session_sequence": 0,
        },
        {
            "id": "WIFI-NWB1-INVALID-NFL1",
            "record_hex": hex_of(nwb1_invalid_nfl1),
            "classification": classify_nwb1_framing(
                nwb1_invalid_nfl1, expected_session=session_id, expected_sequence=0
            ),
            "expected": "INVALID_NFL1",
            "delivery": 0,
            "connection_close": 1,
        },
    ]

    tls_vectors = [
        {
            "id": "WIFI-TLS-SUITE-GROUP-SIGNATURE-EXACT",
            "protocol": TLS_PROTOCOL,
            "ciphersuite": TLS_SUITE,
            "ciphersuite_id": TLS_SUITE_ID,
            "group": TLS_GROUP,
            "group_id": TLS_GROUP_ID,
            "signature_scheme": TLS_SIG,
            "signature_id": TLS_SIG_ID,
            "result": "OK_EXACT",
        },
        {
            "id": "WIFI-TLS-X509-ROLE-RUNTIME-ATTACHMENT",
            "client_binding_hex": hex_of(leaf_client),
            "server_binding_hex": hex_of(leaf_server),
            "binding_length": 82,
            "client_role": 1,
            "server_role": 2,
            "shared_leaf_forbidden": 1,
            "result": "OK",
        },
        {
            "id": "WIFI-TLS-EXPORTER-PEER-CONTEXT-62",
            "label": EXPORTER_PEER_LABEL,
            "context_hex": hex_of(peer_ctx),
            "context_length": len(peer_ctx),
            "context_sha256_hex": hex_of(sha256(peer_ctx)),
            "expected_length": PEER_CONTEXT_LEN,
            "result": "OK",
        },
        {
            "id": "WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64",
            "label": EXPORTER_ATTACHED_LABEL,
            "context_hex": hex_of(attached_ctx),
            "context_length": len(attached_ctx),
            "context_sha256_hex": hex_of(sha256(attached_ctx)),
            "expected_length": ATTACHED_CONTEXT_LEN,
            "depends_on_m4_full": 1,
            "result": "OK",
        },
        {
            "id": "WIFI-TLS-AUTHORITY-ALL-ZERO-GROUP",
            "context_hex": hex_of(zero_ctx),
            "group_class": authority_group_class(bytes(16), 0, 0),
            "expected_class": "ALL_ZERO",
            "allowed_only_if_controllerless_profile_explicit": 1,
            "bound_profile_rejects_all_zero": 1,
            "result": "PROFILE_CONDITIONAL",
        },
        {
            "id": "WIFI-TLS-AUTHORITY-MIXED-REJECT",
            "context_hex": hex_of(mixed_ctx),
            "group_class": authority_group_class(authority_id, 0, 11),
            "expected_class": "MIXED",
            "session_established": 0,
            "result": "REJECT",
        },
        {
            "id": "WIFI-TLS-TICKET-0RTT-RENEGOTIATION-FENCE",
            "session_tickets": 0,
            "early_data_bytes_publish": 0,
            "renegotiation": 0,
            "post_handshake_auth": 0,
            "key_update_local_emit": 0,
            "result": "FENCED_IF_OBSERVED",
        },
        {
            "id": "WIFI-TLS-REVOCATION-CLOCK-RULES",
            "authority_clock_only": 1,
            "os_wall_clock_authority": 0,
            "snapshot_age_max_ms": 300000,
            "age_300000_ok": 1,
            "age_300001_reject": 1,
            "now_equals_valid_until_reject": 1,
            "result": "OK_RULES",
        },
        {
            "id": "WIFI-TLS-R7-OPENSSL-GENERIC-NON-AUTHORITY",
            "r7_rule": R7_GENERIC_OPENSSL_RULE,
            "satisfies_wifi_host_pin": 0,
            "may_use_system_openssl_3": 1,
            "result": "NON_AUTHORITY_FOR_WIFI_PROFILE",
        },
        {
            "id": "WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY",
            "tag": HOST_OPENSSL_TAG,
            "peeled_commit": HOST_OPENSSL_PEELED,
            "targets": ["0x01 linux-x86_64", "0x02 darwin64-arm64-cc"],
            "static_only": 1,
            "result": "HOST_WIFI_AUTHORITY",
        },
        {
            "id": "WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY",
            "esp_idf_commit": ESP_IDF_COMMIT,
            "mbedtls_commit": ESP_MBEDTLS_COMMIT,
            "esp_tls_public_api_forbidden": 1,
            "direct_mbedtls_only": 1,
            "result": "ESP_WIFI_AUTHORITY",
        },
    ]

    preattach_vectors = [
        {
            "id": "WIFI-PREATTACH-CARRIER-NOT-NWB1",
            "nwb1_as_attachment_carrier": 0,
            "m4_carrier_required": 1,
            "result": "BOUNDARY_OK",
        },
        {
            "id": "WIFI-PREATTACH-PEER-SESSION-ONLY-NO-NWB1",
            "state": "PEER_SESSION",
            "peer_session_id_nonzero": 1,
            "nwb1_send": 0,
            "nwb1_receive": 0,
            "fabric_availability": 0,
            "application_publish": 0,
            "result": "NO_NWB1",
        },
        {
            "id": "WIFI-PREATTACH-NWB1-REQUIRES-PA-FULL",
            "m4_full_durable": 1,
            "attachment_authority_match": 1,
            "active_binding_match": 1,
            "second_exporter_ok": 1,
            "state": "ATTACHED",
            "nwb1_allowed": 1,
            "m4_missing_nwb1_allowed": 0,
            "result": "OK_POST_ATTACHMENT",
        },
    ]

    resource_vectors = [
        {
            "id": "WIFI-RESOURCE-ESP-CAPACITY",
            "adapter_max": ESP_ADAPTER_MAX,
            "session_max": ESP_SESSION_MAX,
            "connect_attempt_max": ESP_CONNECT_ATTEMPT_MAX,
            "event_queue_max": ESP_EVENT_QUEUE_MAX,
            "tx_token_max": ESP_TX_TOKEN_MAX,
            "rx_record_max": ESP_RX_RECORD_MAX,
            "rx_loan_max": ESP_RX_LOAN_MAX,
            "record_bytes": RECORD_BYTES_FIXED,
            "event_queue_overflow_at": ESP_EVENT_QUEUE_MAX + 1,
            "result": "ESP_BOUNDS",
        },
        {
            "id": "WIFI-RESOURCE-HOST-CAPACITY",
            "adapter_max": HOST_ADAPTER_MAX,
            "session_max": HOST_SESSION_MAX,
            "connect_attempt_max": HOST_CONNECT_ATTEMPT_MAX,
            "tx_token_per_session": HOST_TX_TOKEN_PER_SESSION,
            "rx_record_per_session": HOST_RX_RECORD_PER_SESSION,
            "record_bytes": RECORD_BYTES_FIXED,
            "result": "HOST_BOUNDS",
        },
        {
            "id": "WIFI-RESOURCE-PRIORITY-ISOLATION",
            "queues": ["critical_control", "application_data", "management_bulk"],
            "bulk_may_starve_critical": 0,
            "result": "ISOLATED",
        },
        {
            "id": "WIFI-RESOURCE-RETAINED-TOKEN-PARTIAL-WRITE",
            "start_send_full_copy_own": 1,
            "partial_tcp_tls_write_outer_would_block": 0,
            "poll_send_internal": 1,
            "token_null_means_retain_0": 1,
            "result": "OK",
        },
        {
            "id": "WIFI-RESOURCE-RELEASE-SEMANTICS",
            "release_send_exact_count_after_terminal": 1,
            "release_before_terminal_forbidden": 1,
            "result": "OK",
        },
        {
            "id": "WIFI-RESOURCE-NO-FALSE-CUSTODY",
            "nwb1_socket_write_is_custody": 0,
            "tls_record_success_is_custody": 0,
            "peer_kernel_ack_is_custody": 0,
            "fabric_cap_custody_advertised": 0,
            "result": "NO_CUSTODY",
        },
        {
            "id": "WIFI-RESOURCE-STORAGE-ARITHMETIC",
            **storage_arithmetic,
            "result": "ARITHMETIC_OK",
        },
    ]

    role_vectors = [
        {
            "id": "WIFI-ROLE-HOST-POSIX-TCP-TLS",
            "adapter_kind": 1,
            "transport": "POSIX_TCP",
            "tls_backend": "PINNED_OPENSSL_3_5_7_STATIC",
            "network_profile_zero_required": 1,
            "credential_provider_null_required": 1,
            "wifi_driver_owner": 0,
            "result": "HOST_RESPONSIBILITY",
        },
        {
            "id": "WIFI-ROLE-ESP32S3-STA-LWIP-MBEDTLS",
            "adapter_kind": 2,
            "transport": "ESP_IDF_WIFI_STA_TCP_LWIP",
            "tls_backend": "ESP_IDF_SUPPLIED_MBEDTLS_DIRECT",
            "network_profile_nonzero_required": 1,
            "credential_provider_required": 1,
            "wifi_driver_sole_owner": 1,
            "wifi_storage_ram": 1,
            "result": "ESP_RESPONSIBILITY",
        },
    ]

    race_vectors = [
        {
            "id": "WIFI-RACE-DISCONNECT-RECONNECT",
            "order": [
                "DISCONNECT_EVENT",
                "FENCE_SESSIONS",
                "AVAILABILITY_PLUS_ONE",
                "CLOSE_SOCKETS",
                "BACKOFF_NOT_BEFORE",
                "RECONNECT_ATTEMPT",
            ],
            "reconnect_before_fence_forbidden": 1,
            "result": "DETERMINISTIC",
        },
        {
            "id": "WIFI-RACE-SLEEP-DRAIN",
            "sleep_marks_unavailable": 1,
            "availability_epoch_delta_on_sleep": 1,
            "fake_available_while_asleep": 0,
            "drain_blocks_new_send_retention": 1,
            "result": "DETERMINISTIC",
        },
        {
            "id": "WIFI-RACE-EVENT-OVERFLOW",
            "event_queue_max": ESP_EVENT_QUEUE_MAX,
            "overflow_count": ESP_EVENT_QUEUE_MAX + 1,
            "result_state": "FENCED",
            "availability": 0,
            "sockets_closed": 1,
            "result": "OVERFLOW_FENCE",
        },
        {
            "id": "WIFI-BACKOFF-DETERMINISTIC",
            "instance_id_hex": hex_of(instance_id),
            "schedule_ms": list(BACKOFF_MS),
            "cap_ms": BACKOFF_CAP_MS,
            "samples": [
                {
                    "failure_generation": gen,
                    "backoff_ms": backoff_ms(gen),
                    "jitter_ms": jitter_ms(instance_id, gen),
                    "not_before_offset_ms": backoff_ms(gen)
                    + jitter_ms(instance_id, gen),
                }
                for gen in (1, 2, 3, 6, 7)
            ],
            "entropy_forbidden": 1,
            "os_random_forbidden": 1,
            "attached_stable_reset_ms": ATTACHED_STABLE_RESET_MS,
            "result": "DETERMINISTIC",
        },
    ]

    constants = {
        "nwb1_header_bytes": NWB1_HEADER,
        "nwb1_payload_min": NWB1_PAYLOAD_MIN,
        "nwb1_payload_max": NWB1_PAYLOAD_MAX,
        "nwb1_total_min": NWB1_TOTAL_MIN,
        "nwb1_total_max": NWB1_TOTAL_MAX,
        "nwb1_payload_reject_low": PAYLOAD_REJECT_LOW,
        "nwb1_payload_reject_high": PAYLOAD_REJECT_HIGH,
        "nwb1_total_reject_low": TOTAL_REJECT_LOW,
        "nwb1_total_reject_high": TOTAL_REJECT_HIGH,
        "peer_context_bytes": PEER_CONTEXT_LEN,
        "attached_context_bytes": ATTACHED_CONTEXT_LEN,
        "keepalive_interval_ms": KEEPALIVE_INTERVAL_MS,
        "keepalive_exclusive_deadline_ms": KEEPALIVE_EXCLUSIVE_DEADLINE_MS,
        "missed_response_threshold": MISSED_RESPONSE_THRESHOLD,
        "blackhole_detect_ms": BLACKHOLE_DETECT_MS,
        "session_lifetime_ms": SESSION_LIFETIME_MS,
        "record_bytes_fixed": RECORD_BYTES_FIXED,
        "esp_tls_session_total_bytes": ESP_TLS_SESSION_TOTAL_BYTES,
        "esp_tls_session_internal_bytes": ESP_TLS_SESSION_INTERNAL_BYTES,
        "esp_tls_session_psram_bytes": ESP_TLS_SESSION_PSRAM_BYTES,
        "esp_tls_crypto_global_internal_bytes": (
            ESP_TLS_CRYPTO_GLOBAL_INTERNAL_BYTES
        ),
        "esp_tls_post_admission_internal_floor_bytes": (
            ESP_TLS_POST_ADMISSION_INTERNAL_FLOOR_BYTES
        ),
        "esp_tls_original_internal_only_requirement_bytes": (
            ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT_BYTES
        ),
        "esp_tls_execution_stack_bytes": ESP_TLS_EXECUTION_STACK_BYTES,
        "esp_tls_crypto_dma_bytes": ESP_TLS_CRYPTO_DMA_BYTES,
        "esp_tls_two_session_internal_envelope_bytes": (
            ESP_TLS_TWO_SESSION_INTERNAL_ENVELOPE_BYTES
        ),
        "esp_tls_map_remainder_observation_bytes": (
            ESP_TLS_MAP_REMAINDER_OBSERVATION_BYTES
        ),
        "esp_tls_map_observation_slack_bytes": (
            ESP_TLS_MAP_OBSERVATION_SLACK_BYTES
        ),
        "esp_tls_in_buffer_bytes": ESP_TLS_IN_BUFFER_BYTES,
        "esp_tls_out_buffer_bytes": ESP_TLS_OUT_BUFFER_BYTES,
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
        "tls_ciphersuite_id": TLS_SUITE_ID,
        "tls_group_id": TLS_GROUP_ID,
        "tls_signature_id": TLS_SIG_ID,
        "nwd1_record_bytes": NWD1_RECORD_BYTES,
        "nwd1_committed_cu_bytes": NWD1_COMMITTED_CU,
        "nwd1_staging_cu_bytes": NWD1_STAGING_CU,
        "network_namespace": NETWORK_NAMESPACE,
    }

    all_vector_groups = [
        association_vectors,
        liveness_vectors,
        network_cred_vectors,
        endpoint_vectors,
        nwb1_vectors,
        tls_vectors,
        preattach_vectors,
        resource_vectors,
        role_vectors,
        race_vectors,
    ]
    found_ids: list[str] = []
    for group in all_vector_groups:
        for row in group:
            found_ids.append(row["id"])

    if sorted(found_ids) != sorted(REQUIRED_ACCEPTANCE_IDS):
        missing = sorted(set(REQUIRED_ACCEPTANCE_IDS) - set(found_ids))
        extra = sorted(set(found_ids) - set(REQUIRED_ACCEPTANCE_IDS))
        raise AssertionError(f"acceptance ID mismatch missing={missing} extra={extra}")
    if len(found_ids) != len(set(found_ids)):
        raise AssertionError("duplicate acceptance IDs in emission")
    if len(found_ids) != len(REQUIRED_ACCEPTANCE_IDS):
        raise AssertionError("acceptance ID count mismatch")
    # Emit inventory in the closed required order (not group walk order).
    ordered_ids = list(REQUIRED_ACCEPTANCE_IDS)

    document: dict[str, Any] = {
        "schema": PINNED_SCHEMA,
        "status": PINNED_STATUS,
        "generator": PINNED_GENERATOR,
        "adr": PINNED_ADR,
        "nonclaims": [
            "SPEC_ACCEPTED",
            "implementation",
            "HIL",
            "RELEASE_SUPPORTED",
            "public_API",
            "production_support",
            "target_execution",
            "P0_closure",
            "independent_review_GO",
        ],
        "constants": constants,
        "required_acceptance_ids": ordered_ids,
        "association_authority_vectors": association_vectors,
        "liveness_vectors": liveness_vectors,
        "network_credential_rotation_vectors": network_cred_vectors,
        "endpoint_vectors": endpoint_vectors,
        "nwb1_vectors": nwb1_vectors,
        "tls_profile_vectors": tls_vectors,
        "preattachment_boundary_vectors": preattach_vectors,
        "resource_queue_vectors": resource_vectors,
        "role_responsibility_vectors": role_vectors,
        "race_backoff_vectors": race_vectors,
        "storage_arithmetic": storage_arithmetic,
        "pins": {
            "nwb1_min_record_sha256_hex": hex_of(sha256(nwb1_min)),
            "nwb1_max_record_sha256_hex": hex_of(sha256(nwb1_max)),
            "peer_context_sha256_hex": hex_of(sha256(peer_ctx)),
            "attached_context_sha256_hex": hex_of(sha256(attached_ctx)),
            "assoc_authority_tag_ascii": "NINLIL-WIFI-ASSOC-AUTHORITY-V1",
            "assoc_authority_input_a_hex": hex_of(assoc_input_a),
            "assoc_authority_a_hex": hex_of(assoc_a),
            "network_profile_digest_a_hex": hex_of(digest_a),
            "nwd1_old_complete_sha256_hex": hex_of(nwd1_complete_digest(nwd1_old)),
            "nwd1_new_complete_sha256_hex": hex_of(nwd1_complete_digest(nwd1_new)),
            "session_id_hex": hex_of(session_id),
            "instance_id_hex": hex_of(instance_id),
            "host_openssl_tag": HOST_OPENSSL_TAG,
            "host_openssl_peeled": HOST_OPENSSL_PEELED,
            "esp_idf_commit": ESP_IDF_COMMIT,
            "esp_mbedtls_commit": ESP_MBEDTLS_COMMIT,
            "nfl1_header_bytes": NFL1_HEADER,
            "nfl1_version": NFL1_VERSION,
        },
        "acceptance_id_count": len(REQUIRED_ACCEPTANCE_IDS),
        "acceptance_ids_emitted": ordered_ids,
        "source_vector_restoration": {
            "schema": PINNED_SCHEMA,
            "acceptance_id_count": len(REQUIRED_ACCEPTANCE_IDS),
            "nwb1_min_total": NWB1_TOTAL_MIN,
            "nwb1_max_total": NWB1_TOTAL_MAX,
            "duplicate_expected_sequence_rule": "prior_delivered + 1",
            "release_before_terminal_forbidden": 1,
            "commit_unknown_includes_corrupt": 1,
            "absent_row_id": "WIFI-NETCRED-FULL-ABSENT",
            "adr": PINNED_ADR,
            "generator": PINNED_GENERATOR,
            "gate_py": PINNED_GATE_PY,
            "gate_mjs": PINNED_GATE_MJS,
            "vector": PINNED_VECTOR,
            "c_test": PINNED_C_TEST,
            "tool_paths": list(PINNED_TOOL_PATHS),
            "independent_nwd1_kat_value_hex": INDEPENDENT_NWD1_KAT_VALUE_HEX,
            "independent_nwd1_kat_header_crc32c": INDEPENDENT_NWD1_KAT_HEADER_CRC,
            "independent_nwd1_kat_auth_digest_hex": INDEPENDENT_NWD1_KAT_AUTH_HEX,
            "independent_nwd1_kat_complete_digest_hex": INDEPENDENT_NWD1_KAT_COMPLETE_HEX,
            # Leaf inventories filled below after full document assembly.
            "object_path_count": 0,
            "integer_leaf_count": 0,
            "string_leaf_count": 0,
            "digest_leaf_count": 0,
            "integer_leaf_paths_sha256_hex": "00" * 32,
            "string_leaf_paths_sha256_hex": "00" * 32,
            "digest_leaf_paths_sha256_hex": "00" * 32,
        },
    }
    _fill_leaf_inventories(document)
    return document


def _iter_typed_paths(value: Any, path: str, pred) -> list[str]:
    out: list[str] = []
    if pred(value):
        out.append(path)
        return out
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            out.extend(_iter_typed_paths(item, child, pred))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(_iter_typed_paths(item, f"{path}[{index}]", pred))
    return out


def _iter_object_paths_local(value: Any, path: str = "$") -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        out.append(path)
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            out.extend(_iter_object_paths_local(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(_iter_object_paths_local(item, f"{path}[{index}]"))
    return out


def _iter_digest_paths_local(value: Any, path: str = "$") -> list[str]:
    out: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}" if path != "$" else f"$.{key}"
            if isinstance(item, str) and (
                key.endswith("digest_hex") or key.endswith("sha256_hex")
            ):
                out.append(child)
            out.extend(_iter_digest_paths_local(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            out.extend(_iter_digest_paths_local(item, f"{path}[{index}]"))
    return out


def _fill_leaf_inventories(document: dict[str, Any]) -> None:
    """Populate restoration inventory after document body is complete."""
    # Two-pass: set counts first (ints), then recompute path sets including counts,
    # then set sha hexes, then recompute string/digest sets including sha fields.
    rest = document["source_vector_restoration"]
    objects = _iter_object_paths_local(document)
    rest["object_path_count"] = len(objects)

    def int_pred(v: Any) -> bool:
        return type(v) is int

    def str_pred(v: Any) -> bool:
        return isinstance(v, str)

    # Clear sha placeholders to known length, set provisional counts
    rest["integer_leaf_paths_sha256_hex"] = "00" * 32
    rest["string_leaf_paths_sha256_hex"] = "00" * 32
    rest["digest_leaf_paths_sha256_hex"] = "00" * 32
    ints = sorted(_iter_typed_paths(document, "$", int_pred))
    rest["integer_leaf_count"] = len(ints)
    # recount after integer_leaf_count assignment (already set, same)
    ints = sorted(_iter_typed_paths(document, "$", int_pred))
    rest["integer_leaf_count"] = len(ints)
    rest["integer_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(ints) + "\n").encode("utf-8")
    ).hex()
    strs = sorted(_iter_typed_paths(document, "$", str_pred))
    rest["string_leaf_count"] = len(strs)
    # string_leaf_count is int — recompute ints after adding it
    ints = sorted(_iter_typed_paths(document, "$", int_pred))
    rest["integer_leaf_count"] = len(ints)
    rest["integer_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(ints) + "\n").encode("utf-8")
    ).hex()
    strs = sorted(_iter_typed_paths(document, "$", str_pred))
    rest["string_leaf_count"] = len(strs)
    rest["string_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(strs) + "\n").encode("utf-8")
    ).hex()
    # string sha assignment may not change string count (replaced same-length hex)
    strs = sorted(_iter_typed_paths(document, "$", str_pred))
    rest["string_leaf_count"] = len(strs)
    rest["string_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(strs) + "\n").encode("utf-8")
    ).hex()
    digs = sorted(_iter_digest_paths_local(document))
    rest["digest_leaf_count"] = len(digs)
    # digest_leaf_count is new int — refresh int inventory once more
    ints = sorted(_iter_typed_paths(document, "$", int_pred))
    rest["integer_leaf_count"] = len(ints)
    rest["integer_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(ints) + "\n").encode("utf-8")
    ).hex()
    digs = sorted(_iter_digest_paths_local(document))
    rest["digest_leaf_count"] = len(digs)
    rest["digest_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(digs) + "\n").encode("utf-8")
    ).hex()
    # Final consistency pass (all fields present).
    objects = _iter_object_paths_local(document)
    rest["object_path_count"] = len(objects)
    ints = sorted(_iter_typed_paths(document, "$", int_pred))
    strs = sorted(_iter_typed_paths(document, "$", str_pred))
    digs = sorted(_iter_digest_paths_local(document))
    rest["integer_leaf_count"] = len(ints)
    rest["string_leaf_count"] = len(strs)
    rest["digest_leaf_count"] = len(digs)
    rest["integer_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(ints) + "\n").encode("utf-8")
    ).hex()
    rest["string_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(strs) + "\n").encode("utf-8")
    ).hex()
    rest["digest_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(digs) + "\n").encode("utf-8")
    ).hex()
    # One more refresh: sha field values may change string path set content not count
    strs = sorted(_iter_typed_paths(document, "$", str_pred))
    rest["string_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(strs) + "\n").encode("utf-8")
    ).hex()
    digs = sorted(_iter_digest_paths_local(document))
    rest["digest_leaf_paths_sha256_hex"] = sha256(
        ("\n".join(digs) + "\n").encode("utf-8")
    ).hex()


def canonical_json(document: dict[str, Any]) -> bytes:
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _row_by_id(document: dict[str, Any], acceptance_id: str) -> dict[str, Any]:
    for group in (
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
    ):
        for row in document[group]:
            if row["id"] == acceptance_id:
                return row
    raise KeyError(acceptance_id)


def _pack_case(document: dict[str, Any], acceptance_id: str) -> dict[str, Any]:
    """Pack one acceptance row into C fixture fields.

    f[0..11] are signed 32-bit semantic integers. s0/s1 optional UTF-8 pins.
    b0/b1 optional byte blobs. sha optional 32-byte digest.
    Mapping is stable per ID family so C hard-coded expectations can bind.
    """
    row = _row_by_id(document, acceptance_id)
    f = [0] * 12
    s0 = ""
    s1 = ""
    b0 = b""
    b1 = b""
    sha_b = b""

    def i(key: str, default: int = 0) -> int:
        value = row.get(key, default)
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            if value > 0x7FFFFFFF:
                return value & 0xFFFFFFFF  # stored as uint bits via cast later
            return int(value)
        return default

    if acceptance_id.startswith("WIFI-ASSOC-"):
        f[0] = i("session_fence")
        f[1] = i("availability_epoch_delta")
        f[2] = i("nwb1_publish")
        f[3] = i("digests_equal", -1)
        f[4] = i("profile_revision", i("old_revision"))
        f[5] = i("new_revision")
        f[6] = i("old_channel")
        f[7] = i("new_channel")
        f[8] = i("reobserve_same_tuple")
        f[9] = i("double_count_forbidden")
        f[10] = i("physical_events_observed")
        f[11] = i("session_fence_generation")
        s0 = str(row.get("result", ""))
        if "association_authority_input_hex" in row:
            b0 = bytes.fromhex(row["association_authority_input_hex"])
            sha_b = bytes.fromhex(row["association_authority_digest_hex"])
        elif "old_association_authority_input_hex" in row:
            b0 = bytes.fromhex(row["old_association_authority_input_hex"])
            b1 = bytes.fromhex(row["new_association_authority_input_hex"])
            # digests carried as s1 concatenated hex is awkward; store old digest in sha
            sha_b = bytes.fromhex(row["old_association_authority_digest_hex"])
            # new digest appended after old in a combined buffer for C: b0=input_old,
            # b1=input_new||digest_new (input len variable). Instead pack new digest
            # into trailing of b1 by emitting separate: b0=old_input, b1=new_input,
            # and put new digest hex in s1.
            s1 = row["new_association_authority_digest_hex"]
    elif acceptance_id.startswith("WIFI-LIVENESS-"):
        f[0] = i("keepalive_interval_ms")
        f[1] = i("exclusive_deadline_ms")
        f[2] = i("timer_shares_phase_deadline", -1)
        f[3] = i("missed_response_threshold")
        f[4] = i("missed_count_at_fail")
        f[5] = i("missed_count_still_ok")
        f[6] = i("blackhole_detect_ms")
        f[7] = i("tcp_ack_alone_not_liveness")
        f[8] = i("os_tcp_keepalive_is_authority", -1)
        f[9] = i("nwb1_or_probe_response_required")
        f[10] = i("wifi_associated")
        f[11] = i("peer_probe_ok", -1)
        s0 = str(row.get("result", ""))
        s1 = str(row.get("condition", row.get("state", "")))
        if "on_liveness_fail" in row:
            block = row["on_liveness_fail"]
            f[0] = int(block["session_fence"])
            f[1] = int(block["nwb1_delivery"])
            f[2] = int(block["connection_close"])
            f[3] = int(block["availability_epoch_delta"])
            f[4] = int(block["double_add_forbidden"])
    elif acceptance_id.startswith("WIFI-NETCRED-"):
        class_map = {
            "OLD": 1,
            "NEW": 2,
            "PARTIAL": 3,
            "EXTRA": 4,
            "THIRD": 5,
            "ABSENT": 6,
            "CORRUPT": 7,
            "BOTH": 8,
        }
        cls = row.get("expected_classification", row.get("classification", ""))
        f[0] = class_map.get(str(cls), 0)
        f[1] = i("publish", -1)
        f[2] = i("requires_fresh_association")
        f[3] = i("current_revision")
        f[4] = i("observed_revision")
        f[5] = i("revision")
        f[6] = i("digests_equal", -1)
        f[7] = i("silent_fallback_forbidden")
        f[8] = i("publish_before_reclassify", -1)
        f[9] = len(row.get("old_rows", []) or [])
        f[10] = len(row.get("new_rows", []) or [])
        f[11] = len(row.get("observed_rows", []) or [])
        s0 = str(row.get("result", row.get("expected_classification", "")))
        if "CORRUPT" in (row.get("classifications_allowed_on_reopen") or []):
            f[6] = 1  # reopen set includes CORRUPT
        if acceptance_id == "WIFI-NETCRED-DUPLICATE-KEY":
            f[0] = 7
            f[5] = 1 if row.get("duplicate_old_key_classification") == "CORRUPT" else 0
        if "observed_value_hex" in row:
            b0 = bytes.fromhex(row["observed_value_hex"])
        if "canonical_value_hex" in row:
            b0 = bytes.fromhex(row["canonical_value_hex"])
            b1 = bytes.fromhex(row["conflicting_value_hex"])
        if "old_value_hex" in row:
            b0 = bytes.fromhex(row["old_value_hex"])
            b1 = bytes.fromhex(row["new_value_hex"])
        if "secret_ref_digest_hex" in row:
            sha_b = bytes.fromhex(row["secret_ref_digest_hex"])
        # Prefer observed/old row value bytes for framing validation in C.
        if not b0 and row.get("observed_rows"):
            b0 = bytes.fromhex(row["observed_rows"][0]["value_hex"])
        if not b0 and row.get("old_rows"):
            b0 = bytes.fromhex(row["old_rows"][0]["value_hex"])
        if not b1 and row.get("new_rows"):
            b1 = bytes.fromhex(row["new_rows"][0]["value_hex"])
    elif acceptance_id.startswith("WIFI-ENDPOINT-"):
        f[0] = i("address_kind")
        f[1] = i("port")
        f[2] = i("dns_authority", -1)
        f[3] = i("unused_tail_must_be_zero")
        f[4] = i("scope_id_required")
        f[5] = i("scope_id_zero_rejected")
        f[6] = i("scope_id_u32")
        f[7] = i("session_fence")
        f[8] = i("availability_epoch_delta")
        f[9] = i("reuse_old_socket_forbidden")
        f[10] = i("nwb1_publish", -1)
        f[11] = i("mdns_browse")
        s0 = str(row.get("result", ""))
        if "address_hex" in row:
            b0 = bytes.fromhex(row["address_hex"])
    elif acceptance_id.startswith("WIFI-NWB1-"):
        f[0] = i("payload_length", i("header_length", i("total_length")))
        f[1] = i("total_length")
        f[2] = i("sequence", i("expected_sequence", -1))
        f[3] = i("prior_delivered_sequence", -1)
        f[4] = i("received_sequence", -1)
        f[5] = i("expected_sequence", -1)
        f[6] = i("deliverable", -1)
        f[7] = i("bytes_available")
        f[8] = i("need_bytes")
        f[9] = i("max_records_read_ahead", i("record_count", -1))
        f[10] = i("delivery", -1)
        f[11] = i("connection_close", i("emit_forbidden", i("is_duplicate_of_prior", i("is_gap", i("is_out_of_order", i("wrap_to_zero_same_session_forbidden", -1))))))
        s0 = str(row.get("result", row.get("expected", row.get("classification", ""))))
        if "record_hex" in row:
            b0 = bytes.fromhex(row["record_hex"])
        if "mutated_record_hex" in row:
            b1 = bytes.fromhex(row["mutated_record_hex"])
        if "stream_hex" in row:
            b0 = bytes.fromhex(row["stream_hex"])
            f[9] = i("record_count")
            f[2] = i("first_sequence")
            f[5] = i("second_sequence")
        if "slice_hex" in row:
            b0 = bytes.fromhex(row["slice_hex"])
        if "record_sha256_hex" in row:
            sha_b = bytes.fromhex(row["record_sha256_hex"])
        if acceptance_id == "WIFI-NWB1-READ-AHEAD-BOUND":
            f[0] = i("max_records_read_ahead")
            f[1] = i("buffer_bytes")
            f[2] = i("unlimited_read_ahead_forbidden")
        if acceptance_id == "WIFI-NWB1-WRAP-REJECT":
            f[2] = i("last_sent_sequence")
            f[5] = i("fresh_session_sequence")
            f[11] = i("wrap_to_zero_same_session_forbidden")
        if acceptance_id == "WIFI-NWB1-CRC32C-INDEPENDENT":
            s0 = "OK"
            s1 = "CORRUPT"
    elif acceptance_id.startswith("WIFI-TLS-"):
        f[0] = i("ciphersuite_id")
        f[1] = i("group_id")
        f[2] = i("signature_id")
        f[3] = i("binding_length", i("context_length", i("expected_length")))
        f[4] = i("client_role")
        f[5] = i("server_role")
        f[6] = i("shared_leaf_forbidden", i("depends_on_m4_full", i("session_tickets", -1)))
        f[7] = i("early_data_bytes_publish", i("session_established", -1))
        f[8] = i("renegotiation", i("authority_clock_only", -1))
        f[9] = i("post_handshake_auth", i("os_wall_clock_authority", -1))
        f[10] = i("key_update_local_emit", i("snapshot_age_max_ms", i("satisfies_wifi_host_pin", -1)))
        f[11] = i("static_only", i("esp_tls_public_api_forbidden", i("direct_mbedtls_only", i("age_300001_reject", -1))))
        s0 = str(row.get("result", ""))
        s1 = str(
            row.get(
                "tag",
                row.get(
                    "group_class",
                    row.get("label", row.get("peeled_commit", row.get("esp_idf_commit", ""))),
                ),
            )
        )
        if "context_hex" in row:
            b0 = bytes.fromhex(row["context_hex"])
            if "context_sha256_hex" in row:
                sha_b = bytes.fromhex(row["context_sha256_hex"])
        if "client_binding_hex" in row:
            b0 = bytes.fromhex(row["client_binding_hex"])
            b1 = bytes.fromhex(row["server_binding_hex"])
        if acceptance_id == "WIFI-TLS-HOST-OPENSSL-PIN-AUTHORITY":
            s0 = row["tag"]
            s1 = row["peeled_commit"]
            f[11] = i("static_only")
        if acceptance_id == "WIFI-TLS-ESP-MBEDTLS-PIN-AUTHORITY":
            s0 = row["esp_idf_commit"]
            s1 = row["mbedtls_commit"]
            f[10] = i("esp_tls_public_api_forbidden")
            f[11] = i("direct_mbedtls_only")
        if acceptance_id == "WIFI-TLS-R7-OPENSSL-GENERIC-NON-AUTHORITY":
            f[10] = i("satisfies_wifi_host_pin")
            f[11] = i("may_use_system_openssl_3")
    elif acceptance_id.startswith("WIFI-PREATTACH-"):
        f[0] = i("nwb1_as_attachment_carrier", i("nwb1_send", i("nwb1_allowed", -1)))
        f[1] = i("m4_carrier_required", i("nwb1_receive", i("m4_full_durable", -1)))
        f[2] = i("peer_session_id_nonzero", i("attachment_authority_match", -1))
        f[3] = i("fabric_availability", i("active_binding_match", -1))
        f[4] = i("application_publish", i("second_exporter_ok", -1))
        f[5] = i("m4_missing_nwb1_allowed", -1)
        s0 = str(row.get("result", ""))
        s1 = str(row.get("state", ""))
    elif acceptance_id.startswith("WIFI-RESOURCE-"):
        f[0] = i("adapter_max", i("start_send_full_copy_own", i("nwb1_socket_write_is_custody", i("nwd1_record_bytes", -1))))
        f[1] = i("session_max", i("partial_tcp_tls_write_outer_would_block", i("tls_record_success_is_custody", i("nwd1_keys_max", -1))))
        f[2] = i("connect_attempt_max", i("poll_send_internal", i("peer_kernel_ack_is_custody", i("committed_cu_bytes", -1))))
        f[3] = i("event_queue_max", i("token_null_means_retain_0", i("fabric_cap_custody_advertised", i("staging_cu_bytes", -1))))
        f[4] = i("event_queue_overflow_at", i("release_send_exact_count_after_terminal", i("plaintext_password_in_storage", -1)))
        f[5] = i("tx_token_max", i("release_before_terminal_forbidden", i("plaintext_password_in_vectors", -1)))
        f[6] = i("rx_record_max", i("secret_ref_digest_only", i("tx_token_per_session", -1)))
        f[7] = i("rx_loan_max", i("rx_record_per_session", -1))
        f[8] = i("record_bytes", i("bulk_may_starve_critical", -1))
        f[9] = i("esp_nwd1_active_profiles_max", -1)
        f[10] = i("host_nwd1_active_profiles_max", -1)
        f[11] = len(row.get("queues", []) or [])
        s0 = str(row.get("result", ""))
        if acceptance_id == "WIFI-RESOURCE-PRIORITY-ISOLATION":
            s1 = ",".join(row.get("queues", []))
        if acceptance_id == "WIFI-RESOURCE-STORAGE-ARITHMETIC":
            f[0] = i("nwd1_record_bytes")
            f[1] = i("nwd1_keys_max")
            f[2] = i("committed_cu_bytes")
            f[3] = i("staging_cu_bytes")
            f[4] = i("plaintext_password_in_storage")
            f[5] = i("plaintext_password_in_vectors")
            f[6] = i("secret_ref_digest_only")
            f[9] = i("esp_nwd1_active_profiles_max")
            f[10] = i("host_nwd1_active_profiles_max")
        if acceptance_id == "WIFI-RESOURCE-RELEASE-SEMANTICS":
            f[4] = i("release_send_exact_count_after_terminal")
            f[5] = i("release_before_terminal_forbidden")
        if acceptance_id == "WIFI-RESOURCE-HOST-CAPACITY":
            f[0] = i("adapter_max")
            f[1] = i("session_max")
            f[2] = i("connect_attempt_max")
            f[6] = i("tx_token_per_session")
            f[7] = i("rx_record_per_session")
            f[8] = i("record_bytes")
    elif acceptance_id.startswith("WIFI-ROLE-"):
        f[0] = i("adapter_kind")
        f[1] = i("network_profile_zero_required", i("network_profile_nonzero_required"))
        f[2] = i("credential_provider_null_required", i("credential_provider_required"))
        f[3] = i("wifi_driver_owner", i("wifi_driver_sole_owner"))
        f[4] = i("wifi_storage_ram")
        s0 = str(row.get("result", ""))
        s1 = str(row.get("tls_backend", ""))
    elif acceptance_id.startswith("WIFI-RACE-") or acceptance_id == "WIFI-BACKOFF-DETERMINISTIC":
        f[0] = i("reconnect_before_fence_forbidden", i("sleep_marks_unavailable", i("event_queue_max", i("entropy_forbidden", -1))))
        f[1] = i("availability_epoch_delta_on_sleep", i("overflow_count", i("os_random_forbidden", -1)))
        f[2] = i("fake_available_while_asleep", i("availability", i("cap_ms", -1)))
        f[3] = i("drain_blocks_new_send_retention", i("sockets_closed", i("attached_stable_reset_ms", -1)))
        f[4] = i("event_queue_max")
        f[5] = len(row.get("order", []) or [])
        f[6] = len(row.get("samples", []) or [])
        f[7] = i("cap_ms")
        s0 = str(row.get("result", row.get("result_state", "")))
        if "order" in row:
            s1 = ">".join(row["order"])
        if acceptance_id == "WIFI-BACKOFF-DETERMINISTIC":
            s1 = row["instance_id_hex"]
            b0 = bytes.fromhex(row["instance_id_hex"])
            # pack first sample backoff/jitter into f8/f9 and gen into f10
            sample0 = row["samples"][0]
            f[8] = int(sample0["backoff_ms"])
            f[9] = int(sample0["jitter_ms"])
            f[10] = int(sample0["failure_generation"])
            f[11] = int(sample0["not_before_offset_ms"])
        if acceptance_id == "WIFI-RACE-EVENT-OVERFLOW":
            f[0] = i("event_queue_max")
            f[1] = i("overflow_count")
            f[2] = i("availability")
            f[3] = i("sockets_closed")
            s0 = str(row.get("result", ""))
            s1 = str(row.get("result_state", ""))
    else:
        raise AssertionError(f"unpacked id {acceptance_id}")

    return {
        "id": acceptance_id,
        "f": f,
        "s0": s0,
        "s1": s1,
        "b0": b0,
        "b1": b1,
        "sha": sha_b,
    }


def emit_c_fixture(document: dict[str, Any], output: Path) -> None:
    pins = document["pins"]
    constants = document["constants"]
    ids = document["required_acceptance_ids"]
    packs = [_pack_case(document, acceptance_id) for acceptance_id in ids]

    def c_bytes_array(name: str, value: bytes) -> str:
        if not value:
            return f"/* empty {name} */\n"
        body = ", ".join(f"0x{byte:02x}" for byte in value)
        return f"static const uint8_t {name}[{len(value)}] = {{ {body} }};\n"

    lines: list[str] = [
        "/* Generated by tools/wifi_bearer_spec_vector_gen.py — do not edit. */",
        "#ifndef NINLIL_WIFI_BEARER_SPEC_FIXTURE_H",
        "#define NINLIL_WIFI_BEARER_SPEC_FIXTURE_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"#define NINLIL_WIFI_ACCEPTANCE_ID_COUNT {len(ids)}u",
        f"#define NINLIL_WIFI_NWB1_HEADER {constants['nwb1_header_bytes']}u",
        f"#define NINLIL_WIFI_NWB1_PAYLOAD_MIN {constants['nwb1_payload_min']}u",
        f"#define NINLIL_WIFI_NWB1_PAYLOAD_MAX {constants['nwb1_payload_max']}u",
        f"#define NINLIL_WIFI_NWB1_TOTAL_MIN {constants['nwb1_total_min']}u",
        f"#define NINLIL_WIFI_NWB1_TOTAL_MAX {constants['nwb1_total_max']}u",
        f"#define NINLIL_WIFI_PEER_CONTEXT_LEN {constants['peer_context_bytes']}u",
        f"#define NINLIL_WIFI_ATTACHED_CONTEXT_LEN {constants['attached_context_bytes']}u",
        f"#define NINLIL_WIFI_NWD1_COMMITTED_CU {constants['nwd1_committed_cu_bytes']}u",
        f"#define NINLIL_WIFI_NWD1_STAGING_CU {constants['nwd1_staging_cu_bytes']}u",
        f"#define NINLIL_WIFI_BLACKHOLE_MS {constants['blackhole_detect_ms']}u",
        f"#define NINLIL_WIFI_KEEPALIVE_MS {constants['keepalive_interval_ms']}u",
        f"#define NINLIL_WIFI_MISSED_THRESHOLD {constants['missed_response_threshold']}u",
        f"#define NINLIL_WIFI_NWD1_RECORD_BYTES {constants['nwd1_record_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_SESSION_TOTAL "
        f"{constants['esp_tls_session_total_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL "
        f"{constants['esp_tls_session_internal_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_SESSION_PSRAM "
        f"{constants['esp_tls_session_psram_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_INTERNAL "
        f"{constants['esp_tls_crypto_global_internal_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_INTERNAL_FLOOR "
        f"{constants['esp_tls_post_admission_internal_floor_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_ORIGINAL_INTERNAL_ONLY_REQUIREMENT "
        f"{constants['esp_tls_original_internal_only_requirement_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_EXECUTION_STACK "
        f"{constants['esp_tls_execution_stack_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_INTERNAL_ENVELOPE "
        f"{constants['esp_tls_two_session_internal_envelope_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_MAP_REMAINDER_OBS "
        f"{constants['esp_tls_map_remainder_observation_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_MAP_SLACK_OBS "
        f"{constants['esp_tls_map_observation_slack_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_IN_BUFFER "
        f"{constants['esp_tls_in_buffer_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_OUT_BUFFER "
        f"{constants['esp_tls_out_buffer_bytes']}u",
        f"#define NINLIL_WIFI_ESP_TLS_EXACT_LIVE_REQUIRED "
        f"{constants['esp_tls_psram_exact_live_allocation_required']}u",
        f"#define NINLIL_WIFI_ESP_TLS_INTERIOR_POINTER_ALLOWED "
        f"{constants['esp_tls_psram_interior_pointer_allowed']}u",
        f"#define NINLIL_WIFI_ESP_TLS_FREE_POINTER_ALLOWED "
        f"{constants['esp_tls_psram_free_pointer_allowed']}u",
        f"#define NINLIL_WIFI_ESP_TLS_WRONG_SIZE_ALLOWED "
        f"{constants['esp_tls_psram_wrong_size_allowed']}u",
        f"#define NINLIL_WIFI_ESP_TLS_CROSS_OWNER_FREE_ALLOWED "
        f"{constants['esp_tls_cross_owner_free_allowed']}u",
        f"#define NINLIL_WIFI_ESP_TLS_CONTRACT_NULL_SPILL_ALLOWED "
        f"{constants['esp_tls_contract_null_spill_allowed']}u",
        f"#define NINLIL_WIFI_ESP_TLS_ORDINARY_OOM_GLOBAL_FATAL "
        f"{constants['esp_tls_ordinary_oom_is_global_fatal']}u",
        f"#define NINLIL_WIFI_ESP_TLS_CANARY_GLOBAL_FATAL "
        f"{constants['esp_tls_canary_corruption_is_global_fatal']}u",
        f"#define NINLIL_WIFI_TLS_SUITE_ID 0x{TLS_SUITE_ID:04x}u",
        f"#define NINLIL_WIFI_TLS_GROUP_ID 0x{TLS_GROUP_ID:04x}u",
        f"#define NINLIL_WIFI_TLS_SIG_ID 0x{TLS_SIG_ID:04x}u",
        f'#define NINLIL_WIFI_HOST_OPENSSL_TAG "{HOST_OPENSSL_TAG}"',
        f'#define NINLIL_WIFI_HOST_OPENSSL_PEELED "{HOST_OPENSSL_PEELED}"',
        f'#define NINLIL_WIFI_ESP_IDF_COMMIT "{ESP_IDF_COMMIT}"',
        f'#define NINLIL_WIFI_ESP_MBEDTLS_COMMIT "{ESP_MBEDTLS_COMMIT}"',
        f'#define NINLIL_WIFI_ASSOC_TAG "NINLIL-WIFI-ASSOC-AUTHORITY-V1"',
        f"#define NINLIL_WIFI_NFL1_HEADER {NFL1_HEADER}u",
        f"#define NINLIL_WIFI_NFL1_VERSION {NFL1_VERSION}u",
        f"#define NINLIL_WIFI_NWD1_KAT_HEADER_CRC "
        f"0x{INDEPENDENT_NWD1_KAT_HEADER_CRC:08x}u",
        f"#define NINLIL_WIFI_OBJECT_PATH_COUNT "
        f"{document['source_vector_restoration']['object_path_count']}u",
        f"#define NINLIL_WIFI_INTEGER_LEAF_COUNT "
        f"{document['source_vector_restoration']['integer_leaf_count']}u",
        f"#define NINLIL_WIFI_STRING_LEAF_COUNT "
        f"{document['source_vector_restoration']['string_leaf_count']}u",
        f"#define NINLIL_WIFI_DIGEST_LEAF_COUNT "
        f"{document['source_vector_restoration']['digest_leaf_count']}u",
        f'#define NINLIL_WIFI_VECTOR_DOCUMENT_SHA256 '
        f'"{hashlib.sha256(canonical_json(document)).hexdigest()}"',
        "",
        "typedef struct ninlil_wifi_case_row {",
        "    const char *id;",
        "    int32_t f[12];",
        "    const char *s0;",
        "    const char *s1;",
        "    const uint8_t *b0;",
        "    size_t b0_len;",
        "    const uint8_t *b1;",
        "    size_t b1_len;",
        "    const uint8_t *sha;",
        "    size_t sha_len;",
        "} ninlil_wifi_case_row_t;",
        "",
        "static const char *const ninlil_wifi_acceptance_ids["
        "NINLIL_WIFI_ACCEPTANCE_ID_COUNT] = {",
    ]
    for acceptance_id in ids:
        lines.append(f'    "{acceptance_id}",')
    lines.append("};")
    lines.append("")

    # Emit per-case blobs
    for index, pack in enumerate(packs):
        if pack["b0"]:
            lines.append(c_bytes_array(f"ninlil_wifi_case_{index}_b0", pack["b0"]))
        if pack["b1"]:
            lines.append(c_bytes_array(f"ninlil_wifi_case_{index}_b1", pack["b1"]))
        if pack["sha"]:
            lines.append(c_bytes_array(f"ninlil_wifi_case_{index}_sha", pack["sha"]))

    # Global pins still exposed for direct tests
    peer = _row_by_id(document, "WIFI-TLS-EXPORTER-PEER-CONTEXT-62")
    attached = _row_by_id(document, "WIFI-TLS-EXPORTER-ATTACHED-CONTEXT-64")
    nwb1_min = _row_by_id(document, "WIFI-NWB1-PAYLOAD-587-ACCEPT")
    lines.append(c_bytes_array("ninlil_wifi_nwb1_min", bytes.fromhex(nwb1_min["record_hex"])))
    lines.append(
        c_bytes_array(
            "ninlil_wifi_nwb1_min_sha256",
            bytes.fromhex(pins["nwb1_min_record_sha256_hex"]),
        )
    )
    lines.append(c_bytes_array("ninlil_wifi_peer_context", bytes.fromhex(peer["context_hex"])))
    lines.append(
        c_bytes_array(
            "ninlil_wifi_peer_context_sha256",
            bytes.fromhex(pins["peer_context_sha256_hex"]),
        )
    )
    lines.append(
        c_bytes_array(
            "ninlil_wifi_attached_context",
            bytes.fromhex(attached["context_hex"]),
        )
    )
    lines.append(
        c_bytes_array(
            "ninlil_wifi_attached_context_sha256",
            bytes.fromhex(pins["attached_context_sha256_hex"]),
        )
    )
    lines.append(
        c_bytes_array("ninlil_wifi_session_id", bytes.fromhex(pins["session_id_hex"]))
    )
    lines.append(
        c_bytes_array("ninlil_wifi_instance_id", bytes.fromhex(pins["instance_id_hex"]))
    )
    # Independent NWD1 KAT literals (not lab encode_nwd1 defaults).
    lines.append(
        c_bytes_array(
            "ninlil_wifi_nwd1_kat_value",
            bytes.fromhex(INDEPENDENT_NWD1_KAT_VALUE_HEX),
        )
    )
    lines.append(
        c_bytes_array(
            "ninlil_wifi_nwd1_kat_auth",
            bytes.fromhex(INDEPENDENT_NWD1_KAT_AUTH_HEX),
        )
    )
    lines.append(
        c_bytes_array(
            "ninlil_wifi_nwd1_kat_complete",
            bytes.fromhex(INDEPENDENT_NWD1_KAT_COMPLETE_HEX),
        )
    )
    lines.append("")

    lines.append(
        "static const ninlil_wifi_case_row_t ninlil_wifi_cases["
        "NINLIL_WIFI_ACCEPTANCE_ID_COUNT] = {"
    )
    for index, pack in enumerate(packs):
        fvals = ", ".join(str(int(v) if v <= 0x7FFFFFFF else (v - 0x100000000)) for v in pack["f"])
        # For large uint32 sequence values store as uint32 bit pattern via cast in C:
        # use unsigned literals for f[] by emitting as int32_t from two's complement.
        f_emit = []
        for v in pack["f"]:
            if isinstance(v, int) and v > 0x7FFFFFFF:
                # reinterpret as int32
                f_emit.append(str(struct.unpack(">i", struct.pack(">I", v & 0xFFFFFFFF))[0]))
            else:
                f_emit.append(str(int(v)))
        fvals = ", ".join(f_emit)
        b0_ptr = f"ninlil_wifi_case_{index}_b0" if pack["b0"] else "NULL"
        b1_ptr = f"ninlil_wifi_case_{index}_b1" if pack["b1"] else "NULL"
        sha_ptr = f"ninlil_wifi_case_{index}_sha" if pack["sha"] else "NULL"
        s0 = pack["s0"].replace("\\", "\\\\").replace('"', '\\"')
        s1 = pack["s1"].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(
            "    { "
            f'"{pack["id"]}", '
            f"{{ {fvals} }}, "
            f'"{s0}", "{s1}", '
            f"{b0_ptr}, {len(pack['b0'])}u, "
            f"{b1_ptr}, {len(pack['b1'])}u, "
            f"{sha_ptr}, {len(pack['sha'])}u "
            "},"
        )
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_WIFI_BEARER_SPEC_FIXTURE_H */")
    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")


def run_self_test() -> None:
    baseline = build_document()
    rendered = canonical_json(baseline)
    altered = build_document()
    altered["constants"]["nwb1_payload_min"] += 1
    if canonical_json(altered) == rendered:
        raise AssertionError("self-test: mutation not observed")
    row = next(
        item
        for item in baseline["nwb1_vectors"]
        if item["id"] == "WIFI-NWB1-CRC32C-INDEPENDENT"
    )
    good = bytes.fromhex(row["record_hex"])
    bad = bytes.fromhex(row["mutated_record_hex"])
    if classify_nwb1_framing(good) != "OK":
        raise AssertionError("self-test: good NWB1")
    if classify_nwb1_framing(bad) != "CORRUPT":
        raise AssertionError("self-test: bad CRC survived")
    repaired = bytearray(bad)
    repaired[36:40] = bytes(4)
    repaired[36:40] = u32(crc32c(bytes(repaired)))
    if classify_nwb1_framing(bytes(repaired)) != "OK":
        raise AssertionError("self-test: CRC repair failed")
    if sha256(bytes(repaired)).hex() != sha256(good).hex():
        raise AssertionError("self-test: restoration hash mismatch")
    if baseline["required_acceptance_ids"] != list(REQUIRED_ACCEPTANCE_IDS):
        raise AssertionError("self-test: required order")
    if baseline["acceptance_ids_emitted"] != list(REQUIRED_ACCEPTANCE_IDS):
        raise AssertionError("self-test: emitted order")
    # Independent association tag KAT (hard domain, not vector-learned).
    base_assoc = next(
        r
        for r in baseline["association_authority_vectors"]
        if r["id"] == "WIFI-ASSOC-AUTHORITY-EPOCH-BASELINE"
    )
    ain = bytes.fromhex(base_assoc["association_authority_input_hex"])
    if association_authority_digest_from_input(ain).hex() != base_assoc[
        "association_authority_digest_hex"
    ]:
        raise AssertionError("self-test: assoc digest tag domain")
    if sha256(b"NINLIL-WIFI-ASSOC-AUTHORITY-X1" + ain).hex() == base_assoc[
        "association_authority_digest_hex"
    ]:
        raise AssertionError("self-test: wrong assoc tag must not match")
    # Bind parse of input to emitted row fields (not opaque).
    bound = parse_association_authority_input(ain)
    if bound["channel"] != base_assoc["channel"]:
        raise AssertionError("self-test: channel bind")
    if hex_of(bound["bssid"]) != base_assoc["bssid_hex"]:
        raise AssertionError("self-test: bssid bind")
    if bound["association_epoch"] != base_assoc["association_epoch"]:
        raise AssertionError("self-test: association_epoch bind")
    if hex_of(bound["profile_id"]) != base_assoc["profile_id_hex"]:
        raise AssertionError("self-test: profile_id bind")
    # Mutating input without changing row fields must desync.
    mutated_in = bytearray(ain)
    mutated_in[0] ^= 0x01
    mut_bound = parse_association_authority_input(bytes(mutated_in))
    if hex_of(mut_bound["profile_id"]) == base_assoc["profile_id_hex"]:
        raise AssertionError("self-test: input mutant must change profile_id parse")
    # Independent NWD1 KAT must match hard-coded constants (not runtime SSID).
    secret_row = next(
        r
        for r in baseline["network_credential_rotation_vectors"]
        if r["id"] == "WIFI-NETCRED-NO-PLAINTEXT-SECRET"
    )
    if secret_row["nwd1_kat_value_hex"] != INDEPENDENT_NWD1_KAT_VALUE_HEX:
        raise AssertionError("self-test: independent NWD1 KAT value drift")
    if secret_row["nwd1_kat_header_crc32c"] != INDEPENDENT_NWD1_KAT_HEADER_CRC:
        raise AssertionError("self-test: independent NWD1 KAT crc drift")
    if secret_row["nwd1_kat_auth_digest_hex"] != INDEPENDENT_NWD1_KAT_AUTH_HEX:
        raise AssertionError("self-test: independent NWD1 KAT auth drift")
    if secret_row["nwd1_kat_complete_digest_hex"] != INDEPENDENT_NWD1_KAT_COMPLETE_HEX:
        raise AssertionError("self-test: independent NWD1 KAT complete drift")
    kat_val = bytes.fromhex(INDEPENDENT_NWD1_KAT_VALUE_HEX)
    if nwd1_header_crc32c(kat_val) != INDEPENDENT_NWD1_KAT_HEADER_CRC:
        raise AssertionError("self-test: KAT header crc recompute")
    if nwd1_auth_digest(kat_val).hex() != INDEPENDENT_NWD1_KAT_AUTH_HEX:
        raise AssertionError("self-test: KAT auth recompute")
    if nwd1_complete_digest(kat_val).hex() != INDEPENDENT_NWD1_KAT_COMPLETE_HEX:
        raise AssertionError("self-test: KAT complete recompute")
    # Runtime old_value integrity still recomputed.
    nwd_val = bytes.fromhex(secret_row["old_value_hex"])
    if nwd1_header_crc32c(nwd_val) != secret_row["old_header_crc32c"]:
        raise AssertionError("self-test: nwd1 header crc")
    if nwd1_auth_digest(nwd_val).hex() != secret_row["old_auth_digest_hex"]:
        raise AssertionError("self-test: nwd1 auth")
    if nwd1_complete_digest(nwd_val).hex() != secret_row["old_complete_digest_hex"]:
        raise AssertionError("self-test: nwd1 complete")
    # Coherent secret_ref swap must change digests.
    swapped = bytearray(nwd_val)
    swapped[128:160] = sha256(b"coherent-secret-ref-swap")
    if nwd1_complete_digest(bytes(swapped)).hex() == secret_row[
        "old_complete_digest_hex"
    ]:
        raise AssertionError("self-test: secret_ref swap must change complete digest")
    # BSSID change row: every old_/new_ field binds to its canonical input.
    bssid_row = next(
        r
        for r in baseline["association_authority_vectors"]
        if r["id"] == "WIFI-ASSOC-SAME-SSID-BSSID-CHANGE-FENCE"
    )
    for prefix, input_key in (
        ("old_", "old_association_authority_input_hex"),
        ("new_", "new_association_authority_input_hex"),
    ):
        parsed = parse_association_authority_input(
            bytes.fromhex(bssid_row[input_key])
        )
        if hex_of(parsed["bssid"]) != bssid_row[f"{prefix}bssid_hex"]:
            raise AssertionError(f"self-test: {prefix}bssid bind")
        if parsed["channel"] != bssid_row[f"{prefix}channel"]:
            raise AssertionError(f"self-test: {prefix}channel bind")
        if parsed["auth_mode"] != bssid_row[f"{prefix}auth_mode"]:
            raise AssertionError(f"self-test: {prefix}auth bind")
        if hex_of(parsed["profile_id"]) != bssid_row[f"{prefix}profile_id_hex"]:
            raise AssertionError(f"self-test: {prefix}profile_id bind")
        if parsed["association_epoch"] != bssid_row[f"{prefix}association_epoch"]:
            raise AssertionError(f"self-test: {prefix}epoch bind")
        if hex_of(parsed["profile_digest"]) != bssid_row[f"{prefix}profile_digest_hex"]:
            raise AssertionError(f"self-test: {prefix}digest bind")
        if hex_of(parsed["binding_id"]) != bssid_row[f"{prefix}binding_id_hex"]:
            raise AssertionError(f"self-test: {prefix}binding bind")
    # Mutating only old_bssid_hex without input must be detectable by bind checks.
    if bssid_row["old_bssid_hex"] == bssid_row["new_bssid_hex"]:
        raise AssertionError("self-test: bssid old!=new")
    desync = dict(bssid_row)
    desync["old_bssid_hex"] = desync["new_bssid_hex"]
    desync_parsed = parse_association_authority_input(
        bytes.fromhex(desync["old_association_authority_input_hex"])
    )
    if hex_of(desync_parsed["bssid"]) == desync["old_bssid_hex"]:
        raise AssertionError(
            "self-test: old_bssid donor-style desync must fail bind"
        )
    # Independent KAT length/constants must be fixed 160B (not generator-self).
    if len(bytes.fromhex(INDEPENDENT_NWD1_KAT_VALUE_HEX)) != NWD1_RECORD_BYTES:
        raise AssertionError("self-test: independent KAT length")
    if b"ninlil-lab-ssid" in bytes.fromhex(INDEPENDENT_NWD1_KAT_VALUE_HEX):
        raise AssertionError("self-test: KAT must not use lab SSID")
    if b"KAT-NWD1-FIXED" not in bytes.fromhex(INDEPENDENT_NWD1_KAT_VALUE_HEX):
        raise AssertionError("self-test: KAT fixed SSID pin")
    # Source metadata hardpins and path existence.
    rest = baseline["source_vector_restoration"]
    if rest["adr"] != PINNED_ADR or rest["generator"] != PINNED_GENERATOR:
        raise AssertionError("self-test: metadata adr/generator drift")
    if rest["tool_paths"] != list(PINNED_TOOL_PATHS):
        raise AssertionError("self-test: tool_paths drift")
    for rel in PINNED_TOOL_PATHS:
        if not (ROOT / rel).is_file():
            raise AssertionError(f"self-test: missing pinned path {rel}")
    if rest["independent_nwd1_kat_value_hex"] != INDEPENDENT_NWD1_KAT_VALUE_HEX:
        raise AssertionError("self-test: restoration KAT value drift")
    # Exhaustive closed-schema + bool-as-int surface (parity with independent gate).
    # Load gate as module only for self-test; production generator does not import it.
    import importlib.util

    gate_path = ROOT / "tools" / "wifi_bearer_spec_gate.py"
    gate_spec = importlib.util.spec_from_file_location(
        "wifi_bearer_spec_gate_selftest", gate_path
    )
    if gate_spec is None or gate_spec.loader is None:
        raise AssertionError("self-test: cannot load gate module")
    gate_mod = importlib.util.module_from_spec(gate_spec)
    gate_spec.loader.exec_module(gate_mod)
    object_paths = gate_mod.iter_object_paths(baseline)
    int_leaves = gate_mod.iter_integer_leaf_paths(baseline)
    if len(object_paths) < 100 or len(int_leaves) < 300:
        raise AssertionError(
            f"self-test: path inventory regression "
            f"objects={len(object_paths)} ints={len(int_leaves)}"
        )
    gate_mod.run_exhaustive_structure_self_test(baseline)
    both = next(
        r
        for r in baseline["network_credential_rotation_vectors"]
        if r["id"] == "WIFI-NETCRED-FULL-BOTH"
    )
    if both["expected_classification"] != "BOTH" or both["classification"] != "BOTH":
        raise AssertionError("self-test: BOTH classification")
    # NFL1 structural: version mutation after CRC repair must fail.
    min_row = next(
        r for r in baseline["nwb1_vectors"] if r["id"] == "WIFI-NWB1-PAYLOAD-587-ACCEPT"
    )
    rec = bytearray(bytes.fromhex(min_row["record_hex"]))
    rec[44] = 0xFF  # NFL1 version high byte area: offset 40+4 = version field
    # version is at payload+4 => record[44:46]
    rec[44:46] = u16(0x00FF)
    rec[36:40] = bytes(4)
    rec[36:40] = u32(crc32c(bytes(rec)))
    if classify_nwb1_framing(bytes(rec)) == "OK":
        raise AssertionError("self-test: NFL1 version mutation survived")
    # NWD1 wrong magic coherent equality must be CORRUPT.
    old = next(
        r
        for r in baseline["network_credential_rotation_vectors"]
        if r["id"] == "WIFI-NETCRED-FULL-OLD"
    )
    key = bytes.fromhex(old["observed_rows"][0]["key_hex"])
    val = bytearray(bytes.fromhex(old["observed_rows"][0]["value_hex"]))
    val[0:4] = b"XWD1"
    if (
        classify_commit_unknown(
            old_rows=[(key, bytes(val))],
            new_rows=[(key, bytes(val))],
            observed_rows=[(key, bytes(val))],
        )
        != "CORRUPT"
    ):
        raise AssertionError("self-test: XWD1 coherent equality accepted")
    # Concrete defect pins in generated source.
    dup = next(r for r in baseline["nwb1_vectors"] if r["id"] == "WIFI-NWB1-DUPLICATE")
    if (
        dup["prior_delivered_sequence"] != 1
        or dup["expected_sequence"] != 2
        or dup["received_sequence"] != 1
    ):
        raise AssertionError("self-test: DUPLICATE sequence contract")
    rel = next(
        r
        for r in baseline["resource_queue_vectors"]
        if r["id"] == "WIFI-RESOURCE-RELEASE-SEMANTICS"
    )
    if rel["release_before_terminal_forbidden"] != 1:
        raise AssertionError("self-test: release_before_terminal_forbidden")
    rec = next(
        r
        for r in baseline["network_credential_rotation_vectors"]
        if r["id"] == "WIFI-NETCRED-COMMIT-UNKNOWN-RECOVERY"
    )
    if "CORRUPT" not in rec["classifications_allowed_on_reopen"]:
        raise AssertionError("self-test: CORRUPT missing from reopen set")
    absent = next(
        r
        for r in baseline["network_credential_rotation_vectors"]
        if r["id"] == "WIFI-NETCRED-FULL-ABSENT"
    )
    if absent["expected_classification"] != "ABSENT":
        raise AssertionError("self-test: ABSENT row")
    dupk = next(
        r
        for r in baseline["network_credential_rotation_vectors"]
        if r["id"] == "WIFI-NETCRED-DUPLICATE-KEY"
    )
    if (
        dupk["expected_classification"] != "CORRUPT"
        or dupk["duplicate_old_key_classification"] != "CORRUPT"
    ):
        raise AssertionError("self-test: duplicate-key CORRUPT")
    for row in baseline["network_credential_rotation_vectors"]:
        if row["id"] != "WIFI-NETCRED-NO-PLAINTEXT-SECRET":
            continue
        for field in ("old_value_hex", "new_value_hex"):
            raw = bytes.fromhex(row[field])
            for forbidden in (b"hunter2", b"p@ssw0rd", b"correct-horse-battery"):
                if forbidden in raw.lower():
                    raise AssertionError("self-test: forbidden secret material")
    # Full-row donor under same ID must change document identity for every ID.
    # (Independent gates reject; generator proves body swap is observable.)
    groups = [
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
    ]
    by = {r["id"]: (g, r) for g in groups for r in baseline[g]}
    donor_obs = 0
    for victim in REQUIRED_ACCEPTANCE_IDS:
        donor = next(i for i in REQUIRED_ACCEPTANCE_IDS if i != victim)
        cand = build_document()
        vg, _ = by[victim]
        _, drow = by[donor]
        for index, row in enumerate(cand[vg]):
            if row["id"] == victim:
                body = dict(drow)
                body["id"] = victim
                cand[vg][index] = body
                break
        if canonical_json(cand) == rendered:
            raise AssertionError(f"self-test: donor swap invisible for {victim}")
        donor_obs += 1
    print(
        "wifi bearer vector generator self-test: OK "
        f"ids={len(REQUIRED_ACCEPTANCE_IDS)} donor_body_swaps={donor_obs} "
        f"sha256={sha256(rendered).hex()}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--emit-c-fixture", type=Path)
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return 0

    document = build_document()
    rendered = canonical_json(document)

    if args.write:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT.write_bytes(rendered)
        print(f"wrote {OUTPUT} sha256={sha256(rendered).hex()}")
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
        emit_c_fixture(document, args.emit_c_fixture)
        print(f"wrote {args.emit_c_fixture}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
