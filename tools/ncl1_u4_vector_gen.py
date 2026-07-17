#!/usr/bin/env python3
"""Authoritative independent NCL1 U4 vector generator / oracle (codec+wire slice).

- Does not import production C.
- required_ids: docs/23 §8.9 ∪ §5.6.2 unique = 46
- vector_count: actual unique vectors in file (47 = 46 required + U4-N-RESERVED-ORDER)
- check: rebuild via build_vectors() and require byte-identical canonical JSON;
  re-verify every payload_hex / ncg1_*_hex CRC and expected_decode.
- self-test: mutations must fail check (exceptions are not swallowed).

Behavior-only catalog rows pin required IDs for later LC; this slice's C bridge
only materializes codec_cases (golden/negative_decode/order_check + semantic
flags pure codec can evaluate). Does not claim U4 session complete / HIL.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import sys
import tempfile
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
VECTOR_PATH = REPO / "spec" / "vectors" / "ncl1-u4-v1.json"
FORMAT = "ninlil-ncl1-u4-v1"

MAGIC_NCG1 = b"NCG1"
NCG1_VER = 1
TYPE_PING = 0x01
TYPE_PONG = 0x02
TYPE_DATA = 0x03
TYPE_RESET = 0x04

MAGIC_NCL1 = b"NCL1"
NCL1_VER = 1
MSG_HELLO = 0x01
MSG_HELLO_ACK = 0x02
MSG_CTRL_ERROR = 0x03
MSG_PING = 0x10
MSG_PONG = 0x11
MSG_RESET = 0x12

# Mirror production ninlil_ncl1_status_t (decode outcomes)
OK = 0
INVALID_ARGUMENT = 1
REJECT_SHORT = 2
REJECT_MAGIC = 3
REJECT_VERSION = 4
REJECT_FLAGS = 5
REJECT_BODY_LEN = 6
REJECT_UNKNOWN = 7
REJECT_TYPE_BINDING = 8
REJECT_BODY_LAYOUT = 9
REJECT_RESERVED = 10

REQUIRED_IDS = [
    "U4-G-ACKLOSS-LAST0-HALFOPEN",
    "U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE",
    "U4-G-CELL-CONTINUITY-RESET-SESSION",
    "U4-G-CELL-RESTART-ACK0-RETRY",
    "U4-G-CELL-RXCOLD-HIGH-HELLO",
    "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK",
    "U4-G-CONTINUITY-RESET-NOTICE-CANCEL-ON-HELLO",
    "U4-G-CTRL-RXCOLD-HELLO-HIGH-ACK",
    "U4-G-DUP-HELLO-RECEIVED",
    "U4-G-HALFOPEN-REHELLO",
    "U4-G-HELLO-OK",
    "U4-G-HELLO-RETRY-NEXT-SEQ",
    "U4-G-PING-PONG",
    "U4-G-RESET-SESSION",
    "U4-G-RESTART-ACK-HIGH-BASELINE",
    "U4-G-RESTART-SEQ0-LAST-HIGH",
    "U4-G-RESTART-SEQ0-LAST0",
    "U4-N-ACK-BASELINE-NONMATCH",
    "U4-N-BAD-MAGIC",
    "U4-N-BASELINE-NONHELLO",
    "U4-N-BODY-LEN",
    "U4-N-CONTINUITY-RESET-STALE-NEW-SESSION",
    "U4-N-CONTINUITY-RESET-STALE-SEQ-ADVANCE",
    "U4-N-COOKIE-RNG-FAIL",
    "U4-N-COOKIE-ZERO",
    "U4-N-CTRL-ERROR-LOOP",
    "U4-N-EMPTY-PING",
    "U4-N-FLAGS",
    "U4-N-HELLO-ACTIVE-COOKIE-REJECT",
    "U4-N-HELLO-BAD-BOOTSTRAP",
    "U4-N-HELLO-INVALID-ROLE",
    "U4-N-HELLO-OK-COOKIE-ZERO",
    "U4-N-HELLO-RETRY-SEQ0-COLD",
    "U4-N-REQ-ZERO",
    "U4-N-SEQ-DISCARD-NO-NCL1-PEEK",
    "U4-N-SEQ-DUP",
    "U4-N-SEQ-GAP",
    "U4-N-SEQ-U32-MAX",
    "U4-N-SESS-ZERO",
    "U4-N-STALE-COOKIE",
    "U4-N-STALE-GEN",
    "U4-N-STREAM-ID",
    "U4-N-TYPE-BIND-HELLO-IN-PING",
    "U4-N-TYPE-BIND-PING-IN-DATA",
    "U4-N-UNKNOWN-TYPE",
    "U4-N-VER",
]

assert len(REQUIRED_IDS) == 46
assert len(set(REQUIRED_IDS)) == 46

# Extra diagnostic not in required union
EXTRA_ORDER_ID = "U4-N-RESERVED-ORDER"


def crc32c(data: bytes) -> int:
    if hasattr(zlib, "crc32c"):
        return zlib.crc32c(data) & 0xFFFFFFFF
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFFFFFF


def ncg1_encode(type_: int, stream_id: int, sequence: int, payload: bytes) -> bytes:
    prefix = bytearray()
    prefix += MAGIC_NCG1
    prefix.append(NCG1_VER)
    prefix.append(type_ & 0xFF)
    prefix += struct.pack(">H", 0)
    prefix += struct.pack(">I", stream_id & 0xFFFFFFFF)
    prefix += struct.pack(">I", sequence & 0xFFFFFFFF)
    prefix += struct.pack(">H", len(payload) & 0xFFFF)
    assert len(prefix) == 18
    header = bytes(prefix) + struct.pack(">I", crc32c(bytes(prefix)))
    body = header + payload
    return body + struct.pack(">I", crc32c(body))


def ncg1_verify(frame: bytes) -> bool:
    if len(frame) < 26:
        return False
    if frame[0:4] != MAGIC_NCG1 or frame[4] != NCG1_VER:
        return False
    plen = struct.unpack(">H", frame[16:18])[0]
    if len(frame) != 26 + plen:
        return False
    hcrc = struct.unpack(">I", frame[18:22])[0]
    if hcrc != crc32c(frame[:18]):
        return False
    fcrc = struct.unpack(">I", frame[-4:])[0]
    if fcrc != crc32c(frame[:-4]):
        return False
    return True


def ncl1_encode(
    msg_type: int,
    request_id: int,
    generation: int,
    cookie: int,
    body: bytes,
    *,
    flags: int = 0,
    version: int = NCL1_VER,
    magic: bytes = MAGIC_NCL1,
) -> bytes:
    hdr = bytearray()
    hdr += magic
    hdr.append(version & 0xFF)
    hdr.append(msg_type & 0xFF)
    hdr += struct.pack(">H", flags & 0xFFFF)
    hdr += struct.pack(">I", request_id & 0xFFFFFFFF)
    hdr += struct.pack(">I", generation & 0xFFFFFFFF)
    hdr += struct.pack(">Q", cookie & 0xFFFFFFFFFFFFFFFF)
    hdr += struct.pack(">H", len(body) & 0xFFFF)
    assert len(hdr) == 26
    return bytes(hdr) + body


def hello_body(min_v=1, max_v=1, flags_supported=0, reserved=0) -> bytes:
    return struct.pack(">HHHH", min_v, max_v, flags_supported, reserved)


def hello_ack_body(selected=1, flags_selected=0, result=0, reserved=0) -> bytes:
    return struct.pack(">HHHH", selected, flags_selected, result, reserved)


def ping_body(token: int) -> bytes:
    return struct.pack(">Q", token & 0xFFFFFFFFFFFFFFFF)


def reset_body(code: int = 1, reserved: bytes = b"\x00\x00\x00") -> bytes:
    return bytes([code & 0xFF]) + reserved


def pure_decode(payload: bytes, ncg1_type: int = 0) -> int:
    """Independent §8.1 steps 2–5 oracle (reserved NOT rejected)."""
    if len(payload) < 26:
        return REJECT_SHORT
    if payload[0:4] != MAGIC_NCL1:
        return REJECT_MAGIC
    if payload[4] != NCL1_VER:
        return REJECT_VERSION
    if struct.unpack(">H", payload[6:8])[0] != 0:
        return REJECT_FLAGS
    body_len = struct.unpack(">H", payload[24:26])[0]
    if body_len > 998:
        return REJECT_BODY_LEN
    if len(payload) != 26 + body_len:
        return REJECT_BODY_LEN
    msg_type = payload[5]
    exact = {
        MSG_HELLO: 8,
        MSG_HELLO_ACK: 8,
        MSG_CTRL_ERROR: 8,
        MSG_PING: 8,
        MSG_PONG: 8,
        MSG_RESET: 4,
    }
    if msg_type not in exact:
        return REJECT_UNKNOWN
    if ncg1_type:
        binding = {
            MSG_HELLO: TYPE_DATA,
            MSG_HELLO_ACK: TYPE_DATA,
            MSG_CTRL_ERROR: TYPE_DATA,
            MSG_PING: TYPE_PING,
            MSG_PONG: TYPE_PONG,
            MSG_RESET: TYPE_RESET,
        }
        if binding[msg_type] != ncg1_type:
            return REJECT_TYPE_BINDING
    if body_len != exact[msg_type]:
        return REJECT_BODY_LAYOUT
    body = payload[26:]
    if msg_type == MSG_HELLO:
        mn, mx, _fs, _rs = struct.unpack(">HHHH", body)
        if mn > mx:
            return REJECT_BODY_LAYOUT
    elif msg_type == MSG_HELLO_ACK:
        _sel, _fs, result, _rs = struct.unpack(">HHHH", body)
        if result not in (0, 1, 2, 3):
            return REJECT_BODY_LAYOUT
    elif msg_type == MSG_CTRL_ERROR:
        code, _rs, _rel = struct.unpack(">HHI", body)
        if code < 1 or code > 7:
            return REJECT_BODY_LAYOUT
    elif msg_type == MSG_RESET:
        if body[0] not in (1, 2, 3):
            return REJECT_BODY_LAYOUT
    return OK


def is_valid_hello_bootstrap(payload: bytes) -> bool:
    if pure_decode(payload, TYPE_DATA) != OK:
        return False
    if payload[5] != MSG_HELLO:
        return False
    gen = struct.unpack(">I", payload[12:16])[0]
    cookie = struct.unpack(">Q", payload[16:24])[0]
    req = struct.unpack(">I", payload[8:12])[0]
    if gen != 0 or cookie != 0 or req == 0:
        return False
    mn, mx, fs, rs = struct.unpack(">HHHH", payload[26:34])
    return mn == 1 and mx == 1 and fs == 0 and rs == 0


def is_structurally_valid_hello_ack(payload: bytes) -> bool:
    if pure_decode(payload, TYPE_DATA) != OK:
        return False
    if payload[5] != MSG_HELLO_ACK:
        return False
    req = struct.unpack(">I", payload[8:12])[0]
    gen = struct.unpack(">I", payload[12:16])[0]
    cookie = struct.unpack(">Q", payload[16:24])[0]
    if req == 0:
        return False
    sel, fs, result, rs = struct.unpack(">HHHH", payload[26:34])
    if fs != 0 or rs != 0:
        return False
    if result == 0:
        return gen != 0 and cookie != 0 and sel == 1
    if result in (1, 2, 3):
        return gen == 0 and cookie == 0
    return False


def check_reserved_ok(payload: bytes) -> bool:
    """Step 7 oracle after successful pure decode."""
    if pure_decode(payload, 0) != OK:
        return False
    msg_type = payload[5]
    body = payload[26:]
    if msg_type == MSG_HELLO:
        return struct.unpack(">HHHH", body)[3] == 0
    if msg_type == MSG_HELLO_ACK:
        return struct.unpack(">HHHH", body)[3] == 0
    if msg_type == MSG_CTRL_ERROR:
        return struct.unpack(">HHI", body)[1] == 0
    if msg_type == MSG_RESET:
        return body[1] == 0 and body[2] == 0 and body[3] == 0
    return True


def build_vectors() -> list[dict]:
    """Return ordered list: all required IDs + EXTRA_ORDER_ID (47 total)."""
    by_id: dict[str, dict] = {}

    def put(v: dict) -> None:
        i = v["id"]
        if i in by_id:
            raise RuntimeError(f"duplicate vector id {i}")
        by_id[i] = v

    # --- Codec goldens ---
    hello = ncl1_encode(MSG_HELLO, 0x1001, 0, 0, hello_body())
    ack = ncl1_encode(
        MSG_HELLO_ACK, 0x1001, 7, 0xC0FFEE0123456789, hello_ack_body()
    )
    put(
        {
            "id": "U4-G-HELLO-OK",
            "kind": "golden_bytes",
            "codec_case": True,
            "hello_ncl1_hex": hello.hex(),
            "hello_ncg1_hex": ncg1_encode(TYPE_DATA, 0, 0, hello).hex(),
            "ack_ncl1_hex": ack.hex(),
            "ack_ncg1_hex": ncg1_encode(TYPE_DATA, 0, 0, ack).hex(),
            "expected_decode": OK,
            "bootstrap_valid": True,
            "structurally_valid_ack": True,
        }
    )

    ping = ncl1_encode(
        MSG_PING, 0x2002, 7, 0xC0FFEE0123456789, ping_body(0xA1B2C3D4E5F60718)
    )
    pong = ncl1_encode(
        MSG_PONG, 0x2002, 7, 0xC0FFEE0123456789, ping_body(0xA1B2C3D4E5F60718)
    )
    put(
        {
            "id": "U4-G-PING-PONG",
            "kind": "golden_bytes",
            "codec_case": True,
            "ping_ncl1_hex": ping.hex(),
            "ping_ncg1_hex": ncg1_encode(TYPE_PING, 0, 1, ping).hex(),
            "pong_ncl1_hex": pong.hex(),
            "pong_ncg1_hex": ncg1_encode(TYPE_PONG, 0, 1, pong).hex(),
            "expected_decode": OK,
        }
    )

    reset = ncl1_encode(MSG_RESET, 0x3003, 7, 0xC0FFEE0123456789, reset_body(1))
    put(
        {
            "id": "U4-G-RESET-SESSION",
            "kind": "golden_bytes",
            "codec_case": True,
            "reset_ncl1_hex": reset.hex(),
            "reset_ncg1_hex": ncg1_encode(TYPE_RESET, 0, 2, reset).hex(),
            "stale_ping_ncl1_hex": ping.hex(),
            "expected_decode": OK,
        }
    )

    # --- Codec negatives (materialized) ---
    bad_magic = bytearray(hello)
    bad_magic[0] ^= 1
    put(
        {
            "id": "U4-N-BAD-MAGIC",
            "kind": "negative_decode",
            "codec_case": True,
            "payload_hex": bytes(bad_magic).hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": REJECT_MAGIC,
        }
    )

    bad_ver = bytearray(hello)
    bad_ver[4] = 2
    put(
        {
            "id": "U4-N-VER",
            "kind": "negative_decode",
            "codec_case": True,
            "payload_hex": bytes(bad_ver).hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": REJECT_VERSION,
        }
    )

    bad_flags = ncl1_encode(MSG_HELLO, 1, 0, 0, hello_body(), flags=1)
    put(
        {
            "id": "U4-N-FLAGS",
            "kind": "negative_decode",
            "codec_case": True,
            "payload_hex": bad_flags.hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": REJECT_FLAGS,
        }
    )

    # body_length header claims 8 but only 4 body bytes present
    hdr = bytearray(ncl1_encode(MSG_HELLO, 1, 0, 0, b"\x00" * 4)[:26])
    hdr[24:26] = struct.pack(">H", 8)
    bad_blen = bytes(hdr) + b"\x00" * 4
    put(
        {
            "id": "U4-N-BODY-LEN",
            "kind": "negative_decode",
            "codec_case": True,
            "payload_hex": bad_blen.hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": REJECT_BODY_LEN,
        }
    )

    req0 = ncl1_encode(MSG_HELLO, 0, 0, 0, hello_body())
    put(
        {
            "id": "U4-N-REQ-ZERO",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": req0.hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": OK,
            "bootstrap_valid": False,
        }
    )

    sess0 = ncl1_encode(MSG_PING, 0x55, 0, 0xC0FFEE0123456789, ping_body(1))
    put(
        {
            "id": "U4-N-SESS-ZERO",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": sess0.hex(),
            "ncg1_type": TYPE_PING,
            "expected_decode": OK,
            "notes": "session gen=0 illegal for active PING (session layer)",
        }
    )

    cookie0 = ncl1_encode(MSG_PING, 0x55, 7, 0, ping_body(1))
    put(
        {
            "id": "U4-N-COOKIE-ZERO",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": cookie0.hex(),
            "ncg1_type": TYPE_PING,
            "expected_decode": OK,
        }
    )

    stale_gen = ncl1_encode(MSG_PING, 0x55, 6, 0xC0FFEE0123456789, ping_body(1))
    put(
        {
            "id": "U4-N-STALE-GEN",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": stale_gen.hex(),
            "ncg1_type": TYPE_PING,
            "expected_decode": OK,
        }
    )

    stale_cookie = ncl1_encode(MSG_PING, 0x55, 7, 0xDEADBEEFCAFEBABE, ping_body(1))
    put(
        {
            "id": "U4-N-STALE-COOKIE",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": stale_cookie.hex(),
            "ncg1_type": TYPE_PING,
            "expected_decode": OK,
        }
    )

    ack_cookie0 = ncl1_encode(MSG_HELLO_ACK, 0x1001, 7, 0, hello_ack_body())
    put(
        {
            "id": "U4-N-HELLO-OK-COOKIE-ZERO",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": ack_cookie0.hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": OK,
            "structurally_valid_ack": False,
        }
    )

    ub = bytearray(ncl1_encode(MSG_HELLO, 1, 0, 0, hello_body()))
    ub[5] = 0x7F
    put(
        {
            "id": "U4-N-UNKNOWN-TYPE",
            "kind": "negative_decode",
            "codec_case": True,
            "payload_hex": bytes(ub).hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": REJECT_UNKNOWN,
        }
    )

    ping_in_data = ncl1_encode(MSG_PING, 1, 7, 0xC0FFEE0123456789, ping_body(1))
    put(
        {
            "id": "U4-N-TYPE-BIND-PING-IN-DATA",
            "kind": "negative_decode",
            "codec_case": True,
            "payload_hex": ping_in_data.hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": REJECT_TYPE_BINDING,
        }
    )

    hello_in_ping = ncl1_encode(MSG_HELLO, 1, 0, 0, hello_body())
    put(
        {
            "id": "U4-N-TYPE-BIND-HELLO-IN-PING",
            "kind": "negative_decode",
            "codec_case": True,
            "payload_hex": hello_in_ping.hex(),
            "ncg1_type": TYPE_PING,
            "expected_decode": REJECT_TYPE_BINDING,
        }
    )

    bad_bootstrap = ncl1_encode(MSG_HELLO, 1, 3, 0, hello_body())  # gen!=0
    put(
        {
            "id": "U4-N-HELLO-BAD-BOOTSTRAP",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": bad_bootstrap.hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": OK,
            "bootstrap_valid": False,
        }
    )

    # empty ping: empty NCL1 payload under NCG1 PING
    put(
        {
            "id": "U4-N-EMPTY-PING",
            "kind": "negative_semantic",
            "codec_case": True,
            "payload_hex": "",
            "ncg1_type": TYPE_PING,
            "expected_decode": REJECT_SHORT,
            "ncg1_hex": ncg1_encode(TYPE_PING, 0, 0, b"").hex(),
        }
    )

    # Craft reserved!=0 via raw body (python encode allows it)
    hello_rsv = ncl1_encode(MSG_HELLO, 1, 0, 0, hello_body(reserved=1))
    put(
        {
            "id": EXTRA_ORDER_ID,
            "kind": "order_check",
            "codec_case": True,
            "payload_hex": hello_rsv.hex(),
            "ncg1_type": TYPE_DATA,
            "expected_decode": OK,
            "bootstrap_valid": False,
            "reserved_ok": False,
            "notes": "pure decode OK; step7 reserved fails; not in required 46",
        }
    )

    # Catalog-only required IDs (session/LC later; still authoritative pins)
    catalog_only = [
        "U4-G-HALFOPEN-REHELLO",
        "U4-G-HELLO-RETRY-NEXT-SEQ",
        "U4-G-ACKLOSS-LAST0-HALFOPEN",
        "U4-G-ACKLOSS-REVERSE-SEQ1-BASELINE",
        "U4-G-RESTART-SEQ0-LAST0",
        "U4-G-RESTART-SEQ0-LAST-HIGH",
        "U4-G-RESTART-ACK-HIGH-BASELINE",
        "U4-G-CELL-RESTART-ACK0-RETRY",
        "U4-G-CELL-RXCOLD-HIGH-HELLO",
        "U4-G-CTRL-RXCOLD-HELLO-HIGH-ACK",
        "U4-G-CELL-CONTINUITY-RESET-SESSION",
        "U4-G-CONTINUITY-RESET-NOTICE-CANCEL-ON-HELLO",
        "U4-G-CONTINUITY-RESET-ACCEPTED-FIFO-BEFORE-ACK",
        "U4-G-DUP-HELLO-RECEIVED",
        "U4-N-CONTINUITY-RESET-STALE-NEW-SESSION",
        "U4-N-CONTINUITY-RESET-STALE-SEQ-ADVANCE",
        "U4-N-SEQ-U32-MAX",
        "U4-N-SEQ-GAP",
        "U4-N-SEQ-DUP",
        "U4-N-STREAM-ID",
        "U4-N-HELLO-ACTIVE-COOKIE-REJECT",
        "U4-N-HELLO-RETRY-SEQ0-COLD",
        "U4-N-SEQ-DISCARD-NO-NCL1-PEEK",
        "U4-N-ACK-BASELINE-NONMATCH",
        "U4-N-BASELINE-NONHELLO",
        "U4-N-HELLO-INVALID-ROLE",
        "U4-N-CTRL-ERROR-LOOP",
        "U4-N-COOKIE-RNG-FAIL",
    ]
    for cid in catalog_only:
        put(
            {
                "id": cid,
                "kind": "behavior_catalog",
                "codec_case": False,
                "notes": "required ID pin; LC/session bridge not in this slice",
            }
        )

    missing = [i for i in REQUIRED_IDS if i not in by_id]
    if missing:
        raise RuntimeError(f"missing required IDs: {missing}")
    if EXTRA_ORDER_ID not in by_id:
        raise RuntimeError("missing order diagnostic")

    # Stable order: required_ids order, then EXTRA
    ordered: list[dict] = []
    for rid in REQUIRED_IDS:
        ordered.append(by_id[rid])
    ordered.append(by_id[EXTRA_ORDER_ID])
    if len(ordered) != 47:
        raise RuntimeError(f"expected 47 vectors, got {len(ordered)}")
    return ordered


def canonical_doc(vectors: list[dict]) -> dict:
    return {
        "format": FORMAT,
        "vector_count": len(vectors),
        "required_id_count": 46,
        "required_ids": list(REQUIRED_IDS),
        "notes": (
            "NCL1 U4 codec+wire vectors. vector_count=actual unique rows (47). "
            "required_ids=§8.9∪§5.6.2 unique (46). Independent generator. "
            "Pure decode does not reject reserved (step7). "
            "HELLO U4 exact min=max=1 flags_supported=0. "
            "behavior_catalog pins are not LC-complete. "
            "Does not claim U4 session / assignment / security / HIL / series complete."
        ),
        "result_codes": {
            "OK": OK,
            "INVALID_ARGUMENT": INVALID_ARGUMENT,
            "REJECT_SHORT": REJECT_SHORT,
            "REJECT_MAGIC": REJECT_MAGIC,
            "REJECT_VERSION": REJECT_VERSION,
            "REJECT_FLAGS": REJECT_FLAGS,
            "REJECT_BODY_LEN": REJECT_BODY_LEN,
            "REJECT_UNKNOWN": REJECT_UNKNOWN,
            "REJECT_TYPE_BINDING": REJECT_TYPE_BINDING,
            "REJECT_BODY_LAYOUT": REJECT_BODY_LAYOUT,
            "REJECT_RESERVED": REJECT_RESERVED,
        },
        "vectors": vectors,
    }


def dumps_canonical(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


def write_json(path: pathlib.Path) -> None:
    doc = canonical_doc(build_vectors())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dumps_canonical(doc), encoding="utf-8")
    print(
        f"wrote {path} vector_count={doc['vector_count']} "
        f"required={doc['required_id_count']}"
    )


def verify_vector_semantics(v: dict) -> None:
    kind = v.get("kind")
    if kind in ("negative_decode", "order_check", "negative_semantic", "golden_bytes"):
        if v.get("codec_case") and "payload_hex" in v:
            payload = bytes.fromhex(v["payload_hex"]) if v["payload_hex"] else b""
            ncg1_type = int(v.get("ncg1_type") or 0)
            got = pure_decode(payload, ncg1_type)
            exp = v.get("expected_decode")
            if exp is not None and got != int(exp):
                raise SystemExit(f"{v['id']}: decode {got} != {exp}")
            if "bootstrap_valid" in v:
                bv = is_valid_hello_bootstrap(payload) if payload else False
                if bv != bool(v["bootstrap_valid"]):
                    raise SystemExit(f"{v['id']}: bootstrap_valid mismatch")
            if "structurally_valid_ack" in v and payload:
                av = is_structurally_valid_hello_ack(payload)
                if av != bool(v["structurally_valid_ack"]):
                    raise SystemExit(f"{v['id']}: ack structural mismatch")
            if "reserved_ok" in v and payload:
                ro = check_reserved_ok(payload)
                if ro != bool(v["reserved_ok"]):
                    raise SystemExit(f"{v['id']}: reserved_ok mismatch")
        if kind == "golden_bytes":
            for key in (
                "hello_ncl1_hex",
                "ack_ncl1_hex",
                "ping_ncl1_hex",
                "pong_ncl1_hex",
                "reset_ncl1_hex",
            ):
                if key in v:
                    p = bytes.fromhex(v[key])
                    if pure_decode(p, 0) != OK:
                        raise SystemExit(f"{v['id']}: {key} pure decode fail")
            for key in (
                "hello_ncg1_hex",
                "ack_ncg1_hex",
                "ping_ncg1_hex",
                "pong_ncg1_hex",
                "reset_ncg1_hex",
            ):
                if key in v and not ncg1_verify(bytes.fromhex(v[key])):
                    raise SystemExit(f"{v['id']}: {key} NCG1 CRC/layout fail")
            if v["id"] == "U4-G-HELLO-OK":
                h = bytes.fromhex(v["hello_ncl1_hex"])
                if not is_valid_hello_bootstrap(h):
                    raise SystemExit("HELLO-OK not valid bootstrap")
                mn, mx, fs, rs = struct.unpack(">HHHH", h[26:34])
                if (mn, mx, fs, rs) != (1, 1, 0, 0):
                    raise SystemExit("HELLO body not U4 exact")
                a = bytes.fromhex(v["ack_ncl1_hex"])
                if not is_structurally_valid_hello_ack(a):
                    raise SystemExit("ACK not structurally valid")
        if "ncg1_hex" in v and not ncg1_verify(bytes.fromhex(v["ncg1_hex"])):
            raise SystemExit(f"{v['id']}: ncg1_hex CRC fail")


def check(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    doc = json.loads(text)
    rebuilt = canonical_doc(build_vectors())
    rebuilt_text = dumps_canonical(rebuilt)
    if text != rebuilt_text:
        raise SystemExit(
            "JSON does not match build_vectors() canonical dump "
            f"(len file={len(text)} rebuild={len(rebuilt_text)})"
        )
    if doc["vector_count"] != 47:
        raise SystemExit(f"vector_count {doc['vector_count']} != 47")
    if doc["required_id_count"] != 46:
        raise SystemExit("required_id_count != 46")
    if doc["required_ids"] != REQUIRED_IDS:
        raise SystemExit("required_ids order/content drift")
    ids = [v["id"] for v in doc["vectors"]]
    if len(ids) != 47 or len(set(ids)) != 47:
        raise SystemExit(f"unique id count {len(set(ids))} != 47")
    for rid in REQUIRED_IDS:
        if rid not in ids:
            raise SystemExit(f"missing required {rid}")
    if EXTRA_ORDER_ID not in ids:
        raise SystemExit("missing U4-N-RESERVED-ORDER")
    for v in doc["vectors"]:
        verify_vector_semantics(v)
    print("ncl1_u4_vector_gen check: OK")


def emit_c_fixture(json_path: pathlib.Path, out_path: pathlib.Path) -> None:
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    cases: list[dict] = []

    def add_case(
        cid: str,
        kind: str,
        payload: bytes,
        ncg1_type: int,
        expected: int,
        *,
        bootstrap: int = -1,
        ack_struct: int = -1,
        reserved_ok: int = -1,
    ) -> None:
        cases.append(
            {
                "id": cid,
                "kind": kind,
                "bytes": payload,
                "ncg1_type": ncg1_type,
                "expected": expected,
                "bootstrap": bootstrap,
                "ack_struct": ack_struct,
                "reserved_ok": reserved_ok,
            }
        )

    for v in doc["vectors"]:
        if not v.get("codec_case"):
            continue
        if v["kind"] == "golden_bytes":
            if "hello_ncl1_hex" in v:
                add_case(
                    v["id"] + "/hello",
                    "golden",
                    bytes.fromhex(v["hello_ncl1_hex"]),
                    TYPE_DATA,
                    OK,
                    bootstrap=1 if v.get("bootstrap_valid") else 0,
                )
            if "ack_ncl1_hex" in v:
                add_case(
                    v["id"] + "/ack",
                    "golden",
                    bytes.fromhex(v["ack_ncl1_hex"]),
                    TYPE_DATA,
                    OK,
                    ack_struct=1 if v.get("structurally_valid_ack") else 0,
                )
            if "ping_ncl1_hex" in v:
                add_case(
                    v["id"] + "/ping",
                    "golden",
                    bytes.fromhex(v["ping_ncl1_hex"]),
                    TYPE_PING,
                    OK,
                )
            if "pong_ncl1_hex" in v:
                add_case(
                    v["id"] + "/pong",
                    "golden",
                    bytes.fromhex(v["pong_ncl1_hex"]),
                    TYPE_PONG,
                    OK,
                )
            if "reset_ncl1_hex" in v:
                add_case(
                    v["id"] + "/reset",
                    "golden",
                    bytes.fromhex(v["reset_ncl1_hex"]),
                    TYPE_RESET,
                    OK,
                )
            continue
        if "payload_hex" not in v or "expected_decode" not in v:
            continue
        payload = bytes.fromhex(v["payload_hex"]) if v["payload_hex"] else b""
        add_case(
            v["id"],
            v["kind"],
            payload,
            int(v.get("ncg1_type") or 0),
            int(v["expected_decode"]),
            bootstrap=(
                1
                if v.get("bootstrap_valid") is True
                else 0
                if v.get("bootstrap_valid") is False
                else -1
            ),
            ack_struct=(
                1
                if v.get("structurally_valid_ack") is True
                else 0
                if v.get("structurally_valid_ack") is False
                else -1
            ),
            reserved_ok=(
                1
                if v.get("reserved_ok") is True
                else 0
                if v.get("reserved_ok") is False
                else -1
            ),
        )

    if not cases:
        raise SystemExit("no codec cases to emit")

    max_len = max((len(c["bytes"]) for c in cases), default=0)
    lines = [
        "/* Generated by tools/ncl1_u4_vector_gen.py — do not edit. */",
        "#ifndef NINLIL_NCL1_U4_VECTOR_FIXTURE_H",
        "#define NINLIL_NCL1_U4_VECTOR_FIXTURE_H",
        "#include <stddef.h>",
        "#include <stdint.h>",
        f"#define NINLIL_NCL1_U4_REQUIRED_ID_COUNT 46u",
        f"#define NINLIL_NCL1_U4_VECTOR_COUNT 47u",
        f"#define NINLIL_NCL1_U4_CODEC_CASE_COUNT {len(cases)}u",
        f"#define NINLIL_NCL1_U4_MAX_PAYLOAD_BYTES {max_len}u",
        "static const char *const NINLIL_NCL1_U4_REQUIRED_IDS[46] = {",
    ]
    for rid in REQUIRED_IDS:
        lines.append(f'    "{rid}",')
    lines.append("};")
    lines.append("typedef struct ninlil_ncl1_u4_codec_case {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    const uint8_t *bytes;")
    lines.append("    size_t length;")
    lines.append("    uint8_t ncg1_type;")
    lines.append("    uint32_t expected_decode;")
    lines.append("    int bootstrap_valid; /* -1 n/a, 0 false, 1 true */")
    lines.append("    int structurally_valid_ack;")
    lines.append("    int reserved_ok;")
    lines.append("} ninlil_ncl1_u4_codec_case_t;")

    for i, c in enumerate(cases):
        b = c["bytes"]
        lines.append(f"static const uint8_t ninlil_ncl1_u4_case_{i}_bytes[] = {{")
        if b:
            hexes = ", ".join(f"0x{x:02x}" for x in b)
            lines.append(f"    {hexes}")
        else:
            lines.append("    0")  # length 0; pointer non-null dummy
        lines.append("};")

    lines.append(
        "static const ninlil_ncl1_u4_codec_case_t ninlil_ncl1_u4_codec_cases[] = {"
    )
    for i, c in enumerate(cases):
        length = len(c["bytes"])
        ptr = f"ninlil_ncl1_u4_case_{i}_bytes"
        lines.append("    {")
        lines.append(f'        "{c["id"]}",')
        lines.append(f'        "{c["kind"]}",')
        lines.append(f"        {ptr},")
        lines.append(f"        {length}u,")
        lines.append(f"        {c['ncg1_type']}u,")
        lines.append(f"        {c['expected']}u,")
        lines.append(f"        {c['bootstrap']},")
        lines.append(f"        {c['ack_struct']},")
        lines.append(f"        {c['reserved_ok']},")
        lines.append("    },")
    lines.append("};")
    lines.append("#endif /* NINLIL_NCL1_U4_VECTOR_FIXTURE_H */")
    text = "\n".join(lines) + "\n"
    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(out_path)
    print(f"emitted {out_path} codec_cases={len(cases)}")


def self_test() -> None:
    failures = 0
    with tempfile.TemporaryDirectory() as td:
        td_path = pathlib.Path(td)
        jp = td_path / "v.json"
        write_json(jp)
        check(jp)

        # Determinism
        write_json(td_path / "a.json")
        write_json(td_path / "b.json")
        if (td_path / "a.json").read_bytes() != (td_path / "b.json").read_bytes():
            raise SystemExit("non-deterministic write")

        # Mutate required_ids length → must fail
        doc = json.loads(jp.read_text(encoding="utf-8"))
        doc["required_ids"] = doc["required_ids"][:-1]
        doc["required_id_count"] = 45
        bad = td_path / "bad_ids.json"
        bad.write_text(dumps_canonical(doc), encoding="utf-8")
        try:
            check(bad)
            print("FAIL: expected check to reject truncated required_ids", file=sys.stderr)
            failures += 1
        except SystemExit as e:
            if "required" not in str(e).lower() and "46" not in str(e) and "match" not in str(e).lower() and "drift" not in str(e).lower() and "canonical" not in str(e).lower() and "JSON" not in str(e):
                # any SystemExit from check is success for mutation detection
                pass

        # Mutate golden HELLO magic → must fail
        doc = json.loads(jp.read_text(encoding="utf-8"))
        for v in doc["vectors"]:
            if v["id"] == "U4-G-HELLO-OK":
                raw = bytearray(bytes.fromhex(v["hello_ncl1_hex"]))
                raw[0] ^= 0xFF
                v["hello_ncl1_hex"] = bytes(raw).hex()
        mut = td_path / "mut_hello.json"
        mut.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        try:
            check(mut)
            print("FAIL: expected check to reject mutated HELLO", file=sys.stderr)
            failures += 1
        except SystemExit:
            pass

        # Mutate expected_decode → must fail (if only canonical compare, still fails rebuild)
        doc = json.loads(jp.read_text(encoding="utf-8"))
        for v in doc["vectors"]:
            if v["id"] == "U4-N-BAD-MAGIC":
                v["expected_decode"] = OK
        mut2 = td_path / "mut_exp.json"
        mut2.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        try:
            check(mut2)
            print("FAIL: expected check to reject expected_decode mutation", file=sys.stderr)
            failures += 1
        except SystemExit:
            pass

        # emit fixture twice deterministic
        h1 = td_path / "f1.h"
        h2 = td_path / "f2.h"
        emit_c_fixture(jp, h1)
        emit_c_fixture(jp, h2)
        if h1.read_bytes() != h2.read_bytes():
            raise SystemExit("emit-c-fixture non-deterministic")
        if b"NINLIL_NCL1_U4_CODEC_CASE_COUNT" not in h1.read_bytes():
            raise SystemExit("fixture missing case count")
        if b"U4-N-BAD-MAGIC" not in h1.read_bytes():
            raise SystemExit("fixture missing BAD-MAGIC")
        if b"U4-N-RESERVED-ORDER" not in h1.read_bytes():
            raise SystemExit("fixture missing RESERVED-ORDER")

    if failures:
        raise SystemExit(f"self-test failures: {failures}")
    print("ncl1_u4_vector_gen self-test: OK")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "cmd", choices=["write", "check", "self-test", "emit-c-fixture"]
    )
    ap.add_argument("args", nargs="*")
    ns = ap.parse_args()
    if ns.cmd == "write":
        write_json(pathlib.Path(ns.args[0]) if ns.args else VECTOR_PATH)
    elif ns.cmd == "check":
        check(pathlib.Path(ns.args[0]) if ns.args else VECTOR_PATH)
    elif ns.cmd == "self-test":
        self_test()
    elif ns.cmd == "emit-c-fixture":
        if len(ns.args) < 2:
            raise SystemExit("emit-c-fixture needs <json> <out.h>")
        emit_c_fixture(pathlib.Path(ns.args[0]), pathlib.Path(ns.args[1]))


if __name__ == "__main__":
    main()
