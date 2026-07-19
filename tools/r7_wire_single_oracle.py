#!/usr/bin/env python3
"""Independent R7 T1 NRW1 SINGLE wire oracle (stdlib only; docs/32 §7).

Implements AES-128-GCM for dual-envelope SINGLE frames without C helpers,
OpenSSL/cryptography bindings, or generated C fixtures as authority.

Subset format id: ninlil-r7-wire-single-t1-v1
This is NOT docs/30 §18 full materialization / r7-radio-wire-v1.json.

PASS ≠ R7 complete / W1 / HIL / Accepted T1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

REPO = pathlib.Path(__file__).resolve().parents[1]
FORMAT_ID = "ninlil-r7-wire-single-t1-v1"
JSON_PATH = REPO / "tests" / "radio" / "private" / "r7_wire_single_t1_vectors.json"
HEADER_PATH = REPO / "tests" / "radio" / "private" / "r7_wire_single_t1_vectors.gen.h"

MANDATORY_IDS: tuple[str, ...] = (
    "R7-T1-SINGLE-N1",
    "R7-T1-SINGLE-N16",
    "R7-T1-SINGLE-N24",
    "R7-T1-SINGLE-N32",
    "R7-T1-SINGLE-N190",
    "R7-T1-SINGLE-HIGH-COUNTER",
    "R7-T1-SINGLE-RELAY-TUPLE",
)

# ---------------------------------------------------------------------------
# AES-128-GCM (independent; same construction as T0 oracle, self-contained)
# ---------------------------------------------------------------------------

_SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
    0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26,
    0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
    0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
    0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F,
    0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC,
    0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14,
    0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
    0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F,
    0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F,
    0xB0, 0x54, 0xBB, 0x16,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def _xtime(x: int) -> int:
    return ((x << 1) & 0xFF) ^ (0x1B if (x & 0x80) else 0)


def aes128_key_expand(key: bytes) -> list[int]:
    if len(key) != 16:
        raise ValueError("aes128 key must be 16 bytes")
    w = list(key)
    i = 16
    rconi = 0
    while i < 176:
        t0, t1, t2, t3 = w[i - 4], w[i - 3], w[i - 2], w[i - 1]
        if i % 16 == 0:
            u = t0
            t0 = _SBOX[t1] ^ _RCON[rconi]
            t1 = _SBOX[t2]
            t2 = _SBOX[t3]
            t3 = _SBOX[u]
            rconi += 1
        w.append(w[i - 16] ^ t0)
        w.append(w[i - 15] ^ t1)
        w.append(w[i - 14] ^ t2)
        w.append(w[i - 13] ^ t3)
        i += 4
    return w


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("aes128 block must be 16 bytes")
    rk = aes128_key_expand(key)
    s = [block[i] ^ rk[i] for i in range(16)]

    def sub_shift(state: list[int]) -> list[int]:
        return [
            _SBOX[state[0]],
            _SBOX[state[5]],
            _SBOX[state[10]],
            _SBOX[state[15]],
            _SBOX[state[4]],
            _SBOX[state[9]],
            _SBOX[state[14]],
            _SBOX[state[3]],
            _SBOX[state[8]],
            _SBOX[state[13]],
            _SBOX[state[2]],
            _SBOX[state[7]],
            _SBOX[state[12]],
            _SBOX[state[1]],
            _SBOX[state[6]],
            _SBOX[state[11]],
        ]

    for r in range(1, 10):
        t = sub_shift(s)
        s2 = [0] * 16
        for c in range(4):
            a0, a1, a2, a3 = t[c * 4 : c * 4 + 4]
            u = a0 ^ a1 ^ a2 ^ a3
            v = a0
            s2[c * 4 + 0] = a0 ^ u ^ _xtime(a0 ^ a1)
            s2[c * 4 + 1] = a1 ^ u ^ _xtime(a1 ^ a2)
            s2[c * 4 + 2] = a2 ^ u ^ _xtime(a2 ^ a3)
            s2[c * 4 + 3] = a3 ^ u ^ _xtime(a3 ^ v)
        s = [s2[i] ^ rk[r * 16 + i] for i in range(16)]
    t = sub_shift(s)
    return bytes(t[i] ^ rk[160 + i] for i in range(16))


def _gf_mul(x: bytearray, y: bytes) -> None:
    z = bytearray(16)
    v = bytearray(y)
    for i in range(16):
        xi = x[i]
        for bit in range(7, -1, -1):
            if (xi >> bit) & 1:
                for j in range(16):
                    z[j] ^= v[j]
            lsb = v[15] & 1
            for j in range(15, 0, -1):
                v[j] = ((v[j] >> 1) | ((v[j - 1] & 1) << 7)) & 0xFF
            v[0] = (v[0] >> 1) & 0xFF
            if lsb:
                v[0] ^= 0xE1
    x[:] = z


def _ghash(h: bytes, aad: bytes, ct: bytes) -> bytes:
    y = bytearray(16)
    for data in (aad, ct):
        off = 0
        while off < len(data):
            n = min(16, len(data) - off)
            block = bytearray(16)
            block[:n] = data[off : off + n]
            for i in range(16):
                y[i] ^= block[i]
            _gf_mul(y, h)
            off += n
    len_block = bytearray(16)
    aad_bits = len(aad) * 8
    ct_bits = len(ct) * 8
    len_block[0:8] = aad_bits.to_bytes(8, "big")
    len_block[8:16] = ct_bits.to_bytes(8, "big")
    for i in range(16):
        y[i] ^= len_block[i]
    _gf_mul(y, h)
    return bytes(y)


def _inc32(counter: bytearray) -> None:
    c = int.from_bytes(counter[12:16], "big")
    c = (c + 1) & 0xFFFFFFFF
    counter[12:16] = c.to_bytes(4, "big")


def aes128_gcm_seal(
    key: bytes, nonce: bytes, aad: bytes, pt: bytes
) -> tuple[bytes, bytes]:
    if len(key) != 16 or len(nonce) != 12:
        raise ValueError("key16 nonce12 required")
    h = aes128_encrypt_block(key, bytes(16))
    j0 = bytearray(nonce + b"\x00\x00\x00\x01")
    counter = bytearray(j0)
    ct = bytearray(len(pt))
    off = 0
    while off < len(pt):
        _inc32(counter)
        stream = aes128_encrypt_block(key, bytes(counter))
        n = min(16, len(pt) - off)
        for i in range(n):
            ct[off + i] = pt[off + i] ^ stream[i]
        off += n
    s = _ghash(h, aad, bytes(ct))
    t = aes128_encrypt_block(key, bytes(j0))
    tag = bytes(t[i] ^ s[i] for i in range(16))
    return bytes(ct), tag


def to_hex(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


def derive_nonce(static_iv: bytes, counter: int) -> bytes:
    if len(static_iv) != 12:
        raise ValueError("static iv must be 12 bytes")
    if counter <= 0 or counter >= (1 << 64) - 1:
        raise ValueError("counter outside assignable domain")
    suffix = int.from_bytes(static_iv[4:], "big") ^ counter
    return static_iv[:4] + suffix.to_bytes(8, "big")


def pack_outer_aad(
    *,
    ack_requested: int,
    hop_remaining: int,
    hop_context_id: int,
    hop_counter: int,
    route_handle: int,
    route_generation: int,
) -> bytes:
    kind_flags = (1 << 4) | (ack_requested & 1)
    return b"".join(
        (
            bytes((0x11, kind_flags, hop_remaining & 0xFF)),
            hop_context_id.to_bytes(4, "big"),
            hop_counter.to_bytes(8, "big"),
            route_handle.to_bytes(2, "big"),
            route_generation.to_bytes(2, "big"),
        )
    )


def pack_e2e_aad(*, e2e_context_id: int, e2e_counter: int) -> bytes:
    return b"".join(
        (
            bytes((0x11, 1 << 4)),
            e2e_context_id.to_bytes(4, "big"),
            e2e_counter.to_bytes(8, "big"),
        )
    )


def app_bytes(n: int, seed: int) -> bytes:
    return bytes(((seed + i * 17) & 0xFF) for i in range(n))


def build_vector(
    vector_id: str,
    *,
    n: int,
    e2e_context_id: int,
    e2e_counter: int,
    hop_context_id: int,
    hop_counter: int,
    ack_requested: int,
    hop_remaining: int,
    route_handle: int,
    route_generation: int,
    e2e_key: bytes,
    e2e_iv: bytes,
    hop_key: bytes,
    hop_iv: bytes,
    app: bytes | None = None,
) -> dict[str, Any]:
    if app is None:
        app = app_bytes(n, 0x40 + n)
    if len(app) != n:
        raise ValueError("app length mismatch")
    if not (1 <= n <= 190):
        raise ValueError("N domain")

    e2e_aad = pack_e2e_aad(
        e2e_context_id=e2e_context_id, e2e_counter=e2e_counter
    )
    e2e_nonce = derive_nonce(e2e_iv, e2e_counter)
    e2e_ct, e2e_tag = aes128_gcm_seal(e2e_key, e2e_nonce, e2e_aad, app)
    e2e_blob = e2e_aad + e2e_ct + e2e_tag
    if len(e2e_blob) != 30 + n:
        raise ValueError("e2e blob length")

    outer_aad = pack_outer_aad(
        ack_requested=ack_requested,
        hop_remaining=hop_remaining,
        hop_context_id=hop_context_id,
        hop_counter=hop_counter,
        route_handle=route_handle,
        route_generation=route_generation,
    )
    hop_nonce = derive_nonce(hop_iv, hop_counter)
    hop_ct, hop_tag = aes128_gcm_seal(hop_key, hop_nonce, outer_aad, e2e_blob)
    outer_frame = outer_aad + hop_ct + hop_tag
    outer_len = 65 + n
    if len(outer_frame) != outer_len:
        raise ValueError(f"outer length want {outer_len} got {len(outer_frame)}")
    # docs/32 §7 pin points
    if n == 1 and outer_len != 66:
        raise ValueError("N1 outer")
    if n == 16 and outer_len != 81:
        raise ValueError("N16 outer")
    if n == 24 and outer_len != 89:
        raise ValueError("N24 outer")
    if n == 32 and outer_len != 97:
        raise ValueError("N32 outer")
    if n == 190 and outer_len != 255:
        raise ValueError("N190 outer")

    return {
        "ack_requested": ack_requested,
        "app": to_hex(app),
        "e2e_aad14": to_hex(e2e_aad),
        "e2e_blob": to_hex(e2e_blob),
        "e2e_context_id": e2e_context_id,
        "e2e_counter": e2e_counter,
        "e2e_ct": to_hex(e2e_ct),
        "e2e_iv12": to_hex(e2e_iv),
        "e2e_key16": to_hex(e2e_key),
        "e2e_nonce12": to_hex(e2e_nonce),
        "e2e_tag16": to_hex(e2e_tag),
        "hop_context_id": hop_context_id,
        "hop_counter": hop_counter,
        "hop_ct": to_hex(hop_ct),
        "hop_iv12": to_hex(hop_iv),
        "hop_key16": to_hex(hop_key),
        "hop_nonce12": to_hex(hop_nonce),
        "hop_remaining": hop_remaining,
        "hop_tag16": to_hex(hop_tag),
        "id": vector_id,
        "n": n,
        "outer_aad19": to_hex(outer_aad),
        "outer_frame": to_hex(outer_frame),
        "outer_len": outer_len,
        "route_generation": route_generation,
        "route_handle": route_handle,
    }


def build_vectors() -> list[dict[str, Any]]:
    e2e_key = from_hex("00112233445566778899aabbccddeeff")
    e2e_iv = from_hex("102132435465768798a9bacb")
    hop_key = from_hex("ffeeddccbbaa99887766554433221100")
    hop_iv = from_hex("0f1e2d3c4b5a69788796a5b4")

    vectors: list[dict[str, Any]] = []
    for vector_id, n in (
        ("R7-T1-SINGLE-N1", 1),
        ("R7-T1-SINGLE-N16", 16),
        ("R7-T1-SINGLE-N24", 24),
        ("R7-T1-SINGLE-N32", 32),
        ("R7-T1-SINGLE-N190", 190),
    ):
        vectors.append(
            build_vector(
                vector_id,
                n=n,
                e2e_context_id=0x01020304,
                e2e_counter=1,
                hop_context_id=0x0A0B0C0D,
                hop_counter=1,
                ack_requested=0,
                hop_remaining=0,
                route_handle=0,
                route_generation=0,
                e2e_key=e2e_key,
                e2e_iv=e2e_iv,
                hop_key=hop_key,
                hop_iv=hop_iv,
            )
        )

    vectors.append(
        build_vector(
            "R7-T1-SINGLE-HIGH-COUNTER",
            n=16,
            e2e_context_id=0x11223344,
            e2e_counter=(1 << 64) - 2,
            hop_context_id=0x55667788,
            hop_counter=(1 << 64) - 2,
            ack_requested=1,
            hop_remaining=0,
            route_handle=0,
            route_generation=0,
            e2e_key=e2e_key,
            e2e_iv=e2e_iv,
            hop_key=hop_key,
            hop_iv=hop_iv,
        )
    )
    vectors.append(
        build_vector(
            "R7-T1-SINGLE-RELAY-TUPLE",
            n=24,
            e2e_context_id=0xAABBCCDD,
            e2e_counter=7,
            hop_context_id=0x10203040,
            hop_counter=9,
            ack_requested=1,
            hop_remaining=3,
            route_handle=0x1234,
            route_generation=0x5678,
            e2e_key=e2e_key,
            e2e_iv=e2e_iv,
            hop_key=hop_key,
            hop_iv=hop_iv,
        )
    )
    vectors.sort(key=lambda row: row["id"])
    return vectors


def build_document() -> dict[str, Any]:
    vectors = build_vectors()
    return {
        "c_bridge": {
            "implemented": True,
            "required_vector_count": len(vectors),
            "skip_allowed": False,
            "status": "implemented",
        },
        "format_id": FORMAT_ID,
        "kind": "r7_t1_nrw1_single_subset",
        "notes": (
            "T1 private pure SINGLE subset only; not docs/30 §18 full "
            "materialization; not r7-radio-wire-v1.json"
        ),
        "vector_count": len(vectors),
        "vectors": vectors,
    }


def canonical_json(document: dict[str, Any]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def generate_header(document: dict[str, Any], json_bytes: bytes) -> bytes:
    digest = hashlib.sha256(json_bytes).hexdigest()
    vectors = document["vectors"]
    lines = [
        "/* generated by tools/r7_wire_single_oracle.py; test-only private fixture */",
        "/* c bridge status: implemented; skip forbidden; T1 subset only */",
        "#ifndef NINLIL_R7_WIRE_SINGLE_T1_VECTORS_GEN_H",
        "#define NINLIL_R7_WIRE_SINGLE_T1_VECTORS_GEN_H",
        "",
        "#include <stdint.h>",
        "",
        f'#define NINLIL_R7_WIRE_T1_VECTOR_JSON_SHA256 "{digest}"',
        f"#define NINLIL_R7_WIRE_T1_VECTOR_COUNT {len(vectors)}u",
        "",
        "typedef struct {",
        "    const char *id;",
        "    uint16_t n;",
        "    uint16_t outer_len;",
        "    uint8_t ack_requested;",
        "    uint8_t hop_remaining;",
        "    uint16_t route_handle;",
        "    uint16_t route_generation;",
        "    uint32_t e2e_context_id;",
        "    uint64_t e2e_counter;",
        "    uint32_t hop_context_id;",
        "    uint64_t hop_counter;",
        "    const char *app;",
        "    const char *e2e_key16;",
        "    const char *e2e_iv12;",
        "    const char *e2e_nonce12;",
        "    const char *e2e_aad14;",
        "    const char *e2e_ct;",
        "    const char *e2e_tag16;",
        "    const char *e2e_blob;",
        "    const char *hop_key16;",
        "    const char *hop_iv12;",
        "    const char *hop_nonce12;",
        "    const char *outer_aad19;",
        "    const char *hop_ct;",
        "    const char *hop_tag16;",
        "    const char *outer_frame;",
        "} ninlil_r7_wire_t1_vector;",
        "",
        "static const ninlil_r7_wire_t1_vector ninlil_r7_wire_t1_vectors[] = {",
    ]
    for row in vectors:
        lines.append("    {")
        lines.append(f'        "{row["id"]}",')
        lines.append(f'        {int(row["n"])}u,')
        lines.append(f'        {int(row["outer_len"])}u,')
        lines.append(f'        {int(row["ack_requested"])}u,')
        lines.append(f'        {int(row["hop_remaining"])}u,')
        lines.append(f'        0x{int(row["route_handle"]):04x}u,')
        lines.append(f'        0x{int(row["route_generation"]):04x}u,')
        lines.append(f'        0x{int(row["e2e_context_id"]):08x}u,')
        lines.append(f'        {int(row["e2e_counter"])}ull,')
        lines.append(f'        0x{int(row["hop_context_id"]):08x}u,')
        lines.append(f'        {int(row["hop_counter"])}ull,')
        for key in (
            "app",
            "e2e_key16",
            "e2e_iv12",
            "e2e_nonce12",
            "e2e_aad14",
            "e2e_ct",
            "e2e_tag16",
            "e2e_blob",
            "hop_key16",
            "hop_iv12",
            "hop_nonce12",
            "outer_aad19",
            "hop_ct",
            "hop_tag16",
            "outer_frame",
        ):
            lines.append(f'        "{row[key]}",')
        lines.append("    },")
    lines.extend(["};", "", "#endif", ""])
    return "\n".join(lines).encode("ascii")


def artifact_bytes() -> tuple[bytes, bytes]:
    document = build_document()
    json_bytes = canonical_json(document)
    return json_bytes, generate_header(document, json_bytes)


def verify_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document is not an object"]
    if document.get("format_id") != FORMAT_ID:
        errors.append("format_id mismatch")
    vectors = document.get("vectors")
    if not isinstance(vectors, list):
        return ["vectors is not an array"]
    if document.get("vector_count") != len(vectors):
        errors.append("vector_count mismatch")
    ids = [row.get("id") for row in vectors if isinstance(row, dict)]
    if ids != sorted(ids):
        errors.append("vector ids not sorted")
    if set(ids) != set(MANDATORY_IDS) or len(ids) != len(MANDATORY_IDS):
        errors.append(f"mandatory id set mismatch got={ids}")
    bridge = document.get("c_bridge")
    if not isinstance(bridge, dict):
        errors.append("c_bridge missing")
    else:
        if bridge.get("implemented") is not True:
            errors.append("c_bridge.implemented")
        if bridge.get("skip_allowed") is not False:
            errors.append("c_bridge.skip_allowed must be false")
        if bridge.get("required_vector_count") != len(vectors):
            errors.append("c_bridge.required_vector_count")
        if bridge.get("status") != "implemented":
            errors.append("c_bridge.status")
    expected = build_document()
    if document != expected:
        errors.append("document differs from independent oracle rebuild")
    for row in vectors:
        if not isinstance(row, dict):
            errors.append("vector row not object")
            continue
        n = int(row["n"])
        outer = int(row["outer_len"])
        if outer != 65 + n:
            errors.append(f"{row['id']}: outer_len")
        if len(from_hex(row["outer_frame"])) != outer:
            errors.append(f"{row['id']}: outer_frame length")
        if len(from_hex(row["e2e_blob"])) != 30 + n:
            errors.append(f"{row['id']}: e2e_blob length")
    return errors


def mutation_self_test() -> list[str]:
    errors: list[str] = []
    original = build_document()
    mutated = json.loads(canonical_json(original))
    mutated["vector_count"] += 1
    if not verify_document(mutated):
        errors.append("count mutation escaped")
    mutated = json.loads(canonical_json(original))
    mutated["c_bridge"]["skip_allowed"] = True
    if not verify_document(mutated):
        errors.append("bridge skip mutation escaped")
    mutated = json.loads(canonical_json(original))
    mutated["vectors"] = mutated["vectors"][1:]
    mutated["vector_count"] = len(mutated["vectors"])
    mutated["c_bridge"]["required_vector_count"] = len(mutated["vectors"])
    if not verify_document(mutated):
        errors.append("vector drop mutation escaped")
    mutated = json.loads(canonical_json(original))
    mutated["vectors"][0]["e2e_tag16"] = to_hex(
        bytearray(from_hex(mutated["vectors"][0]["e2e_tag16"]))
    )
    # flip a tag bit
    tag = bytearray(from_hex(mutated["vectors"][0]["e2e_tag16"]))
    tag[0] ^= 1
    mutated["vectors"][0]["e2e_tag16"] = to_hex(bytes(tag))
    if not verify_document(mutated):
        errors.append("tag flip mutation escaped")
    # deterministic twice via subprocess + PYTHONHASHSEED
    with tempfile.TemporaryDirectory(prefix="r7-t1-oracle-") as td1, tempfile.TemporaryDirectory(
        prefix="r7-t1-oracle-"
    ) as td2:
        for seed, td in (("1", td1), ("2", td2)):
            env = os.environ.copy()
            env["PYTHONHASHSEED"] = seed
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            jpath = pathlib.Path(td) / "v.json"
            hpath = pathlib.Path(td) / "v.h"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO / "tools" / "r7_wire_single_oracle.py"),
                    "generate",
                    "--json",
                    str(jpath),
                    "--header",
                    str(hpath),
                ],
                cwd=str(REPO),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            if proc.returncode != 0:
                errors.append(f"generate under hashseed={seed} failed: {proc.stderr}")
        j1 = (pathlib.Path(td1) / "v.json").read_bytes()
        j2 = (pathlib.Path(td2) / "v.json").read_bytes()
        h1 = (pathlib.Path(td1) / "v.h").read_bytes()
        h2 = (pathlib.Path(td2) / "v.h").read_bytes()
        if j1 != j2 or h1 != h2:
            errors.append("deterministic twice generation mismatch")
    return errors


def self_check() -> int:
    errors = mutation_self_test()
    document = build_document()
    errors.extend(verify_document(document))
    json_a, header_a = artifact_bytes()
    json_b, header_b = artifact_bytes()
    if (json_a, header_a) != (json_b, header_b):
        errors.append("in-process artifact non-deterministic")
    if errors:
        for e in errors:
            print(f"r7_wire_single_oracle FAIL: {e}", file=sys.stderr)
        return 1
    print(
        f"r7_wire_single_oracle self-test OK vectors={document['vector_count']} "
        f"format={FORMAT_ID}"
    )
    return 0


def verify_json_file(path: pathlib.Path) -> int:
    try:
        document = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"r7_wire_single_oracle FAIL: {exc}", file=sys.stderr)
        return 1
    errors = verify_document(document)
    if errors:
        for e in errors:
            print(f"r7_wire_single_oracle FAIL: {e}", file=sys.stderr)
        return 1
    print(f"r7_wire_single_oracle verify-json OK vectors={document['vector_count']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("self-test", "emit-json", "emit-header", "generate", "verify-json"),
    )
    parser.add_argument("--json", type=pathlib.Path)
    parser.add_argument("--header", type=pathlib.Path)
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return self_check()
    json_bytes, header_bytes = artifact_bytes()
    if args.command == "emit-json":
        sys.stdout.buffer.write(json_bytes)
        return 0
    if args.command == "emit-header":
        sys.stdout.buffer.write(header_bytes)
        return 0
    if args.command == "generate":
        if args.json is None or args.header is None:
            parser.error("generate requires --json and --header")
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_bytes(json_bytes)
        args.header.write_bytes(header_bytes)
        return 0
    if args.command == "verify-json":
        if args.json is None:
            parser.error("verify-json requires --json")
        return verify_json_file(args.json)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
