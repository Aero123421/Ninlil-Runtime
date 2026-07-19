#!/usr/bin/env python3
"""Independent R7 T0 radio-wire crypto oracle (stdlib only).

Implements AES-128, AES-128-GCM (96-bit IV), SHA-256, HMAC-SHA-256, and
RFC 5869 HKDF-SHA-256 without C helpers or third-party crypto.

Pins fixed known-answer vectors. Same input run twice must be
byte-identical. Output is lowercase stable hex.

Not R7 complete / not HIL / not production radio.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import pathlib
import sys
from typing import Any

# ---------------------------------------------------------------------------
# AES-128 (FIPS-197) — independent tables
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
    out = bytes(t[i] ^ rk[160 + i] for i in range(16))
    return out


# ---------------------------------------------------------------------------
# GCM (SP 800-38D, 96-bit IV)
# ---------------------------------------------------------------------------


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
    if len(pt) > 255 or len(aad) > 255:
        raise ValueError("len 0..255")
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


def aes128_gcm_open(
    key: bytes, nonce: bytes, aad: bytes, ct: bytes, tag: bytes
) -> bytes | None:
    if len(key) != 16 or len(nonce) != 12 or len(tag) != 16:
        raise ValueError("key16 nonce12 tag16 required")
    if len(ct) > 255 or len(aad) > 255:
        raise ValueError("len 0..255")
    h = aes128_encrypt_block(key, bytes(16))
    j0 = bytearray(nonce + b"\x00\x00\x00\x01")
    s = _ghash(h, aad, ct)
    t = aes128_encrypt_block(key, bytes(j0))
    expect = bytes(t[i] ^ s[i] for i in range(16))
    # constant-time-ish compare then decrypt
    diff = 0
    for a, b in zip(expect, tag):
        diff |= a ^ b
    if diff != 0:
        return None
    counter = bytearray(j0)
    pt = bytearray(len(ct))
    off = 0
    while off < len(ct):
        _inc32(counter)
        stream = aes128_encrypt_block(key, bytes(counter))
        n = min(16, len(ct) - off)
        for i in range(n):
            pt[off + i] = ct[off + i] ^ stream[i]
        off += n
    return bytes(pt)


# ---------------------------------------------------------------------------
# SHA-256 / HKDF (stdlib hashlib/hmac — still independent of C production)
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    if len(salt) == 0:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_sha256(prk: bytes, info: bytes, okm_len: int) -> bytes:
    if len(prk) != 32:
        raise ValueError("prk must be 32 bytes")
    if okm_len <= 0 or okm_len > 255 * 32:
        raise ValueError("okm_len")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < okm_len:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:okm_len]


def hkdf_sha256(
    salt: bytes, ikm: bytes, info: bytes, okm_len: int
) -> bytes:
    return hkdf_expand_sha256(
        hkdf_extract_sha256(salt, ikm), info, okm_len
    )


def to_hex(b: bytes) -> str:
    return b.hex()  # lowercase stable


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# External known-answer pins
# ---------------------------------------------------------------------------

AES_KEY = from_hex("000102030405060708090a0b0c0d0e0f")
AES_PT = from_hex("00112233445566778899aabbccddeeff")
AES_CT = from_hex("69c4e0d86a7b0430d8cdb78070b4c55a")

GCM_EMPTY = (
    bytes(16),
    bytes(12),
    b"",
    b"",
    b"",
    from_hex("58e2fccefa7e3061367f1d57a4e7455a"),
)
GCM_ONE_BLOCK = (
    bytes(16),
    bytes(12),
    b"",
    bytes(16),
    from_hex("0388dace60b6a392f328c2b971b2fe78"),
    from_hex("ab6e47d42cec13bdf53a67b21257bddf"),
)
GCM_AAD_NONBLOCK = (
    from_hex("feffe9928665731c6d6a8f9467308308"),
    from_hex("cafebabefacedbaddecaf888"),
    from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2"),
    from_hex(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39"
    ),
    from_hex(
        "42831ec2217774244b7221b784d0d49c"
        "e3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091"
    ),
    from_hex("5bc94fbc3221a5db94fae95ae7121a47"),
)

SHA_EMPTY = from_hex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
SHA_ABC = from_hex(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
)
SHA_MULTIBLOCK_INPUT = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
SHA_MULTIBLOCK = from_hex(
    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
)

HKDF1_IKM = bytes([0x0B]) * 22
HKDF1_SALT = from_hex("000102030405060708090a0b0c")
HKDF1_INFO = from_hex("f0f1f2f3f4f5f6f7f8f9")
HKDF1_PRK = from_hex(
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
)
HKDF1_OKM = from_hex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)
HKDF2_IKM = bytes(range(0x00, 0x50))
HKDF2_SALT = bytes(range(0x60, 0xB0))
HKDF2_INFO = bytes(range(0xB0, 0x100))
HKDF2_PRK = from_hex(
    "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"
)
HKDF2_OKM = from_hex(
    "b11e398dc80327a1c8e7f78c596a4934"
    "4f012eda2d4efad8a050cc4c19afa97c"
    "59045a99cac7827271cb41c65e590e09"
    "da3275600c2f09b8367793a9aca3db71"
    "cc30c58179ec3e87c14c01d5c1f3434f"
    "1d87"
)

LABELS = (
    ("hop_data_key", b"NINLIL-R6-HOP-DATA-KEY-v1", 16, "hop"),
    ("hop_data_iv", b"NINLIL-R6-HOP-DATA-IV-v1", 12, "hop"),
    ("hop_ack_key", b"NINLIL-R6-HOP-ACK-KEY-v1", 16, "hop"),
    ("hop_ack_iv", b"NINLIL-R6-HOP-ACK-IV-v1", 12, "hop"),
    ("e2e_key", b"NINLIL-R6-E2E-KEY-v1", 16, "e2e"),
    ("e2e_iv", b"NINLIL-R6-E2E-IV-v1", 12, "e2e"),
)


def _opaque(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("opaque too long")
    return len(value).to_bytes(2, "big") + value


def _u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def _u32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def build_binding_inputs() -> tuple[bytes, bytes]:
    site = from_hex("00112233445566778899aabbccddeeff")
    membership_epoch = 0x0102030405060708
    hop = b"".join(
        (
            b"NINLIL-R6-HOP-CTX-v1",
            bytes((0x11, 0x02)),
            _opaque(site),
            _u64(membership_epoch),
            _opaque(b"attachment-a"),
            _u64(9),
            _opaque(b"node-alpha"),
            _opaque(b"node-beta"),
            _opaque(b"controller-1"),
            _u64(7),
            _u32(0x10203040),
            bytes((0,)),
            (3).to_bytes(2, "big"),
        )
    )
    e2e = b"".join(
        (
            b"NINLIL-R6-E2E-CTX-v1",
            bytes((0x11, 0x02)),
            _opaque(site),
            _u64(membership_epoch),
            _opaque(b"e2e-security-1"),
            _u64(3),
            _opaque(b"node-alpha"),
            _opaque(b"node-beta"),
            _opaque(b"controller-1"),
            _u64(7),
            _u32(0x50607080),
            bytes((1,)),
        )
    )
    return hop, e2e


def derive_nonce(static_iv: bytes, counter: int) -> bytes:
    if len(static_iv) != 12:
        raise ValueError("static iv must be 12 bytes")
    if counter <= 0 or counter >= (1 << 64) - 1:
        raise ValueError("counter outside assignable domain")
    suffix = int.from_bytes(static_iv[4:], "big") ^ counter
    return static_iv[:4] + suffix.to_bytes(8, "big")


def _aead_row(
    vector_id: str,
    source: str,
    surface: str,
    key: bytes,
    nonce: bytes,
    aad: bytes,
    plaintext: bytes,
    ciphertext: bytes,
    tag: bytes,
    expect: str = "ok",
) -> dict[str, Any]:
    return {
        "aad": to_hex(aad),
        "ciphertext": to_hex(ciphertext),
        "expect": expect,
        "id": vector_id,
        "key": to_hex(key),
        "kind": "aead",
        "nonce": to_hex(nonce),
        "plaintext": to_hex(plaintext),
        "source": source,
        "surface": surface,
        "tag": to_hex(tag),
    }


def build_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []

    for vector_id, source, fields in (
        ("gcm_nist_empty", "nist_sp_800_38d_empty", GCM_EMPTY),
        ("gcm_nist_one_block", "nist_sp_800_38d_one_block", GCM_ONE_BLOCK),
        (
            "gcm_nist_aad_nonblock",
            "nist_sp_800_38d_aad_nonblock",
            GCM_AAD_NONBLOCK,
        ),
    ):
        vectors.append(_aead_row(vector_id, source, "raw_adapter", *fields))

    key, nonce, aad, plaintext, ciphertext, tag = GCM_ONE_BLOCK
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 1
    vectors.append(
        _aead_row(
            "gcm_nist_one_block_bad_tag",
            "nist_sp_800_38d_negative",
            "raw_adapter",
            key,
            nonce,
            aad,
            plaintext,
            ciphertext,
            bytes(bad_tag),
            "auth_failed",
        )
    )

    r7_key = from_hex("00112233445566778899aabbccddeeff")
    r7_nonce = from_hex("102132435465768798a9bacb")
    for body_len in (0, 1, 15, 16, 17, 220):
        for aad_len in (0, 1, 19):
            aad_bytes = bytes(
                ((0x40 + aad_len + i * 7) & 0xFF) for i in range(aad_len)
            )
            plaintext_bytes = bytes(
                ((0x80 + body_len + i * 11) & 0xFF)
                for i in range(body_len)
            )
            ct, out_tag = aes128_gcm_seal(
                r7_key, r7_nonce, aad_bytes, plaintext_bytes
            )
            vectors.append(
                _aead_row(
                    f"r7_gcm_body_{body_len}_aad_{aad_len}",
                    "r7_boundary_matrix",
                    "portable_wrapper",
                    r7_key,
                    r7_nonce,
                    aad_bytes,
                    plaintext_bytes,
                    ct,
                    out_tag,
                )
            )

    for vector_id, message, digest in (
        ("sha256_empty", b"", SHA_EMPTY),
        ("sha256_abc", b"abc", SHA_ABC),
        ("sha256_multiblock", SHA_MULTIBLOCK_INPUT, SHA_MULTIBLOCK),
    ):
        vectors.append(
            {
                "digest": to_hex(digest),
                "id": vector_id,
                "kind": "sha256",
                "message": to_hex(message),
                "source": "nist_fips_180_4",
                "surface": "portable_wrapper",
            }
        )

    for vector_id, ikm, salt, info, prk, okm in (
        (
            "hkdf_rfc5869_a.1",
            HKDF1_IKM,
            HKDF1_SALT,
            HKDF1_INFO,
            HKDF1_PRK,
            HKDF1_OKM,
        ),
        (
            "hkdf_rfc5869_a.2",
            HKDF2_IKM,
            HKDF2_SALT,
            HKDF2_INFO,
            HKDF2_PRK,
            HKDF2_OKM,
        ),
    ):
        vectors.append(
            {
                "id": vector_id,
                "ikm": to_hex(ikm),
                "info": to_hex(info),
                "kind": "hkdf",
                "okm": to_hex(okm),
                "okm_len": len(okm),
                "prk": to_hex(prk),
                "salt": to_hex(salt),
                "source": "rfc_5869",
                "surface": "raw_adapter",
            }
        )

    hop_input, e2e_input = build_binding_inputs()
    hop_digest = sha256(hop_input)
    e2e_digest = sha256(e2e_input)
    vectors.extend(
        (
            {
                "binding": "hop",
                "digest": to_hex(hop_digest),
                "id": "r6_hop_binding",
                "input": to_hex(hop_input),
                "kind": "binding",
                "source": "docs_30_section_8",
                "surface": "portable_wrapper",
            },
            {
                "binding": "e2e",
                "digest": to_hex(e2e_digest),
                "id": "r6_e2e_binding",
                "input": to_hex(e2e_input),
                "kind": "binding",
                "source": "docs_30_section_8",
                "surface": "portable_wrapper",
            },
        )
    )

    secrets = {"hop": bytes(range(32)), "e2e": bytes(range(32, 64))}
    digests = {"hop": hop_digest, "e2e": e2e_digest}
    for name, label, length, scope in LABELS:
        salt = digests[scope]
        ikm = secrets[scope]
        prk = hkdf_extract_sha256(salt, ikm)
        okm = hkdf_expand_sha256(prk, label, length)
        vectors.append(
            {
                "id": f"r6_schedule_{name}",
                "ikm": to_hex(ikm),
                "info": to_hex(label),
                "kind": "hkdf",
                "okm": to_hex(okm),
                "okm_len": length,
                "prk": to_hex(prk),
                "salt": to_hex(salt),
                "source": "docs_30_section_8",
                "surface": "portable_wrapper",
            }
        )

    static_iv = from_hex("00112233445566778899aabb")
    for name, counter in (
        ("counter_1", 1),
        ("counter_uint64_max_minus_1", (1 << 64) - 2),
    ):
        vectors.append(
            {
                "counter": f"{counter:016x}",
                "id": f"r7_nonce_{name}",
                "kind": "nonce",
                "nonce": to_hex(derive_nonce(static_iv, counter)),
                "source": "docs_30_section_8",
                "static_iv": to_hex(static_iv),
                "surface": "portable_helper",
            }
        )

    return sorted(vectors, key=lambda row: row["id"])


def build_document() -> dict[str, Any]:
    vectors = build_vectors()
    return {
        "artifact": "ninlil_r7_crypto_vectors",
        "c_bridge": {
            "implemented": True,
            "required_vector_count": len(vectors),
            "skip_allowed": False,
            "status": "implemented",
        },
        "schema_version": 1,
        "vector_count": len(vectors),
        "vectors": vectors,
    }


def canonical_json(document: dict[str, Any]) -> bytes:
    text = json.dumps(
        document, ensure_ascii=True, indent=2, sort_keys=True
    ) + "\n"
    data = text.encode("ascii")
    if data != data.lower():
        raise ValueError("canonical json must be lowercase")
    return data


def _c_string(value: str, width: int = 64) -> str:
    if not value:
        return '""'
    chunks = [value[i : i + width] for i in range(0, len(value), width)]
    return "\n        ".join(f'"{chunk}"' for chunk in chunks)


def _header_array(
    rows: list[dict[str, Any]],
    name: str,
    ctype: str,
    fields: tuple[str, ...],
    numeric: frozenset[str] = frozenset(),
) -> list[str]:
    out = [f"static const {ctype} {name}[] = {{"]
    for row in rows:
        values: list[str] = []
        for field in fields:
            value = row[field]
            if field in numeric:
                values.append(f"{value}u")
            else:
                values.append(_c_string(str(value)))
        out.append("    {")
        out.append("        " + ",\n        ".join(values))
        out.append("    },")
    out.append("};")
    return out


def generate_header(document: dict[str, Any], json_bytes: bytes) -> bytes:
    by_kind: dict[str, list[dict[str, Any]]] = {}
    for row in document["vectors"]:
        by_kind.setdefault(row["kind"], []).append(row)
    total = document["vector_count"]
    json_digest = hashlib.sha256(json_bytes).hexdigest()
    lines = [
        "/* generated by tools/r7_radio_wire_oracle.py; test-only private fixture */",
        "/* c bridge status: implemented; this remains a test-only fixture */",
        "/* the c bridge dispatches surface and executes the exact total with no skips */",
        "#ifndef NINLIL_R7_CRYPTO_VECTORS_GEN_H",
        "#define NINLIL_R7_CRYPTO_VECTORS_GEN_H",
        "",
        "#include <stdint.h>",
        "",
        f'#define NINLIL_R7_VECTOR_JSON_SHA256 "{json_digest}"',
        f"#define NINLIL_R7_TEST_VECTOR_COUNT {total}u",
    ]
    for kind in ("aead", "sha256", "hkdf", "binding", "nonce"):
        lines.append(
            f"#define NINLIL_R7_{kind.upper()}_VECTOR_COUNT "
            f"{len(by_kind.get(kind, []))}u"
        )
    lines.extend(
        (
            "",
            (
                "typedef struct { const char *id; const char *surface; "
                "const char *key; const char *nonce; const char *aad; "
                "const char *plaintext; const char *ciphertext; "
                "const char *tag; uint8_t expect_ok; } ninlil_r7_aead_vector;"
            ),
            (
                "typedef struct { const char *id; const char *surface; "
                "const char *message; const char *digest; } "
                "ninlil_r7_sha256_vector;"
            ),
            (
                "typedef struct { const char *id; const char *surface; "
                "const char *salt; const char *ikm; const char *info; "
                "const char *prk; const char *okm; uint16_t okm_len; } "
                "ninlil_r7_hkdf_vector;"
            ),
            (
                "typedef struct { const char *id; const char *surface; "
                "const char *binding; const char *input; const char *digest; } "
                "ninlil_r7_binding_vector;"
            ),
            (
                "typedef struct { const char *id; const char *surface; "
                "const char *static_iv; const char *counter; const char *nonce; } "
                "ninlil_r7_nonce_vector;"
            ),
            "",
        )
    )
    aead_rows = [
        dict(row, expect_ok=1 if row["expect"] == "ok" else 0)
        for row in by_kind["aead"]
    ]
    lines.extend(
        _header_array(
            aead_rows,
            "ninlil_r7_aead_vectors",
            "ninlil_r7_aead_vector",
            (
                "id",
                "surface",
                "key",
                "nonce",
                "aad",
                "plaintext",
                "ciphertext",
                "tag",
                "expect_ok",
            ),
            frozenset(("expect_ok",)),
        )
    )
    lines.extend(
        _header_array(
            by_kind["sha256"],
            "ninlil_r7_sha256_vectors",
            "ninlil_r7_sha256_vector",
            ("id", "surface", "message", "digest"),
        )
    )
    lines.extend(
        _header_array(
            by_kind["hkdf"],
            "ninlil_r7_hkdf_vectors",
            "ninlil_r7_hkdf_vector",
            ("id", "surface", "salt", "ikm", "info", "prk", "okm", "okm_len"),
            frozenset(("okm_len",)),
        )
    )
    lines.extend(
        _header_array(
            by_kind["binding"],
            "ninlil_r7_binding_vectors",
            "ninlil_r7_binding_vector",
            ("id", "surface", "binding", "input", "digest"),
        )
    )
    lines.extend(
        _header_array(
            by_kind["nonce"],
            "ninlil_r7_nonce_vectors",
            "ninlil_r7_nonce_vector",
            ("id", "surface", "static_iv", "counter", "nonce"),
        )
    )
    lines.extend(("", "#endif", ""))
    return "\n".join(lines).encode("ascii")


def artifact_bytes() -> tuple[bytes, bytes]:
    document = build_document()
    json_bytes = canonical_json(document)
    return json_bytes, generate_header(document, json_bytes)


def verify_fixed_pins() -> list[str]:
    errors: list[str] = []
    if aes128_encrypt_block(AES_KEY, AES_PT) != AES_CT:
        errors.append("fips aes-128 c.1 mismatch")
    for name, fields in (
        ("empty", GCM_EMPTY),
        ("one-block", GCM_ONE_BLOCK),
        ("aad-nonblock", GCM_AAD_NONBLOCK),
    ):
        key, nonce, aad, plaintext, ciphertext, tag = fields
        got_ct, got_tag = aes128_gcm_seal(key, nonce, aad, plaintext)
        if (got_ct, got_tag) != (ciphertext, tag):
            errors.append(f"nist gcm {name} seal mismatch")
        if aes128_gcm_open(key, nonce, aad, ciphertext, tag) != plaintext:
            errors.append(f"nist gcm {name} open mismatch")
    for name, message, expected in (
        ("empty", b"", SHA_EMPTY),
        ("abc", b"abc", SHA_ABC),
        ("multiblock", SHA_MULTIBLOCK_INPUT, SHA_MULTIBLOCK),
    ):
        if sha256(message) != expected:
            errors.append(f"sha256 {name} mismatch")
    for name, ikm, salt, info, expected_prk, expected_okm in (
        ("a.1", HKDF1_IKM, HKDF1_SALT, HKDF1_INFO, HKDF1_PRK, HKDF1_OKM),
        ("a.2", HKDF2_IKM, HKDF2_SALT, HKDF2_INFO, HKDF2_PRK, HKDF2_OKM),
    ):
        prk = hkdf_extract_sha256(salt, ikm)
        if prk != expected_prk:
            errors.append(f"rfc5869 {name} prk mismatch")
        if hkdf_expand_sha256(prk, info, len(expected_okm)) != expected_okm:
            errors.append(f"rfc5869 {name} okm mismatch")
    return errors


def verify_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document is not an object"]
    vectors = document.get("vectors")
    if not isinstance(vectors, list):
        return ["vectors is not an array"]
    if document.get("vector_count") != len(vectors):
        errors.append("vector_count does not match vectors length")
    bridge = document.get("c_bridge")
    if not isinstance(bridge, dict):
        errors.append("c_bridge metadata missing")
    else:
        if bridge.get("implemented") is not True:
            errors.append("c bridge implementation status missing")
        if bridge.get("skip_allowed") is not False:
            errors.append("c bridge skip must remain forbidden")
        if bridge.get("status") != "implemented":
            errors.append("c bridge status must be implemented")
        if bridge.get("required_vector_count") != len(vectors):
            errors.append("c bridge required count mismatch")
    ids = [row.get("id") for row in vectors if isinstance(row, dict)]
    if len(ids) != len(vectors) or len(set(ids)) != len(ids):
        errors.append("vector ids missing or duplicated")
    if ids != sorted(ids):
        errors.append("vector ids not in stable order")
    expected = build_document()
    if document != expected:
        errors.append("document differs from independent oracle output")
    try:
        encoded = canonical_json(document)
        if json.loads(encoded) != document:
            errors.append("canonical json round trip mismatch")
    except (TypeError, ValueError) as exc:
        errors.append(f"canonical json rejected: {exc}")
    return errors


def mutation_self_test() -> list[str]:
    errors: list[str] = []
    key, nonce, aad, plaintext, ciphertext, tag = GCM_ONE_BLOCK
    for bit in range(128):
        bad = bytearray(tag)
        bad[bit // 8] ^= 1 << (bit % 8)
        if aes128_gcm_open(key, nonce, aad, ciphertext, bytes(bad)) is not None:
            errors.append(f"gcm tag bit {bit} mutation accepted")
            break
    try:
        aes128_gcm_open(key, nonce, aad, ciphertext, tag[:-1])
    except ValueError:
        pass
    else:
        errors.append("gcm truncated tag was not rejected")
    base_ct, base_tag = aes128_gcm_seal(key, nonce, aad, plaintext)
    changed_key = bytearray(key)
    changed_key[0] ^= 1
    if aes128_gcm_seal(bytes(changed_key), nonce, aad, plaintext) == (base_ct, base_tag):
        errors.append("gcm key mutation did not change sealed output")
    changed_nonce = bytearray(nonce)
    changed_nonce[0] ^= 1
    if aes128_gcm_seal(key, bytes(changed_nonce), aad, plaintext) == (base_ct, base_tag):
        errors.append("gcm nonce mutation did not change sealed output")
    changed_plaintext = bytearray(plaintext)
    changed_plaintext[0] ^= 1
    if aes128_gcm_seal(key, nonce, aad, bytes(changed_plaintext)) == (base_ct, base_tag):
        errors.append("gcm plaintext mutation did not change sealed output")
    changed_ciphertext = bytearray(ciphertext)
    changed_ciphertext[0] ^= 1
    if aes128_gcm_open(key, nonce, aad, bytes(changed_ciphertext), tag) is not None:
        errors.append("gcm ciphertext mutation authenticated")
    aad_key, aad_nonce, aad_value, aad_pt, aad_ct, aad_tag = GCM_AAD_NONBLOCK
    changed_aad = bytearray(aad_value)
    changed_aad[0] ^= 1
    if aes128_gcm_seal(aad_key, aad_nonce, bytes(changed_aad), aad_pt) == (aad_ct, aad_tag):
        errors.append("gcm aad mutation did not change sealed output")
    hop_input, _ = build_binding_inputs()
    salt = sha256(hop_input)
    ikm = bytes(range(32))
    label = LABELS[0][1]
    changed_label = bytearray(label)
    changed_label[0] ^= 1
    if hkdf_sha256(salt, ikm, bytes(changed_label), 16) == hkdf_sha256(
        salt, ikm, label, 16
    ):
        errors.append("hkdf label mutation did not change output")
    baseline_okm = hkdf_sha256(salt, ikm, label, 16)
    changed_salt = bytearray(salt)
    changed_salt[0] ^= 1
    if hkdf_sha256(bytes(changed_salt), ikm, label, 16) == baseline_okm:
        errors.append("hkdf salt mutation did not change output")
    changed_ikm = bytearray(ikm)
    changed_ikm[0] ^= 1
    if hkdf_sha256(salt, bytes(changed_ikm), label, 16) == baseline_okm:
        errors.append("hkdf ikm mutation did not change output")
    static_iv = from_hex("00112233445566778899aabb")
    for invalid_counter in (0, (1 << 64) - 1):
        try:
            derive_nonce(static_iv, invalid_counter)
        except ValueError:
            pass
        else:
            errors.append(f"invalid nonce counter accepted: {invalid_counter}")
    original = build_document()
    mutated = json.loads(canonical_json(original))
    mutated["vector_count"] += 1
    if not verify_document(mutated):
        errors.append("count mutation escaped document verifier")
    mutated = json.loads(canonical_json(original))
    mutated["c_bridge"]["skip_allowed"] = True
    if not verify_document(mutated):
        errors.append("bridge skip mutation escaped document verifier")
    mutated = json.loads(canonical_json(original))
    bad_row = next(
        row for row in mutated["vectors"]
        if row["id"] == "gcm_nist_one_block_bad_tag"
    )
    bad_row["tag"] = to_hex(tag)
    if not verify_document(mutated):
        errors.append("bad-tag mutation escaped document verifier")
    return errors


def self_check() -> int:
    errors = verify_fixed_pins() + mutation_self_test()
    document = build_document()
    errors.extend(verify_document(document))
    json_a, header_a = artifact_bytes()
    json_b, header_b = artifact_bytes()
    if (json_a, header_a) != (json_b, header_b):
        errors.append("two in-process artifact generations differ")
    if errors:
        for error in errors:
            print(f"r7_radio_wire_oracle FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "r7_radio_wire_oracle self-test OK "
        f"vectors={document['vector_count']} c_bridge=implemented"
    )
    return 0


def verify_json_file(path: pathlib.Path) -> int:
    try:
        document = json.loads(path.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"r7_radio_wire_oracle FAIL: {exc}", file=sys.stderr)
        return 1
    errors = verify_document(document)
    if errors:
        for error in errors:
            print(f"r7_radio_wire_oracle FAIL: {error}", file=sys.stderr)
        return 1
    print(f"r7_radio_wire_oracle verify-json OK vectors={document['vector_count']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="R7 T0 independent crypto oracle")
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
