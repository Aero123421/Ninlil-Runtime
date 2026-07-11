#!/usr/bin/env python3
"""Independent D1-A/D1-B1/D1-B2/D1-B3a..i vector oracle (stdlib only; no production C linkage).

Sole oracle implementation for the checked-in domain-store-v1 vector catalog.
Uses hashlib + independent encoders only. Body encode oracles for D1-B1/B2/B3a..i
are hand-written here and intentionally do not import or link production C.

D1 pre-alpha operation identity correction: kind 9/10 identities are exact 42
bytes (digest[32] || token_generation:u64 || phase:u16). Legacy 40-byte form is
rejected. Within the historical 1032-vector prefix, only the seven kind9/10
fixture IDs listed in KIND910_REFIXED_IDS are re-pinned; all other prefix
vectors remain byte-for-byte immutable.

Usage:
  python3 tools/domain_store_vector_gen.py generate <path>
  python3 tools/domain_store_vector_gen.py check <path>
  python3 tools/domain_store_vector_gen.py <path>   # legacy generate alias
"""
import hashlib, json, struct, binascii, sys
from pathlib import Path

def be16(v): return struct.pack(">H", v)
def be32(v): return struct.pack(">I", v)
def be64(v): return struct.pack(">Q", v)

def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFFFFFF

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

# Independent SHA-256 compression (for synthetic ctx_final without hashlib state import).
_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]
_IV = [
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
]

def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def _compress(state, block):
    w = [struct.unpack(">I", block[i:i+4])[0] for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = _rotr(w[i-15], 7) ^ _rotr(w[i-15], 18) ^ (w[i-15] >> 3)
        s1 = _rotr(w[i-2], 17) ^ _rotr(w[i-2], 19) ^ (w[i-2] >> 10)
        w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
    a,b,c,d,e,f,g,h = state
    for i in range(64):
        S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        t1 = (h + S1 + ch + _K[i] + w[i]) & 0xFFFFFFFF
        S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t2 = (S0 + maj) & 0xFFFFFFFF
        h,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xFFFFFFFF,c,b,a,(t1+t2)&0xFFFFFFFF
    return [(state[i] + [a,b,c,d,e,f,g,h][i]) & 0xFFFFFFFF for i in range(8)]

def sha256_final_from_iv_buffer(buffer: bytes, completed_block_bits: int) -> bytes:
    """Finalize from IV with synthetic completed-block bit count + partial buffer."""
    state = list(_IV)
    total_bits = completed_block_bits + len(buffer) * 8
    buf = bytearray(buffer)
    buf.append(0x80)
    while (len(buf) % 64) != 56:
        buf.append(0)
    buf += struct.pack(">Q", total_bits & ((1 << 64) - 1))
    for i in range(0, len(buf), 64):
        state = _compress(state, bytes(buf[i:i+64]))
    return b"".join(struct.pack(">I", x) for x in state)

ROOT = bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x01])

def composite(subtype, components: bytes) -> bytes:
    return sha256(b"NINLIL-DOMAIN-KEY-V1" + bytes([subtype]) + components)

def key_digest(key: bytes) -> bytes:
    return sha256(b"NINLIL-DOMAIN-ENCODED-KEY-V1" + key)

def health_id(priority, kind, identity: bytes) -> bytes:
    return sha256(
        b"NINLIL-DOMAIN-HEALTH-SOURCE-V1"
        + bytes([priority])
        + be16(kind)
        + be16(len(identity))
        + identity
    )

def fence_dig(kind, identity: bytes) -> bytes:
    return sha256(b"NINLIL-DOMAIN-COMMIT-FENCE-V1" + be16(kind) + be16(len(identity)) + identity)

def bkey(fam, st, kind, ident: bytes) -> bytes:
    return ROOT + bytes([fam, st, 1, kind, len(ident)]) + ident

F6 = [
    (0x10, 5, 32, 768), (0x11, 5, 32, 512), (0x20, 2, 16, 1536), (0x21, 3, 8, 64),
    (0x22, 2, 16, 512), (0x23, 5, 32, 512), (0x24, 5, 32, 512), (0x25, 5, 32, 512),
    (0x26, 3, 8, 512), (0x27, 3, 8, 1536), (0x30, 5, 32, 3264), (0x31, 5, 32, 512),
    (0x32, 5, 32, 1024), (0x33, 5, 32, 512), (0x34, 2, 16, 128), (0x40, 5, 32, 1024),
    (0x41, 5, 32, 1024), (0x42, 5, 32, 3264), (0x50, 2, 16, 1536), (0x51, 5, 32, 768),
    (0x52, 5, 32, 1024), (0x60, 1, 0, 64), (0x61, 5, 32, 512), (0x62, 1, 0, 64),
    (0x63, 5, 32, 512), (0x64, 1, 0, 64), (0x7D, 5, 32, 192), (0x7E, 5, 32, 3000),
    (0x7F, 5, 32, 384),
]

def allow_zero_head(fam, st):
    return (fam == 5 and st == 0x01) or (fam == 6 and st in (0x62, 0x7D, 0x7E, 0x7F))

def pvd_zero(fam, st):
    if fam == 5:
        return True
    return fam == 6 and st in (0x10, 0x20, 0x27, 0x40, 0x60, 0x62, 0x64, 0x7D, 0x7E, 0x7F)

def enc_env(rtype, st, flags, rev, head, pvd, body: bytes) -> bytes:
    payload = 96 + len(body)
    out = bytearray()
    out += b"NLR1" + be16(rtype) + be16(1) + be32(payload)
    out += be16(1) + bytes([st, flags]) + be64(rev)
    out += bytes(16) + head + pvd + be32(len(body)) + body
    out += be32(crc32c(bytes(out)))
    return bytes(out)

def hx(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def subject_prefix_from_key(complete_key: bytes) -> bytes:
    return key_digest(complete_key)[:16]


def ordered_ingress_key(seq_be: bytes) -> bytes:
    return ROOT + bytes([6, 0x27, 1, 3, 8]) + seq_be


def family4_capacity_key(resource_kind: int) -> bytes:
    return ROOT + bytes([0x04, resource_kind & 0xFF])


def family3_counter_key(kind: int) -> bytes:
    return ROOT + bytes([0x03, kind & 0xFF])


def bearer_state_key() -> bytes:
    return ROOT + bytes([6, 0x60, 1, 1, 0])


def clock_baseline_key() -> bytes:
    return ROOT + bytes([6, 0x62, 1, 1, 0])


def fence_key() -> bytes:
    return ROOT + bytes([6, 0x64, 1, 1, 0])


def invariant_marker_id(reason: int, subject_kind: int, subject_digest: bytes) -> bytes:
    return sha256(
        b"NINLIL-DOMAIN-INVARIANT-V1"
        + be32(reason)
        + be16(subject_kind)
        + subject_digest
    )[:16]


def enc_body_invariant(reason, subject_kind, subject_digest, epoch, at_ms, detail) -> bytes:
    return (
        be32(reason)
        + be16(subject_kind)
        + be16(0)
        + subject_digest
        + epoch
        + be64(at_ms)
        + detail
    )


def enc_body_bearer(epoch, available, clock_epoch, at_ms) -> bytes:
    return be64(epoch) + be32(available) + clock_epoch + be64(at_ms)


def enc_body_clock(state, epoch, now_ms, generation) -> bytes:
    return be32(state) + be32(0) + epoch + be64(now_ms) + be64(generation)


def enc_body_fence(count, generation) -> bytes:
    return be32(count) + be32(0) + be64(generation)


def enc_body_head_index(index_state, member_key, value_dig, head_dig) -> bytes:
    mkd = key_digest(member_key)
    return (
        be16(index_state)
        + be16(0)
        + mkd
        + be16(len(member_key))
        + be16(0)
        + member_key
        + value_dig
        + head_dig
    )




def text_id(s: bytes) -> bytes:
    assert 1 <= len(s) <= 63
    return bytes([len(s)]) + s


def local_identity(flags, device, installation, site, bind_ep, mem_ep) -> bytes:
    return be32(flags) + device + installation + site + be64(bind_ep) + be64(mem_ep)


def party(rt, app, li: bytes) -> bytes:
    return rt + app + li


def target(flags, trt, tapp, device, installation, site, bind_ep, mem_ep) -> bytes:
    return (
        be32(flags) + trt + tapp + device + installation + site
        + be64(bind_ep) + be64(mem_ep)
    )


def service_identity(ns, svc, schema, rev, dig, major, minor, family) -> bytes:
    return (
        text_id(ns) + text_id(svc) + text_id(schema) + be64(rev) + dig
        + be16(major) + be16(minor) + be32(family)
    )


def raw16(contents: bytes) -> bytes:
    assert len(contents) <= 255
    return be16(len(contents)) + contents


def service_key_raw(app, ns, svc, rev, dig) -> bytes:
    return app + text_id(ns) + text_id(svc) + be64(rev) + dig


def resource_vector(pairs) -> bytes:
    # pairs: list of (used, reserved) length 11
    assert len(pairs) == 11
    out = b""
    for u, r in pairs:
        out += be64(u) + be64(r)
    return out


def scope_raw(app, ns, svc) -> bytes:
    return app + text_id(ns) + text_id(svc)


def primary_id_from_identity(kind, identity: bytes) -> bytes:
    """Encode identity kind/bytes into 16-byte primary_id form (docs17 §4)."""
    if kind == 1:
        return bytes(16)
    if kind == 2:
        return identity[:16]
    if kind == 3:
        return bytes(8) + identity[:8]
    if kind in (4, 5):
        return identity[:16]
    raise ValueError("bad identity kind")


def primary_id_from_composite_subtype(subtype: int, components: bytes) -> bytes:
    """Referenced primary composite identity first 16 (not secondary self-key)."""
    return composite(subtype, components)[:16]


def complete_key_digest_composite(subtype: int, components: bytes) -> bytes:
    """KEY_DIGEST of complete family-6 composite-identity key (kind 5)."""
    return key_digest(bkey(6, subtype, 5, composite(subtype, components)))


def complete_key_digest_id128(subtype: int, identity16: bytes) -> bytes:
    """KEY_DIGEST of complete family-6 ID128 key (kind 2)."""
    assert len(identity16) == 16
    return key_digest(bkey(6, subtype, 2, identity16))


def complete_key_digest_u64(subtype: int, identity8: bytes) -> bytes:
    """KEY_DIGEST of complete family-6 u64 key (kind 3)."""
    assert len(identity8) == 8
    return key_digest(bkey(6, subtype, 3, identity8))


def reservation_primary_key_digest(owner_kind: int, owner_raw_contents: bytes) -> bytes:
    """
    KEY_DIGEST of the referenced primary complete key (docs17 §5.1 / §9).
    Independent of production C helpers.
    """
    if owner_kind == 1:  # SERVICE
        return complete_key_digest_composite(0x10, raw16(owner_raw_contents))
    if owner_kind == 2:  # TRANSACTION → TRANSACTION_ANCHOR
        return complete_key_digest_id128(0x20, owner_raw_contents)
    if owner_kind == 3:  # INGRESS → ORDERED_INGRESS
        return complete_key_digest_u64(0x27, owner_raw_contents)
    if owner_kind == 4:  # DELIVERY
        return complete_key_digest_composite(0x40, raw16(owner_raw_contents))
    if owner_kind == 5:  # CALLBACK → DELIVERY from embedded delivery RAW16 prefix
        dlen = int.from_bytes(owner_raw_contents[:2], "big")
        return complete_key_digest_composite(
            0x40, owner_raw_contents[: 2 + dlen])
    raise ValueError("bad owner kind")


def scheduler_primary_key_digest(owner_kind: int, subject_raw: bytes) -> bytes:
    """
    KEY_DIGEST of SCHEDULER referenced primary (docs17 §5.1 / §8.3).
    owner_kind is scheduler enum: 1 TRANSACTION, 2 DELIVERY, 3 INGRESS.
    """
    if owner_kind == 1:  # TRANSACTION → TRANSACTION_ANCHOR ID128
        return complete_key_digest_id128(0x20, subject_raw)
    if owner_kind == 2:  # DELIVERY composite(delivery_key_raw:RAW16)
        return complete_key_digest_composite(0x40, raw16(subject_raw))
    if owner_kind == 3:  # INGRESS → ORDERED_INGRESS u64
        return complete_key_digest_u64(0x27, subject_raw)
    raise ValueError("bad scheduler owner kind")


def scheduler_primary_id(owner_kind: int, subject_raw: bytes) -> bytes:
    """Common primary_id form for SCHEDULER secondary (not owner_sequence)."""
    if owner_kind == 1:
        return subject_raw  # transaction_id
    if owner_kind == 2:
        return primary_id_from_composite_subtype(0x40, raw16(subject_raw))
    if owner_kind == 3:
        return primary_id_from_identity(3, subject_raw)
    raise ValueError("bad scheduler owner kind")


def blob_owner_primary_key_digest(owner_kind: int, owner_raw: bytes) -> bytes:
    """KEY_DIGEST of BLOB owner primary complete key (BLOB enum: 1 TX, 2 ING, 3 DLV)."""
    if owner_kind == 1:  # TRANSACTION
        return complete_key_digest_id128(0x20, owner_raw)
    if owner_kind == 2:  # INGRESS
        return complete_key_digest_u64(0x27, owner_raw)
    if owner_kind == 3:  # DELIVERY
        return complete_key_digest_composite(0x40, raw16(owner_raw))
    raise ValueError("bad blob owner kind")


def blob_owner_primary_id(owner_kind: int, owner_raw: bytes) -> bytes:
    if owner_kind == 1:
        return owner_raw
    if owner_kind == 2:
        return primary_id_from_identity(3, owner_raw)
    if owner_kind == 3:
        return primary_id_from_composite_subtype(0x40, raw16(owner_raw))
    raise ValueError("bad blob owner kind")


def blob_id_digest(
    owner_kind: int, owner_raw: bytes, blob_kind: int,
    content_digest: bytes, total_length: int,
) -> bytes:
    return sha256(
        b"NINLIL-DOMAIN-BLOB-ID-V1"
        + be16(owner_kind)
        + raw16(owner_raw)
        + be16(blob_kind)
        + content_digest
        + be64(total_length)
    )


def blob_chunk_count_for_total(total_length: int):
    """Checked ceil(total/3072) as u32; 0 length → 0; overflow → None.

    Uses exact Python integers only — no host narrowing of the product.
    """
    if total_length == 0:
        return 0
    if total_length < 0:
        return None
    max_chunk = 3072
    u32_max = 0xFFFFFFFF
    if total_length > ((1 << 64) - 1) - (max_chunk - 1):
        return None
    chunks = (total_length + max_chunk - 1) // max_chunk
    if chunks == 0 or chunks > u32_max:
        return None
    return int(chunks)


def enc_env_full(rtype, st, flags, rev, primary_id, head, pvd, body: bytes) -> bytes:
    payload = 96 + len(body)
    out = bytearray()
    out += b"NLR1" + be16(rtype) + be16(1) + be32(payload)
    out += be16(1) + bytes([st, flags]) + be64(rev)
    out += primary_id + head + pvd + be32(len(body)) + body
    out += be32(crc32c(bytes(out)))
    return bytes(out)


def canonical_op(kind, ident, subject, manifest, ret_kind, ret_dig):
    return sha256(
        b"NINLIL-DOMAIN-OPERATION-V1"
        + be16(kind)
        + be16(len(ident))
        + ident
        + subject
        + manifest
        + be16(ret_kind)
        + ret_dig
    )


def encode_witness_header(
    kind, state, ident, subject, canon, members, chunks, manifest, ret_kind, ret_dig, succ
):
    out = bytearray()
    out += be16(kind) + be16(state) + be16(len(ident)) + ident
    out += subject + canon + be16(members) + be16(chunks) + manifest
    out += be16(ret_kind) + be16(0) + ret_dig + succ
    return bytes(out)


def build_document():
    vectors = []
    def add(**kw):
        base = dict(
            required_workspace_bytes=0, family=0, subtype=0, identity_kind=0,
            record_type=0, flags=0, revision=0, priority=0, source_kind=0,
            fence_kind=0, operation_kind=0, member_count=0, chunk_count=0,
            body_length=0, key_length=0, sha_bit_length=0, sha_buffer_length=0,
            witness_state=0, retention_kind=0,
            identity_hex="", key_hex="", value_hex="", body_hex="", head_hex="",
            pvd_hex="", digest_hex="", digest2_hex="", crc_hex="", notes="",
            subject_hex="", retention_hex="", manifest_hex="", successor_hex="",
            chunk_bodies_hex=[],
        )
        base.update(kw)
        vectors.append(base)

    add(id="DSK1_SHA256_EMPTY", suite="DSK1", op="sha256", expected_status="OK",
        body_hex="", digest_hex=hx(sha256(b"")))
    add(id="DSK1_SHA256_ABC", suite="DSK1", op="sha256", expected_status="OK",
        body_hex=hx(b"abc"), digest_hex=hx(sha256(b"abc")))
    # Max byte-aligned message bits = UINT64_MAX-7. Context stores completed
    # blocks (multiple of 512) + buffer_length; not the total in bit_length alone.
    max_msg_bits = (2**64) - 8  # UINT64_MAX - 7
    completed = max_msg_bits & ~511
    buf_bytes = (max_msg_bits - completed) // 8  # 63
    syn_buf = bytes([0x5A] * buf_bytes)
    max_final_dig = sha256_final_from_iv_buffer(syn_buf, completed)
    add(id="DSK1_SHA_MAX_MSG_FINAL", suite="DSK1", op="sha256_ctx_final", expected_status="OK",
        sha_bit_length=completed, sha_buffer_length=buf_bytes,
        body_hex=hx(syn_buf),
        digest_hex=hx(max_final_dig),
        notes="UINT64_MAX-7 message bits; padding not counted against message limit")
    add(id="DSK1_SHA_OVERFLOW_UPDATE", suite="DSK1", op="sha256_ctx_update", expected_status="INVALID_ARGUMENT",
        sha_bit_length=completed, sha_buffer_length=buf_bytes, body_hex="01")
    add(id="DSK1_SHA_BAD_BUFFER_LEN", suite="DSK1", op="sha256_ctx_update", expected_status="INVALID_ARGUMENT",
        sha_bit_length=0, sha_buffer_length=64, body_hex="01")
    add(id="DSK1_SHA_BAD_BIT_ALIGN", suite="DSK1", op="sha256_ctx_update", expected_status="INVALID_ARGUMENT",
        sha_bit_length=8, sha_buffer_length=0, body_hex="01")
    add(id="DSV1_CRC32C_123456789", suite="DSV1", op="crc32c", expected_status="OK",
        body_hex=hx(b"123456789"), crc_hex=f"{crc32c(b'123456789'):08x}")

    ident = bytes(range(0xA0, 0xB0))
    k = bkey(5, 0x01, 2, ident)
    add(id="DSK1_KEY_F5_01", suite="DSK1", op="key_build", expected_status="OK",
        family=5, subtype=0x01, identity_kind=2, identity_hex=hx(ident),
        key_hex=hx(k), digest_hex=hx(key_digest(k)))
    for st, ik, il, mx in F6:
        if ik == 1:
            ident = b""
        elif ik == 2:
            ident = bytes([(0x10 + st + i) & 0xFF for i in range(16)])
        elif ik == 3:
            ident = be64(0x0102030405060708)
        else:
            ident = composite(st, be16(1) + be16(0))
        k = bkey(6, st, ik, ident)
        add(id=f"DSK1_KEY_F6_{st:02X}", suite="DSK1", op="key_build", expected_status="OK",
            family=6, subtype=st, identity_kind=ik, identity_hex=hx(ident),
            key_hex=hx(k), digest_hex=hx(key_digest(k)))

    add(id="DSK1_KEY_UNKNOWN_SUBTYPE", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT + bytes([6, 0x01, 1, 1, 0])))
    add(id="DSK1_KEY_VERSION_0", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT[:7] + bytes([0])))
    add(id="DSK1_KEY_FUTURE_PREFIX", suite="DSK1", op="key_classify", expected_status="UNSUPPORTED",
        key_hex=hx(ROOT[:7] + bytes([2, 0xAA])))
    add(id="DSK1_KEY_WRONG_ID_LEN", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT + bytes([6, 0x60, 1, 1, 1, 0x00])))
    add(id="DSK1_KEY_FORMAT_0", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT + bytes([6, 0x60, 0, 1, 0])))
    add(id="DSK1_KEY_FORMAT_2", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT + bytes([6, 0x60, 2, 1, 0])))
    add(id="DSK1_KEY_UNKNOWN_KIND", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT + bytes([6, 0x60, 1, 9, 0])))
    k = bkey(6, 0x60, 1, b"")
    add(id="DSK1_KEY_TRAILING", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(k + b"\x00"))
    add(id="DSK1_KEY_SHORT", suite="DSK1", op="key_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT + bytes([6, 0x60, 1, 1])))  # missing identity length

    # primary_id_from_identity positives + length-wrap negatives
    add(id="DSK1_PRIMARY_SINGLETON", suite="DSK1", op="primary_id", expected_status="OK",
        identity_kind=1, identity_hex="", digest_hex=hx(bytes(16)))
    id16 = bytes(range(16))
    add(id="DSK1_PRIMARY_ID128", suite="DSK1", op="primary_id", expected_status="OK",
        identity_kind=2, identity_hex=hx(id16), digest_hex=hx(id16))
    u64id = be64(0x0102030405060708)
    add(id="DSK1_PRIMARY_U64", suite="DSK1", op="primary_id", expected_status="OK",
        identity_kind=3, identity_hex=hx(u64id), digest_hex=hx(bytes(8) + u64id))
    raw32 = bytes(range(32))
    add(id="DSK1_PRIMARY_SHA_RAW", suite="DSK1", op="primary_id", expected_status="OK",
        identity_kind=4, identity_hex=hx(raw32), digest_hex=hx(raw32[:16]))
    add(id="DSK1_PRIMARY_SHA_COMP", suite="DSK1", op="primary_id", expected_status="OK",
        identity_kind=5, identity_hex=hx(raw32), digest_hex=hx(raw32[:16]))
    for kind, base_len, name in [
        (1, 0, "SINGLETON"), (2, 16, "ID128"), (3, 8, "U64"),
        (4, 32, "SHA_RAW"), (5, 32, "SHA_COMP"),
    ]:
        wrap = base_len + 256
        add(id=f"DSK1_PRIMARY_{name}_LEN_PLUS256", suite="DSK1", op="primary_id",
            expected_status="INVALID_ARGUMENT", identity_kind=kind,
            identity_hex=hx(bytes([0xAB] * wrap)))
    add(id="DSK1_PRIMARY_MALFORMED_VIEW", suite="DSK1", op="primary_id",
        expected_status="INVALID_ARGUMENT", identity_kind=2, body_length=4,
        notes="NULL data with nonzero length via body_length sentinel")

    fval = enc_env(6, 0x62, 0, 1, bytes(32), bytes(32), b"")
    add(id="DSK1_ROW_FUTURE_OK", suite="DSK1", op="row_classify", expected_status="UNSUPPORTED",
        key_hex=hx(ROOT[:7] + bytes([2])), value_hex=hx(fval))
    add(id="DSK1_ROW_FUTURE_BAD_CRC", suite="DSK1", op="row_classify", expected_status="CORRUPT",
        key_hex=hx(ROOT[:7] + bytes([2])), value_hex=hx(fval[:-1] + bytes([fval[-1] ^ 1])))

    for st, ik, il, mx in [(0x01, 2, 16, 96)] + list(F6):
        fam = 5 if st == 0x01 else 6
        rtype = 5 if fam == 5 else 6
        flags = 1 if st == 0x30 else 0
        head = bytes(32) if allow_zero_head(fam, st) else bytes([0x11] * 32)
        pvd = bytes(32) if pvd_zero(fam, st) else bytes([0x22] * 32)
        body = bytes([0x5A] * mx)
        val = enc_env(rtype, st, flags, 1, head, pvd, body)
        add(id=f"DSV1_BODY_{st:02X}_EXACT", suite="DSV1", op="envelope_encode", expected_status="OK",
            record_type=rtype, subtype=st, flags=flags, revision=1, body_length=mx,
            body_hex=hx(body), head_hex=hx(head), pvd_hex=hx(pvd),
            value_hex=hx(val), digest_hex=hx(sha256(val)), crc_hex=f"{crc32c(val[:-4]):08x}")
        add(id=f"DSV1_BODY_{st:02X}_PLUS1", suite="DSV1", op="envelope_encode", expected_status="INVALID_ARGUMENT",
            record_type=rtype, subtype=st, flags=flags, revision=1, body_length=mx + 1,
            body_hex=hx(bytes([0x5A] * (mx + 1))), head_hex=hx(head), pvd_hex=hx(pvd))

    val = enc_env(6, 0x62, 0, 1, bytes(32), bytes(32), b"")
    add(id="DSV1_CRC_MUTATION", suite="DSV1", op="envelope_decode", expected_status="CORRUPT",
        value_hex=hx(val[:-1] + bytes([val[-1] ^ 1])))
    add(id="DSV1_TRAILING", suite="DSV1", op="envelope_decode", expected_status="CORRUPT", value_hex=hx(val + b"\x00"))
    add(id="DSV1_SHORT", suite="DSV1", op="envelope_decode", expected_status="CORRUPT", value_hex=hx(val[:-1]))
    tmp = bytearray(val); tmp[6:8] = be16(2); tmp[-4:] = be32(crc32c(bytes(tmp[:-4])))
    add(id="DSV1_RECORD_VERSION_2", suite="DSV1", op="envelope_decode", expected_status="UNSUPPORTED", value_hex=hx(bytes(tmp)))
    pl = 2; tmp = bytearray(b"NLR1" + be16(6) + be16(1) + be32(pl) + be16(2)); tmp += be32(crc32c(bytes(tmp)))
    add(id="DSV1_DOMAIN_FORMAT_2", suite="DSV1", op="envelope_decode", expected_status="UNSUPPORTED", value_hex=hx(bytes(tmp)))
    payload = 4096 - 16
    fut = bytearray(b"NLR1" + be16(99) + be16(2) + be32(payload) + bytes([0xAB] * payload))
    fut += be32(crc32c(bytes(fut)))
    assert len(fut) == 4096
    add(id="DSV1_FUTURE_NLR1_4096", suite="DSV1", op="row_classify", expected_status="UNSUPPORTED",
        key_hex=hx(ROOT[:7] + bytes([3, 0])), value_hex=hx(bytes(fut)))
    add(id="DSV1_VALUE_4097", suite="DSV1", op="envelope_decode", expected_status="CORRUPT",
        value_hex=hx(bytes(fut) + b"\x00"))
    add(id="DSV1_BEARER_ZERO_HEAD", suite="DSV1", op="envelope_encode", expected_status="INVALID_ARGUMENT",
        record_type=6, subtype=0x60, flags=0, revision=1, body_length=0,
        body_hex="", head_hex=hx(bytes(32)), pvd_hex=hx(bytes(32)))
    add(id="DSV1_SERVICE_REV2", suite="DSV1", op="envelope_encode", expected_status="INVALID_ARGUMENT",
        record_type=6, subtype=0x10, flags=0, revision=2, body_length=0,
        body_hex="", head_hex=hx(bytes([0x11] * 32)), pvd_hex=hx(bytes(32)))
    add(id="DSV1_BLOB_CHUNK_DATA_0", suite="DSV1", op="blob_chunk_data_len", expected_status="OK", body_length=0)
    add(id="DSV1_BLOB_CHUNK_DATA_3072", suite="DSV1", op="blob_chunk_data_len", expected_status="OK", body_length=3072)
    add(id="DSV1_BLOB_CHUNK_DATA_3073", suite="DSV1", op="blob_chunk_data_len", expected_status="INVALID_ARGUMENT", body_length=3073)

    id8 = be16(1) + be16(1) + be32(0)
    id32 = bytes(range(32))
    health_pos = [
        (1, 1, id8, "01_CREATE"), (2, 2, id32, "02_COMMIT"), (3, 3, id32, "03_CALLBACK"),
        (4, 4, id32, "04_APP"), (6, 5, bytes([0x41] * 32) + be16(1) + bytes([0x42] * 16), "05_CLOCK"),
        (7, 6, id32, "06_F3"), (7, 7, id32, "07_F4"),
        (7, 8, id32 + be16(1), "08_EVENT"), (7, 9, id32, "09_RETENTION"),
        (7, 10, id32, "10_DELIVERY"), (8, 11, id32, "11_INVARIANT"), (7, 12, id32, "12_SEND"),
    ]
    for p, k, ident, name in health_pos:
        add(id=f"DSH2_HEALTH_{name}", suite="DSH2", op="health_source_id", expected_status="OK",
            priority=p, source_kind=k, identity_hex=hx(ident), digest_hex=hx(health_id(p, k, ident)))
    add(id="DSH2_HEALTH_P5_NONE", suite="DSH2", op="health_source_id", expected_status="INVALID_ARGUMENT",
        priority=5, source_kind=1, identity_hex=hx(id8))
    add(id="DSH2_HEALTH_BAD_STAGE", suite="DSH2", op="health_source_id", expected_status="INVALID_ARGUMENT",
        priority=1, source_kind=1, identity_hex=hx(be16(9) + be16(1) + be32(0)))
    add(id="DSH2_HEALTH_BAD_METHOD", suite="DSH2", op="health_source_id", expected_status="INVALID_ARGUMENT",
        priority=1, source_kind=1, identity_hex=hx(be16(1) + be16(12) + be32(0)))
    add(id="DSH2_HEALTH_BAD_TIMER", suite="DSH2", op="health_source_id", expected_status="INVALID_ARGUMENT",
        priority=6, source_kind=5, identity_hex=hx(bytes([0x41] * 32) + be16(9) + bytes([0x42] * 16)))
    add(id="DSH2_HEALTH_ZERO_EPOCH", suite="DSH2", op="health_source_id", expected_status="INVALID_ARGUMENT",
        priority=6, source_kind=5, identity_hex=hx(bytes([0x41] * 32) + be16(1) + bytes(16)))
    add(id="DSH2_HEALTH_BAD_EVENT_KIND", suite="DSH2", op="health_source_id", expected_status="INVALID_ARGUMENT",
        priority=7, source_kind=8, identity_hex=hx(id32 + be16(6)))
    add(id="DSH2_HEALTH_BAD_LEN", suite="DSH2", op="health_source_id", expected_status="INVALID_ARGUMENT",
        priority=2, source_kind=2, identity_hex=hx(id32[:31]))
    for fk, ident, name in [(1, id32, "1_WITNESS"), (2, ROOT, "2_BOOTSTRAP"), (3, id32, "3_CLOCK"), (4, id32, "4_IDENTITY")]:
        add(id=f"DSH2_FENCE_{name}", suite="DSH2", op="commit_fence_digest", expected_status="OK",
            fence_kind=fk, identity_hex=hx(ident), digest_hex=hx(fence_dig(fk, ident)))
    add(id="DSH2_FENCE_BAD_LEN", suite="DSH2", op="commit_fence_digest", expected_status="INVALID_ARGUMENT",
        fence_kind=1, identity_hex=hx(id32[:31]))

    def op_id(k):
        # kind 9/10: 42 = digest[32] || token_generation:u64 || phase:u16
        # (D1 pre-alpha operation identity correction; legacy 40 not accepted)
        L = {1: 32, 2: 16, 3: 16, 4: 8, 5: 32, 6: 40, 7: 8, 8: 8, 9: 42, 10: 42, 11: 50,
             12: 42, 13: 8, 14: 42, 15: 32, 16: 32, 17: 14, 18: 42, 19: 24, 20: 8, 21: 66}[k]
        b = bytearray([(0x20 + (i & 0x1F)) for i in range(L)])
        if k == 6:
            b[32:40] = be64(1)
        if k in (9, 10):
            b[32:40] = be64(1)
            b[40:42] = be16(1)  # phase 1 default
        if k == 11:
            b[32:40] = be64(1); b[40:48] = be64(1); b[48:50] = be16(1)
        if k == 12:
            b[32:40] = be64(1); b[40:42] = be16(1)
        if k == 14:
            b[32:34] = be16(1); b[34:42] = be64(1)
        if k in (15, 16):
            b[16:32] = bytes([0xAB] * 16)
        if k == 17:
            b[0:2] = be16(1); b[2:10] = be64(1); b[10:14] = be32(0)
        if k == 18:
            b[32:34] = be16(1); b[34:42] = be64(1)
        if k == 19:
            b[16:24] = be64(1)
        if k == 20:
            b[0:8] = be64(1)
        if k == 21:
            b[64:66] = be16(1)
        return bytes(b)

    def wid(k, ident):
        return composite(0x7F, be16(k) + be16(len(ident)) + ident)

    for k in range(1, 22):
        ident = op_id(k)
        add(id=f"DSO2_KIND_{k:02d}", suite="DSO2", op="witness_identity_digest", expected_status="OK",
            operation_kind=k, identity_hex=hx(ident), digest_hex=hx(wid(k, ident)))
    # Closed-value / zero-field boundaries for identity validator
    for name, k, mut in [
        ("02_ZERO_TX", 2, lambda b: b.__setitem__(slice(0, 16), bytes(16))),
        ("03_ZERO_TX", 3, lambda b: b.__setitem__(slice(0, 16), bytes(16))),
        ("04_ZERO_SEQ", 4, lambda b: b.__setitem__(slice(0, 8), be64(0))),
        ("07_ZERO_SEQ", 7, lambda b: b.__setitem__(slice(0, 8), be64(0))),
        ("08_ZERO_SEQ", 8, lambda b: b.__setitem__(slice(0, 8), be64(0))),
        ("13_ZERO_SEQ", 13, lambda b: b.__setitem__(slice(0, 8), be64(0))),
        ("06_ZERO_GEN", 6, lambda b: b.__setitem__(slice(32, 40), be64(0))),
        ("09_ZERO_TOKEN", 9, lambda b: b.__setitem__(slice(32, 40), be64(0))),
        ("11_PHASE_HI", 11, lambda b: b.__setitem__(slice(48, 50), be16(4))),
        ("11_PHASE_LO", 11, lambda b: b.__setitem__(slice(48, 50), be16(0))),
        ("12_PHASE_HI", 12, lambda b: b.__setitem__(slice(40, 42), be16(5))),
        ("14_ZERO_REV", 14, lambda b: b.__setitem__(slice(34, 42), be64(0))),
        ("15_ZERO_OPID", 15, lambda b: b.__setitem__(slice(16, 32), bytes(16))),
        ("15_ZERO_TX", 15, lambda b: b.__setitem__(slice(0, 16), bytes(16))),
        ("16_ZERO_TX", 16, lambda b: b.__setitem__(slice(0, 16), bytes(16))),
        ("16_ZERO_OPID", 16, lambda b: b.__setitem__(slice(16, 32), bytes(16))),
        ("17_RESOURCE_HI", 17, lambda b: b.__setitem__(slice(0, 2), be16(12))),
        ("17_RESOURCE_LO", 17, lambda b: b.__setitem__(slice(0, 2), be16(0))),
        ("17_ZERO_EPOCH", 17, lambda b: b.__setitem__(slice(2, 10), be64(0))),
        ("17_BLOCKED_HI", 17, lambda b: b.__setitem__(slice(10, 14), be32(2))),
        ("18_PHASE_HI", 18, lambda b: b.__setitem__(slice(32, 34), be16(4))),
        ("19_ZERO_GEN", 19, lambda b: b.__setitem__(slice(16, 24), be64(0))),
        ("19_ZERO_RT", 19, lambda b: b.__setitem__(slice(0, 16), bytes(16))),
        ("20_ZERO_EPOCH", 20, lambda b: b.__setitem__(slice(0, 8), be64(0))),
        ("21_ACTION_HI", 21, lambda b: b.__setitem__(slice(64, 66), be16(4))),
    ]:
        b = bytearray(op_id(k)); mut(b)
        add(id=f"DSO2_KIND{name}", suite="DSO2", op="witness_identity_digest", expected_status="INVALID_ARGUMENT",
            operation_kind=k, identity_hex=hx(bytes(b)))
    add(id="DSO2_KIND06_BAD_LEN", suite="DSO2", op="witness_identity_digest", expected_status="INVALID_ARGUMENT",
        operation_kind=6, identity_hex=hx(op_id(6)[:39]))

    def make_seq(i):
        return ROOT + bytes([6, 0x21, 1, 3, 8]) + be64(i + 1)

    def entry_create(role, key, nd):
        return be16(role) + bytes([1, 0]) + be16(len(key)) + be16(0) + key + bytes([0, 1]) + be16(0) + bytes(32) + bytes(32) + nd

    def entry_replace(role, key, od, nd, pr):
        return be16(role) + bytes([2, 0]) + be16(len(key)) + be16(0) + key + bytes([1, 1]) + be16(0) + pr + od + nd

    def entry_erase(role, key, od, pr):
        return be16(role) + bytes([3, 0]) + be16(len(key)) + be16(0) + key + bytes([1, 0]) + be16(0) + pr + od + bytes(32)

    def entry_supersede(key, od, nd):
        return be16(0x067F) + bytes([4, 0]) + be16(len(key)) + be16(0) + key + bytes([1, 1]) + be16(0) + bytes(32) + od + nd

    wdig = bytes([0x33] * 32)
    mk = make_seq(0); nd = sha256(mk)
    chunk = wdig + be16(0) + be16(1) + be16(1) + be16(0) + entry_create(0x0621, mk, nd)
    add(id="DSW1_CREATE", suite="DSW1", op="witness_chunk_roundtrip", expected_status="OK",
        value_hex=hx(chunk), digest_hex=hx(sha256(chunk)))
    od = sha256(mk); nd2 = sha256(b"new"); pr = bytes([0x22] * 32)
    chunk = wdig + be16(0) + be16(1) + be16(1) + be16(0) + entry_replace(0x0621, mk, od, nd2, pr)
    add(id="DSW1_REPLACE", suite="DSW1", op="witness_chunk_roundtrip", expected_status="OK", value_hex=hx(chunk))
    chunk = wdig + be16(0) + be16(1) + be16(1) + be16(0) + entry_erase(0x0621, mk, od, pr)
    add(id="DSW1_ERASE", suite="DSW1", op="witness_chunk_roundtrip", expected_status="OK", value_hex=hx(chunk))
    wh_ident = composite(0x7F, be16(2) + be16(16) + bytes(range(16)))
    wh_key = bkey(6, 0x7F, 5, wh_ident)
    chunk = wdig + be16(0) + be16(1) + be16(1) + be16(0) + entry_supersede(wh_key, sha256(b"oldh"), sha256(b"newh"))
    add(id="DSW1_SUPERSEDE", suite="DSW1", op="witness_chunk_roundtrip", expected_status="OK", value_hex=hx(chunk))
    chunk = wdig + be16(0) + be16(1) + be16(1) + be16(0) + entry_replace(0x0621, mk, od, nd2, bytes(32))
    add(id="DSW1_REPLACE_ZERO_PRIOR", suite="DSW1", op="witness_chunk_decode", expected_status="CORRUPT", value_hex=hx(chunk))
    f3 = ROOT + bytes([3, 1])
    chunk = wdig + be16(0) + be16(1) + be16(1) + be16(0) + entry_replace(0x0300, f3, sha256(f3), sha256(b"n"), bytes(32))
    add(id="DSW1_REPLACE_F3_BASELINE", suite="DSW1", op="witness_chunk_roundtrip", expected_status="OK", value_hex=hx(chunk))
    chunk = wdig + be16(0) + be16(1) + be16(1) + be16(0) + entry_create(0x0300, mk, nd)
    add(id="DSW1_ROLE_MISMATCH", suite="DSW1", op="witness_chunk_decode", expected_status="CORRUPT", value_hex=hx(chunk))
    mk1 = make_seq(1); mk0 = make_seq(0)
    chunk = wdig + be16(0) + be16(1) + be16(2) + be16(0) + entry_create(0x0621, mk1, sha256(mk1)) + entry_create(0x0621, mk0, sha256(mk0))
    add(id="DSW1_UNORDERED", suite="DSW1", op="witness_chunk_decode", expected_status="CORRUPT", value_hex=hx(chunk))

    def build_manifest_chunks(members):
        chunks = (members + 7) // 8
        w = composite(0x7F, be16(2) + be16(16) + bytes(range(16)))
        bodies = []
        for m in range(chunks):
            start = m * 8
            count = min(8, members - start)
            body = bytearray(w + be16(m) + be16(chunks) + be16(count) + be16(0))
            for e in range(count):
                k = make_seq(start + e)
                body += entry_create(0x0621, k, sha256(k))
            bodies.append(bytes(body))
        dig = sha256(b"NINLIL-DOMAIN-MANIFEST-V1" + b"".join(bodies))
        return bodies, dig, w, chunks

    for members in (1, 8, 9, 199, 256):
        bodies, dig, w, ch = build_manifest_chunks(members)
        add(id=f"DSW1_MANIFEST_{members}", suite="DSW1", op="witness_manifest_stream", expected_status="OK",
            member_count=members, chunk_count=ch, digest_hex=hx(dig), digest2_hex=hx(w),
            chunk_bodies_hex=[hx(b) for b in bodies], key_length=21)
    add(id="DSW1_CHUNK_COUNT_1", suite="DSW1", op="chunk_count", expected_status="OK", member_count=1, chunk_count=1)
    add(id="DSW1_CHUNK_COUNT_8", suite="DSW1", op="chunk_count", expected_status="OK", member_count=8, chunk_count=1)
    add(id="DSW1_CHUNK_COUNT_9", suite="DSW1", op="chunk_count", expected_status="OK", member_count=9, chunk_count=2)
    add(id="DSW1_CHUNK_COUNT_199", suite="DSW1", op="chunk_count", expected_status="OK", member_count=199, chunk_count=25)
    add(id="DSW1_CHUNK_COUNT_256", suite="DSW1", op="chunk_count", expected_status="OK", member_count=256, chunk_count=32)
    add(id="DSW1_CHUNK_COUNT_257", suite="DSW1", op="chunk_count", expected_status="INVALID_ARGUMENT", member_count=257)

    # --- Witness header / canonical operation matrix (section 10.0) ---
    def ret_for_kind(k, ident):
        """Return (retention_kind, retention_digest) for a valid positive case."""
        zero32 = bytes(32)
        nonz = bytes([0xCD] * 32)
        if k in (1, 17, 19, 20):
            return 0, zero32
        if k in (2, 3, 13, 15, 16):
            return 2, nonz
        if k == 14:
            # retention subject digest equals subject_primary_key_digest (ident[:32])
            return 2, ident[:32]
        if k in (8, 9, 10, 11):
            # 9/10/11 retention digest equals delivery key digest (first 32 of identity)
            if k in (9, 10, 11):
                return 3, ident[:32]
            return 3, nonz
        if k in (4, 7, 21):
            return 0, zero32  # NEW_DELIVERY / namespace-style valid retention-0
        if k in (5, 6, 12, 18):
            return 2, nonz
        return 0, zero32

    def subject_for_kind(k, ident):
        if k in (4, 7, 13):
            return subject_prefix_from_key(ordered_ingress_key(ident[:8]))
        if k == 17:
            rk = struct.unpack(">H", ident[0:2])[0]
            return subject_prefix_from_key(family4_capacity_key(rk))
        if k == 20:
            return subject_prefix_from_key(bearer_state_key())
        if k in (1, 2, 3, 5, 6, 9, 10, 11, 12, 14, 15, 16, 19, 21):
            return ident[:16]
        # kinds 8, 18: not fully local — any nonzero subject is accepted by D1-A
        return bytes([0x11 + (k & 0x0F)] * 16)

    def members_for_kind(k):
        # stay within kind ceilings; use 1 for compact header framing tests
        return 1

    manifest = bytes([0x44] * 32)
    succ_nonzero = bytes([0x55] * 32)
    header_pos = 0
    canon_pos = 0
    for k in range(1, 22):
        ident = op_id(k)
        subject = subject_for_kind(k, ident)
        ret_k, ret_d = ret_for_kind(k, ident)
        members = members_for_kind(k)
        chunks = (members + 7) // 8
        canon = canonical_op(k, ident, subject, manifest, ret_k, ret_d)
        body = encode_witness_header(
            k, 1, ident, subject, canon, members, chunks, manifest, ret_k, ret_d, bytes(32))
        add(id=f"DSW1_HDR_K{k:02d}_ACTIVE", suite="DSW1", op="witness_header_roundtrip",
            expected_status="OK", operation_kind=k, witness_state=1, retention_kind=ret_k,
            member_count=members, chunk_count=chunks,
            identity_hex=hx(ident), subject_hex=hx(subject), digest_hex=hx(canon),
            manifest_hex=hx(manifest), retention_hex=hx(ret_d), successor_hex=hx(bytes(32)),
            value_hex=hx(body))
        header_pos += 1
        add(id=f"DSO2_CANON_K{k:02d}", suite="DSO2", op="canonical_operation_digest",
            expected_status="OK", operation_kind=k, retention_kind=ret_k,
            identity_hex=hx(ident), subject_hex=hx(subject),
            manifest_hex=hx(manifest), retention_hex=hx(ret_d), digest_hex=hx(canon))
        canon_pos += 1

    # Locally-derivable wrong-subject negatives
    for k in (4, 7, 13, 17, 20):
        ident = op_id(k)
        wrong = bytes([0xEE] * 16)
        ret_k, ret_d = ret_for_kind(k, ident)
        members, chunks = 1, 1
        # still compute a digest as if wrong subject were accepted — encode must reject
        fake_canon = canonical_op(k, ident, wrong, manifest, ret_k, ret_d)
        # canonical_op path also rejects wrong subject via matrix; use raw header fields
        body = encode_witness_header(
            k, 1, ident, wrong, fake_canon, members, chunks, manifest, ret_k, ret_d, bytes(32))
        add(id=f"DSW1_HDR_K{k:02d}_WRONG_SUBJECT", suite="DSW1", op="witness_header_decode",
            expected_status="CORRUPT", operation_kind=k, witness_state=1,
            retention_kind=ret_k, member_count=members, chunk_count=chunks,
            identity_hex=hx(ident), subject_hex=hx(wrong), digest_hex=hx(fake_canon),
            manifest_hex=hx(manifest), retention_hex=hx(ret_d), successor_hex=hx(bytes(32)),
            value_hex=hx(body))
        add(id=f"DSW1_HDR_K{k:02d}_WRONG_SUBJECT_ENC", suite="DSW1", op="witness_header_encode",
            expected_status="INVALID_ARGUMENT", operation_kind=k, witness_state=1,
            retention_kind=ret_k, member_count=members, chunk_count=chunks,
            identity_hex=hx(ident), subject_hex=hx(wrong), digest_hex=hx(fake_canon),
            manifest_hex=hx(manifest), retention_hex=hx(ret_d), successor_hex=hx(bytes(32)))
        add(id=f"DSO2_CANON_K{k:02d}_WRONG_SUBJECT", suite="DSO2", op="canonical_operation_digest",
            expected_status="INVALID_ARGUMENT", operation_kind=k, retention_kind=ret_k,
            identity_hex=hx(ident), subject_hex=hx(wrong),
            manifest_hex=hx(manifest), retention_hex=hx(ret_d))

    # Wrong retention for fixed-retention kinds
    for k, bad_ret in ((1, 2), (2, 0), (8, 2), (13, 0), (17, 2), (19, 2), (20, 3)):
        ident = op_id(k)
        subject = subject_for_kind(k, ident)
        bad_ret_d = bytes([0xCD] * 32) if bad_ret != 0 else bytes(32)
        members, chunks = 1, 1
        fake_canon = bytes([0x77] * 32)
        body = encode_witness_header(
            k, 1, ident, subject, fake_canon, members, chunks, manifest, bad_ret, bad_ret_d, bytes(32))
        add(id=f"DSW1_HDR_K{k:02d}_BAD_RET", suite="DSW1", op="witness_header_decode",
            expected_status="CORRUPT", operation_kind=k, witness_state=1,
            retention_kind=bad_ret, member_count=members, chunk_count=chunks,
            identity_hex=hx(ident), subject_hex=hx(subject), digest_hex=hx(fake_canon),
            manifest_hex=hx(manifest), retention_hex=hx(bad_ret_d), successor_hex=hx(bytes(32)),
            value_hex=hx(body))

    # ACTIVE/SUPERSEDED/RETIRED successor rules (kind 1 positive matrix)
    k = 1
    ident = op_id(k)
    subject = subject_for_kind(k, ident)
    ret_k, ret_d = ret_for_kind(k, ident)
    members, chunks = 1, 1
    canon = canonical_op(k, ident, subject, manifest, ret_k, ret_d)
    # ACTIVE with nonzero successor → reject
    body = encode_witness_header(
        k, 1, ident, subject, canon, members, chunks, manifest, ret_k, ret_d, succ_nonzero)
    add(id="DSW1_HDR_ACTIVE_NONZERO_SUCC", suite="DSW1", op="witness_header_decode",
        expected_status="CORRUPT", operation_kind=k, witness_state=1,
        retention_kind=ret_k, member_count=members, chunk_count=chunks,
        identity_hex=hx(ident), subject_hex=hx(subject), digest_hex=hx(canon),
        manifest_hex=hx(manifest), retention_hex=hx(ret_d), successor_hex=hx(succ_nonzero),
        value_hex=hx(body))
    # SUPERSEDED with zero successor → reject
    body = encode_witness_header(
        k, 2, ident, subject, canon, members, chunks, manifest, ret_k, ret_d, bytes(32))
    add(id="DSW1_HDR_SUPERSEDED_ZERO_SUCC", suite="DSW1", op="witness_header_decode",
        expected_status="CORRUPT", operation_kind=k, witness_state=2,
        retention_kind=ret_k, member_count=members, chunk_count=chunks,
        identity_hex=hx(ident), subject_hex=hx(subject), digest_hex=hx(canon),
        manifest_hex=hx(manifest), retention_hex=hx(ret_d), successor_hex=hx(bytes(32)),
        value_hex=hx(body))
    # SUPERSEDED / RETIRED with nonzero successor → accept
    for state, name in ((2, "SUPERSEDED"), (3, "RETIRED")):
        body = encode_witness_header(
            k, state, ident, subject, canon, members, chunks, manifest, ret_k, ret_d, succ_nonzero)
        add(id=f"DSW1_HDR_{name}_OK", suite="DSW1", op="witness_header_roundtrip",
            expected_status="OK", operation_kind=k, witness_state=state,
            retention_kind=ret_k, member_count=members, chunk_count=chunks,
            identity_hex=hx(ident), subject_hex=hx(subject), digest_hex=hx(canon),
            manifest_hex=hx(manifest), retention_hex=hx(ret_d), successor_hex=hx(succ_nonzero),
            value_hex=hx(body))
    # Canonical digest corruption on otherwise-valid ACTIVE header
    bad_canon = bytes([(canon[0] ^ 1)]) + canon[1:]
    body = encode_witness_header(
        k, 1, ident, subject, bad_canon, members, chunks, manifest, ret_k, ret_d, bytes(32))
    add(id="DSW1_HDR_CANON_CORRUPT", suite="DSW1", op="witness_header_decode",
        expected_status="CORRUPT", operation_kind=k, witness_state=1,
        retention_kind=ret_k, member_count=members, chunk_count=chunks,
        identity_hex=hx(ident), subject_hex=hx(subject), digest_hex=hx(bad_canon),
        manifest_hex=hx(manifest), retention_hex=hx(ret_d), successor_hex=hx(bytes(32)),
        value_hex=hx(body))
    # Trailing byte
    good = encode_witness_header(
        k, 1, ident, subject, canon, members, chunks, manifest, ret_k, ret_d, bytes(32))
    add(id="DSW1_HDR_TRAILING", suite="DSW1", op="witness_header_decode",
        expected_status="CORRUPT", value_hex=hx(good + b"\x00"))
    # Reserved nonzero in retention reserved field: mutate encoded body
    bad_res = bytearray(good)
    # Layout ends: manifest(32), ret_kind(2), reserved(2), ret_dig(32), succ(32).
    res_off = len(good) - 32 - 32 - 2
    bad_res[res_off] = 0x01
    add(id="DSW1_HDR_RESERVED_NONZERO", suite="DSW1", op="witness_header_decode",
        expected_status="CORRUPT", value_hex=hx(bytes(bad_res)))

    # ------------------------------------------------------------------
    # D1-B1: five exact semantic bodies (independent BE oracles)
    # ------------------------------------------------------------------
    def add_body_suite(subtype_name, family, subtype, positives, negatives, mutations, roundtrips):
        """Track per-subtype coverage counters for the catalog checker."""
        return {
            "name": subtype_name,
            "family": family,
            "subtype": subtype,
            "positive": positives,
            "negative": negatives,
            "mutation": mutations,
            "roundtrip": roundtrips,
        }

    b1_cov = {}

    # --- INTERNAL_INVARIANT (family 5 / 01), exact body 96 ---
    inv_pos = inv_neg = inv_mut = inv_rt = 0
    reason = 129  # NINLIL_REASON_OUTCOME_UNKNOWN
    subj_kind = 0x0622  # TRANSACTION_STATE role
    # Synthetic subject complete key digest for the marker preimage only.
    subj_dig = sha256(b"subject-key-for-invariant-v1")
    epoch16 = bytes([0xA0] + [0] * 14 + [0x01])
    detail = sha256(b"detail")
    body_inv = enc_body_invariant(reason, subj_kind, subj_dig, epoch16, 1000, detail)
    assert len(body_inv) == 96
    marker = invariant_marker_id(reason, subj_kind, subj_dig)
    key_inv = bkey(5, 0x01, 2, marker)
    head0 = bytes(32)
    pvd0 = bytes(32)
    val_inv = enc_env_full(5, 0x01, 0, 1, marker, head0, pvd0, body_inv)
    add(id="DSB1_INV_MIN_POSITIVE", suite="DSB1", op="body_encode", expected_status="OK",
        family=5, subtype=0x01, body_length=96, body_hex=hx(body_inv),
        identity_hex=hx(marker), digest_hex=hx(marker),
        notes="reason+subject_kind closed role; reserved=0")
    inv_pos += 1
    add(id="DSB1_INV_ENCODE_DECODE", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=5, subtype=0x01, body_length=96, body_hex=hx(body_inv))
    inv_rt += 1
    inv_pos += 1
    add(id="DSB1_INV_TYPED_POSITIVE", suite="DSB1", op="typed_record", expected_status="OK",
        family=5, subtype=0x01, key_hex=hx(key_inv), value_hex=hx(val_inv),
        body_hex=hx(body_inv), digest_hex=hx(sha256(val_inv)),
        crc_hex=f"{crc32c(val_inv[:-4]):08x}")
    inv_pos += 1
    # Namespace-wide subject (kind 0 + digest 0)
    body_ns = enc_body_invariant(reason, 0, bytes(32), epoch16, 0, detail)
    marker_ns = invariant_marker_id(reason, 0, bytes(32))
    add(id="DSB1_INV_NAMESPACE_SUBJECT", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=5, subtype=0x01, body_length=96, body_hex=hx(body_ns),
        identity_hex=hx(marker_ns))
    inv_pos += 1
    inv_rt += 1
    # Family3 / family4 subject roles
    for sk, name in ((0x0300, "F3"), (0x0400, "F4"), (0x0610, "SVC"), (0x0660, "BEARER")):
        b = enc_body_invariant(reason, sk, subj_dig, epoch16, 1, detail)
        add(id=f"DSB1_INV_SUBJECT_{name}", suite="DSB1", op="body_roundtrip", expected_status="OK",
            family=5, subtype=0x01, body_length=96, body_hex=hx(b))
        inv_pos += 1
        inv_rt += 1
    # Negatives: reserved, short, trailing, bad subject role, kind0+nonzero dig
    bad = bytearray(body_inv); bad[6:8] = be16(1)
    add(id="DSB1_INV_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=5, subtype=0x01, body_hex=hx(bytes(bad)))
    inv_neg += 1
    add(id="DSB1_INV_SHORT", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=5, subtype=0x01, body_hex=hx(body_inv[:-1]))
    inv_neg += 1
    add(id="DSB1_INV_TRAILING", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=5, subtype=0x01, body_hex=hx(body_inv + b"\x00"))
    inv_neg += 1
    bad_role = enc_body_invariant(reason, 0x057F, subj_dig, epoch16, 1, detail)
    add(id="DSB1_INV_BAD_SUBJECT_F5", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=5, subtype=0x01, body_hex=hx(bad_role))
    inv_neg += 1
    bad_wit = enc_body_invariant(reason, 0x067D, subj_dig, epoch16, 1, detail)
    add(id="DSB1_INV_BAD_SUBJECT_7D", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=5, subtype=0x01, body_hex=hx(bad_wit))
    inv_neg += 1
    bad_ns = enc_body_invariant(reason, 0, subj_dig, epoch16, 1, detail)
    add(id="DSB1_INV_KIND0_NONZERO_DIG", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=5, subtype=0x01, body_hex=hx(bad_ns))
    inv_neg += 1
    # Mutation: flip reserved bit in positive body
    mut = bytearray(body_inv); mut[7] ^= 0x01
    add(id="DSB1_INV_MUT_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=5, subtype=0x01, body_hex=hx(bytes(mut)), notes="bit mutation of reserved")
    inv_mut += 1
    # Typed: wrong marker id in key
    bad_key = bkey(5, 0x01, 2, bytes(range(16)))
    bad_val = enc_env_full(5, 0x01, 0, 1, bytes(range(16)), head0, pvd0, body_inv)
    add(id="DSB1_INV_TYPED_BAD_MARKER", suite="DSB1", op="typed_record", expected_status="CORRUPT",
        family=5, subtype=0x01, key_hex=hx(bad_key), value_hex=hx(bad_val))
    inv_neg += 1
    # Typed: revision != 1
    bad_rev = enc_env_full(5, 0x01, 0, 2, marker, head0, pvd0, body_inv)
    add(id="DSB1_INV_TYPED_REV2", suite="DSB1", op="typed_record", expected_status="CORRUPT",
        family=5, subtype=0x01, key_hex=hx(key_inv), value_hex=hx(bad_rev))
    inv_neg += 1
    # BUFFER_TOO_SMALL
    add(id="DSB1_INV_BUFFER_TOO_SMALL", suite="DSB1", op="body_encode", expected_status="BUFFER_TOO_SMALL",
        family=5, subtype=0x01, body_length=96, body_hex=hx(body_inv),
        key_length=0, notes="capacity 0 required length 96")
    inv_neg += 1
    # Public reason registry boundaries (docs12): NONE=0 allowed; gaps rejected.
    for r, name in ((0, "NONE"), (1, "LO"), (24, "HI24"), (64, "64"),
                    (66, "66"), (68, "68"), (86, "86"), (128, "128"),
                    (132, "132"), (4096, "4096"), (4097, "4097")):
        b = enc_body_invariant(r, subj_kind, subj_dig, epoch16, 1, detail)
        add(id=f"DSB1_INV_REASON_{name}", suite="DSB1", op="body_roundtrip",
            expected_status="OK", family=5, subtype=0x01, body_length=96,
            body_hex=hx(b))
        inv_pos += 1
        inv_rt += 1
    for r, name in ((25, "25"), (67, "67"), (87, "87"), (133, "133"),
                    (4098, "4098"), (0xFFFFFFFF, "U32MAX")):
        b = enc_body_invariant(r, subj_kind, subj_dig, epoch16, 1, detail)
        add(id=f"DSB1_INV_REASON_BAD_{name}", suite="DSB1", op="body_decode",
            expected_status="CORRUPT", family=5, subtype=0x01, body_hex=hx(b))
        inv_neg += 1
    # Non-namespace zero subject_digest forbidden (namespace sentinel exclusivity)
    bad_zd = enc_body_invariant(reason, 0x0300, bytes(32), epoch16, 1, detail)
    add(id="DSB1_INV_NONNS_ZERO_DIGEST", suite="DSB1", op="body_decode",
        expected_status="CORRUPT", family=5, subtype=0x01, body_hex=hx(bad_zd))
    inv_neg += 1
    # Explicit mutation of reason field to reserved 67
    mut_r2 = enc_body_invariant(67, subj_kind, subj_dig, epoch16, 1, detail)
    add(id="DSB1_INV_MUT_REASON67", suite="DSB1", op="body_decode",
        expected_status="CORRUPT", family=5, subtype=0x01,
        body_hex=hx(mut_r2), notes="mutation: reason=67 reserved")
    inv_mut += 1
    inv_neg += 1
    b1_cov["01"] = add_body_suite("INTERNAL_INVARIANT", 5, 0x01, inv_pos, inv_neg, inv_mut, inv_rt)

    # --- BEARER_STATE (60), exact body 36 ---
    br_pos = br_neg = br_mut = br_rt = 0
    clock_ep = bytes([0xB0] + [0] * 14 + [0x02])
    body_br = enc_body_bearer(1, 1, clock_ep, 5000)
    assert len(body_br) == 36
    key_br = bearer_state_key()
    head_br = bytes([0x11] * 32)
    val_br = enc_env_full(6, 0x60, 0, 1, bytes(16), head_br, pvd0, body_br)
    add(id="DSB1_BEARER_MIN_POSITIVE", suite="DSB1", op="body_encode", expected_status="OK",
        family=6, subtype=0x60, body_length=36, body_hex=hx(body_br))
    br_pos += 1
    add(id="DSB1_BEARER_ENCODE_DECODE", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x60, body_length=36, body_hex=hx(body_br))
    br_rt += 1
    br_pos += 1
    add(id="DSB1_BEARER_AVAILABLE0", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x60, body_length=36,
        body_hex=hx(enc_body_bearer(2, 0, clock_ep, 0)))
    br_pos += 1
    br_rt += 1
    add(id="DSB1_BEARER_TYPED_POSITIVE", suite="DSB1", op="typed_record", expected_status="OK",
        family=6, subtype=0x60, key_hex=hx(key_br), value_hex=hx(val_br),
        body_hex=hx(body_br), digest_hex=hx(sha256(val_br)),
        crc_hex=f"{crc32c(val_br[:-4]):08x}")
    br_pos += 1
    add(id="DSB1_BEARER_ZERO_EPOCH", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x60, body_hex=hx(enc_body_bearer(0, 1, clock_ep, 1)))
    br_neg += 1
    add(id="DSB1_BEARER_AVAILABLE2", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x60, body_hex=hx(enc_body_bearer(1, 2, clock_ep, 1)))
    br_neg += 1
    add(id="DSB1_BEARER_ZERO_CLOCK", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x60, body_hex=hx(enc_body_bearer(1, 1, bytes(16), 1)))
    br_neg += 1
    add(id="DSB1_BEARER_SHORT", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x60, body_hex=hx(body_br[:-1]))
    br_neg += 1
    add(id="DSB1_BEARER_TRAILING", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x60, body_hex=hx(body_br + b"\x00"))
    br_neg += 1
    mut = bytearray(body_br); mut[8] ^= 0x02  # available field high bit-ish
    add(id="DSB1_BEARER_MUT_AVAILABLE", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x60, body_hex=hx(bytes(mut)))
    br_mut += 1
    # zero head typed (envelope already rejects encode; value with zero head + valid CRC)
    # Construct corrupt value by forcing zero head and fixing CRC
    val_zh = bytearray(val_br)
    val_zh[12 + 28:12 + 60] = bytes(32)  # head_witness_digest in common header
    val_zh[-4:] = be32(crc32c(bytes(val_zh[:-4])))
    add(id="DSB1_BEARER_TYPED_ZERO_HEAD", suite="DSB1", op="typed_record", expected_status="CORRUPT",
        family=6, subtype=0x60, key_hex=hx(key_br), value_hex=hx(bytes(val_zh)))
    br_neg += 1
    add(id="DSB1_BEARER_BUFFER_TOO_SMALL", suite="DSB1", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x60,
        body_length=36, body_hex=hx(body_br), key_length=0)
    br_neg += 1
    b1_cov["60"] = add_body_suite("BEARER_STATE", 6, 0x60, br_pos, br_neg, br_mut, br_rt)

    # --- CLOCK_BASELINE (62), exact body 40 ---
    ck_pos = ck_neg = ck_mut = ck_rt = 0
    body_ck_u = enc_body_clock(1, bytes(16), 0, 0)  # UNINITIALIZED
    body_ck_t = enc_body_clock(2, epoch16, 9000, 1)  # TRUSTED
    assert len(body_ck_u) == 40 and len(body_ck_t) == 40
    key_ck = clock_baseline_key()
    val_ck_u = enc_env_full(6, 0x62, 0, 1, bytes(16), head0, pvd0, body_ck_u)
    val_ck_t = enc_env_full(6, 0x62, 0, 2, bytes(16), head0, pvd0, body_ck_t)
    add(id="DSB1_CLOCK_UNINIT_POSITIVE", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x62, body_length=40, body_hex=hx(body_ck_u))
    ck_pos += 1
    ck_rt += 1
    add(id="DSB1_CLOCK_TRUSTED_POSITIVE", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x62, body_length=40, body_hex=hx(body_ck_t))
    ck_pos += 1
    ck_rt += 1
    add(id="DSB1_CLOCK_TYPED_UNINIT", suite="DSB1", op="typed_record", expected_status="OK",
        family=6, subtype=0x62, key_hex=hx(key_ck), value_hex=hx(val_ck_u),
        body_hex=hx(body_ck_u), digest_hex=hx(sha256(val_ck_u)),
        crc_hex=f"{crc32c(val_ck_u[:-4]):08x}")
    ck_pos += 1
    add(id="DSB1_CLOCK_TYPED_TRUSTED", suite="DSB1", op="typed_record", expected_status="OK",
        family=6, subtype=0x62, key_hex=hx(key_ck), value_hex=hx(val_ck_t),
        body_hex=hx(body_ck_t), digest_hex=hx(sha256(val_ck_t)),
        crc_hex=f"{crc32c(val_ck_t[:-4]):08x}")
    ck_pos += 1
    add(id="DSB1_CLOCK_BAD_STATE", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62, body_hex=hx(enc_body_clock(0, bytes(16), 0, 0)))
    ck_neg += 1
    add(id="DSB1_CLOCK_UNINIT_NONEMPTY", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62, body_hex=hx(enc_body_clock(1, epoch16, 0, 0)))
    ck_neg += 1
    add(id="DSB1_CLOCK_TRUSTED_ZERO_EPOCH", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62, body_hex=hx(enc_body_clock(2, bytes(16), 1, 1)))
    ck_neg += 1
    add(id="DSB1_CLOCK_TRUSTED_ZERO_GEN", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62, body_hex=hx(enc_body_clock(2, epoch16, 1, 0)))
    ck_neg += 1
    add(id="DSB1_CLOCK_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62,
        body_hex=hx(be32(1) + be32(1) + bytes(16) + be64(0) + be64(0)))
    ck_neg += 1
    add(id="DSB1_CLOCK_SHORT", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62, body_hex=hx(body_ck_u[:-1]))
    ck_neg += 1
    add(id="DSB1_CLOCK_TRAILING", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62, body_hex=hx(body_ck_u + b"\x00"))
    ck_neg += 1
    mut = bytearray(body_ck_t); mut[4] ^= 0x01
    add(id="DSB1_CLOCK_MUT_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x62, body_hex=hx(bytes(mut)))
    ck_mut += 1
    # TRUSTED with revision 1 is typed corrupt
    bad_tr = enc_env_full(6, 0x62, 0, 1, bytes(16), head0, pvd0, body_ck_t)
    add(id="DSB1_CLOCK_TYPED_TRUSTED_REV1", suite="DSB1", op="typed_record", expected_status="CORRUPT",
        family=6, subtype=0x62, key_hex=hx(key_ck), value_hex=hx(bad_tr))
    ck_neg += 1
    add(id="DSB1_CLOCK_BUFFER_TOO_SMALL", suite="DSB1", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x62,
        body_length=40, body_hex=hx(body_ck_t), key_length=0)
    ck_neg += 1
    # Same-record rev == gen+1 (docs17 §8.6)
    body_ck_t2 = enc_body_clock(2, epoch16, 9000, 2)
    val_ck_t2 = enc_env_full(6, 0x62, 0, 3, bytes(16), head0, pvd0, body_ck_t2)
    add(id="DSB1_CLOCK_TYPED_REV_GEN_OK", suite="DSB1", op="typed_record",
        expected_status="OK", family=6, subtype=0x62, key_hex=hx(key_ck),
        value_hex=hx(val_ck_t2), body_hex=hx(body_ck_t2),
        digest_hex=hx(sha256(val_ck_t2)),
        crc_hex=f"{crc32c(val_ck_t2[:-4]):08x}")
    ck_pos += 1
    # TRUSTED gen=1 but revision 3 → mismatch
    bad_rg = enc_env_full(6, 0x62, 0, 3, bytes(16), head0, pvd0, body_ck_t)
    add(id="DSB1_CLOCK_TYPED_REV_GEN_MISMATCH", suite="DSB1", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x62, key_hex=hx(key_ck),
        value_hex=hx(bad_rg))
    ck_neg += 1
    # UNINIT with rev=2 (body still gen=0)
    bad_ur = enc_env_full(6, 0x62, 0, 2, bytes(16), head0, pvd0, body_ck_u)
    add(id="DSB1_CLOCK_TYPED_UNINIT_REV2", suite="DSB1", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x62, key_hex=hx(key_ck),
        value_hex=hx(bad_ur))
    ck_neg += 1
    b1_cov["62"] = add_body_suite("CLOCK_BASELINE", 6, 0x62, ck_pos, ck_neg, ck_mut, ck_rt)

    # --- ATTEMPT_REUSE_FENCE (64), exact body 16 ---
    fn_pos = fn_neg = fn_mut = fn_rt = 0
    body_fn = enc_body_fence(1, 1)
    assert len(body_fn) == 16
    key_fn = fence_key()
    head_fn = bytes([0x22] * 32)
    val_fn = enc_env_full(6, 0x64, 0, 1, bytes(16), head_fn, pvd0, body_fn)
    add(id="DSB1_FENCE_MIN_POSITIVE", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x64, body_length=16, body_hex=hx(body_fn))
    fn_pos += 1
    fn_rt += 1
    add(id="DSB1_FENCE_COUNT3_GEN5", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x64, body_length=16, body_hex=hx(enc_body_fence(3, 5)))
    fn_pos += 1
    fn_rt += 1
    add(id="DSB1_FENCE_TYPED_POSITIVE", suite="DSB1", op="typed_record", expected_status="OK",
        family=6, subtype=0x64, key_hex=hx(key_fn), value_hex=hx(val_fn),
        body_hex=hx(body_fn), digest_hex=hx(sha256(val_fn)),
        crc_hex=f"{crc32c(val_fn[:-4]):08x}")
    fn_pos += 1
    add(id="DSB1_FENCE_COUNT0", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x64, body_hex=hx(enc_body_fence(0, 1)))
    fn_neg += 1
    add(id="DSB1_FENCE_GEN0", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x64, body_hex=hx(enc_body_fence(1, 0)))
    fn_neg += 1
    add(id="DSB1_FENCE_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x64, body_hex=hx(be32(1) + be32(1) + be64(1)))
    fn_neg += 1
    add(id="DSB1_FENCE_SHORT", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x64, body_hex=hx(body_fn[:-1]))
    fn_neg += 1
    add(id="DSB1_FENCE_TRAILING", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x64, body_hex=hx(body_fn + b"\x00"))
    fn_neg += 1
    mut = bytearray(body_fn); mut[4] ^= 0x01
    add(id="DSB1_FENCE_MUT_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x64, body_hex=hx(bytes(mut)))
    fn_mut += 1
    add(id="DSB1_FENCE_BUFFER_TOO_SMALL", suite="DSB1", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x64,
        body_length=16, body_hex=hx(body_fn), key_length=0)
    fn_neg += 1
    # fence_generation == record_revision
    body_fn2 = enc_body_fence(2, 5)
    val_fn2 = enc_env_full(6, 0x64, 0, 5, bytes(16), head_fn, pvd0, body_fn2)
    add(id="DSB1_FENCE_TYPED_REV_GEN_OK", suite="DSB1", op="typed_record",
        expected_status="OK", family=6, subtype=0x64, key_hex=hx(key_fn),
        value_hex=hx(val_fn2), body_hex=hx(body_fn2),
        digest_hex=hx(sha256(val_fn2)),
        crc_hex=f"{crc32c(val_fn2[:-4]):08x}")
    fn_pos += 1
    # gen=1 but revision 2
    bad_fn = enc_env_full(6, 0x64, 0, 2, bytes(16), head_fn, pvd0, body_fn)
    add(id="DSB1_FENCE_TYPED_REV_GEN_MISMATCH", suite="DSB1", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x64, key_hex=hx(key_fn),
        value_hex=hx(bad_fn))
    fn_neg += 1
    b1_cov["64"] = add_body_suite("ATTEMPT_REUSE_FENCE", 6, 0x64, fn_pos, fn_neg, fn_mut, fn_rt)

    # --- WITNESS_HEAD_INDEX (7d), exact body 114 (key length 10) ---
    hi_pos = hi_neg = hi_mut = hi_rt = 0
    mk_f3 = family3_counter_key(1)
    mk_f4 = family4_capacity_key(1)
    assert len(mk_f3) == 10 and len(mk_f4) == 10
    val_dig = sha256(b"member-value")
    head_w = bytes([0x33] * 32)
    body_hi_b = enc_body_head_index(1, mk_f3, val_dig, bytes(32))  # BASELINE
    body_hi_w = enc_body_head_index(2, mk_f4, val_dig, head_w)  # WITNESSED
    assert len(body_hi_b) == 114 and len(body_hi_w) == 114
    id_hi_b = composite(0x7D, key_digest(mk_f3))
    id_hi_w = composite(0x7D, key_digest(mk_f4))
    key_hi_b = bkey(6, 0x7D, 5, id_hi_b)
    key_hi_w = bkey(6, 0x7D, 5, id_hi_w)
    val_hi_b = enc_env_full(6, 0x7D, 0, 1, id_hi_b[:16], head0, pvd0, body_hi_b)
    val_hi_w = enc_env_full(6, 0x7D, 0, 2, id_hi_w[:16], head_w, pvd0, body_hi_w)
    add(id="DSB1_HEAD_BASELINE_POSITIVE", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x7D, body_length=114, body_hex=hx(body_hi_b),
        key_hex=hx(mk_f3), digest_hex=hx(key_digest(mk_f3)))
    hi_pos += 1
    hi_rt += 1
    add(id="DSB1_HEAD_WITNESSED_POSITIVE", suite="DSB1", op="body_roundtrip", expected_status="OK",
        family=6, subtype=0x7D, body_length=114, body_hex=hx(body_hi_w),
        key_hex=hx(mk_f4), digest_hex=hx(key_digest(mk_f4)))
    hi_pos += 1
    hi_rt += 1
    add(id="DSB1_HEAD_TYPED_BASELINE", suite="DSB1", op="typed_record", expected_status="OK",
        family=6, subtype=0x7D, key_hex=hx(key_hi_b), value_hex=hx(val_hi_b),
        body_hex=hx(body_hi_b), digest_hex=hx(sha256(val_hi_b)),
        crc_hex=f"{crc32c(val_hi_b[:-4]):08x}")
    hi_pos += 1
    add(id="DSB1_HEAD_TYPED_WITNESSED", suite="DSB1", op="typed_record", expected_status="OK",
        family=6, subtype=0x7D, key_hex=hx(key_hi_w), value_hex=hx(val_hi_w),
        body_hex=hx(body_hi_w), digest_hex=hx(sha256(val_hi_w)),
        crc_hex=f"{crc32c(val_hi_w[:-4]):08x}")
    hi_pos += 1
    # Cover all 4 family3 + a few family4 kinds via body encode positives
    for kk in range(1, 5):
        mk = family3_counter_key(kk)
        b = enc_body_head_index(1, mk, val_dig, bytes(32))
        add(id=f"DSB1_HEAD_F3_{kk:02d}", suite="DSB1", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x7D, body_length=114, body_hex=hx(b))
        hi_pos += 1
        hi_rt += 1
    for kk in (1, 5, 11):
        mk = family4_capacity_key(kk)
        b = enc_body_head_index(1, mk, val_dig, bytes(32))
        add(id=f"DSB1_HEAD_F4_{kk:02d}", suite="DSB1", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x7D, body_length=114, body_hex=hx(b))
        hi_pos += 1
        hi_rt += 1
    # Negatives
    add(id="DSB1_HEAD_BAD_STATE", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D,
        body_hex=hx(be16(0) + be16(0) + key_digest(mk_f3) + be16(10) + be16(0)
                    + mk_f3 + val_dig + bytes(32)))
    hi_neg += 1
    add(id="DSB1_HEAD_BAD_KEY_LEN", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D,
        body_hex=hx(be16(1) + be16(0) + key_digest(mk_f3) + be16(9) + be16(0)
                    + mk_f3[:9] + val_dig + bytes(32)))
    hi_neg += 1
    bad_mk = ROOT + bytes([0x05, 0x01])  # family 5 not allowed
    add(id="DSB1_HEAD_BAD_FAMILY", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D,
        body_hex=hx(be16(1) + be16(0) + key_digest(bad_mk) + be16(10) + be16(0)
                    + bad_mk + val_dig + bytes(32)))
    hi_neg += 1
    # Wrong KEY_DIGEST in body
    add(id="DSB1_HEAD_BAD_KEY_DIGEST", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D,
        body_hex=hx(be16(1) + be16(0) + bytes([0xEE] * 32) + be16(10) + be16(0)
                    + mk_f3 + val_dig + bytes(32)))
    hi_neg += 1
    # BASELINE with nonzero head
    add(id="DSB1_HEAD_BASELINE_NONZERO_HEAD", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D, body_hex=hx(enc_body_head_index(1, mk_f3, val_dig, head_w)))
    hi_neg += 1
    # WITNESSED with zero head
    add(id="DSB1_HEAD_WITNESSED_ZERO_HEAD", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D, body_hex=hx(enc_body_head_index(2, mk_f4, val_dig, bytes(32))))
    hi_neg += 1
    add(id="DSB1_HEAD_SHORT", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D, body_hex=hx(body_hi_b[:-1]))
    hi_neg += 1
    add(id="DSB1_HEAD_TRAILING", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D, body_hex=hx(body_hi_b + b"\x00"))
    hi_neg += 1
    add(id="DSB1_HEAD_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D,
        body_hex=hx(be16(1) + be16(1) + key_digest(mk_f3) + be16(10) + be16(0)
                    + mk_f3 + val_dig + bytes(32)))
    hi_neg += 1
    mut = bytearray(body_hi_b); mut[2] ^= 0x01
    add(id="DSB1_HEAD_MUT_RESERVED", suite="DSB1", op="body_decode", expected_status="CORRUPT",
        family=6, subtype=0x7D, body_hex=hx(bytes(mut)))
    hi_mut += 1
    # Typed: common head mismatch for WITNESSED
    bad_head_val = enc_env_full(6, 0x7D, 0, 2, id_hi_w[:16], bytes([0x44] * 32), pvd0, body_hi_w)
    add(id="DSB1_HEAD_TYPED_HEAD_MISMATCH", suite="DSB1", op="typed_record", expected_status="CORRUPT",
        family=6, subtype=0x7D, key_hex=hx(key_hi_w), value_hex=hx(bad_head_val))
    hi_neg += 1
    # Typed: wrong composite identity
    bad_id_key = bkey(6, 0x7D, 5, bytes([0x55] * 32))
    add(id="DSB1_HEAD_TYPED_BAD_COMPOSITE", suite="DSB1", op="typed_record", expected_status="CORRUPT",
        family=6, subtype=0x7D, key_hex=hx(bad_id_key), value_hex=hx(val_hi_w))
    hi_neg += 1
    add(id="DSB1_HEAD_BUFFER_TOO_SMALL", suite="DSB1", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x7D,
        body_length=114, body_hex=hx(body_hi_b), key_length=0,
        key_hex=hx(mk_f3), digest_hex=hx(key_digest(mk_f3)),
        head_hex=hx(bytes(32)), pvd_hex=hx(val_dig))
    hi_neg += 1
    # BASELINE revision must be 1; WITNESSED revision >= 2
    bad_br = enc_env_full(6, 0x7D, 0, 2, id_hi_b[:16], head0, pvd0, body_hi_b)
    add(id="DSB1_HEAD_TYPED_BASELINE_REV2", suite="DSB1", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x7D, key_hex=hx(key_hi_b),
        value_hex=hx(bad_br))
    hi_neg += 1
    bad_wr = enc_env_full(6, 0x7D, 0, 1, id_hi_w[:16], head_w, pvd0, body_hi_w)
    add(id="DSB1_HEAD_TYPED_WITNESSED_REV1", suite="DSB1", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x7D, key_hex=hx(key_hi_w),
        value_hex=hx(bad_wr))
    hi_neg += 1
    # WITNESSED revision 3 positive boundary
    val_hi_w3 = enc_env_full(6, 0x7D, 0, 3, id_hi_w[:16], head_w, pvd0, body_hi_w)
    add(id="DSB1_HEAD_TYPED_WITNESSED_REV3", suite="DSB1", op="typed_record",
        expected_status="OK", family=6, subtype=0x7D, key_hex=hx(key_hi_w),
        value_hex=hx(val_hi_w3), body_hex=hx(body_hi_w),
        digest_hex=hx(sha256(val_hi_w3)),
        crc_hex=f"{crc32c(val_hi_w3[:-4]):08x}")
    hi_pos += 1
    b1_cov["7d"] = add_body_suite("WITNESS_HEAD_INDEX", 6, 0x7D, hi_pos, hi_neg, hi_mut, hi_rt)


    # --- D1-B2: Service + transaction-admission bodies (suite DSB2) ---
    b2_cov = {}

    def fixture_ids():
        app = bytes([0xA1] + [0] * 14 + [0x01])
        rt = bytes([0xB1] + [0] * 14 + [0x02])
        trt = bytes([0xC1] + [0] * 14 + [0x03])
        tapp = bytes([0xD1] + [0] * 14 + [0x04])
        dev = bytes([0xE1] + [0] * 14 + [0x05])
        site = bytes([0xF1] + [0] * 14 + [0x06])
        dig = sha256(b"descriptor-v1")
        content = sha256(b"content-v1")
        canon = sha256(b"canonical-submission-v1")
        epoch = bytes([0x11] + [0] * 14 + [0x22])
        head_nz = bytes([0x44] * 32)
        pvd_nz = bytes([0x55] * 32)
        return dict(
            app=app, rt=rt, trt=trt, tapp=tapp, dev=dev, site=site, dig=dig,
            content=content, canon=canon, epoch=epoch, head_nz=head_nz,
            pvd_nz=pvd_nz, ns=b"acme.ns", svc=b"svc1", schema=b"schema1",
            ikey=b"idem-key-01",
        )

    F = fixture_ids()
    LI = local_identity(0x5, F["dev"], bytes(16), F["site"], 1, 2)  # device+site
    PARTY = party(F["rt"], F["app"], LI)
    TARGET = target(0x5, F["trt"], F["tapp"], F["dev"], bytes(16), F["site"], 1, 2)
    assert len(PARTY) == 100 and len(TARGET) == 100

    # SERVICE DesiredState (family 2)
    sk_raw = service_key_raw(F["app"], F["ns"], F["svc"], 1, F["dig"])
    # quota/reservation KEY_DIGEST precompute
    sk_raw16 = raw16(sk_raw)
    svc_comp = composite(0x10, sk_raw16)
    svc_key = bkey(6, 0x10, 5, svc_comp)
    quota_comp = composite(0x11, sk_raw16)
    quota_key = bkey(6, 0x11, 5, quota_comp)
    quota_kd = key_digest(quota_key)
    res_comp = composite(0x23, be16(1) + sk_raw16)
    res_key = bkey(6, 0x23, 5, res_comp)
    res_kd = key_digest(res_key)

    def enc_body_service(
        family=2, direction=2, authority=1, applyc=1, min_dl=1000, max_dl=5000,
        grace=100, attempts=8, sk=None
    ):
        sk = sk if sk is not None else sk_raw
        body = bytearray()
        body += raw16(sk)
        body += be64(1) + F["dig"] + F["app"]
        body += text_id(F["ns"]) + text_id(F["svc"]) + text_id(F["schema"])
        body += be16(1) + be16(0) + be16(9)  # major, minor_min, minor_max
        body += be32(family) + be32(direction) + be32(authority) + be32(applyc)
        body += be32(1)  # custody UNTIL_REQUIRED_EVIDENCE
        body += be32(0x1E)  # evidence mask stages 1..4
        body += be32(1024) + be32(1) + be32(4) + be32(attempts)
        body += be32(60000) + be32(10) + be32(1024)
        body += be64(min_dl) + be64(max_dl) + be64(grace)
        body += be64(1000) + be64(500) + be64(1000) + be64(3600000)
        body += quota_kd + res_kd
        return bytes(body)

    # EventFact service variant
    def enc_body_service_event():
        return enc_body_service(
            family=1, direction=1, authority=2, applyc=2,
            min_dl=(1 << 64) - 1, max_dl=(1 << 64) - 1, grace=0, attempts=8
        )

    body_svc = enc_body_service()
    assert len(body_svc) <= 768
    val_svc = enc_env_full(
        6, 0x10, 0, 1, svc_comp[:16], F["head_nz"], bytes(32), body_svc
    )
    s_pos = s_neg = s_mut = s_rt = 0
    add(id="DSB2_SERVICE_DS_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x10, body_length=len(body_svc),
        body_hex=hx(body_svc))
    s_pos += 1; s_rt += 1
    body_svc_ev = enc_body_service_event()
    add(id="DSB2_SERVICE_EF_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x10, body_length=len(body_svc_ev),
        body_hex=hx(body_svc_ev))
    s_pos += 1; s_rt += 1
    add(id="DSB2_SERVICE_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x10, key_hex=hx(svc_key),
        value_hex=hx(val_svc), body_hex=hx(body_svc),
        digest_hex=hx(sha256(val_svc)), crc_hex=f"{crc32c(val_svc[:-4]):08x}")
    s_pos += 1
    # negatives
    bad = bytearray(body_svc); bad[2:18] = bytes(16)  # zero app in raw only
    add(id="DSB2_SERVICE_RAW_MISMATCH", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x10, body_hex=hx(bytes(bad)))
    s_neg += 1
    add(id="DSB2_SERVICE_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x10, body_hex=hx(body_svc[:-1]))
    s_neg += 1
    add(id="DSB2_SERVICE_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x10, body_hex=hx(body_svc + b"\x00"))
    s_neg += 1
    bad_dir = enc_body_service(direction=3)
    add(id="DSB2_SERVICE_BAD_DIR", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x10, body_hex=hx(bad_dir))
    s_neg += 1
    # Corrupt: zero local_application_instance_id field (after raw+rev+dig)
    mut = bytearray(body_svc)
    # after RAW16(sk): offset = 2+len(sk_raw); then rev 8 + dig 32 = start of app
    off = 2 + len(sk_raw) + 8 + 32
    mut[off:off+16] = bytes(16)
    add(id="DSB2_SERVICE_MUT_APP", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x10, body_hex=hx(bytes(mut)))
    s_mut += 1; s_neg += 1
    add(id="DSB2_SERVICE_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x10,
        body_length=len(body_svc), body_hex=hx(body_svc), key_length=0)
    s_neg += 1
    bad_rev = enc_env_full(6, 0x10, 0, 2, svc_comp[:16], F["head_nz"], bytes(32), body_svc)
    add(id="DSB2_SERVICE_TYPED_REV2", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x10, key_hex=hx(svc_key),
        value_hex=hx(bad_rev))
    s_neg += 1
    # Same-body KEY_DIGEST negatives (pure body decode, not typed-only).
    mut_q = bytearray(body_svc)
    mut_q[-64:-32] = bytes([0xEE] * 32)  # quota_key_digest
    add(id="DSB2_SERVICE_BAD_QUOTA_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x10, body_hex=hx(bytes(mut_q)))
    s_neg += 1
    mut_r = bytearray(body_svc)
    mut_r[-32:] = bytes([0xEF] * 32)  # reservation_key_digest
    add(id="DSB2_SERVICE_BAD_RESV_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x10, body_hex=hx(bytes(mut_r)))
    s_neg += 1
    b2_cov["10"] = add_body_suite("SERVICE", 6, 0x10, s_pos, s_neg, s_mut, s_rt)

    # SERVICE_QUOTA (secondary → primary_id = SERVICE composite first 16)
    body_q = (
        sk_raw16 + key_digest(svc_key) + F["epoch"] + be64(0)
        + be32(1) + be64(100) + be32(0) + be32(0) + be64(0)
    )
    assert len(body_q) <= 512
    q_comp = composite(0x11, sk_raw16)
    q_key = bkey(6, 0x11, 5, q_comp)
    # Correct: referenced SERVICE primary, not own QUOTA composite identity.
    q_primary = primary_id_from_composite_subtype(0x10, sk_raw16)
    assert q_primary == svc_comp[:16]
    assert q_primary != q_comp[:16]
    val_q = enc_env_full(6, 0x11, 0, 1, q_primary, F["head_nz"], F["pvd_nz"], body_q)
    q_pos = q_neg = q_mut = q_rt = 0
    add(id="DSB2_QUOTA_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x11, body_length=len(body_q),
        body_hex=hx(body_q))
    q_pos += 1; q_rt += 1
    add(id="DSB2_QUOTA_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x11, key_hex=hx(q_key),
        value_hex=hx(val_q), body_hex=hx(body_q), digest_hex=hx(sha256(val_q)),
        crc_hex=f"{crc32c(val_q[:-4]):08x}")
    q_pos += 1
    # Old defect: self-key-derived primary_id (QUOTA composite first 16).
    val_q_self = enc_env_full(
        6, 0x11, 0, 1, q_comp[:16], F["head_nz"], F["pvd_nz"], body_q)
    add(id="DSB2_QUOTA_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x11, key_hex=hx(q_key),
        value_hex=hx(val_q_self))
    q_neg += 1
    add(id="DSB2_QUOTA_ZERO_EPOCH", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x11,
        body_hex=hx(sk_raw16 + key_digest(svc_key) + bytes(16) + be64(0)
                    + be32(0) + be64(0) + be32(0) + be32(0) + be64(0)))
    q_neg += 1
    add(id="DSB2_QUOTA_BAD_KEY_DIG", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x11,
        body_hex=hx(sk_raw16 + bytes([0xEE]*32) + F["epoch"] + be64(0)
                    + be32(0) + be64(0) + be32(0) + be32(0) + be64(0)))
    q_neg += 1
    add(id="DSB2_QUOTA_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x11, body_hex=hx(body_q[:-1]))
    q_neg += 1
    add(id="DSB2_QUOTA_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x11, body_hex=hx(body_q + b"\x00"))
    q_neg += 1
    mut = bytearray(body_q); mut[2] ^= 0x01
    add(id="DSB2_QUOTA_MUT_RAW", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x11, body_hex=hx(bytes(mut)))
    q_mut += 1; q_neg += 1
    add(id="DSB2_QUOTA_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x11,
        body_length=len(body_q), body_hex=hx(body_q), key_length=0)
    q_neg += 1
    b2_cov["11"] = add_body_suite("SERVICE_QUOTA", 6, 0x11, q_pos, q_neg, q_mut, q_rt)

    # TRANSACTION_ANCHOR DesiredState
    txn = bytes([0x71] + [0]*14 + [0x99])
    SI = service_identity(F["ns"], F["svc"], F["schema"], 1, F["dig"], 1, 0, 2)
    scope = scope_raw(F["app"], F["ns"], F["svc"])
    ikey = F["ikey"]
    txn_seq = 1
    # Exact KEY_DIGEST backlinks (independent oracle; not production helpers).
    seq_kd = complete_key_digest_u64(0x21, be64(txn_seq))
    im_kd = complete_key_digest_composite(0x24, raw16(scope) + raw16(ikey))
    res_tx_kd = complete_key_digest_composite(0x23, be16(2) + raw16(txn))
    # payload_blob_key_digest: non-zero only (blob kind/length cross-record)
    payload_kd = sha256(b"payload-blob")
    assert all(x != bytes(32) for x in (seq_kd, im_kd, res_tx_kd, payload_kd))

    def enc_anchor(
        family=2, event=bytes(16), gen=1, ddl_ep=None, abs_ddl=9000, grace=50,
        emap=None, seq_d=None, im_d=None, res_d=None, scope_bytes=None,
        svc_ident=None,
    ):
        ddl_ep = F["epoch"] if ddl_ep is None else ddl_ep
        emap = bytes(32) if emap is None else emap
        seq_d = seq_kd if seq_d is None else seq_d
        im_d = im_kd if im_d is None else im_d
        res_d = res_tx_kd if res_d is None else res_d
        sc = scope if scope_bytes is None else scope_bytes
        si = SI if svc_ident is None else svc_ident
        b = bytearray()
        b += txn + be64(txn_seq) + be64(2) + be32(family)
        b += PARTY + si
        b += F["content"] + F["canon"] + event + be64(gen)
        b += F["epoch"] + be64(1000) + ddl_ep + be64(abs_ddl) + be64(grace)
        b += be32(1) + be32(1) + TARGET  # required_evidence RECEIVED, target_count 1
        b += raw16(sc) + raw16(ikey)
        b += seq_d + im_d + emap + res_d
        b += be64(2) + payload_kd
        return bytes(b)

    body_a = enc_anchor()
    assert len(body_a) <= 1536
    a_key = bkey(6, 0x20, 2, txn)
    val_a = enc_env_full(6, 0x20, 0, 1, txn, F["head_nz"], bytes(32), body_a)
    a_pos = a_neg = a_mut = a_rt = 0
    add(id="DSB2_ANCHOR_DS_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x20, body_length=len(body_a),
        body_hex=hx(body_a))
    a_pos += 1; a_rt += 1
    # EventFact anchor
    ev_id = bytes([0x81] + [0]*14 + [0x42])
    em_kd = complete_key_digest_composite(0x25, raw16(scope) + ev_id)
    SI_E = service_identity(F["ns"], F["svc"], F["schema"], 1, F["dig"], 1, 0, 1)
    body_ae = enc_anchor(
        family=1, event=ev_id, gen=0, ddl_ep=bytes(16),
        abs_ddl=(1 << 64) - 1, grace=0, emap=em_kd, svc_ident=SI_E)
    add(id="DSB2_ANCHOR_EF_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x20, body_length=len(body_ae),
        body_hex=hx(body_ae))
    a_pos += 1; a_rt += 1
    add(id="DSB2_ANCHOR_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x20, key_hex=hx(a_key),
        value_hex=hx(val_a), body_hex=hx(body_a), digest_hex=hx(sha256(val_a)),
        crc_hex=f"{crc32c(val_a[:-4]):08x}")
    a_pos += 1
    # DS with non-zero event id corrupt
    bad_a = enc_anchor(event=ev_id)
    add(id="DSB2_ANCHOR_DS_EVENT_NZ", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20, body_hex=hx(bad_a))
    a_neg += 1
    # target_count != 1
    def enc_anchor_tc2():
        b = bytearray()
        b += txn + be64(txn_seq) + be64(2) + be32(2)
        b += PARTY + SI
        b += F["content"] + F["canon"] + bytes(16) + be64(1)
        b += F["epoch"] + be64(1000) + F["epoch"] + be64(9000) + be64(50)
        b += be32(1) + be32(2) + TARGET
        b += raw16(scope) + raw16(ikey)
        b += seq_kd + im_kd + bytes(32) + res_tx_kd
        b += be64(2) + payload_kd
        return bytes(b)
    add(id="DSB2_ANCHOR_TARGET_COUNT2", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20, body_hex=hx(enc_anchor_tc2()))
    a_neg += 1
    add(id="DSB2_ANCHOR_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20, body_hex=hx(body_a[:-1]))
    a_neg += 1
    add(id="DSB2_ANCHOR_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20, body_hex=hx(body_a + b"\x00"))
    a_neg += 1
    # Zero transaction_id is same-record corrupt (non-zero required).
    mut = bytearray(body_a)
    mut[0:16] = bytes(16)
    add(id="DSB2_ANCHOR_MUT_TXN", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20, body_hex=hx(bytes(mut)))
    a_mut += 1
    a_neg += 1
    mut2 = bytearray(body_a)
    # family at offset 16+8+8=32
    mut2[32:36] = be32(99)
    add(id="DSB2_ANCHOR_MUT_FAMILY", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20, body_hex=hx(bytes(mut2)))
    a_mut += 1
    a_neg += 1
    add(id="DSB2_ANCHOR_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x20,
        body_length=len(body_a), body_hex=hx(body_a), key_length=0)
    a_neg += 1
    # Derived KEY_DIGEST negatives (body decode only).
    # Layout tail: seq(32)+im(32)+emap(32)+resv(32)+sched_seq(8)+payload(32)
    def mut_anchor_digest(offset_from_end, fill):
        m = bytearray(body_a)
        start = len(m) - offset_from_end
        m[start:start + 32] = fill
        return bytes(m)
    add(id="DSB2_ANCHOR_BAD_SEQ_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20,
        body_hex=hx(mut_anchor_digest(32 + 8 + 32 + 32 + 32 + 32, bytes([0xA1] * 32))))
    a_neg += 1
    add(id="DSB2_ANCHOR_BAD_IDEM_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20,
        body_hex=hx(mut_anchor_digest(32 + 8 + 32 + 32 + 32, bytes([0xA2] * 32))))
    a_neg += 1
    # DesiredState: non-zero event_map_key_digest is corrupt
    add(id="DSB2_ANCHOR_BAD_EMAP_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20,
        body_hex=hx(mut_anchor_digest(32 + 8 + 32 + 32, bytes([0xA3] * 32))))
    a_neg += 1
    add(id="DSB2_ANCHOR_BAD_RESV_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20,
        body_hex=hx(mut_anchor_digest(32 + 8 + 32, bytes([0xA4] * 32))))
    a_neg += 1
    # EventFact wrong event_map KEY_DIGEST
    bad_ae = bytearray(body_ae)
    # emap is third digest of four before sched+payload
    bad_ae[-(32 + 8 + 32 + 32):- (32 + 8 + 32)] = bytes([0xA5] * 32)
    add(id="DSB2_ANCHOR_EF_BAD_EMAP_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20, body_hex=hx(bytes(bad_ae)))
    a_neg += 1
    # Scope namespace/service mismatch: syntactically valid scope_raw but not
    # exact encoding of source.app || service.namespace || service.service.
    scope_mismatch = scope_raw(F["app"], b"other.ns", F["svc"])
    assert scope_mismatch != scope
    add(id="DSB2_ANCHOR_SCOPE_NS_MISMATCH", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x20,
        body_hex=hx(enc_anchor(scope_bytes=scope_mismatch)))
    a_neg += 1
    b2_cov["20"] = add_body_suite("TRANSACTION_ANCHOR", 6, 0x20, a_pos, a_neg, a_mut, a_rt)

    # SEQUENCE_INDEX (secondary → primary_id = body transaction_id)
    body_si = be64(1) + txn + sha256(b"anchor-value")
    assert len(body_si) == 56
    si_key = bkey(6, 0x21, 3, be64(1))
    si_self_primary = primary_id_from_identity(3, be64(1))  # old wrong: padded seq
    assert si_self_primary != txn
    val_si = enc_env_full(6, 0x21, 0, 1, txn, F["head_nz"], F["pvd_nz"], body_si)
    si_pos = si_neg = si_mut = si_rt = 0
    add(id="DSB2_SEQ_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x21, body_length=56, body_hex=hx(body_si))
    si_pos += 1; si_rt += 1
    add(id="DSB2_SEQ_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x21, key_hex=hx(si_key),
        value_hex=hx(val_si), body_hex=hx(body_si), digest_hex=hx(sha256(val_si)),
        crc_hex=f"{crc32c(val_si[:-4]):08x}")
    si_pos += 1
    val_si_self = enc_env_full(
        6, 0x21, 0, 1, si_self_primary, F["head_nz"], F["pvd_nz"], body_si)
    add(id="DSB2_SEQ_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x21, key_hex=hx(si_key),
        value_hex=hx(val_si_self))
    si_neg += 1
    add(id="DSB2_SEQ_ZERO_SEQ", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x21,
        body_hex=hx(be64(0) + txn + sha256(b"a")))
    si_neg += 1
    add(id="DSB2_SEQ_ZERO_TXN", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x21,
        body_hex=hx(be64(1) + bytes(16) + sha256(b"a")))
    si_neg += 1
    add(id="DSB2_SEQ_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x21, body_hex=hx(body_si[:-1]))
    si_neg += 1
    add(id="DSB2_SEQ_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x21, body_hex=hx(body_si + b"\x00"))
    si_neg += 1
    add(id="DSB2_SEQ_ZERO_DIG", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x21,
        body_hex=hx(be64(1) + txn + bytes(32)))
    si_mut += 1; si_neg += 1
    add(id="DSB2_SEQ_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x21,
        body_length=56, body_hex=hx(body_si), key_length=0)
    si_neg += 1
    b2_cov["21"] = add_body_suite("TRANSACTION_SEQUENCE_INDEX", 6, 0x21, si_pos, si_neg, si_mut, si_rt)

    # TRANSACTION_STATE (secondary; key ID128 == body txn, so self-key form equals correct)
    def enc_state(state=1, outcome=0, dlv=0, lev=0, reason=0, park=0,
                  late=0, disc=0, tstate=None):
        tstate = state if tstate is None else tstate
        b = bytearray()
        b += txn + sha256(b"anchor-value")
        b += be32(state) + be32(outcome) + be32(dlv) + be32(lev) + be32(reason) + be32(park)
        b += be64(0) + be32(0) + be64(0) + be64(0)
        b += be32(late) + be32(disc) + TARGET
        b += be32(tstate) + be32(outcome) + be32(reason) + be32(lev)
        return bytes(b)
    body_st = enc_state()
    assert len(body_st) == 224
    st_key = bkey(6, 0x22, 2, txn)
    # primary_id = body transaction_id (coincides with ID128 key form).
    val_st = enc_env_full(6, 0x22, 0, 1, txn, F["head_nz"], F["pvd_nz"], body_st)
    st_pos = st_neg = st_mut = st_rt = 0
    add(id="DSB2_STATE_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x22, body_length=224, body_hex=hx(body_st))
    st_pos += 1; st_rt += 1
    add(id="DSB2_STATE_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x22, key_hex=hx(st_key),
        value_hex=hx(val_st), body_hex=hx(body_st), digest_hex=hx(sha256(val_st)),
        crc_hex=f"{crc32c(val_st[:-4]):08x}")
    st_pos += 1
    # Wrong primary_id (not self-key-distinct for ID128; still prove body-derived check).
    val_st_bad = enc_env_full(
        6, 0x22, 0, 1, bytes([0xEE] * 16), F["head_nz"], F["pvd_nz"], body_st)
    add(id="DSB2_STATE_TYPED_BAD_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x22, key_hex=hx(st_key),
        value_hex=hx(val_st_bad))
    st_neg += 1
    add(id="DSB2_STATE_BAD_ENUM", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x22, body_hex=hx(enc_state(state=0)))
    st_neg += 1
    add(id="DSB2_STATE_TARGET_MISMATCH", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x22, body_hex=hx(enc_state(tstate=2)))
    st_neg += 1
    add(id="DSB2_STATE_BOOL2", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x22, body_hex=hx(enc_state(late=2)))
    st_neg += 1
    add(id="DSB2_STATE_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x22, body_hex=hx(body_st[:-1]))
    st_neg += 1
    add(id="DSB2_STATE_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x22, body_hex=hx(body_st + b"\x00"))
    st_neg += 1
    mut = bytearray(body_st); mut[48] ^= 0x08  # state high bit
    add(id="DSB2_STATE_MUT_STATE", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x22, body_hex=hx(bytes(mut)))
    st_mut += 1; st_neg += 1
    add(id="DSB2_STATE_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x22,
        body_length=224, body_hex=hx(body_st), key_length=0)
    st_neg += 1
    b2_cov["22"] = add_body_suite("TRANSACTION_STATE", 6, 0x22, st_pos, st_neg, st_mut, st_rt)

    # RESERVATION — all five owner kinds (typed + self-key primary negatives)
    rv = resource_vector([(0, 0)] * 11)
    dlv_raw = F["rt"] + F["app"] + txn + F["trt"] + F["tapp"]
    assert len(dlv_raw) == 80
    ingress_seq = be64(7)
    cb_owner_raw = raw16(dlv_raw) + be64(3)  # delivery_key_raw:RAW16 || token_generation
    dlv_primary = primary_id_from_composite_subtype(0x40, raw16(dlv_raw))
    svc_primary = primary_id_from_composite_subtype(0x10, sk_raw16)

    def enc_res_body(owner_kind, owner_raw_contents, inflight=0, pkd=None):
        if pkd is None:
            pkd = reservation_primary_key_digest(owner_kind, owner_raw_contents)
        return (
            be16(owner_kind) + be16(0) + raw16(owner_raw_contents)
            + pkd + rv + be32(inflight) + be32(0) + be64(0) + be32(0)
        )

    def res_owner_primary(owner_kind, owner_raw_contents):
        if owner_kind == 1:  # SERVICE
            return primary_id_from_composite_subtype(0x10, raw16(owner_raw_contents))
        if owner_kind == 2:  # TRANSACTION
            return owner_raw_contents  # transaction_id
        if owner_kind == 3:  # INGRESS
            return primary_id_from_identity(3, owner_raw_contents)
        if owner_kind == 4:  # DELIVERY
            return primary_id_from_composite_subtype(0x40, raw16(owner_raw_contents))
        if owner_kind == 5:  # CALLBACK → DELIVERY composite of delivery RAW16 prefix
            dlen = int.from_bytes(owner_raw_contents[:2], "big")
            return primary_id_from_composite_subtype(
                0x40, owner_raw_contents[: 2 + dlen])
        raise ValueError("bad owner kind")

    def mut_res_primary_kd(body: bytes) -> bytes:
        """Corrupt primary_key_digest field (after owner_kind+reserved+RAW16)."""
        m = bytearray(body)
        # primary_key_digest starts after: u16+u16+raw16(owner)
        owner_len = int.from_bytes(m[4:6], "big")
        off = 6 + owner_len
        m[off:off + 32] = bytes([0xB0] * 32)
        return bytes(m)

    r_pos = r_neg = r_mut = r_rt = 0
    # TRANSACTION owner
    body_r = enc_res_body(2, txn)
    r_comp = composite(0x23, be16(2) + raw16(txn))
    r_key = bkey(6, 0x23, 5, r_comp)
    r_primary = res_owner_primary(2, txn)
    assert r_primary == txn and r_primary != r_comp[:16]
    assert reservation_primary_key_digest(2, txn) == complete_key_digest_id128(0x20, txn)
    val_r = enc_env_full(6, 0x23, 0, 1, r_primary, F["head_nz"], F["pvd_nz"], body_r)
    add(id="DSB2_RES_TX_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x23, body_length=len(body_r),
        body_hex=hx(body_r))
    r_pos += 1; r_rt += 1
    add(id="DSB2_RES_TX_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x23, key_hex=hx(r_key),
        value_hex=hx(val_r), body_hex=hx(body_r), digest_hex=hx(sha256(val_r)),
        crc_hex=f"{crc32c(val_r[:-4]):08x}")
    r_pos += 1
    val_r_self = enc_env_full(
        6, 0x23, 0, 1, r_comp[:16], F["head_nz"], F["pvd_nz"], body_r)
    add(id="DSB2_RES_TX_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x23, key_hex=hx(r_key),
        value_hex=hx(val_r_self))
    r_neg += 1
    add(id="DSB2_RES_TX_BAD_PRIMARY_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23,
        body_hex=hx(mut_res_primary_kd(body_r)))
    r_neg += 1
    r_mut += 1

    # SERVICE owner
    body_rs = enc_res_body(1, sk_raw, inflight=1)
    rs_comp = composite(0x23, be16(1) + raw16(sk_raw))
    rs_key = bkey(6, 0x23, 5, rs_comp)
    rs_primary = res_owner_primary(1, sk_raw)
    assert rs_primary == svc_primary and rs_primary != rs_comp[:16]
    val_rs = enc_env_full(6, 0x23, 0, 1, rs_primary, F["head_nz"], F["pvd_nz"], body_rs)
    add(id="DSB2_RES_SVC_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x23, body_length=len(body_rs),
        body_hex=hx(body_rs))
    r_pos += 1; r_rt += 1
    add(id="DSB2_RES_SVC_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x23, key_hex=hx(rs_key),
        value_hex=hx(val_rs), body_hex=hx(body_rs), digest_hex=hx(sha256(val_rs)),
        crc_hex=f"{crc32c(val_rs[:-4]):08x}")
    r_pos += 1
    val_rs_self = enc_env_full(
        6, 0x23, 0, 1, rs_comp[:16], F["head_nz"], F["pvd_nz"], body_rs)
    add(id="DSB2_RES_SVC_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x23, key_hex=hx(rs_key),
        value_hex=hx(val_rs_self))
    r_neg += 1
    add(id="DSB2_RES_SVC_BAD_PRIMARY_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23,
        body_hex=hx(mut_res_primary_kd(body_rs)))
    r_neg += 1
    r_mut += 1

    # INGRESS owner
    body_ri = enc_res_body(3, ingress_seq)
    ri_comp = composite(0x23, be16(3) + raw16(ingress_seq))
    ri_key = bkey(6, 0x23, 5, ri_comp)
    ri_primary = res_owner_primary(3, ingress_seq)
    assert ri_primary == primary_id_from_identity(3, ingress_seq)
    assert ri_primary != ri_comp[:16]
    val_ri = enc_env_full(6, 0x23, 0, 1, ri_primary, F["head_nz"], F["pvd_nz"], body_ri)
    add(id="DSB2_RES_ING_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x23, body_length=len(body_ri),
        body_hex=hx(body_ri))
    r_pos += 1; r_rt += 1
    add(id="DSB2_RES_ING_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x23, key_hex=hx(ri_key),
        value_hex=hx(val_ri), body_hex=hx(body_ri), digest_hex=hx(sha256(val_ri)),
        crc_hex=f"{crc32c(val_ri[:-4]):08x}")
    r_pos += 1
    val_ri_self = enc_env_full(
        6, 0x23, 0, 1, ri_comp[:16], F["head_nz"], F["pvd_nz"], body_ri)
    add(id="DSB2_RES_ING_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x23, key_hex=hx(ri_key),
        value_hex=hx(val_ri_self))
    r_neg += 1
    add(id="DSB2_RES_ING_BAD_PRIMARY_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23,
        body_hex=hx(mut_res_primary_kd(body_ri)))
    r_neg += 1
    r_mut += 1

    # DELIVERY owner
    body_rd = enc_res_body(4, dlv_raw)
    rd_comp = composite(0x23, be16(4) + raw16(dlv_raw))
    rd_key = bkey(6, 0x23, 5, rd_comp)
    rd_primary = res_owner_primary(4, dlv_raw)
    assert rd_primary == dlv_primary and rd_primary != rd_comp[:16]
    val_rd = enc_env_full(6, 0x23, 0, 1, rd_primary, F["head_nz"], F["pvd_nz"], body_rd)
    add(id="DSB2_RES_DLV_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x23, body_length=len(body_rd),
        body_hex=hx(body_rd))
    r_pos += 1; r_rt += 1
    add(id="DSB2_RES_DLV_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x23, key_hex=hx(rd_key),
        value_hex=hx(val_rd), body_hex=hx(body_rd), digest_hex=hx(sha256(val_rd)),
        crc_hex=f"{crc32c(val_rd[:-4]):08x}")
    r_pos += 1
    val_rd_self = enc_env_full(
        6, 0x23, 0, 1, rd_comp[:16], F["head_nz"], F["pvd_nz"], body_rd)
    add(id="DSB2_RES_DLV_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x23, key_hex=hx(rd_key),
        value_hex=hx(val_rd_self))
    r_neg += 1
    add(id="DSB2_RES_DLV_BAD_PRIMARY_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23,
        body_hex=hx(mut_res_primary_kd(body_rd)))
    r_neg += 1
    r_mut += 1

    # CALLBACK owner (primary = DELIVERY composite of embedded delivery RAW16)
    body_rc = enc_res_body(5, cb_owner_raw)
    rc_comp = composite(0x23, be16(5) + raw16(cb_owner_raw))
    rc_key = bkey(6, 0x23, 5, rc_comp)
    rc_primary = res_owner_primary(5, cb_owner_raw)
    assert rc_primary == dlv_primary and rc_primary != rc_comp[:16]
    # CALLBACK primary_key_digest equals DELIVERY KEY_DIGEST (token gen ignored)
    assert (reservation_primary_key_digest(5, cb_owner_raw)
            == reservation_primary_key_digest(4, dlv_raw))
    val_rc = enc_env_full(6, 0x23, 0, 1, rc_primary, F["head_nz"], F["pvd_nz"], body_rc)
    add(id="DSB2_RES_CB_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x23, body_length=len(body_rc),
        body_hex=hx(body_rc))
    r_pos += 1; r_rt += 1
    add(id="DSB2_RES_CB_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x23, key_hex=hx(rc_key),
        value_hex=hx(val_rc), body_hex=hx(body_rc), digest_hex=hx(sha256(val_rc)),
        crc_hex=f"{crc32c(val_rc[:-4]):08x}")
    r_pos += 1
    val_rc_self = enc_env_full(
        6, 0x23, 0, 1, rc_comp[:16], F["head_nz"], F["pvd_nz"], body_rc)
    add(id="DSB2_RES_CB_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x23, key_hex=hx(rc_key),
        value_hex=hx(val_rc_self))
    r_neg += 1
    add(id="DSB2_RES_CB_BAD_PRIMARY_KD", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23,
        body_hex=hx(mut_res_primary_kd(body_rc)))
    r_neg += 1
    r_mut += 1

    # released bit with nonzero resource
    rv_bad = resource_vector([(1, 0)] + [(0, 0)] * 10)
    body_rb = (
        be16(2) + be16(0) + raw16(txn)
        + reservation_primary_key_digest(2, txn) + rv_bad
        + be32(0) + be32(0) + be64(0) + be32(1)
    )
    add(id="DSB2_RES_RELEASED_NONEMPTY", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23, body_hex=hx(body_rb))
    r_neg += 1
    add(id="DSB2_RES_OWNER0", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23,
        body_hex=hx(be16(0) + be16(0) + raw16(txn)
                    + reservation_primary_key_digest(2, txn)
                    + rv + be32(0) + be32(0) + be64(0) + be32(0)))
    r_neg += 1
    add(id="DSB2_RES_RESERVED", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23,
        body_hex=hx(be16(2) + be16(1) + raw16(txn)
                    + reservation_primary_key_digest(2, txn)
                    + rv + be32(0) + be32(0) + be64(0) + be32(0)))
    r_neg += 1
    add(id="DSB2_RES_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23, body_hex=hx(body_r[:-1]))
    r_neg += 1
    add(id="DSB2_RES_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23, body_hex=hx(body_r + b"\x00"))
    r_neg += 1
    mut = bytearray(body_r); mut[2] ^= 0x01
    add(id="DSB2_RES_MUT_RESERVED", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x23, body_hex=hx(bytes(mut)))
    r_mut += 1; r_neg += 1
    add(id="DSB2_RES_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x23,
        body_length=len(body_r), body_hex=hx(body_r), key_length=0)
    r_neg += 1
    b2_cov["23"] = add_body_suite("RESERVATION", 6, 0x23, r_pos, r_neg, r_mut, r_rt)

    # IDEMPOTENCY_MAP (secondary → primary_id = body transaction_id)
    body_im = raw16(scope) + raw16(ikey) + txn + F["canon"] + sha256(b"anchor-value")
    im_comp = composite(0x24, raw16(scope) + raw16(ikey))
    im_key = bkey(6, 0x24, 5, im_comp)
    assert im_comp[:16] != txn
    val_im = enc_env_full(6, 0x24, 0, 1, txn, F["head_nz"], F["pvd_nz"], body_im)
    im_pos = im_neg = im_mut = im_rt = 0
    add(id="DSB2_IDEM_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x24, body_length=len(body_im),
        body_hex=hx(body_im))
    im_pos += 1; im_rt += 1
    add(id="DSB2_IDEM_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x24, key_hex=hx(im_key),
        value_hex=hx(val_im), body_hex=hx(body_im), digest_hex=hx(sha256(val_im)),
        crc_hex=f"{crc32c(val_im[:-4]):08x}")
    im_pos += 1
    val_im_self = enc_env_full(
        6, 0x24, 0, 1, im_comp[:16], F["head_nz"], F["pvd_nz"], body_im)
    add(id="DSB2_IDEM_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x24, key_hex=hx(im_key),
        value_hex=hx(val_im_self))
    im_neg += 1
    add(id="DSB2_IDEM_EMPTY_KEY", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x24,
        body_hex=hx(raw16(scope) + raw16(b"") + txn + F["canon"] + sha256(b"a")))
    im_neg += 1
    add(id="DSB2_IDEM_KEY_65", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x24,
        body_hex=hx(raw16(scope) + raw16(b"x"*65) + txn + F["canon"] + sha256(b"a")))
    im_neg += 1
    add(id="DSB2_IDEM_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x24, body_hex=hx(body_im[:-1]))
    im_neg += 1
    add(id="DSB2_IDEM_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x24, body_hex=hx(body_im + b"\x00"))
    im_neg += 1
    # Zero application_instance_id in scope_raw (must be non-zero).
    mut = bytearray(body_im)
    mut[2:18] = bytes(16)
    add(id="DSB2_IDEM_MUT_SCOPE", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x24, body_hex=hx(bytes(mut)))
    im_mut += 1; im_neg += 1
    add(id="DSB2_IDEM_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x24,
        body_length=len(body_im), body_hex=hx(body_im), key_length=0)
    im_neg += 1
    b2_cov["24"] = add_body_suite("IDEMPOTENCY_MAP", 6, 0x24, im_pos, im_neg, im_mut, im_rt)

    # EVENT_ID_MAP (secondary → primary_id = body transaction_id)
    body_em = raw16(scope) + ev_id + txn + F["canon"] + raw16(ikey) + sha256(b"anchor-value")
    em_comp = composite(0x25, raw16(scope) + ev_id)
    em_key = bkey(6, 0x25, 5, em_comp)
    assert em_comp[:16] != txn
    val_em = enc_env_full(6, 0x25, 0, 1, txn, F["head_nz"], F["pvd_nz"], body_em)
    em_pos = em_neg = em_mut = em_rt = 0
    add(id="DSB2_EVMAP_POSITIVE", suite="DSB2", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x25, body_length=len(body_em),
        body_hex=hx(body_em))
    em_pos += 1; em_rt += 1
    add(id="DSB2_EVMAP_TYPED", suite="DSB2", op="typed_record",
        expected_status="OK", family=6, subtype=0x25, key_hex=hx(em_key),
        value_hex=hx(val_em), body_hex=hx(body_em), digest_hex=hx(sha256(val_em)),
        crc_hex=f"{crc32c(val_em[:-4]):08x}")
    em_pos += 1
    val_em_self = enc_env_full(
        6, 0x25, 0, 1, em_comp[:16], F["head_nz"], F["pvd_nz"], body_em)
    add(id="DSB2_EVMAP_TYPED_SELF_PRIMARY", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x25, key_hex=hx(em_key),
        value_hex=hx(val_em_self))
    em_neg += 1
    add(id="DSB2_EVMAP_ZERO_EVENT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x25,
        body_hex=hx(raw16(scope) + bytes(16) + txn + F["canon"] + raw16(ikey) + sha256(b"a")))
    em_neg += 1
    add(id="DSB2_EVMAP_SHORT", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x25, body_hex=hx(body_em[:-1]))
    em_neg += 1
    add(id="DSB2_EVMAP_TRAILING", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x25, body_hex=hx(body_em + b"\x00"))
    em_neg += 1
    add(id="DSB2_EVMAP_ZERO_DIG", suite="DSB2", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x25,
        body_hex=hx(raw16(scope) + ev_id + txn + F["canon"] + raw16(ikey) + bytes(32)))
    em_mut += 1; em_neg += 1
    add(id="DSB2_EVMAP_BUFFER_TOO_SMALL", suite="DSB2", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x25,
        body_length=len(body_em), body_hex=hx(body_em), key_length=0)
    em_neg += 1
    # alias-style typed bad composite
    bad_em_key = bkey(6, 0x25, 5, bytes([0x55]*32))
    add(id="DSB2_EVMAP_TYPED_BAD_COMPOSITE", suite="DSB2", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x25, key_hex=hx(bad_em_key),
        value_hex=hx(val_em))
    em_neg += 1
    b2_cov["25"] = add_body_suite("EVENT_ID_MAP", 6, 0x25, em_pos, em_neg, em_mut, em_rt)

    for st in ("10", "11", "20", "21", "22", "23", "24", "25"):
        assert b2_cov[st]["positive"] >= 1
        assert b2_cov[st]["negative"] >= 3
        assert b2_cov[st]["roundtrip"] >= 1

    # --- D1-B3a: SCHEDULER_OWNER (0x26) only ---
    b3_cov = {}
    s_pos = s_neg = s_mut = s_rt = 0
    owner_seq_tx = 1
    owner_seq_dlv = 2
    owner_seq_ing = 3
    logical_epoch = bytes([0xC1]) + bytes([0xC2] * 15)
    wake_epoch = bytes([0xD1]) + bytes([0xD2] * 15)
    assert len(logical_epoch) == 16 and len(wake_epoch) == 16
    assert logical_epoch != bytes(16) and wake_epoch != bytes(16)
    # dlv_raw already built for RESERVATION: 80 bytes five non-zero IDs
    assert len(dlv_raw) == 80
    ingress_seq8 = be64(7)

    def enc_sched_body(
        owner_seq, owner_kind, subject, work_class=1, state_rev=1,
        ready=0, wake_ep=None, wake_ms=0, logical_ms=0, pkd=None,
    ):
        if wake_ep is None:
            wake_ep = bytes(16)
        if pkd is None:
            pkd = scheduler_primary_key_digest(owner_kind, subject)
        return (
            be64(owner_seq) + be16(owner_kind) + be16(work_class)
            + raw16(subject) + pkd + be64(state_rev)
            + logical_epoch + be64(logical_ms)
            + wake_ep + be64(wake_ms) + be32(ready)
        )

    def sched_typed(owner_seq, owner_kind, subject, body, rev=3, state_rev=None):
        """rev is common record_revision; intentionally may differ from state_rev."""
        primary = scheduler_primary_id(owner_kind, subject)
        key = bkey(6, 0x26, 3, be64(owner_seq))
        # Self-key form would be left-pad owner_seq; must differ for non-matching cases
        assert primary != primary_id_from_identity(3, be64(owner_seq)) or owner_kind == 3
        val = enc_env_full(
            6, 0x26, 0, rev, primary, F["head_nz"], F["pvd_nz"], body)
        return key, val, primary

    # TRANSACTION: ready=0, no wake; state_revision != common revision
    body_stx = enc_sched_body(
        owner_seq_tx, 1, txn, work_class=1, state_rev=5, ready=0, logical_ms=0)
    assert len(body_stx) == 122
    assert scheduler_primary_key_digest(1, txn) == complete_key_digest_id128(0x20, txn)
    # identity-digest confusion: sha256(txn) != KEY_DIGEST(complete key)
    assert scheduler_primary_key_digest(1, txn) != sha256(txn)
    stx_key, val_stx, stx_primary = sched_typed(
        owner_seq_tx, 1, txn, body_stx, rev=3)
    assert stx_primary == txn
    add(id="DSB3_SCHED_TX_POSITIVE", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x26, body_length=len(body_stx),
        body_hex=hx(body_stx))
    s_pos += 1; s_rt += 1
    add(id="DSB3_SCHED_TX_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x26, key_hex=hx(stx_key),
        value_hex=hx(val_stx), body_hex=hx(body_stx), digest_hex=hx(sha256(val_stx)),
        crc_hex=f"{crc32c(val_stx[:-4]):08x}", notes="common_rev=3 state_rev=5")
    s_pos += 1
    add(id="DSB3_SCHED_READY0_NO_WAKE", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x26, body_length=len(body_stx),
        body_hex=hx(body_stx), notes="ready=0 next_wake both zero")
    s_pos += 1; s_rt += 1

    # DELIVERY: ready=1 + future wake positive
    body_sdl = enc_sched_body(
        owner_seq_dlv, 2, dlv_raw, work_class=2, state_rev=2, ready=1,
        wake_ep=wake_epoch, wake_ms=9999, logical_ms=100)
    assert len(body_sdl) == 186
    sdl_key, val_sdl, sdl_primary = sched_typed(
        owner_seq_dlv, 2, dlv_raw, body_sdl, rev=7)
    assert sdl_primary != primary_id_from_identity(3, be64(owner_seq_dlv))
    add(id="DSB3_SCHED_DLV_POSITIVE", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x26, body_length=len(body_sdl),
        body_hex=hx(body_sdl))
    s_pos += 1; s_rt += 1
    add(id="DSB3_SCHED_DLV_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x26, key_hex=hx(sdl_key),
        value_hex=hx(val_sdl), body_hex=hx(body_sdl), digest_hex=hx(sha256(val_sdl)),
        crc_hex=f"{crc32c(val_sdl[:-4]):08x}")
    s_pos += 1
    add(id="DSB3_SCHED_READY1_FUTURE_WAKE", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x26, body_length=len(body_sdl),
        body_hex=hx(body_sdl), notes="ready=1 + future wake coexist")
    s_pos += 1; s_rt += 1

    # INGRESS: ready=1 + future wake; common rev != state_rev
    body_sin = enc_sched_body(
        owner_seq_ing, 3, ingress_seq8, work_class=3, state_rev=9, ready=1,
        wake_ep=wake_epoch, wake_ms=42, logical_ms=0)
    assert len(body_sin) == 114
    sin_key, val_sin, sin_primary = sched_typed(
        owner_seq_ing, 3, ingress_seq8, body_sin, rev=4)
    # For INGRESS, primary_id is left-pad ordered_seq — may equal self-key form
    # when owner_sequence happens to equal ordered_seq; here 3 vs 7 so different.
    assert sin_primary == primary_id_from_identity(3, ingress_seq8)
    assert sin_primary != primary_id_from_identity(3, be64(owner_seq_ing))
    add(id="DSB3_SCHED_ING_POSITIVE", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x26, body_length=len(body_sin),
        body_hex=hx(body_sin))
    s_pos += 1; s_rt += 1
    add(id="DSB3_SCHED_ING_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x26, key_hex=hx(sin_key),
        value_hex=hx(val_sin), body_hex=hx(body_sin), digest_hex=hx(sha256(val_sin)),
        crc_hex=f"{crc32c(val_sin[:-4]):08x}", notes="common_rev=4 state_rev=9")
    s_pos += 1
    add(id="DSB3_SCHED_REV_NE_STATE", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x26, key_hex=hx(sin_key),
        value_hex=hx(val_sin), body_hex=hx(body_sin),
        notes="common record_revision != state_revision valid")
    s_pos += 1

    # --- negatives ---
    dummy_pkd = bytes([0xAB] * 32)
    add(id="DSB3_SCHED_OWNER0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 0, txn, pkd=dummy_pkd)))
    s_neg += 1
    add(id="DSB3_SCHED_OWNER4", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 4, txn, pkd=dummy_pkd)))
    s_neg += 1
    add(id="DSB3_SCHED_WORK0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 1, txn, work_class=0)))
    s_neg += 1
    add(id="DSB3_SCHED_WORK7", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 1, txn, work_class=7)))
    s_neg += 1
    add(id="DSB3_SCHED_SUBJECT_LEN", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 1, txn[:15], pkd=dummy_pkd)))
    s_neg += 1
    add(id="DSB3_SCHED_SUBJECT_ZERO_TX", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 1, bytes(16), pkd=dummy_pkd)))
    s_neg += 1
    add(id="DSB3_SCHED_SUBJECT_ZERO_ING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(3, 3, be64(0), pkd=dummy_pkd)))
    s_neg += 1
    # primary_key_digest mutation
    mut_pkd = bytearray(body_stx)
    # after owner_seq(8)+kind(2)+work(2)+raw16(2+16)=30, digest at offset 30
    off_pkd = 8 + 2 + 2 + 2 + 16
    mut_pkd[off_pkd:off_pkd + 32] = bytes([0xB0] * 32)
    add(id="DSB3_SCHED_BAD_PRIMARY_KD", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(bytes(mut_pkd)))
    s_neg += 1; s_mut += 1
    # complete-key vs identity-digest confusion
    body_id_dig = enc_sched_body(
        1, 1, txn, pkd=sha256(txn))  # bare identity digest, not KEY_DIGEST
    add(id="DSB3_SCHED_IDENTITY_DIGEST_CONFUSION", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(body_id_dig),
        notes="primary_key_digest must be KEY_DIGEST(complete key), not sha256(id)")
    s_neg += 1
    # owner key sequence mismatch: key has seq 99, body has seq 1
    bad_seq_key = bkey(6, 0x26, 3, be64(99))
    add(id="DSB3_SCHED_SEQ_MISMATCH", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x26, key_hex=hx(bad_seq_key),
        value_hex=hx(val_stx))
    s_neg += 1
    # wrong common primary_id using scheduler self-key (left-pad owner_sequence)
    self_pid = primary_id_from_identity(3, be64(owner_seq_tx))
    assert self_pid != txn
    val_self = enc_env_full(
        6, 0x26, 0, 3, self_pid, F["head_nz"], F["pvd_nz"], body_stx)
    add(id="DSB3_SCHED_SELF_PRIMARY", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x26, key_hex=hx(stx_key),
        value_hex=hx(val_self),
        notes="primary_id must be referenced primary, not scheduler self-key")
    s_neg += 1
    # zero head
    val_zh = enc_env_full(
        6, 0x26, 0, 3, stx_primary, bytes(32), F["pvd_nz"], body_stx)
    add(id="DSB3_SCHED_ZERO_HEAD", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x26, key_hex=hx(stx_key),
        value_hex=hx(val_zh))
    s_neg += 1
    # zero pvd
    val_zp = enc_env_full(
        6, 0x26, 0, 3, stx_primary, F["head_nz"], bytes(32), body_stx)
    add(id="DSB3_SCHED_ZERO_PVD", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x26, key_hex=hx(stx_key),
        value_hex=hx(val_zp))
    s_neg += 1
    # flags non-zero
    val_fl = enc_env_full(
        6, 0x26, 1, 3, stx_primary, F["head_nz"], F["pvd_nz"], body_stx)
    add(id="DSB3_SCHED_FLAGS", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x26, key_hex=hx(stx_key),
        value_hex=hx(val_fl))
    s_neg += 1
    # state_revision 0
    add(id="DSB3_SCHED_STATE_REV0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 1, txn, state_rev=0)))
    s_neg += 1
    # logical epoch zero
    body_le0 = (
        be64(1) + be16(1) + be16(1) + raw16(txn)
        + scheduler_primary_key_digest(1, txn) + be64(1)
        + bytes(16) + be64(0) + bytes(16) + be64(0) + be32(0)
    )
    add(id="DSB3_SCHED_LOGICAL_EPOCH0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26, body_hex=hx(body_le0))
    s_neg += 1
    # ready=2
    add(id="DSB3_SCHED_READY2", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(1, 1, txn, ready=2)))
    s_neg += 1
    # wake mismatch: epoch non-zero, time zero
    add(id="DSB3_SCHED_WAKE_EPOCH_ONLY", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(
            1, 1, txn, wake_ep=wake_epoch, wake_ms=0)))
    s_neg += 1
    # wake mismatch: epoch zero, time non-zero
    add(id="DSB3_SCHED_WAKE_TIME_ONLY", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(
            1, 1, txn, wake_ep=bytes(16), wake_ms=5)))
    s_neg += 1
    # owner_sequence 0
    add(id="DSB3_SCHED_SEQ0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(enc_sched_body(0, 1, txn)))
    s_neg += 1
    add(id="DSB3_SCHED_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(body_stx[:-1]))
    s_neg += 1
    add(id="DSB3_SCHED_TRAILING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x26,
        body_hex=hx(body_stx + b"\x00"))
    s_neg += 1
    add(id="DSB3_SCHED_BUFFER_TOO_SMALL", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x26,
        body_length=len(body_stx), body_hex=hx(body_stx), key_length=0)
    s_neg += 1

    b3_cov["26"] = add_body_suite("SCHEDULER_OWNER", 6, 0x26, s_pos, s_neg, s_mut, s_rt)
    assert b3_cov["26"]["positive"] >= 6
    assert b3_cov["26"]["negative"] >= 15
    assert b3_cov["26"]["roundtrip"] >= 3

    # --- D1-B3b: ORDERED_INGRESS (0x27) + message_semantic_digest helper ---
    # Append-only after the 530 D1-B3a vectors; do not mutate prior objects.
    i_pos = i_neg = i_mut = i_rt = 0
    EMPTY_SHA = sha256(b"")
    NO_DEADLINE = (1 << 64) - 1
    MAX_RETRY_DELAY = 600000
    EVIDENCE_MAX = 128

    def svc_id(ns, svc, schema, rev, dig, major, minor, family):
        return service_identity(ns, svc, schema, rev, dig, major, minor, family)

    SVC_DS = svc_id(F["ns"], F["svc"], F["schema"], 1, F["dig"], 1, 0, 2)
    SVC_EF = svc_id(F["ns"], F["svc"], F["schema"], 1, F["dig"], 1, 0, 1)
    # max TEXT_ID (63) for namespace/service/schema
    max_tid = b"a" + b"b" * 62
    SVC_MAX = svc_id(max_tid, max_tid, max_tid, 1, F["dig"], 1, 0, 2)
    assert len(SVC_MAX) == 1 + 63 + 1 + 63 + 1 + 63 + 8 + 32 + 2 + 2 + 4

    def ingress_res_kd(ordered_seq):
        seq8 = be64(ordered_seq)
        return complete_key_digest_composite(0x23, be16(3) + raw16(seq8))

    def message_semantic_digest(
        kind, flags, txn, attempt, event, src, tgt, svc, content,
        generation, dl_ep, abs_dl, grace, req_ev, receipt, disp, cert,
        guidance, cancel_kind, retry_delay, ev_ep, ev_now, ev_trust,
        payload=b"", evidence=b"",
    ):
        """Exact docs17 §5.1 preimage; independent of production C."""
        pre = b"NINLIL-BEARER-MESSAGE-V1"
        pre += be32(kind) + be32(flags) + txn + attempt + event
        pre += src + tgt + svc + content
        pre += be64(generation) + dl_ep + be64(abs_dl) + be64(grace)
        pre += be32(req_ev) + be32(receipt) + be32(disp) + be32(cert)
        pre += be32(guidance) + be32(cancel_kind) + be64(retry_delay)
        pre += ev_ep + be64(ev_now) + be32(ev_trust)
        pre += be32(len(payload)) + payload + be32(len(evidence)) + evidence
        return sha256(pre)

    # Default controller durable-copy sample for RECEIPT positives (docs17 §8.3).
    CTRL_EP = bytes([0xA1] + [0] * 14 + [0xC1])
    CTRL_EP2 = bytes([0xA2] + [0] * 14 + [0xC2])

    def enc_ingress_body(
        ordered_seq=1, owner_seq=1, binding=3, kind=1, flags=0,
        txn=None, attempt=None, event=None, src=None, tgt=None, svc=None,
        content=None, generation=1, dl_ep=None, abs_dl=5000, grace=100,
        req_ev=3, receipt=0, disp=0, cert=0, guidance=0, cancel_kind=0,
        retry_delay=0, ev_ep=None, ev_now=0, ev_trust=0, reserved1=0,
        ctrl_ep=None, ctrl_at=0, ctrl_trust=0, ctrl_reserved=0,
        semantic=None, payload_blob=None, evidence_blob=None,
        ingress_state=1, res_kd=None, payload=b"", evidence=b"",
        include_controller=True,
    ):
        """ORDERED_INGRESS body. include_controller=False emits pre-r1 wire
        (legacy underlength / migration negative evidence only)."""
        txn = txn if txn is not None else bytes([0x71] + [0] * 14 + [0x01])
        attempt = attempt if attempt is not None else bytes([0x72] + [0] * 14 + [0x02])
        event = event if event is not None else bytes(16)
        src = src if src is not None else PARTY
        tgt = tgt if tgt is not None else TARGET
        svc = svc if svc is not None else SVC_DS
        content = content if content is not None else F["content"]
        dl_ep = dl_ep if dl_ep is not None else F["epoch"]
        ev_ep = ev_ep if ev_ep is not None else bytes(16)
        payload_blob = payload_blob if payload_blob is not None else bytes(32)
        evidence_blob = evidence_blob if evidence_blob is not None else bytes(32)
        # Controller defaults: RECEIPT → nonzero sample; non-RECEIPT → all-zero.
        if ctrl_ep is None:
            if kind == 2:
                ctrl_ep = CTRL_EP
                if ctrl_trust == 0:
                    ctrl_trust = 1  # TRUSTED
            else:
                ctrl_ep = bytes(16)
        if semantic is None:
            # Preimage excludes controller_* (docs17 §5.1 / §8.3).
            semantic = message_semantic_digest(
                kind, flags, txn, attempt, event, src, tgt, svc, content,
                generation, dl_ep, abs_dl, grace, req_ev, receipt, disp, cert,
                guidance, cancel_kind, retry_delay, ev_ep, ev_now, ev_trust,
                payload=payload, evidence=evidence,
            )
        if res_kd is None:
            res_kd = ingress_res_kd(ordered_seq)
        head = (
            be64(ordered_seq) + be64(owner_seq) + be16(binding) + be16(0)
            + be32(kind) + be32(flags) + txn + attempt + event
            + src + tgt + svc + content + be64(generation) + dl_ep
            + be64(abs_dl) + be64(grace) + be32(req_ev) + be32(receipt)
            + be32(disp) + be32(cert) + be32(guidance) + be32(cancel_kind)
            + be64(retry_delay) + ev_ep + be64(ev_now) + be32(ev_trust)
            + be32(reserved1)
        )
        if include_controller:
            head += (
                ctrl_ep + be64(ctrl_at) + be32(ctrl_trust) + be32(ctrl_reserved)
            )
        return (
            head + semantic + payload_blob + evidence_blob
            + be32(ingress_state) + res_kd
        )

    def ingress_typed(ordered_seq, body, head=None):
        key = ordered_ingress_key(be64(ordered_seq))
        pid = primary_id_from_identity(3, be64(ordered_seq))
        head = head if head is not None else F["head_nz"]
        val = enc_env_full(6, 0x27, 0, 1, pid, head, bytes(32), body)
        return key, pid, val

    # Shared IDs
    txn1 = bytes([0x71] + [0] * 14 + [0x01])
    att1 = bytes([0x72] + [0] * 14 + [0x02])
    att2 = bytes([0x73] + [0] * 14 + [0x03])
    ev_id = bytes([0x81] + [0] * 14 + [0x11])
    ev_clock = bytes([0x91] + [0] * 14 + [0x22])
    nz_blob = bytes([0xAB] * 32)
    nz_blob2 = bytes([0xCD] * 32)

    # --- positives: all 6 message kinds ---
    # APPLICATION DesiredState empty payload (content = SHA256 empty)
    body_app_ds = enc_ingress_body(
        ordered_seq=1, owner_seq=9, binding=3, kind=1,
        content=EMPTY_SHA, generation=1, abs_dl=5000, grace=50, req_ev=3,
        payload=b"", evidence=b"",
    )
    key_app, pid_app, val_app = ingress_typed(1, body_app_ds)
    add(id="DSB3_ING_APP_DS_EMPTY", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_app_ds), body_hex=hx(body_app_ds))
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_APP_DS_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_app),
        value_hex=hx(val_app), body_hex=hx(body_app_ds),
        digest_hex=hx(sha256(val_app)), crc_hex=f"{crc32c(val_app[:-4]):08x}")
    i_pos += 1

    # APPLICATION EventFact empty
    body_app_ef = enc_ingress_body(
        ordered_seq=2, owner_seq=1, binding=2, kind=1, event=ev_id,
        content=EMPTY_SHA, generation=0, dl_ep=bytes(16), abs_dl=NO_DEADLINE,
        grace=0, req_ev=2, svc=SVC_EF, payload=b"", evidence=b"",
    )
    key_ef, _, val_ef = ingress_typed(2, body_app_ef)
    add(id="DSB3_ING_APP_EF_EMPTY", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_app_ef), body_hex=hx(body_app_ef))
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_APP_EF_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_ef),
        value_hex=hx(val_ef), body_hex=hx(body_app_ef))
    i_pos += 1

    # APPLICATION with non-zero payload blob digest (semantic non-zero, no recompute path)
    body_app_nz = enc_ingress_body(
        ordered_seq=3, owner_seq=2, binding=3, kind=1, content=F["content"],
        generation=2, abs_dl=9000, grace=10, req_ev=4,
        payload_blob=nz_blob, semantic=bytes([0x11] * 32),
    )
    key_nz, _, val_nz = ingress_typed(3, body_app_nz)
    add(id="DSB3_ING_APP_PAYLOAD_BLOB_NZ", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_app_nz), body_hex=hx(body_app_nz),
        notes="non-zero payload_blob_key_digest; semantic non-zero; BLOB recompute D3")
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_APP_PAYLOAD_BLOB_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_nz),
        value_hex=hx(val_nz))
    i_pos += 1

    # RECEIPT empty evidence, now=0 trusted
    body_rcpt0 = enc_ingress_body(
        ordered_seq=4, owner_seq=5, binding=1, kind=2, generation=3,
        abs_dl=7000, grace=20, req_ev=3, receipt=3, ev_ep=ev_clock,
        ev_now=0, ev_trust=1, payload=b"", evidence=b"",
    )
    key_r0, _, val_r0 = ingress_typed(4, body_rcpt0)
    add(id="DSB3_ING_RECEIPT_NOW0", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_rcpt0), body_hex=hx(body_rcpt0),
        notes="evidence_now_ms==0 valid monotonic sample")
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_RECEIPT_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_r0),
        value_hex=hx(val_r0))
    i_pos += 1

    # RECEIPT with evidence blob nz + uncertain trust
    body_rcpt_nz = enc_ingress_body(
        ordered_seq=5, owner_seq=6, binding=1, kind=2, generation=4,
        abs_dl=8000, grace=0, req_ev=4, receipt=4, ev_ep=ev_clock,
        ev_now=100, ev_trust=2, evidence_blob=nz_blob2,
        semantic=bytes([0x22] * 32),
    )
    add(id="DSB3_ING_RECEIPT_EVIDENCE_BLOB_NZ", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_rcpt_nz), body_hex=hx(body_rcpt_nz))
    i_pos += 1; i_rt += 1

    # DISPOSITION tuples — all legal rows
    DISP_TUPLES = [
        (1, 1, 1, 0, "RETRY_LATER_0"),
        (1, 1, 1, MAX_RETRY_DELAY, "RETRY_LATER_MAX"),
        (2, 1, 2, 0, "INVALID_PAYLOAD"),
        (3, 1, 2, 0, "UNSUPPORTED_SCHEMA"),
        (4, 1, 2, 0, "UNAUTHORIZED"),
        (5, 1, 0, 0, "STALE"),
        (6, 1, 1, 0, "BUSY_0"),
        (6, 1, 1, MAX_RETRY_DELAY, "BUSY_MAX"),
        (7, 1, 1, 100, "APPLY_NO_EFFECT"),
        (7, 2, 3, 0, "APPLY_POSSIBLE"),
        (8, 2, 3, 0, "VERIFY_FAILED"),
        (9, 1, 1, 50, "CAPACITY"),
        (10, 2, 3, 0, "OUTCOME_UNKNOWN"),
    ]
    seq = 10
    for disp, cert, guid, delay, tag in DISP_TUPLES:
        body_d = enc_ingress_body(
            ordered_seq=seq, owner_seq=1, binding=1, kind=3, generation=1,
            abs_dl=1000, grace=0, req_ev=1, disp=disp, cert=cert,
            guidance=guid, retry_delay=delay,
        )
        key_d, _, val_d = ingress_typed(seq, body_d)
        add(id=f"DSB3_ING_DISP_{tag}", suite="DSB3", op="body_roundtrip",
            expected_status="OK", family=6, subtype=0x27,
            body_length=len(body_d), body_hex=hx(body_d))
        i_pos += 1; i_rt += 1
        add(id=f"DSB3_ING_DISP_{tag}_TYPED", suite="DSB3", op="typed_record",
            expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_d),
            value_hex=hx(val_d))
        i_pos += 1
        seq += 1

    # CANCEL_REQUEST DesiredState
    body_crq = enc_ingress_body(
        ordered_seq=seq, owner_seq=2, binding=3, kind=4, generation=5,
        abs_dl=2000, grace=0, req_ev=2, attempt=att2,
    )
    key_crq, _, val_crq = ingress_typed(seq, body_crq)
    add(id="DSB3_ING_CANCEL_REQ", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_crq), body_hex=hx(body_crq))
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_CANCEL_REQ_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_crq),
        value_hex=hx(val_crq))
    i_pos += 1
    seq += 1

    # CUSTODY_ACCEPTED
    body_cust = enc_ingress_body(
        ordered_seq=seq, owner_seq=3, binding=1, kind=5, generation=6,
        abs_dl=3000, grace=0, req_ev=3,
    )
    key_cu, _, val_cu = ingress_typed(seq, body_cust)
    add(id="DSB3_ING_CUSTODY", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_cust), body_hex=hx(body_cust))
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_CUSTODY_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_cu),
        value_hex=hx(val_cu))
    i_pos += 1
    seq += 1

    # CANCEL_RESULT both cancel kinds
    for ck, tag in ((1, "FENCED"), (3, "TOO_LATE")):
        body_crs = enc_ingress_body(
            ordered_seq=seq, owner_seq=4, binding=1, kind=6, generation=7,
            abs_dl=4000, grace=0, req_ev=3, cancel_kind=ck, attempt=att2,
        )
        key_crs, _, val_crs = ingress_typed(seq, body_crs)
        add(id=f"DSB3_ING_CANCEL_RES_{tag}", suite="DSB3", op="body_roundtrip",
            expected_status="OK", family=6, subtype=0x27,
            body_length=len(body_crs), body_hex=hx(body_crs))
        i_pos += 1; i_rt += 1
        add(id=f"DSB3_ING_CANCEL_RES_{tag}_TYPED", suite="DSB3", op="typed_record",
            expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_crs),
            value_hex=hx(val_crs))
        i_pos += 1
        seq += 1

    # max TEXT_ID body
    body_max = enc_ingress_body(
        ordered_seq=seq, owner_seq=1, binding=3, kind=1, content=EMPTY_SHA,
        generation=1, abs_dl=1000, grace=0, req_ev=1, svc=SVC_MAX,
    )
    key_max, _, val_max = ingress_typed(seq, body_max)
    add(id="DSB3_ING_MAX_TEXT_ID", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_max), body_hex=hx(body_max),
        notes="namespace/service/schema TEXT_ID length 63")
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_MAX_TEXT_ID_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x27, key_hex=hx(key_max),
        value_hex=hx(val_max))
    i_pos += 1
    seq += 1

    # EXISTING_DELIVERY binding on APPLICATION
    body_exd = enc_ingress_body(
        ordered_seq=seq, owner_seq=8, binding=2, kind=1, content=EMPTY_SHA,
        generation=2, abs_dl=1500, grace=0, req_ev=2,
    )
    add(id="DSB3_ING_BINDING_EXISTING_DELIVERY", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_exd), body_hex=hx(body_exd))
    i_pos += 1; i_rt += 1
    seq += 1

    # helper: body_hex = ORDERED_INGRESS body supplying prefix fields;
    # subject_hex = payload bytes; retention_hex = evidence bytes (optional).
    # payload_length in prefix is taken from subject length (not body blob).
    #
    # B3b wire fixture note (DSB3_MSD_*): op is message_semantic_digest, but
    # body_hex is a full ORDERED_INGRESS body used only as prefix source. r1
    # inserts the controller_ingress 32-byte block into that body_hex, so the
    # four MSD vectors change object bytes under the B3b wire migration.
    # The digest_hex / streamed semantic digest itself is unchanged (preimage
    # excludes controller_*).
    sem_app = message_semantic_digest(
        1, 0, txn1, att1, bytes(16), PARTY, TARGET, SVC_DS, EMPTY_SHA,
        1, F["epoch"], 5000, 50, 3, 0, 0, 0, 0, 0, 0, bytes(16), 0, 0,
        payload=b"", evidence=b"",
    )
    add(id="DSB3_MSD_ONESHOT_EMPTY", suite="DSB3", op="message_semantic_digest",
        expected_status="OK", family=6, subtype=0x27,
        body_hex=hx(body_app_ds), digest_hex=hx(sem_app),
        notes="one-shot empty payload/evidence from body prefix")
    i_pos += 1
    pay = b"payload-bytes-01"
    evi = b"ev" * 8  # 16 bytes
    content_pay = sha256(pay)
    # Non-zero payload blob path so body may carry content_pay without empty-sha rule.
    body_stream_src = enc_ingress_body(
        ordered_seq=90, owner_seq=1, binding=3, kind=1, content=content_pay,
        generation=1, abs_dl=5000, grace=0, req_ev=3, payload_blob=nz_blob,
        semantic=bytes([0x33] * 32),
    )
    sem_stream = message_semantic_digest(
        1, 0, txn1, att1, bytes(16), PARTY, TARGET, SVC_DS, content_pay,
        1, F["epoch"], 5000, 0, 3, 0, 0, 0, 0, 0, 0, bytes(16), 0, 0,
        payload=pay, evidence=evi,
    )
    add(id="DSB3_MSD_STREAM_NONEMPTY", suite="DSB3", op="message_semantic_digest",
        expected_status="OK", family=6, subtype=0x27,
        body_hex=hx(body_stream_src), digest_hex=hx(sem_stream),
        subject_hex=hx(pay), retention_hex=hx(evi),
        notes="streaming multi-chunk payload+evidence")
    i_pos += 1
    evi128 = bytes([0xEE] * EVIDENCE_MAX)
    body_evi_src = enc_ingress_body(
        ordered_seq=91, owner_seq=1, binding=1, kind=2, generation=1,
        abs_dl=5000, grace=0, req_ev=3, receipt=3, ev_ep=ev_clock,
        ev_now=0, ev_trust=1, evidence_blob=nz_blob,
        semantic=bytes([0x44] * 32),
    )
    sem_evi = message_semantic_digest(
        2, 0, txn1, att1, bytes(16), PARTY, TARGET, SVC_DS, F["content"],
        1, F["epoch"], 5000, 0, 3, 3, 0, 0, 0, 0, 0, ev_clock, 0, 1,
        payload=b"", evidence=evi128,
    )
    add(id="DSB3_MSD_EVIDENCE_MAX", suite="DSB3", op="message_semantic_digest",
        expected_status="OK", family=6, subtype=0x27,
        body_hex=hx(body_evi_src), digest_hex=hx(sem_evi),
        retention_hex=hx(evi128), notes="evidence length 128 streaming")
    i_pos += 1

    # --- negatives ---
    add(id="DSB3_ING_SEQ0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(ordered_seq=0, content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_OWNER_SEQ0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(owner_seq=0, content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_BAD_BINDING_APP_TX", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(binding=1, kind=1, content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_BAD_BINDING_RCPT_NEW", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            binding=3, kind=2, generation=1, abs_dl=1000, receipt=2,
            ev_ep=ev_clock, ev_trust=1)))
    i_neg += 1
    add(id="DSB3_ING_KIND0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(kind=0, content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_KIND7", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(kind=7, content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_FLAGS_NZ", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(flags=1, content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_TXN_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(txn=bytes(16), content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_ATTEMPT_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(attempt=bytes(16), content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_CONTENT_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(content=bytes(32))))
    i_neg += 1
    add(id="DSB3_ING_REQ_EV_NONE", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(req_ev=0, content=EMPTY_SHA)))
    i_neg += 1
    add(id="DSB3_ING_CANCEL_ON_EF", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=4, event=ev_id, generation=0, dl_ep=bytes(16),
            abs_dl=NO_DEADLINE, grace=0, svc=SVC_EF)))
    i_neg += 1
    add(id="DSB3_ING_EF_FINITE_DEADLINE", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=1, event=ev_id, generation=0, content=EMPTY_SHA,
            abs_dl=1000, grace=0, svc=SVC_EF, dl_ep=F["epoch"])))
    i_neg += 1
    add(id="DSB3_ING_DS_NO_DEADLINE", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=1, content=EMPTY_SHA, abs_dl=NO_DEADLINE, generation=1)))
    i_neg += 1
    add(id="DSB3_ING_APP_EMPTY_BAD_CONTENT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(content=F["content"])))  # not empty sha
    i_neg += 1
    # disposition illegal: RETRY_LATER with delay over max
    add(id="DSB3_ING_DISP_DELAY_OVER", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=3, generation=1, abs_dl=1000, disp=1, cert=1, guidance=1,
            retry_delay=MAX_RETRY_DELAY + 1)))
    i_neg += 1
    # disposition illegal combo
    add(id="DSB3_ING_DISP_BAD_TUPLE", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=3, generation=1, abs_dl=1000, disp=1, cert=2, guidance=1,
            retry_delay=0)))
    i_neg += 1
    # receipt stage zero
    add(id="DSB3_ING_RECEIPT_STAGE0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=0, ev_ep=ev_clock,
            ev_trust=1)))
    i_neg += 1
    # receipt evidence epoch zero
    add(id="DSB3_ING_RECEIPT_EPOCH0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=bytes(16),
            ev_trust=1)))
    i_neg += 1
    # payload blob on non-APPLICATION
    add(id="DSB3_ING_PAYLOAD_BLOB_ON_RCPT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=ev_clock,
            ev_trust=1, payload_blob=nz_blob, semantic=bytes([1] * 32))))
    i_neg += 1
    # evidence blob on APPLICATION
    add(id="DSB3_ING_EVIDENCE_BLOB_ON_APP", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            content=EMPTY_SHA, evidence_blob=nz_blob, semantic=bytes([1] * 32))))
    i_neg += 1
    # non-zero blob path with zero semantic
    add(id="DSB3_ING_BLOB_NZ_SEMANTIC_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            content=F["content"], payload_blob=nz_blob, semantic=bytes(32))))
    i_neg += 1
    # wrong reservation key digest
    bad_res = enc_ingress_body(content=EMPTY_SHA, res_kd=bytes([0xFF] * 32))
    add(id="DSB3_ING_BAD_RES_KD", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27, body_hex=hx(bad_res))
    i_neg += 1
    # wrong semantic recompute (empty path)
    bad_sem = enc_ingress_body(content=EMPTY_SHA, semantic=bytes([0x5A] * 32))
    add(id="DSB3_ING_BAD_SEMANTIC", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27, body_hex=hx(bad_sem))
    i_neg += 1; i_mut += 1
    # short / trailing
    add(id="DSB3_ING_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(body_app_ds[:-1]))
    i_neg += 1
    add(id="DSB3_ING_TRAILING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(body_app_ds + b"\x00"))
    i_neg += 1
    # BTS
    add(id="DSB3_ING_BUFFER_TOO_SMALL", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x27,
        body_length=len(body_app_ds), body_hex=hx(body_app_ds), key_length=0)
    i_neg += 1
    # typed: key sequence mismatch
    bad_key = ordered_ingress_key(be64(99))
    add(id="DSB3_ING_SEQ_MISMATCH", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x27, key_hex=hx(bad_key),
        value_hex=hx(val_app))
    i_neg += 1
    # typed: wrong primary_id
    bad_pid_val = enc_env_full(
        6, 0x27, 0, 1, bytes([0xFF] * 16), F["head_nz"], bytes(32), body_app_ds)
    add(id="DSB3_ING_BAD_PRIMARY", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x27, key_hex=hx(key_app),
        value_hex=hx(bad_pid_val))
    i_neg += 1
    # typed: revision != 1
    bad_rev = enc_env_full(
        6, 0x27, 0, 2, pid_app, F["head_nz"], bytes(32), body_app_ds)
    add(id="DSB3_ING_REV_NE1", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x27, key_hex=hx(key_app),
        value_hex=hx(bad_rev))
    i_neg += 1
    # typed: zero head
    bad_head = enc_env_full(
        6, 0x27, 0, 1, pid_app, bytes(32), bytes(32), body_app_ds)
    add(id="DSB3_ING_ZERO_HEAD", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x27, key_hex=hx(key_app),
        value_hex=hx(bad_head))
    i_neg += 1
    # typed: non-zero PVD
    bad_pvd = enc_env_full(
        6, 0x27, 0, 1, pid_app, F["head_nz"], F["pvd_nz"], body_app_ds)
    add(id="DSB3_ING_NZ_PVD", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x27, key_hex=hx(key_app),
        value_hex=hx(bad_pvd))
    i_neg += 1
    # typed: flags non-zero
    bad_fl = enc_env_full(
        6, 0x27, 1, 1, pid_app, F["head_nz"], bytes(32), body_app_ds)
    add(id="DSB3_ING_HEADER_FLAGS", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x27, key_hex=hx(key_app),
        value_hex=hx(bad_fl))
    i_neg += 1
    # ingress_state != 1
    add(id="DSB3_ING_STATE_NE1", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(content=EMPTY_SHA, ingress_state=2)))
    i_neg += 1
    # reserved1 non-zero
    add(id="DSB3_ING_RESERVED1", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(content=EMPTY_SHA, reserved1=1)))
    i_neg += 1
    # cancel result bad kind 2
    add(id="DSB3_ING_CANCEL_RES_KIND2", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=6, generation=1, abs_dl=1000, cancel_kind=2)))
    i_neg += 1
    # party invalid: zero runtime
    bad_party = party(bytes(16), F["app"], LI)
    add(id="DSB3_ING_BAD_PARTY", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(content=EMPTY_SHA, src=bad_party)))
    i_neg += 1
    # MSD: evidence over max (129 bytes) — one-shot rejects
    add(id="DSB3_MSD_EVIDENCE_OVERMAX", suite="DSB3",
        op="message_semantic_digest", expected_status="INVALID_ARGUMENT",
        family=6, subtype=0x27, body_hex=hx(body_app_ds),
        retention_hex=hx(bytes(129)), digest_hex=hx(bytes(32)),
        notes="evidence length 129 > 128")
    i_neg += 1

    # --- D1-B3b controller-ingress retrofit (docs17 §8.3) ---
    # New B3b wire fixtures only (appended after the pre-r1 DSB3_ING_/MSD_ set).
    # Non-B3b-wire vectors stay byte-stable (NON_B3B_WIRE_FINGERPRINT).
    body_rcpt_ctrl_t = enc_ingress_body(
        ordered_seq=200, owner_seq=1, binding=1, kind=2, generation=1,
        abs_dl=7000, grace=0, req_ev=3, receipt=3, ev_ep=ev_clock,
        ev_now=0, ev_trust=1, ctrl_ep=CTRL_EP, ctrl_at=0, ctrl_trust=1,
    )
    add(id="DSB3_ING_RECEIPT_CTRL_TRUSTED", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_rcpt_ctrl_t), body_hex=hx(body_rcpt_ctrl_t),
        notes="controller TRUSTED, at_ms=0 valid; semantic excludes controller")
    i_pos += 1; i_rt += 1
    body_rcpt_ctrl_u = enc_ingress_body(
        ordered_seq=201, owner_seq=1, binding=1, kind=2, generation=1,
        abs_dl=7000, grace=0, req_ev=3, receipt=2, ev_ep=ev_clock,
        ev_now=50, ev_trust=2, ctrl_ep=CTRL_EP2, ctrl_at=99, ctrl_trust=2,
    )
    add(id="DSB3_ING_RECEIPT_CTRL_UNCERTAIN", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_rcpt_ctrl_u), body_hex=hx(body_rcpt_ctrl_u),
        notes="controller UNCERTAIN + nonzero at_ms")
    i_pos += 1; i_rt += 1
    # Same semantic digest with different controller samples (independence).
    body_rcpt_a = enc_ingress_body(
        ordered_seq=202, owner_seq=1, binding=1, kind=2, generation=1,
        abs_dl=7000, grace=0, req_ev=3, receipt=3, ev_ep=ev_clock,
        ev_now=0, ev_trust=1, ctrl_ep=CTRL_EP, ctrl_at=1, ctrl_trust=1,
    )
    body_rcpt_b = enc_ingress_body(
        ordered_seq=202, owner_seq=1, binding=1, kind=2, generation=1,
        abs_dl=7000, grace=0, req_ev=3, receipt=3, ev_ep=ev_clock,
        ev_now=0, ev_trust=1, ctrl_ep=CTRL_EP2, ctrl_at=999, ctrl_trust=2,
    )
    # semantic field is identical by construction (same preimage args).
    # Tail: semantic[32] + payload_blob[32] + evidence_blob[32] + state[4] + res_kd[32]
    # => semantic at body[-132:-100].
    sem_a = message_semantic_digest(
        2, 0, txn1, att1, bytes(16), PARTY, TARGET, SVC_DS, F["content"],
        1, F["epoch"], 7000, 0, 3, 3, 0, 0, 0, 0, 0, ev_clock, 0, 1,
    )
    assert body_rcpt_a != body_rcpt_b
    assert body_rcpt_a[-132:-100] == body_rcpt_b[-132:-100] == sem_a
    add(id="DSB3_ING_CTRL_SEMANTIC_INDEP_A", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_rcpt_a), body_hex=hx(body_rcpt_a),
        digest_hex=hx(sem_a),
        notes="controller sample A; message_semantic_digest independent of controller")
    i_pos += 1; i_rt += 1
    add(id="DSB3_ING_CTRL_SEMANTIC_INDEP_B", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_rcpt_b), body_hex=hx(body_rcpt_b),
        digest_hex=hx(sem_a),
        notes="controller sample B differs; semantic digest exact same as A")
    i_pos += 1; i_rt += 1
    # non-RECEIPT must keep controller block all-zero (positive APP already does)
    add(id="DSB3_ING_APP_CTRL_ZERO", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x27,
        body_length=len(body_app_ds), body_hex=hx(body_app_ds),
        notes="non-RECEIPT controller block all-zero")
    i_pos += 1; i_rt += 1

    # controller negatives
    add(id="DSB3_ING_CTRL_ON_APP", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            content=EMPTY_SHA, kind=1, ctrl_ep=CTRL_EP, ctrl_trust=1)))
    i_neg += 1
    add(id="DSB3_ING_CTRL_ON_DISP", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=3, generation=1, abs_dl=1000, disp=1, cert=1, guidance=1,
            retry_delay=0, ctrl_ep=CTRL_EP, ctrl_trust=1)))
    i_neg += 1
    add(id="DSB3_ING_CTRL_EPOCH0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=ev_clock,
            ev_trust=1, ctrl_ep=bytes(16), ctrl_trust=1)))
    i_neg += 1
    add(id="DSB3_ING_CTRL_TRUST0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=ev_clock,
            ev_trust=1, ctrl_ep=CTRL_EP, ctrl_trust=0)))
    i_neg += 1
    add(id="DSB3_ING_CTRL_TRUST3", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=ev_clock,
            ev_trust=1, ctrl_ep=CTRL_EP, ctrl_trust=3)))
    i_neg += 1
    add(id="DSB3_ING_CTRL_HALF", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=ev_clock,
            ev_trust=1, ctrl_ep=bytes(16), ctrl_at=5, ctrl_trust=1)),
        notes="half shape: zero epoch with nonzero trust/at")
    i_neg += 1
    add(id="DSB3_ING_CTRL_RESERVED_NZ", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(enc_ingress_body(
            kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=ev_clock,
            ev_trust=1, ctrl_ep=CTRL_EP, ctrl_trust=1, ctrl_reserved=1)))
    i_neg += 1
    # pre-r1 wire (no controller block) = underlength / corrupt for r1 decoder
    legacy = enc_ingress_body(
        content=EMPTY_SHA, include_controller=False)
    add(id="DSB3_ING_LEGACY_UNDERLENGTH", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(legacy),
        notes="pre-r1 ORDERED_INGRESS wire missing controller 32-byte block")
    i_neg += 1
    legacy_rcpt = enc_ingress_body(
        kind=2, generation=1, abs_dl=1000, receipt=2, ev_ep=ev_clock,
        ev_trust=1, include_controller=False)
    add(id="DSB3_ING_LEGACY_RECEIPT_UNDERLENGTH", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x27,
        body_hex=hx(legacy_rcpt),
        notes="legacy RECEIPT positive under r1 is corrupt underlength")
    i_neg += 1

    b3_cov["27"] = add_body_suite(
        "ORDERED_INGRESS", 6, 0x27, i_pos, i_neg, i_mut, i_rt)
    assert b3_cov["27"]["positive"] >= 20
    assert b3_cov["27"]["negative"] >= 25
    assert b3_cov["27"]["roundtrip"] >= 6

    # ------------------------------------------------------------------
    # B3b wire fixture migration guards (DSB3_ING_ + DSB3_MSD_ only).
    # "B3b wire fixture" = any catalog object whose body_hex (or typed value
    # body) is an ORDERED_INGRESS wire image, including MSD ops that only
    # borrow that body as a prefix source. Not "all of suite DSB3".
    # ------------------------------------------------------------------
    def is_b3b_wire_fixture(v):
        return v["id"].startswith("DSB3_ING_") or v["id"].startswith("DSB3_MSD_")

    def b3b_wire_id_order_hash(ids):
        return hashlib.sha256(
            json.dumps(list(ids), separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    def b3b_wire_object_fingerprint(objs):
        return hashlib.sha256(
            json.dumps(list(objs), sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()

    # HEAD pre-r1 (format d1b3f, 884 vectors): the 87 B3b wire fixtures.
    B3B_WIRE_PRE_R1_COUNT = 87
    B3B_WIRE_PRE_R1_ID_ORDER_HASH = (
        "ba731ccfe4a5a8376ef15e3f5453aeed14c3c54f02524c8085486534eb004382"
    )
    B3B_WIRE_PRE_R1_OBJECT_FINGERPRINT = (
        "1a73495e38d0691d5bb8d777ab2c05a1861e3aa53004f7b028c1b376e533db78"
    )
    # Historical: documents HEAD pre-r1 object bytes (not recomputed at r1).
    assert B3B_WIRE_PRE_R1_COUNT == 87
    assert len(B3B_WIRE_PRE_R1_OBJECT_FINGERPRINT) == 64

    # Exact pre-r1 / existing-r1 ID sequence (missing/add/reorder fail).
    B3B_WIRE_EXISTING_ID_SEQUENCE = (
        "DSB3_ING_APP_DS_EMPTY",
        "DSB3_ING_APP_DS_TYPED",
        "DSB3_ING_APP_EF_EMPTY",
        "DSB3_ING_APP_EF_TYPED",
        "DSB3_ING_APP_PAYLOAD_BLOB_NZ",
        "DSB3_ING_APP_PAYLOAD_BLOB_TYPED",
        "DSB3_ING_RECEIPT_NOW0",
        "DSB3_ING_RECEIPT_TYPED",
        "DSB3_ING_RECEIPT_EVIDENCE_BLOB_NZ",
        "DSB3_ING_DISP_RETRY_LATER_0",
        "DSB3_ING_DISP_RETRY_LATER_0_TYPED",
        "DSB3_ING_DISP_RETRY_LATER_MAX",
        "DSB3_ING_DISP_RETRY_LATER_MAX_TYPED",
        "DSB3_ING_DISP_INVALID_PAYLOAD",
        "DSB3_ING_DISP_INVALID_PAYLOAD_TYPED",
        "DSB3_ING_DISP_UNSUPPORTED_SCHEMA",
        "DSB3_ING_DISP_UNSUPPORTED_SCHEMA_TYPED",
        "DSB3_ING_DISP_UNAUTHORIZED",
        "DSB3_ING_DISP_UNAUTHORIZED_TYPED",
        "DSB3_ING_DISP_STALE",
        "DSB3_ING_DISP_STALE_TYPED",
        "DSB3_ING_DISP_BUSY_0",
        "DSB3_ING_DISP_BUSY_0_TYPED",
        "DSB3_ING_DISP_BUSY_MAX",
        "DSB3_ING_DISP_BUSY_MAX_TYPED",
        "DSB3_ING_DISP_APPLY_NO_EFFECT",
        "DSB3_ING_DISP_APPLY_NO_EFFECT_TYPED",
        "DSB3_ING_DISP_APPLY_POSSIBLE",
        "DSB3_ING_DISP_APPLY_POSSIBLE_TYPED",
        "DSB3_ING_DISP_VERIFY_FAILED",
        "DSB3_ING_DISP_VERIFY_FAILED_TYPED",
        "DSB3_ING_DISP_CAPACITY",
        "DSB3_ING_DISP_CAPACITY_TYPED",
        "DSB3_ING_DISP_OUTCOME_UNKNOWN",
        "DSB3_ING_DISP_OUTCOME_UNKNOWN_TYPED",
        "DSB3_ING_CANCEL_REQ",
        "DSB3_ING_CANCEL_REQ_TYPED",
        "DSB3_ING_CUSTODY",
        "DSB3_ING_CUSTODY_TYPED",
        "DSB3_ING_CANCEL_RES_FENCED",
        "DSB3_ING_CANCEL_RES_FENCED_TYPED",
        "DSB3_ING_CANCEL_RES_TOO_LATE",
        "DSB3_ING_CANCEL_RES_TOO_LATE_TYPED",
        "DSB3_ING_MAX_TEXT_ID",
        "DSB3_ING_MAX_TEXT_ID_TYPED",
        "DSB3_ING_BINDING_EXISTING_DELIVERY",
        "DSB3_MSD_ONESHOT_EMPTY",
        "DSB3_MSD_STREAM_NONEMPTY",
        "DSB3_MSD_EVIDENCE_MAX",
        "DSB3_ING_SEQ0",
        "DSB3_ING_OWNER_SEQ0",
        "DSB3_ING_BAD_BINDING_APP_TX",
        "DSB3_ING_BAD_BINDING_RCPT_NEW",
        "DSB3_ING_KIND0",
        "DSB3_ING_KIND7",
        "DSB3_ING_FLAGS_NZ",
        "DSB3_ING_TXN_ZERO",
        "DSB3_ING_ATTEMPT_ZERO",
        "DSB3_ING_CONTENT_ZERO",
        "DSB3_ING_REQ_EV_NONE",
        "DSB3_ING_CANCEL_ON_EF",
        "DSB3_ING_EF_FINITE_DEADLINE",
        "DSB3_ING_DS_NO_DEADLINE",
        "DSB3_ING_APP_EMPTY_BAD_CONTENT",
        "DSB3_ING_DISP_DELAY_OVER",
        "DSB3_ING_DISP_BAD_TUPLE",
        "DSB3_ING_RECEIPT_STAGE0",
        "DSB3_ING_RECEIPT_EPOCH0",
        "DSB3_ING_PAYLOAD_BLOB_ON_RCPT",
        "DSB3_ING_EVIDENCE_BLOB_ON_APP",
        "DSB3_ING_BLOB_NZ_SEMANTIC_ZERO",
        "DSB3_ING_BAD_RES_KD",
        "DSB3_ING_BAD_SEMANTIC",
        "DSB3_ING_SHORT",
        "DSB3_ING_TRAILING",
        "DSB3_ING_BUFFER_TOO_SMALL",
        "DSB3_ING_SEQ_MISMATCH",
        "DSB3_ING_BAD_PRIMARY",
        "DSB3_ING_REV_NE1",
        "DSB3_ING_ZERO_HEAD",
        "DSB3_ING_NZ_PVD",
        "DSB3_ING_HEADER_FLAGS",
        "DSB3_ING_STATE_NE1",
        "DSB3_ING_RESERVED1",
        "DSB3_ING_CANCEL_RES_KIND2",
        "DSB3_ING_BAD_PARTY",
        "DSB3_MSD_EVIDENCE_OVERMAX",
    )
    assert len(B3B_WIRE_EXISTING_ID_SEQUENCE) == B3B_WIRE_PRE_R1_COUNT
    assert (
        b3b_wire_id_order_hash(B3B_WIRE_EXISTING_ID_SEQUENCE)
        == B3B_WIRE_PRE_R1_ID_ORDER_HASH
    )

    # r1 regenerated objects for the same 87 IDs (controller block in body_hex).
    B3B_WIRE_EXISTING_R1_COUNT = 87
    B3B_WIRE_EXISTING_R1_ID_ORDER_HASH = B3B_WIRE_PRE_R1_ID_ORDER_HASH
    B3B_WIRE_EXISTING_R1_OBJECT_FINGERPRINT = (
        "2e16f761ba92e458abd2a37e9119d8d0b8cb7388626f4da04c959efdbe69d9a7"
    )

    # Exact new r1-only B3b wire fixtures (append-only after existing 87).
    B3B_WIRE_NEW_R1_ID_SEQUENCE = (
        "DSB3_ING_RECEIPT_CTRL_TRUSTED",
        "DSB3_ING_RECEIPT_CTRL_UNCERTAIN",
        "DSB3_ING_CTRL_SEMANTIC_INDEP_A",
        "DSB3_ING_CTRL_SEMANTIC_INDEP_B",
        "DSB3_ING_APP_CTRL_ZERO",
        "DSB3_ING_CTRL_ON_APP",
        "DSB3_ING_CTRL_ON_DISP",
        "DSB3_ING_CTRL_EPOCH0",
        "DSB3_ING_CTRL_TRUST0",
        "DSB3_ING_CTRL_TRUST3",
        "DSB3_ING_CTRL_HALF",
        "DSB3_ING_CTRL_RESERVED_NZ",
        "DSB3_ING_LEGACY_UNDERLENGTH",
        "DSB3_ING_LEGACY_RECEIPT_UNDERLENGTH",
    )
    B3B_WIRE_NEW_R1_COUNT = 14
    B3B_WIRE_NEW_R1_ID_ORDER_HASH = (
        "9c8ea2989024a11ca9ff5d15002c6826f8760a4695e0dad6d37dd8bbb927433b"
    )
    B3B_WIRE_NEW_R1_OBJECT_FINGERPRINT = (
        "6bd9d94d52e4d845d794b42f799c60d58718f75e1a5fe80ccc530d0f1e759952"
    )
    assert len(B3B_WIRE_NEW_R1_ID_SEQUENCE) == B3B_WIRE_NEW_R1_COUNT
    assert (
        b3b_wire_id_order_hash(B3B_WIRE_NEW_R1_ID_SEQUENCE)
        == B3B_WIRE_NEW_R1_ID_ORDER_HASH
    )

    # Assert against current catalog slice (existing 87 then new 14, no reorder).
    _b3b_wire_now = [v for v in vectors if is_b3b_wire_fixture(v)]
    _b3b_ids_now = [v["id"] for v in _b3b_wire_now]
    assert len(_b3b_wire_now) == (
        B3B_WIRE_EXISTING_R1_COUNT + B3B_WIRE_NEW_R1_COUNT
    ), f"B3b wire fixture count drift: {len(_b3b_wire_now)}"
    _existing_now = _b3b_wire_now[:B3B_WIRE_EXISTING_R1_COUNT]
    _new_now = _b3b_wire_now[B3B_WIRE_EXISTING_R1_COUNT:]
    _existing_ids_now = [v["id"] for v in _existing_now]
    _new_ids_now = [v["id"] for v in _new_now]
    assert tuple(_existing_ids_now) == B3B_WIRE_EXISTING_ID_SEQUENCE, (
        "B3b wire existing ID missing/add/reorder"
    )
    assert (
        b3b_wire_id_order_hash(_existing_ids_now)
        == B3B_WIRE_EXISTING_R1_ID_ORDER_HASH
    )
    assert len(_existing_now) == B3B_WIRE_EXISTING_R1_COUNT
    assert (
        b3b_wire_object_fingerprint(_existing_now)
        == B3B_WIRE_EXISTING_R1_OBJECT_FINGERPRINT
    ), "B3b wire existing r1 object fingerprint drift"
    assert tuple(_new_ids_now) == B3B_WIRE_NEW_R1_ID_SEQUENCE, (
        "B3b wire new ID missing/add/rename/reorder"
    )
    assert b3b_wire_id_order_hash(_new_ids_now) == B3B_WIRE_NEW_R1_ID_ORDER_HASH
    assert len(_new_now) == B3B_WIRE_NEW_R1_COUNT
    assert (
        b3b_wire_object_fingerprint(_new_now)
        == B3B_WIRE_NEW_R1_OBJECT_FINGERPRINT
    ), "B3b wire new r1 object fingerprint drift"
    # No stray B3b wire IDs outside the fixed sequences.
    assert set(_b3b_ids_now) == set(B3B_WIRE_EXISTING_ID_SEQUENCE) | set(
        B3B_WIRE_NEW_R1_ID_SEQUENCE
    )

    # --- D1-B3c: BLOB (0x30) manifest + chunk pure body codec ---
    # After D1-B3b controller-ingress retrofit; non-B3b-wire vectors keep
    # pre-r1 bytes via NON_B3B_WIRE fingerprint gate.
    b_pos = b_neg = b_mut = b_rt = 0
    EMPTY_SHA = sha256(b"")
    CHUNK_MAX = 3072
    # BLOB owner enum: 1 TX, 2 INGRESS, 3 DELIVERY (distinct from scheduler)
    BLOB_TX, BLOB_ING, BLOB_DLV = 1, 2, 3
    BK_CMD, BK_EVT, BK_ING, BK_EVD, BK_RPL = 1, 2, 3, 4, 5
    assert len(dlv_raw) == 80
    assert len(txn) == 16
    ing_seq8 = be64(42)
    content_nz = sha256(b"blob-content-seed")
    content_one = sha256(b"x")  # single-byte content

    def enc_manifest_body(
        owner_kind, owner_raw, blob_kind, total_length, content=None,
        blob_id=None, owner_pkd=None, chunk_count=None,
    ):
        if content is None:
            content = EMPTY_SHA if total_length == 0 else content_nz
        if chunk_count is None:
            chunk_count = blob_chunk_count_for_total(total_length)
            assert chunk_count is not None
        if blob_id is None:
            blob_id = blob_id_digest(
                owner_kind, owner_raw, blob_kind, content, total_length)
        if owner_pkd is None:
            owner_pkd = blob_owner_primary_key_digest(owner_kind, owner_raw)
        return (
            blob_id + be16(owner_kind) + be16(blob_kind) + raw16(owner_raw)
            + owner_pkd + be64(total_length) + be32(chunk_count) + content
        )

    def enc_chunk_body(
        blob_id, chunk_index, chunk_count, total_length, content, chunk_bytes,
        manifest_kd=None,
    ):
        if manifest_kd is None:
            manifest_kd = complete_key_digest_composite(
                0x30, bytes([1]) + blob_id)
        return (
            blob_id + manifest_kd + be32(chunk_index) + be32(chunk_count)
            + be64(total_length) + content + be32(len(chunk_bytes))
            + chunk_bytes
        )

    def manifest_key(blob_id):
        return bkey(6, 0x30, 5, composite(0x30, bytes([1]) + blob_id))

    def chunk_key(blob_id, index):
        return bkey(
            6, 0x30, 5,
            composite(0x30, bytes([2]) + blob_id + be32(index)))

    def manifest_typed(owner_kind, owner_raw, blob_kind, total_length,
                       content=None, rev=1, flags=1, head=None, pvd=None,
                       primary=None, body=None):
        if content is None:
            content = EMPTY_SHA if total_length == 0 else content_nz
        if body is None:
            body = enc_manifest_body(
                owner_kind, owner_raw, blob_kind, total_length, content=content)
        bid = body[:32]
        if primary is None:
            primary = blob_owner_primary_id(owner_kind, owner_raw)
        if head is None:
            head = F["head_nz"]
        if pvd is None:
            pvd = F["pvd_nz"]
        key = manifest_key(bid)
        val = enc_env_full(6, 0x30, flags, rev, primary, head, pvd, body)
        return key, val, body, bid

    def chunk_typed(
        blob_id, chunk_index, chunk_count, total_length, content, chunk_bytes,
        rev=1, flags=2, head=None, pvd=None, primary=None, body=None,
    ):
        if body is None:
            body = enc_chunk_body(
                blob_id, chunk_index, chunk_count, total_length, content,
                chunk_bytes)
        if primary is None:
            primary = composite(0x30, bytes([1]) + blob_id)[:16]
        if head is None:
            head = F["head_nz"]
        if pvd is None:
            pvd = F["pvd_nz"]
        key = chunk_key(blob_id, chunk_index)
        val = enc_env_full(6, 0x30, flags, rev, primary, head, pvd, body)
        return key, val, body

    # Legal owner-kind pairs (all allowed)
    legal_pairs = [
        (BLOB_TX, txn, BK_CMD, "TX_CMD"),
        (BLOB_TX, txn, BK_EVT, "TX_EVT"),
        (BLOB_ING, ing_seq8, BK_ING, "ING_PAY"),
        (BLOB_ING, ing_seq8, BK_EVD, "ING_EVD"),
        (BLOB_DLV, dlv_raw, BK_CMD, "DLV_CMD"),
        (BLOB_DLV, dlv_raw, BK_EVT, "DLV_EVT"),
        (BLOB_DLV, dlv_raw, BK_RPL, "DLV_RPL"),
    ]
    for owner_kind, owner_raw, blob_kind, tag in legal_pairs:
        body = enc_manifest_body(owner_kind, owner_raw, blob_kind, 1, content=content_one)
        add(id=f"DSB3_BLOB_MAN_{tag}", suite="DSB3", op="body_roundtrip",
            expected_status="OK", family=6, subtype=0x30, flags=1,
            body_length=len(body), body_hex=hx(body),
            notes=f"manifest owner={owner_kind} kind={blob_kind} total=1")
        b_pos += 1
        b_rt += 1
        key, val, body, bid = manifest_typed(
            owner_kind, owner_raw, blob_kind, 1, content=content_one, body=body)
        add(id=f"DSB3_BLOB_MAN_{tag}_TYPED", suite="DSB3", op="typed_record",
            expected_status="OK", family=6, subtype=0x30, flags=1,
            key_hex=hx(key), value_hex=hx(val), body_hex=hx(body),
            digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}")
        b_pos += 1

    # Zero-length manifest (count 0, empty digest)
    body_zero = enc_manifest_body(BLOB_TX, txn, BK_CMD, 0, content=EMPTY_SHA)
    assert blob_chunk_count_for_total(0) == 0
    add(id="DSB3_BLOB_MAN_ZERO", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x30, flags=1,
        body_length=len(body_zero), body_hex=hx(body_zero),
        notes="total_length=0 chunk_count=0 empty content digest")
    b_pos += 1
    b_rt += 1
    key_z, val_z, body_z, bid_z = manifest_typed(
        BLOB_TX, txn, BK_CMD, 0, content=EMPTY_SHA, body=body_zero)
    add(id="DSB3_BLOB_MAN_ZERO_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x30, flags=1,
        key_hex=hx(key_z), value_hex=hx(val_z), body_hex=hx(body_z),
        digest_hex=hx(sha256(val_z)),
        crc_hex=f"{crc32c(val_z[:-4]):08x}")
    b_pos += 1

    # Lengths 1 / 3072 / 3073 and checked ceil boundary
    for total, tag in ((1, "LEN1"), (3072, "LEN3072"), (3073, "LEN3073")):
        cc = blob_chunk_count_for_total(total)
        assert cc == (1 if total <= 3072 else 2)
        body = enc_manifest_body(BLOB_TX, txn, BK_CMD, total, content=content_nz)
        add(id=f"DSB3_BLOB_MAN_{tag}", suite="DSB3", op="body_roundtrip",
            expected_status="OK", family=6, subtype=0x30, flags=1,
            body_length=len(body), body_hex=hx(body),
            notes=f"total={total} chunk_count={cc}")
        b_pos += 1
        b_rt += 1
        add(id=f"DSB3_BLOB_COUNT_{tag}", suite="DSB3", op="blob_chunk_count",
            expected_status="OK", family=6, subtype=0x30,
            sha_bit_length=total, chunk_count=cc)
        b_pos += 1

    # ceil boundary: exact multiple and next
    assert blob_chunk_count_for_total(3072 * 2) == 2
    assert blob_chunk_count_for_total(3072 * 2 + 1) == 3
    add(id="DSB3_BLOB_COUNT_CEIL_MUL", suite="DSB3", op="blob_chunk_count",
        expected_status="OK", family=6, subtype=0x30,
        sha_bit_length=3072 * 2, chunk_count=2,
        notes="exact multiple of 3072")
    b_pos += 1
    add(id="DSB3_BLOB_COUNT_CEIL_NEXT", suite="DSB3", op="blob_chunk_count",
        expected_status="OK", family=6, subtype=0x30,
        sha_bit_length=3072 * 2 + 1, chunk_count=3)
    b_pos += 1
    add(id="DSB3_BLOB_COUNT_ZERO", suite="DSB3", op="blob_chunk_count",
        expected_status="OK", family=6, subtype=0x30,
        sha_bit_length=0, chunk_count=0)
    b_pos += 1
    # ceil overflow: total that needs > UINT32_MAX chunks
    U32_MAX = 0xFFFFFFFF
    overflow_total = (U32_MAX + 1) * CHUNK_MAX
    assert blob_chunk_count_for_total(overflow_total) is None
    add(id="DSB3_BLOB_COUNT_OVERFLOW", suite="DSB3", op="blob_chunk_count",
        expected_status="INVALID_ARGUMENT", family=6, subtype=0x30,
        sha_bit_length=overflow_total, chunk_count=0,
        notes="ceil(total/3072) > UINT32_MAX")
    b_neg += 1

    # Single-chunk positive (content recompute)
    one_bytes = b"x"
    assert content_one == sha256(one_bytes)
    bid_one = blob_id_digest(BLOB_TX, txn, BK_CMD, content_one, 1)
    body_ch1 = enc_chunk_body(bid_one, 0, 1, 1, content_one, one_bytes)
    add(id="DSB3_BLOB_CHK_SINGLE", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        body_length=len(body_ch1), body_hex=hx(body_ch1),
        notes="single chunk content_digest recompute")
    b_pos += 1
    b_rt += 1
    key_c1, val_c1, body_c1 = chunk_typed(
        bid_one, 0, 1, 1, content_one, one_bytes, body=body_ch1)
    add(id="DSB3_BLOB_CHK_SINGLE_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        key_hex=hx(key_c1), value_hex=hx(val_c1), body_hex=hx(body_c1),
        digest_hex=hx(sha256(val_c1)),
        crc_hex=f"{crc32c(val_c1[:-4]):08x}")
    b_pos += 1

    # Non-final / final / max chunk for multi-chunk total=3073
    multi_total = 3073
    multi_count = 2
    multi_content = content_nz  # not equal to sha256 of either chunk alone
    bid_multi = blob_id_digest(BLOB_ING, ing_seq8, BK_ING, multi_content, multi_total)
    nonfinal_bytes = bytes([0x11]) * CHUNK_MAX
    final_bytes = bytes([0x22])  # 1 byte
    assert len(nonfinal_bytes) == CHUNK_MAX and len(final_bytes) == 1
    # Prove multi-chunk does NOT recompute content from local chunk alone:
    # content_digest != sha256(nonfinal) and != sha256(final)
    assert multi_content != sha256(nonfinal_bytes)
    assert multi_content != sha256(final_bytes)
    body_nf = enc_chunk_body(
        bid_multi, 0, multi_count, multi_total, multi_content, nonfinal_bytes)
    body_fin = enc_chunk_body(
        bid_multi, 1, multi_count, multi_total, multi_content, final_bytes)
    add(id="DSB3_BLOB_CHK_NONFINAL", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        body_length=len(body_nf), body_hex=hx(body_nf),
        notes="non-final length 3072; multi content not local recompute")
    b_pos += 1
    b_rt += 1
    add(id="DSB3_BLOB_CHK_FINAL", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        body_length=len(body_fin), body_hex=hx(body_fin),
        notes="final length 1 for total 3073")
    b_pos += 1
    b_rt += 1
    key_nf, val_nf, _ = chunk_typed(
        bid_multi, 0, multi_count, multi_total, multi_content, nonfinal_bytes,
        body=body_nf)
    add(id="DSB3_BLOB_CHK_NONFINAL_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        key_hex=hx(key_nf), value_hex=hx(val_nf), body_hex=hx(body_nf),
        digest_hex=hx(sha256(val_nf)),
        crc_hex=f"{crc32c(val_nf[:-4]):08x}",
        notes="multi-chunk content digest not locally recomputed from one chunk")
    b_pos += 1
    key_fin, val_fin, _ = chunk_typed(
        bid_multi, 1, multi_count, multi_total, multi_content, final_bytes,
        body=body_fin)
    add(id="DSB3_BLOB_CHK_FINAL_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        key_hex=hx(key_fin), value_hex=hx(val_fin), body_hex=hx(body_fin),
        digest_hex=hx(sha256(val_fin)),
        crc_hex=f"{crc32c(val_fin[:-4]):08x}")
    b_pos += 1

    # Max chunk (3072) single
    max_bytes = bytes([0xAB]) * CHUNK_MAX
    max_content = sha256(max_bytes)
    bid_max = blob_id_digest(BLOB_DLV, dlv_raw, BK_RPL, max_content, CHUNK_MAX)
    body_max = enc_chunk_body(bid_max, 0, 1, CHUNK_MAX, max_content, max_bytes)
    add(id="DSB3_BLOB_CHK_MAX", suite="DSB3", op="body_roundtrip",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        body_length=len(body_max), body_hex=hx(body_max),
        notes="single chunk length 3072")
    b_pos += 1
    b_rt += 1
    key_max, val_max, _ = chunk_typed(
        bid_max, 0, 1, CHUNK_MAX, max_content, max_bytes, body=body_max)
    add(id="DSB3_BLOB_CHK_MAX_TYPED", suite="DSB3", op="typed_record",
        expected_status="OK", family=6, subtype=0x30, flags=2,
        key_hex=hx(key_max), value_hex=hx(val_max), body_hex=hx(body_max),
        digest_hex=hx(sha256(val_max)),
        crc_hex=f"{crc32c(val_max[:-4]):08x}")
    b_pos += 1

    # DELIVERY owner typed already covered; TX/INGRESS/DELIVERY manifest above.

    # --- negatives ---
    # flags/body mismatch: chunk flags with manifest body
    key_mm, val_mm, body_mm, _ = manifest_typed(
        BLOB_TX, txn, BK_CMD, 1, content=content_one, flags=2)
    add(id="DSB3_BLOB_FLAGS_CHUNK_ON_MAN", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        key_hex=hx(key_mm), value_hex=hx(val_mm),
        notes="flags=chunk with manifest body")
    b_neg += 1
    # flags=manifest with chunk body
    key_mc, val_mc, body_mc = chunk_typed(
        bid_one, 0, 1, 1, content_one, one_bytes, flags=1)
    add(id="DSB3_BLOB_FLAGS_MAN_ON_CHK", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        key_hex=hx(key_mc), value_hex=hx(val_mc))
    b_neg += 1
    # flags both/zero
    key_f0, val_f0, _, _ = manifest_typed(
        BLOB_TX, txn, BK_CMD, 1, content=content_one, flags=0)
    add(id="DSB3_BLOB_FLAGS_ZERO", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=0,
        key_hex=hx(key_f0), value_hex=hx(val_f0))
    b_neg += 1
    key_f3, val_f3, _, _ = manifest_typed(
        BLOB_TX, txn, BK_CMD, 1, content=content_one, flags=3)
    add(id="DSB3_BLOB_FLAGS_BOTH", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=3,
        key_hex=hx(key_f3), value_hex=hx(val_f3))
    b_neg += 1

    # raw length wrong
    add(id="DSB3_BLOB_RAW_TX_15", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_TX, txn[:15], BK_CMD, 1, content=content_one,
            blob_id=bytes(32), owner_pkd=bytes(32))))
    b_neg += 1
    add(id="DSB3_BLOB_RAW_ING_7", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_ING, ing_seq8[:7], BK_ING, 1, content=content_one,
            blob_id=bytes(32), owner_pkd=bytes(32))))
    b_neg += 1
    add(id="DSB3_BLOB_RAW_DLV_79", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_DLV, dlv_raw[:79], BK_CMD, 1, content=content_one,
            blob_id=bytes(32), owner_pkd=bytes(32))))
    b_neg += 1

    # forbidden owner-kind pairs
    forbidden = [
        (BLOB_TX, txn, BK_ING, "TX_ING"),
        (BLOB_TX, txn, BK_RPL, "TX_RPL"),
        (BLOB_ING, ing_seq8, BK_CMD, "ING_CMD"),
        (BLOB_ING, ing_seq8, BK_RPL, "ING_RPL"),
        (BLOB_DLV, dlv_raw, BK_ING, "DLV_ING"),
        (BLOB_DLV, dlv_raw, BK_EVD, "DLV_EVD"),
    ]
    for owner_kind, owner_raw, blob_kind, tag in forbidden:
        add(id=f"DSB3_BLOB_FORBID_{tag}", suite="DSB3", op="body_decode",
            expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
            body_hex=hx(enc_manifest_body(
                owner_kind, owner_raw, blob_kind, 1, content=content_one,
                blob_id=bytes(32), owner_pkd=bytes(32))))
        b_neg += 1

    # blob_id mutation
    mut_bid = bytearray(enc_manifest_body(
        BLOB_TX, txn, BK_CMD, 1, content=content_one))
    mut_bid[0] ^= 0x01
    add(id="DSB3_BLOB_MAN_BAD_BLOB_ID", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(bytes(mut_bid)))
    b_neg += 1
    b_mut += 1

    # owner primary key digest mutation / identity-digest confusion
    mut_pkd = bytearray(enc_manifest_body(
        BLOB_TX, txn, BK_CMD, 1, content=content_one))
    off_pkd = 32 + 2 + 2 + 2 + 16
    mut_pkd[off_pkd:off_pkd + 32] = bytes([0xB0] * 32)
    add(id="DSB3_BLOB_MAN_BAD_OWNER_PKD", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(bytes(mut_pkd)))
    b_neg += 1
    b_mut += 1
    add(id="DSB3_BLOB_MAN_ID_DIGEST_CONFUSION", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_TX, txn, BK_CMD, 1, content=content_one, owner_pkd=sha256(txn))),
        notes="owner_primary_key_digest must be KEY_DIGEST not sha256(id)")
    b_neg += 1

    # zero / mismatched count
    add(id="DSB3_BLOB_MAN_COUNT_NZ_ZERO_TOTAL", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_TX, txn, BK_CMD, 0, content=EMPTY_SHA, chunk_count=1)))
    b_neg += 1
    add(id="DSB3_BLOB_MAN_COUNT_MISMATCH", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_TX, txn, BK_CMD, 1, content=content_one, chunk_count=2)))
    b_neg += 1
    add(id="DSB3_BLOB_MAN_ZERO_BAD_DIGEST", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_TX, txn, BK_CMD, 0, content=content_nz)))
    b_neg += 1

    # chunk index / zero length / nonfinal/final length errors
    add(id="DSB3_BLOB_CHK_INDEX_OOB", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(enc_chunk_body(
            bid_one, 1, 1, 1, content_one, one_bytes)))
    b_neg += 1
    add(id="DSB3_BLOB_CHK_ZERO_LEN", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(
            bid_one + complete_key_digest_composite(0x30, bytes([1]) + bid_one)
            + be32(0) + be32(1) + be64(1) + content_one + be32(0)),
        notes="zero chunk_length always corrupt")
    b_neg += 1
    add(id="DSB3_BLOB_CHK_NONFINAL_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(enc_chunk_body(
            bid_multi, 0, multi_count, multi_total, multi_content,
            bytes([0x11]) * 3071)))
    b_neg += 1
    add(id="DSB3_BLOB_CHK_FINAL_WRONG", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(enc_chunk_body(
            bid_multi, 1, multi_count, multi_total, multi_content,
            bytes([0x22, 0x33]))))
    b_neg += 1
    add(id="DSB3_BLOB_CHK_COUNT_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(enc_chunk_body(
            bid_one, 0, 0, 1, content_one, one_bytes)))
    b_neg += 1

    # single chunk content mismatch
    add(id="DSB3_BLOB_CHK_SINGLE_CONTENT_MISMATCH", suite="DSB3",
        op="body_decode", expected_status="CORRUPT", family=6, subtype=0x30,
        flags=2,
        body_hex=hx(enc_chunk_body(
            bid_one, 0, 1, 1, content_nz, one_bytes)),
        notes="single-chunk content_digest must equal SHA-256(chunk_bytes)")
    b_neg += 1

    # multi-chunk content not equal to local sha is OK (already positive);
    # vector explicitly notes D3 deferral above (NONFINAL_TYPED).

    # manifest key digest bad
    bad_mkd = enc_chunk_body(
        bid_one, 0, 1, 1, content_one, one_bytes, manifest_kd=bytes([0xCC] * 32))
    add(id="DSB3_BLOB_CHK_BAD_MANIFEST_KD", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(bad_mkd))
    b_neg += 1

    # revision / head / PVD / primary_id
    key_r, val_r, _, _ = manifest_typed(
        BLOB_TX, txn, BK_CMD, 1, content=content_one, rev=2)
    add(id="DSB3_BLOB_REV2", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        key_hex=hx(key_r), value_hex=hx(val_r))
    b_neg += 1
    key_zh, val_zh, _, _ = manifest_typed(
        BLOB_TX, txn, BK_CMD, 1, content=content_one, head=bytes(32))
    add(id="DSB3_BLOB_ZERO_HEAD", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        key_hex=hx(key_zh), value_hex=hx(val_zh))
    b_neg += 1
    key_zp, val_zp, _, _ = manifest_typed(
        BLOB_TX, txn, BK_CMD, 1, content=content_one, pvd=bytes(32))
    add(id="DSB3_BLOB_ZERO_PVD", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        key_hex=hx(key_zp), value_hex=hx(val_zp))
    b_neg += 1
    key_bp, val_bp, _, _ = manifest_typed(
        BLOB_TX, txn, BK_CMD, 1, content=content_one, primary=bytes(16))
    add(id="DSB3_BLOB_BAD_PRIMARY_ID", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        key_hex=hx(key_bp), value_hex=hx(val_bp))
    b_neg += 1
    # chunk primary must be manifest composite first 16, not owner id
    key_cp, val_cp, _ = chunk_typed(
        bid_one, 0, 1, 1, content_one, one_bytes, primary=txn)
    assert txn != composite(0x30, bytes([1]) + bid_one)[:16]
    add(id="DSB3_BLOB_CHK_BAD_PRIMARY_ID", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        key_hex=hx(key_cp), value_hex=hx(val_cp),
        notes="chunk primary_id is manifest composite first 16")
    b_neg += 1
    # key composite mismatch
    bad_key = bkey(6, 0x30, 5, bytes([0x55] * 32))
    add(id="DSB3_BLOB_BAD_KEY_COMPOSITE", suite="DSB3", op="typed_record",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        key_hex=hx(bad_key), value_hex=hx(val_z))
    b_neg += 1

    # short / trailing / BTS
    add(id="DSB3_BLOB_MAN_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(body_zero[:-1]))
    b_neg += 1
    add(id="DSB3_BLOB_MAN_TRAILING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(body_zero + b"\x00"))
    b_neg += 1
    add(id="DSB3_BLOB_CHK_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(body_ch1[:-1]))
    b_neg += 1
    add(id="DSB3_BLOB_CHK_TRAILING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(body_ch1 + b"\x00"))
    b_neg += 1
    add(id="DSB3_BLOB_MAN_BUFFER_TOO_SMALL", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x30, flags=1,
        body_length=len(body_zero), body_hex=hx(body_zero), key_length=0)
    b_neg += 1
    add(id="DSB3_BLOB_CHK_BUFFER_TOO_SMALL", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x30, flags=2,
        body_length=len(body_ch1), body_hex=hx(body_ch1), key_length=0)
    b_neg += 1

    # owner kind 0 / 4
    add(id="DSB3_BLOB_OWNER0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            0, txn, BK_CMD, 1, content=content_one,
            blob_id=bytes(32), owner_pkd=bytes(32))))
    b_neg += 1
    add(id="DSB3_BLOB_OWNER4", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            4, txn, BK_CMD, 1, content=content_one,
            blob_id=bytes(32), owner_pkd=bytes(32))))
    b_neg += 1

    # --- Review-fix appends (keep prior 691 objects as a stable prefix) ---
    # Exact u32 capacity boundaries via checked constants (no host narrowing).
    max_ok_total = U32_MAX * CHUNK_MAX  # exact: 0xFFFFFFFF * 3072
    max_plus1_total = max_ok_total + 1
    assert blob_chunk_count_for_total(max_ok_total) == U32_MAX
    assert blob_chunk_count_for_total(max_plus1_total) is None
    assert overflow_total > max_plus1_total
    add(id="DSB3_BLOB_COUNT_U32_MAX", suite="DSB3", op="blob_chunk_count",
        expected_status="OK", family=6, subtype=0x30,
        sha_bit_length=max_ok_total, chunk_count=U32_MAX,
        notes="total=UINT32_MAX*3072 => count UINT32_MAX")
    b_pos += 1
    add(id="DSB3_BLOB_COUNT_U32_MAX_P1", suite="DSB3", op="blob_chunk_count",
        expected_status="INVALID_ARGUMENT", family=6, subtype=0x30,
        sha_bit_length=max_plus1_total, chunk_count=0,
        notes="total=UINT32_MAX*3072+1 => INVALID, out 0")
    b_neg += 1
    # Focused non-zero digest negatives (docs17 same-record contract).
    add(id="DSB3_BLOB_MAN_CONTENT_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=1,
        body_hex=hx(enc_manifest_body(
            BLOB_TX, txn, BK_CMD, 1, content=bytes(32))),
        notes="nonzero total requires non-zero content_digest")
    b_neg += 1
    add(id="DSB3_BLOB_CHK_MULTI_CONTENT_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(enc_chunk_body(
            bid_multi, 0, multi_count, multi_total, bytes(32), nonfinal_bytes)),
        notes="multi-chunk content_digest must be non-zero; no local recompute")
    b_neg += 1
    add(id="DSB3_BLOB_CHK_BLOB_ID_ZERO", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x30, flags=2,
        body_hex=hx(enc_chunk_body(
            bytes(32), 0, 1, 1, content_one, one_bytes)),
        notes="stored chunk blob_id_digest must be non-zero")
    b_neg += 1

    b3_cov["30"] = add_body_suite("BLOB", 6, 0x30, b_pos, b_neg, b_mut, b_rt)
    assert b3_cov["30"]["positive"] >= 20
    assert b3_cov["30"]["negative"] >= 25
    assert b3_cov["30"]["roundtrip"] >= 8

    # =====================================================================
    # D1-B3d ATTEMPT (0x31) — after BLOB; B3b r1 migration may grow the
    # pre-B3d vector count (ORDERED_INGRESS controller retrofit).
    # =====================================================================
    # Durable gate: non-B3b-wire fixtures only (DSB3_ING_/DSB3_MSD_ excluded).
    # B3b wire migration intentionally changes those objects; do not claim
    # old full-prefix fingerprints that included pre-r1 ING/MSD bytes.
    def non_b3b_wire_fingerprint(vec_list):
        durable = [v for v in vec_list if not is_b3b_wire_fixture(v)]
        return hashlib.sha256(
            json.dumps(durable, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()

    # Pre-r1 non-B3b-wire objects in the pre-B3d prefix (BLOB end inclusive).
    # Re-pinned at D1-B3i: kind9/10 operation identity phase correction (42-byte).
    PRE_B3D_NON_B3B_WIRE_FINGERPRINT = (
        "ec62271a8ff15b172795f10b1dd1235e0b3837ac2ce321c5b76360678586cd30"
    )
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[-1]["id"] == "DSB3_BLOB_CHK_BLOB_ID_ZERO"
    _pre_b3d_fp = non_b3b_wire_fingerprint(vectors)
    assert _pre_b3d_fp == PRE_B3D_NON_B3B_WIRE_FINGERPRINT, (
        f"pre-B3d non-B3b-wire fingerprint drift: got {_pre_b3d_fp}"
    )
    PRE_B3D_VECTOR_COUNT = len(vectors)

    # Private ATTEMPT enums (distinct from reservation/scheduler/BLOB/reply).
    ATT_TX = 1
    ATT_DLV = 2
    AK_CMD = 1
    AK_EVT = 2
    AK_CAN = 3
    AS_PREP = 1
    AS_OBS = 2
    AS_RES = 3
    AS_REC = 4
    SS_PREP = 1
    SS_RETRY = 2
    SS_SENT = 3
    SS_DENIED = 4
    SS_REC = 5
    U64_MAX = (1 << 64) - 1
    att_id = bytes([0xA1 + i for i in range(16)])
    att_id2 = bytes([0xB1 + i for i in range(16)])
    prep_ep = bytes([0xC0 + (i % 16) for i in range(16)])
    timeout_ep = bytes([0xD0 + (i % 16) for i in range(16)])
    target_dg = bytes([0xE0 + (i % 16) for i in range(32)])
    semantic_dg = bytes([0xF0 + (i % 16) for i in range(32)])
    head_nz = F["head_nz"]
    pvd_nz = bytes([0x11 + (i % 200) for i in range(32)])
    assert not all(b == 0 for b in target_dg)
    assert not all(b == 0 for b in semantic_dg)
    assert not all(b == 0 for b in prep_ep)
    # Reuse txn / dlv_raw from B2/B3 fixtures (exact identity material).
    assert len(txn) == 16 and len(dlv_raw) == 80
    assert dlv_raw[32:48] == txn

    def attempt_primary_key_digest(owner_kind: int, owner_raw: bytes) -> bytes:
        if owner_kind == ATT_TX:
            return complete_key_digest_id128(0x20, owner_raw)
        if owner_kind == ATT_DLV:
            return complete_key_digest_composite(0x40, raw16(owner_raw))
        raise ValueError("bad attempt owner")

    def attempt_primary_id(owner_kind: int, owner_raw: bytes, transaction_id: bytes) -> bytes:
        if owner_kind == ATT_TX:
            return transaction_id
        if owner_kind == ATT_DLV:
            return primary_id_from_composite_subtype(0x40, raw16(owner_raw))
        raise ValueError("bad attempt owner")

    def attempt_key_components(owner_kind: int, owner_raw: bytes, attempt_id: bytes) -> bytes:
        return be16(owner_kind) + raw16(owner_raw) + attempt_id

    def attempt_key(owner_kind: int, owner_raw: bytes, attempt_id: bytes) -> bytes:
        return bkey(6, 0x31, 5, composite(0x31, attempt_key_components(
            owner_kind, owner_raw, attempt_id)))

    def enc_attempt_body(
        owner_kind=ATT_TX,
        owner_raw=None,
        attempt_id=None,
        transaction_id=None,
        attempt_kind=AK_CMD,
        attempt_state=AS_PREP,
        send_state=SS_PREP,
        retry_cycle_id=0,
        attempt_in_cycle=0,
        cumulative_attempts=1,
        gen=0,
        inv=0,
        exhausted=0,
        avail=0,
        prepared_epoch=None,
        prepared_at=0,
        timeout_epoch=None,
        timeout_at=0,
        target=None,
        semantic=None,
        primary_kd=None,
        reserved0=0,
        reserved1=0,
    ) -> bytes:
        if owner_raw is None:
            owner_raw = txn if owner_kind == ATT_TX else dlv_raw
        if attempt_id is None:
            attempt_id = att_id
        if transaction_id is None:
            if owner_kind == ATT_DLV and len(owner_raw) >= 48:
                transaction_id = owner_raw[32:48]
            else:
                transaction_id = txn
        if prepared_epoch is None:
            prepared_epoch = prep_ep
        if timeout_epoch is None:
            timeout_epoch = bytes(16)
        if target is None:
            target = target_dg
        if semantic is None:
            semantic = semantic_dg
        if primary_kd is None:
            primary_kd = attempt_primary_key_digest(owner_kind, owner_raw)
        out = bytearray()
        out += attempt_id
        out += be16(owner_kind)
        out += be16(reserved0)
        out += raw16(owner_raw)
        out += primary_kd
        out += transaction_id
        out += target
        out += be16(attempt_kind)
        out += be16(attempt_state)
        out += be64(retry_cycle_id)
        out += be32(attempt_in_cycle)
        out += be64(cumulative_attempts)
        out += be64(gen)
        out += be64(inv)
        out += be32(exhausted)
        out += be32(reserved1)
        out += semantic
        out += prepared_epoch
        out += be64(prepared_at)
        out += be32(send_state)
        out += be64(avail)
        out += timeout_epoch
        out += be64(timeout_at)
        assert len(out) == 242 + len(owner_raw)
        return bytes(out)

    def attempt_typed(
        owner_kind=ATT_TX,
        owner_raw=None,
        attempt_id=None,
        transaction_id=None,
        attempt_kind=AK_CMD,
        attempt_state=AS_PREP,
        send_state=SS_PREP,
        retry_cycle_id=0,
        attempt_in_cycle=0,
        cumulative_attempts=1,
        gen=0,
        inv=0,
        exhausted=0,
        avail=0,
        prepared_epoch=None,
        prepared_at=0,
        timeout_epoch=None,
        timeout_at=0,
        rev=1,
        head=None,
        pvd=None,
        primary=None,
        body=None,
        **kwargs,
    ):
        if owner_raw is None:
            owner_raw = txn if owner_kind == ATT_TX else dlv_raw
        if attempt_id is None:
            attempt_id = att_id
        if transaction_id is None:
            transaction_id = txn if owner_kind == ATT_TX else owner_raw[32:48]
        if head is None:
            head = head_nz
        if pvd is None:
            pvd = pvd_nz
        if body is None:
            body = enc_attempt_body(
                owner_kind=owner_kind, owner_raw=owner_raw,
                attempt_id=attempt_id, transaction_id=transaction_id,
                attempt_kind=attempt_kind, attempt_state=attempt_state,
                send_state=send_state, retry_cycle_id=retry_cycle_id,
                attempt_in_cycle=attempt_in_cycle,
                cumulative_attempts=cumulative_attempts, gen=gen, inv=inv,
                exhausted=exhausted, avail=avail,
                prepared_epoch=prepared_epoch, prepared_at=prepared_at,
                timeout_epoch=timeout_epoch, timeout_at=timeout_at, **kwargs)
        if primary is None:
            primary = attempt_primary_id(owner_kind, owner_raw, transaction_id)
        key = attempt_key(owner_kind, owner_raw, attempt_id)
        val = enc_env_full(6, 0x31, 0, rev, primary, head, pvd, body)
        return key, val, body

    a_pos = 0
    a_neg = 0
    a_mut = 0
    a_rt = 0

    def add_att_pos(vid, body, notes=""):
        nonlocal a_pos, a_rt
        add(id=vid, suite="DSB3", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x31, body_length=len(body), body_hex=hx(body),
            notes=notes)
        a_pos += 1
        a_rt += 1

    def add_att_typed(vid, key, val, body, notes=""):
        nonlocal a_pos
        add(id=vid, suite="DSB3", op="typed_record", expected_status="OK",
            family=6, subtype=0x31, key_hex=hx(key), value_hex=hx(val),
            body_hex=hx(body), digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}", notes=notes)
        a_pos += 1

    def add_att_neg_body(vid, body, notes=""):
        nonlocal a_neg
        add(id=vid, suite="DSB3", op="body_decode", expected_status="CORRUPT",
            family=6, subtype=0x31, body_hex=hx(body), notes=notes)
        a_neg += 1

    def add_att_neg_typed(vid, key, val, notes=""):
        nonlocal a_neg
        add(id=vid, suite="DSB3", op="typed_record", expected_status="CORRUPT",
            family=6, subtype=0x31, key_hex=hx(key), value_hex=hx(val),
            notes=notes)
        a_neg += 1

    # --- Local TX COMMAND matrix rows ---
    # PREPARED/PREPARED
    body_cmd_prep = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_PREP, send_state=SS_PREP,
        cumulative_attempts=1, gen=0, inv=0, exhausted=0, avail=0)
    add_att_pos("DSB3_ATT_TX_CMD_PREP", body_cmd_prep, "local TX COMMAND PREPARED")
    k, v, b = attempt_typed(body=body_cmd_prep)
    add_att_typed("DSB3_ATT_TX_CMD_PREP_TYPED", k, v, b)
    # prepared_at=0 allowed
    body_prep0 = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_PREP, send_state=SS_PREP,
        cumulative_attempts=3, prepared_at=0)
    add_att_pos("DSB3_ATT_TX_CMD_PREP_AT0", body_prep0, "prepared_at_ms=0 valid")

    # RESOLVED/RETRYABLE TxGate (inv=0, avail=0) vs Bearer (inv>=1, avail!=0)
    body_cmd_retry_txg = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_RETRY,
        cumulative_attempts=2, gen=3, inv=0, exhausted=0, avail=0)
    add_att_pos("DSB3_ATT_TX_CMD_RETRY_TXGATE", body_cmd_retry_txg,
                "TxGate TEMPORARY path inv0/avail0")
    body_cmd_retry_br = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_RETRY,
        cumulative_attempts=2, gen=3, inv=2, exhausted=0, avail=7)
    add_att_pos("DSB3_ATT_TX_CMD_RETRY_BEARER", body_cmd_retry_br,
                "Bearer WOULD_BLOCK path inv>=1/avail!=0")

    # RESOLVED/CLOSED_DENIED TxGate vs Bearer
    body_cmd_den_txg = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_DENIED,
        cumulative_attempts=1, gen=1, inv=0, exhausted=0, avail=0)
    add_att_pos("DSB3_ATT_TX_CMD_DENIED_TXGATE", body_cmd_den_txg)
    body_cmd_den_br = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_DENIED,
        cumulative_attempts=1, gen=2, inv=1, exhausted=0, avail=9)
    add_att_pos("DSB3_ATT_TX_CMD_DENIED_BEARER", body_cmd_den_br)

    # OBSERVED_SENT/SENT_POSSIBLE with active timeout and cleared
    body_cmd_obs_to = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_OBS, send_state=SS_SENT,
        cumulative_attempts=4, gen=2, inv=1, exhausted=0, avail=1,
        timeout_epoch=timeout_ep, timeout_at=5000)
    add_att_pos("DSB3_ATT_TX_CMD_OBS_TIMEOUT", body_cmd_obs_to,
                "OBSERVED_SENT active timeout pair")
    body_cmd_obs_clr = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_OBS, send_state=SS_SENT,
        cumulative_attempts=4, gen=2, inv=2, exhausted=0, avail=3)
    add_att_pos("DSB3_ATT_TX_CMD_OBS_CLEARED", body_cmd_obs_clr,
                "OBSERVED_SENT timeout cleared")

    # RESOLVED/SENT_POSSIBLE
    body_cmd_sent = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
        cumulative_attempts=5, gen=4, inv=3, exhausted=0, avail=2)
    add_att_pos("DSB3_ATT_TX_CMD_SENT", body_cmd_sent)
    k, v, b = attempt_typed(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
        cumulative_attempts=5, gen=4, inv=3, exhausted=0, avail=2,
        body=body_cmd_sent)
    add_att_typed("DSB3_ATT_TX_CMD_SENT_TYPED", k, v, b)

    # RECOVERY_REQUIRED pair (frozen counters, avail any, timeout 2-form)
    body_cmd_rec = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_REC, send_state=SS_REC,
        cumulative_attempts=2, gen=5, inv=2, exhausted=0, avail=0,
        timeout_epoch=timeout_ep, timeout_at=1)
    add_att_pos("DSB3_ATT_TX_CMD_RECOVERY", body_cmd_rec)

    # MAX exhausted edges (gen==MAX or inv==MAX with exhausted=1)
    body_cmd_ex_gen = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
        cumulative_attempts=1, gen=U64_MAX, inv=1, exhausted=1, avail=1)
    add_att_pos("DSB3_ATT_TX_CMD_EXH_GEN_MAX", body_cmd_ex_gen,
                "exhausted iff gen==UINT64_MAX")
    body_cmd_ex_inv = enc_attempt_body(
        attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
        cumulative_attempts=1, gen=U64_MAX, inv=U64_MAX, exhausted=1, avail=1)
    add_att_pos("DSB3_ATT_TX_CMD_EXH_INV_MAX", body_cmd_ex_inv,
                "exhausted with inv==gen==UINT64_MAX")

    # --- Local TX EVENT matrix (cycle rules) ---
    body_evt_prep = enc_attempt_body(
        attempt_kind=AK_EVT, attempt_state=AS_PREP, send_state=SS_PREP,
        retry_cycle_id=1, attempt_in_cycle=1, cumulative_attempts=1)
    add_att_pos("DSB3_ATT_TX_EVT_PREP", body_evt_prep, "EVENT cycle>=1 in_cycle 1..8")
    body_evt_edge = enc_attempt_body(
        attempt_kind=AK_EVT, attempt_state=AS_RES, send_state=SS_SENT,
        retry_cycle_id=9, attempt_in_cycle=8, cumulative_attempts=8,
        gen=1, inv=1, avail=4)
    add_att_pos("DSB3_ATT_TX_EVT_IN8", body_evt_edge, "attempt_in_cycle=8 max")
    body_evt_retry_br = enc_attempt_body(
        attempt_kind=AK_EVT, attempt_state=AS_RES, send_state=SS_RETRY,
        retry_cycle_id=2, attempt_in_cycle=3, cumulative_attempts=10,
        gen=4, inv=1, avail=11)
    add_att_pos("DSB3_ATT_TX_EVT_RETRY_BEARER", body_evt_retry_br)
    body_evt_den_txg = enc_attempt_body(
        attempt_kind=AK_EVT, attempt_state=AS_RES, send_state=SS_DENIED,
        retry_cycle_id=1, attempt_in_cycle=1, cumulative_attempts=1,
        gen=1, inv=0, avail=0)
    add_att_pos("DSB3_ATT_TX_EVT_DENIED_TXGATE", body_evt_den_txg)
    body_evt_obs = enc_attempt_body(
        attempt_kind=AK_EVT, attempt_state=AS_OBS, send_state=SS_SENT,
        retry_cycle_id=3, attempt_in_cycle=2, cumulative_attempts=5,
        gen=2, inv=1, avail=6)
    add_att_pos("DSB3_ATT_TX_EVT_OBS", body_evt_obs)
    body_evt_rec = enc_attempt_body(
        attempt_kind=AK_EVT, attempt_state=AS_REC, send_state=SS_REC,
        retry_cycle_id=1, attempt_in_cycle=1, cumulative_attempts=2,
        gen=3, inv=3, avail=0)
    add_att_pos("DSB3_ATT_TX_EVT_RECOVERY", body_evt_rec)
    k, v, b = attempt_typed(
        attempt_kind=AK_EVT, attempt_state=AS_PREP, send_state=SS_PREP,
        retry_cycle_id=1, attempt_in_cycle=1, cumulative_attempts=1,
        body=body_evt_prep)
    add_att_typed("DSB3_ATT_TX_EVT_PREP_TYPED", k, v, b)

    # --- Local TX CANCEL matrix (counters always 0, cycle zero) ---
    body_can_prep = enc_attempt_body(
        attempt_kind=AK_CAN, attempt_state=AS_PREP, send_state=SS_PREP,
        cumulative_attempts=0, gen=0, inv=0, exhausted=0, avail=0)
    add_att_pos("DSB3_ATT_TX_CAN_PREP", body_can_prep)
    body_can_retry = enc_attempt_body(
        attempt_kind=AK_CAN, attempt_state=AS_PREP, send_state=SS_RETRY,
        cumulative_attempts=0, gen=0, inv=0, exhausted=0, avail=5)
    add_att_pos("DSB3_ATT_TX_CAN_RETRY", body_can_retry,
                "CANCEL PREPARED/RETRYABLE avail non-zero")
    body_can_sent = enc_attempt_body(
        attempt_kind=AK_CAN, attempt_state=AS_RES, send_state=SS_SENT,
        cumulative_attempts=0, gen=0, inv=0, exhausted=0, avail=2)
    add_att_pos("DSB3_ATT_TX_CAN_SENT", body_can_sent)
    body_can_den0 = enc_attempt_body(
        attempt_kind=AK_CAN, attempt_state=AS_RES, send_state=SS_DENIED,
        cumulative_attempts=0, gen=0, inv=0, exhausted=0, avail=0)
    add_att_pos("DSB3_ATT_TX_CAN_DENIED_TXGATE", body_can_den0)
    body_can_den1 = enc_attempt_body(
        attempt_kind=AK_CAN, attempt_state=AS_RES, send_state=SS_DENIED,
        cumulative_attempts=0, gen=0, inv=0, exhausted=0, avail=8)
    add_att_pos("DSB3_ATT_TX_CAN_DENIED_BEARER", body_can_den1)
    body_can_rec = enc_attempt_body(
        attempt_kind=AK_CAN, attempt_state=AS_REC, send_state=SS_REC,
        cumulative_attempts=0, gen=0, inv=0, exhausted=0, avail=0)
    add_att_pos("DSB3_ATT_TX_CAN_RECOVERY", body_can_rec)
    k, v, b = attempt_typed(
        attempt_kind=AK_CAN, attempt_state=AS_PREP, send_state=SS_PREP,
        cumulative_attempts=0, body=body_can_prep)
    add_att_typed("DSB3_ATT_TX_CAN_PREP_TYPED", k, v, b)

    # revision >= 1 (replacement rev 2 ok for ATTEMPT)
    k2, v2, b2 = attempt_typed(
        attempt_kind=AK_CMD, attempt_state=AS_PREP, send_state=SS_PREP,
        cumulative_attempts=1, rev=2, body=body_cmd_prep)
    add_att_typed("DSB3_ATT_TX_REV2", k2, v2, b2, "record_revision>=1 allowed")

    # --- DELIVERY remote canonical (all kinds) ---
    for kind, tag in ((AK_CMD, "CMD"), (AK_EVT, "EVT"), (AK_CAN, "CAN")):
        body_r = enc_attempt_body(
            owner_kind=ATT_DLV, owner_raw=dlv_raw, attempt_kind=kind,
            attempt_state=AS_RES, send_state=SS_SENT,
            retry_cycle_id=0, attempt_in_cycle=0, cumulative_attempts=0,
            gen=0, inv=0, exhausted=0, avail=0, prepared_at=0)
        add_att_pos(f"DSB3_ATT_DLV_{tag}_REMOTE", body_r,
                    f"DELIVERY remote {tag} RESOLVED/SENT_POSSIBLE")
        k, v, b = attempt_typed(
            owner_kind=ATT_DLV, owner_raw=dlv_raw, attempt_kind=kind,
            attempt_state=AS_RES, send_state=SS_SENT,
            cumulative_attempts=0, body=body_r)
        add_att_typed(f"DSB3_ATT_DLV_{tag}_REMOTE_TYPED", k, v, b)

    # --- negatives: crossed inv/availability, illegal pairs, cycle, etc. ---
    # crossed: RESOLVED/RETRYABLE with inv=0 and avail non-zero
    add_att_neg_body(
        "DSB3_ATT_TX_CMD_CROSS_INV0_AVAIL",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_RETRY,
            cumulative_attempts=1, gen=2, inv=0, avail=1),
        "crossed TxGate/Bearer path")
    a_mut += 1
    # crossed: inv>=1 and avail=0
    add_att_neg_body(
        "DSB3_ATT_TX_CMD_CROSS_INV1_AVAIL0",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_RETRY,
            cumulative_attempts=1, gen=2, inv=1, avail=0))
    # illegal state/send pair: PREPARED/SENT_POSSIBLE
    add_att_neg_body(
        "DSB3_ATT_TX_CMD_BAD_PAIR_PREP_SENT",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_PREP, send_state=SS_SENT,
            cumulative_attempts=1, gen=1, inv=1, avail=1))
    # OBSERVED_SENT with avail=0
    add_att_neg_body(
        "DSB3_ATT_TX_CMD_OBS_AVAIL0",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_OBS, send_state=SS_SENT,
            cumulative_attempts=1, gen=1, inv=1, avail=0))
    # RESOLVED/SENT with timeout still set
    add_att_neg_body(
        "DSB3_ATT_TX_CMD_SENT_TIMEOUT_NZ",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
            cumulative_attempts=1, gen=1, inv=1, avail=1,
            timeout_epoch=timeout_ep, timeout_at=1))
    # COMMAND cycle wrong
    add_att_neg_body(
        "DSB3_ATT_TX_CMD_CYCLE_NZ",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_PREP, send_state=SS_PREP,
            retry_cycle_id=1, attempt_in_cycle=0, cumulative_attempts=1))
    add_att_neg_body(
        "DSB3_ATT_TX_CMD_CUM0",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_PREP, send_state=SS_PREP,
            cumulative_attempts=0))
    # EVENT cycle wrong: in_cycle 0, 9, cycle 0, cum < in_cycle
    add_att_neg_body(
        "DSB3_ATT_TX_EVT_IN0",
        enc_attempt_body(
            attempt_kind=AK_EVT, attempt_state=AS_PREP, send_state=SS_PREP,
            retry_cycle_id=1, attempt_in_cycle=0, cumulative_attempts=1))
    add_att_neg_body(
        "DSB3_ATT_TX_EVT_IN9",
        enc_attempt_body(
            attempt_kind=AK_EVT, attempt_state=AS_PREP, send_state=SS_PREP,
            retry_cycle_id=1, attempt_in_cycle=9, cumulative_attempts=9))
    add_att_neg_body(
        "DSB3_ATT_TX_EVT_CYCLE0",
        enc_attempt_body(
            attempt_kind=AK_EVT, attempt_state=AS_PREP, send_state=SS_PREP,
            retry_cycle_id=0, attempt_in_cycle=1, cumulative_attempts=1))
    add_att_neg_body(
        "DSB3_ATT_TX_EVT_CUM_LT_IN",
        enc_attempt_body(
            attempt_kind=AK_EVT, attempt_state=AS_PREP, send_state=SS_PREP,
            retry_cycle_id=1, attempt_in_cycle=3, cumulative_attempts=2))
    # CANCEL counters non-zero / cycle non-zero
    add_att_neg_body(
        "DSB3_ATT_TX_CAN_GEN_NZ",
        enc_attempt_body(
            attempt_kind=AK_CAN, attempt_state=AS_PREP, send_state=SS_PREP,
            cumulative_attempts=0, gen=1, inv=0, exhausted=0, avail=0))
    add_att_neg_body(
        "DSB3_ATT_TX_CAN_CYCLE_NZ",
        enc_attempt_body(
            attempt_kind=AK_CAN, attempt_state=AS_PREP, send_state=SS_PREP,
            retry_cycle_id=1, attempt_in_cycle=0, cumulative_attempts=0))
    # inv > gen
    add_att_neg_body(
        "DSB3_ATT_TX_INV_GT_GEN",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
            cumulative_attempts=1, gen=1, inv=2, avail=1))
    # exhausted=1 without MAX
    add_att_neg_body(
        "DSB3_ATT_TX_EXH_WITHOUT_MAX",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
            cumulative_attempts=1, gen=5, inv=3, exhausted=1, avail=1))
    # MAX without exhausted
    add_att_neg_body(
        "DSB3_ATT_TX_MAX_WITHOUT_EXH",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
            cumulative_attempts=1, gen=U64_MAX, inv=1, exhausted=0, avail=1))
    # half timeout
    add_att_neg_body(
        "DSB3_ATT_TX_TIMEOUT_HALF_EP",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_OBS, send_state=SS_SENT,
            cumulative_attempts=1, gen=1, inv=1, avail=1,
            timeout_epoch=timeout_ep, timeout_at=0))
    add_att_neg_body(
        "DSB3_ATT_TX_TIMEOUT_HALF_AT",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_OBS, send_state=SS_SENT,
            cumulative_attempts=1, gen=1, inv=1, avail=1,
            timeout_epoch=bytes(16), timeout_at=9))
    # prepared epoch zero
    add_att_neg_body(
        "DSB3_ATT_TX_PREP_EPOCH0",
        enc_attempt_body(
            attempt_kind=AK_CMD, attempt_state=AS_PREP, send_state=SS_PREP,
            cumulative_attempts=1, prepared_epoch=bytes(16)))
    # owner raw / tx component
    add_att_neg_body(
        "DSB3_ATT_TX_RAW_NE_TXN",
        enc_attempt_body(
            owner_raw=bytes([0x99] * 16), transaction_id=txn,
            primary_kd=bytes([0xAB] * 32)))
    add_att_neg_body(
        "DSB3_ATT_TX_RAW_LEN15",
        enc_attempt_body(owner_raw=txn[:15], primary_kd=bytes([0xAB] * 32)))
    bad_dlv = bytearray(dlv_raw)
    bad_dlv[32:48] = bytes([0x55] * 16)
    add_att_neg_body(
        "DSB3_ATT_DLV_TXN_COMPONENT",
        enc_attempt_body(
            owner_kind=ATT_DLV, owner_raw=bytes(bad_dlv), transaction_id=txn,
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
            cumulative_attempts=0, primary_kd=bytes([0xAB] * 32)),
        "DELIVERY raw [32,48) must equal transaction_id")
    add_att_neg_body(
        "DSB3_ATT_DLV_RAW_LEN79",
        enc_attempt_body(
            owner_kind=ATT_DLV, owner_raw=dlv_raw[:79],
            attempt_kind=AK_CMD, attempt_state=AS_RES, send_state=SS_SENT,
            cumulative_attempts=0, primary_kd=bytes([0xAB] * 32)))
    # remote with non-zero counters / wrong state
    add_att_neg_body(
        "DSB3_ATT_DLV_GEN_NZ",
        enc_attempt_body(
            owner_kind=ATT_DLV, attempt_kind=AK_CMD, attempt_state=AS_RES,
            send_state=SS_SENT, cumulative_attempts=0, gen=1, inv=0, avail=0))
    add_att_neg_body(
        "DSB3_ATT_DLV_BAD_STATE",
        enc_attempt_body(
            owner_kind=ATT_DLV, attempt_kind=AK_CMD, attempt_state=AS_PREP,
            send_state=SS_PREP, cumulative_attempts=0))
    add_att_neg_body(
        "DSB3_ATT_DLV_AVAIL_NZ",
        enc_attempt_body(
            owner_kind=ATT_DLV, attempt_kind=AK_CMD, attempt_state=AS_RES,
            send_state=SS_SENT, cumulative_attempts=0, avail=1))
    # key / primary / digests / reserved
    mut_pkd = bytearray(body_cmd_prep)
    # offset of primary_key_digest: 16+2+2+2+16 = 38
    mut_pkd[38:70] = bytes([0xB0] * 32)
    add_att_neg_body("DSB3_ATT_BAD_PRIMARY_KD", bytes(mut_pkd))
    a_mut += 1
    add_att_neg_body(
        "DSB3_ATT_ZERO_ATTEMPT_ID",
        enc_attempt_body(attempt_id=bytes(16)))
    add_att_neg_body(
        "DSB3_ATT_ZERO_TARGET",
        enc_attempt_body(target=bytes(32)))
    add_att_neg_body(
        "DSB3_ATT_ZERO_SEMANTIC",
        enc_attempt_body(semantic=bytes(32)))
    add_att_neg_body(
        "DSB3_ATT_RESERVED0_NZ",
        enc_attempt_body(reserved0=1))
    add_att_neg_body(
        "DSB3_ATT_RESERVED1_NZ",
        enc_attempt_body(reserved1=1))
    add_att_neg_body(
        "DSB3_ATT_OWNER0",
        enc_attempt_body(owner_kind=0, owner_raw=txn, primary_kd=bytes(32)))
    add_att_neg_body(
        "DSB3_ATT_OWNER3",
        enc_attempt_body(owner_kind=3, owner_raw=txn, primary_kd=bytes(32)))
    add_att_neg_body(
        "DSB3_ATT_KIND0",
        enc_attempt_body(attempt_kind=0))
    add_att_neg_body(
        "DSB3_ATT_STATE0",
        enc_attempt_body(attempt_state=0))
    add_att_neg_body(
        "DSB3_ATT_SEND0",
        enc_attempt_body(send_state=0))
    # short / trailing / BTS
    add_att_neg_body("DSB3_ATT_SHORT", body_cmd_prep[:-1])
    add_att_neg_body("DSB3_ATT_TRAILING", body_cmd_prep + b"\x00")
    add(id="DSB3_ATT_BUFFER_TOO_SMALL", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x31,
        body_length=len(body_cmd_prep), body_hex=hx(body_cmd_prep),
        key_length=0)
    a_neg += 1
    # typed: bad key composite, zero head/pvd, bad primary_id, flags
    bad_key = bkey(6, 0x31, 5, bytes([0x55] * 32))
    _, val_ok, _ = attempt_typed(body=body_cmd_prep)
    add_att_neg_typed("DSB3_ATT_BAD_KEY", bad_key, val_ok)
    k_zh, v_zh, _ = attempt_typed(body=body_cmd_prep, head=bytes(32))
    add_att_neg_typed("DSB3_ATT_ZERO_HEAD", k_zh, v_zh)
    k_zp, v_zp, _ = attempt_typed(body=body_cmd_prep, pvd=bytes(32))
    add_att_neg_typed("DSB3_ATT_ZERO_PVD", k_zp, v_zp)
    k_bp, v_bp, _ = attempt_typed(body=body_cmd_prep, primary=bytes(16))
    add_att_neg_typed("DSB3_ATT_BAD_PRIMARY_ID", k_bp, v_bp)
    k_fl = attempt_key(ATT_TX, txn, att_id)
    v_fl = enc_env_full(6, 0x31, 1, 1, txn, head_nz, pvd_nz, body_cmd_prep)
    add_att_neg_typed("DSB3_ATT_FLAGS_NZ", k_fl, v_fl, "flags must be 0")
    k_r0, v_r0, _ = attempt_typed(body=body_cmd_prep, rev=0)
    add_att_neg_typed("DSB3_ATT_REV0", k_r0, v_r0)

    b3_cov["31"] = add_body_suite("ATTEMPT", 6, 0x31, a_pos, a_neg, a_mut, a_rt)
    assert b3_cov["31"]["positive"] >= 20
    assert b3_cov["31"]["negative"] >= 25
    assert b3_cov["31"]["roundtrip"] >= 8

    # =====================================================================
    # D1-B3e ATTEMPT_ID_INDEX (0x34) — after ATTEMPT (B3b r1 may shift count)
    # =====================================================================
    # Re-pinned at D1-B3i: kind9/10 42-byte identity correction.
    PRE_B3E_NON_B3B_WIRE_FINGERPRINT = (
        "09e7094f166ac698ba921f3a6da1ae2852782898717b40b5cf810320109f83ee"
    )
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[-1]["id"] == "DSB3_ATT_REV0"
    _pre_b3e_fp = non_b3b_wire_fingerprint(vectors)
    assert _pre_b3e_fp == PRE_B3E_NON_B3B_WIRE_FINGERPRINT, (
        f"pre-B3e non-B3b-wire fingerprint drift: got {_pre_b3e_fp}"
    )
    PRE_B3E_VECTOR_COUNT = len(vectors)

    # Distinct attempt IDs for COMMAND / EVENT / CANCEL positives.
    aii_id_cmd = bytes([0xA1 + i for i in range(16)])
    aii_id_evt = bytes([0xB1 + i for i in range(16)])
    aii_id_can = bytes([0xC1 + i for i in range(16)])
    aii_txn = txn  # local-origin TRANSACTION_ANCHOR identity
    aii_creation = bytes([0x51 + (i % 200) for i in range(32)])
    aii_head = F["head_nz"]
    aii_pvd = bytes([0x61 + (i % 180) for i in range(32)])
    assert not all(b == 0 for b in aii_creation)
    assert not all(b == 0 for b in aii_pvd)
    assert len(aii_txn) == 16 and not all(b == 0 for b in aii_txn)

    def attempt_id_index_record_key_digest(
        attempt_id: bytes, transaction_id: bytes
    ) -> bytes:
        """KEY_DIGEST(complete TX-owned ATTEMPT key); never bare composite."""
        comps = (
            be16(ATT_TX)
            + raw16(transaction_id)
            + attempt_id
        )
        return complete_key_digest_composite(0x31, comps)

    def attempt_id_index_bare_composite(
        attempt_id: bytes, transaction_id: bytes
    ) -> bytes:
        """Bare COMPOSITE digest alone — must not pass as record key digest."""
        comps = be16(ATT_TX) + raw16(transaction_id) + attempt_id
        return composite(0x31, comps)

    def enc_attempt_id_index_body(
        attempt_id=None,
        transaction_id=None,
        attempt_kind=AK_CMD,
        reserved=0,
        record_kd=None,
        creation=None,
    ) -> bytes:
        if attempt_id is None:
            attempt_id = aii_id_cmd
        if transaction_id is None:
            transaction_id = aii_txn
        if creation is None:
            creation = aii_creation
        if record_kd is None:
            record_kd = attempt_id_index_record_key_digest(
                attempt_id, transaction_id
            )
        out = bytearray()
        out += attempt_id
        out += transaction_id
        out += be16(attempt_kind)
        out += be16(reserved)
        out += record_kd
        out += creation
        assert len(out) == 100
        return bytes(out)

    def attempt_id_index_key(attempt_id: bytes) -> bytes:
        return bkey(6, 0x34, 2, attempt_id)

    def attempt_id_index_typed(
        attempt_id=None,
        transaction_id=None,
        attempt_kind=AK_CMD,
        rev=1,
        head=None,
        pvd=None,
        primary=None,
        body=None,
        **kwargs,
    ):
        if attempt_id is None:
            attempt_id = aii_id_cmd
        if transaction_id is None:
            transaction_id = aii_txn
        if head is None:
            head = aii_head
        if pvd is None:
            pvd = aii_pvd
        if body is None:
            body = enc_attempt_id_index_body(
                attempt_id=attempt_id,
                transaction_id=transaction_id,
                attempt_kind=attempt_kind,
                **kwargs,
            )
        if primary is None:
            primary = transaction_id
        key = attempt_id_index_key(attempt_id)
        val = enc_env_full(6, 0x34, 0, rev, primary, head, pvd, body)
        return key, val, body

    i_pos = 0
    i_neg = 0
    i_mut = 0
    i_rt = 0

    def add_aii_pos(vid, body, notes=""):
        nonlocal i_pos, i_rt
        add(id=vid, suite="DSB3", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x34, body_length=len(body), body_hex=hx(body),
            notes=notes)
        i_pos += 1
        i_rt += 1

    def add_aii_typed(vid, key, val, body, notes=""):
        nonlocal i_pos
        add(id=vid, suite="DSB3", op="typed_record", expected_status="OK",
            family=6, subtype=0x34, key_hex=hx(key), value_hex=hx(val),
            body_hex=hx(body), digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}", notes=notes)
        i_pos += 1

    def add_aii_neg_body(vid, body, notes=""):
        nonlocal i_neg
        add(id=vid, suite="DSB3", op="body_decode", expected_status="CORRUPT",
            family=6, subtype=0x34, body_hex=hx(body), notes=notes)
        i_neg += 1

    def add_aii_neg_typed(vid, key, val, notes=""):
        nonlocal i_neg
        add(id=vid, suite="DSB3", op="typed_record",
            expected_status="CORRUPT", family=6, subtype=0x34,
            key_hex=hx(key), value_hex=hx(val), notes=notes)
        i_neg += 1

    # --- positives: COMMAND / EVENT / CANCEL body + typed ---
    body_aii_cmd = enc_attempt_id_index_body(
        attempt_id=aii_id_cmd, attempt_kind=AK_CMD)
    body_aii_evt = enc_attempt_id_index_body(
        attempt_id=aii_id_evt, attempt_kind=AK_EVT)
    body_aii_can = enc_attempt_id_index_body(
        attempt_id=aii_id_can, attempt_kind=AK_CAN)
    add_aii_pos("DSB3_AII_CMD_BODY", body_aii_cmd, "COMMAND body roundtrip")
    add_aii_pos("DSB3_AII_EVT_BODY", body_aii_evt, "EVENT body roundtrip")
    add_aii_pos("DSB3_AII_CAN_BODY", body_aii_can, "CANCEL body roundtrip")
    k_cmd, v_cmd, _ = attempt_id_index_typed(
        attempt_id=aii_id_cmd, attempt_kind=AK_CMD, body=body_aii_cmd)
    k_evt, v_evt, _ = attempt_id_index_typed(
        attempt_id=aii_id_evt, attempt_kind=AK_EVT, body=body_aii_evt)
    k_can, v_can, _ = attempt_id_index_typed(
        attempt_id=aii_id_can, attempt_kind=AK_CAN, body=body_aii_can)
    add_aii_typed("DSB3_AII_CMD_TYPED", k_cmd, v_cmd, body_aii_cmd)
    add_aii_typed("DSB3_AII_EVT_TYPED", k_evt, v_evt, body_aii_evt)
    add_aii_typed("DSB3_AII_CAN_TYPED", k_can, v_can, body_aii_can)

    # mutation: flip reserved in positive body → corrupt
    mut_body = bytearray(body_aii_cmd)
    mut_body[34] ^= 0x01
    add(id="DSB3_AII_MUT_RESERVED", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x34,
        body_hex=hx(bytes(mut_body)), notes="reserved flip")
    i_mut += 1
    i_neg += 1

    # --- body negatives ---
    add_aii_neg_body(
        "DSB3_AII_ZERO_ATTEMPT_ID",
        enc_attempt_id_index_body(attempt_id=bytes(16)),
        "attempt_id must be non-zero")
    add_aii_neg_body(
        "DSB3_AII_ZERO_TXN_ID",
        enc_attempt_id_index_body(transaction_id=bytes(16)),
        "transaction_id must be non-zero")
    add_aii_neg_body(
        "DSB3_AII_KIND0",
        enc_attempt_id_index_body(attempt_kind=0),
        "attempt_kind 0 unknown")
    add_aii_neg_body(
        "DSB3_AII_KIND4",
        enc_attempt_id_index_body(attempt_kind=4),
        "attempt_kind 4 unknown")
    add_aii_neg_body(
        "DSB3_AII_RESERVED_NZ",
        enc_attempt_id_index_body(reserved=1),
        "reserved must be 0")
    add_aii_neg_body(
        "DSB3_AII_CREATION_ZERO",
        enc_attempt_id_index_body(creation=bytes(32)),
        "attempt_creation_value_digest must be non-zero")
    add_aii_neg_body(
        "DSB3_AII_RKD_ZERO",
        enc_attempt_id_index_body(record_kd=bytes(32)),
        "attempt_record_key_digest must be non-zero complete-key KEY_DIGEST")
    add_aii_neg_body(
        "DSB3_AII_RKD_BARE_COMPOSITE",
        enc_attempt_id_index_body(
            record_kd=attempt_id_index_bare_composite(aii_id_cmd, aii_txn)),
        "bare composite digest is not KEY_DIGEST(complete ATTEMPT key)")
    add_aii_neg_body(
        "DSB3_AII_RKD_BARE_ATTEMPT_HASH",
        enc_attempt_id_index_body(record_kd=sha256(aii_id_cmd)),
        "sha256(attempt_id) alone is not KEY_DIGEST(complete ATTEMPT key)")
    add_aii_neg_body(
        "DSB3_AII_RKD_WRONG_TXN",
        enc_attempt_id_index_body(
            record_kd=attempt_id_index_record_key_digest(
                aii_id_cmd, bytes([0xEE] * 16))),
        "record key digest derived from wrong transaction_id")
    add_aii_neg_body(
        "DSB3_AII_RKD_WRONG_ATTEMPT",
        enc_attempt_id_index_body(
            record_kd=attempt_id_index_record_key_digest(
                aii_id_evt, aii_txn)),
        "record key digest derived from wrong attempt_id")
    # DELIVERY-shaped derivation: COMPOSITE(31, DELIVERY owner || RAW16(80) || aid)
    dlv_comps = be16(ATT_DLV) + raw16(dlv_raw) + aii_id_cmd
    dlv_shaped_rkd = complete_key_digest_composite(0x31, dlv_comps)
    add_aii_neg_body(
        "DSB3_AII_RKD_DELIVERY_SHAPED",
        enc_attempt_id_index_body(record_kd=dlv_shaped_rkd),
        "DELIVERY-owned ATTEMPT complete-key digest is not valid for index")
    # short / trailing / BTS
    add(id="DSB3_AII_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x34,
        body_hex=hx(body_aii_cmd[:-1]), notes="short body")
    i_neg += 1
    add(id="DSB3_AII_TRAILING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x34,
        body_hex=hx(body_aii_cmd + b"\x00"), notes="trailing byte")
    i_neg += 1
    add(id="DSB3_AII_BTS", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x34,
        body_length=len(body_aii_cmd), body_hex=hx(body_aii_cmd),
        key_length=0)
    i_neg += 1

    # --- typed negatives ---
    # key ID128 mismatch
    bad_key = attempt_id_index_key(aii_id_evt)
    _, val_ok, _ = attempt_id_index_typed(body=body_aii_cmd)
    add_aii_neg_typed(
        "DSB3_AII_KEY_MISMATCH", bad_key, val_ok,
        "key ID128 must equal body attempt_id")
    # wrong key kind (composite instead of ID128)
    wrong_kind_key = bkey(6, 0x34, 5, bytes([0x55] * 32))
    add_aii_neg_typed(
        "DSB3_AII_WRONG_KIND", wrong_kind_key, val_ok,
        "key must be direct ID128")
    # self-key primary_id (attempt_id instead of transaction_id)
    k_sk, v_sk, _ = attempt_id_index_typed(
        body=body_aii_cmd, primary=aii_id_cmd)
    add_aii_neg_typed(
        "DSB3_AII_SELF_KEY_PRIMARY", k_sk, v_sk,
        "primary_id must be transaction_id not attempt_id")
    k_wp, v_wp, _ = attempt_id_index_typed(
        body=body_aii_cmd, primary=bytes([0xDD] * 16))
    add_aii_neg_typed(
        "DSB3_AII_BAD_PRIMARY", k_wp, v_wp, "wrong primary_id")
    k_zp, v_zp, _ = attempt_id_index_typed(
        body=body_aii_cmd, primary=bytes(16))
    add_aii_neg_typed(
        "DSB3_AII_ZERO_PRIMARY", k_zp, v_zp, "zero primary_id")
    k_zh, v_zh, _ = attempt_id_index_typed(
        body=body_aii_cmd, head=bytes(32))
    add_aii_neg_typed("DSB3_AII_ZERO_HEAD", k_zh, v_zh)
    k_zv, v_zv, _ = attempt_id_index_typed(
        body=body_aii_cmd, pvd=bytes(32))
    add_aii_neg_typed("DSB3_AII_ZERO_PVD", k_zv, v_zv)
    k_fl = attempt_id_index_key(aii_id_cmd)
    v_fl = enc_env_full(
        6, 0x34, 1, 1, aii_txn, aii_head, aii_pvd, body_aii_cmd)
    add_aii_neg_typed(
        "DSB3_AII_FLAGS_NZ", k_fl, v_fl, "flags must be 0")
    k_r0, v_r0, _ = attempt_id_index_typed(body=body_aii_cmd, rev=0)
    add_aii_neg_typed("DSB3_AII_REV0", k_r0, v_r0, "revision must be 1")
    k_r2, v_r2, _ = attempt_id_index_typed(body=body_aii_cmd, rev=2)
    add_aii_neg_typed("DSB3_AII_REV2", k_r2, v_r2, "revision must be exact 1")

    b3_cov["34"] = add_body_suite(
        "ATTEMPT_ID_INDEX", 6, 0x34, i_pos, i_neg, i_mut, i_rt)
    assert b3_cov["34"]["positive"] >= 6
    assert b3_cov["34"]["negative"] >= 15
    assert b3_cov["34"]["roundtrip"] >= 3

    # =====================================================================
    # D1-B3f CANCEL_STATE (0x33) — after AII (B3b r1 may shift count)
    # =====================================================================
    # Re-pinned at D1-B3i: kind9/10 42-byte identity correction.
    PRE_B3F_NON_B3B_WIRE_FINGERPRINT = (
        "3221010f0c35d58e4eff9232d508e667b41a8cded9e6e9e59f7e2dd388748c46"
    )
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[-1]["id"] == "DSB3_AII_REV2"
    _pre_b3f_fp = non_b3b_wire_fingerprint(vectors)
    assert _pre_b3f_fp == PRE_B3F_NON_B3B_WIRE_FINGERPRINT, (
        f"pre-B3f non-B3b-wire fingerprint drift: got {_pre_b3f_fp}"
    )
    PRE_B3F_VECTOR_COUNT = len(vectors)

    # Private CANCEL_STATE enums / public bijection constants.
    CS_TX = 1
    CS_DLV = 2
    ST_NONE = 1
    ST_PEND = 2
    ST_FENCED = 3
    ST_TOO_LATE = 4
    CK_NONE = 0
    CK_FENCED = 1
    CK_PEND = 2
    CK_TOO_LATE = 3
    CK_ALREADY = 4  # never stored
    GATE_NEVER = 1
    GATE_RETRY = 2
    GATE_CLOSED = 3
    R_FENCED = 82
    R_TOO_LATE = 83
    R_PEND = 86
    E_NONE = 0
    E_NO_EFFECT = 1
    E_POSSIBLE = 2
    cancel_attempt_id = bytes([0xCA + (i % 40) for i in range(16)])
    cancel_semantic = bytes([0x5A + (i % 180) for i in range(32)])
    cancel_timeout_ep = bytes([0xD1 + (i % 16) for i in range(16)])
    cancel_head = F["head_nz"]
    cancel_pvd = bytes([0x71 + (i % 170) for i in range(32)])
    assert not all(b == 0 for b in cancel_attempt_id)
    assert not all(b == 0 for b in cancel_semantic)
    assert not all(b == 0 for b in cancel_timeout_ep)
    assert not all(b == 0 for b in cancel_pvd)
    assert len(txn) == 16 and len(dlv_raw) == 80
    assert dlv_raw[32:48] == txn

    def cancel_primary_key_digest(owner_kind: int, owner_raw: bytes) -> bytes:
        """Independent KEY_DIGEST of referenced primary complete key."""
        if owner_kind == CS_TX:
            return complete_key_digest_id128(0x20, owner_raw)
        if owner_kind == CS_DLV:
            return complete_key_digest_composite(0x40, raw16(owner_raw))
        raise ValueError("bad cancel owner")

    def cancel_primary_id(owner_kind: int, owner_raw: bytes, transaction_id: bytes) -> bytes:
        if owner_kind == CS_TX:
            return transaction_id
        if owner_kind == CS_DLV:
            return primary_id_from_composite_subtype(0x40, raw16(owner_raw))
        raise ValueError("bad cancel owner")

    def cancel_key_components(owner_kind: int, owner_raw: bytes) -> bytes:
        return be16(owner_kind) + raw16(owner_raw)

    def cancel_key(owner_kind: int, owner_raw: bytes) -> bytes:
        return bkey(6, 0x33, 5, composite(0x33, cancel_key_components(
            owner_kind, owner_raw)))

    def enc_cancel_body(
        owner_kind=CS_TX,
        owner_raw=None,
        transaction_id=None,
        primary_kd=None,
        cancel_attempt=None,
        cancel_state=ST_NONE,
        cancel_kind=CK_NONE,
        reason=0,
        effect=E_NONE,
        gate=GATE_NEVER,
        semantic=None,
        timeout_epoch=None,
        timeout_at=0,
        reserved=0,
    ) -> bytes:
        if transaction_id is None:
            transaction_id = txn
        if owner_raw is None:
            owner_raw = txn if owner_kind == CS_TX else (
                dlv_raw if owner_kind == CS_DLV else txn)
        if primary_kd is None:
            if owner_kind in (CS_TX, CS_DLV):
                primary_kd = cancel_primary_key_digest(owner_kind, owner_raw)
            else:
                # Negatives with unknown owner still need a digest field.
                primary_kd = complete_key_digest_id128(0x20, transaction_id)
        if cancel_attempt is None:
            cancel_attempt = bytes(16)
        if semantic is None:
            semantic = bytes(32)
        if timeout_epoch is None:
            timeout_epoch = bytes(16)
        out = bytearray()
        out += be16(owner_kind)
        out += be16(reserved)
        out += raw16(owner_raw)
        out += primary_kd
        out += transaction_id
        out += cancel_attempt
        out += be32(cancel_state)
        out += be32(cancel_kind)
        out += be32(reason)
        out += be32(effect)
        out += be32(gate)
        out += semantic
        out += timeout_epoch
        out += be64(timeout_at)
        expected = 146 + len(owner_raw)
        assert len(out) == expected, f"cancel body len {len(out)} != {expected}"
        return bytes(out)

    def cancel_typed(
        owner_kind=CS_TX,
        owner_raw=None,
        transaction_id=None,
        rev=1,
        head=None,
        pvd=None,
        primary=None,
        body=None,
        **kwargs,
    ):
        if transaction_id is None:
            transaction_id = txn
        if owner_raw is None:
            owner_raw = txn if owner_kind == CS_TX else dlv_raw
        if head is None:
            head = cancel_head
        if pvd is None:
            pvd = cancel_pvd
        if body is None:
            body = enc_cancel_body(
                owner_kind=owner_kind, owner_raw=owner_raw,
                transaction_id=transaction_id, **kwargs)
        if primary is None:
            primary = cancel_primary_id(owner_kind, owner_raw, transaction_id)
        key = cancel_key(owner_kind, owner_raw)
        val = enc_env_full(6, 0x33, 0, rev, primary, head, pvd, body)
        return key, val, body

    c_pos = 0
    c_neg = 0
    c_mut = 0
    c_rt = 0

    def add_cs_pos(vid, body, notes=""):
        nonlocal c_pos, c_rt
        add(id=vid, suite="DSB3", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x33, body_length=len(body), body_hex=hx(body),
            notes=notes)
        c_pos += 1
        c_rt += 1

    def add_cs_typed(vid, key, val, body, notes=""):
        nonlocal c_pos
        add(id=vid, suite="DSB3", op="typed_record", expected_status="OK",
            family=6, subtype=0x33, key_hex=hx(key), value_hex=hx(val),
            body_hex=hx(body), digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}", notes=notes)
        c_pos += 1

    def add_cs_neg_body(vid, body, notes=""):
        nonlocal c_neg
        add(id=vid, suite="DSB3", op="body_decode", expected_status="CORRUPT",
            family=6, subtype=0x33, body_hex=hx(body), notes=notes)
        c_neg += 1

    def add_cs_neg_typed(vid, key, val, notes=""):
        nonlocal c_neg
        add(id=vid, suite="DSB3", op="typed_record", expected_status="CORRUPT",
            family=6, subtype=0x33, key_hex=hx(key), value_hex=hx(val),
            notes=notes)
        c_neg += 1

    # --- 7 legal matrix rows (+ PENDING gate/timeout variants) ---
    # Shape 1 TX NONE
    body_tx_none = enc_cancel_body(
        owner_kind=CS_TX, cancel_state=ST_NONE, cancel_kind=CK_NONE,
        reason=0, effect=E_NONE, gate=GATE_NEVER)
    assert len(body_tx_none) == 162
    add_cs_pos("DSB3_CS_TX_NONE", body_tx_none, "shape1 TX NONE zero pair")
    k, v, b = cancel_typed(body=body_tx_none)
    add_cs_typed("DSB3_CS_TX_NONE_TYPED", k, v, b, "typed TX NONE")

    # Shape 1 DLV NONE
    body_dlv_none = enc_cancel_body(
        owner_kind=CS_DLV, owner_raw=dlv_raw, cancel_state=ST_NONE,
        cancel_kind=CK_NONE, reason=0, effect=E_NONE, gate=GATE_NEVER)
    assert len(body_dlv_none) == 226
    add_cs_pos("DSB3_CS_DLV_NONE", body_dlv_none, "shape1 DLV NONE zero pair")
    k, v, b = cancel_typed(owner_kind=CS_DLV, owner_raw=dlv_raw, body=body_dlv_none)
    add_cs_typed("DSB3_CS_DLV_NONE_TYPED", k, v, b, "typed DLV NONE")

    # Shape 2 TX PENDING variants
    body_tx_pend_never = enc_cancel_body(
        cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND, effect=E_NONE,
        gate=GATE_NEVER, cancel_attempt=cancel_attempt_id, semantic=cancel_semantic)
    add_cs_pos("DSB3_CS_TX_PEND_NEVER", body_tx_pend_never,
               "shape2 TX PENDING NEVER timeout0")
    body_tx_pend_retry = enc_cancel_body(
        cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND, effect=E_NONE,
        gate=GATE_RETRY, cancel_attempt=cancel_attempt_id, semantic=cancel_semantic)
    add_cs_pos("DSB3_CS_TX_PEND_RETRY", body_tx_pend_retry,
               "shape2 TX PENDING RETRYABLE timeout0")
    body_tx_pend_closed0 = enc_cancel_body(
        cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND, effect=E_NONE,
        gate=GATE_CLOSED, cancel_attempt=cancel_attempt_id, semantic=cancel_semantic)
    add_cs_pos("DSB3_CS_TX_PEND_CLOSED_T0", body_tx_pend_closed0,
               "shape2 TX PENDING CLOSED zero timeout (pre-send crash/denial)")
    body_tx_pend_closed_to = enc_cancel_body(
        cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND, effect=E_NONE,
        gate=GATE_CLOSED, cancel_attempt=cancel_attempt_id, semantic=cancel_semantic,
        timeout_epoch=cancel_timeout_ep, timeout_at=9000)
    add_cs_pos("DSB3_CS_TX_PEND_CLOSED_ACTIVE", body_tx_pend_closed_to,
               "shape2 TX PENDING CLOSED active timeout pair")
    k, v, b = cancel_typed(body=body_tx_pend_never)
    add_cs_typed("DSB3_CS_TX_PEND_TYPED", k, v, b)

    # Shape 3 TX FENCED local (zero pair)
    body_tx_fenced_local = enc_cancel_body(
        cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
        effect=E_NO_EFFECT, gate=GATE_NEVER)
    add_cs_pos("DSB3_CS_TX_FENCED_LOCAL", body_tx_fenced_local,
               "shape3 TX FENCED local pre-dispatch zero pair")

    # Shape 4 TX FENCED remote result
    body_tx_fenced_remote = enc_cancel_body(
        cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
        effect=E_NO_EFFECT, gate=GATE_CLOSED,
        cancel_attempt=cancel_attempt_id, semantic=cancel_semantic)
    add_cs_pos("DSB3_CS_TX_FENCED_REMOTE", body_tx_fenced_remote,
               "shape4 TX FENCED remote result NZ pair CLOSED")
    k, v, b = cancel_typed(body=body_tx_fenced_remote)
    add_cs_typed("DSB3_CS_TX_FENCED_REMOTE_TYPED", k, v, b)

    # Shape 5 DLV FENCED
    body_dlv_fenced = enc_cancel_body(
        owner_kind=CS_DLV, owner_raw=dlv_raw,
        cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
        effect=E_NO_EFFECT, gate=GATE_NEVER,
        cancel_attempt=cancel_attempt_id, semantic=cancel_semantic)
    add_cs_pos("DSB3_CS_DLV_FENCED", body_dlv_fenced, "shape5 DLV FENCED")
    k, v, b = cancel_typed(
        owner_kind=CS_DLV, owner_raw=dlv_raw, body=body_dlv_fenced)
    add_cs_typed("DSB3_CS_DLV_FENCED_TYPED", k, v, b)

    # Shape 6 TX TOO_LATE
    body_tx_too_late = enc_cancel_body(
        cancel_state=ST_TOO_LATE, cancel_kind=CK_TOO_LATE, reason=R_TOO_LATE,
        effect=E_POSSIBLE, gate=GATE_CLOSED,
        cancel_attempt=cancel_attempt_id, semantic=cancel_semantic)
    add_cs_pos("DSB3_CS_TX_TOO_LATE", body_tx_too_late, "shape6 TX TOO_LATE")
    k, v, b = cancel_typed(body=body_tx_too_late, rev=2)
    add_cs_typed("DSB3_CS_TX_TOO_LATE_REV2", k, v, b, "revision>=1 allowed")

    # Shape 7 DLV TOO_LATE
    body_dlv_too_late = enc_cancel_body(
        owner_kind=CS_DLV, owner_raw=dlv_raw,
        cancel_state=ST_TOO_LATE, cancel_kind=CK_TOO_LATE, reason=R_TOO_LATE,
        effect=E_POSSIBLE, gate=GATE_NEVER,
        cancel_attempt=cancel_attempt_id, semantic=cancel_semantic)
    add_cs_pos("DSB3_CS_DLV_TOO_LATE", body_dlv_too_late, "shape7 DLV TOO_LATE")
    k, v, b = cancel_typed(
        owner_kind=CS_DLV, owner_raw=dlv_raw, body=body_dlv_too_late)
    add_cs_typed("DSB3_CS_DLV_TOO_LATE_TYPED", k, v, b)

    # mutation: flip reserved in positive body → corrupt
    mut_body = bytearray(body_tx_none)
    mut_body[2] ^= 0x01
    add(id="DSB3_CS_MUT_RESERVED", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x33,
        body_hex=hx(bytes(mut_body)), notes="reserved flip")
    c_mut += 1
    c_neg += 1

    # --- bijection mismatches / ALREADY_TERMINAL ---
    add_cs_neg_body(
        "DSB3_CS_BIJ_NONE_KIND1",
        enc_cancel_body(cancel_state=ST_NONE, cancel_kind=CK_FENCED,
                        reason=0, effect=E_NONE, gate=GATE_NEVER),
        "NONE bijection: kind must be 0")
    add_cs_neg_body(
        "DSB3_CS_BIJ_PEND_KIND1",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_FENCED, reason=R_PEND,
            effect=E_NONE, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "PENDING bijection: kind must be 2")
    add_cs_neg_body(
        "DSB3_CS_BIJ_PEND_REASON82",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_FENCED,
            effect=E_NONE, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "PENDING bijection: reason must be 86")
    add_cs_neg_body(
        "DSB3_CS_BIJ_PEND_EFFECT1",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NO_EFFECT, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "PENDING bijection: effect must be 0")
    add_cs_neg_body(
        "DSB3_CS_BIJ_FENCED_KIND2",
        enc_cancel_body(
            cancel_state=ST_FENCED, cancel_kind=CK_PEND, reason=R_FENCED,
            effect=E_NO_EFFECT, gate=GATE_NEVER),
        "FENCED bijection: kind must be 1")
    add_cs_neg_body(
        "DSB3_CS_BIJ_FENCED_REASON86",
        enc_cancel_body(
            cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_PEND,
            effect=E_NO_EFFECT, gate=GATE_NEVER),
        "FENCED bijection: reason must be 82")
    add_cs_neg_body(
        "DSB3_CS_BIJ_FENCED_EFFECT0",
        enc_cancel_body(
            cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
            effect=E_NONE, gate=GATE_NEVER),
        "FENCED bijection: effect must be 1")
    add_cs_neg_body(
        "DSB3_CS_BIJ_TOO_LATE_KIND1",
        enc_cancel_body(
            cancel_state=ST_TOO_LATE, cancel_kind=CK_FENCED, reason=R_TOO_LATE,
            effect=E_POSSIBLE, gate=GATE_CLOSED,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "TOO_LATE bijection: kind must be 3")
    add_cs_neg_body(
        "DSB3_CS_BIJ_TOO_LATE_REASON82",
        enc_cancel_body(
            cancel_state=ST_TOO_LATE, cancel_kind=CK_TOO_LATE, reason=R_FENCED,
            effect=E_POSSIBLE, gate=GATE_CLOSED,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "TOO_LATE bijection: reason must be 83")
    add_cs_neg_body(
        "DSB3_CS_BIJ_TOO_LATE_EFFECT1",
        enc_cancel_body(
            cancel_state=ST_TOO_LATE, cancel_kind=CK_TOO_LATE, reason=R_TOO_LATE,
            effect=E_NO_EFFECT, gate=GATE_CLOSED,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "TOO_LATE bijection: effect must be 2")
    add_cs_neg_body(
        "DSB3_CS_ALREADY_TERMINAL",
        enc_cancel_body(
            cancel_state=ST_NONE, cancel_kind=CK_ALREADY, reason=0, effect=E_NONE,
            gate=GATE_NEVER),
        "ALREADY_TERMINAL kind=4 never stored")
    # ALREADY with a non-NONE state that might otherwise look legal
    add_cs_neg_body(
        "DSB3_CS_ALREADY_ON_FENCED",
        enc_cancel_body(
            cancel_state=ST_FENCED, cancel_kind=CK_ALREADY, reason=R_FENCED,
            effect=E_NO_EFFECT, gate=GATE_NEVER),
        "ALREADY_TERMINAL not a legal stored kind for FENCED")

    # --- illegal owner / state / gate / attempt / digest / timeout shapes ---
    add_cs_neg_body(
        "DSB3_CS_OWNER0",
        enc_cancel_body(owner_kind=0),
        "cancel_owner_kind 0 unknown")
    add_cs_neg_body(
        "DSB3_CS_OWNER3",
        enc_cancel_body(
            owner_kind=3, owner_raw=txn,
            primary_kd=complete_key_digest_id128(0x20, txn)),
        "cancel_owner_kind 3 unknown")
    add_cs_neg_body(
        "DSB3_CS_STATE0",
        enc_cancel_body(cancel_state=0, cancel_kind=0, reason=0, effect=0,
                        gate=GATE_NEVER),
        "cancel_state 0 unknown")
    add_cs_neg_body(
        "DSB3_CS_STATE5",
        enc_cancel_body(cancel_state=5, cancel_kind=0, reason=0, effect=0,
                        gate=GATE_NEVER),
        "cancel_state 5 unknown")
    add_cs_neg_body(
        "DSB3_CS_GATE0",
        enc_cancel_body(gate=0),
        "gate 0 unknown")
    add_cs_neg_body(
        "DSB3_CS_GATE4",
        enc_cancel_body(gate=4),
        "gate 4 unknown")
    # DLV PENDING illegal
    add_cs_neg_body(
        "DSB3_CS_DLV_PENDING",
        enc_cancel_body(
            owner_kind=CS_DLV, owner_raw=dlv_raw,
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NONE, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "DLV PENDING illegal")
    # DLV gate must always be NEVER
    add_cs_neg_body(
        "DSB3_CS_DLV_GATE_CLOSED",
        enc_cancel_body(
            owner_kind=CS_DLV, owner_raw=dlv_raw,
            cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
            effect=E_NO_EFFECT, gate=GATE_CLOSED,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "DLV gate always NEVER")
    add_cs_neg_body(
        "DSB3_CS_DLV_GATE_RETRY",
        enc_cancel_body(
            owner_kind=CS_DLV, owner_raw=dlv_raw,
            cancel_state=ST_TOO_LATE, cancel_kind=CK_TOO_LATE, reason=R_TOO_LATE,
            effect=E_POSSIBLE, gate=GATE_RETRY,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "DLV gate RETRYABLE illegal")
    # NONE with NZ attempt
    add_cs_neg_body(
        "DSB3_CS_NONE_NZ_ATTEMPT",
        enc_cancel_body(
            cancel_state=ST_NONE, cancel_kind=CK_NONE, reason=0, effect=0,
            gate=GATE_NEVER, cancel_attempt=cancel_attempt_id,
            semantic=cancel_semantic),
        "NONE requires zero attempt/digest pair")
    # PENDING with zero pair
    add_cs_neg_body(
        "DSB3_CS_PEND_ZERO_PAIR",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NONE, gate=GATE_NEVER),
        "PENDING requires NZ attempt/digest pair")
    # attempt NZ / digest zero mismatch
    add_cs_neg_body(
        "DSB3_CS_ATTEMPT_DIGEST_MISMATCH",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NONE, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=bytes(32)),
        "attempt NZ but digest zero illegal")
    # digest NZ / attempt zero mismatch
    add_cs_neg_body(
        "DSB3_CS_DIGEST_ATTEMPT_MISMATCH",
        enc_cancel_body(
            cancel_state=ST_NONE, cancel_kind=CK_NONE, reason=0, effect=0,
            gate=GATE_NEVER, semantic=cancel_semantic),
        "digest NZ but attempt zero illegal")
    # TX PENDING NEVER with active timeout
    add_cs_neg_body(
        "DSB3_CS_PEND_NEVER_TIMEOUT",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NONE, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic,
            timeout_epoch=cancel_timeout_ep, timeout_at=1),
        "PENDING NEVER requires timeout0")
    # TX PENDING RETRY with active timeout
    add_cs_neg_body(
        "DSB3_CS_PEND_RETRY_TIMEOUT",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NONE, gate=GATE_RETRY,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic,
            timeout_epoch=cancel_timeout_ep, timeout_at=2),
        "PENDING RETRYABLE requires timeout0")
    # TX FENCED local with CLOSED gate
    add_cs_neg_body(
        "DSB3_CS_TX_FENCED_LOCAL_CLOSED",
        enc_cancel_body(
            cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
            effect=E_NO_EFFECT, gate=GATE_CLOSED),
        "TX FENCED zero pair requires NEVER not CLOSED")
    # TX FENCED remote with NEVER
    add_cs_neg_body(
        "DSB3_CS_TX_FENCED_REMOTE_NEVER",
        enc_cancel_body(
            cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
            effect=E_NO_EFFECT, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "TX FENCED NZ pair requires CLOSED")
    # TX TOO_LATE with NEVER
    add_cs_neg_body(
        "DSB3_CS_TX_TOO_LATE_NEVER",
        enc_cancel_body(
            cancel_state=ST_TOO_LATE, cancel_kind=CK_TOO_LATE, reason=R_TOO_LATE,
            effect=E_POSSIBLE, gate=GATE_NEVER,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic),
        "TX TOO_LATE requires CLOSED")
    # TX TOO_LATE zero pair
    add_cs_neg_body(
        "DSB3_CS_TX_TOO_LATE_ZERO",
        enc_cancel_body(
            cancel_state=ST_TOO_LATE, cancel_kind=CK_TOO_LATE, reason=R_TOO_LATE,
            effect=E_POSSIBLE, gate=GATE_CLOSED),
        "TX TOO_LATE requires NZ pair")
    # DLV FENCED zero pair
    add_cs_neg_body(
        "DSB3_CS_DLV_FENCED_ZERO",
        enc_cancel_body(
            owner_kind=CS_DLV, owner_raw=dlv_raw,
            cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
            effect=E_NO_EFFECT, gate=GATE_NEVER),
        "DLV FENCED requires NZ pair")
    # malformed timeout (epoch NZ, at=0)
    add_cs_neg_body(
        "DSB3_CS_TIMEOUT_EPOCH_ONLY",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NONE, gate=GATE_CLOSED,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic,
            timeout_epoch=cancel_timeout_ep, timeout_at=0),
        "timeout epoch NZ requires at_ms NZ")
    # malformed timeout (epoch 0, at NZ)
    add_cs_neg_body(
        "DSB3_CS_TIMEOUT_AT_ONLY",
        enc_cancel_body(
            cancel_state=ST_PEND, cancel_kind=CK_PEND, reason=R_PEND,
            effect=E_NONE, gate=GATE_CLOSED,
            cancel_attempt=cancel_attempt_id, semantic=cancel_semantic,
            timeout_epoch=bytes(16), timeout_at=5),
        "timeout at_ms NZ requires epoch NZ")
    # NONE with non-NEVER gate
    add_cs_neg_body(
        "DSB3_CS_NONE_GATE_CLOSED",
        enc_cancel_body(gate=GATE_CLOSED),
        "NONE requires NEVER gate")
    # TX FENCED local with timeout
    add_cs_neg_body(
        "DSB3_CS_TX_FENCED_LOCAL_TIMEOUT",
        enc_cancel_body(
            cancel_state=ST_FENCED, cancel_kind=CK_FENCED, reason=R_FENCED,
            effect=E_NO_EFFECT, gate=GATE_NEVER,
            timeout_epoch=cancel_timeout_ep, timeout_at=3),
        "TX FENCED local requires timeout0")

    # --- raw / txn / primary_key_digest ---
    add_cs_neg_body(
        "DSB3_CS_ZERO_TXN",
        enc_cancel_body(transaction_id=bytes(16), owner_raw=bytes(16),
                        primary_kd=complete_key_digest_id128(0x20, bytes(16))),
        "transaction_id must be non-zero")
    add_cs_neg_body(
        "DSB3_CS_TX_RAW_MISMATCH",
        enc_cancel_body(owner_raw=bytes([0xEE] * 16)),
        "TX raw must equal transaction_id")
    add_cs_neg_body(
        "DSB3_CS_DLV_TXN_COMPONENT",
        enc_cancel_body(
            owner_kind=CS_DLV,
            owner_raw=dlv_raw[:32] + bytes([0xFF] * 16) + dlv_raw[48:],
            cancel_state=ST_NONE, cancel_kind=CK_NONE, reason=0, effect=0,
            gate=GATE_NEVER),
        "DLV raw [32,48) must equal transaction_id")
    add_cs_neg_body(
        "DSB3_CS_PKD_ZERO",
        enc_cancel_body(primary_kd=bytes(32)),
        "primary_key_digest must be non-zero complete KEY_DIGEST")
    add_cs_neg_body(
        "DSB3_CS_PKD_WRONG",
        enc_cancel_body(primary_kd=bytes([0xAB] * 32)),
        "primary_key_digest must equal KEY_DIGEST of complete primary key")
    add_cs_neg_body(
        "DSB3_CS_PKD_BARE_COMPOSITE",
        enc_cancel_body(
            owner_kind=CS_DLV, owner_raw=dlv_raw,
            primary_kd=composite(0x40, raw16(dlv_raw))),
        "bare composite identity is not KEY_DIGEST(complete DELIVERY key)")
    add_cs_neg_body(
        "DSB3_CS_RESERVED_NZ",
        enc_cancel_body(reserved=1),
        "reserved must be 0")
    # wrong raw length encoded as TX with 80 bytes
    bad_tx_len = bytearray()
    bad_tx_len += be16(CS_TX) + be16(0) + raw16(dlv_raw)
    bad_tx_len += cancel_primary_key_digest(CS_TX, txn)
    bad_tx_len += txn + bytes(16)
    bad_tx_len += be32(ST_NONE) + be32(0) + be32(0) + be32(0) + be32(GATE_NEVER)
    bad_tx_len += bytes(32) + bytes(16) + be64(0)
    add_cs_neg_body(
        "DSB3_CS_TX_RAW_LEN80",
        bytes(bad_tx_len),
        "TX owner_key_raw must be exact 16")
    # short / trailing / BTS
    add(id="DSB3_CS_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x33,
        body_hex=hx(body_tx_none[:-1]), notes="short body")
    c_neg += 1
    add(id="DSB3_CS_TRAILING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x33,
        body_hex=hx(body_tx_none + b"\x00"), notes="trailing byte")
    c_neg += 1
    add(id="DSB3_CS_BTS", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x33,
        body_length=len(body_tx_none), body_hex=hx(body_tx_none),
        key_length=0)
    c_neg += 1

    # --- typed negatives: key / primary / header ---
    _, val_ok, _ = cancel_typed(body=body_tx_none)
    bad_key = cancel_key(CS_DLV, dlv_raw)
    add_cs_neg_typed(
        "DSB3_CS_KEY_MISMATCH", bad_key, val_ok,
        "key COMPOSITE must match body owner")
    wrong_kind_key = bkey(6, 0x33, 2, txn)
    add_cs_neg_typed(
        "DSB3_CS_WRONG_KIND", wrong_kind_key, val_ok,
        "key must be SHA256_COMPOSITE not ID128")
    k_wp, v_wp, _ = cancel_typed(body=body_tx_none, primary=bytes([0xDD] * 16))
    add_cs_neg_typed("DSB3_CS_BAD_PRIMARY", k_wp, v_wp, "wrong primary_id")
    k_zp, v_zp, _ = cancel_typed(body=body_tx_none, primary=bytes(16))
    add_cs_neg_typed("DSB3_CS_ZERO_PRIMARY", k_zp, v_zp, "zero primary_id")
    # self-key primary (composite identity first 16 instead of txn)
    self_pid = composite(0x33, cancel_key_components(CS_TX, txn))[:16]
    k_sk, v_sk, _ = cancel_typed(body=body_tx_none, primary=self_pid)
    add_cs_neg_typed(
        "DSB3_CS_SELF_KEY_PRIMARY", k_sk, v_sk,
        "primary_id must be transaction_id not self composite")
    k_zh, v_zh, _ = cancel_typed(body=body_tx_none, head=bytes(32))
    add_cs_neg_typed("DSB3_CS_ZERO_HEAD", k_zh, v_zh)
    k_zv, v_zv, _ = cancel_typed(body=body_tx_none, pvd=bytes(32))
    add_cs_neg_typed("DSB3_CS_ZERO_PVD", k_zv, v_zv)
    k_fl = cancel_key(CS_TX, txn)
    v_fl = enc_env_full(
        6, 0x33, 1, 1, txn, cancel_head, cancel_pvd, body_tx_none)
    add_cs_neg_typed("DSB3_CS_FLAGS_NZ", k_fl, v_fl, "flags must be 0")
    k_r0, v_r0, _ = cancel_typed(body=body_tx_none, rev=0)
    add_cs_neg_typed("DSB3_CS_REV0", k_r0, v_r0, "revision must be >=1")

    b3_cov["33"] = add_body_suite(
        "CANCEL_STATE", 6, 0x33, c_pos, c_neg, c_mut, c_rt)
    assert b3_cov["33"]["positive"] >= 14
    assert b3_cov["33"]["negative"] >= 30
    assert b3_cov["33"]["roundtrip"] >= 7

    # =====================================================================
    # D1-B3g EVIDENCE_CELL (0x32) — after CANCEL_STATE; preserve first 898
    # =====================================================================
    def vectors_fingerprint(vec_list):
        return hashlib.sha256(
            json.dumps(vec_list, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()

    PRE_B3G_VECTOR_COUNT = 898
    # Re-pinned at D1-B3i: kind9/10 42-byte identity correction.
    PRE_B3G_FULL_FINGERPRINT = (
        "5239009b9dc4bd270e735af8a85fb152cb0690a6ab590277468412491d448d3e"
    )
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[-1]["id"] == "DSB3_CS_REV0"
    assert len(vectors) == PRE_B3G_VECTOR_COUNT
    _pre_b3g_fp = vectors_fingerprint(vectors)
    assert _pre_b3g_fp == PRE_B3G_FULL_FINGERPRINT, (
        f"pre-B3g full fingerprint drift: got {_pre_b3g_fp}"
    )
    PRE_B3G_VECTOR_COUNT_SNAPSHOT = len(vectors)

    # Private EVIDENCE_CELL enums / material constants.
    EV_TX = 1
    EV_DLV = 2
    CK_SUM = 1
    CK_RAW = 2
    ST_UNUSED = 1
    ST_MAT = 2
    STAGE_RECV = 1
    STAGE_DUR = 2
    STAGE_APP = 3
    STAGE_VER = 4
    TRUST_T = 1
    TRUST_U = 2
    FAM_EF = 1
    FAM_DS = 2
    U64_MAX = (1 << 64) - 1
    empty_sha = sha256(b"")
    assert empty_sha == bytes.fromhex(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    target_dig = bytes([0x61 + (i % 120) for i in range(32)])
    content_dig = bytes([0x81 + (i % 100) for i in range(32)])
    ev_epoch = bytes([0x21 + (i % 16) for i in range(16)])
    ev_bytes_max = bytes([(i * 7 + 3) & 0xFF for i in range(128)])
    ev_head = F["head_nz"]
    ev_pvd = bytes([0x91 + (i % 150) for i in range(32)])
    assert not all(b == 0 for b in target_dig)
    assert not all(b == 0 for b in content_dig)
    assert not all(b == 0 for b in ev_epoch)
    assert not all(b == 0 for b in ev_pvd)
    assert len(PARTY) == 100 and len(txn) == 16 and len(dlv_raw) == 80

    def svc_id(ns, svc, schema, rev, dig, major, minor, family):
        return service_identity(ns, svc, schema, rev, dig, major, minor, family)

    SVC_MIN = svc_id(b"a", b"b", b"c", 1, F["dig"], 1, 0, FAM_EF)
    SVC_MAX = svc_id(b"n" * 63, b"s" * 63, b"c" * 63, 1, F["dig"], 1, 0, FAM_DS)
    SVC_EF = svc_id(F["ns"], F["svc"], F["schema"], 1, F["dig"], 1, 0, FAM_EF)
    SVC_DS = svc_id(F["ns"], F["svc"], F["schema"], 1, F["dig"], 1, 0, FAM_DS)
    assert 54 <= len(SVC_MIN) <= 240 and len(SVC_MAX) == 240
    assert len(SVC_EF) <= 240 and len(SVC_DS) <= 240

    def service_slot(svc_wire: bytes) -> bytes:
        assert 54 <= len(svc_wire) <= 240
        return svc_wire + bytes(240 - len(svc_wire))

    def evidence_primary_key_digest(owner_kind: int, owner_raw: bytes) -> bytes:
        if owner_kind == EV_TX:
            return complete_key_digest_id128(0x20, owner_raw)
        if owner_kind == EV_DLV:
            return complete_key_digest_composite(0x40, raw16(owner_raw))
        raise ValueError("bad evidence owner")

    def evidence_primary_id(owner_kind: int, owner_raw: bytes) -> bytes:
        if owner_kind == EV_TX:
            return owner_raw
        if owner_kind == EV_DLV:
            return primary_id_from_composite_subtype(0x40, raw16(owner_raw))
        raise ValueError("bad evidence owner")

    def evidence_key_components(owner_kind: int, owner_raw: bytes, slot: int) -> bytes:
        return be16(owner_kind) + raw16(owner_raw) + be32(slot)

    def evidence_key(owner_kind: int, owner_raw: bytes, slot: int) -> bytes:
        return bkey(6, 0x32, 5, composite(
            0x32, evidence_key_components(owner_kind, owner_raw, slot)))

    def enc_evidence_body(
        owner_kind=EV_TX,
        owner_raw=None,
        cell_kind=CK_SUM,
        cell_state=ST_MAT,
        slot=0,
        primary_kd=None,
        target=None,
        reserved0=0,
        highest=0,
        latest=0,
        material_stage=0,
        disposition=0,
        effect=0,
        late_material=0,
        issuer=None,
        svc_wire=None,
        content=None,
        generation=0,
        sequence=0,
        epoch=None,
        at_ms=0,
        trust=0,
        counter_sat=0,
        evidence_digest=None,
        evidence_length=0,
        evidence_bytes=None,
        reserved1=0,
        valid_count=0,
        exact_dup=0,
        raw_overflow=0,
        late_count=0,
        force_service_slot=None,
    ) -> bytes:
        if owner_raw is None:
            owner_raw = txn if owner_kind == EV_TX else dlv_raw
        if primary_kd is None:
            if owner_kind in (EV_TX, EV_DLV):
                primary_kd = evidence_primary_key_digest(owner_kind, owner_raw)
            else:
                primary_kd = complete_key_digest_id128(0x20, txn)
        if target is None:
            target = target_dig
        if issuer is None:
            issuer = bytes(100)
        if epoch is None:
            epoch = bytes(16)
        if content is None:
            content = bytes(32)
        if evidence_bytes is None:
            evidence_bytes = bytes(128)
        assert len(issuer) == 100
        assert len(evidence_bytes) == 128
        if force_service_slot is not None:
            slot_bytes = force_service_slot
            assert len(slot_bytes) == 240
        elif svc_wire is None:
            slot_bytes = bytes(240)
        else:
            slot_bytes = service_slot(svc_wire)
        if evidence_digest is None:
            # Empty/inactive identity-only shapes store zero digest.
            # Active material always recomputes SHA-256(bytes[0,length)),
            # including length 0 → SHA-256(empty) nonzero.
            is_empty_shape = (
                (cell_kind == CK_SUM and cell_state == ST_MAT
                 and valid_count == 0)
                or (cell_kind == CK_RAW and cell_state == ST_UNUSED)
            )
            if is_empty_shape:
                evidence_digest = bytes(32)
            else:
                evidence_digest = sha256(evidence_bytes[:evidence_length])
        out = bytearray()
        out += be16(owner_kind)
        out += be16(cell_kind)
        out += raw16(owner_raw)
        out += primary_kd
        out += target
        out += be32(slot)
        out += be16(cell_state)
        out += be16(reserved0)
        out += be32(highest)
        out += be32(latest)
        out += be32(material_stage)
        out += be32(disposition)
        out += be32(effect)
        out += be32(late_material)
        out += issuer
        out += slot_bytes
        out += content
        out += be64(generation)
        out += be64(sequence)
        out += epoch
        out += be64(at_ms)
        out += be32(trust)
        out += be32(counter_sat)
        out += evidence_digest
        out += be16(evidence_length)
        out += be16(reserved1)
        out += evidence_bytes
        out += be64(valid_count)
        out += be64(exact_dup)
        out += be64(raw_overflow)
        out += be64(late_count)
        expected = 718 + len(owner_raw)
        assert len(out) == expected, f"evidence body len {len(out)} != {expected}"
        return bytes(out)

    def material_kwargs(
        stage=STAGE_RECV,
        late_material=0,
        late_count=0,
        valid_count=1,
        exact_dup=0,
        raw_overflow=0,
        counter_sat=0,
        family=FAM_EF,
        generation=None,
        sequence=7,
        trust=TRUST_T,
        at_ms=0,
        evidence_length=0,
        evidence_bytes=None,
        svc=None,
        issuer=None,
        content=None,
    ):
        if generation is None:
            generation = 0 if family == FAM_EF else 1
        if svc is None:
            svc = SVC_EF if family == FAM_EF else SVC_DS
        if issuer is None:
            issuer = PARTY
        if content is None:
            content = content_dig
        if evidence_bytes is None:
            if evidence_length == 0:
                evidence_bytes = bytes(128)
            elif evidence_length == 128:
                evidence_bytes = ev_bytes_max
            else:
                evidence_bytes = ev_bytes_max[:evidence_length] + bytes(
                    128 - evidence_length)
        return dict(
            highest=stage,
            latest=stage,
            material_stage=stage,
            late_material=late_material,
            issuer=issuer,
            svc_wire=svc,
            content=content,
            generation=generation,
            sequence=sequence,
            epoch=ev_epoch,
            at_ms=at_ms,
            trust=trust,
            counter_sat=counter_sat,
            evidence_length=evidence_length,
            evidence_bytes=evidence_bytes,
            valid_count=valid_count,
            exact_dup=exact_dup,
            raw_overflow=raw_overflow,
            late_count=late_count,
        )

    def evidence_typed(
        owner_kind=EV_TX,
        owner_raw=None,
        slot=0,
        rev=1,
        head=None,
        pvd=None,
        primary=None,
        body=None,
        **kwargs,
    ):
        if owner_raw is None:
            owner_raw = txn if owner_kind == EV_TX else dlv_raw
        if head is None:
            head = ev_head
        if pvd is None:
            pvd = ev_pvd
        if body is None:
            body = enc_evidence_body(
                owner_kind=owner_kind, owner_raw=owner_raw, slot=slot, **kwargs)
        if primary is None:
            primary = evidence_primary_id(owner_kind, owner_raw)
        key = evidence_key(owner_kind, owner_raw, slot)
        val = enc_env_full(6, 0x32, 0, rev, primary, head, pvd, body)
        return key, val, body

    e_pos = 0
    e_neg = 0
    e_mut = 0
    e_rt = 0

    def add_ev_pos(vid, body, notes=""):
        nonlocal e_pos, e_rt
        add(id=vid, suite="DSB3", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x32, body_length=len(body), body_hex=hx(body),
            notes=notes)
        e_pos += 1
        e_rt += 1

    def add_ev_typed(vid, key, val, body, notes=""):
        nonlocal e_pos
        add(id=vid, suite="DSB3", op="typed_record", expected_status="OK",
            family=6, subtype=0x32, key_hex=hx(key), value_hex=hx(val),
            body_hex=hx(body), digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}", notes=notes)
        e_pos += 1

    def add_ev_neg_body(vid, body, notes=""):
        nonlocal e_neg
        add(id=vid, suite="DSB3", op="body_decode", expected_status="CORRUPT",
            family=6, subtype=0x32, body_hex=hx(body), notes=notes)
        e_neg += 1

    def add_ev_neg_typed(vid, key, val, notes=""):
        nonlocal e_neg
        add(id=vid, suite="DSB3", op="typed_record", expected_status="CORRUPT",
            family=6, subtype=0x32, key_hex=hx(key), value_hex=hx(val),
            notes=notes)
        e_neg += 1

    # --- positives: TX/DLV, summary empty/material, raw unused/material ---
    body_tx_sum_empty = enc_evidence_body(
        owner_kind=EV_TX, cell_kind=CK_SUM, cell_state=ST_MAT, slot=0)
    assert len(body_tx_sum_empty) == 734
    add_ev_pos("DSB3_EV_TX_SUM_EMPTY", body_tx_sum_empty, "SUMMARY empty TX 734")
    k, v, b = evidence_typed(body=body_tx_sum_empty)
    add_ev_typed("DSB3_EV_TX_SUM_EMPTY_TYPED", k, v, b)

    body_dlv_sum_empty = enc_evidence_body(
        owner_kind=EV_DLV, owner_raw=dlv_raw, cell_kind=CK_SUM,
        cell_state=ST_MAT, slot=0)
    assert len(body_dlv_sum_empty) == 798
    add_ev_pos("DSB3_EV_DLV_SUM_EMPTY", body_dlv_sum_empty, "SUMMARY empty DLV 798")
    k, v, b = evidence_typed(
        owner_kind=EV_DLV, owner_raw=dlv_raw, body=body_dlv_sum_empty)
    add_ev_typed("DSB3_EV_DLV_SUM_EMPTY_TYPED", k, v, b)

    body_tx_raw_unused = enc_evidence_body(
        cell_kind=CK_RAW, cell_state=ST_UNUSED, slot=1)
    add_ev_pos("DSB3_EV_TX_RAW_UNUSED", body_tx_raw_unused, "RAW UNUSED slot1")
    k, v, b = evidence_typed(slot=1, body=body_tx_raw_unused)
    add_ev_typed("DSB3_EV_TX_RAW_UNUSED_TYPED", k, v, b)

    body_tx_sum_mat0 = enc_evidence_body(
        cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
        **material_kwargs(evidence_length=0))
    # length 0 still stores SHA256(empty) nonzero
    assert not all(x == 0 for x in sha256(b""))
    add_ev_pos("DSB3_EV_TX_SUM_MAT_LEN0", body_tx_sum_mat0,
               "SUMMARY material evidence_length 0 digest=SHA256(empty)")
    k, v, b = evidence_typed(body=body_tx_sum_mat0)
    add_ev_typed("DSB3_EV_TX_SUM_MAT_LEN0_TYPED", k, v, b)

    body_tx_sum_mat_max = enc_evidence_body(
        cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
        **material_kwargs(
            stage=STAGE_VER, evidence_length=128, late_material=1,
            late_count=1, valid_count=3, exact_dup=1, raw_overflow=1))
    add_ev_pos("DSB3_EV_TX_SUM_MAT_MAX", body_tx_sum_mat_max,
               "SUMMARY material max evidence + counters")

    body_tx_sum_mat_ds = enc_evidence_body(
        cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
        **material_kwargs(family=FAM_DS, generation=2, stage=STAGE_APP))
    add_ev_pos("DSB3_EV_TX_SUM_MAT_DS", body_tx_sum_mat_ds,
               "SUMMARY material DesiredState generation>=1")

    body_tx_raw_mat = enc_evidence_body(
        cell_kind=CK_RAW, cell_state=ST_MAT, slot=3,
        highest=0, latest=0, material_stage=STAGE_DUR,
        late_material=1, issuer=PARTY, svc_wire=SVC_EF, content=content_dig,
        generation=0, sequence=9, epoch=ev_epoch, at_ms=100, trust=TRUST_U,
        evidence_length=5,
        evidence_bytes=ev_bytes_max[:5] + bytes(123))
    add_ev_pos("DSB3_EV_TX_RAW_MAT", body_tx_raw_mat, "RAW MATERIALIZED detail")
    k, v, b = evidence_typed(slot=3, body=body_tx_raw_mat)
    add_ev_typed("DSB3_EV_TX_RAW_MAT_TYPED", k, v, b)

    body_dlv_raw_mat = enc_evidence_body(
        owner_kind=EV_DLV, owner_raw=dlv_raw, cell_kind=CK_RAW,
        cell_state=ST_MAT, slot=8,
        highest=0, latest=0, material_stage=STAGE_RECV,
        late_material=0, issuer=PARTY, svc_wire=SVC_DS, content=content_dig,
        generation=4, sequence=11, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
        evidence_length=1, evidence_bytes=b"\xAB" + bytes(127))
    add_ev_pos("DSB3_EV_DLV_RAW_MAT", body_dlv_raw_mat, "DLV RAW MATERIALIZED slot8")
    k, v, b = evidence_typed(
        owner_kind=EV_DLV, owner_raw=dlv_raw, slot=8, body=body_dlv_raw_mat)
    add_ev_typed("DSB3_EV_DLV_RAW_MAT_TYPED", k, v, b)

    # service min/max pad
    body_svc_min = enc_evidence_body(
        cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
        **material_kwargs(svc=SVC_MIN, family=FAM_EF))
    add_ev_pos("DSB3_EV_SVC_MIN", body_svc_min, "service_slot min 54 + zero pad")
    body_svc_max = enc_evidence_body(
        cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
        **material_kwargs(svc=SVC_MAX, family=FAM_DS, generation=1))
    add_ev_pos("DSB3_EV_SVC_MAX", body_svc_max, "service_slot exact 240 no pad")

    # late / saturation / rev2
    body_sat = enc_evidence_body(
        cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
        **material_kwargs(
            valid_count=U64_MAX, late_count=1, late_material=1,
            counter_sat=1, exact_dup=0, raw_overflow=0))
    add_ev_pos("DSB3_EV_COUNTER_SAT", body_sat, "counter_saturated=1 with UINT64_MAX")
    k, v, b = evidence_typed(body=body_sat, rev=2)
    add_ev_typed("DSB3_EV_REV2_TYPED", k, v, b, "revision>=1 allowed (late/sat)")

    # mutation reserved
    mut_body = bytearray(body_tx_sum_empty)
    # reserved0 is after slot/state: offset = 4+2+16 +32+32+4+2 = 92 for TX
    mut_body[92] ^= 0x01
    add(id="DSB3_EV_MUT_RESERVED0", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x32,
        body_hex=hx(bytes(mut_body)), notes="reserved0 flip")
    e_mut += 1
    e_neg += 1

    # --- matrix / owner / raw / key / primary / target ---
    add_ev_neg_body(
        "DSB3_EV_MATRIX_SUM_UNUSED",
        enc_evidence_body(cell_kind=CK_SUM, cell_state=ST_UNUSED, slot=0),
        "SUMMARY+UNUSED illegal")
    add_ev_neg_body(
        "DSB3_EV_MATRIX_RAW_SLOT0",
        enc_evidence_body(cell_kind=CK_RAW, cell_state=ST_UNUSED, slot=0),
        "RAW+slot0 illegal")
    add_ev_neg_body(
        "DSB3_EV_MATRIX_SUM_SLOT1",
        enc_evidence_body(cell_kind=CK_SUM, cell_state=ST_MAT, slot=1),
        "SUMMARY requires slot 0")
    add_ev_neg_body(
        "DSB3_EV_MATRIX_RAW_SLOT9",
        enc_evidence_body(cell_kind=CK_RAW, cell_state=ST_UNUSED, slot=9),
        "slot > 8 illegal same-record")
    add_ev_neg_body(
        "DSB3_EV_OWNER0",
        enc_evidence_body(owner_kind=0),
        "evidence_owner_kind 0 unknown")
    add_ev_neg_body(
        "DSB3_EV_OWNER3",
        enc_evidence_body(
            owner_kind=3, owner_raw=txn,
            primary_kd=complete_key_digest_id128(0x20, txn)),
        "evidence_owner_kind 3 unknown")
    add_ev_neg_body(
        "DSB3_EV_KIND0",
        enc_evidence_body(cell_kind=0, cell_state=ST_MAT, slot=0),
        "cell_kind 0 unknown")
    add_ev_neg_body(
        "DSB3_EV_STATE0",
        enc_evidence_body(cell_kind=CK_RAW, cell_state=0, slot=1),
        "cell_state 0 unknown")
    add_ev_neg_body(
        "DSB3_EV_TX_RAW_LEN80",
        enc_evidence_body(
            owner_kind=EV_TX, owner_raw=dlv_raw,
            primary_kd=complete_key_digest_id128(0x20, txn)),
        "TX owner_key_raw must be exact 16")
    add_ev_neg_body(
        "DSB3_EV_ZERO_TXN_RAW",
        enc_evidence_body(
            owner_raw=bytes(16),
            primary_kd=complete_key_digest_id128(0x20, bytes(16))),
        "TX raw must be non-zero transaction ID")
    add_ev_neg_body(
        "DSB3_EV_DLV_ZERO_COMP",
        enc_evidence_body(
            owner_kind=EV_DLV,
            owner_raw=dlv_raw[:32] + bytes(16) + dlv_raw[48:]),
        "DLV raw components must be non-zero")
    add_ev_neg_body(
        "DSB3_EV_PKD_ZERO",
        enc_evidence_body(primary_kd=bytes(32)),
        "primary_key_digest must be non-zero KEY_DIGEST")
    add_ev_neg_body(
        "DSB3_EV_PKD_WRONG",
        enc_evidence_body(primary_kd=bytes([0xAB] * 32)),
        "primary_key_digest must equal KEY_DIGEST(complete primary)")
    add_ev_neg_body(
        "DSB3_EV_PKD_BARE_COMPOSITE",
        enc_evidence_body(
            owner_kind=EV_DLV, owner_raw=dlv_raw,
            primary_kd=composite(0x40, raw16(dlv_raw))),
        "bare composite is not KEY_DIGEST(complete DELIVERY key)")
    add_ev_neg_body(
        "DSB3_EV_TARGET_ZERO",
        enc_evidence_body(target=bytes(32)),
        "target_digest must be non-zero")
    add_ev_neg_body(
        "DSB3_EV_RESERVED0_NZ",
        enc_evidence_body(reserved0=1),
        "reserved0 must be 0")
    add_ev_neg_body(
        "DSB3_EV_RESERVED1_NZ",
        enc_evidence_body(reserved1=1),
        "reserved1 must be 0")

    # --- service pad / stage / disp / effect / time / trust / digest / pad ---
    bad_pad = bytearray(service_slot(SVC_EF))
    bad_pad[len(SVC_EF)] = 0x01
    add_ev_neg_body(
        "DSB3_EV_SVC_PAD_NZ",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            **material_kwargs(), force_service_slot=bytes(bad_pad)),
        "service_slot pad must be zero")
    add_ev_neg_body(
        "DSB3_EV_SVC_INACTIVE_NZ",
        enc_evidence_body(
            force_service_slot=service_slot(SVC_EF)),
        "inactive service_slot must be all-zero")
    add_ev_neg_body(
        "DSB3_EV_STAGE_TRIPLE",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            **{**material_kwargs(), "latest": STAGE_DUR}),
        "SUMMARY material stages must be equal")
    add_ev_neg_body(
        "DSB3_EV_STAGE0",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            **material_kwargs(stage=0)),
        "material stages NONE=0 illegal")
    add_ev_neg_body(
        "DSB3_EV_DISP_NZ",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            disposition=1, effect=0, late_material=0, issuer=PARTY,
            svc_wire=SVC_EF, content=content_dig, generation=0, sequence=1,
            epoch=ev_epoch, at_ms=0, trust=TRUST_T, evidence_length=0,
            valid_count=1),
        "disposition must always be 0")
    add_ev_neg_body(
        "DSB3_EV_EFFECT_NZ",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            disposition=0, effect=1, late_material=0, issuer=PARTY,
            svc_wire=SVC_EF, content=content_dig, generation=0, sequence=1,
            epoch=ev_epoch, at_ms=0, trust=TRUST_T, evidence_length=0,
            valid_count=1),
        "effect_certainty must always be 0")
    add_ev_neg_body(
        "DSB3_EV_LATE_COHERENCE",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            late_material=0, issuer=PARTY, svc_wire=SVC_EF, content=content_dig,
            generation=0, sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=2, late_count=1),
        "late_material must equal (late_evidence_count>0)")

    add_ev_neg_body(
        "DSB3_EV_TIME_EPOCH0",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=bytes(16), at_ms=1, trust=TRUST_T,
            evidence_length=0, valid_count=1),
        "evidence_clock_epoch must be non-zero when material")
    add_ev_neg_body(
        "DSB3_EV_TRUST0",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=0, evidence_length=0,
            valid_count=1),
        "evidence_trust must be 1 or 2")
    add_ev_neg_body(
        "DSB3_EV_DIGEST_WRONG",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, evidence_digest=bytes(32), valid_count=1),
        "length0 requires SHA256(empty) not zero digest")
    add_ev_neg_body(
        "DSB3_EV_DIGEST_MISMATCH",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=3,
            evidence_bytes=b"abc" + bytes(125),
            evidence_digest=sha256(b"abd"), valid_count=1),
        "evidence_digest must equal SHA256(bytes[0,length))")
    add_ev_neg_body(
        "DSB3_EV_BYTES_PAD",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=2,
            evidence_bytes=b"ab" + b"\x01" + bytes(125), valid_count=1),
        "evidence_bytes[length,128) must be zero")
    add_ev_neg_body(
        "DSB3_EV_GEN_EF_NZ",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=1,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=1),
        "EventFact generation must be 0")
    add_ev_neg_body(
        "DSB3_EV_GEN_DS_0",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_DS, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=1),
        "DesiredState generation must be >=1")
    add_ev_neg_body(
        "DSB3_EV_EMPTY_ISSUER_NZ",
        enc_evidence_body(issuer=PARTY),
        "SUMMARY empty issuer must be all-zero")
    add_ev_neg_body(
        "DSB3_EV_RAW_MAT_HIGHEST_NZ",
        enc_evidence_body(
            cell_kind=CK_RAW, cell_state=ST_MAT, slot=2,
            highest=STAGE_RECV, latest=0, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0),
        "RAW MATERIALIZED highest/latest must be 0")
    add_ev_neg_body(
        "DSB3_EV_RAW_MAT_COUNTER_NZ",
        enc_evidence_body(
            cell_kind=CK_RAW, cell_state=ST_MAT, slot=2,
            highest=0, latest=0, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=1),
        "RAW MATERIALIZED counters must be 0")
    add_ev_neg_body(
        "DSB3_EV_OVERFLOW_GT",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=1, raw_overflow=2),
        "raw_overflow_count <= valid_material_count")
    add_ev_neg_body(
        "DSB3_EV_LATE_GT",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            late_material=1, issuer=PARTY, svc_wire=SVC_EF, content=content_dig,
            generation=0, sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=1, late_count=2),
        "late_evidence_count <= valid_material_count")
    add_ev_neg_body(
        "DSB3_EV_SAT_INCOHERENT",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            counter_sat=1, evidence_length=0, valid_count=1),
        "counter_saturated=1 requires some counter UINT64_MAX")
    add_ev_neg_body(
        "DSB3_EV_SAT0_MAX",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            counter_sat=0, evidence_length=0, valid_count=U64_MAX),
        "counter_saturated=0 forbids UINT64_MAX counters")
    add_ev_neg_body(
        "DSB3_EV_CONTENT_ZERO",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=bytes(32), generation=0,
            sequence=1, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=1),
        "content_digest must be non-zero when material")
    add_ev_neg_body(
        "DSB3_EV_SEQ_ZERO",
        enc_evidence_body(
            cell_kind=CK_SUM, cell_state=ST_MAT, slot=0,
            highest=STAGE_RECV, latest=STAGE_RECV, material_stage=STAGE_RECV,
            issuer=PARTY, svc_wire=SVC_EF, content=content_dig, generation=0,
            sequence=0, epoch=ev_epoch, at_ms=0, trust=TRUST_T,
            evidence_length=0, valid_count=1),
        "durable_ingress_sequence must be non-zero when material")

    # short / trailing / BTS
    add(id="DSB3_EV_SHORT", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x32,
        body_hex=hx(body_tx_sum_empty[:-1]), notes="short body")
    e_neg += 1
    add(id="DSB3_EV_TRAILING", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x32,
        body_hex=hx(body_tx_sum_empty + b"\x00"), notes="trailing byte")
    e_neg += 1
    add(id="DSB3_EV_BTS", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x32,
        body_length=len(body_tx_sum_empty), body_hex=hx(body_tx_sum_empty),
        key_length=0)
    e_neg += 1

    # typed negatives: key / primary / header / alias
    _, val_ok, _ = evidence_typed(body=body_tx_sum_empty)
    bad_key = evidence_key(EV_DLV, dlv_raw, 0)
    add_ev_neg_typed(
        "DSB3_EV_KEY_MISMATCH", bad_key, val_ok,
        "key COMPOSITE must match body owner/slot")
    wrong_kind_key = bkey(6, 0x32, 2, txn)
    add_ev_neg_typed(
        "DSB3_EV_WRONG_KIND", wrong_kind_key, val_ok,
        "key must be SHA256_COMPOSITE not ID128")
    k_wp, v_wp, _ = evidence_typed(
        body=body_tx_sum_empty, primary=bytes([0xDD] * 16))
    add_ev_neg_typed("DSB3_EV_BAD_PRIMARY", k_wp, v_wp, "wrong primary_id")
    k_zp, v_zp, _ = evidence_typed(body=body_tx_sum_empty, primary=bytes(16))
    add_ev_neg_typed("DSB3_EV_ZERO_PRIMARY", k_zp, v_zp, "zero primary_id")
    self_pid = composite(
        0x32, evidence_key_components(EV_TX, txn, 0))[:16]
    k_sk, v_sk, _ = evidence_typed(body=body_tx_sum_empty, primary=self_pid)
    add_ev_neg_typed(
        "DSB3_EV_SELF_KEY_PRIMARY", k_sk, v_sk,
        "primary_id must be owner primary not self composite")
    k_zh, v_zh, _ = evidence_typed(body=body_tx_sum_empty, head=bytes(32))
    add_ev_neg_typed("DSB3_EV_ZERO_HEAD", k_zh, v_zh)
    k_zv, v_zv, _ = evidence_typed(body=body_tx_sum_empty, pvd=bytes(32))
    add_ev_neg_typed("DSB3_EV_ZERO_PVD", k_zv, v_zv)
    k_fl = evidence_key(EV_TX, txn, 0)
    v_fl = enc_env_full(
        6, 0x32, 1, 1, txn, ev_head, ev_pvd, body_tx_sum_empty)
    add_ev_neg_typed("DSB3_EV_FLAGS_NZ", k_fl, v_fl, "flags must be 0")
    k_r0, v_r0, _ = evidence_typed(body=body_tx_sum_empty, rev=0)
    add_ev_neg_typed("DSB3_EV_REV0", k_r0, v_r0, "revision must be >=1")
    # slot mismatch in key
    bad_slot_key = evidence_key(EV_TX, txn, 1)
    add_ev_neg_typed(
        "DSB3_EV_SLOT_KEY_MISMATCH", bad_slot_key, val_ok,
        "key slot_index must match body")

    b3_cov["32"] = add_body_suite(
        "EVIDENCE_CELL", 6, 0x32, e_pos, e_neg, e_mut, e_rt)
    assert b3_cov["32"]["positive"] >= 12
    assert b3_cov["32"]["negative"] >= 30
    assert b3_cov["32"]["roundtrip"] >= 6


    # =====================================================================
    # D1-B3h DELIVERY (0x40) — after EVIDENCE_CELL; preserve first 970
    # =====================================================================
    PRE_B3H_VECTOR_COUNT = 970
    # Re-pinned at D1-B3i: kind9/10 42-byte identity correction.
    PRE_B3H_FULL_FINGERPRINT = (
        "68620e825ed9d26c9e1874b65f0408038784a28e77a9dde92a1f03ca03c5f0e6"
    )
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[-1]["id"] == "DSB3_EV_SLOT_KEY_MISMATCH"
    assert len(vectors) == PRE_B3H_VECTOR_COUNT
    _pre_b3h_fp = vectors_fingerprint(vectors)
    assert _pre_b3h_fp == PRE_B3H_FULL_FINGERPRINT, (
        f"pre-B3h full fingerprint drift: got {_pre_b3h_fp}"
    )
    PRE_B3H_VECTOR_COUNT_SNAPSHOT = len(vectors)

    # Private DELIVERY constants (docs17 §7.1 / §8.5).
    DLV_APP = 1
    DLV_CANCEL = 2
    FAM_EF = 1
    FAM_DS = 2
    STAGE_RECV = 1
    STAGE_DUR = 2
    STAGE_APP = 3
    STAGE_VER = 4
    NO_DEADLINE = (1 << 64) - 1
    dlv_head = bytes([0xD1] * 32)
    dlv_pvd = bytes(32)  # primary: zero PVD

    def delivery_result_kd(raw80: bytes) -> bytes:
        return complete_key_digest_composite(0x41, raw16(raw80))

    def delivery_reservation_kd(raw80: bytes) -> bytes:
        return complete_key_digest_composite(
            0x23, be16(4) + raw16(raw80))

    def delivery_key(raw80: bytes) -> bytes:
        return bkey(6, 0x40, 5, composite(0x40, raw16(raw80)))

    def delivery_primary_id(raw80: bytes) -> bytes:
        return primary_id_from_composite_subtype(0x40, raw16(raw80))

    def make_party_src(rt=None, app=None):
        if rt is None:
            rt = F["rt"]
        if app is None:
            app = F["app"]
        return party(rt, app, LI)

    def make_target_lt(trt=None, tapp=None):
        if trt is None:
            trt = F["trt"]
        if tapp is None:
            tapp = F["tapp"]
        return target(0x5, trt, tapp, F["dev"], bytes(16), F["site"], 1, 2)

    def make_svc(family, ns=b"n", svc=b"s", schema=b"c"):
        return service_identity(
            ns, svc, schema, 1, F["dig"], 1, 0, family)

    def make_dlv_raw(src_rt=None, src_app=None, txn_id=None, trt=None, tapp=None):
        if src_rt is None:
            src_rt = F["rt"]
        if src_app is None:
            src_app = F["app"]
        if txn_id is None:
            txn_id = txn
        if trt is None:
            trt = F["trt"]
        if tapp is None:
            tapp = F["tapp"]
        raw = src_rt + src_app + txn_id + trt + tapp
        assert len(raw) == 80
        return raw

    def enc_delivery_body(
        creation=DLV_APP,
        raw80=None,
        reserved=0,
        sched_seq=1,
        txn_id=None,
        event_id=None,
        src_party=None,
        lt_target=None,
        svc_wire=None,
        content=None,
        generation=None,
        deadline_epoch=None,
        deadline_ms=None,
        grace=None,
        required=STAGE_RECV,
        payload_kd=None,
        result_kd=None,
        reservation_kd=None,
        family=None,
    ) -> bytes:
        if raw80 is None:
            raw80 = make_dlv_raw()
        if txn_id is None:
            txn_id = raw80[32:48]
        if src_party is None:
            src_party = make_party_src(raw80[0:16], raw80[16:32])
        if lt_target is None:
            lt_target = make_target_lt(raw80[48:64], raw80[64:80])
        if family is None:
            if creation == DLV_CANCEL:
                family = FAM_DS
            else:
                family = FAM_EF
        if svc_wire is None:
            svc_wire = make_svc(family)
        if content is None:
            content = F["content"]
        if event_id is None:
            event_id = ev_id if family == FAM_EF else bytes(16)
        if generation is None:
            generation = 0 if family == FAM_EF else 1
        if deadline_epoch is None:
            deadline_epoch = bytes(16) if family == FAM_EF else F["epoch"]
        if deadline_ms is None:
            deadline_ms = NO_DEADLINE if family == FAM_EF else 1000
        if grace is None:
            grace = 0 if family == FAM_EF else 0
        if payload_kd is None:
            payload_kd = bytes(32) if creation == DLV_CANCEL else F["dig"]
        if result_kd is None:
            result_kd = delivery_result_kd(raw80)
        if reservation_kd is None:
            reservation_kd = delivery_reservation_kd(raw80)
        out = bytearray()
        out += raw16(raw80)
        out += be16(creation)
        out += be16(reserved)
        out += be64(sched_seq)
        out += txn_id
        out += event_id
        out += src_party
        out += lt_target
        out += svc_wire
        out += content
        out += be64(generation)
        out += deadline_epoch
        out += be64(deadline_ms)
        out += be64(grace)
        out += be32(required)
        out += payload_kd
        out += result_kd
        out += reservation_kd
        assert 552 <= len(out) <= 738, len(out)
        return bytes(out)

    def delivery_typed(body=None, rev=1, flags=0, primary_id=None, head=None, pvd=None):
        if body is None:
            body = enc_delivery_body()
        raw_len = int.from_bytes(body[0:2], "big")
        raw80 = body[2:2 + raw_len]
        if primary_id is None:
            primary_id = delivery_primary_id(raw80)
        if head is None:
            head = dlv_head
        if pvd is None:
            pvd = dlv_pvd
        key = delivery_key(raw80)
        val = enc_env_full(6, 0x40, flags, rev, primary_id, head, pvd, body)
        return key, val, body

    d_pos = 0
    d_neg = 0
    d_mut = 0
    d_rt = 0

    def add_dlv_pos(vid, body, notes=""):
        nonlocal d_pos, d_rt
        add(id=vid, suite="DSB3", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x40, body_length=len(body), body_hex=hx(body),
            notes=notes)
        d_pos += 1
        d_rt += 1

    def add_dlv_pos_typed(vid, body, notes=""):
        nonlocal d_pos
        key, val, _ = delivery_typed(body=body)
        add(id=vid, suite="DSB3", op="typed_record", expected_status="OK",
            family=6, subtype=0x40, key_hex=hx(key), value_hex=hx(val),
            body_hex=hx(body), body_length=len(body),
            digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}", notes=notes)
        d_pos += 1

    def add_dlv_neg(vid, body, notes=""):
        nonlocal d_neg
        add(id=vid, suite="DSB3", op="body_decode", expected_status="CORRUPT",
            family=6, subtype=0x40, body_hex=hx(body), notes=notes)
        d_neg += 1

    def add_dlv_neg_typed(vid, key, val, notes=""):
        nonlocal d_neg
        add(id=vid, suite="DSB3", op="typed_record", expected_status="CORRUPT",
            family=6, subtype=0x40, key_hex=hx(key), value_hex=hx(val),
            notes=notes)
        d_neg += 1

    # --- positives ---
    body_app_ef = enc_delivery_body(creation=DLV_APP, family=FAM_EF)
    add_dlv_pos("DSB3_DLV_APP_EF", body_app_ef, "APPLICATION_FIRST EventFact")
    add_dlv_pos_typed("DSB3_DLV_APP_EF_TYPED", body_app_ef)

    body_app_ds = enc_delivery_body(creation=DLV_APP, family=FAM_DS)
    add_dlv_pos("DSB3_DLV_APP_DS", body_app_ds, "APPLICATION_FIRST DesiredState")
    add_dlv_pos_typed("DSB3_DLV_APP_DS_TYPED", body_app_ds)

    body_cancel = enc_delivery_body(creation=DLV_CANCEL, family=FAM_DS)
    add_dlv_pos("DSB3_DLV_CANCEL_FIRST", body_cancel, "CANCEL_FIRST DesiredState")
    add_dlv_pos_typed("DSB3_DLV_CANCEL_FIRST_TYPED", body_cancel)

    body_svc_min = enc_delivery_body(
        creation=DLV_APP, family=FAM_EF,
        svc_wire=make_svc(FAM_EF, ns=b"a", svc=b"b", schema=b"c"))
    add_dlv_pos("DSB3_DLV_SVC_MIN", body_svc_min, "SERVICE_IDENTITY min 54")

    ns_max = bytes([0x61] * 63)
    svc_max = bytes([0x62] * 63)
    sch_max = bytes([0x63] * 63)
    body_svc_max = enc_delivery_body(
        creation=DLV_APP, family=FAM_DS,
        svc_wire=make_svc(FAM_DS, ns=ns_max, svc=svc_max, schema=sch_max))
    assert len(body_svc_max) == 738
    add_dlv_pos("DSB3_DLV_SVC_MAX", body_svc_max, "SERVICE_IDENTITY max 240 body 738")
    add_dlv_pos_typed("DSB3_DLV_SVC_MAX_TYPED", body_svc_max)

    # empty payload still non-zero digest (APPLICATION_FIRST)
    empty_nz = bytes([0xAB] * 32)
    body_empty_payload = enc_delivery_body(
        creation=DLV_APP, family=FAM_EF, payload_kd=empty_nz)
    add_dlv_pos(
        "DSB3_DLV_EMPTY_PAYLOAD_NZ", body_empty_payload,
        "APP_FIRST empty payload still nonzero payload key digest")
    add_dlv_pos_typed("DSB3_DLV_EMPTY_PAYLOAD_NZ_TYPED", body_empty_payload)

    body_grace_ds = enc_delivery_body(
        creation=DLV_APP, family=FAM_DS, grace=999)
    add_dlv_pos(
        "DSB3_DLV_DS_GRACE_ANY", body_grace_ds,
        "DS evidence_grace unrestricted in D1 same-record")

    # --- negatives: raw / bijection ---
    b = bytearray(body_app_ef)
    # force raw length 79 (truncate contents)
    short_raw = make_dlv_raw()[:79]
    add_dlv_neg(
        "DSB3_DLV_RAW_LEN79",
        enc_delivery_body(raw80=short_raw) if False else (
            # manually build invalid: length 79 then rest of valid body with 80-based layout fails
            be16(79) + make_dlv_raw()[:79] + body_app_ef[82:]
        ),
        "delivery_key_raw length must be exact 80")
    # simpler: mutate length prefix to 79 keeping 80 content bytes → overlong tail
    b = bytearray(body_app_ef)
    b[0:2] = be16(79)
    add_dlv_neg("DSB3_DLV_RAW_LEN_PREFIX79", bytes(b), "raw length prefix 79 corrupt")

    b = bytearray(body_app_ef)
    b[0:2] = be16(81)
    # need extra byte; append one before service section end - actually body has exact 80 content
    # prefix 81 will claim 81 content bytes of which only 80 exist before creation_kind
    add_dlv_neg("DSB3_DLV_RAW_LEN_PREFIX81", bytes(b) + b"\x00", "raw length prefix 81")

    zero_comp = bytearray(make_dlv_raw())
    zero_comp[0:16] = bytes(16)
    add_dlv_neg(
        "DSB3_DLV_RAW_ZERO_SRC_RT",
        enc_delivery_body(
            raw80=bytes(zero_comp),
            src_party=make_party_src(bytes(16), F["app"])),
        "source runtime component zero")

    # raw/body bijection: txn mismatch
    bad_txn = bytes([0xEE] * 16)
    add_dlv_neg(
        "DSB3_DLV_TXN_RAW_MISMATCH",
        enc_delivery_body(raw80=make_dlv_raw(), txn_id=bad_txn),
        "transaction_id must match raw[32,48)")

    # creation / reserved / scheduler
    add_dlv_neg(
        "DSB3_DLV_KIND0",
        enc_delivery_body(creation=0),
        "creation_kind 0 unknown")
    add_dlv_neg(
        "DSB3_DLV_KIND3",
        enc_delivery_body(creation=3),
        "creation_kind 3 unknown")
    add_dlv_neg(
        "DSB3_DLV_RESERVED_NZ",
        enc_delivery_body(reserved=1),
        "reserved must be 0")
    add_dlv_neg(
        "DSB3_DLV_SCHED0",
        enc_delivery_body(sched_seq=0),
        "scheduler_owner_sequence must be >=1")
    add_dlv_neg(
        "DSB3_DLV_ZERO_TXN",
        enc_delivery_body(raw80=make_dlv_raw(txn_id=bytes(16)), txn_id=bytes(16)),
        "transaction_id zero")
    add_dlv_neg(
        "DSB3_DLV_ZERO_CONTENT",
        enc_delivery_body(content=bytes(32)),
        "content_digest zero")

    # family / event / gen / deadline / grace
    add_dlv_neg(
        "DSB3_DLV_EF_FINITE_DEADLINE",
        enc_delivery_body(family=FAM_EF, deadline_ms=100, deadline_epoch=F["epoch"]),
        "EventFact must use NO_DEADLINE")
    add_dlv_neg(
        "DSB3_DLV_EF_GEN_NZ",
        enc_delivery_body(family=FAM_EF, generation=1),
        "EventFact generation must be 0")
    add_dlv_neg(
        "DSB3_DLV_EF_EVENT_ZERO",
        enc_delivery_body(family=FAM_EF, event_id=bytes(16)),
        "EventFact event_id non-zero")
    add_dlv_neg(
        "DSB3_DLV_EF_GRACE_NZ",
        enc_delivery_body(family=FAM_EF, grace=1),
        "EventFact evidence_grace must be 0")
    add_dlv_neg(
        "DSB3_DLV_DS_NO_DEADLINE",
        enc_delivery_body(family=FAM_DS, deadline_ms=NO_DEADLINE),
        "DesiredState deadline must not be NO_DEADLINE")
    add_dlv_neg(
        "DSB3_DLV_DS_EVENT_NZ",
        enc_delivery_body(family=FAM_DS, event_id=ev_id),
        "DesiredState event_id zero")
    add_dlv_neg(
        "DSB3_DLV_DS_GEN0",
        enc_delivery_body(family=FAM_DS, generation=0),
        "DesiredState generation >=1")
    add_dlv_neg(
        "DSB3_DLV_DS_EPOCH0",
        enc_delivery_body(family=FAM_DS, deadline_epoch=bytes(16)),
        "DesiredState deadline epoch non-zero")
    add_dlv_neg(
        "DSB3_DLV_CANCEL_EF",
        enc_delivery_body(creation=DLV_CANCEL, family=FAM_EF),
        "CANCEL_FIRST EventFact corrupt")

    # payload policy
    add_dlv_neg(
        "DSB3_DLV_APP_PAYLOAD_ZERO",
        enc_delivery_body(creation=DLV_APP, family=FAM_EF, payload_kd=bytes(32)),
        "APPLICATION_FIRST payload digest must be non-zero")
    add_dlv_neg(
        "DSB3_DLV_CANCEL_PAYLOAD_NZ",
        enc_delivery_body(creation=DLV_CANCEL, family=FAM_DS, payload_kd=F["dig"]),
        "CANCEL_FIRST payload digest must be zero")

    # result / reservation digests
    add_dlv_neg(
        "DSB3_DLV_RESULT_ZERO",
        enc_delivery_body(result_kd=bytes(32)),
        "result_cache_key_digest zero")
    add_dlv_neg(
        "DSB3_DLV_RESULT_WRONG",
        enc_delivery_body(result_kd=F["dig"]),
        "result_cache_key_digest wrong")
    bare_comp = composite(0x41, raw16(make_dlv_raw()))
    add_dlv_neg(
        "DSB3_DLV_RESULT_BARE_COMPOSITE",
        enc_delivery_body(result_kd=bare_comp),
        "bare composite is not KEY_DIGEST(complete RESULT_CACHE key)")
    add_dlv_neg(
        "DSB3_DLV_RES_ZERO",
        enc_delivery_body(reservation_kd=bytes(32)),
        "reservation_key_digest zero")
    add_dlv_neg(
        "DSB3_DLV_RES_WRONG",
        enc_delivery_body(reservation_kd=F["dig"]),
        "reservation_key_digest wrong")
    bare_res = composite(0x23, be16(4) + raw16(make_dlv_raw()))
    add_dlv_neg(
        "DSB3_DLV_RES_BARE_COMPOSITE",
        enc_delivery_body(reservation_kd=bare_res),
        "bare composite is not KEY_DIGEST(complete RESERVATION key)")

    # required evidence
    add_dlv_neg(
        "DSB3_DLV_REQ_EV_NONE",
        enc_delivery_body(required=0),
        "required_evidence known non-zero")
    add_dlv_neg(
        "DSB3_DLV_REQ_EV_UNKNOWN",
        enc_delivery_body(required=99),
        "required_evidence unknown stage")

    # short / trailing / BTS
    add_dlv_neg(
        "DSB3_DLV_SHORT",
        body_app_ef[:-1],
        "short body")
    add_dlv_neg(
        "DSB3_DLV_TRAILING",
        body_app_ef + b"\x00",
        "trailing byte")
    add(id="DSB3_DLV_BTS", suite="DSB3", op="body_encode",
        expected_status="BUFFER_TOO_SMALL", family=6, subtype=0x40,
        body_length=len(body_app_ef), body_hex=hx(body_app_ef),
        notes="encode with capacity 0 returns BTS with required length")
    d_neg += 1

    # invalid nested shape: zero source runtime via party (and matching raw)
    # already covered ZERO_SRC. Add invalid TEXT_ID empty via force:
    # service with empty ns cannot be built by make_svc; craft by mutating
    b = bytearray(body_app_ef)
    # service starts after raw82 + 4 + 8 + 32 + 100 + 100 = 326
    # first TEXT_ID length at offset 326
    assert b[326] >= 1
    b[326] = 0  # invalid empty TEXT_ID length
    add_dlv_neg("DSB3_DLV_SVC_EMPTY_NS", bytes(b), "SERVICE_IDENTITY empty namespace")

    # common / key / primary typed negatives
    k_ok, v_ok, body_ok = delivery_typed(body=body_app_ef)
    k_bad = bkey(6, 0x40, 5, composite(0x40, raw16(make_dlv_raw(txn_id=bytes([1]*16)))))
    # wrong key identity
    add_dlv_neg_typed(
        "DSB3_DLV_KEY_MISMATCH", k_bad, v_ok,
        "key composite must match body delivery_key_raw")
    # wrong primary_id
    bad_pid = bytes([0xFF] * 16)
    v_bad_pid = enc_env_full(6, 0x40, 0, 1, bad_pid, dlv_head, dlv_pvd, body_ok)
    add_dlv_neg_typed(
        "DSB3_DLV_PRIMARY_ID_WRONG", k_ok, v_bad_pid,
        "primary_id must be composite first 16")
    # rev 2 illegal for immutable
    k_r2, v_r2, _ = delivery_typed(body=body_ok, rev=2)
    add_dlv_neg_typed("DSB3_DLV_REV2", k_r2, v_r2, "immutable revision must be 1")
    k_r0, v_r0, _ = delivery_typed(body=body_ok, rev=0)
    add_dlv_neg_typed("DSB3_DLV_REV0", k_r0, v_r0, "revision 0 corrupt")
    k_fl, v_fl, _ = delivery_typed(body=body_ok, flags=1)
    add_dlv_neg_typed("DSB3_DLV_FLAGS_NZ", k_fl, v_fl, "flags must be 0")
    k_zh, v_zh, _ = delivery_typed(body=body_ok, head=bytes(32))
    add_dlv_neg_typed("DSB3_DLV_ZERO_HEAD", k_zh, v_zh, "head must be non-zero")
    k_pvd, v_pvd, _ = delivery_typed(body=body_ok, pvd=bytes([1] * 32))
    add_dlv_neg_typed("DSB3_DLV_PVD_NZ", k_pvd, v_pvd, "primary PVD must be zero")

    # Freeze the original B3h core (970 pre + first 53 DSB3_DLV_*). Later
    # coverage appends only; object identity of this prefix must not drift.
    PRE_B3H_CORE_VECTOR_COUNT = 1023
    # Re-pinned at D1-B3i: kind9/10 42-byte identity correction.
    PRE_B3H_CORE_FULL_FINGERPRINT = (
        "0bc465e425192504fab105cc4f7967044c063f1dabc298aed2079c9099d004a7"
    )
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[969]["id"] == "DSB3_EV_SLOT_KEY_MISMATCH"
    assert vectors[970]["id"] == "DSB3_DLV_APP_EF"
    assert vectors[-1]["id"] == "DSB3_DLV_PVD_NZ"
    assert len(vectors) == PRE_B3H_CORE_VECTOR_COUNT
    _pre_b3h_core_fp = vectors_fingerprint(vectors)
    assert _pre_b3h_core_fp == PRE_B3H_CORE_FULL_FINGERPRINT, (
        f"pre-B3h-core full fingerprint drift: got {_pre_b3h_core_fp}"
    )
    PRE_B3H_CORE_VECTOR_COUNT_SNAPSHOT = len(vectors)
    assert sum(
        1 for v in vectors[PRE_B3H_VECTOR_COUNT_SNAPSHOT:]
        if v["id"].startswith("DSB3_DLV_")
    ) == 53

    # --- coverage append: raw 5-component zero + bijection + nested shape ---
    # Generators assert the intended wire/mutation locus before adding.

    def assert_raw_slice_zero(raw80: bytes, off: int, label: str):
        assert len(raw80) == 80
        assert raw80[off:off + 16] == bytes(16), label
        # other 16-byte components remain non-zero
        for o in (0, 16, 32, 48, 64):
            if o == off:
                continue
            assert raw80[o:o + 16] != bytes(16), f"{label}: unexpected zero at {o}"

    def assert_body_party_rt_app(body: bytes, rt: bytes, app: bytes):
        # after RAW16(80)=82 + creation/reserved 4 + sched 8 + txn 16 + event 16
        # = 126; then PARTY runtime/app at 126..158
        assert body[126:142] == rt
        assert body[142:158] == app

    def assert_body_target_rt_app(body: bytes, trt: bytes, tapp: bytes):
        # PARTY ends at 126+100=226; TARGET: flags4 + trt16 + tapp16
        assert body[230:246] == trt
        assert body[246:262] == tapp

    base_raw = make_dlv_raw()
    assert base_raw[0:16] == F["rt"] and base_raw[16:32] == F["app"]
    assert base_raw[48:64] == F["trt"] and base_raw[64:80] == F["tapp"]

    # raw source.application zero (+ matching body app zero)
    z_app = bytearray(base_raw)
    z_app[16:32] = bytes(16)
    assert_raw_slice_zero(bytes(z_app), 16, "RAW_ZERO_SRC_APP")
    body_z_app = enc_delivery_body(
        raw80=bytes(z_app),
        src_party=make_party_src(F["rt"], bytes(16)))
    assert body_z_app[2:82] == bytes(z_app)
    assert_body_party_rt_app(body_z_app, F["rt"], bytes(16))
    add_dlv_neg(
        "DSB3_DLV_RAW_ZERO_SRC_APP", body_z_app,
        "source application component zero")

    # raw local_target.runtime zero
    z_trt = bytearray(base_raw)
    z_trt[48:64] = bytes(16)
    assert_raw_slice_zero(bytes(z_trt), 48, "RAW_ZERO_TGT_RT")
    body_z_trt = enc_delivery_body(
        raw80=bytes(z_trt),
        lt_target=make_target_lt(bytes(16), F["tapp"]))
    assert body_z_trt[2:82] == bytes(z_trt)
    assert_body_target_rt_app(body_z_trt, bytes(16), F["tapp"])
    add_dlv_neg(
        "DSB3_DLV_RAW_ZERO_TGT_RT", body_z_trt,
        "local_target runtime component zero")

    # raw local_target.application zero
    z_tapp = bytearray(base_raw)
    z_tapp[64:80] = bytes(16)
    assert_raw_slice_zero(bytes(z_tapp), 64, "RAW_ZERO_TGT_APP")
    body_z_tapp = enc_delivery_body(
        raw80=bytes(z_tapp),
        lt_target=make_target_lt(F["trt"], bytes(16)))
    assert body_z_tapp[2:82] == bytes(z_tapp)
    assert_body_target_rt_app(body_z_tapp, F["trt"], bytes(16))
    add_dlv_neg(
        "DSB3_DLV_RAW_ZERO_TGT_APP", body_z_tapp,
        "local_target application component zero")

    # bijection: raw remains valid; body field alone differs
    alt_rt = bytes([0x91] + [0] * 14 + [0xA1])
    alt_app = bytes([0x92] + [0] * 14 + [0xA2])
    alt_trt = bytes([0x93] + [0] * 14 + [0xA3])
    alt_tapp = bytes([0x94] + [0] * 14 + [0xA4])
    assert alt_rt != F["rt"] and alt_app != F["app"]
    assert alt_trt != F["trt"] and alt_tapp != F["tapp"]

    body_mis_rt = enc_delivery_body(
        raw80=base_raw, src_party=make_party_src(alt_rt, F["app"]))
    assert body_mis_rt[2:82] == base_raw
    assert_body_party_rt_app(body_mis_rt, alt_rt, F["app"])
    assert body_mis_rt[126:142] != body_mis_rt[2:18]
    add_dlv_neg(
        "DSB3_DLV_BIJ_SRC_RT", body_mis_rt,
        "body source.runtime must match raw[0,16)")

    body_mis_app = enc_delivery_body(
        raw80=base_raw, src_party=make_party_src(F["rt"], alt_app))
    assert body_mis_app[2:82] == base_raw
    assert_body_party_rt_app(body_mis_app, F["rt"], alt_app)
    assert body_mis_app[142:158] != body_mis_app[18:34]
    add_dlv_neg(
        "DSB3_DLV_BIJ_SRC_APP", body_mis_app,
        "body source.application must match raw[16,32)")

    body_mis_trt = enc_delivery_body(
        raw80=base_raw, lt_target=make_target_lt(alt_trt, F["tapp"]))
    assert body_mis_trt[2:82] == base_raw
    assert_body_target_rt_app(body_mis_trt, alt_trt, F["tapp"])
    assert body_mis_trt[230:246] != body_mis_trt[50:66]
    add_dlv_neg(
        "DSB3_DLV_BIJ_TGT_RT", body_mis_trt,
        "body local_target.runtime must match raw[48,64)")

    body_mis_tapp = enc_delivery_body(
        raw80=base_raw, lt_target=make_target_lt(F["trt"], alt_tapp))
    assert body_mis_tapp[2:82] == base_raw
    assert_body_target_rt_app(body_mis_tapp, F["trt"], alt_tapp)
    assert body_mis_tapp[246:262] != body_mis_tapp[66:82]
    add_dlv_neg(
        "DSB3_DLV_BIJ_TGT_APP", body_mis_tapp,
        "body local_target.application must match raw[64,80)")

    # PARTY invalid shape: flags=0 but device ID non-zero; raw/runtime/app match.
    bad_party_li = local_identity(0, F["dev"], bytes(16), bytes(16), 0, 0)
    assert bad_party_li[0:4] == be32(0)
    assert bad_party_li[4:20] == F["dev"] and F["dev"] != bytes(16)
    body_bad_party = enc_delivery_body(
        raw80=base_raw,
        src_party=party(F["rt"], F["app"], bad_party_li))
    assert body_bad_party[2:82] == base_raw
    assert_body_party_rt_app(body_bad_party, F["rt"], F["app"])
    # local_identity starts at party offset + 32 = 158
    assert body_bad_party[158:162] == be32(0)
    assert body_bad_party[162:178] == F["dev"]
    add_dlv_neg(
        "DSB3_DLV_PARTY_SHAPE", body_bad_party,
        "PARTY local_identity presence invalid (device without flag)")

    # TARGET invalid shape: flags=0 but device non-zero; raw target ids match.
    body_bad_tgt = enc_delivery_body(
        raw80=base_raw,
        lt_target=target(
            0, F["trt"], F["tapp"], F["dev"], bytes(16), bytes(16), 0, 0))
    assert body_bad_tgt[2:82] == base_raw
    assert_body_target_rt_app(body_bad_tgt, F["trt"], F["tapp"])
    # TARGET starts at 226: flags then device at 226+4+32=262
    assert body_bad_tgt[226:230] == be32(0)
    assert body_bad_tgt[262:278] == F["dev"]
    add_dlv_neg(
        "DSB3_DLV_TARGET_SHAPE", body_bad_tgt,
        "TARGET presence invalid (device without flag)")

    b3_cov["40"] = add_body_suite(
        "DELIVERY", 6, 0x40, d_pos, d_neg, d_mut, d_rt)
    assert b3_cov["40"]["positive"] >= 10
    assert b3_cov["40"]["negative"] >= 40
    assert b3_cov["40"]["roundtrip"] >= 6

    # =====================================================================
    # D1-B3i RESULT_CACHE (0x41) — after DELIVERY; preserve first 1032
    # except KIND910_REFIXED_IDS (D1 pre-alpha kind9/10 phase correction).
    # =====================================================================
    KIND910_REFIXED_IDS = (
        "DSO2_KIND_09",
        "DSO2_KIND_10",
        "DSO2_KIND09_ZERO_TOKEN",
        "DSW1_HDR_K09_ACTIVE",
        "DSO2_CANON_K09",
        "DSW1_HDR_K10_ACTIVE",
        "DSO2_CANON_K10",
    )
    PRE_B3I_VECTOR_COUNT = 1032
    # Fingerprint of vectors[0:1032] after kind9/10 42-byte re-pin (computed
    # below once identities are stable). Non-KIND910 entries must match the
    # historical hex; KIND910_REFIXED_IDS are intentionally re-fixed.
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[-1]["id"] == "DSB3_DLV_TARGET_SHAPE"
    assert len(vectors) == PRE_B3I_VECTOR_COUNT
    for vid in KIND910_REFIXED_IDS:
        assert any(v["id"] == vid for v in vectors), vid
    PRE_B3I_VECTOR_COUNT_SNAPSHOT = len(vectors)
    # Non-refixed prefix invariant: 1025 vectors excluding KIND910_REFIXED_IDS.
    # D1 pre-alpha operation identity correction re-pins only those seven IDs.
    KIND910_REFIXED_SET = set(KIND910_REFIXED_IDS)
    _pre_b3i_stable = [v for v in vectors if v["id"] not in KIND910_REFIXED_SET]
    assert len(_pre_b3i_stable) == PRE_B3I_VECTOR_COUNT - len(KIND910_REFIXED_IDS)
    PRE_B3I_STABLE_FINGERPRINT = vectors_fingerprint(_pre_b3i_stable)
    PRE_B3I_STABLE_FINGERPRINT_PIN = (
        "0717fd3014df8156700486b2a3e4ce031770112f540655e1462585fe71c45b7b"
    )
    assert PRE_B3I_STABLE_FINGERPRINT == PRE_B3I_STABLE_FINGERPRINT_PIN, (
        f"pre-B3i stable (non-KIND910) fingerprint drift: "
        f"got {PRE_B3I_STABLE_FINGERPRINT}"
    )
    PRE_B3I_FULL_FINGERPRINT = vectors_fingerprint(vectors)
    PRE_B3I_FULL_FINGERPRINT_PIN = (
        "1202822afd993ce18bdb504a190aac52363da6f4e3bf6ab92463f4789b3c4e6f"
    )
    assert PRE_B3I_FULL_FINGERPRINT == PRE_B3I_FULL_FINGERPRINT_PIN, (
        f"pre-B3i full fingerprint drift: got {PRE_B3I_FULL_FINGERPRINT}"
    )

    # RESULT_CACHE private enums / ABI mirrors (independent of C headers).
    ST_INBOX = 1
    ST_STARTED = 2
    ST_RESULT = 4
    ST_DISP = 5
    ST_RECOVERY = 6
    ST_WAIT = 7
    ST_CANCEL = 8
    TS_NONE = 1
    TS_ACTIVE = 2
    TS_CONSUMED = 3
    TS_EXPIRED = 4
    TS_REC_TOMB = 5
    APP_POS = 1
    APP_DISP = 2
    EV_RECV = 1
    DISP_INVALID = 2
    DISP_OUTCOME = 10
    EFF_NO = 1
    EFF_POSS = 2
    RG_NEVER = 0
    RG_SAME = 1
    RG_MOD = 2
    RG_OP = 3
    F_NONE = 0
    F_FENCED = 1
    F_LATE = 3
    U64_MAX = (1 << 64) - 1
    # Public ABI reason mirrors (include/ninlil/version.h) — no C linkage.
    R_CALLBACK = 23
    R_COUNTER = 76
    R_APP_FAIL = 128
    R_OUTCOME = 129
    R_TIMEOUT = 131
    rc_head = bytes([0xC1] * 32)
    rc_pvd = bytes([0xC2] * 32)  # secondary: non-zero PVD

    def make_rc_raw(src_rt=None, src_app=None, txn_id=None, trt=None, tapp=None):
        if src_rt is None:
            src_rt = F["rt"]
        if src_app is None:
            src_app = F["app"]
        if txn_id is None:
            txn_id = txn
        if trt is None:
            trt = F["trt"]
        if tapp is None:
            tapp = F["tapp"]
        raw = src_rt + src_app + txn_id + trt + tapp
        assert len(raw) == 80
        return raw

    def rc_delivery_kd(raw80: bytes) -> bytes:
        return complete_key_digest_composite(0x40, raw16(raw80))

    def rc_evidence_kd(raw80: bytes) -> bytes:
        return complete_key_digest_composite(
            0x32, be16(2) + raw16(raw80) + be32(0))

    def rc_key(raw80: bytes) -> bytes:
        return bkey(6, 0x41, 5, composite(0x41, raw16(raw80)))

    def rc_primary_id(raw80: bytes) -> bytes:
        return primary_id_from_composite_subtype(0x40, raw16(raw80))

    def op910_ident(kind, dig32, token_gen, phase):
        assert kind in (9, 10)
        assert len(dig32) == 32
        return dig32 + be64(token_gen) + be16(phase)

    def enc_result_cache_body(
        raw80=None,
        n=0,
        app_seen=1,
        app_attempt=1,
        state=ST_INBOX,
        reply=0,
        token_ctx=None,
        token_gen=None,
        tok_epoch=None,
        tok_exp=0,
        started_epoch=None,
        started_at=0,
        completion_exp=0,
        callback=None,
        rec_i=0,
        rec_g=0,
        rec_nb_epoch=None,
        rec_nb_ms=0,
        app_kind=0,
        ev_stage=0,
        disp=0,
        reason=0,
        effect=0,
        guidance=0,
        delay=0,
        evidence_kd=None,
        token_state=TS_NONE,
        cancel_kind=0,
        completed_epoch=None,
        completed_at=0,
        delivery_kd=None,
        txn_id=None,
    ) -> bytes:
        if raw80 is None:
            raw80 = make_rc_raw()
        if txn_id is None:
            txn_id = raw80[32:48]
        if token_gen is None:
            token_gen = n
        if callback is None:
            callback = n
        if delivery_kd is None:
            delivery_kd = rc_delivery_kd(raw80)
        if token_ctx is None:
            token_ctx = bytes(16) if token_state == TS_NONE else txn_id
        if tok_epoch is None:
            tok_epoch = bytes(16)
        if started_epoch is None:
            started_epoch = bytes(16)
        if rec_nb_epoch is None:
            rec_nb_epoch = bytes(16)
        if completed_epoch is None:
            completed_epoch = bytes(16)
        if evidence_kd is None:
            if app_seen == 1:
                evidence_kd = rc_evidence_kd(raw80)
            else:
                evidence_kd = bytes(32)
        out = bytearray()
        out += raw16(raw80)
        out += delivery_kd
        out += txn_id
        out += be64(n)
        out += be32(app_seen)
        out += be32(app_attempt)
        out += be32(state)
        out += be32(reply)
        out += token_ctx
        out += be64(token_gen)
        out += tok_epoch
        out += be64(tok_exp)
        out += started_epoch
        out += be64(started_at)
        out += be64(completion_exp)
        out += be64(callback)
        out += be64(rec_i)
        out += be64(rec_g)
        out += rec_nb_epoch
        out += be64(rec_nb_ms)
        out += be32(app_kind)
        out += be32(ev_stage)
        out += be32(disp)
        out += be32(reason)
        out += be32(effect)
        out += be32(guidance)
        out += be64(delay)
        out += evidence_kd
        out += be32(token_state)
        out += be32(cancel_kind)
        out += completed_epoch
        out += be64(completed_at)
        assert len(out) == 378, len(out)
        return bytes(out)

    def timer_active(started_at=0, exp=1000, epoch=None):
        if epoch is None:
            epoch = F["epoch"]
        return dict(
            tok_epoch=epoch, tok_exp=exp,
            started_epoch=epoch, started_at=started_at,
            completion_exp=exp)

    def completed_nz(at=5000, epoch=None):
        if epoch is None:
            epoch = F["epoch"]
        return dict(completed_epoch=epoch, completed_at=at)

    def e_zero():
        return dict(app_kind=0, ev_stage=0, disp=0, reason=0,
                    effect=0, guidance=RG_NEVER, delay=0,
                    completed_epoch=bytes(16), completed_at=0)

    def e_pos(stage=EV_RECV):
        d = completed_nz()
        d.update(app_kind=APP_POS, ev_stage=stage, disp=0, reason=0,
                 effect=0, guidance=RG_NEVER, delay=0)
        return d

    def e_disp(disposition=DISP_INVALID, reason=R_APP_FAIL, effect=EFF_NO,
               guidance=RG_MOD, delay=0):
        d = completed_nz()
        d.update(app_kind=APP_DISP, ev_stage=0, disp=disposition,
                 reason=reason, effect=effect, guidance=guidance, delay=delay)
        return d

    def e_rec(reason, guidance, token_state, n=1, started_at=0):
        # E_REC shape + matching token tombstone fields
        t = timer_active(started_at=started_at)
        d = dict(
            app_kind=0, ev_stage=0, disp=0, reason=reason,
            effect=EFF_POSS, guidance=guidance, delay=0,
            completed_epoch=bytes(16), completed_at=0,
            n=n, token_state=token_state, token_gen=n, callback=n,
            **t)
        return d

    def d_idle():
        return dict(rec_g=0, rec_i=0, rec_nb_epoch=bytes(16), rec_nb_ms=0)

    def d_open(g=1, i=0):
        return dict(rec_g=g, rec_i=i, rec_nb_epoch=bytes(16), rec_nb_ms=0)

    def d_wait(g=1, i=1, epoch=None, ms=999):
        if epoch is None:
            epoch = F["epoch"]
        return dict(rec_g=g, rec_i=i, rec_nb_epoch=epoch, rec_nb_ms=ms)

    def d_held(g=1, i=1):
        return dict(rec_g=g, rec_i=i, rec_nb_epoch=bytes(16), rec_nb_ms=0)

    def result_typed(body=None, rev=1, flags=0, primary_id=None, head=None, pvd=None):
        if body is None:
            body = enc_result_cache_body()
        raw_len = int.from_bytes(body[0:2], "big")
        raw80 = body[2:2 + raw_len]
        if primary_id is None:
            primary_id = rc_primary_id(raw80)
        if head is None:
            head = rc_head
        if pvd is None:
            pvd = rc_pvd
        key = rc_key(raw80)
        val = enc_env_full(6, 0x41, flags, rev, primary_id, head, pvd, body)
        return key, val, body

    rc_pos = 0
    rc_neg = 0
    rc_mut = 0
    rc_rt = 0

    def add_rc_pos(vid, body, notes=""):
        nonlocal rc_pos, rc_rt
        add(id=vid, suite="DSB3", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x41, body_length=len(body), body_hex=hx(body),
            notes=notes)
        rc_pos += 1
        rc_rt += 1

    def add_rc_pos_typed(vid, body, notes=""):
        nonlocal rc_pos
        key, val, _ = result_typed(body=body)
        add(id=vid, suite="DSB3", op="typed_record", expected_status="OK",
            family=6, subtype=0x41, key_hex=hx(key), value_hex=hx(val),
            body_hex=hx(body), body_length=len(body),
            digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}", notes=notes)
        rc_pos += 1

    def add_rc_neg(vid, body, notes=""):
        nonlocal rc_neg
        add(id=vid, suite="DSB3", op="body_decode", expected_status="CORRUPT",
            family=6, subtype=0x41, body_hex=hx(body), notes=notes)
        rc_neg += 1

    def add_rc_neg_typed(vid, key, val, notes=""):
        nonlocal rc_neg
        add(id=vid, suite="DSB3", op="typed_record", expected_status="CORRUPT",
            family=6, subtype=0x41, key_hex=hx(key), value_hex=hx(val),
            notes=notes)
        rc_neg += 1

    # --- positives: closed matrix shapes ---
    raw_rc = make_rc_raw()
    # 1 virgin inbox
    b_inbox = enc_result_cache_body(
        raw80=raw_rc, n=0, state=ST_INBOX, token_state=TS_NONE,
        app_seen=1, app_attempt=1, cancel_kind=F_NONE, **e_zero(), **d_idle())
    add_rc_pos("DSB3_RC_INBOX_VIRGIN", b_inbox, "state1 N=0 NONE D_IDLE E_ZERO")
    add_rc_pos_typed("DSB3_RC_INBOX_VIRGIN_TYPED", b_inbox)

    # started_at=0 positive ACTIVE
    t0 = timer_active(started_at=0, exp=1000)
    b_start0 = enc_result_cache_body(
        raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
        app_seen=1, app_attempt=1, cancel_kind=F_NONE, **e_zero(), **d_idle(), **t0)
    add_rc_pos("DSB3_RC_STARTED_AT0", b_start0, "started_at_ms=0 legal ACTIVE")
    add_rc_pos_typed("DSB3_RC_STARTED_AT0_TYPED", b_start0)

    # RESULT_COMMITTED E_POS
    b_res = enc_result_cache_body(
        raw80=raw_rc, n=1, state=ST_RESULT, token_state=TS_CONSUMED,
        app_seen=1, app_attempt=1, cancel_kind=F_NONE, **e_pos(), **d_idle(), **t0)
    add_rc_pos("DSB3_RC_RESULT_POS", b_res, "state4 CONSUMED E_POS")
    add_rc_pos_typed("DSB3_RC_RESULT_POS_TYPED", b_res)

    # DISPOSITION pre-callback N=0
    b_disp0 = enc_result_cache_body(
        raw80=raw_rc, n=0, state=ST_DISP, token_state=TS_NONE,
        app_seen=1, app_attempt=1, cancel_kind=F_NONE,
        **e_disp(), **d_idle())
    add_rc_pos("DSB3_RC_DISP_PRE", b_disp0, "state5 pre N=0 F_NONE E_DISP")
    add_rc_pos_typed("DSB3_RC_DISP_PRE_TYPED", b_disp0)

    # DISPOSITION post CONSUMED
    b_disp1 = enc_result_cache_body(
        raw80=raw_rc, n=2, state=ST_DISP, token_state=TS_CONSUMED,
        app_seen=1, app_attempt=2, cancel_kind=F_NONE,
        **e_disp(), **d_held(g=1, i=1), **t0)
    add_rc_pos("DSB3_RC_DISP_POST", b_disp1, "state5 post CONSUMED D_HELD")

    # OUTCOME_UNKNOWN terminal (E_DISP disposition OUTCOME_UNKNOWN) vs recovery
    b_disp_ou = enc_result_cache_body(
        raw80=raw_rc, n=1, state=ST_DISP, token_state=TS_CONSUMED,
        app_seen=1, app_attempt=1, cancel_kind=F_NONE,
        **e_disp(disposition=DISP_OUTCOME, reason=R_OUTCOME, effect=EFF_POSS,
                 guidance=RG_OP, delay=0), **d_idle(), **t0)
    add_rc_pos("DSB3_RC_OUTCOME_TERM", b_disp_ou,
               "OUTCOME_UNKNOWN terminal E_DISP state5")

    # CANCEL_TOMBSTONE_ONLY
    b_cancel = enc_result_cache_body(
        raw80=raw_rc, n=0, state=ST_CANCEL, token_state=TS_NONE,
        app_seen=0, app_attempt=0, cancel_kind=F_FENCED,
        evidence_kd=bytes(32), **e_zero(), **d_idle())
    add_rc_pos("DSB3_RC_CANCEL_FIRST", b_cancel, "state8 A_CANCEL F_FENCED")
    add_rc_pos_typed("DSB3_RC_CANCEL_FIRST_TYPED", b_cancel)

    # REDELIVER inbox N>=1 tombstone D_HELD
    b_redel = enc_result_cache_body(
        raw80=raw_rc, n=3, state=ST_INBOX, token_state=TS_CONSUMED,
        app_seen=1, app_attempt=2, cancel_kind=F_NONE,
        **e_zero(), **d_held(g=2, i=2), **t0)
    add_rc_pos("DSB3_RC_INBOX_REDELIVER", b_redel, "state1 redeliver D_HELD")

    # F_FENCED on inbox virgin
    b_fenced = enc_result_cache_body(
        raw80=raw_rc, n=0, state=ST_INBOX, token_state=TS_NONE,
        app_seen=1, app_attempt=1, cancel_kind=F_FENCED, **e_zero(), **d_idle())
    add_rc_pos("DSB3_RC_INBOX_FENCED", b_fenced, "state1 F_FENCED never-started")

    # F_LATE on started
    b_late = enc_result_cache_body(
        raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
        app_seen=1, app_attempt=1, cancel_kind=F_LATE, **e_zero(), **d_idle(), **t0)
    add_rc_pos("DSB3_RC_STARTED_FLATE", b_late, "state2 F_LATE N>=1")

    # reconcile G=I+1, I=G, I>G positives on recovery
    def rec_body(reason, guidance, ts, n=1, g=1, i=0, state=ST_RECOVERY, **extra):
        er = e_rec(reason, guidance, ts, n=n)
        er.update(d_open(g=g, i=i) if state == ST_RECOVERY else d_wait(g=g, i=i))
        er.update(extra)
        return enc_result_cache_body(
            raw80=raw_rc, state=state, app_seen=1, app_attempt=1,
            cancel_kind=F_NONE, **er)

    b_g_ip1 = rec_body(R_TIMEOUT, RG_SAME, TS_EXPIRED, n=1, g=1, i=0)
    add_rc_pos("DSB3_RC_REC_G_IS_I_P1", b_g_ip1, "G=I+1 D_OPEN timeout EXPIRED")
    add_rc_pos_typed("DSB3_RC_REC_G_IS_I_P1_TYPED", b_g_ip1)

    b_g_eq_i = rec_body(R_TIMEOUT, RG_SAME, TS_EXPIRED, n=1, g=2, i=2)
    add_rc_pos("DSB3_RC_REC_G_EQ_I", b_g_eq_i, "G=I D_OPEN after claim")

    b_i_gt_g = rec_body(R_TIMEOUT, RG_SAME, TS_EXPIRED, n=1, g=1, i=3)
    add_rc_pos("DSB3_RC_REC_I_GT_G", b_i_gt_g, "I>G legal after re-claim")

    # E_REC reason × token positives state6
    add_rc_pos("DSB3_RC_REC_TIMEOUT_EXPIRED",
               rec_body(R_TIMEOUT, RG_SAME, TS_EXPIRED),
               "APPLICATION_COMPLETION_TIMEOUT => EXPIRED")
    add_rc_pos("DSB3_RC_REC_FATAL_TOMB",
               rec_body(R_APP_FAIL, RG_OP, TS_REC_TOMB),
               "APPLICATION_FAILED => RECOVERY_REQUIRED_TOMBSTONE")
    add_rc_pos("DSB3_RC_REC_CONTRACT_TOMB",
               rec_body(R_CALLBACK, RG_OP, TS_REC_TOMB),
               "CALLBACK_CONTRACT => RECOVERY_REQUIRED_TOMBSTONE")
    add_rc_pos("DSB3_RC_REC_OUTCOME_EXPIRED",
               rec_body(R_OUTCOME, RG_OP, TS_EXPIRED),
               "OUTCOME_UNKNOWN recovery EXPIRED")
    add_rc_pos("DSB3_RC_REC_OUTCOME_TOMB",
               rec_body(R_OUTCOME, RG_OP, TS_REC_TOMB),
               "OUTCOME_UNKNOWN recovery RECOVERY_REQUIRED_TOMBSTONE")
    add_rc_pos("DSB3_RC_REC_COUNTER_CONSUMED",
               rec_body(R_COUNTER, RG_OP, TS_CONSUMED, n=U64_MAX, g=1, i=0),
               "COUNTER_EXHAUSTED N=MAX retained CONSUMED")
    add_rc_pos("DSB3_RC_REC_COUNTER_EXPIRED",
               rec_body(R_COUNTER, RG_OP, TS_EXPIRED, n=U64_MAX, g=1, i=0),
               "COUNTER_EXHAUSTED N=MAX retained EXPIRED")

    # state7 D_WAIT with legal pairs
    add_rc_pos("DSB3_RC_WAIT_TIMEOUT",
               rec_body(R_TIMEOUT, RG_SAME, TS_EXPIRED, n=1, g=2, i=1,
                        state=ST_WAIT),
               "state7 timeout EXPIRED D_WAIT")
    add_rc_pos("DSB3_RC_WAIT_CONTRACT",
               rec_body(R_CALLBACK, RG_OP, TS_REC_TOMB, n=1, g=2, i=1,
                        state=ST_WAIT),
               "state7 CALLBACK_CONTRACT tomb D_WAIT")
    add_rc_pos("DSB3_RC_WAIT_COUNTER",
               rec_body(R_COUNTER, RG_OP, TS_CONSUMED, n=U64_MAX, g=2, i=1,
                        state=ST_WAIT),
               "state7 COUNTER_EXHAUSTED CONSUMED D_WAIT")

    # START with D_HELD prior episode
    b_start_held = enc_result_cache_body(
        raw80=raw_rc, n=4, state=ST_STARTED, token_state=TS_ACTIVE,
        app_seen=1, app_attempt=3, cancel_kind=F_NONE,
        **e_zero(), **d_held(g=1, i=2), **timer_active(started_at=10, exp=2000))
    add_rc_pos("DSB3_RC_STARTED_DHELD", b_start_held, "state2 ACTIVE D_HELD")

    # --- negatives ---
    # expiry=0 negative (ACTIVE shape with zero expiry)
    bad = enc_result_cache_body(
        raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
        app_seen=1, app_attempt=1, **e_zero(), **d_idle(),
        tok_epoch=F["epoch"], tok_exp=0, started_epoch=F["epoch"],
        started_at=1, completion_exp=0)
    # force corrupt by manual mutate after legal-looking base
    bb = bytearray(b_start0)
    # token_expires and completion at fixed offsets after raw82
    # layout: 82 + 32 dig + 16 txn + 8 n + 4*4 + 16 ctx + 8 gen + 16 epoch + 8 exp
    # exp offset = 82+32+16+8+16+16+8+16 = 194? let me compute carefully:
    # 0: raw16 82
    # 82: dig 32 -> 114
    # 114: txn 16 -> 130
    # 130: n 8 -> 138
    # 138: seen 4 -> 142
    # 142: attempt 4 -> 146
    # 146: state 4 -> 150
    # 150: reply 4 -> 154
    # 154: ctx 16 -> 170
    # 170: gen 8 -> 178
    # 178: tok_epoch 16 -> 194
    # 194: tok_exp 8 -> 202
    # 202: started_epoch 16 -> 218
    # 218: started_at 8 -> 226
    # 226: completion_exp 8 -> 234
    bb[194:202] = be64(0)
    bb[226:234] = be64(0)
    add_rc_neg("DSB3_RC_EXPIRY0", bytes(bb), "token/completion expiry=0 invalid")

    # G > I+1
    add_rc_neg("DSB3_RC_G_GT_I_P1",
               rec_body(R_TIMEOUT, RG_SAME, TS_EXPIRED, n=1, g=5, i=2),
               "G>I+1 corrupt")

    # delivery_state=3
    bb = bytearray(b_inbox)
    bb[146:150] = be32(3)
    add_rc_neg("DSB3_RC_STATE3", bytes(bb), "delivery_state=3 illegal")

    # N=0 + tombstone
    add_rc_neg("DSB3_RC_N0_TOMB",
               enc_result_cache_body(
                   raw80=raw_rc, n=0, state=ST_INBOX, token_state=TS_CONSUMED,
                   app_seen=1, app_attempt=1, **e_zero(), **d_idle(),
                   token_ctx=raw_rc[32:48], token_gen=0, callback=0,
                   **timer_active()),
               "N=0 + tombstone invalid")

    # N>0 + NONE
    add_rc_neg("DSB3_RC_N_POS_NONE",
               enc_result_cache_body(
                   raw80=raw_rc, n=2, state=ST_STARTED, token_state=TS_NONE,
                   app_seen=1, app_attempt=1, **e_zero(), **d_idle()),
               "N>0 + NONE invalid")

    # state5 pre F_FENCED
    add_rc_neg("DSB3_RC_DISP_PRE_FENCED",
               enc_result_cache_body(
                   raw80=raw_rc, n=0, state=ST_DISP, token_state=TS_NONE,
                   app_seen=1, app_attempt=1, cancel_kind=F_FENCED,
                   **e_disp(), **d_idle()),
               "state5 pre F_FENCED invalid")

    # E_REC wrong token pairs (CALLBACK_CONTRACT+EXPIRED is legal — see re-fix below)
    add_rc_neg("DSB3_RC_TIMEOUT_TOMB",
               rec_body(R_TIMEOUT, RG_SAME, TS_REC_TOMB),
               "TIMEOUT cannot pair RECOVERY_REQUIRED_TOMBSTONE")
    add_rc_neg("DSB3_RC_FATAL_EXPIRED",
               rec_body(R_APP_FAIL, RG_OP, TS_EXPIRED),
               "APPLICATION_FAILED cannot pair EXPIRED")
    # DSB3_RC_CONTRACT_EXPIRED: re-fixed positive (unknown reconcile retains EXPIRED)
    add_rc_pos("DSB3_RC_CONTRACT_EXPIRED",
               rec_body(R_CALLBACK, RG_OP, TS_EXPIRED),
               "CALLBACK_CONTRACT + EXPIRED legal (retained prior timeout tomb)")
    add_rc_neg("DSB3_RC_OUTCOME_CONSUMED",
               rec_body(R_OUTCOME, RG_OP, TS_CONSUMED),
               "OUTCOME_UNKNOWN cannot pair CONSUMED on recovery")
    add_rc_neg("DSB3_RC_COUNTER_N_NOT_MAX",
               rec_body(R_COUNTER, RG_OP, TS_CONSUMED, n=5, g=1, i=0),
               "COUNTER_EXHAUSTED requires N=MAX")
    add_rc_neg("DSB3_RC_COUNTER_ACTIVE",
               rec_body(R_COUNTER, RG_OP, TS_ACTIVE, n=U64_MAX, g=1, i=0),
               "COUNTER_EXHAUSTED cannot be ACTIVE")
    # state7 illegal pair
    add_rc_neg("DSB3_RC_WAIT_FATAL_EXPIRED",
               rec_body(R_APP_FAIL, RG_OP, TS_EXPIRED, n=1, g=2, i=1,
                        state=ST_WAIT),
               "state7 APPLICATION_FAILED cannot pair EXPIRED")

    # raw80 component zero
    zraw = bytearray(make_rc_raw())
    zraw[0:16] = bytes(16)
    add_rc_neg("DSB3_RC_RAW_ZERO_COMP",
               enc_result_cache_body(raw80=bytes(zraw), n=0, state=ST_INBOX,
                   token_state=TS_NONE, **e_zero(), **d_idle()),
               "raw80 component zero")

    # body transaction mismatch
    bad_txn = bytes([0xEE] * 16)
    add_rc_neg("DSB3_RC_TXN_MISMATCH",
               enc_result_cache_body(
                   raw80=raw_rc, txn_id=bad_txn, n=0, state=ST_INBOX,
                   token_state=TS_NONE, **e_zero(), **d_idle()),
               "body transaction mismatch raw[32:48]")

    # body length 377/379
    add_rc_neg("DSB3_RC_LEN377", b_inbox[:-1], "body 377 trailing short")
    add_rc_neg("DSB3_RC_LEN379", b_inbox + b"\x00", "body 379 trailing byte")

    # typed: PVD zero, head zero, primary mismatch, rev0
    k_ok, v_ok, _ = result_typed(body=b_inbox)
    # PVD zero
    raw80 = raw_rc
    v_pvd0 = enc_env_full(6, 0x41, 0, 1, rc_primary_id(raw80), rc_head, bytes(32), b_inbox)
    add_rc_neg_typed("DSB3_RC_PVD_ZERO", rc_key(raw80), v_pvd0, "secondary PVD zero")
    v_head0 = enc_env_full(6, 0x41, 0, 1, rc_primary_id(raw80), bytes(32), rc_pvd, b_inbox)
    add_rc_neg_typed("DSB3_RC_HEAD_ZERO", rc_key(raw80), v_head0, "head zero")
    v_pm = enc_env_full(6, 0x41, 0, 1, bytes([0x11] * 16), rc_head, rc_pvd, b_inbox)
    add_rc_neg_typed("DSB3_RC_PRIMARY_MISMATCH", rc_key(raw80), v_pm,
                     "primary_id mismatch")
    v_rev0 = enc_env_full(6, 0x41, 0, 0, rc_primary_id(raw80), rc_head, rc_pvd, b_inbox)
    add_rc_neg_typed("DSB3_RC_REV0", rc_key(raw80), v_rev0, "revision 0")

    # wrong key digest in body
    bb = bytearray(b_inbox)
    bb[82:114] = bytes([0xFF] * 32)
    add_rc_neg("DSB3_RC_DLV_KD_BAD", bytes(bb), "delivery_key_digest mismatch")

    # mutation: flip state on positive
    bb = bytearray(b_inbox)
    bb[146:150] = be32(99)
    add(id="DSB3_RC_MUT_STATE", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x41,
        body_hex=hx(bytes(bb)), notes="mutation unknown state")
    rc_mut += 1

    # --- kind 9/10 operation identity (42-byte, phase collision) ---
    # docs17 §10: delivery_complete_key_digest[32] || token_generation || phase
    dig_dlv = rc_delivery_kd(raw_rc)
    for kind, phase, vid in (
        (9, 1, "DSB3_RC_OP9_PHASE1"),
        (9, 2, "DSB3_RC_OP9_PHASE2"),
        (10, 1, "DSB3_RC_OP10_PHASE1"),
        (10, 2, "DSB3_RC_OP10_PHASE2"),
    ):
        gen = 1 if phase == 1 else U64_MAX if kind == 9 else 1
        ident = op910_ident(kind, dig_dlv, gen, phase)
        add(id=vid, suite="DSB3", op="witness_identity_digest",
            expected_status="OK", family=6, subtype=0x41, operation_kind=kind,
            identity_hex=hx(ident),
            digest_hex=hx(composite(0x7F, be16(kind) + be16(42) + ident)),
            notes=f"kind{kind} phase{phase} 42-byte identity")
        rc_pos += 1
    # phase collision: same digest+gen, different phase => different witness dig
    id_p1 = op910_ident(9, dig_dlv, 1, 1)
    id_p2 = op910_ident(9, dig_dlv, 1, 2)
    assert id_p1 != id_p2
    d1 = composite(0x7F, be16(9) + be16(42) + id_p1)
    d2 = composite(0x7F, be16(9) + be16(42) + id_p2)
    assert d1 != d2
    add(id="DSB3_RC_OP9_PHASE_COLLISION", suite="DSB3",
        op="witness_identity_digest", expected_status="OK",
        family=6, subtype=0x41, operation_kind=9,
        identity_hex=hx(id_p1), digest_hex=hx(d1),
        digest2_hex=hx(d2),
        notes="phase1 vs phase2 different identity; phase2 identity in body_hex",
        body_hex=hx(id_p2),
        )
    rc_pos += 1
    # invalid phase 0/3
    for phase, tag in ((0, "P0"), (3, "P3")):
        for kind, kn in ((9, "9"), (10, "10")):
            ident = op910_ident(kind, dig_dlv, 1, phase)
            add(id=f"DSB3_RC_OP{kn}_PHASE_{tag}", suite="DSB3",
                op="witness_identity_digest", expected_status="INVALID_ARGUMENT",
                family=6, subtype=0x41, operation_kind=kind,
                identity_hex=hx(ident),
                notes=f"kind{kind} phase={phase} invalid")
            rc_neg += 1
    # legacy 40-byte invalid
    legacy40 = dig_dlv + be64(1)
    assert len(legacy40) == 40
    add(id="DSB3_RC_OP9_LEGACY40", suite="DSB3", op="witness_identity_digest",
        expected_status="INVALID_ARGUMENT", family=6, subtype=0x41,
        operation_kind=9, identity_hex=hx(legacy40),
        notes="legacy 40-byte kind9 rejected")
    add(id="DSB3_RC_OP10_LEGACY40", suite="DSB3", op="witness_identity_digest",
        expected_status="INVALID_ARGUMENT", family=6, subtype=0x41,
        operation_kind=10, identity_hex=hx(legacy40),
        notes="legacy 40-byte kind10 rejected")
    rc_neg += 2
    # zero token_generation
    zgen = op910_ident(9, dig_dlv, 0, 1)
    add(id="DSB3_RC_OP9_ZERO_GEN", suite="DSB3", op="witness_identity_digest",
        expected_status="INVALID_ARGUMENT", family=6, subtype=0x41,
        operation_kind=9, identity_hex=hx(zgen),
        notes="token_generation=0 invalid")
    rc_neg += 1

    # =====================================================================
    # D1-B3i QA append (after first 1097 base): timer strict, CALLBACK_CONTRACT
    # retained tombstones, independent coverage negatives. Prefer append;
    # only DSB3_RC_CONTRACT_EXPIRED was re-fixed in-place above.
    # =====================================================================
    # CALLBACK_CONTRACT + retained tombstones (state6/7)
    add_rc_pos("DSB3_RC_CONTRACT_TOMB_S6",
               rec_body(R_CALLBACK, RG_OP, TS_REC_TOMB),
               "state6 CALLBACK_CONTRACT + RECOVERY_TOMB (direct invalid)")
    add_rc_pos("DSB3_RC_CONTRACT_CONSUMED_S6",
               rec_body(R_CALLBACK, RG_OP, TS_CONSUMED),
               "state6 CALLBACK_CONTRACT + CONSUMED (prior counter path)")
    add_rc_pos("DSB3_RC_CONTRACT_EXPIRED_S7",
               rec_body(R_CALLBACK, RG_OP, TS_EXPIRED, n=1, g=2, i=1,
                        state=ST_WAIT),
               "state7 CALLBACK_CONTRACT + EXPIRED retained")
    add_rc_pos("DSB3_RC_CONTRACT_TOMB_S7",
               rec_body(R_CALLBACK, RG_OP, TS_REC_TOMB, n=1, g=2, i=1,
                        state=ST_WAIT),
               "state7 CALLBACK_CONTRACT + RECOVERY_TOMB")
    add_rc_pos("DSB3_RC_CONTRACT_CONSUMED_S7",
               rec_body(R_CALLBACK, RG_OP, TS_CONSUMED, n=1, g=2, i=1,
                        state=ST_WAIT),
               "state7 CALLBACK_CONTRACT + CONSUMED retained")

    # timer: expiry == started / expiry < started
    t_eq = timer_active(started_at=1000, exp=1000)
    add_rc_neg("DSB3_RC_EXPIRY_EQ_STARTED",
               enc_result_cache_body(
                   raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
                   app_seen=1, app_attempt=1, **e_zero(), **d_idle(), **t_eq),
               "completion_expires == started_at corrupt")
    t_lt = timer_active(started_at=2000, exp=1000)
    add_rc_neg("DSB3_RC_EXPIRY_LT_STARTED",
               enc_result_cache_body(
                   raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
                   app_seen=1, app_attempt=1, **e_zero(), **d_idle(), **t_lt),
               "completion_expires < started_at corrupt")
    # started=0 expiry>0 already positive as DSB3_RC_STARTED_AT0

    # timer epochs zero / mismatch
    add_rc_neg("DSB3_RC_TOK_EPOCH_ZERO",
               enc_result_cache_body(
                   raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
                   app_seen=1, app_attempt=1, **e_zero(), **d_idle(),
                   tok_epoch=bytes(16), tok_exp=1000,
                   started_epoch=F["epoch"], started_at=0, completion_exp=1000),
               "token_clock_epoch zero with ACTIVE")
    add_rc_neg("DSB3_RC_EPOCH_MISMATCH",
               enc_result_cache_body(
                   raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
                   app_seen=1, app_attempt=1, **e_zero(), **d_idle(),
                   tok_epoch=F["epoch"], tok_exp=1000,
                   started_epoch=bytes([0xBB] * 16), started_at=0,
                   completion_exp=1000),
               "token_epoch != delivery_started_epoch")

    # token_context mismatch (not txn)
    add_rc_neg("DSB3_RC_TOKEN_CTX_MISMATCH",
               enc_result_cache_body(
                   raw80=raw_rc, n=1, state=ST_STARTED, token_state=TS_ACTIVE,
                   app_seen=1, app_attempt=1, token_ctx=bytes([0xCC] * 16),
                   **e_zero(), **d_idle(), **timer_active()),
               "token_context_id != transaction_id")

    # callback_invocations / token_generation != N
    b_n = enc_result_cache_body(
        raw80=raw_rc, n=3, state=ST_STARTED, token_state=TS_ACTIVE,
        app_seen=1, app_attempt=1, **e_zero(), **d_idle(), **timer_active())
    bb = bytearray(b_n)
    # callback_invocations at offset 234 (after completion_exp)
    # 82+32+16+8+16+16+8+16+8+16+8+8 = 234 for callback start
    # layout after raw82: dig32,txn16,n8,seen4,att4,st4,rep4,ctx16,gen8,
    # tok_ep16,tok_exp8,st_ep16,st_at8,comp8,cb8,...
    # 82+32=114, +16=130, +8=138, +4*4=154, +16=170, +8=178, +16=194,
    # +8=202, +16=218, +8=226, +8=234 callback, +8=242 rec_i
    # token_generation is at 170
    bb[234:242] = be64(9)  # callback != N
    add_rc_neg("DSB3_RC_CB_NE_N", bytes(bb), "callback_invocations != N")
    bb = bytearray(b_n)
    bb[170:178] = be64(9)  # token_generation != N
    add_rc_neg("DSB3_RC_GEN_NE_N", bytes(bb), "token_generation != N")

    # reconcile mixed not-before (epoch nz, ms 0)
    add_rc_neg("DSB3_RC_NB_MIXED",
               rec_body(R_TIMEOUT, RG_SAME, TS_EXPIRED, n=1, g=1, i=0,
                        rec_nb_epoch=F["epoch"], rec_nb_ms=0),
               "reconcile not-before mixed zero/nonzero")
    # D_HELD I<G on redeliver inbox
    add_rc_neg("DSB3_RC_DHELD_I_LT_G",
               enc_result_cache_body(
                   raw80=raw_rc, n=2, state=ST_INBOX, token_state=TS_CONSUMED,
                   app_seen=1, app_attempt=1, **e_zero(),
                   rec_g=3, rec_i=1, rec_nb_epoch=bytes(16), rec_nb_ms=0,
                   **timer_active()),
               "D_HELD requires I>=G")

    # reply_count=5
    add_rc_neg("DSB3_RC_REPLY5",
               enc_result_cache_body(
                   raw80=raw_rc, n=0, state=ST_INBOX, token_state=TS_NONE,
                   app_seen=1, app_attempt=1, reply=5, **e_zero(), **d_idle()),
               "reply_count=5 out of 0..4")

    # A_APP attempts=0 / evidence zero / wrong
    add_rc_neg("DSB3_RC_AAPP_ATT0",
               enc_result_cache_body(
                   raw80=raw_rc, n=0, state=ST_INBOX, token_state=TS_NONE,
                   app_seen=1, app_attempt=0, **e_zero(), **d_idle()),
               "A_APP requires attempt_count>=1")
    add_rc_neg("DSB3_RC_EV_DIGEST_ZERO",
               enc_result_cache_body(
                   raw80=raw_rc, n=0, state=ST_INBOX, token_state=TS_NONE,
                   app_seen=1, app_attempt=1, evidence_kd=bytes(32),
                   **e_zero(), **d_idle()),
               "A_APP evidence_cell_key_digest zero")
    add_rc_neg("DSB3_RC_EV_DIGEST_WRONG",
               enc_result_cache_body(
                   raw80=raw_rc, n=0, state=ST_INBOX, token_state=TS_NONE,
                   app_seen=1, app_attempt=1, evidence_kd=bytes([0xEE] * 32),
                   **e_zero(), **d_idle()),
               "A_APP evidence_cell_key_digest formula mismatch")

    # RESULT_CACHE key composite mismatch (typed): wrong key identity
    wrong_key = bkey(6, 0x41, 5, composite(0x41, raw16(bytes([0x11] * 80))))
    k_ok2, v_ok2, _ = result_typed(body=b_inbox)
    add_rc_neg_typed("DSB3_RC_KEY_COMPOSITE_MISMATCH", wrong_key, v_ok2,
                     "RESULT_CACHE key composite != body raw")

    # completed epoch/time half-zero (E_POS shape)
    b_half = enc_result_cache_body(
        raw80=raw_rc, n=1, state=ST_RESULT, token_state=TS_CONSUMED,
        app_seen=1, app_attempt=1, **e_pos(), **d_idle(), **timer_active())
    bb = bytearray(b_half)
    # completed_clock_epoch is last 16 before completed_at 8: total 378
    # completed_at at 370:378, epoch at 354:370
    bb[354:370] = bytes(16)  # epoch zero, time remains nz
    add_rc_neg("DSB3_RC_COMPLETED_EPOCH_ZERO", bytes(bb),
               "completed epoch zero with completed_at nonzero")
    bb = bytearray(b_half)
    bb[370:378] = be64(0)  # time zero, epoch remains nz
    add_rc_neg("DSB3_RC_COMPLETED_AT_ZERO", bytes(bb),
               "completed_at zero with completed epoch nonzero")

    b3_cov["41"] = add_body_suite(
        "RESULT_CACHE", 6, 0x41, rc_pos, rc_neg, rc_mut, rc_rt)
    assert b3_cov["41"]["positive"] >= 20
    assert b3_cov["41"]["negative"] >= 20
    assert b3_cov["41"]["roundtrip"] >= 6

    # =====================================================================
    # D1-B3j REVERSE_REPLY (0x42) — after RESULT_CACHE; preserve pre-B3j.
    # =====================================================================
    PRE_B3J_VECTOR_COUNT = len(vectors)
    PRE_B3J_VECTOR_COUNT_SNAPSHOT = PRE_B3J_VECTOR_COUNT
    assert vectors[0]["id"] == "DSK1_SHA256_EMPTY"
    assert vectors[-1]["id"] == "DSB3_RC_COMPLETED_AT_ZERO"
    assert all(
        not v["id"].startswith("DSB3_RR_")
        for v in vectors
    )
    PRE_B3J_FULL_FINGERPRINT = vectors_fingerprint(vectors)
    # Pin of vectors[0:PRE_B3J] at B3j cutover (full pre-B3j catalog incl. B3i).
    PRE_B3J_FULL_FINGERPRINT_PIN = (
        "4d9ee8fcd6fa8eb0239336a9b78a7f1509ca2530abbd015703950627b3812db3"
    )
    assert PRE_B3J_FULL_FINGERPRINT == PRE_B3J_FULL_FINGERPRINT_PIN, (
        f"pre-B3j full fingerprint drift: got {PRE_B3J_FULL_FINGERPRINT}"
    )

    # REVERSE_REPLY private enums (docs17 §8.5 D1-B3j).
    RK_RECEIPT = 1
    RK_DISPOSITION = 2
    RK_CUSTODY = 3
    RK_CANCEL = 4
    SS_PENDING = 1
    SS_WAIT = 2
    SS_SENT = 3
    SS_DENIED = 4
    SS_EXHAUSTED = 5
    U64_MAX_RR = (1 << 64) - 1
    rr_head = bytes([0xD1] * 32)
    rr_pvd = bytes([0xD2] * 32)  # secondary: non-zero PVD
    rr_sem = bytes([0xD3] * 32)
    rr_blob = bytes([0xD4] * 32)
    rr_attempt = bytes([0xA1] + [0] * 14 + [0xA2])

    def make_rr_raw(src_rt=None, src_app=None, txn_id=None, trt=None, tapp=None):
        if src_rt is None:
            src_rt = F["rt"]
        if src_app is None:
            src_app = F["app"]
        if txn_id is None:
            txn_id = txn
        if trt is None:
            trt = F["trt"]
        if tapp is None:
            tapp = F["tapp"]
        raw = src_rt + src_app + txn_id + trt + tapp
        assert len(raw) == 80
        return raw

    def rr_reply_contents(raw80: bytes, kind: int) -> bytes:
        return raw16(raw80) + be32(kind)

    def rr_key(reply86: bytes) -> bytes:
        return bkey(6, 0x42, 5, composite(0x42, raw16(reply86)))

    def rr_primary_id(raw80: bytes) -> bytes:
        return primary_id_from_composite_subtype(0x40, raw16(raw80))

    def enc_reverse_reply_body(
        raw80=None,
        kind=RK_RECEIPT,
        state=SS_PENDING,
        g=0,
        i=0,
        exhausted=0,
        avail=0,
        retry_epoch=None,
        retry_ms=0,
        sem=None,
        blob=None,
        attempt=None,
        txn_id=None,
        reply_raw=None,
        reserved=0,
    ) -> bytes:
        if raw80 is None:
            raw80 = make_rr_raw()
        if txn_id is None:
            txn_id = raw80[32:48]
        if sem is None:
            sem = rr_sem
        if blob is None:
            blob = rr_blob
        if attempt is None:
            attempt = rr_attempt
        if retry_epoch is None:
            retry_epoch = bytes(16)
        if reply_raw is None:
            reply_raw = rr_reply_contents(raw80, kind)
        assert len(reply_raw) == 86
        out = bytearray()
        out += raw16(reply_raw)
        out += raw16(raw80)
        out += txn_id
        out += be32(kind)
        out += sem
        out += blob
        out += be32(state)
        out += be64(g)
        out += be64(i)
        out += be32(exhausted)
        out += be32(reserved)
        out += attempt
        out += be64(avail)
        out += retry_epoch
        out += be64(retry_ms)
        assert len(out) == 330, len(out)
        return bytes(out)

    def reverse_typed(body=None, rev=1, flags=0, primary_id=None, head=None,
                      pvd=None):
        if body is None:
            body = enc_reverse_reply_body()
        # reply RAW16 at start: len 86 at [0:2], contents [2:88]
        reply86 = body[2:88]
        # delivery RAW16 at [88:90] len, contents [90:170]
        raw80 = body[90:170]
        if primary_id is None:
            primary_id = rr_primary_id(raw80)
        if head is None:
            head = rr_head
        if pvd is None:
            pvd = rr_pvd
        key = rr_key(reply86)
        val = enc_env_full(6, 0x42, flags, rev, primary_id, head, pvd, body)
        return key, val, body

    rr_pos = 0
    rr_neg = 0
    rr_mut = 0
    rr_rt = 0

    def add_rr_pos(vid, body, notes=""):
        nonlocal rr_pos, rr_rt
        add(id=vid, suite="DSB3", op="body_roundtrip", expected_status="OK",
            family=6, subtype=0x42, body_length=len(body), body_hex=hx(body),
            notes=notes)
        rr_pos += 1
        rr_rt += 1

    def add_rr_pos_typed(vid, body, notes=""):
        nonlocal rr_pos
        key, val, _ = reverse_typed(body=body)
        add(id=vid, suite="DSB3", op="typed_record", expected_status="OK",
            family=6, subtype=0x42, key_hex=hx(key), value_hex=hx(val),
            body_hex=hx(body), body_length=len(body),
            digest_hex=hx(sha256(val)),
            crc_hex=f"{crc32c(val[:-4]):08x}", notes=notes)
        rr_pos += 1

    def add_rr_neg(vid, body, notes=""):
        nonlocal rr_neg
        add(id=vid, suite="DSB3", op="body_decode", expected_status="CORRUPT",
            family=6, subtype=0x42, body_hex=hx(body), notes=notes)
        rr_neg += 1

    def add_rr_neg_typed(vid, key, val, notes=""):
        nonlocal rr_neg
        add(id=vid, suite="DSB3", op="typed_record", expected_status="CORRUPT",
            family=6, subtype=0x42, key_hex=hx(key), value_hex=hx(val),
            notes=notes)
        rr_neg += 1

    raw_rr = make_rr_raw()
    timer_nz = dict(retry_epoch=F["epoch"], retry_ms=1000)
    timer_z = dict(retry_epoch=bytes(16), retry_ms=0)

    # --- positives: 4 kinds ---
    for kind, tag in (
        (RK_RECEIPT, "RECEIPT"),
        (RK_DISPOSITION, "DISPOSITION"),
        (RK_CUSTODY, "CUSTODY"),
        (RK_CANCEL, "CANCEL"),
    ):
        b = enc_reverse_reply_body(
            raw80=raw_rr, kind=kind, state=SS_PENDING, g=0, i=0,
            exhausted=0, avail=0, **timer_z)
        add_rr_pos(f"DSB3_RR_KIND_{tag}", b, f"kind {kind} virgin PENDING")
        if kind == RK_RECEIPT:
            add_rr_pos_typed("DSB3_RR_KIND_RECEIPT_TYPED", b)

    # --- all states ---
    b_pending = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_PENDING, g=0, i=0, exhausted=0, avail=0,
        **timer_z)
    add_rr_pos("DSB3_RR_PENDING_VIRGIN", b_pending, "state1 virgin G=0")

    # reopen I0 (TxGate path: G>=1, I=0, avail=0)
    b_reopen_i0 = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_PENDING, g=3, i=0, exhausted=0, avail=0,
        **timer_z)
    add_rr_pos("DSB3_RR_PENDING_REOPEN_I0", b_reopen_i0,
               "state1 reopen I=0 avail=0")
    add_rr_pos_typed("DSB3_RR_PENDING_REOPEN_I0_TYPED", b_reopen_i0)

    # reopen I1
    b_reopen_i1 = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_PENDING, g=3, i=1, exhausted=0, avail=7,
        **timer_z)
    add_rr_pos("DSB3_RR_PENDING_REOPEN_I1", b_reopen_i1,
               "state1 reopen I=1 avail nz")

    # mixed G=2 I=1
    b_g2i1 = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_PENDING, g=2, i=1, exhausted=0, avail=9,
        **timer_z)
    add_rr_pos("DSB3_RR_MIXED_G2_I1", b_g2i1, "mixed G=2 I=1")
    add_rr_pos_typed("DSB3_RR_MIXED_G2_I1_TYPED", b_g2i1)

    b_wait = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_WAIT, g=2, i=1, exhausted=0, avail=5,
        **timer_nz)
    add_rr_pos("DSB3_RR_WAITING_RETRY", b_wait, "state2 WAITING_RETRY timer nz")
    add_rr_pos_typed("DSB3_RR_WAITING_RETRY_TYPED", b_wait)

    b_wait_i0 = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_WAIT, g=1, i=0, exhausted=0, avail=0,
        **timer_nz)
    add_rr_pos("DSB3_RR_WAITING_I0", b_wait_i0, "state2 I=0 TxGate path")

    b_sent = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_SENT, g=2, i=1, exhausted=0, avail=11,
        **timer_z)
    add_rr_pos("DSB3_RR_CLOSED_SENT", b_sent, "state3 CLOSED_SENT_OR_UNKNOWN")
    add_rr_pos_typed("DSB3_RR_CLOSED_SENT_TYPED", b_sent)

    b_denied = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_DENIED, g=2, i=0, exhausted=0, avail=0,
        **timer_z)
    add_rr_pos("DSB3_RR_CLOSED_DENIED_I0", b_denied, "state4 I=0")
    b_denied_i = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_DENIED, g=4, i=2, exhausted=0, avail=3,
        **timer_z)
    add_rr_pos("DSB3_RR_CLOSED_DENIED_I", b_denied_i, "state4 I>0")
    add_rr_pos_typed("DSB3_RR_CLOSED_DENIED_TYPED", b_denied_i)

    # MAX: G=MAX I<=G exhausted=1 state5
    b_max_g = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_EXHAUSTED, g=U64_MAX_RR, i=U64_MAX_RR - 1,
        exhausted=1, avail=99, **timer_z)
    add_rr_pos("DSB3_RR_MAX_G", b_max_g, "state5 G=MAX I=MAX-1")
    add_rr_pos_typed("DSB3_RR_MAX_G_TYPED", b_max_g)

    b_max_i = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_EXHAUSTED, g=U64_MAX_RR, i=U64_MAX_RR,
        exhausted=1, avail=1, **timer_z)
    add_rr_pos("DSB3_RR_MAX_I", b_max_i, "state5 G=I=MAX")

    b_max_i_only = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_EXHAUSTED, g=U64_MAX_RR, i=U64_MAX_RR,
        exhausted=1, avail=0xdead, **timer_z)
    # already covered; also I=MAX with G=MAX is only legal I=MAX case when G>=I
    # virgin-ish exhausted with I=0 and G=MAX
    b_max_g_i0 = enc_reverse_reply_body(
        raw80=raw_rr, state=SS_EXHAUSTED, g=U64_MAX_RR, i=0, exhausted=1,
        avail=0, **timer_z)
    add_rr_pos("DSB3_RR_MAX_G_I0", b_max_g_i0, "state5 G=MAX I=0 avail0")

    # --- negatives ---
    # length 329 / 331
    add_rr_neg("DSB3_RR_LEN329", b_pending[:-1], "body 329 trailing short")
    add_rr_neg("DSB3_RR_LEN331", b_pending + b"\x00", "body 331 trailing byte")

    # Total exact 330 with illegal RAW length pair (reply+delivery contents = 166).
    # Intermediate remaining-after-RAWs is still 160; same-record exact 86/80 fails.
    def rr_bad_length_pair(reply_n: int, delivery_n: int) -> bytes:
        assert reply_n + delivery_n == 166
        reply86 = b_pending[2:88]
        raw80 = b_pending[90:170]
        fixed = b_pending[170:330]
        if reply_n >= 86:
            reply_c = reply86 + (b"\x00" * (reply_n - 86))
        else:
            reply_c = reply86[:reply_n]
        if delivery_n >= 80:
            dlv_c = raw80 + (b"\x00" * (delivery_n - 80))
        else:
            dlv_c = raw80[:delivery_n]
        assert len(reply_c) == reply_n and len(dlv_c) == delivery_n
        out = raw16(reply_c) + raw16(dlv_c) + fixed
        assert len(out) == 330, len(out)
        return out

    add_rr_neg("DSB3_RR_LEN_PAIR_87_79", rr_bad_length_pair(87, 79),
               "total330 reply87/delivery79 length pair")
    add_rr_neg("DSB3_RR_LEN_PAIR_85_81", rr_bad_length_pair(85, 81),
               "total330 reply85/delivery81 length pair")

    # raw: zero delivery component
    zraw = bytearray(make_rr_raw())
    zraw[0:16] = bytes(16)
    add_rr_neg("DSB3_RR_RAW_ZERO_COMP",
               enc_reverse_reply_body(raw80=bytes(zraw), state=SS_PENDING,
                                      g=0, i=0, exhausted=0, avail=0, **timer_z),
               "delivery raw component zero")

    # reply raw not delivery RAW16||kind
    bad_reply = bytes([0xFF] * 86)
    add_rr_neg("DSB3_RR_REPLY_RAW_MISMATCH",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=0, i=0, exhausted=0,
                   avail=0, reply_raw=bad_reply, **timer_z),
               "reply_key_raw not delivery RAW16||kind")

    # reply kind body vs trailing u32 mismatch (mutate body kind only)
    bb = bytearray(b_pending)
    # layout: reply88 + delivery82 = 170, then txn16 -> 186, kind u32 at 186
    bb[186:190] = be32(RK_DISPOSITION)  # body kind != reply trailing
    add_rr_neg("DSB3_RR_KIND_MISMATCH", bytes(bb),
               "body reply_kind != reply raw trailing u32")

    # txn mismatch
    add_rr_neg("DSB3_RR_TXN_MISMATCH",
               enc_reverse_reply_body(
                   raw80=raw_rr, txn_id=bytes([0xEE] * 16), state=SS_PENDING,
                   g=0, i=0, exhausted=0, avail=0, **timer_z),
               "body transaction mismatch raw[32:48]")

    # nonzero required zeroed
    add_rr_neg("DSB3_RR_SEM_ZERO",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=0, i=0, exhausted=0,
                   avail=0, sem=bytes(32), **timer_z),
               "semantic_digest zero")
    add_rr_neg("DSB3_RR_BLOB_ZERO",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=0, i=0, exhausted=0,
                   avail=0, blob=bytes(32), **timer_z),
               "body_blob_key_digest zero")
    add_rr_neg("DSB3_RR_ATTEMPT_ZERO",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=0, i=0, exhausted=0,
                   avail=0, attempt=bytes(16), **timer_z),
               "attempt_id zero")

    # reserved nonzero
    add_rr_neg("DSB3_RR_RESERVED_NZ",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=0, i=0, exhausted=0,
                   avail=0, reserved=1, **timer_z),
               "reserved nonzero")

    # counter: I > G
    add_rr_neg("DSB3_RR_I_GT_G",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=1, i=2, exhausted=0,
                   avail=1, **timer_z),
               "I>G corrupt")

    # MAX without exhausted / state5
    add_rr_neg("DSB3_RR_MAX_NO_EXH",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=U64_MAX_RR, i=0,
                   exhausted=0, avail=0, **timer_z),
               "G=MAX with exhausted=0")
    add_rr_neg("DSB3_RR_MAX_WRONG_STATE",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_SENT, g=U64_MAX_RR, i=1,
                   exhausted=1, avail=1, **timer_z),
               "MAX+exhausted on state3 corrupt")

    # state5 without MAX / without exhausted
    add_rr_neg("DSB3_RR_STATE5_NO_MAX",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_EXHAUSTED, g=5, i=3, exhausted=1,
                   avail=1, **timer_z),
               "state5 requires G or I MAX")
    add_rr_neg("DSB3_RR_STATE5_EXH0",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_EXHAUSTED, g=U64_MAX_RR, i=0,
                   exhausted=0, avail=0, **timer_z),
               "state5 exhausted must be 1")
    add_rr_neg("DSB3_RR_STATE5_TIMER_NZ",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_EXHAUSTED, g=U64_MAX_RR, i=0,
                   exhausted=1, avail=0, **timer_nz),
               "state5 timer must be zero")

    # I/avail coupling
    add_rr_neg("DSB3_RR_I0_AVAIL_NZ",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=2, i=0, exhausted=0,
                   avail=1, **timer_z),
               "I=0 requires availability 0")
    add_rr_neg("DSB3_RR_I_POS_AVAIL0",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=2, i=1, exhausted=0,
                   avail=0, **timer_z),
               "I>0 requires availability non-zero")

    # timer mixed
    add_rr_neg("DSB3_RR_TIMER_EPOCH_ONLY",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_WAIT, g=1, i=0, exhausted=0,
                   avail=0, retry_epoch=F["epoch"], retry_ms=0),
               "timer epoch nz ms 0")
    add_rr_neg("DSB3_RR_TIMER_MS_ONLY",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_WAIT, g=1, i=0, exhausted=0,
                   avail=0, retry_epoch=bytes(16), retry_ms=5),
               "timer ms nz epoch 0")
    add_rr_neg("DSB3_RR_WAIT_TIMER_ZERO",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_WAIT, g=1, i=0, exhausted=0,
                   avail=0, **timer_z),
               "state2 requires non-zero timer")
    add_rr_neg("DSB3_RR_PENDING_TIMER_NZ",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=1, i=0, exhausted=0,
                   avail=0, **timer_nz),
               "state1 requires zero timer")

    # state3 I=0 illegal
    add_rr_neg("DSB3_RR_STATE3_I0",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_SENT, g=2, i=0, exhausted=0,
                   avail=0, **timer_z),
               "state3 requires I>=1")

    # unknown kind / state
    add_rr_neg("DSB3_RR_KIND0",
               enc_reverse_reply_body(
                   raw80=raw_rr, kind=0, state=SS_PENDING, g=0, i=0,
                   exhausted=0, avail=0, **timer_z),
               "reply_kind 0 illegal")
    add_rr_neg("DSB3_RR_KIND5",
               enc_reverse_reply_body(
                   raw80=raw_rr, kind=5, state=SS_PENDING, g=0, i=0,
                   exhausted=0, avail=0, **timer_z),
               "reply_kind 5 illegal")
    bb = bytearray(b_pending)
    # send_state at offset after reply88+dlv82+txn16+kind4+sem32+blob32 = 254
    # 88+82=170, +16=186, +4=190, +32=222, +32=254
    bb[254:258] = be32(99)
    add_rr_neg("DSB3_RR_STATE_UNKNOWN", bytes(bb), "unknown send_state")
    add(id="DSB3_RR_MUT_STATE", suite="DSB3", op="body_decode",
        expected_status="CORRUPT", family=6, subtype=0x42,
        body_hex=hx(bytes(bb)), notes="mutation unknown state")
    rr_mut += 1

    # exhausted not 0/1
    bb = bytearray(b_pending)
    # exhausted after state4 + g8 + i8 = 254+4+8+8=274
    bb[274:278] = be32(2)
    add_rr_neg("DSB3_RR_EXH_2", bytes(bb), "exhausted not 0/1")

    # exhausted=1 without MAX on non-state5 already covered; flag1 G not max
    add_rr_neg("DSB3_RR_EXH1_NO_MAX",
               enc_reverse_reply_body(
                   raw80=raw_rr, state=SS_PENDING, g=3, i=1, exhausted=1,
                   avail=1, **timer_z),
               "exhausted=1 requires MAX")

    # typed common header negatives
    k_ok, v_ok, _ = reverse_typed(body=b_pending)
    raw80 = raw_rr
    reply86 = rr_reply_contents(raw80, RK_RECEIPT)
    v_pvd0 = enc_env_full(6, 0x42, 0, 1, rr_primary_id(raw80), rr_head,
                          bytes(32), b_pending)
    add_rr_neg_typed("DSB3_RR_PVD_ZERO", rr_key(reply86), v_pvd0,
                     "secondary PVD zero")
    v_head0 = enc_env_full(6, 0x42, 0, 1, rr_primary_id(raw80), bytes(32),
                           rr_pvd, b_pending)
    add_rr_neg_typed("DSB3_RR_HEAD_ZERO", rr_key(reply86), v_head0, "head zero")
    v_pm = enc_env_full(6, 0x42, 0, 1, bytes([0x11] * 16), rr_head, rr_pvd,
                        b_pending)
    add_rr_neg_typed("DSB3_RR_PRIMARY_MISMATCH", rr_key(reply86), v_pm,
                     "primary_id mismatch")
    v_rev0 = enc_env_full(6, 0x42, 0, 0, rr_primary_id(raw80), rr_head, rr_pvd,
                          b_pending)
    add_rr_neg_typed("DSB3_RR_REV0", rr_key(reply86), v_rev0, "revision 0")
    v_flags = enc_env_full(6, 0x42, 1, 1, rr_primary_id(raw80), rr_head, rr_pvd,
                           b_pending)
    add_rr_neg_typed("DSB3_RR_FLAGS_NZ", rr_key(reply86), v_flags,
                     "common flags nonzero")

    # key composite mismatch
    wrong_key = bkey(6, 0x42, 5, composite(0x42, raw16(bytes([0x11] * 86))))
    _, v_ok2, _ = reverse_typed(body=b_pending)
    add_rr_neg_typed("DSB3_RR_KEY_COMPOSITE_MISMATCH", wrong_key, v_ok2,
                     "REVERSE_REPLY key composite != body reply raw")

    # delivery length wrong in body (truncate reply path via short delivery
    # already fixed-length; mutate delivery length field)
    bb = bytearray(b_pending)
    bb[88:90] = be16(79)  # delivery raw length claim wrong
    add_rr_neg("DSB3_RR_DLV_LEN79", bytes(bb), "delivery raw length 79")

    b3_cov["42"] = add_body_suite(
        "REVERSE_REPLY", 6, 0x42, rr_pos, rr_neg, rr_mut, rr_rt)
    assert b3_cov["42"]["positive"] >= 15
    assert b3_cov["42"]["negative"] >= 25
    assert b3_cov["42"]["roundtrip"] >= 6
    # silence unused if any
    _ = (b_max_i_only,)

    # Completeness: every D1-B1 subtype has >=1 positive body + typed
    for st in ("01", "60", "62", "64", "7d"):
        assert b1_cov[st]["positive"] >= 2
        assert b1_cov[st]["negative"] >= 3
        assert b1_cov[st]["mutation"] >= 1
        assert b1_cov[st]["roundtrip"] >= 1

    primary_ok = sum(1 for v in vectors if v["op"] == "primary_id" and v["expected_status"] == "OK")
    enc_ok = sum(1 for v in vectors if v["op"] == "envelope_encode" and v["expected_status"] == "OK")
    dsb1_pos = sum(1 for v in vectors if v["suite"] == "DSB1"
                   and v["expected_status"] == "OK")
    dsb1_neg = sum(1 for v in vectors if v["suite"] == "DSB1"
                   and v["expected_status"] != "OK")
    dsb2_pos = sum(1 for v in vectors if v["suite"] == "DSB2"
                   and v["expected_status"] == "OK")
    dsb2_neg = sum(1 for v in vectors if v["suite"] == "DSB2"
                   and v["expected_status"] != "OK")
    dsb3_pos = sum(1 for v in vectors if v["suite"] == "DSB3"
                   and v["expected_status"] == "OK")
    dsb3_neg = sum(1 for v in vectors if v["suite"] == "DSB3"
                   and v["expected_status"] != "OK")
    catalog = {
        "dsk1_positive_keys": 30,
        "dsv1_body_exact": 30,
        "dsv1_body_plus1": 30,
        "dsh2_health_positive": 12,
        "dsh2_fence_positive": 4,
        "dso2_kind_positive": 21,
        "dso2_canonical_positive": 21,
        "dsw1_member_stream": 5,
        "dsw1_header_positive": header_pos + 2,  # 21 ACTIVE + SUPERSEDED + RETIRED
        "dsk1_primary_id_positive": primary_ok,
        "dsv1_encode_decode_positive": enc_ok,
        "dsb1_subtype_01_positive": b1_cov["01"]["positive"],
        "dsb1_subtype_60_positive": b1_cov["60"]["positive"],
        "dsb1_subtype_62_positive": b1_cov["62"]["positive"],
        "dsb1_subtype_64_positive": b1_cov["64"]["positive"],
        "dsb1_subtype_7d_positive": b1_cov["7d"]["positive"],
        "dsb1_total_positive": dsb1_pos,
        "dsb1_total_negative": dsb1_neg,
        "dsb2_subtype_10_positive": b2_cov["10"]["positive"],
        "dsb2_subtype_11_positive": b2_cov["11"]["positive"],
        "dsb2_subtype_20_positive": b2_cov["20"]["positive"],
        "dsb2_subtype_21_positive": b2_cov["21"]["positive"],
        "dsb2_subtype_22_positive": b2_cov["22"]["positive"],
        "dsb2_subtype_23_positive": b2_cov["23"]["positive"],
        "dsb2_subtype_24_positive": b2_cov["24"]["positive"],
        "dsb2_subtype_25_positive": b2_cov["25"]["positive"],
        "dsb2_total_positive": dsb2_pos,
        "dsb2_total_negative": dsb2_neg,
        "dsb3_subtype_26_positive": b3_cov["26"]["positive"],
        "dsb3_total_positive": dsb3_pos,
        "dsb3_total_negative": dsb3_neg,
        "dsb3_subtype_27_positive": b3_cov["27"]["positive"],
        "dsb3_subtype_30_positive": b3_cov["30"]["positive"],
        "dsb3_subtype_31_positive": b3_cov["31"]["positive"],
        "dsb3_subtype_34_positive": b3_cov["34"]["positive"],
        "dsb3_subtype_33_positive": b3_cov["33"]["positive"],
        "dsb3_subtype_32_positive": b3_cov["32"]["positive"],
        "dsb3_subtype_40_positive": b3_cov["40"]["positive"],
        "dsb3_subtype_41_positive": b3_cov["41"]["positive"],
        "dsb3_subtype_42_positive": b3_cov["42"]["positive"],
    }
    assert primary_ok == 5
    assert enc_ok == 30  # all EXACT body encodes (service rev2 etc. are not OK)
    assert sum(1 for v in vectors if v["op"] == "key_build" and v["expected_status"] == "OK") == 30
    # D1-A EXACT/PLUS1 ids remain 30 each; D1-B1 does not reuse those suffixes alone.
    assert sum(1 for v in vectors if v["id"].endswith("_EXACT")) == 30
    assert sum(1 for v in vectors if v["id"].endswith("_PLUS1")) == 30
    assert sum(1 for v in vectors if v["id"].startswith("DSH2_HEALTH_") and v["expected_status"] == "OK") == 12
    assert sum(1 for v in vectors if v["id"].startswith("DSH2_FENCE_") and v["expected_status"] == "OK") == 4
    assert sum(1 for v in vectors if v["id"].startswith("DSO2_KIND_") and len(v["id"]) == 12) == 21
    assert sum(1 for v in vectors if v["id"].startswith("DSW1_MANIFEST_")) == 5
    assert sum(1 for v in vectors if v["op"] == "canonical_operation_digest"
               and v["expected_status"] == "OK") == 21
    assert sum(1 for v in vectors if v["op"] == "witness_header_roundtrip"
               and v["expected_status"] == "OK") == catalog["dsw1_header_positive"]
    assert catalog["dsb1_subtype_01_positive"] > 0
    assert catalog["dsb1_subtype_60_positive"] > 0
    assert catalog["dsb1_subtype_62_positive"] > 0
    assert catalog["dsb1_subtype_64_positive"] > 0
    assert catalog["dsb1_subtype_7d_positive"] > 0
    for st in ("10", "11", "20", "21", "22", "23", "24", "25"):
        assert catalog[f"dsb2_subtype_{st}_positive"] > 0
    assert catalog["dsb2_total_positive"] > 0
    assert catalog["dsb2_total_negative"] > 0
    assert catalog["dsb3_subtype_26_positive"] > 0
    assert catalog["dsb3_subtype_27_positive"] > 0
    assert catalog["dsb3_subtype_30_positive"] > 0
    assert catalog["dsb3_subtype_31_positive"] > 0
    assert catalog["dsb3_subtype_34_positive"] > 0
    assert catalog["dsb3_subtype_33_positive"] > 0
    assert catalog["dsb3_subtype_32_positive"] > 0
    assert catalog["dsb3_subtype_40_positive"] > 0
    assert catalog["dsb3_subtype_41_positive"] > 0
    assert catalog["dsb3_subtype_42_positive"] > 0
    assert catalog["dsb3_total_positive"] > 0
    assert catalog["dsb3_total_negative"] > 0
    # Structural: CS/AII/ATT/EV/RC only after their pre-slice.
    assert all(
        not v["id"].startswith("DSB3_RC_")
        for v in vectors[:PRE_B3I_VECTOR_COUNT_SNAPSHOT]
    )
    assert all(
        not v["id"].startswith("DSB3_RR_")
        for v in vectors[:PRE_B3J_VECTOR_COUNT_SNAPSHOT]
    )
    assert all(
        not v["id"].startswith("DSB3_DLV_")
        for v in vectors[:PRE_B3H_VECTOR_COUNT_SNAPSHOT]
    )
    assert all(
        not v["id"].startswith("DSB3_EV_")
        for v in vectors[:PRE_B3G_VECTOR_COUNT_SNAPSHOT]
    )
    assert all(
        not v["id"].startswith("DSB3_CS_")
        for v in vectors[:PRE_B3F_VECTOR_COUNT]
    )
    assert all(
        not v["id"].startswith("DSB3_AII_")
        for v in vectors[:PRE_B3E_VECTOR_COUNT]
    )
    assert all(
        not v["id"].startswith("DSB3_ATT_")
        for v in vectors[:PRE_B3D_VECTOR_COUNT]
    )
    # Kind9/10 42-byte re-pin changes early DSO2/DSW1 vectors inside pre-B3h.
    # Full prefix fingerprint is re-pinned at B3i cutover; stable 1025 checked above.
    _pre_b3j_fp_final = vectors_fingerprint(
        vectors[:PRE_B3J_VECTOR_COUNT_SNAPSHOT])
    assert _pre_b3j_fp_final == PRE_B3J_FULL_FINGERPRINT_PIN, (
        f"post-append pre-B3j full fingerprint drift: got {_pre_b3j_fp_final}"
    )
    _pre_b3i_fp_final = vectors_fingerprint(
        vectors[:PRE_B3I_VECTOR_COUNT_SNAPSHOT])
    assert _pre_b3i_fp_final == PRE_B3I_FULL_FINGERPRINT, (
        f"post-append pre-B3i full fingerprint drift: got {_pre_b3i_fp_final}"
    )
    _pre_b3i_stable_final = vectors_fingerprint(
        [v for v in vectors[:PRE_B3I_VECTOR_COUNT_SNAPSHOT]
         if v["id"] not in KIND910_REFIXED_SET])
    assert _pre_b3i_stable_final == PRE_B3I_STABLE_FINGERPRINT, (
        f"post-append pre-B3i stable fingerprint drift: got {_pre_b3i_stable_final}"
    )
    _pre_b3h_fp_final = vectors_fingerprint(
        vectors[:PRE_B3H_VECTOR_COUNT_SNAPSHOT])
    assert _pre_b3h_fp_final == PRE_B3H_FULL_FINGERPRINT, (
        f"post-append pre-B3h full fingerprint drift: got {_pre_b3h_fp_final}"
    )
    _pre_b3h_core_fp_final = vectors_fingerprint(
        vectors[:PRE_B3H_CORE_VECTOR_COUNT_SNAPSHOT])
    assert _pre_b3h_core_fp_final == PRE_B3H_CORE_FULL_FINGERPRINT, (
        f"post-append pre-B3h-core full fingerprint drift: "
        f"got {_pre_b3h_core_fp_final}"
    )
    assert all(
        not v["id"].startswith("DSB3_DLV_RAW_ZERO_SRC_APP")
        and not v["id"].startswith("DSB3_DLV_BIJ_")
        and not v["id"].startswith("DSB3_DLV_PARTY_SHAPE")
        and not v["id"].startswith("DSB3_DLV_TARGET_SHAPE")
        for v in vectors[:PRE_B3H_CORE_VECTOR_COUNT_SNAPSHOT]
    )
    _pre_b3g_fp_final = vectors_fingerprint(
        vectors[:PRE_B3G_VECTOR_COUNT_SNAPSHOT])
    assert _pre_b3g_fp_final == PRE_B3G_FULL_FINGERPRINT, (
        f"post-append pre-B3g full fingerprint drift: got {_pre_b3g_fp_final}"
    )
    _pre_b3f_fp_final = non_b3b_wire_fingerprint(vectors[:PRE_B3F_VECTOR_COUNT])
    assert _pre_b3f_fp_final == PRE_B3F_NON_B3B_WIRE_FINGERPRINT, (
        f"post-append pre-B3f non-B3b-wire fingerprint drift: got {_pre_b3f_fp_final}"
    )
    _pre_b3e_fp_final = non_b3b_wire_fingerprint(vectors[:PRE_B3E_VECTOR_COUNT])
    assert _pre_b3e_fp_final == PRE_B3E_NON_B3B_WIRE_FINGERPRINT, (
        f"post-append pre-B3e non-B3b-wire fingerprint drift: got {_pre_b3e_fp_final}"
    )
    _pre_b3d_fp_final = non_b3b_wire_fingerprint(vectors[:PRE_B3D_VECTOR_COUNT])
    assert _pre_b3d_fp_final == PRE_B3D_NON_B3B_WIRE_FINGERPRINT, (
        f"post-append pre-B3d non-B3b-wire fingerprint drift: got {_pre_b3d_fp_final}"
    )
    # Full catalog non-B3b count grows with B3g append (computed after build).
    _non_b3b_wire = [v for v in vectors if not is_b3b_wire_fixture(v)]
    assert len(_non_b3b_wire) == 797 + (
        len(vectors) - PRE_B3G_VECTOR_COUNT_SNAPSHOT
    ), f"non-B3b-wire count drift: {len(_non_b3b_wire)}"

    for v in vectors:
        assert v["required_workspace_bytes"] == 0

    doc = {
        "version": 1,
        "format": "ninlil-domain-store-v1-d1b3j",
        "scope": (
            "D1-A framing + D1-B1 bodies (01/60/62/64/7d) + D1-B2 bodies "
            "(10/11/20-25) + D1-B3a body "
            "(26 SCHEDULER_OWNER) + D1-B3b body (27 ORDERED_INGRESS controller_ingress "
            "r1) + message_semantic_digest helper + D1-B3c body (30 BLOB "
            "manifest/chunk) + D1-B3d body (31 ATTEMPT) + D1-B3e body "
            "(34 ATTEMPT_ID_INDEX) + D1-B3f body (33 CANCEL_STATE) + "
            "D1-B3g body (32 EVIDENCE_CELL) + D1-B3h body (40 DELIVERY) + "
            "D1-B3i body (41 RESULT_CACHE; D1 pre-alpha operation identity "
            "correction kind9/10 phase) + D1-B3j body (42 REVERSE_REPLY "
            "exact330/state matrix); not full D1 catalog"
        ),
        "required_workspace_bytes_definition": (
            "Additional caller-provided scratch beyond explicit inputs, outputs, "
            "and state/context objects. Current D1-A/D1-B1/D1-B2/D1-B3a/D1-B3b/"
            "D1-B3c/D1-B3d/D1-B3e/D1-B3f/D1-B3g/D1-B3h/D1-B3i/D1-B3j APIs have no "
            "workspace parameter; value is 0."
        ),
        "catalog": catalog,
        "vectors": vectors,
    }
    return doc


def document_bytes():
    doc = build_document()
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("usage: domain_store_vector_gen.py generate|check <path>", file=sys.stderr)
        return 2
    mode = argv[0]
    if mode not in ("generate", "check") and len(argv) == 1:
        # Legacy: single path argument means generate
        mode = "generate"
        path = Path(argv[0])
    elif mode in ("generate", "check"):
        if len(argv) < 2:
            print("usage: domain_store_vector_gen.py generate|check <path>", file=sys.stderr)
            return 2
        path = Path(argv[1])
    else:
        print("usage: domain_store_vector_gen.py generate|check <path>", file=sys.stderr)
        return 2

    payload = document_bytes()
    if mode == "generate":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        print("vectors", payload.count(b'"id"'), "bytes", len(payload))
        return 0
    # check: compare deterministic in-memory bytes to file
    if not path.is_file():
        print("missing vector file", path, file=sys.stderr)
        return 1
    existing = path.read_bytes()
    if existing != payload:
        print("oracle mismatch: checked-in JSON != regenerated catalog", file=sys.stderr)
        print("checked bytes", len(existing), "regen bytes", len(payload), file=sys.stderr)
        return 1
    print("oracle check ok bytes=%d" % len(payload))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
