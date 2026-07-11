#!/usr/bin/env python3
"""Independent D1-A vector oracle (stdlib only; no production C linkage).

Sole oracle implementation for the checked-in domain-store-v1 vector catalog.
Uses hashlib + independent encoders only.

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


def bearer_state_key() -> bytes:
    return ROOT + bytes([6, 0x60, 1, 1, 0])


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
        L = {1: 32, 2: 16, 3: 16, 4: 8, 5: 32, 6: 40, 7: 8, 8: 8, 9: 40, 10: 40, 11: 50,
             12: 42, 13: 8, 14: 42, 15: 32, 16: 32, 17: 14, 18: 42, 19: 24, 20: 8, 21: 66}[k]
        b = bytearray([(0x20 + (i & 0x1F)) for i in range(L)])
        if k in (6, 9, 10):
            b[32:40] = be64(1)
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

    primary_ok = sum(1 for v in vectors if v["op"] == "primary_id" and v["expected_status"] == "OK")
    enc_ok = sum(1 for v in vectors if v["op"] == "envelope_encode" and v["expected_status"] == "OK")
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
    }
    assert primary_ok == 5
    assert enc_ok == 30  # all EXACT body encodes (service rev2 etc. are not OK)
    assert sum(1 for v in vectors if v["op"] == "key_build" and v["expected_status"] == "OK") == 30
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

    doc = {
        "version": 1,
        "format": "ninlil-domain-store-v1-d1a",
        "scope": "D1-A framing/primitive slice (not full D1 body catalog)",
        "required_workspace_bytes_definition": (
            "Additional caller-provided scratch beyond explicit inputs, outputs, "
            "and state/context objects. Current D1-A APIs have no workspace parameter; value is 0."
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
