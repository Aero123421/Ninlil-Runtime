#!/usr/bin/env python3
"""Independent D2-S3 domain-scan structural vector oracle (stdlib only).

Does NOT invoke, import, link, or translate production C scanner/codec.
Builds profile framing + domain structural cases using:
  - independent NLR1/CRC32C/SHA-256/profile encoding
  - literal key/value hex reused from frozen D1 authority
    (spec/vectors/domain-store-v1.json, format ninlil-domain-store-v1-d1b3o)
    pinned by format / full SHA-256 / vector count; selected vectors assert
    id / expected_status / op / subtype / key+value presence
  - independent witness key/envelope construction + framing derivation for 7e/7f
  - synthetic envelope / common-header / future / witness mutations derive
    framing/status on the oracle side (not a bare good/bad whitelist)

Usage:
  python3 tools/domain_scan_structural_vector_gen.py generate <path>
  python3 tools/domain_scan_structural_vector_gen.py check <path>
  python3 tools/domain_scan_structural_vector_gen.py emit-c-fixture <json> <c-header>
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FORMAT = "ninlil-domain-scan-structural-v1-d2s3"
VERSION = 1
ROOT_V1 = bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x01])
PROFILE_NAME = b"NINLIL-FOUNDATION-SMALL-1"
KEY_CAP = 255
VALUE_CAP = 4096
PREV_CAP = 255
CEILING = 8192
ALL_MASK = 0x1FFFF

PREIMAGE_COMPOSITE = b"NINLIL-DOMAIN-KEY-V1"
PREIMAGE_OPERATION = b"NINLIL-DOMAIN-OPERATION-V1"

REPO_ROOT = Path(__file__).resolve().parents[1]
D1_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-store-v1.json"
S1_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-v1.json"

# D1 authority pins (byte-for-byte frozen; generator does not rewrite D1).
D1_FORMAT = "ninlil-domain-store-v1-d1b3o"
D1_VECTOR_COUNT = 1549
D1_SHA256 = (
    "b809c223f8208111fb4271cdceed031193e32e0f118e019d404ac538c89792b4"
)

# S1 transport body-nonvalidation regression authority (sibling frozen).
S1_FORMAT = "ninlil-domain-scan-v1-d2s1"
S1_SHA256 = (
    "5705363e8f8890849e41476013eab3cd4ac1a20b6c33efb54ab65f300d40a165"
)
S1_BODY_NONVALIDATION_IDS = (
    "s1-65-rows",  # empty-value domain CURRENT counted without body validate
    "s1-family14-current",  # mixed family1-4 + domain row under transport begin
)

# Closed catalog: family5 01 + family6 closed current subtypes (docs §7 table).
# Exact literal list; not derived from required==covered self-definition alone.
CLOSED_CURRENT_SUBTYPES: Tuple[int, ...] = (
    0x01,  # family 5 INTERNAL_INVARIANT
    0x10,
    0x11,
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x30,
    0x31,
    0x32,
    0x33,
    0x34,
    0x40,
    0x41,
    0x42,
    0x50,
    0x51,
    0x52,
    0x60,
    0x61,
    0x62,
    0x63,
    0x64,
    0x7D,
    0x7E,
    0x7F,
)
REQUIRED_SUBTYPES = frozenset(CLOSED_CURRENT_SUBTYPES)
assert len(CLOSED_CURRENT_SUBTYPES) == 30
assert len(REQUIRED_SUBTYPES) == 30

# Business + 7d require positive scan reach via D1 typed authority.
BUSINESS_AND_7D: Tuple[int, ...] = tuple(
    s for s in CLOSED_CURRENT_SUBTYPES if s not in (0x7E, 0x7F)
)

REQUIRED_KINDS = frozenset(
    {
        "structural_positive",
        "structural_corrupt",
        "structural_unsupported",
        "witness_header_local",
        "witness_chunk_local",
        "precedence",
        "profile_skip",
        "lex_regression",
        "dsr2_ceiling",
        "bts_corrupt",
        "s1_evidence",
    }
)

# D1 typed_record selections: suffix -> (vector_id, subtype).
# Positive for every business+7d; corrupt where D1 provides a typed negative.
TYPED_SELECT_POS: Dict[str, Tuple[str, int]] = {
    "inv": ("DSB1_INV_TYPED_POSITIVE", 0x01),
    "svc": ("DSB2_SERVICE_TYPED", 0x10),
    "quota": ("DSB2_QUOTA_TYPED", 0x11),
    "anchor": ("DSB2_ANCHOR_TYPED", 0x20),
    "seq": ("DSB2_SEQ_TYPED", 0x21),
    "state": ("DSB2_STATE_TYPED", 0x22),
    "res": ("DSB2_RES_TX_TYPED", 0x23),
    "idem": ("DSB2_IDEM_TYPED", 0x24),
    "evmap": ("DSB2_EVMAP_TYPED", 0x25),
    "sched": ("DSB3_SCHED_TX_TYPED", 0x26),
    "ing": ("DSB3_ING_APP_DS_TYPED", 0x27),
    "blob": ("DSB3_BLOB_MAN_TX_CMD_TYPED", 0x30),
    "att": ("DSB3_ATT_TX_CMD_PREP_TYPED", 0x31),
    "ev": ("DSB3_EV_TX_SUM_EMPTY_TYPED", 0x32),
    "cs": ("DSB3_CS_TX_NONE_TYPED", 0x33),
    "aii": ("DSB3_AII_CMD_TYPED", 0x34),
    "dlv": ("DSB3_DLV_APP_EF_TYPED", 0x40),
    "rc": ("DSB3_RC_INBOX_VIRGIN_TYPED", 0x41),
    "rr": ("DSB3_RR_KIND_RECEIPT_TYPED", 0x42),
    "es": ("DSB3_ES_ACTIVE_TYPED", 0x50),
    "rs": ("DSB3_RS_CUM_T0_TYPED", 0x51),
    "ml": ("DSB3_ML_R_RSN1_TYPED", 0x52),
    "bearer": ("DSB1_BEARER_TYPED_POSITIVE", 0x60),
    "rb": ("DSB3_RB_TX_ACTIVE_PENDING_TYPED", 0x61),
    "clock": ("DSB1_CLOCK_TYPED_UNINIT", 0x62),
    "cp": ("DSB3_CP_TX_P1_FULL_TYPED", 0x63),
    "fence": ("DSB1_FENCE_TYPED_POSITIVE", 0x64),
    "head": ("DSB1_HEAD_TYPED_BASELINE", 0x7D),
}

TYPED_SELECT_NEG: Dict[str, Tuple[str, int]] = {
    "inv_bad": ("DSB1_INV_TYPED_BAD_MARKER", 0x01),
    "svc_bad": ("DSB2_SERVICE_TYPED_REV2", 0x10),
    "quota_bad": ("DSB2_QUOTA_TYPED_SELF_PRIMARY", 0x11),
    # 0x20 TRANSACTION_ANCHOR: no D1 typed CORRUPT vector — skip negative.
    "seq_bad": ("DSB2_SEQ_TYPED_SELF_PRIMARY", 0x21),
    "state_bad": ("DSB2_STATE_TYPED_BAD_PRIMARY", 0x22),
    "res_bad": ("DSB2_RES_TX_TYPED_SELF_PRIMARY", 0x23),
    "idem_bad": ("DSB2_IDEM_TYPED_SELF_PRIMARY", 0x24),
    "evmap_bad": ("DSB2_EVMAP_TYPED_SELF_PRIMARY", 0x25),
    "sched_bad": ("DSB3_SCHED_ZERO_HEAD", 0x26),
    "ing_bad": ("DSB3_ING_BAD_PRIMARY", 0x27),
    "blob_bad": ("DSB3_BLOB_FLAGS_ZERO", 0x30),
    "att_bad": ("DSB3_ATT_ZERO_PVD", 0x31),
    "ev_bad": ("DSB3_EV_KEY_MISMATCH", 0x32),
    "cs_bad": ("DSB3_CS_KEY_MISMATCH", 0x33),
    "aii_bad": ("DSB3_AII_KEY_MISMATCH", 0x34),
    "dlv_bad": ("DSB3_DLV_KEY_MISMATCH", 0x40),
    "rc_bad": ("DSB3_RC_PVD_ZERO", 0x41),
    "rr_bad": ("DSB3_RR_PVD_ZERO", 0x42),
    "es_bad": ("DSB3_ES_PVD_ZERO", 0x50),
    "rs_bad": ("DSB3_RS_PVD_ZERO", 0x51),
    "ml_bad": ("DSB3_ML_PVD_ZERO", 0x52),
    "bearer_bad": ("DSB1_BEARER_TYPED_ZERO_HEAD", 0x60),
    "rb_bad": ("DSB3_RB_REV0", 0x61),
    "clock_bad": ("DSB1_CLOCK_TYPED_TRUSTED_REV1", 0x62),
    "cp_bad": ("DSB3_CP_REV0", 0x63),
    "fence_bad": ("DSB1_FENCE_TYPED_REV_GEN_MISMATCH", 0x64),
    "head_bad": ("DSB1_HEAD_TYPED_HEAD_MISMATCH", 0x7D),
}

TYPED_SELECT: Dict[str, Tuple[str, int]] = {}
TYPED_SELECT.update(TYPED_SELECT_POS)
TYPED_SELECT.update(TYPED_SELECT_NEG)

WITNESS_HDR_OK = "DSW1_HDR_K01_ACTIVE"
WITNESS_HDR_BAD = "DSW1_HDR_CANON_CORRUPT"
WITNESS_CHUNK_OK = "DSW1_CREATE"
WITNESS_CHUNK_BAD = "DSW1_UNORDERED"

KNOWN_SUBTYPES = frozenset(CLOSED_CURRENT_SUBTYPES)


def be16(v: int) -> bytes:
    return struct.pack(">H", v)


def be32(v: int) -> bytes:
    return struct.pack(">I", v)


def be64(v: int) -> bytes:
    return struct.pack(">Q", v)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if (crc & 1) else (crc >> 1)
    return (~crc) & 0xFFFFFFFF


def sha256(data: bytes) -> bytes:
    """stdlib hashlib SHA-256 (oracle-side; does not invoke production C)."""
    return hashlib.sha256(data).digest()


def hex_of(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


def nlr1(record_type: int, record_version: int, payload: bytes) -> bytes:
    head = b"NLR1" + be16(record_type) + be16(record_version) + be32(len(payload))
    body = head + payload
    return body + be32(crc32c(body))


def composite_digest(subtype: int, components: bytes) -> bytes:
    return sha256(PREIMAGE_COMPOSITE + bytes([subtype & 0xFF]) + components)


def witness_identity_digest(op_kind: int, op_ident: bytes) -> bytes:
    components = be16(op_kind) + be16(len(op_ident)) + op_ident
    return composite_digest(0x7F, components)


def domain_key(
    family: int, subtype: int, identity_kind: int, identity: bytes
) -> bytes:
    return (
        ROOT_V1
        + bytes(
            [
                family & 0xFF,
                subtype & 0xFF,
                0x01,
                identity_kind & 0xFF,
                len(identity),
            ]
        )
        + identity
    )


def enc_env_full(
    rtype: int,
    st: int,
    flags: int,
    rev: int,
    primary_id: bytes,
    head: bytes,
    pvd: bytes,
    body: bytes,
    *,
    record_version: int = 1,
    domain_format: int = 1,
) -> bytes:
    assert len(primary_id) == 16 and len(head) == 32 and len(pvd) == 32
    if record_version != 1:
        return nlr1(rtype, record_version, body)
    payload = bytearray()
    payload += be16(domain_format) + bytes([st & 0xFF, flags & 0xFF]) + be64(rev)
    payload += primary_id + head + pvd + be32(len(body)) + body
    return nlr1(rtype, 1, bytes(payload))


def catalog_key(key_id: int) -> bytes:
    if key_id == 1:
        return ROOT_V1 + bytes([0x01])
    if key_id == 2:
        return ROOT_V1 + bytes([0x02])
    if 3 <= key_id <= 6:
        return ROOT_V1 + bytes([0x03, key_id - 2])
    if 7 <= key_id <= 17:
        return ROOT_V1 + bytes([0x04, key_id - 6])
    raise ValueError(key_id)


def default_binding_fields() -> Dict[str, Any]:
    rid = bytes(range(0x10, 0x20))
    return {
        "storage_schema": 1,
        "role": 1,
        "environment": 1,
        "runtime_id_hex": hex_of(rid),
        "limits": {
            "max_services": 7,
            "max_nonterminal_transactions": 20,
            "max_targets_per_transaction": 1,
            "max_logical_payload_bytes": 1000,
            "max_durable_outbox_payload_bytes": 5000,
            "max_attempts_per_target_per_cycle": 8,
            "max_cancel_attempts_per_transaction": 1,
            "max_evidence_per_target": 3,
            "max_retained_terminal_transactions": 30,
            "max_nonterminal_deliveries": 12,
            "max_event_spool_count": 0,
            "max_event_spool_bytes": 0,
            "max_result_cache_entries": 13,
            "max_retained_dispositions": 14,
            "max_ingress_per_step": 15,
            "max_callbacks_per_step": 16,
            "max_state_transitions_per_step": 17,
            "max_bearer_sends_per_step": 18,
            "max_deferred_tokens": 19,
        },
        "terminal_retention_ms": 0,
        "result_cache_retention_ms": 0,
        "observation_retention_ms": 0,
    }


def encode_binding(fields: Dict[str, Any]) -> bytes:
    lim = fields["limits"]
    payload = bytearray()
    payload += be32(1)
    payload += be16(25)
    payload += PROFILE_NAME
    payload += be32(int(fields["storage_schema"]))
    payload += be32(int(fields["role"]))
    payload += be32(int(fields["environment"]))
    payload += from_hex(fields["runtime_id_hex"])
    for name in (
        "max_services",
        "max_nonterminal_transactions",
        "max_targets_per_transaction",
        "max_logical_payload_bytes",
    ):
        payload += be32(int(lim[name]))
    payload += be64(int(lim["max_durable_outbox_payload_bytes"]))
    for name in (
        "max_attempts_per_target_per_cycle",
        "max_cancel_attempts_per_transaction",
        "max_evidence_per_target",
        "max_retained_terminal_transactions",
        "max_nonterminal_deliveries",
        "max_event_spool_count",
    ):
        payload += be32(int(lim[name]))
    payload += be64(int(lim["max_event_spool_bytes"]))
    for name in (
        "max_result_cache_entries",
        "max_retained_dispositions",
        "max_ingress_per_step",
        "max_callbacks_per_step",
        "max_state_transitions_per_step",
        "max_bearer_sends_per_step",
        "max_deferred_tokens",
    ):
        payload += be32(int(lim[name]))
    payload += be64(int(fields["terminal_retention_ms"]))
    payload += be64(int(fields["result_cache_retention_ms"]))
    payload += be64(int(fields["observation_retention_ms"]))
    assert len(payload) == 167
    enc = nlr1(1, 1, bytes(payload))
    assert len(enc) == 183
    return enc


def encode_identity() -> bytes:
    payload = bytearray()
    payload += be32(0x7)
    payload += bytes(range(0x20, 0x30))
    payload += bytes(range(0x40, 0x50))
    payload += bytes(range(0x60, 0x70))
    payload += be64(1)
    payload += be64(1)
    assert len(payload) == 68
    return nlr1(2, 1, bytes(payload))


def encode_counter(kind: int) -> bytes:
    return nlr1(3, 1, be32(kind) + be64(0) + be32(0))


def encode_capacity(kind: int, limit: int = 0) -> bytes:
    payload = (
        be32(kind)
        + be64(limit)
        + be64(0)
        + be64(0)
        + be64(0)
        + be64(1)
        + be32(0)
        + be32(0)
    )
    return nlr1(4, 1, payload)


def encode_all_profile_rows(
    binding_fields: Dict[str, Any],
    *,
    binding_version: int = 1,
    corrupt_key_id: Optional[int] = None,
) -> List[Dict[str, str]]:
    rows: List[Tuple[int, bytes, bytes]] = []
    for key_id in range(1, 18):
        key = catalog_key(key_id)
        if key_id == 1:
            if binding_version != 1:
                payload = encode_binding(binding_fields)[12:-4]
                value = nlr1(1, binding_version, payload)
            else:
                value = encode_binding(binding_fields)
            if corrupt_key_id == 1:
                value = value[:-1] + bytes([value[-1] ^ 0xFF])
        elif key_id == 2:
            value = encode_identity()
        elif 3 <= key_id <= 6:
            value = encode_counter(key_id - 2)
        else:
            value = encode_capacity(key_id - 6, limit=100 + key_id)
        rows.append((key_id, key, value))
    rows.sort(key=lambda r: r[1])
    return [{"key_hex": hex_of(k), "value_hex": hex_of(v)} for _, k, v in rows]


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_d1() -> Dict[str, Dict[str, Any]]:
    raw = D1_VECTORS.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != D1_SHA256:
        raise SystemExit(
            f"D1 authority SHA256 mismatch: got {digest} want {D1_SHA256}"
        )
    doc = json.loads(raw.decode("utf-8"))
    if doc.get("format") != D1_FORMAT:
        raise SystemExit(f"unexpected D1 format: {doc.get('format')}")
    vectors = doc["vectors"]
    if len(vectors) != D1_VECTOR_COUNT:
        raise SystemExit(
            f"D1 vector count mismatch: got {len(vectors)} want {D1_VECTOR_COUNT}"
        )
    return {v["id"]: v for v in vectors}


def assert_d1_selection(
    d1: Dict[str, Dict[str, Any]], vid: str, subtype: int, *, want_ok: bool
) -> Dict[str, Any]:
    if vid not in d1:
        raise SystemExit(f"D1 selection missing: {vid}")
    v = d1[vid]
    if not v.get("key_hex") or not v.get("value_hex"):
        raise SystemExit(f"D1 {vid}: missing key/value hex")
    status = v.get("expected_status")
    if want_ok and status != "OK":
        raise SystemExit(f"D1 {vid}: expected_status OK, got {status}")
    if not want_ok and status == "OK":
        raise SystemExit(f"D1 {vid}: expected non-OK corrupt status, got OK")
    st = int(v.get("subtype", -1))
    if st != subtype:
        raise SystemExit(f"D1 {vid}: subtype {st:#x} != {subtype:#x}")
    op = v.get("op", "")
    if want_ok or "TYPED" in vid or op == "typed_record":
        # typed selections must be typed_record; witness body uses other ops
        if op not in ("typed_record",) and "TYPED" in vid:
            raise SystemExit(f"D1 {vid}: unexpected op {op}")
    key = from_hex(v["key_hex"])
    if len(key) < 13 or key[9] != (subtype & 0xFF):
        raise SystemExit(f"D1 {vid}: key subtype mismatch")
    return v


def typed_row(
    d1: Dict[str, Dict[str, Any]], suffix: str, *, want_ok: bool
) -> Tuple[Dict[str, str], int]:
    vid, subtype = TYPED_SELECT[suffix]
    v = assert_d1_selection(d1, vid, subtype, want_ok=want_ok)
    return {"key_hex": v["key_hex"], "value_hex": v["value_hex"]}, subtype


def flip_crc(value_hex: str) -> str:
    b = bytearray(from_hex(value_hex))
    b[-1] ^= 0xFF
    return hex_of(bytes(b))


def build_witness_header_record(
    d1: Dict[str, Dict[str, Any]],
    *,
    corrupt_body: bool = False,
    flags: int = 0,
    rev: int = 1,
    primary_id: Optional[bytes] = None,
    head: Optional[bytes] = None,
    pvd: Optional[bytes] = None,
    rtype: int = 6,
    env_subtype: Optional[int] = None,
    key_identity: Optional[bytes] = None,
    key_subtype: int = 0x7F,
) -> Dict[str, str]:
    src = d1[WITNESS_HDR_BAD if corrupt_body else WITNESS_HDR_OK]
    body = from_hex(src["value_hex"])
    op_kind = int(src["operation_kind"])
    ident = from_hex(src["identity_hex"])
    identity = witness_identity_digest(op_kind, ident)
    if key_identity is not None:
        identity = key_identity
    key = domain_key(6, key_subtype, 5, identity)
    primary = identity[:16] if primary_id is None else primary_id
    head_b = bytes(32) if head is None else head
    pvd_b = bytes(32) if pvd is None else pvd
    st = key_subtype if env_subtype is None else env_subtype
    value = enc_env_full(
        rtype, st, flags, rev, primary, head_b, pvd_b, body
    )
    return {"key_hex": hex_of(key), "value_hex": hex_of(value)}


def build_witness_chunk_record(
    d1: Dict[str, Dict[str, Any]],
    *,
    corrupt_body: bool = False,
    flags: int = 0,
    rev: int = 1,
    primary_id: Optional[bytes] = None,
    head: Optional[bytes] = None,
    pvd: Optional[bytes] = None,
    rtype: int = 6,
    env_subtype: Optional[int] = None,
    key_identity: Optional[bytes] = None,
    key_subtype: int = 0x7E,
) -> Dict[str, str]:
    src = d1[WITNESS_CHUNK_BAD if corrupt_body else WITNESS_CHUNK_OK]
    body = from_hex(src["value_hex"])
    wdigest = body[:32]
    chunk_index = struct.unpack(">H", body[32:34])[0]
    identity = composite_digest(0x7E, wdigest + be16(chunk_index))
    if key_identity is not None:
        identity = key_identity
    key = domain_key(6, key_subtype, 5, identity)
    primary = identity[:16] if primary_id is None else primary_id
    head_b = bytes(32) if head is None else head
    pvd_b = bytes(32) if pvd is None else pvd
    st = key_subtype if env_subtype is None else env_subtype
    value = enc_env_full(
        rtype, st, flags, rev, primary, head_b, pvd_b, body
    )
    return {"key_hex": hex_of(key), "value_hex": hex_of(value)}


def future_version_domain_row(base: Dict[str, str]) -> Dict[str, str]:
    """Current key + valid NLR1 with record_version=2 → non-terminal UNSUPPORTED."""
    key = from_hex(base["key_hex"])
    payload = bytes(range(32))
    value = nlr1(6, 2, payload)
    return {"key_hex": hex_of(key), "value_hex": hex_of(value)}


def future_domain_format_row(base: Dict[str, str]) -> Dict[str, str]:
    """Current key + record_version=1 + domain_format=2 framing → UNSUPPORTED."""
    key = from_hex(base["key_hex"])
    payload = be16(2) + bytes(range(30))
    value = nlr1(6, 1, payload)
    return {"key_hex": hex_of(key), "value_hex": hex_of(value)}


def future_root_row() -> Dict[str, str]:
    key = ROOT_V1[:7] + bytes([0x02, 0xAA, 0x01])
    value = nlr1(6, 1, bytes(32))
    return {"key_hex": hex_of(key), "value_hex": hex_of(value)}


def domain_malformed_short_key() -> Dict[str, str]:
    key = ROOT_V1 + bytes([0x06, 0x10])  # incomplete current key
    return {"key_hex": hex_of(key), "value_hex": ""}


def unknown_subtype_row() -> Dict[str, str]:
    """Current-root family6 unknown subtype (0x12) — MALFORMED → CORRUPT."""
    identity = bytes(range(32))
    key = domain_key(6, 0x12, 5, identity)
    value = enc_env_full(6, 0x12, 0, 1, identity[:16], bytes(32), bytes(32), b"")
    return {"key_hex": hex_of(key), "value_hex": hex_of(value)}


def port_trace(n_domain: int, gets: int = 17) -> List[str]:
    t = ["begin:READ_ONLY"] + ["get"] * gets + ["iter_open:prefix0"]
    t += ["iter_next"] * (17 + n_domain)
    t += ["iter_close", "rollback"]
    return t


def expected_base(**kwargs: Any) -> Dict[str, Any]:
    base = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 0,
        "ok_row_count": 17,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": ALL_MASK,
        "family14_iter_seen_mask": ALL_MASK,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "port_trace": [],
    }
    base.update(kwargs)
    return base


def merge_rows(
    profile: List[Dict[str, str]], domain_rows: List[Dict[str, str]]
) -> List[Dict[str, str]]:
    all_rows = list(profile) + list(domain_rows)
    all_rows.sort(key=lambda r: from_hex(r["key_hex"]))
    return all_rows


def make_vec(
    *,
    vid: str,
    kind: str,
    candidate: Dict[str, Any],
    rows: List[Dict[str, str]],
    expected: Dict[str, Any],
    faults: Optional[List[Dict[str, Any]]] = None,
    calls: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if calls is None:
        calls = [
            {"op": "begin_profiled", "row_budget": 0},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize", "row_budget": 0},
        ]
    return {
        "id": vid,
        "kind": kind,
        "candidate_binding": candidate,
        "rows": rows,
        "faults": faults or [],
        "calls": calls,
        "expected": expected,
    }


def model_calls() -> List[Dict[str, Any]]:
    return [
        {"op": "begin_profiled"},
        {"op": "advance", "row_budget": 64},
        {"op": "finalize"},
    ]


def add_modeled(
    vectors: List[Dict[str, Any]],
    *,
    vid: str,
    kind: str,
    candidate: Dict[str, Any],
    rows: List[Dict[str, str]],
    faults: Optional[List[Dict[str, Any]]] = None,
) -> None:
    vec = {
        "candidate_binding": candidate,
        "rows": rows,
        "faults": faults or [],
        "calls": model_calls(),
    }
    vectors.append(
        make_vec(
            vid=vid,
            kind=kind,
            candidate=candidate,
            rows=rows,
            faults=faults,
            expected=run_case_model(vec),
        )
    )


def build_document() -> Dict[str, Any]:
    d1 = load_d1()
    # Pin S1 sibling without rewriting it.
    s1_digest = file_sha256(S1_VECTORS)
    if s1_digest != S1_SHA256:
        raise SystemExit(
            f"S1 authority SHA256 mismatch: got {s1_digest} want {S1_SHA256}"
        )
    s1_doc = json.loads(S1_VECTORS.read_text(encoding="utf-8"))
    if s1_doc.get("format") != S1_FORMAT:
        raise SystemExit(f"unexpected S1 format: {s1_doc.get('format')}")
    s1_ids = {v["id"] for v in s1_doc["vectors"]}
    for sid in S1_BODY_NONVALIDATION_IDS:
        if sid not in s1_ids:
            raise SystemExit(f"S1 body-nonvalidation vector missing: {sid}")

    candidate = default_binding_fields()
    profile = encode_all_profile_rows(candidate)
    vectors: List[Dict[str, Any]] = []
    covered: Set[int] = set()

    # --- Business + 7d positives (all closed catalog except 7e/7f) ---
    for suffix, (_vid, st) in TYPED_SELECT_POS.items():
        row, got_st = typed_row(d1, suffix, want_ok=True)
        assert got_st == st
        covered.add(st)
        add_modeled(
            vectors,
            vid=f"DSS3_POS_{suffix.upper()}",
            kind="structural_positive",
            candidate=candidate,
            rows=merge_rows(profile, [row]),
        )

    # --- D1 typed CORRUPT negatives (where available) ---
    for suffix, (_vid, st) in TYPED_SELECT_NEG.items():
        row, got_st = typed_row(d1, suffix, want_ok=False)
        assert got_st == st
        covered.add(st)
        add_modeled(
            vectors,
            vid=f"DSS3_NEG_{suffix.upper()}",
            kind="structural_corrupt",
            candidate=candidate,
            rows=merge_rows(profile, [row]),
        )

    # --- 7e / 7f local positives (head zero + head nonzero legal) ---
    for st, builder, tag in (
        (0x7F, build_witness_header_record, "WH"),
        (0x7E, build_witness_chunk_record, "WC"),
    ):
        covered.add(st)
        for head_tag, head in (
            ("HEAD0", bytes(32)),
            ("HEADNZ", bytes([0xA5]) * 32),
        ):
            row = builder(d1, head=head)
            add_modeled(
                vectors,
                vid=f"DSS3_{tag}_{head_tag}_OK",
                kind=(
                    "witness_header_local"
                    if st == 0x7F
                    else "witness_chunk_local"
                ),
                candidate=candidate,
                rows=merge_rows(profile, [row]),
            )
        # body matrix negative (D1 pure-body authority embedded in full row)
        row = builder(d1, corrupt_body=True)
        add_modeled(
            vectors,
            vid=f"DSS3_{tag}_BODY_BAD",
            kind=(
                "witness_header_local"
                if st == 0x7F
                else "witness_chunk_local"
            ),
            candidate=candidate,
            rows=merge_rows(profile, [row]),
        )
        # Independent header/envelope mutates → CORRUPT (scan reach evidence;
        # may overlap common_header_local_invariants / decode_envelope).
        # PRIMARY_MISMATCH stays envelope-primary-only (separate locus).
        # KEY_ID_MISMATCH is single-locus: key identity only; envelope
        # primary_id fixed to original identity[:16] so value is byte-identical
        # to the good row (production bridge must still observe CORRUPT).
        orig_ok = builder(d1)
        orig_identity = from_hex(orig_ok["key_hex"])[13:45]
        muts: List[Tuple[str, Dict[str, Any]]] = [
            ("FLAGS_NZ", {"flags": 1}),
            ("PVD_NZ", {"pvd": bytes([0x11]) * 32}),
            ("PRIMARY_MISMATCH", {"primary_id": bytes([0xFF]) * 16}),
            (
                "KEY_ID_MISMATCH",
                {
                    "key_identity": bytes([0x5A]) * 32,
                    "primary_id": orig_identity[:16],
                },
            ),
            ("SUBTYPE_MISMATCH", {"env_subtype": 0x10}),
            ("REV0", {"rev": 0}),
            ("RTYPE_MISMATCH", {"rtype": 5}),
        ]
        for mname, kwargs in muts:
            row = builder(d1, **kwargs)
            if mname == "KEY_ID_MISMATCH":
                # Generator assert: single-locus key bytes only; value exact.
                if row["value_hex"] != orig_ok["value_hex"]:
                    raise SystemExit(
                        f"KEY_ID_MISMATCH {tag}: value must equal original "
                        "(single-locus key identity only)"
                    )
                ok_key = from_hex(orig_ok["key_hex"])
                mut_key = from_hex(row["key_hex"])
                if (
                    len(ok_key) != len(mut_key)
                    or ok_key[:13] != mut_key[:13]
                    or mut_key[13:45] != bytes([0x5A]) * 32
                    or ok_key[13:45] == mut_key[13:45]
                ):
                    raise SystemExit(
                        f"KEY_ID_MISMATCH {tag}: key must differ only in "
                        "identity bytes"
                    )
            add_modeled(
                vectors,
                vid=f"DSS3_{tag}_{mname}",
                kind=(
                    "witness_header_local"
                    if st == 0x7F
                    else "witness_chunk_local"
                ),
                candidate=candidate,
                rows=merge_rows(profile, [row]),
            )
            if mname == "KEY_ID_MISMATCH":
                # Production bridge CORRUPT guarantee (oracle sticky status).
                if vectors[-1]["expected"]["final_status"] != "STORAGE_CORRUPT":
                    raise SystemExit(
                        f"KEY_ID_MISMATCH {tag}: expected STORAGE_CORRUPT "
                        f"got {vectors[-1]['expected']['final_status']}"
                    )

    # Malformed envelope CRC
    base_row, _ = typed_row(d1, "svc", want_ok=True)
    bad_crc = {
        "key_hex": base_row["key_hex"],
        "value_hex": flip_crc(base_row["value_hex"]),
    }
    add_modeled(
        vectors,
        vid="DSS3_MALFORMED_CRC",
        kind="structural_corrupt",
        candidate=candidate,
        rows=merge_rows(profile, [bad_crc]),
    )

    # record_version / domain_format future non-terminal
    fut = future_version_domain_row(base_row)
    add_modeled(
        vectors,
        vid="DSS3_FUTURE_RECORD_VERSION",
        kind="structural_unsupported",
        candidate=candidate,
        rows=merge_rows(profile, [fut]),
    )
    fut_df = future_domain_format_row(base_row)
    add_modeled(
        vectors,
        vid="DSS3_FUTURE_DOMAIN_FORMAT",
        kind="structural_unsupported",
        candidate=candidate,
        rows=merge_rows(profile, [fut_df]),
    )

    corrupt_row, _ = typed_row(d1, "es_bad", want_ok=False)
    # True precedence: record_version future on earlier current key, then corrupt
    add_modeled(
        vectors,
        vid="DSS3_FUTURE_VER_THEN_CORRUPT",
        kind="precedence",
        candidate=candidate,
        rows=merge_rows(profile, [fut, corrupt_row]),
    )
    # domain_format future then current corrupt
    add_modeled(
        vectors,
        vid="DSS3_FUTURE_DF_THEN_CORRUPT",
        kind="precedence",
        candidate=candidate,
        rows=merge_rows(profile, [fut_df, corrupt_row]),
    )
    # Future-root key is lexically after current root; rename matches reality:
    # current corrupt is observed first, then future root.
    add_modeled(
        vectors,
        vid="DSS3_CURRENT_CORRUPT_THEN_FUTURE_ROOT",
        kind="precedence",
        candidate=candidate,
        rows=merge_rows(profile, [future_root_row(), corrupt_row]),
    )

    # profile mismatch: domain malformed skipped (S3 not started)
    mismatch_cand = copy.deepcopy(candidate)
    mismatch_cand["role"] = 2
    add_modeled(
        vectors,
        vid="DSS3_PROFILE_MISMATCH_SKIP",
        kind="profile_skip",
        candidate=mismatch_cand,
        rows=merge_rows(profile, [domain_malformed_short_key()]),
    )

    # future_profile_candidate: binding record_version=2 → skip malformed domain
    fut_profile = encode_all_profile_rows(candidate, binding_version=2)
    add_modeled(
        vectors,
        vid="DSS3_FUTURE_PROFILE_SKIP_MALFORMED",
        kind="profile_skip",
        candidate=candidate,
        rows=merge_rows(fut_profile, [domain_malformed_short_key()]),
    )

    # lex duplicate
    pos_a, _ = typed_row(d1, "bearer", want_ok=True)
    add_modeled(
        vectors,
        vid="DSS3_LEX_DUPLICATE",
        kind="lex_regression",
        candidate=candidate,
        rows=merge_rows(profile, [pos_a, pos_a]),
    )

    # lex out-of-order (higher key presented before lower via unsorted rows
    # is fixed by merge; instead plant reverse domain order by custom rows)
    es_pos, _ = typed_row(d1, "es", want_ok=True)
    svc_pos, _ = typed_row(d1, "svc", want_ok=True)
    # Force storage order: es then svc (es key > svc key) → out-of-order
    ooo_rows = list(profile) + [es_pos, svc_pos]
    # Do NOT sort — storage presents out of order
    add_modeled(
        vectors,
        vid="DSS3_LEX_OUT_OF_ORDER",
        kind="lex_regression",
        candidate=candidate,
        rows=ooo_rows,
    )

    # value length 4097 → iter BUFFER_TOO_SMALL → CORRUPT
    # Fault on first domain iter_next after 17 profile rows: on_call = 18
    add_modeled(
        vectors,
        vid="DSS3_BTS_VALUE_4097",
        kind="bts_corrupt",
        candidate=candidate,
        rows=merge_rows(profile, [svc_pos]),
        faults=[
            {
                "op": "iter_next",
                "on_call": 18,
                "status": "BUFFER_TOO_SMALL",
                "shape": "bts",
                "key_length": 45,
                "value_length": 4097,
            }
        ],
    )

    # current-root unknown subtype → CORRUPT
    add_modeled(
        vectors,
        vid="DSS3_UNKNOWN_SUBTYPE",
        kind="structural_corrupt",
        candidate=candidate,
        rows=merge_rows(profile, [unknown_subtype_row()]),
    )

    # S1 transport body nonvalidation evidence (metadata / dsr2-style pin;
    # production S1 path is sibling oracle — not re-executed here).
    vectors.append(
        make_vec(
            vid="DSS3_S1_TRANSPORT_BODY_NONVALIDATION_PIN",
            kind="s1_evidence",
            candidate=candidate,
            rows=profile,
            expected=expected_base(
                ok_row_count=17,
                port_trace=port_trace(0),
            ),
        )
    )

    # workspace ceiling skeleton
    vectors.append(
        make_vec(
            vid="DSS3_DSR2_CEILING",
            kind="dsr2_ceiling",
            candidate=candidate,
            rows=profile,
            expected=expected_base(
                ok_row_count=17,
                port_trace=port_trace(0),
            ),
        )
    )

    missing = REQUIRED_SUBTYPES - covered
    if missing:
        raise SystemExit(
            f"catalog coverage incomplete: {sorted(hex(x) for x in missing)}"
        )
    # Closed list fixed equality (docs §7): required set == closed literal.
    if covered != REQUIRED_SUBTYPES:
        raise SystemExit(
            f"covered != required closed catalog: "
            f"extra={sorted(hex(x) for x in covered - REQUIRED_SUBTYPES)} "
            f"missing={sorted(hex(x) for x in REQUIRED_SUBTYPES - covered)}"
        )
    # Business+7d must all have positive scan reach
    pos_covered = {
        TYPED_SELECT_POS[s][1] for s in TYPED_SELECT_POS
    } | {0x7E, 0x7F}
    if not set(BUSINESS_AND_7D).issubset(pos_covered):
        raise SystemExit("business+7d positive coverage incomplete")

    doc = {
        "version": VERSION,
        "format": FORMAT,
        "scope": (
            "D2-S3 exact-profile family5/6 structural same-record scan path "
            "(typed business+7d + witness 7e/7f local). Closed catalog = "
            "family5 01 + family6 §7 table. Does not claim D2/DSR1/DSR2/"
            "Stage5/public Runtime/S4/D3 complete."
        ),
        "workspace": {
            "key_capacity": KEY_CAP,
            "value_capacity": VALUE_CAP,
            "previous_key_capacity": PREV_CAP,
            "ceiling_bytes": CEILING,
            "row_validate_scratch": "typed/witness union (sizeof workspace <= 8192)",
        },
        "d1_authority": {
            "path": "spec/vectors/domain-store-v1.json",
            "format": D1_FORMAT,
            "vector_count": D1_VECTOR_COUNT,
            "sha256": D1_SHA256,
            "composition": (
                "Independent authority: selected typed_record vectors supply "
                "literal key/value hex + expected_status/op/subtype. S3 does "
                "not reimplement D1 same-record; oracle composes scan framing "
                "expectations from authority status and independent envelope/"
                "witness/future derivation."
            ),
        },
        "s1_authority": {
            "path": "spec/vectors/domain-scan-v1.json",
            "format": S1_FORMAT,
            "sha256": S1_SHA256,
            "body_nonvalidation_vector_ids": list(S1_BODY_NONVALIDATION_IDS),
            "note": (
                "S1 transport begin classifies CURRENT domain keys without "
                "body structural validation (e.g. s1-65-rows empty values). "
                "Frozen sibling regression; S3 profiled path does not run "
                "transport begin."
            ),
        },
        "catalog_coverage": {
            "closed_subtypes_hex": [
                f"{s:02x}" for s in CLOSED_CURRENT_SUBTYPES
            ],
            "required_subtypes_hex": [
                f"{s:02x}" for s in sorted(REQUIRED_SUBTYPES)
            ],
            "covered_subtypes_hex": [f"{s:02x}" for s in sorted(covered)],
        },
        "vectors": vectors,
    }
    return doc


def run_case_model(vec: Dict[str, Any]) -> Dict[str, Any]:
    """Closed independent reference of profiled begin + S3 structural outcomes."""
    binding = vec["candidate_binding"]
    rows = [
        (from_hex(r["key_hex"]), from_hex(r["value_hex"]))
        for r in vec.get("rows", [])
    ]
    calls = vec["calls"]
    faults = list(vec.get("faults", []))

    exact_binding = encode_binding(binding)
    retained: Dict[int, bytes] = {}
    for kid in range(1, 18):
        if kid == 1:
            retained[kid] = exact_binding
        elif kid == 2:
            retained[kid] = encode_identity()
        elif 3 <= kid <= 6:
            retained[kid] = encode_counter(kid - 2)
        else:
            retained[kid] = encode_capacity(kid - 6, limit=100 + kid)

    snap: Dict[bytes, bytes] = {}
    for k, v in rows:
        snap[k] = v

    stored_binding = snap.get(catalog_key(1), retained[1])
    profile_exact = 0
    profile_mismatch = 0
    future_profile = 0
    sticky: Optional[str] = None
    present_mask = ALL_MASK

    def set_sticky(s: str) -> None:
        nonlocal sticky
        if sticky is None:
            sticky = s

    for kid in range(1, 18):
        key = catalog_key(kid)
        val = snap.get(key)
        if val is None:
            set_sticky("STORAGE_CORRUPT")
            present_mask = 0
            break
        if len(val) < 16 or val[:4] != b"NLR1":
            set_sticky("STORAGE_CORRUPT")
            break
        ver = struct.unpack(">H", val[6:8])[0]
        if ver != 1:
            future_profile = 1
        payload_len = struct.unpack(">I", val[8:12])[0]
        if 12 + payload_len + 4 != len(val):
            set_sticky("STORAGE_CORRUPT")
            break
        if struct.unpack(">I", val[12 + payload_len :])[0] != crc32c(
            val[: 12 + payload_len]
        ):
            set_sticky("STORAGE_CORRUPT")
            break
        retained[kid] = val

    if sticky is None and present_mask == ALL_MASK:
        if future_profile:
            profile_exact = 0
        else:
            if stored_binding == encode_binding(binding):
                profile_exact = 1
            else:
                profile_mismatch = 1

    port: List[str] = []
    state = "IDLE"
    family14 = 0
    current_dom = 0
    ok_rows = 0
    future_seen = 0
    seen_mask = 0
    has_previous = False
    previous = b""
    row_index = 0
    mutation_calls = 0
    close_count = 0
    reopen_required = 0
    iter_next_calls = 0
    used_faults: Set[int] = set()

    def find_fault(op: str, on_call: int) -> Optional[Dict[str, Any]]:
        for i, f in enumerate(faults):
            if i in used_faults:
                continue
            if f.get("op") == op and int(f.get("on_call", 0)) == on_call:
                used_faults.add(i)
                return f
        return None

    def catalog_id(key: bytes) -> Optional[int]:
        if len(key) == 9 and key[:8] == ROOT_V1 and key[8] == 0x01:
            return 1
        if len(key) == 9 and key[:8] == ROOT_V1 and key[8] == 0x02:
            return 2
        if (
            len(key) == 10
            and key[:8] == ROOT_V1
            and key[8] == 0x03
            and 1 <= key[9] <= 4
        ):
            return 2 + key[9]
        if (
            len(key) == 10
            and key[:8] == ROOT_V1
            and key[8] == 0x04
            and 1 <= key[9] <= 11
        ):
            return 6 + key[9]
        return None

    def f14_noncatalog(key: bytes) -> bool:
        if len(key) < 9 or key[:8] != ROOT_V1:
            return False
        if not (0x01 <= key[8] <= 0x04):
            return False
        return catalog_id(key) is None

    def is_known_current_key(key: bytes) -> bool:
        if len(key) < 13 or key[:8] != ROOT_V1:
            return False
        if not (13 <= len(key) <= 45):
            return False
        if key[10] != 1:
            return False
        fam, st = key[8], key[9]
        if fam == 5:
            return st == 0x01
        if fam == 6:
            return st in KNOWN_SUBTYPES and st != 0x01
        return False

    def is_future_root(key: bytes, value: bytes) -> bool:
        if len(key) < 8 or key[:7] != ROOT_V1[:7] or key[7] < 2:
            return False
        if not (16 <= len(value) <= 4096):
            return False
        if value[:4] != b"NLR1":
            return False
        payload_len = struct.unpack(">I", value[8:12])[0]
        if 12 + payload_len + 4 != len(value):
            return False
        return struct.unpack(">I", value[12 + payload_len :])[0] == crc32c(
            value[: 12 + payload_len]
        )

    # D1 composition authority for typed same-record outcomes
    d1 = load_d1()
    typed_status: Dict[Tuple[str, str], str] = {}
    for suffix, (vid, _st) in TYPED_SELECT.items():
        v = d1[vid]
        pair = (v["key_hex"], v["value_hex"])
        if v["expected_status"] == "OK":
            typed_status[pair] = "OK"
        else:
            typed_status[pair] = "CORRUPT"

    # Witness body authority (pure body status from D1) for matrix cases
    wh_body_ok = from_hex(d1[WITNESS_HDR_OK]["value_hex"])
    wh_body_bad = from_hex(d1[WITNESS_HDR_BAD]["value_hex"])
    wc_body_ok = from_hex(d1[WITNESS_CHUNK_OK]["value_hex"])
    wc_body_bad = from_hex(d1[WITNESS_CHUNK_BAD]["value_hex"])

    def primary_id_from_composite_identity(identity: bytes) -> bytes:
        return identity[:16]

    def witness_structural_outcome(
        key: bytes, value: bytes, subtype: int
    ) -> str:
        """Independent framing/status derivation for 7e/7f (not whitelist)."""
        if not is_known_current_key(key) or key[9] != subtype:
            return "CORRUPT"
        if key[11] != 5 or key[12] != 32:
            return "CORRUPT"
        identity = key[13:45]
        if len(value) < 16 or value[:4] != b"NLR1":
            return "CORRUPT"
        rtype = struct.unpack(">H", value[4:6])[0]
        ver = struct.unpack(">H", value[6:8])[0]
        payload_len = struct.unpack(">I", value[8:12])[0]
        if payload_len != len(value) - 16:
            return "CORRUPT"
        if struct.unpack(">I", value[12 + payload_len :])[0] != crc32c(
            value[: 12 + payload_len]
        ):
            return "CORRUPT"
        if ver == 0:
            return "CORRUPT"
        if ver != 1:
            return "UNSUPPORTED"
        if payload_len < 2:
            return "CORRUPT"
        df = struct.unpack(">H", value[12:14])[0]
        if df == 0:
            return "CORRUPT"
        if df != 1:
            return "UNSUPPORTED"
        # Full common header required for domain_format==1
        if payload_len < 96:
            return "CORRUPT"
        env_st = value[14]
        flags = value[15]
        rev = struct.unpack(">Q", value[16:24])[0]
        primary = value[24:40]
        head = value[40:72]
        pvd = value[72:104]
        body_len = struct.unpack(">I", value[104:108])[0]
        if payload_len != 96 + body_len:
            return "CORRUPT"
        body = value[108 : 108 + body_len]
        if rtype != 6:
            return "CORRUPT"
        if env_st != subtype:
            return "CORRUPT"
        if flags != 0:
            return "CORRUPT"
        if rev == 0:
            return "CORRUPT"
        if any(pvd):
            return "CORRUPT"
        if primary != primary_id_from_composite_identity(identity):
            return "CORRUPT"
        # Body matrix: recompute identity from body; corrupt D1 bodies fail.
        if subtype == 0x7F:
            if body == wh_body_bad:
                return "CORRUPT"
            if body != wh_body_ok:
                # Unknown body: still require key identity match if decodable.
                # Without full witness decode, treat non-authority body as CORRUPT
                # unless identity matches a recomputation we can do from known OK.
                return "CORRUPT"
            # Recompute identity from OK body fields (op_kind + identity_hex)
            src = d1[WITNESS_HDR_OK]
            expect_id = witness_identity_digest(
                int(src["operation_kind"]), from_hex(src["identity_hex"])
            )
            if identity != expect_id:
                return "CORRUPT"
        else:
            if body == wc_body_bad:
                return "CORRUPT"
            if body != wc_body_ok:
                return "CORRUPT"
            expect_id = composite_digest(
                0x7E, body[:32] + body[32:34]
            )
            if identity != expect_id:
                return "CORRUPT"
        # head zero or nonzero both legal for witness
        _ = head
        return "OK"

    def domain_outcome(key: bytes, value: bytes) -> str:
        if is_future_root(key, value):
            return "FUTURE_ROOT"
        pair = (hex_of(key), hex_of(value))
        if pair in typed_status:
            return typed_status[pair]
        # Known current witness subtypes: independent framing derivation
        if is_known_current_key(key) and key[9] in (0x7E, 0x7F):
            return witness_structural_outcome(key, value, key[9])
        # Synthetic futures / crc / unknown
        if len(key) >= 8 and key[:8] == ROOT_V1:
            if not is_known_current_key(key):
                # current-root shape but unknown subtype / malformed fields
                return "CORRUPT"
            if len(value) >= 16 and value[:4] == b"NLR1":
                ver = struct.unpack(">H", value[6:8])[0]
                payload_len = struct.unpack(">I", value[8:12])[0]
                if payload_len == len(value) - 16:
                    crc_ok = (
                        struct.unpack(">I", value[12 + payload_len :])[0]
                        == crc32c(value[: 12 + payload_len])
                    )
                    if not crc_ok:
                        return "CORRUPT"
                    if ver == 0:
                        return "CORRUPT"
                    if ver > 1:
                        return "UNSUPPORTED"
                    if payload_len >= 2:
                        df = struct.unpack(">H", value[12:14])[0]
                        if df == 0:
                            return "CORRUPT"
                        if df != 1:
                            return "UNSUPPORTED"
            return "CORRUPT"
        if is_future_root(key, value):
            return "FUTURE_ROOT"
        return "CORRUPT"

    for call in calls:
        op = call["op"]
        if op == "begin_profiled":
            # sticky set during profile GET validation → terminal without iter.
            if sticky is not None:
                state = "DONE"
                port = ["begin:READ_ONLY"] + ["get"] * 17 + ["rollback"]
                continue
            port = ["begin:READ_ONLY"] + ["get"] * 17
            port.append("iter_open:prefix0")
            state = "OPEN"
            if profile_mismatch or future_profile:
                profile_exact = 0
            continue
        if op == "advance":
            if state != "OPEN" or sticky is not None:
                continue
            budget = int(call.get("row_budget", 0))
            if budget == 0:
                set_sticky("INVALID_ARGUMENT")
                continue
            processed = 0
            while processed < budget and sticky is None:
                iter_next_calls += 1
                port.append("iter_next")
                f = find_fault("iter_next", iter_next_calls)
                if f is not None:
                    shape = f.get("shape", "natural")
                    if shape in ("bts", "not_found_poison"):
                        set_sticky("STORAGE_CORRUPT")
                        break
                    if shape == "io_error":
                        set_sticky("STORAGE")
                        break
                if row_index >= len(rows):
                    if seen_mask != present_mask:
                        set_sticky("STORAGE_CORRUPT")
                    else:
                        state = "EXHAUSTED"
                    break
                key, value = rows[row_index]
                row_index += 1
                if has_previous:
                    if key <= previous:
                        set_sticky("STORAGE_CORRUPT")
                        break
                cid = catalog_id(key)
                if cid is not None:
                    bit = 1 << (cid - 1)
                    if seen_mask & bit:
                        set_sticky("STORAGE_CORRUPT")
                        break
                    ret = retained[cid]
                    if value != ret:
                        set_sticky("STORAGE_CORRUPT")
                        break
                    seen_mask |= bit
                    family14 += 1
                elif f14_noncatalog(key):
                    set_sticky("STORAGE_CORRUPT")
                    break
                elif profile_mismatch or future_profile:
                    pass  # skip domain structural / no decode
                elif profile_exact:
                    out = domain_outcome(key, value)
                    if out == "OK":
                        current_dom += 1
                    elif out == "UNSUPPORTED":
                        future_seen = 1
                        current_dom += 1
                    elif out == "FUTURE_ROOT":
                        future_seen = 1
                    else:
                        set_sticky("STORAGE_CORRUPT")
                        break
                else:
                    if is_known_current_key(key):
                        current_dom += 1
                    elif is_future_root(key, value):
                        future_seen = 1
                    else:
                        set_sticky("STORAGE_CORRUPT")
                        break
                previous = key
                has_previous = True
                ok_rows += 1
                processed += 1
            if sticky is not None:
                state = "FAILED"
            continue
        if op == "finalize":
            port.append("iter_close")
            port.append("rollback")
            if sticky is not None:
                final = sticky
                adopted = 0
            elif profile_mismatch or future_profile:
                final = "UNSUPPORTED"
                adopted = 0
            elif future_seen:
                final = "UNSUPPORTED"
                adopted = 0
            else:
                final = "OK"
                adopted = 1
            state = "DONE"
            return expected_base(
                final_status=final,
                adopted=adopted,
                state_after=state,
                recognizable_future_seen=future_seen,
                family14_row_count=family14,
                current_domain_key_count=current_dom,
                ok_row_count=ok_rows,
                profile_exact_active=1 if profile_exact else 0,
                profile_mismatch=1 if profile_mismatch else 0,
                future_profile_candidate=1 if future_profile else 0,
                profile_get_present_mask=present_mask,
                family14_iter_seen_mask=seen_mask,
                reopen_required=reopen_required,
                close_count=close_count,
                mutation_calls=mutation_calls,
                port_trace=port,
            )
    return expected_base(final_status="OK", adopted=0, state_after=state)


def generate(path: Path) -> None:
    doc = build_document()
    for vec in doc["vectors"]:
        if vec["kind"] in ("dsr2_ceiling", "s1_evidence"):
            # Recompute with model for profile-only rows
            vec["expected"] = run_case_model(vec)
            continue
        vec["expected"] = run_case_model(vec)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote {path} ({len(doc['vectors'])} vectors)")


def check(path: Path) -> int:
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    expected = build_document()
    for vec in expected["vectors"]:
        vec["expected"] = run_case_model(vec)
    if on_disk.get("format") != FORMAT or on_disk.get("version") != VERSION:
        print("format/version mismatch", file=sys.stderr)
        return 1
    kinds = {v["kind"] for v in on_disk["vectors"]}
    missing = REQUIRED_KINDS - kinds
    if missing:
        print(f"missing kinds: {sorted(missing)}", file=sys.stderr)
        return 1
    cov = on_disk.get("catalog_coverage", {})
    closed = cov.get("closed_subtypes_hex", [])
    req = set(cov.get("required_subtypes_hex", []))
    got = set(cov.get("covered_subtypes_hex", []))
    need_list = [f"{s:02x}" for s in CLOSED_CURRENT_SUBTYPES]
    need = set(need_list)
    if closed != need_list:
        print(
            f"closed list != docs table order: {closed} vs {need_list}",
            file=sys.stderr,
        )
        return 1
    if req != need or got != need:
        print(
            f"catalog coverage failed: req={sorted(req)} got={sorted(got)} "
            f"need={sorted(need)}",
            file=sys.stderr,
        )
        return 1
    d1a = on_disk.get("d1_authority", {})
    if (
        d1a.get("format") != D1_FORMAT
        or d1a.get("vector_count") != D1_VECTOR_COUNT
        or d1a.get("sha256") != D1_SHA256
    ):
        print("d1_authority pin mismatch", file=sys.stderr)
        return 1
    s1a = on_disk.get("s1_authority", {})
    if (
        s1a.get("format") != S1_FORMAT
        or s1a.get("sha256") != S1_SHA256
        or set(s1a.get("body_nonvalidation_vector_ids", []))
        != set(S1_BODY_NONVALIDATION_IDS)
    ):
        print("s1_authority pin mismatch", file=sys.stderr)
        return 1
    if on_disk.get("workspace", {}).get("ceiling_bytes") != CEILING:
        print("ceiling mismatch", file=sys.stderr)
        return 1
    if json.dumps(on_disk, sort_keys=True) != json.dumps(
        expected, sort_keys=True
    ):
        print(
            "document not deterministically equal to generator output",
            file=sys.stderr,
        )
        for a, b in zip(on_disk.get("vectors", []), expected.get("vectors", [])):
            if a != b:
                print(
                    f" first differ id on_disk={a.get('id')} exp={b.get('id')}",
                    file=sys.stderr,
                )
                if a.get("expected") != b.get("expected"):
                    print(
                        "  expected differ",
                        a.get("expected"),
                        b.get("expected"),
                        file=sys.stderr,
                    )
                break
        if len(on_disk.get("vectors", [])) != len(expected.get("vectors", [])):
            print(
                f" vector count on_disk={len(on_disk.get('vectors', []))} "
                f"exp={len(expected.get('vectors', []))}",
                file=sys.stderr,
            )
        return 1
    print(f"ok: {path} ({len(on_disk['vectors'])} vectors)")
    return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = doc["vectors"]
    max_key = 0
    max_val = 0
    for vec in vectors:
        for r in vec.get("rows", []):
            max_key = max(max_key, len(from_hex(r.get("key_hex", ""))))
            max_val = max(max_val, len(from_hex(r.get("value_hex", ""))))
    max_key = max(max_key, 45)
    max_val = max(max_val, 1024)
    max_rows = max(len(v.get("rows", [])) for v in vectors)
    max_calls = max(len(v.get("calls", [])) for v in vectors)
    max_faults = max((len(v.get("faults", [])) for v in vectors), default=0)
    max_trace = max(
        len(v["expected"].get("port_trace", [])) for v in vectors
    )

    lines: List[str] = []
    lines.append(
        "/* GENERATED by tools/domain_scan_structural_vector_gen.py — do not edit. */"
    )
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_STRUCTURAL_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_STRUCTURAL_VECTOR_FIXTURE_H")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(f"#define NINLIL_DSS_VECTOR_COUNT ((size_t){len(vectors)}u)")
    lines.append(f"#define NINLIL_DSS_MAX_ROWS ((size_t){max_rows}u)")
    lines.append(f"#define NINLIL_DSS_MAX_CALLS ((size_t){max_calls}u)")
    lines.append(
        f"#define NINLIL_DSS_MAX_FAULTS ((size_t){max(max_faults, 1)}u)"
    )
    lines.append(f"#define NINLIL_DSS_MAX_KEY ((size_t){max_key}u)")
    lines.append(f"#define NINLIL_DSS_MAX_VALUE ((size_t){max_val}u)")
    lines.append(
        f"#define NINLIL_DSS_MAX_TRACE ((size_t){max(max_trace, 1)}u)"
    )
    ceiling = int(doc.get("workspace", {}).get("ceiling_bytes", CEILING))
    lines.append(
        f"#define NINLIL_DSS_WORKSPACE_CEILING_BYTES ((uint32_t){ceiling}u)"
    )
    lines.append("")
    lines.append("typedef struct ninlil_dss_row {")
    lines.append("    uint8_t key[NINLIL_DSS_MAX_KEY];")
    lines.append("    uint32_t key_length;")
    lines.append("    uint8_t value[NINLIL_DSS_MAX_VALUE];")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dss_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dss_fault {")
    lines.append("    const char *op;")
    lines.append("    uint32_t on_call;")
    lines.append("    const char *shape;")
    lines.append("    uint32_t key_length;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dss_fault_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dss_call {")
    lines.append("    const char *op;")
    lines.append("    uint32_t row_budget;")
    lines.append("} ninlil_dss_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dss_binding {")
    lines.append("    uint32_t storage_schema;")
    lines.append("    uint32_t role;")
    lines.append("    uint32_t environment;")
    lines.append("    uint8_t runtime_id[16];")
    lines.append("    uint32_t max_services;")
    lines.append("    uint32_t max_nonterminal_transactions;")
    lines.append("    uint32_t max_targets_per_transaction;")
    lines.append("    uint32_t max_logical_payload_bytes;")
    lines.append("    uint64_t max_durable_outbox_payload_bytes;")
    lines.append("    uint32_t max_attempts_per_target_per_cycle;")
    lines.append("    uint32_t max_cancel_attempts_per_transaction;")
    lines.append("    uint32_t max_evidence_per_target;")
    lines.append("    uint32_t max_retained_terminal_transactions;")
    lines.append("    uint32_t max_nonterminal_deliveries;")
    lines.append("    uint32_t max_event_spool_count;")
    lines.append("    uint64_t max_event_spool_bytes;")
    lines.append("    uint32_t max_result_cache_entries;")
    lines.append("    uint32_t max_retained_dispositions;")
    lines.append("    uint32_t max_ingress_per_step;")
    lines.append("    uint32_t max_callbacks_per_step;")
    lines.append("    uint32_t max_state_transitions_per_step;")
    lines.append("    uint32_t max_bearer_sends_per_step;")
    lines.append("    uint32_t max_deferred_tokens;")
    lines.append("    uint64_t terminal_retention_ms;")
    lines.append("    uint64_t result_cache_retention_ms;")
    lines.append("    uint64_t observation_retention_ms;")
    lines.append("} ninlil_dss_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dss_expected {")
    lines.append("    const char *final_status;")
    lines.append("    uint32_t adopted;")
    lines.append("    const char *state_after;")
    lines.append("    uint8_t recognizable_future_seen;")
    lines.append("    uint64_t family14_row_count;")
    lines.append("    uint64_t current_domain_key_count;")
    lines.append("    uint64_t ok_row_count;")
    lines.append("    uint8_t profile_exact_active;")
    lines.append("    uint8_t profile_mismatch;")
    lines.append("    uint8_t future_profile_candidate;")
    lines.append("    uint32_t profile_get_present_mask;")
    lines.append("    uint32_t family14_iter_seen_mask;")
    lines.append("    uint32_t reopen_required;")
    lines.append("    uint32_t close_count;")
    lines.append("    uint32_t mutation_calls;")
    lines.append("    const char *const *port_trace;")
    lines.append("    size_t port_trace_count;")
    lines.append("} ninlil_dss_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dss_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    ninlil_dss_binding_t candidate;")
    lines.append("    const ninlil_dss_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_dss_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_dss_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_dss_expected_t expected;")
    lines.append("} ninlil_dss_vector_t;")
    lines.append("")

    def binding_literal(b: Dict[str, Any]) -> str:
        rid = from_hex(b["runtime_id_hex"])
        rids = ", ".join(f"0x{x:02x}u" for x in rid)
        lim = b["limits"]
        return (
            f"{{ {int(b['storage_schema'])}u, {int(b['role'])}u, "
            f"{int(b['environment'])}u, "
            f"{{ {rids} }}, "
            f"{int(lim['max_services'])}u, "
            f"{int(lim['max_nonterminal_transactions'])}u, "
            f"{int(lim['max_targets_per_transaction'])}u, "
            f"{int(lim['max_logical_payload_bytes'])}u, "
            f"{int(lim['max_durable_outbox_payload_bytes'])}ull, "
            f"{int(lim['max_attempts_per_target_per_cycle'])}u, "
            f"{int(lim['max_cancel_attempts_per_transaction'])}u, "
            f"{int(lim['max_evidence_per_target'])}u, "
            f"{int(lim['max_retained_terminal_transactions'])}u, "
            f"{int(lim['max_nonterminal_deliveries'])}u, "
            f"{int(lim['max_event_spool_count'])}u, "
            f"{int(lim['max_event_spool_bytes'])}ull, "
            f"{int(lim['max_result_cache_entries'])}u, "
            f"{int(lim['max_retained_dispositions'])}u, "
            f"{int(lim['max_ingress_per_step'])}u, "
            f"{int(lim['max_callbacks_per_step'])}u, "
            f"{int(lim['max_state_transitions_per_step'])}u, "
            f"{int(lim['max_bearer_sends_per_step'])}u, "
            f"{int(lim['max_deferred_tokens'])}u, "
            f"{int(b['terminal_retention_ms'])}ull, "
            f"{int(b['result_cache_retention_ms'])}ull, "
            f"{int(b['observation_retention_ms'])}ull }}"
        )

    for vi, vec in enumerate(vectors):
        lines.append(f"static const ninlil_dss_row_t ninlil_dss_rows_{vi}[] = {{")
        for r in vec.get("rows", []):
            kb = from_hex(r.get("key_hex", ""))
            vb = from_hex(r.get("value_hex", ""))
            if len(kb) > max_key or len(vb) > max_val:
                raise SystemExit(f"row too large: {vec['id']}")
            karr = ", ".join(f"0x{b:02x}u" for b in kb) if kb else "0"
            varr = ", ".join(f"0x{b:02x}u" for b in vb) if vb else "0"
            lines.append(
                f"    {{{{ {karr} }}, {len(kb)}u, {{ {varr} }}, {len(vb)}u }},"
            )
        if not vec.get("rows"):
            lines.append("    { { 0u }, 0u, { 0u }, 0u },")
        lines.append("};")
        lines.append(
            f"static const ninlil_dss_fault_t ninlil_dss_faults_{vi}[] = {{"
        )
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f["op"]}", {int(f["on_call"])}u, '
                f'"{f.get("shape", "natural")}", '
                f'{int(f.get("key_length", 0))}u, '
                f'{int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append("    { NULL, 0u, NULL, 0u, 0u },")
        lines.append("};")
        lines.append(
            f"static const ninlil_dss_call_t ninlil_dss_calls_{vi}[] = {{"
        )
        for c in vec["calls"]:
            lines.append(
                f'    {{ "{c["op"]}", {int(c.get("row_budget", 0))}u }},'
            )
        lines.append("};")
        exp = vec["expected"]
        lines.append(f"static const char *const ninlil_dss_trace_{vi}[] = {{")
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append("    NULL")
        lines.append("};")
        lines.append("")

    lines.append(
        "static const ninlil_dss_vector_t "
        "ninlil_dss_vectors[NINLIL_DSS_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(vectors):
        exp = vec["expected"]
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(
            f"        ninlil_dss_rows_{vi}, {len(vec.get('rows', []))}u,"
        )
        lines.append(
            f"        ninlil_dss_faults_{vi}, "
            f"{len(vec.get('faults', []))}u,"
        )
        lines.append(
            f"        ninlil_dss_calls_{vi}, {len(vec['calls'])}u,"
        )
        lines.append("        {")
        lines.append(f'            "{exp["final_status"]}",')
        lines.append(f"            {int(exp['adopted'])}u,")
        lines.append(f'            "{exp["state_after"]}",')
        lines.append(f"            {int(exp['recognizable_future_seen'])}u,")
        lines.append(f"            {int(exp['family14_row_count'])}ull,")
        lines.append(
            f"            {int(exp['current_domain_key_count'])}ull,"
        )
        lines.append(f"            {int(exp['ok_row_count'])}ull,")
        lines.append(f"            {int(exp['profile_exact_active'])}u,")
        lines.append(f"            {int(exp['profile_mismatch'])}u,")
        lines.append(
            f"            {int(exp['future_profile_candidate'])}u,"
        )
        lines.append(
            f"            0x{int(exp['profile_get_present_mask']):x}u,"
        )
        lines.append(
            f"            0x{int(exp['family14_iter_seen_mask']):x}u,"
        )
        lines.append(f"            {int(exp['reopen_required'])}u,")
        lines.append(f"            {int(exp.get('close_count', 0))}u,")
        lines.append(f"            {int(exp['mutation_calls'])}u,")
        lines.append(
            f"            ninlil_dss_trace_{vi}, "
            f"{len(exp.get('port_trace', []))}u"
        )
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_STRUCTURAL_VECTOR_FIXTURE_H */")
    lines.append("")
    header_path.parent.mkdir(parents=True, exist_ok=True)
    header_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {header_path} ({len(vectors)} vectors)")


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "generate":
        if len(argv) != 3:
            print("usage: generate <path>", file=sys.stderr)
            return 2
        generate(Path(argv[2]))
        return 0
    if cmd == "check":
        if len(argv) != 3:
            print("usage: check <path>", file=sys.stderr)
            return 2
        return check(Path(argv[2]))
    if cmd == "emit-c-fixture":
        if len(argv) != 4:
            print("usage: emit-c-fixture <json> <header>", file=sys.stderr)
            return 2
        emit_c_fixture(Path(argv[2]), Path(argv[3]))
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
