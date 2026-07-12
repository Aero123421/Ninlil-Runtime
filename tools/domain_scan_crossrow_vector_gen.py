#!/usr/bin/env python3
"""Independent D3-S1 domain-scan crossrow vector oracle (stdlib only).

Does NOT invoke, import, link, or translate production C scanner/codec.
Builds exact-1 relationship / peer PVD / reverse-primary cases using
independent NLR1/CRC32C/profile encoding and a closed reference model of
docs/17 §18.12 (D3-S1a) evaluator order.

Usage:
  python3 tools/domain_scan_crossrow_vector_gen.py generate <path>
  python3 tools/domain_scan_crossrow_vector_gen.py check <path>
  python3 tools/domain_scan_crossrow_vector_gen.py emit-c-fixture <json> <header>
  python3 tools/domain_scan_crossrow_vector_gen.py self-test
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FORMAT = "ninlil-domain-scan-crossrow-v1-d3s1"
VERSION = 1
ROOT_V1 = bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x01])
PROFILE_NAME = b"NINLIL-FOUNDATION-SMALL-1"
KEY_CAP = 255
VALUE_CAP = 4096
PREV_CAP = 255
CEILING = 8192
ALL_MASK = 0x1FFFF
PVD_OFF = 72
HEADER_SUBTYPE_OFF = 14  # NLR1(4)+type(2)+ver(2)+len(4)+hdr_ver(2) → subtype byte

REPO_ROOT = Path(__file__).resolve().parents[1]
S1_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-v1.json"
S2_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-profile-v1.json"
S3_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-structural-v1.json"
S4_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-exact-get-v1.json"
S5_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-composition-v1.json"
D1_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-store-v1.json"

S1_FORMAT = "ninlil-domain-scan-v1-d2s1"
S1_SHA256 = (
    "5705363e8f8890849e41476013eab3cd4ac1a20b6c33efb54ab65f300d40a165"
)
S1_COUNT = 18
S2_FORMAT = "ninlil-domain-scan-profile-v1-d2s2"
S2_SHA256 = (
    "b0ecac1d4d56e0abb63c53277ed5b1ab86a3e3c1377ad2393de6f4d74edcd0a5"
)
S2_COUNT = 32
S3_FORMAT = "ninlil-domain-scan-structural-v1-d2s3"
S3_SHA256 = (
    "f8e75437202c90476aa93fb0a336c86ad03e7e4820510e15074a69cbc6041684"
)
S3_COUNT = 89
S4_FORMAT = "ninlil-domain-scan-exact-get-v1-d2s4"
S4_SHA256 = (
    "5f458424a2f2adc1fd421285853b7567a9cc6fbf9ba43808b4d8dec69e4b9a8a"
)
S4_COUNT = 30
S5_FORMAT = "ninlil-domain-scan-composition-v1-d2s5"
S5_SHA256 = (
    "9492b40771d4e30a3a24e0e23110da2ecb91ceaa286d169cc90186545085d549"
)
S5_COUNT = 22
D1_FORMAT = "ninlil-domain-store-v1-d1b3o"
D1_SHA256 = (
    "b809c223f8208111fb4271cdceed031193e32e0f118e019d404ac538c89792b4"
)
D1_COUNT = 1549

# Deterministic artifact pin: updated when vectors are intentionally extended.
EXPECTED_VECTOR_COUNT = 94

REQUIRED_KINDS = frozenset(
    {
        # Modes 1–16 forward present_ok
        "mode1_present_ok",
        "mode2_present_ok",
        "mode3_present_ok",
        "mode4_present_ok",
        "mode5_dual_raw_present_ok",
        "mode5_dual_raw_mismatch_corrupt",
        "mode6_present_ok",
        "mode7_present_ok",
        "mode8_ds_absent_ok",
        "mode8_ef_present_ok",
        "mode9_ds_absent_ok",
        "mode9_ef_present_ok",
        "mode10_ds_present_ok",
        "mode10_ef_absent_ok",
        "mode11_present_ok",
        "mode12_present_ok",
        "mode13_present_ok",
        "mode14_ds_present_ok",
        "mode14_ef_absent_ok",
        "mode15_present_ok",
        "mode16_new_delivery_present_ok",
        "mode16_existing_tx_present_ok",
        "mode16_existing_delivery_present_ok",
        "mode16_kind_raw_mismatch_corrupt",
        # Mode1+ missing peer
        "mode1_missing_peer_corrupt",
        # Mode17 reverse inventory
        "mode17_quota_to_service",
        "mode17_res_service",
        "mode17_res_transaction",
        "mode17_res_ingress",
        "mode17_res_delivery",
        "mode17_res_callback_to_delivery",
        "mode17_seq_to_anchor",
        "mode17_state_to_anchor",
        "mode17_idem_to_anchor",
        "mode17_evmap_to_anchor",
        "mode17_evspool_to_anchor",
        "mode17_retry_to_anchor",
        "mode17_mgmt_to_anchor",
        "mode17_sched_tx_to_anchor",
        "mode17_sched_dlv_to_delivery",
        "mode17_sched_ing_to_ingress",
        "mode17_attempt_tx_to_owner",
        "mode17_attempt_dlv_to_owner",
        "mode17_aii_to_anchor",
        "mode17_cancel_tx_to_owner",
        "mode17_cancel_dlv_to_owner",
        "mode17_evidence_tx_to_owner",
        "mode17_evidence_dlv_to_owner",
        "mode17_rc_to_delivery",
        "mode17_rr_to_delivery",
        "mode17_rb_tx_to_subject",
        "mode17_rb_dlv_to_subject",
        "mode17_cp_tx_to_subject",
        "mode17_cp_dlv_to_subject",
        "mode17_absent_primary_corrupt",
        "mode17_pvd_mismatch_corrupt",
        "mode17_idem_dual_raw_mismatch_corrupt",
        # Mode18
        "mode18_attempt_to_index_present",
        "mode18_index_to_attempt_present",
        "mode18_missing_peer_corrupt",
        "mode18_mismatch_corrupt",
        "mode18_delivery_attempt_absent_ok",
        "mode18_delivery_attempt_unexpected_present_corrupt",
        # Mode19
        "mode19_active_present_ok",
        "mode19_active_missing_corrupt",
        "mode19_nonactive_unexpected_present_corrupt",
        "mode19_wrong_peer_pvd_still_ok",
        # Mode20
        "mode20_tx_active_absent_ok",
        "mode20_tx_terminal_present_ok",
        "mode20_tx_terminal_missing_corrupt",
        "mode20_rc_inbox_absent_ok",
        "mode20_rc_started_absent_ok",
        "mode20_rc_recovery_absent_ok",
        "mode20_rc_result_present_ok",
        "mode20_rc_disp_present_ok",
        "mode20_rc_cancel_present_ok",
        "mode20_rc_result_missing_corrupt",
        "mode20_subject_raw_mismatch_corrupt",
        "mode20_active_retention_unexpected_present_corrupt",
        "mode20_reconcile_wait_impossible",
        # Residuals / lifecycle
        "port_failure_no_note",
        "profile_mismatch_skip",
        "profile_future_skip",
        "mode_restart",
        "begin_mode1_smoke",
        "begin_mode20_smoke",
        "d2_begin_profiled_no_d3",
        "begin_mode0_invalid",
        "begin_mode21_invalid",
        "begin_context_null",
        "begin_alias_poison",
        "future_primary_pvd_match_ok",
        "future_primary_pvd_mismatch_corrupt",
        "mutation_zero",
    }
)

SCANNER_CALL_OPS = frozenset(
    {
        "begin_profiled",  # D2-only; no D3 mode/context
        "begin_profiled_d3s1",  # D3-S1; mode 1..20 + context
        "advance",
        "exact_get",
        "note_terminal_corrupt",
        "finalize",
        "abort",
    }
)
HARNESS_CALL_OPS = frozenset({"session_init", "use_rows", "handle_drift"})
CLOSED_CALL_OPS = SCANNER_CALL_OPS | HARNESS_CALL_OPS
FORBIDDEN_CALL_OPS = frozenset({"begin", "begin_transport", "transport_begin"})

VECTOR_KEYS = frozenset(
    {
        "id",
        "kind",
        "mode",
        "candidate_binding",
        "rows",
        "alt_rows",
        "faults",
        "calls",
        "expected",
        "d1_refs",
        "source_ref",
        "peer_ref",
        "row_refs",
        "notes",
        "ownership",
    }
)
REF_KEYS = frozenset(
    {
        "binding",
        "id",
        "key_hex",
        "value_hex",
        "mutations",
        "expect_presence",
        "note",
    }
)
MUTATION_KEYS = frozenset(
    {"offset", "old_hex", "new_hex", "recompute", "directive"}
)
FAULT_KEYS = frozenset(
    {"op", "on_call", "status", "shape", "key_length", "value_length"}
)
CALL_KEYS = frozenset(
    {
        "op",
        "row_budget",
        "key_hex",
        "name",
        "expected_status",
        "mode",
        "context",
    }
)
EXPECTED_KEYS = frozenset(
    {
        "final_status",
        "adopted",
        "state_after",
        "recognizable_future_seen",
        "family14_row_count",
        "current_domain_key_count",
        "ok_row_count",
        "profile_exact_active",
        "profile_mismatch",
        "future_profile_candidate",
        "profile_get_present_mask",
        "family14_iter_seen_mask",
        "reopen_required",
        "close_count",
        "mutation_calls",
        "iter_open_count",
        "port_trace",
        "has_sticky_primary",
        "sticky_primary",
        "d3_peer_get_count",
        "d3_mode_applicable_count",
    }
)

SCOPE = (
    "D3-S1 exact-1 crossrow sibling oracle: modes 1..20 peer rebuild + "
    "presence/PVD/raw bijection + Mode17 reverse table + local gates 18–20. "
    "Does not claim Stage 5 D3 bind, D3-S2 multi-row counts, D4 mutation, "
    "public Runtime, ESP-IDF, or hardware. TEST transport begin forbidden. "
    "Mode20 RECONCILE_WAIT has no legal body in D1 (kind "
    "mode20_reconcile_wait_impossible documents skip). "
    "Oracle/generator only — independent peer-key rebuild; production bridge and D3-S1 complete are out of scope."
)

SHA256_PROCEDURE = (
    "Do not embed full-file sha256 inside this artifact (self-referential hash is "
    "impossible without a placeholder dance). Generator `check` proves deterministic "
    "rebuild equality against tools/domain_scan_crossrow_vector_gen.py. After intentional "
    "extension, compute `sha256sum spec/vectors/domain-scan-crossrow-v1.json` and pin the "
    "full artifact hash in Normative docs/CI later. content_sha256 covers the document "
    "with sha256_procedure/content_sha256 fields set to empty strings before hashing."
)

OWNERSHIP_DEFAULT = (
    "D3-S1 independent crossrow oracle (tools/domain_scan_crossrow_vector_gen.py); "
    "not production C; not Stage5 bridge; not D3-S1 complete claim"
)

# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------


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


def hex_of(b: bytes) -> str:
    return b.hex()


def from_hex(s: str) -> bytes:
    return bytes.fromhex(s) if s else b""


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def value_digest(complete_value: bytes) -> bytes:
    """Independent VALUE_DIGEST = sha256(complete_value) with no prefix."""
    return sha256(complete_value)


def nlr1(record_type: int, record_version: int, payload: bytes) -> bytes:
    head = b"NLR1" + be16(record_type) + be16(record_version) + be32(len(payload))
    body = head + payload
    return body + be32(crc32c(body))


def enc_env_full(
    rtype: int,
    st: int,
    flags: int,
    rev: int,
    primary_id: bytes,
    head: bytes,
    pvd: bytes,
    body: bytes,
) -> bytes:
    assert len(primary_id) == 16 and len(head) == 32 and len(pvd) == 32
    payload = 96 + len(body)
    out = bytearray()
    out += b"NLR1" + be16(rtype) + be16(1) + be32(payload)
    out += be16(1) + bytes([st & 0xFF, flags & 0xFF]) + be64(rev)
    out += primary_id + head + pvd + be32(len(body)) + body
    out += be32(crc32c(bytes(out)))
    return bytes(out)


def header_pvd(complete_value: bytes) -> bytes:
    if len(complete_value) < PVD_OFF + 32:
        return b""
    return complete_value[PVD_OFF : PVD_OFF + 32]


def domain_value_framing(complete_value: bytes) -> str:
    """Classify complete value framing for Mode17 post-PVD layering.

    Returns:
      'current' — NLR1 domain type6 version1 with envelope-sized payload
      'future'  — NLR1 domain type6 with record_version >= 2 (UNSUPPORTED class)
      'corrupt' — unrecognizable / CRC fail / wrong shape

    Mode17 enforces VALUE_DIGEST before this classification; future may skip
    only envelope/raw decode after PVD matched (§18.12 / C verify_peer_present).
    """
    if len(complete_value) < 16 or complete_value[:4] != b"NLR1":
        return "corrupt"
    rtype = int.from_bytes(complete_value[4:6], "big")
    rver = int.from_bytes(complete_value[6:8], "big")
    plen = int.from_bytes(complete_value[8:12], "big")
    if plen > VALUE_CAP or len(complete_value) != 12 + plen + 4:
        return "corrupt"
    if struct.unpack(">I", complete_value[-4:])[0] != crc32c(complete_value[:-4]):
        return "corrupt"
    if rtype != 6:
        return "corrupt"
    if rver >= 2:
        return "future"
    if rver != 1:
        return "corrupt"
    # Current framing needs full domain envelope (header+body+crc floor).
    if len(complete_value) < 112:
        return "corrupt"
    return "current"


def patch_pvd(complete_value: bytes, pvd: bytes) -> bytes:
    """Write PVD at offset 72 and recompute CRC32C (Castagnoli)."""
    if len(pvd) != 32:
        raise ValueError("pvd must be 32 bytes")
    if len(complete_value) < PVD_OFF + 32 + 4:
        raise ValueError("value too short for PVD patch")
    b = bytearray(complete_value)
    b[PVD_OFF : PVD_OFF + 32] = pvd
    body = bytes(b[:-4])
    b[-4:] = be32(crc32c(body))
    return bytes(b)


def composite(subtype: int, components: bytes) -> bytes:
    return sha256(b"NINLIL-DOMAIN-KEY-V1" + bytes([subtype & 0xFF]) + components)


def bkey(fam: int, st: int, kind: int, ident: bytes) -> bytes:
    return ROOT_V1 + bytes([fam & 0xFF, st & 0xFF, 1, kind & 0xFF, len(ident)]) + ident


def raw16(c: bytes) -> bytes:
    if len(c) > 255:
        raise ValueError("raw16 contents > 255")
    return be16(len(c)) + c


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
    assert len(PROFILE_NAME) == 25
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
    assert len(payload) == 167, len(payload)
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
    enc = nlr1(2, 1, bytes(payload))
    assert len(enc) == 84
    return enc


def encode_counter(kind: int) -> bytes:
    payload = be32(kind) + be64(0) + be32(0)
    assert len(payload) == 16
    enc = nlr1(3, 1, payload)
    assert len(enc) == 32
    return enc


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
    assert len(payload) == 52
    enc = nlr1(4, 1, payload)
    assert len(enc) == 68
    return enc


def encode_all_profile_rows(
    binding_fields: Dict[str, Any],
    *,
    binding_version: int = 1,
    mutate_binding_byte: Optional[int] = None,
) -> List[Dict[str, str]]:
    rows: List[Tuple[bytes, bytes]] = []
    for key_id in range(1, 18):
        key = catalog_key(key_id)
        if key_id == 1:
            if binding_version != 1:
                payload = encode_binding(binding_fields)[12:-4]
                head = (
                    b"NLR1"
                    + be16(1)
                    + be16(binding_version)
                    + be32(len(payload))
                )
                body = head + payload
                value = body + be32(crc32c(body))
            else:
                value = encode_binding(binding_fields)
            if mutate_binding_byte is not None:
                b = bytearray(value)
                b[mutate_binding_byte] ^= 0xFF
                value = bytes(b)
        elif key_id == 2:
            value = encode_identity()
        elif 3 <= key_id <= 6:
            value = encode_counter(key_id - 2)
        else:
            value = encode_capacity(key_id - 6, limit=100 + key_id)
        rows.append((key, value))
    rows.sort(key=lambda r: r[0])
    return [{"key_hex": hex_of(k), "value_hex": hex_of(v)} for k, v in rows]


def future_root_key(tag: int = 0x01) -> bytes:
    return bytes(
        [0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x02, 0x10, 0x20, tag, 0x01, 0x00]
    )


def future_root_value() -> bytes:
    return nlr1(6, 2, bytes([0x01, 0x02, 0x03, 0x04]))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def authority_block(
    path: Path, fmt: str, sha: str, count: int
) -> Dict[str, Any]:
    return {
        "path": str(path.relative_to(REPO_ROOT)).replace("\\", "/"),
        "format": fmt,
        "sha256": sha,
        "vector_count": count,
    }


def assert_authority_pins() -> Dict[str, Dict[str, Any]]:
    pins = {}
    for path, fmt, sha, count, name in (
        (S1_VECTORS, S1_FORMAT, S1_SHA256, S1_COUNT, "s1"),
        (S2_VECTORS, S2_FORMAT, S2_SHA256, S2_COUNT, "s2"),
        (S3_VECTORS, S3_FORMAT, S3_SHA256, S3_COUNT, "s3"),
        (S4_VECTORS, S4_FORMAT, S4_SHA256, S4_COUNT, "s4"),
        (S5_VECTORS, S5_FORMAT, S5_SHA256, S5_COUNT, "s5"),
        (D1_VECTORS, D1_FORMAT, D1_SHA256, D1_COUNT, "d1"),
    ):
        if not path.is_file():
            raise SystemExit(f"missing sibling authority {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != fmt:
            raise SystemExit(f"{path}: format pin mismatch")
        actual = file_sha256(path)
        if actual != sha:
            raise SystemExit(f"{path}: sha256 pin mismatch {actual}")
        n = len(data.get("vectors", []))
        if n != count:
            raise SystemExit(f"{path}: vector_count pin mismatch {n} != {count}")
        pins[name] = authority_block(path, fmt, sha, count)
    return pins


# ---------------------------------------------------------------------------
# D1 catalog
# ---------------------------------------------------------------------------

_D1_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def load_d1() -> Dict[str, Dict[str, Any]]:
    global _D1_CACHE
    if _D1_CACHE is None:
        data = json.loads(D1_VECTORS.read_text(encoding="utf-8"))
        _D1_CACHE = {v["id"]: v for v in data["vectors"]}
    return _D1_CACHE


def d1_row(vid: str) -> Dict[str, str]:
    v = load_d1()[vid]
    if not v.get("key_hex") or not v.get("value_hex"):
        raise SystemExit(f"D1 {vid} missing key_hex/value_hex")
    return {"key_hex": v["key_hex"], "value_hex": v["value_hex"]}


def d1_body(vid: str) -> bytes:
    """Body bytes from D1 `body_hex`, or envelope-extracted body from `value_hex`."""
    v = load_d1()[vid]
    if v.get("body_hex"):
        return from_hex(v["body_hex"])
    if v.get("value_hex"):
        _st, body, _pvd = extract_envelope(from_hex(v["value_hex"]))
        return body
    return b""


def d1_verify_refs(refs: List[str], rows: List[Dict[str, str]]) -> None:
    catalog = load_d1()
    by_key = {r["key_hex"]: r for r in rows}
    for rid in refs:
        if rid not in catalog:
            raise SystemExit(f"unknown d1_ref {rid}")
        dv = catalog[rid]
        if not dv.get("key_hex"):
            continue
        if dv["key_hex"] not in by_key:
            continue
        row = by_key[dv["key_hex"]]
        if row["key_hex"] != dv["key_hex"]:
            raise SystemExit(f"d1_ref {rid} key_hex mismatch")
        if len(row["value_hex"]) != len(dv["value_hex"]):
            if rid.endswith("_EF_POSITIVE") or "EF" in rid:
                continue
            if "TERMINAL" in rid.upper():
                continue


def row_from_d1(vid: str, *, pvd_primary: Optional[bytes] = None) -> Dict[str, str]:
    r = d1_row(vid)
    if pvd_primary is not None:
        r = {
            "key_hex": r["key_hex"],
            "value_hex": hex_of(patch_pvd(from_hex(r["value_hex"]), pvd_primary)),
        }
    return r


def primary_digest_of(vid: str) -> bytes:
    return value_digest(from_hex(d1_row(vid)["value_hex"]))


def pvd_patch_mutation(base_value_hex: str, new_pvd: bytes) -> Dict[str, Any]:
    base = from_hex(base_value_hex)
    old = base[PVD_OFF : PVD_OFF + 32]
    return {
        "offset": PVD_OFF,
        "old_hex": hex_of(old),
        "new_hex": hex_of(new_pvd),
        "recompute": "crc32c_trailer",
        "directive": "write_pvd_then_crc32c",
    }


def make_ref(
    *,
    binding: str,
    rid: Optional[str] = None,
    key_hex: str = "",
    value_hex: str = "",
    mutations: Optional[List[Dict[str, Any]]] = None,
    expect_presence: Optional[str] = None,
    note: str = "",
) -> Dict[str, Any]:
    return {
        "binding": binding,
        "id": rid or "",
        "key_hex": key_hex,
        "value_hex": value_hex,
        "mutations": list(mutations or []),
        "expect_presence": expect_presence or "",
        "note": note,
    }


def d1_ref_from_id(
    rid: str,
    *,
    row: Optional[Dict[str, str]] = None,
    expect_presence: Optional[str] = None,
    note: str = "",
) -> Dict[str, Any]:
    catalog = load_d1()
    if rid not in catalog:
        raise SystemExit(f"unknown d1 id for ref: {rid}")
    base = catalog[rid]
    key_hex = (row or {}).get("key_hex") or base.get("key_hex") or ""
    value_hex = (row or {}).get("value_hex") or base.get("value_hex") or ""
    mutations: List[Dict[str, Any]] = []
    if (
        row is not None
        and base.get("value_hex")
        and row.get("value_hex")
        and row["value_hex"] != base["value_hex"]
        and len(row["value_hex"]) == len(base["value_hex"])
    ):
        bv = from_hex(base["value_hex"])
        rv = from_hex(row["value_hex"])
        if bv[:PVD_OFF] == rv[:PVD_OFF] and bv[PVD_OFF + 32 : -4] == rv[PVD_OFF + 32 : -4]:
            mutations.append(
                pvd_patch_mutation(base["value_hex"], rv[PVD_OFF : PVD_OFF + 32])
            )
        else:
            for i, (a, b) in enumerate(zip(bv, rv)):
                if a != b:
                    mutations.append(
                        {
                            "offset": i,
                            "old_hex": f"{a:02x}",
                            "new_hex": f"{b:02x}",
                            "recompute": "crc32c_trailer" if i < len(bv) - 4 else "none",
                            "directive": "byte_patch",
                        }
                    )
                    if len(mutations) > 8:
                        mutations = [
                            {
                                "offset": 0,
                                "old_hex": base["value_hex"],
                                "new_hex": row["value_hex"],
                                "recompute": "crc32c_trailer",
                                "directive": "replace_complete_value_recrc",
                            }
                        ]
                        break
    return make_ref(
        binding="d1",
        rid=rid,
        key_hex=key_hex,
        value_hex=value_hex,
        mutations=mutations,
        expect_presence=expect_presence,
        note=note,
    )


def absent_ref(
    *,
    peer_key_hex: str = "",
    rid: str = "",
    note: str = "ABSENT peer (no row materialised)",
) -> Dict[str, Any]:
    return make_ref(
        binding="absent",
        rid=rid,
        key_hex=peer_key_hex,
        value_hex="",
        expect_presence="ABSENT",
        note=note,
    )


def none_ref(note: str = "") -> Dict[str, Any]:
    return make_ref(binding="none", note=note or "no crossrow source/peer for this vector")


def synthetic_ref(
    *,
    rid: str = "",
    key_hex: str = "",
    value_hex: str = "",
    mutations: Optional[List[Dict[str, Any]]] = None,
    expect_presence: Optional[str] = None,
    note: str = "",
) -> Dict[str, Any]:
    return make_ref(
        binding="synthetic",
        rid=rid,
        key_hex=key_hex,
        value_hex=value_hex,
        mutations=mutations
        or (
            [
                {
                    "offset": 0,
                    "old_hex": "",
                    "new_hex": value_hex,
                    "recompute": "crc32c_trailer",
                    "directive": "materialize_complete_value",
                }
            ]
            if value_hex
            else []
        ),
        expect_presence=expect_presence,
        note=note,
    )


def build_row_refs(
    d1_refs: List[str],
    rows: List[Dict[str, str]],
    source_ref: Dict[str, Any],
    peer_ref: Dict[str, Any],
) -> List[Dict[str, Any]]:
    catalog = load_d1()
    ordered: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for ref in (source_ref, peer_ref):
        rid = ref.get("id") or ""
        kh = ref.get("key_hex") or ""
        if not kh and not rid:
            continue
        key = rid or kh
        if key in seen:
            continue
        seen.add(key)
        ordered.append(
            {
                "id": rid,
                "key_hex": kh,
                "value_hex": ref.get("value_hex") or "",
                "origin": ref.get("binding") or "unknown",
            }
        )
    by_key = {r["key_hex"]: r for r in rows}
    for rid in d1_refs:
        if rid in seen:
            continue
        dv = catalog.get(rid)
        if not dv or not dv.get("key_hex"):
            continue
        if dv["key_hex"] not in by_key:
            ordered.append(
                {
                    "id": rid,
                    "key_hex": dv.get("key_hex") or "",
                    "value_hex": dv.get("value_hex") or "",
                    "origin": "d1_material_only",
                }
            )
            seen.add(rid)
            continue
        row = by_key[dv["key_hex"]]
        origin = "d1"
        if dv.get("value_hex") and row["value_hex"] != dv["value_hex"]:
            origin = "d1_pvd_or_body_patch"
        ordered.append(
            {
                "id": rid,
                "key_hex": row["key_hex"],
                "value_hex": row["value_hex"],
                "origin": origin,
            }
        )
        seen.add(rid)
    return ordered


def vector_fingerprint(vec: Dict[str, Any]) -> str:
    payload = {
        "id": vec["id"],
        "kind": vec["kind"],
        "mode": vec["mode"],
        "d1_refs": vec.get("d1_refs") or [],
        "source_ref": {
            "binding": (vec.get("source_ref") or {}).get("binding"),
            "id": (vec.get("source_ref") or {}).get("id"),
            "key_hex": (vec.get("source_ref") or {}).get("key_hex"),
            "expect_presence": (vec.get("source_ref") or {}).get("expect_presence"),
        },
        "peer_ref": {
            "binding": (vec.get("peer_ref") or {}).get("binding"),
            "id": (vec.get("peer_ref") or {}).get("id"),
            "key_hex": (vec.get("peer_ref") or {}).get("key_hex"),
            "expect_presence": (vec.get("peer_ref") or {}).get("expect_presence"),
        },
        "expected": {
            "final_status": vec["expected"].get("final_status"),
            "adopted": vec["expected"].get("adopted"),
            "state_after": vec["expected"].get("state_after"),
            "mutation_calls": vec["expected"].get("mutation_calls"),
            "d3_peer_get_count": vec["expected"].get("d3_peer_get_count"),
            "d3_mode_applicable_count": vec["expected"].get(
                "d3_mode_applicable_count"
            ),
            "has_sticky_primary": vec["expected"].get("has_sticky_primary"),
            "sticky_primary": vec["expected"].get("sticky_primary"),
        },
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def content_sha256_of_doc(doc: Dict[str, Any]) -> str:
    tmp = copy.deepcopy(doc)
    tmp["sha256_procedure"] = ""
    tmp["content_sha256"] = ""
    raw = json.dumps(tmp, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Independent peer-key rebuild (pure Python; no production C)
# ---------------------------------------------------------------------------

# Family-6 subtypes
ST_SERVICE, ST_QUOTA = 0x10, 0x11
ST_ANCHOR, ST_SEQ, ST_STATE, ST_RES, ST_IDEM, ST_EVMAP = (
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
)
ST_SCHED, ST_INGRESS = 0x26, 0x27
ST_ATTEMPT, ST_EVIDENCE, ST_CANCEL, ST_AII = 0x31, 0x32, 0x33, 0x34
ST_DELIVERY, ST_RC, ST_RR = 0x40, 0x41, 0x42
ST_ES, ST_RETRY, ST_MGMT = 0x50, 0x51, 0x52
ST_RB, ST_CP = 0x61, 0x63

# owner_binding_kind (ORDERED_INGRESS)
BIND_EXISTING_TX = 1
BIND_EXISTING_DLV = 2
BIND_NEW_DELIVERY = 3

# RC physical states / token
RC_ST_INBOX, RC_ST_STARTED, RC_ST_RESULT, RC_ST_DISP = 1, 2, 4, 5
RC_ST_RECOVERY, RC_ST_CANCEL = 6, 8
TS_NONE, TS_ACTIVE, TS_CONSUMED = 1, 2, 3

# TX state terminal
TX_TERMINAL = 5

PARTY_LEN = 100
TARGET_LEN = 100


def key_digest(complete_key: bytes) -> bytes:
    return sha256(b"NINLIL-DOMAIN-ENCODED-KEY-V1" + complete_key)


def parse_raw16_at(buf: bytes, off: int) -> Tuple[bytes, int]:
    if off + 2 > len(buf):
        raise ValueError("raw16 truncated header")
    ln = int.from_bytes(buf[off : off + 2], "big")
    end = off + 2 + ln
    if end > len(buf):
        raise ValueError("raw16 truncated body")
    return buf[off + 2 : end], end


def skip_text_id(buf: bytes, off: int) -> int:
    if off >= len(buf):
        raise ValueError("text_id truncated")
    n = buf[off]
    return off + 1 + n


def skip_service_identity(buf: bytes, off: int) -> int:
    for _ in range(3):
        off = skip_text_id(buf, off)
    return off + 8 + 32 + 2 + 2 + 4  # rev + dig + major + minor + family


def service_identity_family(buf: bytes, off: int) -> int:
    o = off
    for _ in range(3):
        o = skip_text_id(buf, o)
    o += 8 + 32 + 2 + 2
    return int.from_bytes(buf[o : o + 4], "big")


def extract_envelope(complete_value: bytes) -> Tuple[int, bytes, bytes]:
    """Return (subtype, body, pvd) from a complete NLR1 domain envelope."""
    if len(complete_value) < 112 or complete_value[:4] != b"NLR1":
        raise ValueError("not NLR1 envelope")
    st = complete_value[HEADER_SUBTYPE_OFF]
    body_len = struct.unpack(">I", complete_value[104:108])[0]
    body = complete_value[108 : 108 + body_len]
    if len(body) != body_len:
        raise ValueError("body length mismatch")
    pvd = complete_value[PVD_OFF : PVD_OFF + 32]
    return st, body, pvd


def parse_domain_key(key: bytes) -> Optional[Tuple[int, int, int, bytes]]:
    if len(key) < 13 or key[:8] != ROOT_V1:
        return None
    fam, st, ver, kind, id_len = key[8], key[9], key[10], key[11], key[12]
    if ver != 1 or len(key) != 13 + id_len:
        return None
    return fam, st, kind, key[13:]


def k_composite(subtype: int, components: bytes) -> bytes:
    return bkey(6, subtype, 5, composite(subtype, components))


def k_id128(subtype: int, ident16: bytes) -> bytes:
    assert len(ident16) == 16
    return bkey(6, subtype, 2, ident16)


def k_u64(subtype: int, ident8: bytes) -> bytes:
    assert len(ident8) == 8
    return bkey(6, subtype, 3, ident8)


def complete_key_digest_composite(subtype: int, components: bytes) -> bytes:
    return key_digest(k_composite(subtype, components))


def complete_key_digest_id128(subtype: int, identity16: bytes) -> bytes:
    return key_digest(k_id128(subtype, identity16))


def complete_key_digest_u64(subtype: int, identity8: bytes) -> bytes:
    return key_digest(k_u64(subtype, identity8))


def scheduler_primary_key_digest(owner_kind: int, subject: bytes) -> bytes:
    if owner_kind == 1:
        return complete_key_digest_id128(ST_ANCHOR, subject)
    if owner_kind == 2:
        return complete_key_digest_composite(ST_DELIVERY, raw16(subject))
    if owner_kind == 3:
        return complete_key_digest_u64(ST_INGRESS, subject)
    raise ValueError(f"bad scheduler owner_kind {owner_kind}")


def scheduler_primary_id(owner_kind: int, subject: bytes) -> bytes:
    if owner_kind == 1:
        return subject
    if owner_kind == 2:
        return composite(ST_DELIVERY, raw16(subject))[:16]
    if owner_kind == 3:
        return bytes(8) + subject[:8]
    raise ValueError(f"bad scheduler owner_kind {owner_kind}")


def parse_anchor(body: bytes) -> Dict[str, Any]:
    o = 0
    txn = body[o : o + 16]
    o += 16
    txn_seq = int.from_bytes(body[o : o + 8], "big")
    o += 8
    o += 8  # schema/version
    family = int.from_bytes(body[o : o + 4], "big")
    o += 4
    o += PARTY_LEN
    o = skip_service_identity(body, o)
    o += 32 + 32  # content + canon
    event_id = body[o : o + 16]
    o += 16
    o += 8  # generation
    o += 16 + 8 + 16 + 8 + 8  # epochs / deadlines / grace
    o += 4 + 4  # required_evidence + target_count
    o += TARGET_LEN
    scope, o = parse_raw16_at(body, o)
    ikey, o = parse_raw16_at(body, o)
    o += 32 * 4  # seq/im/emap/res digests
    sched_seq = int.from_bytes(body[o : o + 8], "big")
    return {
        "txn": txn,
        "txn_seq": txn_seq,
        "family": family,
        "event_id": event_id,
        "scope": scope,
        "ikey": ikey,
        "sched_seq": sched_seq,
    }


def parse_service(body: bytes) -> Dict[str, Any]:
    sk, o = parse_raw16_at(body, 0)
    return {"service_key_raw": sk}


def parse_delivery(body: bytes) -> Dict[str, Any]:
    draw, o = parse_raw16_at(body, 0)
    creation = int.from_bytes(body[o : o + 2], "big")
    o += 2
    o += 2  # reserved
    sched_seq = int.from_bytes(body[o : o + 8], "big")
    o += 8
    txn = body[o : o + 16]
    o += 16
    event_id = body[o : o + 16]
    o += 16
    o += PARTY_LEN + TARGET_LEN
    fam = service_identity_family(body, o)
    return {
        "delivery_raw": draw,
        "creation": creation,
        "sched_seq": sched_seq,
        "txn": txn,
        "event_id": event_id,
        "family": fam,
    }


def parse_ingress(body: bytes) -> Dict[str, Any]:
    """Parse ORDERED_INGRESS body prefix + party/target for Mode16 delivery raw.

    Layout (docs17 §8 / §18.12): ordered_seq:u64 || owner_seq:u64 ||
    binding:u16 || reserved:u16 || kind:u32 || flags:u32 || txn[16] ||
    attempt[16] || event[16] || source:PARTY(100) || target:TARGET(100) || …
    """
    if len(body) < 76 + PARTY_LEN + TARGET_LEN:
        raise ValueError("ORDERED_INGRESS body too short for party/target")
    ordered_seq = body[0:8]
    owner_seq = int.from_bytes(body[8:16], "big")
    binding = int.from_bytes(body[16:18], "big")
    # reserved 18:20, kind 20:24, flags 24:28, txn 28:44
    txn = body[28:44]
    # PARTY at 76: runtime_id[16] || application_instance_id[16] || local_identity
    src_rt = body[76:92]
    src_app = body[92:108]
    # TARGET at 176: flags:u32 || target_runtime[16] || target_application[16] || …
    tgt_off = 76 + PARTY_LEN
    tgt_rt = body[tgt_off + 4 : tgt_off + 20]
    tgt_app = body[tgt_off + 20 : tgt_off + 36]
    return {
        "ordered_seq": ordered_seq,
        "owner_seq": owner_seq,
        "binding": binding,
        "txn": txn,
        "src_runtime": src_rt,
        "src_application": src_app,
        "tgt_runtime": tgt_rt,
        "tgt_application": tgt_app,
    }


def compose_delivery_raw_from_ingress(ing: Dict[str, Any]) -> bytes:
    """§18.12 EXISTING_DELIVERY subject: exact 80-byte delivery key contents.

    source_runtime_id || source_application_id || transaction_id ||
    target_runtime_id || target_application_id
    """
    draw = (
        ing["src_runtime"]
        + ing["src_application"]
        + ing["txn"]
        + ing["tgt_runtime"]
        + ing["tgt_application"]
    )
    if len(draw) != 80:
        raise ValueError(f"composed delivery_raw length {len(draw)} != 80")
    return draw


def parse_reservation(body: bytes) -> Dict[str, Any]:
    owner_kind = int.from_bytes(body[0:2], "big")
    owner_raw, _ = parse_raw16_at(body, 4)
    return {"owner_kind": owner_kind, "owner_raw": owner_raw}


def parse_sched(body: bytes) -> Dict[str, Any]:
    owner_seq = int.from_bytes(body[0:8], "big")
    owner_kind = int.from_bytes(body[8:10], "big")
    subject, _ = parse_raw16_at(body, 12)
    return {
        "owner_seq": owner_seq,
        "owner_kind": owner_kind,
        "subject": subject,
    }


def parse_idem(body: bytes) -> Dict[str, Any]:
    scope, o = parse_raw16_at(body, 0)
    ikey, o = parse_raw16_at(body, o)
    txn = body[o : o + 16]
    return {"scope": scope, "ikey": ikey, "txn": txn}


def parse_rc(body: bytes) -> Dict[str, Any]:
    draw, o = parse_raw16_at(body, 0)
    o += 32  # delivery_kd
    txn = body[o : o + 16]
    o += 16
    n = int.from_bytes(body[o : o + 8], "big")
    o += 8
    o += 4 + 4  # app_seen, app_attempt
    state = int.from_bytes(body[o : o + 4], "big")
    o += 4
    o += 4  # reply
    o += 16  # token_ctx
    token_gen = int.from_bytes(body[o : o + 8], "big")
    o += 8
    # skip timers to token_state
    # tok_epoch16 + tok_exp8 + started_ep16 + started_at8 + completion_exp8
    # + callback8 + rec_i8 + rec_g8 + rec_nb_ep16 + rec_nb_ms8
    # + app_kind4 + ev4 + disp4 + reason4 + effect4 + guidance4 + delay8 + evidence32
    o += 16 + 8 + 16 + 8 + 8 + 8 + 8 + 8 + 16 + 8 + 4 + 4 + 4 + 4 + 4 + 4 + 8 + 32
    token_state = int.from_bytes(body[o : o + 4], "big")
    return {
        "delivery_raw": draw,
        "txn": txn,
        "n": n,
        "state": state,
        "token_gen": token_gen,
        "token_state": token_state,
    }


def parse_attempt(body: bytes) -> Dict[str, Any]:
    attempt_id = body[0:16]
    owner_kind = int.from_bytes(body[16:18], "big")
    owner_raw, o = parse_raw16_at(body, 20)
    return {
        "attempt_id": attempt_id,
        "owner_kind": owner_kind,
        "owner_raw": owner_raw,
    }


def parse_aii(body: bytes) -> Dict[str, Any]:
    return {"attempt_id": body[0:16], "txn": body[16:32]}


def parse_cancel(body: bytes) -> Dict[str, Any]:
    owner_kind = int.from_bytes(body[0:2], "big")
    owner_raw, _ = parse_raw16_at(body, 4)
    return {"owner_kind": owner_kind, "owner_raw": owner_raw}


def parse_evidence(body: bytes) -> Dict[str, Any]:
    owner_kind = int.from_bytes(body[0:2], "big")
    owner_raw, _ = parse_raw16_at(body, 4)
    return {"owner_kind": owner_kind, "owner_raw": owner_raw}


def parse_rb(body: bytes) -> Dict[str, Any]:
    kind = int.from_bytes(body[0:2], "big")
    subject, _ = parse_raw16_at(body, 4)
    return {"kind": kind, "subject": subject}


def parse_cp(body: bytes) -> Dict[str, Any]:
    kind = int.from_bytes(body[0:2], "big")
    subject, o = parse_raw16_at(body, 4)
    # subject_primary_key_digest[32] then subject_primary_value_digest[32]
    if o + 64 > len(body):
        raise ValueError("CLEANUP_PLAN body too short for digests")
    return {
        "kind": kind,
        "subject": subject,
        "subject_primary_key_digest": body[o : o + 32],
        "subject_primary_value_digest": body[o + 32 : o + 64],
        "subject_primary_value_digest_off": o + 32,
    }


def parse_rr(body: bytes) -> Dict[str, Any]:
    # reply_raw RAW16 then delivery_raw RAW16
    _, o = parse_raw16_at(body, 0)
    draw, _ = parse_raw16_at(body, o)
    return {"delivery_raw": draw}


def parse_state(body: bytes) -> Dict[str, Any]:
    txn = body[0:16]
    state = int.from_bytes(body[48:52], "big")
    return {"txn": txn, "state": state}


def parse_seq(body: bytes) -> Dict[str, Any]:
    return {"seq": int.from_bytes(body[0:8], "big"), "txn": body[8:24]}


def parse_evmap(body: bytes) -> Dict[str, Any]:
    scope, o = parse_raw16_at(body, 0)
    event_id = body[o : o + 16]
    txn = body[o + 16 : o + 32]
    return {"scope": scope, "event_id": event_id, "txn": txn}


def parse_quota(body: bytes) -> Dict[str, Any]:
    sk, _ = parse_raw16_at(body, 0)
    return {"service_key_raw": sk}


def parse_es(body: bytes) -> Dict[str, Any]:
    return {"txn": body[0:16]}


def parse_retry(body: bytes) -> Dict[str, Any]:
    return {"txn": body[0:16]}


def parse_mgmt(body: bytes) -> Dict[str, Any]:
    # op16 + kind2 + res2 + ordered_seq8 + txn16
    return {"txn": body[28:44]}


class PeerEval:
    """Material-induced peer evaluation plan for one applicable source row."""

    __slots__ = (
        "peer_key",
        "expect_presence",
        "check_pvd",
        "skip_pvd",
        "dual_raw",
        "dual_raw2",
        "owner_kind",
        "subject_raw",
        "raw_bijection",
        "mode18_pair",
        "note",
    )

    def __init__(
        self,
        peer_key: bytes,
        *,
        expect_presence: str = "PRESENT",
        check_pvd: bool = True,
        skip_pvd: bool = False,
        dual_raw: Optional[bytes] = None,
        dual_raw2: Optional[bytes] = None,
        owner_kind: Optional[int] = None,
        subject_raw: Optional[bytes] = None,
        raw_bijection: bool = False,
        mode18_pair: bool = False,
        note: str = "",
    ):
        self.peer_key = peer_key
        self.expect_presence = expect_presence
        self.check_pvd = check_pvd
        self.skip_pvd = skip_pvd
        self.dual_raw = dual_raw
        self.dual_raw2 = dual_raw2
        self.owner_kind = owner_kind
        self.subject_raw = subject_raw
        self.raw_bijection = raw_bijection
        self.mode18_pair = mode18_pair
        self.note = note


def rebuild_peer(
    mode: int, source_key: bytes, source_val: bytes
) -> Optional[PeerEval]:
    """Independent peer-key rebuild for Mode 1..20.

    Returns None when the row is not applicable to the mode (subtype mismatch).
    Raises ValueError when the row is applicable but material is insufficient
    to rebuild a peer key.
    """
    parsed = parse_domain_key(source_key)
    if parsed is None:
        return None
    fam, st, _kind, _ident = parsed
    if fam != 6:
        return None
    try:
        _st_env, body, _pvd = extract_envelope(source_val)
    except ValueError:
        return None
    # Prefer key subtype for applicability
    if mode == 1:
        if st != ST_SERVICE:
            return None
        sk = parse_service(body)["service_key_raw"]
        return PeerEval(k_composite(ST_QUOTA, raw16(sk)), note="M1 SERVICE→QUOTA")
    if mode == 2:
        if st != ST_SERVICE:
            return None
        sk = parse_service(body)["service_key_raw"]
        return PeerEval(
            k_composite(ST_RES, be16(1) + raw16(sk)), note="M2 SERVICE→RES"
        )
    if mode in (3, 4, 5, 6, 7, 8, 9, 10):
        if st != ST_ANCHOR:
            return None
        a = parse_anchor(body)
        if mode == 3:
            return PeerEval(k_u64(ST_SEQ, be64(a["txn_seq"])), note="M3→SEQ")
        if mode == 4:
            return PeerEval(k_id128(ST_STATE, a["txn"]), note="M4→STATE")
        if mode == 5:
            return PeerEval(
                k_composite(ST_IDEM, raw16(a["scope"]) + raw16(a["ikey"])),
                dual_raw=a["scope"],
                dual_raw2=a["ikey"],
                raw_bijection=True,
                note="M5 dual-raw→IDEM",
            )
        if mode == 6:
            return PeerEval(
                k_composite(ST_RES, be16(2) + raw16(a["txn"])), note="M6→RES_TX"
            )
        if mode == 7:
            return PeerEval(
                k_u64(ST_SCHED, be64(a["sched_seq"])),
                owner_kind=1,
                subject_raw=a["txn"],
                raw_bijection=True,
                note="M7→SCHED_TX",
            )
        if mode == 8:
            # family-gated: EF PRESENT, DS ABSENT
            if a["family"] == 1:  # EventFact
                return PeerEval(
                    k_composite(ST_EVMAP, raw16(a["scope"]) + a["event_id"]),
                    note="M8 EF→EVMAP",
                )
            return PeerEval(
                k_composite(ST_EVMAP, raw16(a["scope"]) + a["event_id"]),
                expect_presence="ABSENT",
                check_pvd=False,
                note="M8 DS EVMAP ABSENT",
            )
        if mode == 9:
            if a["family"] == 1:
                return PeerEval(k_id128(ST_ES, a["txn"]), note="M9 EF→ES")
            return PeerEval(
                k_id128(ST_ES, a["txn"]),
                expect_presence="ABSENT",
                check_pvd=False,
                note="M9 DS ES ABSENT",
            )
        if mode == 10:
            # DS PRESENT cancel, EF ABSENT
            peer = k_composite(ST_CANCEL, be16(1) + raw16(a["txn"]))
            if a["family"] == 2:  # DesiredState
                return PeerEval(peer, note="M10 DS→CANCEL")
            return PeerEval(
                peer, expect_presence="ABSENT", check_pvd=False, note="M10 EF CANCEL ABSENT"
            )
    if mode in (11, 12, 13, 14):
        if st != ST_DELIVERY:
            return None
        d = parse_delivery(body)
        if mode == 11:
            return PeerEval(
                k_composite(ST_RC, raw16(d["delivery_raw"])), note="M11→RC"
            )
        if mode == 12:
            return PeerEval(
                k_composite(ST_RES, be16(4) + raw16(d["delivery_raw"])),
                note="M12→RES_DLV",
            )
        if mode == 13:
            return PeerEval(
                k_u64(ST_SCHED, be64(d["sched_seq"])),
                owner_kind=2,
                subject_raw=d["delivery_raw"],
                raw_bijection=True,
                note="M13→SCHED_DLV",
            )
        if mode == 14:
            peer = k_composite(ST_CANCEL, be16(2) + raw16(d["delivery_raw"]))
            if d["family"] == 2:
                return PeerEval(peer, note="M14 DS→CANCEL_DLV")
            return PeerEval(
                peer,
                expect_presence="ABSENT",
                check_pvd=False,
                note="M14 EF CANCEL ABSENT",
            )
    if mode in (15, 16):
        if st != ST_INGRESS:
            return None
        ing = parse_ingress(body)
        if mode == 15:
            return PeerEval(
                k_composite(ST_RES, be16(3) + raw16(ing["ordered_seq"])),
                note="M15→RES_ING",
            )
        # Mode16: PRESENT always; peer key = owner_sequence u64
        peer = k_u64(ST_SCHED, be64(ing["owner_seq"]))
        if ing["binding"] == BIND_NEW_DELIVERY:
            return PeerEval(
                peer,
                owner_kind=3,
                subject_raw=ing["ordered_seq"],
                raw_bijection=True,
                check_pvd=True,
                note="M16 NEW_DELIVERY→SCHED",
            )
        if ing["binding"] == BIND_EXISTING_TX:
            return PeerEval(
                peer,
                owner_kind=1,
                subject_raw=ing["txn"],
                raw_bijection=True,
                skip_pvd=True,
                check_pvd=False,
                note="M16 EXISTING_TX→SCHED",
            )
        if ing["binding"] == BIND_EXISTING_DLV:
            # subject = composed delivery raw from ingress party/target/txn
            # (independent of any live DELIVERY row). Peer key = owner_sequence.
            draw = compose_delivery_raw_from_ingress(ing)
            return PeerEval(
                peer,
                owner_kind=2,
                subject_raw=draw,
                raw_bijection=True,
                skip_pvd=True,
                check_pvd=False,
                note="M16 EXISTING_DLV→SCHED",
            )
        raise ValueError(f"Mode16 unknown owner_binding_kind {ing['binding']}")
    if mode == 17:
        return _rebuild_mode17(st, body)
    if mode == 18:
        if st == ST_ATTEMPT:
            att = parse_attempt(body)
            peer = k_id128(ST_AII, att["attempt_id"])
            if att["owner_kind"] == 1:
                # TX-owned local: ATTEMPT_ID_INDEX must be PRESENT at attempt_id.
                return PeerEval(
                    peer,
                    skip_pvd=True,
                    check_pvd=False,
                    mode18_pair=True,
                    owner_kind=att["owner_kind"],
                    subject_raw=att["owner_raw"] + att["attempt_id"],
                    raw_bijection=True,
                    note="M18 ATTEMPT→AII",
                )
            if att["owner_kind"] == 2:
                # DELIVERY-owned remote: no local AII; exact_get attempt_id
                # expects ABSENT (PRESENT is STORAGE_CORRUPT). Peer key is the
                # same ID128(attempt_id) probe production rebuilds.
                return PeerEval(
                    peer,
                    expect_presence="ABSENT",
                    skip_pvd=True,
                    check_pvd=False,
                    note="M18 DELIVERY ATTEMPT→AII ABSENT",
                )
            return None
        if st == ST_AII:
            aii = parse_aii(body)
            peer = k_composite(
                ST_ATTEMPT, be16(1) + raw16(aii["txn"]) + aii["attempt_id"]
            )
            return PeerEval(
                peer,
                skip_pvd=True,
                check_pvd=False,
                mode18_pair=True,
                subject_raw=aii["txn"] + aii["attempt_id"],
                raw_bijection=True,
                note="M18 AII→ATTEMPT",
            )
        return None
    if mode == 19:
        if st != ST_RC:
            return None
        rc = parse_rc(body)
        owner_raw = raw16(rc["delivery_raw"]) + be64(rc["token_gen"])
        peer = k_composite(ST_RES, be16(5) + raw16(owner_raw))
        active = rc["state"] == RC_ST_STARTED and rc["token_state"] == TS_ACTIVE
        if active:
            return PeerEval(
                peer,
                skip_pvd=True,
                check_pvd=False,
                owner_kind=5,
                subject_raw=owner_raw,
                raw_bijection=True,
                note="M19 ACTIVE→CALLBACK RES",
            )
        return PeerEval(
            peer,
            expect_presence="ABSENT",
            skip_pvd=True,
            check_pvd=False,
            note="M19 non-ACTIVE CALLBACK ABSENT",
        )
    if mode == 20:
        if st == ST_STATE:
            stt = parse_state(body)
            peer = k_composite(ST_RB, be16(2) + raw16(stt["txn"]))
            if stt["state"] == TX_TERMINAL:
                return PeerEval(
                    peer,
                    skip_pvd=True,
                    check_pvd=False,
                    owner_kind=2,
                    subject_raw=stt["txn"],
                    raw_bijection=True,
                    note="M20 TX terminal→RB PRESENT",
                )
            return PeerEval(
                peer,
                expect_presence="ABSENT",
                skip_pvd=True,
                check_pvd=False,
                note="M20 TX active→RB ABSENT",
            )
        if st == ST_RC:
            rc = parse_rc(body)
            peer = k_composite(ST_RB, be16(3) + raw16(rc["delivery_raw"]))
            terminal = rc["state"] in (RC_ST_RESULT, RC_ST_DISP, RC_ST_CANCEL)
            if terminal:
                return PeerEval(
                    peer,
                    skip_pvd=True,
                    check_pvd=False,
                    owner_kind=3,
                    subject_raw=rc["delivery_raw"],
                    raw_bijection=True,
                    note="M20 RC terminal→RB PRESENT",
                )
            return PeerEval(
                peer,
                expect_presence="ABSENT",
                skip_pvd=True,
                check_pvd=False,
                note="M20 RC active→RB ABSENT",
            )
        return None
    return None


def _rebuild_mode17(st: int, body: bytes) -> Optional[PeerEval]:
    """Mode17 reverse: secondary → true primary."""
    if st == ST_QUOTA:
        sk = parse_quota(body)["service_key_raw"]
        return PeerEval(
            k_composite(ST_SERVICE, raw16(sk)),
            dual_raw=sk,
            raw_bijection=True,
            note="M17 QUOTA→SERVICE",
        )
    if st == ST_RES:
        r = parse_reservation(body)
        ok, raw = r["owner_kind"], r["owner_raw"]
        if ok == 1:
            peer = k_composite(ST_SERVICE, raw16(raw))
        elif ok == 2:
            peer = k_id128(ST_ANCHOR, raw)
        elif ok == 3:
            peer = k_u64(ST_INGRESS, raw)
        elif ok == 4:
            peer = k_composite(ST_DELIVERY, raw16(raw))
        elif ok == 5:
            dlen = int.from_bytes(raw[:2], "big")
            draw = raw[2 : 2 + dlen]
            peer = k_composite(ST_DELIVERY, raw16(draw))
        else:
            raise ValueError(f"M17 RES bad owner_kind {ok}")
        return PeerEval(
            peer, owner_kind=ok, subject_raw=raw, raw_bijection=True, note="M17 RES→primary"
        )
    if st == ST_SEQ:
        txn = parse_seq(body)["txn"]
        return PeerEval(
            k_id128(ST_ANCHOR, txn),
            subject_raw=txn,
            raw_bijection=True,
            note="M17 SEQ→ANCHOR",
        )
    if st == ST_STATE:
        txn = parse_state(body)["txn"]
        return PeerEval(
            k_id128(ST_ANCHOR, txn),
            subject_raw=txn,
            raw_bijection=True,
            note="M17 STATE→ANCHOR",
        )
    if st == ST_IDEM:
        im = parse_idem(body)
        return PeerEval(
            k_id128(ST_ANCHOR, im["txn"]),
            dual_raw=im["scope"],
            dual_raw2=im["ikey"],
            subject_raw=im["txn"],
            raw_bijection=True,
            note="M17 IDEM→ANCHOR dual-raw",
        )
    if st == ST_EVMAP:
        txn = parse_evmap(body)["txn"]
        return PeerEval(
            k_id128(ST_ANCHOR, txn),
            subject_raw=txn,
            raw_bijection=True,
            note="M17 EVMAP→ANCHOR",
        )
    if st == ST_ES:
        txn = parse_es(body)["txn"]
        return PeerEval(
            k_id128(ST_ANCHOR, txn),
            subject_raw=txn,
            raw_bijection=True,
            note="M17 ES→ANCHOR",
        )
    if st == ST_RETRY:
        txn = parse_retry(body)["txn"]
        return PeerEval(
            k_id128(ST_ANCHOR, txn),
            subject_raw=txn,
            raw_bijection=True,
            note="M17 RS→ANCHOR",
        )
    if st == ST_MGMT:
        txn = parse_mgmt(body)["txn"]
        return PeerEval(
            k_id128(ST_ANCHOR, txn),
            subject_raw=txn,
            raw_bijection=True,
            note="M17 ML→ANCHOR",
        )
    if st == ST_SCHED:
        s = parse_sched(body)
        if s["owner_kind"] == 1:
            peer = k_id128(ST_ANCHOR, s["subject"])
        elif s["owner_kind"] == 2:
            peer = k_composite(ST_DELIVERY, raw16(s["subject"]))
        elif s["owner_kind"] == 3:
            peer = k_u64(ST_INGRESS, s["subject"])
        else:
            raise ValueError(f"M17 SCHED bad owner_kind {s['owner_kind']}")
        return PeerEval(
            peer,
            owner_kind=s["owner_kind"],
            subject_raw=s["subject"],
            raw_bijection=True,
            note="M17 SCHED→primary",
        )
    if st == ST_ATTEMPT:
        att = parse_attempt(body)
        if att["owner_kind"] == 1:
            peer = k_id128(ST_ANCHOR, att["owner_raw"])
        elif att["owner_kind"] == 2:
            peer = k_composite(ST_DELIVERY, raw16(att["owner_raw"]))
        else:
            raise ValueError(f"M17 ATTEMPT bad owner_kind {att['owner_kind']}")
        return PeerEval(
            peer,
            owner_kind=att["owner_kind"],
            subject_raw=att["owner_raw"],
            raw_bijection=True,
            note="M17 ATTEMPT→owner",
        )
    if st == ST_AII:
        txn = parse_aii(body)["txn"]
        return PeerEval(
            k_id128(ST_ANCHOR, txn),
            subject_raw=txn,
            raw_bijection=True,
            note="M17 AII→ANCHOR",
        )
    if st == ST_CANCEL:
        c = parse_cancel(body)
        if c["owner_kind"] == 1:
            peer = k_id128(ST_ANCHOR, c["owner_raw"])
        elif c["owner_kind"] == 2:
            peer = k_composite(ST_DELIVERY, raw16(c["owner_raw"]))
        else:
            raise ValueError(f"M17 CANCEL bad owner_kind {c['owner_kind']}")
        return PeerEval(
            peer,
            owner_kind=c["owner_kind"],
            subject_raw=c["owner_raw"],
            raw_bijection=True,
            note="M17 CANCEL→owner",
        )
    if st == ST_EVIDENCE:
        e = parse_evidence(body)
        if e["owner_kind"] == 1:
            peer = k_id128(ST_ANCHOR, e["owner_raw"])
        elif e["owner_kind"] == 2:
            peer = k_composite(ST_DELIVERY, raw16(e["owner_raw"]))
        else:
            raise ValueError(f"M17 EVIDENCE bad owner_kind {e['owner_kind']}")
        return PeerEval(
            peer,
            owner_kind=e["owner_kind"],
            subject_raw=e["owner_raw"],
            raw_bijection=True,
            note="M17 EVIDENCE→owner",
        )
    if st == ST_RC:
        rc = parse_rc(body)
        return PeerEval(
            k_composite(ST_DELIVERY, raw16(rc["delivery_raw"])),
            subject_raw=rc["delivery_raw"],
            raw_bijection=True,
            note="M17 RC→DELIVERY",
        )
    if st == ST_RR:
        rr = parse_rr(body)
        return PeerEval(
            k_composite(ST_DELIVERY, raw16(rr["delivery_raw"])),
            subject_raw=rr["delivery_raw"],
            raw_bijection=True,
            note="M17 RR→DELIVERY",
        )
    if st == ST_RB:
        rb = parse_rb(body)
        if rb["kind"] == 2:
            peer = k_id128(ST_ANCHOR, rb["subject"])
        elif rb["kind"] == 3:
            peer = k_composite(ST_DELIVERY, raw16(rb["subject"]))
        else:
            raise ValueError(f"M17 RB bad kind {rb['kind']}")
        return PeerEval(
            peer,
            owner_kind=rb["kind"],
            subject_raw=rb["subject"],
            raw_bijection=True,
            note="M17 RB→subject",
        )
    if st == ST_CP:
        cp = parse_cp(body)
        if cp["kind"] == 2:
            peer = k_id128(ST_ANCHOR, cp["subject"])
        elif cp["kind"] == 3:
            peer = k_composite(ST_DELIVERY, raw16(cp["subject"]))
        else:
            raise ValueError(f"M17 CP bad kind {cp['kind']}")
        return PeerEval(
            peer,
            owner_kind=cp["kind"],
            subject_raw=cp["subject"],
            raw_bijection=True,
            note="M17 CP→subject",
        )
    return None


def assert_peer_key_rebuildable(
    mode: int, source_key_hex: str, source_value_hex: str, peer_key_hex: str
) -> PeerEval:
    """Reject vectors whose peer key cannot be rebuilt from source material."""
    ev = rebuild_peer(mode, from_hex(source_key_hex), from_hex(source_value_hex))
    if ev is None:
        raise SystemExit(
            f"mode {mode}: source not applicable for peer rebuild "
            f"(key={source_key_hex[:32]}…)"
        )
    if hex_of(ev.peer_key) != peer_key_hex:
        raise SystemExit(
            f"mode {mode}: peer key rebuild mismatch\n"
            f"  rebuilt={hex_of(ev.peer_key)}\n"
            f"  configured={peer_key_hex}\n"
            f"  note={ev.note}"
        )
    return ev


def make_sched_body(
    owner_seq: int,
    owner_kind: int,
    subject: bytes,
    *,
    work_class: int = 1,
    state_rev: int = 1,
    ready: int = 0,
) -> bytes:
    pkd = scheduler_primary_key_digest(owner_kind, subject)
    logical_epoch = bytes([0xC1]) + bytes([0xC2] * 15)
    return (
        be64(owner_seq)
        + be16(owner_kind)
        + be16(work_class)
        + raw16(subject)
        + pkd
        + be64(state_rev)
        + logical_epoch
        + be64(0)
        + bytes(16)
        + be64(0)
        + be32(ready)
    )


def make_res_body(owner_kind: int, owner_raw: bytes) -> bytes:
    if owner_kind == 1:
        pkd = complete_key_digest_composite(ST_SERVICE, raw16(owner_raw))
    elif owner_kind == 2:
        pkd = complete_key_digest_id128(ST_ANCHOR, owner_raw)
    elif owner_kind == 3:
        pkd = complete_key_digest_u64(ST_INGRESS, owner_raw)
    elif owner_kind == 4:
        pkd = complete_key_digest_composite(ST_DELIVERY, raw16(owner_raw))
    elif owner_kind == 5:
        dlen = int.from_bytes(owner_raw[:2], "big")
        pkd = complete_key_digest_composite(
            ST_DELIVERY, owner_raw[: 2 + dlen]
        )
    else:
        raise ValueError(owner_kind)
    rv = b"".join(be64(0) + be64(0) for _ in range(11))
    return (
        be16(owner_kind)
        + be16(0)
        + raw16(owner_raw)
        + pkd
        + rv
        + be32(0)
        + be32(0)
        + be64(0)
        + be32(0)
    )


def ingress_reservation_key_digest(ordered_seq8: bytes) -> bytes:
    """KEY_DIGEST of RESERVATION composite for INGRESS owner ordered_sequence."""
    if len(ordered_seq8) != 8:
        raise ValueError("ordered_seq must be 8 bytes")
    return complete_key_digest_composite(ST_RES, be16(3) + raw16(ordered_seq8))


def make_ordered_ingress_body_with_seq(base_body: bytes, ordered_seq8: bytes) -> bytes:
    """Clone a legal ORDERED_INGRESS body with a new ordered_sequence + res digest."""
    if len(ordered_seq8) != 8 or int.from_bytes(ordered_seq8, "big") == 0:
        raise ValueError("ordered_seq must be non-zero u64")
    if len(base_body) < 36:
        raise ValueError("ORDERED_INGRESS body too short")
    b = bytearray(base_body)
    b[0:8] = ordered_seq8
    b[-32:] = ingress_reservation_key_digest(ordered_seq8)
    return bytes(b)


def patch_cleanup_plan_live_primary_digest(
    complete_value: bytes, live_pvd: bytes
) -> bytes:
    """Patch CLEANUP_PLAN body subject_primary_value_digest + header PVD; re-CRC.

    Same-record requires body subject_primary_value_digest == header PVD;
    Mode17 requires header PVD == live primary complete-value digest.
    """
    if len(live_pvd) != 32 or live_pvd == bytes(32):
        raise ValueError("live_pvd must be non-zero 32 bytes")
    st, body, _ = extract_envelope(complete_value)
    if st != ST_CP:
        raise ValueError(f"expected CLEANUP_PLAN subtype, got {st:#x}")
    cp = parse_cp(body)
    b = bytearray(body)
    off = cp["subject_primary_value_digest_off"]
    b[off : off + 32] = live_pvd
    primary_id = complete_value[24:40]
    rev = struct.unpack(">Q", complete_value[16:24])[0]
    flags = complete_value[15]
    head = complete_value[40:72]
    return enc_env_full(6, ST_CP, flags, rev, primary_id, head, live_pvd, bytes(b))


def recompute_anchor_idempotency_map_digest(body: bytes) -> bytes:
    """Return ANCHOR body with idempotency_map_key_digest matching scope||ikey."""
    o = 0
    o += 16 + 8 + 8 + 4  # txn, txn_seq, schema, family
    o += PARTY_LEN
    o = skip_service_identity(body, o)
    o += 32 + 32  # content + canon
    o += 16  # event_id
    o += 8  # generation
    o += 16 + 8 + 16 + 8 + 8  # epochs / deadlines / grace
    o += 4 + 4  # required_evidence + target_count
    o += TARGET_LEN
    scope, o = parse_raw16_at(body, o)
    ikey, o = parse_raw16_at(body, o)
    # sequence_index_key_digest[32] then idempotency_map_key_digest[32]
    im_off = o + 32
    im_dig = complete_key_digest_composite(ST_IDEM, raw16(scope) + raw16(ikey))
    b = bytearray(body)
    b[im_off : im_off + 32] = im_dig
    return bytes(b)


def family6_current_row_s3_status(key: bytes, value: bytes) -> str:
    """Independent S3-equivalent structural gate for family-6 CURRENT rows.

    Stdlib/spec-derived only — does not invoke production C. Complete enough to
    reject illegal binding, CP digest desync, ingress sequence mismatch, anchor
    derived-digest drift, callback token_generation=0, and classify framing
    future as UNSUPPORTED. Returns 'OK' | 'UNSUPPORTED' | 'STORAGE_CORRUPT'.
    """
    parsed = parse_domain_key(key)
    if parsed is None:
        return "STORAGE_CORRUPT"
    fam, st, kind, ident = parsed
    if fam != 6:
        return "OK"  # non-family6 out of scope for this gate
    framing = domain_value_framing(value)
    if framing == "future":
        return "UNSUPPORTED"
    if framing != "current":
        return "STORAGE_CORRUPT"
    try:
        vst, body, pvd = extract_envelope(value)
    except ValueError:
        return "STORAGE_CORRUPT"
    if vst != st:
        return "STORAGE_CORRUPT"
    # Common secondary: PVD non-zero for secondaries; primaries zero PVD.
    primary_subtypes = {
        ST_SERVICE,
        ST_ANCHOR,
        ST_INGRESS,
        ST_DELIVERY,
    }
    if st in primary_subtypes:
        if pvd != bytes(32):
            # Primary may still carry zero-only PVD; non-zero is corrupt for primaries.
            return "STORAGE_CORRUPT"
    else:
        if pvd == bytes(32):
            return "STORAGE_CORRUPT"
    # Header primary_id vs key identity (lenient floor: non-empty identity).
    if not ident:
        return "STORAGE_CORRUPT"

    if st == ST_INGRESS:
        try:
            ing = parse_ingress(body)
        except ValueError:
            return "STORAGE_CORRUPT"
        if kind != 3 or len(ident) != 8:
            return "STORAGE_CORRUPT"
        if ing["ordered_seq"] != ident:
            return "STORAGE_CORRUPT"
        if int.from_bytes(ing["ordered_seq"], "big") == 0 or ing["owner_seq"] == 0:
            return "STORAGE_CORRUPT"
        msg_kind = int.from_bytes(body[20:24], "big")
        # APPLICATION/CANCEL_REQUEST: EXISTING_DELIVERY|NEW_DELIVERY only.
        # RECEIPT/DISPOSITION/CUSTODY/CANCEL_RESULT: EXISTING_TX only.
        app_like = msg_kind in (1, 5)  # APPLICATION, CANCEL_REQUEST
        tx_like = msg_kind in (2, 3, 4, 6)  # RECEIPT, DISPOSITION, CUSTODY, CANCEL_RESULT
        if app_like and ing["binding"] not in (BIND_EXISTING_DLV, BIND_NEW_DELIVERY):
            return "STORAGE_CORRUPT"
        if tx_like and ing["binding"] != BIND_EXISTING_TX:
            return "STORAGE_CORRUPT"
        if not app_like and not tx_like:
            return "STORAGE_CORRUPT"
        # reservation_key_digest must match ordered_sequence
        want = ingress_reservation_key_digest(ing["ordered_seq"])
        if body[-32:] != want:
            return "STORAGE_CORRUPT"
        return "OK"

    if st == ST_CP:
        try:
            cp = parse_cp(body)
        except ValueError:
            return "STORAGE_CORRUPT"
        if cp["subject_primary_value_digest"] == bytes(32):
            return "STORAGE_CORRUPT"
        if cp["subject_primary_value_digest"] != pvd:
            return "STORAGE_CORRUPT"
        return "OK"

    if st == ST_ANCHOR:
        try:
            a = parse_anchor(body)
            fixed = recompute_anchor_idempotency_map_digest(body)
        except (ValueError, IndexError):
            return "STORAGE_CORRUPT"
        # derived idempotency_map_key_digest must match scope||ikey material
        if fixed != body:
            return "STORAGE_CORRUPT"
        if not a["scope"] or not a["ikey"] or a["txn"] == bytes(16):
            return "STORAGE_CORRUPT"
        if kind != 2 or len(ident) != 16 or ident != a["txn"]:
            return "STORAGE_CORRUPT"
        return "OK"

    if st == ST_RES:
        try:
            r = parse_reservation(body)
        except ValueError:
            return "STORAGE_CORRUPT"
        if r["owner_kind"] == 5:
            raw = r["owner_raw"]
            if len(raw) < 2 + 80 + 8:
                return "STORAGE_CORRUPT"
            dlen = int.from_bytes(raw[:2], "big")
            if dlen != 80:
                return "STORAGE_CORRUPT"
            tok = int.from_bytes(raw[2 + dlen : 2 + dlen + 8], "big")
            if tok == 0:
                return "STORAGE_CORRUPT"
        return "OK"

    if st == ST_SCHED:
        try:
            s = parse_sched(body)
        except ValueError:
            return "STORAGE_CORRUPT"
        if s["owner_seq"] == 0 or s["owner_kind"] not in (1, 2, 3):
            return "STORAGE_CORRUPT"
        want_pkd = scheduler_primary_key_digest(s["owner_kind"], s["subject"])
        # primary_key_digest sits after owner_seq:u64 || kind:u16 || work:u16 || subject:RAW16
        o = 12
        _subj, o = parse_raw16_at(body, o)
        if body[o : o + 32] != want_pkd:
            return "STORAGE_CORRUPT"
        return "OK"

    return "OK"


def assert_family6_s3_gate_on_rows(
    rows: List[Dict[str, str]], *, context: str
) -> None:
    """Reject emitted vectors that ship illegal family-6 CURRENT material."""
    for r in rows:
        key = from_hex(r["key_hex"])
        val = from_hex(r["value_hex"])
        parsed = parse_domain_key(key)
        if parsed is None or parsed[0] != 6:
            continue
        status = family6_current_row_s3_status(key, val)
        if status == "STORAGE_CORRUPT":
            raise SystemExit(
                f"S3 gate rejected family-6 CURRENT row in {context}: "
                f"key={r['key_hex'][:40]}… subtype={parsed[1]:#x}"
            )


def make_row(
    key: bytes,
    body: bytes,
    *,
    subtype: int,
    primary_id: bytes,
    pvd: Optional[bytes] = None,
    head: Optional[bytes] = None,
    rev: int = 1,
) -> Dict[str, str]:
    if pvd is None:
        pvd = bytes(32)
    if head is None:
        head = bytes([0x11] * 32)
    val = enc_env_full(6, subtype, 0, rev, primary_id, head, pvd, body)
    return {"key_hex": hex_of(key), "value_hex": hex_of(val)}


def recrc_value(complete_value: bytes) -> bytes:
    body = complete_value[:-4]
    return body + be32(crc32c(body))


def patch_body_bytes(complete_value: bytes, body_off: int, new_bytes: bytes) -> bytes:
    """Patch envelope body at body-relative offset and re-CRC."""
    st, body, pvd = extract_envelope(complete_value)
    b = bytearray(body)
    b[body_off : body_off + len(new_bytes)] = new_bytes
    # rebuild envelope keeping header prefix
    head = complete_value[40:72]
    primary_id = complete_value[16:32] if False else complete_value[24:40]
    # primary_id at offset 24: NLR1(4)+t2+v2+len4+hdr2+st1+fl1+rev8 = 24
    primary_id = complete_value[24:40]
    rev = struct.unpack(">Q", complete_value[16:24])[0]
    flags = complete_value[15]
    return enc_env_full(6, st, flags, rev, primary_id, head, pvd, bytes(b))


def make_ef_anchor() -> Tuple[Dict[str, str], List[str]]:
    typed = load_d1()["DSB2_ANCHOR_TYPED"]
    ef = load_d1()["DSB2_ANCHOR_EF_POSITIVE"]
    key = from_hex(typed["key_hex"])
    body = from_hex(ef["body_hex"])
    tv = from_hex(typed["value_hex"])
    primary_id = key[13:29]
    head = tv[40:72]
    val = enc_env_full(6, 0x20, 0, 1, primary_id, head, bytes(32), body)
    return (
        {"key_hex": hex_of(key), "value_hex": hex_of(val)},
        ["DSB2_ANCHOR_TYPED", "DSB2_ANCHOR_EF_POSITIVE"],
    )


def make_terminal_state() -> Tuple[Dict[str, str], List[str]]:
    base = d1_row("DSB2_STATE_TYPED")
    body = bytearray(d1_body("DSB2_STATE_TYPED"))
    body[48:52] = be32(TX_TERMINAL)
    if len(body) >= 212:
        body[208:212] = be32(TX_TERMINAL)
    tv = from_hex(base["value_hex"])
    primary_id = tv[24:40]
    head = tv[40:72]
    val = enc_env_full(6, 0x22, 0, 1, primary_id, head, bytes([0x55] * 32), bytes(body))
    return (
        {"key_hex": base["key_hex"], "value_hex": hex_of(val)},
        ["DSB2_STATE_TYPED"],
    )


def sort_rows(rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
    return sorted(rows, key=lambda r: from_hex(r["key_hex"]))


def merge_rows(*groups: List[Dict[str, str]]) -> List[Dict[str, str]]:
    by: Dict[str, Dict[str, str]] = {}
    for g in groups:
        for r in g:
            by[r["key_hex"]] = r
    return sort_rows(list(by.values()))

# ---------------------------------------------------------------------------
# Reference model (material-induced; no forced findings)
# ---------------------------------------------------------------------------


def expected_base(**kwargs: Any) -> Dict[str, Any]:
    base = {
        "final_status": "OK",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 0,
        "current_domain_key_count": 0,
        "ok_row_count": 0,
        "profile_exact_active": 0,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0,
        "family14_iter_seen_mask": 0,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": 1,
        "port_trace": [],
        "has_sticky_primary": 0,
        "sticky_primary": "",
        "d3_peer_get_count": 0,
        "d3_mode_applicable_count": 0,
    }
    base.update(kwargs)
    return base


def map_storage(status: str) -> str:
    return {
        "BUSY": "WOULD_BLOCK",
        "NO_SPACE": "CAPACITY_EXHAUSTED",
        "IO_ERROR": "STORAGE",
        "UNSUPPORTED_SCHEMA": "UNSUPPORTED",
        "COMMIT_UNKNOWN": "STORAGE_COMMIT_UNKNOWN",
        "CORRUPT": "STORAGE_CORRUPT",
        "BUFFER_TOO_SMALL": "STORAGE_CORRUPT",
        "NOT_FOUND": "OK",
        "OK": "OK",
        "UNKNOWN_RAW": "STORAGE_CORRUPT",
    }.get(status, "STORAGE_CORRUPT")


def _peer_raw_ok(mode: int, ev: PeerEval, peer_val: bytes, source_val: bytes) -> bool:
    """Byte-exact raw / dual-raw / kind bijection against peer body.

    Never treats mere peer presence as proof of body identity. Mode17 compares
    primary body identity fields (INGRESS ordered_sequence, ANCHOR txn/dual-raw,
    DELIVERY raw, SERVICE key) to rebuild material.
    """
    del source_val  # reserved for future source-subtype-specific paths
    try:
        pst, pbody, _ = extract_envelope(peer_val)
    except ValueError:
        return False
    if ev.dual_raw is not None and ev.dual_raw2 is not None:
        # Mode5 forward: peer is IDEM; Mode17 reverse: peer is ANCHOR
        if pst == ST_IDEM:
            im = parse_idem(pbody)
            return im["scope"] == ev.dual_raw and im["ikey"] == ev.dual_raw2
        if pst == ST_ANCHOR:
            a = parse_anchor(pbody)
            if a["scope"] != ev.dual_raw or a["ikey"] != ev.dual_raw2:
                return False
            # When subject_raw carries txn (IDEM reverse), require txn match too.
            if ev.subject_raw is not None and len(ev.subject_raw) == 16:
                return a["txn"] == ev.subject_raw
            return True
        return False
    if mode == 17:
        # True-primary body identity vs rebuild material (never presence-only).
        if pst == ST_SERVICE:
            sk = parse_service(pbody)["service_key_raw"]
            expect = ev.dual_raw if ev.dual_raw is not None else ev.subject_raw
            return expect is not None and sk == expect
        if pst == ST_ANCHOR:
            a = parse_anchor(pbody)
            if ev.subject_raw is None or len(ev.subject_raw) != 16:
                return False
            return a["txn"] == ev.subject_raw
        if pst == ST_INGRESS:
            ing = parse_ingress(pbody)
            if ev.subject_raw is None or len(ev.subject_raw) != 8:
                return False
            return ing["ordered_seq"] == ev.subject_raw
        if pst == ST_DELIVERY:
            d = parse_delivery(pbody)
            expect = ev.subject_raw
            if expect is None:
                return False
            # CALLBACK RES owner nests delivery_raw:RAW16 || token_generation:u64
            if (
                ev.owner_kind == 5
                and len(expect) >= 2 + 8
                and int.from_bytes(expect[:2], "big") == 80
            ):
                dlen = 80
                nested = expect[2 : 2 + dlen]
                return d["delivery_raw"] == nested
            return d["delivery_raw"] == expect
    if ev.raw_bijection and ev.owner_kind is not None and ev.subject_raw is not None:
        if pst == ST_SCHED:
            s = parse_sched(pbody)
            return s["owner_kind"] == ev.owner_kind and s["subject"] == ev.subject_raw
        if pst == ST_RES:
            r = parse_reservation(pbody)
            return r["owner_kind"] == ev.owner_kind and r["owner_raw"] == ev.subject_raw
        if pst == ST_RB:
            rb = parse_rb(pbody)
            return rb["kind"] == ev.owner_kind and rb["subject"] == ev.subject_raw
        if pst == ST_SERVICE and ev.dual_raw is not None:
            return parse_service(pbody)["service_key_raw"] == ev.dual_raw
    if ev.mode18_pair:
        if pst == ST_AII:
            aii = parse_aii(pbody)
            # subject_raw = owner_raw + attempt_id for attempt→aii
            if ev.subject_raw and len(ev.subject_raw) >= 16:
                return aii["attempt_id"] == ev.subject_raw[-16:]
            return False
        if pst == ST_ATTEMPT:
            att = parse_attempt(pbody)
            if ev.subject_raw and len(ev.subject_raw) >= 32:
                return (
                    att["owner_raw"] == ev.subject_raw[:16]
                    and att["attempt_id"] == ev.subject_raw[16:32]
                )
            return False
    if ev.raw_bijection and mode in (7, 13, 16) and pst == ST_SCHED:
        s = parse_sched(pbody)
        if ev.owner_kind is not None and s["owner_kind"] != ev.owner_kind:
            return False
        # Mode16 EXISTING_DELIVERY: subject_raw is independently composed
        # delivery raw; require exact peer subject bijection (no None skip).
        if ev.subject_raw is not None and s["subject"] != ev.subject_raw:
            return False
        if mode == 16 and ev.subject_raw is None:
            return False
        return True
    # Default: no identity obligation declared → accept; Mode17 paths above
    # already enforced identity when peer subtype is a true primary.
    if mode == 17 and ev.raw_bijection:
        return False
    return True


def run_case(vec: Dict[str, Any]) -> Dict[str, Any]:
    """Independent reference model for D3-S1 profiled crossrow lifecycle."""
    binding = vec["candidate_binding"]
    mode = int(vec.get("mode", 0))
    primary_rows = [
        (from_hex(r["key_hex"]), from_hex(r["value_hex"])) for r in vec.get("rows", [])
    ]
    alt_map: Dict[str, List[Tuple[bytes, bytes]]] = {}
    for name, rows in (vec.get("alt_rows") or {}).items():
        alt_map[name] = [
            (from_hex(r["key_hex"]), from_hex(r["value_hex"])) for r in rows
        ]
    faults: List[Dict[str, Any]] = copy.deepcopy(list(vec.get("faults", [])))
    used_fault_indices: Set[int] = set()
    calls = vec["calls"]

    rows = list(primary_rows)
    present_mask = 0
    retained: Dict[int, bytes] = {}
    get_call = 0
    iter_open_count = 0
    port_trace: List[str] = []
    mutation_calls = 0
    close_count = 0
    reopen_required = 0
    fence_pending = 0
    state = "IDLE"
    sticky: Optional[str] = None
    profile_exact = 0
    profile_mismatch = 0
    future_profile = 0
    recon = 0
    seen_mask = 0
    family14 = 0
    current_dom = 0
    ok_rows = 0
    future_seen = 0
    has_previous = False
    previous = b""
    row_index = 0
    txn_live = False
    iter_live = False
    original_authority = 0
    handle_drifted = 0
    last_status = "OK"
    call_statuses: List[str] = []
    d3_peer_get_count = 0
    d3_mode_applicable_count = 0
    d3_bound = 0
    active_mode = mode

    def set_sticky(s: str) -> None:
        nonlocal sticky
        if sticky is None:
            sticky = s

    def catalog_id(key: bytes) -> Optional[int]:
        if len(key) == 9 and key[:8] == ROOT_V1 and key[8] == 0x01:
            return 1
        if len(key) == 9 and key[:8] == ROOT_V1 and key[8] == 0x02:
            return 2
        if len(key) == 10 and key[:8] == ROOT_V1 and key[8] == 0x03 and 1 <= key[9] <= 4:
            return 2 + key[9]
        if len(key) == 10 and key[:8] == ROOT_V1 and key[8] == 0x04 and 1 <= key[9] <= 11:
            return 6 + key[9]
        return None

    def find_fault(op: str, on_call: int) -> Optional[Dict[str, Any]]:
        for index, f in enumerate(faults):
            if index in used_fault_indices:
                continue
            if f["op"] == op and int(f["on_call"]) == on_call:
                used_fault_indices.add(index)
                return f
        return None

    def lookup(key: bytes) -> Optional[bytes]:
        for k, v in rows:
            if k == key:
                return v
        return None

    def validate_and_compare() -> str:
        saw_unsup = False
        saw_corrupt = False
        for kid in range(1, 18):
            val = retained.get(kid)
            if val is None:
                saw_corrupt = True
                continue
            if len(val) < 16 or val[:4] != b"NLR1":
                saw_corrupt = True
                continue
            ver = struct.unpack(">H", val[6:8])[0]
            if ver != 1:
                saw_unsup = True
                continue
            body = val[:-4]
            crc = struct.unpack(">I", val[-4:])[0]
            if crc != crc32c(body):
                saw_corrupt = True
                continue
        if saw_corrupt:
            return "STORAGE_CORRUPT"
        if saw_unsup:
            return "FUTURE"
        bval = retained.get(1, b"")
        if len(bval) >= 183:
            want = encode_binding(binding)
            if bval != want:
                return "MISMATCH"
        return "EXACT"

    def do_profile_gets() -> Optional[str]:
        nonlocal get_call, present_mask, fence_pending, retained
        retained = {}
        present_mask = 0
        for kid in range(1, 18):
            get_call += 1
            port_trace.append("get")
            key = catalog_key(kid)
            fault = find_fault("get", get_call)
            capacity = {1: 183, 2: 84}.get(kid, 32 if kid <= 6 else 68)
            if fault is not None:
                shape = fault.get("shape", "natural")
                status = fault.get("status", "OK")
                if shape == "unknown" or status == "UNKNOWN_RAW":
                    fence_pending = 1
                    return "STORAGE_CORRUPT"
                if status != "OK":
                    return map_storage(status)
            raw = lookup(key)
            if raw is None:
                return "STORAGE_CORRUPT"
            if len(raw) > capacity:
                return "STORAGE_CORRUPT"
            retained[kid] = raw
            present_mask |= 1 << (kid - 1)
        if present_mask != ALL_MASK:
            return "STORAGE_CORRUPT"
        return validate_and_compare()

    def cleanup() -> str:
        nonlocal state, txn_live, iter_live, close_count, reopen_required
        nonlocal fence_pending, original_authority
        if iter_live and txn_live:
            port_trace.append("iter_close")
            iter_live = False
        if txn_live:
            rb_count = 1 + sum(1 for t in port_trace if t == "rollback")
            rb_fault = find_fault("rollback", rb_count)
            port_trace.append("rollback")
            txn_live = False
            iter_live = False
            if rb_fault is not None:
                st = rb_fault.get("status", "IO_ERROR")
                shape = rb_fault.get("shape", "natural")
                fence_pending = 1
                if shape == "unknown" or st == "UNKNOWN_RAW":
                    mapped = "STORAGE_CORRUPT"
                else:
                    mapped = map_storage(st)
                if sticky is None:
                    set_sticky(mapped)
        outcome = sticky or "OK"
        if fence_pending:
            port_trace.append("close")
            close_count += 1
            reopen_required = 1
            fence_pending = 0
            original_authority = 0
        else:
            original_authority = 0
        state = "DONE"
        return outcome

    def reset_session_soft() -> None:
        nonlocal state, sticky, profile_exact, profile_mismatch, future_profile
        nonlocal recon, seen_mask, family14, current_dom, ok_rows, future_seen
        nonlocal has_previous, previous, row_index, txn_live, iter_live
        nonlocal present_mask, retained, fence_pending, original_authority
        nonlocal handle_drifted, d3_bound, get_call
        # Accumulate d3_peer_get_count / d3_mode_applicable_count / port_trace
        # / close_count / iter_open_count across sessions for multi-session vectors.
        state = "IDLE"
        sticky = None
        profile_exact = 0
        profile_mismatch = 0
        future_profile = 0
        recon = 0
        seen_mask = 0
        family14 = 0
        current_dom = 0
        ok_rows = 0
        future_seen = 0
        has_previous = False
        previous = b""
        row_index = 0
        txn_live = False
        iter_live = False
        present_mask = 0
        retained = {}
        fence_pending = 0
        original_authority = 0
        handle_drifted = 0
        d3_bound = 0
        get_call = 0

    def apply_d3_peer(source_key: bytes, source_val: bytes) -> Optional[str]:
        """Material-induced peer evaluation. No forced findings."""
        nonlocal get_call, d3_peer_get_count, d3_mode_applicable_count
        nonlocal fence_pending
        try:
            ev = rebuild_peer(active_mode, source_key, source_val)
        except ValueError:
            return "STORAGE_CORRUPT"
        if ev is None:
            return None
        d3_mode_applicable_count += 1
        peer_key = ev.peer_key
        expect = ev.expect_presence
        get_call += 1
        port_trace.append("get")
        d3_peer_get_count += 1
        fault = find_fault("get", get_call)
        if fault is not None:
            shape = fault.get("shape", "natural")
            status = fault.get("status", "IO_ERROR")
            if shape == "unknown" or status == "UNKNOWN_RAW":
                fence_pending = 1
                return "STORAGE_CORRUPT"
            return map_storage(status)
        peer_val = lookup(peer_key)
        present = peer_val is not None
        if expect == "PRESENT" and not present:
            return "STORAGE_CORRUPT"
        if expect == "ABSENT" and present:
            return "STORAGE_CORRUPT"
        if expect == "ABSENT" and not present:
            return None
        assert peer_val is not None
        # Mode17 layering: ALWAYS VALUE_DIGEST(primary) vs source header PVD
        # before any future-version skip. After matching PVD, future framing
        # skips envelope/raw only (not a forced OK without PVD isolation).
        if active_mode == 17:
            if ev.check_pvd and not ev.skip_pvd:
                live = value_digest(peer_val)
                want = header_pvd(source_val)
                if not want or live != want:
                    return "STORAGE_CORRUPT"
            framing = domain_value_framing(peer_val)
            if framing == "future":
                # PVD already matched (or check disabled); skip body/raw only.
                return None
            if framing != "current":
                return "STORAGE_CORRUPT"
            if ev.raw_bijection or ev.dual_raw is not None or ev.mode18_pair:
                if not _peer_raw_ok(active_mode, ev, peer_val, source_val):
                    return "STORAGE_CORRUPT"
            return None
        # Non-17: peer header PVD vs source value-digest (unless skip)
        if ev.check_pvd and not ev.skip_pvd:
            src_digest = value_digest(source_val)
            peer_hdr = header_pvd(peer_val)
            if peer_hdr and peer_hdr != src_digest:
                return "STORAGE_CORRUPT"
        # Dual-raw / kind / subject bijection
        if ev.raw_bijection or ev.dual_raw is not None or ev.mode18_pair:
            if not _peer_raw_ok(active_mode, ev, peer_val, source_val):
                return "STORAGE_CORRUPT"
        return None

    def do_advance(budget: int) -> str:
        nonlocal row_index, ok_rows, family14, seen_mask, has_previous, previous
        nonlocal state, future_seen, current_dom, fence_pending
        if state != "OPEN":
            return "INVALID_STATE"
        if budget == 0:
            return "INVALID_ARGUMENT"
        if handle_drifted:
            set_sticky("STORAGE_CORRUPT")
            fence_pending = 1
            state = "FAILED"
            return "STORAGE_CORRUPT"
        if not txn_live or not iter_live:
            set_sticky("STORAGE_CORRUPT")
            state = "FAILED"
            return "STORAGE_CORRUPT"
        consumed = 0
        while consumed < budget:
            port_trace.append("iter_next")
            if row_index >= len(rows):
                if recon and seen_mask != present_mask:
                    set_sticky("STORAGE_CORRUPT")
                    state = "FAILED"
                    return "STORAGE_CORRUPT"
                state = "EXHAUSTED"
                return "OK"
            key, val = rows[row_index]
            row_index += 1
            if len(key) < 1 or len(key) > KEY_CAP or len(val) > VALUE_CAP:
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                return "STORAGE_CORRUPT"
            if has_previous and not (key > previous):
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                return "STORAGE_CORRUPT"
            kid = catalog_id(key)
            row_ok = True
            if kid is not None and recon:
                bit = 1 << (kid - 1)
                if seen_mask & bit:
                    set_sticky("STORAGE_CORRUPT")
                    state = "FAILED"
                    return "STORAGE_CORRUPT"
                if retained.get(kid) != val:
                    set_sticky("STORAGE_CORRUPT")
                    state = "FAILED"
                    return "STORAGE_CORRUPT"
                seen_mask |= bit
                family14 += 1
            elif kid is not None:
                family14 += 1
            elif profile_mismatch or future_profile:
                pass
            elif (
                len(key) >= 8
                and len(key) <= KEY_CAP
                and key[:7] == ROOT_V1[:7]
                and key[7] >= 2
                and len(val) >= 16
                and val[:4] == b"NLR1"
                and struct.unpack(">I", val[-4:])[0] == crc32c(val[:-4])
            ):
                # Recognizable future root key (version >= 2).
                future_seen = 1
            elif len(key) >= 8 and key[:7] == ROOT_V1[:7] and key[7] >= 2:
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                return "STORAGE_CORRUPT"
            else:
                # CURRENT domain path (exact-profile S3 + optional D3).
                # Framing-future values (record_version>=2) set future_seen and
                # skip D3 (typed_current_ok=0); PVD-first Mode17 isolation is
                # only applied when the source row itself is CURRENT-typed.
                current_dom += 1
                if profile_exact:
                    s3 = family6_current_row_s3_status(key, val)
                    if s3 == "UNSUPPORTED":
                        future_seen = 1
                    elif s3 != "OK":
                        # Non-family6 CURRENT under exact profile: still try
                        # coarse framing for future envelope, else accept for
                        # oracle (family5 / other not fully modeled here).
                        parsed = parse_domain_key(key)
                        if parsed is not None and parsed[0] == 6:
                            set_sticky("STORAGE_CORRUPT")
                            state = "FAILED"
                            row_ok = False
                            previous = key
                            has_previous = True
                            consumed += 1
                            return "STORAGE_CORRUPT"
                        framing = domain_value_framing(val)
                        if framing == "future":
                            future_seen = 1
                        elif framing == "corrupt" and parsed is not None:
                            set_sticky("STORAGE_CORRUPT")
                            state = "FAILED"
                            row_ok = False
                            previous = key
                            has_previous = True
                            consumed += 1
                            return "STORAGE_CORRUPT"
                    elif d3_bound and not sticky:
                        # Full CURRENT typed success → D3 hybrid leg.
                        d3_st = apply_d3_peer(key, val)
                        if d3_st is not None:
                            set_sticky(d3_st)
                            state = "FAILED"
                            row_ok = False
                            previous = key
                            has_previous = True
                            consumed += 1
                            return d3_st
            previous = key
            has_previous = True
            if row_ok:
                ok_rows += 1
            consumed += 1
        return "OK"

    def do_exact_get(key_hex: str) -> str:
        nonlocal get_call, state, fence_pending
        if state not in ("OPEN", "EXHAUSTED"):
            return "INVALID_STATE"
        key = from_hex(key_hex) if key_hex is not None else b""
        if not key or len(key) < 1 or len(key) > KEY_CAP:
            return "INVALID_ARGUMENT"
        if handle_drifted:
            set_sticky("STORAGE_CORRUPT")
            fence_pending = 1
            state = "FAILED"
            return "STORAGE_CORRUPT"
        if not txn_live or not iter_live:
            set_sticky("STORAGE_CORRUPT")
            state = "FAILED"
            return "STORAGE_CORRUPT"
        get_call += 1
        port_trace.append("get")
        raw = lookup(key)
        if raw is None:
            return "OK"
        if len(raw) > VALUE_CAP:
            set_sticky("STORAGE_CORRUPT")
            state = "FAILED"
            return "STORAGE_CORRUPT"
        return "OK"

    def do_note() -> str:
        nonlocal state
        if state not in ("OPEN", "EXHAUSTED"):
            return "INVALID_STATE"
        set_sticky("STORAGE_CORRUPT")
        state = "FAILED"
        return "STORAGE_CORRUPT"

    for call in calls:
        op = call["op"]
        if op not in CLOSED_CALL_OPS:
            raise SystemExit(f"unknown call op {op}")
        if op in FORBIDDEN_CALL_OPS:
            raise SystemExit(f"forbidden call op {op}")
        if op == "session_init":
            if state not in ("DONE", "IDLE"):
                raise SystemExit(
                    f"illegal session_init ordering while state={state}"
                )
            reset_session_soft()
            last_status = "VOID"
            call_statuses.append("VOID")
            continue
        if op == "use_rows":
            name = call.get("name", "")
            if name not in alt_map:
                raise SystemExit(f"unknown alt_rows name {name}")
            if state != "IDLE":
                raise SystemExit(
                    f"illegal use_rows ordering while state={state}"
                )
            rows = list(alt_map[name])
            last_status = "VOID"
            call_statuses.append("VOID")
            continue
        if op == "handle_drift":
            if state not in ("OPEN", "EXHAUSTED", "FAILED"):
                raise SystemExit(
                    f"illegal handle_drift ordering while state={state}"
                )
            handle_drifted = 1
            last_status = "VOID"
            call_statuses.append("VOID")
            continue
        if op == "begin_profiled":
            # D2-only begin: no D3 mode/context, d3_bound stays 0 → zero
            # D3 applicability / peer gets / notes regardless of domain rows.
            if state != "IDLE":
                last_status = "INVALID_STATE"
                call_statuses.append(last_status)
                continue
            if "mode" in call or call.get("context") is not None:
                # D2 begin must not carry D3 mode/context material.
                last_status = "INVALID_ARGUMENT"
                call_statuses.append(last_status)
                continue
            active_mode = 0
            port_trace.append("begin:READ_ONLY")
            txn_live = True
            original_authority = 1
            d3_bound = 0
            gate = do_profile_gets()
            if gate not in ("EXACT", "MISMATCH", "FUTURE"):
                set_sticky(gate or "STORAGE_CORRUPT")
                last_status = cleanup()
                call_statuses.append(last_status)
                continue
            if gate == "EXACT":
                profile_exact = 1
            elif gate == "MISMATCH":
                profile_mismatch = 1
            else:
                future_profile = 1
            recon = 1
            fault = find_fault("iter_open", 1)
            if fault is not None:
                set_sticky("STORAGE_CORRUPT")
                last_status = cleanup()
                call_statuses.append(last_status)
                continue
            port_trace.append("iter_open:prefix0")
            iter_open_count += 1
            iter_live = True
            state = "OPEN"
            row_index = 0
            last_status = "OK"
            call_statuses.append(last_status)
        elif op == "begin_profiled_d3s1":
            if state != "IDLE":
                last_status = "INVALID_STATE"
                call_statuses.append(last_status)
                continue
            call_mode = int(call.get("mode", mode))
            active_mode = call_mode
            ctx = call.get("context")
            if call_mode < 1 or call_mode > 20:
                last_status = "INVALID_ARGUMENT"
                call_statuses.append(last_status)
                continue
            if ctx in ("null", "alias_session"):
                last_status = "INVALID_ARGUMENT"
                call_statuses.append(last_status)
                continue
            port_trace.append("begin:READ_ONLY")
            txn_live = True
            original_authority = 1
            d3_bound = 1
            gate = do_profile_gets()
            if gate not in ("EXACT", "MISMATCH", "FUTURE"):
                set_sticky(gate or "STORAGE_CORRUPT")
                last_status = cleanup()
                call_statuses.append(last_status)
                continue
            if gate == "EXACT":
                profile_exact = 1
            elif gate == "MISMATCH":
                profile_mismatch = 1
            else:
                future_profile = 1
            recon = 1
            fault = find_fault("iter_open", 1)
            if fault is not None:
                set_sticky("STORAGE_CORRUPT")
                last_status = cleanup()
                call_statuses.append(last_status)
                continue
            port_trace.append("iter_open:prefix0")
            iter_open_count += 1
            iter_live = True
            state = "OPEN"
            row_index = 0
            last_status = "OK"
            call_statuses.append(last_status)
        elif op == "advance":
            last_status = do_advance(int(call.get("row_budget", 0)))
            call_statuses.append(last_status)
        elif op == "exact_get":
            last_status = do_exact_get(call.get("key_hex", ""))
            call_statuses.append(last_status)
        elif op == "note_terminal_corrupt":
            last_status = do_note()
            call_statuses.append(last_status)
        elif op == "finalize":
            if state not in ("EXHAUSTED", "FAILED"):
                last_status = "INVALID_STATE"
            else:
                outcome = cleanup()
                if sticky:
                    last_status = sticky
                elif profile_mismatch or future_profile:
                    last_status = "UNSUPPORTED"
                elif future_seen:
                    last_status = "UNSUPPORTED"
                else:
                    last_status = outcome
            call_statuses.append(last_status)
        elif op == "abort":
            if state not in ("OPEN", "EXHAUSTED", "FAILED"):
                last_status = "INVALID_STATE"
            else:
                outcome = cleanup()
                last_status = sticky or outcome
            call_statuses.append(last_status)
        else:
            raise SystemExit(f"unknown call op {op}")

    if len(call_statuses) != len(calls):
        raise SystemExit("internal: call_statuses length mismatch")

    for call, st in zip(calls, call_statuses):
        call["expected_status"] = st

    if not calls:
        raise SystemExit("vector has empty calls")
    if calls[-1]["op"] in HARNESS_CALL_OPS:
        raise SystemExit("vector must not end on harness-only op")
    final_status = last_status

    adopted = 0
    if (
        calls[-1]["op"] == "finalize"
        and final_status == "OK"
        and reopen_required == 0
        and sticky is None
        and not profile_mismatch
        and not future_profile
        and not future_seen
        and state == "DONE"
    ):
        adopted = 1

    return expected_base(
        final_status=final_status,
        adopted=adopted,
        state_after=state,
        recognizable_future_seen=future_seen,
        family14_row_count=family14,
        current_domain_key_count=current_dom,
        ok_row_count=ok_rows,
        profile_exact_active=profile_exact,
        profile_mismatch=profile_mismatch,
        future_profile_candidate=future_profile,
        profile_get_present_mask=present_mask,
        family14_iter_seen_mask=seen_mask,
        reopen_required=reopen_required,
        close_count=close_count,
        mutation_calls=mutation_calls,
        iter_open_count=iter_open_count,
        port_trace=list(port_trace),
        has_sticky_primary=1 if sticky is not None else 0,
        sticky_primary=sticky or "",
        d3_peer_get_count=d3_peer_get_count,
        d3_mode_applicable_count=d3_mode_applicable_count,
    )


def make_vector(
    vid: str,
    kind: str,
    mode: int,
    rows: List[Dict[str, str]],
    calls: List[Dict[str, Any]],
    *,
    d1_refs: Optional[List[str]] = None,
    faults: Optional[List[Dict[str, Any]]] = None,
    binding: Optional[Dict[str, Any]] = None,
    alt_rows: Optional[Dict[str, List[Dict[str, str]]]] = None,
    source_ref: Optional[Dict[str, Any]] = None,
    peer_ref: Optional[Dict[str, Any]] = None,
    notes: str = "",
    ownership: str = "",
    require_rebuild: bool = True,
) -> Dict[str, Any]:
    stamped_calls = [copy.deepcopy(c) for c in calls]
    refs = list(d1_refs or [])
    d1_verify_refs(refs, rows)
    src_ref = source_ref or none_ref()
    pr_ref = peer_ref or none_ref()
    # Semantic assertion: peer key must be independently rebuildable when present
    if require_rebuild and src_ref.get("key_hex") and pr_ref.get("key_hex"):
        src_row = None
        for r in rows:
            if r["key_hex"] == src_ref["key_hex"]:
                src_row = r
                break
        if src_row is None and src_ref.get("value_hex"):
            src_row = {
                "key_hex": src_ref["key_hex"],
                "value_hex": src_ref["value_hex"],
            }
        if src_row is not None:
            # Use active mode from first D3 begin call if present
            begin_mode = mode
            for c in stamped_calls:
                if c.get("op") == "begin_profiled_d3s1":
                    begin_mode = int(c.get("mode", mode))
                    break
                if c.get("op") == "begin_profiled":
                    # D2-only path: peer rebuild not required via D3 mode
                    begin_mode = 0
                    break
            if begin_mode != 0:
                assert_peer_key_rebuildable(
                    begin_mode,
                    src_row["key_hex"],
                    src_row["value_hex"],
                    pr_ref["key_hex"],
                )
    row_refs = build_row_refs(refs, rows, src_ref, pr_ref)
    note_text = notes or (
        f"mode={mode} kind={kind}; exact-1 crossrow oracle case; mutation_calls=0"
    )
    vec: Dict[str, Any] = {
        "id": vid,
        "kind": kind,
        "mode": mode,
        "candidate_binding": binding or default_binding_fields(),
        "rows": rows,
        "alt_rows": alt_rows or {},
        "faults": faults or [],
        "calls": stamped_calls,
        "d1_refs": refs,
        "source_ref": src_ref,
        "peer_ref": pr_ref,
        "row_refs": row_refs,
        "notes": note_text,
        "ownership": ownership or OWNERSHIP_DEFAULT,
    }
    vec["expected"] = run_case(vec)
    return vec


def std_scan_calls(mode: int, budget: int = 64) -> List[Dict[str, Any]]:
    return [
        {"op": "begin_profiled_d3s1", "mode": mode},
        {"op": "advance", "row_budget": budget},
        {"op": "finalize"},
    ]


# ---------------------------------------------------------------------------
# Case builders (material-induced peers; no forced findings)
# ---------------------------------------------------------------------------


def pair_present(
    vid: str,
    kind: str,
    mode: int,
    source_id: str,
    peer_id: str,
    *,
    extra_ids: Optional[List[str]] = None,
    source_row: Optional[Dict[str, str]] = None,
    peer_row: Optional[Dict[str, str]] = None,
    patch_peer_pvd: bool = True,
    skip_pvd: bool = False,
    notes: str = "",
) -> Dict[str, Any]:
    b = default_binding_fields()
    profile = encode_all_profile_rows(b)
    src = source_row if source_row is not None else d1_row(source_id)
    if peer_row is not None:
        peer = peer_row
    else:
        peer = d1_row(peer_id)
        if patch_peer_pvd and not skip_pvd and mode != 17:
            peer = {
                "key_hex": peer["key_hex"],
                "value_hex": hex_of(
                    patch_pvd(
                        from_hex(peer["value_hex"]),
                        value_digest(from_hex(src["value_hex"])),
                    )
                ),
            }
    if mode == 17 and patch_peer_pvd:
        # Patch SOURCE header PVD to live primary value digest. CLEANUP_PLAN
        # also carries subject_primary_value_digest in the body, which must
        # equal header PVD (same-record) and the live primary digest (Mode17).
        live = value_digest(from_hex(peer["value_hex"]))
        src_val = from_hex(src["value_hex"])
        try:
            src_st, _src_body, _ = extract_envelope(src_val)
        except ValueError:
            src_st = 0
        if src_st == ST_CP:
            src = {
                "key_hex": src["key_hex"],
                "value_hex": hex_of(
                    patch_cleanup_plan_live_primary_digest(src_val, live)
                ),
            }
        else:
            src = {
                "key_hex": src["key_hex"],
                "value_hex": hex_of(patch_pvd(src_val, live)),
            }
    # Validate rebuild: peer key must equal independent rebuild
    ev = assert_peer_key_rebuildable(
        mode, src["key_hex"], src["value_hex"], peer["key_hex"]
    )
    if skip_pvd:
        # rebuild may still want PVD; harness uses skip via material rules
        pass
    rows = merge_rows(profile, [src, peer])
    refs = [source_id, peer_id] + list(extra_ids or [])
    # Drop empty ids
    refs = [r for r in refs if r]
    src_ref = d1_ref_from_id(
        source_id, row=src, expect_presence="PRESENT", note="source applicable row"
    ) if source_id else synthetic_ref(
        key_hex=src["key_hex"],
        value_hex=src["value_hex"],
        expect_presence="PRESENT",
        note="synthetic source",
    )
    if peer_id and peer["key_hex"] == d1_row(peer_id)["key_hex"]:
        pr_ref = d1_ref_from_id(
            peer_id, row=peer, expect_presence="PRESENT", note="peer exact_get target"
        )
    else:
        pr_ref = synthetic_ref(
            key_hex=peer["key_hex"],
            value_hex=peer["value_hex"],
            expect_presence="PRESENT",
            note=f"synthetic peer ({ev.note})",
        )
    return make_vector(
        vid,
        kind,
        mode,
        rows,
        std_scan_calls(mode),
        d1_refs=refs,
        source_ref=src_ref,
        peer_ref=pr_ref,
        notes=notes
        or (
            f"mode{mode} present_ok: rebuilt peer key; {ev.note}; "
            f"material-induced PVD/raw (skip_pvd={skip_pvd})"
        ),
    )


def pair_absent(
    vid: str,
    kind: str,
    mode: int,
    source_id: str,
    *,
    source_row: Optional[Dict[str, str]] = None,
    extra_ids: Optional[List[str]] = None,
    notes: str = "",
) -> Dict[str, Any]:
    b = default_binding_fields()
    profile = encode_all_profile_rows(b)
    src = source_row if source_row is not None else d1_row(source_id)
    ev = rebuild_peer(mode, from_hex(src["key_hex"]), from_hex(src["value_hex"]))
    if ev is None:
        raise SystemExit(f"{vid}: source not applicable for mode {mode}")
    if ev.expect_presence != "ABSENT":
        raise SystemExit(f"{vid}: rebuild expect {ev.expect_presence} not ABSENT")
    rows = merge_rows(profile, [src])
    return make_vector(
        vid,
        kind,
        mode,
        rows,
        std_scan_calls(mode),
        d1_refs=[source_id] + list(extra_ids or []),
        source_ref=d1_ref_from_id(
            source_id, row=src, expect_presence="PRESENT", note="source applicable row"
        ),
        peer_ref=absent_ref(
            peer_key_hex=hex_of(ev.peer_key),
            note=f"ABSENT peer expected; {ev.note}",
        ),
        notes=notes or f"mode{mode} expect ABSENT; {ev.note}",
    )


def pair_missing(
    vid: str,
    kind: str,
    mode: int,
    source_id: str,
    *,
    source_row: Optional[Dict[str, str]] = None,
    notes: str = "",
) -> Dict[str, Any]:
    """PRESENT expected but peer row omitted → material missing corrupt."""
    b = default_binding_fields()
    profile = encode_all_profile_rows(b)
    src = source_row if source_row is not None else d1_row(source_id)
    ev = rebuild_peer(mode, from_hex(src["key_hex"]), from_hex(src["value_hex"]))
    if ev is None or ev.expect_presence != "PRESENT":
        raise SystemExit(f"{vid}: need PRESENT rebuild for missing-peer case")
    rows = merge_rows(profile, [src])  # peer intentionally absent
    return make_vector(
        vid,
        kind,
        mode,
        rows,
        std_scan_calls(mode),
        d1_refs=[source_id],
        source_ref=d1_ref_from_id(
            source_id, row=src, expect_presence="PRESENT", note="source applicable row"
        ),
        peer_ref=absent_ref(
            peer_key_hex=hex_of(ev.peer_key),
            note="peer key rebuilt but row omitted → missing corrupt",
        ),
        notes=notes
        or f"mode{mode} missing peer corrupt: rebuilt key absent from snapshot",
    )


def build_vectors() -> List[Dict[str, Any]]:
    b = default_binding_fields()
    profile = encode_all_profile_rows(b)
    vectors: List[Dict[str, Any]] = []

    def add(v: Dict[str, Any]) -> None:
        vectors.append(v)

    # --- Mode1 SERVICE → QUOTA ---
    add(
        pair_present(
            "D3S1_M01_SERVICE_QUOTA_PRESENT",
            "mode1_present_ok",
            1,
            "DSB2_SERVICE_TYPED",
            "DSB2_QUOTA_TYPED",
        )
    )
    add(
        pair_present(
            "D3S1_M02_SERVICE_RES_PRESENT",
            "mode2_present_ok",
            2,
            "DSB2_SERVICE_TYPED",
            "DSB2_RES_SVC_TYPED",
        )
    )
    add(
        pair_present(
            "D3S1_M03_TX_SEQ_PRESENT",
            "mode3_present_ok",
            3,
            "DSB2_ANCHOR_TYPED",
            "DSB2_SEQ_TYPED",
        )
    )
    add(
        pair_present(
            "D3S1_M04_TX_STATE_PRESENT",
            "mode4_present_ok",
            4,
            "DSB2_ANCHOR_TYPED",
            "DSB2_STATE_TYPED",
        )
    )
    add(
        pair_present(
            "D3S1_M05_TX_IDEM_PRESENT",
            "mode5_dual_raw_present_ok",
            5,
            "DSB2_ANCHOR_TYPED",
            "DSB2_IDEM_TYPED",
        )
    )

    # Mode5 dual-raw mismatch: peer PRESENT at rebuilt key, PVD matches, dual-raw differs
    src5 = d1_row("DSB2_ANCHOR_TYPED")
    ev5 = rebuild_peer(5, from_hex(src5["key_hex"]), from_hex(src5["value_hex"]))
    assert ev5 is not None
    # Start from correct IDEM peer, then corrupt dual-raw fields in body only
    peer5 = row_from_d1(
        "DSB2_IDEM_TYPED",
        pvd_primary=value_digest(from_hex(src5["value_hex"])),
    )
    # Ensure key equals rebuild (same dual-raw → same key)
    if peer5["key_hex"] != hex_of(ev5.peer_key):
        raise SystemExit("Mode5 D1 IDEM key != rebuild")
    # Mutate peer body scope first content byte (body-relative after extract)
    pval = from_hex(peer5["value_hex"])
    _st, pbody, _ = extract_envelope(pval)
    # scope is at body[0:2+len]; flip a content byte inside scope
    mut_body = bytearray(pbody)
    # scope contents start at offset 2
    mut_body[2] ^= 0x5A
    peer5_bad = {
        "key_hex": peer5["key_hex"],  # key still old dual-raw hash
        "value_hex": hex_of(
            enc_env_full(
                6,
                ST_IDEM,
                0,
                1,
                from_hex(peer5["value_hex"])[24:40],
                from_hex(peer5["value_hex"])[40:72],
                value_digest(from_hex(src5["value_hex"])),
                bytes(mut_body),
            )
        ),
    }
    add(
        make_vector(
            "D3S1_M05_DUAL_RAW_MISMATCH",
            "mode5_dual_raw_mismatch_corrupt",
            5,
            merge_rows(profile, [src5, peer5_bad]),
            std_scan_calls(5),
            d1_refs=["DSB2_ANCHOR_TYPED", "DSB2_IDEM_TYPED"],
            source_ref=d1_ref_from_id(
                "DSB2_ANCHOR_TYPED", row=src5, expect_presence="PRESENT"
            ),
            peer_ref=synthetic_ref(
                rid="DSB2_IDEM_TYPED",
                key_hex=peer5_bad["key_hex"],
                value_hex=peer5_bad["value_hex"],
                expect_presence="PRESENT",
                note="IDEM body dual-raw mutated; key still source-rebuilt",
                mutations=[
                    {
                        "offset": 2,
                        "old_hex": f"{pbody[2]:02x}",
                        "new_hex": f"{mut_body[2]:02x}",
                        "recompute": "crc32c_trailer",
                        "directive": "byte_patch_body_dual_raw",
                    }
                ],
            ),
            notes="Mode5 dual-raw bijection fail: material scope byte flip on peer body",
        )
    )

    add(
        pair_present(
            "D3S1_M06_TX_RES_PRESENT",
            "mode6_present_ok",
            6,
            "DSB2_ANCHOR_TYPED",
            "DSB2_RES_TX_TYPED",
        )
    )

    # Mode7: synthetic SCHED peer matching anchor.scheduler_owner_sequence
    src7 = d1_row("DSB2_ANCHOR_TYPED")
    ev7 = rebuild_peer(7, from_hex(src7["key_hex"]), from_hex(src7["value_hex"]))
    assert ev7 is not None and ev7.subject_raw is not None and ev7.owner_kind is not None
    a7 = parse_anchor(d1_body("DSB2_ANCHOR_TYPED"))
    sched7_body = make_sched_body(a7["sched_seq"], 1, a7["txn"])
    peer7 = make_row(
        ev7.peer_key,
        sched7_body,
        subtype=ST_SCHED,
        primary_id=scheduler_primary_id(1, a7["txn"]),
        pvd=value_digest(from_hex(src7["value_hex"])),
    )
    add(
        make_vector(
            "D3S1_M07_TX_SCHED_PRESENT",
            "mode7_present_ok",
            7,
            merge_rows(profile, [src7, peer7]),
            std_scan_calls(7),
            d1_refs=["DSB2_ANCHOR_TYPED"],
            source_ref=d1_ref_from_id("DSB2_ANCHOR_TYPED", row=src7),
            peer_ref=synthetic_ref(
                key_hex=peer7["key_hex"],
                value_hex=peer7["value_hex"],
                expect_presence="PRESENT",
                note=f"synthetic SCHED seq={a7['sched_seq']} owner_kind=1 subject=txn",
            ),
            notes="Mode7 synthetic SCHED peer: key=scheduler_owner_sequence from ANCHOR body",
        )
    )

    # Mode8/9 family gates
    add(
        pair_absent(
            "D3S1_M08_DS_EVENT_MAP_ABSENT",
            "mode8_ds_absent_ok",
            8,
            "DSB2_ANCHOR_TYPED",
        )
    )
    ef_anchor, ef_refs = make_ef_anchor()
    ev8 = rebuild_peer(8, from_hex(ef_anchor["key_hex"]), from_hex(ef_anchor["value_hex"]))
    assert ev8 is not None and ev8.expect_presence == "PRESENT"
    # EVMAP key from EF material; may differ from DSB2_EVMAP (DS scope/event)
    # Build synthetic EVMAP at rebuilt key with PVD
    a_ef = parse_anchor(from_hex(load_d1()["DSB2_ANCHOR_EF_POSITIVE"]["body_hex"]))
    emap_body = (
        raw16(a_ef["scope"])
        + a_ef["event_id"]
        + a_ef["txn"]
        + key_digest(from_hex(ef_anchor["key_hex"]))
        + bytes(32)
    )
    # Keep body simple: use D1 EVMAP body shape if key matches else minimal synthetic
    if hex_of(ev8.peer_key) == d1_row("DSB2_EVMAP_TYPED")["key_hex"]:
        peer_em = row_from_d1(
            "DSB2_EVMAP_TYPED",
            pvd_primary=value_digest(from_hex(ef_anchor["value_hex"])),
        )
        em_ref = d1_ref_from_id("DSB2_EVMAP_TYPED", row=peer_em)
        em_refs = ef_refs + ["DSB2_EVMAP_TYPED"]
    else:
        peer_em = make_row(
            ev8.peer_key,
            d1_body("DSB2_EVMAP_TYPED"),  # shape only
            subtype=ST_EVMAP,
            primary_id=a_ef["txn"],
            pvd=value_digest(from_hex(ef_anchor["value_hex"])),
        )
        # body from D1 may not match EF event — use parsed material body
        peer_em = make_row(
            ev8.peer_key,
            (
                raw16(a_ef["scope"])
                + a_ef["event_id"]
                + a_ef["txn"]
                + bytes(32)  # placeholder digests pad to reasonable
                + bytes(32)
            ),
            subtype=ST_EVMAP,
            primary_id=a_ef["txn"],
            pvd=value_digest(from_hex(ef_anchor["value_hex"])),
        )
        em_ref = synthetic_ref(
            key_hex=peer_em["key_hex"],
            value_hex=peer_em["value_hex"],
            expect_presence="PRESENT",
            note="synthetic EVMAP for EF anchor event_id",
        )
        em_refs = ef_refs
    add(
        make_vector(
            "D3S1_M08_EF_EVENT_MAP_PRESENT",
            "mode8_ef_present_ok",
            8,
            merge_rows(profile, [ef_anchor, peer_em]),
            std_scan_calls(8),
            d1_refs=em_refs,
            source_ref=synthetic_ref(
                rid="DSB2_ANCHOR_EF_POSITIVE",
                key_hex=ef_anchor["key_hex"],
                value_hex=ef_anchor["value_hex"],
                expect_presence="PRESENT",
                note="EF ANCHOR synthetic envelope",
            ),
            peer_ref=em_ref,
        )
    )
    add(
        pair_absent(
            "D3S1_M09_DS_EVENT_SPOOL_ABSENT",
            "mode9_ds_absent_ok",
            9,
            "DSB2_ANCHOR_TYPED",
        )
    )
    ev9 = rebuild_peer(9, from_hex(ef_anchor["key_hex"]), from_hex(ef_anchor["value_hex"]))
    assert ev9 is not None
    if hex_of(ev9.peer_key) == d1_row("DSB3_ES_ACTIVE_TYPED")["key_hex"]:
        peer_es = row_from_d1(
            "DSB3_ES_ACTIVE_TYPED",
            pvd_primary=value_digest(from_hex(ef_anchor["value_hex"])),
        )
        es_ref = d1_ref_from_id("DSB3_ES_ACTIVE_TYPED", row=peer_es)
        es_refs = ef_refs + ["DSB3_ES_ACTIVE_TYPED"]
    else:
        peer_es = make_row(
            ev9.peer_key,
            d1_body("DSB3_ES_ACTIVE_TYPED"),
            subtype=ST_ES,
            primary_id=a_ef["txn"],
            pvd=value_digest(from_hex(ef_anchor["value_hex"])),
        )
        es_ref = synthetic_ref(
            key_hex=peer_es["key_hex"],
            value_hex=peer_es["value_hex"],
            expect_presence="PRESENT",
            note="synthetic ES for EF",
        )
        es_refs = ef_refs
    add(
        make_vector(
            "D3S1_M09_EF_EVENT_SPOOL_PRESENT",
            "mode9_ef_present_ok",
            9,
            merge_rows(profile, [ef_anchor, peer_es]),
            std_scan_calls(9),
            d1_refs=es_refs,
            source_ref=synthetic_ref(
                rid="DSB2_ANCHOR_EF_POSITIVE",
                key_hex=ef_anchor["key_hex"],
                value_hex=ef_anchor["value_hex"],
                expect_presence="PRESENT",
            ),
            peer_ref=es_ref,
        )
    )

    add(
        pair_present(
            "D3S1_M10_DS_CANCEL_PRESENT",
            "mode10_ds_present_ok",
            10,
            "DSB2_ANCHOR_TYPED",
            "DSB3_CS_TX_NONE_TYPED",
        )
    )
    add(
        pair_absent(
            "D3S1_M10_EF_CANCEL_ABSENT",
            "mode10_ef_absent_ok",
            10,
            "DSB2_ANCHOR_TYPED",
            source_row=ef_anchor,
            extra_ids=ef_refs,
        )
    )

    # Modes 11-12 D1 match
    add(
        pair_present(
            "D3S1_M11_DLV_RC_PRESENT",
            "mode11_present_ok",
            11,
            "DSB3_DLV_APP_DS_TYPED",
            "DSB3_RC_INBOX_VIRGIN_TYPED",
        )
    )
    add(
        pair_present(
            "D3S1_M12_DLV_RES_PRESENT",
            "mode12_present_ok",
            12,
            "DSB3_DLV_APP_DS_TYPED",
            "DSB2_RES_DLV_TYPED",
        )
    )

    # Mode13 synthetic SCHED matching delivery.scheduler_owner_sequence
    src13 = d1_row("DSB3_DLV_APP_DS_TYPED")
    ev13 = rebuild_peer(13, from_hex(src13["key_hex"]), from_hex(src13["value_hex"]))
    assert ev13 is not None and ev13.subject_raw is not None
    d13 = parse_delivery(d1_body("DSB3_DLV_APP_DS_TYPED"))
    peer13 = make_row(
        ev13.peer_key,
        make_sched_body(d13["sched_seq"], 2, d13["delivery_raw"]),
        subtype=ST_SCHED,
        primary_id=scheduler_primary_id(2, d13["delivery_raw"]),
        pvd=value_digest(from_hex(src13["value_hex"])),
    )
    add(
        make_vector(
            "D3S1_M13_DLV_SCHED_PRESENT",
            "mode13_present_ok",
            13,
            merge_rows(profile, [src13, peer13]),
            std_scan_calls(13),
            d1_refs=["DSB3_DLV_APP_DS_TYPED"],
            source_ref=d1_ref_from_id("DSB3_DLV_APP_DS_TYPED", row=src13),
            peer_ref=synthetic_ref(
                key_hex=peer13["key_hex"],
                value_hex=peer13["value_hex"],
                expect_presence="PRESENT",
                note=f"synthetic SCHED seq={d13['sched_seq']} owner_kind=2",
            ),
        )
    )

    add(
        pair_present(
            "D3S1_M14_DS_CANCEL_PRESENT",
            "mode14_ds_present_ok",
            14,
            "DSB3_DLV_APP_DS_TYPED",
            "DSB3_CS_DLV_NONE_TYPED",
        )
    )
    dlv_ef = d1_row("DSB3_DLV_APP_EF_TYPED")
    add(
        pair_absent(
            "D3S1_M14_EF_CANCEL_ABSENT",
            "mode14_ef_absent_ok",
            14,
            "DSB3_DLV_APP_EF_TYPED",
            source_row=dlv_ef,
        )
    )

    # Mode15: synthetic RES peer keyed by ordered_sequence
    src15 = d1_row("DSB3_ING_APP_DS_TYPED")
    ev15 = rebuild_peer(15, from_hex(src15["key_hex"]), from_hex(src15["value_hex"]))
    assert ev15 is not None
    ing15 = parse_ingress(d1_body("DSB3_ING_APP_DS_TYPED"))
    peer15 = make_row(
        ev15.peer_key,
        make_res_body(3, ing15["ordered_seq"]),
        subtype=ST_RES,
        primary_id=bytes(8) + ing15["ordered_seq"],
        pvd=value_digest(from_hex(src15["value_hex"])),
    )
    add(
        make_vector(
            "D3S1_M15_ING_RES_PRESENT",
            "mode15_present_ok",
            15,
            merge_rows(profile, [src15, peer15]),
            std_scan_calls(15),
            d1_refs=["DSB3_ING_APP_DS_TYPED"],
            source_ref=d1_ref_from_id("DSB3_ING_APP_DS_TYPED", row=src15),
            peer_ref=synthetic_ref(
                key_hex=peer15["key_hex"],
                value_hex=peer15["value_hex"],
                expect_presence="PRESENT",
                note="synthetic RES_ING from ordered_sequence",
            ),
        )
    )

    # Mode16 NEW_DELIVERY (binding=3, owner_seq=9 on DSB3_ING_APP_DS)
    src16 = d1_row("DSB3_ING_APP_DS_TYPED")
    ev16 = rebuild_peer(16, from_hex(src16["key_hex"]), from_hex(src16["value_hex"]))
    assert ev16 is not None and ev16.owner_kind == 3
    ing16 = parse_ingress(d1_body("DSB3_ING_APP_DS_TYPED"))
    peer16_new = make_row(
        ev16.peer_key,
        make_sched_body(ing16["owner_seq"], 3, ing16["ordered_seq"]),
        subtype=ST_SCHED,
        primary_id=scheduler_primary_id(3, ing16["ordered_seq"]),
        pvd=value_digest(from_hex(src16["value_hex"])),
    )
    add(
        make_vector(
            "D3S1_M16_NEW_DLV_SCHED_PRESENT",
            "mode16_new_delivery_present_ok",
            16,
            merge_rows(profile, [src16, peer16_new]),
            std_scan_calls(16),
            d1_refs=["DSB3_ING_APP_DS_TYPED"],
            source_ref=d1_ref_from_id("DSB3_ING_APP_DS_TYPED", row=src16),
            peer_ref=synthetic_ref(
                key_hex=peer16_new["key_hex"],
                value_hex=peer16_new["value_hex"],
                expect_presence="PRESENT",
                note="NEW_DELIVERY SCHED owner_kind=3 subject=ordered_seq",
            ),
        )
    )

    # Mode16 EXISTING_TX: structurally legal RECEIPT ingress (binding=1 only
    # for RECEIPT/DISPOSITION/CUSTODY/CANCEL_RESULT). Synthesize matching TX
    # SCHED peer by owner_sequence + transaction_id; present OK intent.
    src16_tx = d1_row("DSB3_ING_RECEIPT_TYPED")
    ing_tx_body = d1_body("DSB3_ING_RECEIPT_TYPED")
    ing_tx = parse_ingress(ing_tx_body)
    assert ing_tx["binding"] == BIND_EXISTING_TX
    assert ing_tx["owner_seq"] != 0
    ev16_tx = rebuild_peer(
        16, from_hex(src16_tx["key_hex"]), from_hex(src16_tx["value_hex"])
    )
    assert ev16_tx is not None and ev16_tx.owner_kind == 1
    assert ev16_tx.subject_raw == ing_tx["txn"]
    peer16_tx = make_row(
        ev16_tx.peer_key,
        make_sched_body(ing_tx["owner_seq"], 1, ing_tx["txn"]),
        subtype=ST_SCHED,
        primary_id=scheduler_primary_id(1, ing_tx["txn"]),
        pvd=bytes([0xAB] * 32),  # PVD of referenced TX primary — skip for EXISTING
    )
    add(
        make_vector(
            "D3S1_M16_EXISTING_TX_PRESENT",
            "mode16_existing_tx_present_ok",
            16,
            merge_rows(profile, [src16_tx, peer16_tx]),
            std_scan_calls(16),
            d1_refs=["DSB3_ING_RECEIPT_TYPED"],
            source_ref=d1_ref_from_id(
                "DSB3_ING_RECEIPT_TYPED",
                row=src16_tx,
                expect_presence="PRESENT",
                note=(
                    f"RECEIPT EXISTING_TRANSACTION binding=1 "
                    f"owner_seq={ing_tx['owner_seq']}"
                ),
            ),
            peer_ref=synthetic_ref(
                key_hex=peer16_tx["key_hex"],
                value_hex=peer16_tx["value_hex"],
                expect_presence="PRESENT",
                note=(
                    f"SCHED owner_kind=1 owner_seq={ing_tx['owner_seq']} "
                    "subject=txn (EXISTING_TX)"
                ),
            ),
            notes=(
                "Mode16 EXISTING_TX: legal RECEIPT ingress + SCHED peer matched "
                "by owner_sequence/transaction_id; present OK"
            ),
        )
    )

    # Mode16 EXISTING_DELIVERY: binding=2, owner_seq=2, subject = composed
    # delivery raw from ingress body (not an unrelated D1 DELIVERY raw).
    base_ing_body2 = bytearray(d1_body("DSB3_ING_APP_DS_TYPED"))
    base_ing_body2[8:16] = be64(2)
    base_ing_body2[16:18] = be16(BIND_EXISTING_DLV)
    ing_dlv_body = bytes(base_ing_body2)
    src16_dlv = make_row(
        from_hex(src16["key_hex"]),
        ing_dlv_body,
        subtype=ST_INGRESS,
        primary_id=from_hex(src16["value_hex"])[24:40],
        pvd=bytes(32),
        head=from_hex(src16["value_hex"])[40:72],
    )
    ing16_dlv = parse_ingress(ing_dlv_body)
    draw16 = compose_delivery_raw_from_ingress(ing16_dlv)
    ev16_dlv = rebuild_peer(
        16, from_hex(src16_dlv["key_hex"]), from_hex(src16_dlv["value_hex"])
    )
    assert ev16_dlv is not None and ev16_dlv.owner_kind == 2
    assert ev16_dlv.subject_raw == draw16
    assert len(draw16) == 80
    # Present_ok synthetic SCHED peer must contain composed delivery raw.
    peer16_dlv = make_row(
        ev16_dlv.peer_key,
        make_sched_body(2, 2, draw16),
        subtype=ST_SCHED,
        primary_id=scheduler_primary_id(2, draw16),
        pvd=bytes([0xCD] * 32),
    )
    add(
        make_vector(
            "D3S1_M16_EXISTING_DLV_PRESENT",
            "mode16_existing_delivery_present_ok",
            16,
            merge_rows(profile, [src16_dlv, peer16_dlv]),
            std_scan_calls(16),
            d1_refs=["DSB3_ING_APP_DS_TYPED"],
            source_ref=synthetic_ref(
                rid="DSB3_ING_APP_DS_TYPED",
                key_hex=src16_dlv["key_hex"],
                value_hex=src16_dlv["value_hex"],
                expect_presence="PRESENT",
                note=(
                    "EXISTING_DELIVERY binding=2 owner_seq=2; "
                    "subject_raw=compose(src_rt||src_app||txn||tgt_rt||tgt_app)"
                ),
            ),
            peer_ref=synthetic_ref(
                key_hex=peer16_dlv["key_hex"],
                value_hex=peer16_dlv["value_hex"],
                expect_presence="PRESENT",
                note="SCHED owner_kind=2 subject=composed_delivery_raw_from_ingress",
            ),
            notes=(
                "Mode16 EXISTING_DELIVERY: PeerEval.subject_raw independently "
                "composed from ingress body; peer SCHED subject exact bijection"
            ),
        )
    )

    # Mode16 material subject mismatch: EXISTING_DELIVERY peer kind=2 but
    # subject raw ≠ composed delivery raw (keep corrupt coverage).
    bad_subject16 = bytes([0xEE] * 80)
    assert bad_subject16 != draw16
    peer16_bad = make_row(
        ev16_dlv.peer_key,
        make_sched_body(2, 2, bad_subject16),
        subtype=ST_SCHED,
        primary_id=scheduler_primary_id(2, bad_subject16),
        pvd=bytes([0xCD] * 32),
    )
    add(
        make_vector(
            "D3S1_M16_KIND_RAW_MISMATCH",
            "mode16_kind_raw_mismatch_corrupt",
            16,
            merge_rows(profile, [src16_dlv, peer16_bad]),
            std_scan_calls(16),
            d1_refs=["DSB3_ING_APP_DS_TYPED"],
            source_ref=synthetic_ref(
                rid="DSB3_ING_APP_DS_TYPED",
                key_hex=src16_dlv["key_hex"],
                value_hex=src16_dlv["value_hex"],
                expect_presence="PRESENT",
                note="EXISTING_DELIVERY material subject mismatch source",
            ),
            peer_ref=synthetic_ref(
                key_hex=peer16_bad["key_hex"],
                value_hex=peer16_bad["value_hex"],
                expect_presence="PRESENT",
                note="owner_kind=2 but subject≠composed delivery raw",
            ),
            notes=(
                "Mode16 material subject mismatch: peer PRESENT at owner_seq "
                "with owner_kind=2 but subject_raw ≠ compose_delivery_raw_from_ingress"
            ),
        )
    )

    add(
        pair_missing(
            "D3S1_M01_MISSING_PEER",
            "mode1_missing_peer_corrupt",
            1,
            "DSB2_SERVICE_TYPED",
        )
    )

    # --- Mode17 reverse inventory ---
    m17_pairs = [
        ("D3S1_M17_QUOTA_TO_SERVICE", "mode17_quota_to_service", "DSB2_QUOTA_TYPED", "DSB2_SERVICE_TYPED"),
        ("D3S1_M17_RES_SERVICE", "mode17_res_service", "DSB2_RES_SVC_TYPED", "DSB2_SERVICE_TYPED"),
        ("D3S1_M17_RES_TX", "mode17_res_transaction", "DSB2_RES_TX_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_RES_DLV", "mode17_res_delivery", "DSB2_RES_DLV_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_RES_CB_TO_DLV", "mode17_res_callback_to_delivery", "DSB2_RES_CB_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_SEQ_TO_ANCHOR", "mode17_seq_to_anchor", "DSB2_SEQ_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_STATE_TO_ANCHOR", "mode17_state_to_anchor", "DSB2_STATE_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_IDEM_TO_ANCHOR", "mode17_idem_to_anchor", "DSB2_IDEM_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_EVMAP_TO_ANCHOR", "mode17_evmap_to_anchor", "DSB2_EVMAP_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_ES_TO_ANCHOR", "mode17_evspool_to_anchor", "DSB3_ES_ACTIVE_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_RS_TO_ANCHOR", "mode17_retry_to_anchor", "DSB3_RS_CUM_T0_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_ML_TO_ANCHOR", "mode17_mgmt_to_anchor", "DSB3_ML_R_RSN1_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_SCHED_TX", "mode17_sched_tx_to_anchor", "DSB3_SCHED_TX_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_SCHED_DLV", "mode17_sched_dlv_to_delivery", "DSB3_SCHED_DLV_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_ATT_TX", "mode17_attempt_tx_to_owner", "DSB3_ATT_TX_CMD_PREP_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_ATT_DLV", "mode17_attempt_dlv_to_owner", "DSB3_ATT_DLV_CMD_REMOTE_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_AII", "mode17_aii_to_anchor", "DSB3_AII_CMD_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_CS_TX", "mode17_cancel_tx_to_owner", "DSB3_CS_TX_NONE_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_CS_DLV", "mode17_cancel_dlv_to_owner", "DSB3_CS_DLV_NONE_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_EV_TX", "mode17_evidence_tx_to_owner", "DSB3_EV_TX_SUM_EMPTY_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_EV_DLV", "mode17_evidence_dlv_to_owner", "DSB3_EV_DLV_SUM_EMPTY_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_RC_TO_DLV", "mode17_rc_to_delivery", "DSB3_RC_INBOX_VIRGIN_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_RR_TO_DLV", "mode17_rr_to_delivery", "DSB3_RR_KIND_RECEIPT_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_RB_TX", "mode17_rb_tx_to_subject", "DSB3_RB_TX_ELIGIBLE_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_RB_DLV", "mode17_rb_dlv_to_subject", "DSB3_RB_DLV_CLEANUP_TYPED", "DSB3_DLV_APP_DS_TYPED"),
        ("D3S1_M17_CP_TX", "mode17_cp_tx_to_subject", "DSB3_CP_TX_P1_FULL_TYPED", "DSB2_ANCHOR_TYPED"),
        ("D3S1_M17_CP_DLV", "mode17_cp_dlv_to_subject", "DSB3_CP_DLV_P1_TYPED", "DSB3_DLV_APP_DS_TYPED"),
    ]
    for vid, kind, sec, prim in m17_pairs:
        add(pair_present(vid, kind, 17, sec, prim))

    # Mode17 RES_ING: fully legal ORDERED_INGRESS whose key identity and body
    # ordered_sequence equal RES owner ordered_seq (subject_raw).
    sec_ri = d1_row("DSB2_RES_ING_TYPED")
    ev_ri = rebuild_peer(17, from_hex(sec_ri["key_hex"]), from_hex(sec_ri["value_hex"]))
    assert ev_ri is not None
    r_ri = parse_reservation(d1_body("DSB2_RES_ING_TYPED"))
    assert len(r_ri["owner_raw"]) == 8 and r_ri["owner_raw"] == ev_ri.subject_raw
    ing_ri_body = make_ordered_ingress_body_with_seq(
        d1_body("DSB3_ING_APP_DS_TYPED"), r_ri["owner_raw"]
    )
    assert parse_ingress(ing_ri_body)["ordered_seq"] == r_ri["owner_raw"]
    prim_ri = make_row(
        ev_ri.peer_key,
        ing_ri_body,
        subtype=ST_INGRESS,
        primary_id=bytes(8) + r_ri["owner_raw"],
        pvd=bytes(32),
        head=from_hex(d1_row("DSB3_ING_APP_DS_TYPED")["value_hex"])[40:72],
    )
    sec_ri_p = {
        "key_hex": sec_ri["key_hex"],
        "value_hex": hex_of(
            patch_pvd(
                from_hex(sec_ri["value_hex"]),
                value_digest(from_hex(prim_ri["value_hex"])),
            )
        ),
    }
    add(
        make_vector(
            "D3S1_M17_RES_ING",
            "mode17_res_ingress",
            17,
            merge_rows(profile, [sec_ri_p, prim_ri]),
            std_scan_calls(17),
            d1_refs=["DSB2_RES_ING_TYPED", "DSB3_ING_APP_DS_TYPED"],
            source_ref=d1_ref_from_id("DSB2_RES_ING_TYPED", row=sec_ri_p),
            peer_ref=synthetic_ref(
                key_hex=prim_ri["key_hex"],
                value_hex=prim_ri["value_hex"],
                expect_presence="PRESENT",
                note=(
                    "legal INGRESS primary: key+body ordered_sequence == "
                    "RES owner raw"
                ),
            ),
            notes=(
                "Mode17 RES_ING: synthetic ORDERED_INGRESS with matching "
                "ordered_sequence; binding-kind/digests satisfied"
            ),
        )
    )

    # Mode17 SCHED_ING: fully legal ORDERED_INGRESS from SCHED subject raw
    sec_si = d1_row("DSB3_SCHED_ING_TYPED")
    ev_si = rebuild_peer(17, from_hex(sec_si["key_hex"]), from_hex(sec_si["value_hex"]))
    assert ev_si is not None
    s_si = parse_sched(d1_body("DSB3_SCHED_ING_TYPED"))
    assert len(s_si["subject"]) == 8 and s_si["subject"] == ev_si.subject_raw
    ing_si_body = make_ordered_ingress_body_with_seq(
        d1_body("DSB3_ING_APP_DS_TYPED"), s_si["subject"]
    )
    assert parse_ingress(ing_si_body)["ordered_seq"] == s_si["subject"]
    prim_si = make_row(
        ev_si.peer_key,
        ing_si_body,
        subtype=ST_INGRESS,
        primary_id=bytes(8) + s_si["subject"],
        pvd=bytes(32),
        head=from_hex(d1_row("DSB3_ING_APP_DS_TYPED")["value_hex"])[40:72],
    )
    sec_si_p = {
        "key_hex": sec_si["key_hex"],
        "value_hex": hex_of(
            patch_pvd(
                from_hex(sec_si["value_hex"]),
                value_digest(from_hex(prim_si["value_hex"])),
            )
        ),
    }
    add(
        make_vector(
            "D3S1_M17_SCHED_ING",
            "mode17_sched_ing_to_ingress",
            17,
            merge_rows(profile, [sec_si_p, prim_si]),
            std_scan_calls(17),
            d1_refs=["DSB3_SCHED_ING_TYPED", "DSB3_ING_APP_DS_TYPED"],
            source_ref=d1_ref_from_id("DSB3_SCHED_ING_TYPED", row=sec_si_p),
            peer_ref=synthetic_ref(
                key_hex=prim_si["key_hex"],
                value_hex=prim_si["value_hex"],
                expect_presence="PRESENT",
                note=(
                    "legal INGRESS primary: key+body ordered_sequence == "
                    "SCHED subject raw"
                ),
            ),
            notes=(
                "Mode17 SCHED_ING: synthetic ORDERED_INGRESS with matching "
                "ordered_sequence; binding-kind/digests satisfied"
            ),
        )
    )

    add(
        pair_missing(
            "D3S1_M17_ABSENT_PRIMARY",
            "mode17_absent_primary_corrupt",
            17,
            "DSB2_QUOTA_TYPED",
        )
    )

    # Mode17 PVD mismatch: unpatched secondary vs real primary
    sec_q = d1_row("DSB2_QUOTA_TYPED")
    prim_s = d1_row("DSB2_SERVICE_TYPED")
    # Ensure keys rebuild match; PVD intentionally wrong
    assert_peer_key_rebuildable(
        17, sec_q["key_hex"], sec_q["value_hex"], prim_s["key_hex"]
    )
    add(
        make_vector(
            "D3S1_M17_PVD_MISMATCH",
            "mode17_pvd_mismatch_corrupt",
            17,
            merge_rows(profile, [sec_q, prim_s]),
            std_scan_calls(17),
            d1_refs=["DSB2_QUOTA_TYPED", "DSB2_SERVICE_TYPED"],
            source_ref=d1_ref_from_id("DSB2_QUOTA_TYPED", row=sec_q),
            peer_ref=d1_ref_from_id("DSB2_SERVICE_TYPED", row=prim_s),
            notes="Mode17 PVD mismatch: secondary header PVD ≠ live primary digest",
        )
    )

    # Mode17 IDEM dual-raw mismatch: flip ANCHOR ikey material only, recompute
    # all same-record digests that involve the changed idempotency bytes
    # (idempotency_map_key_digest), patch peer/source PVD to the mutated
    # primary, leave dual-raw mismatch as the sole D3 failure.
    sec_i = d1_row("DSB2_IDEM_TYPED")
    prim_a = d1_row("DSB2_ANCHOR_TYPED")
    aval = from_hex(prim_a["value_hex"])
    _st, abody, _ = extract_envelope(aval)
    a = parse_anchor(abody)
    mut_ab = bytearray(abody)
    idx = bytes(mut_ab).find(a["ikey"])
    if idx < 0:
        raise SystemExit("cannot locate ikey in anchor for dual-raw mut")
    mut_ab[idx] ^= 0xA5
    # Recompute derived digests involving changed idempotency material.
    mut_ab = bytearray(recompute_anchor_idempotency_map_digest(bytes(mut_ab)))
    if family6_current_row_s3_status(
        from_hex(prim_a["key_hex"]),
        enc_env_full(
            6,
            ST_ANCHOR,
            0,
            1,
            aval[24:40],
            aval[40:72],
            bytes(32),
            bytes(mut_ab),
        ),
    ) != "OK":
        raise SystemExit("IDEM dual-raw mut ANCHOR must remain S3-legal")
    prim_a_bad = {
        "key_hex": prim_a["key_hex"],
        "value_hex": hex_of(
            enc_env_full(
                6,
                ST_ANCHOR,
                0,
                1,
                aval[24:40],
                aval[40:72],
                bytes(32),
                bytes(mut_ab),
            )
        ),
    }
    # Source IDEM PVD matches mutated primary; dual-raw still original scope/ikey.
    sec_i_p2 = {
        "key_hex": sec_i["key_hex"],
        "value_hex": hex_of(
            patch_pvd(
                from_hex(sec_i["value_hex"]),
                value_digest(from_hex(prim_a_bad["value_hex"])),
            )
        ),
    }
    add(
        make_vector(
            "D3S1_M17_IDEM_DUAL_RAW_MISMATCH",
            "mode17_idem_dual_raw_mismatch_corrupt",
            17,
            merge_rows(profile, [sec_i_p2, prim_a_bad]),
            std_scan_calls(17),
            d1_refs=["DSB2_IDEM_TYPED", "DSB2_ANCHOR_TYPED"],
            source_ref=d1_ref_from_id("DSB2_IDEM_TYPED", row=sec_i_p2),
            peer_ref=synthetic_ref(
                rid="DSB2_ANCHOR_TYPED",
                key_hex=prim_a_bad["key_hex"],
                value_hex=prim_a_bad["value_hex"],
                expect_presence="PRESENT",
                note=(
                    "ANCHOR ikey flipped + derived digests recomputed; "
                    "PVD matches; dual-raw only mismatch"
                ),
            ),
            notes=(
                "Mode17 IDEM dual-raw bijection fail: structurally valid ANCHOR "
                "with recomputed idempotency_map_key_digest; dual-raw only"
            ),
        )
    )

    # --- Mode18 ---
    add(
        pair_present(
            "D3S1_M18_ATT_TO_INDEX",
            "mode18_attempt_to_index_present",
            18,
            "DSB3_ATT_TX_CMD_PREP_TYPED",
            "DSB3_AII_CMD_TYPED",
            patch_peer_pvd=False,
            skip_pvd=True,
        )
    )
    add(
        pair_present(
            "D3S1_M18_INDEX_TO_ATT",
            "mode18_index_to_attempt_present",
            18,
            "DSB3_AII_CMD_TYPED",
            "DSB3_ATT_TX_CMD_PREP_TYPED",
            patch_peer_pvd=False,
            skip_pvd=True,
        )
    )
    add(
        pair_missing(
            "D3S1_M18_MISSING",
            "mode18_missing_peer_corrupt",
            18,
            "DSB3_ATT_TX_CMD_PREP_TYPED",
        )
    )
    # Mode18 mismatch: AII present at correct key but attempt_id corrupted in body
    att = d1_row("DSB3_ATT_TX_CMD_PREP_TYPED")
    aii = d1_row("DSB3_AII_CMD_TYPED")
    aii_val = from_hex(aii["value_hex"])
    _st, aii_body, _ = extract_envelope(aii_val)
    mut_aii = bytearray(aii_body)
    mut_aii[0] ^= 0xFF  # corrupt attempt_id
    aii_bad = {
        "key_hex": aii["key_hex"],  # key still attempt_id based — intentional mismatch
        "value_hex": hex_of(
            enc_env_full(
                6,
                ST_AII,
                0,
                1,
                aii_val[24:40],
                aii_val[40:72],
                aii_val[PVD_OFF : PVD_OFF + 32],
                bytes(mut_aii),
            )
        ),
    }
    add(
        make_vector(
            "D3S1_M18_MISMATCH",
            "mode18_mismatch_corrupt",
            18,
            merge_rows(profile, [att, aii_bad]),
            std_scan_calls(18),
            d1_refs=["DSB3_ATT_TX_CMD_PREP_TYPED", "DSB3_AII_CMD_TYPED"],
            source_ref=d1_ref_from_id("DSB3_ATT_TX_CMD_PREP_TYPED", row=att),
            peer_ref=synthetic_ref(
                rid="DSB3_AII_CMD_TYPED",
                key_hex=aii_bad["key_hex"],
                value_hex=aii_bad["value_hex"],
                expect_presence="PRESENT",
                note="AII attempt_id body corrupted vs ATTEMPT",
            ),
        )
    )
    # DELIVERY-owned ATTEMPT: Mode18 exact_gets AII(attempt_id) expecting ABSENT.
    att_dlv = d1_row("DSB3_ATT_DLV_CMD_REMOTE_TYPED")
    ev18_dlv = rebuild_peer(
        18, from_hex(att_dlv["key_hex"]), from_hex(att_dlv["value_hex"])
    )
    if ev18_dlv is None or ev18_dlv.expect_presence != "ABSENT":
        raise SystemExit(
            "Mode18 DELIVERY ATTEMPT must be applicable with ABSENT AII expectation"
        )
    add(
        pair_absent(
            "D3S1_M18_DLV_ABSENT",
            "mode18_delivery_attempt_absent_ok",
            18,
            "DSB3_ATT_DLV_CMD_REMOTE_TYPED",
            notes=(
                "Mode18 DELIVERY-owned ATTEMPT: AII attempt_id key ABSENT → OK; "
                "no local index for remote ingress history"
            ),
        )
    )
    # Spurious AII present at the same attempt_id key (D1 AII shares attempt_id
    # with DSB3_ATT_DLV_CMD_REMOTE_TYPED) → STORAGE_CORRUPT on ABSENT expect.
    aii_spurious = d1_row("DSB3_AII_CMD_TYPED")
    if aii_spurious["key_hex"] != hex_of(ev18_dlv.peer_key):
        raise SystemExit(
            "Mode18 DELIVERY unexpected AII key must match rebuilt peer key "
            f"(got {aii_spurious['key_hex']} want {hex_of(ev18_dlv.peer_key)})"
        )
    if family6_current_row_s3_status(
        from_hex(aii_spurious["key_hex"]), from_hex(aii_spurious["value_hex"])
    ) != "OK":
        raise SystemExit("Mode18 DELIVERY spurious AII must be S3-legal")
    v18_unexp = make_vector(
        "D3S1_M18_DLV_UNEXPECTED",
        "mode18_delivery_attempt_unexpected_present_corrupt",
        18,
        merge_rows(profile, [att_dlv, aii_spurious]),
        std_scan_calls(18),
        d1_refs=["DSB3_ATT_DLV_CMD_REMOTE_TYPED", "DSB3_AII_CMD_TYPED"],
        source_ref=d1_ref_from_id(
            "DSB3_ATT_DLV_CMD_REMOTE_TYPED", row=att_dlv
        ),
        peer_ref=d1_ref_from_id(
            "DSB3_AII_CMD_TYPED",
            row=aii_spurious,
            expect_presence="ABSENT",
            note=(
                "spurious S3-legal AII at DELIVERY attempt_id while Mode18 "
                "expects ABSENT"
            ),
        ),
        notes=(
            "Mode18 DELIVERY-owned: AII present at attempt_id probe key while "
            "expect ABSENT → STORAGE_CORRUPT with peer get; mutation_calls=0"
        ),
    )
    if v18_unexp["expected"]["final_status"] != "STORAGE_CORRUPT":
        raise SystemExit(
            "mode18_delivery_attempt_unexpected_present_corrupt must be "
            f"STORAGE_CORRUPT, got {v18_unexp['expected']['final_status']}"
        )
    if int(v18_unexp["expected"].get("d3_peer_get_count", 0)) < 1:
        raise SystemExit(
            "mode18_delivery_attempt_unexpected_present_corrupt must peer-get"
        )
    if int(v18_unexp["expected"].get("mutation_calls", -1)) != 0:
        raise SystemExit(
            "mode18_delivery_attempt_unexpected_present_corrupt mutation must be 0"
        )
    add(v18_unexp)

    # --- Mode19 ---
    rc_started = d1_row("DSB3_RC_STARTED_AT0_TYPED")
    ev19 = rebuild_peer(
        19, from_hex(rc_started["key_hex"]), from_hex(rc_started["value_hex"])
    )
    assert ev19 is not None and ev19.expect_presence == "PRESENT"
    rc_p = parse_rc(d1_body("DSB3_RC_STARTED_AT0_TYPED"))
    owner_raw_cb = raw16(rc_p["delivery_raw"]) + be64(rc_p["token_gen"])
    peer19 = make_row(
        ev19.peer_key,
        make_res_body(5, owner_raw_cb),
        subtype=ST_RES,
        primary_id=composite(ST_DELIVERY, raw16(rc_p["delivery_raw"]))[:16],
        pvd=bytes([0x11] * 32),  # PVD of DELIVERY — not checked in M19
    )
    add(
        make_vector(
            "D3S1_M19_ACTIVE_PRESENT",
            "mode19_active_present_ok",
            19,
            merge_rows(profile, [rc_started, peer19]),
            std_scan_calls(19),
            d1_refs=["DSB3_RC_STARTED_AT0_TYPED"],
            source_ref=d1_ref_from_id("DSB3_RC_STARTED_AT0_TYPED", row=rc_started),
            peer_ref=synthetic_ref(
                key_hex=peer19["key_hex"],
                value_hex=peer19["value_hex"],
                expect_presence="PRESENT",
                note="CALLBACK RES rebuilt from RC dual-raw+token_gen",
            ),
        )
    )
    add(
        pair_missing(
            "D3S1_M19_ACTIVE_MISSING",
            "mode19_active_missing_corrupt",
            19,
            "DSB3_RC_STARTED_AT0_TYPED",
        )
    )
    # nonactive unexpected: RC is non-ACTIVE but has token_generation != 0 so
    # the unexpected CALLBACK RES can be structurally legal (token_gen != 0).
    # RESULT+CONSUMED is non-ACTIVE (Mode19 expects ABSENT) with tok_gen=1.
    rc_nonact = d1_row("DSB3_RC_RESULT_POS_TYPED")
    ev19i = rebuild_peer(
        19, from_hex(rc_nonact["key_hex"]), from_hex(rc_nonact["value_hex"])
    )
    assert ev19i is not None and ev19i.expect_presence == "ABSENT"
    rc_i = parse_rc(d1_body("DSB3_RC_RESULT_POS_TYPED"))
    assert not (
        rc_i["state"] == RC_ST_STARTED and rc_i["token_state"] == TS_ACTIVE
    )
    assert rc_i["token_gen"] != 0
    owner_raw_i = raw16(rc_i["delivery_raw"]) + be64(rc_i["token_gen"])
    peer19_unexp = make_row(
        ev19i.peer_key,
        make_res_body(5, owner_raw_i),
        subtype=ST_RES,
        primary_id=composite(ST_DELIVERY, raw16(rc_i["delivery_raw"]))[:16],
        pvd=bytes([0x22] * 32),
    )
    if family6_current_row_s3_status(
        from_hex(peer19_unexp["key_hex"]), from_hex(peer19_unexp["value_hex"])
    ) != "OK":
        raise SystemExit("Mode19 unexpected CALLBACK RES must be S3-legal")
    add(
        make_vector(
            "D3S1_M19_NONACTIVE_UNEXPECTED",
            "mode19_nonactive_unexpected_present_corrupt",
            19,
            merge_rows(profile, [rc_nonact, peer19_unexp]),
            std_scan_calls(19),
            d1_refs=["DSB3_RC_RESULT_POS_TYPED"],
            source_ref=d1_ref_from_id(
                "DSB3_RC_RESULT_POS_TYPED", row=rc_nonact
            ),
            peer_ref=synthetic_ref(
                key_hex=peer19_unexp["key_hex"],
                value_hex=peer19_unexp["value_hex"],
                expect_presence="ABSENT",
                note=(
                    "unexpected legal CALLBACK RES (token_gen!=0) while "
                    "RC non-ACTIVE"
                ),
            ),
            notes=(
                "Mode19 nonactive unexpected: S3-legal CALLBACK RES present "
                "while source RC remains non-ACTIVE → D3 CORRUPT with peer get"
            ),
        )
    )
    # wrong peer PVD still OK
    bad_pvd_cb = {
        "key_hex": peer19["key_hex"],
        "value_hex": hex_of(
            patch_pvd(from_hex(peer19["value_hex"]), bytes([0xAB] * 32))
        ),
    }
    add(
        make_vector(
            "D3S1_M19_WRONG_PEER_PVD_OK",
            "mode19_wrong_peer_pvd_still_ok",
            19,
            merge_rows(profile, [rc_started, bad_pvd_cb]),
            std_scan_calls(19),
            d1_refs=["DSB3_RC_STARTED_AT0_TYPED"],
            source_ref=d1_ref_from_id("DSB3_RC_STARTED_AT0_TYPED", row=rc_started),
            peer_ref=synthetic_ref(
                key_hex=bad_pvd_cb["key_hex"],
                value_hex=bad_pvd_cb["value_hex"],
                expect_presence="PRESENT",
                note="M19 ignores peer PVD (DELIVERY-owned)",
            ),
        )
    )

    # --- Mode20 ---
    state_active = d1_row("DSB2_STATE_TYPED")
    add(
        pair_absent(
            "D3S1_M20_TX_ACTIVE_ABSENT",
            "mode20_tx_active_absent_ok",
            20,
            "DSB2_STATE_TYPED",
        )
    )
    term_state, term_refs = make_terminal_state()
    ev20t = rebuild_peer(
        20, from_hex(term_state["key_hex"]), from_hex(term_state["value_hex"])
    )
    assert ev20t is not None and ev20t.expect_presence == "PRESENT"
    txn_t = parse_state(
        extract_envelope(from_hex(term_state["value_hex"]))[1]
    )["txn"]
    # RB body
    rb_body_tx = (
        be16(2)
        + be16(0)
        + raw16(txn_t)
        + complete_key_digest_id128(ST_ANCHOR, txn_t)
        + bytes(16)
        + be64(50)
        + be64(100)
        + be64(0)
        + be32(2)  # ELIGIBLE-ish
        + be32(0)
        + be32(0)
    )
    # Use D1 RB if key matches
    if hex_of(ev20t.peer_key) == d1_row("DSB3_RB_TX_ELIGIBLE_TYPED")["key_hex"]:
        rb_tx = d1_row("DSB3_RB_TX_ELIGIBLE_TYPED")
        rb_ref = d1_ref_from_id("DSB3_RB_TX_ELIGIBLE_TYPED", row=rb_tx)
        rb_ids = term_refs + ["DSB3_RB_TX_ELIGIBLE_TYPED"]
    else:
        rb_tx = make_row(
            ev20t.peer_key,
            d1_body("DSB3_RB_TX_ELIGIBLE_TYPED"),
            subtype=ST_RB,
            primary_id=txn_t,
            pvd=bytes(32),
        )
        rb_ref = synthetic_ref(
            key_hex=rb_tx["key_hex"],
            value_hex=rb_tx["value_hex"],
            expect_presence="PRESENT",
        )
        rb_ids = term_refs
    add(
        make_vector(
            "D3S1_M20_TX_TERMINAL_PRESENT",
            "mode20_tx_terminal_present_ok",
            20,
            merge_rows(profile, [term_state, rb_tx]),
            std_scan_calls(20),
            d1_refs=rb_ids,
            source_ref=synthetic_ref(
                rid="DSB2_STATE_TYPED",
                key_hex=term_state["key_hex"],
                value_hex=term_state["value_hex"],
                expect_presence="PRESENT",
                note="terminal STATE state=5",
            ),
            peer_ref=rb_ref,
        )
    )
    add(
        pair_missing(
            "D3S1_M20_TX_TERMINAL_MISSING",
            "mode20_tx_terminal_missing_corrupt",
            20,
            "DSB2_STATE_TYPED",
            source_row=term_state,
        )
    )

    def m20_rc_absent(vid: str, kind: str, rc_id: str) -> Dict[str, Any]:
        return pair_absent(vid, kind, 20, rc_id)

    def m20_rc_present(vid: str, kind: str, rc_id: str) -> Dict[str, Any]:
        rc = d1_row(rc_id)
        ev = rebuild_peer(20, from_hex(rc["key_hex"]), from_hex(rc["value_hex"]))
        assert ev is not None and ev.expect_presence == "PRESENT"
        rc_p = parse_rc(d1_body(rc_id))
        if hex_of(ev.peer_key) == d1_row("DSB3_RB_DLV_CLEANUP_TYPED")["key_hex"]:
            rb = d1_row("DSB3_RB_DLV_CLEANUP_TYPED")
            pref = d1_ref_from_id("DSB3_RB_DLV_CLEANUP_TYPED", row=rb)
            refs = [rc_id, "DSB3_RB_DLV_CLEANUP_TYPED"]
        else:
            rb = make_row(
                ev.peer_key,
                d1_body("DSB3_RB_DLV_CLEANUP_TYPED"),
                subtype=ST_RB,
                primary_id=composite(ST_DELIVERY, raw16(rc_p["delivery_raw"]))[:16],
                pvd=bytes(32),
            )
            pref = synthetic_ref(
                key_hex=rb["key_hex"],
                value_hex=rb["value_hex"],
                expect_presence="PRESENT",
            )
            refs = [rc_id]
        return make_vector(
            vid,
            kind,
            20,
            merge_rows(profile, [rc, rb]),
            std_scan_calls(20),
            d1_refs=refs,
            source_ref=d1_ref_from_id(rc_id, row=rc),
            peer_ref=pref,
        )

    add(m20_rc_absent("D3S1_M20_RC_INBOX_ABSENT", "mode20_rc_inbox_absent_ok", "DSB3_RC_INBOX_VIRGIN_TYPED"))
    add(m20_rc_absent("D3S1_M20_RC_STARTED_ABSENT", "mode20_rc_started_absent_ok", "DSB3_RC_STARTED_AT0_TYPED"))
    add(m20_rc_absent("D3S1_M20_RC_RECOVERY_ABSENT", "mode20_rc_recovery_absent_ok", "DSB3_RC_REC_G_IS_I_P1_TYPED"))
    add(m20_rc_present("D3S1_M20_RC_RESULT_PRESENT", "mode20_rc_result_present_ok", "DSB3_RC_RESULT_POS_TYPED"))
    add(m20_rc_present("D3S1_M20_RC_DISP_PRESENT", "mode20_rc_disp_present_ok", "DSB3_RC_DISP_PRE_TYPED"))
    add(m20_rc_present("D3S1_M20_RC_CANCEL_PRESENT", "mode20_rc_cancel_present_ok", "DSB3_RC_CANCEL_FIRST_TYPED"))
    add(
        pair_missing(
            "D3S1_M20_RC_RESULT_MISSING",
            "mode20_rc_result_missing_corrupt",
            20,
            "DSB3_RC_RESULT_POS_TYPED",
        )
    )

    # Mode20 subject raw mismatch: terminal STATE + RB with wrong subject.
    # Keep RB same-record legal (non-zero PVD/head); D3 catches subject vs txn.
    rb_wrong = make_row(
        ev20t.peer_key,
        (
            be16(2)
            + be16(0)
            + raw16(bytes([0xEE] * 16))  # wrong subject
            + complete_key_digest_id128(ST_ANCHOR, bytes([0xEE] * 16))
            + bytes(16)
            + be64(50)
            + be64(100)
            + be64(0)
            + be32(2)
            + be32(0)
            + be32(0)
        ),
        subtype=ST_RB,
        primary_id=bytes([0xEE] * 16),
        pvd=bytes([0xE4] * 32),
    )
    add(
        make_vector(
            "D3S1_M20_SUBJECT_RAW_MISMATCH",
            "mode20_subject_raw_mismatch_corrupt",
            20,
            merge_rows(profile, [term_state, rb_wrong]),
            std_scan_calls(20),
            d1_refs=term_refs,
            source_ref=synthetic_ref(
                rid="DSB2_STATE_TYPED",
                key_hex=term_state["key_hex"],
                value_hex=term_state["value_hex"],
                expect_presence="PRESENT",
            ),
            peer_ref=synthetic_ref(
                key_hex=rb_wrong["key_hex"],
                value_hex=rb_wrong["value_hex"],
                expect_presence="PRESENT",
                note="RB subject raw ≠ STATE txn",
            ),
        )
    )
    # active retention unexpected present
    ev20a = rebuild_peer(
        20, from_hex(state_active["key_hex"]), from_hex(state_active["value_hex"])
    )
    assert ev20a is not None and ev20a.expect_presence == "ABSENT"
    if hex_of(ev20a.peer_key) == d1_row("DSB3_RB_TX_ELIGIBLE_TYPED")["key_hex"]:
        rb_act = d1_row("DSB3_RB_TX_ELIGIBLE_TYPED")
    else:
        rb_act = make_row(
            ev20a.peer_key,
            d1_body("DSB3_RB_TX_ELIGIBLE_TYPED"),
            subtype=ST_RB,
            primary_id=parse_state(d1_body("DSB2_STATE_TYPED"))["txn"],
            pvd=bytes(32),
        )
    add(
        make_vector(
            "D3S1_M20_ACTIVE_RB_UNEXPECTED",
            "mode20_active_retention_unexpected_present_corrupt",
            20,
            merge_rows(profile, [state_active, rb_act]),
            std_scan_calls(20),
            d1_refs=["DSB2_STATE_TYPED", "DSB3_RB_TX_ELIGIBLE_TYPED"],
            source_ref=d1_ref_from_id("DSB2_STATE_TYPED", row=state_active),
            peer_ref=synthetic_ref(
                key_hex=rb_act["key_hex"],
                value_hex=rb_act["value_hex"],
                expect_presence="ABSENT",
                note="RB present while TX active",
            ),
        )
    )
    add(
        make_vector(
            "D3S1_M20_RECONCILE_WAIT_IMPOSSIBLE_SKIP_NO_LEGAL_BODY",
            "mode20_reconcile_wait_impossible",
            20,
            profile,
            std_scan_calls(20),
            d1_refs=[],
            source_ref=none_ref(
                note="RECONCILE_WAIT: no legal D1 TRANSACTION_STATE/RESULT_CACHE body"
            ),
            peer_ref=none_ref(note="no retention peer materialised"),
            notes=(
                "Mode20 RECONCILE_WAIT category has no legal D1 vector body. "
                "Documented skip (not silent disable). No synthetic illegal body."
            ),
            require_rebuild=False,
        )
    )

    # Port failure
    src_p = d1_row("DSB2_SERVICE_TYPED")
    peer_p = row_from_d1(
        "DSB2_QUOTA_TYPED",
        pvd_primary=value_digest(from_hex(src_p["value_hex"])),
    )
    add(
        make_vector(
            "D3S1_PORT_FAILURE_NO_NOTE",
            "port_failure_no_note",
            1,
            merge_rows(profile, [src_p, peer_p]),
            std_scan_calls(1),
            d1_refs=["DSB2_SERVICE_TYPED", "DSB2_QUOTA_TYPED"],
            faults=[
                {"op": "get", "on_call": 18, "status": "IO_ERROR", "shape": "natural"}
            ],
            source_ref=d1_ref_from_id("DSB2_SERVICE_TYPED", row=src_p),
            peer_ref=d1_ref_from_id("DSB2_QUOTA_TYPED", row=peer_p),
        )
    )

    # Profile skip
    mismatch_rows = encode_all_profile_rows(b)
    bind = bytearray(from_hex(mismatch_rows[0]["value_hex"]))
    bind[50] ^= 0x01
    body = bytes(bind[:-4])
    bind[-4:] = be32(crc32c(body))
    mismatch_rows[0]["value_hex"] = hex_of(bytes(bind))
    add(
        make_vector(
            "D3S1_PROFILE_MISMATCH_SKIP",
            "profile_mismatch_skip",
            1,
            merge_rows(mismatch_rows, [src_p, peer_p]),
            std_scan_calls(1),
            d1_refs=["DSB2_SERVICE_TYPED", "DSB2_QUOTA_TYPED"],
            source_ref=d1_ref_from_id("DSB2_SERVICE_TYPED", row=src_p),
            peer_ref=d1_ref_from_id("DSB2_QUOTA_TYPED", row=peer_p),
            require_rebuild=False,  # D3 skipped by profile
        )
    )
    future_bind = encode_all_profile_rows(b, binding_version=2)
    add(
        make_vector(
            "D3S1_PROFILE_FUTURE_SKIP",
            "profile_future_skip",
            1,
            merge_rows(future_bind, [src_p, peer_p]),
            std_scan_calls(1),
            d1_refs=["DSB2_SERVICE_TYPED", "DSB2_QUOTA_TYPED"],
            source_ref=d1_ref_from_id("DSB2_SERVICE_TYPED", row=src_p),
            peer_ref=d1_ref_from_id("DSB2_QUOTA_TYPED", row=peer_p),
            require_rebuild=False,
        )
    )

    # Mode restart: session1 Mode1 peer eval, session2 Mode2 peer eval
    src_r = d1_row("DSB2_SERVICE_TYPED")
    peer_q = row_from_d1(
        "DSB2_QUOTA_TYPED",
        pvd_primary=value_digest(from_hex(src_r["value_hex"])),
    )
    peer_res = row_from_d1(
        "DSB2_RES_SVC_TYPED",
        pvd_primary=value_digest(from_hex(src_r["value_hex"])),
    )
    rows_ab = merge_rows(profile, [src_r, peer_q, peer_res])
    add(
        make_vector(
            "D3S1_MODE_RESTART_1_TO_2",
            "mode_restart",
            2,
            rows_ab,
            [
                {"op": "begin_profiled_d3s1", "mode": 1},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
                {"op": "session_init"},
                {"op": "begin_profiled_d3s1", "mode": 2},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
            d1_refs=[
                "DSB2_SERVICE_TYPED",
                "DSB2_QUOTA_TYPED",
                "DSB2_RES_SVC_TYPED",
            ],
            source_ref=d1_ref_from_id("DSB2_SERVICE_TYPED", row=src_r),
            peer_ref=d1_ref_from_id(
                "DSB2_RES_SVC_TYPED",
                row=peer_res,
                note="final session Mode2 peer; session1 Mode1 uses QUOTA",
            ),
            notes=(
                "Restart: session1 begin mode=1 evaluates SERVICE→QUOTA; "
                "session2 begin mode=2 evaluates SERVICE→RES. "
                "d3_peer_get_count accumulates across sessions."
            ),
            require_rebuild=False,  # dual-mode; validated below
        )
    )
    # Explicit rebuild validation for restart material
    assert_peer_key_rebuildable(
        1, src_r["key_hex"], src_r["value_hex"], peer_q["key_hex"]
    )
    assert_peer_key_rebuildable(
        2, src_r["key_hex"], src_r["value_hex"], peer_res["key_hex"]
    )

    # Begin smokes / invalid / D2 no-D3
    add(
        make_vector(
            "D3S1_BEGIN_MODE1_SMOKE",
            "begin_mode1_smoke",
            1,
            profile,
            [
                {"op": "begin_profiled_d3s1", "mode": 1},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
            d1_refs=[],
            require_rebuild=False,
        )
    )
    add(
        make_vector(
            "D3S1_BEGIN_MODE20_SMOKE",
            "begin_mode20_smoke",
            20,
            profile,
            [
                {"op": "begin_profiled_d3s1", "mode": 20},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
            d1_refs=[],
            require_rebuild=False,
        )
    )
    # D2 begin_profiled (closed op, distinct from begin_profiled_d3s1):
    # no D3 mode/context; domain material that would be Mode1-applicable is
    # present, but d3_bound=0 → zero applicability / peer gets / sticky note.
    src_d2 = d1_row("DSB2_SERVICE_TYPED")
    peer_d2 = row_from_d1(
        "DSB2_QUOTA_TYPED",
        pvd_primary=value_digest(from_hex(src_d2["value_hex"])),
    )
    v_d2 = make_vector(
        "D3S1_D2_BEGIN_PROFILED_NO_D3",
        "d2_begin_profiled_no_d3",
        0,
        merge_rows(profile, [src_d2, peer_d2]),
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
        d1_refs=["DSB2_SERVICE_TYPED", "DSB2_QUOTA_TYPED"],
        source_ref=d1_ref_from_id("DSB2_SERVICE_TYPED", row=src_d2),
        peer_ref=d1_ref_from_id(
            "DSB2_QUOTA_TYPED",
            row=peer_d2,
            note="domain material present but D2 begin does not evaluate D3 peers",
        ),
        notes=(
            "Closed D2 begin_profiled (not begin_profiled_d3s1): no D3 mode/"
            "context; Mode1-applicable SERVICE+QUOTA present yet "
            "d3_peer_get_count=0 / d3_mode_applicable_count=0 / no sticky note. "
            "D3 invalid/alias cases remain on begin_profiled_d3s1. "
            "Not a D3-S1 complete or C bridge claim."
        ),
        require_rebuild=False,
    )
    if v_d2["expected"]["d3_peer_get_count"] != 0:
        raise SystemExit("d2_begin_profiled_no_d3 must have zero D3 peer gets")
    if v_d2["expected"]["d3_mode_applicable_count"] != 0:
        raise SystemExit(
            "d2_begin_profiled_no_d3 must have zero D3 mode applicable count"
        )
    if v_d2["expected"]["has_sticky_primary"] != 0:
        raise SystemExit("d2_begin_profiled_no_d3 must have no sticky D3 note")
    if any(c.get("op") != "begin_profiled" and c.get("op") not in (
        "advance", "finalize"
    ) for c in v_d2["calls"]):
        pass
    if v_d2["calls"][0].get("op") != "begin_profiled":
        raise SystemExit("d2_begin_profiled_no_d3 must call begin_profiled")
    if "mode" in v_d2["calls"][0] or "context" in v_d2["calls"][0]:
        raise SystemExit("d2_begin_profiled_no_d3 must not carry D3 mode/context")
    add(v_d2)

    add(
        make_vector(
            "D3S1_BEGIN_MODE0_INVALID",
            "begin_mode0_invalid",
            0,
            profile,
            [{"op": "begin_profiled_d3s1", "mode": 0}],
            d1_refs=[],
            require_rebuild=False,
        )
    )
    add(
        make_vector(
            "D3S1_BEGIN_MODE21_INVALID",
            "begin_mode21_invalid",
            21,
            profile,
            [{"op": "begin_profiled_d3s1", "mode": 21}],
            d1_refs=[],
            require_rebuild=False,
        )
    )
    add(
        make_vector(
            "D3S1_BEGIN_CONTEXT_NULL",
            "begin_context_null",
            1,
            profile,
            [{"op": "begin_profiled_d3s1", "mode": 1, "context": "null"}],
            d1_refs=[],
            require_rebuild=False,
        )
    )
    add(
        make_vector(
            "D3S1_BEGIN_ALIAS_POISON",
            "begin_alias_poison",
            1,
            profile,
            [
                {
                    "op": "begin_profiled_d3s1",
                    "mode": 1,
                    "context": "alias_session",
                }
            ],
            d1_refs=[],
            require_rebuild=False,
        )
    )

    # Future primary PVD match/mismatch (Mode17): VALUE_DIGEST first on the
    # D3 peer leg. Iterator visit of the future-framed CURRENT key sets
    # recognizable_future_seen. PVD match → D3 peer OK + finalize UNSUPPORTED
    # (no adopt). PVD mismatch → CORRUPT with future_seen still 1 (SERVICE key
    # is visited before QUOTA in lex order). Preserve PVD-first isolation.
    fut_primary = {
        "key_hex": d1_row("DSB2_SERVICE_TYPED")["key_hex"],
        "value_hex": hex_of(nlr1(6, 2, bytes([0xAA] * 64))),
    }
    assert domain_value_framing(from_hex(fut_primary["value_hex"])) == "future"
    fut_digest = value_digest(from_hex(fut_primary["value_hex"]))
    sec_qf = {
        "key_hex": d1_row("DSB2_QUOTA_TYPED")["key_hex"],
        "value_hex": hex_of(
            patch_pvd(
                from_hex(d1_row("DSB2_QUOTA_TYPED")["value_hex"]),
                fut_digest,
            )
        ),
    }
    assert header_pvd(from_hex(sec_qf["value_hex"])) == fut_digest
    v_fut_ok = make_vector(
        "D3S1_M17_FUTURE_PRIMARY_PVD_MATCH",
        "future_primary_pvd_match_ok",
        17,
        merge_rows(profile, [sec_qf, fut_primary]),
        std_scan_calls(17),
        d1_refs=["DSB2_QUOTA_TYPED", "DSB2_SERVICE_TYPED"],
        source_ref=d1_ref_from_id("DSB2_QUOTA_TYPED", row=sec_qf),
        peer_ref=synthetic_ref(
            rid="DSB2_SERVICE_TYPED",
            key_hex=fut_primary["key_hex"],
            value_hex=fut_primary["value_hex"],
            expect_presence="PRESENT",
            note=(
                "future-framed primary; PVD match → D3 peer OK; iterator "
                "future_seen; finalize UNSUPPORTED"
            ),
        ),
        notes=(
            "Mode17 future primary PVD match: D3 peer leg OK after VALUE_DIGEST; "
            "iterator sets recognizable_future_seen; finalize UNSUPPORTED/no adopt"
        ),
    )
    if v_fut_ok["expected"]["final_status"] != "UNSUPPORTED":
        raise SystemExit(
            f"future_primary_pvd_match_ok must be UNSUPPORTED, got "
            f"{v_fut_ok['expected']['final_status']}"
        )
    if v_fut_ok["expected"]["has_sticky_primary"] != 0:
        raise SystemExit("future_primary_pvd_match_ok must not sticky-corrupt")
    if v_fut_ok["expected"]["recognizable_future_seen"] != 1:
        raise SystemExit("future_primary_pvd_match_ok must set future_seen=1")
    if v_fut_ok["expected"]["adopted"] != 0:
        raise SystemExit("future_primary_pvd_match_ok must not adopt")
    add(v_fut_ok)
    sec_q_bad = {
        "key_hex": d1_row("DSB2_QUOTA_TYPED")["key_hex"],
        "value_hex": hex_of(
            patch_pvd(
                from_hex(d1_row("DSB2_QUOTA_TYPED")["value_hex"]),
                bytes([0x11] * 32),
            )
        ),
    }
    assert header_pvd(from_hex(sec_q_bad["value_hex"])) != fut_digest
    v_fut_bad = make_vector(
        "D3S1_M17_FUTURE_PRIMARY_PVD_MISMATCH",
        "future_primary_pvd_mismatch_corrupt",
        17,
        merge_rows(profile, [sec_q_bad, fut_primary]),
        std_scan_calls(17),
        d1_refs=["DSB2_QUOTA_TYPED", "DSB2_SERVICE_TYPED"],
        source_ref=d1_ref_from_id("DSB2_QUOTA_TYPED", row=sec_q_bad),
        peer_ref=synthetic_ref(
            rid="DSB2_SERVICE_TYPED",
            key_hex=fut_primary["key_hex"],
            value_hex=fut_primary["value_hex"],
            expect_presence="PRESENT",
            note=(
                "same future primary; PVD mismatch → CORRUPT; future_seen=1 "
                "from prior iterator visit"
            ),
        ),
        notes=(
            "Mode17 future primary PVD mismatch: CORRUPT after VALUE_DIGEST; "
            "future_seen=1 from SERVICE visit; PVD-first isolation preserved"
        ),
    )
    if v_fut_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        raise SystemExit(
            f"future_primary_pvd_mismatch_corrupt must be STORAGE_CORRUPT, got "
            f"{v_fut_bad['expected']['final_status']}"
        )
    if v_fut_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        raise SystemExit(
            "future_primary_pvd_mismatch_corrupt sticky must be STORAGE_CORRUPT"
        )
    if v_fut_bad["expected"]["recognizable_future_seen"] != 1:
        raise SystemExit(
            "future_primary_pvd_mismatch_corrupt must set future_seen=1"
        )
    add(v_fut_bad)

    add(
        pair_present(
            "D3S1_MUTATION_ZERO",
            "mutation_zero",
            1,
            "DSB2_SERVICE_TYPED",
            "DSB2_QUOTA_TYPED",
        )
    )

    # Validate kind set
    kinds = {v["kind"] for v in vectors}
    if kinds != REQUIRED_KINDS:
        missing = REQUIRED_KINDS - kinds
        extra = kinds - REQUIRED_KINDS
        raise SystemExit(
            f"kind set mismatch missing={sorted(missing)} extra={sorted(extra)}"
        )
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        raise SystemExit(
            f"vector count {len(vectors)} != EXPECTED_VECTOR_COUNT "
            f"{EXPECTED_VECTOR_COUNT}"
        )
    # Extra semantic assertions (material-induced; no forced outcomes)
    restart = next(v for v in vectors if v["kind"] == "mode_restart")
    if restart["expected"]["d3_peer_get_count"] != 2:
        raise SystemExit(
            f"mode_restart d3_peer_get_count="
            f"{restart['expected']['d3_peer_get_count']} want 2"
        )
    if restart["expected"]["d3_mode_applicable_count"] != 2:
        raise SystemExit("mode_restart applicable count want 2")

    m16_ok = next(
        v for v in vectors if v["kind"] == "mode16_existing_delivery_present_ok"
    )
    if m16_ok["expected"]["final_status"] != "OK":
        raise SystemExit("mode16_existing_delivery_present_ok must finalize OK")
    if m16_ok["expected"]["d3_peer_get_count"] != 1:
        raise SystemExit("mode16_existing_delivery_present_ok peer get want 1")
    # Peer subject must equal independently composed delivery raw
    m16_src_val = None
    m16_peer_val = None
    for r in m16_ok["rows"]:
        if r["key_hex"] == (m16_ok.get("source_ref") or {}).get("key_hex"):
            m16_src_val = from_hex(r["value_hex"])
        if r["key_hex"] == (m16_ok.get("peer_ref") or {}).get("key_hex"):
            m16_peer_val = from_hex(r["value_hex"])
    if m16_src_val is None or m16_peer_val is None:
        raise SystemExit("mode16 existing delivery missing source/peer rows")
    _st, m16_body, _ = extract_envelope(m16_src_val)
    m16_ing = parse_ingress(m16_body)
    m16_draw = compose_delivery_raw_from_ingress(m16_ing)
    m16_ev = rebuild_peer(16, from_hex(m16_ok["source_ref"]["key_hex"]), m16_src_val)
    if m16_ev is None or m16_ev.subject_raw != m16_draw:
        raise SystemExit(
            "mode16 EXISTING_DELIVERY PeerEval.subject_raw must equal composed raw"
        )
    _pst, m16_pbody, _ = extract_envelope(m16_peer_val)
    m16_sched = parse_sched(m16_pbody)
    if m16_sched["owner_kind"] != 2 or m16_sched["subject"] != m16_draw:
        raise SystemExit(
            "mode16 present_ok SCHED peer must carry composed delivery subject"
        )

    m16_bad = next(
        v for v in vectors if v["kind"] == "mode16_kind_raw_mismatch_corrupt"
    )
    if m16_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        raise SystemExit("mode16_kind_raw_mismatch_corrupt must be CORRUPT")

    fut_ok = next(v for v in vectors if v["kind"] == "future_primary_pvd_match_ok")
    fut_bad = next(
        v for v in vectors if v["kind"] == "future_primary_pvd_mismatch_corrupt"
    )
    if fut_ok["expected"]["final_status"] != "UNSUPPORTED":
        raise SystemExit("future_primary_pvd_match_ok must be UNSUPPORTED")
    if fut_ok["expected"]["recognizable_future_seen"] != 1:
        raise SystemExit("future_primary_pvd_match_ok future_seen must be 1")
    if fut_ok["expected"]["adopted"] != 0:
        raise SystemExit("future_primary_pvd_match_ok must not adopt")
    if fut_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        raise SystemExit("future_primary_pvd_mismatch_corrupt must be CORRUPT")
    if fut_bad["expected"]["recognizable_future_seen"] != 1:
        raise SystemExit(
            "future_primary_pvd_mismatch_corrupt future_seen must be 1"
        )
    if fut_ok["expected"]["d3_peer_get_count"] != 1:
        raise SystemExit("future_primary match must perform exactly 1 peer get")
    if fut_bad["expected"]["d3_peer_get_count"] != 1:
        raise SystemExit("future_primary mismatch must perform exactly 1 peer get")

    # Independent S3-equivalent gate over every emitted family-6 CURRENT row.
    for v in vectors:
        assert_family6_s3_gate_on_rows(
            v.get("rows") or [], context=f"vector {v.get('id')}"
        )
        for _alt_name, alt_rows in (v.get("alt_rows") or {}).items():
            assert_family6_s3_gate_on_rows(
                alt_rows, context=f"vector {v.get('id')} alt {_alt_name}"
            )

    d2v = next(v for v in vectors if v["kind"] == "d2_begin_profiled_no_d3")
    if d2v["calls"][0]["op"] != "begin_profiled":
        raise SystemExit("d2_begin_profiled_no_d3 must use begin_profiled op")
    if any(c["op"] == "begin_profiled_d3s1" for c in d2v["calls"]):
        raise SystemExit("d2_begin_profiled_no_d3 must not call begin_profiled_d3s1")
    if d2v["expected"]["d3_peer_get_count"] != 0:
        raise SystemExit("d2_begin_profiled_no_d3 d3_peer_get_count must be 0")
    if d2v["expected"]["d3_mode_applicable_count"] != 0:
        raise SystemExit("d2_begin_profiled_no_d3 applicable count must be 0")
    # D3 invalid/alias remain on d3s1 path
    for kind in (
        "begin_mode0_invalid",
        "begin_mode21_invalid",
        "begin_context_null",
        "begin_alias_poison",
    ):
        bv = next(v for v in vectors if v["kind"] == kind)
        if bv["calls"][0]["op"] != "begin_profiled_d3s1":
            raise SystemExit(f"{kind} must stay on begin_profiled_d3s1")

    return vectors
def build_document() -> Dict[str, Any]:
    pins = assert_authority_pins()
    vectors = build_vectors()
    required_kinds = sorted(REQUIRED_KINDS)
    prior_fingerprints = [
        {
            "id": v["id"],
            "kind": v["kind"],
            "mode": v["mode"],
            "fingerprint": vector_fingerprint(v),
        }
        for v in vectors
    ]
    prefix_material = "".join(e["fingerprint"] for e in prior_fingerprints).encode(
        "utf-8"
    )
    prior_prefix_hash = hashlib.sha256(prefix_material).hexdigest()
    doc: Dict[str, Any] = {
        "version": VERSION,
        "format": FORMAT,
        "scope": SCOPE,
        "vector_count": len(vectors),
        "required_kinds": required_kinds,
        "workspace": {
            "key_capacity": KEY_CAP,
            "value_capacity": VALUE_CAP,
            "previous_key_capacity": PREV_CAP,
            "ceiling_bytes": CEILING,
            "note": (
                "single 4096 value buffer; D3 context separate (421/448); "
                "no second 4096; no KEY_DIGEST reverse; mutation_calls always 0"
            ),
        },
        "s1_authority": pins["s1"],
        "s2_authority": pins["s2"],
        "s3_authority": pins["s3"],
        "s4_authority": pins["s4"],
        "s5_authority": pins["s5"],
        "d1_authority": pins["d1"],
        "prior_fingerprints": prior_fingerprints,
        "prior_fingerprint_prefix_hash": prior_prefix_hash,
        "sha256_procedure": SHA256_PROCEDURE,
        "content_sha256": "",
        "vectors": vectors,
    }
    doc["content_sha256"] = content_sha256_of_doc(doc)
    return doc


def generate(path: Path) -> None:
    # This generator is the frozen D3-S1 prefix authority. Once the shared
    # sibling artifact has advanced to D3-S2, refuse to destructively replace
    # it with the historical 94-vector document. Use the D3-S2 append-only
    # generator for the shared path instead.
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
        if existing.get("format") == "ninlil-domain-scan-crossrow-v1-d3s2":
            raise SystemExit(
                "refusing D3-S2 sibling downgrade; use "
                "tools/domain_scan_crossrow_d3s2_vector_gen.py"
            )
    doc = build_document()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    path.write_text(text, encoding="utf-8")
    kinds = sorted({v["kind"] for v in doc["vectors"]})
    print(
        f"wrote {path} vectors={doc['vector_count']} kinds={len(kinds)} "
        f"content_sha256={doc['content_sha256']}"
    )
    print_mode17_inventory(doc["vectors"])


def _fail_check(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def check(path: Path) -> int:
    if not path.is_file():
        return _fail_check(f"missing {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    expected_doc = build_document()

    if not data.get("vectors"):
        return _fail_check("vectors empty")
    if data.get("format") != FORMAT:
        return _fail_check(f"format mismatch {data.get('format')}")
    if data.get("version") != VERSION:
        return _fail_check("version mismatch")
    if int(data.get("vector_count", -1)) != EXPECTED_VECTOR_COUNT:
        return _fail_check(
            f"root vector_count {data.get('vector_count')} != pin "
            f"{EXPECTED_VECTOR_COUNT}"
        )
    if data.get("required_kinds") != sorted(REQUIRED_KINDS):
        return _fail_check("required_kinds inventory mismatch")
    if not data.get("sha256_procedure"):
        return _fail_check("missing sha256_procedure")
    if not data.get("content_sha256"):
        return _fail_check("missing content_sha256")
    if data.get("content_sha256") != expected_doc.get("content_sha256"):
        return _fail_check("content_sha256 mismatch vs generator")
    if not isinstance(data.get("prior_fingerprints"), list):
        return _fail_check("prior_fingerprints missing or not a list")
    if data.get("prior_fingerprint_prefix_hash") != expected_doc.get(
        "prior_fingerprint_prefix_hash"
    ):
        return _fail_check("prior_fingerprint_prefix_hash mismatch")
    # Append-only prefix: file fingerprints must equal generator prefix in order
    exp_fps = expected_doc["prior_fingerprints"]
    got_fps = data["prior_fingerprints"]
    if len(got_fps) != len(exp_fps):
        return _fail_check(
            f"prior_fingerprints length {len(got_fps)} != {len(exp_fps)}"
        )
    for i, (g, e) in enumerate(zip(got_fps, exp_fps)):
        if g.get("id") != e.get("id") or g.get("fingerprint") != e.get(
            "fingerprint"
        ):
            return _fail_check(
                f"append-prefix drift at prior_fingerprints[{i}] "
                f"id={g.get('id')!r} vs {e.get('id')!r}"
            )

    vectors = data["vectors"]
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        return _fail_check(
            f"vector count {len(vectors)} != pin {EXPECTED_VECTOR_COUNT}"
        )
    kinds: Set[str] = set()
    catalog = load_d1()
    for i, vec in enumerate(vectors):
        for k in VECTOR_KEYS:
            if k not in vec:
                return _fail_check(f"vector {i} missing key {k}")
        kinds.add(vec["kind"])
        extra = set(vec.keys()) - VECTOR_KEYS
        if extra:
            return _fail_check(f"vector {vec['id']} unexpected keys {extra}")
        for ref_name in ("source_ref", "peer_ref"):
            ref = vec.get(ref_name) or {}
            if not REF_KEYS.issuperset(ref.keys()):
                return _fail_check(
                    f"{vec['id']}: {ref_name} unexpected keys "
                    f"{set(ref.keys()) - REF_KEYS}"
                )
            for mut in ref.get("mutations") or []:
                if not MUTATION_KEYS.issuperset(mut.keys()):
                    return _fail_check(
                        f"{vec['id']}: mutation keys drift in {ref_name}"
                    )
        if not isinstance(vec.get("row_refs"), list):
            return _fail_check(f"{vec['id']}: row_refs must be list")
        if not isinstance(vec.get("notes"), str) or not isinstance(
            vec.get("ownership"), str
        ):
            return _fail_check(f"{vec['id']}: notes/ownership must be strings")
        for f in vec.get("faults", []):
            if not FAULT_KEYS.issuperset(f.keys()):
                return _fail_check(f"fault keys drift in {vec['id']}")
        for c in vec.get("calls", []):
            if not CALL_KEYS.issuperset(c.keys()):
                return _fail_check(f"call keys drift in {vec['id']}")
            op = c.get("op")
            if op not in CLOSED_CALL_OPS:
                return _fail_check(
                    f"{vec['id']}: call op {op!r} not in closed set"
                )
            if op in FORBIDDEN_CALL_OPS or op == "begin":
                return _fail_check(
                    f"{vec['id']}: TEST transport begin forbidden in "
                    "crossrow oracle"
                )
            if "expected_status" not in c:
                return _fail_check(
                    f"{vec['id']}: call missing expected_status for op={op}"
                )
            st = c["expected_status"]
            if op in HARNESS_CALL_OPS:
                if st != "VOID":
                    return _fail_check(
                        f"{vec['id']}: harness op {op} must be VOID (got {st})"
                    )
            else:
                if st == "VOID" or not isinstance(st, str) or not st:
                    return _fail_check(
                        f"{vec['id']}: scanner op {op} missing status "
                        f"(got {st!r})"
                    )
        if set(vec["expected"].keys()) != EXPECTED_KEYS:
            return _fail_check(
                f"expected keys drift in {vec['id']}: "
                f"{set(vec['expected'].keys()) ^ EXPECTED_KEYS}"
            )
        # mutation_calls always 0 on success paths without intentional mutation
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(
                f"{vec['id']}: mutation_calls must be 0 (got "
                f"{vec['expected'].get('mutation_calls')})"
            )
        # d1_refs verify against D1 keys present
        for rid in vec.get("d1_refs", []):
            if rid not in catalog:
                return _fail_check(f"{vec['id']}: unknown d1_ref {rid}")
            dv = catalog[rid]
            if not dv.get("key_hex"):
                continue
            # if key appears in rows, key must match D1
            for r in vec.get("rows", []):
                if r["key_hex"] == dv["key_hex"]:
                    if r["key_hex"] != dv["key_hex"]:
                        return _fail_check(
                            f"{vec['id']}: d1_ref {rid} key_hex mismatch"
                        )
                    break
        # Structured source/peer id/key must agree with frozen D1 when binding=d1
        for ref_name in ("source_ref", "peer_ref"):
            ref = vec.get(ref_name) or {}
            if ref.get("binding") != "d1":
                continue
            rid = ref.get("id") or ""
            if not rid:
                return _fail_check(f"{vec['id']}: {ref_name} d1 binding without id")
            if rid not in catalog:
                return _fail_check(f"{vec['id']}: {ref_name} unknown d1 id {rid}")
            dv = catalog[rid]
            if dv.get("key_hex") and ref.get("key_hex") and ref["key_hex"] != dv[
                "key_hex"
            ]:
                return _fail_check(
                    f"{vec['id']}: {ref_name} key_hex != frozen D1 {rid}"
                )

    if kinds != REQUIRED_KINDS:
        missing = REQUIRED_KINDS - kinds
        extra = kinds - REQUIRED_KINDS
        return _fail_check(
            f"kind set mismatch missing={sorted(missing)} "
            f"extra={sorted(extra)}"
        )

    if json.dumps(data, sort_keys=True) != json.dumps(
        expected_doc, sort_keys=True
    ):
        # Helpful drift report
        ev = expected_doc["vectors"]
        if len(ev) == len(vectors):
            for a, b in zip(vectors, ev):
                if json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True):
                    print(f"drift at vector {a.get('id')}", file=sys.stderr)
                    if a.get("expected") != b.get("expected"):
                        for k in sorted(
                            set(a.get("expected", {})) | set(b.get("expected", {}))
                        ):
                            if a.get("expected", {}).get(k) != b.get(
                                "expected", {}
                            ).get(k):
                                print(
                                    f"  expected.{k}: file={a['expected'].get(k)!r} "
                                    f"gen={b['expected'].get(k)!r}",
                                    file=sys.stderr,
                                )
                    break
        else:
            print(
                f"root drift: vector_count file={len(vectors)} "
                f"gen={len(ev)}",
                file=sys.stderr,
            )
        return _fail_check(
            "document not deterministically equal to generator output"
        )

    for key, fmt, sha, count in (
        ("s1_authority", S1_FORMAT, S1_SHA256, S1_COUNT),
        ("s2_authority", S2_FORMAT, S2_SHA256, S2_COUNT),
        ("s3_authority", S3_FORMAT, S3_SHA256, S3_COUNT),
        ("s4_authority", S4_FORMAT, S4_SHA256, S4_COUNT),
        ("s5_authority", S5_FORMAT, S5_SHA256, S5_COUNT),
        ("d1_authority", D1_FORMAT, D1_SHA256, D1_COUNT),
    ):
        auth = data.get(key) or {}
        if auth.get("format") != fmt or auth.get("sha256") != sha:
            return _fail_check(f"{key} pin mismatch")
        if int(auth.get("vector_count", -1)) != count:
            return _fail_check(f"{key} count pin mismatch")

    print(
        f"ok {path} vectors={len(vectors)} kinds={len(kinds)} "
        f"(exact required set) content_sha256={data.get('content_sha256')}"
    )
    return 0


def self_test() -> int:
    """Negative self-tests that must FAIL check when applied to temp mutations."""
    with tempfile.TemporaryDirectory() as td:
        tdir = Path(td)
        clean = tdir / "clean.json"
        generate(clean)
        if check(clean) != 0:
            print("self-test: clean generate+check failed", file=sys.stderr)
            return 1

        def mutate_and_expect_fail(name: str, mutator) -> Optional[str]:
            doc = json.loads(clean.read_text(encoding="utf-8"))
            mutator(doc)
            p = tdir / f"{name}.json"
            p.write_text(
                json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
            # Run subset of check logic without full rebuild equality when needed;
            # full check should fail.
            rc = check(p)
            if rc == 0:
                return f"self-test {name}: expected check failure, got pass"
            return None

        tests = []

        def m_format(doc):
            doc["format"] = "wrong-format"

        def m_d1_sha(doc):
            doc["d1_authority"]["sha256"] = "0" * 64

        def m_kind(doc):
            doc["vectors"][0]["kind"] = "unknown_kind_xyz"

        def m_status(doc):
            for c in doc["vectors"][0]["calls"]:
                if c["op"] in ("begin_profiled_d3s1", "begin_profiled"):
                    c["expected_status"] = "STORAGE"
                    break

        def m_trace(doc):
            doc["vectors"][0]["expected"]["port_trace"] = ["tampered"]

        def m_mutation(doc):
            # Find a mutation_zero path vector
            for v in doc["vectors"]:
                if v["kind"] == "mutation_zero":
                    v["expected"]["mutation_calls"] = 1
                    break

        def m_count(doc):
            doc["vectors"] = doc["vectors"][:-1]

        def m_prefix(doc):
            # Append-prefix violation: reorder first vector
            if len(doc["vectors"]) >= 2:
                doc["vectors"][0], doc["vectors"][1] = (
                    doc["vectors"][1],
                    doc["vectors"][0],
                )

        def m_mode(doc):
            doc["vectors"][0]["mode"] = 99

        def m_get_count(doc):
            doc["vectors"][0]["expected"]["d3_peer_get_count"] = 999

        def m_ref_id(doc):
            # Tamper frozen D1 source id while keeping binding=d1
            for v in doc["vectors"]:
                if (v.get("source_ref") or {}).get("binding") == "d1":
                    v["source_ref"]["id"] = "NOT_A_REAL_D1_ID"
                    break

        def m_vector_count_field(doc):
            doc["vector_count"] = int(doc.get("vector_count", 0)) - 1

        def m_d2_begin_op(doc):
            # Tamper D2 vector to claim d3s1 begin (must fail check)
            for v in doc["vectors"]:
                if v["kind"] == "d2_begin_profiled_no_d3":
                    v["calls"][0]["op"] = "begin_profiled_d3s1"
                    v["calls"][0]["mode"] = 1
                    break

        def m_future_ok_status(doc):
            for v in doc["vectors"]:
                if v["kind"] == "future_primary_pvd_match_ok":
                    v["expected"]["final_status"] = "OK"  # must be UNSUPPORTED
                    break

        for name, fn in (
            ("format", m_format),
            ("d1_sha", m_d1_sha),
            ("kind", m_kind),
            ("status", m_status),
            ("trace", m_trace),
            ("mutation_calls", m_mutation),
            ("count", m_count),
            ("prefix", m_prefix),
            ("mode", m_mode),
            ("get_count", m_get_count),
            ("ref_id", m_ref_id),
            ("vector_count_field", m_vector_count_field),
            ("d2_begin_op", m_d2_begin_op),
            ("future_ok_status", m_future_ok_status),
        ):
            err = mutate_and_expect_fail(name, fn)
            if err:
                tests.append(err)

        # Independent S3-gate negative self-tests (illegal material classes).
        # These must be rejected by family6_current_row_s3_status without C.
        def s3_neg(name: str, key: bytes, value: bytes) -> Optional[str]:
            st = family6_current_row_s3_status(key, value)
            if st != "STORAGE_CORRUPT":
                return f"self-test {name}: gate returned {st}, want STORAGE_CORRUPT"
            return None

        # Illegal binding: APPLICATION + EXISTING_TX
        app_body = bytearray(d1_body("DSB3_ING_APP_DS_TYPED"))
        app_body[16:18] = be16(BIND_EXISTING_TX)
        app_row = make_row(
            from_hex(d1_row("DSB3_ING_APP_DS_TYPED")["key_hex"]),
            bytes(app_body),
            subtype=ST_INGRESS,
            primary_id=from_hex(d1_row("DSB3_ING_APP_DS_TYPED")["value_hex"])[24:40],
            pvd=bytes(32),
            head=from_hex(d1_row("DSB3_ING_APP_DS_TYPED")["value_hex"])[40:72],
        )
        err = s3_neg(
            "illegal_binding",
            from_hex(app_row["key_hex"]),
            from_hex(app_row["value_hex"]),
        )
        if err:
            tests.append(err)

        # CP digest desync: body subject_primary_value_digest != header PVD
        cp_val = from_hex(d1_row("DSB3_CP_TX_P1_FULL_TYPED")["value_hex"])
        cp_bad = patch_pvd(cp_val, bytes([0x5A] * 32))  # header only
        err = s3_neg(
            "cp_digest",
            from_hex(d1_row("DSB3_CP_TX_P1_FULL_TYPED")["key_hex"]),
            cp_bad,
        )
        if err:
            tests.append(err)

        # Ingress sequence mismatch: key u64 != body ordered_sequence
        seq_body = d1_body("DSB3_ING_APP_DS_TYPED")
        wrong_key = k_u64(ST_INGRESS, be64(99))
        seq_row = make_row(
            wrong_key,
            seq_body,
            subtype=ST_INGRESS,
            primary_id=bytes(8) + be64(99),
            pvd=bytes(32),
            head=from_hex(d1_row("DSB3_ING_APP_DS_TYPED")["value_hex"])[40:72],
        )
        err = s3_neg(
            "ingress_sequence",
            from_hex(seq_row["key_hex"]),
            from_hex(seq_row["value_hex"]),
        )
        if err:
            tests.append(err)

        # Anchor derived digest: ikey flip without recomputing map digest
        aval = from_hex(d1_row("DSB2_ANCHOR_TYPED")["value_hex"])
        _st, abody, _ = extract_envelope(aval)
        a = parse_anchor(abody)
        mut = bytearray(abody)
        idx = bytes(mut).find(a["ikey"])
        mut[idx] ^= 0x5C
        anch_bad = enc_env_full(
            6, ST_ANCHOR, 0, 1, aval[24:40], aval[40:72], bytes(32), bytes(mut)
        )
        err = s3_neg(
            "anchor_derived_digest",
            from_hex(d1_row("DSB2_ANCHOR_TYPED")["key_hex"]),
            anch_bad,
        )
        if err:
            tests.append(err)

        # Callback token_generation == 0
        rc = parse_rc(d1_body("DSB3_RC_INBOX_VIRGIN_TYPED"))
        owner0 = raw16(rc["delivery_raw"]) + be64(0)
        res0 = make_row(
            k_composite(ST_RES, be16(5) + raw16(owner0)),
            make_res_body(5, owner0),
            subtype=ST_RES,
            primary_id=composite(ST_DELIVERY, raw16(rc["delivery_raw"]))[:16],
            pvd=bytes([0x33] * 32),
        )
        err = s3_neg(
            "callback_token_generation",
            from_hex(res0["key_hex"]),
            from_hex(res0["value_hex"]),
        )
        if err:
            tests.append(err)

        # Future expectation: framing-future must be UNSUPPORTED (not CORRUPT)
        fut_k = from_hex(d1_row("DSB2_SERVICE_TYPED")["key_hex"])
        fut_v = nlr1(6, 2, bytes([0xAA] * 64))
        fut_st = family6_current_row_s3_status(fut_k, fut_v)
        if fut_st != "UNSUPPORTED":
            tests.append(
                f"self-test future_expectation: gate returned {fut_st}, "
                "want UNSUPPORTED"
            )

        # Mode18 DELIVERY-owned must stay applicable with ABSENT (not skip /
        # not PRESENT). Regression of rebuild to TX-only would drop coverage.
        dlv_row = d1_row("DSB3_ATT_DLV_CMD_REMOTE_TYPED")
        ev_dlv = rebuild_peer(
            18,
            from_hex(dlv_row["key_hex"]),
            from_hex(dlv_row["value_hex"]),
        )
        if ev_dlv is None or ev_dlv.expect_presence != "ABSENT":
            tests.append(
                "self-test mode18_delivery_absent: rebuild must be applicable "
                f"with ABSENT, got {None if ev_dlv is None else ev_dlv.expect_presence}"
            )
        else:
            # Spurious AII at rebuilt key must force STORAGE_CORRUPT under ref eng.
            aii_row = d1_row("DSB3_AII_CMD_TYPED")
            if aii_row["key_hex"] != hex_of(ev_dlv.peer_key):
                tests.append(
                    "self-test mode18_delivery_absent: D1 AII key must match "
                    "DELIVERY attempt_id peer probe"
                )
            else:
                b = default_binding_fields()
                profile = encode_all_profile_rows(b)
                probe = make_vector(
                    "D3S1_M18_SELFTEST_DLV_UNEXPECTED",
                    "mode18_delivery_attempt_unexpected_present_corrupt",
                    18,
                    merge_rows(profile, [dlv_row, aii_row]),
                    std_scan_calls(18),
                    d1_refs=[
                        "DSB3_ATT_DLV_CMD_REMOTE_TYPED",
                        "DSB3_AII_CMD_TYPED",
                    ],
                    source_ref=d1_ref_from_id(
                        "DSB3_ATT_DLV_CMD_REMOTE_TYPED", row=dlv_row
                    ),
                    peer_ref=d1_ref_from_id(
                        "DSB3_AII_CMD_TYPED",
                        row=aii_row,
                        expect_presence="ABSENT",
                    ),
                    require_rebuild=False,
                )
                if probe["expected"]["final_status"] != "STORAGE_CORRUPT":
                    tests.append(
                        "self-test mode18_delivery_unexpected: want "
                        f"STORAGE_CORRUPT got {probe['expected']['final_status']}"
                    )
                if int(probe["expected"].get("d3_peer_get_count", 0)) < 1:
                    tests.append(
                        "self-test mode18_delivery_unexpected: peer get required"
                    )

        if tests:
            for t in tests:
                print(t, file=sys.stderr)
            return 1

        # Clean again
        if check(clean) != 0:
            print("self-test: clean re-check failed", file=sys.stderr)
            return 1
        print(
            "self-test ok (14 negative mutations + 6 S3-gate negatives + "
            "mode18 DELIVERY ABSENT/unexpected probe: "
            "pin/format/kind/vector_count/mode/status/get-count/mutation/trace/"
            "append-prefix/ref-id/d2-begin-op/future-ok-status + "
            "illegal_binding/cp_digest/ingress_sequence/anchor_derived_digest/"
            "callback_token_generation/future_expectation + clean pass)"
        )
        return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    lines: List[str] = []
    lines.append(
        "/* Generated by tools/domain_scan_crossrow_vector_gen.py — do not edit. */"
    )
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(f"#define NINLIL_D3S1_VECTOR_COUNT ((size_t){len(vectors)}u)")
    lines.append(
        f"#define NINLIL_D3S1_WORKSPACE_CEILING_BYTES ((uint32_t){CEILING}u)"
    )
    lines.append("#define NINLIL_D3S1_MAX_TRACE ((size_t)512u)")
    lines.append("#define NINLIL_D3S1_MAX_KEY ((size_t)255u)")
    lines.append("#define NINLIL_D3S1_MAX_VALUE ((size_t)4096u)")
    lines.append("#define NINLIL_D3S1_MAX_ALT ((size_t)4u)")
    lines.append("")
    lines.append("/* No NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN required. */")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_binding {")
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
    lines.append("} ninlil_d3s1_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_row {")
    lines.append("    uint8_t key[64];")
    lines.append("    uint32_t key_length;")
    lines.append("    const uint8_t *value;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_d3s1_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_fault {")
    lines.append("    const char *op;")
    lines.append("    uint32_t on_call;")
    lines.append("    const char *shape;")
    lines.append("    const char *status;")
    lines.append("    uint32_t key_length;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_d3s1_fault_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_call {")
    lines.append("    const char *op;")
    lines.append("    uint32_t row_budget;")
    lines.append("    const uint8_t *key;")
    lines.append("    uint32_t key_length;")
    lines.append("    const char *name;")
    lines.append("    uint8_t mode;")
    lines.append("    const char *context; /* NULL, \"null\", or \"alias_session\" */")
    lines.append("    const char *expected_status;")
    lines.append("} ninlil_d3s1_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_alt {")
    lines.append("    const char *name;")
    lines.append("    const ninlil_d3s1_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("} ninlil_d3s1_alt_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_expected {")
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
    lines.append("    uint32_t iter_open_count;")
    lines.append("    const char *const *port_trace;")
    lines.append("    size_t port_trace_count;")
    lines.append("    uint8_t has_sticky_primary;")
    lines.append("    const char *sticky_primary;")
    lines.append("    uint64_t d3_peer_get_count;")
    lines.append("    uint64_t d3_mode_applicable_count;")
    lines.append("} ninlil_d3s1_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    uint8_t mode;")
    lines.append("    ninlil_d3s1_binding_t candidate;")
    lines.append("    const ninlil_d3s1_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_d3s1_alt_t *alts;")
    lines.append("    size_t alt_count;")
    lines.append("    const ninlil_d3s1_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_d3s1_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_d3s1_expected_t expected;")
    lines.append("} ninlil_d3s1_vector_t;")
    lines.append("")

    def c_bytes_literal(data: bytes, name: str) -> List[str]:
        out = [f"static const uint8_t {name}[] = {{"]
        if data:
            parts = [f"0x{b:02x}" for b in data]
            for i in range(0, len(parts), 12):
                out.append("    " + ", ".join(parts[i : i + 12]) + ",")
        else:
            out.append("    0x00,")
        out.append("};")
        return out

    def binding_literal(fields: Dict[str, Any]) -> str:
        rid = from_hex(fields["runtime_id_hex"])
        rid_l = ", ".join(f"0x{b:02x}" for b in rid)
        lim = fields["limits"]
        return (
            "{ "
            f"{int(fields['storage_schema'])}u, {int(fields['role'])}u, "
            f"{int(fields['environment'])}u, {{ {rid_l} }}, "
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
            f"{int(fields['terminal_retention_ms'])}ull, "
            f"{int(fields['result_cache_retention_ms'])}ull, "
            f"{int(fields['observation_retention_ms'])}ull "
            "}"
        )

    for vi, vec in enumerate(vectors):
        for ri, row in enumerate(vec.get("rows", [])):
            val = from_hex(row["value_hex"])
            lines.extend(c_bytes_literal(val, f"ninlil_d3s1_{vi}_v{ri}"))
        lines.append(f"static const ninlil_d3s1_row_t ninlil_d3s1_{vi}_rows[] = {{")
        for ri, row in enumerate(vec.get("rows", [])):
            key = from_hex(row["key_hex"])
            key_l = ", ".join(f"0x{b:02x}" for b in key)
            pad = ", ".join("0x00" for _ in range(max(0, 64 - len(key))))
            key_arr = key_l + ((", " + pad) if pad else "")
            lines.append(
                f"    {{ {{ {key_arr} }}, {len(key)}u, "
                f"ninlil_d3s1_{vi}_v{ri}, {len(from_hex(row['value_hex']))}u }},"
            )
        if not vec.get("rows"):
            lines.append("    { {0}, 0u, NULL, 0u },")
        lines.append("};")
        lines.append(
            f"static const ninlil_d3s1_alt_t ninlil_d3s1_alts_{vi}[] = {{"
        )
        lines.append("    { NULL, NULL, 0u },")
        lines.append("};")
        lines.append(
            f"static const ninlil_d3s1_fault_t ninlil_d3s1_faults_{vi}[] = {{"
        )
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f.get("op", "")}", {int(f.get("on_call", 0))}u, '
                f'"{f.get("shape", "natural")}", "{f.get("status", "OK")}", '
                f'{int(f.get("key_length", 0))}u, '
                f'{int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append('    { "", 0u, "", "", 0u, 0u },')
        lines.append("};")
        lines.append(
            f"static const ninlil_d3s1_call_t ninlil_d3s1_calls_{vi}[] = {{"
        )
        for c in vec["calls"]:
            mode_c = int(c.get("mode", vec.get("mode", 0)))
            ctx = c.get("context")
            ctx_s = f'"{ctx}"' if ctx else "NULL"
            lines.append(
                f'    {{ "{c["op"]}", {int(c.get("row_budget", 0))}u, NULL, 0u, '
                f'"{c.get("name", "")}", {mode_c}u, {ctx_s}, '
                f'"{c.get("expected_status", "")}" }},'
            )
        lines.append("};")
        exp = vec["expected"]
        lines.append(
            f"static const char *const ninlil_d3s1_trace_{vi}[] = {{"
        )
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append('    "",')
        lines.append("};")

    lines.append(
        "static const ninlil_d3s1_vector_t "
        "ninlil_d3s1_vectors[NINLIL_D3S1_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(vectors):
        exp = vec["expected"]
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {int(vec.get('mode', 0))}u,")
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(
            f"        ninlil_d3s1_{vi}_rows, {len(vec.get('rows', []))}u,"
        )
        lines.append(f"        ninlil_d3s1_alts_{vi}, 0u,")
        lines.append(
            f"        ninlil_d3s1_faults_{vi}, {len(vec.get('faults', []))}u,"
        )
        lines.append(
            f"        ninlil_d3s1_calls_{vi}, {len(vec['calls'])}u,"
        )
        lines.append("        {")
        lines.append(f'            "{exp["final_status"]}",')
        lines.append(f"            {int(exp['adopted'])}u,")
        lines.append(f'            "{exp["state_after"]}",')
        lines.append(f"            {int(exp['recognizable_future_seen'])}u,")
        lines.append(f"            {int(exp['family14_row_count'])}ull,")
        lines.append(f"            {int(exp['current_domain_key_count'])}ull,")
        lines.append(f"            {int(exp['ok_row_count'])}ull,")
        lines.append(f"            {int(exp['profile_exact_active'])}u,")
        lines.append(f"            {int(exp['profile_mismatch'])}u,")
        lines.append(f"            {int(exp['future_profile_candidate'])}u,")
        lines.append(f"            0x{int(exp['profile_get_present_mask']):x}u,")
        lines.append(f"            0x{int(exp['family14_iter_seen_mask']):x}u,")
        lines.append(f"            {int(exp['reopen_required'])}u,")
        lines.append(f"            {int(exp.get('close_count', 0))}u,")
        lines.append(f"            {int(exp['mutation_calls'])}u,")
        lines.append(f"            {int(exp['iter_open_count'])}u,")
        lines.append(
            f"            ninlil_d3s1_trace_{vi}, "
            f"{len(exp.get('port_trace', []))}u,"
        )
        lines.append(f"            {int(exp['has_sticky_primary'])}u,")
        lines.append(f'            "{exp.get("sticky_primary", "")}",')
        lines.append(f"            {int(exp.get('d3_peer_get_count', 0))}ull,")
        lines.append(
            f"            {int(exp.get('d3_mode_applicable_count', 0))}ull"
        )
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H */")
    lines.append("")
    header_path.parent.mkdir(parents=True, exist_ok=True)
    header_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {header_path} ({len(vectors)} vectors)")


def print_mode17_inventory(vectors: List[Dict[str, Any]]) -> None:
    mapping = [
        ("SERVICE_QUOTA → SERVICE", "mode17_quota_to_service"),
        ("RES SERVICE → SERVICE", "mode17_res_service"),
        ("RES TRANSACTION → ANCHOR", "mode17_res_transaction"),
        ("RES INGRESS → INGRESS", "mode17_res_ingress"),
        ("RES DELIVERY → DELIVERY", "mode17_res_delivery"),
        ("RES CALLBACK → DELIVERY", "mode17_res_callback_to_delivery"),
        ("SEQ → ANCHOR", "mode17_seq_to_anchor"),
        ("STATE → ANCHOR", "mode17_state_to_anchor"),
        ("IDEM (dual-raw) → ANCHOR", "mode17_idem_to_anchor"),
        ("EVENT_MAP → ANCHOR", "mode17_evmap_to_anchor"),
        ("EVENT_SPOOL → ANCHOR", "mode17_evspool_to_anchor"),
        ("RETRY_SUMMARY → ANCHOR", "mode17_retry_to_anchor"),
        ("MANAGEMENT_LEDGER → ANCHOR", "mode17_mgmt_to_anchor"),
        ("SCHEDULER TX → ANCHOR", "mode17_sched_tx_to_anchor"),
        ("SCHEDULER DLV → DELIVERY", "mode17_sched_dlv_to_delivery"),
        ("SCHEDULER ING → INGRESS", "mode17_sched_ing_to_ingress"),
        ("ATTEMPT TX → owner ANCHOR", "mode17_attempt_tx_to_owner"),
        ("ATTEMPT DLV → owner DELIVERY", "mode17_attempt_dlv_to_owner"),
        ("ATTEMPT_ID_INDEX → ANCHOR", "mode17_aii_to_anchor"),
        ("CANCEL TX → owner ANCHOR", "mode17_cancel_tx_to_owner"),
        ("CANCEL DLV → owner DELIVERY", "mode17_cancel_dlv_to_owner"),
        ("EVIDENCE TX → owner ANCHOR", "mode17_evidence_tx_to_owner"),
        ("EVIDENCE DLV → owner DELIVERY", "mode17_evidence_dlv_to_owner"),
        ("RESULT_CACHE → DELIVERY", "mode17_rc_to_delivery"),
        ("REVERSE_REPLY → DELIVERY", "mode17_rr_to_delivery"),
        ("RETENTION TX → subject ANCHOR", "mode17_rb_tx_to_subject"),
        ("RETENTION DLV → subject DELIVERY", "mode17_rb_dlv_to_subject"),
        ("CLEANUP TX → subject ANCHOR", "mode17_cp_tx_to_subject"),
        ("CLEANUP DLV → subject DELIVERY", "mode17_cp_dlv_to_subject"),
    ]
    by_kind = {v["kind"]: v["id"] for v in vectors}
    print("Mode17 reverse inventory:")
    print(f"{'source → primary':<40} {'kind':<40} vector_id")
    for label, kind in mapping:
        print(f"{label:<40} {kind:<40} {by_kind.get(kind, 'MISSING')}")


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
    if cmd == "self-test":
        return self_test()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
