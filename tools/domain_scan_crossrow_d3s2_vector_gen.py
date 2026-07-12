#!/usr/bin/env python3
"""Independent D3-S2 crossrow sibling oracle (append-only; stdlib only).

Appends D3-S2 suffix vectors onto the frozen D3-S1 94-vector prefix
produced by tools/domain_scan_crossrow_vector_gen.py:

  * 6 Mode21..26 empty-carrier / empty-secondary COMPLETE product smoke
  * Mode25 slice: CUM total=1 + RECENT C1 + true ANCHOR success, and
    RECENT-without-CUM carrier-ABSENT STORAGE_CORRUPT (note path)
  * Mode26 slice: EVENT_SPOOL resume=1 + MANAGEMENT RESUME + true ANCHOR
    stream success, and MANAGEMENT-without-EVENT_SPOOL carrier-ABSENT
    STORAGE_CORRUPT (note path)
  * Mode24 slice: RESULT_CACHE reply_count=1 + REVERSE_REPLY RECEIPT +
    true DELIVERY known-kind FOCUS/BIND success, and REVERSE_REPLY-
    without-RESULT_CACHE carrier-ABSENT STORAGE_CORRUPT (note path)
  * Mode23 slice: retained TRANSACTION_STATE + true ANCHOR + EVIDENCE
    slots 0..L (L=3) known-slot FOCUS/BIND success (nontrivial
    valid=M+overflow equation), and EVIDENCE-without-STATE BIND
    carrier-ABSENT STORAGE_CORRUPT (note path)
  * Mode22 slice: APPLICATION_FIRST RESULT_CACHE app=1 + DELIVERY-owned
    ATTEMPT stream + true DELIVERY BIND (INDEX ABSENT peer) success, and
    DELIVERY-owned ATTEMPT-without-RESULT_CACHE BIND carrier-ABSENT
    STORAGE_CORRUPT (note path)

Does NOT invoke, import, link, or translate production C scanner/codec.
Does NOT claim full D3-S2 oracle complete (docs/17 §18.13.4 / .5 / .9 / .15).

Usage:
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py generate <path>
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py check <path>
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py emit-c-fixture <json> <header>
  python3 tools/domain_scan_crossrow_d3s2_vector_gen.py self-test
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
D3S1_GEN_PATH = REPO_ROOT / "tools" / "domain_scan_crossrow_vector_gen.py"
DEFAULT_JSON = REPO_ROOT / "spec" / "vectors" / "domain-scan-crossrow-v1.json"

FORMAT = "ninlil-domain-scan-crossrow-v1-d3s2"
VERSION = 1
D3S1_PREFIX_COUNT = 94
D3S2_SMOKE_COUNT = 6
D3S2_MODE25_SLICE_COUNT = 2
D3S2_MODE26_SLICE_COUNT = 2
D3S2_MODE24_SLICE_COUNT = 2
D3S2_MODE23_SLICE_COUNT = 2
D3S2_MODE22_SLICE_COUNT = 2
D3S2_SUFFIX_COUNT = (
    D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
    + D3S2_MODE22_SLICE_COUNT
)  # 16
EXPECTED_VECTOR_COUNT = D3S1_PREFIX_COUNT + D3S2_SUFFIX_COUNT  # 110
D3S2_100_PREFIX_COUNT = D3S1_PREFIX_COUNT + D3S2_SMOKE_COUNT  # 100
D3S2_102_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT + D3S2_SMOKE_COUNT + D3S2_MODE25_SLICE_COUNT
)  # 102
D3S2_104_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
)  # 104
D3S2_106_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
)  # 106
D3S2_108_PREFIX_COUNT = (
    D3S1_PREFIX_COUNT
    + D3S2_SMOKE_COUNT
    + D3S2_MODE25_SLICE_COUNT
    + D3S2_MODE26_SLICE_COUNT
    + D3S2_MODE24_SLICE_COUNT
    + D3S2_MODE23_SLICE_COUNT
)  # 108
CEILING = 8192

# Frozen D3-S1 prefix identity (byte-for-byte rebuild pin).
D3S1_FORMAT = "ninlil-domain-scan-crossrow-v1-d3s1"
D3S1_PREFIX_CONTENT_SHA256 = (
    "76b28d847be8cd7a95e8f1879400403abf702931a3de170a473c7c0f76d95468"
)
D3S1_PREFIX_FINGERPRINT_HASH = (
    "2c99af3c9b3aea228e4478c0d2739352f111fdd8c42303bf07177f8bb8ee8c58"
)

# Frozen 100-vector append-only prefix (94 D3S1 + 6 D3S2 smoke) — prior main.
D3S2_100_CONTENT_SHA256 = (
    "880e4b62cf62eb667397b9c58e547298290df92c87a4308400274e9db090fc89"
)
D3S2_100_FINGERPRINT_HASH = (
    "0d769bba784c0f2250f27d382d4150c22570095da6f12b237b9e49d2bd6c9a0c"
)

# Frozen 102-vector append-only prefix (100 + Mode25 slice).
D3S2_102_CONTENT_SHA256 = (
    "31bee901f9ab613cf7fe1d8e58b28a1c28ea174e8869a859d0a6c756c2ec88ea"
)
D3S2_102_FINGERPRINT_HASH = (
    "c399e6d7a39de7792c7782ee70468f5508d984df509ed3a2b602baa8fb39e246"
)

# Frozen 104-vector append-only prefix (102 + Mode26 slice).
D3S2_104_CONTENT_SHA256 = (
    "03915c54e1e1bbfce20392d36428f5e50c03c91d016c24ec0aba0fb9d0c2f629"
)
D3S2_104_FINGERPRINT_HASH = (
    "baac26572c63a72c3ae90cc02f56b89017100a046aebedeed734ee3fa0ed1b22"
)

# Frozen 106-vector append-only prefix (104 + Mode24 slice) — prior main.
D3S2_106_CONTENT_SHA256 = (
    "3c5f7bfaea92ffa7a4373a48cddfb36936fac23332dfc6fe7c69e0cf5f7b88c2"
)
D3S2_106_FINGERPRINT_HASH = (
    "dba8c377074892b934cd4417ce5a0d1bd917f93b3fa2b49ba023873b15467a1f"
)

# Frozen 108-vector append-only prefix (106 + Mode23 slice) — prior main.
# content hash + fingerprint chain independently derived from origin/main
# 108-vector artifact (not recomputed by rewriting published objects).
D3S2_108_CONTENT_SHA256 = (
    "23e504f1346c04d9a9ee6b59a5eae9bca3b52e4a4de2460c61d0ce7043efab66"
)
D3S2_108_FINGERPRINT_HASH = (
    "724d58e23d504f65b12ab0a6dc7e4df51cfd18c1cc3be956cd4aed560a67a25a"
)

# D1 authority pins for Mode25 material (independent of production C).
D1_CUM_ID = "DSB3_RS_CUM_T0_TYPED"
D1_REC_ID = "DSB3_RS_REC_C1_TYPED"
D1_ANCHOR_ID = "DSB2_ANCHOR_TYPED"

# D1 authority pins for Mode26 material (independent of production C).
D1_ES_ID = "DSB3_ES_ACTIVE_TYPED"
D1_ML_ID = "DSB3_ML_R_RSN1_TYPED"
# EVENT_SPOOL body: successful_resume_count u32 BE at body offset 260;
# discard_committed u32 BE at 264 (docs/17 §8.6 D1-B3k; independent parse).
ES_RESUME_BODY_OFF = 260
ES_DISCARD_BODY_OFF = 264
ML_KIND_RESUME = 15
ML_TX_BODY_OFF = 28  # after operation_id[16] + kind u16 + reserved u16 + seq u64

# D1 authority pins for Mode24 material (independent of production C).
D1_DLV_ID = "DSB3_DLV_APP_DS_TYPED"
D1_RC_ID = "DSB3_RC_RESULT_POS_TYPED"
D1_RR_ID = "DSB3_RR_KIND_RECEIPT_TYPED"
# RESULT_CACHE body (exact 378): reply_count u32 BE after
# delivery_raw:RAW16(82) + delivery_kd[32] + txn[16] + n:u64 + app_seen:u32
# + app_attempt:u32 + state:u32 → body offset 150 (docs/17 §8.5 D1-B3i).
RC_REPLY_COUNT_BODY_OFF = 150
# REVERSE_REPLY body (exact 330): reply_key_raw:RAW16(86) where contents =
# delivery_key_raw:RAW16(82) || reply_kind:u32; closed kinds 1..4
# (RECEIPT..CANCEL_RESULT). Kind wire lives at body offset 2+82.
RR_REPLY_KIND_BODY_OFF = 84  # 2 (RAW16 len) + 82 (delivery RAW16 prefix)
RR_KIND_RECEIPT = 1
RR_KIND_MIN = 1
RR_KIND_MAX = 4
DLV_KEY_CONTENTS_BYTES = 80

# D1 authority pins for Mode22 material (independent of production C).
# RESULT_CACHE / DELIVERY share Mode24 authority IDs; ATTEMPT is DLV-owned.
D1_ATT_DLV_ID = "DSB3_ATT_DLV_CMD_REMOTE_TYPED"
# RESULT_CACHE body (exact 378): application_attempt_count u32 BE at body
# offset 142 (after delivery_raw:RAW16(82) + kd[32] + txn[16] + n:u64
# + app_seen:u32); reply_count remains at 150 (docs/17 §8.5 D1-B3i).
RC_APP_ATTEMPT_BODY_OFF = 142
# ATTEMPT body (exact 322): attempt_id[16] + owner_kind:u16 + reserved:u16
# + owner_key_raw:RAW16 + primary_key_digest[32] + transaction_id[16] + ...
# + attempt_kind:u16. Closed kinds 1 COMMAND / 2 EVENT / 3 CANCEL.
ATT_BODY_LEN = 322
ATT_OWNER_KIND_DELIVERY = 2
ATT_KIND_COMMAND = 1
ATT_KIND_CANCEL = 3

# D1 authority pins for Mode23 material (independent of production C).
D1_STATE_ID = "DSB2_STATE_TYPED"
D1_EV_SUM_MAT_ID = "DSB3_EV_TX_SUM_MAT_LEN0_TYPED"
D1_EV_SUM_EMPTY_ID = "DSB3_EV_TX_SUM_EMPTY_TYPED"
D1_EV_RAW_UNUSED_ID = "DSB3_EV_TX_RAW_UNUSED_TYPED"
D1_EV_RAW_MAT_ID = "DSB3_EV_TX_RAW_MAT_TYPED"
# EVIDENCE_CELL TX body exact 734 (docs/17 §8.3 D1-B3g): owner TX raw16=16.
# Offsets after owner_kind:u16 + cell_kind:u16 + RAW16(18) + pkd32 + target32.
EV_TX_BODY_LEN = 734
EV_CELL_KIND_BODY_OFF = 2
EV_OWNER_RAW_LEN = 16
EV_SLOT_BODY_OFF = 86  # 2+2+2+16+32+32
EV_CELL_STATE_BODY_OFF = 90
EV_LATE_MATERIAL_BODY_OFF = 114  # after reserved0 + 5*u32 stages/disp/effect
EV_VALID_BODY_OFF = 702  # last four u64 counters
EV_OVERFLOW_BODY_OFF = 718
EV_LATE_COUNT_BODY_OFF = 726
EV_OWNER_KIND_TX = 1
EV_CELL_KIND_SUMMARY = 1
EV_CELL_KIND_RAW = 2
EV_CELL_STATE_UNUSED = 1
EV_CELL_STATE_MATERIALIZED = 2
# Accepted profile default_binding max_evidence_per_target (not a cell field).
MODE23_ACCEPTED_L = 3

# Phase / mask constants (docs/17 §18.13; match domain_store_d3s2.h).
PHASE_COMPLETE = 15
PHASE_FAILED = 16
FLAG_BASELINE_DONE = 0x01
FLAG_BIND_PHASE_ACTIVE = 0x04
FLAG_COMPLETE_READY = 0x08
MASK_ATTEMPT = 0x01
MASK_INDEX = 0x02
MASK_EVIDENCE = 0x04
MASK_REPLY = 0x08
MASK_RETRY = 0x10
MASK_MANAGEMENT = 0x20

MODE_BIND_MASK = {
    21: MASK_ATTEMPT | MASK_INDEX,
    22: MASK_ATTEMPT,
    23: MASK_EVIDENCE,
    24: MASK_REPLY,
    25: MASK_RETRY,
    26: MASK_MANAGEMENT,
}
# Empty-carrier smoke drive chunks (Mode21 BIND has two subtypes).
MODE_DRIVE_COUNT = {21: 4, 22: 3, 23: 3, 24: 3, 25: 3, 26: 3}
MODE_ITER_OPEN = {21: 4, 22: 3, 23: 3, 24: 3, 25: 3, 26: 3}

D3S2_SMOKE_KINDS = frozenset(
    {
        "mode21_empty_carrier_empty_secondary_ok",
        "mode22_empty_carrier_empty_secondary_ok",
        "mode23_empty_carrier_empty_secondary_ok",
        "mode24_empty_carrier_empty_secondary_ok",
        "mode25_empty_carrier_empty_secondary_ok",
        "mode26_empty_carrier_empty_secondary_ok",
    }
)
D3S2_MODE25_KINDS = frozenset(
    {
        "mode25_cum_total1_recent_slot1_anchor_ok",
        "mode25_recent_without_cum_carrier_absent_corrupt",
    }
)
D3S2_MODE26_KINDS = frozenset(
    {
        "mode26_es_resume1_mgmt_resume_anchor_ok",
        "mode26_mgmt_without_es_carrier_absent_corrupt",
    }
)
D3S2_MODE24_KINDS = frozenset(
    {
        "mode24_rc_reply1_receipt_delivery_ok",
        "mode24_rr_without_rc_carrier_absent_corrupt",
    }
)
D3S2_MODE23_KINDS = frozenset(
    {
        "mode23_tx_state_slots_L_equation_anchor_ok",
        "mode23_evidence_without_state_carrier_absent_corrupt",
    }
)
D3S2_MODE22_KINDS = frozenset(
    {
        "mode22_rc_app1_dlv_attempt_delivery_ok",
        "mode22_att_without_rc_carrier_absent_corrupt",
    }
)
D3S2_REQUIRED_KINDS = (
    D3S2_SMOKE_KINDS
    | D3S2_MODE25_KINDS
    | D3S2_MODE26_KINDS
    | D3S2_MODE24_KINDS
    | D3S2_MODE23_KINDS
    | D3S2_MODE22_KINDS
)

SCANNER_CALL_OPS = frozenset(
    {
        "begin_profiled",
        "begin_profiled_d3s1",
        "begin_profiled_d3s2",
        "d3s2_drive",
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

# D3-S1 expected keys (prefix must match exactly).
D3S1_EXPECTED_KEYS = frozenset(
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
D3S2_EXPECTED_EXTRA = frozenset(
    {
        "phase",
        "count_complete_mask",
        "binding_complete_mask",
        "flags",
    }
)
D3S2_EXPECTED_KEYS = D3S1_EXPECTED_KEYS | D3S2_EXPECTED_EXTRA

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

SCOPE = (
    "D3-S2 crossrow sibling oracle (append-only on domain-scan-crossrow-v1): "
    "frozen 94-vector D3-S1 exact-1 prefix retained byte-for-byte; frozen "
    "100-vector pin (94 + 6 Mode21..26 empty-carrier smoke) retained; frozen "
    "102-vector pin (100 + Mode25 slice) retained; frozen 104-vector pin "
    "(102 + Mode26 slice) retained; frozen 106-vector pin (104 + Mode24 "
    "slice) retained; frozen 108-vector pin (106 + Mode23 slice) retained "
    "as append-only prefix; Mode22 slice appends APPLICATION_FIRST live "
    "RESULT_CACHE (application_attempt_count=1) carrier + DELIVERY-owned "
    "ATTEMPT (COMMAND) stream focus (observed app=1 cancel=0 C=0; true "
    "iterator EXHAUSTED count bit0) + BIND_ATTEMPT (RESULT_CACHE carrier "
    "subject + true DELIVERY PVD/raw + ATTEMPT_ID_INDEX ABSENT peer; no "
    "FOCUS_INDEX/BIND_INDEX) COMPLETE success, and DELIVERY-owned "
    "ATTEMPT-without-RESULT_CACHE BIND carrier-ABSENT STORAGE_CORRUPT "
    "(note path, not Port fail; primary/INDEX gets must not run). Each "
    "vector is one mode per independent READ_ONLY txn; baseline once + "
    "sequential zero-prefix reopen; stream FOCUS closes only on true "
    "iterator EXHAUSTED; SHA256_COMPOSITE ATTEMPT rows complete-key lex "
    "sorted; mutation_calls=0. Does not claim full D3-S2 oracle complete, "
    "Stage5 D3 bind, D4, public Runtime, ESP-IDF, or hardware. TEST "
    "transport begin forbidden. Independent generator — production C not "
    "invoked for expected generation."
)

SHA256_PROCEDURE = (
    "Do not embed full-file sha256 inside this artifact. Generator `check` "
    "proves deterministic rebuild equality against "
    "tools/domain_scan_crossrow_d3s2_vector_gen.py and fail-closed freezes "
    "the exact 94-vector D3-S1 prefix, the 100-vector prior main, the "
    "102-vector prior main, the 104-vector prior main, the 106-vector "
    "prior main, and the 108-vector prior main "
    "(fingerprint/order/expected/rows/calls/full object equality). "
    "content_sha256 "
    "covers the document with sha256_procedure/content_sha256 fields set "
    "to empty strings before hashing."
)

# Frozen historical ownership for all pre-Mode23 suffix builders (smoke +
# Mode25/26/24). Must stay exact "12-vector" — do not interpolate live
# D3S2_SUFFIX_COUNT (that was the Mode23 append-only ownership-drift defect).
OWNERSHIP_FROZEN_106_PREFIX = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(12-vector suffix on frozen 94-prefix only)"
)
# Alias used by pre-Mode23 builders (smoke / Mode25 / Mode26 / Mode24).
OWNERSHIP_DEFAULT = OWNERSHIP_FROZEN_106_PREFIX
# Current Mode23-only ownership (14-vector suffix at Mode23 append time).
# Hardcoded 14 so a later append does not rewrite published Mode23 objects.
OWNERSHIP_MODE23 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(14-vector suffix on frozen 94-prefix only)"
)
# Current Mode22-only ownership (16-vector suffix at Mode22 append time).
# Hardcoded 16 so a later append does not rewrite published Mode22 objects.
OWNERSHIP_MODE22 = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim "
    "(16-vector suffix on frozen 94-prefix only)"
)


def _load_d3s1():
    spec = importlib.util.spec_from_file_location(
        "domain_scan_crossrow_vector_gen", D3S1_GEN_PATH
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {D3S1_GEN_PATH}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_d3s1 = _load_d3s1()


def from_hex(s: str) -> bytes:
    return _d3s1.from_hex(s)


def hex_of(b: bytes) -> str:
    return _d3s1.hex_of(b)


def content_sha256_of_doc(doc: Dict[str, Any]) -> str:
    tmp = copy.deepcopy(doc)
    tmp["sha256_procedure"] = ""
    tmp["content_sha256"] = ""
    raw = json.dumps(tmp, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def d3s1_vector_fingerprint(vec: Dict[str, Any]) -> str:
    """Prefix fingerprints must match the frozen D3-S1 generator exactly."""
    return _d3s1.vector_fingerprint(vec)


def d3s2_vector_fingerprint(vec: Dict[str, Any]) -> str:
    """Suffix fingerprint includes phase / count+binding masks."""
    exp = vec["expected"]
    payload = {
        "id": vec["id"],
        "kind": vec["kind"],
        "mode": vec["mode"],
        "candidate_binding": vec["candidate_binding"],
        "rows": vec["rows"],
        "alt_rows": vec.get("alt_rows") or {},
        "faults": vec["faults"],
        "calls": vec["calls"],
        "expected": {
            "final_status": exp.get("final_status"),
            "adopted": exp.get("adopted"),
            "state_after": exp.get("state_after"),
            "recognizable_future_seen": exp.get("recognizable_future_seen"),
            "family14_row_count": exp.get("family14_row_count"),
            "current_domain_key_count": exp.get("current_domain_key_count"),
            "ok_row_count": exp.get("ok_row_count"),
            "profile_exact_active": exp.get("profile_exact_active"),
            "profile_mismatch": exp.get("profile_mismatch"),
            "future_profile_candidate": exp.get("future_profile_candidate"),
            "profile_get_present_mask": exp.get("profile_get_present_mask"),
            "family14_iter_seen_mask": exp.get("family14_iter_seen_mask"),
            "reopen_required": exp.get("reopen_required"),
            "close_count": exp.get("close_count"),
            "mutation_calls": exp.get("mutation_calls"),
            "iter_open_count": exp.get("iter_open_count"),
            "port_trace": exp.get("port_trace"),
            "has_sticky_primary": exp.get("has_sticky_primary"),
            "sticky_primary": exp.get("sticky_primary"),
            "d3_peer_get_count": exp.get("d3_peer_get_count"),
            "d3_mode_applicable_count": exp.get("d3_mode_applicable_count"),
            "phase": exp.get("phase"),
            "count_complete_mask": exp.get("count_complete_mask"),
            "binding_complete_mask": exp.get("binding_complete_mask"),
            "flags": exp.get("flags"),
        },
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _walk_trace_segment(n_ok_rows: int) -> List[str]:
    """One zero-prefix full-band walk: n_ok_rows OK visits + terminal NOT_FOUND."""
    return ["iter_next"] * (n_ok_rows + 1)


def _begin_profile_port_prefix() -> List[str]:
    """begin(RO) + 17 family1–4 profile gets (docs/17 §18.13.4 baseline)."""
    return ["begin:READ_ONLY"] + ["get"] * 17


def run_d3s2_empty_carrier_case(
    mode: int, binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Independent reference model for empty-carrier / empty-secondary success.

    Models docs/17 §18.13.4/.5/.9 same-txn machine for profile-only material:
      begin_profiled_d3s2 → baseline once → sequential zero-prefix reopen →
      SELECT_CARRIER empty → BIND set(mode) empty → COMPLETE → finalize adopt.

    Does not invoke production C. Port trace / iter_open / masks match the
    closed empty-carrier production path.
    """
    if mode not in MODE_BIND_MASK:
        raise SystemExit(f"unsupported focus_mode {mode}")
    if len(rows) != 17:
        raise SystemExit(
            f"empty-carrier smoke requires exact 17 profile rows (got {len(rows)})"
        )

    n_drive = MODE_DRIVE_COUNT[mode]
    n_open = MODE_ITER_OPEN[mode]
    bind_mask = MODE_BIND_MASK[mode]
    n_ok = 17

    calls: List[Dict[str, Any]] = [
        {
            "op": "begin_profiled_d3s2",
            "mode": mode,
            "expected_status": "OK",
        }
    ]
    for _ in range(n_drive):
        calls.append(
            {
                "op": "d3s2_drive",
                "row_budget": 256,
                "expected_status": "OK",
            }
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    # Port trace: begin + 17 profile gets + n_open *(open + walk + close) + rollback
    port_trace: List[str] = _begin_profile_port_prefix()
    for _ in range(n_open):
        port_trace.append("iter_open:prefix0")
        port_trace.extend(_walk_trace_segment(n_ok))
        port_trace.append("iter_close")
    port_trace.append("rollback")

    # Baseline freezes D2 counters at 17 family14 / 17 ok / 0 current-domain.
    # INTERNAL passes do not re-increment frozen D2 counters (§18.13.5).
    expected: Dict[str, Any] = {
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
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # Empty-carrier BIND walks no secondaries → 0 peer gets.
        "d3_peer_get_count": 0,
        "d3_mode_applicable_count": 0,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": 0,  # no carriers closed
        "binding_complete_mask": bind_mask,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }

    # Material-induced sanity: profile rows must match candidate binding encoding.
    encoded = _d3s1.encode_all_profile_rows(binding)
    if rows != encoded:
        raise SystemExit("empty-carrier rows must equal stdlib profile encoding")

    return calls, expected


# ---------------------------------------------------------------------------
# Mode25 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _d1_catalog() -> Dict[str, Dict[str, Any]]:
    return _d3s1.load_d1()


def _assert_d1_authority_pin() -> None:
    """Fail-closed: D1 catalog pin must match the D3-S1 generator's pin."""
    cat = _d1_catalog()
    for vid in (
        D1_CUM_ID,
        D1_REC_ID,
        D1_ANCHOR_ID,
        D1_ES_ID,
        D1_ML_ID,
        D1_DLV_ID,
        D1_RC_ID,
        D1_RR_ID,
        D1_STATE_ID,
        D1_EV_SUM_MAT_ID,
        D1_EV_SUM_EMPTY_ID,
        D1_EV_RAW_UNUSED_ID,
        D1_EV_RAW_MAT_ID,
    ):
        if vid not in cat:
            raise SystemExit(f"D1 authority missing required vector {vid}")
        v = cat[vid]
        if not v.get("key_hex") or not v.get("value_hex"):
            raise SystemExit(f"D1 {vid} missing key_hex/value_hex")
    if getattr(_d3s1, "D1_SHA256", None) is None:
        raise SystemExit("d3s1 module missing D1_SHA256 pin")
    raw = _d3s1.D1_VECTORS.read_bytes()
    got = hashlib.sha256(raw).hexdigest()
    if got != _d3s1.D1_SHA256:
        raise SystemExit(
            f"D1 authority pin mismatch: got {got} want {_d3s1.D1_SHA256}"
        )
    data = json.loads(_d3s1.D1_VECTORS.read_text(encoding="utf-8"))
    if data.get("format") != _d3s1.D1_FORMAT:
        raise SystemExit(f"D1 format pin mismatch: {data.get('format')}")
    if len(data["vectors"]) != _d3s1.D1_COUNT:
        raise SystemExit("D1 vector_count pin mismatch")


def _patch_cum_total_completed(value: bytes, total: int) -> bytes:
    """Independent body field patch: CUM total_completed_cycle_count + folded.

    RETRY CUM body (docs/17 §8.6 D1-B3l): tx16 | kind u16 | slot u16 |
    total u64 | folded u64 | … . folded = max(total-4, 0). Same-length
    envelope body replace + CRC32C trailer recompute (stdlib). Does not
    call production C.
    """
    st, body, _pvd = _d3s1.extract_envelope(value)
    if st != 0x51:
        raise SystemExit(f"CUM patch expected subtype 0x51, got {st:#x}")
    if len(body) != 84:
        raise SystemExit(f"CUM body must be exact 84, got {len(body)}")
    kind = struct.unpack_from(">H", body, 16)[0]
    slot = struct.unpack_from(">H", body, 18)[0]
    if kind != 1 or slot != 0:
        raise SystemExit(f"CUM kind/slot must be 1/0, got {kind}/{slot}")
    b = bytearray(body)
    struct.pack_into(">Q", b, 20, int(total))
    folded = 0 if total < 4 else int(total) - 4
    struct.pack_into(">Q", b, 28, folded)
    # admission-style zeros for folded==0 remain as in D1 base when total<=4
    if folded == 0:
        # cumulative_attempt..counter_saturated must be exact 0 (§8.6)
        b[36:] = bytes(len(b) - 36)
    out = bytearray(value)
    # body at fixed envelope offset 108 for current NLR1 domain framing
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        # fall back to search (should not happen for D1 typed values)
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("CUM body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    # re-parse to confirm
    _st2, body2, _ = _d3s1.extract_envelope(bytes(out))
    got_total = struct.unpack_from(">Q", body2, 20)[0]
    got_folded = struct.unpack_from(">Q", body2, 28)[0]
    if got_total != total or got_folded != folded:
        raise SystemExit("CUM total/folded patch did not stick")
    return bytes(out)


def _mode25_material_rows(
    *, include_cum: bool, cum_total: int
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + ANCHOR [+ CUM] + RECENT rows with independent PVD patch.

    Returns (rows_sorted, named_rows, anchor_pvd).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    rec = cat[D1_REC_ID]
    cum = cat[D1_CUM_ID]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)

    rec_key = from_hex(rec["key_hex"])
    rec_val = _d3s1.patch_pvd(from_hex(rec["value_hex"]), anchor_pvd)

    named: Dict[str, Dict[str, str]] = {
        "anchor": {"key_hex": hex_of(anchor_key), "value_hex": hex_of(anchor_val)},
        "recent": {"key_hex": hex_of(rec_key), "value_hex": hex_of(rec_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["anchor"],
        named["recent"],
    ]
    if include_cum:
        cum_key = from_hex(cum["key_hex"])
        cum_val = _patch_cum_total_completed(from_hex(cum["value_hex"]), cum_total)
        cum_val = _d3s1.patch_pvd(cum_val, anchor_pvd)
        named["cum"] = {
            "key_hex": hex_of(cum_key),
            "value_hex": hex_of(cum_val),
        }
        domain_rows.append(named["cum"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    # Lex order: profile family1–4 then domain family6 (ANCHOR 0x20 < RETRY 0x51).
    all_rows = list(profile) + sorted(
        domain_rows, key=lambda r: from_hex(r["key_hex"])
    )
    # Stable sorted full set
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, anchor_pvd


def run_d3s2_mode25_cum_total1_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: CUM total=1 carrier + RECENT slot0 (C1) + true ANCHOR COMPLETE.

    Independent reference model (docs/17 §18.13.4/.5/.7/.9/.10):
      begin → baseline once (freeze D2) → SELECT finds CUM → FOCUS known-slot
      matrix (CUM + RECENT 0..3 presence exact_gets) → SELECT empty →
      BIND_RETRY (CUM self-carrier primary-only; RECENT carrier companion +
      primary) → COMPLETE → finalize adopt. mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode25 success expects 20 rows (17+3), got {n_ok}")
    # Drives: baseline, SELECT+FOCUS matrix, SELECT empty→BIND, BIND COMPLETE
    n_drive = 4
    n_open = 4  # begin open + 3 reopens

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 25, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE: open(from begin) + full walk + reopen(close+open)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS: open + full walk + 5 known-slot gets + reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * 5)  # CUM + RECENT slots 0..3
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND entry: open + full walk + reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND_RETRY: open + walk with interleaved peer gets
    # Order: 17 profile + ANCHOR (next only) + CUM (next+primary get) +
    #        RECENT (next+carrier get+primary get) + NOT_FOUND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # CUM
    port_trace.append("get")  # true primary ANCHOR (CUM self-carrier)
    port_trace.append("iter_next")  # RECENT
    port_trace.append("get")  # carrier companion CUM
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + CUM + RECENT
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # FOCUS matrix 5 + BIND 3 peer exact_gets
        "d3_peer_get_count": 8,
        "d3_mode_applicable_count": 2,  # CUM + RECENT BIND secondaries
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_RETRY,
        "binding_complete_mask": MASK_RETRY,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode25 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    if rows[:17] != encoded:
        # profile subset must match (may interleave if sort differs — force check)
        prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
        if prof != encoded:
            raise SystemExit("mode25 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode25_recent_without_cum_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode25: RECENT + ANCHOR, no same-tx CUM → empty-carrier SELECT then
    BIND_RETRY carrier exact_get ABSENT → note_terminal_corrupt STORAGE_CORRUPT.

    Not a Port failure. abort consumes sticky. mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode25 recent-without-cum expects 19 rows (17+2), got {n_ok}"
        )
    # Drives: baseline OK, SELECT empty→BIND OK, BIND fail
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 25, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until RECENT; carrier CUM ABSENT → note stop
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # RECENT
    port_trace.append("get")  # carrier companion CUM → ABSENT finding
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # ANCHOR + RECENT
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # RECENT BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding  # same default binding; profile already in rows
    return calls, expected


# ---------------------------------------------------------------------------
# Mode26 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _patch_es_resume_discard(
    value: bytes, *, resume: int, discard: int
) -> bytes:
    """Independent body field patch: EVENT_SPOOL resume/discard + re-CRC.

    EVENT_SPOOL body (docs/17 §8.6 D1-B3k): exact 300; successful_resume_count
    u32 BE @260; discard_committed u32 BE @264. Same-length envelope body
    replace + CRC32C trailer recompute (stdlib). Does not call production C.
    """
    st, body, _pvd = _d3s1.extract_envelope(value)
    if st != 0x50:
        raise SystemExit(f"ES patch expected subtype 0x50, got {st:#x}")
    if len(body) != 300:
        raise SystemExit(f"ES body must be exact 300, got {len(body)}")
    if not (0 <= int(resume) <= 8):
        raise SystemExit(f"ES resume out of D1 domain 0..8: {resume}")
    if int(discard) not in (0, 1):
        raise SystemExit(f"ES discard must be 0|1, got {discard}")
    b = bytearray(body)
    struct.pack_into(">I", b, ES_RESUME_BODY_OFF, int(resume))
    struct.pack_into(">I", b, ES_DISCARD_BODY_OFF, int(discard))
    out = bytearray(value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("ES body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    _st2, body2, _ = _d3s1.extract_envelope(bytes(out))
    got_r = struct.unpack_from(">I", body2, ES_RESUME_BODY_OFF)[0]
    got_d = struct.unpack_from(">I", body2, ES_DISCARD_BODY_OFF)[0]
    if got_r != int(resume) or got_d != int(discard):
        raise SystemExit("ES resume/discard patch did not stick")
    return bytes(out)


def _parse_es_resume_discard(value: bytes) -> Tuple[int, int]:
    """Independent EVENT_SPOOL resume/discard parse (no production C)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x50 or len(body) != 300:
        raise SystemExit("ES parse: not a typed EVENT_SPOOL body")
    resume = struct.unpack_from(">I", body, ES_RESUME_BODY_OFF)[0]
    discard = struct.unpack_from(">I", body, ES_DISCARD_BODY_OFF)[0]
    return int(resume), int(discard)


def _parse_ml_tx_and_kind(value: bytes) -> Tuple[bytes, int]:
    """Independent MANAGEMENT_LEDGER body parse: (transaction_id, op_kind)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x52 or len(body) != 364:
        raise SystemExit("ML parse: not a typed MANAGEMENT_LEDGER body")
    kind = struct.unpack_from(">H", body, 16)[0]
    tx = bytes(body[ML_TX_BODY_OFF : ML_TX_BODY_OFF + 16])
    return tx, int(kind)


def _mode26_material_rows(
    *, include_es: bool, resume: int, discard: int
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + ANCHOR + MANAGEMENT [+ EVENT_SPOOL] with PVD patch.

    Returns (rows_sorted, named_rows, anchor_pvd).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    ml = cat[D1_ML_ID]
    es = cat[D1_ES_ID]

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)
    anchor_tx = anchor_key[13:29]
    if len(anchor_tx) != 16:
        raise SystemExit("ANCHOR ID128 identity must be exact 16")

    ml_key = from_hex(ml["key_hex"])
    ml_val = _d3s1.patch_pvd(from_hex(ml["value_hex"]), anchor_pvd)
    ml_tx, ml_kind = _parse_ml_tx_and_kind(ml_val)
    if ml_kind != ML_KIND_RESUME:
        raise SystemExit(f"Mode26 requires MANAGEMENT RESUME kind=15, got {ml_kind}")
    if ml_tx != anchor_tx:
        raise SystemExit(
            "Mode26 MANAGEMENT transaction_id must match ANCHOR/ES tx "
            f"(ml={hex_of(ml_tx)} anchor={hex_of(anchor_tx)})"
        )

    named: Dict[str, Dict[str, str]] = {
        "anchor": {"key_hex": hex_of(anchor_key), "value_hex": hex_of(anchor_val)},
        "mgmt": {"key_hex": hex_of(ml_key), "value_hex": hex_of(ml_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["anchor"],
        named["mgmt"],
    ]
    if include_es:
        es_key = from_hex(es["key_hex"])
        es_val = _patch_es_resume_discard(
            from_hex(es["value_hex"]), resume=resume, discard=discard
        )
        es_val = _d3s1.patch_pvd(es_val, anchor_pvd)
        got_r, got_d = _parse_es_resume_discard(es_val)
        if got_r != int(resume) or got_d != int(discard):
            raise SystemExit("Mode26 ES fixture resume/discard self-check fail")
        es_tx = _d3s1.extract_envelope(es_val)[1][:16]
        if es_tx != anchor_tx:
            raise SystemExit("Mode26 EVENT_SPOOL tx must match ANCHOR")
        named["es"] = {
            "key_hex": hex_of(es_key),
            "value_hex": hex_of(es_val),
        }
        domain_rows.append(named["es"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, anchor_pvd


def run_d3s2_mode26_es_resume1_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode26 stream success: ES resume=1 carrier + 1 MANAGEMENT RESUME + ANCHOR.

    Independent reference model (docs/17 §18.13.4/.5/.6/.7/.9/.10):
      begin → baseline once → SELECT finds EVENT_SPOOL → reopen FOCUS stream
      full-band (H2 on true EXHAUSTED only; observed_a=1 vs declared=1) →
      SELECT empty → BIND_MANAGEMENT (carrier ES companion get + true ANCHOR
      primary) → COMPLETE → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+reopen FOCUS; 3 FOCUS stream H2+reopen SELECT;
      4 SELECT empty→BIND; 5 BIND COMPLETE.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode26 success expects 20 rows (17+3), got {n_ok}")
    n_drive = 5
    n_open = 5

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 26, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT carrier (full residual walk) → reopen FOCUS stream
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 FOCUS_MANAGEMENT stream (0 exact_get per secondary; H2 on EXHAUSTED)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 BIND_MANAGEMENT: carrier companion then true primary (strict order)
    # Order: 17 profile + ANCHOR + ES + MANAGEMENT(next+carrier get+primary get)
    #        + NOT_FOUND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # EVENT_SPOOL
    port_trace.append("iter_next")  # MANAGEMENT
    port_trace.append("get")  # carrier companion EVENT_SPOOL
    port_trace.append("get")  # true primary ANCHOR
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # ANCHOR + ES + MANAGEMENT
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # BIND only: 1 carrier + 1 primary (FOCUS stream uses 0 exact_get)
        "d3_peer_get_count": 2,
        "d3_mode_applicable_count": 1,  # one MANAGEMENT BIND secondary
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_MANAGEMENT,
        "binding_complete_mask": MASK_MANAGEMENT,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode26 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        # profile family1–4 keys are short catalog keys
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode26 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode26_mgmt_without_es_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode26: MANAGEMENT + ANCHOR, no EVENT_SPOOL → empty-carrier SELECT then
    BIND_MANAGEMENT carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary get must not run. abort; mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode26 mgmt-without-es expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 26, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until MANAGEMENT; carrier ES ABSENT → note stop
    # (primary ANCHOR get must not run after carrier ABSENT)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # MANAGEMENT
    port_trace.append("get")  # carrier companion ES → ABSENT finding
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # ANCHOR + MANAGEMENT
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # MANAGEMENT BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


# ---------------------------------------------------------------------------
# Mode24 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _patch_rc_reply_count(value: bytes, reply_count: int) -> bytes:
    """Independent body field patch: RESULT_CACHE reply_count + re-CRC.

    RESULT_CACHE body exact 378 (docs/17 §8.5 D1-B3i). reply_count u32 BE at
    body offset 150; domain 0..4. Same-length envelope body replace + CRC32C
    trailer recompute (stdlib). Does not call production C.
    """
    st, body, _pvd = _d3s1.extract_envelope(value)
    if st != 0x41:
        raise SystemExit(f"RC patch expected subtype 0x41, got {st:#x}")
    if len(body) != 378:
        raise SystemExit(f"RC body must be exact 378, got {len(body)}")
    if not (0 <= int(reply_count) <= 4):
        raise SystemExit(f"RC reply_count out of domain 0..4: {reply_count}")
    b = bytearray(body)
    struct.pack_into(">I", b, RC_REPLY_COUNT_BODY_OFF, int(reply_count))
    out = bytearray(value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        idx = bytes(out).find(body)
        if idx < 0:
            raise SystemExit("RC body not found in envelope value")
        body_off = idx
    out[body_off : body_off + len(body)] = b
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    _st2, body2, _ = _d3s1.extract_envelope(bytes(out))
    got = struct.unpack_from(">I", body2, RC_REPLY_COUNT_BODY_OFF)[0]
    if got != int(reply_count):
        raise SystemExit("RC reply_count patch did not stick")
    return bytes(out)


def _parse_rc_reply_count_and_delivery(value: bytes) -> Tuple[int, bytes, bytes]:
    """Independent RESULT_CACHE parse: (reply_count, delivery_raw80, txn16)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x41 or len(body) != 378:
        raise SystemExit("RC parse: not a typed RESULT_CACHE body")
    raw_len = int.from_bytes(body[0:2], "big")
    if raw_len != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RC delivery raw length {raw_len} != 80")
    delivery_raw = bytes(body[2 : 2 + DLV_KEY_CONTENTS_BYTES])
    txn = bytes(body[114:130])  # after RAW16(82) + kd(32)
    reply_count = struct.unpack_from(">I", body, RC_REPLY_COUNT_BODY_OFF)[0]
    if reply_count > 4:
        raise SystemExit(f"RC reply_count out of domain: {reply_count}")
    return int(reply_count), delivery_raw, txn


def _parse_rr_kind_and_delivery(value: bytes) -> Tuple[int, bytes, bytes]:
    """Independent REVERSE_REPLY parse: (reply_kind, delivery_raw80, txn16).

    reply_key_raw:RAW16(86) = delivery:RAW16(82) || reply_kind:u32.
    Closed domain kinds 1..4 (RECEIPT=1 .. CANCEL_RESULT=4).
    """
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x42 or len(body) != 330:
        raise SystemExit("RR parse: not a typed REVERSE_REPLY body")
    reply_raw_len = int.from_bytes(body[0:2], "big")
    if reply_raw_len != 86:
        raise SystemExit(f"RR reply_key raw length {reply_raw_len} != 86")
    nested_len = int.from_bytes(body[2:4], "big")
    if nested_len != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RR nested delivery raw length {nested_len} != 80")
    delivery_raw = bytes(body[4 : 4 + DLV_KEY_CONTENTS_BYTES])
    reply_kind = struct.unpack_from(">I", body, RR_REPLY_KIND_BODY_OFF)[0]
    if not (RR_KIND_MIN <= reply_kind <= RR_KIND_MAX):
        raise SystemExit(f"RR reply_kind out of closed domain 1..4: {reply_kind}")
    # Body also stores delivery_raw:RAW16 after reply_key; require bijection.
    o = 2 + 86
    dlen = int.from_bytes(body[o : o + 2], "big")
    if dlen != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RR body delivery raw length {dlen} != 80")
    body_draw = bytes(body[o + 2 : o + 2 + DLV_KEY_CONTENTS_BYTES])
    if body_draw != delivery_raw:
        raise SystemExit("RR reply_key delivery raw != body delivery raw")
    # transaction_id follows delivery_raw:RAW16 in body (independent layout).
    txn_off = o + 2 + DLV_KEY_CONTENTS_BYTES
    txn = bytes(body[txn_off : txn_off + 16])
    return int(reply_kind), delivery_raw, txn


def _parse_delivery_raw_and_primary(value: bytes) -> Tuple[bytes, bytes, bytes]:
    """Independent DELIVERY parse: (delivery_raw80, txn16, header primary_id)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x40:
        raise SystemExit(f"DELIVERY parse expected subtype 0x40, got {st:#x}")
    d = _d3s1.parse_delivery(body)
    draw = d["delivery_raw"]
    if len(draw) != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"DELIVERY raw length {len(draw)} != 80")
    primary_id = value[24:40]
    if len(primary_id) != 16:
        raise SystemExit("DELIVERY header primary_id must be exact 16")
    return bytes(draw), bytes(d["txn"]), bytes(primary_id)


def _mode24_material_rows(
    *, include_rc: bool, reply_count: int
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + DELIVERY + REVERSE_REPLY [+ RESULT_CACHE] with PVD patch.

    Returns (rows_sorted, named_rows, delivery_value_digest).
    Independent of production C: D1 authority rows + stdlib body/PVD/CRC.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    dlv = cat[D1_DLV_ID]
    rr = cat[D1_RR_ID]
    rc = cat[D1_RC_ID]

    dlv_key = from_hex(dlv["key_hex"])
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    # Header primary_id / CRC re-validated via independent envelope parse.
    dlv_draw, dlv_txn, dlv_primary_id = _parse_delivery_raw_and_primary(dlv_val)
    if dlv_primary_id != dlv_val[24:40]:
        raise SystemExit("DELIVERY primary_id self-check fail")
    # Key identity for COMPOSITE DELIVERY is KEY_DIGEST(raw16(delivery_raw));
    # primary_id on D1 typed rows is the key identity digest prefix (16 of 32).
    if len(dlv_key) != 45 or dlv_key[8] != 6 or dlv_key[9] != 0x40:
        raise SystemExit("DELIVERY key framing unexpected")

    rr_key = from_hex(rr["key_hex"])
    rr_val = _d3s1.patch_pvd(from_hex(rr["value_hex"]), dlv_pvd)
    rr_kind, rr_draw, rr_txn = _parse_rr_kind_and_delivery(rr_val)
    if rr_kind != RR_KIND_RECEIPT:
        raise SystemExit(
            f"Mode24 requires REVERSE_REPLY RECEIPT kind=1, got {rr_kind}"
        )
    if rr_draw != dlv_draw:
        raise SystemExit("Mode24 RR delivery_raw must match DELIVERY raw")
    if rr_txn != dlv_txn:
        raise SystemExit("Mode24 RR transaction_id must match DELIVERY txn")
    # Independent header PVD/CRC re-parse after patch.
    _st_rr, _body_rr, rr_pvd = _d3s1.extract_envelope(rr_val)
    if rr_pvd != dlv_pvd:
        raise SystemExit("Mode24 RR header PVD must equal DELIVERY VALUE_DIGEST")
    if _d3s1.domain_value_framing(rr_val) != "current":
        raise SystemExit("Mode24 RR envelope framing not current after PVD patch")

    named: Dict[str, Dict[str, str]] = {
        "delivery": {"key_hex": hex_of(dlv_key), "value_hex": hex_of(dlv_val)},
        "rr": {"key_hex": hex_of(rr_key), "value_hex": hex_of(rr_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["delivery"],
        named["rr"],
    ]
    if include_rc:
        rc_key = from_hex(rc["key_hex"])
        rc_val = _patch_rc_reply_count(from_hex(rc["value_hex"]), reply_count)
        rc_val = _d3s1.patch_pvd(rc_val, dlv_pvd)
        got_rc, rc_draw, rc_txn = _parse_rc_reply_count_and_delivery(rc_val)
        if got_rc != int(reply_count):
            raise SystemExit(
                f"Mode24 RC reply_count self-check fail: {got_rc} != {reply_count}"
            )
        if rc_draw != dlv_draw:
            raise SystemExit("Mode24 RC delivery_raw must match DELIVERY raw")
        if rc_txn != dlv_txn:
            raise SystemExit("Mode24 RC transaction_id must match DELIVERY txn")
        _st_rc, _body_rc, rc_pvd = _d3s1.extract_envelope(rc_val)
        if rc_pvd != dlv_pvd:
            raise SystemExit(
                "Mode24 RC header PVD must equal DELIVERY VALUE_DIGEST"
            )
        if _d3s1.domain_value_framing(rc_val) != "current":
            raise SystemExit(
                "Mode24 RC envelope framing not current after patch"
            )
        named["rc"] = {
            "key_hex": hex_of(rc_key),
            "value_hex": hex_of(rc_val),
        }
        domain_rows.append(named["rc"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, dlv_pvd


def run_d3s2_mode24_rc_reply1_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode24 known-kind success: RC reply_count=1 + RR RECEIPT + true DELIVERY.

    Independent reference model (docs/17 §18.13.4/.5/.6/.7/.9/.10 B6k):
      begin → baseline once → SELECT finds RESULT_CACHE → FOCUS known-kind
      matrix (closed reply_kind 1..4 exact_get presence only; no secondary
      stream EXHAUSTED) → count/popcount/mask close (observed=1 == declared) →
      SELECT empty → BIND_REPLY (RESULT_CACHE carrier subject + true DELIVERY
      PVD/raw) → COMPLETE → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+FOCUS matrix; 3 SELECT empty→BIND; 4 BIND COMPLETE.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode24 success expects 20 rows (17+3), got {n_ok}")
    n_drive = 4
    n_open = 4

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 24, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS known-kind: full residual walk + 4 kind presence gets
    # (closed kinds 1..4; B6k; no iterator EXHAUSTED required for close)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * 4)
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND_REPLY: carrier RESULT_CACHE then true DELIVERY primary
    # Order: 17 profile + DELIVERY + RESULT_CACHE + REVERSE_REPLY
    #        (next+carrier get+primary get) + NOT_FOUND
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE
    port_trace.append("iter_next")  # REVERSE_REPLY
    port_trace.append("get")  # carrier companion RESULT_CACHE
    port_trace.append("get")  # true primary DELIVERY
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # DELIVERY + RESULT_CACHE + REVERSE_REPLY
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # FOCUS matrix 4 + BIND 2 peer exact_gets
        "d3_peer_get_count": 6,
        "d3_mode_applicable_count": 1,  # one REVERSE_REPLY BIND secondary
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_REPLY,
        "binding_complete_mask": MASK_REPLY,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode24 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode24 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode24_rr_without_rc_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode24: RR + DELIVERY, no RESULT_CACHE → empty-carrier SELECT then
    BIND_REPLY carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary DELIVERY get must not run. abort; mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode24 rr-without-rc expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 24, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until REVERSE_REPLY; carrier RC ABSENT → note stop
    # (primary DELIVERY get must not run after carrier ABSENT)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # REVERSE_REPLY
    port_trace.append("get")  # carrier companion RESULT_CACHE → ABSENT
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # DELIVERY + REVERSE_REPLY
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # REVERSE_REPLY BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


# ---------------------------------------------------------------------------
# Mode23 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _evidence_composite_key(owner_kind: int, owner_raw: bytes, slot: int) -> bytes:
    """Independent SHA256_COMPOSITE complete key for EVIDENCE_CELL (0x32)."""
    if len(owner_raw) != EV_OWNER_RAW_LEN:
        raise SystemExit(f"evidence owner_raw must be {EV_OWNER_RAW_LEN}")
    components = (
        _d3s1.be16(int(owner_kind))
        + _d3s1.raw16(owner_raw)
        + _d3s1.be32(int(slot))
    )
    return _d3s1.bkey(6, 0x32, 5, _d3s1.composite(0x32, components))


def _replace_evidence_body_and_crc(value: bytes, body: bytes) -> bytes:
    """Same-length envelope body replace + CRC32C trailer (stdlib only)."""
    out = bytearray(value)
    body_off = 108
    if bytes(out[body_off : body_off + len(body)]) != body:
        # Fall back: locate previous body bytes for non-canonical framing.
        st0, body0, _ = _d3s1.extract_envelope(value)
        if st0 != 0x32:
            raise SystemExit(f"evidence envelope subtype {st0:#x} != 0x32")
        idx = bytes(out).find(body0)
        if idx < 0:
            raise SystemExit("evidence body not found in envelope value")
        body_off = idx
        if len(body0) != len(body):
            raise SystemExit("evidence body length must stay fixed (734 TX)")
    if len(body) != EV_TX_BODY_LEN:
        raise SystemExit(f"TX evidence body must be {EV_TX_BODY_LEN}, got {len(body)}")
    out[body_off : body_off + len(body)] = body
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    return bytes(out)


def _parse_tx_evidence_cell(
    value: bytes,
) -> Tuple[int, int, int, bytes, int, int, int, int]:
    """Independent TX EVIDENCE parse.

    Returns (cell_kind, cell_state, slot, owner_raw16, valid, overflow,
    late_count, late_material).
    """
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x32 or len(body) != EV_TX_BODY_LEN:
        raise SystemExit("EV parse: not a typed TX EVIDENCE_CELL body")
    owner_kind = struct.unpack_from(">H", body, 0)[0]
    if owner_kind != EV_OWNER_KIND_TX:
        raise SystemExit(f"EV owner_kind must be TX=1, got {owner_kind}")
    cell_kind = struct.unpack_from(">H", body, EV_CELL_KIND_BODY_OFF)[0]
    raw_len = struct.unpack_from(">H", body, 4)[0]
    if raw_len != EV_OWNER_RAW_LEN:
        raise SystemExit(f"EV owner raw length {raw_len} != 16")
    owner_raw = bytes(body[6 : 6 + EV_OWNER_RAW_LEN])
    slot = struct.unpack_from(">I", body, EV_SLOT_BODY_OFF)[0]
    cell_state = struct.unpack_from(">H", body, EV_CELL_STATE_BODY_OFF)[0]
    late_material = struct.unpack_from(">I", body, EV_LATE_MATERIAL_BODY_OFF)[0]
    valid = struct.unpack_from(">Q", body, EV_VALID_BODY_OFF)[0]
    overflow = struct.unpack_from(">Q", body, EV_OVERFLOW_BODY_OFF)[0]
    late_count = struct.unpack_from(">Q", body, EV_LATE_COUNT_BODY_OFF)[0]
    return (
        int(cell_kind),
        int(cell_state),
        int(slot),
        owner_raw,
        int(valid),
        int(overflow),
        int(late_count),
        int(late_material),
    )


def _build_tx_evidence_value(
    *,
    template_value: bytes,
    slot: int,
    cell_kind: int,
    cell_state: int,
    valid: int = 0,
    overflow: int = 0,
    late_count: int = 0,
    late_material: int = 0,
    anchor_pvd: bytes,
) -> Tuple[bytes, bytes]:
    """Build one TX EVIDENCE complete key+value from a D1 typed template.

    Independent body field patch + composite rekey + PVD→ANCHOR + CRC.
    Does not call production C.
    """
    st, body, _ = _d3s1.extract_envelope(template_value)
    if st != 0x32 or len(body) != EV_TX_BODY_LEN:
        raise SystemExit("EV template must be TX EVIDENCE_CELL typed envelope")
    b = bytearray(body)
    owner_kind = struct.unpack_from(">H", b, 0)[0]
    if owner_kind != EV_OWNER_KIND_TX:
        raise SystemExit("EV template owner must be TRANSACTION")
    raw_len = struct.unpack_from(">H", b, 4)[0]
    if raw_len != EV_OWNER_RAW_LEN:
        raise SystemExit("EV template owner raw length must be 16")
    owner_raw = bytes(b[6 : 6 + EV_OWNER_RAW_LEN])
    struct.pack_into(">H", b, EV_CELL_KIND_BODY_OFF, int(cell_kind))
    struct.pack_into(">I", b, EV_SLOT_BODY_OFF, int(slot))
    struct.pack_into(">H", b, EV_CELL_STATE_BODY_OFF, int(cell_state))
    struct.pack_into(">I", b, EV_LATE_MATERIAL_BODY_OFF, int(late_material))
    struct.pack_into(">Q", b, EV_VALID_BODY_OFF, int(valid))
    struct.pack_into(">Q", b, EV_OVERFLOW_BODY_OFF, int(overflow))
    struct.pack_into(">Q", b, EV_LATE_COUNT_BODY_OFF, int(late_count))
    # RAW MATERIALIZED / UNUSED and SUMMARY empty require zero counters on
    # non-SUMMARY-material shapes; SUMMARY material keeps patched counters.
    if cell_kind == EV_CELL_KIND_RAW:
        struct.pack_into(">Q", b, EV_VALID_BODY_OFF, 0)
        struct.pack_into(">Q", b, 710, 0)  # exact_dup
        struct.pack_into(">Q", b, EV_OVERFLOW_BODY_OFF, 0)
        struct.pack_into(">Q", b, EV_LATE_COUNT_BODY_OFF, 0)
    val = _replace_evidence_body_and_crc(template_value, bytes(b))
    val = _d3s1.patch_pvd(val, anchor_pvd)
    if _d3s1.domain_value_framing(val) != "current":
        raise SystemExit("EV envelope framing not current after patch")
    key = _evidence_composite_key(EV_OWNER_KIND_TX, owner_raw, slot)
    # Self-check independent parse.
    ck, cs, got_slot, got_owner, got_v, got_o, got_l, got_lm = (
        _parse_tx_evidence_cell(val)
    )
    if ck != int(cell_kind) or cs != int(cell_state) or got_slot != int(slot):
        raise SystemExit("EV slot/kind/state patch did not stick")
    if got_owner != owner_raw:
        raise SystemExit("EV owner_raw identity drift")
    if cell_kind == EV_CELL_KIND_SUMMARY:
        if (got_v, got_o, got_l, got_lm) != (
            int(valid),
            int(overflow),
            int(late_count),
            int(late_material),
        ):
            raise SystemExit("EV SUMMARY counter/late_material patch fail")
        # D1 same-record: late_material == (late_evidence_count > 0)
        if int(late_material) != (1 if int(late_count) > 0 else 0):
            raise SystemExit("EV SUMMARY late_material coherence fail")
        if int(overflow) > int(valid) or int(late_count) > int(valid):
            raise SystemExit("EV SUMMARY counter domain fail")
    else:
        if (got_v, got_o, got_l) != (0, 0, 0):
            raise SystemExit("EV RAW counters must be zero")
    _st2, _body2, pvd2 = _d3s1.extract_envelope(val)
    if pvd2 != anchor_pvd:
        raise SystemExit("EV header PVD must equal ANCHOR VALUE_DIGEST")
    return key, val


def _mode23_material_rows(
    *, include_state: bool, nontrivial: bool
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes, int]:
    """Build profile + ANCHOR [+ STATE] + EVIDENCE slots for Mode23.

    Success (include_state=True, nontrivial=True): slots 0..L PRESENT with
    SUMMARY valid=2 overflow=1 late=1 and M=1 RAW MATERIALIZED (late_material=1)
    so equation valid == M + overflow and late coherence hold without false
    late equality (docs/17 §18.13.12.1 Mode23). L from accepted profile (=3).

    Orphan (include_state=False): one SUMMARY empty secondary without STATE.

    Returns (rows_sorted, named_rows, anchor_pvd, L).
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    anchor = cat[D1_ANCHOR_ID]
    state = cat[D1_STATE_ID]
    sum_mat = cat[D1_EV_SUM_MAT_ID]
    sum_empty = cat[D1_EV_SUM_EMPTY_ID]
    raw_unused = cat[D1_EV_RAW_UNUSED_ID]
    raw_mat = cat[D1_EV_RAW_MAT_ID]

    binding = _d3s1.default_binding_fields()
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(
            f"Mode23 accepted L pin drift: binding L={L} != {MODE23_ACCEPTED_L}"
        )

    anchor_key = from_hex(anchor["key_hex"])
    anchor_val = from_hex(anchor["value_hex"])
    anchor_pvd = _d3s1.value_digest(anchor_val)

    named: Dict[str, Dict[str, str]] = {
        "anchor": {
            "key_hex": hex_of(anchor_key),
            "value_hex": hex_of(anchor_val),
        }
    }
    domain_rows: List[Dict[str, str]] = [named["anchor"]]

    if include_state:
        state_key = from_hex(state["key_hex"])
        state_val = from_hex(state["value_hex"])
        named["state"] = {
            "key_hex": hex_of(state_key),
            "value_hex": hex_of(state_val),
        }
        domain_rows.append(named["state"])

    if nontrivial and include_state:
        # SUMMARY@0: valid=2, overflow=1, late=1, late_material=1
        # RAW slot1 MATERIALIZED late_material=1 → M=1, observed_c=1
        # RAW slots 2..L UNUSED
        # Equation: 2 == 1 + 1; late: 1 <= 1 <= 2; overflow <= valid.
        sum_tmpl = from_hex(sum_mat["value_hex"])
        k0, v0 = _build_tx_evidence_value(
            template_value=sum_tmpl,
            slot=0,
            cell_kind=EV_CELL_KIND_SUMMARY,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            valid=2,
            overflow=1,
            late_count=1,
            late_material=1,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot0"] = {"key_hex": hex_of(k0), "value_hex": hex_of(v0)}
        domain_rows.append(named["ev_slot0"])

        mat_tmpl = from_hex(raw_mat["value_hex"])
        k1, v1 = _build_tx_evidence_value(
            template_value=mat_tmpl,
            slot=1,
            cell_kind=EV_CELL_KIND_RAW,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            late_material=1,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot1"] = {"key_hex": hex_of(k1), "value_hex": hex_of(v1)}
        domain_rows.append(named["ev_slot1"])

        unused_tmpl = from_hex(raw_unused["value_hex"])
        for slot in range(2, L + 1):
            ks, vs = _build_tx_evidence_value(
                template_value=unused_tmpl,
                slot=slot,
                cell_kind=EV_CELL_KIND_RAW,
                cell_state=EV_CELL_STATE_UNUSED,
                late_material=0,
                anchor_pvd=anchor_pvd,
            )
            name = f"ev_slot{slot}"
            named[name] = {"key_hex": hex_of(ks), "value_hex": hex_of(vs)}
            domain_rows.append(named[name])
    else:
        # Orphan path: single SUMMARY empty secondary (slot0) is enough for
        # BIND_EVIDENCE to note carrier ABSENT (matches Mode24/25/26 sibling
        # minimal secondary band).
        sum_tmpl = from_hex(sum_empty["value_hex"])
        k0, v0 = _build_tx_evidence_value(
            template_value=sum_tmpl,
            slot=0,
            cell_kind=EV_CELL_KIND_SUMMARY,
            cell_state=EV_CELL_STATE_MATERIALIZED,
            valid=0,
            overflow=0,
            late_count=0,
            late_material=0,
            anchor_pvd=anchor_pvd,
        )
        named["ev_slot0"] = {"key_hex": hex_of(k0), "value_hex": hex_of(v0)}
        domain_rows.append(named["ev_slot0"])

    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    return all_rows, named, anchor_pvd, L


def run_d3s2_mode23_tx_state_slots_equation_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode23 known-slot success: STATE + ANCHOR + slots 0..L COMPLETE.

    Independent reference model (docs/17 §18.13.4/.5/.7/.9/.12.1):
      begin → baseline once → SELECT finds TRANSACTION_STATE → FOCUS
      known-slot exact_get matrix slots 0..L (B6k; not stream EXHAUSTED) →
      equation valid==M+overflow + late coherence → SELECT empty →
      BIND_EVIDENCE (STATE carrier subject + true ANCHOR PVD/raw) for each
      EVIDENCE secondary → COMPLETE → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+FOCUS matrix; 3 SELECT empty→BIND; 4 BIND COMPLETE.
    """
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"mode23 success L pin fail: {L}")
    n_cells = L + 1
    n_ok = len(rows)
    # 17 profile + ANCHOR + STATE + (L+1) EVIDENCE = 17 + 2 + 4 = 23
    if n_ok != 17 + 2 + n_cells:
        raise SystemExit(
            f"mode23 success expects {17 + 2 + n_cells} rows "
            f"(17+ANCHOR+STATE+L+1), got {n_ok}"
        )
    n_drive = 4
    n_open = 4

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT+FOCUS known-slot: full residual walk + (L+1) presence gets
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.extend(["get"] * n_cells)
    port_trace.append("iter_close")
    # drive3 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 BIND_EVIDENCE: each EVIDENCE → STATE carrier + ANCHOR primary
    # Lex order: profile + ANCHOR(0x20) + STATE(0x22) + EVIDENCE(0x32)×(L+1)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # STATE
    for _ in range(n_cells):
        port_trace.append("iter_next")  # EVIDENCE secondary
        port_trace.append("get")  # carrier companion TRANSACTION_STATE
        port_trace.append("get")  # true primary ANCHOR
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2 + n_cells,  # ANCHOR+STATE+EV×(L+1)
        "ok_row_count": n_ok,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # FOCUS matrix (L+1) + BIND 2 peer gets per EVIDENCE cell
        "d3_peer_get_count": n_cells + (n_cells * 2),
        "d3_mode_applicable_count": n_cells,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_EVIDENCE,
        "binding_complete_mask": MASK_EVIDENCE,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode23 success rows must be key-sorted")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode23 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode23_evidence_without_state_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode23: EVIDENCE + ANCHOR, no STATE → empty-carrier SELECT then
    BIND_EVIDENCE carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary ANCHOR get must not run. abort; mutation_calls=0.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode23 evidence-without-state expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until first EVIDENCE; carrier STATE ABSENT → note stop
    # (primary ANCHOR get must not run after carrier ABSENT)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ANCHOR
    port_trace.append("iter_next")  # EVIDENCE
    port_trace.append("get")  # carrier companion STATE → ABSENT
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # ANCHOR + EVIDENCE
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # one EVIDENCE BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected



# ---------------------------------------------------------------------------
# Mode22 material (D1 authority + independent Python encoder/parser)
# ---------------------------------------------------------------------------


def _parse_rc_app_attempt_and_delivery(value: bytes) -> Tuple[int, bytes, bytes]:
    """Independent RESULT_CACHE parse: (app_attempt, delivery_raw80, txn16)."""
    st, body, _ = _d3s1.extract_envelope(value)
    if st != 0x41 or len(body) != 378:
        raise SystemExit("RC parse: not a typed RESULT_CACHE body")
    raw_len = int.from_bytes(body[0:2], "big")
    if raw_len != DLV_KEY_CONTENTS_BYTES:
        raise SystemExit(f"RC delivery raw length {raw_len} != 80")
    delivery_raw = bytes(body[2 : 2 + DLV_KEY_CONTENTS_BYTES])
    txn = bytes(body[114:130])  # after RAW16(82) + kd(32)
    app_attempt = struct.unpack_from(">I", body, RC_APP_ATTEMPT_BODY_OFF)[0]
    return int(app_attempt), delivery_raw, txn


def _parse_attempt_dlv(
    value: bytes,
) -> Tuple[int, bytes, bytes, bytes, int, bytes, bytes]:
    """Independent ATTEMPT parse for DELIVERY-owned rows.

    Returns (owner_kind, owner_raw, attempt_id, txn16, attempt_kind,
    primary_key_digest, header_pvd).
    """
    st, body, pvd = _d3s1.extract_envelope(value)
    if st != 0x31 or len(body) != ATT_BODY_LEN:
        raise SystemExit("ATT parse: not a typed ATTEMPT body 322")
    attempt_id = bytes(body[0:16])
    owner_kind = struct.unpack_from(">H", body, 16)[0]
    raw_len = struct.unpack_from(">H", body, 20)[0]
    if raw_len > 80:
        raise SystemExit(f"ATT owner raw length {raw_len} > 80")
    owner_raw = bytes(body[22 : 22 + raw_len])
    o = 22 + raw_len
    pkd = bytes(body[o : o + 32])
    o += 32
    txn = bytes(body[o : o + 16])
    o += 16
    o += 32  # target_digest
    attempt_kind = struct.unpack_from(">H", body, o)[0]
    return (
        int(owner_kind),
        owner_raw,
        attempt_id,
        txn,
        int(attempt_kind),
        pkd,
        bytes(pvd),
    )


def _attempt_composite_key(
    owner_kind: int, owner_raw: bytes, attempt_id: bytes
) -> bytes:
    """Independent SHA256_COMPOSITE complete key for ATTEMPT (0x31)."""
    if len(attempt_id) != 16:
        raise SystemExit("attempt_id must be exact 16")
    components = (
        _d3s1.be16(int(owner_kind))
        + _d3s1.raw16(owner_raw)
        + attempt_id
    )
    return _d3s1.bkey(6, 0x31, 5, _d3s1.composite(0x31, components))


def _mode22_material_rows(
    *, include_rc: bool
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, str]], bytes]:
    """Build profile + DELIVERY + ATTEMPT [+ RESULT_CACHE] with PVD patch.

    Success (include_rc=True): APPLICATION_FIRST RC app=1 + 1 DLV-owned
    COMMAND ATTEMPT + true DELIVERY. Orphan: ATTEMPT + DELIVERY, no RC.

    Returns (rows_sorted, named_rows, delivery_value_digest).
    Independent of production C: D1 authority rows + stdlib body/PVD/CRC.
    """
    _assert_d1_authority_pin()
    cat = _d1_catalog()
    dlv = cat[D1_DLV_ID]
    att = cat[D1_ATT_DLV_ID]
    rc = cat[D1_RC_ID]

    dlv_key = from_hex(dlv["key_hex"])
    dlv_val = from_hex(dlv["value_hex"])
    dlv_pvd = _d3s1.value_digest(dlv_val)
    dlv_draw, dlv_txn, dlv_primary_id = _parse_delivery_raw_and_primary(dlv_val)
    if dlv_primary_id != dlv_val[24:40]:
        raise SystemExit("DELIVERY primary_id self-check fail")
    if len(dlv_key) != 45 or dlv_key[8] != 6 or dlv_key[9] != 0x40:
        raise SystemExit("DELIVERY key framing unexpected")
    dlv_key_digest = _d3s1.key_digest(dlv_key)

    att_key = from_hex(att["key_hex"])
    att_val = _d3s1.patch_pvd(from_hex(att["value_hex"]), dlv_pvd)
    (
        att_okind,
        att_oraw,
        att_id,
        att_txn,
        att_kind,
        att_pkd,
        att_pvd,
    ) = _parse_attempt_dlv(att_val)
    if att_okind != ATT_OWNER_KIND_DELIVERY:
        raise SystemExit(
            f"Mode22 requires DELIVERY-owned ATTEMPT, got owner_kind={att_okind}"
        )
    if att_kind != ATT_KIND_COMMAND:
        raise SystemExit(
            f"Mode22 success prefers COMMAND attempt_kind=1, got {att_kind}"
        )
    if att_oraw != dlv_draw:
        raise SystemExit("Mode22 ATT owner_raw must match DELIVERY raw")
    if att_txn != dlv_txn:
        raise SystemExit("Mode22 ATT transaction_id must match DELIVERY txn")
    if att_pkd != dlv_key_digest:
        raise SystemExit(
            "Mode22 ATT primary_key_digest must equal KEY_DIGEST(DELIVERY key)"
        )
    if att_pvd != dlv_pvd:
        raise SystemExit(
            "Mode22 ATT header PVD must equal DELIVERY VALUE_DIGEST"
        )
    if _d3s1.domain_value_framing(att_val) != "current":
        raise SystemExit("Mode22 ATT envelope framing not current after PVD patch")
    rebuilt_att_key = _attempt_composite_key(att_okind, att_oraw, att_id)
    if rebuilt_att_key != att_key:
        raise SystemExit("Mode22 ATT complete key rebuild mismatch")

    named: Dict[str, Dict[str, str]] = {
        "delivery": {"key_hex": hex_of(dlv_key), "value_hex": hex_of(dlv_val)},
        "att": {"key_hex": hex_of(att_key), "value_hex": hex_of(att_val)},
    }
    domain_rows: List[Dict[str, str]] = [
        named["delivery"],
        named["att"],
    ]
    if include_rc:
        rc_key = from_hex(rc["key_hex"])
        # Keep D1 app_attempt=1; only patch PVD→DELIVERY for same-txn truth.
        rc_val = _d3s1.patch_pvd(from_hex(rc["value_hex"]), dlv_pvd)
        app_n, rc_draw, rc_txn = _parse_rc_app_attempt_and_delivery(rc_val)
        if app_n != 1:
            raise SystemExit(
                f"Mode22 RC application_attempt_count must be 1, got {app_n}"
            )
        if rc_draw != dlv_draw:
            raise SystemExit("Mode22 RC delivery_raw must match DELIVERY raw")
        if rc_txn != dlv_txn:
            raise SystemExit("Mode22 RC transaction_id must match DELIVERY txn")
        _st_rc, _body_rc, rc_pvd = _d3s1.extract_envelope(rc_val)
        if rc_pvd != dlv_pvd:
            raise SystemExit(
                "Mode22 RC header PVD must equal DELIVERY VALUE_DIGEST"
            )
        if _d3s1.domain_value_framing(rc_val) != "current":
            raise SystemExit(
                "Mode22 RC envelope framing not current after PVD patch"
            )
        named["rc"] = {
            "key_hex": hex_of(rc_key),
            "value_hex": hex_of(rc_val),
        }
        domain_rows.append(named["rc"])

    binding = _d3s1.default_binding_fields()
    profile = _d3s1.encode_all_profile_rows(binding)
    all_rows = list(profile) + list(domain_rows)
    all_rows = sorted(all_rows, key=lambda r: from_hex(r["key_hex"]))
    # SHA256_COMPOSITE ATTEMPT must appear in complete-key lex order among rows.
    att_pos = [
        i
        for i, r in enumerate(all_rows)
        if from_hex(r["key_hex"]) == att_key
    ]
    if len(att_pos) != 1:
        raise SystemExit("Mode22 ATTEMPT row missing after sort")
    return all_rows, named, dlv_pvd


def run_d3s2_mode22_rc_app1_attempt_success(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22 stream success: RC app=1 + DLV-owned ATTEMPT + true DELIVERY.

    Independent reference model (docs/17 §18.13.2/.4/.7/.8/.9/.12.1):
      begin → baseline once → SELECT finds RESULT_CACHE → CANCEL_STATE +
      CLEANUP_PLAN setup gets (ABSENT) → reopen FOCUS_ATTEMPT stream
      (H2 on true EXHAUSTED only; observed app=1 cancel=0 C=0) → SELECT
      empty → BIND_ATTEMPT (RC carrier subject + true DELIVERY PVD/raw +
      ATTEMPT_ID_INDEX ABSENT peer; no FOCUS_INDEX/BIND_INDEX) → COMPLETE
      → finalize adopt. mutation_calls=0.

    Drive chunks (same READ_ONLY txn; zero-prefix sequential reopen):
      1 BASELINE; 2 SELECT+setup gets+reopen FOCUS; 3 FOCUS stream H2;
      4 SELECT empty→BIND; 5 BIND COMPLETE.
    """
    n_ok = len(rows)
    if n_ok != 20:
        raise SystemExit(f"mode22 success expects 20 rows (17+3), got {n_ok}")
    n_drive = 5
    n_open = 5

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT carrier: full residual walk with CANCEL + CLEANUP gets
    # at RESULT_CACHE install (lex: profile + ATT + DLV + RC).
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE carrier install
    port_trace.append("get")  # CANCEL_STATE companion (ABSENT → cancel=0)
    port_trace.append("get")  # CLEANUP_PLAN gate (ABSENT → ordinary counts)
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")
    # drive3 FOCUS_ATTEMPT stream (0 exact_get per secondary; H2 on EXHAUSTED)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive4 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive5 BIND_ATTEMPT: carrier RC + true DELIVERY + INDEX ABSENT (strict)
    # Order: 17 profile + ATTEMPT(next+3 gets) + DELIVERY + RESULT_CACHE + NF
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ATTEMPT secondary
    port_trace.append("get")  # carrier companion RESULT_CACHE
    port_trace.append("get")  # true primary DELIVERY
    port_trace.append("get")  # pair peer ATTEMPT_ID_INDEX → ABSENT OK
    port_trace.append("iter_next")  # DELIVERY
    port_trace.append("iter_next")  # RESULT_CACHE
    port_trace.append("iter_next")  # NOT_FOUND
    port_trace.append("iter_close")  # finalize cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 3,  # DELIVERY + ATTEMPT + RESULT_CACHE
        "ok_row_count": 20,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 0,
        "sticky_primary": "",
        # SELECT setup 2 + BIND 3 peer exact_gets (FOCUS stream uses 0)
        "d3_peer_get_count": 5,
        "d3_mode_applicable_count": 1,  # one DELIVERY-owned ATTEMPT BIND
        "phase": PHASE_COMPLETE,
        "count_complete_mask": MASK_ATTEMPT,  # bit0 only; C lane unused
        "binding_complete_mask": MASK_ATTEMPT,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }
    if rows != sorted(rows, key=lambda r: from_hex(r["key_hex"])):
        raise SystemExit("mode22 success rows must be key-sorted")
    # No ATTEMPT_ID_INDEX rows in success material (INDEX expect 0).
    for r in rows:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("mode22 success must not include ATTEMPT_ID_INDEX")
    encoded = _d3s1.encode_all_profile_rows(binding)
    prof = [r for r in rows if len(from_hex(r["key_hex"])) <= 10]
    if prof != encoded:
        if rows[:17] != encoded and prof != encoded:
            raise SystemExit("mode22 success profile encoding mismatch")
    return calls, expected


def run_d3s2_mode22_att_without_rc_corrupt(
    binding: Dict[str, Any], rows: List[Dict[str, str]]
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Mode22: DLV-owned ATTEMPT + DELIVERY, no RESULT_CACHE → empty-carrier
    SELECT then BIND_ATTEMPT carrier exact_get ABSENT → note_terminal_corrupt
    STORAGE_CORRUPT. Primary DELIVERY get and INDEX ABSENT probe must not run.
    abort; mutation_calls=0. Port failure is not this path.
    """
    n_ok = len(rows)
    if n_ok != 19:
        raise SystemExit(
            f"mode22 att-without-rc expects 19 rows (17+2), got {n_ok}"
        )
    n_drive = 3
    n_open = 3

    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"},
        {
            "op": "d3s2_drive",
            "row_budget": 256,
            "expected_status": "STORAGE_CORRUPT",
        },
        {"op": "abort", "expected_status": "STORAGE_CORRUPT"},
    ]

    walk = _walk_trace_segment(n_ok)
    port_trace: List[str] = _begin_profile_port_prefix()
    # drive1 BASELINE
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive2 SELECT empty → BIND entry reopen
    port_trace.append("iter_open:prefix0")
    port_trace.extend(walk)
    port_trace.append("iter_close")
    # drive3 BIND: walk until ATTEMPT; carrier RC ABSENT → note stop
    # (primary DELIVERY get and INDEX ABSENT probe must not run)
    port_trace.append("iter_open:prefix0")
    port_trace.extend(["iter_next"] * 17)  # profile
    port_trace.append("iter_next")  # ATTEMPT
    port_trace.append("get")  # carrier companion RESULT_CACHE → ABSENT
    port_trace.append("iter_close")  # abort cleanup
    port_trace.append("rollback")

    expected: Dict[str, Any] = {
        "final_status": "STORAGE_CORRUPT",
        "adopted": 0,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 2,  # DELIVERY + ATTEMPT
        "ok_row_count": 19,
        "profile_exact_active": 1,
        "profile_mismatch": 0,
        "future_profile_candidate": 0,
        "profile_get_present_mask": 0x1FFFF,
        "family14_iter_seen_mask": 0x1FFFF,
        "reopen_required": 0,
        "close_count": 0,
        "mutation_calls": 0,
        "iter_open_count": n_open,
        "port_trace": port_trace,
        "has_sticky_primary": 1,
        "sticky_primary": "STORAGE_CORRUPT",
        "d3_peer_get_count": 1,  # sole carrier ABSENT get before note
        "d3_mode_applicable_count": 1,  # one ATTEMPT BIND secondary
        "phase": PHASE_FAILED,
        "count_complete_mask": 0,  # empty-carrier: no FOCUS close
        "binding_complete_mask": 0,  # BIND did not complete
        "flags": FLAG_BASELINE_DONE | FLAG_BIND_PHASE_ACTIVE,
    }
    _ = binding
    return calls, expected


def build_d3s2_mode22_slice_vectors() -> List[Dict[str, Any]]:
    """Mode22 append-only slice (2 vectors) after the frozen 108-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) RC app=1 + DLV-owned COMMAND ATTEMPT + true DELIVERY full success
    rows_a, named_a, _pvd_a = _mode22_material_rows(include_rc=True)
    app_n, rc_draw, _rc_txn = _parse_rc_app_attempt_and_delivery(
        from_hex(named_a["rc"]["value_hex"])
    )
    (
        att_okind,
        att_oraw,
        _aid,
        _atxn,
        att_kind,
        att_pkd,
        _apvd,
    ) = _parse_attempt_dlv(from_hex(named_a["att"]["value_hex"]))
    dlv_draw, _dlv_txn, _pid = _parse_delivery_raw_and_primary(
        from_hex(named_a["delivery"]["value_hex"])
    )
    dlv_key_digest = _d3s1.key_digest(from_hex(named_a["delivery"]["key_hex"]))
    if app_n != 1 or att_kind != ATT_KIND_COMMAND:
        raise SystemExit(
            f"Mode22 success must declare app=1 COMMAND, got app={app_n} "
            f"kind={att_kind}"
        )
    if att_okind != ATT_OWNER_KIND_DELIVERY:
        raise SystemExit("Mode22 success ATTEMPT must be DELIVERY-owned")
    if not (rc_draw == att_oraw == dlv_draw):
        raise SystemExit("Mode22 success delivery raw identity mismatch")
    if att_pkd != dlv_key_digest:
        raise SystemExit("Mode22 success ATT primary_key_digest pin fail")
    # INDEX expect 0: no 0x34 rows.
    for r in rows_a:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("Mode22 success must not ship ATTEMPT_ID_INDEX")
    calls_a, exp_a = run_d3s2_mode22_rc_app1_attempt_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M22_RC_APP1_ATT_DLV_OK",
            "kind": "mode22_rc_app1_dlv_attempt_delivery_ok",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_RC_ID, D1_ATT_DLV_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_a["rc"],
                expect_presence="PRESENT",
                note=(
                    "Mode22 carrier RESULT_CACHE application_attempt_count=1 "
                    "(APPLICATION_FIRST; PVD→DELIVERY VALUE_DIGEST)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_DLV_ID,
                row=named_a["delivery"],
                expect_presence="PRESENT",
                note="true primary DELIVERY for ATTEMPT BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ATT_DLV_ID,
                    row=named_a["att"],
                    expect_presence="PRESENT",
                    note=(
                        "DELIVERY-owned COMMAND ATTEMPT secondary; "
                        "PVD→DELIVERY; INDEX ABSENT peer"
                    ),
                )
            ],
            "notes": (
                "Mode22 FOCUS stream + BIND_ATTEMPT success: live "
                "RESULT_CACHE declares application_attempt_count=1 "
                "(APPLICATION_FIRST), one DELIVERY-owned COMMAND ATTEMPT "
                "same delivery raw, true DELIVERY primary. Single "
                "READ_ONLY txn; baseline once; sequential zero-prefix "
                "reopen; SELECT installs carrier with CANCEL_STATE + "
                "CLEANUP_PLAN setup gets (ABSENT); FOCUS_ATTEMPT stream "
                "closes only on true iterator EXHAUSTED (H2; observed "
                "app=1 cancel=0 C=0 MBZ); count bit0; empty SELECT then "
                "BIND proves RESULT_CACHE carrier subject + DELIVERY "
                "PVD/raw + ATTEMPT_ID_INDEX ABSENT peer (no FOCUS_INDEX / "
                "no BIND_INDEX); COMPLETE; mutation_calls=0. "
                "SHA256_COMPOSITE ATTEMPT complete-key lex sorted. D1 "
                "authority rows patched via independent Python only."
            ),
            "ownership": OWNERSHIP_MODE22,
            "expected": exp_a,
        }
    )

    # B) ATTEMPT + DELIVERY, RC absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode22_material_rows(include_rc=False)
    calls_b, exp_b = run_d3s2_mode22_att_without_rc_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M22_ATT_WITHOUT_RC_CARRIER_ABSENT",
            "kind": "mode22_att_without_rc_carrier_absent_corrupt",
            "mode": 22,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_ATT_DLV_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ATT_DLV_ID,
                row=named_b["att"],
                expect_presence="PRESENT",
                note=(
                    "DELIVERY-owned ATTEMPT secondary without same-tx "
                    "RESULT_CACHE carrier"
                ),
            ),
            "peer_ref": _d3s1.none_ref(
                "RESULT_CACHE carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary/INDEX gets must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_b["delivery"],
                    expect_presence="PRESENT",
                    note=(
                        "true DELIVERY present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode22 empty-carrier SELECT (no RESULT_CACHE) then "
                "BIND_ATTEMPT on live DELIVERY-owned ATTEMPT: carrier "
                "companion exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary DELIVERY "
                "get and INDEX ABSENT probe must not proceed after carrier "
                "ABSENT. Not a Port failure path. abort; mutation_calls=0. "
                "Independent reference model — production C not used for "
                "expected."
            ),
            "ownership": OWNERSHIP_MODE22,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE22_SLICE_COUNT:
        raise SystemExit("mode22 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE22_KINDS:
        raise SystemExit(f"mode22 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_smoke_vectors() -> List[Dict[str, Any]]:
    """First 6-session Mode21..26 empty-carrier product smoke (frozen pin)."""
    binding = _d3s1.default_binding_fields()
    rows = _d3s1.encode_all_profile_rows(binding)
    vectors: List[Dict[str, Any]] = []
    for mode in range(21, 27):
        kind = f"mode{mode}_empty_carrier_empty_secondary_ok"
        vid = f"D3S2_M{mode}_EMPTY_CARRIER_EMPTY_SECONDARY"
        calls, expected = run_d3s2_empty_carrier_case(mode, binding, rows)
        vec: Dict[str, Any] = {
            "id": vid,
            "kind": kind,
            "mode": mode,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows),
            "alt_rows": {},
            "faults": [],
            "calls": calls,
            "d1_refs": [],
            "source_ref": _d3s1.none_ref(
                "empty-carrier: no source secondary"
            ),
            "peer_ref": _d3s1.none_ref("empty-carrier: no peer get"),
            "row_refs": [],
            "notes": (
                f"D3-S2 product smoke Mode{mode}: empty-carrier + empty-secondary "
                f"success session. Single begin_profiled_d3s2; one READ_ONLY txn; "
                f"baseline once; sequential zero-prefix reopen; BIND set({mode}) "
                f"empty walks then COMPLETE; mutation_calls=0. Independent of other "
                f"modes (not a 6-mode single session)."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": expected,
        }
        vectors.append(vec)
    if len(vectors) != D3S2_SMOKE_COUNT:
        raise SystemExit("smoke suffix count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_SMOKE_KINDS:
        raise SystemExit(f"smoke kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode25_slice_vectors() -> List[Dict[str, Any]]:
    """Mode25 append-only slice (2 vectors) after the frozen 100-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) CUM total=1 + RECENT C1 + true ANCHOR full success
    rows_a, named_a, _pvd_a = _mode25_material_rows(include_cum=True, cum_total=1)
    calls_a, exp_a = run_d3s2_mode25_cum_total1_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M25_CUM_T1_REC_S1_ANCHOR_OK",
            "kind": "mode25_cum_total1_recent_slot1_anchor_ok",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_CUM_ID, D1_REC_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_CUM_ID,
                row=named_a["cum"],
                expect_presence="PRESENT",
                note="Mode25 carrier CUM total=1 (body total field patched; PVD→ANCHOR)",
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for CUM/RECENT BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_REC_ID,
                    row=named_a["recent"],
                    expect_presence="PRESENT",
                    note="RECENT cycle1/slot0 companion; PVD→ANCHOR",
                )
            ],
            "notes": (
                "Mode25 FOCUS known-slot + BIND_RETRY success: CUMULATIVE "
                "total_completed_cycle_count=1 carrier, RECENT C1 (slot0) "
                "companion, true ANCHOR primary. Single READ_ONLY txn; baseline "
                "once; sequential zero-prefix reopen; CUM self-carrier; RECENT "
                "carrier companion; both rows primary PVD/raw; COMPLETE; "
                "mutation_calls=0. D1 authority rows patched via independent "
                "Python encoder/parser only."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_a,
        }
    )

    # B) RECENT + ANCHOR, CUM absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode25_material_rows(
        include_cum=False, cum_total=0
    )
    calls_b, exp_b = run_d3s2_mode25_recent_without_cum_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M25_REC_WITHOUT_CUM_CARRIER_ABSENT",
            "kind": "mode25_recent_without_cum_carrier_absent_corrupt",
            "mode": 25,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_REC_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_REC_ID,
                row=named_b["recent"],
                expect_presence="PRESENT",
                note="RECENT secondary without same-tx CUM carrier",
            ),
            "peer_ref": _d3s1.none_ref(
                "CUM carrier companion exact_get ABSENT (real S2 orphan finding)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note="true ANCHOR present but unused after carrier ABSENT note",
                )
            ],
            "notes": (
                "Mode25 empty-carrier SELECT (no CUMULATIVE) then BIND_RETRY on "
                "live RECENT: carrier companion exact_get ABSENT is a real S2 "
                "orphan finding via note_terminal_corrupt → STORAGE_CORRUPT. "
                "Not a Port failure path. abort; mutation_calls=0. Independent "
                "reference model — production C not used for expected."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE25_SLICE_COUNT:
        raise SystemExit("mode25 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE25_KINDS:
        raise SystemExit(f"mode25 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode26_slice_vectors() -> List[Dict[str, Any]]:
    """Mode26 append-only slice (2 vectors) after the frozen 102-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) ES resume=1 + MANAGEMENT RESUME + true ANCHOR full success
    rows_a, named_a, _pvd_a = _mode26_material_rows(
        include_es=True, resume=1, discard=0
    )
    # Fail-closed independent parse of fixture carrier resume/discard.
    es_r, es_d = _parse_es_resume_discard(from_hex(named_a["es"]["value_hex"]))
    if es_r != 1 or es_d != 0:
        raise SystemExit(
            f"Mode26 success ES must declare resume=1 discard=0, got {es_r}/{es_d}"
        )
    calls_a, exp_a = run_d3s2_mode26_es_resume1_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M26_ES_R1_MGMT_RESUME_ANCHOR_OK",
            "kind": "mode26_es_resume1_mgmt_resume_anchor_ok",
            "mode": 26,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_ES_ID, D1_ML_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ES_ID,
                row=named_a["es"],
                expect_presence="PRESENT",
                note=(
                    "Mode26 carrier EVENT_SPOOL successful_resume_count=1 "
                    "discard_committed=0 (body fields patched; PVD→ANCHOR)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for MANAGEMENT BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ML_ID,
                    row=named_a["mgmt"],
                    expect_presence="PRESENT",
                    note="MANAGEMENT RESUME (kind=15) secondary; PVD→ANCHOR",
                )
            ],
            "notes": (
                "Mode26 FOCUS stream + BIND_MANAGEMENT success: live "
                "EVENT_SPOOL declares successful_resume_count=1 + "
                "discard_committed=0, one MANAGEMENT RESUME row same-tx, "
                "true ANCHOR primary. Single READ_ONLY txn; baseline once; "
                "sequential zero-prefix reopen; SELECT carrier then FOCUS "
                "stream closes only on true iterator EXHAUSTED (H2; "
                "observed=1); empty SELECT then BIND proves ES carrier "
                "subject + ANCHOR PVD/raw; COMPLETE; mutation_calls=0. D1 "
                "authority rows patched via independent Python only."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_a,
        }
    )

    # B) MANAGEMENT + ANCHOR, ES absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode26_material_rows(
        include_es=False, resume=0, discard=0
    )
    calls_b, exp_b = run_d3s2_mode26_mgmt_without_es_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M26_MGMT_WITHOUT_ES_CARRIER_ABSENT",
            "kind": "mode26_mgmt_without_es_carrier_absent_corrupt",
            "mode": 26,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_ML_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_ML_ID,
                row=named_b["mgmt"],
                expect_presence="PRESENT",
                note="MANAGEMENT RESUME secondary without same-tx EVENT_SPOOL",
            ),
            "peer_ref": _d3s1.none_ref(
                "EVENT_SPOOL carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary get must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note=(
                        "true ANCHOR present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode26 empty-carrier SELECT (no EVENT_SPOOL) then "
                "BIND_MANAGEMENT on live MANAGEMENT RESUME: carrier "
                "companion exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary ANCHOR get "
                "must not proceed after carrier ABSENT. Not a Port failure "
                "path. abort; mutation_calls=0. Independent reference model "
                "— production C not used for expected."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE26_SLICE_COUNT:
        raise SystemExit("mode26 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE26_KINDS:
        raise SystemExit(f"mode26 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode24_slice_vectors() -> List[Dict[str, Any]]:
    """Mode24 append-only slice (2 vectors) after the frozen 104-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) RC reply_count=1 + RR RECEIPT + true DELIVERY full success
    rows_a, named_a, _pvd_a = _mode24_material_rows(
        include_rc=True, reply_count=1
    )
    rc_count, rc_draw, _rc_txn = _parse_rc_reply_count_and_delivery(
        from_hex(named_a["rc"]["value_hex"])
    )
    rr_kind, rr_draw, _rr_txn = _parse_rr_kind_and_delivery(
        from_hex(named_a["rr"]["value_hex"])
    )
    dlv_draw, _dlv_txn, _pid = _parse_delivery_raw_and_primary(
        from_hex(named_a["delivery"]["value_hex"])
    )
    if rc_count != 1 or rr_kind != RR_KIND_RECEIPT:
        raise SystemExit(
            f"Mode24 success must declare reply_count=1 RECEIPT, got "
            f"rc={rc_count} kind={rr_kind}"
        )
    if not (rc_draw == rr_draw == dlv_draw):
        raise SystemExit("Mode24 success delivery raw identity mismatch")
    calls_a, exp_a = run_d3s2_mode24_rc_reply1_success(binding, rows_a)
    vectors.append(
        {
            "id": "D3S2_M24_RC_RC1_RR_RECEIPT_DLV_OK",
            "kind": "mode24_rc_reply1_receipt_delivery_ok",
            "mode": 24,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [D1_RC_ID, D1_RR_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RC_ID,
                row=named_a["rc"],
                expect_presence="PRESENT",
                note=(
                    "Mode24 carrier RESULT_CACHE reply_count=1 "
                    "(body field patched; PVD→DELIVERY VALUE_DIGEST)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_DLV_ID,
                row=named_a["delivery"],
                expect_presence="PRESENT",
                note="true primary DELIVERY for REVERSE_REPLY BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_RR_ID,
                    row=named_a["rr"],
                    expect_presence="PRESENT",
                    note="REVERSE_REPLY RECEIPT (kind=1) secondary; PVD→DELIVERY",
                )
            ],
            "notes": (
                "Mode24 FOCUS known-kind + BIND_REPLY success: live "
                "RESULT_CACHE declares reply_count=1, one REVERSE_REPLY "
                "RECEIPT (closed kind=1) same delivery raw, true DELIVERY "
                "primary. Single READ_ONLY txn; baseline once; sequential "
                "zero-prefix reopen; FOCUS known-kind exact_get matrix over "
                "closed kinds 1..4 (B6k; not iterator EXHAUSTED); count/"
                "popcount/mask close; empty SELECT then BIND proves "
                "RESULT_CACHE carrier subject + DELIVERY PVD/raw; COMPLETE; "
                "mutation_calls=0. D1 authority rows patched via independent "
                "Python only."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_a,
        }
    )

    # B) RR + DELIVERY, RC absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b = _mode24_material_rows(
        include_rc=False, reply_count=0
    )
    calls_b, exp_b = run_d3s2_mode24_rr_without_rc_corrupt(binding, rows_b)
    vectors.append(
        {
            "id": "D3S2_M24_RR_WITHOUT_RC_CARRIER_ABSENT",
            "kind": "mode24_rr_without_rc_carrier_absent_corrupt",
            "mode": 24,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_RR_ID, D1_DLV_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_RR_ID,
                row=named_b["rr"],
                expect_presence="PRESENT",
                note="REVERSE_REPLY RECEIPT secondary without same-tx RESULT_CACHE",
            ),
            "peer_ref": _d3s1.none_ref(
                "RESULT_CACHE carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary get must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_DLV_ID,
                    row=named_b["delivery"],
                    expect_presence="PRESENT",
                    note=(
                        "true DELIVERY present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode24 empty-carrier SELECT (no RESULT_CACHE) then "
                "BIND_REPLY on live REVERSE_REPLY RECEIPT: carrier companion "
                "exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary DELIVERY "
                "get must not proceed after carrier ABSENT. Not a Port "
                "failure path. abort; mutation_calls=0. Independent "
                "reference model — production C not used for expected."
            ),
            "ownership": OWNERSHIP_DEFAULT,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE24_SLICE_COUNT:
        raise SystemExit("mode24 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE24_KINDS:
        raise SystemExit(f"mode24 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_mode23_slice_vectors() -> List[Dict[str, Any]]:
    """Mode23 append-only slice (2 vectors) after the frozen 106-prefix."""
    binding = _d3s1.default_binding_fields()
    vectors: List[Dict[str, Any]] = []

    # A) STATE + ANCHOR + slots 0..L nontrivial equation full success
    rows_a, named_a, _pvd_a, L_a = _mode23_material_rows(
        include_state=True, nontrivial=True
    )
    if L_a != MODE23_ACCEPTED_L:
        raise SystemExit(f"Mode23 success L must be {MODE23_ACCEPTED_L}, got {L_a}")
    # Fail-closed independent parse of SUMMARY counters and RAW material.
    sum_ck, sum_cs, sum_slot, _own, valid, overflow, late_c, late_m = (
        _parse_tx_evidence_cell(from_hex(named_a["ev_slot0"]["value_hex"]))
    )
    if (
        sum_ck != EV_CELL_KIND_SUMMARY
        or sum_cs != EV_CELL_STATE_MATERIALIZED
        or sum_slot != 0
    ):
        raise SystemExit("Mode23 success SUMMARY shape pin fail")
    if (valid, overflow, late_c, late_m) != (2, 1, 1, 1):
        raise SystemExit(
            f"Mode23 success SUMMARY counters must be valid=2 overflow=1 "
            f"late=1 late_mat=1, got {valid}/{overflow}/{late_c}/{late_m}"
        )
    raw1_ck, raw1_cs, raw1_slot, _o1, _v1, _o1c, _l1, raw1_lm = (
        _parse_tx_evidence_cell(from_hex(named_a["ev_slot1"]["value_hex"]))
    )
    if (
        raw1_ck != EV_CELL_KIND_RAW
        or raw1_cs != EV_CELL_STATE_MATERIALIZED
        or raw1_slot != 1
        or raw1_lm != 1
    ):
        raise SystemExit("Mode23 success RAW slot1 MATERIALIZED late pin fail")
    # Equation + late coherence (docs/17 §18.13.12.1): valid == M + overflow
    # with M=1; observed_c=1 <= declared_c=1 <= declared_a=2; overflow <= valid.
    m_mat = 1
    if valid != m_mat + overflow:
        raise SystemExit("Mode23 success equation valid != M + overflow")
    if not (1 <= late_c <= valid and overflow <= valid):
        raise SystemExit("Mode23 success late/overflow coherence fail")
    calls_a, exp_a = run_d3s2_mode23_tx_state_slots_equation_success(
        binding, rows_a
    )
    vectors.append(
        {
            "id": "D3S2_M23_TX_STATE_SLOTS_L_EQ_ANCHOR_OK",
            "kind": "mode23_tx_state_slots_L_equation_anchor_ok",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_a),
            "alt_rows": {},
            "faults": [],
            "calls": calls_a,
            "d1_refs": [
                D1_STATE_ID,
                D1_ANCHOR_ID,
                D1_EV_SUM_MAT_ID,
                D1_EV_RAW_MAT_ID,
                D1_EV_RAW_UNUSED_ID,
            ],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_STATE_ID,
                row=named_a["state"],
                expect_presence="PRESENT",
                note=(
                    "Mode23 carrier TRANSACTION_STATE retained "
                    "(D1 typed; same txn as EVIDENCE owner raw)"
                ),
            ),
            "peer_ref": _d3s1.d1_ref_from_id(
                D1_ANCHOR_ID,
                row=named_a["anchor"],
                expect_presence="PRESENT",
                note="true primary ANCHOR for EVIDENCE BIND PVD/raw",
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_EV_SUM_MAT_ID,
                    row=named_a["ev_slot0"],
                    expect_presence="PRESENT",
                    note=(
                        "SUMMARY@0 counters valid=2 overflow=1 late=1 "
                        "(body fields patched; PVD→ANCHOR)"
                    ),
                ),
                _d3s1.d1_ref_from_id(
                    D1_EV_RAW_MAT_ID,
                    row=named_a["ev_slot1"],
                    expect_presence="PRESENT",
                    note=(
                        "RAW MATERIALIZED slot1 late_material=1 (M=1); "
                        "PVD→ANCHOR"
                    ),
                ),
            ],
            "notes": (
                "Mode23 FOCUS known-slot + BIND_EVIDENCE success: retained "
                "TRANSACTION_STATE carrier, true ANCHOR primary, EVIDENCE "
                f"slots 0..L (accepted profile L={MODE23_ACCEPTED_L}) all "
                "PRESENT. SUMMARY@0 declares valid_material_count=2, "
                "raw_overflow_count=1, late_evidence_count=1; observed M=1 "
                "RAW MATERIALIZED (slot1 late_material=1) and slots 2..L "
                "RAW UNUSED so equation valid==M+overflow and late "
                "coherence hold without false late equality. Single "
                "READ_ONLY txn; baseline once; sequential zero-prefix "
                "reopen; FOCUS known-slot exact_get matrix 0..L (B6k); "
                "count bit2; BIND proves STATE carrier subject + ANCHOR "
                "PVD/raw for each EVIDENCE secondary; COMPLETE; "
                "mutation_calls=0. SHA256_COMPOSITE rows complete-key lex "
                "sorted. D1 authority rows patched via independent Python "
                "only."
            ),
            "ownership": OWNERSHIP_MODE23,
            "expected": exp_a,
        }
    )

    # B) EVIDENCE + ANCHOR, STATE absent → BIND carrier ABSENT note corrupt
    rows_b, named_b, _pvd_b, _L_b = _mode23_material_rows(
        include_state=False, nontrivial=False
    )
    calls_b, exp_b = run_d3s2_mode23_evidence_without_state_corrupt(
        binding, rows_b
    )
    vectors.append(
        {
            "id": "D3S2_M23_EV_WITHOUT_STATE_CARRIER_ABSENT",
            "kind": "mode23_evidence_without_state_carrier_absent_corrupt",
            "mode": 23,
            "candidate_binding": copy.deepcopy(binding),
            "rows": copy.deepcopy(rows_b),
            "alt_rows": {},
            "faults": [],
            "calls": calls_b,
            "d1_refs": [D1_EV_SUM_EMPTY_ID, D1_ANCHOR_ID],
            "source_ref": _d3s1.d1_ref_from_id(
                D1_EV_SUM_EMPTY_ID,
                row=named_b["ev_slot0"],
                expect_presence="PRESENT",
                note=(
                    "EVIDENCE_CELL SUMMARY secondary without same-tx "
                    "TRANSACTION_STATE carrier"
                ),
            ),
            "peer_ref": _d3s1.none_ref(
                "TRANSACTION_STATE carrier companion exact_get ABSENT "
                "(real S2 orphan finding; primary get must not run)"
            ),
            "row_refs": [
                _d3s1.d1_ref_from_id(
                    D1_ANCHOR_ID,
                    row=named_b["anchor"],
                    expect_presence="PRESENT",
                    note=(
                        "true ANCHOR present but unused after carrier ABSENT note"
                    ),
                )
            ],
            "notes": (
                "Mode23 empty-carrier SELECT (no TRANSACTION_STATE) then "
                "BIND_EVIDENCE on live EVIDENCE_CELL: carrier companion "
                "exact_get ABSENT is a real S2 orphan finding via "
                "note_terminal_corrupt → STORAGE_CORRUPT. Primary ANCHOR "
                "get must not proceed after carrier ABSENT. Not a Port "
                "failure path. abort; mutation_calls=0. Independent "
                "reference model — production C not used for expected."
            ),
            "ownership": OWNERSHIP_MODE23,
            "expected": exp_b,
        }
    )

    if len(vectors) != D3S2_MODE23_SLICE_COUNT:
        raise SystemExit("mode23 slice count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_MODE23_KINDS:
        raise SystemExit(f"mode23 kinds inventory mismatch: {kinds}")
    return vectors


def build_d3s2_suffix_vectors() -> List[Dict[str, Any]]:
    vectors = (
        build_d3s2_smoke_vectors()
        + build_d3s2_mode25_slice_vectors()
        + build_d3s2_mode26_slice_vectors()
        + build_d3s2_mode24_slice_vectors()
        + build_d3s2_mode23_slice_vectors()
        + build_d3s2_mode22_slice_vectors()
    )
    if len(vectors) != D3S2_SUFFIX_COUNT:
        raise SystemExit("suffix count drift")
    kinds = {v["kind"] for v in vectors}
    if kinds != D3S2_REQUIRED_KINDS:
        raise SystemExit(f"suffix kinds inventory mismatch: {kinds}")
    return vectors


def freeze_d3s1_prefix() -> Dict[str, Any]:
    """Rebuild the frozen 94-vector D3-S1 document via the independent generator."""
    doc = _d3s1.build_document()
    if doc.get("format") != D3S1_FORMAT:
        raise SystemExit(f"d3s1 format drift: {doc.get('format')}")
    if int(doc.get("vector_count", -1)) != D3S1_PREFIX_COUNT:
        raise SystemExit(
            f"d3s1 vector_count {doc.get('vector_count')} != {D3S1_PREFIX_COUNT}"
        )
    if len(doc["vectors"]) != D3S1_PREFIX_COUNT:
        raise SystemExit("d3s1 vectors length drift")
    if doc.get("content_sha256") != D3S1_PREFIX_CONTENT_SHA256:
        raise SystemExit(
            "d3s1 content_sha256 pin mismatch vs frozen prefix "
            f"(got {doc.get('content_sha256')})"
        )
    if doc.get("prior_fingerprint_prefix_hash") != D3S1_PREFIX_FINGERPRINT_HASH:
        raise SystemExit("d3s1 prior_fingerprint_prefix_hash pin mismatch")
    return doc


def _fingerprint_entries_for(
    d3s1_vectors: List[Dict[str, Any]], d3s2_vectors: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    for v in d3s1_vectors:
        entries.append(
            {
                "id": v["id"],
                "kind": v["kind"],
                "mode": v["mode"],
                "fingerprint": d3s1_vector_fingerprint(v),
            }
        )
    for v in d3s2_vectors:
        entries.append(
            {
                "id": v["id"],
                "kind": v["kind"],
                "mode": v["mode"],
                "fingerprint": d3s2_vector_fingerprint(v),
            }
        )
    return entries


def _chain_hash(entries: List[Dict[str, Any]]) -> str:
    material = "".join(e["fingerprint"] for e in entries).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def freeze_d3s2_100_prefix(
    d3s1_vectors: List[Dict[str, Any]], smoke_vectors: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Fail-closed freeze of the prior 100-vector main artifact identity."""
    if len(d3s1_vectors) != D3S1_PREFIX_COUNT:
        raise SystemExit("100-prefix d3s1 length drift")
    if len(smoke_vectors) != D3S2_SMOKE_COUNT:
        raise SystemExit("100-prefix smoke length drift")
    entries = _fingerprint_entries_for(d3s1_vectors, smoke_vectors)
    chain = _chain_hash(entries)
    if chain != D3S2_100_FINGERPRINT_HASH:
        raise SystemExit(
            "100-prefix fingerprint chain drift vs frozen main pin "
            f"(got {chain})"
        )
    # Rebuild the historical 100-vector document content hash (scope of that
    # release used the prior SCOPE text; pin content_sha256 of the on-disk
    # prior main artifact by recomputing fingerprints+vector identity only).
    # Vector id/order/rows/calls/expected are re-checked in check() against
    # the rebuilt smoke+d3s1 material; chain pin above is the strong freeze.
    return entries


def build_document() -> Dict[str, Any]:
    prefix_doc = freeze_d3s1_prefix()
    prefix_vectors = prefix_doc["vectors"]
    smoke_vectors = build_d3s2_smoke_vectors()
    mode25_vectors = build_d3s2_mode25_slice_vectors()
    mode26_vectors = build_d3s2_mode26_slice_vectors()
    mode24_vectors = build_d3s2_mode24_slice_vectors()
    mode23_vectors = build_d3s2_mode23_slice_vectors()
    mode22_vectors = build_d3s2_mode22_slice_vectors()
    suffix_vectors = (
        smoke_vectors
        + mode25_vectors
        + mode26_vectors
        + mode24_vectors
        + mode23_vectors
        + mode22_vectors
    )
    if len(suffix_vectors) != D3S2_SUFFIX_COUNT:
        raise SystemExit("suffix assembly count drift")
    vectors = list(prefix_vectors) + list(suffix_vectors)

    # Fail-closed: first 100 == prior main (94 D3S1 + 6 smoke).
    freeze_d3s2_100_prefix(prefix_vectors, smoke_vectors)

    prior_fingerprints = _fingerprint_entries_for(prefix_vectors, suffix_vectors)
    prior_prefix_hash = _chain_hash(prior_fingerprints)

    # Retained D3-S1-only fingerprint chain pin (first 94).
    d3s1_only_hash = _chain_hash(prior_fingerprints[:D3S1_PREFIX_COUNT])
    if d3s1_only_hash != D3S1_PREFIX_FINGERPRINT_HASH:
        raise SystemExit(
            "prefix fingerprint chain drift vs frozen D3-S1 pin "
            f"(got {d3s1_only_hash})"
        )

    # Retained 100-vector chain pin.
    hundred_hash = _chain_hash(prior_fingerprints[:D3S2_100_PREFIX_COUNT])
    if hundred_hash != D3S2_100_FINGERPRINT_HASH:
        raise SystemExit(
            "100-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_hash})"
        )

    # Retained 102-vector chain pin (100 + Mode25 slice).
    hundred_two_hash = _chain_hash(prior_fingerprints[:D3S2_102_PREFIX_COUNT])
    if hundred_two_hash != D3S2_102_FINGERPRINT_HASH:
        raise SystemExit(
            "102-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_two_hash})"
        )

    # Retained 104-vector chain pin (102 + Mode26).
    hundred_four_hash = _chain_hash(prior_fingerprints[:D3S2_104_PREFIX_COUNT])
    if hundred_four_hash != D3S2_104_FINGERPRINT_HASH:
        raise SystemExit(
            "104-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_four_hash})"
        )

    # Retained 106-vector chain pin (104 + Mode24 = prior main).
    hundred_six_hash = _chain_hash(prior_fingerprints[:D3S2_106_PREFIX_COUNT])
    if hundred_six_hash != D3S2_106_FINGERPRINT_HASH:
        raise SystemExit(
            "106-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_six_hash})"
        )

    # Retained 108-vector chain pin (106 + Mode23 = prior main).
    hundred_eight_hash = _chain_hash(prior_fingerprints[:D3S2_108_PREFIX_COUNT])
    if hundred_eight_hash != D3S2_108_FINGERPRINT_HASH:
        raise SystemExit(
            "108-prefix fingerprint chain drift after suffix assembly "
            f"(got {hundred_eight_hash})"
        )

    required_kinds = sorted(
        set(prefix_doc["required_kinds"]) | set(D3S2_REQUIRED_KINDS)
    )

    doc: Dict[str, Any] = {
        "version": VERSION,
        "format": FORMAT,
        "scope": SCOPE,
        "vector_count": len(vectors),
        "d3s1_prefix_count": D3S1_PREFIX_COUNT,
        "d3s2_suffix_count": D3S2_SUFFIX_COUNT,
        "d3s2_100_prefix_count": D3S2_100_PREFIX_COUNT,
        "d3s2_102_prefix_count": D3S2_102_PREFIX_COUNT,
        "d3s2_104_prefix_count": D3S2_104_PREFIX_COUNT,
        "d3s2_106_prefix_count": D3S2_106_PREFIX_COUNT,
        "d3s2_108_prefix_count": D3S2_108_PREFIX_COUNT,
        "required_kinds": required_kinds,
        "workspace": {
            "key_capacity": 255,
            "value_capacity": 4096,
            "previous_key_capacity": 255,
            "ceiling_bytes": CEILING,
            "note": (
                "single 4096 value buffer; D3-S1 context 421/448; D3-S2 context "
                "306/320; no second 4096; mutation_calls always 0; 1 session = 1 mode"
            ),
        },
        "s1_authority": prefix_doc["s1_authority"],
        "s2_authority": prefix_doc["s2_authority"],
        "s3_authority": prefix_doc["s3_authority"],
        "s4_authority": prefix_doc["s4_authority"],
        "s5_authority": prefix_doc["s5_authority"],
        "d1_authority": prefix_doc["d1_authority"],
        "d3s1_prefix_authority": {
            "format": D3S1_FORMAT,
            "vector_count": D3S1_PREFIX_COUNT,
            "content_sha256": D3S1_PREFIX_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S1_PREFIX_FINGERPRINT_HASH,
            "generator": "tools/domain_scan_crossrow_vector_gen.py",
        },
        "d3s2_100_prefix_authority": {
            "vector_count": D3S2_100_PREFIX_COUNT,
            "content_sha256": D3S2_100_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_100_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 Mode21..26 "
                "empty-carrier smoke); Mode25/Mode26/Mode24/Mode23/Mode22 "
                "slice vectors follow"
            ),
        },
        "d3s2_102_prefix_authority": {
            "vector_count": D3S2_102_PREFIX_COUNT,
            "content_sha256": D3S2_102_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_102_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "slice); Mode26/Mode24/Mode23/Mode22 slice vectors follow"
            ),
        },
        "d3s2_104_prefix_authority": {
            "vector_count": D3S2_104_PREFIX_COUNT,
            "content_sha256": D3S2_104_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_104_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "+ Mode26 slices); Mode24/Mode23/Mode22 slice vectors follow"
            ),
        },
        "d3s2_106_prefix_authority": {
            "vector_count": D3S2_106_PREFIX_COUNT,
            "content_sha256": D3S2_106_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_106_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "+ Mode26 + Mode24 slices); Mode23/Mode22 slice vectors follow"
            ),
        },
        "d3s2_108_prefix_authority": {
            "vector_count": D3S2_108_PREFIX_COUNT,
            "content_sha256": D3S2_108_CONTENT_SHA256,
            "prior_fingerprint_prefix_hash": D3S2_108_FINGERPRINT_HASH,
            "note": (
                "append-only freeze of prior main (94 D3S1 + 6 smoke + Mode25 "
                "+ Mode26 + Mode24 + Mode23 slices); Mode22 slice vectors follow"
            ),
        },
        "prior_fingerprints": prior_fingerprints,
        "prior_fingerprint_prefix_hash": prior_prefix_hash,
        "sha256_procedure": SHA256_PROCEDURE,
        "content_sha256": "",
        "vectors": vectors,
    }
    doc["content_sha256"] = content_sha256_of_doc(doc)
    return doc


def generate(path: Path) -> None:
    doc = build_document()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    path.write_text(text, encoding="utf-8")
    print(
        f"wrote {path} vectors={doc['vector_count']} "
        f"(d3s1_prefix={D3S1_PREFIX_COUNT} d3s2_suffix={D3S2_SUFFIX_COUNT}) "
        f"content_sha256={doc['content_sha256']}"
    )


def _fail_check(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def _assert_prefix_identity(
    data_vectors: List[Dict[str, Any]], prefix_doc: Dict[str, Any]
) -> Optional[str]:
    """Fail-closed: first 94 vectors match d3s1 rebuild on fingerprint/order/
    expected/rows/calls (and id/kind/mode)."""
    exp_vecs = prefix_doc["vectors"]
    if len(data_vectors) < D3S1_PREFIX_COUNT:
        return f"vector list shorter than d3s1 prefix ({len(data_vectors)})"
    for i in range(D3S1_PREFIX_COUNT):
        got = data_vectors[i]
        exp = exp_vecs[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return (
                    f"prefix[{i}] {key} mismatch: {got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return f"prefix[{i}] {got.get('id')}: rows not byte-identical to d3s1"
        if got.get("calls") != exp.get("calls"):
            return f"prefix[{i}] {got.get('id')}: calls not identical to d3s1"
        if got.get("expected") != exp.get("expected"):
            return f"prefix[{i}] {got.get('id')}: expected not identical to d3s1"
        gf = d3s1_vector_fingerprint(got)
        ef = d3s1_vector_fingerprint(exp)
        if gf != ef:
            return (
                f"prefix[{i}] {got.get('id')}: fingerprint drift "
                f"{gf} vs {ef}"
            )
        if gf != prefix_doc["prior_fingerprints"][i]["fingerprint"]:
            return f"prefix[{i}] fingerprint vs d3s1 prior_fingerprints drift"
    return None


def check(path: Path) -> int:
    if not path.is_file():
        return _fail_check(f"missing {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    expected_doc = build_document()
    prefix_doc = freeze_d3s1_prefix()

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
    if int(data.get("d3s1_prefix_count", -1)) != D3S1_PREFIX_COUNT:
        return _fail_check("d3s1_prefix_count pin mismatch")
    if int(data.get("d3s2_suffix_count", -1)) != D3S2_SUFFIX_COUNT:
        return _fail_check("d3s2_suffix_count pin mismatch")
    if int(data.get("d3s2_100_prefix_count", -1)) != D3S2_100_PREFIX_COUNT:
        return _fail_check("d3s2_100_prefix_count pin mismatch")
    if int(data.get("d3s2_102_prefix_count", -1)) != D3S2_102_PREFIX_COUNT:
        return _fail_check("d3s2_102_prefix_count pin mismatch")
    if int(data.get("d3s2_104_prefix_count", -1)) != D3S2_104_PREFIX_COUNT:
        return _fail_check("d3s2_104_prefix_count pin mismatch")
    if int(data.get("d3s2_106_prefix_count", -1)) != D3S2_106_PREFIX_COUNT:
        return _fail_check("d3s2_106_prefix_count pin mismatch")
    if int(data.get("d3s2_108_prefix_count", -1)) != D3S2_108_PREFIX_COUNT:
        return _fail_check("d3s2_108_prefix_count pin mismatch")
    if data.get("required_kinds") != expected_doc["required_kinds"]:
        return _fail_check("required_kinds inventory mismatch")
    if not data.get("sha256_procedure"):
        return _fail_check("missing sha256_procedure")
    if not data.get("content_sha256"):
        return _fail_check("missing content_sha256")
    if data.get("content_sha256") != expected_doc.get("content_sha256"):
        return _fail_check("content_sha256 mismatch vs generator")
    if data.get("prior_fingerprint_prefix_hash") != expected_doc.get(
        "prior_fingerprint_prefix_hash"
    ):
        return _fail_check("prior_fingerprint_prefix_hash mismatch")

    # Frozen d3s1 prefix authority pins.
    auth = data.get("d3s1_prefix_authority") or {}
    if auth.get("content_sha256") != D3S1_PREFIX_CONTENT_SHA256:
        return _fail_check("d3s1_prefix_authority content_sha256 pin mismatch")
    if auth.get("prior_fingerprint_prefix_hash") != D3S1_PREFIX_FINGERPRINT_HASH:
        return _fail_check(
            "d3s1_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth.get("vector_count", -1)) != D3S1_PREFIX_COUNT:
        return _fail_check("d3s1_prefix_authority vector_count pin mismatch")

    # Frozen 100-vector prior-main pin.
    auth100 = data.get("d3s2_100_prefix_authority") or {}
    if auth100.get("content_sha256") != D3S2_100_CONTENT_SHA256:
        return _fail_check("d3s2_100_prefix_authority content_sha256 pin mismatch")
    if auth100.get("prior_fingerprint_prefix_hash") != D3S2_100_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_100_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth100.get("vector_count", -1)) != D3S2_100_PREFIX_COUNT:
        return _fail_check("d3s2_100_prefix_authority vector_count pin mismatch")

    # Frozen 102-vector prior-main pin (includes Mode25).
    auth102 = data.get("d3s2_102_prefix_authority") or {}
    if auth102.get("content_sha256") != D3S2_102_CONTENT_SHA256:
        return _fail_check("d3s2_102_prefix_authority content_sha256 pin mismatch")
    if auth102.get("prior_fingerprint_prefix_hash") != D3S2_102_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_102_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth102.get("vector_count", -1)) != D3S2_102_PREFIX_COUNT:
        return _fail_check("d3s2_102_prefix_authority vector_count pin mismatch")

    # Frozen 104-vector prior-main pin (includes Mode25+Mode26).
    auth104 = data.get("d3s2_104_prefix_authority") or {}
    if auth104.get("content_sha256") != D3S2_104_CONTENT_SHA256:
        return _fail_check("d3s2_104_prefix_authority content_sha256 pin mismatch")
    if auth104.get("prior_fingerprint_prefix_hash") != D3S2_104_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_104_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth104.get("vector_count", -1)) != D3S2_104_PREFIX_COUNT:
        return _fail_check("d3s2_104_prefix_authority vector_count pin mismatch")

    # Frozen 106-vector prior-main pin (includes Mode25+Mode26+Mode24).
    auth106 = data.get("d3s2_106_prefix_authority") or {}
    if auth106.get("content_sha256") != D3S2_106_CONTENT_SHA256:
        return _fail_check("d3s2_106_prefix_authority content_sha256 pin mismatch")
    if auth106.get("prior_fingerprint_prefix_hash") != D3S2_106_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_106_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth106.get("vector_count", -1)) != D3S2_106_PREFIX_COUNT:
        return _fail_check("d3s2_106_prefix_authority vector_count pin mismatch")

    # Frozen 108-vector prior-main pin (includes Mode25+Mode26+Mode24+Mode23).
    auth108 = data.get("d3s2_108_prefix_authority") or {}
    if auth108.get("content_sha256") != D3S2_108_CONTENT_SHA256:
        return _fail_check("d3s2_108_prefix_authority content_sha256 pin mismatch")
    if auth108.get("prior_fingerprint_prefix_hash") != D3S2_108_FINGERPRINT_HASH:
        return _fail_check(
            "d3s2_108_prefix_authority prior_fingerprint_prefix_hash pin mismatch"
        )
    if int(auth108.get("vector_count", -1)) != D3S2_108_PREFIX_COUNT:
        return _fail_check("d3s2_108_prefix_authority vector_count pin mismatch")

    vectors = data["vectors"]
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        return _fail_check(
            f"vector count {len(vectors)} != pin {EXPECTED_VECTOR_COUNT}"
        )

    err = _assert_prefix_identity(vectors, prefix_doc)
    if err:
        return _fail_check(err)

    # First 100 vectors: id/order/rows/calls/expected/fingerprint vs rebuild.
    smoke_rebuild = build_d3s2_smoke_vectors()
    expected_100 = list(prefix_doc["vectors"]) + list(smoke_rebuild)
    if len(expected_100) != D3S2_100_PREFIX_COUNT:
        return _fail_check("internal 100-prefix rebuild length drift")
    for i in range(D3S2_100_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_100[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"100-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"100-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
    hundred_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_100_PREFIX_COUNT)
        ]
    )
    if hundred_chain != D3S2_100_FINGERPRINT_HASH:
        return _fail_check(
            f"100-prefix fingerprint chain pin fail (got {hundred_chain})"
        )

    # First 102 vectors: id/order/rows/calls/expected/fingerprint vs rebuild
    # (94 D3S1 + 6 smoke + Mode25 slice = frozen prior main).
    mode25_rebuild = build_d3s2_mode25_slice_vectors()
    expected_102 = list(expected_100) + list(mode25_rebuild)
    if len(expected_102) != D3S2_102_PREFIX_COUNT:
        return _fail_check("internal 102-prefix rebuild length drift")
    for i in range(D3S2_102_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_102[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"102-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"102-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
    hundred_two_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_102_PREFIX_COUNT)
        ]
    )
    if hundred_two_chain != D3S2_102_FINGERPRINT_HASH:
        return _fail_check(
            f"102-prefix fingerprint chain pin fail (got {hundred_two_chain})"
        )

    # First 104 vectors: id/order/rows/calls/expected/fingerprint vs rebuild
    # (94 D3S1 + 6 smoke + Mode25 + Mode26 = frozen prior main).
    mode26_rebuild = build_d3s2_mode26_slice_vectors()
    expected_104 = list(expected_102) + list(mode26_rebuild)
    if len(expected_104) != D3S2_104_PREFIX_COUNT:
        return _fail_check("internal 104-prefix rebuild length drift")
    for i in range(D3S2_104_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_104[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"104-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"104-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
    hundred_four_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_104_PREFIX_COUNT)
        ]
    )
    if hundred_four_chain != D3S2_104_FINGERPRINT_HASH:
        return _fail_check(
            f"104-prefix fingerprint chain pin fail (got {hundred_four_chain})"
        )

    # First 106 vectors: id/order/rows/calls/expected/fingerprint vs rebuild
    # (94 D3S1 + 6 smoke + Mode25 + Mode26 + Mode24 = frozen prior main).
    # Per-field diagnostics retained first; then full object equality so
    # ownership/notes/refs/etc. cannot silently drift (append-only pin).
    mode24_rebuild = build_d3s2_mode24_slice_vectors()
    expected_106 = list(expected_104) + list(mode24_rebuild)
    if len(expected_106) != D3S2_106_PREFIX_COUNT:
        return _fail_check("internal 106-prefix rebuild length drift")
    for i in range(D3S2_106_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_106[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"106-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        # Full object equality after targeted diagnostics (covers ownership,
        # notes, d1_refs, source_ref, peer_ref, row_refs, faults, alt_rows,
        # candidate_binding, and any future vector field).
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"106-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"106-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_six_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_106_PREFIX_COUNT)
        ]
    )
    if hundred_six_chain != D3S2_106_FINGERPRINT_HASH:
        return _fail_check(
            f"106-prefix fingerprint chain pin fail (got {hundred_six_chain})"
        )

    # First 108 vectors: id/order/rows/calls/expected/fingerprint + full
    # object equality vs rebuild (94 D3S1 + 6 smoke + Mode25 + Mode26 +
    # Mode24 + Mode23 = frozen prior main). Mode22 must not rewrite any
    # prior ownership/notes/refs byte.
    mode23_rebuild = build_d3s2_mode23_slice_vectors()
    expected_108 = list(expected_106) + list(mode23_rebuild)
    if len(expected_108) != D3S2_108_PREFIX_COUNT:
        return _fail_check("internal 108-prefix rebuild length drift")
    for i in range(D3S2_108_PREFIX_COUNT):
        got = vectors[i]
        exp = expected_108[i]
        for key in ("id", "kind", "mode"):
            if got.get(key) != exp.get(key):
                return _fail_check(
                    f"108-prefix[{i}] {key} mismatch: "
                    f"{got.get(key)!r} vs {exp.get(key)!r}"
                )
        if got.get("rows") != exp.get("rows"):
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: rows not identical"
            )
        if got.get("calls") != exp.get("calls"):
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: calls not identical"
            )
        if got.get("expected") != exp.get("expected"):
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: expected not identical"
            )
        if i < D3S1_PREFIX_COUNT:
            gf = d3s1_vector_fingerprint(got)
            ef = d3s1_vector_fingerprint(exp)
        else:
            gf = d3s2_vector_fingerprint(got)
            ef = d3s2_vector_fingerprint(exp)
        if gf != ef:
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: fingerprint drift"
            )
        if got != exp:
            all_keys = sorted(set(got.keys()) | set(exp.keys()))
            for key in all_keys:
                if got.get(key) != exp.get(key):
                    return _fail_check(
                        f"108-prefix[{i}] {got.get('id')}: field {key!r} "
                        f"not identical to rebuild"
                    )
            return _fail_check(
                f"108-prefix[{i}] {got.get('id')}: full object inequality"
            )
    hundred_eight_chain = _chain_hash(
        [
            {
                "fingerprint": (
                    d3s1_vector_fingerprint(vectors[i])
                    if i < D3S1_PREFIX_COUNT
                    else d3s2_vector_fingerprint(vectors[i])
                )
            }
            for i in range(D3S2_108_PREFIX_COUNT)
        ]
    )
    if hundred_eight_chain != D3S2_108_FINGERPRINT_HASH:
        return _fail_check(
            f"108-prefix fingerprint chain pin fail (got {hundred_eight_chain})"
        )

    # prior_fingerprints order/identity.
    got_fps = data.get("prior_fingerprints")
    exp_fps = expected_doc["prior_fingerprints"]
    if not isinstance(got_fps, list) or len(got_fps) != len(exp_fps):
        return _fail_check("prior_fingerprints length mismatch")
    for i, (g, e) in enumerate(zip(got_fps, exp_fps)):
        if g.get("id") != e.get("id") or g.get("fingerprint") != e.get(
            "fingerprint"
        ):
            return _fail_check(
                f"append-prefix drift at prior_fingerprints[{i}] "
                f"id={g.get('id')!r} vs {e.get('id')!r}"
            )

    # First 94 prior_fingerprints must equal frozen d3s1 chain.
    for i in range(D3S1_PREFIX_COUNT):
        if (
            got_fps[i].get("fingerprint")
            != prefix_doc["prior_fingerprints"][i]["fingerprint"]
        ):
            return _fail_check(
                f"prior_fingerprints[{i}] != frozen d3s1 fingerprint"
            )

    # Per-vector schema.
    kinds: Set[str] = set()
    for i, vec in enumerate(vectors):
        for k in VECTOR_KEYS:
            if k not in vec:
                return _fail_check(f"vector {i} missing key {k}")
        kinds.add(vec["kind"])
        extra = set(vec.keys()) - VECTOR_KEYS
        if extra:
            return _fail_check(f"vector {vec['id']} unexpected keys {extra}")
        for c in vec.get("calls", []):
            if not CALL_KEYS.issuperset(c.keys()):
                return _fail_check(f"call keys drift in {vec['id']}")
            op = c.get("op")
            if op not in CLOSED_CALL_OPS:
                return _fail_check(
                    f"{vec['id']}: call op {op!r} not in closed set"
                )
            if op in FORBIDDEN_CALL_OPS:
                return _fail_check(
                    f"{vec['id']}: TEST transport begin forbidden"
                )
            if "expected_status" not in c:
                return _fail_check(f"{vec['id']}: call missing expected_status")
            st = c["expected_status"]
            if op in HARNESS_CALL_OPS:
                if st != "VOID":
                    return _fail_check(
                        f"{vec['id']}: harness op {op} must be VOID"
                    )
            else:
                if st == "VOID" or not isinstance(st, str) or not st:
                    return _fail_check(
                        f"{vec['id']}: scanner op {op} missing status"
                    )
        exp_keys = set(vec["expected"].keys())
        if i < D3S1_PREFIX_COUNT:
            if exp_keys != D3S1_EXPECTED_KEYS:
                return _fail_check(
                    f"prefix expected keys drift in {vec['id']}: "
                    f"{exp_keys ^ D3S1_EXPECTED_KEYS}"
                )
        else:
            if exp_keys != D3S2_EXPECTED_KEYS:
                return _fail_check(
                    f"suffix expected keys drift in {vec['id']}: "
                    f"{exp_keys ^ D3S2_EXPECTED_KEYS}"
                )
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    # Suffix-specific pins: smoke [0..6) Mode25 [6..8) Mode26 [8..10)
    # Mode24 [10..12) Mode23 [12..14) Mode22 [14..16).
    suffix = vectors[D3S1_PREFIX_COUNT:]
    if len(suffix) != D3S2_SUFFIX_COUNT:
        return _fail_check("suffix length mismatch")
    smoke = suffix[:D3S2_SMOKE_COUNT]
    mode25 = suffix[D3S2_SMOKE_COUNT : D3S2_SMOKE_COUNT + D3S2_MODE25_SLICE_COUNT]
    mode26_start = D3S2_SMOKE_COUNT + D3S2_MODE25_SLICE_COUNT
    mode26 = suffix[mode26_start : mode26_start + D3S2_MODE26_SLICE_COUNT]
    mode24_start = mode26_start + D3S2_MODE26_SLICE_COUNT
    mode24 = suffix[mode24_start : mode24_start + D3S2_MODE24_SLICE_COUNT]
    mode23_start = mode24_start + D3S2_MODE24_SLICE_COUNT
    mode23 = suffix[mode23_start : mode23_start + D3S2_MODE23_SLICE_COUNT]
    mode22 = suffix[mode23_start + D3S2_MODE23_SLICE_COUNT :]
    if len(mode25) != D3S2_MODE25_SLICE_COUNT:
        return _fail_check("mode25 slice length mismatch")
    if len(mode26) != D3S2_MODE26_SLICE_COUNT:
        return _fail_check("mode26 slice length mismatch")
    if len(mode24) != D3S2_MODE24_SLICE_COUNT:
        return _fail_check("mode24 slice length mismatch")
    if len(mode23) != D3S2_MODE23_SLICE_COUNT:
        return _fail_check("mode23 slice length mismatch")
    if len(mode22) != D3S2_MODE22_SLICE_COUNT:
        return _fail_check("mode22 slice length mismatch")

    for j, vec in enumerate(smoke):
        mode = 21 + j
        if int(vec["mode"]) != mode:
            return _fail_check(f"smoke[{j}] mode order pin fail")
        if vec["kind"] != f"mode{mode}_empty_carrier_empty_secondary_ok":
            return _fail_check(f"smoke[{j}] kind pin fail")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if ops[-1] != "finalize":
            return _fail_check(f"{vec['id']}: must end with finalize")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        drive_n = ops.count("d3s2_drive")
        if drive_n != MODE_DRIVE_COUNT[mode]:
            return _fail_check(
                f"{vec['id']}: d3s2_drive count {drive_n} != "
                f"{MODE_DRIVE_COUNT[mode]}"
            )
        if any(int(c.get("mode", mode)) != mode for c in vec["calls"] if "mode" in c):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        exp = vec["expected"]
        if int(exp["phase"]) != PHASE_COMPLETE:
            return _fail_check(f"{vec['id']}: phase must be COMPLETE")
        if int(exp["count_complete_mask"]) != 0:
            return _fail_check(f"{vec['id']}: empty-carrier count_mask must be 0")
        if int(exp["binding_complete_mask"]) != MODE_BIND_MASK[mode]:
            return _fail_check(f"{vec['id']}: binding_complete_mask pin fail")
        if int(exp["iter_open_count"]) != MODE_ITER_OPEN[mode]:
            return _fail_check(f"{vec['id']}: iter_open_count pin fail")
        if int(exp["adopted"]) != 1:
            return _fail_check(f"{vec['id']}: adopted must be 1")
        exp_calls, exp_expected = run_d3s2_empty_carrier_case(
            mode, vec["candidate_binding"], vec["rows"]
        )
        if vec["calls"] != exp_calls:
            return _fail_check(f"{vec['id']}: calls != independent model")
        if vec["expected"] != exp_expected:
            return _fail_check(f"{vec['id']}: expected != independent model")

    # Mode25 slice pins.
    m25_ok = mode25[0]
    m25_bad = mode25[1]
    if m25_ok["kind"] != "mode25_cum_total1_recent_slot1_anchor_ok":
        return _fail_check("mode25[0] kind pin fail")
    if m25_bad["kind"] != "mode25_recent_without_cum_carrier_absent_corrupt":
        return _fail_check("mode25[1] kind pin fail")
    for vec in mode25:
        if int(vec["mode"]) != 25:
            return _fail_check(f"{vec['id']}: mode must be 25")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 25)) != 25 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m25_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m25_ok['id']}: success must end with finalize")
    if int(m25_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m25_ok['id']}: phase must be COMPLETE")
    if int(m25_ok["expected"]["count_complete_mask"]) != MASK_RETRY:
        return _fail_check(f"{m25_ok['id']}: count_complete_mask pin fail")
    if int(m25_ok["expected"]["binding_complete_mask"]) != MASK_RETRY:
        return _fail_check(f"{m25_ok['id']}: binding_complete_mask pin fail")
    if int(m25_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m25_ok['id']}: adopted must be 1")
    if int(m25_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m25_ok['id']}: sticky must be clear")
    try:
        exp_calls, exp_expected = run_d3s2_mode25_cum_total1_success(
            m25_ok["candidate_binding"], m25_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m25_ok['id']}: model reject: {exc}")
    if m25_ok["calls"] != exp_calls:
        return _fail_check(f"{m25_ok['id']}: calls != independent model")
    if m25_ok["expected"] != exp_expected:
        return _fail_check(f"{m25_ok['id']}: expected != independent model")

    if m25_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m25_bad['id']}: fail path must end with abort")
    if int(m25_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m25_bad['id']}: phase must be FAILED")
    if m25_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m25_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m25_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m25_bad['id']}: adopted must be 0")
    if int(m25_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m25_bad['id']}: sticky must be set")
    if m25_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m25_bad['id']}: sticky_primary pin fail")
    if int(m25_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m25_bad['id']}: binding mask must stay 0")
    if int(m25_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m25_bad['id']}: count mask must stay 0")
    try:
        exp_calls, exp_expected = run_d3s2_mode25_recent_without_cum_corrupt(
            m25_bad["candidate_binding"], m25_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m25_bad['id']}: model reject: {exc}")
    if m25_bad["calls"] != exp_calls:
        return _fail_check(f"{m25_bad['id']}: calls != independent model")
    if m25_bad["expected"] != exp_expected:
        return _fail_check(f"{m25_bad['id']}: expected != independent model")

    # Mode26 slice pins.
    m26_ok = mode26[0]
    m26_bad = mode26[1]
    if m26_ok["kind"] != "mode26_es_resume1_mgmt_resume_anchor_ok":
        return _fail_check("mode26[0] kind pin fail")
    if m26_bad["kind"] != "mode26_mgmt_without_es_carrier_absent_corrupt":
        return _fail_check("mode26[1] kind pin fail")
    for vec in mode26:
        if int(vec["mode"]) != 26:
            return _fail_check(f"{vec['id']}: mode must be 26")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 26)) != 26 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m26_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m26_ok['id']}: success must end with finalize")
    if int(m26_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m26_ok['id']}: phase must be COMPLETE")
    if int(m26_ok["expected"]["count_complete_mask"]) != MASK_MANAGEMENT:
        return _fail_check(f"{m26_ok['id']}: count_complete_mask pin fail")
    if int(m26_ok["expected"]["binding_complete_mask"]) != MASK_MANAGEMENT:
        return _fail_check(f"{m26_ok['id']}: binding_complete_mask pin fail")
    if int(m26_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m26_ok['id']}: adopted must be 1")
    if int(m26_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m26_ok['id']}: sticky must be clear")
    if int(m26_ok["expected"]["iter_open_count"]) != 5:
        return _fail_check(f"{m26_ok['id']}: stream success iter_open_count pin")
    # Independent parse of ES carrier in rows: resume=1 discard=0.
    es_rows = [
        r
        for r in m26_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x50
    ]
    if len(es_rows) != 1:
        return _fail_check(f"{m26_ok['id']}: exactly one EVENT_SPOOL row required")
    try:
        es_r, es_d = _parse_es_resume_discard(from_hex(es_rows[0]["value_hex"]))
    except SystemExit as exc:
        return _fail_check(f"{m26_ok['id']}: ES parse fail: {exc}")
    if es_r != 1 or es_d != 0:
        return _fail_check(
            f"{m26_ok['id']}: ES resume/discard must be 1/0, got {es_r}/{es_d}"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode26_es_resume1_success(
            m26_ok["candidate_binding"], m26_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m26_ok['id']}: model reject: {exc}")
    if m26_ok["calls"] != exp_calls:
        return _fail_check(f"{m26_ok['id']}: calls != independent model")
    if m26_ok["expected"] != exp_expected:
        return _fail_check(f"{m26_ok['id']}: expected != independent model")

    if m26_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m26_bad['id']}: fail path must end with abort")
    if int(m26_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m26_bad['id']}: phase must be FAILED")
    if m26_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m26_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m26_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m26_bad['id']}: adopted must be 0")
    if int(m26_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m26_bad['id']}: sticky must be set")
    if m26_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m26_bad['id']}: sticky_primary pin fail")
    if int(m26_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m26_bad['id']}: binding mask must stay 0")
    if int(m26_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m26_bad['id']}: count mask must stay 0")
    # Orphan path must not include EVENT_SPOOL rows.
    es_bad = [
        r
        for r in m26_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x50
    ]
    if es_bad:
        return _fail_check(f"{m26_bad['id']}: EVENT_SPOOL must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode26_mgmt_without_es_corrupt(
            m26_bad["candidate_binding"], m26_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m26_bad['id']}: model reject: {exc}")
    if m26_bad["calls"] != exp_calls:
        return _fail_check(f"{m26_bad['id']}: calls != independent model")
    if m26_bad["expected"] != exp_expected:
        return _fail_check(f"{m26_bad['id']}: expected != independent model")

    # Mode24 slice pins.
    m24_ok = mode24[0]
    m24_bad = mode24[1]
    if m24_ok["kind"] != "mode24_rc_reply1_receipt_delivery_ok":
        return _fail_check("mode24[0] kind pin fail")
    if m24_bad["kind"] != "mode24_rr_without_rc_carrier_absent_corrupt":
        return _fail_check("mode24[1] kind pin fail")
    for vec in mode24:
        if int(vec["mode"]) != 24:
            return _fail_check(f"{vec['id']}: mode must be 24")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 24)) != 24 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m24_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m24_ok['id']}: success must end with finalize")
    if int(m24_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m24_ok['id']}: phase must be COMPLETE")
    if int(m24_ok["expected"]["count_complete_mask"]) != MASK_REPLY:
        return _fail_check(f"{m24_ok['id']}: count_complete_mask pin fail")
    if int(m24_ok["expected"]["binding_complete_mask"]) != MASK_REPLY:
        return _fail_check(f"{m24_ok['id']}: binding_complete_mask pin fail")
    if int(m24_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m24_ok['id']}: adopted must be 1")
    if int(m24_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m24_ok['id']}: sticky must be clear")
    if int(m24_ok["expected"]["iter_open_count"]) != 4:
        return _fail_check(f"{m24_ok['id']}: known-kind success iter_open_count pin")
    # Independent parse: RESULT_CACHE reply_count=1; RR RECEIPT kind=1;
    # delivery raw identity match across RC/RR/DELIVERY.
    rc_rows = [
        r
        for r in m24_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    rr_rows = [
        r
        for r in m24_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x42
    ]
    dlv_rows = [
        r
        for r in m24_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x40
    ]
    if len(rc_rows) != 1 or len(rr_rows) != 1 or len(dlv_rows) != 1:
        return _fail_check(
            f"{m24_ok['id']}: exact one DELIVERY/RESULT_CACHE/REVERSE_REPLY "
            f"required (got dlv={len(dlv_rows)} rc={len(rc_rows)} rr={len(rr_rows)})"
        )
    try:
        rc_count, rc_draw, _ = _parse_rc_reply_count_and_delivery(
            from_hex(rc_rows[0]["value_hex"])
        )
        rr_kind, rr_draw, _ = _parse_rr_kind_and_delivery(
            from_hex(rr_rows[0]["value_hex"])
        )
        dlv_draw, _, _ = _parse_delivery_raw_and_primary(
            from_hex(dlv_rows[0]["value_hex"])
        )
    except (SystemExit, ValueError, struct.error, KeyError) as exc:
        return _fail_check(f"{m24_ok['id']}: Mode24 parse fail: {exc}")
    if rc_count != 1:
        return _fail_check(
            f"{m24_ok['id']}: RESULT_CACHE reply_count must be 1, got {rc_count}"
        )
    if rr_kind != RR_KIND_RECEIPT:
        return _fail_check(
            f"{m24_ok['id']}: REVERSE_REPLY kind must be RECEIPT=1, got {rr_kind}"
        )
    if not (rc_draw == rr_draw == dlv_draw):
        return _fail_check(
            f"{m24_ok['id']}: delivery raw identity mismatch across RC/RR/DELIVERY"
        )
    # FOCUS close invariants mirrored in expected peer_get/mode_applicable.
    if int(m24_ok["expected"]["d3_peer_get_count"]) != 6:
        return _fail_check(f"{m24_ok['id']}: d3_peer_get_count pin fail")
    if int(m24_ok["expected"]["d3_mode_applicable_count"]) != 1:
        return _fail_check(f"{m24_ok['id']}: d3_mode_applicable_count pin fail")
    try:
        exp_calls, exp_expected = run_d3s2_mode24_rc_reply1_success(
            m24_ok["candidate_binding"], m24_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m24_ok['id']}: model reject: {exc}")
    if m24_ok["calls"] != exp_calls:
        return _fail_check(f"{m24_ok['id']}: calls != independent model")
    if m24_ok["expected"] != exp_expected:
        return _fail_check(f"{m24_ok['id']}: expected != independent model")

    if m24_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m24_bad['id']}: fail path must end with abort")
    if int(m24_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m24_bad['id']}: phase must be FAILED")
    if m24_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m24_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m24_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m24_bad['id']}: adopted must be 0")
    if int(m24_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m24_bad['id']}: sticky must be set")
    if m24_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m24_bad['id']}: sticky_primary pin fail")
    if int(m24_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m24_bad['id']}: binding mask must stay 0")
    if int(m24_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m24_bad['id']}: count mask must stay 0")
    # Orphan path must not include RESULT_CACHE rows.
    rc_bad = [
        r
        for r in m24_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    if rc_bad:
        return _fail_check(f"{m24_bad['id']}: RESULT_CACHE must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode24_rr_without_rc_corrupt(
            m24_bad["candidate_binding"], m24_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m24_bad['id']}: model reject: {exc}")
    if m24_bad["calls"] != exp_calls:
        return _fail_check(f"{m24_bad['id']}: calls != independent model")
    if m24_bad["expected"] != exp_expected:
        return _fail_check(f"{m24_bad['id']}: expected != independent model")

    # Mode23 slice pins.
    m23_ok = mode23[0]
    m23_bad = mode23[1]
    if m23_ok["kind"] != "mode23_tx_state_slots_L_equation_anchor_ok":
        return _fail_check("mode23[0] kind pin fail")
    if m23_bad["kind"] != "mode23_evidence_without_state_carrier_absent_corrupt":
        return _fail_check("mode23[1] kind pin fail")
    for vec in mode23:
        if int(vec["mode"]) != 23:
            return _fail_check(f"{vec['id']}: mode must be 23")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 23)) != 23 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")

    if m23_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m23_ok['id']}: success must end with finalize")
    if int(m23_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m23_ok['id']}: phase must be COMPLETE")
    if int(m23_ok["expected"]["count_complete_mask"]) != MASK_EVIDENCE:
        return _fail_check(f"{m23_ok['id']}: count_complete_mask pin fail")
    if int(m23_ok["expected"]["binding_complete_mask"]) != MASK_EVIDENCE:
        return _fail_check(f"{m23_ok['id']}: binding_complete_mask pin fail")
    if int(m23_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m23_ok['id']}: adopted must be 1")
    if int(m23_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m23_ok['id']}: sticky must be clear")
    if int(m23_ok["expected"]["iter_open_count"]) != 4:
        return _fail_check(f"{m23_ok['id']}: known-slot success iter_open_count pin")
    # Independent parse: STATE present; SUMMARY equation; slots 0..L.
    L = int(m23_ok["candidate_binding"]["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        return _fail_check(f"{m23_ok['id']}: accepted L pin fail, got {L}")
    state_rows = [
        r
        for r in m23_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    ]
    anchor_rows = [
        r
        for r in m23_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x20
    ]
    ev_rows = [
        r
        for r in m23_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x32
    ]
    if len(state_rows) != 1 or len(anchor_rows) != 1 or len(ev_rows) != L + 1:
        return _fail_check(
            f"{m23_ok['id']}: exact one STATE/ANCHOR and L+1 EVIDENCE "
            f"required (got state={len(state_rows)} anchor={len(anchor_rows)} "
            f"ev={len(ev_rows)})"
        )
    # EVIDENCE rows must be complete-key lex sorted (SHA256_COMPOSITE scatter).
    ev_keys = [from_hex(r["key_hex"]) for r in ev_rows]
    if ev_keys != sorted(ev_keys):
        return _fail_check(f"{m23_ok['id']}: EVIDENCE rows not key-lex sorted")
    try:
        parsed = [_parse_tx_evidence_cell(from_hex(r["value_hex"])) for r in ev_rows]
    except (SystemExit, ValueError, struct.error, KeyError, IndexError) as exc:
        return _fail_check(f"{m23_ok['id']}: Mode23 EV parse fail: {exc}")
    by_slot = {p[2]: p for p in parsed}
    if set(by_slot.keys()) != set(range(L + 1)):
        return _fail_check(f"{m23_ok['id']}: EVIDENCE slots must be exact 0..L")
    s0 = by_slot[0]
    if s0[0] != EV_CELL_KIND_SUMMARY or s0[1] != EV_CELL_STATE_MATERIALIZED:
        return _fail_check(f"{m23_ok['id']}: slot0 must be SUMMARY MATERIALIZED")
    valid, overflow, late_c, late_m = s0[4], s0[5], s0[6], s0[7]
    if (valid, overflow, late_c, late_m) != (2, 1, 1, 1):
        return _fail_check(
            f"{m23_ok['id']}: SUMMARY counters must be 2/1/1/1, got "
            f"{valid}/{overflow}/{late_c}/{late_m}"
        )
    m_obs = 0
    late_obs = 0
    for slot in range(1, L + 1):
        ck, cs, _sl, _ow, _v, _o, _lc, lm = by_slot[slot]
        if ck != EV_CELL_KIND_RAW:
            return _fail_check(f"{m23_ok['id']}: slot{slot} must be RAW")
        if cs == EV_CELL_STATE_MATERIALIZED:
            m_obs += 1
            if lm == 1:
                late_obs += 1
        elif cs != EV_CELL_STATE_UNUSED:
            return _fail_check(f"{m23_ok['id']}: slot{slot} bad RAW state")
    if m_obs != 1 or late_obs != 1:
        return _fail_check(
            f"{m23_ok['id']}: observed M/late must be 1/1, got {m_obs}/{late_obs}"
        )
    if valid != m_obs + overflow:
        return _fail_check(f"{m23_ok['id']}: equation valid != M + overflow")
    if not (late_obs <= late_c <= valid and overflow <= valid):
        return _fail_check(f"{m23_ok['id']}: late/overflow coherence fail")
    # FOCUS (L+1) + BIND 2*(L+1)
    if int(m23_ok["expected"]["d3_peer_get_count"]) != (L + 1) + 2 * (L + 1):
        return _fail_check(f"{m23_ok['id']}: d3_peer_get_count pin fail")
    if int(m23_ok["expected"]["d3_mode_applicable_count"]) != L + 1:
        return _fail_check(f"{m23_ok['id']}: d3_mode_applicable_count pin fail")
    try:
        exp_calls, exp_expected = run_d3s2_mode23_tx_state_slots_equation_success(
            m23_ok["candidate_binding"], m23_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_ok['id']}: model reject: {exc}")
    if m23_ok["calls"] != exp_calls:
        return _fail_check(f"{m23_ok['id']}: calls != independent model")
    if m23_ok["expected"] != exp_expected:
        return _fail_check(f"{m23_ok['id']}: expected != independent model")

    if m23_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m23_bad['id']}: fail path must end with abort")
    if int(m23_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m23_bad['id']}: phase must be FAILED")
    if m23_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m23_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m23_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m23_bad['id']}: adopted must be 0")
    if int(m23_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m23_bad['id']}: sticky must be set")
    if m23_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m23_bad['id']}: sticky_primary pin fail")
    if int(m23_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m23_bad['id']}: binding mask must stay 0")
    if int(m23_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m23_bad['id']}: count mask must stay 0")
    # Orphan path must not include TRANSACTION_STATE rows.
    state_bad = [
        r
        for r in m23_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x22
    ]
    if state_bad:
        return _fail_check(f"{m23_bad['id']}: TRANSACTION_STATE must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode23_evidence_without_state_corrupt(
            m23_bad["candidate_binding"], m23_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m23_bad['id']}: model reject: {exc}")
    if m23_bad["calls"] != exp_calls:
        return _fail_check(f"{m23_bad['id']}: calls != independent model")
    if m23_bad["expected"] != exp_expected:
        return _fail_check(f"{m23_bad['id']}: expected != independent model")


    # Mode22 slice pins.
    m22_ok = mode22[0]
    m22_bad = mode22[1]
    if m22_ok["kind"] != "mode22_rc_app1_dlv_attempt_delivery_ok":
        return _fail_check("mode22[0] kind pin fail")
    if m22_bad["kind"] != "mode22_att_without_rc_carrier_absent_corrupt":
        return _fail_check("mode22[1] kind pin fail")
    for vec in mode22:
        if int(vec["mode"]) != 22:
            return _fail_check(f"{vec['id']}: mode must be 22")
        ops = [c["op"] for c in vec["calls"]]
        if ops[0] != "begin_profiled_d3s2":
            return _fail_check(f"{vec['id']}: must begin with begin_profiled_d3s2")
        if "begin_profiled_d3s1" in ops:
            return _fail_check(f"{vec['id']}: dual-bound S1 begin forbidden")
        if ops.count("begin_profiled_d3s2") != 1:
            return _fail_check(f"{vec['id']}: exactly one begin_profiled_d3s2")
        if any(
            int(c.get("mode", 22)) != 22 for c in vec["calls"] if "mode" in c
        ):
            return _fail_check(f"{vec['id']}: multi-mode session forbidden")
        if int(vec["expected"].get("mutation_calls", -1)) != 0:
            return _fail_check(f"{vec['id']}: mutation_calls must be 0")
        # Mode22 must never run FOCUS_INDEX / BIND_INDEX (count/binding mask
        # has ATTEMPT bit only; INDEX bit never set).
        if int(vec["expected"].get("count_complete_mask", 0)) & MASK_INDEX:
            return _fail_check(f"{vec['id']}: INDEX count bit must stay 0")
        if int(vec["expected"].get("binding_complete_mask", 0)) & MASK_INDEX:
            return _fail_check(f"{vec['id']}: INDEX binding bit must stay 0")

    if m22_ok["calls"][-1]["op"] != "finalize":
        return _fail_check(f"{m22_ok['id']}: success must end with finalize")
    if int(m22_ok["expected"]["phase"]) != PHASE_COMPLETE:
        return _fail_check(f"{m22_ok['id']}: phase must be COMPLETE")
    if int(m22_ok["expected"]["count_complete_mask"]) != MASK_ATTEMPT:
        return _fail_check(f"{m22_ok['id']}: count_complete_mask pin fail")
    if int(m22_ok["expected"]["binding_complete_mask"]) != MASK_ATTEMPT:
        return _fail_check(f"{m22_ok['id']}: binding_complete_mask pin fail")
    if int(m22_ok["expected"]["adopted"]) != 1:
        return _fail_check(f"{m22_ok['id']}: adopted must be 1")
    if int(m22_ok["expected"]["has_sticky_primary"]) != 0:
        return _fail_check(f"{m22_ok['id']}: sticky must be clear")
    if int(m22_ok["expected"]["iter_open_count"]) != 5:
        return _fail_check(f"{m22_ok['id']}: stream success iter_open_count pin")
    # Independent parse: RC app=1; ATT DELIVERY-owned COMMAND; raw match;
    # no ATTEMPT_ID_INDEX rows (INDEX expect 0 via BIND ABSENT only).
    rc_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    att_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x31
    ]
    dlv_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x40
    ]
    aii_rows = [
        r
        for r in m22_ok["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x34
    ]
    if len(rc_rows) != 1 or len(att_rows) != 1 or len(dlv_rows) != 1:
        return _fail_check(
            f"{m22_ok['id']}: exact one DELIVERY/RESULT_CACHE/ATTEMPT "
            f"required (got dlv={len(dlv_rows)} rc={len(rc_rows)} "
            f"att={len(att_rows)})"
        )
    if aii_rows:
        return _fail_check(f"{m22_ok['id']}: ATTEMPT_ID_INDEX must be absent")
    # ATTEMPT complete-key lex order among all rows.
    all_keys = [from_hex(r["key_hex"]) for r in m22_ok["rows"]]
    if all_keys != sorted(all_keys):
        return _fail_check(f"{m22_ok['id']}: rows not complete-key lex sorted")
    try:
        app_n, rc_draw, _ = _parse_rc_app_attempt_and_delivery(
            from_hex(rc_rows[0]["value_hex"])
        )
        att_okind, att_oraw, _aid, _atxn, att_kind, att_pkd, _apvd = (
            _parse_attempt_dlv(from_hex(att_rows[0]["value_hex"]))
        )
        dlv_draw, _, _ = _parse_delivery_raw_and_primary(
            from_hex(dlv_rows[0]["value_hex"])
        )
    except (SystemExit, ValueError, struct.error, KeyError, IndexError) as exc:
        return _fail_check(f"{m22_ok['id']}: Mode22 parse fail: {exc}")
    if app_n != 1:
        return _fail_check(
            f"{m22_ok['id']}: RESULT_CACHE application_attempt_count must "
            f"be 1, got {app_n}"
        )
    if att_okind != ATT_OWNER_KIND_DELIVERY or att_kind != ATT_KIND_COMMAND:
        return _fail_check(
            f"{m22_ok['id']}: ATTEMPT must be DELIVERY-owned COMMAND"
        )
    if not (rc_draw == att_oraw == dlv_draw):
        return _fail_check(
            f"{m22_ok['id']}: delivery raw identity mismatch across "
            "RC/ATT/DELIVERY"
        )
    if att_pkd != _d3s1.key_digest(from_hex(dlv_rows[0]["key_hex"])):
        return _fail_check(
            f"{m22_ok['id']}: ATT primary_key_digest != KEY_DIGEST(DELIVERY)"
        )
    # SELECT setup 2 + BIND 3
    if int(m22_ok["expected"]["d3_peer_get_count"]) != 5:
        return _fail_check(f"{m22_ok['id']}: d3_peer_get_count pin fail")
    if int(m22_ok["expected"]["d3_mode_applicable_count"]) != 1:
        return _fail_check(f"{m22_ok['id']}: d3_mode_applicable_count pin fail")
    # Port-trace gets = 17 profile (begin) + 2 SELECT setup + 3 BIND.
    pt = m22_ok["expected"]["port_trace"]
    if pt.count("get") != 17 + 5:
        return _fail_check(
            f"{m22_ok['id']}: port_trace get count must be 22 "
            f"(17 profile + 5 peer), got {pt.count('get')}"
        )
    try:
        exp_calls, exp_expected = run_d3s2_mode22_rc_app1_attempt_success(
            m22_ok["candidate_binding"], m22_ok["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m22_ok['id']}: model reject: {exc}")
    if m22_ok["calls"] != exp_calls:
        return _fail_check(f"{m22_ok['id']}: calls != independent model")
    if m22_ok["expected"] != exp_expected:
        return _fail_check(f"{m22_ok['id']}: expected != independent model")

    if m22_bad["calls"][-1]["op"] != "abort":
        return _fail_check(f"{m22_bad['id']}: fail path must end with abort")
    if int(m22_bad["expected"]["phase"]) != PHASE_FAILED:
        return _fail_check(f"{m22_bad['id']}: phase must be FAILED")
    if m22_bad["expected"]["final_status"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m22_bad['id']}: final_status must be STORAGE_CORRUPT")
    if int(m22_bad["expected"]["adopted"]) != 0:
        return _fail_check(f"{m22_bad['id']}: adopted must be 0")
    if int(m22_bad["expected"]["has_sticky_primary"]) != 1:
        return _fail_check(f"{m22_bad['id']}: sticky must be set")
    if m22_bad["expected"]["sticky_primary"] != "STORAGE_CORRUPT":
        return _fail_check(f"{m22_bad['id']}: sticky_primary pin fail")
    if int(m22_bad["expected"]["binding_complete_mask"]) != 0:
        return _fail_check(f"{m22_bad['id']}: binding mask must stay 0")
    if int(m22_bad["expected"]["count_complete_mask"]) != 0:
        return _fail_check(f"{m22_bad['id']}: count mask must stay 0")
    if int(m22_bad["expected"]["d3_peer_get_count"]) != 1:
        return _fail_check(
            f"{m22_bad['id']}: orphan d3_peer_get_count must be 1 "
            "(carrier only; primary/INDEX must not run)"
        )
    # Orphan path must not include RESULT_CACHE rows.
    rc_bad = [
        r
        for r in m22_bad["rows"]
        if len(from_hex(r["key_hex"])) >= 10
        and from_hex(r["key_hex"])[8] == 6
        and from_hex(r["key_hex"])[9] == 0x41
    ]
    if rc_bad:
        return _fail_check(f"{m22_bad['id']}: RESULT_CACHE must be absent")
    try:
        exp_calls, exp_expected = run_d3s2_mode22_att_without_rc_corrupt(
            m22_bad["candidate_binding"], m22_bad["rows"]
        )
    except SystemExit as exc:
        return _fail_check(f"{m22_bad['id']}: model reject: {exc}")
    if m22_bad["calls"] != exp_calls:
        return _fail_check(f"{m22_bad['id']}: calls != independent model")
    if m22_bad["expected"] != exp_expected:
        return _fail_check(f"{m22_bad['id']}: expected != independent model")


    if not D3S2_REQUIRED_KINDS.issubset(kinds):
        return _fail_check(
            f"missing d3s2 kinds {D3S2_REQUIRED_KINDS - kinds}"
        )

    # Full rebuild equality (canonical document).
    if data.get("content_sha256") != expected_doc.get("content_sha256"):
        return _fail_check("content_sha256 rebuild mismatch")
    if data.get("prior_fingerprints") != expected_doc.get("prior_fingerprints"):
        return _fail_check("prior_fingerprints rebuild mismatch")
    # Vectors deep equality via content hash is sufficient; also pin suffix fps.
    for i in range(D3S1_PREFIX_COUNT, EXPECTED_VECTOR_COUNT):
        if d3s2_vector_fingerprint(vectors[i]) != exp_fps[i]["fingerprint"]:
            return _fail_check(f"suffix fingerprint rebuild fail at {i}")

    print(
        f"ok {path} vectors={len(vectors)} "
        f"(d3s1_prefix={D3S1_PREFIX_COUNT} d3s2_suffix={D3S2_SUFFIX_COUNT}) "
        f"content_sha256={data.get('content_sha256')}"
    )
    return 0


def self_test() -> int:
    """Negative self-tests that must FAIL check when applied to temp mutations."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        clean = root / "clean.json"
        generate(clean)
        if check(clean) != 0:
            print("self-test: clean generate+check failed", file=sys.stderr)
            return 1

        # Historical D3-S1 generator must not downgrade the shared append-only
        # artifact after it has advanced to the D3-S2 format.
        try:
            _d3s1.generate(clean)
        except SystemExit as exc:
            if "refusing D3-S2 sibling downgrade" not in str(exc):
                print(f"self-test: unexpected downgrade error: {exc}", file=sys.stderr)
                return 1
        else:
            print("self-test: D3-S1 generator accepted D3-S2 downgrade", file=sys.stderr)
            return 1

        def mut(name: str, fn) -> Optional[str]:
            p = root / f"{name}.json"
            data = json.loads(clean.read_text(encoding="utf-8"))
            fn(data)
            p.write_text(
                json.dumps(data, indent=2, sort_keys=False) + "\n", encoding="utf-8"
            )
            rc = check(p)
            if rc == 0:
                return f"self-test {name}: expected check failure, got pass"
            return None

        failures: List[str] = []

        def t(name: str, fn) -> None:
            err = mut(name, fn)
            if err:
                failures.append(err)

        t(
            "format_fork",
            lambda d: d.__setitem__("format", "ninlil-domain-scan-crossrow-v1-d3s1"),
        )
        t(
            "vector_count_pin",
            lambda d: d.__setitem__("vector_count", 94),
        )
        t(
            "prefix_row_tamper",
            lambda d: d["vectors"][0]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "prefix_expected_tamper",
            lambda d: d["vectors"][0]["expected"].__setitem__("ok_row_count", 999),
        )
        t(
            "prefix_call_tamper",
            lambda d: d["vectors"][0]["calls"][0].__setitem__(
                "op", "begin_profiled_d3s2"
            ),
        )
        # 100-prefix freeze (smoke Mode21 + last smoke Mode26).
        t(
            "hundred_prefix_row_tamper",
            lambda d: d["vectors"][99]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_prefix_expected_tamper",
            lambda d: d["vectors"][94]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_prefix_fp_authority_tamper",
            lambda d: d["d3s2_100_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "suffix_mode_order",
            lambda d: d["vectors"][94].__setitem__("mode", 22),
        )
        t(
            "suffix_bind_mask",
            lambda d: d["vectors"][94]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "six_mode_single_session",
            lambda d: d["vectors"][94]["calls"].__setitem__(
                0,
                {
                    "op": "begin_profiled_d3s2",
                    "mode": 22,
                    "expected_status": "OK",
                },
            ),
        )
        t(
            "mutation_nonzero",
            lambda d: d["vectors"][95]["expected"].__setitem__("mutation_calls", 1),
        )
        t(
            "forbidden_begin",
            lambda d: d["vectors"][96]["calls"].insert(
                0, {"op": "begin", "expected_status": "OK"}
            ),
        )
        # New Mode25 slice tampers (indices 100, 101).
        t(
            "mode25_ok_count_mask_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode25_ok_bind_mask_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode25_ok_carrier_row_tamper",
            lambda d: d["vectors"][100]["rows"].pop(),
        )
        t(
            "mode25_ok_trace_tamper",
            lambda d: d["vectors"][100]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode25_ok_mutation_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        t(
            "mode25_bad_count_mask_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "count_complete_mask", MASK_RETRY
            ),
        )
        t(
            "mode25_bad_bind_mask_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "binding_complete_mask", MASK_RETRY
            ),
        )
        t(
            "mode25_bad_carrier_insert_tamper",
            lambda d: d["vectors"][101]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode25_bad_trace_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode25_bad_mutation_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        t(
            "mode25_bad_sticky_tamper",
            lambda d: d["vectors"][101]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        # 102-prefix freeze (includes Mode25; Mode26 follows at 102+).
        t(
            "hundred_two_prefix_row_tamper",
            lambda d: d["vectors"][101]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_two_prefix_expected_tamper",
            lambda d: d["vectors"][100]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_two_prefix_fp_authority_tamper",
            lambda d: d["d3s2_102_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_two_prefix_content_authority_tamper",
            lambda d: d["d3s2_102_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # New Mode26 slice tampers (indices 102, 103).
        t(
            "mode26_ok_count_mask_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode26_ok_bind_mask_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode26_ok_carrier_row_tamper",
            lambda d: d["vectors"][102]["rows"].pop(),
        )
        t(
            "mode26_ok_trace_tamper",
            lambda d: d["vectors"][102]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode26_ok_pvd_row_tamper",
            lambda d: d["vectors"][102]["rows"].__setitem__(
                -1,
                {
                    "key_hex": d["vectors"][102]["rows"][-1]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode26_ok_mutation_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        t(
            "mode26_bad_count_mask_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "count_complete_mask", MASK_MANAGEMENT
            ),
        )
        t(
            "mode26_bad_bind_mask_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "binding_complete_mask", MASK_MANAGEMENT
            ),
        )
        t(
            "mode26_bad_carrier_insert_tamper",
            lambda d: d["vectors"][103]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode26_bad_trace_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode26_bad_sticky_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode26_bad_mutation_tamper",
            lambda d: d["vectors"][103]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 104-prefix freeze (includes Mode25+Mode26; Mode24 follows at 104+).
        t(
            "hundred_four_prefix_row_tamper",
            lambda d: d["vectors"][103]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_four_prefix_expected_tamper",
            lambda d: d["vectors"][102]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_four_prefix_fp_authority_tamper",
            lambda d: d["d3s2_104_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_four_prefix_content_authority_tamper",
            lambda d: d["d3s2_104_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # New Mode24 success tampers (index 104): reply_count/popcount/
        # count-mask/bind/PVD/trace/mutation.
        t(
            "mode24_ok_reply_count_row_tamper",
            lambda d: d["vectors"][104]["rows"].__setitem__(
                -2,
                {
                    "key_hex": d["vectors"][104]["rows"][-2]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode24_ok_count_mask_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode24_ok_bind_mask_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode24_ok_peer_get_popcount_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "mode24_ok_pvd_row_tamper",
            lambda d: d["vectors"][104]["rows"].__setitem__(
                -1,
                {
                    "key_hex": d["vectors"][104]["rows"][-1]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode24_ok_trace_tamper",
            lambda d: d["vectors"][104]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode24_ok_mutation_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # New Mode24 orphan tampers (index 105): carrier/trace/sticky/mutation.
        t(
            "mode24_bad_count_mask_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "count_complete_mask", MASK_REPLY
            ),
        )
        t(
            "mode24_bad_bind_mask_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "binding_complete_mask", MASK_REPLY
            ),
        )
        t(
            "mode24_bad_carrier_insert_tamper",
            lambda d: d["vectors"][105]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode24_bad_trace_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode24_bad_sticky_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode24_bad_mutation_tamper",
            lambda d: d["vectors"][105]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 106-prefix freeze (includes Mode25+Mode26+Mode24; Mode23 at 106+).
        t(
            "hundred_six_prefix_row_tamper",
            lambda d: d["vectors"][105]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_six_prefix_expected_tamper",
            lambda d: d["vectors"][104]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_six_prefix_fp_authority_tamper",
            lambda d: d["d3s2_106_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_six_prefix_content_authority_tamper",
            lambda d: d["d3s2_106_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # Ownership must remain frozen 12-vector text on the 106-prefix
        # (append-only; Mode23 must not rewrite prior objects).
        t(
            "hundred_six_prefix_ownership_tamper",
            lambda d: d["vectors"][105].__setitem__(
                "ownership", OWNERSHIP_MODE23
            ),
        )
        # New Mode23 success tampers (index 106): equation/mask/PVD/trace.
        t(
            "mode23_ok_count_mask_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode23_ok_bind_mask_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode23_ok_peer_get_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "mode23_ok_equation_row_tamper",
            lambda d: d["vectors"][106]["rows"].pop(),
        )
        t(
            "mode23_ok_pvd_row_tamper",
            lambda d: d["vectors"][106]["rows"].__setitem__(
                -1,
                {
                    "key_hex": d["vectors"][106]["rows"][-1]["key_hex"],
                    "value_hex": "00" * 32,
                },
            ),
        )
        t(
            "mode23_ok_trace_tamper",
            lambda d: d["vectors"][106]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode23_ok_mutation_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # New Mode23 orphan tampers (index 107): carrier/trace/sticky/mutation.
        t(
            "mode23_bad_count_mask_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "count_complete_mask", MASK_EVIDENCE
            ),
        )
        t(
            "mode23_bad_bind_mask_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "binding_complete_mask", MASK_EVIDENCE
            ),
        )
        t(
            "mode23_bad_carrier_insert_tamper",
            lambda d: d["vectors"][107]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode23_bad_trace_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode23_bad_sticky_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode23_bad_mutation_tamper",
            lambda d: d["vectors"][107]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        # 108-prefix freeze (includes Mode25+Mode26+Mode24+Mode23; Mode22 at 108+).
        t(
            "hundred_eight_prefix_row_tamper",
            lambda d: d["vectors"][107]["rows"].__setitem__(
                0, {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "hundred_eight_prefix_expected_tamper",
            lambda d: d["vectors"][106]["expected"].__setitem__(
                "ok_row_count", 999
            ),
        )
        t(
            "hundred_eight_prefix_fp_authority_tamper",
            lambda d: d["d3s2_108_prefix_authority"].__setitem__(
                "prior_fingerprint_prefix_hash", "0" * 64
            ),
        )
        t(
            "hundred_eight_prefix_content_authority_tamper",
            lambda d: d["d3s2_108_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )
        # Ownership must remain frozen 14-vector text on the 108-prefix
        # (append-only; Mode22 must not rewrite prior Mode23 objects).
        t(
            "hundred_eight_prefix_ownership_tamper",
            lambda d: d["vectors"][107].__setitem__(
                "ownership", OWNERSHIP_MODE22
            ),
        )
        # New Mode22 success tampers (index 108): mask/peer/INDEX/trace/mutation.
        t(
            "mode22_ok_count_mask_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "count_complete_mask", 0
            ),
        )
        t(
            "mode22_ok_bind_mask_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "binding_complete_mask", 0
            ),
        )
        t(
            "mode22_ok_peer_get_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "d3_peer_get_count", 0
            ),
        )
        t(
            "mode22_ok_index_mask_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT | MASK_INDEX
            ),
        )
        t(
            "mode22_ok_unexpected_index_row_tamper",
            lambda d: d["vectors"][108]["rows"].append(
                {"key_hex": "00" * 45, "value_hex": "00" * 32}
            ),
        )
        t(
            "mode22_ok_trace_tamper",
            lambda d: d["vectors"][108]["expected"]["port_trace"].append("put"),
        )
        t(
            "mode22_ok_mutation_tamper",
            lambda d: d["vectors"][108]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        )
        # New Mode22 orphan tampers (index 109): carrier/trace/sticky/mutation.
        t(
            "mode22_bad_count_mask_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "count_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "mode22_bad_bind_mask_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "binding_complete_mask", MASK_ATTEMPT
            ),
        )
        t(
            "mode22_bad_carrier_insert_tamper",
            lambda d: d["vectors"][109]["rows"].append(
                {"key_hex": "00", "value_hex": "00"}
            ),
        )
        t(
            "mode22_bad_peer_get_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "d3_peer_get_count", 3
            ),
        )
        t(
            "mode22_bad_trace_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "port_trace", []
            ),
        )
        t(
            "mode22_bad_sticky_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "sticky_primary", "STORAGE"
            ),
        )
        t(
            "mode22_bad_mutation_tamper",
            lambda d: d["vectors"][109]["expected"].__setitem__(
                "mutation_calls", 7
            ),
        )
        t(
            "content_sha_tamper",
            lambda d: d.__setitem__("content_sha256", "0" * 64),
        )
        t(
            "d3s1_authority_tamper",
            lambda d: d["d3s1_prefix_authority"].__setitem__(
                "content_sha256", "0" * 64
            ),
        )

        # Clean re-check still passes.
        if check(clean) != 0:
            failures.append("self-test: clean re-check failed")

        if failures:
            for f in failures:
                print(f, file=sys.stderr)
            return 1
        print(
            "self-test ok (94+100+102+104+106+108 prefix freeze + mode25/"
            "mode26/mode24/mode23/mode22 slice pins + forbidden ops + clean pass)"
        )
        return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    """Emit D3-S1 94-array (compat) + separate D3-S2 suffix array/type/count=14."""
    data = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    if len(vectors) < D3S1_PREFIX_COUNT:
        raise SystemExit("emit-c-fixture: vector list too short for d3s1 prefix")
    d3s1_vectors = vectors[:D3S1_PREFIX_COUNT]
    d3s2_vectors = vectors[D3S1_PREFIX_COUNT:]
    if len(d3s1_vectors) != D3S1_PREFIX_COUNT:
        raise SystemExit("emit-c-fixture: d3s1 count pin fail")
    if len(d3s2_vectors) != D3S2_SUFFIX_COUNT:
        raise SystemExit(
            f"emit-c-fixture: d3s2 suffix count {len(d3s2_vectors)} != "
            f"{D3S2_SUFFIX_COUNT}"
        )

    lines: List[str] = []
    lines.append(
        "/* Generated by tools/domain_scan_crossrow_d3s2_vector_gen.py — do not edit. */"
    )
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(
        f"#define NINLIL_D3S1_VECTOR_COUNT ((size_t){len(d3s1_vectors)}u)"
    )
    lines.append(
        f"#define NINLIL_D3S2_VECTOR_COUNT ((size_t){len(d3s2_vectors)}u)"
    )
    lines.append(
        f"#define NINLIL_D3S1_WORKSPACE_CEILING_BYTES ((uint32_t){CEILING}u)"
    )
    lines.append("#define NINLIL_D3S1_MAX_TRACE ((size_t)512u)")
    lines.append("#define NINLIL_D3S2_MAX_TRACE ((size_t)512u)")
    lines.append("#define NINLIL_D3S1_MAX_KEY ((size_t)255u)")
    lines.append("#define NINLIL_D3S1_MAX_VALUE ((size_t)4096u)")
    lines.append("#define NINLIL_D3S1_MAX_ALT ((size_t)4u)")
    lines.append("")
    lines.append("/* No NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN required. */")
    lines.append("")

    # ---- shared binding / row / fault / call shapes (D3-S1 names kept) ----
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
    lines.append("typedef ninlil_d3s1_binding_t ninlil_d3s2_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_d3s1_row {")
    lines.append("    uint8_t key[64];")
    lines.append("    uint32_t key_length;")
    lines.append("    const uint8_t *value;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_d3s1_row_t;")
    lines.append("")
    lines.append("typedef ninlil_d3s1_row_t ninlil_d3s2_row_t;")
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
    lines.append("typedef ninlil_d3s1_fault_t ninlil_d3s2_fault_t;")
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
    lines.append("typedef ninlil_d3s1_call_t ninlil_d3s2_call_t;")
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
    lines.append("typedef struct ninlil_d3s2_expected {")
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
    lines.append("    uint8_t phase;")
    lines.append("    uint8_t count_complete_mask;")
    lines.append("    uint8_t binding_complete_mask;")
    lines.append("    uint8_t flags;")
    lines.append("} ninlil_d3s2_expected_t;")
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
    lines.append("typedef struct ninlil_d3s2_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    uint8_t mode;")
    lines.append("    ninlil_d3s2_binding_t candidate;")
    lines.append("    const ninlil_d3s2_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_d3s2_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_d3s2_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_d3s2_expected_t expected;")
    lines.append("} ninlil_d3s2_vector_t;")
    lines.append("")

    def c_bytes_literal(data_b: bytes, name: str) -> List[str]:
        out = [f"static const uint8_t {name}[] = {{"]
        if data_b:
            parts = [f"0x{b:02x}" for b in data_b]
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

    # ---- D3-S1 94 (compat) ----
    for vi, vec in enumerate(d3s1_vectors):
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
        lines.append(f"static const ninlil_d3s1_alt_t ninlil_d3s1_alts_{vi}[] = {{")
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
        lines.append(f"static const char *const ninlil_d3s1_trace_{vi}[] = {{")
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append('    "",')
        lines.append("};")

    lines.append(
        "static const ninlil_d3s1_vector_t "
        "ninlil_d3s1_vectors[NINLIL_D3S1_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(d3s1_vectors):
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
        lines.append(f"        ninlil_d3s1_calls_{vi}, {len(vec['calls'])}u,")
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

    # ---- D3-S2 suffix (smoke + Mode25 + Mode26 + Mode24) ----
    for vi, vec in enumerate(d3s2_vectors):
        for ri, row in enumerate(vec.get("rows", [])):
            val = from_hex(row["value_hex"])
            lines.extend(c_bytes_literal(val, f"ninlil_d3s2_{vi}_v{ri}"))
        lines.append(f"static const ninlil_d3s2_row_t ninlil_d3s2_{vi}_rows[] = {{")
        for ri, row in enumerate(vec.get("rows", [])):
            key = from_hex(row["key_hex"])
            key_l = ", ".join(f"0x{b:02x}" for b in key)
            pad = ", ".join("0x00" for _ in range(max(0, 64 - len(key))))
            key_arr = key_l + ((", " + pad) if pad else "")
            lines.append(
                f"    {{ {{ {key_arr} }}, {len(key)}u, "
                f"ninlil_d3s2_{vi}_v{ri}, {len(from_hex(row['value_hex']))}u }},"
            )
        if not vec.get("rows"):
            lines.append("    { {0}, 0u, NULL, 0u },")
        lines.append("};")
        lines.append(
            f"static const ninlil_d3s2_fault_t ninlil_d3s2_faults_{vi}[] = {{"
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
            f"static const ninlil_d3s2_call_t ninlil_d3s2_calls_{vi}[] = {{"
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
        lines.append(f"static const char *const ninlil_d3s2_trace_{vi}[] = {{")
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append('    "",')
        lines.append("};")

    lines.append(
        "static const ninlil_d3s2_vector_t "
        "ninlil_d3s2_vectors[NINLIL_D3S2_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(d3s2_vectors):
        exp = vec["expected"]
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {int(vec.get('mode', 0))}u,")
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(
            f"        ninlil_d3s2_{vi}_rows, {len(vec.get('rows', []))}u,"
        )
        lines.append(
            f"        ninlil_d3s2_faults_{vi}, {len(vec.get('faults', []))}u,"
        )
        lines.append(f"        ninlil_d3s2_calls_{vi}, {len(vec['calls'])}u,")
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
            f"            ninlil_d3s2_trace_{vi}, "
            f"{len(exp.get('port_trace', []))}u,"
        )
        lines.append(f"            {int(exp['has_sticky_primary'])}u,")
        lines.append(f'            "{exp.get("sticky_primary", "")}",')
        lines.append(f"            {int(exp.get('d3_peer_get_count', 0))}ull,")
        lines.append(
            f"            {int(exp.get('d3_mode_applicable_count', 0))}ull,"
        )
        lines.append(f"            {int(exp['phase'])}u,")
        lines.append(f"            0x{int(exp['count_complete_mask']):02x}u,")
        lines.append(f"            0x{int(exp['binding_complete_mask']):02x}u,")
        lines.append(f"            0x{int(exp['flags']):02x}u")
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_CROSSROW_VECTOR_FIXTURE_H */")
    lines.append("")
    header_path.parent.mkdir(parents=True, exist_ok=True)
    header_path.write_text("\n".join(lines), encoding="utf-8")
    print(
        f"wrote {header_path} "
        f"(d3s1={len(d3s1_vectors)} d3s2={len(d3s2_vectors)} vectors)"
    )


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
