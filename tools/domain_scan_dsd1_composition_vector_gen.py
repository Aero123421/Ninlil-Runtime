#!/usr/bin/env python3
"""Independent D3-S2 P2-A DSD1 multi-session composition oracle (stdlib only).

docs/17 §18.13.16: DSD1_LOGICAL_DELIVERY is composition only — no Mode 28,
no dual-bound S1+S2, no one-baseline-all-modes claim. This sibling chains
self-contained sessions on one D1-valid fixture:

  S1 modes 11 / 14 / 17 / 19  +  S2 modes 22 / 23 / 24

Each session: begin → independent baseline → mode FOCUS/BIND → finalize DONE
→ next session (separate READ_ONLY txn; mutation_calls=0).

Does NOT invoke/translate production C. Does NOT modify the crossrow authority
JSON. Pins D1 + frozen crossrow authority by full SHA/format/count.

Usage:
  python3 tools/domain_scan_dsd1_composition_vector_gen.py generate <path>
  python3 tools/domain_scan_dsd1_composition_vector_gen.py check <path>
  python3 tools/domain_scan_dsd1_composition_vector_gen.py self-test
  python3 tools/domain_scan_dsd1_composition_vector_gen.py emit-c-fixture <json> <h>
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "tools"))

import domain_scan_crossrow_vector_gen as s1  # noqa: E402
import domain_scan_crossrow_d3s2_vector_gen as s2  # noqa: E402
from domain_scan_crossrow_d3s2_vector_gen import (  # noqa: E402
    MODE23_ACCEPTED_L,
    from_hex,
    hex_of,
    _assert_d1_authority_pin,
    _d1_catalog,
    _d3s1,
    _mode22_material_rows,
    _mode24_material_rows,
    _parse_delivery_raw_and_primary,
    _parse_rc_app_attempt_and_delivery,
    _parse_rc_reply_count_and_delivery,
    _patch_rc_reply_count,
    _walk_trace_segment,
    _begin_profile_port_prefix,
    FLAG_BASELINE_DONE,
    FLAG_COMPLETE_READY,
    MASK_ATTEMPT,
    MASK_EVIDENCE,
    MASK_REPLY,
    PHASE_COMPLETE,
)

FORMAT = "ninlil-domain-scan-dsd1-composition-v1-d3s2"
VERSION = 1
SCOPE = (
    "D3-S2 P2-A DSD1 multi-session composition only (§18.13.16). "
    "Chains S1 modes 11/14/17/19 + S2 modes 22/23/24 as separate self-contained "
    "sessions on one D1-valid fixture with DONE between sessions. "
    "Does not claim Mode 28, dual-bound S1+S2, one-baseline-all-modes, "
    "D3-S2 overall complete, Stage 5, D4 writer E2E, public Runtime, ESP-IDF, "
    "or hardware."
)

D1_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-store-v1.json"
CROSSROW_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-crossrow-v1.json"
D1_FORMAT = "ninlil-domain-store-v1-d1b3o"
D1_SHA256 = (
    "b809c223f8208111fb4271cdceed031193e32e0f118e019d404ac538c89792b4"
)
D1_COUNT = 1549
CROSSROW_FORMAT_D3S2 = "ninlil-domain-scan-crossrow-v1-d3s2"
CROSSROW_FORMAT_D3S3 = "ninlil-domain-scan-crossrow-v1-d3s3"
# Frozen D3-S2 raw authority (full-file when format was d3s2 / 144 vectors).
CROSSROW_D3S2_RAW_SHA256 = (
    "e270743e99189a830b1b39d6c4b464fc3d2eb63ff8fe2b20dcfa7ae0f91d01ec"
)
CROSSROW_D3S2_CONTENT_SHA256 = (
    "a9fccb12d932f0082111c94da3a23cd6680dc4bedecb2108e739bdca55d80fed"
)
CROSSROW_D3S2_COUNT = 144
# Backward-compat aliases (d3s2-only worktrees).
CROSSROW_FORMAT = CROSSROW_FORMAT_D3S2
CROSSROW_SHA256 = CROSSROW_D3S2_RAW_SHA256
CROSSROW_COUNT = CROSSROW_D3S2_COUNT

D1_CS_DLV_NONE_ID = "DSB3_CS_DLV_NONE_TYPED"
D1_EV_DLV_SUM_EMPTY_ID = "DSB3_EV_DLV_SUM_EMPTY_TYPED"
D1_EV_DLV_RAW_MAT_ID = "DSB3_EV_DLV_RAW_MAT_TYPED"

SESSION_MODE_ORDER: Tuple[Tuple[str, int], ...] = (
    ("s1", 11),
    ("s1", 14),
    ("s1", 17),
    ("s1", 19),
    ("s2", 22),
    ("s2", 23),
    ("s2", 24),
)

REQUIRED_SESSION_KINDS = frozenset(
    {
        "dsd1_s1_mode11_result_exact1",
        "dsd1_s1_mode14_cancel_gate",
        "dsd1_s1_mode17_delivery_result_pvd",
        "dsd1_s1_mode19_callback_gate",
        "dsd1_s2_mode22_attempt_cardinality",
        "dsd1_s2_mode23_evidence_slots",
        "dsd1_s2_mode24_reply_count",
    }
)

EXPECTED_VECTOR_COUNT = 1
EXPECTED_SESSION_COUNT = 7

# DLV EVIDENCE body exact 798 (docs/17 §8.3): TX offsets + 64 (raw 80 vs 16).
EV_DLV_BODY_LEN = 798
EV_DLV_DELTA = 64
EV_CELL_KIND_BODY_OFF = 2
EV_SLOT_BODY_OFF = 86 + EV_DLV_DELTA
EV_CELL_STATE_BODY_OFF = 90 + EV_DLV_DELTA
EV_OWNER_KIND_DLV = 2
EV_CELL_KIND_SUMMARY = 1
EV_CELL_KIND_RAW = 2
EV_CELL_STATE_UNUSED = 1
EV_CELL_STATE_MATERIALIZED = 2


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _assert_authority_pins() -> None:
    """Pin D1 + crossrow. D3-S3 append keeps frozen D3-S2 144-prefix authority.

    Accept either:
    - historical d3s2 full-file raw/format/count, or
    - d3s3 file whose d3s2_prefix_authority matches the frozen d3s2 pins
      (raw_sha256 / content_sha256 / count) without weakening that pin.
    """
    _assert_d1_authority_pin()
    if not CROSSROW_VECTORS.is_file():
        raise SystemExit(f"missing crossrow authority {CROSSROW_VECTORS}")
    got = _sha256_file(CROSSROW_VECTORS)
    doc = json.loads(CROSSROW_VECTORS.read_text(encoding="utf-8"))
    fmt = doc.get("format")
    if fmt == CROSSROW_FORMAT_D3S2:
        if got != CROSSROW_D3S2_RAW_SHA256:
            raise SystemExit(
                f"crossrow authority sha mismatch: {got} != {CROSSROW_D3S2_RAW_SHA256}"
            )
        if int(doc.get("vector_count", -1)) != CROSSROW_D3S2_COUNT:
            raise SystemExit(
                f"crossrow count pin fail: {doc.get('vector_count')}"
            )
        return
    if fmt == CROSSROW_FORMAT_D3S3:
        auth = doc.get("d3s2_prefix_authority") or {}
        if int(doc.get("d3s2_prefix_count", -1)) != CROSSROW_D3S2_COUNT:
            raise SystemExit(
                f"d3s3 d3s2_prefix_count pin fail: {doc.get('d3s2_prefix_count')}"
            )
        if auth.get("format") != CROSSROW_FORMAT_D3S2:
            raise SystemExit(
                f"d3s3 prefix authority format pin fail: {auth.get('format')!r}"
            )
        if int(auth.get("vector_count", -1)) != CROSSROW_D3S2_COUNT:
            raise SystemExit(
                f"d3s3 prefix authority count pin fail: {auth.get('vector_count')}"
            )
        if auth.get("raw_sha256") != CROSSROW_D3S2_RAW_SHA256:
            raise SystemExit(
                "d3s3 prefix authority raw_sha256 pin fail "
                f"{auth.get('raw_sha256')} != {CROSSROW_D3S2_RAW_SHA256}"
            )
        if auth.get("content_sha256") != CROSSROW_D3S2_CONTENT_SHA256:
            raise SystemExit(
                "d3s3 prefix authority content_sha256 pin fail "
                f"{auth.get('content_sha256')} != {CROSSROW_D3S2_CONTENT_SHA256}"
            )
        if int(doc.get("vector_count", -1)) < CROSSROW_D3S2_COUNT:
            raise SystemExit(
                f"d3s3 vector_count pin fail: {doc.get('vector_count')}"
            )
        return
    raise SystemExit(f"crossrow format pin fail: {fmt!r}")


def _replace_ev_body_any(value: bytes, body: bytes) -> bytes:
    out = bytearray(value)
    st0, body0, _ = _d3s1.extract_envelope(value)
    if st0 != 0x32:
        raise SystemExit(f"evidence subtype {st0:#x}")
    idx = bytes(out).find(body0)
    if idx < 0 or len(body0) != len(body):
        raise SystemExit("evidence body replace fail")
    out[idx : idx + len(body)] = body
    out[-4:] = _d3s1.be32(_d3s1.crc32c(bytes(out[:-4])))
    return bytes(out)


def _dlv_evidence_key(owner_raw: bytes, slot: int) -> bytes:
    if len(owner_raw) != 80:
        raise SystemExit(f"DLV owner_raw must be 80, got {len(owner_raw)}")
    components = (
        _d3s1.be16(EV_OWNER_KIND_DLV)
        + _d3s1.raw16(owner_raw)
        + _d3s1.be32(int(slot))
    )
    return _d3s1.bkey(6, 0x32, 5, _d3s1.composite(0x32, components))


def _build_dlv_sum_empty(dlv_pvd: bytes) -> Dict[str, str]:
    cat = _d1_catalog()
    tmpl = from_hex(cat[D1_EV_DLV_SUM_EMPTY_ID]["value_hex"])
    st, body, _ = _d3s1.extract_envelope(tmpl)
    if st != 0x32 or len(body) != EV_DLV_BODY_LEN:
        raise SystemExit("EV_DLV SUM_EMPTY template unexpected")
    owner_raw = bytes(body[6:86])
    val = _d3s1.patch_pvd(tmpl, dlv_pvd)
    if _d3s1.domain_value_framing(val) != "current":
        raise SystemExit("EV_DLV SUM_EMPTY framing fail after PVD")
    key = _dlv_evidence_key(owner_raw, 0)
    # Catalog key for slot0 must match rebuilt composite.
    catalog_key = from_hex(cat[D1_EV_DLV_SUM_EMPTY_ID]["key_hex"])
    if key != catalog_key:
        raise SystemExit("EV_DLV slot0 key rebuild mismatch")
    if s1.family6_current_row_s3_status(key, val) != "OK":
        raise SystemExit("EV_DLV SUM_EMPTY not S3-OK")
    return {"key_hex": hex_of(key), "value_hex": hex_of(val)}


def _build_dlv_raw_unused(slot: int, dlv_pvd: bytes) -> Dict[str, str]:
    """Construct DELIVERY-owned RAW UNUSED cell from D1 RAW_MAT template.

    Independent body zeroing after identity/slot/state (docs/17 §8.3 shape 3).
    """
    if not (1 <= int(slot) <= 8):
        raise SystemExit(f"RAW UNUSED slot out of domain: {slot}")
    cat = _d1_catalog()
    tmpl = from_hex(cat[D1_EV_DLV_RAW_MAT_ID]["value_hex"])
    st, body, _ = _d3s1.extract_envelope(tmpl)
    if st != 0x32 or len(body) != EV_DLV_BODY_LEN:
        raise SystemExit("EV_DLV RAW_MAT template unexpected")
    b = bytearray(body)
    owner_raw = bytes(b[6:86])
    struct.pack_into(">H", b, EV_CELL_KIND_BODY_OFF, EV_CELL_KIND_RAW)
    struct.pack_into(">I", b, EV_SLOT_BODY_OFF, int(slot))
    struct.pack_into(">H", b, EV_CELL_STATE_BODY_OFF, EV_CELL_STATE_UNUSED)
    # Zero material tail after reserved following state (offset 158 for DLV).
    for off in range(158, len(b)):
        b[off] = 0
    val = _replace_ev_body_any(tmpl, bytes(b))
    val = _d3s1.patch_pvd(val, dlv_pvd)
    if _d3s1.domain_value_framing(val) != "current":
        raise SystemExit("EV_DLV RAW UNUSED framing fail")
    key = _dlv_evidence_key(owner_raw, slot)
    if s1.family6_current_row_s3_status(key, val) != "OK":
        raise SystemExit(f"EV_DLV RAW UNUSED slot{slot} not S3-OK")
    return {"key_hex": hex_of(key), "value_hex": hex_of(val)}


def build_dsd1_fixture() -> Tuple[
    Dict[str, Any], List[Dict[str, str]], Dict[str, Any]
]:
    """One D1-valid snapshot for all DSD1 composition sessions.

    Domain material (APPLICATION_FIRST delivery graph):
      DELIVERY + RESULT_CACHE(app=1,reply=1,PVD=DLV) + DLV-owned ATTEMPT
      + REVERSE_REPLY RECEIPT + CANCEL_STATE NONE (cancel_attempt_id=0 → B=0)
      + EVIDENCE slots 0..L (SUMMARY empty + RAW UNUSED; equation 0==0+0)

    Constructibility notes (no guesswork):
      - Single RC key shared by all RC catalog variants → one RC body only.
      - CS_DLV_NONE PRESENT satisfies Mode14 DS gate and Mode22 cancel=0.
      - RESULT_POS non-ACTIVE ⇒ Mode19 CALLBACK expect ABSENT (no RES row).
      - Mode23 carrier is APP_FIRST RC; requires L+1 DLV EVIDENCE cells.
    """
    _assert_authority_pins()
    cat = _d1_catalog()
    binding = s1.default_binding_fields()
    L = int(binding["limits"]["max_evidence_per_target"])
    if L != MODE23_ACCEPTED_L:
        raise SystemExit(f"accepted L pin drift: {L} != {MODE23_ACCEPTED_L}")

    rows22, named22, dlv_pvd = _mode22_material_rows(include_rc=True)
    _, named24, _ = _mode24_material_rows(include_rc=True, reply_count=1)

    # RESULT_CACHE: keep app=1 from D1 RESULT_POS; set reply_count=1; PVD→DLV.
    rc_val = _patch_rc_reply_count(from_hex(named22["rc"]["value_hex"]), 1)
    rc_val = _d3s1.patch_pvd(rc_val, dlv_pvd)
    app_n, rc_draw, rc_txn = _parse_rc_app_attempt_and_delivery(rc_val)
    reply_n, _, _ = _parse_rc_reply_count_and_delivery(rc_val)
    if app_n != 1 or reply_n != 1:
        raise SystemExit(f"RC app/reply pin fail: app={app_n} reply={reply_n}")
    if _d3s1.domain_value_framing(rc_val) != "current":
        raise SystemExit("RC framing not current")
    rc_row = {
        "key_hex": named22["rc"]["key_hex"],
        "value_hex": hex_of(rc_val),
    }

    # CANCEL_STATE NONE: PRESENT for Mode14; cancel_attempt_id zero ⇒ Mode22 B=0.
    cs = cat[D1_CS_DLV_NONE_ID]
    cs_val = _d3s1.patch_pvd(from_hex(cs["value_hex"]), dlv_pvd)
    if _d3s1.domain_value_framing(cs_val) != "current":
        raise SystemExit("CS framing not current")
    cs_row = {"key_hex": cs["key_hex"], "value_hex": hex_of(cs_val)}

    dlv_draw, dlv_txn, _ = _parse_delivery_raw_and_primary(
        from_hex(named22["delivery"]["value_hex"])
    )
    if rc_draw != dlv_draw or rc_txn != dlv_txn:
        raise SystemExit("RC/DELIVERY identity mismatch")

    ev_rows = [_build_dlv_sum_empty(dlv_pvd)]
    for slot in range(1, L + 1):
        ev_rows.append(_build_dlv_raw_unused(slot, dlv_pvd))
    if len(ev_rows) != L + 1:
        raise SystemExit("EVIDENCE slot count != L+1")

    profile = s1.encode_all_profile_rows(binding)
    domain = [
        named22["delivery"],
        rc_row,
        named22["att"],
        named24["rr"],
        cs_row,
    ] + ev_rows
    # Reject forbidden Mode28 / dual inventory pollution.
    for r in domain:
        k = from_hex(r["key_hex"])
        if len(k) >= 10 and k[8] == 6 and k[9] == 0x34:
            raise SystemExit("DSD1 fixture must not include ATTEMPT_ID_INDEX")
    all_rows = sorted(
        list(profile) + list(domain), key=lambda r: from_hex(r["key_hex"])
    )
    if len(all_rows) != 17 + 9:
        raise SystemExit(
            f"DSD1 fixture row count drift: {len(all_rows)} != 26"
        )
    # Fail-closed domain subtype multiset pin.
    st_list = [
        from_hex(r["key_hex"])[9]
        for r in all_rows
        if len(from_hex(r["key_hex"])) >= 10 and from_hex(r["key_hex"])[8] == 6
    ]
    if st_list != [0x31, 0x32, 0x32, 0x32, 0x32, 0x33, 0x40, 0x41, 0x42]:
        raise SystemExit(f"DSD1 domain subtype order pin fail: {st_list}")

    meta = {
        "L": L,
        "n_ok": len(all_rows),
        "domain_count": 9,
        "dlv_pvd_hex": hex_of(dlv_pvd),
        "app_attempt_count": 1,
        "reply_count": 1,
        "cancel_declared": 0,
    }
    return binding, all_rows, meta


def _s1_session(mode: int, binding: Dict[str, Any], rows: List[Dict[str, str]]) -> Dict[str, Any]:
    kind_map = {
        11: "dsd1_s1_mode11_result_exact1",
        14: "dsd1_s1_mode14_cancel_gate",
        17: "dsd1_s1_mode17_delivery_result_pvd",
        19: "dsd1_s1_mode19_callback_gate",
    }
    if mode not in kind_map:
        raise SystemExit(f"unexpected S1 mode {mode}")
    vec = {
        "id": f"DSD1_S1_MODE{mode}",
        "kind": kind_map[mode],
        "mode": mode,
        "candidate_binding": copy.deepcopy(binding),
        "rows": copy.deepcopy(rows),
        "calls": s1.std_scan_calls(mode),
        "faults": [],
        "alt_rows": {},
    }
    expected = s1.run_case(vec)
    if expected["final_status"] != "OK" or int(expected["adopted"]) != 1:
        raise SystemExit(
            f"S1 mode{mode} composition fixture must COMPLETE: "
            f"{expected['final_status']} adopted={expected['adopted']}"
        )
    if int(expected["mutation_calls"]) != 0:
        raise SystemExit(f"S1 mode{mode} mutation_calls must be 0")
    if expected["port_trace"].count("begin:READ_ONLY") != 1:
        raise SystemExit(f"S1 mode{mode} must be single READ_ONLY txn")
    # Stamp per-call expected_status from reference model.
    calls = copy.deepcopy(vec["calls"])
    # run_case already mutated stamped expected_status into vec['calls']
    # via the object we passed — rebuild cleanly.
    vec2 = {
        "id": vec["id"],
        "kind": vec["kind"],
        "mode": mode,
        "candidate_binding": copy.deepcopy(binding),
        "rows": copy.deepcopy(rows),
        "calls": s1.std_scan_calls(mode),
        "faults": [],
        "alt_rows": {},
    }
    expected = s1.run_case(vec2)
    return {
        "id": f"DSD1_SESSION_S1_MODE{mode}",
        "kind": kind_map[mode],
        "family": "s1",
        "mode": mode,
        "calls": copy.deepcopy(vec2["calls"]),
        "expected": expected,
    }


def _count_peer_gets(port_trace: Sequence[str]) -> int:
    peer = 0
    after_open = False
    for t in port_trace:
        if t == "begin:READ_ONLY":
            after_open = False
        elif t == "iter_open:prefix0":
            after_open = True
        elif after_open and t == "get":
            peer += 1
    return peer


def _s2_expected_common(
    *,
    n_ok: int,
    port_trace: List[str],
    n_open: int,
    d3_peer: int,
    d3_appl: int,
    count_mask: int,
    bind_mask: int,
) -> Dict[str, Any]:
    if port_trace.count("begin:READ_ONLY") != 1:
        raise SystemExit("S2 session must be single READ_ONLY txn")
    if port_trace.count("iter_open:prefix0") != n_open:
        raise SystemExit(
            f"S2 iter_open count {port_trace.count('iter_open:prefix0')} "
            f"!= {n_open}"
        )
    if _count_peer_gets(port_trace) != d3_peer:
        raise SystemExit(
            f"S2 peer get count {_count_peer_gets(port_trace)} != {d3_peer}"
        )
    return {
        "final_status": "OK",
        "adopted": 1,
        "state_after": "DONE",
        "recognizable_future_seen": 0,
        "family14_row_count": 17,
        "current_domain_key_count": 9,
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
        "port_trace": list(port_trace),
        "has_sticky_primary": 0,
        "sticky_primary": "",
        "d3_peer_get_count": d3_peer,
        "d3_mode_applicable_count": d3_appl,
        "phase": PHASE_COMPLETE,
        "count_complete_mask": count_mask,
        "binding_complete_mask": bind_mask,
        "flags": FLAG_BASELINE_DONE | FLAG_COMPLETE_READY,
    }


def _s2_mode22_session(binding: Dict[str, Any], rows: List[Dict[str, str]], n_ok: int) -> Dict[str, Any]:
    """Independent Mode22 reference on the unified DSD1 fixture.

    SELECT finds RESULT_CACHE; CANCEL PRESENT NONE → B=0; CLEANUP ABSENT;
    FOCUS stream observes A=1; BIND_ATTEMPT on the single DLV-owned ATTEMPT.
    """
    walk = _walk_trace_segment(n_ok)
    port: List[str] = _begin_profile_port_prefix()
    # 1 BASELINE
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.append("iter_close")
    # 2 SELECT + CANCEL/CLEANUP setup gets at RC
    # domain lex: ATT, 4×EV, CS, DLV, RC, RR
    port.append("iter_open:prefix0")
    port.extend(["iter_next"] * 17)
    port.append("iter_next")  # ATT
    port.extend(["iter_next"] * 4)  # EV
    port.append("iter_next")  # CS
    port.append("iter_next")  # DLV
    port.append("iter_next")  # RC install
    port.append("get")  # CANCEL PRESENT NONE → B=0
    port.append("get")  # CLEANUP ABSENT
    port.append("iter_next")  # RR
    port.append("iter_next")  # NOT_FOUND
    port.append("iter_close")
    # 3 FOCUS stream
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.append("iter_close")
    # 4 SELECT empty → BIND
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.append("iter_close")
    # 5 BIND_ATTEMPT
    port.append("iter_open:prefix0")
    port.extend(["iter_next"] * 17)
    port.append("iter_next")  # ATT secondary
    port.append("get")  # carrier RC
    port.append("get")  # true primary DLV
    port.append("get")  # INDEX ABSENT peer
    port.extend(["iter_next"] * 4)  # EV
    port.append("iter_next")  # CS
    port.append("iter_next")  # DLV
    port.append("iter_next")  # RC
    port.append("iter_next")  # RR
    port.append("iter_next")  # NOT_FOUND
    port.append("iter_close")
    port.append("rollback")

    n_drive = 5
    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 22, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})
    expected = _s2_expected_common(
        n_ok=n_ok,
        port_trace=port,
        n_open=5,
        d3_peer=5,
        d3_appl=1,
        count_mask=MASK_ATTEMPT,
        bind_mask=MASK_ATTEMPT,
    )
    del binding  # binding identity already encoded in rows
    return {
        "id": "DSD1_SESSION_S2_MODE22",
        "kind": "dsd1_s2_mode22_attempt_cardinality",
        "family": "s2",
        "mode": 22,
        "calls": calls,
        "expected": expected,
    }


def _s2_mode23_session(binding: Dict[str, Any], rows: List[Dict[str, str]], n_ok: int) -> Dict[str, Any]:
    """Independent Mode23 reference: RC APP_FIRST carrier + slots 0..L.

    Empty SUMMARY equation (valid=0, M=0, overflow=0) + RAW UNUSED 1..L.
    """
    L = int(binding["limits"]["max_evidence_per_target"])
    n_cells = L + 1
    walk = _walk_trace_segment(n_ok)
    port: List[str] = _begin_profile_port_prefix()
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.append("iter_close")
    # SELECT + FOCUS known-slot matrix
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.extend(["get"] * n_cells)
    port.append("iter_close")
    # SELECT empty → BIND
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.append("iter_close")
    # BIND_EVIDENCE: 4 EVIDENCE secondaries × (carrier RC + primary DLV)
    port.append("iter_open:prefix0")
    port.extend(["iter_next"] * 17)
    port.append("iter_next")  # ATT
    for _ in range(n_cells):
        port.append("iter_next")  # EV
        port.append("get")  # carrier RC
        port.append("get")  # primary DLV
    port.append("iter_next")  # CS
    port.append("iter_next")  # DLV
    port.append("iter_next")  # RC
    port.append("iter_next")  # RR
    port.append("iter_next")  # NOT_FOUND
    port.append("iter_close")
    port.append("rollback")

    n_drive = 4
    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 23, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})
    expected = _s2_expected_common(
        n_ok=n_ok,
        port_trace=port,
        n_open=4,
        d3_peer=n_cells + 2 * n_cells,  # FOCUS matrix + BIND 2×cells
        d3_appl=n_cells,
        count_mask=MASK_EVIDENCE,
        bind_mask=MASK_EVIDENCE,
    )
    return {
        "id": "DSD1_SESSION_S2_MODE23",
        "kind": "dsd1_s2_mode23_evidence_slots",
        "family": "s2",
        "mode": 23,
        "calls": calls,
        "expected": expected,
    }


def _s2_mode24_session(binding: Dict[str, Any], rows: List[Dict[str, str]], n_ok: int) -> Dict[str, Any]:
    """Independent Mode24 reference: RC reply_count=1 + RR RECEIPT."""
    del binding
    walk = _walk_trace_segment(n_ok)
    port: List[str] = _begin_profile_port_prefix()
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.append("iter_close")
    # SELECT + FOCUS known-kind matrix (kinds 1..4)
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.extend(["get"] * 4)
    port.append("iter_close")
    # SELECT empty → BIND
    port.append("iter_open:prefix0")
    port.extend(walk)
    port.append("iter_close")
    # BIND_REPLY on RR: carrier RC + primary DLV
    port.append("iter_open:prefix0")
    port.extend(["iter_next"] * 17)
    port.append("iter_next")  # ATT
    port.extend(["iter_next"] * 4)  # EV
    port.append("iter_next")  # CS
    port.append("iter_next")  # DLV
    port.append("iter_next")  # RC
    port.append("iter_next")  # RR
    port.append("get")  # carrier RC
    port.append("get")  # primary DLV
    port.append("iter_next")  # NOT_FOUND
    port.append("iter_close")
    port.append("rollback")

    n_drive = 4
    calls: List[Dict[str, Any]] = [
        {"op": "begin_profiled_d3s2", "mode": 24, "expected_status": "OK"}
    ]
    for _ in range(n_drive):
        calls.append(
            {"op": "d3s2_drive", "row_budget": 256, "expected_status": "OK"}
        )
    calls.append({"op": "finalize", "expected_status": "OK"})
    expected = _s2_expected_common(
        n_ok=n_ok,
        port_trace=port,
        n_open=4,
        d3_peer=6,  # 4 known-kind + 2 BIND
        d3_appl=1,
        count_mask=MASK_REPLY,
        bind_mask=MASK_REPLY,
    )
    return {
        "id": "DSD1_SESSION_S2_MODE24",
        "kind": "dsd1_s2_mode24_reply_count",
        "family": "s2",
        "mode": 24,
        "calls": calls,
        "expected": expected,
    }


def build_document() -> Dict[str, Any]:
    binding, rows, meta = build_dsd1_fixture()
    sessions: List[Dict[str, Any]] = []
    for family, mode in SESSION_MODE_ORDER:
        if family == "s1":
            sessions.append(_s1_session(mode, binding, rows))
        elif mode == 22:
            sessions.append(_s2_mode22_session(binding, rows, meta["n_ok"]))
        elif mode == 23:
            sessions.append(_s2_mode23_session(binding, rows, meta["n_ok"]))
        elif mode == 24:
            sessions.append(_s2_mode24_session(binding, rows, meta["n_ok"]))
        else:
            raise SystemExit(f"unexpected session {family}/{mode}")

    kinds = {s["kind"] for s in sessions}
    if kinds != REQUIRED_SESSION_KINDS:
        raise SystemExit(
            f"session kind set mismatch: {sorted(kinds)} "
            f"!= {sorted(REQUIRED_SESSION_KINDS)}"
        )
    if len(sessions) != EXPECTED_SESSION_COUNT:
        raise SystemExit("session count drift")

    # Anti Mode28 / multi-mode / dual-bound claims in artifact.
    for s in sessions:
        if int(s["mode"]) == 28:
            raise SystemExit("Mode 28 forbidden")
        if s["family"] not in ("s1", "s2"):
            raise SystemExit("unknown family")
        # One mode per session.
        modes_in_calls = {
            int(c["mode"])
            for c in s["calls"]
            if "mode" in c and c["op"].startswith("begin_profiled")
        }
        if modes_in_calls != {int(s["mode"])}:
            raise SystemExit(f"session {s['id']} multi-mode begin")

    vector = {
        "id": "DSD1_MULTI_SESSION_S1_S2_COMPOSITION",
        "kind": "dsd1_multi_session_orchestration",
        "candidate_binding": copy.deepcopy(binding),
        "rows": copy.deepcopy(rows),
        "sessions": sessions,
        "notes": (
            "§18.13.16 DSD1 composition: seven self-contained sessions on one "
            "D1-valid APPLICATION_FIRST delivery fixture. Each session has its "
            "own begin + baseline + mode FOCUS/BIND + finalize DONE. Never "
            "dual-bound. Not Mode 28. Not one-baseline-all-modes. S2 alone does "
            "not claim DSD1 complete. mutation_calls=0 per session."
        ),
        "fixture_meta": meta,
    }
    return {
        "version": VERSION,
        "format": FORMAT,
        "scope": SCOPE,
        "vector_count": 1,
        "session_count": EXPECTED_SESSION_COUNT,
        "d1_authority": {
            "path": "spec/vectors/domain-store-v1.json",
            "format": D1_FORMAT,
            "sha256": D1_SHA256,
            "vector_count": D1_COUNT,
        },
        "crossrow_authority": {
            "path": "spec/vectors/domain-scan-crossrow-v1.json",
            "format": CROSSROW_FORMAT,
            "sha256": CROSSROW_SHA256,
            "vector_count": CROSSROW_COUNT,
            "note": (
                "Frozen sibling authority; this composition oracle does not "
                "append to or rewrite crossrow vectors."
            ),
        },
        "workspace": {
            "key_capacity": 255,
            "value_capacity": 4096,
            "previous_key_capacity": 255,
            "ceiling_bytes": 8192,
            "note": (
                "single 4096 value buffer; no second 4096; no full-ID set; "
                "S1 context ceiling 448; S2 context ceiling 320; dual-bound "
                "forbidden per session"
            ),
        },
        "vectors": [vector],
    }


def generate(path: Path) -> None:
    doc = build_document()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {path} vectors={len(doc['vectors'])} "
        f"sessions={doc['session_count']} rows={len(doc['vectors'][0]['rows'])}"
    )


def _composition_contract_error(data: Dict[str, Any]) -> Optional[str]:
    """Validate the composition-only claims independently of regeneration."""
    vectors = data.get("vectors")
    if not isinstance(vectors, list) or len(vectors) != 1:
        return "vector population"
    sessions = vectors[0].get("sessions")
    if not isinstance(sessions, list) or len(sessions) != EXPECTED_SESSION_COUNT:
        return "session population"
    modes = [int(s.get("mode", -1)) for s in sessions]
    if 28 in modes:
        return "Mode 28 present"
    if modes != [11, 14, 17, 19, 22, 23, 24]:
        return f"session mode order {modes}"
    families = [s.get("family") for s in sessions]
    if families != ["s1", "s1", "s1", "s1", "s2", "s2", "s2"]:
        return f"family order {families}"
    for session in sessions:
        session_id = session.get("id", "<unknown>")
        expected = session.get("expected", {})
        if int(expected.get("mutation_calls", -1)) != 0:
            return f"{session_id} mutation_calls"
        trace = expected.get("port_trace", [])
        if not isinstance(trace, list) or trace.count("begin:READ_ONLY") != 1:
            return f"{session_id} multi-txn"
        if expected.get("final_status") != "OK" or int(
            expected.get("adopted", -1)
        ) != 1:
            return f"{session_id} not COMPLETE"
        begin_modes = {
            int(call.get("mode", -1))
            for call in session.get("calls", [])
            if str(call.get("op", "")).startswith("begin_profiled")
        }
        if begin_modes != {int(session["mode"])}:
            return f"{session_id} multi-mode begin"
    return None


def check(path: Path) -> int:
    if not path.is_file():
        print(f"FAIL missing {path}", file=sys.stderr)
        return 1
    data = json.loads(path.read_text(encoding="utf-8"))
    expected = build_document()
    if data.get("format") != FORMAT:
        print(f"FAIL format {data.get('format')!r}", file=sys.stderr)
        return 1
    if int(data.get("vector_count", -1)) != EXPECTED_VECTOR_COUNT:
        print("FAIL vector_count", file=sys.stderr)
        return 1
    if int(data.get("session_count", -1)) != EXPECTED_SESSION_COUNT:
        print("FAIL session_count", file=sys.stderr)
        return 1
    if json.dumps(data, sort_keys=True) != json.dumps(expected, sort_keys=True):
        print(
            "FAIL document not deterministically equal to generator output",
            file=sys.stderr,
        )
        return 1
    contract_error = _composition_contract_error(data)
    if contract_error is not None:
        print(f"FAIL {contract_error}", file=sys.stderr)
        return 1
    print(
        f"ok {path} vectors=1 sessions=7 "
        f"modes=11/14/17/19/22/23/24 mutation0 single-txn-each"
    )
    return 0


def self_test() -> int:
    _assert_authority_pins()
    binding, rows, meta = build_dsd1_fixture()
    if meta["n_ok"] != 26:
        print("FAIL fixture n_ok", file=sys.stderr)
        return 1
    # S1 each mode COMPLETE via independent run_case.
    for mode in (11, 14, 17, 19):
        sess = _s1_session(mode, binding, rows)
        if sess["expected"]["adopted"] != 1:
            print(f"FAIL self-test S1 mode{mode}", file=sys.stderr)
            return 1
    # S2 port-trace peer-get pins.
    s22 = _s2_mode22_session(binding, rows, meta["n_ok"])
    s23 = _s2_mode23_session(binding, rows, meta["n_ok"])
    s24 = _s2_mode24_session(binding, rows, meta["n_ok"])
    if s22["expected"]["d3_peer_get_count"] != 5:
        print("FAIL mode22 peer", file=sys.stderr)
        return 1
    if s23["expected"]["d3_peer_get_count"] != 12:
        print("FAIL mode23 peer", file=sys.stderr)
        return 1
    if s24["expected"]["d3_peer_get_count"] != 6:
        print("FAIL mode24 peer", file=sys.stderr)
        return 1
    # Determinism: generate twice.
    d1 = build_document()
    d2 = build_document()
    if json.dumps(d1, sort_keys=True) != json.dumps(d2, sort_keys=True):
        print("FAIL non-deterministic document", file=sys.stderr)
        return 1
    negative_mutations = (
        ("mode28", lambda d: d["vectors"][0]["sessions"][0].__setitem__("mode", 28)),
        (
            "mutation call",
            lambda d: d["vectors"][0]["sessions"][0]["expected"].__setitem__(
                "mutation_calls", 1
            ),
        ),
        (
            "second transaction",
            lambda d: d["vectors"][0]["sessions"][0]["expected"][
                "port_trace"
            ].append("begin:READ_ONLY"),
        ),
    )
    for label, mutate in negative_mutations:
        noisy = copy.deepcopy(d1)
        mutate(noisy)
        if _composition_contract_error(noisy) is None:
            print(f"FAIL negative mutation undetected: {label}", file=sys.stderr)
            return 1
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "dsd1.json"
        generate(p)
        if check(p) != 0:
            return 1
        h = Path(td) / "fix.h"
        emit_c_fixture(p, h)
        h2 = Path(td) / "fix2.h"
        emit_c_fixture(p, h2)
        if h.read_bytes() != h2.read_bytes():
            print("FAIL emit-c-fixture non-deterministic", file=sys.stderr)
            return 1
        noisy = copy.deepcopy(d1)
        noisy["vectors"][0]["sessions"][0]["expected"][
            "d3_mode_applicable_count"
        ] = 999
        noisy_path = Path(td) / "noisy.json"
        noisy_path.write_text(
            json.dumps(noisy, indent=2) + "\n", encoding="utf-8"
        )
        try:
            emit_c_fixture(noisy_path, Path(td) / "noisy.h")
        except SystemExit:
            pass
        else:
            print("FAIL emit-c-fixture accepted non-canonical input", file=sys.stderr)
            return 1
    print("self-test ok")
    return 0


def _c_bytes_literal(data: bytes, name: str) -> List[str]:
    lines = [f"static const uint8_t {name}[] = {{"]
    chunk: List[str] = []
    for i, b in enumerate(data):
        chunk.append(f"0x{b:02x}u")
        if len(chunk) == 12:
            lines.append("    " + ", ".join(chunk) + ",")
            chunk = []
    if chunk:
        lines.append("    " + ", ".join(chunk) + ",")
    lines.append("};")
    return lines


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    if data.get("format") != FORMAT:
        raise SystemExit(f"emit-c-fixture format {data.get('format')!r}")
    expected = build_document()
    if json.dumps(data, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise SystemExit("emit-c-fixture refuses non-canonical DSD1 authority")
    contract_error = _composition_contract_error(data)
    if contract_error is not None:
        raise SystemExit(f"emit-c-fixture composition contract: {contract_error}")
    vectors = data["vectors"]
    lines: List[str] = []
    lines.append(
        "/* Generated by tools/domain_scan_dsd1_composition_vector_gen.py "
        "— do not edit. */"
    )
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_DSD1_COMPOSITION_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_DSD1_COMPOSITION_VECTOR_FIXTURE_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(
        f"#define NINLIL_DSD1_VECTOR_COUNT ((size_t){len(vectors)}u)"
    )
    lines.append(
        f"#define NINLIL_DSD1_SESSION_COUNT ((size_t){EXPECTED_SESSION_COUNT}u)"
    )
    lines.append("#define NINLIL_DSD1_MAX_TRACE ((size_t)512u)")
    lines.append("#define NINLIL_DSD1_MAX_KEY ((size_t)255u)")
    lines.append("#define NINLIL_DSD1_MAX_VALUE ((size_t)4096u)")
    lines.append("")
    lines.append("typedef struct ninlil_dsd1_binding {")
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
    lines.append("} ninlil_dsd1_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsd1_row {")
    lines.append("    const uint8_t *key;")
    lines.append("    uint32_t key_length;")
    lines.append("    const uint8_t *value;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dsd1_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsd1_call {")
    lines.append("    const char *op;")
    lines.append("    uint8_t mode;")
    lines.append("    uint32_t row_budget;")
    lines.append("    const char *expected_status;")
    lines.append("} ninlil_dsd1_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsd1_expected {")
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
    lines.append("} ninlil_dsd1_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsd1_session {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    const char *family;")
    lines.append("    uint8_t mode;")
    lines.append("    const ninlil_dsd1_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_dsd1_expected_t expected;")
    lines.append("} ninlil_dsd1_session_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsd1_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    ninlil_dsd1_binding_t candidate;")
    lines.append("    const ninlil_dsd1_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_dsd1_session_t *sessions;")
    lines.append("    size_t session_count;")
    lines.append("} ninlil_dsd1_vector_t;")
    lines.append("")

    def binding_literal(b: Dict[str, Any]) -> str:
        rid = from_hex(b["runtime_id_hex"])
        rids = ", ".join(f"0x{x:02x}u" for x in rid)
        lim = b["limits"]
        return (
            f"{{ {int(b['storage_schema'])}u, {int(b['role'])}u, "
            f"{int(b['environment'])}u, {{ {rids} }}, "
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
        # rows
        for ri, row in enumerate(vec["rows"]):
            kb = from_hex(row["key_hex"])
            vb = from_hex(row["value_hex"])
            lines.extend(_c_bytes_literal(kb, f"ninlil_dsd1_v{vi}_k{ri}"))
            lines.extend(_c_bytes_literal(vb, f"ninlil_dsd1_v{vi}_v{ri}"))
        lines.append(
            f"static const ninlil_dsd1_row_t ninlil_dsd1_v{vi}_rows[] = {{"
        )
        for ri, row in enumerate(vec["rows"]):
            kb = from_hex(row["key_hex"])
            vb = from_hex(row["value_hex"])
            lines.append(
                f"    {{ ninlil_dsd1_v{vi}_k{ri}, {len(kb)}u, "
                f"ninlil_dsd1_v{vi}_v{ri}, {len(vb)}u }},"
            )
        lines.append("};")
        lines.append("")

        for si, sess in enumerate(vec["sessions"]):
            # calls
            lines.append(
                f"static const ninlil_dsd1_call_t "
                f"ninlil_dsd1_v{vi}_s{si}_calls[] = {{"
            )
            for c in sess["calls"]:
                mode = int(c.get("mode", sess["mode"]))
                budget = int(c.get("row_budget", 0))
                lines.append(
                    f'    {{ "{c["op"]}", {mode}u, {budget}u, '
                    f'"{c["expected_status"]}" }},'
                )
            lines.append("};")
            # port_trace strings
            exp = sess["expected"]
            for ti, t in enumerate(exp["port_trace"]):
                lines.append(
                    f'static const char ninlil_dsd1_v{vi}_s{si}_t{ti}[] = "{t}";'
                )
            lines.append(
                f"static const char *const ninlil_dsd1_v{vi}_s{si}_trace[] = {{"
            )
            for ti in range(len(exp["port_trace"])):
                lines.append(f"    ninlil_dsd1_v{vi}_s{si}_t{ti},")
            lines.append("};")
            lines.append("")

        lines.append(
            f"static const ninlil_dsd1_session_t ninlil_dsd1_v{vi}_sessions[] = {{"
        )
        for si, sess in enumerate(vec["sessions"]):
            exp = sess["expected"]
            phase = int(exp.get("phase", 0))
            count_m = int(exp.get("count_complete_mask", 0))
            bind_m = int(exp.get("binding_complete_mask", 0))
            flags = int(exp.get("flags", 0))
            lines.append("    {")
            lines.append(f'        "{sess["id"]}",')
            lines.append(f'        "{sess["kind"]}",')
            lines.append(f'        "{sess["family"]}",')
            lines.append(f'        {int(sess["mode"])}u,')
            lines.append(
                f"        ninlil_dsd1_v{vi}_s{si}_calls, "
                f"{len(sess['calls'])}u,"
            )
            lines.append("        {")
            lines.append(f'            "{exp["final_status"]}",')
            lines.append(f'            {int(exp["adopted"])}u,')
            lines.append(f'            "{exp["state_after"]}",')
            lines.append(
                f'            {int(exp["recognizable_future_seen"])}u,'
            )
            lines.append(f'            {int(exp["family14_row_count"])}ull,')
            lines.append(
                f'            {int(exp["current_domain_key_count"])}ull,'
            )
            lines.append(f'            {int(exp["ok_row_count"])}ull,')
            lines.append(f'            {int(exp["profile_exact_active"])}u,')
            lines.append(f'            {int(exp["profile_mismatch"])}u,')
            lines.append(
                f'            {int(exp["future_profile_candidate"])}u,'
            )
            lines.append(
                f'            {int(exp["profile_get_present_mask"])}u,'
            )
            lines.append(
                f'            {int(exp["family14_iter_seen_mask"])}u,'
            )
            lines.append(f'            {int(exp["reopen_required"])}u,')
            lines.append(f'            {int(exp["close_count"])}u,')
            lines.append(f'            {int(exp["mutation_calls"])}u,')
            lines.append(f'            {int(exp["iter_open_count"])}u,')
            lines.append(
                f"            ninlil_dsd1_v{vi}_s{si}_trace, "
                f"{len(exp['port_trace'])}u,"
            )
            lines.append(f'            {int(exp["has_sticky_primary"])}u,')
            sticky = exp.get("sticky_primary") or ""
            lines.append(f'            "{sticky}",')
            lines.append(f'            {int(exp["d3_peer_get_count"])}ull,')
            lines.append(
                f'            {int(exp["d3_mode_applicable_count"])}ull,'
            )
            lines.append(f"            {phase}u,")
            lines.append(f"            {count_m}u,")
            lines.append(f"            {bind_m}u,")
            lines.append(f"            {flags}u")
            lines.append("        }")
            lines.append("    },")
        lines.append("};")
        lines.append("")

    lines.append(
        "static const ninlil_dsd1_vector_t ninlil_dsd1_vectors[] = {"
    )
    for vi, vec in enumerate(vectors):
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(
            f"        ninlil_dsd1_v{vi}_rows, {len(vec['rows'])}u,"
        )
        lines.append(
            f"        ninlil_dsd1_v{vi}_sessions, {len(vec['sessions'])}u"
        )
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_DSD1_COMPOSITION_VECTOR_FIXTURE_H */")
    lines.append("")
    header_path.parent.mkdir(parents=True, exist_ok=True)
    header_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {header_path} ({header_path.stat().st_size} bytes)")


def main(argv: List[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
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
    if cmd == "self-test":
        return self_test()
    if cmd == "emit-c-fixture":
        if len(argv) != 4:
            print("usage: emit-c-fixture <json> <header>", file=sys.stderr)
            return 2
        emit_c_fixture(Path(argv[2]), Path(argv[3]))
        return 0
    print(f"unknown command {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
