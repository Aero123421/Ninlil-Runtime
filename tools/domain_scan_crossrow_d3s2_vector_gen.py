#!/usr/bin/env python3
"""Independent D3-S2 crossrow sibling oracle (append-only; stdlib only).

Appends the first D3-S2 product-smoke suffix (Mode21..26 empty-carrier /
empty-secondary COMPLETE, one mode per session) onto the frozen D3-S1
94-vector prefix produced by tools/domain_scan_crossrow_vector_gen.py.

Does NOT invoke, import, link, or translate production C scanner/codec.
Does NOT claim full D3-S2 oracle complete — only the first 6-session
product smoke (docs/17 §18.13.4 / .5 / .9 / .15).

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
D3S2_SUFFIX_COUNT = 6
EXPECTED_VECTOR_COUNT = D3S1_PREFIX_COUNT + D3S2_SUFFIX_COUNT  # 100
CEILING = 8192

# Frozen D3-S1 prefix identity (byte-for-byte rebuild pin).
D3S1_FORMAT = "ninlil-domain-scan-crossrow-v1-d3s1"
D3S1_PREFIX_CONTENT_SHA256 = (
    "76b28d847be8cd7a95e8f1879400403abf702931a3de170a473c7c0f76d95468"
)
D3S1_PREFIX_FINGERPRINT_HASH = (
    "2c99af3c9b3aea228e4478c0d2739352f111fdd8c42303bf07177f8bb8ee8c58"
)

# Phase / mask constants (docs/17 §18.13; match domain_store_d3s2.h).
PHASE_COMPLETE = 15
FLAG_BASELINE_DONE = 0x01
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
# Drive chunks: baseline + SELECT + BIND set (Mode21 BIND has two subtypes).
MODE_DRIVE_COUNT = {21: 4, 22: 3, 23: 3, 24: 3, 25: 3, 26: 3}
MODE_ITER_OPEN = {21: 4, 22: 3, 23: 3, 24: 3, 25: 3, 26: 3}

D3S2_REQUIRED_KINDS = frozenset(
    {
        "mode21_empty_carrier_empty_secondary_ok",
        "mode22_empty_carrier_empty_secondary_ok",
        "mode23_empty_carrier_empty_secondary_ok",
        "mode24_empty_carrier_empty_secondary_ok",
        "mode25_empty_carrier_empty_secondary_ok",
        "mode26_empty_carrier_empty_secondary_ok",
    }
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
    "frozen 94-vector D3-S1 exact-1 prefix retained byte-for-byte; first "
    "D3-S2 product-smoke suffix = Mode21..26 empty-carrier/empty-secondary "
    "COMPLETE (one mode per independent session; single READ_ONLY txn; "
    "baseline once + sequential zero-prefix reopen; mode-scoped BIND set; "
    "mutation_calls=0). Does not claim full D3-S2 oracle complete, Stage5 "
    "D3 bind, D4, public Runtime, ESP-IDF, or hardware. TEST transport begin "
    "forbidden. Independent generator — production C not invoked."
)

SHA256_PROCEDURE = (
    "Do not embed full-file sha256 inside this artifact. Generator `check` "
    "proves deterministic rebuild equality against "
    "tools/domain_scan_crossrow_d3s2_vector_gen.py and fail-closed freezes the "
    "exact 94-vector D3-S1 prefix (fingerprint/order/expected/rows/calls) "
    "rebuilt from tools/domain_scan_crossrow_vector_gen.py. content_sha256 "
    "covers the document with sha256_procedure/content_sha256 fields set to "
    "empty strings before hashing."
)

OWNERSHIP_DEFAULT = (
    "D3-S2 independent crossrow oracle "
    "(tools/domain_scan_crossrow_d3s2_vector_gen.py); not production C; "
    "not Stage5 bridge; not D3-S2 complete claim (6-session product smoke only)"
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


def _walk_trace_segment() -> List[str]:
    """One zero-prefix full-band walk over 17 catalog rows (17 OK + NOT_FOUND)."""
    return ["iter_next"] * 18


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

    # Port trace: begin + 17 profile gets + n_open *(open + 18 next + close) + rollback
    port_trace: List[str] = ["begin:READ_ONLY"] + ["get"] * 17
    for i in range(n_open):
        port_trace.append("iter_open:prefix0")
        port_trace.extend(_walk_trace_segment())
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


def build_d3s2_suffix_vectors() -> List[Dict[str, Any]]:
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


def build_document() -> Dict[str, Any]:
    prefix_doc = freeze_d3s1_prefix()
    prefix_vectors = prefix_doc["vectors"]
    suffix_vectors = build_d3s2_suffix_vectors()
    vectors = list(prefix_vectors) + list(suffix_vectors)

    # prior_fingerprints: prefix keeps d3s1 hashes; suffix uses extended hash.
    prior_fingerprints: List[Dict[str, Any]] = []
    for v in prefix_vectors:
        prior_fingerprints.append(
            {
                "id": v["id"],
                "kind": v["kind"],
                "mode": v["mode"],
                "fingerprint": d3s1_vector_fingerprint(v),
            }
        )
    for v in suffix_vectors:
        prior_fingerprints.append(
            {
                "id": v["id"],
                "kind": v["kind"],
                "mode": v["mode"],
                "fingerprint": d3s2_vector_fingerprint(v),
            }
        )

    # Full prefix-hash over all fingerprints (append-only evolution).
    prefix_material = "".join(e["fingerprint"] for e in prior_fingerprints).encode(
        "utf-8"
    )
    prior_prefix_hash = hashlib.sha256(prefix_material).hexdigest()

    # Retained D3-S1-only fingerprint chain pin (first 94).
    d3s1_only_material = "".join(
        e["fingerprint"] for e in prior_fingerprints[:D3S1_PREFIX_COUNT]
    ).encode("utf-8")
    d3s1_only_hash = hashlib.sha256(d3s1_only_material).hexdigest()
    if d3s1_only_hash != D3S1_PREFIX_FINGERPRINT_HASH:
        raise SystemExit(
            "prefix fingerprint chain drift vs frozen D3-S1 pin "
            f"(got {d3s1_only_hash})"
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

    vectors = data["vectors"]
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        return _fail_check(
            f"vector count {len(vectors)} != pin {EXPECTED_VECTOR_COUNT}"
        )

    err = _assert_prefix_identity(vectors, prefix_doc)
    if err:
        return _fail_check(err)

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

    # Suffix-specific pins.
    suffix = vectors[D3S1_PREFIX_COUNT:]
    if len(suffix) != D3S2_SUFFIX_COUNT:
        return _fail_check("suffix length mismatch")
    for j, vec in enumerate(suffix):
        mode = 21 + j
        if int(vec["mode"]) != mode:
            return _fail_check(f"suffix[{j}] mode order pin fail")
        if vec["kind"] != f"mode{mode}_empty_carrier_empty_secondary_ok":
            return _fail_check(f"suffix[{j}] kind pin fail")
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
        # Single-session product smoke: no multi-mode.
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
        # Rebuild equality vs generator model.
        exp_calls, exp_expected = run_d3s2_empty_carrier_case(
            mode, vec["candidate_binding"], vec["rows"]
        )
        if vec["calls"] != exp_calls:
            return _fail_check(f"{vec['id']}: calls != independent model")
        if vec["expected"] != exp_expected:
            return _fail_check(f"{vec['id']}: expected != independent model")

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
            "self-test ok (prefix freeze + suffix pins + forbidden ops + clean pass)"
        )
        return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    """Emit D3-S1 94-array (compat) + separate D3-S2 suffix array/type/count=6."""
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

    # ---- D3-S2 suffix 6 ----
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
