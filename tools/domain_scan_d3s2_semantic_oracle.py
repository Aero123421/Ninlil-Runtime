#!/usr/bin/env python3
"""Independent D3-S2 declared-multicount close-semantics oracle.

This supplemental matrix is intentionally independent from the production C
scanner and codec. It models closed predicates in docs/17 section 18.13 for
modes 21..26. It is not the append-only crossrow sibling oracle required by
section 18.13.15 and does not claim the full D3-S2 implementation complete.

Usage:
  python3 tools/domain_scan_d3s2_semantic_oracle.py generate <json>
  python3 tools/domain_scan_d3s2_semantic_oracle.py check <json>
  python3 tools/domain_scan_d3s2_semantic_oracle.py emit-c-fixture <json> <header>
  python3 tools/domain_scan_d3s2_semantic_oracle.py self-test
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


FORMAT = "ninlil-domain-scan-declared-multicount-semantics-v1-d3s2"
VERSION = 1
MODES = frozenset(range(21, 27))
MASK_BY_MODE = {21: 0x03, 22: 0x01, 23: 0x04, 24: 0x08, 25: 0x10, 26: 0x20}
EXPECTED_VECTOR_COUNT = 31
CASE_KEYS = frozenset(
    {
        "id",
        "mode",
        "carrier_present",
        "secondary_present",
        "cleanup_skip",
        "bind_ok",
        "port_status",
        "declared",
        "observed",
        "evidence_l",
        "evidence_slot_mask",
        "evidence_empty_set",
        "declared_reply_count",
        "observed_reply_mask",
        "declared_retry_recent_n",
        "expected",
    }
)


def _popcount4(value: int) -> int:
    return bin(value & 0x0F).count("1")


def _required_evidence_mask(length: int) -> int:
    if not 0 <= length <= 8:
        raise ValueError("evidence L outside closed 0..8 range")
    return (1 << (length + 1)) - 1


def evaluate(case: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one closed D3-S2 semantic case without production imports."""

    unknown = set(case) - CASE_KEYS
    if unknown:
        raise ValueError(f"unknown case keys: {sorted(unknown)}")
    mode = int(case["mode"])
    if mode not in MODES:
        raise ValueError("mode must be 21..26")

    carrier_present = bool(case.get("carrier_present", True))
    secondary_present = bool(case.get("secondary_present", carrier_present))
    cleanup_skip = bool(case.get("cleanup_skip", False))
    bind_ok = bool(case.get("bind_ok", True))
    port_status = str(case.get("port_status", "OK"))
    declared = [int(v) for v in case.get("declared", [0, 0, 0])]
    observed = [int(v) for v in case.get("observed", [0, 0, 0])]
    if len(declared) != 3 or len(observed) != 3:
        raise ValueError("declared/observed require exactly A/B/C")
    if any(v < 0 or v > 0xFFFFFFFFFFFFFFFF for v in declared + observed):
        raise ValueError("counter outside u64")

    required = MASK_BY_MODE[mode]
    result = {
        "final_status": "OK",
        "state_after": "DONE",
        "phase_after": "COMPLETE",
        "has_sticky_primary": 0,
        "sticky_primary": "OK",
        "note_count": 0,
        "complete_ready": 1,
        "required_count_mask": required if carrier_present else 0,
        "count_complete_mask": required if carrier_present else 0,
        "required_binding_mask": required,
        "binding_complete_mask": required,
        "mutation_calls": 0,
    }

    def corrupt() -> dict[str, Any]:
        result.update(
            final_status="STORAGE_CORRUPT",
            state_after="FAILED",
            phase_after="FAILED",
            has_sticky_primary=1,
            sticky_primary="STORAGE_CORRUPT",
            note_count=1,
            complete_ready=0,
        )
        return result

    if port_status != "OK":
        result.update(
            final_status=port_status,
            state_after="FAILED",
            phase_after="FAILED",
            has_sticky_primary=1,
            sticky_primary=port_status,
            note_count=0,
            complete_ready=0,
        )
        return result

    # Empty carrier still performs the mode BIND walk.  An empty secondary
    # band closes; a live secondary without its declared carrier is an orphan.
    if not carrier_present:
        if secondary_present or not bind_ok:
            result["binding_complete_mask"] = 0
            return corrupt()
        return result

    if not bind_ok:
        result["binding_complete_mask"] = 0
        return corrupt()

    da, db, dc = declared
    oa, ob, oc = observed

    if mode in (21, 22):
        # CLEANUP_PLAN skips the ordinary count comparison, never BIND.
        if not cleanup_skip and (oa != da or ob != db):
            return corrupt()
        if mode == 21 and not cleanup_skip and (oc != dc or dc != da + db):
            return corrupt()
        if mode == 22 and (dc != 0 or oc != 0):
            return corrupt()
    elif mode == 23:
        length = int(case.get("evidence_l", 0))
        slots = int(case.get("evidence_slot_mask", 0))
        empty_set = bool(case.get("evidence_empty_set", False))
        if empty_set:
            if slots != 0 or any((da, db, dc, oa, ob, oc)):
                return corrupt()
        elif slots != _required_evidence_mask(length):
            return corrupt()
        elif da != oa + db or oc > dc or dc > da or db > da or ob != 0:
            return corrupt()
    elif mode == 24:
        reply_count = int(case.get("declared_reply_count", da))
        reply_mask = int(case.get("observed_reply_mask", 0))
        if not 0 <= reply_count <= 4 or reply_mask & ~0x0F:
            return corrupt()
        if da != reply_count or oa != da or oa != _popcount4(reply_mask):
            return corrupt()
        if db != 0 or dc != 0 or ob != 0 or oc != 0:
            return corrupt()
    elif mode == 25:
        retry_recent_n = int(case.get("declared_retry_recent_n", db))
        if retry_recent_n != db or db != min(da, 4):
            return corrupt()
        if oa != db or oc != dc or ob != 0:
            return corrupt()
        if dc not in (0, 1) or oc not in (0, 1):
            return corrupt()
    else:  # mode 26
        if oa != da or db != 0 or dc != 0 or ob != 0 or oc != 0:
            return corrupt()

    return result


def _case(case_id: str, mode: int, **values: Any) -> dict[str, Any]:
    case = {"id": case_id, "mode": mode, **values}
    case["expected"] = evaluate(case)
    return case


def build_vectors() -> list[dict[str, Any]]:
    vectors = [
        _case("mode21_counts_ok", 21, declared=[2, 1, 3], observed=[2, 1, 3]),
        _case("mode21_index_mismatch", 21, declared=[2, 1, 3], observed=[2, 1, 2]),
        _case("mode21_cleanup_skip_ok", 21, declared=[2, 1, 3], observed=[0, 0, 0], cleanup_skip=True),
        _case("mode22_app_first_ok", 22, declared=[2, 1, 0], observed=[2, 1, 0]),
        _case("mode22_index_lane_mbz", 22, declared=[2, 1, 0], observed=[2, 1, 1]),
        _case("mode23_slots_equation_ok", 23, declared=[2, 1, 1], observed=[1, 0, 1], evidence_l=1, evidence_slot_mask=0x03),
        _case("mode23_slot_missing", 23, declared=[2, 1, 1], observed=[1, 0, 1], evidence_l=1, evidence_slot_mask=0x01),
        _case("mode23_late_bound_fail", 23, declared=[1, 0, 0], observed=[1, 0, 1], evidence_l=1, evidence_slot_mask=0x03),
        _case("mode23_cancel_first_empty_success", 23, declared=[0, 0, 0], observed=[0, 0, 0], evidence_l=0, evidence_slot_mask=0, evidence_empty_set=True),
        _case("mode23_nonempty_success", 23, declared=[0, 0, 0], observed=[0, 0, 0], evidence_l=3, evidence_slot_mask=0x0F),
        _case("mode24_two_kinds_ok", 24, declared=[2, 0, 0], observed=[2, 0, 0], declared_reply_count=2, observed_reply_mask=0x05),
        _case("mode24_popcount_mismatch", 24, declared=[2, 0, 0], observed=[2, 0, 0], declared_reply_count=2, observed_reply_mask=0x01),
        _case("mode24_reply_zero_empty_success", 24, declared=[0, 0, 0], observed=[0, 0, 0], declared_reply_count=0, observed_reply_mask=0),
        _case("mode24_reply_one_success", 24, declared=[1, 0, 0], observed=[1, 0, 0], declared_reply_count=1, observed_reply_mask=0x01),
        _case("mode24_reply_one_missing", 24, declared=[1, 0, 0], observed=[0, 0, 0], declared_reply_count=1, observed_reply_mask=0),
        _case("mode25_retry_ok", 25, declared=[5, 4, 1], observed=[4, 0, 1], declared_retry_recent_n=4),
        _case("mode25_recent_missing", 25, declared=[3, 3, 1], observed=[2, 0, 1], declared_retry_recent_n=3),
        _case("mode25_cumulative_missing", 25, declared=[1, 1, 1], observed=[1, 0, 0], declared_retry_recent_n=1),
        _case("mode25_retry_zero_success", 25, declared=[0, 0, 1], observed=[0, 0, 1], declared_retry_recent_n=0),
        _case("mode25_retry_one_success", 25, declared=[1, 1, 1], observed=[1, 0, 1], declared_retry_recent_n=1),
        _case("mode25_recent_without_cumulative_fail", 25, carrier_present=False, secondary_present=True),
        _case("mode26_management_ok", 26, declared=[3, 0, 0], observed=[3, 0, 0]),
        _case("mode26_management_mismatch", 26, declared=[3, 0, 0], observed=[2, 0, 0]),
        _case("mode26_management_zero_success", 26, declared=[0, 0, 0], observed=[0, 0, 0]),
        _case("mode26_management_one_success", 26, declared=[1, 0, 0], observed=[1, 0, 0]),
        _case("mode26_management_without_spool_fail", 26, carrier_present=False, secondary_present=True),
        _case("empty_carrier_empty_secondary_ok", 21, carrier_present=False, secondary_present=False),
        _case("empty_carrier_orphan_fail", 21, carrier_present=False, secondary_present=True),
        _case("bind_primary_or_carrier_fail", 24, declared=[0, 0, 0], observed=[0, 0, 0], bind_ok=False),
        _case("port_failure_no_note", 25, port_status="STORAGE"),
        _case("mode22_cleanup_still_binds", 22, declared=[9, 1, 0], observed=[0, 0, 0], cleanup_skip=True, bind_ok=False),
    ]
    assert len(vectors) == EXPECTED_VECTOR_COUNT
    return vectors


def _canonical_payload() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "version": VERSION,
        "format": FORMAT,
        "scope": (
            "Independent D3-S2 §18.13 close semantics for modes 21..26. "
            "Wire rows, exact Port trace, and production bridge remain a later gate."
        ),
        "vector_count": EXPECTED_VECTOR_COUNT,
        "vectors": build_vectors(),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["content_sha256"] = hashlib.sha256(encoded).hexdigest()
    return payload


def _render() -> str:
    return json.dumps(_canonical_payload(), indent=2, sort_keys=True) + "\n"


BRIDGE_IDS = (
    "mode23_cancel_first_empty_success",
    "mode23_nonempty_success",
    "mode24_reply_zero_empty_success",
    "mode24_reply_one_success",
    "mode24_reply_one_missing",
    "mode25_retry_zero_success",
    "mode25_retry_one_success",
    "mode25_recent_without_cumulative_fail",
    "mode26_management_zero_success",
    "mode26_management_one_success",
    "mode26_management_without_spool_fail",
    "empty_carrier_empty_secondary_ok",
    "empty_carrier_orphan_fail",
    "port_failure_no_note",
)


def _c_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit_c_fixture(payload: dict[str, Any]) -> str:
    by_id = {v["id"]: v for v in payload["vectors"]}
    if set(BRIDGE_IDS) - set(by_id):
        raise ValueError("missing bridge vector")
    lines = [
        "/* GENERATED by domain_scan_d3s2_semantic_oracle.py; do not edit. */",
        "#ifndef NINLIL_DOMAIN_SCAN_D3S2_SEMANTIC_FIXTURE_H",
        "#define NINLIL_DOMAIN_SCAN_D3S2_SEMANTIC_FIXTURE_H",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "typedef struct ninlil_d3s2_semantic_vector {",
        "    const char *id;",
        "    uint8_t mode;",
        "    const char *final_status;",
        "    const char *phase_after;",
        "    uint8_t has_sticky_primary;",
        "    uint8_t note_count;",
        "    uint8_t complete_ready;",
        "    uint8_t mutation_calls;",
        "} ninlil_d3s2_semantic_vector_t;",
        "static const ninlil_d3s2_semantic_vector_t NINLIL_D3S2_SEMANTIC_VECTORS[] = {",
    ]
    for case_id in BRIDGE_IDS:
        vector = by_id[case_id]
        expected = vector["expected"]
        lines.append(
            "    { "
            + ", ".join(
                (
                    _c_string(case_id),
                    f"(uint8_t){int(vector['mode'])}u",
                    _c_string(str(expected["final_status"])),
                    _c_string(str(expected["phase_after"])),
                    f"(uint8_t){int(expected['has_sticky_primary'])}u",
                    f"(uint8_t){int(expected['note_count'])}u",
                    f"(uint8_t){int(expected['complete_ready'])}u",
                    f"(uint8_t){int(expected['mutation_calls'])}u",
                )
            )
            + " },"
        )
    lines.extend(
        (
            "};",
            "#define NINLIL_D3S2_SEMANTIC_VECTOR_COUNT \\",
            "    (sizeof(NINLIL_D3S2_SEMANTIC_VECTORS) / sizeof(NINLIL_D3S2_SEMANTIC_VECTORS[0]))",
            "#endif",
            "",
        )
    )
    return "\n".join(lines)


def self_test() -> None:
    vectors = build_vectors()
    assert {v["mode"] for v in vectors} == MODES
    assert any(v["expected"]["final_status"] == "OK" for v in vectors)
    assert any(v["expected"]["final_status"] == "STORAGE_CORRUPT" for v in vectors)
    port = next(v for v in vectors if v["id"] == "port_failure_no_note")
    assert port["expected"]["note_count"] == 0
    cleanup_bind = next(v for v in vectors if v["id"] == "mode22_cleanup_still_binds")
    assert cleanup_bind["expected"]["final_status"] == "STORAGE_CORRUPT"
    invalid = copy.deepcopy(vectors[0])
    invalid["unknown_future_field"] = 1
    try:
        evaluate(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown semantic case key accepted")

    # Mutation sensitivity: each positive mode case must be made corrupt by a
    # mode-relevant observed-lane mutation.
    positives = {
        21: "mode21_counts_ok",
        22: "mode22_app_first_ok",
        23: "mode23_slots_equation_ok",
        24: "mode24_two_kinds_ok",
        25: "mode25_retry_ok",
        26: "mode26_management_ok",
    }
    for mode, case_id in positives.items():
        original = next(v for v in vectors if v["id"] == case_id)
        mutated = copy.deepcopy(original)
        mutated.pop("expected", None)
        mutated["observed"][0] += 1
        assert evaluate(mutated)["final_status"] == "STORAGE_CORRUPT", mode

    assert _render() == _render()
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "a.json"
        path.write_text(_render(), encoding="utf-8")
        assert path.read_text(encoding="utf-8") == _render()
        first = emit_c_fixture(_canonical_payload())
        second = emit_c_fixture(_canonical_payload())
        assert first == second


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: generate <json> | check <json> | emit-c-fixture <json> <header> | self-test", file=sys.stderr)
        return 2
    command = argv[1]
    if command == "self-test" and len(argv) == 2:
        self_test()
        print("ok d3s2 semantic oracle self-test")
        return 0
    if command == "emit-c-fixture" and len(argv) == 4:
        source = Path(argv[2])
        target = Path(argv[3])
        payload = json.loads(source.read_text(encoding="utf-8"))
        if payload != _canonical_payload():
            print(f"stale or invalid: {source}", file=sys.stderr)
            return 1
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(emit_c_fixture(payload), encoding="utf-8")
        print(f"wrote {target} ({len(BRIDGE_IDS)} bridge vectors)")
        return 0
    if command not in {"generate", "check"} or len(argv) != 3:
        print("usage: generate <json> | check <json> | emit-c-fixture <json> <header> | self-test", file=sys.stderr)
        return 2
    path = Path(argv[2])
    rendered = _render()
    if command == "generate":
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"wrote {path} ({EXPECTED_VECTOR_COUNT} vectors)")
        return 0
    if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
        print(f"stale or missing: {path}", file=sys.stderr)
        return 1
    print(f"ok {path} ({EXPECTED_VECTOR_COUNT} vectors)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
