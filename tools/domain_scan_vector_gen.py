#!/usr/bin/env python3
"""Independent D2-S1 domain-scan vector oracle (stdlib only).

Does NOT invoke, import, link, or translate the production C scanner.
Implements a closed reference model of docs/17 §15.1–15.7 / §15.4 S1.

Usage:
  python3 tools/domain_scan_vector_gen.py generate <path>
  python3 tools/domain_scan_vector_gen.py check <path>
  python3 tools/domain_scan_vector_gen.py emit-c-fixture <json> <c-header>
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

FORMAT = "ninlil-domain-scan-v1-d2s1"
VERSION = 1
ROOT_V1 = bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x01])
KEY_CAP = 255
VALUE_CAP = 4096
PREV_CAP = 255
CEILING = 8192

STATUS = {
    "OK": 0,
    "INVALID_ARGUMENT": 1,
    "UNSUPPORTED": 3,
    "CAPACITY_EXHAUSTED": 9,
    "STORAGE": 10,
    "STORAGE_CORRUPT": 11,
    "STORAGE_COMMIT_UNKNOWN": 12,
    "WOULD_BLOCK": 15,
    "INVALID_STATE": 16,
}


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


def nlr1(record_type: int, record_version: int, payload: bytes) -> bytes:
    head = b"NLR1" + be16(record_type) + be16(record_version) + be32(len(payload))
    body = head + payload
    return body + be32(crc32c(body))


def runtime_key_binding() -> bytes:
    return ROOT_V1 + bytes([0x01])


def runtime_key_identity() -> bytes:
    return ROOT_V1 + bytes([0x02])


def runtime_key_counter(suffix: int) -> bytes:
    return ROOT_V1 + bytes([0x03, suffix])


def runtime_key_capacity(suffix: int) -> bytes:
    return ROOT_V1 + bytes([0x04, suffix])


def domain_key_u64(family: int, subtype: int, value: int) -> bytes:
    return ROOT_V1 + bytes([family, subtype, 1, 3, 8]) + be64(value)


def domain_key_id128(family: int, subtype: int, identity: bytes) -> bytes:
    assert len(identity) == 16
    return ROOT_V1 + bytes([family, subtype, 1, 2, 16]) + identity


def future_key() -> bytes:
    return bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x02, 0x10, 0x20, 0x01, 0x01, 0x00])


def future_value() -> bytes:
    return nlr1(6, 2, b"\x01\x02\x03\x04")


def malformed_current_key() -> bytes:
    return ROOT_V1 + bytes([0x06, 0x10])


def is_exact_family14(key: bytes) -> bool:
    if len(key) < 9 or key[:8] != ROOT_V1:
        return False
    if len(key) == 9 and key[8] in (0x01, 0x02):
        return True
    if len(key) == 10:
        if key[8] == 0x03 and 1 <= key[9] <= 4:
            return True
        if key[8] == 0x04 and 1 <= key[9] <= 11:
            return True
    return False


def nlr1_valid(value: bytes) -> bool:
    if len(value) < 16 or len(value) > 4096 or value[:4] != b"NLR1":
        return False
    payload_len = struct.unpack(">I", value[8:12])[0]
    if payload_len != len(value) - 16 or payload_len > 4096 - 16:
        return False
    stored = struct.unpack(">I", value[12 + payload_len : 16 + payload_len])[0]
    return stored == crc32c(value[: 12 + payload_len])


def identity_kind_len_ok(kind: int, length: int) -> bool:
    return {
        1: length == 0,
        2: length == 16,
        3: length == 8,
        4: length == 32,
        5: length == 32,
    }.get(kind, False)


def subtype_expected_kind(family: int, subtype: int) -> Optional[int]:
    if family == 0x05 and subtype == 0x01:
        return 2
    if family != 0x06:
        return None
    if subtype in (0x60, 0x62, 0x64):
        return 1
    if subtype in (0x20, 0x22, 0x34, 0x50):
        return 2
    if subtype in (0x21, 0x26, 0x27):
        return 3
    if subtype in (
        0x10, 0x11, 0x23, 0x24, 0x25, 0x30, 0x31, 0x32, 0x33, 0x40, 0x41, 0x42,
        0x51, 0x52, 0x61, 0x63, 0x7D, 0x7E, 0x7F,
    ):
        return 5
    return None


def current_key_fields_ok(key: bytes) -> bool:
    if len(key) < 13 or len(key) > 45 or key[:8] != ROOT_V1:
        return False
    family, subtype, fmt, kind, id_len = key[8], key[9], key[10], key[11], key[12]
    if fmt != 1:
        return False
    expected = subtype_expected_kind(family, subtype)
    if expected is None or kind != expected:
        return False
    if not identity_kind_len_ok(kind, id_len):
        return False
    return len(key) == 13 + id_len


def classify_key(key: bytes) -> str:
    if not key or len(key) > 255:
        return "MALFORMED"
    if len(key) >= 8 and key[:7] == ROOT_V1[:7] and key[7] >= 2 and len(key) <= 255:
        return "RECOGNIZABLE_FUTURE"
    if len(key) < 8 or key[:8] != ROOT_V1:
        return "MALFORMED"
    if len(key) < 13 or len(key) > 45:
        return "MALFORMED"
    if current_key_fields_ok(key):
        return "CURRENT"
    return "MALFORMED"


def classify_row(key: bytes, value: bytes) -> str:
    kc = classify_key(key)
    if kc == "CURRENT":
        return "CURRENT"
    if (
        len(key) >= 8
        and len(key) <= 255
        and key[:7] == ROOT_V1[:7]
        and key[7] >= 2
        and 16 <= len(value) <= 4096
        and nlr1_valid(value)
    ):
        return "RECOGNIZABLE_FUTURE"
    return "MALFORMED"


def key_strictly_increases(prev: bytes, key: bytes) -> bool:
    n = min(len(prev), len(key))
    for i in range(n):
        if prev[i] < key[i]:
            return True
        if prev[i] > key[i]:
            return False
    return len(key) > len(prev)


def faults_list(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normative: faults is an array of objects."""
    faults = case.get("faults", [])
    if faults is None:
        return []
    if isinstance(faults, dict):
        # Reject legacy object form during check; normalize only if empty.
        raise ValueError("faults must be an array, not an object")
    return list(faults)


def find_fault(faults: List[Dict[str, Any]], op: str, call_no: int) -> Optional[Dict[str, Any]]:
    for f in faults:
        if f.get("op") == op and int(f.get("on_call", 0)) == call_no:
            return f
    return None


class ScannerOracle:
    def __init__(self) -> None:
        self.state = "IDLE"
        self.has_previous = False
        self.previous = b""
        self.has_sticky = False
        self.sticky = "OK"
        self.future_seen = 0
        self.family14 = 0
        self.current = 0
        self.ok_rows = 0
        self.reopen = 0
        self.cleanup_status = "OK"
        self.port_trace: List[str] = []
        # Schema field only (always 0 here). Production mutation-zero is gated
        # by the scripted spy in the C bridge, not by this independent model.
        self.mutation_calls = 0
        self.iter_pos = 0
        self.txn_live = False
        self.iter_live = False
        self.fence_pending = False
        self.close_count = 0

    def _set_sticky(self, status: str) -> None:
        if not self.has_sticky:
            self.has_sticky = True
            self.sticky = status

    def _checked_inc(self, attr: str) -> Optional[str]:
        val = getattr(self, attr)
        if val == (1 << 64) - 1:
            return "STORAGE_CORRUPT"
        setattr(self, attr, val + 1)
        return None

    def _fence(self) -> None:
        self.port_trace.append("close")
        self.close_count += 1
        self.reopen = 1
        self.fence_pending = False

    def begin(self, faults: List[Dict[str, Any]]) -> str:
        if self.state != "IDLE":
            return "INVALID_STATE"
        bf = find_fault(faults, "begin", 1)
        self.port_trace.append("begin:READ_ONLY")
        if bf is not None:
            shape = bf.get("shape", "natural")
            if shape == "ok_null":
                self._fence()
                self.state = "DONE"
                self._set_sticky("STORAGE_CORRUPT")
                return "STORAGE_CORRUPT"
            if shape == "error_with_handle":
                self.port_trace.append("rollback")
                self._fence()
                self.state = "DONE"
                self._set_sticky("STORAGE_CORRUPT")
                return "STORAGE_CORRUPT"
        self.txn_live = True
        iof = find_fault(faults, "iter_open", 1)
        self.port_trace.append("iter_open:prefix0")
        if iof is not None:
            shape = iof.get("shape", "natural")
            if shape == "ok_null":
                # Shape corruption: cleanup txn + fence even if rollback OK.
                self.fence_pending = True
                self.port_trace.append("rollback")
                self.txn_live = False
                self._fence()
                self.state = "DONE"
                self._set_sticky("STORAGE_CORRUPT")
                return "STORAGE_CORRUPT"
            if shape == "error_with_handle":
                self.fence_pending = True
                self.port_trace.append("iter_close")
                self.port_trace.append("rollback")
                self.txn_live = False
                self.iter_live = False
                self._fence()
                self.state = "DONE"
                self._set_sticky("STORAGE_CORRUPT")
                return "STORAGE_CORRUPT"
        self.iter_live = True
        self.state = "OPEN"
        self.iter_pos = 0
        return "OK"

    def advance(
        self,
        rows: List[Tuple[bytes, bytes]],
        row_budget: int,
        faults: List[Dict[str, Any]],
    ) -> str:
        if self.state != "OPEN":
            return "INVALID_STATE"
        if row_budget == 0:
            return "INVALID_ARGUMENT"
        consumed = 0
        while consumed < row_budget:
            self.port_trace.append("iter_next")
            call_no = self.port_trace.count("iter_next")
            nf = find_fault(faults, "iter_next", call_no)
            if nf is not None:
                shape = nf.get("shape", "natural")
                if shape in ("bts", "not_found_poison"):
                    self._set_sticky("STORAGE_CORRUPT")
                    self.state = "FAILED"
                    return "STORAGE_CORRUPT"
                if shape == "io_error":
                    self._set_sticky("STORAGE")
                    self.state = "FAILED"
                    return "STORAGE"
                if shape == "unknown":
                    self.fence_pending = True
                    self._set_sticky("STORAGE_CORRUPT")
                    self.state = "FAILED"
                    return "STORAGE_CORRUPT"
            if self.iter_pos >= len(rows):
                self.state = "EXHAUSTED"
                return "OK"
            key, value = rows[self.iter_pos]
            self.iter_pos += 1
            if not (1 <= len(key) <= KEY_CAP) or len(value) > VALUE_CAP:
                self._set_sticky("STORAGE_CORRUPT")
                self.state = "FAILED"
                return "STORAGE_CORRUPT"
            if self.has_previous and not key_strictly_increases(self.previous, key):
                self._set_sticky("STORAGE_CORRUPT")
                self.state = "FAILED"
                return "STORAGE_CORRUPT"
            # Match production: preflight ok_row headroom before classification
            # or previous-key mutation (no partial diagnostics on overflow).
            if self.ok_rows == (1 << 64) - 1:
                self._set_sticky("STORAGE_CORRUPT")
                self.state = "FAILED"
                return "STORAGE_CORRUPT"
            if is_exact_family14(key):
                err = self._checked_inc("family14")
                if err:
                    self._set_sticky(err)
                    self.state = "FAILED"
                    return err
            else:
                cls = classify_row(key, value)
                if cls == "CURRENT":
                    err = self._checked_inc("current")
                    if err:
                        self._set_sticky(err)
                        self.state = "FAILED"
                        return err
                elif cls == "RECOGNIZABLE_FUTURE":
                    self.future_seen = 1
                else:
                    self._set_sticky("STORAGE_CORRUPT")
                    self.state = "FAILED"
                    return "STORAGE_CORRUPT"
            self.previous = key
            self.has_previous = True
            # Preflighted above; safe known increment (never wraps).
            self.ok_rows += 1
            consumed += 1
        return "OK"

    def _cleanup(self, faults: List[Dict[str, Any]]) -> str:
        if self.iter_live and self.txn_live:
            self.port_trace.append("iter_close")
            self.iter_live = False
        if self.txn_live:
            self.port_trace.append("rollback")
            rb_call = self.port_trace.count("rollback")
            self.txn_live = False
            self.iter_live = False
            rf = find_fault(faults, "rollback", rb_call)
            if rf is not None and str(rf.get("status", "OK")) not in ("OK", "0"):
                self.cleanup_status = "IO_ERROR"
                self._fence()
                self.state = "DONE"
                if self.has_sticky:
                    return self.sticky
                return "STORAGE"
        if self.fence_pending:
            self._fence()
        self.state = "DONE"
        return "OK"

    def finalize(self, faults: List[Dict[str, Any]]) -> Tuple[str, int]:
        if self.state not in ("EXHAUSTED", "FAILED"):
            return "INVALID_STATE", 0
        prior = self.state
        cleanup = self._cleanup(faults)
        if self.has_sticky:
            status = self.sticky
        elif cleanup != "OK":
            status = cleanup
        elif self.future_seen:
            status = "UNSUPPORTED"
        else:
            status = "OK"
        adopted = int(
            prior == "EXHAUSTED"
            and not self.has_sticky
            and self.future_seen == 0
            and cleanup == "OK"
            and status == "OK"
            and self.reopen == 0
        )
        return status, adopted

    def abort(self, faults: List[Dict[str, Any]]) -> str:
        if self.state not in ("OPEN", "EXHAUSTED", "FAILED"):
            return "INVALID_STATE"
        cleanup = self._cleanup(faults)
        if self.has_sticky:
            return self.sticky
        return cleanup


def run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    rows = [(from_hex(r["key_hex"]), from_hex(r.get("value_hex", ""))) for r in case.get("rows", [])]
    faults = faults_list(case)
    oracle = ScannerOracle()
    final_status = "OK"
    adopted = 0
    for call in case["calls"]:
        op = call["op"]
        if op == "begin":
            final_status = oracle.begin(faults)
        elif op == "advance":
            final_status = oracle.advance(rows, int(call.get("row_budget", 64)), faults)
        elif op == "finalize":
            final_status, adopted = oracle.finalize(faults)
        elif op == "abort":
            final_status = oracle.abort(faults)
            adopted = 0
        else:
            raise ValueError(f"unknown op {op}")
    return {
        "final_status": final_status,
        "adopted": adopted,
        "state_after": oracle.state,
        "recognizable_future_seen": oracle.future_seen,
        "family14_row_count": oracle.family14,
        "current_domain_key_count": oracle.current,
        "ok_row_count": oracle.ok_rows,
        "port_trace": oracle.port_trace,
        "mutation_calls": oracle.mutation_calls,
        "reopen_required": oracle.reopen,
        "close_count": oracle.close_count,
    }


def build_vectors() -> List[Dict[str, Any]]:
    vectors: List[Dict[str, Any]] = []

    def add(
        vid: str,
        kind: str,
        rows: List[Tuple[bytes, bytes]],
        calls: List[Dict[str, Any]],
        faults: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        case = {
            "id": vid,
            "kind": kind,
            "rows": [{"key_hex": hex_of(k), "value_hex": hex_of(v)} for k, v in rows],
            "faults": faults or [],
            "calls": calls,
        }
        case["expected"] = run_case(case)
        vectors.append(case)

    add(
        "s1-empty-adopt",
        "lifecycle",
        [],
        [{"op": "begin"}, {"op": "advance", "row_budget": 64}, {"op": "finalize"}],
    )
    add(
        "s1-family14-current",
        "classification",
        [
            (runtime_key_binding(), b""),
            (runtime_key_identity(), b""),
            (runtime_key_counter(1), b""),
            (runtime_key_capacity(1), b""),
            (domain_key_id128(0x05, 0x01, bytes([0x44]) * 16), nlr1(5, 1, b"")),
        ],
        [{"op": "begin"}, {"op": "advance", "row_budget": 64}, {"op": "finalize"}],
    )
    add(
        "s1-future-then-end-unsupported",
        "outcome",
        [(future_key(), future_value())],
        [{"op": "begin"}, {"op": "advance", "row_budget": 8}, {"op": "finalize"}],
    )
    add(
        "s1-budget-1-then-64",
        "row_budget",
        [
            (runtime_key_binding(), b""),
            (runtime_key_identity(), b""),
            (runtime_key_counter(1), b""),
        ],
        [
            {"op": "begin"},
            {"op": "advance", "row_budget": 1},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
    )
    rows65 = [(domain_key_u64(0x06, 0x27, i), b"") for i in range(65)]
    add(
        "s1-65-rows",
        "row_budget",
        rows65,
        [
            {"op": "begin"},
            {"op": "advance", "row_budget": 64},
            {"op": "advance", "row_budget": 1},
            {"op": "advance", "row_budget": 1},
            {"op": "finalize"},
        ],
    )
    add(
        "s1-future-then-malformed-corrupt",
        "outcome",
        [
            (future_key(), future_value()),
            (bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x02, 0xFF]), b""),
        ],
        [{"op": "begin"}, {"op": "advance", "row_budget": 8}, {"op": "finalize"}],
    )
    add(
        "s1-malformed-stops-before-future",
        "outcome",
        [(malformed_current_key(), b""), (future_key(), future_value())],
        [{"op": "begin"}, {"op": "advance", "row_budget": 8}, {"op": "finalize"}],
    )
    add(
        "s1-duplicate-corrupt",
        "outcome",
        [(runtime_key_binding(), b""), (runtime_key_binding(), b"")],
        [{"op": "begin"}, {"op": "advance", "row_budget": 8}, {"op": "finalize"}],
    )
    add(
        "s1-out-of-order-corrupt",
        "outcome",
        [(runtime_key_identity(), b""), (runtime_key_binding(), b"")],
        [{"op": "begin"}, {"op": "advance", "row_budget": 8}, {"op": "finalize"}],
    )
    add(
        "s1-bts-corrupt",
        "call_trace",
        [],
        [{"op": "begin"}, {"op": "advance", "row_budget": 1}, {"op": "finalize"}],
        faults=[{"op": "iter_next", "on_call": 1, "status": "BUFFER_TOO_SMALL", "shape": "bts",
                 "key_length": 300, "value_length": 5000}],
    )
    add(
        "s1-not-found-poison",
        "call_trace",
        [],
        [{"op": "begin"}, {"op": "advance", "row_budget": 1}, {"op": "finalize"}],
        faults=[{"op": "iter_next", "on_call": 1, "status": "NOT_FOUND", "shape": "not_found_poison",
                 "key_length": 1, "value_length": 0}],
    )
    add(
        "s1-begin-ok-null",
        "call_trace",
        [],
        [{"op": "begin"}],
        faults=[{"op": "begin", "on_call": 1, "status": "OK", "shape": "ok_null"}],
    )
    add(
        "s1-begin-error-with-handle-fence",
        "call_trace",
        [],
        [{"op": "begin"}],
        faults=[
            {
                "op": "begin",
                "on_call": 1,
                "status": "IO_ERROR",
                "shape": "error_with_handle",
            }
        ],
    )
    add(
        "s1-iter-open-ok-null-fence",
        "call_trace",
        [],
        [{"op": "begin"}],
        faults=[{"op": "iter_open", "on_call": 1, "status": "OK", "shape": "ok_null"}],
    )
    add(
        "s1-iter-open-error-with-handle-fence",
        "call_trace",
        [],
        [{"op": "begin"}],
        faults=[{"op": "iter_open", "on_call": 1, "status": "IO_ERROR", "shape": "error_with_handle"}],
    )
    add(
        "s1-rollback-failure-preserves-primary",
        "outcome",
        [],
        [{"op": "begin"}, {"op": "advance", "row_budget": 1}, {"op": "finalize"}],
        faults=[
            {"op": "iter_next", "on_call": 1, "status": "IO_ERROR", "shape": "io_error"},
            {"op": "rollback", "on_call": 1, "status": "IO_ERROR", "shape": "io_error"},
        ],
    )
    add(
        "s1-abort-open",
        "lifecycle",
        [(runtime_key_binding(), b"")],
        [{"op": "begin"}, {"op": "advance", "row_budget": 1}, {"op": "abort"}],
    )
    add(
        "s1-dsr2-workspace-ceiling",
        "dsr2_skeleton",
        [],
        [{"op": "begin"}, {"op": "advance", "row_budget": 1}, {"op": "finalize"}],
        faults=[{"op": "iter_next", "on_call": 1, "status": "BUFFER_TOO_SMALL", "shape": "bts",
                 "key_length": 256, "value_length": 65536}],
    )
    return vectors


def document() -> Dict[str, Any]:
    return {
        "version": VERSION,
        "format": FORMAT,
        "scope": (
            "D2-S1 scanner core ownership: DSR1_SCAN transport subset + "
            "DSR2_ESP_BOUND skeleton. Does not claim DSR1 complete, DSR2 "
            "complete, or D2 complete. Counter overflow is D2-detectable "
            "corruption (no wrap)."
        ),
        "workspace": {
            "key_capacity": KEY_CAP,
            "value_capacity": VALUE_CAP,
            "previous_key_capacity": PREV_CAP,
            "ceiling_bytes": CEILING,
        },
        "vectors": build_vectors(),
    }


def generate(path: Path) -> None:
    doc = document()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(doc['vectors'])} vectors)")


def check(path: Path) -> int:
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    expected = document()
    if on_disk.get("format") != FORMAT:
        print(f"format mismatch: {on_disk.get('format')!r}", file=sys.stderr)
        return 1
    if on_disk.get("version") != VERSION:
        print("version mismatch", file=sys.stderr)
        return 1
    if len(on_disk.get("vectors", [])) != len(expected["vectors"]):
        print("vector count mismatch", file=sys.stderr)
        return 1
    for got, want in zip(on_disk["vectors"], expected["vectors"]):
        if got.get("id") != want["id"]:
            print(f"id order mismatch: {got.get('id')} != {want['id']}", file=sys.stderr)
            return 1
        if not isinstance(got.get("faults"), list):
            print(f"{got['id']}: faults must be array", file=sys.stderr)
            return 1
        recomputed = run_case(got)
        if recomputed != got.get("expected"):
            print(f"oracle mismatch for {got['id']}", file=sys.stderr)
            print(" got:", json.dumps(got.get("expected"), sort_keys=True), file=sys.stderr)
            print(" want:", json.dumps(recomputed, sort_keys=True), file=sys.stderr)
            return 1
        if recomputed != want["expected"]:
            print(f"generator drift for {got['id']}", file=sys.stderr)
            return 1
    if json.dumps(on_disk, sort_keys=True) != json.dumps(expected, sort_keys=True):
        print("document not deterministically equal to generator output", file=sys.stderr)
        return 1
    print(f"ok: {path} ({len(on_disk['vectors'])} vectors)")
    return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    """Emit a C header consumed by production scanner bridge tests."""
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = doc["vectors"]
    lines: List[str] = []
    lines.append("/* GENERATED by tools/domain_scan_vector_gen.py emit-c-fixture — do not edit. */")
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_VECTOR_FIXTURE_H")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(f"#define NINLIL_DSF_VECTOR_COUNT ((size_t){len(vectors)}u)")
    lines.append("#define NINLIL_DSF_MAX_ROWS ((size_t)80u)")
    lines.append("#define NINLIL_DSF_MAX_CALLS ((size_t)8u)")
    lines.append("#define NINLIL_DSF_MAX_FAULTS ((size_t)4u)")
    lines.append("#define NINLIL_DSF_MAX_KEY ((size_t)45u)")
    lines.append("#define NINLIL_DSF_MAX_VALUE ((size_t)64u)")
    lines.append("#define NINLIL_DSF_MAX_TRACE ((size_t)128u)")
    lines.append("")
    lines.append("typedef struct ninlil_dsf_row {")
    lines.append("    uint8_t key[NINLIL_DSF_MAX_KEY];")
    lines.append("    uint32_t key_length;")
    lines.append("    uint8_t value[NINLIL_DSF_MAX_VALUE];")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dsf_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsf_fault {")
    lines.append("    const char *op;")
    lines.append("    uint32_t on_call;")
    lines.append("    const char *shape;")
    lines.append("    uint32_t key_length;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dsf_fault_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsf_call {")
    lines.append("    const char *op;")
    lines.append("    uint32_t row_budget;")
    lines.append("} ninlil_dsf_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsf_expected {")
    lines.append("    const char *final_status;")
    lines.append("    uint32_t adopted;")
    lines.append("    const char *state_after;")
    lines.append("    uint8_t recognizable_future_seen;")
    lines.append("    uint64_t family14_row_count;")
    lines.append("    uint64_t current_domain_key_count;")
    lines.append("    uint64_t ok_row_count;")
    lines.append("    uint32_t reopen_required;")
    lines.append("    uint32_t close_count;")
    lines.append("    uint32_t mutation_calls;")
    lines.append("    const char *const *port_trace;")
    lines.append("    size_t port_trace_count;")
    lines.append("} ninlil_dsf_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsf_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    const ninlil_dsf_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_dsf_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_dsf_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_dsf_expected_t expected;")
    lines.append("} ninlil_dsf_vector_t;")
    lines.append("")

    for vi, vec in enumerate(vectors):
        # rows
        lines.append(f"static const ninlil_dsf_row_t ninlil_dsf_rows_{vi}[] = {{")
        for r in vec.get("rows", []):
            kb = from_hex(r.get("key_hex", ""))
            vb = from_hex(r.get("value_hex", ""))
            if len(kb) > 45 or len(vb) > 64:
                # oversized value for fixture limit: store lengths only marker
                raise SystemExit(f"row too large for fixture: {vec['id']}")
            karr = ", ".join(f"0x{b:02x}u" for b in kb) if kb else "0"
            varr = ", ".join(f"0x{b:02x}u" for b in vb) if vb else "0"
            lines.append(
                f"    {{{{ {karr} }}, {len(kb)}u, {{ {varr} }}, {len(vb)}u }},"
            )
        if not vec.get("rows"):
            lines.append("    {0}")
        lines.append("};")
        # faults
        lines.append(f"static const ninlil_dsf_fault_t ninlil_dsf_faults_{vi}[] = {{")
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f["op"]}", {int(f["on_call"])}u, "{f.get("shape", "natural")}", '
                f'{int(f.get("key_length", 0))}u, {int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append('    { NULL, 0u, NULL, 0u, 0u }')
        lines.append("};")
        # calls
        lines.append(f"static const ninlil_dsf_call_t ninlil_dsf_calls_{vi}[] = {{")
        for c in vec["calls"]:
            rb = int(c.get("row_budget", 0))
            lines.append(f'    {{ "{c["op"]}", {rb}u }},')
        lines.append("};")
        # port_trace
        exp = vec["expected"]
        lines.append(f"static const char *const ninlil_dsf_trace_{vi}[] = {{")
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append('    NULL')
        lines.append("};")
        lines.append("")

    lines.append("static const ninlil_dsf_vector_t ninlil_dsf_vectors[NINLIL_DSF_VECTOR_COUNT] = {")
    for vi, vec in enumerate(vectors):
        exp = vec["expected"]
        row_n = max(len(vec.get("rows", [])), 1)
        fault_n = len(vec.get("faults", []))
        call_n = len(vec["calls"])
        trace_n = len(exp.get("port_trace", []))
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        ninlil_dsf_rows_{vi}, {len(vec.get('rows', []))}u,")
        lines.append(f"        ninlil_dsf_faults_{vi}, {fault_n}u,")
        lines.append(f"        ninlil_dsf_calls_{vi}, {call_n}u,")
        lines.append("        {")
        lines.append(f'            "{exp["final_status"]}",')
        lines.append(f'            {int(exp["adopted"])}u,')
        lines.append(f'            "{exp["state_after"]}",')
        lines.append(f'            {int(exp["recognizable_future_seen"])}u,')
        lines.append(f'            {int(exp["family14_row_count"])}ull,')
        lines.append(f'            {int(exp["current_domain_key_count"])}ull,')
        lines.append(f'            {int(exp["ok_row_count"])}ull,')
        lines.append(f'            {int(exp["reopen_required"])}u,')
        lines.append(f'            {int(exp.get("close_count", 0))}u,')
        lines.append(f'            {int(exp["mutation_calls"])}u,')
        lines.append(f"            ninlil_dsf_trace_{vi}, {trace_n}u")
        lines.append("        }")
        lines.append("    },")
        _ = (row_n,)  # silence
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_VECTOR_FIXTURE_H */")
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
    generate(Path(argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
