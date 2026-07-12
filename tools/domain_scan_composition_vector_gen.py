#!/usr/bin/env python3
"""Independent D2-S5 domain-scan composition vector oracle (stdlib only).

Does NOT invoke, import, link, or translate production C scanner/codec.
Builds DSR1/DSR2 composition cases using independent NLR1/CRC32C/profile
encoding and a closed reference model of docs/17 §15.12 / §17.1.5.

Usage:
  python3 tools/domain_scan_composition_vector_gen.py generate <path>
  python3 tools/domain_scan_composition_vector_gen.py check <path>
  python3 tools/domain_scan_composition_vector_gen.py emit-c-fixture <json> <c-header>
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FORMAT = "ninlil-domain-scan-composition-v1-d2s5"
VERSION = 1
ROOT_V1 = bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x01])
PROFILE_NAME = b"NINLIL-FOUNDATION-SMALL-1"
KEY_CAP = 255
VALUE_CAP = 4096
PREV_CAP = 255
CEILING = 8192
ALL_MASK = 0x1FFFF

REPO_ROOT = Path(__file__).resolve().parents[1]
S1_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-v1.json"
S2_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-profile-v1.json"
S3_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-structural-v1.json"
S4_VECTORS = REPO_ROOT / "spec" / "vectors" / "domain-scan-exact-get-v1.json"
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
D1_FORMAT = "ninlil-domain-store-v1-d1b3o"
D1_SHA256 = (
    "b809c223f8208111fb4271cdceed031193e32e0f118e019d404ac538c89792b4"
)
D1_COUNT = 1549

REQUIRED_KINDS = frozenset(
    {
        "budget_1",
        "budget_64",
        "same_snapshot_exact_get",
        "restart_after_abort",
        "restart_after_finalize",
        "restart_changed_snapshot",
        "restart_after_failed",
        "rollback_failure_sticky",
        "unknown_rollback_fence",
        "handle_drift_original",
        "future_then_note",
        "exhausted_future_then_note",
        "mismatch_then_note",
        "structural_future_composition",
        "state_gate",
        "note_then_reject",
        "note_exhausted",
        "close_fence_once",
        "mutation_zero",
        "dsr2_ceiling",
        "dsr2_source",
    }
)

# Deterministic artifact pin: updated when vectors are intentionally extended.
EXPECTED_VECTOR_COUNT = 22

# Closed call-op set (Normative §17.1.5). handle_drift is oracle/bridge harness.
SCANNER_CALL_OPS = frozenset(
    {
        "begin_profiled",
        "advance",
        "exact_get",
        "note_terminal_corrupt",
        "finalize",
        "abort",
    }
)
HARNESS_CALL_OPS = frozenset(
    {
        "session_init",
        "use_rows",
        "handle_drift",
    }
)
CLOSED_CALL_OPS = SCANNER_CALL_OPS | HARNESS_CALL_OPS
# Forbidden in composition oracle (S1 TEST transport only).
FORBIDDEN_CALL_OPS = frozenset({"begin", "begin_transport", "transport_begin"})

VECTOR_KEYS = frozenset(
    {
        "id",
        "kind",
        "candidate_binding",
        "rows",
        "alt_rows",
        "faults",
        "calls",
        "expected",
    }
)
FAULT_KEYS = frozenset(
    {"op", "on_call", "status", "shape", "key_length", "value_length"}
)
CALL_KEYS = frozenset(
    {"op", "row_budget", "key_hex", "name", "expected_status"}
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
    }
)

SCOPE = (
    "D2-S5 bounded scanner composition: DSR1_SCAN complete + DSR2_ESP_BOUND "
    "complete + D2 (bounded scanner) complete only. Does not claim Stage 5, "
    "D3 finding correctness, D4 mutation, S6 orchestration, public Runtime, "
    "ESP-IDF compile, or hardware. D3 injection seam is note_terminal_corrupt "
    "mechanism only."
)


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
                head = b"NLR1" + be16(1) + be16(binding_version) + be32(len(payload))
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
    """Recognizable future-root key (13 bytes; matches production fixture shape)."""
    return bytes(
        [0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x02, 0x10, 0x20, tag, 0x01, 0x00]
    )


def future_root_value() -> bytes:
    """Complete NLR1 future value (record_version 2) required by classify_row."""
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


def run_case(vec: Dict[str, Any]) -> Dict[str, Any]:
    """Independent reference model for profiled composition lifecycle."""
    binding = vec["candidate_binding"]
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
        rb_fault = None
        if txn_live:
            # rollback occurrence is 1-based over all rollbacks in the case
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
        nonlocal handle_drifted
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
                # Recognizable future root (non-terminal; complete NLR1 value).
                future_seen = 1
            elif (
                len(key) >= 8
                and key[:7] == ROOT_V1[:7]
                and key[7] >= 2
            ):
                # Future-shaped key without complete NLR1 value → corrupt.
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                return "STORAGE_CORRUPT"
            else:
                # Non-catalog current-root domain visit (composition seam).
                current_dom += 1
            previous = key
            has_previous = True
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
            # Legal only after cleanup DONE (or fresh object); harness VOID.
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
            # Snapshot switch only between sessions (IDLE after session_init).
            if state != "IDLE":
                raise SystemExit(
                    f"illegal use_rows ordering while state={state}"
                )
            rows = list(alt_map[name])
            last_status = "VOID"
            call_statuses.append("VOID")
            continue
        if op == "handle_drift":
            # Oracle/bridge harness: mark slot drift; no Port; VOID outcome.
            if state not in ("OPEN", "EXHAUSTED", "FAILED"):
                raise SystemExit(
                    f"illegal handle_drift ordering while state={state}"
                )
            handle_drifted = 1
            last_status = "VOID"
            call_statuses.append("VOID")
            continue
        if op == "begin_profiled":
            if state != "IDLE":
                last_status = "INVALID_STATE"
                call_statuses.append(last_status)
                continue
            port_trace.append("begin:READ_ONLY")
            txn_live = True
            original_authority = 1
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

    # Stamp every call with its immediate expected result (scanner status or VOID).
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
    )


def make_vector(
    vid: str,
    kind: str,
    rows: List[Dict[str, str]],
    calls: List[Dict[str, Any]],
    *,
    faults: Optional[List[Dict[str, Any]]] = None,
    binding: Optional[Dict[str, Any]] = None,
    alt_rows: Optional[Dict[str, List[Dict[str, str]]]] = None,
) -> Dict[str, Any]:
    # Deep-copy calls so expected_status stamps are vector-local.
    stamped_calls = [copy.deepcopy(c) for c in calls]
    vec: Dict[str, Any] = {
        "id": vid,
        "kind": kind,
        "candidate_binding": binding or default_binding_fields(),
        "rows": rows,
        "alt_rows": alt_rows or {},
        "faults": faults or [],
        "calls": stamped_calls,
    }
    vec["expected"] = run_case(vec)
    return vec


def build_vectors() -> List[Dict[str, Any]]:
    b = default_binding_fields()
    profile = encode_all_profile_rows(b)
    k_binding = catalog_key(1)
    k_future = future_root_key(0x11)
    k_future2 = future_root_key(0x22)
    fv = hex_of(future_root_value())
    rows_future = profile + [
        {"key_hex": hex_of(k_future), "value_hex": fv}
    ]
    # profile + two future roots: advance(18) visits one future and stays OPEN.
    rows_future_open = profile + [
        {"key_hex": hex_of(k_future), "value_hex": fv},
        {"key_hex": hex_of(k_future2), "value_hex": fv},
    ]

    mismatch_rows = encode_all_profile_rows(b)
    bind = bytearray(from_hex(mismatch_rows[0]["value_hex"]))
    # Flip a payload byte then re-CRC so model sees semantic mismatch.
    bind[50] ^= 0x01
    body = bytes(bind[:-4])
    bind[-4:] = be32(crc32c(body))
    mismatch_rows[0]["value_hex"] = hex_of(bytes(bind))

    # Changed snapshot: extra recognizable future-root after profile so a
    # fresh session restart observes a different front-to-end walk (ok=18,
    # future_seen) without D3 structural semantics.
    rows_changed = profile + [
        {
            "key_hex": hex_of(future_root_key(0xEE)),
            "value_hex": hex_of(future_root_value()),
        }
    ]

    vectors: List[Dict[str, Any]] = []

    # budget 1: partial then resume then exhaust (same session; not restart)
    vectors.append(
        make_vector(
            "S5_BUDGET_1_PARTIAL_RESUME",
            "budget_1",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # budget 64 exhaust
    vectors.append(
        make_vector(
            "S5_BUDGET_64_EXHAUST",
            "budget_64",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # same-snapshot exact_get mid lifecycle
    vectors.append(
        make_vector(
            "S5_SAME_SNAPSHOT_EXACT_GET",
            "same_snapshot_exact_get",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 3},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # fresh-session restart after partial abort.
    # Normative: session_init only after DONE; first post-restart advance
    # budget=1 (front-of-snapshot), then a later advance completes.
    vectors.append(
        make_vector(
            "S5_RESTART_AFTER_PARTIAL_ABORT",
            "restart_after_abort",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "abort"},
                {"op": "session_init"},
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # restart after full exhaust+finalize then fresh session.
    vectors.append(
        make_vector(
            "S5_RESTART_AFTER_FINALIZE",
            "restart_after_finalize",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
                {"op": "session_init"},
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # restart against changed snapshot (first post-restart key is new front).
    vectors.append(
        make_vector(
            "S5_RESTART_CHANGED_SNAPSHOT",
            "restart_changed_snapshot",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 2},
                {"op": "abort"},
                {"op": "session_init"},
                {"op": "use_rows", "name": "changed"},
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
            alt_rows={"changed": rows_changed},
        )
    )

    # restart after FAILED cleanup (note then finalize then new session)
    vectors.append(
        make_vector(
            "S5_RESTART_AFTER_FAILED_CLEANUP",
            "restart_after_failed",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "note_terminal_corrupt"},
                {"op": "finalize"},
                {"op": "session_init"},
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # rollback failure preserves sticky
    vectors.append(
        make_vector(
            "S5_ROLLBACK_FAILURE_PRESERVES_STICKY",
            "rollback_failure_sticky",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "note_terminal_corrupt"},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "rollback",
                    "on_call": 1,
                    "status": "IO_ERROR",
                    "shape": "natural",
                    "key_length": 0,
                    "value_length": 0,
                }
            ],
        )
    )

    # unknown rollback → fence once
    vectors.append(
        make_vector(
            "S5_UNKNOWN_ROLLBACK_FENCE_ONCE",
            "unknown_rollback_fence",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "abort"},
            ],
            faults=[
                {
                    "op": "rollback",
                    "on_call": 1,
                    "status": "UNKNOWN_RAW",
                    "shape": "unknown",
                    "key_length": 0,
                    "value_length": 0,
                }
            ],
        )
    )

    # handle drift closes original
    vectors.append(
        make_vector(
            "S5_HANDLE_DRIFT_CLOSES_ORIGINAL",
            "handle_drift_original",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "handle_drift"},
                {"op": "advance", "row_budget": 1},
                {"op": "finalize"},
            ],
        )
    )

    # future then note while OPEN → corrupt outranks future
    vectors.append(
        make_vector(
            "S5_FUTURE_THEN_NOTE_CORRUPT",
            "future_then_note",
            rows_future_open,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 18},
                {"op": "note_terminal_corrupt"},
                {"op": "finalize"},
            ],
        )
    )

    # exhausted + future then note
    vectors.append(
        make_vector(
            "S5_EXHAUSTED_FUTURE_THEN_NOTE",
            "exhausted_future_then_note",
            rows_future,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "note_terminal_corrupt"},
                {"op": "finalize"},
            ],
        )
    )

    # profile mismatch then note
    vectors.append(
        make_vector(
            "S5_MISMATCH_THEN_NOTE_CORRUPT",
            "mismatch_then_note",
            mismatch_rows,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "note_terminal_corrupt"},
                {"op": "finalize"},
            ],
        )
    )

    # structural/future composition: future root only under exact profile
    vectors.append(
        make_vector(
            "S5_STRUCTURAL_FUTURE_COMPOSITION",
            "structural_future_composition",
            rows_future,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # state gates: note on IDLE, DONE, FAILED
    vectors.append(
        make_vector(
            "S5_NOTE_STATE_GATES",
            "state_gate",
            profile,
            [
                {"op": "note_terminal_corrupt"},
                {"op": "begin_profiled"},
                {"op": "note_terminal_corrupt"},
                {"op": "note_terminal_corrupt"},
                {"op": "finalize"},
            ],
        )
    )

    # note then advance/exact_get rejected
    vectors.append(
        make_vector(
            "S5_NOTE_THEN_ADVANCE_EXACT_REJECT",
            "note_then_reject",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "note_terminal_corrupt"},
                {"op": "advance", "row_budget": 1},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
        )
    )

    # close/fence once (unknown rollback)
    vectors.append(
        make_vector(
            "S5_CLOSE_FENCE_ONCE",
            "close_fence_once",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "abort"},
            ],
            faults=[
                {
                    "op": "rollback",
                    "on_call": 1,
                    "status": "COMMIT_UNKNOWN",
                    "shape": "natural",
                    "key_length": 0,
                    "value_length": 0,
                }
            ],
        )
    )

    # mutation zero
    vectors.append(
        make_vector(
            "S5_MUTATION_ZERO",
            "mutation_zero",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
        )
    )

    # dsr2 ceiling (success path + kind marker)
    vectors.append(
        make_vector(
            "S5_DSR2_CEILING",
            "dsr2_ceiling",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # dsr2 source kind (same success path; bridge asserts source/sizeof gates)
    vectors.append(
        make_vector(
            "S5_DSR2_SOURCE",
            "dsr2_source",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # note on EXHAUSTED without future (clean corrupt inject; distinct kind)
    vectors.append(
        make_vector(
            "S5_NOTE_ON_EXHAUSTED_CLEAN",
            "note_exhausted",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "note_terminal_corrupt"},
                {"op": "finalize"},
            ],
        )
    )

    # extra: budget 1 only then abort (partial abort restart sibling)
    vectors.append(
        make_vector(
            "S5_BUDGET_1_ABORT_ONLY",
            "budget_1",
            profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 1},
                {"op": "abort"},
            ],
        )
    )

    # Validate closed kind coverage
    kinds = {v["kind"] for v in vectors}
    missing = REQUIRED_KINDS - kinds
    if missing:
        raise SystemExit(f"missing required kinds in build: {sorted(missing)}")
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        raise SystemExit(
            f"vector count {len(vectors)} != pin {EXPECTED_VECTOR_COUNT}"
        )
    return vectors


def build_document() -> Dict[str, Any]:
    pins = assert_authority_pins()
    vectors = build_vectors()
    return {
        "version": VERSION,
        "format": FORMAT,
        "scope": SCOPE,
        "workspace": {
            "key_capacity": KEY_CAP,
            "value_capacity": VALUE_CAP,
            "previous_key_capacity": PREV_CAP,
            "ceiling_bytes": CEILING,
            "note": (
                "single 4096 value buffer; no second 4096; no full-ID set; "
                "no unused xref digest/kind/count session fields"
            ),
        },
        "s1_authority": pins["s1"],
        "s2_authority": pins["s2"],
        "s3_authority": pins["s3"],
        "s4_authority": pins["s4"],
        "d1_authority": pins["d1"],
        "vectors": vectors,
    }


def generate(path: Path) -> None:
    doc = build_document()
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, indent=2, sort_keys=False) + "\n"
    path.write_text(text, encoding="utf-8")
    print(f"wrote {path} vectors={len(doc['vectors'])}")


def _fail_check(msg: str) -> int:
    print(msg, file=sys.stderr)
    return 1


def _validate_restart_vector(vec: Dict[str, Any]) -> Optional[str]:
    """Restart: cleanup DONE before session_init; first post-restart advance budget=1."""
    calls = vec["calls"]
    ops = [c["op"] for c in calls]
    if "session_init" not in ops:
        return f"{vec['id']}: restart vector missing session_init"
    si = ops.index("session_init")
    if si == 0:
        return f"{vec['id']}: session_init must follow a prior cleanup"
    # Immediate predecessor of session_init must be finalize or abort
    # (cleanup that leaves DONE).
    pred = ops[si - 1]
    if pred not in ("finalize", "abort"):
        return (
            f"{vec['id']}: session_init must follow finalize/abort "
            f"(got {pred})"
        )
    # After session_init: optional use_rows, then begin_profiled, then
    # advance with budget=1 as first post-restart advance.
    j = si + 1
    if j < len(ops) and ops[j] == "use_rows":
        j += 1
    if j >= len(ops) or ops[j] != "begin_profiled":
        return f"{vec['id']}: post-restart begin_profiled missing"
    j += 1
    if j >= len(ops) or ops[j] != "advance":
        return f"{vec['id']}: first post-restart advance missing"
    if int(calls[j].get("row_budget", 0)) != 1:
        return (
            f"{vec['id']}: first post-restart advance must have row_budget=1 "
            f"(got {calls[j].get('row_budget')})"
        )
    # A later advance must complete the walk.
    if not any(
        calls[k]["op"] == "advance" and k > j for k in range(j + 1, len(calls))
    ):
        return f"{vec['id']}: restart missing later advance after budget1"
    return None


def _validate_note_then_reject(vec: Dict[str, Any]) -> Optional[str]:
    """note_then_reject must contain note then rejected advance/exact_get."""
    calls = vec["calls"]
    ops = [c["op"] for c in calls]
    if "note_terminal_corrupt" not in ops:
        return f"{vec['id']}: note_then_reject missing note_terminal_corrupt"
    ni = ops.index("note_terminal_corrupt")
    if calls[ni].get("expected_status") != "STORAGE_CORRUPT":
        return f"{vec['id']}: note expected_status must be STORAGE_CORRUPT"
    saw_adv = False
    saw_eg = False
    for c in calls[ni + 1 :]:
        if c["op"] == "advance":
            if c.get("expected_status") != "INVALID_STATE":
                return (
                    f"{vec['id']}: post-note advance must be INVALID_STATE "
                    f"(got {c.get('expected_status')})"
                )
            saw_adv = True
        if c["op"] == "exact_get":
            if c.get("expected_status") != "INVALID_STATE":
                return (
                    f"{vec['id']}: post-note exact_get must be INVALID_STATE "
                    f"(got {c.get('expected_status')})"
                )
            saw_eg = True
    if not saw_adv or not saw_eg:
        return (
            f"{vec['id']}: note_then_reject must reject both advance and "
            "exact_get after note"
        )
    return None


def check(path: Path) -> int:
    if not path.is_file():
        return _fail_check(f"missing {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    expected_doc = build_document()

    # Negative anti-false-pass: empty vectors must fail.
    if not data.get("vectors"):
        return _fail_check("vectors empty")
    if data.get("format") != FORMAT:
        return _fail_check(f"format mismatch {data.get('format')}")
    if data.get("version") != VERSION:
        return _fail_check("version mismatch")
    vectors = data["vectors"]
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        return _fail_check(
            f"vector count {len(vectors)} != pin {EXPECTED_VECTOR_COUNT}"
        )
    kinds: Set[str] = set()
    for i, vec in enumerate(vectors):
        for k in VECTOR_KEYS:
            if k not in vec:
                return _fail_check(f"vector {i} missing key {k}")
        kinds.add(vec["kind"])
        if set(vec.keys()) - VECTOR_KEYS:
            return _fail_check(
                f"vector {vec['id']} unexpected keys "
                f"{set(vec.keys()) - VECTOR_KEYS}"
            )
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
                    "composition oracle"
                )
            if "expected_status" not in c:
                return _fail_check(
                    f"{vec['id']}: call missing expected_status for op={op}"
                )
            st = c["expected_status"]
            if op in HARNESS_CALL_OPS:
                if st != "VOID":
                    return _fail_check(
                        f"{vec['id']}: harness op {op} must be VOID "
                        f"(got {st})"
                    )
            else:
                if st == "VOID" or not isinstance(st, str) or not st:
                    return _fail_check(
                        f"{vec['id']}: scanner op {op} missing ninlil "
                        f"expected_status (got {st!r})"
                    )
        if set(vec["expected"].keys()) != EXPECTED_KEYS:
            return _fail_check(
                f"expected keys drift in {vec['id']}: "
                f"{set(vec['expected'].keys()) ^ EXPECTED_KEYS}"
            )
        # Recompute expected for this vector body (strips stamped status then
        # re-stamps via run_case; compare call stamps + expected).
        body = {
            k: copy.deepcopy(vec[k]) for k in VECTOR_KEYS if k != "expected"
        }
        for c in body["calls"]:
            c.pop("expected_status", None)
        recomputed = run_case(body)
        if recomputed != vec["expected"]:
            print(f"expected drift for {vec['id']}", file=sys.stderr)
            for k in sorted(set(recomputed) | set(vec["expected"])):
                if recomputed.get(k) != vec["expected"].get(k):
                    print(
                        f"  {k}: file={vec['expected'].get(k)!r} "
                        f"recomputed={recomputed.get(k)!r}",
                        file=sys.stderr,
                    )
            return 1
        for ci, (fc, bc) in enumerate(zip(vec["calls"], body["calls"])):
            if fc.get("expected_status") != bc.get("expected_status"):
                return _fail_check(
                    f"{vec['id']} call[{ci}] expected_status drift: "
                    f"file={fc.get('expected_status')!r} "
                    f"recomputed={bc.get('expected_status')!r}"
                )

        # Kind-specific structural anti-false-pass rules.
        kind = vec["kind"]
        if kind.startswith("restart_") or kind in (
            "restart_after_abort",
            "restart_after_finalize",
            "restart_changed_snapshot",
            "restart_after_failed",
        ):
            err = _validate_restart_vector(vec)
            if err:
                return _fail_check(err)
        if kind in ("budget_1", "budget_64"):
            if any(c["op"] == "session_init" for c in vec["calls"]):
                return _fail_check(
                    f"{vec['id']}: budget resume must contain no session_init"
                )
        if kind == "note_then_reject":
            err = _validate_note_then_reject(vec)
            if err:
                return _fail_check(err)
        if kind == "note_exhausted":
            if vec["id"] != "S5_NOTE_ON_EXHAUSTED_CLEAN":
                return _fail_check(
                    f"{vec['id']}: note_exhausted kind pin mismatch"
                )
            ops = [c["op"] for c in vec["calls"]]
            if "note_terminal_corrupt" not in ops:
                return _fail_check(f"{vec['id']}: missing note")
            if ops[-1] != "finalize":
                return _fail_check(f"{vec['id']}: must finalize after note")
        if any(c["op"] == "handle_drift" for c in vec["calls"]):
            if kind != "handle_drift_original":
                return _fail_check(
                    f"{vec['id']}: handle_drift only on handle_drift_original"
                )

    # Exact required kind set equality (not subset).
    if kinds != REQUIRED_KINDS:
        missing = REQUIRED_KINDS - kinds
        extra = kinds - REQUIRED_KINDS
        return _fail_check(
            f"kind set mismatch missing={sorted(missing)} "
            f"extra={sorted(extra)}"
        )

    # Full deterministic document equality.
    if json.dumps(data, sort_keys=True) != json.dumps(
        expected_doc, sort_keys=True
    ):
        return _fail_check(
            "document not deterministically equal to generator output"
        )

    # Authority pins inside document.
    for key, fmt, sha, count in (
        ("s1_authority", S1_FORMAT, S1_SHA256, S1_COUNT),
        ("s2_authority", S2_FORMAT, S2_SHA256, S2_COUNT),
        ("s3_authority", S3_FORMAT, S3_SHA256, S3_COUNT),
        ("s4_authority", S4_FORMAT, S4_SHA256, S4_COUNT),
        ("d1_authority", D1_FORMAT, D1_SHA256, D1_COUNT),
    ):
        auth = data.get(key) or {}
        if auth.get("format") != fmt or auth.get("sha256") != sha:
            return _fail_check(f"{key} pin mismatch")
        if int(auth.get("vector_count", -1)) != count:
            return _fail_check(f"{key} count pin mismatch")

    print(
        f"ok {path} vectors={len(vectors)} kinds={len(kinds)} "
        f"(exact required set)"
    )
    return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    lines: List[str] = []
    lines.append(
        "/* Generated by tools/domain_scan_composition_vector_gen.py — do not edit. */"
    )
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_COMPOSITION_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_COMPOSITION_VECTOR_FIXTURE_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(f"#define NINLIL_DSC_VECTOR_COUNT ((size_t){len(vectors)}u)")
    lines.append(
        f"#define NINLIL_DSC_WORKSPACE_CEILING_BYTES ((uint32_t){CEILING}u)"
    )
    lines.append("#define NINLIL_DSC_MAX_TRACE ((size_t)512u)")
    lines.append("#define NINLIL_DSC_MAX_KEY ((size_t)255u)")
    lines.append("#define NINLIL_DSC_MAX_VALUE ((size_t)4096u)")
    lines.append("#define NINLIL_DSC_MAX_ALT ((size_t)4u)")
    lines.append("")
    lines.append("typedef struct ninlil_dsc_binding {")
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
    lines.append("} ninlil_dsc_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsc_row {")
    lines.append("    uint8_t key[16];")
    lines.append("    uint32_t key_length;")
    lines.append("    const uint8_t *value;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dsc_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsc_fault {")
    lines.append("    const char *op;")
    lines.append("    uint32_t on_call;")
    lines.append("    const char *shape;")
    lines.append("    const char *status;")
    lines.append("    uint32_t key_length;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dsc_fault_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsc_call {")
    lines.append("    const char *op;")
    lines.append("    uint32_t row_budget;")
    lines.append("    const uint8_t *key;")
    lines.append("    uint32_t key_length;")
    lines.append("    const char *name;")
    lines.append("    /* Scanner ninlil status name, or VOID for harness ops. */")
    lines.append("    const char *expected_status;")
    lines.append("} ninlil_dsc_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsc_alt {")
    lines.append("    const char *name;")
    lines.append("    const ninlil_dsc_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("} ninlil_dsc_alt_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsc_expected {")
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
    lines.append("} ninlil_dsc_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsc_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    ninlil_dsc_binding_t candidate;")
    lines.append("    const ninlil_dsc_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_dsc_alt_t *alts;")
    lines.append("    size_t alt_count;")
    lines.append("    const ninlil_dsc_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_dsc_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_dsc_expected_t expected;")
    lines.append("} ninlil_dsc_vector_t;")
    lines.append("")

    def binding_literal(b: Dict[str, Any]) -> str:
        rid = from_hex(b["runtime_id_hex"])
        rids = ", ".join(f"0x{x:02x}u" for x in rid)
        lim = b["limits"]
        return (
            f"{{ {int(b['storage_schema'])}u, {int(b['role'])}u, {int(b['environment'])}u, "
            f"{{ {rids} }}, "
            f"{int(lim['max_services'])}u, {int(lim['max_nonterminal_transactions'])}u, "
            f"{int(lim['max_targets_per_transaction'])}u, {int(lim['max_logical_payload_bytes'])}u, "
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

    def emit_rows(prefix: str, rows: List[Dict[str, str]]) -> None:
        for ri, r in enumerate(rows):
            vb = from_hex(r.get("value_hex", ""))
            if len(vb) > 4096:
                vb = vb[:4096]
            arr = ", ".join(f"0x{b:02x}u" for b in vb) if vb else "0"
            lines.append(
                f"static const uint8_t {prefix}_val_{ri}[] = {{ {arr} }};"
            )
        lines.append(f"static const ninlil_dsc_row_t {prefix}_rows[] = {{")
        for ri, r in enumerate(rows):
            kb = from_hex(r.get("key_hex", ""))
            vb = from_hex(r.get("value_hex", ""))
            vlen = min(len(vb), 4096)
            if len(kb) > 16:
                raise SystemExit("key too large for fixture")
            karr = ", ".join(f"0x{b:02x}u" for b in kb) if kb else "0"
            lines.append(
                f"    {{{{ {karr} }}, {len(kb)}u, {prefix}_val_{ri}, {vlen}u }},"
            )
        if not rows:
            lines.append("    { { 0u }, 0u, NULL, 0u },")
        lines.append("};")

    for vi, vec in enumerate(vectors):
        emit_rows(f"ninlil_dsc_{vi}", vec.get("rows", []))
        alt_items = list((vec.get("alt_rows") or {}).items())
        for ai, (aname, arows) in enumerate(alt_items):
            emit_rows(f"ninlil_dsc_{vi}_alt{ai}", arows)
        lines.append(f"static const ninlil_dsc_alt_t ninlil_dsc_alts_{vi}[] = {{")
        for ai, (aname, arows) in enumerate(alt_items):
            lines.append(
                f'    {{ "{aname}", ninlil_dsc_{vi}_alt{ai}_rows, {len(arows)}u }},'
            )
        if not alt_items:
            lines.append('    { NULL, NULL, 0u },')
        lines.append("};")

        lines.append(f"static const ninlil_dsc_fault_t ninlil_dsc_faults_{vi}[] = {{")
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f["op"]}", {int(f["on_call"])}u, "{f.get("shape", "natural")}", '
                f'"{f.get("status", "OK")}", {int(f.get("key_length", 0))}u, '
                f'{int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append('    { NULL, 0u, NULL, NULL, 0u, 0u },')
        lines.append("};")

        for ci, c in enumerate(vec["calls"]):
            if c["op"] == "exact_get":
                kb = from_hex(c.get("key_hex", ""))
                arr = ", ".join(f"0x{b:02x}u" for b in kb) if kb else "0"
                lines.append(
                    f"static const uint8_t ninlil_dsc_callkey_{vi}_{ci}[] = {{ {arr} }};"
                )

        lines.append(f"static const ninlil_dsc_call_t ninlil_dsc_calls_{vi}[] = {{")
        for ci, c in enumerate(vec["calls"]):
            est = c.get("expected_status", "")
            if c["op"] == "exact_get":
                kb = from_hex(c.get("key_hex", ""))
                lines.append(
                    f'    {{ "exact_get", 0u, ninlil_dsc_callkey_{vi}_{ci}, '
                    f'{len(kb)}u, NULL, "{est}" }},'
                )
            elif c["op"] == "use_rows":
                lines.append(
                    f'    {{ "use_rows", 0u, NULL, 0u, "{c.get("name", "")}", '
                    f'"{est}" }},'
                )
            else:
                lines.append(
                    f'    {{ "{c["op"]}", {int(c.get("row_budget", 0))}u, '
                    f'NULL, 0u, NULL, "{est}" }},'
                )
        lines.append("};")

        lines.append(f"static const char *const ninlil_dsc_trace_{vi}[] = {{")
        for t in vec["expected"].get("port_trace", []):
            lines.append(f'    "{t}",')
        if not vec["expected"].get("port_trace"):
            lines.append("    NULL")
        lines.append("};")
        lines.append("")

    lines.append(
        "static const ninlil_dsc_vector_t ninlil_dsc_vectors[NINLIL_DSC_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(vectors):
        exp = vec["expected"]
        alt_count = len(vec.get("alt_rows") or {})
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(
            f"        ninlil_dsc_{vi}_rows, {len(vec.get('rows', []))}u,"
        )
        lines.append(f"        ninlil_dsc_alts_{vi}, {alt_count}u,")
        lines.append(
            f"        ninlil_dsc_faults_{vi}, {len(vec.get('faults', []))}u,"
        )
        lines.append(f"        ninlil_dsc_calls_{vi}, {len(vec['calls'])}u,")
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
            f"            ninlil_dsc_trace_{vi}, {len(exp.get('port_trace', []))}u,"
        )
        lines.append(f"            {int(exp['has_sticky_primary'])}u,")
        lines.append(f'            "{exp.get("sticky_primary", "")}"')
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_COMPOSITION_VECTOR_FIXTURE_H */")
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
