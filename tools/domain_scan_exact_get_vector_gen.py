#!/usr/bin/env python3
"""Independent D2-S4 domain-scan exact-get vector oracle (stdlib only).

Does NOT invoke, import, link, or translate production C scanner/codec.
Builds same-snapshot exact-get cases using independent NLR1/CRC32C/profile
encoding and a closed reference model of docs/17 §15.11 / §17.1.4.

Usage:
  python3 tools/domain_scan_exact_get_vector_gen.py generate <path>
  python3 tools/domain_scan_exact_get_vector_gen.py check <path>
  python3 tools/domain_scan_exact_get_vector_gen.py emit-c-fixture <json> <c-header>
"""

from __future__ import annotations

import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FORMAT = "ninlil-domain-scan-exact-get-v1-d2s4"
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

S1_FORMAT = "ninlil-domain-scan-v1-d2s1"
S1_SHA256 = (
    "5705363e8f8890849e41476013eab3cd4ac1a20b6c33efb54ab65f300d40a165"
)
S2_FORMAT = "ninlil-domain-scan-profile-v1-d2s2"
S2_SHA256 = (
    "b0ecac1d4d56e0abb63c53277ed5b1ab86a3e3c1377ad2393de6f4d74edcd0a5"
)
S3_FORMAT = "ninlil-domain-scan-structural-v1-d2s3"
S3_SHA256 = (
    "f8e75437202c90476aa93fb0a336c86ad03e7e4820510e15074a69cbc6041684"
)

REQUIRED_KINDS = frozenset(
    {
        "present_live",
        "absent",
        "present_zero",
        "exhausted_get",
        "value_boundary",
        "bts_corrupt",
        "descriptor_rewrite",
        "not_found_poison",
        "ok_bad_length",
        "non_ok_nonempty",
        "known_port_fault",
        "unknown_status",
        "fence_shape_combined",
        "state_gate",
        "key_shape",
        "counter_stable",
        "repeat_overwrite",
        "profile_no_auto",
        "dsr2_ceiling",
        "mutation_zero",
    }
)

# Deterministic artifact pin: updated when vectors are intentionally extended.
EXPECTED_VECTOR_COUNT = 30

VECTOR_KEYS = frozenset(
    {
        "id",
        "kind",
        "candidate_binding",
        "rows",
        "faults",
        "calls",
        "expected",
    }
)
FAULT_KEYS = frozenset(
    {"op", "on_call", "status", "shape", "key_length", "value_length"}
)
CALL_KEYS = frozenset({"op", "row_budget", "key_hex"})
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
        "exact_observations",
    }
)
OBS_KEYS = frozenset({"status", "presence", "value_hex"})


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


def absent_key(tag: int = 0xAA) -> bytes:
    """Key that is never installed in the snapshot (exact-get ABSENT)."""
    return ROOT_V1 + bytes([0x7F, 0x00, tag])


def future_root_key(tag: int = 0x01) -> bytes:
    """Recognizable future-root key (non-terminal under exact profile)."""
    # root version 2 + minimal suffix; lexically after current catalog.
    return bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x02, 0x10, 0x20, tag])


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def assert_authority_pins() -> None:
    for path, fmt, sha in (
        (S1_VECTORS, S1_FORMAT, S1_SHA256),
        (S2_VECTORS, S2_FORMAT, S2_SHA256),
        (S3_VECTORS, S3_FORMAT, S3_SHA256),
    ):
        if not path.is_file():
            raise SystemExit(f"missing sibling authority {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != fmt:
            raise SystemExit(f"{path}: format pin mismatch")
        actual = file_sha256(path)
        if actual != sha:
            raise SystemExit(f"{path}: sha256 pin mismatch {actual}")


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
        "exact_observations": [],
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
        "NOT_FOUND": "OK",  # clean path handled separately
        "OK": "OK",
    }.get(status, "STORAGE_CORRUPT")


def run_case(vec: Dict[str, Any]) -> Dict[str, Any]:
    """Independent reference model for profiled begin + exact_get + cleanup."""
    binding = vec["candidate_binding"]
    rows = [(from_hex(r["key_hex"]), from_hex(r["value_hex"])) for r in vec.get("rows", [])]
    faults: List[Dict[str, Any]] = copy.deepcopy(list(vec.get("faults", [])))
    used_fault_indices: Set[int] = set()
    calls = vec["calls"]

    present_mask = 0
    retained: Dict[int, bytes] = {}
    get_call = 0
    iter_opened = 0
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
    iter_next_call = 0
    value_buf = b""
    observations: List[Dict[str, str]] = []
    txn_live = False
    iter_live = False

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
            # CRC check
            body = val[:-4]
            crc = struct.unpack(">I", val[-4:])[0]
            if crc != crc32c(body):
                saw_corrupt = True
                continue
        if saw_corrupt:
            return "STORAGE_CORRUPT"
        if saw_unsup:
            return "FUTURE"
        # compare binding semantic: use max_services only for mismatch vectors
        # Exact when present_mask full and binding version 1.
        # Semantic mismatch is injected via mutate of retained binding bytes
        # that still pass CRC... for oracle simplicity, compare runtime id field.
        bval = retained.get(1, b"")
        if len(bval) >= 183:
            want = encode_binding(binding)
            if bval != want:
                # if only version differed, already FUTURE; else mismatch or corrupt
                # Compare role/env/schema fields loosely: any CRC-valid non-exact
                # is mismatch for oracle cases we generate.
                return "MISMATCH"
        return "EXACT"

    def do_profile_gets() -> Optional[str]:
        nonlocal get_call, present_mask, value_buf, fence_pending
        for kid in range(1, 18):
            get_call += 1
            port_trace.append("get")
            key = catalog_key(kid)
            fault = find_fault("get", get_call)
            capacity = {1: 183, 2: 84}.get(kid, 32 if kid <= 6 else 68)
            length = 0
            status = "OK"
            data_ptr_ok = True
            cap_ok = True
            if fault is not None:
                shape = fault.get("shape", "natural")
                status = fault.get("status", "OK")
                if shape == "bts":
                    status = "BUFFER_TOO_SMALL"
                    length = int(fault.get("value_length", 0) or 0)
                elif shape == "not_found_poison":
                    status = "NOT_FOUND"
                    length = int(fault.get("value_length", 0) or 1)
                elif shape == "rewrite_data_ptr":
                    status = "OK"
                    data_ptr_ok = False
                    raw = lookup(key)
                    length = len(raw) if raw is not None else 0
                elif shape == "rewrite_capacity":
                    status = "OK"
                    cap_ok = False
                    raw = lookup(key)
                    if raw is None:
                        status = "NOT_FOUND"
                        length = 0
                    elif len(raw) > capacity:
                        status = "BUFFER_TOO_SMALL"
                        length = 0
                    else:
                        length = len(raw)
                        retained[kid] = raw
                        present_mask |= 1 << (kid - 1)
                elif shape == "unknown":
                    status = "UNKNOWN_RAW"
                    length = 0
                elif status != "OK":
                    length = 0
                else:
                    fault = None
            if fault is None or fault.get("shape") in (
                "rewrite_data_ptr",
                "rewrite_capacity",
            ):
                if fault is None or fault.get("shape") == "rewrite_data_ptr":
                    raw = lookup(key)
                    if raw is None:
                        status = "NOT_FOUND"
                        length = 0
                    elif len(raw) > capacity:
                        status = "BUFFER_TOO_SMALL"
                        length = 0
                    else:
                        status = "OK"
                        length = len(raw)
                        if data_ptr_ok and cap_ok:
                            retained[kid] = raw
                            present_mask |= 1 << (kid - 1)
            if not data_ptr_ok or not cap_ok:
                fence_pending = 1
                return "STORAGE_CORRUPT"
            if status == "OK":
                if length > capacity:
                    return "STORAGE_CORRUPT"
                continue
            if status == "NOT_FOUND":
                if length != 0:
                    return "STORAGE_CORRUPT"
                continue
            if status == "BUFFER_TOO_SMALL":
                return "STORAGE_CORRUPT"
            if status == "UNKNOWN_RAW":
                fence_pending = 1
                return "STORAGE_CORRUPT"
            if status == "COMMIT_UNKNOWN":
                fence_pending = 1
                return "STORAGE_COMMIT_UNKNOWN"
            if length != 0:
                return "STORAGE_CORRUPT"
            return map_storage(status)
        if present_mask != ALL_MASK:
            return "STORAGE_CORRUPT"
        outcome = validate_and_compare()
        return outcome

    def cleanup(primary: Optional[str]) -> str:
        nonlocal state, txn_live, iter_live, close_count, reopen_required, fence_pending
        if iter_live and txn_live:
            port_trace.append("iter_close")
            iter_live = False
        if txn_live:
            port_trace.append("rollback")
            txn_live = False
            iter_live = False
        outcome = sticky or primary or "OK"
        if fence_pending:
            port_trace.append("close")
            close_count += 1
            reopen_required = 1
            fence_pending = 0
        state = "DONE"
        return outcome

    def do_exact_get(key_hex: str) -> str:
        nonlocal get_call, value_buf, fence_pending, state
        # Prevalidation: state
        if state not in ("OPEN", "EXHAUSTED"):
            return "INVALID_STATE"
        key = from_hex(key_hex) if key_hex is not None else b""
        if not key or len(key) < 1 or len(key) > KEY_CAP:
            return "INVALID_ARGUMENT"
        if not txn_live or not iter_live:
            set_sticky("STORAGE_CORRUPT")
            state = "FAILED"
            return "STORAGE_CORRUPT"

        get_call += 1
        port_trace.append("get")
        fault = find_fault("get", get_call)
        capacity = VALUE_CAP
        length = 0
        status = "OK"
        data_ptr_ok = True
        cap_ok = True
        raw: Optional[bytes] = None

        if fault is not None:
            shape = fault.get("shape", "natural")
            status = fault.get("status", "OK")
            if shape == "bts":
                status = "BUFFER_TOO_SMALL"
                length = int(fault.get("value_length", 0) or 0)
            elif shape == "not_found_poison":
                status = "NOT_FOUND"
                length = int(fault.get("value_length", 0) or 1)
            elif shape == "ok_bad_length":
                status = "OK"
                length = int(fault.get("value_length", 0) or (capacity + 1))
                if length <= capacity:
                    length = capacity + 1
            elif shape == "non_ok_nonempty":
                # Known non-OK (or unknown) with poisoned non-zero length.
                if status == "OK":
                    status = "IO_ERROR"
                if status == "UNKNOWN_RAW":
                    status = "UNKNOWN_RAW"
                length = int(fault.get("value_length", 0) or 1)
            elif shape == "rewrite_data_ptr":
                status = "OK"
                data_ptr_ok = False
                raw = lookup(key)
                length = len(raw) if raw is not None else 0
            elif shape == "rewrite_capacity":
                status = "OK"
                cap_ok = False
                raw = lookup(key)
                if raw is None:
                    status = "NOT_FOUND"
                    length = 0
                elif len(raw) > capacity:
                    status = "BUFFER_TOO_SMALL"
                    length = 0
                else:
                    length = len(raw)
                    value_buf = raw
            elif shape == "unknown":
                status = "UNKNOWN_RAW"
                length = int(fault.get("value_length", 0) or 0)
            elif status != "OK":
                length = 0
            else:
                fault = None

        if fault is None or fault.get("shape") in (
            "rewrite_data_ptr",
            "rewrite_capacity",
        ):
            if fault is None or fault.get("shape") == "rewrite_data_ptr":
                raw = lookup(key)
                if raw is None:
                    status = "NOT_FOUND"
                    length = 0
                elif len(raw) > capacity:
                    status = "BUFFER_TOO_SMALL"
                    length = 0
                else:
                    status = "OK"
                    length = len(raw)
                    if data_ptr_ok and cap_ok:
                        value_buf = raw

        if not data_ptr_ok or not cap_ok:
            # Descriptor rewrite always fences.
            fence_pending = 1
            set_sticky("STORAGE_CORRUPT")
            state = "FAILED"
            observations.append(
                {"status": "STORAGE_CORRUPT", "presence": "", "value_hex": ""}
            )
            return "STORAGE_CORRUPT"

        def note_fail(st: str) -> str:
            observations.append(
                {"status": st, "presence": "", "value_hex": ""}
            )
            return st

        if status == "OK":
            if length > capacity:
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                return note_fail("STORAGE_CORRUPT")
            observations.append(
                {
                    "status": "OK",
                    "presence": "PRESENT",
                    "value_hex": hex_of(value_buf if length else b""),
                }
            )
            return "OK"
        if status == "NOT_FOUND":
            if length != 0:
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                return note_fail("STORAGE_CORRUPT")
            observations.append(
                {"status": "OK", "presence": "ABSENT", "value_hex": ""}
            )
            return "OK"
        if status == "BUFFER_TOO_SMALL":
            set_sticky("STORAGE_CORRUPT")
            state = "FAILED"
            return note_fail("STORAGE_CORRUPT")

        # Combined raw-status / shape precedence: fence-required status sets
        # fence_pending even when length is also poisoned; shape poison still
        # yields STORAGE_CORRUPT over mapped port status.
        known = status in (
            "BUSY",
            "NO_SPACE",
            "IO_ERROR",
            "UNSUPPORTED_SCHEMA",
            "COMMIT_UNKNOWN",
            "CORRUPT",
            "BUFFER_TOO_SMALL",
            "NOT_FOUND",
            "OK",
        )
        if status == "COMMIT_UNKNOWN" or status == "UNKNOWN_RAW" or not known:
            fence_pending = 1
        if status == "UNKNOWN_RAW" or not known or length != 0:
            set_sticky("STORAGE_CORRUPT")
            state = "FAILED"
            return note_fail("STORAGE_CORRUPT")
        if status == "COMMIT_UNKNOWN":
            mapped = "STORAGE_COMMIT_UNKNOWN"
            set_sticky(mapped)
            state = "FAILED"
            return note_fail(mapped)
        mapped = map_storage(status)
        set_sticky(mapped)
        state = "FAILED"
        return note_fail(mapped)

    def do_advance(budget: int) -> str:
        nonlocal row_index, iter_next_call, ok_rows, family14, seen_mask
        nonlocal has_previous, previous, state, value_buf, future_seen
        nonlocal current_dom
        if state != "OPEN":
            return "INVALID_STATE"
        if budget == 0:
            return "INVALID_ARGUMENT"
        consumed = 0
        while consumed < budget:
            iter_next_call += 1
            port_trace.append("iter_next")
            if row_index >= len(rows):
                # natural end
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
            # lex
            if has_previous:
                if not (key > previous):
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
                pass  # skip domain body
            elif (
                len(key) >= 8
                and key[:7] == ROOT_V1[:7]
                and key[7] >= 2
            ):
                # recognizable future root (non-terminal)
                future_seen = 1
            else:
                # non-catalog current-root: oracle treats as domain visit
                # without full S3 body matrix (S4 seam ownership only).
                current_dom += 1
            value_buf = val
            previous = key
            has_previous = True
            ok_rows += 1
            consumed += 1
        return "OK"

    last_status = "OK"
    for call in calls:
        op = call["op"]
        if op == "begin_profiled":
            if state != "IDLE":
                last_status = "INVALID_STATE"
                continue
            port_trace.append("begin:READ_ONLY")
            txn_live = True
            gate = do_profile_gets()
            if gate not in (None, "EXACT", "MISMATCH", "FUTURE") and gate != "OK":
                # gate returns outcome strings
                if gate in ("EXACT", "MISMATCH", "FUTURE"):
                    pass
                else:
                    set_sticky(gate if gate else "STORAGE_CORRUPT")
                    last_status = cleanup(gate)
                    continue
            if gate == "STORAGE_CORRUPT" or (
                gate
                and gate
                not in (
                    "EXACT",
                    "MISMATCH",
                    "FUTURE",
                    None,
                )
            ):
                # already handled above when not EXACT/MISMATCH/FUTURE
                pass
            if gate in ("EXACT", "MISMATCH", "FUTURE"):
                if gate == "EXACT":
                    profile_exact = 1
                elif gate == "MISMATCH":
                    profile_mismatch = 1
                else:
                    future_profile = 1
                recon = 1
                # iter_open
                fault = find_fault("iter_open", 1)
                if fault is not None:
                    set_sticky("STORAGE_CORRUPT")
                    last_status = cleanup("STORAGE_CORRUPT")
                    continue
                port_trace.append("iter_open:prefix0")
                iter_opened = 1
                iter_open_count = 1
                iter_live = True
                state = "OPEN"
                last_status = "OK"
            else:
                # failure path already cleaned?
                if state != "DONE":
                    set_sticky(gate or "STORAGE_CORRUPT")
                    last_status = cleanup(gate)
                else:
                    last_status = sticky or gate or "STORAGE_CORRUPT"
        elif op == "advance":
            last_status = do_advance(int(call.get("row_budget", 0)))
        elif op == "exact_get":
            st = do_exact_get(call.get("key_hex", ""))
            last_status = st
            if st in ("INVALID_ARGUMENT", "INVALID_STATE"):
                observations.append(
                    {
                        "status": st,
                        "presence": "",
                        "value_hex": "",
                    }
                )
        elif op == "finalize":
            if state not in ("EXHAUSTED", "FAILED"):
                last_status = "INVALID_STATE"
            else:
                outcome = cleanup(None)
                if sticky:
                    last_status = sticky
                elif profile_mismatch or future_profile:
                    last_status = "UNSUPPORTED"
                elif future_seen:
                    last_status = "UNSUPPORTED"
                else:
                    last_status = outcome
        elif op == "abort":
            if state not in ("OPEN", "EXHAUSTED", "FAILED"):
                last_status = "INVALID_STATE"
            else:
                outcome = cleanup(None)
                last_status = sticky or outcome
        else:
            raise SystemExit(f"unknown call op {op}")

    adopted = 0
    if (
        state == "DONE"
        and sticky is None
        and not profile_mismatch
        and not future_profile
        and not future_seen
        and last_status == "OK"
        and reopen_required == 0
        and calls
        and calls[-1]["op"] == "finalize"
    ):
        # adopt only if we reached EXHAUSTED without sticky before cleanup
        adopted = 1 if ok_rows >= 0 and recon else 0
        # stricter: only when finalize from clean exhausted
        if not (
            profile_exact
            and family14 == 17
            and present_mask == ALL_MASK
            and seen_mask == ALL_MASK
        ):
            # still may adopt if transport-less? we always recon on profiled
            pass

    # Fix adopt: require no sticky, finalize, and we had exhausted success.
    if sticky is not None or profile_mismatch or future_profile or future_seen:
        adopted = 0
    if calls and calls[-1]["op"] == "finalize" and last_status == "OK" and reopen_required == 0:
        if sticky is None and not profile_mismatch and not future_profile and not future_seen:
            adopted = 1
        else:
            adopted = 0
    else:
        if calls and calls[-1]["op"] != "finalize":
            adopted = 0

    return expected_base(
        final_status=last_status,
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
        exact_observations=list(observations),
    )


def make_vector(
    vid: str,
    kind: str,
    rows: List[Dict[str, str]],
    calls: List[Dict[str, Any]],
    *,
    faults: Optional[List[Dict[str, Any]]] = None,
    binding: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    vec: Dict[str, Any] = {
        "id": vid,
        "kind": kind,
        "candidate_binding": binding or default_binding_fields(),
        "rows": rows,
        "faults": faults or [],
        "calls": calls,
    }
    exp = run_case(vec)
    vec["expected"] = exp
    return vec


def build_vectors() -> List[Dict[str, Any]]:
    b = default_binding_fields()
    profile = encode_all_profile_rows(b)
    rows_only_profile = list(profile)
    # Present targets are catalog keys already in the profile snapshot.
    k_binding = catalog_key(1)
    k_identity = catalog_key(2)
    k_absent = absent_key(0x01)
    # Zero-length / 4096 present targets use opaque keys installed in the
    # snapshot. Vectors that exact_get them abort (or finalize only after
    # no advance through non-catalog current rows) so S3 structural does not
    # terminal-corrupt the seam observation under test.
    k_zero = absent_key(0x02)
    k_4096 = absent_key(0x03)
    rows_zero = profile + [{"key_hex": hex_of(k_zero), "value_hex": ""}]
    rows_4096 = profile + [
        {
            "key_hex": hex_of(k_4096),
            "value_hex": hex_of(bytes([0x5A]) * 4096),
        }
    ]

    mismatch_rows = encode_all_profile_rows(b)
    bind = bytearray(from_hex(mismatch_rows[0]["value_hex"]))
    bind[50] ^= 0x01
    body = bytes(bind[:-4])
    bind[-4:] = be32(crc32c(body))
    mismatch_rows[0]["value_hex"] = hex_of(bytes(bind))

    future_rows = encode_all_profile_rows(b, binding_version=2)
    binding_value_hex = profile[0]["value_hex"]
    identity_value_hex = profile[1]["value_hex"]

    vectors: List[Dict[str, Any]] = []

    # present while iterator live (catalog binding key)
    vectors.append(
        make_vector(
            "S4_PRESENT_WHILE_ITER_LIVE",
            "present_live",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 5},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # missing key
    vectors.append(
        make_vector(
            "S4_ABSENT_KEY",
            "absent",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_absent)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # present zero-length (abort: do not advance through non-catalog row)
    vectors.append(
        make_vector(
            "S4_PRESENT_ZERO_LENGTH",
            "present_zero",
            rows_zero,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_zero)},
                {"op": "abort"},
            ],
        )
    )

    # get in EXHAUSTED
    vectors.append(
        make_vector(
            "S4_GET_IN_EXHAUSTED",
            "exhausted_get",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "exact_get", "key_hex": hex_of(k_identity)},
                {"op": "finalize"},
            ],
        )
    )

    # 4096 boundary present (abort after get; no structural advance of row)
    vectors.append(
        make_vector(
            "S4_VALUE_4096_BOUNDARY",
            "value_boundary",
            rows_4096,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_4096)},
                {"op": "abort"},
            ],
        )
    )

    # BTS 4097 via fault on exact get (18th get)
    vectors.append(
        make_vector(
            "S4_BTS_4097_NO_REREAD",
            "bts_corrupt",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "BUFFER_TOO_SMALL",
                    "shape": "bts",
                    "key_length": 0,
                    "value_length": 4097,
                }
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_REWRITE_DATA_PTR",
            "descriptor_rewrite",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "OK",
                    "shape": "rewrite_data_ptr",
                    "key_length": 0,
                    "value_length": 0,
                }
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_REWRITE_CAPACITY",
            "descriptor_rewrite",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "OK",
                    "shape": "rewrite_capacity",
                    "key_length": 0,
                    "value_length": 0,
                }
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_NOT_FOUND_POISON",
            "not_found_poison",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_absent)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "NOT_FOUND",
                    "shape": "not_found_poison",
                    "key_length": 0,
                    "value_length": 1,
                }
            ],
        )
    )

    # OK + length > capacity (spy OK_BAD_LENGTH → capacity+1 / >4096).
    vectors.append(
        make_vector(
            "S4_OK_BAD_LENGTH",
            "ok_bad_length",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "OK",
                    "shape": "ok_bad_length",
                    "key_length": 0,
                    "value_length": 4097,
                }
            ],
        )
    )

    # Known non-OK + nonempty length: IO → STORAGE_CORRUPT, no fence.
    vectors.append(
        make_vector(
            "S4_IO_NONEMPTY_LENGTH",
            "non_ok_nonempty",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "IO_ERROR",
                    "shape": "non_ok_nonempty",
                    "key_length": 0,
                    "value_length": 1,
                }
            ],
        )
    )

    # COMMIT_UNKNOWN + poisoned length: fence_pending + STORAGE_CORRUPT
    # (shape wins mapping; fence still set from raw status).
    vectors.append(
        make_vector(
            "S4_COMMIT_UNKNOWN_NONEMPTY",
            "fence_shape_combined",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "COMMIT_UNKNOWN",
                    "shape": "non_ok_nonempty",
                    "key_length": 0,
                    "value_length": 1,
                }
            ],
        )
    )

    for name, status, shape in (
        ("IO", "IO_ERROR", "natural"),
        ("BUSY", "BUSY", "natural"),
        ("CORRUPT", "CORRUPT", "natural"),
        ("UNSUPPORTED", "UNSUPPORTED_SCHEMA", "natural"),
        ("COMMIT_UNKNOWN", "COMMIT_UNKNOWN", "natural"),
    ):
        vectors.append(
            make_vector(
                f"S4_GET_FAULT_{name}",
                "known_port_fault",
                rows_only_profile,
                [
                    {"op": "begin_profiled"},
                    {"op": "exact_get", "key_hex": hex_of(k_binding)},
                    {"op": "finalize"},
                ],
                faults=[
                    {
                        "op": "get",
                        "on_call": 18,
                        "status": status,
                        "shape": shape,
                        "key_length": 0,
                        "value_length": 0,
                    }
                ],
            )
        )

    vectors.append(
        make_vector(
            "S4_UNKNOWN_RAW_STATUS",
            "unknown_status",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "UNKNOWN_RAW",
                    "shape": "unknown",
                    "key_length": 0,
                    "value_length": 0,
                }
            ],
        )
    )

    # Unknown raw status + poison length: fence + STORAGE_CORRUPT.
    vectors.append(
        make_vector(
            "S4_UNKNOWN_POISON_LENGTH",
            "fence_shape_combined",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "UNKNOWN_RAW",
                    "shape": "non_ok_nonempty",
                    "key_length": 0,
                    "value_length": 3,
                }
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_STATE_GATE_AFTER_DONE",
            "state_gate",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_KEY_EMPTY_INVALID",
            "key_shape",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": ""},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_COUNTERS_STABLE_ACROSS_GET",
            "counter_stable",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 3},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # repeated overwrite: binding then identity values
    vectors.append(
        make_vector(
            "S4_REPEAT_OVERWRITE",
            "repeat_overwrite",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "exact_get", "key_hex": hex_of(k_identity)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_PROFILE_MISMATCH_NO_AUTO_GET",
            "profile_no_auto",
            mismatch_rows,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_FUTURE_PROFILE_NO_AUTO_GET",
            "profile_no_auto",
            future_rows,
            [
                {"op": "begin_profiled"},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # sizeof/workspace ceiling gate material (bridge asserts sizeof <= 8192).
    vectors.append(
        make_vector(
            "S4_DSR2_CEILING",
            "dsr2_ceiling",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    # mutation_calls == 0 on exact-get success path (bridge kind gate).
    vectors.append(
        make_vector(
            "S4_MUTATION_ZERO",
            "mutation_zero",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_STICKY_THEN_EXACT_REJECTED",
            "state_gate",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "finalize"},
            ],
            faults=[
                {
                    "op": "get",
                    "on_call": 18,
                    "status": "IO_ERROR",
                    "shape": "natural",
                    "key_length": 0,
                    "value_length": 0,
                }
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_GET_CATALOG_KEY_WHILE_LIVE",
            "present_live",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "advance", "row_budget": 64},
                {"op": "finalize"},
            ],
        )
    )

    vectors.append(
        make_vector(
            "S4_ABORT_AFTER_GET",
            "mutation_zero",
            rows_only_profile,
            [
                {"op": "begin_profiled"},
                {"op": "exact_get", "key_hex": hex_of(k_binding)},
                {"op": "abort"},
            ],
        )
    )

    # Sanity: binding/identity hex used by bridge compare pins (generator-side).
    assert from_hex(binding_value_hex)[:4] == b"NLR1"
    assert from_hex(identity_value_hex)[:4] == b"NLR1"

    return vectors


def artifact_dict(vectors: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "version": VERSION,
        "format": FORMAT,
        "scope": (
            "D2-S4 same-snapshot exact get seam ownership only. "
            "Does not claim DSR1_SCAN / DSR2_ESP_BOUND / D2 / Stage 5 / "
            "public Runtime / D3 relationship semantics / ESP hardware complete."
        ),
        "workspace": {
            "key_capacity": KEY_CAP,
            "value_capacity": VALUE_CAP,
            "previous_key_capacity": PREV_CAP,
            "ceiling_bytes": CEILING,
            "value_buffer_note": (
                "single 4096 value buffer reuse for exact_get borrow; "
                "second 4096 buffer forbidden; no full-ID set"
            ),
        },
        "s1_authority": {
            "path": "spec/vectors/domain-scan-v1.json",
            "format": S1_FORMAT,
            "sha256": S1_SHA256,
        },
        "s2_authority": {
            "path": "spec/vectors/domain-scan-profile-v1.json",
            "format": S2_FORMAT,
            "sha256": S2_SHA256,
        },
        "s3_authority": {
            "path": "spec/vectors/domain-scan-structural-v1.json",
            "format": S3_FORMAT,
            "sha256": S3_SHA256,
        },
        "vectors": vectors,
    }


def generate(path: Path) -> None:
    assert_authority_pins()
    vectors = build_vectors()
    kinds = {v["kind"] for v in vectors}
    missing = REQUIRED_KINDS - kinds
    if missing:
        raise SystemExit(f"missing required kinds: {sorted(missing)}")
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        raise SystemExit(
            f"vector count pin mismatch: got={len(vectors)} "
            f"expected={EXPECTED_VECTOR_COUNT}"
        )
    art = artifact_dict(vectors)
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(art, indent=2, sort_keys=True) + "\n"
    path.write_text(text, encoding="utf-8")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"wrote {path} vectors={len(vectors)} sha256={digest}")


def check(path: Path) -> int:
    assert_authority_pins()
    data = json.loads(path.read_text(encoding="utf-8"))
    expected_doc = artifact_dict(build_vectors())
    if data.get("format") != FORMAT or data.get("version") != VERSION:
        print("format/version mismatch", file=sys.stderr)
        return 1
    for key in (
        "scope",
        "workspace",
        "s1_authority",
        "s2_authority",
        "s3_authority",
        "vectors",
    ):
        if key not in data:
            print(f"missing top-level {key}", file=sys.stderr)
            return 1
    if data["workspace"].get("ceiling_bytes") != CEILING:
        print("workspace ceiling pin failed", file=sys.stderr)
        return 1
    if data["s1_authority"].get("sha256") != S1_SHA256:
        print("s1 sha pin failed", file=sys.stderr)
        return 1
    if data["s2_authority"].get("sha256") != S2_SHA256:
        print("s2 sha pin failed", file=sys.stderr)
        return 1
    if data["s3_authority"].get("sha256") != S3_SHA256:
        print("s3 sha pin failed", file=sys.stderr)
        return 1
    if data["s1_authority"].get("format") != S1_FORMAT:
        print("s1 format pin failed", file=sys.stderr)
        return 1
    if data["s2_authority"].get("format") != S2_FORMAT:
        print("s2 format pin failed", file=sys.stderr)
        return 1
    if data["s3_authority"].get("format") != S3_FORMAT:
        print("s3 format pin failed", file=sys.stderr)
        return 1

    vectors = data["vectors"]
    kinds = set()
    rebuilt = expected_doc["vectors"]
    if len(vectors) != EXPECTED_VECTOR_COUNT:
        print(
            f"vector count pin mismatch: file={len(vectors)} "
            f"pin={EXPECTED_VECTOR_COUNT}",
            file=sys.stderr,
        )
        return 1
    if len(rebuilt) != len(vectors):
        print(
            f"vector count mismatch: file={len(vectors)} rebuilt={len(rebuilt)}",
            file=sys.stderr,
        )
        return 1
    for i, (file_v, expect_v) in enumerate(zip(vectors, rebuilt)):
        unknown = set(file_v.keys()) - VECTOR_KEYS
        if unknown:
            print(f"{file_v.get('id')}: unknown keys {unknown}", file=sys.stderr)
            return 1
        if file_v.get("kind") not in REQUIRED_KINDS:
            print(
                f"{file_v.get('id')}: kind {file_v.get('kind')!r} not in "
                f"closed required set",
                file=sys.stderr,
            )
            return 1
        kinds.add(file_v["kind"])
        for f in file_v.get("faults", []):
            if set(f.keys()) - FAULT_KEYS:
                print(f"{file_v['id']}: fault key drift", file=sys.stderr)
                return 1
        for c in file_v["calls"]:
            if set(c.keys()) - CALL_KEYS:
                print(f"{file_v['id']}: call key drift {c}", file=sys.stderr)
                return 1
        exp = file_v["expected"]
        if set(exp.keys()) - EXPECTED_KEYS:
            print(f"{file_v['id']}: expected key drift", file=sys.stderr)
            return 1
        for obs in exp.get("exact_observations", []):
            if set(obs.keys()) - OBS_KEYS:
                print(f"{file_v['id']}: obs key drift", file=sys.stderr)
                return 1
        # Recompute expected independently and compare.
        recomputed = run_case(
            {
                "id": file_v["id"],
                "kind": file_v["kind"],
                "candidate_binding": file_v["candidate_binding"],
                "rows": file_v["rows"],
                "faults": file_v["faults"],
                "calls": file_v["calls"],
            }
        )
        if recomputed != exp:
            print(f"{file_v['id']}: expected mismatch vs oracle model", file=sys.stderr)
            # show small diff
            for k in sorted(set(recomputed) | set(exp)):
                if recomputed.get(k) != exp.get(k):
                    print(f"  {k}: file={exp.get(k)!r} model={recomputed.get(k)!r}")
            return 1
        # Full structural equality per vector (id/kind/rows/faults/calls/expected).
        # Prevents kind drift that would bypass bridge kind gates.
        if file_v != expect_v:
            print(
                f"{file_v.get('id')}: full structural generate/check drift "
                f"(index {i})",
                file=sys.stderr,
            )
            for k in sorted(set(file_v) | set(expect_v)):
                if file_v.get(k) != expect_v.get(k):
                    print(
                        f"  field {k}: file differs from regenerated",
                        file=sys.stderr,
                    )
            return 1
    missing = REQUIRED_KINDS - kinds
    if missing:
        print(f"missing required kinds: {sorted(missing)}", file=sys.stderr)
        return 1
    # Full document structural equality (top-level + vectors).
    if json.dumps(data, sort_keys=True) != json.dumps(
        expected_doc, sort_keys=True
    ):
        print(
            "document not deterministically equal to generator output",
            file=sys.stderr,
        )
        return 1
    print(f"ok {path} vectors={len(vectors)} kinds={len(kinds)}")
    return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    data = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = data["vectors"]
    lines: List[str] = []
    lines.append("/* Generated by tools/domain_scan_exact_get_vector_gen.py — do not edit. */")
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_EXACT_GET_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_EXACT_GET_VECTOR_FIXTURE_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(f"#define NINLIL_DSE_VECTOR_COUNT ((size_t){len(vectors)}u)")
    lines.append(f"#define NINLIL_DSE_WORKSPACE_CEILING_BYTES ((uint32_t){CEILING}u)")
    lines.append("#define NINLIL_DSE_MAX_TRACE ((size_t)256u)")
    lines.append("#define NINLIL_DSE_MAX_KEY ((size_t)255u)")
    lines.append("#define NINLIL_DSE_MAX_VALUE ((size_t)4096u)")
    lines.append("#define NINLIL_DSE_MAX_OBS ((size_t)8u)")
    lines.append("")
    lines.append("typedef struct ninlil_dse_binding {")
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
    lines.append("} ninlil_dse_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dse_row {")
    lines.append("    uint8_t key[16];")
    lines.append("    uint32_t key_length;")
    lines.append("    const uint8_t *value;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dse_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dse_fault {")
    lines.append("    const char *op;")
    lines.append("    uint32_t on_call;")
    lines.append("    const char *shape;")
    lines.append("    const char *status;")
    lines.append("    uint32_t key_length;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dse_fault_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dse_call {")
    lines.append("    const char *op;")
    lines.append("    uint32_t row_budget;")
    lines.append("    const uint8_t *key;")
    lines.append("    uint32_t key_length;")
    lines.append("} ninlil_dse_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dse_obs {")
    lines.append("    const char *status;")
    lines.append("    const char *presence;")
    lines.append("    const uint8_t *value;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dse_obs_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dse_expected {")
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
    lines.append("    const ninlil_dse_obs_t *observations;")
    lines.append("    size_t observation_count;")
    lines.append("} ninlil_dse_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dse_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    ninlil_dse_binding_t candidate;")
    lines.append("    const ninlil_dse_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_dse_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_dse_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_dse_expected_t expected;")
    lines.append("} ninlil_dse_vector_t;")
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

    # Emit value blobs and rows/faults/calls/obs per vector
    for vi, vec in enumerate(vectors):
        for ri, r in enumerate(vec.get("rows", [])):
            vb = from_hex(r.get("value_hex", ""))
            if len(vb) > 4096:
                # store truncated marker — should not happen for natural OK paths
                vb = vb[:4096]
            arr = ", ".join(f"0x{b:02x}u" for b in vb) if vb else "0"
            lines.append(
                f"static const uint8_t ninlil_dse_val_{vi}_{ri}[] = {{ {arr} }};"
            )
        for oi, obs in enumerate(vec["expected"].get("exact_observations", [])):
            vb = from_hex(obs.get("value_hex", ""))
            if len(vb) > 4096:
                vb = vb[:4096]
            arr = ", ".join(f"0x{b:02x}u" for b in vb) if vb else "0"
            lines.append(
                f"static const uint8_t ninlil_dse_obsval_{vi}_{oi}[] = {{ {arr} }};"
            )
        for ci, c in enumerate(vec["calls"]):
            if c["op"] == "exact_get":
                kb = from_hex(c.get("key_hex", ""))
                arr = ", ".join(f"0x{b:02x}u" for b in kb) if kb else "0"
                lines.append(
                    f"static const uint8_t ninlil_dse_callkey_{vi}_{ci}[] = {{ {arr} }};"
                )

        lines.append(f"static const ninlil_dse_row_t ninlil_dse_rows_{vi}[] = {{")
        for ri, r in enumerate(vec.get("rows", [])):
            kb = from_hex(r.get("key_hex", ""))
            vb = from_hex(r.get("value_hex", ""))
            vlen = min(len(vb), 4096)
            if len(kb) > 16:
                raise SystemExit(f"key too large for fixture: {vec['id']}")
            karr = ", ".join(f"0x{b:02x}u" for b in kb) if kb else "0"
            lines.append(
                f"    {{{{ {karr} }}, {len(kb)}u, ninlil_dse_val_{vi}_{ri}, {vlen}u }},"
            )
        if not vec.get("rows"):
            lines.append("    { { 0u }, 0u, NULL, 0u },")
        lines.append("};")

        lines.append(f"static const ninlil_dse_fault_t ninlil_dse_faults_{vi}[] = {{")
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f["op"]}", {int(f["on_call"])}u, "{f.get("shape", "natural")}", '
                f'"{f.get("status", "OK")}", {int(f.get("key_length", 0))}u, '
                f'{int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append('    { NULL, 0u, NULL, NULL, 0u, 0u },')
        lines.append("};")

        lines.append(f"static const ninlil_dse_call_t ninlil_dse_calls_{vi}[] = {{")
        for ci, c in enumerate(vec["calls"]):
            if c["op"] == "exact_get":
                kb = from_hex(c.get("key_hex", ""))
                lines.append(
                    f'    {{ "exact_get", 0u, ninlil_dse_callkey_{vi}_{ci}, {len(kb)}u }},'
                )
            else:
                lines.append(
                    f'    {{ "{c["op"]}", {int(c.get("row_budget", 0))}u, NULL, 0u }},'
                )
        lines.append("};")

        lines.append(f"static const char *const ninlil_dse_trace_{vi}[] = {{")
        for t in vec["expected"].get("port_trace", []):
            lines.append(f'    "{t}",')
        if not vec["expected"].get("port_trace"):
            lines.append("    NULL")
        lines.append("};")

        lines.append(f"static const ninlil_dse_obs_t ninlil_dse_obs_{vi}[] = {{")
        for oi, obs in enumerate(vec["expected"].get("exact_observations", [])):
            vb = from_hex(obs.get("value_hex", ""))
            vlen = min(len(vb), 4096)
            presence = obs.get("presence", "")
            lines.append(
                f'    {{ "{obs["status"]}", "{presence}", '
                f"ninlil_dse_obsval_{vi}_{oi}, {vlen}u }},"
            )
        if not vec["expected"].get("exact_observations"):
            lines.append('    { NULL, NULL, NULL, 0u },')
        lines.append("};")
        lines.append("")

    lines.append(
        "static const ninlil_dse_vector_t ninlil_dse_vectors[NINLIL_DSE_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(vectors):
        exp = vec["expected"]
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(f"        ninlil_dse_rows_{vi}, {len(vec.get('rows', []))}u,")
        lines.append(f"        ninlil_dse_faults_{vi}, {len(vec.get('faults', []))}u,")
        lines.append(f"        ninlil_dse_calls_{vi}, {len(vec['calls'])}u,")
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
            f"            ninlil_dse_trace_{vi}, {len(exp.get('port_trace', []))}u,"
        )
        lines.append(
            f"            ninlil_dse_obs_{vi}, {len(exp.get('exact_observations', []))}u"
        )
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_EXACT_GET_VECTOR_FIXTURE_H */")
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
