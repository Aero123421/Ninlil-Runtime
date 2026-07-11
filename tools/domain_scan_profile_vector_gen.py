#!/usr/bin/env python3
"""Independent D2-S2 domain-scan profile vector oracle (stdlib only).

Does NOT invoke, import, link, or translate production C bootstrap/scanner.
Implements a closed reference model of docs/17 §15.10 / §17.1.2 using
literal NLR1 framing / CRC32C / typed field encoding.

Usage:
  python3 tools/domain_scan_profile_vector_gen.py generate <path>
  python3 tools/domain_scan_profile_vector_gen.py check <path>
  python3 tools/domain_scan_profile_vector_gen.py emit-c-fixture <json> <c-header>
"""

from __future__ import annotations

import copy
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

FORMAT = "ninlil-domain-scan-profile-v1-d2s2"
VERSION = 1
ROOT_V1 = bytes([0x4E, 0x49, 0x4E, 0x4C, 0x49, 0x4C, 0x00, 0x01])
PROFILE_NAME = b"NINLIL-FOUNDATION-SMALL-1"
KEY_CAP = 255
VALUE_CAP = 4096
PREV_CAP = 255
CEILING = 8192
ALL_MASK = 0x1FFFF
ENCODED_CAPS = [183, 84, 32, 32, 32, 32, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68, 68]

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
    # flags: HAS_DEVICE | HAS_INSTALLATION | HAS_SITE = 0x7
    payload += be32(0x7)
    payload += bytes(range(0x20, 0x30))  # device
    payload += bytes(range(0x40, 0x50))  # installation
    payload += bytes(range(0x60, 0x70))  # site
    payload += be64(1)  # binding_epoch
    payload += be64(1)  # membership_epoch
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
    corrupt_key_id: Optional[int] = None,
    omit_key_ids: Optional[List[int]] = None,
    mutate_binding_byte: Optional[int] = None,
) -> List[Dict[str, str]]:
    omit = set(omit_key_ids or [])
    rows: List[Tuple[int, bytes, bytes]] = []
    for key_id in range(1, 18):
        if key_id in omit:
            continue
        key = catalog_key(key_id)
        if key_id == 1:
            if binding_version != 1:
                # Future record version with valid CRC (unsupported).
                payload = encode_binding(binding_fields)[12:-4]
                # re-wrap manually with version
                head = b"NLR1" + be16(1) + be16(binding_version) + be32(len(payload))
                body = head + payload
                value = body + be32(crc32c(body))
            else:
                value = encode_binding(binding_fields)
            if mutate_binding_byte is not None:
                b = bytearray(value)
                # Flip a payload byte before CRC recompute would break CRC;
                # for corrupt path flip CRC trailer byte.
                b[mutate_binding_byte] ^= 0xFF
                value = bytes(b)
            if corrupt_key_id == 1:
                value = value[:-1] + bytes([value[-1] ^ 0xFF])
        elif key_id == 2:
            value = encode_identity()
            if corrupt_key_id == 2:
                value = value[:-1] + bytes([value[-1] ^ 0xFF])
        elif 3 <= key_id <= 6:
            value = encode_counter(key_id - 2)
            if corrupt_key_id == key_id:
                value = value[:-1] + bytes([value[-1] ^ 0xFF])
        else:
            value = encode_capacity(key_id - 6, limit=100 + key_id)
            if corrupt_key_id == key_id:
                value = value[:-1] + bytes([value[-1] ^ 0xFF])
        rows.append((key_id, key, value))
    # storage order: unsigned byte lex of keys (catalog keys are already sorted)
    rows.sort(key=lambda r: r[1])
    return [{"key_hex": hex_of(k), "value_hex": hex_of(v)} for _, k, v in rows]


def domain_malformed_row() -> Dict[str, str]:
    # current-root family6 incomplete key -> malformed under exact profile;
    # skipped under mismatch/future mode.
    key = ROOT_V1 + bytes([0x06, 0x10])
    return {"key_hex": hex_of(key), "value_hex": ""}


def noncatalog_f14_row() -> Dict[str, str]:
    # family 0x03 suffix 0: prefix-shaped noncatalog
    key = ROOT_V1 + bytes([0x03, 0x00])
    return {"key_hex": hex_of(key), "value_hex": ""}


def port_trace_success(gets: int = 17, iters: int = 1, nexts: int = 0) -> List[str]:
    t = ["begin:READ_ONLY"]
    t.extend(["get"] * gets)
    if iters:
        t.append("iter_open:prefix0")
    t.extend(["iter_next"] * nexts)
    t.append("iter_close")
    t.append("rollback")
    return t


def port_trace_no_iter(gets: int = 17) -> List[str]:
    t = ["begin:READ_ONLY"]
    t.extend(["get"] * gets)
    t.append("rollback")
    return t


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
        "port_trace": [],
    }
    base.update(kwargs)
    return base


VECTOR_KEYS = frozenset(
    {"id", "kind", "candidate_binding", "rows", "faults", "calls", "expected"}
)
FAULT_KEYS = frozenset({"op", "on_call", "status", "shape", "key_length", "value_length"})
CALL_KEYS = frozenset({"op", "row_budget"})
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
        "port_trace",
    }
)
# §17.1.2 closed kind set; every required kind must appear in the artifact.
REQUIRED_KINDS = frozenset(
    {
        "profile_exact",
        "profile_mismatch",
        "future_profile",
        "completeness",
        "get_fault",
        "iterator_reconcile",
        "precedence",
        "dsr2_ceiling",
    }
)
ALLOWED_KINDS = REQUIRED_KINDS


def assert_no_unknown_keys(obj: Dict[str, Any], allowed: frozenset, where: str) -> None:
    unknown = set(obj.keys()) - allowed
    if unknown:
        raise SystemExit(f"{where}: unknown keys {sorted(unknown)}")


def run_case(vec: Dict[str, Any]) -> Dict[str, Any]:
    """Closed oracle of profiled begin + advance + finalize/abort outcomes.

    This is an independent reference model, not a production C translator.
    Never mutates the caller's vector/fault objects.
    """
    binding = vec["candidate_binding"]
    rows = [(from_hex(r["key_hex"]), from_hex(r["value_hex"])) for r in vec.get("rows", [])]
    # Deep copy faults so execution never writes oracle-state into inputs.
    faults: List[Dict[str, Any]] = copy.deepcopy(list(vec.get("faults", [])))
    used_fault_indices: Set[int] = set()
    calls = vec["calls"]

    # Simulate Port state
    present_mask = 0
    retained: Dict[int, bytes] = {}
    get_call = 0
    iter_opened = 0
    port_trace: List[str] = []
    mutation_calls = 0
    close_count = 0
    reopen_required = 0
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

    def f14_noncatalog(key: bytes) -> bool:
        if len(key) < 9 or key[:8] != ROOT_V1:
            return False
        if not (0x01 <= key[8] <= 0x04):
            return False
        return catalog_id(key) is None

    def find_fault(op: str, on_call: int) -> Optional[Dict[str, Any]]:
        for index, f in enumerate(faults):
            if index in used_fault_indices:
                continue
            if f["op"] == op and int(f["on_call"]) == on_call:
                used_fault_indices.add(index)
                return f
        return None

    def validate_and_compare() -> str:
        # Match production validate_snapshot: accumulate corrupt > unsupported.
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
            plen = struct.unpack(">I", val[8:12])[0]
            if plen != len(val) - 16:
                saw_corrupt = True
                continue
            st = struct.unpack(">I", val[12 + plen : 16 + plen])[0]
            if st != crc32c(val[: 12 + plen]):
                saw_corrupt = True
                continue
            exp = {
                1: 167,
                2: 68,
                3: 16,
                4: 52,
            }[1 if kid == 1 else 2 if kid == 2 else 3 if kid <= 6 else 4]
            if plen != exp:
                saw_corrupt = True
                continue
            if ver != 1:
                saw_unsup = True
        if saw_corrupt:
            return "STORAGE_CORRUPT"
        if saw_unsup:
            return "UNSUPPORTED"
        cand_enc = encode_binding(binding)
        if retained[1] == cand_enc:
            return "EXACT"
        return "MISMATCH"

    def cleanup(trace_close_iter: bool = True, fence: bool = False) -> None:
        nonlocal state, close_count, reopen_required
        if iter_opened and trace_close_iter:
            port_trace.append("iter_close")
        port_trace.append("rollback")
        if fence:
            port_trace.append("close")
            close_count = 1
            reopen_required = 1
        state = "DONE"

    def do_begin() -> str:
        nonlocal state, present_mask, recon, profile_exact, profile_mismatch
        nonlocal future_profile, iter_opened, get_call
        if state != "IDLE":
            return "INVALID_STATE"
        port_trace.append("begin:READ_ONLY")
        # 17 gets
        row_map = {catalog_id(k): v for k, v in rows if catalog_id(k) is not None}
        for kid in range(1, 18):
            get_call += 1
            f = find_fault("get", get_call)
            port_trace.append("get")
            if f is not None:
                shape = f.get("shape", "natural")
                status_name = f.get("status", "")
                if shape == "bts":
                    set_sticky("STORAGE_CORRUPT")
                    cleanup(trace_close_iter=False, fence=False)
                    return "STORAGE_CORRUPT"
                if shape == "not_found_poison":
                    set_sticky("STORAGE_CORRUPT")
                    cleanup(trace_close_iter=False, fence=False)
                    return "STORAGE_CORRUPT"
                if shape == "io_error":
                    set_sticky("STORAGE")
                    cleanup(trace_close_iter=False, fence=False)
                    return "STORAGE"
                if shape == "unknown":
                    # Unsafe/unknown Storage status: CORRUPT + fence after rollback.
                    set_sticky("STORAGE_CORRUPT")
                    cleanup(trace_close_iter=False, fence=True)
                    return "STORAGE_CORRUPT"
                if shape == "commit_unknown" or status_name == "COMMIT_UNKNOWN":
                    set_sticky("STORAGE_COMMIT_UNKNOWN")
                    cleanup(trace_close_iter=False, fence=True)
                    return "STORAGE_COMMIT_UNKNOWN"
                if shape == "natural" and status_name == "NOT_FOUND":
                    # forced absent
                    continue
            val = row_map.get(kid)
            if val is None:
                continue
            if len(val) > ENCODED_CAPS[kid - 1]:
                set_sticky("STORAGE_CORRUPT")
                cleanup(trace_close_iter=False, fence=False)
                return "STORAGE_CORRUPT"
            present_mask |= 1 << (kid - 1)
            retained[kid] = val
        if present_mask != ALL_MASK:
            set_sticky("STORAGE_CORRUPT")
            cleanup(trace_close_iter=False, fence=False)
            return "STORAGE_CORRUPT"
        gate = validate_and_compare()
        if gate == "STORAGE_CORRUPT":
            set_sticky("STORAGE_CORRUPT")
            cleanup(trace_close_iter=False, fence=False)
            return "STORAGE_CORRUPT"
        if gate == "UNSUPPORTED":
            future_profile = 1
            profile_exact = 0
            profile_mismatch = 0
        elif gate == "EXACT":
            profile_exact = 1
            profile_mismatch = 0
            future_profile = 0
        elif gate == "MISMATCH":
            profile_exact = 0
            profile_mismatch = 1
            future_profile = 0
        else:
            set_sticky("STORAGE_CORRUPT")
            cleanup(trace_close_iter=False, fence=False)
            return "STORAGE_CORRUPT"
        # iter_open exactly 1
        f = find_fault("iter_open", 1)
        port_trace.append("iter_open:prefix0")
        if f is not None:
            set_sticky("STORAGE_CORRUPT")
            cleanup(trace_close_iter=False, fence=False)
            return "STORAGE_CORRUPT"
        iter_opened = 1
        recon = 1
        state = "OPEN"
        return "OK"

    def classify(key: bytes, value: bytes) -> str:
        # Minimal: family14 handled outside; future root version; else corrupt
        if len(key) >= 8 and key[:7] == ROOT_V1[:7] and key[7] >= 2:
            return "FUTURE"
        if len(key) >= 13 and key[:8] == ROOT_V1:
            # coarse: treat complete-looking health id128 as current if long enough
            if key[8] == 0x05 and key[9] == 0x01 and len(key) == 29:
                return "CURRENT"
        return "MALFORMED"

    def process_ok_row(key: bytes, value: bytes) -> str:
        """Returns empty string on success, or sticky status name on failure."""
        nonlocal ok_rows, family14, current_dom, future_seen
        nonlocal has_previous, previous, seen_mask
        if has_previous and not (key > previous):
            set_sticky("STORAGE_CORRUPT")
            return "STORAGE_CORRUPT"
        cid = catalog_id(key)
        if cid is not None:
            bit = 1 << (cid - 1)
            if recon:
                if seen_mask & bit:
                    set_sticky("STORAGE_CORRUPT")
                    return "STORAGE_CORRUPT"
                if retained.get(cid) != value:
                    set_sticky("STORAGE_CORRUPT")
                    return "STORAGE_CORRUPT"
                seen_mask |= bit
                family14 += 1
            else:
                family14 += 1
        elif f14_noncatalog(key):
            set_sticky("STORAGE_CORRUPT")
            return "STORAGE_CORRUPT"
        elif profile_mismatch or future_profile:
            pass  # skip classify
        else:
            cls = classify(key, value)
            if cls == "CURRENT":
                current_dom += 1
            elif cls == "FUTURE":
                future_seen = 1
            else:
                set_sticky("STORAGE_CORRUPT")
                return "STORAGE_CORRUPT"
        previous = key
        has_previous = True
        ok_rows += 1
        return ""

    def do_advance(budget: int) -> str:
        nonlocal state, row_index, iter_next_call
        if state != "OPEN":
            return "INVALID_STATE"
        if budget == 0:
            return "INVALID_ARGUMENT"
        consumed = 0
        while consumed < budget:
            iter_next_call += 1
            f = find_fault("iter_next", iter_next_call)
            port_trace.append("iter_next")
            shape = f.get("shape", "natural") if f is not None else "natural"

            # Descriptor rewrite is unsafe provider shape → terminal CORRUPT + fence.
            if shape in ("rewrite_data_ptr", "rewrite_capacity"):
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                # Fence is applied at finalize/abort cleanup; reopen recorded then.
                return "STORAGE_CORRUPT"

            if shape == "early_end":
                # Clean terminal NOT_FOUND even if natural rows remain.
                if recon and seen_mask != present_mask:
                    set_sticky("STORAGE_CORRUPT")
                    state = "FAILED"
                    return "STORAGE_CORRUPT"
                state = "EXHAUSTED"
                return "OK"

            if shape == "value_mismatch":
                if row_index >= len(rows):
                    set_sticky("STORAGE_CORRUPT")
                    state = "FAILED"
                    return "STORAGE_CORRUPT"
                key, value = rows[row_index]
                row_index += 1
                if value:
                    value = value[:-1] + bytes([value[-1] ^ 0x5A])
                err = process_ok_row(key, value)
                if err:
                    state = "FAILED"
                    return err
                consumed += 1
                continue

            if shape in ("bts", "not_found_poison", "ok_bad_length"):
                set_sticky("STORAGE_CORRUPT")
                state = "FAILED"
                return "STORAGE_CORRUPT"

            # Natural iter_next: next row or clean end.
            if row_index >= len(rows):
                if recon and seen_mask != present_mask:
                    set_sticky("STORAGE_CORRUPT")
                    state = "FAILED"
                    return "STORAGE_CORRUPT"
                state = "EXHAUSTED"
                return "OK"
            key, value = rows[row_index]
            row_index += 1
            err = process_ok_row(key, value)
            if err:
                state = "FAILED"
                return err
            consumed += 1
        return "OK"

    def finalize_outcome() -> Tuple[str, int]:
        nonlocal state
        if state not in ("EXHAUSTED", "FAILED"):
            return "INVALID_STATE", 0
        prior = state
        cleanup()
        if sticky is not None:
            return sticky, 0
        if profile_mismatch or future_profile:
            return "UNSUPPORTED", 0
        if future_seen:
            return "UNSUPPORTED", 0
        if prior == "EXHAUSTED" and reopen_required == 0:
            return "OK", 1
        return "OK", 0

    last_status = "OK"
    adopted = 0
    for call in calls:
        op = call["op"]
        if op == "begin_profiled":
            last_status = do_begin()
        elif op == "advance":
            last_status = do_advance(int(call.get("row_budget", 1)))
        elif op == "finalize":
            last_status, adopted = finalize_outcome()
        elif op == "abort":
            if state in ("OPEN", "EXHAUSTED", "FAILED"):
                cleanup()
                last_status = sticky or "OK"
                adopted = 0
            else:
                last_status = "INVALID_STATE"
        else:
            raise SystemExit(f"unknown call {op}")

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
        port_trace=port_trace,
    )


def build_vectors() -> List[Dict[str, Any]]:
    binding = default_binding_fields()
    mismatch_binding = dict(binding)
    mismatch_binding = {
        **binding,
        "limits": {**binding["limits"], "max_services": 99},
    }
    full_rows = encode_all_profile_rows(binding)
    vectors: List[Dict[str, Any]] = []

    def add(id_: str, kind: str, candidate: Dict[str, Any], rows: List[Dict[str, str]],
            calls: List[Dict[str, Any]], faults: Optional[List[Dict[str, Any]]] = None,
            expected_override: Optional[Dict[str, Any]] = None) -> None:
        vec = {
            "id": id_,
            "kind": kind,
            "candidate_binding": candidate,
            "rows": rows,
            "faults": faults or [],
            "calls": calls,
        }
        exp = run_case(vec)
        if expected_override:
            exp.update(expected_override)
        vec["expected"] = exp
        vectors.append(vec)

    # exact profile success: 17 catalog rows only
    add(
        "S2_PROFILE_EXACT_SUCCESS",
        "profile_exact",
        binding,
        full_rows,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
    )

    # semantic field mismatch
    add(
        "S2_PROFILE_SEMANTIC_MISMATCH",
        "profile_mismatch",
        mismatch_binding,
        full_rows,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
    )

    # future record version on binding
    future_rows = encode_all_profile_rows(binding, binding_version=2)
    add(
        "S2_PROFILE_FUTURE_VERSION",
        "future_profile",
        binding,
        future_rows,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
    )

    # Single snapshot: binding record version 2 (future) AND corrupt identity CRC.
    # validate_snapshot aggregates corrupt > unsupported; no iter_open.
    corrupt_and_future_rows = encode_all_profile_rows(
        binding, binding_version=2, corrupt_key_id=2
    )
    add(
        "S2_CORRUPT_OVERRIDES_FUTURE",
        "precedence",
        binding,
        corrupt_and_future_rows,
        [{"op": "begin_profiled"}],
    )

    # every missing key position (partial completeness)
    for missing in range(1, 18):
        rows = encode_all_profile_rows(binding, omit_key_ids=[missing])
        add(
            f"S2_MISSING_KEY_{missing:02d}",
            "completeness",
            binding,
            rows,
            [{"op": "begin_profiled"}],
        )

    # empty (0/17)
    add(
        "S2_EMPTY_NAMESPACE",
        "completeness",
        binding,
        [],
        [{"op": "begin_profiled"}],
    )

    # get BTS on key 1
    add(
        "S2_GET_BTS_NO_REREAD",
        "get_fault",
        binding,
        full_rows,
        [{"op": "begin_profiled"}],
        faults=[{"op": "get", "on_call": 1, "status": "BUFFER_TOO_SMALL", "shape": "bts", "value_length": 200}],
    )

    # get NOT_FOUND poison length
    add(
        "S2_GET_NOT_FOUND_POISON",
        "get_fault",
        binding,
        full_rows,
        [{"op": "begin_profiled"}],
        faults=[{"op": "get", "on_call": 3, "status": "NOT_FOUND", "shape": "not_found_poison", "value_length": 1}],
    )

    # get IO error (known non-OK, length 0)
    add(
        "S2_GET_IO_ERROR",
        "get_fault",
        binding,
        full_rows,
        [{"op": "begin_profiled"}],
        faults=[{"op": "get", "on_call": 5, "status": "IO_ERROR", "shape": "io_error"}],
    )

    # get unknown status: CORRUPT, rollback then close original, reopen=1, iter_open=0
    add(
        "S2_GET_UNKNOWN_STATUS_FENCE",
        "get_fault",
        binding,
        full_rows,
        [{"op": "begin_profiled"}],
        faults=[{"op": "get", "on_call": 4, "status": "UNKNOWN", "shape": "unknown"}],
    )

    # get COMMIT_UNKNOWN (known non-OK length 0): STORAGE_COMMIT_UNKNOWN + fence
    add(
        "S2_GET_COMMIT_UNKNOWN_FENCE",
        "get_fault",
        binding,
        full_rows,
        [{"op": "begin_profiled"}],
        faults=[
            {
                "op": "get",
                "on_call": 6,
                "status": "COMMIT_UNKNOWN",
                "shape": "commit_unknown",
            }
        ],
    )

    # mismatch continues; domain malformed skipped
    rows_mm = list(full_rows) + [domain_malformed_row()]
    rows_mm.sort(key=lambda r: from_hex(r["key_hex"]))
    add(
        "S2_MISMATCH_SKIP_DOMAIN_MALFORMED",
        "profile_mismatch",
        mismatch_binding,
        rows_mm,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
    )

    # later f14 noncatalog overrides profile candidate
    rows_ov = list(full_rows) + [noncatalog_f14_row()]
    rows_ov.sort(key=lambda r: from_hex(r["key_hex"]))
    add(
        "S2_F14_NONCATALOG_OVERRIDES_MISMATCH",
        "precedence",
        mismatch_binding,
        rows_ov,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
    )

    # (a) iterator value differs from retained get bytes via iter_next fault shape.
    # Shared rows stay intact; fault corrupts only the iter_next presentation.
    add(
        "S2_ITER_VALUE_MISMATCH",
        "iterator_reconcile",
        binding,
        full_rows,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
        faults=[
            {
                "op": "iter_next",
                "on_call": 1,
                "status": "OK",
                "shape": "value_mismatch",
                "key_length": 0,
                "value_length": 0,
            }
        ],
    )

    # (b) early_end after 16 catalog rows: omits key 17 after all 17 gets succeeded.
    add(
        "S2_ITER_EARLY_END_OMIT_LAST",
        "iterator_reconcile",
        binding,
        full_rows,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
        faults=[
            {
                "op": "iter_next",
                "on_call": 17,
                "status": "NOT_FOUND",
                "shape": "early_end",
                "key_length": 0,
                "value_length": 0,
            }
        ],
    )

    # dsr2_ceiling: success path used by bridge to assert top-level workspace
    # ceiling_bytes==8192 and sizeof(workspace)<=ceiling (not a decorative clone).
    add(
        "S2_DSR2_CEILING_NOTE",
        "dsr2_ceiling",
        binding,
        full_rows,
        [
            {"op": "begin_profiled"},
            {"op": "advance", "row_budget": 64},
            {"op": "finalize"},
        ],
    )

    return vectors


def document() -> Dict[str, Any]:
    return {
        "version": VERSION,
        "format": FORMAT,
        "scope": (
            "D2-S2 family1-4 integrity + exact profile gate + one-iterator "
            "reconciliation ownership only. Does not claim DSR1_SCAN complete, "
            "DSR2_ESP_BOUND complete, D2 complete, Stage 5, or public Runtime."
        ),
        "workspace": {
            "key_capacity": KEY_CAP,
            "value_capacity": VALUE_CAP,
            "previous_key_capacity": PREV_CAP,
            "ceiling_bytes": CEILING,
            "encoded_values_bytes": 1143,
            "encoded_packing": "binding183+identity84+counter32x4+capacity68x11",
        },
        "vectors": build_vectors(),
    }


def generate(path: Path) -> None:
    doc = document()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path} ({len(doc['vectors'])} vectors)")


def check(path: Path) -> int:
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    expected = document()
    if on_disk.get("format") != FORMAT:
        print("format mismatch", file=sys.stderr)
        return 1
    if on_disk.get("version") != VERSION:
        print("version mismatch", file=sys.stderr)
        return 1
    if len(on_disk.get("vectors", [])) != len(expected["vectors"]):
        print("vector count mismatch", file=sys.stderr)
        return 1

    kinds_seen: Set[str] = set()
    for got, want in zip(on_disk["vectors"], expected["vectors"]):
        if got.get("id") != want["id"]:
            print(f"id order mismatch: {got.get('id')} != {want['id']}", file=sys.stderr)
            return 1
        kind = got.get("kind")
        if not isinstance(kind, str) or kind not in ALLOWED_KINDS:
            print(
                f"{got.get('id')}: kind {kind!r} not in closed set "
                f"{sorted(ALLOWED_KINDS)}",
                file=sys.stderr,
            )
            return 1
        kinds_seen.add(kind)
        if not isinstance(got.get("faults"), list):
            print(f"{got['id']}: faults must be array", file=sys.stderr)
            return 1
        try:
            assert_no_unknown_keys(got, VECTOR_KEYS, got.get("id", "?"))
            for fi, f in enumerate(got.get("faults", [])):
                if not isinstance(f, dict):
                    raise SystemExit(f"{got['id']}: fault[{fi}] must be object")
                assert_no_unknown_keys(f, FAULT_KEYS, f"{got['id']}.faults[{fi}]")
                if "_used" in f:
                    raise SystemExit(
                        f"{got['id']}: fault contains forbidden execution state _used"
                    )
            for ci, c in enumerate(got.get("calls", [])):
                if not isinstance(c, dict):
                    raise SystemExit(f"{got['id']}: call[{ci}] must be object")
                assert_no_unknown_keys(c, CALL_KEYS, f"{got['id']}.calls[{ci}]")
            if not isinstance(got.get("expected"), dict):
                raise SystemExit(f"{got['id']}: expected must be object")
            assert_no_unknown_keys(
                got["expected"], EXPECTED_KEYS, f"{got['id']}.expected"
            )
        except SystemExit as exc:
            print(str(exc), file=sys.stderr)
            return 1
        # recompute expected from got inputs (must not mutate got)
        trial = {
            "id": got["id"],
            "kind": got["kind"],
            "candidate_binding": got["candidate_binding"],
            "rows": got["rows"],
            "faults": copy.deepcopy(got.get("faults", [])),
            "calls": got["calls"],
        }
        faults_before = json.dumps(got.get("faults", []), sort_keys=True)
        recomputed = run_case(trial)
        faults_after = json.dumps(got.get("faults", []), sort_keys=True)
        if faults_before != faults_after:
            print(f"{got['id']}: run_case mutated input faults", file=sys.stderr)
            return 1
        if recomputed != got.get("expected"):
            print(f"oracle mismatch for {got['id']}", file=sys.stderr)
            print(" got:", json.dumps(got.get("expected"), sort_keys=True), file=sys.stderr)
            print(" want:", json.dumps(recomputed, sort_keys=True), file=sys.stderr)
            return 1
        if recomputed != want["expected"]:
            print(f"generator drift for {got['id']}", file=sys.stderr)
            return 1

    missing_kinds = REQUIRED_KINDS - kinds_seen
    if missing_kinds:
        print(
            f"missing required kinds: {sorted(missing_kinds)}",
            file=sys.stderr,
        )
        return 1

    ws = on_disk.get("workspace")
    if not isinstance(ws, dict) or ws.get("ceiling_bytes") != CEILING:
        print("workspace.ceiling_bytes must be 8192", file=sys.stderr)
        return 1

    if json.dumps(on_disk, sort_keys=True) != json.dumps(expected, sort_keys=True):
        print("document not deterministically equal to generator output", file=sys.stderr)
        return 1
    print(f"ok: {path} ({len(on_disk['vectors'])} vectors)")
    return 0


def emit_c_fixture(json_path: Path, header_path: Path) -> None:
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    vectors = doc["vectors"]
    lines: List[str] = []
    lines.append("/* GENERATED by tools/domain_scan_profile_vector_gen.py — do not edit. */")
    lines.append("#ifndef NINLIL_DOMAIN_SCAN_PROFILE_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_DOMAIN_SCAN_PROFILE_VECTOR_FIXTURE_H")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(f"#define NINLIL_DSP_VECTOR_COUNT ((size_t){len(vectors)}u)")
    lines.append("#define NINLIL_DSP_MAX_ROWS ((size_t)32u)")
    lines.append("#define NINLIL_DSP_MAX_CALLS ((size_t)8u)")
    lines.append("#define NINLIL_DSP_MAX_FAULTS ((size_t)4u)")
    lines.append("#define NINLIL_DSP_MAX_KEY ((size_t)16u)")
    lines.append("#define NINLIL_DSP_MAX_VALUE ((size_t)183u)")
    lines.append("#define NINLIL_DSP_MAX_TRACE ((size_t)128u)")
    ceiling = int(doc.get("workspace", {}).get("ceiling_bytes", CEILING))
    lines.append(f"#define NINLIL_DSP_WORKSPACE_CEILING_BYTES ((uint32_t){ceiling}u)")
    lines.append("")
    lines.append("typedef struct ninlil_dsp_row {")
    lines.append("    uint8_t key[NINLIL_DSP_MAX_KEY];")
    lines.append("    uint32_t key_length;")
    lines.append("    uint8_t value[NINLIL_DSP_MAX_VALUE];")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dsp_row_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsp_fault {")
    lines.append("    const char *op;")
    lines.append("    uint32_t on_call;")
    lines.append("    const char *shape;")
    lines.append("    uint32_t key_length;")
    lines.append("    uint32_t value_length;")
    lines.append("} ninlil_dsp_fault_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsp_call {")
    lines.append("    const char *op;")
    lines.append("    uint32_t row_budget;")
    lines.append("} ninlil_dsp_call_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsp_binding {")
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
    lines.append("} ninlil_dsp_binding_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsp_expected {")
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
    lines.append("} ninlil_dsp_expected_t;")
    lines.append("")
    lines.append("typedef struct ninlil_dsp_vector {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    ninlil_dsp_binding_t candidate;")
    lines.append("    const ninlil_dsp_row_t *rows;")
    lines.append("    size_t row_count;")
    lines.append("    const ninlil_dsp_fault_t *faults;")
    lines.append("    size_t fault_count;")
    lines.append("    const ninlil_dsp_call_t *calls;")
    lines.append("    size_t call_count;")
    lines.append("    ninlil_dsp_expected_t expected;")
    lines.append("} ninlil_dsp_vector_t;")
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

    for vi, vec in enumerate(vectors):
        lines.append(f"static const ninlil_dsp_row_t ninlil_dsp_rows_{vi}[] = {{")
        for r in vec.get("rows", []):
            kb = from_hex(r.get("key_hex", ""))
            vb = from_hex(r.get("value_hex", ""))
            if len(kb) > 16 or len(vb) > 183:
                raise SystemExit(f"row too large for fixture: {vec['id']}")
            karr = ", ".join(f"0x{b:02x}u" for b in kb) if kb else "0"
            varr = ", ".join(f"0x{b:02x}u" for b in vb) if vb else "0"
            lines.append(
                f"    {{{{ {karr} }}, {len(kb)}u, {{ {varr} }}, {len(vb)}u }},"
            )
        if not vec.get("rows"):
            lines.append("    { { 0u }, 0u, { 0u }, 0u },")
        lines.append("};")
        lines.append(f"static const ninlil_dsp_fault_t ninlil_dsp_faults_{vi}[] = {{")
        for f in vec.get("faults", []):
            lines.append(
                f'    {{ "{f["op"]}", {int(f["on_call"])}u, "{f.get("shape", "natural")}", '
                f'{int(f.get("key_length", 0))}u, {int(f.get("value_length", 0))}u }},'
            )
        if not vec.get("faults"):
            lines.append('    { NULL, 0u, NULL, 0u, 0u },')
        lines.append("};")
        lines.append(f"static const ninlil_dsp_call_t ninlil_dsp_calls_{vi}[] = {{")
        for c in vec["calls"]:
            lines.append(f'    {{ "{c["op"]}", {int(c.get("row_budget", 0))}u }},')
        lines.append("};")
        exp = vec["expected"]
        lines.append(f"static const char *const ninlil_dsp_trace_{vi}[] = {{")
        for t in exp.get("port_trace", []):
            lines.append(f'    "{t}",')
        if not exp.get("port_trace"):
            lines.append("    NULL")
        lines.append("};")
        lines.append("")

    lines.append(
        "static const ninlil_dsp_vector_t ninlil_dsp_vectors[NINLIL_DSP_VECTOR_COUNT] = {"
    )
    for vi, vec in enumerate(vectors):
        exp = vec["expected"]
        lines.append("    {")
        lines.append(f'        "{vec["id"]}",')
        lines.append(f'        "{vec["kind"]}",')
        lines.append(f"        {binding_literal(vec['candidate_binding'])},")
        lines.append(f"        ninlil_dsp_rows_{vi}, {len(vec.get('rows', []))}u,")
        lines.append(f"        ninlil_dsp_faults_{vi}, {len(vec.get('faults', []))}u,")
        lines.append(f"        ninlil_dsp_calls_{vi}, {len(vec['calls'])}u,")
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
        lines.append(
            f"            ninlil_dsp_trace_{vi}, {len(exp.get('port_trace', []))}u"
        )
        lines.append("        }")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_DOMAIN_SCAN_PROFILE_VECTOR_FIXTURE_H */")
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
