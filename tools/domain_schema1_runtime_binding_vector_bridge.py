#!/usr/bin/env python3
"""Independent Domain schema1 bridge (Foundation Controller fixture).

Does not import the generator or production C. Rebuilds format-2 bootstrap and
pins every compatibility vector by ID (bytes, status, transcript). Self-test
mutations and full-row donor swaps under same IDs must reject.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "spec/vectors/domain-store-schema1-runtime-binding-v1.json"
ROOT_KEY = bytes.fromhex("4e494e4c494c0001")
FORMAT = "ninlil-domain-store-schema1-runtime-binding-v1"
EXPECTED_STATUS = "PROPOSED_DOCS_ONLY"


def u8(value: int) -> bytes:
    return bytes((value & 0xFF,))


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in data:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def nlr1(record_type: int, payload: bytes) -> bytes:
    body = b"NLR1" + u16(record_type) + u16(1) + u32(len(payload)) + payload
    return body + u32(crc32c(body))


def raw16(value: bytes) -> bytes:
    return u16(len(value)) + value


def encode_binding_payload() -> bytes:
    """Canonical Controller + TEST Foundation SMALL-1 binding payload."""

    profile = b"NINLIL-FOUNDATION-SMALL-1"
    payload = (
        u32(2)
        + raw16(profile)
        + b"NINLIL-DOMAIN-S1"
        + u32(1)
        + u32(2)
        + u64(1)
        + u32(1)  # schema
        + u32(1)  # CONTROLLER
        + u32(1)  # TEST
        + bytes.fromhex("44" * 16)
        + u32(16)
        + u32(32)
        + u32(1)  # targets exact 1
        + u32(256)
        + u64(8192)
        + u32(8)
        + u32(1)  # cancel exact 1
        + u32(3)
        + u32(64)
        + u32(32)
        + u32(0)  # event spool count Controller
        + u64(0)  # event spool bytes
        + u32(32)
        + u32(64)
        + u32(8)
        + u32(8)
        + u32(16)
        + u32(8)
        + u32(16)
        + u64(2000)  # terminal
        + u64(1000)  # result <= terminal
        + u64(3000)
    )
    if len(payload) != 199:
        raise AssertionError(len(payload))
    return payload


def capacity_limits() -> list[int]:
    transaction = 32 + 64
    target = transaction * 1
    return [
        16,
        transaction,
        target,
        8192,
        32,
        0,
        0,
        32 + 64,
        target * (3 + 1),
        8,
        16,
    ]


def rebuild_records() -> list[tuple[bytes, bytes]]:
    binding = nlr1(1, encode_binding_payload())
    identity = nlr1(
        2,
        u32(7)
        + bytes.fromhex("55" * 16)
        + bytes.fromhex("66" * 16)
        + bytes.fromhex("77" * 16)
        + u64(1)
        + u64(1),
    )
    rows = [(ROOT_KEY + b"\x01", binding), (ROOT_KEY + b"\x02", identity)]
    for kind in range(1, 5):
        rows.append(
            (ROOT_KEY + b"\x03" + u8(kind), nlr1(3, u32(kind) + u64(0) + u32(0)))
        )
    for kind, limit in enumerate(capacity_limits(), 1):
        payload = (
            u32(kind)
            + u64(limit)
            + u64(0)
            + u64(0)
            + u64(0)
            + u64(1)
            + u32(0)
            + u32(0)
        )
        rows.append((ROOT_KEY + b"\x04" + u8(kind), nlr1(4, payload)))
    if len(rows) != 17 or [k for k, _ in rows] != sorted(k for k, _ in rows):
        raise AssertionError("rows")
    encoded = sum(len(k) + len(v) for k, v in rows)
    logical = sum(16 + len(k) + len(v) for k, v in rows)
    if encoded != 1343 or logical != 1615:
        raise AssertionError((encoded, logical))
    return rows


def fail(message: str) -> None:
    raise RuntimeError(message)


def independent_snapshot_sha256(rows: list[tuple[bytes, bytes]]) -> str:
    """Literal preimage rule (not delegated to generator/vector authority)."""

    ordered = sorted(rows, key=lambda item: item[0])
    transcript = b"".join(
        u16(len(key)) + key + u32(len(value)) + value for key, value in ordered
    )
    return hashlib.sha256(
        b"NINLIL-DOMAIN-INIT-SNAPSHOT-V1" + u32(len(ordered)) + transcript
    ).hexdigest()


# Hard-coded normative T1a classification transcript (all cases).
# Full Normative RO scan fields — not taught by generator/vector authority.
T1A_TRANSCRIPT_KAT: dict[str, int | str] = {
    "transaction_mode": "READ_ONLY",
    "storage_read_only_begin": 1,
    "iterator_open": 1,
    "iterator_exhausted": 1,
    "iterator_close": 1,
    "rollback": 1,
    "storage_read_write_begin": 0,
    "storage_put": 0,
    "storage_erase": 0,
    "storage_commit": 0,
    "bearer_open": 0,
    "callback": 0,
    "public_handle": 0,
    "publish": 0,
}

T1A_TRANSCRIPT_REQUIRED_KEYS = frozenset(T1A_TRANSCRIPT_KAT.keys())


def canonical_without_integrity(document: dict[str, Any]) -> bytes:
    body = {key: value for key, value in document.items() if key != "integrity"}
    return json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def refresh_integrity(document: dict[str, Any]) -> None:
    document["integrity"] = {
        "scope": "canonical JSON of this document with integrity omitted",
        "sha256": hashlib.sha256(
            canonical_without_integrity(document)
        ).hexdigest(),
    }


def validate(document: dict[str, Any]) -> None:
    if document.get("format") != FORMAT:
        fail("format")
    if document.get("status") != EXPECTED_STATUS:
        fail(f"status {document.get('status')!r}")
    expected_digest = hashlib.sha256(
        canonical_without_integrity(document)
    ).hexdigest()
    if document.get("integrity", {}).get("sha256") != expected_digest:
        fail("document integrity digest mismatch")

    arithmetic = document["bootstrap_format_2_domain_arithmetic"]
    fixture = arithmetic["fixture"]
    limits = fixture["limits"]
    if (
        fixture["role"] != 1
        or fixture["environment"] != 1
        or limits["max_targets_per_transaction"] != 1
        or limits["max_cancel_attempts_per_transaction"] != 1
        or limits["max_event_spool_count"] != 0
        or limits["max_event_spool_bytes"] != 0
        or fixture["result_cache_retention_ms"] > fixture["terminal_retention_ms"]
    ):
        fail("fixture not Foundation Controller")

    rebuilt = rebuild_records()
    expected_rows = arithmetic["records_unsigned_key_order"]
    if len(expected_rows) != 17:
        fail("row count")
    for index, ((key, value), row) in enumerate(zip(rebuilt, expected_rows)):
        if key.hex() != row["key_hex"] or value.hex() != row["value_hex"]:
            fail(f"row bytes {index}")
        if row["key_sha256"] != hashlib.sha256(key).hexdigest():
            fail(f"key sha {index}")
        if row["value_sha256"] != hashlib.sha256(value).hexdigest():
            fail(f"value sha {index}")

    binding_meta = document["binding_format_2"]
    if (
        binding_meta["bootstrap_encoded_key_value_bytes"] != 1343
        or binding_meta["payload_bytes"] != 199
        or binding_meta["value_bytes"] != 215
    ):
        fail("binding meta sizes")

    # Exact ordered ID -> bytes/hash/status/transcript binding.
    positive_value = rebuilt[0][1]
    positive_hex = positive_value.hex()
    positive_sha = hashlib.sha256(positive_value).hexdigest()
    # NLR1 payload starts after 12-byte header (magic/type/ver/len).
    positive_payload = bytearray(positive_value[12:-4])

    def mutated_value(offset: int, replacement: bytes) -> bytes:
        payload = bytearray(positive_payload)
        payload[offset : offset + len(replacement)] = replacement
        return nlr1(1, bytes(payload))

    # Independent exact map (same single-cause mutations as the vector oracle).
    independent_map: dict[str, dict[str, Any]] = {
        "BINDING_FORMAT2_POSITIVE_EXACT": {
            "status": "NINLIL_OK",
            "value": positive_value,
        },
        "BINDING_FORMAT2_UNKNOWN_FORMAT": {
            "status": "NINLIL_E_UNSUPPORTED",
            "value": mutated_value(0, u32(3)),
        },
        "BINDING_FORMAT2_UNKNOWN_PROFILE_ID": {
            "status": "NINLIL_E_UNSUPPORTED",
            "value": mutated_value(31, b"NINLIL-DOMAIN-S2"),
        },
        "BINDING_FORMAT2_PROFILE_REVISION_ROLLBACK": {
            "status": "NINLIL_E_UNSUPPORTED",
            "value": mutated_value(47, u32(0)),
        },
        "BINDING_FORMAT2_WRITER_GENERATION_INSUFFICIENT": {
            "status": "NINLIL_E_UNSUPPORTED",
            "value": mutated_value(51, u32(3)),
        },
        "BINDING_FORMAT2_ROLLBACK_EPOCH_REGRESSION": {
            "status": "NINLIL_E_UNSUPPORTED",
            "value": mutated_value(55, u64(0)),
        },
        "BINDING_FORMAT2_SCHEMA_MISMATCH": {
            "status": "NINLIL_E_UNSUPPORTED",
            "value": mutated_value(63, u32(2)),
        },
        "BINDING_FORMAT2_LAST_LAB_BINARY_DOWNGRADE_REJECT": {
            "status": "NINLIL_E_UNSUPPORTED",
            "value": positive_value,
        },
    }
    by_id = {
        item["id"]: item
        for item in binding_meta["compatibility_vectors"]["vectors"]
    }
    required_ids = list(independent_map.keys())
    if [item["id"] for item in binding_meta["compatibility_vectors"]["vectors"]] != required_ids:
        fail("compat ordered id list")
    if set(by_id) != set(required_ids):
        fail("compat id set")
    for vector_id, expected in independent_map.items():
        item = by_id[vector_id]
        if "computed_status" not in item:
            fail(vector_id + " missing computed_status")
        if item["computed_status"] != item["expected_status"]:
            fail(vector_id + " computed!=expected")
        if item["expected_status"] != expected["status"]:
            fail(vector_id + " status")
        if item["computed_status"] != expected["status"]:
            fail(vector_id + " computed status")
        exp_hex = expected["value"].hex()
        exp_sha = hashlib.sha256(expected["value"]).hexdigest()
        if item["value_hex"] != exp_hex or item["value_sha256"] != exp_sha:
            fail(vector_id + " exact bytes/hash")
        if item["value_sha256"] != hashlib.sha256(
            bytes.fromhex(item["value_hex"])
        ).hexdigest():
            fail(vector_id + " hash mismatch")
        tr = item["transcript"]
        if (
            tr["storage_read_only_begin"] != 1
            or tr["storage_read_write_begin"] != 0
            or tr["storage_put"] != 0
            or tr["storage_erase"] != 0
            or tr["storage_commit"] != 0
            or tr["publish"] != 0
            or tr["public_handle"] != 0
            or tr["callback"] != 0
            or tr["bearer_open"] != 0
        ):
            fail(vector_id + " transcript")

    t0 = next(
        t for t in document["initialization_transitions"] if t["node"] == "T0"
    )
    if (
        t0["mutation_count"] != 0
        or t0["read_only_upgrade_forbidden"] is not True
        or "READ_WRITE" not in t0["authority"]
    ):
        fail("T0 authority pin")

    class_map = {
        "T1A_COMMIT_UNKNOWN_ALL_OLD_0_OF_17": ("OLD", 0),
        "T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17": ("NEW", 17),
        "T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17": ("NINLIL_E_STORAGE_CORRUPT", 1),
        "T1A_COMMIT_UNKNOWN_PARTIAL_16_OF_17": ("NINLIL_E_STORAGE_CORRUPT", 16),
        "T1A_COMMIT_UNKNOWN_EXTRA_ROW": ("NINLIL_E_STORAGE_CORRUPT", 18),
        "T1A_COMMIT_UNKNOWN_FORMAT_MISMATCH": ("NINLIL_E_STORAGE_CORRUPT", 17),
    }
    for case in document["initialization_transition_byte_kats"]["T1a"]:
        expected_class, count = class_map[case["id"]]
        if case["expected_classification"] != expected_class:
            fail(case["id"] + " class")
        if case["computed_classification"] != expected_class:
            fail(case["id"] + " computed class")
        if case["snapshot_record_count"] != count:
            fail(case["id"] + " count")
        tr = case["transcript"]
        if set(tr.keys()) != T1A_TRANSCRIPT_REQUIRED_KEYS:
            fail(case["id"] + " transcript key set")
        for field, expected in T1A_TRANSCRIPT_KAT.items():
            if tr.get(field) != expected:
                fail(f"{case['id']} transcript.{field}")
        # Independent digest recompute from case snapshot rows (or empty).
        # Unconditional for all 6 T1a IDs (including EXTRA_ROW / FORMAT_MISMATCH):
        # materialised row count must equal declared snapshot_record_count.
        case_rows: list[tuple[bytes, bytes]] = [
            (bytes.fromhex(row["key_hex"]), bytes.fromhex(row["value_hex"]))
            for row in case.get("snapshot_records_unsigned_key_order", [])
        ]
        if len(case_rows) != case["snapshot_record_count"]:
            fail(
                case["id"]
                + f" materialised={len(case_rows)} != declared"
                f"={case['snapshot_record_count']}"
            )
        if len(case_rows) != count:
            fail(case["id"] + " materialised != class_map count")
        recomputed = independent_snapshot_sha256(case_rows)
        if case["snapshot_sha256"] != recomputed:
            fail(case["id"] + " snapshot_sha256 independent mismatch")
        if case["id"] == "T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17":
            if len(case_rows) != 17:
                fail("new incomplete rows")
            for index, row in enumerate(case_rows):
                if row != rebuilt[index]:
                    fail(f"new row {index}")
            if recomputed != independent_snapshot_sha256(rebuilt):
                fail("new digest vs rebuilt")


def self_test(document: dict[str, Any]) -> None:
    validate(document)
    rebuilt = rebuild_records()
    positive_hex = rebuilt[0][1].hex()
    t1a = document["initialization_transition_byte_kats"]["T1a"]
    t1a_ids = [case["id"] for case in t1a]

    def mut_status(d: dict[str, Any]) -> None:
        d["status"] = "SPEC_ACCEPTED"

    def mut_class(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][0][
            "expected_classification"
        ] = "NEW"

    def mut_transcript(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][0]["transcript"][
            "publish"
        ] = 1

    def mut_transcript_ro(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][0]["transcript"][
            "storage_read_only_begin"
        ] = 0

    def mut_transcript_mode(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][0]["transcript"][
            "transaction_mode"
        ] = "READ_WRITE"

    def mut_transcript_iterator(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][1]["transcript"][
            "iterator_close"
        ] = 0

    def mut_transcript_rollback(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][2]["transcript"][
            "rollback"
        ] = 0

    def mut_transcript_commit(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][3]["transcript"][
            "storage_commit"
        ] = 1

    def mut_transcript_rw_begin(d: dict[str, Any]) -> None:
        d["initialization_transition_byte_kats"]["T1a"][4]["transcript"][
            "storage_read_write_begin"
        ] = 1

    def mut_digest_coherent(d: dict[str, Any]) -> None:
        case = next(
            c
            for c in d["initialization_transition_byte_kats"]["T1a"]
            if c["id"] == "T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17"
        )
        # Coherent 64-hex change without touching rows + integrity refresh.
        # Must still reject via independent digest recompute (not integrity).
        case["snapshot_sha256"] = "a" * 64

    def mut_digest_coherent_partial(d: dict[str, Any]) -> None:
        case = next(
            c
            for c in d["initialization_transition_byte_kats"]["T1a"]
            if c["id"] == "T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17"
        )
        case["snapshot_sha256"] = "b" * 64

    def mut_extra_row_undercount_repaired_digest(d: dict[str, Any]) -> None:
        """P1 counterexample: EXTRA declared=18, materialise 17, recompute SHA.

        Must reject: len(rows) must equal snapshot_record_count unconditionally.
        """

        case = next(
            c
            for c in d["initialization_transition_byte_kats"]["T1a"]
            if c["id"] == "T1A_COMMIT_UNKNOWN_EXTRA_ROW"
        )
        if case["snapshot_record_count"] != 18:
            fail("extra fixture count")
        case["snapshot_records_unsigned_key_order"] = case[
            "snapshot_records_unsigned_key_order"
        ][:17]
        # Keep declared count=18; only materialised shrinks + digest repaired.
        rows = [
            (bytes.fromhex(row["key_hex"]), bytes.fromhex(row["value_hex"]))
            for row in case["snapshot_records_unsigned_key_order"]
        ]
        case["snapshot_sha256"] = independent_snapshot_sha256(rows)

    def mut_format_mismatch_undercount_repaired_digest(
        d: dict[str, Any],
    ) -> None:
        """P1 counterexample: FORMAT declared=17, materialise 16, recompute SHA."""

        case = next(
            c
            for c in d["initialization_transition_byte_kats"]["T1a"]
            if c["id"] == "T1A_COMMIT_UNKNOWN_FORMAT_MISMATCH"
        )
        if case["snapshot_record_count"] != 17:
            fail("format fixture count")
        case["snapshot_records_unsigned_key_order"] = case[
            "snapshot_records_unsigned_key_order"
        ][:16]
        rows = [
            (bytes.fromhex(row["key_hex"]), bytes.fromhex(row["value_hex"]))
            for row in case["snapshot_records_unsigned_key_order"]
        ]
        case["snapshot_sha256"] = independent_snapshot_sha256(rows)

    def mut_digest(d: dict[str, Any]) -> None:
        d["bootstrap_format_2_domain_arithmetic"][
            "records_unsigned_key_order"
        ][0]["value_sha256"] = "00" * 32

    def mut_compat_status(d: dict[str, Any]) -> None:
        d["binding_format_2"]["compatibility_vectors"]["vectors"][1][
            "expected_status"
        ] = "NINLIL_OK"

    def mut_compat_bytes_to_positive(d: dict[str, Any]) -> None:
        for item in d["binding_format_2"]["compatibility_vectors"]["vectors"]:
            if item["id"] == "BINDING_FORMAT2_UNKNOWN_FORMAT":
                item["value_hex"] = positive_hex
                item["value_sha256"] = hashlib.sha256(
                    bytes.fromhex(positive_hex)
                ).hexdigest()
                break

    def mut_delete_computed_status(d: dict[str, Any]) -> None:
        for item in d["binding_format_2"]["compatibility_vectors"]["vectors"]:
            if item["id"] == "BINDING_FORMAT2_UNKNOWN_FORMAT":
                del item["computed_status"]
                break

    def mut_swap_unknown_format_with_profile(d: dict[str, Any]) -> None:
        by_id = {
            item["id"]: item
            for item in d["binding_format_2"]["compatibility_vectors"]["vectors"]
        }
        left = by_id["BINDING_FORMAT2_UNKNOWN_FORMAT"]
        right = by_id["BINDING_FORMAT2_UNKNOWN_PROFILE_ID"]
        left["value_hex"], right["value_hex"] = (
            right["value_hex"],
            left["value_hex"],
        )
        left["value_sha256"], right["value_sha256"] = (
            right["value_sha256"],
            left["value_sha256"],
        )

    def mut_partial_snapshot(d: dict[str, Any]) -> None:
        case = next(
            c
            for c in d["initialization_transition_byte_kats"]["T1a"]
            if c["id"] == "T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17"
        )
        case["snapshot_records_unsigned_key_order"] = case[
            "snapshot_records_unsigned_key_order"
        ][:8]
        case["snapshot_record_count"] = 8

    def mut_t0(d: dict[str, Any]) -> None:
        for t in d["initialization_transitions"]:
            if t["node"] == "T0":
                t["read_only_upgrade_forbidden"] = False
                t["mutation_count"] = 1

    def mut_computed(d: dict[str, Any]) -> None:
        d["binding_format_2"]["compatibility_vectors"]["vectors"][0][
            "computed_status"
        ] = "NINLIL_E_UNSUPPORTED"

    mutations: list[tuple[str, Any]] = [
        ("status", mut_status),
        ("class", mut_class),
        ("transcript", mut_transcript),
        ("transcript_ro", mut_transcript_ro),
        ("transcript_mode", mut_transcript_mode),
        ("transcript_iterator", mut_transcript_iterator),
        ("transcript_rollback", mut_transcript_rollback),
        ("transcript_commit", mut_transcript_commit),
        ("transcript_rw_begin", mut_transcript_rw_begin),
        ("digest", mut_digest),
        ("digest_coherent", mut_digest_coherent),
        ("digest_coherent_partial", mut_digest_coherent_partial),
        (
            "extra_row_undercount_repaired_digest",
            mut_extra_row_undercount_repaired_digest,
        ),
        (
            "format_mismatch_undercount_repaired_digest",
            mut_format_mismatch_undercount_repaired_digest,
        ),
        ("compat_status", mut_compat_status),
        ("compat_bytes_donor", mut_compat_bytes_to_positive),
        ("delete_computed_status", mut_delete_computed_status),
        ("swap_unknown_format_profile", mut_swap_unknown_format_with_profile),
        ("partial_snapshot", mut_partial_snapshot),
        ("t0", mut_t0),
        ("computed", mut_computed),
    ]
    # Dirty RO-normative fields on every T1a case (must reject).
    dirty_values: dict[str, int | str] = {
        "publish": 1,
        "storage_read_only_begin": 0,
        "rollback": 0,
        "iterator_open": 0,
        "iterator_close": 0,
        "iterator_exhausted": 0,
        "storage_commit": 1,
        "storage_read_write_begin": 1,
        "storage_put": 1,
        "transaction_mode": "READ_WRITE",
    }
    for dst_i, dst_id in enumerate(t1a_ids):
        for field, bad in dirty_values.items():

            def make_transcript_dirty(
                di: int = dst_i, f: str = field, v: int | str = bad
            ) -> Any:
                def _dirty(d: dict[str, Any]) -> None:
                    d["initialization_transition_byte_kats"]["T1a"][di][
                        "transcript"
                    ][f] = v

                return _dirty

            mutations.append(
                (f"transcript_dirty_{field}_on_{dst_id}", make_transcript_dirty())
            )
    # Digest donor swap: OLD digest into NEW case (rows still NEW).
    def mut_digest_donor_old_into_new(d: dict[str, Any]) -> None:
        by_id = {
            c["id"]: c
            for c in d["initialization_transition_byte_kats"]["T1a"]
        }
        by_id["T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17"]["snapshot_sha256"] = by_id[
            "T1A_COMMIT_UNKNOWN_ALL_OLD_0_OF_17"
        ]["snapshot_sha256"]

    mutations.append(("digest_donor_old_into_new", mut_digest_donor_old_into_new))

    def mut_digest_donor_new_into_partial(d: dict[str, Any]) -> None:
        by_id = {
            c["id"]: c
            for c in d["initialization_transition_byte_kats"]["T1a"]
        }
        by_id["T1A_COMMIT_UNKNOWN_PARTIAL_1_OF_17"]["snapshot_sha256"] = by_id[
            "T1A_COMMIT_UNKNOWN_ALL_NEW_17_OF_17"
        ]["snapshot_sha256"]

    mutations.append(
        ("digest_donor_new_into_partial", mut_digest_donor_new_into_partial)
    )

    # Exhaustive ordered negative donor swaps under fixed IDs.
    negative_ids = [
        "BINDING_FORMAT2_UNKNOWN_FORMAT",
        "BINDING_FORMAT2_UNKNOWN_PROFILE_ID",
        "BINDING_FORMAT2_PROFILE_REVISION_ROLLBACK",
        "BINDING_FORMAT2_WRITER_GENERATION_INSUFFICIENT",
        "BINDING_FORMAT2_ROLLBACK_EPOCH_REGRESSION",
        "BINDING_FORMAT2_SCHEMA_MISMATCH",
    ]
    for donor in negative_ids:
        for victim in negative_ids:
            if donor == victim:
                continue

            def make_swap(
                d_id: str = donor, v_id: str = victim
            ) -> Any:
                def _swap(d: dict[str, Any]) -> None:
                    by_id = {
                        item["id"]: item
                        for item in d["binding_format_2"][
                            "compatibility_vectors"
                        ]["vectors"]
                    }
                    by_id[v_id]["value_hex"] = by_id[d_id]["value_hex"]
                    by_id[v_id]["value_sha256"] = by_id[d_id]["value_sha256"]

                return _swap

            mutations.append((f"donor_{donor}_into_{victim}", make_swap()))
    observed = 0
    for name, mutate in mutations:
        changed = copy.deepcopy(document)
        mutate(changed)
        refresh_integrity(changed)  # coherent integrity refresh
        try:
            validate(changed)
        except RuntimeError:
            observed += 1
        else:
            fail(f"mutation survived: {name}")
    if observed != len(mutations):
        fail("mutation count")
    # Source restoration: original still validates.
    validate(document)
    print(
        f"domain_schema1_runtime_binding vector bridge self-test OK "
        f"mutations={observed}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        document = json.loads(VECTOR.read_text(encoding="utf-8"))
        if args.self_test:
            self_test(document)
        else:
            validate(document)
            print(
                "domain_schema1_runtime_binding vector bridge OK "
                f"status={document['status']} rows=17 "
                f"vector_sha256={hashlib.sha256(VECTOR.read_bytes()).hexdigest()[:16]}"
            )
    except (
        OSError,
        json.JSONDecodeError,
        RuntimeError,
        KeyError,
        AssertionError,
        ValueError,
    ) as error:
        print(
            f"domain_schema1_runtime_binding vector bridge FAIL: {error}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
