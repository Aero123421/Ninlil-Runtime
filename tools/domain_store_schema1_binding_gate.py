#!/usr/bin/env python3
"""Independent ADR-0022 closed-status and startup lifecycle gate.

This checker deliberately does not import the generator or production code.
It reclassifies raw bytes and recomputes every startup transcript from the
closed stage/fault table.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VECTOR = (
    ROOT / "spec/vectors/domain-store-schema1-runtime-binding-v1.json"
)

STAGES = [
    "T0_same_rw_zero_row_scan",
    "T1a_format2_bootstrap_full",
    "T1b_uninitialized_metadata_full",
    "T2_d3_s4_s12_cross_row_validation",
    "T3_d4_recovery_full_and_rescan",
    "T4_identity_recovery",
    "T5_trusted_clock_sample",
    "T5_clock_full_commit_and_rescan",
    "T6_durable_health_reconstruction",
    "bearer_open",
    "metrics_entropy",
    "T7_publication_gate",
    "public_runtime_publish",
]

STARTUP_CASES = {
    "STARTUP_T0_ZERO_ROW_SCAN_FAULT": (0, "NINLIL_E_STORAGE"),
    "STARTUP_T1A_BOOTSTRAP_COMMIT_UNKNOWN": (
        1,
        "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
    ),
    "STARTUP_T1B_METADATA_COMMIT_UNKNOWN": (
        2,
        "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
    ),
    "STARTUP_T2_CROSS_ROW_VALIDATION_FAULT": (
        3,
        "NINLIL_E_STORAGE_CORRUPT",
    ),
    "STARTUP_T3_D4_RECOVERY_COMMIT_UNKNOWN": (
        4,
        "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
    ),
    "STARTUP_T4_IDENTITY_CONFLICT": (5, "NINLIL_E_CONFLICT"),
    "STARTUP_T5_TRUSTED_CLOCK_FAULT": (
        6,
        "NINLIL_E_CLOCK_UNCERTAIN",
    ),
    "STARTUP_T5_COMMIT_UNKNOWN": (
        7,
        "NINLIL_E_STORAGE_COMMIT_UNKNOWN",
    ),
    "STARTUP_T6_HEALTH_FAULT": (8, "NINLIL_E_STORAGE_CORRUPT"),
    "STARTUP_BEARER_OPEN_FAULT": (9, "NINLIL_E_WOULD_BLOCK"),
    "STARTUP_ENTROPY_FAULT": (10, "NINLIL_E_ENTROPY"),
    "STARTUP_T7_PUBLICATION_GATE_FAULT": (
        11,
        "NINLIL_E_STORAGE_CORRUPT",
    ),
    "STARTUP_SUCCESS": (None, "NINLIL_OK"),
}

CLOSED_STATUS_CASES = {
    "S4_BINDING_CURRENT_POSITIVE": (
        "NLR1_BINDING",
        "CURRENT",
        "NINLIL_OK",
    ),
    "S4_BINDING_FORMAT3_FUTURE": (
        "NLR1_BINDING",
        "FRAMING_VALID_FUTURE",
        "NINLIL_E_UNSUPPORTED",
    ),
    "S4_NLR1_RECORD_VERSION2_FUTURE": (
        "NLR1_BINDING",
        "FRAMING_VALID_FUTURE",
        "NINLIL_E_UNSUPPORTED",
    ),
    "S4_NLR1_BINDING_CRC_MISMATCH": (
        "NLR1_BINDING",
        "MALFORMED_CURRENT",
        "NINLIL_E_STORAGE_CORRUPT",
    ),
    "S4_NLR1_BINDING_SHORT": (
        "NLR1_BINDING",
        "MALFORMED_CURRENT",
        "NINLIL_E_STORAGE_CORRUPT",
    ),
    "S4_NTS3_CURRENT_POSITIVE": ("NTS3", "CURRENT", "NINLIL_OK"),
    "S4_NTS3_SCHEMA2_FUTURE": (
        "NTS3",
        "FRAMING_VALID_FUTURE",
        "NINLIL_E_UNSUPPORTED",
    ),
    "S4_NTS3_CRC_MISMATCH": (
        "NTS3",
        "MALFORMED_CURRENT",
        "NINLIL_E_STORAGE_CORRUPT",
    ),
    "S4_NTS3_SHORT": (
        "NTS3",
        "MALFORMED_CURRENT",
        "NINLIL_E_STORAGE_CORRUPT",
    ),
    "S4_M4T_CURRENT_POSITIVE": ("M4T", "CURRENT", "NINLIL_OK"),
    "S4_M4T_VERSION2_FUTURE": (
        "M4T",
        "FRAMING_VALID_FUTURE",
        "NINLIL_E_UNSUPPORTED",
    ),
    "S4_M4T_CRC_MISMATCH": (
        "M4T",
        "MALFORMED_CURRENT",
        "NINLIL_E_STORAGE_CORRUPT",
    ),
    "S4_M4T_SHORT": (
        "M4T",
        "MALFORMED_CURRENT",
        "NINLIL_E_STORAGE_CORRUPT",
    ),
}


class GateError(RuntimeError):
    pass


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def classify_nlr1_binding(key: bytes, value: bytes) -> str:
    if key != bytes.fromhex("4e494e4c494c000101"):
        return "NINLIL_E_STORAGE_CORRUPT"
    if len(value) < 16:
        return "NINLIL_E_STORAGE_CORRUPT"
    if value[:4] != b"NLR1":
        return "NINLIL_E_STORAGE_CORRUPT"
    if int.from_bytes(value[4:6], "big") != 1:
        return "NINLIL_E_STORAGE_CORRUPT"
    payload_length = int.from_bytes(value[8:12], "big")
    if len(value) != 12 + payload_length + 4:
        return "NINLIL_E_STORAGE_CORRUPT"
    if int.from_bytes(value[-4:], "big") != crc32c(value[:-4]):
        return "NINLIL_E_STORAGE_CORRUPT"
    record_version = int.from_bytes(value[6:8], "big")
    if record_version > 1:
        return "NINLIL_E_UNSUPPORTED"
    if record_version != 1 or payload_length < 4:
        return "NINLIL_E_STORAGE_CORRUPT"
    binding_format = int.from_bytes(value[12:16], "big")
    if binding_format not in (1, 2):
        return "NINLIL_E_UNSUPPORTED"
    return "NINLIL_OK"


def classify_nts3(key: bytes, value: bytes) -> str:
    if len(key) != 18 or key[:2] not in {
        b"TX",
        b"CN",
        b"DS",
        b"EV",
        b"OC",
        b"ES",
        b"RT",
        b"AP",
    } or not any(key[2:]):
        return "NINLIL_E_STORAGE_CORRUPT"
    if len(value) < 20 or value[:4] != b"NTS3":
        return "NINLIL_E_STORAGE_CORRUPT"
    body_length = int.from_bytes(value[8:12], "big")
    if len(value) != 16 + body_length + 4:
        return "NINLIL_E_STORAGE_CORRUPT"
    if int.from_bytes(value[-4:], "big") != crc32c(value[:-4]):
        return "NINLIL_E_STORAGE_CORRUPT"
    if value[32:48] != key[2:]:
        return "NINLIL_E_STORAGE_CORRUPT"
    schema_major = int.from_bytes(value[4:6], "big")
    if schema_major > 1:
        return "NINLIL_E_UNSUPPORTED"
    if schema_major != 1:
        return "NINLIL_E_STORAGE_CORRUPT"
    if int.from_bytes(value[6:8], "big") != 0:
        return "NINLIL_E_STORAGE_CORRUPT"
    if any(value[12:16]) or body_length < 32:
        return "NINLIL_E_STORAGE_CORRUPT"
    return "NINLIL_OK"


def classify_m4t(key: bytes, value: bytes) -> str:
    if len(key) != 16 or key[:3] != b"M4T":
        return "NINLIL_E_STORAGE_CORRUPT"
    if len(value) != 72:
        return "NINLIL_E_STORAGE_CORRUPT"
    if int.from_bytes(value[68:72], "big") != crc32c(value[:68]):
        return "NINLIL_E_STORAGE_CORRUPT"
    if key[3:7] != value[4:8] or key[7:16] != value[36:45]:
        return "NINLIL_E_STORAGE_CORRUPT"
    version = value[0]
    if version > 1:
        return "NINLIL_E_UNSUPPORTED"
    if version != 1:
        return "NINLIL_E_STORAGE_CORRUPT"
    if (
        value[1] not in (1, 2)
        or any(value[2:4])
        or not int.from_bytes(value[8:16], "big")
        or not int.from_bytes(value[16:24], "big")
        or not int.from_bytes(value[24:28], "big")
        or not int.from_bytes(value[28:36], "big")
        or not any(value[36:68])
    ):
        return "NINLIL_E_STORAGE_CORRUPT"
    return "NINLIL_OK"


def classify_raw(parser: str, key: bytes, value: bytes) -> str:
    if parser == "NLR1_BINDING":
        return classify_nlr1_binding(key, value)
    if parser == "NTS3":
        return classify_nts3(key, value)
    if parser == "M4T":
        return classify_m4t(key, value)
    raise GateError(f"unknown raw parser {parser!r}")


def expected_transcript(fault_index: int | None) -> dict[str, Any]:
    attempted = STAGES if fault_index is None else STAGES[: fault_index + 1]
    completed = STAGES if fault_index is None else STAGES[:fault_index]
    completed_set = set(completed)
    attempted_set = set(attempted)
    t2 = "T2_d3_s4_s12_cross_row_validation" in completed_set
    t3 = "T3_d4_recovery_full_and_rescan" in completed_set
    t4 = "T4_identity_recovery" in completed_set
    published = int("public_runtime_publish" in completed_set)
    return {
        "ordered_attempted_stages": attempted,
        "ordered_completed_stages": completed,
        "T0_complete": int("T0_same_rw_zero_row_scan" in completed_set),
        "T1a_complete": int("T1a_format2_bootstrap_full" in completed_set),
        "T1b_complete": int(
            "T1b_uninitialized_metadata_full" in completed_set
        ),
        "T2_complete": int(t2),
        "T3_complete": int(t3),
        "T4_complete": int(t4),
        "storage_recovery_complete": int(t2 and t3 and t4),
        "trusted_clock_sample_count": int(
            "T5_trusted_clock_sample" in attempted_set
        ),
        "T5_commit_attempt_count": int(
            "T5_clock_full_commit_and_rescan" in attempted_set
        ),
        "T6_health_attempt_count": int(
            "T6_durable_health_reconstruction" in attempted_set
        ),
        "T5_complete": int(
            "T5_clock_full_commit_and_rescan" in completed_set
        ),
        "T6_complete": int(
            "T6_durable_health_reconstruction" in completed_set
        ),
        "T7_complete": int("T7_publication_gate" in completed_set),
        "bearer_open": int("bearer_open" in attempted_set),
        "metrics_entropy": int("metrics_entropy" in attempted_set),
        "callback": 0,
        "public_handle": published,
        "publish": published,
    }


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
    if document.get("format") != (
        "ninlil-domain-store-schema1-runtime-binding-v1"
    ):
        raise GateError("wrong document format")
    expected_digest = hashlib.sha256(
        canonical_without_integrity(document)
    ).hexdigest()
    if document.get("integrity", {}).get("sha256") != expected_digest:
        raise GateError("document integrity digest mismatch")

    closed = document.get("closed_status_oracle_vectors")
    if not isinstance(closed, dict):
        raise GateError("closed status collection missing")
    vectors = closed.get("vectors")
    if not isinstance(vectors, list):
        raise GateError("closed status vectors missing")
    by_id = {vector.get("id"): vector for vector in vectors}
    if len(by_id) != len(vectors) or set(by_id) != set(CLOSED_STATUS_CASES):
        raise GateError("closed status vector set is not exact")
    categories = {
        "CURRENT": 0,
        "FRAMING_VALID_FUTURE": 0,
        "MALFORMED_CURRENT": 0,
    }
    for vector_id, (parser, category, status) in CLOSED_STATUS_CASES.items():
        vector = by_id[vector_id]
        if (
            vector.get("parser") != parser
            or vector.get("category") != category
            or vector.get("expected_status") != status
            or vector.get("canonical_publish") is not False
        ):
            raise GateError(f"{vector_id}: metadata mismatch")
        try:
            key = bytes.fromhex(vector["key_hex"])
            value = bytes.fromhex(vector["value_hex"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GateError(f"{vector_id}: invalid raw hex") from exc
        if hashlib.sha256(value).hexdigest() != vector.get("value_sha256"):
            raise GateError(f"{vector_id}: value digest mismatch")
        computed = classify_raw(parser, key, value)
        if computed != status:
            raise GateError(
                f"{vector_id}: raw classification {computed}, want {status}"
            )
        categories[category] += 1
    if (
        closed.get("fixture_count") != 13
        or closed.get("current_positive_count") != categories["CURRENT"]
        or closed.get("framing_valid_future_count")
        != categories["FRAMING_VALID_FUTURE"]
        or closed.get("malformed_current_count")
        != categories["MALFORMED_CURRENT"]
        or categories != {
            "CURRENT": 3,
            "FRAMING_VALID_FUTURE": 4,
            "MALFORMED_CURRENT": 6,
        }
    ):
        raise GateError("closed status count mismatch")

    startup = document.get("startup_lifecycle_fault_transcripts")
    if not isinstance(startup, dict) or startup.get("canonical_order") != STAGES:
        raise GateError("startup canonical order mismatch")
    startup_vectors = startup.get("vectors")
    if not isinstance(startup_vectors, list):
        raise GateError("startup vectors missing")
    startup_by_id = {vector.get("id"): vector for vector in startup_vectors}
    if (
        len(startup_by_id) != len(startup_vectors)
        or set(startup_by_id) != set(STARTUP_CASES)
    ):
        raise GateError("startup vector set is not exact")
    for vector_id, (fault_index, status) in STARTUP_CASES.items():
        vector = startup_by_id[vector_id]
        if (
            vector.get("fault_stage_index") != fault_index
            or vector.get("expected_status") != status
        ):
            raise GateError(f"{vector_id}: fault metadata mismatch")
        expected = expected_transcript(fault_index)
        if vector.get("transcript") != expected:
            raise GateError(f"{vector_id}: transcript mismatch")
    for required in (
        "STARTUP_T2_CROSS_ROW_VALIDATION_FAULT",
        "STARTUP_T3_D4_RECOVERY_COMMIT_UNKNOWN",
        "STARTUP_T4_IDENTITY_CONFLICT",
        "STARTUP_T7_PUBLICATION_GATE_FAULT",
    ):
        transcript = startup_by_id[required]["transcript"]
        if transcript["public_handle"] != 0 or transcript["publish"] != 0:
            raise GateError(f"{required}: publication escaped")


def mutation_must_fail(
    document: dict[str, Any],
    label: str,
    mutate: Any,
) -> None:
    candidate = copy.deepcopy(document)
    mutate(candidate)
    refresh_integrity(candidate)
    try:
        validate(candidate)
    except GateError:
        return
    raise GateError(f"self-test mutation escaped: {label}")


def run_self_test(document: dict[str, Any]) -> None:
    validate(document)

    def vector(candidate: dict[str, Any], vector_id: str) -> dict[str, Any]:
        return next(
            row
            for row in candidate["closed_status_oracle_vectors"]["vectors"]
            if row["id"] == vector_id
        )

    def startup(candidate: dict[str, Any], vector_id: str) -> dict[str, Any]:
        return next(
            row
            for row in candidate[
                "startup_lifecycle_fault_transcripts"
            ]["vectors"]
            if row["id"] == vector_id
        )

    def break_future_crc(candidate: dict[str, Any]) -> None:
        row = vector(candidate, "S4_NTS3_SCHEMA2_FUTURE")
        raw = bytearray.fromhex(row["value_hex"])
        raw[-1] ^= 1
        row["value_hex"] = raw.hex()
        row["value_sha256"] = hashlib.sha256(raw).hexdigest()

    def break_future_key_binding(
        candidate: dict[str, Any],
        vector_id: str,
    ) -> None:
        row = vector(candidate, vector_id)
        raw = bytearray.fromhex(row["key_hex"])
        raw[-1] ^= 1
        row["key_hex"] = raw.hex()

    mutation_must_fail(document, "future CRC", break_future_crc)
    mutation_must_fail(
        document,
        "NTS3 future key/body binding",
        lambda candidate: break_future_key_binding(
            candidate,
            "S4_NTS3_SCHEMA2_FUTURE",
        ),
    )
    mutation_must_fail(
        document,
        "M4T future key/body binding",
        lambda candidate: break_future_key_binding(
            candidate,
            "S4_M4T_VERSION2_FUTURE",
        ),
    )
    mutation_must_fail(
        document,
        "future expected status",
        lambda candidate: vector(
            candidate,
            "S4_M4T_VERSION2_FUTURE",
        ).__setitem__("expected_status", "NINLIL_E_STORAGE_CORRUPT"),
    )
    mutation_must_fail(
        document,
        "T2 publication",
        lambda candidate: startup(
            candidate,
            "STARTUP_T2_CROSS_ROW_VALIDATION_FAULT",
        )["transcript"].__setitem__("publish", 1),
    )
    mutation_must_fail(
        document,
        "T3 completion",
        lambda candidate: startup(
            candidate,
            "STARTUP_T3_D4_RECOVERY_COMMIT_UNKNOWN",
        )["transcript"].__setitem__("T3_complete", 1),
    )
    mutation_must_fail(
        document,
        "T4 vector removed",
        lambda candidate: candidate[
            "startup_lifecycle_fault_transcripts"
        ]["vectors"].__setitem__(
            slice(None),
            [
                row
                for row in candidate[
                    "startup_lifecycle_fault_transcripts"
                ]["vectors"]
                if row["id"] != "STARTUP_T4_IDENTITY_CONFLICT"
            ],
        ),
    )
    mutation_must_fail(
        document,
        "T7 premature publish",
        lambda candidate: startup(
            candidate,
            "STARTUP_T7_PUBLICATION_GATE_FAULT",
        )["transcript"].__setitem__("public_handle", 1),
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--vector", type=Path, default=DEFAULT_VECTOR)
    args = parser.parse_args()
    try:
        document = json.loads(args.vector.read_text(encoding="utf-8"))
        if args.self_test:
            run_self_test(document)
            print(
                "domain-store schema1 binding gate self-test: PASS "
                "(8 semantic mutations rejected)"
            )
        else:
            validate(document)
            print(
                "domain-store schema1 binding gate: PASS "
                "(closed-status=13 startup=13)"
            )
    except (GateError, OSError, json.JSONDecodeError) as exc:
        print(f"domain-store schema1 binding gate: FAIL: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
