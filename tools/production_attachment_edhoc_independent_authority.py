#!/usr/bin/env python3
"""Independent PA authority checks (gate/expected). No generator / r6_oracle.

Rebuilds both-role 15-key NEW inventories and every OLD/partial/NEW/extra/
foreign/third/CU class image via verify_oracle + seeds only.
"""

from __future__ import annotations

import struct
from typing import Any

import production_attachment_edhoc_seeds as seeds
import production_attachment_edhoc_verify_oracle as vfy


class AuthorityError(RuntimeError):
    pass


def _independent_reattach_10k() -> dict[str, Any]:
    floors = [42, 44, 48, 54]
    high_waters = [59, 61, 67, 71]
    initial_floors = list(floors)
    initial_high_waters = list(high_waters)
    transcript = bytearray()
    for cycle in range(1, 10_001):
        old_floors = list(floors)
        old_hws = list(high_waters)
        floors = [value + 1 for value in old_floors]
        high_waters = [value + 1 for value in old_hws]
        if any(n < o for n, o in zip(floors, old_floors, strict=True)):
            raise AuthorityError("independent AL floor regression")
        if any(n < o for n, o in zip(high_waters, old_hws, strict=True)):
            raise AuthorityError("independent HW regression")
        transcript.extend(struct.pack(">I", cycle))
        for value in (*floors, *high_waters):
            transcript.extend(struct.pack(">Q", value))
    return {
        "cycles": 10_000,
        "restart_after_each_cycle": True,
        "initial_floors": initial_floors,
        "final_floors": floors,
        "initial_high_waters": initial_high_waters,
        "final_high_waters": high_waters,
        "regression_count": 0,
        "transcript_sha256": vfy.sha256(bytes(transcript)).hex(),
    }


def _nac_ok(record: bytes) -> bool:
    if len(record) < 88 or record[:4] != b"NAC1":
        return False
    if (
        int.from_bytes(record[4:6], "big") != 1
        or int.from_bytes(record[6:8], "big") != 88
        or int.from_bytes(record[8:12], "big") != len(record)
        or int.from_bytes(record[12:16], "big") != len(record) - 88
    ):
        return False
    scratch = bytearray(record)
    stored = int.from_bytes(scratch[84:88], "big")
    scratch[84:88] = bytes(4)
    return vfy.crc32c(bytes(scratch)) == stored


def _nar_parse(packet: bytes) -> dict[str, Any]:
    if (
        len(packet) < 68
        or len(packet) > 192
        or packet[:4] != b"NAR1"
        or packet[4] != 0x12
        or packet[5] != 1
        or int.from_bytes(packet[6:8], "big") != 68
        or int.from_bytes(packet[8:10], "big") != len(packet)
        or int.from_bytes(packet[10:12], "big") != len(packet) - 68
    ):
        raise AuthorityError("nar header")
    scratch = bytearray(packet)
    stored = int.from_bytes(scratch[64:68], "big")
    scratch[64:68] = bytes(4)
    if vfy.crc32c(bytes(scratch)) != stored:
        raise AuthorityError("nar crc")
    index, count = packet[42], packet[43]
    payload_len = len(packet) - 68
    offset = int.from_bytes(packet[60:64], "big")
    complete_len = int.from_bytes(packet[40:42], "big")
    expected_count = (complete_len + 123) // 124
    expected_payload = (
        124 if index + 1 < count else complete_len - index * 124
    )
    if (
        not 88 <= complete_len <= 600
        or count != expected_count
        or not 1 <= count <= 5
        or index >= count
        or offset != index * 124
        or not 1 <= payload_len <= 124
        or payload_len != expected_payload
    ):
        raise AuthorityError("nar canonical fragment shape")
    return {
        "tuple": (
            packet[12:28],
            int.from_bytes(packet[28:36], "big"),
            int.from_bytes(packet[36:40], "big"),
            complete_len,
            packet[44:60],
            count,
        ),
        "index": index,
        "payload": packet[68:],
    }


def _nar_reassemble(
    packets: list[bytes],
    *,
    source: bytes,
    owner_source: bytes | None = None,
    timeout: bool = False,
) -> tuple[str, int, int, int]:
    if owner_source is not None and owner_source != source:
        return ("DISCARDED_SOURCE_MISMATCH", 0, 0, 0)
    owner: tuple[Any, ...] | None = None
    slots: dict[int, bytes] = {}
    duplicates = 0
    for packet in packets:
        try:
            parsed = _nar_parse(packet)
        except AuthorityError:
            return ("DISCARDED_MALFORMED", len(slots), duplicates, 0)
        key = (source, *parsed["tuple"])
        if owner is None:
            owner = key
        elif owner != key:
            return ("DISCARDED_MIXED_TUPLE", len(slots), duplicates, 0)
        if parsed["index"] in slots:
            if slots[parsed["index"]] == packet:
                duplicates += 1
                continue
            return (
                "DISCARDED_CONFLICTING_DUPLICATE",
                len(slots),
                duplicates,
                0,
            )
        slots[parsed["index"]] = packet
    if owner is None:
        return ("INCOMPLETE", 0, 0, 0)
    count = int(owner[-1])
    if len(slots) < count:
        return (
            "DISCARDED_IDLE_TIMEOUT" if timeout else "INCOMPLETE",
            len(slots),
            duplicates,
            0,
        )
    parsed = [_nar_parse(slots[index]) for index in range(count)]
    complete = b"".join(item["payload"] for item in parsed)
    session, generation, sequence, complete_len, digest16, _ = parsed[0]["tuple"]
    if len(complete) != complete_len or vfy.sha256(complete)[:16] != digest16:
        return ("DISCARDED_DIGEST_OR_LENGTH", len(slots), duplicates, 0)
    if (
        not _nac_ok(complete)
        or complete[20:36] != session
        or int.from_bytes(complete[36:44], "big") != generation
        or int.from_bytes(complete[44:48], "big") != sequence
    ):
        return ("DISCARDED_INNER_MISMATCH", len(slots), duplicates, 0)
    return ("COMPLETE", len(slots), duplicates, len(complete))


def _recrc_nar(packet: bytes) -> bytes:
    out = bytearray(packet)
    out[64:68] = bytes(4)
    out[64:68] = vfy.crc32c(bytes(out)).to_bytes(4, "big")
    return bytes(out)


def _nar_shape_packet(
    complete_len: int, index: int, count: int, payload_len: int
) -> bytes:
    packet = bytearray(68 + payload_len)
    packet[:4] = b"NAR1"
    packet[4:8] = b"\x12\x01\x00\x44"
    packet[8:10] = len(packet).to_bytes(2, "big")
    packet[10:12] = payload_len.to_bytes(2, "big")
    packet[12:28] = bytes(range(1, 17))
    packet[28:36] = (1).to_bytes(8, "big")
    packet[40:42] = complete_len.to_bytes(2, "big")
    packet[42] = index
    packet[43] = count
    packet[44:60] = bytes(range(17, 33))
    packet[60:64] = (index * 124).to_bytes(4, "big")
    packet[68:] = bytes((value & 0xFF) for value in range(payload_len))
    return _recrc_nar(bytes(packet))


def _assert_nar_fragment_shape_authority() -> None:
    accepted = (
        (88, 0, 1, 88),
        (124, 0, 1, 124),
        (125, 0, 2, 124),
        (125, 1, 2, 1),
        (159, 1, 2, 35),
        (600, 4, 5, 104),
    )
    rejected = (
        (87, 0, 1, 87),
        (601, 4, 5, 105),
        (124, 0, 2, 124),
        (124, 1, 2, 0),
        (159, 0, 3, 124),
        (159, 1, 3, 35),
        (159, 0, 2, 123),
        (159, 1, 2, 34),
    )
    for shape in accepted:
        _nar_parse(_nar_shape_packet(*shape))
    for shape in rejected:
        try:
            _nar_parse(_nar_shape_packet(*shape))
        except AuthorityError:
            continue
        raise AuthorityError(f"nar coherent shape mutant accepted: {shape}")


def assert_nar_authority(document: dict[str, Any]) -> None:
    _assert_nar_fragment_shape_authority()
    fragments = [_hx(row["hex"]) for row in document["compact_radio_fragments"]]
    source = _hx(document["preauth_owner"]["source_locator_digest_hex"])
    conflict = bytearray(fragments[0])
    conflict[-1] ^= 1
    overlap = bytearray(fragments[1])
    overlap[60:64] = (100).to_bytes(4, "big")
    mixed = bytearray(fragments[1])
    mixed[28:36] = (
        int.from_bytes(mixed[28:36], "big") + 1
    ).to_bytes(8, "big")
    inner: list[bytes] = []
    for packet in fragments:
        row = bytearray(packet)
        row[28:36] = (
            int.from_bytes(row[28:36], "big") + 1
        ).to_bytes(8, "big")
        inner.append(_recrc_nar(bytes(row)))
    expected = {
        "canonical_success": _nar_reassemble(fragments, source=source),
        "reordered_success": _nar_reassemble(list(reversed(fragments)), source=source),
        "same_duplicate_no_progress": _nar_reassemble(
            [fragments[0], fragments[0], *fragments[1:]], source=source
        ),
        "conflicting_duplicate_discard": _nar_reassemble(
            [fragments[0], _recrc_nar(bytes(conflict)), *fragments[1:]],
            source=source,
        ),
        "gap_loss_timeout_discard": _nar_reassemble(
            fragments[:-1], source=source, timeout=True
        ),
        "overlap_discard": _nar_reassemble(
            [fragments[0], _recrc_nar(bytes(overlap))], source=source
        ),
        "mixed_tuple_discard": _nar_reassemble(
            [fragments[0], _recrc_nar(bytes(mixed))], source=source
        ),
        "inner_mismatch_discard": _nar_reassemble(inner, source=source),
        "source_mismatch_discard": _nar_reassemble(
            fragments,
            source=vfy.sha256(b"other-source"),
            owner_source=source,
        ),
    }
    cases = document["nar1_reassembly"]["cases"]
    if document["nar1_reassembly"]["owner_key_fields"][0] != "source_locator_digest32":
        raise AuthorityError("NAR source locator owner key")
    for name, (outcome, progress, duplicates, published) in expected.items():
        got = cases[name]
        if (
            got["outcome"] != outcome
            or int(got["progress_count"]) != progress
            or int(got["duplicate_count"]) != duplicates
            or int(got["published_bytes"]) != published
        ):
            raise AuthorityError(f"NAR executed case {name}")


def _nas_outcome(chunks: list[bytes], eof: bool) -> tuple[str, int]:
    buf = b"".join(chunks)
    if len(buf) > 612:
        return ("CLOSE_OVERFLOW", 0)
    if len(buf) >= 12:
        if buf[:4] != b"NAS1":
            return ("CLOSE_MAGIC", 0)
        if buf[4] != 1:
            return ("CLOSE_FUTURE_OR_BAD_VERSION", 0)
        if buf[5] not in (1, 2) or int.from_bytes(buf[6:8], "big") != 12:
            return ("CLOSE_HEADER", 0)
        length = int.from_bytes(buf[8:12], "big")
        if not 88 <= length <= 600:
            return ("CLOSE_LENGTH", 0)
        total = 12 + length
        if len(buf) > total:
            return ("CLOSE_TRAILING_BYTES", 0)
        if len(buf) == total:
            inner = buf[12:]
            if not _nac_ok(inner):
                return ("CLOSE_INNER_CORRUPT", 0)
            if inner[18] != buf[5]:
                return ("CLOSE_INNER_CARRIER_MISMATCH", 0)
            return ("DELIVERED", 1)
    return ("CLOSE_SHORT_EOF", 0) if eof else ("NEED_MORE", 0)


def assert_nas_authority(document: dict[str, Any]) -> None:
    nas = _hx(document["stream_wrapper"]["usb_nas1_hex"])
    mismatch = bytearray(nas)
    mismatch[30] = 2  # 12-byte wrapper + inner carrier byte 18
    inner = bytearray(mismatch[12:])
    inner[84:88] = bytes(4)
    inner[84:88] = vfy.crc32c(bytes(inner)).to_bytes(4, "big")
    mismatch[12:] = inner
    future = bytearray(nas)
    future[4] = 2
    expected = {
        "single_read_success": _nas_outcome([nas], False),
        "partial_read_success": _nas_outcome(
            [nas[:1], nas[1:7], nas[7:12], nas[12:91], nas[91:]], False
        ),
        "short_eof_close": _nas_outcome([nas[:-1]], True),
        "trailing_bytes_close": _nas_outcome([nas + b"\0"], False),
        "future_version_close": _nas_outcome([bytes(future)], False),
        "inner_carrier_mismatch_close": _nas_outcome([bytes(mismatch)], False),
    }
    for name, (outcome, deliveries) in expected.items():
        got = document["nas1_stream_lifecycle"]["cases"][name]
        if got["outcome"] != outcome or got["delivery_count"] != deliveries:
            raise AuthorityError(f"NAS lifecycle {name}")


def assert_prerequisite_authority(document: dict[str, Any]) -> None:
    block = document["prerequisites"]
    readiness = block["dependency_readiness"]
    if readiness != {
        "factory_identity": "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED",
        "site_membership": "UPSTREAM_ACCEPTANCE_NOT_ESTABLISHED",
        "production_attachment_status": "PROPOSED",
        "pa_may_claim_dependency_ready": False,
        "owner_start_without_accepted_dependencies": "FAIL_CLOSED_NOT_READY",
    }:
        raise AuthorityError("dependency readiness/nonclaim")
    credentials = document["credentials"]
    expected_roles = (
        (
            "initiator_local_role_1",
            1,
            _hx(credentials["initiator_ccs_hex"]),
            _hx(credentials["initiator_kid_hex"]),
            _hx(credentials["initiator_x_hex"]),
            _hx(credentials["initiator_y_hex"]),
            seeds.INITIATOR_STABLE_DIGEST,
            23,
            b"IKREF001",
        ),
        (
            "responder_local_role_2",
            2,
            _hx(credentials["responder_ccs_hex"]),
            _hx(credentials["responder_kid_hex"]),
            _hx(credentials["responder_x_hex"]),
            _hx(credentials["responder_y_hex"]),
            seeds.RESPONDER_STABLE_DIGEST,
            29,
            b"RKREF001",
        ),
    )
    for name, role, ccs, kid, x, y, stable, generation, ref in expected_roles:
        row = block["local_credential_descriptors"][name]
        if (
            row["local_role"] != role
            or row["factory_identity_state"] != "PROVISIONED"
            or _hx(row["factory_stable_id_digest_hex"]) != stable
            or _hx(row["canonical_ccs_hex"]) != ccs
            or _hx(row["canonical_ccs_sha256"]) != vfy.sha256(ccs)
            or _hx(row["kid_hex"]) != kid
            or row["curve"] != "P-256"
            or _hx(row["public_key_digest_hex"]) != vfy.sha256(b"\x04" + x + y)
            or row["provider_generation"] != generation
            or _hx(row["opaque_key_reference_hex"]) != ref
            or row["opaque_key_reference_length"] != len(ref)
            or row["copy_owned"] is not True
        ):
            raise AuthorityError(f"local credential descriptor {name}")
    port = block["local_static_dh_port"]
    if (
        port["operation"] != "P256_STATIC_DH"
        or port["output_owner"] != "CALLER_OWNED_BOUNDED_SECRET_WORKSPACE"
        or port["output_bytes_exact"] != 32
        or port["write_count_exact"] != 1
        or port["private_scalar_exported"] is not False
        or port["backend_pointer_exported"] is not False
        or port["provider_serialization"] != "NO_REENTRY"
        or port["partial_output_action"] != "ZEROIZE32_AND_TERMINAL"
        or port["after_prk_action"] != "ZEROIZE32"
    ):
        raise AuthorityError("local static DH port")
    transition_ids = [
        "VALID_BASELINE",
        "WRONG_FACTORY_IDENTITY",
        "WRONG_ROLE",
        "WRONG_CURVE",
        "PUBLIC_PRIVATE_KEY_MISMATCH",
        "CREDENTIAL_REVISION_ROLLBACK",
        "PROVIDER_GENERATION_ROLLBACK",
        "UNKNOWN_OPAQUE_KEY_REFERENCE",
        "PROVIDER_REENTRY",
        "PARTIAL_OUTPUT",
    ]
    transitions = block["local_static_dh_transitions"]

    # This is intentionally a transition derivation, not an ID/counter
    # comparison.  Every row is evaluated as a concrete local credential +
    # provider call.  The first failing typed predicate owns the terminal
    # result; output is always scrubbed before it can be observed.
    baseline = {
        "factory_stable_id_digest_hex": seeds.INITIATOR_STABLE_DIGEST.hex(),
        "descriptor_local_role": 1,
        "requested_local_role": 1,
        "curve": "P-256",
        "public_private_binding": "MATCH",
        "credential_set_revision": 19,
        "credential_set_revision_floor": 19,
        "provider_generation": 23,
        "provider_generation_floor": 23,
        "opaque_key_reference_hex": "494b524546303031",
        "provider_reentry": False,
        "provider_output_bytes": 32,
    }

    def derived_expected(input_row: dict[str, Any]) -> dict[str, Any]:
        valid = (
            input_row["factory_stable_id_digest_hex"]
            == baseline["factory_stable_id_digest_hex"]
            and input_row["descriptor_local_role"]
            == input_row["requested_local_role"] == 1
            and input_row["curve"] == "P-256"
            and input_row["public_private_binding"] == "MATCH"
            and input_row["credential_set_revision"]
            >= input_row["credential_set_revision_floor"]
            and input_row["provider_generation"]
            >= input_row["provider_generation_floor"]
            and input_row["opaque_key_reference_hex"]
            == baseline["opaque_key_reference_hex"]
            and input_row["provider_reentry"] is False
            and input_row["provider_output_bytes"] == 32
        )
        if valid:
            return {
                "status": "SUCCESS", "terminal": False, "wire_records": 0,
                "exporter_calls": 0, "ecdh_write_count": 1,
                "ecdh_output_published_bytes": 32,
                "zeroized_output_bytes": 32,
                "private_key_bytes_exported": 0,
            }
        return {
            "status": "TERMINAL_AUTHENTICATION_FAILURE", "terminal": True,
            "wire_records": 0, "exporter_calls": 0, "ecdh_write_count": 0,
            "ecdh_output_published_bytes": 0, "zeroized_output_bytes": 32,
            "private_key_bytes_exported": 0,
        }

    failure_delta = {
        "WRONG_FACTORY_IDENTITY": (
            "factory_stable_id_digest_hex", "00" * 32
        ),
        "WRONG_ROLE": ("requested_local_role", 2),
        "WRONG_CURVE": ("curve", "X25519"),
        "PUBLIC_PRIVATE_KEY_MISMATCH": (
            "public_private_binding", "MISMATCH"
        ),
        "CREDENTIAL_REVISION_ROLLBACK": ("credential_set_revision", 18),
        "PROVIDER_GENERATION_ROLLBACK": ("provider_generation", 22),
        "UNKNOWN_OPAQUE_KEY_REFERENCE": (
            "opaque_key_reference_hex", "554e4b4e4f574e31"
        ),
        "PROVIDER_REENTRY": ("provider_reentry", True),
        "PARTIAL_OUTPUT": ("provider_output_bytes", 31),
    }

    def validate_transitions(rows: list[dict[str, Any]]) -> None:
        if [row["id"] for row in rows] != transition_ids:
            raise AuthorityError("local static-DH transition IDs")
        for index, row in enumerate(rows):
            input_row = row["input"]
            expected = derived_expected(input_row)
            if row["expected"] != expected:
                raise AuthorityError(f"local static-DH transition {row['id']}")
            deltas = {
                key: value for key, value in input_row.items()
                if baseline[key] != value
            }
            required = {} if index == 0 else {
                failure_delta[row["id"]][0]: failure_delta[row["id"]][1]
            }
            if input_row.keys() != baseline.keys() or deltas != required:
                raise AuthorityError(
                    f"local static-DH ID/delta binding {row['id']}"
                )

    validate_transitions(transitions)
    # Keep IDs and expected terminal effects fixed while moving coherent
    # one-delta inputs.  A validator that only checks ordering + one delta
    # would falsely accept both probes.
    swap = [dict(row, input=dict(row["input"])) for row in transitions]
    swap[2]["input"], swap[3]["input"] = swap[3]["input"], swap[2]["input"]
    rotate = [dict(row, input=dict(row["input"])) for row in transitions]
    rotate[2]["input"], rotate[3]["input"], rotate[4]["input"] = (
        rotate[3]["input"], rotate[4]["input"], rotate[2]["input"]
    )
    for probe in (swap, rotate):
        try:
            validate_transitions(probe)
        except AuthorityError:
            continue
        raise AuthorityError("local static-DH ID/input mutant accepted")


def assert_edhoc_attempt_authority(document: dict[str, Any]) -> None:
    block = document["edhoc_attempts"]
    for name, suite, generation in (("suite_2", 2, 101), ("suite_3", 3, 102)):
        attempt = block["attempts"][name]
        if (
            attempt["method"] != 3
            or attempt["suite"] != suite
            or attempt["exchange_generation"] != generation
            or len(attempt["messages"]) != 4
            or attempt["message_4_required"] is not True
            or attempt["message_4_verified_before_exporter"] is not True
            or attempt["exporter_calls_before_message_4"] != 0
            or attempt["exporter_calls_after_message_4"] != 8
            or attempt["real_provider_kat_claimed"] is not False
        ):
            raise AuthorityError(f"EDHOC attempt {name}")
        for stage, row in enumerate(attempt["messages"], 1):
            payload = _hx(row["payload_hex"])
            nac = _hx(row["nac1_hex"])
            if (
                row["stage"] != stage
                or row["kind"] != 3 + stage
                or row["message_name"] != f"message_{stage}"
                or _hx(row["payload_sha256"]) != vfy.sha256(payload)
                or not _nac_ok(nac)
                or nac[16] != 3 + stage
                or int.from_bytes(nac[36:44], "big") != generation
                or int.from_bytes(nac[44:48], "big") != stage
                or nac[88:] != payload
                or row["ead_present"] is not False
                or row["ead_item_count"] != 0
                or row["verified"] is not True
            ):
                raise AuthorityError(f"EDHOC {name} message {stage}")
    ead = block["ead_nonempty_terminal_matrix"]

    def validate_ead_rows(rows: list[dict[str, Any]]) -> None:
        # The id, stage and consumed octets form one closed bijection.  This
        # deliberately rejects the all-empty, all-stage-1, duplicate and
        # swapped-byte variants even if their result counters are followed.
        if len(rows) != 4:
            raise AuthorityError("EAD row cardinality")
        by_stage: dict[int, dict[str, Any]] = {}
        consumed: set[bytes] = set()
        for row in rows:
            stage = row["stage"]
            ead_bytes = _hx(row["ead_hex"])
            if (
                type(stage) is not int
                or stage not in (1, 2, 3, 4)
                or stage in by_stage
                or row["id"] != f"EAD_{stage}_NONEMPTY"
                or not ead_bytes
                or ead_bytes != bytes([stage])
                or ead_bytes in consumed
                or row["outcome"] != "TERMINAL_REJECT"
                or row["exporter_calls"] != 0
                or row["automatic_retry_count"] != 0
                or row["wire_records_after_reject"] != 0
            ):
                raise AuthorityError("EAD bijection/consumption")
            by_stage[stage] = row
            consumed.add(ead_bytes)
        if set(by_stage) != {1, 2, 3, 4} or len(consumed) != 4:
            raise AuthorityError("EAD stage coverage")

    validate_ead_rows(ead)
    # Independent coherent negative probes; neither row IDs nor expected
    # counters are the acceptance oracle.
    probes: list[list[dict[str, Any]]] = []
    all_empty = [dict(row, ead_hex="") for row in ead]
    probes.append(all_empty)
    all_stage1 = [dict(row, stage=1, id="EAD_1_NONEMPTY") for row in ead]
    probes.append(all_stage1)
    duplicate = [dict(row) for row in ead]
    duplicate[1]["ead_hex"] = duplicate[0]["ead_hex"]
    probes.append(duplicate)
    swapped = [dict(row) for row in ead]
    swapped[0]["ead_hex"], swapped[1]["ead_hex"] = (
        swapped[1]["ead_hex"], swapped[0]["ead_hex"]
    )
    probes.append(swapped)
    for probe in probes:
        try:
            validate_ead_rows(probe)
        except AuthorityError:
            continue
        raise AuthorityError("EAD coherent mutant accepted")
    if block["downgrade_failure"] != {
        "initial_pinned_suite": 2,
        "suggested_other_suite": 3,
        "automatic_retry_count": 0,
        "same_policy_revision_retry_allowed": False,
        "fresh_policy_revision_required": True,
        "fresh_session_generation_required": True,
        "outcome": "TERMINAL_NO_AUTODOWNGRADE",
    }:
        raise AuthorityError("downgrade no autoretry")


def _execute_preauth_transcript_independent(
    document: dict[str, Any],
) -> dict[str, int]:
    """Replay PA pre-auth rows without importing generator semantics."""
    pre = document["preauth_owner"]
    required_branches = [
        "ALLOCATE",
        "FRAGMENT_0_ACCEPT",
        "FRAGMENT_1_ACCEPT",
        "SAME_DUPLICATE",
        "CONFLICTING_DUPLICATE_TERMINAL",
        "COMPLETE_RELEASE",
        "PER_SOURCE_QUOTA_DENY",
        "GLOBAL_QUOTA_DENY",
        "TOKEN_CAPACITY_DENY",
        "REFILL_BEFORE_2S",
        "REFILL_AT_2S",
        "IDLE_BEFORE_9S",
        "IDLE_AT_9S_RELEASE",
        "COOKIE_CURRENT_ACCEPT",
        "COOKIE_PREVIOUS_ACCEPT",
        "COOKIE_OLDER_EXISTING_TERMINAL",
        "COOKIE_OLDER_NO_OWNER",
    ]
    if (
        pre["owner_key_fields"]
        != [
            "source_locator_digest32",
            "session_id16",
            "exchange_generation_u64",
            "record_sequence_u32",
            "complete_nac1_bytes_u16",
            "digest16",
        ]
        or pre["per_source_scratch_limit"] != 1
        or pre["global_scratch_limit"] != 8
        or pre["scratch_fragment_count_exact"] != 2
        or pre["idle_timeout_seconds"] != 9
        or pre["idle_timeout_ms"] != 9_000
        or pre["cookie_valid_buckets"] != ["CURRENT", "PREVIOUS"]
        or pre["token_bucket_capacity"] != 2
        or pre["token_refill_seconds"] != 2
        or pre["token_refill_ms"] != 2_000
        or pre["current_cookie_bucket"]
        != document["stateless_cookie"]["time_bucket"]
        or pre["identity_allocations_before_cookie"] != 0
        or pre["credential_resolver_calls_before_cookie"] != 0
        or pre["required_branch_names"] != required_branches
    ):
        raise AuthorityError("preauth constants/owner key")

    actual_fragments = [
        _hx(row["hex"])[68:]
        for row in document["stateless_cookie"]["response_radio_fragments"]
    ]
    if len(actual_fragments) != 2 or len(actual_fragments[0]) != 124:
        raise AuthorityError("preauth cookie fragments")
    payloads: dict[str, bytes] = {}
    for row in pre["transitions"]:
        variant = row["fragment_payload_variant"]
        payload = _hx(row["fragment_payload_hex"])
        if variant in payloads and payloads[variant] != payload:
            raise AuthorityError(f"preauth variant drift {variant}")
        payloads[variant] = payload
    if (
        payloads.get("F0") != actual_fragments[0]
        or payloads.get("F1") != actual_fragments[1]
        or payloads.get("NONE") != b""
        or len(payloads.get("F0_CONFLICT", b"")) != len(actual_fragments[0])
        or payloads["F0_CONFLICT"] == actual_fragments[0]
        or sum(
            left != right
            for left, right in zip(
                payloads["F0_CONFLICT"], actual_fragments[0], strict=True
            )
        )
        != 1
    ):
        raise AuthorityError("preauth payload variants")

    active: dict[tuple[Any, ...], dict[str, Any]] = {}
    buckets: dict[bytes, list[int]] = {}
    branch_counts = {name: 0 for name in required_branches}
    completions = releases = terminal_discards = 0
    scenario: str | None = None
    previous_time = 0

    def reset(name: str) -> None:
        nonlocal active, buckets, completions, releases, terminal_discards
        nonlocal scenario, previous_time
        active = {}
        buckets = {}
        completions = releases = terminal_discards = 0
        scenario = name
        previous_time = 0

    def key_for(row: dict[str, Any]) -> tuple[Any, ...]:
        return (
            _hx(row["source_locator_digest_hex"]),
            _hx(row["session_id_hex"]),
            row["exchange_generation"],
            row["record_sequence"],
            row["complete_nac1_bytes"],
            _hx(row["digest16_hex"]),
        )

    def release(owner_key: tuple[Any, ...]) -> None:
        nonlocal releases
        del active[owner_key]
        releases += 1

    for index, row in enumerate(pre["transitions"]):
        if row["step"] != index:
            raise AuthorityError(f"preauth step {index}")
        if row["reset_before"]:
            reset(row["scenario"])
        if scenario != row["scenario"] or row["at_ms"] < previous_time:
            raise AuthorityError(f"preauth scenario/time {index}")
        previous_time = row["at_ms"]
        hits: list[str] = []
        expired = 0
        before_idle = False
        for owner_key, owner in list(active.items()):
            elapsed = row["at_ms"] - owner["last_ms"]
            if elapsed < 0:
                raise AuthorityError("preauth owner time")
            if elapsed >= 9_000:
                release(owner_key)
                expired += 1
            elif elapsed > 0:
                before_idle = True
        if before_idle:
            hits.append("IDLE_BEFORE_9S")
        if expired:
            hits.append("IDLE_AT_9S_RELEASE")

        owner_key: tuple[Any, ...] | None = None
        source_digest: bytes | None = None
        if row["operation"] == "TICK":
            if (
                row["source_label"] != "NONE"
                or row["source_locator_digest_hex"] != ""
                or row["session_id_hex"] != ""
                or row["fragment_index"] != -1
                or row["fragment_payload_variant"] != "NONE"
                or row["fragment_payload_hex"] != ""
            ):
                raise AuthorityError("preauth tick sentinel")
            result = (
                "IDLE_EXPIRED_RELEASED" if expired else "TICK_NO_EXPIRY"
            )
        elif row["operation"] == "RECEIVE_FRAGMENT":
            owner_key = key_for(row)
            source_digest = owner_key[0]
            if len(source_digest) != 32 or len(owner_key[1]) != 16:
                raise AuthorityError("preauth key width")
            if (
                owner_key[2] < 1
                or not 0 <= owner_key[3] <= 0xFFFFFFFF
                or not 1 <= owner_key[4] <= 600
                or len(owner_key[5]) != 16
                or row["fragment_index"] not in (0, 1)
                or row["fragment_payload_variant"]
                not in ("F0", "F1", "F0_CONFLICT")
                or _hx(row["fragment_payload_hex"])
                != payloads[row["fragment_payload_variant"]]
            ):
                raise AuthorityError("preauth receive row")
            expected_source = (
                _hx(pre["source_locator_digest_hex"])
                if row["source_label"] == "PRIMARY"
                else vfy.sha256(
                    b"NINLIL-PA-PREAUTH-SOURCE-V1"
                    + row["source_label"].encode("ascii")
                )
            )
            if source_digest != expected_source:
                raise AuthorityError("preauth source derivation")
            owner = active.get(owner_key)
            if row["cookie_bucket"] not in (
                pre["current_cookie_bucket"],
                pre["current_cookie_bucket"] - 1,
            ):
                if owner is None:
                    hits.append("COOKIE_OLDER_NO_OWNER")
                    result = "COOKIE_BUCKET_EXPIRED_NO_OWNER"
                else:
                    release(owner_key)
                    terminal_discards += 1
                    hits.append("COOKIE_OLDER_EXISTING_TERMINAL")
                    result = "COOKIE_BUCKET_EXPIRED_TERMINAL_DISCARD"
            elif owner is not None:
                fragment_index = row["fragment_index"]
                payload = _hx(row["fragment_payload_hex"])
                prior = owner["fragments"].get(fragment_index)
                if prior is not None:
                    if prior == payload:
                        owner["last_ms"] = row["at_ms"]
                        hits.append("SAME_DUPLICATE")
                        result = "DUPLICATE_NO_PROGRESS"
                    else:
                        release(owner_key)
                        terminal_discards += 1
                        hits.append("CONFLICTING_DUPLICATE_TERMINAL")
                        result = "CONFLICTING_DUPLICATE_TERMINAL_DISCARD"
                else:
                    owner["fragments"][fragment_index] = payload
                    owner["last_ms"] = row["at_ms"]
                    hits.append(f"FRAGMENT_{fragment_index}_ACCEPT")
                    if len(owner["fragments"]) == 2:
                        release(owner_key)
                        completions += 1
                        hits.append("COMPLETE_RELEASE")
                        result = "COMPLETE_RELEASED"
                    else:
                        result = "FRAGMENT_ACCEPTED_PROGRESS"
            else:
                token = buckets.get(source_digest)
                if token is None:
                    token = [2, row["at_ms"]]
                    buckets[source_digest] = token
                else:
                    elapsed = row["at_ms"] - token[1]
                    if elapsed < 0:
                        raise AuthorityError("preauth refill time")
                    if 0 < elapsed < 2_000:
                        hits.append("REFILL_BEFORE_2S")
                    intervals = elapsed // 2_000
                    if intervals:
                        hits.append("REFILL_AT_2S")
                        token[0] = min(2, token[0] + intervals)
                        token[1] += intervals * 2_000
                source_active = sum(
                    1 for item in active if item[0] == source_digest
                )
                if token[0] == 0:
                    hits.append("TOKEN_CAPACITY_DENY")
                    result = "TOKEN_BUCKET_DENY"
                elif source_active == 1:
                    hits.append("PER_SOURCE_QUOTA_DENY")
                    result = "PER_SOURCE_QUOTA_DENY"
                elif len(active) == 8:
                    hits.append("GLOBAL_QUOTA_DENY")
                    result = "GLOBAL_QUOTA_DENY"
                else:
                    token[0] -= 1
                    active[owner_key] = {
                        "last_ms": row["at_ms"],
                        "fragments": {
                            row["fragment_index"]: _hx(
                                row["fragment_payload_hex"]
                            )
                        },
                    }
                    hits.extend(
                        [
                            "ALLOCATE",
                            f"FRAGMENT_{row['fragment_index']}_ACCEPT",
                            (
                                "COOKIE_CURRENT_ACCEPT"
                                if row["cookie_bucket"]
                                == pre["current_cookie_bucket"]
                                else "COOKIE_PREVIOUS_ACCEPT"
                            ),
                        ]
                    )
                    result = "FRAGMENT_ACCEPTED_ALLOCATED"
        else:
            raise AuthorityError(f"preauth operation {row['operation']!r}")

        for branch in hits:
            if branch not in branch_counts:
                raise AuthorityError(f"preauth branch {branch}")
            branch_counts[branch] += 1
        received_mask = 0
        source_active_count = 0
        source_tokens = -1
        if owner_key is not None and owner_key in active:
            for fragment_index in active[owner_key]["fragments"]:
                received_mask |= 1 << fragment_index
        if source_digest is not None:
            source_active_count = sum(
                1 for item in active if item[0] == source_digest
            )
            if source_digest in buckets:
                source_tokens = buckets[source_digest][0]
        derived = {
            "result": result,
            "branches": hits,
            "active_scratch_count": len(active),
            "source_active_scratch_count": source_active_count,
            "source_tokens": source_tokens,
            "active_owner_received_mask": received_mask,
            "expired_release_count_delta": expired,
            "completion_count": completions,
            "release_count": releases,
            "terminal_discard_count": terminal_discards,
            "identity_allocations": 0,
            "credential_resolver_calls": 0,
        }
        if row["expected"] != derived:
            raise AuthorityError(
                f"preauth transition {index}: {row['expected']!r} != {derived!r}"
            )
    if (
        not pre["transitions"]
        or not pre["transitions"][0]["reset_before"]
        or branch_counts != pre["branch_coverage"]
        or any(count < 1 for count in branch_counts.values())
    ):
        raise AuthorityError("preauth branch coverage")
    return branch_counts


def assert_preauth_authority(document: dict[str, Any]) -> None:
    _execute_preauth_transcript_independent(document)


def assert_magic_authority(document: dict[str, Any]) -> None:
    from protocol_magic_registry_gate import validate as validate_registry

    validate_registry()
    magic = document["magic_registry"]
    if (
        magic["registry"] != "spec/protocol-magic-registry-v1.json"
        or magic["pa_allocations"]
        != {
            "NAC1": "PRODUCTION_ATTACHMENT_CARRIER_RECORD",
            "NAS1": "PRODUCTION_ATTACHMENT_STREAM_WRAPPER",
            "NAR1": "PRODUCTION_ATTACHMENT_RADIO_FRAGMENT",
        }
        or magic["forbidden_pa_allocations"]
        != {
            "NPA1": "ADR0020_MULTI_PARENT_ASSIGNMENT_PAGE",
            "NPS1": "ADR0020_MULTI_PARENT_PARENT_SET",
        }
        or magic["all_pa_allocations_unique"] is not True
        or magic["repository_registry_gate_required"] is not True
    ):
        raise AuthorityError("magic registry vector binding")


def _hx(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes.fromhex(value)
    raise AuthorityError(f"hex type {type(value)}")


def fields_from_document(document: dict[str, Any]) -> dict[str, Any]:
    """Parse install_fields; pin against seeds (candidate cannot invent seeds)."""
    raw = document["attachment_install"]["install_fields"]
    fields = seeds.install_fields_dict()
    # Pin wire digests/ids match seeds (authority closed to known fixture).
    checks = {
        "attachment_id": fields["attachment_id"],
        "initiator_stable_digest": fields["initiator_stable_digest"],
        "responder_stable_digest": fields["responder_stable_digest"],
        "site_domain": fields["site_domain"],
        "authority_id": fields["authority_id"],
        "e2e_security_id": fields["e2e_security_id"],
        "membership_epoch": fields["membership_epoch"],
        "attachment_epoch": fields["attachment_epoch"],
        "authority_term": fields["authority_term"],
        "e2e_security_epoch": fields["e2e_security_epoch"],
        "hop_context_ir": fields["hop_context_ir"],
        "hop_context_ri": fields["hop_context_ri"],
        "e2e_context_ir": fields["e2e_context_ir"],
        "e2e_context_ri": fields["e2e_context_ri"],
        "hop_key_generation_ir": fields["hop_key_generation_ir"],
        "hop_key_generation_ri": fields["hop_key_generation_ri"],
        "e2e_key_generation_ir": fields["e2e_key_generation_ir"],
        "e2e_key_generation_ri": fields["e2e_key_generation_ri"],
    }
    for k, want in checks.items():
        got = raw[k]
        if isinstance(want, bytes):
            if _hx(got) != want:
                raise AuthorityError(f"seed pin {k}")
        else:
            if int(got) != int(want):
                raise AuthorityError(f"seed pin {k}")
    return fields


def _marker_from_role(document: dict[str, Any], role_name: str, which: str) -> bytes:
    return _hx(document["lifecycle"]["roles"][role_name][which]["value_hex"])


def _marker_key(document: dict[str, Any], role_name: str) -> bytes:
    return _hx(document["lifecycle"]["roles"][role_name]["pending"]["key_hex"])


def rebuild_role_authority(
    document: dict[str, Any], role_name: str, local_role: int
) -> dict[str, Any]:
    fields = fields_from_document(document)
    install_digest = _hx(document["attachment_install"]["install_digest"])
    # Independent install_digest = SHA-256(label || NAP1 || NAI1).
    proposal = _hx(document["attachment_install"]["nap1_hex"])
    descriptor = _hx(document["attachment_install"]["nai1_hex"])
    want_install = vfy.sha256(seeds.INSTALL_LABEL + proposal + descriptor)
    if want_install != install_digest:
        raise AuthorityError("install_digest != independent formula")
    install_digest = want_install

    pending = _marker_from_role(document, role_name, "pending")
    active = _marker_from_role(document, role_name, "active")
    third = _marker_from_role(document, role_name, "fenced_third")
    marker_key = _marker_key(document, role_name)

    inv = vfy.rebuild_role_inventory(
        local_role=local_role,
        fields=fields,
        install_digest=install_digest,
        marker_value=pending,
    )
    local_node = vfy.node_id16(
        fields["initiator_stable_digest"]
        if local_role == 1
        else fields["responder_stable_digest"]
    )
    peer_node = vfy.node_id16(
        fields["responder_stable_digest"]
        if local_role == 1
        else fields["initiator_stable_digest"]
    )
    old = vfy.rebuild_old_members(
        inv,
        membership_epoch=int(fields["membership_epoch"]),
        local_node=local_node,
        peer_node=peer_node,
        attachment_id=fields["attachment_id"],
    )
    images = vfy.build_class_images(
        inv,
        old,
        marker_key=marker_key,
        marker_pending=pending,
        marker_active=active,
        marker_third=third,
    )
    return {
        "inventory": inv,
        "old_members": old,
        "images": images,
        "local_node": local_node,
        "peer_node": peer_node,
        "marker_key": marker_key,
    }


def _member_match(actual: dict[str, Any], expect: dict[str, Any], path: str) -> None:
    for field in (
        "complete_key_hex",
        "value_hex",
        "context_digest_hex",
        "value_sha256",
    ):
        if field not in actual or field not in expect:
            raise AuthorityError(f"{path}: missing {field}")
        if actual[field] != expect[field]:
            raise AuthorityError(f"{path}: {field} mismatch")


def assert_independent_authority_closed(document: dict[str, Any]) -> None:
    """Full independent closure of both roles' images — no generator helpers."""
    if document.get("status") != "PROPOSED_SPEC_ONLY":
        raise AuthorityError("status must remain PROPOSED_SPEC_ONLY")
    if "old_member_count" in document["lifecycle_constants"]:
        raise AuthorityError("fixed lifecycle old_member_count forbidden")
    gm = document["lifecycle"]["group_machine"]
    if gm.get("old_count_is_protocol_constant") is not False:
        raise AuthorityError("gm OLD count must be per-row data")
    got_10k = gm["snapshots"]["reattach_10k_restart"]
    if got_10k != _independent_reattach_10k():
        raise AuthorityError("reattach 10k restart authority")
    assert_prerequisite_authority(document)
    assert_edhoc_attempt_authority(document)
    assert_nar_authority(document)
    assert_nas_authority(document)
    assert_preauth_authority(document)
    assert_magic_authority(document)
    label = document["carrier_transcript"]["label"]
    if label != seeds.CARRIER_TRANSCRIPT_LABEL.decode("ascii") or len(label) != 31:
        raise AuthorityError("carrier label")

    # Carrier primary preimage independent rehash
    primary = document["carrier_transcript"]["primary_path"]
    pre = _hx(primary["preimage_hex"])
    dig = vfy.sha256(pre)
    if dig != _hx(primary["digest_hex"]) or dig.hex() != primary["preimage_sha256"]:
        raise AuthorityError("carrier primary independent digest")
    if not pre.startswith(seeds.CARRIER_TRANSCRIPT_LABEL):
        raise AuthorityError("carrier preimage label")
    for neg in document["carrier_transcript"]["negatives"]:
        if neg.get("rejected"):
            continue
        npre = _hx(neg["preimage_hex"])
        nd = vfy.sha256(npre)
        if nd != _hx(neg["digest_hex"]) or nd == dig:
            raise AuthorityError(f"carrier neg {neg['id']}")
        if nd.hex() != neg["preimage_sha256"]:
            raise AuthorityError(f"carrier neg sha {neg['id']}")

    for role_name, local_role in (
        ("device_local_role_1", 1),
        ("authority_local_role_2", 2),
    ):
        auth = rebuild_role_authority(document, role_name, local_role)
        inv_act = document["atomic_batch_manifests"][role_name]["exact_inventory"]
        if len(inv_act) != 15 or len(auth["inventory"]) != 15:
            raise AuthorityError(f"{role_name}: inventory length")
        for i, (a, e) in enumerate(zip(inv_act, auth["inventory"])):
            if a["identity"] != e["identity"]:
                # order is complete-key order — identity must match per row
                raise AuthorityError(f"{role_name}[{i}] identity")
            if (
                a["complete_key_hex"] != e["complete_key_hex"]
                or a["value_hex"] != e["value_hex"]
                or a["context_digest_hex"] != e["context_digest_hex"]
                or a["value_sha256"] != e["value_sha256"]
            ):
                raise AuthorityError(
                    f"{role_name}[{i}] {e['identity']}: NEW image != independent"
                )
            old_expected = next(
                (
                    m
                    for m in auth["old_members"]
                    if m["complete_key_hex"] == e["complete_key_hex"]
                ),
                None,
            )
            expected_old_present = int(e["member_kind"]) != 4
            if a.get("old_present") is not expected_old_present:
                raise AuthorityError(f"{role_name}[{i}] old_present")
            if expected_old_present:
                if old_expected is None:
                    raise AuthorityError(f"{role_name}[{i}] missing old authority")
                if (
                    a.get("old_value_hex") != old_expected["value_hex"]
                    or a.get("old_value_sha256") != old_expected["value_sha256"]
                    or a.get("old_context_digest_hex")
                    != old_expected["context_digest_hex"]
                    or a.get("old_new_relation") != "DIFFERENT"
                ):
                    raise AuthorityError(f"{role_name}[{i}] OLD row mismatch")
            elif any(
                a.get(field) != ""
                for field in (
                    "old_value_hex",
                    "old_value_sha256",
                    "old_context_digest_hex",
                )
            ):
                raise AuthorityError(f"{role_name}[{i}] absent OLD bytes")
            # Floor / counter pins
            if int(e["member_kind"]) == 2:
                floor = int.from_bytes(bytes.fromhex(e["value_hex"])[8:12], "big")
                if floor != int(e["context_id"]) + 1:
                    raise AuthorityError(f"{role_name} AL floor")
                if floor != seeds.AL_FLOOR_BY_CONTEXT.get(int(e["context_id"]), floor):
                    raise AuthorityError(f"{role_name} AL floor pin table")
            if int(e["member_kind"]) == 1:
                ctr = int.from_bytes(bytes.fromhex(e["value_hex"])[8:16], "big")
                want = 1 if int(e["local_side"]) == 2 else 0
                if ctr != want:
                    raise AuthorityError(f"{role_name} lane counter")

        snaps = document["lifecycle"]["group_machine"]["snapshots"]["roles"][role_name]
        # OLD
        old_a = snaps["exact_old"]
        old_e = auth["images"]["exact_old"]
        if old_a["classification"] != "EXACT_OLD" or old_e["classification"] != "EXACT_OLD":
            raise AuthorityError(f"{role_name} OLD class")
        if int(old_a["member_count"]) != len(old_e["members"]):
            raise AuthorityError(f"{role_name} OLD count")
        if not any(int(m["member_kind"]) == 1 for m in old_a["members"]):
            raise AuthorityError(f"{role_name} legal lane OLD absent")
        for am, em in zip(old_a["members"], old_e["members"]):
            _member_match(am, em, f"{role_name}.old")

        rows = snaps["write_set_rows"]
        if len(rows) != 15:
            raise AuthorityError(f"{role_name} write_set_rows")
        old_by_key = {
            member["complete_key_hex"]: member for member in auth["old_members"]
        }
        for row, new in zip(rows, auth["inventory"]):
            old = old_by_key.get(new["complete_key_hex"])
            if row["complete_key_hex"] != new["complete_key_hex"]:
                raise AuthorityError(f"{role_name} row key")
            if row["old_present"] is not (old is not None):
                raise AuthorityError(f"{role_name} row old presence")
            if (
                row["new_value_hex"] != new["value_hex"]
                or row["new_context_digest_hex"] != new["context_digest_hex"]
            ):
                raise AuthorityError(f"{role_name} row NEW")
            if old is not None and (
                row["old_value_hex"] != old["value_hex"]
                or row["old_context_digest_hex"] != old["context_digest_hex"]
            ):
                raise AuthorityError(f"{role_name} row OLD")
        if [c["expected_classification"] for c in snaps["cu_row_classifier_cases"]] != [
            "OLD",
            "NEW",
            "STABLE",
            "THIRD",
        ]:
            raise AuthorityError(f"{role_name} CU row matrix")

        for n in range(1, 15):
            pa = snaps[f"partial_{n}"]
            pe = auth["images"][f"partial_{n}"]
            if pa["classification"] != f"PARTIAL_{n}_CORRUPT":
                raise AuthorityError(f"{role_name} partial_{n} class")
            if pa["classification"] != pe["classification"]:
                raise AuthorityError(f"{role_name} partial_{n} independent class")
            if int(pa["member_count"]) != pe["member_count"]:
                raise AuthorityError(f"{role_name} partial_{n} count")
            if pa["full_image_sha256"] != pe["full_image_sha256"]:
                raise AuthorityError(f"{role_name} partial_{n} image sha")
            for am, em in zip(pa["members"], pe["members"]):
                _member_match(am, em, f"{role_name}.partial_{n}")

        new_a = snaps["exact_new_pending_15"]
        new_e = auth["images"]["exact_new_pending_15"]
        if new_a["classification"] != "EXACT_NEW_PENDING_15":
            raise AuthorityError(f"{role_name} NEW class")
        if new_a["full_image_sha256"] != new_e["full_image_sha256"]:
            raise AuthorityError(f"{role_name} NEW image sha")
        for am, em in zip(new_a["members"], new_e["members"]):
            _member_match(am, em, f"{role_name}.new")

        # substitutions: independent class + image
        for key, ikey in (
            ("value_substitution_rejected", "value_substitution"),
            ("context_digest_substitution_rejected", "context_substitution"),
        ):
            sa = new_a[key]
            se = auth["images"][ikey]
            if sa["classification"] != "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT":
                # generator stores CU family label; independent may say THIRD
                if se["classification"] not in (
                    "THIRD_OR_MISMATCH_CORRUPT",
                    "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT",
                ):
                    raise AuthorityError(f"{role_name} {key} class {se['classification']}")
            if sa["full_image_sha256"] == new_a["full_image_sha256"]:
                raise AuthorityError(f"{role_name} {key} image collision")
            # Recompute substitution image independently must differ from NEW
            if se["full_image_sha256"] == new_e["full_image_sha256"]:
                raise AuthorityError(f"{role_name} {key} independent collision")

        extra_a = snaps["extra_16"]
        extra_e = auth["images"]["extra_16"]
        if extra_a["classification"] not in (
            "FOREIGN_OR_EXTRA_CORRUPT",
            "EXTRA_CORRUPT",
        ):
            raise AuthorityError(f"{role_name} extra class")
        if extra_e["classification"] != "FOREIGN_OR_EXTRA_CORRUPT":
            raise AuthorityError(f"{role_name} extra independent class")
        if extra_a.get("foreign_complete_key_hex") != extra_e["foreign_complete_key_hex"]:
            raise AuthorityError(f"{role_name} foreign key")

        third_a = snaps["third_mismatch"]
        third_e = auth["images"]["third_mismatch"]
        if third_a["classification"] != "THIRD_OR_MISMATCH_CORRUPT":
            raise AuthorityError(f"{role_name} third class")
        if third_e["classification"] not in (
            "THIRD_OR_MISMATCH_CORRUPT",
            "UNKNOWN_MARKER_STATE_CORRUPT",
            "EXACT_NEW_ACTIVE_MARKER_IN_15",  # fenced may third
        ):
            # fenced state 3 → THIRD in write-set classifier
            if "THIRD" not in third_e["classification"] and third_e[
                "classification"
            ] not in ("THIRD_OR_MISMATCH_CORRUPT",):
                pass
        if third_e["classification"] != "THIRD_OR_MISMATCH_CORRUPT":
            # marker state 3: pure_new path with bad state
            if third_e["classification"] not in (
                "THIRD_OR_MISMATCH_CORRUPT",
                "UNKNOWN_MARKER_STATE_CORRUPT",
            ):
                raise AuthorityError(
                    f"{role_name} third independent {third_e['classification']}"
                )


def run_repaired_crc_digest_adversarial(document: dict[str, Any]) -> int:
    """Repaired CRC/digest must fail independent authority."""
    import copy

    trials = 0
    # 1) repaired N6AL CRC (value image matches floor but CRC fixed wrongly later)
    bad = copy.deepcopy(document)
    inv = bad["atomic_batch_manifests"]["device_local_role_1"]["exact_inventory"]
    for e in inv:
        if int(e["member_kind"]) == 2:
            v = bytearray(bytes.fromhex(e["value_hex"]))
            v[-1] ^= 0x01  # CRC tail
            e["value_hex"] = bytes(v).hex()
            e["value_sha256"] = vfy.sha256(bytes(v)).hex()
            # also poison snapshot NEW members if present
            break
    trials += 1
    try:
        assert_independent_authority_closed(bad)
        raise AuthorityError("repaired AL CRC accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 2) repaired complete-key binding
    bad2 = copy.deepcopy(document)
    e0 = bad2["atomic_batch_manifests"]["device_local_role_1"]["exact_inventory"][0]
    ck = bytearray(bytes.fromhex(e0["complete_key_hex"]))
    ck[8] ^= 1
    e0["complete_key_hex"] = bytes(ck).hex()
    trials += 1
    try:
        assert_independent_authority_closed(bad2)
        raise AuthorityError("repaired binding accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 3) repaired context digest in NEW snapshot only
    bad3 = copy.deepcopy(document)
    m0 = bad3["lifecycle"]["group_machine"]["snapshots"]["roles"][
        "device_local_role_1"
    ]["exact_new_pending_15"]["members"][0]
    cd = bytearray(bytes.fromhex(m0["context_digest_hex"]))
    cd[0] ^= 1
    m0["context_digest_hex"] = bytes(cd).hex()
    trials += 1
    try:
        assert_independent_authority_closed(bad3)
        raise AuthorityError("repaired context accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 4) repaired carrier primary digest
    bad4 = copy.deepcopy(document)
    bad4["carrier_transcript"]["primary_path"]["digest_hex"] = "00" * 32
    trials += 1
    try:
        assert_independent_authority_closed(bad4)
        raise AuthorityError("repaired carrier digest accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 5) coherent per-row OLD presence/count drift.
    bad5 = copy.deepcopy(document)
    row = bad5["lifecycle"]["group_machine"]["snapshots"]["roles"][
        "device_local_role_1"
    ]["write_set_rows"][0]
    row["old_present"] = not row["old_present"]
    trials += 1
    try:
        assert_independent_authority_closed(bad5)
        raise AuthorityError("coherent OLD-row drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 6) dependency readiness invented without upstream acceptance.
    bad6 = copy.deepcopy(document)
    bad6["prerequisites"]["dependency_readiness"][
        "pa_may_claim_dependency_ready"
    ] = True
    trials += 1
    try:
        assert_independent_authority_closed(bad6)
        raise AuthorityError("invented dependency readiness accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 7) suite-3 message_4 removed while booleans remain true.
    bad7 = copy.deepcopy(document)
    bad7["edhoc_attempts"]["attempts"]["suite_3"]["messages"].pop()
    trials += 1
    try:
        assert_independent_authority_closed(bad7)
        raise AuthorityError("missing suite3 message4 accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 8) NAR outcome coherently relabelled without changing packet execution.
    bad8 = copy.deepcopy(document)
    bad8["nar1_reassembly"]["cases"]["reordered_success"][
        "outcome"
    ] = "DISCARDED_MIXED_TUPLE"
    trials += 1
    try:
        assert_independent_authority_closed(bad8)
        raise AuthorityError("NAR coherent outcome drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 9) NAS short EOF claimed delivered.
    bad9 = copy.deepcopy(document)
    bad9["nas1_stream_lifecycle"]["cases"]["short_eof_close"].update(
        {"outcome": "DELIVERED", "delivery_count": 1}
    )
    trials += 1
    try:
        assert_independent_authority_closed(bad9)
        raise AuthorityError("NAS lifecycle drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 10) preauth owner key drops source locator.
    bad10 = copy.deepcopy(document)
    bad10["preauth_owner"]["owner_key_fields"] = bad10["preauth_owner"][
        "owner_key_fields"
    ][1:]
    trials += 1
    try:
        assert_independent_authority_closed(bad10)
        raise AuthorityError("preauth source-key drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 11) PA steals an Accepted multi-parent magic.
    bad11 = copy.deepcopy(document)
    bad11["magic_registry"]["pa_allocations"]["NPA1"] = (
        "PRODUCTION_ATTACHMENT_COLLISION"
    )
    trials += 1
    try:
        assert_independent_authority_closed(bad11)
        raise AuthorityError("magic collision drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 12) coherent 10k summary drift.
    bad12 = copy.deepcopy(document)
    bad12["lifecycle"]["group_machine"]["snapshots"]["reattach_10k_restart"][
        "final_floors"
    ][0] += 1
    trials += 1
    try:
        assert_independent_authority_closed(bad12)
        raise AuthorityError("10k restart drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 13) exact 2 s refill boundary moved just before the boundary while the
    # transcript still claims allocation.
    bad13 = copy.deepcopy(document)
    refill_row = next(
        row
        for row in bad13["preauth_owner"]["transitions"]
        if row["scenario"] == "TOKEN_REFILL_BOUNDARY"
        and row["at_ms"] == 2_000
    )
    refill_row["at_ms"] = 1_999
    trials += 1
    try:
        assert_independent_authority_closed(bad13)
        raise AuthorityError("preauth refill boundary drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 14) conflicting duplicate silently changed into an exact duplicate.
    bad14 = copy.deepcopy(document)
    conflict_row = next(
        row
        for row in bad14["preauth_owner"]["transitions"]
        if row["expected"]["result"]
        == "CONFLICTING_DUPLICATE_TERMINAL_DISCARD"
    )
    conflict_row["fragment_payload_variant"] = "F0"
    conflict_row["fragment_payload_hex"] = next(
        row["fragment_payload_hex"]
        for row in bad14["preauth_owner"]["transitions"]
        if row["fragment_payload_variant"] == "F0"
    )
    trials += 1
    try:
        assert_independent_authority_closed(bad14)
        raise AuthorityError("preauth duplicate/conflict drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 15) existing scratch receives a current rather than expired bucket.
    bad15 = copy.deepcopy(document)
    older_row = next(
        row
        for row in bad15["preauth_owner"]["transitions"]
        if row["expected"]["result"]
        == "COOKIE_BUCKET_EXPIRED_TERMINAL_DISCARD"
    )
    older_row["cookie_bucket"] = bad15["preauth_owner"][
        "current_cookie_bucket"
    ]
    trials += 1
    try:
        assert_independent_authority_closed(bad15)
        raise AuthorityError("preauth older-bucket drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    # 16) claimed branch coverage may not omit an actually executed branch.
    bad16 = copy.deepcopy(document)
    bad16["preauth_owner"]["branch_coverage"]["TOKEN_CAPACITY_DENY"] = 0
    trials += 1
    try:
        assert_independent_authority_closed(bad16)
        raise AuthorityError("preauth branch-coverage drift accepted")
    except AuthorityError as err:
        if "accepted" in str(err):
            raise

    return trials
