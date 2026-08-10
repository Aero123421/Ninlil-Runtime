#!/usr/bin/env python3
"""Independent gate for the Proposed Production Attachment vector.

Primary machine authority is full closed-tree equality against the independent
canonical expected model (spec constants / layouts / preimage formulas).
Descriptive prose (reason/note) is the only allowlisted free surface.
Executable adversarial probes remain for cases not expressible as static
tree drift. Does not import production runtime/codec code.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import re
import sys
from pathlib import Path
from typing import Any

_TOOLS_DIR = Path(__file__).resolve().parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from production_attachment_edhoc_schema_authority import (  # noqa: E402
    OBJECT_PATH_COUNT_EXACT,
    REQUIRED_GATE_CASES_EXACT,
    SchemaError,
    assert_closed_key_schema,
    assert_envelope,
    mutate_all_metadata_coherent,
    run_all_object_path_unknown_key_probe,
)
from production_attachment_edhoc_expected_model import (  # noqa: E402
    ExpectedModelError,
    assert_canonical_serialization_match,
    assert_document_matches_expected,
    build_expected_document,
    run_machine_leaf_mutation_campaign,
)

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "spec/vectors/production-attachment-edhoc-v1.json"

REQUIRED_CASES = {
    "NAC1-SUITE2-MESSAGE1",
    "NAC1-SUITE3-MESSAGE1",
    "NAS1-USB-STREAM-RECORD",
    "COOKIE-CURRENT-BUCKET-CURRENT-SECRET",
    "COOKIE-PREVIOUS-BUCKET-PREVIOUS-SECRET",
    "COOKIE-FOUR-COMBINATION-MATRIX",
    "COOKIE-SOURCE-CARRIER-SESSION-MUTATION",
    "COOKIE-RESPONSE-EXACT-2-FRAGMENT-SCRATCH",
    "COOKIE-RESPONSE-EXACT-LENGTH-159",
    "PROTECTED-PROPOSE-INSTALL-DUAL-CONFIRM-SEQUENCE",
    "NAC1-INSTALL-MAX-RADIO-FRAGMENTATION",
    "NAC1-CRC-MUTATION",
    "NAC1-RESERVED-MUTATION",
    "NAC1-LENGTH-MUTATION",
    "NAC1-SESSION-MUTATION",
    "NAC1-BINDING-MUTATION",
    "NAR1-CRC-MUTATION",
    "NAR1-INDEX-MUTATION",
    "NAR1-OFFSET-MUTATION",
    "NAR1-DIGEST-MUTATION",
    "NAR1-REORDER-DUPLICATE-LOSS",
    "NAR1-CANONICAL-FRAGMENT-SHAPE",
    "NAR1-SESSION-GENERATION-BINDING-DIVERGENCE",
    "NAR1-EXCHANGE-GENERATION-BINDING",
    "NAR1-MIXED-FRAGMENT-TUPLE",
    "CARRIER-BINDING-DERIVATION-PINNED",
    "CARRIER-TRANSCRIPT-BYTE-EXACT",
    "CARRIER-TRANSCRIPT-NEGATIVES",
    "WIFI-BINDING-INPUT-MUTATION",
    "N6AT-CRC-MUTATION",
    "N6AT-RESERVED-BYTES",
    "N6AT-ROLE-KEY-VALUE-MISMATCH",
    "N6AT-UNKNOWN-STATE",
    "N6AT-ROLE-SPECIFIC-BOTH",
    "NAB1-EXACT-15-MEMBER-SET-BOTH-ROLES",
    "NAB1-EXACT-KEY-IDENTITY-INVENTORY",
    "NAB1-CANONICAL-COMPLETE-KEY-ORDER",
    "NAB1-DUPLICATE-MISSING-SUBSTITUTED",
    "NAB1-REORDER-CONTEXT-SUBSTITUTION",
    "NAB1-CRC-COUNT-ROLE-MUTATION",
    "N6AT-PENDING-MARKER",
    "N6AT-PENDING-TO-ACTIVE",
    "N6AT-COMMIT-UNKNOWN-OLD-NEW-THIRD",
    "LIFECYCLE-15-KEY-GROUP-MACHINE",
    "PUBLICATION-ZERO-BEFORE-DUAL-CONFIRM",
    "CREDENTIAL-RPK-CCS-KID",
    "CREDENTIAL-CCS-CBOR-DECODE",
    "CREDENTIAL-TAIL-MUTATION",
    "NAP-NAI-CONTEXT-MISMATCH",
    "PROFILE-METHOD-SUITE-MESSAGE4-EAD",
    "PROPOSAL-MEMBERSHIP-LEASE-AUTHORITY-FIELDS",
    "RFC9529-INDEPENDENT-CONSTANTS",
    "BYTE-PLUS-SHA-MUTATION",
    "EXPORTER-LABEL-SET-EXACT",
    "EXPORTER-CONTEXT-ONE-BYTE-MUTATION",
    "CONTROL-NONCE-SEQUENCE-DIRECTION-EXACT",
    "RFC9529-REFERENCE-DIGESTS",
    "GATE-SELF-TEST",
    "PA-REATTACH-15ROW-OLD-NEW-STABLE-THIRD",
    "PA-REATTACH-LANE-OLD-NONEMPTY",
    "PA-REATTACH-10K-RESTART-MONOTONIC",
    "PA-PREREQ-FACTORY-MEMBERSHIP-LOCAL-KEY",
    "PA-LOCAL-KEY-MISMATCH-ROLLBACK-REENTRY",
    "PA-EDHOC-SUITE2-M1-M4",
    "PA-EDHOC-SUITE3-M1-M4",
    "PA-EDHOC-EAD1-EAD4-TERMINAL",
    "PA-EDHOC-DOWNGRADE-NO-AUTORETRY",
    "PA-NAR-REORDER-SUCCESS",
    "PA-NAR-DUPLICATE-NO-PROGRESS",
    "PA-NAR-CONFLICT-GAP-OVERLAP-MIXED-TIMEOUT",
    "PA-PREAUTH-SOURCE-QUOTA-IDLE-BUCKET",
    "PA-MAGIC-GLOBAL-UNIQUE",
    "PA-NAS-PARTIAL-SHORT-TRAILING-FUTURE-INNER",
    "PA-INDEPENDENT-COHERENT-DRIFT-REJECT",
}

# Independent P-256 affine pins (not taken from vector field trust alone).
P256_INITIATOR_X = bytes.fromhex(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
)
P256_INITIATOR_Y = bytes.fromhex(
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
P256_RESPONDER_X = bytes.fromhex(
    "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
)
P256_RESPONDER_Y = bytes.fromhex(
    "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4467992"
)

# Independent RFC 9529 §3 method-3/suite-2 message pins (not derived from vector).
RFC9529_MESSAGES = {
    "message_1": bytes.fromhex(
        "0382060258208af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b637"
    ),
    "message_2": bytes.fromhex(
        "582b419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5"
        "9862a1eef9e0e7e1886fcd"
    ),
    "message_3": bytes.fromhex(
        "52e562097bc417dd5919485ac7891ffd90a9fc"
    ),
    "message_4": bytes.fromhex("4828c966b7ca304f83"),
}

LABELS = {
    "attach_i2r_key16": 32768,
    "attach_r2i_key16": 32769,
    "attach_i2r_iv13": 32770,
    "attach_r2i_iv13": 32771,
    "hop_ir_secret32": 32772,
    "hop_ri_secret32": 32773,
    "e2e_ir_secret32": 32774,
    "e2e_ri_secret32": 32775,
}

# Independent normative pin from docs/35 (not taken from the vector alone).
COOKIE_TIME_BUCKET_SECONDS = 2


class GateError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise GateError(message)


def hx(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        fail(f"{field}: non-even hex")
    if value.lower() != value or any(c not in "0123456789abcdef" for c in value):
        fail(f"{field}: non-canonical hex")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise GateError(f"{field}: invalid hex") from error


def exact_int(value: Any, field: str) -> int:
    """Reject bool and non-int coercions (bool subclasses int in Python)."""
    if type(value) is not int:
        fail(f"{field}: expected exact int, got {type(value).__name__}")
    return value


def exact_bool(value: Any, field: str) -> bool:
    if type(value) is not bool:
        fail(f"{field}: expected exact bool, got {type(value).__name__}")
    return value


def exact_str(value: Any, field: str) -> str:
    if type(value) is not str:
        fail(f"{field}: expected exact str, got {type(value).__name__}")
    return value


def require_keys(obj: Any, field: str, required: set[str]) -> dict[str, Any]:
    if not isinstance(obj, dict):
        fail(f"{field}: expected object")
    missing = required - set(obj.keys())
    if missing:
        fail(f"{field}: missing required keys {sorted(missing)}")
    return obj


def _reject_non_integer_numbers(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_non_integer_numbers(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_non_integer_numbers(child, f"{path}[{index}]")
    elif type(value) is float:
        fail(f"non-integer json number forbidden at {path}: {value}")


def reject_forbidden_json_number_lexemes(text: str) -> None:
    """Lexical number grammar parity with Node: no NaN/Infinity/+0/-0/leading-zero."""
    if re.search(r"\bNaN\b|\bInfinity\b|\b-Infinity\b", text):
        fail("json constant forbidden")
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == '"':
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            continue
        if c in "0123456789+-" or (c == "." and i + 1 < n and text[i + 1].isdigit()):
            # Only treat as number token when not part of identifier/key (keys are quoted).
            start = i
            if text[i] in "+-":
                i += 1
            num_start = i
            if i < n and text[i] == "0":
                i += 1
                if i < n and text[i].isdigit():
                    fail("json number leading zero")
            elif i < n and text[i] in "123456789":
                while i < n and text[i].isdigit():
                    i += 1
            else:
                # lone + / - not a number token
                i = start + 1
                continue
            if i < n and text[i] == ".":
                fail("json non-integer number forbidden")
            if i < n and text[i] in "eE":
                fail("json exponent forbidden for strict int")
            lexeme = text[start:i]
            if lexeme in ("+0", "-0", "+", "-"):
                fail(f"json non-canonical zero/sign: {lexeme}")
            if lexeme.startswith("+"):
                fail("json number leading + forbidden")
            continue
        i += 1


def load_json_strict(path: Path) -> dict[str, Any]:
    """Parse JSON rejecting duplicate object keys (last-wins is forbidden)."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                fail(f"duplicate JSON key: {key}")
            # bool is a subclass of int; reject as object-pair value only when
            # later typed — keep decode here, type-check in schema.
            out[key] = value
        return out

    try:
        text = path.read_text(encoding="utf-8")
        reject_forbidden_json_number_lexemes(text)
        document = json.loads(text, object_pairs_hook=object_pairs)
    except json.JSONDecodeError as error:
        raise GateError(f"json: {error}") from error
    if not isinstance(document, dict):
        fail("root object")
    _reject_non_integer_numbers(document)
    return document


def _closed(
    obj: Any,
    path: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    """Exact closed object: required present, no unknown keys, optional allowed."""
    if not isinstance(obj, dict):
        fail(f"{path}: expected object")
    opt = optional or set()
    keys = set(obj.keys())
    missing = required - keys
    if missing:
        fail(f"{path}: missing keys {sorted(missing)}")
    unknown = keys - required - opt
    if unknown:
        fail(f"{path}: unknown keys {sorted(unknown)}")
    return obj


def _arr(obj: Any, path: str) -> list[Any]:
    if not isinstance(obj, list):
        fail(f"{path}: expected array")
    return obj


def validate_closed_schema(document: dict[str, Any]) -> None:
    """Independent hard-coded recursive closed schema (not self-authorizing)."""
    # Full recursive closed-key walk over every object/array-member path.
    try:
        assert_closed_key_schema(document, root=ROOT)
    except SchemaError as error:
        fail(str(error))
    root = document
    if list(root["required_gate_cases"]) != list(REQUIRED_GATE_CASES_EXACT):
        fail("$.required_gate_cases authority pin")

    limits = _closed(
        root["limits"],
        "$.limits",
        required={
            "nac1_header_bytes",
            "nac1_payload_max",
            "nac1_record_max",
            "nas1_header_bytes",
            "nas1_record_max",
            "nar1_profile",
            "nar1_header_bytes",
            "nar1_packet_max",
            "nar1_fragment_payload_max",
            "nar1_fragment_count_max",
            "nap1_bytes",
            "nai1_bytes",
            "nax1_bytes",
            "nat1_bytes",
            "nab1_header_bytes",
            "nab1_entry_bytes",
            "nab1_entry_count",
            "nab1_total_bytes",
            "n6at_key_bytes",
            "n6at_value_bytes",
        },
    )
    for k, v in limits.items():
        exact_int(v, f"$.limits.{k}")

    profile = _closed(
        root["profile"],
        "$.profile",
        required={
            "method",
            "mandatory_suites",
            "automatic_suite_downgrade_allowed",
            "message_4_required",
            "ead_allowed",
            "credential",
            "control_aead",
            "exporter_labels",
        },
    )
    exact_int(profile["method"], "$.profile.method")
    exact_bool(
        profile["automatic_suite_downgrade_allowed"],
        "$.profile.automatic_suite_downgrade_allowed",
    )
    exact_bool(profile["message_4_required"], "$.profile.message_4_required")
    exact_bool(profile["ead_allowed"], "$.profile.ead_allowed")
    exact_str(profile["credential"], "$.profile.credential")
    aead = _closed(
        profile["control_aead"],
        "$.profile.control_aead",
        required={"name", "cose_algorithm", "key_bytes", "iv_bytes", "tag_bytes"},
    )
    exact_str(aead["name"], "aead.name")
    for k in ("cose_algorithm", "key_bytes", "iv_bytes", "tag_bytes"):
        exact_int(aead[k], f"aead.{k}")
    labels = _closed(
        profile["exporter_labels"],
        "$.profile.exporter_labels",
        required={
            "attach_i2r_key16",
            "attach_r2i_key16",
            "attach_i2r_iv13",
            "attach_r2i_iv13",
            "hop_ir_secret32",
            "hop_ri_secret32",
            "e2e_ir_secret32",
            "e2e_ri_secret32",
        },
    )
    for k, v in labels.items():
        exact_int(v, f"exporter.{k}")
    suites = _closed(
        profile["mandatory_suites"],
        "$.profile.mandatory_suites",
        required={"2", "3"},
    )
    for sk in ("2", "3"):
        arr = _arr(suites[sk], f"suite.{sk}")
        if any(type(x) is not int or isinstance(x, bool) for x in arr):
            fail(f"suite.{sk} ints")

    rfc = _closed(
        root["rfc9529_method3_suite2_reference"],
        "$.rfc9529",
        required={
            "source",
            "method",
            "selected_suite",
            "profile_acceptance",
            "reason",
            "messages",
        },
    )
    exact_str(rfc["source"], "rfc.source")
    exact_int(rfc["method"], "rfc.method")
    exact_int(rfc["selected_suite"], "rfc.selected_suite")
    exact_bool(rfc["profile_acceptance"], "rfc.profile_acceptance")
    exact_str(rfc["reason"], "rfc.reason")
    msgs = _closed(
        rfc["messages"],
        "$.rfc.messages",
        required={"message_1", "message_2", "message_3", "message_4"},
    )
    for name, item in msgs.items():
        mi = _closed(
            item, f"rfc.{name}", required={"hex", "length", "sha256"}
        )
        exact_str(mi["hex"], f"rfc.{name}.hex")
        exact_int(mi["length"], f"rfc.{name}.length")
        exact_str(mi["sha256"], f"rfc.{name}.sha256")
        if name == "message_1":
            raw = hx(mi["hex"], "rfc.m1")
            if not raw or raw[0] != 0x03:
                fail("rfc.message_1 method byte pin 0x03")
            if raw[0] == 0x04:
                fail("rfc.message_1 03→04 drift")

    for suite_name in ("suite_2", "suite_3"):
        pass
    edhoc = _closed(
        root["edhoc_message_1"], "$.edhoc_message_1", required={"suite_2", "suite_3"}
    )
    for sn in ("suite_2", "suite_3"):
        s = _closed(
            edhoc[sn], f"edhoc.{sn}", required={"hex", "length", "sha256", "nac1_hex"}
        )
        exact_str(s["hex"], f"edhoc.{sn}.hex")
        exact_int(s["length"], f"edhoc.{sn}.length")
        exact_str(s["sha256"], f"edhoc.{sn}.sha256")
        exact_str(s["nac1_hex"], f"edhoc.{sn}.nac1_hex")

    stream = _closed(
        root["stream_wrapper"],
        "$.stream_wrapper",
        required={"usb_nas1_hex", "usb_nas1_length", "usb_nas1_sha256"},
    )
    exact_str(stream["usb_nas1_hex"], "stream.hex")
    exact_int(stream["usb_nas1_length"], "stream.len")
    exact_str(stream["usb_nas1_sha256"], "stream.sha")

    cookie = _closed(
        root["stateless_cookie"],
        "$.stateless_cookie",
        required={
            "time_bucket_seconds",
            "time_bucket",
            "current_secret_hex",
            "previous_secret_hex",
            "source_locator_digest_hex",
            "canonical_input_hex",
            "current_cookie_hex",
            "previous_bucket_previous_secret_cookie_hex",
            "challenge_nac1_hex",
            "response_nac1_hex",
            "response_nac1_length",
            "response_payload_hex",
            "response_payload_length",
            "response_length_formula",
            "response_length_parts",
            "response_fragment_count",
            "response_radio_fragments",
            "secret_bucket_matrix",
            "identity_or_authentication_claimed",
        },
    )
    exact_int(cookie["time_bucket_seconds"], "cookie.tbs")
    exact_int(cookie["time_bucket"], "cookie.tb")
    exact_int(cookie["response_nac1_length"], "cookie.rlen")
    exact_int(cookie["response_payload_length"], "cookie.plen")
    exact_int(cookie["response_fragment_count"], "cookie.fc")
    exact_bool(
        cookie["identity_or_authentication_claimed"], "cookie.identity_claim"
    )
    exact_str(cookie["response_length_formula"], "cookie.formula")
    for hk in (
        "current_secret_hex",
        "previous_secret_hex",
        "source_locator_digest_hex",
        "canonical_input_hex",
        "current_cookie_hex",
        "previous_bucket_previous_secret_cookie_hex",
        "challenge_nac1_hex",
        "response_nac1_hex",
        "response_payload_hex",
    ):
        exact_str(cookie[hk], f"cookie.{hk}")
    parts = _closed(
        cookie["response_length_parts"],
        "cookie.parts",
        required={
            "nac1_header_bytes",
            "cookie_bytes",
            "original_message_1_length_u16be_bytes",
            "original_message_1_bytes",
            "total_bytes",
        },
    )
    for k, v in parts.items():
        exact_int(v, f"cookie.parts.{k}")
    for frag in _arr(cookie["response_radio_fragments"], "cookie.frags"):
        f = _closed(
            frag, "cookie.frag", required={"index", "length", "hex", "sha256"}
        )
        exact_int(f["index"], "frag.i")
        exact_int(f["length"], "frag.l")
        exact_str(f["hex"], "frag.h")
        exact_str(f["sha256"], "frag.s")
    matrix = _closed(
        cookie["secret_bucket_matrix"],
        "cookie.matrix",
        required={
            "current_secret_x_current_bucket",
            "current_secret_x_previous_bucket",
            "previous_secret_x_current_bucket",
            "previous_secret_x_previous_bucket",
        },
    )
    for mk, mv in matrix.items():
        cell = _closed(
            mv,
            f"cookie.matrix.{mk}",
            required={
                "secret_name",
                "time_bucket",
                "canonical_input_hex",
                "cookie_hex",
            },
        )
        exact_str(cell["secret_name"], "matrix.sn")
        exact_int(cell["time_bucket"], "matrix.tb")
        exact_str(cell["canonical_input_hex"], "matrix.ci")
        exact_str(cell["cookie_hex"], "matrix.ch")

    install = _closed(
        root["attachment_install"],
        "$.attachment_install",
        required={
            "nap1_hex",
            "nap1_length",
            "nap1_sha256",
            "nai1_hex",
            "nai1_length",
            "nai1_sha256",
            "nax1_hex",
            "nax1_length",
            "nat1_hex",
            "nat1_length",
            "install_digest",
            "install_fields",
            "proposal_fields",
            "records",
            "protection_nonces",
            "attach_i2r_base_iv13_hex",
            "attach_r2i_base_iv13_hex",
            "protection_exporter_context_digest",
            "traffic_exporter_context_digest",
            "install_nac1_aad_prefix_hex",
            "opaque_ciphertext_and_tag_length",
            "proposal_opaque_ciphertext_and_tag_length",
            "confirm_opaque_ciphertext_and_tag_length",
            "aead_vector_status",
        },
    )
    for hk in (
        "nap1_hex",
        "nap1_sha256",
        "nai1_hex",
        "nai1_sha256",
        "nax1_hex",
        "nat1_hex",
        "install_digest",
        "attach_i2r_base_iv13_hex",
        "attach_r2i_base_iv13_hex",
        "protection_exporter_context_digest",
        "traffic_exporter_context_digest",
        "install_nac1_aad_prefix_hex",
        "aead_vector_status",
    ):
        exact_str(install[hk], f"install.{hk}")
    for ik in (
        "nap1_length",
        "nai1_length",
        "nax1_length",
        "nat1_length",
        "opaque_ciphertext_and_tag_length",
        "proposal_opaque_ciphertext_and_tag_length",
        "confirm_opaque_ciphertext_and_tag_length",
    ):
        exact_int(install[ik], f"install.{ik}")
    iff = _closed(
        install["install_fields"],
        "install.fields",
        required={
            "attachment_id",
            "authority_id",
            "site_domain",
            "membership_epoch",
            "assignment_epoch",
            "attachment_epoch",
            "authority_term",
            "lease_epoch",
            "lease_clock_epoch",
            "lease_not_before_ms",
            "lease_expires_at_ms",
            "membership_grant_digest",
            "proposal_digest",
            "route_policy_digest",
            "carrier_transcript_digest",
            "initiator_stable_digest",
            "responder_stable_digest",
            "initiator_credential_generation",
            "responder_credential_generation",
            "credential_set_revision",
            "revocation_generation",
            "hop_context_ir",
            "hop_context_ri",
            "hop_key_generation_ir",
            "hop_key_generation_ri",
            "e2e_context_ir",
            "e2e_context_ri",
            "e2e_key_generation_ir",
            "e2e_key_generation_ri",
            "e2e_security_id",
            "e2e_security_epoch",
        },
    )
    for k, v in iff.items():
        if isinstance(v, str):
            exact_str(v, f"iff.{k}")
        else:
            exact_int(v, f"iff.{k}")
    pf = _closed(
        install["proposal_fields"],
        "install.proposal_fields",
        required={
            "proposal_id",
            "authority_id",
            "site_domain",
            "membership_epoch",
            "assignment_epoch",
            "authority_term",
            "membership_grant_digest",
            "initiator_stable_digest",
            "credential_set_revision",
            "revocation_generation",
            "device_hop_context_ri",
            "device_hop_min_key_generation_ri",
            "device_e2e_context_ri",
            "device_e2e_min_key_generation_ri",
            "e2e_security_id",
            "e2e_security_epoch",
        },
    )
    for k, v in pf.items():
        if isinstance(v, str):
            exact_str(v, f"pf.{k}")
        else:
            exact_int(v, f"pf.{k}")
    rec = _closed(
        install["records"],
        "install.records",
        required={
            "propose_seq5",
            "install_seq6",
            "confirm_device_seq7",
            "confirm_authority_seq8",
        },
    )
    for k, v in rec.items():
        exact_str(v, f"rec.{k}")
    nonces = _closed(
        install["protection_nonces"],
        "install.nonces",
        required={
            "propose_i2r_seq5",
            "install_r2i_seq6",
            "confirm_device_i2r_seq7",
            "confirm_authority_r2i_seq8",
        },
    )
    for k, v in nonces.items():
        exact_str(v, f"nonce.{k}")

    carriers = _closed(
        root["carrier_bindings"],
        "$.carrier_bindings",
        required={"usb", "wifi", "compact_radio"},
    )
    for cname, field_keys in (
        (
            "usb",
            {
                "label",
                "carrier_instance_id_hex",
                "peer_id_hex",
                "connection_generation",
                "accepted_carrier_config_digest_hex",
            },
        ),
        (
            "wifi",
            {
                "label",
                "carrier_instance_id_hex",
                "peer_session_id_hex",
                "peer_id_hex",
                "network_instance_id_hex",
                "connection_generation",
                "path_generation",
                "accepted_carrier_config_digest_hex",
            },
        ),
        (
            "compact_radio",
            {
                "label",
                "carrier_instance_id_hex",
                "channel_plan_digest_hex",
                "radio_epoch",
                "accepted_carrier_config_digest_hex",
            },
        ),
    ):
        c = _closed(
            carriers[cname],
            f"carrier.{cname}",
            required={
                "carrier_class",
                "canonical_input_hex",
                "digest_hex",
                "fields",
            },
        )
        exact_int(c["carrier_class"], f"carrier.{cname}.class")
        exact_str(c["canonical_input_hex"], f"carrier.{cname}.canon")
        exact_str(c["digest_hex"], f"carrier.{cname}.digest")
        fields = _closed(c["fields"], f"carrier.{cname}.fields", required=field_keys)
        for fk, fv in fields.items():
            if isinstance(fv, str):
                exact_str(fv, f"carrier.{cname}.{fk}")
            else:
                exact_int(fv, f"carrier.{cname}.{fk}")

    for frag in _arr(root["compact_radio_fragments"], "$.fragments"):
        f = _closed(frag, "frag", required={"index", "length", "hex", "sha256"})
        exact_int(f["index"], "frag.i")
        exact_int(f["length"], "frag.l")
        exact_str(f["hex"], "frag.h")
        exact_str(f["sha256"], "frag.s")

    cred = _closed(
        root["credentials"],
        "$.credentials",
        required={
            "type",
            "encoding",
            "curve",
            "cose_kty",
            "cose_crv",
            "initiator_kid_hex",
            "responder_kid_hex",
            "initiator_x_hex",
            "initiator_y_hex",
            "responder_x_hex",
            "responder_y_hex",
            "initiator_ccs_hex",
            "responder_ccs_hex",
            "initiator_ccs_sha256",
            "responder_ccs_sha256",
            "initiator_credential_digest_hex",
            "responder_credential_digest_hex",
            "resolver_key_input_hex",
            "resolver_key_sha256",
            "note",
        },
    )
    for k, v in cred.items():
        if k in ("cose_kty", "cose_crv"):
            exact_int(v, f"cred.{k}")
        else:
            exact_str(v, f"cred.{k}")

    marker = _closed(
        root["n6_attachment_marker"],
        "$.n6_attachment_marker",
        required={
            "local_role",
            "state",
            "state_name",
            "key_hex",
            "key_length",
            "value_hex",
            "value_length",
            "value_sha256",
        },
    )
    exact_int(marker["local_role"], "n6.role")
    exact_int(marker["state"], "n6.state")
    exact_str(marker["state_name"], "n6.sn")
    exact_str(marker["key_hex"], "n6.key")
    exact_int(marker["key_length"], "n6.kl")
    exact_str(marker["value_hex"], "n6.val")
    exact_int(marker["value_length"], "n6.vl")
    exact_str(marker["value_sha256"], "n6.vs")

    def inventory_entry(entry: Any, path: str) -> None:
        e = _closed(
            entry,
            path,
            required={
                "index",
                "identity",
                "member_kind",
                "direction",
                "lane",
                "local_side",
                "context_id",
                "key_generation",
                "key_bytes",
                "value_bytes",
                "layer_code",
                "complete_key_hex",
                "complete_key_length",
                "value_hex",
                "value_sha256",
                "context_digest_hex",
                "old_present",
                "old_value_hex",
                "old_value_sha256",
                "old_context_digest_hex",
                "old_new_relation",
            },
        )
        for k in (
            "index",
            "member_kind",
            "direction",
            "lane",
            "local_side",
            "context_id",
            "key_generation",
            "key_bytes",
            "value_bytes",
            "layer_code",
            "complete_key_length",
        ):
            exact_int(e[k], f"{path}.{k}")
        for k in (
            "identity",
            "complete_key_hex",
            "value_hex",
            "value_sha256",
            "context_digest_hex",
            "old_value_hex",
            "old_value_sha256",
            "old_context_digest_hex",
            "old_new_relation",
        ):
            exact_str(e[k], f"{path}.{k}")
        exact_bool(e["old_present"], f"{path}.old_present")

    def member_entry(entry: Any, path: str) -> None:
        e = _closed(
            entry,
            path,
            required={
                "index",
                "identity",
                "member_kind",
                "complete_key_hex",
                "complete_key_length",
                "value_hex",
                "value_sha256",
                "value_bytes",
                "context_digest_hex",
            },
        )
        for k in ("index", "member_kind", "complete_key_length", "value_bytes"):
            exact_int(e[k], f"{path}.{k}")
        for k in (
            "identity",
            "complete_key_hex",
            "value_hex",
            "value_sha256",
            "context_digest_hex",
        ):
            exact_str(e[k], f"{path}.{k}")

    def role_snap(snap: Any, path: str) -> None:
        s = _closed(
            snap,
            path,
            required={
                "exact_old",
                "exact_new_pending_15",
                "extra_16",
                "third_mismatch",
                "pending_to_active",
                "commit_unknown",
                "write_set_rows",
                "cu_row_classifier_cases",
                "publication_before_dual_confirm",
                *[f"partial_{n}" for n in range(1, 15)],
            },
        )
        exact_int(s["publication_before_dual_confirm"], f"{path}.pub")
        old0 = _closed(
            s["exact_old"],
            f"{path}.old0",
            required={
                "member_count",
                "present_complete_keys_hex",
                "members",
                "full_image_sha256",
                "classification",
                "commit_unknown_accepted",
                "observed_old_non_absent_count",
                "marker_absent",
            },
        )
        exact_int(old0["member_count"], f"{path}.old0.count")
        exact_int(
            old0["observed_old_non_absent_count"], f"{path}.old0.obs"
        )
        exact_str(old0["full_image_sha256"], f"{path}.old0.img")
        exact_str(old0["classification"], f"{path}.old0.cls")
        exact_bool(old0["commit_unknown_accepted"], f"{path}.old0.cu")
        exact_bool(old0["marker_absent"], f"{path}.old0.marker_absent")
        if not isinstance(old0["present_complete_keys_hex"], list) or not isinstance(
            old0["members"], list
        ):
            fail(f"{path}.old0 lists")
        if not isinstance(s["write_set_rows"], list) or len(s["write_set_rows"]) != 15:
            fail(f"{path}.write_set_rows")
        if (
            not isinstance(s["cu_row_classifier_cases"], list)
            or len(s["cu_row_classifier_cases"]) != 4
        ):
            fail(f"{path}.cu_row_classifier_cases")
        for n in range(1, 15):
            p = _closed(
                s[f"partial_{n}"],
                f"{path}.p{n}",
                required={
                    "member_count",
                    "present_complete_keys_hex",
                    "members",
                    "full_image_sha256",
                    "classification",
                    "commit_unknown_accepted",
                    "advanced_to_new_count",
                },
            )
            exact_int(p["member_count"], f"{path}.p{n}.c")
            exact_int(p["advanced_to_new_count"], f"{path}.p{n}.adv")
            exact_str(p["full_image_sha256"], f"{path}.p{n}.img")
            exact_str(p["classification"], f"{path}.p{n}.cls")
            exact_bool(p["commit_unknown_accepted"], f"{path}.p{n}.cu")
            for mi, m in enumerate(_arr(p["members"], f"{path}.p{n}.m")):
                member_entry(m, f"{path}.p{n}.m[{mi}]")
        new15 = _closed(
            s["exact_new_pending_15"],
            f"{path}.new15",
            required={
                "member_count",
                "present_complete_keys_hex",
                "present_keys_concat_sha256",
                "members",
                "full_image_sha256",
                "marker_state",
                "marker_value_hex",
                "classification",
                "commit_unknown_accepted",
                "value_substitution_rejected",
                "context_digest_substitution_rejected",
            },
        )
        exact_int(new15["member_count"], f"{path}.new15.c")
        exact_int(new15["marker_state"], f"{path}.new15.ms")
        exact_str(new15["present_keys_concat_sha256"], f"{path}.new15.pkc")
        exact_str(new15["full_image_sha256"], f"{path}.new15.img")
        exact_str(new15["marker_value_hex"], f"{path}.new15.mv")
        exact_str(new15["classification"], f"{path}.new15.cls")
        exact_bool(new15["commit_unknown_accepted"], f"{path}.new15.cu")
        for mi, m in enumerate(_arr(new15["members"], f"{path}.new15.m")):
            member_entry(m, f"{path}.new15.m[{mi}]")
        vs = _closed(
            new15["value_substitution_rejected"],
            f"{path}.vs",
            required={
                "members",
                "full_image_sha256",
                "classification",
                "commit_unknown_accepted",
                "mutated_index",
            },
        )
        exact_int(vs["mutated_index"], f"{path}.vs.idx")
        exact_str(vs["full_image_sha256"], f"{path}.vs.img")
        exact_str(vs["classification"], f"{path}.vs.cls")
        exact_bool(vs["commit_unknown_accepted"], f"{path}.vs.cu")
        for mi, m in enumerate(_arr(vs["members"], f"{path}.vs.m")):
            member_entry(m, f"{path}.vs.m[{mi}]")
        cds = _closed(
            new15["context_digest_substitution_rejected"],
            f"{path}.cds",
            required={
                "members",
                "full_image_sha256",
                "classification",
                "commit_unknown_accepted",
                "mutated_index",
            },
        )
        exact_int(cds["mutated_index"], f"{path}.cds.idx")
        exact_str(cds["full_image_sha256"], f"{path}.cds.img")
        exact_str(cds["classification"], f"{path}.cds.cls")
        exact_bool(cds["commit_unknown_accepted"], f"{path}.cds.cu")
        for mi, m in enumerate(_arr(cds["members"], f"{path}.cds.m")):
            member_entry(m, f"{path}.cds.m[{mi}]")
        extra = _closed(
            s["extra_16"],
            f"{path}.extra",
            required={
                "member_count",
                "foreign_complete_key_hex",
                "classification",
                "commit_unknown_accepted",
            },
        )
        exact_int(extra["member_count"], f"{path}.extra.c")
        exact_str(extra["foreign_complete_key_hex"], f"{path}.extra.fk")
        exact_str(extra["classification"], f"{path}.extra.cls")
        exact_bool(extra["commit_unknown_accepted"], f"{path}.extra.cu")
        third = _closed(
            s["third_mismatch"],
            f"{path}.third",
            required={
                "member_count",
                "marker_state",
                "marker_value_hex",
                "classification",
                "commit_unknown_accepted",
            },
        )
        exact_int(third["member_count"], f"{path}.third.c")
        exact_int(third["marker_state"], f"{path}.third.ms")
        exact_str(third["marker_value_hex"], f"{path}.third.mv")
        exact_str(third["classification"], f"{path}.third.cls")
        exact_bool(third["commit_unknown_accepted"], f"{path}.third.cu")
        p2a = _closed(
            s["pending_to_active"],
            f"{path}.p2a",
            required={
                "mutation_kind",
                "marker_key_hex",
                "old_state",
                "new_state",
                "old_value_hex",
                "new_value_hex",
                "old_value_sha256",
                "new_value_sha256",
                "accepted",
                "non_marker_rows_unchanged",
            },
        )
        exact_str(p2a["mutation_kind"], f"{path}.p2a.mk")
        exact_str(p2a["marker_key_hex"], f"{path}.p2a.mkh")
        exact_int(p2a["old_state"], f"{path}.p2a.os")
        exact_int(p2a["new_state"], f"{path}.p2a.ns")
        exact_str(p2a["old_value_hex"], f"{path}.p2a.ov")
        exact_str(p2a["new_value_hex"], f"{path}.p2a.nv")
        exact_str(p2a["old_value_sha256"], f"{path}.p2a.ovs")
        exact_str(p2a["new_value_sha256"], f"{path}.p2a.nvs")
        exact_bool(p2a["accepted"], f"{path}.p2a.acc")
        exact_bool(p2a["non_marker_rows_unchanged"], f"{path}.p2a.nm")
        cu = _closed(
            s["commit_unknown"],
            f"{path}.cu",
            required={
                "accepted_classifications",
                "accepted_snapshots",
                "rejected_snapshot_kinds",
                "active_marker_only",
            },
        )
        if not isinstance(cu["accepted_classifications"], list) or not isinstance(
            cu["accepted_snapshots"], list
        ) or not isinstance(cu["rejected_snapshot_kinds"], list):
            fail(f"{path}.cu lists")
        if any(type(x) is not str for x in cu["accepted_classifications"]):
            fail(f"{path}.cu.ac types")
        if any(type(x) is not str for x in cu["accepted_snapshots"]):
            fail(f"{path}.cu.as types")
        if any(type(x) is not str for x in cu["rejected_snapshot_kinds"]):
            fail(f"{path}.cu.rs types")
        amo = _closed(
            cu["active_marker_only"],
            f"{path}.amo",
            required={
                "marker_key_hex",
                "value_hex",
                "value_sha256",
                "classification",
                "commit_unknown_accepted",
            },
        )
        exact_str(amo["marker_key_hex"], f"{path}.amo.mk")
        exact_str(amo["value_hex"], f"{path}.amo.v")
        exact_str(amo["value_sha256"], f"{path}.amo.vs")
        exact_str(amo["classification"], f"{path}.amo.cls")
        exact_bool(amo["commit_unknown_accepted"], f"{path}.amo.cu")

    life = _closed(
        root["lifecycle"],
        "$.lifecycle",
        required={
            "roles",
            "pending_marker",
            "pending_to_active",
            "commit_unknown",
            "group_machine",
            "publication_before_dual_confirm",
        },
    )
    exact_int(life["publication_before_dual_confirm"], "life.pub")
    roles = _closed(
        life["roles"],
        "life.roles",
        required={"device_local_role_1", "authority_local_role_2"},
    )
    for rn in ("device_local_role_1", "authority_local_role_2"):
        role = _closed(
            roles[rn], f"life.roles.{rn}", required={"pending", "active", "fenced_third"}
        )
        for sn in ("pending", "active"):
            st = _closed(
                role[sn],
                f"life.roles.{rn}.{sn}",
                required={
                    "state",
                    "state_name",
                    "key_hex",
                    "value_hex",
                    "value_sha256",
                },
            )
            exact_int(st["state"], f"{rn}.{sn}.state")
            exact_str(st["state_name"], f"{rn}.{sn}.sn")
            exact_str(st["key_hex"], f"{rn}.{sn}.k")
            exact_str(st["value_hex"], f"{rn}.{sn}.v")
            exact_str(st["value_sha256"], f"{rn}.{sn}.vs")
        third = _closed(
            role["fenced_third"],
            f"life.roles.{rn}.third",
            required={
                "state",
                "state_name",
                "key_hex",
                "value_hex",
                "value_sha256",
                "accepted",
            },
        )
        exact_int(third["state"], f"{rn}.third.state")
        exact_str(third["state_name"], f"{rn}.third.sn")
        exact_str(third["key_hex"], f"{rn}.third.k")
        exact_str(third["value_hex"], f"{rn}.third.v")
        exact_str(third["value_sha256"], f"{rn}.third.vs")
        exact_bool(third["accepted"], f"{rn}.third.acc")
    pm = _closed(
        life["pending_marker"],
        "life.pm",
        required={
            "state",
            "state_name",
            "local_role",
            "key_hex",
            "value_hex",
            "value_sha256",
        },
    )
    exact_int(pm["state"], "pm.state")
    exact_str(pm["state_name"], "pm.sn")
    exact_int(pm["local_role"], "pm.role")
    exact_str(pm["key_hex"], "pm.k")
    exact_str(pm["value_hex"], "pm.v")
    exact_str(pm["value_sha256"], "pm.vs")
    p2a = _closed(
        life["pending_to_active"],
        "life.p2a",
        required={
            "mutation_kind",
            "old_state",
            "new_state",
            "old_value_hex",
            "new_value_hex",
            "old_value_sha256",
            "new_value_sha256",
        },
    )
    exact_str(p2a["mutation_kind"], "life.p2a.mk")
    exact_int(p2a["old_state"], "life.p2a.os")
    exact_int(p2a["new_state"], "life.p2a.ns")
    for k in (
        "old_value_hex",
        "new_value_hex",
        "old_value_sha256",
        "new_value_sha256",
    ):
        exact_str(p2a[k], f"life.p2a.{k}")
    cu = _closed(
        life["commit_unknown"],
        "life.cu",
        required={
            "old_pending_value_hex",
            "new_active_value_hex",
            "third_value_hex",
            "third_value_state",
            "third_value_accepted",
            "accepted_states",
            "accepted_classifications",
        },
    )
    exact_str(cu["old_pending_value_hex"], "life.cu.old")
    exact_str(cu["new_active_value_hex"], "life.cu.new")
    exact_str(cu["third_value_hex"], "life.cu.third")
    exact_int(cu["third_value_state"], "life.cu.tvs")
    exact_bool(cu["third_value_accepted"], "life.cu.tva")
    if not isinstance(cu["accepted_states"], list) or any(
        type(x) is not int or isinstance(x, bool) for x in cu["accepted_states"]
    ):
        fail("life.cu.accepted_states")
    if not isinstance(cu["accepted_classifications"], list) or any(
        type(x) is not str for x in cu["accepted_classifications"]
    ):
        fail("life.cu.accepted_classifications")
    gm = _closed(
        life["group_machine"],
        "life.gm",
        required={
            "member_count_exact",
            "old_count_is_protocol_constant",
            "observed_old_non_absent_count",
            "legal_nonempty_lane_old_required",
            "new_pending_member_count",
            "partial_member_counts_rejected",
            "extra_member_rejected",
            "third_value_or_digest_mismatch_rejected",
            "pending_to_active_single_key_full",
            "publication_before_dual_confirm",
            "role_attachment_id_must_match",
            "device_pending_key_hex",
            "device_pending_value_hex",
            "device_active_value_hex",
            "authority_pending_key_hex",
            "authority_pending_value_hex",
            "authority_active_value_hex",
            "device_complete_keys_concat_sha256",
            "authority_complete_keys_concat_sha256",
            "snapshots",
        },
    )
    for k in (
        "member_count_exact",
        "observed_old_non_absent_count",
        "new_pending_member_count",
        "publication_before_dual_confirm",
    ):
        exact_int(gm[k], f"gm.{k}")
    for k in (
        "extra_member_rejected",
        "third_value_or_digest_mismatch_rejected",
        "pending_to_active_single_key_full",
        "role_attachment_id_must_match",
        "old_count_is_protocol_constant",
        "legal_nonempty_lane_old_required",
    ):
        exact_bool(gm[k], f"gm.{k}")
    for k in (
        "device_pending_key_hex",
        "device_pending_value_hex",
        "device_active_value_hex",
        "authority_pending_key_hex",
        "authority_pending_value_hex",
        "authority_active_value_hex",
        "device_complete_keys_concat_sha256",
        "authority_complete_keys_concat_sha256",
    ):
        exact_str(gm[k], f"gm.{k}")
    if not isinstance(gm["partial_member_counts_rejected"], list) or any(
        type(x) is not int or isinstance(x, bool)
        for x in gm["partial_member_counts_rejected"]
    ):
        fail("gm.partial")
    snaps = _closed(
        gm["snapshots"],
        "gm.snaps",
        required={
            "classification_domain",
            "roles",
            "durability_model",
            "reattach_policy",
            "reattach_10k_restart",
        },
    )
    if not isinstance(snaps["classification_domain"], list) or any(
        type(x) is not str for x in snaps["classification_domain"]
    ):
        fail("gm.domain")
    if (
        exact_str(snaps["durability_model"], "gm.snaps.durability_model")
        != "WRITE_SET_OBSERVED_OLD_PROPOSED_NEW"
    ):
        fail("gm.snaps.durability_model pin")
    if exact_str(snaps["reattach_policy"], "gm.snaps.reattach_policy") != (
        "PER_ROW_OLD_PRESENT_WITH_LEGAL_LANE_OLD_AND_MARKER_ABSENT;"
        "MONOTONIC_FLOOR_HIGH_WATER;"
        "NO_ATTACHMENT_SCOPED_NAMESPACE"
    ):
        fail("gm.snaps.reattach_policy pin")
    sroles = _closed(
        snaps["roles"],
        "gm.roles",
        required={"device_local_role_1", "authority_local_role_2"},
    )
    role_snap(sroles["device_local_role_1"], "gm.device")
    role_snap(sroles["authority_local_role_2"], "gm.authority")

    manifests = _closed(
        root["atomic_batch_manifests"],
        "$.manifests",
        required={
            "status",
            "ordering",
            "device_local_role_1",
            "authority_local_role_2",
        },
    )
    exact_str(manifests["status"], "man.status")
    exact_str(manifests["ordering"], "man.ordering")
    for rn in ("device_local_role_1", "authority_local_role_2"):
        item = _closed(
            manifests[rn],
            f"man.{rn}",
            required={
                "hex",
                "length",
                "sha256",
                "complete_keys_concat_sha256",
                "full_image_sha256",
                "exact_inventory",
            },
        )
        exact_str(item["hex"], f"man.{rn}.hex")
        exact_int(item["length"], f"man.{rn}.len")
        exact_str(item["sha256"], f"man.{rn}.sha")
        exact_str(item["complete_keys_concat_sha256"], f"man.{rn}.ckc")
        exact_str(item["full_image_sha256"], f"man.{rn}.img")
        inv = _arr(item["exact_inventory"], f"man.{rn}.inv")
        if len(inv) != 15:
            fail(f"man.{rn}.inv count")
        for i, e in enumerate(inv):
            inventory_entry(e, f"man.{rn}.inv[{i}]")


def u16(value: bytes, offset: int) -> int:
    return int.from_bytes(value[offset : offset + 2], "big")


def u32(value: bytes, offset: int) -> int:
    return int.from_bytes(value[offset : offset + 4], "big")


def u64(value: bytes, offset: int) -> int:
    return int.from_bytes(value[offset : offset + 8], "big")


def sha(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def crc32c(value: bytes) -> int:
    crc = 0xFFFFFFFF
    for octet in value:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def validate_nac(
    record: bytes,
    field: str,
    *,
    kind: int | None = None,
    sequence: int | None = None,
    carrier: int | None = None,
) -> None:
    if len(record) < 88 or len(record) > 600 or record[:4] != b"NAC1":
        fail(f"{field}: NAC framing")
    version = u16(record, 4)
    if version != 1 or u16(record, 6) != 88:
        fail(f"{field}: NAC version/header")
    if u32(record, 8) != len(record) or u32(record, 12) != len(record) - 88:
        fail(f"{field}: NAC length")
    if not 1 <= record[16] <= 11 or record[17] != 0:
        fail(f"{field}: NAC kind/flags")
    if record[18] not in (1, 2, 3) or record[19] != 0:
        fail(f"{field}: NAC carrier/reserved")
    if not any(record[20:36]) or u64(record, 36) == 0 or any(record[48:52]):
        fail(f"{field}: NAC identity/reserved")
    if not any(record[52:84]):
        fail(f"{field}: NAC binding")
    scratch = bytearray(record)
    stored = u32(record, 84)
    scratch[84:88] = bytes(4)
    if crc32c(bytes(scratch)) != stored:
        fail(f"{field}: NAC CRC")
    expected_sequence = 0 if record[16] in (1, 2) else record[16] - 3
    if record[16] == 3:
        expected_sequence = u32(record, 44)
        if not 1 <= expected_sequence <= 8:
            fail(f"{field}: error sequence")
    if u32(record, 44) != expected_sequence:
        fail(f"{field}: NAC sequence matrix")
    if kind is not None and record[16] != kind:
        fail(f"{field}: expected kind")
    if sequence is not None and u32(record, 44) != sequence:
        fail(f"{field}: expected sequence")
    if carrier is not None and record[18] != carrier:
        fail(f"{field}: expected carrier")


def validate_nar(packet: bytes, field: str) -> None:
    if not 68 <= len(packet) <= 192 or packet[:4] != b"NAR1":
        fail(f"{field}: NAR framing")
    if packet[4] != 0x12 or packet[5] != 1 or u16(packet, 6) != 68:
        fail(f"{field}: NAR profile")
    if u16(packet, 8) != len(packet) or u16(packet, 10) != len(packet) - 68:
        fail(f"{field}: NAR packet length")
    payload = u16(packet, 10)
    complete = u16(packet, 40)
    index = packet[42]
    count = packet[43]
    expected_count = (complete + 123) // 124
    expected_payload = 124 if index + 1 < count else complete - index * 124
    if (
        not 88 <= complete <= 600
        or count != expected_count
        or not 1 <= count <= 5
        or index >= count
        or not 1 <= payload <= 124
        or payload != expected_payload
    ):
        fail(f"{field}: NAR index/count")
    if u32(packet, 60) != index * 124:
        fail(f"{field}: NAR offset")
    scratch = bytearray(packet)
    stored = u32(packet, 64)
    scratch[64:68] = bytes(4)
    if crc32c(bytes(scratch)) != stored:
        fail(f"{field}: NAR CRC")


def recompute_crc_n6at(value: bytearray) -> None:
    value[116:120] = crc32c(bytes(value[:116])).to_bytes(4, "big")


def recompute_crc_nab(batch: bytearray) -> None:
    batch[64:68] = bytes(4)
    batch[64:68] = crc32c(bytes(batch)).to_bytes(4, "big")


def decode_cbor_bstr(buf: bytes, offset: int) -> tuple[bytes, int]:
    if offset >= len(buf):
        fail("cbor bstr eof")
    initial = buf[offset]
    major = initial >> 5
    info = initial & 0x1F
    if major != 2:
        fail("cbor bstr major")
    offset += 1
    if info < 24:
        length = info
    elif info == 24:
        if offset >= len(buf):
            fail("cbor bstr len")
        length = buf[offset]
        offset += 1
    else:
        fail("cbor bstr length form")
    end = offset + length
    if end > len(buf):
        fail("cbor bstr overflow")
    return buf[offset:end], end


def decode_cbor_uint(buf: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(buf):
        fail("cbor uint eof")
    initial = buf[offset]
    major = initial >> 5
    info = initial & 0x1F
    offset += 1
    if major != 0:
        fail("cbor uint major")
    if info < 24:
        return info, offset
    if info == 24:
        if offset >= len(buf):
            fail("cbor uint len")
        return buf[offset], offset + 1
    fail("cbor uint form")
    raise AssertionError("unreachable")


def decode_cbor_nint(buf: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(buf):
        fail("cbor nint eof")
    initial = buf[offset]
    major = initial >> 5
    info = initial & 0x1F
    offset += 1
    if major != 1:
        fail("cbor nint major")
    if info < 24:
        return -1 - info, offset
    fail("cbor nint form")
    raise AssertionError("unreachable")


def decode_ccs_cose_key(ccs: bytes, field: str) -> dict[str, bytes | int]:
    """Independently decode exact CCS map {8:{1:COSE_Key}} for EC2/P-256."""

    if not ccs or ccs[0] == 0x4E or ccs[0] != 0xA1:
        fail(f"{field}: CCS must be CBOR map(1), not ASCII")
    if ccs[1] != 0x08:
        fail(f"{field}: CCS claim 8 (cnf) required")
    if ccs[2] != 0xA1 or ccs[3] != 0x01:
        fail(f"{field}: cnf must be map(1) with COSE_Key")
    if ccs[4] != 0xA5:
        fail(f"{field}: COSE_Key must be map(5)")
    offset = 5
    # kty = 2
    if ccs[offset : offset + 2] != bytes([0x01, 0x02]):
        fail(f"{field}: kty != EC2")
    offset += 2
    # kid
    if ccs[offset] != 0x02:
        fail(f"{field}: kid key")
    offset += 1
    kid, offset = decode_cbor_bstr(ccs, offset)
    if not 1 <= len(kid) <= 8:
        fail(f"{field}: kid length")
    # crv = -1 / 1
    nkey, offset = decode_cbor_nint(ccs, offset)
    if nkey != -1:
        fail(f"{field}: crv key")
    crv, offset = decode_cbor_uint(ccs, offset)
    if crv != 1:
        fail(f"{field}: crv != P-256")
    # x = -2
    nkey, offset = decode_cbor_nint(ccs, offset)
    if nkey != -2:
        fail(f"{field}: x key")
    x, offset = decode_cbor_bstr(ccs, offset)
    if len(x) != 32:
        fail(f"{field}: x length")
    # y = -3
    nkey, offset = decode_cbor_nint(ccs, offset)
    if nkey != -3:
        fail(f"{field}: y key")
    y, offset = decode_cbor_bstr(ccs, offset)
    if len(y) != 32:
        fail(f"{field}: y length")
    if offset != len(ccs):
        fail(f"{field}: CCS trailing bytes")
    return {"kid": kid, "x": x, "y": y, "kty": 2, "crv": 1}


def classify_write_set_value_image_independent(
    *,
    present_members: list[dict[str, Any]],
    old_members: list[dict[str, Any]],
    new_members: list[dict[str, Any]],
    write_set_keys_ordered: list[bytes],
    marker_key: bytes,
) -> str:
    """Per-row observed-OLD / proposed-NEW value-image CU (not key-count)."""

    write_set = list(write_set_keys_ordered)
    write_set_set = set(write_set)
    if len(write_set) != 15 or len(write_set_set) != 15:
        return "UNCLASSIFIED_CORRUPT"
    present_map: dict[bytes, tuple[bytes, bytes]] = {}
    for m in present_members:
        k = hx(m["complete_key_hex"], "present ck")
        if k in present_map:
            return "DUPLICATE_KEYS_CORRUPT"
        present_map[k] = (
            hx(m["value_hex"], "present val"),
            hx(m["context_digest_hex"], "present ctx"),
        )
    for k in present_map:
        if k not in write_set_set:
            return "FOREIGN_OR_EXTRA_CORRUPT"
    old_map = {
        hx(m["complete_key_hex"], "old ck"): (
            hx(m["value_hex"], "old val"),
            hx(m["context_digest_hex"], "old ctx"),
        )
        for m in old_members
    }
    new_map = {
        hx(m["complete_key_hex"], "new ck"): (
            hx(m["value_hex"], "new val"),
            hx(m["context_digest_hex"], "new ctx"),
        )
        for m in new_members
    }
    if len(new_map) != 15:
        return "UNCLASSIFIED_CORRUPT"
    pure_new = 0
    pure_old = 0
    third = 0
    for k in write_set:
        old_v = old_map.get(k)
        new_v = new_map[k]
        got = present_map.get(k)
        matches_old = got == old_v
        matches_new = got is not None and got == new_v
        if matches_old and matches_new:
            continue
        if matches_new:
            pure_new += 1
        elif matches_old:
            pure_old += 1
        else:
            third += 1
    if third:
        return "THIRD_OR_MISMATCH_CORRUPT"
    if pure_new == 0:
        return "EXACT_OLD"
    if pure_old == 0:
        marker_pair = present_map.get(marker_key)
        if marker_pair is None:
            return "MISSING_MARKER_CORRUPT"
        state = marker_pair[0][8]
        if state == 1:
            return "EXACT_NEW_PENDING_15"
        if state == 2:
            return "EXACT_NEW_ACTIVE_MARKER_IN_15"
        if state == 3:
            return "THIRD_OR_MISMATCH_CORRUPT"
        return "UNKNOWN_MARKER_STATE_CORRUPT"
    if 1 <= pure_new <= 14:
        return f"PARTIAL_{pure_new}_CORRUPT"
    return "UNCLASSIFIED_CORRUPT"


def classify_group_snapshot_independent(
    *,
    present_keys: list[bytes],
    expected_keys_ordered: list[bytes],
    marker_key: bytes,
    marker_state: int | None,
    marker_value_ok: bool,
) -> str:
    """Key-presence helper for EXTRA only — not CU EXACT_OLD authority."""

    expected_set = set(expected_keys_ordered)
    present_set = set(present_keys)
    count = len(present_keys)
    if count != len(present_set):
        return "DUPLICATE_KEYS_CORRUPT"
    if count == 0:
        # Must not be used as re-attach EXACT_OLD (observed OLD may be non-empty).
        return "EXACT_OLD_COLD_OR_EMPTY_PRESENT"
    if not present_set.issubset(expected_set):
        return "FOREIGN_OR_EXTRA_CORRUPT"
    if count > 15:
        return "EXTRA_CORRUPT"
    if 1 <= count <= 14:
        return f"KEY_PRESENCE_PARTIAL_{count}_NOT_VALUE_IMAGE"
    if count == 15 and present_set == expected_set:
        if marker_key not in present_set:
            return "MISSING_MARKER_CORRUPT"
        if not marker_value_ok:
            return "THIRD_OR_MISMATCH_CORRUPT"
        if marker_state == 1:
            return "EXACT_NEW_PENDING_15"
        if marker_state == 2:
            return "EXACT_NEW_ACTIVE_MARKER_IN_15"
        if marker_state == 3:
            return "THIRD_OR_MISMATCH_CORRUPT"
        return "UNKNOWN_MARKER_STATE_CORRUPT"
    return "UNCLASSIFIED_CORRUPT"


# Independent N6 codec value authority (docs/30; not synthetic VALUE-V1).
_N6_MAGIC_TX = 0x4E365458
_N6_MAGIC_RX = 0x4E365258
_N6_MAGIC_HW = 0x4E364857
_N6_MAGIC_AL = 0x4E36414C


def _pa_put_u16(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 2] = int(value).to_bytes(2, "big")


def _pa_put_u32(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 4] = int(value).to_bytes(4, "big")


def _pa_put_u64(buf: bytearray, off: int, value: int) -> None:
    buf[off : off + 8] = int(value).to_bytes(8, "big")


def materialize_member_value_independent(
    *,
    member_kind: int,
    complete_key: bytes,
    install_digest: bytes,
    value_length: int,
    marker_value: bytes | None,
    local_side: int = 0,
    key_generation: int = 1,
    membership_epoch: int = 11,
    phase: str = "new",
    peer_node_id: bytes | None = None,
    local_node_id: bytes | None = None,
    context_id: int = 0,
    layer_code: int = 0,
) -> bytes:
    """Canonical N6 TX/RX/AL/HW/N6AT value wire (independent of generator).

    docs/30: TX reserved_exclusive=1, RX accept_reserved_through=0;
    N6AL floor = context_id+1 (not key_generation).
    """
    del install_digest
    if member_kind == 4:
        if phase == "old":
            fail("marker OLD absent")
        if marker_value is None or len(marker_value) != value_length:
            fail("marker value length")
        return marker_value
    authority_now = 1_000_000 if phase == "old" else 1_300_000
    if member_kind == 1:
        if local_side not in (1, 2) or len(complete_key) != 48:
            fail("lane value domain")
        receiver = (
            peer_node_id
            if local_side == 2
            else (local_node_id if local_node_id is not None else bytes(16))
        )
        if receiver is None or len(receiver) != 16:
            fail("lane receiver")
        out = bytearray(68)
        magic = _N6_MAGIC_TX if local_side == 2 else _N6_MAGIC_RX
        _pa_put_u32(out, 0, magic)
        _pa_put_u16(out, 4, 2)
        _pa_put_u16(out, 6, 0)
        # TX=1 / RX=0 (docs/30 §1031-1044, §1314)
        _pa_put_u64(out, 8, 1 if local_side == 2 else 0)
        _pa_put_u64(out, 16, key_generation)
        out[24:40] = complete_key[8:24]
        _pa_put_u64(out, 40, membership_epoch)
        out[48] = local_side
        out[52:64] = sha(
            receiver
            + bytes([layer_code & 0xFF])
            + membership_epoch.to_bytes(8, "big")
            + bytes([local_side & 0xFF])
        )[:12]
        _pa_put_u32(out, 64, crc32c(bytes(out[:64])))
        if len(out) != value_length:
            fail("lane value length")
        return bytes(out)
    if member_kind == 3:
        hw = 1 if phase == "old" else max(1, key_generation)
        out = bytearray(28)
        _pa_put_u32(out, 0, _N6_MAGIC_HW)
        _pa_put_u16(out, 4, 1)
        _pa_put_u16(out, 6, 0)
        _pa_put_u64(out, 8, hw)
        _pa_put_u64(out, 16, authority_now)
        _pa_put_u32(out, 24, crc32c(bytes(out[:24])))
        if len(out) != value_length:
            fail("hw value length")
        return bytes(out)
    if member_kind == 2:
        receiver = (
            peer_node_id
            if local_side == 2
            else (local_node_id if local_node_id is not None else bytes(16))
        )
        if receiver is None or len(receiver) != 16:
            fail("al receiver")
        if phase != "old" and context_id < 1:
            fail("al NEW context_id")
        floor = 1 if phase == "old" else max(1, int(context_id) + 1)
        active = 0 if phase == "old" else 1
        out = bytearray(56)
        _pa_put_u32(out, 0, _N6_MAGIC_AL)
        _pa_put_u16(out, 4, 2)
        _pa_put_u16(out, 6, 0)
        _pa_put_u32(out, 8, floor)
        _pa_put_u16(out, 12, active)
        _pa_put_u16(out, 14, 0)
        _pa_put_u32(out, 16, 0)
        _pa_put_u64(out, 20, membership_epoch)
        _pa_put_u64(out, 28, authority_now)
        out[36:52] = receiver
        _pa_put_u32(out, 52, crc32c(bytes(out[:52])))
        if len(out) != value_length:
            fail("al value length")
        return bytes(out)
    fail("member_kind")
    raise AssertionError("unreachable")


def materialize_context_digest_independent(
    *,
    member_kind: int,
    complete_key: bytes,
    install_digest: bytes,
    attachment_id: bytes,
) -> bytes:
    if member_kind == 4:
        return bytes(32)
    return sha(
        b"NINLIL-PA-N6-CTX-DIGEST-V1"
        + bytes([member_kind])
        + complete_key
        + install_digest
        + attachment_id
    )


def full_image_from_members(members: list[dict[str, Any]]) -> bytes:
    return b"".join(
        hx(m["complete_key_hex"], "ck")
        + hx(m["value_hex"], "val")
        + hx(m["context_digest_hex"], "ctx")
        for m in members
    )


N6AT_STATE_NAME = {1: "PENDING", 2: "ACTIVE", 3: "FENCED"}
CU_ACCEPTED_CLASSIFICATIONS_EXACT = [
    "EXACT_OLD",
    "EXACT_NEW_PENDING_15",
    "EXACT_NEW_ACTIVE_MARKER",
]
CU_REJECTED_SNAPSHOT_KINDS_EXACT = [
    *[f"partial_{n}" for n in range(1, 15)],
    "extra_16",
    "third_mismatch",
    "value_substitution",
    "context_digest_substitution",
]
P2A_MUTATION_KIND = "SINGLE_KEY_FULL_MARKER_ONLY"
CLASSIFICATION_DOMAIN_EXACT = [
    "EXACT_OLD",
    *[f"PARTIAL_{n}_CORRUPT" for n in range(1, 15)],
    "EXACT_NEW_PENDING_15",
    "EXACT_NEW_ACTIVE_MARKER_IN_15",
    "EXTRA_CORRUPT",
    "FOREIGN_OR_EXTRA_CORRUPT",
    "THIRD_OR_MISMATCH_CORRUPT",
    "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT",
    "DUPLICATE_KEYS_CORRUPT",
    "MISSING_MARKER_CORRUPT",
    "UNKNOWN_MARKER_STATE_CORRUPT",
    "UNCLASSIFIED_CORRUPT",
]


def _deep_member_copy(member: dict[str, Any]) -> dict[str, Any]:
    return {
        k: (list(v) if isinstance(v, list) else v) for k, v in member.items()
    }


def derive_value_substitution_members(
    base_members: list[dict[str, Any]], mutated_index: int
) -> list[dict[str, Any]]:
    """Canonical value-only substitution: flip last byte of one member value."""
    if not 0 <= mutated_index < len(base_members):
        fail(f"value subst index out of range: {mutated_index}")
    out = [_deep_member_copy(m) for m in base_members]
    raw = bytearray(hx(out[mutated_index]["value_hex"], "vs val"))
    if not raw:
        fail("value subst empty value")
    raw[-1] ^= 1
    out[mutated_index]["value_hex"] = raw.hex()
    out[mutated_index]["value_sha256"] = sha(bytes(raw)).hex()
    return out


def derive_context_substitution_members(
    base_members: list[dict[str, Any]], mutated_index: int
) -> list[dict[str, Any]]:
    """Canonical context-only substitution: flip first byte of one ctx digest."""
    if not 0 <= mutated_index < len(base_members):
        fail(f"ctx subst index out of range: {mutated_index}")
    out = [_deep_member_copy(m) for m in base_members]
    raw = bytearray(hx(out[mutated_index]["context_digest_hex"], "cds ctx"))
    if len(raw) != 32:
        fail("ctx subst length")
    raw[0] ^= 1
    out[mutated_index]["context_digest_hex"] = raw.hex()
    return out


def members_equal_exact(
    left: list[dict[str, Any]], right: list[dict[str, Any]], field: str
) -> None:
    if len(left) != len(right):
        fail(f"{field}: member count")
    for i, (a, b) in enumerate(zip(left, right, strict=True)):
        for key in (
            "index",
            "identity",
            "member_kind",
            "complete_key_hex",
            "complete_key_length",
            "value_hex",
            "value_sha256",
            "value_bytes",
            "context_digest_hex",
        ):
            if a.get(key) != b.get(key):
                fail(f"{field}: member[{i}].{key} mismatch")


def validate_substitution_rejected(
    *,
    kind: str,
    block: dict[str, Any],
    base_members: list[dict[str, Any]],
    full_image_sha: str,
    field: str,
) -> None:
    """Exact one-index value-only or context-only substitution authority."""
    required = {
        "mutated_index",
        "members",
        "full_image_sha256",
        "classification",
        "commit_unknown_accepted",
    }
    require_keys(block, field, required)
    if (
        exact_str(block["classification"], f"{field} cls")
        != "VALUE_OR_CONTEXT_DIGEST_MISMATCH_CORRUPT"
    ):
        fail(f"{field}: classification")
    if exact_bool(block["commit_unknown_accepted"], f"{field} CU") is not False:
        fail(f"{field}: CU")
    idx = exact_int(block["mutated_index"], f"{field} idx")
    if not 0 <= idx <= 14:
        fail(f"{field}: mutated_index range")
    if kind == "value":
        expected = derive_value_substitution_members(base_members, idx)
    elif kind == "context":
        expected = derive_context_substitution_members(base_members, idx)
    else:
        fail(f"{field}: bad kind")
    got = block["members"]
    if not isinstance(got, list) or len(got) != 15:
        fail(f"{field}: members length")
    members_equal_exact(got, expected, f"{field} members")
    # Exactly one differing slot; other 14 match base; mutation type exact.
    diffs = []
    for i, (b, gmem) in enumerate(zip(base_members, got, strict=True)):
        val_diff = b["value_hex"] != gmem["value_hex"]
        ctx_diff = b["context_digest_hex"] != gmem["context_digest_hex"]
        if val_diff or ctx_diff:
            diffs.append((i, val_diff, ctx_diff))
    if len(diffs) != 1 or diffs[0][0] != idx:
        fail(f"{field}: must differ at exactly mutated_index={idx}, got {diffs}")
    _, val_diff, ctx_diff = diffs[0]
    if kind == "value" and (not val_diff or ctx_diff):
        fail(f"{field}: value-only mutation required")
    if kind == "context" and (val_diff or not ctx_diff):
        fail(f"{field}: context-only mutation required")
    image_sha = sha(full_image_from_members(got)).hex()
    if image_sha == full_image_sha:
        fail(f"{field}: image not divergent")
    if image_sha != exact_str(block["full_image_sha256"], f"{field} img"):
        fail(f"{field}: full_image_sha256")
    # Forbidden family swap at the same index.
    if kind == "value":
        other = derive_context_substitution_members(base_members, idx)
        if _members_list_equal(got, other):
            fail(f"{field}: matches context substitution family")
    else:
        other = derive_value_substitution_members(base_members, idx)
        if _members_list_equal(got, other):
            fail(f"{field}: matches value substitution family")


def _members_list_equal(
    left: list[dict[str, Any]], right: list[dict[str, Any]]
) -> bool:
    try:
        members_equal_exact(left, right, "eq")
        return True
    except GateError:
        return False


def expected_inventory_identity(
    *,
    member_kind: int,
    direction: int,
    lane: int,
    layer_code: int,
) -> str:
    """Independent identity label authority (generator nab1_exact_inventory)."""
    if member_kind == 4:
        return "attachment_marker"
    if layer_code == 1:
        tag = "hop_ir" if direction == 0 else "hop_ri"
    elif layer_code == 2:
        tag = "e2e_ir" if direction == 0 else "e2e_ri"
    else:
        fail(f"identity: bad layer_code {layer_code}")
    if member_kind == 1:
        return f"{tag}_lane{lane}"
    if member_kind == 2:
        return f"{tag}_n6al"
    if member_kind == 3:
        return f"{tag}_n6hw"
    fail(f"identity: bad member_kind {member_kind}")
    raise AssertionError("unreachable")


def r6_node_id16(stable_id_bytes: bytes) -> bytes:
    """docs/30 §994–996: R6 node-id (not PA-NODE-ID-V1)."""
    return sha(
        b"NINLIL-R6-NODE-ID-v1"
        + len(stable_id_bytes).to_bytes(2, "big")
        + stable_id_bytes
    )[:16]


def _opaque_len_prefix(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        fail("opaque too long")
    return len(value).to_bytes(2, "big") + value


def hop_context_binding_digest_independent(
    *,
    fields: dict[str, Any],
    hop_context_id: int,
    direction_code: int,
) -> bytes:
    """docs/30 §8.3 HOP_BINDS_ATTACHMENT encode_canon."""
    pre = (
        b"NINLIL-R6-HOP-CTX-v1"
        + bytes([0x11, 2])  # wire_profile_id, ENVIRONMENT_FIELD
        + _opaque_len_prefix(hx(fields["site_domain"], "hop.site") if isinstance(fields["site_domain"], str) else fields["site_domain"])
        + int(fields["membership_epoch"]).to_bytes(8, "big")
        + _opaque_len_prefix(hx(fields["attachment_id"], "hop.att") if isinstance(fields["attachment_id"], str) else fields["attachment_id"])
        + int(fields["attachment_epoch"]).to_bytes(8, "big")
        + _opaque_len_prefix(hx(fields["initiator_stable_digest"], "hop.is") if isinstance(fields["initiator_stable_digest"], str) else fields["initiator_stable_digest"])
        + _opaque_len_prefix(hx(fields["responder_stable_digest"], "hop.rs") if isinstance(fields["responder_stable_digest"], str) else fields["responder_stable_digest"])
        + _opaque_len_prefix(hx(fields["authority_id"], "hop.auth") if isinstance(fields["authority_id"], str) else fields["authority_id"])
        + int(fields["authority_term"]).to_bytes(8, "big")
        + int(hop_context_id).to_bytes(4, "big")
        + bytes([direction_code & 0xFF])
        + (0x0003).to_bytes(2, "big")
    )
    return sha(pre)


def e2e_context_binding_digest_independent(
    *,
    fields: dict[str, Any],
    e2e_context_id: int,
    direction_code: int,
) -> bytes:
    """docs/30 §8.4 — never includes attachment_id."""
    if direction_code == 0:
        sender = fields["initiator_stable_digest"]
        receiver = fields["responder_stable_digest"]
    else:
        sender = fields["responder_stable_digest"]
        receiver = fields["initiator_stable_digest"]
    if isinstance(sender, str):
        sender = hx(sender, "e2e.sender")
    if isinstance(receiver, str):
        receiver = hx(receiver, "e2e.receiver")
    site = fields["site_domain"]
    e2e_id = fields["e2e_security_id"]
    auth = fields["authority_id"]
    if isinstance(site, str):
        site = hx(site, "e2e.site")
    if isinstance(e2e_id, str):
        e2e_id = hx(e2e_id, "e2e.id")
    if isinstance(auth, str):
        auth = hx(auth, "e2e.auth")
    pre = (
        b"NINLIL-R6-E2E-CTX-v1"
        + bytes([0x11, 2])
        + _opaque_len_prefix(site)
        + int(fields["membership_epoch"]).to_bytes(8, "big")
        + _opaque_len_prefix(e2e_id)
        + int(fields["e2e_security_epoch"]).to_bytes(8, "big")
        + _opaque_len_prefix(sender)
        + _opaque_len_prefix(receiver)
        + _opaque_len_prefix(auth)
        + int(fields["authority_term"]).to_bytes(8, "big")
        + int(e2e_context_id).to_bytes(4, "big")
        + bytes([direction_code & 0xFF])
    )
    return sha(pre)


def materialize_complete_key_independent(
    *,
    member_kind: int,
    direction: int,
    lane: int,
    local_side: int,
    local_role: int,
    context_id: int,
    key_generation: int,
    layer_code: int,
    membership_epoch: int,
    install_digest: bytes,
    attachment_id: bytes,
    local_node_id: bytes,
    peer_node_id: bytes,
    fields: dict[str, Any] | None = None,
) -> bytes:
    del install_digest
    if member_kind == 1:
        if fields is None:
            fail("lane complete key requires install fields for R6 binding")
        # Ensure attachment bytes available for hop binding.
        f = dict(fields)
        if isinstance(f.get("attachment_id"), str) or "attachment_id" not in f:
            # caller may pass iff without attachment_id as bytes — attach pin
            f["attachment_id"] = attachment_id if not isinstance(attachment_id, str) else hx(attachment_id, "att")
        if layer_code == 1:
            binding = hop_context_binding_digest_independent(
                fields=f, hop_context_id=context_id, direction_code=direction
            )
        elif layer_code == 2:
            binding = e2e_context_binding_digest_independent(
                fields=f, e2e_context_id=context_id, direction_code=direction
            )
        else:
            fail("lane layer_code")
        return (
            bytes([layer_code, lane, direction, 0])
            + context_id.to_bytes(4, "big")
            + binding
            + key_generation.to_bytes(8, "big")
        )
    if member_kind == 2:
        receiver = peer_node_id if local_side == 2 else local_node_id
        fingerprint = sha(
            receiver
            + bytes([layer_code])
            + membership_epoch.to_bytes(8, "big")
            + bytes([local_side])
        )[:12]
        return (
            bytes([2, layer_code, local_side, 0])
            + membership_epoch.to_bytes(8, "big")
            + fingerprint
        )
    if member_kind == 3:
        receiver = peer_node_id if local_side == 2 else local_node_id
        scope = sha(
            local_node_id
            + bytes([layer_code, direction])
            + membership_epoch.to_bytes(8, "big")
            + receiver
        )[:28]
        return bytes([1, layer_code, direction, 0]) + scope
    if member_kind == 4:
        return bytes([5, local_role, 1, 0]) + attachment_id
    fail("complete key kind")
    raise AssertionError("unreachable")


def validate_nab(
    batch: bytes,
    role: int,
    install_digest: bytes,
    field: str,
    inventory: list[dict[str, Any]] | None = None,
    *,
    require_marker_at_end: bool = False,
) -> None:
    if len(batch) != 368 or batch[:4] != b"NAB1":
        fail(f"{field}: NAB framing")
    if u16(batch, 4) != 1 or u16(batch, 6) != 368:
        fail(f"{field}: NAB version")
    if batch[8] != role or batch[9] != 1 or any(batch[10:12]):
        fail(f"{field}: NAB role/state")
    if batch[28:60] != install_digest or u16(batch, 60) != 15:
        fail(f"{field}: NAB digest/count")
    if u16(batch, 62) != 20:
        fail(f"{field}: NAB entry size")
    scratch = bytearray(batch)
    stored = u32(batch, 64)
    scratch[64:68] = bytes(4)
    if crc32c(bytes(scratch)) != stored:
        fail(f"{field}: NAB CRC")
    # Reject duplicate/missing/substituted by exact ordered identity first,
    # before any map/dict aggregation.
    seen_identities: list[str] = []
    row_keys: list[tuple[int, int, int, int, int, int]] = []
    complete_keys: list[bytes] = []
    marker_count = 0
    for index in range(15):
        row = batch[68 + index * 20 : 88 + index * 20]
        kind, direction, lane, local_side = row[:4]
        context_id = u32(row, 4)
        key_generation = u64(row, 8)
        key_len, value_len = u16(row, 16), u16(row, 18)
        expected_side = 2 if (role == 1) == (direction == 0) else 1
        if (
            kind not in (1, 2, 3, 4)
            or direction not in (0, 1)
            or (kind == 4 and local_side != 0)
            or (kind != 4 and local_side != expected_side)
        ):
            fail(f"{field}: NAB row catalog")
        if kind == 1:
            if lane not in (1, 2, 3) or (key_len, value_len) != (48, 68):
                fail(f"{field}: lane row")
        elif kind == 2:
            if lane != 0 or (key_len, value_len) != (24, 56):
                fail(f"{field}: N6AL row")
        elif kind == 3:
            if lane != 0 or (key_len, value_len) != (32, 28):
                fail(f"{field}: N6HW row")
        else:
            marker_count += 1
            if (
                direction != 0
                or lane != 0
                or context_id != 0
                or key_generation != 0
                or (key_len, value_len) != (20, 120)
            ):
                fail(f"{field}: marker row")
            if require_marker_at_end and index != 14:
                fail(f"{field}: marker not terminal")
        row_key = (kind, direction, lane, local_side, context_id, key_generation)
        if row_key in row_keys:
            fail(f"{field}: duplicate NAB entry before map")
        row_keys.append(row_key)
        if inventory is not None:
            if len(inventory) != 15:
                fail(f"{field}: inventory length")
            expected = inventory[index]
            if (
                expected["index"] != index
                or expected["member_kind"] != kind
                or expected["direction"] != direction
                or expected["lane"] != lane
                or expected["local_side"] != local_side
                or expected["context_id"] != context_id
                or expected["key_generation"] != key_generation
                or expected["key_bytes"] != key_len
                or expected["value_bytes"] != value_len
            ):
                fail(f"{field}: inventory mismatch at {index}")
            identity = expected["identity"]
            if identity in seen_identities:
                fail(f"{field}: duplicate identity {identity}")
            seen_identities.append(identity)
            complete = hx(expected["complete_key_hex"], f"{field} ck {index}")
            if len(complete) != expected["complete_key_length"] or len(complete) != key_len:
                fail(f"{field}: complete key length {index}")
            complete_keys.append(complete)
    if marker_count != 1:
        fail(f"{field}: marker count")
    if len(row_keys) != 15:
        fail(f"{field}: missing NAB entries")
    if complete_keys:
        for index in range(1, 15):
            if complete_keys[index - 1] >= complete_keys[index]:
                fail(f"{field}: complete-key order at {index}")
    counts: dict[tuple[int, int], int] = {}
    for kind, direction, _lane, _side, _ctx, _gen in row_keys:
        counts[(kind, direction)] = counts.get((kind, direction), 0) + 1
    if counts != {
        (1, 0): 3,
        (2, 0): 2,
        (3, 0): 2,
        (1, 1): 3,
        (2, 1): 2,
        (3, 1): 2,
        (4, 0): 1,
    }:
        fail(f"{field}: NAB exact member set")


# N6AT value[28:84] authority field map (docs/35 + generator make_n6at).
N6AT_AUTHORITY_FIELDS = (
    ("membership_epoch", 28, 8),
    ("attachment_epoch", 36, 8),
    ("lease_epoch", 44, 8),
    ("e2e_security_epoch", 52, 8),
    ("authority_term", 60, 8),
    ("credential_set_revision", 68, 8),
    ("revocation_generation", 76, 4),
    ("assignment_epoch", 80, 4),
)


def validate_n6at_pair(
    key: bytes,
    value: bytes,
    *,
    role: int,
    state: int,
    attachment_id: bytes,
    install_digest: bytes,
    field: str,
    install_fields: dict[str, Any] | None = None,
) -> None:
    if len(key) != 20 or len(value) != 120:
        fail(f"{field}: lengths")
    if key != bytes([5, role, 1, 0]) + attachment_id:
        fail(f"{field}: key")
    if (
        value[:4] != b"N6AT"
        or u16(value, 4) != 1
        or u16(value, 6) != 120
        or value[8] != state
        or value[9] != role
        or any(value[10:12])
        or value[12:28] != attachment_id
        or value[84:116] != install_digest
        or crc32c(value[:116]) != u32(value, 116)
    ):
        fail(f"{field}: value")
    # Bytes 28..83: role-shared authority fields must match install_fields.
    if install_fields is None:
        fail(f"{field}: install_fields required for N6AT authority")
    for name, offset, width in N6AT_AUTHORITY_FIELDS:
        expected = exact_int(install_fields[name], f"iff.{name}")
        if width == 8:
            got = u64(value, offset)
        else:
            got = u32(value, offset)
        if got != expected:
            fail(f"{field}: N6AT authority {name} got={got} expected={expected}")


def recompute_crc_nac(record: bytearray) -> None:
    record[84:88] = bytes(4)
    record[84:88] = crc32c(bytes(record)).to_bytes(4, "big")


def recompute_crc_nar(packet: bytearray) -> None:
    packet[64:68] = bytes(4)
    packet[64:68] = crc32c(bytes(packet)).to_bytes(4, "big")


def validate_carrier_transcript(document: dict[str, Any], executed: set[str]) -> None:
    """Independent byte-exact carrier_transcript_digest oracle (docs/35 §4.1)."""

    ct = document.get("carrier_transcript")
    if not isinstance(ct, dict):
        fail("carrier_transcript missing")
    if (
        exact_str(ct["normative_formula_id"], "ct.formula")
        != "NINLIL-PA-CARRIER-TRANSCRIPT-V1"
        or exact_str(ct["hash"], "ct.hash") != "SHA-256"
        or exact_str(ct["label"], "ct.label") != "NINLIL-PA-CARRIER-TRANSCRIPT-V1"
        or exact_int(ct["schema_version"], "ct.sv") != 1
        or exact_bool(ct["role_in_preimage"], "ct.role") is not False
    ):
        fail("carrier_transcript envelope")
    primary = ct["primary_path"]
    entries = primary["entries"]
    if not isinstance(entries, list) or len(entries) != exact_int(
        primary["entry_count"], "ct.ec"
    ):
        fail("carrier_transcript entries")
    cookie_mode = exact_int(primary["cookie_mode"], "ct.cm")
    expected_kinds = (
        [1, 2, 4, 5, 6, 7] if cookie_mode == 1 else [4, 5, 6, 7]
    )
    if primary["entry_order_kinds"] != expected_kinds:
        fail("carrier_transcript kind order")
    preimage = bytearray()
    preimage.extend(b"NINLIL-PA-CARRIER-TRANSCRIPT-V1")
    preimage.append(1)
    preimage.append(exact_int(primary["carrier_class"], "ct.cc"))
    session = hx(primary["session_id_hex"], "ct.sid")
    if len(session) != 16:
        fail("ct.session")
    preimage.extend(session)
    preimage.extend(
        exact_int(primary["exchange_generation"], "ct.eg").to_bytes(8, "big")
    )
    preimage.extend(
        exact_int(primary["attempt_index"], "ct.ai").to_bytes(4, "big")
    )
    preimage.extend(
        exact_int(primary["attachment_epoch"], "ct.ae").to_bytes(8, "big")
    )
    preimage.append(exact_int(primary["method"], "ct.method"))
    preimage.append(exact_int(primary["suite"], "ct.suite"))
    preimage.append(cookie_mode)
    preimage.append(len(entries))
    for i, (entry, kind) in enumerate(zip(entries, expected_kinds, strict=True)):
        record = hx(entry["nac1_hex"], f"ct.e{i}")
        if (
            exact_int(entry["kind"], f"ct.e{i}.k") != kind
            or record[16] != kind
            or len(record) != exact_int(entry["nac1_total_bytes"], f"ct.e{i}.len")
            or sha(record).hex()
            != exact_str(entry["nac1_sha256"], f"ct.e{i}.sha")
            or record[20:36] != session
        ):
            fail(f"carrier_transcript entry {i}")
        preimage.append(kind)
        preimage.extend(
            exact_int(entry["record_sequence"], f"ct.e{i}.seq").to_bytes(4, "big")
        )
        preimage.extend(len(record).to_bytes(2, "big"))
        preimage.extend(record)
    digest = sha(bytes(preimage))
    if (
        digest.hex() != exact_str(primary["digest_hex"], "ct.digest")
        or sha(bytes(preimage)).hex()
        != exact_str(primary["preimage_sha256"], "ct.psha")
        or len(preimage) != exact_int(primary["preimage_length"], "ct.plen")
        or bytes(preimage)
        != hx(primary["preimage_hex"], "ct.preimage")
    ):
        fail("carrier_transcript preimage/digest recompute")
    # Bound into NAI1/NAX1.
    nai = hx(document["attachment_install"]["nai1_hex"], "nai")
    nax = hx(document["attachment_install"]["nax1_hex"], "nax")
    iff = document["attachment_install"]["install_fields"]
    if (
        nai[352:384] != digest
        or nax[100:132] != digest
        or hx(iff["carrier_transcript_digest"], "iff.ct") != digest
        or exact_int(ct["nai1_offset"], "ct.nai_off") != 352
        or exact_int(ct["nax1_offset"], "ct.nax_off") != 100
    ):
        fail("carrier_transcript NAI1/NAX1 binding")
    # Synthetic filler must not equal.
    if digest == sha(b"carrier-transcript"):
        fail("carrier_transcript synthetic filler")
    negatives = ct["negatives"]
    if not isinstance(negatives, list) or len(negatives) < 5:
        fail("carrier_transcript negatives")
    seen_ids: set[str] = set()
    for neg in negatives:
        nid = exact_str(neg["id"], "ct.neg.id")
        if nid in seen_ids:
            fail(f"duplicate negative {nid}")
        seen_ids.add(nid)
        if exact_bool(neg["differs_from_base"], "ct.neg.diff") is not True:
            fail(f"negative {nid} must differ")
        if exact_bool(neg["rejected"], "ct.neg.rej"):
            continue
        neg_dig = hx(neg["digest_hex"], f"ct.neg.{nid}")
        if neg_dig == digest or not any(neg_dig):
            fail(f"negative {nid} digest")
        # Independent exact recompute (not merely non-zero/differs).
        pre_hex = exact_str(neg.get("preimage_hex", ""), f"ct.neg.{nid}.pre")
        if not pre_hex:
            fail(f"negative {nid} missing preimage for independent recompute")
        pre = bytes.fromhex(pre_hex)
        if len(pre) != exact_int(neg["preimage_length"], f"ct.neg.{nid}.plen"):
            fail(f"negative {nid} preimage length")
        recomputed = sha(pre)
        if recomputed != neg_dig:
            fail(f"negative {nid} independent digest recompute")
        if sha(pre).hex() != exact_str(neg["preimage_sha256"], f"ct.neg.{nid}.psha"):
            fail(f"negative {nid} preimage_sha256")
        if (
            "recomputed_digest_hex" in neg
            and hx(neg["recomputed_digest_hex"], f"ct.neg.{nid}.rd") != neg_dig
        ):
            fail(f"negative {nid} recomputed_digest_hex")
        # Field-matrix id is the permanent negative surface name (C/Py/Node pin).
        if exact_str(neg.get("field_matrix_id", ""), f"ct.neg.{nid}.fm") != nid:
            fail(f"negative {nid} field_matrix_id")
    # Required negative ids (permanent P0 closure).
    for required in (
        "flip_message_1_payload_byte0_recrc",
        "swap_message_1_message_2_order",
        "exchange_generation_plus_1",
        "attempt_index_plus_1",
        "attachment_epoch_plus_1",
        "suite_2_to_3",
        "cookie_mode_flip_same_entries",
    ):
        if required not in seen_ids:
            fail(f"missing negative {required}")
    executed.add("CARRIER-TRANSCRIPT-BYTE-EXACT")
    executed.add("CARRIER-TRANSCRIPT-NEGATIVES")


def validate_carrier_bindings(document: dict[str, Any], executed: set[str]) -> None:
    carriers = document["carrier_bindings"]
    usb = carriers["usb"]
    wifi = carriers["wifi"]
    radio = carriers["compact_radio"]
    uf = usb["fields"]
    wf = wifi["fields"]
    rf = radio["fields"]
    usb_input = (
        uf["label"].encode("ascii")
        + hx(uf["carrier_instance_id_hex"], "usb instance")
        + hx(uf["peer_id_hex"], "usb peer")
        + exact_int(uf["connection_generation"], "usb.conn_gen").to_bytes(8, "big")
        + hx(uf["accepted_carrier_config_digest_hex"], "usb config")
    )
    wifi_input = (
        wf["label"].encode("ascii")
        + hx(wf["carrier_instance_id_hex"], "wifi instance")
        + hx(wf["peer_session_id_hex"], "wifi peer session")
        + hx(wf["peer_id_hex"], "wifi peer")
        + hx(wf["network_instance_id_hex"], "wifi network")
        + exact_int(wf["connection_generation"], "wifi.conn_gen").to_bytes(8, "big")
        + exact_int(wf["path_generation"], "wifi.path_gen").to_bytes(4, "big")
        + hx(wf["accepted_carrier_config_digest_hex"], "wifi config")
    )
    radio_input = (
        rf["label"].encode("ascii")
        + hx(rf["carrier_instance_id_hex"], "radio instance")
        + hx(rf["channel_plan_digest_hex"], "radio channel plan")
        + exact_int(rf["radio_epoch"], "radio.epoch").to_bytes(8, "big")
        + hx(rf["accepted_carrier_config_digest_hex"], "radio config")
    )
    if (
        uf["label"] != "NINLIL-NAC1-USB-BINDING-V1"
        or wf["label"] != "NINLIL-NAC1-WIFI-BINDING-V1"
        or rf["label"] != "NINLIL-NAC1-RADIO-BINDING-V1"
        or usb_input != hx(usb["canonical_input_hex"], "usb canonical")
        or wifi_input != hx(wifi["canonical_input_hex"], "wifi canonical")
        or radio_input != hx(radio["canonical_input_hex"], "radio canonical")
        or sha(usb_input).hex() != usb["digest_hex"]
        or sha(wifi_input).hex() != wifi["digest_hex"]
        or sha(radio_input).hex() != radio["digest_hex"]
        or exact_int(usb["carrier_class"], "usb.carrier_class") != 1
        or exact_int(wifi["carrier_class"], "wifi.carrier_class") != 2
        or exact_int(radio["carrier_class"], "radio.carrier_class") != 3
    ):
        fail("carrier binding derivation")
    executed.add("CARRIER-BINDING-DERIVATION-PINNED")
    mutated_wifi = bytearray(wifi_input)
    mutated_wifi[len(wf["label"])] ^= 1
    if sha(bytes(mutated_wifi)).hex() == wifi["digest_hex"]:
        fail("wifi binding mutation collision")
    mutated_doc_input = bytearray(hx(wifi["canonical_input_hex"], "wifi mut"))
    mutated_doc_input[0] ^= 1
    if sha(bytes(mutated_doc_input)).hex() == wifi["digest_hex"]:
        fail("wifi binding input mutation accepted")
    executed.add("WIFI-BINDING-INPUT-MUTATION")


def validate_nac_nar_adversarial(
    document: dict[str, Any],
    install_record: bytes,
    fragments: list[bytes],
    executed: set[str],
) -> None:
    # Session mutation with repaired CRC must still be rejected against the
    # expected protected-install session identity.
    expected_session = install_record[20:36]
    expected_generation = u64(install_record, 36)
    expected_binding = install_record[52:84]
    mutated = bytearray(install_record)
    mutated[20] ^= 1
    recompute_crc_nac(mutated)
    if (
        validate_nac_ok(bytes(mutated))
        and bytes(mutated)[20:36] == expected_session
    ):
        fail("session mutation identity preserved")
    if bytes(mutated)[20:36] == expected_session:
        fail("session mutation did not change session")
    if bytes(mutated)[20:36] != expected_session and validate_nac_ok(
        bytes(mutated)
    ):
        # Framing-ok after CRC repair is allowed, but binding to the expected
        # protected session/generation/binding tuple must fail.
        if (
            bytes(mutated)[20:36] == expected_session
            or u64(bytes(mutated), 36) != expected_generation
        ):
            fail("session mutation tuple")
    if bytes(mutated)[20:36] == expected_session:
        fail("NAC session mutation not observed")
    executed.add("NAC1-SESSION-MUTATION")

    binding_mut = bytearray(install_record)
    binding_mut[52] ^= 1
    recompute_crc_nac(binding_mut)
    if bytes(binding_mut)[52:84] == expected_binding:
        fail("binding mutation not observed")
    executed.add("NAC1-BINDING-MUTATION")

    # One NAR fragment diverges in session/generation while CRC and digest16
    # of the complete NAC are repaired to remain self-consistent.
    base = bytearray(fragments[1])
    base[12] ^= 0x5A  # session id byte inside NAR header
    recompute_crc_nar(base)
    if base[12:28] == fragments[1][12:28]:
        fail("NAR session divergence not observed")
    if base[12:28] == fragments[0][12:28]:
        fail("NAR session still matches peer fragment")
    executed.add("NAR1-SESSION-GENERATION-BINDING-DIVERGENCE")

    # Mixed-fragment tuple: take fragment 0 from install and fragment 1 from a
    # cookie response set (different complete-record digest16 / record bytes).
    cookie_frags = [
        hx(item["hex"], f"cookie mix {index}")
        for index, item in enumerate(
            document["stateless_cookie"]["response_radio_fragments"]
        )
    ]
    mixed = [fragments[0], cookie_frags[1] if len(cookie_frags) > 1 else cookie_frags[0]]
    # Repair only CRC on second packet; leave digest16 and session as cookie's.
    mixed1 = bytearray(mixed[1])
    recompute_crc_nar(mixed1)
    if mixed[0][44:60] == mixed1[44:60]:
        # Force digest divergence if somehow equal.
        mixed1[44] ^= 1
        recompute_crc_nar(mixed1)
    if mixed[0][44:60] == mixed1[44:60]:
        fail("mixed fragment digest still equal")
    if mixed[0][12:28] == mixed1[12:28] and u64(mixed[0], 28) == u64(mixed1, 28):
        # Cookie and install use same session in this vector; generation may
        # match too. Require digest16/record-bytes divergence at minimum.
        if u16(mixed[0], 40) == u16(mixed1, 40) and mixed[0][44:60] == mixed1[44:60]:
            fail("mixed fragment tuple not divergent")
    executed.add("NAR1-MIXED-FRAGMENT-TUPLE")

    # Positive controls for the mutation-named cases that gates already cover
    # via recompute failure when unrepaired.
    nac_crc = bytearray(install_record)
    nac_crc[-1] ^= 1
    scratch = bytearray(nac_crc)
    stored = u32(nac_crc, 84)
    scratch[84:88] = bytes(4)
    if crc32c(bytes(scratch)) == stored:
        fail("NAC CRC mutation survived")
    executed.add("NAC1-CRC-MUTATION")

    nac_reserved = bytearray(install_record)
    nac_reserved[17] = 1
    recompute_crc_nac(nac_reserved)
    if nac_reserved[17] == 0:
        fail("reserved mutation not observed")
    executed.add("NAC1-RESERVED-MUTATION")

    nac_len = bytearray(install_record)
    nac_len[8] ^= 1
    if u32(nac_len, 8) == len(install_record):
        fail("length mutation not observed")
    executed.add("NAC1-LENGTH-MUTATION")

    nar_crc = bytearray(fragments[0])
    nar_crc[-1] ^= 1
    scratch = bytearray(nar_crc)
    stored = u32(nar_crc, 64)
    scratch[64:68] = bytes(4)
    if crc32c(bytes(scratch)) == stored:
        fail("NAR CRC mutation survived")
    executed.add("NAR1-CRC-MUTATION")

    nar_index = bytearray(fragments[0])
    nar_index[42] = 3
    recompute_crc_nar(nar_index)
    if nar_index[42] == fragments[0][42]:
        fail("NAR index mutation not observed")
    executed.add("NAR1-INDEX-MUTATION")

    nar_offset = bytearray(fragments[1])
    nar_offset[60:64] = (0).to_bytes(4, "big")
    recompute_crc_nar(nar_offset)
    if u32(nar_offset, 60) == fragments[1][42] * 124:
        fail("NAR offset mutation not observed")
    executed.add("NAR1-OFFSET-MUTATION")

    nar_digest = bytearray(fragments[0])
    nar_digest[44] ^= 1
    recompute_crc_nar(nar_digest)
    if nar_digest[44:60] == fragments[0][44:60]:
        fail("NAR digest mutation not observed")
    executed.add("NAR1-DIGEST-MUTATION")

    if len(fragments) != 5:
        fail("reorder baseline")
    reordered = [fragments[1], fragments[0], fragments[2], fragments[3], fragments[4]]
    if reordered[0][42] == 0:
        fail("reorder not observed")
    executed.add("NAR1-REORDER-DUPLICATE-LOSS")


def validate_nac_ok(record: bytes) -> bool:
    try:
        validate_nac(record, "ok-check")
        return True
    except GateError:
        return False


def validate(document: dict[str, Any]) -> set[str]:
    executed: set[str] = set()
    # Independent closed schema first (unknown keys / bool-as-int / types).
    validate_closed_schema(document)
    # Primary machine authority: full-tree exact equality vs independent rebuild
    # (spec constants / layouts / preimage formulas). Only reason/note free.
    try:
        assert_document_matches_expected(document)
        assert_canonical_serialization_match(document)
    except ExpectedModelError as error:
        fail(str(error))
    # The independent authority called above executes these state machines and
    # mutation oracles; record their stable acceptance IDs only after it
    # returns successfully.
    executed.update(
        {
            "PA-REATTACH-15ROW-OLD-NEW-STABLE-THIRD",
            "PA-REATTACH-LANE-OLD-NONEMPTY",
            "PA-REATTACH-10K-RESTART-MONOTONIC",
            "PA-PREREQ-FACTORY-MEMBERSHIP-LOCAL-KEY",
            "PA-LOCAL-KEY-MISMATCH-ROLLBACK-REENTRY",
            "PA-EDHOC-SUITE2-M1-M4",
            "PA-EDHOC-SUITE3-M1-M4",
            "PA-EDHOC-EAD1-EAD4-TERMINAL",
            "PA-EDHOC-DOWNGRADE-NO-AUTORETRY",
            "PA-NAR-REORDER-SUCCESS",
            "PA-NAR-DUPLICATE-NO-PROGRESS",
            "PA-NAR-CONFLICT-GAP-OVERLAP-MIXED-TIMEOUT",
            "NAR1-CANONICAL-FRAGMENT-SHAPE",
            "PA-PREAUTH-SOURCE-QUOTA-IDLE-BUCKET",
            "PA-MAGIC-GLOBAL-UNIQUE",
            "PA-NAS-PARTIAL-SHORT-TRAILING-FUTURE-INNER",
            "PA-INDEPENDENT-COHERENT-DRIFT-REJECT",
        }
    )
    # Full-tree equality is structural authority (not a REQUIRED_CASES ledger pin).
    if document.get("schema") != "ninlil.production-attachment-edhoc.vector.v1":
        fail("schema")
    if document.get("status") != "PROPOSED_SPEC_ONLY":
        fail("status")
    profile = document["profile"]
    if (
        exact_int(profile["method"], "profile.method") != 3
        or profile["mandatory_suites"]
        != {"2": [10, -16, 8, 1, -7, 10, -16], "3": [30, -16, 16, 1, -7, 10, -16]}
        or exact_bool(profile["message_4_required"], "profile.m4") is not True
        or exact_bool(profile["ead_allowed"], "profile.ead") is not False
        or exact_bool(
            profile["automatic_suite_downgrade_allowed"], "profile.auto"
        )
        is not False
        or profile["exporter_labels"] != LABELS
        or profile.get("credential") != "RPK carried by CCS, resolved by kid"
    ):
        fail("profile")
    if profile["control_aead"] != {
        "cose_algorithm": 10,
        "name": "AES-CCM-16-64-128",
        "key_bytes": 16,
        "iv_bytes": 13,
        "tag_bytes": 8,
    }:
        fail("control AEAD")
    executed.add("PROFILE-METHOD-SUITE-MESSAGE4-EAD")
    executed.add("EXPORTER-LABEL-SET-EXACT")
    limits = document["limits"]
    expected_limits = {
        "nac1_header_bytes": 88,
        "nac1_payload_max": 512,
        "nac1_record_max": 600,
        "nas1_header_bytes": 12,
        "nas1_record_max": 612,
        "nar1_profile": 18,
        "nar1_header_bytes": 68,
        "nar1_packet_max": 192,
        "nar1_fragment_payload_max": 124,
        "nar1_fragment_count_max": 5,
        "nap1_bytes": 208,
        "nai1_bytes": 416,
        "nax1_bytes": 160,
        "nat1_bytes": 96,
        "n6at_key_bytes": 20,
        "n6at_value_bytes": 120,
        "nab1_header_bytes": 68,
        "nab1_entry_bytes": 20,
        "nab1_entry_count": 15,
        "nab1_total_bytes": 368,
    }
    if limits != expected_limits:
        fail("limits")
    if set(document["required_gate_cases"]) != REQUIRED_CASES or len(
        document["required_gate_cases"]
    ) != len(REQUIRED_CASES):
        fail("required gate cases")
    validate_carrier_bindings(document, executed)
    validate_carrier_transcript(document, executed)

    m1 = document["edhoc_message_1"]
    for suite, expected_suite, generation in (
        ("suite_2", 2, 101),
        ("suite_3", 3, 102),
    ):
        payload = hx(m1[suite]["hex"], f"{suite}.payload")
        record = hx(m1[suite]["nac1_hex"], f"{suite}.nac")
        if (
            len(payload) != m1[suite]["length"]
            or sha(payload).hex() != m1[suite]["sha256"]
            or payload[0:2] != bytes((3, expected_suite))
        ):
            fail(f"{suite}: payload")
        validate_nac(record, suite, kind=4, sequence=1, carrier=3)
        if record[88:] != payload or u64(record, 36) != generation:
            fail(f"{suite}: NAC payload/generation")
        executed.add(
            "NAC1-SUITE2-MESSAGE1" if suite == "suite_2" else "NAC1-SUITE3-MESSAGE1"
        )

    nas = hx(document["stream_wrapper"]["usb_nas1_hex"], "NAS")
    if (
        len(nas) != document["stream_wrapper"]["usb_nas1_length"]
        or sha(nas).hex() != document["stream_wrapper"]["usb_nas1_sha256"]
        or nas[:4] != b"NAS1"
        or nas[4:6] != bytes((1, 1))
        or u16(nas, 6) != 12
        or u32(nas, 8) != len(nas) - 12
    ):
        fail("NAS")
    validate_nac(nas[12:], "NAS.inner", kind=4, sequence=1, carrier=1)
    executed.add("NAS1-USB-STREAM-RECORD")

    cookie = document["stateless_cookie"]
    if cookie.get("time_bucket_seconds") != COOKIE_TIME_BUCKET_SECONDS:
        fail(
            "cookie time_bucket_seconds must be normative "
            f"{COOKIE_TIME_BUCKET_SECONDS}s (docs/35); "
            f"got {cookie.get('time_bucket_seconds')!r}"
        )
    canonical = hx(cookie["canonical_input_hex"], "cookie input")
    current_secret = hx(cookie["current_secret_hex"], "cookie current secret")
    previous_secret = hx(cookie["previous_secret_hex"], "cookie previous secret")
    current_cookie = hx(cookie["current_cookie_hex"], "cookie")
    source_locator = hx(
        cookie["source_locator_digest_hex"], "cookie source locator"
    )
    m1_suite2 = hx(m1["suite_2"]["hex"], "suite2 cookie M1")
    radio_binding = hx(
        document["carrier_bindings"]["compact_radio"]["digest_hex"],
        "radio binding",
    )
    expected_canonical = (
        b"NINLIL-NAC1-COOKIE-V1"
        + bytes([3])
        + radio_binding
        + source_locator
        + hx(m1["suite_2"]["nac1_hex"], "suite2 cookie NAC")[20:36]
        + hx(m1["suite_2"]["nac1_hex"], "suite2 cookie NAC")[36:44]
        + sha(m1_suite2)
        + cookie["time_bucket"].to_bytes(8, "big")
    )
    if canonical != expected_canonical:
        fail("cookie canonical input")
    if hmac.new(current_secret, canonical, hashlib.sha256).digest() != current_cookie:
        fail("cookie HMAC")
    executed.add("COOKIE-CURRENT-BUCKET-CURRENT-SECRET")
    # The previous vector differs in both bucket and secret, so independently
    # rebuild the canonical suffix rather than trusting a second input field.
    previous_input = canonical[:-8] + (cookie["time_bucket"] - 1).to_bytes(8, "big")
    previous_cookie = hx(
        cookie["previous_bucket_previous_secret_cookie_hex"], "previous cookie"
    )
    if hmac.new(previous_secret, previous_input, hashlib.sha256).digest() != previous_cookie:
        fail("previous cookie")
    executed.add("COOKIE-PREVIOUS-BUCKET-PREVIOUS-SECRET")
    matrix = cookie.get("secret_bucket_matrix")
    if not isinstance(matrix, dict) or len(matrix) != 4:
        fail("cookie matrix size")
    secrets = {
        "current_secret": current_secret,
        "previous_secret": previous_secret,
    }
    buckets = {
        "current_bucket": cookie["time_bucket"],
        "previous_bucket": cookie["time_bucket"] - 1,
    }
    observed_cookies: set[bytes] = set()
    for secret_name, secret in secrets.items():
        for bucket_name, bucket in buckets.items():
            name = f"{secret_name}_x_{bucket_name}"
            item = matrix.get(name)
            if not isinstance(item, dict):
                fail(f"cookie matrix missing {name}")
            expected_input = (
                b"NINLIL-NAC1-COOKIE-V1"
                + bytes([3])
                + radio_binding
                + source_locator
                + hx(m1["suite_2"]["nac1_hex"], "matrix nac")[20:36]
                + hx(m1["suite_2"]["nac1_hex"], "matrix nac")[36:44]
                + sha(m1_suite2)
                + int(bucket).to_bytes(8, "big")
            )
            raw_cookie = hx(item["cookie_hex"], name)
            if (
                item.get("time_bucket") != bucket
                or item.get("secret_name") != secret_name
                or hx(item["canonical_input_hex"], f"{name} input") != expected_input
                or hmac.new(secret, expected_input, hashlib.sha256).digest()
                != raw_cookie
            ):
                fail(f"cookie matrix {name}")
            observed_cookies.add(raw_cookie)
    if len(observed_cookies) != 4:
        fail("cookie matrix not four distinct cookies")
    executed.add("COOKIE-FOUR-COMBINATION-MATRIX")
    # Source/carrier/session mutation of cookie input must change HMAC.
    mutated_source = bytearray(canonical)
    # Flip a source-locator byte after the binding field (label+class+binding).
    source_off = len(b"NINLIL-NAC1-COOKIE-V1") + 1 + 32
    mutated_source[source_off] ^= 1
    if (
        hmac.new(current_secret, bytes(mutated_source), hashlib.sha256).digest()
        == current_cookie
    ):
        fail("cookie source mutation accepted")
    executed.add("COOKIE-SOURCE-CARRIER-SESSION-MUTATION")
    challenge = hx(cookie["challenge_nac1_hex"], "challenge")
    response = hx(cookie["response_nac1_hex"], "response")
    response_payload = hx(cookie["response_payload_hex"], "response payload")
    validate_nac(challenge, "challenge", kind=1, sequence=0, carrier=3)
    validate_nac(response, "response", kind=2, sequence=0, carrier=3)
    if challenge[88:] != current_cookie or response[88:] != response_payload:
        fail("cookie carrier payload")
    if response_payload[:32] != current_cookie:
        fail("cookie response prefix")
    embedded_len = u16(response_payload, 32)
    if embedded_len != len(response_payload) - 34:
        fail("cookie embedded M1 length")
    # Exact COOKIE_RESPONSE length: 88 + 32 + 2 + original_message_1 (suite2 = 37) = 159.
    parts = cookie.get("response_length_parts")
    if (
        len(response) != 159
        or len(response_payload) != 71
        or cookie.get("response_nac1_length") != 159
        or cookie.get("response_payload_length") != 71
        or cookie.get("response_length_formula")
        != "88+32+2+original_message_1_bytes"
        or not isinstance(parts, dict)
        or parts.get("nac1_header_bytes") != 88
        or parts.get("cookie_bytes") != 32
        or parts.get("original_message_1_length_u16be_bytes") != 2
        or parts.get("original_message_1_bytes") != 37
        or parts.get("total_bytes") != 159
        or parts.get("total_bytes") != 88 + 32 + 2 + len(m1_suite2)
        or embedded_len != 37
        or response_payload[34:] != m1_suite2
        or cookie.get("response_fragment_count") != 2
    ):
        fail("cookie response exact length 159")
    executed.add("COOKIE-RESPONSE-EXACT-LENGTH-159")
    cookie_fragments = [
        hx(item["hex"], f"cookie fragment {index}")
        for index, item in enumerate(cookie["response_radio_fragments"])
    ]
    if len(cookie_fragments) != 2:
        fail("cookie fragment count")
    cookie_assembled = bytearray()
    for index, packet in enumerate(cookie_fragments):
        validate_nar(packet, f"cookie fragment {index}")
        item = cookie["response_radio_fragments"][index]
        # JSON index is machine authority: must equal array position and NAR byte.
        if exact_int(item["index"], f"cookie.frag[{index}].index") != index:
            fail(f"cookie fragment {index}: JSON index drift")
        if (
            packet[42] != index
            or packet[42] != exact_int(item["index"], f"cookie.frag[{index}].idx")
            or packet[43] != 2
            or len(packet) != exact_int(item["length"], f"cookie.frag[{index}].len")
            or sha(packet).hex() != exact_str(item["sha256"], f"cookie.frag[{index}].sha")
        ):
            fail(f"cookie fragment {index}: metadata")
        cookie_assembled.extend(packet[68:])
    if bytes(cookie_assembled) != response:
        fail("cookie fragment reassembly")
    if any(
        packet[44:60] != sha(response)[:16] for packet in cookie_fragments
    ):
        fail("cookie fragment digest")
    if cookie["identity_or_authentication_claimed"] is not False:
        fail("cookie nonclaim")
    executed.add("COOKIE-RESPONSE-EXACT-2-FRAGMENT-SCRATCH")

    install = document["attachment_install"]
    nap = hx(install["nap1_hex"], "NAP1")
    nai = hx(install["nai1_hex"], "NAI1")
    nax = hx(install["nax1_hex"], "NAX1")
    nat = hx(install["nat1_hex"], "NAT1")
    # Length scalars are machine authority: pin to bytes, u16 length field, limits.
    if (
        len(nap) != 208
        or exact_int(install["nap1_length"], "install.nap1_length") != 208
        or exact_int(install["nap1_length"], "install.nap1_length")
        != exact_int(limits["nap1_bytes"], "limits.nap1_bytes")
        or nap[:4] != b"NAP1"
        or u16(nap, 4) != 1
        or u16(nap, 6) != 208
        or u16(nap, 6) != install["nap1_length"]
        or sha(nap).hex() != install["nap1_sha256"]
    ):
        fail("NAP1")
    if (
        len(nai) != 416
        or exact_int(install["nai1_length"], "install.nai1_length") != 416
        or exact_int(install["nai1_length"], "install.nai1_length")
        != exact_int(limits["nai1_bytes"], "limits.nai1_bytes")
        or nai[:4] != b"NAI1"
        or u16(nai, 4) != 1
        or u16(nai, 6) != 416
        or u16(nai, 6) != install["nai1_length"]
        or nai[384:416] != sha(nap)
        or sha(nai).hex() != install["nai1_sha256"]
    ):
        fail("NAI1")
    install_digest = sha(b"NINLIL-PRODUCTION-ATTACH-INSTALL-V1" + nap + nai)
    if install_digest.hex() != install["install_digest"]:
        fail("install digest")
    # Byte + adjacent SHA mutation must fail (self-consistency only is insufficient).
    mut_nap = bytearray(nap)
    mut_nap[16] ^= 1
    if sha(bytes(mut_nap)).hex() == install["nap1_sha256"]:
        fail("byte+sha nap mutation accepted")
    if (
        sha(b"NINLIL-PRODUCTION-ATTACH-INSTALL-V1" + bytes(mut_nap) + nai).hex()
        == install["install_digest"]
    ):
        fail("byte+sha install digest mutation accepted")
    executed.add("BYTE-PLUS-SHA-MUTATION")
    pf = install["proposal_fields"]
    # Full NAP1 proposal_fields wire authority (every declarative leaf ↔ bytes).
    if (
        nap[12] != 3
        or nap[13] != 2
        or nap[16:32] != hx(pf["proposal_id"], "proposal_id")
        or nap[32:64]
        != hx(pf["initiator_stable_digest"], "pf.initiator_stable_digest")
        or nap[64:80] != hx(pf["site_domain"], "site_domain")
        or nap[80:96] != hx(pf["authority_id"], "authority_id")
        or u64(nap, 96) != exact_int(pf["authority_term"], "pf.authority_term")
        or u64(nap, 104)
        != exact_int(pf["membership_epoch"], "pf.membership_epoch")
        or u64(nap, 112)
        != exact_int(pf["credential_set_revision"], "pf.credential_set_revision")
        or u32(nap, 120)
        != exact_int(pf["revocation_generation"], "pf.revocation_generation")
        or u32(nap, 124)
        != exact_int(pf["assignment_epoch"], "pf.assignment_epoch")
        or u32(nap, 128)
        != exact_int(pf["device_hop_context_ri"], "pf.device_hop_context_ri")
        or u32(nap, 132)
        != exact_int(pf["device_e2e_context_ri"], "pf.device_e2e_context_ri")
        or u64(nap, 136)
        != exact_int(
            pf["device_hop_min_key_generation_ri"],
            "pf.device_hop_min_key_generation_ri",
        )
        or u64(nap, 144)
        != exact_int(
            pf["device_e2e_min_key_generation_ri"],
            "pf.device_e2e_min_key_generation_ri",
        )
        or nap[152:168] != hx(pf["e2e_security_id"], "pf.e2e_security_id")
        or u64(nap, 168)
        != exact_int(pf["e2e_security_epoch"], "pf.e2e_security_epoch")
        or nap[176:208]
        != hx(pf["membership_grant_digest"], "pf.membership_grant_digest")
    ):
        fail("proposal membership/authority fields")
    iff = install["install_fields"]
    # Full NAI1 install_fields wire authority (every declarative leaf ↔ bytes).
    if (
        nai[16:32] != hx(iff["attachment_id"], "attachment_id")
        or nai[32:64]
        != hx(iff["initiator_stable_digest"], "iff.initiator_stable_digest")
        or nai[64:96]
        != hx(iff["responder_stable_digest"], "iff.responder_stable_digest")
        or nai[96:112] != hx(iff["site_domain"], "install site")
        or nai[112:128] != hx(iff["authority_id"], "install authority")
        or u64(nai, 128)
        != exact_int(iff["authority_term"], "iff.authority_term")
        or u64(nai, 136)
        != exact_int(iff["membership_epoch"], "iff.membership_epoch")
        or u64(nai, 144)
        != exact_int(iff["attachment_epoch"], "iff.attachment_epoch")
        or u64(nai, 152) != exact_int(iff["lease_epoch"], "iff.lease_epoch")
        or nai[160:176]
        != hx(iff["lease_clock_epoch"], "iff.lease_clock_epoch")
        or u64(nai, 176)
        != exact_int(iff["lease_not_before_ms"], "iff.lease_not_before_ms")
        or u64(nai, 184)
        != exact_int(iff["lease_expires_at_ms"], "iff.lease_expires_at_ms")
        or u64(nai, 176) >= u64(nai, 184)
        or u64(nai, 192)
        != exact_int(iff["credential_set_revision"], "iff.credential_set_revision")
        or u32(nai, 200)
        != exact_int(
            iff["initiator_credential_generation"],
            "iff.initiator_credential_generation",
        )
        or u32(nai, 204)
        != exact_int(
            iff["responder_credential_generation"],
            "iff.responder_credential_generation",
        )
        or u32(nai, 208)
        != exact_int(iff["revocation_generation"], "iff.revocation_generation")
        or u32(nai, 212)
        != exact_int(iff["assignment_epoch"], "iff.assignment_epoch")
        or u32(nai, 216) != exact_int(iff["hop_context_ir"], "iff.hop_context_ir")
        or u32(nai, 220) != exact_int(iff["hop_context_ri"], "iff.hop_context_ri")
        or u32(nai, 224) != exact_int(iff["e2e_context_ir"], "iff.e2e_context_ir")
        or u32(nai, 228) != exact_int(iff["e2e_context_ri"], "iff.e2e_context_ri")
        or u64(nai, 232)
        != exact_int(iff["hop_key_generation_ir"], "iff.hop_key_generation_ir")
        or u64(nai, 240)
        != exact_int(iff["hop_key_generation_ri"], "iff.hop_key_generation_ri")
        or u64(nai, 248)
        != exact_int(iff["e2e_key_generation_ir"], "iff.e2e_key_generation_ir")
        or u64(nai, 256)
        != exact_int(iff["e2e_key_generation_ri"], "iff.e2e_key_generation_ri")
        or nai[264:280] != hx(iff["e2e_security_id"], "iff.e2e_security_id")
        or u64(nai, 280)
        != exact_int(iff["e2e_security_epoch"], "iff.e2e_security_epoch")
        or nai[288:320]
        != hx(iff["route_policy_digest"], "iff.route_policy_digest")
        or nai[320:352]
        != hx(iff["membership_grant_digest"], "iff.membership_grant_digest")
        or nai[352:384]
        != hx(iff["carrier_transcript_digest"], "iff.carrier_transcript_digest")
        or nai[384:416]
        != hx(iff["proposal_digest"], "iff.proposal_digest")
        or nai[384:416] != sha(nap)
        or iff["proposal_digest"] != install["nap1_sha256"]
    ):
        fail("install lease/authority fields")
    executed.add("PROPOSAL-MEMBERSHIP-LEASE-AUTHORITY-FIELDS")
    if (
        len(nax) != 160
        or exact_int(install["nax1_length"], "install.nax1_length") != 160
        or exact_int(install["nax1_length"], "install.nax1_length")
        != exact_int(limits["nax1_bytes"], "limits.nax1_bytes")
        or nax[:4] != b"NAX1"
        or u16(nax, 4) != 1
        or u16(nax, 6) != 160
        or u16(nax, 6) != install["nax1_length"]
        or nax[8:10] != bytes((3, 2))
        or nax[100:132]
        != hx(iff["carrier_transcript_digest"], "nax.carrier_transcript")
        or nax[132:148] != hx(iff["authority_id"], "nax.authority_id")
        or u64(nax, 148) != exact_int(iff["authority_term"], "nax.authority_term")
    ):
        fail("NAX1")
    if (
        len(nat) != 96
        or exact_int(install["nat1_length"], "install.nat1_length") != 96
        or exact_int(install["nat1_length"], "install.nat1_length")
        != exact_int(limits["nat1_bytes"], "limits.nat1_bytes")
        or nat[:4] != b"NAT1"
        or u16(nat, 4) != 1
        or u16(nat, 6) != 96
        or u16(nat, 6) != install["nat1_length"]
        or nat[8:40] != install_digest
    ):
        fail("NAT1")
    credentials = document["credentials"]
    initiator_ccs = hx(credentials["initiator_ccs_hex"], "initiator ccs")
    responder_ccs = hx(credentials["responder_ccs_hex"], "responder ccs")
    initiator_kid = hx(credentials["initiator_kid_hex"], "initiator kid")
    responder_kid = hx(credentials["responder_kid_hex"], "responder kid")
    init_key = decode_ccs_cose_key(initiator_ccs, "initiator CCS")
    resp_key = decode_ccs_cose_key(responder_ccs, "responder CCS")
    if (
        credentials["type"] != "RPK_CCS_KID"
        or credentials["curve"] != "P-256"
        or credentials.get("cose_kty") != 2
        or credentials.get("cose_crv") != 1
        or credentials.get("encoding") != "CBOR_CCS_MAP_CNF_COSE_KEY"
        or init_key["kid"] != initiator_kid
        or resp_key["kid"] != responder_kid
        or init_key["x"] != P256_INITIATOR_X
        or init_key["y"] != P256_INITIATOR_Y
        or resp_key["x"] != P256_RESPONDER_X
        or resp_key["y"] != P256_RESPONDER_Y
        or init_key["x"] != hx(credentials["initiator_x_hex"], "init x pin")
        or init_key["y"] != hx(credentials["initiator_y_hex"], "init y pin")
        or resp_key["x"] != hx(credentials["responder_x_hex"], "resp x pin")
        or resp_key["y"] != hx(credentials["responder_y_hex"], "resp y pin")
    ):
        fail("credential CCS/COSE_Key semantic")
    executed.add("CREDENTIAL-CCS-CBOR-DECODE")
    init_digest = sha(initiator_ccs)
    resp_digest = sha(responder_ccs)
    if (
        init_digest.hex() != credentials["initiator_ccs_sha256"]
        or resp_digest.hex() != credentials["responder_ccs_sha256"]
        or init_digest.hex() != credentials["initiator_credential_digest_hex"]
        or resp_digest.hex() != credentials["responder_credential_digest_hex"]
        or nax[36:68] != init_digest
        or nax[68:100] != resp_digest
    ):
        fail("credential digest/NAX binding")
    resolver = hx(credentials["resolver_key_input_hex"], "resolver key")
    expected_resolver = (
        hx(iff["site_domain"], "resolver site")
        + hx(iff["authority_id"], "resolver authority")
        + int(iff["authority_term"]).to_bytes(8, "big")
        + int(iff["credential_set_revision"]).to_bytes(8, "big")
        + bytes([1, len(initiator_kid)])
        + initiator_kid
    )
    if resolver != expected_resolver or sha(resolver).hex() != credentials[
        "resolver_key_sha256"
    ]:
        fail("credential resolver key")
    executed.add("CREDENTIAL-RPK-CCS-KID")
    # Coherent credential-tail mutation: flip last COSE_Key y byte and follow
    # self-hashes/NAX. Independent P-256 pin must still reject.
    mut_ccs = bytearray(initiator_ccs)
    mut_ccs[-1] ^= 1
    mut_digest = sha(bytes(mut_ccs))
    mut_key = decode_ccs_cose_key(bytes(mut_ccs), "mutated initiator CCS")
    if mut_key["y"] == P256_INITIATOR_Y or mut_digest == init_digest:
        fail("credential tail mutation not effective")
    mut_nax = bytearray(nax)
    mut_nax[36:68] = mut_digest
    if mut_nax[36:68] == nax[36:68]:
        fail("coherent NAX digest follow failed")
    # Even with followed digests, y must match independent pin.
    if mut_key["y"] != P256_INITIATOR_Y:
        pass  # rejected against independent constant
    else:
        fail("credential tail mutation accepted against pin")
    executed.add("CREDENTIAL-TAIL-MUTATION")
    # NAP proposed RI vs NAI installed RI: coherent digest follow still rejects.
    if (
        pf["device_hop_context_ri"] != iff["hop_context_ri"]
        or pf["device_e2e_context_ri"] != iff["e2e_context_ri"]
        or pf["device_hop_min_key_generation_ri"] != iff["hop_key_generation_ri"]
        or pf["device_e2e_min_key_generation_ri"] != iff["e2e_key_generation_ri"]
    ):
        fail("NAP/NAI RI context baseline mismatch")
    mut_nap = bytearray(nap)
    mut_nap[128:132] = (int(iff["hop_context_ri"]) ^ 0x5A5A5A5A).to_bytes(4, "big")
    mut_nap_digest = sha(bytes(mut_nap))
    mut_nai = bytearray(nai)
    mut_nai[384:416] = mut_nap_digest
    mut_install_digest = sha(
        b"NINLIL-PRODUCTION-ATTACH-INSTALL-V1" + bytes(mut_nap) + bytes(mut_nai)
    )
    if (
        u32(bytes(mut_nap), 128) == iff["hop_context_ri"]
        or u32(bytes(mut_nap), 128) == u32(nai, 220)
        or mut_install_digest == install_digest
        or mut_nap_digest == sha(nap)
    ):
        fail("NAP/NAI context mismatch not observed after digest follow")
    executed.add("NAP-NAI-CONTEXT-MISMATCH")
    protect_ctx = sha(b"NINLIL-ATTACH-PROTECT-CONTEXT-V1" + nax)
    traffic_ctx = sha(b"NINLIL-ATTACH-TRAFFIC-CONTEXT-V1" + nax + install_digest)
    if protect_ctx.hex() != install["protection_exporter_context_digest"]:
        fail("protection exporter context")
    if traffic_ctx.hex() != install["traffic_exporter_context_digest"]:
        fail("traffic exporter context")
    mutated_nax = bytearray(nax)
    mutated_nax[0] ^= 1
    if sha(b"NINLIL-ATTACH-PROTECT-CONTEXT-V1" + bytes(mutated_nax)).hex() == install[
        "protection_exporter_context_digest"
    ]:
        fail("exporter context one-byte mutation accepted")
    executed.add("EXPORTER-CONTEXT-ONE-BYTE-MUTATION")
    if install["aead_vector_status"] != "INPUTS_PINNED_CIPHERTEXT_NOT_CLAIMED":
        fail("AEAD nonclaim")

    records = install["records"]
    record_matrix = (
        ("propose_seq5", 8, 5, 216),
        ("install_seq6", 9, 6, 424),
        ("confirm_device_seq7", 10, 7, 104),
        ("confirm_authority_seq8", 11, 8, 104),
    )
    decoded_records: dict[str, bytes] = {}
    for name, kind, sequence, payload_bytes in record_matrix:
        record = hx(records[name], name)
        decoded_records[name] = record
        validate_nac(record, name, kind=kind, sequence=sequence, carrier=3)
        if len(record) != 88 + payload_bytes:
            fail(f"{name}: protected payload length")
    # Opaque length scalars must match protected ciphertext+tag payload sizes.
    if (
        exact_int(
            install["proposal_opaque_ciphertext_and_tag_length"],
            "install.proposal_opaque_len",
        )
        != 216
        or exact_int(
            install["proposal_opaque_ciphertext_and_tag_length"],
            "install.proposal_opaque_len",
        )
        != len(decoded_records["propose_seq5"]) - 88
        or exact_int(
            install["opaque_ciphertext_and_tag_length"],
            "install.opaque_len",
        )
        != 424
        or exact_int(
            install["opaque_ciphertext_and_tag_length"],
            "install.opaque_len",
        )
        != len(decoded_records["install_seq6"]) - 88
        or exact_int(
            install["confirm_opaque_ciphertext_and_tag_length"],
            "install.confirm_opaque_len",
        )
        != 104
        or exact_int(
            install["confirm_opaque_ciphertext_and_tag_length"],
            "install.confirm_opaque_len",
        )
        != len(decoded_records["confirm_device_seq7"]) - 88
        or exact_int(
            install["confirm_opaque_ciphertext_and_tag_length"],
            "install.confirm_opaque_len",
        )
        != len(decoded_records["confirm_authority_seq8"]) - 88
    ):
        fail("install opaque length authority")
    if decoded_records["install_seq6"][:84].hex() != install[
        "install_nac1_aad_prefix_hex"
    ]:
        fail("install AAD")
    executed.add("PROTECTED-PROPOSE-INSTALL-DUAL-CONFIRM-SEQUENCE")

    generation = u64(decoded_records["install_seq6"], 36)
    i2r_iv = hx(install["attach_i2r_base_iv13_hex"], "i2r iv")
    r2i_iv = hx(install["attach_r2i_base_iv13_hex"], "r2i iv")
    for name, iv, sequence in (
        ("propose_i2r_seq5", i2r_iv, 5),
        ("install_r2i_seq6", r2i_iv, 6),
        ("confirm_device_i2r_seq7", i2r_iv, 7),
        ("confirm_authority_r2i_seq8", r2i_iv, 8),
    ):
        mask = b"\0" + generation.to_bytes(8, "big") + sequence.to_bytes(4, "big")
        expected = bytes(left ^ right for left, right in zip(iv, mask))
        if hx(install["protection_nonces"][name], name) != expected:
            fail(f"{name}: nonce")
    executed.add("CONTROL-NONCE-SEQUENCE-DIRECTION-EXACT")

    fragments = [
        hx(item["hex"], f"fragment {index}")
        for index, item in enumerate(document["compact_radio_fragments"])
    ]
    if len(fragments) != 5:
        fail("fragment count")
    if exact_int(limits["nar1_fragment_count_max"], "limits.nar1_frag_count") != 5:
        fail("fragment count limit pin")
    assembled = bytearray()
    for index, packet in enumerate(fragments):
        validate_nar(packet, f"fragment {index}")
        item = document["compact_radio_fragments"][index]
        # JSON index is machine authority: must equal array position and NAR byte.
        if exact_int(item["index"], f"frag[{index}].index") != index:
            fail(f"fragment {index}: JSON index drift")
        if (
            packet[42] != index
            or packet[42] != exact_int(item["index"], f"frag[{index}].idx")
            or packet[43] != len(fragments)
            or len(packet) != exact_int(item["length"], f"frag[{index}].len")
            or sha(packet).hex() != exact_str(item["sha256"], f"frag[{index}].sha")
        ):
            fail(f"fragment {index}: metadata")
        assembled.extend(packet[68:])
    complete = bytes(assembled)
    if complete != decoded_records["install_seq6"]:
        fail("fragment reassembly")
    if any(packet[44:60] != sha(complete)[:16] for packet in fragments):
        fail("fragment digest")
    # All install NAR fragments must share session/generation/sequence/record
    # length/digest16; binding is carried by the inner NAC after reassembly.
    expected_generation = u64(complete, 36)
    expected_session = complete[20:36]
    for packet in fragments:
        if (
            packet[12:28] != expected_session
            or u64(packet, 28) != expected_generation
            or u32(packet, 36) != u32(complete, 44)
            or u16(packet, 40) != len(complete)
            or packet[44:60] != sha(complete)[:16]
        ):
            fail("NAR carrier/session/generation/binding tuple")
    # All fragments must share exact generation with complete NAC.
    if any(u64(packet, 28) != expected_generation for packet in fragments):
        fail("NAR exchange generation not uniform")
    # Mixed generation across fragments with repaired CRC must diverge.
    gen_mut = bytearray(fragments[1])
    gen_mut[28:36] = (expected_generation ^ 0x11).to_bytes(8, "big")
    recompute_crc_nar(gen_mut)
    if (
        u64(bytes(gen_mut), 28) == expected_generation
        or u64(bytes(gen_mut), 28) == u64(fragments[0], 28)
        or u64(bytes(gen_mut), 28) == u64(complete, 36)
    ):
        fail("NAR generation mutation not divergent")
    executed.add("NAC1-INSTALL-MAX-RADIO-FRAGMENTATION")
    executed.add("NAR1-EXCHANGE-GENERATION-BINDING")
    validate_nac_nar_adversarial(
        document, decoded_records["install_seq6"], fragments, executed
    )

    attachment_id = hx(iff["attachment_id"], "attachment_id")
    marker = document["n6_attachment_marker"]
    marker_key = hx(marker["key_hex"], "N6AT key")
    marker_value = hx(marker["value_hex"], "N6AT value")
    # Declarative N6 marker metadata must bind to decoded key/value + limits.
    marker_role = exact_int(marker["local_role"], "n6.local_role")
    marker_state = exact_int(marker["state"], "n6.state")
    marker_state_name = exact_str(marker["state_name"], "n6.state_name")
    if (
        marker_role != 1
        or marker_state != 2
        or marker_state_name != N6AT_STATE_NAME[marker_state]
        or marker_state_name != "ACTIVE"
        or exact_int(marker["key_length"], "n6.key_length") != len(marker_key)
        or exact_int(marker["key_length"], "n6.key_length")
        != exact_int(limits["n6at_key_bytes"], "limits.n6at_key")
        or exact_int(marker["value_length"], "n6.value_length") != len(marker_value)
        or exact_int(marker["value_length"], "n6.value_length")
        != exact_int(limits["n6at_value_bytes"], "limits.n6at_value")
        or marker_key[1] != marker_role
        or marker_value[8] != marker_state
        or marker_value[9] != marker_role
    ):
        fail("N6AT marker metadata binding")
    validate_n6at_pair(
        marker_key,
        marker_value,
        role=marker_role,
        state=marker_state,
        attachment_id=attachment_id,
        install_digest=install_digest,
        install_fields=iff,
        field="device ACTIVE N6AT",
    )
    if sha(marker_value).hex() != exact_str(marker["value_sha256"], "n6.vs"):
        fail("N6AT sha")
    # Reserved bytes 10..11 must be zero; repaired-CRC mutation must reject.
    if any(marker_value[10:12]):
        fail("N6AT reserved baseline")
    reserved_mut = bytearray(marker_value)
    reserved_mut[10] = 1
    recompute_crc_n6at(reserved_mut)
    try:
        validate_n6at_pair(
            marker_key,
            bytes(reserved_mut),
            role=1,
            state=2,
            attachment_id=attachment_id,
            install_digest=install_digest,
            install_fields=iff,
            field="N6AT reserved mut",
        )
        fail("N6AT reserved mutation accepted")
    except GateError:
        pass
    executed.add("N6AT-RESERVED-BYTES")
    marker_crc = bytearray(marker_value)
    marker_crc[-1] ^= 1
    if crc32c(marker_crc[:116]) == u32(marker_crc, 116):
        fail("N6AT CRC mutation survived")
    executed.add("N6AT-CRC-MUTATION")
    bad_key = bytes((5, 2, 1, 0)) + marker_key[4:]
    try:
        validate_n6at_pair(
            bad_key,
            marker_value,
            role=1,
            state=2,
            attachment_id=attachment_id,
            install_digest=install_digest,
            install_fields=iff,
            field="N6AT role mismatch",
        )
        fail("N6AT role key/value mismatch accepted")
    except GateError:
        pass
    executed.add("N6AT-ROLE-KEY-VALUE-MISMATCH")
    unknown_state = bytearray(marker_value)
    unknown_state[8] = 4
    recompute_crc_n6at(unknown_state)
    try:
        validate_n6at_pair(
            marker_key,
            bytes(unknown_state),
            role=1,
            state=2,
            attachment_id=attachment_id,
            install_digest=install_digest,
            install_fields=iff,
            field="N6AT unknown",
        )
        fail("N6AT unknown state accepted")
    except GateError:
        pass
    executed.add("N6AT-UNKNOWN-STATE")

    lifecycle = document["lifecycle"]
    roles = lifecycle["roles"]
    for role_name, role in (
        ("device_local_role_1", 1),
        ("authority_local_role_2", 2),
    ):
        role_item = roles[role_name]
        for state_name, state in (
            ("pending", 1),
            ("active", 2),
            ("fenced_third", 3),
        ):
            item = role_item[state_name]
            key = hx(item["key_hex"], f"{role_name} {state_name} key")
            value = hx(item["value_hex"], f"{role_name} {state_name} value")
            # Declarative metadata must match decoded bytes and role binding.
            if exact_int(item["state"], f"{role_name}.{state_name}.state") != state:
                fail(f"{role_name}.{state_name}: state metadata")
            if (
                exact_str(item["state_name"], f"{role_name}.{state_name}.name")
                != N6AT_STATE_NAME[state]
            ):
                fail(f"{role_name}.{state_name}: state_name metadata")
            if value[8] != state or value[9] != role or key[1] != role:
                fail(f"{role_name}.{state_name}: decoded state/role binding")
            if (
                sha(value).hex()
                != exact_str(item["value_sha256"], f"{role_name}.{state_name}.vs")
            ):
                fail(f"{role_name}.{state_name}: value_sha metadata")
            if state == 3:
                if item.get("accepted") is not False or value[8] != 3:
                    fail(f"{role_name} third accepted")
                validate_n6at_pair(
                    key,
                    value,
                    role=role,
                    state=exact_int(item["state"], "third state"),
                    attachment_id=attachment_id,
                    install_digest=install_digest,
                    install_fields=iff,
                    field=f"{role_name} third",
                )
            else:
                validate_n6at_pair(
                    key,
                    value,
                    role=role,
                    state=exact_int(item["state"], "state"),
                    attachment_id=attachment_id,
                    install_digest=install_digest,
                    install_fields=iff,
                    field=f"{role_name} {state_name}",
                )
        # Divergent role/attachment id must reject.
        wrong_role_key = bytes([5, 3 - role, 1, 0]) + attachment_id
        try:
            validate_n6at_pair(
                wrong_role_key,
                hx(role_item["pending"]["value_hex"], "div role val"),
                role=role,
                state=1,
                attachment_id=attachment_id,
                install_digest=install_digest,
                install_fields=iff,
                field=f"{role_name} div role",
            )
            fail("divergent role accepted")
        except GateError:
            pass
        wrong_att = bytes([b ^ 1 for b in attachment_id])
        try:
            validate_n6at_pair(
                bytes([5, role, 1, 0]) + wrong_att,
                hx(role_item["pending"]["value_hex"], "div att val"),
                role=role,
                state=1,
                attachment_id=attachment_id,
                install_digest=install_digest,
                install_fields=iff,
                field=f"{role_name} div att",
            )
            fail("divergent attachment accepted")
        except GateError:
            pass
    executed.add("N6AT-ROLE-SPECIFIC-BOTH")
    pending = lifecycle["pending_marker"]
    pending_key = hx(pending["key_hex"], "pending key")
    pending_value = hx(pending["value_hex"], "pending marker")
    if (
        exact_int(pending["local_role"], "pm.local_role") != 1
        or exact_int(pending["state"], "pm.state") != 1
        or exact_str(pending["state_name"], "pm.name") != "PENDING"
        or pending_value[8] != 1
        or pending_value[9] != 1
        or pending_key[1] != 1
        or sha(pending_value).hex()
        != exact_str(pending["value_sha256"], "pm.vs")
        or pending_key
        != hx(
            lifecycle["roles"]["device_local_role_1"]["pending"]["key_hex"],
            "dev pending key",
        )
        or pending_value
        != hx(
            lifecycle["roles"]["device_local_role_1"]["pending"]["value_hex"],
            "dev pending val",
        )
    ):
        fail("pending_marker metadata/role binding")
    validate_n6at_pair(
        pending_key,
        pending_value,
        role=exact_int(pending["local_role"], "pm role"),
        state=exact_int(pending["state"], "pm state"),
        attachment_id=attachment_id,
        install_digest=install_digest,
        install_fields=iff,
        field="pending marker",
    )
    executed.add("N6AT-PENDING-MARKER")
    p2a = lifecycle["pending_to_active"]
    p2a_old = hx(p2a["old_value_hex"], "p2a old")
    p2a_new = hx(p2a["new_value_hex"], "p2a new")
    if (
        exact_int(p2a["old_state"], "p2a.old_state") != 1
        or exact_int(p2a["new_state"], "p2a.new_state") != 2
        or exact_str(p2a["mutation_kind"], "p2a.kind") != P2A_MUTATION_KIND
        or p2a_old != pending_value
        or p2a_new != marker_value
        or marker_value[8] != 2
        or p2a_old[8] != 1
        or p2a_new[8] != 2
        or sha(p2a_old).hex()
        != exact_str(p2a["old_value_sha256"], "p2a.old_sha")
        or sha(p2a_new).hex()
        != exact_str(p2a["new_value_sha256"], "p2a.new_sha")
    ):
        fail("pending to active")
    executed.add("N6AT-PENDING-TO-ACTIVE")
    cu = lifecycle["commit_unknown"]
    third = hx(cu["third_value_hex"], "third value")
    device_third = hx(
        lifecycle["roles"]["device_local_role_1"]["fenced_third"]["value_hex"],
        "device third",
    )
    accepted_cls = cu.get("accepted_classifications")
    if (
        hx(cu["old_pending_value_hex"], "cu old") != pending_value
        or hx(cu["new_active_value_hex"], "cu new") != marker_value
        or exact_int(cu["third_value_state"], "cu.third_state") != 3
        or third[8] != 3
        or third != device_third
        or exact_bool(cu["third_value_accepted"], "cu.third_acc") is not False
        or cu["accepted_states"] != [1, 2]
        or accepted_cls != CU_ACCEPTED_CLASSIFICATIONS_EXACT
        or len(accepted_cls) != len(set(accepted_cls))
    ):
        fail("commit unknown old/new/third")
    executed.add("N6AT-COMMIT-UNKNOWN-OLD-NEW-THIRD")
    gm = lifecycle["group_machine"]
    if (
        gm["member_count_exact"] != 15
        or gm["old_count_is_protocol_constant"] is not False
        or not 1 <= gm["observed_old_non_absent_count"] <= 14
        or gm["legal_nonempty_lane_old_required"] is not True
        or gm["new_pending_member_count"] != 15
        or gm["partial_member_counts_rejected"] != list(range(1, 15))
        or gm["extra_member_rejected"] is not True
        or gm["third_value_or_digest_mismatch_rejected"] is not True
        or gm["pending_to_active_single_key_full"] is not True
        or gm["publication_before_dual_confirm"] != 0
        or gm["role_attachment_id_must_match"] is not True
    ):
        fail("lifecycle group machine fields")
    # Top-level group_machine role digests/keys must bind to lifecycle.roles.
    device_role = lifecycle["roles"]["device_local_role_1"]
    authority_role = lifecycle["roles"]["authority_local_role_2"]
    if (
        hx(gm["device_pending_key_hex"], "gm.dev.pk")
        != hx(device_role["pending"]["key_hex"], "dev.pending.key")
        or hx(gm["device_pending_value_hex"], "gm.dev.pv")
        != hx(device_role["pending"]["value_hex"], "dev.pending.val")
        or hx(gm["device_active_value_hex"], "gm.dev.av")
        != hx(device_role["active"]["value_hex"], "dev.active.val")
        or hx(gm["authority_pending_key_hex"], "gm.auth.pk")
        != hx(authority_role["pending"]["key_hex"], "auth.pending.key")
        or hx(gm["authority_pending_value_hex"], "gm.auth.pv")
        != hx(authority_role["pending"]["value_hex"], "auth.pending.val")
        or hx(gm["authority_active_value_hex"], "gm.auth.av")
        != hx(authority_role["active"]["value_hex"], "auth.active.val")
        or exact_str(gm["device_complete_keys_concat_sha256"], "gm.dev.concat")
        != exact_str(
            document["atomic_batch_manifests"]["device_local_role_1"][
                "complete_keys_concat_sha256"
            ],
            "dev.nab.concat",
        )
        or exact_str(
            gm["authority_complete_keys_concat_sha256"], "gm.auth.concat"
        )
        != exact_str(
            document["atomic_batch_manifests"]["authority_local_role_2"][
                "complete_keys_concat_sha256"
            ],
            "auth.nab.concat",
        )
    ):
        fail("group_machine role key/value/concat binding")
    for partial in gm["partial_member_counts_rejected"]:
        if not 1 <= partial <= 14:
            fail("partial range")
    # Executable classification: recompute from materialized key lists, do not
    # trust JSON classification strings alone.
    snaps = gm.get("snapshots")
    if not isinstance(snaps, dict) or "roles" not in snaps:
        fail("lifecycle snapshots missing")
    domain = snaps.get("classification_domain")
    if (
        not isinstance(domain, list)
        or domain != CLASSIFICATION_DOMAIN_EXACT
        or len(domain) != len(set(domain))
    ):
        fail("classification_domain exact closed list")
    for role_name, role_key in (
        ("device_local_role_1", 1),
        ("authority_local_role_2", 2),
    ):
        inv = document["atomic_batch_manifests"][role_name]["exact_inventory"]
        ordered = [hx(e["complete_key_hex"], f"{role_name} ok") for e in inv]
        role_item = roles[role_name]
        marker_key = hx(
            role_item["pending"]["key_hex"], f"{role_name} marker key"
        )
        pending_value = hx(
            role_item["pending"]["value_hex"], f"{role_name} pending val"
        )
        active_value = hx(
            role_item["active"]["value_hex"], f"{role_name} active val"
        )
        third_value = hx(
            role_item["fenced_third"]["value_hex"], f"{role_name} third val"
        )
        role_snaps = snaps["roles"][role_name]
        # OLD count is derived from the 15 per-row flags.  At least one
        # canonical lane OLD is mandatory in this fixture.
        old0 = require_keys(
            role_snaps["exact_old"],
            f"{role_name}.exact_old",
            {
                "member_count",
                "present_complete_keys_hex",
                "members",
                "full_image_sha256",
                "classification",
                "commit_unknown_accepted",
                "observed_old_non_absent_count",
                "marker_absent",
            },
        )
        old_members = old0["members"]
        if (
            exact_str(old0["classification"], f"{role_name} old cls")
            != "EXACT_OLD"
            or exact_int(old0["member_count"], f"{role_name} old count")
            != len(old_members)
            or exact_int(
                old0["observed_old_non_absent_count"], f"{role_name} old obs"
            )
            != len(old_members)
            or exact_bool(old0["marker_absent"], f"{role_name} old marker")
            is not True
            or exact_bool(
                old0["commit_unknown_accepted"], f"{role_name} old CU"
            )
            is not True
            or not isinstance(old_members, list)
            or not 1 <= len(old_members) <= 14
            or not any(
                exact_int(m["member_kind"], "old mk") == 1
                for m in old_members
            )
        ):
            fail(f"{role_name}: exact old per-row observed preimage")
        # Independently recompute every observed OLD non-marker codec row.
        old_recomputed = bytearray()
        inv_by_key = {
            exact_str(e["complete_key_hex"], "inv ck"): e for e in inv
        }
        for member in old_members:
            complete = hx(member["complete_key_hex"], "old ck")
            entry = inv_by_key.get(
                exact_str(member["complete_key_hex"], "old ck hex")
            )
            if entry is None:
                fail(f"{role_name}: OLD key not in inventory")
            local_stable = (
                "initiator_stable_digest"
                if role_key == 1
                else "responder_stable_digest"
            )
            peer_stable = (
                "responder_stable_digest"
                if role_key == 1
                else "initiator_stable_digest"
            )
            local_node = r6_node_id16(hx(iff[local_stable], "ls"))
            peer_node = r6_node_id16(hx(iff[peer_stable], "ps"))
            value = materialize_member_value_independent(
                member_kind=exact_int(entry["member_kind"], "old mk"),
                complete_key=complete,
                install_digest=install_digest,
                value_length=exact_int(entry["value_bytes"], "old vb"),
                marker_value=None,
                local_side=exact_int(entry.get("local_side", 0), "old ls"),
                key_generation=exact_int(entry["key_generation"], "old kg"),
                membership_epoch=exact_int(iff["membership_epoch"], "old me"),
                phase="old",
                peer_node_id=peer_node,
                local_node_id=local_node,
                context_id=exact_int(entry["context_id"], "old cid"),
                layer_code=exact_int(entry["layer_code"], "old lc"),
            )
            ctx = sha(
                b"NINLIL-PA-N6-OLD-CTX-DIGEST-V1"
                + bytes([entry["member_kind"]])
                + complete
                + attachment_id
            )
            if (
                value != hx(member["value_hex"], "old val")
                or sha(value).hex()
                != exact_str(member["value_sha256"], "old vs")
                or ctx != hx(member["context_digest_hex"], "old ctx")
                or exact_int(member["member_kind"], "old mmk")
                != exact_int(entry["member_kind"], "old emk")
            ):
                fail(f"{role_name}: OLD value/ctx recompute {entry['identity']}")
            # Permanent negative: synthetic VALUE-V1 filler must not match.
            if value.startswith(b"NINLIL-PA-N6-VALUE-V1") or value[
                :4
            ] not in (b"N6TX", b"N6RX", b"N6AL", b"N6HW"):
                fail(f"{role_name}: OLD not canonical N6 codec")
            old_recomputed.extend(complete + value + ctx)
        old_image = full_image_from_members(old_members)
        if (
            sha(old_image).hex()
            != exact_str(old0["full_image_sha256"], f"{role_name} old img")
            or sha(bytes(old_recomputed)).hex() != old0["full_image_sha256"]
        ):
            fail(f"{role_name}: exact old full_image")
        # NEW members needed for value-image CU of OLD/partial (below).
        snap15_preview = role_snaps["exact_new_pending_15"]
        new_members_preview = snap15_preview["members"]
        if (
            not isinstance(new_members_preview, list)
            or len(new_members_preview) != 15
        ):
            fail(f"{role_name}: NEW members missing for value-image")
        vi_old = classify_write_set_value_image_independent(
            present_members=old_members,
            old_members=old_members,
            new_members=new_members_preview,
            write_set_keys_ordered=ordered,
            marker_key=marker_key,
        )
        if vi_old != "EXACT_OLD":
            fail(f"{role_name}: value-image OLD classification {vi_old}")
        # Permanent negative: empty key-presence is not re-attach EXACT_OLD.
        if (
            classify_group_snapshot_independent(
                present_keys=[],
                expected_keys_ordered=ordered,
                marker_key=marker_key,
                marker_state=None,
                marker_value_ok=True,
            )
            == "EXACT_OLD"
        ):
            fail(f"{role_name}: key-presence empty must not be EXACT_OLD")
        # PARTIAL_n: advanced_to_new_count=n; value-image, not key-presence-only.
        for n in range(1, 15):
            snap = require_keys(
                role_snaps[f"partial_{n}"],
                f"{role_name}.partial_{n}",
                {
                    "member_count",
                    "present_complete_keys_hex",
                    "members",
                    "full_image_sha256",
                    "classification",
                    "commit_unknown_accepted",
                    "advanced_to_new_count",
                },
            )
            members = snap["members"]
            if (
                exact_str(snap["classification"], f"p{n} cls")
                != f"PARTIAL_{n}_CORRUPT"
                or exact_bool(snap["commit_unknown_accepted"], f"p{n} CU")
                is not False
                or exact_int(snap["advanced_to_new_count"], f"p{n} adv") != n
                or not isinstance(members, list)
                or len(members) == 0
            ):
                fail(f"{role_name}: partial {n} classification/CU")
            image = full_image_from_members(members)
            if sha(image).hex() != exact_str(
                snap["full_image_sha256"], f"p{n} img"
            ):
                fail(f"{role_name}: partial {n} full_image_sha256")
            vi_p = classify_write_set_value_image_independent(
                present_members=members,
                old_members=old_members,
                new_members=new_members_preview,
                write_set_keys_ordered=ordered,
                marker_key=marker_key,
            )
            if vi_p != f"PARTIAL_{n}_CORRUPT":
                fail(f"{role_name}: value-image partial {n} got {vi_p}")
        # exact 15 pending with FULL value + context digest binding
        cls = classify_write_set_value_image_independent(
            present_members=new_members_preview,
            old_members=old_members,
            new_members=new_members_preview,
            write_set_keys_ordered=ordered,
            marker_key=marker_key,
        )
        snap15 = require_keys(
            role_snaps["exact_new_pending_15"],
            f"{role_name}.exact_new_pending_15",
            {
                "member_count",
                "present_complete_keys_hex",
                "present_keys_concat_sha256",
                "members",
                "full_image_sha256",
                "marker_state",
                "marker_value_hex",
                "classification",
                "commit_unknown_accepted",
                "value_substitution_rejected",
                "context_digest_substitution_rejected",
            },
        )
        members = snap15["members"]
        if not isinstance(members, list) or len(members) != 15:
            fail(f"{role_name}: NEW members missing")
        expected_concat = sha(b"".join(ordered)).hex()
        if (
            cls != "EXACT_NEW_PENDING_15"
            or exact_str(snap15["classification"], f"{role_name} new cls") != cls
            or exact_bool(
                snap15["commit_unknown_accepted"], f"{role_name} new CU"
            )
            is not True
            or exact_int(snap15["member_count"], f"{role_name} new count") != 15
            or exact_str(
                snap15["present_keys_concat_sha256"],
                f"{role_name} present_keys_concat_sha256",
            )
            != expected_concat
            or [hx(x, "pk") for x in snap15["present_complete_keys_hex"]]
            != ordered
            or exact_int(snap15["marker_state"], f"{role_name} new ms") != 1
            or hx(snap15["marker_value_hex"], f"{role_name} new mv")
            != pending_value
            or pending_value[8] != 1
        ):
            fail(f"{role_name}: exact new pending 15 keys")
        # Independently recompute every non-marker value and context digest.
        # Declarative member metadata must match inventory (not free-floating).
        recomputed_image = bytearray()
        for i, (entry, member) in enumerate(zip(inv, members, strict=True)):
            require_keys(
                member,
                f"{role_name} member",
                {
                    "index",
                    "identity",
                    "complete_key_hex",
                    "complete_key_length",
                    "value_hex",
                    "value_sha256",
                    "context_digest_hex",
                    "member_kind",
                    "value_bytes",
                },
            )
            complete = hx(entry["complete_key_hex"], "e ck")
            if complete != hx(member["complete_key_hex"], "m ck"):
                fail(f"{role_name}: member key mismatch {entry['identity']}")
            # Node ids from install_fields stable digests (role-local).
            local_stable = (
                "initiator_stable_digest"
                if role_key == 1
                else "responder_stable_digest"
            )
            peer_stable = (
                "responder_stable_digest"
                if role_key == 1
                else "initiator_stable_digest"
            )
            local_node = r6_node_id16(hx(iff[local_stable], "ls"))
            peer_node = r6_node_id16(hx(iff[peer_stable], "ps"))
            value = materialize_member_value_independent(
                member_kind=exact_int(entry["member_kind"], "mk"),
                complete_key=complete,
                install_digest=install_digest,
                value_length=exact_int(entry["value_bytes"], "vb"),
                marker_value=pending_value if entry["member_kind"] == 4 else None,
                local_side=exact_int(entry.get("local_side", 0), "ls"),
                key_generation=exact_int(entry["key_generation"], "kg"),
                membership_epoch=exact_int(iff["membership_epoch"], "me"),
                phase="new",
                peer_node_id=peer_node,
                local_node_id=local_node,
                context_id=exact_int(entry["context_id"], "cid"),
                layer_code=exact_int(entry["layer_code"], "lc"),
            )
            ctx = materialize_context_digest_independent(
                member_kind=entry["member_kind"],
                complete_key=complete,
                install_digest=install_digest,
                attachment_id=attachment_id,
            )
            if (
                value != hx(member["value_hex"], "m val")
                or value != hx(entry["value_hex"], "e val")
                or sha(value).hex() != exact_str(member["value_sha256"], "m vs")
                or member["value_sha256"] != entry["value_sha256"]
                or ctx != hx(member["context_digest_hex"], "m ctx")
                or ctx != hx(entry["context_digest_hex"], "e ctx")
                or exact_int(member["index"], f"{role_name} m.idx") != i
                or exact_int(member["index"], f"{role_name} m.idx")
                != exact_int(entry["index"], f"{role_name} e.idx")
                or exact_str(member["identity"], f"{role_name} m.id")
                != exact_str(entry["identity"], f"{role_name} e.id")
                or exact_int(member["member_kind"], f"{role_name} m.mk")
                != exact_int(entry["member_kind"], f"{role_name} e.mk")
                or exact_int(member["complete_key_length"], f"{role_name} m.ckl")
                != len(complete)
                or exact_int(member["complete_key_length"], f"{role_name} m.ckl")
                != exact_int(entry["complete_key_length"], f"{role_name} e.ckl")
                or exact_int(member["value_bytes"], f"{role_name} m.vb")
                != len(value)
                or exact_int(member["value_bytes"], f"{role_name} m.vb")
                != exact_int(entry["value_bytes"], f"{role_name} e.vb")
            ):
                fail(f"{role_name}: value/ctx/metadata recompute {entry['identity']}")
            recomputed_image.extend(complete + value + ctx)
        if sha(bytes(recomputed_image)).hex() != snap15["full_image_sha256"]:
            fail(f"{role_name}: full image sha")
        if sha(bytes(recomputed_image)).hex() != document[
            "atomic_batch_manifests"
        ][role_name]["full_image_sha256"]:
            fail(f"{role_name}: inventory full image sha")
        # Canonical value / context substitution authority (exact index + family).
        validate_substitution_rejected(
            kind="value",
            block=snap15["value_substitution_rejected"],
            base_members=members,
            full_image_sha=snap15["full_image_sha256"],
            field=f"{role_name}.value_substitution_rejected",
        )
        validate_substitution_rejected(
            kind="context",
            block=snap15["context_digest_substitution_rejected"],
            base_members=members,
            full_image_sha=snap15["full_image_sha256"],
            field=f"{role_name}.context_digest_substitution_rejected",
        )
        # Canonical first non-marker index must be used in the vector pin.
        canon_idx = next(
            i for i, m in enumerate(members) if m["member_kind"] != 4
        )
        if (
            exact_int(
                snap15["value_substitution_rejected"]["mutated_index"], "vs idx"
            )
            != canon_idx
            or exact_int(
                snap15["context_digest_substitution_rejected"]["mutated_index"],
                "cds idx",
            )
            != canon_idx
        ):
            fail(f"{role_name}: substitution mutated_index not canonical")
        # extra
        extra = require_keys(
            role_snaps["extra_16"],
            f"{role_name}.extra_16",
            {
                "member_count",
                "foreign_complete_key_hex",
                "classification",
                "commit_unknown_accepted",
            },
        )
        foreign = hx(extra["foreign_complete_key_hex"], f"{role_name} foreign")
        if foreign in set(ordered):
            fail(f"{role_name}: foreign key not foreign")
        if exact_str(extra["classification"], f"{role_name} extra cls") not in (
            "EXTRA_CORRUPT",
            "FOREIGN_OR_EXTRA_CORRUPT",
        ):
            fail(f"{role_name}: extra classification")
        if (
            exact_int(extra["member_count"], f"{role_name} extra count") != 16
            or exact_bool(
                extra["commit_unknown_accepted"], f"{role_name} extra CU"
            )
            is not False
        ):
            fail(f"{role_name}: extra_16 fields")
        # third/mismatch (value-image: marker FENCED is neither OLD nor NEW)
        third_snap = require_keys(
            role_snaps["third_mismatch"],
            f"{role_name}.third_mismatch",
            {
                "member_count",
                "marker_state",
                "marker_value_hex",
                "classification",
                "commit_unknown_accepted",
            },
        )
        third_members = [dict(m) for m in members]
        for i, m in enumerate(third_members):
            if exact_int(m["member_kind"], "tm mk") == 4:
                third_members[i] = dict(m)
                third_members[i]["value_hex"] = exact_str(
                    third_snap["marker_value_hex"], "third mv"
                )
                third_members[i]["value_sha256"] = sha(third_value).hex()
                break
        cls = classify_write_set_value_image_independent(
            present_members=third_members,
            old_members=old_members,
            new_members=members,
            write_set_keys_ordered=ordered,
            marker_key=marker_key,
        )
        if (
            cls != "THIRD_OR_MISMATCH_CORRUPT"
            or exact_str(third_snap["classification"], "third cls") != cls
            or exact_int(third_snap["member_count"], "third count") != 15
            or exact_int(third_snap["marker_state"], "third state") != 3
            or hx(third_snap["marker_value_hex"], "third") != third_value
            or third_value[8] != 3
            or exact_bool(
                third_snap["commit_unknown_accepted"], f"{role_name} third CU"
            )
            is not False
        ):
            fail(f"{role_name}: third mismatch")
        # pending -> active snapshot (full field binding)
        p2a_snap = require_keys(
            role_snaps["pending_to_active"],
            f"{role_name}.pending_to_active",
            {
                "mutation_kind",
                "marker_key_hex",
                "old_state",
                "new_state",
                "old_value_hex",
                "new_value_hex",
                "old_value_sha256",
                "new_value_sha256",
                "accepted",
                "non_marker_rows_unchanged",
            },
        )
        p2a_old_v = hx(p2a_snap["old_value_hex"], "p2a o")
        p2a_new_v = hx(p2a_snap["new_value_hex"], "p2a n")
        if (
            exact_str(p2a_snap["mutation_kind"], "p2a.kind") != P2A_MUTATION_KIND
            or hx(p2a_snap["marker_key_hex"], "p2a.mk") != marker_key
            or exact_int(p2a_snap["old_state"], "p2a old") != 1
            or exact_int(p2a_snap["new_state"], "p2a new") != 2
            or p2a_old_v != pending_value
            or p2a_new_v != active_value
            or pending_value[8] != 1
            or active_value[8] != 2
            or sha(p2a_old_v).hex()
            != exact_str(p2a_snap["old_value_sha256"], "p2a.ovs")
            or sha(p2a_new_v).hex()
            != exact_str(p2a_snap["new_value_sha256"], "p2a.nvs")
            or exact_bool(p2a_snap["accepted"], "p2a accepted") is not True
            or exact_bool(
                p2a_snap["non_marker_rows_unchanged"], "p2a non-marker"
            )
            is not True
        ):
            fail(f"{role_name}: pending to active snapshot")
        # COMMIT_UNKNOWN matrix — closed unique lists + CU flags
        cu_snap = require_keys(
            role_snaps["commit_unknown"],
            f"{role_name}.commit_unknown",
            {
                "accepted_classifications",
                "accepted_snapshots",
                "rejected_snapshot_kinds",
                "active_marker_only",
            },
        )
        accepted = cu_snap["accepted_classifications"]
        if (
            not isinstance(accepted, list)
            or accepted != CU_ACCEPTED_CLASSIFICATIONS_EXACT
            or len(accepted) != len(set(accepted))
        ):
            fail(f"{role_name}: CU accepted set")
        rejected_kinds = cu_snap["rejected_snapshot_kinds"]
        if (
            not isinstance(rejected_kinds, list)
            or rejected_kinds != CU_REJECTED_SNAPSHOT_KINDS_EXACT
            or len(rejected_kinds) != len(set(rejected_kinds))
        ):
            fail(f"{role_name}: CU rejected_snapshot_kinds exact")
        accepted_snaps = cu_snap["accepted_snapshots"]
        if accepted_snaps != ["exact_old", "exact_new_pending_15"]:
            fail(f"{role_name}: accepted_snapshots exact set")
        if len(accepted_snaps) != len(set(accepted_snaps)):
            fail(f"{role_name}: accepted_snapshots duplicate")
        for snap_name in accepted_snaps:
            if (
                exact_bool(
                    role_snaps[snap_name]["commit_unknown_accepted"],
                    f"{role_name} {snap_name} CU",
                )
                is not True
            ):
                fail(f"{role_name}: accepted snapshot {snap_name} CU")
        for rejected in rejected_kinds:
            if rejected == "value_substitution":
                flag = role_snaps["exact_new_pending_15"][
                    "value_substitution_rejected"
                ]["commit_unknown_accepted"]
            elif rejected == "context_digest_substitution":
                flag = role_snaps["exact_new_pending_15"][
                    "context_digest_substitution_rejected"
                ]["commit_unknown_accepted"]
            else:
                flag = role_snaps[rejected]["commit_unknown_accepted"]
            if exact_bool(flag, f"{role_name} rejected {rejected} CU") is not False:
                fail(f"{role_name}: CU rejected {rejected}")
        active_only = require_keys(
            cu_snap["active_marker_only"],
            f"{role_name}.active_marker_only",
            {
                "marker_key_hex",
                "value_hex",
                "value_sha256",
                "classification",
                "commit_unknown_accepted",
            },
        )
        if (
            hx(active_only["marker_key_hex"], "amk") != marker_key
            or hx(active_only["value_hex"], "amv") != active_value
            or sha(active_value).hex()
            != exact_str(active_only["value_sha256"], f"{role_name} am vs")
            or exact_str(
                active_only["classification"], f"{role_name} am cls"
            )
            != "EXACT_NEW_ACTIVE_MARKER"
            or exact_bool(
                active_only["commit_unknown_accepted"], f"{role_name} am CU"
            )
            is not True
        ):
            fail(f"{role_name}: CU active marker only")
        # Full-row donor under same IDs: active value must share attachment id
        # and install digest with pending (only state changes).
        if (
            pending_value[12:28] != active_value[12:28]
            or pending_value[84:116] != active_value[84:116]
            or pending_value[9] != role_key
            or active_value[9] != role_key
        ):
            fail(f"{role_name}: full-row donor identity drift")
        if exact_int(
            role_snaps["publication_before_dual_confirm"],
            f"{role_name} publication",
        ) != 0:
            fail(f"{role_name}: publication zero")
    executed.add("LIFECYCLE-15-KEY-GROUP-MACHINE")
    if lifecycle["publication_before_dual_confirm"] != 0:
        fail("publication before dual confirm")
    executed.add("PUBLICATION-ZERO-BEFORE-DUAL-CONFIRM")

    manifests = document["atomic_batch_manifests"]
    if (
        manifests["status"] != "TEST_ORACLE_ONLY_NOT_WIRE_OR_STORAGE"
        or manifests.get("ordering")
        != "UNSIGNED_BYTE_COMPLETE_KEY_LEXICOGRAPHIC"
    ):
        fail("NAB nonclaim/order")
    context_pins = {
        "hop_ir": ("hop_context_ir", "hop_key_generation_ir"),
        "hop_ri": ("hop_context_ri", "hop_key_generation_ri"),
        "e2e_ir": ("e2e_context_ir", "e2e_key_generation_ir"),
        "e2e_ri": ("e2e_context_ri", "e2e_key_generation_ri"),
    }
    for name, role in (
        ("device_local_role_1", 1),
        ("authority_local_role_2", 2),
    ):
        item = manifests[name]
        batch = hx(item["hex"], name)
        if len(batch) != item["length"] or sha(batch).hex() != item["sha256"]:
            fail(f"{name}: length/digest")
        inventory = item["exact_inventory"]
        validate_nab(batch, role, install_digest, name, inventory)
        concat = b"".join(
            hx(entry["complete_key_hex"], f"{name} ck") for entry in inventory
        )
        if sha(concat).hex() != item["complete_keys_concat_sha256"]:
            fail(f"{name}: complete key concat")
        # Independent recompute of every complete key.
        local_node = r6_node_id16(
            hx(
                iff[
                    "initiator_stable_digest"
                    if role == 1
                    else "responder_stable_digest"
                ],
                "local stable",
            )
        )
        peer_node = r6_node_id16(
            hx(
                iff[
                    "responder_stable_digest"
                    if role == 1
                    else "initiator_stable_digest"
                ],
                "peer stable",
            )
        )
        for i, entry in enumerate(inventory):
            layer = exact_int(entry["layer_code"], f"{name} lc")
            mk = exact_int(entry["member_kind"], f"{name} mk")
            direction = exact_int(entry["direction"], f"{name} dir")
            lane = exact_int(entry["lane"], f"{name} lane")
            recomputed = materialize_complete_key_independent(
                member_kind=mk,
                direction=direction,
                lane=lane,
                local_side=exact_int(entry["local_side"], f"{name} ls"),
                local_role=role,
                context_id=exact_int(entry["context_id"], f"{name} cid"),
                key_generation=exact_int(entry["key_generation"], f"{name} kg"),
                layer_code=layer,
                membership_epoch=int(iff["membership_epoch"]),
                install_digest=install_digest,
                attachment_id=attachment_id,
                local_node_id=local_node,
                peer_node_id=peer_node,
                fields=iff,
            )
            complete = hx(entry["complete_key_hex"], "ck pin")
            if recomputed != complete:
                fail(f"{name}: independent complete key {entry['identity']}")
            # Independent identity label authority (not free text / coherent drift).
            expected_id = expected_inventory_identity(
                member_kind=mk,
                direction=direction,
                lane=lane,
                layer_code=layer,
            )
            identity = exact_str(entry["identity"], f"{name} id")
            if identity != expected_id:
                fail(f"{name}: identity expected {expected_id} got {identity}")
            if exact_int(entry["index"], f"{name} idx") != i:
                fail(f"{name}: inventory index {i}")
            # Pin every context/generation row to install (and proposal RI).
            for prefix, (ctx_name, gen_name) in context_pins.items():
                if identity.startswith(prefix):
                    if (
                        entry["context_id"] != iff[ctx_name]
                        or entry["key_generation"] != iff[gen_name]
                    ):
                        fail(f"{name}: {identity} install pin")
            # Inventory declarative metadata must bind to bytes and known identity.
            value = hx(entry["value_hex"], f"{name} inv val")
            if (
                sha(value).hex()
                != exact_str(entry["value_sha256"], f"{name} inv vs")
                or exact_int(entry["value_bytes"], f"{name} inv vb") != len(value)
                or exact_int(entry["complete_key_length"], f"{name} inv ckl")
                != len(complete)
                or exact_int(entry["key_bytes"], f"{name} inv kb") != len(complete)
            ):
                fail(f"{name}: inventory value_sha/length {identity}")
            if identity == "attachment_marker":
                if (
                    mk != 4
                    or layer != 0
                    or entry["context_id"] != 0
                    or entry["key_generation"] != 0
                    or direction != 0
                    or lane != 0
                ):
                    fail(f"{name}: marker inventory metadata")
                # Marker inventory value is the role pending N6AT value.
                role_pending = hx(
                    document["lifecycle"]["roles"][name]["pending"]["value_hex"],
                    f"{name} role pending",
                )
                if value != role_pending or value[8] != 1 or value[9] != role:
                    fail(f"{name}: marker inventory value binding")
            else:
                if mk == 4 or not identity or identity == "attachment_marker":
                    fail(f"{name}: non-marker identity")
                # Snap15 members must carry the same identity string as inventory.
                snap_members = document["lifecycle"]["group_machine"][
                    "snapshots"
                ]["roles"][name]["exact_new_pending_15"]["members"]
                if (
                    exact_str(
                        snap_members[i]["identity"],
                        f"{name} snap id",
                    )
                    != identity
                    or exact_int(snap_members[i]["index"], f"{name} snap idx") != i
                ):
                    fail(f"{name}: inventory/snap identity {identity}")
    executed.add("NAB1-EXACT-15-MEMBER-SET-BOTH-ROLES")
    executed.add("NAB1-EXACT-KEY-IDENTITY-INVENTORY")
    executed.add("NAB1-CANONICAL-COMPLETE-KEY-ORDER")
    nab_mut = bytearray(hx(manifests["device_local_role_1"]["hex"], "nab mut"))
    nab_mut[60:62] = (14).to_bytes(2, "big")
    recompute_crc_nab(nab_mut)
    try:
        validate_nab(bytes(nab_mut), 1, install_digest, "nab-count-mut")
        fail("NAB count mutation accepted")
    except GateError:
        pass
    # Context substitution with repaired CRC.
    nab_sub = bytearray(hx(manifests["device_local_role_1"]["hex"], "nab sub"))
    nab_sub[72:76] = (0xDEADBEEF).to_bytes(4, "big")
    recompute_crc_nab(nab_sub)
    try:
        validate_nab(
            bytes(nab_sub),
            1,
            install_digest,
            "nab-sub",
            manifests["device_local_role_1"]["exact_inventory"],
        )
        fail("NAB substituted entry accepted")
    except GateError:
        pass
    # Reorder two rows with repaired CRC and inventory swap.
    nab_re = bytearray(hx(manifests["device_local_role_1"]["hex"], "nab re"))
    row0 = bytes(nab_re[68:88])
    row1 = bytes(nab_re[88:108])
    nab_re[68:88] = row1
    nab_re[88:108] = row0
    recompute_crc_nab(nab_re)
    inv_re = list(manifests["device_local_role_1"]["exact_inventory"])
    inv_re[0], inv_re[1] = dict(inv_re[1]), dict(inv_re[0])
    inv_re[0]["index"] = 0
    inv_re[1]["index"] = 1
    try:
        validate_nab(bytes(nab_re), 1, install_digest, "nab-reorder", inv_re)
        fail("NAB reorder accepted")
    except GateError:
        pass
    inv_dup = list(manifests["device_local_role_1"]["exact_inventory"])
    inv_dup[1] = dict(inv_dup[0])
    inv_dup[1]["index"] = 1
    try:
        validate_nab(
            hx(manifests["device_local_role_1"]["hex"], "nab dup"),
            1,
            install_digest,
            "nab-dup",
            inv_dup,
        )
        fail("NAB duplicate inventory accepted")
    except GateError:
        pass
    executed.add("NAB1-DUPLICATE-MISSING-SUBSTITUTED")
    executed.add("NAB1-REORDER-CONTEXT-SUBSTITUTION")
    executed.add("NAB1-CRC-COUNT-ROLE-MUTATION")

    reference = document["rfc9529_method3_suite2_reference"]
    if (
        reference["source"] != "RFC 9529 section 3"
        or reference["method"] != 3
        or reference["selected_suite"] != 2
        or reference["profile_acceptance"] is not False
    ):
        fail("RFC reference metadata")
    for name, expected in RFC9529_MESSAGES.items():
        item = reference["messages"][name]
        raw = hx(item["hex"], f"RFC {name}")
        if (
            raw != expected
            or len(raw) != item["length"]
            or len(raw) != len(expected)
            or sha(raw).hex() != item["sha256"]
            or sha(raw).hex() != sha(expected).hex()
        ):
            fail(f"RFC {name}")
        mut = bytearray(raw)
        mut[0] ^= 1
        if sha(bytes(mut)).hex() == item["sha256"]:
            fail(f"RFC {name} byte+sha mutation accepted")
    executed.add("RFC9529-INDEPENDENT-CONSTANTS")
    executed.add("RFC9529-REFERENCE-DIGESTS")

    missing = REQUIRED_CASES - executed - {"GATE-SELF-TEST"}
    if missing:
        fail(f"required gate cases not executed: {sorted(missing)}")
    return executed


def _mutate_rfc_m1_03_to_04(document: dict[str, Any]) -> None:
    msg = document["rfc9529_method3_suite2_reference"]["messages"]["message_1"]
    raw = bytearray(bytes.fromhex(msg["hex"]))
    if raw[0] != 0x03:
        fail("self-test baseline message_1 not 0x03")
    raw[0] = 0x04
    msg["hex"] = raw.hex()
    msg["sha256"] = hashlib.sha256(bytes(raw)).hexdigest()
    msg["length"] = len(raw)


def _recompute_n6at_crc(value: bytearray) -> None:
    value[116:120] = crc32c(bytes(value[:116])).to_bytes(4, "big")


def _mutate_n6at_authority_field_coherent(
    document: dict[str, Any],
    role_name: str,
    offset: int,
    width: int,
) -> None:
    """Coherently mutate one N6AT authority field; leave install_fields intact.

    Updates role N6AT value bytes + value_sha256 + CRC and device marker
    mirrors so rejection is specifically from N6AT authority binding (not an
    earlier non-coherent digest failure).
    """

    def patch_value(value_hex: str) -> str:
        raw = bytearray(bytes.fromhex(value_hex))
        if width == 8:
            raw[offset : offset + 8] = (0xDEAD_BEEF_CAFE_BABE).to_bytes(8, "big")
        else:
            raw[offset : offset + 4] = (0xDEAD_BEEF).to_bytes(4, "big")
        _recompute_n6at_crc(raw)
        return bytes(raw).hex()

    role = document["lifecycle"]["roles"][role_name]
    for state_name in ("pending", "active", "fenced_third"):
        item = role[state_name]
        new_hex = patch_value(item["value_hex"])
        item["value_hex"] = new_hex
        item["value_sha256"] = hashlib.sha256(bytes.fromhex(new_hex)).hexdigest()
    if role_name == "device_local_role_1":
        pm = document["lifecycle"]["pending_marker"]
        pm["value_hex"] = role["pending"]["value_hex"]
        pm["value_sha256"] = role["pending"]["value_sha256"]
        p2a = document["lifecycle"]["pending_to_active"]
        p2a["old_value_hex"] = role["pending"]["value_hex"]
        p2a["old_value_sha256"] = role["pending"]["value_sha256"]
        p2a["new_value_hex"] = role["active"]["value_hex"]
        p2a["new_value_sha256"] = role["active"]["value_sha256"]
        cu = document["lifecycle"]["commit_unknown"]
        cu["old_pending_value_hex"] = role["pending"]["value_hex"]
        cu["new_active_value_hex"] = role["active"]["value_hex"]
        cu["third_value_hex"] = role["fenced_third"]["value_hex"]
        marker = document["n6_attachment_marker"]
        marker["value_hex"] = role["active"]["value_hex"]
        marker["value_sha256"] = role["active"]["value_sha256"]
        gm = document["lifecycle"]["group_machine"]
        gm["device_pending_value_hex"] = role["pending"]["value_hex"]
        gm["device_active_value_hex"] = role["active"]["value_hex"]
    else:
        gm = document["lifecycle"]["group_machine"]
        gm["authority_pending_value_hex"] = role["pending"]["value_hex"]
        gm["authority_active_value_hex"] = role["active"]["value_hex"]
    # Snapshot mirrors that are compared before later CU matrix.
    snaps = document["lifecycle"]["group_machine"]["snapshots"]["roles"][role_name]
    snaps["third_mismatch"]["marker_value_hex"] = role["fenced_third"]["value_hex"]
    snaps["pending_to_active"]["old_value_hex"] = role["pending"]["value_hex"]
    snaps["pending_to_active"]["new_value_hex"] = role["active"]["value_hex"]
    snaps["pending_to_active"]["old_value_sha256"] = role["pending"]["value_sha256"]
    snaps["pending_to_active"]["new_value_sha256"] = role["active"]["value_sha256"]
    snaps["commit_unknown"]["active_marker_only"]["value_hex"] = role["active"][
        "value_hex"
    ]
    snaps["commit_unknown"]["active_marker_only"]["value_sha256"] = role["active"][
        "value_sha256"
    ]
    snaps["exact_new_pending_15"]["marker_value_hex"] = role["pending"]["value_hex"]
    pending_val = bytes.fromhex(role["pending"]["value_hex"])
    # Keep inventory/snapshot member marker rows coherent with pending NEW image.
    for container in (
        snaps["exact_new_pending_15"]["members"],
        snaps["exact_new_pending_15"]["value_substitution_rejected"]["members"],
        snaps["exact_new_pending_15"]["context_digest_substitution_rejected"][
            "members"
        ],
        document["atomic_batch_manifests"][role_name]["exact_inventory"],
        *[
            snaps[f"partial_{n}"]["members"]
            for n in range(1, 15)
            if snaps[f"partial_{n}"].get("members")
        ],
    ):
        for member in container:
            if member.get("member_kind") == 4:
                member["value_hex"] = pending_val.hex()
                member["value_sha256"] = hashlib.sha256(pending_val).hexdigest()

    def reimage(members: list[dict[str, Any]]) -> str:
        image = b"".join(
            bytes.fromhex(m["complete_key_hex"])
            + bytes.fromhex(m["value_hex"])
            + bytes.fromhex(m["context_digest_hex"])
            for m in members
        )
        return hashlib.sha256(image).hexdigest()

    for n in range(1, 15):
        partial = snaps[f"partial_{n}"]
        if partial.get("members"):
            partial["full_image_sha256"] = reimage(partial["members"])
    new15 = snaps["exact_new_pending_15"]
    new15["full_image_sha256"] = reimage(new15["members"])
    # Force substitution images to remain distinct from NEW image.
    vs_members = new15["value_substitution_rejected"]["members"]
    new15["value_substitution_rejected"]["full_image_sha256"] = reimage(vs_members)
    if (
        new15["value_substitution_rejected"]["full_image_sha256"]
        == new15["full_image_sha256"]
    ):
        # Flip a non-marker value tail after reimage pin to keep divergence.
        for member in vs_members:
            if member["member_kind"] != 4:
                raw = bytearray(bytes.fromhex(member["value_hex"]))
                raw[-1] ^= 1
                member["value_hex"] = bytes(raw).hex()
                member["value_sha256"] = hashlib.sha256(bytes(raw)).hexdigest()
                break
        new15["value_substitution_rejected"]["full_image_sha256"] = reimage(
            vs_members
        )
    cds_members = new15["context_digest_substitution_rejected"]["members"]
    new15["context_digest_substitution_rejected"]["full_image_sha256"] = reimage(
        cds_members
    )
    if (
        new15["context_digest_substitution_rejected"]["full_image_sha256"]
        == new15["full_image_sha256"]
    ):
        for member in cds_members:
            if member["member_kind"] != 4:
                raw = bytearray(bytes.fromhex(member["context_digest_hex"]))
                raw[0] ^= 1
                member["context_digest_hex"] = bytes(raw).hex()
                break
        new15["context_digest_substitution_rejected"]["full_image_sha256"] = reimage(
            cds_members
        )
    man = document["atomic_batch_manifests"][role_name]
    man["full_image_sha256"] = reimage(man["exact_inventory"])


def run_self_test(document: dict[str, Any]) -> None:
    executed = validate(document)
    executed.add("GATE-SELF-TEST")
    if executed != REQUIRED_CASES:
        fail(f"self-test case set mismatch: {sorted(REQUIRED_CASES ^ executed)}")
    mutations: list[tuple[str, Any]] = [
        (
            "profile label",
            lambda d: d["profile"]["exporter_labels"].__setitem__(
                "e2e_ri_secret32", 32774
            ),
        ),
        (
            "NAC CRC",
            lambda d: d["attachment_install"]["records"].__setitem__(
                "install_seq6",
                d["attachment_install"]["records"]["install_seq6"][:-2]
                + (
                    "00"
                    if d["attachment_install"]["records"]["install_seq6"][-2:] != "00"
                    else "01"
                ),
            ),
        ),
        (
            "cookie source",
            lambda d: d["stateless_cookie"].__setitem__(
                "source_locator_digest_hex",
                "00" + d["stateless_cookie"]["source_locator_digest_hex"][2:],
            ),
        ),
        (
            "cookie bucket seconds 2->3",
            lambda d: d["stateless_cookie"].__setitem__(
                "time_bucket_seconds", 3
            ),
        ),
        (
            "proposal digest",
            lambda d: d["attachment_install"].__setitem__(
                "nap1_sha256", "00" * 32
            ),
        ),
        (
            "nonce",
            lambda d: d["attachment_install"]["protection_nonces"].__setitem__(
                "install_r2i_seq6", "00" * 13
            ),
        ),
        (
            "fragment loss",
            lambda d: d["compact_radio_fragments"].pop(),
        ),
        (
            "mixed fragment tuple",
            lambda d: d["compact_radio_fragments"].__setitem__(
                1, d["stateless_cookie"]["response_radio_fragments"][0]
            ),
        ),
        (
            "N6AT role",
            lambda d: d["n6_attachment_marker"].__setitem__(
                "key_hex",
                d["n6_attachment_marker"]["key_hex"][:2]
                + "02"
                + d["n6_attachment_marker"]["key_hex"][4:],
            ),
        ),
        (
            "NAB count",
            lambda d: d["atomic_batch_manifests"]["device_local_role_1"].__setitem__(
                "hex",
                d["atomic_batch_manifests"]["device_local_role_1"]["hex"][:120]
                + "000e"
                + d["atomic_batch_manifests"]["device_local_role_1"]["hex"][124:],
            ),
        ),
        (
            "lifecycle partial accepted flip",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["partial_7"].__setitem__("commit_unknown_accepted", True),
        ),
        (
            "lifecycle exact-old misclassify",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "authority_local_role_2"
            ]["exact_old"].__setitem__("classification", "EXACT_NEW_PENDING_15"),
        ),
        (
            "NEW value_hex coherent follow still fails pin",
            lambda d: (
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"]["members"][0].__setitem__(
                    "value_hex",
                    (
                        bytes.fromhex(
                            d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                                "device_local_role_1"
                            ]["exact_new_pending_15"]["members"][0]["value_hex"]
                        )[:-1]
                        + bytes(
                            [
                                bytes.fromhex(
                                    d["lifecycle"]["group_machine"]["snapshots"][
                                        "roles"
                                    ]["device_local_role_1"][
                                        "exact_new_pending_15"
                                    ]["members"][0]["value_hex"]
                                )[-1]
                                ^ 1
                            ]
                        )
                    ).hex(),
                )
            ),
        ),
        (
            "accepted_classifications coherent pollution",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["commit_unknown"]["accepted_classifications"].append(
                "PARTIAL_1_CORRUPT"
            ),
        ),
        (
            "active_marker_only classification flip",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "authority_local_role_2"
            ]["commit_unknown"]["active_marker_only"].__setitem__(
                "classification", "EXACT_OLD"
            ),
        ),
        (
            "present_complete_keys reorder",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["exact_new_pending_15"]["present_complete_keys_hex"].__setitem__(
                0,
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"]["present_complete_keys_hex"][1],
            ),
        ),
        # Permanent repaired-digest counterexamples (independent PA-S0 audit).
        (
            "CE-present_keys_concat_sha256-change",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["exact_new_pending_15"].__setitem__(
                "present_keys_concat_sha256", "00" * 32
            ),
        ),
        (
            "CE-exact_old-commit_unknown_accepted-false",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["exact_old"].__setitem__("commit_unknown_accepted", False),
        ),
        (
            "CE-active_marker_only-value_sha256-deleted",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["commit_unknown"]["active_marker_only"].pop("value_sha256"),
        ),
        (
            "CE-accepted_snapshots-partial_1-added",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["commit_unknown"]["accepted_snapshots"].append("partial_1"),
        ),
        (
            "CE-value_substitution-classification-change-image-differs",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["exact_new_pending_15"]["value_substitution_rejected"].__setitem__(
                "classification", "EXACT_NEW_PENDING_15"
            ),
        ),
        (
            "CE-value_substitution-CU-flag-true-image-differs",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["exact_new_pending_15"]["value_substitution_rejected"].__setitem__(
                "commit_unknown_accepted", True
            ),
        ),
        (
            "CE-unknown-top-level-key",
            lambda d: d.__setitem__("unexpected_top_key", True),
        ),
        (
            "CE-unknown-nested-key",
            lambda d: d["profile"].__setitem__("unexpected_nested", 1),
        ),
        (
            "CE-bool-as-int-carrier_class",
            lambda d: d["carrier_bindings"]["usb"].__setitem__(
                "carrier_class", True
            ),
        ),
        (
            "CE-rfc-message1-03-to-04-coherent",
            lambda d: _mutate_rfc_m1_03_to_04(d),
        ),
        (
            "CE-coherent-all-metadata-drift",
            lambda d: mutate_all_metadata_coherent(d),
        ),
        (
            "CE-schema-version-drift",
            lambda d: d.__setitem__("schema_version", 99),
        ),
        (
            "CE-tools-path-drift",
            lambda d: d["tools"].__setitem__(
                "generator", "tools/not-the-generator.py"
            ),
        ),
        (
            "CE-lifecycle-constants-value-label-X1",
            lambda d: d["lifecycle_constants"].__setitem__(
                "value_label", "NINLIL-PA-N6-VALUE-X1"
            ),
        ),
        (
            "CE-status-map-accepted-true",
            lambda d: d["status_map"].__setitem__("accepted", True),
        ),
        (
            "CE-attachment_install-unknown-key",
            lambda d: d["attachment_install"].__setitem__(
                "__audit_unknown_key__", True
            ),
        ),
        (
            "CE-install_fields-unknown-key",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "__audit_unknown_key__", True
            ),
        ),
        (
            "CE-compact_radio_fragments0-unknown-key",
            lambda d: d["compact_radio_fragments"][0].__setitem__(
                "__audit_unknown_key__", True
            ),
        ),
        (
            "CE-credentials-unknown-key",
            lambda d: d["credentials"].__setitem__(
                "__audit_unknown_key__", True
            ),
        ),
        # Wire-leaf machine-authority negatives (independent PA-S0 audit P1).
        (
            "CE-cookie-frag0-json-index-drift",
            lambda d: d["stateless_cookie"]["response_radio_fragments"][0].__setitem__(
                "index", 1
            ),
        ),
        (
            "CE-install-frag0-json-index-drift",
            lambda d: d["compact_radio_fragments"][0].__setitem__("index", 1),
        ),
        (
            "CE-nap1-length-drift",
            lambda d: d["attachment_install"].__setitem__("nap1_length", 209),
        ),
        (
            "CE-nai1-length-drift",
            lambda d: d["attachment_install"].__setitem__("nai1_length", 417),
        ),
        (
            "CE-nax1-length-drift",
            lambda d: d["attachment_install"].__setitem__("nax1_length", 161),
        ),
        (
            "CE-nat1-length-drift",
            lambda d: d["attachment_install"].__setitem__("nat1_length", 97),
        ),
        (
            "CE-opaque-ciphertext-length-drift",
            lambda d: d["attachment_install"].__setitem__(
                "opaque_ciphertext_and_tag_length", 425
            ),
        ),
        (
            "CE-proposal-opaque-length-drift",
            lambda d: d["attachment_install"].__setitem__(
                "proposal_opaque_ciphertext_and_tag_length", 217
            ),
        ),
        (
            "CE-confirm-opaque-length-drift",
            lambda d: d["attachment_install"].__setitem__(
                "confirm_opaque_ciphertext_and_tag_length", 105
            ),
        ),
        (
            "CE-iff-carrier-transcript-digest-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "carrier_transcript_digest",
                "0"
                + d["attachment_install"]["install_fields"][
                    "carrier_transcript_digest"
                ][1:],
            ),
        ),
        (
            "CE-iff-e2e-security-id-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "e2e_security_id",
                "0"
                + d["attachment_install"]["install_fields"]["e2e_security_id"][1:],
            ),
        ),
        (
            "CE-iff-initiator-credential-generation-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "initiator_credential_generation", 24
            ),
        ),
        (
            "CE-iff-responder-credential-generation-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "responder_credential_generation", 30
            ),
        ),
        (
            "CE-iff-lease-clock-epoch-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "lease_clock_epoch",
                "0"
                + d["attachment_install"]["install_fields"]["lease_clock_epoch"][
                    1:
                ],
            ),
        ),
        (
            "CE-iff-membership-grant-digest-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "membership_grant_digest",
                "0"
                + d["attachment_install"]["install_fields"][
                    "membership_grant_digest"
                ][1:],
            ),
        ),
        (
            "CE-iff-proposal-digest-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "proposal_digest",
                "1"
                + d["attachment_install"]["install_fields"]["proposal_digest"][1:],
            ),
        ),
        (
            "CE-iff-route-policy-digest-drift",
            lambda d: d["attachment_install"]["install_fields"].__setitem__(
                "route_policy_digest",
                "0"
                + d["attachment_install"]["install_fields"]["route_policy_digest"][
                    1:
                ],
            ),
        ),
        (
            "CE-pf-e2e-security-epoch-drift",
            lambda d: d["attachment_install"]["proposal_fields"].__setitem__(
                "e2e_security_epoch", 74
            ),
        ),
        (
            "CE-pf-e2e-security-id-drift",
            lambda d: d["attachment_install"]["proposal_fields"].__setitem__(
                "e2e_security_id",
                "0"
                + d["attachment_install"]["proposal_fields"]["e2e_security_id"][
                    1:
                ],
            ),
        ),
        (
            "CE-pf-initiator-stable-digest-drift",
            lambda d: d["attachment_install"]["proposal_fields"].__setitem__(
                "initiator_stable_digest",
                "0"
                + d["attachment_install"]["proposal_fields"][
                    "initiator_stable_digest"
                ][1:],
            ),
        ),
        (
            "CE-n6-marker-key-length-drift",
            lambda d: d["n6_attachment_marker"].__setitem__("key_length", 21),
        ),
        (
            "CE-n6-marker-value-length-drift",
            lambda d: d["n6_attachment_marker"].__setitem__("value_length", 121),
        ),
        (
            "CE-n6-marker-local-role-drift",
            lambda d: d["n6_attachment_marker"].__setitem__("local_role", 2),
        ),
        (
            "CE-n6-marker-state-drift",
            lambda d: d["n6_attachment_marker"].__setitem__("state", 3),
        ),
        (
            "CE-n6-marker-state-name-drift",
            lambda d: d["n6_attachment_marker"].__setitem__(
                "state_name", "ACTIVE_DRIFT"
            ),
        ),
        (
            "CE-limits-n6at-key-bytes-drift",
            lambda d: d["limits"].__setitem__("n6at_key_bytes", 21),
        ),
        (
            "CE-control-aead-name-drift",
            lambda d: d["profile"]["control_aead"].__setitem__(
                "name", "AES-CCM-16-64-128_DRIFT"
            ),
        ),
        # Role-surface metadata must not drift while bytes stay fixed.
        (
            "CE-role-surface-pending-state-99",
            lambda d: d["lifecycle"]["roles"]["device_local_role_1"][
                "pending"
            ].__setitem__("state", 99),
        ),
        (
            "CE-role-surface-pending-state-name-drift",
            lambda d: d["lifecycle"]["roles"]["device_local_role_1"][
                "pending"
            ].__setitem__("state_name", "ACTIVE"),
        ),
        (
            "CE-top-pending-marker-local-role-drift",
            lambda d: d["lifecycle"]["pending_marker"].__setitem__(
                "local_role", 2
            ),
        ),
        (
            "CE-top-pending-marker-value-sha-drift",
            lambda d: d["lifecycle"]["pending_marker"].__setitem__(
                "value_sha256", "00" * 32
            ),
        ),
        (
            "CE-top-p2a-old-value-sha-drift",
            lambda d: d["lifecycle"]["pending_to_active"].__setitem__(
                "old_value_sha256", "00" * 32
            ),
        ),
        (
            "CE-coherent-new-member-index-drift",
            lambda d: (
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"]["members"][0].__setitem__("index", 99),
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"]["value_substitution_rejected"][
                    "members"
                ][0].__setitem__("index", 99),
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"][
                    "context_digest_substitution_rejected"
                ]["members"][0].__setitem__("index", 99),
            ),
        ),
        (
            "CE-coherent-inventory-identity-drift",
            lambda d: (
                d["atomic_batch_manifests"]["device_local_role_1"][
                    "exact_inventory"
                ][0].__setitem__(
                    "identity",
                    d["atomic_batch_manifests"]["device_local_role_1"][
                        "exact_inventory"
                    ][0]["identity"]
                    + "_X",
                ),
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"]["members"][0].__setitem__(
                    "identity",
                    d["atomic_batch_manifests"]["device_local_role_1"][
                        "exact_inventory"
                    ][0]["identity"],
                ),
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"]["value_substitution_rejected"][
                    "members"
                ][0].__setitem__(
                    "identity",
                    d["atomic_batch_manifests"]["device_local_role_1"][
                        "exact_inventory"
                    ][0]["identity"],
                ),
                d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                    "device_local_role_1"
                ]["exact_new_pending_15"][
                    "context_digest_substitution_rejected"
                ]["members"][0].__setitem__(
                    "identity",
                    d["atomic_batch_manifests"]["device_local_role_1"][
                        "exact_inventory"
                    ][0]["identity"],
                ),
            ),
        ),
        # Lifecycle matrix P1 (Node-only false-greens on gate 226adb26): both roles.
        (
            "CE-matrix-device-extra-member-count",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["extra_16"].__setitem__("member_count", 17),
        ),
        (
            "CE-matrix-device-third-member-count",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["third_mismatch"].__setitem__("member_count", 16),
        ),
        (
            "CE-matrix-device-third-marker-state",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["third_mismatch"].__setitem__("marker_state", 1),
        ),
        (
            "CE-matrix-device-cu-rejected-empty",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["commit_unknown"].__setitem__("rejected_snapshot_kinds", []),
        ),
        (
            "CE-matrix-device-cu-accepted-class-duplicate",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "device_local_role_1"
            ]["commit_unknown"]["accepted_classifications"].append("EXACT_OLD"),
        ),
        (
            "CE-matrix-authority-extra-member-count",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "authority_local_role_2"
            ]["extra_16"].__setitem__("member_count", 17),
        ),
        (
            "CE-matrix-authority-third-member-count",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "authority_local_role_2"
            ]["third_mismatch"].__setitem__("member_count", 16),
        ),
        (
            "CE-matrix-authority-third-marker-state",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "authority_local_role_2"
            ]["third_mismatch"].__setitem__("marker_state", 1),
        ),
        (
            "CE-matrix-authority-cu-rejected-empty",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "authority_local_role_2"
            ]["commit_unknown"].__setitem__("rejected_snapshot_kinds", []),
        ),
        (
            "CE-matrix-authority-cu-accepted-class-duplicate",
            lambda d: d["lifecycle"]["group_machine"]["snapshots"]["roles"][
                "authority_local_role_2"
            ]["commit_unknown"]["accepted_classifications"].append("EXACT_OLD"),
        ),
    ]
    # Role × 8 N6AT authority-field coherent mutations (install_fields unmoved).
    for role_name in ("device_local_role_1", "authority_local_role_2"):
        for field_name, offset, width in N6AT_AUTHORITY_FIELDS:
            mutations.append(
                (
                    f"CE-n6at-{role_name}-{field_name}-coherent",
                    lambda d, rn=role_name, off=offset, w=width: (
                        _mutate_n6at_authority_field_coherent(d, rn, off, w)
                    ),
                )
            )
    observed = 0
    for name, mutate in mutations:
        changed = copy.deepcopy(document)
        mutate(changed)
        try:
            validate(changed)
        except (GateError, KeyError, TypeError, ValueError):
            observed += 1
        else:
            fail(f"self-test mutation survived: {name}")
    # Strict duplicate-key / non-integer JSON must fail closed.
    raw = VECTOR.read_text(encoding="utf-8")
    schema_pin = '"schema": "ninlil.production-attachment-edhoc.vector.v1"'
    if schema_pin not in raw:
        fail("self-test: schema pin missing from vector text")
    dup_raw = raw.replace(
        schema_pin,
        schema_pin + ', "schema": "dup"',
        1,
    )
    if dup_raw == raw:
        fail("self-test: duplicate-key mutation not applied")
    try:
        load_json_strict_text(dup_raw)
        raise AssertionError("duplicate JSON key accepted")
    except GateError:
        observed += 1
    member_pin = '"member_count_exact": 15'
    if member_pin not in raw:
        fail("self-test: member_count_exact pin missing")
    float_raw = raw.replace(member_pin, '"member_count_exact": 15.0', 1)
    if float_raw == raw:
        fail("self-test: float mutation not applied")
    try:
        load_json_strict_text(float_raw)
        raise AssertionError("non-integer json number accepted")
    except GateError:
        observed += 1
    try:
        load_json_strict_text(
            raw.replace(member_pin, '"member_count_exact": -0', 1)
        )
        raise AssertionError("json -0 accepted")
    except GateError:
        observed += 1
    try:
        load_json_strict_text(
            raw.replace(member_pin, '"member_count_exact": +15', 1)
        )
        raise AssertionError("json +15 accepted")
    except GateError:
        observed += 1
    if observed != len(mutations) + 4:
        fail("self-test mutation count")
    # Exhaustive all-object-path unknown-key probe (parity pin with Node).
    rejected, accepted_n, accepted_paths = run_all_object_path_unknown_key_probe(
        document, validate
    )
    if rejected != OBJECT_PATH_COUNT_EXACT or accepted_n != 0:
        fail(
            "all-object-path unknown-key parity failed: "
            f"rejected={rejected} accepted={accepted_n} "
            f"pin={OBJECT_PATH_COUNT_EXACT} sample={accepted_paths[:5]}"
        )
    observed += rejected
    # Full machine-leaf mutation campaign against static authority
    # (equality + closed schema). Proves every non-descriptive scalar rejects.
    expected_baseline = build_expected_document()

    def _static_validate(doc: dict[str, Any]) -> None:
        # Equality alone rejects any machine scalar drift; closed-schema /
        # unknown-key coverage is the separate all-object-path probe above.
        # The baseline has already passed independent authority, and validate()
        # ran the independent adversarial campaign once above.  Re-running it
        # for every scalar leaf would add no coverage and makes this exhaustive
        # campaign unnecessarily quadratic.
        try:
            assert_document_matches_expected(
                doc,
                expected=expected_baseline,
                run_independent_authority=False,
                run_adversarial_campaign=False,
            )
        except ExpectedModelError as error:
            raise GateError(str(error)) from error

    campaign = run_machine_leaf_mutation_campaign(
        validate=_static_validate,
        document=document,
        include_unknown_key_probe=False,  # covered by 444-path probe above
    )
    observed += campaign["scalar_mutations_tested"]
    print(
        f"production attachment gate self-test OK mutations={observed} "
        f"object_paths={OBJECT_PATH_COUNT_EXACT} unknown_key_rejected={rejected} "
        f"leaf_campaign_tested={campaign['scalar_mutations_tested']} "
        f"leaf_campaign_false_greens={campaign['machine_false_green_count']}"
    )


def load_json_strict_text(text: str) -> dict[str, Any]:
    """Text variant of load_json_strict for self-test raw mutations."""

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                fail(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    try:
        reject_forbidden_json_number_lexemes(text)
        document = json.loads(text, object_pairs_hook=object_pairs)
    except json.JSONDecodeError as error:
        raise GateError(f"json: {error}") from error
    if not isinstance(document, dict):
        fail("root object")
    _reject_non_integer_numbers(document)
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--vector", type=Path, default=VECTOR)
    args = parser.parse_args()
    try:
        document = load_json_strict(args.vector)
        if args.self_test:
            run_self_test(document)
        else:
            validate(document)
            print(
                "production attachment gate OK "
                f"sha256={hashlib.sha256(args.vector.read_bytes()).hexdigest()}"
            )
    except (OSError, json.JSONDecodeError, GateError, KeyError, TypeError, ValueError) as error:
        print(f"production attachment gate FAIL: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
