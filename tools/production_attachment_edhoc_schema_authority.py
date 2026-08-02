#!/usr/bin/env python3
"""Independent PA-S0 closed schema authority (not derived from the vector file).

Hard-coded machine authority for the Proposed Production Attachment EDHOC vector.
Imported by the generator (output self-check) and the Python gate. Node and C
carry independently hard-coded mirrors of the same pins; none of them may
construct the schema by reading or reflecting the vector body.
"""

from __future__ import annotations

from typing import Any, Callable  # noqa: F401 — Callable used by probe helper

# --- Authority envelope pins (independent of vector body) ---

SCHEMA_ID = "ninlil.production-attachment-edhoc.vector.v1"
SCHEMA_VERSION = 1
TITLE = "Ninlil Production Attachment EDHOC PA-S0 Proposed Vector"
ADR = "docs/adr/0023-production-attachment-edhoc-profile.md"
NORMATIVE_DOC = "docs/35-production-attachment-edhoc-profile.md"
STATUS = "PROPOSED_SPEC_ONLY"
PA_TRANCHE = "PA-S0"
PA_TRANCHE_STATE = "IN_PROGRESS"

SOURCES_EXACT = (
    "RFC 9528",
    "RFC 9529",
    "docs/03-identity-and-join.md",
    "docs/30-r6-secure-radio-wire.md",
    "docs/34-r7-t1c-authenticated-hop-fresh-install-owner.md",
    "docs/adr/0017-bearer-registry-path-selection.md",
    "docs/adr/0018-wifi-bearer.md",
    "docs/adr/0022-domain-store-schema1-runtime-binding.md",
    "docs/adr/0023-production-attachment-edhoc-profile.md",
    "docs/35-production-attachment-edhoc-profile.md",
    "spec/protocol-magic-registry-v1.json",
)

NONCLAIMS_EXACT = (
    "NOT_ACCEPTED",
    "NOT_IMPLEMENTATION_COMPLETE",
    "NOT_PRODUCTION",
    "NOT_HIL",
    "NOT_RELEASE_SUPPORTED",
    "NOT_PUBLIC_ABI",
    "TEST_ORACLE_ONLY_MANIFESTS",
)

TOOLS_EXACT = {
    "generator": "tools/production_attachment_edhoc_vector_gen.py",
    "composition": "tools/production_attachment_edhoc_composition.py",
    "expected_model": "tools/production_attachment_edhoc_expected_model.py",
    "independent_authority": (
        "tools/production_attachment_edhoc_independent_authority.py"
    ),
    "python_gate": "tools/production_attachment_edhoc_gate.py",
    "node_gate": "tools/production_attachment_edhoc_gate.mjs",
    "c_test": "tests/radio/production_attachment_edhoc_vector_test.c",
    "schema_authority": "tools/production_attachment_edhoc_schema_authority.py",
    "magic_registry_gate": "tools/protocol_magic_registry_gate.py",
}

STATUS_MAP_EXACT = {
    "vector": STATUS,
    "pa_tranche": PA_TRANCHE,
    "pa_tranche_state": PA_TRANCHE_STATE,
    "accepted": False,
    "implementation": False,
    "hil": False,
    "release": False,
    "spec_accepted": False,
}

LIFECYCLE_CONSTANTS_EXACT = {
    "member_count_exact": 15,
    "old_cardinality_rule": "DERIVED_FROM_15_PER_ROW_OLD_PRESENT_FLAGS",
    "new_pending_member_count": 15,
    "partial_member_counts_rejected": list(range(1, 15)),
    "accepted_classifications": [
        "EXACT_OLD",
        "EXACT_NEW_PENDING_15",
        "EXACT_NEW_ACTIVE_MARKER",
    ],
    "accepted_snapshots": ["exact_old", "exact_new_pending_15"],
    "value_label": "NINLIL-PA-N6-CODEC-V1",
    "ctx_label": "NINLIL-PA-N6-CTX-DIGEST-V1",
    "cookie_time_bucket_seconds": 2,
    "method": 3,
    "rfc_message_1_method_byte": 3,
    "nac1_header_bytes": 88,
    "nab1_entry_count": 15,
}

REQUIRED_GATE_CASES_EXACT = (
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
)

ROOT_REQUIRED = frozenset(
    {
        "schema",
        "schema_version",
        "title",
        "adr",
        "normative_doc",
        "status",
        "status_map",
        "sources",
        "nonclaims",
        "tools",
        "lifecycle_constants",
        "limits",
        "profile",
        "rfc9529_method3_suite2_reference",
        "edhoc_message_1",
        "stream_wrapper",
        "stateless_cookie",
        "attachment_install",
        "carrier_bindings",
        "carrier_transcript",
        "compact_radio_fragments",
        "nar1_reassembly",
        "nas1_stream_lifecycle",
        "preauth_owner",
        "magic_registry",
        "prerequisites",
        "edhoc_attempts",
        "credentials",
        "n6_attachment_marker",
        "lifecycle",
        "atomic_batch_manifests",
        "required_gate_cases",
    }
)


class SchemaError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise SchemaError(message)


def exact_int(value: Any, field: str) -> int:
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


def closed(
    obj: Any,
    path: str,
    *,
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(obj, dict):
        fail(f"{path}: expected object")
    opt = set(optional or ())
    keys = set(obj.keys())
    req = set(required)
    missing = req - keys
    if missing:
        fail(f"{path}: missing keys {sorted(missing)}")
    unknown = keys - req - opt
    if unknown:
        fail(f"{path}: unknown keys {sorted(unknown)}")
    return obj


def arr(obj: Any, path: str) -> list[Any]:
    if not isinstance(obj, list):
        fail(f"{path}: expected array")
    return obj


def assert_envelope(document: dict[str, Any]) -> None:
    """Exact authority envelope: metadata pins independent of body digests."""
    root = closed(document, "$", required=ROOT_REQUIRED)
    if exact_str(root["schema"], "$.schema") != SCHEMA_ID:
        fail("$.schema pin")
    if exact_int(root["schema_version"], "$.schema_version") != SCHEMA_VERSION:
        fail("$.schema_version pin")
    if exact_str(root["title"], "$.title") != TITLE:
        fail("$.title pin")
    if exact_str(root["adr"], "$.adr") != ADR:
        fail("$.adr pin")
    if exact_str(root["normative_doc"], "$.normative_doc") != NORMATIVE_DOC:
        fail("$.normative_doc pin")
    if exact_str(root["status"], "$.status") != STATUS:
        fail("$.status pin")

    sources = arr(root["sources"], "$.sources")
    if sources != list(SOURCES_EXACT):
        fail("$.sources exact list pin")
    nonclaims = arr(root["nonclaims"], "$.nonclaims")
    if nonclaims != list(NONCLAIMS_EXACT):
        fail("$.nonclaims exact list pin")

    tools = closed(root["tools"], "$.tools", required=set(TOOLS_EXACT.keys()))
    for key, expected in TOOLS_EXACT.items():
        if exact_str(tools[key], f"$.tools.{key}") != expected:
            fail(f"$.tools.{key} pin")

    sm = closed(
        root["status_map"], "$.status_map", required=set(STATUS_MAP_EXACT.keys())
    )
    for key, expected in STATUS_MAP_EXACT.items():
        if type(expected) is bool:
            if exact_bool(sm[key], f"$.status_map.{key}") is not expected:
                fail(f"$.status_map.{key} pin")
        else:
            if exact_str(sm[key], f"$.status_map.{key}") != expected:
                fail(f"$.status_map.{key} pin")

    lc = closed(
        root["lifecycle_constants"],
        "$.lifecycle_constants",
        required=set(LIFECYCLE_CONSTANTS_EXACT.keys()),
    )
    for key, expected in LIFECYCLE_CONSTANTS_EXACT.items():
        if isinstance(expected, list):
            got = arr(lc[key], f"$.lifecycle_constants.{key}")
            if got != expected:
                fail(f"$.lifecycle_constants.{key} pin")
            if key == "partial_member_counts_rejected":
                for item in got:
                    exact_int(item, f"$.lifecycle_constants.{key}[]")
            elif key == "accepted_classifications" or key == "accepted_snapshots":
                for item in got:
                    exact_str(item, f"$.lifecycle_constants.{key}[]")
        elif type(expected) is int:
            if exact_int(lc[key], f"$.lifecycle_constants.{key}") != expected:
                fail(f"$.lifecycle_constants.{key} pin")
        else:
            if exact_str(lc[key], f"$.lifecycle_constants.{key}") != expected:
                fail(f"$.lifecycle_constants.{key} pin")

    cases = arr(root["required_gate_cases"], "$.required_gate_cases")
    if cases != list(REQUIRED_GATE_CASES_EXACT):
        fail("$.required_gate_cases exact pin")
    for item in cases:
        exact_str(item, "$.required_gate_cases[]")


def envelope_document_fragment() -> dict[str, Any]:
    """Canonical envelope fields for generator emission."""
    return {
        "schema": SCHEMA_ID,
        "schema_version": SCHEMA_VERSION,
        "title": TITLE,
        "adr": ADR,
        "normative_doc": NORMATIVE_DOC,
        "status": STATUS,
        "status_map": dict(STATUS_MAP_EXACT),
        "sources": list(SOURCES_EXACT),
        "nonclaims": list(NONCLAIMS_EXACT),
        "tools": dict(TOOLS_EXACT),
        "lifecycle_constants": {
            **{
                k: (list(v) if isinstance(v, list) else v)
                for k, v in LIFECYCLE_CONSTANTS_EXACT.items()
            }
        },
        "required_gate_cases": list(REQUIRED_GATE_CASES_EXACT),
    }


def mutate_all_metadata_coherent(document: dict[str, Any]) -> None:
    """Coherent all-metadata drift used as permanent false-green probe."""
    document["schema"] = "ninlil.production-attachment-edhoc.vector.v1-DRIFT"
    document["schema_version"] = SCHEMA_VERSION + 1
    document["title"] = TITLE + " DRIFT"
    document["adr"] = "docs/adr/9999-drift.md"
    document["normative_doc"] = "docs/99-drift.md"
    document["status"] = "DRIFTED_STATUS"
    document["status_map"] = {
        "vector": "DRIFTED_STATUS",
        "pa_tranche": "PA-S0",
        "pa_tranche_state": "DRIFTED",
        "accepted": True,
        "implementation": True,
        "hil": True,
        "release": True,
        "spec_accepted": True,
    }
    document["sources"] = list(SOURCES_EXACT) + ["docs/drift.md"]
    document["nonclaims"] = ["DRIFTED"]
    document["tools"] = {
        **TOOLS_EXACT,
        "generator": "tools/drift_gen.py",
    }
    document["lifecycle_constants"] = {
        **LIFECYCLE_CONSTANTS_EXACT,
        "value_label": "NINLIL-PA-N6-VALUE-X1",
        "member_count_exact": 16,
    }


# Hard-coded closed key schema path (authored independently of vector body).
CLOSED_KEY_SCHEMA_RELPATH = "tools/production_attachment_edhoc_closed_key_schema.json"
# Exhaustive object-path count pin (unknown-key mutation coverage).
OBJECT_PATH_COUNT_EXACT = 829
AUDIT_UNKNOWN_KEY = "__audit_unknown_key__"


def load_closed_key_schema(root: Any = None) -> dict[str, Any]:
    """Load committed closed-key schema (not constructed from the vector)."""
    from pathlib import Path

    if root is None:
        root = Path(__file__).resolve().parents[1]
    else:
        root = Path(root)
    path = root / CLOSED_KEY_SCHEMA_RELPATH
    text = path.read_text(encoding="utf-8")
    import json

    schema = json.loads(text)
    if not isinstance(schema, dict) or schema.get("_t") != "obj":
        fail("closed key schema root")
    return schema


def walk_closed_keys(
    value: Any,
    schema: dict[str, Any],
    path: str = "$",
    *,
    object_paths: list[str] | None = None,
) -> None:
    """Recursive closed-key walk: every object/array member path is checked."""
    node_type = schema.get("_t")
    if node_type == "obj":
        if not isinstance(value, dict):
            fail(f"{path}: expected object")
        if object_paths is not None:
            object_paths.append(path)
        keys = set(value.keys())
        expected = set(schema["k"].keys())
        missing = expected - keys
        if missing:
            fail(f"{path}: missing keys {sorted(missing)}")
        unknown = keys - expected
        if unknown:
            fail(f"{path}: unknown keys {sorted(unknown)}")
        for key, child_schema in schema["k"].items():
            walk_closed_keys(
                value[key],
                child_schema,
                f"{path}.{key}",
                object_paths=object_paths,
            )
        return
    if node_type == "arr":
        if not isinstance(value, list):
            fail(f"{path}: expected array")
        item_schema = schema["item"]
        for index, item in enumerate(value):
            walk_closed_keys(
                item,
                item_schema,
                f"{path}[{index}]",
                object_paths=object_paths,
            )
        return
    if node_type == "str":
        if type(value) is not str:
            fail(f"{path}: expected str")
        return
    if node_type == "int":
        if type(value) is not int:
            fail(f"{path}: expected exact int")
        return
    if node_type == "bool":
        if type(value) is not bool:
            fail(f"{path}: expected exact bool")
        return
    fail(f"{path}: bad schema node type {node_type!r}")


def collect_object_paths(document: dict[str, Any], schema: dict[str, Any] | None = None) -> list[str]:
    paths: list[str] = []
    if schema is None:
        schema = load_closed_key_schema()
    walk_closed_keys(document, schema, "$", object_paths=paths)
    return paths


def assert_closed_key_schema(document: dict[str, Any], *, root: Any = None) -> list[str]:
    """Envelope + full recursive closed-key walk; returns object paths."""
    assert_envelope(document)
    schema = load_closed_key_schema(root)
    paths = collect_object_paths(document, schema)
    if len(paths) != OBJECT_PATH_COUNT_EXACT:
        fail(
            f"object path count {len(paths)} != pin {OBJECT_PATH_COUNT_EXACT}"
        )
    return paths


def inject_unknown_at_path(document: dict[str, Any], path: str) -> dict[str, Any]:
    """Deep-copy document and inject AUDIT_UNKNOWN_KEY at object path."""
    import copy
    import re

    out = copy.deepcopy(document)
    if path == "$":
        out[AUDIT_UNKNOWN_KEY] = True
        return out
    node: Any = out
    for name, idx in re.findall(r"\.([A-Za-z0-9_]+)|\[(\d+)\]", path):
        if name:
            node = node[name]
        else:
            node = node[int(idx)]
    if not isinstance(node, dict):
        fail(f"inject path not object: {path}")
    node[AUDIT_UNKNOWN_KEY] = True
    return out


def run_all_object_path_unknown_key_probe(
    document: dict[str, Any],
    validate_fn: Callable[[dict[str, Any]], Any],
) -> tuple[int, int, list[str]]:
    """Return (rejected, accepted_count, accepted_paths)."""
    paths = assert_closed_key_schema(document)
    accepted: list[str] = []
    rejected = 0
    for path in paths:
        mutated = inject_unknown_at_path(document, path)
        try:
            validate_fn(mutated)
        except Exception:
            rejected += 1
        else:
            accepted.append(path)
    return rejected, len(accepted), accepted
