#!/usr/bin/env python3
"""Independent R7 T1b context-binding / HKDF oracle (stdlib only; docs/33 §§3-4,7-9).

Authority is docs/33 only. Does not import production C helpers, OpenSSL
bindings, cryptography, or the generated C header as input authority.

Artifact paths (T1b subset; NOT full r7-radio-wire-v1.json):
  tools/r7_t1b_binding_oracle.py
  spec/vectors/r7-t1b-binding-subset.json
  tests/radio/private/r7_t1b_binding_vectors.h

PASS ≠ T1b implementation acceptance / HIL / R7 complete.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import hmac
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

REPO = pathlib.Path(__file__).resolve().parents[1]
JSON_PATH = REPO / "spec" / "vectors" / "r7-t1b-binding-subset.json"
HEADER_PATH = REPO / "tests" / "radio" / "private" / "r7_t1b_binding_vectors.h"

FORMAT_ID = "ninlil-r7-t1b-binding-subset-v1"
ARTIFACT = "ninlil_r7_t1b_binding_subset"
SCHEMA_VERSION = 1

WIRE_PROFILE_ID = 0x11
ALLOWED_KIND_MASK = 0x0003
ENV_LAB = 1
ENV_FIELD = 2

UINT64_MAX = (1 << 64) - 1
UINT32_MAX = (1 << 32) - 1
CONTEXT_ID_MIN = 1
CONTEXT_ID_MAX = UINT32_MAX - 1

HOP_LABEL = b"NINLIL-R6-HOP-CTX-v1"
E2E_LABEL = b"NINLIL-R6-E2E-CTX-v1"

LABEL_HOP_DATA_KEY = b"NINLIL-R6-HOP-DATA-KEY-v1"  # 25
LABEL_HOP_DATA_IV = b"NINLIL-R6-HOP-DATA-IV-v1"  # 24
LABEL_HOP_ACK_KEY = b"NINLIL-R6-HOP-ACK-KEY-v1"  # 24
LABEL_HOP_ACK_IV = b"NINLIL-R6-HOP-ACK-IV-v1"  # 23
LABEL_E2E_KEY = b"NINLIL-R6-E2E-KEY-v1"  # 20
LABEL_E2E_IV = b"NINLIL-R6-E2E-IV-v1"  # 19

# Exact 24 IDs from docs/33 §9 — sorted multiset authority.
MANDATORY_IDS: tuple[str, ...] = (
    "R7-T1B-E2E-FIELD-D0-MAX",
    "R7-T1B-E2E-FIELD-D0-MIN",
    "R7-T1B-E2E-FIELD-D1-MAX",
    "R7-T1B-E2E-FIELD-D1-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-FIELD-D0-MAX",
    "R7-T1B-HOP-FIELD-D0-MIN",
    "R7-T1B-HOP-FIELD-D1-MAX",
    "R7-T1B-HOP-FIELD-D1-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MIN",
)

assert len(MANDATORY_IDS) == 24
assert len(set(MANDATORY_IDS)) == 24
assert list(MANDATORY_IDS) == sorted(MANDATORY_IDS)

# Manifest build order (layer × env × direction × size); sorted on emit.
_MANIFEST_BUILD_ORDER: tuple[str, ...] = (
    "R7-T1B-HOP-FIELD-D0-MIN",
    "R7-T1B-HOP-FIELD-D0-MAX",
    "R7-T1B-HOP-FIELD-D1-MIN",
    "R7-T1B-HOP-FIELD-D1-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-FIELD-D0-MIN",
    "R7-T1B-E2E-FIELD-D0-MAX",
    "R7-T1B-E2E-FIELD-D1-MIN",
    "R7-T1B-E2E-FIELD-D1-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MAX",
)

assert set(_MANIFEST_BUILD_ORDER) == set(MANDATORY_IDS)

NON_CLAIMS: tuple[str, ...] = (
    "T1b binding/HKDF subset only",
    "not full r7-radio-wire-v1.json materialization",
    "not T1b implementation acceptance",
    "not HIL evidence",
    "not R7 complete",
)


# ---------------------------------------------------------------------------
# Crypto (stdlib hashlib/hmac only)
# ---------------------------------------------------------------------------


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_extract_sha256(salt: bytes, ikm: bytes) -> bytes:
    """RFC 5869 Extract; empty salt becomes HashLen zeros (not used by T1b)."""
    if len(salt) == 0:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand_sha256(prk: bytes, info: bytes, okm_len: int) -> bytes:
    if len(prk) != 32:
        raise ValueError("prk must be 32 bytes")
    if okm_len <= 0 or okm_len > 255 * 32:
        raise ValueError("okm_len out of range")
    if b"\x00" in info:
        raise ValueError("T1b HKDF labels must not contain NUL")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < okm_len:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:okm_len]


def to_hex(data: bytes) -> str:
    return data.hex()  # canonical lowercase


def from_hex(text: str) -> bytes:
    if text != text.lower():
        raise ValueError("hex must be lowercase")
    return bytes.fromhex(text)


# ---------------------------------------------------------------------------
# encode_canon (docs/33 §4 / R6 §8 immutable)
# ---------------------------------------------------------------------------


def _opaque(value: bytes) -> bytes:
    if len(value) > 0xFFFF:
        raise ValueError("opaque too long")
    return len(value).to_bytes(2, "big") + value


def encode_hop_binding(
    *,
    environment_code: int,
    site_domain: bytes,
    membership_epoch: int,
    attachment_id: bytes,
    attachment_epoch: int,
    initiator_stable_id: bytes,
    responder_stable_id: bytes,
    controller_authority_id: bytes,
    controller_term: int,
    hop_context_id: int,
    direction_code: int,
) -> bytes:
    return b"".join(
        (
            HOP_LABEL,
            bytes((WIRE_PROFILE_ID, environment_code & 0xFF)),
            _opaque(site_domain),
            membership_epoch.to_bytes(8, "big"),
            _opaque(attachment_id),
            attachment_epoch.to_bytes(8, "big"),
            _opaque(initiator_stable_id),
            _opaque(responder_stable_id),
            _opaque(controller_authority_id),
            controller_term.to_bytes(8, "big"),
            hop_context_id.to_bytes(4, "big"),
            bytes((direction_code & 0xFF,)),
            ALLOWED_KIND_MASK.to_bytes(2, "big"),
        )
    )


def encode_e2e_binding(
    *,
    environment_code: int,
    site_domain: bytes,
    membership_epoch: int,
    e2e_security_id: bytes,
    e2e_security_epoch: int,
    sender_stable_id: bytes,
    receiver_stable_id: bytes,
    authority_id: bytes,
    authority_term: int,
    e2e_context_id: int,
    direction_code: int,
) -> bytes:
    return b"".join(
        (
            E2E_LABEL,
            bytes((WIRE_PROFILE_ID, environment_code & 0xFF)),
            _opaque(site_domain),
            membership_epoch.to_bytes(8, "big"),
            _opaque(e2e_security_id),
            e2e_security_epoch.to_bytes(8, "big"),
            _opaque(sender_stable_id),
            _opaque(receiver_stable_id),
            _opaque(authority_id),
            authority_term.to_bytes(8, "big"),
            e2e_context_id.to_bytes(4, "big"),
            bytes((direction_code & 0xFF,)),
        )
    )


def derive_hop_bundle(digest32: bytes, traffic_secret32: bytes) -> dict[str, bytes]:
    if len(digest32) != 32 or len(traffic_secret32) != 32:
        raise ValueError("digest/traffic_secret must be 32 bytes")
    prk = hkdf_extract_sha256(digest32, traffic_secret32)
    return {
        "prk": prk,
        "data_key16": hkdf_expand_sha256(prk, LABEL_HOP_DATA_KEY, 16),
        "data_iv12": hkdf_expand_sha256(prk, LABEL_HOP_DATA_IV, 12),
        "ack_key16": hkdf_expand_sha256(prk, LABEL_HOP_ACK_KEY, 16),
        "ack_iv12": hkdf_expand_sha256(prk, LABEL_HOP_ACK_IV, 12),
    }


def derive_e2e_bundle(digest32: bytes, traffic_secret32: bytes) -> dict[str, bytes]:
    if len(digest32) != 32 or len(traffic_secret32) != 32:
        raise ValueError("digest/traffic_secret must be 32 bytes")
    prk = hkdf_extract_sha256(digest32, traffic_secret32)
    return {
        "prk": prk,
        "key16": hkdf_expand_sha256(prk, LABEL_E2E_KEY, 16),
        "iv12": hkdf_expand_sha256(prk, LABEL_E2E_IV, 12),
    }


# ---------------------------------------------------------------------------
# Fixture material (semantic inputs per ID)
# ---------------------------------------------------------------------------


def _fill(seed: int, length: int) -> bytes:
    """Deterministic non-zero-friendly fill; FIELD site never all-zero."""
    if length < 0:
        raise ValueError("length")
    return bytes(((seed + i) % 255) + 1 for i in range(length))


def _parse_vector_id(vector_id: str) -> tuple[str, str, int, str]:
    """Return (layer, environment_tag, direction_code, size_class)."""
    parts = vector_id.split("-")
    if len(parts) < 6 or parts[0] != "R7" or parts[1] != "T1B":
        raise ValueError(f"bad id: {vector_id}")
    layer = parts[2].lower()
    size_class = parts[-1].lower()
    direction = parts[-2]
    if not direction.startswith("D") or len(direction) != 2:
        raise ValueError(f"bad direction in id: {vector_id}")
    direction_code = int(direction[1])
    env_token = "-".join(parts[3:-2])
    return layer, env_token, direction_code, size_class


def _env_code(env_token: str) -> int:
    if env_token == "FIELD":
        return ENV_FIELD
    if env_token in ("LAB-CONTROLLER", "LAB-NO-CONTROLLER"):
        return ENV_LAB
    raise ValueError(f"unknown env token: {env_token}")


def _environment_name(env_token: str) -> str:
    return {
        "FIELD": "field",
        "LAB-CONTROLLER": "lab_controller",
        "LAB-NO-CONTROLLER": "lab_no_controller",
    }[env_token]


def _lengths(env_token: str, size_class: str) -> tuple[int, int, int, int, int]:
    """Return (site, primary, left, right, authority) opaque lengths."""
    no_controller = env_token == "LAB-NO-CONTROLLER"
    if size_class == "min":
        site = 16 if env_token == "FIELD" else 1
        body = 1
        auth = 0 if no_controller else 1
        return site, body, body, body, auth
    if size_class == "max":
        site = 16
        body = 32
        auth = 0 if no_controller else 32
        return site, body, body, body, auth
    raise ValueError(size_class)


def _epochs_and_context(
    env_token: str, size_class: str
) -> tuple[int, int, int, int]:
    """membership, primary_epoch, authority_term, context_id."""
    no_controller = env_token == "LAB-NO-CONTROLLER"
    if size_class == "min":
        membership = 1
        primary = 1
        term = 0 if no_controller else 1
        context = CONTEXT_ID_MIN
        return membership, primary, term, context
    # MAX: pin UINT64_MAX on every relevant epoch/term field (docs/33 §9).
    membership = UINT64_MAX
    primary = UINT64_MAX
    term = 0 if no_controller else UINT64_MAX
    context = CONTEXT_ID_MAX
    return membership, primary, term, context


def traffic_secret_for(vector_id: str) -> bytes:
    return sha256(b"ninlil-r7-t1b-traffic-secret32|" + vector_id.encode("ascii"))


def build_semantic_inputs(vector_id: str) -> dict[str, Any]:
    layer, env_token, direction_code, size_class = _parse_vector_id(vector_id)
    environment_code = _env_code(env_token)
    site_len, primary_len, left_len, right_len, auth_len = _lengths(
        env_token, size_class
    )
    membership, primary_epoch, term, context_id = _epochs_and_context(
        env_token, size_class
    )
    seed_base = (sum(ord(c) for c in vector_id) & 0xFF) or 1
    site = _fill(seed_base, site_len)
    primary = _fill(seed_base + 17, primary_len)
    left = _fill(seed_base + 33, left_len)
    right = _fill(seed_base + 49, right_len)
    authority = _fill(seed_base + 65, auth_len) if auth_len else b""

    common: dict[str, Any] = {
        "layer": layer,
        "environment": _environment_name(env_token),
        "environment_code": environment_code,
        "direction_code": direction_code,
        "size_class": size_class,
        "site_domain": site,
        "membership_epoch": membership,
        "authority_id": authority,
        "authority_term": term,
        "context_id": context_id,
    }
    if layer == "hop":
        common.update(
            {
                "attachment_id": primary,
                "attachment_epoch": primary_epoch,
                "initiator_stable_id": left,
                "responder_stable_id": right,
            }
        )
    elif layer == "e2e":
        common.update(
            {
                "e2e_security_id": primary,
                "e2e_security_epoch": primary_epoch,
                "sender_stable_id": left,
                "receiver_stable_id": right,
            }
        )
    else:
        raise ValueError(layer)
    return common


def _hex_fields_from_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in inputs.items():
        if isinstance(value, bytes):
            out[key] = to_hex(value)
        else:
            out[key] = value
    return out


def compute_vector(vector_id: str) -> dict[str, Any]:
    inputs = build_semantic_inputs(vector_id)
    traffic = traffic_secret_for(vector_id)
    layer = inputs["layer"]
    if layer == "hop":
        canonical = encode_hop_binding(
            environment_code=inputs["environment_code"],
            site_domain=inputs["site_domain"],
            membership_epoch=inputs["membership_epoch"],
            attachment_id=inputs["attachment_id"],
            attachment_epoch=inputs["attachment_epoch"],
            initiator_stable_id=inputs["initiator_stable_id"],
            responder_stable_id=inputs["responder_stable_id"],
            controller_authority_id=inputs["authority_id"],
            controller_term=inputs["authority_term"],
            hop_context_id=inputs["context_id"],
            direction_code=inputs["direction_code"],
        )
        digest = sha256(canonical)
        bundle = derive_hop_bundle(digest, traffic)
        keys = {
            "data_key16": to_hex(bundle["data_key16"]),
            "data_iv12": to_hex(bundle["data_iv12"]),
            "ack_key16": to_hex(bundle["ack_key16"]),
            "ack_iv12": to_hex(bundle["ack_iv12"]),
            "key16": "",
            "iv12": "",
        }
    else:
        canonical = encode_e2e_binding(
            environment_code=inputs["environment_code"],
            site_domain=inputs["site_domain"],
            membership_epoch=inputs["membership_epoch"],
            e2e_security_id=inputs["e2e_security_id"],
            e2e_security_epoch=inputs["e2e_security_epoch"],
            sender_stable_id=inputs["sender_stable_id"],
            receiver_stable_id=inputs["receiver_stable_id"],
            authority_id=inputs["authority_id"],
            authority_term=inputs["authority_term"],
            e2e_context_id=inputs["context_id"],
            direction_code=inputs["direction_code"],
        )
        digest = sha256(canonical)
        bundle = derive_e2e_bundle(digest, traffic)
        keys = {
            "data_key16": "",
            "data_iv12": "",
            "ack_key16": "",
            "ack_iv12": "",
            "key16": to_hex(bundle["key16"]),
            "iv12": to_hex(bundle["iv12"]),
        }

    if layer == "hop":
        if canonical[20] != WIRE_PROFILE_ID:
            raise RuntimeError("hop profile byte")
        if canonical[-2:] != ALLOWED_KIND_MASK.to_bytes(2, "big"):
            raise RuntimeError("hop kind mask")
        s = len(inputs["site_domain"])
        a = len(inputs["attachment_id"])
        i = len(inputs["initiator_stable_id"])
        r = len(inputs["responder_stable_id"])
        c = len(inputs["authority_id"])
        expected_len = 63 + s + a + i + r + c
    else:
        if canonical[20] != WIRE_PROFILE_ID:
            raise RuntimeError("e2e profile byte")
        s = len(inputs["site_domain"])
        q = len(inputs["e2e_security_id"])
        x = len(inputs["sender_stable_id"])
        y = len(inputs["receiver_stable_id"])
        u = len(inputs["authority_id"])
        expected_len = 61 + s + q + x + y + u
    if len(canonical) != expected_len:
        raise RuntimeError(
            f"{vector_id}: canonical length {len(canonical)} != {expected_len}"
        )

    semantic = _hex_fields_from_inputs(inputs)
    row: dict[str, Any] = {
        "id": vector_id,
        "layer": layer,
        "environment": inputs["environment"],
        "environment_code": inputs["environment_code"],
        "direction_code": inputs["direction_code"],
        "size_class": inputs["size_class"],
        "inputs": semantic,
        "traffic_secret32": to_hex(traffic),
        "canonical": to_hex(canonical),
        "canonical_len": len(canonical),
        "digest": to_hex(digest),
        "prk": to_hex(bundle["prk"]),
    }
    row.update(keys)
    return row


def build_vectors() -> list[dict[str, Any]]:
    vectors = [compute_vector(vid) for vid in _MANIFEST_BUILD_ORDER]
    vectors.sort(key=lambda row: row["id"])
    return vectors


def build_document() -> dict[str, Any]:
    vectors = build_vectors()
    if len(vectors) != 24:
        raise RuntimeError(f"vector_count must be 24, got {len(vectors)}")
    ids = [row["id"] for row in vectors]
    if ids != list(MANDATORY_IDS):
        raise RuntimeError(f"mandatory id multiset mismatch: {ids}")
    return {
        "artifact": ARTIFACT,
        "c_bridge": {
            "implemented": True,
            "required_vector_count": 24,
            "skip_allowed": False,
            "status": "implemented",
        },
        "format_id": FORMAT_ID,
        "kind": "r7_t1b_binding_subset",
        "non_claims": list(NON_CLAIMS),
        "notes": (
            "T1b private pure binding/HKDF subset only; "
            "not docs/30 §18 full materialization; "
            "not r7-radio-wire-v1.json; "
            "not implementation/HIL/R7 complete"
        ),
        "schema_version": SCHEMA_VERSION,
        "vector_count": 24,
        "vectors": vectors,
    }


def canonical_json(document: dict[str, Any]) -> bytes:
    text = json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    for row in document.get("vectors", []):
        for key in (
            "traffic_secret32",
            "canonical",
            "digest",
            "prk",
            "data_key16",
            "data_iv12",
            "ack_key16",
            "ack_iv12",
            "key16",
            "iv12",
        ):
            value = row.get(key, "")
            if isinstance(value, str) and value and value != value.lower():
                raise ValueError(f"{row.get('id')}:{key} not lowercase hex")
    return text.encode("ascii")


def _c_quote(value: str) -> str:
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E or ch in '\\"' for ch in value):
        raise ValueError("non-ascii or control in c string")
    return f'"{value}"'


def generate_header(document: dict[str, Any], json_bytes: bytes) -> bytes:
    digest = hashlib.sha256(json_bytes).hexdigest()
    vectors = document["vectors"]
    lines = [
        "/* generated by tools/r7_t1b_binding_oracle.py; test-only private fixture */",
        "/* c bridge status: implemented; skip forbidden; T1b subset only */",
        "/* NOT full r7-radio-wire-v1.json; NOT implementation/HIL/R7 complete */",
        "#ifndef NINLIL_R7_T1B_BINDING_VECTORS_H",
        "#define NINLIL_R7_T1B_BINDING_VECTORS_H",
        "",
        "#include <stdint.h>",
        "",
        f'#define NINLIL_R7_T1B_VECTOR_JSON_SHA256 "{digest}"',
        f"#define NINLIL_R7_T1B_VECTOR_COUNT {len(vectors)}u",
        "#define NINLIL_R7_T1B_REQUIRED_VECTOR_COUNT 24u",
        "",
        "typedef struct ninlil_r7_t1b_binding_vector {",
        "    const char *id;",
        "    const char *layer;",
        "    const char *environment;",
        "    uint8_t environment_code;",
        "    uint8_t direction_code;",
        "    const char *size_class;",
        "    const char *site_domain;",
        "    uint64_t membership_epoch;",
        "    const char *primary_id;",
        "    uint64_t primary_epoch;",
        "    const char *left_stable_id;",
        "    const char *right_stable_id;",
        "    const char *authority_id;",
        "    uint64_t authority_term;",
        "    uint32_t context_id;",
        "    const char *traffic_secret32;",
        "    const char *canonical;",
        "    uint16_t canonical_len;",
        "    const char *digest;",
        "    const char *prk;",
        "    const char *data_key16;",
        "    const char *data_iv12;",
        "    const char *ack_key16;",
        "    const char *ack_iv12;",
        "    const char *key16;",
        "    const char *iv12;",
        "} ninlil_r7_t1b_binding_vector;",
        "",
        "static const ninlil_r7_t1b_binding_vector ninlil_r7_t1b_binding_vectors[] = {",
    ]
    for row in vectors:
        inp = row["inputs"]
        if row["layer"] == "hop":
            primary_id = inp["attachment_id"]
            primary_epoch = int(inp["attachment_epoch"])
            left = inp["initiator_stable_id"]
            right = inp["responder_stable_id"]
        else:
            primary_id = inp["e2e_security_id"]
            primary_epoch = int(inp["e2e_security_epoch"])
            left = inp["sender_stable_id"]
            right = inp["receiver_stable_id"]
        authority_id = inp["authority_id"]
        lines.append("    {")
        lines.append(f"        {_c_quote(row['id'])},")
        lines.append(f"        {_c_quote(row['layer'])},")
        lines.append(f"        {_c_quote(row['environment'])},")
        lines.append(f"        {int(row['environment_code'])}u,")
        lines.append(f"        {int(row['direction_code'])}u,")
        lines.append(f"        {_c_quote(row['size_class'])},")
        lines.append(f"        {_c_quote(inp['site_domain'])},")
        lines.append(f"        {int(inp['membership_epoch'])}ull,")
        lines.append(f"        {_c_quote(primary_id)},")
        lines.append(f"        {primary_epoch}ull,")
        lines.append(f"        {_c_quote(left)},")
        lines.append(f"        {_c_quote(right)},")
        lines.append(f"        {_c_quote(authority_id)},")
        lines.append(f"        {int(inp['authority_term'])}ull,")
        lines.append(f"        {int(inp['context_id'])}u,")
        lines.append(f"        {_c_quote(row['traffic_secret32'])},")
        lines.append(f"        {_c_quote(row['canonical'])},")
        lines.append(f"        {int(row['canonical_len'])}u,")
        lines.append(f"        {_c_quote(row['digest'])},")
        lines.append(f"        {_c_quote(row['prk'])},")
        lines.append(f"        {_c_quote(row['data_key16'])},")
        lines.append(f"        {_c_quote(row['data_iv12'])},")
        lines.append(f"        {_c_quote(row['ack_key16'])},")
        lines.append(f"        {_c_quote(row['ack_iv12'])},")
        lines.append(f"        {_c_quote(row['key16'])},")
        lines.append(f"        {_c_quote(row['iv12'])},")
        lines.append("    },")
    lines.extend(
        [
            "};",
            "",
            "#endif /* NINLIL_R7_T1B_BINDING_VECTORS_H */",
            "",
        ]
    )
    return "\n".join(lines).encode("ascii")


def artifact_bytes() -> tuple[bytes, bytes]:
    document = build_document()
    json_bytes = canonical_json(document)
    header_bytes = generate_header(document, json_bytes)
    return json_bytes, header_bytes


# ---------------------------------------------------------------------------
# Verify / self-test
# ---------------------------------------------------------------------------


def _label_lengths_ok() -> list[str]:
    errors: list[str] = []
    expected = (
        (LABEL_HOP_DATA_KEY, 25),
        (LABEL_HOP_DATA_IV, 24),
        (LABEL_HOP_ACK_KEY, 24),
        (LABEL_HOP_ACK_IV, 23),
        (LABEL_E2E_KEY, 20),
        (LABEL_E2E_IV, 19),
        (HOP_LABEL, 20),
        (E2E_LABEL, 20),
    )
    for label, length in expected:
        if len(label) != length:
            errors.append(f"label length {label!r} want {length} got {len(label)}")
        if b"\x00" in label:
            errors.append(f"label contains NUL: {label!r}")
    return errors


def verify_document(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["document is not an object"]
    if document.get("format_id") != FORMAT_ID:
        errors.append("format_id mismatch")
    if document.get("artifact") != ARTIFACT:
        errors.append("artifact mismatch")
    if document.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version mismatch")
    if document.get("vector_count") != 24:
        errors.append(f"vector_count want 24 got {document.get('vector_count')}")
    vectors = document.get("vectors")
    if not isinstance(vectors, list):
        return errors + ["vectors is not an array"]
    if document.get("vector_count") != len(vectors):
        errors.append("vector_count does not match vectors length")
    ids = [row.get("id") for row in vectors if isinstance(row, dict)]
    if len(ids) != len(vectors):
        errors.append("vector ids missing")
    if len(ids) != len(set(ids)):
        errors.append("vector ids duplicated")
    if ids != sorted(str(i) for i in ids):
        errors.append("vector ids not sorted")
    if set(ids) != set(MANDATORY_IDS) or len(ids) != 24:
        errors.append(f"mandatory id set mismatch got={ids}")
    bridge = document.get("c_bridge")
    if not isinstance(bridge, dict):
        errors.append("c_bridge missing")
    else:
        if bridge.get("implemented") is not True:
            errors.append("c_bridge.implemented")
        if bridge.get("skip_allowed") is not False:
            errors.append("c_bridge.skip_allowed must be false")
        if bridge.get("status") != "implemented":
            errors.append("c_bridge.status")
        if bridge.get("required_vector_count") != 24:
            errors.append("c_bridge.required_vector_count must be 24")
        if bridge.get("required_vector_count") != len(vectors):
            errors.append("c_bridge.required_vector_count drift vs vectors")
    claims = document.get("non_claims")
    if not isinstance(claims, list) or not claims:
        errors.append("non_claims missing")
    expected = build_document()
    if document != expected:
        errors.append("document differs from independent oracle rebuild")
    for row in vectors:
        if not isinstance(row, dict):
            errors.append("vector row not object")
            continue
        rid = row.get("id", "?")
        try:
            rebuilt = compute_vector(str(rid))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{rid}: rebuild failed: {exc}")
            continue
        for key in (
            "canonical",
            "digest",
            "prk",
            "traffic_secret32",
            "data_key16",
            "data_iv12",
            "ack_key16",
            "ack_iv12",
            "key16",
            "iv12",
            "canonical_len",
        ):
            if row.get(key) != rebuilt.get(key):
                errors.append(f"{rid}: field {key} mismatch vs recompute")
        try:
            canon_len = len(from_hex(str(row.get("canonical", ""))))
        except ValueError:
            errors.append(f"{rid}: canonical not lowercase hex")
            continue
        if int(row.get("canonical_len", -1)) != canon_len:
            errors.append(f"{rid}: canonical_len mismatch")
        if row.get("layer") == "hop":
            if not row.get("data_key16") or row.get("key16"):
                errors.append(f"{rid}: hop key fields shape")
        elif row.get("layer") == "e2e":
            if not row.get("key16") or row.get("data_key16"):
                errors.append(f"{rid}: e2e key fields shape")
        if row.get("size_class") == "max":
            inp = row.get("inputs") or {}
            epochs = [
                int(inp.get("membership_epoch", 0)),
                int(inp.get("attachment_epoch", 0) or 0),
                int(inp.get("e2e_security_epoch", 0) or 0),
                int(inp.get("authority_term", 0)),
            ]
            if UINT64_MAX not in epochs:
                errors.append(f"{rid}: MAX missing UINT64_MAX epoch/term pin")
    return errors


def verify_committed_artifacts() -> list[str]:
    errors: list[str] = []
    expected_json, expected_header = artifact_bytes()
    if not JSON_PATH.is_file():
        errors.append(f"missing committed json: {JSON_PATH}")
    else:
        got_json = JSON_PATH.read_bytes()
        if got_json != expected_json:
            errors.append("committed json not fresh vs oracle regenerate")
        try:
            document = json.loads(got_json.decode("ascii"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            errors.append(f"committed json parse: {exc}")
        else:
            errors.extend(verify_document(document))
    if not HEADER_PATH.is_file():
        errors.append(f"missing committed header: {HEADER_PATH}")
    else:
        got_header = HEADER_PATH.read_bytes()
        if got_header != expected_header:
            errors.append("committed header not fresh vs oracle regenerate")
        digest = hashlib.sha256(expected_json).hexdigest()
        if digest.encode("ascii") not in got_header:
            errors.append("header missing json sha256 pin")
        if b"NINLIL_R7_T1B_VECTOR_COUNT 24u" not in got_header:
            errors.append("header vector count pin missing")
        for vid in MANDATORY_IDS:
            if vid.encode("ascii") not in got_header:
                errors.append(f"header missing id {vid}")
    return errors


def _flip_hex_first_byte(hex_str: str) -> str:
    raw = bytearray(from_hex(hex_str))
    raw[0] ^= 0x01
    return to_hex(bytes(raw))


def _hkdf_expand_raw(prk: bytes, info: bytes, okm_len: int) -> bytes:
    """Expand without the T1b NUL-label guard (mutation probes only)."""
    if len(prk) != 32:
        raise ValueError("prk must be 32 bytes")
    okm = b""
    t = b""
    counter = 1
    while len(okm) < okm_len:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:okm_len]


def _encode_from_inputs(inputs: dict[str, Any]) -> bytes:
    if inputs["layer"] == "hop":
        return encode_hop_binding(
            environment_code=int(inputs["environment_code"]),
            site_domain=inputs["site_domain"],
            membership_epoch=int(inputs["membership_epoch"]),
            attachment_id=inputs["attachment_id"],
            attachment_epoch=int(inputs["attachment_epoch"]),
            initiator_stable_id=inputs["initiator_stable_id"],
            responder_stable_id=inputs["responder_stable_id"],
            controller_authority_id=inputs["authority_id"],
            controller_term=int(inputs["authority_term"]),
            hop_context_id=int(inputs["context_id"]),
            direction_code=int(inputs["direction_code"]),
        )
    return encode_e2e_binding(
        environment_code=int(inputs["environment_code"]),
        site_domain=inputs["site_domain"],
        membership_epoch=int(inputs["membership_epoch"]),
        e2e_security_id=inputs["e2e_security_id"],
        e2e_security_epoch=int(inputs["e2e_security_epoch"]),
        sender_stable_id=inputs["sender_stable_id"],
        receiver_stable_id=inputs["receiver_stable_id"],
        authority_id=inputs["authority_id"],
        authority_term=int(inputs["authority_term"]),
        e2e_context_id=int(inputs["context_id"]),
        direction_code=int(inputs["direction_code"]),
    )


def _mutate_int(value: int, *, width_bits: int) -> int:
    """Flip low bit within a fixed-width BE integer domain used by encode_canon."""
    return value ^ 1 if width_bits >= 1 else value


def _opaque_body_mut(value: bytes) -> bytes:
    if not value:
        raise ValueError("empty opaque has no body to flip")
    out = bytearray(value)
    out[0] ^= 0x01
    return bytes(out)


def _opaque_len_mut(value: bytes) -> bytes:
    """Change encoded length by one valid body byte (append or drop last)."""
    if len(value) == 0:
        return b"\x01"
    if len(value) >= 32:
        return value[:-1]
    return value + bytes((0x5A,))


class _MutationCounter:
    """Deterministic ordered mutation-case ledger for self-test reporting."""

    def __init__(self) -> None:
        self.cases: list[str] = []
        self.errors: list[str] = []

    def require(self, name: str, ok: bool, detail: str = "") -> None:
        self.cases.append(name)
        if not ok:
            suffix = f": {detail}" if detail else ""
            self.errors.append(f"{name} escaped{suffix}")

    def require_change(
        self,
        name: str,
        before: bytes | str,
        after: bytes | str,
    ) -> None:
        self.require(name, before != after, "output identical after mutation")


def mutation_self_test() -> tuple[list[str], int]:
    """Strong docs/33 §9 mutation suite. Returns (errors, case_count)."""
    ctr = _MutationCounter()
    for err in _label_lengths_ok():
        ctr.errors.append(err)

    original = build_document()
    baseline_json = canonical_json(original)

    # ------------------------------------------------------------------
    # Structural: drop / extra / duplicate / count / bridge metadata
    # ------------------------------------------------------------------
    mutated = json.loads(baseline_json)
    mutated["vectors"] = mutated["vectors"][1:]
    mutated["vector_count"] = len(mutated["vectors"])
    mutated["c_bridge"]["required_vector_count"] = len(mutated["vectors"])
    ctr.require("doc.drop_vector", bool(verify_document(mutated)))

    mutated = json.loads(baseline_json)
    extra = copy.deepcopy(mutated["vectors"][0])
    extra["id"] = "R7-T1B-EXTRA-SHOULD-FAIL"
    mutated["vectors"] = mutated["vectors"] + [extra]
    mutated["vectors"].sort(key=lambda r: r["id"])
    mutated["vector_count"] = len(mutated["vectors"])
    mutated["c_bridge"]["required_vector_count"] = len(mutated["vectors"])
    ctr.require("doc.extra_vector", bool(verify_document(mutated)))

    mutated = json.loads(baseline_json)
    mutated["vectors"][1] = copy.deepcopy(mutated["vectors"][0])
    mutated["vector_count"] = len(mutated["vectors"])
    ctr.require("doc.duplicate_id", bool(verify_document(mutated)))

    mutated = json.loads(baseline_json)
    mutated["vector_count"] = 25
    ctr.require("doc.vector_count_drift", bool(verify_document(mutated)))

    mutated = json.loads(baseline_json)
    mutated["c_bridge"]["required_vector_count"] = 23
    ctr.require("doc.bridge_count_drift", bool(verify_document(mutated)))

    mutated = json.loads(baseline_json)
    mutated["c_bridge"]["skip_allowed"] = True
    ctr.require("doc.bridge_skip_allowed", bool(verify_document(mutated)))

    mutated = json.loads(baseline_json)
    mutated["non_claims"] = []
    ctr.require("doc.non_claims_empty", bool(verify_document(mutated)))

    # ------------------------------------------------------------------
    # (3) Document expected-byte flips: canonical/digest/PRK + every lane
    # ------------------------------------------------------------------
    hop_row = next(r for r in original["vectors"] if r["layer"] == "hop")
    e2e_row = next(r for r in original["vectors"] if r["layer"] == "e2e")
    doc_flip_fields_hop = (
        "canonical",
        "digest",
        "prk",
        "traffic_secret32",
        "data_key16",
        "data_iv12",
        "ack_key16",
        "ack_iv12",
    )
    doc_flip_fields_e2e = (
        "canonical",
        "digest",
        "prk",
        "traffic_secret32",
        "key16",
        "iv12",
    )
    for field in doc_flip_fields_hop:
        mutated = json.loads(baseline_json)
        row = next(r for r in mutated["vectors"] if r["id"] == hop_row["id"])
        row[field] = _flip_hex_first_byte(row[field])
        ctr.require(f"doc.hop.flip_{field}", bool(verify_document(mutated)))
    for field in doc_flip_fields_e2e:
        mutated = json.loads(baseline_json)
        row = next(r for r in mutated["vectors"] if r["id"] == e2e_row["id"])
        row[field] = _flip_hex_first_byte(row[field])
        ctr.require(f"doc.e2e.flip_{field}", bool(verify_document(mutated)))

    # ------------------------------------------------------------------
    # Representative valid inputs: controller MIN for non-empty authority;
    # no-controller MIN for empty authority behavior only.
    # ------------------------------------------------------------------
    hop_ctrl_id = "R7-T1B-HOP-LAB-CONTROLLER-D0-MIN"
    e2e_ctrl_id = "R7-T1B-E2E-LAB-CONTROLLER-D0-MIN"
    hop_nc_id = "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MIN"
    e2e_nc_id = "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MIN"
    hop_field_id = "R7-T1B-HOP-FIELD-D0-MIN"
    e2e_field_id = "R7-T1B-E2E-FIELD-D0-MIN"

    def _base_pair(vector_id: str) -> tuple[dict[str, Any], bytes, bytes]:
        inputs = build_semantic_inputs(vector_id)
        canon = _encode_from_inputs(inputs)
        return inputs, canon, sha256(canon)

    # (1) Integer field mutations — Hop and E2E
    hop_int_fields = (
        ("environment_code", 8),
        ("membership_epoch", 64),
        ("attachment_epoch", 64),
        ("authority_term", 64),  # controller_term
        ("context_id", 32),
        ("direction_code", 8),
    )
    e2e_int_fields = (
        ("environment_code", 8),
        ("membership_epoch", 64),
        ("e2e_security_epoch", 64),
        ("authority_term", 64),
        ("context_id", 32),
        ("direction_code", 8),
    )
    for layer_tag, vid, fields in (
        ("hop", hop_ctrl_id, hop_int_fields),
        ("hop", hop_field_id, hop_int_fields),
        ("e2e", e2e_ctrl_id, e2e_int_fields),
        ("e2e", e2e_field_id, e2e_int_fields),
    ):
        base_inputs, base_canon, base_digest = _base_pair(vid)
        for field, width in fields:
            trial = copy.deepcopy(base_inputs)
            trial[field] = _mutate_int(int(trial[field]), width_bits=width)
            # Keep environment_code in {1,2} for a meaningful alternate code.
            if field == "environment_code":
                trial[field] = ENV_FIELD if base_inputs["environment_code"] == ENV_LAB else ENV_LAB
            new_canon = _encode_from_inputs(trial)
            new_digest = sha256(new_canon)
            ctr.require_change(
                f"int.{layer_tag}.{vid.split('-')[3]}.{field}.canonical",
                base_canon,
                new_canon,
            )
            ctr.require_change(
                f"int.{layer_tag}.{vid.split('-')[3]}.{field}.digest",
                base_digest,
                new_digest,
            )

    # (2) Opaque body + length mutations — every opaque in both layers
    hop_opaques = (
        "site_domain",
        "attachment_id",
        "initiator_stable_id",
        "responder_stable_id",
        "authority_id",
    )
    e2e_opaques = (
        "site_domain",
        "e2e_security_id",
        "sender_stable_id",
        "receiver_stable_id",
        "authority_id",
    )
    for layer_tag, vid, opaques in (
        ("hop", hop_ctrl_id, hop_opaques),
        ("e2e", e2e_ctrl_id, e2e_opaques),
        ("hop", hop_field_id, hop_opaques),
        ("e2e", e2e_field_id, e2e_opaques),
    ):
        base_inputs, base_canon, base_digest = _base_pair(vid)
        for field in opaques:
            # Body-byte mutation (authority non-empty on controller/FIELD).
            trial = copy.deepcopy(base_inputs)
            trial[field] = _opaque_body_mut(trial[field])
            new_canon = _encode_from_inputs(trial)
            new_digest = sha256(new_canon)
            ctr.require_change(
                f"opaque.{layer_tag}.{vid.split('-')[3]}.{field}.body.canonical",
                base_canon,
                new_canon,
            )
            ctr.require_change(
                f"opaque.{layer_tag}.{vid.split('-')[3]}.{field}.body.digest",
                base_digest,
                new_digest,
            )
            # Encoded-length mutation.
            trial = copy.deepcopy(base_inputs)
            trial[field] = _opaque_len_mut(trial[field])
            new_canon = _encode_from_inputs(trial)
            new_digest = sha256(new_canon)
            ctr.require_change(
                f"opaque.{layer_tag}.{vid.split('-')[3]}.{field}.len.canonical",
                base_canon,
                new_canon,
            )
            ctr.require_change(
                f"opaque.{layer_tag}.{vid.split('-')[3]}.{field}.len.digest",
                base_digest,
                new_digest,
            )

    # No-controller empty authority: encode length-0; mutation by injecting
    # a non-empty body (probe only — not a committed positive vector).
    for layer_tag, vid in (("hop", hop_nc_id), ("e2e", e2e_nc_id)):
        base_inputs, base_canon, base_digest = _base_pair(vid)
        ctr.require(
            f"opaque.{layer_tag}.NOCTRL.authority.empty_len",
            len(base_inputs["authority_id"]) == 0
            and int(base_inputs["authority_term"]) == 0,
        )
        # Empty authority appears as u16be(0) with no body in the wire.
        empty_marker = (0).to_bytes(2, "big")
        # Authority is the last opaque before term/context; presence of a
        # zero-length opaque is required somewhere after the second stable id.
        ctr.require(
            f"opaque.{layer_tag}.NOCTRL.authority.encoded_zero_len",
            empty_marker in base_canon,
        )
        trial = copy.deepcopy(base_inputs)
        trial["authority_id"] = b"\x01"  # probe only
        new_canon = _encode_from_inputs(trial)
        new_digest = sha256(new_canon)
        ctr.require_change(
            f"opaque.{layer_tag}.NOCTRL.authority.inject_body.canonical",
            base_canon,
            new_canon,
        )
        ctr.require_change(
            f"opaque.{layer_tag}.NOCTRL.authority.inject_body.digest",
            base_digest,
            new_digest,
        )
        # Length 0 vs length 1 with empty-looking content still changes u16 len.
        trial = copy.deepcopy(base_inputs)
        trial["authority_id"] = _opaque_len_mut(b"")  # becomes 1 byte
        new_canon = _encode_from_inputs(trial)
        ctr.require_change(
            f"opaque.{layer_tag}.NOCTRL.authority.len0_to_len1.canonical",
            base_canon,
            new_canon,
        )

    # ------------------------------------------------------------------
    # (4) Traffic-secret flip → PRK + every derived lane for that layer
    # ------------------------------------------------------------------
    for layer_tag, vid, derive, lane_keys in (
        (
            "hop",
            hop_ctrl_id,
            derive_hop_bundle,
            ("prk", "data_key16", "data_iv12", "ack_key16", "ack_iv12"),
        ),
        (
            "e2e",
            e2e_ctrl_id,
            derive_e2e_bundle,
            ("prk", "key16", "iv12"),
        ),
    ):
        base = compute_vector(vid)
        digest = from_hex(base["digest"])
        traffic = bytearray(from_hex(base["traffic_secret32"]))
        traffic[0] ^= 0x01
        alt = derive(digest, bytes(traffic))
        for key in lane_keys:
            before = from_hex(base[key]) if key != "prk" else from_hex(base["prk"])
            # bundle keys match field names
            after = alt[key]
            ctr.require_change(
                f"traffic.{layer_tag}.{key}",
                before,
                after,
            )

    # ------------------------------------------------------------------
    # (5) Each of six HKDF labels independently; domain separation
    # ------------------------------------------------------------------
    hop_base = compute_vector(hop_ctrl_id)
    e2e_base = compute_vector(e2e_ctrl_id)
    hop_prk = from_hex(hop_base["prk"])
    e2e_prk = from_hex(e2e_base["prk"])

    hop_label_lanes = (
        (LABEL_HOP_DATA_KEY, 16, "data_key16"),
        (LABEL_HOP_DATA_IV, 12, "data_iv12"),
        (LABEL_HOP_ACK_KEY, 16, "ack_key16"),
        (LABEL_HOP_ACK_IV, 12, "ack_iv12"),
    )
    e2e_label_lanes = (
        (LABEL_E2E_KEY, 16, "key16"),
        (LABEL_E2E_IV, 12, "iv12"),
    )
    for label, length, lane in hop_label_lanes:
        base_okm = hkdf_expand_sha256(hop_prk, label, length)
        flipped = bytearray(label)
        flipped[0] ^= 0x01
        alt_okm = _hkdf_expand_raw(hop_prk, bytes(flipped), length)
        ctr.require_change(f"label.hop.{lane}", base_okm, alt_okm)
        # Lane still matches committed vector under true label.
        ctr.require(
            f"label.hop.{lane}.matches_vector",
            to_hex(base_okm) == hop_base[lane],
        )
    for label, length, lane in e2e_label_lanes:
        base_okm = hkdf_expand_sha256(e2e_prk, label, length)
        flipped = bytearray(label)
        flipped[0] ^= 0x01
        alt_okm = _hkdf_expand_raw(e2e_prk, bytes(flipped), length)
        ctr.require_change(f"label.e2e.{lane}", base_okm, alt_okm)
        ctr.require(
            f"label.e2e.{lane}.matches_vector",
            to_hex(base_okm) == e2e_base[lane],
        )

    # Domain separation (suite-local; not a general avalanche claim).
    hop_data_key = hkdf_expand_sha256(hop_prk, LABEL_HOP_DATA_KEY, 16)
    hop_ack_key = hkdf_expand_sha256(hop_prk, LABEL_HOP_ACK_KEY, 16)
    hop_data_iv = hkdf_expand_sha256(hop_prk, LABEL_HOP_DATA_IV, 12)
    hop_ack_iv = hkdf_expand_sha256(hop_prk, LABEL_HOP_ACK_IV, 12)
    e2e_key = hkdf_expand_sha256(e2e_prk, LABEL_E2E_KEY, 16)
    e2e_iv = hkdf_expand_sha256(e2e_prk, LABEL_E2E_IV, 12)
    ctr.require_change("sep.hop.data_key_vs_ack_key", hop_data_key, hop_ack_key)
    ctr.require_change("sep.hop.data_iv_vs_ack_iv", hop_data_iv, hop_ack_iv)
    ctr.require_change("sep.e2e.key_vs_iv", e2e_key, e2e_iv)
    # Cross-lane pairs also distinct under this suite's PRKs.
    ctr.require_change("sep.hop.data_key_vs_data_iv_prefix", hop_data_key[:12], hop_data_iv)
    ctr.require_change("sep.hop.ack_key_vs_ack_iv_prefix", hop_ack_key[:12], hop_ack_iv)

    # ------------------------------------------------------------------
    # Deterministic generate-twice under distinct PYTHONHASHSEED
    # ------------------------------------------------------------------
    with tempfile.TemporaryDirectory(prefix="r7-t1b-a-") as td1, tempfile.TemporaryDirectory(
        prefix="r7-t1b-b-"
    ) as td2:
        for seed, td in (("1", td1), ("2", td2)):
            env = os.environ.copy()
            env["PYTHONHASHSEED"] = seed
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            jpath = pathlib.Path(td) / "v.json"
            hpath = pathlib.Path(td) / "v.h"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO / "tools" / "r7_t1b_binding_oracle.py"),
                    "generate",
                    "--json",
                    str(jpath),
                    "--header",
                    str(hpath),
                ],
                cwd=str(REPO),
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            ctr.require(
                f"det.generate_hashseed_{seed}",
                proc.returncode == 0,
                proc.stderr or proc.stdout,
            )
        j1 = (pathlib.Path(td1) / "v.json").read_bytes()
        j2 = (pathlib.Path(td2) / "v.json").read_bytes()
        h1 = (pathlib.Path(td1) / "v.h").read_bytes()
        h2 = (pathlib.Path(td2) / "v.h").read_bytes()
        ctr.require("det.json_byte_identical", j1 == j2)
        ctr.require("det.header_byte_identical", h1 == h2)
        # Lowercase hex payloads only (IDs retain stable uppercase tokens).
        doc1 = json.loads(j1.decode("ascii"))
        hex_ok = True
        for row in doc1["vectors"]:
            for key in (
                "traffic_secret32",
                "canonical",
                "digest",
                "prk",
                "data_key16",
                "data_iv12",
                "ack_key16",
                "ack_iv12",
                "key16",
                "iv12",
            ):
                val = row.get(key, "")
                if isinstance(val, str) and val and val != val.lower():
                    hex_ok = False
            for key, val in (row.get("inputs") or {}).items():
                if isinstance(val, str) and val and all(
                    c in "0123456789abcdefABCDEF" for c in val
                ):
                    if len(val) % 2 == 0 and val != val.lower():
                        hex_ok = False
        ctr.require("det.json_lowercase_hex", hex_ok)

    # Stable case list length is part of the self-test contract.
    if len(ctr.cases) != len(set(ctr.cases)):
        ctr.errors.append("mutation case names not unique")
    return ctr.errors, len(ctr.cases)


# Strengthened docs/33 §9 mutation ledger size (silent case drop → red).
PINNED_MUTATION_CASE_COUNT = 189


def run_self_test() -> int:
    errors, case_count = mutation_self_test()
    if case_count != PINNED_MUTATION_CASE_COUNT:
        errors.append(
            f"pinned mutation case count mismatch: got {case_count} "
            f"want {PINNED_MUTATION_CASE_COUNT}"
        )

    document = build_document()
    errors.extend(verify_document(document))
    json_a, header_a = artifact_bytes()
    json_b, header_b = artifact_bytes()
    if (json_a, header_a) != (json_b, header_b):
        errors.append("in-process artifact non-deterministic")
    if errors:
        for err in errors:
            print(f"r7_t1b_binding_oracle self-test FAIL: {err}", file=sys.stderr)
        print(
            f"r7_t1b_binding_oracle self-test mutation_cases={case_count}",
            file=sys.stderr,
        )
        return 1
    print(
        f"r7_t1b_binding_oracle self-test OK vectors={document['vector_count']} "
        f"mutation_cases={case_count} format={FORMAT_ID}"
    )
    return 0


def run_verify() -> int:
    errors = verify_committed_artifacts()
    if errors:
        for err in errors:
            print(f"r7_t1b_binding_oracle verify FAIL: {err}", file=sys.stderr)
        return 1
    document = json.loads(JSON_PATH.read_text(encoding="ascii"))
    print(
        f"r7_t1b_binding_oracle verify OK vectors={document['vector_count']} "
        f"format={FORMAT_ID}"
    )
    return 0


def run_generate(json_path: pathlib.Path, header_path: pathlib.Path) -> int:
    json_bytes, header_bytes = artifact_bytes()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    header_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_bytes(json_bytes)
    header_path.write_bytes(header_bytes)
    print(
        f"r7_t1b_binding_oracle generate OK vectors=24 "
        f"json={json_path} header={header_path}"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("generate", "verify", "self-test"),
    )
    parser.add_argument(
        "--json",
        type=pathlib.Path,
        default=JSON_PATH,
        help=f"JSON output path (default: {JSON_PATH})",
    )
    parser.add_argument(
        "--header",
        type=pathlib.Path,
        default=HEADER_PATH,
        help=f"C header output path (default: {HEADER_PATH})",
    )
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return run_self_test()
    if args.command == "verify":
        return run_verify()
    if args.command == "generate":
        return run_generate(args.json, args.header)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
