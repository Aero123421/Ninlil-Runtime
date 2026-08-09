#!/usr/bin/env python3
"""Independent spec KAT for the Identity/Attachment precondition contract.

This is deliberately a byte/layout oracle, not a provider implementation.  It
does not import the JSON schema or copy its constants: the NIAF record and the
two declared C ABI data models are reconstructed here and compared with both
the checked-in vector and the manifest contract.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import struct
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTOR_PATH = ROOT / "spec/vectors/identity-attachment-precondition-v1.json"
MANIFEST_PATH = ROOT / "public-module-manifest.json"
ADR_PATH = ROOT / "docs/adr/0039-identity-attachment-precondition-gate.md"
MAGIC_REGISTRY_PATH = ROOT / "spec/protocol-magic-registry-v1.json"
ADR_H1 = "# ADR-0039: Identity / Attachment precondition gate"


class GateError(RuntimeError):
    pass


def load_json(path: pathlib.Path) -> dict[str, Any]:
    def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise GateError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates)
    except (OSError, json.JSONDecodeError) as exc:
        raise GateError(f"{path}: unreadable JSON") from exc
    if not isinstance(value, dict):
        raise GateError(f"{path}: root must be object")
    return value


def crc32c(data: bytes) -> int:
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def niaf_record() -> bytes:
    """One fixed, independently reconstructed 308-byte NIAF golden record."""
    ids = [bytes(range(start, start + 16)) for start in range(0, 160, 16)]
    values = [
        0x0102030405060708, 0x1112131415161718,
        0x2122232425262728, 0x3132333435363738,
        0x4142434445464748, 0x5152535455565758,
        0x6162636465666768, 0x7172737475767778,
        0x8182838485868788, 0x9192939495969798,
        0xA1A2A3A4A5A6A7A8, 0xB1B2B3B4B5B6B7B8,
        0xC1C2C3C4C5C6C7C8,
    ]
    out = bytearray(b"NIAF" + struct.pack("<HH", 1, 308))
    expected_id_offsets = (8, 24, 48, 72, 96, 120, 144, 168, 192, 216)
    expected_generation_offsets = (40, 64, 88, 112, 136, 160, 184, 208, 232)
    out.extend(ids[0])
    if len(out) - 16 != expected_id_offsets[0]:
        raise GateError("internal NIAF realm offset drift")
    value_index = 0
    for index, value in enumerate(ids[1:], start=1):
        if len(out) != expected_id_offsets[index]:
            raise GateError("internal NIAF ID offset drift")
        out.extend(value)
        if len(out) != expected_generation_offsets[value_index]:
            raise GateError("internal NIAF generation offset drift")
        out.extend(struct.pack("<Q", values[value_index]))
        value_index += 1
    if len(out) != 240:
        raise GateError("internal NIAF floor offset drift")
    out.extend(struct.pack("<QQQQ", *values[value_index:value_index + 4]))
    if len(out) != 272:
        raise GateError(f"internal NIAF prefix size {len(out)} != 272")
    out.extend(hashlib.sha256(out).digest())
    out.extend(struct.pack("<I", crc32c(out)))
    if len(out) != 308:
        raise GateError(f"internal NIAF size {len(out)} != 308")
    return bytes(out)


NIAF_RECORD_FIELD_ORDER = [
    "uint8_t magic[4]",
    "uint16_t schema_version",
    "uint16_t record_size",
    "uint8_t realm_id[16]",
    "uint8_t runtime_instance_id[16]",
    "uint64_t runtime_generation",
    "uint8_t module_instance_id[16]",
    "uint64_t module_generation",
    "uint8_t provider_instance_id[16]",
    "uint64_t provider_generation_floor",
    "uint8_t stable_identity_id[16]",
    "uint64_t credential_revision_floor",
    "uint8_t membership_authority_id[16]",
    "uint64_t membership_epoch_floor",
    "uint8_t attachment_id[16]",
    "uint64_t attachment_generation_floor",
    "uint8_t session_id[16]",
    "uint64_t session_generation_floor",
    "uint8_t security_context_id[16]",
    "uint64_t security_epoch_floor",
    "uint8_t expiry_authority_id[16]",
    "uint64_t expiry_epoch_floor",
    "uint64_t invalidation_epoch_floor",
    "uint64_t binding_handle_generation_floor",
    "uint64_t key_generation_floor",
    "uint64_t checkpoint_generation",
    "uint8_t payload_digest[32]",
    "uint32_t crc32c",
]
NIAF_FIELD_OFFSETS = [
    [name, offset]
    for name, offset in zip(
        NIAF_RECORD_FIELD_ORDER,
        (0, 4, 6, 8, 24, 40, 48, 64, 72, 88, 96, 112, 120, 136,
         144, 160, 168, 184, 192, 208, 216, 232, 240, 248, 256, 264,
         272, 304),
        strict=True,
    )
]


U32 = "u32"
U64 = "u64"
P = "ptr"
FP = "fnptr"


def fields(*items: tuple[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(items)


TYPES: dict[str, tuple[tuple[str, str], ...]] = {
    "provider": fields(
        ("uint32_t abi_version", U32), ("uint32_t struct_size", U32),
        ("void *context", P), ("ninlil_identity_attachment_resolve_v1_fn resolve_binding", FP),
        ("ninlil_identity_attachment_validate_v1_fn validate_binding", FP),
        ("ninlil_identity_attachment_key_operation_v1_fn perform_key_operation", FP),
        ("ninlil_identity_attachment_release_v1_fn release_binding", FP),
        ("ninlil_identity_attachment_subscribe_v1_fn subscribe_invalidation", FP),
        ("ninlil_identity_attachment_unsubscribe_v1_fn unsubscribe_invalidation", FP)),
    "binding_handle": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint8_t provider_instance_id[16]", "b16"), ("uint64_t provider_generation", U64), ("uint8_t binding_handle_id[16]", "b16"), ("uint64_t binding_handle_generation", U64), ("uint8_t runtime_instance_id[16]", "b16"), ("uint64_t runtime_generation", U64), ("uint8_t module_instance_id[16]", "b16"), ("uint64_t module_generation", U64), ("uint8_t opaque_token[32]", "b32")),
    "binding_snapshot": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint8_t provider_instance_id[16]", "b16"), ("uint64_t provider_generation", U64), ("uint8_t runtime_instance_id[16]", "b16"), ("uint64_t runtime_generation", U64), ("uint8_t module_instance_id[16]", "b16"), ("uint64_t module_generation", U64), ("uint8_t stable_identity_id[16]", "b16"), ("uint64_t credential_revision", U64), ("uint8_t identity_binding_digest[32]", "b32"), ("uint8_t membership_authority_id[16]", "b16"), ("uint64_t membership_epoch", U64), ("uint8_t membership_set_digest[32]", "b32"), ("uint8_t attachment_id[16]", "b16"), ("uint64_t attachment_generation", U64), ("uint8_t session_id[16]", "b16"), ("uint64_t session_generation", U64), ("uint8_t security_context_id[16]", "b16"), ("uint64_t security_epoch", U64), ("uint8_t expiry_authority_id[16]", "b16"), ("uint64_t expiry_epoch", U64), ("uint64_t not_before_tick", U64), ("uint64_t expires_at_tick", U64), ("uint64_t invalidation_epoch", U64)),
    "key_handle": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint8_t provider_instance_id[16]", "b16"), ("uint64_t provider_generation", U64), ("uint8_t binding_handle_id[16]", "b16"), ("uint64_t binding_handle_generation", U64), ("uint8_t key_handle_id[16]", "b16"), ("uint64_t key_generation", U64), ("uint32_t usage_mask", U32), ("uint32_t flags", U32), ("uint8_t opaque_token[32]", "b32")),
    "subscription_handle": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint8_t provider_instance_id[16]", "b16"), ("uint64_t provider_generation", U64), ("uint8_t binding_handle_id[16]", "b16"), ("uint64_t binding_handle_generation", U64), ("uint8_t subscription_id[16]", "b16"), ("uint64_t subscription_generation", U64), ("uint8_t opaque_token[32]", "b32")),
    "resolve_request": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint8_t provider_instance_id[16]", "b16"), ("uint64_t provider_generation", U64), ("uint8_t runtime_instance_id[16]", "b16"), ("uint64_t runtime_generation", U64), ("uint8_t module_instance_id[16]", "b16"), ("uint64_t module_generation", U64), ("uint32_t binding_scope", U32), ("uint32_t requested_usage_mask", U32), ("uint8_t subject_identity_id[16]", "b16"), ("uint64_t deadline_tick", U64), ("uint32_t flags", U32), ("uint32_t reserved_zero", U32)),
    "resolve_result": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint32_t binding_verdict", U32), ("uint32_t flags", U32), ("ninlil_identity_attachment_binding_snapshot_v1_t snapshot", "binding_snapshot"), ("ninlil_identity_attachment_binding_handle_v1_t binding_handle", "binding_handle"), ("ninlil_nonexporting_key_handle_v1_t key_handle", "key_handle")),
    "validate_request": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("ninlil_identity_attachment_binding_handle_v1_t binding_handle", "binding_handle"), ("uint32_t required_usage_mask", U32), ("uint32_t flags", U32), ("uint8_t operation_context_digest[32]", "b32"), ("uint64_t deadline_tick", U64)),
    "validate_result": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint32_t binding_verdict", U32), ("uint32_t flags", U32), ("uint64_t authoritative_invalidation_epoch", U64), ("uint64_t authoritative_expiry_epoch", U64)),
    "key_operation_request": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("ninlil_identity_attachment_binding_handle_v1_t binding_handle", "binding_handle"), ("ninlil_nonexporting_key_handle_v1_t key_handle", "key_handle"), ("uint32_t operation", U32), ("uint32_t flags", U32), ("const uint8_t *nonce", P), ("uint32_t nonce_size", U32), ("const uint8_t *aad", P), ("uint32_t aad_size", U32), ("const uint8_t *input", P), ("uint32_t input_size", U32), ("const uint8_t *authenticator", P), ("uint32_t authenticator_size", U32), ("uint64_t deadline_tick", U64)),
    "key_operation_result": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint32_t operation", U32), ("uint32_t flags", U32), ("uint8_t *output", P), ("uint32_t output_capacity", U32), ("uint32_t output_size", U32), ("uint32_t verified", U32), ("uint32_t reserved_zero", U32)),
    "release_request": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("ninlil_identity_attachment_binding_handle_v1_t binding_handle", "binding_handle"), ("uint32_t flags", U32), ("uint32_t reserved_zero", U32)),
    "release_result": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint32_t released", U32), ("uint32_t flags", U32)),
    "subscribe_request": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("ninlil_identity_attachment_binding_handle_v1_t binding_handle", "binding_handle"), ("void *callback_context", P), ("ninlil_identity_attachment_on_invalidation_v1_fn on_invalidation", FP), ("uint32_t flags", U32), ("uint32_t reserved_zero", U32)),
    "subscribe_result": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("ninlil_identity_attachment_subscription_handle_v1_t subscription_handle", "subscription_handle"), ("uint64_t subscribed_invalidation_epoch", U64), ("uint32_t flags", U32), ("uint32_t reserved_zero", U32)),
    "invalidation_event": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("ninlil_identity_attachment_binding_handle_v1_t binding_handle", "binding_handle"), ("uint32_t reason", U32), ("uint32_t changed_floor_mask", U32), ("uint64_t invalidation_epoch", U64), ("uint64_t provider_generation", U64), ("uint64_t binding_handle_generation", U64), ("uint64_t key_generation", U64), ("uint32_t flags", U32), ("uint32_t reserved_zero", U32)),
    "unsubscribe_request": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("ninlil_identity_attachment_subscription_handle_v1_t subscription_handle", "subscription_handle"), ("uint32_t flags", U32), ("uint32_t reserved_zero", U32)),
    "unsubscribe_result": fields(("uint32_t abi_version", U32), ("uint32_t struct_size", U32), ("uint64_t final_invalidation_epoch", U64), ("uint32_t callbacks_drained", U32), ("uint32_t flags", U32)),
}


PROFILES = {
    "LP64_SYSV": {
        "pointer_bytes": 8,
        "pointer_alignment": 8,
        "function_pointer_bytes": 8,
        "function_pointer_alignment": 8,
        "u64_alignment": 8,
    },
    # ESP-IDF v5.5.3's xtensa-esp32s3-elf-gcc uses 4-byte pointers but an
    # 8-byte uint64_t alignment.  Do not substitute a generic ILP32 ABI.
    "ESP32S3_XTENSA_ILP32": {
        "pointer_bytes": 4,
        "pointer_alignment": 4,
        "function_pointer_bytes": 4,
        "function_pointer_alignment": 4,
        "u64_alignment": 8,
    },
}


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def layout(name: str, profile: dict[str, int], cache: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if name in cache:
        return cache[name]
    sizes = {
        U32: (4, 4),
        U64: (8, profile["u64_alignment"]),
        P: (profile["pointer_bytes"], profile["pointer_alignment"]),
        FP: (profile["function_pointer_bytes"], profile["function_pointer_alignment"]),
        "b16": (16, 1),
        "b32": (32, 1),
    }
    offset = 0
    maximum = 1
    offsets: list[int] = []
    for _, field_type in TYPES[name]:
        if field_type in sizes:
            size, field_align = sizes[field_type]
        else:
            nested = layout(field_type, profile, cache)
            size, field_align = nested["size"], nested["align"]
        offset = align(offset, field_align)
        offsets.append(offset)
        offset += size
        maximum = max(maximum, field_align)
    result = {"size": align(offset, maximum), "align": maximum, "offsets": offsets}
    cache[name] = result
    return result


def expected_vector() -> dict[str, Any]:
    record = niaf_record()
    abi: dict[str, Any] = {}
    for profile_name, profile in PROFILES.items():
        cache: dict[str, dict[str, Any]] = {}
        abi[profile_name] = {**profile, "layouts": {name: layout(name, profile, cache) for name in TYPES}}
    return {
        "schema": "ninlil-identity-attachment-precondition-spec-kat-v1",
        "niaf": {
            "record_field_order": NIAF_RECORD_FIELD_ORDER,
            "field_offsets": NIAF_FIELD_OFFSETS,
            "record_hex": record.hex(),
            "sha256": hashlib.sha256(record).hexdigest(),
            "crc32c": crc32c(record[:304]),
        },
        "provider_abi": abi,
    }


def validate_manifest(manifest: dict[str, Any]) -> None:
    contract = manifest.get("identity_attachment_precondition_contract")
    if not isinstance(contract, dict):
        raise GateError("manifest identity contract missing")
    if contract.get("id") != "ninlil_identity_attachment_precondition_v1":
        raise GateError("manifest identity contract id drift")
    if contract.get("required_module_ids") != ["fabric_v1", "wifi_v1", "wifi_posix_v1", "wifi_esp_v1", "route_relay_v1", "radio_fabric_adapter_v1", "mfdt_v1"]:
        raise GateError("manifest required module roster drift")
    checkpoint = contract.get("restart_checkpoint_contract")
    if not isinstance(checkpoint, dict) or checkpoint.get("magic_ascii") != "NIAF" or checkpoint.get("record_size_bytes") != 308:
        raise GateError("manifest NIAF layout drift")
    if checkpoint.get("payload_digest", {}).get("coverage_size") != 272 or checkpoint.get("crc32c", {}).get("coverage_size") != 304:
        raise GateError("manifest NIAF coverage drift")
    if checkpoint.get("record_field_order") != NIAF_RECORD_FIELD_ORDER:
        raise GateError("manifest NIAF record field order drift")
    port = contract.get("provider_port")
    if not isinstance(port, dict) or port.get("id") != "ninlil_identity_attachment_provider_v1" or port.get("abi_version") != 1:
        raise GateError("manifest provider ABI identity drift")
    field_names = [
        "provider", "binding_handle", "binding_snapshot", "key_handle", "subscription_handle",
        "resolve_request", "resolve_result", "validate_request", "validate_result",
        "key_operation_request", "key_operation_result", "release_request", "release_result",
        "subscribe_request", "subscribe_result", "invalidation_event", "unsubscribe_request", "unsubscribe_result",
    ]
    for name in field_names:
        manifest_fields = port.get(f"{name}_field_order")
        expected_fields = [field for field, _ in TYPES[name]]
        if manifest_fields != expected_fields:
            raise GateError(f"manifest provider ABI field order drift at {name}")


def canonical_adr_status(adr_text: str) -> str:
    lines = adr_text.splitlines()
    if len(lines) < 3 or lines[0] != ADR_H1 or lines[1] != "":
        raise GateError("ADR-0039 canonical heading/status preamble drift")
    match = re.fullmatch(r"- Status: \*\*(Proposed|Accepted)\*\*", lines[2])
    if match is None or any("Status:" in line for line in lines[3:]):
        raise GateError("ADR-0039 canonical status drift")
    return match.group(1)


def validate_niaf_promotion(adr_text: str, registry: dict[str, Any]) -> None:
    expected_status = {"Proposed": "PROPOSED", "Accepted": "SPEC_ACCEPTED"}[
        canonical_adr_status(adr_text)
    ]
    entries = registry.get("entries")
    if not isinstance(entries, list):
        raise GateError("protocol magic registry entries missing")
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get("magic") == "NIAF"]
    if len(matches) != 1:
        raise GateError("protocol magic registry NIAF entry missing/duplicate")
    entry = matches[0]
    if (
        entry.get("owner") != "DOMAIN_STORE"
        or entry.get("artifact") != "DURABLE_RECORD"
        or entry.get("authority") != "docs/adr/0039-identity-attachment-precondition-gate.md"
        or entry.get("status") != expected_status
    ):
        raise GateError("ADR-0039/NIAF protocol magic promotion drift")


def check(
    vector: dict[str, Any],
    manifest: dict[str, Any],
    adr_text: str | None = None,
    magic_registry: dict[str, Any] | None = None,
) -> None:
    if vector != expected_vector():
        raise GateError("spec vector differs from independent NIAF/ABI oracle")
    validate_manifest(manifest)
    validate_niaf_promotion(
        ADR_PATH.read_text(encoding="utf-8") if adr_text is None else adr_text,
        load_json(MAGIC_REGISTRY_PATH) if magic_registry is None else magic_registry,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test", "generate"))
    args = parser.parse_args()
    try:
        if args.command == "generate":
            print(json.dumps(expected_vector(), indent=2, sort_keys=True))
            return 0
        vector = load_json(VECTOR_PATH)
        manifest = load_json(MANIFEST_PATH)
        check(vector, manifest)
        if args.command == "self-test":
            bad = copy.deepcopy(vector)
            bad["niaf"]["record_hex"] = "00" + bad["niaf"]["record_hex"][2:]
            try:
                check(bad, manifest)
            except GateError:
                pass
            else:
                raise GateError("self-test accepted NIAF byte mutation")
            bad_manifest = copy.deepcopy(manifest)
            bad_manifest["identity_attachment_precondition_contract"]["required_module_ids"].pop(0)
            try:
                check(vector, bad_manifest)
            except GateError:
                pass
            else:
                raise GateError("self-test accepted required roster mutation")
            bad_manifest = copy.deepcopy(manifest)
            bad_manifest["identity_attachment_precondition_contract"]["restart_checkpoint_contract"]["record_field_order"][4] = "uint64_t runtime_generation"
            try:
                check(vector, bad_manifest)
            except GateError:
                pass
            else:
                raise GateError("self-test accepted NIAF field order mutation")
            adr_text = ADR_PATH.read_text(encoding="utf-8")
            registry = load_json(MAGIC_REGISTRY_PATH)
            bad_registry = copy.deepcopy(registry)
            for entry in bad_registry["entries"]:
                if entry.get("magic") == "NIAF":
                    entry["status"] = "PROPOSED"
                    break
            try:
                check(
                    vector,
                    manifest,
                    adr_text=adr_text,
                    magic_registry=bad_registry,
                )
            except GateError:
                pass
            else:
                raise GateError("self-test accepted Accepted/PROPOSED NIAF drift")
            try:
                check(
                    vector,
                    manifest,
                    adr_text=adr_text.replace(
                        "- Status: **Accepted**", "- Status: **Proposed**", 1
                    ),
                    magic_registry=registry,
                )
            except GateError:
                pass
            else:
                raise GateError("self-test accepted Proposed/SPEC_ACCEPTED NIAF drift")
    except GateError as exc:
        print(f"identity attachment precondition spec gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"identity attachment precondition spec gate {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
