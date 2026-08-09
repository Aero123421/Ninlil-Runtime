#!/usr/bin/env python3
"""Keep the private consumer's ABI assertions byte-for-byte tied to the KAT."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
VECTOR = ROOT / "spec/vectors/identity-attachment-precondition-v1.json"
MANIFEST = ROOT / "public-module-manifest.json"
ASSERTS = ROOT / "src/runtime/identity_attachment_v1/identity_attachment_v1_layout_asserts.inc"

CTYPE = {
    "provider": "ninlil_identity_attachment_provider_v1_t",
    "binding_handle": "ninlil_identity_attachment_binding_handle_v1_t",
    "binding_snapshot": "ninlil_identity_attachment_binding_snapshot_v1_t",
    "key_handle": "ninlil_nonexporting_key_handle_v1_t",
    "subscription_handle": "ninlil_identity_attachment_subscription_handle_v1_t",
    "resolve_request": "ninlil_identity_attachment_resolve_request_v1_t",
    "resolve_result": "ninlil_identity_attachment_resolve_result_v1_t",
    "validate_request": "ninlil_identity_attachment_validate_request_v1_t",
    "validate_result": "ninlil_identity_attachment_validate_result_v1_t",
    "key_operation_request": "ninlil_identity_attachment_key_operation_request_v1_t",
    "key_operation_result": "ninlil_identity_attachment_key_operation_result_v1_t",
    "release_request": "ninlil_identity_attachment_release_request_v1_t",
    "release_result": "ninlil_identity_attachment_release_result_v1_t",
    "subscribe_request": "ninlil_identity_attachment_subscribe_request_v1_t",
    "subscribe_result": "ninlil_identity_attachment_subscribe_result_v1_t",
    "invalidation_event": "ninlil_identity_attachment_invalidation_event_v1_t",
    "unsubscribe_request": "ninlil_identity_attachment_unsubscribe_request_v1_t",
    "unsubscribe_result": "ninlil_identity_attachment_unsubscribe_result_v1_t",
}
LAYOUT = re.compile(r"IA_LAYOUT\(([^,]+), ([0-9]+)u, ([0-9]+)u\);")
OFFSET = re.compile(r"IA_OFFSET\(([^,]+), ([^,]+), ([0-9]+)u\);")


class FreshnessError(RuntimeError):
    pass


def load(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def member_name(declaration: str) -> str:
    return declaration.rsplit(" ", 1)[1].lstrip("*").split("[", 1)[0]


def expected(vector: dict, manifest: dict, profile: str) -> tuple[list[tuple], list[tuple]]:
    layouts = vector["provider_abi"][profile]["layouts"]
    port = manifest["identity_attachment_precondition_contract"]["provider_port"]
    size_asserts: list[tuple] = []
    offset_asserts: list[tuple] = []
    for name, ctype in CTYPE.items():
        item = layouts[name]
        size_asserts.append((ctype, item["size"], item["align"]))
        fields = port[f"{name}_field_order"]
        if len(fields) != len(item["offsets"]):
            raise FreshnessError(f"{name}: field/offset count drift")
        offset_asserts.extend(
            (ctype, member_name(field), offset)
            for field, offset in zip(fields, item["offsets"], strict=True)
        )
    return size_asserts, offset_asserts


def actual(section: str) -> tuple[list[tuple], list[tuple]]:
    return (
        [(name, int(size), int(alignment)) for name, size, alignment in LAYOUT.findall(section)],
        [(name, field, int(offset)) for name, field, offset in OFFSET.findall(section)],
    )


def check(text: str, vector: dict, manifest: dict) -> None:
    prefix = "#if defined(ESP_PLATFORM)\n"
    if prefix not in text or "\n#else\n" not in text or "\n#endif\n" not in text:
        raise FreshnessError("layout assertion profile split missing")
    esp, rest = text.split(prefix, 1)[1].split("\n#else\n", 1)
    lp64, _ = rest.split("\n#endif\n", 1)
    for profile, section in (("ESP32S3_XTENSA_ILP32", esp), ("LP64_SYSV", lp64)):
        if actual(section) != expected(vector, manifest, profile):
            raise FreshnessError(f"{profile}: layout assertions differ from KAT")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    try:
        vector = load(VECTOR)
        manifest = load(MANIFEST)
        text = ASSERTS.read_text(encoding="utf-8")
        check(text, vector, manifest)
        if args.command == "self-test":
            mutated = text.replace(
                "IA_OFFSET(ninlil_identity_attachment_provider_v1_t, context, 8u);",
                "IA_OFFSET(ninlil_identity_attachment_provider_v1_t, context, 9u);",
                1,
            )
            try:
                check(mutated, vector, manifest)
            except FreshnessError:
                pass
            else:
                raise FreshnessError("self-test accepted offset mutation")
    except (FreshnessError, OSError, KeyError, json.JSONDecodeError) as exc:
        print(f"identity attachment consumer layout freshness: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"identity attachment consumer layout freshness {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
