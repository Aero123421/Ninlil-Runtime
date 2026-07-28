#!/usr/bin/env python3
"""Structural gate for the V1 Runtime durable transaction boundary.

The gate protects three properties that are easy to regress during normal
Runtime maintenance:

* durable transaction records use the canonical, versioned codec rather than
  a native C struct or native-endian scalar;
* production call paths do not place the large transaction/codec workspaces
  on the automatic stack and do not allocate them from the heap;
* the codec retains the schema, bounds, CRC, full-consumption and closed
  semantic-registry checks required for fail-closed restart.

Usage:
  python3 tools/runtime_v1_durable_codec_gate.py check
  python3 tools/runtime_v1_durable_codec_gate.py self-test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME_DIR = REPO_ROOT / "src" / "runtime"

PRODUCTION_PATHS = (
    "runtime_v1_bearer_wire.c",
    "runtime_v1_capability.c",
    "runtime_v1_delivery_durable.c",
    "runtime_v1_event_mgmt.c",
    "runtime_v1_spine_durable.c",
    "v1_durable_allowlist.c",
)
CODEC_PATH = "runtime_v1_transaction_codec.c"
INTERNAL_PATH = "runtime_internal.h"
VERSION_HEADER = REPO_ROOT / "include" / "ninlil" / "version.h"

ALLOC_RE = re.compile(r"\b(?:malloc|calloc|realloc|free|alloca)\s*\(")
NATIVE_TX_SIZE_RE = re.compile(
    r"\bsizeof\s*\(\s*(?:struct\s+)?ninlil_rt_transaction_slot(?:_t)?\s*\)"
)
AUTO_TX_RE = re.compile(
    r"\b(?:struct\s+ninlil_rt_transaction_slot|"
    r"ninlil_rt_transaction_slot_t)\s+"
    r"(?!\*)([A-Za-z_]\w*)\s*(?:[;=\[])"
)
AUTO_RECORD_RE = re.compile(
    r"\b(?:uint8_t|unsigned\s+char|char)\s+\w+\s*\[\s*"
    r"NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES\s*\]"
)
OLD_TX_TOKEN_RE = re.compile(
    r"\b(?:"
    r"NINLIL_RT_V1_TX_(?:RECORD|VALUE)(?:_V[123])?[A-Z0-9_]*|"
    r"ninlil_rt_v1_transaction_(?:record_)?(?:encode|decode)_v[123]"
    r")\b"
)
NATIVE_SCALAR_COPY_RE = re.compile(
    r"\bmemcpy\s*\([^;]{0,180}"
    r"(?:payload_length|spool_revision|record_revision)"
    r"[^;]{0,180}\)",
    re.DOTALL,
)


def strip_c_comments_and_strings(src: str) -> str:
    out: List[str] = []
    index = 0
    while index < len(src):
        ch = src[index]
        if ch == "/" and index + 1 < len(src) and src[index + 1] == "/":
            index += 2
            while index < len(src) and src[index] not in "\r\n":
                index += 1
            continue
        if ch == "/" and index + 1 < len(src) and src[index + 1] == "*":
            index += 2
            while index + 1 < len(src) and not (
                src[index] == "*" and src[index + 1] == "/"
            ):
                if src[index] in "\r\n":
                    out.append(src[index])
                index += 1
            index = min(index + 2, len(src))
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(" ")
            index += 1
            while index < len(src):
                if src[index] == "\\" and index + 1 < len(src):
                    index += 2
                    continue
                if src[index] == quote:
                    index += 1
                    break
                if src[index] in "\r\n":
                    out.append(src[index])
                index += 1
            continue
        out.append(ch)
        index += 1
    return "".join(out)


def read_sources() -> Dict[str, str]:
    names = (*PRODUCTION_PATHS, CODEC_PATH, INTERNAL_PATH)
    return {
        name: (RUNTIME_DIR / name).read_text(encoding="utf-8")
        for name in names
    }


def function_body(source: str, function_name: str) -> str:
    match = re.search(
        r"\b" + re.escape(function_name) + r"\s*\([^)]*\)\s*\{",
        source,
    )
    if match is None:
        return ""
    open_brace = source.find("{", match.start())
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace : index + 1]
    return ""


def analyze(sources: Dict[str, str]) -> List[str]:
    errors: List[str] = []
    stripped = {
        name: strip_c_comments_and_strings(text)
        for name, text in sources.items()
    }

    for name in PRODUCTION_PATHS:
        source = stripped[name]
        for label, pattern in (
            ("heap_or_alloca", ALLOC_RE),
            ("native_transaction_size", NATIVE_TX_SIZE_RE),
            ("automatic_transaction", AUTO_TX_RE),
            ("automatic_record_buffer", AUTO_RECORD_RE),
            ("legacy_transaction_codec", OLD_TX_TOKEN_RE),
            ("native_scalar_durable_copy", NATIVE_SCALAR_COPY_RE),
        ):
            if pattern.search(source):
                errors.append(f"{name}:{label}")

    combined_production = "\n".join(stripped[name] for name in PRODUCTION_PATHS)
    for required in (
        "ninlil_rt_v1_transaction_record_encode",
        "ninlil_rt_v1_transaction_record_decode",
        "ninlil_rt_v1_transaction_record_validate_envelope",
        "ninlil_rt_v1_reservation_marker_encode",
        "ninlil_rt_v1_reservation_marker_decode",
        "ninlil_rt_v1_event_operation_marker_encode",
        "ninlil_rt_v1_event_operation_marker_validate",
    ):
        if required not in combined_production:
            errors.append(f"production:missing_use:{required}")

    codec = stripped[CODEC_PATH]
    for required in (
        "NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MAJOR",
        "NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MINOR",
        "encode_u16_be_at",
        "encode_u32_be_at",
        "decode_u16_be_at",
        "decode_u32_be_at",
        "ninlil_model_domain_crc32c",
        "reader.position != reader.limit",
        "transaction_valid",
        "family_valid",
        "reason_valid",
    ):
        if required not in codec:
            errors.append(f"{CODEC_PATH}:missing:{required}")
    family_body = function_body(codec, "family_valid")
    reason_body = function_body(codec, "reason_valid")
    if not family_body or "default:" not in family_body:
        errors.append(f"{CODEC_PATH}:family_registry_not_closed")
    if not reason_body or "default:" not in reason_body:
        errors.append(f"{CODEC_PATH}:reason_registry_not_closed")
    version_header = strip_c_comments_and_strings(
        VERSION_HEADER.read_text(encoding="utf-8")
    )
    expected_families = {
        value
        for value in re.findall(
            r"#define\s+(NINLIL_FAMILY_[A-Z0-9_]+)\b",
            version_header,
        )
        if "_MASK_" not in value
    }
    actual_families = set(re.findall(
        r"\bcase\s+(NINLIL_FAMILY_[A-Z0-9_]+)\s*:",
        family_body,
    ))
    if actual_families != expected_families:
        errors.append(f"{CODEC_PATH}:family_registry_not_exact")
    expected_reasons = set(re.findall(
        r"#define\s+(NINLIL_REASON_[A-Z0-9_]+)\b",
        version_header,
    ))
    actual_reasons = set(re.findall(
        r"\bcase\s+(NINLIL_REASON_[A-Z0-9_]+)\s*:",
        reason_body,
    ))
    if actual_reasons != expected_reasons:
        errors.append(f"{CODEC_PATH}:reason_registry_not_exact")
    if ALLOC_RE.search(codec):
        errors.append(f"{CODEC_PATH}:heap_or_alloca")
    if AUTO_TX_RE.search(codec):
        errors.append(f"{CODEC_PATH}:automatic_transaction")
    if OLD_TX_TOKEN_RE.search(codec):
        errors.append(f"{CODEC_PATH}:legacy_transaction_codec")

    internal = stripped[INTERNAL_PATH]
    for required in (
        "transaction_codec_bytes",
        "durable_scan_value",
        "transaction_decode_scratch",
        "transaction_scratch",
    ):
        if required not in internal:
            errors.append(f"{INTERNAL_PATH}:missing_runtime_workspace:{required}")

    return sorted(set(errors))


def check() -> None:
    errors = analyze(read_sources())
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("ok runtime_v1_durable_codec_source_gate")


def self_test() -> None:
    baseline = read_sources()
    baseline_errors = analyze(baseline)
    if baseline_errors:
        print("self-test precondition failed:", *baseline_errors, sep="\n  ")
        raise SystemExit(1)

    mutations = (
        (
            "native transaction persistence",
            "runtime_v1_delivery_durable.c",
            "\nstatic size_t mutation(void) {\n"
            "  return sizeof(ninlil_rt_transaction_slot_t);\n}\n",
            "native_transaction_size",
        ),
        (
            "automatic transaction workspace",
            "runtime_v1_spine_durable.c",
            "\nstatic void mutation(void) {\n"
            "  ninlil_rt_transaction_slot_t candidate;\n"
            "  (void)candidate;\n}\n",
            "automatic_transaction",
        ),
        (
            "automatic codec buffer",
            "runtime_v1_event_mgmt.c",
            "\nstatic void mutation(void) {\n"
            "  uint8_t value[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];\n"
            "  (void)value;\n}\n",
            "automatic_record_buffer",
        ),
        (
            "heap allocation",
            "runtime_v1_bearer_wire.c",
            "\nstatic void mutation(void) { (void)malloc(1u); }\n",
            "heap_or_alloca",
        ),
        (
            "legacy codec",
            "runtime_v1_capability.c",
            "\nstatic void mutation(void) {\n"
            "  (void)NINLIL_RT_V1_TX_RECORD_V2_BYTES;\n}\n",
            "legacy_transaction_codec",
        ),
    )
    for label, name, injection, expected in mutations:
        mutated = dict(baseline)
        mutated[name] += injection
        errors = analyze(mutated)
        if not any(expected in error for error in errors):
            print(f"mutation did not go red: {label}", file=sys.stderr)
            raise SystemExit(1)

    mutated = dict(baseline)
    mutated[CODEC_PATH] = mutated[CODEC_PATH].replace(
        "reader.position != reader.limit",
        "reader.position == reader.limit",
        1,
    )
    errors = analyze(mutated)
    if not any("reader.position != reader.limit" in error for error in errors):
        print("mutation did not go red: full consumption", file=sys.stderr)
        raise SystemExit(1)

    mutated = dict(baseline)
    mutated[CODEC_PATH] = mutated[CODEC_PATH].replace(
        "    case NINLIL_REASON_NONE:\n",
        "",
        1,
    )
    errors = analyze(mutated)
    if not any("reason_registry_not_exact" in error for error in errors):
        print("mutation did not go red: reason registry hole", file=sys.stderr)
        raise SystemExit(1)

    print("ok runtime_v1_durable_codec_gate_self_test")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "self-test"):
        print(
            "usage: runtime_v1_durable_codec_gate.py check|self-test",
            file=sys.stderr,
        )
        raise SystemExit(2)
    if sys.argv[1] == "self-test":
        self_test()
    else:
        check()


if __name__ == "__main__":
    main()
