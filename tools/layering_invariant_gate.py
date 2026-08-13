#!/usr/bin/env python3
"""Fail closed on Ninlil portable-Core dependency-direction regressions.

This is intentionally a small include/source-authority gate, not a general
build-graph framework.  It enforces the concrete boundaries in docs/01 and
Accepted ADR-0003 that have executable source representations today.
"""

from __future__ import annotations

import argparse
import posixpath
import pathlib
import re
import sys
from collections.abc import Mapping

REPO = pathlib.Path(__file__).resolve().parents[1]
RRMP_AUTHORITY = "cmake/ninlil_rrmp_sources.cmake"
MFDT_AUTHORITY = "cmake/ninlil_mfdt_v1_sources.cmake"
HOST_RUNTIME_AUTHORITY = "cmake/ninlil_host_runtime_sources.cmake"

RRMP_HOST = ("ports/posix/rrmp_sha256_openssl3.c",)
RRMP_ESP = ("ports/esp-idf/src/rrmp_sha256_mbedtls.c",)
RRMP_PORTABLE = (
    "src/runtime/route_relay_v1/rrmp_util.c",
    "src/runtime/route_relay_v1/rrmp_codec.c",
    "src/runtime/route_relay_v1/rrmp_store.c",
    "src/runtime/route_relay_v1/rrmp_core.c",
    "src/runtime/route_relay_v1/rrmp_seam.c",
    "src/runtime/route_relay_v1/rrmp_fabric_dispatch.c",
    "src/runtime/route_relay_v1/rrmp_composition.c",
)
RRMP_HOST_SIM = ("src/runtime/route_relay_v1/rrmp_sim.c",)
MFDT_HOST = ("src/runtime/mfdt_v1/mfdt_v1_target_alloc.c",)
MFDT_ESP = ("ports/esp-idf/src/mfdt_v1_target_alloc.c",)
MFDT_PRODUCTION = (
    "src/runtime/mfdt_v1/mfdt_v1_crypto.c",
    "src/runtime/mfdt_v1/mfdt_v1_wire.c",
    "src/runtime/mfdt_v1/mfdt_v1_record.c",
    "src/runtime/mfdt_v1/mfdt_v1_store_port.c",
    "src/runtime/mfdt_v1/mfdt_v1_engine.c",
    "src/runtime/mfdt_v1/mfdt_v1_hil_gate.c",
    "src/runtime/mfdt_v1/mfdt_v1_ncl1.c",
    "src/runtime/mfdt_v1/mfdt_v1_pipeline.c",
    "src/runtime/mfdt_v1/mfdt_v1_bearer_worker.c",
    "src/runtime/mfdt_v1/mfdt_v1_foundation_carrier.c",
    "src/runtime/mfdt_v1/mfdt_v1_runtime_owner.c",
    "src/runtime/mfdt_v1/mfdt_v1_runtime_seam.c",
    "src/runtime/mfdt_v1/mfdt_v1_spine.c",
    "src/runtime/mfdt_v1/mfdt_v1_session.c",
)
MFDT_LAB = ("src/runtime/mfdt_v1/mfdt_v1_store.c",)
MFDT_HOST_ONLY = (
    "src/runtime/mfdt_v1/mfdt_v1_host_store.c",
    "src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c",
)
MFDT_ESP_STORE = ("src/runtime/mfdt_v1/mfdt_v1_store_esp.c",)
MFDT_PORTABLE_REFERENCES = (
    "${NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES}",
    "${NINLIL_MFDT_V1_LAB_RELATIVE_SOURCES}",
    "${NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES}",
    "${NINLIL_MFDT_V1_HOST_ADAPTER_RELATIVE_SOURCES}",
)
HOST_RUNTIME_SOURCES = (
    "src/model/control_frame_codec.c",
    "src/model/domain_store_body_codec.c",
    "src/model/domain_store_codec.c",
    "src/model/ncl1_codec.c",
    "src/model/resource_ledger.c",
    "src/model/resource_ledger_batch.c",
    "src/model/runtime_lifecycle_model.c",
    "src/model/runtime_store_bootstrap.c",
    "src/model/runtime_store_codec.c",
    "src/model/submission_admission.c",
    "src/model/submission_preflight.c",
    "src/runtime/domain_store_d3s1.c",
    "src/runtime/domain_store_d3s2.c",
    "src/runtime/domain_store_d3s3.c",
    "src/runtime/domain_store_d3s4.c",
    "src/runtime/domain_store_scanner.c",
    "src/runtime/runtime_public.c",
    "src/runtime/runtime_terminal_owner_projection.c",
    "src/runtime/runtime_store_orchestrator.c",
    "src/runtime/runtime_store_stage5_seam.c",
    "src/runtime/runtime_v1_spine_durable.c",
    "src/runtime/runtime_v1_delivery_durable.c",
    "src/runtime/runtime_v1_transaction_codec.c",
    "src/runtime/runtime_v1_bearer_wire.c",
    "src/runtime/runtime_v1_capability.c",
    "src/runtime/runtime_v1_event_ledger_codec.c",
    "src/runtime/runtime_v1_event_mgmt.c",
    "src/runtime/runtime_v1_family_capability.c",
    "src/runtime/runtime_v1_target_resolver.c",
    "src/runtime/submission_canonical_v1.c",
    "src/runtime/stage5_empty_metadata.c",
    "src/runtime/v1_durable_allowlist.c",
    "src/runtime/v1_durable_restart.c",
    "src/runtime/storage_canonical_plan.c",
    "${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}",
)

# Platform-dependent TUs/headers that intentionally live beside their private
# Transport/Radio implementation today. Every other file in those two source
# trees remains portable and may use only ISO C plus declared first-party
# edges. A new adapter therefore requires an explicit authority update.
PLATFORM_ADAPTER_FILES = frozenset(
    {
        "src/radio/r7_crypto_openssl3.c",
        "src/transport/posix_tls_v1/posix_tls_v1.c",
        "src/transport/wifi_v1/wifi_attachment_m4.c",
        "src/transport/wifi_v1/wifi_esp_mbedtls_profile_probe.c",
        "src/transport/wifi_v1/wifi_esp_owner.c",
        "src/transport/wifi_v1/wifi_esp_owner.h",
        "src/transport/wifi_v1/wifi_esp_sta.c",
        "src/transport/wifi_v1/wifi_esp_tcp.c",
        "src/transport/wifi_v1/wifi_esp_tls_allocator.c",
        "src/transport/wifi_v1/wifi_esp_tls_mbedtls.c",
        "src/transport/wifi_v1/wifi_sha256_host.c",
        "src/transport/wifi_v1/wifi_sha256_mbedtls.c",
        "src/transport/wifi_v1/wifi_tcp_posix.c",
        "src/transport/wifi_v1/wifi_tls_export.c",
        "src/transport/wifi_v1/wifi_tls_host.c",
        "src/transport/wifi_v1/wifi_tls_host_internal.h",
    }
)

INCLUDE_LIKE_DIRECTIVE_RE = re.compile(
    r"^[ \t\v\f]*(?:#|%:)[ \t\v\f]*"
    r"(include(?:_next)?|import)\b([^\r\n]*)",
    re.MULTILINE,
)
LITERAL_INCLUDE_RE = re.compile(
    r'^[ \t\v\f]*([<"])([^>"\r\n]+)[>"][ \t\v\f]*$'
)
ISO_C_HEADERS = frozenset(
    {
        "assert.h",
        "complex.h",
        "ctype.h",
        "errno.h",
        "fenv.h",
        "float.h",
        "inttypes.h",
        "iso646.h",
        "limits.h",
        "locale.h",
        "math.h",
        "setjmp.h",
        "signal.h",
        "stdalign.h",
        "stdarg.h",
        "stdatomic.h",
        "stdbool.h",
        "stddef.h",
        "stdint.h",
        "stdio.h",
        "stdlib.h",
        "stdnoreturn.h",
        "string.h",
        "tgmath.h",
        "threads.h",
        "time.h",
        "uchar.h",
        "wchar.h",
        "wctype.h",
    }
)

# Cross-layer private includes are intentionally exact. Same-layer includes,
# public Ninlil contracts, and Runtime -> Model are handled by the layer map
# below; every other private edge must be named here. This keeps an unrelated
# Transport or Radio TU from gaining access merely because another component
# has one approved seam to that layer.
PRIVATE_CROSS_LAYER_EDGES = frozenset(
    {
        (
            "src/runtime/composition_v1.c",
            "src/transport/fabric_v1/fabric_private_api.h",
        ),
        (
            "src/runtime/c4_c5_lab_wire.h",
            "src/transport/c4_lab_usb_path.h",
        ),
        (
            "src/runtime/c4_c5_lab_wire.h",
            "src/radio/c5_lab_radio_path.h",
        ),
        (
            "src/radio/m4_lab_primitive.c",
            "src/model/domain_store_codec.h",
        ),
        (
            "src/radio/n6_crypto_host.c",
            "src/model/domain_store_codec.h",
        ),
        (
            "src/radio/n6_record_codec.c",
            "src/model/domain_store_codec.h",
        ),
        (
            "src/radio/sx1262_r9_edge.c",
            "src/model/domain_store_codec.h",
        ),
        (
            "src/transport/control_session.h",
            "src/model/control_frame_codec.h",
        ),
        (
            "src/transport/control_session_layout.h",
            "src/model/control_frame_codec.h",
        ),
        (
            "src/transport/fabric_v1/v1_usb_bridge.h",
            "src/model/control_frame_codec.h",
        ),
        (
            "src/transport/logical_session.h",
            "src/model/ncl1_codec.h",
        ),
        (
            "src/transport/logical_session_layout.h",
            "src/model/control_frame_codec.h",
        ),
        (
            "src/transport/logical_session_layout.h",
            "src/model/ncl1_codec.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_binding.h",
            "src/radio/r7_crypto_provider.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_board_owner.h",
            "src/radio/radio_hal.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_n6_owner.c",
            "src/radio/r7_context_binding.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_n6_owner.h",
            "src/radio/n6_context_store.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_n6_owner.h",
            "src/radio/r7_crypto_provider.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_n6_owner.h",
            "src/radio/r7_frag/r7_r2_authority_clock.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_radio_packet_link.h",
            "src/radio/r7_frag/r7_frag_prod_orch.h",
        ),
        (
            "src/radio/sx1262_r9_edge.h",
            "drivers/sx126x/ninlil_sx1262_phy.h",
        ),
        (
            "src/transport/fabric_v1/v1_lab_radio_packet_link.h",
            "drivers/sx126x/ninlil_sx1262_phy.h",
        ),
    }
)


class GateError(RuntimeError):
    pass


def _layer(path: str) -> str | None:
    for prefix, name in (
        ("include/ninlil/", "public"),
        ("src/contract/", "contract"),
        ("src/model/", "model"),
        ("src/runtime/", "runtime"),
        ("src/transport/", "transport"),
        ("src/radio/", "radio"),
        ("ports/", "port"),
        ("drivers/", "driver"),
    ):
        if path.startswith(prefix):
            return name
    return None


_TRIGRAPHS = {
    "??=": "#",
    "??/": "\\",
    "??'": "^",
    "??(": "[",
    "??)": "]",
    "??!": "|",
    "??<": "{",
    "??>": "}",
    "??-": "~",
}


def _translate_for_directive_scan(text: str) -> str:
    """Apply the C phases relevant to finding real include directives.

    Trigraph replacement precedes physical-line splicing, and comments are
    recognized only outside string/character literals.  Keeping newlines and
    replacing comment bytes with spaces preserves directive line boundaries.
    """

    # Normalize all physical end-of-line representations before the phase-2
    # backslash-newline splice; Clang accepts lone CR source lines as well as
    # LF and CRLF.
    text = text.removeprefix("\ufeff")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for source, replacement in _TRIGRAPHS.items():
        text = text.replace(source, replacement)
    # Also reject/normalize the compiler extension that permits horizontal
    # whitespace between the backslash and newline. Strict project builds turn
    # its warning into an error, but the architecture gate must remain closed
    # independently of compiler diagnostics.
    text = re.sub(r"\\[ \t\v\f]*\n", "", text)

    output: list[str] = []
    index = 0
    state = "normal"
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "normal":
            if char == '"':
                state = "string"
                output.append(char)
            elif char == "'":
                state = "character"
                output.append(char)
            elif char == "/" and following == "*":
                state = "block_comment"
                # Translation phase 3 replaces the *whole* comment, including
                # embedded newlines, with one space.  Those newlines therefore
                # cannot terminate a preprocessing directive.
                output.append(" ")
                index += 1
            elif char == "/" and following == "/":
                state = "line_comment"
                output.extend((" ", " "))
                index += 1
            else:
                output.append(char)
        elif state in {"string", "character"}:
            if char == "\n":
                raise GateError("unterminated C string/character literal")
            output.append(char)
            if char == "\\" and following:
                output.append(following)
                index += 1
            elif state == "string" and char == '"':
                state = "normal"
            elif state == "character" and char == "'":
                state = "normal"
        elif state == "block_comment":
            if char == "*" and following == "/":
                index += 1
                state = "normal"
        else:
            if char in "\r\n":
                output.append(char)
                state = "normal"
            else:
                output.append(" ")
        index += 1
    if state not in {"normal", "line_comment"}:
        raise GateError(f"unterminated C lexical construct: {state}")
    return "".join(output)


def _cmake_list(text: str, name: str) -> tuple[str, ...]:
    matches = list(re.finditer(
        rf"\bset\s*\(\s*{re.escape(name)}\b(.*?)\)",
        text,
        flags=re.DOTALL,
    ))
    if len(matches) != 1:
        raise GateError(
            f"CMake source authority must be written by exactly one set(): "
            f"{name}: writes={len(matches)}"
        )
    body = re.sub(r"#[^\r\n]*", "", matches[0].group(1))
    values = tuple(token for token in re.split(r"\s+", body.strip()) if token)
    if not values:
        raise GateError(f"empty CMake source authority: {name}")
    return values


def _expect_closed_cmake_authority(
    text: str, expected_names: tuple[str, ...]
) -> None:
    """Allow only one literal set() write for each source-authority variable."""
    uncommented = re.sub(r"#[^\r\n]*", "", text)
    commands = tuple(
        match.group(1).casefold()
        for match in re.finditer(
            r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)[ \t]*\(",
            uncommented,
        )
    )
    if not commands or any(command != "set" for command in commands):
        raise GateError(
            "CMake source authority may contain only literal set() commands: "
            f"commands={commands!r}"
        )
    targets = tuple(
        match.group(1)
        for match in re.finditer(
            r"\bset\s*\(\s*([^\s\)]+)",
            uncommented,
            flags=re.IGNORECASE,
        )
    )
    if targets != expected_names:
        raise GateError(
            "CMake source authority write set/order drift: "
            f"expected={expected_names!r}, got={targets!r}"
        )


def _expect_exact(text: str, name: str, expected: tuple[str, ...]) -> None:
    actual = _cmake_list(text, name)
    if actual != expected:
        raise GateError(f"{name}: expected {expected!r}, got {actual!r}")


def _resolve_first_party_header(
    source_path: str, include: str, first_party_paths: frozenset[str]
) -> str | None:
    relative = posixpath.normpath(
        posixpath.join(posixpath.dirname(source_path), include)
    )
    if relative in first_party_paths:
        return relative
    if include.startswith("ninlil/") and f"include/{include}" in first_party_paths:
        return f"include/{include}"
    suffix = f"/{include}"
    matches = sorted(path for path in first_party_paths if path.endswith(suffix))
    same_layer = [path for path in matches if _layer(path) == _layer(source_path)]
    if len(same_layer) == 1:
        return same_layer[0]
    if len(matches) > 1:
        raise GateError(
            f"ambiguous first-party include: {source_path}: {include}: {matches}"
        )
    return matches[0] if matches else None


def _portable_edge_allowed(source: str, target: str) -> bool:
    source_layer = _layer(source)
    target_layer = _layer(target)
    if source_layer is None or target_layer is None:
        return False
    if target_layer == "public":
        return True
    if source_layer == target_layer:
        return True
    if source_layer == "runtime" and target_layer == "model":
        return True
    return (source, target) in PRIVATE_CROSS_LAYER_EDGES


def _validate_texts(texts: Mapping[str, str]) -> None:
    first_party_paths = frozenset(
        path for path in texts if path.endswith((".c", ".h"))
    )
    for path, raw in texts.items():
        if not path.endswith((".c", ".h")):
            continue
        source_layer = _layer(path)
        if source_layer not in {
            "public",
            "contract",
            "model",
            "runtime",
            "transport",
            "radio",
        }:
            continue
        source = _translate_for_directive_scan(raw)
        for directive, operand in INCLUDE_LIKE_DIRECTIVE_RE.findall(source):
            if directive != "include":
                raise GateError(
                    f"non-standard include directive is forbidden: "
                    f"{path}: {directive}"
                )
            literal = LITERAL_INCLUDE_RE.fullmatch(operand)
            if literal is None:
                raise GateError(
                    f"non-literal include is forbidden: {path}: {operand.strip()}"
                )
            _delimiter, include = literal.groups()
            target = _resolve_first_party_header(path, include, first_party_paths)
            if target is not None:
                if target.endswith(".c"):
                    raise GateError(
                        f"including a first-party translation unit is forbidden: "
                        f"{path} -> {target}"
                    )
                if not _portable_edge_allowed(path, target):
                    raise GateError(
                        "declared layer map rejects private dependency edge: "
                        f"{path} -> {target}"
                    )
                continue
            if source_layer in {"public", "contract", "model", "runtime"}:
                if include in ISO_C_HEADERS:
                    continue
                raise GateError(
                    "portable Core imports a non-ISO/non-first-party header: "
                    f"{path}: {include}"
                )
            if source_layer in {"transport", "radio"}:
                if include in ISO_C_HEADERS or path in PLATFORM_ADAPTER_FILES:
                    continue
                raise GateError(
                    "portable Transport/Radio source imports a platform header: "
                    f"{path}: {include}"
                )

    rrmp = texts[RRMP_AUTHORITY]
    mfdt = texts[MFDT_AUTHORITY]
    host_runtime = texts[HOST_RUNTIME_AUTHORITY]
    _expect_closed_cmake_authority(
        rrmp,
        (
            "NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES",
            "NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES",
            "NINLIL_RRMP_ESP_ADAPTER_RELATIVE_SOURCES",
            "NINLIL_RRMP_HOST_SIM_RELATIVE_SOURCES",
        ),
    )
    _expect_closed_cmake_authority(
        mfdt,
        (
            "NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES",
            "NINLIL_MFDT_V1_LAB_RELATIVE_SOURCES",
            "NINLIL_MFDT_V1_HOST_ADAPTER_RELATIVE_SOURCES",
            "NINLIL_MFDT_V1_ESP_ADAPTER_RELATIVE_SOURCES",
            "NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES",
            "NINLIL_MFDT_V1_ESP_STORE_RELATIVE_SOURCES",
            "NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES",
            "NINLIL_MFDT_V1_SOURCES_AUTHORITY_LOADED",
        ),
    )
    _expect_closed_cmake_authority(
        host_runtime, ("NINLIL_HOST_RUNTIME_RELATIVE_SOURCES",)
    )
    _expect_exact(rrmp, "NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES", RRMP_HOST)
    _expect_exact(rrmp, "NINLIL_RRMP_ESP_ADAPTER_RELATIVE_SOURCES", RRMP_ESP)
    _expect_exact(rrmp, "NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES", RRMP_PORTABLE)
    _expect_exact(rrmp, "NINLIL_RRMP_HOST_SIM_RELATIVE_SOURCES", RRMP_HOST_SIM)
    _expect_exact(
        mfdt, "NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES", MFDT_PRODUCTION
    )
    _expect_exact(mfdt, "NINLIL_MFDT_V1_LAB_RELATIVE_SOURCES", MFDT_LAB)
    _expect_exact(mfdt, "NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES", MFDT_HOST_ONLY)
    _expect_exact(mfdt, "NINLIL_MFDT_V1_HOST_ADAPTER_RELATIVE_SOURCES", MFDT_HOST)
    _expect_exact(mfdt, "NINLIL_MFDT_V1_ESP_ADAPTER_RELATIVE_SOURCES", MFDT_ESP)
    _expect_exact(
        mfdt, "NINLIL_MFDT_V1_ESP_STORE_RELATIVE_SOURCES", MFDT_ESP_STORE
    )
    _expect_exact(
        mfdt, "NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES", MFDT_PORTABLE_REFERENCES
    )
    _expect_exact(
        mfdt, "NINLIL_MFDT_V1_SOURCES_AUTHORITY_LOADED", ("TRUE",)
    )
    _expect_exact(
        host_runtime,
        "NINLIL_HOST_RUNTIME_RELATIVE_SOURCES",
        HOST_RUNTIME_SOURCES,
    )

    # Exact leaf lists above also reject CMake variable/semicolon expansion.
    # Without this closed grammar, one apparent token can expand into a hidden
    # platform adapter after this text-level gate has accepted it.
    for name, values in (
        ("RRMP portable", RRMP_PORTABLE),
        ("RRMP Host simulator", RRMP_HOST_SIM),
        ("MFDT production", MFDT_PRODUCTION),
        ("MFDT LAB", MFDT_LAB),
        ("MFDT Host", MFDT_HOST_ONLY),
        ("MFDT ESP store", MFDT_ESP_STORE),
    ):
        if any(
            re.fullmatch(r"(?:src|ports|drivers)/[A-Za-z0-9_./+-]+\.c", path)
            is None
            for path in values
        ):
            raise GateError(f"{name} authority contains a non-literal C source")

    if "src/transport/fabric_v1/fabric_rrmp_select_hook.h" in texts:
        raise GateError("deleted Transport-to-Runtime hook was restored")
    fabric_core = texts["src/transport/fabric_v1/fabric_private_core.c"]
    if "ninlil_fabric_private_path_selected_fn_v1" not in fabric_core:
        raise GateError("Fabric lost its opaque path-selected callback seam")


def _read_repo() -> dict[str, str]:
    texts: dict[str, str] = {}
    for base in (REPO / "include", REPO / "src", REPO / "ports", REPO / "drivers"):
        for path in sorted(base.rglob("*")):
            if path.suffix in {".c", ".h"}:
                texts[path.relative_to(REPO).as_posix()] = path.read_text(
                    encoding="utf-8"
                )
    for relative in (RRMP_AUTHORITY, MFDT_AUTHORITY, HOST_RUNTIME_AUTHORITY):
        texts[relative] = (REPO / relative).read_text(encoding="utf-8")
    return texts


def check() -> None:
    _validate_texts(_read_repo())


def self_test() -> None:
    base = _read_repo()
    _validate_texts(base)

    portable_target = "src/runtime/route_relay_v1/rrmp_util.c"
    for header in (
        "mbedtls/sha256.h",
        "nvs.h",
        "sdkconfig.h",
        "lwip/sockets.h",
        "sys/socket.h",
        "poll.h",
        "pthread.h",
        "windows.h",
        "IOKit/serial/IOSerialKeys.h",
        "unistd.h",
        "fcntl.h",
        "dlfcn.h",
        "sys/stat.h",
        "sys/types.h",
        "mach/mach.h",
        "CoreFoundation/CoreFoundation.h",
        "android/log.h",
        "future_vendor_sdk.h",
    ):
        changed = dict(base)
        changed[portable_target] = (
            f"#include <{header}>\n" + changed[portable_target]
        )
        try:
            _validate_texts(changed)
        except GateError:
            pass
        else:
            raise GateError(f"self-test false green: portable include {header}")

    changed = dict(base)
    changed[portable_target] = (
        "#define NINLIL_PLATFORM_HEADER <esp_heap_caps.h>\n"
        "#include NINLIL_PLATFORM_HEADER\n"
        + changed[portable_target]
    )
    try:
        _validate_texts(changed)
    except GateError:
        pass
    else:
        raise GateError("self-test false green: macro-expanded portable include")

    changed = dict(base)
    changed[portable_target] = (
        "%:include <unistd.h>\n" + changed[portable_target]
    )
    try:
        _validate_texts(changed)
    except GateError:
        pass
    else:
        raise GateError("self-test false green: C digraph portable include")

    for label, prefix in (
        ("spliced hash keyword", "#inc\\\nlude <unistd.h>\n"),
        ("spliced hash keyword with spaces", "#inc\\   \nlude <unistd.h>\n"),
        ("spliced digraph keyword", "%:inc\\\nlude <unistd.h>\n"),
        ("spliced lone-CR keyword", "#inc\\\rlude <unistd.h>\r"),
        ("UTF-8 BOM", "\ufeff#include <unistd.h>\n"),
        ("C trigraph", "??=include <unistd.h>\n"),
        ("form-feed directive whitespace", "#\finclude <unistd.h>\n"),
        ("vertical-tab directive whitespace", "\v#\vinclude <unistd.h>\n"),
        ("newline inside block-comment directive gap", "#/*\n*/include <unistd.h>\n"),
        ("include-next extension", "#include_next <unistd.h>\n"),
        ("import extension", "#import <unistd.h>\n"),
        (
            "comment markers in string literals",
            'static const char *a = "/*";\n'
            "#include <unistd.h>\n"
            'static const char *b = "*/";\n',
        ),
    ):
        changed = dict(base)
        changed[portable_target] = prefix + changed[portable_target]
        try:
            _validate_texts(changed)
        except GateError:
            pass
        else:
            raise GateError(
                f"self-test false green: translated include via {label}"
            )

    for source_path, header in (
        (
            "src/runtime/runtime_public.c",
            "../transport/fabric_v1/v1_lab_radio_packet_link.h",
        ),
        (
            "src/runtime/runtime_public.c",
            "../transport/fabric_v1/fabric_private_api.h",
        ),
        (
            "src/model/runtime_lifecycle_model.c",
            "../radio/r7_frag/r7_frag.h",
        ),
        (
            "src/model/runtime_lifecycle_model.c",
            "../transport/wifi_v1/wifi_nwb1.h",
        ),
        (
            "src/radio/radio_hal.c",
            "../runtime/runtime_internal.h",
        ),
        (
            "src/radio/r7_wire_codec.c",
            "../runtime/route_relay_v1/rrmp_types.h",
        ),
        (
            "src/transport/control_session.c",
            "../model/runtime_lifecycle_model.h",
        ),
        (
            "src/transport/fabric_v1/fabric_private_core.c",
            "../../model/runtime_lifecycle_model.h",
        ),
        (
            "src/transport/wifi_v1/wifi_nwb1.c",
            "../../radio/r7_frag/r7_frag.h",
        ),
        (
            "src/transport/control_session.c",
            "../runtime/stage5_empty_metadata.c",
        ),
        (
            "src/radio/radio_hal.c",
            "../runtime/stage5_empty_metadata.c",
        ),
        ("src/radio/radio_hal.c", "unistd.h"),
        ("src/radio/radio_hal.c", "esp_heap_caps.h"),
        ("src/transport/fabric_v1/fabric_private_core.c", "unistd.h"),
        (
            "src/transport/fabric_v1/fabric_private_core.c",
            "esp_heap_caps.h",
        ),
        (
            "src/radio/radio_hal.c",
            "../../ports/esp-idf/src/ninlil_esp_idf_internal.h",
        ),
    ):
        changed = dict(base)
        changed[source_path] = f'#include "{header}"\n' + changed[source_path]
        try:
            _validate_texts(changed)
        except GateError:
            pass
        else:
            raise GateError(
                f"self-test false green: forbidden first-party edge {source_path} -> {header}"
            )

    changed = dict(base)
    transport_target = "src/transport/fabric_v1/fabric_private_core.c"
    changed[transport_target] = (
        '#include "rrmp_fabric_dispatch.h"\n' + changed[transport_target]
    )
    try:
        _validate_texts(changed)
    except GateError:
        pass
    else:
        raise GateError("self-test false green: Transport to Runtime include")

    changed = dict(base)
    changed[RRMP_AUTHORITY] = changed[RRMP_AUTHORITY].replace(
        RRMP_HOST[0], RRMP_ESP[0], 1
    )
    try:
        _validate_texts(changed)
    except GateError:
        pass
    else:
        raise GateError("self-test false green: RRMP adapter authority drift")

    for label, authority, needle, injected in (
        (
            "RRMP variable expansion in portable leaf",
            RRMP_AUTHORITY,
            "set(NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES\n",
            "set(NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES\n"
            "    ${NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES}\n",
        ),
        (
            "RRMP semicolon expansion in portable leaf",
            RRMP_AUTHORITY,
            "    src/runtime/route_relay_v1/rrmp_util.c\n",
            "    src/runtime/route_relay_v1/rrmp_util.c;"
            "ports/posix/rrmp_sha256_openssl3.c\n",
        ),
        (
            "MFDT platform adapter in production leaf",
            MFDT_AUTHORITY,
            "set(NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES\n",
            "set(NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES\n"
            "    ${NINLIL_MFDT_V1_ESP_ADAPTER_RELATIVE_SOURCES}\n",
        ),
        (
            "RRMP post-definition list APPEND",
            RRMP_AUTHORITY,
            "",
            "\nlist(APPEND NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES "
            "${NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES})\n",
        ),
        (
            "RRMP second set write",
            RRMP_AUTHORITY,
            "",
            "\nset(NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES "
            "${NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES})\n",
        ),
        (
            "RRMP post-definition list INSERT",
            RRMP_AUTHORITY,
            "",
            "\nlist(INSERT NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES 0 "
            "ports/posix/rrmp_sha256_openssl3.c)\n",
        ),
        (
            "MFDT post-definition list APPEND",
            MFDT_AUTHORITY,
            "",
            "\nlist(APPEND NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES "
            "${NINLIL_MFDT_V1_ESP_ADAPTER_RELATIVE_SOURCES})\n",
        ),
        (
            "private control session appended to Host Runtime",
            HOST_RUNTIME_AUTHORITY,
            "    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}\n",
            "    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}\n"
            "    src/transport/control_session.c\n",
        ),
        (
            "private logical session appended to Host Runtime",
            HOST_RUNTIME_AUTHORITY,
            "    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}\n",
            "    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}\n"
            "    src/transport/logical_session.c\n",
        ),
        (
            "Host Runtime post-definition list APPEND",
            HOST_RUNTIME_AUTHORITY,
            "",
            "\nlist(APPEND NINLIL_HOST_RUNTIME_RELATIVE_SOURCES "
            "src/transport/control_session.c)\n",
        ),
    ):
        changed = dict(base)
        if needle:
            changed[authority] = changed[authority].replace(needle, injected, 1)
        else:
            changed[authority] += injected
        try:
            _validate_texts(changed)
        except GateError:
            pass
        else:
            raise GateError(f"self-test false green: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    try:
        if args.command == "check":
            check()
        else:
            self_test()
    except (GateError, OSError) as exc:
        print(f"layering invariant gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"layering invariant gate: {args.command}: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
