#!/usr/bin/env python3
"""RRMP ESP memory/resource authority gate.

This gate intentionally separates three claims:

* the final ESP ELF/map contains the production RRMP objects and keeps their
  internal-DRAM BSS contribution below the configured ceiling;
* the checked-in software/HIL manifests agree with the constants compiled by
  the implementation and with the host workspace measurement;
* the ESP build is configured for capability-based PSRAM allocation.

It does *not* claim that a physical board allocated the buffers successfully.
That value remains a physical-HIL evidence field and must stay NOT_RUN/null
until the target campaign is actually executed.

Usage:
  python3 tools/rrmp_esp_dram_budget_gate.py authority-check \
      [--workspace-probe PATH]
  python3 tools/rrmp_esp_dram_budget_gate.py check --map PATH \
      [--sdkconfig PATH]
  python3 tools/rrmp_esp_dram_budget_gate.py self-test
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any

REPO = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO / "tools/rrmp_software_hil_manifest.json"
DEFAULT_TEMPLATE = REPO / "tools/rrmp_hil_evidence_template.json"

# Internal DRAM BSS for RRMP production+smoke objects after SPIRAM offload.
# The large owner workspace/export/store buffers are capability-allocated.
DEFAULT_BSS_BUDGET = 32 * 1024
REQUIRED_OBJS = (
    "rrmp_core.c.obj",
    "rrmp_codec.c.obj",
    "rrmp_store.c.obj",
    "rrmp_util.c.obj",
    "rrmp_seam.c.obj",
    "rrmp_composition.c.obj",
    "rrmp_target_smoke.c.obj",
)
FORBIDDEN_LIVE = ("rrmp_sim.c.obj",)
RESOURCE_FIELDS = (
    "workspace_budget_bytes",
    "workspace_measured_host_bytes",
    "storage_export_max_bytes",
    "storage_piece_scratch_bytes",
    "target_smoke_store_bytes",
    "worst_case_live_dynamic_bytes",
)
CATALOG_NAMES = (
    "ninlil_route_install_batch",
    "ninlil_route_activate",
    "ninlil_route_begin_drain",
    "ninlil_route_retire",
    "ninlil_route_query",
    "ninlil_route_forward_admit",
    "ninlil_route_forward_complete",
    "ninlil_route_cancel_drain",
    "ninlil_route_recover_commit_unknown",
    "ninlil_route_diagnostics_snapshot",
    "ninlil_parent_set_install",
    "ninlil_parent_owner_prepare",
    "ninlil_parent_owner_fence_proof",
    "ninlil_parent_authority_commit",
    "ninlil_parent_owner_prepare_v2",
    "ninlil_parent_owner_fence_proof_v2",
    "ninlil_parent_authority_commit_v2",
    "ninlil_parent_owner_activate",
    "ninlil_parent_endpoint_observe",
    "ninlil_parent_owner_retire",
    "ninlil_parent_query",
    "ninlil_parent_recover_commit_unknown",
    "ninlil_parent_diagnostics_snapshot",
)
SEAM_NAMES = (
    "ninlil_rrmp_seam_admit_from_nfl1_view",
    "ninlil_rrmp_seam_fabric_forward_once",
    "ninlil_rrmp_seam_fabric_relay_cycle",
)


class GateError(RuntimeError):
    """Expected gate rejection."""


def fail(msg: str) -> None:
    raise GateError(msg)


def read_json(path: pathlib.Path) -> dict[str, Any]:
    if not path.is_file():
        fail(f"JSON authority not found: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON authority {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"JSON authority root must be an object: {path}")
    return value


def required_dict(parent: dict[str, Any], key: str, where: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        fail(f"{where}.{key} must be an object")
    return value


def required_int(parent: dict[str, Any], key: str, where: str) -> int:
    value = parent.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"{where}.{key} must be a non-negative integer")
    return value


def required_bool(parent: dict[str, Any], key: str, where: str) -> bool:
    value = parent.get(key)
    if not isinstance(value, bool):
        fail(f"{where}.{key} must be a boolean")
    return value


def parse_uint_define(path: pathlib.Path, name: str) -> int:
    text = path.read_text(encoding="utf-8")
    match = re.search(
        rf"^\s*#define\s+{re.escape(name)}\s+(.+?)\s*$",
        text,
        re.MULTILINE,
    )
    if match is None:
        fail(f"required resource constant missing: {path}:{name}")
    expr = re.sub(r"(?<=\d)[uUlL]+", "", match.group(1)).strip()
    expression = re.fullmatch(
        r"\(?\s*(?P<left>\d+)\s*(?:\*\s*(?P<right>\d+)\s*)?\)?",
        expr,
    )
    if expression is None:
        fail(f"unsupported resource constant expression {name}={match.group(1)!r}")
    value = int(expression.group("left"))
    if expression.group("right") is not None:
        value *= int(expression.group("right"))
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        fail(f"resource constant {name} must evaluate to a positive integer")
    return value


def verify_portable_mutable_scratch(core: str, util: str) -> None:
    mutable_static_object = re.compile(
        r"^[ \t]*static[ \t]+(?P<declaration>[^;{}\n]+);",
        re.MULTILINE,
    )
    for label, source in (("rrmp_core.c", core), ("rrmp_util.c", util)):
        for match in mutable_static_object.finditer(source):
            declaration = " ".join(match.group("declaration").split())
            first_paren = declaration.find("(")
            function_prototype = False
            if first_paren > 0 and not any(
                token in declaration[:first_paren] for token in ("=", "[", "]")
            ):
                depth = 0
                closing_paren = -1
                for index, char in enumerate(declaration[first_paren:], first_paren):
                    if char == "(":
                        depth += 1
                    elif char == ")":
                        depth -= 1
                        if depth == 0:
                            closing_paren = index
                            break
                prefix = declaration[:first_paren].rstrip()
                function_prototype = (
                    closing_paren == len(declaration) - 1
                    and re.search(r"[A-Za-z_][A-Za-z0-9_]*$", prefix) is not None
                )

            # Function prototypes and immutable non-pointer const objects are
            # not mutable storage.  A pointer to const remains mutable unless
            # the pointer itself is const, so it deliberately fails closed.
            immutable_const_object = (
                declaration.startswith("const ") and "*" not in declaration
            )
            # Every mutable static object fails closed, including pointers,
            # arrays, parenthesized initializers and function-pointer objects.
            if function_prototype or immutable_const_object:
                continue
            fail(f"{label} contains mutable static object: {declaration}")
    required_route_scratch = (
        "(uint8_t (*)[NINLIL_RRMP_SLOT_BYTES])o->enc_page_b"
    )
    if required_route_scratch not in core:
        fail("RRMP route-slot scratch is not pinned to the current owner")
    if "static int kat_ok" in util:
        fail("RRMP SHA KAT result must not use a process-global mutable cache")


def verify_explicit_serial_owner(
    abi: str, core: str, seam_header: str, seam_source: str
) -> None:
    first_owner = r"\s*\(\s*ninlil_rrmp_owner_t\s*\*\s*owner\s*,"
    for name in CATALOG_NAMES:
        pattern = re.compile(rf"\b{re.escape(name)}{first_owner}")
        if len(pattern.findall(abi)) != 1:
            fail(f"RRMP catalog declaration lacks explicit owner: {name}")
        if len(pattern.findall(core)) != 1:
            fail(f"RRMP catalog definition lacks explicit owner: {name}")
    for name in SEAM_NAMES:
        pattern = re.compile(rf"\b{re.escape(name)}{first_owner}")
        if len(pattern.findall(seam_header)) != 1:
            fail(f"RRMP seam declaration lacks explicit owner: {name}")
        if len(pattern.findall(seam_source)) != 1:
            fail(f"RRMP seam definition lacks explicit owner: {name}")

    lifecycle = re.compile(
        r"\bninlil_rrmp_owner_unbind\s*\(\s*ninlil_rrmp_owner_t\s*\*\s*owner\s*\)"
    )
    if len(lifecycle.findall(abi)) != 1 or len(lifecycle.findall(core)) != 1:
        fail("RRMP owner_unbind must target one explicit owner")

    sources = (abi, core, seam_header, seam_source)
    forbidden = ("g_bound", "ninlil_rrmp_owner_current")
    for token in forbidden:
        if any(token in source for source in sources):
            fail(f"RRMP legacy current-owner source remains: {token}")


def verify_large_allocations_are_psram_only() -> None:
    abi_path = REPO / "src/runtime/route_relay_v1/rrmp_abi.h"
    core_path = REPO / "src/runtime/route_relay_v1/rrmp_core.c"
    util_path = REPO / "src/runtime/route_relay_v1/rrmp_util.c"
    seam_header_path = REPO / "src/runtime/route_relay_v1/rrmp_seam.h"
    seam_source_path = REPO / "src/runtime/route_relay_v1/rrmp_seam.c"
    smoke_path = REPO / "ports/esp-idf/src/rrmp_target_smoke.c"
    abi = abi_path.read_text(encoding="utf-8")
    core = core_path.read_text(encoding="utf-8")
    util = util_path.read_text(encoding="utf-8")
    seam_header = seam_header_path.read_text(encoding="utf-8")
    seam_source = seam_source_path.read_text(encoding="utf-8")
    smoke = smoke_path.read_text(encoding="utf-8")

    verify_portable_mutable_scratch(core, util)
    verify_explicit_serial_owner(abi, core, seam_header, seam_source)

    for field, size in (
        ("storage_export_scratch", "NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX"),
        ("storage_piece_scratch", "NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX"),
    ):
        if re.search(
            rf"\buint8_t\s+{field}\s*\[\s*{size}\s*\]\s*;", core
        ) is None:
            fail(f"RRMP caller-owned scratch field missing or unbounded: {field}")
    if "heap_caps_malloc(" in core or "esp_heap_caps.h" in core:
        fail("RRMP core must not own platform allocation or lazy global scratch")
    if re.search(r"static\s+uint8_t\s+\*?s_rrmp_storage_", core) is not None:
        fail("RRMP storage scratch must be owner-local, not process-global")

    smoke_fn = re.search(
        r"static void \*smoke_caps_alloc\(.*?\)\s*\{(?P<body>.*?)^\}",
        smoke,
        re.MULTILINE | re.DOTALL,
    )
    if smoke_fn is None:
        fail("RRMP target smoke CAPS allocator not found")
    smoke_body = smoke_fn.group("body")
    if "MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT" not in smoke_body:
        fail("RRMP target smoke buffers are not explicitly allocated from PSRAM")
    if smoke_body.count("heap_caps_aligned_alloc(") != 1:
        fail("RRMP target smoke buffers must not fall back to internal DRAM")


def verify_authority(
    manifest_path: pathlib.Path,
    template_path: pathlib.Path,
    workspace_probe: pathlib.Path | None,
) -> dict[str, int]:
    manifest = read_json(manifest_path)
    template = read_json(template_path)
    ns = required_dict(manifest, "namespace_keys", "manifest")
    prereq = required_dict(template, "software_prerequisites", "template")

    values = {name: required_int(ns, name, "manifest.namespace_keys") for name in RESOURCE_FIELDS}
    for name in RESOURCE_FIELDS:
        other = required_int(prereq, name, "template.software_prerequisites")
        if other != values[name]:
            fail(f"manifest/template resource drift for {name}: {values[name]} != {other}")

    includes_scratch = required_bool(
        ns, "workspace_includes_storage_scratch", "manifest.namespace_keys"
    )
    if required_bool(
        prereq,
        "workspace_includes_storage_scratch",
        "template.software_prerequisites",
    ) != includes_scratch or not includes_scratch:
        fail("RRMP workspace must include both durable scratch buffers")

    expected_worst = (
        values["workspace_measured_host_bytes"]
        + values["target_smoke_store_bytes"]
    )
    if values["worst_case_live_dynamic_bytes"] != expected_worst:
        fail(
            "worst_case_live_dynamic_bytes is not the exact live-buffer sum: "
            f"{values['worst_case_live_dynamic_bytes']} != {expected_worst}"
        )
    if values["workspace_measured_host_bytes"] > values["workspace_budget_bytes"]:
        fail("measured host owner workspace exceeds its checked-in budget")

    kib = ns.get("worst_case_live_dynamic_kib")
    expected_kib = expected_worst / 1024.0
    if isinstance(kib, bool) or not isinstance(kib, (int, float)):
        fail("manifest.namespace_keys.worst_case_live_dynamic_kib must be numeric")
    if abs(float(kib) - expected_kib) > 0.000001:
        fail(f"worst-case KiB drift: {kib} != {expected_kib}")

    types_path = REPO / "src/runtime/route_relay_v1/rrmp_types.h"
    smoke_path = REPO / "ports/esp-idf/src/rrmp_target_smoke.c"
    source_values = {
        "workspace_budget_bytes": parse_uint_define(
            types_path, "NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES"
        ),
        "storage_export_max_bytes": parse_uint_define(
            types_path, "NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX"
        ),
        "storage_piece_scratch_bytes": parse_uint_define(
            types_path, "NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX"
        ),
        "target_smoke_store_bytes": parse_uint_define(
            smoke_path, "RRMP_SMOKE_STORE_BYTES"
        ),
    }
    for name, source_value in source_values.items():
        if values[name] != source_value:
            fail(f"manifest/source resource drift for {name}: {values[name]} != {source_value}")
    manifest_bytes = parse_uint_define(
        types_path, "NINLIL_RRMP_RRM1_BYTES"
    )
    if values["target_smoke_store_bytes"] != (
        values["storage_export_max_bytes"] + manifest_bytes
    ):
        fail(
            "target smoke store is not the exact RRM1 manifest+five-chunk "
            "piece-vector capacity"
        )

    claims = required_dict(manifest, "claims", "manifest")
    physical_hil = required_dict(manifest, "physical_hil", "manifest")
    physical_claims = required_dict(template, "physical_claims", "template")
    if claims.get("physical_rf_powercut_hil") != 0:
        fail("software manifest must not claim physical RF/power-cut HIL")
    if physical_hil.get("status") != "NOT_RUN":
        fail("RRMP physical HIL status must remain NOT_RUN until evidence exists")
    if any(value != "NOT_RUN" for value in physical_claims.values()):
        fail("RRMP physical claims must remain NOT_RUN until evidence exists")
    if prereq.get("esp_runtime_workspace_measured_bytes") is not None:
        fail("ESP runtime workspace measurement must remain null before physical HIL")
    if prereq.get("esp_runtime_minimum_free_psram_bytes") is not None:
        fail("ESP free-PSRAM measurement must remain null before physical HIL")

    verify_large_allocations_are_psram_only()

    if workspace_probe is not None:
        if not workspace_probe.is_file():
            fail(f"workspace probe not found: {workspace_probe}")
        try:
            output = subprocess.check_output(
                [str(workspace_probe)],
                text=True,
                stderr=subprocess.STDOUT,
                timeout=120,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            fail(f"workspace probe failed: {exc}")
        match = re.search(r"\bws(?:_bytes)?=(\d+)\b", output)
        if match is None:
            fail("workspace probe did not report ws=<integer> or ws_bytes=<integer>")
        measured = int(match.group(1))
        if measured != values["workspace_measured_host_bytes"]:
            fail(
                "manifest/host-binary workspace drift: "
                f"{values['workspace_measured_host_bytes']} != {measured}"
            )

    return values


def config_enabled(text: str, name: str) -> bool:
    return (
        re.search(rf"^\s*{re.escape(name)}=y\s*$", text, re.MULTILINE) is not None
        or re.search(
            rf"^\s*#define\s+{re.escape(name)}\s+1\s*$", text, re.MULTILINE
        )
        is not None
    )


def verify_sdkconfig(path: pathlib.Path) -> None:
    if not path.is_file():
        fail(f"sdkconfig not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    for name in (
        "CONFIG_SPIRAM",
        "CONFIG_SPIRAM_USE_CAPS_ALLOC",
        "CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1",
    ):
        if not config_enabled(text, name):
            fail(f"required ESP resource config is not enabled: {name}")


def parse_rrmp_bss(map_text: str) -> list[tuple[int, str, str]]:
    """Return live RRMP rows from `.dram0.bss`, including wrapped rows."""
    rows: list[tuple[int, str, str]] = []
    same_line = re.compile(
        r"^\s+(\.bss\S*)\s+0x[0-9a-fA-F]+\s+"
        r"(0x[0-9a-fA-F]+)\s+(\S*rrmp\S*)\s*$"
    )
    section_only = re.compile(r"^\s+(\.bss\S*)\s*$")
    continuation = re.compile(
        r"^\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+"
        r"(\S*rrmp\S*)\s*$"
    )
    output_section = re.compile(
        r"^(\.\S+)\s+0x[0-9a-fA-F]+\s+0x[0-9a-fA-F]+"
    )
    in_dram_bss = False
    pending: str | None = None
    for line in map_text.splitlines():
        output = output_section.match(line)
        if output is not None:
            in_dram_bss = output.group(1) == ".dram0.bss"
            pending = None
            continue
        if not in_dram_bss:
            continue
        match = same_line.match(line)
        if match is not None:
            rows.append((int(match.group(2), 16), match.group(3), line.strip()))
            pending = None
            continue
        split = section_only.match(line)
        if split is not None:
            pending = split.group(1)
            continue
        match = continuation.match(line)
        if pending is not None and match is not None:
            rows.append(
                (
                    int(match.group(1), 16),
                    match.group(2),
                    f"{pending} {line.strip()}",
                )
            )
        pending = None
    return rows


def check_map(map_path: pathlib.Path, budget: int) -> int:
    if not map_path.is_file():
        fail(f"map not found: {map_path}")
    text = map_path.read_text(encoding="utf-8", errors="replace")

    for label in FORBIDDEN_LIVE:
        live = re.findall(
            rf"^\s*\.(?:bss|text)[^\n]*{re.escape(label)}",
            text,
            re.MULTILINE,
        )
        for hit in live:
            match = re.search(r"(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)", hit)
            if match is not None and int(match.group(2), 16) > 0:
                fail(f"host-only sim TU live in production map: {label}")

    for required in REQUIRED_OBJS:
        if required not in text:
            fail(f"required RRMP object missing from map: {required}")

    rows = parse_rrmp_bss(text)
    if not rows:
        fail(
            "zero live RRMP .dram0.bss rows parsed (map format mismatch or "
            "RRMP not linked)"
        )
    total = sum(size for size, _, _ in rows)
    if total > budget:
        fail(f"RRMP .bss total {total} exceeds budget {budget}")
    return total


def expect_rejection(fn: Any, label: str) -> None:
    try:
        fn()
    except GateError:
        return
    fail(f"self-test false-green: {label} was accepted")


def self_test() -> None:
    values = verify_authority(DEFAULT_MANIFEST, DEFAULT_TEMPLATE, None)
    core = (REPO / "src/runtime/route_relay_v1/rrmp_core.c").read_text(
        encoding="utf-8"
    )
    abi = (REPO / "src/runtime/route_relay_v1/rrmp_abi.h").read_text(
        encoding="utf-8"
    )
    seam_header = (REPO / "src/runtime/route_relay_v1/rrmp_seam.h").read_text(
        encoding="utf-8"
    )
    seam_source = (REPO / "src/runtime/route_relay_v1/rrmp_seam.c").read_text(
        encoding="utf-8"
    )
    util = (REPO / "src/runtime/route_relay_v1/rrmp_util.c").read_text(
        encoding="utf-8"
    )
    sample = """
.dram0.bss 0x3fc9db68 0x100
 .bss.rrmp  0x00000000  0x00000100  libninlil.a(rrmp_core.c.obj)
 .text.rrmp 0x00000000  0x00000200  libninlil.a(rrmp_codec.c.obj)
rrmp_store.c.obj
rrmp_util.c.obj
rrmp_seam.c.obj
rrmp_core.c.obj
rrmp_codec.c.obj
rrmp_composition.c.obj
rrmp_target_smoke.c.obj
"""
    split_oversized = """
.dram0.bss 0x3fc9db68 0x20000
 .bss.rrmp_enormous_workspace_with_long_symbol_name
                0x3fc9db68 0x20000 libninlil.a(rrmp_core.c.obj)
rrmp_store.c.obj
rrmp_util.c.obj
rrmp_seam.c.obj
rrmp_codec.c.obj
rrmp_composition.c.obj
rrmp_target_smoke.c.obj
"""
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        map_path = root / "test.map"
        map_path.write_text(sample, encoding="utf-8")
        if check_map(map_path, DEFAULT_BSS_BUDGET) != 256:
            fail("self-test map BSS parser returned the wrong total")
        split_path = root / "split.map"
        split_path.write_text(split_oversized, encoding="utf-8")
        expect_rejection(
            lambda: check_map(split_path, DEFAULT_BSS_BUDGET),
            "split-line oversized RRMP BSS row",
        )

        bad_manifest = read_json(DEFAULT_MANIFEST)
        bad_manifest["namespace_keys"]["worst_case_live_dynamic_bytes"] += 1
        bad_manifest_path = root / "bad-manifest.json"
        bad_manifest_path.write_text(
            json.dumps(bad_manifest, sort_keys=True), encoding="utf-8"
        )
        expect_rejection(
            lambda: verify_authority(bad_manifest_path, DEFAULT_TEMPLATE, None),
            "incorrect live-buffer sum",
        )

        bad_manifest = read_json(DEFAULT_MANIFEST)
        bad_manifest["namespace_keys"]["workspace_includes_storage_scratch"] = False
        bad_manifest_path.write_text(
            json.dumps(bad_manifest, sort_keys=True), encoding="utf-8"
        )
        expect_rejection(
            lambda: verify_authority(bad_manifest_path, DEFAULT_TEMPLATE, None),
            "process-global durable scratch regression",
        )

        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core + "\n    static uint8_t renamed_scratch[64];\n", util
            ),
            "function-static route scratch regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core,
                util + "\n    static int renamed_kat_cache = -1;\n",
            ),
            "function-static SHA KAT cache regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core.replace(
                    "(uint8_t (*)[NINLIL_RRMP_SLOT_BYTES])o->enc_page_b",
                    "(uint8_t (*)[NINLIL_RRMP_SLOT_BYTES])slot_scratch",
                    1,
                ),
                util,
            ),
            "route scratch detached from owner",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core + "\nstatic uint8_t file_scope_scratch[64];\n", util
            ),
            "column-zero file-static route scratch regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core,
                util + "\nstatic int file_scope_kat_cache = -1;\n",
            ),
            "column-zero file-static SHA KAT cache regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core, util + "\nstatic int disguised_cache = (0);\n"
            ),
            "parenthesized mutable static initializer regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core, util + "\nstatic uint8_t disguised_scratch[(64)];\n"
            ),
            "parenthesized mutable static array regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core, util + "\nstatic int (*mutable_callback)(void);\n"
            ),
            "mutable static function-pointer regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core,
                util
                + "\nstatic const uint8_t *renamed_storage_scratch = NULL;\n",
            ),
            "mutable static pointer-to-const regression",
        )
        expect_rejection(
            lambda: verify_portable_mutable_scratch(
                core + "\nstatic ninlil_rrmp_owner_t *renamed_bound;\n", util
            ),
            "renamed mutable owner pointer regression",
        )
        verify_portable_mutable_scratch(
            core,
            util
            + "\nstatic int rrmp_self_test_prototype(const uint8_t *bytes);\n",
        )
        verify_explicit_serial_owner(abi, core, seam_header, seam_source)
        expect_rejection(
            lambda: verify_explicit_serial_owner(
                abi.replace(
                    "ninlil_route_install_batch(\n    ninlil_rrmp_owner_t *owner,",
                    "ninlil_route_install_batch(",
                    1,
                ),
                core,
                seam_header,
                seam_source,
            ),
            "catalog owner argument removal",
        )
        expect_rejection(
            lambda: verify_explicit_serial_owner(
                abi,
                core + "\nstatic ninlil_rrmp_owner_t *g_bound;\n",
                seam_header,
                seam_source,
            ),
            "legacy owner pointer spelling",
        )
        expect_rejection(
            lambda: verify_explicit_serial_owner(
                abi + "\nninlil_rrmp_owner_t *ninlil_rrmp_owner_current(void);\n",
                core,
                seam_header,
                seam_source,
            ),
            "legacy current-owner accessor",
        )

        bad_config = root / "sdkconfig"
        bad_config.write_text(
            "CONFIG_SPIRAM=y\n"
            "CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=y\n",
            encoding="utf-8",
        )
        expect_rejection(
            lambda: verify_sdkconfig(bad_config),
            "missing CONFIG_SPIRAM_USE_CAPS_ALLOC",
        )

    print(
        "rrmp_esp_dram_budget_gate self-test OK "
        f"worst_case={values['worst_case_live_dynamic_bytes']}"
    )


def add_authority_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", type=pathlib.Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--template", type=pathlib.Path, default=DEFAULT_TEMPLATE)
    parser.add_argument("--workspace-probe", type=pathlib.Path)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    authority = sub.add_parser("authority-check")
    add_authority_args(authority)

    check = sub.add_parser("check")
    check.add_argument("--map", required=True, type=pathlib.Path)
    check.add_argument("--budget", type=int, default=DEFAULT_BSS_BUDGET)
    check.add_argument("--sdkconfig", type=pathlib.Path)
    add_authority_args(check)

    sub.add_parser("self-test")
    args = parser.parse_args()

    if args.cmd == "self-test":
        self_test()
        return 0

    values = verify_authority(args.manifest, args.template, args.workspace_probe)
    if args.cmd == "authority-check":
        print(
            "rrmp_resource_authority_gate OK "
            f"workspace={values['workspace_measured_host_bytes']} "
            f"worst_case={values['worst_case_live_dynamic_bytes']}"
        )
        return 0

    total = check_map(args.map, args.budget)
    if args.sdkconfig is not None:
        verify_sdkconfig(args.sdkconfig)
    print(
        f"rrmp_esp_dram_budget_gate OK bss_total={total} "
        f"budget={args.budget} worst_case={values['worst_case_live_dynamic_bytes']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print(f"rrmp_esp_dram_budget_gate FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1)
