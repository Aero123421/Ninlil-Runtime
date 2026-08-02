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


def verify_large_allocations_are_psram_only() -> None:
    core_path = REPO / "src/runtime/route_relay_v1/rrmp_core.c"
    smoke_path = REPO / "ports/esp-idf/src/rrmp_target_smoke.c"
    core = core_path.read_text(encoding="utf-8")
    smoke = smoke_path.read_text(encoding="utf-8")

    core_fn = re.search(
        r"static int rrmp_export_scratch_ready\(void\)\s*\{(?P<body>.*?)^\}",
        core,
        re.MULTILINE | re.DOTALL,
    )
    if core_fn is None:
        fail("RRMP export scratch allocator not found")
    core_body = core_fn.group("body")
    if core_body.count("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT") != 2:
        fail("RRMP export/piece scratch buffers are not explicitly allocated from PSRAM")
    if core_body.count("heap_caps_malloc(") != 2:
        fail("RRMP export/piece scratch allocation count drift or internal-DRAM fallback")

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

    expected_worst = (
        values["workspace_measured_host_bytes"]
        + values["storage_export_max_bytes"]
        + values["storage_piece_scratch_bytes"]
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
    rows: list[tuple[int, str, str]] = []
    pat = re.compile(
        r"^\s*\.bss[^\s]*\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+(\S*rrmp\S*)\s*$"
    )
    for line in map_text.splitlines():
        match = pat.match(line)
        if match is None:
            continue
        rows.append((int(match.group(1), 16), match.group(2), line.strip()))
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

    total = sum(size for size, _, _ in parse_rrmp_bss(text))
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
    sample = """
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
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        map_path = root / "test.map"
        map_path.write_text(sample, encoding="utf-8")
        if check_map(map_path, DEFAULT_BSS_BUDGET) != 256:
            fail("self-test map BSS parser returned the wrong total")

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
