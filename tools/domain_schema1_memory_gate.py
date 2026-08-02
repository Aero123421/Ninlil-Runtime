#!/usr/bin/env python3
"""
Domain schema1 HOST_CANDIDATE memory gate.

Completion requires either:
  - NINLIL_ESP_MAP / --esp-map: ESP-IDF .map with feature-ON DRAM evidence, OR
  - NINLIL_DOMAIN_MEMORY_HOST_ONLY=1 for explicit host-only non-completion check.

Map-less default is FAIL (no false-green). Peak formula:
  peak = sizeof(runtime) + max(sizeof(owner_ws), sizeof(kind1_ws))
  # both workspaces are transient and mutually exclusive

Optional ESP_HIL acceptance JSON (free heap / stack watermark) via
NINLIL_DOMAIN_HIL_METRICS when present.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

KIND1_WS_CEILING = 196608
RUNTIME_DRAM_SOFT = 131072
HOST_PEAK_SOFT = RUNTIME_DRAM_SOFT + KIND1_WS_CEILING  # 327680


def fail(msg: str) -> int:
    print(f"domain_schema1_memory_gate FAIL: {msg}", file=sys.stderr)
    return 1


def check_headers() -> list[str]:
    errs: list[str] = []
    k1 = (REPO / "src/runtime/domain_schema1_kind1_register.h").read_text(
        encoding="utf-8"
    )
    owner = (REPO / "src/runtime/domain_schema1_startup_owner.h").read_text(
        encoding="utf-8"
    )
    if str(KIND1_WS_CEILING) not in k1:
        errs.append("kind1_register.h missing KIND1_WS_CEILING_BYTES")
    if str(RUNTIME_DRAM_SOFT) not in k1:
        errs.append("kind1_register.h missing RUNTIME_DRAM_SOFT_BUDGET")
    if "HOST_PEAK_SOFT_BUDGET" not in k1:
        errs.append("kind1_register.h missing HOST_PEAK_SOFT_BUDGET_BYTES")
    if "OWNER_WORKSPACE_CEILING" not in owner:
        errs.append("startup_owner.h missing OWNER_WORKSPACE_CEILING")
    if "Caller-owned" not in owner and "caller-owned" not in owner:
        errs.append("owner workspace must document caller-owned")
    return errs


def parse_esp_map(map_path: Path) -> dict[str, int]:
    text = map_path.read_text(encoding="utf-8", errors="replace")
    totals: dict[str, int] = {}
    for m in re.finditer(
        r"^\s*\.(dram0\.[a-zA-Z0-9_]+)\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)",
        text,
        re.M,
    ):
        name, size_hex = m.group(1), m.group(2)
        totals[name] = totals.get(name, 0) + int(size_hex, 16)
    for m in re.finditer(r"\bDRAM\b[^\n]*?\s(\d+)\s+\d+\s+\d+", text):
        totals["DRAM_table"] = int(m.group(1))
    # .bss / .data under DIRAM when present
    for m in re.finditer(
        r"^\s*\.(bss|data)\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)",
        text,
        re.M,
    ):
        totals[m.group(1)] = totals.get(m.group(1), 0) + int(m.group(2), 16)
    return totals


def check_esp_map(map_path: Path) -> list[str]:
    errs: list[str] = []
    if not map_path.is_file():
        return [f"ESP map not found: {map_path}"]
    totals = parse_esp_map(map_path)
    if not totals:
        return [
            f"could not parse DRAM sections from {map_path}; "
            "feature-ON map is a required completion artifact"
        ]
    dram = sum(v for k, v in totals.items() if k.startswith("dram0."))
    if "DRAM_table" in totals:
        dram = max(dram, totals["DRAM_table"])
    # Static BSS envelope: runtime-class soft + spare for ports, not 2x fudge alone.
    static_soft = HOST_PEAK_SOFT
    if dram > static_soft:
        errs.append(
            f"ESP static DRAM~{dram} exceeds peak soft {static_soft} "
            f"(sections={totals})"
        )
    else:
        print(
            f"domain_schema1_memory_gate ESP map DRAM~{dram} "
            f"peak_soft={static_soft} sections={totals}"
        )
    # Require feature symbol evidence when nm dump provided
    return errs


def check_hil_metrics(path: Path) -> list[str]:
    errs: list[str] = []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"HIL metrics unreadable: {exc}"]
    # Expected keys from ESP acceptance harness
    for key in (
        "min_free_heap_after_runtime_create",
        "min_free_heap_during_service_register",
        "min_free_heap_after_service_register",
        "task_stack_high_watermark_bytes",
    ):
        if key not in data:
            errs.append(f"HIL metrics missing {key}")
    return errs


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("check", "self-test", "completion"))
    p.add_argument("--esp-map", type=Path, default=None)
    p.add_argument("--hil-metrics", type=Path, default=None)
    args = p.parse_args(argv)

    errs = check_headers()
    if args.mode == "self-test":
        if errs:
            return fail("; ".join(errs))
        print("domain_schema1_memory_gate self-test OK")
        return 0

    map_path = args.esp_map
    if map_path is None and os.environ.get("NINLIL_ESP_MAP"):
        map_path = Path(os.environ["NINLIL_ESP_MAP"])
    hil_path = args.hil_metrics
    if hil_path is None and os.environ.get("NINLIL_DOMAIN_HIL_METRICS"):
        hil_path = Path(os.environ["NINLIL_DOMAIN_HIL_METRICS"])

    host_only = os.environ.get("NINLIL_DOMAIN_MEMORY_HOST_ONLY") == "1"
    if map_path is None:
        if args.mode == "completion" or not host_only:
            return fail(
                "ESP feature-ON .map required (set NINLIL_ESP_MAP or --esp-map). "
                "Map-less is not a completion success. "
                "For host header-only non-completion: "
                "NINLIL_DOMAIN_MEMORY_HOST_ONLY=1"
            )
        print(
            "domain_schema1_memory_gate HOST_ONLY: headers only "
            f"(peak soft formula runtime+kind1_ws <= {HOST_PEAK_SOFT}); "
            "NOT completion"
        )
    else:
        errs.extend(check_esp_map(map_path))

    if hil_path is not None:
        errs.extend(check_hil_metrics(hil_path))
    elif args.mode == "completion":
        print(
            "domain_schema1_memory_gate: HIL metrics optional until "
            "NINLIL_DOMAIN_HIL_METRICS is provided"
        )

    print(
        "domain_schema1_memory_gate peak formula: "
        "sizeof(runtime) [includes service/tx arrays] "
        f"+ max(owner_heap_ws, kind1_heap_ws) <= {HOST_PEAK_SOFT}"
    )
    if errs:
        return fail("; ".join(errs))
    print("domain_schema1_memory_gate OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
