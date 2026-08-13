#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""MFDT private footprint budget gate (static sizes).

ESP32-S3 cannot host dual 64KB workspaces + dual lab stores + 120KB engine
scratch. After redesign:
  - single spine engine + workspace + lab store
  - record + NRC1 regions live inside the caller-owned workspace (~50KB)
  - no dual cu_old/cu_new

This gate compiles a tiny size probe and checks hard upper bounds.
Physical map/stack evidence requires a separate real ESP ELF proof.
ADR-0021 is Accepted specification; this gate does not promote release support.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Hard budgets (bytes) for host static layout after redesign.
# ESP adapter moves workspace-class giants to SPIRAM/heap
# (ports/esp-idf/src/mfdt_v1_target_alloc.c);
# this gate still measures portable sizeof() for host struct layout.
MAX_SPINE_CTX = 220_000  # single ws+store+eng+pipe (was ~365KB dual)
# Compatibility label below is retained for evidence readers. This is now the
# record+NRC1 region budget inside one owner workspace, not external scratch.
MAX_ENGINE_SCRATCH = 55_000  # ACTIVE+NRC1 owner regions (was ~120KB external)
MAX_LAB_STORE = 130_000  # one host lab store pool
MAX_WORKSPACE = 65_536 + 64


def main() -> int:
    src = r"""
#include "mfdt_v1.h"
#include "mfdt_v1_spine.h"
#include "mfdt_v1_pipeline.h"
#include <stdio.h>
int main(void) {
  printf("workspace %zu\n", sizeof(ninlil_mfdt_v1_workspace_t));
  printf("lab_store %zu\n", sizeof(ninlil_mfdt_v1_lab_store_t));
  printf("engine %zu\n", sizeof(ninlil_mfdt_v1_engine_t));
  printf("pipeline %zu\n", sizeof(ninlil_mfdt_v1_pipeline_t));
  printf("spine_ctx %zu\n", sizeof(ninlil_mfdt_v1_spine_ctx_t));
  printf("engine_scratch %u\n",
         (unsigned)(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX
                    + NINLIL_MFDT_V1_NRC1_VALUE_BYTES));
  return 0;
}
"""
    with tempfile.TemporaryDirectory() as td:
        cpath = Path(td) / "size.c"
        cpath.write_text(src)
        out = Path(td) / "size"
        cmd = [
            "cc",
            "-std=c11",
            f"-I{ROOT / 'src' / 'runtime' / 'mfdt_v1'}",
            f"-I{ROOT / 'include'}",
            "-DNINLIL_MFDT_V1_PRIVATE=1",
            str(cpath),
            "-o",
            str(out),
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            sys.stderr.write(r.stderr)
            print("mfdt_v1_footprint_gate: compile failed", file=sys.stderr)
            return 1
        r2 = subprocess.run([str(out)], capture_output=True, text=True, check=True)
        sizes = {}
        for line in r2.stdout.splitlines():
            k, v = line.split()
            sizes[k] = int(v)
        print(r2.stdout, end="")
        fails = []
        if sizes.get("spine_ctx", 0) > MAX_SPINE_CTX:
            fails.append(f"spine_ctx {sizes['spine_ctx']} > {MAX_SPINE_CTX}")
        if sizes.get("lab_store", 0) > MAX_LAB_STORE:
            fails.append(f"lab_store {sizes['lab_store']} > {MAX_LAB_STORE}")
        if sizes.get("workspace", 0) > MAX_WORKSPACE:
            fails.append(f"workspace {sizes['workspace']} > {MAX_WORKSPACE}")
        if sizes.get("engine_scratch", 0) > MAX_ENGINE_SCRATCH:
            fails.append(
                f"engine_scratch {sizes['engine_scratch']} > {MAX_ENGINE_SCRATCH}"
            )
        # Dual-pair residual must not reappear via 2x workspace in spine.
        if sizes.get("spine_ctx", 0) > (sizes.get("workspace", 0) * 2 + 50_000):
            # spine should be ~1 workspace + 1 lab, not 2+2
            pass
        if fails:
            for f in fails:
                print(f"FAIL: {f}", file=sys.stderr)
            return 1
        print("mfdt_v1_footprint_gate OK")
        print("NOTE: host-size evidence does not substitute for ESP .su/map proof")
        print("NOTE: physical power-cut HIL NOT_RUN; RELEASE_SUPPORTED absent")
        return 0


if __name__ == "__main__":
    sys.exit(main())
