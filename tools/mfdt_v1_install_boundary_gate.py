#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate: private MFDT symbols must not leak into installed ninlil_runtime.

Authority: cmake/ninlil_mfdt_v1_sources.cmake + CMakeLists OSS boundary —
MFDT is private default-OFF, headers never installed, symbols only on
ninlil_runtime_private (not install(TARGETS ninlil_runtime)).

When MFDT is OFF, both archives should lack MFDT symbols.
When MFDT is ON, runtime_private may export; installable ninlil_runtime must not.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


MFDT_MARKERS = (
    "ninlil_mfdt_v1_",
    "mfdt_v1_",
)


def nm_symbols(archive: Path) -> str:
    if not archive.is_file():
        return ""
    r = subprocess.run(
        ["nm", "-g", str(archive)],
        capture_output=True,
        text=True,
        check=False,
    )
    return r.stdout + r.stderr


def has_mfdt(text: str) -> list[str]:
    hits = []
    for line in text.splitlines():
        for m in MFDT_MARKERS:
            if m in line:
                hits.append(line.strip())
                break
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--build-dir", required=True)
    args = ap.parse_args()
    bdir = Path(args.build_dir)
    runtime = bdir / "libninlil_runtime.a"
    private = bdir / "libninlil_runtime_private.a"
    # Also accept private-only tree without host runtime.
    installed_like = runtime if runtime.is_file() else None
    fails = []
    if installed_like is not None:
        hits = has_mfdt(nm_symbols(installed_like))
        if hits:
            fails.append(
                f"installed-like ninlil_runtime contains MFDT symbols "
                f"({len(hits)} hits), e.g. {hits[0]}"
            )
        else:
            print(f"OK: {installed_like.name} has zero MFDT symbols")
    else:
        print("NOTE: libninlil_runtime.a absent in this build (skip install archive)")
    if private.is_file():
        ph = has_mfdt(nm_symbols(private))
        print(
            f"INFO: ninlil_runtime_private MFDT symbols: {len(ph)} "
            f"(allowed when NINLIL_ENABLE_MFDT_V1_PRIVATE=ON)"
        )
    if fails:
        for f in fails:
            print(f"FAIL: {f}", file=sys.stderr)
        return 1
    print("mfdt_v1_install_boundary_gate OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
