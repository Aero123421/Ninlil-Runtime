#!/usr/bin/env python3
"""Executable MFDT power-cut HIL runner — honest NOT_RUN without hardware.

Does not fabricate flash/HIL success. When no device/port is available, writes
a machine-readable evidence record with status=NOT_RUN and exits 0 so CI can
archive the residual without false-green FULL_ESP_HIL_ATTESTED claims.

Usage:
  python3 tools/ninlil_hil/mfdt_v1_hil_runner.py [--port PATH] [--out PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="MFDT V1 HIL runner (NOT_RUN without HW)")
    ap.add_argument("--port", default="", help="Serial port for ESP HIL fixture")
    ap.add_argument(
        "--out",
        default="docs/work/evidence/mfdt_v1_hil_not_run.json",
        help="Evidence JSON path",
    )
    ap.add_argument(
        "--require-hardware",
        action="store_true",
        help="Exit non-zero if hardware is absent (strict operator mode)",
    )
    args = ap.parse_args()

    port = (args.port or "").strip()
    has_hw = False
    reason = "no_serial_port_configured"
    if port:
        p = Path(port)
        if p.exists():
            has_hw = True
            reason = "port_present_but_physical_powercut_fixture_not_executed"
        else:
            reason = f"port_missing:{port}"

    evidence = {
        "schema": "mfdt_v1_hil_evidence_v1",
        "feature": "ADR-0021 multi-frame durable transfer",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "status": "NOT_RUN" if not has_hw else "INCOMPLETE",
        "full_esp_hil_attested": False,
        "physical_powercut_executed": False,
        "port": port or None,
        "reason": reason,
        "required_boundaries": [
            "G_R_OPEN",
            "G_R_PAGE",
            "G_R_CHUNK",
            "G_R_TERMINAL",
            "G_R_RETENTION_GC",
            "COMMIT_UNKNOWN_OLD_NEW",
        ],
        "nonclaims": [
            "Does not claim HIL success",
            "Does not claim format-4 power-cut proof",
            "Does not promote SPEC_ACCEPTED or RELEASE_SUPPORTED",
        ],
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": evidence["status"], "out": str(out_path), "reason": reason}))

    if args.require_hardware and not has_hw:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
