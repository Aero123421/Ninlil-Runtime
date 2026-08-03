#!/usr/bin/env python3
"""Wi-Fi v1 physical AP HIL runner — software-executable evidence only.

Physical on-air AP association remains NOT_RUN until HW credentials + AP
evidence are collected. This runner always emits executable NOT_RUN JSON
for CI residual gates (mirrors mfdt_v1_hil_runner pattern).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, help="Output JSON path")
    args = ap.parse_args()
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "component": "wifi_v1",
        "adr": "0018",
        "status": "NOT_RUN",
        "physical_ap_hil": "NOT_RUN",
        "full_esp_hil_attested": False,
        "software_path": "private/default-OFF candidate",
        "reason": (
            "Physical AP association requires provisioned SSID/PSK and on-air "
            "evidence; authority app refuses synthetic GOT_IP/127.0.0.1 path."
        ),
        "runner_executable": True,
    }
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wifi_v1_hil_runner: wrote {out} status=NOT_RUN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
