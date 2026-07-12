#!/usr/bin/env python3
"""Extract pinned D1 golden rows needed by D3-S2 production bridge tests.

The source is the independently generated, frozen domain-store-v1 artifact.
No production C codec/scanner is imported.  This avoids hand-maintained wire
bytes while preserving an explicit dependency pin.

Usage:
  python3 tools/domain_scan_d3s2_wire_fixture_gen.py check <domain-store.json>
  python3 tools/domain_scan_d3s2_wire_fixture_gen.py emit-c-fixture <json> <header>
  python3 tools/domain_scan_d3s2_wire_fixture_gen.py self-test <json>
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path
from typing import Any


D1_FORMAT = "ninlil-domain-store-v1-d1b3o"
D1_COUNT = 1549
D1_SHA256 = "b809c223f8208111fb4271cdceed031193e32e0f118e019d404ac538c89792b4"
SELECTED = (
    ("RETRY_RECENT_C1", "DSB3_RS_REC_C1_TYPED"),
    ("EVENT_SPOOL_PARKED_CYCLE", "DSB3_ES_PARKED_CYCLE_TYPED"),
    ("MANAGEMENT_RESUME", "DSB3_ML_R_RSN1_TYPED"),
)


def load_pinned(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != D1_SHA256:
        raise ValueError("domain-store-v1 full SHA256 drift")
    payload = json.loads(raw)
    if payload.get("format") != D1_FORMAT:
        raise ValueError("domain-store-v1 format drift")
    vectors = payload.get("vectors")
    if not isinstance(vectors, list) or len(vectors) != D1_COUNT:
        raise ValueError("domain-store-v1 vector count drift")
    return payload


def selected_rows(payload: dict[str, Any]) -> list[tuple[str, str, bytes, bytes]]:
    by_id = {v.get("id"): v for v in payload["vectors"]}
    rows: list[tuple[str, str, bytes, bytes]] = []
    for symbol, vector_id in SELECTED:
        vector = by_id.get(vector_id)
        if vector is None or vector.get("expected_status") != "OK":
            raise ValueError(f"missing positive D1 vector: {vector_id}")
        key = bytes.fromhex(vector.get("key_hex", ""))
        value = bytes.fromhex(vector.get("value_hex", ""))
        if not key or not value:
            raise ValueError(f"empty typed row: {vector_id}")
        rows.append((symbol, vector_id, key, value))
    return rows


def _array(name: str, data: bytes) -> list[str]:
    lines = [f"static const uint8_t {name}[] = {{"]
    for start in range(0, len(data), 12):
        chunk = data[start : start + 12]
        lines.append("    " + ", ".join(f"0x{value:02x}u" for value in chunk) + ",")
    lines.append("};")
    return lines


def emit(payload: dict[str, Any]) -> str:
    lines = [
        "/* GENERATED from pinned domain-store-v1.json; do not edit. */",
        "#ifndef NINLIL_DOMAIN_SCAN_D3S2_WIRE_FIXTURE_H",
        "#define NINLIL_DOMAIN_SCAN_D3S2_WIRE_FIXTURE_H",
        "#include <stddef.h>",
        "#include <stdint.h>",
    ]
    for symbol, vector_id, key, value in selected_rows(payload):
        prefix = f"NINLIL_D3S2_WIRE_{symbol}"
        lines.append(f"/* {vector_id} */")
        lines.extend(_array(prefix + "_KEY", key))
        lines.extend(_array(prefix + "_VALUE", value))
        lines.append(f"#define {prefix}_KEY_LEN ((size_t){len(key)}u)")
        lines.append(f"#define {prefix}_VALUE_LEN ((size_t){len(value)}u)")
    lines.extend(("#endif", ""))
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: check <json> | emit-c-fixture <json> <header> | self-test <json>", file=sys.stderr)
        return 2
    command = argv[1]
    source = Path(argv[2])
    try:
        payload = load_pinned(source)
        rendered = emit(payload)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if command == "check" and len(argv) == 3:
        print(f"ok pinned D3-S2 wire source ({len(SELECTED)} rows)")
        return 0
    if command == "emit-c-fixture" and len(argv) == 4:
        target = Path(argv[3])
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered, encoding="utf-8")
        print(f"wrote {target} ({len(SELECTED)} rows)")
        return 0
    if command == "self-test" and len(argv) == 3:
        assert rendered == emit(load_pinned(source))
        with tempfile.TemporaryDirectory() as td:
            a = Path(td) / "a.h"
            b = Path(td) / "b.h"
            a.write_text(rendered, encoding="utf-8")
            b.write_text(emit(payload), encoding="utf-8")
            assert a.read_bytes() == b.read_bytes()
        print("ok D3-S2 wire fixture self-test")
        return 0
    print("usage: check <json> | emit-c-fixture <json> <header> | self-test <json>", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
