#!/usr/bin/env python3
"""Resync MFDT hardpins from the single vector generator authority.

Normative order:
  1) Finish ADR/work/CMake/C-source normative edits.
  2) Run this tool (aligns generator ADR pin to live ADR, regenerates vector,
     refreshes Python/Node source+map pins, C vector/map seals, acceptance
     artifact pins from live sealed digests).
  3) Fresh configure/build and run the ten CMake tests.

Does not weaken hardpins: every pin is recomputed from live file bytes or from
the generator-produced seal. Does not invent digests.
"""

from __future__ import annotations

import hashlib
import json
import pprint
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text: str, pattern: str, repl: str, label: str) -> str:
    new, n = re.subn(pattern, repl, text, count=1, flags=re.M | re.S)
    if n != 1:
        raise SystemExit(f"failed to update {label}: matches={n}")
    return new


def render_python_ids(ids: list[str]) -> str:
    lines = ["REQUIRED_VECTOR_IDS: tuple[str, ...] = ("]
    lines.extend(f"    {item!r}," for item in ids)
    lines.append(")")
    return "\n".join(lines)


def render_node_ids(ids: list[str]) -> str:
    rendered = json.dumps(ids, ensure_ascii=False, indent=2)
    return f"const REQUIRED_VECTOR_IDS = {rendered};"


def render_c_authority(doc: dict[str, object]) -> str:
    family_number = {
        "catalog": 0,
        "budget": 1,
        "positive": 2,
        "negative": 3,
        "commit_unknown": 4,
        "transcript": 5,
    }
    rows = [
        "static const mfdt_id_authority_t k_mfdt_authority[MFDT_ID_COUNT] = {"
    ]
    for vector in doc["vectors"]:  # type: ignore[index]
        assert isinstance(vector, dict)
        expected = vector["expected"]
        assert isinstance(expected, dict)
        family = vector["family"]
        if family not in family_number:
            raise SystemExit(f"unknown C authority family: {family!r}")
        status = expected.get("status")
        if not isinstance(status, str):
            raise SystemExit(f"missing expected.status: {vector.get('id')}")
        classification = expected.get("classification", "")
        if not isinstance(classification, str):
            classification = ""
        reject_code = expected.get("reject_code", expected.get("code", -1))
        if not isinstance(reject_code, int) or isinstance(reject_code, bool):
            reject_code = -1
        chunk_count = expected.get("chunk_count", -1)
        if not isinstance(chunk_count, int) or isinstance(chunk_count, bool):
            chunk_count = -1
        total_length = expected.get("total_length", -1)
        if not isinstance(total_length, int) or isinstance(total_length, bool):
            total_length = -1
        rows.append(
            '    {{ "{}", (enum mfdt_family){}, "{}", "{}", {}, {}, {} }},'.format(
                vector["id"],
                family_number[family],
                status,
                classification,
                reject_code,
                chunk_count,
                total_length,
            )
        )
    rows.append("};")
    return "\n".join(rows)


def render_c_family_counts(doc: dict[str, object]) -> str:
    family_names = (
        ("catalog", "CATALOG"),
        ("budget", "BUDGET"),
        ("positive", "POSITIVE"),
        ("negative", "NEGATIVE"),
        ("commit_unknown", "COMMIT_UNKNOWN"),
        ("transcript", "TRANSCRIPT"),
    )
    vectors = doc["vectors"]
    assert isinstance(vectors, list)
    counts = {name: 0 for name, _ in family_names}
    for vector in vectors:
        assert isinstance(vector, dict)
        family = vector.get("family")
        if family not in counts:
            raise SystemExit(f"unknown C authority family: {family!r}")
        counts[family] += 1
    lines = ["/* BEGIN GENERATED FAMILY COUNTS */", "enum {"]
    for index, (name, symbol) in enumerate(family_names):
        suffix = "," if index + 1 < len(family_names) else ""
        lines.append(f"    MFDT_{symbol}_ID_COUNT = {counts[name]}{suffix}")
    lines.extend(["};", "/* END GENERATED FAMILY COUNTS */"])
    return "\n".join(lines)


def render_c_bytes(symbol: str, value: bytes) -> str:
    lines = [f"static const uint8_t {symbol}[{len(value)}] = {{"]
    for offset in range(0, len(value), 12):
        chunk = value[offset : offset + 12]
        lines.append("    " + ", ".join(f"0x{octet:02x}" for octet in chunk) + ",")
    lines.append("};")
    return "\n".join(lines)


def main() -> int:
    adr_path = ROOT / "docs/adr/0021-multi-frame-durable-custody.md"
    gen_path = ROOT / "tools/multi_frame_durable_transfer_spec_vector_gen.py"
    if not adr_path.is_file() or not gen_path.is_file():
        raise SystemExit("missing ADR or generator")

    live_adr = sha256_file(adr_path)
    gen_text = gen_path.read_text(encoding="utf-8")
    m = re.search(r'PINNED_ADR_SHA256_HEX = \(\n    "([0-9a-f]{64})"\n\)', gen_text)
    if not m:
        raise SystemExit("generator PINNED_ADR_SHA256_HEX not found")
    if m.group(1) != live_adr:
        print(f"align generator ADR pin {m.group(1)} -> {live_adr}")
        gen_text = replace_once(
            gen_text,
            r'PINNED_ADR_SHA256_HEX = \(\n    "[0-9a-f]{64}"\n\)',
            f'PINNED_ADR_SHA256_HEX = (\n    "{live_adr}"\n)',
            "generator ADR pin",
        )
        gen_path.write_text(gen_text, encoding="utf-8")
    else:
        print("generator ADR pin already matches live ADR")

    r = subprocess.run(
        [sys.executable, str(gen_path), "--write"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    print(r.stdout.strip())

    live_gen = sha256_file(gen_path)
    vector_path = ROOT / "spec/vectors/multi-frame-durable-transfer-spec-v1.json"
    live_vector = sha256_file(vector_path)
    doc = json.loads(vector_path.read_text(encoding="utf-8"))
    required_ids = doc["required_vector_ids"]
    vectors = doc["vectors"]
    if (
        not isinstance(required_ids, list)
        or not all(isinstance(item, str) for item in required_ids)
        or not isinstance(vectors, list)
        or [row.get("id") for row in vectors if isinstance(row, dict)] != required_ids
        or len(required_ids) != len(set(required_ids))
        or set(doc["authority_index"]) != set(required_ids)
    ):
        raise SystemExit("generator vector inventory is not a closed exact authority")
    live_map = doc["authority_map_sha256_hex"]
    src = doc["source_sha256_hex"]
    if src["docs/adr/0021-multi-frame-durable-custody.md"] != live_adr:
        raise SystemExit("vector ADR source digest mismatch")
    if src["tools/multi_frame_durable_transfer_spec_vector_gen.py"] != live_gen:
        raise SystemExit("vector generator source digest mismatch")

    py_path = ROOT / "tools/multi_frame_durable_transfer_spec_gate.py"
    py = py_path.read_text(encoding="utf-8")
    py = replace_once(
        py,
        r"REQUIRED_VECTOR_IDS: tuple\[str, \.\.\.\] = \(.*?\n\)",
        render_python_ids(required_ids),
        "python required ids",
    )
    py_authority = pprint.pformat(
        doc["authority_index"], width=120, sort_dicts=False
    )
    py = replace_once(
        py,
        r"AUTHORITY: dict\[str, dict\[str, Any\]\] = .*?(?=\n\nCHUNK_SIZE)",
        f"AUTHORITY: dict[str, dict[str, Any]] = {py_authority}",
        "python literal authority",
    )
    py = replace_once(
        py,
        r'AUTHORITY_MAP_SHA256_HEX = "[0-9a-f]{64}"',
        f'AUTHORITY_MAP_SHA256_HEX = "{live_map}"',
        "python map sha",
    )
    py = replace_once(
        py,
        r"PINNED_SOURCE_SHA256_HEX: dict\[str, str\] = \{.*?\n\}",
        (
            "PINNED_SOURCE_SHA256_HEX: dict[str, str] = {\n"
            f'    PINNED_ADR_PATH: "{live_adr}",\n'
            '    "tools/multi_frame_durable_transfer_spec_vector_gen.py": (\n'
            f'        "{live_gen}"\n'
            "    ),\n"
            "}"
        ),
        "python source pins",
    )
    py_path.write_text(py, encoding="utf-8")

    node_path = ROOT / "tools/multi_frame_durable_transfer_spec_gate.mjs"
    node = node_path.read_text(encoding="utf-8")
    node = replace_once(
        node,
        r"const REQUIRED_VECTOR_IDS = \[.*?\n\];",
        render_node_ids(required_ids),
        "node required ids",
    )
    node_authority = json.dumps(
        doc["authority_index"], sort_keys=False, separators=(",", ":")
    )
    node = replace_once(
        node,
        r"const AUTHORITY = .*?(?=\n\nconst CHUNK_SIZE)",
        f"const AUTHORITY = {node_authority};",
        "node literal authority",
    )
    node = replace_once(
        node,
        r'const AUTHORITY_MAP_SHA256_HEX = "[0-9a-f]{64}"',
        f'const AUTHORITY_MAP_SHA256_HEX = "{live_map}"',
        "node map sha",
    )
    node = replace_once(
        node,
        r"const PINNED_SOURCE_SHA256_HEX = \{.*?\n\};",
        (
            "const PINNED_SOURCE_SHA256_HEX = {\n"
            f'  [PINNED_ADR_PATH]: "{live_adr}",\n'
            '  "tools/multi_frame_durable_transfer_spec_vector_gen.py":\n'
            f'    "{live_gen}",\n'
            "};"
        ),
        "node source pins",
    )
    node_path.write_text(node, encoding="utf-8")

    c_auth = ROOT / "tests/model/multi_frame_durable_transfer_c_authority.h"
    ct = c_auth.read_text(encoding="utf-8")
    ct = replace_once(
        ct,
        r"MFDT_ID_COUNT = \d+,",
        f"MFDT_ID_COUNT = {len(required_ids)},",
        "C id count",
    )
    ct = replace_once(
        ct,
        r"/\* BEGIN GENERATED FAMILY COUNTS \*/.*?/\* END GENERATED FAMILY COUNTS \*/",
        render_c_family_counts(doc),
        "C family counts",
    )
    ct = replace_once(
        ct,
        r"static const mfdt_id_authority_t k_mfdt_authority\[MFDT_ID_COUNT\] = \{.*?\n\};",
        render_c_authority(doc),
        "C id authority",
    )
    by_id = {
        row["id"]: row for row in vectors if isinstance(row, dict)
    }
    schema2_hex = by_id["MF-POS-NM30-SCHEMA2-LAYOUT-KAT"]["nm30_value_hex"]
    legacy_hex = by_id["MF-NEG-NM30-SCHEMA1-COLD-REPLAY-DENY"][
        "legacy_nm30_value_hex"
    ]
    nm30_kats = (
        "/* BEGIN GENERATED NM30 KATS */\n"
        + render_c_bytes("k_mfdt_nm30_schema2_kat", bytes.fromhex(schema2_hex))
        + "\n\n"
        + render_c_bytes("k_mfdt_nm30_schema1_legacy_kat", bytes.fromhex(legacy_hex))
        + "\n/* END GENERATED NM30 KATS */"
    )
    ct = replace_once(
        ct,
        r"/\* BEGIN GENERATED NM30 KATS \*/.*?/\* END GENERATED NM30 KATS \*/",
        nm30_kats,
        "C NM30 KAT bytes",
    )
    one_fixture = by_id["MF-POS-ONE-BYTE"]["fixture"]
    one_kats = (
        "/* BEGIN GENERATED ONE-BYTE KATS */\n"
        + render_c_bytes(
            "k_mfdt_one_open_body", bytes.fromhex(one_fixture["open_body_hex"])
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_open_accept", bytes.fromhex(one_fixture["open_accept_hex"])
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_page0", bytes.fromhex(one_fixture["pages"][0]["body_hex"])
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_chunk0", bytes.fromhex(one_fixture["chunks"][0]["body_hex"])
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_finalize", bytes.fromhex(one_fixture["finalize_hex"])
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_transfer_accept",
            bytes.fromhex(one_fixture["transfer_accept_hex"]),
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_entry0", bytes.fromhex(one_fixture["entries_hex"][0])
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_content", bytes.fromhex(one_fixture["content_hex"])
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_manifest_digest",
            bytes.fromhex(one_fixture["manifest_digest_hex"]),
        )
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_whole_digest",
            bytes.fromhex(one_fixture["content_sha256_hex"]),
        )
        + "\n\n"
        + render_c_bytes("k_mfdt_sha256_empty", hashlib.sha256(b"").digest())
        + "\n\n"
        + render_c_bytes(
            "k_mfdt_one_publication_token",
            bytes.fromhex(one_fixture["publication_token_hex"]),
        )
        + "\n/* END GENERATED ONE-BYTE KATS */"
    )
    ct = replace_once(
        ct,
        r"/\* BEGIN GENERATED ONE-BYTE KATS \*/.*?/\* END GENERATED ONE-BYTE KATS \*/",
        one_kats,
        "C one-byte KAT bytes",
    )
    ct = replace_once(
        ct,
        r'static const char k_mfdt_vector_sha256_hex\[\] =\n    "[0-9a-f]{64}";',
        f'static const char k_mfdt_vector_sha256_hex[] =\n    "{live_vector}";',
        "C vector sha",
    )
    ct = replace_once(
        ct,
        r'static const char k_mfdt_authority_map_sha256_hex\[\] =\n    "[0-9a-f]{64}";',
        f'static const char k_mfdt_authority_map_sha256_hex[] =\n    "{live_map}";',
        "C map sha",
    )
    c_auth.write_text(ct, encoding="utf-8")

    mfdt_cmake_rel = "cmake/ninlil_mfdt_ctest.cmake"
    mfdt_cmake_path = ROOT / mfdt_cmake_rel
    if not mfdt_cmake_path.is_file():
        raise SystemExit(f"missing dedicated MFDT cmake authority: {mfdt_cmake_rel}")

    # Import inventory extractor from acceptance gate without running it.
    sys.path.insert(0, str(ROOT / "tools"))
    from multi_frame_durable_transfer_acceptance_gate import (  # type: ignore
        extract_mfdt_cmake_inventory,
        inventory_canonical_json,
        sha256_text,
    )

    inv = extract_mfdt_cmake_inventory(mfdt_cmake_path.read_text(encoding="utf-8"))
    inv_sha = sha256_text(inventory_canonical_json(inv))

    final_pins = {
        "docs/adr/0021-multi-frame-durable-custody.md": live_adr,
        "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md": sha256_file(
            ROOT / "docs/work/2026-08-01-mfdt-spec-accepted-promotion.md"
        ),
        "docs/work/2026-08-01-mfdt-application-handoff-spec-repair.md": sha256_file(
            ROOT / "docs/work/2026-08-01-mfdt-application-handoff-spec-repair.md"
        ),
        "docs/work/2026-08-02-mfdt-deadline-sentinel-record-safety-erratum.md": sha256_file(
            ROOT
            / "docs/work/2026-08-02-mfdt-deadline-sentinel-record-safety-erratum.md"
        ),
        "docs/reviews/2026-08-01-mfdt-application-handoff-spec-accepted.md": sha256_file(
            ROOT / "docs/reviews/2026-08-01-mfdt-application-handoff-spec-accepted.md"
        ),
        "spec/vectors/multi-frame-durable-transfer-spec-v1.json": live_vector,
        "tools/multi_frame_durable_transfer_spec_vector_gen.py": live_gen,
        "tools/multi_frame_durable_transfer_spec_gate.py": sha256_file(py_path),
        "tools/multi_frame_durable_transfer_spec_gate.mjs": sha256_file(node_path),
        "tests/model/multi_frame_durable_transfer_c_gate_test.c": sha256_file(
            ROOT / "tests/model/multi_frame_durable_transfer_c_gate_test.c"
        ),
        "tests/model/multi_frame_durable_transfer_c_authority.h": sha256_file(c_auth),
        # Dedicated MFDT cmake authority only — never whole-repo CMakeLists.txt.
        mfdt_cmake_rel: sha256_file(mfdt_cmake_path),
    }
    block_lines = ["PINNED_ARTIFACT_SHA256: dict[str, str] = {"]
    for rel, digest in final_pins.items():
        block_lines.append(f'    "{rel}":')
        block_lines.append(f'        "{digest}",')
    block_lines.append("}")
    accept_path = ROOT / "tools/multi_frame_durable_transfer_acceptance_gate.py"
    at = accept_path.read_text(encoding="utf-8")
    at = replace_once(
        at,
        r"PINNED_ARTIFACT_SHA256: dict\[str, str\] = \{.*?\n\}",
        "\n".join(block_lines),
        "acceptance pins",
    )
    at = replace_once(
        at,
        r'PINNED_CMAKE_INVENTORY_SHA256 = \(\n    "[0-9a-f]{64}"\n\)',
        f'PINNED_CMAKE_INVENTORY_SHA256 = (\n    "{inv_sha}"\n)',
        "cmake inventory sha",
    )
    accept_path.write_text(at, encoding="utf-8")
    # Final consistency: generator --check and gate --check without rebuild.
    for cmd in (
        [sys.executable, str(gen_path), "--check"],
        [sys.executable, str(py_path), "--check"],
        ["node", str(node_path), "--check"],
        [sys.executable, str(accept_path), "--check"],
    ):
        subprocess.run(cmd, cwd=ROOT, check=True)

    print("authority resync OK")
    print(f"  adr={live_adr}")
    print(f"  generator={live_gen}")
    print(f"  vector={live_vector}")
    print(f"  map={live_map}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
