#!/usr/bin/env python3
"""Regenerate fabric_v1_vector_fixture.h from accepted machine vectors.

Does not import production codecs. Run:
  python3 tools/fabric_v1_vector_fixture_gen.py
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "spec/vectors/fabric-bearer-spec-v1.json"
OUT = ROOT / "tests/transport/fabric_v1/fabric_v1_vector_fixture.h"


def c_array(name: str, hexstr: str) -> tuple[str, int]:
    b = bytes.fromhex(hexstr)
    lines = [f"static const uint8_t {name}[] = {{"]
    for i in range(0, len(b), 16):
        chunk = ", ".join(f"0x{x:02x}" for x in b[i : i + 16])
        lines.append(f"    {chunk},")
    lines.append("};")
    lines.append(f"static const uint32_t {name}_len = {len(b)}u;")
    return "\n".join(lines), len(b)


def render() -> str:
    d = json.loads(VECTOR.read_text())
    parts: list[str] = [
        "/* SPDX-License-Identifier: Apache-2.0 */",
        "/*",
        " * AUTO-GENERATED from spec/vectors/fabric-bearer-spec-v1.json",
        " * by tools/fabric_v1_vector_fixture_gen.py — do not hand-edit.",
        " */",
        "#ifndef NINLIL_FABRIC_V1_VECTOR_FIXTURE_H",
        "#define NINLIL_FABRIC_V1_VECTOR_FIXTURE_H",
        "#include <stdint.h>",
        "",
    ]
    pos_ids = []
    for i, v in enumerate(d["nfl1_positive_vectors"]):
        name = f"g_nfl1_pos_{i}"
        arr, _ = c_array(name, v["encoded_hex"])
        parts.append(arr)
        parts.append(f'static const char {name}_id[] = "{v["id"]}";')
        parts.append(f'static const char {name}_sha[] = "{v["sha256_hex"]}";')
        pos_ids.append((name, v["kind"], v["sha256_hex"]))

    neg_ids = []
    for i, v in enumerate(d["nfl1_negative_vectors"]):
        hx = v.get("encoded_hex")
        name = f"g_nfl1_neg_{i}"
        if not hx:
            continue
        ln = len(hx) // 2
        if ln > 2048:
            parts.append(f"/* {v['id']} length-only {ln} */")
            parts.append(f"static const uint32_t {name}_len = {ln}u;")
            neg_ids.append((name, v["id"], ln, v.get("expected", ""), True))
            continue
        arr, ln = c_array(name, hx)
        parts.append(arr)
        parts.append(f'static const char {name}_id[] = "{v["id"]}";')
        parts.append(
            f'static const char {name}_expected[] = "{v.get("expected", "")}";'
        )
        neg_ids.append((name, v["id"], ln, v.get("expected", ""), False))

    store_ids = []
    for i, v in enumerate(d["storage_records"]):
        name = f"g_store_{i}"
        karr, kln = c_array(name + "_key", v["key_hex"])
        varr, vln = c_array(name + "_val", v["value_hex"])
        parts.append(karr)
        parts.append(varr)
        parts.append(f'static const char {name}_id[] = "{v["id"]}";')
        store_ids.append((name, kln, vln))

    parts.append(f"#define FABRIC_V1_NFL1_POS_COUNT {len(pos_ids)}u")
    parts.append(f"#define FABRIC_V1_NFL1_NEG_COUNT {len(neg_ids)}u")
    parts.append(f"#define FABRIC_V1_STORAGE_COUNT {len(store_ids)}u")
    parts.append(
        f"#define FABRIC_V1_SELECTION_COUNT {len(d['selection_vectors'])}u"
    )
    parts.append(
        f"#define FABRIC_V1_FBA_STATE_COUNT "
        f"{len(d['fba_state_transition_vectors'])}u"
    )
    parts.append(
        f"#define FABRIC_V1_COMMIT_UNKNOWN_COUNT "
        f"{len(d['commit_unknown_matrix'])}u"
    )
    parts.append(
        f"#define FABRIC_V1_OUTER_BEARER_COUNT "
        f"{len(d['outer_bearer_vectors'])}u"
    )
    parts.append(
        f"#define FABRIC_V1_MIXED_VERSION_COUNT {len(d['mixed_version'])}u"
    )
    parts.append(
        f"#define FABRIC_V1_FBA_CU_COUNT "
        f"{len(d['fba_commit_unknown_vectors'])}u"
    )
    parts.append(
        f"#define FABRIC_V1_FRESH_ADOPTION_COUNT "
        f"{len(d['fresh_adoption_vectors'])}u"
    )
    parts.append(
        f"#define FABRIC_V1_STORAGE_NEG_COUNT "
        f"{len(d['storage_negative_vectors'])}u"
    )
    parts.append(
        "typedef struct fabric_v1_nfl1_pos_row {"
        " const char *id; const uint8_t *bytes; uint32_t len;"
        " uint32_t kind; const char *sha_hex; } fabric_v1_nfl1_pos_row_t;"
    )
    parts.append(
        "static const fabric_v1_nfl1_pos_row_t g_nfl1_pos_table[] = {"
    )
    for i, (name, kind, _sha) in enumerate(pos_ids):
        parts.append(
            f"  {{ {name}_id, {name}, {name}_len, {kind}u, {name}_sha }},"
        )
    parts.append("};")
    parts.append(
        "typedef struct fabric_v1_nfl1_neg_row {"
        " const char *id; const uint8_t *bytes; uint32_t len;"
        " const char *expected; int length_only; } fabric_v1_nfl1_neg_row_t;"
    )
    parts.append(
        "static const fabric_v1_nfl1_neg_row_t g_nfl1_neg_table[] = {"
    )
    for name, id_, ln, exp, lo in neg_ids:
        if lo:
            parts.append(
                f'  {{ "{id_}", 0, {ln}u, "{exp}", 1 }},'
            )
        else:
            parts.append(
                f"  {{ {name}_id, {name}, {name}_len, {name}_expected, 0 }},"
            )
    parts.append("};")
    parts.append(
        "typedef struct fabric_v1_store_row {"
        " const char *id; const uint8_t *key; uint32_t key_len;"
        " const uint8_t *val; uint32_t val_len; } fabric_v1_store_row_t;"
    )
    parts.append("static const fabric_v1_store_row_t g_store_table[] = {")
    for i, (name, kln, vln) in enumerate(store_ids):
        parts.append(
            f"  {{ {name}_id, {name}_key, {name}_key_len,"
            f" {name}_val, {name}_val_len }},"
        )
    parts.append("};")
    parts.append("#endif")
    return "\n".join(parts) + "\n"


def self_test() -> int:
    expected = render()
    if not OUT.exists() or OUT.read_text() != expected:
        print(f"self-test FAIL: {OUT} missing/stale")
        return 1
    orig = OUT.read_text()
    try:
        OUT.write_text(orig + "/*drift*/\n")
        if OUT.read_text() == expected:
            print("self-test FAIL: mutation not applied")
            return 1
    finally:
        OUT.write_text(orig)
    if OUT.read_text() != expected:
        print("self-test FAIL: not restored")
        return 1
    print(f"self-test OK {OUT}")
    return 0


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate fabric_v1_vector_fixture.h (nonmutating --check)"
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    expected = render()
    if args.write:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(expected)
        print(f"wrote {OUT} ({len(expected)} bytes)")
        return 0
    if not OUT.exists():
        print(f"missing {OUT}")
        return 1
    if OUT.read_text() != expected:
        print(f"stale {OUT}: deterministic drift vs generator")
        return 1
    print(f"check ok {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
