#!/usr/bin/env python3
"""Independent NCG1 control-frame golden / mutation oracle.

Does not import production C. Applies negative mutation recipes and checks
expected reject codes with an independent decoder matching docs/19.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct
import sys
import zlib

REPO = pathlib.Path(__file__).resolve().parents[1]
VECTOR_PATH = REPO / "spec" / "vectors" / "control-frame-v1.json"

MAGIC = b"NCG1"
VERSION = 1
TYPE_PING = 0x01
TYPE_PONG = 0x02
TYPE_DATA = 0x03
TYPE_RESET = 0x04
HEADER_PREFIX = 18
HEADER = 22
OVERHEAD = 26
MAX_PAYLOAD = 1024

FORMAT = "ninlil-control-frame-v1-m3"

# Mirror production private result codes.
RESULT_OK = 0
RESULT_NEED_MORE = 1
RESULT_BAD_MAGIC = 2
RESULT_BAD_VERSION = 3
RESULT_BAD_TYPE = 4
RESULT_BAD_FLAGS = 5
RESULT_BAD_LENGTH = 6
RESULT_BAD_HEADER_CRC = 7
RESULT_BAD_FRAME_CRC = 8
RESULT_TRUNCATED = 9

KNOWN_TYPES = {TYPE_PING, TYPE_PONG, TYPE_DATA, TYPE_RESET}


def crc32c(data: bytes) -> int:
    if hasattr(zlib, "crc32c"):
        return zlib.crc32c(data) & 0xFFFFFFFF
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x82F63B78
            else:
                crc >>= 1
    return (~crc) & 0xFFFFFFFF


def encode(
    type_: int,
    stream_or_cell_id: int,
    sequence: int,
    payload: bytes,
    flags: int = 0,
    version: int = VERSION,
) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("payload too large")
    prefix = bytearray()
    prefix += MAGIC
    prefix.append(version & 0xFF)
    prefix.append(type_ & 0xFF)
    prefix += struct.pack(">H", flags & 0xFFFF)
    prefix += struct.pack(">I", stream_or_cell_id & 0xFFFFFFFF)
    prefix += struct.pack(">I", sequence & 0xFFFFFFFF)
    prefix += struct.pack(">H", len(payload) & 0xFFFF)
    assert len(prefix) == HEADER_PREFIX
    header_crc = crc32c(bytes(prefix))
    header = bytes(prefix) + struct.pack(">I", header_crc)
    body = header + payload
    frame_crc = crc32c(body)
    return body + struct.pack(">I", frame_crc)


def decode_exact(raw: bytes) -> int:
    """Independent one-shot exact-frame decode result code (docs/19 / C codec)."""
    if len(raw) < HEADER:
        return RESULT_TRUNCATED
    if raw[:4] != MAGIC:
        return RESULT_BAD_MAGIC
    version = raw[4]
    type_ = raw[5]
    flags = struct.unpack(">H", raw[6:8])[0]
    plen = struct.unpack(">H", raw[16:18])[0]
    stored_hcrc = struct.unpack(">I", raw[18:22])[0]
    computed_hcrc = crc32c(raw[:HEADER_PREFIX])
    if version != VERSION:
        return RESULT_BAD_VERSION
    if type_ not in KNOWN_TYPES:
        return RESULT_BAD_TYPE
    if flags != 0:
        return RESULT_BAD_FLAGS
    if plen > MAX_PAYLOAD:
        return RESULT_BAD_LENGTH
    if stored_hcrc != computed_hcrc:
        return RESULT_BAD_HEADER_CRC
    frame_len = OVERHEAD + plen
    if len(raw) < frame_len:
        return RESULT_TRUNCATED
    if len(raw) != frame_len:
        return RESULT_BAD_LENGTH  # exact API: no trailing
    stored_fcrc = struct.unpack(">I", raw[HEADER + plen : HEADER + plen + 4])[0]
    computed_fcrc = crc32c(raw[: HEADER + plen])
    if stored_fcrc != computed_fcrc:
        return RESULT_BAD_FRAME_CRC
    return RESULT_OK


def apply_mutation(base: bytes, recipe: dict) -> bytes:
    buf = bytearray(base)
    op = recipe["op"]
    if op == "xor0":
        idx = int(recipe["byte_index"])
        buf[idx] ^= int(recipe["xor"]) & 0xFF
    elif op == "set":
        idx = int(recipe["byte_index"])
        buf[idx] = int(recipe["value"]) & 0xFF
    elif op == "set_u16_be":
        idx = int(recipe["byte_index"])
        val = int(recipe["value"]) & 0xFFFF
        buf[idx] = (val >> 8) & 0xFF
        buf[idx + 1] = val & 0xFF
        # If we change payload_length without fixing CRCs, header/frame CRC fail
        # depending on validation order. For BAD_LENGTH we must recompute header
        # CRC after setting an oversize length so length check wins after CRC ok.
        if recipe.get("recompute_header_crc"):
            hcrc = crc32c(bytes(buf[:HEADER_PREFIX]))
            buf[18:22] = struct.pack(">I", hcrc)
            # Keep trailing frame crc as garbage relative to new length claim;
            # decoder rejects BAD_LENGTH before needing full body if length>MAX.
    elif op == "recompute_header_crc_only":
        hcrc = crc32c(bytes(buf[:HEADER_PREFIX]))
        buf[18:22] = struct.pack(">I", hcrc)
    else:
        raise ValueError(f"unknown mutation op {op}")
    return bytes(buf)


def golden_vectors() -> list[dict]:
    vectors: list[dict] = []

    frame = encode(TYPE_DATA, 0x01020304, 1, b"")
    vectors.append(
        {
            "id": "empty_data",
            "type": TYPE_DATA,
            "stream_or_cell_id": 0x01020304,
            "sequence": 1,
            "payload_hex": "",
            "frame_hex": frame.hex(),
            "expected_result": RESULT_OK,
        }
    )

    payload = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    frame = encode(TYPE_PING, 0, 0, payload)
    vectors.append(
        {
            "id": "ping_4",
            "type": TYPE_PING,
            "stream_or_cell_id": 0,
            "sequence": 0,
            "payload_hex": payload.hex(),
            "frame_hex": frame.hex(),
            "expected_result": RESULT_OK,
        }
    )

    frame = encode(TYPE_PONG, 7, 99, b"ok")
    vectors.append(
        {
            "id": "pong_ok",
            "type": TYPE_PONG,
            "stream_or_cell_id": 7,
            "sequence": 99,
            "payload_hex": b"ok".hex(),
            "frame_hex": frame.hex(),
            "expected_result": RESULT_OK,
        }
    )

    frame = encode(TYPE_RESET, 0xFFFFFFFF, 0x80000001, b"\x00")
    vectors.append(
        {
            "id": "reset_max_id",
            "type": TYPE_RESET,
            "stream_or_cell_id": 0xFFFFFFFF,
            "sequence": 0x80000001,
            "payload_hex": "00",
            "frame_hex": frame.hex(),
            "expected_result": RESULT_OK,
        }
    )

    payload = bytes([0xA5]) * MAX_PAYLOAD
    frame = encode(TYPE_DATA, 42, 1000, payload)
    vectors.append(
        {
            "id": "max_payload",
            "type": TYPE_DATA,
            "stream_or_cell_id": 42,
            "sequence": 1000,
            "payload_hex": payload.hex(),
            "frame_hex": frame.hex(),
            "expected_result": RESULT_OK,
        }
    )

    vectors.append(
        {
            "id": "crc32c_123456789",
            "ascii": "123456789",
            "crc32c": f"{crc32c(b'123456789'):08x}",
        }
    )

    base = encode(TYPE_DATA, 1, 2, b"xy")
    vectors.append(
        {
            "id": "mut_base",
            "frame_hex": base.hex(),
            "expected_result": RESULT_OK,
        }
    )

    # Negative recipes: applied by checker/generator, not stored as pre-mutated hex.
    vectors.append(
        {
            "id": "mut_bad_magic",
            "base_id": "mut_base",
            "op": "xor0",
            "byte_index": 0,
            "xor": 1,
            "expected_result": RESULT_BAD_MAGIC,
        }
    )
    vectors.append(
        {
            "id": "mut_bad_version",
            "base_id": "mut_base",
            "op": "set",
            "byte_index": 4,
            "value": 2,
            "expected_result": RESULT_BAD_VERSION,
        }
    )
    vectors.append(
        {
            "id": "mut_bad_type",
            "base_id": "mut_base",
            "op": "set",
            "byte_index": 5,
            "value": 0xFF,
            "expected_result": RESULT_BAD_TYPE,
        }
    )
    vectors.append(
        {
            "id": "mut_bad_flags",
            "base_id": "mut_base",
            "op": "set",
            "byte_index": 7,
            "value": 1,
            "expected_result": RESULT_BAD_FLAGS,
        }
    )
    # Oversize payload_length with recomputed header CRC so BAD_LENGTH wins.
    vectors.append(
        {
            "id": "mut_bad_length",
            "base_id": "mut_base",
            "op": "set_u16_be",
            "byte_index": 16,
            "value": MAX_PAYLOAD + 1,
            "recompute_header_crc": True,
            "expected_result": RESULT_BAD_LENGTH,
        }
    )
    vectors.append(
        {
            "id": "mut_bad_header_crc",
            "base_id": "mut_base",
            "op": "xor0",
            "byte_index": 18,
            "xor": 1,
            "expected_result": RESULT_BAD_HEADER_CRC,
        }
    )
    vectors.append(
        {
            "id": "mut_bad_frame_crc",
            "base_id": "mut_base",
            "op": "xor0",
            "byte_index": len(base) - 1,
            "xor": 0xFF,
            "expected_result": RESULT_BAD_FRAME_CRC,
        }
    )

    return vectors


def build_document() -> dict:
    vectors = golden_vectors()
    return {
        "format": FORMAT,
        "vector_count": len(vectors),
        "notes": (
            "Independent NCG1 golden + applied negative mutation recipes. "
            "Mutations are applied by the checker; expected_result mirrors "
            "production private result codes. Does not claim M3 complete."
        ),
        "result_codes": {
            "OK": RESULT_OK,
            "NEED_MORE": RESULT_NEED_MORE,
            "BAD_MAGIC": RESULT_BAD_MAGIC,
            "BAD_VERSION": RESULT_BAD_VERSION,
            "BAD_TYPE": RESULT_BAD_TYPE,
            "BAD_FLAGS": RESULT_BAD_FLAGS,
            "BAD_LENGTH": RESULT_BAD_LENGTH,
            "BAD_HEADER_CRC": RESULT_BAD_HEADER_CRC,
            "BAD_FRAME_CRC": RESULT_BAD_FRAME_CRC,
            "TRUNCATED": RESULT_TRUNCATED,
        },
        "vectors": vectors,
    }


def write_vectors(path: pathlib.Path) -> None:
    doc = build_document()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {path} ({doc['vector_count']} vectors)")


def check_vectors(path: pathlib.Path) -> None:
    if not path.is_file():
        print(f"missing {path}", file=sys.stderr)
        raise SystemExit(1)
    on_disk = json.loads(path.read_text(encoding="utf-8"))
    expected = build_document()
    if on_disk != expected:
        print("control-frame vector drift", file=sys.stderr)
        print(f"  format on disk={on_disk.get('format')} expected={expected['format']}")
        print(
            f"  count on disk={on_disk.get('vector_count')} "
            f"expected={expected['vector_count']}"
        )
        od = {v["id"]: v for v in on_disk.get("vectors", [])}
        ex = {v["id"]: v for v in expected["vectors"]}
        for key in ex:
            if od.get(key) != ex[key]:
                print(f"  first drift id={key}", file=sys.stderr)
                break
        raise SystemExit(1)

    if crc32c(b"123456789") != 0xE3069283:
        print("CRC32C golden mismatch", file=sys.stderr)
        raise SystemExit(1)

    by_id = {v["id"]: v for v in expected["vectors"]}
    required_muts = {
        "mut_bad_magic": RESULT_BAD_MAGIC,
        "mut_bad_version": RESULT_BAD_VERSION,
        "mut_bad_type": RESULT_BAD_TYPE,
        "mut_bad_flags": RESULT_BAD_FLAGS,
        "mut_bad_length": RESULT_BAD_LENGTH,
        "mut_bad_header_crc": RESULT_BAD_HEADER_CRC,
        "mut_bad_frame_crc": RESULT_BAD_FRAME_CRC,
    }

    for v in expected["vectors"]:
        if v["id"] == "crc32c_123456789":
            continue
        if "op" in v:
            base = by_id[v["base_id"]]
            base_raw = bytes.fromhex(base["frame_hex"])
            mutated = apply_mutation(base_raw, v)
            got = decode_exact(mutated)
            want = int(v["expected_result"])
            if got != want:
                print(
                    f"mutation {v['id']}: got result {got} expected {want}",
                    file=sys.stderr,
                )
                raise SystemExit(1)
            if v["id"] in required_muts and want != required_muts[v["id"]]:
                print(f"mutation catalog mismatch {v['id']}", file=sys.stderr)
                raise SystemExit(1)
            continue

        if "frame_hex" not in v:
            continue
        raw = bytes.fromhex(v["frame_hex"])
        got = decode_exact(raw)
        want = int(v.get("expected_result", RESULT_OK))
        if got != want:
            print(
                f"golden {v['id']}: got result {got} expected {want}",
                file=sys.stderr,
            )
            raise SystemExit(1)
        if want == RESULT_OK:
            if raw[:4] != MAGIC:
                print(f"bad magic {v['id']}", file=sys.stderr)
                raise SystemExit(1)
            plen = struct.unpack(">H", raw[16:18])[0]
            if len(raw) != OVERHEAD + plen:
                print(f"length mismatch {v['id']}", file=sys.stderr)
                raise SystemExit(1)
            if crc32c(raw[:-4]) != struct.unpack(">I", raw[-4:])[0]:
                print(f"frame crc mismatch {v['id']}", file=sys.stderr)
                raise SystemExit(1)
            if crc32c(raw[:HEADER_PREFIX]) != struct.unpack(">I", raw[18:22])[0]:
                print(f"header crc mismatch {v['id']}", file=sys.stderr)
                raise SystemExit(1)

    for mid in required_muts:
        if mid not in by_id:
            print(f"missing required mutation {mid}", file=sys.stderr)
            raise SystemExit(1)

    print(
        f"control_frame_vector_gen check OK "
        f"({expected['vector_count']} vectors, "
        f"{len(required_muts)} mutations applied)"
    )


def materialize_cases(doc: dict) -> list[dict]:
    """Expand JSON vectors into concrete bytes + expected_result for C bridge.

    Golden frames keep their frame_hex. Mutation recipes are *applied* here so
    the C fixture contains post-mutation bytes, not recipes alone.
    """
    by_id = {v["id"]: v for v in doc["vectors"]}
    cases: list[dict] = []
    for v in doc["vectors"]:
        if v["id"] == "crc32c_123456789":
            continue
        if "op" in v:
            base = by_id[v["base_id"]]
            base_raw = bytes.fromhex(base["frame_hex"])
            raw = apply_mutation(base_raw, v)
            cases.append(
                {
                    "id": v["id"],
                    "kind": "mutation",
                    "bytes": raw,
                    "expected_result": int(v["expected_result"]),
                }
            )
            continue
        if "frame_hex" not in v:
            continue
        raw = bytes.fromhex(v["frame_hex"])
        cases.append(
            {
                "id": v["id"],
                "kind": "golden",
                "bytes": raw,
                "expected_result": int(v.get("expected_result", RESULT_OK)),
            }
        )
    return cases


def _c_byte_array(name: str, data: bytes) -> list[str]:
    lines = [f"static const uint8_t {name}[] = {{"]
    if not data:
        lines.append("    0u")
        lines.append("};")
        return lines
    row: list[str] = []
    for i, b in enumerate(data):
        row.append(f"0x{b:02x}u")
        if len(row) == 12 or i + 1 == len(data):
            lines.append("    " + ", ".join(row) + ("," if i + 1 < len(data) else ""))
            row = []
    lines.append("};")
    return lines


def emit_c_fixture(json_path: pathlib.Path, header_path: pathlib.Path) -> None:
    """Write deterministic C header consumed by production decoder bridge."""
    if not json_path.is_file():
        print(f"missing {json_path}", file=sys.stderr)
        raise SystemExit(1)
    doc = json.loads(json_path.read_text(encoding="utf-8"))
    # Freshness vs generator authority: on-disk JSON must match rebuild.
    expected = build_document()
    if doc != expected:
        print(
            "emit-c-fixture refused: JSON drifts from generator authority",
            file=sys.stderr,
        )
        raise SystemExit(1)

    cases = materialize_cases(doc)
    # Sanity: independent decode matches expected for every case.
    for c in cases:
        got = decode_exact(c["bytes"])
        if got != c["expected_result"]:
            print(
                f"emit-c-fixture: {c['id']} decode {got} != {c['expected_result']}",
                file=sys.stderr,
            )
            raise SystemExit(1)

    lines: list[str] = []
    lines.append(
        "/* GENERATED by tools/control_frame_vector_gen.py emit-c-fixture"
        " — do not edit. */"
    )
    lines.append("#ifndef NINLIL_CONTROL_FRAME_VECTOR_FIXTURE_H")
    lines.append("#define NINLIL_CONTROL_FRAME_VECTOR_FIXTURE_H")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("")
    lines.append(
        f"#define NINLIL_CFV_CASE_COUNT ((size_t){len(cases)}u)"
    )
    lines.append(
        f"#define NINLIL_CFV_MAX_FRAME_BYTES ((size_t){OVERHEAD + MAX_PAYLOAD}u)"
    )
    lines.append("")
    lines.append("typedef struct ninlil_cfv_case {")
    lines.append("    const char *id;")
    lines.append("    const char *kind;")
    lines.append("    const uint8_t *bytes;")
    lines.append("    size_t length;")
    lines.append("    uint32_t expected_result;")
    lines.append("} ninlil_cfv_case_t;")
    lines.append("")

    for i, c in enumerate(cases):
        lines.extend(_c_byte_array(f"ninlil_cfv_bytes_{i}", c["bytes"]))
        lines.append("")

    lines.append("static const ninlil_cfv_case_t ninlil_cfv_cases[NINLIL_CFV_CASE_COUNT] = {")
    for i, c in enumerate(cases):
        lines.append("    {")
        lines.append(f'        "{c["id"]}",')
        lines.append(f'        "{c["kind"]}",')
        lines.append(f"        ninlil_cfv_bytes_{i},")
        lines.append(f"        (size_t){len(c['bytes'])}u,")
        lines.append(f"        (uint32_t){c['expected_result']}u")
        lines.append("    },")
    lines.append("};")
    lines.append("")
    lines.append("#endif /* NINLIL_CONTROL_FRAME_VECTOR_FIXTURE_H */")
    lines.append("")

    text = "\n".join(lines)
    header_path.parent.mkdir(parents=True, exist_ok=True)
    header_path.write_text(text, encoding="utf-8")
    print(
        f"wrote {header_path} ({len(cases)} cases, {len(text)} bytes)",
        flush=True,
    )


def self_test() -> None:
    """Negative self-tests: recipe/expected/operator drift must fail closed."""
    import copy
    import tempfile

    doc = build_document()
    cases = materialize_cases(doc)
    assert len(cases) >= 10
    muts = [c for c in cases if c["kind"] == "mutation"]
    golds = [c for c in cases if c["kind"] == "golden"]
    assert len(muts) == 7
    assert any(c["id"] == "empty_data" for c in golds)

    # Deterministic emit twice.
    with tempfile.TemporaryDirectory() as td:
        td_path = pathlib.Path(td)
        json_path = td_path / "v.json"
        json_path.write_text(
            json.dumps(doc, indent=2, sort_keys=False) + "\n", encoding="utf-8"
        )
        a = td_path / "a.h"
        b = td_path / "b.h"
        emit_c_fixture(json_path, a)
        emit_c_fixture(json_path, b)
        if a.read_bytes() != b.read_bytes():
            print("self-test: emit-c-fixture non-deterministic", file=sys.stderr)
            raise SystemExit(1)

    # Wrong expected_result on a mutation must not match independent decode.
    bad_doc = copy.deepcopy(doc)
    for v in bad_doc["vectors"]:
        if v["id"] == "mut_bad_version":
            v["expected_result"] = RESULT_OK  # wrong on purpose
            break
    else:
        raise SystemExit("self-test: mut_bad_version missing")
    by_id = {v["id"]: v for v in bad_doc["vectors"]}
    recipe = by_id["mut_bad_version"]
    base_raw = bytes.fromhex(by_id[recipe["base_id"]]["frame_hex"])
    mutated = apply_mutation(base_raw, recipe)
    got = decode_exact(mutated)
    if got == RESULT_OK:
        print("self-test: wrong expected not detected", file=sys.stderr)
        raise SystemExit(1)
    if got == recipe["expected_result"]:
        print("self-test: forged expected matched decode", file=sys.stderr)
        raise SystemExit(1)

    # Wrong mutation operator yields different reject than catalog expects.
    recipe2 = dict(recipe)
    recipe2["op"] = "xor0"
    recipe2["byte_index"] = 0
    recipe2["xor"] = 1
    # Remove set-only keys that confuse apply
    recipe2.pop("value", None)
    wrong = apply_mutation(base_raw, recipe2)
    got2 = decode_exact(wrong)
    if got2 == RESULT_BAD_VERSION:
        print("self-test: operator swap still BAD_VERSION", file=sys.stderr)
        raise SystemExit(1)
    if got2 != RESULT_BAD_MAGIC:
        print(f"self-test: expected BAD_MAGIC got {got2}", file=sys.stderr)
        raise SystemExit(1)

    # materialize uses applied bytes: mutating catalog expected must make
    # emit-c-fixture refuse when independent decode disagrees.
    with tempfile.TemporaryDirectory() as td:
        td_path = pathlib.Path(td)
        # Force authority match by writing bad_doc as if it were generator output
        # — emit checks build_document() equality, so patch generator path:
        # Call materialize + decode mismatch path directly.
        mat = materialize_cases(bad_doc)
        failed = False
        for c in mat:
            if c["id"] != "mut_bad_version":
                continue
            if decode_exact(c["bytes"]) != c["expected_result"]:
                failed = True
        if not failed:
            print("self-test: materialize did not surface expected drift", file=sys.stderr)
            raise SystemExit(1)

    print("control_frame_vector_gen self-test OK")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command",
        choices=("generate", "check", "emit-c-fixture", "self-test"),
    )
    parser.add_argument("path", nargs="?", default=str(VECTOR_PATH))
    parser.add_argument(
        "header",
        nargs="?",
        default=None,
        help="output header path for emit-c-fixture",
    )
    args = parser.parse_args()
    if args.command == "generate":
        write_vectors(pathlib.Path(args.path))
    elif args.command == "check":
        check_vectors(pathlib.Path(args.path))
    elif args.command == "emit-c-fixture":
        if args.header is None:
            print(
                "usage: emit-c-fixture <json> <header>",
                file=sys.stderr,
            )
            raise SystemExit(2)
        emit_c_fixture(pathlib.Path(args.path), pathlib.Path(args.header))
    else:
        self_test()


if __name__ == "__main__":
    main()
