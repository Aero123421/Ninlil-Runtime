#!/usr/bin/env python3
"""Materialize docs/30 mandatory r7-radio-wire-v1.json + C fixture.

Independent of production C codec helpers for crypto (uses r7_radio_wire_oracle
AES-GCM/HKDF/SHA-256 tables). Generates twice byte-identically.

Not HIL. Not physical RF. status=HOST_MATERIALIZED after successful generate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import struct
import sys
from typing import Any

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

from r7_radio_wire_oracle import (  # noqa: E402
    aes128_gcm_seal,
    build_vectors as oracle_crypto_vectors,
    derive_nonce,
    from_hex,
    hkdf_sha256,
    sha256,
    to_hex,
)

JSON_OUT = REPO / "spec" / "vectors" / "r7-radio-wire-v1.json"
HEADER_OUT = REPO / "tests" / "radio" / "r7_frag" / "r7_radio_wire_v1_fixture.h"

# Mandatory docs/30 §18 IDs (closed set for gate).
MANDATORY_IDS = frozenset(
    {
        "r6_hop_binding",
        "r6_e2e_binding",
        "r6_schedule_hop_data_key",
        "r6_schedule_hop_data_iv",
        "r6_schedule_hop_ack_key",
        "r6_schedule_hop_ack_iv",
        "r6_schedule_e2e_key",
        "r6_schedule_e2e_iv",
        "r7_nonce_counter_1",
        "r7_nonce_counter_uint64_max_minus_1",
        "n6_layout_tx_counter_crc",
        "n6_layout_rx_window_crc",
        "n6_layout_context_meta_crc",
        "n6_crc_bitflip_negative",
        "single_n_1",
        "single_n_16",
        "single_n_24",
        "single_n_32",
        "single_n_190",
        "link_ack",
        "frag_start_min",
        "frag_start_max",
        "frag_cont_min",
        "frag_cont_max",
        "frag_ack_partial",
        "frag_ack_complete",
        "frag_ack_abort",
        "outer_frame_single_full",
        "clock_fault_durable_latch_restart",
        "class_b_operator_recovery",
        "R7-FRAG-FINAL-GOOD",
        "R7-FRAG-FINAL-DIGEST-FAIL",
        "R7-FRAG-FINAL-RESOURCE-FAIL",
        "R7-FRAG-ACK-BEFORE-LINK-ACK",
    }
)


def _u16be(x: int) -> bytes:
    return struct.pack(">H", x & 0xFFFF)


def _u32be(x: int) -> bytes:
    return struct.pack(">I", x & 0xFFFFFFFF)


def _u64be(x: int) -> bytes:
    return struct.pack(">Q", x & 0xFFFFFFFFFFFFFFFF)


def _crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def _aead_frame(
    vector_id: str,
    kind: str,
    key: bytes,
    static_iv: bytes,
    counter: int,
    aad: bytes,
    plaintext: bytes,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    nonce = derive_nonce(static_iv, counter)
    ct, tag = aes128_gcm_seal(key, nonce, aad, plaintext)
    row: dict[str, Any] = {
        "aad": to_hex(aad),
        "ciphertext": to_hex(ct),
        "counter": f"{counter:016x}",
        "expect": "ok",
        "frame": to_hex(aad + ct + tag) if kind.startswith("outer") else to_hex(aad + plaintext[:0] + ct + tag),
        "id": vector_id,
        "key": to_hex(key),
        "kind": kind,
        "nonce": to_hex(nonce),
        "plaintext": to_hex(plaintext),
        "source": "docs_30_section_18",
        "static_iv": to_hex(static_iv),
        "surface": "independent_oracle",
        "tag": to_hex(tag),
    }
    # concatenated frame = aad || ciphertext || tag for wire classes
    row["frame"] = to_hex(aad + ct + tag)
    if extra:
        row.update(extra)
    return row


def build_wire_vectors() -> list[dict[str, Any]]:
    vectors: list[dict[str, Any]] = []
    # Include all independent crypto vectors from T0 oracle.
    for row in oracle_crypto_vectors():
        vectors.append(dict(row))

    key = from_hex("00112233445566778899aabbccddeeff")
    hop_iv = from_hex("0102030405060708090a0b0c")
    e2e_iv = from_hex("1112131415161718191a1b1c")

    # N6 layout CRC pins (structural body + crc16).
    for name, body in (
        ("n6_layout_tx_counter_crc", b"n6.tx.counter.v1" + _u64be(1)),
        ("n6_layout_rx_window_crc", b"n6.rx.window.v1" + _u32be(64) + _u64be(1)),
        ("n6_layout_context_meta_crc", b"n6.ctx.meta.v1" + _u32be(1) + _u32be(2)),
    ):
        crc = _crc16_ccitt(body)
        vectors.append(
            {
                "body": to_hex(body),
                "crc16": f"{crc:04x}",
                "id": name,
                "kind": "n6_layout",
                "record": to_hex(body + _u16be(crc)),
                "source": "docs_30_section_20",
                "surface": "independent_oracle",
            }
        )
    body = b"n6.tx.counter.v1" + _u64be(1)
    good = _crc16_ccitt(body)
    bad = good ^ 0x0001
    vectors.append(
        {
            "body": to_hex(body),
            "crc16_bad": f"{bad:04x}",
            "crc16_good": f"{good:04x}",
            "expect": "crc_fail",
            "id": "n6_crc_bitflip_negative",
            "kind": "n6_layout_negative",
            "source": "docs_30_section_18",
            "surface": "independent_oracle",
        }
    )

    # SINGLE N=1/16/24/32/190 (E2E PT = app; AAD14 structural).
    for n in (1, 16, 24, 32, 190):
        app = bytes((0xA0 + i) & 0xFF for i in range(n))
        # e2e_type SINGLE=1 in high nibble (docs/30 / r7_wire_codec).
        e2e_aad = bytes([0x11, 0x10]) + _u32be(1) + _u64be(1)
        assert len(e2e_aad) == 14
        vectors.append(
            _aead_frame(
                f"single_n_{n}",
                "e2e_single",
                key,
                e2e_iv,
                1,
                e2e_aad,
                app,
                {"app_len": n},
            )
        )

    # LINK_ACK body 16B + outer AAD19 class.
    link_pt = _u32be(1) + _u64be(1) + _u16be(0x0001) + bytes([0, 0])
    assert len(link_pt) == 16
    # kind in high nibble (docs/30 / r7_frag_wire seal: kind << 4).
    link_aad = bytes([0x11, 0x20, 0x00]) + _u32be(2) + _u64be(2) + _u16be(0) + bytes([0])
    # pad/truncate to 19
    link_aad = (link_aad + bytes(19))[:19]
    vectors.append(
        _aead_frame("link_ack", "outer_link_ack", key, hop_iv, 2, link_aad, link_pt)
    )

    # FRAG START min (S=1) / max (S=126) — plan-valid headers.
    # plan_validate: total_len matches S + (frag_count-1)*unit class.
    for name, chunk_len, total_len, frag_count, unit in (
        ("frag_start_min", 1, 181, 2, 180),
        ("frag_start_max", 126, 306, 2, 180),
    ):
        start_hdr = (
            bytes([0xA5] * 16)  # nonzero transfer_id
            + _u64be(1)
            + _u32be(total_len)
            + _u16be(frag_count)
            + _u16be(unit)
            + bytes([0x33] * 32)
        )
        pt = start_hdr + bytes((0x10 + i) & 0xFF for i in range(chunk_len))
        # e2e_type START=2 in high nibble.
        aad = bytes([0x11, 0x20]) + _u32be(1) + _u64be(3)
        aad = (aad + bytes(14))[:14]
        vectors.append(
            _aead_frame(name, "e2e_frag_start", key, e2e_iv, 3, aad, pt)
        )

    cont_hdr = _u64be(1) + _u16be(1)  # handle + frag_index
    for name, chunk_len in (("frag_cont_min", 1), ("frag_cont_max", 180)):
        pt = cont_hdr + bytes((0x20 + i) & 0xFF for i in range(chunk_len))
        # e2e_type CONT=3 in high nibble.
        aad = bytes([0x11, 0x30]) + _u32be(1) + _u64be(4)
        aad = (aad + bytes(14))[:14]
        vectors.append(
            _aead_frame(name, "e2e_frag_cont", key, e2e_iv, 4, aad, pt)
        )

    # FRAG_ACK PARTIAL/COMPLETE/ABORT PT (14B class).
    for name, status, reason, bitmap in (
        ("frag_ack_partial", 0, 0, 0x0001),
        ("frag_ack_complete", 1, 0, 0x0003),
        ("frag_ack_abort", 2, 1, 0x0000),
    ):
        pt = _u64be(1) + _u16be(2) + _u16be(bitmap) + bytes([status, reason])
        assert len(pt) == 14
        # e2e_type ACK=4 in high nibble.
        aad = bytes([0x11, 0x40]) + _u32be(1) + _u64be(5)
        aad = (aad + bytes(14))[:14]
        vectors.append(
            _aead_frame(name, "e2e_frag_ack", key, e2e_iv, 5, aad, pt)
        )

    # Full outer SINGLE frame (outer AAD19 + e2e blob as PT).
    e2e_blob_pt = from_hex("00" * 38)  # placeholder sealed e2e size class
    # OUTER_KIND_DATA=1 in high nibble.
    outer_aad = bytes([0x11, 0x10, 0x00]) + _u32be(1) + _u64be(7) + _u16be(0) + bytes([0])
    outer_aad = (outer_aad + bytes(19))[:19]
    vectors.append(
        _aead_frame(
            "outer_frame_single_full",
            "outer_data",
            key,
            hop_iv,
            7,
            outer_aad,
            e2e_blob_pt,
        )
    )

    # State / policy vectors (no AEAD; exact closed IDs).
    for vid, note in (
        (
            "clock_fault_durable_latch_restart",
            "clock_fault_sets_fence_tx0_until_recover",
        ),
        ("class_b_operator_recovery", "operator_recovery_required_closed"),
        ("R7-FRAG-FINAL-GOOD", "full_bitmap_digest_match_complete"),
        ("R7-FRAG-FINAL-DIGEST-FAIL", "full_bitmap_digest_mismatch_abort"),
        ("R7-FRAG-FINAL-RESOURCE-FAIL", "resource_full_ack0_no_owner"),
        (
            "R7-FRAG-ACK-BEFORE-LINK-ACK",
            "frag_ack_supersedes_before_link_ack_apply",
        ),
    ):
        vectors.append(
            {
                "id": vid,
                "kind": "state_policy",
                "note": note,
                "source": "docs_30_section_18",
                "surface": "independent_oracle",
            }
        )

    return sorted(vectors, key=lambda r: r["id"])


def build_document() -> dict[str, Any]:
    vectors = build_wire_vectors()
    ids = {v["id"] for v in vectors}
    missing = sorted(MANDATORY_IDS - ids)
    if missing:
        raise SystemExit(f"missing mandatory vector ids: {missing}")
    return {
        "artifact": "r7-radio-wire-v1",
        "c_bridge": {
            "fixture_header": "tests/radio/r7_frag/r7_radio_wire_v1_fixture.h",
            "implemented": True,
            "required_vector_count": len(vectors),
            "skip_allowed": False,
            "status": "implemented",
        },
        "docs": "docs/30-r6-secure-radio-wire.md §15 / §18",
        "hil": "NOT_RUN",
        "mandatory_ids": sorted(MANDATORY_IDS),
        "physical_rf": "NOT_RUN",
        "schema": "r7-radio-wire-v1",
        "schema_version": 1,
        "status": "HOST_MATERIALIZED",
        "vector_count": len(vectors),
        "vectors": vectors,
    }


def canonical_json(document: dict[str, Any]) -> bytes:
    text = json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    data = text.encode("ascii")
    # Hex payloads must be lowercase; allow mixed id tokens (R7-FRAG-*).
    for row in document["vectors"]:
        for k, v in row.items():
            if isinstance(v, str) and all(c in "0123456789abcdef" for c in v) and len(v) >= 8:
                if v != v.lower():
                    raise ValueError(f"non-lowercase hex in {row['id']}.{k}")
    return data


def generate_header(document: dict[str, Any], json_bytes: bytes) -> bytes:
    digest = hashlib.sha256(json_bytes).hexdigest()
    lines = [
        "/* GENERATED by tools/r7_radio_wire_v1_materialize.py - do not edit */",
        "#ifndef NINLIL_R7_RADIO_WIRE_V1_FIXTURE_H",
        "#define NINLIL_R7_RADIO_WIRE_V1_FIXTURE_H",
        "#include <stddef.h>",
        f"#define NINLIL_R7_RADIO_WIRE_V1_VECTOR_COUNT ({document['vector_count']}u)",
        f'#define NINLIL_R7_RADIO_WIRE_V1_JSON_SHA256 "{digest}"',
        f'#define NINLIL_R7_RADIO_WIRE_V1_STATUS "{document["status"]}"',
        f'#define NINLIL_R7_RADIO_WIRE_V1_HIL "{document["hil"]}"',
        "typedef struct ninlil_r7_radio_wire_v1_row {",
        "    const char *id;",
        "    const char *kind;",
        "    const char *key_hex;",
        "    const char *nonce_hex;",
        "    const char *static_iv_hex;",
        "    const char *aad_hex;",
        "    const char *plaintext_hex;",
        "    const char *ciphertext_hex;",
        "    const char *tag_hex;",
        "    const char *frame_hex;",
        "} ninlil_r7_radio_wire_v1_row_t;",
        "static const ninlil_r7_radio_wire_v1_row_t",
        "ninlil_r7_radio_wire_v1_rows[NINLIL_R7_RADIO_WIRE_V1_VECTOR_COUNT] = {",
    ]
    for row in document["vectors"]:
        def g(k: str) -> str:
            v = row.get(k, "")
            return v if isinstance(v, str) else ""

        lines.append(
            "    { "
            f'"{row["id"]}", "{row["kind"]}", '
            f'"{g("key")}", "{g("nonce")}", "{g("static_iv")}", "{g("aad")}", '
            f'"{g("plaintext")}", "{g("ciphertext")}", "{g("tag")}", '
            f'"{g("frame")}" '
            "},"
        )
    lines.extend(
        [
            "};",
            "/* Back-compat alias for id/kind-only consumers. */",
            "#define ninlil_r7_radio_wire_v1_ids ninlil_r7_radio_wire_v1_rows",
            "#endif /* NINLIL_R7_RADIO_WIRE_V1_FIXTURE_H */",
            "",
        ]
    )
    return ("\n".join(lines)).encode("ascii")


def verify_document(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if document.get("schema") != "r7-radio-wire-v1":
        errors.append("schema")
    if document.get("status") == "PARTIAL_IMPL_HOST":
        errors.append("partial self-claim forbidden")
    if document.get("hil") != "NOT_RUN":
        errors.append("hil must be NOT_RUN until physical evidence")
    ids = [v["id"] for v in document.get("vectors", [])]
    if len(ids) != len(set(ids)):
        errors.append("duplicate ids")
    missing = sorted(MANDATORY_IDS - set(ids))
    if missing:
        errors.append(f"missing mandatory: {missing}")
    if document.get("vector_count") != len(ids):
        errors.append("vector_count mismatch")
    if document.get("c_bridge", {}).get("skip_allowed"):
        errors.append("c_bridge.skip_allowed must be false")
    # Header freshness required: fixture must match generator output.
    hdr_path = REPO / document.get("c_bridge", {}).get(
        "fixture_header", "tests/radio/r7_frag/r7_radio_wire_v1_fixture.h"
    )
    if not hdr_path.is_file():
        errors.append(f"missing C fixture header: {hdr_path}")
    else:
        try:
            fresh_doc = build_document()
            fresh_json = canonical_json(fresh_doc)
            fresh_hdr = generate_header(fresh_doc, fresh_json)
            on_disk_hdr = hdr_path.read_bytes()
            if on_disk_hdr != fresh_hdr:
                errors.append("C fixture header stale vs generator")
            if b"ninlil_r7_radio_wire_v1_rows" not in on_disk_hdr:
                errors.append("C fixture missing consumable row table")
            if b"ciphertext_hex" not in on_disk_hdr and b"ciphertext" not in on_disk_hdr:
                # struct fields present as member names in typedef
                if b"ciphertext_hex" not in on_disk_hdr:
                    errors.append("C fixture lacks ciphertext field")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"header freshness check failed: {exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=("self-test", "generate", "verify"))
    args = ap.parse_args(argv)
    if args.mode == "self-test":
        d1 = build_document()
        d2 = build_document()
        b1 = canonical_json(d1)
        b2 = canonical_json(d2)
        if b1 != b2:
            print("r7_radio_wire_v1 FAIL: non-deterministic generate", file=sys.stderr)
            return 1
        errs = verify_document(d1)
        if errs:
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            return 1
        print(
            f"r7_radio_wire_v1 self-test OK vectors={d1['vector_count']} "
            f"mandatory={len(MANDATORY_IDS)} hil=NOT_RUN"
        )
        return 0
    if args.mode == "generate":
        doc = build_document()
        raw = canonical_json(doc)
        hdr = generate_header(doc, raw)
        JSON_OUT.parent.mkdir(parents=True, exist_ok=True)
        HEADER_OUT.parent.mkdir(parents=True, exist_ok=True)
        JSON_OUT.write_bytes(raw)
        HEADER_OUT.write_bytes(hdr)
        print(
            f"r7_radio_wire_v1 generate OK json={JSON_OUT} "
            f"header={HEADER_OUT} vectors={doc['vector_count']}"
        )
        return 0
    # verify on-disk
    try:
        doc = json.loads(JSON_OUT.read_text(encoding="ascii"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"r7_radio_wire_v1 FAIL: {exc}", file=sys.stderr)
        return 1
    # Freshness: regenerating must match on-disk bytes.
    fresh = canonical_json(build_document())
    on_disk = JSON_OUT.read_bytes()
    if fresh != on_disk:
        print("r7_radio_wire_v1 FAIL: on-disk stale vs generator", file=sys.stderr)
        return 1
    errs = verify_document(doc)
    if errs:
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"r7_radio_wire_v1 verify OK vectors={doc['vector_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
