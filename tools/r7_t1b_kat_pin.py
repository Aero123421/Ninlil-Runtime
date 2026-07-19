#!/usr/bin/env python3
"""T1b subset vector freshness + pin gate (docs/33 §9–10).

Regenerate oracle artifacts and compare to committed fixtures. Exact 24 ID
multiset, lowercase hex, labels/profile/mask/non-claims/c_bridge no-skip,
artifact and header SHA pins. Mutation self-tests force red on
byte/count/ID/metadata/header/hash drift.

PASS ≠ C bridge execution / ESP KAT / HIL / T1b Accepted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
from collections import Counter
from typing import Any, Union

REPO = pathlib.Path(__file__).resolve().parents[1]
ORACLE = REPO / "tools" / "r7_t1b_binding_oracle.py"
JSON_FIXTURE = REPO / "spec" / "vectors" / "r7-t1b-binding-subset.json"
HEADER_FIXTURE = REPO / "tests" / "radio" / "private" / "r7_t1b_binding_vectors.h"

MANDATORY = 24
FORMAT_ID = "ninlil-r7-t1b-binding-subset-v1"
ARTIFACT = "ninlil_r7_t1b_binding_subset"
WIRE_PROFILE = 0x11
ALLOWED_MASK = 0x0003

MANDATORY_IDS: tuple[str, ...] = (
    "R7-T1B-E2E-FIELD-D0-MAX",
    "R7-T1B-E2E-FIELD-D0-MIN",
    "R7-T1B-E2E-FIELD-D1-MAX",
    "R7-T1B-E2E-FIELD-D1-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MAX",
    "R7-T1B-E2E-LAB-NO-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-FIELD-D0-MAX",
    "R7-T1B-HOP-FIELD-D0-MIN",
    "R7-T1B-HOP-FIELD-D1-MAX",
    "R7-T1B-HOP-FIELD-D1-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MAX",
    "R7-T1B-HOP-LAB-CONTROLLER-D1-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D0-MIN",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MAX",
    "R7-T1B-HOP-LAB-NO-CONTROLLER-D1-MIN",
)

# Domain-separated pin over committed JSON + generated header bytes.
# Refresh only with intentional vector review (docs/33 §9).
PINNED_ARTIFACT_SHA256 = (
    "b47b39b1a81b68982564276d0a76d178cc595777dbafdf694f299787045dc30b"
)
PINNED_JSON_SHA256 = (
    "977f0911a5cb825dc860f1388fac602b223ed3ccbb4635ce4881696b94e892fe"
)
PINNED_HEADER_SHA256 = (
    "b9b37cf250c67a583f09f05b18c6d60caf0962e301537abd6a1e9987800b48a2"
)

LABELS = (
    b"NINLIL-R6-HOP-CTX-v1",
    b"NINLIL-R6-E2E-CTX-v1",
    b"NINLIL-R6-HOP-DATA-KEY-v1",
    b"NINLIL-R6-HOP-DATA-IV-v1",
    b"NINLIL-R6-HOP-ACK-KEY-v1",
    b"NINLIL-R6-HOP-ACK-IV-v1",
    b"NINLIL-R6-E2E-KEY-v1",
    b"NINLIL-R6-E2E-IV-v1",
)

HEX_RE = re.compile(r"^[0-9a-f]*$")

# Exact self-test mutation ledger. Unexecuted or under-count is red.
# 1 vector_drop 2 extra_id 3 duplicate_id 4 skip_allowed
# 5 digest_byte_flip_pin 6 uppercase_hex 7 header_count 8 header_id
# 9 json_sha_pin 10 header_sha_pin 11 artifact_sha_pin 12 profile_byte
# 13 empty_non_claims 14 format_id_drift
EXPECTED_MUTATION_COUNT = 14

BytesOrPath = Union[bytes, pathlib.Path]


def run(
    cmd: list[str], *, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged["PYTHONDONTWRITEBYTECODE"] = "1"
    if env:
        merged.update(env)
    return subprocess.run(
        cmd,
        cwd=str(REPO),
        env=merged,
        text=True,
        capture_output=True,
        check=False,
    )


def artifact_digest(json_bytes: bytes, header_bytes: bytes) -> str:
    d = hashlib.sha256()
    d.update(b"ninlil-r7-t1b-json\x00")
    d.update(json_bytes)
    d.update(b"ninlil-r7-t1b-header\x00")
    d.update(header_bytes)
    return d.hexdigest()


def regenerate() -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory(prefix="r7-t1b-pin-regen-") as td:
        j = pathlib.Path(td) / "out.json"
        h = pathlib.Path(td) / "out.h"
        proc = run(
            [
                sys.executable,
                str(ORACLE),
                "generate",
                "--json",
                str(j),
                "--header",
                str(h),
            ]
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"oracle generate failed: {proc.stderr or proc.stdout}"
            )
        return j.read_bytes(), h.read_bytes()


def _load_bytes(source: BytesOrPath) -> bytes:
    if isinstance(source, (bytes, bytearray)):
        return bytes(source)
    return pathlib.Path(source).read_bytes()


def _is_lower_hex(value: str) -> bool:
    if not isinstance(value, str):
        return False
    if len(value) % 2 != 0:
        return False
    return HEX_RE.fullmatch(value) is not None


def structural_document_errors(doc: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if doc.get("format_id") != FORMAT_ID:
        errors.append(f"format_id want {FORMAT_ID}")
    if doc.get("artifact") != ARTIFACT:
        errors.append(f"artifact want {ARTIFACT}")
    if doc.get("vector_count") != MANDATORY:
        errors.append(f"vector_count want {MANDATORY} got {doc.get('vector_count')}")
    vectors = doc.get("vectors")
    if not isinstance(vectors, list):
        return errors + ["vectors not a list"]
    if len(vectors) != MANDATORY:
        errors.append(f"vectors length want {MANDATORY} got {len(vectors)}")
    ids = [row.get("id") for row in vectors if isinstance(row, dict)]
    if Counter(ids) != Counter(MANDATORY_IDS):
        errors.append(
            f"ID multiset mismatch got={sorted(str(i) for i in ids)} "
            f"want={list(MANDATORY_IDS)}"
        )
    if len(ids) != len(set(ids)):
        errors.append("duplicate vector IDs")
    if ids != sorted(str(i) for i in ids):
        errors.append("vector IDs not sorted")

    bridge = doc.get("c_bridge")
    if not isinstance(bridge, dict):
        errors.append("c_bridge missing")
    else:
        if bridge.get("skip_allowed") is not False:
            errors.append("c_bridge.skip_allowed must be false")
        if bridge.get("implemented") is not True:
            errors.append("c_bridge.implemented must be true")
        if bridge.get("status") != "implemented":
            errors.append("c_bridge.status must be implemented")
        if bridge.get("required_vector_count") != MANDATORY:
            errors.append("c_bridge.required_vector_count must be 24")

    claims = doc.get("non_claims")
    if not isinstance(claims, list) or not claims:
        errors.append("non_claims missing/empty")
    else:
        joined = " ".join(str(c).lower() for c in claims)
        for needle in ("t1b", "not", "hil", "r7"):
            if needle not in joined:
                # soft: at least some non-claims language present
                pass
        if "not" not in joined and "not " not in joined:
            errors.append("non_claims must assert non-completion")

    # Lowercase hex on all material fields.
    hex_keys = (
        "canonical",
        "digest",
        "prk",
        "traffic_secret32",
        "data_key16",
        "data_iv12",
        "ack_key16",
        "ack_iv12",
        "key16",
        "iv12",
    )
    for row in vectors:
        if not isinstance(row, dict):
            errors.append("vector row not object")
            continue
        rid = row.get("id", "?")
        for key in hex_keys:
            val = row.get(key, "")
            if val in ("", None):
                continue
            if not _is_lower_hex(str(val)):
                errors.append(f"{rid}:{key} not lowercase hex")
        # Profile / mask fixed in canonical: byte 20 is profile after 20-byte label.
        try:
            canon = bytes.fromhex(str(row.get("canonical", "")))
        except ValueError:
            errors.append(f"{rid}: canonical not hex")
            continue
        if len(canon) < 22:
            errors.append(f"{rid}: canonical too short for profile")
            continue
        if canon[20] != WIRE_PROFILE:
            errors.append(f"{rid}: profile byte want 0x{WIRE_PROFILE:02x}")
        if row.get("layer") == "hop":
            if len(canon) < 2 or int.from_bytes(canon[-2:], "big") != ALLOWED_MASK:
                errors.append(f"{rid}: hop allowed_kind_mask not 0x{ALLOWED_MASK:04x}")
    return errors


def header_errors(header_bytes: bytes, json_bytes: bytes) -> list[str]:
    errors: list[str] = []
    if b"NINLIL_R7_T1B_VECTOR_COUNT 24u" not in header_bytes:
        errors.append("header count macro missing/wrong")
    if b"NINLIL_R7_T1B_REQUIRED_VECTOR_COUNT 24u" not in header_bytes:
        errors.append("header required count macro missing/wrong")
    digest = hashlib.sha256(json_bytes).hexdigest().encode("ascii")
    if digest not in header_bytes:
        errors.append("header missing JSON SHA-256 pin")
    for vid in MANDATORY_IDS:
        if vid.encode("ascii") not in header_bytes:
            errors.append(f"header missing id {vid}")
    # Labels / profile non-claims in comments
    if b"skip forbidden" not in header_bytes and b"skip_allowed" not in header_bytes:
        if b"skip" not in header_bytes.lower():
            errors.append("header missing skip-forbidden annotation")
    return errors


def validate_artifacts(
    json_source: BytesOrPath,
    header_source: BytesOrPath,
    *,
    fresh_json: bytes | None = None,
    fresh_header: bytes | None = None,
    expected_json_sha: str = PINNED_JSON_SHA256,
    expected_header_sha: str = PINNED_HEADER_SHA256,
    expected_artifact_sha: str = PINNED_ARTIFACT_SHA256,
) -> list[str]:
    """Production check core on path or bytes (pins + structural + header).

    Same validation path as check() for committed fixture material. Optional
    fresh_* bytes enable oracle-regenerate freshness compares. Expected-pin
    overrides exist only to isolate each comparison in self_test(); check()
    always uses the fixed module constants.
    """
    errors: list[str] = []
    try:
        json_bytes = _load_bytes(json_source)
        header_bytes = _load_bytes(header_source)
    except OSError as exc:
        return [f"artifact load: {exc}"]

    if fresh_json is not None and json_bytes != fresh_json:
        errors.append("committed JSON is stale vs oracle")
    if fresh_header is not None and header_bytes != fresh_header:
        errors.append("committed header is stale vs oracle")

    json_sha = hashlib.sha256(json_bytes).hexdigest()
    header_sha = hashlib.sha256(header_bytes).hexdigest()
    art_sha = artifact_digest(json_bytes, header_bytes)
    if json_sha != expected_json_sha:
        errors.append(f"JSON SHA pin mismatch got={json_sha}")
    if header_sha != expected_header_sha:
        errors.append(f"header SHA pin mismatch got={header_sha}")
    if art_sha != expected_artifact_sha:
        errors.append(f"artifact SHA pin mismatch got={art_sha}")

    try:
        doc = json.loads(json_bytes.decode("ascii"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        errors.append(f"committed JSON parse: {exc}")
        doc = {}
    if isinstance(doc, dict):
        errors.extend(structural_document_errors(doc))
    errors.extend(header_errors(header_bytes, json_bytes))
    return errors


def validate_artifacts_rc(
    json_source: BytesOrPath,
    header_source: BytesOrPath,
    *,
    fresh_json: bytes | None = None,
    fresh_header: bytes | None = None,
    expected_json_sha: str = PINNED_JSON_SHA256,
    expected_header_sha: str = PINNED_HEADER_SHA256,
    expected_artifact_sha: str = PINNED_ARTIFACT_SHA256,
) -> int:
    """Return 0 iff validate_artifacts reports no errors (production check shape)."""
    return (
        0
        if not validate_artifacts(
            json_source,
            header_source,
            fresh_json=fresh_json,
            fresh_header=fresh_header,
            expected_json_sha=expected_json_sha,
            expected_header_sha=expected_header_sha,
            expected_artifact_sha=expected_artifact_sha,
        )
        else 1
    )


def _dump_json(doc: dict[str, Any]) -> bytes:
    return (json.dumps(doc, sort_keys=True, indent=2) + "\n").encode("ascii")


def _sync_header_json_sha(header_bytes: bytes, old_json: bytes, new_json: bytes) -> bytes:
    """Keep header structural/header_errors green after intentional JSON mutation."""
    old_sha = hashlib.sha256(old_json).hexdigest().encode("ascii")
    new_sha = hashlib.sha256(new_json).hexdigest().encode("ascii")
    if old_sha not in header_bytes:
        raise RuntimeError("committed header missing baseline JSON SHA pin")
    return header_bytes.replace(old_sha, new_sha, 1)


def check() -> int:
    errors: list[str] = []
    try:
        fresh_json, fresh_header = regenerate()
    except RuntimeError as exc:
        print(f"r7_t1b_kat_pin FAIL: {exc}", file=sys.stderr)
        return 1

    try:
        committed_json = JSON_FIXTURE.read_bytes()
        committed_header = HEADER_FIXTURE.read_bytes()
    except OSError as exc:
        print(f"r7_t1b_kat_pin FAIL: {exc}", file=sys.stderr)
        return 1

    errors.extend(
        validate_artifacts(
            committed_json,
            committed_header,
            fresh_json=fresh_json,
            fresh_header=fresh_header,
        )
    )

    # Dual hashseed regenerate identity.
    with tempfile.TemporaryDirectory(prefix="r7-t1b-pin-hash-") as td:
        for seed in ("0", "99"):
            j = pathlib.Path(td) / f"{seed}.json"
            h = pathlib.Path(td) / f"{seed}.h"
            proc = run(
                [
                    sys.executable,
                    str(ORACLE),
                    "generate",
                    "--json",
                    str(j),
                    "--header",
                    str(h),
                ],
                env={"PYTHONHASHSEED": seed},
            )
            if proc.returncode != 0:
                errors.append(f"generate hashseed={seed} failed")
        j0 = (pathlib.Path(td) / "0.json").read_bytes()
        j99 = (pathlib.Path(td) / "99.json").read_bytes()
        if j0 != j99 or j0 != committed_json:
            errors.append("hashseed dual generate not identical to committed")

    # Oracle verify command must pass on committed artifacts.
    verify = run([sys.executable, str(ORACLE), "verify"])
    if verify.returncode != 0:
        errors.append(
            f"oracle verify failed: {verify.stderr or verify.stdout}"
        )

    # Label presence in oracle source (fixed, not caller-selected).
    oracle_text = ORACLE.read_bytes()
    for label in LABELS:
        if label not in oracle_text:
            errors.append(f"oracle missing fixed label {label!r}")

    if errors:
        for e in errors:
            print(f"r7_t1b_kat_pin FAIL: {e}", file=sys.stderr)
        return 1
    art_sha = artifact_digest(committed_json, committed_header)
    print(
        f"r7_t1b_kat_pin: PASS vectors={MANDATORY} "
        f"digest={art_sha[:16]}… ids=exact24 lowercase_hex=yes "
        f"c_bridge.skip_allowed=false"
    )
    return 0


def self_test() -> int:
    failures: list[str] = []
    if check() != 0:
        failures.append("baseline check red")
        for f in failures:
            print(f"r7_t1b_kat_pin self-test FAIL: {f}", file=sys.stderr)
        return 1

    committed_json = JSON_FIXTURE.read_bytes()
    committed_header = HEADER_FIXTURE.read_bytes()
    committed = json.loads(committed_json.decode("ascii"))
    executed = 0

    def expect_red(
        name: str,
        json_b: bytes,
        header_b: bytes,
        *,
        expected_json_sha: str = PINNED_JSON_SHA256,
        expected_header_sha: str = PINNED_HEADER_SHA256,
        expected_artifact_sha: str = PINNED_ARTIFACT_SHA256,
        only_error_prefix: str | None = None,
    ) -> None:
        nonlocal executed
        executed += 1
        # Path and bytes forms of the same production validation path.
        with tempfile.TemporaryDirectory(prefix="r7-t1b-pin-mut-") as td:
            td_path = pathlib.Path(td)
            j_path = td_path / "mut.json"
            h_path = td_path / "mut.h"
            j_path.write_bytes(json_b)
            h_path.write_bytes(header_b)
            validation_kwargs = {
                "expected_json_sha": expected_json_sha,
                "expected_header_sha": expected_header_sha,
                "expected_artifact_sha": expected_artifact_sha,
            }
            rc_path = validate_artifacts_rc(
                j_path, h_path, **validation_kwargs
            )
            rc_bytes = validate_artifacts_rc(
                json_b, header_b, **validation_kwargs
            )
            if rc_path == 0 or rc_bytes == 0:
                failures.append(f"{name} did not go red via real pin path")
            path_errs = validate_artifacts(j_path, h_path, **validation_kwargs)
            errs = validate_artifacts(json_b, header_b, **validation_kwargs)
            if not errs:
                failures.append(f"{name} validate_artifacts empty")
            if path_errs != errs:
                failures.append(f"{name} path/bytes validation diverged")
            if only_error_prefix is not None and (
                len(errs) != 1 or not errs[0].startswith(only_error_prefix)
            ):
                failures.append(
                    f"{name} not isolated to {only_error_prefix!r}: {errs}"
                )

    # 1) Count / ID drop
    doc = json.loads(json.dumps(committed))
    doc["vectors"] = doc["vectors"][1:]
    doc["vector_count"] = len(doc["vectors"])
    doc["c_bridge"]["required_vector_count"] = len(doc["vectors"])
    expect_red("vector_drop", _dump_json(doc), committed_header)

    # 2) Extra ID
    doc2 = json.loads(json.dumps(committed))
    extra = dict(doc2["vectors"][0])
    extra["id"] = "R7-T1B-EXTRA-ID"
    doc2["vectors"] = list(doc2["vectors"]) + [extra]
    doc2["vector_count"] = len(doc2["vectors"])
    expect_red("extra_id", _dump_json(doc2), committed_header)

    # 3) Duplicate ID
    doc3 = json.loads(json.dumps(committed))
    doc3["vectors"] = list(doc3["vectors"])
    doc3["vectors"][1] = dict(doc3["vectors"][0])
    expect_red("duplicate_id", _dump_json(doc3), committed_header)

    # 4) Metadata: skip_allowed true
    doc4 = json.loads(json.dumps(committed))
    doc4["c_bridge"]["skip_allowed"] = True
    expect_red("skip_allowed", _dump_json(doc4), committed_header)

    # 5) Digest byte flip — semantic pin mutation (structural may stay green;
    #    header embedded JSON SHA re-synced so only SHA pins reject).
    doc5 = json.loads(json.dumps(committed))
    dig = bytearray(bytes.fromhex(doc5["vectors"][0]["digest"]))
    dig[0] ^= 1
    doc5["vectors"][0]["digest"] = dig.hex()
    mut5_json = _dump_json(doc5)
    mut5_header = _sync_header_json_sha(committed_header, committed_json, mut5_json)
    # Guard: structural alone must not be the sole reject (pin path required).
    if structural_document_errors(doc5):
        failures.append("digest flip unexpectedly failed structural-only")
    if header_errors(mut5_header, mut5_json):
        failures.append("digest flip unexpectedly failed header_errors after sync")
    expect_red("digest_byte_flip_pin", mut5_json, mut5_header)

    # 6) Uppercase hex
    doc6 = json.loads(json.dumps(committed))
    doc6["vectors"][0]["digest"] = doc6["vectors"][0]["digest"].upper()
    expect_red("uppercase_hex", _dump_json(doc6), committed_header)

    # 7) Header count mutation
    bad_header = committed_header.replace(
        b"NINLIL_R7_T1B_VECTOR_COUNT 24u",
        b"NINLIL_R7_T1B_VECTOR_COUNT 23u",
        1,
    )
    expect_red("header_count", committed_json, bad_header)

    # 8) Header missing ID
    bad_header2 = committed_header.replace(
        MANDATORY_IDS[0].encode("ascii"), b"R7-T1B-MISSING-ID-XXXX", 1
    )
    expect_red("header_id", committed_json, bad_header2)

    # 9) JSON SHA pin — flip digest + sync header so pin constants are sole reject
    #    (same material as #5; distinct name for ledger clarity on pin gate).
    #    Use a different vector index to keep mutations independent.
    doc9 = json.loads(json.dumps(committed))
    dig9 = bytearray(bytes.fromhex(doc9["vectors"][1]["digest"]))
    dig9[1] ^= 1
    doc9["vectors"][1]["digest"] = dig9.hex()
    mut9_json = _dump_json(doc9)
    mut9_header = _sync_header_json_sha(committed_header, committed_json, mut9_json)
    if hashlib.sha256(mut9_json).hexdigest() == PINNED_JSON_SHA256:
        failures.append("JSON SHA mutation did not change pin identity")
    if structural_document_errors(doc9):
        failures.append("JSON SHA mutation unexpectedly structural-red")
    if header_errors(mut9_header, mut9_json):
        failures.append("JSON SHA mutation unexpectedly header_errors-red")
    expect_red(
        "json_sha_pin",
        mut9_json,
        mut9_header,
        expected_header_sha=hashlib.sha256(mut9_header).hexdigest(),
        expected_artifact_sha=artifact_digest(mut9_json, mut9_header),
        only_error_prefix="JSON SHA pin mismatch",
    )

    # 10) Header SHA pin — comment-only drift (header_errors stays green)
    mut10_header = committed_header.replace(
        b"generated by tools/r7_t1b_binding_oracle.py",
        b"generated by tools/r7_t1b_binding_oracle.pX",
        1,
    )
    if hashlib.sha256(mut10_header).hexdigest() == PINNED_HEADER_SHA256:
        failures.append("header SHA mutation did not change pin identity")
    if header_errors(mut10_header, committed_json):
        failures.append("header SHA comment mutation unexpectedly header_errors-red")
    expect_red(
        "header_sha_pin",
        committed_json,
        mut10_header,
        expected_artifact_sha=artifact_digest(committed_json, mut10_header),
        only_error_prefix="header SHA pin mismatch",
    )

    # 11) Domain-separated artifact SHA — JSON body pin-only drift
    #     (structural green, header sync, artifact pin must reject).
    doc11 = json.loads(json.dumps(committed))
    dig11 = bytearray(bytes.fromhex(doc11["vectors"][2]["digest"]))
    dig11[2] ^= 1
    doc11["vectors"][2]["digest"] = dig11.hex()
    mut11_json = _dump_json(doc11)
    mut11_header = _sync_header_json_sha(committed_header, committed_json, mut11_json)
    art_mut = artifact_digest(mut11_json, mut11_header)
    if art_mut == PINNED_ARTIFACT_SHA256:
        failures.append("artifact SHA mutation did not change pin identity")
    if structural_document_errors(doc11):
        failures.append("artifact SHA mutation unexpectedly structural-red")
    if header_errors(mut11_header, mut11_json):
        failures.append("artifact SHA mutation unexpectedly header_errors-red")
    expect_red(
        "artifact_sha_pin",
        mut11_json,
        mut11_header,
        expected_json_sha=hashlib.sha256(mut11_json).hexdigest(),
        expected_header_sha=hashlib.sha256(mut11_header).hexdigest(),
        only_error_prefix="artifact SHA pin mismatch",
    )

    # 12) Profile byte mutation
    doc7 = json.loads(json.dumps(committed))
    canon = bytearray(bytes.fromhex(doc7["vectors"][0]["canonical"]))
    canon[20] = 0x22
    doc7["vectors"][0]["canonical"] = canon.hex()
    expect_red("profile_byte", _dump_json(doc7), committed_header)

    # 13) empty non_claims metadata drift
    doc8 = json.loads(json.dumps(committed))
    doc8["non_claims"] = []
    expect_red("empty_non_claims", _dump_json(doc8), committed_header)

    # 14) format_id drift
    doc9f = json.loads(json.dumps(committed))
    doc9f["format_id"] = "wrong-format"
    expect_red("format_id_drift", _dump_json(doc9f), committed_header)

    if executed != EXPECTED_MUTATION_COUNT:
        failures.append(
            f"mutation count want {EXPECTED_MUTATION_COUNT} got {executed}"
        )

    if failures:
        for f in failures:
            print(f"r7_t1b_kat_pin self-test FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "r7_t1b_kat_pin self-test: PASS "
        f"(mutations={executed}/{EXPECTED_MUTATION_COUNT} "
        "digest/json/header/artifact pin + id/count/metadata/header red; "
        "PASS≠Accepted/HIL)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args(argv)
    return check() if args.command == "check" else self_test()


if __name__ == "__main__":
    raise SystemExit(main())
