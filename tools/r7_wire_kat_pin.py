#!/usr/bin/env python3
"""T1 subset vector freshness + pin gate (docs/32 §7–8).

Regenerate oracle artifacts and compare to committed fixtures. Execute
production-linked bridge count contract via generated header count.
Mutation self-tests force red on drop / tag flip / skip metadata.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
ORACLE = REPO / "tools" / "r7_wire_single_oracle.py"
JSON_FIXTURE = REPO / "tests" / "radio" / "private" / "r7_wire_single_t1_vectors.json"
HEADER_FIXTURE = REPO / "tests" / "radio" / "private" / "r7_wire_single_t1_vectors.gen.h"
MANDATORY = 7


def run(cmd: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
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
    d.update(b"ninlil-r7-wire-t1-json\x00")
    d.update(json_bytes)
    d.update(b"ninlil-r7-wire-t1-header\x00")
    d.update(header_bytes)
    return d.hexdigest()


def regenerate() -> tuple[bytes, bytes]:
    proc = run([sys.executable, str(ORACLE), "emit-json"])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr)
    json_bytes = proc.stdout.encode("ascii") if isinstance(proc.stdout, str) else b""
    # emit-json writes binary-ish via text mode; re-run with capture of bytes
    proc_j = subprocess.run(
        [sys.executable, str(ORACLE), "emit-json"],
        cwd=str(REPO),
        capture_output=True,
        check=False,
    )
    proc_h = subprocess.run(
        [sys.executable, str(ORACLE), "emit-header"],
        cwd=str(REPO),
        capture_output=True,
        check=False,
    )
    if proc_j.returncode != 0 or proc_h.returncode != 0:
        raise RuntimeError("oracle emit failed")
    return proc_j.stdout, proc_h.stdout


def check() -> int:
    errors: list[str] = []
    try:
        fresh_json, fresh_header = regenerate()
    except RuntimeError as exc:
        print(f"r7_wire_kat_pin FAIL: {exc}", file=sys.stderr)
        return 1
    committed_json = JSON_FIXTURE.read_bytes()
    committed_header = HEADER_FIXTURE.read_bytes()
    if fresh_json != committed_json:
        errors.append("committed JSON is stale vs oracle")
    if fresh_header != committed_header:
        errors.append("committed header is stale vs oracle")
    doc = json.loads(committed_json.decode("ascii"))
    if doc.get("vector_count") != MANDATORY:
        errors.append(f"vector_count want {MANDATORY}")
    if doc.get("c_bridge", {}).get("skip_allowed") is not False:
        errors.append("skip_allowed must be false")
    if b"NINLIL_R7_WIRE_T1_VECTOR_COUNT 7u" not in committed_header:
        errors.append("header count macro missing/wrong")
    # dual hashseed regenerate identity
    with tempfile.TemporaryDirectory(prefix="r7-t1-pin-") as td:
        for seed in ("0", "99"):
            j = pathlib.Path(td) / f"{seed}.json"
            h = pathlib.Path(td) / f"{seed}.h"
            env = {"PYTHONHASHSEED": seed}
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
                env=env,
            )
            if proc.returncode != 0:
                errors.append(f"generate hashseed={seed} failed")
        j0 = (pathlib.Path(td) / "0.json").read_bytes()
        j99 = (pathlib.Path(td) / "99.json").read_bytes()
        if j0 != j99 or j0 != committed_json:
            errors.append("hashseed dual generate not identical to committed")
    if errors:
        for e in errors:
            print(f"r7_wire_kat_pin FAIL: {e}", file=sys.stderr)
        return 1
    print(
        f"r7_wire_kat_pin: PASS vectors={MANDATORY} "
        f"digest={artifact_digest(committed_json, committed_header)[:16]}…"
    )
    return 0


def self_test() -> int:
    failures: list[str] = []
    if check() != 0:
        failures.append("baseline check red")
        for f in failures:
            print(f"r7_wire_kat_pin self-test FAIL: {f}", file=sys.stderr)
        return 1
    # Mutate in temp: vector drop must make verify-document red via oracle.
    doc = json.loads(JSON_FIXTURE.read_text(encoding="ascii"))
    doc["vectors"] = doc["vectors"][1:]
    doc["vector_count"] = len(doc["vectors"])
    doc["c_bridge"]["required_vector_count"] = len(doc["vectors"])
    with tempfile.TemporaryDirectory(prefix="r7-t1-pin-mut-") as td:
        bad = pathlib.Path(td) / "bad.json"
        bad.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="ascii")
        proc = run([sys.executable, str(ORACLE), "verify-json", "--json", str(bad)])
        if proc.returncode == 0:
            failures.append("vector drop verify did not go red")
        # skip_allowed true
        doc2 = json.loads(JSON_FIXTURE.read_text(encoding="ascii"))
        doc2["c_bridge"]["skip_allowed"] = True
        bad2 = pathlib.Path(td) / "skip.json"
        bad2.write_text(
            json.dumps(doc2, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        proc2 = run([sys.executable, str(ORACLE), "verify-json", "--json", str(bad2)])
        if proc2.returncode == 0:
            failures.append("skip_allowed mutation did not go red")
        # expected tag flip
        doc3 = json.loads(JSON_FIXTURE.read_text(encoding="ascii"))
        tag = bytearray(bytes.fromhex(doc3["vectors"][0]["e2e_tag16"]))
        tag[0] ^= 1
        doc3["vectors"][0]["e2e_tag16"] = tag.hex()
        bad3 = pathlib.Path(td) / "tag.json"
        bad3.write_text(
            json.dumps(doc3, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        proc3 = run([sys.executable, str(ORACLE), "verify-json", "--json", str(bad3)])
        if proc3.returncode == 0:
            failures.append("tag flip mutation did not go red")
    if failures:
        for f in failures:
            print(f"r7_wire_kat_pin self-test FAIL: {f}", file=sys.stderr)
        return 1
    print("r7_wire_kat_pin self-test: PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args(argv)
    return check() if args.command == "check" else self_test()


if __name__ == "__main__":
    raise SystemExit(main())
