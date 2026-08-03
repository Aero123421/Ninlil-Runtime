#!/usr/bin/env python3
"""Reproducible domain-store schema1 independent-review manifest authority.

Algorithm: ninlil-domain-review-manifest-v1

Ordered files (JSON, Node gate, Python gate, generator):
  1. spec/vectors/domain-store-schema1-runtime-binding-v1.json
  2. tools/domain_store_schema1_binding_gate.mjs
  3. tools/domain_store_schema1_binding_gate.py
  4. tools/domain_store_schema1_binding_vector_gen.py

For each path in order, read raw bytes and append UTF-8 frame:
  "{path}\\n{byte_length_decimal}\\n{sha256_hex}\\n"
Manifest digest = SHA-256 (hex) of the concatenation of all frames.

Also records JSON-only SHA-256 of file (1) for the review document.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
ALGORITHM_ID = "ninlil-domain-review-manifest-v1"
MANIFEST_PATHS: tuple[str, ...] = (
    "spec/vectors/domain-store-schema1-runtime-binding-v1.json",
    "tools/domain_store_schema1_binding_gate.mjs",
    "tools/domain_store_schema1_binding_gate.py",
    "tools/domain_store_schema1_binding_vector_gen.py",
)
REVIEW_PATH = (
    "docs/reviews/2026-07-29-domain-store-schema1-spec-accepted.md"
)
CHECK_CMD = (
    "python3 tools/domain_store_schema1_review_manifest_gate.py check"
)


class GateError(RuntimeError):
    """Manifest authority failure."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_manifest(root: pathlib.Path = ROOT) -> dict[str, object]:
    frames: list[bytes] = []
    entries: list[dict[str, object]] = []
    for rel in MANIFEST_PATHS:
        path = root / rel
        if not path.is_file():
            raise GateError(f"manifest member missing: {rel}")
        data = path.read_bytes()
        digest = sha256_hex(data)
        frame = f"{rel}\n{len(data)}\n{digest}\n".encode("utf-8")
        frames.append(frame)
        entries.append(
            {
                "path": rel,
                "length": len(data),
                "sha256": digest,
            }
        )
    manifest_digest = sha256_hex(b"".join(frames))
    json_digest = str(entries[0]["sha256"])
    return {
        "algorithm": ALGORITHM_ID,
        "paths": list(MANIFEST_PATHS),
        "entries": entries,
        "json_sha256": json_digest,
        "manifest_sha256": manifest_digest,
        "check_command": CHECK_CMD,
    }


def format_report(result: dict[str, object]) -> str:
    lines = [
        f"algorithm: {result['algorithm']}",
        f"check_command: {result['check_command']}",
        f"json_sha256: {result['json_sha256']}",
        f"manifest_sha256: {result['manifest_sha256']}",
        "members:",
    ]
    for entry in result["entries"]:  # type: ignore[union-attr]
        lines.append(
            f"  - {entry['path']} length={entry['length']} sha256={entry['sha256']}"
        )
    return "\n".join(lines) + "\n"


def check_review_document(root: pathlib.Path, result: dict[str, object]) -> None:
    path = root / REVIEW_PATH
    if not path.is_file():
        raise GateError(f"review document missing: {REVIEW_PATH}")
    text = path.read_text(encoding="utf-8")
    required = [
        f"algorithm: `{ALGORITHM_ID}`",
        f"check_command: `{CHECK_CMD}`",
        f"json_sha256: `{result['json_sha256']}`",
        f"manifest_sha256: `{result['manifest_sha256']}`",
    ]
    for needle in required:
        if needle not in text:
            raise GateError(
                f"{REVIEW_PATH} missing required manifest authority line: {needle}"
            )
    # Forbid stale unexplained historical digest.
    if "729133ced29766e2bcb830985c7fcda0bb3f253c29d92fc3b300e75c27eb2973" in text:
        raise GateError(
            f"{REVIEW_PATH} still contains obsolete unexplained manifest digest 729…"
        )
    # Exactly one manifest_sha256 code span with the current digest.
    digests = re.findall(r"manifest_sha256:\s*`([0-9a-f]{64})`", text)
    if digests != [result["manifest_sha256"]]:
        raise GateError(
            f"{REVIEW_PATH} manifest_sha256 authority drift: {digests!r}"
        )


def check(root: pathlib.Path = ROOT) -> dict[str, object]:
    result = compute_manifest(root)
    check_review_document(root, result)
    return result


def self_test(root: pathlib.Path = ROOT) -> None:
    result = compute_manifest(root)
    # Determinism: recompute twice.
    again = compute_manifest(root)
    if again != result:
        raise GateError("manifest recompute is non-deterministic")
    # Frame integrity: path order matters.
    if list(result["paths"]) != list(MANIFEST_PATHS):
        raise GateError("manifest path order drift")
    # Mutation of first frame changes digest (in-memory).
    entries = list(result["entries"])  # type: ignore[arg-type]
    bad_frames = []
    for entry in entries:
        rel = str(entry["path"])
        length = int(entry["length"])  # type: ignore[arg-type]
        digest = str(entry["sha256"])
        if rel == MANIFEST_PATHS[0]:
            digest = "0" * 64
        bad_frames.append(f"{rel}\n{length}\n{digest}\n".encode("utf-8"))
    bad_digest = sha256_hex(b"".join(bad_frames))
    if bad_digest == result["manifest_sha256"]:
        raise GateError("manifest digest ignored member mutation")
    # Review document must match current digest (live check).
    check_review_document(root, result)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Domain-store schema1 review manifest gate"
    )
    parser.add_argument("command", choices=("check", "self-test", "print"))
    args = parser.parse_args(argv)
    try:
        if args.command == "print":
            result = compute_manifest()
            sys.stdout.write(format_report(result))
            return 0
        if args.command == "check":
            result = check()
            sys.stdout.write(
                "domain_store_schema1_review_manifest_gate check: PASS\n"
                + format_report(result)
            )
            return 0
        self_test()
        sys.stdout.write(
            "domain_store_schema1_review_manifest_gate self-test: PASS\n"
        )
        return 0
    except (GateError, OSError, UnicodeError) as exc:
        print(
            f"domain_store_schema1_review_manifest_gate: FAIL: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
