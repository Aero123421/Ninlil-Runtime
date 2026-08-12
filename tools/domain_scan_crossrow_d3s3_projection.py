#!/usr/bin/env python3
"""Project the frozen D3-S3 prefix from the append-only D3-S4 authority.

The shared crossrow artifact advances in-place. Older D3-S1/S2/S3 generators
remain frozen and intentionally reject the newer top-level format. This tool
produces the exact prior D3-S3 authority in the build directory so those
regressions continue to execute without weakening their format/count gates.

This is a projection helper, not a second source of semantic truth. The input
must first pass the complete independent D3-S4 checker.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

from domain_scan_crossrow_d3s4_authority import AuthorityError, load_expanded

REPO = Path(__file__).resolve().parents[1]
D3S4_TOOL = REPO / "tools" / "domain_scan_crossrow_d3s4_vector_gen.py"
DEFAULT_SOURCE = REPO / "spec" / "vectors" / "domain-scan-crossrow-v1.json"

D3S3_FORMAT = "ninlil-domain-scan-crossrow-v1-d3s3"
D3S3_SCOPE = (
    "D3-S3 constructible BLOB lifecycle append-only on d3s1+d3s2 prefix"
)
D3S3_COUNT = 283
D3S3_CONTENT_SHA256 = (
    "9d33b213d3b0cf24bc993717d11c88d5ff7485f11c59d50fed845ebb6c888e22"
)
D3S3_RAW_SHA256 = (
    "c8cecf86d430deeed3885e9da8d0b4b79d525f2d1183092d56f99314d47076b6"
)
D3S3_VECTOR_PREFIX_SHA256 = (
    "c39e821b3f6a627758036b49b98a2fc1649bf488b9c9ec9651dcc4bee1f41d41"
)


class ProjectionError(ValueError):
    """Closed projection failure."""


def _load_d3s4_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "ninlil_domain_scan_crossrow_d3s4_projection_authority", D3S4_TOOL
    )
    if spec is None or spec.loader is None:
        raise ProjectionError("cannot load D3-S4 authority module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _content_sha256(document: Dict[str, Any]) -> str:
    body = {
        key: value
        for key, value in document.items()
        if key != "content_sha256"
    }
    canonical = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _validate_projection_bytes(raw: bytes) -> Dict[str, Any]:
    try:
        document = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProjectionError(f"projected JSON malformed: {exc}") from exc
    if not isinstance(document, dict):
        raise ProjectionError("projected document is not an object")
    vectors = document.get("vectors")
    if (
        document.get("format") != D3S3_FORMAT
        or document.get("vector_count") != D3S3_COUNT
        or not isinstance(vectors, list)
        or len(vectors) != D3S3_COUNT
    ):
        raise ProjectionError("projected format/count mismatch")
    if "d3s4_suffix_count" in document or "d3s4_meta" in document:
        raise ProjectionError("projected document retained D3-S4 metadata")
    if document.get("content_sha256") != D3S3_CONTENT_SHA256:
        raise ProjectionError("projected content pin mismatch")
    if _content_sha256(document) != D3S3_CONTENT_SHA256:
        raise ProjectionError("projected content recomputation mismatch")
    prefix_raw = json.dumps(
        vectors,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if hashlib.sha256(prefix_raw).hexdigest() != D3S3_VECTOR_PREFIX_SHA256:
        raise ProjectionError("projected vector-prefix pin mismatch")
    if hashlib.sha256(raw).hexdigest() != D3S3_RAW_SHA256:
        raise ProjectionError("projected whole-file raw pin mismatch")
    canonical = (
        json.dumps(document, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    if raw != canonical:
        raise ProjectionError("projected serialization is not canonical")
    return document


def project_bytes(source: Path) -> bytes:
    authority = _load_d3s4_module()
    if authority.check(source, quiet=True) != 0:
        raise ProjectionError("D3-S4 source authority check failed")
    try:
        document = load_expanded(source, pin_fixed_authority=True)
    except AuthorityError as exc:
        raise ProjectionError(f"source unreadable: {exc}") from exc
    if not isinstance(document, dict):
        raise ProjectionError("source document is not an object")
    vectors = document.get("vectors")
    if not isinstance(vectors, list) or len(vectors) < D3S3_COUNT:
        raise ProjectionError("source does not contain the complete D3-S3 prefix")

    projected = dict(document)
    projected["format"] = D3S3_FORMAT
    projected["scope"] = D3S3_SCOPE
    projected["vector_count"] = D3S3_COUNT
    projected["vectors"] = vectors[:D3S3_COUNT]
    projected.pop("d3s4_suffix_count", None)
    projected.pop("d3s4_meta", None)
    projected["content_sha256"] = _content_sha256(projected)
    raw = (
        json.dumps(projected, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    _validate_projection_bytes(raw)
    return raw


def write_projection(source: Path, output: Path) -> None:
    raw = project_bytes(source)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, output)


def check_projection(source: Path, projection: Path) -> None:
    expected = project_bytes(source)
    try:
        actual = projection.read_bytes()
    except OSError as exc:
        raise ProjectionError(f"projection unreadable: {exc}") from exc
    _validate_projection_bytes(actual)
    if actual != expected:
        raise ProjectionError("projection is stale")


def self_test(source: Path) -> None:
    raw = project_bytes(source)
    document = _validate_projection_bytes(raw)
    mutated = dict(document)
    mutated_vectors = list(document["vectors"])
    mutated_first = dict(mutated_vectors[0])
    mutated_first["id"] = "MUTATED_D3S3_PREFIX"
    mutated_vectors[0] = mutated_first
    mutated["vectors"] = mutated_vectors
    mutated["content_sha256"] = _content_sha256(mutated)
    mutated_raw = (
        json.dumps(mutated, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    try:
        _validate_projection_bytes(mutated_raw)
    except ProjectionError:
        pass
    else:
        raise ProjectionError("prefix mutation was not rejected")


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "project":
            write_projection(Path(argv[2]), Path(argv[3]))
            print(f"projected D3-S3 authority: {argv[3]}")
            return 0
        if len(argv) == 4 and argv[1] == "check":
            check_projection(Path(argv[2]), Path(argv[3]))
            print("D3-S3 projection check OK")
            return 0
        if len(argv) in (2, 3) and argv[1] == "self-test":
            source = Path(argv[2]) if len(argv) == 3 else DEFAULT_SOURCE
            self_test(source)
            print("D3-S3 projection self-test OK")
            return 0
        print(
            "error: usage: project <d3s4.json> <d3s3.json> | "
            "check <d3s4.json> <d3s3.json> | self-test [d3s4.json]",
            file=sys.stderr,
        )
        return 2
    except (OSError, ProjectionError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
