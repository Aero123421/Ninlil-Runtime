#!/usr/bin/env python3
"""Deterministic manifest/shard authority for the D3-S4 cross-row oracle.

The public authority is a small manifest plus ordered, independently hashed
semantic slices.  A consumer can validate the complete 468-vector authority
while retaining at most one shard in memory.  ``load_expanded`` exists for the
legacy D3-S4 gate, whose semantic checks still require the complete document.

This module deliberately has no dependency on the D3-S4 generator.  The fixed
semantic pins below were computed from the pre-sharding canonical authority.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterator, List, Mapping, Sequence, Tuple

MANIFEST_FORMAT = "ninlil-domain-scan-crossrow-manifest-v1"
SHARD_FORMAT = "ninlil-domain-scan-crossrow-shard-v1"
EXPANDED_FORMAT = "ninlil-domain-scan-crossrow-v1-d3s4"
VERSION = 1
MAX_SHARD_BYTES = 10 * 1024 * 1024
TARGET_SHARD_BYTES = 7 * 1024 * 1024

EXPANDED_VECTOR_COUNT = 468
EXPANDED_CONTENT_SHA256 = (
    "b18f717e2752c9d617d575c86194ef644f301706263674f2666a5d29ed951e25"
)
EXPANDED_ORDER_SHA256 = (
    "17ec848715537a261f274a392d23c586045b87bc0adf1fe65cb1e15c7f0c8c4d"
)
EXPANDED_NEGATIVE_COUNT = 191
EXPANDED_NEGATIVE_SHA256 = (
    "74e0ded28a87d77f002db181a496a70efd29f601833c08d2379e717fff7f00ee"
)
EXPANDED_CANONICAL_SHA256 = (
    "33d936597ce617952043f6a0324ba616b8d71acf41cc8744d1b3f771abd54f15"
)

_MANIFEST_KEYS = {
    "format",
    "version",
    "expanded_format",
    "expanded_vector_count",
    "expanded_content_sha256",
    "expanded_order_sha256",
    "expanded_negative_count",
    "expanded_negative_sha256",
    "expanded_canonical_sha256",
    "expanded_key_order",
    "max_shard_bytes",
    "top_level",
    "shards",
}
_SHARD_KEYS = {"format", "version", "start", "count", "vectors"}
_SHARD_ENTRY_KEYS = {
    "path",
    "stage",
    "slice",
    "start",
    "count",
    "bytes",
    "sha256",
    "first_id",
    "last_id",
}


class AuthorityError(ValueError):
    """Raised when a manifest, shard, or expanded semantic pin is invalid."""


def canonical_bytes(value: Any) -> bytes:
    """Return the repository byte representation: compact UTF-8 JSON plus LF."""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def stable_bytes(value: Any) -> bytes:
    """Return sorted-key compact JSON bytes (no trailing LF)."""
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def compute_content_sha256(doc: Mapping[str, Any]) -> str:
    digest = hashlib.sha256()
    keys = sorted(key for key in doc if key != "content_sha256")
    digest.update(b"{")
    for key_index, key in enumerate(keys):
        if key_index:
            digest.update(b",")
        digest.update(stable_bytes(key))
        digest.update(b":")
        value = doc[key]
        if key == "vectors" and isinstance(value, Sequence):
            digest.update(b"[")
            for vector_index, vector in enumerate(value):
                if vector_index:
                    digest.update(b",")
                digest.update(stable_bytes(vector))
            digest.update(b"]")
        else:
            digest.update(stable_bytes(value))
    digest.update(b"}")
    return digest.hexdigest()


def order_row(index: int, vector: Mapping[str, Any]) -> bytes:
    return (
        f"{index}\0{vector.get('id', '')}\0{vector.get('kind', '')}\0"
        f"{vector.get('mode', '')}\0{int(bool(vector.get('positive')))}"
    ).encode("utf-8")


def negative_projection(vector: Mapping[str, Any]) -> Dict[str, Any]:
    expected = vector.get("expected")
    if not isinstance(expected, Mapping):
        expected = {}
    faults = vector.get("faults")
    if not isinstance(faults, list):
        faults = []
    return {
        "id": vector.get("id"),
        "kind": vector.get("kind"),
        "mode": vector.get("mode"),
        "negative_base": vector.get("negative_base"),
        "declared_mutation_fields": vector.get("declared_mutation_fields"),
        "first_reason": expected.get("d3s4_first_reason"),
        "faults": faults,
    }


def compute_semantic_pins(vectors: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    order = hashlib.sha256()
    negatives: List[Dict[str, Any]] = []
    for index, vector in enumerate(vectors):
        if index:
            order.update(b"\n")
        order.update(order_row(index, vector))
        if vector.get("positive") is False:
            negatives.append(negative_projection(vector))
    negative_raw = json.dumps(
        negatives, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return {
        "vector_count": len(vectors),
        "order_sha256": order.hexdigest(),
        "negative_count": len(negatives),
        "negative_sha256": hashlib.sha256(negative_raw).hexdigest(),
    }


def _load_canonical_object(path: Path, *, label: str) -> Tuple[Dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AuthorityError(f"{label}: cannot read {path}: {exc}") from exc
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityError(f"{label}: malformed JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuthorityError(f"{label}: root is not an object: {path}")
    if raw != canonical_bytes(value):
        raise AuthorityError(f"{label}: non-canonical compact JSON: {path}")
    return value, raw


def _safe_shard_path(manifest_path: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative:
        raise AuthorityError("manifest: shard path must be a non-empty string")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or "." in pure.parts:
        raise AuthorityError(f"manifest: unsafe shard path {relative!r}")
    if pure.as_posix() != relative or "\\" in relative:
        raise AuthorityError(f"manifest: shard path is not canonical POSIX {relative!r}")
    root = manifest_path.parent.resolve()
    candidate = (root / Path(*pure.parts)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise AuthorityError(f"manifest: shard escapes authority root {relative!r}") from exc
    return candidate


def _require_exact_keys(value: Mapping[str, Any], want: set[str], label: str) -> None:
    got = set(value)
    if got != want:
        raise AuthorityError(
            f"{label}: closed keys differ missing={sorted(want - got)!r} "
            f"extra={sorted(got - want)!r}"
        )


def _require_int(value: Any, label: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise AuthorityError(f"{label}: expected integer >= {minimum}")
    return value


def _require_sha(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(ch not in "0123456789abcdef" for ch in value)
    ):
        raise AuthorityError(f"{label}: expected lowercase SHA-256 hex")
    return value


def load_manifest(path: Path, *, pin_fixed_authority: bool = True) -> Dict[str, Any]:
    """Load and structurally validate a canonical manifest (not its shards)."""
    manifest, _raw = _load_canonical_object(path, label="manifest")
    _require_exact_keys(manifest, _MANIFEST_KEYS, "manifest")
    if manifest["format"] != MANIFEST_FORMAT or manifest["version"] != VERSION:
        raise AuthorityError("manifest: format/version mismatch")
    if manifest["expanded_format"] != EXPANDED_FORMAT:
        raise AuthorityError("manifest: expanded format mismatch")
    count = _require_int(manifest["expanded_vector_count"], "manifest.vector_count")
    neg_count = _require_int(
        manifest["expanded_negative_count"], "manifest.negative_count"
    )
    for key in (
        "expanded_content_sha256",
        "expanded_order_sha256",
        "expanded_negative_sha256",
        "expanded_canonical_sha256",
    ):
        _require_sha(manifest[key], f"manifest.{key}")
    limit = _require_int(manifest["max_shard_bytes"], "manifest.max_shard_bytes", minimum=1)
    if limit > MAX_SHARD_BYTES:
        raise AuthorityError(
            f"manifest: max_shard_bytes {limit} exceeds hard cap {MAX_SHARD_BYTES}"
        )
    top = manifest["top_level"]
    if not isinstance(top, dict) or "vectors" in top:
        raise AuthorityError("manifest: top_level must be an object without vectors")
    key_order = manifest["expanded_key_order"]
    if (
        not isinstance(key_order, list)
        or not all(isinstance(key, str) for key in key_order)
        or len(set(key_order)) != len(key_order)
        or set(key_order) != set(top) | {"vectors"}
    ):
        raise AuthorityError("manifest: expanded_key_order is not an exact unique key set")
    shards = manifest["shards"]
    if not isinstance(shards, list) or not shards:
        raise AuthorityError("manifest: shards must be a non-empty array")
    if pin_fixed_authority:
        fixed = {
            "expanded_vector_count": EXPANDED_VECTOR_COUNT,
            "expanded_content_sha256": EXPANDED_CONTENT_SHA256,
            "expanded_order_sha256": EXPANDED_ORDER_SHA256,
            "expanded_negative_count": EXPANDED_NEGATIVE_COUNT,
            "expanded_negative_sha256": EXPANDED_NEGATIVE_SHA256,
            "expanded_canonical_sha256": EXPANDED_CANONICAL_SHA256,
        }
        for key, want in fixed.items():
            if manifest[key] != want:
                raise AuthorityError(
                    f"manifest: {key} {manifest[key]!r} != fixed authority {want!r}"
                )
        if count != EXPANDED_VECTOR_COUNT or neg_count != EXPANDED_NEGATIVE_COUNT:
            raise AuthorityError("manifest: fixed count mismatch")
    return manifest


def iter_vectors(
    path: Path, *, pin_fixed_authority: bool = True
) -> Iterator[Dict[str, Any]]:
    """Yield validated vectors in global order while retaining one shard at a time."""
    manifest = load_manifest(path, pin_fixed_authority=pin_fixed_authority)
    expected_start = 0
    seen_paths: set[str] = set()
    order = hashlib.sha256()
    negative = hashlib.sha256()
    negative.update(b"[")
    negative_count = 0
    first_negative = True
    limit = int(manifest["max_shard_bytes"])

    for shard_index, entry in enumerate(manifest["shards"]):
        label = f"manifest.shards[{shard_index}]"
        if not isinstance(entry, dict):
            raise AuthorityError(f"{label}: entry is not an object")
        _require_exact_keys(entry, _SHARD_ENTRY_KEYS, label)
        relative = entry["path"]
        if relative in seen_paths:
            raise AuthorityError(f"{label}: duplicate path {relative!r}")
        seen_paths.add(relative)
        shard_path = _safe_shard_path(path, relative)
        shard, raw = _load_canonical_object(shard_path, label=label)
        if len(raw) > limit or len(raw) > MAX_SHARD_BYTES:
            raise AuthorityError(f"{label}: shard is too large ({len(raw)} bytes)")
        if entry["bytes"] != len(raw):
            raise AuthorityError(f"{label}: byte length mismatch")
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise AuthorityError(f"{label}: raw SHA-256 mismatch")
        _require_exact_keys(shard, _SHARD_KEYS, label)
        if shard["format"] != SHARD_FORMAT or shard["version"] != VERSION:
            raise AuthorityError(f"{label}: shard format/version mismatch")
        start = _require_int(shard["start"], f"{label}.start")
        count = _require_int(shard["count"], f"{label}.count", minimum=1)
        vectors = shard["vectors"]
        if not isinstance(vectors, list) or len(vectors) != count:
            raise AuthorityError(f"{label}: vectors/count mismatch")
        if (
            entry["start"] != start
            or entry["count"] != count
            or start != expected_start
        ):
            raise AuthorityError(f"{label}: non-contiguous start/count")
        first_id = vectors[0].get("id") if isinstance(vectors[0], dict) else None
        last_id = vectors[-1].get("id") if isinstance(vectors[-1], dict) else None
        if entry["first_id"] != first_id or entry["last_id"] != last_id:
            raise AuthorityError(f"{label}: first/last id mismatch")
        for local_index, vector in enumerate(vectors):
            if not isinstance(vector, dict):
                raise AuthorityError(f"{label}.vectors[{local_index}]: not an object")
            global_index = start + local_index
            if global_index:
                order.update(b"\n")
            order.update(order_row(global_index, vector))
            if vector.get("positive") is False:
                if not first_negative:
                    negative.update(b",")
                negative.update(
                    json.dumps(
                        negative_projection(vector),
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                first_negative = False
                negative_count += 1
            yield vector
        expected_start += count
        del vectors, shard, raw

    negative.update(b"]")
    if expected_start != manifest["expanded_vector_count"]:
        raise AuthorityError("manifest: expanded vector count does not match shards")
    if order.hexdigest() != manifest["expanded_order_sha256"]:
        raise AuthorityError("manifest: expanded order SHA-256 mismatch")
    if negative_count != manifest["expanded_negative_count"]:
        raise AuthorityError("manifest: expanded negative count mismatch")
    if negative.hexdigest() != manifest["expanded_negative_sha256"]:
        raise AuthorityError("manifest: expanded negative SHA-256 mismatch")


def _stream_object_hash(
    key_order: Sequence[str],
    top: Mapping[str, Any],
    vectors: Sequence[Mapping[str, Any]] | Iterator[Mapping[str, Any]],
    *,
    sorted_values: bool,
    trailing_lf: bool,
) -> str:
    digest = hashlib.sha256()
    digest.update(b"{")
    for key_index, key in enumerate(key_order):
        if key_index:
            digest.update(b",")
        key_raw = (
            stable_bytes(key)
            if sorted_values
            else json.dumps(key, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        )
        digest.update(key_raw)
        digest.update(b":")
        if key == "vectors":
            digest.update(b"[")
            for vector_index, vector in enumerate(vectors):
                if vector_index:
                    digest.update(b",")
                digest.update(
                    stable_bytes(vector)
                    if sorted_values
                    else json.dumps(
                        vector, ensure_ascii=False, separators=(",", ":")
                    ).encode("utf-8")
                )
            digest.update(b"]")
        else:
            value = top[key]
            digest.update(
                stable_bytes(value)
                if sorted_values
                else json.dumps(
                    value, ensure_ascii=False, separators=(",", ":")
                ).encode("utf-8")
            )
    digest.update(b"}")
    if trailing_lf:
        digest.update(b"\n")
    return digest.hexdigest()


def _stream_expanded_hashes(
    manifest: Mapping[str, Any], vectors: Sequence[Mapping[str, Any]]
) -> Tuple[str, str]:
    """Compute expanded hashes vector-by-vector (no monolithic serialization)."""
    top = manifest["top_level"]
    content_keys = sorted(
        set(key for key in top if key != "content_sha256") | {"vectors"}
    )
    content_sha = _stream_object_hash(
        content_keys, top, vectors, sorted_values=True, trailing_lf=False
    )
    canonical_sha = _stream_object_hash(
        manifest["expanded_key_order"],
        top,
        vectors,
        sorted_values=False,
        trailing_lf=True,
    )
    return content_sha, canonical_sha


def load_expanded(
    path: Path, *, pin_fixed_authority: bool = True
) -> Dict[str, Any]:
    """Load a manifest authority as its original expanded document.

    Legacy expanded JSON is accepted for mutation/self-test inputs.  A legacy
    input receives canonical and semantic verification only when
    ``pin_fixed_authority`` is true.
    """
    try:
        probe_raw = path.read_bytes()
        probe = json.loads(probe_raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorityError(f"authority: unreadable/malformed {path}: {exc}") from exc
    if not isinstance(probe, dict):
        raise AuthorityError("authority: root is not an object")
    if probe.get("format") != MANIFEST_FORMAT:
        if pin_fixed_authority:
            if probe_raw != canonical_bytes(probe):
                raise AuthorityError("authority: legacy expanded JSON is not canonical")
            pins = compute_semantic_pins(probe.get("vectors", []))
            if (
                probe.get("format") != EXPANDED_FORMAT
                or pins["vector_count"] != EXPANDED_VECTOR_COUNT
                or probe.get("content_sha256") != EXPANDED_CONTENT_SHA256
                or compute_content_sha256(probe) != EXPANDED_CONTENT_SHA256
                or pins["order_sha256"] != EXPANDED_ORDER_SHA256
                or pins["negative_count"] != EXPANDED_NEGATIVE_COUNT
                or pins["negative_sha256"] != EXPANDED_NEGATIVE_SHA256
                or hashlib.sha256(probe_raw).hexdigest()
                != EXPANDED_CANONICAL_SHA256
            ):
                raise AuthorityError("authority: legacy expanded fixed pins mismatch")
        return probe

    manifest = load_manifest(path, pin_fixed_authority=pin_fixed_authority)
    vectors = list(iter_vectors(path, pin_fixed_authority=pin_fixed_authority))
    top = manifest["top_level"]
    doc = {
        key: (vectors if key == "vectors" else top[key])
        for key in manifest["expanded_key_order"]
    }
    content_sha, canonical_sha = _stream_expanded_hashes(manifest, vectors)
    if content_sha != manifest["expanded_content_sha256"]:
        raise AuthorityError("manifest: expanded content SHA-256 mismatch")
    if canonical_sha != manifest["expanded_canonical_sha256"]:
        raise AuthorityError("manifest: expanded canonical SHA-256 mismatch")
    if doc.get("content_sha256") != content_sha:
        raise AuthorityError("manifest: top-level content_sha256 mismatch")
    return doc


def verify_streaming(
    path: Path, *, pin_fixed_authority: bool = True
) -> Dict[str, Any]:
    """Verify every manifest/shard/expanded pin without retaining all vectors."""
    manifest = load_manifest(path, pin_fixed_authority=pin_fixed_authority)
    top = manifest["top_level"]
    content_keys = sorted(
        set(key for key in top if key != "content_sha256") | {"vectors"}
    )
    content_sha = _stream_object_hash(
        content_keys,
        top,
        iter_vectors(path, pin_fixed_authority=pin_fixed_authority),
        sorted_values=True,
        trailing_lf=False,
    )
    if content_sha != manifest["expanded_content_sha256"]:
        raise AuthorityError("manifest: streaming expanded content SHA-256 mismatch")
    if top.get("content_sha256") != content_sha:
        raise AuthorityError("manifest: top-level content_sha256 mismatch")
    canonical_sha = _stream_object_hash(
        manifest["expanded_key_order"],
        top,
        iter_vectors(path, pin_fixed_authority=pin_fixed_authority),
        sorted_values=False,
        trailing_lf=True,
    )
    if canonical_sha != manifest["expanded_canonical_sha256"]:
        raise AuthorityError("manifest: streaming expanded canonical SHA-256 mismatch")
    return manifest


def _stage_ranges(count: int) -> List[Tuple[int, int, str]]:
    if count < 283:
        return [(0, count, "legacy")]
    ranges = [(0, 94, "d3s1"), (94, 144, "d3s2"), (144, 283, "d3s3")]
    if count > 283:
        ranges.append((283, count, "d3s4"))
    return ranges


def _partition_vectors(
    vectors: Sequence[Mapping[str, Any]], target_bytes: int
) -> List[Tuple[int, int, str, int]]:
    """Return deterministic sequential stage slices under ``target_bytes``."""
    result: List[Tuple[int, int, str, int]] = []
    vector_sizes = [
        len(
            json.dumps(
                vector, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        )
        for vector in vectors
    ]

    def shard_size(start: int, count: int, vector_bytes: int) -> int:
        prefix = (
            f'{{"format":"{SHARD_FORMAT}","version":{VERSION},'
            f'"start":{start},"count":{count},"vectors":['
        ).encode("utf-8")
        # commas between vectors + closing array/object + LF
        return len(prefix) + vector_bytes + max(0, count - 1) + 3

    for stage_start, stage_end, stage in _stage_ranges(len(vectors)):
        start = stage_start
        slice_index = 0
        while start < stage_end:
            end = start
            payload_bytes = 0
            while end < stage_end:
                next_payload = payload_bytes + vector_sizes[end]
                candidate_size = shard_size(
                    start, end - start + 1, next_payload
                )
                if end > start and candidate_size > target_bytes:
                    break
                if candidate_size > MAX_SHARD_BYTES:
                    raise AuthorityError(
                        f"vector {start} cannot fit hard shard cap {MAX_SHARD_BYTES}"
                    )
                payload_bytes = next_payload
                end += 1
            result.append((start, end, stage, slice_index))
            start = end
            slice_index += 1
    return result


def write_sharded(
    manifest_path: Path,
    doc: Mapping[str, Any],
    *,
    pin_fixed_authority: bool = True,
    target_shard_bytes: int = TARGET_SHARD_BYTES,
    _fault_point: str | None = None,
) -> Dict[str, Any]:
    """Crash-consistently publish a manifest and content-addressed shard generation.

    Shards are installed first under ``<stem>.d/<expanded-canonical-sha>/``.
    The manifest is then the sole atomic visibility point.  A crash before its
    ``os.replace`` leaves the old manifest fully usable; a crash after it leaves
    the new immutable generation fully usable.  Old generations are retained so
    a concurrent reader that already opened the old manifest cannot lose shards.
    ``_fault_point`` is private fault-injection surface for the permanent test.
    """
    if not isinstance(doc, Mapping) or not isinstance(doc.get("vectors"), list):
        raise AuthorityError("write: expanded document/vectors missing")
    vectors: List[Mapping[str, Any]] = doc["vectors"]
    pins = compute_semantic_pins(vectors)
    content_sha = compute_content_sha256(doc)
    top = {key: value for key, value in doc.items() if key != "vectors"}
    canonical_sha = _stream_object_hash(
        list(doc.keys()), top, vectors, sorted_values=False, trailing_lf=True
    )
    if doc.get("content_sha256") != content_sha:
        raise AuthorityError("write: content_sha256 field mismatch")
    if pin_fixed_authority:
        got = (
            len(vectors),
            content_sha,
            pins["order_sha256"],
            pins["negative_count"],
            pins["negative_sha256"],
            canonical_sha,
        )
        want = (
            EXPANDED_VECTOR_COUNT,
            EXPANDED_CONTENT_SHA256,
            EXPANDED_ORDER_SHA256,
            EXPANDED_NEGATIVE_COUNT,
            EXPANDED_NEGATIVE_SHA256,
            EXPANDED_CANONICAL_SHA256,
        )
        if got != want:
            raise AuthorityError(f"write: fixed semantic pins mismatch got={got!r}")
    if target_shard_bytes <= 0 or target_shard_bytes > MAX_SHARD_BYTES:
        raise AuthorityError("write: target shard size is outside hard cap")

    stem = manifest_path.name[:-5] if manifest_path.name.endswith(".json") else manifest_path.name
    generation_id = canonical_sha
    final_container = manifest_path.parent / f"{stem}.d"
    final_generation = final_container / generation_id
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(
        tempfile.mkdtemp(prefix=f".{stem}.authority-", dir=manifest_path.parent)
    )
    temp_container = temp_root / f"{stem}.d"
    temp_generation = temp_container / generation_id
    temp_generation.mkdir(parents=True)
    installed_generation = False
    published_manifest = False
    try:
        entries: List[Dict[str, Any]] = []
        for ordinal, (start, end, stage, slice_index) in enumerate(
            _partition_vectors(vectors, target_shard_bytes)
        ):
            shard = {
                "format": SHARD_FORMAT,
                "version": VERSION,
                "start": start,
                "count": end - start,
                "vectors": vectors[start:end],
            }
            raw = canonical_bytes(shard)
            name = f"{ordinal:03d}-{stage}-slice-{slice_index:02d}.json"
            shard_path = temp_generation / name
            shard_path.write_bytes(raw)
            entries.append(
                {
                    "path": f"{stem}.d/{generation_id}/{name}",
                    "stage": stage,
                    "slice": slice_index,
                    "start": start,
                    "count": end - start,
                    "bytes": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "first_id": vectors[start].get("id"),
                    "last_id": vectors[end - 1].get("id"),
                }
            )
        manifest: Dict[str, Any] = {
            "format": MANIFEST_FORMAT,
            "version": VERSION,
            "expanded_format": doc.get("format"),
            "expanded_vector_count": len(vectors),
            "expanded_content_sha256": content_sha,
            "expanded_order_sha256": pins["order_sha256"],
            "expanded_negative_count": pins["negative_count"],
            "expanded_negative_sha256": pins["negative_sha256"],
            "expanded_canonical_sha256": canonical_sha,
            "expanded_key_order": list(doc.keys()),
            "max_shard_bytes": MAX_SHARD_BYTES,
            "top_level": {key: value for key, value in doc.items() if key != "vectors"},
            "shards": entries,
        }
        temp_manifest = temp_root / manifest_path.name
        temp_manifest.write_bytes(canonical_bytes(manifest))

        # Validate the staged tree with the same reader before publication.
        load_expanded(temp_manifest, pin_fixed_authority=pin_fixed_authority)

        final_container.mkdir(exist_ok=True)
        if final_generation.exists():
            staged_files = sorted(
                path.name for path in temp_generation.iterdir() if path.is_file()
            )
            existing_files = sorted(
                path.name for path in final_generation.iterdir() if path.is_file()
            )
            if staged_files != existing_files:
                raise AuthorityError(
                    "write: content-addressed generation file set collision"
                )
            for name in staged_files:
                if (
                    hashlib.sha256((temp_generation / name).read_bytes()).digest()
                    != hashlib.sha256((final_generation / name).read_bytes()).digest()
                ):
                    raise AuthorityError(
                        f"write: content-addressed generation collision at {name}"
                    )
        else:
            os.replace(temp_generation, final_generation)
            installed_generation = True
        if _fault_point == "after_generation_install":
            raise AuthorityError("self-test injected after-generation-install failure")

        # Sole visibility point: old manifest or complete new generation, never a
        # manifest that names a partially installed/missing shard directory.
        os.replace(temp_manifest, manifest_path)
        published_manifest = True
        if _fault_point == "after_manifest_replace":
            raise AuthorityError("self-test injected after-manifest-replace failure")
        return manifest
    except BaseException:
        # Ordinary exceptions roll back an unpublished generation.  A hard process
        # crash may leave the content-addressed directory orphaned, but the old
        # manifest remains consistent and a later identical publication can reuse it.
        if installed_generation and not published_manifest:
            shutil.rmtree(final_generation, ignore_errors=True)
            try:
                final_container.rmdir()
            except OSError:
                pass
        raise
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


__all__ = [
    "AuthorityError",
    "EXPANDED_CANONICAL_SHA256",
    "EXPANDED_CONTENT_SHA256",
    "EXPANDED_NEGATIVE_COUNT",
    "EXPANDED_NEGATIVE_SHA256",
    "EXPANDED_ORDER_SHA256",
    "EXPANDED_VECTOR_COUNT",
    "MANIFEST_FORMAT",
    "MAX_SHARD_BYTES",
    "canonical_bytes",
    "compute_content_sha256",
    "compute_semantic_pins",
    "iter_vectors",
    "load_expanded",
    "load_manifest",
    "negative_projection",
    "order_row",
    "verify_streaming",
    "write_sharded",
]


def _tree_snapshot(manifest_path: Path) -> Dict[str, str]:
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent
    manifest = load_manifest(manifest_path, pin_fixed_authority=True)
    paths = [manifest_path]
    paths.extend(
        _safe_shard_path(manifest_path, entry["path"])
        for entry in manifest["shards"]
    )
    return {
        str(path.resolve().relative_to(root)): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in paths
    }


def self_test(path: Path) -> None:
    """Determinism, atomic cleanup, and source-tree no-write regression test."""
    before = _tree_snapshot(path)
    verify_streaming(path, pin_fixed_authority=True)
    doc = load_expanded(path, pin_fixed_authority=True)
    with tempfile.TemporaryDirectory(prefix="ninlil-d3s4-authority-selftest-") as td:
        root = Path(td)
        output = root / "domain-scan-crossrow-v1.json"
        write_sharded(output, doc, pin_fixed_authority=True)
        first = _tree_snapshot(output)
        write_sharded(output, doc, pin_fixed_authority=True)
        second = _tree_snapshot(output)
        if first != second:
            raise AuthorityError("self-test: two-run output tree is not deterministic")
        if any(root.glob(".*.authority-*")):
            raise AuthorityError("self-test: successful publication left temp directory")

        # Failure after generation installation but before the manifest visibility
        # point rolls back cleanly (ordinary exception path).
        failure = root / "failure.json"
        try:
            write_sharded(
                failure,
                doc,
                pin_fixed_authority=True,
                _fault_point="after_generation_install",
            )
        except AuthorityError as exc:
            if "after-generation-install" not in str(exc):
                raise
        else:
            raise AuthorityError("self-test: pre-manifest fault injection was green")
        if any(root.glob(".*.authority-*")):
            raise AuthorityError("self-test: failed publication left temp directory")
        if failure.exists() or (root / "failure.d").exists():
            raise AuthorityError("self-test: failed publication exposed partial authority")

        # Failure after the atomic manifest replace must leave a completely readable
        # authority, proving the manifest is the single visibility/commit point.
        committed = root / "committed.json"
        try:
            write_sharded(
                committed,
                doc,
                pin_fixed_authority=True,
                _fault_point="after_manifest_replace",
            )
        except AuthorityError as exc:
            if "after-manifest-replace" not in str(exc):
                raise
        else:
            raise AuthorityError("self-test: post-manifest fault injection was green")
        verify_streaming(committed, pin_fixed_authority=True)
        if any(root.glob(".*.authority-*")):
            raise AuthorityError("self-test: committed publication left temp directory")
    after = _tree_snapshot(path)
    if before != after:
        raise AuthorityError("self-test: source authority tree was mutated")


def _main(argv: List[str]) -> int:
    repo = Path(__file__).resolve().parents[1]
    default = repo / "spec" / "vectors" / "domain-scan-crossrow-v1.json"
    if len(argv) not in (1, 2) or argv[0] not in {"check", "self-test"}:
        print(
            f"error: usage: {Path(sys.argv[0]).name} check|self-test [manifest.json]",
            file=sys.stderr,
        )
        return 2
    authority = Path(argv[1]) if len(argv) == 2 else default
    try:
        if argv[0] == "check":
            manifest = verify_streaming(authority, pin_fixed_authority=True)
            print(
                "D3-S4 manifest authority OK "
                f"shards={len(manifest['shards'])} "
                f"vectors={manifest['expanded_vector_count']} "
                f"negatives={manifest['expanded_negative_count']}"
            )
        else:
            self_test(authority)
            print("D3-S4 manifest authority self-test OK")
        return 0
    except (AuthorityError, OSError, ValueError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
