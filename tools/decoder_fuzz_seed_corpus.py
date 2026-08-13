#!/usr/bin/env python3
"""Generate deterministic libFuzzer seed corpora from existing Ninlil KATs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "nfl1_codec",
    "rrmp_codec",
    "r7_wire_codec",
    "r7_frag_wire",
    "n6_record_codec",
    "domain_store_body_codec",
)

# Selector order is the switch authority in domain_store_body_codec_fuzzer.c.
# Each row is one production body decoder and one checked-in positive DSB KAT.
DOMAIN_BODY_DECODER_SEEDS = (
    ("internal_invariant", "DSB1_INV_ENCODE_DECODE", 0x01, 0),
    ("bearer_state", "DSB1_BEARER_ENCODE_DECODE", 0x60, 0),
    ("clock_baseline", "DSB1_CLOCK_UNINIT_POSITIVE", 0x62, 0),
    ("attempt_reuse_fence", "DSB1_FENCE_MIN_POSITIVE", 0x64, 0),
    ("witness_head_index", "DSB1_HEAD_BASELINE_POSITIVE", 0x7D, 0),
    ("service", "DSB2_SERVICE_DS_POSITIVE", 0x10, 0),
    ("service_quota", "DSB2_QUOTA_POSITIVE", 0x11, 0),
    ("transaction_anchor", "DSB2_ANCHOR_DS_POSITIVE", 0x20, 0),
    ("transaction_sequence_index", "DSB2_SEQ_POSITIVE", 0x21, 0),
    ("transaction_state", "DSB2_STATE_POSITIVE", 0x22, 0),
    ("reservation", "DSB2_RES_TX_POSITIVE", 0x23, 0),
    ("idempotency_map", "DSB2_IDEM_POSITIVE", 0x24, 0),
    ("event_id_map", "DSB2_EVMAP_POSITIVE", 0x25, 0),
    ("scheduler_owner", "DSB3_SCHED_TX_POSITIVE", 0x26, 0),
    ("ordered_ingress", "DSB3_ING_APP_DS_EMPTY", 0x27, 0),
    ("blob_manifest", "DSB3_BLOB_MAN_TX_CMD", 0x30, 1),
    ("blob_chunk", "DSB3_BLOB_CHK_SINGLE", 0x30, 2),
    ("attempt", "DSB3_ATT_TX_CMD_PREP", 0x31, 0),
    ("attempt_id_index", "DSB3_AII_CMD_BODY", 0x34, 0),
    ("cancel_state", "DSB3_CS_TX_NONE", 0x33, 0),
    ("evidence_cell", "DSB3_EV_TX_SUM_EMPTY", 0x32, 0),
    ("delivery", "DSB3_DLV_APP_EF", 0x40, 0),
    ("result_cache", "DSB3_RC_INBOX_VIRGIN", 0x41, 0),
    ("reverse_reply", "DSB3_RR_KIND_RECEIPT", 0x42, 0),
    ("event_spool", "DSB3_ES_ACTIVE", 0x50, 0),
    ("retry_summary", "DSB3_RS_CUM_T0", 0x51, 0),
    ("management_ledger", "DSB3_ML_R_RSN1", 0x52, 0),
    ("retention_basis", "DSB3_RB_TX_ACTIVE_PENDING", 0x61, 0),
    ("cleanup_plan", "DSB3_CP_TX_P1_FULL", 0x63, 0),
)


class CorpusError(RuntimeError):
    """Corpus authority mismatch."""


@dataclass(frozen=True)
class Seed:
    target: str
    name: str
    origin: str
    data: bytes
    decoder: str = ""


def _load_json(relative: str) -> dict:
    with (ROOT / relative).open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise CorpusError(f"{relative}: top-level JSON must be an object")
    return value


def _bytes_from_hex(origin: str, value: object) -> bytes:
    if not isinstance(value, str) or len(value) % 2 != 0:
        raise CorpusError(f"{origin}: expected even-length hex string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise CorpusError(f"{origin}: invalid hex") from exc


def _safe_name(value: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    if not name:
        raise CorpusError("empty seed filename")
    return name


def _n6_kat_seeds() -> list[Seed]:
    relative = "tests/radio/n6_record_codec_test.c"
    text = (ROOT / relative).read_text(encoding="utf-8")
    found: dict[str, str] = {}
    pattern = re.compile(
        r"static const char \*const HEX_([A-Z]+)\s*=\s*"
        r"((?:\"[0-9a-fA-F]*\"\s*)+);"
    )
    for match in pattern.finditer(text):
        found[match.group(1)] = "".join(
            re.findall(r'\"([0-9a-fA-F]*)\"', match.group(2))
        )
    order = ("LK", "TX", "RX", "HWK", "HWV", "ALK", "ALV", "RTK", "RTV", "CFK", "CFV")
    if tuple(name for name in order if name in found) != order:
        raise CorpusError(f"{relative}: exact 11 independent HEX_* KATs are required")
    return [
        Seed(
            "n6_record_codec",
            f"{index:02d}-{name.lower()}",
            f"{relative}:HEX_{name}",
            bytes((index,)) + _bytes_from_hex(f"{relative}:HEX_{name}", found[name]),
        )
        for index, name in enumerate(order)
    ]


def _vector_seeds() -> list[Seed]:
    seeds: list[Seed] = []

    fabric_path = "spec/vectors/fabric-bearer-spec-v1.json"
    fabric = _load_json(fabric_path)
    positives = fabric.get("nfl1_positive_vectors")
    if not isinstance(positives, list) or len(positives) < 3:
        raise CorpusError(f"{fabric_path}: at least three NFL1 positives required")
    for index, row in enumerate(positives[:3]):
        if not isinstance(row, dict):
            raise CorpusError(f"{fabric_path}: NFL1 row {index} is not an object")
        row_id = _safe_name(str(row.get("id", f"positive-{index}")))
        seeds.append(Seed(
            "nfl1_codec",
            row_id,
            f"{fabric_path}:nfl1_positive_vectors[{index}].encoded_hex",
            _bytes_from_hex(f"{fabric_path}:{row_id}", row.get("encoded_hex")),
        ))

    rrmp_path = "spec/vectors/route-relay-multiparent-spec-v1.json"
    rrmp = _load_json(rrmp_path)
    fixtures = rrmp.get("fixtures")
    if not isinstance(fixtures, dict):
        raise CorpusError(f"{rrmp_path}: fixtures object missing")
    seeds.append(Seed(
        "rrmp_codec",
        "nrm1-1hop",
        f"{rrmp_path}:fixtures.nrm1_1hop_hex",
        _bytes_from_hex(f"{rrmp_path}:nrm1_1hop_hex", fixtures.get("nrm1_1hop_hex")),
    ))

    r7_path = "spec/vectors/r7-radio-wire-v1.json"
    r7 = _load_json(r7_path)
    vectors = r7.get("vectors")
    if not isinstance(vectors, list):
        raise CorpusError(f"{r7_path}: vectors array missing")
    wire_kinds = {"outer_data", "e2e_single"}
    frag_kinds = {
        "e2e_frag_start", "e2e_frag_cont", "e2e_frag_ack", "outer_link_ack"
    }
    seen_frag: set[str] = set()
    for index, row in enumerate(vectors):
        if not isinstance(row, dict):
            continue
        kind = row.get("kind")
        row_id = _safe_name(str(row.get("id", f"vector-{index}")))
        if kind in wire_kinds and isinstance(row.get("aad"), str):
            seeds.append(Seed(
                "r7_wire_codec",
                row_id,
                f"{r7_path}:vectors[{index}].aad",
                _bytes_from_hex(f"{r7_path}:{row_id}.aad", row["aad"]),
            ))
        if kind in frag_kinds and kind not in seen_frag and isinstance(row.get("plaintext"), str):
            seen_frag.add(str(kind))
            seeds.append(Seed(
                "r7_frag_wire",
                row_id,
                f"{r7_path}:vectors[{index}].plaintext",
                _bytes_from_hex(f"{r7_path}:{row_id}.plaintext", row["plaintext"]),
                {
                    "e2e_frag_start": "0",
                    "e2e_frag_cont": "1",
                    "e2e_frag_ack": "2",
                    "outer_link_ack": "3",
                }[str(kind)],
            ))
    if not wire_kinds.issubset({row.get("kind") for row in vectors if isinstance(row, dict)}):
        raise CorpusError(f"{r7_path}: outer_data/e2e_single seed vectors missing")
    if seen_frag != frag_kinds:
        raise CorpusError(
            f"{r7_path}: exact FRAG start/cont/ACK/LINK_ACK seeds missing")

    domain_path = "spec/vectors/domain-store-v1.json"
    domain = _load_json(domain_path)
    domain_vectors = domain.get("vectors")
    if not isinstance(domain_vectors, list):
        raise CorpusError(f"{domain_path}: vectors array missing")
    by_id = {
        str(row["id"]): (index, row)
        for index, row in enumerate(domain_vectors)
        if isinstance(row, dict) and isinstance(row.get("id"), str)
    }
    if len(DOMAIN_BODY_DECODER_SEEDS) != 29:
        raise CorpusError("Domain body decoder seed authority must contain 29 rows")
    for selector, (decoder, row_id, subtype, flags) in enumerate(
        DOMAIN_BODY_DECODER_SEEDS
    ):
        if row_id not in by_id:
            raise CorpusError(f"{domain_path}: required DSB KAT missing: {row_id}")
        index, row = by_id[row_id]
        if (
            row.get("op") != "body_roundtrip"
            or row.get("expected_status") != "OK"
            or row.get("subtype") != subtype
            or row.get("flags") != flags
            or not isinstance(row.get("body_hex"), str)
        ):
            raise CorpusError(f"{domain_path}:{row_id}: positive body authority drift")
        body = _bytes_from_hex(f"{domain_path}:{row_id}.body_hex", row["body_hex"])
        if not body or row.get("body_length") != len(body):
            raise CorpusError(f"{domain_path}:{row_id}: body length drift")
        seeds.append(Seed(
            "domain_store_body_codec",
            f"{selector:02d}-{_safe_name(decoder)}-{_safe_name(row_id)}",
            f"{domain_path}:vectors[{index}].body_hex",
            bytes((selector,)) + body,
            decoder,
        ))

    seeds.extend(_n6_kat_seeds())
    return seeds


def _regression_seeds() -> list[Seed]:
    base = ROOT / "tests/fuzz/regressions"
    seeds: list[Seed] = []
    for target in TARGETS:
        directory = base / target
        if not directory.is_dir():
            continue
        for path in sorted(directory.iterdir()):
            if path.is_file() and not path.name.startswith("."):
                seeds.append(Seed(
                    target,
                    f"regression-{_safe_name(path.name)}",
                    str(path.relative_to(ROOT)),
                    path.read_bytes(),
                ))
    return seeds


def expected() -> tuple[dict[Path, bytes], bytes]:
    files: dict[Path, bytes] = {}
    records: list[dict[str, object]] = []
    for seed in sorted(_vector_seeds() + _regression_seeds(), key=lambda item: (item.target, item.name)):
        if seed.target not in TARGETS:
            raise CorpusError(f"unknown target: {seed.target}")
        relative = Path(seed.target) / seed.name
        if relative in files:
            raise CorpusError(f"duplicate seed path: {relative}")
        files[relative] = seed.data
        record: dict[str, object] = {
            "bytes": len(seed.data),
            "origin": seed.origin,
            "path": relative.as_posix(),
            "sha256": hashlib.sha256(seed.data).hexdigest(),
        }
        if seed.decoder:
            record["decoder"] = seed.decoder
        records.append(record)
    present = {path.parts[0] for path in files}
    if present != set(TARGETS):
        raise CorpusError(f"seed targets mismatch: missing={sorted(set(TARGETS) - present)}")
    manifest = {
        "format": "ninlil-decoder-fuzz-seed-corpus-v1",
        "seed_count": len(records),
        "targets": list(TARGETS),
        "seeds": records,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    return files, manifest_bytes


def _safe_output(path: Path) -> Path:
    resolved = path.resolve()
    try:
        repository_relative = resolved.relative_to(ROOT)
    except ValueError:
        repository_relative = None
    if (
        repository_relative is not None
        and repository_relative.parts
        and (
            repository_relative.parts[0] == "build"
            or repository_relative.parts[0].startswith("build-")
        )
    ):
        return resolved

    temporary_roots = {
        Path(tempfile.gettempdir()).resolve(),
        Path("/tmp").resolve(),
        Path("/var/tmp").resolve(),
    }
    for temporary_root in temporary_roots:
        try:
            relative = resolved.relative_to(temporary_root)
        except ValueError:
            continue
        if relative.parts:
            return resolved
    raise CorpusError(
        "output must be below repository build* or a system temporary "
        f"directory: {resolved}"
    )


def generate(output: Path) -> None:
    output = _safe_output(output)
    files, manifest = expected()
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    for relative, data in files.items():
        path = output / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (output / "manifest.json").write_bytes(manifest)


def check(output: Path) -> None:
    output = _safe_output(output)
    files, manifest = expected()
    actual = {
        path.relative_to(output): path.read_bytes()
        for path in output.rglob("*")
        if path.is_file()
    } if output.is_dir() else {}
    wanted = dict(files)
    wanted[Path("manifest.json")] = manifest
    missing = sorted(str(path) for path in wanted.keys() - actual.keys())
    extra = sorted(str(path) for path in actual.keys() - wanted.keys())
    changed = sorted(str(path) for path in wanted.keys() & actual.keys() if wanted[path] != actual[path])
    if missing or extra or changed:
        raise CorpusError(f"corpus drift: missing={missing} extra={extra} changed={changed}")


def verify_reachability(domain_runner: Path, r7_runner: Path) -> None:
    runners = {
        "domain_store_body_codec": domain_runner.resolve(),
        "r7_frag_wire": r7_runner.resolve(),
    }
    for target, runner in runners.items():
        if not runner.is_file():
            raise CorpusError(f"{target}: reachability runner missing: {runner}")

    seeds = [seed for seed in _vector_seeds() if seed.decoder]
    domain = [seed for seed in seeds if seed.target == "domain_store_body_codec"]
    r7 = [seed for seed in seeds if seed.target == "r7_frag_wire"]
    if len(domain) != 29 or {seed.data[0] for seed in domain} != set(range(29)):
        raise CorpusError("Domain reachability requires exact selectors 0..28")
    if len(r7) != 4 or {seed.decoder for seed in r7} != {"0", "1", "2", "3"}:
        raise CorpusError("R7 reachability requires start/cont/ACK/LINK_ACK seeds")

    def run(
        seed: Seed, data: Optional[bytes] = None
    ) -> subprocess.CompletedProcess[bytes]:
        command = [str(runners[seed.target])]
        if seed.target == "r7_frag_wire":
            command.append(seed.decoder)
        return subprocess.run(
            command,
            input=seed.data if data is None else data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    for seed in domain + r7:
        completed = run(seed)
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise CorpusError(
                f"{seed.target}/{seed.name}: decoder {seed.decoder} "
                f"unreachable (rc={completed.returncode}): {detail}"
            )

    if run(domain[0], bytes((29,)) + domain[0].data[1:]).returncode == 0:
        raise CorpusError("Domain reachability runner accepted selector 29")
    ack = next(seed for seed in r7 if seed.decoder == "2")
    if run(ack, ack.data[:-1]).returncode == 0:
        raise CorpusError("R7 ACK reachability runner accepted a 13-byte ACK")
    link_ack = next(seed for seed in r7 if seed.decoder == "3")
    if run(link_ack, link_ack.data[:-1]).returncode == 0:
        raise CorpusError("R7 LINK_ACK reachability runner accepted a 15-byte body")


def self_test() -> None:
    for protected in (
        ROOT,
        ROOT / "tests",
        ROOT / "src",
        ROOT / ".git",
        ROOT / "builder" / "corpus",
        ROOT / "buildscripts" / "corpus",
    ):
        try:
            _safe_output(protected)
        except CorpusError:
            pass
        else:
            raise CorpusError(
                f"self-test false-green: protected output accepted: {protected}"
            )
    vector_seeds = _vector_seeds()
    domain = [
        seed for seed in vector_seeds
        if seed.target == "domain_store_body_codec"
    ]
    r7 = [seed for seed in vector_seeds if seed.target == "r7_frag_wire"]
    if len(domain) != 29 or [seed.data[0] for seed in domain] != list(range(29)):
        raise CorpusError("self-test false-green: Domain selectors are not exact 0..28")
    ack = [seed for seed in r7 if seed.decoder == "2"]
    if len(ack) != 1 or len(ack[0].data) != 14:
        raise CorpusError("self-test false-green: R7 FRAG_ACK is not exact 14 bytes")
    link_ack = [seed for seed in r7 if seed.decoder == "3"]
    if len(link_ack) != 1 or len(link_ack[0].data) != 16:
        raise CorpusError("self-test false-green: R7 LINK_ACK is not exact 16 bytes")
    _safe_output(ROOT / "build-fuzz-self-test" / "corpus")
    with tempfile.TemporaryDirectory(prefix="ninlil-decoder-fuzz-corpus-") as tmp:
        output = Path(tmp) / "corpus"
        generate(output)
        check(output)
        victim = next(path for path in sorted(output.rglob("*")) if path.is_file() and path.name != "manifest.json" and path.stat().st_size > 0)
        data = bytearray(victim.read_bytes())
        data[0] ^= 0x01
        victim.write_bytes(data)
        try:
            check(output)
        except CorpusError:
            pass
        else:
            raise CorpusError("self-test false-green: mutated seed was accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=("generate", "check", "self-test", "reachability")
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--domain-runner", type=Path)
    parser.add_argument("--r7-runner", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            if any((args.output, args.domain_runner, args.r7_runner)):
                raise CorpusError("self-test accepts no path options")
            self_test()
        elif args.command == "reachability":
            if args.output is not None:
                raise CorpusError("--output is not valid with reachability")
            if args.domain_runner is None or args.r7_runner is None:
                raise CorpusError(
                    "reachability requires --domain-runner and --r7-runner")
            verify_reachability(args.domain_runner, args.r7_runner)
        else:
            if args.domain_runner is not None or args.r7_runner is not None:
                raise CorpusError("runner options are valid only with reachability")
            if args.output is None:
                raise CorpusError(f"{args.command} requires --output")
            if args.command == "generate":
                generate(args.output)
            else:
                check(args.output)
    except CorpusError as exc:
        print(f"decoder fuzz seed corpus: ERROR: {exc}")
        return 1
    print(f"decoder fuzz seed corpus: {args.command} OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
