"""Command-line interface for Ninlil HIL evidence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .model import (
    EvidenceError, canonical_json_bytes, load_json_file, validate_manifest
)
from .runner import inventory_receipt, run_campaign, safe_write, verify_run
from .selftest import run_self_test
from .templates import create_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 -m tools.ninlil_hil",
        description="Bounded Ninlil HIL evidence runner (does not promote ESP FULL)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="execute argv plugins and seal one run")
    run.add_argument("--manifest", required=True, type=Path)
    run.add_argument("--output-root", required=True, type=Path)
    run.add_argument(
        "--plugin-json",
        required=True,
        action="append",
        help='repeatable object: {"name":"x","argv":["program","arg"]}',
    )

    verify = subparsers.add_parser("verify", help="verify schema and SHA-256 inventory")
    verify.add_argument("--run-dir", required=True, type=Path)
    verify.add_argument(
        "--allow-failed",
        action="store_true",
        help="return success for an intact FAIL bundle (integrity inspection only)",
    )
    verify.add_argument(
        "--expected-receipt",
        help="caller-retained SHA-256 of inventory.json; binds verification to the run receipt",
    )

    validate = subparsers.add_parser("validate-manifest")
    validate.add_argument("--manifest", required=True, type=Path)

    template = subparsers.add_parser(
        "create-manifest", help="create a closed ESP storage campaign manifest"
    )
    template.add_argument(
        "--profile",
        required=True,
        choices=("esp-storage-atomic-v1", "esp-storage-namespace-v1"),
    )
    template.add_argument("--campaign-id", required=True)
    template.add_argument("--run-id", required=True)
    template.add_argument("--repository-commit", required=True)
    template.add_argument("--tree-state", required=True, choices=("clean", "dirty"))
    template.add_argument("--firmware-sha256", required=True)
    template.add_argument("--firmware-build-id", required=True)
    template.add_argument("--idf-version", required=True)
    template.add_argument(
        "--resource-json",
        required=True,
        action="append",
        help="repeatable resource object conforming to the manifest schema",
    )
    template.add_argument(
        "--requested",
        choices=("EVIDENCE_ONLY", "FULL_CANDIDATE_REVIEW"),
        default="EVIDENCE_ONLY",
    )
    template.add_argument(
        "--delay-ms",
        action="append",
        type=float,
        default=[],
        help="atomic profile only; repeat once for every planned sweep delay",
    )
    template.add_argument("--output", required=True, type=Path)

    subparsers.add_parser("self-test", help="offline positive and mutation tests")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            run_dir, verdict = run_campaign(
                args.manifest, args.output_root, args.plugin_json
            )
            print(
                json.dumps(
                    {
                        "run_dir": str(run_dir),
                        "inventory_receipt_sha256": inventory_receipt(run_dir),
                        "status": verdict["status"],
                        "evidence_complete": verdict["evidence_complete"],
                        "full_promotion_permitted": False,
                        "runtime_policy": "ESP_UNPROVEN",
                    },
                    sort_keys=True,
                )
            )
            return 0 if verdict["status"] == "PASS" else 2
        if args.command == "verify":
            verdict = verify_run(args.run_dir, args.expected_receipt)
            print(
                json.dumps(
                    {
                        "status": verdict["status"],
                        "evidence_complete": verdict["evidence_complete"],
                        "full_promotion_permitted": False,
                        "runtime_policy": "ESP_UNPROVEN",
                    },
                    sort_keys=True,
                )
            )
            return 0 if verdict["status"] == "PASS" or args.allow_failed else 2
        if args.command == "validate-manifest":
            manifest = validate_manifest(load_json_file(args.manifest))
            print(
                json.dumps(
                    {
                        "schema": manifest["schema"],
                        "campaign_id": manifest["campaign_id"],
                        "run_id": manifest["run_id"],
                        "valid": True,
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "create-manifest":
            try:
                resources = [json.loads(raw) for raw in args.resource_json]
            except json.JSONDecodeError as error:
                raise EvidenceError(f"resource JSON is invalid: {error}") from error
            if args.profile == "esp-storage-atomic-v1" and not args.delay_ms:
                raise EvidenceError("atomic manifest requires at least one --delay-ms")
            if args.profile == "esp-storage-namespace-v1" and args.delay_ms:
                raise EvidenceError("namespace manifest does not accept --delay-ms")
            manifest = create_manifest(
                profile=args.profile,
                campaign_id=args.campaign_id,
                run_id=args.run_id,
                repository_commit=args.repository_commit,
                tree_state=args.tree_state,
                firmware_sha256=args.firmware_sha256,
                firmware_build_id=args.firmware_build_id,
                idf_version=args.idf_version,
                resources=resources,
                requested=args.requested,
                delays_ms=args.delay_ms,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            safe_write(args.output, canonical_json_bytes(manifest))
            print(json.dumps({"manifest": str(args.output), "valid": True}))
            return 0
        if args.command == "self-test":
            run_self_test()
            return 0
    except EvidenceError as error:
        print(f"ninlil_hil: {error}", file=sys.stderr)
        return 2
    except OSError as error:
        filename = error.filename if isinstance(error.filename, str) else "filesystem"
        print(
            f"ninlil_hil: filesystem/process operation failed for {filename}",
            file=sys.stderr,
        )
        return 2
    parser.error("unknown command")
    return 2
