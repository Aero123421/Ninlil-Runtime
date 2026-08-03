#!/usr/bin/env python3
"""Run MFDT Host acceptance binaries without accepting crash/link REDs.

The checked-in manifest names every behavioral witness.  In ``red`` mode a
binary must execute normally, report every named witness, and fail at least one
named witness.  In ``green`` mode every witness and process must pass.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--build-dir",
        type=Path,
        required=True,
        help="CMake build directory containing acceptance executables",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        required=True,
        help="JSON manifest of executable names and behavioral witnesses",
    )
    parser.add_argument(
        "--mode",
        choices=("red", "green"),
        default="green",
    )
    return parser.parse_args()


def load_manifest(path: Path) -> list[dict[str, Any]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read manifest {path}: {error}") from error
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ValueError("manifest schema must be exactly 1")
    binaries = document.get("binaries")
    if not isinstance(binaries, list) or not binaries:
        raise ValueError("manifest binaries must be a non-empty array")
    for entry in binaries:
        if not isinstance(entry, dict):
            raise ValueError("each binary entry must be an object")
        if not isinstance(entry.get("name"), str) or not entry["name"]:
            raise ValueError("each binary needs a non-empty name")
        witnesses = entry.get("witnesses")
        if (
            not isinstance(witnesses, list)
            or not witnesses
            or not all(isinstance(item, str) and item for item in witnesses)
            or len(witnesses) != len(set(witnesses))
        ):
            raise ValueError(
                f"{entry['name']}: witnesses must be unique non-empty strings"
            )
    return binaries


def executable_path(build_dir: Path, name: str) -> Path:
    candidate = build_dir / name
    if os.name == "nt":
        candidate = candidate.with_suffix(".exe")
    return candidate


def run_binary(
    build_dir: Path,
    entry: dict[str, Any],
    mode: str,
) -> tuple[bool, bool]:
    name = entry["name"]
    path = executable_path(build_dir, name)
    if not path.is_file():
        print(
            f"ACCEPTANCE_INFRA_FAIL {name}: executable missing: {path}",
            file=sys.stderr,
        )
        return False, False
    try:
        completed = subprocess.run(
            [str(path)],
            cwd=build_dir,
            check=False,
            capture_output=True,
            text=True,
            timeout=entry.get("timeout_seconds", 120),
        )
    except subprocess.TimeoutExpired:
        print(
            f"ACCEPTANCE_INFRA_FAIL {name}: timeout",
            file=sys.stderr,
        )
        return False, False
    except OSError as error:
        print(
            f"ACCEPTANCE_INFRA_FAIL {name}: execution failed: {error}",
            file=sys.stderr,
        )
        return False, False

    combined = completed.stdout + completed.stderr
    if completed.returncode < 0:
        print(
            f"ACCEPTANCE_INFRA_FAIL {name}: crashed by signal "
            f"{-completed.returncode}",
            file=sys.stderr,
        )
        print(combined, file=sys.stderr, end="")
        return False, False

    missing: list[str] = []
    failed: list[str] = []
    for witness in entry["witnesses"]:
        passed_marker = f"WITNESS_PASS {witness}"
        failed_marker = f"WITNESS_FAIL {witness}"
        has_pass = passed_marker in combined
        has_fail = failed_marker in combined
        if has_pass == has_fail:
            missing.append(witness)
        elif has_fail:
            failed.append(witness)

    if missing:
        print(
            f"ACCEPTANCE_INFRA_FAIL {name}: missing/ambiguous witnesses: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        print(combined, file=sys.stderr, end="")
        return False, bool(failed)

    if mode == "green":
        ok = completed.returncode == 0 and not failed
    else:
        # A RED campaign may contain already-green independent binaries.  Each
        # process still has to agree with its named witness results, and the
        # aggregate check below requires at least one behavioral RED.
        ok = (
            (completed.returncode != 0 and bool(failed))
            or (completed.returncode == 0 and not failed)
        )
    if not ok:
        print(
            f"ACCEPTANCE_{mode.upper()}_FAIL {name}: "
            f"rc={completed.returncode} failed={','.join(failed) or 'none'}",
            file=sys.stderr,
        )
        print(combined, file=sys.stderr, end="")
        return False, bool(failed)

    print(
        f"ACCEPTANCE_{mode.upper()}_PASS {name}: "
        f"witnesses={len(entry['witnesses'])} "
        f"failed={len(failed)}"
    )
    return True, bool(failed)


def main() -> int:
    args = parse_args()
    try:
        binaries = load_manifest(args.manifest)
    except ValueError as error:
        print(f"ACCEPTANCE_INFRA_FAIL: {error}", file=sys.stderr)
        return 2

    all_ok = True
    any_behavioral_red = False
    for entry in binaries:
        ok, had_red = run_binary(args.build_dir, entry, args.mode)
        all_ok = all_ok and ok
        any_behavioral_red = any_behavioral_red or had_red
    if args.mode == "red" and not any_behavioral_red:
        print(
            "ACCEPTANCE_RED_FAIL: no named behavioral RED was observed",
            file=sys.stderr,
        )
        return 1
    if not all_ok:
        return 1
    print(
        f"MFDT_HOST_ACCEPTANCE_{args.mode.upper()} "
        f"binaries={len(binaries)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
