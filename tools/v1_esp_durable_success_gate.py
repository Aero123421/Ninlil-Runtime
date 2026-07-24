#!/usr/bin/env python3
"""V1-LAB ESP durable FULL success structural prohibition gate (unit 1c / P0-5).

Without power-cut HIL attestation, ESP dual-slot storage must not link or
source-export paths that admit FULL/custody success. Host conformance may use
FULL_HOST_MODEL; ESP target must stay ESP_UNPROVEN / COMMIT_UNKNOWN only.

Usage:
  python3 tools/v1_esp_durable_success_gate.py check [--archive PATH] [--nm NM]
  python3 tools/v1_esp_durable_success_gate.py self-test

CTest names:
  v1_esp_durable_success_source_gate
  v1_esp_durable_success_gate_self_test
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL_C = REPO_ROOT / "ports" / "esp-idf" / "storage" / "model" / "esp_storage_model.c"
FLASH_C = REPO_ROOT / "ports" / "esp-idf" / "storage" / "esp" / "esp_storage_flash_media.c"
PRIVATE_H = REPO_ROOT / "ports" / "esp-idf" / "storage" / "private" / "esp_storage_private.h"
CONFORMANCE_C = (
    REPO_ROOT / "tests" / "port" / "esp_storage_conformance_test.c"
)

ESP_TARGET_COMMIT_TAIL = """\
#if defined(ESP_PLATFORM)
    /* There is deliberately no unattested ESP target branch to FULL OK. */
    return NINLIL_STORAGE_COMMIT_UNKNOWN;
#else
"""

FLASH_BIND_POLICY = "NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN"

FORBIDDEN_TARGET_ARCHIVE_SYMBOLS = (
    "ninlil_port_esp_storage_private_simulate_full_reinit",
    "ninlil_port_esp_storage_private_simulate_crash",
    "ninlil_port_esp_storage_host_media_ops",
    "ninlil_port_esp_storage_init",
    "ninlil_port_esp_storage_simulate_full_reinit",
    "ninlil_port_esp_storage_simulate_crash",
)

FORBIDDEN_TARGET_ARCHIVE_PREFIXES = (
    "ninlil_port_esp_storage_host_media_",
)

ARCHIVE_KINDS = ("host", "target")

REQUIRED_CONFORMANCE_TESTS = (
    "test_esp_unproven_never_full_ok",
    "test_esp_unproven_readback_match_no_success_promotion",
)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_nm_defined(stdout: str) -> set[str]:
    defined: set[str] = set()
    for line in stdout.splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        if parts[-1].endswith(":"):
            continue
        type_token = parts[-2] if len(parts) >= 3 else parts[0]
        if type_token in ("U", "w", "v"):
            continue
        if len(type_token) == 1 and type_token.isalpha():
            name = parts[-1]
            if name.startswith("_"):
                name = name[1:]
            defined.add(name)
    return defined


def check_source() -> List[str]:
    errors: List[str] = []
    model = read_text(MODEL_C)
    flash = read_text(FLASH_C)
    private = read_text(PRIVATE_H)
    conformance = read_text(CONFORMANCE_C)

    if ESP_TARGET_COMMIT_TAIL not in model:
        errors.append(
            "esp_storage_model.c missing ESP_PLATFORM COMMIT_UNKNOWN-only tail"
        )
    if "FULL_HOST_MODEL" in flash:
        errors.append("esp_storage_flash_media.c references FULL_HOST_MODEL")
    if FLASH_BIND_POLICY not in flash:
        errors.append(
            "esp_storage_flash_media.c must bind FULL_ESP_UNPROVEN policy"
        )
    if (
        "#if !defined(ESP_PLATFORM)\n"
        "    NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL"
    ) not in private:
        errors.append("FULL_HOST_MODEL is not compile-excluded from ESP target")
    for test_name in REQUIRED_CONFORMANCE_TESTS:
        if test_name not in conformance:
            errors.append(
                f"esp_storage_conformance_test.c missing negative test {test_name}"
            )
    return errors


def check_archive(archive: Path, nm: str, kind: str) -> List[str]:
    errors: List[str] = []
    if kind not in ARCHIVE_KINDS:
        errors.append(f"unknown archive kind {kind!r}")
        return errors
    if not archive.is_file():
        errors.append(f"missing archive: {archive}")
        return errors
    try:
        completed = subprocess.run(
            [nm, "-g", str(archive)],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        errors.append(f"nm executable missing: {nm}")
        return errors
    except subprocess.CalledProcessError as exc:
        errors.append(f"nm failed: {(exc.stdout or '')[:300]}")
        return errors

    defined = parse_nm_defined(completed.stdout)
    if kind == "target":
        for symbol in FORBIDDEN_TARGET_ARCHIVE_SYMBOLS:
            if symbol in defined:
                errors.append(f"forbidden success/bypass symbol exported: {symbol}")
        for symbol in sorted(defined):
            for prefix in FORBIDDEN_TARGET_ARCHIVE_PREFIXES:
                if symbol.startswith(prefix):
                    errors.append(
                        f"forbidden host-only seam exported on target archive: "
                        f"{symbol}"
                    )
                    break
    required = (
        "ninlil_port_esp_storage_flash_bind",
        "ninlil_port_esp_storage_flash_unbind",
    )
    for symbol in required:
        if symbol not in defined:
            errors.append(f"required opaque bind symbol missing: {symbol}")
    return errors


def check(
    archive: Path | None = None,
    nm: str = "nm",
    archive_kind: str | None = None,
) -> Tuple[List[str], List[str]]:
    errors = check_source()
    if archive is not None:
        if archive_kind is None:
            errors.append("--archive requires --archive-kind host|target")
        else:
            errors.extend(check_archive(archive, nm, archive_kind))
    elif archive_kind is not None:
        errors.append("--archive-kind requires --archive")
    return errors, []


def self_test() -> None:
    errors, _ = check()
    if errors:
        print("self-test precondition failed:", *errors, sep="\n  ")
        sys.exit(1)

    orig_model = read_text(MODEL_C)
    orig_conformance = read_text(CONFORMANCE_C)

    def mut_ok_under_esp() -> None:
        MODEL_C.write_text(
            orig_model.replace(
                ESP_TARGET_COMMIT_TAIL,
                "#if defined(ESP_PLATFORM)\n"
                "    return NINLIL_STORAGE_OK;\n#else\n",
                1,
            ),
            encoding="utf-8",
        )

    try:
        mut_ok_under_esp()
        e, _ = check()
        if not any("COMMIT_UNKNOWN-only" in x for x in e):
            print("mutation: ESP_PLATFORM STORAGE_OK did not go red")
            sys.exit(1)
    finally:
        MODEL_C.write_text(orig_model, encoding="utf-8")

    try:
        CONFORMANCE_C.write_text(
            orig_conformance.replace(
                "test_esp_unproven_readback_match_no_success_promotion",
                "test_esp_unproven_readback_match_REMOVED",
            ),
            encoding="utf-8",
        )
        e, _ = check()
        if not any("readback_match_no_success_promotion" in x for x in e):
            print("mutation: missing readback negative test did not go red")
            sys.exit(1)
    finally:
        CONFORMANCE_C.write_text(orig_conformance, encoding="utf-8")

    print("ok v1_esp_durable_success_gate_self_test")


def main() -> None:
    archive: Path | None = None
    archive_kind: str | None = None
    nm = "nm"
    args = sys.argv[1:]
    if not args or args[0] not in ("check", "self-test"):
        print(
            "usage: v1_esp_durable_success_gate.py check|self-test "
            "[--archive PATH --archive-kind host|target] [--nm NM]",
            file=sys.stderr,
        )
        sys.exit(2)
    if args[0] == "self-test":
        self_test()
        return
    i = 1
    while i < len(args):
        if args[i] == "--archive" and i + 1 < len(args):
            archive = Path(args[i + 1])
            i += 2
        elif args[i] == "--archive-kind" and i + 1 < len(args):
            archive_kind = args[i + 1]
            i += 2
        elif args[i] == "--nm" and i + 1 < len(args):
            nm = args[i + 1]
            i += 2
        else:
            print(f"unknown argument: {args[i]}", file=sys.stderr)
            sys.exit(2)
    errors, warnings = check(
        archive=archive, nm=nm, archive_kind=archive_kind
    )
    for w in warnings:
        print(f"warning: {w}")
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    if archive is not None:
        print(
            f"ok v1_esp_durable_success_source_gate "
            f"(archive={archive.name})"
        )
    else:
        print("ok v1_esp_durable_success_source_gate")


if __name__ == "__main__":
    main()
