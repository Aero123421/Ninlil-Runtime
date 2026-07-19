#!/usr/bin/env python3
"""ESP compile-commands presence gate for R7 mbedTLS adapter (docs/31).

Proves the ESP smoke compile_commands set includes the mbedTLS adapter exactly
once and never includes the Host OpenSSL adapter.  Does not claim ESP KAT
execution, HIL, or R7 complete.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys


REPO = pathlib.Path(__file__).resolve().parents[1]
MBEDTLS_SUFFIX = "/ports/esp-idf/src/r7_crypto_mbedtls.c"
OPENSSL_BASENAME = "r7_crypto_openssl3.c"


def check(compile_commands: pathlib.Path) -> int:
    try:
        commands = json.loads(compile_commands.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"r7_esp_link_presence_gate FAIL: cannot read commands: {exc}", file=sys.stderr)
        return 1
    if not isinstance(commands, list):
        print("r7_esp_link_presence_gate FAIL: compile_commands is not a list", file=sys.stderr)
        return 1

    mbedtls_count = 0
    openssl_hits: list[str] = []
    for entry in commands:
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file")
        if not isinstance(file_path, str):
            continue
        posix = pathlib.Path(file_path).as_posix()
        if posix.endswith(MBEDTLS_SUFFIX):
            mbedtls_count += 1
        if pathlib.Path(file_path).name == OPENSSL_BASENAME:
            openssl_hits.append(posix)

    errors: list[str] = []
    if mbedtls_count != 1:
        errors.append(
            f"expected exactly one mbedTLS adapter compile command, got {mbedtls_count}"
        )
    if openssl_hits:
        errors.append(
            "Host OpenSSL adapter entered ESP compile commands: "
            + ", ".join(openssl_hits)
        )
    if errors:
        for error in errors:
            print(f"r7_esp_link_presence_gate FAIL: {error}", file=sys.stderr)
        return 1
    print("r7_esp_link_presence_gate: PASS (mbedtls=1 openssl=0)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check",))
    parser.add_argument(
        "--compile-commands",
        type=pathlib.Path,
        required=True,
        help="path to compile_commands.json from the ESP smoke build",
    )
    args = parser.parse_args(argv)
    return check(args.compile_commands)


if __name__ == "__main__":
    raise SystemExit(main())
