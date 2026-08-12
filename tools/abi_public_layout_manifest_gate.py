#!/usr/bin/env python3
"""Fail closed when byte-stream public layouts/constants miss ABI manifest rows."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


REPO = pathlib.Path(__file__).resolve().parents[1]
PUBLIC_HEADERS = (
    "include/ninlil/byte_stream.h",
    "include/ninlil/posix_usb_serial_v1.h",
)
COMMENT = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def fail(message: str) -> None:
    raise ValueError(message)


def layout_inventory(text: str) -> tuple[set[str], set[tuple[str, str]], set[str]]:
    text = COMMENT.sub("", text)
    structs: set[str] = set()
    fields: set[tuple[str, str]] = set()
    constants: set[str] = set()

    for match in re.finditer(r"^\s*#define\s+(NINLIL_[A-Za-z0-9_]+)(.*)$", text, re.MULTILINE):
        name, suffix = match.groups()
        # A function-like macro has no whitespace between its name and '('.
        # Object-like constants commonly begin their replacement text with a
        # parenthesized cast and must remain part of the ABI inventory.
        if name.endswith("_H") or suffix.startswith("("):
            continue
        constants.add(name)

    typedef_ranges: list[tuple[int, int]] = []
    for match in re.finditer(
        r"typedef\s+struct\s+[A-Za-z_][A-Za-z0-9_]*\s*\{(.*?)\}\s*"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*;",
        text,
        re.DOTALL,
    ):
        typedef_ranges.append(match.span())
        _add_fields(match.group(2), match.group(1), structs, fields)

    for match in re.finditer(
        r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{(.*?)\}\s*;",
        text,
        re.DOTALL,
    ):
        if any(start <= match.start() < end for start, end in typedef_ranges):
            continue
        _add_fields(f"struct {match.group(1)}", match.group(2), structs, fields)
    return structs, fields, constants


def _add_fields(
    struct_name: str,
    body: str,
    structs: set[str],
    fields: set[tuple[str, str]],
) -> None:
    structs.add(struct_name)
    for declaration in body.split(";"):
        declaration = declaration.strip()
        if not declaration:
            continue
        callback = re.search(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", declaration)
        if callback:
            fields.add((struct_name, callback.group(1)))
            continue
        name = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*$", declaration)
        if name is None:
            fail(f"cannot parse public field in {struct_name}: {declaration}")
        fields.add((struct_name, name.group(1)))


def manifest_inventory(text: str) -> tuple[set[str], set[tuple[str, str]], set[str]]:
    constants = set(re.findall(r"MANIFEST_CONST\((NINLIL_[A-Za-z0-9_]+)\)", text))
    structs = set(re.findall(r"MANIFEST_STRUCT_BEGIN\(([^)]+)\)", text))
    fields = set(
        re.findall(
            r"MANIFEST_FIELD\(([^,]+),\s*([A-Za-z_][A-Za-z0-9_]*)\)", text
        )
    )
    return structs, fields, constants


def check(repo: pathlib.Path) -> None:
    expected_structs: set[str] = set()
    expected_fields: set[tuple[str, str]] = set()
    expected_constants: set[str] = set()
    for relative in PUBLIC_HEADERS:
        structs, fields, constants = layout_inventory((repo / relative).read_text(encoding="utf-8"))
        expected_structs |= structs
        expected_fields |= fields
        expected_constants |= constants

    manifest_structs, manifest_fields, manifest_constants = manifest_inventory(
        (repo / "tools/abi_manifest_structs.inc").read_text(encoding="utf-8")
        + "\n"
        + (repo / "tools/abi_manifest_constants.inc").read_text(encoding="utf-8")
    )
    missing_structs = sorted(expected_structs - manifest_structs)
    missing_fields = sorted(expected_fields - manifest_fields)
    missing_constants = sorted(expected_constants - manifest_constants)
    if missing_structs or missing_fields or missing_constants:
        details = [
            *(f"missing struct {name}" for name in missing_structs),
            *(f"missing field {struct}.{field}" for struct, field in missing_fields),
            *(f"missing constant {name}" for name in missing_constants),
        ]
        fail("; ".join(details))


def self_test() -> None:
    repo = REPO
    check(repo)
    original = (repo / "tools/abi_manifest_structs.inc").read_text(encoding="utf-8")
    mutant = original.replace(
        "    MANIFEST_FIELD(ninlil_byte_stream_stats_t, bytes_read)\n", "", 1
    )
    if mutant == original:
        fail("self-test mutation setup failed")
    path = repo / "tools/abi_manifest_structs.inc"
    combined = path.read_text(encoding="utf-8")
    # In-memory mutation proves the checker rejects an omitted public layout row.
    try:
        expected = layout_inventory((repo / PUBLIC_HEADERS[0]).read_text(encoding="utf-8"))[1]
        actual = manifest_inventory(mutant)[1]
        if expected - actual:
            raise ValueError("mutation rejected")
    except ValueError as exc:
        if str(exc) != "mutation rejected":
            raise
    else:
        fail("self-test mutation was accepted")
    if combined != original:
        fail("self-test mutated source tree")

    constant_path = repo / "tools/abi_manifest_constants.inc"
    constant_original = constant_path.read_text(encoding="utf-8")
    expected_constants: set[str] = set()
    for relative in PUBLIC_HEADERS:
        expected_constants |= layout_inventory(
            (repo / relative).read_text(encoding="utf-8")
        )[2]
    for constant in (
        "NINLIL_BYTE_STREAM_OK",
        "NINLIL_POSIX_USB_SERIAL_OBJECT_BYTES",
        "NINLIL_POSIX_USB_SERIAL_EINTR_RETRY_MAX",
    ):
        row = f"    MANIFEST_CONST({constant})\n"
        mutant = constant_original.replace(row, "", 1)
        if mutant == constant_original:
            fail(f"self-test constant mutation setup failed: {constant}")
        if not expected_constants - manifest_inventory(mutant)[2]:
            fail(f"self-test missing constant was accepted: {constant}")
    if constant_path.read_text(encoding="utf-8") != constant_original:
        fail("self-test mutated constant manifest")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    parser.add_argument("--repo", type=pathlib.Path, default=REPO)
    args = parser.parse_args()
    try:
        if args.command == "self-test":
            self_test()
            print("abi_public_layout_manifest_gate self-test OK")
        else:
            check(args.repo.resolve())
            print("abi_public_layout_manifest_gate OK")
    except (OSError, ValueError) as exc:
        print(f"abi_public_layout_manifest_gate FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
