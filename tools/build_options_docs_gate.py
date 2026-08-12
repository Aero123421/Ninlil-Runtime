#!/usr/bin/env python3
"""Keep the documented user-facing CMake variable set in sync."""

from __future__ import annotations

import argparse
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_PATHS = (
    pathlib.Path("CMakeLists.txt"),
    pathlib.Path("cmake/ninlil_posix_sqlite_sqlite3.cmake"),
)
DOC_PATH = pathlib.Path("docs/build-options.md")
COMMAND_START_RE = re.compile(r"^\s*(option|set)\(", re.IGNORECASE)
NAME_RE = re.compile(r"^\s*(?:option|set)\(\s*(NINLIL_[A-Z0-9_]+)\b")
CACHE_TYPE_RE = re.compile(r"\bCACHE\s+(?:BOOL|FILEPATH|PATH|STRING)\b")
DOC_ROW_RE = re.compile(r"^\| `(?P<name>NINLIL_[A-Z0-9_]+)` \|", re.MULTILINE)


class GateError(RuntimeError):
    """Expected documentation drift."""


def cmake_commands(text: str) -> list[str]:
    """Return top-level option()/set() command blocks from a CMake file."""
    commands: list[str] = []
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        if not COMMAND_START_RE.match(lines[index]):
            index += 1
            continue
        block = [lines[index]]
        depth = lines[index].count("(") - lines[index].count(")")
        index += 1
        while depth > 0 and index < len(lines):
            block.append(lines[index])
            depth += lines[index].count("(") - lines[index].count(")")
            index += 1
        commands.append("\n".join(block))
    return commands


def source_names(texts: list[str]) -> list[str]:
    """Discover option() and typed CACHE set() variables in source order."""
    names: list[str] = []
    for source in texts:
        for command in cmake_commands(source):
            match = NAME_RE.match(command)
            if match is None:
                continue
            is_option = command.lstrip().lower().startswith("option(")
            if not is_option and CACHE_TYPE_RE.search(command) is None:
                continue
            name = match.group(1)
            if name not in names:
                names.append(name)
    return names


def documented_names(text: str) -> list[str]:
    return [match.group("name") for match in DOC_ROW_RE.finditer(text)]


def compare(expected: list[str], documented: list[str]) -> None:
    duplicates = sorted(
        name for name in set(documented) if documented.count(name) != 1
    )
    if duplicates:
        raise GateError("duplicate documentation rows: " + ", ".join(duplicates))
    missing = [name for name in expected if name not in documented]
    extra = [name for name in documented if name not in expected]
    if missing or extra:
        parts = []
        if missing:
            parts.append("missing: " + ", ".join(missing))
        if extra:
            parts.append("not user-facing CMake entries: " + ", ".join(extra))
        raise GateError("; ".join(parts))


def check(root: pathlib.Path) -> None:
    try:
        texts = [(root / path).read_text(encoding="utf-8") for path in SOURCE_PATHS]
        doc = (root / DOC_PATH).read_text(encoding="utf-8")
    except OSError as exc:
        raise GateError(str(exc)) from exc
    expected = source_names(texts)
    documented = documented_names(doc)
    compare(expected, documented)
    print(f"build options docs gate ok: {len(expected)} entries")


def self_test() -> None:
    sources = [
        "option(NINLIL_ALPHA \"alpha\" ON)\n"
        "set(NINLIL_BETA \"\" CACHE PATH \"beta\")\n"
        "set(NINLIL_INTERNAL value)\n",
        "set(NINLIL_GAMMA AUTO CACHE STRING \"gamma\")\n"
        "set(NINLIL_GAMMA AUTO CACHE STRING \"gamma\" FORCE)\n",
    ]
    expected = ["NINLIL_ALPHA", "NINLIL_BETA", "NINLIL_GAMMA"]
    if source_names(sources) != expected:
        raise AssertionError("source discovery failed")
    good_doc = "\n".join(f"| `{name}` | BOOL | x | x | x |" for name in expected)
    compare(expected, documented_names(good_doc))
    for bad_doc in (
        good_doc.replace("| `NINLIL_BETA` | BOOL | x | x | x |\n", ""),
        good_doc + "\n| `NINLIL_EXTRA` | BOOL | x | x | x |",
        good_doc + "\n| `NINLIL_ALPHA` | BOOL | x | x | x |",
    ):
        try:
            compare(expected, documented_names(bad_doc))
        except GateError:
            pass
        else:
            raise AssertionError("negative self-test unexpectedly passed")
    print("build options docs gate self-test ok")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "self-test"))
    parser.add_argument("--root", type=pathlib.Path, default=ROOT)
    args = parser.parse_args()
    try:
        if args.mode == "check":
            check(args.root.resolve())
        else:
            self_test()
    except (GateError, AssertionError) as exc:
        print(f"build options docs gate failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
