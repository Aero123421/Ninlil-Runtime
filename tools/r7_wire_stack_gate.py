#!/usr/bin/env python3
"""R7 T1 wire static-frame gate (docs/32 §9.7–8).

.su: production wire functions static, frame <= 2560.
When --compile-commands is provided: r7_wire_codec.c exact once, with
-fstack-usage exact once and optimization flags exact sole -O2 once.
Missing / non-O2 / duplicate compile entries are fail-closed.

PASS ≠ ESP task stack / adapter chain / T1 Accepted.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
import sys
import tempfile
from typing import Iterable

REPO = pathlib.Path(__file__).resolve().parents[1]
CMAKE = REPO / "CMakeLists.txt"
CEILING = 2560
REQUIRED = frozenset(
    {
        "ninlil_r7_wire_pack_outer_data_aad",
        "ninlil_r7_wire_parse_outer_data_aad",
        "ninlil_r7_wire_pack_e2e_single_aad",
        "ninlil_r7_wire_parse_e2e_single_aad",
        "ninlil_r7_wire_seal_e2e_single",
        "ninlil_r7_wire_open_e2e_single",
        "ninlil_r7_wire_seal_outer_single",
        "ninlil_r7_wire_open_outer_single",
    }
)
EXPECTED_FILES = ("r7_wire_codec.c.su",)
COMPILE_SOURCES = ("r7_wire_codec.c",)


def structural_errors(cmake_text: str) -> list[str]:
    errors: list[str] = []
    block = re.search(
        r"foreach\s*\(\s*_r7_wire_src\s+IN\s+LISTS\s+"
        r"NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES\s*\)(.*?)endforeach\s*\(\s*\)",
        cmake_text,
        re.DOTALL,
    )
    if block is None:
        return ["R7 wire compile-options block missing"]
    body = block.group(1)
    for token in ("-fstack-usage", f"-Wframe-larger-than={CEILING}"):
        if body.count(token) != 1:
            errors.append(f"wire compile-options require exactly one {token}")
    return errors


def parse_su_lines(lines: Iterable[str]) -> tuple[list[str], dict[str, tuple[int, str]]]:
    errors: list[str] = []
    records: dict[str, tuple[int, str]] = {}
    for line_number, raw in enumerate(lines, 1):
        line = raw.rstrip("\r\n")
        if not line:
            continue
        columns = line.split("\t")
        if len(columns) != 3:
            errors.append(f"line {line_number}: expected 3 tab-separated columns")
            continue
        location, byte_text, kind = columns
        function = location.rsplit(":", 1)[-1]
        if not function or not byte_text.isdigit():
            errors.append(f"line {line_number}: invalid function/frame record")
            continue
        if kind != "static":
            errors.append(f"{function}: frame kind must be static, got {kind}")
            continue
        frame = int(byte_text)
        if frame > CEILING:
            errors.append(f"{function}: frame {frame} exceeds {CEILING}")
        if function in records:
            errors.append(f"{function}: duplicate .su record")
        else:
            records[function] = (frame, kind)
    return errors, records


def check_su_dir(su_dir: pathlib.Path) -> list[str]:
    errors: list[str] = []
    files: list[pathlib.Path] = []
    for expected in EXPECTED_FILES:
        matches = sorted(su_dir.rglob(expected)) if su_dir.is_dir() else []
        if len(matches) != 1:
            errors.append(f"{expected}: expected exactly one artifact, got {len(matches)}")
        else:
            files.append(matches[0])
    if errors:
        return errors
    lines: list[str] = []
    for path in files:
        try:
            lines.extend(path.read_text(encoding="utf-8").splitlines())
        except (OSError, UnicodeError) as exc:
            errors.append(f"cannot read {path}: {exc}")
    parse_errs, records = parse_su_lines(lines)
    errors.extend(parse_errs)
    missing = sorted(REQUIRED - records.keys())
    if missing:
        errors.append(f"required wire records missing: {', '.join(missing)}")
    return errors


def optimization_flags(tokens: list[str]) -> list[str]:
    return [tok for tok in tokens if tok == "-O" or re.fullmatch(r"-O[0-9sgzfast]*", tok)]


def tokenize_entry(entry: dict) -> list[str]:
    if isinstance(entry.get("arguments"), list):
        return [str(x) for x in entry["arguments"]]
    cmd = entry.get("command")
    if isinstance(cmd, str) and cmd.strip():
        try:
            return shlex.split(cmd)
        except ValueError:
            return cmd.split()
    return []


def check_compile_commands(path: pathlib.Path) -> list[str]:
    """Fail-closed GCC Release authority when path is supplied.

    Requires:
      - exactly one compile command for r7_wire_codec.c
      - -fstack-usage exact once
      - optimization flags exact ['-O2'] (sole -O2 once; missing -O* is red)
    """
    errors: list[str] = []
    try:
        commands = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot read compile_commands: {exc}"]
    if not isinstance(commands, list):
        return ["compile_commands is not a list"]
    matches: list[dict] = []
    for entry in commands:
        if not isinstance(entry, dict):
            continue
        file_path = entry.get("file")
        if not isinstance(file_path, str):
            continue
        if pathlib.Path(file_path).name in COMPILE_SOURCES:
            matches.append(entry)
    if len(matches) != 1:
        errors.append(
            f"expected exactly one wire compile command, got {len(matches)}"
        )
        return errors
    tokens = tokenize_entry(matches[0])
    if tokens.count("-fstack-usage") != 1:
        errors.append(
            f"wire TU -fstack-usage count={tokens.count('-fstack-usage')} want 1"
        )
    o_flags = optimization_flags(tokens)
    if o_flags != ["-O2"]:
        errors.append(
            f"wire TU optimization flags must be exact ['-O2'], got {o_flags}"
        )
    return errors


def run_check(su_dir: pathlib.Path, compile_commands: pathlib.Path | None) -> int:
    errors: list[str] = []
    try:
        cmake_text = CMAKE.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"r7_wire_stack_gate FAIL: {exc}", file=sys.stderr)
        return 1
    errors.extend(structural_errors(cmake_text))
    if not su_dir.is_dir():
        errors.append(f"su-dir missing: {su_dir}")
    else:
        errors.extend(check_su_dir(su_dir))
    if compile_commands is not None:
        errors.extend(check_compile_commands(compile_commands))
    if errors:
        for e in errors:
            print(f"r7_wire_stack_gate FAIL: {e}", file=sys.stderr)
        return 1
    print(f"r7_wire_stack_gate: PASS (ceiling={CEILING})")
    return 0


def _write_cc(path: pathlib.Path, entries: list[dict]) -> None:
    path.write_text(json.dumps(entries), encoding="utf-8")


def run_self_test() -> int:
    failures: list[str] = []
    cmake_text = CMAKE.read_text(encoding="utf-8")
    if structural_errors(cmake_text):
        failures.append(f"baseline structural red: {structural_errors(cmake_text)}")
    wire_token = (
        "foreach(_r7_wire_src IN LISTS NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES)"
    )
    if cmake_text.count(wire_token) != 1:
        failures.append("wire foreach token count != 1")
    else:
        start = cmake_text.find(wire_token)
        end = cmake_text.find("endforeach()", start)
        block = cmake_text[start:end]
        if block.count("-fstack-usage") != 1:
            failures.append("wire block -fstack-usage count != 1")
        else:
            mutated_block = block.replace("-fstack-usage", "-fno-stack-usage", 1)
            mutated = cmake_text[:start] + mutated_block + cmake_text[end:]
            if not structural_errors(mutated):
                failures.append("stack-usage drop escaped")
    sample = "ninlil_r7_wire_seal_e2e_single\t3000\tstatic\n"
    errs, rec = parse_su_lines(sample.splitlines())
    if not any("exceeds" in e for e in errs):
        failures.append("ceiling overflow did not go red")
    if "ninlil_r7_wire_seal_e2e_single" not in rec:
        failures.append("ceiling sample not recorded")
    bad_kind = "ninlil_r7_wire_seal_e2e_single\t100\tdynamic\n"
    errs2, rec2 = parse_su_lines(bad_kind.splitlines())
    if not errs2:
        failures.append("dynamic kind did not produce parse error")
    if "ninlil_r7_wire_seal_e2e_single" in rec2:
        failures.append("dynamic kind was incorrectly recorded")

    # compile_commands mutations: missing entry, non-O2, duplicate, no -fstack-usage
    with tempfile.TemporaryDirectory(prefix="r7-wire-stack-") as td:
        td_path = pathlib.Path(td)
        good = {
            "directory": str(td_path),
            "file": str(td_path / "r7_wire_codec.c"),
            "arguments": [
                "gcc",
                "-O2",
                "-fstack-usage",
                "-c",
                "r7_wire_codec.c",
            ],
        }
        good_path = td_path / "good.json"
        _write_cc(good_path, [good])
        if check_compile_commands(good_path):
            failures.append(
                f"good compile_commands red: {check_compile_commands(good_path)}"
            )

        empty_path = td_path / "empty.json"
        _write_cc(empty_path, [])
        if not check_compile_commands(empty_path):
            failures.append("missing wire compile command did not go red")

        non_o2 = dict(good)
        non_o2["arguments"] = ["gcc", "-O3", "-fstack-usage", "-c", "r7_wire_codec.c"]
        non_o2_path = td_path / "non_o2.json"
        _write_cc(non_o2_path, [non_o2])
        errs_o2 = check_compile_commands(non_o2_path)
        if not any("-O2" in e or "optimization" in e for e in errs_o2):
            failures.append(f"non-O2 did not go red: {errs_o2}")

        missing_o = dict(good)
        missing_o["arguments"] = ["gcc", "-fstack-usage", "-c", "r7_wire_codec.c"]
        miss_path = td_path / "miss_o.json"
        _write_cc(miss_path, [missing_o])
        if not check_compile_commands(miss_path):
            failures.append("missing -O* did not go red")

        dup_path = td_path / "dup.json"
        _write_cc(dup_path, [good, dict(good)])
        if not check_compile_commands(dup_path):
            failures.append("duplicate wire compile command did not go red")

        no_su = dict(good)
        no_su["arguments"] = ["gcc", "-O2", "-c", "r7_wire_codec.c"]
        no_su_path = td_path / "no_su.json"
        _write_cc(no_su_path, [no_su])
        if not check_compile_commands(no_su_path):
            failures.append("missing -fstack-usage did not go red")

    if failures:
        for f in failures:
            print(f"r7_wire_stack_gate self-test FAIL: {f}", file=sys.stderr)
        return 1
    print("r7_wire_stack_gate self-test: PASS")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("check")
    p.add_argument("--su-dir", type=pathlib.Path, required=True)
    p.add_argument("--compile-commands", type=pathlib.Path)
    sub.add_parser("self-test")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return run_self_test()
    return run_check(args.su_dir, args.compile_commands)


if __name__ == "__main__":
    raise SystemExit(main())
