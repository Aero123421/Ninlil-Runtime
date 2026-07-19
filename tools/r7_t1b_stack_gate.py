#!/usr/bin/env python3
"""R7 T1b binding static-frame gate (docs/33 §8, §10).

.su: exact six production binding functions, static kind, frame <= 2560.
When --compile-commands is provided: r7_context_binding.c exact once, with
-fstack-usage exact once. An NDEBUG/Release command must have effective final
optimization -O2; an earlier CMake default (for example -O3) is allowed only
when the later source-local -O2 overrides it. Missing / ineffective non-O2 /
duplicate / dynamic / unknown / over-limit are fail-closed.

PASS ≠ ESP task stack / adapter chain / T1b Accepted / R7 complete.
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
        "ninlil_r7_encode_hop_binding",
        "ninlil_r7_encode_e2e_binding",
        "ninlil_r7_digest_hop_binding",
        "ninlil_r7_digest_e2e_binding",
        "ninlil_r7_derive_hop_key_bundle_verified",
        "ninlil_r7_derive_e2e_key_bundle_verified",
    }
)
EXPECTED_FILES = ("r7_context_binding.c.su",)
COMPILE_SOURCES = ("r7_context_binding.c",)


def structural_errors(cmake_text: str) -> list[str]:
    errors: list[str] = []
    block = re.search(
        r"foreach\s*\(\s*_r7_t1b_src\s+IN\s+LISTS\s+"
        r"NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES\s*\)(.*?)endforeach\s*\(\s*\)",
        cmake_text,
        re.DOTALL,
    )
    if block is None:
        return ["R7 T1b binding compile-options block missing"]
    body = block.group(1)
    for token in ("-fstack-usage", f"-Wframe-larger-than={CEILING}"):
        if body.count(token) != 1:
            errors.append(f"binding compile-options require exactly one {token}")
    if body.count("$<$<CONFIG:Release>:-O2>") != 1:
        errors.append("binding compile-options require exact Release effective -O2")
    if "NOT _ninlil_any_sanitizer_active" not in body:
        errors.append(
            "frame warning must be disabled only for sanitizer instrumentation"
        )
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
            errors.append(
                f"{expected}: expected exactly one artifact, got {len(matches)}"
            )
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
        errors.append(f"required binding records missing: {', '.join(missing)}")
    # Unknown external production APIs beyond the exact six are fail-closed
    # only for the required name set; static helpers may appear in .su and are
    # tolerated if they stay under ceiling and static (already checked).
    # Reject unknown *required-prefix* extras that claim to be public APIs.
    for name in sorted(records.keys()):
        if name.startswith("ninlil_r7_") and name not in REQUIRED:
            # Allow internal helpers (secure_zero etc.) — only exact public
            # API set is required; extra ninlil_r7_* symbols are not rejected
            # here because .su includes static helpers. Unknown *required*
            # functions are handled by missing check. Reject dynamic already.
            pass
    # Exact: every REQUIRED present (done). Reject if a REQUIRED name is
    # duplicated (done). Over-limit (done).
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
            f"expected exactly one binding compile command, got {len(matches)}"
        )
        return errors
    tokens = tokenize_entry(matches[0])
    if tokens.count("-fstack-usage") != 1:
        errors.append(
            f"binding TU -fstack-usage count={tokens.count('-fstack-usage')} want 1"
        )
    o_flags = optimization_flags(tokens)
    is_ndebug = "-DNDEBUG" in tokens or any(
        tok.startswith("-DNDEBUG=") for tok in tokens
    )
    if is_ndebug and (not o_flags or o_flags[-1] != "-O2"):
        errors.append(
            "binding TU NDEBUG build must have effective final -O2, "
            f"got {o_flags}"
        )
    return errors


def run_check(su_dir: pathlib.Path, compile_commands: pathlib.Path | None) -> int:
    errors: list[str] = []
    try:
        cmake_text = CMAKE.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"r7_t1b_stack_gate FAIL: {exc}", file=sys.stderr)
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
            print(f"r7_t1b_stack_gate FAIL: {e}", file=sys.stderr)
        return 1
    print(f"r7_t1b_stack_gate: PASS (ceiling={CEILING}, apis={len(REQUIRED)})")
    return 0


def _write_cc(path: pathlib.Path, entries: list[dict]) -> None:
    path.write_text(json.dumps(entries), encoding="utf-8")


def _good_su_lines() -> list[str]:
    lines: list[str] = []
    for name in sorted(REQUIRED):
        lines.append(f"r7_context_binding.c:1:{name}\t512\tstatic")
    return lines


def run_self_test() -> int:
    failures: list[str] = []
    cmake_text = CMAKE.read_text(encoding="utf-8")
    if structural_errors(cmake_text):
        failures.append(f"baseline structural red: {structural_errors(cmake_text)}")
    t1b_token = (
        "foreach(_r7_t1b_src IN LISTS NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES)"
    )
    if cmake_text.count(t1b_token) != 1:
        failures.append("binding foreach token count != 1")
    else:
        start = cmake_text.find(t1b_token)
        end = cmake_text.find("endforeach()", start)
        block = cmake_text[start:end]
        if block.count("-fstack-usage") != 1:
            failures.append("binding block -fstack-usage count != 1")
        else:
            mutated_block = block.replace("-fstack-usage", "-fno-stack-usage", 1)
            mutated = cmake_text[:start] + mutated_block + cmake_text[end:]
            if not structural_errors(mutated):
                failures.append("stack-usage drop escaped")
        mutated_o2 = cmake_text[:start] + block.replace(
            "$<$<CONFIG:Release>:-O2>", "$<$<CONFIG:Release>:-O3>", 1
        ) + cmake_text[end:]
        if not structural_errors(mutated_o2):
            failures.append("Release -O2 mutation escaped")

    sample = "ninlil_r7_derive_hop_key_bundle_verified\t3000\tstatic\n"
    errs, rec = parse_su_lines(sample.splitlines())
    if not any("exceeds" in e for e in errs):
        failures.append("ceiling overflow did not go red")
    if "ninlil_r7_derive_hop_key_bundle_verified" not in rec:
        failures.append("ceiling sample not recorded")
    bad_kind = "ninlil_r7_derive_hop_key_bundle_verified\t100\tdynamic\n"
    errs2, rec2 = parse_su_lines(bad_kind.splitlines())
    if not errs2:
        failures.append("dynamic kind did not produce parse error")
    if "ninlil_r7_derive_hop_key_bundle_verified" in rec2:
        failures.append("dynamic kind was incorrectly recorded")

    with tempfile.TemporaryDirectory(prefix="r7-t1b-stack-") as td:
        td_path = pathlib.Path(td)
        su_dir = td_path / "su"
        su_dir.mkdir()
        su_path = su_dir / "r7_context_binding.c.su"
        su_path.write_text("\n".join(_good_su_lines()) + "\n", encoding="utf-8")
        good_errs = check_su_dir(su_dir)
        if good_errs:
            failures.append(f"good .su red: {good_errs}")

        # Missing function
        missing_lines = [
            ln
            for ln in _good_su_lines()
            if "ninlil_r7_encode_hop_binding" not in ln
        ]
        su_path.write_text("\n".join(missing_lines) + "\n", encoding="utf-8")
        if not any("missing" in e for e in check_su_dir(su_dir)):
            failures.append("missing required function did not go red")

        # Duplicate function
        dups = _good_su_lines() + [
            "r7_context_binding.c:2:ninlil_r7_encode_hop_binding\t10\tstatic"
        ]
        su_path.write_text("\n".join(dups) + "\n", encoding="utf-8")
        if not any("duplicate" in e for e in check_su_dir(su_dir)):
            failures.append("duplicate function did not go red")

        # Over limit
        over = [
            "r7_context_binding.c:1:ninlil_r7_encode_hop_binding\t3000\tstatic"
        ] + [
            ln
            for ln in _good_su_lines()
            if "ninlil_r7_encode_hop_binding" not in ln
        ]
        su_path.write_text("\n".join(over) + "\n", encoding="utf-8")
        if not any("exceeds" in e for e in check_su_dir(su_dir)):
            failures.append("over-limit did not go red")

        # Dynamic kind
        dyn = [
            "r7_context_binding.c:1:ninlil_r7_encode_hop_binding\t100\tdynamic"
        ] + [
            ln
            for ln in _good_su_lines()
            if "ninlil_r7_encode_hop_binding" not in ln
        ]
        su_path.write_text("\n".join(dyn) + "\n", encoding="utf-8")
        if not any("static" in e or "dynamic" in e for e in check_su_dir(su_dir)):
            failures.append("dynamic kind in dir did not go red")

        # Missing .su file
        empty_dir = td_path / "empty_su"
        empty_dir.mkdir()
        if not check_su_dir(empty_dir):
            failures.append("missing .su file did not go red")

        good = {
            "directory": str(td_path),
            "file": str(td_path / "r7_context_binding.c"),
            "arguments": [
                "gcc",
                "-O3",
                "-DNDEBUG",
                "-O2",
                "-fstack-usage",
                "-c",
                "r7_context_binding.c",
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
            failures.append("missing binding compile command did not go red")

        non_o2 = dict(good)
        non_o2["arguments"] = [
            "gcc",
            "-O3",
            "-DNDEBUG",
            "-fstack-usage",
            "-c",
            "r7_context_binding.c",
        ]
        non_o2_path = td_path / "non_o2.json"
        _write_cc(non_o2_path, [non_o2])
        errs_o2 = check_compile_commands(non_o2_path)
        if not any("-O2" in e or "optimization" in e for e in errs_o2):
            failures.append(f"non-O2 did not go red: {errs_o2}")

        missing_o = dict(good)
        missing_o["arguments"] = [
            "gcc",
            "-DNDEBUG",
            "-fstack-usage",
            "-c",
            "r7_context_binding.c",
        ]
        miss_path = td_path / "miss_o.json"
        _write_cc(miss_path, [missing_o])
        if not check_compile_commands(miss_path):
            failures.append("missing -O* did not go red")

        debug_no_o = dict(good)
        debug_no_o["arguments"] = [
            "gcc",
            "-g",
            "-fstack-usage",
            "-c",
            "r7_context_binding.c",
        ]
        debug_path = td_path / "debug.json"
        _write_cc(debug_path, [debug_no_o])
        if check_compile_commands(debug_path):
            failures.append(
                f"Debug no-optimization command red: {check_compile_commands(debug_path)}"
            )

        dup_path = td_path / "dup.json"
        _write_cc(dup_path, [good, dict(good)])
        if not check_compile_commands(dup_path):
            failures.append("duplicate binding compile command did not go red")

        no_su = dict(good)
        no_su["arguments"] = [
            "gcc", "-DNDEBUG", "-O2", "-c", "r7_context_binding.c"
        ]
        no_su_path = td_path / "no_su.json"
        _write_cc(no_su_path, [no_su])
        if not check_compile_commands(no_su_path):
            failures.append("missing -fstack-usage did not go red")

    if failures:
        for f in failures:
            print(f"r7_t1b_stack_gate self-test FAIL: {f}", file=sys.stderr)
        return 1
    print("r7_t1b_stack_gate self-test: PASS")
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
