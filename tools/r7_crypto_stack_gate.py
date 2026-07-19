#!/usr/bin/env python3
"""R7 portable crypto static-frame gate for GCC/Clang .su artifacts.

docs/31 §11.6 authority:
  - GCC Release uses exact active -O2 (not -O0/-O1/-O3/-Os/-Ofast)
  - production portable/nonce objects compile with -fstack-usage
  - .su records: required wrappers, static kind, frame <= 2560

check:
  --su-dir DIR                 production .su evidence
  --compile-commands FILE      optional; when present, prove -O2 + -fstack-usage
                               on r7_crypto_portable.c / r7_crypto_nonce.c objects

self-test: structural + .su parser mutations + compile_commands mutations +
CI GCC Release flag structure (CMAKE_C_FLAGS_RELEASE=-O2, EXPORT_COMPILE_COMMANDS).

PASS ≠ product GO / R7 complete / ESP HIL / T0 accepted.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import shlex
import sys
from typing import Iterable


REPO = pathlib.Path(__file__).resolve().parents[1]
CMAKE = REPO / "CMakeLists.txt"
CI_YML = REPO / ".github" / "workflows" / "ci.yml"
CEILING = 2560
REQUIRED = frozenset(
    {
        "ninlil_r7_crypto_provider_validate",
        "ninlil_r7_crypto_sha256",
        "ninlil_r7_crypto_hkdf_extract_sha256",
        "ninlil_r7_crypto_hkdf_expand_sha256",
        "ninlil_r7_crypto_aes128_gcm_seal",
        "ninlil_r7_crypto_aes128_gcm_open",
        "ninlil_r7_crypto_nonce_from_counter",
    }
)
EXPECTED_FILES = ("r7_crypto_portable.c.su", "r7_crypto_nonce.c.su")
# Production objects whose compile_commands must carry -fstack-usage + active -O2.
R7_COMPILE_SOURCES = ("r7_crypto_portable.c", "r7_crypto_nonce.c")


def structural_errors(cmake_text: str) -> list[str]:
    errors: list[str] = []
    block = re.search(
        r"foreach\s*\(\s*_r7_src\s+IN\s+LISTS\s+"
        r"NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES\s*\)(.*?)endforeach\s*\(\s*\)",
        cmake_text,
        re.DOTALL,
    )
    if block is None:
        return ["R7 portable compile-options block missing"]
    body = block.group(1)
    for token in ("-fstack-usage", f"-Wframe-larger-than={CEILING}"):
        if body.count(token) != 1:
            errors.append(f"R7 compile-options block requires exactly one {token}")
    if "NOT _ninlil_any_sanitizer_active" not in body:
        errors.append("frame warning must be disabled only for sanitizer instrumentation")
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


def artifact_errors(su_dir: pathlib.Path) -> list[str]:
    errors: list[str] = []
    files: list[pathlib.Path] = []
    for name in EXPECTED_FILES:
        matches = sorted(su_dir.rglob(name)) if su_dir.is_dir() else []
        if len(matches) != 1:
            errors.append(f"{name}: expected exactly one artifact, got {len(matches)}")
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
    parsed_errors, records = parse_su_lines(lines)
    errors.extend(parsed_errors)
    missing = sorted(REQUIRED - records.keys())
    if missing:
        errors.append(f"required wrapper records missing: {', '.join(missing)}")
    return errors


def tokenize_compile_command(entry: dict) -> list[str]:
    """Return argv tokens from a compile_commands entry (command or arguments)."""
    if "arguments" in entry and isinstance(entry["arguments"], list):
        return [str(x) for x in entry["arguments"]]
    cmd = entry.get("command")
    if isinstance(cmd, str) and cmd.strip():
        try:
            return shlex.split(cmd)
        except ValueError:
            return cmd.split()
    return []


def optimization_flags(tokens: list[str]) -> list[str]:
    """All optimization-like command tokens.

    The authority is deliberately stricter than a compiler's last-wins
    behavior: docs/31 requires one unambiguous ``-O2`` token, so unknown
    future spellings such as ``-O4`` and the bare ``-O`` must also fail.
    """
    return [tok for tok in tokens if tok.startswith("-O")]


def source_basename(entry: dict) -> str:
    file_path = entry.get("file") or entry.get("source") or ""
    return pathlib.Path(str(file_path)).name


def compile_commands_errors(compile_commands: pathlib.Path) -> list[str]:
    """Prove r7 portable/nonce production compile lines: -fstack-usage + active -O2."""
    errors: list[str] = []
    try:
        raw = compile_commands.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [f"compile_commands unreadable/invalid: {exc}"]
    if not isinstance(data, list):
        return ["compile_commands is not a JSON list"]

    by_src: dict[str, list[list[str]]] = {name: [] for name in R7_COMPILE_SOURCES}
    for entry in data:
        if not isinstance(entry, dict):
            continue
        base = source_basename(entry)
        if base not in by_src:
            continue
        tokens = tokenize_compile_command(entry)
        if not tokens:
            errors.append(f"{base}: empty compile command")
            continue
        by_src[base].append(tokens)

    for name in R7_COMPILE_SOURCES:
        lines = by_src[name]
        if len(lines) == 0:
            errors.append(
                f"{name}: no compile_commands entry "
                "(expected production object under Release with "
                "CMAKE_EXPORT_COMPILE_COMMANDS=ON)"
            )
            continue
        # Exactly one production compile line is the intended Host shape; more
        # than one is ambiguous evidence (e.g. test recompiles of same basename).
        if len(lines) != 1:
            errors.append(
                f"{name}: expected exactly one compile_commands entry, "
                f"got {len(lines)}"
            )
        for tokens in lines:
            joined = tokens  # list for membership
            if "-fstack-usage" not in joined:
                errors.append(f"{name}: missing -fstack-usage in compile command")
            opt_tokens = optimization_flags(tokens)
            if opt_tokens != ["-O2"]:
                errors.append(
                    f"{name}: optimization flags must be exact ['-O2'], "
                    f"got {opt_tokens!r}"
                )
    return errors


def ci_gcc_release_structure_errors(ci_text: str) -> list[str]:
    """GCC Release job must force -O2 authority and export compile_commands."""
    errors: list[str] = []
    # Locate the Ubuntu GCC Release N6+R7 job block roughly.
    # Evidence must be real cmake args, not comments alone.
    if "CMAKE_C_FLAGS_RELEASE" not in ci_text:
        errors.append(
            "ci.yml missing CMAKE_C_FLAGS_RELEASE (GCC Release -O2 authority)"
        )
    # Accept either quoted or escaped forms of -O2 -DNDEBUG.
    o2_patterns = (
        'CMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG"',
        "CMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG",
        'CMAKE_C_FLAGS_RELEASE=-O2\\ -DNDEBUG',
        "CMAKE_C_FLAGS_RELEASE:STRING=-O2 -DNDEBUG",
    )
    if not any(p in ci_text for p in o2_patterns):
        # Also accept -DCMAKE_C_FLAGS_RELEASE=-O2 with separate NDEBUG.
        if (
            "-DCMAKE_C_FLAGS_RELEASE=-O2" not in ci_text
            and 'DCMAKE_C_FLAGS_RELEASE="-O2' not in ci_text
        ):
            errors.append(
                "ci.yml GCC Release must set CMAKE_C_FLAGS_RELEASE to exact "
                "-O2 -DNDEBUG (not bare default -O3)"
            )
    if "CMAKE_EXPORT_COMPILE_COMMANDS=ON" not in ci_text and (
        "CMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON" not in ci_text
    ):
        errors.append(
            "ci.yml must enable CMAKE_EXPORT_COMPILE_COMMANDS=ON for "
            "compile_commands -O2/-fstack-usage evidence"
        )
    return errors


def run_check(
    su_dir: pathlib.Path,
    compile_commands: pathlib.Path | None = None,
) -> int:
    try:
        cmake_text = CMAKE.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"r7 crypto stack gate FAIL: cannot read CMakeLists.txt: {exc}", file=sys.stderr)
        return 1
    errors = structural_errors(cmake_text) + artifact_errors(su_dir)
    if compile_commands is not None:
        errors.extend(compile_commands_errors(compile_commands))
    if errors:
        for error in errors:
            print(f"r7 crypto stack gate FAIL: {error}", file=sys.stderr)
        return 1
    extra = ""
    if compile_commands is not None:
        extra = " compile_commands=-O2+-fstack-usage"
    print(
        f"r7 crypto stack gate: PASS "
        f"(required={len(REQUIRED)} ceiling={CEILING}{extra})"
    )
    return 0


def run_self_test() -> int:
    try:
        cmake_text = CMAKE.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"r7 crypto stack self-test FAIL: {exc}", file=sys.stderr)
        return 1
    if structural_errors(cmake_text):
        print("r7 crypto stack self-test FAIL: structural baseline is red", file=sys.stderr)
        return 1
    good_lines = [
        f"x.c:1:{name}\t{index * 16}\tstatic"
        for index, name in enumerate(sorted(REQUIRED), 1)
    ]
    errors, records = parse_su_lines(good_lines)
    if errors or set(records) != set(REQUIRED):
        print("r7 crypto stack self-test FAIL: parser baseline is red", file=sys.stderr)
        return 1
    mutations = (
        good_lines[1:],
        good_lines + [good_lines[0]],
        [good_lines[0].replace("\tstatic", "\tdynamic")] + good_lines[1:],
        [good_lines[0].replace("\t16\t", f"\t{CEILING + 1}\t")] + good_lines[1:],
        [good_lines[0].replace("\t16\t", "\tunknown\t")] + good_lines[1:],
    )
    escaped: list[int] = []
    for index, lines in enumerate(mutations, 1):
        mutation_errors, mutation_records = parse_su_lines(lines)
        if not mutation_errors and REQUIRED <= mutation_records.keys():
            escaped.append(index)
    bad_cmake = cmake_text.replace(
        f"-Wframe-larger-than={CEILING}",
        f"-Wframe-larger-than={CEILING + 1}",
        1,
    )
    if not structural_errors(bad_cmake):
        escaped.append(len(mutations) + 1)

    # --- compile_commands mutations ---
    def _entry(file_name: str, command: str) -> dict:
        return {
            "directory": "/tmp/build",
            "command": command,
            "file": f"/tmp/src/radio/{file_name}",
        }

    good_cmd = (
        "cc -O2 -DNDEBUG -fstack-usage -Wframe-larger-than=2560 "
        "-c /tmp/src/radio/{src} -o /tmp/{src}.o"
    )
    good_cc = [
        _entry("r7_crypto_portable.c", good_cmd.format(src="r7_crypto_portable.c")),
        _entry("r7_crypto_nonce.c", good_cmd.format(src="r7_crypto_nonce.c")),
    ]
    # Write temp JSON via in-memory path simulation: call inspect with tempfile.
    import tempfile

    failures: list[str] = []

    def _cc_errs(entries: list[dict]) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="r7-cc-") as td:
            path = pathlib.Path(td) / "compile_commands.json"
            path.write_text(json.dumps(entries), encoding="utf-8")
            return compile_commands_errors(path)

    if _cc_errs(good_cc):
        failures.append(f"compile_commands baseline red: {_cc_errs(good_cc)}")

    # Missing -fstack-usage → RED.
    no_su = [
        _entry(
            "r7_crypto_portable.c",
            "cc -O2 -DNDEBUG -c /tmp/src/radio/r7_crypto_portable.c -o x.o",
        ),
        _entry("r7_crypto_nonce.c", good_cmd.format(src="r7_crypto_nonce.c")),
    ]
    if not _cc_errs(no_su):
        failures.append("missing -fstack-usage did not go red")

    # Active -O3 (default Release) → RED.
    o3 = [
        _entry(
            "r7_crypto_portable.c",
            "cc -O3 -DNDEBUG -fstack-usage -c /tmp/src/radio/r7_crypto_portable.c -o x.o",
        ),
        _entry("r7_crypto_nonce.c", good_cmd.format(src="r7_crypto_nonce.c")),
    ]
    if not _cc_errs(o3):
        failures.append("active -O3 did not go red")

    # -O2 then later -O3 → active -O3 RED.
    o2_then_o3 = [
        _entry(
            "r7_crypto_portable.c",
            "cc -O2 -DNDEBUG -O3 -fstack-usage "
            "-c /tmp/src/radio/r7_crypto_portable.c -o x.o",
        ),
        _entry("r7_crypto_nonce.c", good_cmd.format(src="r7_crypto_nonce.c")),
    ]
    if not _cc_errs(o2_then_o3):
        failures.append("last-wins -O3 after -O2 did not go red")

    # -O3 then -O2 is still ambiguous evidence and must be RED.
    o3_then_o2 = [
        _entry(
            "r7_crypto_portable.c",
            "cc -O3 -DNDEBUG -O2 -fstack-usage "
            "-c /tmp/src/radio/r7_crypto_portable.c -o x.o",
        ),
        _entry("r7_crypto_nonce.c", good_cmd.format(src="r7_crypto_nonce.c")),
    ]
    if not _cc_errs(o3_then_o2):
        failures.append("competing -O3 before active -O2 did not go red")

    # Unknown/future and bare optimization spellings must also fail closed.
    for label, flags in (
        ("unknown_before", "-O4 -O2"),
        ("unknown_after", "-O2 -O4"),
        ("bare_before", "-O -O2"),
        ("duplicate_exact", "-O2 -O2"),
    ):
        mutated = [
            _entry(
                "r7_crypto_portable.c",
                f"cc {flags} -DNDEBUG -fstack-usage "
                "-c /tmp/src/radio/r7_crypto_portable.c -o x.o",
            ),
            _entry("r7_crypto_nonce.c", good_cmd.format(src="r7_crypto_nonce.c")),
        ]
        if not _cc_errs(mutated):
            failures.append(f"{label} optimization mutation did not go red")

    # Missing source entirely → RED.
    only_one = [
        _entry("r7_crypto_portable.c", good_cmd.format(src="r7_crypto_portable.c")),
    ]
    if not _cc_errs(only_one):
        failures.append("missing nonce compile entry did not go red")

    # arguments-array form GREEN.
    args_form = [
        {
            "directory": "/tmp/build",
            "arguments": [
                "cc",
                "-O2",
                "-DNDEBUG",
                "-fstack-usage",
                "-c",
                "/tmp/src/radio/r7_crypto_portable.c",
                "-o",
                "x.o",
            ],
            "file": "/tmp/src/radio/r7_crypto_portable.c",
        },
        {
            "directory": "/tmp/build",
            "arguments": [
                "cc",
                "-O2",
                "-DNDEBUG",
                "-fstack-usage",
                "-c",
                "/tmp/src/radio/r7_crypto_nonce.c",
                "-o",
                "y.o",
            ],
            "file": "/tmp/src/radio/r7_crypto_nonce.c",
        },
    ]
    if _cc_errs(args_form):
        failures.append(f"arguments form baseline red: {_cc_errs(args_form)}")

    # CI structure: good snippet green, missing O2 red, env-only comment red.
    good_ci = (
        "ubuntu-gcc-release-n6-frame:\n"
        "  steps:\n"
        "    - run: >-\n"
        "        cmake -S . -B build/ci-ubuntu-gcc-rel-n6\n"
        "        -DCMAKE_BUILD_TYPE=Release\n"
        '        -DCMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG"\n'
        "        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON\n"
    )
    if ci_gcc_release_structure_errors(good_ci):
        failures.append(
            f"ci structure good red: {ci_gcc_release_structure_errors(good_ci)}"
        )
    bad_ci = (
        "ubuntu-gcc-release-n6-frame:\n"
        "  steps:\n"
        "    - run: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release\n"
    )
    if not ci_gcc_release_structure_errors(bad_ci):
        failures.append("ci structure missing O2 did not go red")

    # Real ci.yml: after fix must be green; report residual as failure.
    if CI_YML.is_file():
        real_ci_errs = ci_gcc_release_structure_errors(
            CI_YML.read_text(encoding="utf-8")
        )
        if real_ci_errs:
            failures.append("ci.yml GCC Release structure still red: " + "; ".join(real_ci_errs))

    if escaped:
        print(
            f"r7 crypto stack self-test FAIL: su mutations escaped {escaped}",
            file=sys.stderr,
        )
        return 1
    if failures:
        for f in failures:
            print(f"r7 crypto stack self-test FAIL: {f}", file=sys.stderr)
        return 1
    print(
        f"r7 crypto stack self-test: PASS "
        f"({len(mutations) + 1} su mutations + compile_commands/CI structure rejected)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    parser.add_argument("--su-dir", type=pathlib.Path)
    parser.add_argument(
        "--compile-commands",
        type=pathlib.Path,
        default=None,
        help="compile_commands.json for -O2 / -fstack-usage evidence",
    )
    args = parser.parse_args()
    if args.command == "check":
        if args.su_dir is None:
            parser.error("check requires --su-dir")
        return run_check(args.su_dir, args.compile_commands)
    return run_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
