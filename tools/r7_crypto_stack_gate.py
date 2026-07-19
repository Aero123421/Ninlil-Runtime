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
  --require-maccumulate-outgoing-args
                               only with --compile-commands; prove each R7 TU has
                               exact-one -maccumulate-outgoing-args (GCC x86 authority)

self-test: structural + .su parser mutations + compile_commands mutations +
CI GCC Release flag structure (CMAKE_C_FLAGS_RELEASE=-O2, EXPORT_COMPILE_COMMANDS,
require-maccumulate CLI, fail-closed negative configure).

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
MACCUMULATE_FLAG = "-maccumulate-outgoing-args"
REQUIRE_MACCUMULATE_CLI = "--require-maccumulate-outgoing-args"
# Exact CMake FATAL_ERROR reason prefix (docs authority: native GNU x86 host).
MACCUMULATE_FATAL_REASON = (
    "GNU x86/x86_64 host requires -maccumulate-outgoing-args"
)
NEGATIVE_PROBE_CACHE = "-DNINLIL_HAS_MACCUMULATE_OUTGOING_ARGS=FALSE"
GCC_AUTHORITY_JOB = "ubuntu-gcc-release-n6-frame"
GCC_AUTHORITY_SHELL = "bash --noprofile --norc -euo pipefail {0}"
STEP_NEG_CONFIGURE = (
    "Fail-closed negative configure (maccumulate probe forced FALSE)"
)
STEP_R7_STACK = (
    "R7 compile_commands -O2 / -fstack-usage evidence (docs/31 §11.6)"
)

# Canonical normalized command tuples for the two critical steps.
# Derived via _join_shell_continuations from the known-good ci.yml scripts
# (ubuntu-gcc-release-n6-frame). Exact equality is required — any wrapper,
# || true, echo decoy, reorder, or extra/missing command is RED.
CANONICAL_NEG_CONFIGURE_COMMANDS: tuple[str, ...] = (
    "set -euo pipefail",
    "neg=build/ci-ubuntu-gcc-rel-n6-macc-neg",
    "log=${neg}-configure.log",
    "mkdir -p build",
    'rm -rf "$neg"',
    "set +e",
    # Single joined cmake line (flags + redirect).
    'cmake -S . -B "$neg" -G Ninja -DCMAKE_BUILD_TYPE=Release '
    "-DCMAKE_C_COMPILER=gcc-13 -DCMAKE_CXX_COMPILER=g++-13 "
    "-DCMAKE_C_FLAGS_RELEASE='-O2 -DNDEBUG' "
    "-DCMAKE_CXX_FLAGS_RELEASE='-O2 -DNDEBUG' "
    "-DNINLIL_ENABLE_STRICT_WARNINGS=ON -DNINLIL_ENABLE_SANITIZERS=OFF "
    "-DNINLIL_SQLITE_LINKAGE=SHARED "
    "-DNINLIL_HAS_MACCUMULATE_OUTGOING_ARGS=FALSE >\"$log\" 2>&1",
    "rc=$?",
    "set -e",
    'echo "----- negative configure log (rc=${rc}) -----"',
    'cat "$log"',
    'echo "----- end negative configure log -----"',
    'if test "${rc}" -eq 0; then',
    'echo "false-green: negative configure succeeded (expected FATAL_ERROR)" >&2',
    "exit 1",
    "fi",
    "if ! grep -F 'GNU x86/x86_64 host requires -maccumulate-outgoing-args' "
    '"$log"; then',
    'echo "false-green: negative configure failed without exact" '
    '"maccumulate fatal reason" >&2',
    "exit 1",
    "fi",
    'echo "negative configure FAIL-CLOSED OK (exact fatal reason present)"',
)

CANONICAL_R7_STACK_COMMANDS: tuple[str, ...] = (
    "set -euo pipefail",
    "cc=build/ci-ubuntu-gcc-rel-n6/compile_commands.json",
    "su=build/ci-ubuntu-gcc-rel-n6/CMakeFiles/ninlil_runtime_private.dir",
    'test -f "$cc"',
    "if ! grep -E '^CMAKE_C_FLAGS_RELEASE:STRING=-O2 -DNDEBUG$' "
    "build/ci-ubuntu-gcc-rel-n6/CMakeCache.txt; then",
    'echo "false-green: CMAKE_C_FLAGS_RELEASE is not exact -O2 -DNDEBUG" >&2',
    "grep CMAKE_C_FLAGS_RELEASE build/ci-ubuntu-gcc-rel-n6/CMakeCache.txt "
    "|| true",
    "exit 1",
    "fi",
    "python3 tools/r7_crypto_stack_gate.py check --su-dir \"$su\" "
    "--compile-commands \"$cc\" --require-maccumulate-outgoing-args",
)


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


def compile_commands_errors(
    compile_commands: pathlib.Path,
    *,
    require_maccumulate_outgoing_args: bool = False,
) -> list[str]:
    """Prove r7 portable/nonce production compile lines: -fstack-usage + active -O2.

    When ``require_maccumulate_outgoing_args`` is True (GCC x86 authority only),
    each R7 TU must also carry exact-one ``-maccumulate-outgoing-args``.
    """
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
            if require_maccumulate_outgoing_args:
                n_macc = sum(1 for t in tokens if t == MACCUMULATE_FLAG)
                if n_macc != 1:
                    errors.append(
                        f"{name}: {MACCUMULATE_FLAG} must appear exact-once "
                        f"in compile command, got {n_macc}"
                    )
    return errors


def _leading_spaces(line: str) -> int:
    """Count leading ASCII spaces only (GHA YAML indent)."""
    n = 0
    for ch in line:
        if ch == " ":
            n += 1
        else:
            break
    return n


def _extract_gha_job(ci_text: str, job_id: str) -> str | None:
    """Extract one top-level job block by exact id (indent 2). Not a full YAML parser."""
    m = re.search(rf"^  {re.escape(job_id)}:\s*$", ci_text, re.MULTILINE)
    if m is None:
        return None
    rest = ci_text[m.end() :]
    m2 = re.search(r"^  [A-Za-z0-9_-]+:\s*$", rest, re.MULTILINE)
    if m2 is None:
        return ci_text[m.start() :]
    return ci_text[m.start() : m.end() + m2.start()]


def _dedent_run_body(body_lines: list[str], min_indent: int) -> str:
    out: list[str] = []
    for line in body_lines:
        if not line.strip():
            out.append("")
            continue
        if _leading_spaces(line) >= min_indent:
            out.append(line[min_indent:])
        else:
            out.append(line.lstrip(" "))
    return "\n".join(out).rstrip() + ("\n" if body_lines else "")


def _extract_named_steps(
    job_text: str,
) -> dict[str, list[dict[str, str | None]]]:
    """Map step name -> run/control metadata for critical-step validation.

    Duplicate names produce multiple entries so callers can fail exact-once.
    Only records keys present on the step mapping (raw string values).
    """
    lines = job_text.splitlines()
    found: dict[str, list[dict[str, str | None]]] = {}
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)-\s+name:\s*(.+?)\s*$", lines[i])
        if m is None:
            i += 1
            continue
        step_indent = _leading_spaces(lines[i])
        name = m.group(2).strip()
        i += 1
        run_body: str | None = None
        step_if: str | None = None
        step_coe: str | None = None
        step_shell: str | None = None
        extra_keys: list[str] = []
        while i < len(lines):
            line = lines[i]
            # Next list item at same indent ends this step.
            if re.match(rf"^{' ' * step_indent}-\s+", line):
                break
            # Next top-level job key (2 spaces, not deeper).
            if re.match(r"^  [A-Za-z0-9_-]+:\s*$", line) and step_indent >= 2:
                break
            # Step-level metadata (more indented than the list dash).
            meta_indent = _leading_spaces(line)
            if meta_indent > step_indent:
                key_m = re.match(r"^\s*([A-Za-z0-9_-]+):", line)
                if (
                    key_m is not None
                    and meta_indent == step_indent + 2
                    and key_m.group(1)
                    not in {"run", "if", "continue-on-error", "shell"}
                ):
                    extra_keys.append(key_m.group(1))
                if_m = re.match(r"^\s*if:\s*(.*)$", line)
                if if_m is not None:
                    step_if = if_m.group(1).strip()
                    i += 1
                    continue
                coe_m = re.match(r"^\s*continue-on-error:\s*(.*)$", line)
                if coe_m is not None:
                    step_coe = coe_m.group(1).strip()
                    i += 1
                    continue
                shell_m = re.match(r"^\s*shell:\s*(.*)$", line)
                if shell_m is not None:
                    step_shell = shell_m.group(1).strip()
                    i += 1
                    continue
            rm = re.match(r"^(\s*)run:\s*(\||>-|>)?\s*(.*)$", line)
            if rm is not None:
                run_indent = _leading_spaces(line)
                style = rm.group(2) or ""
                inline = (rm.group(3) or "").strip()
                i += 1
                if style in ("|", ">", ">-") or not inline:
                    body_lines: list[str] = []
                    content_indent = run_indent + 2
                    while i < len(lines):
                        bl = lines[i]
                        if bl.strip() == "":
                            body_lines.append("")
                            i += 1
                            continue
                        if _leading_spaces(bl) <= run_indent:
                            break
                        body_lines.append(bl)
                        i += 1
                    run_body = _dedent_run_body(body_lines, content_indent)
                else:
                    run_body = inline + "\n"
                # YAML mapping key order is not significant. Keep scanning the
                # same step so if:/continue-on-error: placed after run: cannot
                # bypass the critical-step metadata guard.
                continue
            i += 1
        found.setdefault(name, []).append(
            {
                "run": run_body if run_body is not None else "",
                "if": step_if,
                "continue_on_error": step_coe,
                "shell": step_shell,
                "extra_keys": ",".join(extra_keys) if extra_keys else None,
            }
        )
    return found


def _extract_named_step_runs(job_text: str) -> dict[str, list[str]]:
    """Compatibility helper: name -> list of run bodies only."""
    raw = _extract_named_steps(job_text)
    return {k: [str(e.get("run") or "") for e in v] for k, v in raw.items()}


def _join_shell_continuations(script: str) -> list[str]:
    """Join backslash-continued lines; drop blanks and full-line # comments."""
    joined: list[str] = []
    buf = ""
    for raw in script.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if line.endswith("\\"):
            buf += line[:-1].rstrip() + " "
            continue
        buf += line
        piece = " ".join(buf.split())
        if piece and not piece.startswith("#"):
            joined.append(piece)
        buf = ""
    if buf.strip():
        piece = " ".join(buf.split())
        if piece and not piece.startswith("#"):
            joined.append(piece)
    return joined


def _job_metadata_errors(job_text: str) -> list[str]:
    """Pin the GCC authority job runner/shell and reject control overrides."""
    errors: list[str] = []
    allowed = {"name", "runs-on", "timeout-minutes", "defaults", "steps"}
    for line in job_text.splitlines()[1:]:
        # Job-level keys are indent 4 under the job id (indent 2). YAML mapping
        # key order is not significant, so inspect both before and after steps:.
        key_m = re.match(r"^    ([A-Za-z0-9_-]+):(?:\s*(.*))?$", line)
        if key_m is None:
            continue
        key = key_m.group(1)
        value = (key_m.group(2) or "").strip()
        if key == "if":
            errors.append(
                f"job {GCC_AUTHORITY_JOB} must not set job-level if: "
                f"(got {line.strip()!r})"
            )
        elif key not in allowed:
            errors.append(
                f"job {GCC_AUTHORITY_JOB} has forbidden job-level key {key!r}"
            )
        elif key == "runs-on" and value != "ubuntu-24.04":
            errors.append(
                f"job {GCC_AUTHORITY_JOB} runs-on must be ubuntu-24.04, "
                f"got {value!r}"
            )
    shell_block = (
        "    defaults:\n"
        "      run:\n"
        f"        shell: {GCC_AUTHORITY_SHELL}\n"
    )
    if job_text.count(shell_block) != 1:
        errors.append(
            f"job {GCC_AUTHORITY_JOB} must define exact-once defaults.run.shell "
            f"as {GCC_AUTHORITY_SHELL!r}"
        )
    return errors


def _critical_step_meta_errors(
    step_name: str, step: dict[str, str | None]
) -> list[str]:
    """Critical steps must not set if: or continue-on-error:."""
    errors: list[str] = []
    if step.get("if") is not None:
        errors.append(
            f"step {step_name!r} must not set if: (got {step['if']!r})"
        )
    if step.get("continue_on_error") is not None:
        errors.append(
            f"step {step_name!r} must not set continue-on-error: "
            f"(got {step['continue_on_error']!r})"
        )
    if step.get("shell") is not None:
        errors.append(
            f"step {step_name!r} must not override shell: "
            f"(got {step['shell']!r})"
        )
    if step.get("extra_keys") is not None:
        errors.append(
            f"step {step_name!r} has forbidden extra metadata keys: "
            f"{step['extra_keys']!r}"
        )
    return errors


def _exact_command_tuple_errors(
    script: str, expected: tuple[str, ...], label: str
) -> list[str]:
    """Require exact equality of normalized joined command tuples."""
    got = tuple(_join_shell_continuations(script))
    if got == expected:
        return []
    # Concise mismatch: lengths + first differing index.
    detail = f"len got={len(got)} expected={len(expected)}"
    for i, (a, b) in enumerate(zip(got, expected)):
        if a != b:
            detail += f"; first_diff@{i} got={a!r} expected={b!r}"
            break
    else:
        if len(got) != len(expected):
            detail += "; prefix matches but length differs"
    return [f"{label}: run command tuple mismatch ({detail})"]


def ci_gcc_release_structure_errors(ci_text: str) -> list[str]:
    """GCC Release job: O2/export + exact named step run-script authority."""
    errors: list[str] = []
    # Preserve existing O2 / export structure checks (whole-file token presence).
    if "CMAKE_C_FLAGS_RELEASE" not in ci_text:
        errors.append(
            "ci.yml missing CMAKE_C_FLAGS_RELEASE (GCC Release -O2 authority)"
        )
    o2_patterns = (
        'CMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG"',
        "CMAKE_C_FLAGS_RELEASE=-O2 -DNDEBUG",
        'CMAKE_C_FLAGS_RELEASE=-O2\\ -DNDEBUG',
        "CMAKE_C_FLAGS_RELEASE:STRING=-O2 -DNDEBUG",
        "CMAKE_C_FLAGS_RELEASE='-O2 -DNDEBUG'",
    )
    if not any(p in ci_text for p in o2_patterns):
        if (
            "-DCMAKE_C_FLAGS_RELEASE=-O2" not in ci_text
            and 'DCMAKE_C_FLAGS_RELEASE="-O2' not in ci_text
            and "DCMAKE_C_FLAGS_RELEASE='-O2" not in ci_text
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

    job = _extract_gha_job(ci_text, GCC_AUTHORITY_JOB)
    if job is None:
        errors.append(f"ci.yml missing exact job {GCC_AUTHORITY_JOB}")
        return errors

    errors.extend(_job_metadata_errors(job))

    steps = _extract_named_steps(job)
    for step_name, expected in (
        (STEP_NEG_CONFIGURE, CANONICAL_NEG_CONFIGURE_COMMANDS),
        (STEP_R7_STACK, CANONICAL_R7_STACK_COMMANDS),
    ):
        entries = steps.get(step_name)
        if entries is None:
            errors.append(
                f"ci.yml job {GCC_AUTHORITY_JOB} missing exact step name "
                f"{step_name!r}"
            )
            continue
        if len(entries) != 1:
            errors.append(
                f"ci.yml step {step_name!r} must appear exact-once, "
                f"found {len(entries)}"
            )
            continue
        step = entries[0]
        errors.extend(_critical_step_meta_errors(step_name, step))
        body = str(step.get("run") or "")
        if not body.strip():
            errors.append(f"ci.yml step {step_name!r} has empty run script")
            continue
        errors.extend(
            _exact_command_tuple_errors(body, expected, f"step {step_name!r}")
        )
    return errors


def run_check(
    su_dir: pathlib.Path,
    compile_commands: pathlib.Path | None = None,
    *,
    require_maccumulate_outgoing_args: bool = False,
) -> int:
    try:
        cmake_text = CMAKE.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"r7 crypto stack gate FAIL: cannot read CMakeLists.txt: {exc}", file=sys.stderr)
        return 1
    errors = structural_errors(cmake_text) + artifact_errors(su_dir)
    if compile_commands is not None:
        errors.extend(
            compile_commands_errors(
                compile_commands,
                require_maccumulate_outgoing_args=require_maccumulate_outgoing_args,
            )
        )
    if errors:
        for error in errors:
            print(f"r7 crypto stack gate FAIL: {error}", file=sys.stderr)
        return 1
    extra = ""
    if compile_commands is not None:
        extra = " compile_commands=-O2+-fstack-usage"
        if require_maccumulate_outgoing_args:
            extra += "+maccumulate"
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

    # --- optional maccumulate compile_commands evidence ---
    def _cc_errs_macc(entries: list[dict]) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="r7-cc-macc-") as td:
            path = pathlib.Path(td) / "compile_commands.json"
            path.write_text(json.dumps(entries), encoding="utf-8")
            return compile_commands_errors(
                path, require_maccumulate_outgoing_args=True
            )

    good_macc_cmd = (
        "cc -O2 -DNDEBUG -fstack-usage -Wframe-larger-than=2560 "
        f"{MACCUMULATE_FLAG} "
        "-c /tmp/src/radio/{src} -o /tmp/{src}.o"
    )
    good_macc_cc = [
        _entry("r7_crypto_portable.c", good_macc_cmd.format(src="r7_crypto_portable.c")),
        _entry("r7_crypto_nonce.c", good_macc_cmd.format(src="r7_crypto_nonce.c")),
    ]
    if _cc_errs_macc(good_macc_cc):
        failures.append(
            f"require-maccumulate baseline red: {_cc_errs_macc(good_macc_cc)}"
        )
    # Without the flag, default compile_commands_errors stays green (portable).
    if _cc_errs(good_macc_cc):
        failures.append(
            f"default compile_commands rejected maccumulate-bearing cmd: "
            f"{_cc_errs(good_macc_cc)}"
        )
    # Missing maccumulate under require → RED (good_cmd has none).
    if not _cc_errs_macc(good_cc):
        failures.append("require-maccumulate missing flag did not go red")
    # Duplicate maccumulate → RED.
    dup_macc = [
        _entry(
            "r7_crypto_portable.c",
            "cc -O2 -DNDEBUG -fstack-usage "
            f"{MACCUMULATE_FLAG} {MACCUMULATE_FLAG} "
            "-c /tmp/src/radio/r7_crypto_portable.c -o x.o",
        ),
        _entry("r7_crypto_nonce.c", good_macc_cmd.format(src="r7_crypto_nonce.c")),
    ]
    if not _cc_errs_macc(dup_macc):
        failures.append("require-maccumulate duplicate flag did not go red")

    # CLI misuse: require without --compile-commands must fail-closed.
    import subprocess

    gate_py = str(pathlib.Path(__file__).resolve())

    def _cli(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, gate_py, *args],
            capture_output=True,
            text=True,
        )

    cli = _cli(["check", "--su-dir", "/tmp", REQUIRE_MACCUMULATE_CLI])
    if cli.returncode == 0:
        failures.append(
            "CLI --require-maccumulate-outgoing-args without "
            "--compile-commands did not fail"
        )

    # P2: check-only options with self-test must parser.error (rc 2).
    for label, args in (
        ("self-test+require", ["self-test", REQUIRE_MACCUMULATE_CLI]),
        (
            "self-test+compile-commands",
            ["self-test", "--compile-commands", "/tmp/missing.json"],
        ),
        ("self-test+su-dir", ["self-test", "--su-dir", "/tmp"]),
    ):
        p = _cli(args)
        if p.returncode != 2:
            failures.append(
                f"CLI {label} expected rc=2, got {p.returncode}"
            )

    # Minimal O2/export smoke (still required).
    bad_ci = (
        "ubuntu-gcc-release-n6-frame:\n"
        "  steps:\n"
        "    - run: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release\n"
    )
    if not ci_gcc_release_structure_errors(bad_ci):
        failures.append("ci structure missing O2 did not go red")

    # Real ci.yml must be green under step-scoped authority.
    if not CI_YML.is_file():
        failures.append("ci.yml missing for structure self-test")
    else:
        real_ci = CI_YML.read_text(encoding="utf-8")
        real_ci_errs = ci_gcc_release_structure_errors(real_ci)
        if real_ci_errs:
            failures.append(
                "ci.yml GCC Release structure still red: "
                + "; ".join(real_ci_errs)
            )
        else:
            # Three independent false-green decoys must go RED.
            # (1) remove require from real gate; echo the flag instead
            # (also drop trailing \ on prior line so it cannot glue into echo).
            decoy1 = real_ci.replace(
                "            --compile-commands \"$cc\" \\\n"
                "            --require-maccumulate-outgoing-args\n",
                "            --compile-commands \"$cc\"\n"
                '          echo "--require-maccumulate-outgoing-args"\n',
                1,
            )
            if decoy1 == real_ci:
                failures.append("decoy1 mutation did not edit require flag line")
            elif not ci_gcc_release_structure_errors(decoy1):
                failures.append(
                    "decoy1: echo require-flag without gate arg stayed green"
                )

            # (2) replace fatal grep with echo of the fatal string.
            decoy2 = real_ci.replace(
                "          if ! grep -F 'GNU x86/x86_64 host requires "
                "-maccumulate-outgoing-args' \\\n"
                '               "$log"; then\n',
                "          if ! echo 'GNU x86/x86_64 host requires "
                "-maccumulate-outgoing-args'; then\n",
                1,
            )
            if decoy2 == real_ci:
                # fallback: coarser replace of grep line only
                decoy2 = real_ci.replace(
                    "grep -F 'GNU x86/x86_64 host requires "
                    "-maccumulate-outgoing-args'",
                    "echo 'GNU x86/x86_64 host requires "
                    "-maccumulate-outgoing-args'",
                    1,
                )
            if decoy2 == real_ci:
                failures.append("decoy2 mutation did not edit grep fatal line")
            elif not ci_gcc_release_structure_errors(decoy2):
                failures.append(
                    "decoy2: echo fatal-reason without grep stayed green"
                )

            # (3) delete negative configure step; fake step echoes three strings.
            job = _extract_gha_job(real_ci, GCC_AUTHORITY_JOB)
            if job is None:
                failures.append("decoy3: cannot extract GCC authority job")
            else:
                # Drop the whole named negative step (name + run block).
                step_pat = re.compile(
                    r"^      - name: "
                    + re.escape(STEP_NEG_CONFIGURE)
                    + r"\n"
                    r"        run: \|\n"
                    r"(?:          .*\n)*",
                    re.MULTILINE,
                )
                decoy3_job, n_sub = step_pat.subn(
                    "      - name: "
                    + STEP_NEG_CONFIGURE
                    + "\n"
                    "        run: |\n"
                    "          echo "
                    f"'{NEGATIVE_PROBE_CACHE}'\n"
                    "          echo "
                    f"'{MACCUMULATE_FATAL_REASON}'\n"
                    "          echo "
                    "'build/ci-ubuntu-gcc-rel-n6-macc-neg'\n",
                    job,
                    count=1,
                )
                if n_sub != 1:
                    failures.append(
                        "decoy3 mutation did not replace negative configure once"
                    )
                else:
                    decoy3 = real_ci.replace(job, decoy3_job, 1)
                    if not ci_gcc_release_structure_errors(decoy3):
                        failures.append(
                            "decoy3: fake echo-only negative step stayed green"
                        )

            # Five bypasses that soft checkers used to miss — all must RED.
            # (B1) job-level if: false
            b1 = real_ci.replace(
                f"  {GCC_AUTHORITY_JOB}:\n",
                f"  {GCC_AUTHORITY_JOB}:\n    if: false\n",
                1,
            )
            if b1 == real_ci or not ci_gcc_release_structure_errors(b1):
                failures.append(
                    "bypass job if:false stayed green or mutation failed"
                )

            # (B2) R7 critical step if: false
            b2 = real_ci.replace(
                f"      - name: {STEP_R7_STACK}\n        run: |\n",
                f"      - name: {STEP_R7_STACK}\n"
                "        if: false\n"
                "        run: |\n",
                1,
            )
            if b2 == real_ci or not ci_gcc_release_structure_errors(b2):
                failures.append(
                    "bypass R7 step if:false stayed green or mutation failed"
                )

            # (B3) R7 continue-on-error: true
            b3 = real_ci.replace(
                f"      - name: {STEP_R7_STACK}\n        run: |\n",
                f"      - name: {STEP_R7_STACK}\n"
                "        continue-on-error: true\n"
                "        run: |\n",
                1,
            )
            if b3 == real_ci or not ci_gcc_release_structure_errors(b3):
                failures.append(
                    "bypass R7 continue-on-error:true stayed green "
                    "or mutation failed"
                )

            # (B4) gate command suffixed with || true
            b4 = real_ci.replace(
                "            --require-maccumulate-outgoing-args\n",
                "            --require-maccumulate-outgoing-args || true\n",
                1,
            )
            if b4 == real_ci or not ci_gcc_release_structure_errors(b4):
                failures.append(
                    "bypass gate || true stayed green or mutation failed"
                )

            # (B5) wrap gate invocation in if false; then ... fi
            b5 = real_ci.replace(
                "          python3 tools/r7_crypto_stack_gate.py check \\\n"
                "            --su-dir \"$su\" \\\n"
                "            --compile-commands \"$cc\" \\\n"
                "            --require-maccumulate-outgoing-args\n",
                "          if false; then\n"
                "          python3 tools/r7_crypto_stack_gate.py check \\\n"
                "            --su-dir \"$su\" \\\n"
                "            --compile-commands \"$cc\" \\\n"
                "            --require-maccumulate-outgoing-args\n"
                "          fi\n",
                1,
            )
            if b5 == real_ci or not ci_gcc_release_structure_errors(b5):
                failures.append(
                    "bypass if-false wrapper around gate stayed green "
                    "or mutation failed"
                )

            # (B6) job-level if after steps (YAML mapping order is arbitrary)
            real_job = _extract_gha_job(real_ci, GCC_AUTHORITY_JOB)
            if real_job is None:
                failures.append("bypass job-if-after: cannot extract GCC job")
            else:
                b6 = real_ci.replace(real_job, real_job + "    if: false\n", 1)
                if b6 == real_ci or not ci_gcc_release_structure_errors(b6):
                    failures.append(
                        "bypass job if:false after steps stayed green "
                        "or mutation failed"
                    )

            # (B7) step continue-on-error after run block
            b7 = real_ci.replace(
                "            --require-maccumulate-outgoing-args\n",
                "            --require-maccumulate-outgoing-args\n"
                "        continue-on-error: true\n",
                1,
            )
            if b7 == real_ci or not ci_gcc_release_structure_errors(b7):
                failures.append(
                    "bypass R7 continue-on-error after run stayed green "
                    "or mutation failed"
                )

            # (B8) job default shell replaced with a no-op interpreter.
            authority_job = _extract_gha_job(real_ci, GCC_AUTHORITY_JOB)
            if authority_job is None:
                failures.append("bypass job-shell: cannot extract GCC job")
            else:
                b8_job = authority_job.replace(
                    f"        shell: {GCC_AUTHORITY_SHELL}\n",
                    "        shell: true {0}\n",
                    1,
                )
                b8 = real_ci.replace(authority_job, b8_job, 1)
                if (
                    b8_job == authority_job
                    or not ci_gcc_release_structure_errors(b8)
                ):
                    failures.append(
                        "bypass job defaults shell:true stayed green "
                        "or mutation failed"
                    )

            # (B9) critical step overrides the pinned job shell.
            b9 = real_ci.replace(
                f"      - name: {STEP_R7_STACK}\n        run: |\n",
                f"      - name: {STEP_R7_STACK}\n"
                "        shell: true {0}\n"
                "        run: |\n",
                1,
            )
            if b9 == real_ci or not ci_gcc_release_structure_errors(b9):
                failures.append(
                    "bypass R7 step shell:true stayed green or mutation failed"
                )

            # (B10) job-level environment can redirect command/tool behavior.
            b10 = real_ci.replace(
                f"  {GCC_AUTHORITY_JOB}:\n",
                f"  {GCC_AUTHORITY_JOB}:\n"
                "    env:\n"
                "      BASH_ENV: /tmp/ci-bypass\n",
                1,
            )
            if b10 == real_ci or not ci_gcc_release_structure_errors(b10):
                failures.append(
                    "bypass job env stayed green or mutation failed"
                )

            # (B11) critical-step environment is forbidden as extra metadata.
            b11 = real_ci.replace(
                f"      - name: {STEP_R7_STACK}\n        run: |\n",
                f"      - name: {STEP_R7_STACK}\n"
                "        env:\n"
                "          BASH_ENV: /tmp/ci-bypass\n"
                "        run: |\n",
                1,
            )
            if b11 == real_ci or not ci_gcc_release_structure_errors(b11):
                failures.append(
                    "bypass R7 step env stayed green or mutation failed"
                )

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
    parser.add_argument(
        "--require-maccumulate-outgoing-args",
        dest="require_maccumulate_outgoing_args",
        action="store_true",
        default=False,
        help=(
            "with --compile-commands, require exact-one "
            f"{MACCUMULATE_FLAG} on each R7 production TU "
            "(GCC x86 authority only; not for Clang/ESP)"
        ),
    )
    args = parser.parse_args()
    if args.command == "self-test":
        # Check-only options must not be accepted with self-test (rc=2).
        if args.su_dir is not None:
            parser.error("self-test does not accept --su-dir")
        if args.compile_commands is not None:
            parser.error("self-test does not accept --compile-commands")
        if args.require_maccumulate_outgoing_args:
            parser.error(
                "self-test does not accept --require-maccumulate-outgoing-args"
            )
        return run_self_test()
    if args.command == "check":
        if args.su_dir is None:
            parser.error("check requires --su-dir")
        if args.require_maccumulate_outgoing_args and args.compile_commands is None:
            parser.error(
                "--require-maccumulate-outgoing-args requires --compile-commands"
            )
        return run_check(
            args.su_dir,
            args.compile_commands,
            require_maccumulate_outgoing_args=args.require_maccumulate_outgoing_args,
        )
    parser.error(f"unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
