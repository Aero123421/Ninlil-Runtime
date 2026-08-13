#!/usr/bin/env python3
"""Fail-closed lint for r7_frag host tests and their remote CI routing.

Rejects always-true assertions, over-broad multi-status OR chains, and loss of
the R7 issue-owner-state test from either normal or ASan host-matrix routing.

Forbidden:
  - expect_t("...", 1) / expect_t("...", 1u)  (constant true)
  - expect_t("...", true) with C true as literal 1 in second arg only
  - expect_t / expect_i conditions with 4+ status alternatives OR'd together
    when PROD_OK is one branch (masks R1/R2/N6 failures as green)

``self-test`` removes each required owner-state route and proves it is RED.
"""

from __future__ import annotations

import argparse
import re
import shlex
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_GLOBS = [
    "tests/radio/r7_frag/**/*.c",
]
MATRIX_SCRIPT = ROOT / "tools/ci_completion_feature_host_matrix.sh"
OWNER_TEST = "nrw1_r7_issue_owner_state_private"
OWNER_TARGET = "ninlil_r7_issue_owner_state_test"
MATRIX_FUNCTIONS = ("r7_frag_on_normal", "r7_frag_on_asan")

# expect_t("label", 1) or expect_t("label", 1u)
ALWAYS_TRUE = re.compile(
    r"""expect_t\s*\(\s*"[^"]*"\s*,\s*1u?\s*\)""",
    re.MULTILINE,
)

# Broad OR of many PROD status codes (4+ alternatives) — false-green risk
BROAD_OR = re.compile(
    r"""expect_[ti]\s*\([^;]*?
        (?:NINLIL_R7_FRAG_PROD_OK|NINLIL_R7_FRAG_SESS_OK)
        (?:\s*\|\|\s*st\s*==\s*NINLIL_R7_FRAG_(?:PROD|SESS)_\w+){3,}
    """,
    re.MULTILINE | re.DOTALL | re.VERBOSE,
)

# Soft optional failure markers that always pass
OPTIONAL_FAIL = re.compile(
    r"""expect_t\s*\(\s*"(?:[^"]*optional[^"]*|[^"]*may exhaust[^"]*)"\s*,\s*1u?\s*\)""",
    re.IGNORECASE,
)


def iter_test_files() -> list[Path]:
    out: list[Path] = []
    for g in TEST_GLOBS:
        out.extend(ROOT.glob(g))
    return sorted(set(out))


def test_lint_findings() -> list[str]:
    findings: list[str] = []
    for path in iter_test_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(ROOT)
        for m in ALWAYS_TRUE.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            findings.append(f"{rel}:{line}: always-true expect_t(..., 1)")
        for m in OPTIONAL_FAIL.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            findings.append(f"{rel}:{line}: optional always-true assert")
        for m in BROAD_OR.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = re.sub(r"\s+", " ", m.group(0))[:120]
            findings.append(
                f"{rel}:{line}: over-broad multi-status OR (false-green): {snippet}"
            )
    return findings


def function_body(source: str, name: str) -> str | None:
    match = re.search(
        rf"(?ms)^{re.escape(name)}\(\) \{{\n(?P<body>.*?)(?=^\}}\n)",
        source,
    )
    return None if match is None else match.group("body")


def shell_calls(body: str, command: str) -> list[list[str]]:
    logical = re.sub(r"\\\r?\n[ \t]*", " ", body)
    calls: list[list[str]] = []
    for line in logical.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            words = shlex.split(stripped, comments=True, posix=True)
        except ValueError:
            continue
        for index, word in enumerate(words):
            if word == command:
                calls.append(words[index + 1 :])
    return calls


def matrix_findings(source: str) -> list[str]:
    findings: list[str] = []
    for function_name in MATRIX_FUNCTIONS:
        body = function_body(source, function_name)
        if body is None:
            findings.append(f"matrix: missing function {function_name}")
            continue

        required = shell_calls(body, "require_tests_present")
        required_count = sum(args.count(OWNER_TEST) for args in required)
        if len(required) != 1 or required_count != 1:
            findings.append(
                f"matrix:{function_name}: require_tests_present must contain "
                f"exactly one {OWNER_TEST}"
            )

        builds = shell_calls(body, "build_targets_or_fail")
        build_count = sum(args.count(OWNER_TARGET) for args in builds)
        if build_count != 1:
            findings.append(
                f"matrix:{function_name}: build_targets_or_fail must contain "
                f"exactly one {OWNER_TARGET}"
            )

        selectors = shell_calls(body, "run_ctest_regex")
        if len(selectors) != 1 or not selectors[0]:
            findings.append(
                f"matrix:{function_name}: expected exactly one CTest selector"
            )
            continue
        selector = selectors[0][-1]
        try:
            matches_owner = re.fullmatch(selector, OWNER_TEST) is not None
        except re.error:
            matches_owner = False
        if selector.count(OWNER_TEST) != 1 or not matches_owner:
            findings.append(
                f"matrix:{function_name}: CTest selector must contain and match "
                f"exactly {OWNER_TEST}"
            )
    return findings


def replace_nth_in_function(
    source: str,
    function_name: str,
    needle: str,
    occurrence: int,
) -> str:
    body = function_body(source, function_name)
    if body is None:
        raise AssertionError(f"self-test fixture missing {function_name}")
    positions = [match.start() for match in re.finditer(re.escape(needle), body)]
    if occurrence >= len(positions):
        raise AssertionError(
            f"self-test fixture {function_name} missing occurrence {occurrence} "
            f"of {needle}"
        )
    offset = source.index(body) + positions[occurrence]
    return source[:offset] + source[offset + len(needle) :]


def self_test() -> None:
    source = MATRIX_SCRIPT.read_text(encoding="utf-8")
    baseline = matrix_findings(source)
    if baseline:
        raise AssertionError(f"matrix baseline must pass: {baseline}")

    mutations = (
        ("normal required", "r7_frag_on_normal", OWNER_TEST, 0),
        ("normal selector", "r7_frag_on_normal", OWNER_TEST, 1),
        ("normal build", "r7_frag_on_normal", OWNER_TARGET, 0),
        ("ASan required", "r7_frag_on_asan", OWNER_TEST, 0),
        ("ASan selector", "r7_frag_on_asan", OWNER_TEST, 1),
        ("ASan build", "r7_frag_on_asan", OWNER_TARGET, 0),
    )
    for label, function_name, needle, occurrence in mutations:
        mutant = replace_nth_in_function(
            source, function_name, needle, occurrence
        )
        if not matrix_findings(mutant):
            raise AssertionError(f"matrix deletion mutation stayed green: {label}")
        print(f"  deletion mutation '{label}' correctly failed")
    print("r7_frag_false_green_gate self-test: OK")


def run_check() -> int:
    findings = test_lint_findings()
    try:
        matrix_source = MATRIX_SCRIPT.read_text(encoding="utf-8")
    except OSError as exc:
        findings.append(f"matrix: cannot read {MATRIX_SCRIPT}: {exc}")
    else:
        findings.extend(matrix_findings(matrix_source))

    if findings:
        print("r7_frag_false_green_gate: FAIL", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("r7_frag_false_green_gate: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", nargs="?", choices=("check", "self-test"), default="check")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return 0
    return run_check()


if __name__ == "__main__":
    sys.exit(main())
