#!/usr/bin/env python3
"""Single authority for R7 T1b CTest registration + focused run (docs/33 §10).

Uses ``ctest --show-only=json-v1`` so registration is exact multiset **and**
free of skip/DISABLED/WILL_FAIL/PASS_REGULAR_EXPRESSION properties.

CTest names use ``nrw1_t1b_*`` so T0 ``r7_*`` exact 16/15 and T1 ``nrw1_t1_*``
exact 12/11 authorities are unchanged.

Profiles:
  normal     — full T1b set including production stack gate (13)
  sanitizer  — same set minus production stack gate (12)

Commands:
  check-registration --build-dir DIR --profile normal|sanitizer
  run-focused        --build-dir DIR --profile normal|sanitizer
  self-test

PASS ≠ product GO / R7 complete / ESP HIL / T1b Accepted.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[1]

# docs/33 §10 exact normal multiset (order of registration authority).
NRW1_T1B_CORE_REQUIRED: tuple[str, ...] = (
    "nrw1_t1b_binding_portable_strict",
    "nrw1_t1b_vectors_bridge",
    "nrw1_t1b_oracle_self_test",
    "nrw1_t1b_oracle_verify",
    "nrw1_t1b_kat_pin",
    "nrw1_t1b_kat_pin_self_test",
    "nrw1_t1b_platform_split_gate",
    "nrw1_t1b_platform_split_gate_self_test",
    "nrw1_t1b_tests_off_packaging_gate",
    "nrw1_t1b_tests_off_packaging_gate_self_test",
    "nrw1_t1b_ctest_gate_self_test",
    "nrw1_t1b_stack_gate_self_test",
)

NRW1_T1B_PRODUCTION_STACK = "nrw1_t1b_stack_gate"
NRW1_T1B_FOCUSED_REGEX = r"nrw1_t1b_"

# Prefixes that must never collide with T1b registration (authorities preserved).
FOREIGN_PREFIXES: tuple[str, ...] = (
    "r7_",  # T0 (except pure substring matches handled via startswith below)
    "nrw1_t1_",  # T1 — note nrw1_t1b_ does NOT start with nrw1_t1_ + end boundary
)

FORBIDDEN_SKIP_PROPERTIES: frozenset[str] = frozenset(
    {
        "DISABLED",
        "SKIP_RETURN_CODE",
        "SKIP_REGULAR_EXPRESSION",
        "SKIP_REGULAR_EXPRESSION_MATCH",
        "SKIP_RETURN_CODE_MATCH",
        "WILL_FAIL",
        "PASS_REGULAR_EXPRESSION",
    }
)


def required_for_profile(profile: str) -> tuple[str, ...]:
    if profile == "normal":
        return NRW1_T1B_CORE_REQUIRED + (NRW1_T1B_PRODUCTION_STACK,)
    if profile == "sanitizer":
        return NRW1_T1B_CORE_REQUIRED
    raise ValueError(f"unknown profile: {profile}")


def _truthy_disabled(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "on", "yes", "y"}
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return bool(value)


def properties_map(test: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    props = test.get("properties")
    if not isinstance(props, list):
        return out
    for item in props:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str) and name:
            out[name] = item.get("value")
    return out


def test_skip_property_errors(name: str, props: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key, value in props.items():
        upper = key.upper()
        if upper == "DISABLED" or key == "DISABLED":
            if _truthy_disabled(value):
                errors.append(
                    f"false-green: required test '{name}' has DISABLED={value!r}"
                )
            continue
        if upper == "WILL_FAIL" or key == "WILL_FAIL":
            if _truthy_disabled(value):
                errors.append(
                    f"false-green: required test '{name}' has WILL_FAIL={value!r}"
                )
            continue
        if upper in FORBIDDEN_SKIP_PROPERTIES or key in FORBIDDEN_SKIP_PROPERTIES:
            if upper in {"DISABLED", "WILL_FAIL"}:
                continue
            errors.append(
                f"false-green: required test '{name}' has skip property "
                f"{key}={value!r}"
            )
            continue
        if upper.startswith("SKIP_"):
            errors.append(
                f"false-green: required test '{name}' has skip-equivalent "
                f"property {key}={value!r}"
            )
    return errors


def is_t1b_name(name: str) -> bool:
    return name.startswith("nrw1_t1b_")


def registration_errors_from_tests(
    tests: list[dict[str, Any]], profile: str
) -> list[str]:
    errors: list[str] = []
    required = required_for_profile(profile)
    required_set = set(required)

    names: list[str] = []
    by_name: dict[str, list[dict[str, Any]]] = {}
    for test in tests:
        if not isinstance(test, dict):
            errors.append("false-green: non-object entry in ctest json tests[]")
            continue
        name = test.get("name")
        if not isinstance(name, str) or not name:
            errors.append("false-green: test entry missing name")
            continue
        names.append(name)
        by_name.setdefault(name, []).append(test)

    registered = [n for n in names if is_t1b_name(n)]
    registered_set = set(registered)

    for name in required:
        count = sum(1 for n in names if n == name)
        if count != 1:
            errors.append(
                f"false-green: expected exactly one CTest '{name}', got {count}"
            )

    for name in sorted(registered_set - required_set):
        errors.append(
            f"false-green: unexpected nrw1_t1b_* CTest '{name}' "
            f"(not in profile={profile} exact set)"
        )
    for name in sorted(required_set - registered_set):
        if sum(1 for n in names if n == name) == 0:
            errors.append(
                f"false-green: missing nrw1_t1b_* CTest '{name}' "
                f"from profile={profile} exact set"
            )

    if len(registered) != len(required) or sorted(registered) != sorted(required):
        reg_counts = Counter(registered)
        exp_counts = Counter(required)
        for name, cnt in sorted(reg_counts.items()):
            exp = exp_counts.get(name, 0)
            if cnt != exp and name in required_set and cnt > 1:
                errors.append(
                    f"false-green: nrw1_t1b_* multiset mismatch for '{name}': "
                    f"registered={cnt}, expected={exp}"
                )

    prod = sum(1 for n in names if n == NRW1_T1B_PRODUCTION_STACK)
    if profile == "normal" and prod != 1:
        errors.append(
            f"false-green: production {NRW1_T1B_PRODUCTION_STACK} count={prod} "
            f"(profile=normal expects 1)"
        )
    if profile == "sanitizer" and prod != 0:
        errors.append(
            f"false-green: production {NRW1_T1B_PRODUCTION_STACK} count={prod} "
            f"(profile=sanitizer expects 0)"
        )

    # Prefix-collision guard: T1b names must not be registered under T0/T1 sets.
    for name in registered:
        # nrw1_t1b_ is intentionally distinct from nrw1_t1_ (no shared prefix
        # boundary: 'nrw1_t1b_' does not start with 'nrw1_t1_' + non-b).
        if name.startswith("nrw1_t1_") and not name.startswith("nrw1_t1b_"):
            errors.append(f"false-green: T1 prefix collision '{name}'")

    for name in required:
        for test in by_name.get(name, []):
            props = properties_map(test)
            errors.extend(test_skip_property_errors(name, props))

    return errors


def load_ctest_json(build_dir: Path) -> dict[str, Any]:
    proc = subprocess.run(
        ["ctest", "--test-dir", str(build_dir), "--show-only=json-v1"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"ctest --show-only=json-v1 failed (rc={proc.returncode}):\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    text = proc.stdout.strip()
    if not text:
        raise RuntimeError("ctest --show-only=json-v1 produced empty stdout")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"ctest json-v1 parse failed: {exc}\nstdout head={text[:400]!r}"
        ) from exc
    if not isinstance(data, dict) or not isinstance(data.get("tests"), list):
        raise RuntimeError("ctest json-v1 missing tests[] array")
    return data


def run_check_registration(build_dir: Path, profile: str) -> int:
    try:
        data = load_ctest_json(build_dir)
    except RuntimeError as exc:
        print(f"r7_t1b_ctest_gate FAIL: {exc}", file=sys.stderr)
        return 1
    tests = data["tests"]
    assert isinstance(tests, list)
    errors = registration_errors_from_tests(tests, profile)
    if errors:
        for e in errors:
            print(f"r7_t1b_ctest_gate FAIL: {e}", file=sys.stderr)
        return 1
    required = required_for_profile(profile)
    registered = [
        t.get("name")
        for t in tests
        if isinstance(t, dict)
        and isinstance(t.get("name"), str)
        and is_t1b_name(t["name"])
    ]
    prod = sum(1 for n in registered if n == NRW1_T1B_PRODUCTION_STACK)
    print(
        f"r7_t1b_ctest_gate: registration PASS "
        f"(profile={profile}, required={len(required)}, "
        f"nrw1_t1b_registered={len(registered)}, exact_set=yes, "
        f"json-v1=yes, skip_props=clean, production_stack={prod})"
    )
    return 0


def run_focused(build_dir: Path, profile: str) -> int:
    rc = run_check_registration(build_dir, profile)
    if rc != 0:
        return rc
    proc = subprocess.run(
        [
            "ctest",
            "--test-dir",
            str(build_dir),
            "-R",
            NRW1_T1B_FOCUSED_REGEX,
            "--output-on-failure",
        ],
        check=False,
    )
    if proc.returncode != 0:
        print(
            f"r7_t1b_ctest_gate FAIL: focused CTest rc={proc.returncode}",
            file=sys.stderr,
        )
        return proc.returncode
    print(
        f"r7_t1b_ctest_gate: focused run PASS "
        f"(profile={profile}, -R {NRW1_T1B_FOCUSED_REGEX!r})"
    )
    return 0


def _synthetic_tests(names: list[str]) -> list[dict[str, Any]]:
    return [
        {
            "name": n,
            "command": ["true"],
            "properties": [{"name": "WORKING_DIRECTORY", "value": "/tmp"}],
        }
        for n in names
    ]


def _replace_nth(text: str, needle: str, replacement: str, ordinal: int) -> str:
    """Replace one exact occurrence, failing closed on source-shape drift."""
    positions: list[int] = []
    start = 0
    while True:
        pos = text.find(needle, start)
        if pos < 0:
            break
        positions.append(pos)
        start = pos + len(needle)
    if ordinal < 0 or ordinal >= len(positions):
        raise ValueError(
            f"mutation needle occurrence {ordinal} missing; count={len(positions)}"
        )
    pos = positions[ordinal]
    return text[:pos] + replacement + text[pos + len(needle) :]


def production_mutation_errors() -> list[str]:
    """Prove the portable test rejects the three audited production defects.

    This compiles the real portable test against a temporary copy of the
    production TU.  A compile failure is not accepted as a red test: every
    mutant must compile successfully and the resulting executable itself must
    fail.  Repository files are read-only throughout this check.
    """
    errors: list[str] = []
    compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if compiler is None:
        return ["production mutation gate requires cc, clang, or gcc on PATH"]

    source_path = REPO / "src" / "radio" / "r7_context_binding.c"
    test_path = REPO / "tests" / "radio" / "private" / "r7_t1b_binding_test.c"
    try:
        source = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return [f"cannot read production mutation source: {exc}"]

    copy_needle = "ninlil_r7_binding_copy(out, candidate, need);"
    compare_needle = "for (i = 0u; i < 32u; i++) {"
    if source.count(copy_needle) != 2:
        errors.append(
            "production mutation source-shape drift: exact encode publish "
            f"count want 2 got {source.count(copy_needle)}"
        )
    if source.count(compare_needle) != 1:
        errors.append(
            "production mutation source-shape drift: digest compare loop "
            f"count want 1 got {source.count(compare_needle)}"
        )
    if errors:
        return errors

    mutants: list[tuple[str, str]] = []
    for ordinal, layer in enumerate(("hop", "e2e")):
        mutants.append(
            (
                f"encode_overpublish_{layer}",
                _replace_nth(
                    source,
                    copy_needle,
                    "ninlil_r7_binding_copy(out, candidate, sizeof(candidate));",
                    ordinal,
                ),
            )
        )
    mutants.append(
        (
            "digest_compare_first_byte_only",
            _replace_nth(
                source,
                compare_needle,
                "for (i = 0u; i < 1u; i++) {",
                0,
            ),
        )
    )
    if len(mutants) != 3:
        return [f"production mutation count want 3 got {len(mutants)}"]

    with tempfile.TemporaryDirectory(prefix="nrw1-t1b-prod-mut-") as td:
        root = Path(td)
        common = [
            compiler,
            "-std=c11",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-Wvla",
            "-DNINLIL_R7_BINDING_TEST_BUILD=1",
            f"-I{REPO / 'src' / 'radio'}",
            str(test_path),
            str(REPO / "src" / "radio" / "r7_crypto_portable.c"),
            str(REPO / "src" / "radio" / "r7_crypto_nonce.c"),
        ]
        for label, mutated_source in mutants:
            mutant_c = root / f"r7_context_binding_{label}.c"
            binary = root / f"r7_t1b_{label}"
            mutant_c.write_text(mutated_source, encoding="utf-8")
            try:
                compile_proc = subprocess.run(
                    common + [str(mutant_c), "-o", str(binary)],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=30,
                )
            except subprocess.TimeoutExpired:
                errors.append(
                    f"production mutation {label} compile timed out after 30s"
                )
                continue
            if compile_proc.returncode != 0:
                errors.append(
                    f"production mutation {label} did not compile; a compile "
                    f"failure is not accepted as detection:\n{compile_proc.stdout}\n"
                    f"{compile_proc.stderr}"
                )
                continue
            try:
                run_proc = subprocess.run(
                    [str(binary)],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
            except subprocess.TimeoutExpired:
                errors.append(
                    f"production mutation {label} execution timed out after 10s"
                )
                continue
            if run_proc.returncode == 0:
                errors.append(
                    f"production mutation {label} false-green: portable test "
                    f"returned 0; stdout={run_proc.stdout!r} stderr={run_proc.stderr!r}"
                )
    return errors


def run_self_test() -> int:
    failures: list[str] = []
    normal = set(required_for_profile("normal"))
    sanitizer = set(required_for_profile("sanitizer"))
    if normal - sanitizer != {NRW1_T1B_PRODUCTION_STACK}:
        failures.append("profile delta must be exactly production stack")
    if sanitizer - normal:
        failures.append("sanitizer has unexpected extras")
    if NRW1_T1B_PRODUCTION_STACK in NRW1_T1B_CORE_REQUIRED:
        failures.append("production stack must not live in core")
    if len(required_for_profile("normal")) != 13:
        failures.append(
            f"normal count want 13 got {len(required_for_profile('normal'))}"
        )
    if len(required_for_profile("sanitizer")) != 12:
        failures.append(
            f"sanitizer count want 12 got {len(required_for_profile('sanitizer'))}"
        )

    normal_list = list(required_for_profile("normal"))
    if registration_errors_from_tests(_synthetic_tests(normal_list), "normal"):
        failures.append(
            "normal baseline red: "
            f"{registration_errors_from_tests(_synthetic_tests(normal_list), 'normal')}"
        )
    missing = [n for n in normal_list if n != "nrw1_t1b_kat_pin"]
    if not registration_errors_from_tests(_synthetic_tests(missing), "normal"):
        failures.append("missing required did not go red")
    dup = list(normal_list) + ["nrw1_t1b_vectors_bridge"]
    if not registration_errors_from_tests(_synthetic_tests(dup), "normal"):
        failures.append("duplicate did not go red")
    san_with_prod = list(required_for_profile("sanitizer")) + [
        NRW1_T1B_PRODUCTION_STACK
    ]
    if not registration_errors_from_tests(
        _synthetic_tests(san_with_prod), "sanitizer"
    ):
        failures.append("sanitizer+stack did not go red")
    if registration_errors_from_tests(
        _synthetic_tests(list(required_for_profile("sanitizer"))), "sanitizer"
    ):
        failures.append("sanitizer baseline red")
    if not registration_errors_from_tests(
        _synthetic_tests(list(required_for_profile("sanitizer"))), "normal"
    ):
        failures.append("normal without stack did not go red")
    with_unexpected = list(normal_list) + ["nrw1_t1b_unexpected_test"]
    if not registration_errors_from_tests(
        _synthetic_tests(with_unexpected), "normal"
    ):
        failures.append("unexpected name did not go red")
    # T0/T1 noise must not be counted as T1b.
    with_noise = list(normal_list) + [
        "r7_crypto_portable_strict",
        "nrw1_t1_wire_portable_strict",
        "n6_frame_stack_gate",
    ]
    if registration_errors_from_tests(_synthetic_tests(with_noise), "normal"):
        failures.append("non-nrw1_t1b noise incorrectly red")

    # Profile drift: rename one required test.
    drifted = [
        ("nrw1_t1b_oracle_verify" if n != "nrw1_t1b_oracle_verify" else "nrw1_t1b_oracle_verify_v2")
        if n == "nrw1_t1b_oracle_verify"
        else n
        for n in normal_list
    ]
    if not registration_errors_from_tests(_synthetic_tests(drifted), "normal"):
        failures.append("profile name drift did not go red")

    disabled_tests = _synthetic_tests(normal_list)
    for t in disabled_tests:
        if t["name"] == "nrw1_t1b_vectors_bridge":
            t["properties"].append({"name": "DISABLED", "value": True})
    errs_dis = registration_errors_from_tests(disabled_tests, "normal")
    if not any("DISABLED" in e for e in errs_dis):
        failures.append(f"DISABLED=true mutation did not go red: {errs_dis}")

    skip_rc_tests = _synthetic_tests(normal_list)
    for t in skip_rc_tests:
        if t["name"] == "nrw1_t1b_oracle_self_test":
            t["properties"].append({"name": "SKIP_RETURN_CODE", "value": 77})
    errs_src = registration_errors_from_tests(skip_rc_tests, "normal")
    if not any("SKIP_RETURN_CODE" in e for e in errs_src):
        failures.append(f"SKIP_RETURN_CODE mutation did not go red: {errs_src}")

    skip_re_tests = _synthetic_tests(normal_list)
    for t in skip_re_tests:
        if t["name"] == "nrw1_t1b_kat_pin":
            t["properties"].append(
                {"name": "SKIP_REGULAR_EXPRESSION", "value": "SKIPME"}
            )
    errs_sre = registration_errors_from_tests(skip_re_tests, "normal")
    if not any("SKIP_REGULAR_EXPRESSION" in e for e in errs_sre):
        failures.append(
            f"SKIP_REGULAR_EXPRESSION mutation did not go red: {errs_sre}"
        )

    pass_re_tests = _synthetic_tests(normal_list)
    for t in pass_re_tests:
        if t["name"] == "nrw1_t1b_binding_portable_strict":
            t["properties"].append(
                {"name": "PASS_REGULAR_EXPRESSION", "value": "MAGIC"}
            )
    errs_pre = registration_errors_from_tests(pass_re_tests, "normal")
    if not any("PASS_REGULAR_EXPRESSION" in e for e in errs_pre):
        failures.append(
            f"PASS_REGULAR_EXPRESSION mutation did not go red: {errs_pre}"
        )

    will_fail_tests = _synthetic_tests(normal_list)
    for t in will_fail_tests:
        if t["name"] == "nrw1_t1b_platform_split_gate":
            t["properties"].append({"name": "WILL_FAIL", "value": True})
    errs_wf = registration_errors_from_tests(will_fail_tests, "normal")
    if not any("WILL_FAIL" in e for e in errs_wf):
        failures.append(f"WILL_FAIL=true mutation did not go red: {errs_wf}")

    cmake = shutil.which("cmake")
    ctest = shutil.which("ctest")
    if not cmake or not ctest:
        failures.append(
            "cmake/ctest missing on PATH — integration mutation cannot skip "
            f"(cmake={cmake!r}, ctest={ctest!r})"
        )
    else:
        prop_cases = (
            ("DISABLED", "TRUE"),
            ("SKIP_RETURN_CODE", "77"),
            ("SKIP_REGULAR_EXPRESSION", "SKIPME"),
            ("PASS_REGULAR_EXPRESSION", "MAGIC"),
            ("WILL_FAIL", "TRUE"),
        )
        for prop_name, prop_value in prop_cases:
            try:
                with tempfile.TemporaryDirectory(prefix="nrw1-t1b-ctest-mut-") as td:
                    root = Path(td)
                    src = root / "src"
                    build = root / "build"
                    src.mkdir()
                    names_cmake = "\n".join(
                        f'  "{n}"' for n in required_for_profile("normal")
                    )
                    (src / "CMakeLists.txt").write_text(
                        textwrap.dedent(
                            f"""\
                            cmake_minimum_required(VERSION 3.16)
                            project(nrw1_t1b_gate_mutation LANGUAGES NONE)
                            enable_testing()
                            set(_names
                            {names_cmake}
                            )
                            foreach(_n IN LISTS _names)
                              add_test(NAME "${{_n}}" COMMAND "${{CMAKE_COMMAND}}" -E true)
                            endforeach()
                            set_tests_properties(nrw1_t1b_vectors_bridge PROPERTIES
                              {prop_name} {prop_value})
                            """
                        ),
                        encoding="utf-8",
                    )
                    gen = "Ninja" if shutil.which("ninja") else "Unix Makefiles"
                    conf = subprocess.run(
                        [cmake, "-S", str(src), "-B", str(build), "-G", gen],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if conf.returncode != 0:
                        failures.append(
                            f"integration configure failed for {prop_name}: "
                            f"{conf.stdout}\n{conf.stderr}"
                        )
                        continue
                    data = load_ctest_json(build)
                    tests = data["tests"]
                    assert isinstance(tests, list)
                    errs = registration_errors_from_tests(tests, "normal")
                    if not any(prop_name in e for e in errs):
                        failures.append(
                            f"integration {prop_name} mutation not red via "
                            f"json-v1: {errs}"
                        )
            except Exception as exc:  # noqa: BLE001 — self-test must not skip
                failures.append(
                    f"integration mutation {prop_name} raised: {exc}"
                )

    failures.extend(production_mutation_errors())

    if failures:
        for f in failures:
            print(f"r7_t1b_ctest_gate self-test FAIL: {f}", file=sys.stderr)
        return 1
    print(
        f"r7_t1b_ctest_gate self-test: PASS "
        f"(core={len(NRW1_T1B_CORE_REQUIRED)}, "
        f"normal={len(required_for_profile('normal'))}, "
        f"sanitizer={len(required_for_profile('sanitizer'))}, "
        f"json-v1+skip/PASS_REGEX/WILL_FAIL+cmake-integration=yes, "
        f"production_mutations=3)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p_reg = sub.add_parser("check-registration")
    p_reg.add_argument("--build-dir", type=Path, required=True)
    p_reg.add_argument("--profile", choices=("normal", "sanitizer"), required=True)
    p_run = sub.add_parser("run-focused")
    p_run.add_argument("--build-dir", type=Path, required=True)
    p_run.add_argument("--profile", choices=("normal", "sanitizer"), required=True)
    sub.add_parser("self-test")
    args = parser.parse_args(argv)
    if args.command == "self-test":
        return run_self_test()
    build_dir = args.build_dir.resolve()
    if not build_dir.is_dir():
        print(
            f"r7_t1b_ctest_gate FAIL: build dir missing: {build_dir}",
            file=sys.stderr,
        )
        return 1
    if args.command == "check-registration":
        return run_check_registration(build_dir, args.profile)
    if args.command == "run-focused":
        return run_focused(build_dir, args.profile)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
