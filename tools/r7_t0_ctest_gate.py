#!/usr/bin/env python3
"""Single authority for R7 T0 CTest registration + focused run (docs/31 §11).

CI must call this tool instead of duplicating required-name arrays. Profiles:

  normal     — full R7 set including production stack gate (exact once)
  sanitizer  — same set minus production r7_crypto_stack_gate (must be 0)

Commands:
  check-registration --build-dir DIR --profile normal|sanitizer
  run-focused        --build-dir DIR --profile normal|sanitizer
  self-test

PASS ≠ product GO / R7 complete / ESP HIL / T0 accepted.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# Required CTest names: exact set, exact once each. Order is documentation only.
R7_CORE_REQUIRED: tuple[str, ...] = (
    "r7_crypto_portable_strict",
    "r7_crypto_openssl3",
    "r7_crypto_vectors_bridge",
    "r7_crypto_zeroization_gate",
    "r7_crypto_zeroization_gate_self_test",
    "r7_radio_wire_oracle_self_test",
    "r7_radio_wire_oracle_verify",
    "r7_kat_pin",
    "r7_kat_pin_self_test",
    "r7_crypto_platform_split_gate",
    "r7_crypto_platform_split_gate_self_test",
    "r7_crypto_stack_gate_self_test",
    "r7_crypto_tests_off_packaging_gate",
    "r7_crypto_tests_off_packaging_gate_self_test",
    "r7_t0_ctest_gate_self_test",
)

# Production .su authority — registered only when sanitizers are OFF.
R7_PRODUCTION_STACK = "r7_crypto_stack_gate"

# Covers crypto/KAT/oracle/packaging plus the registration authority self-test.
R7_FOCUSED_REGEX = r"r7_(crypto_|kat_pin|radio_wire_oracle|t0_ctest_gate)"

_TEST_LINE = re.compile(r"^Test\s+#(?P<num>[0-9]+):\s+(?P<name>\S+)\s*$")


def required_for_profile(profile: str) -> tuple[str, ...]:
    if profile == "normal":
        return R7_CORE_REQUIRED + (R7_PRODUCTION_STACK,)
    if profile == "sanitizer":
        return R7_CORE_REQUIRED
    raise ValueError(f"unknown profile: {profile}")


def parse_ctest_listing(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        m = _TEST_LINE.match(line.strip())
        if m:
            names.append(m.group("name"))
    return names


def count_exact(names: list[str], required: str) -> int:
    return sum(1 for n in names if n == required)


def r7_registered_names(names: list[str]) -> list[str]:
    """All CTest names in the r7_* family (registration authority surface)."""
    return [n for n in names if n.startswith("r7_")]


def registration_errors(names: list[str], profile: str) -> list[str]:
    """Required names exact once AND registered r7_* set exact-equals profile.

    Presence-only checks are a false-green: an unexpected r7_* (e.g.
    r7_unexpected_test or a suffix copy like r7_crypto_openssl3_copy) would
    still pass if only required names are counted.
    """
    errors: list[str] = []
    required = required_for_profile(profile)
    required_set = set(required)

    for name in required:
        count = count_exact(names, name)
        if count != 1:
            errors.append(
                f"false-green: expected exactly one CTest '{name}', got {count}"
            )

    # Exact set: every registered r7_* must be in the profile expected set,
    # and every expected name must appear (already enforced above for count).
    registered = r7_registered_names(names)
    registered_set = set(registered)
    unexpected = sorted(registered_set - required_set)
    for name in unexpected:
        errors.append(
            f"false-green: unexpected r7_* CTest '{name}' "
            f"(not in profile={profile} exact set)"
        )
    missing = sorted(required_set - registered_set)
    for name in missing:
        # Already reported via count!=1 when absent; still explicit for set.
        if count_exact(names, name) == 0:
            errors.append(
                f"false-green: missing r7_* CTest '{name}' "
                f"from profile={profile} exact set"
            )

    # Multiset equality: duplicates of expected or unexpected both red.
    if len(registered) != len(required) or sorted(registered) != sorted(required):
        # Avoid pure-noise when missing/unexpected already listed; still catch
        # duplicates of an expected name (sorted multiset mismatch).
        reg_counts = Counter(registered)
        exp_counts = Counter(required)
        for name, cnt in sorted(reg_counts.items()):
            exp = exp_counts.get(name, 0)
            if cnt != exp:
                if name in required_set and cnt > 1:
                    errors.append(
                        f"false-green: r7_* multiset mismatch for '{name}': "
                        f"registered={cnt}, expected={exp}"
                    )
                elif name not in required_set:
                    # unexpected already listed; duplicate unexpected too
                    if cnt > 1:
                        errors.append(
                            f"false-green: duplicate unexpected r7_* '{name}' "
                            f"count={cnt}"
                        )

    # Production stack gate: normal=1, sanitizer=0 (not merely "in required").
    prod = count_exact(names, R7_PRODUCTION_STACK)
    if profile == "normal" and prod != 1:
        errors.append(
            f"false-green: production {R7_PRODUCTION_STACK} count={prod} "
            f"(profile=normal expects 1)"
        )
    if profile == "sanitizer" and prod != 0:
        errors.append(
            f"false-green: production {R7_PRODUCTION_STACK} count={prod} "
            f"(profile=sanitizer expects 0)"
        )
    # Duplicate detection for any required name (belt + suspenders).
    for name in required:
        if names.count(name) > 1:
            errors.append(f"duplicate CTest registration: {name}")
    return errors


def ctest_n(build_dir: Path) -> str:
    proc = subprocess.run(
        ["ctest", "--test-dir", str(build_dir), "-N"],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"ctest -N failed (rc={proc.returncode}):\n"
            f"{proc.stdout}\n{proc.stderr}"
        )
    return proc.stdout + proc.stderr


def run_check_registration(build_dir: Path, profile: str) -> int:
    try:
        listing = ctest_n(build_dir)
    except RuntimeError as exc:
        print(f"r7_t0_ctest_gate FAIL: {exc}", file=sys.stderr)
        return 1
    names = parse_ctest_listing(listing)
    errors = registration_errors(names, profile)
    if errors:
        for e in errors:
            print(f"r7_t0_ctest_gate FAIL: {e}", file=sys.stderr)
        r7_lines = [n for n in names if n.startswith("r7_")]
        if r7_lines:
            print("registered r7_* tests:", file=sys.stderr)
            for n in r7_lines:
                print(f"  {n}", file=sys.stderr)
        return 1
    required = required_for_profile(profile)
    registered = r7_registered_names(names)
    print(
        f"r7_t0_ctest_gate: registration PASS "
        f"(profile={profile}, required={len(required)}, "
        f"r7_registered={len(registered)}, exact_set=yes, "
        f"production_stack="
        f"{count_exact(names, R7_PRODUCTION_STACK)})"
    )
    return 0


def run_focused(build_dir: Path, profile: str) -> int:
    # Always re-check registration so focused run cannot green-wash a skip.
    rc = run_check_registration(build_dir, profile)
    if rc != 0:
        return rc
    proc = subprocess.run(
        [
            "ctest",
            "--test-dir",
            str(build_dir),
            "-R",
            R7_FOCUSED_REGEX,
            "--output-on-failure",
        ],
        check=False,
    )
    if proc.returncode != 0:
        print(
            f"r7_t0_ctest_gate FAIL: focused CTest rc={proc.returncode}",
            file=sys.stderr,
        )
        return proc.returncode
    print(
        f"r7_t0_ctest_gate: focused run PASS "
        f"(profile={profile}, -R {R7_FOCUSED_REGEX!r})"
    )
    return 0


def run_self_test() -> int:
    failures: list[str] = []

    # Required sets differ by exactly the production stack gate.
    normal = set(required_for_profile("normal"))
    sanitizer = set(required_for_profile("sanitizer"))
    if normal - sanitizer != {R7_PRODUCTION_STACK}:
        failures.append(
            f"profile delta must be exactly {{{R7_PRODUCTION_STACK}}}, "
            f"got {normal - sanitizer}"
        )
    if sanitizer - normal:
        failures.append(f"sanitizer has unexpected extras: {sanitizer - normal}")
    if R7_PRODUCTION_STACK in R7_CORE_REQUIRED:
        failures.append("production stack must not live in R7_CORE_REQUIRED")
    if len(R7_CORE_REQUIRED) != len(set(R7_CORE_REQUIRED)):
        failures.append("R7_CORE_REQUIRED has internal duplicates")

    # Synthetic normal listing: each required exact once → GREEN.
    normal_list = list(required_for_profile("normal"))
    if registration_errors(normal_list, "normal"):
        failures.append(f"normal baseline red: {registration_errors(normal_list, 'normal')}")

    # Drop one required → RED.
    missing = [n for n in normal_list if n != "r7_kat_pin"]
    if not registration_errors(missing, "normal"):
        failures.append("missing required name did not go red")

    # Duplicate → RED.
    dup = list(normal_list) + ["r7_crypto_openssl3"]
    if not registration_errors(dup, "normal"):
        failures.append("duplicate required name did not go red")

    # Sanitizer profile: production stack present → RED.
    san_with_prod = list(required_for_profile("sanitizer")) + [R7_PRODUCTION_STACK]
    if not registration_errors(san_with_prod, "sanitizer"):
        failures.append("sanitizer+production stack did not go red")

    # Sanitizer baseline without production stack → GREEN.
    san_ok = list(required_for_profile("sanitizer"))
    if registration_errors(san_ok, "sanitizer"):
        failures.append(f"sanitizer baseline red: {registration_errors(san_ok, 'sanitizer')}")

    # Normal without production stack → RED.
    normal_no_prod = list(required_for_profile("sanitizer"))
    if not registration_errors(normal_no_prod, "normal"):
        failures.append("normal without production stack did not go red")

    # Unexpected r7_* (not in authority) → RED even when all required present.
    with_unexpected = list(normal_list) + ["r7_unexpected_test"]
    if not registration_errors(with_unexpected, "normal"):
        failures.append("unexpected r7_* name did not go red")
    unexp_errs = registration_errors(with_unexpected, "normal")
    if not any("unexpected" in e and "r7_unexpected_test" in e for e in unexp_errs):
        failures.append(f"unexpected error text missing: {unexp_errs}")

    # Suffix copy of a required name → RED (exact set, not prefix match).
    with_suffix = list(normal_list) + ["r7_crypto_openssl3_copy"]
    if not registration_errors(with_suffix, "normal"):
        failures.append("suffix copy r7_* did not go red")
    suffix_errs = registration_errors(with_suffix, "normal")
    if not any("r7_crypto_openssl3_copy" in e for e in suffix_errs):
        failures.append(f"suffix copy error text missing: {suffix_errs}")

    # Non-r7 tests coexisting must not disturb exact r7_* set (GREEN).
    with_noise = list(normal_list) + ["n6_frame_stack_gate", "smoke_c11"]
    if registration_errors(with_noise, "normal"):
        failures.append(
            f"non-r7 noise incorrectly red: {registration_errors(with_noise, 'normal')}"
        )

    # Parser: only exact "Test #N: name" lines.
    sample = (
        "Test project /tmp/x\n"
        "  Test #1: r7_crypto_portable_strict\n"
        "  Test #2: r7_crypto_stack_gate\n"
        "Total Tests: 2\n"
    )
    parsed = parse_ctest_listing(sample)
    if parsed != ["r7_crypto_portable_strict", "r7_crypto_stack_gate"]:
        failures.append(f"parse_ctest_listing mismatch: {parsed}")

    # Packaging gates must be in the authority (cannot be forgotten by CI).
    for name in (
        "r7_crypto_tests_off_packaging_gate",
        "r7_crypto_tests_off_packaging_gate_self_test",
    ):
        if name not in R7_CORE_REQUIRED:
            failures.append(f"missing packaging gate in authority: {name}")

    if failures:
        for f in failures:
            print(f"r7_t0_ctest_gate self-test FAIL: {f}", file=sys.stderr)
        return 1
    print(
        f"r7_t0_ctest_gate self-test: PASS "
        f"(core={len(R7_CORE_REQUIRED)}, "
        f"normal={len(required_for_profile('normal'))}, "
        f"sanitizer={len(required_for_profile('sanitizer'))})"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_reg = sub.add_parser(
        "check-registration",
        help="assert required R7 CTest names exact once for profile",
    )
    p_reg.add_argument("--build-dir", type=Path, required=True)
    p_reg.add_argument(
        "--profile",
        choices=("normal", "sanitizer"),
        required=True,
    )

    p_run = sub.add_parser(
        "run-focused",
        help="check-registration then ctest -R focused R7 set",
    )
    p_run.add_argument("--build-dir", type=Path, required=True)
    p_run.add_argument(
        "--profile",
        choices=("normal", "sanitizer"),
        required=True,
    )

    sub.add_parser("self-test", help="mutation / authority self-test")

    args = parser.parse_args(argv)
    if args.command == "self-test":
        return run_self_test()
    build_dir = args.build_dir.resolve()
    if not build_dir.is_dir():
        print(
            f"r7_t0_ctest_gate FAIL: build dir missing: {build_dir}",
            file=sys.stderr,
        )
        return 1
    if args.command == "check-registration":
        return run_check_registration(build_dir, args.profile)
    if args.command == "run-focused":
        return run_focused(build_dir, args.profile)
    print(f"unknown command: {args.command}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
