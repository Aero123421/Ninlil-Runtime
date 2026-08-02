#!/usr/bin/env python3
"""Fail-closed release distribution authority (ordered checks).

Runs the closed release-authority surface in fixed order so CI/CTest cannot
skip a later gate when an earlier one is green alone:

  1. release_forbidden_vocabulary_gate (source tree denylist)
  2. release_archive_payload_gate self-test (includes gate-source scan + two-run)
  3. release_archive_payload_gate check --two-run (worktree archive)
  4. release_archive_payload_gate build-from-git --two-run (commit tree archive)
  5. posix_lab_tests_off_surface_gate (tests-OFF no tests/support)
  6. markdown_link_gate
  7. compatibility_matrix_gate
  8. third_party_notice_gate
  9. release_version_identity self-test + print-core
 10. release_workflow_identity_gate
 11. spdx_release_sbom self-test
 12. esp_idf_sdk_public_boundary_gate
 13. m1a_public_family_docs_gate

``cleanroom`` additionally runs from-release-archive unpack→build→package.

Does not claim external GitHub CI green until a push is observed.
"""

from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
PY = sys.executable

# Fail-closed order (name, argv relative to tools/).
ORDERED_CHECKS: list[tuple[str, list[str]]] = [
    ("release_forbidden_vocabulary_gate", ["release_forbidden_vocabulary_gate.py", "check"]),
    (
        "release_forbidden_vocabulary_gate_self_test",
        ["release_forbidden_vocabulary_gate.py", "self-test"],
    ),
    (
        "release_archive_payload_gate_self_test",
        ["release_archive_payload_gate.py", "self-test"],
    ),
    (
        "release_archive_payload_gate_worktree_two_run",
        ["release_archive_payload_gate.py", "check", "--two-run"],
    ),
    (
        "release_archive_payload_gate_git_two_run",
        [
            "release_archive_payload_gate.py",
            "build-from-git",
            "--two-run",
            "--source",
            "git",
            "--treeish",
            "HEAD",
            "--prefix",
            "ninlil-runtime-authority",
        ],
    ),
    ("posix_lab_tests_off_surface_gate", ["posix_lab_tests_off_surface_gate.py", "check"]),
    (
        "posix_lab_tests_off_surface_gate_self_test",
        ["posix_lab_tests_off_surface_gate.py", "self-test"],
    ),
    ("markdown_link_gate", ["markdown_link_gate.py", "check"]),
    ("markdown_link_gate_self_test", ["markdown_link_gate.py", "self-test"]),
    ("compatibility_matrix_gate", ["compatibility_matrix_gate.py", "check"]),
    (
        "compatibility_matrix_gate_self_test",
        ["compatibility_matrix_gate.py", "self-test"],
    ),
    ("third_party_notice_gate", ["third_party_notice_gate.py", "check"]),
    (
        "third_party_notice_gate_self_test",
        ["third_party_notice_gate.py", "self-test"],
    ),
    (
        "release_version_identity_self_test",
        ["release_version_identity.py", "self-test"],
    ),
    (
        "release_version_identity_print_core",
        ["release_version_identity.py", "print-core"],
    ),
    (
        "release_workflow_identity_gate",
        ["release_workflow_identity_gate.py", "check"],
    ),
    (
        "release_workflow_identity_gate_self_test",
        ["release_workflow_identity_gate.py", "self-test"],
    ),
    ("spdx_release_sbom_self_test", ["spdx_release_sbom.py", "self-test"]),
    (
        "esp_idf_sdk_public_boundary_gate",
        ["esp_idf_sdk_public_boundary_gate.py", "check"],
    ),
    (
        "esp_idf_sdk_public_boundary_gate_self_test",
        ["esp_idf_sdk_public_boundary_gate.py", "self-test"],
    ),
    ("m1a_public_family_docs_gate", ["m1a_public_family_docs_gate.py", "check"]),
    (
        "m1a_public_family_docs_gate_self_test",
        ["m1a_public_family_docs_gate.py", "self-test"],
    ),
]


class GateFailure(Exception):
    pass


def run_step(name: str, argv: list[str]) -> None:
    cmd = [PY, str(REPO_ROOT / "tools" / argv[0]), *argv[1:]]
    print(f"==> {name}: {' '.join(cmd)}")
    proc = subprocess.run(cmd, cwd=str(REPO_ROOT))
    if proc.returncode != 0:
        raise GateFailure(f"{name} failed with exit {proc.returncode}")


def check(*, include_cleanroom: bool) -> None:
    results: list[str] = []
    for name, argv in ORDERED_CHECKS:
        run_step(name, argv)
        results.append(f"PASS {name}")
    if include_cleanroom:
        run_step(
            "release_archive_cleanroom",
            ["release_archive_payload_gate.py", "cleanroom", "--profile", "host"],
        )
        results.append("PASS release_archive_cleanroom")
    print("release_distribution_authority_gate OK:")
    for line in results:
        print(f"  {line}")


def self_test() -> None:
    # Authority must list archive, tests-off, and rendered-doc link gates before
    # compatibility. A green compatibility JSON must not hide broken public
    # navigation in the same release.
    names = [n for n, _ in ORDERED_CHECKS]
    assert "release_archive_payload_gate_self_test" in names
    assert "posix_lab_tests_off_surface_gate" in names
    assert "markdown_link_gate" in names
    i_arch = names.index("release_archive_payload_gate_self_test")
    i_lab = names.index("posix_lab_tests_off_surface_gate")
    i_markdown = names.index("markdown_link_gate")
    i_matrix = names.index("compatibility_matrix_gate")
    if not (i_arch < i_lab < i_markdown < i_matrix):
        raise GateFailure(
            "fail-closed order broken: archive/lab/markdown must precede "
            "compatibility"
        )
    # Smoke: run only the cheap self-tests prefix without full packaging rebuilds
    # (full check is CTest/CI authority).
    for name, argv in ORDERED_CHECKS:
        if name.endswith("_self_test") or name.endswith("print_core"):
            if "posix_lab" in name and argv[-1] == "self-test":
                run_step(name, argv)
            elif "archive" in name and argv[-1] == "self-test":
                # archive self-test is heavy but required for authority
                run_step(name, argv)
            elif "vocabulary" in name or "compatibility" in name or "third_party" in name:
                if argv[-1] == "self-test":
                    run_step(name, argv)
            elif "markdown" in name:
                if argv[-1] == "self-test":
                    run_step(name, argv)
            elif "workflow" in name or "version" in name or "spdx" in name:
                run_step(name, argv)
            elif "boundary" in name or "m1a" in name:
                if argv[-1] == "self-test":
                    run_step(name, argv)
    print("release_distribution_authority_gate self-test OK (order + cheap self-tests)")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test", "check-with-cleanroom"))
    args = parser.parse_args(argv[1:])
    try:
        if args.command == "self-test":
            self_test()
        elif args.command == "check-with-cleanroom":
            check(include_cleanroom=True)
        else:
            check(include_cleanroom=False)
    except GateFailure as e:
        print(f"release_distribution_authority_gate FAIL: {e}", file=sys.stderr)
        return 1
    except AssertionError as e:
        print(f"release_distribution_authority_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
