#!/usr/bin/env python3
"""Fail closed on workflow source split or remote Action supply-chain drift."""

from __future__ import annotations

import argparse
import copy
import pathlib
import re
import sys
from dataclasses import dataclass


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_REF = "${{ inputs.source-ref || github.sha }}"
RESOLVED_REF = "${{ needs.resolve-source.outputs.commit }}"
WORKFLOW_REF = "${{ needs.resolve-source.outputs.workflow-commit }}"
REMOTE_ACTIONS = {
    "actions/checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "634f93cb2916e3fdff6788551b99b062d0335ce0",
    "actions/attest": "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
    "anchore/sbom-action/download-syft": (
        "e22c389904149dbc22b58101806040fa8d37a610"
    ),
}
REMOTE_MINIMUM_COUNTS = {
    "actions/checkout": 1,
    "actions/upload-artifact": 2,
    "actions/download-artifact": 2,
    "actions/attest": 2,
    "anchore/sbom-action/download-syft": 1,
}
LOCAL_ACTIONS = {
    "./.github/workflows/ci.yml",
    "./.github/workflows/esp-idf.yml",
}


class GateError(RuntimeError):
    """A deterministic workflow identity validation failure."""


@dataclass
class Inputs:
    ci: str
    esp: str
    release: str


def read(path: str) -> str:
    try:
        return (ROOT / path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise GateError(f"cannot read {path}: {exc}") from exc


def load() -> Inputs:
    return Inputs(
        ci=read(".github/workflows/ci.yml"),
        esp=read(".github/workflows/esp-idf.yml"),
        release=read(".github/workflows/release.yml"),
    )


def require_count(text: str, token: str, expected: int, label: str) -> None:
    actual = text.count(token)
    if actual != expected:
        raise GateError(f"{label}: expected {expected}, got {actual}")


def checkout_blocks(text: str, label: str) -> list[str]:
    lines = text.splitlines()
    blocks: list[str] = []
    for index, line in enumerate(lines):
        if re.match(r"^\s*-\s+uses:\s+actions/checkout@", line) is None:
            continue
        indent = len(line) - len(line.lstrip(" "))
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            stripped = candidate.lstrip(" ")
            candidate_indent = len(candidate) - len(stripped)
            if stripped.startswith("- ") and candidate_indent <= indent:
                break
            end += 1
        blocks.append("\n".join(lines[index:end]))
    if not blocks:
        raise GateError(f"{label}: no checkout step")
    return blocks


def validate_all_uses(inputs: Inputs) -> None:
    counts = {name: 0 for name in REMOTE_ACTIONS}
    for label, text in (
        ("CI", inputs.ci),
        ("ESP-IDF", inputs.esp),
        ("Release", inputs.release),
    ):
        uses = re.findall(r"(?m)^\s*(?:-\s+)?uses:\s+([^\s#]+)\s*$", text)
        if not uses:
            raise GateError(f"{label}: no uses entries")
        for value in uses:
            if value.startswith("./"):
                if value not in LOCAL_ACTIONS:
                    raise GateError(f"{label}: unknown local workflow/action: {value}")
                continue
            if "@" not in value:
                raise GateError(f"{label}: remote Action lacks ref: {value}")
            name, ref = value.rsplit("@", 1)
            if name not in REMOTE_ACTIONS:
                raise GateError(f"{label}: remote Action not in closed allowlist: {name}")
            if re.fullmatch(r"[0-9a-f]{40}", ref) is None:
                raise GateError(f"{label}: remote Action is not a full commit SHA: {value}")
            if ref != REMOTE_ACTIONS[name]:
                raise GateError(f"{label}: remote Action SHA drift: {value}")
            counts[name] += 1
    for name, minimum in REMOTE_MINIMUM_COUNTS.items():
        if counts[name] < minimum:
            raise GateError(f"remote Action {name}: expected at least {minimum}")


def validate_reusable(text: str, label: str) -> None:
    require_count(text, "workflow_call:", 1, f"{label} workflow_call")
    require_count(
        text,
        "source-ref:\n        description: Exact source commit to verify",
        1,
        f"{label} source-ref input",
    )
    require_count(
        text,
        "workflow-definition-ref:\n"
        "        description: Exact commit containing this reusable workflow definition",
        1,
        f"{label} workflow-definition-ref input",
    )
    for index, block in enumerate(checkout_blocks(text, label)):
        require_count(
            block,
            f"ref: {SOURCE_REF}",
            1,
            f"{label} checkout[{index}] immutable source",
        )
        require_count(
            block,
            "persist-credentials: false",
            1,
            f"{label} checkout[{index}] credentials",
        )
    for token in (
        "ACTUAL_WORKFLOW_COMMIT: ${{ github.workflow_sha }}",
        "EXPECTED_WORKFLOW_COMMIT: "
        "${{ inputs.workflow-definition-ref || github.workflow_sha }}",
        'test "${ACTUAL_WORKFLOW_COMMIT}" = "${EXPECTED_WORKFLOW_COMMIT}"',
    ):
        if token not in text:
            raise GateError(f"{label}: workflow definition identity token absent: {token}")


def validate_linter(ci: str) -> None:
    for token in (
        "actionlint_1.7.12_linux_amd64.tar.gz",
        "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8",
        "shellcheck-v0.11.0.linux.x86_64.tar.xz",
        "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198",
        '-shellcheck "${RUNNER_TEMP}/shellcheck-v0.11.0/shellcheck"',
    ):
        require_count(ci, token, 1, f"workflow linter pin {token}")


def job_body(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise GateError(f"release job absent: {job_id}")
    return match.group(1)


def validate_release(release: str) -> None:
    for token, expected, label in (
        ("resolve-source:", 1, "source resolver"),
        (
            "ref: ${{ github.event_name == 'workflow_dispatch' && inputs.ref || github.sha }}",
            1,
            "single mutable-ref resolution",
        ),
        (f"source-ref: {RESOLVED_REF}", 2, "reusable source commit"),
        (f"workflow-definition-ref: {WORKFLOW_REF}", 2, "reusable workflow commit"),
        (
            "ref: ${{ needs.verify.outputs.verified-commit }}",
            1,
            "package verified source",
        ),
        (
            'test "${ACTUAL_WORKFLOW_COMMIT}" = "${RESOLVED_WORKFLOW_COMMIT}"',
            1,
            "verify workflow identity",
        ),
        (
            '"workflow_definition_commit": workflow_commit',
            1,
            "release metadata workflow commit",
        ),
        (
            '"source_commit": source_commit',
            1,
            "release metadata source commit",
        ),
    ):
        require_count(release, token, expected, label)
    package = job_body(release, "package")
    for dependency in (
        "resolve-source",
        "full-host-ci",
        "esp32s3-target-ci",
        "verify",
    ):
        require_count(
            package,
            f"      - {dependency}",
            1,
            f"package dependency {dependency}",
        )
    for workflow in LOCAL_ACTIONS:
        require_count(release, f"uses: {workflow}", 1, f"reusable {workflow}")
    for token in (
        "ninlil-release-build-metadata-v1",
        "source-commit: ${{ steps.metadata.outputs.commit }}",
        "workflow-commit: ${{ steps.metadata.outputs.workflow-commit }}",
        "${BASE}.build-metadata.json",
    ):
        if token not in release:
            raise GateError(f"release immutable metadata token absent: {token}")


def validate(inputs: Inputs) -> None:
    validate_reusable(inputs.ci, "CI")
    validate_reusable(inputs.esp, "ESP-IDF")
    validate_linter(inputs.ci)
    validate_release(inputs.release)
    validate_all_uses(inputs)


def self_test() -> None:
    baseline = load()
    validate(baseline)

    def reject(label: str, mutation: Inputs) -> None:
        try:
            validate(mutation)
        except GateError:
            return
        raise GateError(f"self-test mutation was accepted: {label}")

    mutable_ci = copy.deepcopy(baseline)
    mutable_ci.ci = mutable_ci.ci.replace(
        f"ref: {SOURCE_REF}",
        "ref: ${{ github.ref }}",
        1,
    )
    reject("mutable CI checkout", mutable_ci)

    floating_sbom = copy.deepcopy(baseline)
    floating_sbom.release = floating_sbom.release.replace(
        "@e22c389904149dbc22b58101806040fa8d37a610",
        "@main",
        1,
    )
    reject("floating SBOM Action", floating_sbom)

    unknown_action = copy.deepcopy(baseline)
    unknown_action.release = unknown_action.release.replace(
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        "attacker/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
        1,
    )
    reject("unknown Action owner", unknown_action)

    workflow_split = copy.deepcopy(baseline)
    workflow_split.release = workflow_split.release.replace(
        f"workflow-definition-ref: {WORKFLOW_REF}",
        "workflow-definition-ref: ${{ github.sha }}",
        1,
    )
    reject("reusable workflow definition split", workflow_split)

    missing_metadata = copy.deepcopy(baseline)
    missing_metadata.release = missing_metadata.release.replace(
        '"workflow_definition_commit": workflow_commit',
        '"workflow_definition": workflow_commit',
        1,
    )
    reject("workflow identity absent from metadata", missing_metadata)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    try:
        if args.command == "check":
            validate(load())
        else:
            self_test()
    except GateError as exc:
        print(f"release workflow identity gate: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"release workflow identity gate {args.command}: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
