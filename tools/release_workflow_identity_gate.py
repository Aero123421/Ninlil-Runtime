#!/usr/bin/env python3
"""Fail closed on workflow source split or remote Action supply-chain drift.

Authority is the *semantic YAML tree* after Unicode escapes, anchors, aliases,
merge keys, and duplicate-key rejection — not comments, not env decoys, and not
regex substring matches. Each step's `uses` / `with.ref` / `with.persist-credentials`
is bound in its exact step context.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import pathlib
import re
import shlex
import sys
from dataclasses import dataclass
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
_TOOLS = pathlib.Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

from yaml_semantic import (  # type: ignore  # noqa: E402
    load_yaml_document,
    step_env,
    step_uses,
    step_with,
    walk_job_steps,
)
SOURCE_REF = "${{ inputs.source-ref || github.sha }}"
RESOLVED_REF = "${{ needs.resolve-source.outputs.commit }}"
WORKFLOW_REF = "${{ needs.resolve-source.outputs.workflow-commit }}"
DCO_HEAD_REF = "${{ github.event.pull_request.head.sha }}"
DCO_BASE_SHA = "${{ github.event.pull_request.base.sha }}"
CI_BADGE = (
    "[![CI](https://github.com/Aero123421/Ninlil-Runtime/actions/"
    "workflows/ci.yml/badge.svg?branch=main)](https://github.com/"
    "Aero123421/Ninlil-Runtime/actions/workflows/ci.yml?query=branch%3Amain)"
)
REMOTE_ACTIONS = {
    "actions/checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "634f93cb2916e3fdff6788551b99b062d0335ce0",
    "actions/attest": "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
    "github/codeql-action/init": "5595ccaf912efad79be6eef63a5619ff05969be3",
    "github/codeql-action/analyze": "5595ccaf912efad79be6eef63a5619ff05969be3",
    "anchore/sbom-action/download-syft": (
        "e22c389904149dbc22b58101806040fa8d37a610"
    ),
}
REMOTE_ACTION_JOB_AUTHORITY: dict[str, dict[str, tuple[str, ...]]] = {
    # Closed semantic authority: workflow label -> job id -> remote Action
    # sequence. This binds each pinned Action to the job which executes it,
    # while remaining stable when non-Action steps are inserted or reordered.
    # A global occurrence count is insufficient because moving a checkout from
    # one job into another can preserve the total while silently removing
    # source identity from the first job.
    "CI": {
        "workflow-syntax": ("actions/checkout",),
        "compatibility-matrix": ("actions/checkout",),
        "cmake-floor-package": ("actions/checkout", "actions/setup-node"),
        "optional-composition": ("actions/checkout", "actions/setup-node"),
        "ubuntu-dynamic-strict": ("actions/checkout", "actions/setup-node"),
        "ubuntu-gcc-release-n6-frame": ("actions/checkout", "actions/setup-node"),
        "ubuntu-clang-release-r7": ("actions/checkout", "actions/setup-node"),
        "ubuntu-static-strict": ("actions/checkout", "actions/setup-node"),
        "ubuntu-static-tests-off-consumer": ("actions/checkout",),
        "clang-sanitizers": ("actions/checkout", "actions/setup-node"),
        "decoder-fuzz": (
            "actions/checkout",
            "actions/setup-node",
            "actions/upload-artifact",
        ),
        "mfdt-v1-private": ("actions/checkout", "actions/setup-node"),
        "wifi-v1-private": ("actions/checkout", "actions/setup-node"),
        "wifi-v1-openssl-authority": ("actions/checkout", "actions/setup-node"),
        "domain-schema1-runtime": ("actions/checkout", "actions/setup-node"),
        "fabric-v1-private": ("actions/checkout", "actions/setup-node"),
        "r7-frag-private": ("actions/checkout", "actions/setup-node"),
        "rrmp-v1-private": ("actions/checkout", "actions/setup-node"),
        "host-completion-integrated-e2e": ("actions/checkout", "actions/setup-node"),
        "clang-non-sanitizer-hygiene": ("actions/checkout", "actions/setup-node"),
        "ubuntu-release-archive-cleanroom": ("actions/checkout", "actions/setup-node"),
        "macos-release-archive-cleanroom": ("actions/checkout", "actions/setup-node"),
        "macos-dynamic": ("actions/checkout", "actions/setup-node"),
        "macos-dynamic-asan": ("actions/checkout", "actions/setup-node"),
        "clang-pointer-compare": ("actions/checkout", "actions/setup-node"),
    },
    "ESP-IDF": {
        "esp32s3-component-build": ("actions/checkout",),
    },
    "CodeQL": {
        "analyze": (
            "actions/checkout",
            "actions/setup-node",
            "github/codeql-action/init",
            "github/codeql-action/analyze",
        ),
    },
    "Coverage": {
        "coverage-map": (
            "actions/checkout",
            "actions/setup-node",
            "actions/upload-artifact",
        ),
    },
    "DCO": {
        "signoff": ("actions/checkout",),
    },
    "Release": {
        "resolve-source": ("actions/checkout",),
        "verify": ("actions/checkout", "actions/setup-node"),
        "package": (
            "actions/checkout",
            "anchore/sbom-action/download-syft",
            "actions/upload-artifact",
        ),
        "attest": (
            "actions/download-artifact",
            "actions/attest",
            "actions/attest",
            "actions/upload-artifact",
        ),
        "publish": ("actions/download-artifact",),
    },
}
LOCAL_ACTIONS = {
    "./.github/workflows/ci.yml",
    "./.github/workflows/esp-idf.yml",
}
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DYNAMIC_RE = re.compile(r"(\$\{\{|\$\(|`)")
RELEASE_SEMANTIC_SHA256 = (
    "f0c4f63ec65de0c598baa64c67cd262e2bb8f3ab6d99cbea50cc2c9437213ddb"
)


class GateError(RuntimeError):
    """A deterministic workflow identity validation failure."""


def semantic_tree_sha256(value: Any) -> str:
    """Hash the parsed YAML tree, including key types and list order."""

    def normalize(item: Any) -> Any:
        if isinstance(item, dict):
            return {
                f"{type(key).__name__}:{key}": normalize(child)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [normalize(child) for child in item]
        return item

    encoded = json.dumps(
        normalize(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class Inputs:
    ci: str
    esp: str
    release: str
    codeql: str
    coverage: str
    dco: str
    readme: str


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
        codeql=read(".github/workflows/codeql.yml"),
        coverage=read(".github/workflows/coverage.yml"),
        dco=read(".github/workflows/dco.yml"),
        readme=read("README.md"),
    )


def parse_workflow(text: str, label: str) -> Any:
    try:
        doc = load_yaml_document(text)
    except ValueError as exc:
        raise GateError(f"{label}: {exc}") from exc
    if not isinstance(doc, dict):
        raise GateError(f"{label}: workflow root must be a mapping")
    return doc


def validate_uses_identity(value: str, label: str) -> tuple[str, str] | None:
    if not value or not str(value).strip():
        raise GateError(f"{label}: empty uses identity")
    value = str(value).strip()
    if DYNAMIC_RE.search(value):
        raise GateError(f"{label}: dynamic/variable uses is forbidden: {value!r}")
    if value.startswith("./"):
        if value not in LOCAL_ACTIONS:
            raise GateError(f"{label}: unknown local workflow/action: {value}")
        return None
    if "@" not in value:
        raise GateError(f"{label}: remote Action lacks ref: {value}")
    name, ref = value.rsplit("@", 1)
    name = name.strip()
    ref = ref.strip()
    if name not in REMOTE_ACTIONS:
        raise GateError(f"{label}: remote Action not in closed allowlist: {name}")
    if FULL_SHA_RE.fullmatch(ref) is None:
        raise GateError(f"{label}: remote Action is not a full commit SHA: {value}")
    if ref != REMOTE_ACTIONS[name]:
        raise GateError(f"{label}: remote Action SHA drift: {value}")
    return name, ref


def collect_executed_uses(doc: Any, label: str) -> list[str]:
    uses_values: list[str] = []
    for job_id, step_index, mapping in walk_job_steps(doc):
        value = step_uses(mapping)
        if value is None:
            continue
        where = (
            f"{label} job={job_id}"
            if step_index is None
            else f"{label} job={job_id} step[{step_index}]"
        )
        validate_uses_identity(value, where)
        uses_values.append(value)
    if not uses_values:
        raise GateError(f"{label}: no uses entries in semantic YAML tree")
    return uses_values


def validate_all_uses(inputs: Inputs) -> None:
    for label, text in (
        ("CI", inputs.ci),
        ("ESP-IDF", inputs.esp),
        ("Release", inputs.release),
        ("CodeQL", inputs.codeql),
        ("Coverage", inputs.coverage),
        ("DCO", inputs.dco),
    ):
        doc = parse_workflow(text, label)
        actual: dict[str, list[str]] = {}
        for job_id, _step_index, mapping in walk_job_steps(doc):
            value = step_uses(mapping)
            if value is None:
                continue
            result = validate_uses_identity(value, label)
            if result is None:
                continue
            name, _ref = result
            actual.setdefault(job_id, []).append(name)
        actual_closed = {job: tuple(actions) for job, actions in actual.items()}
        expected = REMOTE_ACTION_JOB_AUTHORITY[label]
        if actual_closed != expected:
            missing_jobs = sorted(set(expected) - set(actual_closed))
            extra_jobs = sorted(set(actual_closed) - set(expected))
            drift = {
                job: {
                    "expected": expected[job],
                    "actual": actual_closed[job],
                }
                for job in sorted(set(expected) & set(actual_closed))
                if expected[job] != actual_closed[job]
            }
            raise GateError(
                f"{label}: remote Action job authority mismatch "
                f"missing_jobs={missing_jobs} extra_jobs={extra_jobs} "
                f"sequence_drift={drift}"
            )


def validate_setup_node(inputs: Inputs) -> None:
    expected_with = {"node-version": "22.18.0", "check-latest": False}
    for label, text in (
        ("CI", inputs.ci),
        ("ESP-IDF", inputs.esp),
        ("Release", inputs.release),
        ("CodeQL", inputs.codeql),
        ("Coverage", inputs.coverage),
        ("DCO", inputs.dco),
    ):
        doc = parse_workflow(text, label)
        seen: set[str] = set()
        for job_id, step_index, mapping in walk_job_steps(doc):
            if step_index is None:
                continue
            value = step_uses(mapping)
            if value is None or not str(value).startswith("actions/setup-node@"):
                continue
            if job_id in seen:
                raise GateError(f"{label} job={job_id}: duplicate setup-node step")
            seen.add(job_id)
            if step_with(mapping) != expected_with:
                raise GateError(
                    f"{label} job={job_id} step[{step_index}]: "
                    "setup-node must pin Node 22.18.0 with check-latest=false"
                )
        expected = {
            job_id
            for job_id, actions in REMOTE_ACTION_JOB_AUTHORITY[label].items()
            if "actions/setup-node" in actions
        }
        if seen != expected:
            raise GateError(
                f"{label}: setup-node job set drift "
                f"missing={sorted(expected - seen)} extra={sorted(seen - expected)}"
            )


def checkout_steps(doc: Any, label: str) -> list[tuple[str, int, dict[Any, Any]]]:
    found: list[tuple[str, int, dict[Any, Any]]] = []
    for job_id, step_index, mapping in walk_job_steps(doc):
        if step_index is None:
            continue
        value = step_uses(mapping)
        if value is None:
            continue
        if str(value).startswith("actions/checkout@"):
            found.append((job_id, step_index, mapping))
    if not found:
        raise GateError(f"{label}: no checkout step in semantic tree")
    return found


def semantic_run_commands(
    doc: Any, marker: str, label: str
) -> list[tuple[str, int, list[str]]]:
    """Return active shell commands containing marker after comment removal."""
    found: list[tuple[str, int, list[str]]] = []
    for job_id, step_index, mapping in walk_job_steps(doc):
        if step_index is None:
            continue
        run = mapping.get("run")
        if not isinstance(run, str):
            continue
        for command in logical_shell_commands(run):
            if marker not in command:
                continue
            try:
                words = shlex.split(command, comments=True, posix=True)
            except ValueError as exc:
                raise GateError(
                    f"{label} job={job_id} step[{step_index}] invalid marked shell "
                    f"command: {exc}"
                ) from exc
            if any(marker in word for word in words):
                found.append((job_id, step_index, words))
    return found


def require_exact_active_command(
    doc: Any, expected: list[str], marker: str, label: str
) -> None:
    matches = semantic_run_commands(doc, marker, label)
    exact = [item for item in matches if item[2] == expected]
    if len(exact) != 1:
        rendered = [words for _job, _step, words in matches]
        raise GateError(
            f"{label}: expected exactly one active command {expected!r}, "
            f"got exact={len(exact)} candidates={rendered!r}"
        )


def validate_reusable(text: str, label: str) -> None:
    if text.count("workflow_call:") != 1:
        raise GateError(f"{label} workflow_call: expected 1")
    if (
        text.count(
            "source-ref:\n        description: Exact source commit to verify"
        )
        != 1
    ):
        raise GateError(f"{label} source-ref input missing")
    if (
        text.count(
            "workflow-definition-ref:\n"
            "        description: Exact commit containing this reusable workflow definition"
        )
        != 1
    ):
        raise GateError(f"{label} workflow-definition-ref input missing")

    doc = parse_workflow(text, label)
    trigger_key: object = True if True in doc else "on"
    if set(doc) != {
        "name",
        trigger_key,
        "concurrency",
        "permissions",
        "jobs",
    }:
        raise GateError(
            f"{label}: reusable workflow root fields are not closed: "
            f"{sorted(map(str, doc))}"
        )
    if doc.get("name") != label:
        raise GateError(f"{label}: workflow name drift")
    expected_inputs = {
        "source-ref": {
            "description": "Exact source commit to verify",
            "required": False,
            "type": "string",
        },
        "workflow-definition-ref": {
            "description": (
                "Exact commit containing this reusable workflow definition"
            ),
            "required": False,
            "type": "string",
        },
    }
    expected_triggers = {
        "push": {"branches": ["main"]},
        "pull_request": None,
        "workflow_call": {"inputs": expected_inputs},
    }
    if doc.get(trigger_key) != expected_triggers:
        raise GateError(
            f"{label}: triggers/workflow_call inputs are not the closed authority"
        )
    expected_concurrency = {
        "group": (
            "${{ github.workflow }}-${{ github.event_name }}-"
            "${{ github.event.pull_request.number || github.ref }}"
        ),
        "cancel-in-progress": "${{ github.event_name == 'pull_request' }}",
    }
    if doc.get("concurrency") != expected_concurrency:
        raise GateError(f"{label}: concurrency authority drift")
    if doc.get("permissions") != {"contents": "read"}:
        raise GateError(f"{label}: workflow permissions must be exactly contents: read")

    for job_id, step_index, step in checkout_steps(doc, label):
        with_map = step_with(step)
        # Authority is with.ref only — env.ref / comments never count.
        if "ref" not in with_map:
            raise GateError(
                f"{label} job={job_id} step[{step_index}]: checkout missing with.ref"
            )
        ref = with_map.get("ref")
        if ref != SOURCE_REF:
            raise GateError(
                f"{label} job={job_id} step[{step_index}]: executable with.ref must be "
                f"{SOURCE_REF!r}, got {ref!r}"
            )
        # env must not be used as ref authority smuggle channel.
        env_map = step_env(step)
        if "ref" in env_map and env_map.get("ref") == SOURCE_REF and ref != SOURCE_REF:
            raise GateError(
                f"{label} job={job_id} step[{step_index}]: env.ref decoy cannot "
                "satisfy immutable source ref"
            )
        if "persist-credentials" not in with_map:
            raise GateError(
                f"{label} job={job_id} step[{step_index}]: "
                "checkout missing with.persist-credentials"
            )
        persist = with_map.get("persist-credentials")
        # YAML bool false or string "false" only — env/unrelated keys never count.
        if persist is not False and persist != "false":
            raise GateError(
                f"{label} job={job_id} step[{step_index}]: "
                f"with.persist-credentials must be false, got {persist!r}"
            )
        # Reject env.persist-credentials decoy when with is wrong (already covered)
        # and reject true with env false.
        if env_map.get("persist-credentials") in (False, "false") and persist is True:
            raise GateError(
                f"{label} job={job_id} step[{step_index}]: "
                "env.persist-credentials decoy cannot satisfy with.persist-credentials"
            )

    identity_steps: list[tuple[str, int, dict[str, Any]]] = []
    for job_id, step_index, step in walk_job_steps(doc):
        if step_index is None:
            continue
        env_map = step_env(step)
        if "ACTUAL_WORKFLOW_COMMIT" in env_map or "EXPECTED_WORKFLOW_COMMIT" in env_map:
            identity_steps.append((job_id, step_index, env_map))
    if len(identity_steps) != 1:
        raise GateError(
            f"{label}: expected exactly one semantic workflow identity step, "
            f"got {len(identity_steps)}"
        )
    job_id, step_index, identity_env = identity_steps[0]
    if identity_env.get("ACTUAL_WORKFLOW_COMMIT") != "${{ github.workflow_sha }}":
        raise GateError(
            f"{label} job={job_id} step[{step_index}]: ACTUAL_WORKFLOW_COMMIT "
            "must be github.workflow_sha"
        )
    if identity_env.get("EXPECTED_WORKFLOW_COMMIT") != (
        "${{ inputs.workflow-definition-ref || github.workflow_sha }}"
    ):
        raise GateError(
            f"{label} job={job_id} step[{step_index}]: EXPECTED_WORKFLOW_COMMIT "
            "must bind workflow-definition-ref"
        )
    require_exact_active_command(
        doc,
        ["test", "${ACTUAL_WORKFLOW_COMMIT}", "=", "${EXPECTED_WORKFLOW_COMMIT}"],
        "ACTUAL_WORKFLOW_COMMIT",
        label,
    )


def validate_linter(ci: str) -> None:
    doc = parse_workflow(ci, "CI")
    expected_envs = (
        {
            "ACTIONLINT_ARCHIVE": "actionlint_1.7.12_linux_amd64.tar.gz",
            "ACTIONLINT_SHA256": (
                "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"
            ),
        },
        {
            "SHELLCHECK_ARCHIVE": "shellcheck-v0.11.0.linux.x86_64.tar.xz",
            "SHELLCHECK_SHA256": (
                "8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198"
            ),
        },
    )
    for expected in expected_envs:
        key = next(iter(expected))
        matches = []
        for job_id, step_index, step in walk_job_steps(doc):
            if step_index is None:
                continue
            env_map = step_env(step)
            if key in env_map:
                matches.append((job_id, step_index, env_map))
        if len(matches) != 1:
            raise GateError(f"CI linter env {key}: expected one step, got {len(matches)}")
        job_id, step_index, env_map = matches[0]
        for env_key, value in expected.items():
            if env_map.get(env_key) != value:
                raise GateError(
                    f"CI job={job_id} step[{step_index}] {env_key} pin mismatch"
                )

    require_exact_active_command(
        doc,
        [
            "${RUNNER_TEMP}/actionlint/actionlint",
            "-shellcheck",
            "${RUNNER_TEMP}/shellcheck-v0.11.0/shellcheck",
            ".github/workflows/*.yml",
        ],
        "actionlint/actionlint",
        "CI linter",
    )
    for marker, version_path in (
        ("ACTIONLINT_SHA256", "/v1.7.12/"),
        ("SHELLCHECK_SHA256", "/v0.11.0/"),
    ):
        checksum_commands = semantic_run_commands(doc, marker, "CI linter")
        if len(checksum_commands) != 1:
            raise GateError(
                f"CI linter {marker}: expected one active checksum command, "
                f"got {len(checksum_commands)}"
            )
        words = checksum_commands[0][2]
        if "sha256sum" not in words or "--check" not in words or "--strict" not in words:
            raise GateError(f"CI linter {marker}: checksum command is incomplete")
        download_commands = semantic_run_commands(
            doc,
            version_path,
            "CI linter",
        )
        if len(download_commands) != 1:
            raise GateError(
                f"CI linter {marker}: expected one pinned active download URL"
            )


def validate_all_private_traceability_job(ci: str) -> None:
    """Bind cited-test JUnit production to CTest's --test-dir path rules."""
    doc = parse_workflow(ci, "CI all-private traceability")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        raise GateError("CI all-private traceability: jobs are absent")
    job = jobs.get("host-completion-integrated-e2e")
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        raise GateError("CI all-private traceability: owner job is absent")
    if set(job) != {
        "name",
        "runs-on",
        "timeout-minutes",
        "defaults",
        "steps",
    }:
        raise GateError("CI all-private traceability: owner job fields are not closed")
    if (
        job.get("name") != "Host all-private coexistence + canonical actual E2E"
        or job.get("runs-on") != "ubuntu-24.04"
        or job.get("timeout-minutes") != 45
        or job.get("defaults")
        != {"run": {"shell": "bash --noprofile --norc -euo pipefail {0}"}}
    ):
        raise GateError(
            "CI all-private traceability: owner job execution authority drift"
        )
    step_names = (
        "Prepare traceability registration coverage V2 (all-private)",
        "Produce traceability JUnit V2 (all-private)",
        "Verify traceability registration coverage V2 (all-private)",
    )
    matches: list[tuple[int, dict[Any, Any]]] = []
    for name in step_names:
        named = [
            (index, step)
            for index, step in enumerate(job["steps"])
            if isinstance(step, dict) and step.get("name") == name
        ]
        if len(named) != 1 or set(named[0][1]) != {"name", "run"}:
            raise GateError(
                "CI all-private traceability: exact preparation/producer/"
                "evidence steps are not closed"
            )
        matches.append(named[0])
    prepare_index, _ = matches[0]
    producer_index, producer_step = matches[1]
    evidence_index, evidence_step = matches[2]
    if producer_index != prepare_index + 1 or evidence_index != producer_index + 1:
        raise GateError(
            "CI all-private traceability: preparation, JUnit production, and "
            "evidence check must be adjacent"
        )
    expected_ctest = (
        "ctest --test-dir build/host-completion-allfeat --output-on-failure "
        "--no-tests=error --output-junit traceability-cited-junit.xml "
        '-R "$(cat build/host-completion-allfeat/traceability-cited.regex)"'
    )
    expected_gate = (
        "python3 tools/traceability_complete_coverage_gate.py --check "
        "--profile all-private=build/host-completion-allfeat --junit "
        "all-private=build/host-completion-allfeat/traceability-cited-junit.xml"
    )
    expected_self_test = (
        "python3 tools/traceability_complete_coverage_gate.py --self-test"
    )
    if logical_shell_commands(producer_step.get("run", "")) != [expected_ctest]:
        raise GateError(
            "CI all-private traceability: exact CTest JUnit producer path drift"
        )
    if logical_shell_commands(evidence_step.get("run", "")) != [
        expected_self_test,
        expected_gate,
    ]:
        raise GateError(
            "CI all-private traceability: evidence commands must be exactly "
            "self-test then JUnit consumer"
        )


def validate_baseline_traceability_job(ci: str) -> None:
    """Bind baseline JUnit production to CTest's --test-dir path rules."""
    doc = parse_workflow(ci, "CI baseline traceability")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        raise GateError("CI baseline traceability: jobs are absent")
    job = jobs.get("ubuntu-dynamic-strict")
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        raise GateError("CI baseline traceability: owner job is absent")
    if set(job) != {
        "name",
        "runs-on",
        "timeout-minutes",
        "defaults",
        "steps",
    }:
        raise GateError("CI baseline traceability: owner job fields are not closed")
    if (
        job.get("name") != "Ubuntu dynamic SQLite strict full"
        or job.get("runs-on") != "ubuntu-24.04"
        or job.get("timeout-minutes") != 40
        or job.get("defaults")
        != {"run": {"shell": "bash --noprofile --norc -euo pipefail {0}"}}
    ):
        raise GateError("CI baseline traceability: owner job execution authority drift")
    test_steps = [
        (index, step)
        for index, step in enumerate(job["steps"])
        if isinstance(step, dict) and step.get("name") == "Test full matrix"
    ]
    evidence_steps = [
        (index, step)
        for index, step in enumerate(job["steps"])
        if isinstance(step, dict)
        and step.get("name") == "Traceability registration coverage V2 (baseline)"
    ]
    if (
        len(test_steps) != 1
        or set(test_steps[0][1]) != {"name", "run"}
        or len(evidence_steps) != 1
        or set(evidence_steps[0][1]) != {"name", "run"}
    ):
        raise GateError("CI baseline traceability: evidence steps are not closed")
    test_index, test_step = test_steps[0]
    evidence_index, evidence_step = evidence_steps[0]
    if evidence_index != test_index + 1:
        raise GateError(
            "CI baseline traceability: evidence check must immediately follow "
            "the JUnit producer step"
        )
    expected_ctest = (
        "ctest --test-dir build/ci-ubuntu-dyn --output-on-failure "
        "--output-junit ctest-junit.xml"
    )
    expected_gate = (
        "python3 tools/traceability_complete_coverage_gate.py --check "
        "--profile baseline=build/ci-ubuntu-dyn --junit "
        "baseline=build/ci-ubuntu-dyn/ctest-junit.xml"
    )
    expected_self_test = (
        "python3 tools/traceability_complete_coverage_gate.py --self-test"
    )
    if logical_shell_commands(test_step.get("run", "")) != [expected_ctest]:
        raise GateError("CI baseline traceability: CTest JUnit producer path drift")
    if logical_shell_commands(evidence_step.get("run", "")) != [
        expected_self_test,
        expected_gate,
    ]:
        raise GateError(
            "CI baseline traceability: evidence commands must be exactly "
            "self-test then JUnit consumer"
        )


def validate_clang_release_r7_job(ci: str) -> None:
    """Keep the full Release matrix inside a measured, executable time budget."""
    doc = parse_workflow(ci, "CI Clang Release R7")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        raise GateError("CI Clang Release R7: jobs are absent")
    job = jobs.get("ubuntu-clang-release-r7")
    if not isinstance(job, dict):
        raise GateError("CI Clang Release R7: owner job is absent")
    if (
        job.get("name") != "Ubuntu Clang Release R7 authority"
        or job.get("runs-on") != "ubuntu-24.04"
        or job.get("timeout-minutes") != 45
    ):
        raise GateError(
            "CI Clang Release R7: runner/name/45-minute budget authority drift"
        )


def validate_macos_dynamic_job(ci: str) -> None:
    """Keep the full macOS matrix inside a measured, executable time budget."""
    doc = parse_workflow(ci, "CI macOS dynamic")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        raise GateError("CI macOS dynamic: jobs are absent")
    job = jobs.get("macos-dynamic")
    if not isinstance(job, dict):
        raise GateError("CI macOS dynamic: owner job is absent")
    if (
        job.get("name") != "macOS dynamic SQLite full"
        or job.get("runs-on") != "macos-15"
        or job.get("timeout-minutes") != 50
    ):
        raise GateError(
            "CI macOS dynamic: runner/name/50-minute budget authority drift"
        )


def job_body(workflow: str, job_id: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise GateError(f"release job absent: {job_id}")
    return match.group(1)


def logical_shell_commands(script: str) -> list[str]:
    """Join only explicit backslash continuations from a semantic YAML run."""
    commands: list[str] = []
    current = ""
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        continued = line.endswith("\\")
        piece = line[:-1].rstrip() if continued else line
        current = f"{current} {piece}".strip()
        if not continued:
            commands.append(current)
            current = ""
    if current:
        raise GateError("unterminated shell line continuation in release workflow")
    return commands


def validate_git_archive_command(doc: Any) -> None:
    matches: list[tuple[str, list[str]]] = []
    for job_id, step_index, mapping in walk_job_steps(doc):
        if step_index is None:
            continue
        run = mapping.get("run")
        if not isinstance(run, str):
            continue
        for command in logical_shell_commands(run):
            if not command.startswith(
                "python3 tools/release_archive_payload_gate.py build-from-git"
            ):
                continue
            try:
                tokens = shlex.split(command, posix=True)
            except ValueError as exc:
                raise GateError(
                    f"Release job={job_id} step[{step_index}] invalid shell: {exc}"
                ) from exc
            if tokens[:3] == [
                "python3",
                "tools/release_archive_payload_gate.py",
                "build-from-git",
            ]:
                matches.append((job_id, tokens))
    if len(matches) != 1:
        raise GateError(
            "release must execute exactly one build-from-git command, "
            f"got {len(matches)}"
        )
    job_id, tokens = matches[0]
    if job_id != "package":
        raise GateError(f"build-from-git must execute in package job, got {job_id}")
    expected = [
        "python3",
        "tools/release_archive_payload_gate.py",
        "build-from-git",
        "--two-run",
        "--source",
        "git",
        "--require-clean-worktree",
        "--no-force-release-gates",
        "--treeish",
        "HEAD",
        "--prefix",
        "${BASE}",
        "--out-dir",
        "${RUNNER_TEMP}/ninlil-release-arch",
    ]
    if tokens != expected:
        raise GateError(
            "build-from-git release argv must bind immutable source, clean "
            f"checkout, two-run, and output identity exactly: got={tokens!r}"
        )


def validate_package_staging(doc: Any) -> None:
    """Keep generated files out of the repository until clean-tree capture.

    ``--require-clean-worktree`` is meaningless if SBOM/build metadata was
    already written under ``dist/``. Bind both pre-archive files to
    ``runner.temp`` and require all repository-local output commands to occur
    after the immutable git-tree archive command.
    """
    matches: list[tuple[str, int, dict[Any, Any], list[str]]] = []
    for job_id, step_index, step in walk_job_steps(doc):
        if step_index is None:
            continue
        run = step.get("run")
        if not isinstance(run, str) or "build-from-git" not in run:
            continue
        matches.append((job_id, step_index, step, logical_shell_commands(run)))
    if len(matches) != 1:
        raise GateError(
            f"release package staging step count must be 1, got {len(matches)}"
        )
    job_id, step_index, step, commands = matches[0]
    if job_id != "package":
        raise GateError(
            f"release package staging must execute in package job, got {job_id}"
        )
    env_map = step_env(step)
    expected_env = {
        "SBOM": (
            "${{ runner.temp }}/"
            "${{ steps.metadata.outputs.base }}.spdx.json"
        ),
        "BUILD_METADATA": (
            "${{ runner.temp }}/"
            "${{ steps.metadata.outputs.base }}.build-metadata.json"
        ),
    }
    for key, expected in expected_env.items():
        if env_map.get(key) != expected:
            raise GateError(
                f"Release job={job_id} step[{step_index}] {key} must stage "
                f"outside repository: got={env_map.get(key)!r}"
            )

    archive_indices = [
        index
        for index, command in enumerate(commands)
        if command.startswith(
            "python3 tools/release_archive_payload_gate.py build-from-git"
        )
    ]
    if len(archive_indices) != 1:
        raise GateError("package staging cannot identify one archive command")
    archive_index = archive_indices[0]
    for command in commands[:archive_index]:
        if "dist/" in command or command in {"rm -rf dist", "mkdir -p dist"}:
            raise GateError(
                "repository-local dist output occurs before clean git-tree "
                f"archive capture: {command!r}"
            )

    required_after = (
        'rm -rf dist',
        'mkdir -p dist',
        'mv "${SBOM}" "dist/${BASE}.spdx.json"',
        'mv "${BUILD_METADATA}" "dist/${BASE}.build-metadata.json"',
    )
    for command in required_after:
        indices = [i for i, actual in enumerate(commands) if actual == command]
        if len(indices) != 1 or indices[0] <= archive_index:
            raise GateError(
                f"release package staging command must occur once after "
                f"archive capture: {command!r}"
            )


def validate_release_version_identity(release: str) -> None:
    """Fail-closed: workflow must bind tag/core to CMake/matrix/inventory/ESP."""
    required = (
        "python3 tools/release_version_identity.py self-test",
        "python3 tools/release_version_identity.py enforce",
        "python3 tools/release_version_identity.py print-core",
        "python3 tools/release_distribution_authority_gate.py check",
        "python3 tools/release_archive_payload_gate.py build-from-git",
        "python3 tools/release_archive_payload_gate.py cleanroom",
        "python3 tools/release_forbidden_vocabulary_gate.py check",
        '--project-version "${PROJECT_VERSION}"',
        '--source-version "${SOURCE_VERSION}"',
        "--select-catalogers=-github-actions-usage-cataloger,-github-action-workflow-usage-cataloger",
        '"project_version": project_version',
        '"source_version": source_version',
        '"artifact_base": base',
        'test "${base}" = "ninlil-runtime-${tag}"',
        'test "${core}" = "$(python3 tools/release_version_identity.py print-core)"',
    )
    for token in required:
        if token not in release:
            raise GateError(f"release version identity token absent: {token}")
    # Loose SemVer-only tag acceptance (no core bind) must not remain.
    if "release tag must be SemVer with a leading v" in release:
        raise GateError(
            "release workflow still accepts arbitrary SemVer tags without "
            "canonical core binding"
        )
    # Bypass via bare base= without enforce is forbidden: require enforce output.
    if "identity_json=\"$(python3 tools/release_version_identity.py enforce" not in release:
        raise GateError(
            "release workflow must capture enforce JSON for base/core/source_version"
        )


def validate_release_envelope(doc: Any) -> None:
    """Bind the privileged release pipeline to one exact semantic authority."""
    trigger_key: object = True if True in doc else "on"
    if set(doc) != {
        "name",
        trigger_key,
        "permissions",
        "concurrency",
        "jobs",
    }:
        raise GateError(
            "Release: root fields are not closed: "
            f"{sorted(map(str, doc))}"
        )
    if doc.get("name") != "Release":
        raise GateError("Release: workflow name drift")
    expected_triggers = {
        "push": {"tags": ["v*"]},
        "workflow_dispatch": {
            "inputs": {
                "ref": {
                    "description": (
                        "Commit, branch, or tag to package without publishing"
                    ),
                    "required": False,
                    "type": "string",
                }
            }
        },
    }
    if doc.get(trigger_key) != expected_triggers:
        raise GateError("Release: trigger/input authority drift")
    if doc.get("permissions") != {"contents": "read"}:
        raise GateError("Release: top-level permissions must be contents: read")
    if doc.get("concurrency") != {
        "group": "release-${{ github.ref }}",
        "cancel-in-progress": False,
    }:
        raise GateError("Release: concurrency authority drift")

    jobs = doc.get("jobs")
    expected_job_ids = {
        "resolve-source",
        "full-host-ci",
        "esp32s3-target-ci",
        "verify",
        "package",
        "attest",
        "publish",
    }
    if not isinstance(jobs, dict) or set(jobs) != expected_job_ids:
        raise GateError("Release: job set is not closed")

    reusable_expected = {
        "full-host-ci": {
            "name": "Reuse the full Linux and macOS CI matrix",
            "needs": "resolve-source",
            "permissions": {"contents": "read"},
            "uses": "./.github/workflows/ci.yml",
            "with": {
                "source-ref": RESOLVED_REF,
                "workflow-definition-ref": WORKFLOW_REF,
            },
        },
        "esp32s3-target-ci": {
            "name": "Reuse the pinned ESP32-S3 target matrix",
            "needs": "resolve-source",
            "permissions": {"contents": "read"},
            "uses": "./.github/workflows/esp-idf.yml",
            "with": {
                "source-ref": RESOLVED_REF,
                "workflow-definition-ref": WORKFLOW_REF,
            },
        },
    }
    for job_id, expected in reusable_expected.items():
        if jobs.get(job_id) != expected:
            raise GateError(f"Release: reusable job {job_id} authority drift")

    job_authority = {
        "resolve-source": {
            "fields": {
                "name", "runs-on", "timeout-minutes", "permissions",
                "outputs", "defaults", "steps",
            },
            "name": "Resolve one immutable source commit",
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 5,
            "permissions": {"contents": "read"},
        },
        "verify": {
            "fields": {
                "name", "needs", "runs-on", "timeout-minutes", "permissions",
                "outputs", "defaults", "steps",
            },
            "name": "Full host verification",
            "needs": "resolve-source",
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 90,
            "permissions": {"contents": "read"},
        },
        "package": {
            "fields": {
                "name", "needs", "runs-on", "timeout-minutes", "permissions",
                "outputs", "defaults", "steps",
            },
            "name": "Source, SBOM, and checksums",
            "needs": [
                "resolve-source", "full-host-ci", "esp32s3-target-ci", "verify"
            ],
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 15,
            "permissions": {"contents": "read"},
        },
        "attest": {
            "fields": {
                "name", "if", "needs", "runs-on", "timeout-minutes",
                "permissions", "defaults", "steps",
            },
            "name": "Provenance and SBOM attestations",
            "if": "github.event_name == 'push' && github.ref_type == 'tag'",
            "needs": "package",
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 15,
            "permissions": {
                "contents": "read", "id-token": "write", "attestations": "write"
            },
        },
        "publish": {
            "fields": {
                "name", "if", "needs", "runs-on", "timeout-minutes",
                "permissions", "defaults", "steps",
            },
            "name": "Publish immutable tag release",
            "if": "github.event_name == 'push' && github.ref_type == 'tag'",
            "needs": ["package", "attest"],
            "runs-on": "ubuntu-24.04",
            "timeout-minutes": 10,
            "permissions": {"contents": "write"},
        },
    }
    strict_defaults = {
        "run": {"shell": "bash --noprofile --norc -euo pipefail {0}"}
    }
    for job_id, expected in job_authority.items():
        job = jobs.get(job_id)
        if not isinstance(job, dict) or set(job) != expected["fields"]:
            raise GateError(f"Release: {job_id} job fields are not closed")
        for key, value in expected.items():
            if key == "fields":
                continue
            if job.get(key) != value:
                raise GateError(f"Release: {job_id}.{key} authority drift")
        if job.get("defaults") != strict_defaults:
            raise GateError(f"Release: {job_id} strict shell authority drift")

    checkout_pin = f"actions/checkout@{REMOTE_ACTIONS['actions/checkout']}"
    expected_checkouts = {
        "resolve-source": {
            "name": "Resolve requested release source",
            "uses": checkout_pin,
            "with": {
                "fetch-depth": 0,
                "persist-credentials": False,
                "ref": (
                    "${{ github.event_name == 'workflow_dispatch' && "
                    "inputs.ref || github.sha }}"
                ),
            },
        },
        "verify": {
            "name": "Checkout release source",
            "uses": checkout_pin,
            "with": {
                "fetch-depth": 0,
                "persist-credentials": False,
                "ref": RESOLVED_REF,
            },
        },
        "package": {
            "name": "Checkout release source",
            "uses": checkout_pin,
            "with": {
                "fetch-depth": 0,
                "persist-credentials": False,
                "ref": "${{ needs.verify.outputs.verified-commit }}",
            },
        },
    }
    for job_id, expected in expected_checkouts.items():
        steps = jobs[job_id].get("steps")
        if not isinstance(steps, list) or not steps or steps[0] != expected:
            raise GateError(f"Release: {job_id} checkout authority drift")

    # The full parsed tree is a compact exact authority for every active step,
    # run script, env mapping, attestation input, and publishing credential.
    # Comments do not affect it; any executable semantic change requires an
    # intentional review and pin update here.
    actual_digest = semantic_tree_sha256(doc)
    if actual_digest != RELEASE_SEMANTIC_SHA256:
        raise GateError(
            "Release: semantic workflow digest drift "
            f"expected={RELEASE_SEMANTIC_SHA256} actual={actual_digest}"
        )


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
        if release.count(token) != expected:
            raise GateError(f"{label}: expected {expected}, got {release.count(token)}")
    package = job_body(release, "package")
    for dependency in (
        "resolve-source",
        "full-host-ci",
        "esp32s3-target-ci",
        "verify",
    ):
        if package.count(f"      - {dependency}") != 1:
            raise GateError(f"package dependency {dependency} missing")

    doc = parse_workflow(release, "Release")
    validate_release_envelope(doc)
    require_exact_active_command(
        doc,
        [
            "${SYFT_CMD}",
            "scan",
            "dir:.",
            "--source-name",
            "ninlil-runtime",
            "--source-version",
            "${SOURCE_VERSION}",
            (
                "--select-catalogers=-github-actions-usage-cataloger,"
                "-github-action-workflow-usage-cataloger"
            ),
            "--output",
            "spdx-json=${RAW_SBOM}",
        ],
        "spdx-json=${RAW_SBOM}",
        "Release Syft source scan",
    )
    validate_git_archive_command(doc)
    validate_package_staging(doc)
    require_exact_active_command(
        doc,
        ["test", "${ACTUAL_WORKFLOW_COMMIT}", "=", "${RESOLVED_WORKFLOW_COMMIT}"],
        "ACTUAL_WORKFLOW_COMMIT",
        "Release source resolver",
    )
    require_exact_active_command(
        doc,
        [
            "python3",
            "tools/release_distribution_authority_gate.py",
            "check",
        ],
        "release_distribution_authority_gate.py",
        "Release distribution authority",
    )
    require_exact_active_command(
        doc,
        [
            "python3",
            "tools/release_distribution_authority_gate.py",
            "self-test",
        ],
        "release_distribution_authority_gate.py",
        "Release distribution authority self-test",
    )
    require_exact_active_command(
        doc,
        ["python3", "tools/release_version_identity.py", "self-test"],
        "release_version_identity.py",
        "Release version identity self-test",
    )
    require_exact_active_command(
        doc,
        [
            (
                "identity_json=$(python3 tools/release_version_identity.py enforce "
                "--event-name ${EVENT_NAME} --ref-name ${REF_NAME} "
                "--ref-type ${REF_TYPE} --commit ${commit})"
            )
        ],
        "release_version_identity.py enforce",
        "Release version identity enforcement",
    )
    require_exact_active_command(
        doc,
        [
            "test",
            "${core}",
            "=",
            "$(python3 tools/release_version_identity.py print-core)",
        ],
        "release_version_identity.py print-core",
        "Release canonical core equality",
    )
    require_exact_active_command(
        doc,
        ["test", "${base}", "=", "ninlil-runtime-${tag}"],
        "ninlil-runtime-${tag}",
        "Release tagged artifact identity",
    )
    require_exact_active_command(
        doc,
        ["test", "${base}", "=", "ninlil-runtime-dry-run-${commit:0:12}"],
        "ninlil-runtime-dry-run-",
        "Release dry-run artifact identity",
    )
    require_exact_active_command(
        doc,
        [
            "python3",
            "tools/release_archive_payload_gate.py",
            "cleanroom",
            "--tar",
            "dist/${BASE}.tar.gz",
            "--zip",
            "dist/${BASE}.zip",
            "--prefix",
            "${BASE}",
            "--profile",
            "host",
            "--out-dir",
            "${RUNNER_TEMP}/ninlil-release-cleanroom",
        ],
        "release_archive_payload_gate.py",
        "Release shipped archive clean-room",
    )
    local_uses = [
        v for v in collect_executed_uses(doc, "Release") if v.startswith("./")
    ]
    for workflow in LOCAL_ACTIONS:
        if local_uses.count(workflow) != 1:
            raise GateError(
                f"reusable {workflow}: expected exactly 1 executed uses, "
                f"got {local_uses.count(workflow)}"
            )
    for token in (
        "ninlil-release-build-metadata-v1",
        "source-commit: ${{ steps.metadata.outputs.commit }}",
        "workflow-commit: ${{ steps.metadata.outputs.workflow-commit }}",
        "${BASE}.build-metadata.json",
    ):
        if token not in release:
            raise GateError(f"release immutable metadata token absent: {token}")
    validate_release_version_identity(release)


def validate_dco(dco: str) -> None:
    doc = parse_workflow(dco, "DCO")
    trigger_key: object = True if True in doc else "on"
    if set(doc) != {"name", trigger_key, "permissions", "jobs"}:
        raise GateError(f"DCO: root fields are not closed: {sorted(map(str, doc))}")
    if doc.get("name") != "DCO sign-off":
        raise GateError("DCO: workflow name drift")
    if doc.get(trigger_key) != {"pull_request": None}:
        raise GateError("DCO: only pull_request may trigger the sign-off workflow")
    if doc.get("permissions") != {"contents": "read"}:
        raise GateError("DCO: permissions must be exactly contents: read")

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"signoff"}:
        raise GateError("DCO: jobs must contain only signoff")
    job = jobs["signoff"]
    if not isinstance(job, dict) or set(job) != {
        "name",
        "runs-on",
        "timeout-minutes",
        "defaults",
        "steps",
    }:
        raise GateError("DCO: signoff job fields are not closed")
    if job.get("name") != "Sign-off trailers":
        raise GateError("DCO: signoff job display name drift")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 5:
        raise GateError("DCO: runner/timeout authority drift")
    if job.get("defaults") != {
        "run": {"shell": "bash --noprofile --norc -euo pipefail {0}"}
    }:
        raise GateError("DCO: strict shell authority drift")

    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) != 2:
        raise GateError("DCO: signoff job must contain exactly two steps")
    checkout, verify = steps
    if not isinstance(checkout, dict) or set(checkout) != {"uses", "with"}:
        raise GateError("DCO: checkout step fields are not closed")
    if checkout.get("uses") != (
        f"actions/checkout@{REMOTE_ACTIONS['actions/checkout']}"
    ):
        raise GateError("DCO: checkout Action identity drift")
    if step_with(checkout) != {
        "ref": DCO_HEAD_REF,
        "fetch-depth": 0,
        "persist-credentials": False,
    }:
        raise GateError("DCO: checkout must bind exact PR head with full history")

    if not isinstance(verify, dict) or set(verify) != {"name", "env", "run"}:
        raise GateError("DCO: verifier step fields are not closed")
    if verify.get("name") != "Verify DCO 1.1 sign-off":
        raise GateError("DCO: verifier step name/version drift")
    if step_env(verify) != {
        "BASE_SHA": DCO_BASE_SHA,
        "HEAD_SHA": DCO_HEAD_REF,
    }:
        raise GateError("DCO: base/head event SHA authority drift")
    run = verify.get("run")
    if not isinstance(run, str):
        raise GateError("DCO: verifier run script is absent")
    expected_commands = [
        'git show "${BASE_SHA}:tools/dco_signoff_gate.py" > '
        '"${RUNNER_TEMP}/dco_signoff_gate.py"',
        'python3 "${RUNNER_TEMP}/dco_signoff_gate.py" self-test',
        'python3 "${RUNNER_TEMP}/dco_signoff_gate.py" check-range '
        '"${BASE_SHA}" "${HEAD_SHA}"',
    ]
    if logical_shell_commands(run) != expected_commands:
        raise GateError(
            "DCO: verifier must execute the base-commit gate self-test and "
            "exact contribution range"
        )


def validate_coverage(coverage: str) -> None:
    doc = parse_workflow(coverage, "Coverage")
    trigger_key: object = True if True in doc else "on"
    if set(doc) != {"name", trigger_key, "permissions", "jobs"}:
        raise GateError(
            f"Coverage: root fields are not closed: {sorted(map(str, doc))}"
        )
    if doc.get("name") != "Clang coverage map":
        raise GateError("Coverage: workflow name drift")
    if doc.get(trigger_key) != {
        "push": {"branches": ["main"]},
        "pull_request": None,
    }:
        raise GateError("Coverage: trigger authority drift")
    if doc.get("permissions") != {"contents": "read"}:
        raise GateError("Coverage: permissions must be exactly contents: read")

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"coverage-map"}:
        raise GateError("Coverage: jobs must contain only coverage-map")
    job = jobs["coverage-map"]
    if not isinstance(job, dict) or set(job) != {
        "name",
        "runs-on",
        "timeout-minutes",
        "steps",
    }:
        raise GateError("Coverage: coverage-map job fields are not closed")
    if job.get("name") != "Non-threshold C/C++ coverage artifact":
        raise GateError("Coverage: job display name drift")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 30:
        raise GateError("Coverage: runner/timeout authority drift")

    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) != 5:
        raise GateError("Coverage: job must contain exactly five steps")
    checkout, setup_node, install, build, upload = steps
    if not isinstance(checkout, dict) or set(checkout) != {"uses", "with"}:
        raise GateError("Coverage: checkout step fields are not closed")
    if checkout.get("uses") != (
        f"actions/checkout@{REMOTE_ACTIONS['actions/checkout']}"
    ) or step_with(checkout) != {"persist-credentials": False}:
        raise GateError(
            "Coverage: checkout must use the event ref with credentials disabled"
        )
    if not isinstance(setup_node, dict) or set(setup_node) != {"uses", "with"}:
        raise GateError("Coverage: setup-node step fields are not closed")
    if setup_node.get("uses") != (
        f"actions/setup-node@{REMOTE_ACTIONS['actions/setup-node']}"
    ) or step_with(setup_node) != {
        "node-version": "22.18.0",
        "check-latest": False,
    }:
        raise GateError("Coverage: setup-node identity/configuration drift")
    if not isinstance(install, dict) or set(install) != {"name", "run"}:
        raise GateError("Coverage: dependency-install step fields are not closed")
    if install.get("name") != "Install Clang and build dependencies" or (
        logical_shell_commands(install.get("run", "")) != [
            "sudo apt-get update && sudo apt-get install -y "
            "clang llvm libsqlite3-dev libssl-dev ninja-build"
        ]
    ):
        raise GateError("Coverage: dependency-install command drift")
    if not isinstance(build, dict) or set(build) != {"name", "env", "run"}:
        raise GateError("Coverage: instrumented build step fields are not closed")
    if build.get("name") != "Build and execute focused instrumented smoke":
        raise GateError("Coverage: instrumented build step name drift")
    if step_env(build) != {
        "LLVM_PROFILE_FILE": (
            "${{ github.workspace }}/build/coverage-raw/%p.profraw"
        )
    }:
        raise GateError("Coverage: LLVM profile output authority drift")
    expected_commands = [
        "cmake -S . -B build/coverage -G Ninja "
        "-DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ "
        "-DCMAKE_C_FLAGS='-fprofile-instr-generate -fcoverage-mapping' "
        "-DCMAKE_EXE_LINKER_FLAGS='-fprofile-instr-generate' "
        "-DCMAKE_SHARED_LINKER_FLAGS='-fprofile-instr-generate'",
        "cmake --build build/coverage --target "
        "ninlil_v1_runtime_delivery_test --parallel 2",
        "ctest --test-dir build/coverage --output-on-failure "
        "-R '^v1_runtime_delivery$'",
        "python3 tools/clang_coverage_artifact.py --binary "
        "build/coverage/ninlil_v1_runtime_delivery_test --profraw-dir "
        "build/coverage-raw --out build/coverage-artifact",
    ]
    if logical_shell_commands(build.get("run", "")) != expected_commands:
        raise GateError("Coverage: instrumented command sequence drift")
    if not isinstance(upload, dict) or set(upload) != {"uses", "with"}:
        raise GateError("Coverage: upload step fields are not closed")
    if upload.get("uses") != (
        f"actions/upload-artifact@{REMOTE_ACTIONS['actions/upload-artifact']}"
    ) or step_with(upload) != {
        "name": "clang-coverage-map",
        "path": "build/coverage-artifact",
        "if-no-files-found": "error",
    }:
        raise GateError("Coverage: upload Action/configuration drift")
    require_exact_active_command(
        doc,
        [
            "cmake",
            "--build",
            "build/coverage",
            "--target",
            "ninlil_v1_runtime_delivery_test",
            "--parallel",
            "2",
        ],
        "ninlil_v1_runtime_delivery_test",
        "Coverage runtime target",
    )
    require_exact_active_command(
        doc,
        [
            "ctest",
            "--test-dir",
            "build/coverage",
            "--output-on-failure",
            "-R",
            "^v1_runtime_delivery$",
        ],
        "v1_runtime_delivery",
        "Coverage runtime execution",
    )
    require_exact_active_command(
        doc,
        [
            "python3",
            "tools/clang_coverage_artifact.py",
            "--binary",
            "build/coverage/ninlil_v1_runtime_delivery_test",
            "--profraw-dir",
            "build/coverage-raw",
            "--out",
            "build/coverage-artifact",
        ],
        "clang_coverage_artifact.py",
        "Coverage artifact",
    )


def validate_decoder_fuzz_job(ci: str) -> None:
    """Bind the reusable CI workflow to all six sustained decoder fuzzers."""
    doc = parse_workflow(ci, "Decoder fuzz")
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or "decoder-fuzz" not in jobs:
        raise GateError("Decoder fuzz: job is absent")
    job = jobs["decoder-fuzz"]
    if not isinstance(job, dict) or set(job) != {
        "name",
        "runs-on",
        "timeout-minutes",
        "defaults",
        "steps",
    }:
        raise GateError("Decoder fuzz: job fields are not closed")
    if job.get("name") != "Decoder fuzz (6 boundaries, 5 minutes each)":
        raise GateError("Decoder fuzz: job display name drift")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 20:
        raise GateError("Decoder fuzz: runner/timeout authority drift")
    if job.get("defaults") != {
        "run": {"shell": "bash --noprofile --norc -euo pipefail {0}"}
    }:
        raise GateError("Decoder fuzz: strict shell authority drift")

    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) != 8:
        raise GateError("Decoder fuzz: job must contain exactly eight steps")
    checkout, setup_node, install, configure, build, seed, fuzz, upload = steps
    if not isinstance(checkout, dict) or set(checkout) != {"uses", "with"}:
        raise GateError("Decoder fuzz: checkout step fields are not closed")
    if checkout.get("uses") != (
        f"actions/checkout@{REMOTE_ACTIONS['actions/checkout']}"
    ) or step_with(checkout) != {
        "ref": SOURCE_REF,
        "persist-credentials": False,
    }:
        raise GateError("Decoder fuzz: immutable checkout authority drift")
    if not isinstance(setup_node, dict) or set(setup_node) != {"uses", "with"}:
        raise GateError("Decoder fuzz: setup-node step fields are not closed")
    if setup_node.get("uses") != (
        f"actions/setup-node@{REMOTE_ACTIONS['actions/setup-node']}"
    ) or step_with(setup_node) != {
        "node-version": "22.18.0",
        "check-latest": False,
    }:
        raise GateError("Decoder fuzz: setup-node identity/configuration drift")

    named_run_steps = (
        (install, "Install Clang and build dependencies"),
        (configure, "Configure private libFuzzer targets"),
        (build, "Build all six harnesses"),
        (seed, "Generate and verify vector-derived seed corpus"),
    )
    for step, expected_name in named_run_steps:
        if not isinstance(step, dict) or set(step) != {"name", "run"}:
            raise GateError(
                f"Decoder fuzz: {expected_name} step fields are not closed"
            )
        if step.get("name") != expected_name:
            raise GateError(f"Decoder fuzz: {expected_name} step name drift")
    if logical_shell_commands(install.get("run", "")) != [
        "sudo apt-get update && sudo apt-get install -y clang "
        "libclang-rt-dev libsqlite3-dev libssl-dev ninja-build"
    ]:
        raise GateError("Decoder fuzz: dependency-install command drift")
    if logical_shell_commands(configure.get("run", "")) != [
        "cmake -S . -B build/ci-decoder-fuzz -G Ninja "
        "-DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER=clang "
        "-DCMAKE_CXX_COMPILER=clang++ -DNINLIL_ENABLE_SANITIZERS=ON "
        "-DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON "
        "-DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON "
        "-DNINLIL_BUILD_DECODER_FUZZERS=ON"
    ]:
        raise GateError("Decoder fuzz: configure command drift")
    if logical_shell_commands(build.get("run", "")) != [
        "cmake --build build/ci-decoder-fuzz --parallel 2 "
        "--target ninlil_decoder_fuzzers"
    ]:
        raise GateError("Decoder fuzz: build command drift")
    if logical_shell_commands(seed.get("run", "")) != [
        "python3 tools/decoder_fuzz_seed_corpus.py self-test",
        "python3 tools/decoder_fuzz_seed_corpus.py generate "
        "--output build/ci-decoder-fuzz/corpus",
        "python3 tools/decoder_fuzz_seed_corpus.py check "
        "--output build/ci-decoder-fuzz/corpus",
    ]:
        raise GateError("Decoder fuzz: seed authority command drift")

    if not isinstance(fuzz, dict) or set(fuzz) != {"name", "env", "run"}:
        raise GateError("Decoder fuzz: sustained-run step fields are not closed")
    if fuzz.get("name") != "Fuzz all decoder boundaries concurrently":
        raise GateError("Decoder fuzz: sustained-run step name drift")
    if step_env(fuzz) != {
        "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
    }:
        raise GateError("Decoder fuzz: sanitizer environment drift")
    expected_fuzz_commands = [
        "build=$PWD/build/ci-decoder-fuzz",
        'mkdir -p "$build/fuzz-artifacts" "$build/fuzz-logs"',
        "specs=(",
        "ninlil_nfl1_codec_fuzzer:nfl1_codec",
        "ninlil_rrmp_codec_fuzzer:rrmp_codec",
        "ninlil_r7_wire_codec_fuzzer:r7_wire_codec",
        "ninlil_r7_frag_wire_fuzzer:r7_frag_wire",
        "ninlil_n6_record_codec_fuzzer:n6_record_codec",
        "ninlil_domain_store_body_codec_fuzzer:domain_store_body_codec",
        ")",
        "pids=()",
        "names=()",
        'for spec in "${specs[@]}"; do',
        "binary=${spec%%:*}",
        "corpus=${spec#*:}",
        'names+=("$binary")',
        '"$build/$binary" "$build/corpus/$corpus" -max_total_time=300 '
        '-max_len=4096 -timeout=10 -rss_limit_mb=2048 '
        '-artifact_prefix="$build/fuzz-artifacts/$corpus-" '
        '>"$build/fuzz-logs/$corpus.log" 2>&1 &',
        'pids+=("$!")',
        "done",
        "failed=0",
        'for i in "${!pids[@]}"; do',
        'if wait "${pids[$i]}"; then',
        'tail -n 8 "$build/fuzz-logs/${specs[$i]#*:}.log"',
        "else",
        'echo "fuzzer failed: ${names[$i]}" >&2',
        'cat "$build/fuzz-logs/${specs[$i]#*:}.log" >&2',
        "failed=1",
        "fi",
        "done",
        'exit "$failed"',
    ]
    if logical_shell_commands(fuzz.get("run", "")) != expected_fuzz_commands:
        raise GateError("Decoder fuzz: six-target sustained-run authority drift")

    if not isinstance(upload, dict) or set(upload) != {
        "name",
        "if",
        "uses",
        "with",
    }:
        raise GateError("Decoder fuzz: failure-upload step fields are not closed")
    if upload.get("name") != "Upload crash inputs and logs":
        raise GateError("Decoder fuzz: failure-upload step name drift")
    if upload.get("if") != "${{ failure() }}" or upload.get("uses") != (
        f"actions/upload-artifact@{REMOTE_ACTIONS['actions/upload-artifact']}"
    ):
        raise GateError("Decoder fuzz: failure-only upload identity drift")
    if step_with(upload) != {
        "name": "decoder-fuzz-failure-${{ github.run_id }}",
        "path": (
            "build/ci-decoder-fuzz/fuzz-artifacts\n"
            "build/ci-decoder-fuzz/fuzz-logs\n"
            "build/ci-decoder-fuzz/corpus/manifest.json\n"
        ),
        "if-no-files-found": "error",
        "retention-days": 14,
    }:
        raise GateError("Decoder fuzz: failure artifact configuration drift")


def validate_codeql(codeql: str) -> None:
    """Bind CodeQL to both installed-Host and all-private Host production."""
    doc = parse_workflow(codeql, "CodeQL")
    trigger_key: object = True if True in doc else "on"
    if set(doc) != {"name", trigger_key, "permissions", "jobs"}:
        raise GateError(
            f"CodeQL: root fields are not closed: {sorted(map(str, doc))}"
        )
    if doc.get("name") != "CodeQL":
        raise GateError("CodeQL: workflow name drift")
    if doc.get(trigger_key) != {
        "push": {"branches": ["main"]},
        "pull_request": None,
        "schedule": [{"cron": "23 3 * * 1"}],
    }:
        raise GateError("CodeQL: trigger authority drift")
    if doc.get("permissions") != {
        "contents": "read",
        "security-events": "write",
    }:
        raise GateError("CodeQL: permissions authority drift")

    jobs = doc.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"analyze"}:
        raise GateError("CodeQL: jobs must contain only analyze")
    job = jobs["analyze"]
    if not isinstance(job, dict) or set(job) != {
        "name",
        "runs-on",
        "timeout-minutes",
        "steps",
    }:
        raise GateError("CodeQL: analyze job fields are not closed")
    if job.get("name") != "C/C++ analysis":
        raise GateError("CodeQL: analyze job display name drift")
    if job.get("runs-on") != "ubuntu-24.04" or job.get("timeout-minutes") != 45:
        raise GateError("CodeQL: runner/timeout authority drift")

    steps = job.get("steps")
    if not isinstance(steps, list) or len(steps) != 6:
        raise GateError("CodeQL: analyze job must contain exactly six steps")
    checkout, setup_node, init, install, build, analyze = steps
    if not isinstance(checkout, dict) or set(checkout) != {"uses", "with"}:
        raise GateError("CodeQL: checkout step fields are not closed")
    if checkout.get("uses") != (
        f"actions/checkout@{REMOTE_ACTIONS['actions/checkout']}"
    ) or step_with(checkout) != {"persist-credentials": False}:
        raise GateError(
            "CodeQL: checkout must use the event ref with credentials disabled"
        )
    if not isinstance(setup_node, dict) or set(setup_node) != {"uses", "with"}:
        raise GateError("CodeQL: setup-node step fields are not closed")
    if setup_node.get("uses") != (
        f"actions/setup-node@{REMOTE_ACTIONS['actions/setup-node']}"
    ) or step_with(setup_node) != {
        "node-version": "22.18.0",
        "check-latest": False,
    }:
        raise GateError("CodeQL: setup-node identity/configuration drift")
    if not isinstance(init, dict) or set(init) != {"uses", "with"}:
        raise GateError("CodeQL: init step fields are not closed")
    if init.get("uses") != (
        f"github/codeql-action/init@{REMOTE_ACTIONS['github/codeql-action/init']}"
    ) or step_with(init) != {"languages": "c-cpp", "build-mode": "manual"}:
        raise GateError("CodeQL: init language/build mode drift")
    if not isinstance(install, dict) or set(install) != {"name", "run"}:
        raise GateError("CodeQL: dependency-install step fields are not closed")
    if install.get("name") != "Install build dependencies" or logical_shell_commands(
        install.get("run", "")
    ) != [
        "sudo apt-get update && sudo apt-get install -y "
        "libsqlite3-dev libssl-dev ninja-build"
    ]:
        raise GateError("CodeQL: dependency-install command drift")
    if not isinstance(build, dict) or set(build) != {"name", "run"}:
        raise GateError("CodeQL: build step fields are not closed")
    if build.get("name") != "Build C/C++ database":
        raise GateError("CodeQL: build step name drift")
    expected_build_commands = [
        "cmake -S . -B build/codeql -G Ninja -DNINLIL_BUILD_TESTS=OFF",
        "cmake --build build/codeql --parallel 2",
        "cmake -S . -B build/codeql-all-private -G Ninja "
        "-DNINLIL_BUILD_TESTS=ON "
        "-DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON "
        "-DNINLIL_ENABLE_PRIVATE_WIFI_V1=ON "
        "-DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON "
        "-DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON "
        "-DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON "
        "-DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON "
        "-DNINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=ON",
        "cmake --build build/codeql-all-private --target "
        "host_completion_all_private_build --parallel 2",
    ]
    if logical_shell_commands(build.get("run", "")) != expected_build_commands:
        raise GateError("CodeQL: build command sequence drift")
    if not isinstance(analyze, dict) or set(analyze) != {"uses"}:
        raise GateError("CodeQL: analyze step fields are not closed")
    if analyze.get("uses") != (
        "github/codeql-action/analyze@"
        f"{REMOTE_ACTIONS['github/codeql-action/analyze']}"
    ):
        raise GateError("CodeQL: analyze Action identity drift")
    require_exact_active_command(
        doc,
        [
            "cmake", "-S", ".", "-B", "build/codeql", "-G", "Ninja",
            "-DNINLIL_BUILD_TESTS=OFF",
        ],
        "build/codeql",
        "CodeQL installed Host configure",
    )
    require_exact_active_command(
        doc,
        ["cmake", "--build", "build/codeql", "--parallel", "2"],
        "build/codeql",
        "CodeQL installed Host build",
    )
    require_exact_active_command(
        doc,
        [
            "cmake", "-S", ".", "-B", "build/codeql-all-private", "-G",
            "Ninja", "-DNINLIL_BUILD_TESTS=ON",
            "-DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=ON",
            "-DNINLIL_ENABLE_PRIVATE_WIFI_V1=ON",
            "-DNINLIL_ENABLE_PRIVATE_FABRIC_V1=ON",
            "-DNINLIL_ENABLE_R7_FRAG_PRIVATE=ON",
            "-DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON",
            "-DNINLIL_ENABLE_MFDT_V1_PRIVATE=ON",
            "-DNINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=ON",
        ],
        "build/codeql-all-private",
        "CodeQL all-private Host configure",
    )
    require_exact_active_command(
        doc,
        [
            "cmake", "--build", "build/codeql-all-private", "--target",
            "host_completion_all_private_build", "--parallel", "2",
        ],
        "host_completion_all_private_build",
        "CodeQL all-private Host build",
    )


def validate_ci_badge(readme: str, ci: str) -> None:
    badges = re.findall(
        r"\[!\[[^\]\n]*\]\([^\)\n]*badge\.svg[^\)\n]*\)\]"
        r"\([^\)\n]*\)",
        readme,
    )
    if badges != [CI_BADGE]:
        raise GateError(
            "README badge authority must contain only the canonical main CI badge: "
            f"got={badges!r}"
        )
    doc = parse_workflow(ci, "CI badge")
    if doc.get("name") != "CI":
        raise GateError("README CI badge does not match the workflow display name")
    trigger_key: object = True if True in doc else "on"
    triggers = doc.get(trigger_key)
    if not isinstance(triggers, dict):
        raise GateError("CI badge workflow triggers are absent")
    push = triggers.get("push")
    if not isinstance(push, dict) or push.get("branches") != ["main"]:
        raise GateError("README CI badge branch must match CI push branch main")


def validate(inputs: Inputs) -> None:
    validate_reusable(inputs.ci, "CI")
    validate_reusable(inputs.esp, "ESP-IDF")
    validate_all_private_traceability_job(inputs.ci)
    validate_baseline_traceability_job(inputs.ci)
    validate_clang_release_r7_job(inputs.ci)
    validate_macos_dynamic_job(inputs.ci)
    validate_linter(inputs.ci)
    validate_decoder_fuzz_job(inputs.ci)
    validate_release(inputs.release)
    validate_dco(inputs.dco)
    validate_codeql(inputs.codeql)
    validate_coverage(inputs.coverage)
    validate_ci_badge(inputs.readme, inputs.ci)
    validate_all_uses(inputs)
    validate_setup_node(inputs)
    # Also run the dedicated version-identity self-test (fail-closed).
    import subprocess

    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "release_version_identity.py"), "self-test"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise GateError(
            f"release_version_identity self-test failed: {proc.stderr.strip()}"
        )


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

    nested_all_private_junit = copy.deepcopy(baseline)
    all_private_junit_path = "--output-junit traceability-cited-junit.xml"
    if nested_all_private_junit.ci.count(all_private_junit_path) != 1:
        raise GateError("self-test fixture missing all-private JUnit producer path")
    nested_all_private_junit.ci = nested_all_private_junit.ci.replace(
        all_private_junit_path,
        "--output-junit "
        "build/host-completion-allfeat/traceability-cited-junit.xml",
        1,
    )
    reject("all-private JUnit path nested below --test-dir", nested_all_private_junit)

    nested_baseline_junit = copy.deepcopy(baseline)
    nested_baseline_junit.ci = nested_baseline_junit.ci.replace(
        "--output-junit ctest-junit.xml",
        "--output-junit build/ci-ubuntu-dyn/ctest-junit.xml",
        1,
    )
    reject("baseline JUnit path nested below --test-dir", nested_baseline_junit)

    missing_baseline_junit = copy.deepcopy(baseline)
    missing_baseline_junit.ci = missing_baseline_junit.ci.replace(
        " --output-junit ctest-junit.xml",
        "",
        1,
    )
    reject("baseline JUnit producer removed", missing_baseline_junit)

    overwritten_all_private_junit = copy.deepcopy(baseline)
    all_private_body = job_body(
        overwritten_all_private_junit.ci,
        "host-completion-integrated-e2e",
    )
    all_private_self_test = (
        "          python3 tools/traceability_complete_coverage_gate.py "
        "--self-test\n"
    )
    if all_private_body.count(all_private_self_test) != 1:
        raise GateError("self-test fixture missing all-private evidence self-test")
    overwritten_all_private_body = all_private_body.replace(
        all_private_self_test,
        "          printf forged > "
        "build/host-completion-allfeat/traceability-cited-junit.xml\n"
        + all_private_self_test,
        1,
    )
    overwritten_all_private_junit.ci = overwritten_all_private_junit.ci.replace(
        all_private_body,
        overwritten_all_private_body,
        1,
    )
    reject(
        "all-private JUnit overwritten after production",
        overwritten_all_private_junit,
    )

    intermediate_all_private_overwrite = copy.deepcopy(baseline)
    all_private_body = job_body(
        intermediate_all_private_overwrite.ci,
        "host-completion-integrated-e2e",
    )
    all_private_evidence_step = (
        "      - name: Verify traceability registration coverage V2 (all-private)\n"
    )
    if all_private_body.count(all_private_evidence_step) != 1:
        raise GateError("self-test fixture missing all-private evidence step")
    intermediate_all_private_body = all_private_body.replace(
        all_private_evidence_step,
        "      - name: Overwrite all-private JUnit\n"
        "        run: printf forged > "
        "build/host-completion-allfeat/traceability-cited-junit.xml\n"
        + all_private_evidence_step,
        1,
    )
    intermediate_all_private_overwrite.ci = (
        intermediate_all_private_overwrite.ci.replace(
            all_private_body,
            intermediate_all_private_body,
            1,
        )
    )
    reject(
        "all-private JUnit overwritten in an intermediate step",
        intermediate_all_private_overwrite,
    )

    hijacked_all_private_commands = copy.deepcopy(baseline)
    all_private_body = job_body(
        hijacked_all_private_commands.ci,
        "host-completion-integrated-e2e",
    )
    all_private_producer_prefix = (
        "      - name: Produce traceability JUnit V2 (all-private)\n"
        "        run: >-\n"
        "          ctest --test-dir build/host-completion-allfeat \\\n"
    )
    if all_private_body.count(all_private_producer_prefix) != 1:
        raise GateError("self-test fixture missing all-private producer command")
    hijacked_all_private_body = all_private_body.replace(
        all_private_producer_prefix,
        "      - name: Produce traceability JUnit V2 (all-private)\n"
        "        run: >-\n"
        "          ctest() { printf forged > "
        "build/host-completion-allfeat/traceability-cited-junit.xml; };\n"
        "          python3() { return 0; };\n"
        "          ctest --test-dir build/host-completion-allfeat \\\n",
        1,
    )
    hijacked_all_private_commands.ci = hijacked_all_private_commands.ci.replace(
        all_private_body,
        hijacked_all_private_body,
        1,
    )
    reject("all-private evidence commands shadowed", hijacked_all_private_commands)

    missing_all_private_self_test = copy.deepcopy(baseline)
    all_private_body = job_body(
        missing_all_private_self_test.ci,
        "host-completion-integrated-e2e",
    )
    if all_private_body.count(all_private_self_test) != 1:
        raise GateError("self-test fixture missing all-private evidence self-test")
    missing_all_private_self_test.ci = missing_all_private_self_test.ci.replace(
        all_private_body,
        all_private_body.replace(all_private_self_test, "", 1),
        1,
    )
    reject("all-private evidence self-test removed", missing_all_private_self_test)

    overwritten_baseline_junit = copy.deepcopy(baseline)
    baseline_body = job_body(overwritten_baseline_junit.ci, "ubuntu-dynamic-strict")
    baseline_self_test = (
        "          python3 tools/traceability_complete_coverage_gate.py "
        "--self-test\n"
    )
    if baseline_body.count(baseline_self_test) != 1:
        raise GateError("self-test fixture missing baseline evidence self-test")
    overwritten_baseline_body = baseline_body.replace(
        baseline_self_test,
        baseline_self_test
        + "          printf forged > build/ci-ubuntu-dyn/ctest-junit.xml\n",
        1,
    )
    overwritten_baseline_junit.ci = overwritten_baseline_junit.ci.replace(
        baseline_body,
        overwritten_baseline_body,
        1,
    )
    reject(
        "baseline JUnit overwritten before evidence check",
        overwritten_baseline_junit,
    )

    intermediate_baseline_overwrite = copy.deepcopy(baseline)
    baseline_body = job_body(
        intermediate_baseline_overwrite.ci,
        "ubuntu-dynamic-strict",
    )
    baseline_evidence_step = (
        "      - name: Traceability registration coverage V2 (baseline)\n"
    )
    if baseline_body.count(baseline_evidence_step) != 1:
        raise GateError("self-test fixture missing baseline evidence step")
    intermediate_baseline_body = baseline_body.replace(
        baseline_evidence_step,
        "      - name: Overwrite baseline JUnit\n"
        "        run: printf forged > build/ci-ubuntu-dyn/ctest-junit.xml\n"
        + baseline_evidence_step,
        1,
    )
    intermediate_baseline_overwrite.ci = intermediate_baseline_overwrite.ci.replace(
        baseline_body,
        intermediate_baseline_body,
        1,
    )
    reject(
        "baseline JUnit overwritten in an intermediate step",
        intermediate_baseline_overwrite,
    )

    missing_baseline_self_test = copy.deepcopy(baseline)
    baseline_body = job_body(missing_baseline_self_test.ci, "ubuntu-dynamic-strict")
    if baseline_body.count(baseline_self_test) != 1:
        raise GateError("self-test fixture missing baseline evidence self-test")
    missing_baseline_self_test.ci = missing_baseline_self_test.ci.replace(
        baseline_body,
        baseline_body.replace(baseline_self_test, "", 1),
        1,
    )
    reject("baseline evidence self-test removed", missing_baseline_self_test)

    non_blocking_baseline_job = copy.deepcopy(baseline)
    baseline_body = job_body(non_blocking_baseline_job.ci, "ubuntu-dynamic-strict")
    timeout_line = "    timeout-minutes: 40\n"
    if baseline_body.count(timeout_line) != 1:
        raise GateError("self-test fixture missing baseline job timeout")
    non_blocking_baseline_body = baseline_body.replace(
        timeout_line,
        timeout_line + "    continue-on-error: true\n",
        1,
    )
    non_blocking_baseline_job.ci = non_blocking_baseline_job.ci.replace(
        baseline_body,
        non_blocking_baseline_body,
        1,
    )
    reject("baseline evidence job made non-blocking", non_blocking_baseline_job)

    non_blocking_all_private_job = copy.deepcopy(baseline)
    all_private_body = job_body(
        non_blocking_all_private_job.ci,
        "host-completion-integrated-e2e",
    )
    timeout_line = "    timeout-minutes: 45\n"
    if all_private_body.count(timeout_line) != 1:
        raise GateError("self-test fixture missing all-private job timeout")
    non_blocking_all_private_body = all_private_body.replace(
        timeout_line,
        timeout_line + "    continue-on-error: true\n",
        1,
    )
    non_blocking_all_private_job.ci = non_blocking_all_private_job.ci.replace(
        all_private_body,
        non_blocking_all_private_body,
        1,
    )
    reject("all-private evidence job made non-blocking", non_blocking_all_private_job)

    short_clang_release = copy.deepcopy(baseline)
    clang_release_body = job_body(
        short_clang_release.ci, "ubuntu-clang-release-r7"
    )
    if clang_release_body.count("    timeout-minutes: 45\n") != 1:
        raise GateError("self-test fixture missing Clang Release R7 budget")
    short_clang_release.ci = short_clang_release.ci.replace(
        clang_release_body,
        clang_release_body.replace("timeout-minutes: 45", "timeout-minutes: 35"),
        1,
    )
    reject("Clang Release R7 measured budget shortened", short_clang_release)

    short_macos_dynamic = copy.deepcopy(baseline)
    macos_dynamic_body = job_body(short_macos_dynamic.ci, "macos-dynamic")
    if macos_dynamic_body.count("    timeout-minutes: 50\n") != 1:
        raise GateError("self-test fixture missing macOS dynamic budget")
    short_macos_dynamic.ci = short_macos_dynamic.ci.replace(
        macos_dynamic_body,
        macos_dynamic_body.replace("timeout-minutes: 50", "timeout-minutes: 35"),
        1,
    )
    reject("macOS dynamic measured budget shortened", short_macos_dynamic)

    floating_dco_checkout = copy.deepcopy(baseline)
    floating_dco_checkout.dco = floating_dco_checkout.dco.replace(
        f"actions/checkout@{REMOTE_ACTIONS['actions/checkout']}",
        "actions/checkout@main",
        1,
    )
    reject("floating DCO checkout", floating_dco_checkout)

    head_controlled_dco_gate = copy.deepcopy(baseline)
    head_controlled_dco_gate.dco = head_controlled_dco_gate.dco.replace(
        'git show "${BASE_SHA}:tools/dco_signoff_gate.py" > '
        '"${RUNNER_TEMP}/dco_signoff_gate.py"',
        'cp tools/dco_signoff_gate.py "${RUNNER_TEMP}/dco_signoff_gate.py"',
        1,
    )
    reject("DCO verifier loaded from untrusted PR head", head_controlled_dco_gate)

    missing_dco_check = copy.deepcopy(baseline)
    missing_dco_check.dco = missing_dco_check.dco.replace(
        'python3 "${RUNNER_TEMP}/dco_signoff_gate.py" check-range '
        '"${BASE_SHA}" "${HEAD_SHA}"',
        "true",
        1,
    )
    reject("DCO range check removed", missing_dco_check)

    header_only_coverage = copy.deepcopy(baseline)
    header_only_coverage.coverage = header_only_coverage.coverage.replace(
        "ninlil_v1_runtime_delivery_test",
        "ninlil_smoke_c11",
    ).replace("v1_runtime_delivery", "smoke_c11")
    reject("header-only smoke masquerades as Runtime coverage", header_only_coverage)

    privileged_coverage = copy.deepcopy(baseline)
    privileged_coverage.coverage = privileged_coverage.coverage.replace(
        "  pull_request:\n",
        "  pull_request_target:\n",
        1,
    ).replace(
        "permissions:\n  contents: read",
        "permissions: write-all",
        1,
    ).replace(
        "        with:\n          persist-credentials: false",
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "          persist-credentials: true",
        1,
    )
    reject(
        "Coverage privileged target trigger executes untrusted PR head",
        privileged_coverage,
    )

    public_only_codeql = copy.deepcopy(baseline)
    public_only_codeql.codeql = public_only_codeql.codeql.replace(
        "          cmake --build build/codeql-all-private \\\n"
        "            --target host_completion_all_private_build --parallel 2\n",
        "",
        1,
    )
    reject("CodeQL omits all-private Host production build", public_only_codeql)

    partial_private_codeql = copy.deepcopy(baseline)
    partial_private_codeql.codeql = partial_private_codeql.codeql.replace(
        "            -DNINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=ON \\\n",
        "",
        1,
    )
    reject("CodeQL all-private profile omits RRMP", partial_private_codeql)

    one_short_fuzzer = copy.deepcopy(baseline)
    for spec in (
        "            ninlil_rrmp_codec_fuzzer:rrmp_codec\n",
        "            ninlil_r7_wire_codec_fuzzer:r7_wire_codec\n",
        "            ninlil_r7_frag_wire_fuzzer:r7_frag_wire\n",
        "            ninlil_n6_record_codec_fuzzer:n6_record_codec\n",
        "            ninlil_domain_store_body_codec_fuzzer:domain_store_body_codec\n",
    ):
        one_short_fuzzer.ci = one_short_fuzzer.ci.replace(spec, "", 1)
    one_short_fuzzer.ci = one_short_fuzzer.ci.replace(
        "-max_total_time=300",
        "-max_total_time=1",
        1,
    )
    reject("Decoder fuzz reduced to one one-second boundary", one_short_fuzzer)

    privileged_codeql = copy.deepcopy(baseline)
    privileged_codeql.codeql = privileged_codeql.codeql.replace(
        "  pull_request:\n",
        "  pull_request_target:\n",
        1,
    ).replace(
        "permissions:\n  contents: read\n  security-events: write",
        "permissions: write-all",
        1,
    ).replace(
        "        with:\n          persist-credentials: false",
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
        "          persist-credentials: true",
        1,
    )
    reject(
        "CodeQL privileged target trigger checks out untrusted PR head",
        privileged_codeql,
    )

    wrong_badge_branch = copy.deepcopy(baseline)
    wrong_badge_branch.readme = wrong_badge_branch.readme.replace(
        "badge.svg?branch=main",
        "badge.svg?branch=next",
        1,
    )
    reject("README CI badge branch drift", wrong_badge_branch)

    smuggle_sha = copy.deepcopy(baseline)
    smuggle_sha.ci = smuggle_sha.ci.replace(
        f"ref: {SOURCE_REF}",
        f"ref: ${{{{ github.sha }}}}  # ref: {SOURCE_REF}",
        1,
    )
    reject("source ref github.sha with old token in comment", smuggle_sha)

    smuggle_ref = copy.deepcopy(baseline)
    smuggle_ref.ci = smuggle_ref.ci.replace(
        f"ref: {SOURCE_REF}",
        f"ref: ${{{{ github.ref }}}}  # ref: {SOURCE_REF}",
        1,
    )
    reject("reusable checkout ref github.ref with old token in comment", smuggle_ref)

    # env.ref decoy while with.ref is mutable.
    env_decoy = copy.deepcopy(baseline)
    env_decoy.ci = env_decoy.ci.replace(
        f"ref: {SOURCE_REF}\n          persist-credentials: false",
        f"ref: ${{{{ github.ref }}}}\n          env:\n            ref: {SOURCE_REF}\n"
        f"          persist-credentials: false",
        1,
    )
    reject("checkout ref github.ref with env.ref decoy", env_decoy)

    # persist-credentials true + env false decoy.
    persist_decoy = copy.deepcopy(baseline)
    persist_decoy.ci = persist_decoy.ci.replace(
        "persist-credentials: false",
        "persist-credentials: true\n          env:\n            persist-credentials: false",
        1,
    )
    reject("persist-credentials true with env false decoy", persist_decoy)

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

    for label, injection in (
        (
            "added uses attacker/evil@main",
            "\n      - uses: attacker/evil@main\n",
        ),
        (
            r'unicode escaped key \u0075ses attacker',
            '\n      - "\\u0075ses": attacker/evil@main\n',
        ),
        (
            'quoted key "uses" attacker/evil@main',
            '\n      - "uses": attacker/evil@main\n',
        ),
        (
            "flow map uses attacker/evil@main",
            "\n      - {uses: attacker/evil@main}\n",
        ),
        (
            "block scalar uses attacker/evil@main",
            "\n      - uses: |\n          attacker/evil@main\n",
        ),
        (
            "variable uses",
            "\n      - uses: ${{ vars.EVIL }}\n",
        ),
        (
            "quoted scalar uses attacker",
            '\n      - uses: "attacker/evil@main"\n',
        ),
    ):
        mut = copy.deepcopy(baseline)
        mut.release = mut.release + injection
        reject(label, mut)

    duplicate_action = copy.deepcopy(baseline)
    duplicate_action.release += (
        "\n  extra-action:\n"
        "    runs-on: ubuntu-24.04\n"
        "    steps:\n"
        "      - uses: actions/checkout@"
        "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0\n"
        f"        with:\n"
        f"          ref: {SOURCE_REF}\n"
        "          persist-credentials: false\n"
    )
    reject("unexpected duplicate allowed Action", duplicate_action)

    # Preserve the old global checkout total while moving source identity from
    # one semantic job into another. A count-only gate accepts this shape; the
    # closed job/action authority must reject it.
    relocated_checkout = copy.deepcopy(baseline)
    checkout_block = (
        f"      - uses: actions/checkout@{REMOTE_ACTIONS['actions/checkout']}\n"
        "        with:\n"
        f"          ref: {SOURCE_REF}\n"
        "          persist-credentials: false\n"
    )
    if relocated_checkout.ci.count(checkout_block) < 2:
        raise GateError("self-test fixture missing reusable checkout blocks")
    relocated_checkout.ci = relocated_checkout.ci.replace(
        checkout_block,
        "      - run: true\n",
        1,
    )
    relocated_checkout.ci = relocated_checkout.ci.replace(
        checkout_block,
        checkout_block + checkout_block,
        1,
    )
    reject(
        "checkout relocated between jobs with unchanged global count",
        relocated_checkout,
    )

    workflow_split = copy.deepcopy(baseline)
    workflow_split.release = workflow_split.release.replace(
        f"workflow-definition-ref: {WORKFLOW_REF}",
        "workflow-definition-ref: ${{ github.sha }}",
        1,
    )
    reject("reusable workflow definition split", workflow_split)

    privileged_release = copy.deepcopy(baseline)
    privileged_release.release = privileged_release.release.replace(
        "on:\n  push:",
        "on:\n  pull_request_target:\n  push:",
        1,
    ).replace(
        "permissions:\n  contents: read",
        "permissions: write-all",
        1,
    ).replace(
        (
            "ref: ${{ github.event_name == 'workflow_dispatch' && "
            "inputs.ref || github.sha }}"
        ),
        (
            "ref: ${{ github.event.pull_request.head.sha }}  # ref: "
            "${{ github.event_name == 'workflow_dispatch' && "
            "inputs.ref || github.sha }}"
        ),
        1,
    ).replace(
        "  verify:\n    name: Full host verification\n",
        "  verify:\n    name: Full host verification\n    env:\n"
        "      GH_TOKEN: ${{ github.token }}\n",
        1,
    )
    reject(
        "Release privileged target trigger executes untrusted PR head",
        privileged_release,
    )

    for label, field in (("CI", "ci"), ("ESP-IDF", "esp")):
        privileged_reusable = copy.deepcopy(baseline)
        original = getattr(privileged_reusable, field)
        mutated = original.replace(
            "  pull_request:\n",
            "  pull_request_target:\n",
            1,
        ).replace(
            "permissions:\n  contents: read",
            "permissions: write-all",
            1,
        )
        first_steps = "    steps:\n"
        injected = (
            "    steps:\n"
            "      - name: Execute untrusted PR head\n"
            "        env:\n"
            "          GH_TOKEN: ${{ github.token }}\n"
            "        run: git fetch origin '${{ github.event.pull_request.head.sha }}' "
            "&& git checkout FETCH_HEAD && ./attacker-code\n"
        )
        mutated = mutated.replace(first_steps, injected, 1)
        setattr(privileged_reusable, field, mutated)
        reject(
            f"{label} privileged target trigger executes untrusted PR head",
            privileged_reusable,
        )

    missing_metadata = copy.deepcopy(baseline)
    missing_metadata.release = missing_metadata.release.replace(
        '"workflow_definition_commit": workflow_commit',
        '"workflow_definition": workflow_commit',
        1,
    )
    reject("workflow identity absent from metadata", missing_metadata)

    float_checkout = copy.deepcopy(baseline)
    pin = REMOTE_ACTIONS["actions/checkout"]
    float_checkout.ci = float_checkout.ci.replace(
        f"uses: actions/checkout@{pin}",
        f"uses: actions/checkout@main  # uses: actions/checkout@{pin}",
        1,
    )
    reject("checkout uses @main with old SHA in comment", float_checkout)

    wrong_node_version = copy.deepcopy(baseline)
    wrong_node_version.ci = wrong_node_version.ci.replace(
        "          node-version: 22.18.0",
        "          node-version: 18.0.0",
        1,
    )
    reject("setup-node version drift", wrong_node_version)

    # Version identity: workflow must not accept arbitrary SemVer / wrong core.
    strip_enforce = copy.deepcopy(baseline)
    strip_enforce.release = strip_enforce.release.replace(
        "python3 tools/release_version_identity.py enforce",
        "echo bypass-version-identity",
        1,
    )
    reject("remove release_version_identity enforce", strip_enforce)

    fabricated_identity = copy.deepcopy(baseline)
    enforce_block = (
        '          identity_json="$(python3 tools/release_version_identity.py enforce \\\n'
        '            --event-name "${EVENT_NAME}" \\\n'
        '            --ref-name "${REF_NAME}" \\\n'
        '            --ref-type "${REF_TYPE}" \\\n'
        '            --commit "${commit}")"'
    )
    fabricated_block = (
        "          # identity_json=\"$(python3 "
        "tools/release_version_identity.py enforce \\\n"
        '          #   --event-name "${EVENT_NAME}" \\\n'
        '          #   --ref-name "${REF_NAME}" \\\n'
        '          #   --ref-type "${REF_TYPE}" \\\n'
        '          #   --commit "${commit}")"\n'
        "          identity_json='{\"core\":\"0.0.0\","
        "\"base\":\"forged\",\"source_version\":\"forged\",\"tag\":\"\"}'"
    )
    if enforce_block not in fabricated_identity.release:
        raise GateError("self-test fixture missing release identity enforce block")
    fabricated_identity.release = fabricated_identity.release.replace(
        enforce_block,
        fabricated_block,
        1,
    )
    reject("commented enforce with fabricated identity JSON", fabricated_identity)

    strip_core_test = copy.deepcopy(baseline)
    strip_core_test.release = strip_core_test.release.replace(
        'test "${core}" = "$(python3 tools/release_version_identity.py print-core)"',
        "true",
        1,
    )
    reject("remove core print-core equality check", strip_core_test)

    loose_semver = copy.deepcopy(baseline)
    # Re-introduce pre-fix loose tag regex path (no core bind).
    loose_semver.release = loose_semver.release.replace(
        "python3 tools/release_version_identity.py self-test\n",
        "python3 tools/release_version_identity.py self-test\n"
        '          # release tag must be SemVer with a leading v\n',
        1,
    )
    reject("reintroduce loose SemVer-only tag acceptance string", loose_semver)

    worktree_archive = copy.deepcopy(baseline)
    worktree_archive.release = worktree_archive.release.replace(
        "--source git",
        "--source worktree",
        1,
    )
    reject("release archive sourced from mutable worktree", worktree_archive)

    duplicate_archive_source = copy.deepcopy(baseline)
    duplicate_archive_source.release = duplicate_archive_source.release.replace(
        "--source git",
        "--source git --source worktree",
        1,
    )
    reject("release archive duplicate source override", duplicate_archive_source)

    missing_archive_source = copy.deepcopy(baseline)
    missing_archive_source.release = missing_archive_source.release.replace(
        "--source git",
        "",
        1,
    )
    reject("release archive missing source authority", missing_archive_source)

    missing_two_run = copy.deepcopy(baseline)
    missing_two_run.release = missing_two_run.release.replace(
        "            --two-run \\\n"
        "            --source git",
        "            --source git",
        1,
    )
    reject("release archive missing two-run authority", missing_two_run)

    missing_clean_checkout = copy.deepcopy(baseline)
    missing_clean_checkout.release = missing_clean_checkout.release.replace(
        "            --require-clean-worktree \\\n",
        "",
        1,
    )
    reject(
        "release archive missing clean-worktree authority",
        missing_clean_checkout,
    )

    force_live_gate_overlay = copy.deepcopy(baseline)
    force_live_gate_overlay.release = force_live_gate_overlay.release.replace(
        "            --no-force-release-gates \\\n",
        "",
        1,
    )
    reject(
        "release archive permits live gate overlay",
        force_live_gate_overlay,
    )

    metadata_inside_worktree = copy.deepcopy(baseline)
    metadata_inside_worktree.release = metadata_inside_worktree.release.replace(
        (
            "          BUILD_METADATA: ${{ runner.temp }}/"
            "${{ steps.metadata.outputs.base }}.build-metadata.json"
        ),
        "          BUILD_METADATA: dist/${{ steps.metadata.outputs.base }}.build-metadata.json",
        1,
    )
    reject(
        "build metadata staged inside worktree before clean check",
        metadata_inside_worktree,
    )

    early_dist = copy.deepcopy(baseline)
    early_dist.release = early_dist.release.replace(
        (
            '        run: |\n'
            '          test -s "${SBOM}"\n\n'
            '          python3 - "${BASE}"'
        ),
        (
            '        run: |\n'
            '          mkdir -p dist\n'
            '          test -s "${SBOM}"\n\n'
            '          python3 - "${BASE}"'
        ),
        1,
    )
    reject("dist created before clean git archive", early_dist)

    cleanroom_without_shipped_archives = copy.deepcopy(baseline)
    cleanroom_without_shipped_archives.release = (
        cleanroom_without_shipped_archives.release.replace(
            '          python3 tools/release_archive_payload_gate.py cleanroom \\\n'
            '            --tar "dist/${BASE}.tar.gz" \\\n'
            '            --zip "dist/${BASE}.zip" \\\n'
            '            --prefix "${BASE}" \\\n'
            "            --profile host \\\n"
            '            --out-dir "${RUNNER_TEMP}/ninlil-release-cleanroom"',
            "          python3 tools/release_archive_payload_gate.py cleanroom "
            "--profile host "
            '--out-dir "${RUNNER_TEMP}/ninlil-release-cleanroom"',
            1,
        )
    )
    reject(
        "clean-room rebuild detached from shipped archives",
        cleanroom_without_shipped_archives,
    )

    commented_distribution_gate = copy.deepcopy(baseline)
    commented_distribution_gate.release = (
        commented_distribution_gate.release.replace(
            "          python3 tools/release_distribution_authority_gate.py check",
            "          # python3 tools/release_distribution_authority_gate.py check",
            1,
        )
    )
    reject("commented release distribution authority", commented_distribution_gate)

    commented_workflow_equality = copy.deepcopy(baseline)
    commented_workflow_equality.release = (
        commented_workflow_equality.release.replace(
            '          test "${ACTUAL_WORKFLOW_COMMIT}" = "${RESOLVED_WORKFLOW_COMMIT}"',
            '          # test "${ACTUAL_WORKFLOW_COMMIT}" = "${RESOLVED_WORKFLOW_COMMIT}"',
            1,
        )
    )
    reject("commented workflow commit equality", commented_workflow_equality)

    commented_linter = copy.deepcopy(baseline)
    commented_linter.ci = commented_linter.ci.replace(
        '          "${RUNNER_TEMP}/actionlint/actionlint"',
        '          # "${RUNNER_TEMP}/actionlint/actionlint"',
        1,
    )
    reject("commented pinned linter argv", commented_linter)

    strip_project_version = copy.deepcopy(baseline)
    strip_project_version.release = strip_project_version.release.replace(
        '--project-version "${PROJECT_VERSION}"',
        "",
    )
    reject("SBOM enrich without --project-version", strip_project_version)

    strip_source_version = copy.deepcopy(baseline)
    strip_source_version.release = strip_source_version.release.replace(
        '--source-version "${SOURCE_VERSION}"',
        "",
    )
    reject("SBOM enrich without --source-version", strip_source_version)

    broad_syft_catalogers = copy.deepcopy(baseline)
    broad_syft_catalogers.release = broad_syft_catalogers.release.replace(
        "--select-catalogers=-github-actions-usage-cataloger,-github-action-workflow-usage-cataloger",
        "",
    )
    reject(
        "SBOM scan without exact GitHub Actions cataloger exclusions",
        broad_syft_catalogers,
    )

    hidden_narrow_syft_catalogers = copy.deepcopy(baseline)
    hidden_narrow_syft_catalogers.release = (
        "# --select-catalogers=-github-actions-usage-cataloger,"
        "-github-action-workflow-usage-cataloger\n"
        + hidden_narrow_syft_catalogers.release.replace(
            "--select-catalogers=-github-actions-usage-cataloger,"
            "-github-action-workflow-usage-cataloger",
            "--override-default-catalogers python-installed-package-cataloger",
            1,
        )
    )
    reject(
        "SBOM scan narrowed while exact cataloger flag survives only in comment",
        hidden_narrow_syft_catalogers,
    )

    wrong_base = copy.deepcopy(baseline)
    wrong_base.release = wrong_base.release.replace(
        'test "${base}" = "ninlil-runtime-${tag}"',
        "true",
        1,
    )
    reject("artifact base not bound to tag", wrong_base)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    try:
        # Ensure vendor path is importable when run as a script.
        tools_dir = str(ROOT / "tools")
        if tools_dir not in sys.path:
            sys.path.insert(0, tools_dir)
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
