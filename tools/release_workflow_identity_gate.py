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
REMOTE_ACTIONS = {
    "actions/checkout": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
    "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
    "actions/upload-artifact": "ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact": "634f93cb2916e3fdff6788551b99b062d0335ce0",
    "actions/attest": "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6",
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


def validate(inputs: Inputs) -> None:
    validate_reusable(inputs.ci, "CI")
    validate_reusable(inputs.esp, "ESP-IDF")
    validate_linter(inputs.ci)
    validate_release(inputs.release)
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
