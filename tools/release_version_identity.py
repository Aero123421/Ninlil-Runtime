#!/usr/bin/env python3
"""Canonical release version identity (fail-closed).

Policy
------
- Canonical *core* version is CMake ``project(ninlil VERSION X.Y.Z)`` and must
  equal ``compatibility-matrix.json:runtime_release``,
  ``dependency-inventory.json:project.version``, and
  ``ports/esp-idf/components/ninlil/idf_component.yml:version``.
- Core components are decimal integers without leading zeros
  (``0`` allowed; ``01`` rejected).
- Publish tags must match::

      vCORE[ -PRERELEASE ][ +BUILD ]

  where CORE is exactly the canonical core. Prerelease/build suffixes do not
  change package/matrix/CMake core identity; artifact base may use the full tag.
- Dry-run (workflow_dispatch) has no publish tag; core is still validated.
- Invalid SemVer, wrong core, leading zeros, or empty core → hard fail.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]

# Core: 0 | [1-9][0-9]* for each of major.minor.patch (no leading zeros).
CORE_RE = re.compile(
    r"^(?P<core>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$"
)
# Full release tag: vCORE[-pre][+build]
TAG_RE = re.compile(
    r"^v"
    r"(?P<core>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))"
    r"(?P<pre>-(?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?P<build>\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"$"
)
CMAKE_VERSION_RE = re.compile(
    r"^project\(ninlil VERSION ([0-9]+\.[0-9]+\.[0-9]+) LANGUAGES C CXX\)$",
    re.MULTILINE,
)
IDF_VERSION_RE = re.compile(r'^version: "([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE)


class VersionIdentityError(RuntimeError):
    """Fail-closed release version identity error."""


def read_text(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise VersionIdentityError(f"cannot read {path}: {exc}") from exc


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise VersionIdentityError(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise VersionIdentityError(f"{path}: top-level must be object")
    return value


def normalize_core(value: str, label: str) -> str:
    match = CORE_RE.fullmatch(value.strip())
    if match is None:
        raise VersionIdentityError(
            f"{label}: core version must be MAJOR.MINOR.PATCH without leading "
            f"zeros (got {value!r})"
        )
    return match.group("core")


def read_canonical_core(root: pathlib.Path = ROOT) -> str:
    """Return the single canonical core version shared by all project metadata."""
    cmake = read_text(root / "CMakeLists.txt")
    cmake_matches = CMAKE_VERSION_RE.findall(cmake)
    if len(cmake_matches) != 1:
        raise VersionIdentityError(
            f"CMake project VERSION: expected exactly one match, got {len(cmake_matches)}"
        )
    cmake_version = normalize_core(cmake_matches[0], "CMake")

    matrix = load_json(root / "compatibility-matrix.json")
    matrix_version = normalize_core(str(matrix.get("runtime_release", "")), "matrix")

    inventory = load_json(root / "dependency-inventory.json")
    project = inventory.get("project")
    if not isinstance(project, dict):
        raise VersionIdentityError("dependency inventory project must be an object")
    inventory_version = normalize_core(str(project.get("version", "")), "inventory")

    component = read_text(
        root / "ports" / "esp-idf" / "components" / "ninlil" / "idf_component.yml"
    )
    idf_matches = IDF_VERSION_RE.findall(component)
    if len(idf_matches) != 1:
        raise VersionIdentityError(
            f"ESP idf_component.yml version: expected exactly one match, "
            f"got {len(idf_matches)}"
        )
    esp_version = normalize_core(idf_matches[0], "ESP component")

    versions = {
        "cmake": cmake_version,
        "matrix": matrix_version,
        "inventory": inventory_version,
        "esp_component": esp_version,
    }
    unique = set(versions.values())
    if len(unique) != 1:
        raise VersionIdentityError(
            f"canonical core version drift across authorities: {versions}"
        )
    return cmake_version


def parse_release_tag(tag: str) -> dict[str, str | None]:
    match = TAG_RE.fullmatch(tag.strip())
    if match is None:
        raise VersionIdentityError(
            f"release tag must be vMAJOR.MINOR.PATCH with optional "
            f"-prerelease and/or +build, no leading zeros in core "
            f"(got {tag!r})"
        )
    return {
        "tag": tag.strip(),
        "core": match.group("core"),
        "prerelease": match.group("pre"),
        "build": match.group("build"),
    }


def check_tag_matches_core(tag: str, core: str) -> dict[str, str | None]:
    parsed = parse_release_tag(tag)
    if parsed["core"] != core:
        raise VersionIdentityError(
            f"release tag core {parsed['core']!r} must equal canonical core "
            f"{core!r} (tag={tag!r})"
        )
    return parsed


def artifact_base_for_tag(tag: str) -> str:
    """Artifact prefix uses the full validated tag (includes prerelease/build)."""
    parse_release_tag(tag)  # validate form
    return f"ninlil-runtime-{tag}"


def artifact_base_for_dry_run(commit: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise VersionIdentityError("dry-run commit must be a full 40-char SHA")
    return f"ninlil-runtime-dry-run-{commit[:12]}"


def enforce(
    *,
    event_name: str,
    ref_name: str = "",
    ref_type: str = "",
    commit: str = "",
    root: pathlib.Path = ROOT,
) -> dict[str, str]:
    """Return outputs: core, tag, base, source_version, project_version."""
    core = read_canonical_core(root)
    if event_name == "push":
        if ref_type and ref_type != "tag":
            raise VersionIdentityError(
                f"push release events must be tags (ref_type={ref_type!r})"
            )
        tag = ref_name
        if not tag:
            raise VersionIdentityError("push release requires ref_name tag")
        check_tag_matches_core(tag, core)
        base = artifact_base_for_tag(tag)
        source_version = tag
        return {
            "core": core,
            "project_version": core,
            "tag": tag,
            "base": base,
            "source_version": source_version,
        }
    if event_name == "workflow_dispatch":
        if not commit:
            raise VersionIdentityError("dry-run requires full source commit")
        base = artifact_base_for_dry_run(commit)
        return {
            "core": core,
            "project_version": core,
            "tag": "",
            "base": base,
            "source_version": commit,
        }
    raise VersionIdentityError(f"unsupported event_name: {event_name!r}")


def self_test() -> None:
    core = read_canonical_core(ROOT)
    if not CORE_RE.fullmatch(core):
        raise VersionIdentityError(f"self-test: bad core from tree: {core!r}")

    # Valid tag with optional prerelease/build.
    check_tag_matches_core(f"v{core}", core)
    check_tag_matches_core(f"v{core}-rc.1", core)
    check_tag_matches_core(f"v{core}+build.1", core)
    check_tag_matches_core(f"v{core}-rc.1+build.1", core)

    def reject(label: str, fn) -> None:
        try:
            fn()
        except VersionIdentityError:
            return
        raise VersionIdentityError(f"self-test mutation was accepted: {label}")

    # Wrong core (e.g. v9.9.9 while tree is 0.1.0).
    wrong_parts = core.split(".")
    wrong = f"{int(wrong_parts[0]) + 9}.{wrong_parts[1]}.{wrong_parts[2]}"
    reject(
        "wrong core tag",
        lambda: check_tag_matches_core(f"v{wrong}", core),
    )
    reject(
        "prerelease with wrong core",
        lambda: check_tag_matches_core(f"v{wrong}-rc.1", core),
    )
    reject(
        "build metadata with wrong core",
        lambda: check_tag_matches_core(f"v{wrong}+meta", core),
    )
    reject(
        "leading zero major",
        lambda: parse_release_tag("v01.0.0"),
    )
    reject(
        "leading zero minor",
        lambda: parse_release_tag(f"v{core.split('.')[0]}.01.0"),
    )
    reject(
        "leading zero patch",
        lambda: parse_release_tag("v0.1.00"),
    )
    reject(
        "missing v prefix",
        lambda: parse_release_tag(core),
    )
    reject(
        "invalid tag garbage",
        lambda: parse_release_tag("v1.2"),
    )
    reject(
        "empty tag",
        lambda: parse_release_tag(""),
    )

    # enforce happy path
    out = enforce(
        event_name="push",
        ref_name=f"v{core}",
        ref_type="tag",
        commit="a" * 40,
    )
    if out["core"] != core or out["base"] != f"ninlil-runtime-v{core}":
        raise VersionIdentityError(f"self-test enforce push drift: {out}")
    dry = enforce(
        event_name="workflow_dispatch",
        commit="b" * 40,
    )
    if dry["tag"] != "" or dry["project_version"] != core:
        raise VersionIdentityError(f"self-test enforce dry-run drift: {dry}")
    reject(
        "enforce push wrong core",
        lambda: enforce(
            event_name="push",
            ref_name=f"v{wrong}",
            ref_type="tag",
            commit="a" * 40,
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("print-core", help="Print canonical core version")
    sub.add_parser("self-test", help="Mutation self-test")

    p_tag = sub.add_parser("check-tag", help="Validate tag against canonical core")
    p_tag.add_argument("--tag", required=True)

    p_en = sub.add_parser("enforce", help="Fail-closed release identity for a run")
    p_en.add_argument("--event-name", required=True, choices=("push", "workflow_dispatch"))
    p_en.add_argument("--ref-name", default="")
    p_en.add_argument("--ref-type", default="")
    p_en.add_argument("--commit", default="")
    p_en.add_argument(
        "--github-output",
        action="store_true",
        help="Append core/tag/base/source_version/project_version to $GITHUB_OUTPUT",
    )

    args = parser.parse_args()
    try:
        if args.command == "print-core":
            print(read_canonical_core(ROOT))
        elif args.command == "self-test":
            self_test()
            print("release version identity self-test: PASS")
        elif args.command == "check-tag":
            core = read_canonical_core(ROOT)
            parsed = check_tag_matches_core(args.tag, core)
            print(json.dumps(parsed, sort_keys=True))
        else:
            result = enforce(
                event_name=args.event_name,
                ref_name=args.ref_name,
                ref_type=args.ref_type,
                commit=args.commit,
            )
            if args.github_output:
                import os

                out_path = os.environ.get("GITHUB_OUTPUT")
                if not out_path:
                    raise VersionIdentityError("GITHUB_OUTPUT is not set")
                with open(out_path, "a", encoding="utf-8") as handle:
                    for key, value in result.items():
                        handle.write(f"{key}={value}\n")
            print(json.dumps(result, sort_keys=True))
    except VersionIdentityError as exc:
        print(f"release version identity: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
