#!/usr/bin/env python3
"""Fail-closed V2 traceability registration coverage authority.

The historical filename remains stable for existing automation; the emitted
gate and CTest names describe the narrower registration claim.

V2 deliberately separates three claims:

* structural coverage: every non-fenced H2/H3/H4 heading, explicit
  ``NIN-FND-*`` requirement set, and NIN-INV-001..014 is indexed;
* identity stability: IDs are explicit values bound to full heading paths and
  are never derived from current document order;
* enabled evidence: referenced tests must exist in a configured CTest JSON
  registry for the profile being checked.

Source hashes are drift fences only.  They are not treated as evidence that a
test proves newly-added prose. Focused invariant evidence pins static,
reader-reviewable, assertion-bearing anchors in test sources. The lexical
floor rejects commented-out, incomplete, and obviously vacuous assertions;
it does not establish semantic sufficiency or measure assertion strength.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


FORMAT = "NINLIL_TRACEABILITY_COVERAGE_V2"
MANIFEST = "requirements-traceability-coverage.json"
EXPECTED_SOURCES = (
    "docs/12-foundation-abi.md",
    "docs/13-foundation-state-machine.md",
    "docs/14-foundation-ports-and-simulator.md",
)
EXPECTED_INVARIANTS = tuple(f"NIN-INV-{index:03d}" for index in range(1, 15))
EXPECTED_PROFILES = ("baseline", "all-private")
HEADING_ID_RE = re.compile(r"^NIN-PR1-DOC(?:12|13|14)-[A-Z0-9-]+$")
FND_ID_RE = re.compile(r"^NIN-FND-[A-Z0-9-]+$")
INVARIANT_ID_RE = re.compile(r"^NIN-INV-(?:00[1-9]|01[0-4])$")
TEST_ID_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.+-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ATX_RE = re.compile(r"^(#{2,4}) ([^#].*?)\s*$")
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
FND_RE = re.compile(r"`(NIN-FND-[A-Z0-9-]+)`")
INVARIANT_RE = re.compile(r"^- `(NIN-INV-[0-9]{3})`: .+$")
ASSERTION_REGION_RE = re.compile(
    r"\b(?:REQUIRE|CHECK|expect_(?:t|i|st|u64))\s*\([^;]*\)\s*;",
    re.DOTALL,
)
VACUOUS_ASSERTION_RE = re.compile(
    r"\s*(?:(?:REQUIRE|CHECK)\s*\(\s*"
    r"(?:1[uUlL]*|true|TRUE|!\s*0[uUlL]*)\s*\)"
    r"|expect_t\s*\(\s*,\s*"
    r"(?:1[uUlL]*|true|TRUE|!\s*0[uUlL]*)\s*\))\s*;\s*",
    re.DOTALL,
)
CPP_CONDITIONAL_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef|endif)\b")


class CoverageError(ValueError):
    """Deterministic reader-facing validation failure."""


def _reject_duplicate_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CoverageError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _json_load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_object_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CoverageError(f"cannot read strict JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise CoverageError(f"{path} root must be an object")
    return value


def _object(value: Any, context: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CoverageError(f"{context} must be an object")
    actual = set(value)
    if actual != keys:
        raise CoverageError(
            f"{context} fields mismatch: "
            f"missing={sorted(keys - actual)} extra={sorted(actual - keys)}"
        )
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise CoverageError(f"{context} must be an array")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_path(root: Path, relative: Any, context: str) -> tuple[str, Path]:
    if not isinstance(relative, str) or relative.startswith("/"):
        raise CoverageError(f"{context} has invalid repository path")
    root = root.resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise CoverageError(f"{context} escapes repository root") from exc
    return relative, path


def _c_code_projection(text: str) -> str:
    """Blank C comments and literals while preserving offsets and newlines."""
    projected = list(text)
    state = "code"
    index = 0
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                projected[index] = projected[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if char == "/" and next_char == "*":
                projected[index] = projected[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if char == '"':
                projected[index] = " "
                state = "string"
                index += 1
                continue
            if char == "'":
                projected[index] = " "
                state = "character"
                index += 1
                continue
            index += 1
            continue
        if state == "line-comment":
            if char == "\n":
                state = "code"
            else:
                projected[index] = " "
            index += 1
            continue
        if state == "block-comment":
            if char == "*" and next_char == "/":
                projected[index] = projected[index + 1] = " "
                index += 2
                state = "code"
            else:
                if char != "\n":
                    projected[index] = " "
                index += 1
            continue
        if char == "\\":
            projected[index] = " "
            if index + 1 < len(text) and next_char != "\n":
                projected[index + 1] = " "
            index += 2
            continue
        if (state == "string" and char == '"') or (
            state == "character" and char == "'"
        ):
            state = "code"
        if char != "\n":
            projected[index] = " "
        index += 1
    return "".join(projected)


def _preprocessor_conditional_depth(text: str, offset: int) -> int:
    depth = 0
    for line in _c_code_projection(text[:offset]).splitlines():
        match = CPP_CONDITIONAL_RE.match(line)
        if match is None:
            continue
        if match.group(1) == "endif":
            depth = max(0, depth - 1)
        else:
            depth += 1
    return depth


def _require_assertion_bearing_anchor(
    anchor: str,
    source_text: str,
    source_offset: int,
    context: str,
) -> None:
    """Require at least one active, complete, non-obviously-vacuous assertion."""
    if _preprocessor_conditional_depth(source_text, source_offset) != 0:
        raise CoverageError(
            f"{context} is inside a conditional-preprocessor region"
        )
    projected = _c_code_projection(source_text)[
        source_offset : source_offset + len(anchor)
    ]
    assertions = ASSERTION_REGION_RE.findall(projected)
    if not assertions:
        raise CoverageError(f"{context} is not an active assertion-bearing anchor")
    if all(VACUOUS_ASSERTION_RE.fullmatch(item) for item in assertions):
        raise CoverageError(f"{context} has only obviously vacuous assertions")


def _outside_fence_lines(text: str) -> list[tuple[int, str]]:
    output: list[tuple[int, str]] = []
    fence_character = ""
    fence_length = 0
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if fence_character:
            stripped = line.lstrip()
            if (
                stripped.startswith(fence_character * fence_length)
                and set(stripped.split(maxsplit=1)[0]) == {fence_character}
                and len(stripped.split(maxsplit=1)[0]) >= fence_length
            ):
                fence_character = ""
                fence_length = 0
            continue
        if match is not None:
            marker = match.group(1)
            fence_character = marker[0]
            fence_length = len(marker)
            continue
        output.append((number, line))
    if fence_character:
        raise CoverageError("unterminated Markdown fence")
    return output


def _heading_units(text: str, source: str) -> dict[tuple[str, ...], dict[str, Any]]:
    stack: dict[int, str] = {}
    units: dict[tuple[str, ...], dict[str, Any]] = {}
    for line_number, line in _outside_fence_lines(text):
        match = ATX_RE.fullmatch(line)
        if match is None:
            continue
        level = len(match.group(1))
        heading = f"{match.group(1)} {match.group(2)}"
        stack[level] = heading
        for stale in [value for value in stack if value > level]:
            del stack[stale]
        path = tuple(stack[current] for current in sorted(stack) if current <= level)
        if not path or not path[0].startswith("## "):
            raise CoverageError(
                f"{source}:{line_number} H{level} has no H2 parent"
            )
        if path in units:
            raise CoverageError(f"{source} duplicate full heading path: {path}")
        units[path] = {"level": level, "line": line_number}
    if not units:
        raise CoverageError(f"{source} has no H2/H3/H4 units")
    return units


def _explicit_fnd_ids(text: str) -> set[str]:
    return {
        match.group(1)
        for _number, line in _outside_fence_lines(text)
        for match in FND_RE.finditer(line)
    }


def _invariant_section(text: str, heading: str) -> dict[str, str]:
    lines = text.splitlines()
    try:
        start = lines.index(heading) + 1
    except ValueError as exc:
        raise CoverageError("invariant source heading is missing") from exc
    found: dict[str, str] = {}
    for line in lines[start:]:
        if line.startswith("## "):
            break
        match = INVARIANT_RE.fullmatch(line)
        if match is None:
            continue
        identity = match.group(1)
        if identity in found:
            raise CoverageError(f"duplicate invariant line: {identity}")
        found[identity] = line
    if tuple(sorted(found)) != EXPECTED_INVARIANTS:
        raise CoverageError(
            "invariant section set mismatch: "
            f"expected={list(EXPECTED_INVARIANTS)} actual={sorted(found)}"
        )
    return found


def _profile_tests(
    value: Any, context: str, *, require_each: bool = False
) -> dict[str, list[str]]:
    mapping = _object(value, context, set(EXPECTED_PROFILES))
    result: dict[str, list[str]] = {}
    for profile in EXPECTED_PROFILES:
        tests = _array(mapping[profile], f"{context}.{profile}")
        if require_each and not tests:
            raise CoverageError(f"{context}.{profile} must not be empty")
        seen: set[str] = set()
        result[profile] = []
        for test in tests:
            if not isinstance(test, str) or TEST_ID_RE.fullmatch(test) is None:
                raise CoverageError(f"{context} invalid test ID: {test!r}")
            if test in seen:
                raise CoverageError(f"{context} duplicate test ID: {test}")
            seen.add(test)
            result[profile].append(test)
    return result


def _ctest_property_true(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().upper() in {"1", "ON", "TRUE", "YES", "Y"}
    return False


def _ctest_json_registry(value: dict[str, Any]) -> set[str]:
    tests = value.get("tests")
    if not isinstance(tests, list):
        raise CoverageError("configured CTest JSON has no tests array")
    names: set[str] = set()
    enabled: set[str] = set()
    for index, test in enumerate(tests):
        if not isinstance(test, dict) or not isinstance(test.get("name"), str):
            raise CoverageError(f"configured CTest tests[{index}] has no name")
        name = test["name"]
        if name in names:
            raise CoverageError(f"duplicate configured CTest name: {name}")
        names.add(name)
        properties = test.get("properties", [])
        if not isinstance(properties, list):
            raise CoverageError(
                f"configured CTest tests[{index}] properties is not an array"
            )
        disabled = False
        for property_index, prop in enumerate(properties):
            if not isinstance(prop, dict) or not isinstance(prop.get("name"), str):
                raise CoverageError(
                    "configured CTest "
                    f"tests[{index}].properties[{property_index}] is invalid"
                )
            if prop["name"] == "DISABLED" and _ctest_property_true(
                prop.get("value")
            ):
                disabled = True
        if not disabled:
            enabled.add(name)
    return enabled


def _ctest_registry(path: Path) -> set[str]:
    if path.is_dir():
        command = [
            "ctest",
            "--test-dir",
            str(path),
            "--show-only=json-v1",
        ]
        completed = subprocess.run(
            command, check=False, capture_output=True, text=True
        )
        if completed.returncode != 0:
            raise CoverageError(
                f"configured CTest query failed for {path}: {completed.stderr.strip()}"
            )
        try:
            value = json.loads(
                completed.stdout, object_pairs_hook=_reject_duplicate_object_keys
            )
        except (json.JSONDecodeError, CoverageError) as exc:
            raise CoverageError(f"invalid configured CTest JSON: {exc}") from exc
    else:
        value = _json_load(path)
    return _ctest_json_registry(value)


def _junit_passed(path: Path) -> set[str]:
    """Return passed CTest names from an externally-produced JUnit report."""
    try:
        root = ET.fromstring(path.read_bytes())
    except (OSError, ET.ParseError) as exc:
        raise CoverageError(f"cannot read JUnit XML {path}: {exc}") from exc
    passed: set[str] = set()
    seen: set[str] = set()
    for case in root.iter("testcase"):
        name = case.get("name")
        if not isinstance(name, str) or TEST_ID_RE.fullmatch(name) is None:
            raise CoverageError("JUnit testcase has invalid/missing CTest name")
        if name in seen:
            raise CoverageError(f"duplicate JUnit testcase name: {name}")
        seen.add(name)
        if any(child.tag in {"failure", "error", "skipped"} for child in case):
            continue
        passed.add(name)
    if not seen:
        raise CoverageError("JUnit XML has no testcase entries")
    return passed


def _require_enabled(
    mapping: dict[str, list[str]],
    context: str,
    registries: dict[str, set[str]],
) -> int:
    links = 0
    for profile, enabled in registries.items():
        for test in mapping[profile]:
            if test not in enabled:
                raise CoverageError(
                    f"{context} references disabled/unregistered "
                    f"{profile} CTest: {test}"
                )
            links += 1
    return links


def _require_junit_passed(
    mapping: dict[str, list[str]], context: str, junit: dict[str, set[str]]
) -> int:
    links = 0
    for profile, passed in junit.items():
        for test in mapping[profile]:
            if test not in passed:
                raise CoverageError(
                    f"{context} has no passing JUnit evidence for {profile} CTest: {test}"
                )
            links += 1
    return links


def _validate_anchor_evidence(
    root: Path,
    value: Any,
    context: str,
    registries: dict[str, set[str]],
) -> int:
    evidence = _object(
        value, context, {"source", "anchors", "tests_by_profile"}
    )
    relative, path = _safe_path(root, evidence["source"], f"{context}.source")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise CoverageError(f"cannot read evidence source {relative}: {exc}") from exc
    anchors = _array(evidence["anchors"], f"{context}.anchors")
    if not anchors:
        raise CoverageError(f"{context}.anchors must not be empty")
    seen: set[str] = set()
    for anchor in anchors:
        if not isinstance(anchor, str) or not anchor:
            raise CoverageError(f"{context} invalid source anchor")
        if anchor in seen:
            raise CoverageError(f"{context} duplicate source anchor")
        if text.count(anchor) != 1:
            raise CoverageError(
                f"{context} source anchor must occur exactly once in {relative}: "
                f"{anchor!r}"
            )
        _require_assertion_bearing_anchor(
            anchor,
            text,
            text.find(anchor),
            context,
        )
        seen.add(anchor)
    tests = _profile_tests(
        evidence["tests_by_profile"], f"{context}.tests_by_profile"
    )
    return _require_enabled(tests, context, registries)


def validate(
    root: Path,
    manifest: dict[str, Any],
    registries: dict[str, set[str]],
    junit: dict[str, set[str]] | None = None,
) -> dict[str, int]:
    root = root.resolve()
    if not registries or set(registries) - set(EXPECTED_PROFILES):
        raise CoverageError("at least one known configured CTest profile is required")
    top = _object(
        manifest,
        "coverage manifest",
        {
            "format",
            "schema_version",
            "normative_sources",
            "explicit_requirement_sets",
            "delegated_authorities",
            "invariant_source",
        },
    )
    if top["format"] != FORMAT or top["schema_version"] != 2:
        raise CoverageError("unsupported coverage manifest format/schema")

    sources = _array(top["normative_sources"], "normative_sources")
    if len(sources) != len(EXPECTED_SOURCES):
        raise CoverageError("normative source set is incomplete")
    seen_source: set[str] = set()
    seen_ids: set[str] = set()
    actual_fnd: set[str] = set()
    heading_count = 0
    test_links = 0
    junit_links = 0
    for source_index, raw_source in enumerate(sources):
        source = _object(
            raw_source,
            f"normative_sources[{source_index}]",
            {"path", "sha256", "heading_units"},
        )
        relative, path = _safe_path(
            root, source["path"], f"normative_sources[{source_index}]"
        )
        if relative != EXPECTED_SOURCES[source_index] or relative in seen_source:
            raise CoverageError("normative source sequence/set mismatch")
        seen_source.add(relative)
        if not isinstance(source["sha256"], str) or SHA256_RE.fullmatch(
            source["sha256"]
        ) is None:
            raise CoverageError(f"{relative} has invalid byte SHA-256")
        try:
            raw = path.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeError) as exc:
            raise CoverageError(f"cannot read {relative}: {exc}") from exc
        if _sha256_bytes(raw) != source["sha256"]:
            raise CoverageError(f"{relative} source byte SHA-256 mismatch")
        actual_units = _heading_units(text, relative)
        actual_fnd.update(_explicit_fnd_ids(text))
        listed: dict[tuple[str, ...], dict[str, Any]] = {}
        for index, raw_unit in enumerate(
            _array(source["heading_units"], f"{relative}.heading_units")
        ):
            unit = _object(
                raw_unit,
                f"{relative}.heading_units[{index}]",
                {"id", "level", "path", "profiles", "tests_by_profile"},
            )
            if (
                not isinstance(unit["id"], str)
                or HEADING_ID_RE.fullmatch(unit["id"]) is None
                or unit["id"] in seen_ids
            ):
                raise CoverageError(f"invalid/duplicate stable heading ID: {unit['id']!r}")
            seen_ids.add(unit["id"])
            if unit["level"] not in (2, 3, 4):
                raise CoverageError(f"{unit['id']} invalid heading level")
            path_value = _array(unit["path"], f"{unit['id']}.path")
            if not path_value or not all(isinstance(item, str) for item in path_value):
                raise CoverageError(f"{unit['id']} invalid full heading path")
            path_tuple = tuple(path_value)
            if path_tuple in listed:
                raise CoverageError(f"duplicate listed full heading path: {path_tuple}")
            listed[path_tuple] = unit
            profiles = _array(unit["profiles"], f"{unit['id']}.profiles")
            if (
                not profiles
                or not all(profile in EXPECTED_PROFILES for profile in profiles)
                or len(profiles) != len(set(profiles))
            ):
                raise CoverageError(f"{unit['id']} invalid profiles")
            tests = _profile_tests(
                unit["tests_by_profile"],
                f"{unit['id']}.tests_by_profile",
            )
            for profile in EXPECTED_PROFILES:
                if bool(tests[profile]) != (profile in profiles):
                    raise CoverageError(
                        f"{unit['id']} profile/evidence applicability mismatch: "
                        f"{profile}"
                    )
            test_links += _require_enabled(tests, unit["id"], registries)
            if junit:
                junit_links += _require_junit_passed(tests, unit["id"], junit)
        if set(listed) != set(actual_units):
            raise CoverageError(
                f"{relative} heading coverage mismatch: "
                f"missing={sorted(set(actual_units) - set(listed))} "
                f"extra={sorted(set(listed) - set(actual_units))}"
            )
        for path_tuple, unit in listed.items():
            if (
                unit["level"] != actual_units[path_tuple]["level"]
                or len(path_tuple) != unit["level"] - 1
            ):
                raise CoverageError(f"{unit['id']} full heading path/level mismatch")
        heading_count += len(listed)

    requirement_rows = _array(
        top["explicit_requirement_sets"], "explicit_requirement_sets"
    )
    listed_fnd: set[str] = set()
    for index, raw_row in enumerate(requirement_rows):
        row = _object(
            raw_row,
            f"explicit_requirement_sets[{index}]",
            {"id", "source", "tests_by_profile"},
        )
        identity = row["id"]
        if (
            not isinstance(identity, str)
            or FND_ID_RE.fullmatch(identity) is None
            or identity in listed_fnd
            or identity in seen_ids
        ):
            raise CoverageError(f"invalid/duplicate explicit requirement ID: {identity!r}")
        if row["source"] != "docs/14-foundation-ports-and-simulator.md":
            raise CoverageError(f"{identity} has invalid requirement source")
        listed_fnd.add(identity)
        seen_ids.add(identity)
        tests = _profile_tests(
            row["tests_by_profile"],
            f"{identity}.tests_by_profile",
            require_each=True,
        )
        test_links += _require_enabled(tests, identity, registries)
        if junit:
            junit_links += _require_junit_passed(tests, identity, junit)
    if listed_fnd != actual_fnd:
        raise CoverageError(
            "explicit NIN-FND requirement coverage mismatch: "
            f"missing={sorted(actual_fnd - listed_fnd)} "
            f"extra={sorted(listed_fnd - actual_fnd)}"
        )

    authorities = _array(top["delegated_authorities"], "delegated_authorities")
    if len(authorities) != 1:
        raise CoverageError("exactly one vector delegated authority is required")
    authority = _object(
        authorities[0],
        "delegated_authorities[0]",
        {"id", "kind", "expected_items", "tests_by_profile"},
    )
    if (
        authority["id"] != "NIN-PR1-VECTOR-303"
        or authority["kind"] != "foundation-vector-inventory-and-reference"
        or authority["expected_items"] != 303
    ):
        raise CoverageError("vector delegated authority identity/count mismatch")
    tests = _profile_tests(
        authority["tests_by_profile"],
        "delegated_authorities[0].tests_by_profile",
        require_each=True,
    )
    for profile in EXPECTED_PROFILES:
        if set(tests[profile]) != {
            "vector_inventory_check",
            "vector_reference_check",
        }:
            raise CoverageError("vector delegated authority test set mismatch")
    test_links += _require_enabled(tests, authority["id"], registries)
    if junit:
        junit_links += _require_junit_passed(tests, authority["id"], junit)

    invariant_source = _object(
        top["invariant_source"],
        "invariant_source",
        {"path", "heading", "invariants"},
    )
    if (
        invariant_source["path"] != "docs/07-testing-and-quality.md"
        or invariant_source["heading"] != "## 常時検査するinvariant"
    ):
        raise CoverageError("invariant source identity mismatch")
    _, invariant_path = _safe_path(
        root, invariant_source["path"], "invariant_source.path"
    )
    invariant_text = invariant_path.read_text(encoding="utf-8")
    actual_invariants = _invariant_section(
        invariant_text, invariant_source["heading"]
    )
    rows = _array(invariant_source["invariants"], "invariant_source.invariants")
    if len(rows) != len(EXPECTED_INVARIANTS):
        raise CoverageError("invariant coverage set is incomplete")
    listed_invariants: list[str] = []
    subclaim_count = 0
    for index, raw_row in enumerate(rows):
        row = _object(
            raw_row,
            f"invariant_source.invariants[{index}]",
            {"id", "line_sha256", "subclaims"},
        )
        identity = row["id"]
        if (
            identity != EXPECTED_INVARIANTS[index]
            or not isinstance(identity, str)
            or INVARIANT_ID_RE.fullmatch(identity) is None
            or identity in seen_ids
        ):
            raise CoverageError(f"invalid/order/duplicate invariant ID: {identity!r}")
        seen_ids.add(identity)
        listed_invariants.append(identity)
        if (
            not isinstance(row["line_sha256"], str)
            or SHA256_RE.fullmatch(row["line_sha256"]) is None
            or _sha256_bytes(actual_invariants[identity].encode("utf-8"))
            != row["line_sha256"]
        ):
            raise CoverageError(f"{identity} invariant line SHA-256 mismatch")
        subclaims = _array(row["subclaims"], f"{identity}.subclaims")
        if not subclaims:
            raise CoverageError(f"{identity} has no evidence subclaims")
        seen_claims: set[str] = set()
        for claim_index, raw_claim in enumerate(subclaims):
            claim = _object(
                raw_claim,
                f"{identity}.subclaims[{claim_index}]",
                {"id", "profiles", "evidence"},
            )
            claim_id = claim["id"]
            if not isinstance(claim_id, str) or not claim_id or claim_id in seen_claims:
                raise CoverageError(f"{identity} invalid/duplicate subclaim ID")
            seen_claims.add(claim_id)
            profiles = _array(claim["profiles"], f"{identity}.{claim_id}.profiles")
            if (
                not profiles
                or not all(profile in EXPECTED_PROFILES for profile in profiles)
                or len(profiles) != len(set(profiles))
            ):
                raise CoverageError(f"{identity}.{claim_id} invalid profiles")
            evidence = _array(claim["evidence"], f"{identity}.{claim_id}.evidence")
            if not evidence:
                raise CoverageError(f"{identity}.{claim_id} has no evidence")
            applicable: set[str] = set()
            for evidence_index, raw_evidence in enumerate(evidence):
                test_links += _validate_anchor_evidence(
                    root,
                    raw_evidence,
                    f"{identity}.{claim_id}.evidence[{evidence_index}]",
                    registries,
                )
                if junit:
                    junit_links += _require_junit_passed(
                        _profile_tests(
                            raw_evidence["tests_by_profile"],
                            f"{identity}.{claim_id}.evidence[{evidence_index}].tests_by_profile",
                        ),
                        f"{identity}.{claim_id}.evidence[{evidence_index}]",
                        junit,
                    )
                evidence_profiles = raw_evidence["tests_by_profile"]
                for profile in profiles:
                    if evidence_profiles[profile]:
                        applicable.add(profile)
                for profile in EXPECTED_PROFILES:
                    if profile not in profiles and evidence_profiles[profile]:
                        raise CoverageError(
                            f"{identity}.{claim_id} has evidence for "
                            f"non-applicable profile {profile}"
                        )
            if applicable != set(profiles):
                raise CoverageError(
                    f"{identity}.{claim_id} missing profile evidence: "
                    f"{sorted(set(profiles) - applicable)}"
                )
            subclaim_count += 1
    if tuple(listed_invariants) != EXPECTED_INVARIANTS:
        raise CoverageError("invariant coverage sequence mismatch")
    required_inv010 = {"queue", "retry", "dedup", "reassembly", "journal"}
    inv010 = rows[9]
    if {claim["id"] for claim in inv010["subclaims"]} != required_inv010:
        raise CoverageError("NIN-INV-010 five-subclaim coverage mismatch")
    required_inv005 = {
        "transaction-id-stable",
        "logical-retry-fresh-attempt",
        "crash-replay-same-attempt",
        "protected-wire-fresh-nonce",
    }
    if {claim["id"] for claim in rows[4]["subclaims"]} != required_inv005:
        raise CoverageError("NIN-INV-005 four-subclaim coverage mismatch")

    return {
        "sources": len(sources),
        "headings": heading_count,
        "requirements": len(listed_fnd),
        "vectors": authority["expected_items"],
        "invariants": len(rows),
        "subclaims": subclaim_count,
        "test_links": test_links,
        "junit_pass_links": junit_links,
    }


def _all_manifest_tests(manifest: dict[str, Any]) -> set[str]:
    tests: set[str] = set()
    for source in manifest["normative_sources"]:
        for unit in source["heading_units"]:
            for values in unit["tests_by_profile"].values():
                tests.update(values)
    for row in manifest["explicit_requirement_sets"]:
        for values in row["tests_by_profile"].values():
            tests.update(values)
    for authority in manifest["delegated_authorities"]:
        for values in authority["tests_by_profile"].values():
            tests.update(values)
    for invariant in manifest["invariant_source"]["invariants"]:
        for claim in invariant["subclaims"]:
            for evidence in claim["evidence"]:
                for values in evidence["tests_by_profile"].values():
                    tests.update(values)
    return tests


def _expect_failure(
    name: str,
    root: Path,
    manifest: dict[str, Any],
    registries: dict[str, set[str]],
    expected: str,
) -> None:
    try:
        validate(root, manifest, registries)
    except (CoverageError, OSError, UnicodeError) as exc:
        if expected not in str(exc):
            raise CoverageError(
                f"self-test {name}: expected {expected!r}, got {str(exc)!r}"
            ) from exc
        return
    raise CoverageError(f"self-test {name}: mutation was accepted")


def self_test(root: Path, manifest: dict[str, Any]) -> None:
    all_tests = _all_manifest_tests(manifest)
    registries = {profile: set(all_tests) for profile in EXPECTED_PROFILES}
    validate(root, manifest, registries)
    junit = {profile: set(all_tests) for profile in EXPECTED_PROFILES}
    validate(root, manifest, registries, junit)
    junit["baseline"].remove(
        manifest["normative_sources"][0]["heading_units"][0]["tests_by_profile"]["baseline"][0]
    )
    try:
        validate(root, manifest, registries, junit)
    except CoverageError as exc:
        if "no passing JUnit evidence" not in str(exc):
            raise
    else:
        raise CoverageError("self-test missing JUnit result was accepted")

    evidence = manifest["invariant_source"]["invariants"][0]["subclaims"][0]["evidence"][0]
    anchor = evidence["anchors"][0]
    source = (root / evidence["source"]).read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory() as raw_temp:
        temp = Path(raw_temp)
        (temp / "anchor.c").write_text(source.replace(anchor, "", 1), encoding="utf-8")
        mutated_evidence = copy.deepcopy(evidence)
        mutated_evidence["source"] = "anchor.c"
        try:
            _validate_anchor_evidence(temp, mutated_evidence, "anchor-deletion", registries)
        except CoverageError as exc:
            if "must occur exactly once" not in str(exc):
                raise
        else:
            raise CoverageError("self-test source-anchor deletion was accepted")

        coherent_mutations = (
            (
                "coherent-assertion-deletion",
                "(void)result.next.state;",
                "not an active assertion-bearing anchor",
            ),
            (
                "coherent-assertion-comment-out",
                f"/* {anchor} */",
                "not an active assertion-bearing anchor",
            ),
            (
                "coherent-vacuous-assertion",
                "REQUIRE(1);",
                "only obviously vacuous assertions",
            ),
        )
        for mutation_name, replacement, expected in coherent_mutations:
            (temp / "anchor.c").write_text(
                source.replace(anchor, replacement, 1), encoding="utf-8"
            )
            mutated_evidence = copy.deepcopy(evidence)
            mutated_evidence["source"] = "anchor.c"
            mutated_evidence["anchors"][0] = replacement
            try:
                _validate_anchor_evidence(
                    temp, mutated_evidence, mutation_name, registries
                )
            except CoverageError as exc:
                if expected not in str(exc):
                    raise
            else:
                raise CoverageError(
                    f"self-test {mutation_name} was accepted"
                )

        (temp / "anchor.c").write_text(
            source.replace(anchor, f"#if 0\n{anchor}\n#endif", 1),
            encoding="utf-8",
        )
        mutated_evidence = copy.deepcopy(evidence)
        mutated_evidence["source"] = "anchor.c"
        try:
            _validate_anchor_evidence(
                temp,
                mutated_evidence,
                "coherent-preprocessor-noop",
                registries,
            )
        except CoverageError as exc:
            if "conditional-preprocessor region" not in str(exc):
                raise
        else:
            raise CoverageError(
                "self-test coherent-preprocessor-noop was accepted"
            )

    mutated = copy.deepcopy(manifest)
    mutated["normative_sources"][0]["heading_units"].pop()
    _expect_failure("omitted-heading", root, mutated, registries, "heading coverage")

    mutated = copy.deepcopy(manifest)
    duplicate = copy.deepcopy(mutated["normative_sources"][0]["heading_units"][0])
    mutated["normative_sources"][0]["heading_units"].append(duplicate)
    _expect_failure("duplicate-heading-id", root, mutated, registries, "duplicate")

    mutated = copy.deepcopy(manifest)
    mutated["explicit_requirement_sets"].pop()
    _expect_failure("omitted-fnd", root, mutated, registries, "NIN-FND")

    mutated = copy.deepcopy(manifest)
    mutated["normative_sources"][0]["sha256"] = "0" * 64
    _expect_failure("source-byte-hash", root, mutated, registries, "byte SHA-256")

    missing_test = manifest["normative_sources"][0]["heading_units"][0][
        "tests_by_profile"
    ]["baseline"][0]
    disabled = {profile: set(all_tests) for profile in EXPECTED_PROFILES}
    disabled["baseline"].remove(missing_test)
    _expect_failure(
        "if-false-disabled-test",
        root,
        manifest,
        disabled,
        "disabled/unregistered baseline CTest",
    )
    parsed_disabled = _ctest_json_registry(
        {
            "tests": [
                {
                    "name": missing_test,
                    "properties": [{"name": "DISABLED", "value": True}],
                }
            ]
        }
    )
    if missing_test in parsed_disabled:
        raise CoverageError("self-test configured DISABLED CTest was enabled")

    sample = (
        "## Parent\n"
        "```md\n### Fenced fake\n```\n"
        "### Live A\n"
        "### Live B\n"
    )
    units = _heading_units(sample, "self-test.md")
    if len(units) != 3 or any("Fenced fake" in part for path in units for part in path):
        raise CoverageError("self-test fenced heading was not excluded")
    reordered = (
        "## Parent\n"
        "### Live B\n"
        "### Live A\n"
    )
    first = set(_heading_units("## Parent\n### Live A\n### Live B\n", "a"))
    second = set(_heading_units(reordered, "b"))
    if first != second:
        raise CoverageError("self-test heading reorder changed stable path set")

    moved = (
        "## 常時検査するinvariant\n"
        + "\n".join(
            f"- `NIN-INV-{index:03d}`: x." for index in range(1, 14)
        )
        + "\n## Other\n- `NIN-INV-014`: moved.\n"
    )
    try:
        _invariant_section(moved, "## 常時検査するinvariant")
    except CoverageError as exc:
        if "invariant section set mismatch" not in str(exc):
            raise
    else:
        raise CoverageError("self-test moved invariant was accepted")

    materializer = root / "tools/traceability_coverage_v2_materialize.py"
    for mode, marker in (
        ("--check", "traceability coverage V2 freshness ok:"),
        ("--self-test", "traceability coverage V2 materializer self-test ok"),
    ):
        completed = subprocess.run(
            [sys.executable, str(materializer), mode],
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0 or marker not in completed.stdout:
            raise CoverageError(
                f"materializer {mode} failed: "
                f"{completed.stderr.strip() or completed.stdout.strip()}"
            )


def _parse_profiles(values: list[str]) -> dict[str, set[str]]:
    registries: dict[str, set[str]] = {}
    for value in values:
        if "=" not in value:
            raise CoverageError("--profile requires NAME=CTestJSON-or-build-dir")
        name, raw_path = value.split("=", 1)
        if name not in EXPECTED_PROFILES or name in registries or not raw_path:
            raise CoverageError(f"invalid/duplicate configured profile: {name!r}")
        registries[name] = _ctest_registry(Path(raw_path))
    return registries


def _parse_junit(values: list[str]) -> dict[str, set[str]]:
    results: dict[str, set[str]] = {}
    for value in values:
        if "=" not in value:
            raise CoverageError("--junit requires NAME=JUnitXML")
        name, raw_path = value.split("=", 1)
        if name not in EXPECTED_PROFILES or name in results or not raw_path:
            raise CoverageError(f"invalid/duplicate JUnit profile: {name!r}")
        results[name] = _junit_passed(Path(raw_path))
    return results


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="configured baseline/all-private CTest JSON file or build directory",
    )
    parser.add_argument(
        "--junit",
        action="append",
        default=[],
        metavar="NAME=PATH",
        help="optional CTest --output-junit XML; checks cited CTests passed, not assertion strength",
    )
    args = parser.parse_args(argv)
    try:
        manifest = _json_load(args.root / MANIFEST)
        if args.self_test:
            self_test(args.root, manifest)
            print("traceability registration coverage V2 self-test ok")
        else:
            registries = _parse_profiles(args.profile)
            junit = _parse_junit(args.junit)
            if junit and set(junit) != set(registries):
                raise CoverageError("JUnit profiles must exactly match configured CTest profiles")
            result = validate(args.root, manifest, registries, junit)
            print(
                "traceability registration coverage V2 ok: "
                + " ".join(f"{key}={value}" for key, value in result.items())
                + f" profiles={','.join(sorted(registries))}"
            )
    except (CoverageError, OSError, UnicodeError) as exc:
        print(f"traceability registration coverage V2 error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
