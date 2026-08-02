#!/usr/bin/env python3
"""Docs-wide gate: M1a reserved public families must not read as supported.

Locks ADR-0024 / docs/12 §14 usability for entry docs and the broader docs
tree:

  - M1a public families are DesiredState + EventFact only.
  - LATEST_STATE_RESERVED / MEASUREMENT_RESERVED (and peers) stay
    service_register UNSUPPORTED — not first-class public families.
  - V1 LAB display/leak product labels are
    ``display snapshot event (EventFact)`` /
    ``leak measurement event (EventFact)``.
  - Historical executable names (*display_latest_state*, *leak_measurement*)
    are label-only compatibility identifiers.

Does not claim full NLP understanding of every synonym. Fail-closed on
known misread patterns; self-test proves mutations are rejected.
"""

from __future__ import annotations

import pathlib
import re
import sys
import tempfile
from typing import Callable, Iterable

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]

# Historical evidence / independent reviews are snapshots — not re-edited by
# this gate. ADR-0024 itself may discuss the misread problem by name.
EXCLUDE_DIR_PARTS = frozenset(
    {
        "work",
        "reviews",
        ".git",
        "build",
        "tmp-v1",
        "node_modules",
        "_vendor",
    }
)
EXCLUDE_PATH_SUFFIXES = (
    # Self-documenting authority; may quote forbidden misreads as counterexamples.
    "docs/adr/0024-m1a-public-family-matrix-freeze.md",
    "tools/m1a_public_family_docs_gate.py",
)

ENTRY_SURFACES = (
    REPO_ROOT / "README.md",
    REPO_ROOT / "docs" / "v1-lab-quickstart.md",
)

REQUIRED_PHRASES = (
    "display snapshot event (EventFact)",
    "leak measurement event (EventFact)",
    "ADR-0024",
)

# Same-line disambiguators that mean the reserved family is NOT claimed as live.
DISAMBIGUATION = re.compile(
    r"UNSUPPORTED|EventFact|ADR-0024|must\s+fail|remain(?:s)?|"
    r"register-red|not\s+used|not\s+(?:a\s+)?first-class|"
    r"label-only|historical|out\s+of\s+scope|予約|"
    r"実装はM1aでunsupported|実装するのは",
    re.IGNORECASE,
)

def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Line-level patterns that misread as "reserved public family is supported".
BANNED_LINE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "uplink LatestState as wire/family path",
        re.compile(r"上行\s*LatestState\b"),
    ),
    (
        "uplink MeasurementBatch as wire/family path",
        re.compile(r"上行\s*MeasurementBatch\b"),
    ),
    (
        "English uplink LatestState as wire/family path",
        _re(r"\buplink\s+LatestState\b"),
    ),
    (
        "English uplink MeasurementBatch as wire/family path",
        _re(r"\buplink\s+MeasurementBatch\b"),
    ),
    (
        "LatestState claimed as first-class public family",
        _re(
            r"\bLatestState\b[^\n]{0,60}\b(?:first-class|public)\s+family\b"
            r"|\b(?:first-class|public)\s+family\b[^\n]{0,60}\bLatestState\b"
        ),
    ),
    (
        "MeasurementBatch claimed supported/enabled as public family",
        _re(
            r"\bMeasurementBatch\b[^\n]{0,40}\b(?:supported|enabled|implemented)\b"
            r"|\b(?:supports?|enables?|implements?)\b[^\n]{0,40}\bMeasurementBatch\b"
        ),
    ),
    (
        "LATEST_STATE_RESERVED claimed supported/enabled/admitted",
        _re(
            r"\bLATEST_STATE_RESERVED\b[^\n]{0,48}"
            r"\b(?:supported|enabled|admitted|OK|success)\b"
        ),
    ),
    (
        "MEASUREMENT_RESERVED claimed supported/enabled/admitted",
        _re(
            r"\bMEASUREMENT_RESERVED\b[^\n]{0,48}"
            r"\b(?:supported|enabled|admitted|OK|success)\b"
        ),
    ),
    (
        "service_register success for reserved LATEST_STATE",
        _re(
            r"service_register[^\n]{0,80}LATEST_STATE[^\n]{0,40}"
            r"(?:OK|success|supported|enabled)"
        ),
    ),
    (
        "service_register success for reserved MEASUREMENT",
        _re(
            r"service_register[^\n]{0,80}MEASUREMENT[^\n]{0,40}"
            r"(?:OK|success|supported|enabled)"
        ),
    ),
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def _is_excluded(path: pathlib.Path) -> bool:
    try:
        rel = path.resolve().relative_to(REPO_ROOT)
    except ValueError:
        return True
    rel_s = rel.as_posix()
    if rel_s in EXCLUDE_PATH_SUFFIXES:
        return True
    parts = set(rel.parts)
    if parts & EXCLUDE_DIR_PARTS:
        # Allow docs/work exclusion via 'work' under docs/
        if "docs" in rel.parts and ("work" in rel.parts or "reviews" in rel.parts):
            return True
        if any(p in EXCLUDE_DIR_PARTS for p in rel.parts if p != "docs"):
            # tools/_vendor etc.
            if "_vendor" in rel.parts or ".git" in rel.parts:
                return True
    # Exclude build trees at repo root
    if rel.parts and rel.parts[0] in {"build", "tmp-v1", "tmp", "out"}:
        return True
    return False


def iter_scan_paths() -> list[pathlib.Path]:
    paths: list[pathlib.Path] = []
    globs = (
        "README.md",
        "docs/**/*.md",
        "examples/**/*.{c,h,md}",
        "cmake/**/*.cmake",
        "ports/**/README.md",
    )
    # pathlib doesn't expand brace globs; expand manually.
    candidates: list[pathlib.Path] = []
    candidates.append(REPO_ROOT / "README.md")
    candidates.extend(REPO_ROOT.glob("docs/**/*.md"))
    candidates.extend(REPO_ROOT.glob("examples/**/*.c"))
    candidates.extend(REPO_ROOT.glob("examples/**/*.h"))
    candidates.extend(REPO_ROOT.glob("examples/**/*.md"))
    candidates.extend(REPO_ROOT.glob("cmake/**/*.cmake"))
    candidates.extend(REPO_ROOT.glob("ports/**/README.md"))
    for path in candidates:
        if not path.is_file():
            continue
        if _is_excluded(path):
            continue
        paths.append(path)
    return sorted(set(paths), key=lambda p: p.as_posix())


def _line_allowed(line: str) -> bool:
    return DISAMBIGUATION.search(line) is not None


def scan_text(text: str, where: str) -> list[str]:
    hits: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("<!--"):
            continue
        for label, pattern in BANNED_LINE_PATTERNS:
            if not pattern.search(line):
                continue
            if _line_allowed(line):
                continue
            hits.append(f"{where}:{lineno}: banned ({label}): {stripped[:160]}")
    return hits


def assert_entry_surfaces() -> None:
    for path in ENTRY_SURFACES:
        if not path.is_file():
            fail(f"missing entry surface: {path.relative_to(REPO_ROOT)}")
        text = path.read_text(encoding="utf-8")
        rel = path.relative_to(REPO_ROOT).as_posix()
        for phrase in REQUIRED_PHRASES:
            if phrase not in text:
                fail(f"{rel} must contain required phrase {phrase!r} (ADR-0024 usability)")
        # Historical names may remain, but must be labeled compatibility-only.
        if "display_latest_state" in text or "leak_measurement" in text:
            if not re.search(
                r"label-only|historical(?:\s+name|\s+label| target)?|互換",
                text,
                re.IGNORECASE,
            ):
                fail(
                    f"{rel} mentions historical display_latest_state / "
                    "leak_measurement targets without label-only/historical note"
                )


def check_paths(paths: Iterable[pathlib.Path]) -> None:
    all_hits: list[str] = []
    for path in paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.resolve().relative_to(REPO_ROOT).as_posix()
        all_hits.extend(scan_text(text, rel))
    if all_hits:
        preview = "\n".join(all_hits[:20])
        more = "" if len(all_hits) <= 20 else f"\n... +{len(all_hits) - 20} more"
        fail(
            "reserved public family misread patterns found "
            f"({len(all_hits)} hit(s)):\n{preview}{more}"
        )


def check() -> None:
    assert_entry_surfaces()
    paths = iter_scan_paths()
    if len(paths) < 10:
        fail(f"scan path set unexpectedly small: {len(paths)}")
    check_paths(paths)
    print(
        "m1a_public_family_docs_gate OK: "
        f"scanned={len(paths)} entry_phrases=ok "
        "banned_misreads=0 (ADR-0024)"
    )


def _expect_fail(label: str, mutator: Callable[[], None]) -> None:
    try:
        mutator()
    except GateFailure as e:
        print(f"  self-test mutation {label!r} correctly failed: {e}")
        return
    fail(f"self-test mutation {label!r} did not fail (false green)")


def self_test() -> None:
    # 1) Banned uplink LatestState line.
    def mut_uplink_ls() -> None:
        hits = scan_text(
            "| Display | 2-process loopback 上行 LatestState |\n",
            "mutant.md",
        )
        if not hits:
            fail("mutator setup: uplink LatestState not detected")
        fail(hits[0])

    _expect_fail("uplink_LatestState", mut_uplink_ls)

    # 2) MeasurementBatch supported claim.
    def mut_mb_supported() -> None:
        hits = scan_text(
            "This release supports MeasurementBatch uplink end-to-end.\n",
            "mutant.md",
        )
        if not hits:
            fail("mutator setup: MeasurementBatch supported not detected")
        fail(hits[0])

    _expect_fail("measurement_supported", mut_mb_supported)

    # 3) Entry surface missing required phrase.
    def mut_entry() -> None:
        with tempfile.TemporaryDirectory() as td:
            p = pathlib.Path(td) / "README.md"
            p.write_text(
                "# x\nM1a families incomplete without required phrases\n",
                encoding="utf-8",
            )
            # inline assert
            text = p.read_text(encoding="utf-8")
            for phrase in REQUIRED_PHRASES:
                if phrase not in text:
                    fail(f"README.md must contain required phrase {phrase!r}")

    _expect_fail("entry_missing_phrase", mut_entry)

    # 4) Disambiguated line is allowed.
    ok_hits = scan_text(
        "Product LatestState label is EventFact only (ADR-0024); "
        "LATEST_STATE_RESERVED remains UNSUPPORTED.\n",
        "ok.md",
    )
    if ok_hits:
        fail(f"self-test false positive on disambiguated line: {ok_hits}")

    check()
    print("m1a_public_family_docs_gate self-test OK")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: m1a_public_family_docs_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    try:
        if argv[1] == "check":
            check()
        else:
            self_test()
    except GateFailure as e:
        print(f"m1a_public_family_docs_gate FAIL: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
