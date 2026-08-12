#!/usr/bin/env python3
"""Validate the immutable 2026-08-11 review source and exhaustive OR map."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
INDEX = ROOT / "docs/reviews/2026-08-11-ninlil-runtime-exhaustive-review-index.md"
EVIDENCE = ROOT / "docs/reviews/2026-08-11-ninlil-runtime-exhaustive-review-evidence.md"
BEGIN = "<!-- ninlil-oss-review-provenance-v1:begin -->"
END = "<!-- ninlil-oss-review-provenance-v1:end -->"
EVIDENCE_BEGIN = "<!-- ninlil-oss-review-evidence-v1:begin -->"
EVIDENCE_END = "<!-- ninlil-oss-review-evidence-v1:end -->"
KINDS = {"context", "observation", "finding", "recommendation"}
EXPECTED_REVIEW_TARGET = "9cc907fe3a384aba9bf0e984b62fa55fa1207f3f"
EXPECTED_LEDGER_PATH = "docs/work/2026-08-12-oss-review-completion-ledger.md"
EXPECTED_SOURCE = {
    "path": "docs/reviews/2026-08-11-ninlil-runtime-exhaustive-review-source.txt",
    "canonical_bytes": 46449,
    "canonical_lines": 414,
    "canonical_sha256": (
        "e912e6bd7eaa698d5313267ff058bfe27818119eb0409884ef1c21e9b7fe39ec"
    ),
    "received_bytes": 46448,
    "received_sha256": (
        "5e7154f6a1a8990e579f7275cd0353fddb2d37ec7e2a628c774b38d1da3f4512"
    ),
    "normalization": "append-final-lf",
}
EXPECTED_STATUSES = tuple(
    "EXTERNAL" if number in {9, 33}
    else "NO_ACTION" if number in {35, 37}
    else "CLOSED"
    for number in range(1, 38)
)
EXPECTED_SPANS_SHA256 = (
    "94a67e9ed1e583bd753f1cfd34ad81fb38e1c25769fc6356f0a766934424f090"
)
EXPECTED_ENTRIES_SHA256 = (
    "9e0f475d623509fc3a64057c730c3f09732c0639bd9f6ca1b9ebd7956d8d4cad"
)
CHARTER_MATURITY = "現在の maturity: Experimental / pre-alpha"
CHARTER_ENGLISH_EXIT = (
    "public alpha までに、normative API / protocol / porting / contribution "
    "文書の英語版を正本として整備する。"
)
README_MATURITY = "**プレリリース SDK**"


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _extract(text: str, begin: str, end: str) -> dict[str, object]:
    middle = _top_level_marker_region(text, begin, end)
    match = re.fullmatch(r"\s*```json\s*\n(?P<body>.*?)\n```\s*", middle, re.DOTALL)
    if match is None:
        raise ValueError("provenance authority must be one live JSON fence")
    value = json.loads(match.group("body"), object_pairs_hook=_closed_object)
    if not isinstance(value, dict):
        raise ValueError("provenance authority must be an object")
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _semantic_sha256(value: object) -> str:
    return _sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _without_html_comments(text: str) -> str:
    output: list[str] = []
    cursor = 0
    while cursor < len(text):
        opening = text.find("<!--", cursor)
        closing = text.find("-->", cursor)
        if closing >= 0 and (opening < 0 or closing < opening):
            raise ValueError("unmatched Markdown HTML comment close")
        if opening < 0:
            output.append(text[cursor:])
            break
        output.append(text[cursor:opening])
        closing = text.find("-->", opening + 4)
        if closing < 0:
            raise ValueError("unterminated Markdown HTML comment")
        cursor = closing + 3
    return "".join(output)


def _top_level_marker_region(text: str, begin: str, end: str) -> str:
    """Return one live authority region outside Markdown comments/fences."""
    begin_token = "NINLIL_ACTIVE_REVIEW_BEGIN_056C2EF8"
    end_token = "NINLIL_ACTIVE_REVIEW_END_056C2EF8"
    if begin_token in text or end_token in text:
        raise ValueError("reserved review-authority token occurs in Markdown")
    protected = text.replace(begin, begin_token).replace(end, end_token)
    clean = _without_html_comments(protected)
    lines = clean.splitlines(keepends=True)
    fence: str | None = None
    fence_length = 0
    begins: list[int] = []
    ends: list[int] = []
    for index, line in enumerate(lines):
        body = line.rstrip("\r\n")
        if fence is None:
            stripped = body.strip()
            if stripped == begin_token:
                begins.append(index)
                continue
            if stripped == end_token:
                ends.append(index)
                continue
            opening = re.fullmatch(r"[ \t]{0,3}(`{3,}|~{3,})[^\r\n]*", body)
            if opening is not None:
                marker = opening.group(1)
                fence = marker[0]
                fence_length = len(marker)
        elif re.fullmatch(
            rf"[ \t]{{0,3}}{re.escape(fence)}{{{fence_length},}}[ \t]*",
            body,
        ):
            fence = None
            fence_length = 0
    if fence is not None:
        raise ValueError("unterminated Markdown fence in review authority")
    if len(begins) != 1 or len(ends) != 1 or begins[0] >= ends[0]:
        raise ValueError("review authority markers must occur exactly once in order")
    return "".join(lines[begins[0] + 1 : ends[0]])


def _active_markdown(text: str) -> str:
    """Remove fenced code and HTML comments before prose sentinel checks."""
    without_comments = _without_html_comments(text)
    output: list[str] = []
    fence: str | None = None
    fence_length = 0
    for line in without_comments.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if fence is None:
            match = re.fullmatch(r"[ \t]{0,3}(`{3,}|~{3,})[^\r\n]*", body)
            if match is None:
                output.append(line)
            else:
                fence = match.group(1)[0]
                fence_length = len(match.group(1))
        elif re.fullmatch(
            rf"[ \t]{{0,3}}{re.escape(fence)}{{{fence_length},}}[ \t]*",
            body,
        ):
            fence = None
            fence_length = 0
    if fence is not None:
        raise ValueError("unterminated Markdown fence in maturity authority")
    return "".join(output)


def validate(
    root: pathlib.Path,
    index_text: str | None = None,
    evidence_text: str | None = None,
    ledger_text_override: str | None = None,
    charter_text: str | None = None,
    readme_text: str | None = None,
    source_bytes_override: bytes | None = None,
) -> list[str]:
    errors: list[str] = []
    index_path = root / INDEX.relative_to(ROOT)
    try:
        authority = _extract(
            index_path.read_text(encoding="utf-8") if index_text is None else index_text,
            BEGIN,
            END,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        return [f"review provenance index: {exc}"]
    if set(authority) != {
        "schema", "review_target", "source", "ledger_path", "spans"
    }:
        errors.append("review provenance top-level fields are not closed")
    if authority.get("schema") != "ninlil-oss-review-provenance-v1":
        errors.append("review provenance schema drift")
    target = authority.get("review_target")
    if not isinstance(target, str) or re.fullmatch(r"[0-9a-f]{40}", target) is None:
        errors.append("review target must be one lowercase full SHA-1")
    if target != EXPECTED_REVIEW_TARGET:
        errors.append("review target differs from immutable code authority")

    source = authority.get("source")
    if not isinstance(source, dict) or set(source) != {
        "path", "canonical_bytes", "canonical_lines", "canonical_sha256",
        "received_bytes", "received_sha256", "normalization"
    }:
        errors.append("review source authority fields are not closed")
        source = {}
    if source != EXPECTED_SOURCE:
        errors.append("review source metadata differs from immutable code authority")
    source_path_raw = source.get("path")
    if not isinstance(source_path_raw, str):
        errors.append("review source path is invalid")
        source_bytes = b""
    else:
        source_path = root / source_path_raw
        if source_bytes_override is not None:
            source_bytes = source_bytes_override
        else:
            try:
                source_bytes = source_path.read_bytes()
            except OSError as exc:
                errors.append(f"review source unreadable: {exc}")
                source_bytes = b""
    if len(source_bytes) != source.get("canonical_bytes"):
        errors.append("review source canonical byte count mismatch")
    if _sha256(source_bytes) != source.get("canonical_sha256"):
        errors.append("review source canonical SHA-256 mismatch")
    if not source_bytes.endswith(b"\n"):
        errors.append("review source canonical form must end in LF")
    received = source_bytes[:-1] if source_bytes.endswith(b"\n") else b""
    if source.get("normalization") != "append-final-lf":
        errors.append("review source normalization drift")
    if len(received) != source.get("received_bytes"):
        errors.append("review source received byte count mismatch")
    if _sha256(received) != source.get("received_sha256"):
        errors.append("review source received SHA-256 mismatch")
    lines = source_bytes.splitlines()
    if len(lines) != source.get("canonical_lines"):
        errors.append("review source logical line count mismatch")
    if (
        not isinstance(target, str)
        or len(lines) < 5
        or lines[4] != f"対象 {target[:7]}".encode("utf-8")
    ):
        errors.append("review source target line differs from full target authority")

    ledger_raw = authority.get("ledger_path")
    if not isinstance(ledger_raw, str):
        errors.append("review ledger path is invalid")
        ledger_text = ""
    else:
        if ledger_raw != EXPECTED_LEDGER_PATH:
            errors.append("review ledger path differs from immutable code authority")
        try:
            ledger_text = (
                (root / ledger_raw).read_text(encoding="utf-8")
                if ledger_text_override is None
                else ledger_text_override
            )
        except (OSError, UnicodeError) as exc:
            errors.append(f"review ledger unreadable: {exc}")
            ledger_text = ""
    try:
        active_ledger_text = _active_markdown(ledger_text)
    except ValueError as exc:
        errors.append(f"review ledger authority: {exc}")
        active_ledger_text = ""
    ledger_rows = re.findall(
        r"^\| (OR-\d{2}) \|.*?\| (CLOSED|IN_PROGRESS|OPEN|EXTERNAL|NO_ACTION) \|",
        active_ledger_text,
        re.MULTILINE,
    )
    ledger_ids = [item[0] for item in ledger_rows]
    ledger_status = dict(ledger_rows)
    expected_ids = [f"OR-{number:02d}" for number in range(1, 38)]
    if ledger_ids != expected_ids:
        errors.append(f"review ledger OR IDs must be exact 01..37 (got {ledger_ids})")
    if tuple(status for _, status in ledger_rows) != EXPECTED_STATUSES:
        errors.append("review ledger status vector differs from accepted disposition")
    ledger_targets = re.findall(
        r"^commit `([0-9a-f]{40})` を対象",
        active_ledger_text,
        re.MULTILINE,
    )
    if ledger_targets != [target]:
        errors.append("review ledger target must exactly match provenance authority")

    spans = authority.get("spans")
    if not isinstance(spans, list) or not spans:
        errors.append("review provenance spans must be a non-empty list")
        spans = []
    cursor = 1
    referenced: set[str] = set()
    for index, span in enumerate(spans):
        if not isinstance(span, dict) or set(span) != {"start", "end", "kind", "or_ids"}:
            errors.append(f"review span {index}: fields are not closed")
            continue
        start = span.get("start")
        end = span.get("end")
        kind = span.get("kind")
        ids = span.get("or_ids")
        if not isinstance(start, int) or not isinstance(end, int) or start != cursor or end < start:
            errors.append(f"review span {index}: ranges must be contiguous and non-empty")
            continue
        cursor = end + 1
        if kind not in KINDS:
            errors.append(f"review span {index}: invalid kind {kind!r}")
        if not isinstance(ids, list) or any(item not in expected_ids for item in ids):
            errors.append(f"review span {index}: invalid OR references")
            continue
        if kind in {"finding", "recommendation", "observation"} and not ids:
            errors.append(f"review span {index}: classified source span needs an OR reference")
        if kind == "context" and ids:
            errors.append(f"review span {index}: context must not reference an OR")
        referenced.update(ids)
    if cursor != len(lines) + 1:
        errors.append(
            f"review spans must cover exact lines 1..{len(lines)} (ended at {cursor - 1})"
        )
    missing_ids = sorted(set(expected_ids) - referenced)
    if missing_ids:
        errors.append("review provenance misses ledger ID(s): " + ", ".join(missing_ids))
    if _semantic_sha256(spans) != EXPECTED_SPANS_SHA256:
        errors.append("review provenance span authority digest mismatch")

    evidence_path = root / EVIDENCE.relative_to(ROOT)
    try:
        evidence = _extract(
            evidence_path.read_text(encoding="utf-8")
            if evidence_text is None
            else evidence_text,
            EVIDENCE_BEGIN,
            EVIDENCE_END,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"review evidence index: {exc}")
        evidence = {}
    if set(evidence) != {"schema", "pull_request", "entries"}:
        errors.append("review evidence top-level fields are not closed")
    if evidence.get("schema") != "ninlil-oss-review-evidence-v1":
        errors.append("review evidence schema drift")
    if evidence.get("pull_request") != (
        "https://github.com/Aero123421/Ninlil-Runtime/pull/117"
    ):
        errors.append("review evidence pull-request authority drift")
    entries = evidence.get("entries")
    evidence_ids: list[str] = []
    if not isinstance(entries, list):
        errors.append("review evidence entries must be a list")
        entries = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != {
            "id", "status", "records", "authorities", "checks", "remote"
        }:
            errors.append(f"review evidence entry {index}: fields are not closed")
            continue
        item_id = entry.get("id")
        status = entry.get("status")
        if not isinstance(item_id, str):
            errors.append(f"review evidence entry {index}: invalid ID")
            continue
        evidence_ids.append(item_id)
        if status != ledger_status.get(item_id):
            errors.append(f"review evidence {item_id}: status differs from ledger")
        for field in ("records", "authorities"):
            paths = entry.get(field)
            if not isinstance(paths, list) or not paths:
                errors.append(f"review evidence {item_id}: {field} must be non-empty")
                continue
            for raw_path in paths:
                if not isinstance(raw_path, str) or not (root / raw_path).exists():
                    errors.append(
                        f"review evidence {item_id}: missing {field} path {raw_path!r}"
                    )
        checks = entry.get("checks")
        if (
            not isinstance(checks, list)
            or not checks
            or any(not isinstance(check, str) or not check for check in checks)
        ):
            errors.append(f"review evidence {item_id}: checks must be non-empty strings")
        if not isinstance(entry.get("remote"), str) or not entry.get("remote"):
            errors.append(f"review evidence {item_id}: remote class is invalid")
    if evidence_ids != expected_ids:
        errors.append(
            f"review evidence IDs must be exact 01..37 (got {evidence_ids})"
        )
    if _semantic_sha256(entries) != EXPECTED_ENTRIES_SHA256:
        errors.append("review evidence entry authority digest mismatch")

    try:
        actual_charter = (
            (root / "docs/00-project-charter.md").read_text(encoding="utf-8")
            if charter_text is None
            else charter_text
        )
        actual_readme = (
            (root / "README.md").read_text(encoding="utf-8")
            if readme_text is None
            else readme_text
        )
    except (OSError, UnicodeError) as exc:
        errors.append(f"review maturity authority unreadable: {exc}")
    else:
        try:
            active_charter = _active_markdown(actual_charter)
            active_readme = _active_markdown(actual_readme)
        except ValueError as exc:
            errors.append(str(exc))
            active_charter = ""
            active_readme = ""
        if not re.search(
            rf"^{re.escape(CHARTER_MATURITY)}$", active_charter, re.MULTILINE
        ):
            errors.append("Charter pre-alpha maturity authority drift")
        if active_charter.count(CHARTER_ENGLISH_EXIT) != 1:
            errors.append("Charter public-alpha English exit authority drift")
        if active_readme.count(README_MATURITY) != 1:
            errors.append("README pre-release maturity authority drift")
    return errors


def self_test() -> None:
    baseline = INDEX.read_text(encoding="utf-8")
    evidence = EVIDENCE.read_text(encoding="utf-8")
    ledger = (ROOT / "docs/work/2026-08-12-oss-review-completion-ledger.md").read_text(
        encoding="utf-8"
    )
    charter = (ROOT / "docs/00-project-charter.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    source_bytes = (ROOT / EXPECTED_SOURCE["path"]).read_bytes()
    if validate(ROOT, baseline, evidence):
        raise RuntimeError("repository baseline failed provenance validation")
    mutations = [
        baseline.replace('"start": 159, "end": 159', '"start": 160, "end": 160', 1),
        baseline.replace('"OR-36"', '"OR-12"', 1),
        baseline.replace('"canonical_sha256": "e912e6bd', '"canonical_sha256": "0912e6bd', 1),
        baseline.replace(
            '"schema": "ninlil-oss-review-provenance-v1",',
            '"schema": "ninlil-oss-review-provenance-v1",\n'
            '  "schema": "ninlil-oss-review-provenance-v1",',
            1,
        ),
        "````markdown\n" + baseline + "\n````\n",
        "<!--\n" + baseline + "\n-->\n",
    ]
    for index, mutation in enumerate(mutations):
        if mutation == baseline or not validate(ROOT, mutation, evidence):
            raise RuntimeError(f"provenance mutation {index} was accepted")
    source_mutation = source_bytes.replace(
        "ファジングが皆無".encode("utf-8"),
        "ファジングは十分".encode("utf-8"),
        1,
    )
    if source_mutation == source_bytes:
        raise RuntimeError("source mutation fixture did not change the source")
    received_mutation = source_mutation[:-1]
    coherent_source_index = baseline.replace(
        str(EXPECTED_SOURCE["canonical_bytes"]),
        str(len(source_mutation)),
        1,
    ).replace(
        str(EXPECTED_SOURCE["received_bytes"]),
        str(len(received_mutation)),
        1,
    ).replace(
        str(EXPECTED_SOURCE["canonical_sha256"]),
        _sha256(source_mutation),
        1,
    ).replace(
        str(EXPECTED_SOURCE["received_sha256"]),
        _sha256(received_mutation),
        1,
    )
    if not validate(
        ROOT,
        coherent_source_index,
        evidence,
        source_bytes_override=source_mutation,
    ):
        raise RuntimeError("coherent review-source replacement was accepted")
    replacement_target = "a" * 40
    target_source = source_bytes.replace(
        f"対象 {EXPECTED_REVIEW_TARGET[:7]}".encode("utf-8"),
        f"対象 {replacement_target[:7]}".encode("utf-8"),
        1,
    )
    target_received = target_source[:-1]
    coherent_target_index = (
        baseline.replace(EXPECTED_REVIEW_TARGET, replacement_target, 1)
        .replace(
            str(EXPECTED_SOURCE["canonical_sha256"]),
            _sha256(target_source),
            1,
        )
        .replace(
            str(EXPECTED_SOURCE["received_sha256"]),
            _sha256(target_received),
            1,
        )
    )
    coherent_target_ledger = ledger.replace(
        EXPECTED_REVIEW_TARGET,
        replacement_target,
        1,
    )
    if (
        target_source == source_bytes
        or coherent_target_ledger == ledger
        or not validate(
            ROOT,
            coherent_target_index,
            evidence,
            ledger_text_override=coherent_target_ledger,
            source_bytes_override=target_source,
        )
    ):
        raise RuntimeError("coherent review-target replacement was accepted")
    evidence_mutations = [
        evidence.replace('"id":"OR-36"', '"id":"OR-12"', 1),
        evidence.replace('"status":"EXTERNAL"', '"status":"CLOSED"', 1),
        evidence.replace('"tools/runtime_step_epilogue_gate.py"',
                         '"tools/missing-runtime-step-gate.py"', 1),
        evidence.replace(
            '"schema": "ninlil-oss-review-evidence-v1",',
            '"schema": "ninlil-oss-review-evidence-v1",\n'
            '  "schema": "ninlil-oss-review-evidence-v1",',
            1,
        ),
        "````markdown\n" + evidence + "\n````\n",
        "<!--\n" + evidence + "\n-->\n",
    ]
    for index, mutation in enumerate(evidence_mutations):
        if mutation == evidence or not validate(ROOT, baseline, mutation):
            raise RuntimeError(f"evidence mutation {index} was accepted")
    coherent_ledger = ledger.replace(
        "| OR-09 | copyright holder/SPDX/DCO経路が不在 | EXTERNAL |",
        "| OR-09 | copyright holder/SPDX/DCO経路が不在 | CLOSED |",
        1,
    )
    coherent_evidence = evidence.replace(
        '"id":"OR-09","status":"EXTERNAL"',
        '"id":"OR-09","status":"CLOSED"',
        1,
    )
    if (
        coherent_ledger == ledger
        or coherent_evidence == evidence
        or not validate(
            ROOT,
            baseline,
            coherent_evidence,
            ledger_text_override=coherent_ledger,
        )
    ):
        raise RuntimeError("coherent external-to-closed mutation was accepted")
    redirected_index = baseline.replace(
        EXPECTED_LEDGER_PATH,
        "docs/work/alternate-completion-ledger.md",
        1,
    )
    if redirected_index == baseline or not validate(
        ROOT,
        redirected_index,
        evidence,
        ledger_text_override=ledger,
    ):
        raise RuntimeError("review ledger path redirection was accepted")
    ledger_mutations = (
        "````markdown\n" + ledger + "\n````\n",
        "<!--\n" + ledger + "\n-->\n",
    )
    for index, ledger_mutation in enumerate(ledger_mutations):
        if not validate(
            ROOT,
            baseline,
            evidence,
            ledger_text_override=ledger_mutation,
        ):
            raise RuntimeError(f"inactive review ledger mutation {index} was accepted")
    premise_mutations = (
        (charter.replace(CHARTER_MATURITY, "現在の maturity: Public alpha", 1), readme),
        (charter.replace(CHARTER_ENGLISH_EXIT, "", 1), readme),
        (charter, readme.replace(README_MATURITY, "**安定版 SDK**", 1)),
        (
            charter.replace(CHARTER_MATURITY, "現在の maturity: Public alpha", 1)
            + f"\n<!-- {CHARTER_MATURITY} -->\n",
            readme,
        ),
        (
            charter.replace(CHARTER_ENGLISH_EXIT, "", 1)
            + f"\n<!-- {CHARTER_ENGLISH_EXIT} -->\n",
            readme,
        ),
        (
            charter,
            readme.replace(README_MATURITY, "**Public alpha SDK**", 1)
            + f"\n<!-- {README_MATURITY} -->\n",
        ),
        (
            charter.replace(CHARTER_MATURITY, "現在の maturity: Public alpha", 1)
            + f"\n<!--\n{CHARTER_MATURITY}\n",
            readme,
        ),
    )
    for index, (charter_mutation, readme_mutation) in enumerate(premise_mutations):
        if not validate(
            ROOT,
            baseline,
            evidence,
            charter_text=charter_mutation,
            readme_text=readme_mutation,
        ):
            raise RuntimeError(f"maturity premise mutation {index} was accepted")
    print("OSS review provenance gate self-test: ok")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return 0
    errors = validate(ROOT)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("OSS review provenance gate: source/map/ledger exact")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
