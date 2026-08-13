#!/usr/bin/env python3
"""V1-LAB durable allowlist structural and exact-authority gate (unit 1a).

Ensures production durable puts flow only through v1_durable_allowlist.c and
that the header, record table, operation/kind mask, and work-record matrix are
the same closed authority.

Usage:
  python3 tools/v1_durable_allowlist_gate.py check
  python3 tools/v1_durable_allowlist_gate.py self-test

CTest names:
  v1_durable_allowlist_source_gate
  v1_durable_allowlist_gate_self_test
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_C = REPO_ROOT / "src" / "runtime" / "v1_durable_allowlist.c"
ALLOWLIST_H = REPO_ROOT / "src" / "runtime" / "v1_durable_allowlist.h"
ALLOWLIST_DOC = (
    REPO_ROOT / "docs" / "work" / "2026-07-23-v1-durable-allowlist.md"
)
STAGE5_C = REPO_ROOT / "src" / "runtime" / "stage5_empty_metadata.c"
CANONICAL_C = REPO_ROOT / "src" / "runtime" / "storage_canonical_plan.c"
PUBLIC_LEAK = REPO_ROOT / "include" / "ninlil" / "v1_durable_allowlist.h"

DIRECT_PUT_RE = re.compile(r"storage\s*->\s*put\s*\(")
STORAGE_PUT_RE = re.compile(r"ninlil_v1_durable_storage_put\s*\(")
KIND_COUNT_RE = re.compile(
    r"#define\s+NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT"
    r"\s+\(\(uint32_t\)(\d+)u\)"
)
OPERATION_COUNT_RE = re.compile(
    r"#define\s+NINLIL_V1_DURABLE_ALLOWLIST_OPERATION_COUNT"
    r"\s+\(\(uint32_t\)(\d+)u\)"
)
KIND_ENUM_RE = re.compile(
    r"^\s*(NINLIL_V1_DURABLE_KIND_[A-Z0-9_]+)\s*=\s*(\d+),?\s*$",
    re.MULTILINE,
)
OPERATION_ENUM_RE = re.compile(
    r"^\s*(NINLIL_V1_DURABLE_OP_[A-Z0-9_]+)\s*=\s*(\d+),?\s*$",
    re.MULTILINE,
)
RECORD_TABLE_ROW_RE = re.compile(
    r"\{\s*(NINLIL_V1_DURABLE_KIND_[A-Z0-9_]+)\s*,"
    r"\s*(NINLIL_V1_DURABLE_OWNER_[A-Z0-9_]+)\s*,"
    r'\s*"([A-Z0-9_]+)"\s*\}',
    re.MULTILINE,
)
MATRIX_ROW_RE = re.compile(
    r"\{\s*(NINLIL_V1_DURABLE_OP_[A-Z0-9_]+)\s*,"
    r"\s*UINT64_C\(\s*(0x[0-9a-fA-F]+)\s*\)\s*\}",
    re.MULTILINE,
)
DOC_KIND_COUNT_RE = re.compile(
    r"^## 2\. Record kind allowlist[（(](\d+) kinds[）)]"
    r"[^\S\r\n]*$",
    re.MULTILINE,
)

KIND_NAMES: Tuple[str, ...] = (
    "RS_BINDING",
    "RS_IDENTITY",
    "RS_COUNTER_TRANSACTION",
    "RS_COUNTER_ORDERED_INPUT",
    "RS_COUNTER_ASSIGNED_OWNER",
    "RS_COUNTER_VISITED_OWNER",
    "RS_CAPACITY_SERVICE",
    "RS_CAPACITY_TRANSACTION",
    "RS_CAPACITY_TARGET",
    "RS_CAPACITY_OUTBOX_BYTES",
    "RS_CAPACITY_DELIVERY",
    "RS_CAPACITY_EVENT_SPOOL_COUNT",
    "RS_CAPACITY_EVENT_SPOOL_BYTES",
    "RS_CAPACITY_RESULT_CACHE",
    "RS_CAPACITY_EVIDENCE",
    "RS_CAPACITY_INGRESS",
    "RS_CAPACITY_DEFERRED_TOKEN",
    "DOM_WITNESS_HEAD_INDEX",
    "DOM_CLOCK_BASELINE",
    "SPINE_SERVICE_MARKER",
    "SPINE_TXN_ADMISSION",
    "SPINE_CANCEL_ADMISSION",
    "SPINE_DELIVERY_STARTED",
    "SPINE_DELIVERY_EVIDENCE",
    "SPINE_DELIVERY_OUTCOME",
    "SPINE_EVENT_SPOOL",
    "SPINE_EVENT_RESUME",
    "SPINE_EVENT_DISCARD",
    "SPINE_RETRY_STATE",
    "SPINE_RESERVATION",
    "M4_INSTALL_TOKEN",
    "C3_REPLAY_ADMISSION",
    "SPINE_BEARER_STATE",
    "SPINE_ATTEMPT_PREPARE",
    "DOM_IDEMPOTENCY_MAP",
    "DOM_EVENT_ID_MAP",
    "DOM_WITNESS_HEADER",
    "DOM_WITNESS_MANIFEST_CHUNK",
    "DOM_SERVICE",
    "DOM_SERVICE_QUOTA",
    "DOM_RESERVATION",
)
CAPACITY_KIND_NAMES = KIND_NAMES[6:17]
OPERATION_MATRIX: Tuple[Tuple[str, Tuple[str, ...]], ...] = (
    ("BOOTSTRAP_COMMIT", KIND_NAMES[:17]),
    (
        "METADATA_INIT_COMMIT",
        ("DOM_WITNESS_HEAD_INDEX", "DOM_CLOCK_BASELINE"),
    ),
    ("CLOCK_TRUSTED_COMMIT", ("DOM_CLOCK_BASELINE",)),
    (
        "SERVICE_REGISTER_COMMIT",
        ("SPINE_SERVICE_MARKER", "RS_CAPACITY_SERVICE"),
    ),
    (
        "SUBMIT_ADMISSION_COMMIT",
        (
            "SPINE_TXN_ADMISSION",
            "SPINE_RESERVATION",
            "SPINE_SERVICE_MARKER",
            "DOM_IDEMPOTENCY_MAP",
            "DOM_EVENT_ID_MAP",
            "DOM_WITNESS_HEADER",
            "DOM_WITNESS_MANIFEST_CHUNK",
            *CAPACITY_KIND_NAMES,
        ),
    ),
    (
        "CANCEL_ADMISSION_COMMIT",
        (
            "SPINE_CANCEL_ADMISSION",
            "SPINE_SERVICE_MARKER",
            "RS_COUNTER_ORDERED_INPUT",
            *CAPACITY_KIND_NAMES,
        ),
    ),
    (
        "DELIVERY_STARTED_COMMIT",
        (
            "SPINE_DELIVERY_STARTED",
            "SPINE_SERVICE_MARKER",
            "RS_COUNTER_ORDERED_INPUT",
            *CAPACITY_KIND_NAMES,
        ),
    ),
    (
        "DELIVERY_EVIDENCE_COMMIT",
        (
            "SPINE_DELIVERY_EVIDENCE",
            "SPINE_SERVICE_MARKER",
            "RS_COUNTER_ORDERED_INPUT",
            *CAPACITY_KIND_NAMES,
        ),
    ),
    (
        "DELIVERY_OUTCOME_COMMIT",
        (
            "SPINE_DELIVERY_OUTCOME",
            "SPINE_SERVICE_MARKER",
            *CAPACITY_KIND_NAMES,
        ),
    ),
    ("EVENT_SPOOL_COMMIT", ("SPINE_EVENT_SPOOL",)),
    (
        "EVENT_RESUME_COMMIT",
        (
            "SPINE_EVENT_RESUME",
            "SPINE_SERVICE_MARKER",
            "RS_COUNTER_ORDERED_INPUT",
            *CAPACITY_KIND_NAMES,
        ),
    ),
    (
        "EVENT_DISCARD_COMMIT",
        (
            "SPINE_EVENT_DISCARD",
            "SPINE_SERVICE_MARKER",
            "RS_COUNTER_ORDERED_INPUT",
            *CAPACITY_KIND_NAMES,
        ),
    ),
    ("RETRY_STATE_COMMIT", ("SPINE_RETRY_STATE",)),
    ("RESERVATION_COMMIT", ("SPINE_RESERVATION",)),
    ("M4_INSTALL_TOKEN_COMMIT", ("M4_INSTALL_TOKEN",)),
    ("C3_REPLAY_ADMISSION_COMMIT", ("C3_REPLAY_ADMISSION",)),
    ("BEARER_STATE_COMMIT", ("SPINE_BEARER_STATE",)),
    (
        "APPLICATION_ATTEMPT_PREPARE_COMMIT",
        ("SPINE_ATTEMPT_PREPARE",),
    ),
    (
        "DESTROY_RECOVERY_COMMIT",
        (
            "SPINE_DELIVERY_EVIDENCE",
            "SPINE_SERVICE_MARKER",
            *CAPACITY_KIND_NAMES,
        ),
    ),
)


def strip_c_comments_and_strings(src: str) -> str:
    out: List[str] = []
    i = 0
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == "/" and i + 1 < n and src[i + 1] == "/":
            i += 2
            while i < n and src[i] not in "\n\r":
                i += 1
            continue
        if ch == "/" and i + 1 < n and src[i + 1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i + 1] == "/"):
                if src[i] in "\n\r":
                    out.append(src[i])
                i += 1
            i = min(i + 2, n)
            continue
        if ch == '"':
            out.append(" ")
            i += 1
            while i < n and src[i] != '"':
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i = min(i + 1, n)
            continue
        if ch == "'":
            out.append(" ")
            i += 1
            while i < n and src[i] != "'":
                if src[i] == "\\" and i + 1 < n:
                    i += 2
                else:
                    i += 1
            i = min(i + 1, n)
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def expected_kind_symbols() -> Tuple[str, ...]:
    return tuple(f"NINLIL_V1_DURABLE_KIND_{name}" for name in KIND_NAMES)


def expected_operation_symbols() -> Tuple[str, ...]:
    return tuple(
        f"NINLIL_V1_DURABLE_OP_{operation}"
        for operation, _ in OPERATION_MATRIX
    )


def kind_mask(kind_names: Sequence[str]) -> int:
    indexes = {name: index for index, name in enumerate(KIND_NAMES)}
    return sum(1 << indexes[name] for name in kind_names)


def expected_doc_kind_catalog() -> Tuple[Tuple[int, str, str], ...]:
    return tuple(
        (
            index + 1,
            name,
            (
                "M4"
                if name == "M4_INSTALL_TOKEN"
                else "C3" if name == "C3_REPLAY_ADMISSION" else "S1"
            ),
        )
        for index, name in enumerate(KIND_NAMES)
    )


def append_exact_mismatch(
    errors: List[str],
    label: str,
    actual: Sequence[object],
    expected: Sequence[object],
) -> None:
    if actual == expected:
        return
    if len(actual) != len(expected):
        errors.append(
            f"{label} row count {len(actual)} != exact count {len(expected)}"
        )
    for index, (actual_row, expected_row) in enumerate(zip(actual, expected)):
        if actual_row != expected_row:
            errors.append(
                f"{label} mismatch at row {index + 1}: "
                f"{actual_row!r} != {expected_row!r}"
            )
            return
    if len(actual) > len(expected):
        errors.append(f"{label} has extra row {actual[len(expected)]!r}")
    elif len(actual) < len(expected):
        errors.append(f"{label} omits row {expected[len(actual)]!r}")


def parse_doc_operation_rows(
    doc_text: str,
) -> Tuple[Tuple[str, Tuple[str, ...]], ...]:
    start_marker = "## 4. Operation allowlist"
    end_marker = "\n## 5."
    if start_marker not in doc_text:
        return ()
    section = doc_text.split(start_marker, 1)[1]
    if end_marker in section:
        section = section.split(end_marker, 1)[0]
    rows: List[Tuple[str, Tuple[str, ...]]] = []
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().split("|")[1:-1]]
        if len(cells) != 3:
            continue
        operation_match = re.fullmatch(r"`([A-Z0-9_]+)`", cells[0])
        if operation_match is None:
            continue
        kinds = tuple(re.findall(r"`([A-Z][A-Z0-9_]+)`", cells[2]))
        rows.append((operation_match.group(1), kinds))
    return tuple(rows)


def parse_doc_kind_catalog(
    doc_text: str,
) -> Tuple[Optional[int], Tuple[Tuple[int, str, str], ...]]:
    count_match = DOC_KIND_COUNT_RE.search(doc_text)
    if count_match is None:
        return None, ()
    section = doc_text[count_match.end() :]
    if "\n### 2" in section:
        section = section.split("\n### 2", 1)[0]
    rows: List[Tuple[int, str, str]] = []
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().split("|")[1:-1]]
        if len(cells) != 5 or re.fullmatch(r"\d+", cells[0]) is None:
            continue
        kind_match = re.fullmatch(r"`?([A-Z][A-Z0-9_]+)`?", cells[1])
        owner_match = re.fullmatch(r"`?(S1|M4|C3)`?", cells[4])
        if kind_match is None or owner_match is None:
            continue
        rows.append(
            (int(cells[0]), kind_match.group(1), owner_match.group(1))
        )
    return int(count_match.group(1)), tuple(rows)


def validate_exact_authority(
    h_text: str,
    c_text: str,
    doc_text: str,
) -> List[str]:
    errors: List[str] = []
    kind_symbols = expected_kind_symbols()
    operation_symbols = expected_operation_symbols()

    kind_count_match = KIND_COUNT_RE.search(h_text)
    if kind_count_match is None:
        errors.append(
            "missing NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT in header"
        )
    elif int(kind_count_match.group(1)) != len(KIND_NAMES):
        errors.append(
            "record-kind count does not match exact authority: "
            f"{kind_count_match.group(1)} != {len(KIND_NAMES)}"
        )

    operation_count_match = OPERATION_COUNT_RE.search(h_text)
    if operation_count_match is None:
        errors.append(
            "missing NINLIL_V1_DURABLE_ALLOWLIST_OPERATION_COUNT in header"
        )
    elif int(operation_count_match.group(1)) != len(OPERATION_MATRIX):
        errors.append(
            "operation count does not match exact authority: "
            f"{operation_count_match.group(1)} != {len(OPERATION_MATRIX)}"
        )

    actual_kind_enum = tuple(
        (symbol, int(number)) for symbol, number in KIND_ENUM_RE.findall(h_text)
    )
    expected_kind_enum = tuple(
        (symbol, index + 1) for index, symbol in enumerate(kind_symbols)
    )
    append_exact_mismatch(
        errors, "record-kind enum authority", actual_kind_enum, expected_kind_enum
    )

    actual_operation_enum = tuple(
        (symbol, int(number))
        for symbol, number in OPERATION_ENUM_RE.findall(h_text)
    )
    expected_operation_enum = tuple(
        (symbol, index + 1) for index, symbol in enumerate(operation_symbols)
    )
    append_exact_mismatch(
        errors,
        "operation enum authority",
        actual_operation_enum,
        expected_operation_enum,
    )

    expected_record_rows = tuple(
        (
            symbol,
            (
                "NINLIL_V1_DURABLE_OWNER_M4"
                if name == "M4_INSTALL_TOKEN"
                else (
                    "NINLIL_V1_DURABLE_OWNER_C3"
                    if name == "C3_REPLAY_ADMISSION"
                    else "NINLIL_V1_DURABLE_OWNER_S1"
                )
            ),
            name,
        )
        for symbol, name in zip(kind_symbols, KIND_NAMES)
    )
    actual_record_rows = tuple(RECORD_TABLE_ROW_RE.findall(c_text))
    append_exact_mismatch(
        errors,
        "record table authority",
        actual_record_rows,
        expected_record_rows,
    )

    expected_mask_rows = tuple(
        (
            f"NINLIL_V1_DURABLE_OP_{operation}",
            kind_mask(kinds),
        )
        for operation, kinds in OPERATION_MATRIX
    )
    actual_mask_rows = tuple(
        (operation, int(mask, 16))
        for operation, mask in MATRIX_ROW_RE.findall(c_text)
    )
    append_exact_mismatch(
        errors,
        "operation mask authority",
        actual_mask_rows,
        expected_mask_rows,
    )

    doc_kind_count, actual_doc_kind_catalog = parse_doc_kind_catalog(doc_text)
    if doc_kind_count is None:
        errors.append("document §2 record-kind count heading missing")
    elif doc_kind_count != len(KIND_NAMES):
        errors.append(
            "document §2 record-kind count does not match exact authority: "
            f"{doc_kind_count} != {len(KIND_NAMES)}"
        )
    append_exact_mismatch(
        errors,
        "document §2 kind catalog",
        actual_doc_kind_catalog,
        expected_doc_kind_catalog(),
    )

    actual_doc_rows = parse_doc_operation_rows(doc_text)
    append_exact_mismatch(
        errors,
        "document §4 operation matrix",
        actual_doc_rows,
        OPERATION_MATRIX,
    )
    return errors


def check_sources(
    *,
    h_text: Optional[str] = None,
    c_text: Optional[str] = None,
    doc_text: Optional[str] = None,
    stage5_text: Optional[str] = None,
) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    if PUBLIC_LEAK.is_file():
        errors.append(f"public header leak: {PUBLIC_LEAK}")

    h_text = read_text(ALLOWLIST_H) if h_text is None else h_text
    c_text = read_text(ALLOWLIST_C) if c_text is None else c_text
    doc_text = read_text(ALLOWLIST_DOC) if doc_text is None else doc_text
    stage5_text = read_text(STAGE5_C) if stage5_text is None else stage5_text
    errors.extend(validate_exact_authority(h_text, c_text, doc_text))

    stage5_stripped = strip_c_comments_and_strings(stage5_text)
    if not STORAGE_PUT_RE.search(stage5_stripped):
        errors.append("stage5_empty_metadata.c missing ninlil_v1_durable_storage_put")
    stage5_puts = list(DIRECT_PUT_RE.finditer(stage5_stripped))
    if stage5_puts:
        errors.append(
            "stage5_empty_metadata.c: expected 0 direct storage->put "
            f"(use ninlil_v1_durable_storage_put), found {len(stage5_puts)}"
        )
    elif "put_encoded" not in stage5_stripped:
        errors.append("stage5_empty_metadata.c: durable put outside put_encoded")

    allowlist_stripped = strip_c_comments_and_strings(c_text)
    puts = list(DIRECT_PUT_RE.finditer(allowlist_stripped))
    if len(puts) != 1:
        errors.append(
            "v1_durable_allowlist.c: expected exactly 1 storage->put, "
            f"found {len(puts)}"
        )

    if "ninlil_v1_durable_writer_gate_check" not in read_text(
        REPO_ROOT / "src" / "runtime" / "runtime_store_orchestrator.c"
    ):
        errors.append(
            "runtime_store_orchestrator.c missing bootstrap writer gate check"
        )
    if "ninlil_v1_durable_storage_put" not in stage5_text:
        errors.append("stage5_empty_metadata.c missing domain storage_put wiring")

    return errors, warnings


def check() -> Tuple[List[str], List[str]]:
    return check_sources()


def require_mutation_red(
    label: str,
    errors: Sequence[str],
    expected_fragment: str,
) -> None:
    if not any(expected_fragment in error for error in errors):
        print(f"mutation: {label} did not go red")
        for error in errors:
            print(f"  observed: {error}")
        sys.exit(1)


def self_test() -> None:
    errors, _ = check()
    if errors:
        print("self-test precondition failed:", *errors, sep="\n  ")
        sys.exit(1)

    stage5_text = read_text(STAGE5_C)
    bypassed_stage5 = stage5_text.replace(
        "gate_status = ninlil_v1_durable_storage_put(\n"
        "        operation, storage, txn, k, v, inout_fence);",
        "gate_status = NINLIL_OK; /* storage_put removed for mutation */",
        1,
    )
    if bypassed_stage5 == stage5_text:
        print("mutation precondition: stage5 storage_put call not found")
        sys.exit(1)
    mutation_errors, _ = check_sources(stage5_text=bypassed_stage5)
    require_mutation_red("storage_put bypass", mutation_errors, "storage_put")

    h_text = read_text(ALLOWLIST_H)
    count_match = KIND_COUNT_RE.search(h_text)
    if count_match is None:
        print("mutation precondition: kind count declaration missing")
        sys.exit(1)
    mutated_count = int(count_match.group(1)) + 1
    changed_header = (
        h_text[: count_match.start(1)]
        + str(mutated_count)
        + h_text[count_match.end(1) :]
    )
    mutation_errors, _ = check_sources(h_text=changed_header)
    require_mutation_red(
        "record-kind count mismatch",
        mutation_errors,
        "record-kind count",
    )

    doc_text = read_text(ALLOWLIST_DOC)
    doc_count_match = DOC_KIND_COUNT_RE.search(doc_text)
    if doc_count_match is None:
        print("mutation precondition: document §2 kind count missing")
        sys.exit(1)
    changed_doc_count = (
        doc_text[: doc_count_match.start(1)]
        + str(int(doc_count_match.group(1)) + 1)
        + doc_text[doc_count_match.end(1) :]
    )
    mutation_errors, _ = check_sources(doc_text=changed_doc_count)
    require_mutation_red(
        "document §2 count mismatch",
        mutation_errors,
        "document §2 record-kind count",
    )

    omitted_doc_count = (
        doc_text[: doc_count_match.start()]
        + "## 2. Record kind allowlist"
        + doc_text[doc_count_match.end() :]
    )
    mutation_errors, _ = check_sources(doc_text=omitted_doc_count)
    require_mutation_red(
        "document §2 count omission",
        mutation_errors,
        "document §2 record-kind count",
    )

    doc_kind_row = re.search(
        r"^\| 41 \| DOM_RESERVATION \|[^\r\n]*\r?\n?",
        doc_text,
        re.MULTILINE,
    )
    if doc_kind_row is None:
        print("mutation precondition: document §2 kind 41 row missing")
        sys.exit(1)
    omitted_doc_kind = (
        doc_text[: doc_kind_row.start()] + doc_text[doc_kind_row.end() :]
    )
    mutation_errors, _ = check_sources(doc_text=omitted_doc_kind)
    require_mutation_red(
        "document §2 kind omission",
        mutation_errors,
        "document §2 kind catalog",
    )

    changed_doc_kind = doc_text.replace(
        "| 41 | DOM_RESERVATION |",
        "| 41 | DOM_RESERVATION_MUTATED |",
        1,
    )
    if changed_doc_kind == doc_text:
        print("mutation precondition: document §2 kind 41 token missing")
        sys.exit(1)
    mutation_errors, _ = check_sources(doc_text=changed_doc_kind)
    require_mutation_red(
        "document §2 kind change",
        mutation_errors,
        "document §2 kind catalog",
    )

    doc_operation_row = re.search(
        r"^\| `BOOTSTRAP_COMMIT` \|[^\r\n]*\r?\n?",
        doc_text,
        re.MULTILINE,
    )
    if doc_operation_row is None:
        print("mutation precondition: document §4 operation row missing")
        sys.exit(1)
    omitted_doc_operation = (
        doc_text[: doc_operation_row.start()]
        + doc_text[doc_operation_row.end() :]
    )
    mutation_errors, _ = check_sources(doc_text=omitted_doc_operation)
    require_mutation_red(
        "document §4 operation omission",
        mutation_errors,
        "document §4 operation matrix",
    )

    clock_operation_row = re.search(
        r"^\| `CLOCK_TRUSTED_COMMIT` \|[^\r\n]*\r?\n?",
        doc_text,
        re.MULTILINE,
    )
    if clock_operation_row is None:
        print("mutation precondition: document §4 clock row missing")
        sys.exit(1)
    changed_clock_row = clock_operation_row.group(0).replace(
        "`DOM_CLOCK_BASELINE`",
        "`DOM_WITNESS_HEAD_INDEX`",
        1,
    )
    if changed_clock_row == clock_operation_row.group(0):
        print("mutation precondition: document §4 clock kind missing")
        sys.exit(1)
    changed_doc_operation = (
        doc_text[: clock_operation_row.start()]
        + changed_clock_row
        + doc_text[clock_operation_row.end() :]
    )
    mutation_errors, _ = check_sources(doc_text=changed_doc_operation)
    require_mutation_red(
        "document §4 operation/kind change",
        mutation_errors,
        "document §4 operation matrix",
    )

    c_text = read_text(ALLOWLIST_C)
    matrix_rows = list(MATRIX_ROW_RE.finditer(c_text))
    if len(matrix_rows) != len(OPERATION_MATRIX):
        print("mutation precondition: exact operation matrix rows not found")
        sys.exit(1)
    first_row = matrix_rows[0]

    omitted_operation = c_text[: first_row.start()] + c_text[first_row.end() :]
    mutation_errors, _ = check_sources(c_text=omitted_operation)
    require_mutation_red(
        "operation omission",
        mutation_errors,
        "operation mask authority",
    )

    extra_operation = (
        c_text[: first_row.end()]
        + "\n"
        + first_row.group(0)
        + c_text[first_row.end() :]
    )
    mutation_errors, _ = check_sources(c_text=extra_operation)
    require_mutation_red(
        "extra operation",
        mutation_errors,
        "operation mask authority",
    )

    mask_start, mask_end = first_row.span(2)
    changed_mask = int(first_row.group(2), 16) ^ (1 << (len(KIND_NAMES) - 1))
    changed_pair = (
        c_text[:mask_start]
        + f"0x{changed_mask:09x}"
        + c_text[mask_end:]
    )
    mutation_errors, _ = check_sources(c_text=changed_pair)
    require_mutation_red(
        "operation/kind pair",
        mutation_errors,
        "operation mask authority",
    )

    print("ok v1_durable_allowlist_gate_self_test")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "self-test"):
        print(
            "usage: v1_durable_allowlist_gate.py check|self-test",
            file=sys.stderr,
        )
        sys.exit(2)
    if sys.argv[1] == "self-test":
        self_test()
        return
    errors, warnings = check()
    for warning in warnings:
        print(f"warning: {warning}")
    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
    print("ok v1_durable_allowlist_source_gate")


if __name__ == "__main__":
    main()
