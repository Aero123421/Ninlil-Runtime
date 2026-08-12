#!/usr/bin/env python3
"""Fail closed when public ownership/status contracts drift from their APIs."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = "include/ninlil/runtime.h"
PLATFORM = "include/ninlil/platform.h"
SERVICE = "include/ninlil/service.h"
TRANSACTION = "include/ninlil/transaction.h"
HEADERS = (RUNTIME, PLATFORM, SERVICE, TRANSACTION)


class ContractError(RuntimeError):
    pass


def statuses(words: str) -> set[str]:
    return {"NINLIL_" + word for word in words.split()}


# Exact reviewed public status sets. NINLIL_E_CALLBACK and NINLIL_E_INTERNAL
# are deliberately absent: both remain reserved/never generated in M1a.
RUNTIME_STATUSES = {
    "runtime_create": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_CONFLICT "
        "E_CAPACITY_EXHAUSTED E_STORAGE E_STORAGE_CORRUPT "
        "E_STORAGE_COMMIT_UNKNOWN E_CLOCK_UNCERTAIN E_ENTROPY E_WOULD_BLOCK "
        "E_DEGRADED"
    ),
    "runtime_destroy": statuses(
        "OK E_INVALID_ARGUMENT E_INVALID_STATE E_WRONG_THREAD E_REENTRANT "
        "E_DEGRADED E_WOULD_BLOCK E_CAPACITY_EXHAUSTED E_STORAGE "
        "E_STORAGE_CORRUPT E_STORAGE_COMMIT_UNKNOWN"
    ),
    "service_register": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_WRONG_THREAD "
        "E_REENTRANT E_CONFLICT E_CAPACITY_EXHAUSTED E_STORAGE "
        "E_STORAGE_CORRUPT E_STORAGE_COMMIT_UNKNOWN E_WOULD_BLOCK "
        "E_INVALID_STATE E_DEGRADED"
    ),
    "submit": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_WRONG_THREAD "
        "E_REENTRANT "
        "E_CAPACITY_EXHAUSTED E_STORAGE E_STORAGE_CORRUPT "
        "E_STORAGE_COMMIT_UNKNOWN E_CLOCK_UNCERTAIN E_ENTROPY E_WOULD_BLOCK "
        "E_INVALID_STATE E_DEGRADED"
    ),
    "offer_accept": statuses(
        "E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_WRONG_THREAD "
        "E_REENTRANT E_STORAGE_COMMIT_UNKNOWN E_INVALID_STATE E_DEGRADED"
    ),
    "cancel_request": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_WRONG_THREAD "
        "E_REENTRANT E_NOT_FOUND E_CAPACITY_EXHAUSTED E_STORAGE "
        "E_STORAGE_CORRUPT E_STORAGE_COMMIT_UNKNOWN E_WOULD_BLOCK "
        "E_CLOCK_UNCERTAIN E_INVALID_STATE E_DEGRADED"
    ),
    "event_resume": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_WRONG_THREAD "
        "E_REENTRANT E_NOT_FOUND E_CAPACITY_EXHAUSTED E_STORAGE "
        "E_STORAGE_CORRUPT E_STORAGE_COMMIT_UNKNOWN E_CLOCK_UNCERTAIN "
        "E_WOULD_BLOCK E_INVALID_STATE E_DEGRADED"
    ),
    "event_discard": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_WRONG_THREAD "
        "E_REENTRANT E_NOT_FOUND E_CAPACITY_EXHAUSTED E_STORAGE "
        "E_STORAGE_CORRUPT E_STORAGE_COMMIT_UNKNOWN E_CLOCK_UNCERTAIN "
        "E_WOULD_BLOCK E_INVALID_STATE E_DEGRADED"
    ),
    "transaction_query": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_WRONG_THREAD E_NOT_FOUND "
        "E_BUFFER_TOO_SMALL E_STORAGE_CORRUPT E_INVALID_STATE E_DEGRADED"
    ),
    "transaction_list": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_WRONG_THREAD E_INVALID_STATE "
        "E_DEGRADED"
    ),
    "delivery_complete": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_WRONG_THREAD E_REENTRANT "
        "E_NOT_FOUND E_INVALID_STATE E_CLOCK_UNCERTAIN E_DEGRADED "
        "E_CAPACITY_EXHAUSTED E_WOULD_BLOCK E_STORAGE E_STORAGE_CORRUPT "
        "E_STORAGE_COMMIT_UNKNOWN"
    ),
    "runtime_step": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_UNSUPPORTED E_WRONG_THREAD "
        "E_REENTRANT E_CAPACITY_EXHAUSTED E_STORAGE E_STORAGE_CORRUPT "
        "E_STORAGE_COMMIT_UNKNOWN E_CLOCK_UNCERTAIN E_ENTROPY E_WOULD_BLOCK "
        "E_INVALID_STATE E_DEGRADED"
    ),
    "capacity_snapshot": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_WRONG_THREAD "
        "E_BUFFER_TOO_SMALL E_STORAGE_CORRUPT E_INVALID_STATE E_DEGRADED"
    ),
    "metrics_snapshot": statuses(
        "OK E_INVALID_ARGUMENT E_ABI_MISMATCH E_WRONG_THREAD E_INVALID_STATE "
        "E_DEGRADED"
    ),
}

RUNTIME_PHRASES = {
    "runtime_create": ("copies their values and namespace", "execution context as owner"),
    "runtime_destroy": (
        "failures before DESTROYING",
        "Once DESTROYING is entered, every return status consumes runtime",
        "cleanup failure never restores them",
    ),
    "service_register": ("copies descriptor text", "Runtime-owned Service handle"),
    "submit": ("all nested views for the call", "inspect out_result->kind"),
    "offer_accept": ("well-formed call returns NINLIL_E_UNSUPPORTED", "never NINLIL_OK"),
    "cancel_request": ("Controller only", "not completed remote cancellation"),
    "event_resume": ("borrows request and audit_metadata", "rather than treating OK as a state change"),
    "event_discard": ("borrows request and audit_metadata", "spool_released non-zero"),
    "transaction_query": ("target array", "read-only callback entry is allowed"),
    "transaction_list": ("caller owns page/items", "not BUFFER_TOO_SMALL", "read-only callback entry is allowed"),
    "delivery_complete": ("evidence is deep-copied", "NINLIL_OK consumes the active token"),
    "runtime_step": (
        "Callbacks may run synchronously",
        "not Transaction outcome",
        "does not expand the public Foundation completion claim",
    ),
    "capacity_snapshot": ("All 11 entries are required", "not admission guarantees", "read-only callback entry is allowed"),
    "metrics_snapshot": ("does not increment counters", "read-only callback entry is allowed"),
}

# Supporting public contracts are deliberately anchored to the declaration they
# govern, not merely to a file-level prose block.
DIRECT_COMMENTS = {
    PLATFORM: {
        "typedef struct ninlil_allocator_ops {": ("exact pointer/size/alignment once",),
        "typedef struct ninlil_execution_ops {": ("returns non-zero and stable",),
        "typedef struct ninlil_clock_ops {": (
            "closed status set is NINLIL_PORT_OK",
            "non-OK must not publish partial output",
            "A -> B -> A is a Port contract violation",
        ),
        "typedef struct ninlil_entropy_ops {": ("writes all requested bytes only on NINLIL_PORT_OK",),
        "typedef struct ninlil_storage_ops {": ("closed NINLIL_STORAGE_* domain",),
        "typedef struct ninlil_bearer_ops {": ("closed NINLIL_BEARER_* domain",),
        "typedef struct ninlil_tx_gate_ops {": ("definitely unaccepted permit", "no permit is reused"),
        "typedef struct ninlil_origin_authorization_ops {": ("decision allowed/denied is semantic",),
        "typedef struct ninlil_platform_ops {": ("All eight sub-vtable pointers are required",),
    },
    SERVICE: {
        "typedef struct ninlil_service_descriptor {": ("copies the complete semantic descriptor",),
        "typedef ninlil_callback_action_t (*ninlil_on_delivery_fn)(": ("callback automatic storage is too short-lived", "never its pointer or payload"),
        "typedef ninlil_reconcile_action_t (*ninlil_on_reconcile_fn)(": ("post-return immediate deep-copy lifetime",),
        "typedef struct ninlil_service_callbacks {": ("copies this table's user/function pointer values",),
    },
    TRANSACTION: {
        "typedef struct ninlil_submission {": ("every nested view is copied only on admit",),
        "typedef struct ninlil_submission_result {": ("NINLIL_OK is only the API boundary",),
        "typedef struct ninlil_transaction_snapshot {": ("BUFFER_TOO_SMALL publishes only the required target_count",),
        "typedef struct ninlil_transaction_page {": ("without BUFFER_TOO_SMALL",),
        "typedef struct ninlil_cancel_result {": ("not cancel completion",),
        "typedef struct ninlil_event_resume_request {": ("audit_metadata is retained only via durable copy",),
        "typedef struct ninlil_event_discard_result {": ("never merely for API NINLIL_OK",),
    },
}

STRUCT_PHRASES = {
    "ninlil_storage_ops_t": (
        "capacity is fixed and length is zero on entry",
        "Both lengths start zero; BUFFER_TOO_SMALL writes lengths only",
        "changes neither buffer nor iterator position",
        "OK deep-copies key/value into transaction staging before return",
        "Explicitly consumes an iterator once, and only while its txn is active",
        "NINLIL_STORAGE_COMMIT_UNKNOWN is not success and txn cannot be retried",
    ),
    "ninlil_bearer_ops_t": (
        "provider deep-copied them before return",
        "WOULD_BLOCK/UNAVAILABLE/DENIED/LOST_UNKNOWN retain no message",
        "conservatively possible delivery, not success",
        "valid through exactly one release_received call",
        "non-OK publishes no releasable message",
        "Consumes the one successful receive result after Core copies or drops it",
    ),
}


def normalize(text: str) -> str:
    text = re.sub(r"^\s*\* ?", "", text, flags=re.MULTILINE)
    return re.sub(r"\s+", " ", text).strip()


def read_sources() -> dict[str, str]:
    return {path: (ROOT / path).read_text(encoding="utf-8") for path in HEADERS}


def require_once(text: str, anchor: str, label: str) -> int:
    count = text.count(anchor)
    if count != 1:
        raise ContractError(f"{label}: expected exactly one anchor, found {count}")
    return text.index(anchor)


def preceding_comment(text: str, anchor: str, label: str) -> str:
    prefix = text[: require_once(text, anchor, label)]
    end = prefix.rfind("*/")
    if end < 0 or prefix[end + 2 :].strip():
        raise ContractError(f"{label}: contract comment is not directly before declaration")
    start = prefix.rfind("/*", 0, end)
    if start < 0:
        raise ContractError(f"{label}: missing contract comment")
    return normalize(prefix[start + 2 : end])


def require_phrases(text: str, phrases: tuple[str, ...], label: str) -> None:
    for phrase in phrases:
        if phrase not in text:
            raise ContractError(f"{label}: missing contract phrase: {phrase}")


def validate_runtime(text: str) -> None:
    declared = set(re.findall(r"\bninlil_status_t\s+ninlil_([a-z0-9_]+)\s*\(", text))
    expected = set(RUNTIME_STATUSES)
    if declared != expected:
        raise ContractError(
            "runtime public API inventory mismatch: "
            f"missing={sorted(expected - declared)} undocumented={sorted(declared - expected)}"
        )
    for name, expected_statuses in RUNTIME_STATUSES.items():
        comment = preceding_comment(text, f"ninlil_status_t ninlil_{name}(", name)
        require_phrases(comment, ("Ownership/output:", "Reachable statuses:"), name)
        require_phrases(comment, RUNTIME_PHRASES[name], name)
        paragraph = comment.split("Reachable statuses:", 1)[1].split(".", 1)[0]
        actual = set(re.findall(r"\bNINLIL_(?:OK|E_[A-Z_]+)\b", paragraph))
        if actual != expected_statuses:
            raise ContractError(
                f"ninlil_{name} status set mismatch: "
                f"missing={sorted(expected_statuses - actual)} "
                f"unexpected={sorted(actual - expected_statuses)}"
            )


def struct_body(text: str, typedef_name: str) -> str:
    name = typedef_name.removesuffix("_t")
    start_anchor = f"typedef struct {name} {{"
    end_anchor = f"}} {typedef_name};"
    start = require_once(text, start_anchor, typedef_name)
    end = text.find(end_anchor, start)
    if end < 0:
        raise ContractError(f"{typedef_name}: missing struct terminator")
    return normalize(text[start : end + len(end_anchor)])


def validate(sources: Mapping[str, str]) -> None:
    missing = [path for path in HEADERS if path not in sources]
    if missing:
        raise ContractError(f"missing source inputs: {missing}")
    validate_runtime(sources[RUNTIME])
    for path, anchors in DIRECT_COMMENTS.items():
        for anchor, phrases in anchors.items():
            label = f"{path}:{anchor}"
            require_phrases(preceding_comment(sources[path], anchor, label), phrases, label)
    for typedef_name, phrases in STRUCT_PHRASES.items():
        require_phrases(struct_body(sources[PLATFORM], typedef_name), phrases, typedef_name)
    storage = struct_body(sources[PLATFORM], "ninlil_storage_ops_t")
    consume = "Always consumes txn and all open child iterators, regardless of status"
    if storage.count(consume) != 2:
        raise ContractError("ninlil_storage_ops_t: commit and rollback must both consume txn/iterators")


def mutate_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise ContractError(f"self-test {label}: mutation anchor count is {text.count(old)}")
    return text.replace(old, new, 1)


def expect_red(label: str, sources: Mapping[str, str], diagnostic: str) -> None:
    try:
        validate(sources)
    except ContractError as error:
        if diagnostic not in str(error):
            raise ContractError(f"self-test {label}: wrong RED diagnostic: {error}") from error
        return
    raise ContractError(f"self-test {label}: mutation false-greened")


def self_test() -> None:
    baseline = read_sources()
    validate(baseline)

    deleted = {path: re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL) for path, text in baseline.items()}
    expect_red("all contract comments deleted", deleted, "contract comment")

    deleted = dict(baseline)
    deleted[RUNTIME] = mutate_once(
        deleted[RUNTIME],
        " * NINLIL_E_ABI_MISMATCH, NINLIL_E_WRONG_THREAD, NINLIL_E_NOT_FOUND,\n"
        " * NINLIL_E_BUFFER_TOO_SMALL, NINLIL_E_STORAGE_CORRUPT,\n",
        " * NINLIL_E_ABI_MISMATCH, NINLIL_E_WRONG_THREAD, NINLIL_E_NOT_FOUND,\n",
        "representative status line deleted",
    )
    expect_red("representative status line deleted", deleted, "ninlil_transaction_query status set mismatch")

    deleted = dict(baseline)
    deleted[RUNTIME] = mutate_once(
        deleted[RUNTIME],
        " * entered, every return status consumes runtime and all Runtime-owned Service/\n",
        " * entered, cleanup proceeds before the Runtime allocation is released.\n",
        "destroy consume rule deleted",
    )
    expect_red(
        "destroy consume rule deleted",
        deleted,
        "Once DESTROYING is entered, every return status consumes runtime",
    )

    deleted = dict(baseline)
    deleted[PLATFORM] = mutate_once(
        deleted[PLATFORM],
        " * epoch ID has been published (A -> B -> A is a Port contract violation).\n",
        "",
        "clock epoch reuse rule deleted",
    )
    expect_red(
        "clock epoch reuse rule deleted",
        deleted,
        "A -> B -> A is a Port contract violation",
    )


def main(argv: list[str]) -> int:
    usage = "usage: public_header_contract_gate.py {check|self-test|--check|--self-test}"
    if len(argv) != 2:
        print(usage, file=sys.stderr)
        return 2
    command = argv[1].removeprefix("--")
    try:
        if command == "check":
            validate(read_sources())
            print("public header contract gate: PASS")
        elif command == "self-test":
            self_test()
            print("public header contract gate self-test: PASS (4/4 mutations RED)")
        else:
            print(usage, file=sys.stderr)
            return 2
        return 0
    except (ContractError, OSError) as error:
        print(f"public header contract gate: FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
