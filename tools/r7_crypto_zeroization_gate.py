#!/usr/bin/env python3
"""Structural gate for the R7 portable crypto zeroization contract.

This gate deliberately inspects only function bodies.  Its C lexer masks
comments and literals before matching braces, so a marker in a comment,
string, another function, or trailing text cannot satisfy a requirement.

Authority: docs/31-r7-crypto-provider-and-aead.md sections 7, 9, and 11.
This is structural evidence; it does not claim runtime memory observation.
"""

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import re
import sys
from collections.abc import Sequence


REPO = pathlib.Path(__file__).resolve().parents[1]
PORTABLE_PATH = REPO / "src" / "radio" / "r7_crypto_portable.c"
NONCE_PATH = REPO / "src" / "radio" / "r7_crypto_nonce.c"


class GateError(RuntimeError):
    """Raised when a source cannot be parsed safely enough for this gate."""


@dataclasses.dataclass(frozen=True)
class FunctionBody:
    """A C function definition's body, including its outer braces."""

    name: str
    start: int
    end: int
    text: str


@dataclasses.dataclass(frozen=True)
class Requirement:
    """One independently removable structural zeroization marker."""

    marker_id: str
    source_name: str
    function_name: str
    pattern: re.Pattern[str]
    description: str


@dataclasses.dataclass(frozen=True)
class CleanupContract:
    """One wrapper whose post-copy region must have one cleanup exit."""

    contract_id: str
    source_name: str
    function_name: str
    boundary_pattern: re.Pattern[str]
    operation_pattern: re.Pattern[str]


def _mask_c_comments_and_literals(
    source: str, *, preserve_memory_literal: bool = False
) -> str:
    """Mask C comments and literals while preserving offsets and newlines.

    ``"memory"`` may be retained as a narrowly allowed compiler-barrier token.
    All other string and character literals remain masked, so marker-looking
    text inside a literal cannot satisfy a structural requirement.
    """

    chars = list(source)
    masked = list(source)
    state = "code"
    literal_start = -1
    i = 0

    def erase(index: int) -> None:
        if chars[index] not in "\r\n":
            masked[index] = " "

    while i < len(chars):
        ch = chars[i]
        nxt = chars[i + 1] if i + 1 < len(chars) else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                erase(i)
                erase(i + 1)
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                erase(i)
                erase(i + 1)
                state = "block_comment"
                i += 2
                continue
            if ch == '"':
                erase(i)
                literal_start = i
                state = "string"
                i += 1
                continue
            if ch == "'":
                erase(i)
                literal_start = i
                state = "char"
                i += 1
                continue
            i += 1
            continue

        if state == "line_comment":
            erase(i)
            if ch in "\r\n":
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            erase(i)
            if ch == "*" and nxt == "/":
                erase(i + 1)
                state = "code"
                i += 2
            else:
                i += 1
            continue

        if state in ("string", "char"):
            erase(i)
            if ch == "\\":
                if i + 1 < len(chars):
                    erase(i + 1)
                    i += 2
                else:
                    i += 1
                continue
            if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                if (
                    preserve_memory_literal
                    and state == "string"
                    and source[literal_start : i + 1] == '"memory"'
                ):
                    masked[literal_start : i + 1] = chars[literal_start : i + 1]
                state = "code"
                literal_start = -1
            i += 1
            continue

        raise AssertionError(f"unexpected lexer state: {state}")

    if state in ("block_comment", "string", "char"):
        raise GateError(f"unterminated C lexical construct: {state}")
    return "".join(masked)


def _matching_delimiter(masked: str, opening: int, left: str, right: str) -> int:
    if opening >= len(masked) or masked[opening] != left:
        raise GateError(f"expected {left!r} at offset {opening}")
    depth = 0
    for i in range(opening, len(masked)):
        if masked[i] == left:
            depth += 1
        elif masked[i] == right:
            depth -= 1
            if depth == 0:
                return i
            if depth < 0:
                break
    raise GateError(f"unmatched {left!r} at offset {opening}")


def extract_function_body(source: str, function_name: str) -> FunctionBody:
    """Extract exactly one named C function definition with brace awareness."""

    masked = _mask_c_comments_and_literals(source)
    name_rx = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    definitions: list[FunctionBody] = []

    for match in name_rx.finditer(masked):
        open_paren = masked.find("(", match.start(), match.end())
        close_paren = _matching_delimiter(masked, open_paren, "(", ")")
        cursor = close_paren + 1
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        if cursor >= len(masked) or masked[cursor] != "{":
            continue
        close_brace = _matching_delimiter(masked, cursor, "{", "}")
        definitions.append(
            FunctionBody(
                name=function_name,
                start=cursor,
                end=close_brace + 1,
                text=source[cursor : close_brace + 1],
            )
        )

    if len(definitions) != 1:
        raise GateError(
            f"{function_name}: expected exactly one definition, got {len(definitions)}"
        )
    return definitions[0]


def _secure_zero_call(variable: str) -> re.Pattern[str]:
    return re.compile(
        rf"\bninlil_r7_crypto_secure_zero\s*\(\s*{re.escape(variable)}\s*,"
        rf"\s*sizeof\s*\(\s*{re.escape(variable)}\s*\)\s*\)\s*;",
        re.DOTALL,
    )


def _copy_to_call(variable: str) -> re.Pattern[str]:
    return re.compile(
        rf"\bninlil_r7_crypto_copy\s*\(\s*{re.escape(variable)}\s*,",
        re.DOTALL,
    )


def _provider_operation(callback: str) -> re.Pattern[str]:
    return re.compile(
        rf"\braw\s*=\s*provider\s*->\s*{re.escape(callback)}\s*\(",
        re.DOTALL,
    )


def _nonce_volatile_wipe(variable: str) -> re.Pattern[str]:
    """Match assignment to a volatile byte view followed by its zero loop."""

    return re.compile(
        rf"\bv\s*=\s*\(\s*volatile\s+uint8_t\s*\*\s*\)\s*"
        rf"{re.escape(variable)}\s*;\s*"
        rf"for\s*\(\s*k\s*=\s*0u?\s*;\s*k\s*<\s*"
        rf"sizeof\s*\(\s*{re.escape(variable)}\s*\)\s*;\s*k\+\+\s*\)\s*"
        rf"\{{\s*v\s*\[\s*k\s*\]\s*=\s*0u?\s*;\s*\}}",
        re.DOTALL,
    )


SECURE_ZERO_FUNCTION = "ninlil_r7_crypto_secure_zero"

REQUIREMENTS: tuple[Requirement, ...] = (
    Requirement(
        "secure-zero.volatile-byte-view",
        "portable",
        SECURE_ZERO_FUNCTION,
        re.compile(
            r"\bvolatile\s+uint8_t\s*\*\s*v\s*=\s*"
            r"\(\s*volatile\s+uint8_t\s*\*\s*\)\s*p\s*;",
            re.DOTALL,
        ),
        "secure-zero helper must write through a volatile uint8_t pointer",
    ),
    Requirement(
        "secure-zero.byte-store",
        "portable",
        SECURE_ZERO_FUNCTION,
        re.compile(
            r"\bfor\s*\(\s*i\s*=\s*0u?\s*;\s*i\s*<\s*n\s*;\s*i\+\+\s*\)"
            r"\s*\{\s*v\s*\[\s*i\s*\]\s*=\s*0u?\s*;\s*\}",
            re.DOTALL,
        ),
        "secure-zero helper must wipe every byte in the exact 0..n-1 loop",
    ),
    Requirement(
        "secure-zero.compiler-barrier",
        "portable",
        SECURE_ZERO_FUNCTION,
        re.compile(
            r"\batomic_signal_fence\s*\(\s*memory_order_seq_cst\s*\)\s*;",
            re.DOTALL,
        ),
        "secure-zero helper must end with an exact seq_cst compiler fence",
    ),
    Requirement(
        "sha256.zero.candidate",
        "portable",
        "ninlil_r7_crypto_sha256",
        _secure_zero_call("candidate"),
        "SHA-256 candidate must be securely zeroed exactly once",
    ),
    Requirement(
        "sha256.zero.msg-copy",
        "portable",
        "ninlil_r7_crypto_sha256",
        _secure_zero_call("msg_copy"),
        "SHA-256 input copy must be securely zeroed exactly once",
    ),
    Requirement(
        "hkdf-extract.zero.candidate",
        "portable",
        "ninlil_r7_crypto_hkdf_extract_sha256",
        _secure_zero_call("candidate"),
        "HKDF-Extract candidate must be securely zeroed exactly once",
    ),
    Requirement(
        "hkdf-extract.zero.salt-copy",
        "portable",
        "ninlil_r7_crypto_hkdf_extract_sha256",
        _secure_zero_call("salt_copy"),
        "HKDF-Extract salt copy must be securely zeroed exactly once",
    ),
    Requirement(
        "hkdf-extract.zero.ikm-copy",
        "portable",
        "ninlil_r7_crypto_hkdf_extract_sha256",
        _secure_zero_call("ikm_copy"),
        "HKDF-Extract IKM copy must be securely zeroed exactly once",
    ),
    Requirement(
        "hkdf-expand.zero.candidate",
        "portable",
        "ninlil_r7_crypto_hkdf_expand_sha256",
        _secure_zero_call("candidate"),
        "HKDF-Expand candidate must be securely zeroed exactly once",
    ),
    Requirement(
        "hkdf-expand.zero.prk-copy",
        "portable",
        "ninlil_r7_crypto_hkdf_expand_sha256",
        _secure_zero_call("prk_copy"),
        "HKDF-Expand PRK copy must be securely zeroed exactly once",
    ),
    Requirement(
        "hkdf-expand.zero.info-copy",
        "portable",
        "ninlil_r7_crypto_hkdf_expand_sha256",
        _secure_zero_call("info_copy"),
        "HKDF-Expand info copy must be securely zeroed exactly once",
    ),
    Requirement(
        "seal.zero.candidate",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_seal",
        _secure_zero_call("candidate"),
        "Seal candidate must be securely zeroed exactly once",
    ),
    Requirement(
        "seal.zero.key-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_seal",
        _secure_zero_call("key_copy"),
        "Seal key copy must be securely zeroed exactly once",
    ),
    Requirement(
        "seal.zero.nonce-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_seal",
        _secure_zero_call("nonce_copy"),
        "Seal nonce copy must be securely zeroed exactly once",
    ),
    Requirement(
        "seal.zero.aad-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_seal",
        _secure_zero_call("aad_copy"),
        "Seal AAD copy must be securely zeroed exactly once",
    ),
    Requirement(
        "seal.zero.pt-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_seal",
        _secure_zero_call("pt_copy"),
        "Seal plaintext copy must be securely zeroed exactly once",
    ),
    Requirement(
        "open.zero.candidate",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_open",
        _secure_zero_call("candidate"),
        "Open candidate must be securely zeroed exactly once",
    ),
    Requirement(
        "open.zero.key-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_open",
        _secure_zero_call("key_copy"),
        "Open key copy must be securely zeroed exactly once",
    ),
    Requirement(
        "open.zero.nonce-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_open",
        _secure_zero_call("nonce_copy"),
        "Open nonce copy must be securely zeroed exactly once",
    ),
    Requirement(
        "open.zero.aad-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_open",
        _secure_zero_call("aad_copy"),
        "Open AAD copy must be securely zeroed exactly once",
    ),
    Requirement(
        "open.zero.sealed-copy",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_open",
        _secure_zero_call("sealed_copy"),
        "Open sealed-input copy must be securely zeroed exactly once",
    ),
    Requirement(
        "nonce.zero.work",
        "nonce",
        "ninlil_r7_crypto_nonce_from_counter",
        _nonce_volatile_wipe("work"),
        "nonce work buffer must be wiped through a volatile byte view",
    ),
    Requirement(
        "nonce.zero.ctr-be",
        "nonce",
        "ninlil_r7_crypto_nonce_from_counter",
        _nonce_volatile_wipe("ctr_be"),
        "nonce counter buffer must be wiped through a volatile byte view",
    ),
)


CLEANUP_CONTRACTS: tuple[CleanupContract, ...] = (
    CleanupContract(
        "sha256",
        "portable",
        "ninlil_r7_crypto_sha256",
        _copy_to_call("msg_copy"),
        _provider_operation("sha256"),
    ),
    CleanupContract(
        "hkdf-extract",
        "portable",
        "ninlil_r7_crypto_hkdf_extract_sha256",
        _copy_to_call("salt_copy"),
        _provider_operation("hkdf_extract_sha256"),
    ),
    CleanupContract(
        "hkdf-expand",
        "portable",
        "ninlil_r7_crypto_hkdf_expand_sha256",
        _copy_to_call("prk_copy"),
        _provider_operation("hkdf_expand_sha256"),
    ),
    CleanupContract(
        "seal",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_seal",
        _copy_to_call("key_copy"),
        _provider_operation("aes128_gcm_seal"),
    ),
    CleanupContract(
        "open",
        "portable",
        "ninlil_r7_crypto_aes128_gcm_open",
        _copy_to_call("key_copy"),
        _provider_operation("aes128_gcm_open"),
    ),
)


def _read_sources() -> dict[str, str]:
    paths = {"portable": PORTABLE_PATH, "nonce": NONCE_PATH}
    sources: dict[str, str] = {}
    for name, path in paths.items():
        try:
            sources[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise GateError(f"cannot read {path.relative_to(REPO)}: {exc}") from exc
    return sources


def _requirement_matches(
    requirement: Requirement, sources: dict[str, str]
) -> tuple[FunctionBody, list[re.Match[str]]]:
    body = extract_function_body(
        sources[requirement.source_name], requirement.function_name
    )
    masked_body = _mask_c_comments_and_literals(
        body.text, preserve_memory_literal=True
    )
    return body, list(requirement.pattern.finditer(masked_body))


def _brace_depth_at(masked: str, position: int) -> int:
    """Return lexical brace depth immediately before ``position``."""

    depth = 0
    for ch in masked[:position]:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                raise GateError("brace depth became negative")
    return depth


def _previous_code_character(masked: str, position: int) -> str:
    cursor = position - 1
    while cursor >= 0 and masked[cursor].isspace():
        cursor -= 1
    return masked[cursor] if cursor >= 0 else ""


def _validate_cleanup_contract(
    contract: CleanupContract, sources: dict[str, str]
) -> list[str]:
    """Validate reachable, direct cleanup followed by the only post-copy return."""

    marker = f"control.{contract.contract_id}"
    errors: list[str] = []
    try:
        body = extract_function_body(
            sources[contract.source_name], contract.function_name
        )
    except GateError as exc:
        return [f"{marker}: parse failure: {exc}"]
    masked = _mask_c_comments_and_literals(body.text)

    boundaries = list(contract.boundary_pattern.finditer(masked))
    operations = list(contract.operation_pattern.finditer(masked))
    if len(boundaries) != 1:
        errors.append(
            f"{marker}: expected exactly one post-copy boundary, got {len(boundaries)}"
        )
    if len(operations) != 1:
        errors.append(
            f"{marker}: expected exactly one provider operation, got {len(operations)}"
        )
    if len(boundaries) != 1 or len(operations) != 1:
        return errors

    boundary_end = boundaries[0].end()
    operation_end = operations[0].end()
    if operation_end <= boundary_end:
        errors.append(f"{marker}: provider operation must follow the first bounded copy")

    cleanup_requirements = [
        requirement
        for requirement in REQUIREMENTS
        if requirement.source_name == contract.source_name
        and requirement.function_name == contract.function_name
        and ".zero." in requirement.marker_id
    ]
    cleanup_positions: list[int] = []
    for requirement in cleanup_requirements:
        matches = list(requirement.pattern.finditer(masked))
        if len(matches) != 1:
            errors.append(
                f"{marker}: {requirement.marker_id} must occur exactly once for control-flow audit"
            )
            continue
        match = matches[0]
        cleanup_positions.append(match.start())
        try:
            depth = _brace_depth_at(masked, match.start())
        except GateError as exc:
            errors.append(f"{marker}: {requirement.marker_id}: {exc}")
            continue
        if depth != 1:
            errors.append(
                f"{marker}: {requirement.marker_id} must be an unconditional function-body statement"
            )
        line_start = masked.rfind("\n", 0, match.start()) + 1
        if masked[line_start : match.start()].strip():
            errors.append(
                f"{marker}: {requirement.marker_id} has a same-line control prefix"
            )
        previous = _previous_code_character(masked, match.start())
        if previous not in (";", "{", "}"):
            errors.append(
                f"{marker}: {requirement.marker_id} is controlled by a preceding expression"
            )
        if match.start() <= operation_end:
            errors.append(
                f"{marker}: {requirement.marker_id} occurs before the provider operation completes"
            )

    if cleanup_positions != sorted(cleanup_positions):
        errors.append(f"{marker}: cleanup calls are not in their required stable order")

    return_rx = re.compile(r"\breturn\b[^;{}]*;", re.DOTALL)
    post_copy_returns = [
        match for match in return_rx.finditer(masked) if match.start() > boundary_end
    ]
    if len(post_copy_returns) != 1:
        errors.append(
            f"{marker}: post-copy region must contain exactly one return, "
            f"got {len(post_copy_returns)}"
        )
        return errors

    final_return = post_copy_returns[0]
    try:
        return_depth = _brace_depth_at(masked, final_return.start())
    except GateError as exc:
        errors.append(f"{marker}: final return: {exc}")
        return errors
    if return_depth != 1:
        errors.append(f"{marker}: the only post-copy return must be top-level")
    if any(position >= final_return.start() for position in cleanup_positions):
        errors.append(f"{marker}: every cleanup call must precede the final return")
    if re.search(r"\bgoto\b", masked[boundary_end : final_return.start()]):
        errors.append(f"{marker}: goto is forbidden in the post-copy cleanup region")
    if masked[final_return.end() : -1].strip():
        errors.append(f"{marker}: executable text follows the final return")
    return errors


def _validate_cleanup_control_flow(sources: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for contract in CLEANUP_CONTRACTS:
        errors.extend(_validate_cleanup_contract(contract, sources))
    return errors


def validate_sources(sources: dict[str, str]) -> list[str]:
    """Return stable marker-specific diagnostics for all violations."""

    errors: list[str] = []
    for requirement in REQUIREMENTS:
        try:
            _body, matches = _requirement_matches(requirement, sources)
        except GateError as exc:
            errors.append(f"{requirement.marker_id}: parse failure: {exc}")
            continue
        if len(matches) != 1:
            errors.append(
                f"{requirement.marker_id}: {requirement.description}; "
                f"expected exactly 1 marker, got {len(matches)}"
            )
    errors.extend(_validate_cleanup_control_flow(sources))
    return errors


def _delete_one_marker(
    sources: dict[str, str], requirement: Requirement
) -> dict[str, str]:
    """Delete one exact in-function marker from an in-memory source copy."""

    body, matches = _requirement_matches(requirement, sources)
    if len(matches) != 1:
        raise GateError(
            f"{requirement.marker_id}: mutation setup expected one marker, got {len(matches)}"
        )
    match = matches[0]
    absolute_start = body.start + match.start()
    absolute_end = body.start + match.end()
    mutated = dict(sources)
    text = sources[requirement.source_name]
    mutated[requirement.source_name] = text[:absolute_start] + text[absolute_end:]
    return mutated


def _comment_out_one_marker(
    sources: dict[str, str], requirement: Requirement
) -> dict[str, str]:
    """Comment out one exact marker in memory; it must no longer count as code."""

    body, matches = _requirement_matches(requirement, sources)
    if len(matches) != 1:
        raise GateError(
            f"{requirement.marker_id}: mutation setup expected one marker, got {len(matches)}"
        )
    match = matches[0]
    absolute_start = body.start + match.start()
    absolute_end = body.start + match.end()
    mutated = dict(sources)
    text = sources[requirement.source_name]
    marker = text[absolute_start:absolute_end]
    if "*/" in marker:
        raise GateError(
            f"{requirement.marker_id}: marker cannot be safely comment-mutated"
        )
    mutated[requirement.source_name] = (
        text[:absolute_start] + "/*" + marker + "*/" + text[absolute_end:]
    )
    return mutated


def _brace_extractor_self_test() -> list[str]:
    errors: list[str] = []
    fixture = r'''
int decoy(void) { return 0; }
int target(int x) {
    const char *s = "literal } {";
    char c = '}';
    /* comment } { */
    // line comment }
    if (x) { x--; }
    return x;
}
'''
    try:
        body = extract_function_body(fixture, "target")
    except GateError as exc:
        return [f"brace-extractor: valid fixture rejected: {exc}"]
    if "return x;" not in body.text or "decoy" in body.text:
        errors.append("brace-extractor: wrong function extent")
    try:
        extract_function_body("int broken(void) { return 0;", "broken")
    except GateError:
        pass
    else:
        errors.append("brace-extractor: unmatched brace fixture was accepted")
    return errors


def _replace_once(
    sources: dict[str, str],
    source_name: str,
    old: str,
    new: str,
    mutation_name: str,
) -> tuple[dict[str, str], str | None]:
    text = sources[source_name]
    count = text.count(old)
    if count != 1:
        return sources, (
            f"semantic mutation {mutation_name}: expected one setup token, got {count}"
        )
    mutated = dict(sources)
    mutated[source_name] = text.replace(old, new, 1)
    return mutated, None


def _semantic_mutation_self_test(sources: dict[str, str]) -> list[str]:
    """Mutations that retain marker text but must still fail the stronger gate."""

    cleanup = "    ninlil_r7_crypto_secure_zero(candidate, sizeof(candidate));"
    sha_cleanup_prefix = (
        cleanup
        + "\n    ninlil_r7_crypto_secure_zero(msg_copy, sizeof(msg_copy));"
    )
    mutations = (
        (
            "zero-loop-bound",
            "portable",
            "for (i = 0u; i < n; i++) {\n        v[i] = 0u;\n    }",
            "for (i = 0u; i < 0u; i++) {\n        v[i] = 0u;\n    }",
            "secure-zero.byte-store:",
        ),
        (
            "relaxed-fence",
            "portable",
            "atomic_signal_fence(memory_order_seq_cst);",
            "atomic_signal_fence(memory_order_relaxed);",
            "secure-zero.compiler-barrier:",
        ),
        (
            "dead-cleanup",
            "portable",
            sha_cleanup_prefix,
            "    if (0) { ninlil_r7_crypto_secure_zero(candidate, sizeof(candidate)); }\n"
            "    ninlil_r7_crypto_secure_zero(msg_copy, sizeof(msg_copy));",
            "control.sha256:",
        ),
        (
            "post-copy-bypass",
            "portable",
            sha_cleanup_prefix,
            "    if (st != NINLIL_R7_CRYPTO_OK) { return st; }\n"
            + sha_cleanup_prefix,
            "control.sha256:",
        ),
    )
    errors: list[str] = []
    for name, source_name, old, new, expected_prefix in mutations:
        mutated, setup_error = _replace_once(
            sources, source_name, old, new, name
        )
        if setup_error is not None:
            errors.append(setup_error)
            continue
        mutation_errors = validate_sources(mutated)
        if not any(error.startswith(expected_prefix) for error in mutation_errors):
            errors.append(
                f"semantic mutation {name}: weakened source passed without "
                f"{expected_prefix.rstrip(':')} rejection"
            )
    return errors


def run_check() -> int:
    try:
        sources = _read_sources()
        errors = validate_sources(sources)
    except GateError as exc:
        errors = [str(exc)]
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        print(f"r7 crypto zeroization gate: FAIL ({len(errors)} violation(s))")
        return 1
    print(f"r7 crypto zeroization gate: PASS ({len(REQUIREMENTS)} markers)")
    return 0


def run_self_test() -> int:
    try:
        sources = _read_sources()
        baseline_errors = validate_sources(sources)
    except GateError as exc:
        baseline_errors = [str(exc)]
        sources = {}

    errors = _brace_extractor_self_test()
    if baseline_errors:
        errors.extend(f"baseline: {error}" for error in baseline_errors)
    else:
        errors.extend(_semantic_mutation_self_test(sources))
        for requirement in REQUIREMENTS:
            try:
                deleted = _delete_one_marker(sources, requirement)
                deletion_errors = validate_sources(deleted)
                commented = _comment_out_one_marker(sources, requirement)
                comment_errors = validate_sources(commented)
            except GateError as exc:
                errors.append(f"{requirement.marker_id}: mutation setup failed: {exc}")
                continue
            if not any(
                error.startswith(f"{requirement.marker_id}:")
                for error in deletion_errors
            ):
                errors.append(
                    f"{requirement.marker_id}: deleting its in-memory marker did not fail validation"
                )
            if not any(
                error.startswith(f"{requirement.marker_id}:")
                for error in comment_errors
            ):
                errors.append(
                    f"{requirement.marker_id}: commenting out its in-memory marker did not fail validation"
                )

    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        print(f"r7 crypto zeroization self-test: FAIL ({len(errors)} violation(s))")
        return 1
    print(
        "r7 crypto zeroization self-test: PASS "
        f"({len(REQUIREMENTS)} deletions + "
        f"{len(REQUIREMENTS)} comment-outs + 4 semantic mutations rejected)"
    )
    return 0


def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Check R7 portable crypto structural zeroization evidence."
    )
    parser.add_argument("command", choices=("check", "self-test"))
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "check":
        return run_check()
    return run_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
