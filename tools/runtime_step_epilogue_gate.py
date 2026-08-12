#!/usr/bin/env python3
"""Keep Runtime step re-entry cleanup on one structural exit."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import shlex
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/runtime/runtime_public.c"
TRIGRAPHS = {
    "??=": "#",
    "??/": "\\",
    "??'": "^",
    "??(": "[",
    "??)": "]",
    "??!": "|",
    "??<": "{",
    "??>": "}",
    "??-": "~",
}
INCLUDE_DIRS = (
    "include",
    "src",
    "src/model",
    "src/runtime",
    "src/runtime/mfdt_v1",
    "src/contract",
    "src/transport",
    "src/transport/fabric_v1",
    "src/radio",
    "src/runtime/route_relay_v1",
    "ports/posix",
)
TEST_TARGET_DEFINITIONS = (
    "NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN=1",
    "NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM=1",
    "NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1",
    "NINLIL_R7_CRYPTO_TEST_BUILD=1",
    "NINLIL_R7_WIRE_TEST_BUILD=1",
    "NINLIL_R7_BINDING_TEST_BUILD=1",
)
PROFILES = (
    ("default", ()),
    ("tests-default", TEST_TARGET_DEFINITIONS),
    (
        "tests-all-private",
        TEST_TARGET_DEFINITIONS
        + (
            "NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1",
            "NINLIL_ENABLE_PRIVATE_FABRIC_V1=1",
            "NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1",
            "NINLIL_MFDT_V1_PRIVATE=1",
        ),
    ),
)


def _translation_phase_1_2(text: str) -> str:
    """Normalize C11 trigraphs and line splices before lexical masking."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    for source, target in TRIGRAPHS.items():
        text = text.replace(source, target)
    return text.replace("\\\n", "")


def _mask_comments_and_literals(text: str) -> str:
    text = _translation_phase_1_2(text)
    out = list(text)
    index = 0
    state = "code"
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and next_char == "/":
                out[index] = out[index + 1] = " "
                index += 2
                state = "line"
                continue
            if char == "/" and next_char == "*":
                out[index] = out[index + 1] = " "
                index += 2
                state = "block"
                continue
            if char == '"':
                out[index] = " "
                state = "string"
            elif char == "'":
                out[index] = " "
                state = "char"
        elif state == "line":
            if char == "\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block":
            if char == "*" and next_char == "/":
                out[index] = out[index + 1] = " "
                index += 2
                state = "code"
                continue
            if char != "\n":
                out[index] = " "
        else:
            if char == "\\" and next_char:
                out[index] = " "
                if next_char != "\n":
                    out[index + 1] = " "
                index += 2
                continue
            if (state == "string" and char == '"') or (state == "char" and char == "'"):
                state = "code"
            if char != "\n":
                out[index] = " "
        index += 1
    if state in {"block", "string", "char"}:
        raise ValueError(f"unterminated C lexical state: {state}")
    masked = "".join(out)
    # C11 alternative punctuators are real braces to the compiler. Normalize
    # them after literal/comment masking so brace-depth checks see their
    # semantics and not their spelling.
    return masked.replace("<%", "{").replace("%>", "}")


def _compiler_command(compiler: str | None) -> list[str]:
    if compiler is not None:
        return [compiler]
    command = shlex.split(os.environ.get("CC", "cc"))
    if not command:
        raise ValueError("CC must name a C compiler")
    return command


def _preprocess(
    source: str,
    definitions: tuple[str, ...],
    compiler: str | None,
) -> str:
    command = [*_compiler_command(compiler), "-E", "-P", "-std=c11", "-x", "c"]
    for relative in INCLUDE_DIRS:
        command.extend(("-I", str(ROOT / relative)))
    command.extend(f"-D{definition}" for definition in definitions)
    command.append("-")
    result = subprocess.run(
        command,
        input=source,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.strip().splitlines()
        raise ValueError(
            "C preprocessing failed: " + (detail[-1] if detail else "unknown error")
        )
    return result.stdout


def _function_body(translation_unit: str) -> str:
    masked = _mask_comments_and_literals(translation_unit)
    definitions = list(
        re.finditer(
            r"\bninlil_status_t\s+ninlil_runtime_step\s*"
            r"\([^;{}]*\)\s*\{",
            masked,
            re.DOTALL,
        )
    )
    if len(definitions) != 1:
        raise ValueError(
            "preprocessed runtime_step definition must occur exactly once"
        )
    opening = definitions[0].end() - 1
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return masked[opening + 1:index]
    raise ValueError("preprocessed runtime_step definition is unterminated")


def _brace_depth(text: str, position: int) -> int:
    depth = 0
    for char in text[:position]:
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth


def _validate_profile(
    source: str,
    definitions: tuple[str, ...],
    compiler: str | None,
) -> list[str]:
    errors: list[str] = []
    try:
        body = _function_body(_preprocess(source, definitions, compiler))
    except ValueError as exc:
        return [str(exc)]

    set_pattern = re.compile(r"runtime\s*->\s*in_step\s*=\s*1u\s*;")
    clear_pattern = re.compile(r"runtime\s*->\s*in_step\s*=\s*0u\s*;")
    in_step_pattern = re.compile(r"runtime\s*->\s*in_step\b")
    member_pattern = re.compile(r"(?:->|\.)\s*in_step\b")
    label_pattern = re.compile(r"\bstep_exit\s*:")
    sets = list(set_pattern.finditer(body))
    clears = list(clear_pattern.finditer(body))
    in_step_uses = list(in_step_pattern.finditer(body))
    member_uses = list(member_pattern.finditer(body))
    labels = list(label_pattern.finditer(body))
    if len(sets) != 1:
        errors.append("runtime_step must set in_step exactly once")
    if len(clears) != 1:
        errors.append("runtime_step must clear in_step exactly once")
    if len(labels) != 1:
        errors.append("runtime_step must have exactly one step_exit label")
    if len(in_step_uses) != 2:
        errors.append("runtime_step must touch in_step only at entry and epilogue")
    if len(member_uses) != 2:
        errors.append("runtime_step must not access in_step through another receiver")
    if errors:
        return errors

    set_at = sets[0].start()
    label_at = labels[0].start()
    clear_at = clears[0].start()
    if [use.start() for use in in_step_uses] != [set_at, clear_at]:
        errors.append("runtime_step has an in_step access outside the closed pair")
    expected_member_positions = [
        body.find("->", set_at, sets[0].end()),
        body.find("->", clear_at, clears[0].end()),
    ]
    if [use.start() for use in member_uses] != expected_member_positions:
        errors.append("runtime_step in_step member accesses differ from the closed pair")
    if not (set_at < label_at < clear_at):
        errors.append("runtime_step epilogue order drift")
    for label, position in (
        ("in_step set", set_at),
        ("step_exit label", label_at),
        ("in_step clear", clear_at),
    ):
        if _brace_depth(body, position) != 0:
            errors.append(f"runtime_step {label} must be at function top level")

    entry = re.compile(
        r"runtime\s*->\s*in_step\s*=\s*1u\s*;\s*"
        r"runtime\s*->\s*step_phase\s*=\s*"
        r"NINLIL_RT_STEP_PHASE_CLOCK\s*;"
    )
    entries = list(entry.finditer(body))
    if len(entries) != 1 or entries[0].start() != set_at:
        errors.append("runtime_step entry must set in_step then CLOCK unconditionally")

    pre_entry = body[:set_at]
    if re.search(r"\bgoto\b", pre_entry):
        errors.append("runtime_step pre-entry validation must not jump around entry")
    if re.search(
        r"(?m)^[ \t]*(?!case\b|default\b)([A-Za-z_]\w*)[ \t]*:",
        pre_entry,
    ):
        errors.append("runtime_step pre-entry validation must not define labels")
    budget_guard = re.compile(
        r"if\s*\(\s*"
        r"ingress_budget\s*>\s*runtime\s*->\s*config\s*\.\s*limits\s*\.\s*"
        r"max_ingress_per_step\s*\|\|\s*"
        r"callback_budget\s*>\s*runtime\s*->\s*config\s*\.\s*limits\s*\.\s*"
        r"max_callbacks_per_step\s*\|\|\s*"
        r"transition_budget\s*>\s*runtime\s*->\s*config\s*\.\s*limits\s*\.\s*"
        r"max_state_transitions_per_step\s*\|\|\s*"
        r"send_budget\s*>\s*runtime\s*->\s*config\s*\.\s*limits\s*\.\s*"
        r"max_bearer_sends_per_step\s*\)\s*\{\s*"
        r"return\s+[^;{}]+\s*;\s*\}\s*$",
        re.DOTALL,
    )
    if budget_guard.search(pre_entry) is None:
        errors.append("runtime_step entry must immediately follow the closed budget guard")

    post_entry = body[set_at:]
    returns = list(re.finditer(r"\breturn\b", post_entry))
    if len(returns) != 1:
        errors.append("runtime_step must have exactly one return after entering in_step")
    gotos = re.findall(r"\bgoto\s+([A-Za-z_]\w*)\s*;", post_entry)
    if not gotos or any(target != "step_exit" for target in gotos):
        errors.append("every post-entry goto must target step_exit")

    before_label = body[:label_at].rstrip()
    if not re.search(r"goto\s+step_exit\s*;\s*$", before_label):
        errors.append("runtime_step normal path must explicitly enter step_exit")

    epilogue = body[label_at:]
    exact_epilogue = re.compile(
        r"\s*step_exit\s*:\s*"
        r"runtime\s*->\s*in_step\s*=\s*0u\s*;\s*"
        r"runtime\s*->\s*step_phase\s*=\s*NINLIL_RT_STEP_PHASE_IDLE\s*;\s*"
        r"out_result\s*->\s*health\s*=\s*runtime\s*->\s*health\s*;\s*"
        r"out_result\s*->\s*degraded_reason\s*=\s*"
        r"runtime\s*->\s*degraded_reason\s*;\s*"
        r"return\s+status\s*;\s*",
        re.DOTALL,
    )
    if exact_epilogue.fullmatch(epilogue) is None:
        errors.append("runtime_step epilogue must be the closed cleanup sequence")

    nonlocal_exit = re.search(
        r"\b(?:longjmp|siglongjmp|exit|_Exit|quick_exit|abort|thrd_exit|pthread_exit)\s*\(",
        post_entry,
    )
    if nonlocal_exit is not None:
        errors.append("runtime_step post-entry path uses a nonlocal process/thread exit")
    return errors


def _profiles(
    configured_definitions: tuple[str, ...],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    if not configured_definitions:
        return PROFILES
    return PROFILES + (("configured-runtime-private", configured_definitions),)


def validate(
    source: str,
    compiler: str | None = None,
    configured_definitions: tuple[str, ...] = (),
) -> list[str]:
    errors: list[str] = []
    for profile, definitions in _profiles(configured_definitions):
        errors.extend(
            f"{profile}: {error}"
            for error in _validate_profile(source, definitions, compiler)
        )
    return errors


def self_test(
    compiler: str | None = None,
    configured_definitions: tuple[str, ...] = (),
) -> None:
    baseline = SOURCE.read_text(encoding="utf-8")
    if validate(baseline, compiler, configured_definitions):
        raise RuntimeError("repository runtime_step baseline is invalid")
    conditional_mutation = baseline.replace(
        "#define NINLIL_RT_SERVICE_MAGIC",
        "#if defined(NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM)\n"
        "#define STEP_TEST_ROUTE() return status\n"
        "#else\n"
        "#define STEP_TEST_ROUTE() goto step_exit\n"
        "#endif\n"
        "#define NINLIL_RT_SERVICE_MAGIC",
        1,
    ).replace("goto step_exit;", "STEP_TEST_ROUTE();", 1)
    mutations = [
        baseline.replace("goto step_exit;", "return status;", 1),
        baseline.replace("goto step_exit;", "ret\\\nurn status;", 1),
        baseline.replace("goto step_exit;", "ret??/\nurn status;", 1),
        baseline.replace("goto step_exit;", "goto bypass_cleanup;", 1).replace(
            "return status;\n}\n\nninlil_status_t ninlil_offer_accept(",
            "return status;\n\nbypass_cleanup:\n    return status;\n}"
            "\n\nninlil_status_t ninlil_offer_accept(",
            1,
        ),
        baseline.replace(
            "runtime->in_step = 0u;",
            "if (status == NINLIL_OK) { runtime->in_step = 0u; }",
            1,
        ),
        baseline.replace(
            "runtime->in_step = 0u;",
            "#if 0\n    runtime->in_step = 0u;\n#endif",
            1,
        ),
        baseline.replace(
            "#define NINLIL_RT_SERVICE_MAGIC",
            "#define STEP_EARLY_RETURN() return status\n"
            "#define NINLIL_RT_SERVICE_MAGIC",
            1,
        ).replace("goto step_exit;", "STEP_EARLY_RETURN();", 1),
        baseline.replace("runtime->in_step = 0u;", "", 1),
        baseline.replace(
            "runtime->in_step = 0u;",
            "runtime->in_step = 0u;\n    runtime->in_step = 0u;",
            1,
        ),
        baseline.replace("return status;\n}\n\nninlil_status_t ninlil_offer_accept(",
                         "return NINLIL_OK;\n}\n\nninlil_status_t ninlil_offer_accept(", 1),
        baseline.replace(
            "goto step_exit;",
            "abort();",
            1,
        ),
        baseline.replace(
            "runtime->in_step = 1u;",
            "if (runtime->pending_work != 0u) runtime->in_step = 1u;",
            1,
        ),
        baseline.replace(
            "runtime->in_step = 1u;",
            "if (runtime->pending_work != 0u) <%\n"
            "        runtime->in_step = 1u;\n"
            "    %>",
            1,
        ),
        baseline.replace(
            "runtime->in_step = 1u;\n"
            "    runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;",
            "goto after_step_entry;\n"
            "    runtime->in_step = 1u;\n"
            "after_step_entry:\n"
            "    runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;",
            1,
        ),
        baseline.replace(
            "runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;",
            "runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;\n"
            "    runtime->in_step = 0;",
            1,
        ),
        baseline.replace(
            "runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;",
            "runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;\n"
            "    ninlil_runtime_t *alias = runtime;\n"
            "    alias->in_step = 0u;",
            1,
        ),
        baseline.replace(
            "runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;",
            "runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;\n"
            "    runtime->in_step--;",
            1,
        ),
    ]
    for index, mutation in enumerate(mutations):
        if mutation == baseline:
            raise RuntimeError(f"runtime_step epilogue mutation {index} did not apply")
        for profile, definitions in _profiles(configured_definitions):
            if not _validate_profile(mutation, definitions, compiler):
                raise RuntimeError(
                    f"runtime_step epilogue mutation {index} was accepted "
                    f"by profile {profile}"
                )
    if conditional_mutation == baseline:
        raise RuntimeError("conditional target-profile mutation did not apply")
    for profile, definitions in _profiles(configured_definitions):
        rejected = bool(_validate_profile(conditional_mutation, definitions, compiler))
        active = "NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM=1" in definitions
        if rejected != active:
            outcome = "rejected" if rejected else "accepted"
            expectation = "RED" if active else "GREEN"
            raise RuntimeError(
                "conditional target-profile mutation was "
                f"{outcome} by {profile}; expected {expectation}"
            )
    print(
        "runtime step epilogue gate self-test: "
        f"ok ({len(mutations)} all-profile mutations x "
        f"{len(_profiles(configured_definitions))} profiles + "
        "1 conditional profile matrix)"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    parser.add_argument("--cc")
    parser.add_argument("--define", action="append", default=[])
    args = parser.parse_args()
    configured_definitions = tuple(args.define)
    if args.command == "self-test":
        self_test(args.cc, configured_definitions)
        return 0
    errors = validate(
        SOURCE.read_text(encoding="utf-8"),
        args.cc,
        configured_definitions,
    )
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print("runtime step epilogue gate: single cleanup exit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
