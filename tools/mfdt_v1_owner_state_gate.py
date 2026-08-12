#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Reject mutable process-global state in private MFDT production sources."""

from __future__ import annotations

import argparse
import pathlib
import re
import tempfile


REPO = pathlib.Path(__file__).resolve().parents[1]
SOURCE_DIR = pathlib.Path("src/runtime/mfdt_v1")
SOURCE_GLOBS = (
    "src/runtime/mfdt_v1/*.[ch]",
    "ports/esp-idf/src/mfdt_v1*.[ch]",
)

# Scan every real `static` token, including function-local declarations.  The
# source is first blanked for comments and literals so text cannot impersonate
# a declaration.  Each start is classified below; only a true function
# declaration/definition or a const, non-pointer object is exempt.
COMMENT_OR_LITERAL = re.compile(
    r'(?ms)/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
)
STATIC_TOKEN = re.compile(r"\bstatic\b")
LINE_SPLICE = re.compile(r"\\[ \t\v\f]*\n")
TOKEN_PASTE = re.compile(r"##|%:%:")
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
C_TYPE_WORDS = {
    "auto", "char", "const", "double", "enum", "extern", "float", "inline",
    "int", "long", "register", "restrict", "short", "signed", "static",
    "struct", "typedef", "union", "unsigned", "void", "volatile",
    "_Atomic", "_Bool", "_Complex", "_Imaginary", "_Noreturn",
}


def blank_comments_and_literals(text: str) -> str:
    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group(0))

    return COMMENT_OR_LITERAL.sub(blank, text)


def apply_translation_phases_1_and_2(text: str) -> str:
    """Apply the C11 source transformations that can form a `static` token."""
    translated = text.replace("\r\n", "\n").replace("\r", "\n")
    for trigraph, replacement in TRIGRAPHS.items():
        translated = translated.replace(trigraph, replacement)
    return LINE_SPLICE.sub("", translated)


def ambiguous_preprocessor_constructs(text: str) -> list[str]:
    translated = apply_translation_phases_1_and_2(text)
    cleaned = blank_comments_and_literals(translated)
    if TOKEN_PASTE.search(cleaned) is not None:
        # Expanding arbitrary macros would make this gate compiler/toolchain
        # dependent. MFDT production sources do not need token pasting, so its
        # presence is rejected rather than guessed at.
        return ["token-paste operator may synthesize file-static storage"]
    return []


def true_function_declarator(declaration: str) -> bool:
    """Recognize an ordinary C function prototype/definition, not an object."""
    # Postfix attributes and macro-expanded declarators are deliberately not
    # guessed here: an ambiguous file-static declaration must fail closed.
    if "__attribute__" in declaration or declaration.lstrip().startswith("#"):
        return False
    opening = declaration.find("(")
    if opening < 0:
        return False
    prefix = declaration[:opening]
    if "=" in prefix or "[" in prefix:
        return False
    name_match = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
    if name_match is None or name_match.group(1) in C_TYPE_WORDS:
        return False

    depth = 0
    closing = -1
    for index in range(opening, len(declaration)):
        char = declaration[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                closing = index
                break
    if closing < 0:
        return False
    suffix = declaration[closing + 1:].lstrip()
    return suffix.startswith(";") or suffix.startswith("{")


def immutable_const_object(declaration: str) -> bool:
    head = declaration.split("=", 1)[0]
    return re.search(r"\bconst\b", head) is not None and "*" not in head


def mutable_static_declarations(text: str) -> list[str]:
    cleaned = blank_comments_and_literals(apply_translation_phases_1_and_2(text))
    found: list[str] = []
    for match in STATIC_TOKEN.finditer(cleaned):
        line_start = cleaned.rfind("\n", 0, match.start()) + 1
        if cleaned[line_start:match.start()].lstrip().startswith("#"):
            found.append(" ".join(cleaned[line_start:].split()))
            continue
        semicolon = cleaned.find(";", match.end())
        if semicolon < 0:
            declaration = cleaned[match.start():]
        else:
            declaration = cleaned[match.start():semicolon + 1]
        if true_function_declarator(declaration):
            continue
        if immutable_const_object(declaration):
            continue
        found.append(" ".join(declaration.split()))
    return found


def check(root: pathlib.Path) -> None:
    source_root = root / SOURCE_DIR
    failures: list[str] = []
    source_paths = sorted(
        {path for pattern in SOURCE_GLOBS for path in root.glob(pattern)}
    )
    for path in source_paths:
        text = path.read_text(encoding="utf-8")
        for issue in ambiguous_preprocessor_constructs(text):
            failures.append(f"{path.relative_to(root)}: {issue}")
        for declaration in mutable_static_declarations(text):
            failures.append(f"{path.relative_to(root)}: {declaration}")
    if failures:
        raise SystemExit(
            "mfdt_v1_owner_state_gate FAIL: mutable static object(s):\n  "
            + "\n  ".join(failures)
        )

    store = (source_root / "mfdt_v1_store_esp.c").read_text(encoding="utf-8")
    wire = (source_root / "mfdt_v1_wire.c").read_text(encoding="utf-8")
    required = (
        "ninlil_mfdt_v1_esp_store_bind(ninlil_mfdt_v1_lab_store_t *st",
        "ninlil_mfdt_v1_lab_store_fini",
        "st->esp.readback",
        "st->esp.old_pool",
    )
    missing = [token for token in required if token not in store]
    if missing:
        raise SystemExit(
            "mfdt_v1_owner_state_gate FAIL: owner seam missing: "
            + ", ".join(missing)
        )
    if "Use the caller's final 972-byte output as the 951-byte digest preimage" not in wire:
        raise SystemExit(
            "mfdt_v1_owner_state_gate FAIL: page encoder owner scratch missing"
        )
    print("mfdt_v1_owner_state_gate OK: mutable_static_objects=0")


def self_test() -> None:
    assert mutable_static_declarations("static const uint8_t table[2] = {0};") == []
    assert mutable_static_declarations("static uint8_t const table[2] = {0};") == []
    assert mutable_static_declarations("static int helper(void);") == []
    assert mutable_static_declarations("static int *helper_pointer(void);") == []
    mutations = (
        "static uint8_t renamed_scratch[951];",
        "    static int hidden_cache = 1;",
        "static void *detached_owner;",
        "static int x=(0);",
        "static uint8_t x[(64)];",
        "static int (*callback)(void);",
        "static const uint8_t *p=NULL;",
        "static int hidden_owner_cache __attribute__((unused));",
        "#define MFDT_HIDDEN_CACHE static int macro_wrapped_cache",
        "sta\\\ntic uint8_t line_spliced_cache;",
        "sta??/\ntic uint8_t trigraph_spliced_cache;",
    )
    for mutation in mutations:
        found = mutable_static_declarations(mutation)
        if len(found) != 1:
            raise SystemExit(
                "mfdt_v1_owner_state_gate self-test FAIL: accepted " + mutation
            )

    paste_mutations = (
        "#define MFDT_FILE_LOCAL sta ## tic\nMFDT_FILE_LOCAL int pasted_cache;",
        "#define MFDT_FILE_LOCAL sta %:%: tic\nMFDT_FILE_LOCAL int pasted_cache;",
    )
    for mutation in paste_mutations:
        found = ambiguous_preprocessor_constructs(mutation)
        if len(found) != 1:
            raise SystemExit(
                "mfdt_v1_owner_state_gate self-test FAIL: accepted " + mutation
            )

    # Exercise the repository walker as well as the declaration parser. Each
    # mutation gets a fresh tree so one rejection cannot mask the next case.
    repository_mutations = (
        ("\nstatic uint8_t renamed_page_workspace[951];\n",
         "renamed_page_workspace"),
        ("\nsta\\\ntic uint8_t line_spliced_page_workspace[951];\n",
         "line_spliced_page_workspace"),
        ("\n#define MFDT_FILE_LOCAL sta ## tic\n"
         "MFDT_FILE_LOCAL uint8_t pasted_page_workspace[951];\n",
         "token-paste operator"),
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = pathlib.Path(temporary)
        target = root / SOURCE_DIR
        target.mkdir(parents=True)
        for path in (REPO / SOURCE_DIR).glob("*.[ch]"):
            (target / path.name).write_text(path.read_text(encoding="utf-8"),
                                            encoding="utf-8")
        esp_target = root / "ports/esp-idf/src"
        esp_target.mkdir(parents=True)
        for path in (REPO / "ports/esp-idf/src").glob("mfdt_v1*.[ch]"):
            (esp_target / path.name).write_text(
                path.read_text(encoding="utf-8"), encoding="utf-8")
        victim = target / "mfdt_v1_wire.c"
        baseline = victim.read_text(encoding="utf-8")
        for mutation, expected_failure in repository_mutations:
            victim.write_text(baseline + mutation, encoding="utf-8")
            try:
                check(root)
            except SystemExit as failure:
                if expected_failure not in str(failure):
                    raise SystemExit(
                        "mfdt_v1_owner_state_gate self-test FAIL: "
                        "repository mutation failed for the wrong reason"
                    ) from failure
            else:
                raise SystemExit(
                    "mfdt_v1_owner_state_gate self-test FAIL: "
                    "repository mutation passed"
                )
        victim.write_text(baseline, encoding="utf-8")
    print(
        "mfdt_v1_owner_state_gate self-test OK: "
        f"parser_mutations={len(mutations) + len(paste_mutations)} "
        f"repository_mutations={len(repository_mutations)}"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "self-test"))
    parser.add_argument("--root", type=pathlib.Path, default=REPO)
    args = parser.parse_args()
    if args.mode == "self-test":
        self_test()
    else:
        check(args.root.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
