#!/usr/bin/env python3
"""CMake source gate: shared generated fixture headers must not be multi-exec SOURCES.

Root QA NO-GO (build reliability, independent of U2 USB CDC):

When two or more add_executable targets list the same add_custom_command OUTPUT
generated header as a SOURCES entry, Ninja can schedule that custom command
twice. A concurrent compile unit may then #include a partially written header
(e.g. unknown ninlil_d3s1_* / cascading errors). Single-config Release-alone
or sanitizer-alone can still PASS.

Contract enforced here:

1. Any CMAKE_CURRENT_BINARY_DIR/*fixture*.h (or var expanding to one) that is
   listed as an add_executable SOURCES entry on two or more executables is a
   hard fail.
2. domain_scan_crossrow_vector_fixture.h is the known multi-consumer case and
   must use the dedicated pattern:
   - exactly one add_custom_command OUTPUT for that basename
   - add_custom_target(ninlil_domain_scan_crossrow_vector_fixture DEPENDS ...)
   - both oracle bridge executables do NOT list the header as SOURCES
   - both executables add_dependencies(... ninlil_domain_scan_crossrow_vector_fixture)

self-test mutates a temporary CMakeLists copy to re-attach the shared fixture
as multi-exec SOURCES and proves the checker fails (not soft token smoke).
"""

from __future__ import annotations

import pathlib
import re
import shutil
import sys
import tempfile
from typing import Callable, Dict, List, Set, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
HOST_CMAKE = REPO_ROOT / "CMakeLists.txt"

CROSSROW_FIXTURE_BASENAME = "domain_scan_crossrow_vector_fixture.h"
CROSSROW_CUSTOM_TARGET = "ninlil_domain_scan_crossrow_vector_fixture"
CROSSROW_BRIDGE_EXES = (
    "ninlil_domain_store_scanner_crossrow_oracle_bridge_test",
    "ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test",
)

# set(_var ${CMAKE_CURRENT_BINARY_DIR}/something_fixture.h)
SET_FIXTURE_VAR = re.compile(
    r"set\s*\(\s*(_ninlil_\w+)\s+"
    r"\$\{CMAKE_CURRENT_BINARY_DIR\}/([A-Za-z0-9_.-]*fixture[A-Za-z0-9_.-]*\.h)\s*\)",
    re.IGNORECASE,
)

# OUTPUT ${var} or OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/name.h
OUTPUT_LINE = re.compile(
    r"OUTPUT\s+"
    r"(?:\$\{([A-Za-z0-9_]+)\}|"
    r"\$\{CMAKE_CURRENT_BINARY_DIR\}/([A-Za-z0-9_.-]+\.h))",
    re.IGNORECASE,
)

ADD_EXECUTABLE = re.compile(
    r"add_executable\s*\(\s*([A-Za-z0-9_]+)\s*(.*?)\)",
    re.IGNORECASE | re.DOTALL,
)

ADD_CUSTOM_TARGET = re.compile(
    r"add_custom_target\s*\(\s*([A-Za-z0-9_]+)\s*(.*?)\)",
    re.IGNORECASE | re.DOTALL,
)

ADD_DEPENDENCIES = re.compile(
    r"add_dependencies\s*\(\s*([A-Za-z0-9_]+)\s+([A-Za-z0-9_\s]+?)\)",
    re.IGNORECASE | re.DOTALL,
)

SOURCE_TOKEN = re.compile(
    r"\$\{([A-Za-z0-9_]+)\}|"
    r"([A-Za-z0-9_./${}-]+\.h)"
)


class GateFailure(Exception):
    pass


def fail(msg: str) -> None:
    raise GateFailure(msg)


def strip_cmake_comments(text: str) -> str:
    """Strip # line comments outside of quoted strings (best-effort)."""
    out: List[str] = []
    for line in text.splitlines(keepends=True):
        in_sq = False
        in_dq = False
        i = 0
        kept = []
        while i < len(line):
            ch = line[i]
            if ch == "'" and not in_dq:
                in_sq = not in_sq
                kept.append(ch)
            elif ch == '"' and not in_sq:
                in_dq = not in_dq
                kept.append(ch)
            elif ch == "#" and not in_sq and not in_dq:
                # Drop rest of line content but keep newline.
                if line.endswith("\n"):
                    kept.append("\n")
                break
            else:
                kept.append(ch)
            i += 1
        out.append("".join(kept))
    return "".join(out)


def fixture_var_map(text: str) -> Dict[str, str]:
    """Map cmake var name -> fixture basename for BINARY_DIR fixture headers."""
    mapping: Dict[str, str] = {}
    for m in SET_FIXTURE_VAR.finditer(text):
        mapping[m.group(1)] = m.group(2)
    return mapping


def executable_sources(text: str) -> Dict[str, List[str]]:
    """Map executable name -> raw source tokens (vars and paths)."""
    result: Dict[str, List[str]] = {}
    for m in ADD_EXECUTABLE.finditer(text):
        name = m.group(1)
        body = m.group(2)
        tokens: List[str] = []
        for tm in SOURCE_TOKEN.finditer(body):
            if tm.group(1):
                tokens.append("${" + tm.group(1) + "}")
            else:
                tokens.append(tm.group(2))
        result[name] = tokens
    return result


def resolve_fixture_sources(
    tokens: List[str], var_to_base: Dict[str, str]
) -> Set[str]:
    """Resolve source tokens that refer to generated fixture basenames."""
    found: Set[str] = set()
    for tok in tokens:
        if tok.startswith("${") and tok.endswith("}"):
            var = tok[2:-1]
            if var in var_to_base:
                found.add(var_to_base[var])
            continue
        base = pathlib.Path(tok).name
        if "fixture" in base.lower() and base.endswith(".h"):
            found.add(base)
    return found


def multi_exec_fixture_owners(
    text: str,
) -> Dict[str, List[str]]:
    """Fixture basename -> list of executables that list it as SOURCES."""
    cleaned = strip_cmake_comments(text)
    var_map = fixture_var_map(cleaned)
    exes = executable_sources(cleaned)
    owners: Dict[str, List[str]] = {}
    for exe, tokens in exes.items():
        for base in resolve_fixture_sources(tokens, var_map):
            owners.setdefault(base, []).append(exe)
    return owners


def custom_target_bodies(text: str) -> Dict[str, str]:
    cleaned = strip_cmake_comments(text)
    return {m.group(1): m.group(2) for m in ADD_CUSTOM_TARGET.finditer(cleaned)}


def dependency_edges(text: str) -> List[Tuple[str, Set[str]]]:
    cleaned = strip_cmake_comments(text)
    edges: List[Tuple[str, Set[str]]] = []
    for m in ADD_DEPENDENCIES.finditer(cleaned):
        target = m.group(1)
        deps = set(m.group(2).split())
        edges.append((target, deps))
    return edges


def count_output_mentions(text: str, basename: str) -> int:
    cleaned = strip_cmake_comments(text)
    var_map = fixture_var_map(cleaned)
    vars_for_base = {v for v, b in var_map.items() if b == basename}
    count = 0
    for m in OUTPUT_LINE.finditer(cleaned):
        var = m.group(1)
        direct = m.group(2)
        if direct == basename:
            count += 1
        elif var and var in vars_for_base:
            count += 1
    return count


def check_text(text: str, where: str = "CMakeLists.txt") -> None:
    owners = multi_exec_fixture_owners(text)
    multi = {base: exes for base, exes in owners.items() if len(exes) >= 2}
    if multi:
        detail = "; ".join(
            f"{base} SOURCES of {', '.join(exes)}" for base, exes in sorted(multi.items())
        )
        fail(
            f"{where}: generated fixture header listed as SOURCES on multiple "
            f"executables (Ninja shared OUTPUT race): {detail}. "
            "Use a single add_custom_command OUTPUT + dedicated add_custom_target "
            "+ add_dependencies / OBJECT_DEPENDS; do not attach the header as "
            "SOURCES to more than one executable."
        )

    # Hard pin for the known multi-consumer crossrow fixture.
    if CROSSROW_FIXTURE_BASENAME in owners:
        fail(
            f"{where}: {CROSSROW_FIXTURE_BASENAME} must not be an add_executable "
            f"SOURCES entry (consumers: {owners[CROSSROW_FIXTURE_BASENAME]}). "
            f"Own it via add_custom_target({CROSSROW_CUSTOM_TARGET}) and "
            "include-dir + OBJECT_DEPENDS + add_dependencies."
        )

    n_out = count_output_mentions(text, CROSSROW_FIXTURE_BASENAME)
    if n_out != 1:
        fail(
            f"{where}: expected exactly one add_custom_command OUTPUT for "
            f"{CROSSROW_FIXTURE_BASENAME}, found {n_out}"
        )

    targets = custom_target_bodies(text)
    if CROSSROW_CUSTOM_TARGET not in targets:
        fail(
            f"{where}: missing add_custom_target({CROSSROW_CUSTOM_TARGET}) "
            f"for shared {CROSSROW_FIXTURE_BASENAME}"
        )
    body = targets[CROSSROW_CUSTOM_TARGET]
    if "_ninlil_d3s1_fixture" not in body and CROSSROW_FIXTURE_BASENAME not in body:
        fail(
            f"{where}: {CROSSROW_CUSTOM_TARGET} must DEPENDS the crossrow "
            "fixture OUTPUT"
        )

    edges = dependency_edges(text)
    for exe in CROSSROW_BRIDGE_EXES:
        if not any(
            target == exe and CROSSROW_CUSTOM_TARGET in deps for target, deps in edges
        ):
            fail(
                f"{where}: add_executable {exe} must add_dependencies("
                f"{CROSSROW_CUSTOM_TARGET}) so generation completes before compile"
            )


def check_path(path: pathlib.Path) -> None:
    if not path.is_file():
        fail(f"missing required file: {path}")
    check_text(path.read_text(encoding="utf-8"), where=str(path.name))


def check() -> None:
    check_path(HOST_CMAKE)
    print(
        "cmake_generated_fixture_source_gate ok: "
        f"no multi-exec fixture SOURCES; {CROSSROW_FIXTURE_BASENAME} "
        f"owned by {CROSSROW_CUSTOM_TARGET}"
    )


def _expect_fail(label: str, mutator: Callable[[pathlib.Path], None]) -> None:
    with tempfile.TemporaryDirectory(prefix="cmake-fixture-gate-") as td:
        root = pathlib.Path(td)
        dst = root / "CMakeLists.txt"
        shutil.copy2(HOST_CMAKE, dst)
        mutator(dst)
        try:
            check_path(dst)
        except GateFailure as e:
            print(f"  self-test mutation {label!r} correctly failed: {e}")
            return
        fail(f"self-test mutation {label!r} did not fail the checker (false green)")


def _mut_reattach_shared_fixture_as_multi_sources(path: pathlib.Path) -> None:
    """False-green: put shared fixture back into both bridge executables' SOURCES."""
    text = path.read_text(encoding="utf-8")
    # First bridge: only .c source
    old1 = (
        "add_executable(ninlil_domain_store_scanner_crossrow_oracle_bridge_test\n"
        "        ${_ninlil_crossrow_bridge_c}\n"
        "    )"
    )
    new1 = (
        "add_executable(ninlil_domain_store_scanner_crossrow_oracle_bridge_test\n"
        "        ${_ninlil_crossrow_bridge_c}\n"
        "        ${_ninlil_d3s1_fixture}\n"
        "    )"
    )
    old2 = (
        "add_executable(ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test\n"
        "        ${_ninlil_crossrow_d3s2_bridge_c}\n"
        "    )"
    )
    new2 = (
        "add_executable(ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test\n"
        "        ${_ninlil_crossrow_d3s2_bridge_c}\n"
        "        ${_ninlil_d3s1_fixture}\n"
        "    )"
    )
    if old1 not in text or old2 not in text:
        fail("mutator setup: crossrow bridge add_executable blocks not found")
    text = text.replace(old1, new1, 1).replace(old2, new2, 1)
    path.write_text(text, encoding="utf-8")


def _mut_drop_custom_target(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    pat = re.compile(
        r"add_custom_target\s*\(\s*"
        + re.escape(CROSSROW_CUSTOM_TARGET)
        + r"\s+DEPENDS\s+\$\{_ninlil_d3s1_fixture\}\s*\)",
        re.IGNORECASE,
    )
    if not pat.search(text):
        fail("mutator setup: crossrow custom_target block missing")
    path.write_text(pat.sub("# removed custom target", text), encoding="utf-8")


def _mut_drop_one_add_dependencies(path: pathlib.Path) -> None:
    text = path.read_text(encoding="utf-8")
    old = (
        "add_dependencies(\n"
        "        ninlil_domain_store_scanner_crossrow_oracle_bridge_test\n"
        "        ninlil_domain_scan_crossrow_vector_fixture\n"
        "    )"
    )
    if old not in text:
        fail("mutator setup: d3s1 bridge add_dependencies block missing")
    path.write_text(text.replace(old, "# removed add_dependencies", 1), encoding="utf-8")


def _mut_duplicate_output_command(path: pathlib.Path) -> None:
    """Duplicate the crossrow OUTPUT custom command (two generator rules)."""
    text = path.read_text(encoding="utf-8")
    marker = (
        "add_custom_target(ninlil_domain_scan_crossrow_vector_fixture\n"
        "        DEPENDS ${_ninlil_d3s1_fixture}\n"
        "    )"
    )
    if marker not in text:
        fail("mutator setup: custom_target marker missing for OUTPUT dup")
    dup = (
        "add_custom_command(\n"
        "        OUTPUT ${_ninlil_d3s1_fixture}\n"
        "        COMMAND ${Python3_EXECUTABLE} -c \"pass\"\n"
        "        COMMENT \"duplicate crossrow fixture OUTPUT (mutator)\"\n"
        "        VERBATIM\n"
        "    )\n"
        + marker
    )
    path.write_text(text.replace(marker, dup, 1), encoding="utf-8")


def self_test() -> None:
    if not HOST_CMAKE.is_file():
        fail(f"missing host CMakeLists for self-test: {HOST_CMAKE}")
    check_path(HOST_CMAKE)

    mutations: List[Tuple[str, Callable[[pathlib.Path], None]]] = [
        ("reattach_shared_fixture_multi_sources", _mut_reattach_shared_fixture_as_multi_sources),
        ("drop_crossrow_custom_target", _mut_drop_custom_target),
        ("drop_one_bridge_add_dependencies", _mut_drop_one_add_dependencies),
        ("duplicate_crossrow_output_command", _mut_duplicate_output_command),
    ]
    for label, mut in mutations:
        _expect_fail(label, mut)

    print(
        f"cmake_generated_fixture_source_gate self-test ok: "
        f"mutations={len(mutations)}"
    )


def main(argv: List[str]) -> int:
    if len(argv) < 2 or argv[1] not in ("check", "self-test"):
        print(
            "usage: cmake_generated_fixture_source_gate.py check|self-test",
            file=sys.stderr,
        )
        return 2
    try:
        if argv[1] == "self-test":
            self_test()
        else:
            check()
    except GateFailure as e:
        print(
            f"cmake_generated_fixture_source_gate FAIL: {e}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
