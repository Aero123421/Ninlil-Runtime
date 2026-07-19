#!/usr/bin/env python3
"""Structural + dependency gate for R7 T1 wire source authority (docs/32 §9).

Portable wire codec exact once on Host+ESP via shared private list. No platform
crypto adapters, no OpenSSL/mbedTLS headers in wire sources, no public install.
Production wire sources must not include/call radio_hal / profile_loader /
pcp_authority / N6 / OS headers-APIs, or use calloc/realloc/free/malloc/alloca/VLA.

Also runs a portable C compile proof (``-std=c11 -Werror -Wvla -fsyntax-only``).

Does not claim ESP KAT / HIL / T1 Accepted.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from typing import Mapping

REPO = pathlib.Path(__file__).resolve().parents[1]
AUTHORITY = "cmake/ninlil_r7_wire_sources.cmake"
RUNTIME_AUTHORITY = "cmake/ninlil_runtime_private_sources.cmake"
HOST_CMAKE = "CMakeLists.txt"
ESP_CMAKE = "ports/esp-idf/components/ninlil/CMakeLists.txt"
WIRE_C = "src/radio/r7_wire_codec.c"
WIRE_H = "src/radio/r7_wire_codec.h"
WIRE_CTEST = "cmake/ninlil_r7_wire_ctest.cmake"
PORTABLE_VAR = "NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES"
EXACT = {PORTABLE_VAR: ("src/radio/r7_wire_codec.c",)}
READ_PATHS = (
    AUTHORITY,
    RUNTIME_AUTHORITY,
    HOST_CMAKE,
    ESP_CMAKE,
    WIRE_C,
    WIRE_H,
    WIRE_CTEST,
)

EXACT_APIS = (
    "ninlil_r7_wire_pack_outer_data_aad",
    "ninlil_r7_wire_parse_outer_data_aad",
    "ninlil_r7_wire_pack_e2e_single_aad",
    "ninlil_r7_wire_parse_e2e_single_aad",
    "ninlil_r7_wire_seal_e2e_single",
    "ninlil_r7_wire_open_e2e_single",
    "ninlil_r7_wire_seal_outer_single",
    "ninlil_r7_wire_open_outer_single",
)
WIRE_TEST_SEAM_MACRO = "NINLIL_R7_WIRE_TEST_BUILD"
WIRE_TEST_SEAM = "ninlil_r7_wire_test_spans_forbidden"

# Exact production #include allowlists (after comment strip; each exact once).
WIRE_C_ALLOWED_INCLUDES: tuple[str, ...] = (
    '"r7_wire_codec.h"',
    "<stdatomic.h>",
)
WIRE_H_ALLOWED_INCLUDES: tuple[str, ...] = (
    '"r7_crypto_provider.h"',
    "<stddef.h>",
    "<stdint.h>",
)
_INCLUDE_ANY_DIRECTIVE = re.compile(
    r"^[ \t]*#[ \t]*(include(?:_next)?)[ \t]*(.*)$",
    re.MULTILINE,
)
_INCLUDE_LITERAL_OPERAND = re.compile(r'(?:"[^"\r\n]+"|<[^>\r\n]+>)')

# Include paths / basenames forbidden in production wire TU.
BANNED_INCLUDE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r'#\s*include\s*[<"]\s*radio_hal\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*profile_loader\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*pcp_authority\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*n6_[A-Za-z0-9_/.-]+\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*openssl/'),
    re.compile(r'#\s*include\s*[<"]\s*mbedtls/'),
    # Platform factory adapters (Host OpenSSL 3 / ESP mbedTLS) — not portable.
    re.compile(r'#\s*include\s*[<"]\s*r7_crypto_openssl3\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*r7_crypto_mbedtls\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*unistd\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*pthread\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*windows\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*fcntl\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*sys/'),
    re.compile(r'#\s*include\s*[<"]\s*netinet/'),
    re.compile(r'#\s*include\s*[<"]\s*arpa/'),
    re.compile(r'#\s*include\s*[<"]\s*poll\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*signal\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*time\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*sx1262'),
)

# Forbidden tokens after comment/string strip: heap/OS APIs and real private
# family identifiers (types + functions), not fake n6_/profile_ prefixes.
BANNED_TOKEN_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("malloc", re.compile(r"\b(?:__builtin_)?malloc\s*\(")),
    ("calloc", re.compile(r"\b(?:__builtin_)?calloc\s*\(")),
    ("realloc", re.compile(r"\b(?:__builtin_)?realloc\s*\(")),
    ("free", re.compile(r"\b(?:__builtin_)?free\s*\(")),
    ("alloca", re.compile(r"\b(?:__builtin_)?alloca\s*\(")),
    # Additional C/POSIX heap acquisition APIs (after comment/string strip).
    ("aligned_alloc", re.compile(r"\b(?:__builtin_)?aligned_alloc\s*\(")),
    ("posix_memalign", re.compile(r"\bposix_memalign\s*\(")),
    ("memalign", re.compile(r"\bmemalign\s*\(")),
    ("valloc", re.compile(r"\bvalloc\s*\(")),
    ("pvalloc", re.compile(r"\bpvalloc\s*\(")),
    ("strdup", re.compile(r"\bstrdup\s*\(")),
    ("strndup", re.compile(r"\bstrndup\s*\(")),
    ("fopen", re.compile(r"\bfopen\s*\(")),
    ("pthread_create", re.compile(r"\bpthread_create\s*\(")),
    ("gettimeofday", re.compile(r"\bgettimeofday\s*\(")),
    ("clock_gettime", re.compile(r"\bclock_gettime\s*\(")),
    ("nanosleep", re.compile(r"\bnanosleep\s*\(")),
    ("sleep", re.compile(r"\bsleep\s*\(")),
    # Real production families (docs/32 §1): capture types and functions.
    ("ninlil_n6_", re.compile(r"\bninlil_n6_[A-Za-z0-9_]+\b")),
    ("ninlil_pcp_", re.compile(r"\bninlil_pcp_[A-Za-z0-9_]+\b")),
    ("ninlil_r5_", re.compile(r"\bninlil_r5_[A-Za-z0-9_]+\b")),
    ("ninlil_radio_hal_", re.compile(r"\bninlil_radio_hal_[A-Za-z0-9_]+\b")),
)

# Heap APIs that self-test injects one-by-one (must each go red).
HEAP_API_INJECTIONS: tuple[tuple[str, str], ...] = (
    ("aligned_alloc", "static void *_aa = aligned_alloc(16, 16);\n"),
    ("posix_memalign", "static void *_pm(void){void *p=0; (void)posix_memalign(&p,16,16); return p;}\n"),
    ("memalign", "static void *_ma = memalign(16, 16);\n"),
    ("valloc", "static void *_va = valloc(16);\n"),
    ("pvalloc", "static void *_pva = pvalloc(16);\n"),
    ("strdup", 'static char *_sd = strdup("x");\n'),
    ("strndup", 'static char *_snd = strndup("xy", 1);\n'),
    (
        "builtin_malloc_free",
        "static void _bmf(void){void *p=__builtin_malloc(16u); "
        "__builtin_free(p);}\n",
    ),
    ("builtin_calloc", "static void *_bc(void){return __builtin_calloc(1u,1u);}\n"),
    (
        "builtin_realloc",
        "static void *_br(void *p){return __builtin_realloc(p,16u);}\n",
    ),
    ("builtin_alloca", "static void *_ba(void){return __builtin_alloca(16u);}\n"),
    (
        "builtin_aligned_alloc",
        "static void *_baa(void){return __builtin_aligned_alloc(16u,16u);}\n",
    ),
)

# VLA: non-constant size in array declarator of automatic storage.
# Catches `uint8_t buf[n];` / `int a[len + 1];` while allowing `uint8_t buf[16];`.
_VLA_DECL = re.compile(
    r"(?m)^\s*(?:static\s+)?(?:const\s+)?"
    r"(?:unsigned\s+)?(?:char|uint8_t|uint16_t|uint32_t|uint64_t|int|size_t|void)\s+"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\[\s*([^\]]+)\s*\]\s*;"
)


def read_texts() -> dict[str, str]:
    texts: dict[str, str] = {}
    for relative in READ_PATHS:
        path = REPO / relative
        texts[relative] = path.read_text(encoding="utf-8")
    return texts


def strip_c_comments(source: str) -> str:
    """Remove // and /* */ comments; keep preprocessor string forms intact."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                break
            out.append("\n" * source.count("\n", i, end + 2))
            i = end + 2
            continue
        # Keep strings/chars intact for #include "..." detection.
        out.append(source[i])
        i += 1
    return "".join(out)


def strip_c_comments_and_strings(source: str) -> str:
    """Remove comments and string/char literals for call/VLA scanning."""
    out: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
            continue
        if source.startswith("/*", i):
            end = source.find("*/", i + 2)
            if end < 0:
                break
            out.append("\n" * source.count("\n", i, end + 2))
            i = end + 2
            continue
        if source[i] == '"':
            i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('""')
            continue
        if source[i] == "'":
            i += 1
            while i < n:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == "'":
                    i += 1
                    break
                i += 1
            out.append("''")
            continue
        out.append(source[i])
        i += 1
    return "".join(out)


def looks_like_runtime_size_expr(expr: str) -> bool:
    """True when size expression likely uses a runtime/local identifier.

    Macro constants (ALL_CAPS / NINLIL_*) and integer literals are not VLAs.
    Any identifier containing a lowercase letter is treated as runtime size.
    """
    e = expr.strip()
    if not e:
        return False
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", e):
        if ident == "sizeof":
            continue
        if any(ch.islower() for ch in ident):
            return True
    return False


def find_vla_decls(stripped: str) -> list[str]:
    hits: list[str] = []
    for m in _VLA_DECL.finditer(stripped):
        size_expr = m.group(1)
        if looks_like_runtime_size_expr(size_expr):
            hits.append(m.group(0).strip())
    return hits


def extract_includes_after_comment_strip(source: str) -> list[str]:
    """Return every include operand after C phase-2 splice and comment removal.

    Literal operands are returned verbatim. Macro/non-literal operands and
    include_next receive a sentinel that cannot match the exact allowlist.
    """
    spliced = re.sub(r"\\\r?\n", "", source)
    no_comments = strip_c_comments(spliced)
    operands: list[str] = []
    for match in _INCLUDE_ANY_DIRECTIVE.finditer(no_comments):
        directive = match.group(1)
        operand = match.group(2).strip()
        if directive != "include" or _INCLUDE_LITERAL_OPERAND.fullmatch(operand) is None:
            operands.append(f"<{directive}:non-literal:{operand}>")
        else:
            operands.append(operand)
    return operands


def include_allowlist_errors(
    label: str, source: str, allowed: tuple[str, ...]
) -> list[str]:
    """Exact multiset: each allowed include exact once, extra includes 0."""
    errors: list[str] = []
    got = extract_includes_after_comment_strip(source)
    want = Counter(allowed)
    have = Counter(got)
    if have != want:
        missing = sorted((want - have).elements())
        extra = sorted((have - want).elements())
        dup = sorted(
            inc for inc, n in have.items() if n > want.get(inc, 0) and n > 1
        )
        if missing:
            errors.append(
                f"{label}: missing required include(s) exact-once: {missing}"
            )
        if extra:
            errors.append(
                f"{label}: extra/non-allowlisted include(s): {extra}"
            )
        if not missing and not extra and have != want:
            # Counts differ only by over/under of allowlisted names.
            for inc in sorted(set(want) | set(have)):
                if have.get(inc, 0) != want.get(inc, 0):
                    errors.append(
                        f"{label}: include {inc!r} count got={have.get(inc, 0)} "
                        f"want={want.get(inc, 0)}"
                    )
        if dup and not any("count" in e for e in errors):
            errors.append(f"{label}: duplicate include(s): {dup}")
        if not errors:
            errors.append(
                f"{label}: include multiset mismatch got={got!r} want={list(allowed)!r}"
            )
    return errors


def dependency_errors(label: str, source: str) -> list[str]:
    errors: list[str] = []
    # Includes: strip comments only so #include "foo.h" strings survive.
    no_comments = strip_c_comments(source)
    for pattern in BANNED_INCLUDE_RES:
        if pattern.search(no_comments):
            errors.append(
                f"{label}: banned include matched {pattern.pattern}"
            )
    # Tokens / VLA: also strip string/char literals.
    stripped = strip_c_comments_and_strings(source)
    for name, pattern in BANNED_TOKEN_RES:
        if pattern.search(stripped):
            errors.append(f"{label}: banned token/API '{name}' present")
    for hit in find_vla_decls(stripped):
        errors.append(f"{label}: VLA declaration present: {hit}")
    return errors


def cmake_set_entries(text: str, variable: str) -> tuple[str, ...] | None:
    match = re.search(
        rf"\bset\s*\(\s*{re.escape(variable)}\b(.*?)\)",
        text,
        re.DOTALL,
    )
    if match is None:
        return None
    body = re.sub(r"#[^\r\n]*", "", match.group(1))
    return tuple(token for token in re.split(r"\s+", body.strip()) if token)


def require_once(errors: list[str], text: str, token: str, label: str) -> None:
    count = text.count(token)
    if count != 1:
        errors.append(f"{label}: expected token exactly once, got {count}: {token}")


def cmake_install_call_bodies(text: str) -> list[str]:
    bodies: list[str] = []
    for match in re.finditer(r"\binstall\s*\(", text, re.IGNORECASE):
        start = match.end()
        depth = 1
        i = start
        n = len(text)
        while i < n and depth > 0:
            ch = text[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            i += 1
        if depth == 0:
            bodies.append(text[start : i - 1])
    return bodies


def strip_exact_wire_test_seam(header: str, errors: list[str]) -> str:
    """Remove only the canonical test-only seam before API exact-set audit."""
    pattern = re.compile(
        r"#ifdef\s+NINLIL_R7_WIRE_TEST_BUILD\s*\n"
        r"int\s+ninlil_r7_wire_test_spans_forbidden\s*\(\s*\n"
        r"\s*const\s+void\s+\*a\s*,\s*size_t\s+a_len\s*,\s*"
        r"const\s+void\s+\*b\s*,\s*size_t\s+b_len\s*\)\s*;\s*\n"
        r"#endif",
        re.MULTILINE,
    )
    matches = list(pattern.finditer(header))
    if len(matches) != 1 or header.count(WIRE_TEST_SEAM_MACRO) != 1:
        errors.append("wire header test seam must be one exact conditional block")
        return header
    return header[: matches[0].start()] + header[matches[0].end() :]


def wire_test_seam_source_errors(source: str) -> list[str]:
    pattern = re.compile(
        r"#ifdef\s+NINLIL_R7_WIRE_TEST_BUILD\s*\n"
        r"int\s+ninlil_r7_wire_test_spans_forbidden\s*\(\s*\n"
        r"\s*const\s+void\s+\*a\s*,\s*size_t\s+a_len\s*,\s*"
        r"const\s+void\s+\*b\s*,\s*size_t\s+b_len\s*\)\s*\n"
        r"\{\s*\n\s*return\s+ninlil_r7_wire_spans_forbidden\s*"
        r"\(\s*a\s*,\s*a_len\s*,\s*b\s*,\s*b_len\s*\)\s*;\s*\n"
        r"\}\s*\n#endif",
        re.MULTILINE,
    )
    if len(list(pattern.finditer(source))) != 1 or source.count(WIRE_TEST_SEAM_MACRO) != 1:
        return ["wire source test seam must be one exact conditional wrapper"]
    return []


def validate_texts(texts: Mapping[str, str]) -> list[str]:
    errors: list[str] = []
    authority = texts[AUTHORITY]
    for variable, expected in EXACT.items():
        entries = cmake_set_entries(authority, variable)
        if entries is None:
            errors.append(f"authority missing {variable}")
            continue
        if entries != expected:
            errors.append(f"{variable}: got={entries!r} want={expected!r}")
        for entry in entries:
            if entry.startswith(("tests/", "tools/")) or ".gen." in entry:
                errors.append(f"non-production source: {entry}")

    runtime = texts[RUNTIME_AUTHORITY]
    require_once(
        errors,
        runtime,
        'include("${CMAKE_CURRENT_LIST_DIR}/ninlil_r7_wire_sources.cmake")',
        "wire authority include",
    )
    if runtime.count("${NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES}") != 2:
        errors.append(
            "wire portable var must appear in T1 runtime append and VLA set "
            f"(got {runtime.count('${NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES}')})"
        )
    if not re.search(
        r"list\s*\(\s*APPEND\s+NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\s+"
        r"\$\{NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES\}\s*\)",
        runtime,
    ):
        errors.append("dedicated T1 wire runtime append block missing")

    host = texts[HOST_CMAKE]
    if "ninlil_r7_wire_ctest.cmake" not in host:
        errors.append("Host CMake missing T1 ctest include")
    for body in cmake_install_call_bodies(host):
        lower = body.lower()
        for needle in ("r7_wire_codec", "r7_wire_single_t1", "nrw1_t1"):
            if needle in lower:
                errors.append(f"T1 private artifact in install(): {needle}")
                break

    errors.extend(dependency_errors(WIRE_C, texts[WIRE_C]))
    errors.extend(dependency_errors(WIRE_H, texts[WIRE_H]))
    # Exact include allowlist (blacklist alone misses dirent.h etc.).
    errors.extend(
        include_allowlist_errors(WIRE_C, texts[WIRE_C], WIRE_C_ALLOWED_INCLUDES)
    )
    errors.extend(
        include_allowlist_errors(WIRE_H, texts[WIRE_H], WIRE_H_ALLOWED_INCLUDES)
    )

    if '#include "r7_crypto_provider.h"' not in texts[WIRE_H]:
        errors.append("wire header must include r7_crypto_provider.h")
    if "ninlil_r7_crypto_aes128_gcm_seal" not in texts[WIRE_C]:
        errors.append("wire codec must call portable AES-GCM seal")
    if "ninlil_r7_crypto_nonce_from_counter" not in texts[WIRE_C]:
        errors.append("wire codec must call sole nonce helper")

    errors.extend(wire_test_seam_source_errors(texts[WIRE_C]))
    if "NINLIL_R7_WIRE_TEST_BUILD=1" not in texts[HOST_CMAKE]:
        errors.append("Host test private archive must define wire test seam")
    ctest = texts[WIRE_CTEST]
    if not re.search(
        r"target_compile_definitions\s*\(\s*ninlil_r7_wire_portable_test\s+PRIVATE\s+"
        r"NINLIL_R7_WIRE_TEST_BUILD=1\s*\)",
        ctest,
        flags=re.MULTILINE,
    ):
        errors.append("wire portable target must define wire test seam")

    header = strip_exact_wire_test_seam(texts[WIRE_H], errors)
    declared = set(re.findall(r"\bninlil_r7_wire_[A-Za-z0-9_]+\b", header))
    type_names = {
        "ninlil_r7_wire_status",
        "ninlil_r7_wire_outer_data_fields",
        "ninlil_r7_wire_e2e_single_fields",
    }
    api_declared = declared - type_names
    if api_declared != set(EXACT_APIS):
        missing = sorted(set(EXACT_APIS) - api_declared)
        extra = sorted(api_declared - set(EXACT_APIS))
        if missing:
            errors.append(f"header missing exact wire API: {missing}")
        if extra:
            errors.append(
                f"header declares non-exact ninlil_r7_wire_* (composite/extra): {extra}"
            )
    source = texts[WIRE_C]
    defined = set(
        re.findall(
            r"(?m)^ninlil_r7_wire_status\s+(ninlil_r7_wire_[A-Za-z0-9_]+)\s*\(",
            source,
        )
    )
    if defined != set(EXACT_APIS):
        missing = sorted(set(EXACT_APIS) - defined)
        extra = sorted(defined - set(EXACT_APIS))
        if missing:
            errors.append(f"source missing exact wire API definition: {missing}")
        if extra:
            errors.append(
                f"source defines non-exact external wire API (composite/extra): {extra}"
            )

    # size_t > UINTPTR_MAX fail-closed inside span alias helper (docs/32 §6).
    # Public domain lengths never reach this arm dynamically; the guard must
    # still return 1 (forbidden) and must not be inverted to return 0.
    uintptr_len_guard = re.search(
        r"if\s*\(\s*a_len\s*>\s*\(\s*size_t\s*\)\s*UINTPTR_MAX\s*"
        r"\|\|\s*b_len\s*>\s*\(\s*size_t\s*\)\s*UINTPTR_MAX\s*\)\s*"
        r"\{\s*return\s+1\s*;\s*\}",
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    if uintptr_len_guard is None:
        errors.append(
            "wire codec missing fail-closed "
            "(a_len > (size_t)UINTPTR_MAX || b_len > (size_t)UINTPTR_MAX) "
            "return 1 in span forbidden helper"
        )
    return errors


def portable_compile_proof(wire_c: pathlib.Path, wire_h_dir: pathlib.Path) -> list[str]:
    """Compile wire TU as portable C11 with -Wvla; no platform crypto headers."""
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if not cc:
        return ["portable compile proof: no C compiler (cc/clang/gcc) on PATH"]
    cmd = [
        cc,
        "-std=c11",
        "-pedantic",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wvla",
        "-fsyntax-only",
        f"-I{wire_h_dir}",
        str(wire_c),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        return [
            "portable compile proof failed:\n"
            f"cmd={' '.join(cmd)}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        ]
    return []


def run_check() -> int:
    try:
        texts = read_texts()
    except OSError as exc:
        print(f"r7_wire_platform_split_gate FAIL: {exc}", file=sys.stderr)
        return 1
    errors = validate_texts(texts)
    errors.extend(
        portable_compile_proof(REPO / WIRE_C, REPO / "src" / "radio")
    )
    if errors:
        for e in errors:
            print(f"r7_wire_platform_split_gate FAIL: {e}", file=sys.stderr)
        return 1
    print("r7_wire_platform_split_gate: PASS (portable=1, deps=clean, compile=ok)")
    return 0


def run_self_test() -> int:
    baseline = read_texts()
    if validate_texts(baseline):
        print(
            "r7_wire_platform_split_gate self-test FAIL: baseline red",
            file=sys.stderr,
        )
        return 1
    # Compile proof must pass on baseline.
    if portable_compile_proof(REPO / WIRE_C, REPO / "src" / "radio"):
        print(
            "r7_wire_platform_split_gate self-test FAIL: baseline compile red",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []

    structural_mutations = (
        (AUTHORITY, "src/radio/r7_wire_codec.c", "tests/radio/fake.c"),
        (
            RUNTIME_AUTHORITY,
            "list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\n"
            "    ${NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES}\n)",
            "list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\n"
            "    ${NINLIL_R7_WIRE_PORTABLE_MISSING}\n)",
        ),
        (
            WIRE_H,
            '#include "r7_crypto_provider.h"',
            '#include "openssl/evp.h"',
        ),
        (
            HOST_CMAKE,
            "install(FILES LICENSE\n"
            "    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/ninlil)",
            "install(FILES\n"
            "    src/radio/r7_wire_codec.h\n"
            "    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})",
        ),
        (
            WIRE_H,
            "ninlil_r7_wire_status ninlil_r7_wire_open_outer_single(",
            "ninlil_r7_wire_status ninlil_r7_wire_seal_full(\n"
            "    void);\nninlil_r7_wire_status ninlil_r7_wire_open_outer_single(",
        ),
        # The sole extra test declaration is allowed only in its exact guard.
        (
            WIRE_H,
            "#ifdef NINLIL_R7_WIRE_TEST_BUILD\n",
            "#ifdef NINLIL_R7_WIRE_TEST_BUILD_RENAMED\n",
        ),
        (
            WIRE_H,
            "#ifdef NINLIL_R7_WIRE_TEST_BUILD\n",
            "#if 1\n",
        ),
        (
            WIRE_H,
            "    const void *a, size_t a_len, const void *b, size_t b_len);\n"
            "#endif\n\n"
            "typedef struct ninlil_r7_wire_outer_data_fields",
            "    const void *a, size_t a_len, const void *b, size_t b_len);\n"
            "int ninlil_r7_wire_test_extra(void);\n"
            "#endif\n\n"
            "typedef struct ninlil_r7_wire_outer_data_fields",
        ),
        (
            WIRE_C,
            "#ifdef NINLIL_R7_WIRE_TEST_BUILD\n",
            "#ifdef NINLIL_R7_WIRE_TEST_BUILD_RENAMED\n",
        ),
        # size_t>UINTPTR_MAX guard: deletion must go red.
        (
            WIRE_C,
            "    if (a_len > (size_t)UINTPTR_MAX || b_len > (size_t)UINTPTR_MAX) {\n"
            "        return 1;\n"
            "    }\n",
            "    /* deleted UINTPTR_MAX length fail-closed guard */\n",
        ),
        # size_t>UINTPTR_MAX guard: inversion to return 0 must go red.
        (
            WIRE_C,
            "    if (a_len > (size_t)UINTPTR_MAX || b_len > (size_t)UINTPTR_MAX) {\n"
            "        return 1;\n"
            "    }\n",
            "    if (a_len > (size_t)UINTPTR_MAX || b_len > (size_t)UINTPTR_MAX) {\n"
            "        return 0;\n"
            "    }\n",
        ),
    )
    for index, (path, old, new) in enumerate(structural_mutations, 1):
        if baseline[path].count(old) != 1:
            failures.append(f"structural mutation {index} setup token count != 1")
            continue
        mutated = dict(baseline)
        mutated[path] = baseline[path].replace(old, new, 1)
        if not validate_texts(mutated):
            failures.append(f"structural mutation {index} escaped")

    # Dependency injections: real production API tokens + platform factory headers.
    inject_anchor = '#include "r7_wire_codec.h"\n'
    if baseline[WIRE_C].count(inject_anchor) != 1:
        failures.append("inject anchor count != 1 in wire .c")
    else:
        dep_injections: tuple[tuple[str, str], ...] = (
            ("radio_hal_include", '#include "radio_hal.h"\n'),
            ("profile_loader_include", '#include "profile_loader.h"\n'),
            ("pcp_authority_include", '#include "pcp_authority.h"\n'),
            ("n6_include", '#include "n6_record_codec.h"\n'),
            ("openssl3_factory_hdr", '#include "r7_crypto_openssl3.h"\n'),
            ("mbedtls_factory_hdr", '#include "r7_crypto_mbedtls.h"\n'),
            ("unistd_include", "#include <unistd.h>\n"),
            ("pthread_include", "#include <pthread.h>\n"),
            ("sys_time_include", "#include <sys/time.h>\n"),
            ("calloc_call", "static void *_p = calloc(1, 1);\n"),
            ("realloc_call", "static void *_q = realloc((void*)0, 1);\n"),
            ("free_call", "static void _f(void *p) { free(p); }\n"),
            ("malloc_call", "static void *_m = malloc(1);\n"),
            (
                "vla_decl",
                "static void _vla(size_t n)\n"
                "{\n"
                "    uint8_t buf[n];\n"
                "    (void)buf;\n"
                "}\n",
            ),
            # Real API tokens (not fake n6_*/profile_* prefixes).
            (
                "ninlil_n6_context_pool_bytes",
                "static size_t _n6 = ninlil_n6_context_pool_bytes(1u);\n",
            ),
            (
                "ninlil_pcp_object_size",
                "static size_t _pcp = ninlil_pcp_object_size();\n",
            ),
            (
                "ninlil_r5_object_size",
                "static size_t _r5 = ninlil_r5_object_size();\n",
            ),
            (
                "ninlil_radio_hal_object_size",
                "static size_t _hal = ninlil_radio_hal_object_size();\n",
            ),
        )
        for name, snippet in dep_injections + HEAP_API_INJECTIONS:
            mutated = dict(baseline)
            mutated[WIRE_C] = baseline[WIRE_C].replace(
                inject_anchor, inject_anchor + snippet, 1
            )
            errs = validate_texts(mutated)
            if not errs:
                failures.append(f"dependency mutation '{name}' escaped (no errors)")

    # Comment-only noise must NOT go red (false-positive guard).
    noise = dict(baseline)
    noise[WIRE_C] = baseline[WIRE_C].replace(
        inject_anchor,
        inject_anchor
        + "/* no ninlil_n6_ ninlil_pcp_ ninlil_r5_ ninlil_radio_hal_ */\n"
        + "/* no r7_crypto_openssl3.h r7_crypto_mbedtls.h malloc free VLA */\n"
        + "/* aligned_alloc posix_memalign memalign valloc pvalloc strdup strndup */\n"
        + "/* #include <dirent.h> #include <stdio.h> */\n"
        + "// #include <dirent.h>\n"
        + "// calloc realloc unistd pthread\n",
        1,
    )
    if validate_texts(noise):
        failures.append(
            f"comment-only noise incorrectly red: {validate_texts(noise)}"
        )

    # Exact include allowlist mutations (dirent was a real false-green vs blacklist).
    include_mutations: tuple[tuple[str, str, str, str], ...] = (
        (
            "dirent_add",
            WIRE_C,
            inject_anchor,
            inject_anchor + "#include <dirent.h>\n",
        ),
        (
            "unknown_stdio_add",
            WIRE_C,
            inject_anchor,
            inject_anchor + "#include <stdio.h>\n",
        ),
        (
            "macro_include_add",
            WIRE_C,
            inject_anchor,
            inject_anchor
            + "#define EXTRA_HEADER <stdlib.h>\n"
            + "#include EXTRA_HEADER\n",
        ),
        (
            "line_splice_include_add",
            WIRE_C,
            inject_anchor,
            inject_anchor + "#include \\\n<stdlib.h>\n",
        ),
        (
            "c_allowed_delete",
            WIRE_C,
            '#include "r7_wire_codec.h"\n',
            "/* deleted r7_wire_codec.h include */\n",
        ),
        (
            "c_allowed_duplicate",
            WIRE_C,
            "#include <stdatomic.h>\n",
            "#include <stdatomic.h>\n#include <stdatomic.h>\n",
        ),
        (
            "h_allowed_delete",
            WIRE_H,
            "#include <stddef.h>\n",
            "/* deleted stddef.h include */\n",
        ),
        (
            "h_allowed_duplicate",
            WIRE_H,
            "#include <stdint.h>\n",
            "#include <stdint.h>\n#include <stdint.h>\n",
        ),
        (
            "h_unknown_add",
            WIRE_H,
            '#include "r7_crypto_provider.h"\n',
            '#include "r7_crypto_provider.h"\n#include <dirent.h>\n',
        ),
    )
    for name, path, old, new in include_mutations:
        if baseline[path].count(old) != 1:
            failures.append(
                f"include mutation '{name}' setup token count != 1"
            )
            continue
        mutated = dict(baseline)
        mutated[path] = baseline[path].replace(old, new, 1)
        if not validate_texts(mutated):
            failures.append(f"include mutation '{name}' escaped (no errors)")

    # Both non-literal macro operands and phase-2 line-spliced operands compile
    # on the host, so the structural allowlist itself must make them red.
    include_compile_repros = {
        "macro": "#define EXTRA_HEADER <stdlib.h>\n#include EXTRA_HEADER\n",
        "line_splice": "#include \\\n<stdlib.h>\n",
    }
    for name, snippet in include_compile_repros.items():
        repro = dict(baseline)
        repro[WIRE_C] = baseline[WIRE_C].replace(
            inject_anchor, inject_anchor + snippet, 1
        )
        if not validate_texts(repro):
            failures.append(f"{name} include compile repro escaped validate")
            continue
        with tempfile.TemporaryDirectory(
            prefix=f"r7-wire-{name}-include-repro-"
        ) as td:
            mut_c = pathlib.Path(td) / "r7_wire_codec.c"
            mut_c.write_text(repro[WIRE_C], encoding="utf-8")
            compile_errs = portable_compile_proof(
                mut_c, REPO / "src" / "radio"
            )
            if compile_errs:
                failures.append(
                    f"{name} include repro must compile to prove gate catch: "
                    f"{compile_errs}"
                )

    # Audit repro: #include <stdlib.h> + aligned_alloc must fail validate.
    repro = dict(baseline)
    repro[WIRE_C] = baseline[WIRE_C].replace(
        inject_anchor,
        inject_anchor
        + "#include <stdlib.h>\n"
        + "static void *_repro = aligned_alloc(16, 16);\n",
        1,
    )
    repro_errs = validate_texts(repro)
    if not repro_errs:
        failures.append("aligned_alloc audit repro escaped validate_texts")
    elif not any("aligned_alloc" in e for e in repro_errs):
        failures.append(
            f"aligned_alloc audit repro red without token match: {repro_errs}"
        )
    else:
        with tempfile.TemporaryDirectory(prefix="r7-wire-heap-repro-") as td:
            td_path = pathlib.Path(td)
            mut_c = td_path / "r7_wire_codec.c"
            mut_c.write_text(repro[WIRE_C], encoding="utf-8")
            compile_errs = portable_compile_proof(mut_c, REPO / "src" / "radio")
            # Gate acceptance requires both green; validate is already red.
            if not repro_errs and not compile_errs:
                failures.append(
                    "aligned_alloc audit repro passed validate and compile"
                )
            # Prefer compile also red (implicit decl / Werror) when possible.
            _ = compile_errs

    # Compiler builtins bypass a bare `malloc(` token regex and need no header.
    # The mutation must compile while validate_texts rejects both builtins.
    secure_zero_anchor = (
        "static void ninlil_r7_wire_secure_zero(void *p, size_t n)\n"
        "{\n"
        "    volatile uint8_t *v = (volatile uint8_t *)p;\n"
        "    size_t i;\n\n"
    )
    if baseline[WIRE_C].count(secure_zero_anchor) != 1:
        failures.append("builtin heap repro secure_zero anchor count != 1")
    else:
        builtin_repro = dict(baseline)
        builtin_repro[WIRE_C] = baseline[WIRE_C].replace(
            secure_zero_anchor,
            secure_zero_anchor
            + "    void *hidden_heap = __builtin_malloc(16u);\n"
            + "    __builtin_free(hidden_heap);\n\n",
            1,
        )
        builtin_errs = validate_texts(builtin_repro)
        if not any("malloc" in e for e in builtin_errs) or not any(
            "free" in e for e in builtin_errs
        ):
            failures.append(
                f"builtin malloc/free repro not rejected by both tokens: "
                f"{builtin_errs}"
            )
        with tempfile.TemporaryDirectory(prefix="r7-wire-builtin-heap-repro-") as td:
            mut_c = pathlib.Path(td) / "r7_wire_codec.c"
            mut_c.write_text(builtin_repro[WIRE_C], encoding="utf-8")
            compile_errs = portable_compile_proof(
                mut_c, REPO / "src" / "radio"
            )
            if compile_errs:
                failures.append(
                    "builtin malloc/free repro must compile to prove gate catch: "
                    f"{compile_errs}"
                )

    if failures:
        for f in failures:
            print(f"r7_wire_platform_split_gate self-test FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "r7_wire_platform_split_gate self-test: PASS "
        f"(structural={len(structural_mutations)}, "
        f"dependency_injections=real-API+factory+heap, "
        f"heap_apis={len(HEAP_API_INJECTIONS)}, "
        f"include_allowlist_mutations={len(include_mutations)}, "
        f"comment_noise=green, include_macro_splice=validate_red+compile_green, "
        f"heap_builtin=validate_red+compile_green, "
        f"aligned_alloc_repro=validate_red)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    return run_check() if args.command == "check" else run_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
