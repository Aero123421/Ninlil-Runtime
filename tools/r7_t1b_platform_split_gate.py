#!/usr/bin/env python3
"""Structural + dependency gate for R7 T1b binding source authority (docs/33 §1, §10).

Portable binding TU exact once on Host via single authority
``cmake/ninlil_nrw1_t1b_ctest.cmake`` (source list + private/VLA append + test
registration function). Expected ESP component contract: include the same
authority after the shared private list so the binding TU expands once.

Production binding sources must not include/call OS/heap/VLA/platform crypto,
KGuard, N6, R2/R5/W1/radio HAL, or use calloc/realloc/free/malloc/alloca.
Crypto only via T0 ``ninlil_r7_crypto_*`` wrappers. Exact six production APIs.
Test seams excluded from production (guarded by NINLIL_R7_BINDING_TEST_BUILD).

Does not claim ESP KAT / HIL / T1b Accepted / R7 complete.
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
AUTHORITY = "cmake/ninlil_nrw1_t1b_ctest.cmake"
RUNTIME_AUTHORITY = "cmake/ninlil_runtime_private_sources.cmake"
HOST_CMAKE = "CMakeLists.txt"
ESP_CMAKE = "ports/esp-idf/components/ninlil/CMakeLists.txt"
BINDING_C = "src/radio/r7_context_binding.c"
BINDING_H = "src/radio/r7_context_binding.h"
PORTABLE_VAR = "NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES"
EXACT = {PORTABLE_VAR: ("src/radio/r7_context_binding.c",)}
READ_PATHS = (
    AUTHORITY,
    RUNTIME_AUTHORITY,
    HOST_CMAKE,
    ESP_CMAKE,
    BINDING_C,
    BINDING_H,
)

EXACT_APIS = (
    "ninlil_r7_encode_hop_binding",
    "ninlil_r7_encode_e2e_binding",
    "ninlil_r7_digest_hop_binding",
    "ninlil_r7_digest_e2e_binding",
    "ninlil_r7_derive_hop_key_bundle_verified",
    "ninlil_r7_derive_e2e_key_bundle_verified",
)
BINDING_TEST_SEAM_MACRO = "NINLIL_R7_BINDING_TEST_BUILD"
BINDING_TEST_SEAMS = (
    "ninlil_r7_binding_test_spans_forbidden",
    "ninlil_r7_binding_test_set_secret_probe",
)

BINDING_C_ALLOWED_INCLUDES: tuple[str, ...] = (
    '"r7_context_binding.h"',
    "<stdatomic.h>",
)
BINDING_H_ALLOWED_INCLUDES: tuple[str, ...] = (
    '"r7_crypto_provider.h"',
    "<stddef.h>",
    "<stdint.h>",
)
_INCLUDE_ANY_DIRECTIVE = re.compile(
    r"^[ \t]*#[ \t]*(include(?:_next)?)[ \t]*(.*)$",
    re.MULTILINE,
)
_INCLUDE_LITERAL_OPERAND = re.compile(r'(?:"[^"\r\n]+"|<[^>\r\n]+>)')

BANNED_INCLUDE_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r'#\s*include\s*[<"]\s*radio_hal\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*profile_loader\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*pcp_authority\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*n6_[A-Za-z0-9_/.-]+\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*openssl/'),
    re.compile(r'#\s*include\s*[<"]\s*mbedtls/'),
    re.compile(r'#\s*include\s*[<"]\s*r7_crypto_openssl3\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*r7_crypto_mbedtls\.h\s*[>"]'),
    re.compile(r'#\s*include\s*[<"]\s*r7_wire_codec\.h\s*[>"]'),
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
    re.compile(r'#\s*include\s*[<"]\s*kguard', re.IGNORECASE),
)

BANNED_TOKEN_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("malloc", re.compile(r"\b(?:__builtin_)?malloc\s*\(")),
    ("calloc", re.compile(r"\b(?:__builtin_)?calloc\s*\(")),
    ("realloc", re.compile(r"\b(?:__builtin_)?realloc\s*\(")),
    ("free", re.compile(r"\b(?:__builtin_)?free\s*\(")),
    ("alloca", re.compile(r"\b(?:__builtin_)?alloca\s*\(")),
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
    ("ninlil_n6_", re.compile(r"\bninlil_n6_[A-Za-z0-9_]+\b")),
    ("ninlil_pcp_", re.compile(r"\bninlil_pcp_[A-Za-z0-9_]+\b")),
    ("ninlil_r5_", re.compile(r"\bninlil_r5_[A-Za-z0-9_]+\b")),
    ("ninlil_radio_hal_", re.compile(r"\bninlil_radio_hal_[A-Za-z0-9_]+\b")),
    ("ninlil_r7_wire_", re.compile(r"\bninlil_r7_wire_[A-Za-z0-9_]+\b")),
    ("EVP_", re.compile(r"\bEVP_[A-Za-z0-9_]+\b")),
    ("mbedtls_", re.compile(r"\bmbedtls_[A-Za-z0-9_]+\b")),
)

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
        out.append(source[i])
        i += 1
    return "".join(out)


def strip_c_comments_and_strings(source: str) -> str:
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
    errors: list[str] = []
    got = extract_includes_after_comment_strip(source)
    want = Counter(allowed)
    have = Counter(got)
    if have != want:
        missing = sorted((want - have).elements())
        extra = sorted((have - want).elements())
        if missing:
            errors.append(
                f"{label}: missing required include(s) exact-once: {missing}"
            )
        if extra:
            errors.append(
                f"{label}: extra/non-allowlisted include(s): {extra}"
            )
        if not missing and not extra and have != want:
            for inc in sorted(set(want) | set(have)):
                if have.get(inc, 0) != want.get(inc, 0):
                    errors.append(
                        f"{label}: include {inc!r} count got={have.get(inc, 0)} "
                        f"want={want.get(inc, 0)}"
                    )
        if not errors:
            errors.append(
                f"{label}: include multiset mismatch got={got!r} want={list(allowed)!r}"
            )
    return errors


def dependency_errors(label: str, source: str) -> list[str]:
    errors: list[str] = []
    no_comments = strip_c_comments(source)
    for pattern in BANNED_INCLUDE_RES:
        if pattern.search(no_comments):
            errors.append(
                f"{label}: banned include matched {pattern.pattern}"
            )
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


def strip_exact_binding_test_seam(header: str, errors: list[str]) -> str:
    """Remove the exact test-only seam block before API exact-set audit."""
    pattern = re.compile(
        r"#ifdef\s+NINLIL_R7_BINDING_TEST_BUILD\s*\n"
        r".*?"
        r"#endif\s*/\*\s*NINLIL_R7_BINDING_TEST_BUILD\s*\*/",
        re.MULTILINE | re.DOTALL,
    )
    matches = list(pattern.finditer(header))
    if len(matches) != 1:
        # Fallback: count macro occurrences and strip last ifdef block loosely.
        if header.count(BINDING_TEST_SEAM_MACRO) < 1:
            errors.append("binding header missing test seam macro guard")
            return header
        # Still try to strip any #ifdef NINLIL_R7_BINDING_TEST_BUILD ... #endif
        loose = re.compile(
            r"#ifdef\s+NINLIL_R7_BINDING_TEST_BUILD\b.*?#endif[^\n]*\n?",
            re.MULTILINE | re.DOTALL,
        )
        loose_matches = list(loose.finditer(header))
        if len(loose_matches) != 1:
            errors.append(
                "binding header test seam must be one exact conditional block"
            )
            return header
        return header[: loose_matches[0].start()] + header[loose_matches[0].end() :]
    return header[: matches[0].start()] + header[matches[0].end() :]


def binding_test_seam_source_errors(source: str) -> list[str]:
    if source.count(BINDING_TEST_SEAM_MACRO) < 1:
        return ["binding source missing test seam macro"]
    for seam in BINDING_TEST_SEAMS:
        if seam not in source:
            return [f"binding source missing test seam {seam}"]
        # Must only appear under #ifdef test build (at least one occurrence).
        if not re.search(
            rf"#ifdef\s+{BINDING_TEST_SEAM_MACRO}[\s\S]*?\b{re.escape(seam)}\b",
            source,
        ):
            return [f"binding test seam {seam} not under TEST_BUILD guard"]
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

    # Authority must append portable sources to private + VLA lists exactly.
    if not re.search(
        r"list\s*\(\s*APPEND\s+NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\s+"
        r"\$\{NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES\}\s*\)",
        authority,
    ):
        errors.append("authority missing private runtime append of binding sources")
    if not re.search(
        r"list\s*\(\s*APPEND\s+NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES\s+"
        r"\$\{NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES\}\s*\)",
        authority,
    ):
        errors.append("authority missing VLA append of binding sources")
    if "function(ninlil_nrw1_t1b_register_tests)" not in authority and (
        "function(ninlil_nrw1_t1b_register_tests )" not in authority
    ):
        # tolerate whitespace variants
        if not re.search(
            r"function\s*\(\s*ninlil_nrw1_t1b_register_tests\s*\)", authority
        ):
            errors.append("authority missing ninlil_nrw1_t1b_register_tests function")

    # Never recompile production binding into test targets.
    if re.search(
        r"add_executable\s*\([^)]*r7_context_binding\.c",
        authority,
        re.DOTALL,
    ):
        errors.append("authority recompiles production binding into a test target")
    if "src/radio/r7_context_binding.c" in re.findall(
        r"add_executable\s*\((.*?)\)", authority, re.DOTALL
    ):
        # crude: if binding.c appears inside any add_executable body
        for m in re.finditer(r"add_executable\s*\((.*?)\)", authority, re.DOTALL):
            if "r7_context_binding.c" in m.group(1):
                errors.append(
                    "authority lists r7_context_binding.c in add_executable"
                )

    host = texts[HOST_CMAKE]
    require_once(
        errors,
        host,
        "cmake/ninlil_nrw1_t1b_ctest.cmake",
        "Host T1b authority include path",
    )
    # Include must appear after runtime private sources include.
    rt_pos = host.find("cmake/ninlil_runtime_private_sources.cmake")
    t1b_pos = host.find("cmake/ninlil_nrw1_t1b_ctest.cmake")
    if rt_pos < 0 or t1b_pos < 0 or t1b_pos < rt_pos:
        errors.append(
            "Host must include T1b authority after shared private source authority"
        )
    require_once(
        errors,
        host,
        "ninlil_nrw1_t1b_register_tests()",
        "Host T1b test registration call",
    )
    if "NINLIL_R7_BINDING_TEST_BUILD=1" not in host:
        errors.append("Host tests-ON private archive must define binding test seam")
    if "NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES" not in host:
        errors.append("Host missing binding compile-options foreach list")

    for body in cmake_install_call_bodies(host):
        lower = body.lower()
        for needle in (
            "r7_context_binding",
            "r7_t1b",
            "nrw1_t1b",
            "r7-t1b-binding",
        ):
            if needle in lower:
                errors.append(f"T1b private artifact in install(): {needle}")
                break

    # Expected ESP component contract: include the same T1b authority so the
    # portable binding TU expands into the component SRCS via the shared private
    # list append. Match the include() call itself (comments may mention the path).
    esp = texts[ESP_CMAKE]
    esp_include_token = (
        'include("${NINLIL_REPO_ROOT}/cmake/ninlil_nrw1_t1b_ctest.cmake")'
    )
    if esp.count(esp_include_token) != 1:
        errors.append(
            "ESP component must include ninlil_nrw1_t1b_ctest.cmake exactly once "
            f"(got {esp.count(esp_include_token)})"
        )
    if "NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES" not in esp:
        errors.append("ESP missing expansion of shared private source list")
    # Production ESP must not *define* the test seam macro (comments may name it).
    esp_no_comments = re.sub(r"(?m)#.*$", "", esp)
    if re.search(
        r"\bNINLIL_R7_BINDING_TEST_BUILD\b",
        esp_no_comments,
    ):
        errors.append("ESP must not define NINLIL_R7_BINDING_TEST_BUILD (production)")

    errors.extend(dependency_errors(BINDING_C, texts[BINDING_C]))
    errors.extend(dependency_errors(BINDING_H, texts[BINDING_H]))
    errors.extend(
        include_allowlist_errors(BINDING_C, texts[BINDING_C], BINDING_C_ALLOWED_INCLUDES)
    )
    errors.extend(
        include_allowlist_errors(BINDING_H, texts[BINDING_H], BINDING_H_ALLOWED_INCLUDES)
    )

    if '#include "r7_crypto_provider.h"' not in texts[BINDING_H]:
        errors.append("binding header must include r7_crypto_provider.h")
    # T0 wrapper-only crypto dependency.
    t0_calls = (
        "ninlil_r7_crypto_sha256",
        "ninlil_r7_crypto_hkdf_extract_sha256",
        "ninlil_r7_crypto_hkdf_expand_sha256",
    )
    for call in t0_calls:
        if call not in texts[BINDING_C]:
            errors.append(f"binding source must call T0 wrapper {call}")

    errors.extend(binding_test_seam_source_errors(texts[BINDING_C]))

    header = strip_exact_binding_test_seam(texts[BINDING_H], errors)
    # Public API declarations (int32_t return).
    declared = set(
        re.findall(
            r"\bint32_t\s+(ninlil_r7_(?:encode|digest|derive)_[A-Za-z0-9_]+)\s*\(",
            header,
        )
    )
    if declared != set(EXACT_APIS):
        missing = sorted(set(EXACT_APIS) - declared)
        extra = sorted(declared - set(EXACT_APIS))
        if missing:
            errors.append(f"header missing exact binding API: {missing}")
        if extra:
            errors.append(
                f"header declares non-exact ninlil_r7_* binding API: {extra}"
            )
    # Test seams must not remain after strip.
    for seam in BINDING_TEST_SEAMS:
        if seam in header:
            errors.append(f"test seam leaked outside TEST_BUILD guard: {seam}")

    source = texts[BINDING_C]
    defined = set(
        re.findall(
            r"(?m)^int32_t\s+(ninlil_r7_(?:encode|digest|derive)_[A-Za-z0-9_]+)\s*\(",
            source,
        )
    )
    if defined != set(EXACT_APIS):
        missing = sorted(set(EXACT_APIS) - defined)
        extra = sorted(defined - set(EXACT_APIS))
        if missing:
            errors.append(f"source missing exact binding API definition: {missing}")
        if extra:
            errors.append(
                f"source defines non-exact external binding API: {extra}"
            )

    # Authority must register exact docs/33 names (sample markers).
    for name in (
        "nrw1_t1b_binding_portable_strict",
        "nrw1_t1b_vectors_bridge",
        "nrw1_t1b_stack_gate",
    ):
        if name not in authority:
            errors.append(f"authority missing CTest name {name}")

    return errors


def portable_compile_proof(
    binding_c: pathlib.Path, include_dir: pathlib.Path
) -> list[str]:
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
        f"-I{include_dir}",
        str(binding_c),
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
        print(f"r7_t1b_platform_split_gate FAIL: {exc}", file=sys.stderr)
        return 1
    errors = validate_texts(texts)
    errors.extend(
        portable_compile_proof(REPO / BINDING_C, REPO / "src" / "radio")
    )
    if errors:
        for e in errors:
            print(f"r7_t1b_platform_split_gate FAIL: {e}", file=sys.stderr)
        return 1
    print(
        "r7_t1b_platform_split_gate: PASS "
        "(portable=1, apis=6, deps=clean, compile=ok, T0-only)"
    )
    return 0


def run_self_test() -> int:
    baseline = read_texts()
    base_errs = validate_texts(baseline)
    if base_errs:
        print(
            "r7_t1b_platform_split_gate self-test FAIL: baseline red:\n  "
            + "\n  ".join(base_errs),
            file=sys.stderr,
        )
        return 1
    if portable_compile_proof(REPO / BINDING_C, REPO / "src" / "radio"):
        print(
            "r7_t1b_platform_split_gate self-test FAIL: baseline compile red",
            file=sys.stderr,
        )
        return 1

    failures: list[str] = []

    structural_mutations = (
        (
            AUTHORITY,
            "set(NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES\n"
            "    src/radio/r7_context_binding.c\n"
            ")",
            "set(NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES\n"
            "    tests/radio/fake.c\n"
            ")",
        ),
        (
            AUTHORITY,
            "list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\n"
            "        ${NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES}\n"
            "    )",
            "list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\n"
            "        ${NINLIL_R7_BINDING_PORTABLE_MISSING}\n"
            "    )",
        ),
        (
            BINDING_H,
            '#include "r7_crypto_provider.h"',
            '#include "openssl/evp.h"',
        ),
        (
            HOST_CMAKE,
            "install(FILES LICENSE NOTICE THIRD-PARTY-NOTICES.md\n"
            "    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/ninlil)",
            "install(FILES\n"
            "    src/radio/r7_context_binding.h\n"
            "    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})",
        ),
        (
            BINDING_H,
            "int32_t ninlil_r7_derive_e2e_key_bundle_verified(",
            "int32_t ninlil_r7_derive_generic(\n"
            "    void);\nint32_t ninlil_r7_derive_e2e_key_bundle_verified(",
        ),
        (
            BINDING_H,
            "#ifdef NINLIL_R7_BINDING_TEST_BUILD\n",
            "#ifdef NINLIL_R7_BINDING_TEST_BUILD_RENAMED\n",
        ),
        (
            ESP_CMAKE,
            'include("${NINLIL_REPO_ROOT}/cmake/ninlil_nrw1_t1b_ctest.cmake")',
            'include("${NINLIL_REPO_ROOT}/cmake/ninlil_nrw1_t1b_ctest_MISSING.cmake")',
        ),
        (
            HOST_CMAKE,
            "NINLIL_R7_BINDING_TEST_BUILD=1",
            "NINLIL_R7_BINDING_TEST_BUILD_OFF=1",
        ),
    )
    for index, (path, old, new) in enumerate(structural_mutations, 1):
        if baseline[path].count(old) != 1:
            failures.append(
                f"structural mutation {index} setup token count != 1 "
                f"({path}: {old[:48]!r})"
            )
            continue
        mutated = dict(baseline)
        mutated[path] = baseline[path].replace(old, new, 1)
        if not validate_texts(mutated):
            failures.append(f"structural mutation {index} escaped")

    inject_anchor = '#include "r7_context_binding.h"\n'
    if baseline[BINDING_C].count(inject_anchor) != 1:
        failures.append("inject anchor count != 1 in binding .c")
    else:
        dep_injections: tuple[tuple[str, str], ...] = (
            ("radio_hal_include", '#include "radio_hal.h"\n'),
            ("profile_loader_include", '#include "profile_loader.h"\n'),
            ("pcp_authority_include", '#include "pcp_authority.h"\n'),
            ("n6_include", '#include "n6_record_codec.h"\n'),
            ("openssl3_factory_hdr", '#include "r7_crypto_openssl3.h"\n'),
            ("mbedtls_factory_hdr", '#include "r7_crypto_mbedtls.h"\n'),
            ("wire_codec_hdr", '#include "r7_wire_codec.h"\n'),
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
            (
                "ninlil_r7_wire_seal",
                "static int _w = ninlil_r7_wire_seal_e2e_single();\n",
            ),
            ("evp_call", "static void *_e = EVP_aes_128_gcm();\n"),
            ("mbedtls_call", "static int _m = mbedtls_sha256_ret(0,0,0,0);\n"),
        )
        for name, snippet in dep_injections + HEAP_API_INJECTIONS:
            mutated = dict(baseline)
            mutated[BINDING_C] = baseline[BINDING_C].replace(
                inject_anchor, inject_anchor + snippet, 1
            )
            errs = validate_texts(mutated)
            if not errs:
                failures.append(f"dependency mutation '{name}' escaped (no errors)")

    # Comment-only noise must stay green.
    noise = dict(baseline)
    noise[BINDING_C] = baseline[BINDING_C].replace(
        inject_anchor,
        inject_anchor
        + "/* no ninlil_n6_ ninlil_pcp_ ninlil_r5_ ninlil_radio_hal_ */\n"
        + "/* no r7_crypto_openssl3.h r7_crypto_mbedtls.h malloc free VLA */\n"
        + "/* #include <dirent.h> #include <stdio.h> */\n"
        + "// #include <dirent.h>\n"
        + "// calloc realloc unistd pthread\n",
        1,
    )
    if validate_texts(noise):
        failures.append(
            f"comment-only noise incorrectly red: {validate_texts(noise)}"
        )

    include_mutations: tuple[tuple[str, str, str, str], ...] = (
        (
            "dirent_add",
            BINDING_C,
            inject_anchor,
            inject_anchor + "#include <dirent.h>\n",
        ),
        (
            "c_allowed_delete",
            BINDING_C,
            '#include "r7_context_binding.h"\n',
            "/* deleted r7_context_binding.h include */\n",
        ),
        (
            "c_allowed_duplicate",
            BINDING_C,
            "#include <stdatomic.h>\n",
            "#include <stdatomic.h>\n#include <stdatomic.h>\n",
        ),
        (
            "h_allowed_delete",
            BINDING_H,
            "#include <stddef.h>\n",
            "/* deleted stddef.h include */\n",
        ),
        (
            "h_unknown_add",
            BINDING_H,
            '#include "r7_crypto_provider.h"\n',
            '#include "r7_crypto_provider.h"\n#include <dirent.h>\n',
        ),
    )
    for name, path, old, new in include_mutations:
        if baseline[path].count(old) != 1:
            failures.append(f"include mutation '{name}' setup token count != 1")
            continue
        mutated = dict(baseline)
        mutated[path] = baseline[path].replace(old, new, 1)
        if not validate_texts(mutated):
            failures.append(f"include mutation '{name}' escaped (no errors)")

    # Drop all T0 call sites for each wrapper must red. Replacement must not
    # retain the original token as a substring (e.g. foo → foo_MISSING fails).
    t0_drop_map = (
        ("ninlil_r7_crypto_sha256", "ninlil_r7_crypto_digest_renamed"),
        (
            "ninlil_r7_crypto_hkdf_extract_sha256",
            "ninlil_r7_crypto_hkdf_pull_renamed",
        ),
        (
            "ninlil_r7_crypto_hkdf_expand_sha256",
            "ninlil_r7_crypto_hkdf_push_renamed",
        ),
    )
    for call, replacement in t0_drop_map:
        if baseline[BINDING_C].count(call) < 1:
            failures.append(f"T0 call {call} not in baseline source")
            continue
        mutated = dict(baseline)
        mutated[BINDING_C] = baseline[BINDING_C].replace(call, replacement)
        if call in mutated[BINDING_C]:
            failures.append(f"T0 call drop setup incomplete for {call}")
            continue
        if not validate_texts(mutated):
            failures.append(f"T0 call drop {call} escaped")

    if failures:
        for f in failures:
            print(f"r7_t1b_platform_split_gate self-test FAIL: {f}", file=sys.stderr)
        return 1
    print(
        "r7_t1b_platform_split_gate self-test: PASS "
        f"(structural={len(structural_mutations)}, "
        f"dependency+heap injections red, include allowlist red, "
        f"comment_noise=green, T0-only)"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    return run_check() if args.command == "check" else run_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
