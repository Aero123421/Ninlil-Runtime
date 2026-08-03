#!/usr/bin/env python3
"""Fail-closed structural gate for the R7 Host/ESP crypto source split.

This proves source authority and build wiring only.  It does not substitute
for compiling OpenSSL 3, ESP-IDF/mbedTLS, KAT execution, or HIL.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Mapping


REPO = pathlib.Path(__file__).resolve().parents[1]
AUTHORITY = "cmake/ninlil_r7_crypto_sources.cmake"
RUNTIME_AUTHORITY = "cmake/ninlil_runtime_private_sources.cmake"
HOST_CMAKE = "CMakeLists.txt"
ESP_CMAKE = "ports/esp-idf/components/ninlil/CMakeLists.txt"

PORTABLE_VAR = "NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES"
HOST_VAR = "NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES"
ESP_VAR = "NINLIL_R7_CRYPTO_ESP_RELATIVE_SOURCES"

EXACT = {
    PORTABLE_VAR: (
        "src/radio/r7_crypto_portable.c",
        "src/radio/r7_crypto_nonce.c",
    ),
    HOST_VAR: ("src/radio/r7_crypto_openssl3.c",),
    ESP_VAR: ("ports/esp-idf/src/r7_crypto_mbedtls.c",),
}

READ_PATHS = (
    AUTHORITY,
    RUNTIME_AUTHORITY,
    HOST_CMAKE,
    ESP_CMAKE,
    "src/radio/r7_crypto_portable.c",
    "src/radio/r7_crypto_nonce.c",
    "src/radio/r7_crypto_provider.h",
    "src/radio/r7_crypto_openssl3.c",
    "src/radio/r7_crypto_openssl3.h",
    "ports/esp-idf/src/r7_crypto_mbedtls.c",
    "ports/esp-idf/src/r7_crypto_mbedtls.h",
)


def read_texts() -> dict[str, str]:
    texts: dict[str, str] = {}
    for relative in READ_PATHS:
        path = REPO / relative
        try:
            texts[relative] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RuntimeError(f"cannot read {relative}: {exc}") from exc
    return texts


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
    """Return full text of each top-level install(...) call, multi-line aware.

    Line-filter approaches (``if \"install\" in line``) miss:

        install(FILES
          src/radio/r7_crypto_provider.h
          DESTINATION include)

    because private paths sit on lines that do not contain the word install.
    """
    bodies: list[str] = []
    # Match install token followed by optional whitespace and open paren.
    for match in re.finditer(r"\binstall\s*\(", text, re.IGNORECASE):
        start = match.end()  # just after '('
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


def private_r7_in_install_rules(host: str) -> list[str]:
    """Detect private R7 crypto artifacts inside any install(...) body."""
    errors: list[str] = []
    needles = (
        "r7_crypto",
        "tests/radio/private",
        "r7_crypto_vectors",
        "r7_crypto_provider.h",
        "r7_crypto_openssl3.h",
        "r7_crypto_mbedtls",
    )
    for index, body in enumerate(cmake_install_call_bodies(host), 1):
        lower = body.lower()
        for needle in needles:
            if needle.lower() in lower:
                errors.append(
                    f"R7 private crypto artifact in install() call #{index}: {needle}"
                )
                break
    return errors


def validate_texts(texts: Mapping[str, str]) -> list[str]:
    errors: list[str] = []
    authority = texts[AUTHORITY]
    parsed: dict[str, tuple[str, ...]] = {}
    for variable, expected in EXACT.items():
        entries = cmake_set_entries(authority, variable)
        if entries is None:
            errors.append(f"authority missing {variable}")
            continue
        parsed[variable] = entries
        if entries != expected:
            errors.append(
                f"{variable}: exact source set mismatch got={entries!r} want={expected!r}"
            )
        if len(entries) != len(set(entries)):
            errors.append(f"{variable}: duplicate source")
        for entry in entries:
            if entry.startswith(("tests/", "tools/")) or ".gen." in entry:
                errors.append(f"{variable}: non-production source: {entry}")

    all_sets = [set(parsed.get(variable, ())) for variable in EXACT]
    for left in range(len(all_sets)):
        for right in range(left + 1, len(all_sets)):
            overlap = sorted(all_sets[left] & all_sets[right])
            if overlap:
                errors.append(f"platform source sets overlap: {overlap}")

    runtime = texts[RUNTIME_AUTHORITY]
    require_once(
        errors,
        runtime,
        'include("${CMAKE_CURRENT_LIST_DIR}/ninlil_r7_crypto_sources.cmake")',
        "portable authority include",
    )
    runtime_append = re.search(
        r"\blist\s*\(\s*APPEND\s+NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\b(.*?)\)",
        runtime,
        re.DOTALL,
    )
    if runtime_append is None:
        errors.append("shared portable runtime append block missing")
    else:
        append_body = runtime_append.group(1)
        require_once(
            errors,
            append_body,
            "${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}",
            "portable runtime expansion",
        )
        if "${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}" in append_body:
            errors.append("Host adapter leaked into shared portable runtime list")
        if "${NINLIL_R7_CRYPTO_ESP_RELATIVE_SOURCES}" in append_body:
            errors.append("ESP adapter leaked into shared portable runtime list")
    if runtime.count("${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}") != 2:
        errors.append("portable source variable must appear in runtime and VLA sets")
    if runtime.count("${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}") != 1:
        errors.append("Host source variable must appear only in the Host VLA set")
    if "${NINLIL_R7_CRYPTO_ESP_RELATIVE_SOURCES}" in runtime:
        errors.append("ESP adapter variable must not appear in shared authority")

    host = texts[HOST_CMAKE]
    r7_host_block_match = re.search(
        r"set\(NINLIL_R7_HOST_CRYPTO_ENABLED FALSE\)"
        r"(?P<body>.*?)"
        r"set\(NINLIL_R7_HOST_CRYPTO_ENABLED TRUE\)\s*endif\(\)",
        host,
        re.DOTALL,
    )
    if r7_host_block_match is None:
        errors.append("Host R7 OpenSSL discovery block missing")
    else:
        r7_host_block = r7_host_block_match.group("body")
        require_once(
            errors,
            r7_host_block,
            "find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)",
            "Host OpenSSL discovery",
        )
        # Scope the exact-major check to the R7 discovery block. Other Host
        # transports have their own OpenSSL checks and cannot satisfy this one.
        if "OPENSSL_VERSION VERSION_LESS \"3\"" not in r7_host_block and (
            "OPENSSL_VERSION VERSION_LESS 3" not in r7_host_block
        ):
            errors.append(
                "Host CMake missing OpenSSL major lower-bound (VERSION_LESS 3)"
            )
        has_upper_bound = (
            "NOT OPENSSL_VERSION VERSION_LESS \"4\"" in r7_host_block
            or "NOT OPENSSL_VERSION VERSION_LESS 4" in r7_host_block
            or "OPENSSL_VERSION VERSION_GREATER_EQUAL \"4\"" in r7_host_block
            or "OPENSSL_VERSION VERSION_GREATER_EQUAL 4" in r7_host_block
        )
        if not has_upper_bound:
            errors.append(
                "Host CMake missing OpenSSL major upper-bound (<4 / exact 3)"
            )
    private_host_sources = re.search(
        r"target_sources\s*\(\s*ninlil_runtime_private\s+PRIVATE\s+"
        r"\$\{NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES\}\s*\)",
        host,
        re.DOTALL,
    )
    if private_host_sources is None:
        errors.append("Host private target adapter expansion missing")
    public_runtime_sources = re.search(
        r"add_library\s*\(\s*ninlil_runtime\s+STATIC\b(.*?)\)",
        host,
        re.DOTALL,
    )
    if public_runtime_sources is None:
        errors.append("installable Host Runtime target missing")
    elif public_runtime_sources.group(1).count(
        "${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}"
    ) != 1:
        errors.append(
            "installable Host Runtime must carry the Host adapter exactly once"
        )
    if host.count("${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}") != 2:
        errors.append(
            "Host adapter variable must appear exactly once in the private "
            "target and once in the installable Host Runtime"
        )
    require_once(
        errors,
        host,
        "target_link_libraries(ninlil_runtime_private PRIVATE OpenSSL::Crypto)",
        "Host private crypto link",
    )
    public_runtime_link = re.search(
        r"target_link_libraries\s*\(\s*ninlil_runtime\b(.*?)\)",
        host,
        re.DOTALL,
    )
    if public_runtime_link is None or public_runtime_link.group(1).count(
        "OpenSSL::Crypto"
    ) != 1:
        errors.append(
            "installable Host Runtime must link OpenSSL::Crypto exactly once"
        )
    if "${NINLIL_R7_CRYPTO_ESP_RELATIVE_SOURCES}" in host:
        errors.append("ESP adapter variable leaked into Host CMake")

    esp = texts[ESP_CMAKE]
    require_once(
        errors,
        esp,
        "foreach(_rel IN LISTS NINLIL_R7_CRYPTO_ESP_RELATIVE_SOURCES)",
        "ESP adapter expansion",
    )
    # R7 ESP crypto requires idf_component_register PRIV_REQUIRES to list
    # bare "mbedtls" (not only a later idf::mbedtls link or a comment).
    # False-green: PRIV_REQUIRES in a comment + idf::mbedtls elsewhere.
    reg = re.search(
        r"idf_component_register\s*\(([\s\S]*?)\)\s*(?:\n|$)",
        esp,
    )
    if reg is None:
        errors.append("ESP component missing idf_component_register(...)")
    else:
        body = reg.group(1)
        priv = re.search(
            r"\bPRIV_REQUIRES\b([\s\S]*?)(?=\bREQUIRES\b|\bSRCS\b|\bINCLUDE_DIRS\b|\bPRIV_INCLUDE_DIRS\b|\Z)",
            body,
        )
        if priv is None:
            errors.append(
                "ESP idf_component_register missing PRIV_REQUIRES block"
            )
        else:
            tokens = re.findall(r"[A-Za-z0-9_.:${}]+", priv.group(1))
            if "mbedtls" not in tokens:
                errors.append(
                    "ESP idf_component_register PRIV_REQUIRES missing "
                    "exact token mbedtls"
                )
    if "${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}" in esp:
        errors.append("Host adapter variable leaked into ESP CMake")

    for relative in EXACT[PORTABLE_VAR]:
        source = texts[relative].lower()
        if re.search(r"#\s*include\s*[<\"](?:openssl|mbedtls)/", source):
            errors.append(f"portable source imports platform crypto header: {relative}")
    provider = texts["src/radio/r7_crypto_provider.h"].lower()
    if re.search(r"#\s*include\s*[<\"](?:openssl|mbedtls)/", provider):
        errors.append("private provider ABI imports a platform crypto header")
    if "mbedtls/" in texts["src/radio/r7_crypto_openssl3.c"].lower():
        errors.append("OpenSSL adapter imports mbedTLS")
    if "openssl/" in texts["ports/esp-idf/src/r7_crypto_mbedtls.c"].lower():
        errors.append("mbedTLS adapter imports OpenSSL")
    openssl_src = texts["src/radio/r7_crypto_openssl3.c"]
    if "OPENSSL_VERSION_MAJOR != 3" not in openssl_src and (
        "OPENSSL_VERSION_MAJOR !=3" not in openssl_src
    ):
        errors.append(
            "OpenSSL adapter must compile-error when OPENSSL_VERSION_MAJOR != 3"
        )

    errors.extend(private_r7_in_install_rules(host))
    return errors


def run_check() -> int:
    try:
        texts = read_texts()
    except RuntimeError as exc:
        print(f"r7 crypto platform split gate FAIL: {exc}", file=sys.stderr)
        return 1
    errors = validate_texts(texts)
    if errors:
        for error in errors:
            print(f"r7 crypto platform split gate FAIL: {error}", file=sys.stderr)
        return 1
    print(
        "r7 crypto platform split gate: PASS "
        "(portable=2 host-source=1 private+public consumers=2 esp=1)"
    )
    return 0


def run_self_test() -> int:
    try:
        baseline = read_texts()
    except RuntimeError as exc:
        print(f"r7 crypto platform split self-test FAIL: {exc}", file=sys.stderr)
        return 1
    if validate_texts(baseline):
        print("r7 crypto platform split self-test FAIL: baseline is red", file=sys.stderr)
        return 1

    mutations = (
        (AUTHORITY, "src/radio/r7_crypto_nonce.c", "src/radio/r7_crypto_openssl3.c"),
        (AUTHORITY, "ports/esp-idf/src/r7_crypto_mbedtls.c", "src/radio/r7_crypto_openssl3.c"),
        (
            HOST_CMAKE,
            "target_link_libraries(ninlil_runtime_private PRIVATE OpenSSL::Crypto)",
            "target_link_libraries(ninlil_runtime_private PRIVATE OpenSSL::Crypt0)",
        ),
        (
            HOST_CMAKE,
            "        ${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}\n"
            "    )\n"
            "    add_library(Ninlil::runtime ALIAS ninlil_runtime)",
            "    )\n"
            "    add_library(Ninlil::runtime ALIAS ninlil_runtime)",
        ),
        (
            HOST_CMAKE,
            "        PUBLIC\n"
            "            ninlil\n"
            "            OpenSSL::Crypto\n"
            "    )",
            "        PUBLIC\n"
            "            ninlil\n"
            "    )",
        ),
        (ESP_CMAKE, "        mbedtls\n", ""),
        (
            RUNTIME_AUTHORITY,
            "list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\n"
            "    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}\n"
            "    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}\n)",
            "list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES\n"
            "    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}\n)",
        ),
        (AUTHORITY, "src/radio/r7_crypto_nonce.c", "tests/radio/fake.c"),
        # Multi-line install(FILES private header...) false-green regression:
        # private path is NOT on the line containing "install".
        (
            HOST_CMAKE,
            "install(FILES LICENSE NOTICE THIRD-PARTY-NOTICES.md\n"
            "    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/ninlil)",
            "install(FILES\n"
            "    src/radio/r7_crypto_provider.h\n"
            "    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})",
        ),
        # Drop OpenSSL major upper bound → must go red (4.x would pass find_package 3).
        (
            HOST_CMAKE,
            "    if(OPENSSL_VERSION VERSION_LESS \"3\"\n"
            "            OR NOT OPENSSL_VERSION VERSION_LESS \"4\")\n"
            "        message(FATAL_ERROR\n"
            "            \"Ninlil R7 Host crypto requires OpenSSL major version exactly 3 \"\n"
            "            \"(found ${OPENSSL_VERSION})\")\n"
            "    endif()\n",
            "",
        ),
        # Major != 3 compile guard dropped from adapter.
        (
            "src/radio/r7_crypto_openssl3.c",
            "OPENSSL_VERSION_MAJOR != 3",
            "OPENSSL_VERSION_MAJOR < 3",
        ),
    )
    failures: list[str] = []
    for index, (path, old, new) in enumerate(mutations, 1):
        if baseline[path].count(old) != 1:
            failures.append(f"mutation {index} setup token count != 1")
            continue
        mutated = dict(baseline)
        mutated[path] = baseline[path].replace(old, new, 1)
        if not validate_texts(mutated):
            failures.append(f"mutation {index} escaped gate")
    if failures:
        for failure in failures:
            print(f"r7 crypto platform split self-test FAIL: {failure}", file=sys.stderr)
        return 1
    print(f"r7 crypto platform split self-test: PASS ({len(mutations)} mutations rejected)")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    args = parser.parse_args()
    return run_check() if args.command == "check" else run_self_test()


if __name__ == "__main__":
    raise SystemExit(main())
