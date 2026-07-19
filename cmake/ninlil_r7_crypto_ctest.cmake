# R7 T0 private crypto CTest registration (docs/31, ADR-0011).
#
# Included only under NINLIL_BUILD_TESTS. Tests link the real production
# ninlil_runtime_private archive (portable wrapper + Host OpenSSL 3 adapter).
# Do not recompile production crypto sources into test-only duplicate objects.
# ESP mbedTLS adapter is not built or executed here.

if(NOT NINLIL_BUILD_TESTS)
    return()
endif()

if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
    message(FATAL_ERROR
        "NINLIL_BUILD_TESTS=ON requires NINLIL_R7_HOST_CRYPTO_ENABLED "
        "(OpenSSL 3 Host adapter for R7 private crypto)")
endif()

# ---------------------------------------------------------------------------
# C executables: production private archive only (no source-level copies)
# ---------------------------------------------------------------------------

add_executable(ninlil_r7_crypto_portable_test
    tests/radio/r7_crypto_portable_test.c
)
target_include_directories(ninlil_r7_crypto_portable_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
)
target_compile_definitions(ninlil_r7_crypto_portable_test PRIVATE
    NINLIL_R7_CRYPTO_TEST_BUILD=1)
target_link_libraries(ninlil_r7_crypto_portable_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_r7_crypto_portable_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_r7_crypto_portable_test)
add_test(
    NAME r7_crypto_portable_strict
    COMMAND ninlil_r7_crypto_portable_test
)

add_executable(ninlil_r7_crypto_openssl3_test
    tests/radio/r7_crypto_openssl3_test.c
)
target_include_directories(ninlil_r7_crypto_openssl3_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
)
# OpenSSL headers are for the host-only version probe; production keeps
# OpenSSL private on ninlil_runtime_private. Do not install this test.
target_link_libraries(ninlil_r7_crypto_openssl3_test PRIVATE
    ninlil_runtime_private
    ninlil
    OpenSSL::Crypto
)
set_target_properties(ninlil_r7_crypto_openssl3_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_r7_crypto_openssl3_test)
add_test(
    NAME r7_crypto_openssl3
    COMMAND ninlil_r7_crypto_openssl3_test
)

add_executable(ninlil_r7_crypto_vectors_bridge_test
    tests/radio/r7_crypto_vectors_bridge_test.c
)
target_include_directories(ninlil_r7_crypto_vectors_bridge_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
)
target_link_libraries(ninlil_r7_crypto_vectors_bridge_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_r7_crypto_vectors_bridge_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_r7_crypto_vectors_bridge_test)
add_test(
    NAME r7_crypto_vectors_bridge
    COMMAND ninlil_r7_crypto_vectors_bridge_test
)

# ---------------------------------------------------------------------------
# Python gates: zeroization, oracle, pin, platform split, stack
# ---------------------------------------------------------------------------

add_test(
    NAME r7_crypto_zeroization_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_zeroization_gate.py
        check
)
add_test(
    NAME r7_crypto_zeroization_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_zeroization_gate.py
        self-test
)

add_test(
    NAME r7_radio_wire_oracle_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_radio_wire_oracle.py
        self-test
)
add_test(
    NAME r7_radio_wire_oracle_verify
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_radio_wire_oracle.py
        verify-json
        --json
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio/private/r7_crypto_vectors.json
)

add_test(
    NAME r7_kat_pin
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_kat_pin.py
        check
)
add_test(
    NAME r7_kat_pin_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_kat_pin.py
        self-test
)
# Pin/self-test recompile their own bridge mutation probes; still require the
# production-linked bridge target to exist so CMake cannot drop the real link.
set_tests_properties(r7_kat_pin r7_kat_pin_self_test PROPERTIES
    DEPENDS r7_crypto_vectors_bridge)

add_test(
    NAME r7_crypto_platform_split_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_platform_split_gate.py
        check
)
add_test(
    NAME r7_crypto_platform_split_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_platform_split_gate.py
        self-test
)

# Fresh tests-OFF Release packaging for R7 private crypto (docs/31 §10–11):
# isolated subbuild, ctest -N = 0, bare all archive path-count 0, explicit
# ninlil_runtime_private path-count 1, portable/nonce/openssl3 members exact
# once, mbedtls/test/oracle/generated/seam 0, install public-only.
# Mutations live in tools/r7_crypto_tests_off_packaging_gate.py self-test.
add_test(
    NAME r7_crypto_tests_off_packaging_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_tests_off_packaging_gate.py
        check
        --src-root ${CMAKE_CURRENT_SOURCE_DIR}
        --generator ${CMAKE_GENERATOR}
)
add_test(
    NAME r7_crypto_tests_off_packaging_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_tests_off_packaging_gate.py
        self-test
        --src-root ${CMAKE_CURRENT_SOURCE_DIR}
)

# Single authority for CI required-name / profile checks (docs/31 §11).
# CI invokes tools/r7_t0_ctest_gate.py; self-test keeps the authority honest.
add_test(
    NAME r7_t0_ctest_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t0_ctest_gate.py
        self-test
)

# Stack: self-test always; production .su check only when not under sanitizers
# (same policy as n6_frame_stack_gate). Authority is production object dir.
add_test(
    NAME r7_crypto_stack_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_stack_gate.py
        self-test
)
if(NOT _ninlil_any_sanitizer_active)
    # docs/31 §11.6: .su ceiling plus compile_commands evidence for exact -O2
    # and -fstack-usage on portable/nonce production objects. When
    # CMAKE_EXPORT_COMPILE_COMMANDS is OFF the compile_commands path may be
    # absent — pass it only when the file exists at ctest time via a cmake -E
    # wrapper is awkward; instead always pass the conventional path and let
    # the gate fail closed if CI claimed Release authority without exporting.
    # Local Debug builds without export still pass .su-only when the path is
    # missing: gate treats missing file as error only when the flag is given.
    set(_r7_stack_gate_cmd
        ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_crypto_stack_gate.py
        check
        --su-dir
        ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ninlil_runtime_private.dir
    )
    if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json")
        list(APPEND _r7_stack_gate_cmd
            --compile-commands
            ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        )
    elseif(CMAKE_EXPORT_COMPILE_COMMANDS)
        # Configured to export but file not yet written — still require path so
        # post-build ctest cannot skip -O2 evidence.
        list(APPEND _r7_stack_gate_cmd
            --compile-commands
            ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        )
    endif()
    add_test(
        NAME r7_crypto_stack_gate
        COMMAND ${_r7_stack_gate_cmd}
    )
    # CTest DEPENDS names other tests, not targets. Link any R7 C test that
    # already builds ninlil_runtime_private so .su exists before the gate.
    set_tests_properties(r7_crypto_stack_gate PROPERTIES
        DEPENDS r7_crypto_portable_strict)
else()
    message(STATUS
        "r7_crypto_stack_gate: not registered under active sanitizer "
        "(production .su non-authoritative; self-test still enabled; "
        "non-sanitize CI owns .su)")
endif()
