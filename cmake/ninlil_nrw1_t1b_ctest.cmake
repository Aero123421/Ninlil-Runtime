# R7 T1b single source + CTest authority (docs/33, ADR-0013).
#
# This is the only T1b registration authority. Top-level CMakeLists.txt must
# include it exactly once after cmake/ninlil_runtime_private_sources.cmake and
# before add_library(ninlil_runtime_private). Test registration is a function
# called exactly once after that private target exists when NINLIL_BUILD_TESTS.
#
# Portable production source (Host + ESP via shared private list):
#   src/radio/r7_context_binding.c
# Do not recompile this source into test-only objects. Do not inject
# test/oracle/generated fixtures into the production list. Do not install.
# Does not claim ESP KAT / HIL / R7 complete / T1b Accepted.

# ---------------------------------------------------------------------------
# Exact portable production source set (docs/33 §1, §10)
# ---------------------------------------------------------------------------

set(NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES
    src/radio/r7_context_binding.c
)

# Append exactly once into shared private production + VLA authorities so Host
# and ESP (when they include this file after the shared private list) expand
# the binding TU exactly once. Guard against double-include duplication.
if(NOT DEFINED NINLIL_R7_BINDING_SOURCES_APPENDED)
    list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
        ${NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES}
    )
    list(APPEND NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES
        ${NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES}
    )
    set(NINLIL_R7_BINDING_SOURCES_APPENDED TRUE)
endif()

# ---------------------------------------------------------------------------
# CTest registration (called from top-level only when tests enabled)
# ---------------------------------------------------------------------------

function(ninlil_nrw1_t1b_register_tests)
    if(NOT NINLIL_BUILD_TESTS)
        return()
    endif()

    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "NINLIL_BUILD_TESTS=ON requires NINLIL_R7_HOST_CRYPTO_ENABLED "
            "(OpenSSL 3 Host adapter required for R7 T1b binding tests)")
    endif()

    # Portable strict: production private archive only (no second binding TU).
    add_executable(ninlil_r7_t1b_binding_portable_test
        tests/radio/private/r7_t1b_binding_test.c
    )
    target_include_directories(ninlil_r7_t1b_binding_portable_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio/private
    )
    target_compile_definitions(ninlil_r7_t1b_binding_portable_test PRIVATE
        NINLIL_R7_BINDING_TEST_BUILD=1
    )
    target_link_libraries(ninlil_r7_t1b_binding_portable_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_r7_t1b_binding_portable_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_r7_t1b_binding_portable_test)
    add_test(
        NAME nrw1_t1b_binding_portable_strict
        COMMAND ninlil_r7_t1b_binding_portable_test
    )

    # Vector bridge: production private archive + Host OpenSSL adapter only.
    add_executable(ninlil_r7_t1b_vectors_bridge_test
        tests/radio/r7_t1b_binding_vectors_bridge_test.c
    )
    target_include_directories(ninlil_r7_t1b_vectors_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio/private
    )
    target_link_libraries(ninlil_r7_t1b_vectors_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_r7_t1b_vectors_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_r7_t1b_vectors_bridge_test)
    add_test(
        NAME nrw1_t1b_vectors_bridge
        COMMAND ninlil_r7_t1b_vectors_bridge_test
    )

    # Oracle / pin / platform / packaging / stack / ctest authorities.
    add_test(
        NAME nrw1_t1b_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_binding_oracle.py
            self-test
    )
    add_test(
        NAME nrw1_t1b_oracle_verify
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_binding_oracle.py
            verify
    )

    add_test(
        NAME nrw1_t1b_kat_pin
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_kat_pin.py
            check
    )
    add_test(
        NAME nrw1_t1b_kat_pin_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_kat_pin.py
            self-test
    )
    set_tests_properties(nrw1_t1b_kat_pin nrw1_t1b_kat_pin_self_test PROPERTIES
        DEPENDS nrw1_t1b_vectors_bridge)

    add_test(
        NAME nrw1_t1b_platform_split_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_platform_split_gate.py
            check
    )
    add_test(
        NAME nrw1_t1b_platform_split_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_platform_split_gate.py
            self-test
    )

    add_test(
        NAME nrw1_t1b_tests_off_packaging_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_tests_off_packaging_gate.py
            check
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
            --generator ${CMAKE_GENERATOR}
    )
    add_test(
        NAME nrw1_t1b_tests_off_packaging_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_tests_off_packaging_gate.py
            self-test
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_test(
        NAME nrw1_t1b_ctest_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_ctest_gate.py
            self-test
    )

    add_test(
        NAME nrw1_t1b_stack_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_stack_gate.py
            self-test
    )
    # Production stack .su is non-authoritative under sanitizers (docs/33 §10).
    # Self-test remains registered; only the production stack check is omitted.
    if(NOT _ninlil_any_sanitizer_active)
        set(_r7_t1b_stack_gate_cmd
            ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_t1b_stack_gate.py
            check
            --su-dir
            ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ninlil_runtime_private.dir
        )
        if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json")
            list(APPEND _r7_t1b_stack_gate_cmd
                --compile-commands
                ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
            )
        elseif(CMAKE_EXPORT_COMPILE_COMMANDS)
            list(APPEND _r7_t1b_stack_gate_cmd
                --compile-commands
                ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
            )
        endif()
        add_test(
            NAME nrw1_t1b_stack_gate
            COMMAND ${_r7_t1b_stack_gate_cmd}
        )
        set_tests_properties(nrw1_t1b_stack_gate PROPERTIES
            DEPENDS nrw1_t1b_binding_portable_strict)
    else()
        message(STATUS
            "nrw1_t1b_stack_gate: not registered under active sanitizer "
            "(production .su non-authoritative; self-test still enabled)")
    endif()
endfunction()
