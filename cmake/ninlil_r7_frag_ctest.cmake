# R7 private NRW1 LINK/FRAG candidate — host CTest registration only.
# Source list authority: cmake/ninlil_r7_frag_sources.cmake (single).
# Not installed. Not public ABI. Not HIL/RF.
#
# ESP packaging is separate (ports/esp-idf/components/ninlil + Kconfig).
# This file must not be the only place the portable source list is defined.

include(${CMAKE_CURRENT_LIST_DIR}/ninlil_r7_frag_sources.cmake)

if(NOT NINLIL_ENABLE_R7_FRAG_PRIVATE)
    return()
endif()

if(NOT NINLIL_BUILD_TESTS)
    return()
endif()

if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
    message(WARNING
        "NINLIL_ENABLE_R7_FRAG_PRIVATE=ON but Host OpenSSL crypto disabled; "
        "skipping r7_frag CTest registration")
    return()
endif()

# Private static library — EXCLUDE_FROM_ALL, never installed.
add_library(ninlil_r7_frag_private STATIC EXCLUDE_FROM_ALL
    ${NINLIL_R7_FRAG_PORTABLE_RELATIVE_SOURCES}
    ${NINLIL_V1_LAB_RADIO_PATH_RELATIVE_SOURCES}
)
target_include_directories(ninlil_r7_frag_private PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/drivers/sx126x
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(ninlil_r7_frag_private PRIVATE
    NINLIL_R7_FRAG_WITH_N6=1
    NINLIL_R7_FRAG_PRIVATE=1
)
target_link_libraries(ninlil_r7_frag_private PRIVATE
    ninlil_runtime_private
    ninlil_sx1262
    ninlil
)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_link_libraries(ninlil_r7_frag_private PRIVATE OpenSSL::Crypto)
endif()
set_target_properties(ninlil_r7_frag_private PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_private)

# Exact stack-usage artifacts for every production FRAG source (ceiling 4096).
# Host gate: tools/r7_frag_stack_gate.py --su-dir <object dir>.
# ASan/UBSan inflate frames and rewrite .su kind to dynamic — skip
# -Wframe-larger-than under sanitizer; still emit .su when supported.
foreach(_r7_frag_src IN LISTS NINLIL_R7_FRAG_PORTABLE_RELATIVE_SOURCES)
    if(DEFINED _ninlil_any_sanitizer_active AND _ninlil_any_sanitizer_active)
        set_source_files_properties(${_r7_frag_src} PROPERTIES
            COMPILE_OPTIONS "-fstack-usage"
        )
    else()
        set_source_files_properties(${_r7_frag_src} PROPERTIES
            COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=4096"
        )
    endif()
endforeach()

add_test(
    NAME nrw1_frag_radio_wire_v1_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_radio_wire_v1_materialize.py
        self-test
)
add_test(
    NAME nrw1_frag_radio_wire_v1_verify
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_radio_wire_v1_materialize.py
        verify
)
add_test(
    NAME nrw1_frag_stack_gate_structural
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_frag_stack_gate.py
        check
)
add_test(
    NAME nrw1_frag_stack_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_frag_stack_gate.py
        self-test
)
# After private lib build, re-check with host .su artifacts.
# Sanitizer builds rewrite .su kind to dynamic and inflate frames — register
# presence without hiding the authoritative bounded path. Normal builds omit
# --allow-dynamic, reject unbounded dynamic rows, and enforce the 4096 ceiling
# for both static and compiler-proven dynamic,bounded rows.
if(DEFINED _ninlil_any_sanitizer_active AND _ninlil_any_sanitizer_active)
    add_test(
        NAME nrw1_frag_stack_gate_host_su
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_frag_stack_gate.py
            check
            --allow-dynamic
            --su-dir ${CMAKE_BINARY_DIR}/CMakeFiles/ninlil_r7_frag_private.dir
    )
else()
    add_test(
        NAME nrw1_frag_stack_gate_host_su
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_frag_stack_gate.py
            check
            --su-dir ${CMAKE_BINARY_DIR}/CMakeFiles/ninlil_r7_frag_private.dir
    )
endif()
set_tests_properties(nrw1_frag_stack_gate_host_su PROPERTIES
    FIXTURES_REQUIRED r7_frag_private_build
)

add_executable(ninlil_r7_frag_state_test EXCLUDE_FROM_ALL
    tests/radio/r7_frag/r7_frag_state_test.c
)
target_include_directories(ninlil_r7_frag_state_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
)
target_link_libraries(ninlil_r7_frag_state_test PRIVATE ninlil_r7_frag_private)
set_target_properties(ninlil_r7_frag_state_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_state_test)
add_test(NAME nrw1_frag_state_private COMMAND ninlil_r7_frag_state_test)

add_executable(ninlil_r7_frag_ack_ledger_test EXCLUDE_FROM_ALL
    tests/radio/r7_frag/r7_frag_ack_ledger_test.c
)
target_include_directories(ninlil_r7_frag_ack_ledger_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
)
target_link_libraries(ninlil_r7_frag_ack_ledger_test PRIVATE ninlil_r7_frag_private)
set_target_properties(ninlil_r7_frag_ack_ledger_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_ack_ledger_test)
add_test(NAME nrw1_frag_ack_ledger_private COMMAND ninlil_r7_frag_ack_ledger_test)

add_executable(ninlil_r7_frag_durable_snapshot_test EXCLUDE_FROM_ALL
    tests/radio/r7_frag/r7_frag_durable_snapshot_test.c
)
target_include_directories(ninlil_r7_frag_durable_snapshot_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
)
target_link_libraries(ninlil_r7_frag_durable_snapshot_test PRIVATE ninlil_r7_frag_private)
set_target_properties(ninlil_r7_frag_durable_snapshot_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_durable_snapshot_test)
add_test(NAME nrw1_frag_durable_snapshot_private COMMAND ninlil_r7_frag_durable_snapshot_test)

add_executable(ninlil_r7_frag_session_test EXCLUDE_FROM_ALL
    tests/radio/r7_frag/r7_frag_session_test.c
)
target_include_directories(ninlil_r7_frag_session_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
)
target_link_libraries(ninlil_r7_frag_session_test PRIVATE
    ninlil_r7_frag_private
    ninlil_runtime_private
    ninlil
)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_link_libraries(ninlil_r7_frag_session_test PRIVATE OpenSSL::Crypto)
endif()
set_target_properties(ninlil_r7_frag_session_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_session_test)
add_test(NAME nrw1_frag_session_private COMMAND ninlil_r7_frag_session_test)

add_executable(ninlil_r7_frag_lifecycle_matrix_test EXCLUDE_FROM_ALL
    tests/radio/r7_frag/r7_frag_lifecycle_matrix_test.c
)
target_include_directories(ninlil_r7_frag_lifecycle_matrix_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
)
target_link_libraries(ninlil_r7_frag_lifecycle_matrix_test PRIVATE
    ninlil_r7_frag_private
    ninlil_runtime_private
    ninlil
)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_link_libraries(ninlil_r7_frag_lifecycle_matrix_test PRIVATE
        OpenSSL::Crypto)
endif()
set_target_properties(ninlil_r7_frag_lifecycle_matrix_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_lifecycle_matrix_test)
add_test(NAME nrw1_frag_lifecycle_matrix_private
    COMMAND ninlil_r7_frag_lifecycle_matrix_test)

add_executable(ninlil_r7_frag_completion_test EXCLUDE_FROM_ALL
    tests/radio/r7_frag/r7_frag_completion_test.c
)
target_include_directories(ninlil_r7_frag_completion_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
)
target_link_libraries(ninlil_r7_frag_completion_test PRIVATE
    ninlil_r7_frag_private
    ninlil_runtime_private
    ninlil
)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_link_libraries(ninlil_r7_frag_completion_test PRIVATE OpenSSL::Crypto)
endif()
set_target_properties(ninlil_r7_frag_completion_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_completion_test)
add_test(NAME nrw1_frag_completion_private COMMAND ninlil_r7_frag_completion_test)

# ---------------------------------------------------------------------------
# Wire fixture codec/crypto KAT (production codec + fixed vectors + negatives).
# HIL remains NOT_RUN in fixture status field.
#
# DUPLICATE-OWNER GUARD (r7_crypto_stack_gate): this target MUST list ONLY the
# test translation unit below. Production r7_crypto_portable.c / r7_crypto_nonce.c
# / r7_wire_codec.c / r7_frag_wire.c / r7_frag_core.c MUST come from linked
# archives ninlil_runtime_private + ninlil_r7_frag_private. Re-adding those .c
# files as sources is a permanent RED (third compile owner).
# packaging_gate enforces this shape.
# ---------------------------------------------------------------------------
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    add_executable(ninlil_r7_radio_wire_v1_fixture_test EXCLUDE_FROM_ALL
        tests/radio/r7_frag/r7_radio_wire_v1_fixture_test.c
    )
    target_include_directories(ninlil_r7_radio_wire_v1_fixture_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio/r7_frag
    )
    target_link_libraries(ninlil_r7_radio_wire_v1_fixture_test PRIVATE
        ninlil_r7_frag_private
        ninlil_runtime_private
        ninlil
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_r7_radio_wire_v1_fixture_test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_strict_warnings(ninlil_r7_radio_wire_v1_fixture_test)
    add_test(NAME nrw1_frag_radio_wire_v1_fixture_codec
        COMMAND ninlil_r7_radio_wire_v1_fixture_test)
    set_tests_properties(nrw1_frag_radio_wire_v1_fixture_codec PROPERTIES
        FIXTURES_REQUIRED r7_frag_private_build)
endif()

# Deterministic target smoke (LINK_ACK / multi-frag / reorder / restart).
add_executable(ninlil_r7_frag_target_smoke_test EXCLUDE_FROM_ALL
    tests/radio/r7_frag/r7_frag_target_smoke_test.c
)
target_include_directories(ninlil_r7_frag_target_smoke_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
)
target_link_libraries(ninlil_r7_frag_target_smoke_test PRIVATE
    ninlil_r7_frag_private
    ninlil_runtime_private
    ninlil
)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_link_libraries(ninlil_r7_frag_target_smoke_test PRIVATE OpenSSL::Crypto)
endif()
set_target_properties(ninlil_r7_frag_target_smoke_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_r7_frag_target_smoke_test)
add_test(NAME nrw1_frag_target_smoke_private
    COMMAND ninlil_r7_frag_target_smoke_test)

# Production integration: N6 testbuild + R2 + R1 + L1 ledger (host-only).
if(TARGET ninlil_n6_store_testbuild)
    add_executable(ninlil_r7_frag_prod_integration_test EXCLUDE_FROM_ALL
        tests/radio/r7_frag/r7_frag_prod_integration_test.c
        tests/support/n6_mem_storage.c
        tests/support/n6_local_identity_fixture.c
        tests/support/radio_hal_spy.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
    )
    target_compile_definitions(ninlil_r7_frag_prod_integration_test PRIVATE
        NINLIL_N6_TEST_BUILD=1
    )
    target_include_directories(ninlil_r7_frag_prod_integration_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_r7_frag_prod_integration_test PRIVATE
        ninlil_r7_frag_private
        ninlil_n6_store_testbuild
        ninlil_runtime_private
        ninlil
    )
    if(NINLIL_R7_HOST_CRYPTO_ENABLED)
        target_link_libraries(ninlil_r7_frag_prod_integration_test PRIVATE
            OpenSSL::Crypto)
    endif()
    set_target_properties(ninlil_r7_frag_prod_integration_test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_strict_warnings(ninlil_r7_frag_prod_integration_test)
    add_test(NAME nrw1_frag_prod_integration_private
        COMMAND ninlil_r7_frag_prod_integration_test)

    add_executable(ninlil_v1_lab_radio_packet_link_vertical_test
        EXCLUDE_FROM_ALL
        tests/transport/fabric_v1/v1_lab_radio_packet_link_vertical_test.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
        tests/support/fake_byte_stream.c
        tests/support/sx1262_bus_spy.c
    )
    target_include_directories(
        ninlil_v1_lab_radio_packet_link_vertical_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/drivers/sx126x
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(
        ninlil_v1_lab_radio_packet_link_vertical_test PRIVATE
        ninlil_r7_frag_private
        ninlil_runtime_private
        ninlil_sx1262
        ninlil_fabric_v1
        ninlil
        OpenSSL::Crypto
    )
    set_target_properties(
        ninlil_v1_lab_radio_packet_link_vertical_test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_strict_warnings(
        ninlil_v1_lab_radio_packet_link_vertical_test)
    add_test(NAME v1_lab_radio_packet_link_vertical
        COMMAND ninlil_v1_lab_radio_packet_link_vertical_test)
endif()

set(_r7_frag_test_tgts
    ninlil_r7_frag_state_test
    ninlil_r7_frag_ack_ledger_test
    ninlil_r7_frag_durable_snapshot_test
    ninlil_r7_frag_session_test
    ninlil_r7_frag_lifecycle_matrix_test
    ninlil_r7_frag_completion_test
    ninlil_r7_frag_target_smoke_test
)
set(_r7_frag_test_names
    nrw1_frag_state_private
    nrw1_frag_ack_ledger_private
    nrw1_frag_durable_snapshot_private
    nrw1_frag_session_private
    nrw1_frag_lifecycle_matrix_private
    nrw1_frag_completion_private
    nrw1_frag_target_smoke_private
)
if(TARGET ninlil_r7_radio_wire_v1_fixture_test)
    list(APPEND _r7_frag_test_tgts ninlil_r7_radio_wire_v1_fixture_test)
endif()
if(TARGET ninlil_r7_frag_prod_integration_test)
    list(APPEND _r7_frag_test_tgts ninlil_r7_frag_prod_integration_test)
    list(APPEND _r7_frag_test_names nrw1_frag_prod_integration_private)
endif()
if(TARGET ninlil_v1_lab_radio_packet_link_vertical_test)
    list(APPEND _r7_frag_test_tgts
        ninlil_v1_lab_radio_packet_link_vertical_test)
    list(APPEND _r7_frag_test_names
        v1_lab_radio_packet_link_vertical)
endif()

set_tests_properties(${_r7_frag_test_names}
    PROPERTIES FIXTURES_REQUIRED r7_frag_private_build)
add_test(NAME nrw1_frag_private_build
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
        --target ${_r7_frag_test_tgts}
)
set_tests_properties(nrw1_frag_private_build PROPERTIES
    FIXTURES_SETUP r7_frag_private_build)
