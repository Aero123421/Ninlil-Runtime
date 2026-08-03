# R7 T1 NRW1 SINGLE pure wire codec CTest registration (docs/32, ADR-0012).
#
# Included only under NINLIL_BUILD_TESTS. Tests link the real production
# ninlil_runtime_private archive (wire codec + T0 portable + Host OpenSSL 3).
# Do not recompile production wire sources into test-only duplicate objects.
# CTest names use nrw1_t1_* so T0 r7_* exact-set authority is unchanged.

if(NOT NINLIL_BUILD_TESTS)
    return()
endif()

if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
    message(FATAL_ERROR
        "NINLIL_BUILD_TESTS=ON requires NINLIL_R7_HOST_CRYPTO_ENABLED "
        "(OpenSSL 3 Host adapter required for R7 T1 wire tests)")
endif()

# ---------------------------------------------------------------------------
# C executables: production private archive only
# ---------------------------------------------------------------------------

add_executable(ninlil_r7_wire_portable_test
    tests/radio/r7_wire_portable_test.c
)
target_include_directories(ninlil_r7_wire_portable_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
)
target_compile_definitions(ninlil_r7_wire_portable_test PRIVATE
    NINLIL_R7_WIRE_TEST_BUILD=1
)
target_link_libraries(ninlil_r7_wire_portable_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_r7_wire_portable_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_r7_wire_portable_test)
add_test(
    NAME nrw1_t1_wire_portable_strict
    COMMAND ninlil_r7_wire_portable_test
)

add_executable(ninlil_r7_wire_vectors_bridge_test
    tests/radio/r7_wire_vectors_bridge_test.c
)
target_include_directories(ninlil_r7_wire_vectors_bridge_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
)
target_link_libraries(ninlil_r7_wire_vectors_bridge_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_r7_wire_vectors_bridge_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_r7_wire_vectors_bridge_test)
add_test(
    NAME nrw1_t1_vectors_bridge
    COMMAND ninlil_r7_wire_vectors_bridge_test
)

add_executable(ninlil_nra1_codec_test
    tests/transport/fabric_v1/nra1_codec_test.c
)
target_include_directories(ninlil_nra1_codec_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
)
target_link_libraries(ninlil_nra1_codec_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_nra1_codec_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_nra1_codec_test)
add_test(
    NAME nra1_v1_codec
    COMMAND ninlil_nra1_codec_test
)

add_executable(ninlil_nvb1_codec_test
    tests/transport/fabric_v1/nvb1_codec_test.c
)
target_include_directories(ninlil_nvb1_codec_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
)
target_link_libraries(ninlil_nvb1_codec_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_nvb1_codec_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_nvb1_codec_test)
add_test(
    NAME nvb1_v1_codec
    COMMAND ninlil_nvb1_codec_test
)

add_executable(ninlil_v1_lab_binding_test
    tests/transport/fabric_v1/v1_lab_binding_test.c
)
target_include_directories(ninlil_v1_lab_binding_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
)
target_link_libraries(ninlil_v1_lab_binding_test PRIVATE
    ninlil_runtime_private
    ninlil_fabric_v1
    ninlil
)
set_target_properties(ninlil_v1_lab_binding_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_v1_lab_binding_test)
add_test(
    NAME v1_lab_binding_codec
    COMMAND ninlil_v1_lab_binding_test
)

add_executable(ninlil_v1_lab_n6_owner_test
    tests/transport/fabric_v1/v1_lab_n6_owner_test.c
    tests/support/n6_mem_storage.c
)
target_include_directories(ninlil_v1_lab_n6_owner_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
)
target_link_libraries(ninlil_v1_lab_n6_owner_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_v1_lab_n6_owner_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_v1_lab_n6_owner_test)
add_test(
    NAME v1_lab_n6_owner
    COMMAND ninlil_v1_lab_n6_owner_test
)

add_executable(ninlil_v1_lab_provisioner_test
    tests/transport/fabric_v1/v1_lab_provisioner_test.c
    tests/support/in_memory_storage.c
)
target_include_directories(ninlil_v1_lab_provisioner_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
)
target_link_libraries(ninlil_v1_lab_provisioner_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_v1_lab_provisioner_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_v1_lab_provisioner_test)
add_test(
    NAME v1_lab_provisioner
    COMMAND ninlil_v1_lab_provisioner_test
)

add_executable(ninlil_v1_usb_bridge_test
    tests/transport/fabric_v1/v1_usb_bridge_test.c
    tests/support/fake_byte_stream.c
)
target_include_directories(ninlil_v1_usb_bridge_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
)
target_link_libraries(ninlil_v1_usb_bridge_test PRIVATE
    ninlil_runtime_private
    ninlil
)
set_target_properties(ninlil_v1_usb_bridge_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_v1_usb_bridge_test)
add_test(
    NAME v1_usb_bridge
    COMMAND ninlil_v1_usb_bridge_test
)

if(TARGET ninlil_posix_usb_serial
    AND (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux"))
    add_executable(ninlil_v1_usb_bridge_pty_test
        tests/transport/fabric_v1/v1_usb_bridge_pty_test.c
        tests/support/in_memory_storage.c
    )
    target_include_directories(ninlil_v1_usb_bridge_pty_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_v1_usb_bridge_pty_test PRIVATE
        ninlil_runtime_private
        ninlil_posix_usb_serial
        ninlil
    )
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(ninlil_v1_usb_bridge_pty_test PRIVATE util)
    endif()
    set_target_properties(ninlil_v1_usb_bridge_pty_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_posix_usb_serial_feature_macros(
        ninlil_v1_usb_bridge_pty_test)
    ninlil_apply_strict_warnings(ninlil_v1_usb_bridge_pty_test)
    add_test(
        NAME v1_usb_bridge_pty
        COMMAND ninlil_v1_usb_bridge_pty_test
    )
endif()

add_test(
    NAME v1_lab_n6_callsite_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/v1_lab_n6_callsite_gate.py
        check --root ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(
    NAME v1_lab_n6_callsite_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/v1_lab_n6_callsite_gate.py
        self-test --root ${CMAKE_CURRENT_SOURCE_DIR}
)

# ---------------------------------------------------------------------------
# Python gates: oracle, pin, platform, packaging, stack, ctest authority
# ---------------------------------------------------------------------------

add_test(
    NAME nrw1_t1_oracle_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_single_oracle.py
        self-test
)
add_test(
    NAME nrw1_t1_oracle_verify
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_single_oracle.py
        verify-json
        --json
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio/private/r7_wire_single_t1_vectors.json
)

add_test(
    NAME nra1_v1_mapping_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/nra1_mapping_gate.py
        check
)

add_test(
    NAME nrw1_t1_kat_pin
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_kat_pin.py
        check
)
add_test(
    NAME nrw1_t1_kat_pin_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_kat_pin.py
        self-test
)
set_tests_properties(nrw1_t1_kat_pin nrw1_t1_kat_pin_self_test PROPERTIES
    DEPENDS nrw1_t1_vectors_bridge)

add_test(
    NAME nrw1_t1_platform_split_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_platform_split_gate.py
        check
)
add_test(
    NAME nrw1_t1_platform_split_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_platform_split_gate.py
        self-test
)

add_test(
    NAME nrw1_t1_tests_off_packaging_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_tests_off_packaging_gate.py
        check
        --src-root ${CMAKE_CURRENT_SOURCE_DIR}
        --generator ${CMAKE_GENERATOR}
)
add_test(
    NAME nrw1_t1_tests_off_packaging_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_tests_off_packaging_gate.py
        self-test
        --src-root ${CMAKE_CURRENT_SOURCE_DIR}
)

add_test(
    NAME nrw1_t1_ctest_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/nrw1_t1_ctest_gate.py
        self-test
)

add_test(
    NAME nrw1_t1_stack_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_stack_gate.py
        self-test
)
if(NOT _ninlil_any_sanitizer_active)
    set(_r7_wire_stack_gate_cmd
        ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/r7_wire_stack_gate.py
        check
        --su-dir
        ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ninlil_runtime_private.dir
    )
    if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json")
        list(APPEND _r7_wire_stack_gate_cmd
            --compile-commands
            ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        )
    elseif(CMAKE_EXPORT_COMPILE_COMMANDS)
        list(APPEND _r7_wire_stack_gate_cmd
            --compile-commands
            ${CMAKE_CURRENT_BINARY_DIR}/compile_commands.json
        )
    endif()
    add_test(
        NAME nrw1_t1_stack_gate
        COMMAND ${_r7_wire_stack_gate_cmd}
    )
    set_tests_properties(nrw1_t1_stack_gate PROPERTIES
        DEPENDS nrw1_t1_wire_portable_strict)
else()
    message(STATUS
        "nrw1_t1_stack_gate: not registered under active sanitizer "
        "(production .su non-authoritative; self-test still enabled)")
endif()
