# V1-LAB item 10b integration E2E gate (RC prerequisite).

function(ninlil_v1_integration_gate_register_tests)
    if(NOT NINLIL_BUILD_TESTS)
        return()
    endif()

    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "NINLIL_BUILD_TESTS=ON requires NINLIL_R7_HOST_CRYPTO_ENABLED "
            "(OpenSSL 3 Host adapter required for integration gate)")
    endif()

    add_executable(ninlil_v1_integration_gate_e2e_test
        tests/runtime/v1_integration_gate_e2e_test.c
        tests/support/v1_lab_integration_topology.c
        tests/support/m4_lab_credential_fixture.c
        tests/support/fake_byte_stream.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
        tests/support/canonical_origin_authorization.c
    )
    target_include_directories(ninlil_v1_integration_gate_e2e_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/loopback_bearer
    )
    target_compile_definitions(ninlil_v1_integration_gate_e2e_test PRIVATE
        NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1
    )
    target_link_libraries(ninlil_v1_integration_gate_e2e_test PRIVATE
        ninlil_runtime_private
        ninlil
        ninlil_posix_lab_platform
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_v1_integration_gate_e2e_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_strict_warnings(ninlil_v1_integration_gate_e2e_test)
    add_test(
        NAME v1_integration_gate_e2e
        COMMAND ninlil_v1_integration_gate_e2e_test
    )
    add_test(
        NAME v1_integration_gate_structural
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/v1_integration_gate.py
            check
    )
endfunction()
