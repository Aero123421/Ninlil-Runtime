# C3-LAB secure wire + context lifecycle (V1 item 8).
#
# Include exactly once after cmake/ninlil_m4_lab_ctest.cmake and before
# add_library(ninlil_runtime_private).

set(NINLIL_C3_LAB_PORTABLE_RELATIVE_SOURCES
    src/radio/c3_lab_context_lifecycle.c
    src/radio/c3_lab_secure_wire.c
)

if(NOT DEFINED NINLIL_C3_LAB_SOURCES_APPENDED)
    list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
        ${NINLIL_C3_LAB_PORTABLE_RELATIVE_SOURCES}
    )
    set(NINLIL_C3_LAB_SOURCES_APPENDED TRUE)
endif()

function(ninlil_c3_lab_register_tests)
    if(NOT NINLIL_BUILD_TESTS)
        return()
    endif()

    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "NINLIL_BUILD_TESTS=ON requires NINLIL_R7_HOST_CRYPTO_ENABLED "
            "(OpenSSL 3 Host adapter required for C3 LAB secure wire tests)")
    endif()

    add_executable(ninlil_c3_lab_secure_wire_test
        tests/radio/c3_lab_secure_wire_test.c
        tests/support/m4_lab_credential_fixture.c
    )
    target_include_directories(ninlil_c3_lab_secure_wire_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_c3_lab_secure_wire_test PRIVATE
        ninlil_runtime_private
        ninlil
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_c3_lab_secure_wire_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_c3_lab_secure_wire_test)
    add_test(
        NAME c3_lab_secure_wire
        COMMAND ninlil_c3_lab_secure_wire_test
    )

    add_executable(ninlil_c3_lab_secure_1hop_e2e_test
        tests/runtime/c3_lab_secure_1hop_e2e_test.c
        tests/support/m4_lab_credential_fixture.c
    )
    target_include_directories(ninlil_c3_lab_secure_1hop_e2e_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/loopback_bearer
    )
    target_link_libraries(ninlil_c3_lab_secure_1hop_e2e_test PRIVATE
        ninlil_runtime_private
        ninlil_posix_lab_platform
        ninlil
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_c3_lab_secure_1hop_e2e_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_c3_lab_secure_1hop_e2e_test)
    add_test(
        NAME c3_lab_secure_1hop_e2e
        COMMAND ninlil_c3_lab_secure_1hop_e2e_test
    )
endfunction()
