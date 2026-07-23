# M4 LAB Join/Attachment single source + CTest authority (V1 item 7).
#
# Include exactly once after cmake/ninlil_runtime_private_sources.cmake and
# before add_library(ninlil_runtime_private).

set(NINLIL_M4_LAB_PORTABLE_RELATIVE_SOURCES
    src/radio/m4_lab_primitive.c
    src/radio/m4_lab_membership.c
    src/radio/m4_lab_install_token.c
    src/radio/m4_lab_handshake.c
)

if(NOT DEFINED NINLIL_M4_LAB_SOURCES_APPENDED)
    list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
        ${NINLIL_M4_LAB_PORTABLE_RELATIVE_SOURCES}
    )
    set(NINLIL_M4_LAB_SOURCES_APPENDED TRUE)
endif()

function(ninlil_m4_lab_register_tests)
    if(NOT NINLIL_BUILD_TESTS)
        return()
    endif()

    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "NINLIL_BUILD_TESTS=ON requires NINLIL_R7_HOST_CRYPTO_ENABLED "
            "(OpenSSL 3 Host adapter required for M4 LAB join tests)")
    endif()

    add_executable(ninlil_m4_lab_join_handshake_test
        tests/radio/m4_lab_join_handshake_test.c
        tests/support/m4_lab_credential_fixture.c
    )
    target_include_directories(ninlil_m4_lab_join_handshake_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_m4_lab_join_handshake_test PRIVATE
        ninlil_runtime_private
        ninlil
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_m4_lab_join_handshake_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_m4_lab_join_handshake_test)
    add_test(
        NAME m4_lab_join_handshake
        COMMAND ninlil_m4_lab_join_handshake_test
    )
endfunction()
