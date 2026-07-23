# C4/C5-LAB USB + radio software path (V1 item 9).
#
# Include after cmake/ninlil_c6_lab_ctest.cmake and before
# add_library(ninlil_runtime_private).

set(NINLIL_C4_C5_LAB_PORTABLE_RELATIVE_SOURCES
    src/transport/c4_lab_usb_path.c
    src/radio/c5_lab_radio_path.c
    src/runtime/c4_c5_lab_wire.c
)

if(NOT DEFINED NINLIL_C4_C5_LAB_SOURCES_APPENDED)
    list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
        ${NINLIL_C4_C5_LAB_PORTABLE_RELATIVE_SOURCES}
    )
    set(NINLIL_C4_C5_LAB_SOURCES_APPENDED TRUE)
endif()

function(ninlil_c4_c5_lab_register_tests)
    if(NOT NINLIL_BUILD_TESTS)
        return()
    endif()

    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "NINLIL_BUILD_TESTS=ON requires NINLIL_R7_HOST_CRYPTO_ENABLED "
            "(OpenSSL 3 Host adapter required for C4/C5 LAB path tests)")
    endif()

    add_executable(ninlil_c4_lab_usb_path_test
        tests/transport/c4_lab_usb_path_test.c
        tests/support/fake_byte_stream.c
    )
    target_include_directories(ninlil_c4_lab_usb_path_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_compile_definitions(ninlil_c4_lab_usb_path_test PRIVATE
        NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1
    )
    target_link_libraries(ninlil_c4_lab_usb_path_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_c4_lab_usb_path_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_c4_lab_usb_path_test)
    add_test(
        NAME c4_lab_usb_path
        COMMAND ninlil_c4_lab_usb_path_test
    )

    add_executable(ninlil_c5_lab_radio_path_test
        tests/radio/c5_lab_radio_path_test.c
        tests/support/m4_lab_credential_fixture.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
    )
    target_include_directories(ninlil_c5_lab_radio_path_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
    )
    target_link_libraries(ninlil_c5_lab_radio_path_test PRIVATE
        ninlil_runtime_private
        ninlil
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_c5_lab_radio_path_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_c5_lab_radio_path_test)
    add_test(
        NAME c5_lab_radio_path
        COMMAND ninlil_c5_lab_radio_path_test
    )

    add_executable(ninlil_c4_c5_lab_path_e2e_test
        tests/runtime/c4_c5_lab_path_e2e_test.c
        tests/support/m4_lab_credential_fixture.c
        tests/support/fake_byte_stream.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
    )
    target_include_directories(ninlil_c4_c5_lab_path_e2e_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
    )
    target_compile_definitions(ninlil_c4_c5_lab_path_e2e_test PRIVATE
        NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1
    )
    target_link_libraries(ninlil_c4_c5_lab_path_e2e_test PRIVATE
        ninlil_runtime_private
        ninlil
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_c4_c5_lab_path_e2e_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_c4_c5_lab_path_e2e_test)
    add_test(
        NAME c4_c5_lab_path_e2e
        COMMAND ninlil_c4_c5_lab_path_e2e_test
    )
endfunction()
