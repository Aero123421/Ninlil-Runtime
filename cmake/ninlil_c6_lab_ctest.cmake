# C6-LAB enforcement (V1 item 10a): LAB_ONLY profile + sole-edge gate.
#
# Include after cmake/ninlil_c3_lab_ctest.cmake and before
# add_library(ninlil_runtime_private).

set(NINLIL_C6_LAB_PORTABLE_RELATIVE_SOURCES
    src/radio/v1_frame_manifest.c
    src/radio/c6_lab_spi_tx_sim.c
    src/radio/c6_lab_enforcement.c
)

if(NOT DEFINED NINLIL_C6_LAB_SOURCES_APPENDED)
    list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
        ${NINLIL_C6_LAB_PORTABLE_RELATIVE_SOURCES}
    )
    set(NINLIL_C6_LAB_SOURCES_APPENDED TRUE)
endif()

function(ninlil_c6_lab_register_tests)
    if(NOT NINLIL_BUILD_TESTS)
        return()
    endif()

    add_executable(ninlil_c6_lab_enforcement_test
        tests/radio/c6_lab_enforcement_test.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
    )
    target_include_directories(ninlil_c6_lab_enforcement_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
    )
    target_link_libraries(ninlil_c6_lab_enforcement_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_c6_lab_enforcement_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_c6_lab_enforcement_test)
    add_test(
        NAME c6_lab_enforcement
        COMMAND ninlil_c6_lab_enforcement_test
    )
endfunction()
