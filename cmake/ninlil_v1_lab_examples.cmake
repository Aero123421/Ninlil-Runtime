# V1-LAB item 10b host simulation examples (build-tree only; not installed).

function(ninlil_v1_lab_examples_register)
    if(NOT NINLIL_BUILD_TESTS)
        return()
    endif()
    if(NOT NINLIL_POSIX_LAB_PLATFORM_ENABLED)
        message(STATUS "V1 LAB examples: skipped (POSIX lab platform disabled)")
        return()
    endif()
    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "V1 LAB examples require NINLIL_R7_HOST_CRYPTO_ENABLED "
            "(OpenSSL 3 Host adapter)")
    endif()

    set(_ninlil_v1_lab_example_common
        examples/v1_lab/v1_lab_host_sim.c
        tests/support/v1_lab_integration_topology.c
        tests/support/m4_lab_credential_fixture.c
        tests/support/fake_byte_stream.c
        tests/support/in_memory_storage.c
    )
    set(_ninlil_v1_lab_example_includes
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/loopback_bearer
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/v1_lab
    )

    function(_ninlil_v1_lab_add_integration_example target source)
        add_executable(${target}
            ${source}
            ${_ninlil_v1_lab_example_common}
        )
        target_include_directories(${target} PRIVATE ${_ninlil_v1_lab_example_includes})
        target_compile_definitions(${target} PRIVATE
            NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1
        )
        target_link_libraries(${target} PRIVATE
            ninlil_runtime_private
            ninlil
            ninlil_posix_lab_platform
            OpenSSL::Crypto
        )
        set_target_properties(${target} PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            NINLIL_TEST_ONLY_ARTIFACT TRUE
        )
        ninlil_apply_posix_host_feature_macros(${target})
        ninlil_apply_strict_warnings(${target})
    endfunction()

    _ninlil_v1_lab_add_integration_example(
        ninlil_v1_lab_controller_submit_example
        examples/v1_lab/controller_submit.c
    )
    _ninlil_v1_lab_add_integration_example(
        ninlil_v1_lab_cell_custody_example
        examples/v1_lab/cell_custody.c
    )

    add_executable(ninlil_v1_lab_display_latest_state_example
        examples/v1_lab/display_latest_state.c
        examples/v1_lab/v1_lab_loopback_uplink.c
    )
    add_executable(ninlil_v1_lab_leak_measurement_example
        examples/v1_lab/leak_measurement.c
        examples/v1_lab/v1_lab_loopback_uplink.c
    )
    foreach(_uplink_target IN ITEMS
        ninlil_v1_lab_display_latest_state_example
        ninlil_v1_lab_leak_measurement_example
    )
        target_include_directories(${_uplink_target} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/v1_lab
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/loopback_bearer
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        )
        target_link_libraries(${_uplink_target} PRIVATE
            ninlil_runtime_private
            ninlil
            ninlil_posix_lab_platform
        )
        set_target_properties(${_uplink_target} PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            NINLIL_TEST_ONLY_ARTIFACT TRUE
        )
        ninlil_apply_posix_host_feature_macros(${_uplink_target})
        ninlil_apply_strict_warnings(${_uplink_target})
    endforeach()

    add_test(
        NAME v1_lab_controller_submit_example
        COMMAND ninlil_v1_lab_controller_submit_example
    )
    add_test(
        NAME v1_lab_cell_custody_example
        COMMAND ninlil_v1_lab_cell_custody_example
    )
    add_test(
        NAME v1_lab_display_latest_state_example
        COMMAND ninlil_v1_lab_display_latest_state_example
    )
    add_test(
        NAME v1_lab_leak_measurement_example
        COMMAND ninlil_v1_lab_leak_measurement_example
    )
endfunction()
