# Ninlil tests-only target and CTest registration authority.
# Included from the top-level CMakeLists.txt only when NINLIL_BUILD_TESTS=ON.
# Keep production options, policy, installable targets, and package generation
# in the top-level file; this file preserves the original directory scope.

    enable_testing()

    if(TARGET ninlil_posix_tls_v1)
        # Same production sources, recompiled only for focused deterministic
        # fault injection. This archive is tests-only and never installed.
        add_library(ninlil_posix_tls_v1_test_hooks STATIC
            ${_ninlil_posix_tls_v1_srcs})
        target_include_directories(ninlil_posix_tls_v1_test_hooks
            PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/wifi_v1
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/posix_tls_v1)
        target_compile_definitions(ninlil_posix_tls_v1_test_hooks PRIVATE
            NINLIL_POSIX_TLS_V1_BUILD=1
            NINLIL_WIFI_RX_STREAM_SINGLE_RECORD=1
            NINLIL_POSIX_TLS_V1_TEST_HOOKS=1)
        target_link_libraries(ninlil_posix_tls_v1_test_hooks PUBLIC
            ninlil_fabric_v1
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads)
        set_target_properties(ninlil_posix_tls_v1_test_hooks PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            POSITION_INDEPENDENT_CODE ON
            C_VISIBILITY_PRESET hidden
            NINLIL_TEST_ONLY_ARTIFACT TRUE)
        ninlil_apply_strict_warnings(ninlil_posix_tls_v1_test_hooks)

        add_executable(ninlil_posix_tls_v1_lifecycle_test
            tests/transport/posix_tls_v1/posix_tls_v1_lifecycle_test.c)
        target_link_libraries(ninlil_posix_tls_v1_lifecycle_test PRIVATE
            ninlil_posix_tls_v1)
        set_target_properties(ninlil_posix_tls_v1_lifecycle_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_posix_tls_v1_lifecycle_test)
        add_test(
            NAME posix_tls_v1_lifecycle
            COMMAND ninlil_posix_tls_v1_lifecycle_test)

        add_executable(ninlil_posix_tls_v1_registration_test
            tests/transport/posix_tls_v1/posix_tls_v1_registration_test.c
            tests/support/in_memory_storage.c)
        target_include_directories(ninlil_posix_tls_v1_registration_test
            PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests/support)
        target_link_libraries(ninlil_posix_tls_v1_registration_test PRIVATE
            ninlil_posix_tls_v1)
        set_target_properties(
            ninlil_posix_tls_v1_registration_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_posix_tls_v1_registration_test)
        add_test(
            NAME posix_tls_v1_registration
            COMMAND ninlil_posix_tls_v1_registration_test)

        add_executable(ninlil_posix_tls_v1_loopback_test
            tests/transport/posix_tls_v1/posix_tls_v1_loopback_test.c
            tests/support/in_memory_storage.c)
        target_include_directories(ninlil_posix_tls_v1_loopback_test
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/posix_tls_v1
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1)
        target_link_libraries(ninlil_posix_tls_v1_loopback_test PRIVATE
            ninlil_posix_tls_v1_test_hooks)
        set_target_properties(ninlil_posix_tls_v1_loopback_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_posix_tls_v1_loopback_test)
        add_test(
            NAME posix_tls_v1_loopback
            COMMAND bash
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/posix_tls_v1_run_loopback.sh
                $<TARGET_FILE:ninlil_posix_tls_v1_loopback_test>
                ${CMAKE_CURRENT_SOURCE_DIR})
    endif()

    add_test(
        NAME cmake_package_version_compatibility
        COMMAND ${CMAKE_COMMAND}
            -DNINLIL_VERSION_FILE=${CMAKE_CURRENT_BINARY_DIR}/NinlilConfigVersion.cmake
            -DNINLIL_TEST_DIR=${CMAKE_CURRENT_BINARY_DIR}/package-version-policy
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/package_version_policy_test.cmake
    )

    if(NINLIL_HOST_RUNTIME_ENABLED)
        add_test(
            NAME host_runtime_tests_off_installed_consumer
            COMMAND ${CMAKE_COMMAND}
                -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                -DNINLIL_PARENT_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                "-DNINLIL_SMOKE_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DNINLIL_SMOKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                -DNINLIL_SMOKE_WITH_SQLITE=OFF
                -DNINLIL_SMOKE_DOMAIN_SCHEMA1=OFF
                -DNINLIL_SMOKE_ENABLE_SANITIZERS=${NINLIL_ENABLE_SANITIZERS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_host_runtime_tests_off_smoke.cmake
        )
        if(NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
            add_test(
                NAME host_runtime_tests_off_installed_consumer_sqlite
                COMMAND ${CMAKE_COMMAND}
                    -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                    -DNINLIL_PARENT_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                    -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                    -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                    "-DNINLIL_SMOKE_C_COMPILER=${CMAKE_C_COMPILER}"
                    "-DNINLIL_SMOKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                    -DNINLIL_SMOKE_WITH_SQLITE=ON
                    -DNINLIL_SMOKE_DOMAIN_SCHEMA1=OFF
                    -DNINLIL_SMOKE_ENABLE_SANITIZERS=${NINLIL_ENABLE_SANITIZERS}
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_host_runtime_tests_off_smoke.cmake
            )
        endif()
        # Fresh Domain-ON install-consumer + nm evidence (default remains OFF).
        add_test(
            NAME host_runtime_tests_off_installed_consumer_domain_on
            COMMAND ${CMAKE_COMMAND}
                -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                -DNINLIL_PARENT_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                "-DNINLIL_SMOKE_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DNINLIL_SMOKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                -DNINLIL_SMOKE_WITH_SQLITE=OFF
                -DNINLIL_SMOKE_DOMAIN_SCHEMA1=ON
                -DNINLIL_SMOKE_ENABLE_SANITIZERS=${NINLIL_ENABLE_SANITIZERS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_host_runtime_tests_off_smoke.cmake
        )
        if(NINLIL_BUILD_FABRIC_V1)
            add_test(
                NAME fabric_v1_tests_off_installed_consumer
                COMMAND ${CMAKE_COMMAND}
                    -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                    -DNINLIL_PARENT_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                    -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                    -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                    "-DNINLIL_SMOKE_C_COMPILER=${CMAKE_C_COMPILER}"
                    "-DNINLIL_SMOKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                    -DNINLIL_SMOKE_ENABLE_SANITIZERS=${NINLIL_ENABLE_SANITIZERS}
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_fabric_v1_tests_off_smoke.cmake)
        endif()
        if(NINLIL_BUILD_FABRIC_V1
           AND NINLIL_BUILD_POSIX_TLS_V1
           AND NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
            add_test(
                NAME posix_tls_v1_tests_off_installed_runtime_e2e
                COMMAND ${CMAKE_COMMAND}
                    -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                    -DNINLIL_PARENT_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                    -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                    -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                    "-DNINLIL_SMOKE_C_COMPILER=${CMAKE_C_COMPILER}"
                    "-DNINLIL_SMOKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                    -DNINLIL_SMOKE_ENABLE_SANITIZERS=${NINLIL_ENABLE_SANITIZERS}
                    -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_posix_tls_runtime_e2e_tests_off_smoke.cmake)
            set_tests_properties(
                posix_tls_v1_tests_off_installed_runtime_e2e
                PROPERTIES TIMEOUT 240)
        endif()
    endif()

    if(NINLIL_POSIX_USB_SERIAL_ENABLED)
        add_test(
            NAME posix_usb_serial_v1_tests_off_installed_consumer
            COMMAND ${CMAKE_COMMAND}
                -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                -DNINLIL_PARENT_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                "-DNINLIL_SMOKE_C_COMPILER=${CMAKE_C_COMPILER}"
                "-DNINLIL_SMOKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
                -DNINLIL_SMOKE_ENABLE_SANITIZERS=${NINLIL_ENABLE_SANITIZERS}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_posix_usb_serial_tests_off_smoke.cmake)
        set_tests_properties(
            posix_usb_serial_v1_tests_off_installed_consumer
            PROPERTIES TIMEOUT 120)
    endif()

    add_test(
        NAME runtime_private_subproject_smoke
        COMMAND ${CMAKE_COMMAND}
            -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -DNINLIL_SMOKE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/private_subproject
            -DNINLIL_SMOKE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/private-subproject-smoke
            "-DNINLIL_GENERATOR=${CMAKE_GENERATOR}"
            -DNINLIL_BUILD_CONFIG=$<CONFIG>
            -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
            -DNINLIL_SANITIZER_SUPPORTED=${_ninlil_sanitizer_supported}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/private_subproject_smoke.cmake
    )

    function(ninlil_assert_no_test_only_link target)
        foreach(link_property LINK_LIBRARIES INTERFACE_LINK_LIBRARIES)
            get_target_property(linked_targets ${target} ${link_property})
            if(linked_targets)
                foreach(linked_target IN LISTS linked_targets)
                    if(TARGET ${linked_target})
                        get_target_property(is_test_only
                            ${linked_target} NINLIL_TEST_ONLY_ARTIFACT)
                        if(is_test_only)
                            message(FATAL_ERROR
                                "${target} links TEST-only artifact ${linked_target}")
                        endif()
                    endif()
                endforeach()
            endif()
        endforeach()
    endfunction()

    add_library(ninlil_contract STATIC
        src/contract/abi_contract.c
    )
    target_include_directories(ninlil_contract PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/contract
    )
    target_link_libraries(ninlil_contract PRIVATE ninlil)
    set_target_properties(ninlil_contract PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_contract)

    add_executable(ninlil_abi_contract_test
        tests/contract/abi_contract_test.c
    )
    target_include_directories(ninlil_abi_contract_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/contract
    )
    target_link_libraries(ninlil_abi_contract_test PRIVATE ninlil_contract ninlil)
    set_target_properties(ninlil_abi_contract_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_abi_contract_test)

    add_test(NAME abi_contract_header COMMAND ninlil_abi_contract_test header)
    add_test(NAME abi_contract_output COMMAND ninlil_abi_contract_test output)
    add_test(NAME abi_contract_enum COMMAND ninlil_abi_contract_test enum)

    add_library(ninlil_scheduler_model STATIC
        src/model/scheduler_candidate.c
    )
    target_include_directories(ninlil_scheduler_model PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_scheduler_model PRIVATE ninlil)
    set_target_properties(ninlil_scheduler_model PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_scheduler_model)

    add_executable(ninlil_scheduler_candidate_test
        tests/model/scheduler_candidate_test.c
    )
    target_include_directories(ninlil_scheduler_candidate_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_scheduler_candidate_test PRIVATE
        ninlil_scheduler_model
        ninlil
    )
    set_target_properties(ninlil_scheduler_candidate_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_scheduler_candidate_test)

    add_test(
        NAME scheduler_candidate_model
        COMMAND ninlil_scheduler_candidate_test
    )

    add_library(ninlil_reducer_model STATIC
        src/model/deadline_projection.c
        src/model/desired_deadline_transition.c
        src/model/desired_target_snapshot_internal.c
        src/model/required_receipt_transition.c
        src/model/resource_ledger.c
        src/model/resource_ledger_batch.c
        src/model/submission_admission.c
        src/model/submission_preflight.c
    )
    get_target_property(_ninlil_reducer_sources ninlil_reducer_model SOURCES)
    foreach(_source IN LISTS _ninlil_reducer_sources)
        get_filename_component(_source_name "${_source}" NAME)
        if(_source_name STREQUAL "domain_store_body_codec.c"
           OR _source_name STREQUAL "domain_store_codec.c"
           OR _source_name STREQUAL "runtime_lifecycle_model.c"
           OR _source_name STREQUAL "runtime_store_codec.c"
           OR _source_name STREQUAL "runtime_store_bootstrap.c"
           OR _source_name STREQUAL "domain_store_scanner.c"
           OR _source_name STREQUAL "domain_store_d3s1.c"
           OR _source_name STREQUAL "domain_store_d3s2.c"
           OR _source_name STREQUAL "domain_store_d3s3.c"
           OR _source_name STREQUAL "domain_store_d3s4.c"
           OR _source_name STREQUAL "runtime_store_orchestrator.c"
           OR _source_name STREQUAL "runtime_store_stage5_seam.c")
            message(FATAL_ERROR
                "private Runtime source duplicated in reducer: ${_source}")
        endif()
    endforeach()
    target_include_directories(ninlil_reducer_model PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_reducer_model PRIVATE ninlil)
    set_target_properties(ninlil_reducer_model PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_reducer_model)

    add_executable(ninlil_deadline_projection_test
        tests/model/deadline_projection_test.c
    )
    target_include_directories(ninlil_deadline_projection_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_deadline_projection_test PRIVATE
        ninlil_reducer_model
        ninlil
    )
    set_target_properties(ninlil_deadline_projection_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_deadline_projection_test)

    add_test(
        NAME deadline_projection_model
        COMMAND ninlil_deadline_projection_test
    )

    add_executable(ninlil_required_receipt_transition_test
        tests/model/required_receipt_transition_test.c
    )
    target_include_directories(ninlil_required_receipt_transition_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_required_receipt_transition_test PRIVATE
        ninlil_reducer_model
        ninlil
    )
    set_target_properties(ninlil_required_receipt_transition_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_required_receipt_transition_test)

    add_test(
        NAME required_receipt_transition_model
        COMMAND ninlil_required_receipt_transition_test
    )

    add_executable(ninlil_desired_deadline_transition_test
        tests/model/desired_deadline_transition_test.c
    )
    target_include_directories(ninlil_desired_deadline_transition_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_desired_deadline_transition_test PRIVATE
        ninlil_reducer_model
        ninlil
    )
    set_target_properties(ninlil_desired_deadline_transition_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_desired_deadline_transition_test)

    add_test(
        NAME desired_deadline_transition_model
        COMMAND ninlil_desired_deadline_transition_test
    )

    add_executable(ninlil_resource_ledger_test
        tests/model/resource_ledger_test.c
    )
    target_include_directories(ninlil_resource_ledger_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_resource_ledger_test PRIVATE
        ninlil_reducer_model
        ninlil
    )
    set_target_properties(ninlil_resource_ledger_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_resource_ledger_test)

    add_test(
        NAME resource_ledger_model
        COMMAND ninlil_resource_ledger_test
    )

    add_executable(ninlil_resource_ledger_batch_test
        tests/model/resource_ledger_batch_test.c
    )
    target_include_directories(ninlil_resource_ledger_batch_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_resource_ledger_batch_test PRIVATE
        ninlil_reducer_model
        ninlil
    )
    set_target_properties(ninlil_resource_ledger_batch_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_resource_ledger_batch_test)

    add_test(
        NAME resource_ledger_batch_model
        COMMAND ninlil_resource_ledger_batch_test
    )

    add_executable(ninlil_runtime_lifecycle_model_test
        tests/model/runtime_lifecycle_model_test.c
    )
    target_include_directories(ninlil_runtime_lifecycle_model_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_runtime_lifecycle_model_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    if(NINLIL_ENABLE_MFDT_V1_PRIVATE)
        target_compile_definitions(ninlil_runtime_lifecycle_model_test PRIVATE
            NINLIL_MFDT_V1_PRIVATE=1
        )
    endif()
    set_target_properties(ninlil_runtime_lifecycle_model_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_runtime_lifecycle_model_test)

    add_test(
        NAME runtime_lifecycle_model
        COMMAND ninlil_runtime_lifecycle_model_test
    )

    add_executable(ninlil_runtime_store_codec_test
        tests/model/runtime_store_codec_test.c
    )
    target_include_directories(ninlil_runtime_store_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_runtime_store_codec_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_runtime_store_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_runtime_store_codec_test)

    add_test(
        NAME runtime_store_codec
        COMMAND ninlil_runtime_store_codec_test
    )

    add_executable(ninlil_control_frame_codec_test
        tests/model/control_frame_codec_test.c
    )
    target_include_directories(ninlil_control_frame_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_control_frame_codec_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_control_frame_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_control_frame_codec_test)

    add_test(
        NAME control_frame_codec
        COMMAND ninlil_control_frame_codec_test
    )

    add_library(ninlil_domain_vector_parse STATIC
        tests/support/domain_vector_parse.c
    )
    target_include_directories(ninlil_domain_vector_parse PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    set_target_properties(ninlil_domain_vector_parse PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_vector_parse)

    add_executable(ninlil_domain_store_codec_test
        tests/model/domain_store_codec_test.c
    )
    target_include_directories(ninlil_domain_store_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_domain_store_codec_test PRIVATE
        ninlil_runtime_private
        ninlil_domain_vector_parse
        ninlil
    )
    set_target_properties(ninlil_domain_store_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_store_codec_test)

    add_test(
        NAME domain_store_codec
        COMMAND ninlil_domain_store_codec_test
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
    )

    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(
        NAME markdown_link_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/markdown_link_gate.py
            check
            --root
            ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(
        NAME markdown_link_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/markdown_link_gate.py
            self-test
    )
    set(_ninlil_runtime_step_gate_args
        --cc ${CMAKE_C_COMPILER}
        --define NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN=1
        --define NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM=1
        --define NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1
        --define NINLIL_R7_CRYPTO_TEST_BUILD=1
        --define NINLIL_R7_WIRE_TEST_BUILD=1
        --define NINLIL_R7_BINDING_TEST_BUILD=1)
    if(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
        list(APPEND _ninlil_runtime_step_gate_args
            --define NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
    endif()
    if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
        list(APPEND _ninlil_runtime_step_gate_args
            --define NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    endif()
    if(NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
        list(APPEND _ninlil_runtime_step_gate_args
            --define NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1)
    endif()
    if(NINLIL_ENABLE_MFDT_V1_PRIVATE)
        list(APPEND _ninlil_runtime_step_gate_args
            --define NINLIL_MFDT_V1_PRIVATE=1)
    endif()
    add_test(
        NAME runtime_step_epilogue_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/runtime_step_epilogue_gate.py
            check
            ${_ninlil_runtime_step_gate_args}
    )
    add_test(
        NAME runtime_step_epilogue_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/runtime_step_epilogue_gate.py
            self-test
            ${_ninlil_runtime_step_gate_args}
    )
    add_test(
        NAME oss_review_provenance_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/oss_review_provenance_gate.py
            check
    )
    add_test(
        NAME oss_review_provenance_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/oss_review_provenance_gate.py
            self-test
    )
    add_test(
        NAME build_options_docs_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/build_options_docs_gate.py
            check
    )
    add_test(
        NAME build_options_docs_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/build_options_docs_gate.py
            self-test
    )
    add_test(
        NAME layering_invariant_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/layering_invariant_gate.py
            check
    )
    add_test(
        NAME layering_invariant_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/layering_invariant_gate.py
            self-test
    )
    set_tests_properties(
        layering_invariant_gate
        PROPERTIES TIMEOUT 30
    )
    set_tests_properties(
        layering_invariant_gate_self_test
        PROPERTIES TIMEOUT 180
    )
    add_test(
        NAME compatibility_matrix_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/compatibility_matrix_gate.py
            check
    )
    add_test(
        NAME compatibility_matrix_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/compatibility_matrix_gate.py
            self-test
    )
    add_test(
        NAME public_module_manifest_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/public_module_manifest_gate.py
            check
    )
    add_test(
        NAME public_module_manifest_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/public_module_manifest_gate.py
            self-test
    )
    add_test(
        NAME domain_store_schema1_review_manifest_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_review_manifest_gate.py
            check
    )
    add_test(
        NAME domain_store_schema1_review_manifest_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_review_manifest_gate.py
            self-test
    )
    add_test(
        NAME third_party_notice_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/third_party_notice_gate.py
            check
    )
    add_test(
        NAME third_party_notice_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/third_party_notice_gate.py
            self-test
    )
    add_test(
        NAME release_workflow_identity_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_workflow_identity_gate.py
            check
    )
    add_test(
        NAME release_workflow_identity_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_workflow_identity_gate.py
            self-test
    )
    add_test(
        NAME release_spdx_sbom_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/spdx_release_sbom.py
            self-test
    )
    add_test(
        NAME control_frame_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/control_frame_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/control-frame-v1.json
    )
    add_test(
        NAME control_frame_vector_gen_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/control_frame_vector_gen.py
            self-test
    )

    # Production C bridge: materialised golden + applied mutations from JSON.
    set(_ninlil_cf_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/control_frame_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_cf_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/control_frame_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/control-frame-v1.json
            ${_ninlil_cf_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/control_frame_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/control-frame-v1.json
        COMMENT "Generate control-frame production bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_control_frame_vector_oracle_bridge_test
        tests/model/control_frame_vector_oracle_bridge_test.c
        ${_ninlil_cf_fixture}
    )
    target_include_directories(ninlil_control_frame_vector_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(ninlil_control_frame_vector_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_control_frame_vector_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_control_frame_vector_oracle_bridge_test)
    add_test(
        NAME control_frame_vector_oracle_bridge
        COMMAND ninlil_control_frame_vector_oracle_bridge_test
    )
    add_test(
        NAME control_frame_vector_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'control_frame_vector_gen.py'; js=root/'spec'/'vectors'/'control-frame-v1.json'; build=pathlib.Path(r'${_ninlil_cf_fixture}'); assert build.is_file(), 'missing build fixture'; td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); ta,tb,tbld=a.read_bytes(),b.read_bytes(),build.read_bytes(); assert ta==tb, 'emit non-deterministic'; assert ta==tbld, 'build fixture stale'; assert b'NINLIL_CFV_CASE_COUNT' in ta; assert b'mut_bad_version' in ta; assert b'mut_bad_frame_crc' in ta; print('control_frame fixture freshness+determinism ok', len(ta), 'bytes')"
    )
    set_tests_properties(control_frame_vector_fixture_freshness PROPERTIES
        DEPENDS control_frame_vector_oracle_bridge
    )

    # U4 NCL1 pure codec + authoritative vectors (codec/wire slice only).
    # Does not claim U4 session/LC complete / HIL / series complete.
    add_executable(ninlil_ncl1_codec_test
        tests/model/ncl1_codec_test.c
    )
    target_include_directories(ninlil_ncl1_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_ncl1_codec_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_ncl1_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_ncl1_codec_test)
    add_test(
        NAME ncl1_codec
        COMMAND ninlil_ncl1_codec_test
    )

    add_test(
        NAME ncl1_u4_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/ncl1_u4_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/ncl1-u4-v1.json
    )
    add_test(
        NAME ncl1_u4_vector_gen_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/ncl1_u4_vector_gen.py
            self-test
    )

    set(_ninlil_ncl1_u4_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/ncl1_u4_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_ncl1_u4_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/ncl1_u4_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/ncl1-u4-v1.json
            ${_ninlil_ncl1_u4_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/ncl1_u4_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/ncl1-u4-v1.json
        COMMENT "Generate NCL1 U4 production codec bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_ncl1_vector_oracle_bridge_test
        tests/model/ncl1_vector_oracle_bridge_test.c
        ${_ninlil_ncl1_u4_fixture}
    )
    target_include_directories(ninlil_ncl1_vector_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(ninlil_ncl1_vector_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_ncl1_vector_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_ncl1_vector_oracle_bridge_test)
    add_test(
        NAME ncl1_vector_oracle_bridge
        COMMAND ninlil_ncl1_vector_oracle_bridge_test
    )
    add_test(
        NAME ncl1_u4_vector_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'ncl1_u4_vector_gen.py'; js=root/'spec'/'vectors'/'ncl1-u4-v1.json'; build=pathlib.Path(r'${_ninlil_ncl1_u4_fixture}'); assert build.is_file(), 'missing build fixture'; td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); ta,tb,tbld=a.read_bytes(),b.read_bytes(),build.read_bytes(); assert ta==tb, 'emit non-deterministic'; assert ta==tbld, 'build fixture stale'; assert b'NINLIL_NCL1_U4_CODEC_CASE_COUNT' in ta; assert b'U4-N-BAD-MAGIC' in ta; assert b'U4-N-RESERVED-ORDER' in ta; print('ncl1_u4 fixture freshness+determinism ok', len(ta), 'bytes')"
    )
    set_tests_properties(ncl1_u4_vector_fixture_freshness PROPERTIES
        DEPENDS ncl1_vector_oracle_bridge
    )

    add_test(
        NAME domain_store_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
    )
    add_test(
        NAME domain_store_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_vector_gen.py
            self-test
    )
    add_test(
        NAME domain_store_schema1_binding_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_binding_vector_gen.py
            --check
    )
    add_test(
        NAME domain_store_schema1_binding_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_binding_vector_gen.py
            --self-test
    )
    add_test(
        NAME domain_store_schema1_binding_independent_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_binding_gate.py
            --check
    )
    add_test(
        NAME domain_store_schema1_binding_independent_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_binding_gate.py
            --self-test
    )
    find_program(NINLIL_NODE_EXECUTABLE NAMES node nodejs)
    if(NOT NINLIL_NODE_EXECUTABLE)
        message(FATAL_ERROR
            "Ninlil's test suite requires Node.js >=18 for independent "
            "specification gates. Install Node.js 18 or newer and retry, or "
            "configure the library package with -DNINLIL_BUILD_TESTS=OFF.")
    endif()
    execute_process(
        COMMAND ${NINLIL_NODE_EXECUTABLE} --version
        RESULT_VARIABLE _ninlil_node_version_result
        OUTPUT_VARIABLE _ninlil_node_version
        ERROR_VARIABLE _ninlil_node_version_error
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT _ninlil_node_version_result EQUAL 0
            OR NOT _ninlil_node_version MATCHES "^v([0-9]+)\\.")
        message(FATAL_ERROR
            "Ninlil's test suite requires a runnable Node.js >=18 "
            "(found '${_ninlil_node_version}'). Install Node.js 18 or newer, "
            "or configure the library package with -DNINLIL_BUILD_TESTS=OFF.")
    endif()
    if(CMAKE_MATCH_1 LESS 18)
        message(FATAL_ERROR
            "Ninlil's test suite requires Node.js >=18 "
            "(found ${_ninlil_node_version}). Install Node.js 18 or newer, "
            "or configure the library package with -DNINLIL_BUILD_TESTS=OFF.")
    endif()
    add_test(
        NAME domain_store_schema1_binding_node_gate
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_binding_gate.mjs
            --check
    )
    add_test(
        NAME domain_store_schema1_binding_node_gate_self_test
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_schema1_binding_gate.mjs
            --self-test
    )
    set_tests_properties(
        domain_store_schema1_binding_vector_oracle_self_test
        domain_store_schema1_binding_independent_gate
        domain_store_schema1_binding_independent_gate_self_test
        domain_store_schema1_binding_node_gate
        domain_store_schema1_binding_node_gate_self_test
        PROPERTIES DEPENDS domain_store_schema1_binding_vector_oracle
    )

    # ADR-0023 / docs/35 Proposed Production Attachment specification gates.
    # These prove the candidate byte contract only; no EDHOC dependency,
    # production implementation, crypto correctness, or HIL is claimed.
    add_test(
        NAME production_attachment_edhoc_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_vector_gen.py
            --check
    )
    add_test(
        NAME production_attachment_edhoc_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_vector_gen.py
            --self-test
    )
    add_test(
        NAME production_attachment_edhoc_python_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_gate.py
            --check
    )
    add_test(
        NAME production_attachment_edhoc_python_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_gate.py
            --self-test
    )
    add_test(
        NAME production_attachment_edhoc_node_gate
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_gate.mjs
            --check
    )
    add_test(
        NAME production_attachment_edhoc_node_gate_self_test
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_gate.mjs
            --self-test
    )
    add_test(
        NAME production_attachment_magic_registry_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/protocol_magic_registry_gate.py
            --check
    )
    add_test(
        NAME production_attachment_magic_registry_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/protocol_magic_registry_gate.py
            --self-test
    )

    # ADR-0021 MFDT SPEC-ONLY gates: dedicated authority file (not whole-repo CMake).
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_mfdt_ctest.cmake)
    # MFDT must not mutate Accepted U5/U6 v2 freeze / R6 docs/25 / docs/23 pins.
    # Separate from the 10-test MFDT SPEC inventory (acceptance does not own this).
    add_test(
        NAME mfdt_freeze_noninterference_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_freeze_noninterference_gate.py
            check
    )
    add_test(
        NAME mfdt_freeze_noninterference_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_freeze_noninterference_gate.py
            self-test
    )

    # ADR-0019 / ADR-0020 SPEC_ACCEPTED Route Relay + Multi-parent design gates.
    # Accepted contract / oracle consistency only. No production feature default-ON,
    # implementation, public ABI, HIL, or RELEASE_SUPPORTED claim.
    # Registered only under NINLIL_BUILD_TESTS=ON (not in tests-OFF target graph).
    add_test(
        NAME route_relay_multiparent_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/route_relay_multiparent_spec_vector_gen.py
            --check
    )
    add_test(
        NAME route_relay_multiparent_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/route_relay_multiparent_spec_vector_gen.py
            --self-test
    )
    add_test(
        NAME route_relay_multiparent_python_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/route_relay_multiparent_spec_gate.py
            --check
    )
    add_test(
        NAME route_relay_multiparent_python_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/route_relay_multiparent_spec_gate.py
            --self-test
    )
    add_test(
        NAME route_relay_multiparent_node_gate
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/route_relay_multiparent_spec_gate.mjs
            --check
    )
    add_test(
        NAME route_relay_multiparent_node_gate_self_test
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/route_relay_multiparent_spec_gate.mjs
            --self-test
    )
    add_test(
        NAME rrmp_software_manifest_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/rrmp_software_manifest_gate.py
            check
    )
    add_test(
        NAME rrmp_software_manifest_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/rrmp_software_manifest_gate.py
            self-test
    )
    set_tests_properties(
        route_relay_multiparent_vector_oracle_self_test
        route_relay_multiparent_python_gate
        route_relay_multiparent_python_gate_self_test
        route_relay_multiparent_node_gate
        route_relay_multiparent_node_gate_self_test
        rrmp_software_manifest_gate
        rrmp_software_manifest_gate_self_test
        PROPERTIES DEPENDS route_relay_multiparent_vector_oracle
    )

    set(_ninlil_pa_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/production_attachment_edhoc_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_pa_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_vector_gen.py
            --emit-c-fixture ${_ninlil_pa_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_composition.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_schema_authority.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/production_attachment_edhoc_closed_key_schema.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/production-attachment-edhoc-v1.json
        COMMENT "Generate Proposed Production Attachment C11 fixture"
        VERBATIM
    )
    add_custom_target(ninlil_pa_fixture_gen DEPENDS ${_ninlil_pa_fixture})
    add_executable(ninlil_production_attachment_edhoc_vector_test
        tests/radio/production_attachment_edhoc_vector_test.c
    )
    add_dependencies(
        ninlil_production_attachment_edhoc_vector_test
        ninlil_pa_fixture_gen)
    target_include_directories(
        ninlil_production_attachment_edhoc_vector_test PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_property(
        SOURCE tests/radio/production_attachment_edhoc_vector_test.c
        APPEND PROPERTY OBJECT_DEPENDS ${_ninlil_pa_fixture})
    set_target_properties(
        ninlil_production_attachment_edhoc_vector_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_production_attachment_edhoc_vector_test)
    add_test(
        NAME production_attachment_edhoc_c11_gate
        COMMAND ninlil_production_attachment_edhoc_vector_test
    )
    add_test(
        NAME production_attachment_edhoc_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'production_attachment_edhoc_vector_gen.py'; build=pathlib.Path(r'${_ninlil_pa_fixture}'); assert build.is_file(), 'missing fixture'; td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'--emit-c-fixture',str(a)]); subprocess.check_call([sys.executable,str(py),'--emit-c-fixture',str(b)]); ta,tb,tbuild=a.read_bytes(),b.read_bytes(),build.read_bytes(); assert ta==tb, 'fixture non-deterministic'; assert ta==tbuild, 'build fixture stale'; assert b'NINLIL_PA_FRAGMENT_COUNT 5u' in ta; assert b'NINLIL_PA_NAB_ENTRY_COUNT 15u' in ta; print('production attachment fixture freshness ok',len(ta),'bytes')"
    )
    set_tests_properties(
        production_attachment_edhoc_vector_oracle_self_test
        production_attachment_edhoc_python_gate
        production_attachment_edhoc_python_gate_self_test
        production_attachment_edhoc_node_gate
        production_attachment_edhoc_node_gate_self_test
        production_attachment_magic_registry_gate
        production_attachment_magic_registry_gate_self_test
        production_attachment_edhoc_c11_gate
        production_attachment_edhoc_fixture_freshness
        PROPERTIES DEPENDS production_attachment_edhoc_vector_oracle
    )
    # ADR-0018 Proposed Wi-Fi real-path authority candidate (spec-only).
    # Independent generator/Python/Node/C11 gates; no Wi-Fi driver/TLS/HIL claim.
    add_test(
        NAME wifi_bearer_spec_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_vector_gen.py
            --check
    )
    add_test(
        NAME wifi_bearer_spec_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_vector_gen.py
            --self-test
    )
    add_test(
        NAME wifi_bearer_spec_python_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_gate.py
            --check
    )
    add_test(
        NAME wifi_bearer_spec_python_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_gate.py
            --self-test
    )
    add_test(
        NAME wifi_bearer_spec_node_gate
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_gate.mjs
            --check
    )
    add_test(
        NAME wifi_bearer_spec_node_gate_self_test
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_gate.mjs
            --self-test
    )
    set(_ninlil_wifi_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/wifi_bearer_spec_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_wifi_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_vector_gen.py
            --emit-c-fixture ${_ninlil_wifi_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_bearer_spec_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/wifi-bearer-spec-v1.json
        COMMENT "Generate Proposed Wi-Fi bearer C11 fixture"
        VERBATIM
    )
    add_custom_target(ninlil_wifi_fixture_gen DEPENDS ${_ninlil_wifi_fixture})
    add_executable(ninlil_wifi_bearer_spec_vector_test
        tests/transport/wifi_bearer_spec_vector_test.c
    )
    add_dependencies(
        ninlil_wifi_bearer_spec_vector_test
        ninlil_wifi_fixture_gen)
    target_include_directories(
        ninlil_wifi_bearer_spec_vector_test PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_property(
        SOURCE tests/transport/wifi_bearer_spec_vector_test.c
        APPEND PROPERTY OBJECT_DEPENDS ${_ninlil_wifi_fixture})
    set_target_properties(
        ninlil_wifi_bearer_spec_vector_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_wifi_bearer_spec_vector_test)
    # Normal host builds stay unsanitized. ASan/UBSan only when
    # NINLIL_ENABLE_SANITIZERS=ON (or global sanitizer path already active).
    if(NINLIL_ENABLE_SANITIZERS)
        if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU|AppleClang")
            target_compile_options(ninlil_wifi_bearer_spec_vector_test PRIVATE
                -fsanitize=address,undefined
                -fno-omit-frame-pointer)
            target_link_options(ninlil_wifi_bearer_spec_vector_test PRIVATE
                -fsanitize=address,undefined)
        endif()
    endif()
    add_test(
        NAME wifi_bearer_spec_c11_gate
        COMMAND ninlil_wifi_bearer_spec_vector_test
    )
    add_test(
        NAME wifi_bearer_spec_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'wifi_bearer_spec_vector_gen.py'; build=pathlib.Path(r'${_ninlil_wifi_fixture}'); assert build.is_file(), 'missing fixture'; td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'--emit-c-fixture',str(a)]); subprocess.check_call([sys.executable,str(py),'--emit-c-fixture',str(b)]); ta,tb,tbuild=a.read_bytes(),b.read_bytes(),build.read_bytes(); assert ta==tb, 'fixture non-deterministic'; assert ta==tbuild, 'build fixture stale'; assert b'NINLIL_WIFI_ACCEPTANCE_ID_COUNT 79u' in ta; assert b'ninlil_wifi_cases' in ta; print('wifi bearer fixture freshness ok',len(ta),'bytes')"
    )
    set_tests_properties(
        wifi_bearer_spec_vector_oracle_self_test
        wifi_bearer_spec_python_gate
        wifi_bearer_spec_python_gate_self_test
        wifi_bearer_spec_node_gate
        wifi_bearer_spec_node_gate_self_test
        wifi_bearer_spec_c11_gate
        wifi_bearer_spec_fixture_freshness
        PROPERTIES DEPENDS wifi_bearer_spec_vector_oracle
    )

    # Private Wi-Fi Host candidate unit + real-socket e2e (ADR-0018).
    if(NINLIL_ENABLE_PRIVATE_WIFI_V1)
        add_test(
            NAME wifi_v1_esp_resource_gate_self_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_v1_esp_resource_gate.py
                self-test)
        add_test(
            NAME wifi_v1_openssl_pin_provenance_self_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_v1_openssl_pin_provenance.py
                --self-test)

        add_executable(wifi_v1_nwb1_test
            tests/transport/wifi_v1/wifi_v1_nwb1_test.c)
        target_link_libraries(wifi_v1_nwb1_test PRIVATE ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_nwb1_test)
        add_test(NAME wifi_v1_nwb1_test COMMAND wifi_v1_nwb1_test)

        add_executable(wifi_v1_credentials_test
            tests/transport/wifi_v1/wifi_v1_credentials_test.c
            tests/support/in_memory_storage.c)
        target_include_directories(wifi_v1_credentials_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(wifi_v1_credentials_test PRIVATE ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_credentials_test)
        add_test(NAME wifi_v1_credentials_test COMMAND wifi_v1_credentials_test)

        add_executable(wifi_v1_leaf_binding_test
            tests/transport/wifi_v1/wifi_v1_leaf_binding_test.c)
        target_link_libraries(wifi_v1_leaf_binding_test PRIVATE ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_leaf_binding_test)
        add_test(NAME wifi_v1_leaf_binding_test COMMAND wifi_v1_leaf_binding_test)

        add_executable(wifi_v1_journal_test
            tests/transport/wifi_v1/wifi_v1_journal_test.c
            tests/support/in_memory_storage.c)
        target_include_directories(wifi_v1_journal_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(wifi_v1_journal_test PRIVATE ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_journal_test)
        add_test(NAME wifi_v1_journal_test COMMAND wifi_v1_journal_test)

        add_executable(wifi_v1_storage_commit_unknown_test
            tests/transport/wifi_v1/wifi_v1_storage_commit_unknown_test.c
            tests/support/in_memory_storage.c)
        target_include_directories(wifi_v1_storage_commit_unknown_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(wifi_v1_storage_commit_unknown_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_storage_commit_unknown_test)
        add_test(NAME wifi_v1_storage_commit_unknown_test
            COMMAND wifi_v1_storage_commit_unknown_test)

        add_executable(wifi_v1_reconnect_test
            tests/transport/wifi_v1/wifi_v1_reconnect_test.c)
        target_link_libraries(wifi_v1_reconnect_test PRIVATE ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_reconnect_test)
        add_test(NAME wifi_v1_reconnect_test COMMAND wifi_v1_reconnect_test)

        add_executable(wifi_v1_exporter_kat_test
            tests/transport/wifi_v1/wifi_v1_exporter_kat_test.c)
        target_link_libraries(wifi_v1_exporter_kat_test PRIVATE
            ninlil_wifi_v1_private OpenSSL::Crypto)
        ninlil_apply_strict_warnings(wifi_v1_exporter_kat_test)
        add_test(NAME wifi_v1_exporter_kat_test COMMAND wifi_v1_exporter_kat_test)

        add_executable(wifi_v1_attachment_gate_test
            tests/transport/wifi_v1/wifi_v1_attachment_gate_test.c)
        target_link_libraries(wifi_v1_attachment_gate_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_attachment_gate_test)
        add_test(NAME wifi_v1_attachment_gate_test
            COMMAND wifi_v1_attachment_gate_test)

        add_executable(wifi_v1_esp_owner_test
            tests/transport/wifi_v1/wifi_v1_esp_owner_test.c)
        target_link_libraries(wifi_v1_esp_owner_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_esp_owner_test)
        add_test(NAME wifi_v1_esp_owner_test COMMAND wifi_v1_esp_owner_test)

        add_executable(wifi_v1_esp_owner_sm_test
            tests/transport/wifi_v1/wifi_v1_esp_owner_sm_test.c)
        target_link_libraries(wifi_v1_esp_owner_sm_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_esp_owner_sm_test)
        add_test(NAME wifi_v1_esp_owner_sm_test COMMAND wifi_v1_esp_owner_sm_test)

        add_executable(wifi_v1_tls_arena_test
            tests/transport/wifi_v1/wifi_v1_tls_arena_test.c)
        target_link_libraries(wifi_v1_tls_arena_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_tls_arena_test)
        add_test(NAME wifi_v1_tls_arena_test COMMAND wifi_v1_tls_arena_test)

        # ADR-0026: compile the exact ESP allocator + R7 adapter sources on
        # Host against a deterministic fake ESP/mbedTLS boundary.  This is a
        # production-code owner/fault test, not an ESP target/HIL claim.
        add_executable(wifi_v1_r7_other_registered_fault_test
            tests/transport/wifi_v1/wifi_v1_r7_other_registered_fault_test.c
            tests/support/fake_esp_mbedtls/fake_esp_mbedtls.c
            src/transport/wifi_v1/wifi_esp_tls_allocator.c
            src/transport/wifi_v1/wifi_tls_arena.c
            src/transport/wifi_v1/wifi_tls_resource_policy.c
            ports/esp-idf/src/r7_crypto_mbedtls.c
            src/radio/r7_crypto_portable.c)
        target_include_directories(
            wifi_v1_r7_other_registered_fault_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support/fake_esp_mbedtls/include
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/wifi_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/radio)
        target_compile_definitions(
            wifi_v1_r7_other_registered_fault_test PRIVATE
            ESP_PLATFORM=1
            NINLIL_ENABLE_PRIVATE_WIFI_V1=1
            NINLIL_WIFI_ESP_TLS_ALLOCATOR_TEST_BUILD=1
            MBEDTLS_HKDF_C=1)
        set_target_properties(
            wifi_v1_r7_other_registered_fault_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(
            wifi_v1_r7_other_registered_fault_test)
        add_test(
            NAME wifi_v1_r7_other_registered_fault_test
            COMMAND wifi_v1_r7_other_registered_fault_test)

        add_executable(wifi_v1_esp_tls_identity_matrix_test
            tests/transport/wifi_v1/wifi_v1_esp_tls_identity_matrix_test.c)
        target_link_libraries(wifi_v1_esp_tls_identity_matrix_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_esp_tls_identity_matrix_test)
        add_test(NAME wifi_v1_esp_tls_identity_matrix_test
            COMMAND wifi_v1_esp_tls_identity_matrix_test)

        add_executable(wifi_v1_esp_adapter_e2e_test
            tests/transport/wifi_v1/wifi_v1_esp_adapter_e2e_test.c
            src/transport/wifi_v1/wifi_adapter_v1_esp.c
            tests/support/in_memory_storage.c)
        target_include_directories(wifi_v1_esp_adapter_e2e_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1)
        target_compile_definitions(wifi_v1_esp_adapter_e2e_test PRIVATE
            NINLIL_WIFI_ESP_ADAPTER_HOST_TEST=1
            NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
        target_link_libraries(wifi_v1_esp_adapter_e2e_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_esp_adapter_e2e_test)
        add_test(NAME wifi_v1_esp_adapter_e2e_test
            COMMAND wifi_v1_esp_adapter_e2e_test)

        add_executable(wifi_v1_m4_evidence_test
            tests/transport/wifi_v1/wifi_v1_m4_evidence_test.c
            tests/support/in_memory_storage.c)
        target_include_directories(wifi_v1_m4_evidence_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(wifi_v1_m4_evidence_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_m4_evidence_test)
        add_test(NAME wifi_v1_m4_evidence_test COMMAND wifi_v1_m4_evidence_test)

        # External-consumer forge probe: public header only surface.
        add_executable(wifi_v1_m4_forge_probe_test
            tests/transport/wifi_v1/wifi_v1_m4_forge_probe_test.c)
        target_link_libraries(wifi_v1_m4_forge_probe_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_m4_forge_probe_test)
        add_test(NAME wifi_v1_m4_forge_probe_test
            COMMAND wifi_v1_m4_forge_probe_test)

        add_executable(wifi_v1_m4_owner_concurrency_test
            tests/transport/wifi_v1/wifi_v1_m4_owner_concurrency_test.c)
        target_link_libraries(wifi_v1_m4_owner_concurrency_test PRIVATE
            ninlil_wifi_v1_private Threads::Threads)
        ninlil_apply_strict_warnings(wifi_v1_m4_owner_concurrency_test)
        add_test(NAME wifi_v1_m4_owner_concurrency_test
            COMMAND wifi_v1_m4_owner_concurrency_test)

        # Stale-completion barrier: needs test hooks on production sources.
        # Build a dedicated instrumented wifi archive + test (not default lib).
        add_library(ninlil_wifi_v1_m4_hooks STATIC EXCLUDE_FROM_ALL
            ${_ninlil_wifi_v1_srcs}
        )
        target_include_directories(ninlil_wifi_v1_m4_hooks PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/transport/wifi_v1>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        )
        target_compile_definitions(ninlil_wifi_v1_m4_hooks PRIVATE
            NINLIL_ENABLE_PRIVATE_WIFI_V1=1
            NINLIL_WIFI_M4_TEST_HOOKS=1)
        if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
            target_include_directories(ninlil_wifi_v1_m4_hooks PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1)
            target_compile_definitions(ninlil_wifi_v1_m4_hooks PRIVATE
                NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
        endif()
        if(NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL)
            target_compile_definitions(ninlil_wifi_v1_m4_hooks PUBLIC
                NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=1)
        endif()
        if(NINLIL_WIFI_OPENSSL_AUTHORITY)
            target_compile_definitions(ninlil_wifi_v1_m4_hooks PUBLIC
                NINLIL_WIFI_HOST_OPENSSL_STATIC_AUTHORITY=1)
        endif()
        target_link_libraries(ninlil_wifi_v1_m4_hooks PUBLIC
            Threads::Threads OpenSSL::SSL OpenSSL::Crypto)
        set_target_properties(ninlil_wifi_v1_m4_hooks PROPERTIES
            C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
            POSITION_INDEPENDENT_CODE ON C_VISIBILITY_PRESET hidden)
        ninlil_apply_strict_warnings(ninlil_wifi_v1_m4_hooks)

        add_executable(wifi_v1_m4_stale_load_barrier_test
            tests/transport/wifi_v1/wifi_v1_m4_stale_load_barrier_test.c
            tests/support/in_memory_storage.c)
        target_include_directories(wifi_v1_m4_stale_load_barrier_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_definitions(wifi_v1_m4_stale_load_barrier_test PRIVATE
            NINLIL_WIFI_M4_TEST_HOOKS=1)
        target_link_libraries(wifi_v1_m4_stale_load_barrier_test PRIVATE
            ninlil_wifi_v1_m4_hooks Threads::Threads)
        ninlil_apply_strict_warnings(wifi_v1_m4_stale_load_barrier_test)
        add_test(NAME wifi_v1_m4_stale_load_barrier_test
            COMMAND wifi_v1_m4_stale_load_barrier_test)

        # Full TSan: instrument library body + concurrency + stale-load tests.
        # Enabled only with NINLIL_ENABLE_TSAN=ON on non-Apple (CI Linux job).
        if(NINLIL_ENABLE_TSAN AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU"
                AND NOT APPLE)
            add_executable(wifi_v1_m4_owner_concurrency_tsan_test
                tests/transport/wifi_v1/wifi_v1_m4_owner_concurrency_test.c)
            target_link_libraries(wifi_v1_m4_owner_concurrency_tsan_test PRIVATE
                ninlil_wifi_v1_private Threads::Threads)
            target_compile_options(wifi_v1_m4_owner_concurrency_tsan_test PRIVATE
                -fsanitize=thread -fno-omit-frame-pointer)
            target_link_options(wifi_v1_m4_owner_concurrency_tsan_test PRIVATE
                -fsanitize=thread)
            add_test(NAME wifi_v1_m4_owner_concurrency_tsan_test
                COMMAND wifi_v1_m4_owner_concurrency_tsan_test)

            add_executable(wifi_v1_m4_stale_load_barrier_tsan_test
                tests/transport/wifi_v1/wifi_v1_m4_stale_load_barrier_test.c
                tests/support/in_memory_storage.c)
            target_include_directories(
                wifi_v1_m4_stale_load_barrier_tsan_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
                ${CMAKE_CURRENT_SOURCE_DIR}/include)
            target_compile_definitions(
                wifi_v1_m4_stale_load_barrier_tsan_test PRIVATE
                NINLIL_WIFI_M4_TEST_HOOKS=1)
            target_link_libraries(wifi_v1_m4_stale_load_barrier_tsan_test PRIVATE
                ninlil_wifi_v1_m4_hooks Threads::Threads)
            target_compile_options(wifi_v1_m4_stale_load_barrier_tsan_test
                PRIVATE -fsanitize=thread -fno-omit-frame-pointer)
            target_link_options(wifi_v1_m4_stale_load_barrier_tsan_test PRIVATE
                -fsanitize=thread)
            target_compile_options(ninlil_wifi_v1_m4_hooks PRIVATE
                -fsanitize=thread -fno-omit-frame-pointer)
            target_link_options(ninlil_wifi_v1_m4_hooks PUBLIC
                -fsanitize=thread)
            add_test(NAME wifi_v1_m4_stale_load_barrier_tsan_test
                COMMAND wifi_v1_m4_stale_load_barrier_tsan_test)
        endif()

        add_executable(wifi_v1_tls_storage_align_test
            tests/transport/wifi_v1/wifi_v1_tls_storage_align_test.c)
        target_link_libraries(wifi_v1_tls_storage_align_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_tls_storage_align_test)
        add_test(NAME wifi_v1_tls_storage_align_test
            COMMAND wifi_v1_tls_storage_align_test)

        add_executable(wifi_v1_queue_drop_wrap_test
            tests/transport/wifi_v1/wifi_v1_queue_drop_wrap_test.c)
        target_link_libraries(wifi_v1_queue_drop_wrap_test PRIVATE
            ninlil_wifi_v1_private)
        ninlil_apply_strict_warnings(wifi_v1_queue_drop_wrap_test)
        add_test(NAME wifi_v1_queue_drop_wrap_test
            COMMAND wifi_v1_queue_drop_wrap_test)

        if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
            add_executable(wifi_v1_fabric_link_test
                tests/transport/wifi_v1/wifi_v1_fabric_link_test.c)
            target_include_directories(wifi_v1_fabric_link_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
                ${CMAKE_CURRENT_SOURCE_DIR}/include)
            target_compile_definitions(wifi_v1_fabric_link_test PRIVATE
                NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
                NINLIL_ENABLE_PRIVATE_WIFI_V1=1)
            target_link_libraries(wifi_v1_fabric_link_test PRIVATE
                ninlil_wifi_v1_private)
            ninlil_apply_strict_warnings(wifi_v1_fabric_link_test)
            add_test(NAME wifi_v1_fabric_link_test COMMAND wifi_v1_fabric_link_test)

            add_executable(wifi_v1_adapter_lifecycle_test
                tests/transport/wifi_v1/wifi_v1_adapter_lifecycle_test.c
                tests/support/in_memory_storage.c)
            target_include_directories(wifi_v1_adapter_lifecycle_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
                ${CMAKE_CURRENT_SOURCE_DIR}/include)
            target_compile_definitions(wifi_v1_adapter_lifecycle_test PRIVATE
                NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
                NINLIL_ENABLE_PRIVATE_WIFI_V1=1)
            target_link_libraries(wifi_v1_adapter_lifecycle_test PRIVATE
                ninlil_wifi_v1_private)
            ninlil_apply_strict_warnings(wifi_v1_adapter_lifecycle_test)
            add_test(NAME wifi_v1_adapter_lifecycle_test
                COMMAND wifi_v1_adapter_lifecycle_test)

        endif()

        add_executable(wifi_v1_host_e2e_driver
            tools/wifi_v1_host_e2e_driver.c
            tests/support/in_memory_storage.c)
        target_include_directories(wifi_v1_host_e2e_driver PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_definitions(
            wifi_v1_host_e2e_driver PRIVATE _DEFAULT_SOURCE=1)
        target_link_libraries(wifi_v1_host_e2e_driver PRIVATE ninlil_wifi_v1_private)
        if(NINLIL_ENABLE_PRIVATE_FABRIC_V1
            AND NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
            target_sources(wifi_v1_host_e2e_driver PRIVATE
                tools/wifi_v1_fabric_host_send.c
                tools/wifi_v1_runtime_host_e2e.c
                src/transport/fabric_v1/nfl1_codec.c
                src/transport/fabric_v1/fabric_private_util.c
                src/transport/fabric_v1/fabric_workspace.c
                src/transport/fabric_v1/fabric_private_records.c
                src/transport/fabric_v1/fabric_private_select.c
                src/transport/fabric_v1/fabric_private_core.c)
            target_include_directories(wifi_v1_host_e2e_driver PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
                ${CMAKE_CURRENT_SOURCE_DIR}/tools)
            target_compile_definitions(wifi_v1_host_e2e_driver PRIVATE
                NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
                NINLIL_ENABLE_PRIVATE_WIFI_V1=1
                NINLIL_FABRIC_HOST_DIAGNOSTICS=1
                NINLIL_WIFI_HOST_FABRIC_SEND=1)
            target_link_libraries(wifi_v1_host_e2e_driver PRIVATE
                ninlil_runtime_private
                ninlil_posix_lab_platform
                ninlil_posix_sqlite_storage)
        endif()
        set_target_properties(wifi_v1_host_e2e_driver PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(wifi_v1_host_e2e_driver)

        add_test(
            NAME wifi_v1_host_e2e
            COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tools/wifi_v1_run_host_e2e.sh
                $<TARGET_FILE:wifi_v1_host_e2e_driver>
        )
        # Registered CTest is the bounded PR/ASan sample. The pinned-authority
        # CI job excludes this test and runs one explicit FRAMES=10000 release
        # evidence path, so ordinary matrices do not duplicate the ~18 min load.
        # halt_on_error=1: first ASan/UBSan report fails (no soft continue).
        set_tests_properties(wifi_v1_host_e2e PROPERTIES
            TIMEOUT 600
            ENVIRONMENT
                "FRAMES=200;UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1;ASAN_OPTIONS=halt_on_error=1:detect_stack_use_after_return=1"
        )

        # Optional TSan build of unit tests when compiler supports it.
        if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU|AppleClang"
            AND NOT APPLE AND NOT NINLIL_ENABLE_SANITIZERS)
            add_executable(wifi_v1_reconnect_tsan_test
                tests/transport/wifi_v1/wifi_v1_reconnect_test.c)
            target_link_libraries(wifi_v1_reconnect_tsan_test PRIVATE
                ninlil_wifi_v1_private)
            target_compile_options(wifi_v1_reconnect_tsan_test PRIVATE
                -fsanitize=thread -fno-omit-frame-pointer)
            target_link_options(wifi_v1_reconnect_tsan_test PRIVATE
                -fsanitize=thread)
            add_test(NAME wifi_v1_reconnect_tsan_test
                COMMAND wifi_v1_reconnect_tsan_test)
        endif()
    endif()

    add_test(
        NAME fabric_bearer_spec_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_bearer_spec_vector_gen.py
            --check
    )
    add_test(
        NAME fabric_bearer_spec_vector_gen_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_bearer_spec_vector_gen.py
            --self-test
    )
    add_test(
        NAME fabric_bearer_spec_cross_language_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_bearer_spec_gate.py
            --check
    )
    add_test(
        NAME fabric_bearer_spec_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_bearer_spec_gate.py
            --self-test
    )
    set_tests_properties(
        fabric_bearer_spec_vector_gen_self_test
        fabric_bearer_spec_cross_language_gate
        fabric_bearer_spec_gate_self_test
        PROPERTIES DEPENDS fabric_bearer_spec_vector_oracle
    )

    add_executable(ninlil_domain_vector_parse_test
        tests/model/domain_vector_parse_test.c
    )
    target_include_directories(ninlil_domain_vector_parse_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_domain_vector_parse_test PRIVATE
        ninlil_domain_vector_parse
    )
    set_target_properties(ninlil_domain_vector_parse_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_vector_parse_test)

    add_test(
        NAME domain_vector_parse_negative
        COMMAND ninlil_domain_vector_parse_test
    )

    add_executable(ninlil_runtime_store_bootstrap_test
        tests/model/runtime_store_bootstrap_test.c
    )
    target_include_directories(ninlil_runtime_store_bootstrap_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_runtime_store_bootstrap_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_runtime_store_bootstrap_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_runtime_store_bootstrap_test)

    add_test(
        NAME runtime_store_bootstrap
        COMMAND ninlil_runtime_store_bootstrap_test
    )

    # ADR-0022 tranche-1: format-2 binding + T0/T1a private feature-gated tests.
    # Always compiled into the test binary with the feature ON; production
    # private archive only includes the translation unit when the option is ON.
    add_executable(ninlil_domain_schema1_runtime_binding_test
        tests/model/domain_schema1_runtime_binding_test.c
        src/model/domain_schema1_runtime_binding.c
    )
    target_include_directories(ninlil_domain_schema1_runtime_binding_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_compile_definitions(ninlil_domain_schema1_runtime_binding_test PRIVATE
        NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
    target_link_libraries(ninlil_domain_schema1_runtime_binding_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_domain_schema1_runtime_binding_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_schema1_runtime_binding_test)
    add_test(
        NAME domain_schema1_runtime_binding
        COMMAND ninlil_domain_schema1_runtime_binding_test
    )

    find_program(CMAKE_NM NAMES nm llvm-nm)
    if(NOT CMAKE_NM)
        set(CMAKE_NM nm)
    endif()
    # Closed private inventory for feature-gated Domain schema1 (ADR-0022).
    # Not public include/ninlil ABI: symbols live only under src/model and
    # src/runtime private headers. Exact set is the production call-graph for
    # T0–T7 + kind-1 register/restore/quota + LAB cohabitation; not a pad list.
    # Notable multi-TU helpers (must remain linkage-visible, not static):
    #   validate_binding — binding encode/decode/open path
    #   classify_existing_namespace_adopt — startup owner T0 existing-NS adopt
    #   export_magic_match — export transcript magic gate
    #   is_lab_operational_key — Domain scan rejects V1-LAB TX/NRS keys
    #   quota_stage — Domain-ON admit SERVICE_QUOTA REPLACE
    set(_ninlil_d22_required_syms
        ninlil_domain_schema1_validate_foundation_common
        ninlil_domain_schema1_validate_binding
        ninlil_domain_schema1_validate_identity
        ninlil_domain_schema1_checked_count_bytes
        ninlil_domain_schema1_encode_binding
        ninlil_domain_schema1_decode_binding
        ninlil_domain_schema1_classify_binding_open
        ninlil_domain_schema1_classify_t0
        ninlil_domain_schema1_build_bootstrap_plan
        ninlil_domain_schema1_bootstrap_record_at
        ninlil_domain_schema1_classify_t1a_commit_unknown
        ninlil_domain_schema1_build_metadata_plan
        ninlil_domain_schema1_metadata_record_at
        ninlil_domain_schema1_classify_t1b_commit_unknown
        ninlil_domain_schema1_build_t5_clock_plan
        ninlil_domain_schema1_classify_t5_commit_unknown
        ninlil_domain_schema1_startup_init
        ninlil_domain_schema1_startup_complete_stage
        ninlil_domain_schema1_startup_fault
        ninlil_domain_schema1_startup_publication_allowed
        ninlil_domain_schema1_startup_pre_publish_side_effects_zero
        ninlil_domain_schema1_startup_export_transcript
        ninlil_domain_schema1_kind1_build_plan
        ninlil_domain_schema1_kind1_member_at
        ninlil_domain_schema1_kind1_plan_finish
        ninlil_domain_schema1_classify_kind1_commit_unknown
        ninlil_domain_schema1_classify_existing_namespace_adopt
        ninlil_domain_schema1_lab_classify_namespace
        ninlil_domain_schema1_export_magic_match
        ninlil_domain_schema1_owner_run_storage_recovery
        ninlil_domain_schema1_owner_t7_publication_gate
        ninlil_domain_schema1_kind1_owner_commit
        ninlil_domain_schema1_kind1_encode_members
        ninlil_domain_schema1_kind1_commit_full
        ninlil_domain_schema1_kind1_classify_readback
        ninlil_domain_schema1_service_register
        ninlil_domain_schema1_service_registry_restore
        ninlil_domain_schema1_quota_stage
        ninlil_domain_schema1_is_lab_operational_key
    )
    add_test(
        NAME domain_schema1_runtime_binding_feature_symbol_archive
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess; feature='${NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING}'; on=feature in ('ON','1','TRUE','true','True'); nm=r'${CMAKE_NM}'; build=pathlib.Path(r'${CMAKE_CURRENT_BINARY_DIR}'); lib=build/'libninlil_runtime_private.a'; assert lib.is_file(), 'missing private archive'; out=subprocess.check_output([nm,'-g','-U',str(lib)], text=True, errors='replace'); found=set();
[found.add(line.split()[-1].lstrip('_')) for line in out.splitlines() if line.strip()]; found=set(s for s in found if s.startswith('ninlil_domain_schema1_')); required=set([s for s in r'${_ninlil_d22_required_syms}'.split(';') if s]);
assert (not on and found==set()) or (on and found==required), ('feature='+feature+' found='+repr(sorted(found))+' required='+repr(sorted(required))); extra=found-required; assert not (on and extra), 'unexpected extra symbols '+repr(sorted(extra));
pub=build/'libninlil_runtime.a';
if pub.is_file():
 outp=subprocess.check_output([nm,'-g','-U',str(pub)], text=True, errors='replace'); pfound=set(line.split()[-1].lstrip('_') for line in outp.splitlines() if line.strip()); pfound=set(s for s in pfound if s.startswith('ninlil_domain_schema1_'));
 assert (not on and pfound==set()) or (on and pfound==required), ('public archive domain symbols mismatch feature='+feature+' found='+repr(sorted(pfound))+' required='+repr(sorted(required)));
 print('domain_schema1 public archive ok feature='+feature+' count='+str(len(pfound)));
print('domain_schema1 exact symbol archive ok feature='+feature+' count='+str(len(found)))"
    )
    add_test(
        NAME domain_schema1_runtime_binding_feature_symbol_exact_self_test
        COMMAND ${Python3_EXECUTABLE} -c
            "required=set([s for s in r'${_ninlil_d22_required_syms}'.split(';') if s]); found=set(required)|{'ninlil_domain_schema1_unexpected_extra'}; assert found!=required and len(found)==len(required)+1; print('domain_schema1 exact symbol self-test OK rejects 12th prefix')"
    )

    add_test(
        NAME domain_schema1_runtime_binding_vector_bridge
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_schema1_runtime_binding_vector_bridge.py
            --check
    )
    add_test(
        NAME domain_schema1_runtime_binding_vector_bridge_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_schema1_runtime_binding_vector_bridge.py
            --self-test
    )
    add_test(
        NAME domain_schema1_lab_export_tool_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/ninlil_lab_export.py
            --self-test
    )

    # ADR-0017 private Fabric v1 / NFL1: default-OFF production sources; tests
    # always compile the private TUs with the feature definition ON so KATs run
    # without requiring NINLIL_ENABLE_PRIVATE_FABRIC_V1 for the archive.
    set(_ninlil_fabric_v1_private_srcs
        ${NINLIL_FABRIC_V1_CORE_RELATIVE_SOURCES}
        src/transport/fabric_v1/fabric_host_radio_packet_link.c
    )
    if(NINLIL_BUILD_FABRIC_V1)
        add_executable(ninlil_fabric_v1_public_api_test
            tests/transport/fabric_v1/fabric_v1_public_api_test.c)
        target_link_libraries(ninlil_fabric_v1_public_api_test PRIVATE
            ninlil_fabric_v1)
        set_target_properties(ninlil_fabric_v1_public_api_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_fabric_v1_public_api_test)
        add_test(NAME fabric_v1_public_api
            COMMAND ninlil_fabric_v1_public_api_test)

        add_executable(ninlil_fabric_v1_public_behavior_test
            tests/transport/fabric_v1/fabric_v1_public_behavior_test.c)
        target_include_directories(ninlil_fabric_v1_public_behavior_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/fabric_v1)
        target_link_libraries(ninlil_fabric_v1_public_behavior_test PRIVATE
            ninlil_fabric_v1)
        set_target_properties(ninlil_fabric_v1_public_behavior_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_fabric_v1_public_behavior_test)
        add_test(NAME fabric_v1_public_behavior
            COMMAND ninlil_fabric_v1_public_behavior_test)
    endif()
    add_executable(ninlil_fabric_v1_nfl1_codec_test
        tests/transport/fabric_v1/nfl1_codec_test.c
        src/transport/fabric_v1/nfl1_codec.c
        src/transport/fabric_v1/fabric_private_util.c
    )
    target_include_directories(ninlil_fabric_v1_nfl1_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_nfl1_codec_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_nfl1_codec_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_nfl1_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_nfl1_codec_test)
    add_test(NAME fabric_v1_nfl1_codec COMMAND ninlil_fabric_v1_nfl1_codec_test)

    add_executable(ninlil_fabric_v1_lifecycle_test
        tests/transport/fabric_v1/fabric_v1_lifecycle_test.c
        ${_ninlil_fabric_v1_private_srcs}
    )
    target_include_directories(ninlil_fabric_v1_lifecycle_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_lifecycle_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_lifecycle_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_lifecycle_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_lifecycle_test)
    add_test(NAME fabric_v1_lifecycle COMMAND ninlil_fabric_v1_lifecycle_test)

    add_executable(ninlil_fabric_v1_p1_contracts_test
        tests/transport/fabric_v1/fabric_v1_p1_contracts_test.c
        ${_ninlil_fabric_v1_private_srcs}
    )
    target_include_directories(ninlil_fabric_v1_p1_contracts_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_p1_contracts_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_p1_contracts_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_p1_contracts_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_p1_contracts_test)
    add_test(NAME fabric_v1_p1_contracts COMMAND ninlil_fabric_v1_p1_contracts_test)

    add_executable(ninlil_fabric_v1_selection_test
        tests/transport/fabric_v1/fabric_v1_selection_test.c
        ${_ninlil_fabric_v1_private_srcs}
    )
    target_include_directories(ninlil_fabric_v1_selection_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_selection_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_selection_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_selection_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_selection_test)
    add_test(NAME fabric_v1_selection COMMAND ninlil_fabric_v1_selection_test)

    add_executable(ninlil_fabric_v1_records_test
        tests/transport/fabric_v1/fabric_v1_records_test.c
        ${_ninlil_fabric_v1_private_srcs}
    )
    target_include_directories(ninlil_fabric_v1_records_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_records_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_records_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_records_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_records_test)
    add_test(NAME fabric_v1_records COMMAND ninlil_fabric_v1_records_test)

    add_executable(ninlil_fabric_v1_nfl1_semantic_test
        tests/transport/fabric_v1/fabric_v1_nfl1_test.c
        src/transport/fabric_v1/nfl1_codec.c
        src/transport/fabric_v1/fabric_private_util.c
    )
    target_include_directories(ninlil_fabric_v1_nfl1_semantic_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_nfl1_semantic_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_nfl1_semantic_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_nfl1_semantic_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_nfl1_semantic_test)
    add_test(NAME fabric_v1_nfl1_semantic COMMAND ninlil_fabric_v1_nfl1_semantic_test)

    add_executable(ninlil_fabric_v1_vector_matrix_test
        tests/transport/fabric_v1/fabric_v1_vector_matrix_test.c
        ${_ninlil_fabric_v1_private_srcs}
    )
    target_include_directories(ninlil_fabric_v1_vector_matrix_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_vector_matrix_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_vector_matrix_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_vector_matrix_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_vector_matrix_test)
    add_test(NAME fabric_v1_vector_matrix COMMAND ninlil_fabric_v1_vector_matrix_test)

    if(NINLIL_ENABLE_PRIVATE_WIFI_V1)
        add_executable(wifi_v1_actual_adapter_fabric_e2e_test
            tests/transport/wifi_v1/wifi_v1_actual_adapter_fabric_e2e_test.c
            src/transport/wifi_v1/wifi_adapter_v1_esp.c
            tests/support/in_memory_storage.c
            ${_ninlil_fabric_v1_private_srcs}
        )
        target_include_directories(
            wifi_v1_actual_adapter_fabric_e2e_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/wifi_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(
            wifi_v1_actual_adapter_fabric_e2e_test PRIVATE
            NINLIL_WIFI_ESP_ADAPTER_HOST_TEST=1
            NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
            NINLIL_ENABLE_PRIVATE_WIFI_V1=1
        )
        target_link_libraries(
            wifi_v1_actual_adapter_fabric_e2e_test PRIVATE
            ninlil_wifi_v1_private
            ninlil
        )
        set_target_properties(
            wifi_v1_actual_adapter_fabric_e2e_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_strict_warnings(
            wifi_v1_actual_adapter_fabric_e2e_test)
        add_test(
            NAME wifi_v1_actual_adapter_fabric_e2e_test
            COMMAND wifi_v1_actual_adapter_fabric_e2e_test)
    endif()

    add_executable(ninlil_fabric_v1_host_acceptance_test
        tests/transport/fabric_v1/fabric_v1_host_acceptance_test.c
        ${_ninlil_fabric_v1_private_srcs}
    )
    target_include_directories(ninlil_fabric_v1_host_acceptance_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/fabric_v1
    )
    target_compile_definitions(ninlil_fabric_v1_host_acceptance_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_link_libraries(ninlil_fabric_v1_host_acceptance_test PRIVATE ninlil)
    set_target_properties(ninlil_fabric_v1_host_acceptance_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_fabric_v1_host_acceptance_test)
    add_test(NAME fabric_v1_host_acceptance COMMAND ninlil_fabric_v1_host_acceptance_test)

    # Fixture generators: compare-only --check + mutation self-test.
    add_test(
        NAME fabric_v1_selection_vector_gen_check
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_v1_selection_vector_gen.py
            --check
    )
    add_test(
        NAME fabric_v1_selection_vector_gen_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_v1_selection_vector_gen.py
            --self-test
    )
    add_test(
        NAME fabric_v1_exec_catalog_gen_check
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_v1_exec_catalog_gen.py
            --check
    )
    add_test(
        NAME fabric_v1_exec_catalog_gen_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_v1_exec_catalog_gen.py
            --self-test
    )
    add_test(
        NAME fabric_v1_vector_fixture_gen_check
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_v1_vector_fixture_gen.py
            --check
    )
    add_test(
        NAME fabric_v1_vector_fixture_gen_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/fabric_v1_vector_fixture_gen.py
            --self-test
    )

    set(_ninlil_fabric_v1_required_syms
        ninlil_fabric_private_nfl1_encode
        ninlil_fabric_private_nfl1_decode
        ninlil_fabric_private_nfl1_clear
        ninlil_fabric_private_create_v1
        ninlil_fabric_private_destroy_v1
        ninlil_fabric_private_register_link_v1
        ninlil_fabric_private_select
    )
    add_test(
        NAME fabric_v1_private_feature_symbol_archive
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess; feature='${NINLIL_ENABLE_PRIVATE_FABRIC_V1}'; on=feature in ('ON','1','TRUE','true','True'); nm=r'${CMAKE_NM}'; lib=pathlib.Path(r'${CMAKE_CURRENT_BINARY_DIR}')/'libninlil_runtime_private.a'; assert lib.is_file(), 'missing private archive'; out=subprocess.check_output([nm,'-g','-U',str(lib)], text=True, errors='replace'); found=set();
[found.add(line.split()[-1].lstrip('_')) for line in out.splitlines() if line.strip()]; found=set(s for s in found if s.startswith('ninlil_fabric_private_')); required=set([s for s in r'${_ninlil_fabric_v1_required_syms}'.split(';') if s]);
assert (not on and len(found)==0) or (on and required.issubset(found)), ('feature='+feature+' found_count='+str(len(found))+' missing='+repr(sorted(required-found))); print('fabric_v1 private symbol archive ok feature='+feature+' fabric_syms='+str(len(found)))"
    )

    # ADR-0019/0020 private route-relay/multi-parent: tests always compile the
    # private TUs with the feature definition ON so host KATs run without
    # requiring NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1 for the production archive.
    set(_ninlil_rrmp_private_srcs
        ${NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES}
        ${NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES}
        ${NINLIL_RRMP_HOST_SIM_RELATIVE_SOURCES}
    )
    set(_ninlil_rrmp_test_defs
        NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1
    )

    # Apply shared RRMP host-test properties (one owner path; no duplicate core).
    function(ninlil_rrmp_test_common_props _name)
        target_include_directories(${_name} PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/route_relay_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime/route_relay_v1
        )
        target_compile_definitions(${_name} PRIVATE ${_ninlil_rrmp_test_defs})
        target_link_libraries(${_name} PRIVATE ninlil)
        if(NINLIL_R7_HOST_CRYPTO_ENABLED)
            target_link_libraries(${_name} PRIVATE OpenSSL::Crypto)
        endif()
        set_target_properties(${_name} PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_strict_warnings(${_name})
        if(NOT _ninlil_any_sanitizer_active)
            include(CheckCCompilerFlag)
            check_c_compiler_flag(-Wframe-larger-than=2048 NINLIL_RRMP_TEST_HAS_WFRAME_2048)
            if(NINLIL_RRMP_TEST_HAS_WFRAME_2048)
                set(_ninlil_rrmp_test_frame_srcs
                    ${NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES}
                )
                set_source_files_properties(${_ninlil_rrmp_test_frame_srcs} PROPERTIES
                    COMPILE_OPTIONS "-Wframe-larger-than=2048;-fstack-usage"
                )
            endif()
        endif()
        add_test(NAME ${_name} COMMAND ${_name})
    endfunction()

    function(ninlil_add_rrmp_test _name)
        # All trailing args are host test sources; private RRMP TUs appended once.
        add_executable(${_name} ${ARGN} ${_ninlil_rrmp_private_srcs})
        ninlil_rrmp_test_common_props(${_name})
    endfunction()

    ninlil_add_rrmp_test(ninlil_rrmp_codec_test
        tests/runtime/route_relay_v1/rrmp_codec_test.c)
    ninlil_add_rrmp_test(ninlil_rrmp_sm_test
        tests/runtime/route_relay_v1/rrmp_sm_test.c)
    ninlil_add_rrmp_test(ninlil_rrmp_serial_owner_state_test
        tests/runtime/route_relay_v1/rrmp_serial_owner_state_test.c)
    ninlil_add_rrmp_test(ninlil_rrmp_crash_corrupt_test
        tests/runtime/route_relay_v1/rrmp_crash_corrupt_test.c)
    ninlil_add_rrmp_test(ninlil_rrmp_storage_atomicity_test
        tests/runtime/route_relay_v1/rrmp_storage_atomicity_test.c)
    ninlil_add_rrmp_test(ninlil_rrmp_token_ledger_test
        tests/runtime/route_relay_v1/rrmp_token_ledger_test.c)
    ninlil_add_rrmp_test(ninlil_rrmp_sim_lifecycle_test
        tests/runtime/route_relay_v1/rrmp_sim_lifecycle_test.c)
    # Host-only lifecycle fixture TU (not production, not ESP component).
    # Explicit multi-source list — never rely on production composition for KAT.
    ninlil_add_rrmp_test(ninlil_rrmp_composition_test
        tests/runtime/route_relay_v1/rrmp_composition_test.c
        tests/runtime/route_relay_v1/rrmp_host_lifecycle_fixture.c)

    # ADR-0029 §5: two live Fabric/RRMP pairs must not share dispatch state.
    add_executable(ninlil_rrmp_fabric_two_instance_isolation_test
        tests/runtime/route_relay_v1/rrmp_fabric_two_instance_isolation_test.c
        ${_ninlil_fabric_v1_private_srcs}
        ${_ninlil_rrmp_private_srcs})
    ninlil_rrmp_test_common_props(
        ninlil_rrmp_fabric_two_instance_isolation_test)
    target_include_directories(
        ninlil_rrmp_fabric_two_instance_isolation_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/transport/fabric_v1)
    target_compile_definitions(
        ninlil_rrmp_fabric_two_instance_isolation_test PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)

    add_test(
        NAME rrmp_resource_authority_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/rrmp_esp_dram_budget_gate.py
            authority-check
            --workspace-probe $<TARGET_FILE:ninlil_rrmp_codec_test>
    )
    add_test(
        NAME rrmp_resource_authority_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/rrmp_esp_dram_budget_gate.py
            self-test
    )

    set(_ninlil_rrmp_required_syms
        ninlil_rrmp_owner_init
        ninlil_rrmp_owner_workspace_bytes
        ninlil_rrmp_owner_bind
        ninlil_rrmp_owner_unbind
        ninlil_route_install_batch
        ninlil_route_activate
        ninlil_route_begin_drain
        ninlil_route_retire
        ninlil_route_query
        ninlil_route_forward_admit
        ninlil_route_forward_complete
        ninlil_route_cancel_drain
        ninlil_route_recover_commit_unknown
        ninlil_route_diagnostics_snapshot
        ninlil_rrmp_owner_bind_authorized
        ninlil_rrmp_core_forward_admit_with_carrier
        ninlil_rrmp_core_hop_forward_execute
        ninlil_rrmp_core_link_ack_from_evidence
        ninlil_rrmp_core_worker_tick
        ninlil_parent_set_install
        ninlil_parent_owner_prepare
        ninlil_parent_owner_fence_proof
        ninlil_parent_authority_commit
        ninlil_parent_owner_prepare_v2
        ninlil_parent_owner_fence_proof_v2
        ninlil_parent_authority_commit_v2
        ninlil_parent_owner_activate
        ninlil_parent_endpoint_observe
        ninlil_parent_owner_retire
        ninlil_parent_query
        ninlil_parent_recover_commit_unknown
        ninlil_parent_diagnostics_snapshot
        ninlil_rrmp_encode_nrd1
        ninlil_rrmp_encode_nps1
        ninlil_rrmp_core_forward_service_once
        ninlil_rrmp_route_precedence_pick
    )
    # Dedicated EXCLUDE_FROM_ALL archive for feature-symbol proof (does not
    # depend on unrelated private archive build breakages).
    add_library(ninlil_rrmp_private_probe STATIC EXCLUDE_FROM_ALL
        ${_ninlil_rrmp_private_srcs}
    )
    # Public platform ABI (ninlil/platform.h) + private RRMP headers.
    # Mirrors ninlil_add_rrmp_test linkage of public includes via ninlil.
    target_include_directories(ninlil_rrmp_private_probe PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/route_relay_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix
    )
    target_compile_definitions(ninlil_rrmp_private_probe PRIVATE
        ${_ninlil_rrmp_test_defs})
    if(NINLIL_R7_HOST_CRYPTO_ENABLED)
        target_link_libraries(ninlil_rrmp_private_probe PRIVATE OpenSSL::Crypto)
    endif()
    set_target_properties(ninlil_rrmp_private_probe PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    # Match production RRMP frame ceiling on non-sanitizer host builds.
    if(NOT _ninlil_any_sanitizer_active AND NINLIL_RRMP_TEST_HAS_WFRAME_2048)
        set_source_files_properties(
            src/runtime/route_relay_v1/rrmp_util.c
            src/runtime/route_relay_v1/rrmp_codec.c
            src/runtime/route_relay_v1/rrmp_store.c
            src/runtime/route_relay_v1/rrmp_core.c
            src/runtime/route_relay_v1/rrmp_seam.c
            src/runtime/route_relay_v1/rrmp_fabric_dispatch.c
            src/runtime/route_relay_v1/rrmp_composition.c
            PROPERTIES COMPILE_OPTIONS "-Wframe-larger-than=2048;-fstack-usage"
        )
    endif()
    # Probe archive (implementation sources) only when feature ON — OFF must not
    # compile rrmp implementation as evidence of absence.
    if(NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
        add_test(
            NAME rrmp_private_feature_symbol_probe
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
                --target ninlil_rrmp_private_probe
        )
        set_tests_properties(
            rrmp_private_feature_symbol_probe PROPERTIES
            RESOURCE_LOCK ninlil_ctest_build_tree)
    endif()
    # Feature-OFF production proxy: empty archive that MUST lack RRMP symbols.
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/rrmp_prod_off_proxy.c
        "void ninlil_prod_off_proxy_anchor(void) {}\n")
    add_library(ninlil_rrmp_prod_off_proxy STATIC EXCLUDE_FROM_ALL
        ${CMAKE_CURRENT_BINARY_DIR}/rrmp_prod_off_proxy.c)
    set_target_properties(ninlil_rrmp_prod_off_proxy PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    add_test(
        NAME rrmp_private_feature_symbol_prod_off_proxy
        COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
            --target ninlil_rrmp_prod_off_proxy
    )
    set_tests_properties(
        rrmp_private_feature_symbol_prod_off_proxy PROPERTIES
        RESOURCE_LOCK ninlil_ctest_build_tree)
    add_test(
        NAME rrmp_private_feature_symbol_archive
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess; feature='${NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1}'; on=feature in ('ON','1','TRUE','true','True'); nm=r'${CMAKE_NM}'; probe=pathlib.Path(r'${CMAKE_CURRENT_BINARY_DIR}')/'libninlil_rrmp_private_probe.a'; offp=pathlib.Path(r'${CMAKE_CURRENT_BINARY_DIR}')/'libninlil_rrmp_prod_off_proxy.a'; prod=pathlib.Path(r'${CMAKE_CURRENT_BINARY_DIR}')/'libninlil_runtime_private.a'; required=set([s for s in r'${_ninlil_rrmp_required_syms}'.split(';') if s]);
def syms(p):
 out=subprocess.check_output([nm,'-g','-U',str(p)], text=True, errors='replace'); f=set();
 [f.add(line.split()[-1].lstrip('_')) for line in out.splitlines() if line.strip()];
 return set(s for s in f if s.startswith('ninlil_rrmp_') or s.startswith('ninlil_route_') or s.startswith('ninlil_parent_'));
assert offp.is_file(), 'missing feature-OFF production proxy archive (no skip)';
offs=syms(offp); assert len(offs)==0, 'feature-OFF proxy must have zero rrmp symbols '+repr(sorted(offs));
if on:
 assert probe.is_file(), 'feature ON requires rrmp probe archive';
 ps=syms(probe); assert required.issubset(ps), 'probe missing '+repr(sorted(required-ps));
 forbidden={'ninlil_rrmp_owner_current'}; assert ps.isdisjoint(forbidden), 'probe retained legacy owner symbols '+repr(sorted(ps&forbidden));
 ops=set(s for s in required if s.startswith('ninlil_route_') or s.startswith('ninlil_parent_'));
 assert len(ops)>=20, 'need 20 catalog ops got '+str(len(ops));
 assert prod.is_file(), 'feature ON requires production archive present (no skip)';
 fs=syms(prod); assert required.issubset(fs), 'prod missing '+repr(sorted(required-fs));
 assert fs.isdisjoint(forbidden), 'prod retained legacy owner symbols '+repr(sorted(fs&forbidden));
 print('rrmp private symbol archive ok feature=ON probe_syms='+str(len(ps))+' ops='+str(len(ops)));
else:
 # OFF: must not require compiling implementation probe as evidence.
 assert not probe.is_file() or len(syms(probe))==0 or True;
 if prod.is_file():
  fs=syms(prod); assert 'ninlil_rrmp_owner_init' not in fs and 'ninlil_route_install_batch' not in fs, 'feature OFF prod must lack rrmp';
 print('rrmp private symbol archive ok feature=OFF off_proxy_syms=0 (no impl probe required)');"
    )
    if(NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
        set_tests_properties(rrmp_private_feature_symbol_archive PROPERTIES
            DEPENDS "rrmp_private_feature_symbol_probe;rrmp_private_feature_symbol_prod_off_proxy"
        )
    else()
        set_tests_properties(rrmp_private_feature_symbol_archive PROPERTIES
            DEPENDS "rrmp_private_feature_symbol_prod_off_proxy"
        )
    endif()

    add_test(
        NAME domain_schema1_runtime_binding_vector_bridge_node
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_schema1_runtime_binding_vector_bridge.mjs
            --check
    )
    add_test(
        NAME domain_schema1_runtime_binding_vector_bridge_node_self_test
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_schema1_runtime_binding_vector_bridge.mjs
            --self-test
    )

    add_executable(ninlil_domain_schema1_runtime_binding_bridge_test
        tests/model/domain_schema1_runtime_binding_bridge_test.c
        src/model/domain_schema1_runtime_binding.c
    )
    target_include_directories(ninlil_domain_schema1_runtime_binding_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_compile_definitions(ninlil_domain_schema1_runtime_binding_bridge_test PRIVATE
        NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
    target_link_libraries(ninlil_domain_schema1_runtime_binding_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_domain_schema1_runtime_binding_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_schema1_runtime_binding_bridge_test)
    add_test(
        NAME domain_schema1_runtime_binding_bridge
        COMMAND ninlil_domain_schema1_runtime_binding_bridge_test
    )

    # ADR-0022 T1b–T7 / kind-1 / LAB quarantine (private; no runtime_public).
    add_executable(ninlil_domain_schema1_startup_authority_test
        tests/model/domain_schema1_startup_authority_test.c
        src/model/domain_schema1_runtime_binding.c
        src/model/domain_schema1_startup_authority.c
    )
    target_include_directories(ninlil_domain_schema1_startup_authority_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_compile_definitions(ninlil_domain_schema1_startup_authority_test PRIVATE
        NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
    target_link_libraries(ninlil_domain_schema1_startup_authority_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_domain_schema1_startup_authority_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_schema1_startup_authority_test)
    add_test(
        NAME domain_schema1_startup_authority
        COMMAND ninlil_domain_schema1_startup_authority_test
    )

    if(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
        add_executable(ninlil_domain_schema1_startup_owner_test
            tests/runtime/domain_schema1_startup_owner_test.c
        )
        target_include_directories(ninlil_domain_schema1_startup_owner_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        )
        target_compile_definitions(ninlil_domain_schema1_startup_owner_test PRIVATE
            NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
        target_link_libraries(ninlil_domain_schema1_startup_owner_test PRIVATE
            ninlil_runtime_private
            ninlil_test_storage_fixture
            ninlil_test_platform_fixtures
            ninlil_test_typed_bearer_fixture
            ninlil
        )
        set_target_properties(ninlil_domain_schema1_startup_owner_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_strict_warnings(ninlil_domain_schema1_startup_owner_test)
        add_test(
            NAME domain_schema1_startup_owner
            COMMAND ninlil_domain_schema1_startup_owner_test
        )
        add_executable(ninlil_domain_schema1_publication_not_ready_test
            tests/runtime/domain_schema1_publication_not_ready_test.c
        )
        target_include_directories(
            ninlil_domain_schema1_publication_not_ready_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        )
        target_compile_definitions(
            ninlil_domain_schema1_publication_not_ready_test PRIVATE
            NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
        target_link_libraries(
            ninlil_domain_schema1_publication_not_ready_test PRIVATE
            ninlil_runtime_private
            ninlil_test_storage_fixture
            ninlil_test_platform_fixtures
            ninlil_test_typed_bearer_fixture
            ninlil
        )
        set_target_properties(
            ninlil_domain_schema1_publication_not_ready_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_strict_warnings(
            ninlil_domain_schema1_publication_not_ready_test)
        add_test(
            NAME domain_schema1_publication_not_ready
            COMMAND ninlil_domain_schema1_publication_not_ready_test
        )
        # Host header-only (explicit non-completion). ESP map required for completion.
        add_test(
            NAME domain_schema1_memory_gate_host_only
            COMMAND ${CMAKE_COMMAND} -E env
                NINLIL_DOMAIN_MEMORY_HOST_ONLY=1
                ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_schema1_memory_gate.py
                check
        )
        add_test(
            NAME domain_schema1_memory_gate_self_test
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_schema1_memory_gate.py
                self-test
        )
        # Completion path: fails without NINLIL_ESP_MAP (no false-green).
        add_test(
            NAME domain_schema1_memory_gate_completion_requires_map
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_schema1_memory_gate.py
                completion
        )
        set_tests_properties(
            domain_schema1_memory_gate_completion_requires_map
            PROPERTIES WILL_FAIL TRUE
        )
    endif()

    add_executable(ninlil_runtime_store_orchestrator_test
        tests/runtime/runtime_store_orchestrator_test.c
    )
    target_include_directories(ninlil_runtime_store_orchestrator_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(ninlil_runtime_store_orchestrator_test PRIVATE
        ninlil_runtime_private
        ninlil_test_storage_fixture
        ninlil_test_platform_fixtures
        ninlil
    )
    set_target_properties(ninlil_runtime_store_orchestrator_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_runtime_store_orchestrator_test)
    add_test(
        NAME runtime_store_orchestrator
        COMMAND ninlil_runtime_store_orchestrator_test
    )

    add_executable(ninlil_storage_canonical_plan_test
        tests/runtime/storage_canonical_plan_test.c
    )
    target_include_directories(ninlil_storage_canonical_plan_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(ninlil_storage_canonical_plan_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_storage_canonical_plan_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_storage_canonical_plan_test)
    add_test(
        NAME storage_canonical_plan
        COMMAND ninlil_storage_canonical_plan_test
    )

    add_executable(ninlil_runtime_store_stage5_seam_test
        tests/runtime/runtime_store_stage5_seam_test.c
    )
    target_include_directories(ninlil_runtime_store_stage5_seam_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(ninlil_runtime_store_stage5_seam_test PRIVATE
        ninlil_runtime_private
        ninlil_test_storage_fixture
        ninlil_test_platform_fixtures
        ninlil
    )
    set_target_properties(ninlil_runtime_store_stage5_seam_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_runtime_store_stage5_seam_test)
    add_test(
        NAME runtime_store_stage5_seam
        COMMAND ninlil_runtime_store_stage5_seam_test
    )

    add_executable(ninlil_stage5_empty_metadata_test
        tests/runtime/stage5_empty_metadata_test.c
    )
    target_include_directories(ninlil_stage5_empty_metadata_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(ninlil_stage5_empty_metadata_test PRIVATE
        ninlil_runtime_private
        ninlil_test_storage_fixture
        ninlil_test_platform_fixtures
        ninlil
    )
    set_target_properties(ninlil_stage5_empty_metadata_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_stage5_empty_metadata_test)
    add_test(
        NAME stage5_empty_metadata
        COMMAND ninlil_stage5_empty_metadata_test
    )

    add_executable(ninlil_v1_durable_allowlist_test
        tests/runtime/v1_durable_allowlist_test.c
    )
    target_include_directories(ninlil_v1_durable_allowlist_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(ninlil_v1_durable_allowlist_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_v1_durable_allowlist_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_durable_allowlist_test)
    add_test(
        NAME v1_durable_allowlist
        COMMAND ninlil_v1_durable_allowlist_test
    )

    add_executable(ninlil_v1_transaction_codec_test
        tests/runtime/v1_transaction_codec_test.c
    )
    target_include_directories(ninlil_v1_transaction_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(ninlil_v1_transaction_codec_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_v1_transaction_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_transaction_codec_test)
    add_test(
        NAME v1_transaction_codec
        COMMAND ninlil_v1_transaction_codec_test
    )

    add_executable(ninlil_v1_event_ledger_codec_test
        tests/runtime/v1_event_ledger_codec_test.c
    )
    target_include_directories(ninlil_v1_event_ledger_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(ninlil_v1_event_ledger_codec_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_v1_event_ledger_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_event_ledger_codec_test)
    add_test(
        NAME v1_event_ledger_codec
        COMMAND ninlil_v1_event_ledger_codec_test
    )

    add_executable(ninlil_v1_event_mgmt_ledger_test
        tests/runtime/v1_event_mgmt_ledger_test.c
    )
    target_include_directories(ninlil_v1_event_mgmt_ledger_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_v1_event_mgmt_ledger_test PRIVATE
        ninlil_runtime_private
        ninlil_test_platform_fixtures
        ninlil_test_storage_fixture
        ninlil_test_typed_bearer_fixture
        ninlil
    )
    set_target_properties(ninlil_v1_event_mgmt_ledger_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_event_mgmt_ledger_test)
    add_test(
        NAME v1_event_mgmt_ledger
        COMMAND ninlil_v1_event_mgmt_ledger_test
    )

    add_executable(ninlil_v1_runtime_spine_test
        tests/runtime/v1_runtime_spine_test.c
    )
    target_include_directories(ninlil_v1_runtime_spine_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_v1_runtime_spine_test PRIVATE
        ninlil_runtime_private
        ninlil_test_platform_fixtures
        ninlil_test_storage_fixture
        ninlil_test_typed_bearer_fixture
        ninlil
    )
    set_target_properties(ninlil_v1_runtime_spine_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_runtime_spine_test)
    add_test(
        NAME v1_runtime_spine
        COMMAND ninlil_v1_runtime_spine_test
    )

    add_executable(ninlil_v1_runtime_delivery_test
        tests/runtime/v1_runtime_delivery_test.c
    )
    target_include_directories(ninlil_v1_runtime_delivery_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_v1_runtime_delivery_test PRIVATE
        ninlil_runtime_private
        ninlil_test_platform_fixtures
        ninlil_test_storage_fixture
        ninlil_test_typed_bearer_fixture
        ninlil
    )
    set_target_properties(ninlil_v1_runtime_delivery_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_runtime_delivery_test)
    add_test(
        NAME v1_runtime_delivery
        COMMAND ninlil_v1_runtime_delivery_test
    )

    add_executable(ninlil_runtime_terminal_owner_projection_test
        tests/runtime/runtime_terminal_owner_projection_test.c
    )
    target_include_directories(
        ninlil_runtime_terminal_owner_projection_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_link_libraries(
        ninlil_runtime_terminal_owner_projection_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(
        ninlil_runtime_terminal_owner_projection_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_runtime_terminal_owner_projection_test)
    add_test(
        NAME runtime_terminal_owner_projection
        COMMAND ninlil_runtime_terminal_owner_projection_test
    )

    add_executable(ninlil_v1_runtime_capability_test
        tests/runtime/v1_runtime_capability_test.c
    )
    target_include_directories(ninlil_v1_runtime_capability_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_v1_runtime_capability_test PRIVATE
        ninlil_runtime_private
        ninlil_test_platform_fixtures
        ninlil_test_storage_fixture
        ninlil_test_typed_bearer_fixture
        ninlil
    )
    if(NINLIL_ENABLE_MFDT_V1_PRIVATE)
        target_include_directories(
            ninlil_v1_runtime_capability_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
        )
        target_compile_definitions(
            ninlil_v1_runtime_capability_test PRIVATE
            NINLIL_TEST_MFDT_RUNTIME_FAIL_CLOSED=1
        )
    endif()
    set_target_properties(ninlil_v1_runtime_capability_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_runtime_capability_test)
    add_test(
        NAME v1_runtime_capability
        COMMAND ninlil_v1_runtime_capability_test
    )

    add_executable(ninlil_v1_runtime_family_test
        tests/runtime/v1_runtime_family_test.c
    )
    target_include_directories(ninlil_v1_runtime_family_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_v1_runtime_family_test PRIVATE
        ninlil_runtime_private
        ninlil_test_platform_fixtures
        ninlil_test_storage_fixture
        ninlil_test_typed_bearer_fixture
        ninlil
    )
    set_target_properties(ninlil_v1_runtime_family_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_runtime_family_test)
    add_test(
        NAME v1_runtime_family
        COMMAND ninlil_v1_runtime_family_test
    )

    add_library(ninlil_test_scripted_storage_spy STATIC
        tests/support/scripted_storage_spy.c
    )
    target_include_directories(ninlil_test_scripted_storage_spy PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_test_scripted_storage_spy PRIVATE ninlil)
    set_target_properties(ninlil_test_scripted_storage_spy PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_strict_warnings(ninlil_test_scripted_storage_spy)

    add_executable(ninlil_domain_store_scanner_test
        tests/runtime/domain_store_scanner_test.c
    )
    target_include_directories(ninlil_domain_store_scanner_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    )
    target_compile_definitions(ninlil_domain_store_scanner_test PRIVATE
        NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN=1)
    target_link_libraries(ninlil_domain_store_scanner_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(ninlil_domain_store_scanner_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_store_scanner_test)
    add_test(
        NAME domain_store_scanner
        COMMAND ninlil_domain_store_scanner_test
    )

    # D3-S1 context/rebuild modes 1–20 + begin/evaluator unit coverage.
    # D3 overall / Stage5 D3 bind / D4 / public Runtime remain pending.
    add_executable(ninlil_domain_store_d3s1_test
        tests/runtime/domain_store_d3s1_test.c
    )
    target_include_directories(ninlil_domain_store_d3s1_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_domain_store_d3s1_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(ninlil_domain_store_d3s1_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_store_d3s1_test)
    add_test(
        NAME domain_store_d3s1
        COMMAND ninlil_domain_store_d3s1_test
    )

    # D3-S2 core: context/begin/reopen/PASS_INTERNAL freeze/B0/cleanup and
    # incremental Mode 21–26 FOCUS/BIND coverage. D3 complete remains pending.
    set(_ninlil_d3s2_wire_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_d3s2_wire_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_d3s2_wire_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_wire_fixture_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
            ${_ninlil_d3s2_wire_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_wire_fixture_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
        COMMENT "Generate pinned D3-S2 wire fixtures"
        VERBATIM
    )
    add_executable(ninlil_domain_store_d3s2_test
        tests/runtime/domain_store_d3s2_test.c
        ${_ninlil_d3s2_wire_fixture}
    )
    target_include_directories(ninlil_domain_store_d3s2_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(ninlil_domain_store_d3s2_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(ninlil_domain_store_d3s2_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_store_d3s2_test)
    add_test(
        NAME domain_store_d3s2
        COMMAND ninlil_domain_store_d3s2_test
    )

    # D3-S3 core: context/begin/drive empty product + anti-false-pass layout pins.
    # D3 complete / Stage5 D3 bind / D4 / public Runtime remain pending.
    add_executable(ninlil_domain_store_d3s3_test
        tests/runtime/domain_store_d3s3_test.c
    )
    target_include_directories(ninlil_domain_store_d3s3_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_domain_store_d3s3_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(ninlil_domain_store_d3s3_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_store_d3s3_test)
    add_test(
        NAME domain_store_d3s3
        COMMAND ninlil_domain_store_d3s3_test
    )
    add_test(
        NAME domain_scan_d3s2_wire_fixture_source
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_wire_fixture_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
    )
    add_test(
        NAME domain_scan_d3s2_wire_fixture_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_wire_fixture_gen.py
            self-test
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
    )
    add_test(
        NAME domain_scan_d3s2_wire_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_d3s2_wire_fixture_gen.py'; js=root/'spec'/'vectors'/'domain-store-v1.json'; build=pathlib.Path(r'${_ninlil_d3s2_wire_fixture}'); td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); assert a.read_bytes()==b.read_bytes()==build.read_bytes(); print('d3s2 wire fixture freshness+determinism ok')"
    )
    set_tests_properties(domain_scan_d3s2_wire_fixture_freshness PROPERTIES
        DEPENDS domain_store_d3s2
    )

    add_test(
        NAME domain_scan_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-v1.json
    )

    # Production bridge: oracle expectations vs production scanner (generated fixture).
    set(_ninlil_dsf_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_dsf_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-v1.json
            ${_ninlil_dsf_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-v1.json
        COMMENT "Generate domain-scan production bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_domain_store_scanner_oracle_bridge_test
        tests/runtime/domain_store_scanner_oracle_bridge_test.c
        ${_ninlil_dsf_fixture}
    )
    target_include_directories(ninlil_domain_store_scanner_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_compile_definitions(ninlil_domain_store_scanner_oracle_bridge_test PRIVATE
        NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN=1)
    target_link_libraries(ninlil_domain_store_scanner_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(ninlil_domain_store_scanner_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_store_scanner_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_oracle_bridge
        COMMAND ninlil_domain_store_scanner_oracle_bridge_test
    )

    # D2-S2 independent profile oracle + production profiled-begin bridge.
    add_test(
        NAME domain_scan_profile_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_profile_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-profile-v1.json
    )
    set(_ninlil_dsp_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_profile_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_dsp_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_profile_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-profile-v1.json
            ${_ninlil_dsp_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_profile_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-profile-v1.json
        COMMENT "Generate domain-scan-profile production bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_domain_store_scanner_profile_oracle_bridge_test
        tests/runtime/domain_store_scanner_profile_oracle_bridge_test.c
        ${_ninlil_dsp_fixture}
    )
    target_include_directories(
        ninlil_domain_store_scanner_profile_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_profile_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_profile_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_profile_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_profile_oracle_bridge
        COMMAND ninlil_domain_store_scanner_profile_oracle_bridge_test
    )

    # D2-S3 independent structural oracle + production profiled-begin bridge.
    add_test(
        NAME domain_scan_structural_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_structural_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-structural-v1.json
    )
    set(_ninlil_dss_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_structural_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_dss_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_structural_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-structural-v1.json
            ${_ninlil_dss_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_structural_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-structural-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
        COMMENT "Generate domain-scan-structural production bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_domain_store_scanner_structural_oracle_bridge_test
        tests/runtime/domain_store_scanner_structural_oracle_bridge_test.c
        ${_ninlil_dss_fixture}
    )
    target_include_directories(
        ninlil_domain_store_scanner_structural_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_structural_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_structural_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_structural_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_structural_oracle_bridge
        COMMAND ninlil_domain_store_scanner_structural_oracle_bridge_test
    )

    # D2-S4 independent exact-get oracle + production private exact_get bridge.
    add_test(
        NAME domain_scan_exact_get_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_exact_get_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-exact-get-v1.json
    )
    set(_ninlil_dse_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_exact_get_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_dse_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_exact_get_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-exact-get-v1.json
            ${_ninlil_dse_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_exact_get_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-exact-get-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-profile-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-structural-v1.json
        COMMENT "Generate domain-scan-exact-get production bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_domain_store_scanner_exact_get_oracle_bridge_test
        tests/runtime/domain_store_scanner_exact_get_oracle_bridge_test.c
        ${_ninlil_dse_fixture}
    )
    target_include_directories(
        ninlil_domain_store_scanner_exact_get_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_exact_get_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_exact_get_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_exact_get_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_exact_get_oracle_bridge
        COMMAND ninlil_domain_store_scanner_exact_get_oracle_bridge_test
    )

    # D2-S5 independent composition oracle + production profiled-begin bridge.
    add_test(
        NAME domain_scan_composition_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_composition_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-composition-v1.json
    )
    set(_ninlil_dsc_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_composition_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_dsc_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_composition_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-composition-v1.json
            ${_ninlil_dsc_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_composition_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-composition-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-profile-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-structural-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-exact-get-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
        COMMENT "Generate domain-scan-composition production bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_domain_store_scanner_composition_oracle_bridge_test
        tests/runtime/domain_store_scanner_composition_oracle_bridge_test.c
        ${_ninlil_dsc_fixture}
    )
    target_include_directories(
        ninlil_domain_store_scanner_composition_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_composition_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_composition_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_composition_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_composition_oracle_bridge
        COMMAND ninlil_domain_store_scanner_composition_oracle_bridge_test
    )

    # D3-S2 P2-A DSD1 multi-session composition sibling (docs/17 §18.13.16):
    # S1 modes 11/14/17/19 + S2 modes 22/23/24 as seven self-contained sessions
    # on one D1-valid fixture. Does not modify crossrow authority. Not Mode 28;
    # not dual-bound; not one-baseline-all-modes; not D3-S2 overall complete.
    add_test(
        NAME domain_scan_dsd1_composition_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_dsd1_composition_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-dsd1-composition-v1.json
    )
    add_test(
        NAME domain_scan_dsd1_composition_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_dsd1_composition_vector_gen.py
            self-test
    )
    set(_ninlil_dsd1_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_dsd1_composition_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_dsd1_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_dsd1_composition_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-dsd1-composition-v1.json
            ${_ninlil_dsd1_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_dsd1_composition_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s2_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-dsd1-composition-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
        COMMENT "Generate domain-scan-dsd1-composition production bridge fixture"
        VERBATIM
    )
    add_test(
        NAME domain_scan_dsd1_composition_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_dsd1_composition_vector_gen.py'; js=root/'spec'/'vectors'/'domain-scan-dsd1-composition-v1.json'; build=pathlib.Path(r'${_ninlil_dsd1_fixture}'); assert build.is_file(), 'missing build fixture '+str(build); td=tempfile.mkdtemp(); outs=[pathlib.Path(td)/'a.h', pathlib.Path(td)/'b.h']; [subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(o)]) for o in outs]; ta,tb,tbld=outs[0].read_bytes(),outs[1].read_bytes(),build.read_bytes(); assert ta==tb, 'emit-c-fixture non-deterministic'; assert ta==tbld, 'build fixture stale vs emit-c-fixture'; assert b'NINLIL_DSD1_VECTOR_COUNT ((size_t)1u)' in ta, 'dsd1 vector count pin missing'; assert b'NINLIL_DSD1_SESSION_COUNT ((size_t)7u)' in ta, 'dsd1 session count pin missing'; print('dsd1 composition fixture freshness+determinism ok', len(ta), 'bytes')"
    )
    set_tests_properties(domain_scan_dsd1_composition_fixture_freshness PROPERTIES
        DEPENDS domain_store_scanner_dsd1_composition_oracle_bridge
    )
    add_executable(ninlil_domain_store_scanner_dsd1_composition_oracle_bridge_test
        tests/runtime/domain_store_scanner_dsd1_composition_oracle_bridge_test.c
        ${_ninlil_dsd1_fixture}
    )
    target_include_directories(
        ninlil_domain_store_scanner_dsd1_composition_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_dsd1_composition_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_dsd1_composition_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_dsd1_composition_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_dsd1_composition_oracle_bridge
        COMMAND ninlil_domain_store_scanner_dsd1_composition_oracle_bridge_test
    )

    # The append-only crossrow authority is now D3-S4 (468 vectors). Keep the
    # frozen D3-S1/S2/S3 generators strict by projecting the exact accepted
    # 283-vector D3-S3 predecessor into the build directory. The projection
    # first runs the complete D3-S4 checker and is byte-pinned to the prior
    # D3-S3 whole-file authority; it is never a second semantic source.
    set(_ninlil_d3s4_authority
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json)
    set(_ninlil_d3s4_authority_shards
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/000-d3s1-slice-00.json
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/001-d3s2-slice-00.json
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/002-d3s3-slice-00.json
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/003-d3s3-slice-01.json
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/004-d3s4-slice-00.json
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/005-d3s4-slice-01.json
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/006-d3s4-slice-02.json
        ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.d/b0feba1f2543e1355532a835abe93f57da540cf89f35999737b2b259467bb2aa/007-d3s4-slice-03.json
    )
    set(_ninlil_d3s4_authority_loader
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s4_authority.py)
    set(_ninlil_d3s3_projection
        ${CMAKE_CURRENT_BINARY_DIR}/domain-scan-crossrow-d3s3-projection.json)
    add_custom_command(
        OUTPUT ${_ninlil_d3s3_projection}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_projection.py
            project
            ${_ninlil_d3s4_authority}
            ${_ninlil_d3s3_projection}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_projection.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s4_vector_gen.py
            ${_ninlil_d3s4_authority_loader}
            ${_ninlil_d3s4_authority}
            ${_ninlil_d3s4_authority_shards}
        COMMENT "Project exact frozen D3-S3 authority from D3-S4 append-only JSON"
        VERBATIM
    )
    add_custom_target(ninlil_domain_scan_crossrow_d3s3_projection
        DEPENDS ${_ninlil_d3s3_projection})
    add_test(
        NAME domain_scan_crossrow_d3s3_projection_check
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_projection.py
            check
            ${_ninlil_d3s4_authority}
            ${_ninlil_d3s3_projection}
    )
    add_test(
        NAME domain_scan_crossrow_d3s3_projection_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_projection.py
            self-test
            ${_ninlil_d3s4_authority}
    )
    add_test(
        NAME domain_scan_crossrow_d3s4_manifest_authority
        COMMAND ${Python3_EXECUTABLE}
            ${_ninlil_d3s4_authority_loader}
            check
            ${_ninlil_d3s4_authority}
    )
    add_test(
        NAME domain_scan_crossrow_d3s4_manifest_authority_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${_ninlil_d3s4_authority_loader}
            self-test
            ${_ninlil_d3s4_authority}
    )
    add_test(
        NAME domain_scan_crossrow_d3s4_manifest_node_authority
        COMMAND ${NINLIL_NODE_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s4_manifest_check.mjs
            ${_ninlil_d3s4_authority}
    )
    add_test(
        NAME domain_scan_crossrow_d3s4_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s4_vector_gen.py
            check
            ${_ninlil_d3s4_authority}
    )
    add_test(
        NAME domain_scan_crossrow_d3s4_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s4_vector_gen.py
            self-test
    )
    set_tests_properties(
        domain_scan_crossrow_d3s3_projection_check
        domain_scan_crossrow_d3s3_projection_self_test
        domain_scan_crossrow_d3s4_manifest_authority
        domain_scan_crossrow_d3s4_manifest_authority_self_test
        domain_scan_crossrow_d3s4_manifest_node_authority
        domain_scan_crossrow_d3s4_vector_oracle
        domain_scan_crossrow_d3s4_vector_oracle_self_test
        PROPERTIES TIMEOUT 180
    )
    # This mutation suite reconstructs the full D3-S4 oracle repeatedly and
    # exceeds 180 seconds on a four-core runner. Keep the larger budget scoped
    # to this one test; the sibling checks retain their 180-second ceiling.
    set_tests_properties(
        domain_scan_crossrow_d3s4_vector_oracle_self_test
        PROPERTIES TIMEOUT 600
    )
    set_tests_properties(
        domain_scan_crossrow_d3s4_manifest_authority_self_test
        PROPERTIES DEPENDS domain_scan_crossrow_d3s4_manifest_authority
    )
    set_tests_properties(
        domain_scan_crossrow_d3s3_projection_check
        domain_scan_crossrow_d3s3_projection_self_test
        domain_scan_crossrow_d3s4_vector_oracle
        domain_scan_crossrow_d3s4_vector_oracle_self_test
        PROPERTIES DEPENDS
            "domain_scan_crossrow_d3s4_manifest_authority;domain_scan_crossrow_d3s4_manifest_node_authority"
    )

    # Append-only D3-S2 crossrow sibling oracle (docs/17 §18.13.15):
    # frozen 94-vector D3-S1 prefix + 6 Mode21..26 empty-carrier smoke +
    # Mode25 CUM/RECENT/ANCHOR + Mode26 ES/MANAGEMENT + Mode24 RC/RR/DELIVERY
    # slices (suffix=12).
    # Independent generator rebuilds prefix from domain_scan_crossrow_vector_gen
    # and fails closed on prefix fingerprint/order/expected/rows/calls drift.
    # Does not claim full D3-S2 oracle complete. Stage5 D3 remains unbound.
    add_test(
        NAME domain_scan_crossrow_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s2_vector_gen.py
            check
            ${_ninlil_d3s3_projection}
    )
    add_test(
        NAME domain_scan_crossrow_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s2_vector_gen.py
            self-test
    )
    # Fixture freshness + determinism: emit twice (byte-identical) and equal
    # the build-dir artifact consumed by the production bridges.
    # Fail-closed pins: D3-S1 count=94 and D3-S2 suffix count=12.
    set(_ninlil_d3s1_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_crossrow_vector_fixture.h)
    add_test(
        NAME domain_scan_crossrow_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_crossrow_d3s2_vector_gen.py'; js=pathlib.Path(r'${_ninlil_d3s3_projection}'); build=pathlib.Path(r'${_ninlil_d3s1_fixture}'); assert build.is_file(), 'missing build fixture '+str(build); td=tempfile.mkdtemp(); outs=[pathlib.Path(td)/'a.h', pathlib.Path(td)/'b.h']; [subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(o)]) for o in outs]; ta,tb,tbld=outs[0].read_bytes(),outs[1].read_bytes(),build.read_bytes(); assert ta==tb, 'emit-c-fixture non-deterministic'; assert ta==tbld, 'build fixture stale vs emit-c-fixture'; assert b'NINLIL_D3S1_VECTOR_COUNT ((size_t)94u)' in ta, 'd3s1 vector count pin missing'; assert b'NINLIL_D3S2_VECTOR_COUNT ((size_t)50u)' in ta, 'd3s2 vector count pin missing'; print('crossrow fixture freshness+determinism ok', len(ta), 'bytes')"
    )
    # Single generator rule for the shared bridge fixture header.
    # Do NOT list this OUTPUT as a source on multiple executables: Ninja will
    # schedule the same custom command twice and compile can read a partial
    # header (build reliability; independent of U2 USB CDC).
    add_custom_command(
        OUTPUT ${_ninlil_d3s1_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s2_vector_gen.py
            emit-c-fixture
            ${_ninlil_d3s3_projection}
            ${_ninlil_d3s1_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s2_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_vector_gen.py
            ${_ninlil_d3s3_projection}
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-profile-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-structural-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-exact-get-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-composition-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
        COMMENT "Generate domain-scan-crossrow production bridge fixture (d3s1+d3s2)"
        VERBATIM
    )
    add_custom_target(ninlil_domain_scan_crossrow_vector_fixture
        DEPENDS ${_ninlil_d3s1_fixture}
    )
    # D3-S1 production bridge: still executes the frozen 94-vector prefix only.
    # Generated header is NOT a source (shared OUTPUT race); include dir +
    # OBJECT_DEPENDS + add_dependencies guarantee generation-before-compile.
    set(_ninlil_crossrow_bridge_c
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime/domain_store_scanner_crossrow_oracle_bridge_test.c)
    set(_ninlil_crossrow_d3s2_bridge_c
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c)
    set_source_files_properties(
        ${_ninlil_crossrow_bridge_c}
        ${_ninlil_crossrow_d3s2_bridge_c}
        PROPERTIES OBJECT_DEPENDS ${_ninlil_d3s1_fixture}
    )
    add_executable(ninlil_domain_store_scanner_crossrow_oracle_bridge_test
        ${_ninlil_crossrow_bridge_c}
    )
    target_include_directories(
        ninlil_domain_store_scanner_crossrow_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_crossrow_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_crossrow_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_crossrow_oracle_bridge_test)
    add_dependencies(
        ninlil_domain_store_scanner_crossrow_oracle_bridge_test
        ninlil_domain_scan_crossrow_vector_fixture
    )
    add_test(
        NAME domain_store_scanner_crossrow_oracle_bridge
        COMMAND ninlil_domain_store_scanner_crossrow_oracle_bridge_test
    )
    # D3-S2 first product-smoke bridge: 6 empty-carrier/empty-secondary sessions.
    # Not a full D3-S2 oracle complete claim.
    add_executable(ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test
        ${_ninlil_crossrow_d3s2_bridge_c}
    )
    target_include_directories(
        ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test)
    add_dependencies(
        ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test
        ninlil_domain_scan_crossrow_vector_fixture
    )
    add_test(
        NAME domain_store_scanner_crossrow_d3s2_oracle_bridge
        COMMAND ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test
    )
    # Freshness compares against the build artifact; ensure it is generated.
    set_tests_properties(domain_scan_crossrow_fixture_freshness PROPERTIES
        DEPENDS "domain_store_scanner_crossrow_oracle_bridge;domain_store_scanner_crossrow_d3s2_oracle_bridge"
    )

    # D3-S3 append-only crossrow oracle + production bridge
    add_test(
        NAME domain_scan_crossrow_d3s3_vector_oracle
        COMMAND ${CMAKE_COMMAND} -E env
            NINLIL_D3S3_AUTHORITY_PATH=${_ninlil_d3s3_projection}
            ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
                check
                ${_ninlil_d3s3_projection}
    )
    add_test(
        NAME domain_scan_crossrow_d3s3_vector_oracle_self_test
        COMMAND ${CMAKE_COMMAND} -E env
            NINLIL_D3S3_AUTHORITY_PATH=${_ninlil_d3s3_projection}
            ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
                self-test
    )
    set(_ninlil_d3s3_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_crossrow_d3s3_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_d3s3_fixture}
        COMMAND ${CMAKE_COMMAND} -E env
            NINLIL_D3S3_AUTHORITY_PATH=${_ninlil_d3s3_projection}
            ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
                emit-c-fixture
                ${_ninlil_d3s3_projection}
                ${_ninlil_d3s3_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
            ${_ninlil_d3s3_projection}
        COMMENT "Generate domain-scan-crossrow D3-S3 production bridge fixture"
        VERBATIM
    )
    add_executable(ninlil_domain_store_scanner_crossrow_d3s3_oracle_bridge_test
        tests/runtime/domain_store_scanner_crossrow_d3s3_oracle_bridge_test.c
        ${_ninlil_d3s3_fixture}
    )
    target_include_directories(
        ninlil_domain_store_scanner_crossrow_d3s3_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_crossrow_d3s3_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_crossrow_d3s3_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_crossrow_d3s3_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_crossrow_d3s3_oracle_bridge
        COMMAND ninlil_domain_store_scanner_crossrow_d3s3_oracle_bridge_test
    )
    add_test(
        NAME domain_scan_crossrow_d3s3_fixture_freshness
        COMMAND ${CMAKE_COMMAND} -E env
            NINLIL_D3S3_AUTHORITY_PATH=${_ninlil_d3s3_projection}
            ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_crossrow_d3s3_vector_gen.py'; js=pathlib.Path(r'${_ninlil_d3s3_projection}'); build=pathlib.Path(r'${_ninlil_d3s3_fixture}'); td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); assert a.read_bytes()==b.read_bytes()==build.read_bytes(); print('d3s3 fixture freshness+determinism ok')"
    )
    set_tests_properties(domain_scan_crossrow_d3s3_fixture_freshness PROPERTIES
        DEPENDS domain_store_scanner_crossrow_d3s3_oracle_bridge
    )

    # D3-S4 append-only authority (full 468 check) + typed bridge. The
    # authority and self-test are registered once above beside the frozen
    # D3-S3 projection; this block owns only the generated C bridge.
    set(_ninlil_d3s4_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_crossrow_d3s4_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_d3s4_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s4_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
            ${_ninlil_d3s4_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s4_vector_gen.py
            ${_ninlil_d3s4_authority_loader}
            ${_ninlil_d3s4_authority}
            ${_ninlil_d3s4_authority_shards}
        COMMENT "Generate domain-scan-crossrow D3-S4 typed production fixture"
        VERBATIM
    )
    add_executable(ninlil_domain_store_scanner_crossrow_d3s4_oracle_bridge_test
        tests/runtime/domain_store_scanner_crossrow_d3s4_oracle_bridge_test.c
        ${_ninlil_d3s4_fixture}
    )
    target_include_directories(
        ninlil_domain_store_scanner_crossrow_d3s4_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_scanner_crossrow_d3s4_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_scanner_crossrow_d3s4_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_scanner_crossrow_d3s4_oracle_bridge_test)
    add_test(
        NAME domain_store_scanner_crossrow_d3s4_oracle_bridge
        COMMAND ninlil_domain_store_scanner_crossrow_d3s4_oracle_bridge_test
    )
    add_test(
        NAME domain_scan_crossrow_d3s4_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_crossrow_d3s4_vector_gen.py'; js=root/'spec'/'vectors'/'domain-scan-crossrow-v1.json'; build=pathlib.Path(r'${_ninlil_d3s4_fixture}'); td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); assert a.read_bytes()==b.read_bytes()==build.read_bytes(); print('d3s4 fixture freshness+determinism ok')"
    )
    set_tests_properties(domain_scan_crossrow_d3s4_fixture_freshness PROPERTIES
        DEPENDS
            "domain_store_scanner_crossrow_d3s4_oracle_bridge;domain_scan_crossrow_d3s4_manifest_authority;domain_scan_crossrow_d3s4_manifest_node_authority"
    )

    # Supplemental D3-S2 close-semantics matrix. This is not the Normative
    # append-only crossrow sibling oracle required by docs/17 section 18.13.15.
    # A growing subset is bridged below; that full oracle remains pending.
    add_test(
        NAME domain_scan_d3s2_semantic_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_semantic_oracle.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-declared-multicount-semantics-v1.json
    )
    add_test(
        NAME domain_scan_d3s2_semantic_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_semantic_oracle.py
            self-test
    )
    set(_ninlil_d3s2_semantic_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_d3s2_semantic_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_d3s2_semantic_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_semantic_oracle.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-declared-multicount-semantics-v1.json
            ${_ninlil_d3s2_semantic_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_d3s2_semantic_oracle.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-declared-multicount-semantics-v1.json
        COMMENT "Generate D3-S2 semantic oracle bridge fixture"
        VERBATIM
    )
    add_library(ninlil_domain_store_d3s2_test_scenarios OBJECT
        tests/runtime/domain_store_d3s2_test.c
        ${_ninlil_d3s2_wire_fixture}
    )
    target_compile_definitions(ninlil_domain_store_d3s2_test_scenarios PRIVATE
        NINLIL_D3S2_TEST_NO_MAIN=1
    )
    target_include_directories(ninlil_domain_store_d3s2_test_scenarios PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    set_target_properties(ninlil_domain_store_d3s2_test_scenarios PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_domain_store_d3s2_test_scenarios)
    add_executable(ninlil_domain_store_d3s2_semantic_oracle_bridge_test
        tests/runtime/domain_store_d3s2_semantic_oracle_bridge_test.c
        ${_ninlil_d3s2_semantic_fixture}
        $<TARGET_OBJECTS:ninlil_domain_store_d3s2_test_scenarios>
    )
    target_include_directories(
        ninlil_domain_store_d3s2_semantic_oracle_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(
        ninlil_domain_store_d3s2_semantic_oracle_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil_test_scripted_storage_spy
        ninlil
    )
    set_target_properties(
        ninlil_domain_store_d3s2_semantic_oracle_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_domain_store_d3s2_semantic_oracle_bridge_test)
    add_test(
        NAME domain_store_d3s2_semantic_oracle_bridge
        COMMAND ninlil_domain_store_d3s2_semantic_oracle_bridge_test
    )
    add_test(
        NAME domain_scan_d3s2_semantic_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_d3s2_semantic_oracle.py'; js=root/'spec'/'vectors'/'domain-scan-declared-multicount-semantics-v1.json'; build=pathlib.Path(r'${_ninlil_d3s2_semantic_fixture}'); td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); assert a.read_bytes()==b.read_bytes()==build.read_bytes(); print('d3s2 semantic fixture freshness+determinism ok')"
    )
    set_tests_properties(domain_scan_d3s2_semantic_fixture_freshness PROPERTIES
        DEPENDS domain_store_d3s2_semantic_oracle_bridge
    )

    # Release absence: transport-only begin must not appear in tests-OFF private
    # object symbols (nm). Production profiled begin + exact_get + note remain.
    add_test(
        NAME domain_scan_transport_begin_release_absent
        COMMAND ${CMAKE_COMMAND}
            -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            "-DNINLIL_GENERATOR=${CMAKE_GENERATOR}"
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/domain_scan_transport_begin_absent.cmake
    )

    # DSR2_ESP_BOUND complete (S5): dedicated checked-in source gate.
    # Strips comments/strings; bans allocators/65536/re-read; proves single
    # value buffer; rejects automatic workspace/record locals; builds
    # scanner-local call graph to reject direct/mutual recursion; fail-closed
    # if function bodies cannot be parsed. Complements compiler -Wvla on
    # domain_store_scanner.c. Residual: no permanent stack-byte ceiling is
    # claimed; large automatic records are banned by source analysis.
    add_test(
        NAME domain_scan_dsr2_complete_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_dsr2_gate.py
            check
    )
    add_test(
        NAME domain_scan_dsr2_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_dsr2_gate.py
            self-test
    )

    # D2-S3 typed stack source gate: public validate_typed_record must not
    # declare a large typed_record local; no-output path is a separate helper.
    # No nonportable stack-usage attributes required. Pure expression form.
    add_test(
        NAME domain_scan_typed_stack_source_gate
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,re,sys; t=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}/src/model/domain_store_body_codec.c').read_text(); m=re.search(r'ninlil_status_t\\s+ninlil_model_domain_validate_typed_record\\s*\\(', t); sys.exit(print('public validate_typed_record not found') or 1) if not m else None; i=t.find('{', m.end()); depth=0; end=next((j+1 for j,ch in enumerate(t[i:], i) if (depth:=depth+(1 if ch=='{' else -1 if ch=='}' else 0))==0), None); body=t[i:end]; bad=(['large_local_in_public'] if re.search(r'ninlil_model_domain_typed_record_t\\s+\\w+\\s*;', body) else [])+([] if 'validate_typed_record_no_output' in t else ['missing_no_output_helper'])+([] if 'validate_typed_record_no_output' in body else ['public_does_not_call_no_output']); sys.exit(0 if not bad else (print('typed stack source gate failed:', bad) or 1))"
    )

    # D2-S6 source/release gates: production seam uses begin_profiled only
    # (never TEST transport begin); no 65536 allocator reread remains in
    # L2b1 orchestrator; stage5 workspace is bounded (no VLA / large stack).
    # tools/runtime_store_stage5_gate.py: comment/string strip, fail-closed
    # parse, negative self-tests. Complements compiler -Wvla on seam/orch.
    add_test(
        NAME runtime_store_stage5_seam_source_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/runtime_store_stage5_gate.py
            check
    )
    add_test(
        NAME runtime_store_stage5_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/runtime_store_stage5_gate.py
            self-test
    )
    add_test(
        NAME v1_durable_allowlist_source_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/v1_durable_allowlist_gate.py
            check
    )
    add_test(
        NAME v1_durable_allowlist_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/v1_durable_allowlist_gate.py
            self-test
    )
    add_test(
        NAME runtime_v1_durable_codec_source_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/runtime_v1_durable_codec_gate.py
            check
    )
    add_test(
        NAME runtime_v1_durable_codec_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/runtime_v1_durable_codec_gate.py
            self-test
    )

    # M3 packaging gates: host private source authority, ESP-IDF port
    # authority, component CMake include, ESP_IDF_VERSION pin consistency
    # across docs/CI/component metadata. Does not claim M3 port complete.
    add_test(
        NAME esp_idf_component_packaging_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_idf_component_packaging_gate.py
            check
    )
    add_test(
        NAME esp_idf_component_packaging_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_idf_component_packaging_gate.py
            self-test
    )
    # ESP SDK public include boundary: no src/** in public INCLUDE_DIRS;
    # external consumer positive/negative compile (host CC simulation).
    add_test(
        NAME esp_idf_sdk_public_boundary_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_idf_sdk_public_boundary_gate.py
            check
    )
    add_test(
        NAME esp_idf_sdk_public_boundary_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_idf_sdk_public_boundary_gate.py
            self-test
    )

    # M1a public family matrix usability (ADR-0024): docs-wide ban on wording
    # that misreads reserved LATEST_STATE/MEASUREMENT as first-class supported
    # families; entry surfaces must use display/leak EventFact labels.
    add_test(
        NAME m1a_public_family_docs_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/m1a_public_family_docs_gate.py
            check
    )
    add_test(
        NAME m1a_public_family_docs_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/m1a_public_family_docs_gate.py
            self-test
    )

    # Repo/release forbidden vocabulary: zero product-token hits
    # (case/space/typo variants of the banned k+guard family) across all
    # git-tracked release source/docs/archive content.
    add_test(
        NAME release_forbidden_vocabulary_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_forbidden_vocabulary_gate.py
            check
    )
    add_test(
        NAME release_forbidden_vocabulary_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_forbidden_vocabulary_gate.py
            self-test
    )
    # Release archive payload: expand tar/zip (or build from worktree), required
    # legal/security docs exact hashes, no symlink/traversal, denylist, two-run.
    add_test(
        NAME release_archive_payload_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_archive_payload_gate.py
            check
            --two-run
    )
    add_test(
        NAME release_archive_payload_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_archive_payload_gate.py
            self-test
    )
    # tests-OFF: POSIX LAB platform (tests/support fixtures) must not enter
    # default all or install/export surfaces.
    add_test(
        NAME posix_lab_tests_off_surface_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/posix_lab_tests_off_surface_gate.py
            check
    )
    add_test(
        NAME posix_lab_tests_off_surface_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/posix_lab_tests_off_surface_gate.py
            self-test
    )
    # Ordered release distribution authority (vocab → archive → tests-OFF
    # surface → Markdown links → matrix/notice/version/workflow/SBOM/public
    # boundary).
    add_test(
        NAME release_distribution_authority_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_distribution_authority_gate.py
            check
    )
    add_test(
        NAME release_distribution_authority_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_distribution_authority_gate.py
            self-test
    )
    add_test(
        NAME release_archive_cleanroom_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/release_archive_payload_gate.py
            cleanroom
            --profile host
    )

    # U0 radio/USB boundary freeze: docs consistency + terminology only.
    # Does not claim U1 complete / USB series complete / SX1262 production.
    add_test(
        NAME radio_usb_boundary_docs_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/radio_usb_boundary_docs_gate.py
            check
    )
    add_test(
        NAME radio_usb_boundary_docs_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/radio_usb_boundary_docs_gate.py
            self-test
    )

    # U5/U6 Normative docs: layout arithmetic + lifecycle + namespace budget.
    # Required docs PR gate (not word-marker only). Does not claim U5/U6 complete.
    add_test(
        NAME u5_u6_docs_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/u5_u6_docs_gate.py
            check
    )
    add_test(
        NAME u5_u6_docs_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/u5_u6_docs_gate.py
            self-test
    )

    # C1 portable contract must stay free of termios/fd/pthread/platform types.
    add_test(
        NAME byte_stream_portability_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/byte_stream_portability_gate.py
            check
    )
    add_test(
        NAME byte_stream_portability_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/byte_stream_portability_gate.py
            self-test
    )
    # C1 dual-surface include closure: private header self-contained under
    # -I src/transport; public under -I include; cascade control/logical/c4
    # resolve ninlil_byte_stream_* without leaking src/** to public roots.
    add_test(
        NAME byte_stream_include_closure_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/byte_stream_include_closure_gate.py
            check
    )
    add_test(
        NAME byte_stream_include_closure_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/byte_stream_include_closure_gate.py
            self-test
    )

    # U3: C3 control session + C4 pump structural/mutation gate (not marker-only).
    add_test(
        NAME control_session_u3_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/control_session_u3_gate.py
            check
    )
    add_test(
        NAME control_session_u3_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/control_session_u3_gate.py
            self-test
    )

    # R1: ninlil_radio_hal sole transmit-with-permit + host spy structural gate.
    # Does not claim R2/R4/SX1262/RF/legal/HIL/production radio complete.
    add_test(
        NAME radio_hal_r1_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/radio_hal_r1_gate.py
            check
    )
    add_test(
        NAME radio_hal_r1_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/radio_hal_r1_gate.py
            self-test
    )

    # R4: SX1262 control-plane backend structural gate (docs/28 + ADR-0008).
    # Does not claim R4 complete / RF TX / HIL / legal / R9 sole-edge.
    add_test(
        NAME sx1262_r4_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/sx1262_r4_gate.py
            check
    )
    add_test(
        NAME sx1262_r4_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/sx1262_r4_gate.py
            self-test
    )
    # Pure pending_logic single-TU C11 strict compile (stddef/NULL; -Werror).
    add_test(
        NAME sx1262_spi_pending_logic_strict_compile
        COMMAND ${CMAKE_C_COMPILER}
            -std=c11
            -Wall
            -Wextra
            -Werror
            -pedantic
            -c
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src/sx1262_spi_pending_logic.c
            -I${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
            -o
            ${CMAKE_CURRENT_BINARY_DIR}/sx1262_spi_pending_logic_strict.o
    )

    # R2: Physical Compliance Permit authority Normative freeze docs gate.
    # Does not claim R2 body implementation / legal / RF / HIL / re-review GO.
    add_test(
        NAME pcp_r2_docs_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pcp_r2_docs_gate.py
            check
    )
    add_test(
        NAME pcp_r2_docs_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pcp_r2_docs_gate.py
            self-test
    )

    add_test(
        NAME pcp_r2_rw_scan_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pcp_r2_rw_scan_gate.py
            check
    )
    add_test(
        NAME pcp_r2_rw_scan_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/pcp_r2_rw_scan_gate.py
            self-test
    )

    # R2 complete private header consumer compile (types/sizeof only).
    add_executable(ninlil_pcp_r2_consumer_compile
        tests/radio/pcp_r2_consumer_compile_test.c
    )
    target_include_directories(ninlil_pcp_r2_consumer_compile PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    set_target_properties(ninlil_pcp_r2_consumer_compile PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_pcp_r2_consumer_compile)
    add_test(NAME pcp_r2_consumer_compile COMMAND ninlil_pcp_r2_consumer_compile)

    # R2 time_sample ABI: real platform.h offsetof (POSIX LP64 host).
    add_executable(ninlil_pcp_r2_time_sample_abi
        tests/radio/pcp_r2_time_sample_abi_test.c
    )
    target_include_directories(ninlil_pcp_r2_time_sample_abi PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    set_target_properties(ninlil_pcp_r2_time_sample_abi PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_pcp_r2_time_sample_abi)
    add_test(NAME pcp_r2_time_sample_abi COMMAND ninlil_pcp_r2_time_sample_abi)

    # ILP32-class static_assert compile (ESP32-S3 layout class) via arm-none-eabi when present.
    find_program(NINLIL_ARM_NONE_EABI_GCC arm-none-eabi-gcc)
    if(NINLIL_ARM_NONE_EABI_GCC)
        add_custom_target(pcp_r2_time_sample_abi_ilp32_obj
            COMMAND ${NINLIL_ARM_NONE_EABI_GCC}
                -std=c11
                -ffreestanding
                -I${CMAKE_CURRENT_SOURCE_DIR}/include
                -c ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio/pcp_r2_time_sample_abi_static.c
                -o ${CMAKE_CURRENT_BINARY_DIR}/pcp_r2_time_sample_abi_ilp32.o
            DEPENDS
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio/pcp_r2_time_sample_abi_static.c
                ${CMAKE_CURRENT_SOURCE_DIR}/include/ninlil/platform.h
                ${CMAKE_CURRENT_SOURCE_DIR}/include/ninlil/version.h
            COMMENT "R2 time_sample ABI static_assert ILP32 (arm-none-eabi)"
            VERBATIM
        )
        add_test(
            NAME pcp_r2_time_sample_abi_ilp32
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
                --target pcp_r2_time_sample_abi_ilp32_obj
        )
        set_tests_properties(
            pcp_r2_time_sample_abi_ilp32 PROPERTIES
            RESOURCE_LOCK ninlil_ctest_build_tree)
    endif()

    add_executable(ninlil_radio_hal_r1_test
        tests/radio/radio_hal_r1_test.c
        tests/support/radio_hal_spy.c
    )
    target_include_directories(ninlil_radio_hal_r1_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_radio_hal_r1_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_radio_hal_r1_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_radio_hal_r1_test)
    add_test(
        NAME radio_hal_r1
        COMMAND ninlil_radio_hal_r1_test
    )

    # R3: LoRa airtime calculator (host candidate) — docs/oracle/C bridge.
    # airtime_r3_gate check includes VECTORS_FRESH_DETERMINISTIC:
    #   oracle emit-json/emit-c twice in independent temp dirs;
    #   run1==run2 and byte-identical to committed
    #   tests/radio/airtime_r3_vectors.json + airtime_r3_vectors.gen.h.
    # Does not claim R3 complete / Japan / HIL / RF.
    # tools/ and vector fixtures are tests-ON only (not private archive).
    add_test(
        NAME airtime_r3_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/airtime_r3_gate.py
            check
    )
    add_test(
        NAME airtime_r3_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/airtime_r3_gate.py
            self-test
    )
    add_test(
        NAME airtime_r3_oracle_self_check
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/airtime_r3_oracle.py
            self-check
    )
    add_executable(ninlil_airtime_r3_bridge_test
        tests/radio/airtime_r3_bridge_test.c
    )
    target_include_directories(ninlil_airtime_r3_bridge_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/radio
    )
    target_link_libraries(ninlil_airtime_r3_bridge_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_airtime_r3_bridge_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_airtime_r3_bridge_test)
    add_test(
        NAME airtime_r3_bridge
        COMMAND ninlil_airtime_r3_bridge_test
    )

    # R5: LAB_ONLY profile loader + full §9.3 permit bind matrix (host candidate).
    # Does not claim FIELD/PRODUCTION/Japan legal/RF/HIL/R5 complete.
    add_test(
        NAME profile_r5_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/profile_r5_gate.py
            check
    )
    add_test(
        NAME profile_r5_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/profile_r5_gate.py
            self-test
    )
    # R6: secure compact radio wire Normative freeze (docs-only).
    # Does not claim R7 codec/AEAD, handshake implementation, HIL, or R6 complete.
    # Chunk D N6 private record codec (exact length / CRC / alias / closed domain).
    # Host candidate only — not R6 complete / not ESP N6 ready.
    # Test-build N6 store: same N6 production sources + fixture binders.
    # Marked NINLIL_TEST_ONLY_ARTIFACT — never installed.
    add_library(ninlil_n6_store_testbuild STATIC EXCLUDE_FROM_ALL
        ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
        src/model/domain_store_codec.c
    )
    target_compile_definitions(ninlil_n6_store_testbuild PRIVATE NINLIL_N6_TEST_BUILD=1)
    target_include_directories(ninlil_n6_store_testbuild PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    set_target_properties(ninlil_n6_store_testbuild PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE)
    ninlil_apply_strict_warnings(ninlil_n6_store_testbuild)

    add_executable(ninlil_n6_context_store_test
        tests/radio/n6_context_store_test.c
        tests/support/n6_mem_storage.c
        tests/support/n6_local_identity_fixture.c
    )
    target_compile_definitions(ninlil_n6_context_store_test PRIVATE NINLIL_N6_TEST_BUILD=1)
    target_include_directories(ninlil_n6_context_store_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(ninlil_n6_context_store_test PRIVATE
        ninlil_n6_store_testbuild
        ninlil
    )
    set_target_properties(ninlil_n6_context_store_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_n6_context_store_test)
    add_test(
        NAME n6_context_store
        COMMAND ninlil_n6_context_store_test
    )

    add_executable(ninlil_n6_accepted_adapters_test
        tests/radio/n6_accepted_adapters_test.c
        tests/support/n6_mem_storage.c
        tests/support/n6_local_identity_fixture.c
    )
    target_include_directories(ninlil_n6_accepted_adapters_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(ninlil_n6_accepted_adapters_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_n6_accepted_adapters_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_n6_accepted_adapters_test)
    add_test(
        NAME n6_accepted_adapters
        COMMAND ninlil_n6_accepted_adapters_test
    )

    # Production private archive leakage + canonical N6 source authority.
    # Host tests-ON archive probe (DEPENDS explicit private target because
    # ninlil_runtime_private is EXCLUDE_FROM_ALL).
    add_test(
        NAME n6_chunk_d_private_symbol_leakage
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_chunk_d_leakage_gate.py
            check
            --archive $<TARGET_FILE:ninlil_runtime_private>
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
            --build-dir ${CMAKE_CURRENT_BINARY_DIR}
    )
    add_test(
        NAME n6_chunk_d_private_symbol_leakage_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_chunk_d_leakage_gate.py
            self-test
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(n6_chunk_d_private_symbol_leakage PROPERTIES
        DEPENDS ninlil_runtime_private)

    # Fresh tests-OFF Release packaging gate (docs/30 §20.2 / ADR-0010):
    # isolated subbuild, ctest -N = 0, explicit --target ninlil_runtime_private
    # (EXCLUDE_FROM_ALL pin), temp install public-only, ar N6 exact-once,
    # fixture/test/oracle/spy 0, nm/strings + leakage leak 0.
    # Mutation self-tests live in n6_chunk_d_leakage_gate.py self-test.
    add_test(
        NAME n6_tests_off_packaging_gate
        COMMAND ${CMAKE_COMMAND}
            -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            "-DNINLIL_GENERATOR=${CMAKE_GENERATOR}"
            -DNINLIL_PYTHON=${Python3_EXECUTABLE}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/n6_tests_off_packaging.cmake
    )

    # Heap ban: sources + exact three N6 members of production private archive.
    add_test(
        NAME n6_heap_ban_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_heap_ban_gate.py
            check
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
            --archive $<TARGET_FILE:ninlil_runtime_private>
    )
    add_test(
        NAME n6_heap_ban_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_heap_ban_gate.py
            self-test
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(n6_heap_ban_gate PROPERTIES
        DEPENDS ninlil_runtime_private)

    # N6 accepted-source SHA-256 pin gate (docs/07 manifest; not C semantics).
    add_test(
        NAME n6_storage_callsite_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_storage_callsite_gate.py
            check
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(
        NAME n6_storage_callsite_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_storage_callsite_gate.py
            self-test
            --src-root ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(n6_storage_callsite_gate PROPERTIES TIMEOUT 30)
    set_tests_properties(n6_storage_callsite_gate_self_test PROPERTIES TIMEOUT 60)

    # GCC 13 Release compile_commands structural self-test (false-green mutations).
    # Live check against a real compile_commands.json is CI-only
    # (ubuntu-gcc-release-n6-frame with gcc-13); do not register host check CTest
    # that would false-red AppleClang / non-13 toolchains. R6 required identity
    # set remains the exact 14 names asserted in that CI job.
    add_test(
        NAME n6_gcc13_release_compile_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_gcc13_release_compile_gate.py
            self-test
    )
    set_tests_properties(n6_gcc13_release_compile_gate_self_test PROPERTIES
        TIMEOUT 30)

    # Stack-usage: recursive discover under production object dir only
    # (CMakeFiles/ninlil_runtime_private.dir). Never whole-build or testbuild.
    # Host AppleClang/GCC both emit .su — missing artifacts fail (no host skip).
    # ESP N6 .su is separate: without --esp-su-dir the gate reports ESP NOT-RUN
    # (not a PASS). When an ESP object dir is available, pass --esp-su-dir.
    # ESP CI collects actual ESP N6 .su and passes both --su-dir/--esp-su-dir
    # (host substitute forbidden; see n6_frame_stack_gate check-structure).
    #
    # Production .su gate is authoritative only for non-sanitize host builds
    # (matches -Wframe-larger-than skip above). ASan/UBSan — including active
    # pointer-compare ASan — rewrite .su kind to dynamic and inflate frames;
    # do not register/run the production gate when _ninlil_any_sanitizer_active.
    # Self-test and check-structure always run (logic/wiring regression only).
    # GNU x86 Debug/Release both register production (static .su via
    # -maccumulate-outgoing-args); only sanitizer builds skip production.
    add_test(
        NAME n6_frame_stack_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_frame_stack_gate.py
            self-test
    )
    add_test(
        NAME n6_frame_stack_gate_structure
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_frame_stack_gate.py
            check-structure
    )
    if(NOT _ninlil_any_sanitizer_active)
        add_test(
            NAME n6_frame_stack_gate
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/n6_frame_stack_gate.py
                check
                --su-dir ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ninlil_runtime_private.dir
        )
        set_tests_properties(n6_frame_stack_gate PROPERTIES
            DEPENDS ninlil_runtime_private)
    else()
        message(STATUS
            "n6_frame_stack_gate: not registered under active sanitizer "
            "(NINLIL_ENABLE_SANITIZERS or pointer-compare; production .su "
            "non-authoritative under instrumentation; "
            "n6_frame_stack_gate_self_test/structure still enabled; "
            "non-sanitize CI owns .su)")
    endif()

    add_executable(ninlil_n6_record_codec_test
        tests/radio/n6_record_codec_test.c
    )
    target_include_directories(ninlil_n6_record_codec_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(ninlil_n6_record_codec_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_n6_record_codec_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_n6_record_codec_test)
    add_test(
        NAME n6_record_codec
        COMMAND ninlil_n6_record_codec_test
    )

    add_test(
        NAME radio_wire_r6_docs_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/radio_wire_r6_docs_gate.py
            check
    )
    add_test(
        NAME radio_wire_r6_docs_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/radio_wire_r6_docs_gate.py
            self-test
    )

    # R7 T0 private crypto: portable/OpenSSL3/37-vector bridge + gates.
    # Single authority: cmake/ninlil_r7_crypto_ctest.cmake. Does not claim
    # W1/L1 codec, ESP KAT execution, HIL, or R7 complete.
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_r7_crypto_ctest.cmake)
    # R7 T1 NRW1 SINGLE pure wire codec (docs/32). Separate nrw1_t1_* CTest
    # authority; does not weaken T0 r7_* exact 16/15. Not R7 full / W1 / HIL.
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_r7_wire_ctest.cmake)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_r7_frag_ctest.cmake)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_decoder_fuzz.cmake)
    # ADR-0021 MFDT private implementation (default-OFF). Distinct from
    # SPEC-ONLY gates in cmake/ninlil_mfdt_ctest.cmake. Not installed/public/HIL.
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_mfdt_v1_ctest.cmake)

    # Simultaneous all-private Host integration authority.
    #
    # Configure/CTest registration alone is not evidence.  The aggregate target
    # builds the production-private archives and two final executables:
    #  - one-process coexistence probe with a checked live call through Domain,
    #    Fabric, Wi-Fi, R7 FRAG, RRMP, and MFDT (not cross-feature E2E);
    #  - the fail-closed test-only multi-process transport fixture.
    #
    # Register only for the exact six-feature profile.  This is Host software
    # evidence and never claims physical HIL/RF/power-cut execution.
    if(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING
        AND NINLIL_ENABLE_PRIVATE_WIFI_V1
        AND NINLIL_ENABLE_PRIVATE_FABRIC_V1
        AND NINLIL_ENABLE_R7_FRAG_PRIVATE
        AND NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1
        AND NINLIL_ENABLE_MFDT_V1_PRIVATE)
        foreach(_host_completion_required_target IN ITEMS
                ninlil_runtime_private
                ninlil_wifi_v1_private
                ninlil_r7_frag_private)
            if(NOT TARGET ${_host_completion_required_target})
                message(FATAL_ERROR
                    "all-private Host integration requires CMake target "
                    "${_host_completion_required_target}")
            endif()
        endforeach()
        unset(_host_completion_required_target)

        add_executable(ninlil_host_completion_all_private_coexistence_probe
            EXCLUDE_FROM_ALL
            tests/host/host_completion_all_private_coexistence_probe.c)
        target_include_directories(
            ninlil_host_completion_all_private_coexistence_probe PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/route_relay_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/wifi_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
            ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_definitions(
            ninlil_host_completion_all_private_coexistence_probe PRIVATE
            NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1
            NINLIL_ENABLE_PRIVATE_WIFI_V1=1
            NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
            NINLIL_ENABLE_R7_FRAG_PRIVATE=1
            NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1
            NINLIL_ENABLE_MFDT_V1_PRIVATE=1)
        target_link_libraries(
            ninlil_host_completion_all_private_coexistence_probe PRIVATE
            ninlil_wifi_v1_private
            ninlil_r7_frag_private
            ninlil_runtime_private
            ninlil)
        set_target_properties(
            ninlil_host_completion_all_private_coexistence_probe PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            NINLIL_TEST_ONLY_ARTIFACT TRUE)
        ninlil_apply_strict_warnings(
            ninlil_host_completion_all_private_coexistence_probe)
        if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
            target_compile_options(
                ninlil_host_completion_all_private_coexistence_probe
                PRIVATE -Wvla)
        endif()

        add_executable(ninlil_host_completion_transport_fixture_e2e
            EXCLUDE_FROM_ALL
            tests/host/host_completion_transport_fixture_e2e.c
            tests/support/host_completion_wire.c
            tests/support/in_memory_storage.c)
        target_include_directories(
            ninlil_host_completion_transport_fixture_e2e PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/route_relay_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/wifi_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/host
            ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_compile_definitions(
            ninlil_host_completion_transport_fixture_e2e PRIVATE
            _DEFAULT_SOURCE=1
            NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1
            NINLIL_ENABLE_PRIVATE_WIFI_V1=1
            NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
            NINLIL_ENABLE_R7_FRAG_PRIVATE=1
            NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1
            NINLIL_ENABLE_MFDT_V1_PRIVATE=1
            NINLIL_RRMP_HAVE_OPENSSL=1)
        target_link_libraries(
            ninlil_host_completion_transport_fixture_e2e PRIVATE
            ninlil_wifi_v1_private
            ninlil_r7_frag_private
            ninlil_runtime_private
            ninlil)
        set_target_properties(
            ninlil_host_completion_transport_fixture_e2e PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            NINLIL_TEST_ONLY_ARTIFACT TRUE)
        ninlil_apply_strict_warnings(
            ninlil_host_completion_transport_fixture_e2e)
        if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
            target_compile_options(
                ninlil_host_completion_transport_fixture_e2e PRIVATE -Wvla)
        endif()

        add_custom_target(host_completion_all_private_build
            DEPENDS
                ninlil_runtime_private
                ninlil_wifi_v1_private
                ninlil_r7_frag_private
                ninlil_host_completion_all_private_coexistence_probe
                ninlil_host_completion_transport_fixture_e2e)

        add_test(
            NAME host_completion_all_private_build_fixture
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
                --target host_completion_all_private_build)
        set_tests_properties(
            host_completion_all_private_build_fixture PROPERTIES
            FIXTURES_SETUP host_completion_all_private_build
            RESOURCE_LOCK ninlil_ctest_build_tree)

        add_test(
            NAME host_completion_all_private_coexistence_probe
            COMMAND ninlil_host_completion_all_private_coexistence_probe)
        set_tests_properties(
            host_completion_all_private_coexistence_probe PROPERTIES
            FIXTURES_REQUIRED host_completion_all_private_build
            PASS_REGULAR_EXPRESSION
                "all_private_coexistence: ALL PASS process_calls=6 canonical_cross_feature_e2e=NOT_CLAIMED physical_hil=NOT_RUN"
            TIMEOUT 60)

        if(NINLIL_ENABLE_SANITIZERS)
            set(_host_completion_profile_label "asan")
        else()
            set(_host_completion_profile_label "normal")
        endif()
        add_test(
            NAME host_completion_transport_fixture_e2e
            COMMAND
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/host_completion_integrated_e2e.sh
                --driver
                    $<TARGET_FILE:ninlil_host_completion_transport_fixture_e2e>
                --coexistence-probe
                    $<TARGET_FILE:ninlil_host_completion_all_private_coexistence_probe>
                --label ${_host_completion_profile_label})
        set_tests_properties(
            host_completion_transport_fixture_e2e PROPERTIES
            FIXTURES_REQUIRED host_completion_all_private_build
            TIMEOUT 600
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            ENVIRONMENT
                "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1;ASAN_OPTIONS=halt_on_error=1:detect_stack_use_after_return=1:detect_leaks=0")

        add_test(
            NAME host_completion_transport_fixture_e2e_negative_self_test
            COMMAND
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/host_completion_integrated_e2e.sh
                --driver
                    $<TARGET_FILE:ninlil_host_completion_transport_fixture_e2e>
                --coexistence-probe
                    $<TARGET_FILE:ninlil_host_completion_all_private_coexistence_probe>
                --label ${_host_completion_profile_label}-negative-preflight
                --negative-self-test)
        set_tests_properties(
            host_completion_transport_fixture_e2e_negative_self_test PROPERTIES
            FIXTURES_REQUIRED host_completion_all_private_build
            PASS_REGULAR_EXPRESSION
                "host_completion_transport_fixture_e2e: NEGATIVE SELF-TEST PASS"
            TIMEOUT 900
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            ENVIRONMENT
                "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1;ASAN_OPTIONS=halt_on_error=1:detect_stack_use_after_return=1:detect_leaks=0")
        unset(_host_completion_profile_label)
    endif()

    # Private MFDT (ADR-0021) optional runtime probe when enabled: production
    # sources only (no host lab store). Not installed. Not public ABI.
    if(NINLIL_ENABLE_MFDT_V1_PRIVATE)
        include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_mfdt_v1_sources.cmake)
        add_library(ninlil_mfdt_v1_runtime_probe STATIC EXCLUDE_FROM_ALL
            ${NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES}
            src/runtime/mfdt_v1/mfdt_v1_store.c
        )
        target_include_directories(ninlil_mfdt_v1_runtime_probe PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_compile_definitions(ninlil_mfdt_v1_runtime_probe PRIVATE
            NINLIL_MFDT_V1_PRIVATE=1
            NINLIL_MFDT_V1_RUNTIME_PROBE=1
        )
        set_target_properties(ninlil_mfdt_v1_runtime_probe PROPERTIES
            C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
            NINLIL_TEST_ONLY_ARTIFACT TRUE
            POSITION_INDEPENDENT_CODE ON
        )
        ninlil_apply_strict_warnings(ninlil_mfdt_v1_runtime_probe)
        add_test(NAME mfdt_v1_runtime_probe_build
            COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
                --target ninlil_mfdt_v1_runtime_probe)
        set_tests_properties(mfdt_v1_runtime_probe_build PROPERTIES
            RESOURCE_LOCK ninlil_ctest_build_tree)
    endif()

    # R7 T1b context binding (docs/33). Source authority already included once
    # above private-target creation; register nrw1_t1b_* CTests exactly once.
    # Prefix is disjoint from T0 r7_* (16/15) and T1 nrw1_t1_* (12/11).
    ninlil_nrw1_t1b_register_tests()
    ninlil_m4_lab_register_tests()
    ninlil_c3_lab_register_tests()
    ninlil_c6_lab_register_tests()
    ninlil_c4_c5_lab_register_tests()
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_v1_integration_gate_ctest.cmake)
    ninlil_v1_integration_gate_register_tests()
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_v1_lab_examples.cmake)
    ninlil_v1_lab_examples_register()
    add_test(
        NAME c6_lab_enforcement_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/c6_lab_enforcement_gate.py
            check
    )
    add_test(
        NAME profile_r5_golden_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/profile_r5_golden_oracle.py
    )
    add_executable(ninlil_profile_r5_test
        tests/radio/profile_r5_test.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
    )
    target_include_directories(ninlil_profile_r5_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(ninlil_profile_r5_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_profile_r5_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_profile_r5_test)
    add_test(
        NAME profile_r5
        COMMAND ninlil_profile_r5_test
    )

    # R2 Physical Compliance Permit authority — host vectors §14.1 + faults.
    # Does not claim legal/R3/HIL/re-review GO. Docs gate alone is not completion.
    add_executable(ninlil_pcp_r2_authority_test
        tests/radio/pcp_r2_authority_test.c
        tests/support/in_memory_storage.c
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
        tests/support/scripted_storage_spy.c
        tests/support/radio_hal_spy.c
    )
    target_include_directories(ninlil_pcp_r2_authority_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_pcp_r2_authority_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_pcp_r2_authority_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_pcp_r2_authority_test)
    add_test(
        NAME pcp_r2_authority
        COMMAND ninlil_pcp_r2_authority_test
    )

    # R4 host control-plane tests + bus spy (tests-only; not production archive).
    add_executable(ninlil_sx1262_r4_test
        tests/radio/sx1262_r4_test.c
        tests/support/sx1262_bus_spy.c
    )
    target_include_directories(ninlil_sx1262_r4_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/drivers/sx126x
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
    )
    target_link_libraries(ninlil_sx1262_r4_test PRIVATE
        ninlil_sx1262
    )
    set_target_properties(ninlil_sx1262_r4_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_sx1262_r4_test)
    add_test(
        NAME sx1262_r4
        COMMAND ninlil_sx1262_r4_test
    )

    # R9 physical TX/RX + R1 sole-edge composition (Proposed ADR-0025).
    add_executable(ninlil_sx1262_r9_test
        tests/radio/sx1262_r9_test.c
        tests/support/sx1262_bus_spy.c
        tests/support/radio_hal_spy.c
    )
    target_include_directories(ninlil_sx1262_r9_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/drivers/sx126x
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
    )
    target_link_libraries(ninlil_sx1262_r9_test PRIVATE
        ninlil_sx1262
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_sx1262_r9_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_sx1262_r9_test)
    add_test(
        NAME sx1262_r9
        COMMAND ninlil_sx1262_r9_test
    )

    # ESP RF bus capability pure policy (CONTROL_ONLY vs RF_SOLE).
    add_executable(ninlil_sx1262_esp_rf_bus_capability_test
        tests/radio/sx1262_esp_rf_bus_capability_test.c
    )
    target_include_directories(ninlil_sx1262_esp_rf_bus_capability_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/drivers/sx126x
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
    )
    target_link_libraries(ninlil_sx1262_esp_rf_bus_capability_test PRIVATE
        ninlil_sx1262
    )
    set_target_properties(ninlil_sx1262_esp_rf_bus_capability_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_sx1262_esp_rf_bus_capability_test)
    add_test(
        NAME sx1262_esp_rf_bus_capability
        COMMAND ninlil_sx1262_esp_rf_bus_capability_test
    )

    add_test(
        NAME sx1262_r9_sole_edge_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/sx1262_r9_sole_edge_gate.py
            check
    )

    add_executable(ninlil_control_session_u3_test
        tests/transport/control_session_u3_test.c
        tests/support/fake_byte_stream.c
    )
    target_include_directories(ninlil_control_session_u3_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_control_session_u3_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    # Host-test-only declaration of private stats seam (symbol lives in private
    # archive; not public ABI / not in include/ninlil).
    target_compile_definitions(ninlil_control_session_u3_test PRIVATE
        NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM=1)
    set_target_properties(ninlil_control_session_u3_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_control_session_u3_test)
    add_test(
        NAME control_session_u3
        COMMAND ninlil_control_session_u3_test
    )

    # U4 logical session host candidate: engine + §8.9 engine IDs (38) + gates.
    # Does not claim USB series complete / HIL / assignment / security.
    add_test(
        NAME logical_session_u4_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/logical-session-u4-v1.json
    )
    add_test(
        NAME logical_session_u4_vector_gen_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_vector_gen.py
            self-test
    )
    add_test(
        NAME logical_session_u4_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_gate.py
            check
    )
    add_test(
        NAME logical_session_u4_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_gate.py
            self-test
    )
    add_test(
        NAME logical_session_u4_assert_hygiene
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_assert_hygiene.py
            check
    )
    set(_ninlil_ls_u4_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/logical_session_u4_vector_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_ls_u4_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/logical-session-u4-v1.json
            ${_ninlil_ls_u4_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/logical-session-u4-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/ncl1-u4-v1.json
        COMMENT "Generate U4 logical session engine behavior fixture"
        VERBATIM
    )
    add_custom_target(ninlil_ls_u4_fixture_gen DEPENDS ${_ninlil_ls_u4_fixture})

    add_executable(ninlil_logical_session_u4_test
        tests/transport/logical_session_u4_test.c
        tests/support/fake_byte_stream.c
    )
    add_dependencies(ninlil_logical_session_u4_test ninlil_ls_u4_fixture_gen)
    target_include_directories(ninlil_logical_session_u4_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_BINARY_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    set_property(SOURCE tests/transport/logical_session_u4_test.c
        APPEND PROPERTY OBJECT_DEPENDS ${_ninlil_ls_u4_fixture})
    target_link_libraries(ninlil_logical_session_u4_test PRIVATE
        ninlil_runtime_private
        ninlil
    )
    target_compile_definitions(ninlil_logical_session_u4_test PRIVATE
        NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1)
    set_target_properties(ninlil_logical_session_u4_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_logical_session_u4_test)
    add_test(
        NAME logical_session_u4
        COMMAND ninlil_logical_session_u4_test
    )
    add_test(
        NAME logical_session_u4_expect_mutation
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/logical_session_u4_assert_hygiene.py
            mutation
            --build-dir ${CMAKE_CURRENT_BINARY_DIR}
            --exe $<TARGET_FILE:ninlil_logical_session_u4_test>
            --fixture ${_ninlil_ls_u4_fixture}
    )
    set_tests_properties(logical_session_u4_expect_mutation PROPERTIES
        DEPENDS logical_session_u4
        TIMEOUT 600
        RUN_SERIAL TRUE
        RESOURCE_LOCK logical_session_u4_fixture
    )
    add_test(
        NAME logical_session_u4_fixture_freshness
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'logical_session_u4_vector_gen.py'; js=root/'spec'/'vectors'/'logical-session-u4-v1.json'; build=pathlib.Path(r'${_ninlil_ls_u4_fixture}'); assert build.is_file(), 'missing build fixture'; td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); ta,tb,tbld=a.read_bytes(),b.read_bytes(),build.read_bytes(); assert ta==tb, 'emit non-deterministic'; assert ta==tbld, 'build fixture stale'; assert b'NINLIL_LS_U4_ENGINE_REQUIRED_ID_COUNT' in ta; assert b'U4-G-HELLO-OK' in ta; assert b'tx_blob' in ta or b'tx_hex' in ta or b'EF_TX_HEX' in ta; print('logical_session_u4 fixture freshness ok', len(ta), 'bytes')"
    )
    set_tests_properties(logical_session_u4_fixture_freshness PROPERTIES
        DEPENDS logical_session_u4
        RESOURCE_LOCK logical_session_u4_fixture
    )

    # Build reliability: generated fixture headers must not be multi-exec
    # SOURCES (Ninja shared OUTPUT race / partial-header compile). Independent
    # of U2 USB CDC. Crossrow fixture uses custom_target + add_dependencies.
    add_test(
        NAME cmake_generated_fixture_source_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake_generated_fixture_source_gate.py
            check
    )
    add_test(
        NAME cmake_generated_fixture_source_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/cmake_generated_fixture_source_gate.py
            self-test
    )

    # U2: exact esp_tinyusb pin+locks, A2 hygiene, no control-CDC console.
    # Full check requires committed dependencies.lock (generated via Docker).
    add_test(
        NAME esp_usb_cdc_u2_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_usb_cdc_u2_gate.py
            check
    )
    add_test(
        NAME esp_usb_cdc_u2_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_usb_cdc_u2_gate.py
            self-test
    )

    # U1 host CTest: PTY + syscall seam. Not Required HIL; not U1 complete.
    # Host-test-only FORCE fcntl CLOEXEC twin library+test live only in this
    # NINLIL_BUILD_TESTS block — never in tests-OFF configure/target graph,
    # install, export, or ESP packaging.
    if(NINLIL_POSIX_USB_SERIAL_ENABLED)
        add_executable(ninlil_posix_usb_serial_test
            tests/port/posix_usb_serial_test.c
        )
        target_include_directories(ninlil_posix_usb_serial_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/usb_serial
        )
        target_link_libraries(ninlil_posix_usb_serial_test PRIVATE
            ninlil_posix_usb_serial
        )
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            # openpty lives in libutil on glibc hosts.
            target_link_libraries(ninlil_posix_usb_serial_test PRIVATE util)
        endif()
        set_target_properties(ninlil_posix_usb_serial_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_usb_serial_feature_macros(ninlil_posix_usb_serial_test)
        ninlil_apply_strict_warnings(ninlil_posix_usb_serial_test)
        add_test(
            NAME posix_usb_serial_u1
            COMMAND ninlil_posix_usb_serial_test
        )

        # Host-test-only private twin: FORCE fcntl CLOEXEC fallback so modern
        # Linux/macOS CI compiles the path production omits when O_CLOEXEC
        # exists. Defined only under NINLIL_BUILD_TESTS=ON.
        add_library(ninlil_posix_usb_serial_cloexec_fallback STATIC
            EXCLUDE_FROM_ALL
            ports/posix/usb_serial/ninlil_posix_usb_serial.c
        )
        target_include_directories(ninlil_posix_usb_serial_cloexec_fallback
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/include
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/usb_serial
        )
        set_target_properties(ninlil_posix_usb_serial_cloexec_fallback PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            POSITION_INDEPENDENT_CODE ON
            C_VISIBILITY_PRESET hidden
            NINLIL_TEST_ONLY_ARTIFACT TRUE
        )
        ninlil_apply_posix_usb_serial_feature_macros(
            ninlil_posix_usb_serial_cloexec_fallback)
        ninlil_apply_strict_warnings(ninlil_posix_usb_serial_cloexec_fallback)
        target_compile_definitions(
            ninlil_posix_usb_serial_cloexec_fallback PRIVATE
            NINLIL_POSIX_USB_SERIAL_FORCE_FCNTL_CLOEXEC_FALLBACK=1
        )
        target_link_libraries(ninlil_posix_usb_serial_cloexec_fallback
            PUBLIC Threads::Threads)

        add_executable(ninlil_posix_usb_serial_cloexec_fallback_test
            tests/port/posix_usb_serial_cloexec_fallback_test.c
        )
        target_include_directories(
            ninlil_posix_usb_serial_cloexec_fallback_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/usb_serial
            ${CMAKE_CURRENT_SOURCE_DIR}/include
        )
        target_link_libraries(ninlil_posix_usb_serial_cloexec_fallback_test
            PRIVATE ninlil_posix_usb_serial_cloexec_fallback
        )
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_link_libraries(
                ninlil_posix_usb_serial_cloexec_fallback_test PRIVATE util)
        endif()
        set_target_properties(
            ninlil_posix_usb_serial_cloexec_fallback_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_usb_serial_feature_macros(
            ninlil_posix_usb_serial_cloexec_fallback_test)
        ninlil_apply_strict_warnings(
            ninlil_posix_usb_serial_cloexec_fallback_test)
        target_compile_definitions(
            ninlil_posix_usb_serial_cloexec_fallback_test PRIVATE
            NINLIL_POSIX_USB_SERIAL_FORCE_FCNTL_CLOEXEC_FALLBACK=1
        )
        add_test(
            NAME posix_usb_serial_cloexec_fallback
            COMMAND ninlil_posix_usb_serial_cloexec_fallback_test
        )
    endif()

    add_executable(ninlil_submission_preflight_test
        tests/model/submission_preflight_test.c
    )
    target_include_directories(ninlil_submission_preflight_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_submission_preflight_test PRIVATE
        ninlil_reducer_model
        ninlil
    )
    set_target_properties(ninlil_submission_preflight_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_submission_preflight_test)

    add_test(
        NAME submission_preflight_model
        COMMAND ninlil_submission_preflight_test
    )

    add_executable(ninlil_submission_admission_test
        tests/model/submission_admission_test.c
    )
    target_include_directories(ninlil_submission_admission_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_submission_admission_test PRIVATE
        ninlil_reducer_model
        ninlil
    )
    set_target_properties(ninlil_submission_admission_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_submission_admission_test)

    add_test(
        NAME submission_admission_model
        COMMAND ninlil_submission_admission_test
    )

    add_library(ninlil_test_storage_fixture STATIC
        tests/support/in_memory_storage.c
    )
    target_include_directories(ninlil_test_storage_fixture PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_test_storage_fixture PRIVATE ninlil)
    set_target_properties(ninlil_test_storage_fixture PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_test_storage_fixture)

    add_library(ninlil_test_storage_conformance STATIC
        tests/support/storage_conformance.c
    )
    target_include_directories(ninlil_test_storage_conformance PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_test_storage_conformance PRIVATE ninlil)
    set_target_properties(ninlil_test_storage_conformance PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_test_storage_conformance)

    add_library(ninlil_test_typed_bearer_fixture STATIC
        tests/support/typed_simulated_bearer.c
    )
    target_include_directories(ninlil_test_typed_bearer_fixture PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_test_typed_bearer_fixture PRIVATE ninlil)
    set_target_properties(ninlil_test_typed_bearer_fixture PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_test_typed_bearer_fixture)

    add_library(ninlil_test_origin_auth_fixture STATIC
        tests/support/canonical_origin_authorization.c
    )
    set_property(TARGET ninlil_test_origin_auth_fixture
        PROPERTY NINLIL_TEST_ONLY_ARTIFACT TRUE)
    target_include_directories(ninlil_test_origin_auth_fixture PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_test_origin_auth_fixture PRIVATE ninlil)
    set_target_properties(ninlil_test_origin_auth_fixture PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_test_origin_auth_fixture)

    add_executable(ninlil_canonical_origin_authorization_test
        tests/port/canonical_origin_authorization_test.c
    )
    target_link_libraries(ninlil_canonical_origin_authorization_test PRIVATE
        ninlil_test_origin_auth_fixture
        ninlil
    )
    set_target_properties(ninlil_canonical_origin_authorization_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_canonical_origin_authorization_test)
    add_test(
        NAME canonical_origin_authorization_fixture
        COMMAND ninlil_canonical_origin_authorization_test
    )

    # Configure-time release composition gate. The public SDK target must not
    # acquire the synthetic TEST grant provider as a direct dependency.
    ninlil_assert_no_test_only_link(ninlil)
    ninlil_assert_no_test_only_link(ninlil_runtime_private)
    if(NINLIL_POSIX_USB_SERIAL_ENABLED)
        # Production port must not link host-test FORCE twin / other test-only.
        ninlil_assert_no_test_only_link(ninlil_posix_usb_serial)
    endif()

    add_executable(ninlil_typed_simulated_bearer_test
        tests/port/typed_simulated_bearer_test.c
    )
    target_link_libraries(ninlil_typed_simulated_bearer_test PRIVATE
        ninlil_test_typed_bearer_fixture
        ninlil
    )
    set_target_properties(ninlil_typed_simulated_bearer_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_typed_simulated_bearer_test)
    add_test(
        NAME typed_simulated_bearer_fixture
        COMMAND ninlil_typed_simulated_bearer_test
    )

    add_executable(ninlil_in_memory_storage_test
        tests/port/in_memory_storage_test.c
    )
    target_link_libraries(ninlil_in_memory_storage_test PRIVATE
        ninlil_test_storage_fixture
        ninlil
    )
    set_target_properties(ninlil_in_memory_storage_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_in_memory_storage_test)

    add_test(
        NAME in_memory_storage_conformance
        COMMAND ninlil_in_memory_storage_test
    )

    add_executable(ninlil_in_memory_storage_shared_conformance_test
        tests/port/in_memory_storage_shared_conformance_test.c
    )
    target_link_libraries(ninlil_in_memory_storage_shared_conformance_test PRIVATE
        ninlil_test_storage_conformance
        ninlil_test_storage_fixture
        ninlil
    )
    set_target_properties(ninlil_in_memory_storage_shared_conformance_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(
        ninlil_in_memory_storage_shared_conformance_test)
    add_test(
        NAME in_memory_storage_shared_conformance
        COMMAND ninlil_in_memory_storage_shared_conformance_test
    )

    add_executable(ninlil_in_memory_storage_boundary_test
        tests/port/in_memory_storage_boundary_test.c
    )
    target_link_libraries(ninlil_in_memory_storage_boundary_test PRIVATE
        ninlil_test_storage_fixture
        ninlil
    )
    set_target_properties(ninlil_in_memory_storage_boundary_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_in_memory_storage_boundary_test)

    add_test(
        NAME in_memory_storage_boundaries
        COMMAND ninlil_in_memory_storage_boundary_test
    )

    if(NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
        ninlil_sqlite3_select_test_interpose_backend()
        # Test-only SQLite interposition seam (not installed; not in production TU).
        add_executable(ninlil_posix_sqlite_storage_test
            tests/port/posix_sqlite_storage_test.c
            tests/port/posix_sqlite_persist_interpose.c
        )
        target_include_directories(ninlil_posix_sqlite_storage_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/sqlite_storage
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/port
        )
        target_link_libraries(ninlil_posix_sqlite_storage_test PRIVATE
            ninlil_posix_sqlite_storage
            SQLite3::SQLite3
            ninlil
        )
        if(NINLIL_TEST_SQLITE_INTERPOSE_BACKEND STREQUAL "WRAP")
            target_compile_definitions(ninlil_posix_sqlite_storage_test PRIVATE
                NINLIL_TEST_SQLITE_INTERPOSE_WRAP=1)
            target_link_options(ninlil_posix_sqlite_storage_test PRIVATE
                "LINKER:--wrap=sqlite3_exec"
                "LINKER:--wrap=sqlite3_prepare_v2"
                "LINKER:--wrap=sqlite3_get_autocommit")
            message(STATUS
                "POSIX SQLite test interpose backend: GNU --wrap (static)")
        elseif(NINLIL_TEST_SQLITE_INTERPOSE_BACKEND STREQUAL "DLSYM")
            target_compile_definitions(ninlil_posix_sqlite_storage_test PRIVATE
                NINLIL_TEST_SQLITE_INTERPOSE_DLSYM=1)
            target_link_libraries(ninlil_posix_sqlite_storage_test PRIVATE
                ${CMAKE_DL_LIBS})
            message(STATUS
                "POSIX SQLite test interpose backend: RTLD_NEXT dlsym (shared)")
        else()
            message(FATAL_ERROR
                "Internal error: no SQLite test interpose backend selected")
        endif()
        set_target_properties(ninlil_posix_sqlite_storage_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_sqlite_feature_macros(ninlil_posix_sqlite_storage_test)
        ninlil_apply_strict_warnings(ninlil_posix_sqlite_storage_test)
        add_test(
            NAME posix_sqlite_storage
            COMMAND ninlil_posix_sqlite_storage_test
        )
        # Wall-clock upper bounds inside the busy-timeout assertion are load
        # dependent. CTest owns whole-test hang detection instead.
        set_tests_properties(posix_sqlite_storage PROPERTIES TIMEOUT 60)

        add_executable(ninlil_v1_posix_sqlite_restart_e2e_test
            tests/runtime/v1_posix_sqlite_restart_e2e_test.c
        )
        target_include_directories(ninlil_v1_posix_sqlite_restart_e2e_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
        )
        target_link_libraries(ninlil_v1_posix_sqlite_restart_e2e_test PRIVATE
            ninlil_runtime_private
            ninlil_posix_sqlite_storage
            ninlil
        )
        set_target_properties(ninlil_v1_posix_sqlite_restart_e2e_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_sqlite_feature_macros(
            ninlil_v1_posix_sqlite_restart_e2e_test)
        ninlil_apply_strict_warnings(ninlil_v1_posix_sqlite_restart_e2e_test)
        add_test(
            NAME v1_posix_sqlite_restart_e2e
            COMMAND ninlil_v1_posix_sqlite_restart_e2e_test
        )

        add_executable(ninlil_v1_posix_provider_conformance_test
            tests/port/v1_posix_provider_conformance_test.c
        )
        target_include_directories(ninlil_v1_posix_provider_conformance_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        )
        target_link_libraries(ninlil_v1_posix_provider_conformance_test PRIVATE
            ninlil_posix_lab_platform
            ninlil
        )
        set_target_properties(ninlil_v1_posix_provider_conformance_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_sqlite_feature_macros(
            ninlil_v1_posix_provider_conformance_test)
        ninlil_apply_strict_warnings(ninlil_v1_posix_provider_conformance_test)
        add_test(
            NAME v1_posix_provider_conformance
            COMMAND ninlil_v1_posix_provider_conformance_test
        )

        add_executable(ninlil_posix_loopback_partial_read_test
            tests/port/posix_loopback_bearer_partial_read_test.c
        )
        target_include_directories(ninlil_posix_loopback_partial_read_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/loopback_bearer
        )
        target_link_libraries(ninlil_posix_loopback_partial_read_test PRIVATE
            ninlil_posix_lab_platform
            ninlil
        )
        set_target_properties(ninlil_posix_loopback_partial_read_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_host_feature_macros(
            ninlil_posix_loopback_partial_read_test)
        ninlil_apply_strict_warnings(ninlil_posix_loopback_partial_read_test)
        add_test(
            NAME posix_loopback_partial_read
            COMMAND ninlil_posix_loopback_partial_read_test
        )
        set_tests_properties(posix_loopback_partial_read PROPERTIES TIMEOUT 10)

        add_executable(ninlil_v1_posix_platform_restart_e2e_test
            tests/runtime/v1_posix_platform_restart_e2e_test.c
        )
        target_include_directories(ninlil_v1_posix_platform_restart_e2e_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
        )
        target_link_libraries(ninlil_v1_posix_platform_restart_e2e_test PRIVATE
            ninlil_runtime_private
            ninlil_posix_lab_platform
            ninlil
        )
        set_target_properties(ninlil_v1_posix_platform_restart_e2e_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_sqlite_feature_macros(
            ninlil_v1_posix_platform_restart_e2e_test)
        ninlil_apply_strict_warnings(ninlil_v1_posix_platform_restart_e2e_test)
        add_test(
            NAME v1_posix_platform_restart_e2e
            COMMAND ninlil_v1_posix_platform_restart_e2e_test
        )

        add_executable(ninlil_v1_direct_1hop_e2e_test
            tests/runtime/v1_direct_1hop_e2e_test.c
        )
        target_include_directories(ninlil_v1_direct_1hop_e2e_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/loopback_bearer
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        )
        target_link_libraries(ninlil_v1_direct_1hop_e2e_test PRIVATE
            ninlil_runtime_private
            ninlil_posix_lab_platform
            ninlil
        )
        set_target_properties(ninlil_v1_direct_1hop_e2e_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_sqlite_feature_macros(ninlil_v1_direct_1hop_e2e_test)
        ninlil_apply_strict_warnings(ninlil_v1_direct_1hop_e2e_test)
        add_test(
            NAME v1_direct_1hop_e2e
            COMMAND ninlil_v1_direct_1hop_e2e_test
        )

        if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
            add_executable(ninlil_runtime_fabric_actual_e2e_test
                tests/host/runtime_fabric_actual_e2e_test.c
                examples/multi_service_node/multi_service_node_profile.c
            )
            target_include_directories(
                ninlil_runtime_fabric_actual_e2e_test PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/model
                ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
                ${CMAKE_CURRENT_SOURCE_DIR}/examples/multi_service_node
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
            )
            target_compile_definitions(
                ninlil_runtime_fabric_actual_e2e_test PRIVATE
                NINLIL_ENABLE_PRIVATE_FABRIC_V1=1
            )
            if(NINLIL_ENABLE_MFDT_V1_PRIVATE)
                target_include_directories(
                    ninlil_runtime_fabric_actual_e2e_test PRIVATE
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
                )
                target_compile_definitions(
                    ninlil_runtime_fabric_actual_e2e_test PRIVATE
                    NINLIL_MFDT_V1_PRIVATE=1
                )
            endif()
            target_link_libraries(
                ninlil_runtime_fabric_actual_e2e_test PRIVATE
                ninlil_runtime_private
                ninlil_posix_lab_platform
                ninlil
            )
            set_target_properties(
                ninlil_runtime_fabric_actual_e2e_test PROPERTIES
                C_STANDARD 11
                C_STANDARD_REQUIRED ON
                C_EXTENSIONS OFF
            )
            ninlil_apply_posix_sqlite_feature_macros(
                ninlil_runtime_fabric_actual_e2e_test)
            ninlil_apply_strict_warnings(
                ninlil_runtime_fabric_actual_e2e_test)
            add_test(
                NAME runtime_fabric_actual_e2e
                COMMAND ninlil_runtime_fabric_actual_e2e_test
            )
            set_tests_properties(runtime_fabric_actual_e2e PROPERTIES
                TIMEOUT 60)
            add_test(
                NAME multi_service_node_host_actual_e2e
                COMMAND ninlil_runtime_fabric_actual_e2e_test
            )
            set_tests_properties(
                multi_service_node_host_actual_e2e PROPERTIES TIMEOUT 60)
            if(NINLIL_ENABLE_MFDT_V1_PRIVATE)
                add_test(
                    NAME mfdt_v1_fabric_actual_e2e
                    COMMAND ninlil_runtime_fabric_actual_e2e_test
                )
                set_tests_properties(
                    mfdt_v1_fabric_actual_e2e PROPERTIES TIMEOUT 60)
            endif()
        endif()

        # The all-private aggregate must also compile/link the canonical
        # Foundation owner-plane -> NFL1 actual E2E executable.  Domain Schema
        # 1 public Runtime readiness currently disables execution in this exact
        # tree; CI executes its three named CTests in an explicitly labelled
        # Domain-OFF companion profile (normal + ASan/UBSan).  Do not infer
        # Domain/Wi-Fi/R7 FRAG/RRMP cross-feature connectivity from that run.
        if(TARGET host_completion_all_private_build)
            if(NOT TARGET ninlil_runtime_fabric_actual_e2e_test)
                message(FATAL_ERROR
                    "all-private Host aggregate requires "
                    "ninlil_runtime_fabric_actual_e2e_test")
            endif()
            add_dependencies(
                host_completion_all_private_build
                ninlil_runtime_fabric_actual_e2e_test)
        endif()

        add_test(
            NAME posix_sqlite_storage_package_surface_negative
            COMMAND ${CMAKE_COMMAND}
                -DNINLIL_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                -DNINLIL_BUILD_CONFIG=$<CONFIG>
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/posix_sqlite_package_surface_negative.cmake
        )

        add_executable(ninlil_posix_sqlite_storage_shared_conformance_test
            tests/port/posix_sqlite_storage_shared_conformance_test.c
        )
        target_link_libraries(
            ninlil_posix_sqlite_storage_shared_conformance_test PRIVATE
            ninlil_test_storage_conformance
            ninlil_posix_sqlite_storage
            ninlil
        )
        set_target_properties(
            ninlil_posix_sqlite_storage_shared_conformance_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_sqlite_feature_macros(
            ninlil_posix_sqlite_storage_shared_conformance_test)
        ninlil_apply_strict_warnings(
            ninlil_posix_sqlite_storage_shared_conformance_test)
        add_test(
            NAME posix_sqlite_storage_shared_conformance
            COMMAND ninlil_posix_sqlite_storage_shared_conformance_test
        )

        add_executable(ninlil_posix_sqlite_storage_example
            ports/posix/examples/sqlite_storage_minimal.c
        )
        target_include_directories(ninlil_posix_sqlite_storage_example PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
        )
        target_link_libraries(ninlil_posix_sqlite_storage_example PRIVATE
            ninlil_posix_sqlite_storage
            ninlil
        )
        set_target_properties(ninlil_posix_sqlite_storage_example PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_posix_sqlite_feature_macros(
            ninlil_posix_sqlite_storage_example)
        ninlil_apply_strict_warnings(ninlil_posix_sqlite_storage_example)
        add_test(
            NAME posix_sqlite_storage_example
            COMMAND ninlil_posix_sqlite_storage_example
        )
        set(_ninlil_smoke_expect_static OFF)
        if(NINLIL_SQLITE_IS_STATIC)
            set(_ninlil_smoke_expect_static ON)
        endif()
        set(_ninlil_smoke_sqlite_inc "")
        if(DEFINED SQLite3_INCLUDE_DIR AND SQLite3_INCLUDE_DIR)
            set(_ninlil_smoke_sqlite_inc "${SQLite3_INCLUDE_DIR}")
        elseif(DEFINED SQLite3_INCLUDE_DIRS AND SQLite3_INCLUDE_DIRS)
            list(GET SQLite3_INCLUDE_DIRS 0 _ninlil_smoke_sqlite_inc)
        endif()
        set(_ninlil_install_smoke_sanitizers OFF)
        if(NINLIL_ENABLE_SANITIZERS
           OR _ninlil_pointer_compare_sanitizer_supported)
            set(_ninlil_install_smoke_sanitizers ON)
        endif()
        add_test(
            NAME posix_sqlite_storage_installed_consumer
            COMMAND ${CMAKE_COMMAND}
                -DNINLIL_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                -DNINLIL_BUILD_CONFIG=$<CONFIG>
                -DNINLIL_SMOKE_HOST_RUNTIME_ENABLED=${NINLIL_HOST_RUNTIME_ENABLED}
                -DNINLIL_SMOKE_FABRIC_V1_ENABLED=${NINLIL_BUILD_FABRIC_V1}
                -DNINLIL_SMOKE_POSIX_TLS_V1_ENABLED=${NINLIL_BUILD_POSIX_TLS_V1}
                -DNINLIL_SMOKE_POSIX_USB_SERIAL_ENABLED=${NINLIL_POSIX_USB_SERIAL_ENABLED}
                -DNINLIL_INSTALL_SMOKE_SANITIZERS=${_ninlil_install_smoke_sanitizers}
                "-DNINLIL_SMOKE_SQLITE3_LIBRARY=${NINLIL_SQLITE_LIBRARY_PATH}"
                "-DNINLIL_SMOKE_SQLITE3_INCLUDE_DIR=${_ninlil_smoke_sqlite_inc}"
                -DNINLIL_SMOKE_EXPECT_STATIC_SQLITE=${_ninlil_smoke_expect_static}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_posix_sqlite_consumer_smoke.cmake
        )
    endif()

    # M3 ESP dual-slot durable storage port (host media conformance).
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_esp_storage_sources.cmake)
    add_library(ninlil_port_esp_storage STATIC
        ${NINLIL_ESP_STORAGE_HOST_TEST_RELATIVE_SOURCES}
    )
    target_include_directories(ninlil_port_esp_storage PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/storage/include
    )
    target_include_directories(ninlil_port_esp_storage PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/storage/model
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/storage/private
    )
    target_link_libraries(ninlil_port_esp_storage PRIVATE ninlil)
    set_target_properties(ninlil_port_esp_storage PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_port_esp_storage)
    # AppleClang does not emit GCC-compatible .su artifacts. The production
    # ESP-IDF compiler is GCC and is the authoritative frame-size gate.
    set(NINLIL_ESP_STORAGE_HAS_SU OFF)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(ninlil_port_esp_storage PRIVATE
            -Wvla
            -fstack-usage
        )
        set(NINLIL_ESP_STORAGE_HAS_SU ON)
    elseif(CMAKE_C_COMPILER_ID MATCHES "^Clang$")
        target_compile_options(ninlil_port_esp_storage PRIVATE -Wvla)
    endif()
    # Fail the build if any storage-port frame exceeds the FreeRTOS-safe budget.
    include(CheckCCompilerFlag)
    check_c_compiler_flag(-Wframe-larger-than=2048
        NINLIL_HAS_WFRAME_LARGER_THAN)
    if(NINLIL_HAS_WFRAME_LARGER_THAN
        AND NOT CMAKE_C_COMPILER_ID STREQUAL "AppleClang"
        AND NOT CMAKE_C_FLAGS MATCHES "-fsanitize")
        target_compile_options(ninlil_port_esp_storage PRIVATE
            -Wframe-larger-than=2048
        )
        # GCC accepts -Werror=frame-larger-than=N; Clang uses global -Werror.
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            target_compile_options(ninlil_port_esp_storage PRIVATE
                -Werror=frame-larger-than=2048
            )
        endif()
    endif()

    add_executable(ninlil_esp_storage_conformance_test
        tests/port/esp_storage_conformance_test.c
    )
    target_include_directories(ninlil_esp_storage_conformance_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/storage/private
    )
    target_link_libraries(ninlil_esp_storage_conformance_test PRIVATE
        ninlil_port_esp_storage
        ninlil
    )
    set_target_properties(ninlil_esp_storage_conformance_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_esp_storage_conformance_test)
    add_test(
        NAME esp_storage_dual_slot_conformance
        COMMAND ninlil_esp_storage_conformance_test
    )

    add_test(
        NAME v1_esp_durable_success_source_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/v1_esp_durable_success_gate.py
            check
    )
    add_test(
        NAME v1_esp_durable_success_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/v1_esp_durable_success_gate.py
            self-test
    )

    add_test(
        NAME esp_storage_budget_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_storage_budget_gate.py
    )

    add_test(
        NAME esp_storage_wear_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_storage_wear_gate.py
    )

    add_test(
        NAME esp_storage_public_api_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_storage_public_api_gate.py
            --archive $<TARGET_FILE:ninlil_port_esp_storage>
            --archive-kind host
    )
    add_test(
        NAME esp_storage_public_api_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_storage_public_api_gate.py
            self-test
    )

    add_test(
        NAME esp_storage_hil_runner_selftest
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/storage/hil/host_powercut_runner.py
            --self-test
    )
    add_test(
        NAME ninlil_hil_evidence_self_test
        COMMAND ${Python3_EXECUTABLE}
            -B
            -m
            tools.ninlil_hil
            self-test
    )
    set_tests_properties(
        ninlil_hil_evidence_self_test
        PROPERTIES
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    )

    add_test(
        NAME esp_storage_map_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_storage_map_gate.py
    )
    add_test(
        NAME esp_storage_map_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_storage_map_gate.py
            self-test
    )

    # Parse real -fstack-usage artifacts from the storage port object build.
    if(NINLIL_ESP_STORAGE_HAS_SU)
        set(_ninlil_esp_stack_gate_args
            --require-su
            --require-model
            ${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/ninlil_port_esp_storage.dir
        )
    else()
        set(_ninlil_esp_stack_gate_args
            --compiler-skip=${CMAKE_C_COMPILER_ID}
        )
    endif()
    add_test(
        NAME esp_storage_stack_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/esp_storage_stack_gate.py
            ${_ninlil_esp_stack_gate_args}
    )
    set_tests_properties(esp_storage_stack_gate PROPERTIES
        DEPENDS ninlil_esp_storage_conformance_test
    )
    add_library(ninlil_test_platform_fixtures STATIC
        tests/support/platform_basic_fixtures.c
        tests/support/deterministic_entropy.c
    )
    target_include_directories(ninlil_test_platform_fixtures PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
    )
    target_link_libraries(ninlil_test_platform_fixtures PRIVATE ninlil)
    set_target_properties(ninlil_test_platform_fixtures PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_test_platform_fixtures)

    if(NINLIL_HOST_RUNTIME_ENABLED AND TARGET ninlil_fabric_v1)
        add_executable(ninlil_composition_v1_create_test
            tests/runtime/composition_v1_create_test.c)
        target_link_libraries(ninlil_composition_v1_create_test PRIVATE
            ninlil_runtime
            ninlil_fabric_v1
            ninlil_test_storage_fixture
            ninlil_test_platform_fixtures)
        set_target_properties(ninlil_composition_v1_create_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_composition_v1_create_test)
        add_test(
            NAME composition_v1_create
            COMMAND ninlil_composition_v1_create_test)

        add_executable(ninlil_composition_v1_namespace_test
            tests/runtime/composition_v1_namespace_test.c)
        target_link_libraries(ninlil_composition_v1_namespace_test PRIVATE
            ninlil_runtime
            ninlil_fabric_v1
            ninlil_test_storage_fixture
            ninlil_test_platform_fixtures)
        set_target_properties(ninlil_composition_v1_namespace_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_composition_v1_namespace_test)
        add_test(
            NAME composition_v1_namespace
            COMMAND ninlil_composition_v1_namespace_test)

        add_executable(ninlil_composition_v1_lifecycle_test
            tests/runtime/composition_v1_lifecycle_test.c)
        target_link_libraries(ninlil_composition_v1_lifecycle_test PRIVATE
            ninlil_runtime
            ninlil_fabric_v1
            ninlil_test_storage_fixture
            ninlil_test_platform_fixtures)
        target_include_directories(ninlil_composition_v1_lifecycle_test PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime)
        set_target_properties(ninlil_composition_v1_lifecycle_test PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(ninlil_composition_v1_lifecycle_test)
        add_test(
            NAME composition_v1_lifecycle
            COMMAND ninlil_composition_v1_lifecycle_test)
    endif()

    add_executable(ninlil_platform_basic_fixtures_test
        tests/port/platform_basic_fixtures_test.c
    )
    target_link_libraries(ninlil_platform_basic_fixtures_test PRIVATE
        ninlil_test_platform_fixtures
        ninlil
    )
    set_target_properties(ninlil_platform_basic_fixtures_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_platform_basic_fixtures_test)
    add_test(
        NAME platform_basic_fixtures
        COMMAND ninlil_platform_basic_fixtures_test
    )

    # ESP-IDF port pure logic + port-owned header contracts (host only;
    # no ESP-IDF / FreeRTOS backend link). Spec: docs/20 + docs/22 + U2 pure.
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_esp_idf_port_sources.cmake)
    add_library(ninlil_esp_idf_port_pure STATIC
        ${NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES}
    )
    target_include_directories(ninlil_esp_idf_port_pure
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/include
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
            ${CMAKE_CURRENT_SOURCE_DIR}/src/model
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    )
    # control_boundary_logic reuses private NCG1 codec (docs/19 boundary).
    target_link_libraries(ninlil_esp_idf_port_pure PRIVATE
        ninlil
        ninlil_runtime_private
    )
    set_target_properties(ninlil_esp_idf_port_pure PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        C_VISIBILITY_PRESET hidden
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_strict_warnings(ninlil_esp_idf_port_pure)

    add_executable(ninlil_esp_idf_port_logic_test
        tests/port/esp_idf_port_logic_test.c
    )
    target_include_directories(ninlil_esp_idf_port_logic_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/include
    )
    target_link_libraries(ninlil_esp_idf_port_logic_test PRIVATE
        ninlil_esp_idf_port_pure
        ninlil
    )
    set_target_properties(ninlil_esp_idf_port_logic_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_esp_idf_port_logic_test)
    add_test(
        NAME esp_idf_port_logic
        COMMAND ninlil_esp_idf_port_logic_test
    )

    add_executable(ninlil_v1_esp_provider_availability_test
        tests/port/v1_esp_provider_availability_test.c
    )
    target_include_directories(ninlil_v1_esp_provider_availability_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/include
    )
    target_link_libraries(ninlil_v1_esp_provider_availability_test PRIVATE
        ninlil_esp_idf_port_pure
        ninlil
    )
    set_target_properties(ninlil_v1_esp_provider_availability_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_v1_esp_provider_availability_test)
    add_test(
        NAME v1_esp_provider_availability
        COMMAND ninlil_v1_esp_provider_availability_test
    )

    # U2 A2 pure state/ring/ownership tests (host only; not physical HIL).
    add_executable(ninlil_esp_usb_cdc_logic_test
        tests/port/esp_usb_cdc_logic_test.c
    )
    target_include_directories(ninlil_esp_usb_cdc_logic_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    )
    target_link_libraries(ninlil_esp_usb_cdc_logic_test PRIVATE
        ninlil_esp_idf_port_pure
    )
    set_target_properties(ninlil_esp_usb_cdc_logic_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_esp_usb_cdc_logic_test)
    add_test(
        NAME esp_usb_cdc_u2_logic
        COMMAND ninlil_esp_usb_cdc_logic_test
    )

    add_executable(ninlil_owner_cell_agent_logic_test
        tests/port/owner_cell_agent_logic_test.c
    )
    target_include_directories(ninlil_owner_cell_agent_logic_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    )
    target_link_libraries(ninlil_owner_cell_agent_logic_test PRIVATE
        ninlil_esp_idf_port_pure
        ninlil_runtime_private
        ninlil
    )
    set_target_properties(ninlil_owner_cell_agent_logic_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_owner_cell_agent_logic_test)
    add_test(
        NAME owner_cell_agent_logic
        COMMAND ninlil_owner_cell_agent_logic_test
    )

    add_executable(ninlil_deterministic_entropy_test
        tests/port/deterministic_entropy_test.c
    )
    target_link_libraries(ninlil_deterministic_entropy_test PRIVATE
        ninlil_test_platform_fixtures
        ninlil
    )
    set_target_properties(ninlil_deterministic_entropy_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_deterministic_entropy_test)
    add_test(
        NAME deterministic_entropy_v1
        COMMAND ninlil_deterministic_entropy_test
    )

    add_executable(ninlil_smoke_c11 tests/smoke/c_consumer.c)
    target_link_libraries(ninlil_smoke_c11 PRIVATE ninlil)
    set_target_properties(ninlil_smoke_c11 PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_smoke_c11)

    add_executable(ninlil_smoke_cxx17 tests/smoke/cxx_consumer.cpp)
    target_link_libraries(ninlil_smoke_cxx17 PRIVATE ninlil)
    target_compile_features(ninlil_smoke_cxx17 PRIVATE cxx_std_17)
    ninlil_apply_strict_warnings(ninlil_smoke_cxx17)

    add_test(NAME smoke_c11 COMMAND ninlil_smoke_c11)
    add_test(NAME smoke_cxx17 COMMAND ninlil_smoke_cxx17)

    add_test(
        NAME public_header_contract_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/public_header_contract_gate.py
            check)
    add_test(
        NAME public_header_contract_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/public_header_contract_gate.py
            self-test)

    set(NINLIL_PUBLIC_HEADERS
        version platform service transaction runtime byte_stream fabric_v1
        composition_v1 posix_tls_v1 posix_usb_serial_v1)
    foreach(_header IN LISTS NINLIL_PUBLIC_HEADERS)
        set(_c_source "${CMAKE_CURRENT_BINARY_DIR}/self_contained_${_header}_c11.c")
        file(WRITE "${_c_source}"
            "#include <ninlil/${_header}.h>\n"
            "int main(void) { return 0; }\n"
        )
        set(_c_target "ninlil_self_contained_${_header}_c11")
        add_executable(${_c_target} "${_c_source}")
        target_link_libraries(${_c_target} PRIVATE ninlil)
        set_target_properties(${_c_target} PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
        )
        ninlil_apply_strict_warnings(${_c_target})
        add_test(NAME self_contained_${_header}_c11 COMMAND ${_c_target})

        set(_cxx_source "${CMAKE_CURRENT_BINARY_DIR}/self_contained_${_header}_cxx17.cpp")
        file(WRITE "${_cxx_source}"
            "#include <ninlil/${_header}.h>\n"
            "int main() { return 0; }\n"
        )
        set(_cxx_target "ninlil_self_contained_${_header}_cxx17")
        add_executable(${_cxx_target} "${_cxx_source}")
        target_link_libraries(${_cxx_target} PRIVATE ninlil)
        target_compile_features(${_cxx_target} PRIVATE cxx_std_17)
        ninlil_apply_strict_warnings(${_cxx_target})
        add_test(NAME self_contained_${_header}_cxx17 COMMAND ${_cxx_target})
    endforeach()

    add_executable(ninlil_abi_manifest_gen tools/abi_manifest_gen.c)
    target_link_libraries(ninlil_abi_manifest_gen PRIVATE ninlil)
    set_target_properties(ninlil_abi_manifest_gen PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_abi_manifest_gen)

    add_executable(ninlil_abi_manifest_coverage_test tools/abi_manifest_coverage_test.c)
    set_target_properties(ninlil_abi_manifest_coverage_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_abi_manifest_coverage_test)

    add_executable(ninlil_abi_drift_tool
        tools/abi_drift_tool.c
        tools/abi_drift_schema.c
    )
    set_target_properties(ninlil_abi_drift_tool PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_abi_drift_tool)

    add_executable(ninlil_abi_drift_test
        tools/abi_drift_test.c
        tools/abi_drift_schema.c
    )
    set_target_properties(ninlil_abi_drift_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_abi_drift_test)

    add_test(
        NAME abi_drift_check
        COMMAND ninlil_abi_drift_tool check ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(
        NAME abi_drift_negative
        COMMAND ninlil_abi_drift_test ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}
    )

    add_executable(ninlil_reason_registry_tool
        tools/reason_registry_tool.c
        tools/yaml_reason_schema.c
    )
    set_target_properties(ninlil_reason_registry_tool PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_reason_registry_tool)

    add_executable(ninlil_yaml_reason_parser_test
        tools/yaml_reason_parser_test.c
        tools/yaml_reason_schema.c
    )
    set_target_properties(ninlil_yaml_reason_parser_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_yaml_reason_parser_test)

    set(NINLIL_REASON_YAML "${CMAKE_CURRENT_SOURCE_DIR}/schemas/foundation-m1a-reason-codes.yaml")
    set(NINLIL_REASON_HEADER "${CMAKE_CURRENT_SOURCE_DIR}/include/ninlil/version.h")
    set(NINLIL_REASON_ARTIFACT "${CMAKE_CURRENT_SOURCE_DIR}/generated/foundation-m1a-reason-registry.txt")
    set(NINLIL_ABI_GOLDEN_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/abi/golden")

    add_test(
        NAME abi_manifest_repeatable
        COMMAND ${CMAKE_COMMAND}
            -DGEN=$<TARGET_FILE:ninlil_abi_manifest_gen>
            -DCMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/abi_manifest_repeatable.cmake
    )
    add_test(
        NAME abi_manifest_golden
        COMMAND ${CMAKE_COMMAND}
            -DGEN=$<TARGET_FILE:ninlil_abi_manifest_gen>
            -DGOLDEN_DIR=${NINLIL_ABI_GOLDEN_DIR}
            -DNINLIL_ABI_GOLDEN_ALLOW_MISSING=${NINLIL_ABI_GOLDEN_ALLOW_MISSING}
            -DCMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/abi_manifest_golden.cmake
    )
    add_test(
        NAME abi_manifest_golden_missing_negative
        COMMAND ${CMAKE_COMMAND}
            -DGOLDEN_SCRIPT=${CMAKE_CURRENT_SOURCE_DIR}/cmake/abi_manifest_golden.cmake
            -DCMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/abi_manifest_golden_self_test.cmake
    )
    add_test(
        NAME abi_manifest_coverage
        COMMAND ${CMAKE_COMMAND}
            -DGEN=$<TARGET_FILE:ninlil_abi_manifest_gen>
            -DCOVERAGE_TEST=$<TARGET_FILE:ninlil_abi_manifest_coverage_test>
            -DCMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/abi_manifest_coverage.cmake
    )
    add_test(
        NAME abi_public_layout_manifest_gate
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/abi_public_layout_manifest_gate.py
            check
    )
    add_test(
        NAME abi_public_layout_manifest_gate_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/abi_public_layout_manifest_gate.py
            self-test
    )
    find_program(NINLIL_ARM_NONE_EABI_OBJCOPY arm-none-eabi-objcopy)
    if(NINLIL_ARM_NONE_EABI_GCC AND NINLIL_ARM_NONE_EABI_OBJCOPY)
        add_test(
            NAME abi_manifest_ilp32_golden
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/abi_manifest_ilp32_golden.py
                check ${NINLIL_ABI_GOLDEN_DIR}/ILP32-le-32.manifest
                --cc ${NINLIL_ARM_NONE_EABI_GCC}
                --objcopy ${NINLIL_ARM_NONE_EABI_OBJCOPY}
        )
    endif()
    add_test(
        NAME reason_registry_check
        COMMAND ninlil_reason_registry_tool
            check
            ${NINLIL_REASON_YAML}
            ${NINLIL_REASON_HEADER}
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${NINLIL_REASON_ARTIFACT}
    )
    add_test(
        NAME yaml_reason_parser
        COMMAND ninlil_yaml_reason_parser_test ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_BINARY_DIR}
    )

    add_executable(ninlil_operator_projection_tool
        tools/operator_projection_tool.c
        tools/operator_projection_schema.c
        tools/yaml_reason_schema.c
    )
    set_target_properties(ninlil_operator_projection_tool PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_operator_projection_tool)

    add_executable(ninlil_operator_projection_test
        tools/operator_projection_test.c
        tools/operator_projection_schema.c
        tools/yaml_reason_schema.c
    )
    set_target_properties(ninlil_operator_projection_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_operator_projection_test)

    add_test(
        NAME operator_projection_check
        COMMAND ninlil_operator_projection_tool check ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(operator_projection_check PROPERTIES
        PASS_REGULAR_EXPRESSION
            "operator projection ok: contexts=7 states=15 references=15 reason_hints=54"
    )
    add_test(
        NAME operator_projection_negative
        COMMAND ninlil_operator_projection_test ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_executable(ninlil_hook_registry_tool
        tools/hook_registry_tool.c
        tools/hook_registry_schema.c
    )
    set_target_properties(ninlil_hook_registry_tool PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_hook_registry_tool)

    add_executable(ninlil_hook_registry_test
        tools/hook_registry_test.c
        tools/hook_registry_schema.c
    )
    set_target_properties(ninlil_hook_registry_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_hook_registry_test)

    add_test(
        NAME hook_registry_mirror_check
        COMMAND ninlil_hook_registry_tool check ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(
        NAME hook_registry_mirror_negative
        COMMAND ninlil_hook_registry_test ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_executable(ninlil_vector_inventory_tool
        tools/vector_inventory_tool.c
        tools/vector_inventory_schema.c
    )
    set_target_properties(ninlil_vector_inventory_tool PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_vector_inventory_tool)

    add_executable(ninlil_vector_inventory_test
        tools/vector_inventory_test.c
        tools/vector_inventory_schema.c
    )
    set_target_properties(ninlil_vector_inventory_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_vector_inventory_test)

    add_test(
        NAME vector_inventory_check
        COMMAND ninlil_vector_inventory_tool check ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(vector_inventory_check PROPERTIES
        PASS_REGULAR_EXPRESSION
            "vector inventory ok: total=303 table=259 explicit=26 bullet=16 canonical=2"
    )
    add_test(
        NAME vector_inventory_negative
        COMMAND ninlil_vector_inventory_test ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_executable(ninlil_vector_reference_tool
        tools/vector_reference_tool.c
        tools/vector_reference_schema.c
        tools/vector_inventory_schema.c
    )
    set_target_properties(ninlil_vector_reference_tool PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_vector_reference_tool)

    add_executable(ninlil_vector_reference_test
        tools/vector_reference_test.c
        tools/vector_reference_schema.c
        tools/vector_inventory_schema.c
    )
    set_target_properties(ninlil_vector_reference_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_vector_reference_test)

    add_test(
        NAME vector_reference_check
        COMMAND ninlil_vector_reference_tool check ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(vector_reference_check PROPERTIES
        PASS_REGULAR_EXPRESSION
            "vector references ok: definitions=303 mandatory_unique=281 pr_unique=296 union=303 mandatory_occurrences=285 pr_occurrences=296 mandatory_rows=40 pr_bullets=11 excluded=1"
    )
    add_test(
        NAME vector_reference_negative
        COMMAND ninlil_vector_reference_test ${CMAKE_CURRENT_SOURCE_DIR}
    )

    add_executable(ninlil_traceability_tool
        tools/traceability_tool.c
        tools/traceability_schema.c
    )
    set_target_properties(ninlil_traceability_tool PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_traceability_tool)

    add_executable(ninlil_traceability_test
        tools/traceability_test.c
        tools/traceability_schema.c
    )
    set_target_properties(ninlil_traceability_test PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_strict_warnings(ninlil_traceability_test)

    add_test(
        NAME traceability_check
        COMMAND ninlil_traceability_tool check ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(traceability_check PROPERTIES
        PASS_REGULAR_EXPRESSION
            "traceability ok: entries=10 verified=10 partial=0 planned=0 test_links=26"
    )
    add_test(
        NAME traceability_negative
        COMMAND ninlil_traceability_test ${CMAKE_CURRENT_SOURCE_DIR}
    )
    add_test(
        NAME traceability_registration_coverage_v2_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/traceability_complete_coverage_gate.py
            --self-test
            --root ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_tests_properties(
        traceability_registration_coverage_v2_self_test
        PROPERTIES
            PASS_REGULAR_EXPRESSION
                "traceability registration coverage V2 self-test ok"
    )

    # Coverage evidence is profile-specific.  Domain Schema 1 currently
    # disables the public Runtime regression tests, and a no-SQLite build omits
    # the POSIX provider evidence. Neither is a complete baseline profile.
    set(_ninlil_traceability_coverage_profile "")
    if(NINLIL_POSIX_SQLITE_STORAGE_ENABLED
       AND NOT NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
        set(_ninlil_traceability_coverage_profile "baseline")
    elseif(NINLIL_POSIX_SQLITE_STORAGE_ENABLED
        AND NINLIL_ENABLE_PRIVATE_WIFI_V1
        AND NINLIL_ENABLE_PRIVATE_FABRIC_V1
        AND NINLIL_ENABLE_R7_FRAG_PRIVATE
        AND NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1
        AND NINLIL_ENABLE_MFDT_V1_PRIVATE
    )
        set(_ninlil_traceability_coverage_profile "all-private")
    endif()
    if(_ninlil_traceability_coverage_profile)
        add_test(
            NAME traceability_registration_coverage_v2_check
            COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_CURRENT_SOURCE_DIR}/tools/traceability_complete_coverage_gate.py
                --check
                --root ${CMAKE_CURRENT_SOURCE_DIR}
                --profile
                ${_ninlil_traceability_coverage_profile}=${CMAKE_CURRENT_BINARY_DIR}
        )
        set_tests_properties(
            traceability_registration_coverage_v2_check
            PROPERTIES
                PASS_REGULAR_EXPRESSION
                    "traceability registration coverage V2 ok:"
        )
    endif()
    unset(_ninlil_traceability_coverage_profile)

    if(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
        # Public Runtime creation is intentionally unavailable while
        # NINLIL_DOMAIN_SCHEMA1_PUBLIC_RUNTIME_READY is 0u. Keep these
        # executables compiling, but report their execution as DISABLED
        # rather than turning the expected NINLIL_E_UNSUPPORTED into noisy
        # regression failures. domain_schema1_publication_not_ready is the
        # active feature-ON acceptance; the default-OFF build remains the
        # authority for the complete V1-LAB public Runtime regression suite.
        #
        # Remove this routing only in the same reviewed change that promotes
        # the readiness constant and closes the Domain completion matrix.
        set(_ninlil_domain_not_ready_public_runtime_tests
            v1_event_mgmt_ledger
            v1_runtime_spine
            v1_runtime_delivery
            v1_runtime_capability
            v1_runtime_family
            composition_v1_create
            composition_v1_namespace
            composition_v1_lifecycle
            v1_posix_platform_restart_e2e
            v1_direct_1hop_e2e
            runtime_fabric_actual_e2e
            multi_service_node_host_actual_e2e
            mfdt_v1_fabric_actual_e2e
            mfdt_v1_runtime_owner_private
            mfdt_v1_runtime_sidecar_fault_private
            v1_integration_gate_e2e
            v1_lab_controller_submit_example
            v1_lab_cell_custody_example
            v1_lab_display_latest_state_example
            v1_lab_leak_measurement_example
            posix_sqlite_storage_installed_consumer
        )
        foreach(_ninlil_test IN LISTS
                _ninlil_domain_not_ready_public_runtime_tests)
            if(TEST ${_ninlil_test})
                set_tests_properties(${_ninlil_test} PROPERTIES DISABLED TRUE)
            endif()
        endforeach()
        unset(_ninlil_test)
        unset(_ninlil_domain_not_ready_public_runtime_tests)
    endif()

    add_custom_target(ninlil_generate_reason_registry
        COMMAND ninlil_reason_registry_tool
            generate
            ${NINLIL_REASON_YAML}
            ${NINLIL_REASON_HEADER}
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${NINLIL_REASON_ARTIFACT}
        DEPENDS ninlil_reason_registry_tool
        COMMENT "Generate foundation reason registry artifact"
    )

    add_custom_target(ninlil_generate_abi_manifest
        COMMAND ninlil_abi_manifest_gen
        DEPENDS ninlil_abi_manifest_gen
        COMMENT "Print ABI manifest for current toolchain/target"
    )
