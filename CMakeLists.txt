cmake_minimum_required(VERSION 3.16)

project(ninlil VERSION 0.1.0 LANGUAGES C CXX)

add_library(ninlil INTERFACE)
target_include_directories(ninlil INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    enable_testing()

    option(NINLIL_ENABLE_SANITIZERS "Build with ASan and UBSan" OFF)
    if(NINLIL_ENABLE_SANITIZERS)
        set(_ninlil_sanitizer_supported FALSE)
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU"
           OR CMAKE_C_COMPILER_ID STREQUAL "Clang"
           OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
            set(_ninlil_sanitizer_supported TRUE)
        endif()
        if(NOT _ninlil_sanitizer_supported)
            message(FATAL_ERROR
                "NINLIL_ENABLE_SANITIZERS=ON requires GNU, Clang, or AppleClang")
        endif()
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()

    set(NINLIL_STRICT_C_FLAGS
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -pedantic-errors
    )
    set(NINLIL_STRICT_CXX_FLAGS
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -pedantic-errors
    )

    function(ninlil_apply_strict_warnings target)
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:${NINLIL_STRICT_C_FLAGS}>
            $<$<COMPILE_LANGUAGE:CXX>:${NINLIL_STRICT_CXX_FLAGS}>
        )
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

    set(NINLIL_PUBLIC_HEADERS version platform service transaction runtime)
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
            -DCMAKE_BINARY_DIR=${CMAKE_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/abi_manifest_golden.cmake
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
            "vector inventory ok: total=282 table=238 explicit=26 bullet=16 canonical=2"
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
            "vector references ok: definitions=282 mandatory_unique=255 pr_unique=275 union=282 mandatory_occurrences=259 pr_occurrences=275 mandatory_rows=40 pr_bullets=11 excluded=1"
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
            "traceability ok: entries=9 verified=6 partial=3 planned=0 test_links=20"
    )
    add_test(
        NAME traceability_negative
        COMMAND ninlil_traceability_test ${CMAKE_CURRENT_SOURCE_DIR}
    )

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
endif()
