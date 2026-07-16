cmake_minimum_required(VERSION 3.16)

project(ninlil VERSION 0.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    set(NINLIL_IS_TOP_LEVEL ON)
    set(_ninlil_build_tests_default ON)
    set(_ninlil_strict_warnings_default ON)
else()
    set(NINLIL_IS_TOP_LEVEL OFF)
    set(_ninlil_build_tests_default OFF)
    set(_ninlil_strict_warnings_default OFF)
endif()
option(NINLIL_BUILD_TESTS "Build Ninlil's test suite"
    ${_ninlil_build_tests_default})
option(NINLIL_ENABLE_STRICT_WARNINGS "Build Ninlil with warnings as errors"
    ${_ninlil_strict_warnings_default})
option(NINLIL_BUILD_POSIX_SQLITE_STORAGE
    "Build POSIX SQLite storage port when SQLite3 is available" ON)

add_library(ninlil INTERFACE)
add_library(Ninlil::ninlil ALIAS ninlil)
target_include_directories(ninlil INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

# ASan/UBSan coverage builds. Sanitizer archives are non-ship artifacts:
# installed-consumer smoke skips only archive/object absolute-path hygiene when
# this option is explicitly ON (ASan global descriptors embed absolute -c
# paths). Ship hygiene is enforced by non-sanitizer production/CI gates.
# Do not lower sanitizer coverage or disable ASan globals for path hygiene.
option(NINLIL_ENABLE_SANITIZERS "Build with ASan and UBSan" OFF)
set(_ninlil_sanitizer_supported FALSE)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU"
   OR CMAKE_C_COMPILER_ID STREQUAL "Clang"
   OR CMAKE_C_COMPILER_ID STREQUAL "AppleClang")
    set(_ninlil_sanitizer_supported TRUE)
endif()
if(NINLIL_ENABLE_SANITIZERS)
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
    if(NINLIL_ENABLE_STRICT_WARNINGS)
        if(NOT (CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
           OR NOT (CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$"))
            message(FATAL_ERROR
                "NINLIL_ENABLE_STRICT_WARNINGS=ON requires GNU or Clang family compilers")
        endif()
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:${NINLIL_STRICT_C_FLAGS}>
            $<$<COMPILE_LANGUAGE:CXX>:${NINLIL_STRICT_CXX_FLAGS}>
        )
    endif()
endfunction()

# Single source of feature macros for POSIX SQLite library/example/tests.
# glibc + -std=c11 (no extensions): realpath needs XSI; flock/MAP_ANONYMOUS
# need _DEFAULT_SOURCE. macOS keeps _DARWIN_C_SOURCE only.
function(ninlil_apply_posix_sqlite_feature_macros target)
    if(APPLE)
        target_compile_definitions(${target} PRIVATE
            _DARWIN_C_SOURCE
        )
    else()
        target_compile_definitions(${target} PRIVATE
            _XOPEN_SOURCE=700
            _DEFAULT_SOURCE
        )
    endif()
endfunction()

# Host-only durable storage port. Missing SQLite must not break portable core.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_posix_sqlite_sqlite3.cmake)
set(NINLIL_POSIX_SQLITE_STORAGE_ENABLED FALSE)
set(NINLIL_CONFIG_SQLITE_STATIC FALSE)
set(NINLIL_CONFIG_SQLITE_NEEDS_ZLIB FALSE)
set(NINLIL_CONFIG_SQLITE_NEEDS_THREADS FALSE)
if(NINLIL_BUILD_POSIX_SQLITE_STORAGE)
    # macOS static + host tests is never a supported combination (ld64 has no
    # GNU --wrap). Fail before discovery so CI cannot silently skip the port.
    if(APPLE AND NINLIL_BUILD_TESTS
       AND NINLIL_SQLITE_LINKAGE STREQUAL "STATIC")
        message(FATAL_ERROR
            "NINLIL_SQLITE_LINKAGE=STATIC with NINLIL_BUILD_TESTS=ON is "
            "unsupported on macOS (no safe static interpose backend). Use "
            "SHARED/AUTO with dylib, or -DNINLIL_BUILD_TESTS=OFF. Production "
            "static install on macOS is outside the supported matrix "
            "(docs/08, port README).")
    endif()
    ninlil_sqlite3_find_with_preference()
    if(NOT SQLite3_FOUND AND NINLIL_SQLITE_LINKAGE STREQUAL "STATIC")
        message(FATAL_ERROR
            "NINLIL_SQLITE_LINKAGE=STATIC requested but no static libsqlite3 "
            "archive was found")
    endif()
    if(NOT SQLite3_FOUND AND NINLIL_SQLITE_LINKAGE STREQUAL "SHARED")
        message(FATAL_ERROR
            "NINLIL_SQLITE_LINKAGE=SHARED requested but no shared libsqlite3 "
            "was found")
    endif()
    if(SQLite3_FOUND)
        if(NOT TARGET SQLite3::SQLite3 AND TARGET SQLite::SQLite3)
            add_library(SQLite3::SQLite3 ALIAS SQLite::SQLite3)
        endif()
        ninlil_sqlite3_resolve_library_path(NINLIL_SQLITE_LIBRARY_PATH)
        ninlil_sqlite3_classify_path(
            "${NINLIL_SQLITE_LIBRARY_PATH}" _ninlil_sqlite_kind)
        if(_ninlil_sqlite_kind STREQUAL "static")
            set(NINLIL_SQLITE_IS_STATIC TRUE)
        elseif(_ninlil_sqlite_kind STREQUAL "shared")
            set(NINLIL_SQLITE_IS_STATIC FALSE)
        else()
            # AUTO: never guess shared/static from an unclassifiable path.
            if(NINLIL_SQLITE_LINKAGE STREQUAL "AUTO")
                message(FATAL_ERROR
                    "NINLIL_SQLITE_LINKAGE=AUTO cannot reliably classify "
                    "SQLite library path '${NINLIL_SQLITE_LIBRARY_PATH}' "
                    "(need a known suffix: .a/.lib or .so/.dylib/.tbd/.dll). "
                    "Set NINLIL_SQLITE_LINKAGE=STATIC or SHARED explicitly, "
                    "or point SQLite3_LIBRARY at a classifiable path.")
            elseif(NINLIL_SQLITE_LINKAGE STREQUAL "STATIC")
                ninlil_sqlite3_accept_opaque_static(
                    "${NINLIL_SQLITE_LIBRARY_PATH}" _opaque_ok)
                if(NOT _opaque_ok)
                    message(FATAL_ERROR
                        "NINLIL_SQLITE_LINKAGE=STATIC but path "
                        "'${NINLIL_SQLITE_LIBRARY_PATH}' is not a classifiable "
                        "static archive and is not an acceptable opaque "
                        "operator-forced file (must exist, regular file, "
                        "not a shared-library name).")
                endif()
                set(NINLIL_SQLITE_IS_STATIC TRUE)
                message(STATUS
                    "POSIX SQLite: accepting operator-forced opaque static "
                    "archive '${NINLIL_SQLITE_LIBRARY_PATH}'")
            else()
                message(FATAL_ERROR
                    "NINLIL_SQLITE_LINKAGE=SHARED but path "
                    "'${NINLIL_SQLITE_LIBRARY_PATH}' is not a classifiable "
                    "shared library (.so/.dylib/.tbd/.dll)")
            endif()
        endif()
        if(NINLIL_SQLITE_LINKAGE STREQUAL "STATIC" AND NOT NINLIL_SQLITE_IS_STATIC)
            message(FATAL_ERROR
                "NINLIL_SQLITE_LINKAGE=STATIC requested but resolved "
                "'${NINLIL_SQLITE_LIBRARY_PATH}' is not static")
        endif()
        if(NINLIL_SQLITE_LINKAGE STREQUAL "SHARED" AND NINLIL_SQLITE_IS_STATIC)
            message(FATAL_ERROR
                "NINLIL_SQLITE_LINKAGE=SHARED requested but resolved "
                "'${NINLIL_SQLITE_LIBRARY_PATH}' is a static archive")
        endif()

        if(NINLIL_SQLITE_IS_STATIC AND APPLE AND NINLIL_BUILD_TESTS)
            message(FATAL_ERROR
                "Static libsqlite3 with NINLIL_BUILD_TESTS=ON is unsupported on "
                "macOS (no GNU --wrap). Use shared SQLite or "
                "-DNINLIL_BUILD_TESTS=OFF. Production static install on macOS is "
                "also outside the supported matrix (see docs/08, port README).")
        endif()

        set(NINLIL_POSIX_SQLITE_STORAGE_ENABLED TRUE)
        add_library(ninlil_posix_sqlite_storage STATIC
            ports/posix/sqlite_storage/ninlil_posix_sqlite_storage.c
            ports/posix/sqlite_storage/ninlil_posix_sqlite_token_advance.c
        )
        add_library(Ninlil::ninlil_posix_sqlite_storage ALIAS
            ninlil_posix_sqlite_storage)
        target_include_directories(ninlil_posix_sqlite_storage
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include>
                $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/include
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/sqlite_storage
        )
        target_link_libraries(ninlil_posix_sqlite_storage
            PUBLIC
                ninlil
                SQLite3::SQLite3
        )
        if(NINLIL_SQLITE_IS_STATIC)
            ninlil_sqlite3_collect_static_system_deps(
                "${NINLIL_SQLITE_LIBRARY_PATH}")
            if(NINLIL_SQLITE_STATIC_SYSTEM_DEPS)
                target_link_libraries(ninlil_posix_sqlite_storage
                    PUBLIC ${NINLIL_SQLITE_STATIC_SYSTEM_DEPS})
            endif()
            set(NINLIL_CONFIG_SQLITE_STATIC TRUE)
            set(NINLIL_CONFIG_SQLITE_NEEDS_ZLIB ${NINLIL_SQLITE_NEEDS_ZLIB})
            if(UNIX AND NOT APPLE)
                set(NINLIL_CONFIG_SQLITE_NEEDS_THREADS TRUE)
            endif()
        endif()
        set_target_properties(ninlil_posix_sqlite_storage PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            POSITION_INDEPENDENT_CODE ON
            C_VISIBILITY_PRESET hidden
        )
        ninlil_apply_posix_sqlite_feature_macros(ninlil_posix_sqlite_storage)
        ninlil_apply_strict_warnings(ninlil_posix_sqlite_storage)
        ninlil_posix_sqlite_apply_path_remap(ninlil_posix_sqlite_storage)
        if(NINLIL_SQLITE_IS_STATIC)
            set(_ninlil_sqlite_kind_msg "static")
        else()
            set(_ninlil_sqlite_kind_msg "shared")
        endif()
        message(STATUS
            "POSIX SQLite storage port: enabled (${_ninlil_sqlite_kind_msg}"
            " '${NINLIL_SQLITE_LIBRARY_PATH}'"
            " linkage=${NINLIL_SQLITE_LINKAGE})")
    else()
        message(STATUS
            "POSIX SQLite storage port: disabled (SQLite3 not found)")
    endif()
endif()

# Installable OSS SDK package. The portable interface is always exported;
# the host SQLite archive/factory header are exported only when discovered.
install(TARGETS ninlil EXPORT NinlilTargets)
install(DIRECTORY include/ninlil
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE
    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/ninlil)
if(NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
    install(TARGETS ninlil_posix_sqlite_storage
        EXPORT NinlilTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ports/posix/include/ninlil_posix_sqlite_storage.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()
set(NINLIL_CONFIG_HAS_POSIX_SQLITE
    ${NINLIL_POSIX_SQLITE_STORAGE_ENABLED})
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/NinlilConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Ninlil)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(EXPORT NinlilTargets
    FILE NinlilTargets.cmake
    NAMESPACE Ninlil::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Ninlil)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Ninlil)

# Production private Runtime sources: single authority shared with the
# ESP-IDF component packaging under ports/esp-idf/components/ninlil.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_runtime_private_sources.cmake)

add_library(ninlil_runtime_private STATIC EXCLUDE_FROM_ALL
    ${NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES}
)
set_property(TARGET ninlil_runtime_private
    PROPERTY NINLIL_PRODUCTION_PRIVATE_ARTIFACT TRUE)
target_include_directories(ninlil_runtime_private PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
)
target_link_libraries(ninlil_runtime_private PRIVATE ninlil)
set_target_properties(ninlil_runtime_private PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
)
ninlil_apply_strict_warnings(ninlil_runtime_private)
# DSR2_ESP_BOUND: compiler VLA rejection on scanner TU (GNU/Clang/AppleClang).
# C11 extensions remain OFF; -Wvla under existing -Werror for this source only.
# Does not invent a permanent stack-byte ceiling — large automatic record
# objects are proved absent by tools/domain_scan_dsr2_gate.py source analysis.
# S6 seam also rejects VLAs (bounded workspace only).
if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    foreach(_vla_source IN LISTS NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES)
        set_property(
            SOURCE ${_vla_source}
            APPEND PROPERTY COMPILE_OPTIONS -Wvla
        )
    endforeach()
endif()
if(NINLIL_ENABLE_SANITIZERS)
    target_link_options(ninlil_runtime_private INTERFACE
        -fsanitize=address,undefined)
endif()
# S1 transport-only begin is TEST-build only: declare/compile under this macro.
# tests-OFF release private archive must not contain ninlil_domain_scan_begin.
if(NINLIL_BUILD_TESTS)
    target_compile_definitions(ninlil_runtime_private PRIVATE
        NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN=1)
endif()

if(NINLIL_BUILD_TESTS)
    enable_testing()

    add_test(
        NAME runtime_private_subproject_smoke
        COMMAND ${CMAKE_COMMAND}
            -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -DNINLIL_SMOKE_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}/tests/cmake/private_subproject
            -DNINLIL_SMOKE_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/private-subproject-smoke
            "-DNINLIL_GENERATOR=${CMAKE_GENERATOR}"
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

    add_test(
        NAME domain_store_vector_oracle
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_store_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
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
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
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
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_crossrow_d3s2_vector_gen.py'; js=root/'spec'/'vectors'/'domain-scan-crossrow-v1.json'; build=pathlib.Path(r'${_ninlil_d3s1_fixture}'); assert build.is_file(), 'missing build fixture '+str(build); td=tempfile.mkdtemp(); outs=[pathlib.Path(td)/'a.h', pathlib.Path(td)/'b.h']; [subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(o)]) for o in outs]; ta,tb,tbld=outs[0].read_bytes(),outs[1].read_bytes(),build.read_bytes(); assert ta==tb, 'emit-c-fixture non-deterministic'; assert ta==tbld, 'build fixture stale vs emit-c-fixture'; assert b'NINLIL_D3S1_VECTOR_COUNT ((size_t)94u)' in ta, 'd3s1 vector count pin missing'; assert b'NINLIL_D3S2_VECTOR_COUNT ((size_t)49u)' in ta, 'd3s2 vector count pin missing'; print('crossrow fixture freshness+determinism ok', len(ta), 'bytes')"
    )
    add_custom_command(
        OUTPUT ${_ninlil_d3s1_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s2_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
            ${_ninlil_d3s1_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s2_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-profile-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-structural-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-exact-get-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-composition-v1.json
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-store-v1.json
        COMMENT "Generate domain-scan-crossrow production bridge fixture (d3s1+d3s2)"
        VERBATIM
    )
    # D3-S1 production bridge: still executes the frozen 94-vector prefix only.
    add_executable(ninlil_domain_store_scanner_crossrow_oracle_bridge_test
        tests/runtime/domain_store_scanner_crossrow_oracle_bridge_test.c
        ${_ninlil_d3s1_fixture}
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
    add_test(
        NAME domain_store_scanner_crossrow_oracle_bridge
        COMMAND ninlil_domain_store_scanner_crossrow_oracle_bridge_test
    )
    # D3-S2 first product-smoke bridge: 6 empty-carrier/empty-secondary sessions.
    # Not a full D3-S2 oracle complete claim.
    add_executable(ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test
        tests/runtime/domain_store_scanner_crossrow_d3s2_oracle_bridge_test.c
        ${_ninlil_d3s1_fixture}
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
    add_test(
        NAME domain_store_scanner_crossrow_d3s2_oracle_bridge
        COMMAND ninlil_domain_store_scanner_crossrow_d3s2_oracle_bridge_test
    )
    # Freshness compares against the build artifact; ensure it is generated.
    set_tests_properties(domain_scan_crossrow_fixture_freshness PROPERTIES
        DEPENDS "domain_store_scanner_crossrow_oracle_bridge;domain_store_scanner_crossrow_d3s2_oracle_bridge"
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
        add_test(
            NAME posix_sqlite_storage_installed_consumer
            COMMAND ${CMAKE_COMMAND}
                -DNINLIL_BUILD_DIR=${CMAKE_CURRENT_BINARY_DIR}
                -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
                -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
                -DNINLIL_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}
                -DNINLIL_BUILD_CONFIG=$<CONFIG>
                -DNINLIL_INSTALL_SMOKE_SANITIZERS=${NINLIL_ENABLE_SANITIZERS}
                "-DNINLIL_SMOKE_SQLITE3_LIBRARY=${NINLIL_SQLITE_LIBRARY_PATH}"
                "-DNINLIL_SMOKE_SQLITE3_INCLUDE_DIR=${_ninlil_smoke_sqlite_inc}"
                -DNINLIL_SMOKE_EXPECT_STATIC_SQLITE=${_ninlil_smoke_expect_static}
                -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/installed_posix_sqlite_consumer_smoke.cmake
        )
    endif()

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
    # no ESP-IDF / FreeRTOS backend link). Spec: docs/19.
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_esp_idf_port_sources.cmake)
    add_library(ninlil_esp_idf_port_pure STATIC
        ${NINLIL_ESP_IDF_PORT_PURE_RELATIVE_SOURCES}
    )
    target_include_directories(ninlil_esp_idf_port_pure
        PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/include
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
    )
    target_link_libraries(ninlil_esp_idf_port_pure PRIVATE ninlil)
    set_target_properties(ninlil_esp_idf_port_pure PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
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
            "vector inventory ok: total=301 table=257 explicit=26 bullet=16 canonical=2"
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
            "vector references ok: definitions=301 mandatory_unique=274 pr_unique=294 union=301 mandatory_occurrences=278 pr_occurrences=294 mandatory_rows=40 pr_bullets=11 excluded=1"
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
