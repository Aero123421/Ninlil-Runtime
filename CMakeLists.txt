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

# R7 Host private crypto uses OpenSSL major version exactly 3 (docs/31).
# find_package(OpenSSL 3) means >=3 and would accept 4.x; fail-closed on
# major >=4 and on empty OPENSSL_VERSION. Top-level builds (including the
# tests-OFF packaging gate) must prove that production adapter. A downstream
# add_subdirectory consumer that builds only the installable public interface
# is not forced to acquire a dependency for an EXCLUDE_FROM_ALL private target.
set(NINLIL_R7_HOST_CRYPTO_ENABLED FALSE)
if(NINLIL_IS_TOP_LEVEL OR NINLIL_BUILD_TESTS)
    find_package(OpenSSL 3 REQUIRED COMPONENTS Crypto)
    if(NOT DEFINED OPENSSL_VERSION OR OPENSSL_VERSION STREQUAL "")
        message(FATAL_ERROR
            "OpenSSL discovered but OPENSSL_VERSION is empty; "
            "R7 Host crypto requires OpenSSL major version exactly 3")
    endif()
    if(OPENSSL_VERSION VERSION_LESS "3"
            OR NOT OPENSSL_VERSION VERSION_LESS "4")
        message(FATAL_ERROR
            "Ninlil R7 Host crypto requires OpenSSL major version exactly 3 "
            "(found ${OPENSSL_VERSION})")
    endif()
    set(NINLIL_R7_HOST_CRYPTO_ENABLED TRUE)
endif()

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
# Dedicated pointer-compare sanitizer (docs/22). Not a substitute for
# NINLIL_ENABLE_SANITIZERS alone: uses -fsanitize=address,pointer-compare and
# ASAN_OPTIONS=detect_invalid_pointer_pairs=2. Feature-detected; required on
# Linux CI (see .github/workflows/ci.yml).
option(NINLIL_ENABLE_POINTER_COMPARE_SANITIZER
    "Build with ASan+pointer-compare (invalid pointer pairs)" OFF)
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

set(_ninlil_pointer_compare_sanitizer_supported FALSE)
if(NINLIL_ENABLE_POINTER_COMPARE_SANITIZER)
    if(NOT _ninlil_sanitizer_supported)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            message(FATAL_ERROR
                "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER=ON requires GNU/Clang on Linux")
        else()
            message(WARNING
                "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER ignored: unsupported compiler")
        endif()
    else()
        include(CheckCSourceCompiles)
        set(_ninlil_pc_save_flags "${CMAKE_REQUIRED_FLAGS}")
        set(CMAKE_REQUIRED_FLAGS
            "-fsanitize=address,pointer-compare -fno-omit-frame-pointer")
        set(CMAKE_REQUIRED_LINK_OPTIONS
            "-fsanitize=address,pointer-compare")
        check_c_source_compiles(
            "int main(void) { return 0; }"
            NINLIL_HAS_POINTER_COMPARE_SANITIZER)
        set(CMAKE_REQUIRED_FLAGS "${_ninlil_pc_save_flags}")
        unset(CMAKE_REQUIRED_LINK_OPTIONS)
        if(NINLIL_HAS_POINTER_COMPARE_SANITIZER)
            set(_ninlil_pointer_compare_sanitizer_supported TRUE)
            add_compile_options(
                -fsanitize=address,pointer-compare -fno-omit-frame-pointer)
            add_link_options(-fsanitize=address,pointer-compare)
            message(STATUS
                "pointer-compare sanitizer enabled (detect_invalid_pointer_pairs=2 at test time)")
        elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            message(FATAL_ERROR
                "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER=ON required on Linux but "
                "-fsanitize=address,pointer-compare is unsupported by this toolchain")
        else()
            message(WARNING
                "NINLIL_ENABLE_POINTER_COMPARE_SANITIZER requested but unsupported; skipping")
        endif()
    endif()
endif()

# Any active sanitizer instrumentation (ASan/UBSan and/or active pointer-compare
# ASan). Production N6 frame ceiling and .su multipass gate are non-authoritative
# under redzones / dynamic .su rewrite — skip those only when this is TRUE.
# Self-test/structure and all non-sanitizer Debug/Release/ESP gates stay strict.
set(_ninlil_any_sanitizer_active FALSE)
if(NINLIL_ENABLE_SANITIZERS OR _ninlil_pointer_compare_sanitizer_supported)
    set(_ninlil_any_sanitizer_active TRUE)
endif()

# Native GNU x86/x86_64 host builds only: -maccumulate-outgoing-args fixes
# .su kind=dynamic caused by push/pop of outgoing call arguments (GCC classifies
# those frames as dynamic even without VLAs). Feature-detect; fail closed when
# unavailable on this host. Shared by N6 production and R7 portable production
# sources (AES-GCM seal/open wrappers need static .su on the same host class).
# Do not apply to AppleClang, Clang, non-x86 hosts, cross builds, or ESP Xtensa.
# Cache probe name NINLIL_HAS_MACCUMULATE_OUTGOING_ARGS is stable for CI assert.
set(_ninlil_maccumulate_outgoing_args FALSE)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT CMAKE_CROSSCOMPILING)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _ninlil_target_cpu)
    if(_ninlil_target_cpu MATCHES "^(x86_64|amd64|x64|i[3-6]86|x86)$")
        include(CheckCCompilerFlag)
        check_c_compiler_flag(
            -maccumulate-outgoing-args
            NINLIL_HAS_MACCUMULATE_OUTGOING_ARGS)
        if(NOT NINLIL_HAS_MACCUMULATE_OUTGOING_ARGS)
            message(FATAL_ERROR
                "GNU x86/x86_64 host requires -maccumulate-outgoing-args for "
                "N6/R7 production static .su classification, but the C compiler "
                "rejected the flag (target=${CMAKE_SYSTEM_PROCESSOR})")
        endif()
        set(_ninlil_maccumulate_outgoing_args TRUE)
        message(STATUS
            "N6/R7 production: -maccumulate-outgoing-args enabled "
            "(native GNU target ${CMAKE_SYSTEM_PROCESSOR}; "
            "NINLIL_HAS_MACCUMULATE_OUTGOING_ARGS=1)")
    endif()
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

# Feature macros for A1 POSIX USB serial (termios/poll/TIOCEXCL) under
# C_EXTENSIONS OFF. Host-only; not installed; not part of public package.
function(ninlil_apply_posix_usb_serial_feature_macros target)
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

        set(NINLIL_POSIX_LAB_PLATFORM_ENABLED TRUE)
        add_library(ninlil_posix_lab_platform STATIC
            ports/posix/lab_platform/ninlil_posix_lab_platform.c
            ports/posix/loopback_bearer/ninlil_posix_loopback_bearer.c
            ports/posix/loopback_bearer/ninlil_posix_loopback_bearer_wire.c
            ports/posix/loopback_bearer/ninlil_posix_loopback_bearer_inject.c
            tests/support/platform_basic_fixtures.c
            tests/support/deterministic_entropy.c
            tests/support/typed_simulated_bearer.c
            tests/support/canonical_origin_authorization.c
        )
        add_library(Ninlil::ninlil_posix_lab_platform ALIAS
            ninlil_posix_lab_platform)
        target_include_directories(ninlil_posix_lab_platform
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include>
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/include
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/lab_platform
                ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/loopback_bearer
                ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
        )
        target_link_libraries(ninlil_posix_lab_platform
            PUBLIC
                ninlil
                ninlil_posix_sqlite_storage
        )
        set_target_properties(ninlil_posix_lab_platform PROPERTIES
            C_STANDARD 11
            C_STANDARD_REQUIRED ON
            C_EXTENSIONS OFF
            POSITION_INDEPENDENT_CODE ON
            C_VISIBILITY_PRESET hidden
        )
        ninlil_apply_posix_sqlite_feature_macros(ninlil_posix_lab_platform)
        ninlil_apply_strict_warnings(ninlil_posix_lab_platform)
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
install(FILES LICENSE NOTICE THIRD-PARTY-NOTICES.md
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

# R7 T1b context binding (docs/33): single source/test authority. Appends the
# portable binding TU into the shared private/VLA lists exactly once before
# ninlil_runtime_private is created. Test registration is a separate function
# call under NINLIL_BUILD_TESTS (does not recompile production sources).
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_nrw1_t1b_ctest.cmake)

# M4 LAB Join/Attachment (V1 item 7): append portable sources before private lib.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_m4_lab_ctest.cmake)

# C3-LAB secure wire + context lifecycle (V1 item 8).
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_c3_lab_ctest.cmake)

# C6-LAB enforcement (V1 item 10a): LAB_ONLY sole-edge gate.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_c6_lab_ctest.cmake)

# C4/C5-LAB USB + radio software path (V1 item 9).
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_c4_c5_lab_ctest.cmake)

# R4 SX1262 portable control-plane (D1). Not public ABI. Not RF TX complete.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_sx1262_sources.cmake)

add_library(ninlil_runtime_private STATIC EXCLUDE_FROM_ALL
    ${NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES}
)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_sources(ninlil_runtime_private PRIVATE
        ${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES})
endif()
# N6 production set (codec+crypto+context) comes only from
# cmake/ninlil_runtime_private_sources.cmake — no host-only re-injection.

set_property(TARGET ninlil_runtime_private
    PROPERTY NINLIL_PRODUCTION_PRIVATE_ARTIFACT TRUE)
target_include_directories(ninlil_runtime_private PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
)

# R4 production-private portable SX1262 backend (drivers/sx126x). Host tests
# and ESP packaging share cmake/ninlil_sx1262_sources.cmake. Spy stays tests-only.
add_library(ninlil_sx1262 STATIC EXCLUDE_FROM_ALL
    ${NINLIL_SX1262_PORTABLE_RELATIVE_SOURCES}
    ${NINLIL_SX1262_ESP_PURE_RELATIVE_SOURCES}
)
set_property(TARGET ninlil_sx1262
    PROPERTY NINLIL_PRODUCTION_PRIVATE_ARTIFACT TRUE)
target_include_directories(ninlil_sx1262 PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/drivers/sx126x>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/include>
)
set_target_properties(ninlil_sx1262 PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
)
ninlil_apply_strict_warnings(ninlil_sx1262)
if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    target_compile_options(ninlil_sx1262 PRIVATE -Wvla)
endif()
if(NINLIL_ENABLE_SANITIZERS)
    target_link_options(ninlil_sx1262 INTERFACE
        -fsanitize=address,undefined)
endif()
target_link_libraries(ninlil_runtime_private PRIVATE ninlil)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_link_libraries(ninlil_runtime_private PRIVATE OpenSSL::Crypto)
endif()
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
    # N6 production: frame ceiling + stack-usage artifacts for multipass boot gate.
    # .su lands next to objects under CMakeFiles/ninlil_runtime_private.dir/ —
    # that directory is the sole authoritative host input to n6_frame_stack_gate
    # (not testbuild, not an unused side directory). AppleClang emits .su and
    # supports -Wframe-larger-than; do not host-skip.
    # ASan/UBSan (including pointer-compare ASan) inflate frames (redzones) and
    # rewrite .su kind to dynamic — skip -Wframe-larger-than when any sanitizer
    # is active (_ninlil_any_sanitizer_active). Production .su CTest gate is
    # registered only when that flag is FALSE (see tests below).
    # GNU host x86: also -maccumulate-outgoing-args (see detection above) so
    # outgoing-arg push/pop does not force dynamic .su on Debug or Release.
    # Same conditional flag is applied to R7 portable production sources below.
    foreach(_n6_src IN LISTS NINLIL_N6_PRODUCTION_RELATIVE_SOURCES)
        set(_n6_compile_opts -Wvla -Werror -fstack-usage)
        if(NOT _ninlil_any_sanitizer_active)
            list(APPEND _n6_compile_opts -Wframe-larger-than=2048)
        endif()
        if(_ninlil_maccumulate_outgoing_args)
            list(APPEND _n6_compile_opts -maccumulate-outgoing-args)
        endif()
        set_property(
            SOURCE ${_n6_src}
            APPEND PROPERTY COMPILE_OPTIONS ${_n6_compile_opts}
        )
    endforeach()
    # R7 portable wrapper: docs/31 §11.6 candidate static-frame ceiling.
    # Adapter call-chain/task stack sufficiency remains a separate ESP gate.
    # Native GNU x86: share -maccumulate-outgoing-args with N6 so AES-GCM
    # seal/open .su kind stays static (not dynamic,bounded).
    foreach(_r7_src IN LISTS NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES)
        set(_r7_compile_opts -Werror -fstack-usage)
        if(NOT _ninlil_any_sanitizer_active)
            list(APPEND _r7_compile_opts -Wframe-larger-than=2560)
        endif()
        if(_ninlil_maccumulate_outgoing_args)
            list(APPEND _r7_compile_opts -maccumulate-outgoing-args)
        endif()
        set_property(
            SOURCE ${_r7_src}
            APPEND PROPERTY COMPILE_OPTIONS ${_r7_compile_opts}
        )
    endforeach()
    # R7 T1 NRW1 SINGLE pure wire codec: docs/32 §9.8 host candidate ceiling
    # 2560 static. Adapter/ESP task stack sufficiency is not claimed.
    foreach(_r7_wire_src IN LISTS NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES)
        set(_r7_wire_compile_opts -Werror -fstack-usage)
        if(NOT _ninlil_any_sanitizer_active)
            list(APPEND _r7_wire_compile_opts -Wframe-larger-than=2560)
        endif()
        if(_ninlil_maccumulate_outgoing_args)
            list(APPEND _r7_wire_compile_opts -maccumulate-outgoing-args)
        endif()
        set_property(
            SOURCE ${_r7_wire_src}
            APPEND PROPERTY COMPILE_OPTIONS ${_r7_wire_compile_opts}
        )
    endforeach()
    # R7 T1b context binding: docs/33 §8/§10 host candidate static-frame
    # ceiling 2560. Release must be effectively -O2 (the source-local option
    # intentionally follows CMake's default -O3, so the last option wins).
    # Production binding TU only; tests link the private archive.
    foreach(_r7_t1b_src IN LISTS NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES)
        set(_r7_t1b_compile_opts -Werror -fstack-usage)
        list(APPEND _r7_t1b_compile_opts "$<$<CONFIG:Release>:-O2>")
        if(NOT _ninlil_any_sanitizer_active)
            list(APPEND _r7_t1b_compile_opts -Wframe-larger-than=2560)
        endif()
        if(_ninlil_maccumulate_outgoing_args)
            list(APPEND _r7_t1b_compile_opts -maccumulate-outgoing-args)
        endif()
        set_property(
            SOURCE ${_r7_t1b_src}
            APPEND PROPERTY COMPILE_OPTIONS ${_r7_t1b_compile_opts}
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
        NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN=1
        NINLIL_CTRL_SESSION_ENABLE_TEST_SEAM=1
        NINLIL_LOGICAL_SESSION_ENABLE_TEST_SEAM=1
        # R7 portable span-overflow seam (docs/31); tests-OFF omits this symbol.
        NINLIL_R7_CRYPTO_TEST_BUILD=1
        # T1 wire pairwise-span seam; tests-OFF and production omit this symbol.
        NINLIL_R7_WIRE_TEST_BUILD=1
        # T1b binding secret-zero / span seams; tests-OFF and ESP omit these.
        NINLIL_R7_BINDING_TEST_BUILD=1)
endif()

# U1 A1 POSIX USB/serial adapter (host-only production-private). Implements
# C1 byte-stream contract. NOT installed; NOT public include/ninlil; NOT
# linked into ESP packaging. Required HIL Linux+macOS still pending — do not
# treat this target as U1 complete.
set(NINLIL_POSIX_USB_SERIAL_ENABLED FALSE)
# U1 host adapter targets Linux and macOS only (docs/23 §3.2). Not all UNIX.
if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    set(NINLIL_POSIX_USB_SERIAL_ENABLED TRUE)
    add_library(ninlil_posix_usb_serial STATIC EXCLUDE_FROM_ALL
        ports/posix/usb_serial/ninlil_posix_usb_serial.c
    )
    add_library(Ninlil::ninlil_posix_usb_serial ALIAS ninlil_posix_usb_serial)
    target_include_directories(ninlil_posix_usb_serial
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/usb_serial>
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/transport>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
    )
    set_target_properties(ninlil_posix_usb_serial PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
        NINLIL_PRODUCTION_PRIVATE_ARTIFACT TRUE
    )
    ninlil_apply_posix_usb_serial_feature_macros(ninlil_posix_usb_serial)
    ninlil_apply_strict_warnings(ninlil_posix_usb_serial)
    # pthread for owner-thread fencing; util only needed by tests (openpty).
    find_package(Threads REQUIRED)
    target_link_libraries(ninlil_posix_usb_serial PUBLIC Threads::Threads)
    message(STATUS
        "POSIX USB serial adapter (U1 A1): enabled (host private; not installed)")
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
           OR _source_name STREQUAL "domain_store_d3s3.c"
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
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_crossrow_d3s2_vector_gen.py'; js=root/'spec'/'vectors'/'domain-scan-crossrow-v1.json'; build=pathlib.Path(r'${_ninlil_d3s1_fixture}'); assert build.is_file(), 'missing build fixture '+str(build); td=tempfile.mkdtemp(); outs=[pathlib.Path(td)/'a.h', pathlib.Path(td)/'b.h']; [subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(o)]) for o in outs]; ta,tb,tbld=outs[0].read_bytes(),outs[1].read_bytes(),build.read_bytes(); assert ta==tb, 'emit-c-fixture non-deterministic'; assert ta==tbld, 'build fixture stale vs emit-c-fixture'; assert b'NINLIL_D3S1_VECTOR_COUNT ((size_t)94u)' in ta, 'd3s1 vector count pin missing'; assert b'NINLIL_D3S2_VECTOR_COUNT ((size_t)50u)' in ta, 'd3s2 vector count pin missing'; print('crossrow fixture freshness+determinism ok', len(ta), 'bytes')"
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
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
            check
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
    )
    add_test(
        NAME domain_scan_crossrow_d3s3_vector_oracle_self_test
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
            self-test
    )
    set(_ninlil_d3s3_fixture
        ${CMAKE_CURRENT_BINARY_DIR}/domain_scan_crossrow_d3s3_fixture.h)
    add_custom_command(
        OUTPUT ${_ninlil_d3s3_fixture}
        COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
            emit-c-fixture
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
            ${_ninlil_d3s3_fixture}
        DEPENDS
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/domain_scan_crossrow_d3s3_vector_gen.py
            ${CMAKE_CURRENT_SOURCE_DIR}/spec/vectors/domain-scan-crossrow-v1.json
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
        COMMAND ${Python3_EXECUTABLE} -c
            "import pathlib,subprocess,sys,tempfile; root=pathlib.Path(r'${CMAKE_CURRENT_SOURCE_DIR}'); py=root/'tools'/'domain_scan_crossrow_d3s3_vector_gen.py'; js=root/'spec'/'vectors'/'domain-scan-crossrow-v1.json'; build=pathlib.Path(r'${_ninlil_d3s3_fixture}'); td=pathlib.Path(tempfile.mkdtemp()); a=td/'a.h'; b=td/'b.h'; subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(a)]); subprocess.check_call([sys.executable,str(py),'emit-c-fixture',str(js),str(b)]); assert a.read_bytes()==b.read_bytes()==build.read_bytes(); print('d3s3 fixture freshness+determinism ok')"
    )
    set_tests_properties(domain_scan_crossrow_d3s3_fixture_freshness PROPERTIES
        DEPENDS domain_store_scanner_crossrow_d3s3_oracle_bridge
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
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
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
            PUBLIC
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/usb_serial>
                $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/transport>
            PRIVATE
                ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
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
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
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
            "vector inventory ok: total=302 table=258 explicit=26 bullet=16 canonical=2"
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
            "vector references ok: definitions=302 mandatory_unique=280 pr_unique=295 union=302 mandatory_occurrences=284 pr_occurrences=295 mandatory_rows=40 pr_bullets=11 excluded=1"
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
