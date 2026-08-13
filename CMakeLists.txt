cmake_minimum_required(VERSION 3.20)

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
option(NINLIL_BUILD_DECODER_FUZZERS
    "Build opt-in Clang/libFuzzer decoder boundary harnesses (not installed)"
    OFF)
if(NINLIL_BUILD_DECODER_FUZZERS AND NOT NINLIL_BUILD_TESTS)
    message(FATAL_ERROR
        "NINLIL_BUILD_DECODER_FUZZERS requires NINLIL_BUILD_TESTS=ON; "
        "the six private harness targets live only in the test graph")
endif()
option(NINLIL_ABI_GOLDEN_ALLOW_MISSING
    "Allow ABI golden tests to skip a target with no committed golden"
    OFF)
option(NINLIL_ENABLE_STRICT_WARNINGS "Build Ninlil with warnings as errors"
    ${_ninlil_strict_warnings_default})
option(NINLIL_BUILD_HOST_RUNTIME
    "Build and install the static Host Runtime SDK target"
    ${NINLIL_IS_TOP_LEVEL})
option(NINLIL_BUILD_FABRIC_V1
    "Build and install the experimental portable Fabric v1 target"
    ${NINLIL_BUILD_HOST_RUNTIME})
option(NINLIL_BUILD_POSIX_TLS_V1
    "Build and install the experimental Linux/macOS POSIX TLS Fabric port"
    ${NINLIL_BUILD_FABRIC_V1})
set(_ninlil_posix_usb_serial_default OFF)
if(NINLIL_IS_TOP_LEVEL
   AND (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux"))
    set(_ninlil_posix_usb_serial_default ON)
endif()
option(NINLIL_BUILD_POSIX_USB_SERIAL_V1
    "Build and install the experimental Linux/macOS POSIX USB serial port"
    ${_ninlil_posix_usb_serial_default})
option(NINLIL_BUILD_V1_LAB_CONTROLLER
    "Build the private Linux/macOS V1 USB Controller diagnostic"
    OFF)
set(NINLIL_POSIX_USB_SERIAL_ENABLED FALSE)
if(NINLIL_BUILD_POSIX_USB_SERIAL_V1)
    if(NOT (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux"))
        message(FATAL_ERROR
            "NINLIL_BUILD_POSIX_USB_SERIAL_V1 is supported only on Linux and macOS")
    endif()
    set(NINLIL_POSIX_USB_SERIAL_ENABLED TRUE)
endif()
option(NINLIL_BUILD_POSIX_SQLITE_STORAGE
    "Build POSIX SQLite storage port when SQLite3 is available" ON)
option(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING
    "Enable ADR-0022 Domain schema1 format-2 runtime binding private slice" OFF)
option(NINLIL_ENABLE_PRIVATE_FABRIC_V1
    "Enable ADR-0017 private Fabric Bearer v1 / NFL1 source candidate (default-OFF, non-installed)"
    OFF)
option(NINLIL_ENABLE_PRIVATE_WIFI_V1
    "Enable ADR-0018 private Wi-Fi Host candidate (default-OFF, non-installed; POSIX+OpenSSL3)"
    OFF)
option(NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL
    "LAB smoke only: allow wifi Host TLS init when OpenSSL != exact 3.5.7 (not authority)"
    OFF)
option(NINLIL_WIFI_OPENSSL_AUTHORITY
    "Require exact pinned static OpenSSL 3.5.7 for Wi-Fi Host authority"
    OFF)
set(NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT "" CACHE PATH
    "Hermetic OpenSSL 3.5.7 static install root used by Wi-Fi Host authority")
option(NINLIL_ENABLE_R7_FRAG_PRIVATE
    "Build private NRW1 LINK/FRAG candidate (default OFF; not installed)" OFF)
option(NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1
    "Enable ADR-0019/0020 private route-relay/multi-parent Host candidate (default-OFF, non-installed)"
    OFF)
option(NINLIL_ENABLE_MFDT_V1_PRIVATE
    "Build private ADR-0021 MFDT candidate (default OFF; not installed; not public ABI)"
    OFF)

if(NINLIL_WIFI_OPENSSL_AUTHORITY)
    if(NOT NINLIL_ENABLE_PRIVATE_WIFI_V1)
        message(FATAL_ERROR
            "NINLIL_WIFI_OPENSSL_AUTHORITY requires "
            "NINLIL_ENABLE_PRIVATE_WIFI_V1=ON")
    endif()
    if(NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL)
        message(FATAL_ERROR
            "NINLIL_WIFI_OPENSSL_AUTHORITY and "
            "NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL are mutually exclusive")
    endif()
    if(NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT STREQUAL ""
            OR NOT IS_DIRECTORY "${NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT}")
        message(FATAL_ERROR
            "NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT must name the hermetic "
            "OpenSSL 3.5.7 static install")
    endif()
    file(REAL_PATH "${NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT}"
        NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT)
    set(OPENSSL_ROOT_DIR "${NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT}"
        CACHE PATH "Pinned OpenSSL root" FORCE)
    set(OPENSSL_USE_STATIC_LIBS TRUE CACHE BOOL
        "Use pinned static OpenSSL archives" FORCE)
endif()

# R7 Host crypto uses OpenSSL major version exactly 3 (docs/31).
# find_package(OpenSSL 3) means >=3 and would accept 4.x; fail-closed on
# major >=4 and on empty OPENSSL_VERSION. The installable Host Runtime and
# top-level/test builds must prove that production adapter. A downstream
# add_subdirectory consumer that disables NINLIL_BUILD_HOST_RUNTIME and tests
# is not forced to acquire OpenSSL for an EXCLUDE_FROM_ALL private target.
set(NINLIL_R7_HOST_CRYPTO_ENABLED FALSE)
if(NINLIL_IS_TOP_LEVEL OR NINLIL_BUILD_TESTS OR NINLIL_BUILD_HOST_RUNTIME)
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
option(NINLIL_ENABLE_TSAN
    "Instrument private wifi/fabric libraries with ThreadSanitizer (non-Apple)"
    OFF)
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
# Also recognize an explicit toolchain/global sanitizer flag.  Focused UBSan
# jobs intentionally use CMAKE_C_FLAGS rather than enabling the combined
# ASan+UBSan option; instrumented stack frames and .su files are equally
# non-authoritative in that mode.
set(_ninlil_effective_c_flags
    "${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_DEBUG} ${CMAKE_C_FLAGS_RELEASE} "
    "${CMAKE_C_FLAGS_RELWITHDEBINFO} ${CMAKE_C_FLAGS_MINSIZEREL}")
if(_ninlil_effective_c_flags MATCHES "(^|[ ;])-fsanitize=")
    set(_ninlil_any_sanitizer_active TRUE)
endif()

# Native GNU x86/x86_64 host builds only: -maccumulate-outgoing-args fixes
# .su kind=dynamic caused by push/pop of outgoing call arguments (GCC classifies
# those frames as dynamic even without VLAs). Feature-detect; fail closed when
# unavailable on this host. Shared by the Fabric radio chain, N6 production,
# and R7 portable production sources (outgoing calls otherwise make GCC report
# bounded frames as dynamic in the same host class).
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
                "Fabric/N6/R7 production static .su classification, but the C compiler "
                "rejected the flag (target=${CMAKE_SYSTEM_PROCESSOR})")
        endif()
        set(_ninlil_maccumulate_outgoing_args TRUE)
        message(STATUS
            "Fabric/N6/R7 production: -maccumulate-outgoing-args enabled "
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

# Single source of feature macros for POSIX host targets.
# glibc + -std=c11 (no extensions): realpath needs XSI; flock/MAP_ANONYMOUS
# need _DEFAULT_SOURCE. macOS keeps _DARWIN_C_SOURCE only.
function(ninlil_apply_posix_host_feature_macros target)
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

function(ninlil_apply_posix_sqlite_feature_macros target)
    ninlil_apply_posix_host_feature_macros(${target})
endfunction()

# Feature macros for the Linux/macOS POSIX USB serial reference port and its
# private tests (termios/poll/TIOCEXCL under C_EXTENSIONS OFF).
function(ninlil_apply_posix_usb_serial_feature_macros target)
    ninlil_apply_posix_host_feature_macros(${target})
endfunction()

# Host-only durable storage port. Missing SQLite must not break portable core.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_posix_sqlite_sqlite3.cmake)
set(NINLIL_POSIX_SQLITE_STORAGE_ENABLED FALSE)
set(NINLIL_POSIX_LAB_PLATFORM_ENABLED FALSE)
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

        # LAB host platform composes tests/support fixtures. Build only when
        # NINLIL_BUILD_TESTS is ON so tests-OFF default ``all`` / install never
        # compiles or ships test fixture objects.
        set(NINLIL_POSIX_LAB_PLATFORM_ENABLED FALSE)
        if(NINLIL_BUILD_TESTS)
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
                NINLIL_TEST_ONLY_ARTIFACT TRUE
            )
            ninlil_apply_posix_sqlite_feature_macros(ninlil_posix_lab_platform)
            ninlil_apply_strict_warnings(ninlil_posix_lab_platform)
            message(STATUS
                "POSIX LAB platform: enabled (tests-only; tests/support fixtures)")
        else()
            message(STATUS
                "POSIX LAB platform: skipped (NINLIL_BUILD_TESTS=OFF; "
                "no tests/support in default all)")
        endif()
    else()
        message(STATUS
            "POSIX SQLite storage port: disabled (SQLite3 not found)")
    endif()
endif()

# Installable OSS SDK package. The portable interface is always exported.
# Host Runtime and SQLite install rules are added by their target blocks.
install(TARGETS ninlil EXPORT NinlilTargets)
install(DIRECTORY include/ninlil
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES LICENSE NOTICE THIRD-PARTY-NOTICES.md
    DESTINATION ${CMAKE_INSTALL_DATADIR}/licenses/ninlil)
install(FILES compatibility-matrix.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ninlil)
install(FILES dependency-inventory.json
    DESTINATION ${CMAKE_INSTALL_DATADIR}/ninlil)
if(NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
    install(TARGETS ninlil_posix_sqlite_storage
        EXPORT NinlilTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    install(FILES ports/posix/include/ninlil_posix_sqlite_storage.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

# Production private Runtime sources: single authority shared with the
# ESP-IDF component packaging under ports/esp-idf/components/ninlil.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_runtime_private_sources.cmake)

# Installable Host Runtime sources are a separate immutable authority. The
# private integration archive below is deliberately broader and must never be
# reused as the public SDK source set.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_host_runtime_sources.cmake)

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

# ADR-0029 portable Fabric v1 / ADR-0032 Composition v1. Host and ESP-IDF
# consume the same explicit production source authority.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_composition_v1_sources.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_rrmp_sources.cmake)
if(NINLIL_BUILD_FABRIC_V1)
    add_library(ninlil_fabric_v1 STATIC
        ${NINLIL_FABRIC_V1_PUBLIC_RELATIVE_SOURCES})
    add_library(Ninlil::fabric_v1 ALIAS ninlil_fabric_v1)
    target_include_directories(ninlil_fabric_v1
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1)
    target_link_libraries(ninlil_fabric_v1 PUBLIC ninlil)
    set_target_properties(ninlil_fabric_v1 PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
        EXPORT_NAME fabric_v1)
    ninlil_apply_strict_warnings(ninlil_fabric_v1)
    ninlil_apply_installed_archive_path_remap(ninlil_fabric_v1)
    if(NINLIL_ENABLE_SANITIZERS)
        target_link_options(ninlil_fabric_v1 INTERFACE
            -fsanitize=address,undefined)
    endif()
    install(TARGETS ninlil_fabric_v1
        EXPORT NinlilTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

# ADR-0030 Host reference port.  Keep this allowlist explicit: no ESP STA,
# lwIP, mbedTLS, owner, private umbrella, discovery, Join, or plugin source is
# permitted in the installed target.
if(NINLIL_BUILD_POSIX_TLS_V1)
    if(NOT (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux"))
        message(FATAL_ERROR
            "NINLIL_BUILD_POSIX_TLS_V1 is supported only on Linux and macOS")
    endif()
    if(NOT NINLIL_BUILD_FABRIC_V1)
        message(FATAL_ERROR
            "NINLIL_BUILD_POSIX_TLS_V1 requires NINLIL_BUILD_FABRIC_V1=ON")
    endif()
    find_package(OpenSSL 3 REQUIRED COMPONENTS SSL Crypto)
    if(NOT DEFINED OPENSSL_VERSION OR OPENSSL_VERSION STREQUAL ""
            OR OPENSSL_VERSION VERSION_LESS "3"
            OR NOT OPENSSL_VERSION VERSION_LESS "4")
        message(FATAL_ERROR
            "Ninlil::posix_tls_v1 requires OpenSSL >=3,<4 "
            "(found '${OPENSSL_VERSION}')")
    endif()
    find_package(Threads REQUIRED)
    set(_ninlil_posix_tls_v1_srcs
        src/transport/posix_tls_v1/posix_tls_v1.c
        src/transport/posix_tls_v1/posix_tls_v1_records.c
        # Selected Host-only ADR-0018 implementation units.  Keep this list
        # explicit: wifi_session.c also contains M4/NWB1/payload machinery and
        # is intentionally not linked by the C1 peer-session tranche.
        src/transport/wifi_v1/wifi_tcp_posix.c
        src/transport/wifi_v1/wifi_tls_host.c
        src/transport/wifi_v1/wifi_tls_export.c
        src/transport/wifi_v1/wifi_tls_leaf_binding.c
        src/transport/wifi_v1/wifi_reconnect.c
        src/transport/wifi_v1/wifi_storage_cu.c
        src/transport/wifi_v1/wifi_nwb1.c
        src/transport/wifi_v1/wifi_stream.c
        src/transport/wifi_v1/wifi_sha256_host.c)
    add_library(ninlil_posix_tls_v1 STATIC ${_ninlil_posix_tls_v1_srcs})
    add_library(Ninlil::posix_tls_v1 ALIAS ninlil_posix_tls_v1)
    target_include_directories(ninlil_posix_tls_v1
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/wifi_v1
    )
    target_compile_definitions(ninlil_posix_tls_v1 PRIVATE
        NINLIL_POSIX_TLS_V1_BUILD=1
        NINLIL_WIFI_RX_STREAM_SINGLE_RECORD=1)
    target_link_libraries(ninlil_posix_tls_v1
        PUBLIC
            ninlil_fabric_v1
            OpenSSL::SSL
            OpenSSL::Crypto
            Threads::Threads)
    set_target_properties(ninlil_posix_tls_v1 PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
        EXPORT_NAME posix_tls_v1)
    ninlil_apply_strict_warnings(ninlil_posix_tls_v1)
    ninlil_apply_installed_archive_path_remap(ninlil_posix_tls_v1)
    if(NINLIL_ENABLE_SANITIZERS)
        target_link_options(ninlil_posix_tls_v1 INTERFACE
            -fsanitize=address,undefined)
    endif()
    install(TARGETS ninlil_posix_tls_v1
        EXPORT NinlilTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

add_library(ninlil_runtime_private STATIC EXCLUDE_FROM_ALL
    ${NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES}
    ${NINLIL_SX1262_R9_EDGE_RELATIVE_SOURCES}
    ${NINLIL_PCP_LAB_SESSION_LEDGER_RELATIVE_SOURCES}
)
if(NINLIL_R7_HOST_CRYPTO_ENABLED)
    target_sources(ninlil_runtime_private PRIVATE
        ${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES})
endif()
if(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
    target_sources(ninlil_runtime_private PRIVATE
        src/model/domain_schema1_runtime_binding.c
        src/model/domain_schema1_startup_authority.c
        src/runtime/domain_schema1_startup_owner.c
        src/runtime/domain_schema1_kind1_register.c)
    # PUBLIC: TUs including runtime_internal.h must match the private archive
    # feature bit so domain_schema1 workspace fields do not shift callback
    # /evidence offsets in the private runtime layout.
    target_compile_definitions(ninlil_runtime_private PUBLIC
        NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
    # runtime_public.c / runtime_internal.h need the feature bit for the
    # create-path integration and workspace layout.
    target_include_directories(ninlil_runtime_private PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime)
endif()
if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
    # Private Fabric v1 candidate (ADR-0017). Canonical NFL1 is nfl1_codec.c only.
    # Headers under src/transport/fabric_v1/ are never installed.
    target_sources(ninlil_runtime_private PRIVATE
        ${NINLIL_FABRIC_V1_CORE_RELATIVE_SOURCES})
    target_compile_definitions(ninlil_runtime_private PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    target_include_directories(ninlil_runtime_private PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1)
endif()

# Private route-relay / multi-parent candidate (ADR-0019 / ADR-0020).
# Default-OFF; headers under src/runtime/route_relay_v1/ are never installed.
# Does not modify public ABI or Fabric/NRW1 contracts.
if(NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
    set(_ninlil_rrmp_prod_srcs
        ${NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES}
        ${NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES}
        ${NINLIL_RRMP_HOST_SIM_RELATIVE_SOURCES}
    )
    # ESP/task-path set: same as ports/esp-idf RRMP list (no host-only sim).
    set(_ninlil_rrmp_frame_gated_srcs
        ${NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES}
    )
    target_sources(ninlil_runtime_private PRIVATE ${_ninlil_rrmp_prod_srcs})
    target_compile_definitions(ninlil_runtime_private PRIVATE
        NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1)
    target_include_directories(ninlil_runtime_private PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/route_relay_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix)
    # Fabric select hook needs rrmp headers when both candidates are ON.
    if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
        target_include_directories(ninlil_runtime_private PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/route_relay_v1)
    endif()
    # ESP/host stack budget: no 4 KiB page copies on task stacks (do not raise).
    # Match ports/esp-idf RRMP -Wframe-larger-than=2048 (sim is host-test-only).
    # ASan/UBSan inflate frames (redzones) and rewrite .su kind — same as N6:
    # skip -Wframe-larger-than when _ninlil_any_sanitizer_active. Do not key off
    # CMAKE_C_FLAGS alone (sanitizers are add_compile_options, not C_FLAGS).
    # Authoritative stack evidence: non-sanitize host .su + ESP frame gate.
    if(NOT _ninlil_any_sanitizer_active)
        include(CheckCCompilerFlag)
        check_c_compiler_flag(-Wframe-larger-than=2048 NINLIL_RRMP_HAS_WFRAME_2048)
        if(NINLIL_RRMP_HAS_WFRAME_2048)
            # Host strict builds already use -Werror; do not use -Werror=frame-larger-than=
            # (unsupported spelling on AppleClang).
            set_source_files_properties(${_ninlil_rrmp_frame_gated_srcs} PROPERTIES
                COMPILE_OPTIONS "-Wframe-larger-than=2048;-fstack-usage"
            )
        endif()
    else()
        message(STATUS
            "RRMP host frame gate (-Wframe-larger-than=2048) skipped under "
            "active sanitizer; use non-sanitize .su / ESP gate as stack authority")
    endif()
endif()

# Private MFDT V1 (ADR-0021). Default-OFF.
# OSS boundary: MFDT sources/symbols land ONLY on ninlil_runtime_private
# (never installed). Headers under src/runtime/mfdt_v1/ never installed.
# Installable ninlil_runtime stays free of private MFDT symbols (see gate).
if(NINLIL_ENABLE_MFDT_V1_PRIVATE)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_mfdt_v1_sources.cmake)
    foreach(_mfdt_rel IN LISTS NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES)
        target_sources(ninlil_runtime_private PRIVATE ${_mfdt_rel})
    endforeach()
    target_compile_definitions(ninlil_runtime_private PRIVATE
        NINLIL_MFDT_V1_PRIVATE=1)
    target_include_directories(ninlil_runtime_private PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1)
endif()

# Private Wi-Fi Host candidate (ADR-0018). Standalone static library; not installed.
# Uses OpenSSL::SSL for TLS1.3 mutual auth. Does not modify Core/Fabric sources.
if(NINLIL_ENABLE_PRIVATE_WIFI_V1)
    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "NINLIL_ENABLE_PRIVATE_WIFI_V1 requires OpenSSL 3 Host crypto "
            "(top-level build or NINLIL_BUILD_HOST_RUNTIME/TESTS)")
    endif()
    find_package(OpenSSL 3 REQUIRED COMPONENTS SSL Crypto)
    set(_ninlil_wifi_v1_srcs
        src/transport/wifi_v1/wifi_nwb1.c
        src/transport/wifi_v1/wifi_nfl1_min.c
        src/transport/wifi_v1/wifi_stream.c
        src/transport/wifi_v1/wifi_queues.c
        src/transport/wifi_v1/wifi_tls_arena.c
        src/transport/wifi_v1/wifi_tls_resource_policy.c
        src/transport/wifi_v1/wifi_sha256_host.c
        src/transport/wifi_v1/wifi_tcp_posix.c
        src/transport/wifi_v1/wifi_tls_host.c
        src/transport/wifi_v1/wifi_tls_export.c
        src/transport/wifi_v1/wifi_storage_cu.c
        src/transport/wifi_v1/wifi_credentials.c
        src/transport/wifi_v1/wifi_journal.c
        src/transport/wifi_v1/wifi_reconnect.c
        src/transport/wifi_v1/wifi_attachment_m4.c
        src/transport/wifi_v1/wifi_tls_leaf_binding.c
        src/transport/wifi_v1/wifi_session.c
        src/transport/wifi_v1/wifi_fabric_adapter.c
        src/transport/wifi_v1/wifi_esp_tcp.c
        src/transport/wifi_v1/wifi_esp_tls_mbedtls.c
        src/transport/wifi_v1/wifi_esp_sta.c
        src/transport/wifi_v1/wifi_esp_owner.c
    )
    if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
        list(APPEND _ninlil_wifi_v1_srcs
            src/transport/wifi_v1/wifi_fabric_link_ops.c
            src/transport/wifi_v1/wifi_esp_fabric_link_ops.c
            src/transport/wifi_v1/wifi_adapter_v1.c)
    endif()
    add_library(ninlil_wifi_v1_private STATIC EXCLUDE_FROM_ALL
        ${_ninlil_wifi_v1_srcs}
    )
    # A matching version string alone is never authority.  Authority requires
    # exact static archives under the hermetic root; the release archive/hash,
    # final link closure, and isolated libctx are independently gated in CI.
    if(NINLIL_WIFI_OPENSSL_AUTHORITY)
        if(NOT DEFINED OPENSSL_VERSION
                OR NOT OPENSSL_VERSION VERSION_EQUAL "3.5.7")
            message(FATAL_ERROR
                "Wi-Fi Host authority requires OpenSSL exact 3.5.7 "
                "(found '${OPENSSL_VERSION}')")
        endif()
        foreach(_pair IN ITEMS
                "OPENSSL_SSL_LIBRARY;${OPENSSL_SSL_LIBRARY}"
                "OPENSSL_CRYPTO_LIBRARY;${OPENSSL_CRYPTO_LIBRARY}")
            list(GET _pair 0 _name)
            list(GET _pair 1 _path)
            if(_path STREQUAL "" OR NOT EXISTS "${_path}")
                message(FATAL_ERROR "${_name} is missing for Wi-Fi authority")
            endif()
            file(REAL_PATH "${_path}" _real)
            string(FIND "${_real}"
                "${NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT}/" _under_root)
            if(NOT _under_root EQUAL 0 OR NOT _real MATCHES "\\.a$")
                message(FATAL_ERROR
                    "${_name} must be a static archive below the hermetic "
                    "root; got '${_real}'")
            endif()
        endforeach()
        file(REAL_PATH "${OPENSSL_INCLUDE_DIR}" _openssl_include_real)
        if(NOT _openssl_include_real STREQUAL
                "${NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT}/include")
            message(FATAL_ERROR
                "OPENSSL_INCLUDE_DIR escaped hermetic authority root: "
                "'${_openssl_include_real}'")
        endif()
        message(STATUS
            "wifi_v1 Host OpenSSL authority: exact 3.5.7 static "
            "root=${NINLIL_WIFI_OPENSSL_AUTHORITY_ROOT}")
        target_compile_definitions(ninlil_wifi_v1_private PUBLIC
            NINLIL_WIFI_HOST_OPENSSL_STATIC_AUTHORITY=1)
    else()
        message(WARNING
            "wifi_v1 Host build is non-authority (OpenSSL "
            "'${OPENSSL_VERSION}'). TLS init fails closed unless "
            "NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=ON (LAB only).")
        if(NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL)
            target_compile_definitions(ninlil_wifi_v1_private PUBLIC
                NINLIL_WIFI_ALLOW_UNPINNED_OPENSSL=1)
        endif()
    endif()
    set_property(TARGET ninlil_wifi_v1_private
        PROPERTY NINLIL_PRODUCTION_PRIVATE_ARTIFACT TRUE)
    target_include_directories(ninlil_wifi_v1_private PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src/transport/wifi_v1>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_compile_definitions(ninlil_wifi_v1_private PRIVATE
        NINLIL_ENABLE_PRIVATE_WIFI_V1=1)
    if(NINLIL_ENABLE_PRIVATE_FABRIC_V1)
        target_include_directories(ninlil_wifi_v1_private PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1)
        target_compile_definitions(ninlil_wifi_v1_private PRIVATE
            NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
    endif()
    # M4 owner registry: pthread mutex + OpenSSL DRBG (host).
    find_package(Threads REQUIRED)
    target_link_libraries(ninlil_wifi_v1_private PUBLIC Threads::Threads)
    target_link_libraries(ninlil_wifi_v1_private PUBLIC
        OpenSSL::SSL
        OpenSSL::Crypto
    )
    set_target_properties(ninlil_wifi_v1_private PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
    )
    ninlil_apply_strict_warnings(ninlil_wifi_v1_private)
    if(NINLIL_ENABLE_SANITIZERS AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU|AppleClang")
        target_compile_options(ninlil_wifi_v1_private PRIVATE
            -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(ninlil_wifi_v1_private PUBLIC
            -fsanitize=address,undefined)
    endif()
    # TSan instruments the library body itself when requested (non-Apple).
    if(NINLIL_ENABLE_TSAN AND CMAKE_C_COMPILER_ID MATCHES "Clang|GNU"
            AND NOT APPLE)
        target_compile_options(ninlil_wifi_v1_private PRIVATE
            -fsanitize=thread -fno-omit-frame-pointer)
        target_link_options(ninlil_wifi_v1_private PUBLIC
            -fsanitize=thread)
    endif()
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
    ${CMAKE_CURRENT_SOURCE_DIR}/drivers/sx126x
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
target_include_directories(ninlil_sx1262 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/ports/esp-idf/src
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
    # Actual ESP RX-chain frames: keep codec/hash/mapper automatic storage
    # below the task-safe ceiling and emit source-specific .su evidence.
    set(_ninlil_fabric_radio_stack_sources
        src/transport/fabric_v1/fabric_private_util.c
        src/transport/fabric_v1/nfl1_codec.c
        src/transport/fabric_v1/v1_lab_radio_mapping.c
    )
    foreach(_fabric_radio_src IN LISTS _ninlil_fabric_radio_stack_sources)
        set(_fabric_radio_compile_opts -fstack-usage)
        if(NOT _ninlil_any_sanitizer_active)
            list(APPEND _fabric_radio_compile_opts -Wframe-larger-than=2048)
        endif()
        if(_ninlil_maccumulate_outgoing_args)
            list(APPEND _fabric_radio_compile_opts -maccumulate-outgoing-args)
        endif()
        set_property(
            SOURCE ${_fabric_radio_src}
            APPEND PROPERTY COMPILE_OPTIONS ${_fabric_radio_compile_opts}
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

# Installable Host Runtime. It compiles the public Host source authority plus
# the Host OpenSSL 3 adapter. It intentionally receives no LAB, simulator,
# physical-radio edge, mutable private-source append, or test definition.
set(NINLIL_HOST_RUNTIME_ENABLED FALSE)
if(NINLIL_BUILD_HOST_RUNTIME)
    if(NOT NINLIL_R7_HOST_CRYPTO_ENABLED)
        message(FATAL_ERROR
            "NINLIL_BUILD_HOST_RUNTIME requires the OpenSSL 3 Host adapter")
    endif()
    foreach(_ninlil_host_runtime_source IN LISTS
            NINLIL_HOST_RUNTIME_RELATIVE_SOURCES)
        if(_ninlil_host_runtime_source MATCHES
           "(^|/)(tests?|examples?|simulator|v1_lab|[^/]*_lab_|pcp_lab|sx1262|mfdt_v1|route_relay_v1|wifi_v1|r7_frag|n6_)(/|[^/]*$)")
            message(FATAL_ERROR
                "installable Host Runtime source authority contains a "
                "LAB/simulator/private-candidate/physical-radio source: "
                "${_ninlil_host_runtime_source}")
        endif()
    endforeach()
    add_library(ninlil_runtime STATIC
        ${NINLIL_HOST_RUNTIME_RELATIVE_SOURCES}
        ${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}
    )
    add_library(Ninlil::runtime ALIAS ninlil_runtime)
    target_include_directories(ninlil_runtime PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    )
    # When Domain schema1 is enabled, the installed public Host Runtime must
    # expose the same Domain-backed create/register/restore symbols as the
    # private gate target. Default remains OFF; OFF builds keep zero Domain
    # symbols in the installed archive.
    if(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
        target_sources(ninlil_runtime PRIVATE
            src/model/domain_schema1_runtime_binding.c
            src/model/domain_schema1_startup_authority.c
            src/runtime/domain_schema1_startup_owner.c
            src/runtime/domain_schema1_kind1_register.c)
        target_compile_definitions(ninlil_runtime PRIVATE
            NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
    endif()
    # MFDT is private-only: never append to installable ninlil_runtime.
    # Enable path is ninlil_runtime_private above (NINLIL_ENABLE_MFDT_V1_PRIVATE).
    target_link_libraries(ninlil_runtime
        PUBLIC
            ninlil
            OpenSSL::Crypto
    )
    if(TARGET ninlil_fabric_v1)
        target_sources(ninlil_runtime PRIVATE
            ${NINLIL_COMPOSITION_V1_RELATIVE_SOURCES})
        target_link_libraries(ninlil_runtime PUBLIC ninlil_fabric_v1)
    endif()
    set_target_properties(ninlil_runtime PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        EXPORT_NAME runtime
    )
    ninlil_apply_strict_warnings(ninlil_runtime)
    ninlil_apply_installed_archive_path_remap(ninlil_runtime)
    if(NINLIL_ENABLE_SANITIZERS)
        target_link_options(ninlil_runtime INTERFACE
            -fsanitize=address,undefined)
    endif()
    install(TARGETS ninlil_runtime
        EXPORT NinlilTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    set(NINLIL_HOST_RUNTIME_ENABLED TRUE)
endif()

# ADR-0031 Host reference byte-stream port. PTY tests prove the software path;
# physical Linux/macOS USB CDC HIL remains separate evidence.
if(NINLIL_POSIX_USB_SERIAL_ENABLED)
    add_library(ninlil_posix_usb_serial STATIC
        ports/posix/usb_serial/ninlil_posix_usb_serial.c
    )
    add_library(Ninlil::posix_usb_serial_v1 ALIAS ninlil_posix_usb_serial)
    target_include_directories(ninlil_posix_usb_serial
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/usb_serial
    )
    set_target_properties(ninlil_posix_usb_serial PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
        POSITION_INDEPENDENT_CODE ON
        C_VISIBILITY_PRESET hidden
        EXPORT_NAME posix_usb_serial_v1
    )
    ninlil_apply_posix_usb_serial_feature_macros(ninlil_posix_usb_serial)
    ninlil_apply_strict_warnings(ninlil_posix_usb_serial)
    # pthread for owner-thread fencing; util only needed by tests (openpty).
    find_package(Threads REQUIRED)
    target_link_libraries(ninlil_posix_usb_serial PUBLIC Threads::Threads)
    ninlil_apply_installed_archive_path_remap(ninlil_posix_usb_serial)
    if(NINLIL_ENABLE_SANITIZERS)
        target_link_options(ninlil_posix_usb_serial INTERFACE
            -fsanitize=address,undefined)
    endif()
    install(TARGETS ninlil_posix_usb_serial
        EXPORT NinlilTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
    message(STATUS
        "POSIX USB serial v1 reference port: enabled (Linux/macOS software path)")
endif()

if(NINLIL_BUILD_V1_LAB_CONTROLLER)
    if(NOT (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux"))
        message(FATAL_ERROR
            "NINLIL_BUILD_V1_LAB_CONTROLLER supports Linux and macOS only")
    endif()
    if(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
        message(FATAL_ERROR
            "NINLIL_BUILD_V1_LAB_CONTROLLER requires "
            "NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=OFF")
    endif()
    foreach(_ninlil_controller_dependency IN ITEMS
            ninlil_runtime
            ninlil_fabric_v1
            ninlil_posix_sqlite_storage
            ninlil_posix_usb_serial)
        if(NOT TARGET ${_ninlil_controller_dependency})
            message(FATAL_ERROR
                "NINLIL_BUILD_V1_LAB_CONTROLLER requires target "
                "${_ninlil_controller_dependency}")
        endif()
    endforeach()
    add_executable(ninlil_v1_lab_controller
        examples/v1_lab/v1_lab_controller.c
        examples/v1_lab/v1_lab_controller_platform.c
        src/transport/fabric_v1/v1_usb_fabric_link.c
    )
    target_include_directories(ninlil_v1_lab_controller PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/v1_lab
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport
        ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1
    )
    target_link_libraries(ninlil_v1_lab_controller PRIVATE
        ninlil_runtime
        ninlil_fabric_v1
        ninlil_posix_sqlite_storage
        ninlil_posix_usb_serial
        ninlil
        OpenSSL::Crypto
        Threads::Threads
    )
    set_target_properties(ninlil_v1_lab_controller PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    ninlil_apply_posix_host_feature_macros(ninlil_v1_lab_controller)
    ninlil_apply_strict_warnings(ninlil_v1_lab_controller)
endif()

# Generate the package only after all optional exported targets are known.
set(NINLIL_CONFIG_HAS_HOST_RUNTIME ${NINLIL_HOST_RUNTIME_ENABLED})
set(NINLIL_CONFIG_HAS_POSIX_TLS_V1 ${NINLIL_BUILD_POSIX_TLS_V1})
set(NINLIL_CONFIG_HAS_POSIX_USB_SERIAL_V1
    ${NINLIL_POSIX_USB_SERIAL_ENABLED})
set(NINLIL_CONFIG_HAS_POSIX_SQLITE
    ${NINLIL_POSIX_SQLITE_STORAGE_ENABLED})
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/NinlilConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Ninlil)
if(PROJECT_VERSION_MAJOR EQUAL 0)
    # Ninlil's 0.x policy permits a breaking change at every minor release.
    set(NINLIL_PACKAGE_VERSION_COMPATIBILITY SameMinorVersion)
else()
    set(NINLIL_PACKAGE_VERSION_COMPATIBILITY SameMajorVersion)
endif()
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY ${NINLIL_PACKAGE_VERSION_COMPATIBILITY})
install(EXPORT NinlilTargets
    FILE NinlilTargets.cmake
    NAMESPACE Ninlil::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Ninlil)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/NinlilConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/Ninlil)

if(NINLIL_BUILD_TESTS)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_ctest.cmake)
endif()
