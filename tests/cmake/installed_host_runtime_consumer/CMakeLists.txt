# Repository and installed-package consumers share one supported CMake floor.
cmake_minimum_required(VERSION 3.20)

project(ninlil_installed_host_runtime_consumer LANGUAGES C CXX)

option(NINLIL_CONSUMER_EXPECT_SQLITE
    "Also exercise the optional installed POSIX SQLite target" OFF)
option(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY
    "Expect feature-ON public Runtime create to fail closed" OFF)
option(NINLIL_CONSUMER_ENABLE_SANITIZERS
    "Instrument the clean installed-package consumer with ASan/UBSan" OFF)

if(NINLIL_CONSUMER_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$"
       OR NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        message(FATAL_ERROR
            "installed consumer sanitizers require GNU, Clang, or AppleClang")
    endif()
    add_compile_options(
        -fsanitize=address,undefined
        -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

find_package(Ninlil CONFIG REQUIRED)

foreach(_required_target
        Ninlil::ninlil
        Ninlil::runtime)
    if(NOT TARGET ${_required_target})
        message(FATAL_ERROR
            "installed package is missing required target '${_required_target}'")
    endif()
    get_target_property(_required_target_imported
        ${_required_target} IMPORTED)
    if(NOT _required_target_imported)
        message(FATAL_ERROR
            "consumer must use imported installed target "
            "'${_required_target}', not a source-tree target")
    endif()
endforeach()

get_filename_component(_ninlil_source_root
    "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
foreach(_public_target Ninlil::ninlil Ninlil::runtime)
    get_target_property(_public_includes
        ${_public_target} INTERFACE_INCLUDE_DIRECTORIES)
    foreach(_public_include IN LISTS _public_includes)
        if(_public_include MATCHES
           "^${_ninlil_source_root}/(include|src|examples|tests/support)(/|$)")
            message(FATAL_ERROR
                "installed target '${_public_target}' leaks source-tree "
                "include path '${_public_include}'")
        endif()
    endforeach()
endforeach()

add_executable(ninlil_installed_host_runtime_consumer
    consumer.c
    memory_storage.c
)
target_link_libraries(ninlil_installed_host_runtime_consumer PRIVATE
    Ninlil::runtime
)
get_target_property(_memory_consumer_links
    ninlil_installed_host_runtime_consumer LINK_LIBRARIES)
if(NOT _memory_consumer_links STREQUAL "Ninlil::runtime")
    message(FATAL_ERROR
        "memory consumer direct link set must be exactly Ninlil::runtime, got "
        "'${_memory_consumer_links}'")
endif()
if(NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY)
    target_compile_definitions(
        ninlil_installed_host_runtime_consumer
        PRIVATE NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY=1
    )
endif()
set_target_properties(ninlil_installed_host_runtime_consumer PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    target_compile_options(ninlil_installed_host_runtime_consumer PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -pedantic-errors
    )
endif()

enable_testing()
add_test(NAME installed_host_runtime_memory_consumer_runs
    COMMAND ninlil_installed_host_runtime_consumer)

# Generate this tiny translation unit in the clean consumer build tree so the
# installed package itself, rather than source-tree include paths, proves the
# C++17 compile/link boundary and compatibility aliases.
set(_ninlil_installed_cxx_surface
    "${CMAKE_CURRENT_BINARY_DIR}/installed_public_surface.cpp")
file(WRITE "${_ninlil_installed_cxx_surface}" [=[
#include <ninlil/runtime.h>

static_assert(NINLIL_FOUNDATION_MAX_EXACT_TARGETS == 4u);
static_assert(NINLIL_ROLE_CONTROLLER == 1u);
static_assert(NINLIL_ROLE_ENDPOINT == 2u);
static_assert(NINLIL_ROLE_CELL_AGENT == 3u);
static_assert(NINLIL_ROLE_CELL_AGENT_RESERVED == NINLIL_ROLE_CELL_AGENT);
static_assert(NINLIL_ENV_TEST == 1u);
static_assert(NINLIL_ENV_LAB == 2u);
static_assert(NINLIL_ENV_FIELD == 3u);
static_assert(NINLIL_ENV_PRODUCTION == 4u);
static_assert(NINLIL_ENV_LAB_RESERVED == NINLIL_ENV_LAB);
static_assert(NINLIL_ENV_FIELD_RESERVED == NINLIL_ENV_FIELD);
static_assert(
    NINLIL_ENV_PRODUCTION_RESERVED == NINLIL_ENV_PRODUCTION);

int main()
{
    return ninlil_runtime_destroy(nullptr) == NINLIL_E_INVALID_ARGUMENT
        ? 0 : 1;
}
]=])
add_executable(
    ninlil_installed_host_runtime_cxx17_surface
    "${_ninlil_installed_cxx_surface}")
target_link_libraries(
    ninlil_installed_host_runtime_cxx17_surface PRIVATE
    Ninlil::runtime)
target_compile_features(
    ninlil_installed_host_runtime_cxx17_surface PRIVATE cxx_std_17)
set_target_properties(
    ninlil_installed_host_runtime_cxx17_surface PROPERTIES
    CXX_EXTENSIONS OFF)
if(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    target_compile_options(
        ninlil_installed_host_runtime_cxx17_surface PRIVATE
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -pedantic-errors)
endif()
add_test(
    NAME installed_host_runtime_cxx17_surface_runs
    COMMAND ninlil_installed_host_runtime_cxx17_surface)

if(NINLIL_CONSUMER_EXPECT_SQLITE)
    if(NOT TARGET Ninlil::ninlil_posix_sqlite_storage)
        message(FATAL_ERROR
            "SQLite-enabled package is missing "
            "'Ninlil::ninlil_posix_sqlite_storage'")
    endif()
    get_target_property(_sqlite_target_imported
        Ninlil::ninlil_posix_sqlite_storage IMPORTED)
    if(NOT _sqlite_target_imported)
        message(FATAL_ERROR
            "SQLite consumer must use the imported installed provider target")
    endif()
    add_executable(ninlil_installed_host_runtime_sqlite_consumer
        consumer.c
    )
    target_compile_definitions(
        ninlil_installed_host_runtime_sqlite_consumer
        PRIVATE
            NINLIL_CONSUMER_WITH_SQLITE=1
            $<$<BOOL:${NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY}>:
                NINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY=1>
    )
    target_link_libraries(
        ninlil_installed_host_runtime_sqlite_consumer PRIVATE
        Ninlil::runtime
        Ninlil::ninlil_posix_sqlite_storage
    )
    get_target_property(_sqlite_consumer_links
        ninlil_installed_host_runtime_sqlite_consumer LINK_LIBRARIES)
    if(NOT _sqlite_consumer_links STREQUAL
       "Ninlil::runtime;Ninlil::ninlil_posix_sqlite_storage")
        message(FATAL_ERROR
            "SQLite consumer direct link set must contain only installed "
            "Runtime and SQLite targets, got '${_sqlite_consumer_links}'")
    endif()
    set_target_properties(
        ninlil_installed_host_runtime_sqlite_consumer PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED ON
        C_EXTENSIONS OFF
    )
    if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        target_compile_options(
            ninlil_installed_host_runtime_sqlite_consumer PRIVATE
            -Wall
            -Wextra
            -Werror
            -Wpedantic
            -pedantic-errors
        )
    endif()
    add_test(NAME installed_host_runtime_sqlite_consumer_runs
        COMMAND ninlil_installed_host_runtime_sqlite_consumer
            "${CMAKE_CURRENT_BINARY_DIR}/installed-host-runtime.sqlite3"
    )
endif()
