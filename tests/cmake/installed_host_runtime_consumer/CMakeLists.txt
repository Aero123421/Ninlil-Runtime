# Repository and installed-package consumers share one supported CMake floor.
cmake_minimum_required(VERSION 3.20)

project(ninlil_installed_host_runtime_consumer LANGUAGES C)

option(NINLIL_CONSUMER_EXPECT_SQLITE
    "Also exercise the optional installed POSIX SQLite target" OFF)

find_package(Ninlil CONFIG REQUIRED)

foreach(_required_target
        Ninlil::ninlil
        Ninlil::runtime)
    if(NOT TARGET ${_required_target})
        message(FATAL_ERROR
            "installed package is missing required target '${_required_target}'")
    endif()
endforeach()

add_executable(ninlil_installed_host_runtime_consumer
    consumer.c
    memory_storage.c
)
target_link_libraries(ninlil_installed_host_runtime_consumer PRIVATE
    Ninlil::runtime
)
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

if(NINLIL_CONSUMER_EXPECT_SQLITE)
    if(NOT TARGET Ninlil::ninlil_posix_sqlite_storage)
        message(FATAL_ERROR
            "SQLite-enabled package is missing "
            "'Ninlil::ninlil_posix_sqlite_storage'")
    endif()
    add_executable(ninlil_installed_host_runtime_sqlite_consumer
        consumer.c
    )
    target_compile_definitions(
        ninlil_installed_host_runtime_sqlite_consumer
        PRIVATE NINLIL_CONSUMER_WITH_SQLITE=1
    )
    target_link_libraries(
        ninlil_installed_host_runtime_sqlite_consumer PRIVATE
        Ninlil::runtime
        Ninlil::ninlil_posix_sqlite_storage
    )
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
