cmake_minimum_required(VERSION 3.16)
project(ninlil_installed_posix_sqlite_consumer LANGUAGES C)

option(NINLIL_CONSUMER_ENABLE_SANITIZERS
    "Link a consumer against a sanitizer-instrumented installed archive" OFF)
option(NINLIL_CONSUMER_EXPECT_STATIC_SQLITE
    "Require the consumer to link a static libsqlite3.a (no .so NEEDED)" OFF)
set(NINLIL_CONSUMER_SQLITE3_LIBRARY "" CACHE FILEPATH
    "Forced SQLite3 library path for static false-green prevention")

if(NINLIL_CONSUMER_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        message(FATAL_ERROR "consumer sanitizer smoke requires GNU/Clang")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

# When the producer built against a specific archive, force FindSQLite3 to the
# same path before find_package(Ninlil) pulls find_dependency(SQLite3).
if(NINLIL_CONSUMER_SQLITE3_LIBRARY)
    if(NOT EXISTS "${NINLIL_CONSUMER_SQLITE3_LIBRARY}")
        message(FATAL_ERROR
            "NINLIL_CONSUMER_SQLITE3_LIBRARY does not exist: "
            "${NINLIL_CONSUMER_SQLITE3_LIBRARY}")
    endif()
    set(SQLite3_LIBRARY "${NINLIL_CONSUMER_SQLITE3_LIBRARY}" CACHE FILEPATH
        "SQLite3 library" FORCE)
    set(SQLite3_LIBRARIES "${NINLIL_CONSUMER_SQLITE3_LIBRARY}" CACHE STRING
        "SQLite3 libraries" FORCE)
endif()
if(DEFINED SQLite3_INCLUDE_DIR AND SQLite3_INCLUDE_DIR)
    set(SQLite3_INCLUDE_DIRS "${SQLite3_INCLUDE_DIR}" CACHE PATH
        "SQLite3 includes" FORCE)
endif()

find_package(Ninlil CONFIG REQUIRED)

add_executable(ninlil_installed_posix_sqlite_consumer consumer.c)
target_link_libraries(ninlil_installed_posix_sqlite_consumer PRIVATE
    Ninlil::ninlil_posix_sqlite_storage)
set_target_properties(ninlil_installed_posix_sqlite_consumer PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF)
if(APPLE)
    target_compile_definitions(ninlil_installed_posix_sqlite_consumer PRIVATE
        _DARWIN_C_SOURCE)
else()
    target_compile_definitions(ninlil_installed_posix_sqlite_consumer PRIVATE
        _XOPEN_SOURCE=700
        _DEFAULT_SOURCE)
endif()

if(NINLIL_CONSUMER_EXPECT_STATIC_SQLITE)
    if(NOT NINLIL_CONSUMER_SQLITE3_LIBRARY)
        message(FATAL_ERROR
            "NINLIL_CONSUMER_EXPECT_STATIC_SQLITE requires "
            "NINLIL_CONSUMER_SQLITE3_LIBRARY to pin libsqlite3.a")
    endif()
    if(NOT NINLIL_CONSUMER_SQLITE3_LIBRARY MATCHES "\\.(a|lib)$"
       AND NOT NINLIL_CONSUMER_SQLITE3_LIBRARY MATCHES "libsqlite3\\.a")
        # Still allow opaque operator-forced archives under STATIC producer.
        message(STATUS
            "static consumer using forced SQLite path "
            "'${NINLIL_CONSUMER_SQLITE3_LIBRARY}'")
    endif()
    # Prefer the forced archive ahead of any IMPORTED shared SQLite3 target.
    target_link_libraries(ninlil_installed_posix_sqlite_consumer PRIVATE
        "${NINLIL_CONSUMER_SQLITE3_LIBRARY}")
    message(STATUS
        "installed consumer pinned to static SQLite: "
        "${NINLIL_CONSUMER_SQLITE3_LIBRARY}")
endif()

enable_testing()
add_test(NAME installed_posix_sqlite_consumer_runs
    COMMAND ninlil_installed_posix_sqlite_consumer)
