cmake_minimum_required(VERSION 3.20)

project(ninlil_installed_posix_tls_runtime_e2e_consumer LANGUAGES C)

option(NINLIL_CONSUMER_ENABLE_SANITIZERS
    "Instrument the installed-package E2E consumer with ASan/UBSan" OFF)

if(NINLIL_CONSUMER_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        message(FATAL_ERROR
            "installed consumer sanitizers require GNU, Clang, or AppleClang")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

find_package(Ninlil CONFIG REQUIRED)
find_package(OpenSSL 3 REQUIRED COMPONENTS SSL Crypto)

foreach(_required_target
        Ninlil::runtime
        Ninlil::fabric_v1
        Ninlil::posix_tls_v1
        Ninlil::ninlil_posix_sqlite_storage)
    if(NOT TARGET ${_required_target})
        message(FATAL_ERROR "installed package is missing '${_required_target}'")
    endif()
    get_target_property(_is_imported ${_required_target} IMPORTED)
    if(NOT _is_imported)
        message(FATAL_ERROR "'${_required_target}' is not imported")
    endif()
endforeach()

add_executable(ninlil_installed_posix_tls_runtime_e2e_consumer consumer.c)
target_link_libraries(ninlil_installed_posix_tls_runtime_e2e_consumer PRIVATE
    Ninlil::runtime
    Ninlil::fabric_v1
    Ninlil::posix_tls_v1
    Ninlil::ninlil_posix_sqlite_storage
    OpenSSL::Crypto)
set_target_properties(ninlil_installed_posix_tls_runtime_e2e_consumer PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    target_compile_options(ninlil_installed_posix_tls_runtime_e2e_consumer PRIVATE
        -Wall -Wextra -Werror -Wpedantic -pedantic-errors)
endif()
