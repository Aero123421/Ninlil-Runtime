cmake_minimum_required(VERSION 3.20)

project(ninlil_installed_fabric_v1_consumer LANGUAGES C)

option(NINLIL_CONSUMER_ENABLE_SANITIZERS
    "Instrument this clean installed-package consumer with ASan/UBSan" OFF)

if(NINLIL_CONSUMER_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        message(FATAL_ERROR
            "installed consumer sanitizers require GNU, Clang, or AppleClang")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

find_package(Ninlil CONFIG REQUIRED)

foreach(_required_target Ninlil::ninlil Ninlil::runtime Ninlil::fabric_v1)
    if(NOT TARGET ${_required_target})
        message(FATAL_ERROR
            "installed package is missing '${_required_target}'")
    endif()
    get_target_property(_is_imported ${_required_target} IMPORTED)
    if(NOT _is_imported)
        message(FATAL_ERROR "'${_required_target}' is not imported")
    endif()
endforeach()

get_filename_component(_ninlil_source_root
    "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
foreach(_public_target Ninlil::ninlil Ninlil::runtime Ninlil::fabric_v1)
    get_target_property(_public_includes
        ${_public_target} INTERFACE_INCLUDE_DIRECTORIES)
    foreach(_public_include IN LISTS _public_includes)
        if(_public_include MATCHES
           "^${_ninlil_source_root}/(include|src|examples|tests)(/|$)")
            message(FATAL_ERROR
                "installed target '${_public_target}' leaks source path "
                "'${_public_include}'")
        endif()
    endforeach()
endforeach()

add_executable(ninlil_installed_fabric_v1_consumer
    consumer.c
    direct_packet_link.c
    ../installed_host_runtime_consumer/memory_storage.c)
target_include_directories(ninlil_installed_fabric_v1_consumer PRIVATE
    ../installed_host_runtime_consumer)
target_link_libraries(ninlil_installed_fabric_v1_consumer PRIVATE
    Ninlil::runtime
    Ninlil::fabric_v1
    OpenSSL::Crypto)
set_target_properties(ninlil_installed_fabric_v1_consumer PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    target_compile_options(ninlil_installed_fabric_v1_consumer PRIVATE
        -Wall -Wextra -Werror -Wpedantic -pedantic-errors)
endif()

enable_testing()
add_test(NAME installed_fabric_v1_consumer_runs
    COMMAND ninlil_installed_fabric_v1_consumer)
