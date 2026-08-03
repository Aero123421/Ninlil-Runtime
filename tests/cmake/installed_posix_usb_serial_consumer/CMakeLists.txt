cmake_minimum_required(VERSION 3.20)

project(ninlil_installed_posix_usb_serial_consumer LANGUAGES C)

option(NINLIL_CONSUMER_ENABLE_SANITIZERS
    "Instrument the installed-package consumer with ASan/UBSan" OFF)

find_package(Ninlil CONFIG REQUIRED)
if(NOT TARGET Ninlil::posix_usb_serial_v1)
    message(FATAL_ERROR
        "installed package is missing Ninlil::posix_usb_serial_v1")
endif()

add_executable(ninlil_installed_posix_usb_serial_consumer consumer.c)
target_link_libraries(ninlil_installed_posix_usb_serial_consumer PRIVATE
    Ninlil::posix_usb_serial_v1)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(ninlil_installed_posix_usb_serial_consumer PRIVATE util)
endif()
set_target_properties(ninlil_installed_posix_usb_serial_consumer PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    target_compile_options(ninlil_installed_posix_usb_serial_consumer PRIVATE
        -Wall -Wextra -Werror -Wpedantic -pedantic-errors)
endif()
if(NINLIL_CONSUMER_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
        message(FATAL_ERROR "sanitizers require GNU, Clang, or AppleClang")
    endif()
    target_compile_options(ninlil_installed_posix_usb_serial_consumer PRIVATE
        -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(ninlil_installed_posix_usb_serial_consumer PRIVATE
        -fsanitize=address,undefined)
endif()
