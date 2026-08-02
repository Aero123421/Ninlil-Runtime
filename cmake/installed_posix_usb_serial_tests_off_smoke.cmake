# Fresh tests-OFF install and public-only PTY consumer for ADR-0031.
if(NOT DEFINED NINLIL_SOURCE_DIR
   OR NOT DEFINED NINLIL_PARENT_BUILD_DIR
   OR NOT DEFINED NINLIL_GENERATOR
   OR NOT DEFINED NINLIL_CTEST_COMMAND)
    message(FATAL_ERROR
        "installed POSIX USB serial smoke requires source/build/generator/ctest")
endif()
if(NOT DEFINED NINLIL_SMOKE_ENABLE_SANITIZERS)
    set(NINLIL_SMOKE_ENABLE_SANITIZERS OFF)
endif()
set(_compiler_args)
if(DEFINED NINLIL_SMOKE_C_COMPILER
   AND NOT NINLIL_SMOKE_C_COMPILER STREQUAL "")
    list(APPEND _compiler_args
        "-DCMAKE_C_COMPILER=${NINLIL_SMOKE_C_COMPILER}")
endif()
if(DEFINED NINLIL_SMOKE_CXX_COMPILER
   AND NOT NINLIL_SMOKE_CXX_COMPILER STREQUAL "")
    list(APPEND _compiler_args
        "-DCMAKE_CXX_COMPILER=${NINLIL_SMOKE_CXX_COMPILER}")
endif()

get_filename_component(NINLIL_PARENT_BUILD_DIR
    "${NINLIL_PARENT_BUILD_DIR}" ABSOLUTE BASE_DIR "${NINLIL_SOURCE_DIR}")
set(_work "${NINLIL_PARENT_BUILD_DIR}/installed-posix-usb-serial-tests-off")
set(_producer "${_work}/producer")
set(_prefix "${_work}/prefix")
set(_consumer "${_work}/consumer")
file(REMOVE_RECURSE "${_work}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -S "${NINLIL_SOURCE_DIR}"
        -B "${_producer}"
        -G "${NINLIL_GENERATOR}"
        ${_compiler_args}
        -DCMAKE_BUILD_TYPE=Release
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_BUILD_HOST_RUNTIME=OFF
        -DNINLIL_BUILD_FABRIC_V1=OFF
        -DNINLIL_BUILD_POSIX_TLS_V1=OFF
        -DNINLIL_BUILD_POSIX_USB_SERIAL_V1=ON
        -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=OFF
        -DNINLIL_ENABLE_STRICT_WARNINGS=ON
        -DNINLIL_ENABLE_SANITIZERS=${NINLIL_SMOKE_ENABLE_SANITIZERS}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "producer configure failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${NINLIL_CTEST_COMMAND}" -N
    WORKING_DIRECTORY "${_producer}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0
   OR (NOT _out MATCHES "Total Tests:[ \t]*0"
       AND NOT _out MATCHES "No tests were found"))
    message(FATAL_ERROR "tests-OFF producer registered tests:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_producer}"
        --config Release --parallel
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "producer build failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${_producer}"
        --prefix "${_prefix}" --config Release
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "producer install failed:\n${_out}${_err}")
endif()

set(_public_header "${_prefix}/include/ninlil/posix_usb_serial_v1.h")
if(NOT EXISTS "${_public_header}")
    message(FATAL_ERROR "installed package lacks posix_usb_serial_v1.h")
endif()
file(GLOB_RECURSE _private_usb_headers
    "${_prefix}/include/*ninlil_posix_usb_serial.h")
if(_private_usb_headers)
    message(FATAL_ERROR
        "private POSIX USB serial header leaked: ${_private_usb_headers}")
endif()
file(READ "${_public_header}" _header_text)
foreach(_forbidden sys_ops set_sys_ops test_force_generation FORCE_FCNTL)
    string(FIND "${_header_text}" "${_forbidden}" _hit)
    if(NOT _hit EQUAL -1)
        message(FATAL_ERROR "public header leaks test seam '${_forbidden}'")
    endif()
endforeach()

set(_consumer_args
    -S "${NINLIL_SOURCE_DIR}/tests/cmake/installed_posix_usb_serial_consumer"
    -B "${_consumer}"
    -G "${NINLIL_GENERATOR}"
    ${_compiler_args}
    "-DCMAKE_PREFIX_PATH=${_prefix}"
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    -DNINLIL_CONSUMER_ENABLE_SANITIZERS=${NINLIL_SMOKE_ENABLE_SANITIZERS})
if(NINLIL_GENERATOR MATCHES "(Xcode|Visual Studio|Ninja Multi-Config)")
    set(_config Debug)
else()
    list(APPEND _consumer_args -DCMAKE_BUILD_TYPE=Debug)
    set(_config Debug)
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" ${_consumer_args}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "consumer configure failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_consumer}"
        --config "${_config}" --parallel
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "consumer build failed:\n${_out}${_err}")
endif()

file(READ "${_consumer}/compile_commands.json" _compile_graph)
foreach(_forbidden_path
        "${NINLIL_SOURCE_DIR}/include"
        "${NINLIL_SOURCE_DIR}/src"
        "${NINLIL_SOURCE_DIR}/ports"
        "${NINLIL_SOURCE_DIR}/tests/support"
        "${_producer}")
    string(FIND "${_compile_graph}" "${_forbidden_path}" _hit)
    if(NOT _hit EQUAL -1)
        message(FATAL_ERROR
            "installed consumer leaks source/private path '${_forbidden_path}'")
    endif()
endforeach()

set(_binary "${_consumer}/ninlil_installed_posix_usb_serial_consumer")
if(NOT EXISTS "${_binary}")
    set(_binary
        "${_consumer}/${_config}/ninlil_installed_posix_usb_serial_consumer")
endif()
if(NOT EXISTS "${_binary}")
    message(FATAL_ERROR "installed consumer binary was not built")
endif()
set(_run_command "${_binary}")
if(NINLIL_SMOKE_ENABLE_SANITIZERS)
    set(_asan "halt_on_error=1")
    if(CMAKE_HOST_APPLE)
        string(APPEND _asan ":detect_leaks=0")
    endif()
    set(_run_command "${CMAKE_COMMAND}" -E env
        "ASAN_OPTIONS=${_asan}"
        "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"
        "${_binary}")
endif()
execute_process(
    COMMAND ${_run_command}
    TIMEOUT 30
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "installed PTY consumer failed:\n${_out}${_err}")
endif()
if(NOT _out MATCHES
   "posix_usb_serial_v1_installed_consumer: PASS bidirectional=1 reopen=1 generation=1")
    message(FATAL_ERROR "installed consumer evidence is incomplete:\n${_out}")
endif()

file(REMOVE_RECURSE "${_work}")
message(STATUS
    "installed POSIX USB serial tests-OFF consumer: OK (PTY software path)")
