# Fresh tests-OFF install and public Runtime/Fabric/POSIX TLS restart E2E.
if(NOT DEFINED NINLIL_SOURCE_DIR
   OR NOT DEFINED NINLIL_PARENT_BUILD_DIR
   OR NOT DEFINED NINLIL_GENERATOR
   OR NOT DEFINED NINLIL_CTEST_COMMAND)
    message(FATAL_ERROR
        "installed POSIX TLS Runtime E2E requires source/build/generator/ctest")
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
set(_work "${NINLIL_PARENT_BUILD_DIR}/installed-posix-tls-runtime-e2e")
set(_producer "${_work}/producer")
set(_prefix "${_work}/prefix")
set(_consumer "${_work}/consumer")
set(_e2e_work "${_work}/run")
file(REMOVE_RECURSE "${_work}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -S "${NINLIL_SOURCE_DIR}"
        -B "${_producer}"
        -G "${NINLIL_GENERATOR}"
        ${_compiler_args}
        -DCMAKE_BUILD_TYPE=Release
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_BUILD_HOST_RUNTIME=ON
        -DNINLIL_BUILD_FABRIC_V1=ON
        -DNINLIL_BUILD_POSIX_TLS_V1=ON
        -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=ON
        -DNINLIL_ENABLE_STRICT_WARNINGS=ON
        -DNINLIL_ENABLE_SANITIZERS=${NINLIL_SMOKE_ENABLE_SANITIZERS}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "POSIX TLS E2E producer configure failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${NINLIL_CTEST_COMMAND}" -N
    WORKING_DIRECTORY "${_producer}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0
   OR (NOT _out MATCHES "Total Tests:[ \t]*0"
       AND NOT _out MATCHES "No tests were found"))
    message(FATAL_ERROR
        "POSIX TLS E2E tests-OFF producer registered tests:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_producer}"
        --config Release --parallel
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "POSIX TLS E2E producer build failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${_producer}"
        --prefix "${_prefix}" --config Release
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "POSIX TLS E2E install failed:\n${_out}${_err}")
endif()

foreach(_header
        ninlil/runtime.h
        ninlil/fabric_v1.h
        ninlil/posix_tls_v1.h
        ninlil_posix_sqlite_storage.h)
    if(NOT EXISTS "${_prefix}/include/${_header}")
        message(FATAL_ERROR "installed package lacks ${_header}")
    endif()
endforeach()
file(GLOB_RECURSE _private_headers
    "${_prefix}/*fabric_private*"
    "${_prefix}/*posix_tls_v1_internal*"
    "${_prefix}/*test_hook*")
if(_private_headers)
    message(FATAL_ERROR "private/test headers leaked: ${_private_headers}")
endif()

set(_consumer_source
    "${NINLIL_SOURCE_DIR}/tests/cmake/installed_posix_tls_runtime_e2e_consumer/consumer.c")
file(READ "${_consumer_source}" _consumer_text)
foreach(_required
        "ninlil_runtime_create("
        "ninlil_fabric_v1_create("
        "ninlil_posix_tls_v1_create("
        "ninlil_submit("
        "ninlil_transaction_query("
        "ninlil_runtime_step("
        "ninlil_posix_tls_v1_unregister_begin("
        "ninlil_runtime_destroy(")
    string(FIND "${_consumer_text}" "${_required}" _hit)
    if(_hit EQUAL -1)
        message(FATAL_ERROR
            "installed POSIX TLS consumer lacks '${_required}'")
    endif()
endforeach()
foreach(_forbidden
        "fabric_private"
        "posix_tls_v1_internal"
        "NINLIL_POSIX_TLS_V1_TEST_HOOKS"
        "tests/support"
        "socket("
        "connect(")
    string(FIND "${_consumer_text}" "${_forbidden}" _hit)
    if(NOT _hit EQUAL -1)
        message(FATAL_ERROR
            "installed POSIX TLS consumer uses forbidden '${_forbidden}'")
    endif()
endforeach()

set(_consumer_args
    -S "${NINLIL_SOURCE_DIR}/tests/cmake/installed_posix_tls_runtime_e2e_consumer"
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
    message(FATAL_ERROR
        "POSIX TLS E2E consumer configure failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_consumer}"
        --config "${_config}" --parallel
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "POSIX TLS E2E consumer build failed:\n${_out}${_err}")
endif()

file(READ "${_consumer}/compile_commands.json" _compile_graph)
foreach(_forbidden_path
        "${NINLIL_SOURCE_DIR}/include"
        "${NINLIL_SOURCE_DIR}/src"
        "${NINLIL_SOURCE_DIR}/tests/support"
        "${_producer}")
    string(FIND "${_compile_graph}" "${_forbidden_path}" _hit)
    if(NOT _hit EQUAL -1)
        message(FATAL_ERROR
            "installed consumer leaks source/private path '${_forbidden_path}'")
    endif()
endforeach()

set(_consumer_binary
    "${_consumer}/ninlil_installed_posix_tls_runtime_e2e_consumer")
if(NOT EXISTS "${_consumer_binary}")
    set(_consumer_binary
        "${_consumer}/${_config}/ninlil_installed_posix_tls_runtime_e2e_consumer")
endif()
if(NOT EXISTS "${_consumer_binary}")
    message(FATAL_ERROR "installed POSIX TLS consumer binary was not built")
endif()
find_program(_bash NAMES bash REQUIRED)
set(_run_command
    "${_bash}"
    "${NINLIL_SOURCE_DIR}/tools/posix_tls_v1_run_runtime_e2e.sh"
    "${_consumer_binary}"
    "${NINLIL_SOURCE_DIR}"
    "${_e2e_work}")
if(NINLIL_SMOKE_ENABLE_SANITIZERS)
    set(_asan "halt_on_error=1")
    if(CMAKE_HOST_APPLE)
        string(APPEND _asan ":detect_leaks=0")
    endif()
    set(_run_command "${CMAKE_COMMAND}" -E env
        "ASAN_OPTIONS=${_asan}"
        "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"
        ${_run_command})
endif()
execute_process(
    COMMAND ${_run_command}
    TIMEOUT 180
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "installed POSIX TLS Runtime restart E2E failed:\n${_out}${_err}\n"
        "artifacts: ${_e2e_work}")
endif()
if(NOT _out MATCHES
   "posix_tls_v1_runtime_e2e: PASS processes=2 rounds=2 sqlite_reuse=1")
    message(FATAL_ERROR "POSIX TLS E2E success evidence is incomplete:\n${_out}")
endif()

file(REMOVE_RECURSE "${_work}")
message(STATUS
    "installed POSIX TLS Runtime tests-OFF E2E: OK "
    "(two processes; real TLS; verified Receipt; clean SQLite restart)")
