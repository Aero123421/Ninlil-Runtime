# Fresh tests-OFF install/export and two-instance public Fabric consumer gate.
if(NOT DEFINED NINLIL_SOURCE_DIR
   OR NOT DEFINED NINLIL_PARENT_BUILD_DIR
   OR NOT DEFINED NINLIL_GENERATOR
   OR NOT DEFINED NINLIL_CTEST_COMMAND)
    message(FATAL_ERROR
        "installed Fabric v1 smoke requires source/build/generator/ctest")
endif()
if(NOT DEFINED NINLIL_SMOKE_ENABLE_SANITIZERS)
    set(NINLIL_SMOKE_ENABLE_SANITIZERS OFF)
endif()

get_filename_component(NINLIL_PARENT_BUILD_DIR
    "${NINLIL_PARENT_BUILD_DIR}" ABSOLUTE BASE_DIR "${NINLIL_SOURCE_DIR}")
set(_work "${NINLIL_PARENT_BUILD_DIR}/installed-fabric-v1-tests-off")
set(_producer "${_work}/producer")
set(_prefix "${_work}/prefix")
set(_consumer "${_work}/consumer")
file(REMOVE_RECURSE "${_work}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -S "${NINLIL_SOURCE_DIR}"
        -B "${_producer}"
        -G "${NINLIL_GENERATOR}"
        -DCMAKE_BUILD_TYPE=Release
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_BUILD_HOST_RUNTIME=ON
        -DNINLIL_BUILD_FABRIC_V1=ON
        -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=OFF
        -DNINLIL_ENABLE_STRICT_WARNINGS=ON
        -DNINLIL_ENABLE_SANITIZERS=${NINLIL_SMOKE_ENABLE_SANITIZERS}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "Fabric producer configure failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${NINLIL_CTEST_COMMAND}" -N
    WORKING_DIRECTORY "${_producer}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0
   OR (NOT _out MATCHES "Total Tests:[ \t]*0"
       AND NOT _out MATCHES "No tests were found"))
    message(FATAL_ERROR "Fabric tests-OFF producer registered tests:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_producer}"
        --config Release --parallel
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "Fabric producer build failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${_producer}"
        --prefix "${_prefix}" --config Release
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "Fabric producer install failed:\n${_out}${_err}")
endif()

if(NOT EXISTS "${_prefix}/include/ninlil/fabric_v1.h")
    message(FATAL_ERROR "installed package lacks ninlil/fabric_v1.h")
endif()
file(GLOB_RECURSE _fabric_archives
    "${_prefix}/*ninlil_fabric_v1.a"
    "${_prefix}/*ninlil_fabric_v1.lib")
list(LENGTH _fabric_archives _archive_count)
if(NOT _archive_count EQUAL 1)
    message(FATAL_ERROR
        "installed Fabric archive count must be one: ${_fabric_archives}")
endif()
list(GET _fabric_archives 0 _fabric_archive)

file(GLOB_RECURSE _metadata "${_prefix}/*/cmake/Ninlil/*.cmake")
set(_metadata_text "")
foreach(_file IN LISTS _metadata)
    file(READ "${_file}" _text)
    string(APPEND _metadata_text "\n${_text}")
    foreach(_forbidden "${NINLIL_SOURCE_DIR}/src" "${_producer}/src")
        string(FIND "${_text}" "${_forbidden}" _hit)
        if(NOT _hit EQUAL -1)
            message(FATAL_ERROR
                "installed Fabric target leaks private include '${_forbidden}'")
        endif()
    endforeach()
endforeach()
if(NOT _metadata_text MATCHES "Ninlil::fabric_v1")
    message(FATAL_ERROR "installed metadata lacks Ninlil::fabric_v1")
endif()
file(GLOB_RECURSE _private_headers
    "${_prefix}/*fabric_private*"
    "${_prefix}/*fabric_workspace.h"
    "${_prefix}/*nfl1_codec.h")
if(_private_headers)
    message(FATAL_ERROR "private Fabric headers leaked: ${_private_headers}")
endif()

find_program(_nm NAMES nm REQUIRED)
execute_process(
    COMMAND "${_nm}" -g "${_fabric_archive}"
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _symbols ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "nm failed for Fabric archive: ${_err}")
endif()
foreach(_symbol
        workspace_required create bearer_ops register_link
        unregister_begin unregister_poll policy_put policy_remove
        policy_snapshot authority_put authority_remove authority_snapshot
        link_snapshot link_availability_update metrics_snapshot step
        close_begin close_poll destroy)
    if(NOT _symbols MATCHES
       "[ \t]_?ninlil_fabric_v1_${_symbol}([\r\n]|$)")
        message(FATAL_ERROR
            "installed Fabric archive lacks ninlil_fabric_v1_${_symbol}")
    endif()
endforeach()

set(_consumer_args
    -S "${NINLIL_SOURCE_DIR}/tests/cmake/installed_fabric_v1_consumer"
    -B "${_consumer}"
    -G "${NINLIL_GENERATOR}"
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
    message(FATAL_ERROR "Fabric consumer configure failed:\n${_out}${_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_consumer}"
        --config "${_config}" --parallel
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR "Fabric consumer build failed:\n${_out}${_err}")
endif()

file(READ "${_consumer}/compile_commands.json" _compile_graph)
foreach(_forbidden
        "${NINLIL_SOURCE_DIR}/include"
        "${NINLIL_SOURCE_DIR}/src"
        "${NINLIL_SOURCE_DIR}/tests/support"
        "${_producer}")
    string(FIND "${_compile_graph}" "${_forbidden}" _hit)
    if(NOT _hit EQUAL -1)
        message(FATAL_ERROR
            "installed Fabric consumer leaks source/private path '${_forbidden}'")
    endif()
endforeach()

set(_test_command
    "${NINLIL_CTEST_COMMAND}" --test-dir "${_consumer}"
    -C "${_config}" --output-on-failure)
if(NINLIL_SMOKE_ENABLE_SANITIZERS)
    set(_asan "halt_on_error=1")
    if(CMAKE_HOST_APPLE)
        string(APPEND _asan ":detect_leaks=0")
    endif()
    set(_test_command "${CMAKE_COMMAND}" -E env
        "ASAN_OPTIONS=${_asan}"
        "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"
        ${_test_command})
endif()
execute_process(
    COMMAND ${_test_command}
    RESULT_VARIABLE _rc OUTPUT_VARIABLE _out ERROR_VARIABLE _err)
if(NOT _rc EQUAL 0)
    message(FATAL_ERROR
        "installed Fabric two-instance E2E failed:\n${_out}${_err}")
endif()

file(REMOVE_RECURSE "${_work}")
message(STATUS
    "installed Fabric v1 tests-OFF smoke: OK (public target/header; "
    "two isolated Runtime/Fabric instances; forward ApplicationData; "
    "reverse Receipt; no private include/install leak)")
