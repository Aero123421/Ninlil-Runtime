# Verify tests-OFF private archive exposes profiled begin and lacks transport begin.

if(NOT DEFINED NINLIL_SOURCE_DIR)
    message(FATAL_ERROR "NINLIL_SOURCE_DIR is required")
endif()
if(NOT DEFINED NINLIL_GENERATOR)
    set(NINLIL_GENERATOR "Unix Makefiles")
endif()

string(RANDOM LENGTH 8 _suffix)
set(_work "${CMAKE_BINARY_DIR}/domain-scan-transport-absent-${_suffix}")
if(_work STREQUAL "/domain-scan-transport-absent-${_suffix}"
    OR _work STREQUAL "domain-scan-transport-absent-${_suffix}")
    set(_work "/tmp/domain-scan-transport-absent-${_suffix}")
endif()
file(REMOVE_RECURSE "${_work}")
file(MAKE_DIRECTORY "${_work}")

execute_process(
    COMMAND ${CMAKE_COMMAND}
        -S "${NINLIL_SOURCE_DIR}"
        -B "${_work}/build"
        -G "${NINLIL_GENERATOR}"
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_ENABLE_STRICT_WARNINGS=ON
    RESULT_VARIABLE _cfg_rc
    OUTPUT_VARIABLE _cfg_out
    ERROR_VARIABLE _cfg_err
)
if(NOT _cfg_rc EQUAL 0)
    message(FATAL_ERROR "configure failed:\n${_cfg_out}${_cfg_err}")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND}
        --build "${_work}/build"
        --target ninlil_runtime_private
    RESULT_VARIABLE _bld_rc
    OUTPUT_VARIABLE _bld_out
    ERROR_VARIABLE _bld_err
)
if(NOT _bld_rc EQUAL 0)
    message(FATAL_ERROR "build failed:\n${_bld_out}${_bld_err}")
endif()

file(GLOB_RECURSE _archives "${_work}/build/*ninlil_runtime_private*")
set(_archive "")
foreach(_cand IN LISTS _archives)
    if(_cand MATCHES "libninlil_runtime_private\\.a$")
        set(_archive "${_cand}")
    endif()
endforeach()
if(_archive STREQUAL "")
    message(FATAL_ERROR "private archive not found under ${_work}/build")
endif()

execute_process(
    COMMAND nm -g "${_archive}"
    RESULT_VARIABLE _nm_rc
    OUTPUT_VARIABLE _nm_out
    ERROR_VARIABLE _nm_err
)
if(NOT _nm_rc EQUAL 0)
    message(FATAL_ERROR "nm failed:\n${_nm_out}${_nm_err}")
endif()

set(_text "${_nm_out}${_nm_err}")
string(FIND "${_text}" "ninlil_domain_scan_begin_profiled" _prof_pos)
if(_prof_pos EQUAL -1)
    message(FATAL_ERROR
        "profiled begin missing from tests-OFF private archive")
endif()

string(REGEX MATCH
    "ninlil_domain_scan_begin([^_]|$)"
    _transport_hit
    "${_text}")
if(_transport_hit)
    # nm may list begin_profiled which also contains the prefix; require exact.
    string(REGEX MATCHALL
        "[^\n]*ninlil_domain_scan_begin[^\n]*"
        _lines
        "${_text}")
    foreach(_line IN LISTS _lines)
        if(_line MATCHES "ninlil_domain_scan_begin_profiled")
            continue()
        endif()
        if(_line MATCHES "ninlil_domain_scan_begin([^a-zA-Z0-9_]|$)")
            message(FATAL_ERROR
                "transport begin present in tests-OFF archive: ${_line}")
        endif()
    endforeach()
endif()

file(REMOVE_RECURSE "${_work}")
message(STATUS "transport begin absent from tests-OFF private archive")
