# Negative gate: production archive and public install header must not expose
# test-only seams (barrier/hook/interpose/commit_fault/test_ceilings) or
# residual "test-only" vocabulary on the install surface.

if(NOT DEFINED NINLIL_BUILD_DIR OR NOT DEFINED NINLIL_SOURCE_DIR)
    message(FATAL_ERROR "posix_sqlite package surface gate requires build/source")
endif()

if(NOT DEFINED NINLIL_BUILD_CONFIG OR NINLIL_BUILD_CONFIG STREQUAL "")
    set(NINLIL_BUILD_CONFIG Release)
endif()

set(_archive "${NINLIL_BUILD_DIR}/libninlil_posix_sqlite_storage.a")
if(NOT EXISTS "${_archive}")
    set(_archive
        "${NINLIL_BUILD_DIR}/${NINLIL_BUILD_CONFIG}/libninlil_posix_sqlite_storage.a")
endif()
if(NOT EXISTS "${_archive}")
    message(FATAL_ERROR "production archive not found under ${NINLIL_BUILD_DIR}")
endif()

set(_header
    "${NINLIL_SOURCE_DIR}/ports/posix/include/ninlil_posix_sqlite_storage.h")
if(NOT EXISTS "${_header}")
    message(FATAL_ERROR "public header missing: ${_header}")
endif()

set(_bad_header_patterns
    "persist_barrier"
    "set_persist_barrier"
    "PERSIST_BARRIER"
    "persist_barrier_fn"
    "barrier_hook"
    "commit_fault"
    "COMMIT_FAULT"
    "set_commit_fault"
    "set_test_ceilings"
    "test_ceilings"
    "test-only"
    "test only"
    "Test-only"
)
foreach(_pat IN LISTS _bad_header_patterns)
    file(STRINGS "${_header}" _hits REGEX "${_pat}")
    if(_hits)
        message(FATAL_ERROR
            "public header must not contain '${_pat}': ${_header}")
    endif()
endforeach()

find_program(NINLIL_NM_EXECUTABLE NAMES nm)
if(NOT NINLIL_NM_EXECUTABLE)
    message(FATAL_ERROR "nm is required for package surface negative gate")
endif()

execute_process(
    COMMAND "${NINLIL_NM_EXECUTABLE}" "${_archive}"
    RESULT_VARIABLE _nm_rc
    OUTPUT_VARIABLE _nm_out
    ERROR_VARIABLE _nm_err)
if(NOT _nm_rc EQUAL 0)
    message(FATAL_ERROR "nm failed on ${_archive}: ${_nm_err}")
endif()

string(REGEX MATCH
    "(barrier|hook|persist_barrier|interpose|commit_fault|set_commit_fault|set_test_ceilings|test_ceilings)"
    _nm_hit
    "${_nm_out}")
if(_nm_hit)
    message(FATAL_ERROR
        "production archive nm must not contain banned symbols "
        "(matched '${_nm_hit}'): ${_archive}")
endif()

message(STATUS
    "posix_sqlite package surface negative: header and archive clean (${_archive})")
