# N6 tests-OFF Release production packaging gate (docs/30 §20.2 / ADR-0010 Chunk D).
#
# Fresh isolated OFF Release subbuild (never reuses the parent tests-ON tree):
#   1. configure NINLIL_BUILD_TESTS=OFF + CMAKE_BUILD_TYPE=Release
#   2. prove ctest -N reports zero tests
#   3. bare `all` then exact-count 0 for private archive paths
#   4. explicit --target ninlil_runtime_private then exact-count 1 path
#   5. temp install; public-only install tree
#   6. ar/nm/strings via tools/n6_chunk_d_leakage_gate.py
#
# Archive discovery policy (exact path-count, no last-wins):
#   - GLOB_RECURSE candidates whose path matches libninlil_runtime_private.(a|lib)$
#   - Count is the number of matching path strings (no realpath collapse).
#   - Symlink A and symlink B are two candidates if both paths match.
#   - bare all  → length MUST be 0
#   - explicit  → length MUST be 1 (0 and 2+ both FATAL)
#
# PASS ≠ product GO / R6 complete / ESP N6 ready.

if(NOT DEFINED NINLIL_SOURCE_DIR)
    message(FATAL_ERROR "NINLIL_SOURCE_DIR is required")
endif()
if(NOT DEFINED NINLIL_GENERATOR)
    set(NINLIL_GENERATOR "Unix Makefiles")
endif()
if(NOT DEFINED NINLIL_PYTHON)
    find_program(NINLIL_PYTHON NAMES python3 python REQUIRED)
endif()

# Collect matching production private archive path strings under a build tree.
# Policy: exact path-count (no realpath dedup; each GLOB path is one candidate).
function(n6_collect_private_archives root_dir out_list_var)
    set(_found "")
    file(GLOB_RECURSE _raw "${root_dir}/*ninlil_runtime_private*")
    foreach(_cand IN LISTS _raw)
        if(_cand MATCHES "libninlil_runtime_private\\.(a|lib)$")
            list(APPEND _found "${_cand}")
        endif()
    endforeach()
    set(${out_list_var} "${_found}" PARENT_SCOPE)
endfunction()

string(RANDOM LENGTH 8 _n6_suffix)
set(_n6_work "${CMAKE_BINARY_DIR}/n6-tests-off-packaging-${_n6_suffix}")
if(_n6_work STREQUAL "/n6-tests-off-packaging-${_n6_suffix}"
    OR _n6_work STREQUAL "n6-tests-off-packaging-${_n6_suffix}")
    set(_n6_work "/tmp/n6-tests-off-packaging-${_n6_suffix}")
endif()
file(REMOVE_RECURSE "${_n6_work}")
file(MAKE_DIRECTORY "${_n6_work}")
set(_n6_build "${_n6_work}/build")
set(_n6_prefix "${_n6_work}/install")

message(STATUS "n6_tests_off_packaging: fresh OFF Release under ${_n6_work}")

# --- 1) configure tests-OFF Release ---
execute_process(
    COMMAND ${CMAKE_COMMAND}
        -S "${NINLIL_SOURCE_DIR}"
        -B "${_n6_build}"
        -G "${NINLIL_GENERATOR}"
        -DCMAKE_BUILD_TYPE=Release
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_ENABLE_STRICT_WARNINGS=ON
        -DNINLIL_ENABLE_SANITIZERS=OFF
    RESULT_VARIABLE _n6_cfg_rc
    OUTPUT_VARIABLE _n6_cfg_out
    ERROR_VARIABLE _n6_cfg_err
)
if(NOT _n6_cfg_rc EQUAL 0)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: configure failed:\n${_n6_cfg_out}${_n6_cfg_err}")
endif()

# --- 2) ctest -N must report zero tests (no test graph under OFF) ---
execute_process(
    COMMAND ${CMAKE_CTEST_COMMAND} -N
    WORKING_DIRECTORY "${_n6_build}"
    RESULT_VARIABLE _n6_ctest_rc
    OUTPUT_VARIABLE _n6_ctest_out
    ERROR_VARIABLE _n6_ctest_err
)
if(NOT _n6_ctest_rc EQUAL 0)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: ctest -N failed:\n${_n6_ctest_out}${_n6_ctest_err}")
endif()
set(_n6_ctest_text "${_n6_ctest_out}${_n6_ctest_err}")
string(REGEX MATCH "Total Tests:[ \t]*([0-9]+)" _n6_total_match "${_n6_ctest_text}")
if(_n6_total_match)
    set(_n6_total "${CMAKE_MATCH_1}")
    if(NOT _n6_total STREQUAL "0")
        file(REMOVE_RECURSE "${_n6_work}")
        message(FATAL_ERROR
            "n6_tests_off_packaging: ctest -N reported Total Tests: ${_n6_total} "
            "(expected 0 under NINLIL_BUILD_TESTS=OFF)\n${_n6_ctest_text}")
    endif()
else()
    string(FIND "${_n6_ctest_text}" "No tests were found" _n6_no_tests_pos)
    if(_n6_no_tests_pos EQUAL -1)
        file(REMOVE_RECURSE "${_n6_work}")
        message(FATAL_ERROR
            "n6_tests_off_packaging: cannot parse ctest -N output "
            "(need Total Tests: 0 or No tests were found):\n${_n6_ctest_text}")
    endif()
endif()

# --- 3) bare `all` then private archive path-count MUST be 0 ---
execute_process(
    COMMAND ${CMAKE_COMMAND}
        --build "${_n6_build}"
        --config Release
    RESULT_VARIABLE _n6_all_rc
    OUTPUT_VARIABLE _n6_all_out
    ERROR_VARIABLE _n6_all_err
)
if(NOT _n6_all_rc EQUAL 0)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: default all build failed:\n"
        "${_n6_all_out}${_n6_all_err}")
endif()

n6_collect_private_archives("${_n6_build}" _n6_after_all_list)
list(LENGTH _n6_after_all_list _n6_after_all_count)
if(NOT _n6_after_all_count EQUAL 0)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: EXCLUDE_FROM_ALL broken — after bare `all`, "
        "libninlil_runtime_private.(a|lib) path count must be 0, got "
        "${_n6_after_all_count}: ${_n6_after_all_list}")
endif()

# --- 4) explicit private target; path count MUST be exactly 1 ---
execute_process(
    COMMAND ${CMAKE_COMMAND}
        --build "${_n6_build}"
        --config Release
        --target ninlil_runtime_private
    RESULT_VARIABLE _n6_bld_rc
    OUTPUT_VARIABLE _n6_bld_out
    ERROR_VARIABLE _n6_bld_err
)
if(NOT _n6_bld_rc EQUAL 0)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: explicit ninlil_runtime_private build failed "
        "(EXCLUDE_FROM_ALL requires --target; do not rely on bare all):\n"
        "${_n6_bld_out}${_n6_bld_err}")
endif()

n6_collect_private_archives("${_n6_build}" _n6_after_explicit_list)
list(LENGTH _n6_after_explicit_list _n6_after_explicit_count)
if(NOT _n6_after_explicit_count EQUAL 1)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: after explicit --target ninlil_runtime_private, "
        "libninlil_runtime_private.(a|lib) path count must be exactly 1, got "
        "${_n6_after_explicit_count}: ${_n6_after_explicit_list} "
        "(0 = EXCLUDE_FROM_ALL oversight; 2+ = ambiguous production evidence)")
endif()
list(GET _n6_after_explicit_list 0 _n6_archive)

# --- 5) temp install (public OSS surface only; private archive not installed) ---
file(MAKE_DIRECTORY "${_n6_prefix}")
execute_process(
    COMMAND ${CMAKE_COMMAND}
        --install "${_n6_build}"
        --prefix "${_n6_prefix}"
        --config Release
    RESULT_VARIABLE _n6_inst_rc
    OUTPUT_VARIABLE _n6_inst_out
    ERROR_VARIABLE _n6_inst_err
)
if(NOT _n6_inst_rc EQUAL 0)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: install failed:\n${_n6_inst_out}${_n6_inst_err}")
endif()

# --- 6) ar / nm / strings / install-tree via packaging leakage gate ---
execute_process(
    COMMAND ${NINLIL_PYTHON}
        "${NINLIL_SOURCE_DIR}/tools/n6_chunk_d_leakage_gate.py"
        check
        --archive "${_n6_archive}"
        --src-root "${NINLIL_SOURCE_DIR}"
        --build-dir "${_n6_build}"
        --install-prefix "${_n6_prefix}"
        --require-tests-off-hygiene
    RESULT_VARIABLE _n6_gate_rc
    OUTPUT_VARIABLE _n6_gate_out
    ERROR_VARIABLE _n6_gate_err
)
if(NOT _n6_gate_rc EQUAL 0)
    file(REMOVE_RECURSE "${_n6_work}")
    message(FATAL_ERROR
        "n6_tests_off_packaging: leakage/packaging gate failed:\n"
        "${_n6_gate_out}${_n6_gate_err}")
endif()

file(REMOVE_RECURSE "${_n6_work}")
message(STATUS
    "n6_tests_off_packaging: OK "
    "(fresh OFF Release; ctest-N=0; bare-all archive path-count=0; "
    "explicit target path-count=1; ar N6 exact-once; "
    "fixture/test/oracle/spy 0; nm exact DEFINED T/t; strings hard-enforced; "
    "install public-only)")
