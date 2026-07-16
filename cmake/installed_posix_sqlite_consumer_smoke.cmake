if(NOT DEFINED NINLIL_BUILD_DIR
   OR NOT DEFINED NINLIL_SOURCE_DIR
   OR NOT DEFINED NINLIL_GENERATOR
   OR NOT DEFINED NINLIL_CTEST_COMMAND)
    message(FATAL_ERROR "installed consumer smoke requires build/source/generator/ctest")
endif()

set(_root "${NINLIL_BUILD_DIR}/installed-posix-sqlite-consumer-smoke")
set(_prefix "${_root}/prefix")
set(_build "${_root}/build")
file(REMOVE_RECURSE "${_root}")

if(NOT DEFINED NINLIL_BUILD_CONFIG OR NINLIL_BUILD_CONFIG STREQUAL "")
    set(NINLIL_BUILD_CONFIG Release)
endif()
if(NOT DEFINED NINLIL_INSTALL_SMOKE_SANITIZERS)
    set(NINLIL_INSTALL_SMOKE_SANITIZERS OFF)
endif()

# Optional: force the same SQLite archive the producer used (required for
# static false-green prevention).
if(NOT DEFINED NINLIL_SMOKE_SQLITE3_LIBRARY)
    set(NINLIL_SMOKE_SQLITE3_LIBRARY "")
endif()
if(NOT DEFINED NINLIL_SMOKE_SQLITE3_INCLUDE_DIR)
    set(NINLIL_SMOKE_SQLITE3_INCLUDE_DIR "")
endif()
if(NOT DEFINED NINLIL_SMOKE_EXPECT_STATIC_SQLITE)
    set(NINLIL_SMOKE_EXPECT_STATIC_SQLITE OFF)
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${NINLIL_BUILD_DIR}"
        --prefix "${_prefix}" --config "${NINLIL_BUILD_CONFIG}"
    RESULT_VARIABLE _install_rc)
if(NOT _install_rc EQUAL 0)
    message(FATAL_ERROR "Ninlil install failed: ${_install_rc}")
endif()

# Installed package surface must not ship test-only interpose/barrier/hook API.
set(_installed_header "${_prefix}/include/ninlil_posix_sqlite_storage.h")
set(_installed_archive "${_prefix}/lib/libninlil_posix_sqlite_storage.a")
if(NOT EXISTS "${_installed_header}")
    message(FATAL_ERROR "installed header missing: ${_installed_header}")
endif()
if(NOT EXISTS "${_installed_archive}")
    message(FATAL_ERROR "installed archive missing: ${_installed_archive}")
endif()
file(STRINGS "${_installed_header}" _bad_api
    REGEX "persist_barrier|set_persist_barrier|PERSIST_BARRIER|barrier_hook|commit_fault|COMMIT_FAULT|set_commit_fault|set_test_ceilings|test_ceilings|test-only|test only|Test-only")
if(_bad_api)
    message(FATAL_ERROR
        "installed header exposes banned test seam surface: ${_installed_header}")
endif()
find_program(_nm NAMES nm)
if(NOT _nm)
    message(FATAL_ERROR "nm is required to gate installed archive surface")
endif()
execute_process(
    COMMAND "${_nm}" "${_installed_archive}"
    RESULT_VARIABLE _nm_rc
    OUTPUT_VARIABLE _nm_out
    ERROR_VARIABLE _nm_err)
if(NOT _nm_rc EQUAL 0)
    message(FATAL_ERROR "nm failed on installed archive: ${_nm_err}")
endif()
string(REGEX MATCH "(barrier|hook|persist_barrier|interpose|commit_fault|set_commit_fault|set_test_ceilings|test_ceilings)" _nm_hit "${_nm_out}")
if(_nm_hit)
    message(FATAL_ERROR
        "installed archive nm must not contain banned symbols "
        "(matched '${_nm_hit}')")
endif()

# Metadata: cmake package + header must not embed absolute source paths.
file(GLOB_RECURSE _pkg_files "${_prefix}/lib/cmake/Ninlil/*")
list(APPEND _pkg_files "${_prefix}/include/ninlil_posix_sqlite_storage.h")
foreach(_pf IN LISTS _pkg_files)
    if(IS_DIRECTORY "${_pf}" OR NOT EXISTS "${_pf}")
        continue()
    endif()
    file(READ "${_pf}" _pcontent)
    string(FIND "${_pcontent}" "${NINLIL_SOURCE_DIR}" _src_pos)
    if(NOT _src_pos EQUAL -1)
        message(FATAL_ERROR
            "installed package file embeds source path: ${_pf}")
    endif()
    string(FIND "${_pcontent}" "${NINLIL_BUILD_DIR}" _bin_pos)
    if(NOT _bin_pos EQUAL -1)
        message(FATAL_ERROR
            "installed package file embeds build path: ${_pf}")
    endif()
endforeach()

# Binary-safe scan of the installed archive for absolute source/build roots.
# Uses strings(1) so Debug DWARF still fails if path remaps are missing.
# Note: when the build directory is nested under the source tree, a naive
# substring match for SOURCE_DIR alone would false-positive on BUILD_DIR;
# check distinctive absolute needles instead.
#
# Skip policy (explicit only): when the producer was configured with
# NINLIL_ENABLE_SANITIZERS=ON or the supported pointer-compare sanitizer,
# ASan global descriptors embed absolute -c source paths that prefix-map
# cannot rewrite. Instrumented archives are not ship artifacts. Skip ONLY
# this archive/object hygiene block; package surface, nm, install,
# find_package, consumer link, and run still run.
# No compiler-id guessing and no fallback that disables the scan implicitly.
if(NINLIL_INSTALL_SMOKE_SANITIZERS)
    message(STATUS
        "installed consumer smoke: skipping archive/object path hygiene "
        "(producer sanitizer instrumentation is ON; instrumented artifacts are "
        "non-ship; non-sanitizer production builds still require needles=0)")
else()
    find_program(_strings NAMES strings)
    if(NOT _strings)
        message(FATAL_ERROR "strings is required to scan installed archive paths")
    endif()
    execute_process(
        COMMAND "${_strings}" "${_installed_archive}"
        RESULT_VARIABLE _str_rc
        OUTPUT_VARIABLE _str_out
        ERROR_VARIABLE _str_err)
    if(NOT _str_rc EQUAL 0)
        message(FATAL_ERROR "strings failed on installed archive: ${_str_err}")
    endif()
    get_filename_component(_src_abs "${NINLIL_SOURCE_DIR}" ABSOLUTE)
    get_filename_component(_bin_abs "${NINLIL_BUILD_DIR}" ABSOLUTE)
    set(_needles
        "${_bin_abs}/"
        "${_bin_abs}"
        "${_src_abs}/ports/"
        "${_src_abs}/include/"
        "${_src_abs}/src/"
        "${_src_abs}/CMakeLists.txt"
    )
    foreach(_needle IN LISTS _needles)
        string(FIND "${_str_out}" "${_needle}" _npos)
        if(NOT _npos EQUAL -1)
            message(FATAL_ERROR
                "installed archive strings contain absolute path needle "
                "'${_needle}'")
        endif()
    endforeach()
    # Compile-flag re-embedding: -ffile-prefix-map=/abs/... must not appear in
    # the archive (relies on -gno-record-gcc-switches).
    string(FIND "${_str_out}" "file-prefix-map=${_src_abs}" _fmap_src)
    string(FIND "${_str_out}" "file-prefix-map=${_bin_abs}" _fmap_bin)
    string(FIND "${_str_out}" "debug-prefix-map=${_src_abs}" _dmap_src)
    string(FIND "${_str_out}" "debug-prefix-map=${_bin_abs}" _dmap_bin)
    if(NOT _fmap_src EQUAL -1 OR NOT _fmap_bin EQUAL -1
       OR NOT _dmap_src EQUAL -1 OR NOT _dmap_bin EQUAL -1)
        message(FATAL_ERROR
            "installed archive re-embeds absolute prefix-map compile flags")
    endif()

    # Object-level scan (readelf on .a is unreliable / false-green).
    # Absolute needles in extracted objects must be 0. GNU production applies
    # feature-checked -gdwarf-4 so .debug_line_str is absent; Clang/AppleClang
    # may retain the DWARF5 section when content is path-clean — ban absolute
    # needles, not section presence alone.
    find_program(_readelf NAMES readelf)
    find_program(_ar NAMES ar ${CMAKE_AR})
    if(NOT _ar)
        message(FATAL_ERROR
            "ar is required to extract installed archive objects for path hygiene")
    endif()
    set(_ar_tmp "${CMAKE_CURRENT_BINARY_DIR}/ninlil-archive-path-scan")
    file(REMOVE_RECURSE "${_ar_tmp}")
    file(MAKE_DIRECTORY "${_ar_tmp}")
    execute_process(
        COMMAND "${_ar}" x "${_installed_archive}"
        WORKING_DIRECTORY "${_ar_tmp}"
        RESULT_VARIABLE _ar_rc
        ERROR_VARIABLE _ar_err)
    if(NOT _ar_rc EQUAL 0)
        message(FATAL_ERROR "ar x failed on installed archive: ${_ar_err}")
    endif()
    file(GLOB _objs "${_ar_tmp}/*")
    if(NOT _objs)
        message(FATAL_ERROR
            "ar x produced no objects from '${_installed_archive}'")
    endif()
    foreach(_obj IN LISTS _objs)
        if(IS_DIRECTORY "${_obj}")
            continue()
        endif()
        # Optional section inventory when readelf exists (Linux CI). Absolute
        # needles are the ship-hygiene contract; Clang may keep DWARF5
        # .debug_line_str when content is remapped clean. GNU CI separately
        # requires feature-checked -gdwarf-4 + section absence.
        if(_readelf)
            execute_process(
                COMMAND "${_readelf}" -S "${_obj}"
                RESULT_VARIABLE _sec_rc
                OUTPUT_VARIABLE _sec_out
                ERROR_QUIET)
            if(_sec_rc EQUAL 0 AND _sec_out MATCHES "\\.debug_line_str")
                message(STATUS
                    "object '${_obj}' has DWARF5 .debug_line_str "
                    "(allowed if absolute needles are absent)")
            endif()
        endif()
        execute_process(
            COMMAND "${_strings}" "${_obj}"
            RESULT_VARIABLE _ostr_rc
            OUTPUT_VARIABLE _ostr_out
            ERROR_QUIET)
        if(NOT _ostr_rc EQUAL 0)
            message(FATAL_ERROR "strings failed on object '${_obj}'")
        endif()
        foreach(_needle IN LISTS _needles)
            string(FIND "${_ostr_out}" "${_needle}" _on)
            if(NOT _on EQUAL -1)
                message(FATAL_ERROR
                    "object '${_obj}' strings contain absolute path "
                    "needle '${_needle}'")
            endif()
        endforeach()
        string(FIND "${_ostr_out}" "file-prefix-map=${_src_abs}" _ofm)
        string(FIND "${_ostr_out}" "file-prefix-map=${_bin_abs}" _ofmb)
        if(NOT _ofm EQUAL -1 OR NOT _ofmb EQUAL -1)
            message(FATAL_ERROR
                "object '${_obj}' re-embeds absolute prefix-map flags")
        endif()
    endforeach()
    file(REMOVE_RECURSE "${_ar_tmp}")
endif()

# Shared consumer package args (prefix / SQLite pin / sanitizers). Build-type
# variants are applied per matrix case below.
set(_consumer_common_args
    "-DCMAKE_PREFIX_PATH=${_prefix}"
    "-DNINLIL_CONSUMER_ENABLE_SANITIZERS=${NINLIL_INSTALL_SMOKE_SANITIZERS}"
)
if(NINLIL_SMOKE_SQLITE3_LIBRARY)
    list(APPEND _consumer_common_args
        "-DSQLite3_LIBRARY=${NINLIL_SMOKE_SQLITE3_LIBRARY}"
        "-DSQLite3_LIBRARIES=${NINLIL_SMOKE_SQLITE3_LIBRARY}")
endif()
if(NINLIL_SMOKE_SQLITE3_INCLUDE_DIR)
    list(APPEND _consumer_common_args
        "-DSQLite3_INCLUDE_DIR=${NINLIL_SMOKE_SQLITE3_INCLUDE_DIR}"
        "-DSQLite3_INCLUDE_DIRS=${NINLIL_SMOKE_SQLITE3_INCLUDE_DIR}")
endif()
if(NINLIL_SMOKE_EXPECT_STATIC_SQLITE)
    list(APPEND _consumer_common_args
        "-DNINLIL_CONSUMER_EXPECT_STATIC_SQLITE=ON")
    if(NINLIL_SMOKE_SQLITE3_LIBRARY)
        list(APPEND _consumer_common_args
            "-DNINLIL_CONSUMER_SQLITE3_LIBRARY=${NINLIL_SMOKE_SQLITE3_LIBRARY}")
    endif()
endif()

# One install, then consumer matrix:
# - match: producer config (historical path)
# - none: omit CMAKE_BUILD_TYPE (regression for empty/default consumer)
# - alt: Debug↔Release mismatch (MAP_IMPORTED_CONFIG / single-config export)
# - strict_map: alt config with identity CMAKE_MAP_IMPORTED_CONFIG_* so only
#   package target MAP (not CMake auto-fallback) can resolve locations
# Multi-config generators: single configure (no build type) + Debug/Release
# build/run; static checks run on the first successful executable.
set(_consumer_is_multi FALSE)
if(NINLIL_GENERATOR MATCHES "Multi-Config"
   OR NINLIL_GENERATOR MATCHES "Visual Studio"
   OR NINLIL_GENERATOR STREQUAL "Xcode")
    set(_consumer_is_multi TRUE)
endif()

string(TOUPPER "${NINLIL_BUILD_CONFIG}" _producer_cfg_upper)
if(_producer_cfg_upper STREQUAL "DEBUG")
    set(_alt_consumer_cfg "Release")
else()
    set(_alt_consumer_cfg "Debug")
endif()

function(ninlil_installed_consumer_static_checks build_dir build_config label build_out build_err)
    if(NINLIL_SMOKE_EXPECT_STATIC_SQLITE AND NINLIL_SMOKE_SQLITE3_LIBRARY)
        string(FIND "${build_out}${build_err}"
            "${NINLIL_SMOKE_SQLITE3_LIBRARY}" _lib_pos)
        if(_lib_pos EQUAL -1)
            string(FIND "${build_out}${build_err}" "libsqlite3.a" _a_pos)
            if(_a_pos EQUAL -1)
                message(FATAL_ERROR
                    "static consumer link did not mention libsqlite3.a or "
                    "SQLite3_LIBRARY='${NINLIL_SMOKE_SQLITE3_LIBRARY}' "
                    "(${label}). Link output:\n${build_out}\n${build_err}")
            endif()
        endif()
        string(FIND "${build_out}${build_err}" "libsqlite3.so" _so_pos)
        if(NOT _so_pos EQUAL -1)
            message(FATAL_ERROR
                "static consumer link line references libsqlite3.so "
                "(${label}):\n${build_out}\n${build_err}")
        endif()
    endif()

    if(NOT NINLIL_SMOKE_EXPECT_STATIC_SQLITE)
        return()
    endif()

    set(_exe "")
    foreach(_cand
            "${build_dir}/ninlil_installed_posix_sqlite_consumer"
            "${build_dir}/${build_config}/ninlil_installed_posix_sqlite_consumer")
        if(EXISTS "${_cand}")
            set(_exe "${_cand}")
            break()
        endif()
    endforeach()
    if(NOT _exe)
        message(FATAL_ERROR
            "cannot locate installed consumer executable under "
            "${build_dir} (${label})")
    endif()
    find_program(_ldd NAMES ldd)
    find_program(_otool NAMES otool)
    find_program(_readelf NAMES readelf)
    if(_ldd)
        execute_process(
            COMMAND "${_ldd}" "${_exe}"
            RESULT_VARIABLE _ldd_rc
            OUTPUT_VARIABLE _ldd_out
            ERROR_VARIABLE _ldd_err)
        if(NOT _ldd_rc EQUAL 0)
            message(FATAL_ERROR "ldd failed (${label}): ${_ldd_err}")
        endif()
        if(_ldd_out MATCHES "libsqlite3\\.so")
            message(FATAL_ERROR
                "static consumer still depends on libsqlite3.so "
                "(${label}):\n${_ldd_out}")
        endif()
        message(STATUS
            "static consumer ldd (${label}): no libsqlite3.so dependency")
    elseif(_otool)
        execute_process(
            COMMAND "${_otool}" -L "${_exe}"
            RESULT_VARIABLE _ot_rc
            OUTPUT_VARIABLE _ot_out
            ERROR_VARIABLE _ot_err)
        if(NOT _ot_rc EQUAL 0)
            message(FATAL_ERROR "otool -L failed (${label}): ${_ot_err}")
        endif()
        if(_ot_out MATCHES "libsqlite3")
            message(FATAL_ERROR
                "consumer unexpectedly links libsqlite3 dylib "
                "(${label}):\n${_ot_out}")
        endif()
    else()
        message(FATAL_ERROR
            "ldd or otool required to assert no shared libsqlite3 dependency")
    endif()
    if(_readelf)
        execute_process(
            COMMAND "${_readelf}" -d "${_exe}"
            RESULT_VARIABLE _re_rc
            OUTPUT_VARIABLE _re_out
            ERROR_QUIET)
        if(_re_rc EQUAL 0 AND _re_out MATCHES "libsqlite3\\.so")
            message(FATAL_ERROR
                "readelf -d shows libsqlite3.so NEEDED (${label}):\n${_re_out}")
        endif()
    endif()
endfunction()

function(ninlil_installed_consumer_build_and_run build_dir build_config label)
    message(STATUS
        "installed consumer build/run '${label}': dir='${build_dir}' "
        "config='${build_config}'")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" --build "${build_dir}"
            --config "${build_config}"
            --verbose
        RESULT_VARIABLE _build_rc
        OUTPUT_VARIABLE _build_out
        ERROR_VARIABLE _build_err)
    if(NOT _build_rc EQUAL 0)
        message(FATAL_ERROR
            "installed consumer build failed (${label}): ${_build_rc}\n"
            "${_build_out}\n${_build_err}")
    endif()

    set(_ctest_cmd
        "${NINLIL_CTEST_COMMAND}" --test-dir "${build_dir}"
        --output-on-failure)
    if(build_config AND NOT build_config STREQUAL "")
        list(APPEND _ctest_cmd -C "${build_config}")
    endif()
    execute_process(
        COMMAND ${_ctest_cmd}
        RESULT_VARIABLE _test_rc)
    if(NOT _test_rc EQUAL 0)
        message(FATAL_ERROR
            "installed consumer execution failed (${label}): ${_test_rc}")
    endif()

    ninlil_installed_consumer_static_checks(
        "${build_dir}" "${build_config}" "${label}"
        "${_build_out}" "${_build_err}")
endfunction()

function(ninlil_installed_consumer_run_one)
    set(options)
    set(oneValueArgs LABEL BUILD_TYPE BUILD_CONFIG BUILD_DIR)
    set(multiValueArgs EXTRA_CMAKE_ARGS)
    cmake_parse_arguments(NIC "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})
    if(NOT NIC_LABEL OR NOT NIC_BUILD_DIR)
        message(FATAL_ERROR
            "ninlil_installed_consumer_run_one requires LABEL and BUILD_DIR")
    endif()
    if(NOT DEFINED NIC_BUILD_CONFIG OR NIC_BUILD_CONFIG STREQUAL "")
        if(NIC_BUILD_TYPE AND NOT NIC_BUILD_TYPE STREQUAL "")
            set(NIC_BUILD_CONFIG "${NIC_BUILD_TYPE}")
        else()
            set(NIC_BUILD_CONFIG "${NINLIL_BUILD_CONFIG}")
        endif()
    endif()

    set(_args ${_consumer_common_args})
    if(DEFINED NIC_EXTRA_CMAKE_ARGS)
        list(APPEND _args ${NIC_EXTRA_CMAKE_ARGS})
    endif()
    if(DEFINED NIC_BUILD_TYPE AND NOT NIC_BUILD_TYPE STREQUAL "")
        list(APPEND _args "-DCMAKE_BUILD_TYPE=${NIC_BUILD_TYPE}")
    endif()

    file(REMOVE_RECURSE "${NIC_BUILD_DIR}")
    message(STATUS
        "installed consumer case '${NIC_LABEL}': build_type='${NIC_BUILD_TYPE}' "
        "build_config='${NIC_BUILD_CONFIG}'")

    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            -S "${NINLIL_SOURCE_DIR}/tests/cmake/installed_posix_sqlite_consumer"
            -B "${NIC_BUILD_DIR}"
            -G "${NINLIL_GENERATOR}"
            ${_args}
        RESULT_VARIABLE _configure_rc)
    if(NOT _configure_rc EQUAL 0)
        message(FATAL_ERROR
            "installed consumer configure failed (${NIC_LABEL}): ${_configure_rc}")
    endif()

    ninlil_installed_consumer_build_and_run(
        "${NIC_BUILD_DIR}" "${NIC_BUILD_CONFIG}" "${NIC_LABEL}")
endfunction()

if(_consumer_is_multi)
    # Multi-config: one configure without CMAKE_BUILD_TYPE, then Debug+Release.
    set(_mc_build "${_root}/consumer-multi")
    file(REMOVE_RECURSE "${_mc_build}")
    message(STATUS
        "installed consumer multi-config generator: configure once, build Debug+Release")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            -S "${NINLIL_SOURCE_DIR}/tests/cmake/installed_posix_sqlite_consumer"
            -B "${_mc_build}"
            -G "${NINLIL_GENERATOR}"
            ${_consumer_common_args}
        RESULT_VARIABLE _configure_rc)
    if(NOT _configure_rc EQUAL 0)
        message(FATAL_ERROR
            "installed multi-config consumer configure failed: ${_configure_rc}")
    endif()
    foreach(_mc_cfg Debug Release)
        ninlil_installed_consumer_build_and_run(
            "${_mc_build}" "${_mc_cfg}" "multi-${_mc_cfg}")
    endforeach()
else()
    ninlil_installed_consumer_run_one(
        LABEL "match"
        BUILD_DIR "${_root}/consumer-match"
        BUILD_TYPE "${NINLIL_BUILD_CONFIG}"
        BUILD_CONFIG "${NINLIL_BUILD_CONFIG}")

    # Regression: omit CMAKE_BUILD_TYPE entirely (empty/default single-config).
    ninlil_installed_consumer_run_one(
        LABEL "none"
        BUILD_DIR "${_root}/consumer-none"
        BUILD_TYPE ""
        BUILD_CONFIG "${NINLIL_BUILD_CONFIG}")

    ninlil_installed_consumer_run_one(
        LABEL "alt-${_alt_consumer_cfg}"
        BUILD_DIR "${_root}/consumer-alt"
        BUILD_TYPE "${_alt_consumer_cfg}"
        BUILD_CONFIG "${_alt_consumer_cfg}")

    # Strict identity maps: without package MAP_IMPORTED_CONFIG / plain
    # IMPORTED_LOCATION, generate fails with missing IMPORTED_LOCATION for the
    # alt consumer configuration when the install only shipped producer config.
    string(TOUPPER "${_alt_consumer_cfg}" _alt_upper)
    ninlil_installed_consumer_run_one(
        LABEL "strict-map-${_alt_consumer_cfg}"
        BUILD_DIR "${_root}/consumer-strict-map"
        BUILD_TYPE "${_alt_consumer_cfg}"
        BUILD_CONFIG "${_alt_consumer_cfg}"
        EXTRA_CMAKE_ARGS
            "-DCMAKE_MAP_IMPORTED_CONFIG_${_alt_upper}=${_alt_consumer_cfg}")
endif()
