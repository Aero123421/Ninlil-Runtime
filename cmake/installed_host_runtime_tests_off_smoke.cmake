# Fresh tests-OFF install/export gate for the public Host Runtime package.
#
# Proves:
#   - tests are absent and the public runtime is built/installed by default;
#   - Ninlil::runtime and its OpenSSL 3 dependency are exported;
#   - SQLite-OFF has no SQLite package, target, header, or archive dependency;
#   - SQLite-ON preserves the optional installed provider integration;
#   - the archive contains the real public Runtime and Host crypto symbols;
#   - private/test symbols, private archives, test objects, and absolute build
#     paths do not leak;
#   - an independent public-API-only consumer can create -> step -> destroy.

if(NOT DEFINED NINLIL_SOURCE_DIR
   OR NOT DEFINED NINLIL_PARENT_BUILD_DIR
   OR NOT DEFINED NINLIL_GENERATOR
   OR NOT DEFINED NINLIL_CTEST_COMMAND)
    message(FATAL_ERROR
        "installed Host Runtime smoke requires source/build/generator/ctest")
endif()

if(NOT DEFINED NINLIL_SMOKE_WITH_SQLITE)
    set(NINLIL_SMOKE_WITH_SQLITE OFF)
endif()
if(NINLIL_SMOKE_WITH_SQLITE)
    set(_sqlite_mode "sqlite-on")
else()
    set(_sqlite_mode "sqlite-off")
endif()

set(_work
    "${NINLIL_PARENT_BUILD_DIR}/installed-host-runtime-tests-off-${_sqlite_mode}")
set(_producer_build "${_work}/producer")
set(_prefix "${_work}/prefix")
set(_consumer_build "${_work}/consumer")
file(REMOVE_RECURSE "${_work}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -S "${NINLIL_SOURCE_DIR}"
        -B "${_producer_build}"
        -G "${NINLIL_GENERATOR}"
        -DCMAKE_BUILD_TYPE=Release
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_BUILD_HOST_RUNTIME=ON
        -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=${NINLIL_SMOKE_WITH_SQLITE}
        -DNINLIL_ENABLE_STRICT_WARNINGS=ON
        -DNINLIL_ENABLE_SANITIZERS=OFF
    RESULT_VARIABLE _configure_rc
    OUTPUT_VARIABLE _configure_out
    ERROR_VARIABLE _configure_err)
if(NOT _configure_rc EQUAL 0)
    message(FATAL_ERROR
        "tests-OFF producer configure failed:\n"
        "${_configure_out}${_configure_err}")
endif()

execute_process(
    COMMAND "${NINLIL_CTEST_COMMAND}" -N
    WORKING_DIRECTORY "${_producer_build}"
    RESULT_VARIABLE _ctest_n_rc
    OUTPUT_VARIABLE _ctest_n_out
    ERROR_VARIABLE _ctest_n_err)
if(NOT _ctest_n_rc EQUAL 0)
    message(FATAL_ERROR
        "tests-OFF ctest -N failed:\n${_ctest_n_out}${_ctest_n_err}")
endif()
set(_ctest_n_text "${_ctest_n_out}${_ctest_n_err}")
if(NOT _ctest_n_text MATCHES "Total Tests:[ \t]*0"
   AND NOT _ctest_n_text MATCHES "No tests were found")
    message(FATAL_ERROR
        "tests-OFF build unexpectedly registered tests:\n${_ctest_n_text}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_producer_build}"
        --config Release --parallel
    RESULT_VARIABLE _build_rc
    OUTPUT_VARIABLE _build_out
    ERROR_VARIABLE _build_err)
if(NOT _build_rc EQUAL 0)
    message(FATAL_ERROR
        "tests-OFF producer build failed:\n${_build_out}${_build_err}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --install "${_producer_build}"
        --prefix "${_prefix}" --config Release
    RESULT_VARIABLE _install_rc
    OUTPUT_VARIABLE _install_out
    ERROR_VARIABLE _install_err)
if(NOT _install_rc EQUAL 0)
    message(FATAL_ERROR
        "tests-OFF install failed:\n${_install_out}${_install_err}")
endif()

file(GLOB_RECURSE _runtime_candidates
    "${_prefix}/*ninlil_runtime.a"
    "${_prefix}/*ninlil_runtime.lib")
set(_runtime_archives "")
foreach(_candidate IN LISTS _runtime_candidates)
    get_filename_component(_candidate_name "${_candidate}" NAME)
    if(_candidate_name MATCHES "^(lib)?ninlil_runtime\\.(a|lib)$")
        list(APPEND _runtime_archives "${_candidate}")
    endif()
endforeach()
list(LENGTH _runtime_archives _runtime_archive_count)
if(NOT _runtime_archive_count EQUAL 1)
    message(FATAL_ERROR
        "installed public Runtime archive count must be exactly 1, got "
        "${_runtime_archive_count}: ${_runtime_archives}")
endif()
list(GET _runtime_archives 0 _runtime_archive)

file(GLOB_RECURSE _private_leaks
    "${_prefix}/*ninlil_runtime_private*")
if(_private_leaks)
    message(FATAL_ERROR
        "private Runtime leaked into install tree: ${_private_leaks}")
endif()

file(GLOB_RECURSE _package_metadata
    "${_prefix}/*/cmake/Ninlil/*.cmake")
set(_package_text "")
set(_targets_text "")
foreach(_metadata IN LISTS _package_metadata)
    file(READ "${_metadata}" _metadata_text)
    string(APPEND _package_text "\n${_metadata_text}")
    get_filename_component(_metadata_name "${_metadata}" NAME)
    if(_metadata_name MATCHES "^NinlilTargets.*\\.cmake$")
        string(APPEND _targets_text "\n${_metadata_text}")
    endif()
    string(FIND "${_metadata_text}" "${NINLIL_SOURCE_DIR}" _source_hit)
    string(FIND "${_metadata_text}" "${_producer_build}" _build_hit)
    if(NOT _source_hit EQUAL -1 OR NOT _build_hit EQUAL -1)
        message(FATAL_ERROR
            "installed package metadata embeds producer path: ${_metadata}")
    endif()
endforeach()
if(NOT _package_text MATCHES "Ninlil::runtime"
   OR NOT _package_text MATCHES "OpenSSL::Crypto")
    message(FATAL_ERROR
        "installed package is missing Runtime/OpenSSL target metadata")
endif()

file(GLOB_RECURSE _sqlite_archives
    "${_prefix}/*ninlil_posix_sqlite_storage.a"
    "${_prefix}/*ninlil_posix_sqlite_storage.lib")
file(GLOB_RECURSE _sqlite_headers
    "${_prefix}/*ninlil_posix_sqlite_storage.h")
if(NINLIL_SMOKE_WITH_SQLITE)
    if(NOT _targets_text MATCHES
       "Ninlil::ninlil_posix_sqlite_storage"
       OR NOT _sqlite_archives
       OR NOT _sqlite_headers)
        message(FATAL_ERROR
            "SQLite-ON install is missing its target, archive, or header")
    endif()
else()
    if(_targets_text MATCHES
       "Ninlil::ninlil_posix_sqlite_storage"
       OR _sqlite_archives
       OR _sqlite_headers)
        message(FATAL_ERROR
            "SQLite-OFF install leaked a SQLite target, archive, or header")
    endif()
endif()

find_program(_ar NAMES ar REQUIRED)
execute_process(
    COMMAND "${_ar}" t "${_runtime_archive}"
    RESULT_VARIABLE _ar_rc
    OUTPUT_VARIABLE _ar_out
    ERROR_VARIABLE _ar_err)
if(NOT _ar_rc EQUAL 0)
    message(FATAL_ERROR "ar failed on public Runtime: ${_ar_err}")
endif()
string(TOLOWER "${_ar_out}" _ar_lower)
if(_ar_lower MATCHES "(^|[\r\n])[^\\r\\n]*(test|fixture|oracle|spy|testbuild)[^\\r\\n]*\\.(o|obj)([\r\n]|$)")
    message(FATAL_ERROR
        "public Runtime archive contains a test-only object:\n${_ar_out}")
endif()

find_program(_nm NAMES nm REQUIRED)
execute_process(
    COMMAND "${_nm}" -g "${_runtime_archive}"
    RESULT_VARIABLE _nm_rc
    OUTPUT_VARIABLE _nm_out
    ERROR_VARIABLE _nm_err)
if(NOT _nm_rc EQUAL 0)
    message(FATAL_ERROR "nm failed on public Runtime: ${_nm_err}")
endif()
foreach(_required_symbol
        ninlil_runtime_create
        ninlil_runtime_step
        ninlil_runtime_destroy
        ninlil_r7_crypto_openssl3_provider_init)
    if(NOT _nm_out MATCHES "[ \t]_?${_required_symbol}([\r\n]|$)")
        message(FATAL_ERROR
            "public Runtime archive lacks '${_required_symbol}'")
    endif()
endforeach()
foreach(_banned_symbol
        ninlil_domain_scan_begin
        ninlil_r7_crypto_test_spans_forbidden
        ninlil_r7_wire_test_spans_forbidden
        ninlil_r7_binding_test_spans_forbidden
        ninlil_r7_binding_test_set_secret_probe)
    if(_nm_out MATCHES "[ \t]_?${_banned_symbol}([\r\n]|$)")
        message(FATAL_ERROR
            "public Runtime archive exposes test-only symbol "
            "'${_banned_symbol}'")
    endif()
endforeach()
if(_nm_out MATCHES
   "[ \t]_?ninlil_(ctrl_session_test_|logical_session_test_|n6_test_)[^ \t\r\n]*")
    message(FATAL_ERROR
        "public Runtime archive exposes a test-only symbol:\n${_nm_out}")
endif()

find_program(_strings NAMES strings REQUIRED)
execute_process(
    COMMAND "${_strings}" "${_runtime_archive}"
    RESULT_VARIABLE _strings_rc
    OUTPUT_VARIABLE _strings_out
    ERROR_VARIABLE _strings_err)
if(NOT _strings_rc EQUAL 0)
    message(FATAL_ERROR "strings failed on public Runtime: ${_strings_err}")
endif()
foreach(_needle
        "${NINLIL_SOURCE_DIR}/"
        "${_producer_build}/"
        "${NINLIL_SOURCE_DIR}"
        "${_producer_build}")
    string(FIND "${_strings_out}" "${_needle}" _needle_hit)
    if(NOT _needle_hit EQUAL -1)
        message(FATAL_ERROR
            "public Runtime archive embeds producer path '${_needle}'")
    endif()
endforeach()

set(_consumer_args
    -S "${NINLIL_SOURCE_DIR}/tests/cmake/installed_host_runtime_consumer"
    -B "${_consumer_build}"
    -G "${NINLIL_GENERATOR}"
    "-DCMAKE_PREFIX_PATH=${_prefix}"
    -DCMAKE_MAP_IMPORTED_CONFIG_DEBUG=DEBUG
    -DNINLIL_CONSUMER_EXPECT_SQLITE=${NINLIL_SMOKE_WITH_SQLITE}
)
if(NOT NINLIL_SMOKE_WITH_SQLITE)
    list(APPEND _consumer_args
        -DCMAKE_DISABLE_FIND_PACKAGE_SQLite3=TRUE)
endif()
if(NINLIL_GENERATOR MATCHES
   "(Xcode|Visual Studio|Ninja Multi-Config)")
    set(_consumer_config Debug)
else()
    list(APPEND _consumer_args -DCMAKE_BUILD_TYPE=Debug)
    set(_consumer_config Debug)
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" ${_consumer_args}
    RESULT_VARIABLE _consumer_configure_rc
    OUTPUT_VARIABLE _consumer_configure_out
    ERROR_VARIABLE _consumer_configure_err)
if(NOT _consumer_configure_rc EQUAL 0)
    message(FATAL_ERROR
        "installed consumer configure failed:\n"
        "${_consumer_configure_out}${_consumer_configure_err}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${_consumer_build}"
        --config "${_consumer_config}" --parallel
    RESULT_VARIABLE _consumer_build_rc
    OUTPUT_VARIABLE _consumer_build_out
    ERROR_VARIABLE _consumer_build_err)
if(NOT _consumer_build_rc EQUAL 0)
    message(FATAL_ERROR
        "installed consumer build failed:\n"
        "${_consumer_build_out}${_consumer_build_err}")
endif()
execute_process(
    COMMAND "${NINLIL_CTEST_COMMAND}" --test-dir "${_consumer_build}"
        -C "${_consumer_config}" --output-on-failure
    RESULT_VARIABLE _consumer_test_rc
    OUTPUT_VARIABLE _consumer_test_out
    ERROR_VARIABLE _consumer_test_err)
if(NOT _consumer_test_rc EQUAL 0)
    message(FATAL_ERROR
        "installed consumer create/step/destroy failed:\n"
        "${_consumer_test_out}${_consumer_test_err}")
endif()

file(REMOVE_RECURSE "${_work}")
message(STATUS
    "installed Host Runtime tests-OFF smoke: OK "
    "(${_sqlite_mode}; export + symbols/leaks + "
    "external create/step/destroy)")
