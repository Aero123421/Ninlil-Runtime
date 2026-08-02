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
#   - an independent public-API-only consumer exercises the 3-role x
#     4-environment create matrix, Cell Agent fail-closed service authority,
#     2/4-target DesiredState deep-copy/query/list/retry/restart, and four
#     application Services without a private helper.

if(NOT DEFINED NINLIL_SOURCE_DIR
   OR NOT DEFINED NINLIL_PARENT_BUILD_DIR
   OR NOT DEFINED NINLIL_GENERATOR
   OR NOT DEFINED NINLIL_CTEST_COMMAND)
    message(FATAL_ERROR
        "installed Host Runtime smoke requires source/build/generator/ctest")
endif()

# A command-line caller may pass a build directory relative to the repository.
# The installed consumer is configured from its own build directory, where a
# relative CMAKE_PREFIX_PATH would resolve to the wrong location.  Normalize
# the parent once before deriving producer, install, and consumer paths.
get_filename_component(
    NINLIL_PARENT_BUILD_DIR
    "${NINLIL_PARENT_BUILD_DIR}"
    ABSOLUTE
    BASE_DIR "${NINLIL_SOURCE_DIR}")

if(NOT DEFINED NINLIL_SMOKE_WITH_SQLITE)
    set(NINLIL_SMOKE_WITH_SQLITE OFF)
endif()
if(NOT DEFINED NINLIL_SMOKE_DOMAIN_SCHEMA1)
    set(NINLIL_SMOKE_DOMAIN_SCHEMA1 OFF)
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

set(_consumer_source_path
    "${NINLIL_SOURCE_DIR}/tests/cmake/installed_host_runtime_consumer/consumer.c")
file(READ "${_consumer_source_path}" _consumer_source_text)

function(_ninlil_installed_consumer_source_contract source_text out_ok)
    set(_ok TRUE)
    foreach(_required_token
            "CONSUMER_SERVICE_COUNT = 4"
            "CONSUMER_TRANSACTION_COUNT = 3"
            "CONSUMER_PROFILE_COUNT"
            "CONSUMER_EXACT_MAX_TARGETS"
            "NINLIL_ROLE_CELL_AGENT"
            "NINLIL_ENV_PRODUCTION"
            "NINLIL_E_BUFFER_TOO_SMALL"
            "NINLIL_TX_GATE_TEMPORARY"
            "ninlil_service_register("
            "ninlil_submit("
            "ninlil_transaction_query("
            "ninlil_transaction_list("
            "ninlil_capacity_snapshot("
            "ninlil_metrics_snapshot("
            "ninlil_runtime_step("
            "ninlil_runtime_destroy("
            "exercise_after_restart("
            "exercise_public_profile_case("
            "exercise_unknown_profile_rejection("
            "exercise_exact_targets_before_restart("
            "exercise_exact_targets_after_restart("
            "establish_one_isolated_retry_attempt("
            "verify_query_buffer_too_small("
            "verify_four_services_were_restored("
            "create_sqlite_storage(database_path);"
            "status == NINLIL_E_CONFLICT"
            "repeated.kind != NINLIL_SUBMISSION_ALREADY_ADMITTED"
            "conflict.kind != NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT"
            "after_dedupe.record_revision != before_dedupe.record_revision"
            "snapshot.record_revision == saved->record_revision"
            "used != CONSUMER_SERVICE_COUNT"
            "used != evidence->transaction_capacity_used"
            "CONSUMER_REQUIRE(")
        string(FIND "${source_text}" "${_required_token}" _required_hit)
        if(_required_hit EQUAL -1)
            set(_ok FALSE)
        endif()
    endforeach()
    foreach(_forbidden_token
            "runtime_internal.h"
            "tests/support"
            "examples/multi_service_node"
            "ninlil_runtime_private"
            "ninlil_test_")
        string(FIND "${source_text}" "${_forbidden_token}" _forbidden_hit)
        if(NOT _forbidden_hit EQUAL -1)
            set(_ok FALSE)
        endif()
    endforeach()
    set(${out_ok} ${_ok} PARENT_SCOPE)
endfunction()

_ninlil_installed_consumer_source_contract(
    "${_consumer_source_text}" _consumer_contract_ok)
if(NOT _consumer_contract_ok)
    message(FATAL_ERROR
        "installed consumer source contract is incomplete or uses a "
        "private/test/example helper")
endif()
foreach(_mutation_token
        "ninlil_service_register("
        "ninlil_submit("
        "ninlil_transaction_query("
        "ninlil_transaction_list("
        "ninlil_capacity_snapshot("
        "ninlil_metrics_snapshot("
        "ninlil_runtime_step("
        "exercise_after_restart("
        "exercise_public_profile_case("
        "exercise_unknown_profile_rejection("
        "exercise_exact_targets_before_restart("
        "exercise_exact_targets_after_restart("
        "establish_one_isolated_retry_attempt("
        "verify_query_buffer_too_small("
        "verify_four_services_were_restored("
        "create_sqlite_storage(database_path);"
        "status == NINLIL_E_CONFLICT"
        "repeated.kind != NINLIL_SUBMISSION_ALREADY_ADMITTED"
        "conflict.kind != NINLIL_SUBMISSION_IDEMPOTENCY_CONFLICT"
        "after_dedupe.record_revision != before_dedupe.record_revision"
        "snapshot.record_revision == saved->record_revision"
        "used != CONSUMER_SERVICE_COUNT"
        "used != evidence->transaction_capacity_used"
        "CONSUMER_REQUIRE(")
    string(REPLACE "${_mutation_token}" ""
        _consumer_mutant "${_consumer_source_text}")
    _ninlil_installed_consumer_source_contract(
        "${_consumer_mutant}" _consumer_mutant_ok)
    if(_consumer_mutant_ok)
        message(FATAL_ERROR
            "installed consumer source contract failed to reject removal of "
            "'${_mutation_token}'")
    endif()
endforeach()
if(NINLIL_SMOKE_WITH_SQLITE)
    set(_sqlite_mode "sqlite-on")
else()
    set(_sqlite_mode "sqlite-off")
endif()
if(NINLIL_SMOKE_DOMAIN_SCHEMA1)
    set(_domain_mode "domain-on")
else()
    set(_domain_mode "domain-off")
endif()
if(NINLIL_SMOKE_ENABLE_SANITIZERS)
    set(_sanitizer_mode "sanitizers-on")
else()
    set(_sanitizer_mode "sanitizers-off")
endif()

set(_work
    "${NINLIL_PARENT_BUILD_DIR}/installed-host-runtime-tests-off-${_sqlite_mode}-${_domain_mode}-${_sanitizer_mode}")
set(_producer_build "${_work}/producer")
set(_prefix "${_work}/prefix")
set(_consumer_build "${_work}/consumer")
file(REMOVE_RECURSE "${_work}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -S "${NINLIL_SOURCE_DIR}"
        -B "${_producer_build}"
        -G "${NINLIL_GENERATOR}"
        ${_compiler_args}
        -DCMAKE_BUILD_TYPE=Release
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_BUILD_HOST_RUNTIME=ON
        -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=${NINLIL_SMOKE_WITH_SQLITE}
        -DNINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=${NINLIL_SMOKE_DOMAIN_SCHEMA1}
        -DNINLIL_ENABLE_STRICT_WARNINGS=ON
        -DNINLIL_ENABLE_SANITIZERS=${NINLIL_SMOKE_ENABLE_SANITIZERS}
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
# Domain schema1: when producer enabled the feature, installed public archive
# must expose the same Domain-backed symbols as the private gate target.
# Default-OFF producers must keep Domain symbols absent.
if(DEFINED NINLIL_SMOKE_DOMAIN_SCHEMA1 AND NINLIL_SMOKE_DOMAIN_SCHEMA1)
    foreach(_domain_symbol
            ninlil_domain_schema1_service_register
            ninlil_domain_schema1_service_registry_restore
            ninlil_domain_schema1_owner_run_storage_recovery
            ninlil_domain_schema1_owner_t7_publication_gate)
        if(NOT _nm_out MATCHES "[ \t]_?${_domain_symbol}([\r\n]|$)")
            message(FATAL_ERROR
                "Domain-ON public Runtime archive lacks '${_domain_symbol}'")
        endif()
    endforeach()
    message(STATUS
        "installed Domain-ON public Runtime nm evidence: Domain symbols present")
else()
    foreach(_domain_symbol
            ninlil_domain_schema1_service_register
            ninlil_domain_schema1_service_registry_restore
            ninlil_domain_schema1_owner_run_storage_recovery)
        if(_nm_out MATCHES "[ \t]_?${_domain_symbol}([\r\n]|$)")
            message(FATAL_ERROR
                "Domain-OFF public Runtime archive must not expose "
                "'${_domain_symbol}'")
        endif()
    endforeach()
endif()
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

# ASan global descriptors deliberately carry translation-unit paths. Keep
# exact archive path-hygiene enforcement on every normal shipping build, and
# skip only this non-ship binary-content check for an explicitly instrumented
# evidence build. Package metadata/source-graph leak checks remain mandatory.
if(NOT NINLIL_SMOKE_ENABLE_SANITIZERS)
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
endif()

set(_consumer_args
    -S "${NINLIL_SOURCE_DIR}/tests/cmake/installed_host_runtime_consumer"
    -B "${_consumer_build}"
    -G "${NINLIL_GENERATOR}"
    ${_compiler_args}
    "-DCMAKE_PREFIX_PATH=${_prefix}"
    -DCMAKE_MAP_IMPORTED_CONFIG_DEBUG=DEBUG
    -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    -DNINLIL_CONSUMER_EXPECT_SQLITE=${NINLIL_SMOKE_WITH_SQLITE}
    -DNINLIL_CONSUMER_EXPECT_DOMAIN_NOT_READY=${NINLIL_SMOKE_DOMAIN_SCHEMA1}
    -DNINLIL_CONSUMER_ENABLE_SANITIZERS=${NINLIL_SMOKE_ENABLE_SANITIZERS}
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

set(_consumer_compile_commands
    "${_consumer_build}/compile_commands.json")
if(NOT EXISTS "${_consumer_compile_commands}")
    message(FATAL_ERROR
        "installed consumer did not emit compile_commands.json")
endif()
file(READ "${_consumer_compile_commands}" _consumer_compile_text)
foreach(_forbidden_compile_path
        "${NINLIL_SOURCE_DIR}/include"
        "${NINLIL_SOURCE_DIR}/src"
        "${NINLIL_SOURCE_DIR}/examples"
        "${NINLIL_SOURCE_DIR}/tests/support"
        "${_producer_build}")
    string(FIND
        "${_consumer_compile_text}" "${_forbidden_compile_path}"
        _forbidden_compile_hit)
    if(NOT _forbidden_compile_hit EQUAL -1)
        message(FATAL_ERROR
            "installed consumer compile graph leaks producer/source path "
            "'${_forbidden_compile_path}'")
    endif()
endforeach()
if(EXISTS "${_consumer_build}/build.ninja")
    file(READ "${_consumer_build}/build.ninja" _consumer_link_graph)
    foreach(_forbidden_link_token
            "ninlil_runtime_private"
            "runtime_internal"
            "tests/support"
            "examples/multi_service_node")
        string(FIND
            "${_consumer_link_graph}" "${_forbidden_link_token}"
            _forbidden_link_hit)
        if(NOT _forbidden_link_hit EQUAL -1)
            message(FATAL_ERROR
                "installed consumer link graph contains forbidden dependency "
                "'${_forbidden_link_token}'")
        endif()
    endforeach()
endif()
set(_consumer_test_command
    "${NINLIL_CTEST_COMMAND}" --test-dir "${_consumer_build}"
    -C "${_consumer_config}" --output-on-failure)
if(NINLIL_SMOKE_ENABLE_SANITIZERS)
    set(_asan_options "halt_on_error=1")
    if(CMAKE_HOST_APPLE)
        string(APPEND _asan_options ":detect_leaks=0")
    endif()
    set(_consumer_test_command
        "${CMAKE_COMMAND}" -E env
        "ASAN_OPTIONS=${_asan_options}"
        "UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1"
        ${_consumer_test_command})
endif()
execute_process(
    COMMAND ${_consumer_test_command}
    RESULT_VARIABLE _consumer_test_rc
    OUTPUT_VARIABLE _consumer_test_out
    ERROR_VARIABLE _consumer_test_err)
if(NOT _consumer_test_rc EQUAL 0)
    message(FATAL_ERROR
        "installed consumer lifecycle/fail-closed check failed:\n"
        "${_consumer_test_out}${_consumer_test_err}")
endif()

file(REMOVE_RECURSE "${_work}")
if(NINLIL_SMOKE_DOMAIN_SCHEMA1)
    set(_lifecycle_claim "external create fail-closed NINLIL_E_UNSUPPORTED")
else()
    set(_lifecycle_claim
        "external four-Service durable lifecycle + restart/dedupe/query/list")
endif()
message(STATUS
    "installed Host Runtime tests-OFF smoke: OK "
    "(${_sqlite_mode}; ${_domain_mode}; ${_sanitizer_mode}; "
    "export + symbols/leaks + "
    "${_lifecycle_claim})")
