# ADR-0021 MFDT private host CTest registration (default-OFF).
# Source list authority: cmake/ninlil_mfdt_v1_sources.cmake (single).
# Not installed. Not public ABI. Not HIL/RF/power-cut claim.
# SPEC-ONLY gates remain in cmake/ninlil_mfdt_ctest.cmake (always under tests-ON).

include(${CMAKE_CURRENT_LIST_DIR}/ninlil_mfdt_v1_sources.cmake)

if(NOT NINLIL_ENABLE_MFDT_V1_PRIVATE)
    return()
endif()

if(NOT NINLIL_BUILD_TESTS)
    return()
endif()

# Private static library — EXCLUDE_FROM_ALL, never installed.
add_library(ninlil_mfdt_v1_private STATIC EXCLUDE_FROM_ALL
    ${NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES}
)
target_include_directories(ninlil_mfdt_v1_private PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(ninlil_mfdt_v1_private PRIVATE
    NINLIL_MFDT_V1_PRIVATE=1
)
set_target_properties(ninlil_mfdt_v1_private PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
    POSITION_INDEPENDENT_CODE ON
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_private)

foreach(_mfdt_src IN LISTS NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES)
    set_source_files_properties(${_mfdt_src} PROPERTIES
        COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=16384;-Wvla"
    )
endforeach()

# ---- Unit: crypto / geometry / CU -----------------------------------------
add_executable(ninlil_mfdt_v1_unit_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_unit_test.c
)
target_include_directories(ninlil_mfdt_v1_unit_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_unit_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_unit_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_unit_test)
add_test(NAME mfdt_v1_unit_private COMMAND ninlil_mfdt_v1_unit_test)

# ---- E2E happy / negative / crash / lifecycle ----------------------------
add_executable(ninlil_mfdt_v1_e2e_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_e2e_test.c
)
target_include_directories(ninlil_mfdt_v1_e2e_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_e2e_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_e2e_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_e2e_test)
add_test(NAME mfdt_v1_e2e_private COMMAND ninlil_mfdt_v1_e2e_test)

# ---- Lifecycle reuse (10k) -----------------------------------------------
add_executable(ninlil_mfdt_v1_lifecycle_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_lifecycle_test.c
)
target_include_directories(ninlil_mfdt_v1_lifecycle_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_lifecycle_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_lifecycle_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_lifecycle_test)
add_test(NAME mfdt_v1_lifecycle_private COMMAND ninlil_mfdt_v1_lifecycle_test)
set_tests_properties(mfdt_v1_lifecycle_private PROPERTIES TIMEOUT 120)

# ---- Independent vector wire KAT (not self-referential lab-only) ----------
add_executable(ninlil_mfdt_v1_kat_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_kat_test.c
)
target_include_directories(ninlil_mfdt_v1_kat_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_kat_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_kat_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_kat_test)
add_test(NAME mfdt_v1_kat_private COMMAND ninlil_mfdt_v1_kat_test)

# ---- Repaired contract promotion witness (phase-1 RED -> production GREEN) -
add_executable(ninlil_mfdt_v1_contract_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_contract_red_test.c
)
target_include_directories(ninlil_mfdt_v1_contract_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_contract_test PRIVATE
    ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_contract_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_contract_test)
add_test(NAME mfdt_v1_contract_green
    COMMAND ninlil_mfdt_v1_contract_test)

# ---- Fault / transactional FULL / expiry / adversarial codec ------------
add_executable(ninlil_mfdt_v1_fault_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_fault_test.c
)
target_include_directories(ninlil_mfdt_v1_fault_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_fault_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_fault_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_fault_test)
add_test(NAME mfdt_v1_fault_private COMMAND ninlil_mfdt_v1_fault_test)

# ---- NCL1 / pipeline / runtime seam ---------------------------------------
add_executable(ninlil_mfdt_v1_pipeline_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_pipeline_test.c
)
target_include_directories(ninlil_mfdt_v1_pipeline_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_pipeline_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_pipeline_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_pipeline_test)
add_test(NAME mfdt_v1_pipeline_private COMMAND ninlil_mfdt_v1_pipeline_test)

# Media FULL CU / restart / session negotiate (software, not physical HIL).
add_executable(ninlil_mfdt_v1_media_cu_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_media_cu_test.c
)
target_include_directories(ninlil_mfdt_v1_media_cu_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_media_cu_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_media_cu_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_media_cu_test)
add_test(NAME mfdt_v1_media_cu_private COMMAND ninlil_mfdt_v1_media_cu_test)

# Two-endpoint transport sim: WOULD_BLOCK / drop / no-provider / restart.
add_executable(ninlil_mfdt_v1_transport_sim_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_transport_sim_test.c
)
target_include_directories(ninlil_mfdt_v1_transport_sim_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_transport_sim_test PRIVATE ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_transport_sim_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_transport_sim_test)
add_test(NAME mfdt_v1_transport_sim_private COMMAND ninlil_mfdt_v1_transport_sim_test)

# ESP store adapter COMMIT_UNKNOWN fail-closed + handle-width (host mock).
# Compiles mfdt_v1_store_esp.c (not host lab store) + portable HIL gate + crypto.
add_executable(ninlil_mfdt_v1_esp_store_cu_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_esp_store_cu_test.c
    src/runtime/mfdt_v1/mfdt_v1_store_esp.c
    src/runtime/mfdt_v1/mfdt_v1_hil_gate.c
    src/runtime/mfdt_v1/mfdt_v1_target_alloc.c
    src/runtime/mfdt_v1/mfdt_v1_crypto.c
    src/runtime/mfdt_v1/mfdt_v1_wire.c
)
target_include_directories(ninlil_mfdt_v1_esp_store_cu_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_definitions(ninlil_mfdt_v1_esp_store_cu_test PRIVATE
    NINLIL_MFDT_V1_PRIVATE=1
)
set_target_properties(ninlil_mfdt_v1_esp_store_cu_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_esp_store_cu_test)
add_test(NAME mfdt_v1_esp_store_cu_private COMMAND ninlil_mfdt_v1_esp_store_cu_test)

# Exact Host typed provider: guarantees, complete final-view atomicity,
# capacity/union ceilings, deterministic faults, and snapshot serialization.
add_executable(ninlil_mfdt_v1_host_store_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_host_store_test.c
)
target_include_directories(ninlil_mfdt_v1_host_store_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ninlil_mfdt_v1_host_store_test PRIVATE
    ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_host_store_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_host_store_test)
add_test(NAME mfdt_v1_host_store_private
    COMMAND ninlil_mfdt_v1_host_store_test)

# Test-only typed provider that materializes every post-CU durable view. The
# fixture is linked only into this and the integrated coordinator acceptance
# binary; it is never part of any production/ESP source list.
add_executable(ninlil_mfdt_v1_host_store_mutation_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_host_store_mutation_test.c
    tests/runtime/mfdt_v1/mfdt_v1_typed_mutation_provider.c
)
target_include_directories(ninlil_mfdt_v1_host_store_mutation_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime/mfdt_v1
)
target_link_libraries(ninlil_mfdt_v1_host_store_mutation_test PRIVATE
    ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_host_store_mutation_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_host_store_mutation_test)
add_test(NAME mfdt_v1_host_store_mutation_private
    COMMAND ninlil_mfdt_v1_host_store_mutation_test)

# Malicious typed-provider shapes and initialization aliases.  This isolates
# adapter fail-closed/cleanup behavior from the reference Host provider.
add_executable(ninlil_mfdt_v1_store_port_adversarial_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_store_port_adversarial_test.c
)
target_include_directories(ninlil_mfdt_v1_store_port_adversarial_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ninlil_mfdt_v1_store_port_adversarial_test PRIVATE
    ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_store_port_adversarial_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_store_port_adversarial_test)
add_test(NAME mfdt_v1_store_port_adversarial_private
    COMMAND ninlil_mfdt_v1_store_port_adversarial_test)

# Slot-local memory binding: valid disjoint layout plus behavioral rejection of
# unaligned/overlapping regions and aliases that a successful init would zero.
add_executable(ninlil_mfdt_v1_host_slot_contract_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_host_slot_contract_test.c
)
target_include_directories(ninlil_mfdt_v1_host_slot_contract_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ninlil_mfdt_v1_host_slot_contract_test PRIVATE
    ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_host_slot_contract_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_host_slot_contract_test)
add_test(NAME mfdt_v1_host_slot_contract_private
    COMMAND ninlil_mfdt_v1_host_slot_contract_test)

# Exact four-slot Host coordinator: ownership guards, routing, deterministic
# restart, TOCTOU-free snapshot recovery, scheduling, CU global fence, and
# actual two-owner NCL1 transfer progress.
add_executable(ninlil_mfdt_v1_host_coordinator_acceptance_test
    EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_host_coordinator_acceptance_test.c
    tests/runtime/mfdt_v1/mfdt_v1_typed_mutation_provider.c
)
target_include_directories(
    ninlil_mfdt_v1_host_coordinator_acceptance_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime/mfdt_v1
)
target_link_libraries(
    ninlil_mfdt_v1_host_coordinator_acceptance_test PRIVATE
    ninlil_mfdt_v1_private)
set_target_properties(
    ninlil_mfdt_v1_host_coordinator_acceptance_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(
    ninlil_mfdt_v1_host_coordinator_acceptance_test)
add_test(NAME mfdt_v1_host_coordinator_acceptance_private
    COMMAND ninlil_mfdt_v1_host_coordinator_acceptance_test)

# Exact receiver request KATs over the typed Host provider: semantic reject
# matrices, immutable NRC1 conflict handling, stateless malformed OPEN,
# short-BIND silence, and request-triggered terminal three-operation FULLs.
add_executable(ninlil_mfdt_v1_request_kat_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_request_kat_test.c
)
target_include_directories(ninlil_mfdt_v1_request_kat_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(ninlil_mfdt_v1_request_kat_test PRIVATE
    ninlil_mfdt_v1_private)
set_target_properties(ninlil_mfdt_v1_request_kat_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_request_kat_test)
add_test(NAME mfdt_v1_request_kat_private
    COMMAND ninlil_mfdt_v1_request_kat_test)

# ---- Instance-local Runtime owner / existing Runtime Storage Port ---------
if(NINLIL_POSIX_LAB_PLATFORM_ENABLED)
    add_executable(ninlil_mfdt_v1_runtime_owner_test EXCLUDE_FROM_ALL
        tests/runtime/mfdt_v1/mfdt_v1_runtime_owner_test.c
    )
    target_include_directories(ninlil_mfdt_v1_runtime_owner_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
    )
    target_compile_definitions(ninlil_mfdt_v1_runtime_owner_test PRIVATE
        NINLIL_MFDT_V1_PRIVATE=1
    )
    target_link_libraries(ninlil_mfdt_v1_runtime_owner_test PRIVATE
        ninlil_runtime_private
        ninlil_posix_lab_platform
        ninlil
    )
    set_target_properties(ninlil_mfdt_v1_runtime_owner_test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_posix_sqlite_feature_macros(
        ninlil_mfdt_v1_runtime_owner_test)
    ninlil_apply_strict_warnings(ninlil_mfdt_v1_runtime_owner_test)
    add_test(NAME mfdt_v1_runtime_owner_private
        COMMAND ninlil_mfdt_v1_runtime_owner_test)
endif()

# Deterministic in-memory fault injection for NMS1 bootstrap CU
# ABSENT/NEW/PARTIAL/EXTRA/THIRD, foreign-row fencing, leak closure, and
# Bearer -> sidecar -> Foundation teardown order. Software-only, not HIL.
add_executable(ninlil_mfdt_v1_runtime_sidecar_fault_test EXCLUDE_FROM_ALL
    tests/runtime/mfdt_v1/mfdt_v1_runtime_sidecar_fault_test.c
)
target_include_directories(
    ninlil_mfdt_v1_runtime_sidecar_fault_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/support
)
target_compile_definitions(
    ninlil_mfdt_v1_runtime_sidecar_fault_test PRIVATE
    NINLIL_MFDT_V1_PRIVATE=1
)
target_link_libraries(
    ninlil_mfdt_v1_runtime_sidecar_fault_test PRIVATE
    ninlil_runtime_private
    ninlil_test_storage_fixture
    ninlil_test_platform_fixtures
    ninlil_test_typed_bearer_fixture
    ninlil
)
set_target_properties(
    ninlil_mfdt_v1_runtime_sidecar_fault_test PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
    NINLIL_TEST_ONLY_ARTIFACT TRUE
)
ninlil_apply_strict_warnings(ninlil_mfdt_v1_runtime_sidecar_fault_test)
add_test(NAME mfdt_v1_runtime_sidecar_fault_private
    COMMAND ninlil_mfdt_v1_runtime_sidecar_fault_test)

# Real POSIX SQLite cold close/reopen.  This remains Host-only and conditional
# on the already-discovered provider; missing SQLite never breaks portable
# MFDT builds.  It is intentionally outside the always-present witness
# manifest so an unavailable optional dependency cannot become a false pass.
if(NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
    add_executable(ninlil_mfdt_v1_host_sqlite_restart_test
        EXCLUDE_FROM_ALL
        tests/runtime/mfdt_v1/mfdt_v1_host_sqlite_restart_test.c
    )
    target_include_directories(
        ninlil_mfdt_v1_host_sqlite_restart_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/mfdt_v1
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix/include
    )
    target_link_libraries(
        ninlil_mfdt_v1_host_sqlite_restart_test PRIVATE
        ninlil_mfdt_v1_private
        ninlil_posix_sqlite_storage
    )
    set_target_properties(
        ninlil_mfdt_v1_host_sqlite_restart_test PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF
        NINLIL_TEST_ONLY_ARTIFACT TRUE
    )
    ninlil_apply_posix_sqlite_feature_macros(
        ninlil_mfdt_v1_host_sqlite_restart_test)
    ninlil_apply_strict_warnings(
        ninlil_mfdt_v1_host_sqlite_restart_test)
    add_test(NAME mfdt_v1_host_sqlite_restart_private
        COMMAND ninlil_mfdt_v1_host_sqlite_restart_test)
endif()

add_test(NAME mfdt_v1_host_acceptance_runner
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_v1_host_acceptance_runner.py
        --build-dir ${CMAKE_BINARY_DIR}
        --manifest
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/runtime/mfdt_v1/mfdt_v1_host_acceptance_manifest.json
        --mode green
)
set_tests_properties(mfdt_v1_host_acceptance_runner PROPERTIES
    FIXTURES_REQUIRED mfdt_v1_private_build
    TIMEOUT 300
)

# HIL runner: honest NOT_RUN without hardware (exit 0 archives residual).
add_test(NAME mfdt_v1_hil_runner_not_run
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/ninlil_hil/mfdt_v1_hil_runner.py
        --out ${CMAKE_BINARY_DIR}/mfdt_v1_hil_not_run.json
)

# ESP map contract dry-run (no docker required).
add_test(NAME mfdt_v1_esp_map_proof_dry_run
    COMMAND ${CMAKE_COMMAND} -E env NINLIL_ESP_CI_DRY_RUN=1
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_v1_esp_idf_map_proof.sh
)

# Install/symbol boundary: private MFDT must not appear in installed runtime.
add_test(NAME mfdt_v1_install_symbol_boundary
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_v1_install_boundary_gate.py
        --build-dir ${CMAKE_BINARY_DIR}
)
# Footprint budget gate (static sizes; ESP map residual when no ELF).
add_test(NAME mfdt_v1_footprint_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_v1_footprint_gate.py
)

# ESP DRAM budget gate self-test (zero-row fail-closed without device map).
add_test(NAME mfdt_v1_esp_dram_budget_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_v1_esp_dram_budget_gate.py
        self-test
)

# Source/archive boundary gate: the Host owner/provider stays out of the ESP
# one-slot source set, public install, and installed archive.
add_test(NAME mfdt_v1_host_profile_boundary_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_v1_host_profile_boundary_gate.py
        check
        --root ${CMAKE_CURRENT_SOURCE_DIR}
        --build-dir ${CMAKE_BINARY_DIR}
)
add_test(NAME mfdt_v1_host_profile_boundary_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/mfdt_v1_host_profile_boundary_gate.py
        self-test
)

set(_mfdt_v1_test_tgts
    ninlil_runtime_private
    ninlil_mfdt_v1_unit_test
    ninlil_mfdt_v1_e2e_test
    ninlil_mfdt_v1_lifecycle_test
    ninlil_mfdt_v1_fault_test
    ninlil_mfdt_v1_kat_test
    ninlil_mfdt_v1_contract_test
    ninlil_mfdt_v1_pipeline_test
    ninlil_mfdt_v1_media_cu_test
    ninlil_mfdt_v1_transport_sim_test
    ninlil_mfdt_v1_esp_store_cu_test
    ninlil_mfdt_v1_host_store_test
    ninlil_mfdt_v1_host_store_mutation_test
    ninlil_mfdt_v1_store_port_adversarial_test
    ninlil_mfdt_v1_host_slot_contract_test
    ninlil_mfdt_v1_host_coordinator_acceptance_test
    ninlil_mfdt_v1_request_kat_test
    ninlil_mfdt_v1_runtime_sidecar_fault_test
)
set(_mfdt_v1_test_names
    mfdt_v1_unit_private
    mfdt_v1_e2e_private
    mfdt_v1_lifecycle_private
    mfdt_v1_fault_private
    mfdt_v1_kat_private
    mfdt_v1_contract_green
    mfdt_v1_pipeline_private
    mfdt_v1_media_cu_private
    mfdt_v1_transport_sim_private
    mfdt_v1_esp_store_cu_private
    mfdt_v1_host_store_private
    mfdt_v1_host_store_mutation_private
    mfdt_v1_store_port_adversarial_private
    mfdt_v1_host_slot_contract_private
    mfdt_v1_host_coordinator_acceptance_private
    mfdt_v1_request_kat_private
    mfdt_v1_runtime_sidecar_fault_private
    mfdt_v1_host_profile_boundary_gate
)
if(NINLIL_POSIX_LAB_PLATFORM_ENABLED)
    list(APPEND _mfdt_v1_test_tgts
        ninlil_mfdt_v1_runtime_owner_test)
    list(APPEND _mfdt_v1_test_names
        mfdt_v1_runtime_owner_private)
endif()
if(NINLIL_POSIX_SQLITE_STORAGE_ENABLED)
    list(APPEND _mfdt_v1_test_tgts
        ninlil_mfdt_v1_host_sqlite_restart_test)
    list(APPEND _mfdt_v1_test_names
        mfdt_v1_host_sqlite_restart_private)
endif()

set_tests_properties(${_mfdt_v1_test_names}
    PROPERTIES FIXTURES_REQUIRED mfdt_v1_private_build)
add_test(NAME mfdt_v1_private_build
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR}
        --target ${_mfdt_v1_test_tgts}
)
set_tests_properties(mfdt_v1_private_build PROPERTIES
    FIXTURES_SETUP mfdt_v1_private_build)
