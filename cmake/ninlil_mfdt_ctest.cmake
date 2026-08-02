# ADR-0021 Proposed multi-frame durable transfer SPEC-ONLY gates.
# Four authority systems: generator / Python / Node / C11.
# No implementation, HIL, public ABI, or RELEASE_SUPPORTED claim.
# Included only under NINLIL_BUILD_TESTS=ON (not tests-OFF / not install).
#
# This file is the dedicated MFDT CMake authority surface. Acceptance gate
# pins this file's content digest and semantic inventory — not whole-repo
# CMakeLists.txt — so unrelated feature wiring cannot invalidate MFDT.

if(NOT NINLIL_BUILD_TESTS)
    return()
endif()

add_test(
    NAME multi_frame_durable_transfer_vector_oracle
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_spec_vector_gen.py
        --check
)
add_test(
    NAME multi_frame_durable_transfer_vector_oracle_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_spec_vector_gen.py
        --self-test
)
add_test(
    NAME multi_frame_durable_transfer_python_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_spec_gate.py
        --check
)
add_test(
    NAME multi_frame_durable_transfer_python_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_spec_gate.py
        --self-test
)
add_test(
    NAME multi_frame_durable_transfer_node_gate
    COMMAND ${NINLIL_NODE_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_spec_gate.mjs
        --check
)
add_test(
    NAME multi_frame_durable_transfer_node_gate_self_test
    COMMAND ${NINLIL_NODE_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_spec_gate.mjs
        --self-test
)
add_executable(ninlil_multi_frame_durable_transfer_c_gate_test
    tests/model/multi_frame_durable_transfer_c_gate_test.c
)
target_include_directories(ninlil_multi_frame_durable_transfer_c_gate_test PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/model
)
set_target_properties(ninlil_multi_frame_durable_transfer_c_gate_test PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED ON
    C_EXTENSIONS OFF
)
ninlil_apply_strict_warnings(ninlil_multi_frame_durable_transfer_c_gate_test)
add_test(
    NAME multi_frame_durable_transfer_c_gate
    COMMAND ninlil_multi_frame_durable_transfer_c_gate_test
        --check
        ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(
    NAME multi_frame_durable_transfer_c_gate_self_test
    COMMAND ninlil_multi_frame_durable_transfer_c_gate_test
        --self-test
        ${CMAKE_CURRENT_SOURCE_DIR}
)
add_test(
    NAME multi_frame_durable_transfer_acceptance_gate
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_acceptance_gate.py
        --check
)
add_test(
    NAME multi_frame_durable_transfer_acceptance_gate_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/multi_frame_durable_transfer_acceptance_gate.py
        --self-test
)
set_tests_properties(
    multi_frame_durable_transfer_vector_oracle_self_test
    multi_frame_durable_transfer_python_gate
    multi_frame_durable_transfer_python_gate_self_test
    multi_frame_durable_transfer_node_gate
    multi_frame_durable_transfer_node_gate_self_test
    multi_frame_durable_transfer_c_gate
    multi_frame_durable_transfer_c_gate_self_test
    multi_frame_durable_transfer_acceptance_gate
    multi_frame_durable_transfer_acceptance_gate_self_test
    PROPERTIES DEPENDS multi_frame_durable_transfer_vector_oracle
)
