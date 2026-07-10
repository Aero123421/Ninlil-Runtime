if(NOT DEFINED GEN)
    message(FATAL_ERROR "GEN not set")
endif()
if(NOT DEFINED COVERAGE_TEST)
    message(FATAL_ERROR "COVERAGE_TEST not set")
endif()

set(MANIFEST_PATH "${CMAKE_BINARY_DIR}/abi_manifest_coverage.txt")

execute_process(
    COMMAND ${GEN}
    OUTPUT_FILE "${MANIFEST_PATH}"
    RESULT_VARIABLE gen_result
)
if(NOT gen_result EQUAL 0)
    message(FATAL_ERROR "abi manifest generator failed")
endif()

execute_process(
    COMMAND ${COVERAGE_TEST} "${MANIFEST_PATH}"
    RESULT_VARIABLE coverage_result
)
if(NOT coverage_result EQUAL 0)
    message(FATAL_ERROR "abi manifest coverage check failed")
endif()
