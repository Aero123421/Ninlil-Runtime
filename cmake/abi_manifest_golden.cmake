if(NOT DEFINED GEN)
    message(FATAL_ERROR "GEN not set")
endif()
if(NOT DEFINED GOLDEN_DIR)
    message(FATAL_ERROR "GOLDEN_DIR not set")
endif()

set(ACTUAL "${CMAKE_BINARY_DIR}/abi_manifest_actual.txt")

execute_process(
    COMMAND ${GEN}
    OUTPUT_FILE "${ACTUAL}"
    RESULT_VARIABLE gen_result
)
if(NOT gen_result EQUAL 0)
    message(FATAL_ERROR "abi manifest generator failed")
endif()

file(READ "${ACTUAL}" actual_content)
if(actual_content MATCHES "target\\.id=([^\n]+)")
    set(TARGET_ID "${CMAKE_MATCH_1}")
else()
    message(FATAL_ERROR "abi manifest missing target.id")
endif()

set(GOLDEN "${GOLDEN_DIR}/${TARGET_ID}.manifest")
if(NOT EXISTS "${GOLDEN}")
    message(STATUS "abi manifest golden skipped: no golden for target ${TARGET_ID}")
    return()
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND} -E compare_files "${GOLDEN}" "${ACTUAL}"
    RESULT_VARIABLE cmp_result
)
if(NOT cmp_result EQUAL 0)
    message(FATAL_ERROR "abi manifest golden mismatch for target ${TARGET_ID}")
endif()
