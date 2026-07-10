if(NOT DEFINED GEN)
    message(FATAL_ERROR "GEN not set")
endif()

execute_process(
    COMMAND ${GEN}
    OUTPUT_FILE "${CMAKE_BINARY_DIR}/abi_manifest_repeat_a.txt"
    RESULT_VARIABLE gen_a_result
)
if(NOT gen_a_result EQUAL 0)
    message(FATAL_ERROR "abi manifest generator failed (run a)")
endif()

execute_process(
    COMMAND ${GEN}
    OUTPUT_FILE "${CMAKE_BINARY_DIR}/abi_manifest_repeat_b.txt"
    RESULT_VARIABLE gen_b_result
)
if(NOT gen_b_result EQUAL 0)
    message(FATAL_ERROR "abi manifest generator failed (run b)")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND} -E compare_files
        "${CMAKE_BINARY_DIR}/abi_manifest_repeat_a.txt"
        "${CMAKE_BINARY_DIR}/abi_manifest_repeat_b.txt"
    RESULT_VARIABLE cmp_result
)
if(NOT cmp_result EQUAL 0)
    message(FATAL_ERROR "abi manifest is not repeatable for this toolchain/target")
endif()
