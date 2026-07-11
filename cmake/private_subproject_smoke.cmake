if(NOT DEFINED NINLIL_SOURCE_DIR
   OR NOT DEFINED NINLIL_SMOKE_SOURCE_DIR
   OR NOT DEFINED NINLIL_SMOKE_BINARY_DIR
   OR NOT DEFINED NINLIL_GENERATOR
   OR NOT DEFINED NINLIL_CTEST_COMMAND)
    message(FATAL_ERROR "private subproject smoke arguments are incomplete")
endif()

file(REMOVE_RECURSE "${NINLIL_SMOKE_BINARY_DIR}")

execute_process(
    COMMAND "${CMAKE_COMMAND}"
        -S "${NINLIL_SMOKE_SOURCE_DIR}"
        -B "${NINLIL_SMOKE_BINARY_DIR}"
        -G "${NINLIL_GENERATOR}"
        -DNINLIL_SOURCE_DIR=${NINLIL_SOURCE_DIR}
        -DBUILD_SHARED_LIBS=ON
    RESULT_VARIABLE _configure_result
    OUTPUT_VARIABLE _configure_output
    ERROR_VARIABLE _configure_error
)
if(NOT _configure_result EQUAL 0)
    message(FATAL_ERROR
        "subproject configure failed\n${_configure_output}\n${_configure_error}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${NINLIL_SMOKE_BINARY_DIR}"
        --target ninlil_subproject_public_consumer
    RESULT_VARIABLE _build_result
    OUTPUT_VARIABLE _build_output
    ERROR_VARIABLE _build_error
)
if(NOT _build_result EQUAL 0)
    message(FATAL_ERROR
        "subproject build failed\n${_build_output}\n${_build_error}")
endif()
include("${NINLIL_SMOKE_BINARY_DIR}/ninlil-smoke-paths.cmake")
if(EXISTS "${NINLIL_PRIVATE_ARCHIVE}")
    message(FATAL_ERROR "default public build unexpectedly built private archive")
endif()
execute_process(
    COMMAND "${NINLIL_PUBLIC_CONSUMER}"
    RESULT_VARIABLE _public_run_result
)
if(NOT _public_run_result EQUAL 0)
    message(FATAL_ERROR "public subproject consumer failed at runtime")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" --build "${NINLIL_SMOKE_BINARY_DIR}"
        --target ninlil_runtime_private ninlil_subproject_private_consumer
    RESULT_VARIABLE _private_build_result
    OUTPUT_VARIABLE _private_build_output
    ERROR_VARIABLE _private_build_error
)
if(NOT _private_build_result EQUAL 0)
    message(FATAL_ERROR
        "private target build failed\n${_private_build_output}\n${_private_build_error}")
endif()
execute_process(
    COMMAND "${NINLIL_PRIVATE_CONSUMER}"
    RESULT_VARIABLE _private_run_result
)
if(NOT _private_run_result EQUAL 0)
    message(FATAL_ERROR "private subproject consumer failed at runtime")
endif()

execute_process(
    COMMAND "${NINLIL_CTEST_COMMAND}" --test-dir "${NINLIL_SMOKE_BINARY_DIR}" -N
    RESULT_VARIABLE _ctest_result
    OUTPUT_VARIABLE _ctest_output
    ERROR_VARIABLE _ctest_error
)
if(NOT _ctest_result EQUAL 0 OR NOT _ctest_output MATCHES "Total Tests: 0")
    message(FATAL_ERROR
        "subproject test isolation failed\n${_ctest_output}\n${_ctest_error}")
endif()

if(NINLIL_SANITIZER_SUPPORTED)
    set(_san_binary "${NINLIL_SMOKE_BINARY_DIR}-san")
    file(REMOVE_RECURSE "${_san_binary}")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            -S "${NINLIL_SMOKE_SOURCE_DIR}"
            -B "${_san_binary}"
            -G "${NINLIL_GENERATOR}"
            -DNINLIL_SOURCE_DIR=${NINLIL_SOURCE_DIR}
            -DNINLIL_ENABLE_SANITIZERS=ON
            -DBUILD_SHARED_LIBS=ON
        RESULT_VARIABLE _san_configure_result
        OUTPUT_VARIABLE _san_configure_output
        ERROR_VARIABLE _san_configure_error
    )
    if(NOT _san_configure_result EQUAL 0)
        message(FATAL_ERROR
            "sanitizer subproject configure failed\n${_san_configure_output}\n${_san_configure_error}")
    endif()
    execute_process(
        COMMAND "${CMAKE_COMMAND}" --build "${_san_binary}"
            --target ninlil_subproject_private_consumer
        RESULT_VARIABLE _san_build_result
        OUTPUT_VARIABLE _san_build_output
        ERROR_VARIABLE _san_build_error
    )
    if(NOT _san_build_result EQUAL 0)
        message(FATAL_ERROR
            "sanitizer private final link failed\n${_san_build_output}\n${_san_build_error}")
    endif()
    include("${_san_binary}/ninlil-smoke-paths.cmake")
    execute_process(
        COMMAND "${CMAKE_COMMAND}" -E env
            ASAN_OPTIONS=detect_leaks=0:halt_on_error=1
            UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
            "${NINLIL_PRIVATE_CONSUMER}"
        RESULT_VARIABLE _san_run_result
        OUTPUT_VARIABLE _san_run_output
        ERROR_VARIABLE _san_run_error
    )
    if(NOT _san_run_result EQUAL 0)
        message(FATAL_ERROR
            "sanitizer private consumer failed\n${_san_run_output}\n${_san_run_error}")
    endif()
endif()
