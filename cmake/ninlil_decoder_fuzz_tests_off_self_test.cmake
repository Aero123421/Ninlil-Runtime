if(NOT DEFINED NINLIL_SOURCE_DIR OR NOT DEFINED NINLIL_BINARY_DIR
        OR NOT DEFINED NINLIL_GENERATOR)
    message(FATAL_ERROR "decoder fuzz tests-OFF self-test arguments missing")
endif()

execute_process(
    COMMAND ${CMAKE_COMMAND}
        -S ${NINLIL_SOURCE_DIR}
        -B ${NINLIL_BINARY_DIR}
        -G ${NINLIL_GENERATOR}
        -DNINLIL_BUILD_TESTS=OFF
        -DNINLIL_BUILD_DECODER_FUZZERS=ON
        -DNINLIL_BUILD_HOST_RUNTIME=OFF
        -DNINLIL_BUILD_FABRIC_V1=OFF
        -DNINLIL_BUILD_POSIX_TLS_V1=OFF
        -DNINLIL_BUILD_POSIX_USB_SERIAL_V1=OFF
        -DNINLIL_BUILD_POSIX_SQLITE_STORAGE=OFF
    RESULT_VARIABLE _result
    OUTPUT_VARIABLE _stdout
    ERROR_VARIABLE _stderr)

if(_result EQUAL 0)
    message(FATAL_ERROR
        "fuzzers-ON/tests-OFF configure unexpectedly succeeded (target-0 false green)")
endif()
set(_output "${_stdout}\n${_stderr}")
if(NOT _output MATCHES
        "NINLIL_BUILD_DECODER_FUZZERS requires NINLIL_BUILD_TESTS=ON")
    message(FATAL_ERROR
        "fuzzers-ON/tests-OFF configure failed without the canonical diagnostic:\n${_output}")
endif()

message(STATUS "decoder fuzz tests-OFF configure self-test: expected failure observed")
