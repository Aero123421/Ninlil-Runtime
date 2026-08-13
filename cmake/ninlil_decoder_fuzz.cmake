# Seed authority runs in the ordinary test graph even when the fuzz binaries
# stay OFF. It writes only to a temporary directory during its self-test.
add_test(
    NAME decoder_fuzz_seed_corpus_self_test
    COMMAND ${Python3_EXECUTABLE}
        ${CMAKE_CURRENT_SOURCE_DIR}/tools/decoder_fuzz_seed_corpus.py
        self-test)
set_tests_properties(decoder_fuzz_seed_corpus_self_test PROPERTIES TIMEOUT 30)
add_test(
    NAME decoder_fuzz_tests_off_configure_self_test
    COMMAND ${CMAKE_COMMAND}
        -DNINLIL_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DNINLIL_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}/decoder-fuzz-tests-off-negative
        -DNINLIL_GENERATOR=${CMAKE_GENERATOR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ninlil_decoder_fuzz_tests_off_self_test.cmake)
set_tests_properties(
    decoder_fuzz_tests_off_configure_self_test PROPERTIES TIMEOUT 30)

# Standalone semantic-seed runners do not need a libFuzzer runtime. Keep them
# available to private-R7 builds so the selector/body routing can be checked
# on toolchains such as AppleClang too; they remain EXCLUDE_FROM_ALL.
if(TARGET ninlil_r7_frag_private)
    add_executable(ninlil_domain_store_fuzz_seed_reachability EXCLUDE_FROM_ALL
        tests/fuzz/domain_store_body_codec_fuzzer.c)
    target_include_directories(ninlil_domain_store_fuzz_seed_reachability PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/model)
    target_compile_definitions(ninlil_domain_store_fuzz_seed_reachability PRIVATE
        NINLIL_FUZZ_REACHABILITY_MAIN=1)
    target_link_libraries(ninlil_domain_store_fuzz_seed_reachability PRIVATE
        ninlil_runtime_private ninlil)

    add_executable(ninlil_r7_frag_fuzz_seed_reachability EXCLUDE_FROM_ALL
        tests/fuzz/r7_frag_wire_fuzzer.c)
    target_include_directories(ninlil_r7_frag_fuzz_seed_reachability PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
        ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag)
    target_compile_definitions(ninlil_r7_frag_fuzz_seed_reachability PRIVATE
        NINLIL_FUZZ_REACHABILITY_MAIN=1)
    target_link_libraries(ninlil_r7_frag_fuzz_seed_reachability PRIVATE
        ninlil_r7_frag_private ninlil_runtime_private ninlil OpenSSL::Crypto)

    foreach(_ninlil_reachability_runner IN ITEMS
            ninlil_domain_store_fuzz_seed_reachability
            ninlil_r7_frag_fuzz_seed_reachability)
        set_target_properties(${_ninlil_reachability_runner} PROPERTIES
            C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
        ninlil_apply_strict_warnings(${_ninlil_reachability_runner})
    endforeach()
endif()

# Opt-in libFuzzer targets for decoder boundaries.  They are never part of the
# default build, install, release archive, or ordinary CTest build target.
if(NOT NINLIL_BUILD_DECODER_FUZZERS)
    return()
endif()

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "NINLIL_BUILD_DECODER_FUZZERS requires Clang/libFuzzer")
endif()
if(NOT NINLIL_ENABLE_SANITIZERS)
    message(FATAL_ERROR
        "NINLIL_BUILD_DECODER_FUZZERS requires NINLIL_ENABLE_SANITIZERS=ON")
endif()
if(NOT TARGET ninlil_r7_frag_private)
    message(FATAL_ERROR
        "NINLIL_BUILD_DECODER_FUZZERS requires NINLIL_ENABLE_R7_FRAG_PRIVATE=ON")
endif()

# AppleClang identifies as Clang even when the installed toolchain omits the
# libFuzzer runtime. Probe the exact compile+link capability during configure
# so an explicit fuzz request cannot fail much later at the aggregate link.
include(CheckCSourceCompiles)
set(_ninlil_fuzzer_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
set(_ninlil_fuzzer_saved_required_link_options "${CMAKE_REQUIRED_LINK_OPTIONS}")
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -fsanitize=fuzzer")
list(APPEND CMAKE_REQUIRED_LINK_OPTIONS -fsanitize=fuzzer)
check_c_source_compiles(
    "#include <stddef.h>\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) { (void)data; (void)size; return 0; }"
    NINLIL_HAVE_WORKING_LIBFUZZER_RUNTIME)
set(CMAKE_REQUIRED_FLAGS "${_ninlil_fuzzer_saved_required_flags}")
set(CMAKE_REQUIRED_LINK_OPTIONS "${_ninlil_fuzzer_saved_required_link_options}")
if(NOT NINLIL_HAVE_WORKING_LIBFUZZER_RUNTIME)
    message(FATAL_ERROR
        "NINLIL_BUILD_DECODER_FUZZERS requires a Clang toolchain with a "
        "working libFuzzer compile/link runtime (use Linux Clang or an "
        "LLVM installation that ships libclang_rt.fuzzer)")
endif()

add_executable(ninlil_nfl1_codec_fuzzer EXCLUDE_FROM_ALL
    tests/fuzz/nfl1_codec_fuzzer.c
    src/transport/fabric_v1/nfl1_codec.c
    src/transport/fabric_v1/fabric_private_util.c)
target_include_directories(ninlil_nfl1_codec_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/transport/fabric_v1)
target_compile_definitions(ninlil_nfl1_codec_fuzzer PRIVATE
    NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
target_link_libraries(ninlil_nfl1_codec_fuzzer PRIVATE ninlil)

add_executable(ninlil_rrmp_codec_fuzzer EXCLUDE_FROM_ALL
    tests/fuzz/rrmp_codec_fuzzer.c ${_ninlil_rrmp_private_srcs})
target_include_directories(ninlil_rrmp_codec_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime/route_relay_v1
    ${CMAKE_CURRENT_SOURCE_DIR}/ports/posix)
target_compile_definitions(ninlil_rrmp_codec_fuzzer PRIVATE ${_ninlil_rrmp_test_defs})
target_link_libraries(ninlil_rrmp_codec_fuzzer PRIVATE ninlil OpenSSL::Crypto)

add_executable(ninlil_r7_wire_codec_fuzzer EXCLUDE_FROM_ALL
    tests/fuzz/r7_wire_codec_fuzzer.c)
target_include_directories(ninlil_r7_wire_codec_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio)
target_link_libraries(ninlil_r7_wire_codec_fuzzer PRIVATE ninlil_runtime_private ninlil)

add_executable(ninlil_r7_frag_wire_fuzzer EXCLUDE_FROM_ALL
    tests/fuzz/r7_frag_wire_fuzzer.c)
target_include_directories(ninlil_r7_frag_wire_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio/r7_frag)
target_link_libraries(ninlil_r7_frag_wire_fuzzer PRIVATE
    ninlil_r7_frag_private ninlil_runtime_private ninlil OpenSSL::Crypto)

add_executable(ninlil_n6_record_codec_fuzzer EXCLUDE_FROM_ALL
    tests/fuzz/n6_record_codec_fuzzer.c)
target_include_directories(ninlil_n6_record_codec_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/radio ${CMAKE_CURRENT_SOURCE_DIR}/src/model)
target_link_libraries(ninlil_n6_record_codec_fuzzer PRIVATE ninlil_runtime_private ninlil)

add_executable(ninlil_domain_store_body_codec_fuzzer EXCLUDE_FROM_ALL
    tests/fuzz/domain_store_body_codec_fuzzer.c)
target_include_directories(ninlil_domain_store_body_codec_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/model)
target_link_libraries(ninlil_domain_store_body_codec_fuzzer PRIVATE ninlil_runtime_private ninlil)

foreach(_ninlil_fuzzer IN ITEMS
        ninlil_nfl1_codec_fuzzer
        ninlil_rrmp_codec_fuzzer
        ninlil_r7_wire_codec_fuzzer
        ninlil_r7_frag_wire_fuzzer
        ninlil_n6_record_codec_fuzzer
        ninlil_domain_store_body_codec_fuzzer)
    set_target_properties(${_ninlil_fuzzer} PROPERTIES
        C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
    target_compile_options(${_ninlil_fuzzer} PRIVATE -fsanitize=fuzzer)
    target_link_options(${_ninlil_fuzzer} PRIVATE -fsanitize=fuzzer)
    ninlil_apply_strict_warnings(${_ninlil_fuzzer})
endforeach()

set(_ninlil_decoder_fuzz_reachability_command
    ${Python3_EXECUTABLE}
    ${CMAKE_CURRENT_SOURCE_DIR}/tools/decoder_fuzz_seed_corpus.py
    reachability
    --domain-runner $<TARGET_FILE:ninlil_domain_store_fuzz_seed_reachability>
    --r7-runner $<TARGET_FILE:ninlil_r7_frag_fuzz_seed_reachability>)
add_custom_target(ninlil_decoder_fuzz_seed_reachability
    COMMAND ${_ninlil_decoder_fuzz_reachability_command}
    DEPENDS
        ninlil_domain_store_fuzz_seed_reachability
        ninlil_r7_frag_fuzz_seed_reachability
    VERBATIM)
add_test(
    NAME decoder_fuzz_seed_reachability_self_test
    COMMAND ${_ninlil_decoder_fuzz_reachability_command})
set_tests_properties(
    decoder_fuzz_seed_reachability_self_test PROPERTIES TIMEOUT 60)

add_custom_target(ninlil_decoder_fuzzers)
add_dependencies(ninlil_decoder_fuzzers
    ninlil_nfl1_codec_fuzzer
    ninlil_rrmp_codec_fuzzer
    ninlil_r7_wire_codec_fuzzer
    ninlil_r7_frag_wire_fuzzer
    ninlil_n6_record_codec_fuzzer
    ninlil_domain_store_body_codec_fuzzer
    ninlil_decoder_fuzz_seed_reachability)
