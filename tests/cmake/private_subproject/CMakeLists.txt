cmake_minimum_required(VERSION 3.16)

project(ninlil_private_subproject_smoke LANGUAGES C CXX)

enable_testing()

if(NOT DEFINED NINLIL_SOURCE_DIR)
    message(FATAL_ERROR "NINLIL_SOURCE_DIR is required")
endif()

add_subdirectory("${NINLIL_SOURCE_DIR}" ninlil-child)

if(NOT TARGET ninlil OR NOT TARGET ninlil_runtime_private)
    message(FATAL_ERROR "required Ninlil targets are missing")
endif()

get_target_property(_private_type ninlil_runtime_private TYPE)
if(NOT _private_type STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "private target is not STATIC: ${_private_type}")
endif()
get_target_property(_private_marker ninlil_runtime_private
    NINLIL_PRODUCTION_PRIVATE_ARTIFACT)
if(NOT _private_marker)
    message(FATAL_ERROR "private target marker is missing")
endif()
get_target_property(_private_pic ninlil_runtime_private
    POSITION_INDEPENDENT_CODE)
if(NOT _private_pic)
    message(FATAL_ERROR "private target PIC contract is missing")
endif()
get_target_property(_private_visibility ninlil_runtime_private
    C_VISIBILITY_PRESET)
if(NOT _private_visibility STREQUAL "hidden")
    message(FATAL_ERROR
        "private target visibility is not hidden: ${_private_visibility}")
endif()

get_target_property(_public_links ninlil INTERFACE_LINK_LIBRARIES)
if(_public_links)
    message(FATAL_ERROR "public target unexpectedly links: ${_public_links}")
endif()
get_target_property(_public_compile_options ninlil INTERFACE_COMPILE_OPTIONS)
get_target_property(_public_link_options ninlil INTERFACE_LINK_OPTIONS)
if(_public_compile_options OR _public_link_options)
    message(FATAL_ERROR
        "public flags unexpectedly leaked: ${_public_compile_options};${_public_link_options}")
endif()
get_target_property(_public_includes ninlil INTERFACE_INCLUDE_DIRECTORIES)
list(LENGTH _public_includes _public_include_count)
if(NOT _public_include_count EQUAL 2)
    message(FATAL_ERROR "public include set is not exact: ${_public_includes}")
endif()
set(_expected_public_includes
    "$<BUILD_INTERFACE:${NINLIL_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
)
list(SORT _public_includes)
list(SORT _expected_public_includes)
if(NOT _public_includes STREQUAL _expected_public_includes)
    message(FATAL_ERROR "public include mismatch: ${_public_includes}")
endif()
foreach(_include IN LISTS _public_includes)
    if(_include MATCHES "src/model" OR _include MATCHES "tests/support")
        message(FATAL_ERROR "private/test include leaked: ${_include}")
    endif()
endforeach()
get_target_property(_private_interface_includes ninlil_runtime_private
    INTERFACE_INCLUDE_DIRECTORIES)
if(_private_interface_includes)
    message(FATAL_ERROR
        "private includes leaked through interface: ${_private_interface_includes}")
endif()

get_target_property(_private_sources ninlil_runtime_private SOURCES)
list(LENGTH _private_sources _private_source_count)
if(NOT _private_source_count EQUAL 7)
    message(FATAL_ERROR "private source count is not 7: ${_private_sources}")
endif()
set(_private_source_names)
foreach(_source IN LISTS _private_sources)
    if(_source MATCHES "tests/support")
        message(FATAL_ERROR "TEST fixture leaked into private target: ${_source}")
    endif()
    get_filename_component(_source_name "${_source}" NAME)
    list(APPEND _private_source_names "${_source_name}")
endforeach()
list(SORT _private_source_names)
set(_expected_private_source_names
    domain_store_body_codec.c
    domain_store_codec.c
    domain_store_scanner.c
    runtime_lifecycle_model.c
    runtime_store_bootstrap.c
    runtime_store_codec.c
    runtime_store_orchestrator.c
)
list(SORT _expected_private_source_names)
if(NOT _private_source_names STREQUAL _expected_private_source_names)
    message(FATAL_ERROR
        "private source allowlist mismatch: ${_private_source_names}")
endif()

get_property(_child_tests DIRECTORY "${NINLIL_SOURCE_DIR}" PROPERTY TESTS)
if(_child_tests)
    message(FATAL_ERROR "subproject registered Ninlil tests: ${_child_tests}")
endif()

include(CheckCSourceCompiles)
set(CMAKE_REQUIRED_INCLUDES "${NINLIL_SOURCE_DIR}/include")
check_c_source_compiles(
    "#include \"runtime_store_bootstrap.h\"\nint main(void) { return 0; }"
    NINLIL_PRIVATE_HEADER_LEAKED)
if(NINLIL_PRIVATE_HEADER_LEAKED)
    message(FATAL_ERROR "private Runtime Store header is publicly includable")
endif()
check_c_source_compiles(
    "#include \"runtime_store_orchestrator.h\"\nint main(void) { return 0; }"
    NINLIL_PRIVATE_ORCHESTRATOR_HEADER_LEAKED)
if(NINLIL_PRIVATE_ORCHESTRATOR_HEADER_LEAKED)
    message(FATAL_ERROR "private Runtime orchestrator header is publicly includable")
endif()

check_c_source_compiles(
    "#include \"domain_store_codec.h\"\nint main(void) { return 0; }"
    NINLIL_PRIVATE_DOMAIN_HEADER_LEAKED)
if(NINLIL_PRIVATE_DOMAIN_HEADER_LEAKED)
    message(FATAL_ERROR "private Domain Store header is publicly includable")
endif()
check_c_source_compiles(
    "#include \"domain_store_body_codec.h\"\nint main(void) { return 0; }"
    NINLIL_PRIVATE_DOMAIN_BODY_HEADER_LEAKED)
if(NINLIL_PRIVATE_DOMAIN_BODY_HEADER_LEAKED)
    message(FATAL_ERROR "private Domain Store body header is publicly includable")
endif()
check_c_source_compiles(
    "#include \"domain_store_scanner.h\"\nint main(void) { return 0; }"
    NINLIL_PRIVATE_DOMAIN_SCANNER_HEADER_LEAKED)
if(NINLIL_PRIVATE_DOMAIN_SCANNER_HEADER_LEAKED)
    message(FATAL_ERROR "private Domain Store scanner header is publicly includable")
endif()

add_executable(ninlil_subproject_public_consumer consumer.c)
target_link_libraries(ninlil_subproject_public_consumer PRIVATE ninlil)

add_executable(ninlil_subproject_private_consumer private_consumer.c)
target_include_directories(ninlil_subproject_private_consumer PRIVATE
    "${NINLIL_SOURCE_DIR}/src/model"
    "${NINLIL_SOURCE_DIR}/src/runtime"
)
target_link_libraries(ninlil_subproject_private_consumer PRIVATE
    ninlil_runtime_private
    ninlil
)

file(GENERATE OUTPUT "${CMAKE_BINARY_DIR}/ninlil-smoke-paths.cmake" CONTENT
    "set(NINLIL_PUBLIC_CONSUMER \"$<TARGET_FILE:ninlil_subproject_public_consumer>\")\nset(NINLIL_PRIVATE_CONSUMER \"$<TARGET_FILE:ninlil_subproject_private_consumer>\")\nset(NINLIL_PRIVATE_ARCHIVE \"$<TARGET_FILE:ninlil_runtime_private>\")\n"
)
