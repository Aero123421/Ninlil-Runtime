# SPDX-License-Identifier: Apache-2.0

if(NOT DEFINED NINLIL_VERSION_FILE OR
        NOT EXISTS "${NINLIL_VERSION_FILE}")
    message(FATAL_ERROR "NINLIL_VERSION_FILE must name the generated version file")
endif()
if(NOT DEFINED NINLIL_TEST_DIR OR NINLIL_TEST_DIR STREQUAL "")
    message(FATAL_ERROR "NINLIL_TEST_DIR is required")
endif()

file(MAKE_DIRECTORY "${NINLIL_TEST_DIR}")

function(ninlil_assert_version file requested expected_compatible
        expected_exact)
    string(REPLACE "." ";" requested_parts "${requested}")
    list(LENGTH requested_parts requested_count)
    list(GET requested_parts 0 requested_major)
    if(requested_count GREATER 1)
        list(GET requested_parts 1 requested_minor)
    else()
        set(requested_minor 0)
    endif()
    if(requested_count GREATER 2)
        list(GET requested_parts 2 requested_patch)
    else()
        set(requested_patch 0)
    endif()

    set(PACKAGE_FIND_VERSION "${requested}")
    set(PACKAGE_FIND_VERSION_MAJOR "${requested_major}")
    set(PACKAGE_FIND_VERSION_MINOR "${requested_minor}")
    set(PACKAGE_FIND_VERSION_PATCH "${requested_patch}")
    set(PACKAGE_FIND_VERSION_TWEAK 0)
    set(PACKAGE_FIND_VERSION_COUNT "${requested_count}")
    set(PACKAGE_FIND_VERSION_RANGE "")
    unset(PACKAGE_VERSION)
    unset(PACKAGE_VERSION_COMPATIBLE)
    unset(PACKAGE_VERSION_EXACT)
    unset(PACKAGE_VERSION_UNSUITABLE)

    include("${file}")

    if(PACKAGE_VERSION_COMPATIBLE)
        set(actual_compatible TRUE)
    else()
        set(actual_compatible FALSE)
    endif()
    if(PACKAGE_VERSION_EXACT)
        set(actual_exact TRUE)
    else()
        set(actual_exact FALSE)
    endif()
    if(NOT actual_compatible STREQUAL expected_compatible OR
            NOT actual_exact STREQUAL expected_exact)
        message(FATAL_ERROR
            "${file}: request ${requested}: compatible=${actual_compatible}, "
            "exact=${actual_exact}; expected compatible=${expected_compatible}, "
            "exact=${expected_exact}")
    endif()
endfunction()

# The actual 0.1.0 package must not cross a 0.x minor boundary.
ninlil_assert_version("${NINLIL_VERSION_FILE}" "0.1.0" TRUE TRUE)
ninlil_assert_version("${NINLIL_VERSION_FILE}" "0.0.9" FALSE FALSE)
ninlil_assert_version("${NINLIL_VERSION_FILE}" "0.2.0" FALSE FALSE)
ninlil_assert_version("${NINLIL_VERSION_FILE}" "1.0.0" FALSE FALSE)

# Prove patch releases in the same 0.x minor accept an older requirement.
include(CMakePackageConfigHelpers)
set(synthetic_019 "${NINLIL_TEST_DIR}/NinlilConfigVersion-0.1.9.cmake")
write_basic_package_version_file(
    "${synthetic_019}"
    VERSION 0.1.9
    COMPATIBILITY SameMinorVersion)
ninlil_assert_version("${synthetic_019}" "0.1.0" TRUE FALSE)
ninlil_assert_version("${synthetic_019}" "0.2.0" FALSE FALSE)

message(STATUS "Ninlil CMake package version compatibility policy: PASS")
