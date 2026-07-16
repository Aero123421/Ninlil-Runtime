# Ninlil portable Core / private Runtime as an ESP-IDF component (M3-prep).
#
# This packages already-implemented portable sources for ESP32-S3 target
# compilation. It does not implement NVS storage, FreeRTOS owner tasks, USB,
# Wi-Fi, SX1262, radio MAC, Join, or KGuard adapters.
#
# Source list authority is cmake/ninlil_runtime_private_sources.cmake (shared
# with the host build). Do not list sources with file(GLOB).

get_filename_component(NINLIL_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")

set(NINLIL_COMPONENT_SRCS "")
foreach(_rel IN LISTS NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()

idf_component_register(
    SRCS ${NINLIL_COMPONENT_SRCS}
    INCLUDE_DIRS "${NINLIL_REPO_ROOT}/include"
    PRIV_INCLUDE_DIRS
        "${NINLIL_REPO_ROOT}/src/model"
        "${NINLIL_REPO_ROOT}/src/runtime"
)

# Portable Core remains C11 without language extensions. ESP-IDF-specific
# headers must not be added to portable sources.
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE
    -std=c11
    -Wall
    -Wextra
    -Werror
    -Wpedantic
    -Wvla
)

# Match host production private build: TEST-only transport begin is OFF.
# Do not define NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN here.
