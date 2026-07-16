# Ninlil portable Core / private Runtime + M3-basic ESP-IDF platform adapters.
#
# Portable sources: cmake/ninlil_runtime_private_sources.cmake
# ESP-IDF port sources: cmake/ninlil_esp_idf_port_sources.cmake
# Do not list sources with file(GLOB). Do not merge ESP-IDF sources into the
# portable authority.
#
# This does not implement NVS storage, FreeRTOS owner-task body, USB, Wi-Fi,
# SX1262, radio MAC, Join, or KGuard adapters.

get_filename_component(NINLIL_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_esp_idf_port_sources.cmake")

set(NINLIL_COMPONENT_SRCS "")
foreach(_rel IN LISTS NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()

idf_component_register(
    SRCS ${NINLIL_COMPONENT_SRCS}
    INCLUDE_DIRS
        "${NINLIL_REPO_ROOT}/include"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/include"
    PRIV_INCLUDE_DIRS
        "${NINLIL_REPO_ROOT}/src/model"
        "${NINLIL_REPO_ROOT}/src/runtime"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/src"
    PRIV_REQUIRES
        esp_timer
        esp_hw_support
        bootloader_support
        freertos
)

# Portable Core remains C11-compatible (enforced by the host build). The
# target build keeps ESP-IDF's GNU C dialect because its public Xtensa and
# newlib headers require GNU asm/include_next extensions.
target_compile_features(${COMPONENT_LIB} PRIVATE c_std_11)
target_compile_options(${COMPONENT_LIB} PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wvla
)

# Match host production private build: TEST-only transport begin is OFF.
# Do not define NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN here.
