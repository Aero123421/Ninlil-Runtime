# Ninlil portable Core / private Runtime + M3 ESP-IDF port adapters + storage.
#
# Portable sources: cmake/ninlil_runtime_private_sources.cmake
# ESP-IDF port sources: cmake/ninlil_esp_idf_port_sources.cmake
# Durable storage: cmake/ninlil_esp_storage_sources.cmake
# Do not list sources with file(GLOB). Do not merge ESP-IDF sources into the
# portable authority.
#
# Includes M3-basic (clock/entropy/execution), M3 owner/cell/loopback skeleton,
# format-4 dual-slot durable-storage candidate, and U2 A2 USB CDC-ACM adapter
# candidate (esp_tinyusb), and R1 portable radio_hal (sole transmit-with-permit;
# default-deny without R2 permit ops). Does not implement Wi-Fi, SX1262 SPI TX,
# radio MAC, Join, or KGuard adapters. Does not claim storage FULL attestation,
# physical power-cut HIL, U2 HIL, R1 production radio complete, or field-ready.

get_filename_component(NINLIL_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_esp_idf_port_sources.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_esp_storage_sources.cmake")

set(NINLIL_COMPONENT_SRCS "")
foreach(_rel IN LISTS NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()

idf_component_register(
    SRCS ${NINLIL_COMPONENT_SRCS}
    INCLUDE_DIRS
        "${NINLIL_REPO_ROOT}/include"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/include"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/storage/include"
        "${NINLIL_REPO_ROOT}/src/transport"
    PRIV_INCLUDE_DIRS
        "${NINLIL_REPO_ROOT}/src/model"
        "${NINLIL_REPO_ROOT}/src/runtime"
        "${NINLIL_REPO_ROOT}/src/transport"
        "${NINLIL_REPO_ROOT}/src/radio"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/src"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/storage/model"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/storage/private"
    PRIV_REQUIRES
        esp_timer
        esp_hw_support
        bootloader_support
        freertos
        spi_flash
        esp_partition
        wear_levelling
        esp_tinyusb
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

# Private pure helpers use NINLIL_ESP_IDF_INTERNAL (hidden). Do not set
# C_VISIBILITY_PRESET hidden on the whole component: public port APIs must
# remain default-visible for application link. Private .c symbols that need
# non-DEFAULT visibility mark NINLIL_ESP_IDF_INTERNAL explicitly.

set(_ninlil_storage_srcs "")
foreach(_rel IN LISTS NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES)
    list(APPEND _ninlil_storage_srcs "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
set_source_files_properties(${_ninlil_storage_srcs} PROPERTIES
    COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=2048"
)

# Match host production private build: TEST-only transport begin is OFF.
# Do not define NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN here.
