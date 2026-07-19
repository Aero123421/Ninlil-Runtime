# Ninlil portable Core / private Runtime + M3 ESP-IDF port adapters + storage.
#
# Portable sources: cmake/ninlil_runtime_private_sources.cmake
# R7 T1b binding source: cmake/ninlil_nrw1_t1b_ctest.cmake (include exactly once
# after the shared private authority; appends r7_context_binding.c once).
# ESP-IDF port sources: cmake/ninlil_esp_idf_port_sources.cmake
# Durable storage: cmake/ninlil_esp_storage_sources.cmake
# R4 SX1262 control-plane: cmake/ninlil_sx1262_sources.cmake
# Do not list sources with file(GLOB). Do not merge ESP-IDF sources into the
# portable authority.
#
# Includes M3-basic (clock/entropy/execution), M3 owner/cell/loopback skeleton,
# format-4 dual-slot durable-storage candidate, U2 A2 USB CDC-ACM adapter
# candidate (esp_tinyusb), R1 portable radio_hal (sole transmit-with-permit;
# default-deny without R2 permit ops), R2 private pcp_authority (durable permit
# authority body; private only), R3 airtime_calculator (private), R4 SX1262
# control-plane backend (reset/init/SPI only; SetTx denied; not RF TX/RX
# complete), R5 private LAB_ONLY profile_loader + PCP bind candidate
# (profile_loader.c via portable private authority; host/ESP packaging only),
# R7 T0 mbedTLS adapter, T1 wire codec, and T1b context binding (private).
# Does not implement Wi-Fi, SX1262 physical RF TX/RX path, SetTx path, radio
# MAC, Join, or KGuard adapters. Does not claim storage FULL attestation,
# physical power-cut HIL, U2 HIL, R1/R2/R3/R4/R5/R7 complete, FIELD, PRODUCTION,
# Japan legal, RF HIL, production radio, or field-ready.
# Never define NINLIL_R7_BINDING_TEST_BUILD here (test seams stay host-only).

get_filename_component(NINLIL_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
# T1b source authority exact once after shared private (docs/33 §1 / §10).
# Appends NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES into the shared private
# list under an include guard so r7_context_binding.c is packaged exact once.
# Do not call ninlil_nrw1_t1b_register_tests() on ESP (host CTest only).
include("${NINLIL_REPO_ROOT}/cmake/ninlil_nrw1_t1b_ctest.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_esp_idf_port_sources.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_esp_storage_sources.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_sx1262_sources.cmake")

set(NINLIL_COMPONENT_SRCS "")
foreach(_rel IN LISTS NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_R7_CRYPTO_ESP_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_ESP_IDF_PORT_ALL_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_ESP_STORAGE_TARGET_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_SX1262_PORTABLE_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_SX1262_ESP_BUS_RELATIVE_SOURCES)
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
        "${NINLIL_REPO_ROOT}/drivers/sx126x"
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
        driver
        mbedtls
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

# N6 production set (docs/30 §20.4.1): stack-usage artifacts + frame ceiling.
# Apply to every NINLIL_N6_PRODUCTION_RELATIVE_SOURCES member from the shared
# private authority. ESP GCC supports both flags; .su files land next to the
# component objects and are collected by esp-idf.yml for n6_frame_stack_gate
# (--su-dir / --esp-su-dir). Missing N6 .su is FAIL; host substitute forbidden.
set(_ninlil_n6_srcs "")
foreach(_rel IN LISTS NINLIL_N6_PRODUCTION_RELATIVE_SOURCES)
    list(APPEND _ninlil_n6_srcs "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
set_source_files_properties(${_ninlil_n6_srcs} PROPERTIES
    COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=2048"
)

# R7 T1b binding production (docs/33 §8 / §10): -Wvla, -fstack-usage, and
# 2560-byte frame ceiling on the authority source set only. Test seam macro
# NINLIL_R7_BINDING_TEST_BUILD must remain undefined on ESP.
set(_ninlil_t1b_srcs "")
foreach(_rel IN LISTS NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES)
    list(APPEND _ninlil_t1b_srcs "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
set_source_files_properties(${_ninlil_t1b_srcs} PROPERTIES
    COMPILE_OPTIONS "-Wvla;-fstack-usage;-Wframe-larger-than=2560"
)

# Match host production private build: TEST-only transport begin is OFF.
# Do not define NINLIL_DOMAIN_SCAN_ENABLE_TEST_TRANSPORT_BEGIN here.
# Do not define NINLIL_R7_BINDING_TEST_BUILD (T1b test seams stay host-only).
