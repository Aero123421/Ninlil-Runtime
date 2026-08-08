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
# Private NRW1 LINK/FRAG (default-OFF Kconfig) uses cmake/ninlil_r7_frag_sources.cmake.
# R9 physical path (Proposed ADR-0025) is packaged via NINLIL_SX1262_PORTABLE
# (phy) + sx1262_r9_edge in runtime private + ESP bus (SPI/BUSY/DIO1/ANT_SW).
# Sole production SetTx: radio_hal_transmit_with_permit → r9_edge → phy_arm_tx.
# Bare R4 request_transmit remains TX_DENIED. Does not claim RF HIL PASS,
# Japan legal, storage FULL attestation, physical power-cut HIL, U2 HIL,
# R1/R2/R3/R4/R5/R7/R9 complete, FIELD, PRODUCTION, or field-ready.
# Never define NINLIL_R7_BINDING_TEST_BUILD here (test seams stay host-only).

get_filename_component(NINLIL_REPO_ROOT
    "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)

include("${NINLIL_REPO_ROOT}/cmake/ninlil_runtime_private_sources.cmake")
# T1b source authority exact once after shared private (docs/33 §1 / §10).
# Appends NINLIL_R7_BINDING_PORTABLE_RELATIVE_SOURCES into the shared private
# list under an include guard so r7_context_binding.c is packaged exact once.
# Do not call ninlil_nrw1_t1b_register_tests() on ESP (host CTest only).
include("${NINLIL_REPO_ROOT}/cmake/ninlil_nrw1_t1b_ctest.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_m4_lab_ctest.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_esp_idf_port_sources.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_esp_storage_sources.cmake")
include("${NINLIL_REPO_ROOT}/cmake/ninlil_sx1262_sources.cmake")
# Public Fabric/Composition source authority shared with the Host SDK build.
include("${NINLIL_REPO_ROOT}/cmake/ninlil_composition_v1_sources.cmake")
# FRAG source authority only — do not auto-append; gated by Kconfig below.
include("${NINLIL_REPO_ROOT}/cmake/ninlil_r7_frag_sources.cmake")
# MFDT source authority only — do not auto-append; gated by Kconfig below.
include("${NINLIL_REPO_ROOT}/cmake/ninlil_mfdt_v1_sources.cmake")

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
# Fabric and Composition are public portable SDK surfaces on ESP32-S3. Packet
# links remain separate platform/application-owned objects.
foreach(_rel IN LISTS NINLIL_FABRIC_V1_PUBLIC_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
foreach(_rel IN LISTS NINLIL_COMPOSITION_V1_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
# R4 control-plane always. R9 phy+edge only when Kconfig enables R9 (default n).
foreach(_rel IN LISTS NINLIL_SX1262_ESP_DEFAULT_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
if(CONFIG_NINLIL_ENABLE_SX1262_R9)
    foreach(_rel IN LISTS NINLIL_SX1262_PHY_RELATIVE_SOURCES)
        list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
    foreach(_rel IN LISTS NINLIL_SX1262_R9_EDGE_RELATIVE_SOURCES)
        list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
endif()
# Session RAM ledger: diagnostic-only; absent from release radio_hil / smoke.
if(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
    foreach(_rel IN LISTS NINLIL_PCP_LAB_SESSION_LEDGER_RELATIVE_SOURCES)
        list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
endif()
foreach(_rel IN LISTS NINLIL_SX1262_ESP_BUS_RELATIVE_SOURCES)
    list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()

# Default-OFF private FRAG: PRODUCTION sources only (never lab session/durable).
# Lab TUs (session + test durable) stay host-only — DRAM / claim isolation.
set(NINLIL_R7_FRAG_PRIV_INCLUDES "")
if(CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE)
    foreach(_rel IN LISTS NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES)
        list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
    list(APPEND NINLIL_R7_FRAG_PRIV_INCLUDES
        "${NINLIL_REPO_ROOT}/src/radio/r7_frag"
    )
endif()

# The V1 LAB packet-link is meaningful only with both R7 and the physical R9
# path. Kconfig encodes that dependency; keep the source absent otherwise.
if(CONFIG_NINLIL_ENABLE_V1_LAB_RADIO_PATH)
    foreach(_rel IN LISTS NINLIL_V1_LAB_RADIO_PATH_RELATIVE_SOURCES)
        list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
endif()

# Default-OFF private MFDT (ADR-0021): production engine+crypto+wire+record.
# Host in-memory lab store (mfdt_v1_store.c) is NEVER linked on ESP.
# ESP links the storage_ops-backed FULL adapter; the application must bind a
# durable provider before use, otherwise every mutation fails closed.
set(NINLIL_MFDT_V1_PRIV_INCLUDES "")
if(CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE)
    foreach(_rel IN LISTS NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES)
        list(APPEND NINLIL_COMPONENT_SRCS "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
    # ESP durable FULL adapter (storage_ops bind); fail-closed until bound.
    # Target smoke: live two-endpoint callpath from app_main (not dummy pins).
    list(APPEND NINLIL_COMPONENT_SRCS
        "${NINLIL_REPO_ROOT}/src/runtime/mfdt_v1/mfdt_v1_store_esp.c"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/src/mfdt_v1_target_smoke.c"
    )
    list(APPEND NINLIL_MFDT_V1_PRIV_INCLUDES
        "${NINLIL_REPO_ROOT}/src/runtime/mfdt_v1"
    )
endif()

# Default-OFF Domain schema1 HOST_CANDIDATE (ADR-0022). Not public ABI.
set(NINLIL_DOMAIN_SCHEMA1_PRIV_INCLUDES "")
if(CONFIG_NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
    list(APPEND NINLIL_COMPONENT_SRCS
        "${NINLIL_REPO_ROOT}/src/model/domain_schema1_runtime_binding.c"
        "${NINLIL_REPO_ROOT}/src/model/domain_schema1_startup_authority.c"
        "${NINLIL_REPO_ROOT}/src/runtime/domain_schema1_startup_owner.c"
        "${NINLIL_REPO_ROOT}/src/runtime/domain_schema1_kind1_register.c"
    )
    list(APPEND NINLIL_DOMAIN_SCHEMA1_PRIV_INCLUDES
        "${NINLIL_REPO_ROOT}/src/model"
        "${NINLIL_REPO_ROOT}/src/runtime"
    )
endif()

# Default-OFF private Wi-Fi v1 (ADR-0018). ESP STA/lwIP/mbedTLS path.
# SHA provider is mbedTLS-only on ESP (wifi_sha256_mbedtls.c); no OpenSSL.
#
# Component acceptance: when private Wi-Fi is ON, ESP-IDF mbedTLS must export
# keying material (CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT). wifi_v1 session
# IDs come only from mbedtls_ssl_export_keying_material; synthetic IDs are
# forbidden. Source still fails closed if the macro is absent at compile time.
set(NINLIL_WIFI_V1_PRIV_INCLUDES "")
if(CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1)
    if(NOT CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT)
        message(FATAL_ERROR
            "CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1 requires "
            "CONFIG_MBEDTLS_SSL_KEYING_MATERIAL_EXPORT=y "
            "(mbedtls_ssl_export_keying_material; no synthetic session IDs)")
    endif()
    if(NOT CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC
        OR CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC
        OR CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC
        OR CONFIG_MBEDTLS_DEFAULT_MEM_ALLOC)
        message(FATAL_ERROR
            "private Wi-Fi v1 requires the sole bounded TLS allocator: "
            "CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC=y and internal/external/default "
            "mbedTLS allocators disabled")
    endif()
    list(APPEND NINLIL_COMPONENT_SRCS
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_nwb1.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_nfl1_min.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_stream.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_queues.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_tls_arena.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_tls_resource_policy.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_sha256_mbedtls.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_reconnect.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_storage_cu.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_credentials.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_journal.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_attachment_m4.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_tls_leaf_binding.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_tls_export.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_fabric_adapter.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_sta.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_tcp.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_mbedtls_profile_probe.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_tls_allocator.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_tls_mbedtls.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_owner.c"
    )
    # Fabric private headers for composition. Host packet-link ops (session/
    # OpenSSL) stay host-only — not linked on ESP-IDF. ESP final app binds
    # fabric_adapter to owner (non-null) with STA/TLS/NWB1 path.
    if(CONFIG_NINLIL_ENABLE_PRIVATE_FABRIC_V1)
        list(APPEND NINLIL_COMPONENT_SRCS
            "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_fabric_link_ops.c"
            "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_adapter_v1_esp.c"
        )
        list(APPEND NINLIL_WIFI_V1_PRIV_INCLUDES
            "${NINLIL_REPO_ROOT}/src/transport/fabric_v1"
        )
    endif()
    list(APPEND NINLIL_WIFI_V1_PRIV_INCLUDES
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1"
    )
endif()

# Default-OFF route-relay / multi-parent HOST_CANDIDATE (ADR-0019/0020).
# Not public ABI. Simulator TU is host-only (excluded on ESP).
set(NINLIL_RRMP_PRIV_INCLUDES "")
if(CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
    list(APPEND NINLIL_COMPONENT_SRCS
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_util.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_codec.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_store.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_core.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_seam.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_fabric_dispatch.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_composition.c"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/src/rrmp_target_smoke.c"
    )
    list(APPEND NINLIL_RRMP_PRIV_INCLUDES
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1"
    )
endif()

# Public INCLUDE_DIRS: only installable / formal package surfaces.
# Never export src/** roots publicly — private TUs use PRIV_INCLUDE_DIRS.
# C1 types live at include/ninlil/byte_stream.h (not src/transport as a root).
#
# Wi-Fi STA owner needs esp_event/esp_wifi/esp_netif/nvs_flash/lwip headers at
# compile time. List them in PRIV_REQUIRES when private Wi-Fi is ON (not only
# post-register target_link_libraries).
set(NINLIL_WIFI_PRIV_REQUIRES "")
if(CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1)
    list(APPEND NINLIL_WIFI_PRIV_REQUIRES
        esp_event
        esp_wifi
        esp_netif
        nvs_flash
        lwip
    )
endif()
idf_component_register(
    SRCS ${NINLIL_COMPONENT_SRCS}
    INCLUDE_DIRS
        "${NINLIL_REPO_ROOT}/include"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/include"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/storage/include"
    PRIV_INCLUDE_DIRS
        "${NINLIL_REPO_ROOT}/src/model"
        "${NINLIL_REPO_ROOT}/src/runtime"
        "${NINLIL_REPO_ROOT}/src/transport"
        "${NINLIL_REPO_ROOT}/src/transport/fabric_v1"
        "${NINLIL_REPO_ROOT}/src/radio"
        ${NINLIL_R7_FRAG_PRIV_INCLUDES}
        ${NINLIL_MFDT_V1_PRIV_INCLUDES}
        ${NINLIL_DOMAIN_SCHEMA1_PRIV_INCLUDES}
        ${NINLIL_WIFI_V1_PRIV_INCLUDES}
        ${NINLIL_RRMP_PRIV_INCLUDES}
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
        esp_psram
        ${NINLIL_WIFI_PRIV_REQUIRES}
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
# Every ESP image excludes the legacy request_transmit_with_permit symbol.
# Session ledger selection is independent of the sole-edge production guard.
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    NINLIL_SX1262_PRODUCTION_BUILD=1
)
# The public Composition owner is caller-workspace based; its glue must stay
# off task stacks and below the ESP V1 frame ceiling.
set(_ninlil_composition_v1_srcs "")
foreach(_rel IN LISTS NINLIL_COMPOSITION_V1_RELATIVE_SOURCES)
    list(APPEND _ninlil_composition_v1_srcs
        "${NINLIL_REPO_ROOT}/${_rel}")
endforeach()
set_source_files_properties(${_ninlil_composition_v1_srcs} PROPERTIES
    COMPILE_OPTIONS "-fstack-usage;-Wframe-larger-than=2048"
)
if(CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_ENABLE_PRIVATE_WIFI_V1=1)
endif()
if(CONFIG_NINLIL_ENABLE_PRIVATE_FABRIC_V1)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_ENABLE_PRIVATE_FABRIC_V1=1)
endif()
if(CONFIG_NINLIL_ENABLE_SX1262_R9)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_ENABLE_SX1262_R9=1
    )
    # Stack-usage evidence for R9/PCP/R5/HAL authority TUs (auditor P2).
    set(_ninlil_r9_stack_srcs "")
    foreach(_rel IN LISTS NINLIL_SX1262_PHY_RELATIVE_SOURCES NINLIL_SX1262_R9_EDGE_RELATIVE_SOURCES)
        list(APPEND _ninlil_r9_stack_srcs "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
    list(APPEND _ninlil_r9_stack_srcs
        "${NINLIL_REPO_ROOT}/src/radio/pcp_authority.c"
        "${NINLIL_REPO_ROOT}/src/radio/profile_loader.c"
        "${NINLIL_REPO_ROOT}/src/radio/radio_hal.c"
        "${NINLIL_REPO_ROOT}/src/radio/airtime_calculator.c"
    )
    if(CONFIG_NINLIL_RADIO_HIL_SESSION_LEDGER_DIAG)
        list(APPEND _ninlil_r9_stack_srcs
            "${NINLIL_REPO_ROOT}/src/radio/pcp_lab_session_ledger.c"
        )
    endif()
    set_source_files_properties(${_ninlil_r9_stack_srcs} PROPERTIES
        COMPILE_OPTIONS "-Wvla;-fstack-usage;-Wframe-larger-than=16384"
    )
endif()
if(CONFIG_NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1)
endif()
if(CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_MFDT_V1_PRIVATE=1
        NINLIL_MFDT_V1_HAVE_PLATFORM_STORAGE=1
    )
    set(_ninlil_mfdt_srcs "")
    foreach(_rel IN LISTS NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES)
        list(APPEND _ninlil_mfdt_srcs "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
    list(APPEND _ninlil_mfdt_srcs
        "${NINLIL_REPO_ROOT}/src/runtime/mfdt_v1/mfdt_v1_store_esp.c"
    )
    set_source_files_properties(${_ninlil_mfdt_srcs} PROPERTIES
        COMPILE_OPTIONS "-Wvla;-fstack-usage;-Wframe-larger-than=16384"
    )
endif()
if(CONFIG_NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_ENABLE_PRIVATE_ROUTE_RELAY_V1=1
        NINLIL_RRMP_HAVE_MBEDTLS=1)
    if(CONFIG_NINLIL_RRMP_ROLE_ENDPOINT)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE
            NINLIL_RRMP_ROLE_ENDPOINT=1)
    endif()
    if(CONFIG_NINLIL_RRMP_ROLE_RELAY)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE
            NINLIL_RRMP_ROLE_RELAY=1)
    endif()
    if(CONFIG_NINLIL_RRMP_ROLE_PARENT)
        target_compile_definitions(${COMPONENT_LIB} PRIVATE
            NINLIL_RRMP_ROLE_PARENT=1)
    endif()
    # Stack/frame gate: RRMP TUs must not put owner workspace on task stacks.
    # Workspace is caller-owned PSRAM heap (≤384 KiB budget); frames stay small.
    set(_ninlil_rrmp_srcs "")
    list(APPEND _ninlil_rrmp_srcs
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_util.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_codec.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_store.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_core.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_seam.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_fabric_dispatch.c"
        "${NINLIL_REPO_ROOT}/src/runtime/route_relay_v1/rrmp_composition.c"
        "${NINLIL_REPO_ROOT}/ports/esp-idf/src/rrmp_target_smoke.c"
    )
    # Encode scratch lives in owner workspace — frames must stay tight.
    set_source_files_properties(${_ninlil_rrmp_srcs} PROPERTIES
        COMPILE_OPTIONS "-Wvla;-fstack-usage;-Wframe-larger-than=2048"
    )
endif()
if(CONFIG_NINLIL_ENABLE_PRIVATE_WIFI_V1)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_ENABLE_PRIVATE_WIFI_V1=1)
    # Belt-and-suspenders: idf_component_register PRIV_REQUIRES above is
    # authoritative; re-link ensures include/export paths for STA owner TUs.
    target_link_libraries(${COMPONENT_LIB} PRIVATE
        idf::esp_event
        idf::esp_wifi
        idf::esp_netif
        idf::nvs_flash
        idf::lwip
        idf::mbedtls
    )
    set(_ninlil_wifi_srcs "")
    list(APPEND _ninlil_wifi_srcs
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_nwb1.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_stream.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_queues.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_tls_arena.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_tls_resource_policy.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_sha256_mbedtls.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_reconnect.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_owner.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_mbedtls_profile_probe.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_tls_allocator.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_tls_mbedtls.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_sta.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_tcp.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_storage_cu.c"
        "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_credentials.c"
    )
    if(CONFIG_NINLIL_ENABLE_PRIVATE_FABRIC_V1)
        list(APPEND _ninlil_wifi_srcs
            "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_esp_fabric_link_ops.c"
            "${NINLIL_REPO_ROOT}/src/transport/wifi_v1/wifi_adapter_v1_esp.c"
        )
    endif()
    set_source_files_properties(${_ninlil_wifi_srcs} PROPERTIES
        COMPILE_OPTIONS "-Wvla;-fstack-usage;-Wframe-larger-than=8192"
    )
endif()

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

# Private FRAG enable: N6/R2 path + private compile defs. Not public ABI.
# ENDPOINT resource profile for ESP (docs/30 §13 endpoint pins): smaller
# reasm/payload so multi-instance BSS stays within device budgets.
if(CONFIG_NINLIL_ENABLE_R7_FRAG_PRIVATE)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE
        NINLIL_R7_FRAG_PRIVATE=1
        NINLIL_R7_FRAG_WITH_N6=1
        NINLIL_R7_FRAG_PROFILE_ENDPOINT=1
        # Light target smoke: one ENDPOINT reasm engine, no session BSS.
        NINLIL_R7_FRAG_SMOKE_LIGHT=1
        # Lab session/test durable TUs are not in ESP production sources.
        NINLIL_R7_FRAG_SESS_WITH_TEST_DURABLE=0
    )
    set(_ninlil_r7_frag_srcs "")
    foreach(_rel IN LISTS NINLIL_R7_FRAG_PRODUCTION_RELATIVE_SOURCES)
        list(APPEND _ninlil_r7_frag_srcs "${NINLIL_REPO_ROOT}/${_rel}")
    endforeach()
    set_source_files_properties(${_ninlil_r7_frag_srcs} PROPERTIES
        COMPILE_OPTIONS "-Wvla;-fstack-usage;-Wframe-larger-than=4096"
    )
endif()
