# Single source authority for private ADR-0021 MFDT candidate.
#
# Host and ESP-IDF expand these exact lists when the default-OFF enable option is
# on. Do not file(GLOB). Do not install. Do not append into public/installed
# libs (installable ninlil_runtime must stay free of MFDT symbols — see
# tools/mfdt_v1_install_boundary_gate.py). Host path: ninlil_runtime_private only.
# Do not inject test fixtures into the production list.
# ADR-0021 is Accepted; these implementation sources remain private,
# default-OFF, non-installed candidates under that accepted boundary.
#
# Enable contracts:
#   Host:  NINLIL_ENABLE_MFDT_V1_PRIVATE=ON (top-level CMake option, default OFF)
#   ESP:   CONFIG_NINLIL_ENABLE_MFDT_V1_PRIVATE=y (component Kconfig, default n)
#
# Source closure:
#   PRODUCTION — may land in ESP component when Kconfig ON (engine + crypto).
#     Lab FULL store simulator is host-only (not flash driver).
#   LAB — host private lib / unit tests only (in-memory FULL + crash inject).
#
# When disabled: zero MFDT TUs in component archive / public install / default
# smoke ELF (symbol absence is a packaging residual for map gates).
# Not public ABI. Not power-cut/RF HIL without hardware.

set(NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES
    src/runtime/mfdt_v1/mfdt_v1_crypto.c
    src/runtime/mfdt_v1/mfdt_v1_wire.c
    src/runtime/mfdt_v1/mfdt_v1_record.c
    # Private typed storage dispatch used by both the one-slot ESP engine and
    # the four-slot Host coordinator. This is not the Host provider/owner.
    src/runtime/mfdt_v1/mfdt_v1_store_port.c
    src/runtime/mfdt_v1/mfdt_v1_engine.c
    src/runtime/mfdt_v1/mfdt_v1_hil_gate.c
    src/runtime/mfdt_v1/mfdt_v1_ncl1.c
    src/runtime/mfdt_v1/mfdt_v1_pipeline.c
    src/runtime/mfdt_v1/mfdt_v1_bearer_worker.c
    src/runtime/mfdt_v1/mfdt_v1_foundation_carrier.c
    src/runtime/mfdt_v1/mfdt_v1_runtime_owner.c
    src/runtime/mfdt_v1/mfdt_v1_runtime_seam.c
    src/runtime/mfdt_v1/mfdt_v1_spine.c
    src/runtime/mfdt_v1/mfdt_v1_session.c
)

set(NINLIL_MFDT_V1_LAB_RELATIVE_SOURCES
    src/runtime/mfdt_v1/mfdt_v1_store.c
)

# Mutually exclusive private allocator adapters. The portable engine imports
# only mfdt_v1_target_alloc.h; platform SDK headers stay in ports/.
set(NINLIL_MFDT_V1_HOST_ADAPTER_RELATIVE_SOURCES
    src/runtime/mfdt_v1/mfdt_v1_target_alloc.c
)

set(NINLIL_MFDT_V1_ESP_ADAPTER_RELATIVE_SOURCES
    ports/esp-idf/src/mfdt_v1_target_alloc.c
)

# Host-only reference provider and coordinator. These sources are deliberately
# excluded from NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES so the ESP component
# remains the one-slot profile and cannot acquire the 262656-byte Host owner.
set(NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES
    src/runtime/mfdt_v1/mfdt_v1_host_store.c
    src/runtime/mfdt_v1/mfdt_v1_host_coordinator.c
)

# ESP durable FULL adapter (replaces host lab store on component builds).
set(NINLIL_MFDT_V1_ESP_STORE_RELATIVE_SOURCES
    src/runtime/mfdt_v1/mfdt_v1_store_esp.c
)

# Full portable private set (host private lib + host tests).
set(NINLIL_MFDT_V1_PORTABLE_RELATIVE_SOURCES
    ${NINLIL_MFDT_V1_PRODUCTION_RELATIVE_SOURCES}
    ${NINLIL_MFDT_V1_LAB_RELATIVE_SOURCES}
    ${NINLIL_MFDT_V1_HOST_RELATIVE_SOURCES}
    ${NINLIL_MFDT_V1_HOST_ADAPTER_RELATIVE_SOURCES}
)

set(NINLIL_MFDT_V1_SOURCES_AUTHORITY_LOADED TRUE)
