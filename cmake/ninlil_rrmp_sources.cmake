# Single source authority for private RRMP (ADR-0019/0020).
# Portable Runtime sources import only rrmp_sha256_provider.h; the mutually
# exclusive primitive adapters below own platform crypto-library headers.

set(NINLIL_RRMP_PORTABLE_RELATIVE_SOURCES
    src/runtime/route_relay_v1/rrmp_util.c
    src/runtime/route_relay_v1/rrmp_codec.c
    src/runtime/route_relay_v1/rrmp_store.c
    src/runtime/route_relay_v1/rrmp_core.c
    src/runtime/route_relay_v1/rrmp_seam.c
    src/runtime/route_relay_v1/rrmp_fabric_dispatch.c
    src/runtime/route_relay_v1/rrmp_composition.c
)

set(NINLIL_RRMP_HOST_ADAPTER_RELATIVE_SOURCES
    ports/posix/rrmp_sha256_openssl3.c
)

set(NINLIL_RRMP_ESP_ADAPTER_RELATIVE_SOURCES
    ports/esp-idf/src/rrmp_sha256_mbedtls.c
)

set(NINLIL_RRMP_HOST_SIM_RELATIVE_SOURCES
    src/runtime/route_relay_v1/rrmp_sim.c
)
