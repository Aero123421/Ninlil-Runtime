# Single authority for production private Runtime sources.
# Host CMakeLists.txt and ports/esp-idf/components/ninlil both include this file.
# Paths are relative to the repository root. Do not use file(GLOB).
#
# Keep this list explicit: generated fixtures, tests/, tools/, and host-only
# contract/reducer sources must not appear here.

set(NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    src/model/control_frame_codec.c
    src/model/domain_store_body_codec.c
    src/model/domain_store_codec.c
    src/model/ncl1_codec.c
    src/model/runtime_lifecycle_model.c
    src/model/runtime_store_bootstrap.c
    src/model/runtime_store_codec.c
    src/runtime/domain_store_d3s1.c
    src/runtime/domain_store_d3s2.c
    src/runtime/domain_store_scanner.c
    src/runtime/runtime_store_orchestrator.c
    src/runtime/runtime_store_stage5_seam.c
    src/runtime/stage5_empty_metadata.c
    src/runtime/storage_canonical_plan.c
    src/transport/control_session.c
    src/radio/airtime_calculator.c
    src/radio/radio_hal.c
    src/radio/pcp_authority.c
    src/radio/profile_loader.c
    src/transport/logical_session.c
)

# Exact N6 production private set — single authority (define once).
# Host runtime list, VLA/frame options, ESP packaging, and testbuild expand
# this variable; do not repeat literal path lists.
set(NINLIL_N6_PRODUCTION_RELATIVE_SOURCES
    src/radio/n6_record_codec.c
    src/radio/n6_crypto_host.c
    src/radio/n6_context_store.c
)

# Expand N6 production set into the shared private runtime source list once.
list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
)

set(NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES
    src/model/ncl1_codec.c
    src/runtime/domain_store_scanner.c
    src/runtime/domain_store_d3s1.c
    src/runtime/domain_store_d3s2.c
    src/runtime/runtime_store_stage5_seam.c
    src/runtime/stage5_empty_metadata.c
    src/runtime/runtime_store_orchestrator.c
    src/runtime/storage_canonical_plan.c
    src/transport/control_session.c
    src/radio/airtime_calculator.c
    src/radio/radio_hal.c
    src/radio/pcp_authority.c
    src/radio/profile_loader.c
    src/transport/logical_session.c
    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
)
