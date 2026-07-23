# Single authority for production private Runtime sources.
# Host CMakeLists.txt and ports/esp-idf/components/ninlil both include this file.
# Paths are relative to the repository root. Do not use file(GLOB).
#
# Keep this list explicit: generated fixtures, tests/, tools/, and host-only
# contract/reducer sources must not appear here.

include("${CMAKE_CURRENT_LIST_DIR}/ninlil_r7_crypto_sources.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/ninlil_r7_wire_sources.cmake")

set(NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    src/model/control_frame_codec.c
    src/model/domain_store_body_codec.c
    src/model/domain_store_codec.c
    src/model/ncl1_codec.c
    src/model/resource_ledger.c
    src/model/resource_ledger_batch.c
    src/model/runtime_lifecycle_model.c
    src/model/runtime_store_bootstrap.c
    src/model/runtime_store_codec.c
    src/model/submission_admission.c
    src/model/submission_preflight.c
    src/runtime/domain_store_d3s1.c
    src/runtime/domain_store_d3s2.c
    src/runtime/domain_store_d3s3.c
    src/runtime/domain_store_scanner.c
    src/runtime/runtime_public.c
    src/runtime/runtime_store_orchestrator.c
    src/runtime/runtime_store_stage5_seam.c
    src/runtime/runtime_v1_spine_durable.c
    src/runtime/runtime_v1_delivery_durable.c
    src/runtime/runtime_v1_capability.c
    src/runtime/runtime_v1_event_mgmt.c
    src/runtime/submission_canonical_v1.c
    src/runtime/stage5_empty_metadata.c
    src/runtime/v1_durable_allowlist.c
    src/runtime/v1_durable_restart.c
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

# Expand N6 production set and R7 T0 portable crypto into the shared private
# runtime source list. Keep this exact two-variable append block so T0
# platform-split mutation authority remains honest (do not fold T1 into it).
list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    ${NINLIL_N6_PRODUCTION_RELATIVE_SOURCES}
    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}
)

# R7 T1 NRW1 SINGLE pure wire codec (docs/32): separate append so T0 authority
# tokens stay exact-once and are not weakened.
list(APPEND NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    ${NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES}
)

set(NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES
    src/model/ncl1_codec.c
    src/runtime/domain_store_scanner.c
    src/runtime/domain_store_d3s1.c
    src/runtime/domain_store_d3s2.c
    src/runtime/domain_store_d3s3.c
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
    ${NINLIL_R7_CRYPTO_PORTABLE_RELATIVE_SOURCES}
    ${NINLIL_R7_CRYPTO_HOST_RELATIVE_SOURCES}
    ${NINLIL_R7_WIRE_PORTABLE_RELATIVE_SOURCES}
)
