# Single authority for production private Runtime sources.
# Host CMakeLists.txt and ports/esp-idf/components/ninlil both include this file.
# Paths are relative to the repository root. Do not use file(GLOB).
#
# Keep this list explicit: generated fixtures, tests/, tools/, and host-only
# contract/reducer sources must not appear here.

set(NINLIL_RUNTIME_PRIVATE_RELATIVE_SOURCES
    src/model/domain_store_body_codec.c
    src/model/domain_store_codec.c
    src/model/runtime_lifecycle_model.c
    src/model/runtime_store_bootstrap.c
    src/model/runtime_store_codec.c
    src/runtime/domain_store_d3s1.c
    src/runtime/domain_store_d3s2.c
    src/runtime/domain_store_scanner.c
    src/runtime/runtime_store_orchestrator.c
    src/runtime/runtime_store_stage5_seam.c
)

set(NINLIL_RUNTIME_PRIVATE_VLA_RELATIVE_SOURCES
    src/runtime/domain_store_scanner.c
    src/runtime/domain_store_d3s1.c
    src/runtime/domain_store_d3s2.c
    src/runtime/runtime_store_stage5_seam.c
    src/runtime/runtime_store_orchestrator.c
)
