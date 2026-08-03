# Single source authority for the public Fabric/Composition v1 implementation.
# Host CMake and the ESP-IDF component include this file. Paths are relative to
# the repository root; tests, examples and platform packet links do not belong
# in these lists.

set(NINLIL_FABRIC_V1_CORE_RELATIVE_SOURCES
    src/transport/fabric_v1/nfl1_codec.c
    src/transport/fabric_v1/fabric_private_util.c
    src/transport/fabric_v1/fabric_workspace.c
    src/transport/fabric_v1/fabric_private_records.c
    src/transport/fabric_v1/fabric_private_select.c
    src/transport/fabric_v1/fabric_private_core.c
)

set(NINLIL_FABRIC_V1_PUBLIC_RELATIVE_SOURCES
    ${NINLIL_FABRIC_V1_CORE_RELATIVE_SOURCES}
    src/transport/fabric_v1/fabric_v1_public.c
)

set(NINLIL_COMPOSITION_V1_RELATIVE_SOURCES
    src/runtime/composition_v1.c
)
