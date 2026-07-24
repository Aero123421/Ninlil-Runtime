#include "v1_frame_manifest.h"

static const ninlil_v1_frame_manifest_entry_t k_v1_frame_manifest[] = {
    {NINLIL_V1_FRAME_M4_JOIN_REQUEST, "M4/C2-LAB",
        "Join handshake request (pre-attachment control)"},
    {NINLIL_V1_FRAME_M4_JOIN_CHALLENGE, "M4/C2-LAB",
        "Controller challenge with nonce/epoch"},
    {NINLIL_V1_FRAME_M4_JOIN_RESPONSE, "M4/C2-LAB",
        "Endpoint identity proof response"},
    {NINLIL_V1_FRAME_M4_JOIN_INSTALL, "M4/C2-LAB",
        "Install token delivery after successful join"},
    {NINLIL_V1_FRAME_M4_JOIN_REJECT, "M4/C2-LAB",
        "Explicit join rejection (membership/credential/expiry/replay)"},
    {NINLIL_V1_FRAME_R7_HOP_DATA, "C3-LAB/R7",
        "Post-attachment secure hop DATA lane (NRW1 wire_profile_id=0x11)"},
    {NINLIL_V1_FRAME_R7_HOP_ACK, "C3-LAB/R7",
        "Post-attachment secure hop LINK_ACK lane"},
};

int ninlil_v1_frame_type_is_transmittable(ninlil_v1_frame_type_t type)
{
    uint32_t i;

    for (i = 0u; i < NINLIL_V1_FRAME_MANIFEST_COUNT; ++i) {
        if (k_v1_frame_manifest[i].type == type) {
            return 1;
        }
    }
    return 0;
}

const ninlil_v1_frame_manifest_entry_t *ninlil_v1_frame_manifest_table(
    uint32_t *out_count)
{
    if (out_count != NULL) {
        *out_count = NINLIL_V1_FRAME_MANIFEST_COUNT;
    }
    return k_v1_frame_manifest;
}
