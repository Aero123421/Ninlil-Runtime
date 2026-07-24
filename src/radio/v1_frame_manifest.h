#ifndef NINLIL_RADIO_V1_FRAME_MANIFEST_H
#define NINLIL_RADIO_V1_FRAME_MANIFEST_H

/*
 * V1-LAB exact-set manifest of radio frame types that may reach SPI TX.
 *
 * Normative companion: docs/work/2026-07-23-v1-frame-manifest.md
 * Not public include/ninlil. Not production regulatory certification.
 *
 * SEMANTIC: V1_LAB_EXACT_SET_ONLY
 * SEMANTIC: NO_BEACON_DIAG_RELAY_FRAG_V1
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t ninlil_v1_frame_type_t;

#define NINLIL_V1_FRAME_NONE ((ninlil_v1_frame_type_t)0u)
#define NINLIL_V1_FRAME_M4_JOIN_REQUEST ((ninlil_v1_frame_type_t)1u)
#define NINLIL_V1_FRAME_M4_JOIN_CHALLENGE ((ninlil_v1_frame_type_t)2u)
#define NINLIL_V1_FRAME_M4_JOIN_RESPONSE ((ninlil_v1_frame_type_t)3u)
#define NINLIL_V1_FRAME_M4_JOIN_INSTALL ((ninlil_v1_frame_type_t)4u)
#define NINLIL_V1_FRAME_M4_JOIN_REJECT ((ninlil_v1_frame_type_t)5u)
#define NINLIL_V1_FRAME_R7_HOP_DATA ((ninlil_v1_frame_type_t)6u)
#define NINLIL_V1_FRAME_R7_HOP_ACK ((ninlil_v1_frame_type_t)7u)

#define NINLIL_V1_FRAME_MANIFEST_COUNT ((uint32_t)7u)

typedef struct ninlil_v1_frame_manifest_entry {
    ninlil_v1_frame_type_t type;
    const char *owner;
    const char *purpose;
} ninlil_v1_frame_manifest_entry_t;

int ninlil_v1_frame_type_is_transmittable(ninlil_v1_frame_type_t type);

const ninlil_v1_frame_manifest_entry_t *ninlil_v1_frame_manifest_table(
    uint32_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_V1_FRAME_MANIFEST_H */
