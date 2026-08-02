#ifndef NINLIL_R7_FRAG_PROFILE_H
#define NINLIL_R7_FRAG_PROFILE_H

/*
 * CELL_64_V1 resource pins (docs/30 §13). Compile-time profile.
 * Default: controller. Define NINLIL_R7_FRAG_PROFILE_ENDPOINT=1 for endpoint.
 */

#include <stddef.h>
#include <stdint.h>

#define NINLIL_R7_FRAG_CONT_UNIT ((uint16_t)180u)
#define NINLIL_R7_FRAG_S_MAX ((uint16_t)126u)
#define NINLIL_R7_FRAG_TOTAL_MAX ((uint32_t)2048u)
#define NINLIL_R7_FRAG_COUNT_MAX ((uint16_t)13u)
#define NINLIL_R7_FRAG_TOMBSTONE_SLOTS ((size_t)32u)
#define NINLIL_R7_FRAG_TOMBSTONE_CANON ((size_t)72u)

#define NINLIL_R7_FRAG_E2E_PREP_MAX ((uint8_t)4u)
#define NINLIL_R7_FRAG_HOP_ATTEMPT_MAX ((uint8_t)4u)
#define NINLIL_R7_FRAG_OUTER_ATTEMPT_MAX ((uint8_t)16u)
#define NINLIL_R7_FRAG_CONTROL_ACK_RESERVE ((size_t)8u)
#define NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2 ((uint8_t)2u)

#define NINLIL_R7_FRAG_LINK_ACK_WAIT_MS ((uint64_t)3000u)
#define NINLIL_R7_FRAG_LINK_RETRY_INTERVAL_MS ((uint64_t)500u)
#define NINLIL_R7_FRAG_LINK_GROUP_TTL_MS ((uint64_t)15000u)
#define NINLIL_R7_FRAG_ACK_WAIT_MS ((uint64_t)5000u)
#define NINLIL_R7_FRAG_RETRY_INTERVAL_MS ((uint64_t)500u)
#define NINLIL_R7_FRAG_SENDER_TTL_MS ((uint64_t)90000u)
#define NINLIL_R7_FRAG_RECEIVER_TTL_MS ((uint64_t)90000u)
#define NINLIL_R7_FRAG_IDLE_MS ((uint64_t)20000u)
#define NINLIL_R7_FRAG_PARTIAL_ACK_IDLE_MS ((uint64_t)2000u)
#define NINLIL_R7_FRAG_TOMBSTONE_TTL_MS ((uint64_t)90000u)

#if defined(NINLIL_R7_FRAG_PROFILE_ENDPOINT) && (NINLIL_R7_FRAG_PROFILE_ENDPOINT)
#define NINLIL_R7_FRAG_REASM_SLOTS ((size_t)2u)
#define NINLIL_R7_FRAG_PAYLOAD_BUDGET ((size_t)4096u)
#define NINLIL_R7_FRAG_MAX_PER_PEER ((size_t)2u)
#define NINLIL_R7_FRAG_OUTGOING_TRANSFERS ((size_t)2u)
#else
/* Controller CELL_64_V1 */
#define NINLIL_R7_FRAG_REASM_SLOTS ((size_t)16u)
#define NINLIL_R7_FRAG_PAYLOAD_BUDGET ((size_t)32768u)
#define NINLIL_R7_FRAG_MAX_PER_PEER ((size_t)2u)
#define NINLIL_R7_FRAG_OUTGOING_TRANSFERS ((size_t)16u)
#endif

#endif /* NINLIL_R7_FRAG_PROFILE_H */
