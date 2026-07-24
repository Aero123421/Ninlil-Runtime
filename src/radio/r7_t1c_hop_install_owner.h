#ifndef NINLIL_R7_T1C_HOP_INSTALL_OWNER_H
#define NINLIL_R7_T1C_HOP_INSTALL_OWNER_H

/*
 * R7 T1c Hop fresh-install owner — token/claim surface (docs/34 §4).
 * Production-private. M4 mints complete tokens; T1c consume is item 8.
 *
 * SEMANTIC: R7_T1C_M4_HOP_TOKEN_ONE_SHOT_CONSUME
 * SEMANTIC: R7_T1C_CLAIM_COPY_OWNED_NO_CALLER_SPANS
 * SEMANTIC: R7_T1C_PUBLIC_ABI_UNCHANGED
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_R7_T1C_HOP_ACCEPT_OK       ((uint32_t)0u)
#define NINLIL_R7_T1C_HOP_ACCEPT_REJECTED ((uint32_t)1u)
#define NINLIL_R7_T1C_HOP_ACCEPT_STALE    ((uint32_t)2u)
#define NINLIL_R7_T1C_HOP_ACCEPT_INTERNAL ((uint32_t)3u)

#define NINLIL_R7_T1C_HOP_CLAIM_ABI   ((uint16_t)1u)
#define NINLIL_R7_T1C_HOP_CLAIM_BYTES ((uint16_t)272u)
#define NINLIL_R7_T1C_HOP_OPS_ABI     ((uint16_t)1u)

#define NINLIL_R7_T1C_SITE_MAX ((uint16_t)16u)
#define NINLIL_R7_T1C_ID_MAX     ((uint16_t)32u)

typedef uint32_t ninlil_r7_t1c_hop_accept_status_t;

typedef struct ninlil_r7_t1c_hop_install_token
    ninlil_r7_t1c_hop_install_token_t;

typedef struct ninlil_r7_t1c_hop_install_claim {
    uint16_t abi_version;
    uint16_t struct_size;
    uint32_t reserved_zero;

    uint8_t environment_code;
    uint8_t direction_code;
    uint8_t alloc_side;
    uint8_t reserved1;

    uint16_t site_domain_len;
    uint16_t attachment_id_len;
    uint16_t initiator_stable_id_len;
    uint16_t responder_stable_id_len;
    uint16_t controller_authority_id_len;
    uint16_t reserved2;

    uint8_t site_domain[16];
    uint8_t attachment_id[32];
    uint8_t initiator_stable_id[32];
    uint8_t responder_stable_id[32];
    uint8_t controller_authority_id[32];

    uint64_t membership_epoch;
    uint64_t attachment_epoch;
    uint64_t controller_term;
    uint32_t hop_context_id;
    uint32_t reserved3;

    uint8_t expected_digest32[32];
    uint8_t traffic_secret32[32];
    uint64_t key_generation;
} ninlil_r7_t1c_hop_install_claim_t;

typedef struct ninlil_r7_t1c_hop_install_ops {
    uint16_t abi_version;
    uint16_t struct_size;
    uint32_t reserved_zero;
    void *user;
    ninlil_r7_t1c_hop_accept_status_t (*consume)(
        void *user,
        ninlil_r7_t1c_hop_install_token_t *mutable_token,
        ninlil_r7_t1c_hop_install_claim_t *claim_out);
} ninlil_r7_t1c_hop_install_ops_t;

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_T1C_HOP_INSTALL_OWNER_H */
