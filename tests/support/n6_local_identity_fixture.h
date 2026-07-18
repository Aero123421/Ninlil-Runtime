#ifndef NINLIL_N6_LOCAL_IDENTITY_FIXTURE_H
#define NINLIL_N6_LOCAL_IDENTITY_FIXTURE_H

/*
 * TEST_ONLY fixture accepted-identity provider (docs/30 §20.4.1).
 * Caller-owned reentrant ops — no shared mutable static user pointer.
 * Calls production ninlil_n6_bind_local_identity_accepted only.
 */

#include "n6_context_store.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ninlil_n6_accepted_local_identity_token {
    uint32_t live;
    uint32_t consume_count;
    uint8_t node_id16[16];
    uint32_t scripted_status;
    uint32_t bad_shape; /* legacy: forces struct_size=1 if claim_struct_size==0 */
    /* If non-zero: write this claim.struct_size (for under/over-size KATs). */
    uint16_t claim_struct_size;
    uint16_t pad0;
};

typedef struct n6_local_id_fixture_user {
    uint32_t consume_calls;
} n6_local_id_fixture_user_t;

void n6_local_id_fixture_token_mint(
    ninlil_n6_accepted_local_identity_token_t *tok,
    const uint8_t node_id16[16],
    uint32_t scripted_status);

void n6_local_id_fixture_token_mint_fill(
    ninlil_n6_accepted_local_identity_token_t *tok,
    uint8_t fill,
    uint32_t scripted_status);

/* Fill caller-owned ops (reentrant). */
void n6_local_id_fixture_ops_init(
    ninlil_n6_local_identity_ops_t *ops, n6_local_id_fixture_user_t *user);

ninlil_n6_status_t n6_local_id_fixture_bind(
    ninlil_n6_t *n6, const uint8_t node_id16[16]);

ninlil_n6_status_t n6_local_id_fixture_bind_fill(ninlil_n6_t *n6, uint8_t fill);

#ifdef __cplusplus
}
#endif

#endif
