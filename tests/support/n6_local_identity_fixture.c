#include "n6_local_identity_fixture.h"

#include <string.h>

static ninlil_n6_local_identity_accept_status_t n6_fix_consume(
    void *user,
    ninlil_n6_accepted_local_identity_token_t *mutable_token,
    ninlil_n6_local_identity_claim_t *claim_out)
{
    n6_local_id_fixture_user_t *u = (n6_local_id_fixture_user_t *)user;
    ninlil_n6_local_identity_accept_status_t st;

    if (u != NULL) {
        u->consume_calls += 1u;
    }
    if (mutable_token == NULL || claim_out == NULL) {
        return NINLIL_N6_LOCAL_ID_ACCEPT_INTERNAL;
    }
    mutable_token->consume_count += 1u;
    if (mutable_token->live == 0u) {
        return NINLIL_N6_LOCAL_ID_ACCEPT_STALE;
    }
    mutable_token->live = 0u;
    st = (ninlil_n6_local_identity_accept_status_t)mutable_token->scripted_status;
    if (st != NINLIL_N6_LOCAL_ID_ACCEPT_OK) {
        return st;
    }
    if (mutable_token->bad_shape != 0u) {
        claim_out->abi_version = 99u;
        claim_out->struct_size = 1u;
        claim_out->reserved_zero = 1u;
        return NINLIL_N6_LOCAL_ID_ACCEPT_OK;
    }
    claim_out->abi_version = NINLIL_N6_LOCAL_ID_CLAIM_ABI;
    claim_out->reserved_zero = 0u;
    (void)memcpy(claim_out->local_node_id, mutable_token->node_id16, 16u);
    /* Exact-size KAT: non-zero claim_struct_size overrides wire size field. */
    if (mutable_token->claim_struct_size != 0u) {
        claim_out->struct_size = mutable_token->claim_struct_size;
    } else {
        claim_out->struct_size = NINLIL_N6_LOCAL_ID_CLAIM_BYTES;
    }
    return NINLIL_N6_LOCAL_ID_ACCEPT_OK;
}

void n6_local_id_fixture_token_mint(
    ninlil_n6_accepted_local_identity_token_t *tok,
    const uint8_t node_id16[16],
    uint32_t scripted_status)
{
    if (tok == NULL) {
        return;
    }
    (void)memset(tok, 0, sizeof(*tok));
    tok->live = 1u;
    tok->scripted_status = scripted_status;
    if (node_id16 != NULL) {
        (void)memcpy(tok->node_id16, node_id16, 16u);
    }
}

void n6_local_id_fixture_token_mint_fill(
    ninlil_n6_accepted_local_identity_token_t *tok,
    uint8_t fill,
    uint32_t scripted_status)
{
    uint8_t id[16];
    (void)memset(id, fill, sizeof(id));
    n6_local_id_fixture_token_mint(tok, id, scripted_status);
}

void n6_local_id_fixture_ops_init(
    ninlil_n6_local_identity_ops_t *ops, n6_local_id_fixture_user_t *user)
{
    if (ops == NULL) {
        return;
    }
    (void)memset(ops, 0, sizeof(*ops));
    ops->abi_version = NINLIL_N6_LOCAL_ID_OPS_ABI;
    ops->struct_size = (uint16_t)sizeof(ninlil_n6_local_identity_ops_t);
    ops->reserved_zero = 0u;
    ops->user = user;
    ops->consume = n6_fix_consume;
}

ninlil_n6_status_t n6_local_id_fixture_bind(
    ninlil_n6_t *n6, const uint8_t node_id16[16])
{
    ninlil_n6_accepted_local_identity_token_t tok;
    n6_local_id_fixture_user_t user;
    ninlil_n6_local_identity_ops_t ops;

    (void)memset(&user, 0, sizeof(user));
    n6_local_id_fixture_token_mint(&tok, node_id16, NINLIL_N6_LOCAL_ID_ACCEPT_OK);
    n6_local_id_fixture_ops_init(&ops, &user);
    return ninlil_n6_bind_local_identity_accepted(n6, &ops, &tok);
}

ninlil_n6_status_t n6_local_id_fixture_bind_fill(ninlil_n6_t *n6, uint8_t fill)
{
    uint8_t id[16];
    (void)memset(id, fill, sizeof(id));
    return n6_local_id_fixture_bind(n6, id);
}
