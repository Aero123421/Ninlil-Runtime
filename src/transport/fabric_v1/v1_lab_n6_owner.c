/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_lab_n6_owner.h"

#include "r7_context_binding.h"
#include "v1_lab_binding.h"

#include <string.h>

struct ninlil_n6_accepted_local_identity_token {
    uint32_t live;
    uint8_t node_id[16];
};

struct ninlil_n6_accepted_authority_token {
    uint32_t live;
    ninlil_n6_authority_claim_t claim;
};

struct ninlil_n6_accepted_install_token {
    uint32_t live;
    ninlil_n6_install_claim_t claim;
};

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t i;

    if (bytes == NULL) {
        return 0;
    }
    for (i = 0u; i < length; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any != 0u;
}

static int owner_known(const ninlil_v1_lab_n6_owner_t *owner)
{
    return owner != NULL && owner->magic == NINLIL_V1_LAB_N6_OWNER_MAGIC
        && owner->active != 0u;
}

static int owner_live(const ninlil_v1_lab_n6_owner_t *owner)
{
    return owner_known(owner) && owner->n6 != NULL;
}

static ninlil_n6_local_identity_accept_status_t consume_local_identity(
    void *user,
    ninlil_n6_accepted_local_identity_token_t *token,
    ninlil_n6_local_identity_claim_t *claim_out)
{
    (void)user;
    if (token == NULL || claim_out == NULL) {
        return NINLIL_N6_LOCAL_ID_ACCEPT_INTERNAL;
    }
    if (token->live == 0u) {
        return NINLIL_N6_LOCAL_ID_ACCEPT_STALE;
    }
    token->live = 0u;
    (void)memset(claim_out, 0, sizeof(*claim_out));
    claim_out->abi_version = NINLIL_N6_LOCAL_ID_CLAIM_ABI;
    claim_out->struct_size = NINLIL_N6_LOCAL_ID_CLAIM_BYTES;
    (void)memcpy(claim_out->local_node_id, token->node_id, 16u);
    ninlil_n6_secure_zero(token->node_id, sizeof(token->node_id));
    return NINLIL_N6_LOCAL_ID_ACCEPT_OK;
}

static ninlil_n6_authority_accept_status_t consume_authority(
    void *user,
    ninlil_n6_accepted_authority_token_t *token,
    ninlil_n6_authority_claim_t *claim_out)
{
    (void)user;
    if (token == NULL || claim_out == NULL) {
        return NINLIL_N6_AUTHORITY_ACCEPT_INTERNAL;
    }
    if (token->live == 0u) {
        return NINLIL_N6_AUTHORITY_ACCEPT_STALE;
    }
    token->live = 0u;
    *claim_out = token->claim;
    ninlil_n6_secure_zero(&token->claim, sizeof(token->claim));
    return NINLIL_N6_AUTHORITY_ACCEPT_OK;
}

static ninlil_n6_install_accept_status_t consume_install(
    void *user,
    ninlil_n6_accepted_install_token_t *token,
    ninlil_n6_install_claim_t *claim_out)
{
    (void)user;
    if (token == NULL || claim_out == NULL) {
        return NINLIL_N6_INSTALL_ACCEPT_INTERNAL;
    }
    if (token->live == 0u) {
        return NINLIL_N6_INSTALL_ACCEPT_STALE;
    }
    token->live = 0u;
    *claim_out = token->claim;
    ninlil_n6_secure_zero(&token->claim, sizeof(token->claim));
    return NINLIL_N6_INSTALL_ACCEPT_OK;
}

static void owner_fence(ninlil_v1_lab_n6_owner_t *owner)
{
    if (owner != NULL) {
        ninlil_n6_t *n6 = owner->n6;
        owner->fenced = 1u;
        owner->booted = 0u;
        owner->n6 = NULL;
        if (n6 != NULL) {
            (void)ninlil_n6_shutdown(n6);
        }
        ninlil_n6_secure_zero(&owner->n6_crypto, sizeof(owner->n6_crypto));
        ninlil_n6_secure_zero(&owner->r7_crypto, sizeof(owner->r7_crypto));
        ninlil_n6_secure_zero(
            owner->local_runtime_id, sizeof(owner->local_runtime_id));
        ninlil_n6_secure_zero(
            owner->local_node_id, sizeof(owner->local_node_id));
        ninlil_n6_secure_zero(owner->authority_clock_epoch_id,
            sizeof(owner->authority_clock_epoch_id));
    }
}

ninlil_n6_status_t ninlil_v1_lab_n6_owner_init(
    ninlil_v1_lab_n6_owner_t *owner,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const uint8_t local_runtime_id[16])
{
    ninlil_n6_local_identity_ops_t identity_ops;
    ninlil_n6_accepted_local_identity_token_t identity_token;
    ninlil_n6_status_t st;
    uint8_t node_id[16];

    if (owner == NULL || n6 == NULL || storage == NULL || n6_crypto == NULL
        || r7_crypto == NULL || local_runtime_id == NULL
        || n6_crypto->sha256 == NULL || n6_crypto->hkdf_sha256 == NULL
        || !bytes_nonzero(local_runtime_id, 16u)
        || ninlil_r7_crypto_provider_validate(r7_crypto)
            != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (ninlil_n6_node_id16_from_stable(
            n6_crypto, local_runtime_id, 16u, node_id)
        != 0) {
        return NINLIL_N6_CRYPTO;
    }

    (void)memset(owner, 0, sizeof(*owner));
    owner->magic = NINLIL_V1_LAB_N6_OWNER_MAGIC;
    owner->active = 1u;
    owner->n6 = n6;
    owner->n6_crypto = *n6_crypto;
    owner->r7_crypto = *r7_crypto;
    (void)memcpy(owner->local_runtime_id, local_runtime_id, 16u);
    (void)memcpy(owner->local_node_id, node_id, 16u);
    ninlil_n6_secure_zero(node_id, sizeof(node_id));

    st = ninlil_n6_bind_storage(n6, storage);
    if (st != NINLIL_N6_OK) {
        owner_fence(owner);
        return st;
    }
    st = ninlil_n6_bind_crypto(n6, n6_crypto);
    if (st != NINLIL_N6_OK) {
        owner_fence(owner);
        return st;
    }

    (void)memset(&identity_ops, 0, sizeof(identity_ops));
    identity_ops.abi_version = NINLIL_N6_LOCAL_ID_OPS_ABI;
    identity_ops.struct_size = (uint16_t)sizeof(identity_ops);
    identity_ops.consume = consume_local_identity;
    (void)memset(&identity_token, 0, sizeof(identity_token));
    identity_token.live = 1u;
    (void)memcpy(identity_token.node_id, owner->local_node_id, 16u);
    st = ninlil_n6_bind_local_identity_accepted(
        n6, &identity_ops, &identity_token);
    ninlil_n6_secure_zero(&identity_token, sizeof(identity_token));
    if (st != NINLIL_N6_OK) {
        owner_fence(owner);
        return st;
    }
    return NINLIL_N6_OK;
}

static int class_d_result_valid(
    const ninlil_r2_authority_clock_result_t *result)
{
    return result != NULL
        && result->typed_class == NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH
        && result->sample_fields_valid == 1u
        && result->sample_trust == NINLIL_CLOCK_TRUSTED
        && result->result_catalog == NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP
        && result->exact_status == NINLIL_PCP_OK
        && result->business_mutation == NINLIL_R2_SAMPLE_BUSINESS_ZERO
        && result->durable_meta_mutation == NINLIL_R2_SAMPLE_META_ZERO
        && result->txn_provenance == NINLIL_R2_SAMPLE_PRECHECK_ZERO
        && bytes_nonzero(result->sample_epoch_id, 16u);
}

ninlil_n6_status_t ninlil_v1_lab_n6_owner_boot_from_class_d(
    ninlil_v1_lab_n6_owner_t *owner,
    const ninlil_r2_authority_clock_result_t *result)
{
    ninlil_n6_authority_ops_t ops;
    ninlil_n6_accepted_authority_token_t token;
    ninlil_n6_status_t st;

    if (!owner_known(owner) || result == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (owner->fenced != 0u) {
        return NINLIL_N6_FENCED;
    }
    if (!owner_live(owner)) {
        return NINLIL_N6_INVALID_STATE;
    }
    if (owner->booted != 0u) {
        return NINLIL_N6_INVALID_STATE;
    }
    if (!class_d_result_valid(result)) {
        return NINLIL_N6_M4_REQUIRED;
    }

    (void)memset(&ops, 0, sizeof(ops));
    ops.abi_version = NINLIL_N6_AUTHORITY_OPS_ABI;
    ops.struct_size = (uint16_t)sizeof(ops);
    ops.consume = consume_authority;
    (void)memset(&token, 0, sizeof(token));
    token.live = 1u;
    token.claim.abi_version = NINLIL_N6_AUTHORITY_CLAIM_ABI;
    token.claim.struct_size = NINLIL_N6_AUTHORITY_CLAIM_BYTES;
    (void)memcpy(
        token.claim.clock_epoch_id, result->sample_epoch_id, 16u);
    token.claim.now_ms = result->sample_now_ms;
    st = ninlil_n6_bind_authority_stamp_accepted(owner->n6, &ops, &token);
    ninlil_n6_secure_zero(&token, sizeof(token));
    if (st != NINLIL_N6_OK) {
        owner_fence(owner);
        return st;
    }
    st = ninlil_n6_boot_scan(owner->n6);
    if (st != NINLIL_N6_OK) {
        owner_fence(owner);
        return st;
    }
    (void)memcpy(
        owner->authority_clock_epoch_id, result->sample_epoch_id, 16u);
    owner->booted = 1u;
    return NINLIL_N6_OK;
}

static const ninlil_v1_lab_endpoint_t *endpoint_for_side(
    const ninlil_v1_lab_binding_t *binding, uint8_t side)
{
    return side == NINLIL_V1_LAB_SIDE_A ? &binding->endpoint_a
                                        : &binding->endpoint_b;
}

static uint8_t opposite_side(uint8_t side)
{
    return side == NINLIL_V1_LAB_SIDE_A ? NINLIL_V1_LAB_SIDE_B
                                        : NINLIL_V1_LAB_SIDE_A;
}

static uint8_t direction_for_flow(
    const ninlil_v1_lab_binding_t *binding, uint8_t flow)
{
    uint8_t sender = flow == NINLIL_V1_LAB_FLOW_A_TO_B
        ? NINLIL_V1_LAB_SIDE_A
        : NINLIL_V1_LAB_SIDE_B;
    return sender == binding->controller_side ? NINLIL_N6_DIR_IR
                                               : NINLIL_N6_DIR_RI;
}

static int binding_digest_for(
    const ninlil_v1_lab_n6_owner_t *owner,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t flow,
    uint8_t layer,
    uint32_t context_id,
    uint8_t out_digest[32])
{
    const ninlil_v1_lab_endpoint_t *controller =
        endpoint_for_side(binding, binding->controller_side);
    const ninlil_v1_lab_endpoint_t *peer =
        endpoint_for_side(binding, opposite_side(binding->controller_side));
    uint8_t sender_side = flow == NINLIL_V1_LAB_FLOW_A_TO_B
        ? NINLIL_V1_LAB_SIDE_A
        : NINLIL_V1_LAB_SIDE_B;
    const ninlil_v1_lab_endpoint_t *sender =
        endpoint_for_side(binding, sender_side);
    const ninlil_v1_lab_endpoint_t *receiver =
        endpoint_for_side(binding, opposite_side(sender_side));
    uint8_t direction = direction_for_flow(binding, flow);

    if (layer == NINLIL_N6_LAYER_HOP) {
        ninlil_r7_hop_binding_input input;
        (void)memset(&input, 0, sizeof(input));
        input.environment_code = NINLIL_R7_BINDING_ENV_LAB;
        input.site_domain.bytes = binding->radio_site_domain_id;
        input.site_domain.length = 16u;
        input.membership_epoch = binding->radio_membership_epoch;
        input.attachment_id.bytes = binding->pair_binding_digest;
        input.attachment_id.length = 32u;
        input.attachment_epoch = binding->pair_generation;
        input.initiator_stable_id.bytes = controller->runtime_id;
        input.initiator_stable_id.length = 16u;
        input.responder_stable_id.bytes = peer->runtime_id;
        input.responder_stable_id.length = 16u;
        input.controller_authority_id.bytes = controller->runtime_id;
        input.controller_authority_id.length = 16u;
        input.controller_term = binding->pair_generation;
        input.hop_context_id = context_id;
        input.direction_code = direction;
        return ninlil_r7_digest_hop_binding(
                   &owner->r7_crypto, &input, out_digest)
                == NINLIL_R7_BINDING_OK
            ? 1
            : 0;
    }
    {
        ninlil_r7_e2e_binding_input input;
        (void)memset(&input, 0, sizeof(input));
        input.environment_code = NINLIL_R7_BINDING_ENV_LAB;
        input.site_domain.bytes = binding->radio_site_domain_id;
        input.site_domain.length = 16u;
        input.membership_epoch = binding->radio_membership_epoch;
        input.e2e_security_id.bytes = binding->e2e_security_id;
        input.e2e_security_id.length = 32u;
        input.e2e_security_epoch = binding->pair_generation;
        input.sender_stable_id.bytes = sender->runtime_id;
        input.sender_stable_id.length = 16u;
        input.receiver_stable_id.bytes = receiver->runtime_id;
        input.receiver_stable_id.length = 16u;
        input.authority_id.bytes = controller->runtime_id;
        input.authority_id.length = 16u;
        input.authority_term = binding->pair_generation;
        input.e2e_context_id = context_id;
        input.direction_code = direction;
        return ninlil_r7_digest_e2e_binding(
                   &owner->r7_crypto, &input, out_digest)
                == NINLIL_R7_BINDING_OK
            ? 1
            : 0;
    }
}

static ninlil_n6_status_t install_one(
    ninlil_v1_lab_n6_owner_t *owner,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t local_side,
    uint8_t flow,
    uint8_t layer,
    uint32_t context_id,
    const uint8_t secret[32],
    ninlil_n6_handle_t *out_handle)
{
    ninlil_n6_install_ops_t ops;
    ninlil_n6_accepted_install_token_t token;
    const ninlil_v1_lab_endpoint_t *receiver;
    uint8_t receiver_side;
    uint8_t receiver_node_id[16];
    ninlil_n6_status_t st;

    receiver_side = flow == NINLIL_V1_LAB_FLOW_A_TO_B
        ? NINLIL_V1_LAB_SIDE_B
        : NINLIL_V1_LAB_SIDE_A;
    receiver = endpoint_for_side(binding, receiver_side);
    if (ninlil_n6_node_id16_from_stable(
            &owner->n6_crypto, receiver->runtime_id, 16u, receiver_node_id)
        != 0) {
        return NINLIL_N6_CRYPTO;
    }

    (void)memset(&token, 0, sizeof(token));
    token.live = 1u;
    token.claim.abi_version = NINLIL_N6_INSTALL_CLAIM_ABI;
    token.claim.struct_size = NINLIL_N6_INSTALL_CLAIM_BYTES;
    token.claim.layer_code = layer;
    token.claim.direction_code = direction_for_flow(binding, flow);
    token.claim.alloc_side = local_side == receiver_side
        ? NINLIL_N6_ALLOC_INBOUND_RX
        : NINLIL_N6_ALLOC_OUTBOUND_TX;
    token.claim.context_id = context_id;
    token.claim.membership_epoch = binding->radio_membership_epoch;
    token.claim.key_generation = binding->pair_generation;
    if (!binding_digest_for(
            owner, binding, flow, layer, context_id,
            token.claim.binding_digest32)) {
        ninlil_n6_secure_zero(&token, sizeof(token));
        ninlil_n6_secure_zero(receiver_node_id, sizeof(receiver_node_id));
        return NINLIL_N6_CRYPTO;
    }
    (void)memcpy(token.claim.traffic_secret32, secret, 32u);
    (void)memcpy(token.claim.local_node_id, owner->local_node_id, 16u);
    (void)memcpy(token.claim.receiver_node_id, receiver_node_id, 16u);
    ninlil_n6_secure_zero(receiver_node_id, sizeof(receiver_node_id));

    (void)memset(&ops, 0, sizeof(ops));
    ops.abi_version = NINLIL_N6_INSTALL_OPS_ABI;
    ops.struct_size = (uint16_t)sizeof(ops);
    ops.consume = consume_install;
    if (layer == NINLIL_N6_LAYER_HOP) {
        st = ninlil_n6_install_hop_accepted(
            owner->n6, &ops, &token, out_handle);
    } else {
        st = ninlil_n6_install_e2e_accepted(
            owner->n6, &ops, &token, out_handle);
    }
    ninlil_n6_secure_zero(&token, sizeof(token));
    return st;
}

ninlil_n6_status_t ninlil_v1_lab_n6_owner_install_pair(
    ninlil_v1_lab_n6_owner_t *owner,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    ninlil_v1_lab_n6_handles_t *out_handles)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_v1_lab_binding_status_t binding_st;
    ninlil_n6_status_t st;
    uint8_t local_side = 0u;
    const ninlil_v1_lab_endpoint_t *local_endpoint;

    if (out_handles != NULL) {
        (void)memset(out_handles, 0, sizeof(*out_handles));
    }
    if (!owner_known(owner) || encoded_binding == NULL || out_handles == NULL) {
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    if (owner->fenced != 0u) {
        return NINLIL_N6_FENCED;
    }
    if (!owner_live(owner)) {
        return NINLIL_N6_INVALID_STATE;
    }
    if (owner->booted == 0u) {
        return NINLIL_N6_INVALID_STATE;
    }
    owner->last_install_count = 0u;

    (void)memset(&binding, 0, sizeof(binding));
    (void)memset(&handles, 0, sizeof(handles));
    binding_st = ninlil_v1_lab_binding_decode(
        &owner->r7_crypto, encoded_binding, encoded_length, &binding);
    if (binding_st != NINLIL_V1_LAB_BINDING_OK
        || ninlil_v1_lab_binding_local_side(
               &binding, owner->local_runtime_id, &local_side)
            != NINLIL_V1_LAB_BINDING_OK) {
        ninlil_v1_lab_binding_clear(&binding);
        return NINLIL_N6_INVALID_ARGUMENT;
    }
    local_endpoint = endpoint_for_side(&binding, local_side);
    if (memcmp(
            local_endpoint->clock_epoch_id,
            owner->authority_clock_epoch_id,
            16u)
        != 0) {
        ninlil_v1_lab_binding_clear(&binding);
        return NINLIL_N6_M4_REQUIRED;
    }

    st = install_one(owner, &binding, local_side,
        NINLIL_V1_LAB_FLOW_A_TO_B, NINLIL_N6_LAYER_HOP,
        binding.a_to_b_hop_context_id, binding.a_to_b_hop_secret,
        &handles.a_to_b_hop);
    if (st == NINLIL_N6_OK) {
        owner->last_install_count = 1u;
        st = install_one(owner, &binding, local_side,
            NINLIL_V1_LAB_FLOW_A_TO_B, NINLIL_N6_LAYER_E2E,
            binding.a_to_b_e2e_context_id, binding.a_to_b_e2e_secret,
            &handles.a_to_b_e2e);
    }
    if (st == NINLIL_N6_OK) {
        owner->last_install_count = 2u;
        st = install_one(owner, &binding, local_side,
            NINLIL_V1_LAB_FLOW_B_TO_A, NINLIL_N6_LAYER_HOP,
            binding.b_to_a_hop_context_id, binding.b_to_a_hop_secret,
            &handles.b_to_a_hop);
    }
    if (st == NINLIL_N6_OK) {
        owner->last_install_count = 3u;
        st = install_one(owner, &binding, local_side,
            NINLIL_V1_LAB_FLOW_B_TO_A, NINLIL_N6_LAYER_E2E,
            binding.b_to_a_e2e_context_id, binding.b_to_a_e2e_secret,
            &handles.b_to_a_e2e);
    }
    if (st != NINLIL_N6_OK) {
        (void)memset(&handles, 0, sizeof(handles));
        owner_fence(owner);
        ninlil_v1_lab_binding_clear(&binding);
        return st;
    }
    owner->last_install_count = 4u;
    *out_handles = handles;
    ninlil_v1_lab_binding_clear(&binding);
    return NINLIL_N6_OK;
}

int ninlil_v1_lab_n6_owner_is_fenced(
    const ninlil_v1_lab_n6_owner_t *owner)
{
    return owner_known(owner) && owner->fenced != 0u ? 1 : 0;
}

void ninlil_v1_lab_n6_owner_clear(ninlil_v1_lab_n6_owner_t *owner)
{
    if (owner != NULL) {
        if (owner_live(owner)) {
            (void)ninlil_n6_shutdown(owner->n6);
        }
        ninlil_n6_secure_zero(owner, sizeof(*owner));
    }
}
