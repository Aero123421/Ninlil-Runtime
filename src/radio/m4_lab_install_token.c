/*
 * M4 LAB install token mint + T1c consume surface (mint only; consume stub for item 8).
 */

#include "m4_lab_install_token.h"

#include <string.h>

#define M4_DURABLE_KEY_MAGIC_0 ((uint8_t)0x4du)
#define M4_DURABLE_KEY_MAGIC_1 ((uint8_t)0x34u)
#define M4_DURABLE_KEY_MAGIC_2 ((uint8_t)0x54u)

static void m4_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
}

static void m4_store_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static void m4_store_u64_be(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)((v >> 56) & 0xffu);
    out[1] = (uint8_t)((v >> 48) & 0xffu);
    out[2] = (uint8_t)((v >> 40) & 0xffu);
    out[3] = (uint8_t)((v >> 32) & 0xffu);
    out[4] = (uint8_t)((v >> 24) & 0xffu);
    out[5] = (uint8_t)((v >> 16) & 0xffu);
    out[6] = (uint8_t)((v >> 8) & 0xffu);
    out[7] = (uint8_t)(v & 0xffu);
}

static int m4_binding_valid(const ninlil_m4_lab_install_binding_t *b)
{
    if (b == NULL) {
        return 0;
    }
    if (b->site_domain_len == 0u
        || b->site_domain_len > NINLIL_M4_LAB_SITE_DOMAIN_MAX
        || b->attachment_id_len == 0u
        || b->attachment_id_len > NINLIL_M4_LAB_STABLE_ID_MAX
        || b->initiator_stable_id_len == 0u
        || b->initiator_stable_id_len > NINLIL_M4_LAB_STABLE_ID_MAX
        || b->responder_stable_id_len == 0u
        || b->responder_stable_id_len > NINLIL_M4_LAB_STABLE_ID_MAX) {
        return 0;
    }
    if (b->membership_epoch == 0u || b->attachment_epoch == 0u
        || b->hop_context_id == 0u || b->session_id == 0u) {
        return 0;
    }
    if (b->direction_code != NINLIL_R7_BINDING_DIR_IR
        && b->direction_code != NINLIL_R7_BINDING_DIR_RI) {
        return 0;
    }
    return 1;
}

static ninlil_m4_lab_status_t m4_fill_claim(
    const ninlil_m4_lab_install_binding_t *binding,
    const uint8_t expected_digest32[32],
    const uint8_t traffic_secret32[32],
    uint64_t key_generation,
    ninlil_r7_t1c_hop_install_claim_t *claim)
{
    (void)memset(claim, 0, sizeof(*claim));
    claim->abi_version = NINLIL_R7_T1C_HOP_CLAIM_ABI;
    claim->struct_size = NINLIL_R7_T1C_HOP_CLAIM_BYTES;
    claim->environment_code = NINLIL_R7_BINDING_ENV_LAB;
    claim->direction_code = binding->direction_code;
    claim->alloc_side = binding->alloc_side;
    claim->site_domain_len = binding->site_domain_len;
    claim->attachment_id_len = binding->attachment_id_len;
    claim->initiator_stable_id_len = binding->initiator_stable_id_len;
    claim->responder_stable_id_len = binding->responder_stable_id_len;
    claim->controller_authority_id_len = 0u;
    (void)memcpy(claim->site_domain, binding->site_domain, 16u);
    (void)memcpy(claim->attachment_id, binding->attachment_id, 32u);
    (void)memcpy(
        claim->initiator_stable_id, binding->initiator_stable_id, 32u);
    (void)memcpy(
        claim->responder_stable_id, binding->responder_stable_id, 32u);
    claim->membership_epoch = binding->membership_epoch;
    claim->attachment_epoch = binding->attachment_epoch;
    claim->controller_term = 0u;
    claim->hop_context_id = binding->hop_context_id;
    claim->key_generation = key_generation;
    (void)memcpy(claim->expected_digest32, expected_digest32, 32u);
    (void)memcpy(claim->traffic_secret32, traffic_secret32, 32u);
    return NINLIL_M4_LAB_OK;
}

static ninlil_m4_lab_status_t m4_derive_traffic_secret(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t proof_hmac[NINLIL_M4_LAB_PROOF_LEN],
    const uint8_t challenge_nonce[NINLIL_M4_LAB_NONCE_LEN],
    uint32_t session_id,
    uint8_t out_traffic_secret32[32])
{
    static const uint8_t k_label[] = {
        'N', 'I', 'N', 'L', 'I', 'L', '-', 'M', '4', '-',
        'L', 'A', 'B', '-', 'T', 'R', 'A', 'F', 'F', 'I', 'C', '-', 'v', '1'
    };
    uint8_t msg[32u + NINLIL_M4_LAB_NONCE_LEN + 4u + sizeof(k_label)];
    size_t off = 0u;
    ninlil_r7_crypto_status st;

    (void)memcpy(msg + off, proof_hmac, 32u);
    off += 32u;
    (void)memcpy(msg + off, challenge_nonce, NINLIL_M4_LAB_NONCE_LEN);
    off += NINLIL_M4_LAB_NONCE_LEN;
    m4_store_u32_be(msg + off, session_id);
    off += 4u;
    (void)memcpy(msg + off, k_label, sizeof(k_label));
    off += sizeof(k_label);

    st = ninlil_r7_crypto_sha256(provider, msg, off, out_traffic_secret32);
    m4_secure_zero(msg, sizeof(msg));
    if (st != NINLIL_R7_CRYPTO_OK) {
        m4_secure_zero(out_traffic_secret32, 32u);
        return NINLIL_M4_LAB_BACKEND_FAILED;
    }
    return NINLIL_M4_LAB_OK;
}

ninlil_m4_lab_status_t ninlil_m4_lab_install_token_mint(
    const ninlil_r7_crypto_provider *provider,
    const ninlil_m4_lab_install_binding_t *binding,
    const uint8_t proof_hmac[NINLIL_M4_LAB_PROOF_LEN],
    const uint8_t challenge_nonce[NINLIL_M4_LAB_NONCE_LEN],
    ninlil_r7_t1c_hop_install_token_t *out_token,
    ninlil_m4_lab_install_token_mint_result_t *out_result)
{
    ninlil_r7_hop_binding_input hop_in;
    ninlil_r7_binding_bytes site;
    ninlil_r7_binding_bytes attachment;
    ninlil_r7_binding_bytes initiator;
    ninlil_r7_binding_bytes responder;
    ninlil_r7_binding_bytes authority;
    uint8_t expected_digest32[32];
    uint8_t traffic_secret32[32];
    uint64_t key_generation;
    ninlil_m4_lab_status_t st;
    int32_t bind_st;

    if (provider == NULL || binding == NULL || proof_hmac == NULL
        || challenge_nonce == NULL || out_token == NULL
        || out_result == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    (void)memset(out_token, 0, sizeof(*out_token));
    (void)memset(out_result, 0, sizeof(*out_result));
    if (m4_binding_valid(binding) == 0) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    site.bytes = binding->site_domain;
    site.length = binding->site_domain_len;
    attachment.bytes = binding->attachment_id;
    attachment.length = binding->attachment_id_len;
    initiator.bytes = binding->initiator_stable_id;
    initiator.length = binding->initiator_stable_id_len;
    responder.bytes = binding->responder_stable_id;
    responder.length = binding->responder_stable_id_len;
    authority.bytes = NULL;
    authority.length = 0u;

    (void)memset(&hop_in, 0, sizeof(hop_in));
    hop_in.environment_code = NINLIL_R7_BINDING_ENV_LAB;
    hop_in.site_domain = site;
    hop_in.membership_epoch = binding->membership_epoch;
    hop_in.attachment_id = attachment;
    hop_in.attachment_epoch = binding->attachment_epoch;
    hop_in.initiator_stable_id = initiator;
    hop_in.responder_stable_id = responder;
    hop_in.controller_authority_id = authority;
    hop_in.controller_term = 0u;
    hop_in.hop_context_id = binding->hop_context_id;
    hop_in.direction_code = binding->direction_code;

    bind_st = ninlil_r7_digest_hop_binding(
        provider, &hop_in, expected_digest32);
    if (bind_st != NINLIL_R7_BINDING_OK) {
        m4_secure_zero(expected_digest32, sizeof(expected_digest32));
        return NINLIL_M4_LAB_BACKEND_FAILED;
    }

    st = m4_derive_traffic_secret(
        provider,
        proof_hmac,
        challenge_nonce,
        binding->session_id,
        traffic_secret32);
    if (st != NINLIL_M4_LAB_OK) {
        m4_secure_zero(expected_digest32, sizeof(expected_digest32));
        return st;
    }

    key_generation = binding->attachment_epoch;
    out_token->abi_version = NINLIL_M4_LAB_INSTALL_TOKEN_ABI;
    out_token->struct_size = (uint16_t)sizeof(*out_token);
    out_token->live = 1u;
    out_token->consumed = 0u;
    out_token->session_id = binding->session_id;
    (void)memcpy(out_token->traffic_secret32, traffic_secret32, 32u);
    (void)memcpy(out_token->expected_digest32, expected_digest32, 32u);
    (void)m4_fill_claim(
        binding,
        expected_digest32,
        traffic_secret32,
        key_generation,
        &out_token->claim);

    st = ninlil_r7_crypto_sha256(
        provider,
        (const uint8_t *)out_token,
        sizeof(*out_token),
        out_result->token_fingerprint);
    m4_secure_zero(traffic_secret32, sizeof(traffic_secret32));
    m4_secure_zero(expected_digest32, sizeof(expected_digest32));
    if (st != NINLIL_R7_CRYPTO_OK) {
        m4_secure_zero(out_token, sizeof(*out_token));
        return NINLIL_M4_LAB_BACKEND_FAILED;
    }

    st = ninlil_m4_lab_install_token_encode_durable(
        binding->session_id,
        binding->membership_epoch,
        binding->attachment_epoch,
        binding->hop_context_id,
        key_generation,
        out_result->token_fingerprint,
        out_result->durable_key,
        out_result->durable_value);
    if (st != NINLIL_M4_LAB_OK) {
        m4_secure_zero(out_token, sizeof(*out_token));
        return st;
    }
    out_result->success = 1;
    return NINLIL_M4_LAB_OK;
}

ninlil_r7_t1c_hop_accept_status_t ninlil_m4_lab_install_token_consume(
    void *user,
    ninlil_r7_t1c_hop_install_token_t *mutable_token,
    ninlil_r7_t1c_hop_install_claim_t *claim_out)
{
    (void)user;
    if (mutable_token == NULL || claim_out == NULL) {
        return NINLIL_R7_T1C_HOP_ACCEPT_REJECTED;
    }
    if (mutable_token->live == 0u || mutable_token->consumed != 0u) {
        return NINLIL_R7_T1C_HOP_ACCEPT_STALE;
    }
    if (mutable_token->claim.struct_size != NINLIL_R7_T1C_HOP_CLAIM_BYTES
        || mutable_token->claim.abi_version != NINLIL_R7_T1C_HOP_CLAIM_ABI) {
        return NINLIL_R7_T1C_HOP_ACCEPT_REJECTED;
    }
    (void)memcpy(claim_out, &mutable_token->claim, sizeof(*claim_out));
    mutable_token->consumed = 1u;
    mutable_token->live = 0u;
    return NINLIL_R7_T1C_HOP_ACCEPT_OK;
}

void ninlil_m4_lab_install_token_ops_init(
    ninlil_r7_t1c_hop_install_ops_t *ops)
{
    if (ops == NULL) {
        return;
    }
    (void)memset(ops, 0, sizeof(*ops));
    ops->abi_version = NINLIL_R7_T1C_HOP_OPS_ABI;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->consume = ninlil_m4_lab_install_token_consume;
}

ninlil_m4_lab_status_t ninlil_m4_lab_install_token_encode_durable(
    uint32_t session_id,
    uint64_t membership_epoch,
    uint64_t attachment_epoch,
    uint32_t hop_context_id,
    uint64_t key_generation,
    const uint8_t token_fingerprint[32],
    uint8_t out_key[16],
    uint8_t out_value[NINLIL_M4_LAB_DURABLE_RECORD_BYTES])
{
    uint32_t crc;

    if (token_fingerprint == NULL || out_key == NULL || out_value == NULL) {
        return NINLIL_M4_LAB_INVALID_ARGUMENT;
    }
    if (session_id == 0u || membership_epoch == 0u || attachment_epoch == 0u
        || hop_context_id == 0u || key_generation == 0u) {
        return NINLIL_M4_LAB_STRUCTURAL;
    }

    (void)memset(out_key, 0, 16u);
    out_key[0] = M4_DURABLE_KEY_MAGIC_0;
    out_key[1] = M4_DURABLE_KEY_MAGIC_1;
    out_key[2] = M4_DURABLE_KEY_MAGIC_2;
    m4_store_u32_be(out_key + 3, session_id);
    (void)memcpy(out_key + 7, token_fingerprint, 9u);

    (void)memset(out_value, 0, NINLIL_M4_LAB_DURABLE_RECORD_BYTES);
    out_value[0] = 1u;
    out_value[1] = NINLIL_M4_LAB_TOKEN_STATE_MINTED;
    m4_store_u32_be(out_value + 4, session_id);
    m4_store_u64_be(out_value + 8, membership_epoch);
    m4_store_u64_be(out_value + 16, attachment_epoch);
    m4_store_u32_be(out_value + 24, hop_context_id);
    m4_store_u64_be(out_value + 28, key_generation);
    (void)memcpy(out_value + 36, token_fingerprint, 32u);
    crc = ninlil_m4_lab_crc32c(out_value, 68u);
    m4_store_u32_be(out_value + 68, crc);
    return NINLIL_M4_LAB_OK;
}
