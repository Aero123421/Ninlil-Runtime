/*
 * C3-LAB context lifecycle + T1c token consume install (V1 item 8).
 */

#include "c3_lab_context_lifecycle.h"

#include <string.h>

#define C3_KEY_MAGIC_0 ((uint8_t)0x43u)
#define C3_KEY_MAGIC_1 ((uint8_t)0x33u)
#define C3_KEY_MAGIC_2 ((uint8_t)0x52u)

static void c3_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;

    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
}

static void c3_store_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static void c3_store_u64_be(uint8_t *out, uint64_t v)
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

static int c3_state_allows_install(const ninlil_c3_lab_context_store_t *store)
{
    if (store == NULL) {
        return 0;
    }
    return store->state == NINLIL_C3_LAB_STATE_NONE
        || store->state == NINLIL_C3_LAB_STATE_RESTART_REQUIRED;
}

static int c3_state_allows_wire(const ninlil_c3_lab_context_store_t *store)
{
    if (store == NULL) {
        return 0;
    }
    return store->state == NINLIL_C3_LAB_STATE_ACTIVE;
}

static void c3_lane_init(ninlil_c3_lab_lane_context_t *lane)
{
    if (lane == NULL) {
        return;
    }
    (void)memset(lane, 0, sizeof(*lane));
    lane->tx_next_counter = 1u;
}

static void c3_hop_init(
    ninlil_c3_lab_hop_context_t *hop,
    uint32_t hop_context_id,
    uint64_t epoch,
    uint64_t key_generation,
    uint8_t direction_code,
    const ninlil_r7_hop_key_bundle *bundle)
{
    (void)memset(hop, 0, sizeof(*hop));
    hop->installed = 1u;
    hop->hop_context_id = hop_context_id;
    hop->epoch = epoch;
    hop->key_generation = key_generation;
    hop->direction_code = direction_code;
    c3_lane_init(&hop->data);
    c3_lane_init(&hop->ack);
    (void)memcpy(hop->data.hop_key16, bundle->data_key16, 16u);
    (void)memcpy(hop->data.hop_iv12, bundle->data_iv12, 12u);
    (void)memcpy(hop->ack.hop_key16, bundle->ack_key16, 16u);
    (void)memcpy(hop->ack.hop_iv12, bundle->ack_iv12, 12u);
    hop->data.active = 1u;
    hop->ack.active = 1u;
}

static void c3_e2e_init(
    ninlil_c3_lab_e2e_context_t *e2e,
    uint32_t e2e_context_id,
    uint64_t epoch,
    uint64_t key_generation,
    const ninlil_r7_e2e_key_bundle *bundle)
{
    (void)memset(e2e, 0, sizeof(*e2e));
    e2e->installed = 1u;
    e2e->e2e_context_id = e2e_context_id;
    e2e->epoch = epoch;
    e2e->key_generation = key_generation;
    e2e->tx_next_counter = 1u;
    (void)memcpy(e2e->key16, bundle->key16, 16u);
    (void)memcpy(e2e->iv12, bundle->iv12, 12u);
}

static ninlil_c3_lab_status_t c3_derive_traffic_secret(
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

    (void)memcpy(msg + off, proof_hmac, 32u);
    off += 32u;
    (void)memcpy(msg + off, challenge_nonce, NINLIL_M4_LAB_NONCE_LEN);
    off += NINLIL_M4_LAB_NONCE_LEN;
    c3_store_u32_be(msg + off, session_id);
    off += 4u;
    (void)memcpy(msg + off, k_label, sizeof(k_label));
    off += sizeof(k_label);

    if (ninlil_r7_crypto_sha256(provider, msg, off, out_traffic_secret32)
        != NINLIL_R7_CRYPTO_OK) {
        c3_secure_zero(msg, sizeof(msg));
        c3_secure_zero(out_traffic_secret32, 32u);
        return NINLIL_C3_LAB_BACKEND_FAILED;
    }
    c3_secure_zero(msg, sizeof(msg));
    return NINLIL_C3_LAB_OK;
}

static int c3_claim_to_hop_input(
    const ninlil_r7_t1c_hop_install_claim_t *claim,
    ninlil_r7_hop_binding_input *out)
{
    if (claim == NULL || out == NULL) {
        return 0;
    }
    (void)memset(out, 0, sizeof(*out));
    out->environment_code = claim->environment_code;
    out->site_domain.bytes = claim->site_domain;
    out->site_domain.length = claim->site_domain_len;
    out->membership_epoch = claim->membership_epoch;
    out->attachment_id.bytes = claim->attachment_id;
    out->attachment_id.length = claim->attachment_id_len;
    out->attachment_epoch = claim->attachment_epoch;
    out->initiator_stable_id.bytes = claim->initiator_stable_id;
    out->initiator_stable_id.length = claim->initiator_stable_id_len;
    out->responder_stable_id.bytes = claim->responder_stable_id;
    out->responder_stable_id.length = claim->responder_stable_id_len;
    out->controller_authority_id.bytes =
        claim->controller_authority_id_len == 0u
        ? NULL
        : claim->controller_authority_id;
    out->controller_authority_id.length = claim->controller_authority_id_len;
    out->controller_term = claim->controller_term;
    out->hop_context_id = claim->hop_context_id;
    out->direction_code = claim->direction_code;
    return 1;
}

static int c3_claim_to_e2e_input(
    const ninlil_r7_t1c_hop_install_claim_t *claim,
    uint8_t direction_code,
    ninlil_r7_e2e_binding_input *out)
{
    if (claim == NULL || out == NULL) {
        return 0;
    }
    (void)memset(out, 0, sizeof(*out));
    out->environment_code = claim->environment_code;
    out->site_domain.bytes = claim->site_domain;
    out->site_domain.length = claim->site_domain_len;
    out->membership_epoch = claim->membership_epoch;
    out->e2e_security_id.bytes = claim->attachment_id;
    out->e2e_security_id.length = claim->attachment_id_len;
    out->e2e_security_epoch = claim->attachment_epoch;
    if (direction_code == NINLIL_R7_BINDING_DIR_IR) {
        out->sender_stable_id.bytes = claim->initiator_stable_id;
        out->sender_stable_id.length = claim->initiator_stable_id_len;
        out->receiver_stable_id.bytes = claim->responder_stable_id;
        out->receiver_stable_id.length = claim->responder_stable_id_len;
    } else {
        out->sender_stable_id.bytes = claim->responder_stable_id;
        out->sender_stable_id.length = claim->responder_stable_id_len;
        out->receiver_stable_id.bytes = claim->initiator_stable_id;
        out->receiver_stable_id.length = claim->initiator_stable_id_len;
    }
    out->authority_id.bytes =
        claim->controller_authority_id_len == 0u
        ? NULL
        : claim->controller_authority_id;
    out->authority_id.length = claim->controller_authority_id_len;
    out->authority_term = claim->controller_term;
    out->e2e_context_id = claim->hop_context_id;
    out->direction_code = direction_code;
    return 1;
}

static ninlil_c3_lab_status_t c3_install_from_claim(
    ninlil_c3_lab_context_store_t *store,
    const ninlil_r7_t1c_hop_install_claim_t *claim,
    const uint8_t traffic_secret32[32],
    uint8_t tx_direction,
    uint8_t rx_direction,
    ninlil_c3_lab_install_result_t *out_result)
{
    ninlil_r7_hop_binding_input hop_tx_in;
    ninlil_r7_hop_binding_input hop_rx_in;
    ninlil_r7_e2e_binding_input e2e_tx_in;
    ninlil_r7_e2e_binding_input e2e_rx_in;
    ninlil_r7_hop_key_bundle hop_tx_keys;
    ninlil_r7_hop_key_bundle hop_rx_keys;
    ninlil_r7_e2e_key_bundle e2e_tx_keys;
    ninlil_r7_e2e_key_bundle e2e_rx_keys;
    uint8_t hop_tx_digest[32];
    uint8_t hop_rx_digest[32];
    uint8_t e2e_tx_digest[32];
    uint8_t e2e_rx_digest[32];
    uint64_t epoch;
    ninlil_c3_lab_status_t st = NINLIL_C3_LAB_OK;

    if (!c3_state_allows_install(store)) {
        return NINLIL_C3_LAB_FENCED;
    }
    if (claim->struct_size != NINLIL_R7_T1C_HOP_CLAIM_BYTES
        || claim->abi_version != NINLIL_R7_T1C_HOP_CLAIM_ABI
        || claim->hop_context_id == 0u
        || claim->key_generation == 0u) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    epoch = store->freshness_epoch + 1u;
    if (epoch == 0u) {
        epoch = 1u;
    }

    if (!c3_claim_to_hop_input(claim, &hop_tx_in)) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }
    hop_tx_in.direction_code = tx_direction;
    if (!c3_claim_to_hop_input(claim, &hop_rx_in)) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }
    hop_rx_in.direction_code = rx_direction;

    if (ninlil_r7_digest_hop_binding(
            store->provider, &hop_tx_in, hop_tx_digest)
            != NINLIL_R7_BINDING_OK) {
        c3_secure_zero(hop_tx_digest, sizeof(hop_tx_digest));
        return NINLIL_C3_LAB_BACKEND_FAILED;
    }
    if (tx_direction == claim->direction_code
        && memcmp(hop_tx_digest, claim->expected_digest32, 32u) != 0) {
        c3_secure_zero(hop_tx_digest, sizeof(hop_tx_digest));
        return NINLIL_C3_LAB_AUTH_FAILED;
    }
    if (ninlil_r7_digest_hop_binding(
            store->provider, &hop_rx_in, hop_rx_digest)
        != NINLIL_R7_BINDING_OK) {
        c3_secure_zero(hop_tx_digest, sizeof(hop_tx_digest));
        c3_secure_zero(hop_rx_digest, sizeof(hop_rx_digest));
        return NINLIL_C3_LAB_BACKEND_FAILED;
    }

    if (!c3_claim_to_e2e_input(claim, tx_direction, &e2e_tx_in)
        || !c3_claim_to_e2e_input(claim, rx_direction, &e2e_rx_in)) {
        c3_secure_zero(hop_tx_digest, sizeof(hop_tx_digest));
        c3_secure_zero(hop_rx_digest, sizeof(hop_rx_digest));
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    if (ninlil_r7_digest_e2e_binding(
            store->provider, &e2e_tx_in, e2e_tx_digest)
        != NINLIL_R7_BINDING_OK
        || ninlil_r7_digest_e2e_binding(
            store->provider, &e2e_rx_in, e2e_rx_digest)
            != NINLIL_R7_BINDING_OK) {
        c3_secure_zero(hop_tx_digest, sizeof(hop_tx_digest));
        c3_secure_zero(hop_rx_digest, sizeof(hop_rx_digest));
        c3_secure_zero(e2e_tx_digest, sizeof(e2e_tx_digest));
        c3_secure_zero(e2e_rx_digest, sizeof(e2e_rx_digest));
        return NINLIL_C3_LAB_BACKEND_FAILED;
    }

    if (ninlil_r7_derive_hop_key_bundle_verified(
            store->provider,
            &hop_tx_in,
            hop_tx_digest,
            traffic_secret32,
            &hop_tx_keys)
        != NINLIL_R7_BINDING_OK
        || ninlil_r7_derive_hop_key_bundle_verified(
            store->provider,
            &hop_rx_in,
            hop_rx_digest,
            traffic_secret32,
            &hop_rx_keys)
            != NINLIL_R7_BINDING_OK
        || ninlil_r7_derive_e2e_key_bundle_verified(
            store->provider,
            &e2e_tx_in,
            e2e_tx_digest,
            traffic_secret32,
            &e2e_tx_keys)
            != NINLIL_R7_BINDING_OK
        || ninlil_r7_derive_e2e_key_bundle_verified(
            store->provider,
            &e2e_rx_in,
            e2e_rx_digest,
            traffic_secret32,
            &e2e_rx_keys)
            != NINLIL_R7_BINDING_OK) {
        c3_secure_zero(&hop_tx_keys, sizeof(hop_tx_keys));
        c3_secure_zero(&hop_rx_keys, sizeof(hop_rx_keys));
        c3_secure_zero(&e2e_tx_keys, sizeof(e2e_tx_keys));
        c3_secure_zero(&e2e_rx_keys, sizeof(e2e_rx_keys));
        c3_secure_zero(hop_tx_digest, sizeof(hop_tx_digest));
        c3_secure_zero(hop_rx_digest, sizeof(hop_rx_digest));
        c3_secure_zero(e2e_tx_digest, sizeof(e2e_tx_digest));
        c3_secure_zero(e2e_rx_digest, sizeof(e2e_rx_digest));
        return NINLIL_C3_LAB_AUTH_FAILED;
    }

    c3_hop_init(
        &store->hop_tx,
        claim->hop_context_id,
        epoch,
        claim->key_generation,
        tx_direction,
        &hop_tx_keys);
    c3_hop_init(
        &store->hop_rx,
        claim->hop_context_id,
        epoch,
        claim->key_generation,
        rx_direction,
        &hop_rx_keys);
    c3_e2e_init(
        &store->e2e_tx,
        claim->hop_context_id,
        epoch,
        claim->key_generation,
        &e2e_tx_keys);
    c3_e2e_init(
        &store->e2e_rx,
        claim->hop_context_id,
        epoch,
        claim->key_generation,
        &e2e_rx_keys);

    store->freshness_epoch = epoch;
    store->state = NINLIL_C3_LAB_STATE_ACTIVE;
    store->installed_token_count += 1u;

    if (out_result != NULL) {
        out_result->hop_context_id = claim->hop_context_id;
        out_result->e2e_context_id = claim->hop_context_id;
        out_result->epoch = epoch;
    }

    c3_secure_zero(&hop_tx_keys, sizeof(hop_tx_keys));
    c3_secure_zero(&hop_rx_keys, sizeof(hop_rx_keys));
    c3_secure_zero(&e2e_tx_keys, sizeof(e2e_tx_keys));
    c3_secure_zero(&e2e_rx_keys, sizeof(e2e_rx_keys));
    c3_secure_zero(hop_tx_digest, sizeof(hop_tx_digest));
    c3_secure_zero(hop_rx_digest, sizeof(hop_rx_digest));
    c3_secure_zero(e2e_tx_digest, sizeof(e2e_tx_digest));
    c3_secure_zero(e2e_rx_digest, sizeof(e2e_rx_digest));
    return st;
}

void ninlil_c3_lab_context_store_init(
    ninlil_c3_lab_context_store_t *store,
    const ninlil_r7_crypto_provider *provider)
{
    if (store == NULL) {
        return;
    }
    (void)memset(store, 0, sizeof(*store));
    store->provider = provider;
    store->state = NINLIL_C3_LAB_STATE_NONE;
}

ninlil_c3_lab_status_t ninlil_c3_lab_install_from_token(
    ninlil_c3_lab_context_store_t *store,
    ninlil_r7_t1c_hop_install_token_t *token,
    ninlil_c3_lab_install_result_t *out_result)
{
    ninlil_r7_t1c_hop_install_claim_t claim;
    uint8_t fingerprint[32];
    ninlil_r7_t1c_hop_accept_status_t consume_st;
    ninlil_c3_lab_status_t st;

    if (store == NULL || store->provider == NULL || token == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    if (token->live == 0u || token->consumed != 0u) {
        return NINLIL_C3_LAB_STALE;
    }

    if (ninlil_r7_crypto_sha256(
            store->provider,
            (const uint8_t *)token,
            sizeof(*token),
            fingerprint)
        != NINLIL_R7_CRYPTO_OK) {
        return NINLIL_C3_LAB_BACKEND_FAILED;
    }
    if (store->has_token_fingerprint != 0u
        && memcmp(
            fingerprint,
            store->token_fingerprint_seen,
            32u)
            == 0) {
        c3_secure_zero(fingerprint, sizeof(fingerprint));
        return NINLIL_C3_LAB_STALE;
    }
    if (!c3_state_allows_install(store)) {
        c3_secure_zero(fingerprint, sizeof(fingerprint));
        return NINLIL_C3_LAB_FENCED;
    }

    consume_st = ninlil_m4_lab_install_token_consume(NULL, token, &claim);
    if (consume_st != NINLIL_R7_T1C_HOP_ACCEPT_OK) {
        c3_secure_zero(fingerprint, sizeof(fingerprint));
        if (consume_st == NINLIL_R7_T1C_HOP_ACCEPT_STALE) {
            return NINLIL_C3_LAB_STALE;
        }
        return NINLIL_C3_LAB_REJECTED;
    }
    store->consumed_token_count += 1u;
    (void)memcpy(store->token_fingerprint_seen, fingerprint, 32u);
    store->has_token_fingerprint = 1u;
    c3_secure_zero(fingerprint, sizeof(fingerprint));

    st = c3_install_from_claim(
        store,
        &claim,
        token->traffic_secret32,
        claim.direction_code,
        (uint8_t)(claim.direction_code == NINLIL_R7_BINDING_DIR_IR
            ? NINLIL_R7_BINDING_DIR_RI
            : NINLIL_R7_BINDING_DIR_IR),
        out_result);
    c3_secure_zero(&claim, sizeof(claim));
    return st;
}

ninlil_c3_lab_status_t ninlil_c3_lab_install_responder(
    ninlil_c3_lab_context_store_t *store,
    const ninlil_m4_lab_install_binding_t *binding,
    const uint8_t proof_hmac[NINLIL_M4_LAB_PROOF_LEN],
    const uint8_t challenge_nonce[NINLIL_M4_LAB_NONCE_LEN],
    ninlil_c3_lab_install_result_t *out_result)
{
    ninlil_r7_t1c_hop_install_claim_t claim;
    uint8_t expected_digest32[32];
    uint8_t traffic_secret32[32];
    ninlil_r7_hop_binding_input hop_in;
    ninlil_r7_binding_bytes site;
    ninlil_r7_binding_bytes attachment;
    ninlil_r7_binding_bytes initiator;
    ninlil_r7_binding_bytes responder;
    ninlil_r7_binding_bytes authority;
    ninlil_c3_lab_status_t st;

    if (store == NULL || store->provider == NULL || binding == NULL
        || proof_hmac == NULL || challenge_nonce == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
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
    hop_in.direction_code = NINLIL_R7_BINDING_DIR_IR;

    if (ninlil_r7_digest_hop_binding(
            store->provider, &hop_in, expected_digest32)
        != NINLIL_R7_BINDING_OK) {
        return NINLIL_C3_LAB_BACKEND_FAILED;
    }

    st = c3_derive_traffic_secret(
        store->provider,
        proof_hmac,
        challenge_nonce,
        binding->session_id,
        traffic_secret32);
    if (st != NINLIL_C3_LAB_OK) {
        c3_secure_zero(expected_digest32, sizeof(expected_digest32));
        return st;
    }

    (void)memset(&claim, 0, sizeof(claim));
    claim.abi_version = NINLIL_R7_T1C_HOP_CLAIM_ABI;
    claim.struct_size = NINLIL_R7_T1C_HOP_CLAIM_BYTES;
    claim.environment_code = NINLIL_R7_BINDING_ENV_LAB;
    claim.direction_code = NINLIL_R7_BINDING_DIR_IR;
    claim.alloc_side = binding->alloc_side;
    claim.site_domain_len = binding->site_domain_len;
    claim.attachment_id_len = binding->attachment_id_len;
    claim.initiator_stable_id_len = binding->initiator_stable_id_len;
    claim.responder_stable_id_len = binding->responder_stable_id_len;
    (void)memcpy(claim.site_domain, binding->site_domain, 16u);
    (void)memcpy(claim.attachment_id, binding->attachment_id, 32u);
    (void)memcpy(claim.initiator_stable_id, binding->initiator_stable_id, 32u);
    (void)memcpy(claim.responder_stable_id, binding->responder_stable_id, 32u);
    claim.membership_epoch = binding->membership_epoch;
    claim.attachment_epoch = binding->attachment_epoch;
    claim.hop_context_id = binding->hop_context_id;
    claim.key_generation = binding->attachment_epoch;
    (void)memcpy(claim.expected_digest32, expected_digest32, 32u);
    (void)memcpy(claim.traffic_secret32, traffic_secret32, 32u);

    st = c3_install_from_claim(
        store,
        &claim,
        traffic_secret32,
        NINLIL_R7_BINDING_DIR_RI,
        NINLIL_R7_BINDING_DIR_IR,
        out_result);
    c3_secure_zero(expected_digest32, sizeof(expected_digest32));
    c3_secure_zero(traffic_secret32, sizeof(traffic_secret32));
    c3_secure_zero(&claim, sizeof(claim));
    return st;
}

static void c3_fence_store(ninlil_c3_lab_context_store_t *store)
{
    c3_secure_zero(&store->hop_tx, sizeof(store->hop_tx));
    c3_secure_zero(&store->hop_rx, sizeof(store->hop_rx));
    c3_secure_zero(&store->e2e_tx, sizeof(store->e2e_tx));
    c3_secure_zero(&store->e2e_rx, sizeof(store->e2e_rx));
}

ninlil_c3_lab_status_t ninlil_c3_lab_context_clean_restart(
    ninlil_c3_lab_context_store_t *store)
{
    if (store == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    c3_fence_store(store);
    store->state = NINLIL_C3_LAB_STATE_RESTART_REQUIRED;
    return NINLIL_C3_LAB_OK;
}

ninlil_c3_lab_status_t ninlil_c3_lab_context_commit_unknown_restart(
    ninlil_c3_lab_context_store_t *store)
{
    if (store == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    c3_fence_store(store);
    store->state = NINLIL_C3_LAB_STATE_COMMIT_UNKNOWN;
    return NINLIL_C3_LAB_OK;
}

static ninlil_c3_lab_lane_context_t *c3_lane_ptr(
    ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    uint8_t layer_e2e,
    int tx)
{
    if (store == NULL) {
        return NULL;
    }
    if (layer_e2e != 0u) {
        return NULL;
    }
    if (tx != 0) {
        if (lane == NINLIL_C3_LAB_LANE_DATA) {
            return &store->hop_tx.data;
        }
        if (lane == NINLIL_C3_LAB_LANE_ACK) {
            return &store->hop_tx.ack;
        }
        return NULL;
    }
    if (lane == NINLIL_C3_LAB_LANE_DATA) {
        return &store->hop_rx.data;
    }
    if (lane == NINLIL_C3_LAB_LANE_ACK) {
        return &store->hop_rx.ack;
    }
    return NULL;
}

ninlil_c3_lab_status_t ninlil_c3_lab_tx_burn_counter(
    ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t *out_counter)
{
    uint64_t counter;

    if (store == NULL || out_counter == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    if (!c3_state_allows_wire(store)) {
        return NINLIL_C3_LAB_FENCED;
    }

    if (layer_e2e != 0u) {
        if (store->e2e_tx.installed == 0u) {
            return NINLIL_C3_LAB_STRUCTURAL;
        }
        counter = store->e2e_tx.tx_next_counter;
        if (counter == 0u || counter == UINT64_MAX) {
            return NINLIL_C3_LAB_COUNTER;
        }
        store->e2e_tx.tx_next_counter = counter + 1u;
        *out_counter = counter;
        return NINLIL_C3_LAB_OK;
    }

    {
        ninlil_c3_lab_lane_context_t *lc = c3_lane_ptr(store, lane, 0u, 1);
        if (lc == NULL || lc->active == 0u) {
            return NINLIL_C3_LAB_STRUCTURAL;
        }
        counter = lc->tx_next_counter;
        if (counter == 0u || counter == UINT64_MAX) {
            return NINLIL_C3_LAB_COUNTER;
        }
        lc->tx_next_counter = counter + 1u;
        *out_counter = counter;
        return NINLIL_C3_LAB_OK;
    }
}

static int c3_replay_seen(uint64_t rx_highest, uint64_t window_base, uint64_t bitmap, uint64_t counter)
{
    uint64_t delta;

    (void)window_base;

    if (counter == 0u) {
        return 1;
    }
    if (counter > rx_highest) {
        return 0;
    }
    delta = rx_highest - counter;
    if (delta >= NINLIL_C3_LAB_RX_WINDOW) {
        return 0;
    }
    return ((bitmap >> delta) & 1u) != 0u ? 1 : 0;
}

static void c3_replay_record(
    uint64_t *rx_highest,
    uint64_t *window_base,
    uint64_t *bitmap,
    uint64_t counter)
{
    uint64_t delta;

    if (counter > *rx_highest) {
        delta = counter - *rx_highest;
        if (delta >= NINLIL_C3_LAB_RX_WINDOW) {
            *window_base = counter - (NINLIL_C3_LAB_RX_WINDOW - 1u);
            *bitmap = 1u;
        } else {
            *bitmap <<= (unsigned)delta;
            *bitmap |= 1u;
        }
        *rx_highest = counter;
        return;
    }
    delta = *rx_highest - counter;
    if (delta < NINLIL_C3_LAB_RX_WINDOW) {
        *bitmap |= (1ull << delta);
    }
}

ninlil_c3_lab_status_t ninlil_c3_lab_rx_precheck(
    const ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t counter)
{
    if (store == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    if (!c3_state_allows_wire(store)) {
        return NINLIL_C3_LAB_FENCED;
    }
    if (counter == 0u) {
        return NINLIL_C3_LAB_COUNTER;
    }

    if (layer_e2e != 0u) {
        if (store->e2e_rx.installed == 0u) {
            return NINLIL_C3_LAB_STRUCTURAL;
        }
        if (c3_replay_seen(
                store->e2e_rx.rx_highest,
                store->e2e_rx.rx_window_base,
                store->e2e_rx.rx_bitmap,
                counter)
            != 0) {
            return NINLIL_C3_LAB_REPLAY;
        }
        return NINLIL_C3_LAB_OK;
    }

    {
        const ninlil_c3_lab_lane_context_t *lc;
        if (lane == NINLIL_C3_LAB_LANE_DATA) {
            lc = &store->hop_rx.data;
        } else if (lane == NINLIL_C3_LAB_LANE_ACK) {
            lc = &store->hop_rx.ack;
        } else {
            return NINLIL_C3_LAB_STRUCTURAL;
        }
        if (lc->active == 0u) {
            return NINLIL_C3_LAB_STRUCTURAL;
        }
        if (c3_replay_seen(
                lc->rx_highest,
                lc->rx_window_base,
                lc->rx_bitmap,
                counter)
            != 0) {
            return NINLIL_C3_LAB_REPLAY;
        }
        return NINLIL_C3_LAB_OK;
    }
}

ninlil_c3_lab_status_t ninlil_c3_lab_rx_admit(
    ninlil_c3_lab_context_store_t *store,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t counter)
{
    ninlil_c3_lab_status_t st;

    st = ninlil_c3_lab_rx_precheck(store, lane, layer_e2e, counter);
    if (st != NINLIL_C3_LAB_OK) {
        return st;
    }

    if (layer_e2e != 0u) {
        c3_replay_record(
            &store->e2e_rx.rx_highest,
            &store->e2e_rx.rx_window_base,
            &store->e2e_rx.rx_bitmap,
            counter);
        return NINLIL_C3_LAB_OK;
    }

    {
        ninlil_c3_lab_lane_context_t *lc = c3_lane_ptr(store, lane, 0u, 0);
        if (lc == NULL) {
            return NINLIL_C3_LAB_STRUCTURAL;
        }
        c3_replay_record(
            &lc->rx_highest,
            &lc->rx_window_base,
            &lc->rx_bitmap,
            counter);
        return NINLIL_C3_LAB_OK;
    }
}

ninlil_c3_lab_status_t ninlil_c3_lab_encode_durable_admission(
    const ninlil_c3_lab_context_store_t *store,
    uint32_t hop_context_id,
    uint8_t lane,
    uint8_t layer_e2e,
    uint64_t counter,
    uint8_t out_key[NINLIL_C3_LAB_DURABLE_KEY_BYTES],
    uint8_t out_value[NINLIL_C3_LAB_DURABLE_RECORD_BYTES])
{
    uint32_t crc;

    if (store == NULL || out_key == NULL || out_value == NULL) {
        return NINLIL_C3_LAB_INVALID_ARGUMENT;
    }
    if (hop_context_id == 0u || counter == 0u) {
        return NINLIL_C3_LAB_STRUCTURAL;
    }

    (void)memset(out_key, 0, NINLIL_C3_LAB_DURABLE_KEY_BYTES);
    out_key[0] = C3_KEY_MAGIC_0;
    out_key[1] = C3_KEY_MAGIC_1;
    out_key[2] = C3_KEY_MAGIC_2;
    c3_store_u32_be(out_key + 3, hop_context_id);
    out_key[7] = lane;
    out_key[8] = layer_e2e;
    c3_store_u32_be(out_key + 9, (uint32_t)(counter & 0xffffffffu));

    (void)memset(out_value, 0, NINLIL_C3_LAB_DURABLE_RECORD_BYTES);
    out_value[0] = 1u;
    out_value[1] = 1u;
    c3_store_u32_be(out_value + 4, hop_context_id);
    c3_store_u64_be(out_value + 8, store->freshness_epoch);
    out_value[16] = lane;
    out_value[17] = layer_e2e;
    c3_store_u64_be(out_value + 20, counter);
    crc = ninlil_m4_lab_crc32c(out_value, 44u);
    c3_store_u32_be(out_value + 44, crc);
    return NINLIL_C3_LAB_OK;
}
