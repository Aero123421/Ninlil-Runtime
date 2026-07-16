#include "loopback_tx_permit_logic.h"

#include "abi_header_stage_logic.h"
#include "pointer_range_logic.h"

#include <string.h>

static void sat_inc(uint32_t *counter)
{
    if (counter != NULL && *counter < UINT32_MAX) {
        *counter += 1u;
    }
}

static int id128_nonzero(const ninlil_id128_t *id)
{
    uint32_t i;

    if (id == NULL) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        if (id->bytes[i] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int message_kind_known(ninlil_bearer_message_kind_t kind)
{
    return kind == NINLIL_BEARER_MESSAGE_APPLICATION
        || kind == NINLIL_BEARER_MESSAGE_RECEIPT
        || kind == NINLIL_BEARER_MESSAGE_DISPOSITION
        || kind == NINLIL_BEARER_MESSAGE_CANCEL_REQUEST
        || kind == NINLIL_BEARER_MESSAGE_CUSTODY_ACCEPTED
        || kind == NINLIL_BEARER_MESSAGE_CANCEL_RESULT;
}

int ninlil_esp_idf_loopback_tx_permit_policy_allows(
    ninlil_environment_t environment,
    uint32_t loopback_enabled)
{
    return environment == NINLIL_ENV_TEST && loopback_enabled != 0u;
}

static int request_ok(const ninlil_tx_request_t *request)
{
    if (request == NULL) {
        return 0;
    }
    if (request->abi_version != NINLIL_ABI_VERSION) {
        return 0;
    }
    if (request->struct_size < (uint16_t)sizeof(*request)) {
        return 0;
    }
    if (!id128_nonzero(&request->transaction_id)
        || !id128_nonzero(&request->attempt_id)) {
        return 0;
    }
    if (!message_kind_known(request->message_kind)) {
        return 0;
    }
    if (request->logical_bytes == 0u) {
        return 0;
    }
    if (request->content_digest.algorithm != NINLIL_DIGEST_SHA256) {
        return 0;
    }
    if (request->content_digest.reserved_zero != 0u) {
        return 0;
    }
    return 1;
}

static int now_ok(const ninlil_time_sample_t *now)
{
    if (now == NULL) {
        return 0;
    }
    if (now->abi_version != NINLIL_ABI_VERSION) {
        return 0;
    }
    if (now->struct_size < (uint16_t)sizeof(*now)) {
        return 0;
    }
    if (!id128_nonzero(&now->clock_epoch_id)) {
        return 0;
    }
    if (now->trust != NINLIL_CLOCK_TRUSTED
        && now->trust != NINLIL_CLOCK_UNCERTAIN) {
        return 0;
    }
    if (now->reserved_zero != 0u) {
        return 0;
    }
    return 1;
}

/*
 * Release identity: known semantic fields only. struct_size excluded so
 * forward-extended permits match; extension tail is never read for identity.
 */
static int permit_public_equal(
    const ninlil_tx_permit_t *a,
    const ninlil_tx_permit_t *b)
{
    return a->abi_version == b->abi_version
        && memcmp(&a->permit_id, &b->permit_id, sizeof(a->permit_id)) == 0
        && memcmp(&a->attempt_id, &b->attempt_id, sizeof(a->attempt_id)) == 0
        && memcmp(
               &a->clock_epoch_id, &b->clock_epoch_id, sizeof(a->clock_epoch_id))
            == 0
        && a->expires_at_ms == b->expires_at_ms;
}

static int permit_header_ok(const ninlil_tx_permit_t *permit)
{
    if (permit == NULL) {
        return 0;
    }
    if (permit->abi_version != NINLIL_ABI_VERSION) {
        return 0;
    }
    if (permit->struct_size < (uint16_t)sizeof(*permit)) {
        return 0;
    }
    return 1;
}

int ninlil_esp_idf_loopback_tx_permit_init_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_esp_idf_loopback_tx_permit_config_t *config,
    ninlil_tx_gate_status_t (*acquire)(
        void *user,
        const ninlil_tx_request_t *request,
        const ninlil_time_sample_t *now,
        ninlil_tx_permit_t *out_permit),
    void (*release_unused)(void *user, const ninlil_tx_permit_t *permit))
{
    ninlil_esp_idf_loopback_tx_permit_config_t local_cfg;
    ninlil_esp_idf_abi_header_t hdr;

    if (gate == NULL || config == NULL || acquire == NULL
        || release_unused == NULL) {
        return 1;
    }
    if (gate->lifecycle != 0u) {
        return 1;
    }
    /*
     * Stage config completely before any gate write. Declared full range
     * nonoverlap with gate storage. After this, never re-read caller config.
     */
    if (ninlil_esp_idf_abi_stage_known_prefix(
            config,
            sizeof(local_cfg),
            gate,
            sizeof(*gate),
            &local_cfg,
            &hdr)
        != 0) {
        return 1;
    }
    (void)hdr;

    gate->ops.abi_version = NINLIL_ABI_VERSION;
    gate->ops.struct_size = (uint16_t)sizeof(gate->ops);
    gate->ops.user = gate;
    gate->ops.acquire = acquire;
    gate->ops.release_unused = release_unused;
    gate->environment = local_cfg.environment;
    gate->loopback_enabled = local_cfg.loopback_enabled;
    gate->live_count = 0u;
    gate->next_permit_seq = 1u;
    gate->seq_exhausted = 0u;
    (void)memset(gate->slots, 0, sizeof(gate->slots));
    (void)memset(&gate->stats, 0, sizeof(gate->stats));
    gate->lifecycle = 1u;
    return 0;
}

void ninlil_esp_idf_loopback_tx_permit_shutdown_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate)
{
    if (gate != NULL && gate->lifecycle == 1u) {
        gate->lifecycle = 2u;
        gate->live_count = 0u;
        (void)memset(gate->slots, 0, sizeof(gate->slots));
    }
}

int ninlil_esp_idf_loopback_tx_permit_shutdown_blocked_by_live(
    const ninlil_esp_idf_loopback_tx_permit_t *gate)
{
    return gate == NULL || gate->lifecycle != 1u || gate->live_count > 0u;
}

ninlil_tx_gate_status_t ninlil_esp_idf_loopback_tx_permit_acquire_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    ninlil_tx_request_t local_req;
    ninlil_time_sample_t local_now;
    ninlil_esp_idf_abi_header_t hdr;
    uint32_t i;
    ninlil_esp_idf_loopback_tx_permit_slot_t *slot;
    uint64_t expires;

    if (gate == NULL) {
        return NINLIL_TX_GATE_DENIED;
    }
    if (out_permit == NULL) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    if (gate->lifecycle != 1u) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    /* Output must not alias gate storage (would poison permit write). */
    if (ninlil_esp_idf_fixed_arg_rejects(
            out_permit, sizeof(*out_permit), gate, sizeof(*gate))) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    /* Stage request/now: header + declared full range vs gate + known prefix. */
    if (ninlil_esp_idf_abi_stage_known_prefix(
            request,
            sizeof(local_req),
            gate,
            sizeof(*gate),
            &local_req,
            &hdr)
        != 0) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    (void)hdr;
    if (ninlil_esp_idf_abi_stage_known_prefix(
            now,
            sizeof(local_now),
            gate,
            sizeof(*gate),
            &local_now,
            &hdr)
        != 0) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    (void)hdr;

    if (!request_ok(&local_req) || !now_ok(&local_now)) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    if (!ninlil_esp_idf_loopback_tx_permit_policy_allows(
            gate->environment, gate->loopback_enabled)) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    if (gate->seq_exhausted != 0u || gate->next_permit_seq == UINT32_MAX) {
        gate->seq_exhausted = 1u;
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    if (local_now.now_ms > UINT64_MAX - 1000u) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    expires = local_now.now_ms + 1000u;
    if (expires <= local_now.now_ms) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }
    if (gate->live_count >= NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_MAX_LIVE) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }

    slot = NULL;
    for (i = 0u; i < NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_MAX_LIVE; ++i) {
        if (gate->slots[i].state == NINLIL_ESP_IDF_LOOPBACK_SLOT_FREE) {
            slot = &gate->slots[i];
            break;
        }
    }
    if (slot == NULL) {
        for (i = 0u; i < NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_MAX_LIVE; ++i) {
            if (gate->slots[i].state
                == NINLIL_ESP_IDF_LOOPBACK_SLOT_RELEASED) {
                slot = &gate->slots[i];
                break;
            }
        }
    }
    if (slot == NULL) {
        sat_inc(&gate->stats.acquire_denied);
        return NINLIL_TX_GATE_DENIED;
    }

    (void)memset(slot, 0, sizeof(*slot));
    slot->state = NINLIL_ESP_IDF_LOOPBACK_SLOT_LIVE;
    slot->permit.abi_version = NINLIL_ABI_VERSION;
    slot->permit.struct_size = (uint16_t)sizeof(slot->permit);
    slot->permit.permit_id.bytes[0] = 0x4cu;
    slot->permit.permit_id.bytes[1] = 0x42u;
    slot->permit.permit_id.bytes[12] =
        (uint8_t)((gate->next_permit_seq >> 24) & 0xffu);
    slot->permit.permit_id.bytes[13] =
        (uint8_t)((gate->next_permit_seq >> 16) & 0xffu);
    slot->permit.permit_id.bytes[14] =
        (uint8_t)((gate->next_permit_seq >> 8) & 0xffu);
    slot->permit.permit_id.bytes[15] =
        (uint8_t)(gate->next_permit_seq & 0xffu);
    if (gate->next_permit_seq == UINT32_MAX - 1u) {
        gate->next_permit_seq = UINT32_MAX;
        gate->seq_exhausted = 1u;
    } else {
        gate->next_permit_seq += 1u;
    }
    slot->permit.attempt_id = local_req.attempt_id;
    slot->permit.clock_epoch_id = local_now.clock_epoch_id;
    slot->permit.expires_at_ms = expires;
    slot->transaction_id = local_req.transaction_id;
    slot->message_kind = local_req.message_kind;
    slot->logical_bytes = local_req.logical_bytes;
    slot->content_digest = local_req.content_digest;
    gate->live_count += 1u;
    *out_permit = slot->permit;
    sat_inc(&gate->stats.acquire_ok);
    return NINLIL_TX_GATE_OK;
}

void ninlil_esp_idf_loopback_tx_permit_release_unused_pure(
    ninlil_esp_idf_loopback_tx_permit_t *gate,
    const ninlil_tx_permit_t *permit)
{
    ninlil_tx_permit_t local_permit;
    ninlil_esp_idf_abi_header_t hdr;
    uint32_t i;

    if (gate == NULL || permit == NULL || gate->lifecycle != 1u) {
        return;
    }
    if (ninlil_esp_idf_abi_stage_known_prefix(
            permit,
            sizeof(local_permit),
            gate,
            sizeof(*gate),
            &local_permit,
            &hdr)
        != 0) {
        sat_inc(&gate->stats.reuse_denied);
        return;
    }
    (void)hdr;
    if (!permit_header_ok(&local_permit)) {
        sat_inc(&gate->stats.reuse_denied);
        return;
    }
    for (i = 0u; i < NINLIL_ESP_IDF_LOOPBACK_TX_PERMIT_MAX_LIVE; ++i) {
        ninlil_esp_idf_loopback_tx_permit_slot_t *slot = &gate->slots[i];
        if (slot->state == NINLIL_ESP_IDF_LOOPBACK_SLOT_FREE) {
            continue;
        }
        if (!permit_public_equal(&slot->permit, &local_permit)) {
            continue;
        }
        if (slot->state == NINLIL_ESP_IDF_LOOPBACK_SLOT_LIVE) {
            slot->state = NINLIL_ESP_IDF_LOOPBACK_SLOT_RELEASED;
            if (gate->live_count > 0u) {
                gate->live_count -= 1u;
            }
            sat_inc(&gate->stats.release_ok);
            return;
        }
        sat_inc(&gate->stats.reuse_denied);
        return;
    }
    sat_inc(&gate->stats.reuse_denied);
}
