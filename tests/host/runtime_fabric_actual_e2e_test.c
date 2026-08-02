/*
 * Actual Portable Runtime -> private Fabric -> packet-link -> peer Runtime E2E.
 *
 * This test intentionally does not call Fabric's bearer API directly and does
 * not synthesize a Receipt.  A public ninlil_submit() must reach the endpoint
 * callback through NFL1, and the callback's VERIFIED Receipt must traverse the
 * reverse Fabric path before the controller transaction can become SATISFIED.
 *
 * Private/test-only.  No installed ABI and no physical-HIL claim.
 */
#include "domain_store_codec.h"
#include "fabric_private_api.h"
#include "multi_service_node_profile.h"
#include "ninlil_posix_lab_platform.h"
#include "platform_basic_fixtures.h"

#include <ninlil/runtime.h>

#if defined(NINLIL_MFDT_V1_PRIVATE)
#include "mfdt_v1.h"
#include "mfdt_v1_bearer_worker.h"
#include "mfdt_v1_foundation_carrier.h"
#include "mfdt_v1_pipeline.h"
#include "mfdt_v1_session.h"
#endif

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                        \
                "%s:%d requirement failed: %s\n",                              \
                __FILE__,                                                      \
                __LINE__,                                                      \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define PAIR_QUEUE_CAPACITY 16u
#define PAIR_TOKEN_CAPACITY 16u
#define PAIR_PERMIT_CAPACITY 64u
#define PAIR_PACKET_MAX NINLIL_FABRIC_NFL1_STRUCTURAL_MAX

typedef struct pair_frame {
    uint32_t used;
    uint32_t loaned;
    uint32_t length;
    uint32_t generation;
    uint8_t bytes[PAIR_PACKET_MAX];
} pair_frame_t;

typedef struct pair_tx_token {
    uint32_t used;
    uint32_t terminal;
    uint32_t generation;
} pair_tx_token_t;

typedef struct pair_tx_gate {
    const ninlil_clock_ops_t *clock;
    uint64_t next_sequence;
    uint32_t acquire_calls;
    uint32_t release_calls;
    uint8_t issuer_tag;
} pair_tx_gate_t;

typedef struct pair_link_endpoint {
    struct pair_link_endpoint *peer;
    const ninlil_clock_ops_t *clock;
    uint32_t open;
    uint32_t available;
    uint64_t availability_epoch;
    uint32_t next_generation;
    uint32_t start_calls;
    uint32_t poll_calls;
    uint32_t receive_calls;
    uint32_t release_receive_calls;
    uint32_t accepted_packets;
    uint32_t drop_budget;
    uint32_t dropped_packets;
    uint32_t duplicate_budget;
    uint32_t duplicated_packets;
    uint32_t permit_count;
    uint8_t consumed_permits[PAIR_PERMIT_CAPACITY][16];
    pair_tx_token_t tokens[PAIR_TOKEN_CAPACITY];
    pair_frame_t queue[PAIR_QUEUE_CAPACITY];
    uint32_t queue_head;
    uint32_t queue_count;
} pair_link_endpoint_t;

typedef struct runtime_side {
    ninlil_posix_lab_platform_t *platform;
    ninlil_platform_ops_t platform_ops;
    ninlil_fabric_private_t *fabric;
    const ninlil_bearer_ops_t *fabric_bearer;
    ninlil_fabric_registration_private_t *registration;
    ninlil_runtime_t *runtime;
    ninlil_service_t *service;
    pair_link_endpoint_t link;
    pair_tx_gate_t tx_gate;
    ninlil_tx_gate_ops_t tx_gate_ops;
    _Alignas(16) uint8_t fabric_workspace[NINLIL_FABRIC_WORKSPACE_BYTES];
} runtime_side_t;

static uint32_t g_delivery_calls;
static const uint8_t g_verified_evidence[] = {
    0x56u, 0x45u, 0x52u, 0x49u, 0x46u, 0x49u, 0x45u, 0x44u
};

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void set_id(ninlil_id128_t *id, uint8_t seed)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        id->bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static int id_is_zero(const ninlil_id128_t *id)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int id_equal(const ninlil_id128_t *left, const ninlil_id128_t *right)
{
    return memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static void store_u64_be(uint8_t out[8], uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        out[7u - index] = (uint8_t)(value >> (index * 8u));
    }
}

static void set_digest(ninlil_digest256_t *digest, uint8_t seed)
{
    uint32_t index;
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    for (index = 0u; index < 32u; ++index) {
        digest->bytes[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static int set_payload_digest(
    ninlil_digest256_t *digest, const uint8_t *payload, uint32_t length)
{
    ninlil_model_domain_digest_t model_digest;
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    if (ninlil_model_domain_sha256(payload, length, &model_digest)
        != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(
        digest->bytes, model_digest.bytes, sizeof(digest->bytes));
    return 1;
}

static int permit_seen(
    const pair_link_endpoint_t *endpoint, const uint8_t permit_id[16])
{
    uint32_t index;
    for (index = 0u; index < endpoint->permit_count; ++index) {
        if (memcmp(endpoint->consumed_permits[index], permit_id, 16u) == 0) {
            return 1;
        }
    }
    return 0;
}

static ninlil_tx_gate_status_t pair_tx_gate_acquire(
    void *user,
    const ninlil_tx_request_t *request,
    const ninlil_time_sample_t *now,
    ninlil_tx_permit_t *out_permit)
{
    pair_tx_gate_t *gate = (pair_tx_gate_t *)user;
    uint32_t index;

    if (out_permit != NULL) {
        (void)memset(out_permit, 0, sizeof(*out_permit));
    }
    if (gate == NULL || request == NULL || now == NULL || out_permit == NULL
        || request->abi_version != NINLIL_ABI_VERSION
        || request->struct_size != (uint16_t)sizeof(*request)
        || request->message_kind < NINLIL_BEARER_MESSAGE_APPLICATION
        || request->message_kind > NINLIL_BEARER_MESSAGE_CANCEL_RESULT
        || id_is_zero(&request->transaction_id)
        || id_is_zero(&request->attempt_id)
        || now->abi_version != NINLIL_ABI_VERSION
        || now->struct_size != (uint16_t)sizeof(*now)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || id_is_zero(&now->clock_epoch_id)
        || gate->next_sequence == UINT64_MAX
        || UINT64_MAX - now->now_ms < 60000u) {
        (void)fprintf(
            stderr,
            "pair tx gate denied: gate=%d request=%d now=%d out=%d "
            "request_header=%u/%u kind=%u tx_zero=%d attempt_zero=%d "
            "now_header=%u/%u trust=%u epoch_zero=%d sequence=%llu "
            "now_ms=%llu\n",
            gate != NULL,
            request != NULL,
            now != NULL,
            out_permit != NULL,
            request == NULL ? 0u : (unsigned)request->abi_version,
            request == NULL ? 0u : (unsigned)request->struct_size,
            request == NULL ? 0u : (unsigned)request->message_kind,
            request == NULL ? 1 : id_is_zero(&request->transaction_id),
            request == NULL ? 1 : id_is_zero(&request->attempt_id),
            now == NULL ? 0u : (unsigned)now->abi_version,
            now == NULL ? 0u : (unsigned)now->struct_size,
            now == NULL ? 0u : (unsigned)now->trust,
            now == NULL ? 1 : id_is_zero(&now->clock_epoch_id),
            gate == NULL ? 0ull
                         : (unsigned long long)gate->next_sequence,
            now == NULL ? 0ull : (unsigned long long)now->now_ms);
        return NINLIL_TX_GATE_DENIED;
    }

    gate->next_sequence += 1u;
    set_header(
        &out_permit->abi_version,
        &out_permit->struct_size,
        sizeof(*out_permit));
    for (index = 0u; index < 8u; ++index) {
        out_permit->permit_id.bytes[index] =
            (uint8_t)(gate->issuer_tag + (uint8_t)index);
    }
    store_u64_be(
        &out_permit->permit_id.bytes[8], gate->next_sequence);
    out_permit->attempt_id = request->attempt_id;
    out_permit->clock_epoch_id = now->clock_epoch_id;
    out_permit->expires_at_ms = now->now_ms + 60000u;
    gate->acquire_calls += 1u;
    return NINLIL_TX_GATE_OK;
}

static void pair_tx_gate_release_unused(
    void *user, const ninlil_tx_permit_t *permit)
{
    pair_tx_gate_t *gate = (pair_tx_gate_t *)user;
    if (gate != NULL && permit != NULL) {
        gate->release_calls += 1u;
    }
}

static void pair_tx_gate_init(
    pair_tx_gate_t *gate,
    ninlil_tx_gate_ops_t *ops,
    const ninlil_clock_ops_t *clock,
    uint8_t issuer_tag)
{
    (void)memset(gate, 0, sizeof(*gate));
    gate->clock = clock;
    gate->issuer_tag = issuer_tag;
    (void)memset(ops, 0, sizeof(*ops));
    set_header(&ops->abi_version, &ops->struct_size, sizeof(*ops));
    ops->user = gate;
    ops->acquire = pair_tx_gate_acquire;
    ops->release_unused = pair_tx_gate_release_unused;
}

static int permit_valid(
    const pair_link_endpoint_t *endpoint,
    const ninlil_fabric_packet_view_v1_t *packet)
{
    const ninlil_tx_permit_t *permit;
    ninlil_time_sample_t now;

    if (endpoint == NULL || packet == NULL || endpoint->clock == NULL
        || endpoint->clock->now == NULL) {
        (void)fprintf(stderr, "pair permit: missing endpoint/packet/clock\n");
        return 0;
    }
    permit = packet->permit;
    if (permit == NULL || permit->abi_version != NINLIL_ABI_VERSION
        || permit->struct_size != (uint16_t)sizeof(*permit)
        || id_is_zero(&permit->permit_id)
        || !id_equal(&permit->attempt_id, &packet->attempt_id)
        || permit_seen(endpoint, permit->permit_id.bytes) != 0) {
        (void)fprintf(
            stderr,
            "pair permit: shape=%u/%u zero=%d attempt_equal=%d seen=%d\n",
            permit == NULL ? 0u : (unsigned)permit->abi_version,
            permit == NULL ? 0u : (unsigned)permit->struct_size,
            permit == NULL ? 1 : id_is_zero(&permit->permit_id),
            permit == NULL
                ? 0
                : id_equal(&permit->attempt_id, &packet->attempt_id),
            permit == NULL
                ? 0
                : permit_seen(endpoint, permit->permit_id.bytes));
        return 0;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (endpoint->clock->now(endpoint->clock->user, &now) != NINLIL_PORT_OK
        || now.trust != NINLIL_CLOCK_TRUSTED
        || !id_equal(&permit->clock_epoch_id, &now.clock_epoch_id)
        || permit->expires_at_ms == 0u || now.now_ms >= permit->expires_at_ms) {
        (void)fprintf(
            stderr,
            "pair permit: time status/trust=%u epoch_equal=%d now=%llu "
            "expires=%llu\n",
            (unsigned)now.trust,
            id_equal(&permit->clock_epoch_id, &now.clock_epoch_id),
            (unsigned long long)now.now_ms,
            (unsigned long long)permit->expires_at_ms);
        return 0;
    }
    return 1;
}

static ninlil_fabric_link_status_t pair_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    if (endpoint == NULL || out_handle == NULL || endpoint->open != 0u) {
        if (out_handle != NULL) {
            *out_handle = NULL;
        }
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    endpoint->open = 1u;
    *out_handle = endpoint;
    return NINLIL_FABRIC_LINK_OK;
}

static void pair_close(
    void *user, ninlil_fabric_packet_link_handle_t handle)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    if (endpoint != NULL && handle == endpoint) {
        endpoint->open = 0u;
    }
}

static pair_tx_token_t *pair_find_token(
    pair_link_endpoint_t *endpoint, ninlil_fabric_packet_token_t token)
{
    uint32_t generation = (uint32_t)(uintptr_t)token;
    uint32_t index;
    for (index = 0u; index < PAIR_TOKEN_CAPACITY; ++index) {
        if (endpoint->tokens[index].used != 0u
            && endpoint->tokens[index].generation == generation) {
            return &endpoint->tokens[index];
        }
    }
    return NULL;
}

static ninlil_fabric_link_status_t pair_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    pair_link_endpoint_t *peer;
    pair_tx_token_t *token_slot = NULL;
    pair_frame_t *frame;
    uint32_t enqueue_count = 1u;
    uint32_t token_index;
    uint32_t queue_index;

    if (out_token != NULL) {
        *out_token = NULL;
    }
    if (endpoint == NULL || handle != endpoint || out_token == NULL
        || packet == NULL || endpoint->open == 0u
        || endpoint->peer == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    peer = endpoint->peer;
    if (endpoint->available == 0u || peer->available == 0u
        || peer->open == 0u) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (packet->bytes == NULL || packet->length == 0u
        || packet->length > PAIR_PACKET_MAX
        || permit_valid(endpoint, packet) == 0) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (endpoint->drop_budget != 0u) {
        enqueue_count = 0u;
    } else if (endpoint->duplicate_budget != 0u) {
        enqueue_count = 2u;
    }
    if (peer->queue_count + enqueue_count > PAIR_QUEUE_CAPACITY
        || endpoint->permit_count >= PAIR_PERMIT_CAPACITY) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    for (token_index = 0u; token_index < PAIR_TOKEN_CAPACITY; ++token_index) {
        if (endpoint->tokens[token_index].used == 0u) {
            token_slot = &endpoint->tokens[token_index];
            break;
        }
    }
    if (token_slot == NULL || endpoint->next_generation == UINT32_MAX) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }

    endpoint->next_generation += 1u;
    if (endpoint->drop_budget != 0u) {
        endpoint->drop_budget -= 1u;
        endpoint->dropped_packets += 1u;
    } else {
        queue_index =
            (peer->queue_head + peer->queue_count) % PAIR_QUEUE_CAPACITY;
        frame = &peer->queue[queue_index];
        (void)memset(frame, 0, sizeof(*frame));
        frame->used = 1u;
        frame->length = packet->length;
        frame->generation = endpoint->next_generation;
        (void)memcpy(frame->bytes, packet->bytes, packet->length);
        peer->queue_count += 1u;

        if (endpoint->duplicate_budget != 0u) {
            endpoint->duplicate_budget -= 1u;
            queue_index =
                (peer->queue_head + peer->queue_count) % PAIR_QUEUE_CAPACITY;
            frame = &peer->queue[queue_index];
            (void)memset(frame, 0, sizeof(*frame));
            frame->used = 1u;
            frame->length = packet->length;
            frame->generation = endpoint->next_generation;
            (void)memcpy(frame->bytes, packet->bytes, packet->length);
            peer->queue_count += 1u;
            endpoint->duplicated_packets += 1u;
        }
    }

    (void)memset(token_slot, 0, sizeof(*token_slot));
    token_slot->used = 1u;
    token_slot->generation = endpoint->next_generation;
    (void)memcpy(
        endpoint->consumed_permits[endpoint->permit_count],
        packet->permit->permit_id.bytes,
        16u);
    endpoint->permit_count += 1u;
    endpoint->start_calls += 1u;
    endpoint->accepted_packets += 1u;
    *out_token = (void *)(uintptr_t)token_slot->generation;
    return NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_link_status_t pair_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    pair_tx_token_t *slot;
    if (endpoint == NULL || handle != endpoint || out_completion == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot = pair_find_token(endpoint, token);
    if (slot == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(out_completion, 0, sizeof(*out_completion));
    out_completion->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    slot->terminal = 1u;
    endpoint->poll_calls += 1u;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t pair_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    pair_tx_token_t *slot;
    if (endpoint == NULL || handle != endpoint) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot = pair_find_token(endpoint, token);
    if (slot == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot->terminal = 1u;
    return NINLIL_FABRIC_LINK_OK;
}

static void pair_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    pair_tx_token_t *slot;
    if (endpoint == NULL || handle != endpoint) {
        return;
    }
    slot = pair_find_token(endpoint, token);
    if (slot != NULL && slot->terminal != 0u) {
        (void)memset(slot, 0, sizeof(*slot));
    }
}

static ninlil_fabric_link_status_t pair_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    pair_frame_t *frame;
    if (out_bytes != NULL) {
        *out_bytes = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    if (endpoint == NULL || handle != endpoint || out_bytes == NULL
        || out_length == NULL || out_receive_token == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    endpoint->receive_calls += 1u;
    if (endpoint->queue_count == 0u) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    frame = &endpoint->queue[endpoint->queue_head];
    if (frame->used == 0u || frame->loaned != 0u || frame->length == 0u) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    frame->loaned = 1u;
    *out_bytes = frame->bytes;
    *out_length = frame->length;
    *out_receive_token = frame;
    return NINLIL_FABRIC_LINK_OK;
}

static void pair_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    pair_frame_t *frame = (pair_frame_t *)receive_token;
    if (endpoint == NULL || handle != endpoint || frame == NULL
        || endpoint->queue_count == 0u
        || frame != &endpoint->queue[endpoint->queue_head]
        || frame->loaned == 0u) {
        return;
    }
    (void)memset(frame, 0, sizeof(*frame));
    endpoint->queue_head =
        (endpoint->queue_head + 1u) % PAIR_QUEUE_CAPACITY;
    endpoint->queue_count -= 1u;
    endpoint->release_receive_calls += 1u;
}

static ninlil_fabric_link_status_t pair_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    pair_link_endpoint_t *endpoint = (pair_link_endpoint_t *)user;
    ninlil_time_sample_t now;
    if (endpoint == NULL || handle != endpoint || out_state == NULL
        || endpoint->clock == NULL || endpoint->clock->now == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (endpoint->clock->now(endpoint->clock->user, &now) != NINLIL_PORT_OK
        || now.trust != NINLIL_CLOCK_TRUSTED
        || UINT64_MAX - now.now_ms < 600000u) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    out_state->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->availability_epoch = endpoint->availability_epoch;
    out_state->availability_clock_epoch_id = now.clock_epoch_id;
    out_state->available_until_ms = now.now_ms + 600000u;
    out_state->available = endpoint->available;
    return NINLIL_FABRIC_LINK_OK;
}

static void pair_ops_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    pair_link_endpoint_t *endpoint)
{
    (void)memset(ops, 0, sizeof(*ops));
    ops->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = endpoint;
    ops->open = pair_open;
    ops->close = pair_close;
    ops->start_send = pair_start_send;
    ops->poll_send = pair_poll_send;
    ops->cancel_send = pair_cancel_send;
    ops->release_send = pair_release_send;
    ops->receive_next = pair_receive_next;
    ops->release_received = pair_release_received;
    ops->state = pair_state;
}

static ninlil_runtime_config_t runtime_config(
    ninlil_role_t role,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    uint8_t runtime_seed)
{
    ninlil_runtime_config_t config;
    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = role;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, runtime_seed);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, (uint8_t)(runtime_seed + 0x10u));
    set_id(
        &config.local_identity.installation_id,
        (uint8_t)(runtime_seed + 0x20u));
    set_id(
        &config.local_identity.site_domain_id,
        (uint8_t)(runtime_seed + 0x30u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = storage_namespace;
    config.storage_namespace.length = storage_namespace_length;
    set_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions =
        role == NINLIL_ROLE_ENDPOINT ? 32u : 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes =
        role == NINLIL_ROLE_CONTROLLER ? 32768u : 0u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 4u;
    config.limits.max_retained_terminal_transactions = 32u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_event_spool_count =
        role == NINLIL_ROLE_ENDPOINT ? 32u : 0u;
    config.limits.max_event_spool_bytes =
        role == NINLIL_ROLE_ENDPOINT ? 32768u : 0u;
    config.limits.max_result_cache_entries = 32u;
    config.limits.max_retained_dispositions = 32u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 60000u;
    config.result_cache_retention_ms = 60000u;
    config.observation_retention_ms = 60000u;
    return config;
}

static ninlil_service_descriptor_t service_descriptor(uint8_t app_seed)
{
    static const uint8_t namespace_id[] = "org.ninlil.fabric.actual";
    static const uint8_t service_id[] = "verified-state";
    static const uint8_t schema_id[] = "verified-state-v1";
    ninlil_service_descriptor_t descriptor;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version,
        &descriptor.struct_size,
        sizeof(descriptor));
    descriptor.namespace_id.data = namespace_id;
    descriptor.namespace_id.length = sizeof(namespace_id) - 1u;
    descriptor.service_id.data = service_id;
    descriptor.service_id.length = sizeof(service_id) - 1u;
    descriptor.schema_id.data = schema_id;
    descriptor.schema_id.length = sizeof(schema_id) - 1u;
    descriptor.descriptor_revision = 1u;
    set_digest(&descriptor.descriptor_digest, 0x41u);
    set_id(&descriptor.local_application_instance_id, app_seed);
    descriptor.schema_major = 1u;
    descriptor.family = NINLIL_FAMILY_DESIRED_STATE;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_APPLICATION_DEDUP;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);
    descriptor.logical_payload_limit = 1024u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 8u;
    descriptor.max_attempts_per_target_per_cycle = 8u;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 20u;
    descriptor.max_payload_bytes_per_window = 20480u;
    descriptor.minimum_deadline_ms = 60000u;
    descriptor.maximum_deadline_ms = 60000u;
    descriptor.maximum_evidence_grace_ms = 5000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 100u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 60000u;
    return descriptor;
}

static ninlil_callback_action_t endpoint_delivery(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    (void)user;
    (void)token;
    if (delivery == NULL || out_result == NULL
        || delivery->payload.length != 16u
        || delivery->payload.data == NULL) {
        return NINLIL_CALLBACK_DEFER;
    }
    g_delivery_calls += 1u;
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage = NINLIL_EVIDENCE_VERIFIED;
    out_result->evidence.data = g_verified_evidence;
    out_result->evidence.length = sizeof(g_verified_evidence);
    return NINLIL_CALLBACK_COMPLETE;
}

static ninlil_reconcile_action_t endpoint_reconcile(
    void *user,
    const ninlil_reconcile_view_t *delivery,
    ninlil_application_result_t *out_known_result)
{
    (void)user;
    (void)delivery;
    (void)out_known_result;
    return NINLIL_RECONCILE_REDELIVER;
}

#define MULTI_CALLBACK_PAYLOADS_MAX 2u

static int service_identity_matches_descriptor(
    const ninlil_service_identity_t *identity,
    const ninlil_service_descriptor_t *descriptor,
    uint16_t expected_schema_minor)
{
    if (identity == NULL || descriptor == NULL
        || identity->abi_version != NINLIL_ABI_VERSION
        || identity->struct_size != (uint16_t)sizeof(*identity)
        || descriptor->namespace_id.data == NULL
        || descriptor->service_id.data == NULL
        || descriptor->schema_id.data == NULL
        || identity->namespace_id.length != descriptor->namespace_id.length
        || identity->service_id.length != descriptor->service_id.length
        || identity->schema_id.length != descriptor->schema_id.length
        || memcmp(
               identity->namespace_id.bytes,
               descriptor->namespace_id.data,
               descriptor->namespace_id.length)
            != 0
        || memcmp(
               identity->service_id.bytes,
               descriptor->service_id.data,
               descriptor->service_id.length)
            != 0
        || memcmp(
               identity->schema_id.bytes,
               descriptor->schema_id.data,
               descriptor->schema_id.length)
            != 0
        || identity->descriptor_revision != descriptor->descriptor_revision
        || identity->descriptor_digest.algorithm
            != descriptor->descriptor_digest.algorithm
        || identity->descriptor_digest.reserved_zero
            != descriptor->descriptor_digest.reserved_zero
        || memcmp(
               identity->descriptor_digest.bytes,
               descriptor->descriptor_digest.bytes,
               sizeof(identity->descriptor_digest.bytes))
            != 0
        || identity->schema_major != descriptor->schema_major
        || identity->schema_minor != expected_schema_minor
        || identity->family != descriptor->family) {
        return 0;
    }
    return 1;
}

typedef struct multi_callback_state {
    const ninlil_service_descriptor_t *expected_service;
    uint16_t expected_schema_minor;
    ninlil_multi_service_node_state_t *node_state;
    uint32_t node_service_index;
    uint64_t node_query_correlation;
    const uint8_t *expected_payloads[MULTI_CALLBACK_PAYLOADS_MAX];
    uint32_t expected_lengths[MULTI_CALLBACK_PAYLOADS_MAX];
    uint32_t expected_count;
    uint32_t seen_mask;
    uint32_t calls;
    uint32_t route_mismatches;
    uint32_t payload_mismatches;
    uint32_t state_mismatches;
} multi_callback_state_t;

static ninlil_callback_action_t multi_service_delivery(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_result)
{
    static const uint8_t evidence[] = "multi-service-applied";
    multi_callback_state_t *state = (multi_callback_state_t *)user;
    uint32_t index;
    int matched = 0;

    (void)token;
    if (state == NULL || delivery == NULL || out_result == NULL) {
        return NINLIL_CALLBACK_DEFER;
    }
    state->calls += 1u;
    if (!service_identity_matches_descriptor(
            &delivery->service,
            state->expected_service,
            state->expected_schema_minor)) {
        state->route_mismatches += 1u;
        return NINLIL_CALLBACK_DEFER;
    }
    for (index = 0u; index < state->expected_count; ++index) {
        if (delivery->payload.length == state->expected_lengths[index]
            && delivery->payload.data != NULL
            && memcmp(
                   delivery->payload.data,
                   state->expected_payloads[index],
                   state->expected_lengths[index])
                == 0) {
            state->seen_mask |= (uint32_t)1u << index;
            matched = 1;
            break;
        }
    }
    if (matched == 0) {
        state->payload_mismatches += 1u;
        return NINLIL_CALLBACK_DEFER;
    }
    if (state->node_state != NULL
        && ninlil_multi_service_node_note_delivery(
               state->node_state,
               state->node_service_index,
               state->node_query_correlation)
            != NINLIL_OK) {
        state->state_mismatches += 1u;
        return NINLIL_CALLBACK_DEFER;
    }
    out_result->kind = NINLIL_APP_RESULT_POSITIVE_EVIDENCE;
    out_result->evidence_stage =
        delivery->service.family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_EVIDENCE_APPLIED
        : NINLIL_EVIDENCE_VERIFIED;
    out_result->evidence.data = evidence;
    out_result->evidence.length = sizeof(evidence) - 1u;
    return NINLIL_CALLBACK_COMPLETE;
}

/*
 * A service_id alone is not a routing identity.  Keep service_id identical
 * while namespace, schema, and descriptor digest collide.  A service-id-only
 * callback mutation would accept the payload and return COMPLETE.
 */
static int multi_service_identity_collision_fixture(
    const ninlil_service_descriptor_t *expected,
    const uint8_t *payload,
    uint32_t payload_length)
{
    multi_callback_state_t state;
    ninlil_delivery_view_t delivery;
    ninlil_application_result_t result;
    ninlil_callback_action_t action;

    if (expected == NULL || payload == NULL
        || expected->namespace_id.length == 0u
        || expected->namespace_id.length > NINLIL_MAX_TEXT_ID_BYTES
        || expected->service_id.length == 0u
        || expected->service_id.length > NINLIL_MAX_TEXT_ID_BYTES
        || expected->schema_id.length == 0u
        || expected->schema_id.length > NINLIL_MAX_TEXT_ID_BYTES) {
        return 0;
    }
    (void)memset(&state, 0, sizeof(state));
    state.expected_service = expected;
    state.expected_schema_minor = expected->schema_minor_min;
    state.expected_payloads[0] = payload;
    state.expected_lengths[0] = payload_length;
    state.expected_count = 1u;

    (void)memset(&delivery, 0, sizeof(delivery));
    set_header(
        &delivery.abi_version, &delivery.struct_size, sizeof(delivery));
    set_header(
        &delivery.service.abi_version,
        &delivery.service.struct_size,
        sizeof(delivery.service));
    delivery.service.namespace_id.length =
        (uint8_t)expected->namespace_id.length;
    (void)memcpy(
        delivery.service.namespace_id.bytes,
        expected->namespace_id.data,
        expected->namespace_id.length);
    delivery.service.namespace_id.bytes[0] ^= 0x20u;
    delivery.service.service_id.length = (uint8_t)expected->service_id.length;
    (void)memcpy(
        delivery.service.service_id.bytes,
        expected->service_id.data,
        expected->service_id.length);
    delivery.service.schema_id.length = (uint8_t)expected->schema_id.length;
    (void)memcpy(
        delivery.service.schema_id.bytes,
        expected->schema_id.data,
        expected->schema_id.length);
    delivery.service.schema_id.bytes[0] ^= 0x20u;
    delivery.service.descriptor_revision = expected->descriptor_revision;
    delivery.service.descriptor_digest = expected->descriptor_digest;
    delivery.service.descriptor_digest.bytes[0] ^= 0x80u;
    delivery.service.schema_major = expected->schema_major;
    delivery.service.schema_minor = expected->schema_minor_min;
    delivery.service.family = expected->family;
    delivery.payload.data = payload;
    delivery.payload.length = payload_length;

    (void)memset(&result, 0, sizeof(result));
    set_header(&result.abi_version, &result.struct_size, sizeof(result));
    action = multi_service_delivery(NULL, NULL, &delivery, &result);
    if (action != NINLIL_CALLBACK_DEFER || state.calls != 0u) {
        /*
         * NULL user proves the public callback still rejects invalid
         * invocation; now execute the collision against the real state.
         */
        return 0;
    }
    action = multi_service_delivery(&state, NULL, &delivery, &result);
    return action == NINLIL_CALLBACK_DEFER && state.calls == 1u
        && state.route_mismatches == 1u && state.payload_mismatches == 0u
        && state.seen_mask == 0u;
}

static ninlil_origin_auth_status_t multi_service_origin_allow(
    void *user,
    const ninlil_origin_authorization_request_t *request,
    ninlil_origin_authorization_decision_t *out_decision)
{
    (void)user;
    if (request == NULL || out_decision == NULL
        || request->service.family != NINLIL_FAMILY_EVENT_FACT
        || request->payload_length == 0u
        || request->payload_length > 1024u
        || request->now.trust != NINLIL_CLOCK_TRUSTED
        || request->now.now_ms > UINT64_MAX - 600000u) {
        return NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE;
    }
    (void)memset(out_decision, 0, sizeof(*out_decision));
    set_header(
        &out_decision->abi_version,
        &out_decision->struct_size,
        sizeof(*out_decision));
    out_decision->allowed = 1u;
    out_decision->reason = NINLIL_REASON_NONE;
    out_decision->retry_guidance = NINLIL_RETRY_NEVER;
    set_id(&out_decision->provider_id, 0xD1u);
    out_decision->provider_revision = 1u;
    set_digest(&out_decision->decision_digest, 0xE1u);
    set_id(&out_decision->grant_id, 0xF1u);
    out_decision->grant_revision = 1u;
    out_decision->clock_epoch_id = request->now.clock_epoch_id;
    out_decision->evaluated_at_ms = request->now.now_ms;
    out_decision->valid_from_ms = 0u;
    out_decision->expires_at_ms = request->now.now_ms + 600000u;
    out_decision->max_payload_bytes = 1024u;
    out_decision->max_active_spool_count = 32u;
    out_decision->max_active_spool_bytes = 32768u;
    out_decision->rate_window_ms = 10000u;
    out_decision->max_admissions_per_window = 8u;
    out_decision->max_attempts_per_retry_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    return NINLIL_ORIGIN_AUTH_OK;
}

static void fill_link_descriptor(
    ninlil_fabric_link_descriptor_v1_t *descriptor,
    const ninlil_id128_t *peer_runtime_id,
    const ninlil_time_sample_t *now)
{
    (void)memset(descriptor, 0, sizeof(*descriptor));
    descriptor->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    descriptor->struct_size = (uint16_t)sizeof(*descriptor);
    set_id(&descriptor->instance_id, 0x61u);
    descriptor->link_kind = NINLIL_FABRIC_LINK_KIND_LOOPBACK;
    descriptor->direction_mask = NINLIL_FABRIC_LINK_DIRECTION_SEND
        | NINLIL_FABRIC_LINK_DIRECTION_RECEIVE;
    descriptor->capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_RESERVATION
        | NINLIL_FABRIC_CAP_CUSTODY | NINLIL_FABRIC_CAP_EVIDENCE;
    descriptor->descriptor_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"actual-e2e-descriptor",
        sizeof("actual-e2e-descriptor") - 1u,
        descriptor->descriptor_digest);
    set_id(&descriptor->security_profile_id, 0x30u);
    descriptor->security_capability_flags =
        NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"actual-e2e-security",
        sizeof("actual-e2e-security") - 1u,
        descriptor->security_binding_digest);
    descriptor->attestation_epoch = 1u;
    descriptor->attestation_clock_epoch_id = now->clock_epoch_id;
    descriptor->attestation_expires_at_ms = now->now_ms + 600000u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"actual-e2e-attestation",
        sizeof("actual-e2e-attestation") - 1u,
        descriptor->attestation_digest);
    descriptor->authenticated_peer_runtime_id = *peer_runtime_id;
    set_id(&descriptor->attachment_authority_id, 0x50u);
    ninlil_fabric_private_sha256(
        (const uint8_t *)"actual-e2e-attachment",
        sizeof("actual-e2e-attachment") - 1u,
        descriptor->attachment_binding_digest);
    descriptor->maximum_packet_bytes = PAIR_PACKET_MAX;
    descriptor->maximum_transfer_bytes = PAIR_PACKET_MAX;
    descriptor->latency_class = 1u;
    descriptor->cost_class = 1u;
    descriptor->reservation_capacity = 8u;
    descriptor->peer_nfl1_version = 1u;
    descriptor->peer_fabric_capability_flags =
        NINLIL_FABRIC_PEER_CAP_NFL1_V1;
    descriptor->configuration_revision = 1u;
    ninlil_fabric_private_sha256(
        (const uint8_t *)"actual-e2e-configuration",
        sizeof("actual-e2e-configuration") - 1u,
        descriptor->configuration_digest);
}

static void service_identity_digest(
    const ninlil_service_descriptor_t *descriptor, uint8_t out_digest[32])
{
    ninlil_fabric_private_nfl1_service_identity_digest(
        descriptor->namespace_id.data,
        (uint16_t)descriptor->namespace_id.length,
        descriptor->service_id.data,
        (uint16_t)descriptor->service_id.length,
        descriptor->schema_id.data,
        (uint16_t)descriptor->schema_id.length,
        descriptor->descriptor_revision,
        descriptor->descriptor_digest.bytes,
        descriptor->schema_major,
        descriptor->schema_minor_min,
        descriptor->family,
        out_digest);
}

/*
 * The same controller-assigned forward policy is installed on both peers.
 * Reverse Receipt must use the saved triggering FBA1/FBT1 context, not invent
 * a second route-policy identity.  This is the contract the actual E2E proves.
 */
static int install_forward_policy_seeded(
    runtime_side_t *side,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *endpoint_runtime_id,
    const ninlil_id128_t *endpoint_application_id,
    const ninlil_time_sample_t *now,
    uint8_t policy_seed,
    uint8_t binding_seed,
    uint8_t authority_seed,
    uint8_t owner_seed)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_authority_binding_v1_t binding;
    ninlil_fabric_path_policy_v1_t snapshot;
    uint8_t service_digest[32];

    service_identity_digest(descriptor, service_digest);
    (void)memset(&policy, 0, sizeof(policy));
    policy.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    policy.struct_size = (uint16_t)sizeof(policy);
    set_id(&policy.policy_id, policy_seed);
    policy.revision = 1u;
    (void)memcpy(
        policy.service_identity_digest, service_digest, sizeof(service_digest));
    policy.family = descriptor->family;
    policy.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    policy.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    policy.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    policy.required_capability_flags = NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE
        | NINLIL_FABRIC_CAP_UNICAST | NINLIL_FABRIC_CAP_CUSTODY
        | NINLIL_FABRIC_CAP_EVIDENCE;
    policy.required_security_flags = NINLIL_FABRIC_SECURITY_INTEGRITY
        | NINLIL_FABRIC_SECURITY_CONFIDENTIALITY
        | NINLIL_FABRIC_SECURITY_REPLAY_PROTECTION
        | NINLIL_FABRIC_SECURITY_SESSION_FRESHNESS;
    policy.maximum_latency_class = 10u;
    policy.maximum_cost_class = 10u;
    policy.minimum_packet_bytes = NINLIL_FABRIC_NFL1_STRUCTURAL_MIN;
    policy.authority_mode = NINLIL_FABRIC_AUTHORITY_MODE_BOUND_REQUIRED;
    policy.deadline_guard_ms = 0u;
    policy.candidate_count = 1u;
    set_id(&policy.candidates[0].instance_id, 0x61u);
    policy.candidates[0].rank = 1u;
    policy.candidates[0].reservation_units = 1u;
    if (ninlil_fabric_private_policy_put_v1(side->fabric, &policy)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    (void)memset(&snapshot, 0, sizeof(snapshot));
    if (ninlil_fabric_private_policy_snapshot_v1(
            side->fabric, &policy.policy_id, policy.revision, &snapshot)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }

    (void)memset(&binding, 0, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    set_id(&binding.binding_id, binding_seed);
    (void)memcpy(
        binding.service_identity_digest,
        service_digest,
        sizeof(service_digest));
    binding.family = descriptor->family;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    binding.endpoint_runtime_id = *endpoint_runtime_id;
    binding.target_runtime_id = *endpoint_runtime_id;
    binding.target_application_id = *endpoint_application_id;
    binding.policy_id = policy.policy_id;
    binding.policy_revision = policy.revision;
    (void)memcpy(
        binding.policy_digest,
        snapshot.canonical_digest_zero_on_input,
        sizeof(binding.policy_digest));
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    set_id(&binding.authority_id, authority_seed);
    binding.authority_term = 1u;
    binding.assignment_epoch = 1u;
    set_id(&binding.owner_scope_id, owner_seed);
    {
        uint32_t index;
        for (index = 0u; index < sizeof(binding.owner_tuple_canonical);
             ++index) {
            binding.owner_tuple_canonical[index] =
                (uint8_t)(owner_seed + 0x10u + (uint8_t)index);
        }
    }
    (void)memcpy(
        binding.owner_tuple_canonical,
        endpoint_runtime_id->bytes,
        sizeof(endpoint_runtime_id->bytes));
    (void)memcpy(
        binding.owner_tuple_canonical + sizeof(endpoint_runtime_id->bytes),
        endpoint_application_id->bytes,
        sizeof(endpoint_application_id->bytes));
    ninlil_fabric_private_owner_tuple_digest(
        binding.owner_tuple_canonical, binding.owner_tuple_digest);
    binding.authority_clock_epoch_id = now->clock_epoch_id;
    binding.lease_expires_at_ms = now->now_ms + 600000u;
    binding.assignment_revision = 1u;
    return ninlil_fabric_private_authority_put_v1(side->fabric, &binding)
        == NINLIL_FABRIC_PRIVATE_OK;
}

static int install_forward_policy(
    runtime_side_t *side,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *endpoint_runtime_id,
    const ninlil_id128_t *endpoint_application_id,
    const ninlil_time_sample_t *now)
{
    return install_forward_policy_seeded(
        side,
        descriptor,
        endpoint_runtime_id,
        endpoint_application_id,
        now,
        0x71u,
        0x81u,
        0x91u,
        0xA1u);
}

#if defined(NINLIL_MFDT_V1_PRIVATE)
/*
 * One Fabric instance is bidirectional. MFDT response frames are themselves
 * NCL1 DATA Application messages (some exceed the Foundation evidence limit),
 * so both target authorities must coexist under the same path policy.
 */
static int install_additional_forward_authority(
    runtime_side_t *side,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_id128_t *target_runtime_id,
    const ninlil_id128_t *target_application_id,
    const ninlil_time_sample_t *now,
    uint8_t binding_seed)
{
    ninlil_fabric_path_policy_v1_t policy;
    ninlil_fabric_authority_binding_v1_t binding;
    ninlil_fabric_path_policy_v1_t snapshot;
    uint8_t service_digest[32];
    uint32_t index;

    service_identity_digest(descriptor, service_digest);
    (void)memset(&policy, 0, sizeof(policy));
    set_id(&policy.policy_id, 0x71u);
    (void)memset(&snapshot, 0, sizeof(snapshot));
    if (ninlil_fabric_private_policy_snapshot_v1(
            side->fabric, &policy.policy_id, 1u, &snapshot)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }

    (void)memset(&binding, 0, sizeof(binding));
    binding.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    binding.struct_size = (uint16_t)sizeof(binding);
    set_id(&binding.binding_id, binding_seed);
    (void)memcpy(
        binding.service_identity_digest,
        service_digest,
        sizeof(service_digest));
    binding.family = descriptor->family;
    binding.direction = NINLIL_FABRIC_POLICY_DIRECTION_FORWARD;
    binding.traffic_class = NINLIL_FABRIC_TRAFFIC_APPLICATION;
    binding.scope_selector = NINLIL_FABRIC_SCOPE_TARGET_RUNTIME;
    binding.endpoint_runtime_id = *target_runtime_id;
    binding.target_runtime_id = *target_runtime_id;
    binding.target_application_id = *target_application_id;
    binding.policy_id = policy.policy_id;
    binding.policy_revision = 1u;
    (void)memcpy(
        binding.policy_digest,
        snapshot.canonical_digest_zero_on_input,
        sizeof(binding.policy_digest));
    binding.authority_state = NINLIL_FABRIC_AUTHORITY_BOUND;
    set_id(&binding.authority_id, (uint8_t)(binding_seed + 0x10u));
    binding.authority_term = 1u;
    binding.assignment_epoch = 1u;
    set_id(&binding.owner_scope_id, (uint8_t)(binding_seed + 0x20u));
    for (index = 0u; index < sizeof(binding.owner_tuple_canonical); ++index) {
        binding.owner_tuple_canonical[index] =
            (uint8_t)(binding_seed + (uint8_t)index);
    }
    (void)memcpy(
        binding.owner_tuple_canonical,
        target_runtime_id->bytes,
        sizeof(target_runtime_id->bytes));
    (void)memcpy(
        binding.owner_tuple_canonical + 16u,
        target_application_id->bytes,
        sizeof(target_application_id->bytes));
    ninlil_fabric_private_owner_tuple_digest(
        binding.owner_tuple_canonical, binding.owner_tuple_digest);
    binding.authority_clock_epoch_id = now->clock_epoch_id;
    binding.lease_expires_at_ms = now->now_ms + 600000u;
    binding.assignment_revision = 1u;
    return ninlil_fabric_private_authority_put_v1(side->fabric, &binding)
        == NINLIL_FABRIC_PRIVATE_OK;
}
#endif

static int side_init(
    runtime_side_t *side,
    ninlil_role_t role,
    const ninlil_id128_t *peer_runtime_id,
    const char *database_path)
{
    ninlil_posix_lab_platform_config_t platform_config;
    ninlil_fabric_config_v1_t fabric_config;
    ninlil_fabric_link_descriptor_v1_t link_descriptor;
    ninlil_fabric_packet_link_ops_v1_t link_ops;
    ninlil_time_sample_t now;
    const ninlil_platform_ops_t *base_ops;

    (void)memset(side, 0, sizeof(*side));
    ninlil_posix_lab_platform_config_defaults(&platform_config);
    platform_config.database_path = database_path;
    platform_config.role = role;
    platform_config.environment = NINLIL_ENV_TEST;
    platform_config.execution_context_id = 1u;
    platform_config.entropy_seed =
        role == NINLIL_ROLE_CONTROLLER
        ? 0x434f4e54524f4c4cull
        : 0x454e44504f494e54ull;
    platform_config.entropy_stream_id =
        role == NINLIL_ROLE_CONTROLLER ? 0x11u : 0x21u;
    platform_config.max_entries_per_namespace = 1024u;
    platform_config.max_bytes_per_namespace = 4u * 1024u * 1024u;
    side->platform = ninlil_posix_lab_platform_create(&platform_config);
    if (side->platform == NULL) {
        return 0;
    }
    base_ops = ninlil_posix_lab_platform_ops(side->platform);
    if (base_ops == NULL || base_ops->clock == NULL
        || base_ops->clock->now == NULL) {
        return 0;
    }
    side->platform_ops = *base_ops;
    side->link.clock = base_ops->clock;
    side->link.available = 1u;
    side->link.availability_epoch = 1u;
    pair_tx_gate_init(
        &side->tx_gate,
        &side->tx_gate_ops,
        base_ops->clock,
        role == NINLIL_ROLE_CONTROLLER ? 0x31u : 0x51u);
    side->platform_ops.tx_gate = &side->tx_gate_ops;

    (void)memset(&fabric_config, 0, sizeof(fabric_config));
    fabric_config.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    fabric_config.struct_size = (uint16_t)sizeof(fabric_config);
    fabric_config.profile_id = NINLIL_FABRIC_PROFILE_1;
    fabric_config.storage = base_ops->storage;
    fabric_config.clock = base_ops->clock;
    fabric_config.execution = base_ops->execution;
    if (ninlil_fabric_private_create_v1(
            &fabric_config,
            side->fabric_workspace,
            sizeof(side->fabric_workspace),
            &side->fabric)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    if (ninlil_fabric_private_bearer_ops_v1(
            side->fabric, &side->fabric_bearer)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (base_ops->clock->now(base_ops->clock->user, &now) != NINLIL_PORT_OK
        || now.trust != NINLIL_CLOCK_TRUSTED) {
        return 0;
    }
    fill_link_descriptor(&link_descriptor, peer_runtime_id, &now);
    pair_ops_init(&link_ops, &side->link);
    if (ninlil_fabric_private_register_link_v1(
            side->fabric,
            &link_descriptor,
            &link_ops,
            &side->registration)
        != NINLIL_FABRIC_PRIVATE_OK) {
        return 0;
    }
    side->platform_ops.bearer = side->fabric_bearer;
    return 1;
}

static int side_close(runtime_side_t *side)
{
    uint32_t done = 0u;
    uint32_t work = 0u;
    uint32_t spins;
    int ok = 1;

    if (side->runtime != NULL) {
        if (ninlil_runtime_destroy(side->runtime) != NINLIL_OK) {
            ok = 0;
        }
        side->runtime = NULL;
    }
    if (side->fabric != NULL) {
        if (ninlil_fabric_private_close_begin_v1(side->fabric)
            != NINLIL_FABRIC_PRIVATE_OK) {
            ok = 0;
        }
        for (spins = 0u; spins < 128u && done == 0u; ++spins) {
            (void)ninlil_fabric_private_step_v1(
                side->fabric, 64u, &work);
            (void)ninlil_fabric_private_close_poll_v1(
                side->fabric, &done);
        }
        if (done == 0u
            || ninlil_fabric_private_destroy_v1(side->fabric)
                != NINLIL_FABRIC_PRIVATE_OK) {
            ok = 0;
        }
        side->fabric = NULL;
    }
    if (side->platform != NULL) {
        ninlil_posix_lab_platform_destroy(side->platform);
        side->platform = NULL;
    }
    return ok;
}

static int query_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *out_snapshot,
    ninlil_target_snapshot_t *out_target)
{
    (void)memset(out_target, 0, sizeof(*out_target));
    set_header(
        &out_target->abi_version,
        &out_target->struct_size,
        sizeof(*out_target));
    (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
    set_header(
        &out_snapshot->abi_version,
        &out_snapshot->struct_size,
        sizeof(*out_snapshot));
    out_snapshot->targets = out_target;
    out_snapshot->target_capacity = 1u;
    return ninlil_transaction_query(
        runtime, transaction_id, out_snapshot)
        == NINLIL_OK;
}

static int run_actual_e2e(void)
{
    static const uint8_t controller_namespace[] = "actual-core-controller";
    static const uint8_t endpoint_namespace[] = "actual-core-endpoint";
    static const uint8_t idempotency_key[] = "actual-fabric-e2e-idempotency";
    static const uint8_t payload[16] = {
        0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
        0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu
    };
    runtime_side_t controller;
    runtime_side_t endpoint;
    ninlil_id128_t controller_runtime_id;
    ninlil_id128_t endpoint_runtime_id;
    ninlil_id128_t endpoint_app_id;
    ninlil_runtime_config_t controller_config;
    ninlil_runtime_config_t endpoint_config;
    ninlil_service_descriptor_t controller_descriptor;
    ninlil_service_descriptor_t endpoint_descriptor;
    ninlil_service_callbacks_t callbacks;
    ninlil_time_sample_t controller_now;
    ninlil_time_sample_t endpoint_now;
    ninlil_submission_t submission;
    ninlil_submission_result_t submission_result;
    ninlil_concrete_target_t target;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target_snapshot;
    ninlil_status_t runtime_status;
    uint32_t step;
    int satisfied = 0;

    set_id(&controller_runtime_id, 0x10u);
    set_id(&endpoint_runtime_id, 0x21u);
    set_id(&endpoint_app_id, 0x81u);
    REQUIRE(side_init(
        &controller,
        NINLIL_ROLE_CONTROLLER,
        &endpoint_runtime_id,
        NULL));
    REQUIRE(side_init(
        &endpoint,
        NINLIL_ROLE_ENDPOINT,
        &controller_runtime_id,
        NULL));
    controller.link.peer = &endpoint.link;
    endpoint.link.peer = &controller.link;

    (void)memset(&controller_now, 0, sizeof(controller_now));
    set_header(
        &controller_now.abi_version,
        &controller_now.struct_size,
        sizeof(controller_now));
    REQUIRE(
        controller.platform_ops.clock->now(
            controller.platform_ops.clock->user, &controller_now)
        == NINLIL_PORT_OK);
    (void)memset(&endpoint_now, 0, sizeof(endpoint_now));
    set_header(
        &endpoint_now.abi_version,
        &endpoint_now.struct_size,
        sizeof(endpoint_now));
    REQUIRE(
        endpoint.platform_ops.clock->now(
            endpoint.platform_ops.clock->user, &endpoint_now)
        == NINLIL_PORT_OK);

    controller_descriptor = service_descriptor(0x70u);
    endpoint_descriptor = service_descriptor(0x81u);
    REQUIRE(install_forward_policy(
        &controller,
        &controller_descriptor,
        &endpoint_runtime_id,
        &endpoint_app_id,
        &controller_now));
    REQUIRE(install_forward_policy(
        &endpoint,
        &endpoint_descriptor,
        &endpoint_runtime_id,
        &endpoint_app_id,
        &endpoint_now));

    controller_config = runtime_config(
        NINLIL_ROLE_CONTROLLER,
        controller_namespace,
        sizeof(controller_namespace) - 1u,
        0x10u);
    endpoint_config = runtime_config(
        NINLIL_ROLE_ENDPOINT,
        endpoint_namespace,
        sizeof(endpoint_namespace) - 1u,
        0x21u);
    runtime_status = ninlil_runtime_create(
        &controller_config, &controller.platform_ops, &controller.runtime);
    if (runtime_status != NINLIL_OK) {
        (void)fprintf(
            stderr,
            "controller runtime_create status=%u\n",
            (unsigned)runtime_status);
    }
    REQUIRE(runtime_status == NINLIL_OK);
    runtime_status = ninlil_runtime_create(
        &endpoint_config, &endpoint.platform_ops, &endpoint.runtime);
    if (runtime_status != NINLIL_OK) {
        (void)fprintf(
            stderr,
            "endpoint runtime_create status=%u\n",
            (unsigned)runtime_status);
    }
    REQUIRE(runtime_status == NINLIL_OK);

    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version, &callbacks.struct_size, sizeof(callbacks));
    REQUIRE(ninlil_service_register(
                controller.runtime,
                &controller_descriptor,
                &callbacks,
                &controller.service)
        == NINLIL_OK);
    callbacks.on_delivery = endpoint_delivery;
    callbacks.on_reconcile = endpoint_reconcile;
    REQUIRE(ninlil_service_register(
                endpoint.runtime,
                &endpoint_descriptor,
                &callbacks,
                &endpoint.service)
        == NINLIL_OK);

    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    target.target_runtime_id = endpoint_runtime_id;
    target.target_application_instance_id = endpoint_app_id;
    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.targets = &target;
    submission.target_count = 1u;
    submission.schema_major = 1u;
    submission.required_evidence = NINLIL_EVIDENCE_VERIFIED;
    submission.effect_deadline_ms = 60000u;
    submission.evidence_grace_ms = 5000u;
    submission.generation = 1u;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length = sizeof(idempotency_key) - 1u;
    submission.payload.data = payload;
    submission.payload.length = sizeof(payload);
    REQUIRE(set_payload_digest(
        &submission.content_digest, payload, sizeof(payload)));
    (void)memset(&submission_result, 0, sizeof(submission_result));
    set_header(
        &submission_result.abi_version,
        &submission_result.struct_size,
        sizeof(submission_result));
    REQUIRE(ninlil_submit(
                controller.service, &submission, &submission_result)
        == NINLIL_OK);
    REQUIRE(
        submission_result.kind == NINLIL_SUBMISSION_ADMITTED_READY);

    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 8u;
    budget.max_callbacks = 8u;
    budget.max_state_transitions = 16u;
    budget.max_bearer_sends = 8u;
    for (step = 0u; step < 512u; ++step) {
        uint32_t work = 0u;

        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        runtime_status =
            ninlil_runtime_step(controller.runtime, &budget, &step_result);
        if (runtime_status != NINLIL_OK) {
            (void)fprintf(
                stderr,
                "controller runtime_step failed at step=%u status=%d "
                "ingress=%u callbacks=%u transitions=%u sends=%u health=%u "
                "degraded=%u\n",
                (unsigned)step,
                (int)runtime_status,
                (unsigned)step_result.ingress_processed,
                (unsigned)step_result.callbacks_invoked,
                (unsigned)step_result.state_transitions,
                (unsigned)step_result.bearer_sends,
                (unsigned)step_result.health,
                (unsigned)step_result.degraded_reason);
            return 1;
        }
        REQUIRE(ninlil_fabric_private_step_v1(
                    controller.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        REQUIRE(ninlil_fabric_private_step_v1(
                    endpoint.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        runtime_status =
            ninlil_runtime_step(endpoint.runtime, &budget, &step_result);
        if (runtime_status != NINLIL_OK) {
            (void)fprintf(
                stderr,
                "endpoint runtime_step failed at step=%u status=%d "
                "ingress=%u callbacks=%u transitions=%u sends=%u health=%u "
                "degraded=%u\n",
                (unsigned)step,
                (int)runtime_status,
                (unsigned)step_result.ingress_processed,
                (unsigned)step_result.callbacks_invoked,
                (unsigned)step_result.state_transitions,
                (unsigned)step_result.bearer_sends,
                (unsigned)step_result.health,
                (unsigned)step_result.degraded_reason);
            return 1;
        }
        REQUIRE(ninlil_fabric_private_step_v1(
                    endpoint.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        REQUIRE(ninlil_fabric_private_step_v1(
                    controller.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);

        REQUIRE(query_transaction(
            controller.runtime,
            &submission_result.transaction_id,
            &snapshot,
            &target_snapshot));
        if (snapshot.state == NINLIL_TXN_TERMINAL
            && snapshot.outcome == NINLIL_OUTCOME_SATISFIED
            && target_snapshot.latest_evidence >= NINLIL_EVIDENCE_VERIFIED) {
            satisfied = 1;
            break;
        }
    }

    if (satisfied == 0) {
        (void)fprintf(
            stderr,
            "actual E2E did not satisfy: state=%u outcome=%u reason=%u "
            "target_state=%u target_outcome=%u target_reason=%u evidence=%u "
            "delivery=%u ctrl_tx=%u end_tx=%u ctrl_q=%u end_q=%u\n",
            (unsigned)snapshot.state,
            (unsigned)snapshot.outcome,
            (unsigned)snapshot.reason,
            (unsigned)target_snapshot.state,
            (unsigned)target_snapshot.outcome,
            (unsigned)target_snapshot.reason,
            (unsigned)target_snapshot.latest_evidence,
            (unsigned)g_delivery_calls,
            (unsigned)controller.link.start_calls,
            (unsigned)endpoint.link.start_calls,
            (unsigned)controller.link.queue_count,
            (unsigned)endpoint.link.queue_count);
    }
    REQUIRE(satisfied != 0);
    REQUIRE(g_delivery_calls == 1u);
    REQUIRE(controller.link.start_calls >= 1u);
    REQUIRE(endpoint.link.start_calls >= 1u);
    REQUIRE(controller.link.accepted_packets >= 1u);
    REQUIRE(endpoint.link.accepted_packets >= 1u);
    REQUIRE(side_close(&endpoint));
    REQUIRE(side_close(&controller));
    return 0;
}

static int submit_multi_service_transaction(
    ninlil_service_t *service,
    const ninlil_id128_t *target_runtime_id,
    const ninlil_id128_t *target_application_id,
    ninlil_family_t family,
    const uint8_t *idempotency_key,
    uint32_t idempotency_key_length,
    const uint8_t *payload,
    uint32_t payload_length,
    uint8_t event_seed,
    uint64_t generation,
    ninlil_submission_result_t *out_result)
{
    ninlil_concrete_target_t target;
    ninlil_submission_t submission;
    ninlil_status_t status;

    (void)memset(&target, 0, sizeof(target));
    set_header(&target.abi_version, &target.struct_size, sizeof(target));
    target.target_runtime_id = *target_runtime_id;
    target.target_application_instance_id = *target_application_id;

    (void)memset(&submission, 0, sizeof(submission));
    set_header(
        &submission.abi_version,
        &submission.struct_size,
        sizeof(submission));
    submission.schema_major = 1u;
    submission.targets = &target;
    submission.target_count = 1u;
    submission.required_evidence =
        family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_EVIDENCE_APPLIED
        : NINLIL_EVIDENCE_VERIFIED;
    submission.effect_deadline_ms =
        family == NINLIL_FAMILY_EVENT_FACT
        ? NINLIL_NO_DEADLINE
        : 60000u;
    submission.evidence_grace_ms =
        family == NINLIL_FAMILY_EVENT_FACT ? 0u : 5000u;
    submission.idempotency_key.data = idempotency_key;
    submission.idempotency_key.length = idempotency_key_length;
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        set_id(&submission.event_id, event_seed);
    }
    submission.generation = generation;
    submission.payload.data = payload;
    submission.payload.length = payload_length;
    if (!set_payload_digest(
            &submission.content_digest, payload, payload_length)) {
        return 0;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    set_header(
        &out_result->abi_version,
        &out_result->struct_size,
        sizeof(*out_result));
    status = ninlil_submit(service, &submission, out_result);
    if (status != NINLIL_OK
        || out_result->kind != NINLIL_SUBMISSION_ADMITTED_READY) {
        (void)fprintf(
            stderr,
            "multi-service submit failed: family=%u status=%d kind=%u "
            "reason=%u retry=%u delay=%llu payload=%u\n",
            (unsigned)family,
            (int)status,
            (unsigned)out_result->kind,
            (unsigned)out_result->reason,
            (unsigned)out_result->retry_guidance,
            (unsigned long long)out_result->retry_delay_ms,
            (unsigned)payload_length);
        return 0;
    }
    return 1;
}

static int multi_transaction_satisfied(
    ninlil_runtime_t *runtime,
    const ninlil_submission_result_t *result,
    const ninlil_service_descriptor_t *expected_service,
    ninlil_evidence_stage_t expected_evidence)
{
    ninlil_transaction_snapshot_t snapshot;
    ninlil_target_snapshot_t target;

    if (runtime == NULL || result == NULL || expected_service == NULL
        || !query_transaction(
            runtime, &result->transaction_id, &snapshot, &target)) {
        return 0;
    }
    return id_equal(&snapshot.transaction_id, &result->transaction_id)
        && service_identity_matches_descriptor(
            &snapshot.service,
            expected_service,
            expected_service->schema_minor_min)
        && snapshot.family == expected_service->family
        && snapshot.state == NINLIL_TXN_TERMINAL
        && snapshot.outcome == NINLIL_OUTCOME_SATISFIED
        && snapshot.reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET
        && snapshot.latest_evidence == expected_evidence
        && snapshot.target_count == 1u
        && target.state == NINLIL_TXN_TERMINAL
        && target.outcome == NINLIL_OUTCOME_SATISFIED
        && target.reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET
        && target.latest_evidence == expected_evidence;
}

static int transaction_list_exact(
    ninlil_runtime_t *runtime,
    const ninlil_submission_result_t *const *expected_results,
    const ninlil_service_descriptor_t *const *expected_services,
    uint32_t expected_count)
{
    ninlil_query_t query;
    ninlil_transaction_page_t page;
    ninlil_transaction_summary_t items[8];
    uint8_t seen[8];
    uint32_t index;

    if (runtime == NULL || expected_results == NULL
        || expected_services == NULL || expected_count == 0u
        || expected_count > 8u) {
        return 0;
    }
    (void)memset(&query, 0, sizeof(query));
    set_header(&query.abi_version, &query.struct_size, sizeof(query));
    query.include_terminal = 1u;
    query.include_nonterminal = 1u;
    (void)memset(&page, 0, sizeof(page));
    set_header(&page.abi_version, &page.struct_size, sizeof(page));
    (void)memset(items, 0, sizeof(items));
    for (index = 0u; index < 8u; ++index) {
        set_header(
            &items[index].abi_version,
            &items[index].struct_size,
            sizeof(items[index]));
    }
    page.items = items;
    page.item_capacity = 8u;
    (void)memset(seen, 0, sizeof(seen));
    if (ninlil_transaction_list(runtime, &query, &page) != NINLIL_OK
        || page.item_count != expected_count || page.has_more != 0u) {
        return 0;
    }
    for (index = 0u; index < page.item_count; ++index) {
        uint32_t expected_index;
        int found = 0;

        if (items[index].abi_version != NINLIL_ABI_VERSION
            || items[index].struct_size != (uint16_t)sizeof(items[index])
            || items[index].state != NINLIL_TXN_TERMINAL
            || items[index].outcome != NINLIL_OUTCOME_SATISFIED
            || items[index].reason
                != NINLIL_REASON_REQUIRED_EVIDENCE_MET) {
            return 0;
        }
        for (expected_index = 0u;
             expected_index < expected_count;
             ++expected_index) {
            if (id_equal(
                    &items[index].transaction_id,
                    &expected_results[expected_index]->transaction_id)) {
                if (seen[expected_index] != 0u
                    || !service_identity_matches_descriptor(
                        &items[index].service,
                        expected_services[expected_index],
                        expected_services[expected_index]->schema_minor_min)
                    || items[index].family
                        != expected_services[expected_index]->family) {
                    return 0;
                }
                seen[expected_index] = 1u;
                found = 1;
                break;
            }
        }
        if (found == 0) {
            return 0;
        }
    }
    for (index = 0u; index < expected_count; ++index) {
        if (seen[index] == 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * One physical endpoint, four simultaneous public Services:
 *
 *   display.command       DesiredState downlink
 *   access.event          EventFact uplink
 *   temperature.telemetry EventFact uplink (periodic + query response)
 *   temperature.query     DesiredState downlink
 *
 * The response is submitted only after the query callback has returned.  One
 * outbound frame is duplicated and one is silently lost after transport
 * acceptance, proving application effects stay exactly once while the public
 * retry/dedup path converges.
 */
static int run_multi_service_actual_e2e(void)
{
    enum {
        MULTI_DISPLAY = NINLIL_MULTI_SERVICE_NODE_DISPLAY_COMMAND,
        MULTI_ACCESS = NINLIL_MULTI_SERVICE_NODE_ACCESS_EVENT,
        MULTI_TEMPERATURE =
            NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_TELEMETRY,
        MULTI_QUERY = NINLIL_MULTI_SERVICE_NODE_TEMPERATURE_QUERY,
        MULTI_SERVICE_COUNT = NINLIL_MULTI_SERVICE_NODE_SERVICE_COUNT
    };
    static const uint8_t controller_namespace[] =
        "multi-service-controller";
    static const uint8_t endpoint_namespace[] = "multi-service-endpoint";
    static const ninlil_family_t families[MULTI_SERVICE_COUNT] = {
        NINLIL_FAMILY_DESIRED_STATE,
        NINLIL_FAMILY_EVENT_FACT,
        NINLIL_FAMILY_EVENT_FACT,
        NINLIL_FAMILY_DESIRED_STATE
    };
    static const uint8_t display_payload[] = {
        0x01u, 0x00u, 0x2au, 0x0fu,
        0xe6u, 0xb0u, 0xb4u, 0xe6u, 0xbcu, 0x8fu,
        0xe3u, 0x82u, 0x8cu, 0xe6u, 0xa4u, 0x9cu,
        0xe7u, 0x9fu, 0xa5u
    };
    static const uint8_t access_payload[] = {
        0xa5u, 0x01u, 0x7fu, 0x00u, 0xffu, 0x10u, 0x20u, 0x30u
    };
    static const uint8_t temperature_periodic_payload[] = {
        0x01u, 0x09u, 0x29u, 0x00u, 0x00u, 0x00u
    };
    static const uint8_t temperature_query_payload[] = {
        0x51u, 0x01u, 0x00u, 0x00u, 0x00u, 0x2au
    };
    static const uint8_t temperature_response_payload[] = {
        0x52u, 0x01u, 0x09u, 0x2au, 0x00u, 0x00u, 0x00u, 0x2au
    };
    static const uint8_t display_idempotency[] = "multi-display-1";
    static const uint8_t access_idempotency[] = "multi-access-1";
    static const uint8_t temperature_idempotency[] = "multi-temperature-1";
    static const uint8_t query_idempotency[] = "multi-query-1";
    static const uint8_t response_idempotency[] = "multi-response-1";
    runtime_side_t controller;
    runtime_side_t endpoint;
    ninlil_id128_t controller_runtime_id;
    ninlil_id128_t endpoint_runtime_id;
    ninlil_runtime_config_t controller_config;
    ninlil_runtime_config_t endpoint_config;
    ninlil_origin_authorization_ops_t multi_origin_ops;
    ninlil_multi_service_node_profile_t controller_profile;
    ninlil_multi_service_node_profile_t endpoint_profile;
    ninlil_multi_service_node_state_t physical_node_state;
    ninlil_service_descriptor_t controller_descriptors[MULTI_SERVICE_COUNT];
    ninlil_service_descriptor_t endpoint_descriptors[MULTI_SERVICE_COUNT];
    ninlil_service_t *controller_services[MULTI_SERVICE_COUNT];
    ninlil_service_t *endpoint_services[MULTI_SERVICE_COUNT];
    multi_callback_state_t callback_states[MULTI_SERVICE_COUNT];
    ninlil_service_callbacks_t callbacks;
    ninlil_time_sample_t controller_now;
    ninlil_time_sample_t endpoint_now;
    ninlil_submission_result_t display_result;
    ninlil_submission_result_t access_result;
    ninlil_submission_result_t temperature_result;
    ninlil_submission_result_t query_result;
    ninlil_submission_result_t response_result;
    ninlil_step_budget_t budget;
    ninlil_step_result_t step_result;
    ninlil_status_t runtime_status;
    uint32_t index;
    uint32_t step;
    int response_submitted = 0;
    int all_satisfied = 0;

    (void)memset(controller_services, 0, sizeof(controller_services));
    (void)memset(endpoint_services, 0, sizeof(endpoint_services));
    (void)memset(callback_states, 0, sizeof(callback_states));
    set_id(&controller_runtime_id, 0x10u);
    set_id(&endpoint_runtime_id, 0x21u);
    REQUIRE(side_init(
        &controller,
        NINLIL_ROLE_CONTROLLER,
        &endpoint_runtime_id,
        NULL));
    REQUIRE(side_init(
        &endpoint,
        NINLIL_ROLE_ENDPOINT,
        &controller_runtime_id,
        NULL));
    controller.link.peer = &endpoint.link;
    endpoint.link.peer = &controller.link;
    (void)memset(&multi_origin_ops, 0, sizeof(multi_origin_ops));
    set_header(
        &multi_origin_ops.abi_version,
        &multi_origin_ops.struct_size,
        sizeof(multi_origin_ops));
    multi_origin_ops.evaluate = multi_service_origin_allow;
    endpoint.platform_ops.origin_authorization = &multi_origin_ops;

    (void)memset(&controller_now, 0, sizeof(controller_now));
    set_header(
        &controller_now.abi_version,
        &controller_now.struct_size,
        sizeof(controller_now));
    REQUIRE(
        controller.platform_ops.clock->now(
            controller.platform_ops.clock->user, &controller_now)
        == NINLIL_PORT_OK);
    (void)memset(&endpoint_now, 0, sizeof(endpoint_now));
    set_header(
        &endpoint_now.abi_version,
        &endpoint_now.struct_size,
        sizeof(endpoint_now));
    REQUIRE(
        endpoint.platform_ops.clock->now(
            endpoint.platform_ops.clock->user, &endpoint_now)
        == NINLIL_PORT_OK);

    REQUIRE(ninlil_multi_service_node_profile_init(
                &controller_profile, 0x70u)
        == NINLIL_OK);
    REQUIRE(ninlil_multi_service_node_profile_init(
                &endpoint_profile, 0x80u)
        == NINLIL_OK);
    REQUIRE(ninlil_multi_service_node_profile_validate(&controller_profile)
        == NINLIL_OK);
    REQUIRE(ninlil_multi_service_node_profile_validate(&endpoint_profile)
        == NINLIL_OK);
    REQUIRE(controller_profile.manifest.runtime_role_constraint
        == NINLIL_MULTI_SERVICE_NODE_ROLE_NEUTRAL);
    REQUIRE(endpoint_profile.manifest.runtime_role_constraint
        == NINLIL_MULTI_SERVICE_NODE_ROLE_NEUTRAL);
    REQUIRE(controller_profile.manifest.service_count
        == MULTI_SERVICE_COUNT);
    REQUIRE(endpoint_profile.manifest.service_count == MULTI_SERVICE_COUNT);
    REQUIRE(controller_profile.manifest.service_mask
        == NINLIL_MULTI_SERVICE_NODE_ALL_SERVICES_MASK);
    REQUIRE(endpoint_profile.manifest.receive_service_mask
        == NINLIL_MULTI_SERVICE_NODE_RECEIVE_MASK);
    REQUIRE(endpoint_profile.manifest.originate_service_mask
        == NINLIL_MULTI_SERVICE_NODE_ORIGINATE_MASK);
    REQUIRE(ninlil_multi_service_node_state_init(&physical_node_state)
        == NINLIL_OK);

    for (index = 0u; index < MULTI_SERVICE_COUNT; ++index) {
        controller_descriptors[index] =
            controller_profile.services[index];
        endpoint_descriptors[index] = endpoint_profile.services[index];
        REQUIRE(controller_descriptors[index].family == families[index]);
        REQUIRE(endpoint_descriptors[index].family == families[index]);
        REQUIRE(install_forward_policy_seeded(
            &controller,
            &controller_descriptors[index],
            families[index] == NINLIL_FAMILY_EVENT_FACT
                ? &controller_runtime_id
                : &endpoint_runtime_id,
            families[index] == NINLIL_FAMILY_EVENT_FACT
                ? &controller_descriptors[index].local_application_instance_id
                : &endpoint_descriptors[index].local_application_instance_id,
            &controller_now,
            (uint8_t)(0x11u + index),
            (uint8_t)(0x31u + index),
            (uint8_t)(0x51u + index),
            (uint8_t)(0x71u + index)));
        REQUIRE(install_forward_policy_seeded(
            &endpoint,
            &endpoint_descriptors[index],
            families[index] == NINLIL_FAMILY_EVENT_FACT
                ? &controller_runtime_id
                : &endpoint_runtime_id,
            families[index] == NINLIL_FAMILY_EVENT_FACT
                ? &controller_descriptors[index].local_application_instance_id
                : &endpoint_descriptors[index].local_application_instance_id,
            &endpoint_now,
            (uint8_t)(0x11u + index),
            (uint8_t)(0x31u + index),
            (uint8_t)(0x51u + index),
            (uint8_t)(0x71u + index)));
        callback_states[index].expected_service =
            &controller_descriptors[index];
        callback_states[index].expected_schema_minor =
            controller_descriptors[index].schema_minor_min;
    }
    callback_states[MULTI_DISPLAY].node_state = &physical_node_state;
    callback_states[MULTI_DISPLAY].node_service_index = MULTI_DISPLAY;
    callback_states[MULTI_QUERY].node_state = &physical_node_state;
    callback_states[MULTI_QUERY].node_service_index = MULTI_QUERY;
    callback_states[MULTI_QUERY].node_query_correlation = 42u;

    callback_states[MULTI_DISPLAY].expected_payloads[0] = display_payload;
    callback_states[MULTI_DISPLAY].expected_lengths[0] =
        sizeof(display_payload);
    callback_states[MULTI_DISPLAY].expected_count = 1u;
    callback_states[MULTI_ACCESS].expected_payloads[0] = access_payload;
    callback_states[MULTI_ACCESS].expected_lengths[0] =
        sizeof(access_payload);
    callback_states[MULTI_ACCESS].expected_count = 1u;
    callback_states[MULTI_TEMPERATURE].expected_payloads[0] =
        temperature_periodic_payload;
    callback_states[MULTI_TEMPERATURE].expected_lengths[0] =
        sizeof(temperature_periodic_payload);
    callback_states[MULTI_TEMPERATURE].expected_payloads[1] =
        temperature_response_payload;
    callback_states[MULTI_TEMPERATURE].expected_lengths[1] =
        sizeof(temperature_response_payload);
    callback_states[MULTI_TEMPERATURE].expected_count = 2u;
    callback_states[MULTI_QUERY].expected_payloads[0] =
        temperature_query_payload;
    callback_states[MULTI_QUERY].expected_lengths[0] =
        sizeof(temperature_query_payload);
    callback_states[MULTI_QUERY].expected_count = 1u;
    REQUIRE(multi_service_identity_collision_fixture(
        &controller_descriptors[MULTI_DISPLAY],
        display_payload,
        sizeof(display_payload)));

    controller_config = runtime_config(
        NINLIL_ROLE_CONTROLLER,
        controller_namespace,
        sizeof(controller_namespace) - 1u,
        0x10u);
    endpoint_config = runtime_config(
        NINLIL_ROLE_ENDPOINT,
        endpoint_namespace,
        sizeof(endpoint_namespace) - 1u,
        0x21u);
    controller_config.limits.max_services = 8u;
    endpoint_config.limits.max_services = 8u;
    REQUIRE(ninlil_runtime_create(
                &controller_config,
                &controller.platform_ops,
                &controller.runtime)
        == NINLIL_OK);
    REQUIRE(ninlil_runtime_create(
                &endpoint_config,
                &endpoint.platform_ops,
                &endpoint.runtime)
        == NINLIL_OK);

    for (index = 0u; index < MULTI_SERVICE_COUNT; ++index) {
        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version,
            &callbacks.struct_size,
            sizeof(callbacks));
        if (families[index] == NINLIL_FAMILY_EVENT_FACT) {
            callbacks.user = &callback_states[index];
            callbacks.on_delivery = multi_service_delivery;
            callbacks.on_reconcile = endpoint_reconcile;
        }
        REQUIRE(ninlil_service_register(
                    controller.runtime,
                    &controller_descriptors[index],
                    &callbacks,
                    &controller_services[index])
            == NINLIL_OK);

        (void)memset(&callbacks, 0, sizeof(callbacks));
        set_header(
            &callbacks.abi_version,
            &callbacks.struct_size,
            sizeof(callbacks));
        if (families[index] == NINLIL_FAMILY_DESIRED_STATE) {
            callbacks.user = &callback_states[index];
            callbacks.on_delivery = multi_service_delivery;
            callbacks.on_reconcile = endpoint_reconcile;
        }
        REQUIRE(ninlil_service_register(
                    endpoint.runtime,
                    &endpoint_descriptors[index],
                    &callbacks,
                    &endpoint_services[index])
            == NINLIL_OK);
    }

    REQUIRE(submit_multi_service_transaction(
        controller_services[MULTI_DISPLAY],
        &endpoint_runtime_id,
        &endpoint_descriptors[MULTI_DISPLAY].local_application_instance_id,
        NINLIL_FAMILY_DESIRED_STATE,
        display_idempotency,
        sizeof(display_idempotency) - 1u,
        display_payload,
        sizeof(display_payload),
        0u,
        1u,
        &display_result));
    REQUIRE(submit_multi_service_transaction(
        endpoint_services[MULTI_ACCESS],
        &controller_runtime_id,
        &controller_descriptors[MULTI_ACCESS].local_application_instance_id,
        NINLIL_FAMILY_EVENT_FACT,
        access_idempotency,
        sizeof(access_idempotency) - 1u,
        access_payload,
        sizeof(access_payload),
        0xA1u,
        0u,
        &access_result));
    REQUIRE(ninlil_multi_service_node_note_originated(
                &physical_node_state, MULTI_ACCESS)
        == NINLIL_OK);
    REQUIRE(submit_multi_service_transaction(
        endpoint_services[MULTI_TEMPERATURE],
        &controller_runtime_id,
        &controller_descriptors[MULTI_TEMPERATURE]
             .local_application_instance_id,
        NINLIL_FAMILY_EVENT_FACT,
        temperature_idempotency,
        sizeof(temperature_idempotency) - 1u,
        temperature_periodic_payload,
        sizeof(temperature_periodic_payload),
        0xB1u,
        0u,
        &temperature_result));
    REQUIRE(ninlil_multi_service_node_note_originated(
                &physical_node_state, MULTI_TEMPERATURE)
        == NINLIL_OK);
    REQUIRE(submit_multi_service_transaction(
        controller_services[MULTI_QUERY],
        &endpoint_runtime_id,
        &endpoint_descriptors[MULTI_QUERY].local_application_instance_id,
        NINLIL_FAMILY_DESIRED_STATE,
        query_idempotency,
        sizeof(query_idempotency) - 1u,
        temperature_query_payload,
        sizeof(temperature_query_payload),
        0u,
        1u,
        &query_result));

    controller.link.duplicate_budget = 1u;
    endpoint.link.drop_budget = 1u;
    (void)memset(&budget, 0, sizeof(budget));
    set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
    budget.max_ingress_messages = 8u;
    budget.max_callbacks = 8u;
    budget.max_state_transitions = 16u;
    budget.max_bearer_sends = 8u;
    for (step = 0u; step < 1024u; ++step) {
        uint32_t work = 0u;

        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        runtime_status =
            ninlil_runtime_step(controller.runtime, &budget, &step_result);
        if (runtime_status != NINLIL_OK) {
            (void)fprintf(
                stderr,
                "multi controller step=%u status=%d health=%u reason=%u "
                "ingress=%u callbacks=%u transitions=%u sends=%u\n",
                (unsigned)step,
                (int)runtime_status,
                (unsigned)step_result.health,
                (unsigned)step_result.degraded_reason,
                (unsigned)step_result.ingress_processed,
                (unsigned)step_result.callbacks_invoked,
                (unsigned)step_result.state_transitions,
                (unsigned)step_result.bearer_sends);
        }
        REQUIRE(runtime_status == NINLIL_OK);
        REQUIRE(ninlil_fabric_private_step_v1(
                    controller.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        REQUIRE(ninlil_fabric_private_step_v1(
                    endpoint.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);

        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        runtime_status =
            ninlil_runtime_step(endpoint.runtime, &budget, &step_result);
        if (runtime_status != NINLIL_OK) {
            ninlil_transaction_snapshot_t access_snapshot;
            ninlil_transaction_snapshot_t temperature_snapshot;
            ninlil_target_snapshot_t access_target;
            ninlil_target_snapshot_t temperature_target;

            (void)query_transaction(
                endpoint.runtime,
                &access_result.transaction_id,
                &access_snapshot,
                &access_target);
            (void)query_transaction(
                endpoint.runtime,
                &temperature_result.transaction_id,
                &temperature_snapshot,
                &temperature_target);
            (void)fprintf(
                stderr,
                "multi endpoint step=%u status=%d health=%u reason=%u "
                "ingress=%u callbacks=%u transitions=%u sends=%u "
                "access=%u/%u/%u target=%u/%u/%u "
                "temperature=%u/%u/%u target=%u/%u/%u "
                "links=%u/%u queues=%u/%u callback-events=%u/%u\n",
                (unsigned)step,
                (int)runtime_status,
                (unsigned)step_result.health,
                (unsigned)step_result.degraded_reason,
                (unsigned)step_result.ingress_processed,
                (unsigned)step_result.callbacks_invoked,
                (unsigned)step_result.state_transitions,
                (unsigned)step_result.bearer_sends,
                (unsigned)access_snapshot.state,
                (unsigned)access_snapshot.outcome,
                (unsigned)access_snapshot.reason,
                (unsigned)access_target.state,
                (unsigned)access_target.outcome,
                (unsigned)access_target.reason,
                (unsigned)temperature_snapshot.state,
                (unsigned)temperature_snapshot.outcome,
                (unsigned)temperature_snapshot.reason,
                (unsigned)temperature_target.state,
                (unsigned)temperature_target.outcome,
                (unsigned)temperature_target.reason,
                (unsigned)controller.link.start_calls,
                (unsigned)endpoint.link.start_calls,
                (unsigned)controller.link.queue_count,
                (unsigned)endpoint.link.queue_count,
                (unsigned)callback_states[MULTI_ACCESS].calls,
                (unsigned)callback_states[MULTI_TEMPERATURE].calls);
        }
        REQUIRE(runtime_status == NINLIL_OK);
        if (ninlil_multi_service_node_temperature_response_pending(
                &physical_node_state)
                != 0u
            && response_submitted == 0) {
            uint64_t query_correlation = 0u;
            int admitted;

            REQUIRE(ninlil_multi_service_node_temperature_response_begin(
                        &physical_node_state, &query_correlation)
                == NINLIL_OK);
            REQUIRE(query_correlation == 42u);
            REQUIRE(ninlil_multi_service_node_temperature_response_finish(
                        &physical_node_state, 0u)
                == NINLIL_OK);
            REQUIRE(ninlil_multi_service_node_temperature_response_pending(
                        &physical_node_state)
                == 1u);
            REQUIRE(ninlil_multi_service_node_temperature_response_begin(
                        &physical_node_state, &query_correlation)
                == NINLIL_OK);
            REQUIRE(query_correlation == 42u);
            admitted = submit_multi_service_transaction(
                endpoint_services[MULTI_TEMPERATURE],
                &controller_runtime_id,
                &controller_descriptors[MULTI_TEMPERATURE]
                     .local_application_instance_id,
                NINLIL_FAMILY_EVENT_FACT,
                response_idempotency,
                sizeof(response_idempotency) - 1u,
                temperature_response_payload,
                sizeof(temperature_response_payload),
                0xC1u,
                0u,
                &response_result);
            REQUIRE(ninlil_multi_service_node_temperature_response_finish(
                        &physical_node_state, admitted != 0 ? 1u : 0u)
                == NINLIL_OK);
            REQUIRE(admitted != 0);
            response_submitted = 1;
        }
        REQUIRE(ninlil_fabric_private_step_v1(
                    endpoint.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        REQUIRE(ninlil_fabric_private_step_v1(
                    controller.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        REQUIRE(ninlil_test_clock_advance(
            (ninlil_test_clock_t *)controller.platform_ops.clock->user,
            100u));
        REQUIRE(ninlil_test_clock_advance(
            (ninlil_test_clock_t *)endpoint.platform_ops.clock->user,
            100u));

        if (response_submitted != 0
            && multi_transaction_satisfied(
                controller.runtime,
                &display_result,
                &controller_descriptors[MULTI_DISPLAY],
                NINLIL_EVIDENCE_VERIFIED)
            && multi_transaction_satisfied(
                endpoint.runtime,
                &access_result,
                &endpoint_descriptors[MULTI_ACCESS],
                NINLIL_EVIDENCE_APPLIED)
            && multi_transaction_satisfied(
                endpoint.runtime,
                &temperature_result,
                &endpoint_descriptors[MULTI_TEMPERATURE],
                NINLIL_EVIDENCE_APPLIED)
            && multi_transaction_satisfied(
                controller.runtime,
                &query_result,
                &controller_descriptors[MULTI_QUERY],
                NINLIL_EVIDENCE_VERIFIED)
            && multi_transaction_satisfied(
                endpoint.runtime,
                &response_result,
                &endpoint_descriptors[MULTI_TEMPERATURE],
                NINLIL_EVIDENCE_APPLIED)) {
            all_satisfied = 1;
            break;
        }
    }

    if (all_satisfied == 0) {
        ninlil_transaction_snapshot_t snapshots[5];
        ninlil_target_snapshot_t targets[5];
        const ninlil_submission_result_t *results[5] = {
            &display_result,
            &access_result,
            &temperature_result,
            &query_result,
            &response_result
        };
        ninlil_runtime_t *runtimes[5] = {
            controller.runtime,
            endpoint.runtime,
            endpoint.runtime,
            controller.runtime,
            endpoint.runtime
        };

        (void)fprintf(
            stderr,
            "multi-service incomplete: response=%d callbacks=%u/%u/%u/%u "
            "seen=%u/%u/%u/%u links=%u/%u queues=%u/%u\n",
            response_submitted,
            (unsigned)callback_states[MULTI_DISPLAY].calls,
            (unsigned)callback_states[MULTI_ACCESS].calls,
            (unsigned)callback_states[MULTI_TEMPERATURE].calls,
            (unsigned)callback_states[MULTI_QUERY].calls,
            (unsigned)callback_states[MULTI_DISPLAY].seen_mask,
            (unsigned)callback_states[MULTI_ACCESS].seen_mask,
            (unsigned)callback_states[MULTI_TEMPERATURE].seen_mask,
            (unsigned)callback_states[MULTI_QUERY].seen_mask,
            (unsigned)controller.link.start_calls,
            (unsigned)endpoint.link.start_calls,
            (unsigned)controller.link.queue_count,
            (unsigned)endpoint.link.queue_count);
        for (index = 0u; index < 5u; ++index) {
            int found = response_submitted != 0 || index != 4u;
            if (found != 0
                && query_transaction(
                    runtimes[index],
                    &results[index]->transaction_id,
                    &snapshots[index],
                    &targets[index])) {
                (void)fprintf(
                    stderr,
                    "  tx[%u]=%u/%u/%u evidence=%u target=%u/%u/%u/%u\n",
                    (unsigned)index,
                    (unsigned)snapshots[index].state,
                    (unsigned)snapshots[index].outcome,
                    (unsigned)snapshots[index].reason,
                    (unsigned)snapshots[index].latest_evidence,
                    (unsigned)targets[index].state,
                    (unsigned)targets[index].outcome,
                    (unsigned)targets[index].reason,
                    (unsigned)targets[index].latest_evidence);
            }
        }
    }
    REQUIRE(all_satisfied != 0);
    REQUIRE(controller.link.duplicated_packets == 1u);
    REQUIRE(controller.link.duplicate_budget == 0u);
    REQUIRE(endpoint.link.dropped_packets == 1u);
    REQUIRE(endpoint.link.drop_budget == 0u);
    REQUIRE(callback_states[MULTI_DISPLAY].calls == 1u);
    REQUIRE(callback_states[MULTI_DISPLAY].seen_mask == 1u);
    REQUIRE(callback_states[MULTI_ACCESS].calls == 1u);
    REQUIRE(callback_states[MULTI_ACCESS].seen_mask == 1u);
    REQUIRE(callback_states[MULTI_TEMPERATURE].calls == 2u);
    REQUIRE(callback_states[MULTI_TEMPERATURE].seen_mask == 3u);
    REQUIRE(callback_states[MULTI_QUERY].calls == 1u);
    REQUIRE(callback_states[MULTI_QUERY].seen_mask == 1u);
    for (index = 0u; index < MULTI_SERVICE_COUNT; ++index) {
        REQUIRE(callback_states[index].route_mismatches == 0u);
        REQUIRE(callback_states[index].payload_mismatches == 0u);
        REQUIRE(callback_states[index].state_mismatches == 0u);
    }
    REQUIRE(ninlil_multi_service_node_acceptance_complete(
                &physical_node_state)
        == NINLIL_OK);
    {
        const ninlil_submission_result_t *controller_results[2] = {
            &display_result,
            &query_result
        };
        const ninlil_service_descriptor_t *controller_result_services[2] = {
            &controller_descriptors[MULTI_DISPLAY],
            &controller_descriptors[MULTI_QUERY]
        };
        const ninlil_submission_result_t *endpoint_results[3] = {
            &access_result,
            &temperature_result,
            &response_result
        };
        const ninlil_service_descriptor_t *endpoint_result_services[3] = {
            &endpoint_descriptors[MULTI_ACCESS],
            &endpoint_descriptors[MULTI_TEMPERATURE],
            &endpoint_descriptors[MULTI_TEMPERATURE]
        };

        REQUIRE(transaction_list_exact(
            controller.runtime,
            controller_results,
            controller_result_services,
            2u));
        REQUIRE(transaction_list_exact(
            endpoint.runtime,
            endpoint_results,
            endpoint_result_services,
            3u));
    }
    REQUIRE(side_close(&endpoint));
    REQUIRE(side_close(&controller));
    return 0;
}

#if defined(NINLIL_MFDT_V1_PRIVATE)
typedef struct mfdt_upper_fixture {
    const uint8_t *expected;
    uint32_t expected_len;
    uint8_t token[16];
    uint8_t token_valid;
    uint32_t prepare_calls;
    uint32_t effect_count;
} mfdt_upper_fixture_t;

static int mfdt_upper_prepare(
    void *user,
    const uint8_t publication_token[16],
    const uint8_t *content,
    uint32_t content_len,
    uint8_t publication_evidence_digest_out[32])
{
    mfdt_upper_fixture_t *fixture = (mfdt_upper_fixture_t *)user;
    uint8_t material[20];

    if (fixture == NULL || publication_token == NULL
        || publication_evidence_digest_out == NULL
        || content_len != fixture->expected_len
        || (content_len != 0u
            && (content == NULL
                || memcmp(content, fixture->expected, content_len) != 0))) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    fixture->prepare_calls += 1u;
    if (fixture->token_valid != 0u) {
        if (memcmp(fixture->token, publication_token, 16u) != 0) {
            return NINLIL_MFDT_V1_ERR_DIGEST;
        }
        (void)memcpy(material, publication_token, 16u);
        ninlil_mfdt_v1_put_u32(material + 16u, content_len);
        ninlil_mfdt_v1_sha256(
            material, sizeof(material), publication_evidence_digest_out);
        return NINLIL_MFDT_V1_ALREADY_COMMITTED;
    }
    (void)memcpy(fixture->token, publication_token, 16u);
    fixture->token_valid = 1u;
    fixture->effect_count += 1u;
    (void)memcpy(material, publication_token, 16u);
    ninlil_mfdt_v1_put_u32(material + 16u, content_len);
    ninlil_mfdt_v1_sha256(
        material, sizeof(material), publication_evidence_digest_out);
    return NINLIL_MFDT_V1_PREPARED;
}

static ninlil_service_descriptor_t mfdt_carrier_descriptor(void)
{
    static const uint8_t namespace_id[] = "org.ninlil.private";
    static const uint8_t service_id[] = "mfdt-control";
    static const uint8_t schema_id[] = "ncl1-mfdt-v1";
    ninlil_service_descriptor_t descriptor;
    ninlil_service_identity_t identity;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version,
        &descriptor.struct_size,
        sizeof(descriptor));
    descriptor.namespace_id.data = namespace_id;
    descriptor.namespace_id.length = sizeof(namespace_id) - 1u;
    descriptor.service_id.data = service_id;
    descriptor.service_id.length = sizeof(service_id) - 1u;
    descriptor.schema_id.data = schema_id;
    descriptor.schema_id.length = sizeof(schema_id) - 1u;
    (void)ninlil_mfdt_v1_foundation_carrier_service_identity(&identity);
    descriptor.descriptor_revision = identity.descriptor_revision;
    descriptor.descriptor_digest = identity.descriptor_digest;
    descriptor.schema_major = identity.schema_major;
    descriptor.schema_minor_min = identity.schema_minor;
    descriptor.schema_minor_max = identity.schema_minor;
    descriptor.family = identity.family;
    return descriptor;
}

static void mfdt_party(
    ninlil_party_t *party, const ninlil_id128_t *runtime_id, uint8_t app_seed)
{
    (void)memset(party, 0, sizeof(*party));
    set_header(&party->abi_version, &party->struct_size, sizeof(*party));
    party->runtime_id = *runtime_id;
    set_id(&party->application_instance_id, app_seed);
    set_header(
        &party->local_identity.abi_version,
        &party->local_identity.struct_size,
        sizeof(party->local_identity));
    party->local_identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(
        &party->local_identity.device_id, (uint8_t)(app_seed + 0x10u));
    set_id(
        &party->local_identity.installation_id,
        (uint8_t)(app_seed + 0x20u));
    set_id(
        &party->local_identity.site_domain_id,
        (uint8_t)(app_seed + 0x30u));
    party->local_identity.binding_epoch = 1u;
    party->local_identity.membership_epoch = 1u;
}

static void mfdt_target(
    ninlil_concrete_target_t *target, const ninlil_party_t *party)
{
    (void)memset(target, 0, sizeof(*target));
    set_header(&target->abi_version, &target->struct_size, sizeof(*target));
    target->target_runtime_id = party->runtime_id;
    target->target_application_instance_id = party->application_instance_id;
    target->device_id = party->local_identity.device_id;
    target->installation_id = party->local_identity.installation_id;
    target->site_domain_id = party->local_identity.site_domain_id;
    target->binding_epoch = party->local_identity.binding_epoch;
    target->membership_epoch = party->local_identity.membership_epoch;
    target->flags = party->local_identity.flags;
}

static int mfdt_carrier_init(
    ninlil_mfdt_v1_foundation_carrier_t *carrier,
    runtime_side_t *side,
    ninlil_role_t role,
    const ninlil_party_t *source,
    const ninlil_party_t *peer,
    ninlil_mfdt_v1_session_t *session)
{
    ninlil_mfdt_v1_foundation_carrier_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.bearer = side->fabric_bearer;
    config.clock = side->platform_ops.clock;
    config.tx_gate = &side->tx_gate_ops;
    config.role = role;
    config.source = *source;
    mfdt_target(&config.target, peer);
    config.session = session;
    config.deadline_window_ms =
        NINLIL_MFDT_V1_CARRIER_DEADLINE_MS_DEFAULT;
    if (ninlil_mfdt_v1_foundation_carrier_init(carrier, &config)
            != NINLIL_MFDT_V1_OK
        || ninlil_mfdt_v1_foundation_carrier_open(carrier)
            != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    return 1;
}

static int mfdt_exchange_frame(
    runtime_side_t *sender_side,
    ninlil_mfdt_v1_foundation_carrier_t *sender,
    runtime_side_t *receiver_side,
    ninlil_mfdt_v1_foundation_carrier_t *receiver,
    const uint8_t *frame,
    size_t frame_len,
    uint8_t *received,
    size_t received_cap,
    size_t *received_len)
{
    uint32_t spin;
    int result;

    result = ninlil_mfdt_v1_foundation_carrier_tx(
        sender, frame, frame_len);
    if (result != NINLIL_MFDT_V1_OK) {
        (void)fprintf(
            stderr,
            "mfdt_exchange_frame: tx failed result=%d frame_len=%lu "
            "sender_start=%u sender_queue=%u receiver_queue=%u\n",
            result,
            (unsigned long)frame_len,
            sender_side->link.start_calls,
            sender_side->link.queue_count,
            receiver_side->link.queue_count);
        return 0;
    }
    for (spin = 0u; spin < 128u; ++spin) {
        uint32_t work = 0u;

        if (ninlil_fabric_private_step_v1(
                sender_side->fabric, 64u, &work)
                != NINLIL_FABRIC_PRIVATE_OK
            || ninlil_fabric_private_step_v1(
                receiver_side->fabric, 64u, &work)
                != NINLIL_FABRIC_PRIVATE_OK) {
            (void)fprintf(
                stderr,
                "mfdt_exchange_frame: fabric step failed spin=%u "
                "sender_queue=%u receiver_queue=%u\n",
                spin,
                sender_side->link.queue_count,
                receiver_side->link.queue_count);
            return 0;
        }
        result = ninlil_mfdt_v1_foundation_carrier_rx(
            receiver, received, received_cap, received_len);
        if (result == NINLIL_MFDT_V1_OK) {
            return 1;
        }
        if (result != NINLIL_MFDT_V1_ERR_BUSY) {
            (void)fprintf(
                stderr,
                "mfdt_exchange_frame: rx failed result=%d spin=%u "
                "sender_start=%u receiver_receive=%u sender_queue=%u "
                "receiver_queue=%u\n",
                result,
                spin,
                sender_side->link.start_calls,
                receiver_side->link.receive_calls,
                sender_side->link.queue_count,
                receiver_side->link.queue_count);
            return 0;
        }
    }
    (void)fprintf(
        stderr,
        "mfdt_exchange_frame: timeout sender_start=%u receiver_receive=%u "
        "sender_queue=%u receiver_queue=%u\n",
        sender_side->link.start_calls,
        receiver_side->link.receive_calls,
        sender_side->link.queue_count,
        receiver_side->link.queue_count);
    return 0;
}

static void mfdt_config(
    ninlil_mfdt_v1_config_t *config,
    const ninlil_mfdt_v1_session_t *session,
    const ninlil_time_sample_t *now)
{
    (void)memset(config, 0, sizeof(*config));
    config->policy = NINLIL_MFDT_V1_POLICY_ON;
    config->mfdt_admission_version = session->mfdt_admission_version;
    config->host_mode = 1u;
    config->session_generation = session->session_generation;
    config->mfdt_capability = NINLIL_MFDT_V1_CAP_NCL1_DATA;
    config->retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    config->now_ms = now->now_ms;
    (void)memcpy(
        config->local_clock_epoch.bytes,
        now->clock_epoch_id.bytes,
        sizeof(config->local_clock_epoch.bytes));
}

static int run_mfdt_actual_fabric_e2e(void)
{
    runtime_side_t controller;
    runtime_side_t endpoint;
    ninlil_id128_t controller_runtime_id;
    ninlil_id128_t endpoint_runtime_id;
    ninlil_party_t controller_party;
    ninlil_party_t endpoint_party;
    ninlil_service_descriptor_t descriptor;
    ninlil_time_sample_t controller_now;
    ninlil_time_sample_t endpoint_now;
    ninlil_mfdt_v1_session_t controller_session;
    ninlil_mfdt_v1_session_t endpoint_session;
    ninlil_mfdt_v1_foundation_carrier_t controller_carrier;
    ninlil_mfdt_v1_foundation_carrier_t endpoint_carrier;
    ninlil_mfdt_v1_config_t controller_mfdt_config;
    ninlil_mfdt_v1_config_t endpoint_mfdt_config;
    ninlil_mfdt_v1_engine_t sender_engine;
    ninlil_mfdt_v1_engine_t receiver_engine;
    ninlil_mfdt_v1_workspace_t sender_workspace;
    ninlil_mfdt_v1_workspace_t receiver_workspace;
    ninlil_mfdt_v1_lab_store_t sender_store;
    ninlil_mfdt_v1_lab_store_t receiver_store;
    ninlil_mfdt_v1_pipeline_t sender_pipeline;
    ninlil_mfdt_v1_pipeline_t receiver_pipeline;
    ninlil_mfdt_v1_bearer_worker_t sender_worker;
    ninlil_mfdt_v1_bearer_worker_t receiver_worker;
    mfdt_upper_fixture_t upper;
    uint8_t controller_nonce[16];
    uint8_t endpoint_nonce[16];
    uint8_t transfer_id[16];
    uint8_t offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t received[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    uint8_t content[4096];
    ninlil_bearer_message_t carrier_probe;
    size_t offer_len = 0u;
    size_t accept_len = 0u;
    size_t received_len = 0u;
    uint32_t step;
    uint32_t index;
    int complete = 0;

    set_id(&controller_runtime_id, 0x11u);
    set_id(&endpoint_runtime_id, 0x31u);
    REQUIRE(side_init(
        &controller,
        NINLIL_ROLE_CONTROLLER,
        &endpoint_runtime_id,
        NULL));
    REQUIRE(side_init(
        &endpoint,
        NINLIL_ROLE_ENDPOINT,
        &controller_runtime_id,
        NULL));
    controller.link.peer = &endpoint.link;
    endpoint.link.peer = &controller.link;
    mfdt_party(
        &controller_party, &controller_runtime_id, 0xC1u);
    mfdt_party(&endpoint_party, &endpoint_runtime_id, 0xD1u);
    REQUIRE(ninlil_test_clock_advance(
        (ninlil_test_clock_t *)controller.platform_ops.clock->user,
        1000u));
    REQUIRE(ninlil_test_clock_advance(
        (ninlil_test_clock_t *)endpoint.platform_ops.clock->user,
        1000u));

    (void)memset(&controller_now, 0, sizeof(controller_now));
    set_header(
        &controller_now.abi_version,
        &controller_now.struct_size,
        sizeof(controller_now));
    REQUIRE(
        controller.platform_ops.clock->now(
            controller.platform_ops.clock->user, &controller_now)
        == NINLIL_PORT_OK);
    (void)memset(&endpoint_now, 0, sizeof(endpoint_now));
    set_header(
        &endpoint_now.abi_version,
        &endpoint_now.struct_size,
        sizeof(endpoint_now));
    REQUIRE(
        endpoint.platform_ops.clock->now(
            endpoint.platform_ops.clock->user, &endpoint_now)
        == NINLIL_PORT_OK);

    descriptor = mfdt_carrier_descriptor();
    REQUIRE(install_forward_policy(
        &controller,
        &descriptor,
        &endpoint_runtime_id,
        &endpoint_party.application_instance_id,
        &controller_now));
    REQUIRE(install_additional_forward_authority(
        &controller,
        &descriptor,
        &controller_runtime_id,
        &controller_party.application_instance_id,
        &controller_now,
        0xA2u));
    REQUIRE(install_forward_policy(
        &endpoint,
        &descriptor,
        &endpoint_runtime_id,
        &endpoint_party.application_instance_id,
        &endpoint_now));
    REQUIRE(install_additional_forward_authority(
        &endpoint,
        &descriptor,
        &controller_runtime_id,
        &controller_party.application_instance_id,
        &endpoint_now,
        0xA2u));

    ninlil_mfdt_v1_session_init(
        &controller_session, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_session_init(
        &endpoint_session, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    REQUIRE(
        ninlil_mfdt_v1_session_bind(
            &controller_session,
            2u,
            7u,
            UINT64_C(0x1122334455667788),
            1u,
            controller_runtime_id.bytes,
            endpoint_runtime_id.bytes)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(
        ninlil_mfdt_v1_session_bind(
            &endpoint_session,
            2u,
            7u,
            UINT64_C(0x1122334455667788),
            1u,
            endpoint_runtime_id.bytes,
            controller_runtime_id.bytes)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(mfdt_carrier_init(
        &controller_carrier,
        &controller,
        NINLIL_ROLE_CONTROLLER,
        &controller_party,
        &endpoint_party,
        &controller_session));
    REQUIRE(mfdt_carrier_init(
        &endpoint_carrier,
        &endpoint,
        NINLIL_ROLE_ENDPOINT,
        &endpoint_party,
        &controller_party,
        &endpoint_session));

    for (index = 0u; index < sizeof(controller_nonce); ++index) {
        controller_nonce[index] = (uint8_t)(0x41u + index);
        endpoint_nonce[index] = (uint8_t)(0x81u + index);
    }
    REQUIRE(
        ninlil_mfdt_v1_session_build_offer(
            &controller_session,
            0x10203040u,
            controller_nonce,
            offer,
            sizeof(offer),
            &offer_len)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(
        ninlil_mfdt_v1_foundation_carrier_build_message(
            &controller_carrier,
            offer,
            offer_len,
            &controller_now,
            &carrier_probe)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(
        ninlil_mfdt_v1_foundation_carrier_accept_message(
            &endpoint_carrier,
            &carrier_probe,
            received,
            sizeof(received),
            &received_len)
        == NINLIL_MFDT_V1_OK);
    carrier_probe.transaction_id.bytes[0] ^= 0x80u;
    REQUIRE(
        ninlil_mfdt_v1_foundation_carrier_accept_message(
            &endpoint_carrier,
            &carrier_probe,
            received,
            sizeof(received),
            &received_len)
        == NINLIL_MFDT_V1_ERR_CORRUPT);
    carrier_probe.transaction_id.bytes[0] ^= 0x80u;
    carrier_probe.attempt_id.bytes[0] ^= 0x80u;
    REQUIRE(
        ninlil_mfdt_v1_foundation_carrier_accept_message(
            &endpoint_carrier,
            &carrier_probe,
            received,
            sizeof(received),
            &received_len)
        == NINLIL_MFDT_V1_ERR_CORRUPT);
    carrier_probe.attempt_id.bytes[0] ^= 0x80u;
    REQUIRE(mfdt_exchange_frame(
        &controller,
        &controller_carrier,
        &endpoint,
        &endpoint_carrier,
        offer,
        offer_len,
        received,
        sizeof(received),
        &received_len));
    REQUIRE(
        ninlil_mfdt_v1_session_on_offer(
            &endpoint_session,
            received,
            received_len,
            endpoint_nonce,
            accept,
            sizeof(accept),
            &accept_len)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(mfdt_exchange_frame(
        &endpoint,
        &endpoint_carrier,
        &controller,
        &controller_carrier,
        accept,
        accept_len,
        received,
        sizeof(received),
        &received_len));
    REQUIRE(
        ninlil_mfdt_v1_session_on_accept(
            &controller_session, received, received_len)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(
        ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&controller_session));
    REQUIRE(
        ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&endpoint_session));

    mfdt_config(
        &controller_mfdt_config, &controller_session, &controller_now);
    mfdt_config(&endpoint_mfdt_config, &endpoint_session, &endpoint_now);
    ninlil_mfdt_v1_lab_store_init(&sender_store);
    ninlil_mfdt_v1_lab_store_init(&receiver_store);
    REQUIRE(
        ninlil_mfdt_v1_engine_init(
            &sender_engine,
            &sender_workspace,
            &sender_store,
            &controller_mfdt_config)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(
        ninlil_mfdt_v1_engine_init(
            &receiver_engine,
            &receiver_workspace,
            &receiver_store,
            &endpoint_mfdt_config)
        == NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_pipeline_init(
        &sender_pipeline,
        &sender_engine,
        NULL,
        NULL,
        NULL,
        controller_session.session_generation,
        controller_session.session_cookie);
    ninlil_mfdt_v1_pipeline_init(
        &receiver_pipeline,
        NULL,
        &receiver_engine,
        NULL,
        NULL,
        endpoint_session.session_generation,
        endpoint_session.session_cookie);
    (void)memset(&upper, 0, sizeof(upper));
    for (index = 0u; index < sizeof(content); ++index) {
        content[index] =
            (uint8_t)((index * UINT32_C(37) + UINT32_C(11)) & UINT32_C(0xff));
    }
    upper.expected = content;
    upper.expected_len = sizeof(content);
    REQUIRE(
        ninlil_mfdt_v1_bearer_worker_init(
            &sender_worker,
            &sender_pipeline,
            ninlil_mfdt_v1_foundation_carrier_tx,
            ninlil_mfdt_v1_foundation_carrier_rx,
            ninlil_mfdt_v1_foundation_carrier_now,
            &controller_carrier,
            NULL,
            NULL,
            4u)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(
        ninlil_mfdt_v1_bearer_worker_init(
            &receiver_worker,
            &receiver_pipeline,
            ninlil_mfdt_v1_foundation_carrier_tx,
            ninlil_mfdt_v1_foundation_carrier_rx,
            ninlil_mfdt_v1_foundation_carrier_now,
            &endpoint_carrier,
            mfdt_upper_prepare,
            &upper,
            4u)
        == NINLIL_MFDT_V1_OK);
    for (index = 0u; index < sizeof(transfer_id); ++index) {
        transfer_id[index] = (uint8_t)(0x55u + index);
    }
    REQUIRE(
        ninlil_mfdt_v1_pipeline_sender_begin(
            &sender_pipeline,
            transfer_id,
            content,
            sizeof(content))
        == NINLIL_MFDT_V1_OK);

    for (step = 0u; step < 2048u; ++step) {
        uint32_t work = 0u;
        int sender_result;
        int receiver_result;

        sender_result =
            ninlil_mfdt_v1_bearer_worker_step(&sender_worker);
        REQUIRE(
            sender_result == NINLIL_MFDT_V1_OK
            || sender_result == NINLIL_MFDT_V1_ERR_BUSY);
        REQUIRE(
            ninlil_fabric_private_step_v1(
                controller.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        REQUIRE(
            ninlil_fabric_private_step_v1(endpoint.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        receiver_result =
            ninlil_mfdt_v1_bearer_worker_step(&receiver_worker);
        if (receiver_result != NINLIL_MFDT_V1_OK
            && receiver_result != NINLIL_MFDT_V1_ERR_BUSY) {
            (void)fprintf(
                stderr,
                "mfdt actual Fabric receiver failed result=%d step=%u "
                "sender_phase=%u sender_out=%u receiver_out=%u "
                "sender_queue=%u receiver_queue=%u\n",
                receiver_result,
                step,
                (unsigned)sender_pipeline.phase,
                (unsigned)sender_pipeline.outbox_valid,
                (unsigned)receiver_pipeline.outbox_valid,
                controller.link.queue_count,
                endpoint.link.queue_count);
        }
        REQUIRE(
            receiver_result == NINLIL_MFDT_V1_OK
            || receiver_result == NINLIL_MFDT_V1_ERR_BUSY);
        REQUIRE(
            ninlil_fabric_private_step_v1(endpoint.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        REQUIRE(
            ninlil_fabric_private_step_v1(
                controller.fabric, 64u, &work)
            == NINLIL_FABRIC_PRIVATE_OK);
        if (sender_pipeline.complete != 0u
            && receiver_engine.handoff_complete != 0u) {
            complete = 1;
            break;
        }
    }
    REQUIRE(complete != 0);
    REQUIRE(upper.effect_count == 1u);
    REQUIRE(upper.prepare_calls == 1u);
    REQUIRE(controller.link.start_calls > 2u);
    REQUIRE(endpoint.link.start_calls > 2u);
    REQUIRE(
        ninlil_mfdt_v1_pipeline_finish_terminal(&sender_pipeline)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(
        ninlil_mfdt_v1_pipeline_finish_terminal(&receiver_pipeline)
        == NINLIL_MFDT_V1_OK);

    ninlil_mfdt_v1_foundation_carrier_close(&endpoint_carrier);
    ninlil_mfdt_v1_foundation_carrier_close(&controller_carrier);
    REQUIRE(side_close(&endpoint));
    REQUIRE(side_close(&controller));
    return 0;
}
#endif

int main(void)
{
    int result = run_actual_e2e();
    if (result == 0) {
        result = run_multi_service_actual_e2e();
    }
#if defined(NINLIL_MFDT_V1_PRIVATE)
    if (result == 0) {
        result = run_mfdt_actual_fabric_e2e();
    }
#endif
    if (result == 0) {
        (void)printf("runtime_fabric_actual_e2e_test: PASS\n");
    }
    return result;
}
