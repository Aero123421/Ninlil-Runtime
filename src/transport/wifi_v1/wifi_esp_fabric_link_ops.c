/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_esp_fabric_link_ops.h"

#include "wifi_nwb1.h"

#include <ninlil/version.h>

#include <stdint.h>
#include <string.h>

enum {
    ESP_LINK_TOKEN_TAG = 0x5bu,
    ESP_LINK_RX_TOKEN_TAG = 0x6du,
    ESP_LINK_PROVIDER_MAGIC = 0x57455031u /* WEP1 */
};

static ninlil_wifi_esp_fabric_link_user_t *provider_user(
    void *opaque,
    uint32_t *out_authority_phase)
{
    ninlil_wifi_fabric_call_scope_v1_t *scope;
    ninlil_wifi_esp_fabric_link_user_t *user;
    if (out_authority_phase != NULL) {
        *out_authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    }
    if (opaque == NULL) {
        return NULL;
    }
    scope = (ninlil_wifi_fabric_call_scope_v1_t *)opaque;
    if (scope->magic == NINLIL_WIFI_FABRIC_CALL_SCOPE_MAGIC) {
        if (!ninlil_wifi_fabric_call_scope_valid(scope)) {
            return NULL;
        }
        user = (ninlil_wifi_esp_fabric_link_user_t *)scope->provider_user;
        if (user == NULL || user->provider_magic != ESP_LINK_PROVIDER_MAGIC) {
            return NULL;
        }
        if (out_authority_phase != NULL) {
            *out_authority_phase = scope->authority->phase;
        }
        return user;
    }
    /* Explicit low-level test seam; adapter-created ops are always scoped. */
    user = (ninlil_wifi_esp_fabric_link_user_t *)opaque;
    if (user->provider_magic != ESP_LINK_PROVIDER_MAGIC
        || user->durable_outer_permit_authority == 0u) {
        return NULL;
    }
    if (out_authority_phase != NULL) {
        *out_authority_phase = NINLIL_WIFI_FABRIC_CALL_ACTIVE;
    }
    return user;
}

static int phase_allows_open(uint32_t phase)
{
    return phase == NINLIL_WIFI_FABRIC_CALL_PREPARED
        || phase == NINLIL_WIFI_FABRIC_CALL_ACTIVE;
}

static int phase_allows_new_io(uint32_t phase)
{
    return phase == NINLIL_WIFI_FABRIC_CALL_ACTIVE;
}

static int bytes_zero(const uint8_t *p, size_t n)
{
    size_t i;
    if (p == NULL) {
        return 1;
    }
    for (i = 0u; i < n; ++i) {
        if (p[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static ninlil_fabric_link_status_t map_status(ninlil_wifi_status_t status)
{
    if (status == NINLIL_WIFI_OK) {
        return NINLIL_FABRIC_LINK_OK;
    }
    if (status == NINLIL_WIFI_WOULD_BLOCK
        || status == NINLIL_WIFI_BACKPRESSURE
        || status == NINLIL_WIFI_CAPACITY) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (status == NINLIL_WIFI_DENIED
        || status == NINLIL_WIFI_CREDENTIAL
        || status == NINLIL_WIFI_INVALID_STATE
        || status == NINLIL_WIFI_INVALID_ARGUMENT) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (status == NINLIL_WIFI_CORRUPT) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (status == NINLIL_WIFI_CLOSED || status == NINLIL_WIFI_FENCED
        || status == NINLIL_WIFI_UNAVAILABLE) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
}

static ninlil_fabric_packet_link_handle_t make_handle(uint32_t generation)
{
    return (ninlil_fabric_packet_link_handle_t)(uintptr_t)generation;
}

static int handle_matches(
    const ninlil_wifi_esp_fabric_link_user_t *user,
    ninlil_fabric_packet_link_handle_t handle,
    int permit_closed)
{
    if (user == NULL || handle == NULL) {
        return 0;
    }
    if (user->open
        && (uintptr_t)handle == (uintptr_t)user->open_generation) {
        return 1;
    }
    return permit_closed && !user->open && user->closed_generation != 0u
        && (uintptr_t)handle == (uintptr_t)user->closed_generation;
}

static ninlil_fabric_packet_token_t make_send_token(uint32_t generation)
{
    uintptr_t value = ((uintptr_t)generation << 8)
        | (uintptr_t)ESP_LINK_TOKEN_TAG;
    return (ninlil_fabric_packet_token_t)value;
}

static int send_token_matches(
    const ninlil_wifi_esp_fabric_link_user_t *user,
    ninlil_fabric_packet_token_t token)
{
    uintptr_t value;
    if (user == NULL || token == NULL || !user->send_in_use) {
        return 0;
    }
    value = (uintptr_t)token;
    return (value & 0xffu) == ESP_LINK_TOKEN_TAG
        && (uint32_t)(value >> 8) == user->send_generation;
}

static void *make_rx_token(uint32_t generation)
{
    return (void *)(((uintptr_t)generation << 8)
        | (uintptr_t)ESP_LINK_RX_TOKEN_TAG);
}

static int rx_token_matches(
    const ninlil_wifi_esp_fabric_link_user_t *user,
    const void *token)
{
    uintptr_t value;
    if (user == NULL || token == NULL || !user->rx_loan_active) {
        return 0;
    }
    value = (uintptr_t)token;
    return (value & 0xffu) == ESP_LINK_RX_TOKEN_TAG
        && (uint32_t)(value >> 8) == user->rx_generation;
}

ninlil_wifi_status_t ninlil_wifi_esp_fabric_bind_trusted_clock(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const ninlil_time_sample_t *sample)
{
    if (user == NULL || sample == NULL
        || sample->abi_version != NINLIL_ABI_VERSION
        || sample->struct_size != (uint16_t)sizeof(*sample)
        || sample->trust != NINLIL_CLOCK_TRUSTED
        || sample->reserved_zero != 0u
        || bytes_zero(sample->clock_epoch_id.bytes, 16u)) {
        return NINLIL_WIFI_DENIED;
    }
    if (user->permit_clock_epoch_set
        && (memcmp(
                user->permit_clock_epoch_id,
                sample->clock_epoch_id.bytes,
                16u)
                != 0
            || sample->now_ms < user->permit_now_ms)) {
        return NINLIL_WIFI_DENIED;
    }
    user->permit_now_ms = sample->now_ms;
    (void)memcpy(
        user->permit_clock_epoch_id, sample->clock_epoch_id.bytes, 16u);
    user->permit_clock_epoch_set = 1u;
    return NINLIL_WIFI_OK;
}

static ninlil_fabric_link_status_t link_open(
    void *opaque,
    ninlil_fabric_packet_link_handle_t *out_handle)
{
    uint32_t authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, &authority_phase);
    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    if (user == NULL || !phase_allows_open(authority_phase)
        || user->owner == NULL || out_handle == NULL
        || user->open || user->send_in_use
        || user->owner->phase != NINLIL_WIFI_PHASE_ATTACHED
        || user->owner->availability_epoch == 0u
        || user->owner->availability_epoch_exhausted
        || user->open_generation == UINT32_MAX
        || (uintptr_t)(user->open_generation + 1u) == 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    user->open_generation += 1u;
    if (user->open_generation == 0u) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    user->closed_generation = 0u;
    user->availability_epoch_seen = user->owner->availability_epoch;
    user->open = 1u;
    *out_handle = make_handle(user->open_generation);
    return NINLIL_FABRIC_LINK_OK;
}

static void mark_send_terminal(
    ninlil_wifi_esp_fabric_link_user_t *user,
    uint32_t completion)
{
    if (user == NULL || !user->send_in_use) {
        return;
    }
    user->send_terminal = 1u;
    user->send_completion_kind = completion;
    user->permit_retired = 1u;
}

static void link_close(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle)
{
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, NULL);
    if (user == NULL || (handle != NULL
            && !handle_matches(user, handle, 0))) {
        return;
    }
    if (user->send_in_use && !user->send_terminal) {
        (void)ninlil_wifi_esp_owner_cancel_tx_sequence(
            user->owner, user->send_sequence);
        user->send_cancelled = 1u;
        mark_send_terminal(
            user, NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE);
    }
    user->rx_loan_active = 0u;
    user->closed_generation = user->open_generation;
    user->open = 0u;
}

static ninlil_fabric_link_status_t validate_permit(
    const ninlil_wifi_esp_fabric_link_user_t *user,
    const ninlil_fabric_packet_view_v1_t *packet)
{
    const ninlil_tx_permit_t *permit;
    if (user == NULL || packet == NULL || packet->permit == NULL
        || user->durable_outer_permit_authority == 0u
        || user->permit_clock_epoch_set == 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    permit = packet->permit;
    if (permit->abi_version != NINLIL_ABI_VERSION
        || permit->struct_size != (uint16_t)sizeof(*permit)
        || bytes_zero(permit->permit_id.bytes, 16u)
        || permit->expires_at_ms == 0u
        || user->permit_now_ms >= permit->expires_at_ms
        || memcmp(
               permit->clock_epoch_id.bytes,
               user->permit_clock_epoch_id,
               16u)
            != 0
        || (!bytes_zero(packet->attempt_id.bytes, 16u)
            && memcmp(
                   permit->attempt_id.bytes, packet->attempt_id.bytes, 16u)
                != 0)
        || (user->send_in_use
            && memcmp(user->permit_id, permit->permit_id.bytes, 16u) == 0)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t link_start_send(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    uint32_t authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, &authority_phase);
    ninlil_fabric_link_status_t status;
    ninlil_wifi_status_t wifi_status;
    uint32_t sequence;
    if (out_token != NULL) {
        *out_token = NULL;
    }
    if (user == NULL || !phase_allows_new_io(authority_phase)
        || !handle_matches(user, handle, 0)
        || packet == NULL || packet->bytes == NULL || out_token == NULL
        || packet->api_version != 1u
        || packet->struct_size != (uint16_t)sizeof(*packet)
        || packet->reserved_zero != 0u
        || packet->length > NINLIL_WIFI_NWB1_PAYLOAD_MAX) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    status = validate_permit(user, packet);
    if (status != NINLIL_FABRIC_LINK_OK) {
        return status;
    }
    if (user->send_in_use || user->owner->tx_count != 0u
        || user->owner->tx_partial_len != 0u) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (user->owner->availability_epoch != user->availability_epoch_seen
        || user->owner->phase != NINLIL_WIFI_PHASE_ATTACHED
        || user->send_generation == UINT32_MAX
        || user->send_generation >= (uint32_t)(UINTPTR_MAX >> 8)) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    sequence = user->owner->next_tx_sequence;
    wifi_status = ninlil_wifi_esp_owner_send_payload(
        user->owner, packet->bytes, packet->length);
    if (wifi_status != NINLIL_WIFI_OK) {
        return map_status(wifi_status);
    }
    user->send_generation += 1u;
    if (user->send_generation == 0u) {
        ninlil_wifi_esp_owner_fence(user->owner);
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    user->send_in_use = 1u;
    user->send_terminal = 0u;
    user->send_cancelled = 0u;
    user->permit_retired = 0u;
    user->send_sequence = sequence;
    user->send_completion_kind =
        NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    (void)memcpy(user->permit_id, packet->permit->permit_id.bytes, 16u);
    *out_token = make_send_token(user->send_generation);
    return NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_link_status_t link_poll_send(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, NULL);
    ninlil_wifi_status_t status;
    uint32_t work = 0u;
    if (out_completion != NULL) {
        (void)memset(out_completion, 0, sizeof(*out_completion));
    }
    if (user == NULL || out_completion == NULL
        || !handle_matches(user, handle, 1)
        || !send_token_matches(user, token)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    out_completion->api_version = 1u;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    if (user->send_terminal) {
        out_completion->kind = user->send_completion_kind;
        return NINLIL_FABRIC_LINK_OK;
    }
    if (ninlil_wifi_esp_owner_tx_sequence_completed(
            user->owner, user->send_sequence)) {
        mark_send_terminal(
            user, NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
        out_completion->kind = user->send_completion_kind;
        return NINLIL_FABRIC_LINK_OK;
    }
    if (user->owner->availability_epoch != user->availability_epoch_seen) {
        mark_send_terminal(
            user, NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN);
        out_completion->kind = user->send_completion_kind;
        return NINLIL_FABRIC_LINK_OK;
    }
    status = ninlil_wifi_esp_owner_step(user->owner, 1u, &work);
    if (ninlil_wifi_esp_owner_tx_sequence_completed(
            user->owner, user->send_sequence)) {
        mark_send_terminal(
            user, NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE);
    } else if (status != NINLIL_WIFI_OK
        && status != NINLIL_WIFI_WOULD_BLOCK
        && status != NINLIL_WIFI_BACKPRESSURE) {
        mark_send_terminal(
            user, NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN);
    }
    out_completion->kind = user->send_terminal
        ? user->send_completion_kind
        : NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t link_cancel_send(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, NULL);
    if (user == NULL || !handle_matches(user, handle, 0)
        || !send_token_matches(user, token)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (!user->send_terminal) {
        (void)ninlil_wifi_esp_owner_cancel_tx_sequence(
            user->owner, user->send_sequence);
        user->send_cancelled = 1u;
        mark_send_terminal(
            user, NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE);
    }
    return NINLIL_FABRIC_LINK_OK;
}

static void link_release_send(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, NULL);
    if (user == NULL || !handle_matches(user, handle, 1)
        || !send_token_matches(user, token) || !user->send_terminal
        || !user->permit_retired
        || user->durable_outer_permit_authority == 0u) {
        return;
    }
    user->send_in_use = 0u;
    user->send_terminal = 0u;
    user->send_cancelled = 0u;
    user->permit_retired = 0u;
    user->send_sequence = 0u;
    user->send_completion_kind = 0u;
    (void)memset(user->permit_id, 0, sizeof(user->permit_id));
    if (!user->open) {
        user->closed_generation = 0u;
    }
}

static ninlil_fabric_link_status_t link_receive_next(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    uint32_t authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, &authority_phase);
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0u;
    uint32_t sequence = 0u;
    uint32_t work = 0u;
    size_t record_len = 0u;
    ninlil_wifi_status_t status;
    if (out_bytes != NULL) {
        *out_bytes = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    if (user == NULL || !phase_allows_new_io(authority_phase)
        || !handle_matches(user, handle, 0)
        || out_bytes == NULL || out_length == NULL
        || out_receive_token == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (user->rx_loan_active) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (user->owner->availability_epoch != user->availability_epoch_seen) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    status = ninlil_wifi_esp_owner_step(user->owner, 1u, &work);
    if (status != NINLIL_WIFI_OK && status != NINLIL_WIFI_WOULD_BLOCK
        && status != NINLIL_WIFI_BACKPRESSURE) {
        return map_status(status);
    }
    status = ninlil_wifi_esp_owner_recv_record(
        user->owner,
        user->rx_record,
        sizeof(user->rx_record),
        &record_len,
        &sequence);
    if (status == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_FABRIC_LINK_EMPTY;
    }
    if (status != NINLIL_WIFI_OK) {
        return map_status(status);
    }
    status = ninlil_wifi_nwb1_classify(
        user->rx_record,
        record_len,
        user->owner->ids.attached_session_id,
        0,
        0u,
        &payload,
        &payload_len,
        &sequence);
    if (status != NINLIL_WIFI_OK || payload == NULL || payload_len == 0u) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (payload != user->rx_record) {
        (void)memmove(user->rx_record, payload, payload_len);
    }
    if (user->rx_generation == UINT32_MAX
        || user->rx_generation >= (uint32_t)(UINTPTR_MAX >> 8)) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    user->rx_generation += 1u;
    user->rx_record_len = payload_len;
    user->rx_loan_active = 1u;
    *out_bytes = user->rx_record;
    *out_length = payload_len;
    *out_receive_token = make_rx_token(user->rx_generation);
    return NINLIL_FABRIC_LINK_OK;
}

static void link_release_received(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, NULL);
    if (user == NULL || !handle_matches(user, handle, 0)
        || !rx_token_matches(user, receive_token)) {
        return;
    }
    user->rx_loan_active = 0u;
    user->rx_record_len = 0u;
}

static ninlil_fabric_link_status_t link_state(
    void *opaque,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    ninlil_wifi_esp_fabric_link_user_t *user =
        provider_user(opaque, NULL);
    if (out_state != NULL) {
        (void)memset(out_state, 0, sizeof(*out_state));
    }
    if (user == NULL || user->owner == NULL || out_state == NULL
        || (handle != NULL && !handle_matches(user, handle, 1))) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    out_state->api_version = 1u;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->availability_epoch = user->owner->availability_epoch;
    (void)memcpy(
        out_state->availability_clock_epoch_id.bytes,
        user->permit_clock_epoch_id,
        16u);
    out_state->available_until_ms = UINT64_MAX;
    out_state->available = user->open
        && user->owner->phase == NINLIL_WIFI_PHASE_ATTACHED
        && !user->owner->availability_epoch_exhausted
        && user->owner->availability_epoch == user->availability_epoch_seen;
    return NINLIL_FABRIC_LINK_OK;
}

static void packet_link_ops_fill(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    void *ops_user)
{
    if (ops == NULL) {
        return;
    }
    (void)memset(ops, 0, sizeof(*ops));
    ops->api_version = 1u;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = ops_user;
    ops->open = link_open;
    ops->close = link_close;
    ops->start_send = link_start_send;
    ops->poll_send = link_poll_send;
    ops->cancel_send = link_cancel_send;
    ops->release_send = link_release_send;
    ops->receive_next = link_receive_next;
    ops->release_received = link_release_received;
    ops->state = link_state;
}

void ninlil_wifi_esp_fabric_packet_link_ops_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_esp_fabric_link_user_t *user,
    ninlil_wifi_esp_owner_t *owner)
{
    if (user == NULL) {
        packet_link_ops_fill(ops, NULL);
        return;
    }
    (void)memset(user, 0, sizeof(*user));
    user->provider_magic = ESP_LINK_PROVIDER_MAGIC;
    user->owner = owner;
    ninlil_wifi_fabric_call_authority_init(&user->call_authority);
    packet_link_ops_fill(ops, user);
}

void ninlil_wifi_esp_fabric_packet_link_ops_scoped_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_esp_fabric_link_user_t *user,
    ninlil_wifi_fabric_call_scope_v1_t *scope,
    const void *fabric_cookie)
{
    if (user == NULL || scope == NULL
        || user->provider_magic != ESP_LINK_PROVIDER_MAGIC) {
        packet_link_ops_fill(ops, NULL);
        return;
    }
    ninlil_wifi_fabric_call_scope_init(
        scope, user, &user->call_authority, fabric_cookie);
    packet_link_ops_fill(ops, scope);
}

int ninlil_wifi_esp_fabric_packet_link_authority_prepare(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    if (user == NULL || user->provider_magic != ESP_LINK_PROVIDER_MAGIC
        || !ninlil_wifi_fabric_call_authority_prepare(
            &user->call_authority, fabric_cookie)) {
        return 0;
    }
    user->durable_outer_permit_authority = 1u;
    return 1;
}

int ninlil_wifi_esp_fabric_packet_link_authority_activate(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    return user != NULL && user->provider_magic == ESP_LINK_PROVIDER_MAGIC
        && ninlil_wifi_fabric_call_authority_activate(
            &user->call_authority, fabric_cookie);
}

int ninlil_wifi_esp_fabric_packet_link_authority_drain(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    return user != NULL && user->provider_magic == ESP_LINK_PROVIDER_MAGIC
        && ninlil_wifi_fabric_call_authority_drain(
            &user->call_authority, fabric_cookie);
}

int ninlil_wifi_esp_fabric_packet_link_authority_unbind(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    if (user == NULL || user->provider_magic != ESP_LINK_PROVIDER_MAGIC
        || !ninlil_wifi_fabric_call_authority_unbind(
            &user->call_authority, fabric_cookie)) {
        return 0;
    }
    user->durable_outer_permit_authority = 0u;
    return 1;
}
