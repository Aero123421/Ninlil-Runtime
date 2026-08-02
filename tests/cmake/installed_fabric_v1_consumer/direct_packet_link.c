#include "direct_packet_link.h"

#include <stdint.h>
#include <string.h>

static void set_header(uint16_t *version, uint16_t *size, size_t value_size)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value_size;
}

static int id_zero(const ninlil_id128_t *id)
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
    return memcmp(left->bytes, right->bytes, 16u) == 0;
}

static int permit_seen(
    const installed_pair_link_t *link, const uint8_t permit_id[16])
{
    uint32_t index;
    for (index = 0u; index < link->permit_count; ++index) {
        if (memcmp(link->consumed_permits[index], permit_id, 16u) == 0) {
            return 1;
        }
    }
    return 0;
}

static int permit_valid(
    const installed_pair_link_t *link,
    const ninlil_fabric_packet_view_v1_t *packet)
{
    ninlil_time_sample_t now;
    const ninlil_tx_permit_t *permit;

    if (link == NULL || packet == NULL || link->clock == NULL
        || link->clock->now == NULL) {
        return 0;
    }
    permit = packet->permit;
    if (permit == NULL || permit->abi_version != NINLIL_ABI_VERSION
        || permit->struct_size != (uint16_t)sizeof(*permit)
        || id_zero(&permit->permit_id)
        || !id_equal(&permit->attempt_id, &packet->attempt_id)
        || permit_seen(link, permit->permit_id.bytes)) {
        return 0;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    return link->clock->now(link->clock->user, &now) == NINLIL_PORT_OK
        && now.trust == NINLIL_CLOCK_TRUSTED
        && id_equal(&permit->clock_epoch_id, &now.clock_epoch_id)
        && permit->expires_at_ms != 0u && now.now_ms < permit->expires_at_ms;
}

static ninlil_fabric_link_status_t link_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    if (link == NULL || out_handle == NULL || link->open != 0u) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    link->open = 1u;
    *out_handle = link;
    return NINLIL_FABRIC_LINK_OK;
}

static void link_close(void *user, ninlil_fabric_packet_link_handle_t handle)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    if (link != NULL && handle == link) {
        link->open = 0u;
    }
}

static installed_pair_token_t *find_token(
    installed_pair_link_t *link, ninlil_fabric_packet_token_t token)
{
    const uint32_t generation = (uint32_t)(uintptr_t)token;
    uint32_t index;
    for (index = 0u; index < INSTALLED_PAIR_TOKEN_CAPACITY; ++index) {
        if (link->tokens[index].used != 0u
            && link->tokens[index].generation == generation) {
            return &link->tokens[index];
        }
    }
    return NULL;
}

static ninlil_fabric_link_status_t link_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    installed_pair_token_t *token_slot = NULL;
    installed_pair_frame_t *frame;
    uint32_t index;
    uint32_t queue_index;

    if (out_token != NULL) {
        *out_token = NULL;
    }
    if (link == NULL || handle != link || packet == NULL || out_token == NULL
        || link->open == 0u || link->peer == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (link->available == 0u || link->peer->available == 0u
        || link->peer->open == 0u) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (packet->bytes == NULL || packet->length == 0u
        || packet->length > INSTALLED_PAIR_PACKET_MAX
        || !permit_valid(link, packet)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (link->peer->queue_count >= INSTALLED_PAIR_QUEUE_CAPACITY
        || link->permit_count >= INSTALLED_PAIR_PERMIT_CAPACITY) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    for (index = 0u; index < INSTALLED_PAIR_TOKEN_CAPACITY; ++index) {
        if (link->tokens[index].used == 0u) {
            token_slot = &link->tokens[index];
            break;
        }
    }
    if (token_slot == NULL || link->next_generation == UINT32_MAX) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }

    link->next_generation += 1u;
    queue_index = (link->peer->queue_head + link->peer->queue_count)
        % INSTALLED_PAIR_QUEUE_CAPACITY;
    frame = &link->peer->queue[queue_index];
    (void)memset(frame, 0, sizeof(*frame));
    frame->used = 1u;
    frame->length = packet->length;
    (void)memcpy(frame->bytes, packet->bytes, packet->length);
    link->peer->queue_count += 1u;

    (void)memset(token_slot, 0, sizeof(*token_slot));
    token_slot->used = 1u;
    token_slot->generation = link->next_generation;
    (void)memcpy(
        link->consumed_permits[link->permit_count],
        packet->permit->permit_id.bytes,
        16u);
    link->permit_count += 1u;
    link->start_calls += 1u;
    link->accepted_packets += 1u;
    *out_token = (void *)(uintptr_t)token_slot->generation;
    return NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_link_status_t link_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    installed_pair_token_t *slot;
    if (link == NULL || handle != link || out_completion == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot = find_token(link, token);
    if (slot == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(out_completion, 0, sizeof(*out_completion));
    out_completion->api_version = NINLIL_FABRIC_API_VERSION;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    slot->terminal = 1u;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t link_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    installed_pair_token_t *slot;
    if (link == NULL || handle != link) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot = find_token(link, token);
    if (slot == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot->terminal = 1u;
    return NINLIL_FABRIC_LINK_OK;
}

static void link_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    installed_pair_token_t *slot;
    if (link == NULL || handle != link) {
        return;
    }
    slot = find_token(link, token);
    if (slot != NULL && slot->terminal != 0u) {
        (void)memset(slot, 0, sizeof(*slot));
    }
}

static ninlil_fabric_link_status_t link_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    installed_pair_frame_t *frame;
    if (out_bytes != NULL) {
        *out_bytes = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    if (link == NULL || handle != link || out_bytes == NULL
        || out_length == NULL || out_receive_token == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (link->queue_count == 0u) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    frame = &link->queue[link->queue_head];
    if (frame->used == 0u || frame->loaned != 0u || frame->length == 0u) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    frame->loaned = 1u;
    *out_bytes = frame->bytes;
    *out_length = frame->length;
    *out_receive_token = frame;
    return NINLIL_FABRIC_LINK_OK;
}

static void link_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    installed_pair_frame_t *frame = (installed_pair_frame_t *)receive_token;
    if (link == NULL || handle != link || frame == NULL
        || link->queue_count == 0u
        || frame != &link->queue[link->queue_head]
        || frame->loaned == 0u) {
        return;
    }
    (void)memset(frame, 0, sizeof(*frame));
    link->queue_head =
        (link->queue_head + 1u) % INSTALLED_PAIR_QUEUE_CAPACITY;
    link->queue_count -= 1u;
}

static ninlil_fabric_link_status_t link_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    installed_pair_link_t *link = (installed_pair_link_t *)user;
    ninlil_time_sample_t now;
    if (link == NULL || handle != link || out_state == NULL
        || link->clock == NULL || link->clock->now == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (link->clock->now(link->clock->user, &now) != NINLIL_PORT_OK
        || now.trust != NINLIL_CLOCK_TRUSTED
        || UINT64_MAX - now.now_ms < 600000u) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    out_state->api_version = NINLIL_FABRIC_API_VERSION;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->availability_epoch = link->availability_epoch;
    out_state->availability_clock_epoch_id = now.clock_epoch_id;
    out_state->available_until_ms = now.now_ms + 600000u;
    out_state->available = link->available;
    return NINLIL_FABRIC_LINK_OK;
}

void installed_pair_link_init(
    installed_pair_link_t *link, const ninlil_clock_ops_t *clock)
{
    (void)memset(link, 0, sizeof(*link));
    link->clock = clock;
    link->available = 1u;
    link->availability_epoch = 1u;
}

void installed_pair_link_connect(
    installed_pair_link_t *left, installed_pair_link_t *right)
{
    left->peer = right;
    right->peer = left;
}

void installed_pair_link_ops(
    installed_pair_link_t *link, ninlil_fabric_packet_link_ops_v1_t *out_ops)
{
    (void)memset(out_ops, 0, sizeof(*out_ops));
    out_ops->api_version = NINLIL_FABRIC_API_VERSION;
    out_ops->struct_size = (uint16_t)sizeof(*out_ops);
    out_ops->user = link;
    out_ops->open = link_open;
    out_ops->close = link_close;
    out_ops->start_send = link_start_send;
    out_ops->poll_send = link_poll_send;
    out_ops->cancel_send = link_cancel_send;
    out_ops->release_send = link_release_send;
    out_ops->receive_next = link_receive_next;
    out_ops->release_received = link_release_received;
    out_ops->state = link_state;
}
