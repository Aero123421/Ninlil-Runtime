/* SPDX-License-Identifier: Apache-2.0 */
#include "fabric_host_radio_packet_link.h"

#include <string.h>

void ninlil_fabric_host_radio_user_init(ninlil_fabric_host_radio_user_t *u)
{
    if (u == NULL) {
        return;
    }
    (void)memset(u, 0, sizeof(*u));
    u->available = 1u;
    u->availability_epoch = 1u;
    u->next_start_status = NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_link_status_t radio_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    if (u == NULL || out_handle == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    u->open = 1u;
    *out_handle = (ninlil_fabric_packet_link_handle_t)u;
    return NINLIL_FABRIC_LINK_OK;
}

static void radio_close(void *user, ninlil_fabric_packet_link_handle_t handle)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    (void)handle;
    if (u != NULL) {
        u->open = 0u;
    }
}

/*
 * Host-radio provider Tx Gate (same semantic as fabric_private_api.h contract).
 * DENIED / WOULD_BLOCK: no retain; WOULD_BLOCK preferred after capacity check.
 */
static int radio_permit_ok(const ninlil_fabric_packet_view_v1_t *packet)
{
    const ninlil_tx_permit_t *pr;
    uint32_t i;
    int zero;
    if (packet == NULL) {
        return 0;
    }
    pr = packet->permit;
    if (pr == NULL || pr->abi_version != NINLIL_ABI_VERSION
        || pr->struct_size != (uint16_t)sizeof(*pr)
        || pr->expires_at_ms == 0u) {
        return 0;
    }
    zero = 1;
    for (i = 0u; i < 16u; ++i) {
        if (pr->permit_id.bytes[i] != 0u) {
            zero = 0;
            break;
        }
    }
    if (zero != 0) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        if (pr->attempt_id.bytes[i] != packet->attempt_id.bytes[i]) {
            return 0;
        }
    }
    return 1;
}

static ninlil_fabric_link_status_t radio_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    uint32_t i;
    (void)handle;
    if (u == NULL || packet == NULL || out_token == NULL || u->open == 0u) {
        if (out_token != NULL) {
            *out_token = NULL;
        }
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    *out_token = NULL;
    if (radio_permit_ok(packet) == 0) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (u->available == 0u) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (packet->length == 0u || packet->bytes == NULL
        || packet->length > NINLIL_FABRIC_HOST_RADIO_MAX_BYTES) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    /* Capacity before I/O bookkeeping: WOULD_BLOCK consumes no permit. */
    for (i = 0u; i < NINLIL_FABRIC_HOST_RADIO_TX_SLOTS; ++i) {
        if (u->tx[i].used == 0u) {
            break;
        }
    }
    if (i >= NINLIL_FABRIC_HOST_RADIO_TX_SLOTS) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    u->start_calls++;
    if (u->next_start_status != NINLIL_FABRIC_LINK_RETAINED
        && u->next_start_status != NINLIL_FABRIC_LINK_OK) {
        ninlil_fabric_link_status_t st = u->next_start_status;
        u->next_start_status = NINLIL_FABRIC_LINK_RETAINED;
        return st;
    }
    u->tx[i].used = 1u;
    u->tx[i].terminal = 0u;
    u->next_gen++;
    u->tx[i].generation = u->next_gen;
    u->tx[i].length = packet->length;
    (void)memcpy(u->tx[i].bytes, packet->bytes, packet->length);
    u->retain_bytes = packet->length;
    *out_token = (ninlil_fabric_packet_token_t)(uintptr_t)(u->tx[i].generation);
    return NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_host_radio_tx_slot_t *find_tx(
    ninlil_fabric_host_radio_user_t *u, ninlil_fabric_packet_token_t token)
{
    uint32_t gen = (uint32_t)(uintptr_t)token;
    uint32_t i;
    for (i = 0u; i < NINLIL_FABRIC_HOST_RADIO_TX_SLOTS; ++i) {
        if (u->tx[i].used != 0u && u->tx[i].generation == gen) {
            return &u->tx[i];
        }
    }
    return NULL;
}

static ninlil_fabric_link_status_t radio_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    ninlil_fabric_host_radio_tx_slot_t *slot;
    (void)handle;
    if (u == NULL || out_completion == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(out_completion, 0, sizeof(*out_completion));
    out_completion->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    slot = find_tx(u, token);
    if (slot == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot->terminal = 1u;
    out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t radio_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    ninlil_fabric_host_radio_tx_slot_t *slot;
    (void)handle;
    if (u == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot = find_tx(u, token);
    if (slot == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    slot->terminal = 1u;
    return NINLIL_FABRIC_LINK_OK;
}

static void radio_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    ninlil_fabric_host_radio_tx_slot_t *slot;
    (void)handle;
    if (u == NULL) {
        return;
    }
    slot = find_tx(u, token);
    if (slot != NULL && slot->terminal != 0u) {
        (void)memset(slot, 0, sizeof(*slot));
        u->retain_bytes = 0u;
    }
}

static ninlil_fabric_link_status_t radio_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    (void)handle;
    if (u == NULL || out_bytes == NULL || out_length == NULL
        || out_receive_token == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    *out_receive_token = NULL;
    *out_bytes = NULL;
    *out_length = 0u;
    if (u->rx_len == 0u || u->rx_loan != 0u) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    *out_bytes = u->rx_bytes;
    *out_length = u->rx_len;
    u->rx_loan = 1u;
    *out_receive_token = (void *)(uintptr_t)1;
    return NINLIL_FABRIC_LINK_OK;
}

static void radio_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    (void)handle;
    (void)receive_token;
    if (u != NULL) {
        u->rx_loan = 0u;
        u->rx_len = 0u;
    }
}

static ninlil_fabric_link_status_t radio_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    ninlil_fabric_host_radio_user_t *u = (ninlil_fabric_host_radio_user_t *)user;
    (void)handle;
    if (u == NULL || out_state == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    (void)memset(out_state, 0, sizeof(*out_state));
    out_state->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->available = u->available;
    out_state->availability_epoch = u->availability_epoch;
    out_state->available_until_ms = 300000u;
    {
        uint32_t i;
        for (i = 0u; i < 16u; ++i) {
            out_state->availability_clock_epoch_id.bytes[i] =
                (uint8_t)(0xA1u + i);
        }
    }
    return NINLIL_FABRIC_LINK_OK;
}

void ninlil_fabric_host_radio_packet_link_ops_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_fabric_host_radio_user_t *user)
{
    if (ops == NULL) {
        return;
    }
    (void)memset(ops, 0, sizeof(*ops));
    ops->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = user;
    ops->open = radio_open;
    ops->close = radio_close;
    ops->start_send = radio_start_send;
    ops->poll_send = radio_poll_send;
    ops->cancel_send = radio_cancel_send;
    ops->release_send = radio_release_send;
    ops->receive_next = radio_receive_next;
    ops->release_received = radio_release_received;
    ops->state = radio_state;
}

int ninlil_fabric_host_radio_push_rx(
    ninlil_fabric_host_radio_user_t *u,
    const uint8_t *bytes,
    uint32_t len)
{
    if (u == NULL || bytes == NULL || len == 0u
        || len > NINLIL_FABRIC_HOST_RADIO_MAX_BYTES || u->rx_loan != 0u) {
        return -1;
    }
    (void)memcpy(u->rx_bytes, bytes, len);
    u->rx_len = len;
    return 0;
}
