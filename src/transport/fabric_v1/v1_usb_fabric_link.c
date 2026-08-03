#include "v1_usb_fabric_link.h"

#include "nfl1_codec.h"

#include "ninlil/version.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#define USB_FABRIC_TX_TOKEN_TAG ((uintptr_t)0x6du)
#define USB_FABRIC_RX_TOKEN_TAG ((uintptr_t)0x79u)
#if UINTPTR_MAX <= UINT32_MAX
#define USB_FABRIC_TX_GENERATION_MAX ((uint32_t)(UINTPTR_MAX >> 16u))
#define USB_FABRIC_RX_GENERATION_MAX ((uint32_t)(UINTPTR_MAX >> 8u))
#else
#define USB_FABRIC_TX_GENERATION_MAX (UINT32_MAX - UINT32_C(1))
#define USB_FABRIC_RX_GENERATION_MAX (UINT32_MAX - UINT32_C(1))
#endif

static void clear_bytes(void *pointer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;

    if (pointer == NULL) {
        return;
    }
    while (length > 0u) {
        *bytes = 0u;
        ++bytes;
        --length;
    }
}

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t i;

    if (bytes == NULL) {
        return 1;
    }
    for (i = 0u; i < length; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any == 0u;
}

static int flow_valid(uint8_t flow)
{
    return flow == NINLIL_V1_LAB_FLOW_A_TO_B
        || flow == NINLIL_V1_LAB_FLOW_B_TO_A;
}

static uint8_t flow_index(uint8_t flow)
{
    return (uint8_t)(flow - NINLIL_V1_LAB_FLOW_A_TO_B);
}

static int clock_valid(const ninlil_clock_ops_t *clock)
{
    return clock != NULL && clock->abi_version == NINLIL_ABI_VERSION
        && clock->struct_size == (uint16_t)sizeof(*clock)
        && clock->now != NULL;
}

static int sample_valid(const ninlil_time_sample_t *sample)
{
    return sample != NULL && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size == (uint16_t)sizeof(*sample)
        && sample->trust == NINLIL_CLOCK_TRUSTED
        && sample->reserved_zero == 0u
        && !bytes_zero(sample->clock_epoch_id.bytes, 16u);
}

static int sample_now(
    const ninlil_v1_usb_fabric_link_t *link,
    ninlil_time_sample_t *out)
{
    if (link == NULL || out == NULL || !clock_valid(&link->clock)) {
        return 0;
    }
    (void)memset(out, 0, sizeof(*out));
    if (link->clock.now(link->clock.user, out) != NINLIL_PORT_OK
        || !sample_valid(out)) {
        clear_bytes(out, sizeof(*out));
        return 0;
    }
    return 1;
}

static int prepared_valid(const ninlil_v1_usb_fabric_link_t *link)
{
    return link != NULL && link->magic == NINLIL_V1_USB_FABRIC_LINK_MAGIC
        && link->prepared != 0u;
}

static int bridge_live(const ninlil_v1_usb_fabric_link_t *link)
{
    return prepared_valid(link) && link->active != 0u
        && link->bridge != NULL
        && link->bridge->role == NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER
        && link->bridge_generation != 0u
        && link->bridge->active_generation == link->bridge_generation
        && link->bridge->board_info_received != 0u
        && !ninlil_v1_usb_bridge_is_fenced(link->bridge);
}

static int port_valid(const ninlil_v1_usb_fabric_port_t *port)
{
    return port != NULL && port->active != 0u && flow_valid(port->flow)
        && port->owner != NULL && prepared_valid(port->owner)
        && port->owner->active != 0u;
}

static int port_index_of(
    const ninlil_v1_usb_fabric_link_t *link,
    const ninlil_v1_usb_fabric_port_t *port,
    uint8_t *out_index)
{
    uint8_t i;

    if (!prepared_valid(link) || port == NULL || out_index == NULL) {
        return 0;
    }
    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_PATH_MAX; ++i) {
        if (port == &link->ports[i]) {
            *out_index = i;
            return 1;
        }
    }
    return 0;
}

static int handle_matches(
    const ninlil_v1_usb_fabric_port_t *port,
    ninlil_fabric_packet_link_handle_t handle,
    int allow_closed)
{
    return port_valid(port) && handle == (void *)port
        && (port->open != 0u || allow_closed != 0);
}

static ninlil_fabric_packet_token_t make_tx_token(
    uint32_t generation, uint8_t slot)
{
    uintptr_t value = ((uintptr_t)generation << 16u)
        | ((uintptr_t)(slot + 1u) << 8u) | USB_FABRIC_TX_TOKEN_TAG;
    return (ninlil_fabric_packet_token_t)value;
}

static int decode_tx_token(
    ninlil_fabric_packet_token_t token,
    uint32_t *out_generation,
    uint8_t *out_slot)
{
    uintptr_t value;
    uintptr_t slot_plus_one;

    if (token == NULL || out_generation == NULL || out_slot == NULL) {
        return 0;
    }
    value = (uintptr_t)token;
    slot_plus_one = (value >> 8u) & (uintptr_t)0xffu;
    if ((value & (uintptr_t)0xffu) != USB_FABRIC_TX_TOKEN_TAG
        || slot_plus_one == 0u
        || slot_plus_one > NINLIL_V1_USB_FABRIC_LINK_TX_MAX) {
        return 0;
    }
    *out_generation = (uint32_t)(value >> 16u);
    *out_slot = (uint8_t)(slot_plus_one - 1u);
    return *out_generation != 0u;
}

static void *make_rx_token(uint32_t generation)
{
    uintptr_t value = ((uintptr_t)generation << 8u)
        | USB_FABRIC_RX_TOKEN_TAG;
    return (void *)value;
}

static int rx_token_matches(
    const ninlil_v1_usb_fabric_port_t *port,
    const void *token)
{
    uintptr_t value;

    if (!port_valid(port) || token == NULL || port->rx.active == 0u
        || port->rx.loaned == 0u || port->rx.generation == 0u) {
        return 0;
    }
    value = (uintptr_t)token;
    return (value & (uintptr_t)0xffu) == USB_FABRIC_RX_TOKEN_TAG
        && (uint32_t)(value >> 8u) == port->rx.generation;
}

static ninlil_v1_usb_fabric_tx_t *tx_for_token(
    ninlil_v1_usb_fabric_link_t *link,
    const ninlil_v1_usb_fabric_port_t *port,
    ninlil_fabric_packet_token_t token,
    uint8_t *out_slot)
{
    ninlil_v1_usb_fabric_tx_t *tx;
    uint32_t generation = 0u;
    uint8_t slot = 0u;
    uint8_t port_index = 0u;

    if (!prepared_valid(link) || port == NULL
        || !port_index_of(link, port, &port_index)
        || !decode_tx_token(token, &generation, &slot)) {
        return NULL;
    }
    tx = &link->tx[slot];
    if (tx->active == 0u || tx->generation != generation
        || tx->port_index != port_index) {
        return NULL;
    }
    if (out_slot != NULL) {
        *out_slot = slot;
    }
    return tx;
}

static void mark_unavailable(ninlil_v1_usb_fabric_link_t *link)
{
    uint8_t i;

    if (!prepared_valid(link)) {
        return;
    }
    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_PATH_MAX; ++i) {
        ninlil_v1_usb_fabric_port_t *port = &link->ports[i];
        if (port->active == 0u || port->state.available == 0u) {
            continue;
        }
        port->state.available = 0u;
        if (port->state.availability_epoch != UINT64_MAX) {
            port->state.availability_epoch += 1u;
        }
    }
}

static ninlil_fabric_link_status_t usb_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;

    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    if (!port_valid(port) || out_handle == NULL || port->open != 0u
        || port->state.available == 0u || !bridge_live(port->owner)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    port->open = 1u;
    *out_handle = (void *)port;
    return NINLIL_FABRIC_LINK_OK;
}

static void usb_close(
    void *user, ninlil_fabric_packet_link_handle_t handle)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;
    ninlil_v1_usb_fabric_link_t *link;
    uint8_t port_index;
    uint8_t i;

    if (!handle_matches(port, handle, 0)) {
        return;
    }
    link = port->owner;
    if (!port_index_of(link, port, &port_index)) {
        return;
    }
    if (port->rx.active != 0u) {
        return;
    }
    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_TX_MAX; ++i) {
        if (link->tx[i].active != 0u
            && link->tx[i].port_index == port_index
            && link->tx[i].released == 0u) {
            return;
        }
    }
    port->open = 0u;
}

static int packet_shape_valid(
    const ninlil_v1_usb_fabric_port_t *port,
    const ninlil_fabric_packet_view_v1_t *packet,
    const ninlil_time_sample_t *now)
{
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    const ninlil_tx_permit_t *permit;
    uint32_t required = 0u;
    int valid;

    if (!port_valid(port) || packet == NULL || packet->bytes == NULL
        || now == NULL || packet->api_version != NINLIL_FABRIC_API_VERSION
        || packet->struct_size != (uint16_t)sizeof(*packet)
        || packet->reserved_zero != 0u
        || packet->length < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || packet->length > NINLIL_V1_LAB_FABRIC_PACKET_MAX
        || packet->path_selection_epoch == 0u
        || bytes_zero(packet->transaction_id.bytes, 16u)
        || bytes_zero(packet->attempt_id.bytes, 16u)
        || memcmp(packet->selected_path_id.bytes, port->path_id, 16u) != 0
        || packet->permit == NULL) {
        return 0;
    }
    permit = packet->permit;
    if (permit->abi_version != NINLIL_ABI_VERSION
        || permit->struct_size != (uint16_t)sizeof(*permit)
        || bytes_zero(permit->permit_id.bytes, 16u)
        || memcmp(permit->attempt_id.bytes, packet->attempt_id.bytes, 16u)
            != 0
        || permit->expires_at_ms == 0u || now->now_ms >= permit->expires_at_ms
        || memcmp(permit->clock_epoch_id.bytes,
               now->clock_epoch_id.bytes, 16u)
            != 0) {
        return 0;
    }
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    valid = ninlil_fabric_private_nfl1_decode(packet->bytes,
                packet->length, &workspace, &envelope, &required)
            == NINLIL_FABRIC_PRIVATE_NFL1_OK
        && memcmp(envelope.transaction_id.bytes,
               packet->transaction_id.bytes, 16u)
            == 0
        && memcmp(envelope.attempt_id.bytes,
               packet->attempt_id.bytes, 16u)
            == 0
        && memcmp(envelope.selected_path_id.bytes,
               packet->selected_path_id.bytes, 16u)
            == 0
        && envelope.path_selection_epoch == packet->path_selection_epoch;
    clear_bytes(&workspace, sizeof(workspace));
    clear_bytes(&envelope, sizeof(envelope));
    return valid;
}

static int permit_live(
    const ninlil_v1_usb_fabric_link_t *link,
    const uint8_t permit_id[16])
{
    uint8_t i;

    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_TX_MAX; ++i) {
        if (link->tx[i].active != 0u
            && memcmp(link->tx[i].permit_id, permit_id, 16u) == 0) {
            return 1;
        }
    }
    return 0;
}

static ninlil_fabric_link_status_t map_submit_status(
    ninlil_v1_usb_bridge_status_t status)
{
    if (status == NINLIL_V1_USB_BRIDGE_BUSY
        || status == NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (status == NINLIL_V1_USB_BRIDGE_LINK_DOWN
        || status == NINLIL_V1_USB_BRIDGE_FENCED
        || status == NINLIL_V1_USB_BRIDGE_SEQUENCE_EXHAUSTED) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (status == NINLIL_V1_USB_BRIDGE_IO_ERROR) {
        return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    }
    return NINLIL_FABRIC_LINK_CORRUPT;
}

static ninlil_fabric_link_status_t usb_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;
    ninlil_v1_usb_fabric_link_t *link;
    ninlil_v1_usb_bridge_handle_t bridge_handle;
    ninlil_time_sample_t now;
    ninlil_v1_usb_bridge_status_t bridge_status;
    uint8_t slot;
    uint8_t port_index = 0u;
    uint32_t generation;

    if (out_token != NULL) {
        *out_token = NULL;
    }
    if (!handle_matches(port, handle, 0) || packet == NULL
        || out_token == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    link = port->owner;
    if (!bridge_live(link) || !port_index_of(link, port, &port_index)) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (!sample_now(link, &now)) {
        mark_unavailable(link);
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (!packet_shape_valid(port, packet, &now)
        || permit_live(link, packet->permit->permit_id.bytes)) {
        clear_bytes(&now, sizeof(now));
        return NINLIL_FABRIC_LINK_DENIED;
    }
    for (slot = 0u; slot < NINLIL_V1_USB_FABRIC_LINK_TX_MAX; ++slot) {
        if (link->tx[slot].active == 0u) {
            break;
        }
    }
    if (slot >= NINLIL_V1_USB_FABRIC_LINK_TX_MAX
        || link->next_tx_generation > USB_FABRIC_TX_GENERATION_MAX) {
        clear_bytes(&now, sizeof(now));
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    (void)memset(&bridge_handle, 0, sizeof(bridge_handle));
    bridge_status = ninlil_v1_usb_bridge_submit_fabric(link->bridge,
        packet->bytes, packet->length, packet->permit->expires_at_ms,
        &bridge_handle);
    if (bridge_status != NINLIL_V1_USB_BRIDGE_OK) {
        clear_bytes(&now, sizeof(now));
        if (bridge_status == NINLIL_V1_USB_BRIDGE_LINK_DOWN
            || bridge_status == NINLIL_V1_USB_BRIDGE_FENCED) {
            mark_unavailable(link);
        }
        return map_submit_status(bridge_status);
    }
    generation = link->next_tx_generation;
    if (generation == 0u) {
        generation = 1u;
    }
    link->next_tx_generation = generation + 1u;
    (void)memset(&link->tx[slot], 0, sizeof(link->tx[slot]));
    link->tx[slot].active = 1u;
    link->tx[slot].bridge_live = 1u;
    link->tx[slot].port_index = port_index;
    link->tx[slot].completion_kind =
        NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    link->tx[slot].generation = generation;
    link->tx[slot].bridge_handle = bridge_handle;
    (void)memcpy(link->tx[slot].permit_id,
        packet->permit->permit_id.bytes, 16u);
    *out_token = make_tx_token(generation, slot);
    clear_bytes(&now, sizeof(now));
    return NINLIL_FABRIC_LINK_RETAINED;
}

static uint8_t completion_kind(
    const ninlil_v1_usb_bridge_completion_t *completion)
{
    if (completion->reason == NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS) {
        return completion->remote_status_code
                == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL
            ? NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE
            : NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
    }
    return NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
}

static int take_bridge_completion(
    ninlil_v1_usb_fabric_link_t *link,
    ninlil_v1_usb_fabric_tx_t *tx)
{
    ninlil_v1_usb_bridge_completion_t completion;
    ninlil_v1_usb_bridge_status_t status;

    if (link == NULL || tx == NULL || tx->active == 0u
        || tx->bridge_live == 0u) {
        return 0;
    }
    (void)memset(&completion, 0, sizeof(completion));
    status = ninlil_v1_usb_bridge_take_completion(link->bridge,
        tx->bridge_handle, &completion);
    if (status == NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
        return 0;
    }
    tx->bridge_live = 0u;
    tx->terminal = 1u;
    tx->completion_kind = status == NINLIL_V1_USB_BRIDGE_OK
        ? completion_kind(&completion)
        : NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
    clear_bytes(&completion, sizeof(completion));
    return 1;
}

static ninlil_fabric_link_status_t usb_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;
    ninlil_v1_usb_fabric_tx_t *tx;

    if (out_completion != NULL) {
        (void)memset(out_completion, 0, sizeof(*out_completion));
    }
    if (!handle_matches(port, handle, 1) || out_completion == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    tx = tx_for_token(port->owner, port, token, NULL);
    if (tx == NULL || tx->released != 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (tx->terminal == 0u) {
        (void)take_bridge_completion(port->owner, tx);
    }
    out_completion->api_version = NINLIL_FABRIC_API_VERSION;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    out_completion->kind = tx->completion_kind;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t usb_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;
    ninlil_v1_usb_fabric_tx_t *tx;

    if (!handle_matches(port, handle, 1)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    tx = tx_for_token(port->owner, port, token, NULL);
    if (tx == NULL || tx->released != 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (tx->terminal != 0u) {
        return NINLIL_FABRIC_LINK_OK;
    }
    if (take_bridge_completion(port->owner, tx)) {
        return NINLIL_FABRIC_LINK_OK;
    }
    tx->terminal = 1u;
    tx->completion_kind = NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
    return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
}

static void usb_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;
    ninlil_v1_usb_fabric_tx_t *tx;

    if (!handle_matches(port, handle, 1)) {
        return;
    }
    tx = tx_for_token(port->owner, port, token, NULL);
    if (tx == NULL || tx->terminal == 0u || tx->released != 0u) {
        return;
    }
    if (tx->bridge_live != 0u) {
        tx->released = 1u;
        return;
    }
    clear_bytes(tx, sizeof(*tx));
}

static ninlil_fabric_link_status_t usb_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;

    if (out_bytes != NULL) {
        *out_bytes = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    if (!handle_matches(port, handle, 0) || out_bytes == NULL
        || out_length == NULL || out_receive_token == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (port->rx.active == 0u) {
        return NINLIL_FABRIC_LINK_EMPTY;
    }
    if (port->rx.loaned != 0u) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    port->rx.loaned = 1u;
    *out_bytes = port->rx.bytes;
    *out_length = port->rx.length;
    *out_receive_token = make_rx_token(port->rx.generation);
    return NINLIL_FABRIC_LINK_OK;
}

static void usb_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;

    if (!handle_matches(port, handle, 0)
        || !rx_token_matches(port, receive_token)) {
        return;
    }
    clear_bytes(&port->rx, sizeof(port->rx));
}

static ninlil_fabric_link_status_t usb_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    ninlil_v1_usb_fabric_port_t *port =
        (ninlil_v1_usb_fabric_port_t *)user;

    if (out_state != NULL) {
        (void)memset(out_state, 0, sizeof(*out_state));
    }
    if (port == NULL || port->active == 0u || out_state == NULL
        || (handle != NULL && handle != (void *)port)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    *out_state = port->state;
    out_state->available = port->open != 0u && bridge_live(port->owner)
        && port->state.available != 0u;
    return NINLIL_FABRIC_LINK_OK;
}

static void fill_ops(ninlil_v1_usb_fabric_port_t *port)
{
    (void)memset(&port->ops, 0, sizeof(port->ops));
    port->ops.api_version = NINLIL_FABRIC_API_VERSION;
    port->ops.struct_size = (uint16_t)sizeof(port->ops);
    port->ops.user = port;
    port->ops.open = usb_open;
    port->ops.close = usb_close;
    port->ops.start_send = usb_start_send;
    port->ops.poll_send = usb_poll_send;
    port->ops.cancel_send = usb_cancel_send;
    port->ops.release_send = usb_release_send;
    port->ops.receive_next = usb_receive_next;
    port->ops.release_received = usb_release_received;
    port->ops.state = usb_state;
}

ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_prepare(
    ninlil_v1_usb_fabric_link_t *link)
{
    if (link == NULL) {
        return NINLIL_V1_USB_FABRIC_LINK_INVALID_ARGUMENT;
    }
    (void)memset(link, 0, sizeof(*link));
    link->magic = NINLIL_V1_USB_FABRIC_LINK_MAGIC;
    link->prepared = 1u;
    link->next_tx_generation = 1u;
    link->next_rx_generation = 1u;
    return NINLIL_V1_USB_FABRIC_LINK_OK;
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_fabric_link_board_info_handoff(
    void *user,
    const ninlil_nvb1_board_info_t *info)
{
    ninlil_v1_usb_fabric_link_t *link =
        (ninlil_v1_usb_fabric_link_t *)user;

    if (!prepared_valid(link) || info == NULL || link->active != 0u
        || link->board_info_received != 0u
        || bytes_zero(info->clock_epoch_id, 16u)
        || info->clock_trust != NINLIL_CLOCK_TRUSTED) {
        return NINLIL_V1_USB_BRIDGE_INVALID_STATE;
    }
    link->board_info = *info;
    link->board_info_received = 1u;
    return NINLIL_V1_USB_BRIDGE_OK;
}

ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_board_info(
    const ninlil_v1_usb_fabric_link_t *link,
    ninlil_nvb1_board_info_t *out_info)
{
    if (out_info != NULL) {
        (void)memset(out_info, 0, sizeof(*out_info));
    }
    if (!prepared_valid(link) || out_info == NULL) {
        return NINLIL_V1_USB_FABRIC_LINK_INVALID_ARGUMENT;
    }
    if (link->board_info_received == 0u) {
        return NINLIL_V1_USB_FABRIC_LINK_INVALID_STATE;
    }
    *out_info = link->board_info;
    return NINLIL_V1_USB_FABRIC_LINK_OK;
}

static int installed_state_valid(
    const ninlil_v1_usb_fabric_link_t *link,
    const ninlil_v1_usb_bridge_t *bridge,
    uint64_t installed_pair_generation)
{
    return prepared_valid(link) && link->board_info_received != 0u
        && bridge != NULL
        && bridge->role == NINLIL_V1_USB_BRIDGE_ROLE_HOST_CONTROLLER
        && bridge->callback_user == (void *)link
        && bridge->fabric_handoff == ninlil_v1_usb_fabric_link_handoff
        && bridge->board_info == ninlil_v1_usb_fabric_link_board_info_handoff
        && bridge->board_info_received != 0u
        && bridge->active_generation != 0u
        && !ninlil_v1_usb_bridge_is_fenced(bridge)
        && installed_pair_generation != 0u;
}

typedef struct pending_path {
    uint8_t active;
    uint8_t flow;
    uint8_t path_id[16];
    ninlil_fabric_link_descriptor_v1_t descriptor;
    ninlil_fabric_link_state_v1_t state;
} pending_path_t;

static int pair_index(
    const ninlil_v1_usb_fabric_link_t *link,
    const uint8_t pair_id[32],
    uint8_t *out_index)
{
    uint8_t i;

    if (out_index == NULL) {
        return 0;
    }
    for (i = 0u; i < link->pair_count; ++i) {
        if (memcmp(link->pair_ids[i], pair_id, 32u) == 0) {
            *out_index = i;
            return 1;
        }
    }
    return 0;
}

static int path_known(
    const ninlil_v1_usb_fabric_link_t *link,
    const uint8_t path_id[16])
{
    uint8_t i;

    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_PATH_MAX; ++i) {
        if (link->ports[i].active != 0u
            && memcmp(link->ports[i].path_id, path_id, 16u) == 0) {
            return 1;
        }
    }
    return 0;
}

ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_activate(
    ninlil_v1_usb_fabric_link_t *link,
    ninlil_v1_usb_bridge_t *bridge,
    const ninlil_r7_crypto_provider *crypto,
    const ninlil_clock_ops_t *clock,
    const uint8_t local_runtime_id[16],
    const uint8_t *encoded_binding,
    size_t encoded_length,
    uint64_t installed_pair_generation)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_time_sample_t now;
    pending_path_t pending[NINLIL_V1_USB_FABRIC_LINK_PATH_MAX / 2u];
    const ninlil_v1_lab_endpoint_t *local;
    uint8_t free_ports[NINLIL_V1_USB_FABRIC_LINK_PATH_MAX];
    uint8_t free_count = 0u;
    uint8_t commit_index = 0u;
    uint8_t new_path_count = 0u;
    uint8_t known_pair_index = 0u;
    uint8_t side = 0u;
    uint8_t row_index;

    if (!installed_state_valid(link, bridge, installed_pair_generation)
        || crypto == NULL || !clock_valid(clock)
        || local_runtime_id == NULL || bytes_zero(local_runtime_id, 16u)
        || encoded_binding == NULL) {
        return NINLIL_V1_USB_FABRIC_LINK_INVALID_ARGUMENT;
    }
    (void)memset(&binding, 0, sizeof(binding));
    (void)memset(&now, 0, sizeof(now));
    (void)memset(pending, 0, sizeof(pending));
    (void)memset(free_ports, 0, sizeof(free_ports));
    if (ninlil_v1_lab_binding_decode(crypto, encoded_binding,
            encoded_length, &binding) != NINLIL_V1_LAB_BINDING_OK
        || binding.pair_generation != installed_pair_generation
        || ninlil_v1_lab_binding_local_side(
               &binding, local_runtime_id, &side)
            != NINLIL_V1_LAB_BINDING_OK
        || side != binding.controller_side
        || clock->now(clock->user, &now) != NINLIL_PORT_OK
        || !sample_valid(&now)) {
        ninlil_v1_lab_binding_clear(&binding);
        clear_bytes(&now, sizeof(now));
        return NINLIL_V1_USB_FABRIC_LINK_BINDING;
    }
    if (link->active != 0u
        && (link->bridge != bridge
            || link->bridge_generation != bridge->active_generation
            || link->clock.user != clock->user || link->clock.now != clock->now
            || memcmp(link->local_runtime_id, local_runtime_id, 16u) != 0)) {
        ninlil_v1_lab_binding_clear(&binding);
        clear_bytes(&now, sizeof(now));
        return NINLIL_V1_USB_FABRIC_LINK_FENCED;
    }
    local = side == NINLIL_V1_LAB_SIDE_A
        ? &binding.endpoint_a
        : &binding.endpoint_b;
    if (local->clock_trust != NINLIL_CLOCK_TRUSTED
        || memcmp(local->clock_epoch_id, now.clock_epoch_id.bytes, 16u) != 0
        || memcmp(link->board_info.clock_epoch_id,
               now.clock_epoch_id.bytes, 16u)
            != 0) {
        ninlil_v1_lab_binding_clear(&binding);
        clear_bytes(&now, sizeof(now));
        return NINLIL_V1_USB_FABRIC_LINK_FENCED;
    }
    if (pair_index(link, binding.pair_id, &known_pair_index)) {
        int exact = memcmp(link->pair_binding_digests[known_pair_index],
                        binding.pair_binding_digest, 32u)
            == 0;
        ninlil_v1_lab_binding_clear(&binding);
        clear_bytes(&now, sizeof(now));
        return exact ? NINLIL_V1_USB_FABRIC_LINK_OK
                     : NINLIL_V1_USB_FABRIC_LINK_BINDING;
    }
    if (link->pair_count >= NINLIL_V1_USB_FABRIC_LINK_PAIR_MAX) {
        ninlil_v1_lab_binding_clear(&binding);
        clear_bytes(&now, sizeof(now));
        return NINLIL_V1_USB_FABRIC_LINK_INVALID_STATE;
    }
    for (row_index = 0u; row_index < binding.service_count; ++row_index) {
        const ninlil_v1_lab_service_row_t *row =
            &binding.services[row_index];
        uint8_t index = flow_index(row->flow);
        pending_path_t *path;

        if (!flow_valid(row->flow)) {
            ninlil_v1_lab_binding_clear(&binding);
            clear_bytes(&now, sizeof(now));
            return NINLIL_V1_USB_FABRIC_LINK_BINDING;
        }
        path = &pending[index];
        if (path->active != 0u) {
            if (memcmp(path->path_id, row->selected_path_id, 16u) != 0) {
                ninlil_v1_lab_binding_clear(&binding);
                clear_bytes(&now, sizeof(now));
                return NINLIL_V1_USB_FABRIC_LINK_BINDING;
            }
            continue;
        }
        if (ninlil_v1_lab_fabric_build_path(crypto, &binding,
                local_runtime_id, row->flow, &path->descriptor,
                &path->state) != NINLIL_V1_LAB_FABRIC_OK) {
            ninlil_v1_lab_binding_clear(&binding);
            clear_bytes(&now, sizeof(now));
            clear_bytes(pending, sizeof(pending));
            return NINLIL_V1_USB_FABRIC_LINK_BINDING;
        }
        path->active = 1u;
        path->flow = row->flow;
        (void)memcpy(path->path_id, row->selected_path_id, 16u);
        new_path_count += 1u;
    }
    if (new_path_count == 0u
        || new_path_count
            > (uint8_t)(NINLIL_V1_USB_FABRIC_LINK_PATH_MAX
                - link->port_count)) {
        ninlil_v1_lab_binding_clear(&binding);
        clear_bytes(&now, sizeof(now));
        clear_bytes(pending, sizeof(pending));
        return NINLIL_V1_USB_FABRIC_LINK_BINDING;
    }
    for (row_index = 0u;
         row_index < (uint8_t)(NINLIL_V1_USB_FABRIC_LINK_PATH_MAX / 2u);
         ++row_index) {
        if (pending[row_index].active != 0u
            && path_known(link, pending[row_index].path_id)) {
            ninlil_v1_lab_binding_clear(&binding);
            clear_bytes(&now, sizeof(now));
            clear_bytes(pending, sizeof(pending));
            return NINLIL_V1_USB_FABRIC_LINK_BINDING;
        }
    }
    for (row_index = 0u;
         row_index < NINLIL_V1_USB_FABRIC_LINK_PATH_MAX;
         ++row_index) {
        if (link->ports[row_index].active == 0u) {
            free_ports[free_count] = row_index;
            free_count += 1u;
        }
    }
    if (free_count < new_path_count) {
        ninlil_v1_lab_binding_clear(&binding);
        clear_bytes(&now, sizeof(now));
        clear_bytes(pending, sizeof(pending));
        return NINLIL_V1_USB_FABRIC_LINK_BINDING;
    }
    for (row_index = 0u;
         row_index < (uint8_t)(NINLIL_V1_USB_FABRIC_LINK_PATH_MAX / 2u);
         ++row_index) {
        ninlil_v1_usb_fabric_port_t *port;

        if (pending[row_index].active == 0u) {
            continue;
        }
        port = &link->ports[free_ports[commit_index]];
        commit_index += 1u;
        (void)memset(port, 0, sizeof(*port));
        port->active = 1u;
        port->flow = pending[row_index].flow;
        port->owner = link;
        (void)memcpy(port->path_id, pending[row_index].path_id, 16u);
        port->descriptor = pending[row_index].descriptor;
        port->state = pending[row_index].state;
        fill_ops(port);
        link->port_count += 1u;
    }
    if (link->active == 0u) {
        link->bridge = bridge;
        link->bridge_generation = bridge->active_generation;
        link->clock = *clock;
        (void)memcpy(link->local_runtime_id, local_runtime_id, 16u);
    }
    (void)memcpy(link->pair_ids[link->pair_count], binding.pair_id, 32u);
    (void)memcpy(link->pair_binding_digests[link->pair_count],
        binding.pair_binding_digest, 32u);
    link->pair_count += 1u;
    link->active = 1u;
    ninlil_v1_lab_binding_clear(&binding);
    clear_bytes(&now, sizeof(now));
    clear_bytes(pending, sizeof(pending));
    return NINLIL_V1_USB_FABRIC_LINK_OK;
}

ninlil_v1_usb_fabric_link_status_t ninlil_v1_usb_fabric_link_path(
    ninlil_v1_usb_fabric_link_t *link,
    const uint8_t selected_path_id[16],
    const ninlil_fabric_link_descriptor_v1_t **out_descriptor,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops)
{
    uint8_t i;

    if (out_descriptor != NULL) {
        *out_descriptor = NULL;
    }
    if (out_ops != NULL) {
        *out_ops = NULL;
    }
    if (!bridge_live(link) || selected_path_id == NULL
        || bytes_zero(selected_path_id, 16u)
        || out_descriptor == NULL || out_ops == NULL) {
        return NINLIL_V1_USB_FABRIC_LINK_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_PATH_MAX; ++i) {
        ninlil_v1_usb_fabric_port_t *port = &link->ports[i];
        if (port->active != 0u
            && memcmp(port->path_id, selected_path_id, 16u) == 0) {
            *out_descriptor = &port->descriptor;
            *out_ops = &port->ops;
            return NINLIL_V1_USB_FABRIC_LINK_OK;
        }
    }
    return NINLIL_V1_USB_FABRIC_LINK_NOT_FOUND;
}

uint32_t ninlil_v1_usb_fabric_link_handoff(
    void *user,
    const uint8_t *encoded_packet,
    size_t encoded_length)
{
    ninlil_v1_usb_fabric_link_t *link =
        (ninlil_v1_usb_fabric_link_t *)user;
    ninlil_fabric_private_nfl1_workspace_t workspace;
    ninlil_fabric_private_nfl1_envelope_t envelope;
    ninlil_v1_usb_fabric_port_t *port = NULL;
    uint32_t required = 0u;
    uint8_t i;

    if (!bridge_live(link)) {
        return NINLIL_NVB1_STATUS_UNSUPPORTED;
    }
    if (encoded_packet == NULL
        || encoded_length < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || encoded_length > NINLIL_V1_LAB_FABRIC_PACKET_MAX) {
        return NINLIL_NVB1_STATUS_REJECTED;
    }
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&envelope, 0, sizeof(envelope));
    if (ninlil_fabric_private_nfl1_decode(encoded_packet,
            (uint32_t)encoded_length, &workspace, &envelope, &required)
        != NINLIL_FABRIC_PRIVATE_NFL1_OK) {
        clear_bytes(&workspace, sizeof(workspace));
        clear_bytes(&envelope, sizeof(envelope));
        return NINLIL_NVB1_STATUS_REJECTED;
    }
    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_PATH_MAX; ++i) {
        if (link->ports[i].active != 0u
            && memcmp(link->ports[i].path_id,
                   envelope.selected_path_id.bytes, 16u)
                == 0) {
            port = &link->ports[i];
            break;
        }
    }
    if (port == NULL || envelope.path_selection_epoch == 0u
        || bytes_zero(envelope.transaction_id.bytes, 16u)
        || bytes_zero(envelope.attempt_id.bytes, 16u)) {
        clear_bytes(&workspace, sizeof(workspace));
        clear_bytes(&envelope, sizeof(envelope));
        return NINLIL_NVB1_STATUS_REJECTED;
    }
    if (port->open == 0u || port->rx.active != 0u
        || link->next_rx_generation > USB_FABRIC_RX_GENERATION_MAX) {
        clear_bytes(&workspace, sizeof(workspace));
        clear_bytes(&envelope, sizeof(envelope));
        return NINLIL_NVB1_STATUS_BUSY;
    }
    (void)memset(&port->rx, 0, sizeof(port->rx));
    port->rx.active = 1u;
    port->rx.generation = link->next_rx_generation;
    link->next_rx_generation += 1u;
    port->rx.length = (uint32_t)encoded_length;
    (void)memcpy(port->rx.bytes, encoded_packet, encoded_length);
    clear_bytes(&workspace, sizeof(workspace));
    clear_bytes(&envelope, sizeof(envelope));
    return NINLIL_NVB1_STATUS_ACCEPTED_LOCAL;
}

static void reap_released(ninlil_v1_usb_fabric_link_t *link)
{
    uint8_t i;

    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_TX_MAX; ++i) {
        ninlil_v1_usb_fabric_tx_t *tx = &link->tx[i];
        if (tx->active == 0u || tx->released == 0u) {
            continue;
        }
        if (tx->bridge_live != 0u) {
            (void)take_bridge_completion(link, tx);
        }
        if (tx->bridge_live == 0u) {
            clear_bytes(tx, sizeof(*tx));
        }
    }
}

ninlil_v1_usb_bridge_status_t ninlil_v1_usb_fabric_link_step(
    ninlil_v1_usb_fabric_link_t *link,
    uint64_t now_ms,
    uint32_t poll_timeout_ms)
{
    ninlil_v1_usb_bridge_status_t status;

    if (!prepared_valid(link) || link->active == 0u
        || link->bridge == NULL) {
        return NINLIL_V1_USB_BRIDGE_INVALID_ARGUMENT;
    }
    status = ninlil_v1_usb_bridge_step(
        link->bridge, now_ms, poll_timeout_ms);
    reap_released(link);
    if (!bridge_live(link)) {
        mark_unavailable(link);
    }
    return status;
}

void ninlil_v1_usb_fabric_link_clear(ninlil_v1_usb_fabric_link_t *link)
{
    uint8_t i;

    if (!prepared_valid(link)) {
        return;
    }
    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_PATH_MAX; ++i) {
        if (link->ports[i].open != 0u || link->ports[i].rx.active != 0u) {
            return;
        }
    }
    for (i = 0u; i < NINLIL_V1_USB_FABRIC_LINK_TX_MAX; ++i) {
        if (link->tx[i].active != 0u) {
            return;
        }
    }
    clear_bytes(link, sizeof(*link));
}
