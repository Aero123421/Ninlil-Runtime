/* SPDX-License-Identifier: Apache-2.0 */
#include "v1_lab_radio_packet_link.h"

#include "nfl1_codec.h"

#include "ninlil/version.h"

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define V1_LAB_RADIO_LINK_MAGIC ((uint32_t)0x91c6a45bu)
#define V1_LAB_RADIO_TX_TOKEN_TAG ((uintptr_t)0x51u)
#define V1_LAB_RADIO_RX_TOKEN_TAG ((uintptr_t)0x63u)
#define V1_LAB_RADIO_OUTER_MIN ((uint32_t)66u)

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

static void clear_bytes(void *pointer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)pointer;
    size_t i;

    if (pointer == NULL) {
        return;
    }
    for (i = 0u; i < length; ++i) {
        bytes[i] = 0u;
    }
}

static int flow_valid(uint8_t flow)
{
    return flow == NINLIL_V1_LAB_FLOW_A_TO_B
        || flow == NINLIL_V1_LAB_FLOW_B_TO_A;
}

static uint8_t opposite_flow(uint8_t flow)
{
    return flow == NINLIL_V1_LAB_FLOW_A_TO_B
        ? NINLIL_V1_LAB_FLOW_B_TO_A
        : NINLIL_V1_LAB_FLOW_A_TO_B;
}

static uint8_t route_index(uint8_t pair_slot, uint8_t flow)
{
    return (uint8_t)(pair_slot * 2u + (flow - 1u));
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
    const ninlil_v1_lab_radio_packet_link_t *link,
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

static int link_valid(const ninlil_v1_lab_radio_packet_link_t *link)
{
    return link != NULL && link->magic == V1_LAB_RADIO_LINK_MAGIC
        && link->closed == 0u && link->phy != NULL
        && clock_valid(&link->clock);
}

static int port_valid(const ninlil_v1_lab_radio_path_port_t *port)
{
    return port != NULL && port->active != 0u && port->owner != NULL
        && link_valid(port->owner)
        && port->pair_slot < NINLIL_V1_LAB_RADIO_PAIR_MAX
        && flow_valid(port->original_flow);
}

static int handle_matches(
    const ninlil_v1_lab_radio_path_port_t *port,
    ninlil_fabric_packet_link_handle_t handle,
    int allow_closed)
{
    return port_valid(port) && handle == (void *)port
        && (port->open != 0u || allow_closed != 0);
}

static ninlil_fabric_packet_token_t make_tx_token(uint32_t generation)
{
    uintptr_t value = ((uintptr_t)generation << 8u)
        | V1_LAB_RADIO_TX_TOKEN_TAG;
    return (ninlil_fabric_packet_token_t)value;
}

static void *make_rx_token(uint32_t generation)
{
    uintptr_t value = ((uintptr_t)generation << 8u)
        | V1_LAB_RADIO_RX_TOKEN_TAG;
    return (void *)value;
}

static int tx_token_matches(
    const ninlil_v1_lab_radio_packet_link_t *link,
    const ninlil_v1_lab_radio_path_port_t *port,
    ninlil_fabric_packet_token_t token)
{
    uintptr_t value;

    if (!link_valid(link) || !port_valid(port) || token == NULL
        || link->tx.active == 0u
        || link->tx.port_index != route_index(port->pair_slot, port->original_flow)) {
        return 0;
    }
    value = (uintptr_t)token;
    return (value & (uintptr_t)0xffu) == V1_LAB_RADIO_TX_TOKEN_TAG
        && (uint32_t)(value >> 8u) == link->tx.generation;
}

static int rx_token_matches(
    const ninlil_v1_lab_radio_packet_link_t *link,
    const ninlil_v1_lab_radio_path_port_t *port,
    const void *token)
{
    uintptr_t value;

    if (!link_valid(link) || !port_valid(port) || token == NULL
        || link->rx.active == 0u || link->rx.loaned == 0u
        || link->rx.port_index != route_index(port->pair_slot, port->original_flow)) {
        return 0;
    }
    value = (uintptr_t)token;
    return (value & (uintptr_t)0xffu) == V1_LAB_RADIO_RX_TOKEN_TAG
        && (uint32_t)(value >> 8u) == link->rx.generation;
}

static void mark_port_unavailable(ninlil_v1_lab_radio_path_port_t *port)
{
    if (port == NULL || port->active == 0u || port->state.available == 0u) {
        return;
    }
    port->state.available = 0u;
    if (port->state.availability_epoch != UINT64_MAX) {
        port->state.availability_epoch += 1u;
    }
}

static void mark_pair_unavailable(
    ninlil_v1_lab_radio_packet_link_t *link, uint8_t pair_slot)
{
    uint8_t flow;

    if (link == NULL) {
        return;
    }
    for (flow = NINLIL_V1_LAB_FLOW_A_TO_B;
         flow <= NINLIL_V1_LAB_FLOW_B_TO_A;
         ++flow) {
        mark_port_unavailable(&link->ports[route_index(pair_slot, flow)]);
    }
}

static void mark_all_unavailable(ninlil_v1_lab_radio_packet_link_t *link)
{
    uint8_t i;

    if (link == NULL) {
        return;
    }
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_LINK_PATH_MAX; ++i) {
        mark_port_unavailable(&link->ports[i]);
    }
}

static ninlil_v1_lab_radio_link_status_t map_mapping_status(
    ninlil_v1_lab_radio_packet_link_t *link,
    uint8_t pair_slot,
    ninlil_v1_lab_radio_mapping_status_t status)
{
    if (status == NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    if (status == NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY) {
        return NINLIL_V1_LAB_RADIO_LINK_CAPACITY;
    }
    if (status == NINLIL_V1_LAB_RADIO_MAPPING_FENCED) {
        mark_pair_unavailable(link, pair_slot);
        return NINLIL_V1_LAB_RADIO_LINK_FENCED;
    }
    if (status == NINLIL_V1_LAB_RADIO_MAPPING_CONFLICT) {
        return NINLIL_V1_LAB_RADIO_LINK_CONFLICT;
    }
    if (status == NINLIL_V1_LAB_RADIO_MAPPING_BINDING
        || status == NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND) {
        return NINLIL_V1_LAB_RADIO_LINK_BINDING;
    }
    if (status == NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
}

static ninlil_fabric_link_status_t step_status_to_fabric(
    ninlil_v1_lab_radio_link_status_t status)
{
    if (status == NINLIL_V1_LAB_RADIO_LINK_OK) {
        return NINLIL_FABRIC_LINK_OK;
    }
    if (status == NINLIL_V1_LAB_RADIO_LINK_CAPACITY) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (status == NINLIL_V1_LAB_RADIO_LINK_FENCED) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (status == NINLIL_V1_LAB_RADIO_LINK_PHY) {
        return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    }
    if (status == NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    return NINLIL_FABRIC_LINK_CORRUPT;
}

static ninlil_fabric_link_status_t radio_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;

    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    if (!port_valid(port) || out_handle == NULL || port->open != 0u
        || port->state.available == 0u
        || port->owner->mapper.pairs[port->pair_slot].fenced != 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    port->open = 1u;
    *out_handle = (void *)port;
    return NINLIL_FABRIC_LINK_OK;
}

static void radio_close(
    void *user, ninlil_fabric_packet_link_handle_t handle)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;

    if (!handle_matches(port, handle, 0)) {
        return;
    }
    if ((port->owner->tx.active != 0u
            && port->owner->tx.port_index
                == route_index(port->pair_slot, port->original_flow))
        || (port->owner->rx.active != 0u
            && port->owner->rx.port_index
                == route_index(port->pair_slot, port->original_flow))) {
        return;
    }
    port->open = 0u;
}

static int packet_shape_valid(
    const ninlil_v1_lab_radio_path_port_t *port,
    const ninlil_fabric_packet_view_v1_t *packet,
    const ninlil_time_sample_t *now)
{
    const ninlil_tx_permit_t *permit;

    if (!port_valid(port) || packet == NULL || packet->bytes == NULL
        || now == NULL || packet->api_version != NINLIL_FABRIC_API_VERSION
        || packet->struct_size != (uint16_t)sizeof(*packet)
        || packet->reserved_zero != 0u
        || packet->length < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || packet->length > NINLIL_V1_LAB_RADIO_NFL1_MAX
        || packet->path_selection_epoch == 0u
        || memcmp(packet->selected_path_id.bytes, port->path_id, 16u) != 0
        || packet->permit == NULL) {
        return 0;
    }
    permit = packet->permit;
    return permit->abi_version == NINLIL_ABI_VERSION
        && permit->struct_size == (uint16_t)sizeof(*permit)
        && !bytes_zero(permit->permit_id.bytes, 16u)
        && !bytes_zero(packet->attempt_id.bytes, 16u)
        && memcmp(permit->attempt_id.bytes, packet->attempt_id.bytes, 16u) == 0
        && permit->expires_at_ms != 0u && now->now_ms < permit->expires_at_ms
        && memcmp(
               permit->clock_epoch_id.bytes,
               now->clock_epoch_id.bytes,
               16u)
            == 0;
}

static ninlil_fabric_link_status_t start_send_common(
    ninlil_v1_lab_radio_packet_link_t *link,
    ninlil_v1_lab_radio_path_port_t *expected_port,
    const uint8_t *nfl1,
    uint32_t nfl1_length,
    const ninlil_tx_permit_t *permit,
    uint8_t delegated,
    const ninlil_time_sample_t *now,
    ninlil_fabric_packet_token_t *out_token)
{
    ninlil_v1_lab_radio_path_port_t *port;
    ninlil_r7_frag_prod_tx_result_t result;
    ninlil_v1_lab_radio_mapping_status_t mapping_status;
    ninlil_v1_lab_radio_route_t *route;
    ninlil_sx1262_phy_stats_t stats;
    uint8_t pair_slot = 0u;
    uint8_t radio_flow = 0u;
    uint8_t original_flow;
    uint8_t nra1[NINLIL_NRA1_APPLICATION_BODY_MAX];
    size_t nra1_length = 0u;
    uint64_t candidate_token;
    int r7_held;
    int32_t r7_status;

    if (!link_valid(link) || nfl1 == NULL || now == NULL
        || nfl1_length < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || nfl1_length > NINLIL_V1_LAB_RADIO_NFL1_MAX
        || (delegated == 0u && (expected_port == NULL || permit == NULL))) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (link->tx.active != 0u || link->rx.active != 0u
        || ninlil_sx1262_phy_state(link->phy)
            == NINLIL_SX1262_PHY_STATE_TX_ACTIVE) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    (void)memset(nra1, 0, sizeof(nra1));
    mapping_status = ninlil_v1_lab_radio_mapper_encode(
        &link->mapper,
        nfl1,
        nfl1_length,
        now,
        &pair_slot,
        &radio_flow,
        nra1,
        sizeof(nra1),
        &nra1_length);
    if (mapping_status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        ninlil_v1_lab_radio_link_status_t local =
            map_mapping_status(link,
                expected_port != NULL ? expected_port->pair_slot : pair_slot,
                mapping_status);
        clear_bytes(nra1, sizeof(nra1));
        return step_status_to_fabric(local);
    }
    original_flow = nra1[4] == NINLIL_NRA1_KIND_RECEIPT
        ? opposite_flow(radio_flow)
        : radio_flow;
    if (!flow_valid(radio_flow) || !flow_valid(original_flow)) {
        clear_bytes(nra1, sizeof(nra1));
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    port = &link->ports[route_index(pair_slot, original_flow)];
    if (!port_valid(port)
        || (expected_port != NULL && expected_port != port)) {
        clear_bytes(nra1, sizeof(nra1));
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    route = &link->routes[route_index(pair_slot, radio_flow)];
    if (route->active == 0u || route->r7 == NULL
        || link->next_candidate_token == UINT64_MAX
        || link->next_tx_generation == UINT32_MAX
        || link->next_tx_generation >= (uint32_t)(UINTPTR_MAX >> 8u)) {
        clear_bytes(nra1, sizeof(nra1));
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    r7_status = ninlil_r7_frag_prod_time_authority_valid(route->r7)
        ? ninlil_r7_frag_prod_time_authority_refresh(
              route->r7, route->r7->time_owner_gen)
        : ninlil_r7_frag_prod_time_authority_mint(route->r7, NULL);
    if (r7_status != NINLIL_R7_FRAG_PROD_OK) {
        clear_bytes(nra1, sizeof(nra1));
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    ninlil_sx1262_phy_stats(link->phy, &stats);
    (void)memset(&result, 0, sizeof(result));
    candidate_token = link->next_candidate_token;
    r7_status = ninlil_r7_frag_prod_tx_single(
        route->r7,
        link->owner_token,
        candidate_token,
        nra1,
        nra1_length,
        route->e2e_context_id,
        route->hop_context_id,
        0u,
        &result);
    link->next_candidate_token += 1u;
    clear_bytes(nra1, sizeof(nra1));
    r7_held = result.edge_invoked == 0u
        && result.cleanup_class == NINLIL_R7_FRAG_CLN_ISSUED_HELD
        && route->r7->held_tx_live != 0u;
    if (!r7_held
        && (r7_status != NINLIL_R7_FRAG_PROD_OK
            || result.edge_invoked == 0u)) {
        ninlil_fabric_link_status_t failure = result.edge_invoked != 0u
            ? NINLIL_FABRIC_LINK_LOST_UNKNOWN
            : (r7_status == NINLIL_R7_FRAG_PROD_ADMISSION
                    || r7_status == NINLIL_R7_FRAG_PROD_LEDGER
                    || r7_status == NINLIL_R7_FRAG_PROD_RESOURCE
                ? NINLIL_FABRIC_LINK_WOULD_BLOCK
                : NINLIL_FABRIC_LINK_DENIED);
        clear_bytes(&result, sizeof(result));
        return failure;
    }
    link->next_tx_generation += 1u;
    (void)memset(&link->tx, 0, sizeof(link->tx));
    link->tx.active = 1u;
    link->tx.port_index = route_index(pair_slot, original_flow);
    link->tx.completion_kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    link->tx.r7_held = r7_held != 0 ? 1u : 0u;
    link->tx.r7_route_index = route_index(pair_slot, radio_flow);
    link->tx.delegated = delegated != 0u ? 1u : 0u;
    link->tx.generation = link->next_tx_generation;
    link->tx.candidate_token = candidate_token;
    link->tx.tx_ok_before = stats.tx_ok;
    link->tx.tx_timeout_before = stats.tx_timeout;
    if (permit != NULL) {
        (void)memcpy(link->tx.permit_id, permit->permit_id.bytes, 16u);
        (void)memcpy(link->tx.permit_clock_epoch_id,
            permit->clock_epoch_id.bytes, 16u);
    }
    if (out_token != NULL) {
        *out_token = make_tx_token(link->tx.generation);
    }
    clear_bytes(&result, sizeof(result));
    return NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_link_status_t radio_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;
    ninlil_v1_lab_radio_packet_link_t *link;
    ninlil_time_sample_t now;
    ninlil_fabric_link_status_t status;

    if (out_token != NULL) {
        *out_token = NULL;
    }
    if (!handle_matches(port, handle, 0) || packet == NULL
        || out_token == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    link = port->owner;
    if (!sample_now(link, &now)) {
        mark_pair_unavailable(link, port->pair_slot);
        clear_bytes(&now, sizeof(now));
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (!packet_shape_valid(port, packet, &now)) {
        clear_bytes(&now, sizeof(now));
        return NINLIL_FABRIC_LINK_DENIED;
    }
    status = start_send_common(link, port, packet->bytes, packet->length,
        packet->permit, 0u, &now, out_token);
    clear_bytes(&now, sizeof(now));
    return status;
}

static ninlil_v1_lab_radio_link_status_t progress_tx(
    ninlil_v1_lab_radio_packet_link_t *link)
{
    ninlil_r7_frag_prod_tx_result_t r7_result;
    ninlil_v1_lab_radio_route_t *route;
    ninlil_sx1262_phy_stats_t stats;
    ninlil_sx1262_error_t error;
    ninlil_sx1262_status_t status;
    ninlil_sx1262_phy_state_t state;
    int32_t r7_status;

    if (!link_valid(link) || link->tx.active == 0u || link->tx.terminal != 0u) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    if (link->tx.r7_held != 0u) {
        if (link->tx.r7_route_index >= NINLIL_V1_LAB_RADIO_LINK_PATH_MAX) {
            link->tx.terminal = 1u;
            link->tx.completion_kind =
                NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
            return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
        }
        route = &link->routes[link->tx.r7_route_index];
        if (route->active == 0u || route->r7 == NULL) {
            link->tx.terminal = 1u;
            link->tx.completion_kind =
                NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
            return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
        }
        (void)memset(&r7_result, 0, sizeof(r7_result));
        r7_status = ninlil_r7_frag_prod_tx_resume_held(
            route->r7,
            link->owner_token,
            link->tx.candidate_token,
            &r7_result);
        if (r7_result.edge_invoked == 0u
            && r7_result.cleanup_class
                == NINLIL_R7_FRAG_CLN_ISSUED_HELD
            && route->r7->held_tx_live != 0u) {
            clear_bytes(&r7_result, sizeof(r7_result));
            return NINLIL_V1_LAB_RADIO_LINK_OK;
        }
        if (r7_status != NINLIL_R7_FRAG_PROD_OK
            || r7_result.edge_invoked == 0u) {
            link->tx.terminal = 1u;
            link->tx.completion_kind = r7_result.edge_invoked != 0u
                ? NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN
                : NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
            clear_bytes(&r7_result, sizeof(r7_result));
            return NINLIL_V1_LAB_RADIO_LINK_OK;
        }
        link->tx.r7_held = 0u;
        clear_bytes(&r7_result, sizeof(r7_result));
    }
    (void)memset(&error, 0, sizeof(error));
    status = ninlil_sx1262_phy_poll(link->phy, &error);
    state = ninlil_sx1262_phy_state(link->phy);
    ninlil_sx1262_phy_stats(link->phy, &stats);
    if (stats.tx_ok > link->tx.tx_ok_before) {
        link->tx.terminal = 1u;
        link->tx.completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    if (status != NINLIL_SX1262_OK
        || state == NINLIL_SX1262_PHY_STATE_FAULT) {
        link->tx.terminal = 1u;
        link->tx.completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
        mark_all_unavailable(link);
        return NINLIL_V1_LAB_RADIO_LINK_PHY;
    }
    if (stats.tx_timeout > link->tx.tx_timeout_before) {
        link->tx.terminal = 1u;
        link->tx.completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    if (state != NINLIL_SX1262_PHY_STATE_TX_ACTIVE
        && state != NINLIL_SX1262_PHY_STATE_TX_ARMED) {
        link->tx.terminal = 1u;
        link->tx.completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
        return NINLIL_V1_LAB_RADIO_LINK_PHY;
    }
    return NINLIL_V1_LAB_RADIO_LINK_OK;
}

static ninlil_fabric_link_status_t radio_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;
    ninlil_v1_lab_radio_packet_link_t *link;

    if (out_completion != NULL) {
        (void)memset(out_completion, 0, sizeof(*out_completion));
    }
    if (!handle_matches(port, handle, 1) || out_completion == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    link = port->owner;
    if (!tx_token_matches(link, port, token)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (link->tx.terminal == 0u) {
        (void)progress_tx(link);
    }
    out_completion->api_version = NINLIL_FABRIC_API_VERSION;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    out_completion->kind = link->tx.completion_kind;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t radio_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;
    ninlil_v1_lab_radio_packet_link_t *link;
    ninlil_sx1262_phy_state_t state;

    if (!handle_matches(port, handle, 1)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    link = port->owner;
    if (!tx_token_matches(link, port, token)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (link->tx.terminal != 0u) {
        return NINLIL_FABRIC_LINK_OK;
    }
    if (link->tx.r7_held != 0u) {
        ninlil_v1_lab_radio_route_t *route;
        int32_t cleanup_status;

        if (link->tx.r7_route_index >= NINLIL_V1_LAB_RADIO_LINK_PATH_MAX) {
            link->tx.terminal = 1u;
            link->tx.completion_kind =
                NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
            return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
        }
        route = &link->routes[link->tx.r7_route_index];
        if (route->active == 0u || route->r7 == NULL) {
            link->tx.terminal = 1u;
            link->tx.completion_kind =
                NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
            return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
        }
        cleanup_status = ninlil_r7_frag_prod_cleanup(
            route->r7,
            NINLIL_R7_FRAG_CLN_ISSUED_DRAIN,
            route->r7->held_permit_sequence);
        link->tx.terminal = 1u;
        link->tx.r7_held = 0u;
        link->tx.completion_kind = cleanup_status == NINLIL_R7_FRAG_PROD_OK
            ? NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE
            : NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
        return cleanup_status == NINLIL_R7_FRAG_PROD_OK
            ? NINLIL_FABRIC_LINK_OK
            : NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    }
    (void)progress_tx(link);
    state = ninlil_sx1262_phy_state(link->phy);
    if (state == NINLIL_SX1262_PHY_STATE_TX_ACTIVE
        || state == NINLIL_SX1262_PHY_STATE_TX_ARMED) {
        return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    }
    link->tx.terminal = 1u;
    link->tx.completion_kind =
        NINLIL_FABRIC_LINK_COMPLETION_LOST_UNKNOWN;
    return NINLIL_FABRIC_LINK_OK;
}

static void radio_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;
    ninlil_v1_lab_radio_packet_link_t *link;

    if (!handle_matches(port, handle, 1)) {
        return;
    }
    link = port->owner;
    if (!tx_token_matches(link, port, token) || link->tx.terminal == 0u) {
        return;
    }
    clear_bytes(&link->tx, sizeof(link->tx));
}

static uint32_t load_u32_be(const uint8_t bytes[4])
{
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u)
        | ((uint32_t)bytes[2] << 8u) | (uint32_t)bytes[3];
}

static ninlil_v1_lab_radio_link_status_t admit_rx(
    ninlil_v1_lab_radio_packet_link_t *link,
    const uint8_t *outer,
    uint32_t outer_length)
{
    ninlil_r7_frag_prod_rx_result_t result;
    ninlil_v1_lab_radio_route_t *route = NULL;
    ninlil_time_sample_t now;
    ninlil_v1_lab_radio_mapping_status_t mapping_status;
    uint8_t original_flow;
    uint8_t port_index;
    uint32_t mapper_token = 0u;
    uint32_t nfl1_length = 0u;
    uint32_t hop_context_id;
    uint8_t candidate_count = 0u;
    uint8_t i;
    int32_t r7_status;

    if (!link_valid(link) || outer == NULL
        || outer_length < V1_LAB_RADIO_OUTER_MIN
        || outer_length > NINLIL_SX1262_PHY_MAX_FRAME || outer[0] != 0x11u) {
        return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
    }
    hop_context_id = load_u32_be(outer + 3u);
    (void)memset(&result, 0, sizeof(result));
    r7_status = NINLIL_R7_FRAG_PROD_WIRE;
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_LINK_PATH_MAX; ++i) {
        ninlil_v1_lab_radio_route_t *candidate = &link->routes[i];

        if (candidate->active == 0u || candidate->receive == 0u
            || candidate->r7 == NULL
            || candidate->hop_context_id != hop_context_id) {
            continue;
        }
        candidate_count += 1u;
        clear_bytes(&result, sizeof(result));
        r7_status = ninlil_r7_frag_prod_rx_outer(
            candidate->r7,
            outer,
            outer_length,
            candidate->hop_context_id,
            candidate->e2e_context_id,
            &result);
        if (r7_status == NINLIL_R7_FRAG_PROD_OK) {
            route = candidate;
            break;
        }
    }
    if (candidate_count == 0u) {
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_BINDING;
    }
    if (route == NULL) {
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
    }
    if (result.published == 0u || result.body_applied == 0u) {
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    if (result.e2e_type != 1u || result.app_len < 5u
        || result.app_len > NINLIL_NRA1_APPLICATION_BODY_MAX) {
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
    }
    if (!sample_now(link, &now)) {
        mark_pair_unavailable(link, route->pair_slot);
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_FENCED;
    }
    original_flow = result.app[4] == NINLIL_NRA1_KIND_RECEIPT
        ? opposite_flow(route->flow)
        : route->flow;
    if (!flow_valid(original_flow)) {
        clear_bytes(&now, sizeof(now));
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
    }
    port_index = route_index(route->pair_slot, original_flow);
    if (link->ports[port_index].active == 0u) {
        clear_bytes(&now, sizeof(now));
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_BINDING;
    }
    if (link->next_rx_generation == UINT32_MAX
        || link->next_rx_generation >= (uint32_t)(UINTPTR_MAX >> 8u)) {
        clear_bytes(&now, sizeof(now));
        clear_bytes(&result, sizeof(result));
        return NINLIL_V1_LAB_RADIO_LINK_CAPACITY;
    }
    mapping_status = ninlil_v1_lab_radio_mapper_decode(
        &link->mapper,
        route->pair_slot,
        route->flow,
        result.app,
        result.app_len,
        &now,
        link->rx.nfl1,
        sizeof(link->rx.nfl1),
        &nfl1_length,
        &mapper_token);
    clear_bytes(&now, sizeof(now));
    clear_bytes(&result, sizeof(result));
    if (mapping_status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        return map_mapping_status(link, route->pair_slot, mapping_status);
    }
    link->next_rx_generation += 1u;
    link->rx.active = 1u;
    link->rx.port_index = port_index;
    link->rx.generation = link->next_rx_generation;
    link->rx.mapper_receipt_token = mapper_token;
    link->rx.nfl1_length = nfl1_length;
    return NINLIL_V1_LAB_RADIO_LINK_OK;
}

ninlil_v1_lab_radio_link_status_t ninlil_v1_lab_radio_packet_link_step(
    ninlil_v1_lab_radio_packet_link_t *link)
{
    ninlil_sx1262_phy_state_t before;
    ninlil_sx1262_phy_state_t after;
    ninlil_sx1262_error_t error;
    ninlil_sx1262_rx_meta_t meta;
    ninlil_sx1262_status_t status;
    uint8_t outer[NINLIL_SX1262_PHY_MAX_FRAME];

    if (!link_valid(link)) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    if (link->tx.active != 0u) {
        ninlil_v1_lab_radio_link_status_t tx_status =
            NINLIL_V1_LAB_RADIO_LINK_OK;

        if (link->tx.terminal == 0u) {
            tx_status = progress_tx(link);
        }
        if (link->tx.delegated != 0u && link->tx.terminal != 0u) {
            clear_bytes(&link->tx, sizeof(link->tx));
        }
        return tx_status;
    }
    if (link->rx.active != 0u) {
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    before = ninlil_sx1262_phy_state(link->phy);
    if (before == NINLIL_SX1262_PHY_STATE_TX_ACTIVE
        || before == NINLIL_SX1262_PHY_STATE_TX_ARMED) {
        (void)memset(&error, 0, sizeof(error));
        status = ninlil_sx1262_phy_poll(link->phy, &error);
        if (status != NINLIL_SX1262_OK) {
            mark_all_unavailable(link);
            return NINLIL_V1_LAB_RADIO_LINK_PHY;
        }
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    if (before == NINLIL_SX1262_PHY_STATE_RX_ACTIVE) {
        (void)memset(&error, 0, sizeof(error));
        status = ninlil_sx1262_phy_poll(link->phy, &error);
        if (status != NINLIL_SX1262_OK) {
            mark_all_unavailable(link);
            return NINLIL_V1_LAB_RADIO_LINK_PHY;
        }
        after = ninlil_sx1262_phy_state(link->phy);
        if (after == NINLIL_SX1262_PHY_STATE_RX_ACTIVE) {
            return NINLIL_V1_LAB_RADIO_LINK_OK;
        }
        (void)memset(&meta, 0, sizeof(meta));
        (void)memset(outer, 0, sizeof(outer));
        status = ninlil_sx1262_phy_take_rx(
            link->phy, outer, sizeof(outer), &meta, &error);
        if (status != NINLIL_SX1262_OK) {
            clear_bytes(outer, sizeof(outer));
            mark_all_unavailable(link);
            return NINLIL_V1_LAB_RADIO_LINK_PHY;
        }
        if (meta.classification != NINLIL_SX1262_RX_OK
            || meta.length == 0u) {
            clear_bytes(outer, sizeof(outer));
            return NINLIL_V1_LAB_RADIO_LINK_OK;
        }
        status = admit_rx(link, outer, meta.length);
        clear_bytes(outer, sizeof(outer));
        return status;
    }
    if (before == NINLIL_SX1262_PHY_STATE_IDLE) {
        (void)memset(&error, 0, sizeof(error));
        status = ninlil_sx1262_phy_start_rx(
            link->phy, NINLIL_V1_LAB_RADIO_LINK_RX_TIMEOUT_MS, &error);
        if (status != NINLIL_SX1262_OK) {
            mark_all_unavailable(link);
            return NINLIL_V1_LAB_RADIO_LINK_PHY;
        }
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    mark_all_unavailable(link);
    return NINLIL_V1_LAB_RADIO_LINK_PHY;
}

ninlil_v1_lab_radio_link_status_t
ninlil_v1_lab_radio_packet_link_board_submit(
    ninlil_v1_lab_radio_packet_link_t *link,
    const uint8_t *nfl1,
    uint32_t nfl1_length)
{
    ninlil_time_sample_t now;
    ninlil_fabric_link_status_t status;

    if (!link_valid(link) || nfl1 == NULL
        || nfl1_length < NINLIL_FABRIC_PRIVATE_NFL1_STRUCTURAL_MIN
        || nfl1_length > NINLIL_V1_LAB_RADIO_NFL1_MAX) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    if (!sample_now(link, &now)) {
        mark_all_unavailable(link);
        return NINLIL_V1_LAB_RADIO_LINK_FENCED;
    }
    status = start_send_common(
        link, NULL, nfl1, nfl1_length, NULL, 1u, &now, NULL);
    clear_bytes(&now, sizeof(now));
    if (status == NINLIL_FABRIC_LINK_RETAINED
        || status == NINLIL_FABRIC_LINK_OK) {
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    if (status == NINLIL_FABRIC_LINK_WOULD_BLOCK) {
        return NINLIL_V1_LAB_RADIO_LINK_CAPACITY;
    }
    if (status == NINLIL_FABRIC_LINK_UNAVAILABLE) {
        return NINLIL_V1_LAB_RADIO_LINK_FENCED;
    }
    if (status == NINLIL_FABRIC_LINK_LOST_UNKNOWN) {
        return NINLIL_V1_LAB_RADIO_LINK_PHY;
    }
    if (status == NINLIL_FABRIC_LINK_CORRUPT) {
        return NINLIL_V1_LAB_RADIO_LINK_CORRUPT;
    }
    return NINLIL_V1_LAB_RADIO_LINK_BINDING;
}

ninlil_v1_lab_radio_link_status_t
ninlil_v1_lab_radio_packet_link_board_receive_next(
    ninlil_v1_lab_radio_packet_link_t *link,
    const uint8_t **out_nfl1,
    uint32_t *out_length,
    void **out_receive_token)
{
    if (out_nfl1 != NULL) {
        *out_nfl1 = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    if (!link_valid(link) || out_nfl1 == NULL || out_length == NULL
        || out_receive_token == NULL) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    if (link->rx.active == 0u) {
        return NINLIL_V1_LAB_RADIO_LINK_EMPTY;
    }
    if (link->rx.loaned != 0u) {
        return NINLIL_V1_LAB_RADIO_LINK_CAPACITY;
    }
    link->rx.loaned = 1u;
    *out_nfl1 = link->rx.nfl1;
    *out_length = link->rx.nfl1_length;
    *out_receive_token = make_rx_token(link->rx.generation);
    return NINLIL_V1_LAB_RADIO_LINK_OK;
}

ninlil_v1_lab_radio_link_status_t
ninlil_v1_lab_radio_packet_link_board_release_received(
    ninlil_v1_lab_radio_packet_link_t *link,
    void *receive_token,
    uint8_t accepted_local)
{
    ninlil_v1_lab_radio_path_port_t *port;
    ninlil_v1_lab_radio_mapping_status_t mapping_status;
    uint8_t pair_slot;

    if (!link_valid(link) || link->rx.port_index
            >= NINLIL_V1_LAB_RADIO_LINK_PATH_MAX
        || accepted_local > 1u) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    port = &link->ports[link->rx.port_index];
    if (!rx_token_matches(link, port, receive_token)) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    pair_slot = port->pair_slot;
    if (link->rx.mapper_receipt_token != 0u) {
        mapping_status = accepted_local != 0u
            ? ninlil_v1_lab_radio_mapper_commit_received(
                  &link->mapper, link->rx.mapper_receipt_token)
            : ninlil_v1_lab_radio_mapper_abort_received(
                  &link->mapper, link->rx.mapper_receipt_token);
        if (mapping_status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
            clear_bytes(&link->rx, sizeof(link->rx));
            return map_mapping_status(link, pair_slot, mapping_status);
        }
    }
    clear_bytes(&link->rx, sizeof(link->rx));
    return NINLIL_V1_LAB_RADIO_LINK_OK;
}

static ninlil_fabric_link_status_t radio_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;
    ninlil_v1_lab_radio_packet_link_t *link;
    ninlil_v1_lab_radio_link_status_t status;
    uint8_t port_index;

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
    link = port->owner;
    port_index = route_index(port->pair_slot, port->original_flow);
    if (link->rx.active != 0u) {
        if (link->rx.port_index != port_index) {
            return NINLIL_FABRIC_LINK_EMPTY;
        }
        if (link->rx.loaned != 0u) {
            return NINLIL_FABRIC_LINK_WOULD_BLOCK;
        }
    } else {
        status = ninlil_v1_lab_radio_packet_link_step(link);
        if (status != NINLIL_V1_LAB_RADIO_LINK_OK) {
            return step_status_to_fabric(status);
        }
        if (link->rx.active == 0u || link->rx.port_index != port_index) {
            return NINLIL_FABRIC_LINK_EMPTY;
        }
    }
    link->rx.loaned = 1u;
    *out_bytes = link->rx.nfl1;
    *out_length = link->rx.nfl1_length;
    *out_receive_token = make_rx_token(link->rx.generation);
    return NINLIL_FABRIC_LINK_OK;
}

static void radio_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;
    ninlil_v1_lab_radio_packet_link_t *link;

    if (!handle_matches(port, handle, 0)) {
        return;
    }
    link = port->owner;
    if (!rx_token_matches(link, port, receive_token)) {
        return;
    }
    (void)ninlil_v1_lab_radio_packet_link_board_release_received(
        link, receive_token, 1u);
}

static ninlil_fabric_link_status_t radio_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    ninlil_v1_lab_radio_path_port_t *port =
        (ninlil_v1_lab_radio_path_port_t *)user;

    if (out_state != NULL) {
        (void)memset(out_state, 0, sizeof(*out_state));
    }
    if (!port_valid(port) || out_state == NULL
        || (handle != NULL && !handle_matches(port, handle, 1))) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    *out_state = port->state;
    out_state->available = port->open != 0u && port->state.available != 0u
        && port->owner->mapper.pairs[port->pair_slot].fenced == 0u
        && ninlil_sx1262_phy_state(port->owner->phy)
            != NINLIL_SX1262_PHY_STATE_FAULT;
    return NINLIL_FABRIC_LINK_OK;
}

static void fill_ops(ninlil_v1_lab_radio_path_port_t *port)
{
    (void)memset(&port->ops, 0, sizeof(port->ops));
    port->ops.api_version = NINLIL_FABRIC_API_VERSION;
    port->ops.struct_size = (uint16_t)sizeof(port->ops);
    port->ops.user = port;
    port->ops.open = radio_open;
    port->ops.close = radio_close;
    port->ops.start_send = radio_start_send;
    port->ops.poll_send = radio_poll_send;
    port->ops.cancel_send = radio_cancel_send;
    port->ops.release_send = radio_release_send;
    port->ops.receive_next = radio_receive_next;
    port->ops.release_received = radio_release_received;
    port->ops.state = radio_state;
}

ninlil_v1_lab_radio_link_status_t ninlil_v1_lab_radio_packet_link_init(
    ninlil_v1_lab_radio_packet_link_t *link,
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t local_runtime_id[16],
    const ninlil_clock_ops_t *clock,
    ninlil_sx1262_phy_t *phy)
{
    ninlil_time_sample_t now;

    if (link == NULL || crypto == NULL || local_runtime_id == NULL
        || bytes_zero(local_runtime_id, 16u) || !clock_valid(clock)
        || phy == NULL) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    (void)memset(&now, 0, sizeof(now));
    if (clock->now(clock->user, &now) != NINLIL_PORT_OK
        || !sample_valid(&now)) {
        clear_bytes(&now, sizeof(now));
        return NINLIL_V1_LAB_RADIO_LINK_FENCED;
    }
    (void)memset(link, 0, sizeof(*link));
    if (ninlil_v1_lab_radio_mapper_init(
            &link->mapper, crypto, local_runtime_id)
        != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        clear_bytes(&now, sizeof(now));
        clear_bytes(link, sizeof(*link));
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    link->magic = V1_LAB_RADIO_LINK_MAGIC;
    link->owner_token = (uint64_t)(uintptr_t)link;
    if (link->owner_token == 0u) {
        link->owner_token = 1u;
    }
    link->next_candidate_token = 1u;
    link->clock = *clock;
    link->phy = phy;
    clear_bytes(&now, sizeof(now));
    return NINLIL_V1_LAB_RADIO_LINK_OK;
}

static int route_bind_valid(
    const ninlil_r7_frag_prod_bind_t *bind,
    uint32_t hop_context_id,
    uint32_t e2e_context_id)
{
    return bind != NULL && ninlil_r7_frag_prod_bind_is_inited(bind)
        && bind->n6 != NULL && bind->crypto != NULL
        && ninlil_r7_crypto_provider_validate(bind->crypto)
            == NINLIL_R7_CRYPTO_OK
        && bind->hop_data_context_id == hop_context_id
        && bind->e2e_context_id_pin == e2e_context_id
        && hop_context_id != 0u && e2e_context_id != 0u;
}

ninlil_v1_lab_radio_link_status_t
ninlil_v1_lab_radio_packet_link_install_pair(
    ninlil_v1_lab_radio_packet_link_t *link,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    ninlil_r7_frag_prod_bind_t *a_to_b,
    ninlil_r7_frag_prod_bind_t *b_to_a,
    uint8_t *out_pair_slot)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_time_sample_t now;
    ninlil_v1_lab_radio_mapping_status_t mapping_status;
    const ninlil_v1_lab_endpoint_t *local_endpoint;
    uint8_t pair_slot = 0u;
    uint8_t local_side = 0u;
    uint8_t flow;
    uint8_t i;

    if (!link_valid(link) || encoded_binding == NULL || a_to_b == NULL
        || b_to_a == NULL || out_pair_slot == NULL || link->tx.active != 0u
        || link->rx.active != 0u) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_LINK_PATH_MAX; ++i) {
        if (link->ports[i].open != 0u) {
            return NINLIL_V1_LAB_RADIO_LINK_CONFLICT;
        }
    }
    (void)memset(&binding, 0, sizeof(binding));
    if (ninlil_v1_lab_binding_decode(
            &link->mapper.crypto,
            encoded_binding,
            encoded_length,
            &binding)
            != NINLIL_V1_LAB_BINDING_OK
        || ninlil_v1_lab_binding_local_side(
               &binding, link->mapper.local_runtime_id, &local_side)
            != NINLIL_V1_LAB_BINDING_OK
        || !sample_now(link, &now)) {
        ninlil_v1_lab_binding_clear(&binding);
        return NINLIL_V1_LAB_RADIO_LINK_BINDING;
    }
    local_endpoint = local_side == NINLIL_V1_LAB_SIDE_A
        ? &binding.endpoint_a
        : &binding.endpoint_b;
    if (local_endpoint->clock_trust != NINLIL_CLOCK_TRUSTED
        || memcmp(
               local_endpoint->clock_epoch_id,
               now.clock_epoch_id.bytes,
               16u)
            != 0
        || !route_bind_valid(
            a_to_b,
            binding.a_to_b_hop_context_id,
            binding.a_to_b_e2e_context_id)
        || !route_bind_valid(
            b_to_a,
            binding.b_to_a_hop_context_id,
            binding.b_to_a_e2e_context_id)) {
        clear_bytes(&now, sizeof(now));
        ninlil_v1_lab_binding_clear(&binding);
        return NINLIL_V1_LAB_RADIO_LINK_BINDING;
    }
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_PAIR_MAX; ++i) {
        const ninlil_v1_lab_radio_pair_slot_t *existing =
            &link->mapper.pairs[i];
        if (existing->active == 0u
            || memcmp(existing->binding.pair_id, binding.pair_id, 32u) != 0) {
            continue;
        }
        if (existing->binding.raw_length != binding.raw_length
            || memcmp(
                   existing->binding.raw,
                   binding.raw,
                   binding.raw_length)
                != 0
            || existing->fenced != 0u
            || link->routes[route_index(i, NINLIL_V1_LAB_FLOW_A_TO_B)].r7
                != a_to_b
            || link->routes[route_index(i, NINLIL_V1_LAB_FLOW_B_TO_A)].r7
                != b_to_a) {
            clear_bytes(&now, sizeof(now));
            ninlil_v1_lab_binding_clear(&binding);
            return NINLIL_V1_LAB_RADIO_LINK_CONFLICT;
        }
        *out_pair_slot = i;
        clear_bytes(&now, sizeof(now));
        ninlil_v1_lab_binding_clear(&binding);
        return NINLIL_V1_LAB_RADIO_LINK_OK;
    }
    mapping_status = ninlil_v1_lab_radio_mapper_install_pair(
        &link->mapper,
        encoded_binding,
        encoded_length,
        &pair_slot);
    if (mapping_status != NINLIL_V1_LAB_RADIO_MAPPING_OK) {
        clear_bytes(&now, sizeof(now));
        ninlil_v1_lab_binding_clear(&binding);
        return map_mapping_status(link, pair_slot, mapping_status);
    }
    for (flow = NINLIL_V1_LAB_FLOW_A_TO_B;
         flow <= NINLIL_V1_LAB_FLOW_B_TO_A;
         ++flow) {
        ninlil_v1_lab_radio_route_t *route =
            &link->routes[route_index(pair_slot, flow)];
        route->active = 1u;
        route->pair_slot = pair_slot;
        route->flow = flow;
        route->receive = (uint8_t)(
            (flow == NINLIL_V1_LAB_FLOW_A_TO_B
                && local_side == NINLIL_V1_LAB_SIDE_B)
            || (flow == NINLIL_V1_LAB_FLOW_B_TO_A
                && local_side == NINLIL_V1_LAB_SIDE_A));
        route->hop_context_id = flow == NINLIL_V1_LAB_FLOW_A_TO_B
            ? binding.a_to_b_hop_context_id
            : binding.b_to_a_hop_context_id;
        route->e2e_context_id = flow == NINLIL_V1_LAB_FLOW_A_TO_B
            ? binding.a_to_b_e2e_context_id
            : binding.b_to_a_e2e_context_id;
        route->r7 = flow == NINLIL_V1_LAB_FLOW_A_TO_B ? a_to_b : b_to_a;
    }
    for (i = 0u; i < binding.service_count; ++i) {
        ninlil_v1_lab_radio_path_port_t *port;
        const ninlil_v1_lab_service_row_t *row = &binding.services[i];

        port = &link->ports[route_index(pair_slot, row->flow)];
        if (port->active != 0u) {
            continue;
        }
        port->active = 1u;
        port->pair_slot = pair_slot;
        port->original_flow = row->flow;
        port->owner = link;
        (void)memcpy(port->path_id, row->selected_path_id, 16u);
        port->state.api_version = NINLIL_FABRIC_API_VERSION;
        port->state.struct_size = (uint16_t)sizeof(port->state);
        port->state.availability_epoch = binding.pair_generation;
        (void)memcpy(
            port->state.availability_clock_epoch_id.bytes,
            local_endpoint->clock_epoch_id,
            16u);
        port->state.available_until_ms = UINT64_MAX;
        port->state.available = 1u;
        fill_ops(port);
        link->port_count += 1u;
    }
    link->route_count = (uint8_t)(link->route_count + 2u);
    *out_pair_slot = pair_slot;
    clear_bytes(&now, sizeof(now));
    ninlil_v1_lab_binding_clear(&binding);
    return NINLIL_V1_LAB_RADIO_LINK_OK;
}

ninlil_v1_lab_radio_link_status_t ninlil_v1_lab_radio_packet_link_path(
    ninlil_v1_lab_radio_packet_link_t *link,
    uint8_t pair_slot,
    uint8_t original_flow,
    const uint8_t **out_path_id,
    const ninlil_fabric_packet_link_ops_v1_t **out_ops)
{
    ninlil_v1_lab_radio_path_port_t *port;

    if (out_path_id != NULL) {
        *out_path_id = NULL;
    }
    if (out_ops != NULL) {
        *out_ops = NULL;
    }
    if (!link_valid(link) || pair_slot >= NINLIL_V1_LAB_RADIO_PAIR_MAX
        || !flow_valid(original_flow) || out_path_id == NULL
        || out_ops == NULL) {
        return NINLIL_V1_LAB_RADIO_LINK_INVALID_ARGUMENT;
    }
    port = &link->ports[route_index(pair_slot, original_flow)];
    if (port->active == 0u) {
        return NINLIL_V1_LAB_RADIO_LINK_BINDING;
    }
    *out_path_id = port->path_id;
    *out_ops = &port->ops;
    return NINLIL_V1_LAB_RADIO_LINK_OK;
}

void ninlil_v1_lab_radio_packet_link_clear(
    ninlil_v1_lab_radio_packet_link_t *link)
{
    uint8_t i;

    if (!link_valid(link) || link->tx.active != 0u || link->rx.active != 0u) {
        return;
    }
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_LINK_PATH_MAX; ++i) {
        if (link->ports[i].open != 0u) {
            return;
        }
    }
    ninlil_v1_lab_radio_mapper_clear(&link->mapper);
    clear_bytes(link, sizeof(*link));
}
