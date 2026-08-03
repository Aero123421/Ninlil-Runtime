#include "v1_lab_board_owner.h"

#include "v1_lab_binding.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

#define V1_LAB_BOARD_OWNER_MAGIC ((uint32_t)0x91c6a66bu)

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

static int owner_valid(const ninlil_v1_lab_board_owner_t *owner)
{
    return owner != NULL && owner->magic == V1_LAB_BOARD_OWNER_MAGIC
        && owner->active != 0u && owner->provisioner != NULL;
}

static void owner_fence(ninlil_v1_lab_board_owner_t *owner)
{
    if (owner_valid(owner)) {
        owner->fenced = 1u;
    }
}

static void configure_bind(
    ninlil_v1_lab_board_owner_t *owner,
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_n6_handle_t hop_handle,
    ninlil_n6_handle_t e2e_handle,
    uint32_t hop_context_id,
    uint32_t e2e_context_id,
    int outbound)
{
    ninlil_r7_frag_prod_bind_reset(bind);
    bind->n6 = owner->provisioner->n6;
    bind->hop_data_handle = hop_handle;
    bind->e2e_handle = e2e_handle;
    bind->hop_data_context_id = hop_context_id;
    bind->e2e_context_id_pin = e2e_context_id;
    bind->crypto = &owner->radio.mapper.crypto;
    if (outbound != 0) {
        bind->pcp = owner->pcp;
        bind->hal = owner->hal;
        (void)ninlil_r7_frag_prod_set_live(bind, &owner->live);
    }
}

static void pair_installed(
    void *user,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    const ninlil_v1_lab_n6_handles_t *handles)
{
    ninlil_v1_lab_board_owner_t *owner =
        (ninlil_v1_lab_board_owner_t *)user;
    ninlil_v1_lab_board_owner_pair_t *pair;
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_radio_link_status_t status;
    uint8_t local_side = 0u;
    uint8_t pair_slot = 0u;
    int a_to_b_outbound;

    if (!owner_valid(owner) || owner->fenced != 0u
        || encoded_binding == NULL || handles == NULL
        || owner->pair_count >= NINLIL_V1_LAB_RADIO_PAIR_MAX
        || owner->provisioner->n6 == NULL
        || ninlil_v1_lab_provisioner_is_fenced(owner->provisioner)) {
        owner_fence(owner);
        return;
    }
    (void)memset(&binding, 0, sizeof(binding));
    if (ninlil_v1_lab_binding_decode(&owner->radio.mapper.crypto,
            encoded_binding, encoded_length, &binding)
            != NINLIL_V1_LAB_BINDING_OK
        || ninlil_v1_lab_binding_local_side(&binding,
               owner->radio.mapper.local_runtime_id, &local_side)
            != NINLIL_V1_LAB_BINDING_OK) {
        ninlil_v1_lab_binding_clear(&binding);
        owner_fence(owner);
        return;
    }

    pair = &owner->pairs[owner->pair_count];
    a_to_b_outbound = local_side == NINLIL_V1_LAB_SIDE_A;
    configure_bind(owner, &pair->a_to_b, handles->a_to_b_hop,
        handles->a_to_b_e2e, binding.a_to_b_hop_context_id,
        binding.a_to_b_e2e_context_id, a_to_b_outbound);
    configure_bind(owner, &pair->b_to_a, handles->b_to_a_hop,
        handles->b_to_a_e2e, binding.b_to_a_hop_context_id,
        binding.b_to_a_e2e_context_id, !a_to_b_outbound);
    status = ninlil_v1_lab_radio_packet_link_install_pair(&owner->radio,
        encoded_binding, encoded_length, &pair->a_to_b, &pair->b_to_a,
        &pair_slot);
    if (status != NINLIL_V1_LAB_RADIO_LINK_OK
        || pair_slot != owner->pair_count) {
        ninlil_r7_frag_prod_bind_reset(&pair->a_to_b);
        ninlil_r7_frag_prod_bind_reset(&pair->b_to_a);
        ninlil_v1_lab_binding_clear(&binding);
        owner_fence(owner);
        return;
    }
    owner->pair_count += 1u;
    ninlil_v1_lab_binding_clear(&binding);
}

static uint32_t fabric_handoff(
    void *user, const uint8_t *encoded_packet, size_t encoded_length)
{
    ninlil_v1_lab_board_owner_t *owner =
        (ninlil_v1_lab_board_owner_t *)user;
    ninlil_v1_lab_radio_link_status_t status;

    if (!owner_valid(owner) || owner->fenced != 0u
        || encoded_packet == NULL || encoded_length > UINT32_MAX) {
        return NINLIL_NVB1_STATUS_REJECTED;
    }
    status = ninlil_v1_lab_radio_packet_link_board_submit(
        &owner->radio, encoded_packet, (uint32_t)encoded_length);
    if (status == NINLIL_V1_LAB_RADIO_LINK_OK) {
        return NINLIL_NVB1_STATUS_ACCEPTED_LOCAL;
    }
    if (status == NINLIL_V1_LAB_RADIO_LINK_CAPACITY) {
        return NINLIL_NVB1_STATUS_BUSY;
    }
    if (status == NINLIL_V1_LAB_RADIO_LINK_BINDING) {
        return NINLIL_NVB1_STATUS_UNSUPPORTED;
    }
    if (status == NINLIL_V1_LAB_RADIO_LINK_FENCED
        || status == NINLIL_V1_LAB_RADIO_LINK_PHY
        || status == NINLIL_V1_LAB_RADIO_LINK_CORRUPT) {
        owner_fence(owner);
    }
    return NINLIL_NVB1_STATUS_REJECTED;
}

ninlil_v1_lab_board_owner_status_t ninlil_v1_lab_board_owner_init(
    ninlil_v1_lab_board_owner_t *owner,
    const ninlil_v1_lab_board_owner_config_t *config)
{
    ninlil_v1_usb_bridge_config_t bridge_config;

    if (owner == NULL || config == NULL || config->usb_stream == NULL
        || config->provisioner == NULL || config->crypto == NULL
        || config->local_runtime_id == NULL || config->clock == NULL
        || config->phy == NULL || config->pcp == NULL || config->hal == NULL
        || config->live == NULL || config->provisioner->active == 0u
        || ninlil_v1_lab_provisioner_is_fenced(config->provisioner)) {
        return NINLIL_V1_LAB_BOARD_OWNER_INVALID_ARGUMENT;
    }
    (void)memset(owner, 0, sizeof(*owner));
    owner->magic = V1_LAB_BOARD_OWNER_MAGIC;
    owner->active = 1u;
    owner->provisioner = config->provisioner;
    owner->pcp = config->pcp;
    owner->hal = config->hal;
    owner->live = *config->live;
    if (ninlil_v1_lab_radio_packet_link_init(&owner->radio,
            config->crypto, config->local_runtime_id, config->clock,
            config->phy)
        != NINLIL_V1_LAB_RADIO_LINK_OK) {
        clear_bytes(owner, sizeof(*owner));
        return NINLIL_V1_LAB_BOARD_OWNER_RADIO;
    }
    (void)memset(&bridge_config, 0, sizeof(bridge_config));
    bridge_config.role = NINLIL_V1_USB_BRIDGE_ROLE_USB_BOARD;
    bridge_config.stream = config->usb_stream;
    bridge_config.provisioner = config->provisioner;
    bridge_config.pair_installed = pair_installed;
    bridge_config.fabric_handoff = fabric_handoff;
    bridge_config.callback_user = owner;
    if (ninlil_v1_usb_bridge_init(&owner->bridge, &bridge_config)
        != NINLIL_V1_USB_BRIDGE_OK) {
        ninlil_v1_lab_radio_packet_link_clear(&owner->radio);
        clear_bytes(owner, sizeof(*owner));
        return NINLIL_V1_LAB_BOARD_OWNER_USB;
    }
    return NINLIL_V1_LAB_BOARD_OWNER_OK;
}

static ninlil_v1_lab_board_owner_status_t complete_usb_receive(
    ninlil_v1_lab_board_owner_t *owner)
{
    ninlil_v1_usb_bridge_completion_t completion;
    ninlil_v1_usb_bridge_status_t usb_status;
    ninlil_v1_lab_radio_link_status_t radio_status;
    uint8_t accepted = 0u;

    if (owner->usb_receive_pending == 0u) {
        return NINLIL_V1_LAB_BOARD_OWNER_OK;
    }
    (void)memset(&completion, 0, sizeof(completion));
    usb_status = ninlil_v1_usb_bridge_take_completion(&owner->bridge,
        owner->usb_receive_handle, &completion);
    if (usb_status == NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
        return NINLIL_V1_LAB_BOARD_OWNER_OK;
    }
    if (usb_status != NINLIL_V1_USB_BRIDGE_OK) {
        owner_fence(owner);
        return NINLIL_V1_LAB_BOARD_OWNER_USB;
    }
    accepted = completion.reason
                == NINLIL_V1_USB_BRIDGE_COMPLETION_REMOTE_STATUS
            && completion.remote_status_code
                == NINLIL_NVB1_STATUS_ACCEPTED_LOCAL
        ? 1u
        : 0u;
    radio_status = ninlil_v1_lab_radio_packet_link_board_release_received(
        &owner->radio, owner->radio_receive_token, accepted);
    clear_bytes(&owner->usb_receive_handle,
        sizeof(owner->usb_receive_handle));
    owner->radio_receive_token = NULL;
    owner->usb_receive_pending = 0u;
    if (radio_status != NINLIL_V1_LAB_RADIO_LINK_OK) {
        owner_fence(owner);
        return NINLIL_V1_LAB_BOARD_OWNER_RADIO;
    }
    return NINLIL_V1_LAB_BOARD_OWNER_OK;
}

static ninlil_v1_lab_board_owner_status_t map_bridge_step(
    ninlil_v1_usb_bridge_status_t status)
{
    if (status == NINLIL_V1_USB_BRIDGE_OK
        || status == NINLIL_V1_USB_BRIDGE_WOULD_BLOCK) {
        return NINLIL_V1_LAB_BOARD_OWNER_OK;
    }
    if (status == NINLIL_V1_USB_BRIDGE_LINK_DOWN
        || status == NINLIL_V1_USB_BRIDGE_FENCED) {
        return NINLIL_V1_LAB_BOARD_OWNER_LINK_DOWN;
    }
    if (status == NINLIL_V1_USB_BRIDGE_BUSY) {
        return NINLIL_V1_LAB_BOARD_OWNER_BUSY;
    }
    return NINLIL_V1_LAB_BOARD_OWNER_USB;
}

ninlil_v1_lab_board_owner_status_t ninlil_v1_lab_board_owner_step(
    ninlil_v1_lab_board_owner_t *owner,
    uint64_t now_ms,
    uint32_t usb_poll_timeout_ms)
{
    ninlil_v1_lab_board_owner_status_t completion_status;
    ninlil_v1_lab_board_owner_status_t bridge_result;
    ninlil_v1_usb_bridge_status_t usb_status;
    ninlil_v1_lab_radio_link_status_t radio_status;
    const uint8_t *nfl1 = NULL;
    uint32_t nfl1_length = 0u;
    void *receive_token = NULL;

    if (!owner_valid(owner) || now_ms == 0u) {
        return NINLIL_V1_LAB_BOARD_OWNER_INVALID_ARGUMENT;
    }
    if (owner->fenced != 0u
        || ninlil_v1_lab_provisioner_is_fenced(owner->provisioner)) {
        owner_fence(owner);
        return NINLIL_V1_LAB_BOARD_OWNER_FENCED;
    }
    completion_status = complete_usb_receive(owner);
    if (completion_status != NINLIL_V1_LAB_BOARD_OWNER_OK) {
        return completion_status;
    }

    usb_status = ninlil_v1_usb_bridge_step(
        &owner->bridge, now_ms, usb_poll_timeout_ms);
    bridge_result = map_bridge_step(usb_status);
    if (bridge_result == NINLIL_V1_LAB_BOARD_OWNER_USB) {
        owner_fence(owner);
        return bridge_result;
    }

    radio_status = ninlil_v1_lab_radio_packet_link_step(&owner->radio);
    if (radio_status != NINLIL_V1_LAB_RADIO_LINK_OK) {
        owner_fence(owner);
        return radio_status == NINLIL_V1_LAB_RADIO_LINK_PHY
            ? NINLIL_V1_LAB_BOARD_OWNER_RADIO
            : NINLIL_V1_LAB_BOARD_OWNER_FENCED;
    }
    if (owner->usb_receive_pending != 0u
        || bridge_result != NINLIL_V1_LAB_BOARD_OWNER_OK) {
        return bridge_result;
    }

    radio_status = ninlil_v1_lab_radio_packet_link_board_receive_next(
        &owner->radio, &nfl1, &nfl1_length, &receive_token);
    if (radio_status == NINLIL_V1_LAB_RADIO_LINK_EMPTY) {
        return NINLIL_V1_LAB_BOARD_OWNER_OK;
    }
    if (radio_status != NINLIL_V1_LAB_RADIO_LINK_OK) {
        owner_fence(owner);
        return NINLIL_V1_LAB_BOARD_OWNER_RADIO;
    }
    if (now_ms > UINT64_MAX - NINLIL_V1_LAB_BOARD_OWNER_USB_DEADLINE_MS) {
        (void)ninlil_v1_lab_radio_packet_link_board_release_received(
            &owner->radio, receive_token, 0u);
        owner_fence(owner);
        return NINLIL_V1_LAB_BOARD_OWNER_FENCED;
    }
    usb_status = ninlil_v1_usb_bridge_submit_fabric(&owner->bridge,
        nfl1, nfl1_length,
        now_ms + NINLIL_V1_LAB_BOARD_OWNER_USB_DEADLINE_MS,
        &owner->usb_receive_handle);
    if (usb_status != NINLIL_V1_USB_BRIDGE_OK) {
        (void)ninlil_v1_lab_radio_packet_link_board_release_received(
            &owner->radio, receive_token, 0u);
        return map_bridge_step(usb_status);
    }
    owner->radio_receive_token = receive_token;
    owner->usb_receive_pending = 1u;
    return NINLIL_V1_LAB_BOARD_OWNER_OK;
}

int ninlil_v1_lab_board_owner_is_fenced(
    const ninlil_v1_lab_board_owner_t *owner)
{
    return owner_valid(owner) && owner->fenced != 0u ? 1 : 0;
}

ninlil_v1_lab_board_owner_status_t ninlil_v1_lab_board_owner_clear(
    ninlil_v1_lab_board_owner_t *owner)
{
    uint8_t i;

    if (!owner_valid(owner)) {
        return NINLIL_V1_LAB_BOARD_OWNER_INVALID_ARGUMENT;
    }
    if (owner->usb_receive_pending != 0u || owner->radio.tx.active != 0u
        || owner->radio.rx.active != 0u) {
        return NINLIL_V1_LAB_BOARD_OWNER_BUSY;
    }
    ninlil_v1_usb_bridge_clear(&owner->bridge);
    ninlil_v1_lab_radio_packet_link_clear(&owner->radio);
    for (i = 0u; i < NINLIL_V1_LAB_RADIO_PAIR_MAX; ++i) {
        ninlil_r7_frag_prod_bind_reset(&owner->pairs[i].a_to_b);
        ninlil_r7_frag_prod_bind_reset(&owner->pairs[i].b_to_a);
    }
    clear_bytes(owner, sizeof(*owner));
    return NINLIL_V1_LAB_BOARD_OWNER_OK;
}
