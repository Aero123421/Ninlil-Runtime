#include "c5_lab_radio_path.h"

#include "airtime_calculator.h"
#include "v1_frame_manifest.h"

#include <string.h>

#define NINLIL_C5_LAB_RADIO_MAGIC ((uint32_t)0x4F444135u) /* '5ADO' LE */

struct ninlil_c5_lab_radio {
    uint32_t magic;
    uint32_t lifecycle;
    ninlil_c3_lab_context_store_t *store;
    ninlil_c6_lab_t *c6;
    ninlil_c5_lab_radio_channel_t *rx_channel;
    ninlil_c5_lab_radio_stats_t stats;
};

_Static_assert(
    sizeof(ninlil_c5_lab_radio_t) <= NINLIL_C5_LAB_RADIO_OBJECT_BYTES,
    "c5_lab_radio object exceeds OBJECT_BYTES ceiling");

const char *ninlil_c5_lab_mac_owner_label(void)
{
    return NINLIL_C5_LAB_MAC_OWNER_LABEL;
}

void ninlil_c5_lab_radio_channel_init(ninlil_c5_lab_radio_channel_t *channel)
{
    if (channel == NULL) {
        return;
    }
    (void)memset(channel, 0, sizeof(*channel));
}

int ninlil_c5_lab_radio_channel_deliver(
    ninlil_c5_lab_radio_channel_t *channel,
    const uint8_t *frame,
    uint32_t frame_len)
{
    uint32_t slot;

    if (channel == NULL || frame == NULL || frame_len == 0u
        || frame_len > NINLIL_C5_LAB_RADIO_FIFO_FRAME_MAX) {
        return 0;
    }
    if (channel->count >= NINLIL_C5_LAB_RADIO_FIFO_DEPTH) {
        channel->overflow_count += 1u;
        return 0;
    }
    slot = channel->tail;
    channel->tail = (channel->tail + 1u) % NINLIL_C5_LAB_RADIO_FIFO_DEPTH;
    channel->count += 1u;
    channel->frame_lens[slot] = frame_len;
    (void)memcpy(channel->frames[slot], frame, frame_len);
    channel->irq_raise_count += 1u;
    return 1;
}

static int channel_pop(
    ninlil_c5_lab_radio_channel_t *channel,
    uint8_t *out,
    uint32_t out_cap,
    uint32_t *out_len)
{
    uint32_t slot;

    if (channel == NULL || out == NULL || out_len == NULL) {
        return 0;
    }
    if (channel->count == 0u) {
        return 0;
    }
    slot = channel->head;
    channel->head = (channel->head + 1u) % NINLIL_C5_LAB_RADIO_FIFO_DEPTH;
    channel->count -= 1u;
    if (channel->frame_lens[slot] > out_cap) {
        return 0;
    }
    (void)memcpy(out, channel->frames[slot], channel->frame_lens[slot]);
    *out_len = channel->frame_lens[slot];
    return 1;
}

size_t ninlil_c5_lab_radio_object_size(void)
{
    return sizeof(ninlil_c5_lab_radio_t);
}

ninlil_c5_lab_radio_status_t ninlil_c5_lab_radio_init_object(
    ninlil_c5_lab_radio_object_t *object,
    ninlil_c3_lab_context_store_t *store,
    ninlil_c6_lab_t *c6,
    ninlil_c5_lab_radio_channel_t *rx_channel,
    ninlil_c5_lab_radio_t **out_radio)
{
    ninlil_c5_lab_radio_t *radio;

    if (object == NULL || store == NULL || c6 == NULL || rx_channel == NULL
        || out_radio == NULL) {
        return NINLIL_C5_LAB_RADIO_INVALID_ARGUMENT;
    }
    if (sizeof(ninlil_c5_lab_radio_t) > sizeof(object->storage)) {
        return NINLIL_C5_LAB_RADIO_INVALID_STATE;
    }
    radio = (ninlil_c5_lab_radio_t *)(void *)object->storage;
    (void)memset(radio, 0, sizeof(*radio));
    radio->magic = NINLIL_C5_LAB_RADIO_MAGIC;
    radio->lifecycle = 1u;
    radio->store = store;
    radio->c6 = c6;
    radio->rx_channel = rx_channel;
    *out_radio = radio;
    return NINLIL_C5_LAB_RADIO_OK;
}

static void digest_fold_local(
    const uint8_t *bytes,
    uint32_t length,
    uint8_t out_digest[32])
{
    uint32_t i;
    (void)memset(out_digest, 0, 32u);
    for (i = 0u; i < length; ++i) {
        out_digest[i % 32u] ^= bytes[i];
    }
    out_digest[0] ^= (uint8_t)(length & 0xFFu);
    out_digest[1] ^= (uint8_t)((length >> 8) & 0xFFu);
}

ninlil_c5_lab_radio_status_t ninlil_c5_lab_radio_tx_data(
    ninlil_c5_lab_radio_t *radio,
    const uint8_t *payload,
    size_t payload_len,
    ninlil_c5_lab_radio_channel_t *peer_channel)
{
    ninlil_c3_lab_wire_send_result_t send;
    ninlil_c6_lab_error_t c6_err;
    ninlil_c6_lab_stats_t c6_stats;
    ninlil_r5_issue_plan_t plan;
    ninlil_c6_lab_status_t c6_st;
    uint64_t spi_before;
    uint64_t spi_after;
    uint8_t tx_frame[NINLIL_C3_LAB_WIRE_FRAME_MAX];

    if (radio == NULL || radio->magic != NINLIL_C5_LAB_RADIO_MAGIC
        || payload == NULL || payload_len == 0u) {
        return NINLIL_C5_LAB_RADIO_INVALID_ARGUMENT;
    }
    radio->stats.tx_attempts += 1u;
    if (ninlil_c3_lab_wire_seal_data(
            radio->store, payload, payload_len, 1u, &send)
        != NINLIL_C3_LAB_OK) {
        return NINLIL_C5_LAB_RADIO_INVALID_STATE;
    }
    if (send.frame_len > sizeof(tx_frame)) {
        return NINLIL_C5_LAB_RADIO_INVALID_STATE;
    }
    (void)memcpy(tx_frame, send.frame, send.frame_len);
    (void)memset(&plan, 0, sizeof(plan));
    plan.frame_bytes = tx_frame;
    plan.frame_byte_length = (uint32_t)send.frame_len;
    digest_fold_local(tx_frame, plan.frame_byte_length, plan.frame_digest);
    plan.frame_digest_algorithm = 1u;
    plan.airtime_in.sf = 7u;
    plan.airtime_in.cr = 1u;
    plan.airtime_in.header_implicit = 0u;
    plan.airtime_in.crc_on = 1u;
    plan.airtime_in.ldro = NINLIL_AIRTIME_LDRO_OFF;
    plan.airtime_in.payload_len_bytes = (uint8_t)send.frame_len;
    plan.airtime_in.preamble_len_symbols = 8u;
    plan.airtime_in.bw_hz = 125000u;
    plan.not_before_ms = 0u;
    plan.expiry_ms = 600000u;
    ninlil_c6_lab_stats(radio->c6, &c6_stats);
    spi_before = c6_stats.spi_tx_count;
    c6_st = ninlil_c6_lab_transmit(
        radio->c6,
        NINLIL_V1_FRAME_R7_HOP_DATA,
        &plan,
        &c6_err);
    ninlil_c6_lab_stats(radio->c6, &c6_stats);
    spi_after = c6_stats.spi_tx_count;
    radio->stats.spi_tx_count = spi_after;
    if (c6_st != NINLIL_C6_LAB_OK || spi_after <= spi_before) {
        radio->stats.permit_fail += 1u;
        return NINLIL_C5_LAB_RADIO_PERMIT_DENIED;
    }
    radio->stats.tx_ok += 1u;
    if (peer_channel != NULL) {
        (void)ninlil_c5_lab_radio_channel_deliver(
            peer_channel,
            send.frame,
            (uint32_t)send.frame_len);
    }
    return NINLIL_C5_LAB_RADIO_OK;
}

ninlil_c5_lab_radio_status_t ninlil_c5_lab_radio_irq_rx_admit(
    ninlil_c5_lab_radio_t *radio,
    uint8_t *out_payload,
    size_t out_capacity,
    size_t *out_payload_len)
{
    uint8_t frame[NINLIL_C5_LAB_RADIO_FIFO_FRAME_MAX];
    uint32_t frame_len = 0u;
    ninlil_c3_lab_wire_recv_result_t recv;
    ninlil_c3_lab_status_t st;

    if (radio == NULL || radio->magic != NINLIL_C5_LAB_RADIO_MAGIC
        || out_payload == NULL || out_payload_len == NULL) {
        return NINLIL_C5_LAB_RADIO_INVALID_ARGUMENT;
    }
    if (!channel_pop(radio->rx_channel, frame, sizeof(frame), &frame_len)) {
        return NINLIL_C5_LAB_RADIO_FIFO_EMPTY;
    }
    radio->stats.rx_irq += 1u;
    st = ninlil_c3_lab_wire_open_data(
        radio->store, frame, frame_len, &recv);
    if (st == NINLIL_C3_LAB_REPLAY) {
        radio->stats.rx_replay += 1u;
        return NINLIL_C5_LAB_RADIO_REPLAY;
    }
    if (st == NINLIL_C3_LAB_AUTH_FAILED || st == NINLIL_C3_LAB_STRUCTURAL) {
        radio->stats.rx_auth_fail += 1u;
        return NINLIL_C5_LAB_RADIO_AUTH_FAILED;
    }
    if (st != NINLIL_C3_LAB_OK) {
        radio->stats.rx_auth_fail += 1u;
        return NINLIL_C5_LAB_RADIO_AUTH_FAILED;
    }
    if (recv.payload_len > out_capacity) {
        return NINLIL_C5_LAB_RADIO_INVALID_ARGUMENT;
    }
    (void)memcpy(out_payload, recv.payload, recv.payload_len);
    *out_payload_len = recv.payload_len;
    radio->stats.rx_admit_ok += 1u;
    return NINLIL_C5_LAB_RADIO_OK;
}

void ninlil_c5_lab_radio_stats_snapshot(
    const ninlil_c5_lab_radio_t *radio,
    ninlil_c5_lab_radio_stats_t *out_stats)
{
    if (radio == NULL || out_stats == NULL) {
        return;
    }
    *out_stats = radio->stats;
}
