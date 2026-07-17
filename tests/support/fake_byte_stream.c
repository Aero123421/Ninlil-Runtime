#include "fake_byte_stream.h"

#include <string.h>

static void set_err(
    ninlil_fake_byte_stream_t *fake,
    ninlil_byte_stream_error_t *out,
    ninlil_byte_stream_status_t status,
    ninlil_byte_stream_stage_t stage,
    const char *hint)
{
    ninlil_byte_stream_error_t e;

    (void)memset(&e, 0, sizeof(e));
    e.status = status;
    e.stage = stage;
    if (hint != NULL) {
        size_t i;
        for (i = 0u; i + 1u < NINLIL_BYTE_STREAM_HINT_BYTES && hint[i] != '\0';
             ++i) {
            e.hint[i] = hint[i];
        }
        e.hint[i] = '\0';
    }
    fake->last_error = e;
    if (out != NULL) {
        *out = e;
    }
}

static int owner_ok(const ninlil_fake_byte_stream_t *fake)
{
    if (!fake->enforce_owner) {
        return 1;
    }
    if (fake->link == NINLIL_BYTE_STREAM_LINK_CLOSED) {
        return 1;
    }
    return fake->caller_token == fake->owner_token;
}

static ninlil_byte_stream_status_t wrong_owner_out(
    ninlil_fake_byte_stream_t *fake,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_byte_stream_error_t e;

    (void)memset(&e, 0, sizeof(e));
    e.status = NINLIL_BYTE_STREAM_WRONG_OWNER;
    e.stage = NINLIL_BYTE_STREAM_STAGE_OWNER;
    (void)memcpy(e.hint, "wrong owner", 12);
    if (out_error != NULL) {
        *out_error = e;
    }
    (void)fake;
    return NINLIL_BYTE_STREAM_WRONG_OWNER;
}

static void bump_generation(ninlil_fake_byte_stream_t *fake)
{
    uint32_t discarded = fake->rx_len;

    fake->link_generation += 1u;
    if (fake->link_generation == 0u) {
        fake->link_generation = 1u;
    }
    fake->link = NINLIL_BYTE_STREAM_LINK_UP;
    fake->rx_head = 0u;
    fake->rx_len = 0u;
    fake->tx_head = 0u;
    fake->tx_len = 0u;
    fake->stats.generation_rx_discard_bytes = ninlil_byte_stream_sat_add_u64(
        fake->stats.generation_rx_discard_bytes, discarded);
    fake->stats.link_up_count =
        ninlil_byte_stream_sat_add_u64(fake->stats.link_up_count, 1u);
    fake->latched_events &= (ninlil_byte_stream_event_t)~NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
    fake->latched_events |= NINLIL_BYTE_STREAM_EVENT_LINK_UP;
}

static ninlil_byte_stream_status_t fake_open(
    ninlil_byte_stream_t *stream,
    const char *endpoint_token,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_fake_byte_stream_t *fake = (ninlil_fake_byte_stream_t *)stream->self;

    (void)endpoint_token;
    if (fake == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (fake->link != NINLIL_BYTE_STREAM_LINK_CLOSED) {
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_OPEN, "not closed");
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    ninlil_fake_byte_stream_open_up(fake, fake->caller_token);
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_status_t fake_close(
    ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_fake_byte_stream_t *fake = (ninlil_fake_byte_stream_t *)stream->self;

    if (fake == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!owner_ok(fake) && fake->link != NINLIL_BYTE_STREAM_LINK_CLOSED) {
        return wrong_owner_out(fake, out_error);
    }
    ninlil_fake_byte_stream_close(fake);
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_status_t fake_write(
    ninlil_byte_stream_t *stream,
    const uint8_t *data,
    uint32_t length,
    uint32_t *out_accepted,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_fake_byte_stream_t *fake = (ninlil_fake_byte_stream_t *)stream->self;
    uint32_t free_b;
    uint32_t i;

    if (fake == NULL || out_accepted == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!owner_ok(fake)) {
        return wrong_owner_out(fake, out_error);
    }
    if (fake->gen_bump_on_next_write) {
        fake->gen_bump_on_next_write = 0;
        bump_generation(fake);
    }
    if (fake->force_status != 0u) {
        ninlil_byte_stream_status_t st = fake->force_status;
        fake->force_status = 0u;
        *out_accepted = 0u;
        set_err(fake, out_error, st, NINLIL_BYTE_STREAM_STAGE_WRITE, "forced");
        return st;
    }
    if (fake->link != NINLIL_BYTE_STREAM_LINK_UP) {
        *out_accepted = 0u;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
            NINLIL_BYTE_STREAM_STAGE_WRITE, "not up");
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    if (length > 0u && data == NULL) {
        *out_accepted = 0u;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_WRITE, "null data");
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (fake->force_write_would_block_nonzero_once) {
        fake->force_write_would_block_nonzero_once = 0;
        *out_accepted = (length > 0u) ? 1u : 1u;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_WOULD_BLOCK,
            NINLIL_BYTE_STREAM_STAGE_WRITE, "forced wb nonzero");
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    if (fake->force_write_would_block) {
        *out_accepted = 0u;
        fake->stats.would_block_count =
            ninlil_byte_stream_sat_add_u64(fake->stats.would_block_count, 1u);
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_WOULD_BLOCK,
            NINLIL_BYTE_STREAM_STAGE_WRITE, "forced wb");
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }

    free_b = NINLIL_FAKE_BS_RING_BYTES - fake->tx_len;

    /* Adversarial partial OK inject (protocol violation for C4). */
    if (fake->force_partial_ok_once) {
        uint32_t n = fake->force_partial_ok_accept;
        fake->force_partial_ok_once = 0;
        fake->force_partial_ok_accept = 0u;
        if (n > length) {
            n = length;
        }
        if (n > free_b) {
            n = free_b;
        }
        if (n == 0u || n >= length) {
            n = (length > 1u && free_b > 0u) ? 1u : 0u;
            if (n >= length) {
                n = 0u;
            }
        }
        for (i = 0u; i < n; ++i) {
            uint32_t idx =
                (fake->tx_head + fake->tx_len) % NINLIL_FAKE_BS_RING_BYTES;
            fake->tx[idx] = data[i];
            fake->tx_len += 1u;
        }
        *out_accepted = n;
        fake->stats.bytes_written =
            ninlil_byte_stream_sat_add_u64(fake->stats.bytes_written, n);
        fake->stats.tx_ring_bytes = fake->tx_len;
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
        }
        return NINLIL_BYTE_STREAM_OK;
    }

    /* Normative all-or-none: full length or WOULD_BLOCK accepted=0. */
    if (length > free_b) {
        *out_accepted = 0u;
        fake->stats.would_block_count =
            ninlil_byte_stream_sat_add_u64(fake->stats.would_block_count, 1u);
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_WOULD_BLOCK,
            NINLIL_BYTE_STREAM_STAGE_WRITE, "tx full all-or-none");
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    for (i = 0u; i < length; ++i) {
        uint32_t idx = (fake->tx_head + fake->tx_len) % NINLIL_FAKE_BS_RING_BYTES;
        fake->tx[idx] = data[i];
        fake->tx_len += 1u;
    }
    *out_accepted = length;
    fake->stats.bytes_written =
        ninlil_byte_stream_sat_add_u64(fake->stats.bytes_written, length);
    fake->stats.tx_high_watermark = ninlil_byte_stream_sat_hwm_u32(
        fake->stats.tx_high_watermark, fake->tx_len);
    fake->stats.tx_ring_bytes = fake->tx_len;
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_status_t fake_read(
    ninlil_byte_stream_t *stream,
    uint8_t *out_data,
    uint32_t capacity,
    uint32_t *out_length,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_fake_byte_stream_t *fake = (ninlil_fake_byte_stream_t *)stream->self;
    uint32_t n;
    uint32_t i;

    if (fake == NULL || out_length == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!owner_ok(fake)) {
        return wrong_owner_out(fake, out_error);
    }
    if (capacity == 0u) {
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ, "capacity 0");
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (fake->force_read_ok_over_capacity_once) {
        fake->force_read_ok_over_capacity_once = 0;
        *out_length = capacity + 1u;
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
        }
        return NINLIL_BYTE_STREAM_OK;
    }
    if (fake->force_read_would_block_nonzero_once) {
        fake->force_read_would_block_nonzero_once = 0;
        *out_length = 1u;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_WOULD_BLOCK,
            NINLIL_BYTE_STREAM_STAGE_READ, "wb nonzero");
        return NINLIL_BYTE_STREAM_WOULD_BLOCK;
    }
    if (fake->gen_bump_on_next_read) {
        /*
         * TOCTOU inject: deliver available bytes under old ring, then advance
         * generation (A2 reconnect mid-read). Caller must ticket-check before
         * treating those bytes as bound-session RX.
         */
        fake->gen_bump_on_next_read = 0;
        if (out_data == NULL) {
            *out_length = 0u;
            set_err(
                fake, out_error, NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
                NINLIL_BYTE_STREAM_STAGE_READ, "null out");
            return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
        }
        n = fake->rx_len;
        if (n > capacity) {
            n = capacity;
        }
        for (i = 0u; i < n; ++i) {
            out_data[i] = fake->rx[fake->rx_head];
            fake->rx_head = (fake->rx_head + 1u) % NINLIL_FAKE_BS_RING_BYTES;
        }
        fake->rx_len -= n;
        *out_length = n;
        fake->stats.bytes_read =
            ninlil_byte_stream_sat_add_u64(fake->stats.bytes_read, n);
        bump_generation(fake);
        if (out_error != NULL) {
            (void)memset(out_error, 0, sizeof(*out_error));
        }
        return NINLIL_BYTE_STREAM_OK;
    }
    if (fake->inject_rx_overflow) {
        fake->inject_rx_overflow = 0;
        fake->stats.rx_overflow_count =
            ninlil_byte_stream_sat_add_u64(fake->stats.rx_overflow_count, 1u);
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_RX_OVERFLOW,
            NINLIL_BYTE_STREAM_STAGE_RX_RING, "inject overflow");
        return NINLIL_BYTE_STREAM_RX_OVERFLOW;
    }
    if (fake->force_status != 0u) {
        ninlil_byte_stream_status_t st = fake->force_status;
        fake->force_status = 0u;
        set_err(fake, out_error, st, NINLIL_BYTE_STREAM_STAGE_READ, "forced");
        return st;
    }
    if (fake->link == NINLIL_BYTE_STREAM_LINK_CLOSED) {
        *out_length = 0u;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_READ, "closed");
        return NINLIL_BYTE_STREAM_CLOSED;
    }
    if (fake->link == NINLIL_BYTE_STREAM_LINK_DOWN) {
        if (fake->rx_len == 0u) {
            *out_length = 0u;
            set_err(
                fake, out_error, NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
                NINLIL_BYTE_STREAM_STAGE_READ, "down empty");
            return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
        }
    } else if (fake->link != NINLIL_BYTE_STREAM_LINK_UP
        && fake->link != NINLIL_BYTE_STREAM_LINK_LISTENING) {
        *out_length = 0u;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_INVALID_STATE,
            NINLIL_BYTE_STREAM_STAGE_READ, "bad link");
        return NINLIL_BYTE_STREAM_INVALID_STATE;
    }
    if (out_data == NULL) {
        *out_length = 0u;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_INVALID_ARGUMENT,
            NINLIL_BYTE_STREAM_STAGE_READ, "null out");
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    n = fake->rx_len;
    if (n > capacity) {
        n = capacity;
    }
    for (i = 0u; i < n; ++i) {
        out_data[i] = fake->rx[fake->rx_head];
        fake->rx_head = (fake->rx_head + 1u) % NINLIL_FAKE_BS_RING_BYTES;
    }
    fake->rx_len -= n;
    *out_length = n;
    fake->stats.bytes_read =
        ninlil_byte_stream_sat_add_u64(fake->stats.bytes_read, n);
    fake->stats.rx_ring_bytes = fake->rx_len;
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_status_t fake_poll(
    ninlil_byte_stream_t *stream,
    uint32_t timeout_ms,
    ninlil_byte_stream_event_t *out_events,
    ninlil_byte_stream_error_t *out_error)
{
    ninlil_fake_byte_stream_t *fake = (ninlil_fake_byte_stream_t *)stream->self;
    ninlil_byte_stream_event_t ev = NINLIL_BYTE_STREAM_EVENT_NONE;

    (void)timeout_ms;
    if (fake == NULL || out_events == NULL) {
        return NINLIL_BYTE_STREAM_INVALID_ARGUMENT;
    }
    if (!owner_ok(fake)) {
        return wrong_owner_out(fake, out_error);
    }
    if (fake->inject_rx_overflow) {
        fake->inject_rx_overflow = 0;
        fake->stats.rx_overflow_count =
            ninlil_byte_stream_sat_add_u64(fake->stats.rx_overflow_count, 1u);
        fake->latched_events |= NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
        *out_events = NINLIL_BYTE_STREAM_EVENT_RX_OVERFLOW;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_RX_OVERFLOW,
            NINLIL_BYTE_STREAM_STAGE_RX_RING, "poll overflow");
        return NINLIL_BYTE_STREAM_RX_OVERFLOW;
    }
    if (fake->link == NINLIL_BYTE_STREAM_LINK_CLOSED) {
        *out_events = NINLIL_BYTE_STREAM_EVENT_NONE;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_CLOSED,
            NINLIL_BYTE_STREAM_STAGE_POLL, "closed");
        return NINLIL_BYTE_STREAM_CLOSED;
    }
    if (fake->link == NINLIL_BYTE_STREAM_LINK_DOWN) {
        *out_events = NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
        set_err(
            fake, out_error, NINLIL_BYTE_STREAM_ERR_LINK_DOWN,
            NINLIL_BYTE_STREAM_STAGE_POLL, "down");
        return NINLIL_BYTE_STREAM_ERR_LINK_DOWN;
    }
    if (fake->rx_len > 0u) {
        ev |= NINLIL_BYTE_STREAM_EVENT_READABLE;
    }
    if (fake->tx_len < NINLIL_FAKE_BS_RING_BYTES
        && fake->link == NINLIL_BYTE_STREAM_LINK_UP) {
        ev |= NINLIL_BYTE_STREAM_EVENT_WRITABLE;
    }
    ev |= fake->latched_events;
    fake->latched_events = NINLIL_BYTE_STREAM_EVENT_NONE;
    *out_events = ev;
    if (out_error != NULL) {
        (void)memset(out_error, 0, sizeof(*out_error));
    }
    return NINLIL_BYTE_STREAM_OK;
}

static ninlil_byte_stream_link_t fake_link(const ninlil_byte_stream_t *stream)
{
    const ninlil_fake_byte_stream_t *fake =
        (const ninlil_fake_byte_stream_t *)stream->self;
    return fake != NULL ? fake->link : NINLIL_BYTE_STREAM_LINK_CLOSED;
}

static uint64_t fake_gen(const ninlil_byte_stream_t *stream)
{
    const ninlil_fake_byte_stream_t *fake =
        (const ninlil_fake_byte_stream_t *)stream->self;
    return fake != NULL ? fake->link_generation : 0u;
}

static void fake_stats(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_stats_t *out_stats)
{
    const ninlil_fake_byte_stream_t *fake =
        (const ninlil_fake_byte_stream_t *)stream->self;
    if (out_stats == NULL) {
        return;
    }
    (void)memset(out_stats, 0, sizeof(*out_stats));
    if (fake != NULL) {
        *out_stats = fake->stats;
    }
}

static void fake_last_error(
    const ninlil_byte_stream_t *stream,
    ninlil_byte_stream_error_t *out_error)
{
    const ninlil_fake_byte_stream_t *fake =
        (const ninlil_fake_byte_stream_t *)stream->self;
    if (out_error == NULL) {
        return;
    }
    (void)memset(out_error, 0, sizeof(*out_error));
    if (fake != NULL) {
        *out_error = fake->last_error;
    }
}

static const ninlil_byte_stream_ops_t FAKE_OPS = {
    fake_open,
    fake_close,
    fake_write,
    fake_read,
    fake_poll,
    fake_link,
    fake_gen,
    fake_stats,
    fake_last_error
};

void ninlil_fake_byte_stream_init(ninlil_fake_byte_stream_t *fake)
{
    if (fake == NULL) {
        return;
    }
    (void)memset(fake, 0, sizeof(*fake));
    fake->view.ops = &FAKE_OPS;
    fake->view.self = fake;
    fake->link = NINLIL_BYTE_STREAM_LINK_CLOSED;
    fake->enforce_owner = 1;
    fake->owner_token = 1u;
    fake->caller_token = 1u;
}

void ninlil_fake_byte_stream_open_up(
    ninlil_fake_byte_stream_t *fake,
    uint32_t owner_token)
{
    if (fake == NULL) {
        return;
    }
    fake->owner_token = owner_token;
    fake->caller_token = owner_token;
    fake->link = NINLIL_BYTE_STREAM_LINK_UP;
    fake->link_generation += 1u;
    if (fake->link_generation == 0u) {
        fake->link_generation = 1u;
    }
    fake->rx_head = 0u;
    fake->rx_len = 0u;
    fake->tx_head = 0u;
    fake->tx_len = 0u;
    fake->stats.open_count =
        ninlil_byte_stream_sat_add_u64(fake->stats.open_count, 1u);
    fake->stats.link_up_count =
        ninlil_byte_stream_sat_add_u64(fake->stats.link_up_count, 1u);
    fake->latched_events |= NINLIL_BYTE_STREAM_EVENT_LINK_UP;
}

void ninlil_fake_byte_stream_close(ninlil_fake_byte_stream_t *fake)
{
    if (fake == NULL) {
        return;
    }
    fake->link = NINLIL_BYTE_STREAM_LINK_CLOSED;
    fake->rx_head = 0u;
    fake->rx_len = 0u;
    fake->tx_head = 0u;
    fake->tx_len = 0u;
    fake->stats.close_count =
        ninlil_byte_stream_sat_add_u64(fake->stats.close_count, 1u);
}

void ninlil_fake_byte_stream_link_down(ninlil_fake_byte_stream_t *fake)
{
    if (fake == NULL) {
        return;
    }
    fake->link = NINLIL_BYTE_STREAM_LINK_DOWN;
    fake->stats.link_down_count =
        ninlil_byte_stream_sat_add_u64(fake->stats.link_down_count, 1u);
    fake->latched_events |= NINLIL_BYTE_STREAM_EVENT_LINK_DOWN;
}

void ninlil_fake_byte_stream_link_up_again(ninlil_fake_byte_stream_t *fake)
{
    if (fake == NULL) {
        return;
    }
    bump_generation(fake);
}

int ninlil_fake_byte_stream_inject_rx(
    ninlil_fake_byte_stream_t *fake,
    const uint8_t *data,
    uint32_t length)
{
    uint32_t i;

    if (fake == NULL || (length > 0u && data == NULL)) {
        return 0;
    }
    if (length > NINLIL_FAKE_BS_RING_BYTES - fake->rx_len) {
        return 0;
    }
    for (i = 0u; i < length; ++i) {
        uint32_t idx = (fake->rx_head + fake->rx_len) % NINLIL_FAKE_BS_RING_BYTES;
        fake->rx[idx] = data[i];
        fake->rx_len += 1u;
    }
    fake->stats.rx_high_watermark = ninlil_byte_stream_sat_hwm_u32(
        fake->stats.rx_high_watermark, fake->rx_len);
    fake->stats.rx_ring_bytes = fake->rx_len;
    return 1;
}

uint32_t ninlil_fake_byte_stream_take_tx(
    ninlil_fake_byte_stream_t *fake,
    uint8_t *out,
    uint32_t capacity)
{
    uint32_t n;
    uint32_t i;

    if (fake == NULL || out == NULL) {
        return 0u;
    }
    n = fake->tx_len;
    if (n > capacity) {
        n = capacity;
    }
    for (i = 0u; i < n; ++i) {
        out[i] = fake->tx[fake->tx_head];
        fake->tx_head = (fake->tx_head + 1u) % NINLIL_FAKE_BS_RING_BYTES;
    }
    fake->tx_len -= n;
    fake->stats.tx_ring_bytes = fake->tx_len;
    return n;
}

void ninlil_fake_byte_stream_set_caller_token(
    ninlil_fake_byte_stream_t *fake,
    uint32_t token)
{
    if (fake != NULL) {
        fake->caller_token = token;
    }
}

void ninlil_fake_byte_stream_set_force_write_would_block(
    ninlil_fake_byte_stream_t *fake,
    int enable)
{
    if (fake != NULL) {
        fake->force_write_would_block = enable ? 1 : 0;
    }
}

void ninlil_fake_byte_stream_force_partial_ok_once(
    ninlil_fake_byte_stream_t *fake,
    uint32_t accepted)
{
    if (fake != NULL) {
        fake->force_partial_ok_once = 1;
        fake->force_partial_ok_accept = accepted;
    }
}

void ninlil_fake_byte_stream_inject_overflow(ninlil_fake_byte_stream_t *fake)
{
    if (fake != NULL) {
        fake->inject_rx_overflow = 1;
    }
}

void ninlil_fake_byte_stream_bump_gen_on_next_read(
    ninlil_fake_byte_stream_t *fake)
{
    if (fake != NULL) {
        fake->gen_bump_on_next_read = 1;
    }
}

void ninlil_fake_byte_stream_bump_gen_on_next_write(
    ninlil_fake_byte_stream_t *fake)
{
    if (fake != NULL) {
        fake->gen_bump_on_next_write = 1;
    }
}

void ninlil_fake_byte_stream_force_read_ok_over_capacity_once(
    ninlil_fake_byte_stream_t *fake)
{
    if (fake != NULL) {
        fake->force_read_ok_over_capacity_once = 1;
    }
}

void ninlil_fake_byte_stream_force_read_would_block_nonzero_once(
    ninlil_fake_byte_stream_t *fake)
{
    if (fake != NULL) {
        fake->force_read_would_block_nonzero_once = 1;
    }
}

void ninlil_fake_byte_stream_force_write_would_block_nonzero_once(
    ninlil_fake_byte_stream_t *fake)
{
    if (fake != NULL) {
        fake->force_write_would_block_nonzero_once = 1;
    }
}
