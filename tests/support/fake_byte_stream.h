#ifndef NINLIL_TEST_FAKE_BYTE_STREAM_H
#define NINLIL_TEST_FAKE_BYTE_STREAM_H

/*
 * Host-test-only C1 fake byte-stream for U3 adversarial tests.
 * Not production. Not installed. Not public ABI.
 *
 * Default write mode is normative all-or-none (C1): either full length is
 * accepted or WOULD_BLOCK with accepted==0. Adversarial injects:
 * - force_partial_ok_once: next write returns OK with accepted < length
 * - gen_bump_on_next_read / gen_bump_on_next_write: advance generation during
 *   the I/O call (A2 reconnect TOCTOU) before returning OK.
 */

#include <stddef.h>
#include <stdint.h>

#include "byte_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_FAKE_BS_RING_BYTES ((uint32_t)4096u)

typedef struct ninlil_fake_byte_stream {
    ninlil_byte_stream_t view;
    ninlil_byte_stream_link_t link;
    uint64_t link_generation;
    uint32_t owner_token;
    uint32_t caller_token;
    int enforce_owner;

    uint8_t rx[NINLIL_FAKE_BS_RING_BYTES];
    uint32_t rx_head;
    uint32_t rx_len;
    uint8_t tx[NINLIL_FAKE_BS_RING_BYTES];
    uint32_t tx_head;
    uint32_t tx_len;

    /* When non-zero, next write returns OK with this accepted (< length). */
    uint32_t force_partial_ok_accept;
    int force_partial_ok_once;
    /* When non-zero, next write returns WOULD_BLOCK without accepting. */
    int force_write_would_block;
    /* Inject RX overflow once on next poll/read. */
    int inject_rx_overflow;
    /* Advance generation once during next read / next write (TOCTOU). */
    int gen_bump_on_next_read;
    int gen_bump_on_next_write;
    /* Malformed C1 one-shots. */
    int force_read_ok_over_capacity_once;
    int force_read_would_block_nonzero_once;
    int force_write_would_block_nonzero_once;
    /* Force next read/write/poll status (0 = disabled). */
    ninlil_byte_stream_status_t force_status;

    ninlil_byte_stream_stats_t stats;
    ninlil_byte_stream_error_t last_error;
    ninlil_byte_stream_event_t latched_events;
} ninlil_fake_byte_stream_t;

void ninlil_fake_byte_stream_init(ninlil_fake_byte_stream_t *fake);

void ninlil_fake_byte_stream_open_up(
    ninlil_fake_byte_stream_t *fake,
    uint32_t owner_token);

void ninlil_fake_byte_stream_close(ninlil_fake_byte_stream_t *fake);

void ninlil_fake_byte_stream_link_down(ninlil_fake_byte_stream_t *fake);

void ninlil_fake_byte_stream_link_up_again(ninlil_fake_byte_stream_t *fake);

int ninlil_fake_byte_stream_inject_rx(
    ninlil_fake_byte_stream_t *fake,
    const uint8_t *data,
    uint32_t length);

uint32_t ninlil_fake_byte_stream_take_tx(
    ninlil_fake_byte_stream_t *fake,
    uint8_t *out,
    uint32_t capacity);

void ninlil_fake_byte_stream_set_caller_token(
    ninlil_fake_byte_stream_t *fake,
    uint32_t token);

void ninlil_fake_byte_stream_set_force_write_would_block(
    ninlil_fake_byte_stream_t *fake,
    int enable);

/* Adversarial: next write OK with accepted = min(n, free) where n < length. */
void ninlil_fake_byte_stream_force_partial_ok_once(
    ninlil_fake_byte_stream_t *fake,
    uint32_t accepted);

void ninlil_fake_byte_stream_inject_overflow(ninlil_fake_byte_stream_t *fake);

void ninlil_fake_byte_stream_bump_gen_on_next_read(
    ninlil_fake_byte_stream_t *fake);

void ninlil_fake_byte_stream_bump_gen_on_next_write(
    ninlil_fake_byte_stream_t *fake);

/*
 * Malformed C1 injects (protocol violations for C4 fail-closed tests):
 * - next read returns OK with out_length > capacity
 * - next read returns WOULD_BLOCK with out_length != 0
 * - next write returns WOULD_BLOCK with accepted != 0
 */
void ninlil_fake_byte_stream_force_read_ok_over_capacity_once(
    ninlil_fake_byte_stream_t *fake);
void ninlil_fake_byte_stream_force_read_would_block_nonzero_once(
    ninlil_fake_byte_stream_t *fake);
void ninlil_fake_byte_stream_force_write_would_block_nonzero_once(
    ninlil_fake_byte_stream_t *fake);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TEST_FAKE_BYTE_STREAM_H */
