#ifndef NINLIL_TEST_RADIO_HAL_SPY_H
#define NINLIL_TEST_RADIO_HAL_SPY_H

/*
 * Host-only spy port for R1 ninlil_radio_hal.
 *
 * Trace proves external-callback order that the spy can actually observe:
 *   DIGEST -> PERMIT_CHECK -> CONSUME -> EDGE (each exactly once on success).
 * Each event is recorded inside the corresponding callback (real observation).
 * There is no EV_ATTEMPT: HAL transmit entry is not independently instrumented
 * in R1; inventing ATTEMPT on first digest would fabricate evidence.
 *
 * Time: ctx-authoritative clock_ms (NOT caller now; NIN-CMP-003 sim only).
 * Does not import production SPI/SX1262. Not public ABI.
 * Trace is bounded; no secrets; payload full dump not recorded by default.
 */

#include "radio_hal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RADIO_HAL_SPY_TRACE_CAP ((size_t)64u)
#define NINLIL_RADIO_HAL_SPY_CONSUMED_CAP ((size_t)128u)
#define NINLIL_RADIO_HAL_SPY_SAMPLE_BYTES ((size_t)16u)

/* Semantic permit fields for single-field plan mutation tests. */
#define NINLIL_RADIO_HAL_SPY_FIELD_NONE ((uint32_t)0u)
#define NINLIL_RADIO_HAL_SPY_FIELD_HW_REV ((uint32_t)1u)
#define NINLIL_RADIO_HAL_SPY_FIELD_REG_REV ((uint32_t)2u)
#define NINLIL_RADIO_HAL_SPY_FIELD_SITE_REV ((uint32_t)3u)
#define NINLIL_RADIO_HAL_SPY_FIELD_SITE_EPOCH ((uint32_t)4u)
#define NINLIL_RADIO_HAL_SPY_FIELD_CHANNEL ((uint32_t)5u)
#define NINLIL_RADIO_HAL_SPY_FIELD_PHY_BW ((uint32_t)6u)
#define NINLIL_RADIO_HAL_SPY_FIELD_PHY_SF ((uint32_t)7u)
#define NINLIL_RADIO_HAL_SPY_FIELD_PHY_CR ((uint32_t)8u)
#define NINLIL_RADIO_HAL_SPY_FIELD_PHY_PREAMBLE ((uint32_t)9u)
#define NINLIL_RADIO_HAL_SPY_FIELD_PHY_TX_POWER ((uint32_t)10u)
#define NINLIL_RADIO_HAL_SPY_FIELD_PHY_FLAGS ((uint32_t)11u)
#define NINLIL_RADIO_HAL_SPY_FIELD_DIGEST_ALG ((uint32_t)12u)
#define NINLIL_RADIO_HAL_SPY_FIELD_FRAME_LEN ((uint32_t)13u)
#define NINLIL_RADIO_HAL_SPY_FIELD_AIRTIME ((uint32_t)14u)
#define NINLIL_RADIO_HAL_SPY_FIELD_NOT_BEFORE ((uint32_t)15u)
#define NINLIL_RADIO_HAL_SPY_FIELD_EXPIRY ((uint32_t)16u)
#define NINLIL_RADIO_HAL_SPY_FIELD_SEQ ((uint32_t)17u)
#define NINLIL_RADIO_HAL_SPY_FIELD_RESERVED ((uint32_t)18u)
#define NINLIL_RADIO_HAL_SPY_FIELD_HW_ID0 ((uint32_t)19u)
#define NINLIL_RADIO_HAL_SPY_FIELD_DIGEST0 ((uint32_t)20u)
#define NINLIL_RADIO_HAL_SPY_FIELD_TX_ID0 ((uint32_t)21u)

typedef uint32_t ninlil_radio_hal_spy_event_t;

#define NINLIL_RADIO_HAL_SPY_EV_DIGEST ((ninlil_radio_hal_spy_event_t)1u)
#define NINLIL_RADIO_HAL_SPY_EV_PERMIT_CHECK ((ninlil_radio_hal_spy_event_t)2u)
#define NINLIL_RADIO_HAL_SPY_EV_CONSUME ((ninlil_radio_hal_spy_event_t)3u)
#define NINLIL_RADIO_HAL_SPY_EV_EDGE ((ninlil_radio_hal_spy_event_t)4u)
#define NINLIL_RADIO_HAL_SPY_EV_STATUS ((ninlil_radio_hal_spy_event_t)5u)

typedef struct ninlil_radio_hal_spy_trace_record {
    uint64_t sequence;
    ninlil_radio_hal_spy_event_t event;
    ninlil_radio_hal_status_t status;
    ninlil_radio_hal_stage_t stage;
    ninlil_radio_hal_reason_t reason;
    uint32_t frame_length;
    uint64_t permit_sequence;
    uint8_t sample[NINLIL_RADIO_HAL_SPY_SAMPLE_BYTES];
    uint8_t sample_len;
    uint8_t reserved0[7];
} ninlil_radio_hal_spy_trace_record_t;

typedef struct ninlil_radio_hal_spy {
    /* Scriptable R2 seam outcomes (next call). 0 = OK. */
    ninlil_radio_hal_status_t next_validate_status;
    ninlil_radio_hal_status_t next_consume_status;
    ninlil_radio_hal_status_t next_edge_status;
    ninlil_radio_hal_status_t next_digest_status;

    /* Authoritative time domain owned by this spy (R2 seam sim). */
    uint64_t clock_ms;
    uint64_t last_validate_clock_ms;
    uint64_t last_consume_clock_ms;

    /*
     * Mutation spies (const-cast working plan). After OK return, HAL must
     * plan_matches_seal fail → edge 0. Never given seal storage by HAL.
     */
    uint32_t mutate_frame_on_validate; /* flip first byte if length>0 */
    uint32_t mutate_frame_on_digest;   /* after successful digest verify */
    uint32_t mutate_frame_on_consume;
    uint32_t mutate_permit_on_validate; /* channel/PHY fields */
    uint32_t mutate_permit_on_consume;
    /*
     * Padding-independence probe: memset working permit to poison then
     * restore every semantic field. HAL must still plan_matches_seal.
     */
    uint32_t poison_permit_padding_on_validate;
    /*
     * Single semantic field mutation on working plan (validate).
     * Values: NINLIL_RADIO_HAL_SPY_FIELD_* (0 = none).
     */
    uint32_t mutate_permit_semantic_field;
    uint32_t reenter_transmit_on_validate;
    uint32_t reenter_transmit_on_digest;
    uint32_t reenter_transmit_on_consume;
    uint32_t reenter_transmit_on_edge;
    /* True caller-buffer mutation (not working plan): set by test. */
    uint8_t *caller_frame_bytes;
    uint32_t caller_frame_len;
    uint32_t mutate_caller_frame_on_validate;
    uint8_t last_caller_frame_sample;
    uint32_t reenter_status_seen;

    /* Counters */
    uint64_t validate_calls;
    uint64_t consume_calls;
    uint64_t edge_calls;
    uint64_t digest_calls;
    uint64_t edge_bytes_total;

    /* One-shot consume table (R2 seam simulation) */
    uint64_t consumed_seqs[NINLIL_RADIO_HAL_SPY_CONSUMED_CAP];
    uint32_t consumed_count;
    uint32_t consumed_overflow;

    /* Bounded ordered trace */
    ninlil_radio_hal_spy_trace_record_t trace[NINLIL_RADIO_HAL_SPY_TRACE_CAP];
    uint32_t trace_count;
    uint32_t trace_overflow;
    uint64_t trace_seq;

    /* Optional HAL pointer for reentry tests */
    ninlil_radio_hal_t *reenter_hal;
    ninlil_radio_hal_permit_snapshot_t reenter_permit;
    ninlil_radio_hal_frame_view_t reenter_frame;

    /* Last edge metadata (no full payload) */
    uint32_t last_edge_length;
    uint64_t last_edge_permit_seq;
    uint8_t last_edge_sample[NINLIL_RADIO_HAL_SPY_SAMPLE_BYTES];
    uint8_t last_edge_sample_len;
} ninlil_radio_hal_spy_t;

void ninlil_radio_hal_spy_init(ninlil_radio_hal_spy_t *spy);

const ninlil_radio_hal_edge_ops_t *ninlil_radio_hal_spy_edge_ops(void);
const ninlil_radio_hal_permit_ops_t *ninlil_radio_hal_spy_permit_ops(void);
const ninlil_radio_hal_digest_ops_t *ninlil_radio_hal_spy_digest_ops(void);

/* Host-test digest fold (NOT production / NOT R6 wire). */
void ninlil_radio_hal_spy_digest_fold(
    const uint8_t *bytes,
    uint32_t length,
    uint8_t out_digest[NINLIL_RADIO_HAL_DIGEST_BYTES]);

size_t ninlil_radio_hal_spy_trace_count(const ninlil_radio_hal_spy_t *spy);
int ninlil_radio_hal_spy_trace_overflowed(const ninlil_radio_hal_spy_t *spy);
const ninlil_radio_hal_spy_trace_record_t *ninlil_radio_hal_spy_trace_at(
    const ninlil_radio_hal_spy_t *spy,
    size_t index);

/*
 * True iff the trace shows exactly one DIGEST, one PERMIT_CHECK, one CONSUME,
 * and one EDGE, in that order (no fabricated ATTEMPT; callback-observed only).
 */
int ninlil_radio_hal_spy_trace_has_order_success(
    const ninlil_radio_hal_spy_t *spy);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TEST_RADIO_HAL_SPY_H */
