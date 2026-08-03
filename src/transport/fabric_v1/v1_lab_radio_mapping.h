#ifndef NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_RADIO_MAPPING_H
#define NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_RADIO_MAPPING_H

/* Private fixed-capacity NFL1 <-> NRA1 mapping from ADR-0035/0036. */

#include "nra1_codec.h"
#include "v1_lab_binding.h"

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_V1_LAB_RADIO_PAIR_MAX ((uint8_t)2u)
#define NINLIL_V1_LAB_RADIO_CORRELATION_MAX ((uint8_t)4u)
#define NINLIL_V1_LAB_RADIO_NFL1_MAX ((uint32_t)760u)
#define NINLIL_V1_LAB_RADIO_CORRELATION_MS ((uint64_t)30000u)

typedef uint32_t ninlil_v1_lab_radio_mapping_status_t;
#define NINLIL_V1_LAB_RADIO_MAPPING_OK \
    ((ninlil_v1_lab_radio_mapping_status_t)0u)
#define NINLIL_V1_LAB_RADIO_MAPPING_INVALID_ARGUMENT \
    ((ninlil_v1_lab_radio_mapping_status_t)1u)
#define NINLIL_V1_LAB_RADIO_MAPPING_BINDING \
    ((ninlil_v1_lab_radio_mapping_status_t)2u)
#define NINLIL_V1_LAB_RADIO_MAPPING_UNSUPPORTED \
    ((ninlil_v1_lab_radio_mapping_status_t)3u)
#define NINLIL_V1_LAB_RADIO_MAPPING_CORRUPT \
    ((ninlil_v1_lab_radio_mapping_status_t)4u)
#define NINLIL_V1_LAB_RADIO_MAPPING_CAPACITY \
    ((ninlil_v1_lab_radio_mapping_status_t)5u)
#define NINLIL_V1_LAB_RADIO_MAPPING_CONFLICT \
    ((ninlil_v1_lab_radio_mapping_status_t)6u)
#define NINLIL_V1_LAB_RADIO_MAPPING_NOT_FOUND \
    ((ninlil_v1_lab_radio_mapping_status_t)7u)
#define NINLIL_V1_LAB_RADIO_MAPPING_FENCED \
    ((ninlil_v1_lab_radio_mapping_status_t)8u)

typedef struct ninlil_v1_lab_radio_pair_slot {
    uint8_t active;
    uint8_t fenced;
    uint8_t local_side;
    uint8_t has_last_now;
    uint64_t last_now_ms;
    ninlil_v1_lab_binding_t binding;
} ninlil_v1_lab_radio_pair_slot_t;

typedef struct ninlil_v1_lab_radio_correlation {
    uint8_t active;
    uint8_t pair_slot;
    uint8_t original_flow;
    uint8_t service_slot;
    uint8_t required_evidence;
    uint8_t receipt_pending;
    uint8_t pending_stage;
    uint8_t reserved_zero;
    uint32_t receipt_token;
    uint64_t expires_at_ms;
    uint8_t transaction_id[16];
    uint8_t attempt_id[16];
    uint32_t nfl1_length;
    uint8_t nfl1[NINLIL_V1_LAB_RADIO_NFL1_MAX];
} ninlil_v1_lab_radio_correlation_t;

typedef struct ninlil_v1_lab_radio_mapper {
    uint32_t magic;
    ninlil_r7_crypto_provider crypto;
    uint8_t local_runtime_id[16];
    uint32_t next_receipt_token;
    ninlil_v1_lab_radio_pair_slot_t pairs[NINLIL_V1_LAB_RADIO_PAIR_MAX];
    ninlil_v1_lab_radio_correlation_t
        correlations[NINLIL_V1_LAB_RADIO_CORRELATION_MAX];
} ninlil_v1_lab_radio_mapper_t;

ninlil_v1_lab_radio_mapping_status_t ninlil_v1_lab_radio_mapper_init(
    ninlil_v1_lab_radio_mapper_t *mapper,
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t local_runtime_id[16]);

/* Installs one exact encoded NLB1 binding and returns its fixed slot 0..1. */
ninlil_v1_lab_radio_mapping_status_t
ninlil_v1_lab_radio_mapper_install_pair(
    ninlil_v1_lab_radio_mapper_t *mapper,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    uint8_t *out_pair_slot);

ninlil_v1_lab_radio_mapping_status_t
ninlil_v1_lab_radio_mapper_remove_pair(
    ninlil_v1_lab_radio_mapper_t *mapper, uint8_t pair_slot);

/*
 * Maps a complete Fabric NFL1 packet to one compact NRA1 body. The returned
 * radio flow selects the directional authenticated R7 child.
 */
ninlil_v1_lab_radio_mapping_status_t ninlil_v1_lab_radio_mapper_encode(
    ninlil_v1_lab_radio_mapper_t *mapper,
    const uint8_t *nfl1,
    uint32_t nfl1_length,
    const ninlil_time_sample_t *now,
    uint8_t *out_pair_slot,
    uint8_t *out_radio_flow,
    uint8_t *out_nra1,
    size_t out_capacity,
    size_t *out_length);

/*
 * Decodes only after the caller authenticated the exact pair/directional R7
 * child. A non-zero Receipt token must be committed after Fabric copy/release.
 */
ninlil_v1_lab_radio_mapping_status_t ninlil_v1_lab_radio_mapper_decode(
    ninlil_v1_lab_radio_mapper_t *mapper,
    uint8_t pair_slot,
    uint8_t authenticated_radio_flow,
    const uint8_t *nra1,
    size_t nra1_length,
    const ninlil_time_sample_t *now,
    uint8_t *out_nfl1,
    uint32_t out_capacity,
    uint32_t *out_length,
    uint32_t *out_receipt_token);

ninlil_v1_lab_radio_mapping_status_t
ninlil_v1_lab_radio_mapper_commit_received(
    ninlil_v1_lab_radio_mapper_t *mapper, uint32_t receipt_token);

void ninlil_v1_lab_radio_mapper_clear(
    ninlil_v1_lab_radio_mapper_t *mapper);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_V1_LAB_RADIO_MAPPING_H */
