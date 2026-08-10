/* SPDX-License-Identifier: Apache-2.0 */
/* Private PA-S3b1 post-admission NAR1 candidate. Not installed ABI. */
#ifndef NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_PA_S3_NAR1_REASSEMBLY_H
#define NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_PA_S3_NAR1_REASSEMBLY_H

#include <ninlil/version.h>

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_PA_S3_NAR1_PRIVATE __attribute__((visibility("hidden")))
#else
#define NINLIL_PA_S3_NAR1_PRIVATE
#endif

#define NINLIL_PA_S3_NAR1_PACKET_BYTES_MAX ((uint32_t)192u)
#define NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX ((uint32_t)600u)
#define NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES ((uint32_t)32u)

typedef uint32_t ninlil_pa_s3_nar1_outcome_v1_t;
#define NINLIL_PA_S3_NAR1_PROGRESS ((ninlil_pa_s3_nar1_outcome_v1_t)1u)
#define NINLIL_PA_S3_NAR1_DUPLICATE ((ninlil_pa_s3_nar1_outcome_v1_t)2u)
#define NINLIL_PA_S3_NAR1_DELIVERED ((ninlil_pa_s3_nar1_outcome_v1_t)3u)
#define NINLIL_PA_S3_NAR1_TERMINAL ((ninlil_pa_s3_nar1_outcome_v1_t)4u)

typedef struct ninlil_pa_s3_nar1_config_v1 {
    uint64_t owner_context_id;
    uint8_t source_locator_digest[NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES];
} ninlil_pa_s3_nar1_config_v1_t;

typedef struct ninlil_pa_s3_nar1_owner_v1 {
    uint8_t record[NINLIL_PA_S3_NAR1_RECORD_BYTES_MAX];
    uint8_t source_locator_digest[NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES];
    uint8_t session_id[16];
    uint8_t record_digest[16];
    uint64_t owner_context_id;
    uint64_t exchange_generation;
    uint32_t record_sequence;
    uint32_t complete_bytes;
    uint32_t fragment_count;
    uint32_t received_mask;
    uint32_t received_count;
    uint32_t state;
    uint32_t in_call;
} ninlil_pa_s3_nar1_owner_v1_t;

/*
 * Caller-owned, zero-initialized, and serialized by exact owner_context_id.
 * One owner accepts one admitted source and one canonical NAR1 record. The
 * source digest is caller supplied in this Host candidate; live locator and
 * cookie authority are not connected. Every packet is parsed before owner
 * mutation. Exact duplicates make no progress. Any malformed, mixed, source-
 * mismatched, or conflicting packet terminally wipes the partial record.
 * `feed` requires a 600-byte disjoint output and copies exactly once only
 * after SHA-256 and contained NAC1 structural checks. Close wipes all bytes.
 */
NINLIL_PA_S3_NAR1_PRIVATE ninlil_status_t ninlil_pa_s3_nar1_owner_v1_init(
    ninlil_pa_s3_nar1_owner_v1_t *owner,
    const ninlil_pa_s3_nar1_config_v1_t *config);
NINLIL_PA_S3_NAR1_PRIVATE ninlil_status_t ninlil_pa_s3_nar1_owner_v1_feed(
    ninlil_pa_s3_nar1_owner_v1_t *owner,
    uint64_t owner_context_id,
    const uint8_t source_locator_digest[NINLIL_PA_S3_NAR1_SOURCE_DIGEST_BYTES],
    const uint8_t *packet,
    size_t packet_size,
    uint8_t *out_record,
    size_t out_record_capacity,
    size_t *out_record_size,
    ninlil_pa_s3_nar1_outcome_v1_t *out_outcome);
NINLIL_PA_S3_NAR1_PRIVATE ninlil_status_t ninlil_pa_s3_nar1_owner_v1_close(
    ninlil_pa_s3_nar1_owner_v1_t *owner,
    uint64_t owner_context_id);

#endif
