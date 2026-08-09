/* SPDX-License-Identifier: Apache-2.0 */
/* Private PA-S3a NAS1 direct-stream candidate. Not installed ABI. */
#ifndef NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_PA_S3_NAS1_STREAM_H
#define NINLIL_RUNTIME_PRODUCTION_ATTACHMENT_V1_PA_S3_NAS1_STREAM_H

#include <ninlil/version.h>

#include <stddef.h>
#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_PA_S3_NAS1_PRIVATE __attribute__((visibility("hidden")))
#else
#define NINLIL_PA_S3_NAS1_PRIVATE
#endif

#define NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX ((uint32_t)612u)
#define NINLIL_PA_S3_NAC1_RECORD_BYTES_MAX ((uint32_t)600u)
#define NINLIL_PA_S3_NAS1_USB_STREAM ((uint32_t)1u)
#define NINLIL_PA_S3_NAS1_WIFI_STREAM ((uint32_t)2u)

typedef uint32_t ninlil_pa_s3_nas1_outcome_v1_t;
#define NINLIL_PA_S3_NAS1_NEED_MORE ((ninlil_pa_s3_nas1_outcome_v1_t)1u)
#define NINLIL_PA_S3_NAS1_DELIVERED ((ninlil_pa_s3_nas1_outcome_v1_t)2u)
#define NINLIL_PA_S3_NAS1_CLOSE ((ninlil_pa_s3_nas1_outcome_v1_t)3u)

typedef struct ninlil_pa_s3_nas1_config_v1 {
    uint64_t owner_context_id;
    uint8_t session_id[16];
    uint8_t carrier_binding_digest[32];
    uint64_t exchange_generation;
    uint32_t carrier_class;
    uint32_t kind;
    uint32_t record_sequence;
} ninlil_pa_s3_nas1_config_v1_t;

typedef struct ninlil_pa_s3_nas1_owner_v1 {
    uint8_t buffer[NINLIL_PA_S3_NAS1_WRAPPER_BYTES_MAX];
    uint8_t session_id[16];
    uint8_t carrier_binding_digest[32];
    uint64_t owner_context_id;
    uint64_t exchange_generation;
    uint32_t buffered_bytes;
    uint32_t wrapper_bytes;
    uint32_t carrier_class;
    uint32_t kind;
    uint32_t record_sequence;
    uint32_t state;
    uint32_t in_call;
} ninlil_pa_s3_nas1_owner_v1_t;

/*
 * Caller-owned and serialized by exact owner_context_id. Zero-initialize
 * before init and close before reuse. One owner accepts one NAS1 wrapper.
 * `feed` requires a 600-byte caller output on every call, changes its bytes
 * only on exact delivery, and never rescans after malformed input. Close wipes
 * the complete owner. This is structural direct-stream parsing only: no socket,
 * admission, credential, EDHOC state, NAR1, Composition, or availability.
 */
NINLIL_PA_S3_NAS1_PRIVATE ninlil_status_t ninlil_pa_s3_nas1_owner_v1_init(
    ninlil_pa_s3_nas1_owner_v1_t *owner,
    const ninlil_pa_s3_nas1_config_v1_t *config);
NINLIL_PA_S3_NAS1_PRIVATE ninlil_status_t ninlil_pa_s3_nas1_owner_v1_feed(
    ninlil_pa_s3_nas1_owner_v1_t *owner,
    uint64_t owner_context_id,
    const uint8_t *bytes,
    size_t byte_count,
    uint32_t end_of_stream,
    uint8_t *out_record,
    size_t out_record_capacity,
    size_t *out_record_size,
    ninlil_pa_s3_nas1_outcome_v1_t *out_outcome);
NINLIL_PA_S3_NAS1_PRIVATE ninlil_status_t ninlil_pa_s3_nas1_owner_v1_close(
    ninlil_pa_s3_nas1_owner_v1_t *owner,
    uint64_t owner_context_id);

#endif
