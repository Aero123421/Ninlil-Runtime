#ifndef NINLIL_MODEL_RUNTIME_STORE_CODEC_INTERNAL_H
#define NINLIL_MODEL_RUNTIME_STORE_CODEC_INTERNAL_H

#include "runtime_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Codec implementation/test-only API; not an L2a2/L2b model contract.
 * All input/output ranges must be pairwise disjoint; overlap is rejected
 * without modifying them. Decode payload borrows the encoded input bytes;
 * no decoded payload storage is owned by the result.
 */
#define NINLIL_MODEL_RUNTIME_STORE_ENVELOPE_OVERHEAD ((uint32_t)16u)
#define NINLIL_MODEL_RUNTIME_STORE_MAX_PAYLOAD_BYTES ((uint32_t)65520u)

typedef struct ninlil_model_runtime_store_envelope {
    ninlil_model_runtime_store_record_type_t type;
    uint16_t version;
    ninlil_bytes_view_t payload;
    uint32_t crc32c;
} ninlil_model_runtime_store_envelope_t;

uint32_t ninlil_model_runtime_store_crc32c(
    const uint8_t *bytes,
    uint32_t length);

ninlil_status_t ninlil_model_runtime_store_encode_envelope(
    ninlil_model_runtime_store_record_type_t type,
    ninlil_bytes_view_t payload,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_model_runtime_store_decode_envelope(
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_envelope_t *out_envelope);

#ifdef __cplusplus
}
#endif

#endif
