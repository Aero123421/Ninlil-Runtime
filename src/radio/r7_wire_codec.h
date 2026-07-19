#ifndef NINLIL_R7_WIRE_CODEC_H
#define NINLIL_R7_WIRE_CODEC_H

/*
 * R7 T1 NRW1 SINGLE pure wire codec (docs/32, ADR-0012).
 *
 * SEMANTIC: R7_T1_PRIVATE_PURE_SINGLE_CODEC_ONLY
 * SEMANTIC: R7_T1_CALLER_SUPPLIES_KEYS_IVS_COUNTERS
 * SEMANTIC: R7_T1_NO_N6_R2_R5_COMPILE_DEPENDENCY
 * SEMANTIC: R7_T1_DUAL_ENVELOPE_REQUIRED
 * SEMANTIC: R7_T1_FAILURE_CALLER_MUTATION_ZERO
 * SEMANTIC: R7_T1_LAYER_ATOMIC_PUBLISH
 * SEMANTIC: R7_T1_NO_STATE_BYPASS_COMPOSITE_API
 * SEMANTIC: R7_T1_PUBLIC_ABI_UNCHANGED
 *
 * Production-private under src/radio/. Not public ABI. Not installed.
 * No OS / heap / VLA / OpenSSL / mbedTLS / N6 / R2 / R5 / HAL headers.
 * Crypto only via ninlil_r7_crypto_* portable wrapper (docs/31).
 */

#include "r7_crypto_provider.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Exact wire domains (docs/30 §§6–7, docs/32 §3)                               */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_WIRE_PROFILE_ID ((uint8_t)0x11u)
#define NINLIL_R7_WIRE_OUTER_KIND_DATA ((uint8_t)1u)
#define NINLIL_R7_WIRE_E2E_TYPE_SINGLE ((uint8_t)1u)

#define NINLIL_R7_WIRE_OUTER_AAD_LEN ((size_t)19u)
#define NINLIL_R7_WIRE_E2E_AAD_LEN ((size_t)14u)
#define NINLIL_R7_WIRE_TAG_LEN ((size_t)16u)

#define NINLIL_R7_WIRE_APP_MIN ((size_t)1u)
#define NINLIL_R7_WIRE_APP_MAX ((size_t)190u)
#define NINLIL_R7_WIRE_E2E_BLOB_MIN ((size_t)31u)   /* 30 + 1 */
#define NINLIL_R7_WIRE_E2E_BLOB_MAX ((size_t)220u)  /* 30 + 190 */
#define NINLIL_R7_WIRE_FRAME_MIN ((size_t)66u)      /* 65 + 1 */
#define NINLIL_R7_WIRE_FRAME_MAX ((size_t)255u)     /* 65 + 190 */

/* -------------------------------------------------------------------------- */
/* Closed wire status catalog (numeric values fixed; not public/wire ABI)     */
/* -------------------------------------------------------------------------- */

#define NINLIL_R7_WIRE_OK ((int32_t)0)
#define NINLIL_R7_WIRE_INVALID_ARGUMENT ((int32_t)1)
#define NINLIL_R7_WIRE_STRUCTURAL ((int32_t)2)
#define NINLIL_R7_WIRE_LENGTH_CLASS ((int32_t)3)
#define NINLIL_R7_WIRE_CAPACITY ((int32_t)4)
#define NINLIL_R7_WIRE_ALIAS ((int32_t)5)
#define NINLIL_R7_WIRE_AUTH_FAILED ((int32_t)6)
#define NINLIL_R7_WIRE_BACKEND_FAILED ((int32_t)7)
#define NINLIL_R7_WIRE_INTERNAL_CONTRACT ((int32_t)8)

typedef int32_t ninlil_r7_wire_status;

/* Private test seam for the T1 codec's own pairwise span predicate. */
#ifdef NINLIL_R7_WIRE_TEST_BUILD
int ninlil_r7_wire_test_spans_forbidden(
    const void *a, size_t a_len, const void *b, size_t b_len);
#endif

typedef struct ninlil_r7_wire_outer_data_fields {
    uint8_t ack_requested; /* exact 0 or 1 */
    uint8_t hop_remaining;
    uint32_t hop_context_id;
    uint64_t hop_counter;
    uint16_t route_handle;
    uint16_t route_generation;
} ninlil_r7_wire_outer_data_fields;

typedef struct ninlil_r7_wire_e2e_single_fields {
    uint32_t e2e_context_id;
    uint64_t e2e_counter;
} ninlil_r7_wire_e2e_single_fields;

/* -------------------------------------------------------------------------- */
/* AAD pack / parse                                                           */
/* -------------------------------------------------------------------------- */

ninlil_r7_wire_status ninlil_r7_wire_pack_outer_data_aad(
    const ninlil_r7_wire_outer_data_fields *fields,
    uint8_t *out_aad19,
    size_t out_capacity);

ninlil_r7_wire_status ninlil_r7_wire_parse_outer_data_aad(
    const uint8_t *aad19,
    size_t aad_len,
    ninlil_r7_wire_outer_data_fields *out_fields);

ninlil_r7_wire_status ninlil_r7_wire_pack_e2e_single_aad(
    const ninlil_r7_wire_e2e_single_fields *fields,
    uint8_t *out_aad14,
    size_t out_capacity);

ninlil_r7_wire_status ninlil_r7_wire_parse_e2e_single_aad(
    const uint8_t *aad14,
    size_t aad_len,
    ninlil_r7_wire_e2e_single_fields *out_fields);

/* -------------------------------------------------------------------------- */
/* E2E SINGLE Seal / Open                                                     */
/* -------------------------------------------------------------------------- */

ninlil_r7_wire_status ninlil_r7_wire_seal_e2e_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_wire_e2e_single_fields *fields,
    const uint8_t *app,
    size_t app_len,
    uint8_t *out_blob,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_wire_status ninlil_r7_wire_open_e2e_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *blob,
    size_t blob_len,
    ninlil_r7_wire_e2e_single_fields *out_fields,
    uint8_t *out_app,
    size_t out_capacity,
    size_t *out_len);

/* -------------------------------------------------------------------------- */
/* Outer DATA/SINGLE Seal / Open                                              */
/* -------------------------------------------------------------------------- */

ninlil_r7_wire_status ninlil_r7_wire_seal_outer_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const ninlil_r7_wire_outer_data_fields *fields,
    const uint8_t *e2e_blob,
    size_t e2e_blob_len,
    uint8_t *out_frame,
    size_t out_capacity,
    size_t *out_len);

ninlil_r7_wire_status ninlil_r7_wire_open_outer_single(
    const ninlil_r7_crypto_provider *provider,
    const uint8_t key16[16],
    const uint8_t static_iv12[12],
    const uint8_t *frame,
    size_t frame_len,
    ninlil_r7_wire_outer_data_fields *out_fields,
    uint8_t *out_e2e_blob,
    size_t out_capacity,
    size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_WIRE_CODEC_H */
