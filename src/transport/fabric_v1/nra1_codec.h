/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private NRA1 v1 compact ApplicationData/Receipt body codec.
 * Authority: docs/adr/0035-v1-compact-radio-mapping.md
 *
 * Not installed. Not public ABI. No heap, no VLA, no crypto or RF I/O.
 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_NRA1_CODEC_H
#define NINLIL_TRANSPORT_FABRIC_V1_NRA1_CODEC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_NRA1_KIND_APPLICATION ((uint8_t)1u)
#define NINLIL_NRA1_KIND_RECEIPT ((uint8_t)2u)

#define NINLIL_NRA1_APPLICATION_HEADER_BYTES ((size_t)62u)
#define NINLIL_NRA1_APPLICATION_PAYLOAD_MIN ((size_t)1u)
#define NINLIL_NRA1_APPLICATION_PAYLOAD_MAX ((size_t)128u)
#define NINLIL_NRA1_APPLICATION_BODY_MIN ((size_t)63u)
#define NINLIL_NRA1_APPLICATION_BODY_MAX ((size_t)190u)
#define NINLIL_NRA1_RECEIPT_BODY_BYTES ((size_t)46u)
#define NINLIL_NRA1_SERVICE_SLOT_MIN ((uint8_t)1u)
#define NINLIL_NRA1_SERVICE_SLOT_MAX ((uint8_t)31u)

typedef int32_t ninlil_nra1_status_t;

#define NINLIL_NRA1_OK ((ninlil_nra1_status_t)0)
#define NINLIL_NRA1_INVALID_ARGUMENT ((ninlil_nra1_status_t)1)
#define NINLIL_NRA1_STRUCTURAL ((ninlil_nra1_status_t)2)
#define NINLIL_NRA1_LENGTH ((ninlil_nra1_status_t)3)
#define NINLIL_NRA1_CAPACITY ((ninlil_nra1_status_t)4)
#define NINLIL_NRA1_ALIAS ((ninlil_nra1_status_t)5)
#define NINLIL_NRA1_SEMANTIC ((ninlil_nra1_status_t)6)
#define NINLIL_NRA1_UNSUPPORTED ((ninlil_nra1_status_t)7)

typedef struct ninlil_nra1_application {
    uint8_t service_slot;
    uint8_t required_evidence;
    uint8_t transaction_id[16];
    uint8_t attempt_id[16];
    uint8_t subject[16];
    uint64_t absolute_effect_deadline_ms;
    size_t payload_len;
    uint8_t payload[NINLIL_NRA1_APPLICATION_PAYLOAD_MAX];
} ninlil_nra1_application_t;

typedef struct ninlil_nra1_receipt {
    uint8_t service_slot;
    uint8_t receipt_stage;
    uint8_t transaction_id[16];
    uint8_t attempt_id[16];
    uint64_t evidence_time_now_ms;
} ninlil_nra1_receipt_t;

ninlil_nra1_status_t ninlil_nra1_encode_application(
    const ninlil_nra1_application_t *application,
    uint8_t *out_body,
    size_t out_capacity,
    size_t *out_length);

ninlil_nra1_status_t ninlil_nra1_decode_application(
    const uint8_t *body,
    size_t body_length,
    ninlil_nra1_application_t *out_application);

ninlil_nra1_status_t ninlil_nra1_encode_receipt(
    const ninlil_nra1_receipt_t *receipt,
    uint8_t *out_body,
    size_t out_capacity,
    size_t *out_length);

ninlil_nra1_status_t ninlil_nra1_decode_receipt(
    const uint8_t *body,
    size_t body_length,
    ninlil_nra1_receipt_t *out_receipt);

/* Family checks occur only after the authenticated service slot is resolved. */
ninlil_nra1_status_t ninlil_nra1_validate_application_family(
    const ninlil_nra1_application_t *application,
    uint32_t family);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_NRA1_CODEC_H */
