/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_FABRIC_V1_NVB1_CODEC_H
#define NINLIL_TRANSPORT_FABRIC_V1_NVB1_CODEC_H

/*
 * Private V1 USB bridge envelope (ADR-0036).
 * Carried only as an NCG1 DATA payload. Not installed and not public ABI.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_NVB1_HEADER_BYTES ((size_t)16u)
#define NINLIL_NVB1_ENVELOPE_MAX ((size_t)1024u)
#define NINLIL_NVB1_PAYLOAD_MAX ((size_t)1008u)

#define NINLIL_NVB1_KIND_BINDING_SET ((uint8_t)1u)
#define NINLIL_NVB1_KIND_FABRIC_PACKET ((uint8_t)2u)
#define NINLIL_NVB1_KIND_STATUS ((uint8_t)3u)
#define NINLIL_NVB1_KIND_BOARD_INFO ((uint8_t)4u)

#define NINLIL_NVB1_BINDING_MIN ((size_t)557u)
#define NINLIL_NVB1_BINDING_MAX ((size_t)966u)
#define NINLIL_NVB1_FABRIC_MIN ((size_t)587u)
#define NINLIL_NVB1_FABRIC_MAX ((size_t)760u)
#define NINLIL_NVB1_STATUS_BYTES ((size_t)16u)
#define NINLIL_NVB1_BOARD_INFO_BYTES ((size_t)32u)

#define NINLIL_NVB1_STATUS_INSTALLED ((uint32_t)1u)
#define NINLIL_NVB1_STATUS_ACCEPTED_LOCAL ((uint32_t)2u)
#define NINLIL_NVB1_STATUS_REJECTED ((uint32_t)3u)
#define NINLIL_NVB1_STATUS_BUSY ((uint32_t)4u)
#define NINLIL_NVB1_STATUS_STORAGE_UNKNOWN ((uint32_t)5u)
#define NINLIL_NVB1_STATUS_UNSUPPORTED ((uint32_t)6u)
#define NINLIL_NVB1_STATUS_REPROVISION_REQUIRED ((uint32_t)7u)

typedef uint32_t ninlil_nvb1_status_t;
#define NINLIL_NVB1_OK ((ninlil_nvb1_status_t)0u)
#define NINLIL_NVB1_INVALID_ARGUMENT ((ninlil_nvb1_status_t)1u)
#define NINLIL_NVB1_LENGTH ((ninlil_nvb1_status_t)2u)
#define NINLIL_NVB1_STRUCTURAL ((ninlil_nvb1_status_t)3u)
#define NINLIL_NVB1_CAPACITY ((ninlil_nvb1_status_t)4u)
#define NINLIL_NVB1_ALIAS ((ninlil_nvb1_status_t)5u)

typedef struct ninlil_nvb1_envelope {
    uint8_t kind;
    uint64_t operation_id;
    const uint8_t *payload;
    size_t payload_length;
} ninlil_nvb1_envelope_t;

typedef struct ninlil_nvb1_local_status {
    uint32_t code;
    uint64_t pair_generation;
} ninlil_nvb1_local_status_t;

typedef struct ninlil_nvb1_board_info {
    uint8_t clock_epoch_id[16];
    uint64_t clock_now_ms;
    uint32_t clock_trust;
} ninlil_nvb1_board_info_t;

ninlil_nvb1_status_t ninlil_nvb1_encode(
    const ninlil_nvb1_envelope_t *envelope,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_length);

ninlil_nvb1_status_t ninlil_nvb1_decode(
    const uint8_t *encoded,
    size_t encoded_length,
    ninlil_nvb1_envelope_t *out_envelope);

ninlil_nvb1_status_t ninlil_nvb1_status_encode(
    const ninlil_nvb1_local_status_t *status,
    uint8_t out[NINLIL_NVB1_STATUS_BYTES]);

ninlil_nvb1_status_t ninlil_nvb1_status_decode(
    const uint8_t encoded[NINLIL_NVB1_STATUS_BYTES],
    ninlil_nvb1_local_status_t *out_status);

ninlil_nvb1_status_t ninlil_nvb1_board_info_encode(
    const ninlil_nvb1_board_info_t *info,
    uint8_t out[NINLIL_NVB1_BOARD_INFO_BYTES]);

ninlil_nvb1_status_t ninlil_nvb1_board_info_decode(
    const uint8_t encoded[NINLIL_NVB1_BOARD_INFO_BYTES],
    ninlil_nvb1_board_info_t *out_info);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_FABRIC_V1_NVB1_CODEC_H */
