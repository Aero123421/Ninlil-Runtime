/* SPDX-License-Identifier: Apache-2.0
 * Private NCL1/NCG1 adapter for MFN1 negotiation 0x34..0x35 and MFDT
 * transfer control messages 0x36..0x43.
 * Does not modify production NCL1 v2 catalog; private candidate only.
 * SEMANTIC: NOT_PUBLIC_ABI / NOT_INSTALLED / MAPPING_CANDIDATE
 */
#ifndef NINLIL_MFDT_V1_NCL1_H
#define NINLIL_MFDT_V1_NCL1_H

#include "mfdt_v1.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NCG1 DATA type (docs/19) — sole accepted MFDT control carrier. */
#define NINLIL_MFDT_V1_NCG1_DATA ((uint8_t)0x03u)

/* Exact NCL1 framing constants (unchanged envelope). */
#define NINLIL_MFDT_V1_NCL1_HEADER_BYTES ((uint16_t)26u)
#define NINLIL_MFDT_V1_NCL1_MAX_BODY     ((uint16_t)998u)
#define NINLIL_MFDT_V1_NCL1_MAX_MSG      ((uint16_t)1024u)
#define NINLIL_MFDT_V1_NCL1_LOGICAL_VER  ((uint8_t)1u)

/* 1 if type is an MFDT transfer control message (0x36..0x43). */
int ninlil_mfdt_v1_ncl1_is_transfer_type(uint8_t message_type);

/* 1 if type is MFN1 negotiation or MFDT transfer private control. */
int ninlil_mfdt_v1_ncl1_is_mfdt_type(uint8_t message_type);

/* 1 if (ncg1_type, private_type) binding is allowed (DATA only). */
int ninlil_mfdt_v1_ncl1_binding_ok(uint8_t ncg1_type, uint8_t mfdt_type);

/*
 * Encode NCL1 envelope around an MFDT body.
 * out_len = 26 + body_len. body_len must be 1..998.
 * request_id is 32-bit NCL1 field (low 32 of MFDT request_id when ≤u32 max).
 */
int ninlil_mfdt_v1_ncl1_encode(
    uint8_t mfdt_message_type, uint32_t request_id, uint32_t session_generation,
    uint64_t session_cookie, const uint8_t *mfdt_body, uint16_t body_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

/*
 * Decode NCL1 payload (NCG1 DATA body). On success:
 *  *mfdt_type, *request_id, *session_generation, *session_cookie set;
 *  *body points into payload (not copied); *body_len set.
 * Rejects non-MFDT types and non-DATA ncg1_type when ncg1_type != 0.
 */
int ninlil_mfdt_v1_ncl1_decode(
    const uint8_t *payload, size_t payload_len, uint8_t ncg1_type,
    uint8_t *mfdt_type, uint32_t *request_id, uint32_t *session_generation,
    uint64_t *session_cookie, const uint8_t **body, uint16_t *body_len);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_MFDT_V1_NCL1_H */
