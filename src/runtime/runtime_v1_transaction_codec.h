/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_RUNTIME_V1_TRANSACTION_CODEC_H
#define NINLIL_RUNTIME_V1_TRANSACTION_CODEC_H

/*
 * V1-LAB-private transaction snapshot codec (NTS3).
 *
 * NTS3 is deterministic and independent of C object layout, but it is not a
 * canonical Ninlil durable format, not NLR1, and not a docs/17 domain-store
 * record.  A storage namespace containing NTS3 rows MUST NOT be shared with a
 * different runtime/profile or with another durable schema.  No compatibility
 * promise is made outside the exact V1-LAB profile and schema version.
 *
 * Schema 1.2 adds ADR-0021 target-local MFDT correlation to the durable
 * per-target attempt binding/retry/timer/evidence state from schema 1.1.
 * Earlier minors are deliberately fail-closed: this pre-release LAB namespace
 * has no implicit migration and no earlier row is interpreted as schema 1.2.
 *
 * Records contain no padding, pointers, native endianness, enum width, or
 * sizeof(struct); they use network byte order, a bounded variable-length
 * body, and CRC32C over the complete header and body.
 */

#include <ninlil/version.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MAJOR ((uint16_t)1u)
#define NINLIL_RT_V1_TRANSACTION_RECORD_SCHEMA_MINOR ((uint16_t)2u)
#define NINLIL_RT_V1_TRANSACTION_RECORD_HEADER_BYTES ((uint32_t)16u)
#define NINLIL_RT_V1_TRANSACTION_RECORD_TRAILER_BYTES ((uint32_t)4u)
#define NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES ((uint32_t)4096u)

struct ninlil_rt_transaction_slot;

ninlil_status_t ninlil_rt_v1_transaction_record_encode(
    const struct ninlil_rt_transaction_slot *transaction,
    uint8_t *out_bytes,
    uint32_t out_capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_rt_v1_transaction_record_decode(
    ninlil_bytes_view_t record,
    struct ninlil_rt_transaction_slot *decode_scratch,
    struct ninlil_rt_transaction_slot *out_transaction);

ninlil_status_t ninlil_rt_v1_transaction_record_validate_envelope(
    ninlil_bytes_view_t record);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_V1_TRANSACTION_CODEC_H */
