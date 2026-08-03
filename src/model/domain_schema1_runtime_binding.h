#ifndef NINLIL_MODEL_DOMAIN_SCHEMA1_RUNTIME_BINDING_H
#define NINLIL_MODEL_DOMAIN_SCHEMA1_RUNTIME_BINDING_H

/*
 * ADR-0022 private Domain schema1 runtime binding slice (format 2 + T0/T1a).
 * Feature-gated production-private API. Not installed. Not public ABI.
 * Default compile feature is OFF.
 *
 * Binding/limit/role validation follows docs/12 NINLIL-FOUNDATION-SMALL-1.
 * Implementation incomplete; design-only SPEC_ACCEPTED does not promote here.
 */

#include "runtime_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_DOMAIN_SCHEMA1_BINDING_FORMAT ((uint32_t)2u)
#define NINLIL_DOMAIN_SCHEMA1_BINDING_PAYLOAD_BYTES ((uint32_t)199u)
#define NINLIL_DOMAIN_SCHEMA1_BINDING_VALUE_BYTES ((uint32_t)215u)
#define NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT ((uint32_t)17u)
#define NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES \
    ((uint32_t)1343u)
#define NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_LOGICAL_BYTES ((uint32_t)1615u)
#define NINLIL_DOMAIN_SCHEMA1_STORAGE_PROFILE_ID_BYTES ((uint32_t)16u)
#define NINLIL_DOMAIN_SCHEMA1_MINIMUM_WRITER_GENERATION ((uint32_t)2u)
#define NINLIL_DOMAIN_SCHEMA1_STORAGE_PROFILE_REVISION ((uint32_t)1u)
#define NINLIL_DOMAIN_SCHEMA1_ROLLBACK_EPOCH ((uint64_t)1u)
#define NINLIL_DOMAIN_SCHEMA1_STORAGE_SCHEMA ((uint32_t)1u)
#define NINLIL_DOMAIN_SCHEMA1_STORAGE_OP_MAX ((uint32_t)32u)
/* Hard cap before size_t multiply of row/op arrays (testable 32-bit boundary). */
#define NINLIL_DOMAIN_SCHEMA1_COUNT_HARD_CAP ((uint32_t)65536u)

typedef enum ninlil_domain_schema1_consumer {
    NINLIL_DOMAIN_SCHEMA1_CONSUMER_CANONICAL_DOMAIN = 1,
    NINLIL_DOMAIN_SCHEMA1_CONSUMER_LAST_LAB_BINARY = 2
} ninlil_domain_schema1_consumer_t;

typedef enum ninlil_domain_schema1_t0_class {
    NINLIL_DOMAIN_SCHEMA1_T0_REJECT = 0,
    NINLIL_DOMAIN_SCHEMA1_T0_ZERO_ROW_AUTHORITY = 1
} ninlil_domain_schema1_t0_class_t;

typedef enum ninlil_domain_schema1_t1a_class {
    NINLIL_DOMAIN_SCHEMA1_T1A_CORRUPT = 0,
    NINLIL_DOMAIN_SCHEMA1_T1A_OLD = 1,
    NINLIL_DOMAIN_SCHEMA1_T1A_NEW = 2
} ninlil_domain_schema1_t1a_class_t;

typedef enum ninlil_domain_schema1_storage_op_kind {
    NINLIL_DOMAIN_SCHEMA1_OP_TX_BEGIN_READ_WRITE = 1,
    NINLIL_DOMAIN_SCHEMA1_OP_TX_BEGIN_READ_ONLY = 2,
    NINLIL_DOMAIN_SCHEMA1_OP_PUT = 3,
    NINLIL_DOMAIN_SCHEMA1_OP_ERASE = 4,
    NINLIL_DOMAIN_SCHEMA1_OP_COMMIT = 5,
    NINLIL_DOMAIN_SCHEMA1_OP_ROLLBACK = 6,
    NINLIL_DOMAIN_SCHEMA1_OP_ITER_OPEN = 7,
    NINLIL_DOMAIN_SCHEMA1_OP_ITER_NEXT_NOT_FOUND = 8,
    NINLIL_DOMAIN_SCHEMA1_OP_ITER_NEXT_ROW = 9,
    NINLIL_DOMAIN_SCHEMA1_OP_ITER_CLOSE = 10
} ninlil_domain_schema1_storage_op_kind_t;

typedef struct ninlil_domain_schema1_storage_op {
    ninlil_domain_schema1_storage_op_kind_t kind;
    uint32_t transaction_id;
} ninlil_domain_schema1_storage_op_t;

typedef struct ninlil_domain_schema1_storage_transcript {
    const ninlil_domain_schema1_storage_op_t *ops;
    uint32_t op_count;
} ninlil_domain_schema1_storage_transcript_t;

typedef struct ninlil_domain_schema1_binding {
    ninlil_model_runtime_store_binding_t common;
    uint8_t storage_profile_id[NINLIL_DOMAIN_SCHEMA1_STORAGE_PROFILE_ID_BYTES];
    uint32_t storage_profile_revision;
    uint32_t minimum_writer_generation;
    uint64_t rollback_epoch;
} ninlil_domain_schema1_binding_t;

typedef struct ninlil_domain_schema1_bootstrap_plan {
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_runtime_store_limits_t capacity_source_limits;
    uint32_t record_count;
    uint32_t encoded_key_value_bytes;
    uint32_t logical_bytes;
    /*
     * Immutable seal captured at build_bootstrap_plan. Any later mutation of
     * public plan fields (including substitution of another valid identity
     * id/limit/retention) is rejected by plan_is_canonical / record_at.
     */
    ninlil_domain_schema1_binding_t sealed_binding;
    ninlil_model_runtime_store_identity_t sealed_identity;
    ninlil_model_runtime_store_limits_t sealed_capacity_source_limits;
    uint32_t sealed_record_count;
    uint32_t sealed_encoded_key_value_bytes;
    uint32_t sealed_logical_bytes;
    uint32_t sealed_crc32c;
    uint32_t sealed_magic;
} ninlil_domain_schema1_bootstrap_plan_t;

#define NINLIL_DOMAIN_SCHEMA1_PLAN_SEAL_MAGIC ((uint32_t)0x44325331u)

typedef struct ninlil_domain_schema1_bootstrap_record {
    ninlil_model_runtime_store_key_t key;
    uint8_t value[NINLIL_DOMAIN_SCHEMA1_BINDING_VALUE_BYTES];
    uint32_t value_length;
} ninlil_domain_schema1_bootstrap_record_t;

typedef struct ninlil_domain_schema1_snapshot_row {
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
} ninlil_domain_schema1_snapshot_row_t;

/* Shared Foundation SMALL-1 role-profile validator (common fields only). */
ninlil_status_t ninlil_domain_schema1_validate_foundation_common(
    const ninlil_model_runtime_store_binding_t *common);

/* Format-2 extras + Foundation common. */
ninlil_status_t ninlil_domain_schema1_validate_binding(
    const ninlil_domain_schema1_binding_t *binding);

/* Identity flags/epochs/id shape (docs/12 local identity). */
ninlil_status_t ninlil_domain_schema1_validate_identity(
    const ninlil_model_runtime_store_identity_t *identity);

/*
 * Test-visible checked multiply.
 * count==0 => success and *out_bytes==0 (no division).
 * count>HARD_CAP or size_t overflow => fail (return 0).
 */
int ninlil_domain_schema1_checked_count_bytes(
    uint32_t count,
    size_t element_size,
    size_t *out_bytes);

ninlil_status_t ninlil_domain_schema1_encode_binding(
    const ninlil_domain_schema1_binding_t *binding,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length);

ninlil_status_t ninlil_domain_schema1_decode_binding(
    ninlil_bytes_view_t encoded,
    ninlil_domain_schema1_binding_t *out_binding);

/*
 * CANONICAL: expected create-config required; Foundation + format2 exact match.
 * LAST_LAB: full format1 decode + Foundation common validator (rejects fakes).
 */
ninlil_status_t ninlil_domain_schema1_classify_binding_open(
    ninlil_bytes_view_t encoded_value,
    ninlil_domain_schema1_consumer_t consumer,
    uint32_t writer_generation,
    const ninlil_domain_schema1_binding_t *expected);

ninlil_status_t ninlil_domain_schema1_classify_t0(
    const ninlil_domain_schema1_storage_transcript_t *transcript,
    ninlil_domain_schema1_t0_class_t *out_class);

ninlil_status_t ninlil_domain_schema1_build_bootstrap_plan(
    const ninlil_domain_schema1_binding_t *binding,
    const ninlil_model_runtime_store_identity_t *identity,
    ninlil_domain_schema1_bootstrap_plan_t *out_plan);

ninlil_status_t ninlil_domain_schema1_bootstrap_record_at(
    const ninlil_domain_schema1_bootstrap_plan_t *plan,
    uint32_t index,
    ninlil_domain_schema1_bootstrap_record_t *out_record);

ninlil_status_t ninlil_domain_schema1_classify_t1a_commit_unknown(
    const ninlil_domain_schema1_bootstrap_plan_t *expected_plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_t1a_class_t *out_class);

#ifdef __cplusplus
}
#endif

#endif
