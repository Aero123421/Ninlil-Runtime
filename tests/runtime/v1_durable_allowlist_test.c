/*
 * V1-LAB durable allowlist profile tests (unit 1a).
 * Writer gate RED probe + recovery publication rejection (4 kinds) +
 * COMMIT_UNKNOWN restart (no false success).
 */

#include "v1_durable_allowlist.h"

#include "domain_store_codec.h"
#include "runtime_internal.h"
#include "runtime_store_bootstrap.h"
#include "runtime_store_codec.h"
#include "runtime_v1_bearer_wire.h"
#include "runtime_v1_transaction_codec.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void set_header(uint16_t *version, uint16_t *size, size_t value)
{
    *version = NINLIL_ABI_VERSION;
    *size = (uint16_t)value;
}

static void set_id(ninlil_id128_t *id, uint8_t tag)
{
    uint32_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        id->bytes[index] = (uint8_t)(tag + index);
    }
}

static void set_digest(ninlil_digest256_t *digest, uint8_t tag)
{
    (void)memset(digest, 0, sizeof(*digest));
    digest->algorithm = NINLIL_DIGEST_SHA256;
    digest->bytes[sizeof(digest->bytes) - 1u] = tag;
}

static void fill_valid_bearer_state_row(
    uint8_t key[18],
    uint8_t value[48])
{
    static const uint8_t magic[8] = {
        0x4eu, 0x42u, 0x53u, 0x31u, 0x00u, 0x01u, 0x00u, 0x00u
    };
    uint32_t index;

    (void)memset(key, 0, 18u);
    (void)memset(value, 0, 48u);
    key[0] = 0x42u;
    key[1] = 0x53u;
    for (index = 0u; index < 16u; ++index) {
        key[index + 2u] = (uint8_t)(0x10u + index);
    }
    (void)memcpy(value, magic, sizeof(magic));
    value[15] = 1u;
    value[19] = 1u;
    value[24] = 0xa0u;
    value[39] = 1u;
}

static int require_bearer_state_row_rejected(
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value,
    ninlil_status_t expected_status)
{
    ninlil_bytes_view_t keys[1] = {key};
    ninlil_bytes_view_t values[1] = {value};
    ninlil_v1_durable_record_kind_t kind =
        NINLIL_V1_DURABLE_KIND_RS_BINDING;
    ninlil_v1_durable_recovery_publication_result_t result;

    REQUIRE(ninlil_rt_v1_bearer_state_marker_validate(key, value)
        == expected_status);
    REQUIRE(ninlil_v1_durable_classify_row(key, value, &kind)
        == expected_status);
    REQUIRE(kind == NINLIL_V1_DURABLE_KIND_SPINE_BEARER_STATE);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_BEARER_STATE_COMMIT,
                key,
                value)
        == expected_status);
    REQUIRE(ninlil_v1_durable_recovery_publication_gate(
                keys, values, 1u, 0u, &result)
        == expected_status);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason
        == (expected_status == NINLIL_E_UNSUPPORTED
            ? NINLIL_V1_DURABLE_RECOVERY_REJECT_UNKNOWN
            : NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT));
    return 0;
}

static int test_bearer_state_exact_validator_and_mutations(void)
{
    static const uint32_t reserved_offsets[] = {16u, 17u, 18u, 20u, 23u};
    uint8_t key[18];
    uint8_t value[48];
    uint8_t long_key[19];
    uint8_t long_value[49];
    uint8_t mutated_key[18];
    uint8_t mutated_value[48];
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_record_kind_t kind;
    ninlil_v1_durable_recovery_publication_result_t result;
    uint32_t index;

    fill_valid_bearer_state_row(key, value);
    keys[0] = (ninlil_bytes_view_t){key, sizeof(key)};
    values[0] = (ninlil_bytes_view_t){value, sizeof(value)};
    REQUIRE(ninlil_rt_v1_bearer_state_marker_validate(keys[0], values[0])
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_classify_row(keys[0], values[0], &kind)
        == NINLIL_OK);
    REQUIRE(kind == NINLIL_V1_DURABLE_KIND_SPINE_BEARER_STATE);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_BEARER_STATE_COMMIT,
                keys[0],
                values[0])
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_recovery_publication_gate(
                keys, values, 1u, 0u, &result)
        == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(result.success_evidence_count == 1u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_NONE);

    REQUIRE(require_bearer_state_row_rejected(
                (ninlil_bytes_view_t){key, sizeof(key) - 1u},
                values[0],
                NINLIL_E_UNSUPPORTED)
        == 0);
    (void)memcpy(long_key, key, sizeof(key));
    long_key[sizeof(long_key) - 1u] = 0u;
    REQUIRE(require_bearer_state_row_rejected(
                (ninlil_bytes_view_t){long_key, sizeof(long_key)},
                values[0],
                NINLIL_E_UNSUPPORTED)
        == 0);
    REQUIRE(require_bearer_state_row_rejected(
                keys[0],
                (ninlil_bytes_view_t){value, sizeof(value) - 1u},
                NINLIL_E_STORAGE_CORRUPT)
        == 0);
    (void)memcpy(long_value, value, sizeof(value));
    long_value[sizeof(long_value) - 1u] = 0u;
    REQUIRE(require_bearer_state_row_rejected(
                keys[0],
                (ninlil_bytes_view_t){long_value, sizeof(long_value)},
                NINLIL_E_STORAGE_CORRUPT)
        == 0);
    REQUIRE(require_bearer_state_row_rejected(
                keys[0],
                (ninlil_bytes_view_t){NULL, 0u},
                NINLIL_E_STORAGE_CORRUPT)
        == 0);

    {
        ninlil_bytes_view_t invalid_keys[1] = {
            {NULL, sizeof(key)}
        };
        ninlil_bytes_view_t invalid_values[1] = {values[0]};

        kind = NINLIL_V1_DURABLE_KIND_RS_BINDING;
        REQUIRE(ninlil_rt_v1_bearer_state_marker_validate(
                    invalid_keys[0], invalid_values[0])
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(ninlil_v1_durable_classify_row(
                    invalid_keys[0], invalid_values[0], &kind)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(kind == (ninlil_v1_durable_record_kind_t)0);
        REQUIRE(ninlil_v1_durable_writer_gate_check(
                    NINLIL_V1_DURABLE_OP_BEARER_STATE_COMMIT,
                    invalid_keys[0],
                    invalid_values[0])
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(ninlil_v1_durable_recovery_publication_gate(
                    invalid_keys, invalid_values, 1u, 0u, &result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(result.adopted == 0u);
        REQUIRE(result.success_evidence_count == 0u);
    }
    {
        ninlil_bytes_view_t invalid_keys[1] = {keys[0]};
        ninlil_bytes_view_t invalid_values[1] = {
            {NULL, sizeof(value)}
        };

        kind = NINLIL_V1_DURABLE_KIND_RS_BINDING;
        REQUIRE(ninlil_rt_v1_bearer_state_marker_validate(
                    invalid_keys[0], invalid_values[0])
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(ninlil_v1_durable_classify_row(
                    invalid_keys[0], invalid_values[0], &kind)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(kind == (ninlil_v1_durable_record_kind_t)0);
        REQUIRE(ninlil_v1_durable_writer_gate_check(
                    NINLIL_V1_DURABLE_OP_BEARER_STATE_COMMIT,
                    invalid_keys[0],
                    invalid_values[0])
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(ninlil_v1_durable_recovery_publication_gate(
                    invalid_keys, invalid_values, 1u, 0u, &result)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(result.adopted == 0u);
        REQUIRE(result.success_evidence_count == 0u);
    }

    (void)memcpy(mutated_key, key, sizeof(mutated_key));
    (void)memset(&mutated_key[2], 0, 16u);
    REQUIRE(require_bearer_state_row_rejected(
                (ninlil_bytes_view_t){mutated_key, sizeof(mutated_key)},
                values[0],
                NINLIL_E_STORAGE_CORRUPT)
        == 0);

    (void)memcpy(mutated_value, value, sizeof(mutated_value));
    mutated_value[0] ^= 1u;
    REQUIRE(require_bearer_state_row_rejected(
                keys[0],
                (ninlil_bytes_view_t){
                    mutated_value, sizeof(mutated_value)},
                NINLIL_E_STORAGE_CORRUPT)
        == 0);

    (void)memcpy(mutated_value, value, sizeof(mutated_value));
    (void)memset(&mutated_value[8], 0, 8u);
    REQUIRE(require_bearer_state_row_rejected(
                keys[0],
                (ninlil_bytes_view_t){
                    mutated_value, sizeof(mutated_value)},
                NINLIL_E_STORAGE_CORRUPT)
        == 0);

    for (index = 0u;
         index < sizeof(reserved_offsets) / sizeof(reserved_offsets[0]);
         ++index) {
        (void)memcpy(mutated_value, value, sizeof(mutated_value));
        mutated_value[reserved_offsets[index]] = 1u;
        REQUIRE(require_bearer_state_row_rejected(
                    keys[0],
                    (ninlil_bytes_view_t){
                        mutated_value, sizeof(mutated_value)},
                    NINLIL_E_STORAGE_CORRUPT)
            == 0);
    }

    (void)memcpy(mutated_value, value, sizeof(mutated_value));
    mutated_value[19] = 2u;
    REQUIRE(require_bearer_state_row_rejected(
                keys[0],
                (ninlil_bytes_view_t){
                    mutated_value, sizeof(mutated_value)},
                NINLIL_E_STORAGE_CORRUPT)
        == 0);

    (void)memcpy(mutated_value, value, sizeof(mutated_value));
    (void)memset(&mutated_value[24], 0, 16u);
    REQUIRE(require_bearer_state_row_rejected(
                keys[0],
                (ninlil_bytes_view_t){
                    mutated_value, sizeof(mutated_value)},
                NINLIL_E_STORAGE_CORRUPT)
        == 0);
    return 0;
}

static int test_writer_gate_red_probe(void)
{
    ninlil_model_runtime_store_key_t rs_key;
    ninlil_model_runtime_store_key_t ordered_input_key;
    ninlil_model_runtime_store_key_t capacity_key;
    ninlil_status_t status;

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
        == NINLIL_OK);

    /*
     * RED: bootstrap operation must not emit domain metadata rows.
     * put count 0 (gate rejects before storage).
     */
    status = ninlil_v1_durable_writer_gate_check(
        NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT,
        (ninlil_bytes_view_t){rs_key.bytes, rs_key.length},
        (ninlil_bytes_view_t){NULL, 0u});
    REQUIRE(status == NINLIL_OK);

    {
        ninlil_model_runtime_store_key_t rs_key;
        ninlil_status_t status;

        REQUIRE(ninlil_model_runtime_store_build_key(
                    NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
            == NINLIL_OK);
        /* RED: metadata operation must not emit bootstrap rows. */
        status = ninlil_v1_durable_writer_gate_check(
            NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT,
            (ninlil_bytes_view_t){rs_key.bytes, rs_key.length},
            (ninlil_bytes_view_t){NULL, 0u});
        REQUIRE(status == NINLIL_E_UNSUPPORTED);
    }

    status = ninlil_v1_durable_probe_disallowed_writer_kind(
        NINLIL_V1_DURABLE_OP_METADATA_INIT_COMMIT,
        (ninlil_bytes_view_t){NULL, 0u},
        (ninlil_bytes_view_t){NULL, 0u});
    REQUIRE(status == NINLIL_E_UNSUPPORTED);

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT,
                &ordered_input_key)
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_EVENT_RESUME_COMMIT,
                (ninlil_bytes_view_t){
                    ordered_input_key.bytes, ordered_input_key.length},
                (ninlil_bytes_view_t){NULL, 0u})
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_EVENT_DISCARD_COMMIT,
                (ninlil_bytes_view_t){
                    ordered_input_key.bytes, ordered_input_key.length},
                (ninlil_bytes_view_t){NULL, 0u})
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT,
                (ninlil_bytes_view_t){
                    ordered_input_key.bytes, ordered_input_key.length},
                (ninlil_bytes_view_t){NULL, 0u})
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
                (ninlil_bytes_view_t){
                    ordered_input_key.bytes, ordered_input_key.length},
                (ninlil_bytes_view_t){NULL, 0u})
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TRANSACTION,
                &capacity_key)
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_DELIVERY_EVIDENCE_COMMIT,
                (ninlil_bytes_view_t){
                    capacity_key.bytes, capacity_key.length},
                (ninlil_bytes_view_t){NULL, 0u})
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_DELIVERY_STARTED_COMMIT,
                (ninlil_bytes_view_t){
                    capacity_key.bytes, capacity_key.length},
                (ninlil_bytes_view_t){NULL, 0u})
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_DESTROY_RECOVERY_COMMIT,
                (ninlil_bytes_view_t){
                    capacity_key.bytes, capacity_key.length},
                (ninlil_bytes_view_t){NULL, 0u})
        == NINLIL_OK);

    return 0;
}

static int test_recovery_reject_unknown(void)
{
    /*
     * Recognizable future root (docs/17 §5): version byte 2, valid min key.
     * Classifies as RECOGNIZABLE_FUTURE → UNSUPPORTED (unknown to V1 profile).
     */
    static const uint8_t future_key[] = {
        0x4e, 0x49, 0x4e, 0x4c, 0x49, 0x4c, 0x00, 0x02,
        0x06, 0x10, 0x01, 0x02, 0x10
    };
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    keys[0] = (ninlil_bytes_view_t){future_key, sizeof(future_key)};
    values[0] = (ninlil_bytes_view_t){NULL, 0u};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 1u, 0u, &result);
    REQUIRE(status == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_UNKNOWN);
    return 0;
}

static int test_recovery_reject_corrupt(void)
{
    static const uint8_t corrupt_key[] = {
        0x4e, 0x49, 0x4e, 0x4c, 0x49, 0x4c, 0x00, 0x01,
        0x06, 0x62, 0x01, 0x01, 0x00
    };
    static const uint8_t corrupt_value[] = {0x4e, 0x4c, 0x52, 0x31};
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    keys[0] = (ninlil_bytes_view_t){corrupt_key, sizeof(corrupt_key)};
    values[0] = (ninlil_bytes_view_t){corrupt_value, sizeof(corrupt_value)};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 1u, 0u, &result);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_CORRUPT);
    return 0;
}

static int test_recovery_reject_mixed(void)
{
    ninlil_model_runtime_store_key_t rs_key;
    static const uint8_t unknown_key[] = {0xde, 0xad};
    ninlil_bytes_view_t keys[2];
    ninlil_bytes_view_t values[2];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
        == NINLIL_OK);
    keys[0] = (ninlil_bytes_view_t){rs_key.bytes, rs_key.length};
    values[0] = (ninlil_bytes_view_t){NULL, 0u};
    keys[1] = (ninlil_bytes_view_t){unknown_key, sizeof(unknown_key)};
    values[1] = (ninlil_bytes_view_t){NULL, 0u};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 2u, 0u, &result);
    REQUIRE(status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason == NINLIL_V1_DURABLE_RECOVERY_REJECT_MIXED);
    return 0;
}

static int test_recovery_reject_commit_unknown_restart(void)
{
    ninlil_model_runtime_store_key_t rs_key;
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_recovery_publication_result_t result;
    ninlil_status_t status;

    REQUIRE(ninlil_model_runtime_store_build_key(
                NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &rs_key)
        == NINLIL_OK);
    keys[0] = (ninlil_bytes_view_t){rs_key.bytes, rs_key.length};
    values[0] = (ninlil_bytes_view_t){NULL, 0u};
    status = ninlil_v1_durable_recovery_publication_gate(
        keys, values, 1u, 1u, &result);
    REQUIRE(status == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.success_evidence_count == 0u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_COMMIT_UNKNOWN);
    return 0;
}

static int test_eight_byte_runtime_prefix_is_rejected_without_oob(void)
{
    static const uint8_t truncated_key[] = {
        0x4e, 0x49, 0x4e, 0x4c, 0x49, 0x4c, 0x00, 0x01
    };
    ninlil_v1_durable_record_kind_t kind =
        NINLIL_V1_DURABLE_KIND_RS_BINDING;

    REQUIRE(ninlil_v1_durable_classify_row(
                (ninlil_bytes_view_t){
                    truncated_key, (uint32_t)sizeof(truncated_key)},
                (ninlil_bytes_view_t){NULL, 0u},
                &kind)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(kind == (ninlil_v1_durable_record_kind_t)0);
    return 0;
}

static int test_attempt_prepare_is_writer_and_recovery_allowlisted(void)
{
    uint8_t key[18] = {0};
    uint8_t value[NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES];
    uint32_t value_length = 0u;
    ninlil_rt_transaction_slot_t transaction;
    ninlil_bytes_view_t keys[1];
    ninlil_bytes_view_t values[1];
    ninlil_v1_durable_record_kind_t kind;
    ninlil_v1_durable_recovery_publication_result_t result;

    key[0] = 0x41u;
    key[1] = 0x50u;
    /* Exercise the historical runtime-store discriminator collision. */
    key[7] = 0x01u;
    key[8] = 0x01u;
    (void)memset(&transaction, 0, sizeof(transaction));
    transaction.in_use = 1u;
    transaction.origin_admission = 1u;
    transaction.family = NINLIL_FAMILY_DESIRED_STATE;
    transaction.deadline_verdict = NINLIL_DEADLINE_PENDING;
    transaction.delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    transaction.transaction_sequence = 1u;
    transaction.record_revision = 1u;
    transaction.bearer_route = 1u;
    (void)memcpy(
        transaction.transaction_id.bytes,
        &key[2],
        sizeof(transaction.transaction_id.bytes));
    set_id(&transaction.service_app_id, 0x11u);
    set_header(
        &transaction.source.abi_version,
        &transaction.source.struct_size,
        sizeof(transaction.source));
    set_id(&transaction.source.runtime_id, 0x21u);
    set_id(&transaction.source.application_instance_id, 0x31u);
    set_header(
        &transaction.source.local_identity.abi_version,
        &transaction.source.local_identity.struct_size,
        sizeof(transaction.source.local_identity));
    set_header(
        &transaction.service.abi_version,
        &transaction.service.struct_size,
        sizeof(transaction.service));
    transaction.service.namespace_id.length = 10u;
    (void)memcpy(
        transaction.service.namespace_id.bytes, "org.ninlil", 10u);
    transaction.service.service_id.length = 4u;
    (void)memcpy(transaction.service.service_id.bytes, "test", 4u);
    transaction.service.schema_id.length = 7u;
    (void)memcpy(transaction.service.schema_id.bytes, "test-v1", 7u);
    transaction.service.descriptor_revision = 1u;
    set_digest(&transaction.service.descriptor_digest, 0x41u);
    transaction.service.schema_major = 1u;
    transaction.service.family = NINLIL_FAMILY_DESIRED_STATE;
    set_digest(&transaction.content_digest, 0x42u);
    transaction.idempotency_key_length = 3u;
    transaction.idempotency_key[0] = (uint8_t)'a';
    transaction.idempotency_key[1] = (uint8_t)'b';
    transaction.idempotency_key[2] = (uint8_t)'c';
    set_digest(&transaction.canonical_submission_digest, 0x43u);
    transaction.effect_deadline_ms = 1000u;
    transaction.generation = 1u;
    set_id(&transaction.deadline_clock_epoch_id, 0x43u);
    transaction.bound_target_count = 1u;
    transaction.bound_targets[0].in_use = 1u;
    transaction.bound_targets[0].delivery_phase =
        NINLIL_RT_DELIVERY_QUEUED;
    set_header(
        &transaction.bound_targets[0].target.abi_version,
        &transaction.bound_targets[0].target.struct_size,
        sizeof(transaction.bound_targets[0].target));
    set_id(
        &transaction.bound_targets[0].target.target_runtime_id, 0x51u);
    set_id(
        &transaction.bound_targets[0].target
            .target_application_instance_id,
        0x61u);
    REQUIRE(ninlil_rt_v1_transaction_record_encode(
                &transaction,
                value,
                (uint32_t)sizeof(value),
                &value_length)
        == NINLIL_OK);
    REQUIRE(ninlil_v1_durable_classify_row(
                (ninlil_bytes_view_t){key, sizeof(key)},
                (ninlil_bytes_view_t){value, value_length},
                &kind)
        == NINLIL_OK);
    REQUIRE(kind == NINLIL_V1_DURABLE_KIND_SPINE_ATTEMPT_PREPARE);
    REQUIRE(ninlil_v1_durable_writer_gate_check(
                NINLIL_V1_DURABLE_OP_APPLICATION_ATTEMPT_PREPARE_COMMIT,
                (ninlil_bytes_view_t){key, sizeof(key)},
                (ninlil_bytes_view_t){value, value_length})
        == NINLIL_OK);
    keys[0] = (ninlil_bytes_view_t){key, sizeof(key)};
    values[0] = (ninlil_bytes_view_t){value, value_length};
    REQUIRE(ninlil_v1_durable_recovery_publication_gate(
                keys, values, 1u, 0u, &result)
        == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(result.success_evidence_count == 1u);
    REQUIRE(result.reject_reason
        == NINLIL_V1_DURABLE_RECOVERY_REJECT_NONE);
    return 0;
}

static int test_allowlist_table_closed(void)
{
    REQUIRE(NINLIL_V1_DURABLE_ALLOWLIST_RECORD_KIND_COUNT == 41u);
    REQUIRE(NINLIL_V1_DURABLE_ALLOWLIST_OPERATION_COUNT == 19u);
    REQUIRE(g_ninlil_v1_durable_allowlist_table[0].kind
        == NINLIL_V1_DURABLE_KIND_RS_BINDING);
    REQUIRE(g_ninlil_v1_durable_allowlist_table[28].kind
        == NINLIL_V1_DURABLE_KIND_SPINE_RETRY_STATE);
    REQUIRE(g_ninlil_v1_durable_allowlist_table[30].kind
        == NINLIL_V1_DURABLE_KIND_M4_INSTALL_TOKEN);
    REQUIRE(g_ninlil_v1_durable_allowlist_table[32].kind
        == NINLIL_V1_DURABLE_KIND_SPINE_BEARER_STATE);
    REQUIRE(g_ninlil_v1_durable_allowlist_table[33].kind
        == NINLIL_V1_DURABLE_KIND_SPINE_ATTEMPT_PREPARE);
    return 0;
}

int main(void)
{
    REQUIRE(test_allowlist_table_closed() == 0);
    REQUIRE(test_bearer_state_exact_validator_and_mutations() == 0);
    REQUIRE(test_writer_gate_red_probe() == 0);
    REQUIRE(test_recovery_reject_unknown() == 0);
    REQUIRE(test_recovery_reject_corrupt() == 0);
    REQUIRE(test_recovery_reject_mixed() == 0);
    REQUIRE(test_recovery_reject_commit_unknown_restart() == 0);
    REQUIRE(test_eight_byte_runtime_prefix_is_rejected_without_oob() == 0);
    REQUIRE(test_attempt_prepare_is_writer_and_recovery_allowlisted() == 0);
    (void)printf("v1_durable_allowlist_test ok\n");
    return 0;
}
