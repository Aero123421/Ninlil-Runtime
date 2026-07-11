#ifndef NINLIL_MODEL_RUNTIME_STORE_CODEC_H
#define NINLIL_MODEL_RUNTIME_STORE_CODEC_H

#include <stddef.h>
#include <stdint.h>

#include <ninlil/runtime.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * All input and output object/byte ranges must be pairwise disjoint.
 * Overlap is rejected without modifying any participating range.
 */

#define NINLIL_MODEL_RUNTIME_STORE_KEY_MAX_BYTES ((uint32_t)10u)
#define NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT ((uint32_t)17u)
#define NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES \
    ((uint32_t)1311u)
#define NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_LOGICAL_BYTES ((uint32_t)1583u)
#define NINLIL_MODEL_RUNTIME_STORE_BINDING_PAYLOAD_BYTES ((uint32_t)167u)
#define NINLIL_MODEL_RUNTIME_STORE_IDENTITY_PAYLOAD_BYTES ((uint32_t)68u)
#define NINLIL_MODEL_RUNTIME_STORE_COUNTER_PAYLOAD_BYTES ((uint32_t)16u)
#define NINLIL_MODEL_RUNTIME_STORE_CAPACITY_PAYLOAD_BYTES ((uint32_t)52u)
#define NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES ((uint32_t)183u)
#define NINLIL_MODEL_RUNTIME_STORE_IDENTITY_VALUE_BYTES ((uint32_t)84u)
#define NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES ((uint32_t)32u)
#define NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES ((uint32_t)68u)

typedef enum ninlil_model_runtime_store_key_id {
    NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING = 1,
    NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY = 2,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION = 3,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ORDERED_INPUT = 4,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_ASSIGNED_OWNER = 5,
    NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER = 6,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE = 7,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TRANSACTION = 8,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_TARGET = 9,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_OUTBOX_BYTES = 10,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DELIVERY = 11,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_COUNT = 12,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVENT_SPOOL_BYTES = 13,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_RESULT_CACHE = 14,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_EVIDENCE = 15,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_INGRESS = 16,
    NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN = 17
} ninlil_model_runtime_store_key_id_t;

typedef struct ninlil_model_runtime_store_key {
    uint8_t bytes[NINLIL_MODEL_RUNTIME_STORE_KEY_MAX_BYTES];
    uint32_t length;
} ninlil_model_runtime_store_key_t;

typedef enum ninlil_model_runtime_store_record_type {
    NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING = 1,
    NINLIL_MODEL_RUNTIME_STORE_RECORD_IDENTITY = 2,
    NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER = 3,
    NINLIL_MODEL_RUNTIME_STORE_RECORD_CAPACITY = 4
} ninlil_model_runtime_store_record_type_t;

typedef struct ninlil_model_runtime_store_limits {
    uint32_t max_services;
    uint32_t max_nonterminal_transactions;
    uint32_t max_targets_per_transaction;
    uint32_t max_logical_payload_bytes;
    uint64_t max_durable_outbox_payload_bytes;
    uint32_t max_attempts_per_target_per_cycle;
    uint32_t max_cancel_attempts_per_transaction;
    uint32_t max_evidence_per_target;
    uint32_t max_retained_terminal_transactions;
    uint32_t max_nonterminal_deliveries;
    uint32_t max_event_spool_count;
    uint64_t max_event_spool_bytes;
    uint32_t max_result_cache_entries;
    uint32_t max_retained_dispositions;
    uint32_t max_ingress_per_step;
    uint32_t max_callbacks_per_step;
    uint32_t max_state_transitions_per_step;
    uint32_t max_bearer_sends_per_step;
    uint32_t max_deferred_tokens;
} ninlil_model_runtime_store_limits_t;

typedef struct ninlil_model_runtime_store_binding {
    uint32_t storage_schema;
    ninlil_role_t role;
    ninlil_environment_t environment;
    ninlil_id128_t runtime_id;
    ninlil_model_runtime_store_limits_t limits;
    uint64_t terminal_retention_ms;
    uint64_t result_cache_retention_ms;
    uint64_t observation_retention_ms;
} ninlil_model_runtime_store_binding_t;

typedef struct ninlil_model_runtime_store_identity {
    uint32_t flags;
    ninlil_id128_t device_id;
    ninlil_id128_t installation_id;
    ninlil_id128_t site_domain_id;
    uint64_t binding_epoch;
    uint64_t membership_epoch;
} ninlil_model_runtime_store_identity_t;

typedef enum ninlil_model_runtime_store_counter_kind {
    NINLIL_MODEL_RUNTIME_STORE_COUNTER_TRANSACTION = 1,
    NINLIL_MODEL_RUNTIME_STORE_COUNTER_ORDERED_INPUT = 2,
    NINLIL_MODEL_RUNTIME_STORE_COUNTER_ASSIGNED_OWNER = 3,
    NINLIL_MODEL_RUNTIME_STORE_COUNTER_VISITED_OWNER = 4
} ninlil_model_runtime_store_counter_kind_t;

typedef struct ninlil_model_runtime_store_counter {
    ninlil_model_runtime_store_counter_kind_t kind;
    uint64_t value;
    uint32_t exhausted_marker;
} ninlil_model_runtime_store_counter_t;

typedef struct ninlil_model_runtime_store_capacity {
    ninlil_resource_kind_t kind;
    uint64_t limit;
    uint64_t used;
    uint64_t reserved;
    uint64_t high_water;
    uint64_t capacity_epoch;
    uint32_t blocked;
    uint32_t counter_exhausted;
} ninlil_model_runtime_store_capacity_t;

ninlil_status_t ninlil_model_runtime_store_build_key(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_model_runtime_store_key_t *out_key);

ninlil_status_t ninlil_model_runtime_store_parse_key(
    ninlil_bytes_view_t encoded_key,
    ninlil_model_runtime_store_key_id_t *out_key_id);

ninlil_status_t ninlil_model_runtime_store_record_type_for_key(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_model_runtime_store_record_type_t *out_type);

ninlil_status_t ninlil_model_runtime_store_encode_binding(
    const ninlil_model_runtime_store_binding_t *binding,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length);
ninlil_status_t ninlil_model_runtime_store_decode_binding(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_binding_t *out_binding);

ninlil_status_t ninlil_model_runtime_store_encode_identity(
    const ninlil_model_runtime_store_identity_t *identity,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length);
ninlil_status_t ninlil_model_runtime_store_decode_identity(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_identity_t *out_identity);

ninlil_status_t ninlil_model_runtime_store_encode_counter(
    ninlil_model_runtime_store_key_id_t key_id,
    const ninlil_model_runtime_store_counter_t *counter,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length);
ninlil_status_t ninlil_model_runtime_store_decode_counter(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_counter_t *out_counter);

ninlil_status_t ninlil_model_runtime_store_encode_capacity(
    ninlil_model_runtime_store_key_id_t key_id,
    const ninlil_model_runtime_store_capacity_t *entry,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length);
ninlil_status_t ninlil_model_runtime_store_decode_capacity(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_capacity_t *out_entry);

#ifdef __cplusplus
}
#endif

#endif
