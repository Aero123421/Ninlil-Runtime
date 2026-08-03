/*
 * ADR-0022 private format-2 Domain schema1 binding + T0/T1a bootstrap.
 * Foundation SMALL-1 role-aware validation (docs/12). No heap/VLA. No public ABI.
 */

#include "domain_schema1_runtime_binding.h"

#include "runtime_store_codec_internal.h"

#include <limits.h>
#include <ninlil/version.h>
#include <string.h>

#if defined(NINLIL_MFDT_V1_PRIVATE)
#define NINLIL_DOMAIN_LOGICAL_PAYLOAD_PROFILE_MAX ((uint32_t)32768u)
#else
#define NINLIL_DOMAIN_LOGICAL_PAYLOAD_PROFILE_MAX ((uint32_t)1024u)
#endif

#if !defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    || (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING == 0)
#error "domain_schema1_runtime_binding.c requires NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING=1"
#endif

static const uint8_t PROFILE_NAME[] = "NINLIL-FOUNDATION-SMALL-1";
static const uint8_t STORAGE_PROFILE_ID[] = "NINLIL-DOMAIN-S1";
_Static_assert(sizeof(PROFILE_NAME) == 26u, "profile name includes NUL");
_Static_assert(sizeof(STORAGE_PROFILE_ID) == 17u, "storage profile id includes NUL");

static int ranges_are_disjoint(
    const void *left,
    size_t left_length,
    const void *right,
    size_t right_length)
{
    uintptr_t left_start;
    uintptr_t right_start;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left_length == 0u || right_length == 0u) {
        return 1;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_length > UINTPTR_MAX - left_start
        || right_length > UINTPTR_MAX - right_start) {
        return 0;
    }
    left_end = left_start + left_length;
    right_end = right_start + right_length;
    return left_end <= right_start || right_end <= left_start;
}

static int encode_ranges_are_disjoint(
    const void *input,
    size_t input_length,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    const int has_input = input != NULL && input_length != 0u;
    const int has_output = out_bytes != NULL && capacity != 0u;

    return (!has_input
            || ranges_are_disjoint(
                input, input_length, out_length, sizeof(*out_length)))
        && (!has_output
            || ranges_are_disjoint(
                out_bytes, capacity, out_length, sizeof(*out_length)))
        && (!has_input || !has_output
            || ranges_are_disjoint(
                input, input_length, out_bytes, capacity));
}

static int bytes_view_shape_is_valid(ninlil_bytes_view_t view)
{
    return (view.length == 0u && view.data == NULL)
        || (view.length > 0u && view.data != NULL);
}

static void encode_u16_be(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)(value >> 8u);
    destination[1] = (uint8_t)value;
}

static void encode_u32_be(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)(value >> 24u);
    destination[1] = (uint8_t)(value >> 16u);
    destination[2] = (uint8_t)(value >> 8u);
    destination[3] = (uint8_t)value;
}

static void encode_u64_be(uint8_t *destination, uint64_t value)
{
    encode_u32_be(destination, (uint32_t)(value >> 32u));
    encode_u32_be(&destination[4], (uint32_t)value);
}

static uint16_t decode_u16_be(const uint8_t *source)
{
    return (uint16_t)(((uint16_t)source[0] << 8u) | source[1]);
}

static uint32_t decode_u32_be(const uint8_t *source)
{
    return ((uint32_t)source[0] << 24u) | ((uint32_t)source[1] << 16u)
        | ((uint32_t)source[2] << 8u) | (uint32_t)source[3];
}

static uint64_t decode_u64_be(const uint8_t *source)
{
    return ((uint64_t)decode_u32_be(source) << 32u)
        | (uint64_t)decode_u32_be(&source[4]);
}

static int id_is_nonzero(const ninlil_id128_t *id)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

int ninlil_domain_schema1_checked_count_bytes(
    uint32_t count,
    size_t element_size,
    size_t *out_bytes)
{
    if (out_bytes == NULL || element_size == 0u) {
        return 0;
    }
    /* Exact zero semantics: empty count is valid and never divides. */
    if (count == 0u) {
        *out_bytes = 0u;
        return 1;
    }
    if (count > NINLIL_DOMAIN_SCHEMA1_COUNT_HARD_CAP) {
        return 0;
    }
    if (element_size > SIZE_MAX / (size_t)count) {
        return 0;
    }
    *out_bytes = (size_t)count * element_size;
    return 1;
}

static int add_u64_checked(uint64_t left, uint64_t right, uint64_t *out)
{
    if (left > UINT64_MAX - right) {
        return 0;
    }
    *out = left + right;
    return 1;
}

static int mul_u64_checked(uint64_t left, uint64_t right, uint64_t *out)
{
    if (left != 0u && right > UINT64_MAX / left) {
        return 0;
    }
    *out = left * right;
    return 1;
}

/*
 * Field-by-field comparison only. Interior/tail padding must not participate
 * (sizeof may be 88 with 4 tail padding after max_deferred_tokens).
 */
static int limits_equal(
    const ninlil_model_runtime_store_limits_t *left,
    const ninlil_model_runtime_store_limits_t *right)
{
    return left->max_services == right->max_services
        && left->max_nonterminal_transactions
        == right->max_nonterminal_transactions
        && left->max_targets_per_transaction
        == right->max_targets_per_transaction
        && left->max_logical_payload_bytes == right->max_logical_payload_bytes
        && left->max_durable_outbox_payload_bytes
        == right->max_durable_outbox_payload_bytes
        && left->max_attempts_per_target_per_cycle
        == right->max_attempts_per_target_per_cycle
        && left->max_cancel_attempts_per_transaction
        == right->max_cancel_attempts_per_transaction
        && left->max_evidence_per_target == right->max_evidence_per_target
        && left->max_retained_terminal_transactions
        == right->max_retained_terminal_transactions
        && left->max_nonterminal_deliveries == right->max_nonterminal_deliveries
        && left->max_event_spool_count == right->max_event_spool_count
        && left->max_event_spool_bytes == right->max_event_spool_bytes
        && left->max_result_cache_entries == right->max_result_cache_entries
        && left->max_retained_dispositions == right->max_retained_dispositions
        && left->max_ingress_per_step == right->max_ingress_per_step
        && left->max_callbacks_per_step == right->max_callbacks_per_step
        && left->max_state_transitions_per_step
        == right->max_state_transitions_per_step
        && left->max_bearer_sends_per_step == right->max_bearer_sends_per_step
        && left->max_deferred_tokens == right->max_deferred_tokens;
}

/*
 * docs/12 NINLIL-FOUNDATION-SMALL-1 role/environment closed sets +
 * lower/conditional/cross-field/retention/upper tables.
 */
ninlil_status_t ninlil_domain_schema1_validate_foundation_common(
    const ninlil_model_runtime_store_binding_t *common)
{
    const ninlil_model_runtime_store_limits_t *limits;
    uint32_t service_max;
    uint32_t transaction_max;
    uint32_t retained_max;

    if (common == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (common->role < NINLIL_ROLE_CONTROLLER
        || common->role > NINLIL_ROLE_CELL_AGENT_RESERVED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (common->environment < NINLIL_ENV_TEST
        || common->environment > NINLIL_ENV_PRODUCTION_RESERVED) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (common->role == NINLIL_ROLE_CELL_AGENT_RESERVED) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (common->environment != NINLIL_ENV_TEST) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (common->storage_schema != NINLIL_DOMAIN_SCHEMA1_STORAGE_SCHEMA
        || !id_is_nonzero(&common->runtime_id)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    limits = &common->limits;
    if (limits->max_services < 1u
        || limits->max_nonterminal_transactions < 1u
        || limits->max_targets_per_transaction != 1u
        || limits->max_logical_payload_bytes < 1u
        || limits->max_attempts_per_target_per_cycle
            != NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE
        || limits->max_cancel_attempts_per_transaction != 1u
        || limits->max_evidence_per_target < 1u
        || limits->max_retained_terminal_transactions < 1u
        || limits->max_nonterminal_deliveries < 1u
        || limits->max_result_cache_entries < 1u
        || limits->max_retained_dispositions < 1u
        || limits->max_ingress_per_step < 1u
        || limits->max_callbacks_per_step < 1u
        || limits->max_state_transitions_per_step < 2u
        || limits->max_bearer_sends_per_step < 1u
        || limits->max_deferred_tokens < 1u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (common->role == NINLIL_ROLE_CONTROLLER) {
        if (limits->max_durable_outbox_payload_bytes < 1u
            || limits->max_event_spool_count != 0u
            || limits->max_event_spool_bytes != 0u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    } else {
        /* ENDPOINT */
        if (limits->max_durable_outbox_payload_bytes != 0u) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        if (limits->max_event_spool_count == 0u) {
            if (limits->max_event_spool_bytes != 0u) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
        } else if (
            limits->max_event_spool_bytes
            < NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }

    if (limits->max_deferred_tokens > limits->max_nonterminal_deliveries
        || limits->max_nonterminal_deliveries
            > limits->max_nonterminal_transactions
        || limits->max_event_spool_count
            > limits->max_nonterminal_transactions) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (common->role == NINLIL_ROLE_CONTROLLER
        && limits->max_durable_outbox_payload_bytes
            < limits->max_logical_payload_bytes) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (common->terminal_retention_ms < 1u
        || common->terminal_retention_ms > NINLIL_M1A_MAX_RETENTION_MS
        || common->result_cache_retention_ms < 1u
        || common->result_cache_retention_ms > common->terminal_retention_ms
        || common->observation_retention_ms > NINLIL_M1A_MAX_RETENTION_MS) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    service_max = common->role == NINLIL_ROLE_CONTROLLER ? 16u : 8u;
    transaction_max = common->role == NINLIL_ROLE_CONTROLLER ? 256u : 32u;
    retained_max = common->role == NINLIL_ROLE_CONTROLLER ? 2048u : 64u;
    if (limits->max_services > service_max
        || limits->max_nonterminal_transactions > transaction_max
        || limits->max_logical_payload_bytes
            > NINLIL_DOMAIN_LOGICAL_PAYLOAD_PROFILE_MAX
        || limits->max_evidence_per_target > 8u
        || limits->max_retained_terminal_transactions > retained_max
        || limits->max_nonterminal_deliveries > 32u
        || limits->max_result_cache_entries > 64u
        || limits->max_retained_dispositions > 64u
        || limits->max_ingress_per_step > 64u
        || limits->max_callbacks_per_step > 64u
        || limits->max_state_transitions_per_step > 64u
        || limits->max_bearer_sends_per_step > 64u
        || limits->max_deferred_tokens > 32u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (common->role == NINLIL_ROLE_CONTROLLER) {
        if (limits->max_durable_outbox_payload_bytes > 262144u) {
            return NINLIL_E_UNSUPPORTED;
        }
    } else if (
        limits->max_event_spool_count > 32u
        || limits->max_event_spool_bytes > 32768u) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_validate_binding(
    const ninlil_domain_schema1_binding_t *binding)
{
    ninlil_status_t status;
    uint64_t capacity_limits[11];

    if (binding == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_domain_schema1_validate_foundation_common(&binding->common);
    if (status != NINLIL_OK) {
        return status;
    }
    if (memcmp(binding->storage_profile_id, STORAGE_PROFILE_ID, 16u) != 0) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (binding->storage_profile_revision
        != NINLIL_DOMAIN_SCHEMA1_STORAGE_PROFILE_REVISION) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (binding->minimum_writer_generation
        != NINLIL_DOMAIN_SCHEMA1_MINIMUM_WRITER_GENERATION) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (binding->rollback_epoch != NINLIL_DOMAIN_SCHEMA1_ROLLBACK_EPOCH) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (!add_u64_checked(
            binding->common.limits.max_nonterminal_transactions,
            binding->common.limits.max_retained_terminal_transactions,
            &capacity_limits[0])
        || !mul_u64_checked(
            capacity_limits[0],
            binding->common.limits.max_targets_per_transaction,
            &capacity_limits[1])) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)capacity_limits;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_validate_identity(
    const ninlil_model_runtime_store_identity_t *identity)
{
    const uint32_t known = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    uint32_t device;
    uint32_t installation;
    uint32_t site;

    if (identity == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if ((identity->flags & ~known) != 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    device = identity->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE;
    installation = identity->flags & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    site = identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE;
    if (device == 0u || site == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (((device != 0u) != id_is_nonzero(&identity->device_id))
        || ((installation != 0u)
            != id_is_nonzero(&identity->installation_id))
        || ((site != 0u) != id_is_nonzero(&identity->site_domain_id))
        || (((device | installation) != 0u)
            != (identity->binding_epoch != 0u))
        || ((site != 0u) != (identity->membership_epoch != 0u))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

static int binding_exact_equal(
    const ninlil_domain_schema1_binding_t *left,
    const ninlil_domain_schema1_binding_t *right)
{
    return left->common.storage_schema == right->common.storage_schema
        && left->common.role == right->common.role
        && left->common.environment == right->common.environment
        && memcmp(
               left->common.runtime_id.bytes,
               right->common.runtime_id.bytes,
               16u)
            == 0
        && limits_equal(&left->common.limits, &right->common.limits)
        && left->common.terminal_retention_ms
        == right->common.terminal_retention_ms
        && left->common.result_cache_retention_ms
        == right->common.result_cache_retention_ms
        && left->common.observation_retention_ms
        == right->common.observation_retention_ms
        && memcmp(left->storage_profile_id, right->storage_profile_id, 16u)
            == 0
        && left->storage_profile_revision == right->storage_profile_revision
        && left->minimum_writer_generation == right->minimum_writer_generation
        && left->rollback_epoch == right->rollback_epoch;
}

static void put_common_tail(
    uint8_t *payload,
    uint32_t *offset,
    const ninlil_model_runtime_store_binding_t *common)
{
    uint32_t o = *offset;
#define PUT32(v)                         \
    do {                                 \
        encode_u32_be(&payload[o], (v)); \
        o += 4u;                         \
    } while (0)
#define PUT64(v)                         \
    do {                                 \
        encode_u64_be(&payload[o], (v)); \
        o += 8u;                         \
    } while (0)
    PUT32(common->storage_schema);
    PUT32(common->role);
    PUT32(common->environment);
    (void)memcpy(&payload[o], common->runtime_id.bytes, 16u);
    o += 16u;
    PUT32(common->limits.max_services);
    PUT32(common->limits.max_nonterminal_transactions);
    PUT32(common->limits.max_targets_per_transaction);
    PUT32(common->limits.max_logical_payload_bytes);
    PUT64(common->limits.max_durable_outbox_payload_bytes);
    PUT32(common->limits.max_attempts_per_target_per_cycle);
    PUT32(common->limits.max_cancel_attempts_per_transaction);
    PUT32(common->limits.max_evidence_per_target);
    PUT32(common->limits.max_retained_terminal_transactions);
    PUT32(common->limits.max_nonterminal_deliveries);
    PUT32(common->limits.max_event_spool_count);
    PUT64(common->limits.max_event_spool_bytes);
    PUT32(common->limits.max_result_cache_entries);
    PUT32(common->limits.max_retained_dispositions);
    PUT32(common->limits.max_ingress_per_step);
    PUT32(common->limits.max_callbacks_per_step);
    PUT32(common->limits.max_state_transitions_per_step);
    PUT32(common->limits.max_bearer_sends_per_step);
    PUT32(common->limits.max_deferred_tokens);
    PUT64(common->terminal_retention_ms);
    PUT64(common->result_cache_retention_ms);
    PUT64(common->observation_retention_ms);
#undef PUT32
#undef PUT64
    *offset = o;
}

static void get_common_tail(
    const uint8_t *payload,
    uint32_t *offset,
    ninlil_model_runtime_store_binding_t *common)
{
    uint32_t o = *offset;
#define GET32(field)                          \
    do {                                      \
        (field) = decode_u32_be(&payload[o]); \
        o += 4u;                              \
    } while (0)
#define GET64(field)                          \
    do {                                      \
        (field) = decode_u64_be(&payload[o]); \
        o += 8u;                              \
    } while (0)
    GET32(common->storage_schema);
    GET32(common->role);
    GET32(common->environment);
    (void)memcpy(common->runtime_id.bytes, &payload[o], 16u);
    o += 16u;
    GET32(common->limits.max_services);
    GET32(common->limits.max_nonterminal_transactions);
    GET32(common->limits.max_targets_per_transaction);
    GET32(common->limits.max_logical_payload_bytes);
    GET64(common->limits.max_durable_outbox_payload_bytes);
    GET32(common->limits.max_attempts_per_target_per_cycle);
    GET32(common->limits.max_cancel_attempts_per_transaction);
    GET32(common->limits.max_evidence_per_target);
    GET32(common->limits.max_retained_terminal_transactions);
    GET32(common->limits.max_nonterminal_deliveries);
    GET32(common->limits.max_event_spool_count);
    GET64(common->limits.max_event_spool_bytes);
    GET32(common->limits.max_result_cache_entries);
    GET32(common->limits.max_retained_dispositions);
    GET32(common->limits.max_ingress_per_step);
    GET32(common->limits.max_callbacks_per_step);
    GET32(common->limits.max_state_transitions_per_step);
    GET32(common->limits.max_bearer_sends_per_step);
    GET32(common->limits.max_deferred_tokens);
    GET64(common->terminal_retention_ms);
    GET64(common->result_cache_retention_ms);
    GET64(common->observation_retention_ms);
#undef GET32
#undef GET64
    *offset = o;
}

static int derive_capacity_limits(
    const ninlil_model_runtime_store_limits_t *limits,
    uint64_t out_limits[11])
{
    uint64_t transaction;
    uint64_t target;
    uint64_t evidence_plus;
    uint64_t cache_sum;

    if (!add_u64_checked(
            limits->max_nonterminal_transactions,
            limits->max_retained_terminal_transactions,
            &transaction)
        || !mul_u64_checked(
            transaction, limits->max_targets_per_transaction, &target)
        || !add_u64_checked(
            limits->max_result_cache_entries,
            limits->max_retained_dispositions,
            &cache_sum)
        || !add_u64_checked(limits->max_evidence_per_target, 1u, &evidence_plus)
        || !mul_u64_checked(target, evidence_plus, &out_limits[8])) {
        return 0;
    }
    out_limits[0] = limits->max_services;
    out_limits[1] = transaction;
    out_limits[2] = target;
    out_limits[3] = limits->max_durable_outbox_payload_bytes;
    out_limits[4] = limits->max_nonterminal_deliveries;
    out_limits[5] = limits->max_event_spool_count;
    out_limits[6] = limits->max_event_spool_bytes;
    out_limits[7] = cache_sum;
    out_limits[9] = limits->max_ingress_per_step;
    out_limits[10] = limits->max_deferred_tokens;
    return 1;
}

static uint32_t plan_seal_crc(const ninlil_domain_schema1_bootstrap_plan_t *plan)
{
    uint8_t material[sizeof(ninlil_domain_schema1_binding_t)
        + sizeof(ninlil_model_runtime_store_identity_t)
        + sizeof(ninlil_model_runtime_store_limits_t)
        + 12u];
    uint32_t offset = 0u;

    (void)memcpy(
        material + offset, &plan->sealed_binding, sizeof(plan->sealed_binding));
    offset += (uint32_t)sizeof(plan->sealed_binding);
    (void)memcpy(
        material + offset,
        &plan->sealed_identity,
        sizeof(plan->sealed_identity));
    offset += (uint32_t)sizeof(plan->sealed_identity);
    (void)memcpy(
        material + offset,
        &plan->sealed_capacity_source_limits,
        sizeof(plan->sealed_capacity_source_limits));
    offset += (uint32_t)sizeof(plan->sealed_capacity_source_limits);
    encode_u32_be(material + offset, plan->sealed_record_count);
    offset += 4u;
    encode_u32_be(material + offset, plan->sealed_encoded_key_value_bytes);
    offset += 4u;
    encode_u32_be(material + offset, plan->sealed_logical_bytes);
    offset += 4u;
    return ninlil_model_runtime_store_crc32c(material, offset);
}

static int plan_is_canonical(const ninlil_domain_schema1_bootstrap_plan_t *plan)
{
    uint64_t capacity_limits[11];

    if (plan == NULL) {
        return 0;
    }
    if (plan->sealed_magic != NINLIL_DOMAIN_SCHEMA1_PLAN_SEAL_MAGIC) {
        return 0;
    }
    if (ninlil_domain_schema1_validate_binding(&plan->sealed_binding)
            != NINLIL_OK
        || ninlil_domain_schema1_validate_identity(&plan->sealed_identity)
            != NINLIL_OK
        || !limits_equal(
            &plan->sealed_capacity_source_limits,
            &plan->sealed_binding.common.limits)
        || plan->sealed_record_count
            != NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT
        || plan->sealed_encoded_key_value_bytes
            != NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES
        || plan->sealed_logical_bytes
            != NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_LOGICAL_BYTES
        || !derive_capacity_limits(
            &plan->sealed_binding.common.limits, capacity_limits)) {
        return 0;
    }
    (void)capacity_limits;
    /* Reject any post-build substitution of public plan fields. */
    if (memcmp(
            &plan->binding, &plan->sealed_binding, sizeof(plan->binding))
            != 0
        || memcmp(
               &plan->identity,
               &plan->sealed_identity,
               sizeof(plan->identity))
            != 0
        || !limits_equal(
            &plan->capacity_source_limits,
            &plan->sealed_capacity_source_limits)
        || plan->record_count != plan->sealed_record_count
        || plan->encoded_key_value_bytes
            != plan->sealed_encoded_key_value_bytes
        || plan->logical_bytes != plan->sealed_logical_bytes
        || plan->sealed_crc32c != plan_seal_crc(plan)) {
        return 0;
    }
    return 1;
}

ninlil_status_t ninlil_domain_schema1_encode_binding(
    const ninlil_domain_schema1_binding_t *binding,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint8_t payload[NINLIL_DOMAIN_SCHEMA1_BINDING_PAYLOAD_BYTES];
    uint32_t offset = 0u;
    ninlil_status_t status;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_ranges_are_disjoint(
            binding,
            binding == NULL ? 0u : sizeof(*binding),
            out_bytes,
            capacity,
            out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL) || binding == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_domain_schema1_validate_binding(binding);
    if (status != NINLIL_OK) {
        return status;
    }

    encode_u32_be(&payload[offset], NINLIL_DOMAIN_SCHEMA1_BINDING_FORMAT);
    offset += 4u;
    encode_u16_be(&payload[offset], 25u);
    offset += 2u;
    (void)memcpy(&payload[offset], PROFILE_NAME, 25u);
    offset += 25u;
    (void)memcpy(&payload[offset], binding->storage_profile_id, 16u);
    offset += 16u;
    encode_u32_be(&payload[offset], binding->storage_profile_revision);
    offset += 4u;
    encode_u32_be(&payload[offset], binding->minimum_writer_generation);
    offset += 4u;
    encode_u64_be(&payload[offset], binding->rollback_epoch);
    offset += 8u;
    put_common_tail(payload, &offset, &binding->common);
    if (offset != NINLIL_DOMAIN_SCHEMA1_BINDING_PAYLOAD_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        (ninlil_bytes_view_t){payload, sizeof(payload)},
        out_bytes,
        capacity,
        out_length);
}

ninlil_status_t ninlil_domain_schema1_decode_binding(
    ninlil_bytes_view_t encoded,
    ninlil_domain_schema1_binding_t *out_binding)
{
    ninlil_model_runtime_store_envelope_t envelope;
    const uint8_t *payload;
    uint32_t offset = 0u;
    ninlil_status_t status;

    if (out_binding == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!bytes_view_shape_is_valid(encoded)) {
        (void)memset(out_binding, 0, sizeof(*out_binding));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(
            encoded.data,
            encoded.length,
            out_binding,
            sizeof(*out_binding))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_binding, 0, sizeof(*out_binding));
    status = ninlil_model_runtime_store_decode_envelope(encoded, &envelope);
    if (status != NINLIL_OK) {
        return status;
    }
    if (envelope.type != NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING
        || envelope.version != 1u
        || envelope.payload.length
            != NINLIL_DOMAIN_SCHEMA1_BINDING_PAYLOAD_BYTES) {
        return NINLIL_E_UNSUPPORTED;
    }
    payload = envelope.payload.data;
    if (decode_u32_be(payload) != NINLIL_DOMAIN_SCHEMA1_BINDING_FORMAT
        || decode_u16_be(&payload[4]) != 25u
        || memcmp(&payload[6], PROFILE_NAME, 25u) != 0) {
        return NINLIL_E_UNSUPPORTED;
    }
    offset = 31u;
    (void)memcpy(out_binding->storage_profile_id, &payload[offset], 16u);
    offset += 16u;
    out_binding->storage_profile_revision = decode_u32_be(&payload[offset]);
    offset += 4u;
    out_binding->minimum_writer_generation = decode_u32_be(&payload[offset]);
    offset += 4u;
    out_binding->rollback_epoch = decode_u64_be(&payload[offset]);
    offset += 8u;
    get_common_tail(payload, &offset, &out_binding->common);
    if (offset != NINLIL_DOMAIN_SCHEMA1_BINDING_PAYLOAD_BYTES) {
        (void)memset(out_binding, 0, sizeof(*out_binding));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = ninlil_domain_schema1_validate_binding(out_binding);
    if (status != NINLIL_OK) {
        (void)memset(out_binding, 0, sizeof(*out_binding));
        return status;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_classify_binding_open(
    ninlil_bytes_view_t encoded_value,
    ninlil_domain_schema1_consumer_t consumer,
    uint32_t writer_generation,
    const ninlil_domain_schema1_binding_t *expected)
{
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_binding_t format1;
    ninlil_status_t status;
    ninlil_model_runtime_store_envelope_t envelope;
    uint32_t binding_format;

    if (!bytes_view_shape_is_valid(encoded_value)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_runtime_store_decode_envelope(
        encoded_value, &envelope);
    if (status != NINLIL_OK) {
        return status;
    }
    if (envelope.type != NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING
        || envelope.version != 1u || envelope.payload.length < 4u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    binding_format = decode_u32_be(envelope.payload.data);

    if (consumer == NINLIL_DOMAIN_SCHEMA1_CONSUMER_LAST_LAB_BINARY) {
        if (binding_format != 1u) {
            return NINLIL_E_UNSUPPORTED;
        }
        status = ninlil_model_runtime_store_decode_binding(
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
            encoded_value,
            &format1);
        if (status != NINLIL_OK) {
            return status == NINLIL_E_UNSUPPORTED ? status
                                                 : NINLIL_E_STORAGE_CORRUPT;
        }
        /* Exact Foundation profile on full format1 body. */
        return ninlil_domain_schema1_validate_foundation_common(&format1);
    }

    if (consumer != NINLIL_DOMAIN_SCHEMA1_CONSUMER_CANONICAL_DOMAIN) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (expected == NULL
        || ninlil_domain_schema1_validate_binding(expected) != NINLIL_OK) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (binding_format != NINLIL_DOMAIN_SCHEMA1_BINDING_FORMAT) {
        return NINLIL_E_UNSUPPORTED;
    }
    status = ninlil_domain_schema1_decode_binding(encoded_value, &binding);
    if (status != NINLIL_OK) {
        return status;
    }
    if (writer_generation < binding.minimum_writer_generation) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (!binding_exact_equal(&binding, expected)) {
        return NINLIL_E_UNSUPPORTED;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_classify_t0(
    const ninlil_domain_schema1_storage_transcript_t *transcript,
    ninlil_domain_schema1_t0_class_t *out_class)
{
    const ninlil_domain_schema1_storage_op_t *ops;
    size_t ops_bytes;
    uint32_t txn;

    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (transcript == NULL
        || !ranges_are_disjoint(
            transcript, sizeof(*transcript), out_class, sizeof(*out_class))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (transcript->op_count > 0u) {
        if (transcript->ops == NULL
            || !ninlil_domain_schema1_checked_count_bytes(
                transcript->op_count,
                sizeof(ninlil_domain_schema1_storage_op_t),
                &ops_bytes)
            || !ranges_are_disjoint(
                transcript->ops, ops_bytes, out_class, sizeof(*out_class))) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }

    *out_class = NINLIL_DOMAIN_SCHEMA1_T0_REJECT;
    ops = transcript->ops;
    if (transcript->op_count != 4u || ops == NULL) {
        return NINLIL_OK;
    }
    if (ops[0].kind != NINLIL_DOMAIN_SCHEMA1_OP_TX_BEGIN_READ_WRITE
        || ops[0].transaction_id == 0u) {
        return NINLIL_OK;
    }
    txn = ops[0].transaction_id;
    if (ops[1].kind != NINLIL_DOMAIN_SCHEMA1_OP_ITER_OPEN
        || ops[1].transaction_id != txn
        || ops[2].kind != NINLIL_DOMAIN_SCHEMA1_OP_ITER_NEXT_NOT_FOUND
        || ops[2].transaction_id != txn
        || ops[3].kind != NINLIL_DOMAIN_SCHEMA1_OP_ITER_CLOSE
        || ops[3].transaction_id != txn) {
        return NINLIL_OK;
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_T0_ZERO_ROW_AUTHORITY;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_build_bootstrap_plan(
    const ninlil_domain_schema1_binding_t *binding,
    const ninlil_model_runtime_store_identity_t *identity,
    ninlil_domain_schema1_bootstrap_plan_t *out_plan)
{
    ninlil_domain_schema1_bootstrap_record_t record;
    uint32_t index;
    uint32_t encoded_bytes = 0u;
    uint32_t logical_bytes = 0u;
    ninlil_status_t status;

    if (out_plan == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(
            binding,
            binding == NULL ? 0u : sizeof(*binding),
            out_plan,
            sizeof(*out_plan))
        || !ranges_are_disjoint(
            identity,
            identity == NULL ? 0u : sizeof(*identity),
            out_plan,
            sizeof(*out_plan))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_plan, 0, sizeof(*out_plan));
    if (binding == NULL || identity == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_domain_schema1_validate_binding(binding);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_domain_schema1_validate_identity(identity);
    if (status != NINLIL_OK) {
        return status;
    }
    out_plan->binding = *binding;
    out_plan->identity = *identity;
    out_plan->capacity_source_limits = binding->common.limits;
    out_plan->record_count = NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT;
    out_plan->encoded_key_value_bytes =
        NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES;
    out_plan->logical_bytes = NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_LOGICAL_BYTES;
    /* Capture immutable seal before any record derivation. */
    out_plan->sealed_binding = out_plan->binding;
    out_plan->sealed_identity = out_plan->identity;
    out_plan->sealed_capacity_source_limits = out_plan->capacity_source_limits;
    out_plan->sealed_record_count = out_plan->record_count;
    out_plan->sealed_encoded_key_value_bytes =
        out_plan->encoded_key_value_bytes;
    out_plan->sealed_logical_bytes = out_plan->logical_bytes;
    out_plan->sealed_magic = NINLIL_DOMAIN_SCHEMA1_PLAN_SEAL_MAGIC;
    out_plan->sealed_crc32c = plan_seal_crc(out_plan);

    for (index = 0u; index < NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT;
         ++index) {
        status = ninlil_domain_schema1_bootstrap_record_at(
            out_plan, index, &record);
        if (status != NINLIL_OK) {
            (void)memset(out_plan, 0, sizeof(*out_plan));
            return status;
        }
        encoded_bytes += record.key.length + record.value_length;
        logical_bytes += 16u + record.key.length + record.value_length;
    }
    if (encoded_bytes
            != NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_ENCODED_KEY_VALUE_BYTES
        || logical_bytes != NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_LOGICAL_BYTES
        || !plan_is_canonical(out_plan)) {
        (void)memset(out_plan, 0, sizeof(*out_plan));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_bootstrap_record_at(
    const ninlil_domain_schema1_bootstrap_plan_t *plan,
    uint32_t index,
    ninlil_domain_schema1_bootstrap_record_t *out_record)
{
    ninlil_model_runtime_store_key_id_t key_id;
    ninlil_status_t status;
    uint64_t capacity_limits[11];

    if (out_record == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (plan == NULL
        || !ranges_are_disjoint(
            plan, sizeof(*plan), out_record, sizeof(*out_record))) {
        if (out_record != NULL) {
            (void)memset(out_record, 0, sizeof(*out_record));
        }
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_record, 0, sizeof(*out_record));
    if (!plan_is_canonical(plan)
        || index >= NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    key_id = (ninlil_model_runtime_store_key_id_t)(index + 1u);
    status = ninlil_model_runtime_store_build_key(key_id, &out_record->key);
    if (status != NINLIL_OK) {
        (void)memset(out_record, 0, sizeof(*out_record));
        return status;
    }
    /* Always recompute from sealed fields, never mutable public copies. */
    if (index == 0u) {
        status = ninlil_domain_schema1_encode_binding(
            &plan->sealed_binding,
            out_record->value,
            sizeof(out_record->value),
            &out_record->value_length);
    } else if (index == 1u) {
        status = ninlil_model_runtime_store_encode_identity(
            &plan->sealed_identity,
            out_record->value,
            sizeof(out_record->value),
            &out_record->value_length);
    } else if (index < 6u) {
        ninlil_model_runtime_store_counter_t counter;
        counter.kind =
            (ninlil_model_runtime_store_counter_kind_t)(index - 1u);
        counter.value = 0u;
        counter.exhausted_marker = 0u;
        status = ninlil_model_runtime_store_encode_counter(
            key_id,
            &counter,
            out_record->value,
            sizeof(out_record->value),
            &out_record->value_length);
    } else {
        ninlil_model_runtime_store_capacity_t capacity;
        uint32_t capacity_index = index - 6u;
        if (!derive_capacity_limits(
                &plan->sealed_binding.common.limits, capacity_limits)) {
            (void)memset(out_record, 0, sizeof(*out_record));
            return NINLIL_E_INVALID_ARGUMENT;
        }
        capacity.kind = (ninlil_resource_kind_t)(capacity_index + 1u);
        capacity.limit = capacity_limits[capacity_index];
        capacity.used = 0u;
        capacity.reserved = 0u;
        capacity.high_water = 0u;
        capacity.capacity_epoch = 1u;
        capacity.blocked = 0u;
        capacity.counter_exhausted = 0u;
        status = ninlil_model_runtime_store_encode_capacity(
            key_id,
            &capacity,
            out_record->value,
            sizeof(out_record->value),
            &out_record->value_length);
    }
    if (status != NINLIL_OK) {
        (void)memset(out_record, 0, sizeof(*out_record));
    }
    return status;
}

ninlil_status_t ninlil_domain_schema1_classify_t1a_commit_unknown(
    const ninlil_domain_schema1_bootstrap_plan_t *expected_plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_t1a_class_t *out_class)
{
    uint32_t index;
    ninlil_domain_schema1_bootstrap_record_t expected;
    size_t rows_bytes;

    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (expected_plan == NULL
        || !ranges_are_disjoint(
            expected_plan,
            sizeof(*expected_plan),
            out_class,
            sizeof(*out_class))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (row_count > 0u) {
        if (rows == NULL
            || !ninlil_domain_schema1_checked_count_bytes(
                row_count,
                sizeof(ninlil_domain_schema1_snapshot_row_t),
                &rows_bytes)
            || !ranges_are_disjoint(
                rows, rows_bytes, out_class, sizeof(*out_class))
            || !ranges_are_disjoint(
                expected_plan, sizeof(*expected_plan), rows, rows_bytes)) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
        for (index = 0u; index < row_count; ++index) {
            if (!bytes_view_shape_is_valid(rows[index].key)
                || !bytes_view_shape_is_valid(rows[index].value)
                || !ranges_are_disjoint(
                    rows[index].key.data,
                    rows[index].key.length,
                    out_class,
                    sizeof(*out_class))
                || !ranges_are_disjoint(
                    rows[index].value.data,
                    rows[index].value.length,
                    out_class,
                    sizeof(*out_class))
                || !ranges_are_disjoint(
                    expected_plan,
                    sizeof(*expected_plan),
                    rows[index].key.data,
                    rows[index].key.length)
                || !ranges_are_disjoint(
                    expected_plan,
                    sizeof(*expected_plan),
                    rows[index].value.data,
                    rows[index].value.length)) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
        }
    }

    *out_class = NINLIL_DOMAIN_SCHEMA1_T1A_CORRUPT;
    if (!plan_is_canonical(expected_plan)) {
        return NINLIL_OK;
    }
    if (row_count == 0u) {
        *out_class = NINLIL_DOMAIN_SCHEMA1_T1A_OLD;
        return NINLIL_OK;
    }
    if (row_count != NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT) {
        return NINLIL_OK;
    }
    for (index = 0u; index < row_count; ++index) {
        ninlil_status_t status = ninlil_domain_schema1_bootstrap_record_at(
            expected_plan, index, &expected);
        if (status != NINLIL_OK) {
            return NINLIL_OK;
        }
        if (rows[index].key.length != expected.key.length
            || rows[index].value.length != expected.value_length
            || memcmp(
                   rows[index].key.data,
                   expected.key.bytes,
                   expected.key.length)
                != 0
            || memcmp(
                   rows[index].value.data,
                   expected.value,
                   expected.value_length)
                != 0) {
            return NINLIL_OK;
        }
    }
    *out_class = NINLIL_DOMAIN_SCHEMA1_T1A_NEW;
    return NINLIL_OK;
}
