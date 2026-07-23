#include "runtime_internal.h"
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_event_mgmt.h"
#include "runtime_v1_spine_durable.h"

#include "submission_admission.h"
#include "submission_preflight.h"

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define NINLIL_RT_SERVICE_MAGIC ((uint32_t)0x4e525356u)

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int id_nonzero(const ninlil_id128_t *id)
{
    return bytes_nonzero(id->bytes, sizeof(id->bytes));
}

static int header_valid(uint16_t abi_version, uint16_t struct_size, size_t expected)
{
    return abi_version == NINLIL_ABI_VERSION && struct_size == (uint16_t)expected;
}

static int validate_struct_header(const void *header, size_t expected_size)
{
    const uint16_t *fields = (const uint16_t *)header;

    if (header == NULL) {
        return 0;
    }
    return header_valid(fields[0], fields[1], expected_size);
}

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

void ninlil_rt_zero_submission_result(ninlil_submission_result_t *result)
{
    if (result != NULL) {
        (void)memset(result, 0, sizeof(*result));
        set_header(&result->abi_version, &result->struct_size, sizeof(*result));
    }
}

void ninlil_rt_zero_cancel_result(ninlil_cancel_result_t *result)
{
    if (result != NULL) {
        (void)memset(result, 0, sizeof(*result));
        set_header(&result->abi_version, &result->struct_size, sizeof(*result));
    }
}

void ninlil_rt_zero_step_result(ninlil_step_result_t *result)
{
    if (result != NULL) {
        (void)memset(result, 0, sizeof(*result));
        set_header(&result->abi_version, &result->struct_size, sizeof(*result));
        result->health = NINLIL_HEALTH_OK;
    }
}

ninlil_status_t ninlil_rt_validate_live_runtime(
    ninlil_runtime_t *runtime,
    uint32_t allow_destroying)
{
    if (runtime == NULL || runtime->magic != NINLIL_RT_MAGIC) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (runtime->lifecycle == NINLIL_RT_LIFECYCLE_DESTROYED) {
        return NINLIL_E_INVALID_STATE;
    }
    if (runtime->lifecycle == NINLIL_RT_LIFECYCLE_DESTROYING
        && allow_destroying == 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    if (runtime->lifecycle != NINLIL_RT_LIFECYCLE_LIVE
        && !(allow_destroying != 0u
            && runtime->lifecycle == NINLIL_RT_LIFECYCLE_DESTROYING)) {
        return NINLIL_E_INVALID_STATE;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_validate_owner_thread(
    ninlil_runtime_t *runtime,
    uint32_t allow_callback)
{
    const ninlil_execution_ops_t *execution;
    uint64_t context_id;

    if (runtime->platform == NULL || runtime->platform->execution == NULL
        || runtime->platform->execution->current_context_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    execution = runtime->platform->execution;
    context_id = execution->current_context_id(execution->user);
    if (context_id == 0u) {
        return NINLIL_E_DEGRADED;
    }
    if (context_id != runtime->owner_context_id) {
        return NINLIL_E_WRONG_THREAD;
    }
    if (runtime->in_step != 0u && allow_callback == 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (runtime->in_callback != 0u) {
        return NINLIL_E_REENTRANT;
    }
    return NINLIL_OK;
}

static void *rt_allocate(
    const ninlil_platform_ops_t *platform,
    uint64_t size,
    uint32_t alignment)
{
    if (platform == NULL || platform->allocator == NULL
        || platform->allocator->allocate == NULL) {
        return NULL;
    }
    return platform->allocator->allocate(
        platform->allocator->user, size, alignment);
}

static void rt_deallocate(
    const ninlil_platform_ops_t *platform,
    void *ptr,
    uint64_t size,
    uint32_t alignment)
{
    if (platform == NULL || platform->allocator == NULL
        || platform->allocator->deallocate == NULL || ptr == NULL) {
        return;
    }
    platform->allocator->deallocate(
        platform->allocator->user, ptr, size, alignment);
}

static void rt_free_runtime(
    const ninlil_platform_ops_t *platform,
    ninlil_runtime_t *runtime)
{
    if (runtime == NULL) {
        return;
    }
    if (runtime->services != NULL) {
        rt_deallocate(
            platform,
            runtime->services,
            (uint64_t)runtime->service_capacity * sizeof(*runtime->services),
            (uint32_t)alignof(ninlil_rt_service_slot_t));
    }
    if (runtime->transactions != NULL) {
        rt_deallocate(
            platform,
            runtime->transactions,
            (uint64_t)runtime->transaction_capacity
                * sizeof(*runtime->transactions),
            (uint32_t)alignof(ninlil_rt_transaction_slot_t));
    }
    if (runtime->namespace_bytes != NULL) {
        rt_deallocate(
            platform,
            runtime->namespace_bytes,
            runtime->namespace_length,
            1u);
    }
    rt_deallocate(
        platform, runtime, sizeof(*runtime), (uint32_t)alignof(ninlil_runtime_t));
}

static void rt_close_ports(ninlil_runtime_t *runtime)
{
    const ninlil_platform_ops_t *platform = runtime->platform;

    if (platform == NULL) {
        return;
    }
    if (platform->bearer != NULL && platform->bearer->close != NULL
        && runtime->bearer != NULL) {
        platform->bearer->close(platform->bearer->user, runtime->bearer);
        runtime->bearer = NULL;
    }
    if (platform->storage != NULL && platform->storage->close != NULL
        && runtime->storage != NULL) {
        platform->storage->close(platform->storage->user, runtime->storage);
        runtime->storage = NULL;
    }
}

static int descriptor_text_valid(ninlil_bytes_view_t view)
{
    return view.length > 0u && view.length <= NINLIL_MAX_TEXT_ID_BYTES
        && (view.length == 0u || view.data != NULL);
}

static int digest_valid(const ninlil_digest256_t *digest)
{
    return digest != NULL && digest->algorithm == NINLIL_DIGEST_SHA256
        && digest->reserved_zero == 0u
        && bytes_nonzero(digest->bytes, sizeof(digest->bytes));
}

static int evidence_mask_valid(uint32_t mask)
{
    const uint32_t known =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_VERIFIED);

    return mask != 0u && (mask & ~known) == 0u;
}

static int descriptor_matches_role_matrix(
    ninlil_role_t role,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_model_local_submission_side_t *out_side)
{
    if (descriptor->family == NINLIL_FAMILY_DESIRED_STATE) {
        if (descriptor->direction != NINLIL_DIRECTION_DOWNLINK
            || descriptor->admission_authority
                != NINLIL_AUTHORITY_CONTROLLER_ONLY
            || descriptor->apply_contract == NINLIL_APPLY_ATOMIC_PARTICIPANT_RESERVED) {
            return 0;
        }
        if (role == NINLIL_ROLE_CONTROLLER) {
            if (callbacks->on_delivery != NULL || callbacks->on_reconcile != NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_SENDER;
            return 1;
        }
        if (role == NINLIL_ROLE_ENDPOINT) {
            if (callbacks->on_delivery == NULL) {
                return -1;
            }
            if (descriptor->apply_contract == NINLIL_APPLY_APPLICATION_DEDUP
                && callbacks->on_reconcile == NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER;
            return 1;
        }
        return 0;
    }
    if (descriptor->family == NINLIL_FAMILY_EVENT_FACT) {
        if (descriptor->direction != NINLIL_DIRECTION_UPLINK
            || descriptor->admission_authority
                != NINLIL_AUTHORITY_ORIGIN_WITH_GRANT
            || descriptor->apply_contract == NINLIL_APPLY_ATOMIC_PARTICIPANT_RESERVED) {
            return 0;
        }
        if (role == NINLIL_ROLE_ENDPOINT) {
            if (callbacks->on_delivery != NULL || callbacks->on_reconcile != NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_SENDER;
            return 1;
        }
        if (role == NINLIL_ROLE_CONTROLLER) {
            if (callbacks->on_delivery == NULL || callbacks->on_reconcile == NULL) {
                return -1;
            }
            *out_side = NINLIL_MODEL_LOCAL_SUBMISSION_RECEIVER;
            return 1;
        }
        return 0;
    }
    return 0;
}

static int descriptor_limits_within_runtime(
    const ninlil_model_runtime_resource_limits_projection_t *limits,
    const ninlil_service_descriptor_t *descriptor)
{
    if (descriptor->target_limit != 1u
        || limits->max_targets_per_transaction != 1u) {
        return 0;
    }
    if (descriptor->logical_payload_limit > limits->max_logical_payload_bytes
        || descriptor->inflight_limit > limits->max_nonterminal_transactions
        || descriptor->max_attempts_per_target_per_cycle
            != NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE) {
        return 0;
    }
    return 1;
}

static int descriptor_semantics_valid(
    const ninlil_service_descriptor_t *descriptor,
    uint64_t terminal_retention_ms,
    uint64_t result_cache_retention_ms)
{
    if (!descriptor_text_valid(descriptor->namespace_id)
        || !descriptor_text_valid(descriptor->service_id)
        || !descriptor_text_valid(descriptor->schema_id)
        || !digest_valid(&descriptor->descriptor_digest)
        || !id_nonzero(&descriptor->local_application_instance_id)
        || descriptor->schema_minor_min > descriptor->schema_minor_max
        || descriptor->reserved_zero_u16 != 0u
        || descriptor->reserved_zero_u32 != 0u
        || !evidence_mask_valid(descriptor->supported_evidence_mask)
        || descriptor->logical_payload_limit == 0u
        || descriptor->inflight_limit == 0u
        || descriptor->admission_window_ms == 0u
        || descriptor->admission_window_ms > NINLIL_M1A_MAX_RETRY_DELAY_MS
        || descriptor->max_admissions_per_window == 0u
        || descriptor->max_payload_bytes_per_window
            < descriptor->logical_payload_limit
        || descriptor->required_dedup_window_ms == 0u
        || descriptor->attempt_receipt_timeout_ms == 0u
        || descriptor->attempt_receipt_timeout_ms
            > NINLIL_M1A_MAX_ATTEMPT_RECEIPT_TIMEOUT_MS
        || descriptor->retry_backoff_ms == 0u
        || descriptor->retry_backoff_ms > NINLIL_M1A_MAX_RETRY_BACKOFF_MS
        || descriptor->application_completion_timeout_ms == 0u
        || descriptor->application_completion_timeout_ms
            > NINLIL_M1A_MAX_APPLICATION_COMPLETION_TIMEOUT_MS) {
        return 0;
    }
    if (terminal_retention_ms < descriptor->required_dedup_window_ms
        || result_cache_retention_ms < descriptor->required_dedup_window_ms) {
        return -2;
    }
    if (descriptor->family == NINLIL_FAMILY_DESIRED_STATE) {
        if (descriptor->minimum_deadline_ms == 0u
            || descriptor->minimum_deadline_ms > descriptor->maximum_deadline_ms
            || descriptor->maximum_deadline_ms >= NINLIL_NO_DEADLINE
            || descriptor->maximum_evidence_grace_ms == 0u) {
            return 0;
        }
        return 1;
    }
    if (descriptor->family == NINLIL_FAMILY_EVENT_FACT) {
        if (descriptor->minimum_deadline_ms != NINLIL_NO_DEADLINE
            || descriptor->maximum_deadline_ms != NINLIL_NO_DEADLINE
            || descriptor->maximum_evidence_grace_ms != 0u) {
            return 0;
        }
        return 1;
    }
    return -1;
}

static void fill_model_service(
    ninlil_rt_service_slot_t *slot,
    const ninlil_runtime_t *runtime,
    ninlil_model_local_submission_side_t side)
{
    const ninlil_service_descriptor_t *descriptor = &slot->descriptor;

    (void)memset(&slot->model_service, 0, sizeof(slot->model_service));
    slot->model_service.family = descriptor->family;
    slot->model_service.local_side = side;
    slot->model_service.source.abi_version = NINLIL_ABI_VERSION;
    slot->model_service.source.struct_size =
        (uint16_t)sizeof(slot->model_service.source);
    slot->model_service.source.runtime_id = runtime->config.runtime_id;
    slot->model_service.source.application_instance_id =
        descriptor->local_application_instance_id;
    slot->model_service.source.local_identity.abi_version = NINLIL_ABI_VERSION;
    slot->model_service.source.local_identity.struct_size =
        (uint16_t)sizeof(slot->model_service.source.local_identity);
    slot->model_service.source.local_identity.device_id =
        runtime->config.device_id;
    slot->model_service.source.local_identity.installation_id =
        runtime->config.installation_id;
    slot->model_service.source.local_identity.site_domain_id =
        runtime->config.site_domain_id;
    slot->model_service.source.local_identity.binding_epoch =
        runtime->config.binding_epoch;
    slot->model_service.source.local_identity.membership_epoch =
        runtime->config.membership_epoch;
    slot->model_service.source.local_identity.flags =
        runtime->config.identity_flags;
    slot->model_service.identity.abi_version = NINLIL_ABI_VERSION;
    slot->model_service.identity.struct_size =
        (uint16_t)sizeof(slot->model_service.identity);
    (void)memcpy(
        slot->model_service.identity.namespace_id.bytes,
        descriptor->namespace_id.data,
        descriptor->namespace_id.length);
    slot->model_service.identity.namespace_id.length =
        (uint8_t)descriptor->namespace_id.length;
    (void)memcpy(
        slot->model_service.identity.service_id.bytes,
        descriptor->service_id.data,
        descriptor->service_id.length);
    slot->model_service.identity.service_id.length =
        (uint8_t)descriptor->service_id.length;
    (void)memcpy(
        slot->model_service.identity.schema_id.bytes,
        descriptor->schema_id.data,
        descriptor->schema_id.length);
    slot->model_service.identity.schema_id.length =
        (uint8_t)descriptor->schema_id.length;
    slot->model_service.identity.descriptor_revision =
        descriptor->descriptor_revision;
    slot->model_service.identity.descriptor_digest = descriptor->descriptor_digest;
    slot->model_service.identity.schema_major = descriptor->schema_major;
    slot->model_service.identity.schema_minor = descriptor->schema_minor_min;
    slot->model_service.identity.family = descriptor->family;
    slot->model_service.schema_major = descriptor->schema_major;
    slot->model_service.schema_minor_min = descriptor->schema_minor_min;
    slot->model_service.schema_minor_max = descriptor->schema_minor_max;
    slot->model_service.supported_evidence_mask =
        descriptor->supported_evidence_mask;
    slot->model_service.logical_payload_limit = descriptor->logical_payload_limit;
    slot->model_service.inflight_limit = descriptor->inflight_limit;
    slot->model_service.admission_window_ms = descriptor->admission_window_ms;
    slot->model_service.max_admissions_per_window =
        descriptor->max_admissions_per_window;
    slot->model_service.max_payload_bytes_per_window =
        descriptor->max_payload_bytes_per_window;
    slot->model_service.max_evidence_per_target = 8u;
    slot->model_service.minimum_deadline_ms = descriptor->minimum_deadline_ms;
    slot->model_service.maximum_deadline_ms = descriptor->maximum_deadline_ms;
    slot->model_service.maximum_evidence_grace_ms =
        descriptor->maximum_evidence_grace_ms;
}

static int service_key_equal(
    const ninlil_service_descriptor_t *left,
    const ninlil_service_descriptor_t *right)
{
    return left->namespace_id.length == right->namespace_id.length
        && left->service_id.length == right->service_id.length
        && left->descriptor_revision == right->descriptor_revision
        && memcmp(
            left->namespace_id.data,
            right->namespace_id.data,
            left->namespace_id.length)
            == 0
        && memcmp(
            left->service_id.data,
            right->service_id.data,
            left->service_id.length)
            == 0;
}

static int service_contract_equal(
    const ninlil_service_descriptor_t *left,
    const ninlil_service_descriptor_t *right)
{
    return left->schema_major == right->schema_major
        && left->schema_minor_min == right->schema_minor_min
        && left->schema_minor_max == right->schema_minor_max
        && left->family == right->family
        && left->direction == right->direction
        && left->admission_authority == right->admission_authority
        && left->apply_contract == right->apply_contract
        && left->custody_policy == right->custody_policy
        && left->supported_evidence_mask == right->supported_evidence_mask
        && left->logical_payload_limit == right->logical_payload_limit
        && left->target_limit == right->target_limit
        && left->inflight_limit == right->inflight_limit
        && left->max_attempts_per_target_per_cycle
            == right->max_attempts_per_target_per_cycle
        && left->admission_window_ms == right->admission_window_ms
        && left->max_admissions_per_window == right->max_admissions_per_window
        && left->max_payload_bytes_per_window
            == right->max_payload_bytes_per_window
        && left->minimum_deadline_ms == right->minimum_deadline_ms
        && left->maximum_deadline_ms == right->maximum_deadline_ms
        && left->maximum_evidence_grace_ms == right->maximum_evidence_grace_ms
        && left->attempt_receipt_timeout_ms == right->attempt_receipt_timeout_ms
        && left->retry_backoff_ms == right->retry_backoff_ms
        && left->application_completion_timeout_ms
            == right->application_completion_timeout_ms
        && left->required_dedup_window_ms == right->required_dedup_window_ms
        && memcmp(
            left->descriptor_digest.bytes,
            right->descriptor_digest.bytes,
            sizeof(left->descriptor_digest.bytes))
            == 0;
}

static int callbacks_equal(
    const ninlil_service_callbacks_t *left,
    const ninlil_service_callbacks_t *right)
{
    return left->user == right->user
        && left->on_delivery == right->on_delivery
        && left->on_reconcile == right->on_reconcile;
}

static ninlil_rt_service_slot_t *find_service_slot(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    uint32_t *out_index)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        ninlil_rt_service_slot_t *slot = &runtime->services[index];

        if (slot->in_use == 0u) {
            continue;
        }
        if (service_key_equal(descriptor, &slot->descriptor)) {
            if (out_index != NULL) {
                *out_index = index;
            }
            return slot;
        }
    }
    return NULL;
}

static ninlil_rt_service_slot_t *alloc_service_slot(
    ninlil_runtime_t *runtime,
    uint32_t *out_index)
{
    uint32_t index;

    for (index = 0u; index < runtime->service_capacity; ++index) {
        if (runtime->services[index].in_use == 0u) {
            if (out_index != NULL) {
                *out_index = index;
            }
            return &runtime->services[index];
        }
    }
    return NULL;
}

static void service_deregister_slot(ninlil_rt_service_slot_t *slot)
{
    if (slot == NULL) {
        return;
    }
    (void)memset(slot, 0, sizeof(*slot));
}

ninlil_rt_transaction_slot_t *ninlil_rt_find_transaction(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id)
{
    uint32_t index;

    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        ninlil_rt_transaction_slot_t *slot = &runtime->transactions[index];

        if (slot->in_use != 0u
            && memcmp(
                slot->transaction_id.bytes,
                transaction_id->bytes,
                sizeof(transaction_id->bytes))
                == 0) {
            return slot;
        }
    }
    return NULL;
}

ninlil_rt_transaction_slot_t *ninlil_rt_alloc_transaction(
    ninlil_runtime_t *runtime)
{
    uint32_t index;

    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        if (runtime->transactions[index].in_use == 0u) {
            return &runtime->transactions[index];
        }
    }
    return NULL;
}

/* --- public API --- */

ninlil_status_t ninlil_runtime_create(
    const ninlil_runtime_config_t *config,
    const ninlil_platform_ops_t *platform,
    ninlil_runtime_t **out_runtime)
{
    ninlil_model_runtime_validation_result_t validation;
    ninlil_model_runtime_create_gate_t gate;
    ninlil_runtime_store_stage5_result_t stage5;
    ninlil_stage5_empty_metadata_result_t empty_meta;
    ninlil_model_runtime_entropy_observation_t entropy_obs[4];
    ninlil_model_runtime_entropy_result_t entropy;
    ninlil_model_runtime_health_projection_t health;
    ninlil_model_runtime_stage9_health_input_t health_in;
    ninlil_runtime_t *runtime = NULL;
    ninlil_status_t status;
    uint32_t index;

    if (out_runtime == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_runtime = NULL;

    status = ninlil_model_runtime_validate_and_derive(
        config, platform, &validation);
    if (status != NINLIL_OK) {
        return validation.status;
    }

    if (platform->execution == NULL
        || platform->execution->current_context_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (platform->execution->current_context_id(platform->execution->user) == 0u) {
        return NINLIL_E_DEGRADED;
    }

    runtime = rt_allocate(platform, sizeof(*runtime), (uint32_t)alignof(ninlil_runtime_t));
    if (runtime == NULL) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    (void)memset(runtime, 0, sizeof(*runtime));
    runtime->magic = NINLIL_RT_MAGIC;
    runtime->lifecycle = NINLIL_RT_LIFECYCLE_CREATING;
    runtime->platform = platform;
    runtime->config = validation.accepted_config;
    runtime->capacity_limits = validation.capacity_limits;
    status = ninlil_model_resource_ledger_init(
        &runtime->capacity_limits, &runtime->resource_ledger);
    if (status != NINLIL_OK) {
        rt_free_runtime(platform, runtime);
        return status;
    }
    runtime->owner_context_id =
        platform->execution->current_context_id(platform->execution->user);
    runtime->namespace_length = config->storage_namespace.length;
    runtime->namespace_bytes = rt_allocate(
        platform, runtime->namespace_length, 1u);
    runtime->services = rt_allocate(
        platform,
        (uint64_t)runtime->config.limits.max_services
            * sizeof(*runtime->services),
        (uint32_t)alignof(ninlil_rt_service_slot_t));
    runtime->transactions = rt_allocate(
        platform,
        (uint64_t)runtime->config.limits.max_nonterminal_transactions
            * sizeof(*runtime->transactions),
        (uint32_t)alignof(ninlil_rt_transaction_slot_t));
    if (runtime->namespace_bytes == NULL
        || (runtime->config.limits.max_services > 0u && runtime->services == NULL)
        || (runtime->config.limits.max_nonterminal_transactions > 0u
            && runtime->transactions == NULL)) {
        rt_free_runtime(platform, runtime);
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    if (runtime->config.limits.max_services > 0u) {
        (void)memset(
            runtime->services,
            0,
            (size_t)runtime->config.limits.max_services
                * sizeof(*runtime->services));
    }
    if (runtime->config.limits.max_nonterminal_transactions > 0u) {
        (void)memset(
            runtime->transactions,
            0,
            (size_t)runtime->config.limits.max_nonterminal_transactions
                * sizeof(*runtime->transactions));
    }
    (void)memcpy(
        runtime->namespace_bytes,
        config->storage_namespace.data,
        runtime->namespace_length);
    runtime->service_capacity = runtime->config.limits.max_services;
    runtime->transaction_capacity =
        runtime->config.limits.max_nonterminal_transactions;

    {
        ninlil_bytes_view_t ns = {
            runtime->namespace_bytes, runtime->namespace_length
        };
        ninlil_storage_status_t storage_status = platform->storage->open(
            platform->storage->user,
            ns,
            NINLIL_STORAGE_SCHEMA_M1A,
            &runtime->storage);
        ninlil_model_runtime_map_storage_open(
            storage_status, runtime->storage != NULL, &gate);
        if (gate.continue_create == 0u) {
            rt_close_ports(runtime);
            rt_free_runtime(platform, runtime);
            return gate.api_status;
        }
    }

    (void)memset(&stage5, 0, sizeof(stage5));
    status = ninlil_runtime_store_stage5_private_hookup(
        platform->storage,
        &runtime->storage,
        &validation,
        NULL,
        &runtime->stage5_ws,
        &stage5);
    if (status != NINLIL_OK) {
        rt_close_ports(runtime);
        rt_free_runtime(platform, runtime);
        return status;
    }

    if (stage5.outcome
        == NINLIL_RUNTIME_STORE_STAGE5_NEW_BOOTSTRAP_STAGE5_PENDING) {
        status = ninlil_stage5_empty_metadata_commit(
            platform->storage,
            &runtime->storage,
            &validation,
            &runtime->empty_ws,
            &empty_meta);
        if (status != NINLIL_OK || empty_meta.reopen_required != 0u) {
            rt_close_ports(runtime);
            rt_free_runtime(platform, runtime);
            return status != NINLIL_OK ? status : NINLIL_E_STORAGE_COMMIT_UNKNOWN;
        }
        runtime->storage_recovery_complete = 1u;
    } else if (stage5.outcome
               == NINLIL_RUNTIME_STORE_STAGE5_EXISTING_SCAN_ADOPTED_D3_PENDING) {
        ninlil_v1_durable_recovery_publication_result_t publication;

        status = ninlil_v1_durable_recovery_publication_gate_storage(
            platform->storage,
            runtime->storage,
            runtime->commit_unknown_fence,
            &publication);
        if (status != NINLIL_OK) {
            rt_close_ports(runtime);
            rt_free_runtime(platform, runtime);
            return status;
        }
        if (publication.adopted != 0u
            && publication.success_evidence_count != 0u) {
            runtime->storage_recovery_complete = 1u;
        }
    } else {
        rt_close_ports(runtime);
        rt_free_runtime(platform, runtime);
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (runtime->storage_recovery_complete == 0u) {
        rt_close_ports(runtime);
        rt_free_runtime(platform, runtime);
        return NINLIL_E_STORAGE_CORRUPT;
    }

    {
        ninlil_bearer_status_t bearer_status = platform->bearer->open(
            platform->bearer->user,
            &config->runtime_id,
            config->role,
            &runtime->bearer);
        ninlil_model_runtime_map_bearer_open(
            bearer_status, runtime->bearer != NULL, &gate);
        if (gate.continue_create == 0u) {
            rt_close_ports(runtime);
            rt_free_runtime(platform, runtime);
            return gate.api_status;
        }
    }

    {
        ninlil_model_runtime_clock_input_t clock_in;

        (void)memset(&clock_in, 0, sizeof(clock_in));
        clock_in.port_status = platform->clock->now(
            platform->clock->user, &clock_in.sample);
        ninlil_model_runtime_classify_clock_with_external_baseline(
            &clock_in, &gate);
        if (gate.continue_create == 0u) {
            rt_close_ports(runtime);
            rt_free_runtime(platform, runtime);
            return gate.api_status;
        }
        runtime->started_sample = clock_in.sample;
    }

    (void)memset(entropy_obs, 0, sizeof(entropy_obs));
    for (index = 0u; index < 4u; ++index) {
        uint8_t candidate[16];

        entropy_obs[index].port_status = platform->entropy->fill(
            platform->entropy->user, candidate, 16u);
        (void)memcpy(
            entropy_obs[index].candidate.bytes, candidate, sizeof(candidate));
    }
    status = ninlil_model_runtime_map_metrics_entropy(
        entropy_obs, 4u, &entropy);
    if (status != NINLIL_OK || entropy.api_status != NINLIL_OK) {
        rt_close_ports(runtime);
        rt_free_runtime(platform, runtime);
        return entropy.api_status != NINLIL_OK
            ? entropy.api_status : status;
    }
    runtime->metrics_epoch_id = entropy.metrics_epoch_id;

    (void)memset(&health_in, 0, sizeof(health_in));
    health_in.storage_recovery_complete = runtime->storage_recovery_complete;
    ninlil_model_runtime_project_stage9_health(&health_in, &health);
    runtime->health = health.health;
    runtime->degraded_reason = health.degraded_reason;
    runtime->lifecycle = NINLIL_RT_LIFECYCLE_LIVE;

    if (runtime->storage_recovery_complete != 0u) {
        status = ninlil_rt_v1_delivery_restart_scan(runtime);
        if (status != NINLIL_OK) {
            rt_close_ports(runtime);
            rt_free_runtime(platform, runtime);
            return status;
        }
    }

    *out_runtime = runtime;
    return NINLIL_OK;
}

ninlil_status_t ninlil_runtime_destroy(ninlil_runtime_t *runtime)
{
    ninlil_status_t status;
    uint32_t index;

    status = ninlil_rt_validate_live_runtime(runtime, 1u);
    if (status == NINLIL_E_INVALID_ARGUMENT || status == NINLIL_E_INVALID_STATE) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    runtime->lifecycle = NINLIL_RT_LIFECYCLE_DESTROYING;
    for (index = 0u; index < runtime->service_capacity; ++index) {
        service_deregister_slot(&runtime->services[index]);
    }
    rt_close_ports(runtime);
    runtime->lifecycle = NINLIL_RT_LIFECYCLE_DESTROYED;
    if (runtime->platform != NULL && runtime->platform->allocator != NULL
        && runtime->platform->allocator->deallocate != NULL) {
        rt_free_runtime(runtime->platform, runtime);
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_service_register(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_service_t **out_service)
{
    ninlil_status_t status;
    ninlil_model_local_submission_side_t side;
    int matrix;
    int semantics;
    ninlil_rt_service_slot_t *slot;
    uint32_t slot_index = 0u;
    uint32_t free_index = 0u;

    if (out_service != NULL) {
        *out_service = NULL;
    }
    if (runtime == NULL || descriptor == NULL || callbacks == NULL
        || out_service == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!validate_struct_header(descriptor, sizeof(*descriptor))
        || !validate_struct_header(callbacks, sizeof(*callbacks))) {
        return NINLIL_E_ABI_MISMATCH;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }

    matrix = descriptor_matches_role_matrix(
        runtime->config.role, descriptor, callbacks, &side);
    if (matrix == 0) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (matrix < 0) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    semantics = descriptor_semantics_valid(
        descriptor,
        runtime->config.terminal_retention_ms,
        runtime->config.result_cache_retention_ms);
    if (semantics == -2) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (semantics <= 0) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!descriptor_limits_within_runtime(
            &runtime->config.limits, descriptor)) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (descriptor->family == NINLIL_FAMILY_EVENT_FACT
        && side == NINLIL_MODEL_LOCAL_SUBMISSION_SENDER
        && (runtime->config.limits.max_event_spool_count == 0u
            || runtime->config.limits.max_event_spool_bytes
                < NINLIL_M1A_EVENT_MANAGEMENT_RESERVATION_BYTES)) {
        return NINLIL_E_UNSUPPORTED;
    }

    slot = find_service_slot(runtime, descriptor, &slot_index);
    if (slot != NULL) {
        if (!service_contract_equal(descriptor, &slot->descriptor)
            || memcmp(
                descriptor->local_application_instance_id.bytes,
                slot->descriptor.local_application_instance_id.bytes,
                sizeof(descriptor->local_application_instance_id.bytes))
                != 0) {
            return NINLIL_E_CONFLICT;
        }
        if (!callbacks_equal(callbacks, &slot->callbacks)) {
            return NINLIL_E_CONFLICT;
        }
        slot->attached = 1u;
        *out_service = &slot->public_handle;
        return NINLIL_OK;
    }

    if (runtime->service_count >= runtime->service_capacity) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    slot = alloc_service_slot(runtime, &free_index);
    if (slot == NULL) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }

    slot_index = free_index;
    status = ninlil_rt_v1_spine_service_register_commit(
        runtime, descriptor, &slot_index);
    if (status != NINLIL_OK) {
        return status;
    }

    slot->in_use = 1u;
    slot->attached = 1u;
    slot->descriptor = *descriptor;
    slot->callbacks = *callbacks;
    fill_model_service(slot, runtime, side);
    slot->public_handle.magic = NINLIL_RT_SERVICE_MAGIC;
    slot->public_handle.runtime = runtime;
    slot->public_handle.slot_index = free_index;
    runtime->service_count += 1u;
    runtime->pending_work = 1u;
    *out_service = &slot->public_handle;
    return NINLIL_OK;
}

ninlil_status_t ninlil_submit(
    ninlil_service_t *service,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result)
{
    ninlil_runtime_t *runtime;
    ninlil_rt_service_slot_t *slot;
    ninlil_status_t status;

    ninlil_rt_zero_submission_result(out_result);
    if (service == NULL || submission == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (service->magic != NINLIL_RT_SERVICE_MAGIC || service->runtime == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    runtime = service->runtime;
    if (!validate_struct_header(submission, sizeof(*submission))
        || !validate_struct_header(out_result, sizeof(*out_result))) {
        return NINLIL_E_ABI_MISMATCH;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (service->slot_index >= runtime->service_capacity) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    slot = &runtime->services[service->slot_index];
    if (slot->in_use == 0u || slot->attached == 0u) {
        return NINLIL_E_INVALID_STATE;
    }

    return ninlil_rt_v1_spine_submit_admission(
        runtime, slot, submission, out_result);
}

ninlil_status_t ninlil_cancel_request(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result)
{
    ninlil_status_t status;

    ninlil_rt_zero_cancel_result(out_result);
    if (runtime == NULL || transaction_id == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!validate_struct_header(out_result, sizeof(*out_result))
        || !id_nonzero(transaction_id)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    if (runtime->config.role != NINLIL_ROLE_CONTROLLER) {
        return NINLIL_E_UNSUPPORTED;
    }
    return ninlil_rt_v1_spine_cancel_admission(
        runtime, transaction_id, out_result);
}

ninlil_status_t ninlil_runtime_step(
    ninlil_runtime_t *runtime,
    const ninlil_step_budget_t *budget,
    ninlil_step_result_t *out_result)
{
    ninlil_status_t status;
    ninlil_time_sample_t sample;
    ninlil_port_status_t clock_status;
    ninlil_rt_v1_step_delivery_result_t delivery_result;
    uint32_t ingress_budget;
    uint32_t callback_budget;
    uint32_t transition_budget;
    uint32_t send_budget;

    ninlil_rt_zero_step_result(out_result);
    if (runtime == NULL || budget == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!validate_struct_header(budget, sizeof(*budget))
        || !validate_struct_header(out_result, sizeof(*out_result))) {
        return NINLIL_E_ABI_MISMATCH;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 1u);
    if (status != NINLIL_OK) {
        return status;
    }

    ingress_budget = budget->max_ingress_messages;
    callback_budget = budget->max_callbacks;
    transition_budget = budget->max_state_transitions;
    send_budget = budget->max_bearer_sends;
    if (ingress_budget > runtime->config.limits.max_ingress_per_step) {
        ingress_budget = runtime->config.limits.max_ingress_per_step;
    }
    if (callback_budget > runtime->config.limits.max_callbacks_per_step) {
        callback_budget = runtime->config.limits.max_callbacks_per_step;
    }
    if (transition_budget
        > runtime->config.limits.max_state_transitions_per_step) {
        transition_budget =
            runtime->config.limits.max_state_transitions_per_step;
    }
    if (send_budget > runtime->config.limits.max_bearer_sends_per_step) {
        send_budget = runtime->config.limits.max_bearer_sends_per_step;
    }
    (void)send_budget;

    runtime->in_step = 1u;
    runtime->step_phase = NINLIL_RT_STEP_PHASE_CLOCK;
    clock_status = runtime->platform->clock->now(
        runtime->platform->clock->user, &sample);
    if (clock_status != NINLIL_PORT_OK
        || sample.trust != NINLIL_CLOCK_TRUSTED
        || !id_nonzero(&sample.clock_epoch_id)) {
        runtime->in_step = 0u;
        runtime->step_phase = NINLIL_RT_STEP_PHASE_IDLE;
        out_result->health = runtime->health;
        out_result->degraded_reason = runtime->degraded_reason;
        return clock_status == NINLIL_PORT_TEMPORARY_FAILURE
            || (clock_status == NINLIL_PORT_OK
                && sample.trust == NINLIL_CLOCK_UNCERTAIN)
            ? NINLIL_E_CLOCK_UNCERTAIN
            : NINLIL_E_DEGRADED;
    }

    runtime->step_phase = NINLIL_RT_STEP_PHASE_WORK;
    (void)memset(&delivery_result, 0, sizeof(delivery_result));
    status = ninlil_rt_v1_delivery_step(
        runtime,
        &sample,
        ingress_budget,
        callback_budget,
        transition_budget,
        &delivery_result);
    if (status != NINLIL_OK) {
        runtime->in_step = 0u;
        runtime->step_phase = NINLIL_RT_STEP_PHASE_IDLE;
        out_result->health = runtime->health;
        out_result->degraded_reason = runtime->degraded_reason;
        return status;
    }

    runtime->step_phase = NINLIL_RT_STEP_PHASE_PROJECT;
    out_result->health = runtime->health;
    out_result->degraded_reason = runtime->degraded_reason;
    out_result->more_work = delivery_result.work_remaining != 0u
        ? 1u
        : runtime->pending_work;
    runtime->in_step = 0u;
    runtime->step_phase = NINLIL_RT_STEP_PHASE_IDLE;
    return NINLIL_OK;
}

ninlil_status_t ninlil_offer_accept(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *offer_id,
    ninlil_submission_result_t *out_result)
{
    ninlil_status_t status;

    ninlil_rt_zero_submission_result(out_result);
    if (runtime == NULL || offer_id == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!validate_struct_header(out_result, sizeof(*out_result))) {
        return NINLIL_E_ABI_MISMATCH;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    return NINLIL_E_UNSUPPORTED;
}

ninlil_status_t ninlil_event_resume(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_resume_request_t *request,
    ninlil_event_resume_result_t *out_result)
{
    if (out_result != NULL) {
        (void)memset(out_result, 0, sizeof(*out_result));
        set_header(
            &out_result->abi_version, &out_result->struct_size, sizeof(*out_result));
    }
    if (runtime == NULL || transaction_id == NULL || request == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!validate_struct_header(request, sizeof(*request))
        || !validate_struct_header(out_result, sizeof(*out_result))) {
        return NINLIL_E_ABI_MISMATCH;
    }
    return ninlil_rt_v1_event_resume(
        runtime, transaction_id, request, out_result);
}

ninlil_status_t ninlil_event_discard(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    const ninlil_event_discard_request_t *request,
    ninlil_event_discard_result_t *out_result)
{
    if (out_result != NULL) {
        (void)memset(out_result, 0, sizeof(*out_result));
        set_header(
            &out_result->abi_version, &out_result->struct_size, sizeof(*out_result));
    }
    if (runtime == NULL || transaction_id == NULL || request == NULL
        || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!validate_struct_header(request, sizeof(*request))
        || !validate_struct_header(out_result, sizeof(*out_result))) {
        return NINLIL_E_ABI_MISMATCH;
    }
    return ninlil_rt_v1_event_discard(
        runtime, transaction_id, request, out_result);
}

ninlil_status_t ninlil_transaction_query(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_transaction_snapshot_t *inout_snapshot)
{
    if (inout_snapshot != NULL) {
        (void)memset(inout_snapshot, 0, sizeof(*inout_snapshot));
        set_header(
            &inout_snapshot->abi_version,
            &inout_snapshot->struct_size,
            sizeof(*inout_snapshot));
    }
    if (runtime == NULL || transaction_id == NULL || inout_snapshot == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (ninlil_rt_find_transaction(runtime, transaction_id) == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    return NINLIL_E_NOT_FOUND;
}

ninlil_status_t ninlil_transaction_list(
    ninlil_runtime_t *runtime,
    const ninlil_query_t *query,
    ninlil_transaction_page_t *inout_page)
{
    (void)query;
    if (inout_page != NULL) {
        (void)memset(inout_page, 0, sizeof(*inout_page));
        set_header(
            &inout_page->abi_version, &inout_page->struct_size, sizeof(*inout_page));
    }
    if (runtime == NULL || query == NULL || inout_page == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_delivery_complete(
    ninlil_runtime_t *runtime,
    const ninlil_delivery_token_t *token,
    const ninlil_application_result_t *result)
{
    (void)token;
    (void)result;
    if (runtime == NULL || token == NULL || result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_E_NOT_FOUND;
}

ninlil_status_t ninlil_capacity_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_capacity_snapshot_t *inout_snapshot)
{
    if (inout_snapshot != NULL) {
        (void)memset(inout_snapshot, 0, sizeof(*inout_snapshot));
        set_header(
            &inout_snapshot->abi_version,
            &inout_snapshot->struct_size,
            sizeof(*inout_snapshot));
    }
    if (runtime == NULL || inout_snapshot == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_metrics_snapshot(
    ninlil_runtime_t *runtime,
    ninlil_metrics_snapshot_t *out_snapshot)
{
    if (out_snapshot != NULL) {
        (void)memset(out_snapshot, 0, sizeof(*out_snapshot));
        set_header(
            &out_snapshot->abi_version,
            &out_snapshot->struct_size,
            sizeof(*out_snapshot));
        if (runtime != NULL) {
            out_snapshot->metrics_epoch_id = runtime->metrics_epoch_id;
        }
    }
    if (runtime == NULL || out_snapshot == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}
