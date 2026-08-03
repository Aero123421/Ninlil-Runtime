#include "runtime_v1_spine_durable.h"

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_d3s1.h"
#include "runtime_v1_capability.h"
#include "runtime_v1_delivery_durable.h"
#include "runtime_v1_family_capability.h"
#include "runtime_v1_target_resolver.h"
#include "resource_ledger_batch.h"
#include "submission_admission.h"
#include "submission_canonical_v1.h"
#include "submission_preflight.h"
#include "v1_durable_allowlist.h"
#if defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    && (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING != 0)
#include "domain_schema1_kind1_register.h"
#endif
#if defined(NINLIL_MFDT_V1_PRIVATE)
#include "mfdt_v1_runtime_owner.h"
#endif

#include <string.h>

#define NINLIL_RT_V1_MARKER_CN 0x434eu

static ninlil_status_t map_storage_mutation_status(
    ninlil_runtime_t *runtime,
    ninlil_storage_status_t status);

#define NINLIL_RT_V1_SERVICE_MAGIC_0 0x4eu
#define NINLIL_RT_V1_SERVICE_MAGIC_1 0x53u
#define NINLIL_RT_V1_SERVICE_MAGIC_2 0x4cu
#define NINLIL_RT_V1_SERVICE_MAGIC_3 0x31u
#define NINLIL_RT_V1_SERVICE_SCHEMA_MAJOR ((uint16_t)1u)
#define NINLIL_RT_V1_SERVICE_SCHEMA_MINOR ((uint16_t)0u)
#define NINLIL_RT_V1_SERVICE_HEADER_BYTES ((uint32_t)16u)
#define NINLIL_RT_V1_SERVICE_TRAILER_BYTES ((uint32_t)4u)

static void set_header(uint16_t *abi_version, uint16_t *struct_size, size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void saturating_increment_u64(uint64_t *value)
{
    if (*value != UINT64_MAX) {
        *value += 1u;
    }
}

#if defined(NINLIL_MFDT_V1_PRIVATE)
static int runtime_mfdt_enabled(
    const ninlil_runtime_t *runtime,
    uint32_t logical_payload_length,
    uint32_t target_count)
{
    return target_count >= 1u
        && target_count <= NINLIL_MFDT_V1_HOST_SLOT_COUNT
        && ninlil_rt_mfdt_v1_runtime_should_use(
            runtime, logical_payload_length);
}

static int mfdt_roster_has_duplicate_runtime(
    const ninlil_concrete_target_t *targets,
    uint32_t target_count)
{
    uint32_t left;
    uint32_t right;

    if (targets == NULL || target_count == 0u ||
        target_count > NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return 0;
    }
    for (left = 0u; left < target_count; ++left) {
        for (right = left + 1u; right < target_count; ++right) {
            if (memcmp(
                    targets[left].target_runtime_id.bytes,
                    targets[right].target_runtime_id.bytes,
                    16u) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static ninlil_status_t map_mfdt_sender_open_status(
    ninlil_runtime_t *runtime,
    int status)
{
    switch (status) {
    case NINLIL_MFDT_V1_OK:
        return NINLIL_OK;
    case NINLIL_MFDT_V1_ERR_CAPACITY:
        return NINLIL_E_CAPACITY_EXHAUSTED;
    case NINLIL_MFDT_V1_ERR_BUSY:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_MFDT_V1_ERR_STORAGE:
        return NINLIL_E_STORAGE;
    case NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN:
    case NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED:
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_MFDT_V1_ERR_CORRUPT:
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_CORRUPT;
    case NINLIL_MFDT_V1_ERR_POLICY_OFF:
    case NINLIL_MFDT_V1_ERR_VERSION:
    case NINLIL_MFDT_V1_ERR_STATE:
        return NINLIL_E_INVALID_STATE;
    case NINLIL_MFDT_V1_ERR_PARAM:
    case NINLIL_MFDT_V1_ERR_DIGEST:
    case NINLIL_MFDT_V1_ERR_LAYOUT:
    case NINLIL_MFDT_V1_ERR_EXPIRED:
    case NINLIL_MFDT_V1_ERR_ABORT_DENIED:
    default:
        return NINLIL_E_INVALID_ARGUMENT;
    }
}

static void fill_mfdt_application_envelope(
    ninlil_bearer_message_t *application,
    const ninlil_rt_transaction_slot_t *transaction,
    const ninlil_submission_t *submission,
    uint32_t target_ordinal)
{
    (void)memset(application, 0, sizeof(*application));
    set_header(
        &application->abi_version,
        &application->struct_size,
        sizeof(*application));
    application->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    application->transaction_id = transaction->transaction_id;
    application->attempt_id =
        transaction->bound_targets[target_ordinal].active_attempt_id;
    application->event_id = transaction->event_id;
    application->source = transaction->source;
    application->target =
        transaction->bound_targets[target_ordinal].target;
    application->service = transaction->service;
    application->content_digest = transaction->content_digest;
    application->generation = transaction->generation;
    application->deadline_clock_epoch_id =
        transaction->deadline_clock_epoch_id;
    application->absolute_effect_deadline_ms =
        transaction->effect_deadline_ms;
    application->evidence_grace_ms = transaction->evidence_grace_ms;
    application->required_evidence = transaction->required_evidence;
    application->payload = submission->payload;
}
#endif

static ninlil_status_t map_storage_mutation_status(
    ninlil_runtime_t *runtime,
    ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_OK;
    }
    saturating_increment_u64(&runtime->metrics.storage_failures);
    switch (status) {
    case NINLIL_STORAGE_BUSY:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_STORAGE_NO_SPACE:
        return NINLIL_E_CAPACITY_EXHAUSTED;
    case NINLIL_STORAGE_IO_ERROR:
        return NINLIL_E_STORAGE;
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        return NINLIL_E_UNSUPPORTED;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
        return NINLIL_E_STORAGE_CORRUPT;
    default:
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static int id_is_zero(const ninlil_id128_t *id)
{
    uint32_t index;

    for (index = 0u; index < (uint32_t)sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

#if defined(NINLIL_MFDT_V1_PRIVATE)
static int mfdt_attempt_id_is_in_use(
    const ninlil_runtime_t *runtime,
    const ninlil_id128_t *attempt_id)
{
    uint32_t transaction_index;

    for (transaction_index = 0u;
         transaction_index < runtime->transaction_capacity;
         ++transaction_index) {
        const ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[transaction_index];
        uint32_t attempt_index;

        if (transaction->in_use == 0u) {
            continue;
        }
        for (attempt_index = 0u;
             attempt_index < transaction->attempt_count
                && attempt_index < NINLIL_RT_V1_MAX_ATTEMPTS_PER_TXN;
             ++attempt_index) {
            if (memcmp(
                    transaction->attempt_ids[attempt_index].bytes,
                    attempt_id->bytes,
                    sizeof(attempt_id->bytes)) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int mfdt_attempt_matches_prior_candidate(
    const ninlil_rt_transaction_slot_t *transaction,
    uint32_t target_index,
    const ninlil_id128_t *attempt_id)
{
    uint32_t prior;

    for (prior = 0u; prior < target_index; ++prior) {
        if (transaction->bound_targets[prior].attempt_prepared != 0u &&
            memcmp(
                transaction->bound_targets[prior].active_attempt_id.bytes,
                attempt_id->bytes,
                sizeof(attempt_id->bytes)) == 0) {
            return 1;
        }
    }
    return 0;
}

static ninlil_status_t prepare_mfdt_admission_target_attempt(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    uint32_t target_index)
{
    ninlil_id128_t attempt_id;
    ninlil_rt_target_slot_t *target;
    uint32_t draw;

    if (transaction->bearer_route
            != (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1
        || target_index >= transaction->bound_target_count
        || target_index >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&attempt_id, 0, sizeof(attempt_id));
    for (draw = 0u; draw < 4u; ++draw) {
        ninlil_port_status_t entropy_status =
            runtime->platform->entropy->fill(
                runtime->platform->entropy->user,
                attempt_id.bytes,
                (uint32_t)sizeof(attempt_id.bytes));

        if (entropy_status == NINLIL_PORT_OK
            && !id_is_zero(&attempt_id)
            && !mfdt_attempt_id_is_in_use(runtime, &attempt_id)
            && !mfdt_attempt_matches_prior_candidate(
                transaction, target_index, &attempt_id)) {
            break;
        }
        (void)memset(&attempt_id, 0, sizeof(attempt_id));
    }
    if (draw == 4u) {
        runtime->health = NINLIL_HEALTH_DEGRADED;
        runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
        return NINLIL_E_ENTROPY;
    }

    target = &transaction->bound_targets[target_index];
    transaction->attempt_ids[target_index] = attempt_id;
    transaction->attempt_target_indices[target_index] =
        (uint8_t)target_index;
    transaction->attempt_count = target_index + 1u;
    transaction->cumulative_attempts = target_index + 1u;
    target->active_attempt_id = attempt_id;
    target->attempt_prepared = 1u;
    target->retry_budget -= 1u;
    target->attempt_in_cycle = 1u;
    target->cumulative_attempts = 1u;
    if (target_index == 0u) {
        transaction->attempt_id = attempt_id;
        transaction->attempt_prepared = 1u;
        transaction->retry_budget = target->retry_budget;
        if (transaction->family == NINLIL_FAMILY_EVENT_FACT) {
            transaction->attempt_in_cycle = 1u;
        }
    }
    return NINLIL_OK;
}
#endif

/* Constant-time byte equality for digest comparisons. */
static int bytes_equal_ct(const uint8_t *left, const uint8_t *right, size_t length)
{
    size_t index;
    uint8_t acc = 0u;

    for (index = 0u; index < length; ++index) {
        acc = (uint8_t)(acc | (left[index] ^ right[index]));
    }
    return acc == 0u;
}

static int digest_equal_ct(
    const ninlil_digest256_t *left,
    const ninlil_digest256_t *right)
{
    if (left == NULL || right == NULL) {
        return 0;
    }
    if (left->algorithm != right->algorithm
        || left->reserved_zero != right->reserved_zero) {
        return 0;
    }
    return bytes_equal_ct(
        left->bytes, right->bytes, sizeof(left->bytes));
}

static int text_id_equals_view(
    const ninlil_text_id_t *text,
    const ninlil_bytes_view_t *view)
{
    if (text == NULL || view == NULL
        || (uint32_t)text->length != view->length) {
        return 0;
    }
    if (view->length == 0u) {
        return 1;
    }
    return memcmp(text->bytes, view->data, view->length) == 0;
}

static int origin_matches_service_scope(
    const ninlil_rt_service_slot_t *slot,
    const ninlil_rt_transaction_slot_t *transaction)
{
    if (slot == NULL || transaction == NULL
        || transaction->in_use == 0u
        || transaction->origin_admission == 0u) {
        return 0;
    }
    return memcmp(
               slot->descriptor.local_application_instance_id.bytes,
               transaction->service_app_id.bytes,
               sizeof(transaction->service_app_id.bytes))
            == 0
        && text_id_equals_view(
            &transaction->service.namespace_id,
            &slot->descriptor.namespace_id)
        && text_id_equals_view(
            &transaction->service.service_id,
            &slot->descriptor.service_id);
}

static void fill_existing_from_transaction(
    ninlil_model_existing_admission_t *existing,
    const ninlil_rt_transaction_slot_t *transaction)
{
    (void)memset(existing, 0, sizeof(*existing));
    existing->transaction_id = transaction->transaction_id;
    existing->canonical_submission_digest =
        transaction->canonical_submission_digest;
    existing->assurance = transaction->assurance;
}

static void fill_existing_from_ids(
    ninlil_model_existing_admission_t *existing,
    const uint8_t transaction_id[16],
    const uint8_t canonical_digest[32],
    const ninlil_rt_transaction_slot_t *optional_txn)
{
    (void)memset(existing, 0, sizeof(*existing));
    (void)memcpy(existing->transaction_id.bytes, transaction_id, 16u);
    existing->canonical_submission_digest.algorithm = NINLIL_DIGEST_SHA256;
    existing->canonical_submission_digest.reserved_zero = 0u;
    (void)memcpy(
        existing->canonical_submission_digest.bytes, canonical_digest, 32u);
    if (optional_txn != NULL) {
        existing->assurance = optional_txn->assurance;
    }
}

static int build_idempotency_scope_raw(
    const ninlil_rt_service_slot_t *slot,
    uint8_t *out_scope,
    uint16_t *out_len)
{
    uint32_t o = 0u;
    uint8_t ns_len;
    uint8_t svc_len;

    if (slot == NULL || out_scope == NULL || out_len == NULL) {
        return 0;
    }
    ns_len = (uint8_t)slot->descriptor.namespace_id.length;
    svc_len = (uint8_t)slot->descriptor.service_id.length;
    if (ns_len < 1u || svc_len < 1u
        || 16u + 1u + (uint32_t)ns_len + 1u + (uint32_t)svc_len > 255u) {
        return 0;
    }
    (void)memcpy(
        out_scope,
        slot->descriptor.local_application_instance_id.bytes,
        16u);
    o = 16u;
    out_scope[o++] = ns_len;
    (void)memcpy(
        &out_scope[o], slot->descriptor.namespace_id.data, ns_len);
    o += ns_len;
    out_scope[o++] = svc_len;
    (void)memcpy(
        &out_scope[o], slot->descriptor.service_id.data, svc_len);
    o += svc_len;
    *out_len = (uint16_t)o;
    return 1;
}

static void fire_admission_hook(ninlil_runtime_t *runtime, const char *name)
{
    if (runtime != NULL && runtime->private_transition_hook != NULL
        && name != NULL) {
        runtime->private_transition_hook(
            runtime->private_transition_hook_user, name);
    }
}

#if defined(NINLIL_MFDT_V1_PRIVATE)
static ninlil_status_t finish_mfdt_prearmed_failure(
    ninlil_runtime_t *runtime,
    const ninlil_rt_transaction_slot_t *transaction,
    const uint8_t prearmed_slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT],
    uint8_t prearmed_count,
    ninlil_status_t original_status,
    ninlil_submission_result_t *out_result)
{
    if (original_status == NINLIL_E_STORAGE_COMMIT_UNKNOWN ||
        runtime->commit_unknown_fence != 0u) {
        runtime->commit_unknown_fence = 1u;
        out_result->kind = NINLIL_SUBMISSION_INVALID;
        out_result->reason = NINLIL_REASON_STORAGE_COMMIT_UNKNOWN;
        out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (prearmed_count == 0u) {
        return original_status;
    }
    while (prearmed_count != 0u) {
        uint8_t target_index = (uint8_t)(prearmed_count - 1u);
        int cleanup_rc;
        ninlil_status_t cleanup_status;

        fire_admission_hook(
            runtime, "admission.before_mfdt_sender_disarm");
        cleanup_rc = ninlil_rt_mfdt_v1_runtime_sender_disarm(
            runtime,
            prearmed_slots[target_index],
            transaction->bound_targets[target_index].mfdt_transfer_id);
        fire_admission_hook(
            runtime, "admission.after_mfdt_sender_disarm");
        if (cleanup_rc != NINLIL_MFDT_V1_OK) {
            runtime->commit_unknown_fence = 1u;
            cleanup_status = map_mfdt_sender_open_status(runtime, cleanup_rc);
            if (cleanup_status == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
                out_result->kind = NINLIL_SUBMISSION_INVALID;
                out_result->reason = NINLIL_REASON_STORAGE_COMMIT_UNKNOWN;
                out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
            }
            return cleanup_status;
        }
        prearmed_count = target_index;
    }
    return original_status;
}
#endif

/*
 * Encode docs/17 IDEMPOTENCY_MAP / EVENT_ID_MAP as a full domain envelope.
 * head_witness_digest must be the real WITNESS_HEADER composite identity
 * (witness_digest) of the admission witness group that CREATE-members this
 * map row — never a synthetic tag preimage.
 */
static ninlil_status_t encode_idempotency_map_record(
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_id128_t *transaction_id,
    const ninlil_digest256_t *canonical_digest,
    const uint8_t anchor_value_digest[32],
    const uint8_t head_witness_digest[32],
    uint8_t *out_key,
    uint8_t *out_key_len,
    uint8_t *out_value,
    uint32_t value_capacity,
    uint32_t *out_value_len)
{
    uint8_t scope[255];
    uint16_t scope_len = 0u;
    uint8_t body[NINLIL_MODEL_DOMAIN_BODY_IDEMPOTENCY_MAP_MAX];
    uint32_t body_len = 0u;
    ninlil_model_domain_body_idempotency_map_t map_body;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t body_view;
    ninlil_status_t status;

    if (head_witness_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    {
        uint32_t zi;
        int nonzero = 0;
        for (zi = 0u; zi < 32u; ++zi) {
            if (head_witness_digest[zi] != 0u) {
                nonzero = 1;
                break;
            }
        }
        if (nonzero == 0) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    if (!build_idempotency_scope_raw(slot, scope, &scope_len)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
        scope,
        scope_len,
        submission->idempotency_key.data,
        (uint16_t)submission->idempotency_key.length,
        out_key,
        out_key_len);
    if (status != NINLIL_OK) {
        return status;
    }

    (void)memset(&map_body, 0, sizeof(map_body));
    map_body.scope_raw_length = scope_len;
    map_body.scope_raw = scope;
    map_body.idempotency_key_length =
        (uint16_t)submission->idempotency_key.length;
    map_body.idempotency_key = submission->idempotency_key.data;
    (void)memcpy(map_body.transaction_id, transaction_id->bytes, 16u);
    (void)memcpy(
        map_body.canonical_submission_digest, canonical_digest->bytes, 32u);
    (void)memcpy(map_body.anchor_value_digest, anchor_value_digest, 32u);
    status = ninlil_model_domain_encode_body_idempotency_map(
        &map_body, body, sizeof(body), &body_len);
    if (status != NINLIL_OK) {
        return status;
    }

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP;
    hdr.flags = 0u;
    hdr.record_revision = 1u;
    hdr.body_length = body_len;
    (void)memcpy(hdr.primary_id, transaction_id->bytes, 16u);
    (void)memcpy(hdr.primary_value_digest, anchor_value_digest, 32u);
    (void)memcpy(hdr.head_witness_digest, head_witness_digest, 32u);

    body_view.data = body;
    body_view.length = body_len;
    return ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
        &hdr,
        body_view,
        out_value,
        value_capacity,
        out_value_len);
}

static ninlil_status_t encode_event_id_map_record(
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_id128_t *transaction_id,
    const ninlil_digest256_t *canonical_digest,
    const uint8_t anchor_value_digest[32],
    const uint8_t head_witness_digest[32],
    uint8_t *out_key,
    uint8_t *out_key_len,
    uint8_t *out_value,
    uint32_t value_capacity,
    uint32_t *out_value_len)
{
    uint8_t scope[255];
    uint16_t scope_len = 0u;
    uint8_t body[NINLIL_MODEL_DOMAIN_BODY_EVENT_ID_MAP_MAX];
    uint32_t body_len = 0u;
    ninlil_model_domain_body_event_id_map_t map_body;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t body_view;
    ninlil_status_t status;

    if (head_witness_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    {
        uint32_t zi;
        int nonzero = 0;
        for (zi = 0u; zi < 32u; ++zi) {
            if (head_witness_digest[zi] != 0u) {
                nonzero = 1;
                break;
            }
        }
        if (nonzero == 0) {
            return NINLIL_E_INVALID_ARGUMENT;
        }
    }
    if (!build_idempotency_scope_raw(slot, scope, &scope_len)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_domain_scan_d3s1_rebuild_tx_event_id_map_key(
        scope,
        scope_len,
        submission->event_id.bytes,
        out_key,
        out_key_len);
    if (status != NINLIL_OK) {
        return status;
    }

    (void)memset(&map_body, 0, sizeof(map_body));
    map_body.scope_raw_length = scope_len;
    map_body.scope_raw = scope;
    (void)memcpy(map_body.event_id, submission->event_id.bytes, 16u);
    (void)memcpy(map_body.transaction_id, transaction_id->bytes, 16u);
    (void)memcpy(
        map_body.canonical_submission_digest, canonical_digest->bytes, 32u);
    map_body.idempotency_key_length =
        (uint16_t)submission->idempotency_key.length;
    map_body.idempotency_key = submission->idempotency_key.data;
    (void)memcpy(map_body.anchor_value_digest, anchor_value_digest, 32u);
    status = ninlil_model_domain_encode_body_event_id_map(
        &map_body, body, sizeof(body), &body_len);
    if (status != NINLIL_OK) {
        return status;
    }

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP;
    hdr.flags = 0u;
    hdr.record_revision = 1u;
    hdr.body_length = body_len;
    (void)memcpy(hdr.primary_id, transaction_id->bytes, 16u);
    (void)memcpy(hdr.primary_value_digest, anchor_value_digest, 32u);
    (void)memcpy(hdr.head_witness_digest, head_witness_digest, 32u);

    body_view.data = body;
    body_view.length = body_len;
    return ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
        &hdr,
        body_view,
        out_value,
        value_capacity,
        out_value_len);
}

static ninlil_status_t encode_domain_metadata_envelope(
    uint8_t subtype,
    const uint8_t identity[32],
    ninlil_bytes_view_t body,
    uint8_t *out_key,
    uint8_t *out_key_len,
    uint8_t *out_value,
    uint32_t value_capacity,
    uint32_t *out_value_len)
{
    ninlil_model_domain_key_t domain_key;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t identity_view;
    ninlil_status_t status;

    identity_view.data = identity;
    identity_view.length = 32u;
    status = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        subtype,
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity_view,
        &domain_key);
    if (status != NINLIL_OK) {
        return status;
    }
    if (domain_key.length > 64u || out_key == NULL || out_key_len == NULL) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    (void)memcpy(out_key, domain_key.bytes, domain_key.length);
    *out_key_len = (uint8_t)domain_key.length;

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = subtype;
    hdr.flags = 0u;
    hdr.record_revision = 1u;
    hdr.body_length = body.length;
    status = ninlil_model_domain_primary_id_from_identity(
        NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE,
        identity_view,
        hdr.primary_id);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memset(hdr.head_witness_digest, 0, 32u);
    (void)memset(hdr.primary_value_digest, 0, 32u);
    return ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN,
        &hdr,
        body,
        out_value,
        value_capacity,
        out_value_len);
}

static ninlil_status_t retention_subject_key_digest_for_txn(
    const ninlil_id128_t *transaction_id,
    uint8_t out_digest[32])
{
    ninlil_model_domain_key_t anchor_key;
    ninlil_bytes_view_t identity;
    ninlil_model_domain_digest_t dig;
    ninlil_status_t status;

    identity.data = transaction_id->bytes;
    identity.length = 16u;
    status = ninlil_model_domain_build_key(
        NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
        NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
        NINLIL_MODEL_DOMAIN_ID_KIND_ID128,
        identity,
        &anchor_key);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_key_digest(
        (ninlil_bytes_view_t){anchor_key.bytes, anchor_key.length}, &dig);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memcpy(out_digest, dig.bytes, 32u);
    return NINLIL_OK;
}

static ninlil_status_t storage_get_bytes(
    ninlil_runtime_t *runtime,
    ninlil_bytes_view_t key,
    uint8_t *out_value,
    uint32_t capacity,
    uint32_t *out_len,
    int *out_present)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t st;

    *out_present = 0;
    *out_len = 0u;
    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->storage == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;
    st = storage->begin(
        storage->user, runtime->storage, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_mutation_status(runtime, st);
    }
    value.data = out_value;
    value.capacity = capacity;
    value.length = 0u;
    st = storage->get(storage->user, txn, key, &value);
    (void)storage->rollback(storage->user, txn);
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_OK;
    }
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_mutation_status(runtime, st);
    }
    *out_present = 1;
    *out_len = value.length;
    return NINLIL_OK;
}

static void lookup_caller_key_mapping(
    ninlil_runtime_t *runtime,
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_digest256_t *canonical_digest,
    ninlil_model_mapping_fact_t *out_mapping)
{
    uint32_t index;
    uint8_t scope[255];
    uint16_t scope_len = 0u;
    uint8_t key[64];
    uint8_t key_len = 0u;
    uint8_t value[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    uint32_t value_len = 0u;
    int present = 0;
    ninlil_status_t status;
    ninlil_model_domain_typed_record_t typed;

    (void)memset(out_mapping, 0, sizeof(*out_mapping));
    out_mapping->state = NINLIL_MODEL_MAPPING_ABSENT;
    if (runtime == NULL || slot == NULL || submission == NULL
        || canonical_digest == NULL
        || submission->idempotency_key.length < 1u
        || submission->idempotency_key.length > NINLIL_MAX_IDEMPOTENCY_BYTES
        || submission->idempotency_key.data == NULL) {
        return;
    }

    /* Primary: independent durable IDEMPOTENCY_MAP row. */
    if (build_idempotency_scope_raw(slot, scope, &scope_len)
        && ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
               scope,
               scope_len,
               submission->idempotency_key.data,
               (uint16_t)submission->idempotency_key.length,
               key,
               &key_len)
            == NINLIL_OK) {
        status = storage_get_bytes(
            runtime,
            (ninlil_bytes_view_t){key, key_len},
            value,
            sizeof(value),
            &value_len,
            &present);
        if (status != NINLIL_OK) {
            out_mapping->state = NINLIL_MODEL_MAPPING_STORAGE_FAILURE;
            out_mapping->failure_status = status;
            return;
        }
        if (present != 0) {
            status = ninlil_model_domain_validate_typed_record(
                (ninlil_bytes_view_t){key, key_len},
                (ninlil_bytes_view_t){value, value_len},
                &typed);
            if (status != NINLIL_OK
                || typed.subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP) {
                out_mapping->state = NINLIL_MODEL_MAPPING_STORAGE_FAILURE;
                out_mapping->failure_status = NINLIL_E_STORAGE_CORRUPT;
                return;
            }
            {
                const ninlil_rt_transaction_slot_t *txn =
                    ninlil_rt_find_transaction(
                        runtime,
                        (const ninlil_id128_t *)
                            typed.idempotency_map.transaction_id);
                fill_existing_from_ids(
                    &out_mapping->existing,
                    typed.idempotency_map.transaction_id,
                    typed.idempotency_map.canonical_submission_digest,
                    txn);
            }
            out_mapping->record_verified = 1u;
            if (digest_equal_ct(
                    &out_mapping->existing.canonical_submission_digest,
                    canonical_digest)) {
                out_mapping->state = NINLIL_MODEL_MAPPING_MATCH;
            } else {
                out_mapping->state = NINLIL_MODEL_MAPPING_MISMATCH;
            }
            return;
        }
    }

    /* Fallback: restored origin TX rows (pre-map-cutover / in-memory). */
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        const ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[index];

        if (!origin_matches_service_scope(slot, transaction)
            || transaction->idempotency_key_length
                != submission->idempotency_key.length
            || memcmp(
                transaction->idempotency_key,
                submission->idempotency_key.data,
                submission->idempotency_key.length)
                != 0) {
            continue;
        }
        fill_existing_from_transaction(&out_mapping->existing, transaction);
        out_mapping->record_verified = 1u;
        if (digest_equal_ct(
                &transaction->canonical_submission_digest,
                canonical_digest)) {
            out_mapping->state = NINLIL_MODEL_MAPPING_MATCH;
        } else {
            out_mapping->state = NINLIL_MODEL_MAPPING_MISMATCH;
        }
        return;
    }
}

static void lookup_event_id_mapping(
    ninlil_runtime_t *runtime,
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_digest256_t *canonical_digest,
    ninlil_model_mapping_fact_t *out_mapping)
{
    uint32_t index;
    uint8_t scope[255];
    uint16_t scope_len = 0u;
    uint8_t key[64];
    uint8_t key_len = 0u;
    uint8_t value[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    uint32_t value_len = 0u;
    int present = 0;
    ninlil_status_t status;
    ninlil_model_domain_typed_record_t typed;

    (void)memset(out_mapping, 0, sizeof(*out_mapping));
    out_mapping->state = NINLIL_MODEL_MAPPING_ABSENT;
    if (runtime == NULL || slot == NULL || submission == NULL
        || canonical_digest == NULL
        || id_is_zero(&submission->event_id)) {
        return;
    }

    if (build_idempotency_scope_raw(slot, scope, &scope_len)
        && ninlil_domain_scan_d3s1_rebuild_tx_event_id_map_key(
               scope, scope_len, submission->event_id.bytes, key, &key_len)
            == NINLIL_OK) {
        status = storage_get_bytes(
            runtime,
            (ninlil_bytes_view_t){key, key_len},
            value,
            sizeof(value),
            &value_len,
            &present);
        if (status != NINLIL_OK) {
            out_mapping->state = NINLIL_MODEL_MAPPING_STORAGE_FAILURE;
            out_mapping->failure_status = status;
            return;
        }
        if (present != 0) {
            status = ninlil_model_domain_validate_typed_record(
                (ninlil_bytes_view_t){key, key_len},
                (ninlil_bytes_view_t){value, value_len},
                &typed);
            if (status != NINLIL_OK
                || typed.subtype != NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP) {
                out_mapping->state = NINLIL_MODEL_MAPPING_STORAGE_FAILURE;
                out_mapping->failure_status = NINLIL_E_STORAGE_CORRUPT;
                return;
            }
            {
                const ninlil_rt_transaction_slot_t *txn =
                    ninlil_rt_find_transaction(
                        runtime,
                        (const ninlil_id128_t *)
                            typed.event_id_map.transaction_id);
                fill_existing_from_ids(
                    &out_mapping->existing,
                    typed.event_id_map.transaction_id,
                    typed.event_id_map.canonical_submission_digest,
                    txn);
            }
            out_mapping->record_verified = 1u;
            if (digest_equal_ct(
                    &out_mapping->existing.canonical_submission_digest,
                    canonical_digest)
                && typed.event_id_map.idempotency_key_length
                    == submission->idempotency_key.length
                && submission->idempotency_key.data != NULL
                && memcmp(
                    typed.event_id_map.idempotency_key,
                    submission->idempotency_key.data,
                    submission->idempotency_key.length)
                    == 0) {
                out_mapping->state = NINLIL_MODEL_MAPPING_MATCH;
            } else {
                out_mapping->state = NINLIL_MODEL_MAPPING_MISMATCH;
            }
            return;
        }
    }

    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        const ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[index];

        if (!origin_matches_service_scope(slot, transaction)
            || transaction->family != NINLIL_FAMILY_EVENT_FACT
            || memcmp(
                transaction->event_id.bytes,
                submission->event_id.bytes,
                sizeof(submission->event_id.bytes))
                != 0) {
            continue;
        }
        fill_existing_from_transaction(&out_mapping->existing, transaction);
        out_mapping->record_verified = 1u;
        if (digest_equal_ct(
                &transaction->canonical_submission_digest,
                canonical_digest)
            && transaction->idempotency_key_length
                == submission->idempotency_key.length
            && submission->idempotency_key.data != NULL
            && memcmp(
                transaction->idempotency_key,
                submission->idempotency_key.data,
                submission->idempotency_key.length)
                == 0) {
            out_mapping->state = NINLIL_MODEL_MAPPING_MATCH;
        } else {
            out_mapping->state = NINLIL_MODEL_MAPPING_MISMATCH;
        }
        return;
    }
}

static ninlil_status_t stage_admission_map_rows(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t txn,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_rt_transaction_slot_t *admitted,
    const uint8_t *txn_record,
    uint32_t txn_record_len)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;
    uint8_t im_key[64];
    uint8_t em_key[64];
    uint8_t im_key_len = 0u;
    uint8_t em_key_len = 0u;
    uint8_t map_value[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    uint32_t map_value_len = 0u;
    uint8_t im_value_digest[32];
    uint8_t em_value_digest[32];
    ninlil_model_domain_digest_t anchor;
    ninlil_model_domain_digest_t witness_digest;
    ninlil_model_domain_digest_t value_dig;
    ninlil_model_domain_digest_t manifest_dig;
    ninlil_model_domain_digest_t canon_dig;
    ninlil_model_domain_manifest_digest_ctx_t manifest_ctx;
    ninlil_model_domain_witness_header_t wh;
    ninlil_model_domain_witness_chunk_t chunk;
    ninlil_bytes_view_t op_identity;
    ninlil_bytes_view_t body_view;
    uint8_t retention_subject[32];
    uint8_t header_body[NINLIL_MODEL_DOMAIN_WITNESS_HEADER_BODY_MAX];
    uint8_t chunk_body[NINLIL_MODEL_DOMAIN_MANIFEST_CHUNK_BODY_MAX];
    uint8_t meta_key[64];
    uint8_t meta_key_len = 0u;
    uint8_t meta_value[NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES];
    uint32_t header_body_len = 0u;
    uint32_t chunk_body_len = 0u;
    uint32_t meta_value_len = 0u;
    uint16_t op_kind;
    uint16_t member_count;
    int include_event;
    ninlil_status_t status;

    status = ninlil_model_domain_sha256(txn_record, txn_record_len, &anchor);
    if (status != NINLIL_OK) {
        return status;
    }

    include_event =
        (slot->model_service.family == NINLIL_FAMILY_EVENT_FACT) ? 1 : 0;
    op_kind = include_event != 0 ? 3u : 2u;
    op_identity.data = admitted->transaction_id.bytes;
    op_identity.length = 16u;
    status = ninlil_model_domain_witness_identity_digest(
        op_kind, op_identity, &witness_digest);
    if (status != NINLIL_OK) {
        return status;
    }
    status = retention_subject_key_digest_for_txn(
        &admitted->transaction_id, retention_subject);
    if (status != NINLIL_OK) {
        return status;
    }

    fire_admission_hook(runtime, "admission.before_idempotency_map_put");
    status = encode_idempotency_map_record(
        slot,
        submission,
        &admitted->transaction_id,
        &admitted->canonical_submission_digest,
        anchor.bytes,
        witness_digest.bytes,
        im_key,
        &im_key_len,
        map_value,
        sizeof(map_value),
        &map_value_len);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_value_digest(
        (ninlil_bytes_view_t){map_value, map_value_len}, &value_dig);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memcpy(im_value_digest, value_dig.bytes, 32u);
    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        storage,
        txn,
        (ninlil_bytes_view_t){im_key, im_key_len},
        (ninlil_bytes_view_t){map_value, map_value_len},
        &runtime->commit_unknown_fence);
    fire_admission_hook(runtime, "admission.after_idempotency_map_put");
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        return status;
    }

    (void)memset(em_value_digest, 0, sizeof(em_value_digest));
    if (include_event != 0) {
        fire_admission_hook(runtime, "admission.before_event_id_map_put");
        map_value_len = 0u;
        status = encode_event_id_map_record(
            slot,
            submission,
            &admitted->transaction_id,
            &admitted->canonical_submission_digest,
            anchor.bytes,
            witness_digest.bytes,
            em_key,
            &em_key_len,
            map_value,
            sizeof(map_value),
            &map_value_len);
        if (status != NINLIL_OK) {
            return status;
        }
        status = ninlil_model_domain_value_digest(
            (ninlil_bytes_view_t){map_value, map_value_len}, &value_dig);
        if (status != NINLIL_OK) {
            return status;
        }
        (void)memcpy(em_value_digest, value_dig.bytes, 32u);
        status = ninlil_v1_durable_storage_put(
            NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
            storage,
            txn,
            (ninlil_bytes_view_t){em_key, em_key_len},
            (ninlil_bytes_view_t){map_value, map_value_len},
            &runtime->commit_unknown_fence);
        fire_admission_hook(runtime, "admission.after_event_id_map_put");
        if (status != NINLIL_OK) {
            saturating_increment_u64(&runtime->metrics.storage_failures);
            return status;
        }
    }

    member_count = include_event != 0 ? 2u : 1u;
    (void)memset(&chunk, 0, sizeof(chunk));
    (void)memcpy(chunk.witness_digest, witness_digest.bytes, 32u);
    chunk.chunk_index = 0u;
    chunk.chunk_count = 1u;
    chunk.entry_count = member_count;

    /*
     * Manifest entries must be key lexicographic. Rebuild keys already
     * ordered by encoding both maps first; sort the 1–2 entries here.
     */
    {
        const uint8_t *k0 = im_key;
        uint8_t k0_len = im_key_len;
        const uint8_t *d0 = im_value_digest;
        uint16_t role0 =
            (uint16_t)((NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN << 8)
                | NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP);
        const uint8_t *k1 = NULL;
        uint8_t k1_len = 0u;
        const uint8_t *d1 = NULL;
        uint16_t role1 = 0u;
        int swap = 0;

        if (include_event != 0) {
            k1 = em_key;
            k1_len = em_key_len;
            d1 = em_value_digest;
            role1 =
                (uint16_t)((NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN << 8)
                    | NINLIL_MODEL_DOMAIN_SUBTYPE_EVENT_ID_MAP);
            {
                uint8_t min_len = k0_len < k1_len ? k0_len : k1_len;
                int cmp = memcmp(k0, k1, min_len);
                if (cmp > 0 || (cmp == 0 && k0_len > k1_len)) {
                    swap = 1;
                }
            }
            if (swap != 0) {
                const uint8_t *tmpk = k0;
                uint8_t tmpl = k0_len;
                const uint8_t *tmpd = d0;
                uint16_t tmpr = role0;
                k0 = k1;
                k0_len = k1_len;
                d0 = d1;
                role0 = role1;
                k1 = tmpk;
                k1_len = tmpl;
                d1 = tmpd;
                role1 = tmpr;
            }
        }

        chunk.entries[0].record_role = role0;
        chunk.entries[0].action = NINLIL_MODEL_DOMAIN_WITNESS_ACTION_CREATE;
        chunk.entries[0].key_length = k0_len;
        chunk.entries[0].key_bytes = k0;
        chunk.entries[0].old_present = 0u;
        chunk.entries[0].new_present = 1u;
        (void)memcpy(chunk.entries[0].new_value_digest, d0, 32u);
        if (include_event != 0) {
            chunk.entries[1].record_role = role1;
            chunk.entries[1].action =
                NINLIL_MODEL_DOMAIN_WITNESS_ACTION_CREATE;
            chunk.entries[1].key_length = k1_len;
            chunk.entries[1].key_bytes = k1;
            chunk.entries[1].old_present = 0u;
            chunk.entries[1].new_present = 1u;
            (void)memcpy(chunk.entries[1].new_value_digest, d1, 32u);
        }
    }

    fire_admission_hook(runtime, "admission.before_witness_chunk_put");
    status = ninlil_model_domain_encode_witness_chunk(
        &chunk, chunk_body, sizeof(chunk_body), &chunk_body_len);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_manifest_digest_init(&manifest_ctx);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_manifest_digest_update(
        &manifest_ctx,
        (ninlil_bytes_view_t){chunk_body, chunk_body_len});
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_domain_manifest_digest_final(
        &manifest_ctx, &manifest_dig);
    if (status != NINLIL_OK) {
        return status;
    }

    {
        uint8_t chunk_components[34];
        ninlil_model_domain_digest_t chunk_identity;

        (void)memcpy(chunk_components, witness_digest.bytes, 32u);
        chunk_components[32] = 0u;
        chunk_components[33] = 0u;
        status = ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            (ninlil_bytes_view_t){chunk_components, 34u},
            &chunk_identity);
        if (status != NINLIL_OK) {
            return status;
        }
        body_view.data = chunk_body;
        body_view.length = chunk_body_len;
        meta_key_len = 0u;
        meta_value_len = 0u;
        status = encode_domain_metadata_envelope(
            NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_MANIFEST_CHUNK,
            chunk_identity.bytes,
            body_view,
            meta_key,
            &meta_key_len,
            meta_value,
            sizeof(meta_value),
            &meta_value_len);
        if (status != NINLIL_OK) {
            return status;
        }
        status = ninlil_v1_durable_storage_put(
            NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
            storage,
            txn,
            (ninlil_bytes_view_t){meta_key, meta_key_len},
            (ninlil_bytes_view_t){meta_value, meta_value_len},
            &runtime->commit_unknown_fence);
        fire_admission_hook(runtime, "admission.after_witness_chunk_put");
        if (status != NINLIL_OK) {
            saturating_increment_u64(&runtime->metrics.storage_failures);
            return status;
        }
    }

    (void)memset(&wh, 0, sizeof(wh));
    wh.operation_kind = op_kind;
    wh.witness_state = NINLIL_MODEL_DOMAIN_WITNESS_STATE_ACTIVE;
    wh.operation_identity_length = 16u;
    (void)memcpy(
        wh.operation_identity, admitted->transaction_id.bytes, 16u);
    (void)memcpy(wh.subject_id, admitted->transaction_id.bytes, 16u);
    wh.member_count = member_count;
    wh.chunk_count = 1u;
    (void)memcpy(wh.manifest_digest, manifest_dig.bytes, 32u);
    wh.retention_kind = 2u;
    (void)memcpy(wh.retention_subject_key_digest, retention_subject, 32u);
    status = ninlil_model_domain_canonical_operation_digest(
        op_kind,
        op_identity,
        wh.subject_id,
        wh.manifest_digest,
        wh.retention_kind,
        wh.retention_subject_key_digest,
        &canon_dig);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memcpy(wh.canonical_digest, canon_dig.bytes, 32u);

    fire_admission_hook(runtime, "admission.before_witness_header_put");
    status = ninlil_model_domain_encode_witness_header(
        &wh, header_body, sizeof(header_body), &header_body_len);
    if (status != NINLIL_OK) {
        return status;
    }
    body_view.data = header_body;
    body_view.length = header_body_len;
    meta_key_len = 0u;
    meta_value_len = 0u;
    status = encode_domain_metadata_envelope(
        NINLIL_MODEL_DOMAIN_SUBTYPE_WITNESS_HEADER,
        witness_digest.bytes,
        body_view,
        meta_key,
        &meta_key_len,
        meta_value,
        sizeof(meta_value),
        &meta_value_len);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        storage,
        txn,
        (ninlil_bytes_view_t){meta_key, meta_key_len},
        (ninlil_bytes_view_t){meta_value, meta_value_len},
        &runtime->commit_unknown_fence);
    fire_admission_hook(runtime, "admission.after_witness_header_put");
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        return status;
    }
    return NINLIL_OK;
}

static ninlil_status_t recompute_payload_content_digest_match(
    const ninlil_submission_t *submission,
    uint32_t *out_matches)
{
    ninlil_model_domain_digest_t actual;
    ninlil_status_t status;

    *out_matches = 0u;
    if (submission == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (submission->content_digest.algorithm != NINLIL_DIGEST_SHA256
        || submission->content_digest.reserved_zero != 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if ((submission->payload.length == 0u && submission->payload.data != NULL)
        || (submission->payload.length > 0u
            && submission->payload.data == NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_model_domain_sha256(
        submission->payload.data,
        submission->payload.length,
        &actual);
    if (status != NINLIL_OK) {
        return status;
    }
    *out_matches = bytes_equal_ct(
                       actual.bytes,
                       submission->content_digest.bytes,
                       sizeof(actual.bytes))
        ? 1u
        : 0u;
    return NINLIL_OK;
}

static void encode_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void encode_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void encode_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)(value >> 56);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
}

static uint16_t decode_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t decode_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24)
        | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8)
        | (uint32_t)in[3];
}

static uint64_t decode_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56)
        | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40)
        | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24)
        | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8)
        | (uint64_t)in[7];
}

static ninlil_status_t storage_txn_commit_full(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t txn)
{
    const ninlil_storage_ops_t *storage = runtime->platform->storage;

    return map_storage_mutation_status(
        runtime,
        storage->commit(storage->user, txn, NINLIL_DURABILITY_FULL));
}

static int bytes_view_fits_text(const ninlil_bytes_view_t *view)
{
    return view != NULL
        && view->length >= 1u
        && view->length <= NINLIL_MAX_TEXT_ID_BYTES
        && view->data != NULL;
}

ninlil_status_t ninlil_rt_v1_spine_service_ledger_key(
    const ninlil_service_descriptor_t *descriptor,
    uint8_t *out_key,
    uint32_t out_capacity,
    uint32_t *out_length)
{
    uint32_t need;

    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (descriptor == NULL || out_key == NULL || out_length == NULL
        || !bytes_view_fits_text(&descriptor->namespace_id)
        || !bytes_view_fits_text(&descriptor->service_id)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    need = 3u + 16u + 8u + 1u + descriptor->namespace_id.length + 1u
        + descriptor->service_id.length;
    if (need > NINLIL_RT_V1_SERVICE_LEDGER_KEY_MAX_BYTES
        || need > out_capacity) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    out_key[0] = 0x4eu;
    out_key[1] = 0x52u;
    out_key[2] = 0x53u;
    (void)memcpy(&out_key[3], descriptor->local_application_instance_id.bytes, 16u);
    encode_u64_be(&out_key[19], descriptor->descriptor_revision);
    out_key[27] = (uint8_t)descriptor->namespace_id.length;
    (void)memcpy(
        &out_key[28],
        descriptor->namespace_id.data,
        descriptor->namespace_id.length);
    out_key[28u + descriptor->namespace_id.length] =
        (uint8_t)descriptor->service_id.length;
    (void)memcpy(
        &out_key[29u + descriptor->namespace_id.length],
        descriptor->service_id.data,
        descriptor->service_id.length);
    *out_length = need;
    return NINLIL_OK;
}

static ninlil_status_t service_ledger_append(
    uint8_t *out,
    uint32_t capacity,
    uint32_t *pos,
    const uint8_t *bytes,
    uint32_t length)
{
    if (*pos > capacity || length > capacity - *pos
        || (length != 0u && bytes == NULL)) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    if (length != 0u) {
        (void)memcpy(&out[*pos], bytes, length);
    }
    *pos += length;
    return NINLIL_OK;
}

static ninlil_status_t service_ledger_append_u8(
    uint8_t *out, uint32_t capacity, uint32_t *pos, uint8_t value)
{
    return service_ledger_append(out, capacity, pos, &value, 1u);
}

static ninlil_status_t service_ledger_append_u16(
    uint8_t *out, uint32_t capacity, uint32_t *pos, uint16_t value)
{
    uint8_t bytes[2];

    encode_u16_be(bytes, value);
    return service_ledger_append(out, capacity, pos, bytes, 2u);
}

static ninlil_status_t service_ledger_append_u32(
    uint8_t *out, uint32_t capacity, uint32_t *pos, uint32_t value)
{
    uint8_t bytes[4];

    encode_u32_be(bytes, value);
    return service_ledger_append(out, capacity, pos, bytes, 4u);
}

static ninlil_status_t service_ledger_append_u64(
    uint8_t *out, uint32_t capacity, uint32_t *pos, uint64_t value)
{
    uint8_t bytes[8];

    encode_u64_be(bytes, value);
    return service_ledger_append(out, capacity, pos, bytes, 8u);
}

static ninlil_status_t service_ledger_append_view(
    uint8_t *out,
    uint32_t capacity,
    uint32_t *pos,
    const ninlil_bytes_view_t *view)
{
    ninlil_status_t status;

    if (!bytes_view_fits_text(view)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = service_ledger_append_u8(out, capacity, pos, (uint8_t)view->length);
    if (status != NINLIL_OK) {
        return status;
    }
    return service_ledger_append(out, capacity, pos, view->data, view->length);
}

ninlil_status_t ninlil_rt_v1_spine_service_ledger_encode(
    const ninlil_rt_service_slot_t *slot,
    uint8_t *out_bytes,
    uint32_t out_capacity,
    uint32_t *out_length)
{
    const ninlil_service_descriptor_t *d;
    uint32_t pos;
    uint32_t body_length;
    uint32_t crc;
    ninlil_status_t status;

    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (slot == NULL || out_bytes == NULL || out_length == NULL
        || slot->in_use == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (out_capacity < NINLIL_RT_V1_SERVICE_HEADER_BYTES
            + NINLIL_RT_V1_SERVICE_TRAILER_BYTES
        || out_capacity > NINLIL_RT_V1_SERVICE_LEDGER_VALUE_MAX_BYTES) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }

    d = &slot->descriptor;
    (void)memset(out_bytes, 0, out_capacity);
    out_bytes[0] = NINLIL_RT_V1_SERVICE_MAGIC_0;
    out_bytes[1] = NINLIL_RT_V1_SERVICE_MAGIC_1;
    out_bytes[2] = NINLIL_RT_V1_SERVICE_MAGIC_2;
    out_bytes[3] = NINLIL_RT_V1_SERVICE_MAGIC_3;
    encode_u16_be(&out_bytes[4], NINLIL_RT_V1_SERVICE_SCHEMA_MAJOR);
    encode_u16_be(&out_bytes[6], NINLIL_RT_V1_SERVICE_SCHEMA_MINOR);
    pos = NINLIL_RT_V1_SERVICE_HEADER_BYTES;

    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, (uint32_t)slot->model_service.local_side);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(out_bytes, out_capacity, &pos, d->family);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->direction);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->admission_authority);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->apply_contract);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->custody_policy);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->supported_evidence_mask);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->logical_payload_limit);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->target_limit);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->inflight_limit);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->max_attempts_per_target_per_cycle);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->admission_window_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->max_admissions_per_window);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->max_payload_bytes_per_window);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u16(
        out_bytes, out_capacity, &pos, d->schema_major);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u16(
        out_bytes, out_capacity, &pos, d->schema_minor_min);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u16(
        out_bytes, out_capacity, &pos, d->schema_minor_max);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u16(
        out_bytes, out_capacity, &pos, d->reserved_zero_u16);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u32(
        out_bytes, out_capacity, &pos, d->reserved_zero_u32);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->minimum_deadline_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->maximum_deadline_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->maximum_evidence_grace_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->attempt_receipt_timeout_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->retry_backoff_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->application_completion_timeout_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->required_dedup_window_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, d->descriptor_revision);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u16(
        out_bytes, out_capacity, &pos, d->descriptor_digest.algorithm);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u16(
        out_bytes, out_capacity, &pos, d->descriptor_digest.reserved_zero);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append(
        out_bytes, out_capacity, &pos, d->descriptor_digest.bytes, 32u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append(
        out_bytes,
        out_capacity,
        &pos,
        d->local_application_instance_id.bytes,
        16u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_view(
        out_bytes, out_capacity, &pos, &d->namespace_id);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_view(
        out_bytes, out_capacity, &pos, &d->service_id);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_view(
        out_bytes, out_capacity, &pos, &d->schema_id);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, slot->quota_inflight);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, slot->quota_admissions);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, slot->quota_payload_bytes);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append(
        out_bytes, out_capacity, &pos, slot->quota_window_epoch, 16u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_append_u64(
        out_bytes, out_capacity, &pos, slot->quota_window_start_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    if (pos > out_capacity - NINLIL_RT_V1_SERVICE_TRAILER_BYTES) {
        return NINLIL_E_BUFFER_TOO_SMALL;
    }
    body_length = pos - NINLIL_RT_V1_SERVICE_HEADER_BYTES;
    encode_u32_be(&out_bytes[8], body_length);
    encode_u32_be(&out_bytes[12], 0u);
    crc = ninlil_model_domain_crc32c(out_bytes, pos);
    encode_u32_be(&out_bytes[pos], crc);
    pos += NINLIL_RT_V1_SERVICE_TRAILER_BYTES;
    *out_length = pos;
    return NINLIL_OK;
}

static ninlil_status_t service_ledger_take(
    const uint8_t *data,
    uint32_t limit,
    uint32_t *pos,
    uint8_t *out,
    uint32_t length)
{
    if (*pos > limit || length > limit - *pos) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (length != 0u && out != NULL) {
        (void)memcpy(out, &data[*pos], length);
    }
    *pos += length;
    return NINLIL_OK;
}

static ninlil_status_t service_ledger_take_u8(
    const uint8_t *data, uint32_t limit, uint32_t *pos, uint8_t *out)
{
    return service_ledger_take(data, limit, pos, out, 1u);
}

static ninlil_status_t service_ledger_take_u16(
    const uint8_t *data, uint32_t limit, uint32_t *pos, uint16_t *out)
{
    uint8_t bytes[2];
    ninlil_status_t status = service_ledger_take(data, limit, pos, bytes, 2u);

    if (status != NINLIL_OK) {
        return status;
    }
    *out = decode_u16_be(bytes);
    return NINLIL_OK;
}

static ninlil_status_t service_ledger_take_u32(
    const uint8_t *data, uint32_t limit, uint32_t *pos, uint32_t *out)
{
    uint8_t bytes[4];
    ninlil_status_t status = service_ledger_take(data, limit, pos, bytes, 4u);

    if (status != NINLIL_OK) {
        return status;
    }
    *out = decode_u32_be(bytes);
    return NINLIL_OK;
}

static ninlil_status_t service_ledger_take_u64(
    const uint8_t *data, uint32_t limit, uint32_t *pos, uint64_t *out)
{
    uint8_t bytes[8];
    ninlil_status_t status = service_ledger_take(data, limit, pos, bytes, 8u);

    if (status != NINLIL_OK) {
        return status;
    }
    *out = decode_u64_be(bytes);
    return NINLIL_OK;
}

static ninlil_status_t service_ledger_take_owned_text(
    const uint8_t *data,
    uint32_t limit,
    uint32_t *pos,
    uint8_t *owned,
    ninlil_bytes_view_t *view)
{
    uint8_t length = 0u;
    ninlil_status_t status = service_ledger_take_u8(data, limit, pos, &length);

    if (status != NINLIL_OK) {
        return status;
    }
    if (length < 1u || length > NINLIL_MAX_TEXT_ID_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = service_ledger_take(data, limit, pos, owned, length);
    if (status != NINLIL_OK) {
        return status;
    }
    view->data = owned;
    view->length = length;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_spine_service_ledger_decode(
    ninlil_bytes_view_t record,
    ninlil_rt_service_slot_t *out_slot)
{
    uint32_t body_length;
    uint32_t expected;
    uint32_t crc_wire;
    uint32_t crc_calc;
    uint32_t pos;
    uint32_t local_side = 0u;
    ninlil_service_descriptor_t *d;
    ninlil_status_t status;

    if (out_slot == NULL || record.data == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (record.length
            < NINLIL_RT_V1_SERVICE_HEADER_BYTES
                + NINLIL_RT_V1_SERVICE_TRAILER_BYTES
        || record.length > NINLIL_RT_V1_SERVICE_LEDGER_VALUE_MAX_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (record.data[0] != NINLIL_RT_V1_SERVICE_MAGIC_0
        || record.data[1] != NINLIL_RT_V1_SERVICE_MAGIC_1
        || record.data[2] != NINLIL_RT_V1_SERVICE_MAGIC_2
        || record.data[3] != NINLIL_RT_V1_SERVICE_MAGIC_3
        || decode_u16_be(&record.data[4]) != NINLIL_RT_V1_SERVICE_SCHEMA_MAJOR
        || decode_u16_be(&record.data[6]) != NINLIL_RT_V1_SERVICE_SCHEMA_MINOR
        || decode_u32_be(&record.data[12]) != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    body_length = decode_u32_be(&record.data[8]);
    expected = NINLIL_RT_V1_SERVICE_HEADER_BYTES + body_length
        + NINLIL_RT_V1_SERVICE_TRAILER_BYTES;
    if (expected != record.length) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    crc_wire = decode_u32_be(
        &record.data[record.length - NINLIL_RT_V1_SERVICE_TRAILER_BYTES]);
    crc_calc = ninlil_model_domain_crc32c(
        record.data, record.length - NINLIL_RT_V1_SERVICE_TRAILER_BYTES);
    if (crc_wire != crc_calc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    (void)memset(out_slot, 0, sizeof(*out_slot));
    out_slot->in_use = 1u;
    out_slot->attached = 0u;
    d = &out_slot->descriptor;
    set_header(&d->abi_version, &d->struct_size, sizeof(*d));
    pos = NINLIL_RT_V1_SERVICE_HEADER_BYTES;

    status = service_ledger_take_u32(record.data, record.length, &pos, &local_side);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(record.data, record.length, &pos, &d->family);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->direction);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->admission_authority);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->apply_contract);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->custody_policy);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->supported_evidence_mask);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->logical_payload_limit);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->target_limit);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->inflight_limit);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->max_attempts_per_target_per_cycle);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->admission_window_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->max_admissions_per_window);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->max_payload_bytes_per_window);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u16(
        record.data, record.length, &pos, &d->schema_major);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u16(
        record.data, record.length, &pos, &d->schema_minor_min);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u16(
        record.data, record.length, &pos, &d->schema_minor_max);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u16(
        record.data, record.length, &pos, &d->reserved_zero_u16);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u32(
        record.data, record.length, &pos, &d->reserved_zero_u32);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->minimum_deadline_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->maximum_deadline_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->maximum_evidence_grace_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->attempt_receipt_timeout_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->retry_backoff_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->application_completion_timeout_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->required_dedup_window_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &d->descriptor_revision);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u16(
        record.data, record.length, &pos, &d->descriptor_digest.algorithm);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u16(
        record.data, record.length, &pos, &d->descriptor_digest.reserved_zero);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take(
        record.data, record.length, &pos, d->descriptor_digest.bytes, 32u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take(
        record.data,
        record.length,
        &pos,
        d->local_application_instance_id.bytes,
        16u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_owned_text(
        record.data,
        record.length,
        &pos,
        out_slot->owned_namespace,
        &d->namespace_id);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_owned_text(
        record.data,
        record.length,
        &pos,
        out_slot->owned_service_id,
        &d->service_id);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_owned_text(
        record.data,
        record.length,
        &pos,
        out_slot->owned_schema_id,
        &d->schema_id);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &out_slot->quota_inflight);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &out_slot->quota_admissions);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &out_slot->quota_payload_bytes);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take(
        record.data, record.length, &pos, out_slot->quota_window_epoch, 16u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = service_ledger_take_u64(
        record.data, record.length, &pos, &out_slot->quota_window_start_ms);
    if (status != NINLIL_OK) {
        return status;
    }
    if (pos != record.length - NINLIL_RT_V1_SERVICE_TRAILER_BYTES) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_slot->model_service.local_side =
        (ninlil_model_local_submission_side_t)local_side;
    out_slot->model_service.family = d->family;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_spine_service_ledger_stage(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t txn,
    const ninlil_rt_service_slot_t *slot,
    ninlil_v1_durable_operation_t operation)
{
    const ninlil_storage_ops_t *storage;
    uint8_t key[NINLIL_RT_V1_SERVICE_LEDGER_KEY_MAX_BYTES];
    uint32_t key_length = 0u;
    uint32_t value_length = 0u;
    ninlil_status_t status;

    if (runtime == NULL || txn == NULL || slot == NULL
        || runtime->platform == NULL || runtime->platform->storage == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * Writer-gate enforces the closed operation→kind matrix. Register uses
     * SERVICE_REGISTER_COMMIT; admission uses SUBMIT; origin terminal uses
     * the caller's terminal op (OUTCOME/CANCEL/DISCARD/…) once that op
     * allowlists SPINE_SERVICE_MARKER.
     */
    if (operation < NINLIL_V1_DURABLE_OP_BOOTSTRAP_COMMIT
        || operation > NINLIL_V1_DURABLE_OP_DESTROY_RECOVERY_COMMIT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;
    status = ninlil_rt_v1_spine_service_ledger_key(
        &slot->descriptor, key, sizeof(key), &key_length);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_v1_spine_service_ledger_encode(
        slot,
        runtime->transaction_codec_bytes,
        NINLIL_RT_V1_SERVICE_LEDGER_VALUE_MAX_BYTES
            < NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES
            ? NINLIL_RT_V1_SERVICE_LEDGER_VALUE_MAX_BYTES
            : NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES,
        &value_length);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_v1_durable_storage_put(
        operation,
        storage,
        txn,
        (ninlil_bytes_view_t){key, key_length},
        (ninlil_bytes_view_t){runtime->transaction_codec_bytes, value_length},
        &runtime->commit_unknown_fence);
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
    }
    return status;
}

ninlil_status_t ninlil_rt_v1_spine_service_register_commit(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    uint32_t slot_index)
{
    const ninlil_storage_ops_t *storage;
    ninlil_model_capacity_batch_input_t capacity_input;
    ninlil_model_capacity_batch_result_t reserved;
    ninlil_model_capacity_batch_result_t committed;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t begin_status;
    ninlil_status_t status;

    (void)slot_index;
    if (runtime == NULL || slot == NULL || runtime->platform == NULL
        || runtime->platform->storage == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    /*
     * SERVICE is a durable semantic registry resource.  Derive the final
     * committed ledger before beginning the storage transaction so the NRS
     * service row and the SERVICE capacity row can be published by one FULL
     * commit. The public Runtime remains unchanged until that commit returns
     * OK.
     */
    (void)memset(&capacity_input, 0, sizeof(capacity_input));
    capacity_input.current = runtime->resource_ledger;
    capacity_input.operation =
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK;
    capacity_input.request_count = 1u;
    capacity_input.requests[0].kind = NINLIL_RESOURCE_SERVICE;
    capacity_input.requests[0].amount = 1u;
    status = ninlil_model_capacity_batch_transition(
        &capacity_input, &reserved);
    if (status != NINLIL_OK) {
        return status;
    }
    if (reserved.action != NINLIL_MODEL_CAPACITY_BATCH_ALL_RESERVED) {
        return reserved.action
                == NINLIL_MODEL_CAPACITY_BATCH_BLOCK_SET_REQUIRED
                || reserved.action
                    == NINLIL_MODEL_CAPACITY_BATCH_ALREADY_BLOCKED
            ? NINLIL_E_CAPACITY_EXHAUSTED
            : NINLIL_E_STORAGE_CORRUPT;
    }
    capacity_input.current = reserved.next;
    capacity_input.operation =
        NINLIL_MODEL_CAPACITY_BATCH_COMMIT_RESERVED;
    status = ninlil_model_capacity_batch_transition(
        &capacity_input, &committed);
    if (status != NINLIL_OK
        || committed.action
            != NINLIL_MODEL_CAPACITY_BATCH_ALL_COMMITTED) {
        return status != NINLIL_OK ? status : NINLIL_E_STORAGE_CORRUPT;
    }

    storage = runtime->platform->storage;
    begin_status = storage->begin(
        storage->user, runtime->storage, NINLIL_STORAGE_READ_WRITE, &txn);
    if (begin_status != NINLIL_STORAGE_OK) {
        return map_storage_mutation_status(runtime, begin_status);
    }
    status = ninlil_rt_v1_spine_service_ledger_stage(
        runtime,
        txn,
        slot,
        NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    status = ninlil_rt_v1_stage_resource_ledger_kind(
        runtime,
        txn,
        NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT,
        &committed.next,
        NINLIL_RESOURCE_SERVICE);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    status = storage_txn_commit_full(runtime, txn);
    if (status == NINLIL_OK) {
        runtime->resource_ledger = committed.next;
    }
    return status;
}

ninlil_status_t ninlil_rt_v1_spine_service_capacity_reject_commit(
    ninlil_runtime_t *runtime)
{
    const ninlil_storage_ops_t *storage;
    const uint32_t service_index =
        (uint32_t)NINLIL_RESOURCE_SERVICE - 1u;
    const ninlil_model_capacity_entry_t *current_service;
    ninlil_model_capacity_batch_input_t capacity_input;
    ninlil_model_capacity_batch_result_t blocked;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t begin_status;
    ninlil_status_t status;

    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->storage == NULL
        || service_index >= NINLIL_MODEL_RESOURCE_KIND_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    current_service = &runtime->resource_ledger.entries[service_index];
    if (current_service->kind != NINLIL_RESOURCE_SERVICE
        || current_service->limit != runtime->service_capacity
        || current_service->used != runtime->service_count
        || current_service->reserved != 0u
        || current_service->used < current_service->limit) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    (void)memset(&capacity_input, 0, sizeof(capacity_input));
    capacity_input.current = runtime->resource_ledger;
    capacity_input.operation =
        NINLIL_MODEL_CAPACITY_BATCH_RESERVE_OR_BLOCK;
    capacity_input.request_count = 1u;
    capacity_input.requests[0].kind = NINLIL_RESOURCE_SERVICE;
    capacity_input.requests[0].amount = 1u;
    status = ninlil_model_capacity_batch_transition(
        &capacity_input, &blocked);
    if (status != NINLIL_OK) {
        return status;
    }
    if (blocked.action == NINLIL_MODEL_CAPACITY_BATCH_ALREADY_BLOCKED) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    if (blocked.action
        != NINLIL_MODEL_CAPACITY_BATCH_BLOCK_SET_REQUIRED) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    storage = runtime->platform->storage;
    begin_status = storage->begin(
        storage->user, runtime->storage, NINLIL_STORAGE_READ_WRITE, &txn);
    if (begin_status != NINLIL_STORAGE_OK) {
        return map_storage_mutation_status(runtime, begin_status);
    }
    status = ninlil_rt_v1_stage_resource_ledger_kind(
        runtime,
        txn,
        NINLIL_V1_DURABLE_OP_SERVICE_REGISTER_COMMIT,
        &blocked.next,
        NINLIL_RESOURCE_SERVICE);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        return status;
    }
    status = storage_txn_commit_full(runtime, txn);
    if (status != NINLIL_OK) {
        return status;
    }
    runtime->resource_ledger = blocked.next;
    return NINLIL_E_CAPACITY_EXHAUSTED;
}

int ninlil_rt_v1_spine_quota_window_is_current(
    const ninlil_rt_service_slot_t *slot,
    const ninlil_time_sample_t *sample)
{
    uint64_t window_ms;
    uint64_t expected_start;

    if (slot == NULL || sample == NULL
        || sample->abi_version != NINLIL_ABI_VERSION
        || sample->struct_size != sizeof(*sample)
        || sample->trust != NINLIL_CLOCK_TRUSTED
        || sample->reserved_zero != 0u
        || id_is_zero(&sample->clock_epoch_id)) {
        return -1;
    }
    window_ms = slot->descriptor.admission_window_ms;
    if (window_ms == 0u) {
        return -1;
    }
    expected_start = sample->now_ms - (sample->now_ms % window_ms);
    if (memcmp(
            slot->quota_window_epoch,
            sample->clock_epoch_id.bytes,
            sizeof(sample->clock_epoch_id.bytes))
        != 0) {
        return 0;
    }
    if (slot->quota_window_start_ms != expected_start) {
        return 0;
    }
    return 1;
}

ninlil_status_t ninlil_rt_v1_spine_service_restore(
    ninlil_runtime_t *runtime)
{
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    uint8_t key_buf[255];
    ninlil_mut_bytes_t key;
    ninlil_mut_bytes_t value;
    ninlil_bytes_view_t prefix;
    ninlil_rt_service_slot_t decoded;
    uint32_t free_index;

    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->storage == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    storage = runtime->platform->storage;
    st = storage->begin(
        storage->user, runtime->storage, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage_mutation_status(runtime, st);
    }
    prefix.data = NULL;
    prefix.length = 0u;
    st = storage->iter_open(storage->user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        return NINLIL_E_STORAGE;
    }

    for (;;) {
        ninlil_status_t status;
        ninlil_rt_service_slot_t *slot = NULL;
        uint32_t prior;

        key.data = key_buf;
        key.capacity = (uint32_t)sizeof(key_buf);
        key.length = 0u;
        value.data = runtime->durable_scan_value;
        value.capacity = NINLIL_MODEL_DOMAIN_PRIVATE_RECORD_MAX_BYTES;
        value.length = 0u;
        st = storage->iter_next(storage->user, iter, &key, &value);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE;
        }
        if (key.length < 3u || key.data == NULL
            || key.data[0] != 0x4eu || key.data[1] != 0x52u
            || key.data[2] != 0x53u) {
            continue;
        }
        /*
         * LAB restore: key prefix must be exact NRS ledger shape; reject
         * truncated/overlong keys as corrupt rather than silently skipping.
         */
        if (key.length < 4u || key.length > NINLIL_RT_V1_SERVICE_LEDGER_KEY_MAX_BYTES) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        status = ninlil_rt_v1_spine_service_ledger_decode(
            (ninlil_bytes_view_t){value.data, value.length}, &decoded);
        if (status != NINLIL_OK) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return status == NINLIL_E_INVALID_ARGUMENT
                ? NINLIL_E_STORAGE_CORRUPT
                : status;
        }
        if (decoded.descriptor.namespace_id.length == 0u
            || decoded.descriptor.service_id.length == 0u
            || decoded.descriptor.schema_id.length == 0u
            || decoded.descriptor.admission_window_ms == 0u
            || decoded.descriptor.family == 0u) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        for (prior = 0u; prior < runtime->service_capacity; ++prior) {
            ninlil_rt_service_slot_t *existing = &runtime->services[prior];

            if (existing->in_use == 0u) {
                continue;
            }
            if (existing->descriptor.namespace_id.length
                    == decoded.descriptor.namespace_id.length
                && existing->descriptor.service_id.length
                    == decoded.descriptor.service_id.length
                && existing->descriptor.descriptor_revision
                    == decoded.descriptor.descriptor_revision
                && memcmp(
                       existing->descriptor.local_application_instance_id.bytes,
                       decoded.descriptor.local_application_instance_id.bytes,
                       16u)
                    == 0
                && memcmp(
                       existing->owned_namespace,
                       decoded.owned_namespace,
                       existing->descriptor.namespace_id.length)
                    == 0
                && memcmp(
                       existing->owned_service_id,
                       decoded.owned_service_id,
                       existing->descriptor.service_id.length)
                    == 0) {
                storage->iter_close(storage->user, iter);
                (void)storage->rollback(storage->user, txn);
                return NINLIL_E_STORAGE_CORRUPT;
            }
        }
        for (free_index = 0u; free_index < runtime->service_capacity;
             ++free_index) {
            if (runtime->services[free_index].in_use == 0u) {
                slot = &runtime->services[free_index];
                break;
            }
        }
        if (slot == NULL) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_CAPACITY_EXHAUSTED;
        }
        *slot = decoded;
        /*
         * Rebind owned text views to this slot's buffers after structure
         * assignment (decode filled views against the temporary decode object).
         */
        slot->descriptor.namespace_id.data = slot->owned_namespace;
        slot->descriptor.service_id.data = slot->owned_service_id;
        slot->descriptor.schema_id.data = slot->owned_schema_id;
        slot->attached = 0u;
        (void)memset(&slot->callbacks, 0, sizeof(slot->callbacks));
        slot->public_handle.magic = 0u;
        slot->public_handle.runtime = NULL;
        slot->public_handle.slot_index = free_index;
        runtime->service_count += 1u;
    }

    storage->iter_close(storage->user, iter);
    (void)storage->rollback(storage->user, txn);
    return NINLIL_OK;
}

static ninlil_model_descriptor_contract_extension_t descriptor_contract_from(
    const ninlil_service_descriptor_t *descriptor)
{
    ninlil_model_descriptor_contract_extension_t contract;

    (void)memset(&contract, 0, sizeof(contract));
    contract.direction = descriptor->direction;
    contract.admission_authority = descriptor->admission_authority;
    contract.apply_contract = descriptor->apply_contract;
    contract.custody_policy = descriptor->custody_policy;
    contract.target_limit = descriptor->target_limit;
    contract.max_attempts_per_target_per_cycle =
        descriptor->max_attempts_per_target_per_cycle;
    contract.attempt_receipt_timeout_ms =
        descriptor->attempt_receipt_timeout_ms;
    contract.retry_backoff_ms = descriptor->retry_backoff_ms;
    contract.application_completion_timeout_ms =
        descriptor->application_completion_timeout_ms;
    contract.required_dedup_window_ms = descriptor->required_dedup_window_ms;
    return contract;
}

static void copy_grant_snapshot(
    ninlil_model_origin_grant_snapshot_t *out_grant,
    const ninlil_origin_authorization_decision_t *decision)
{
    out_grant->provider_id = decision->provider_id;
    out_grant->provider_revision = decision->provider_revision;
    out_grant->decision_digest = decision->decision_digest;
    out_grant->grant_id = decision->grant_id;
    out_grant->grant_revision = decision->grant_revision;
    out_grant->clock_epoch_id = decision->clock_epoch_id;
    out_grant->evaluated_at_ms = decision->evaluated_at_ms;
    out_grant->valid_from_ms = decision->valid_from_ms;
    out_grant->expires_at_ms = decision->expires_at_ms;
    out_grant->retry_delay_ms = decision->retry_delay_ms;
    out_grant->max_payload_bytes = decision->max_payload_bytes;
    out_grant->max_active_spool_count = decision->max_active_spool_count;
    out_grant->max_active_spool_bytes = decision->max_active_spool_bytes;
    out_grant->rate_window_ms = decision->rate_window_ms;
    out_grant->max_admissions_per_window = decision->max_admissions_per_window;
    out_grant->max_attempts_per_retry_cycle =
        decision->max_attempts_per_retry_cycle;
}

static ninlil_status_t fill_origin_authority(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    ninlil_model_submission_preflight_input_t *input,
    const ninlil_time_sample_t *admission_sample)
{
    const ninlil_origin_authorization_ops_t *origin;
    ninlil_origin_authorization_request_t request;
    ninlil_origin_authorization_decision_t decision;
    ninlil_origin_auth_status_t auth_status;

    if (slot->model_service.family != NINLIL_FAMILY_EVENT_FACT
        && slot->model_service.family != NINLIL_FAMILY_LATEST_STATE_RESERVED
        && slot->model_service.family != NINLIL_FAMILY_MEASUREMENT_RESERVED) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_NOT_APPLICABLE;
        return NINLIL_OK;
    }

    origin = runtime->platform->origin_authorization;
    if (origin == NULL || origin->evaluate == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(&request, 0, sizeof(request));
    set_header(&request.abi_version, &request.struct_size, sizeof(request));
    request.environment = runtime->config.environment;
    request.source = slot->model_service.source;
    if (submission->target_count == 1u && submission->targets != NULL) {
        request.target = submission->targets[0];
    }
    request.service = slot->model_service.identity;
    request.event_id = submission->event_id;
    request.content_digest = submission->content_digest;
    request.required_evidence = submission->required_evidence;
    request.payload_length = (uint32_t)submission->payload.length;
    request.active_spool_count =
        (uint32_t)input->event_grant_usage.active_spool_count;
    request.admissions_in_current_window =
        (uint32_t)input->quota.admissions_in_window;
    request.active_spool_bytes = input->event_grant_usage.active_spool_bytes;
    /*
     * docs/12: M1a request rate window is descriptor admission_window_ms
     * (`floor(now_ms / admission_window_ms)`), not a hardcoded 10000ms.
     */
    if (slot->descriptor.admission_window_ms == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    request.current_window_started_at_ms =
        input->clock.now_ms
        - (input->clock.now_ms % slot->descriptor.admission_window_ms);
    request.now = *admission_sample;

    (void)memset(&decision, 0, sizeof(decision));
    auth_status = origin->evaluate(origin->user, &request, &decision);
    if (auth_status == NINLIL_ORIGIN_AUTH_TEMPORARY_FAILURE) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_TEMPORARY_FAILURE;
        return NINLIL_OK;
    }
    if (auth_status == NINLIL_ORIGIN_AUTH_PERMANENT_FAILURE) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_PERMANENT_OR_INVALID;
        return NINLIL_OK;
    }
    if (auth_status != NINLIL_ORIGIN_AUTH_OK) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (decision.allowed == 0u) {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_DENY;
        input->authority.deny_reason = decision.reason;
        input->authority.deny_guidance = decision.retry_guidance;
        input->authority.deny_retry_delay_ms = decision.retry_delay_ms;
        copy_grant_snapshot(&input->authority.grant, &decision);
        return NINLIL_OK;
    }

    input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_ALLOW;
    copy_grant_snapshot(&input->authority.grant, &decision);
    return NINLIL_OK;
}

static ninlil_status_t fill_preflight_input(
    ninlil_model_submission_preflight_input_t *input,
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_time_sample_t *admission_sample)
{
    ninlil_status_t status;
    ninlil_rt_target_resolve_result_t resolved_targets;
    uint32_t digest_matches = 0u;
    uint32_t target_index;
    int mapping_only;

    (void)memset(input, 0, sizeof(*input));
    mapping_only = (admission_sample == NULL);
    input->service = slot->model_service;
    input->submission.schema_major = submission->schema_major;
    input->submission.schema_minor = submission->schema_minor;
    input->submission.target_count = submission->target_count;
    status = ninlil_rt_v1_resolve_submission_targets(
        runtime, &slot->descriptor, submission, &resolved_targets);
    if (status != NINLIL_OK) {
        return status;
    }
    if (resolved_targets.reject_reason != NINLIL_REASON_NONE) {
        input->submission.target_count = 0u;
    } else {
        input->submission.target_count = resolved_targets.target_count;
        for (target_index = 0u;
             target_index < resolved_targets.target_count;
             ++target_index) {
            input->submission.targets[target_index] =
                resolved_targets.targets[target_index].target;
        }
        input->submission.target = input->submission.targets[0];
    }
    input->submission.required_evidence = submission->required_evidence;
    input->submission.payload_length = submission->payload.length;
    input->submission.content_digest = submission->content_digest;
    status = recompute_payload_content_digest_match(
        submission, &digest_matches);
    if (status != NINLIL_OK) {
        return status;
    }
    input->submission.content_digest_matches = digest_matches;
    input->submission.effect_deadline_ms = submission->effect_deadline_ms;
    input->submission.evidence_grace_ms = submission->evidence_grace_ms;
    input->submission.event_id = submission->event_id;
    input->submission.generation = submission->generation;
    if (submission->idempotency_key.length > 0u
        && submission->idempotency_key.length <= 64u
        && submission->idempotency_key.data != NULL) {
        input->submission.idempotency_key.length =
            (uint8_t)submission->idempotency_key.length;
        (void)memcpy(
            input->submission.idempotency_key.bytes,
            submission->idempotency_key.data,
            submission->idempotency_key.length);
    }
    /*
     * Target resolver failures are semantic rejections.  Stop before
     * canonical encoding (which intentionally refuses a zero/duplicate
     * roster) so they cannot be misreported as API INVALID_ARGUMENT.
     */
    if (input->submission.target_count == 0u) {
        input->submission.canonical_submission_digest.algorithm =
            NINLIL_DIGEST_SHA256;
        input->caller_key_mapping.state = NINLIL_MODEL_MAPPING_ABSENT;
        input->event_id_mapping.state = NINLIL_MODEL_MAPPING_ABSENT;
        input->clock.state = NINLIL_MODEL_ADMISSION_CLOCK_TRUSTED;
        input->clock.clock_epoch_id.bytes[0] = 1u;
        input->resource_ledger = runtime->resource_ledger;
        return NINLIL_OK;
    }
    {
        ninlil_submission_t canonical_submission = *submission;
        ninlil_concrete_target_t canonical_targets[
            NINLIL_RT_V1_MAX_TARGETS_PER_TXN];

        for (target_index = 0u;
             target_index < resolved_targets.target_count;
             ++target_index) {
            canonical_targets[target_index] =
                resolved_targets.targets[target_index].target;
        }
        canonical_submission.targets = canonical_targets;
        canonical_submission.target_count = resolved_targets.target_count;
        status = ninlil_rt_canonical_submission_digest_v1(
            &slot->descriptor,
            &canonical_submission,
            &input->submission.canonical_submission_digest);
    }
    if (status != NINLIL_OK) {
        return status;
    }
    /*
     * Mapping lookup is pure RAM over restored + live origin transactions.
     * Mismatch/ALREADY terminate before clock/provider/quota/entropy/commit.
     */
    lookup_caller_key_mapping(
        runtime,
        slot,
        submission,
        &input->submission.canonical_submission_digest,
        &input->caller_key_mapping);
    if (slot->model_service.family == NINLIL_FAMILY_EVENT_FACT) {
        lookup_event_id_mapping(
            runtime,
            slot,
            submission,
            &input->submission.canonical_submission_digest,
            &input->event_id_mapping);
    } else {
        input->event_id_mapping.state = NINLIL_MODEL_MAPPING_ABSENT;
    }
    input->last_transaction_sequence = runtime->transaction_sequence;
    input->last_scheduler_owner_sequence =
        runtime->last_assigned_scheduler_owner_sequence;
    input->resource_ledger = runtime->resource_ledger;

    if (mapping_only != 0) {
        /*
         * Phase-1: mapping/syntax only. No trusted-clock sample, Origin
         * Authorization, or quota window classification.
         */
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_NOT_APPLICABLE;
        input->clock.state = NINLIL_MODEL_ADMISSION_CLOCK_TRUSTED;
        input->clock.clock_epoch_id.bytes[0] = 1u;
        input->clock.now_ms = 0u;
        input->quota.inflight_count = slot->quota_inflight;
        input->quota.window_is_current = 0u;
        return NINLIL_OK;
    }

    input->clock.state = NINLIL_MODEL_ADMISSION_CLOCK_TRUSTED;
    input->clock.clock_epoch_id = admission_sample->clock_epoch_id;
    input->clock.now_ms = admission_sample->now_ms;
    /*
     * Origin Authorization is after idempotency (docs/12 exact order).  Skip
     * the provider on content-digest mismatch or any mapping terminal path.
     */
    if (input->submission.content_digest_matches != 0u
        && input->caller_key_mapping.state == NINLIL_MODEL_MAPPING_ABSENT
        && input->event_id_mapping.state == NINLIL_MODEL_MAPPING_ABSENT) {
        status = fill_origin_authority(
            runtime, slot, submission, input, admission_sample);
        if (status != NINLIL_OK) {
            return status;
        }
    } else {
        input->authority.fact = NINLIL_MODEL_ORIGIN_AUTH_NOT_APPLICABLE;
    }
    {
        int window_current = ninlil_rt_v1_spine_quota_window_is_current(
            slot, admission_sample);

        if (window_current < 0) {
            return NINLIL_E_CLOCK_UNCERTAIN;
        }
        input->quota.inflight_count = slot->quota_inflight;
        if (window_current != 0) {
            input->quota.admissions_in_window = slot->quota_admissions;
            input->quota.payload_bytes_in_window = slot->quota_payload_bytes;
            input->quota.window_is_current = 1u;
        } else {
            /*
             * Epoch or fixed-window bucket mismatch: evaluate from zero
             * counters without mutating the durable bucket until FULL admit.
             */
            input->quota.admissions_in_window = 0u;
            input->quota.payload_bytes_in_window = 0u;
            input->quota.window_is_current = 0u;
        }
    }
    return NINLIL_OK;
}

static ninlil_status_t read_admission_clock(
    ninlil_runtime_t *runtime,
    ninlil_time_sample_t *out_sample)
{
    ninlil_port_status_t status;

    (void)memset(out_sample, 0, sizeof(*out_sample));
    status = runtime->platform->clock->now(
        runtime->platform->clock->user, out_sample);
    if (status == NINLIL_PORT_TEMPORARY_FAILURE) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (status != NINLIL_PORT_OK
        || out_sample->abi_version != NINLIL_ABI_VERSION
        || out_sample->struct_size != sizeof(*out_sample)
        || out_sample->trust != NINLIL_CLOCK_TRUSTED
        || id_is_zero(&out_sample->clock_epoch_id)
        || out_sample->reserved_zero != 0u) {
        return NINLIL_E_DEGRADED;
    }
    return NINLIL_OK;
}

static ninlil_status_t fill_transaction_id_draws(
    ninlil_runtime_t *runtime,
    ninlil_model_id_allocation_input_t *input)
{
    uint32_t index;

    for (index = 0u;
         index < NINLIL_MODEL_TRANSACTION_ID_MAX_DRAWS;
         ++index) {
        ninlil_model_transaction_id_draw_t *draw = &input->draws[index];
        ninlil_port_status_t status;

        draw->ordinal = index + 1u;
        status = runtime->platform->entropy->fill(
            runtime->platform->entropy->user,
            draw->candidate.bytes,
            (uint32_t)sizeof(draw->candidate.bytes));
        input->draw_count = index + 1u;
        if (status == NINLIL_PORT_TEMPORARY_FAILURE) {
            draw->entropy_state =
                NINLIL_MODEL_ENTROPY_DRAW_TEMPORARY_FAILURE;
            draw->collision_state =
                NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
            continue;
        }
        if (status != NINLIL_PORT_OK) {
            draw->entropy_state =
                NINLIL_MODEL_ENTROPY_DRAW_PERMANENT_FAILURE;
            draw->collision_state =
                NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
            continue;
        }
        draw->entropy_state = NINLIL_MODEL_ENTROPY_DRAW_FULL;
        if (id_is_zero(&draw->candidate)) {
            draw->collision_state =
                NINLIL_MODEL_TRANSACTION_COLLISION_NOT_CHECKED;
            continue;
        }
        draw->collision_state =
            ninlil_rt_find_transaction(runtime, &draw->candidate) == NULL
            ? NINLIL_MODEL_TRANSACTION_ID_UNIQUE
            : NINLIL_MODEL_TRANSACTION_ID_COLLISION;
        if (draw->collision_state == NINLIL_MODEL_TRANSACTION_ID_UNIQUE) {
            return NINLIL_OK;
        }
    }
    return NINLIL_OK;
}

static void fill_admitted_transaction(
    ninlil_runtime_t *runtime,
    ninlil_rt_transaction_slot_t *transaction,
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_model_admission_write_set_t *write_set,
    const ninlil_time_sample_t *admission_sample)
{
    uint32_t target_index;
    (void)memset(transaction, 0, sizeof(*transaction));
    transaction->in_use = 1u;
    transaction->origin_admission = 1u;
    transaction->transaction_id = write_set->transaction_id;
    transaction->service_app_id =
        slot->descriptor.local_application_instance_id;
    transaction->event_id = submission->event_id;
    transaction->source = write_set->plan.source;
    transaction->service = write_set->plan.service;
    transaction->content_digest = submission->content_digest;
    if (submission->idempotency_key.length > 0u
        && submission->idempotency_key.length <= NINLIL_MAX_IDEMPOTENCY_BYTES
        && submission->idempotency_key.data != NULL) {
        transaction->idempotency_key_length =
            (uint8_t)submission->idempotency_key.length;
        (void)memcpy(
            transaction->idempotency_key,
            submission->idempotency_key.data,
            submission->idempotency_key.length);
    }
    transaction->canonical_submission_digest =
        write_set->plan.canonical_submission_digest;
    transaction->family = slot->model_service.family;
    transaction->required_evidence = submission->required_evidence;
    transaction->latest_evidence =
        write_set->initial_family_snapshot.latest_evidence;
    transaction->deadline_verdict =
        write_set->initial_family_snapshot.deadline_verdict;
    transaction->transaction_sequence =
        write_set->plan.transaction_sequence;
    transaction->record_revision =
        write_set->transaction_record_revision;
    transaction->pending_dispatch = 1u;
    transaction->delivery_phase = NINLIL_RT_DELIVERY_QUEUED;
    transaction->effect_deadline_ms =
        write_set->plan.absolute_effect_deadline_ms;
    transaction->evidence_grace_ms = submission->evidence_grace_ms;
    transaction->admission_clock_epoch_id =
        write_set->plan.admission_clock_epoch_id;
    transaction->deadline_clock_epoch_id =
        write_set->plan.deadline_clock_epoch_id;
    transaction->generation = submission->generation;
    transaction->payload_length = (uint32_t)submission->payload.length;
    {
        uint32_t copy_len = (uint32_t)submission->payload.length;
        uint8_t use_mfdt = 0u;
#if defined(NINLIL_MFDT_V1_PRIVATE)
        if (runtime_mfdt_enabled(
                runtime, copy_len, write_set->plan.target_count)) {
            use_mfdt = 1u;
        }
#else
        (void)runtime;
#endif
        if (use_mfdt != 0u) {
            /* Content custody is NM3S; slot keeps digest identity only. */
            transaction->inline_payload_length = 0u;
            (void)memset(transaction->owned_payload, 0,
                         sizeof(transaction->owned_payload));
        } else if (copy_len != 0u) {
            if (copy_len > NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES) {
                copy_len = NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES;
            }
            transaction->inline_payload_length = copy_len;
            (void)memcpy(
                transaction->owned_payload,
                submission->payload.data,
                copy_len);
        } else {
            transaction->inline_payload_length = 0u;
        }
        transaction->bearer_route =
            use_mfdt != 0u
                ? (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1
                : (uint8_t)ninlil_rt_v1_default_bearer_route();
    }
    transaction->semantic_priority =
        ninlil_rt_v1_semantic_priority_for_family(slot->model_service.family);
    transaction->reservation_active = 1u;
    transaction->reservation_evidence_units =
        (slot->model_service.max_evidence_per_target + 1u)
        * write_set->plan.target_count;
    transaction->admitted_at_ms = admission_sample->now_ms;
    transaction->attempt_receipt_timeout_ms =
        slot->descriptor.attempt_receipt_timeout_ms;
    transaction->retry_backoff_ms = slot->descriptor.retry_backoff_ms;
    transaction->retry_budget = NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    transaction->retry_cycle_id =
        transaction->family == NINLIL_FAMILY_EVENT_FACT ? 1u : 0u;
    transaction->attempt_in_cycle = 0u;
    transaction->cumulative_attempts = 0u;
    transaction->spool_revision =
        transaction->family == NINLIL_FAMILY_EVENT_FACT
        ? (write_set->event_spool_revision != 0u
                ? write_set->event_spool_revision : 1u)
        : 0u;
    transaction->assurance = write_set->assurance;
    transaction->bound_target_count = write_set->plan.target_count;
    for (target_index = 0u;
         target_index < transaction->bound_target_count;
         ++target_index) {
        transaction->bound_targets[target_index].in_use = 1u;
        transaction->bound_targets[target_index].target =
            write_set->plan.targets[target_index];
        ninlil_rt_v1_initialize_target_state(
            &transaction->bound_targets[target_index],
            transaction->family);
    }
#if defined(NINLIL_MFDT_V1_PRIVATE)
    if (transaction->bearer_route
        == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1) {
        for (target_index = 0u;
             target_index < transaction->bound_target_count;
             ++target_index) {
            ninlil_bearer_message_t application;

            fill_mfdt_application_envelope(
                &application, transaction, submission, target_index);
            ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
                &application,
                target_index,
                transaction->bound_targets[target_index].mfdt_transfer_id);
            transaction->bound_targets[target_index].mfdt_target_ordinal =
                target_index;
        }
    }
#endif
    transaction->active_target_index = 0u;
    if (transaction->family == NINLIL_FAMILY_DESIRED_STATE) {
        ninlil_rt_v1_activate_target(transaction, 0u);
        ninlil_rt_v1_refresh_target_aggregate(transaction);
    }
}

ninlil_status_t ninlil_rt_v1_spine_submit_admission(
    ninlil_runtime_t *runtime,
    ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    ninlil_submission_result_t *out_result)
{
    ninlil_model_submission_preflight_input_t preflight_in;
    ninlil_model_submission_preflight_result_t preflight_out;
    ninlil_model_id_allocation_input_t alloc_in;
    ninlil_model_id_allocation_result_t alloc_out;
    ninlil_model_admission_commit_input_t commit_in;
    ninlil_model_admission_commit_result_t commit_out;
    ninlil_rt_transaction_slot_t *txn_slot;
    ninlil_rt_transaction_slot_t *admitted_transaction;
    ninlil_time_sample_t admission_sample;
    ninlil_status_t status;
    const ninlil_storage_ops_t *storage;
    ninlil_storage_txn_t txn = NULL;
    uint8_t marker_key[32];
    uint32_t marker_value_length = 0u;
    int mapping_terminal = 0;
#if defined(NINLIL_MFDT_V1_PRIVATE)
    uint8_t mfdt_prearmed_count = 0u;
    uint8_t mfdt_prearmed_slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT] = {
        UINT8_MAX, UINT8_MAX, UINT8_MAX, UINT8_MAX
    };
#endif

    /*
     * docs/12 exact order: syntax/schema/content → idempotency/event mapping
     * lookup → trusted admission reference sample → … . Mapping ALREADY /
     * CONFLICT must not sample trusted clock or call Origin Authorization.
     */
    status = fill_preflight_input(
        &preflight_in, runtime, slot, submission, NULL);
    if (status != NINLIL_OK) {
        return status;
    }
    mapping_terminal =
        (preflight_in.caller_key_mapping.state != NINLIL_MODEL_MAPPING_ABSENT
            || preflight_in.event_id_mapping.state
                != NINLIL_MODEL_MAPPING_ABSENT
            || preflight_in.submission.content_digest_matches == 0u);
    if (mapping_terminal != 0) {
        status = ninlil_model_submission_preflight(
            &preflight_in, &preflight_out);
        if (status != NINLIL_OK) {
            return status;
        }
        if (preflight_out.action
            == NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL) {
            *out_result = preflight_out.public_result;
            return preflight_out.api_status;
        }
        /* Fall through only if mapping-only path still wants new admit. */
    }
    status = read_admission_clock(runtime, &admission_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    status = fill_preflight_input(
        &preflight_in, runtime, slot, submission, &admission_sample);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_model_submission_preflight(&preflight_in, &preflight_out);
    if (status != NINLIL_OK) {
        return status;
    }
    if (preflight_out.action == NINLIL_MODEL_SUBMISSION_PREFLIGHT_TERMINAL) {
        *out_result = preflight_out.public_result;
        return preflight_out.api_status;
    }
#if defined(NINLIL_MFDT_V1_PRIVATE)
    if (runtime_mfdt_enabled(
            runtime,
            (uint32_t)submission->payload.length,
            preflight_in.submission.target_count) &&
        mfdt_roster_has_duplicate_runtime(
            preflight_in.submission.targets,
            preflight_in.submission.target_count)) {
        out_result->kind = NINLIL_SUBMISSION_REJECTED;
        out_result->reason = NINLIL_REASON_TARGET_COUNT_UNSUPPORTED;
        out_result->retry_guidance = NINLIL_RETRY_MODIFIED;
        return NINLIL_OK;
    }
#endif
    if (preflight_out.action
        == NINLIL_MODEL_SUBMISSION_PREFLIGHT_CAPACITY_BLOCK_COMMIT_REQUIRED) {
        storage = runtime->platform->storage;
        status = map_storage_mutation_status(
            runtime,
            storage->begin(
                storage->user,
                runtime->storage,
                NINLIL_STORAGE_READ_WRITE,
                &txn));
        if (status != NINLIL_OK) {
            return status;
        }
        status = ninlil_rt_v1_stage_resource_ledger(
            runtime,
            txn,
            NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
            &preflight_out.capacity_block.next_ledger);
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, txn);
            return status;
        }
        status = storage_txn_commit_full(runtime, txn);
        if (status != NINLIL_OK) {
            return status;
        }
        runtime->resource_ledger =
            preflight_out.capacity_block.next_ledger;
        out_result->kind = NINLIL_SUBMISSION_REJECTED;
        out_result->reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
        out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
        return NINLIL_OK;
    }
    if (preflight_out.action
        != NINLIL_MODEL_SUBMISSION_PREFLIGHT_READY_FOR_ID_ALLOCATION) {
        return NINLIL_E_INTERNAL;
    }

    {
        ninlil_rt_v1_bearer_route_t admit_route =
            ninlil_rt_v1_default_bearer_route();
#if defined(NINLIL_MFDT_V1_PRIVATE)
        if (runtime_mfdt_enabled(
                runtime,
                (uint32_t)submission->payload.length,
                preflight_out.admission.target_count)) {
            admit_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
        }
#endif
        status = ninlil_rt_v1_check_bearer_payload_admission(
            admit_route,
            (uint32_t)submission->payload.length,
            out_result);
        if (status != NINLIL_OK) {
            return status;
        }
        if (out_result->kind == NINLIL_SUBMISSION_REJECTED) {
            return NINLIL_OK;
        }
    }

    if (runtime->nonterminal_transaction_count
        >= runtime->config.limits.max_nonterminal_transactions) {
        out_result->kind = NINLIL_SUBMISSION_REJECTED;
        out_result->reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
        out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
        return NINLIL_OK;
    }

    (void)memset(&alloc_in, 0, sizeof(alloc_in));
    alloc_in.preflight_plan = preflight_out.admission;
    alloc_in.descriptor_contract = descriptor_contract_from(&slot->descriptor);
    alloc_in.payload.length = submission->payload.length;
    if (submission->payload.length > 0u && submission->payload.data != NULL) {
        uint32_t plen = (uint32_t)submission->payload.length;
        uint8_t mfdt = 0u;
#if defined(NINLIL_MFDT_V1_PRIVATE)
        if (runtime_mfdt_enabled(
                runtime, plen, preflight_out.admission.target_count)) {
            mfdt = 1u;
        }
#endif
        alloc_in.payload.length = plen;
        alloc_in.payload.content_verified = 1u;
        alloc_in.payload.verified_content_digest = submission->content_digest;
        if (mfdt == 0u) {
            if (plen > NINLIL_MODEL_ADMISSION_MAX_PAYLOAD_BYTES) {
                plen = NINLIL_MODEL_ADMISSION_MAX_PAYLOAD_BYTES;
            }
            (void)memcpy(
                alloc_in.payload.bytes,
                submission->payload.data,
                plen);
            alloc_in.payload.length = plen;
        }
        /* MFDT: digest-only admission payload; content → NM3S in arm step. */
    }
    status = fill_transaction_id_draws(runtime, &alloc_in);
    if (status != NINLIL_OK) {
        return status;
    }

    status = ninlil_model_reduce_transaction_id_allocation(
        &alloc_in, &alloc_out);
    if (status != NINLIL_OK) {
        return status;
    }
    if (alloc_out.action != NINLIL_MODEL_ID_ALLOCATION_READY_FOR_FULL_COMMIT) {
        *out_result = alloc_out.public_result;
        return alloc_out.api_status;
    }

    txn_slot = ninlil_rt_alloc_transaction(runtime);
    if (txn_slot == NULL) {
        out_result->kind = NINLIL_SUBMISSION_REJECTED;
        out_result->reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
        out_result->retry_guidance = NINLIL_RETRY_SAME_AFTER;
        return NINLIL_OK;
    }

    admitted_transaction = &runtime->transaction_scratch;
    fill_admitted_transaction(
        runtime,
        admitted_transaction,
        slot,
        submission,
        &alloc_out.write_set,
        &admission_sample);
#if defined(NINLIL_MFDT_V1_PRIVATE)
    if (admitted_transaction->bearer_route
        == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1) {
        uint32_t target_index;

        for (target_index = 0u;
             target_index < admitted_transaction->bound_target_count;
             ++target_index) {
            ninlil_bearer_message_t application;
            int mrc;

            fire_admission_hook(
                runtime, "admission.before_mfdt_attempt_draw");
            status = prepare_mfdt_admission_target_attempt(
                runtime, admitted_transaction, target_index);
            fire_admission_hook(
                runtime, "admission.after_mfdt_attempt_draw");
            if (status != NINLIL_OK) {
                return finish_mfdt_prearmed_failure(
                    runtime,
                    admitted_transaction,
                    mfdt_prearmed_slots,
                    mfdt_prearmed_count,
                    status,
                    out_result);
            }
            fill_mfdt_application_envelope(
                &application,
                admitted_transaction,
                submission,
                target_index);
            fire_admission_hook(
                runtime, "admission.before_mfdt_sender_open");
            mrc = ninlil_rt_mfdt_v1_runtime_sender_open(
                runtime,
                &application,
                submission->payload.data,
                (uint32_t)submission->payload.length,
                target_index,
                admitted_transaction->bound_targets[target_index]
                    .mfdt_transfer_id,
                &mfdt_prearmed_slots[target_index]);
            fire_admission_hook(
                runtime, "admission.after_mfdt_sender_open");
            if (mrc != NINLIL_MFDT_V1_OK) {
                saturating_increment_u64(&runtime->metrics.storage_failures);
                status = map_mfdt_sender_open_status(runtime, mrc);
                return finish_mfdt_prearmed_failure(
                    runtime,
                    admitted_transaction,
                    mfdt_prearmed_slots,
                    mfdt_prearmed_count,
                    status,
                    out_result);
            }
            mfdt_prearmed_count += 1u;
        }
    }
#endif
    status = ninlil_rt_v1_transaction_record_encode(
        admitted_transaction,
        runtime->transaction_codec_bytes,
        NINLIL_RT_V1_TRANSACTION_RECORD_MAX_BYTES,
        &marker_value_length);
    if (status != NINLIL_OK) {
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime,
            admitted_transaction,
            mfdt_prearmed_slots,
            mfdt_prearmed_count,
            status,
            out_result);
#else
        return status;
#endif
    }

    storage = runtime->platform->storage;
    status = map_storage_mutation_status(
        runtime,
        storage->begin(
            storage->user,
            runtime->storage,
            NINLIL_STORAGE_READ_WRITE,
            &txn));
    if (status != NINLIL_OK) {
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime,
            admitted_transaction,
            mfdt_prearmed_slots,
            mfdt_prearmed_count,
            status,
            out_result);
#else
        return status;
#endif
    }

    marker_key[0] = 0x54u;
    marker_key[1] = 0x58u;
    (void)memcpy(
        &marker_key[2],
        alloc_out.write_set.transaction_id.bytes,
        sizeof(alloc_out.write_set.transaction_id.bytes));

    fire_admission_hook(runtime, "admission.before_txn_put");
    status = ninlil_v1_durable_storage_put(
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        storage,
        txn,
        (ninlil_bytes_view_t){marker_key, 18u},
        (ninlil_bytes_view_t){
            runtime->transaction_codec_bytes, marker_value_length},
        &runtime->commit_unknown_fence);
    fire_admission_hook(runtime, "admission.after_txn_put");
    if (status != NINLIL_OK) {
        saturating_increment_u64(&runtime->metrics.storage_failures);
        (void)storage->rollback(storage->user, txn);
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime, admitted_transaction, mfdt_prearmed_slots,
            mfdt_prearmed_count, status, out_result);
#else
        return status;
#endif
    }

    status = stage_admission_map_rows(
        runtime,
        txn,
        slot,
        submission,
        admitted_transaction,
        runtime->transaction_codec_bytes,
        marker_value_length);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime, admitted_transaction, mfdt_prearmed_slots,
            mfdt_prearmed_count, status, out_result);
#else
        return status;
#endif
    }

    {
        ninlil_rt_v1_bearer_route_t res_route =
            ninlil_rt_v1_default_bearer_route();
#if defined(NINLIL_MFDT_V1_PRIVATE)
        if (admitted_transaction->bearer_route
            == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1) {
            res_route = NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1;
        }
#endif
        status = ninlil_rt_v1_stage_reservation_marker(
            runtime,
            txn,
            NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
            &alloc_out.write_set.transaction_id,
            (uint32_t)submission->payload.length,
            res_route);
    }
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime, admitted_transaction, mfdt_prearmed_slots,
            mfdt_prearmed_count, status, out_result);
#else
        return status;
#endif
    }
    status = ninlil_rt_v1_stage_resource_ledger(
        runtime,
        txn,
        NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT,
        &preflight_out.admission.resources.committed_ledger);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime, admitted_transaction, mfdt_prearmed_slots,
            mfdt_prearmed_count, status, out_result);
#else
        return status;
#endif
    }

    {
        ninlil_rt_service_slot_t quota_snapshot = *slot;
        const ninlil_model_quota_commit_plan_t *quota =
            &preflight_out.admission.quota;

        quota_snapshot.quota_inflight = quota->next_inflight_count;
        quota_snapshot.quota_admissions = quota->next_admissions_in_window;
        quota_snapshot.quota_payload_bytes = quota->next_payload_bytes_in_window;
        (void)memcpy(
            quota_snapshot.quota_window_epoch,
            quota->clock_epoch_id.bytes,
            sizeof(quota_snapshot.quota_window_epoch));
        quota_snapshot.quota_window_start_ms = quota->window_started_at_ms;
#if defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    && (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING != 0)
        /*
         * Domain-ON: durable admission quota is Domain SERVICE_QUOTA, not
         * the V1-LAB NRS service ledger. Prefer Domain QUOTA; if the
         * Domain envelope stage cannot apply (e.g. witness chain not yet
         * updated for mid-group REPLACE), fall back to NRS ledger rewrite
         * so admission still has a durable quota surface under HOST_CANDIDATE.
         */
        /*
         * Domain path: always stage Domain SERVICE_QUOTA. Also co-stage NRS
         * when Domain stage succeeds so hybrid tools can still read NRS; if
         * Domain fails, fail the admit (do not silently fall back to NRS-only
         * which leaves Domain QUOTA at register-zero on restart restore).
         */
        status = ninlil_domain_schema1_quota_stage(
            runtime, txn, &quota_snapshot);
        if (status == NINLIL_OK) {
            ninlil_status_t nrs_st = ninlil_rt_v1_spine_service_ledger_stage(
                runtime,
                txn,
                &quota_snapshot,
                NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT);
            if (nrs_st != NINLIL_OK) {
                status = nrs_st;
            }
        }
#else
        status = ninlil_rt_v1_spine_service_ledger_stage(
            runtime,
            txn,
            &quota_snapshot,
            NINLIL_V1_DURABLE_OP_SUBMIT_ADMISSION_COMMIT);
#endif
        if (status != NINLIL_OK) {
            (void)storage->rollback(storage->user, txn);
#if defined(NINLIL_MFDT_V1_PRIVATE)
            return finish_mfdt_prearmed_failure(
                runtime, admitted_transaction, mfdt_prearmed_slots,
                mfdt_prearmed_count, status, out_result);
#else
            return status;
#endif
        }
    }

    (void)memset(&commit_in, 0, sizeof(commit_in));
    commit_in.write_set = alloc_out.write_set;
    commit_in.commit_state = NINLIL_MODEL_ADMISSION_COMMIT_OK;
    status = ninlil_model_reduce_admission_commit(&commit_in, &commit_out);
    if (status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime, admitted_transaction, mfdt_prearmed_slots,
            mfdt_prearmed_count, status, out_result);
#else
        return status;
#endif
    }
    if (commit_out.api_status != NINLIL_OK) {
        (void)storage->rollback(storage->user, txn);
        *out_result = commit_out.public_result;
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime, admitted_transaction, mfdt_prearmed_slots,
            mfdt_prearmed_count, commit_out.api_status, out_result);
#else
        return commit_out.api_status;
#endif
    }

    fire_admission_hook(runtime, "admission.before_full_commit");
    status = storage_txn_commit_full(runtime, txn);
    fire_admission_hook(runtime, "admission.after_full_commit");
    if (status != NINLIL_OK) {
#if defined(NINLIL_MFDT_V1_PRIVATE)
        return finish_mfdt_prearmed_failure(
            runtime, admitted_transaction, mfdt_prearmed_slots,
            mfdt_prearmed_count, status, out_result);
#else
        return status;
#endif
    }

    runtime->transaction_sequence =
        admitted_transaction->transaction_sequence;
    runtime->transaction_count += 1u;
    runtime->nonterminal_transaction_count += 1u;
    runtime->resource_ledger =
        preflight_out.admission.resources.committed_ledger;
    slot->quota_inflight = preflight_out.admission.quota.next_inflight_count;
    slot->quota_admissions =
        preflight_out.admission.quota.next_admissions_in_window;
    slot->quota_payload_bytes =
        preflight_out.admission.quota.next_payload_bytes_in_window;
    (void)memcpy(
        slot->quota_window_epoch,
        preflight_out.admission.quota.clock_epoch_id.bytes,
        sizeof(slot->quota_window_epoch));
    slot->quota_window_start_ms =
        preflight_out.admission.quota.window_started_at_ms;

    *txn_slot = *admitted_transaction;
    runtime->pending_work = 1u;

#if defined(NINLIL_MFDT_V1_PRIVATE)
    /*
     * Post-admission-FULL (only after durable admit OK): in-RAM family scope.
     * Runtime-owner sender open already succeeded pre-commit (NM3S durable).
     * Family begin
     * failure must NOT rewrite public result to REJECTED while the admitted
     * TX remains durable.
     *
     * Exact post-commit outcome:
     *   result  = ADMITTED_READY (from commit_out; never REJECT here)
     *   TX slot = durable ADMITTED_READY + pending_work
     *   MFDT    = Runtime-owner sidecar retains sender custody in NM3S
     *   family  = best-effort; on fail: HEALTH_DEGRADED + CAPACITY_UNAVAILABLE
     * Recovery / restart is owned by the same Runtime sidecar configuration;
     * this slice does not claim cross-store orphan reconciliation.
     */
    if (admitted_transaction->bearer_route
        == (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1) {
        if (ninlil_rt_v1_family_bounded_transfer_begin(
                ninlil_rt_v1_family_workspace(runtime),
                &admitted_transaction->transaction_id,
                admitted_transaction->payload_length == 0u
                    ? 1u
                    : admitted_transaction->payload_length) == 0) {
            /* Keep ADMITTED_READY; fence health only — no false reject. */
            runtime->health = NINLIL_HEALTH_DEGRADED;
            runtime->degraded_reason = NINLIL_REASON_CAPACITY_UNAVAILABLE;
        }
    }
#endif

    *out_result = commit_out.public_result;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_spine_cancel_admission(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id,
    ninlil_cancel_result_t *out_result)
{
    ninlil_rt_transaction_slot_t *txn;
    ninlil_rt_transaction_slot_t *candidate;
    int terminalized;
    ninlil_status_t status;
    uint32_t target_index;

    if (runtime == NULL || transaction_id == NULL || out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    txn = ninlil_rt_find_transaction(runtime, transaction_id);
    if (txn == NULL) {
        return NINLIL_E_NOT_FOUND;
    }
    if (txn->family != NINLIL_FAMILY_DESIRED_STATE) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (txn->cancel_kind != 0u) {
        out_result->kind = txn->cancel_kind;
        out_result->reason = txn->reason;
        out_result->current_outcome = txn->outcome;
        return NINLIL_OK;
    }
    if (txn->terminal != 0u) {
        out_result->kind = NINLIL_CANCEL_ALREADY_TERMINAL;
        out_result->reason = txn->reason;
        out_result->current_outcome = txn->outcome;
        return NINLIL_OK;
    }

    candidate = &runtime->transaction_scratch;
    *candidate = *txn;
    terminalized = 1;
    for (target_index = 0u;
         target_index < candidate->bound_target_count;
         ++target_index) {
        const ninlil_rt_target_slot_t *target =
            &candidate->bound_targets[target_index];

        if (target->in_use == 0u || target->terminal != 0u
            || target->cumulative_attempts != 0u
            || target->send_observation_closed != 0u
            || target->latest_evidence != NINLIL_EVIDENCE_NONE) {
            terminalized = 0;
            break;
        }
    }
    if (terminalized != 0) {
        for (target_index = 0u;
             target_index < candidate->bound_target_count;
             ++target_index) {
            ninlil_rt_target_slot_t *target =
                &candidate->bound_targets[target_index];

            target->terminal = 1u;
            target->pending_dispatch = 0u;
            target->attempt_prepared = 0u;
            (void)memset(
                &target->active_attempt_id,
                0,
                sizeof(target->active_attempt_id));
            target->send_observation_closed = 0u;
            target->send_observed_at_ms = 0u;
            (void)memset(
                &target->send_observed_clock_epoch_id,
                0,
                sizeof(target->send_observed_clock_epoch_id));
            target->next_retry_ms = 0u;
            (void)memset(
                &target->next_retry_clock_epoch_id,
                0,
                sizeof(target->next_retry_clock_epoch_id));
            target->delivery_phase = NINLIL_RT_DELIVERY_OUTCOME;
            target->outcome =
                NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT;
            target->reason =
                NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH;
        }
        candidate->active_target_index =
            NINLIL_RT_V1_NO_ACTIVE_TARGET;
        candidate->attempt_prepared = 0u;
        (void)memset(
            &candidate->attempt_id,
            0,
            sizeof(candidate->attempt_id));
        ninlil_rt_v1_refresh_target_aggregate(candidate);
        candidate->cancel_kind = NINLIL_CANCEL_FENCED_BEFORE_DISPATCH;
        candidate->reason = NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH;
        candidate->outcome = NINLIL_OUTCOME_CANCELLED_BEFORE_EFFECT;
    } else {
        candidate->cancel_kind = NINLIL_CANCEL_PENDING_REMOTE_FENCE;
        candidate->reason = NINLIL_REASON_CANCEL_PENDING_REMOTE_FENCE;
        candidate->outcome = NINLIL_OUTCOME_NONE;
    }

    status = ninlil_rt_v1_commit_transaction_snapshot(
        runtime,
        txn,
        candidate,
        NINLIL_RT_V1_MARKER_CN,
        NINLIL_V1_DURABLE_OP_CANCEL_ADMISSION_COMMIT);
    if (status != NINLIL_OK) {
        return status;
    }
    if (terminalized != 0) {
        runtime->nonterminal_transaction_count -= 1u;
    }

    out_result->kind = txn->cancel_kind;
    out_result->reason = txn->reason;
    out_result->current_outcome = txn->outcome;
    return NINLIL_OK;
}

ninlil_status_t ninlil_rt_v1_map_read_classify(
    ninlil_runtime_t *runtime,
    const ninlil_rt_service_slot_t *slot,
    const ninlil_submission_t *submission,
    const ninlil_digest256_t *canonical_digest,
    const ninlil_id128_t *proposed_txn_id,
    ninlil_rt_v1_map_truth_class_t *out_class)
{
    ninlil_model_mapping_fact_t key_map;
    ninlil_model_mapping_fact_t event_map;
    int key_present;
    int key_proposed;
    int tx_present;
    const ninlil_rt_transaction_slot_t *txn;

    if (out_class == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_class = NINLIL_RT_V1_MAP_TRUTH_CORRUPT;
    if (runtime == NULL || slot == NULL || submission == NULL
        || canonical_digest == NULL || proposed_txn_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    lookup_caller_key_mapping(
        runtime, slot, submission, canonical_digest, &key_map);
    if (key_map.state == NINLIL_MODEL_MAPPING_STORAGE_FAILURE) {
        *out_class = NINLIL_RT_V1_MAP_TRUTH_CORRUPT;
        return key_map.failure_status != NINLIL_OK
            ? key_map.failure_status
            : NINLIL_E_STORAGE_CORRUPT;
    }

    key_present = key_map.state != NINLIL_MODEL_MAPPING_ABSENT;
    key_proposed = key_map.state == NINLIL_MODEL_MAPPING_MATCH
        && memcmp(
               key_map.existing.transaction_id.bytes,
               proposed_txn_id->bytes,
               16u)
            == 0;

    txn = ninlil_rt_find_transaction(runtime, proposed_txn_id);
    tx_present = txn != NULL && txn->origin_admission != 0u;

    if (slot->model_service.family == NINLIL_FAMILY_EVENT_FACT) {
        lookup_event_id_mapping(
            runtime, slot, submission, canonical_digest, &event_map);
        if (event_map.state == NINLIL_MODEL_MAPPING_STORAGE_FAILURE) {
            *out_class = NINLIL_RT_V1_MAP_TRUTH_CORRUPT;
            return event_map.failure_status != NINLIL_OK
                ? event_map.failure_status
                : NINLIL_E_STORAGE_CORRUPT;
        }
        if (key_present != (event_map.state != NINLIL_MODEL_MAPPING_ABSENT)) {
            *out_class = NINLIL_RT_V1_MAP_TRUTH_MIXED;
            return NINLIL_OK;
        }
        if (key_present != 0
            && memcmp(
                   key_map.existing.transaction_id.bytes,
                   event_map.existing.transaction_id.bytes,
                   16u)
                != 0) {
            *out_class = NINLIL_RT_V1_MAP_TRUTH_MIXED;
            return NINLIL_OK;
        }
    }

    if (!key_present && !tx_present) {
        *out_class = NINLIL_RT_V1_MAP_TRUTH_ABSENT;
        return NINLIL_OK;
    }
    if (key_present && tx_present && key_proposed) {
        /*
         * BOTH requires map and TX to agree on canonical digest.  A third
         * durable value (map digest != TX digest for same id) is THIRD.
         */
        if (digest_equal_ct(
                &key_map.existing.canonical_submission_digest,
                &txn->canonical_submission_digest)) {
            *out_class = NINLIL_RT_V1_MAP_TRUTH_BOTH;
        } else {
            *out_class = NINLIL_RT_V1_MAP_TRUTH_THIRD;
        }
        return NINLIL_OK;
    }
    if (key_present && !tx_present && key_proposed) {
        *out_class = NINLIL_RT_V1_MAP_TRUTH_PROPOSED;
        return NINLIL_OK;
    }
    if (!key_present && tx_present) {
        *out_class = NINLIL_RT_V1_MAP_TRUTH_MIXED;
        return NINLIL_OK;
    }
    if (key_present && !key_proposed) {
        if (tx_present) {
            *out_class = NINLIL_RT_V1_MAP_TRUTH_MIXED;
        } else {
            *out_class = NINLIL_RT_V1_MAP_TRUTH_OLD;
        }
        return NINLIL_OK;
    }
    *out_class = NINLIL_RT_V1_MAP_TRUTH_CORRUPT;
    return NINLIL_OK;
}
