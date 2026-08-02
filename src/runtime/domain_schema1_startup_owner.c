/*
 * ADR-0022 Canonical Domain schema1 startup owner (HOST_CANDIDATE).
 * Real storage_ops. Feature-gated. No public ABI.
 */

#include "domain_schema1_startup_owner.h"

#include <string.h>

#if !defined(NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING) \
    || (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING == 0)
#error "domain_schema1_startup_owner.c requires feature ON"
#endif

static void fence_handle(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_schema1_owner_result_t *result)
{
    if (storage != NULL && inout_handle != NULL && *inout_handle != NULL
        && storage->close != NULL) {
        storage->close(storage->user, *inout_handle);
        *inout_handle = NULL;
    }
    if (result != NULL) {
        result->reopen_required = 1u;
        result->outcome = NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_FENCED;
    }
}

static ninlil_status_t map_storage(ninlil_storage_status_t st)
{
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_OK;
    }
    if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_E_NOT_FOUND;
    }
    if (st == NINLIL_STORAGE_CORRUPT) {
        { return NINLIL_E_STORAGE_CORRUPT; }
    }
    return NINLIL_E_STORAGE;
}

static int nonzero_16(const uint8_t value[16])
{
    uint32_t i;

    if (value == NULL) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        if (value[i] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int trusted_sample_valid(const ninlil_time_sample_t *sample)
{
    return sample != NULL
        && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size == sizeof(*sample)
        && sample->trust == NINLIL_CLOCK_TRUSTED
        && sample->reserved_zero == 0u
        && nonzero_16(sample->clock_epoch_id.bytes);
}

static void fill_binding_identity(
    const ninlil_model_runtime_validation_result_t *validation,
    ninlil_domain_schema1_binding_t *binding,
    ninlil_model_runtime_store_identity_t *identity)
{
    const ninlil_model_runtime_config_projection_t *cfg =
        &validation->accepted_config;
    uint32_t i;

    (void)memset(binding, 0, sizeof(*binding));
    (void)memset(identity, 0, sizeof(*identity));

    binding->common.storage_schema = NINLIL_DOMAIN_SCHEMA1_STORAGE_SCHEMA;
    binding->common.role = cfg->role;
    binding->common.environment = cfg->environment;
    binding->common.runtime_id = cfg->runtime_id;
    binding->common.limits.max_services = cfg->limits.max_services;
    binding->common.limits.max_nonterminal_transactions =
        cfg->limits.max_nonterminal_transactions;
    binding->common.limits.max_targets_per_transaction =
        cfg->limits.max_targets_per_transaction;
    binding->common.limits.max_logical_payload_bytes =
        cfg->limits.max_logical_payload_bytes;
    binding->common.limits.max_durable_outbox_payload_bytes =
        cfg->limits.max_durable_outbox_payload_bytes;
    binding->common.limits.max_attempts_per_target_per_cycle =
        cfg->limits.max_attempts_per_target_per_cycle;
    binding->common.limits.max_cancel_attempts_per_transaction =
        cfg->limits.max_cancel_attempts_per_transaction;
    binding->common.limits.max_evidence_per_target =
        cfg->limits.max_evidence_per_target;
    binding->common.limits.max_retained_terminal_transactions =
        cfg->limits.max_retained_terminal_transactions;
    binding->common.limits.max_nonterminal_deliveries =
        cfg->limits.max_nonterminal_deliveries;
    binding->common.limits.max_event_spool_count =
        cfg->limits.max_event_spool_count;
    binding->common.limits.max_event_spool_bytes =
        cfg->limits.max_event_spool_bytes;
    binding->common.limits.max_result_cache_entries =
        cfg->limits.max_result_cache_entries;
    binding->common.limits.max_retained_dispositions =
        cfg->limits.max_retained_dispositions;
    binding->common.limits.max_ingress_per_step =
        cfg->limits.max_ingress_per_step;
    binding->common.limits.max_callbacks_per_step =
        cfg->limits.max_callbacks_per_step;
    binding->common.limits.max_state_transitions_per_step =
        cfg->limits.max_state_transitions_per_step;
    binding->common.limits.max_bearer_sends_per_step =
        cfg->limits.max_bearer_sends_per_step;
    binding->common.limits.max_deferred_tokens =
        cfg->limits.max_deferred_tokens;
    binding->common.terminal_retention_ms = cfg->terminal_retention_ms;
    binding->common.result_cache_retention_ms = cfg->result_cache_retention_ms;
    binding->common.observation_retention_ms = cfg->observation_retention_ms;
    (void)memcpy(
        binding->storage_profile_id, "NINLIL-DOMAIN-S1", 16u);
    binding->storage_profile_revision =
        NINLIL_DOMAIN_SCHEMA1_STORAGE_PROFILE_REVISION;
    binding->minimum_writer_generation =
        NINLIL_DOMAIN_SCHEMA1_MINIMUM_WRITER_GENERATION;
    binding->rollback_epoch = NINLIL_DOMAIN_SCHEMA1_ROLLBACK_EPOCH;

    identity->flags = cfg->identity_flags;
    identity->device_id = cfg->device_id;
    identity->installation_id = cfg->installation_id;
    identity->site_domain_id = cfg->site_domain_id;
    identity->binding_epoch = cfg->binding_epoch;
    identity->membership_epoch = cfg->membership_epoch;
    (void)i;
}

static ninlil_status_t scan_namespace(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    ninlil_domain_schema1_owner_workspace_t *ws,
    uint32_t *out_count,
    int read_only)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t prefix = {NULL, 0u};
    uint32_t count = 0u;

    *out_count = 0u;
    ws->snap_count = 0u;
    st = storage->begin(
        storage->user,
        handle,
        read_only != 0 ? NINLIL_STORAGE_READ_ONLY
                       : NINLIL_STORAGE_READ_WRITE,
        &txn);
    if (st != NINLIL_STORAGE_OK) {
        return map_storage(st);
    }
    st = storage->iter_open(storage->user, txn, prefix, &iter);
    if (st != NINLIL_STORAGE_OK) {
        (void)storage->rollback(storage->user, txn);
        return map_storage(st);
    }
    for (;;) {
        ninlil_mut_bytes_t k;
        ninlil_mut_bytes_t v;
        k.data = ws->scan_key;
        k.capacity = sizeof(ws->scan_key);
        k.length = 0u;
        v.data = ws->scan_value;
        v.capacity = sizeof(ws->scan_value);
        v.length = 0u;
        st = storage->iter_next(storage->user, iter, &k, &v);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            { return NINLIL_E_STORAGE_CORRUPT; }
        }
        if (st != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return map_storage(st);
        }
        /*
         * ADR-0022 namespace quarantine: a Domain schema1 owner never adopts
         * a namespace that also contains V1-LAB operational records.
         */
        if (ninlil_domain_schema1_is_lab_operational_key(k.data, k.length)
            != 0) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (count >= NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP) {
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            { return NINLIL_E_STORAGE_CORRUPT; }
        }
        if (k.length > NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP
            || v.length > NINLIL_DOMAIN_SCHEMA1_OWNER_SNAP_VALUE_CAP) {
            /* Domain T1a/T1b CU path only materializes bounded rows. */
            storage->iter_close(storage->user, iter);
            (void)storage->rollback(storage->user, txn);
            { return NINLIL_E_STORAGE_CORRUPT; }
        }
        (void)memcpy(ws->snap_key[count], k.data, k.length);
        ws->snap_key_len[count] = k.length;
        (void)memcpy(ws->snap_value[count], v.data, v.length);
        ws->snap_value_len[count] = v.length;
        ws->snapshot_rows[count].key.data = ws->snap_key[count];
        ws->snapshot_rows[count].key.length = k.length;
        ws->snapshot_rows[count].value.data = ws->snap_value[count];
        ws->snapshot_rows[count].value.length = v.length;
        count += 1u;
    }
    storage->iter_close(storage->user, iter);
    (void)storage->rollback(storage->user, txn);
    ws->snap_count = count;
    *out_count = count;
    return NINLIL_OK;
}

/*
 * Locate and D1-validate the singleton CLOCK_BASELINE in the current
 * materialized snapshot.  Returning "some non-old bytes" as TRUSTED is not
 * sufficient: key/envelope/body/revision/CRC/state must all be canonical.
 */
static ninlil_status_t decode_snapshot_clock(
    ninlil_domain_schema1_owner_workspace_t *ws,
    const ninlil_domain_schema1_t5_clock_plan_t *key_plan,
    uint32_t *out_row_index)
{
    uint32_t i;
    uint32_t found = 0u;

    if (ws == NULL || key_plan == NULL || out_row_index == NULL
        || key_plan->clock_key_length == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_row_index = 0u;
    (void)memset(&ws->typed_record, 0, sizeof(ws->typed_record));
    for (i = 0u; i < ws->snap_count; ++i) {
        if (ws->snap_key_len[i] != key_plan->clock_key_length
            || memcmp(
                   ws->snap_key[i],
                   key_plan->clock_key,
                   key_plan->clock_key_length)
                != 0) {
            continue;
        }
        found += 1u;
        if (found != 1u) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ninlil_model_domain_validate_typed_record(
                (ninlil_bytes_view_t){
                    ws->snap_key[i], ws->snap_key_len[i]},
                (ninlil_bytes_view_t){
                    ws->snap_value[i], ws->snap_value_len[i]},
                &ws->typed_record)
                != NINLIL_OK
            || ws->typed_record.family
                != NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN
            || ws->typed_record.subtype
                != NINLIL_MODEL_DOMAIN_SUBTYPE_CLOCK_BASELINE) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        *out_row_index = i;
    }
    return found == 1u ? NINLIL_OK : NINLIL_E_STORAGE_CORRUPT;
}

/*
 * Canonical apply requires capacity.used_entries == begin_view.row_count
 * and used_bytes == begin logical bytes. begin_rows must describe the full
 * pre-mutation namespace; final_rows the full post-mutation namespace.
 */
static ninlil_status_t full_apply_transition(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    const ninlil_storage_canonical_row_t *begin_rows,
    uint32_t begin_count,
    const ninlil_storage_canonical_row_t *final_rows,
    uint32_t final_count,
    ninlil_domain_schema1_owner_result_t *result)
{
    ninlil_storage_canonical_view_t begin_view;
    ninlil_storage_canonical_view_t final_view;
    ninlil_storage_canonical_result_t apply;
    ninlil_storage_status_t st;

    begin_view.rows = begin_rows;
    begin_view.row_count = begin_count;
    final_view.rows = final_rows;
    final_view.row_count = final_count;
    (void)memset(&apply, 0, sizeof(apply));
    st = ninlil_storage_canonical_apply(
        storage, handle, begin_view, final_view, NULL, NULL, &apply);
    result->cleanup_status = apply.cleanup_status;
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_OK;
    }
    if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (apply.fence_required != 0u) {
        { return NINLIL_E_STORAGE_CORRUPT; }
    }
    return map_storage(st);
}

static ninlil_status_t materialize_boot_rows(
    ninlil_domain_schema1_owner_workspace_t *ws,
    uint32_t *out_count)
{
    uint32_t i;
    ninlil_status_t st;
    for (i = 0u; i < NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT; ++i) {
        st = ninlil_domain_schema1_bootstrap_record_at(
            &ws->boot_plan, i, &ws->boot_records[i]);
        if (st != NINLIL_OK) {
            return st;
        }
        ws->apply_rows[i].key.data = ws->boot_records[i].key.bytes;
        ws->apply_rows[i].key.length = ws->boot_records[i].key.length;
        ws->apply_rows[i].value.data = ws->boot_records[i].value;
        ws->apply_rows[i].value.length = ws->boot_records[i].value_length;
    }
    *out_count = NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT;
    return NINLIL_OK;
}

static ninlil_status_t materialize_meta_rows(
    ninlil_domain_schema1_owner_workspace_t *ws,
    uint32_t base,
    uint32_t *out_count)
{
    uint32_t i;
    ninlil_status_t st;
    for (i = 0u; i < NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT; ++i) {
        st = ninlil_domain_schema1_metadata_record_at(
            &ws->meta_plan, i, &ws->meta_records[i]);
        if (st != NINLIL_OK) {
            return st;
        }
        ws->apply_rows[base + i].key.data = ws->meta_records[i].key;
        ws->apply_rows[base + i].key.length = ws->meta_records[i].key_length;
        ws->apply_rows[base + i].value.data = ws->meta_records[i].value;
        ws->apply_rows[base + i].value.length =
            ws->meta_records[i].value_length;
    }
    *out_count = NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT;
    return NINLIL_OK;
}

static int keys_sorted_unique(
    const ninlil_storage_canonical_row_t *rows,
    uint32_t count)
{
    uint32_t i;
    for (i = 1u; i < count; ++i) {
        uint32_t a = rows[i - 1u].key.length;
        uint32_t b = rows[i].key.length;
        uint32_t n = a < b ? a : b;
        int cmp = memcmp(rows[i - 1u].key.data, rows[i].key.data, n);
        if (cmp > 0 || (cmp == 0 && a >= b)) {
            return 0;
        }
    }
    return 1;
}

/* Insertion-sort apply_rows[0..count) by key (workspace-local, no large stack). */
static void sort_apply_rows(
    ninlil_storage_canonical_row_t *rows,
    uint32_t count)
{
    uint32_t i;
    uint32_t j;
    for (i = 1u; i < count; ++i) {
        ninlil_storage_canonical_row_t key = rows[i];
        j = i;
        while (j > 0u) {
            uint32_t a = rows[j - 1u].key.length;
            uint32_t b = key.key.length;
            uint32_t n = a < b ? a : b;
            int cmp = memcmp(rows[j - 1u].key.data, key.key.data, n);
            if (cmp < 0 || (cmp == 0 && a <= b)) {
                break;
            }
            rows[j] = rows[j - 1u];
            j -= 1u;
        }
        rows[j] = key;
    }
}

/*
 * ADR-0022 D22-02: the authoritative T0 empty observation and the T1a
 * bootstrap CREATE are one RW transaction.  A second canonical-apply
 * transaction would leave a race between "observed empty" and the 17 puts.
 *
 * Non-empty namespaces are never adopted from this mutable snapshot: this
 * helper rolls the RW transaction back and the caller obtains a fresh RO
 * snapshot before any existing-state classification.
 */
static ninlil_status_t t0_scan_and_create_t1a_same_rw(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    ninlil_domain_schema1_owner_workspace_t *ws,
    uint32_t *out_row_count,
    uint32_t *out_wrote,
    ninlil_domain_schema1_owner_result_t *result)
{
    ninlil_storage_capacity_t capacity;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_storage_status_t sst;
    ninlil_bytes_view_t prefix = {NULL, 0u};
    uint32_t count = 0u;
    uint32_t boot_n = 0u;
    uint32_t i;
    uint64_t final_bytes = 0u;

    *out_row_count = 0u;
    *out_wrote = 0u;
    ws->snap_count = 0u;

    if (storage->capacity == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    sst = storage->capacity(storage->user, handle, &capacity);
    if (sst != NINLIL_STORAGE_OK) {
        return map_storage(sst);
    }
    if (capacity.abi_version != NINLIL_ABI_VERSION
        || capacity.struct_size != sizeof(capacity)
        || capacity.max_entries == 0u || capacity.max_bytes == 0u
        || capacity.used_entries > capacity.max_entries
        || capacity.used_bytes > capacity.max_bytes) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    if (materialize_boot_rows(ws, &boot_n) != NINLIL_OK
        || boot_n != NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    sort_apply_rows(ws->apply_rows, boot_n);
    if (!keys_sorted_unique(ws->apply_rows, boot_n)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    for (i = 0u; i < boot_n; ++i) {
        uint64_t row_bytes = UINT64_C(16)
            + ws->apply_rows[i].key.length
            + ws->apply_rows[i].value.length;
        if (final_bytes > UINT64_MAX - row_bytes) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        final_bytes += row_bytes;
    }

    sst = storage->begin(
        storage->user, handle, NINLIL_STORAGE_READ_WRITE, &txn);
    if ((sst == NINLIL_STORAGE_OK) != (txn != NULL)) {
        if (txn != NULL) {
            result->cleanup_status =
                storage->rollback(storage->user, txn);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (sst != NINLIL_STORAGE_OK) {
        return map_storage(sst);
    }
    sst = storage->iter_open(storage->user, txn, prefix, &iter);
    if ((sst == NINLIL_STORAGE_OK) != (iter != NULL)) {
        if (iter != NULL) {
            storage->iter_close(storage->user, iter);
        }
        result->cleanup_status = storage->rollback(storage->user, txn);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (sst != NINLIL_STORAGE_OK) {
        result->cleanup_status = storage->rollback(storage->user, txn);
        return map_storage(sst);
    }

    for (;;) {
        ninlil_mut_bytes_t key = {
            ws->scan_key, sizeof(ws->scan_key), 0u};
        ninlil_mut_bytes_t value = {
            ws->scan_value, sizeof(ws->scan_value), 0u};
        sst = storage->iter_next(
            storage->user, iter, &key, &value);
        if (sst == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (sst != NINLIL_STORAGE_OK) {
            storage->iter_close(storage->user, iter);
            result->cleanup_status = storage->rollback(storage->user, txn);
            return sst == NINLIL_STORAGE_BUFFER_TOO_SMALL
                ? NINLIL_E_STORAGE_CORRUPT : map_storage(sst);
        }
        if (ninlil_domain_schema1_is_lab_operational_key(
                key.data, key.length)
            != 0
            || count >= NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP
            || key.length > NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP
            || value.length > NINLIL_DOMAIN_SCHEMA1_OWNER_SNAP_VALUE_CAP) {
            storage->iter_close(storage->user, iter);
            result->cleanup_status = storage->rollback(storage->user, txn);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        count += 1u;
    }
    storage->iter_close(storage->user, iter);
    iter = NULL;
    *out_row_count = count;

    if (count != 0u) {
        result->cleanup_status = storage->rollback(storage->user, txn);
        if (result->cleanup_status != NINLIL_STORAGE_OK) {
            return NINLIL_E_STORAGE_CORRUPT;
        }
        return NINLIL_OK;
    }
    if (capacity.used_entries != 0u || capacity.used_bytes != 0u) {
        result->cleanup_status = storage->rollback(storage->user, txn);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if ((uint64_t)boot_n > capacity.max_entries
        || final_bytes > capacity.max_bytes) {
        result->cleanup_status = storage->rollback(storage->user, txn);
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    for (i = 0u; i < boot_n; ++i) {
        sst = storage->put(
            storage->user,
            txn,
            ws->apply_rows[i].key,
            ws->apply_rows[i].value);
        if (sst != NINLIL_STORAGE_OK) {
            result->cleanup_status = storage->rollback(storage->user, txn);
            return map_storage(sst);
        }
    }
    sst = storage->commit(
        storage->user, txn, NINLIL_DURABILITY_FULL);
    if (sst == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (sst != NINLIL_STORAGE_OK) {
        return map_storage(sst);
    }
    *out_wrote = 1u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_owner_run_storage_recovery(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_model_runtime_validation_result_t *validation,
    const ninlil_time_sample_t *trusted_sample_or_null,
    ninlil_domain_schema1_owner_workspace_t *workspace,
    ninlil_domain_schema1_owner_result_t *out_result)
{

    ninlil_status_t st;
    uint32_t row_count = 0u;
    uint32_t n = 0u;
    uint32_t t0_wrote = 0u;
    ninlil_domain_schema1_t1a_class_t t1a;
    ninlil_domain_schema1_group_class_t t1b;
    ninlil_domain_schema1_group_class_t t5c;
    ninlil_domain_schema1_lab_namespace_class_t lab;

    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->t1a_class = NINLIL_DOMAIN_SCHEMA1_T1A_CORRUPT;
    out_result->t1b_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    out_result->t5_class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    out_result->lab_class = NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT;

    if (storage == NULL || inout_handle == NULL || *inout_handle == NULL
        || validation == NULL || validation->status != NINLIL_OK
        || workspace == NULL
        || storage->begin == NULL || storage->put == NULL
        || storage->commit == NULL || storage->rollback == NULL
        || storage->iter_open == NULL || storage->iter_next == NULL
        || storage->iter_close == NULL || storage->close == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    (void)memset(workspace, 0, sizeof(*workspace));
    fill_binding_identity(validation, &workspace->binding, &workspace->identity);
    st = ninlil_domain_schema1_validate_binding(&workspace->binding);
    if (st != NINLIL_OK) {
        out_result->status = st;
        out_result->outcome = NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_FENCED;
        return st;
    }
    st = ninlil_domain_schema1_validate_identity(&workspace->identity);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = ninlil_domain_schema1_build_bootstrap_plan(
        &workspace->binding, &workspace->identity, &workspace->boot_plan);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = ninlil_domain_schema1_build_metadata_plan(
        &workspace->boot_plan, &workspace->meta_plan);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = ninlil_domain_schema1_startup_init(&workspace->stages);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }

    /*
     * --- T0/T1a NEW seam ---
     * Empty scan and the 17-row CREATE are one RW transaction.  Existing
     * state is routed to a fresh RO scan below before classification.
     */
    st = t0_scan_and_create_t1a_same_rw(
        storage,
        *inout_handle,
        workspace,
        &row_count,
        &t0_wrote,
        out_result);
    if (st != NINLIL_OK) {
        if (st == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
            fence_handle(storage, inout_handle, out_result);
            out_result->outcome =
                NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_COMMIT_UNKNOWN;
        }
        out_result->status = st;
        return st;
    }

    if (t0_wrote != 0u) {
        uint32_t boot_n = NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT;
        uint32_t meta_n = 0u;
        /* T0 and T1a are complete only after the same-RW FULL commit. */
        st = ninlil_domain_schema1_startup_complete_stage(
            &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T0);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        out_result->wrote_t1a = 1u;
        st = ninlil_domain_schema1_startup_complete_stage(
            &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T1A);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }

        /* T1b: begin=17 bootstrap, final=17+16 metadata (full post view). */
        st = materialize_meta_rows(workspace, boot_n, &meta_n);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        n = boot_n + meta_n;
        sort_apply_rows(workspace->apply_rows, n);
        /* begin rows: re-materialize bootstrap only into snap for begin view. */
        {
            ninlil_storage_canonical_row_t begin_rows[
                NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT];
            uint32_t bi;
            for (bi = 0u; bi < boot_n; ++bi) {
                begin_rows[bi].key.data = workspace->boot_records[bi].key.bytes;
                begin_rows[bi].key.length =
                    workspace->boot_records[bi].key.length;
                begin_rows[bi].value.data = workspace->boot_records[bi].value;
                begin_rows[bi].value.length =
                    workspace->boot_records[bi].value_length;
            }
            sort_apply_rows(begin_rows, boot_n);
            st = full_apply_transition(
                storage,
                *inout_handle,
                begin_rows,
                boot_n,
                workspace->apply_rows,
                n,
                out_result);
        }
        if (st == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
            fence_handle(storage, inout_handle, out_result);
            out_result->outcome =
                NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_COMMIT_UNKNOWN;
            out_result->status = st;
            return st;
        }
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        out_result->wrote_t1b = 1u;
        st = ninlil_domain_schema1_startup_complete_stage(
            &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T1B);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        out_result->outcome = NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_NEW_FULL;
        out_result->t1a_class = NINLIL_DOMAIN_SCHEMA1_T1A_NEW;
        out_result->t1b_class = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
    } else {
        /* EXISTING: binding+identity exact ⇒ T1a NEW (counters may have advanced). */
        ninlil_domain_schema1_bootstrap_record_t br_bind;
        ninlil_domain_schema1_bootstrap_record_t br_id;
        uint32_t sj;
        int bind_ok = 0;
        int id_ok = 0;

        /* Never classify the mutable T0 snapshot; adopt from fresh RO only. */
        st = scan_namespace(
            storage, *inout_handle, workspace, &row_count, 1);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        st = ninlil_domain_schema1_startup_complete_stage(
            &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T0);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }

        st = ninlil_domain_schema1_bootstrap_record_at(
            &workspace->boot_plan, 0u, &br_bind);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        st = ninlil_domain_schema1_bootstrap_record_at(
            &workspace->boot_plan, 1u, &br_id);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        for (sj = 0u; sj < workspace->snap_count; ++sj) {
            if (workspace->snapshot_rows[sj].key.length == br_bind.key.length
                && memcmp(
                       workspace->snapshot_rows[sj].key.data,
                       br_bind.key.bytes,
                       br_bind.key.length)
                    == 0
                && workspace->snapshot_rows[sj].value.length
                    == br_bind.value_length
                && memcmp(
                       workspace->snapshot_rows[sj].value.data,
                       br_bind.value,
                       br_bind.value_length)
                    == 0) {
                bind_ok = 1;
            }
            if (workspace->snapshot_rows[sj].key.length == br_id.key.length
                && memcmp(
                       workspace->snapshot_rows[sj].key.data,
                       br_id.key.bytes,
                       br_id.key.length)
                    == 0
                && workspace->snapshot_rows[sj].value.length
                    == br_id.value_length
                && memcmp(
                       workspace->snapshot_rows[sj].value.data,
                       br_id.value,
                       br_id.value_length)
                    == 0) {
                id_ok = 1;
            }
        }
        if (bind_ok == 0 || id_ok == 0) {
            out_result->t1a_class = NINLIL_DOMAIN_SCHEMA1_T1A_CORRUPT;
            out_result->status = NINLIL_E_STORAGE_CORRUPT;
            out_result->outcome = NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_FENCED;
            { return NINLIL_E_STORAGE_CORRUPT; }
        }
        t1a = NINLIL_DOMAIN_SCHEMA1_T1A_NEW;
        out_result->t1a_class = t1a;
        st = ninlil_domain_schema1_startup_complete_stage(
            &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T1A);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }

        st = ninlil_domain_schema1_classify_t1b_commit_unknown(
            &workspace->boot_plan,
            &workspace->meta_plan,
            workspace->snapshot_rows,
            workspace->snap_count,
            &t1b);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        out_result->t1b_class = t1b;
        if (t1b == NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT) {
            /*
             * Post-T5 / post-kind1: clock TRUSTED and capacity may advance, so
             * T1b exact-UNINITIALIZED fails. Require accepted semantic adopt
             * (every row D1-current + binding/identity exact) — no count-only.
             */
            ninlil_domain_schema1_group_class_t adopt =
                NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
            st = ninlil_domain_schema1_classify_existing_namespace_adopt(
                &workspace->boot_plan,
                workspace->snapshot_rows,
                workspace->snap_count,
                &adopt);
            if (st != NINLIL_OK
                || adopt != NINLIL_DOMAIN_SCHEMA1_GROUP_NEW) {
                out_result->status = NINLIL_E_STORAGE_CORRUPT;
                { return NINLIL_E_STORAGE_CORRUPT; }
            }
            t1b = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
            out_result->t1b_class = t1b;
        }
        if (t1b == NINLIL_DOMAIN_SCHEMA1_GROUP_OLD) {
            uint32_t boot_n = 0u;
            uint32_t meta_n = 0u;
            ninlil_storage_canonical_row_t begin_rows[
                NINLIL_DOMAIN_SCHEMA1_BOOTSTRAP_RECORD_COUNT];
            uint32_t bi;
            /* T1a NEW + T1b OLD: begin=17, final=33. */
            st = materialize_boot_rows(workspace, &boot_n);
            if (st != NINLIL_OK) {
                out_result->status = st;
                return st;
            }
            for (bi = 0u; bi < boot_n; ++bi) {
                begin_rows[bi] = workspace->apply_rows[bi];
            }
            st = materialize_meta_rows(workspace, boot_n, &meta_n);
            if (st != NINLIL_OK) {
                out_result->status = st;
                return st;
            }
            n = boot_n + meta_n;
            sort_apply_rows(begin_rows, boot_n);
            sort_apply_rows(workspace->apply_rows, n);
            st = full_apply_transition(
                storage,
                *inout_handle,
                begin_rows,
                boot_n,
                workspace->apply_rows,
                n,
                out_result);
            if (st == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
                fence_handle(storage, inout_handle, out_result);
                out_result->outcome =
                    NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_COMMIT_UNKNOWN;
                out_result->status = st;
                return st;
            }
            if (st != NINLIL_OK) {
                out_result->status = st;
                return st;
            }
            out_result->wrote_t1b = 1u;
        }
        st = ninlil_domain_schema1_startup_complete_stage(
            &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T1B);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        out_result->outcome =
            NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_EXISTING_ADOPTED;
    }

    /*
     * --- T2 private scaffold ---
     * This validates the implemented bootstrap/metadata subset only. It does
     * not represent complete D3-S1..S12 composition and therefore cannot
     * authorize public Runtime publication while the readiness gate is 0u.
     */
    st = scan_namespace(storage, *inout_handle, workspace, &row_count, 1);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = ninlil_domain_schema1_classify_t1b_commit_unknown(
        &workspace->boot_plan,
        &workspace->meta_plan,
        workspace->snapshot_rows,
        workspace->snap_count,
        &t1b);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    if (t1b != NINLIL_DOMAIN_SCHEMA1_GROUP_NEW) {
        ninlil_domain_schema1_group_class_t adopt =
            NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
        st = ninlil_domain_schema1_classify_existing_namespace_adopt(
            &workspace->boot_plan,
            workspace->snapshot_rows,
            workspace->snap_count,
            &adopt);
        if (st != NINLIL_OK || adopt != NINLIL_DOMAIN_SCHEMA1_GROUP_NEW) {
            out_result->status = NINLIL_E_STORAGE_CORRUPT;
            { return NINLIL_E_STORAGE_CORRUPT; }
        }
    }
    /* LAB quarantine: format2 domain must not cohabit LAB-distinct evidence. */
    st = ninlil_domain_schema1_lab_classify_namespace(
        2u, 1u, 1u, 0u, 0u, 0u, 0u, &lab);
    if (st != NINLIL_OK
        || lab != NINLIL_DOMAIN_SCHEMA1_LAB_NS_EXACT_DOMAIN) {
        out_result->status = NINLIL_E_STORAGE_CORRUPT;
        { return NINLIL_E_STORAGE_CORRUPT; }
    }
    out_result->lab_class = lab;
    st = ninlil_domain_schema1_startup_complete_stage(
        &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T2);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }

    /* --- T3 private scaffold: bounded rescan fence (mutation 0 when clean) ---
     * Post-T1b baseline is 33 rows; post-kind1 (and later) namespaces grow.
     * Fence only requires the sealed bootstrap+metadata floor and ROW_CAP.
     * D4 recovery-item convergence is not implemented here. */
    st = scan_namespace(storage, *inout_handle, workspace, &row_count, 1);
    if (st != NINLIL_OK || row_count < 33u
        || row_count > NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP) {
        out_result->status =
            st != NINLIL_OK ? st : NINLIL_E_STORAGE_CORRUPT;
        return out_result->status;
    }
    st = ninlil_domain_schema1_startup_complete_stage(
        &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T3);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }

    /* --- T4: local identity exact match vs create config --- */
    {
        ninlil_domain_schema1_bootstrap_record_t id_rec;
        uint32_t i;
        int found = 0;
        st = ninlil_domain_schema1_bootstrap_record_at(
            &workspace->boot_plan, 1u, &id_rec);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        for (i = 0u; i < workspace->snap_count; ++i) {
            if (workspace->snapshot_rows[i].key.length == id_rec.key.length
                && memcmp(
                       workspace->snapshot_rows[i].key.data,
                       id_rec.key.bytes,
                       id_rec.key.length)
                    == 0
                && workspace->snapshot_rows[i].value.length
                    == id_rec.value_length
                && memcmp(
                       workspace->snapshot_rows[i].value.data,
                       id_rec.value,
                       id_rec.value_length)
                    == 0) {
                found = 1;
                break;
            }
        }
        if (found == 0) {
            out_result->status = NINLIL_E_CONFLICT;
            return NINLIL_E_CONFLICT;
        }
    }
    st = ninlil_domain_schema1_startup_complete_stage(
        &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T4);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }

    /* --- T5: trusted clock FULL / exact existing-clock validation --- */
    st = ninlil_domain_schema1_startup_complete_stage(
        &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T5_SAMPLE);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    if (trusted_sample_or_null == NULL
        || trusted_sample_or_null->trust != NINLIL_CLOCK_TRUSTED) {
        out_result->status = NINLIL_E_CLOCK_UNCERTAIN;
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (!trusted_sample_valid(trusted_sample_or_null)) {
        out_result->status = NINLIL_E_DEGRADED;
        return NINLIL_E_DEGRADED;
    }
    (void)memcpy(
        workspace->trusted_epoch,
        trusted_sample_or_null->clock_epoch_id.bytes,
        16u);
    workspace->trusted_now_ms = trusted_sample_or_null->now_ms;

    /*
     * Generation 1 is first built as a sealed key authority.  If the durable
     * clock is already TRUSTED and a new epoch is observed, the plan is
     * rebuilt below with checked publish_generation+1.
     */
    st = ninlil_domain_schema1_build_t5_clock_plan(
        workspace->trusted_epoch,
        workspace->trusted_now_ms,
        1u,
        &workspace->t5_plan);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = scan_namespace(storage, *inout_handle, workspace, &row_count, 1);
    if (st != NINLIL_OK || row_count == 0u
        || row_count > NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP) {
        out_result->status =
            st != NINLIL_OK ? st : NINLIL_E_STORAGE_CORRUPT;
        return out_result->status;
    }
    {
        uint32_t clock_row = 0u;
        uint64_t next_generation = 0u;
        int transition_required = 0;
        ninlil_model_domain_body_clock_baseline_t durable_clock;

        st = decode_snapshot_clock(
            workspace, &workspace->t5_plan, &clock_row);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }
        durable_clock = workspace->typed_record.clock_baseline;
        if (durable_clock.baseline_state
            == NINLIL_MODEL_DOMAIN_BASELINE_STATE_UNINITIALIZED) {
            next_generation = 1u;
            transition_required = 1;
        } else if (durable_clock.baseline_state
                   == NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED) {
            if (memcmp(
                    durable_clock.trusted_clock_epoch,
                    workspace->trusted_epoch,
                    sizeof(workspace->trusted_epoch))
                == 0) {
                if (workspace->trusted_now_ms
                    < durable_clock.last_trusted_now_ms) {
                    out_result->status = NINLIL_E_DEGRADED;
                    return NINLIL_E_DEGRADED;
                }
            } else {
                if (durable_clock.publish_generation == UINT64_MAX) {
                    out_result->status = NINLIL_E_DEGRADED;
                    return NINLIL_E_DEGRADED;
                }
                next_generation = durable_clock.publish_generation + 1u;
                transition_required = 1;
            }
        } else {
            out_result->status = NINLIL_E_STORAGE_CORRUPT;
            return NINLIL_E_STORAGE_CORRUPT;
        }

        if (transition_required != 0) {
            uint32_t i;
            ninlil_storage_canonical_row_t begin_rows[
                NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP];

            st = ninlil_domain_schema1_build_t5_clock_plan(
                workspace->trusted_epoch,
                workspace->trusted_now_ms,
                next_generation,
                &workspace->t5_plan);
            if (st != NINLIL_OK) {
                out_result->status = st;
                return st;
            }
            for (i = 0u; i < row_count; ++i) {
                begin_rows[i].key.data = workspace->snap_key[i];
                begin_rows[i].key.length = workspace->snap_key_len[i];
                begin_rows[i].value.data = workspace->snap_value[i];
                begin_rows[i].value.length = workspace->snap_value_len[i];
                workspace->apply_rows[i] = begin_rows[i];
            }
            workspace->apply_rows[clock_row].value.data =
                workspace->t5_plan.new_value;
            workspace->apply_rows[clock_row].value.length =
                workspace->t5_plan.new_value_length;
            st = full_apply_transition(
                storage,
                *inout_handle,
                begin_rows,
                row_count,
                workspace->apply_rows,
                row_count,
                out_result);
            if (st == NINLIL_E_STORAGE_COMMIT_UNKNOWN) {
                fence_handle(storage, inout_handle, out_result);
                out_result->outcome =
                    NINLIL_DOMAIN_SCHEMA1_OWNER_OUTCOME_COMMIT_UNKNOWN;
                out_result->status = st;
                return st;
            }
            if (st != NINLIL_OK) {
                out_result->status = st;
                return st;
            }
            out_result->wrote_t5 = 1u;
        } else {
            out_result->wrote_t5 = 0u;
        }

        st = ninlil_domain_schema1_startup_complete_stage(
            &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T5_COMMIT);
        if (st != NINLIL_OK) {
            out_result->status = st;
            return st;
        }

        if (transition_required != 0) {
            st = scan_namespace(
                storage, *inout_handle, workspace, &row_count, 1);
            if (st != NINLIL_OK) {
                out_result->status = st;
                return st;
            }
            st = ninlil_domain_schema1_classify_t5_commit_unknown(
                &workspace->t5_plan,
                workspace->snapshot_rows,
                workspace->snap_count,
                &t5c);
            if (st != NINLIL_OK
                || t5c != NINLIL_DOMAIN_SCHEMA1_GROUP_NEW
                || decode_snapshot_clock(
                       workspace, &workspace->t5_plan, &clock_row)
                    != NINLIL_OK
                || workspace->typed_record.clock_baseline.baseline_state
                    != NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED
                || workspace->typed_record.clock_baseline.publish_generation
                    != next_generation
                || workspace->typed_record.clock_baseline.last_trusted_now_ms
                    != workspace->trusted_now_ms
                || memcmp(
                       workspace->typed_record.clock_baseline
                           .trusted_clock_epoch,
                       workspace->trusted_epoch,
                       sizeof(workspace->trusted_epoch))
                    != 0) {
                out_result->status = NINLIL_E_STORAGE_CORRUPT;
                return NINLIL_E_STORAGE_CORRUPT;
            }
        } else {
            t5c = NINLIL_DOMAIN_SCHEMA1_GROUP_NEW;
        }
        out_result->t5_class = t5c;
    }

    /*
     * --- T6 private stage-order scaffold ---
     * Durable health-source reconstruction is not implemented. Completing the
     * private transcript keeps authority tests useful, but the public Runtime
     * readiness gate remains 0u and this must never be treated as production
     * recovery completion.
     */
    st = ninlil_domain_schema1_startup_complete_stage(
        &workspace->stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T6);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }

    out_result->storage_recovery_t0_t6_complete = 1u;
    out_result->t7_ready = 1u;
    out_result->status = NINLIL_OK;
    (void)ninlil_domain_schema1_startup_export_transcript(
        &workspace->stages, &out_result->transcript);
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_owner_t7_publication_gate(
    const ninlil_domain_schema1_owner_result_t *storage_result,
    uint32_t bearer_open_ok,
    uint32_t metrics_entropy_ok,
    ninlil_domain_schema1_startup_state_t *stages,
    ninlil_domain_schema1_owner_result_t *out_result)
{
    ninlil_status_t st;

    if (out_result == NULL || storage_result == NULL || stages == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_result = *storage_result;
    if (storage_result->storage_recovery_t0_t6_complete == 0u
        || storage_result->t7_ready == 0u) {
        out_result->status = NINLIL_E_INVALID_STATE;
        return NINLIL_E_INVALID_STATE;
    }
    if (bearer_open_ok == 0u || metrics_entropy_ok == 0u) {
        out_result->status = NINLIL_E_INVALID_STATE;
        return NINLIL_E_INVALID_STATE;
    }
    if (!ninlil_domain_schema1_startup_pre_publish_side_effects_zero(stages)) {
        /* Before T7: handle/publish/callback must still be 0. */
        out_result->status = NINLIL_E_INVALID_STATE;
        return NINLIL_E_INVALID_STATE;
    }
    st = ninlil_domain_schema1_startup_complete_stage(
        stages, NINLIL_DOMAIN_SCHEMA1_STAGE_BEARER_OPEN);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = ninlil_domain_schema1_startup_complete_stage(
        stages, NINLIL_DOMAIN_SCHEMA1_STAGE_METRICS_ENTROPY);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = ninlil_domain_schema1_startup_complete_stage(
        stages, NINLIL_DOMAIN_SCHEMA1_STAGE_T7);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    st = ninlil_domain_schema1_startup_complete_stage(
        stages, NINLIL_DOMAIN_SCHEMA1_STAGE_PUBLISH);
    if (st != NINLIL_OK) {
        out_result->status = st;
        return st;
    }
    if (!ninlil_domain_schema1_startup_publication_allowed(stages)) {
        out_result->status = NINLIL_E_INVALID_STATE;
        return NINLIL_E_INVALID_STATE;
    }
    (void)ninlil_domain_schema1_startup_export_transcript(
        stages, &out_result->transcript);
    out_result->status = NINLIL_OK;
    return NINLIL_OK;
}

ninlil_status_t ninlil_domain_schema1_kind1_owner_commit(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    const ninlil_domain_schema1_kind1_plan_t *plan,
    const ninlil_bytes_view_t *member_values,
    ninlil_domain_schema1_kind1_owner_result_t *out_result)
{
    /*
     * Deprecated thin entry. Use ninlil_domain_schema1_service_register /
     * kind1_commit_full (heap workspace, full-namespace begin/final).
     */
    if (out_result == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_result, 0, sizeof(*out_result));
    out_result->class = NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT;
    (void)storage;
    (void)inout_handle;
    (void)plan;
    (void)member_values;
    out_result->status = NINLIL_E_UNSUPPORTED;
    return NINLIL_E_UNSUPPORTED;
}
