/* D3-S3 R18 typed authority bridge. Generated fields are compared, never parsed.
 * Two-lane: rep1_l2 production (real API vs typed actual) and formal_precheck
 * (independent typed-row validator; no production API; zero Port). */
#include "domain_store_d3s3.h"
#include "domain_store_scanner.h"
#include "scripted_storage_spy.h"
#include "domain_scan_crossrow_d3s3_fixture.h"

#include <stdio.h>
#include <string.h>

static const char *current_id = "";

#define REQUIRE(x) do { if (!(x)) { (void)fprintf(stderr, "%s: %s\n", current_id, #x); return 1; } } while (0)

static int fail_at(const char *what, size_t index)
{
    (void)fprintf(stderr, "%s: typed mismatch %s[%zu]\n", current_id, what, index);
    return 1;
}

static int bytes_equal(ninlil_d3s3_bytes_t want, const uint8_t *got, uint32_t got_length)
{
    return want.length == got_length && (want.length == 0u || (want.data != NULL && got != NULL && memcmp(want.data, got, want.length) == 0));
}

static int runtime_status(ninlil_d3s3_runtime_status_t want, ninlil_status_t got)
{
    static const ninlil_status_t map[] = { NINLIL_OK, NINLIL_E_STORAGE_CORRUPT, NINLIL_E_STORAGE,
        NINLIL_E_STORAGE_COMMIT_UNKNOWN, NINLIL_E_CAPACITY_EXHAUSTED, NINLIL_E_WOULD_BLOCK,
        NINLIL_E_UNSUPPORTED, NINLIL_E_INVALID_STATE, NINLIL_E_INVALID_ARGUMENT };
    return (unsigned)want < sizeof(map) / sizeof(map[0]) && map[want] == got;
}

static int storage_status(ninlil_d3s3_storage_status_t want, ninlil_storage_status_t got)
{
    static const ninlil_storage_status_t map[] = { NINLIL_STORAGE_OK, NINLIL_STORAGE_NOT_FOUND,
        NINLIL_STORAGE_NO_SPACE, NINLIL_STORAGE_IO_ERROR, NINLIL_STORAGE_CORRUPT,
        NINLIL_STORAGE_COMMIT_UNKNOWN, NINLIL_STORAGE_BUSY, NINLIL_STORAGE_UNSUPPORTED_SCHEMA };
    return (unsigned)want < sizeof(map) / sizeof(map[0]) && map[want] == got;
}

static int state_equal(ninlil_d3s3_state_t want, ninlil_domain_scan_state_t got)
{
    return (unsigned)want <= NINLIL_D3S3_STATE_DONE && (unsigned)want == (unsigned)got;
}

static int optional_runtime_equal(ninlil_d3s3_optional_runtime_status_t want, uint8_t present, ninlil_status_t got)
{
    return want.present == present && (!want.present || runtime_status(want.value, got));
}

static int optional_storage_equal(ninlil_d3s3_optional_storage_status_t want, int present, ninlil_storage_status_t got)
{
    return want.present == (uint8_t)present && (!want.present || storage_status(want.value, got));
}

static int spy_op_equal(ninlil_d3s3_op_t want, ninlil_spy_op_t got)
{
    static const ninlil_spy_op_t map[] = { NINLIL_SPY_OP_BEGIN, NINLIL_SPY_OP_GET,
        NINLIL_SPY_OP_ITER_OPEN, NINLIL_SPY_OP_ITER_NEXT, NINLIL_SPY_OP_ITER_CLOSE,
        NINLIL_SPY_OP_ROLLBACK, NINLIL_SPY_OP_CLOSE };
    return (unsigned)want < sizeof(map) / sizeof(map[0]) && map[want] == got;
}

static int compare_event(const ninlil_d3s3_port_event_t *want,
    const ninlil_spy_trace_t *got, uint32_t seq, uint32_t api_call_index, uint32_t on_call)
{
    if (want->seq != seq || want->api_call_index != api_call_index || want->on_call != on_call ||
        !spy_op_equal(want->op, got->op) || want->storage_status.present != got->status_present ||
        (want->storage_status.present && !storage_status(want->storage_status.value, got->status)) ||
        want->input_handle_id != got->input_handle_id || want->output_handle_id != got->output_handle_id ||
        (want->mode == NINLIL_D3S3_MODE_READ_ONLY) != got->mode_present ||
        (got->mode_present && (want->mode != NINLIL_D3S3_MODE_READ_ONLY || got->mode != NINLIL_STORAGE_READ_ONLY)) ||
        !bytes_equal(want->prefix, got->prefix_bytes, got->prefix_length) ||
        !bytes_equal(want->request_key, got->request_key_bytes, got->request_key_bytes_length) ||
        !bytes_equal(want->key, got->key_bytes, got->key_bytes_length) ||
        want->key_capacity != got->key_capacity || want->key_length != got->key_length ||
        want->value_capacity != got->value_capacity || want->value_length != got->value_length) {
        (void)fprintf(stderr,
            "  event detail want seq=%u api=%u on=%u op=%u st_p=%u vl=%u rk_len=%u "
            "got api=%u on=%u op=%u st_p=%u st=%d vl=%u rk_len=%u kcap=%u klen=%u vcap=%u\n",
            want->seq, want->api_call_index, want->on_call, (unsigned)want->op,
            (unsigned)want->storage_status.present, want->value_length,
            want->request_key.length,
            api_call_index, on_call, (unsigned)got->op, (unsigned)got->status_present,
            got->status_present ? (int)got->status : -1, got->value_length,
            got->request_key_bytes_length, got->key_capacity, got->key_length,
            got->value_capacity);
        return 0;
    }
    return 1;
}

/* Small pure slice used to prove checkpoint/window fields cannot be ignored. */
static int checkpoint_window_tuple_equal(const ninlil_d3s3_checkpoint_t *want,
    uint32_t event_start, uint32_t event_end, uint32_t get_count, uint8_t phase, uint8_t txn_live)
{
    return want->port.event_start == event_start && want->port.event_end == event_end &&
        want->port.get_count == get_count && want->d3s3.phase == phase && want->session.txn_live == txn_live;
}

static uint32_t handle_id(const ninlil_scripted_storage_spy_t *spy, const void *handle, int iter)
{
    if (handle == NULL) return NINLIL_D3S3_HANDLE_NONE;
    if (handle == (const void *)&spy->handle_token) return NINLIL_D3S3_HANDLE_H1;
    if (handle == (const void *)&spy->txn_token) return NINLIL_D3S3_HANDLE_T1;
    if (iter && handle == (const void *)&spy->iter_token && spy->iter_generation <= 10u)
        return NINLIL_D3S3_HANDLE_I1 + spy->iter_generation - 1u;
    return UINT32_MAX;
}

/*
 * storage_handle_id projects the *caller-owned* handle slot value (runner
 * handle), not session->bound_handle_value. The latter is the historical
 * original identity retained for exact-once fence close and stays non-null
 * after the caller slot has been nulled. Pre-fence (clean success, CU
 * fence_pending) the slot is still H1; after fence it is null.
 */
static int compare_checkpoint(const ninlil_d3s3_checkpoint_t *want, ninlil_status_t returned,
    const ninlil_domain_scan_session_t *session, const ninlil_domain_scan_d3s3_context_t *context,
    const ninlil_domain_scan_result_t *result, const ninlil_scripted_storage_spy_t *spy,
    ninlil_storage_handle_t caller_storage_handle,
    uint32_t actual_event_start, uint32_t actual_event_end)
{
    const ninlil_d3s3_checkpoint_session_t *s = &want->session;
    const ninlil_d3s3_checkpoint_context_t *d = &want->d3s3;
    const ninlil_d3s3_checkpoint_port_t *p = &want->port;
    uint64_t peer = spy->get_calls >= 17u ? (uint64_t)spy->get_calls - 17u : 0u;
    uint32_t reopen = spy->iter_open_calls > 0u ? spy->iter_open_calls - 1u : 0u;
    uint32_t reopen_success = spy->iter_open_success_calls > 0u
        ? spy->iter_open_success_calls - 1u
        : 0u;
    #define CP(x, name) do { if (!(x)) { (void)fprintf(stderr, "%s: checkpoint %s\n", current_id, name); return 0; } } while (0)
    CP(runtime_status(want->returned_status, returned), "returned_status"); CP(state_equal(s->state, session->state), "session.state"); CP(s->txn_live == session->txn_live, "session.txn_live"); CP(s->iter_live == session->iter_live, "session.iter_live");
    if (!checkpoint_window_tuple_equal(
            want, actual_event_start, actual_event_end, spy->get_calls,
            context->phase, session->txn_live)) {
        (void)fprintf(stderr,
            "%s: checkpoint checkpoint_window_tuple want=%u/%u/%u/%u/%u got=%u/%u/%u/%u/%u\n",
            current_id,
            want->port.event_start,
            want->port.event_end,
            want->port.get_count,
            want->d3s3.phase,
            want->session.txn_live,
            actual_event_start,
            actual_event_end,
            spy->get_calls,
            context->phase,
            session->txn_live);
        return 0;
    }
    CP(optional_runtime_equal(s->sticky_primary, session->has_sticky_primary, session->sticky_primary), "session.sticky_primary"); CP(optional_storage_equal(s->cleanup_status, session->cleanup_status != NINLIL_STORAGE_OK, session->cleanup_status), "session.cleanup_status"); CP(s->reopen_required == session->reopen_required, "session.reopen_required"); CP(s->fence_pending == session->fence_pending, "session.fence_pending");
    if (s->profile_exact_active != session->profile_exact_active) { (void)fprintf(stderr, "%s: checkpoint session.profile_exact_active want=%u got=%u\n", current_id, (unsigned)s->profile_exact_active, (unsigned)session->profile_exact_active); return 0; } CP(s->profile_mismatch == session->profile_mismatch, "session.profile_mismatch"); CP(s->future_profile_candidate == session->future_profile_candidate, "session.future_profile_candidate"); CP(s->recognizable_future_seen == session->recognizable_future_seen, "session.recognizable_future_seen"); CP(s->family14_row_count == session->family14_row_count, "session.family14_row_count"); CP(s->family14_iter_seen_mask == session->family14_iter_seen_mask, "session.family14_iter_seen_mask"); CP(s->profile_get_present_mask == session->profile_get_present_mask, "session.profile_get_present_mask"); CP(s->ok_row_count == session->ok_row_count, "session.ok_row_count"); CP(s->current_domain_key_count == session->current_domain_key_count, "session.current_domain_key_count"); CP(s->has_previous == session->has_previous && bytes_equal(s->previous_key, session->bound_workspace == NULL ? NULL : session->bound_workspace->previous_key, session->previous_key_length), "session.previous_key");
    CP(d->phase == context->phase && d->pass_kind == context->pass_kind && d->focus_mode == context->focus_mode && d->focus_sub == context->focus_sub && d->semantic_pass == context->semantic_pass, "context.phase_tuple");
    if (d->lifecycle_class != context->lifecycle_class
        || d->expected_live != context->expected_live
        || d->observed_live != context->observed_live
        || d->reply_kind != context->reply_kind) {
        (void)fprintf(stderr,
            "%s: checkpoint context.lifecycle_tuple want=%u/%u/%u/%u got=%u/%u/%u/%u\n",
            current_id,
            (unsigned)d->lifecycle_class,
            (unsigned)d->expected_live,
            (unsigned)d->observed_live,
            (unsigned)d->reply_kind,
            (unsigned)context->lifecycle_class,
            (unsigned)context->expected_live,
            (unsigned)context->observed_live,
            (unsigned)context->reply_kind);
        return 0;
    }
    if (d->flags != context->flags
        || d->count_complete_mask != context->count_complete_mask
        || d->binding_complete_mask != context->binding_complete_mask) {
        (void)fprintf(stderr,
            "%s: checkpoint context.masks want=%u/%u/%u got=%u/%u/%u\n",
            current_id,
            (unsigned)d->flags,
            (unsigned)d->count_complete_mask,
            (unsigned)d->binding_complete_mask,
            (unsigned)context->flags,
            (unsigned)context->count_complete_mask,
            (unsigned)context->binding_complete_mask);
        return 0;
    }
    CP(bytes_equal(d->last_carrier_key, context->last_carrier_key, context->last_carrier_key_len) && bytes_equal(d->focus_id16, context->focus_id16, 16u), "context.bytes");
    CP(p->trace_count == spy->trace_count && p->begin_count == spy->begin_calls && p->get_count == spy->get_calls && p->iter_open_count == spy->iter_open_calls && p->iter_next_count == spy->iter_next_calls && p->iter_close_count == spy->iter_close_calls && p->rollback_count == spy->rollback_calls && p->close_count == spy->close_calls, "port.counts"); CP(p->d3_peer_get_count == peer && p->reopen_attempt_count == reopen && p->reopen_success_count == reopen_success && p->mutation_calls == spy->mutation_calls && p->trace_overflow == spy->trace_overflow, "port.counters"); CP(p->storage_handle_id == handle_id(spy, caller_storage_handle, 0) && p->txn_handle_id == handle_id(spy, session->txn, 0) && p->iter_handle_id == handle_id(spy, session->iter, 1), "port.handles");
    #undef CP
    if (want->has_result == 0u) return result == NULL;
    if (result == NULL || !runtime_status(want->result.status, result->status) || want->result.adopted != result->adopted ||
        !state_equal(want->result.state_after, session->state) || want->result.reopen_required != result->reopen_required ||
        want->result.has_sticky_primary != session->has_sticky_primary || !optional_runtime_equal(want->result.sticky_primary, session->has_sticky_primary, session->sticky_primary) || want->result.mutation_calls != spy->mutation_calls ||
        !optional_storage_equal(want->result.cleanup_status, result->cleanup_status != NINLIL_STORAGE_OK, result->cleanup_status) ||
        want->result.profile_exact_active != result->profile_exact_active || want->result.profile_mismatch != result->profile_mismatch ||
        want->result.future_profile_candidate != result->future_profile_candidate || want->result.recognizable_future_seen != result->recognizable_future_seen ||
        want->result.family14_row_count != result->family14_row_count || want->result.family14_iter_seen_mask != result->family14_iter_seen_mask ||
        want->result.profile_get_present_mask != result->profile_get_present_mask || want->result.ok_row_count != result->ok_row_count ||
        want->result.current_domain_key_count != result->current_domain_key_count || want->result.d3_peer_get_count != peer) return 0;
    return 1;
}

static void apply_binding(ninlil_model_runtime_store_binding_t *out, const ninlil_d3s3_binding_t *in)
{
    (void)memset(out, 0, sizeof(*out)); out->storage_schema = in->storage_schema;
    out->role = (ninlil_role_t)in->role; out->environment = (ninlil_environment_t)in->environment;
    (void)memcpy(out->runtime_id.bytes, in->runtime_id, 16u);
    out->limits.max_services=in->max_services; out->limits.max_nonterminal_transactions=in->max_nonterminal_transactions;
    out->limits.max_targets_per_transaction=in->max_targets_per_transaction; out->limits.max_logical_payload_bytes=in->max_logical_payload_bytes;
    out->limits.max_durable_outbox_payload_bytes=in->max_durable_outbox_payload_bytes; out->limits.max_attempts_per_target_per_cycle=in->max_attempts_per_target_per_cycle;
    out->limits.max_cancel_attempts_per_transaction=in->max_cancel_attempts_per_transaction; out->limits.max_evidence_per_target=in->max_evidence_per_target;
    out->limits.max_retained_terminal_transactions=in->max_retained_terminal_transactions; out->limits.max_nonterminal_deliveries=in->max_nonterminal_deliveries;
    out->limits.max_event_spool_count=in->max_event_spool_count; out->limits.max_event_spool_bytes=in->max_event_spool_bytes;
    out->limits.max_result_cache_entries=in->max_result_cache_entries; out->limits.max_retained_dispositions=in->max_retained_dispositions;
    out->limits.max_ingress_per_step=in->max_ingress_per_step; out->limits.max_callbacks_per_step=in->max_callbacks_per_step;
    out->limits.max_state_transitions_per_step=in->max_state_transitions_per_step; out->limits.max_bearer_sends_per_step=in->max_bearer_sends_per_step;
    out->limits.max_deferred_tokens=in->max_deferred_tokens; out->terminal_retention_ms=in->terminal_retention_ms;
    out->result_cache_retention_ms=in->result_cache_retention_ms; out->observation_retention_ms=in->observation_retention_ms;
}

static int expected_call_status(const char *name, ninlil_status_t *out)
{
    if (strcmp(name, "OK") == 0) *out=NINLIL_OK; else if (strcmp(name,"STORAGE")==0) *out=NINLIL_E_STORAGE;
    else if (strcmp(name,"STORAGE_CORRUPT")==0) *out=NINLIL_E_STORAGE_CORRUPT; else if (strcmp(name,"INVALID_ARGUMENT")==0) *out=NINLIL_E_INVALID_ARGUMENT;
    else if (strcmp(name,"INVALID_STATE")==0) *out=NINLIL_E_INVALID_STATE; else if (strcmp(name,"UNSUPPORTED")==0) *out=NINLIL_E_UNSUPPORTED;
    else if (strcmp(name,"NINLIL_OK")==0) *out=NINLIL_OK; else if (strcmp(name,"NINLIL_E_STORAGE_CORRUPT")==0) *out=NINLIL_E_STORAGE_CORRUPT;
    else if (strcmp(name,"NINLIL_E_STORAGE")==0) *out=NINLIL_E_STORAGE; else if (strcmp(name,"NINLIL_E_STORAGE_COMMIT_UNKNOWN")==0) *out=NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    else if (strcmp(name,"NINLIL_E_CAPACITY_EXHAUSTED")==0) *out=NINLIL_E_CAPACITY_EXHAUSTED; else if (strcmp(name,"NINLIL_E_WOULD_BLOCK")==0) *out=NINLIL_E_WOULD_BLOCK;
    else if (strcmp(name,"NINLIL_E_UNSUPPORTED")==0) *out=NINLIL_E_UNSUPPORTED; else if (strcmp(name,"NINLIL_E_INVALID_STATE")==0) *out=NINLIL_E_INVALID_STATE;
    else if (strcmp(name,"NINLIL_E_INVALID_ARGUMENT")==0) *out=NINLIL_E_INVALID_ARGUMENT; else return 0;
    return 1;
}

static int fault_op(const char *name, ninlil_spy_op_t *out)
{
    if (strcmp(name, "get") == 0) *out=NINLIL_SPY_OP_GET; else if (strcmp(name, "iter_next") == 0) *out=NINLIL_SPY_OP_ITER_NEXT; else if (strcmp(name,"begin")==0) *out=NINLIL_SPY_OP_BEGIN; else if (strcmp(name,"iter_open")==0) *out=NINLIL_SPY_OP_ITER_OPEN; else if (strcmp(name,"rollback")==0) *out=NINLIL_SPY_OP_ROLLBACK; else return 0; return 1;
}
static int fault_status(const char *name, ninlil_storage_status_t *out)
{
    if(strcmp(name,"OK")==0)*out=NINLIL_STORAGE_OK; else if(strcmp(name,"NOT_FOUND")==0)*out=NINLIL_STORAGE_NOT_FOUND; else if(strcmp(name,"NO_SPACE")==0)*out=NINLIL_STORAGE_NO_SPACE; else if(strcmp(name,"IO_ERROR")==0)*out=NINLIL_STORAGE_IO_ERROR; else if(strcmp(name,"CORRUPT")==0)*out=NINLIL_STORAGE_CORRUPT; else if(strcmp(name,"COMMIT_UNKNOWN")==0)*out=NINLIL_STORAGE_COMMIT_UNKNOWN; else if(strcmp(name,"BUSY")==0)*out=NINLIL_STORAGE_BUSY; else if(strcmp(name,"UNSUPPORTED_SCHEMA")==0)*out=NINLIL_STORAGE_UNSUPPORTED_SCHEMA; else return 0; return 1;
}
static int fault_shape(const char *name, ninlil_spy_shape_t *out)
{
    if(strcmp(name,"natural")==0) *out=NINLIL_SPY_SHAPE_NATURAL; else if(strcmp(name,"ok_null")==0) *out=NINLIL_SPY_SHAPE_OK_NULL; else if(strcmp(name,"error_with_handle")==0) *out=NINLIL_SPY_SHAPE_ERROR_WITH_HANDLE; else if(strcmp(name,"bts_lengths")==0) *out=NINLIL_SPY_SHAPE_BTS_LENGTHS; else if(strcmp(name,"not_found_poison")==0) *out=NINLIL_SPY_SHAPE_NOT_FOUND_POISON; else if(strcmp(name,"ok_bad_length")==0) *out=NINLIL_SPY_SHAPE_OK_BAD_LENGTH; else if(strcmp(name,"non_ok_nonempty_length")==0) *out=NINLIL_SPY_SHAPE_NON_OK_NONEMPTY_LENGTH; else if(strcmp(name,"rewrite_data_ptr")==0) *out=NINLIL_SPY_SHAPE_REWRITE_DATA_PTR; else if(strcmp(name,"rewrite_capacity")==0) *out=NINLIL_SPY_SHAPE_REWRITE_CAPACITY; else if(strcmp(name,"value_mismatch")==0) *out=NINLIL_SPY_SHAPE_VALUE_MISMATCH; else if(strcmp(name,"early_end")==0) *out=NINLIL_SPY_SHAPE_EARLY_END; else return 0; return 1;
}

/* Independent typed-row validator: multiset complete-key equality (no Runtime). */
static int typed_rows_have_duplicate_complete_key(
    const ninlil_d3s3_row_t *rows, size_t row_count)
{
    size_t i;
    size_t j;
    for (i = 0u; i < row_count; i++) {
        if (rows[i].key_length > 64u) {
            return 0;
        }
        for (j = i + 1u; j < row_count; j++) {
            if (rows[i].key_length == rows[j].key_length
                && memcmp(rows[i].key, rows[j].key, rows[i].key_length) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* Map independent detection → closed precheck_error; unknown → RED. */
static int independent_precheck_error(
    const ninlil_d3s3_vector_t *vec, ninlil_d3s3_precheck_error_t *out)
{
    if (typed_rows_have_duplicate_complete_key(vec->rows, vec->row_count)) {
        *out = NINLIL_D3S3_PRECHECK_DUPLICATE_COMPLETE_KEY;
        return 1;
    }
    (void)fprintf(stderr,
        "%s: formal_precheck independent validator found no closed precheck reason\n",
        current_id);
    return 0;
}

/*
 * R18 formal_precheck lane: validator-only.
 * - No production API (begin/drive/finalize not called).
 * - calls / checkpoints / Port empty; precheck_error matches independent row scan.
 * - Spy counters prove Port=0 (production not invoked).
 * - Does not synthesize runtime status / session / checkpoint / result.
 */
static int run_formal_precheck(const ninlil_d3s3_vector_t *vec)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_d3s3_precheck_error_t detected;
    size_t i;

    current_id = vec->id;

    /* Closed precheck_error enum only; unknown is RED. */
    if (vec->precheck_error != NINLIL_D3S3_PRECHECK_DUPLICATE_COMPLETE_KEY) {
        (void)fprintf(stderr,
            "%s: formal_precheck unknown/unsupported precheck_error=%u\n",
            current_id, (unsigned)vec->precheck_error);
        return 1;
    }

    /* Fixture structural claims: no production call column / Port / faults. */
    REQUIRE(vec->call_count == 0u);
    REQUIRE(vec->fault_count == 0u);
    REQUIRE(vec->expected == NULL);

    if (!independent_precheck_error(vec, &detected)) {
        return 1;
    }
    if (detected != vec->precheck_error) {
        (void)fprintf(stderr,
            "%s: precheck_error mismatch independent=%u fixture=%u\n",
            current_id, (unsigned)detected, (unsigned)vec->precheck_error);
        return 1;
    }

    /* Materialize rows into spy storage only — never call production APIs. */
    ninlil_spy_init(&spy);
    for (i = 0u; i < vec->row_count; i++) {
        REQUIRE(ninlil_spy_add_row(&spy, vec->rows[i].key, vec->rows[i].key_length,
            vec->rows[i].value, vec->rows[i].value_length));
    }

    /* Production API not invoked: all Port counters / trace remain zero. */
    REQUIRE(spy.begin_calls == 0u);
    REQUIRE(spy.get_calls == 0u);
    REQUIRE(spy.iter_open_calls == 0u);
    REQUIRE(spy.iter_next_calls == 0u);
    REQUIRE(spy.iter_close_calls == 0u);
    REQUIRE(spy.rollback_calls == 0u);
    REQUIRE(spy.close_calls == 0u);
    REQUIRE(spy.trace_count == 0u);
    REQUIRE(spy.trace_overflow == 0u);
    REQUIRE(spy.mutation_calls == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int production_fixture_grammar_valid(const ninlil_d3s3_vector_t *vec)
{
    return vec != NULL
        && vec->calls != NULL
        && vec->call_count > 0u
        && vec->calls[0].op != NULL
        && strcmp(vec->calls[0].op, "begin_profiled_d3s3") == 0
        && vec->calls[vec->call_count - 1u].op != NULL
        && strcmp(vec->calls[vec->call_count - 1u].op, "finalize") == 0
        && vec->expected != NULL
        && vec->expected->port_trace != NULL
        && vec->expected->port_trace_count > 0u;
}

/* R18 rep1_l2 production lane: real API + field-for-field actual compare. */
static int run_production_vector(const ninlil_d3s3_vector_t *vec)
{
    ninlil_scripted_storage_spy_t spy; ninlil_domain_scan_session_t session; ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context; ninlil_model_runtime_store_binding_t candidate; ninlil_storage_handle_t handle;
    ninlil_domain_scan_result_t result; ninlil_status_t st=NINLIL_E_INVALID_STATE, expected; size_t i;
    current_id=vec->id;
    if (vec->precheck_error != NINLIL_D3S3_PRECHECK_NONE) {
        (void)fprintf(stderr, "%s: rep1_l2 forbids precheck_error=%u\n",
            current_id, (unsigned)vec->precheck_error);
        return 1;
    }
    /* Fail-closed production fixture grammar (independent; empty/null columns RED). */
    REQUIRE(production_fixture_grammar_valid(vec));
    ninlil_spy_init(&spy); apply_binding(&candidate,&vec->candidate);
    for(i=0u;i<vec->row_count;i++) REQUIRE(ninlil_spy_add_row(&spy,vec->rows[i].key,vec->rows[i].key_length,vec->rows[i].value,vec->rows[i].value_length));
    for(i=0u;i<vec->fault_count;i++) { ninlil_spy_op_t op; ninlil_storage_status_t fs; ninlil_spy_shape_t shape; REQUIRE(fault_op(vec->faults[i].op,&op) && fault_status(vec->faults[i].status,&fs) && fault_shape(vec->faults[i].shape,&shape)); REQUIRE(ninlil_spy_add_fault(&spy, op, vec->faults[i].on_call, fs, shape, vec->faults[i].key_length,vec->faults[i].value_length)); }
    handle=ninlil_spy_open_handle(&spy); ninlil_domain_scan_session_init(&session); (void)memset(&workspace,0,sizeof(workspace)); (void)memset(&context,0,sizeof(context)); (void)memset(&result,0,sizeof(result));
    for(i=0u;i<vec->call_count;i++) { const ninlil_d3s3_call_t *c=&vec->calls[i]; size_t before=spy.trace_count; const ninlil_domain_scan_result_t *rp=NULL;
        REQUIRE(expected_call_status(c->expected_status,&expected));
        ninlil_spy_trace_set_api_call_index(&spy, (uint32_t)i);
        if(strcmp(c->op,"begin_profiled_d3s3")==0) st=ninlil_domain_scan_begin_profiled_d3s3(&session,ninlil_spy_ops(&spy),&handle,&workspace,&candidate,c->mode,&context);
        else if(strcmp(c->op,"d3s3_drive")==0) st=ninlil_domain_scan_d3s3_drive(&session,c->row_budget);
        else if(strcmp(c->op,"finalize")==0) { st=ninlil_domain_scan_finalize(&session,&result); rp=&result; } else { (void)fprintf(stderr,"%s: unknown call %s\n",current_id,c->op); return 1; }
        REQUIRE(st==expected); REQUIRE(spy.trace_count<=1024u);
        if(!compare_checkpoint(c->checkpoint,st,&session,&context,rp,&spy,handle,(uint32_t)before,(uint32_t)spy.trace_count)) return fail_at("checkpoint",i);
    }
    /* Production API was invoked and observed nonzero Port (not formal zero-Port). */
    REQUIRE(spy.begin_calls > 0u);
    REQUIRE(spy.trace_count > 0u);
    REQUIRE(spy.mutation_calls==0u && ninlil_spy_assert_no_mutations(&spy)); REQUIRE(spy.trace_overflow==0u); REQUIRE(spy.trace_count==vec->expected->port_trace_count);
    { uint32_t occurrences[NINLIL_SPY_OP_COUNT]={0}; for(i=0u;i<spy.trace_count;i++) { occurrences[spy.trace[i].op]++; if(!compare_event(&vec->expected->port_trace[i],&spy.trace[i],(uint32_t)i,spy.trace[i].api_call_index,occurrences[spy.trace[i].op])) return fail_at("port_event",i); } }
    return 0;
}

/*
 * C mutation proof: emptied call/Port columns on a real production vector copy
 * must make run_production_vector RED (scope-selected; no ID skip).
 */
static int production_grammar_mutation_test(void)
{
    ninlil_d3s3_vector_t broken;
    ninlil_d3s3_expected_t broken_expected;
    size_t i;
    int found = 0;

    for (i = 0u; i < NINLIL_D3S3_VECTOR_COUNT; i++) {
        if (ninlil_d3s3_vectors[i].execution_scope == NINLIL_D3S3_SCOPE_REP1_L2) {
            broken = ninlil_d3s3_vectors[i];
            found = 1;
            break;
        }
    }
    REQUIRE(found != 0);
    /* Source must be well-formed before mutation (guards not vacuous). */
    REQUIRE(production_fixture_grammar_valid(&broken));

    /* Empty call schedule is RED even if the expected Port transcript survives. */
    broken.calls = NULL;
    broken.call_count = 0u;
    if (production_fixture_grammar_valid(&broken)) {
        (void)fprintf(stderr, "production grammar accepted empty calls\n");
        return 1;
    }

    /* Empty Port transcript is independently RED with the calls left intact. */
    broken = ninlil_d3s3_vectors[i];
    broken_expected = *broken.expected;
    broken_expected.port_trace = NULL;
    broken_expected.port_trace_count = 0u;
    broken.expected = &broken_expected;
    if (production_fixture_grammar_valid(&broken)) {
        (void)fprintf(stderr, "production grammar accepted empty Port trace\n");
        return 1;
    }

    /* A missing typed Runtime expected object is also RED. */
    broken = ninlil_d3s3_vectors[i];
    broken.expected = NULL;
    if (production_fixture_grammar_valid(&broken)) {
        (void)fprintf(stderr, "production grammar accepted NULL expected\n");
        return 1;
    }
    return 0;
}

/*
 * T2 projection helper: port.storage_handle_id maps the caller-owned handle
 * value (runner slot), not session->bound_handle_value. After fence the
 * caller is null while historical original identity may still be H1.
 */
static int handle_projection_regression_test(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_storage_handle_t caller;
    ninlil_storage_handle_t historical;

    ninlil_spy_init(&spy);
    historical = ninlil_spy_open_handle(&spy);
    REQUIRE(historical == (ninlil_storage_handle_t)&spy.handle_token);
    REQUIRE(handle_id(&spy, historical, 0) == NINLIL_D3S3_HANDLE_H1);

    /* Clean / pre-fence / pre-finalize CU: caller retains H1. */
    caller = historical;
    REQUIRE(handle_id(&spy, caller, 0) == NINLIL_D3S3_HANDLE_H1);

    /* After fence: caller slot nulled; historical original still H1. */
    caller = NULL;
    REQUIRE(handle_id(&spy, caller, 0) == NINLIL_D3S3_HANDLE_NONE);
    REQUIRE(handle_id(&spy, historical, 0) == NINLIL_D3S3_HANDLE_H1);
    /* Bridge compare must prefer caller (NONE), not historical (H1). */
    REQUIRE(handle_id(&spy, caller, 0) != handle_id(&spy, historical, 0));
    return 0;
}

/* C-helper mutation proof: each authority dimension must turn a match RED. */
static int comparator_mutation_test(void)
{
    ninlil_d3s3_port_event_t e=ninlil_d3s3_vectors[0].expected->port_trace[0]; ninlil_spy_trace_t t;
    ninlil_d3s3_checkpoint_t cp=*ninlil_d3s3_vectors[0].calls[0].checkpoint; uint8_t byte=1u;
    (void)memset(&t,0,sizeof(t)); t.op=NINLIL_SPY_OP_BEGIN; t.status=NINLIL_STORAGE_OK; t.status_present=1u; t.mode=NINLIL_STORAGE_READ_ONLY; t.mode_present=1u; t.input_handle_id=NINLIL_D3S3_HANDLE_H1; t.output_handle_id=NINLIL_D3S3_HANDLE_T1;
    if(!compare_event(&e,&t,0u,0u,1u)) return 1;
    e.request_key.data=&byte; e.request_key.length=1u;
    if(compare_event(&e,&t,0u,0u,1u)) return 1;
    e=ninlil_d3s3_vectors[0].expected->port_trace[0];
    e.storage_status.value=NINLIL_D3S3_SS_IO_ERROR;
    if(compare_event(&e,&t,0u,0u,1u)) return 1;
    e=ninlil_d3s3_vectors[0].expected->port_trace[0]; e.value_capacity=1u;
    if(compare_event(&e,&t,0u,0u,1u)) return 1;
    if(!checkpoint_window_tuple_equal(&cp,cp.port.event_start,cp.port.event_end,cp.port.get_count,cp.d3s3.phase,cp.session.txn_live)) return 1;
    cp.port.event_end++; if(checkpoint_window_tuple_equal(&cp,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_start,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_end,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.get_count,ninlil_d3s3_vectors[0].calls[0].checkpoint->d3s3.phase,ninlil_d3s3_vectors[0].calls[0].checkpoint->session.txn_live)) return 1;
    cp=*ninlil_d3s3_vectors[0].calls[0].checkpoint; cp.port.get_count++; if(checkpoint_window_tuple_equal(&cp,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_start,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_end,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.get_count,ninlil_d3s3_vectors[0].calls[0].checkpoint->d3s3.phase,ninlil_d3s3_vectors[0].calls[0].checkpoint->session.txn_live)) return 1;
    cp=*ninlil_d3s3_vectors[0].calls[0].checkpoint; cp.d3s3.phase++; if(checkpoint_window_tuple_equal(&cp,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_start,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_end,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.get_count,ninlil_d3s3_vectors[0].calls[0].checkpoint->d3s3.phase,ninlil_d3s3_vectors[0].calls[0].checkpoint->session.txn_live)) return 1;
    cp=*ninlil_d3s3_vectors[0].calls[0].checkpoint; cp.session.txn_live ^= 1u; if(checkpoint_window_tuple_equal(&cp,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_start,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.event_end,ninlil_d3s3_vectors[0].calls[0].checkpoint->port.get_count,ninlil_d3s3_vectors[0].calls[0].checkpoint->d3s3.phase,ninlil_d3s3_vectors[0].calls[0].checkpoint->session.txn_live)) return 1;
    return 0;
}

int main(void)
{
    size_t i;
    size_t n_prod = 0u;
    size_t n_formal = 0u;
    size_t n_visited = 0u;
    int first_rc = 0;
    const char *first_fail_id = NULL;
    ninlil_d3s3_execution_scope_t first_fail_scope = NINLIL_D3S3_SCOPE_REP1_L2;

    REQUIRE(NINLIL_D3S2_PREFIX_COUNT == 144u);
    REQUIRE(NINLIL_D3S3_VECTOR_COUNT == 136u);
    REQUIRE(NINLIL_D3S3_PRODUCTION_COUNT == 135u);
    REQUIRE(NINLIL_D3S3_FORMAL_PRECHECK_COUNT == 1u);
    REQUIRE(NINLIL_D3S3_VECTOR_COUNT
        == NINLIL_D3S3_PRODUCTION_COUNT + NINLIL_D3S3_FORMAL_PRECHECK_COUNT);
    REQUIRE(comparator_mutation_test() == 0);
    REQUIRE(production_grammar_mutation_test() == 0);
    REQUIRE(handle_projection_regression_test() == 0);

    /* Visit every vector; scope enum branch only — ID skip forbidden / silent skip RED. */
    for (i = 0u; i < NINLIL_D3S3_VECTOR_COUNT; i++) {
        const ninlil_d3s3_vector_t *vec = &ninlil_d3s3_vectors[i];
        int rc;

        current_id = vec->id;
        n_visited += 1u;

        switch (vec->execution_scope) {
        case NINLIL_D3S3_SCOPE_REP1_L2:
            n_prod += 1u;
            rc = run_production_vector(vec);
            break;
        case NINLIL_D3S3_SCOPE_FORMAL_PRECHECK:
            n_formal += 1u;
            rc = run_formal_precheck(vec);
            break;
        default:
            (void)fprintf(stderr,
                "%s: unknown execution_scope=%u (index=%zu) RED\n",
                vec->id, (unsigned)vec->execution_scope, i);
            return 1;
        }

        if (rc != 0 && first_rc == 0) {
            first_rc = rc;
            first_fail_id = vec->id;
            first_fail_scope = vec->execution_scope;
        }
    }

    /* Count drift RED (must visit all; no silent skip). */
    if (n_visited != NINLIL_D3S3_VECTOR_COUNT
        || n_prod != NINLIL_D3S3_PRODUCTION_COUNT
        || n_formal != NINLIL_D3S3_FORMAL_PRECHECK_COUNT) {
        (void)fprintf(stderr,
            "d3s3 typed bridge count drift RED visited=%zu want=%zu "
            "production=%zu want=%zu formal_precheck=%zu want=%zu\n",
            n_visited, (size_t)NINLIL_D3S3_VECTOR_COUNT,
            n_prod, (size_t)NINLIL_D3S3_PRODUCTION_COUNT,
            n_formal, (size_t)NINLIL_D3S3_FORMAL_PRECHECK_COUNT);
        return 1;
    }

    if (first_rc != 0) {
        (void)fprintf(stderr,
            "d3s3 typed bridge FAILED at %s scope=%s "
            "(visited=%zu production=%zu formal_precheck=%zu)\n",
            first_fail_id != NULL ? first_fail_id : "?",
            first_fail_scope == NINLIL_D3S3_SCOPE_FORMAL_PRECHECK
                ? "formal_precheck"
                : "rep1_l2",
            n_visited, n_prod, n_formal);
        return 1;
    }

    (void)printf(
        "domain_store_scanner_crossrow_d3s3_oracle_bridge OK "
        "(%zu typed vectors; production=%zu formal_precheck=%zu)\n",
        (size_t)NINLIL_D3S3_VECTOR_COUNT, n_prod, n_formal);
    return 0;
}
