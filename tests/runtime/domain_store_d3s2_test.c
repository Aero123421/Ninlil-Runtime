/*
 * D3-S2 core private unit tests (docs/17 §18.13 vertical slice).
 *
 * Covers fixed context, begin prevalidation, same-txn baseline + reopen,
 * PASS_INTERNAL freeze, drive B0, incomplete finalize reject, cleanup,
 * and focused P0-1..P0-8 regressions (the independent JSON oracle remains
 * a later slice).
 * Does NOT claim Mode 21–26 full product COMPLETE / D3 overall /
 * Stage5 / public Runtime / D3-S2 complete.
 */

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_d3s1.h"
#include "domain_store_d3s1_fixtures.h"
#include "domain_store_d3s2.h"
#include "domain_store_scanner.h"
#include "domain_scan_d3s2_wire_fixture.h"
#include "runtime_store_codec.h"
#include "scripted_storage_spy.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static void set_id(ninlil_id128_t *id, uint8_t first)
{
    uint8_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(first + i);
    }
}

static void default_binding(ninlil_model_runtime_store_binding_t *b)
{
    (void)memset(b, 0, sizeof(*b));
    b->storage_schema = NINLIL_STORAGE_SCHEMA_M1A;
    b->role = NINLIL_ROLE_CONTROLLER;
    b->environment = NINLIL_ENV_TEST;
    set_id(&b->runtime_id, 0x10u);
    b->limits.max_services = 7u;
    b->limits.max_nonterminal_transactions = 20u;
    b->limits.max_targets_per_transaction = 1u;
    b->limits.max_logical_payload_bytes = 1000u;
    b->limits.max_durable_outbox_payload_bytes = 5000u;
    b->limits.max_attempts_per_target_per_cycle = 8u;
    b->limits.max_cancel_attempts_per_transaction = 1u;
    b->limits.max_evidence_per_target = 3u;
    b->limits.max_retained_terminal_transactions = 30u;
    b->limits.max_nonterminal_deliveries = 12u;
    b->limits.max_event_spool_count = 0u;
    b->limits.max_event_spool_bytes = 0u;
    b->limits.max_result_cache_entries = 13u;
    b->limits.max_retained_dispositions = 14u;
    b->limits.max_ingress_per_step = 15u;
    b->limits.max_callbacks_per_step = 16u;
    b->limits.max_state_transitions_per_step = 17u;
    b->limits.max_bearer_sends_per_step = 18u;
    b->limits.max_deferred_tokens = 19u;
}

static int install_full_profile(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_model_runtime_store_binding_t *candidate)
{
    uint32_t key_id;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_runtime_store_key_t key;
    uint8_t value[183];
    uint32_t value_length;

    default_binding(candidate);
    (void)memset(&identity, 0, sizeof(identity));
    identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&identity.device_id, 0x20u);
    set_id(&identity.installation_id, 0x40u);
    set_id(&identity.site_domain_id, 0x60u);
    identity.binding_epoch = 1u;
    identity.membership_epoch = 1u;

    for (key_id = 1u; key_id <= 17u; ++key_id) {
        ninlil_status_t st;
        if (ninlil_model_runtime_store_build_key(
                (ninlil_model_runtime_store_key_id_t)key_id, &key)
            != NINLIL_OK) {
            return 0;
        }
        value_length = 0u;
        if (key_id == 1u) {
            st = ninlil_model_runtime_store_encode_binding(
                candidate, value, sizeof(value), &value_length);
        } else if (key_id == 2u) {
            st = ninlil_model_runtime_store_encode_identity(
                &identity, value, sizeof(value), &value_length);
        } else if (key_id <= 6u) {
            ninlil_model_runtime_store_counter_t counter;
            counter.kind =
                (ninlil_model_runtime_store_counter_kind_t)(key_id - 2u);
            counter.value = 0u;
            counter.exhausted_marker = 0u;
            st = ninlil_model_runtime_store_encode_counter(
                (ninlil_model_runtime_store_key_id_t)key_id, &counter, value,
                sizeof(value), &value_length);
        } else {
            ninlil_model_runtime_store_capacity_t cap;
            (void)memset(&cap, 0, sizeof(cap));
            cap.kind = (ninlil_resource_kind_t)(key_id - 6u);
            cap.limit = 100u + key_id;
            cap.capacity_epoch = 1u;
            st = ninlil_model_runtime_store_encode_capacity(
                (ninlil_model_runtime_store_key_id_t)key_id, &cap, value,
                sizeof(value), &value_length);
        }
        if (st != NINLIL_OK) {
            return 0;
        }
        if (!ninlil_spy_add_row(
                spy, key.bytes, key.length, value, value_length)) {
            return 0;
        }
    }
    return 1;
}

/* ---- (1) sizes / modes / masks ---- */

static int test_d3s2_context_size_session_and_masks(void)
{
    uint8_t m;

    REQUIRE(sizeof(ninlil_domain_scan_d3s2_context_t)
        == NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_SIZE_BYTES);
    REQUIRE(sizeof(ninlil_domain_scan_d3s2_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_CEILING_BYTES);
    REQUIRE(_Alignof(ninlil_domain_scan_d3s2_context_t) == 1);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_SIZE_BYTES == 306u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_CEILING_BYTES == 320u);
    REQUIRE(
        NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_CEILING_BYTES
            - NINLIL_DOMAIN_SCAN_D3S2_CONTEXT_SIZE_BYTES
        == 14u);

    REQUIRE(NINLIL_DOMAIN_SCAN_D3S1_SESSION_FUTURE_BYTES == 144u);
    REQUIRE(sizeof(ninlil_domain_scan_session_t)
        <= NINLIL_DOMAIN_SCAN_D3S1_SESSION_FUTURE_BYTES);
    REQUIRE(sizeof(ninlil_domain_scan_session_t) >= 136u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S1_STAGE5_FUTURE_PACKED_BYTES == 8384u);
    REQUIRE(NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES == 8192u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S2_OUTER_AGGREGATE_CEILING_BYTES == 9152u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S2_AGGREGATE_PACKED_SUM_BYTES == 9111u);

    REQUIRE(NINLIL_DOMAIN_SCAN_D3S2_MODE_MIN == 21u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S2_MODE_MAX == 26u);
    for (m = 21u; m <= 26u; m += 1u) {
        uint8_t count_m = ninlil_domain_scan_d3s2_required_count_mask(m);
        uint8_t bind_m = ninlil_domain_scan_d3s2_required_binding_mask(m);
        REQUIRE(count_m != 0u);
        REQUIRE(count_m == bind_m);
        REQUIRE((count_m & 0xC0u) == 0u);
    }
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(21u)
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT
            | NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX));
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(22u)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT);
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(23u)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE);
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(24u)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY);
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(25u)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY);
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(26u)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT);
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(20u) == 0u);
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(27u) == 0u);
    return 0;
}

/* ---- (2) begin prevalidation ---- */

static int test_d3s2_begin_prevalidation(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint64_t before;
    uint8_t session_canary[sizeof(session)];
    uint8_t context_canary[sizeof(context)];
    uint8_t workspace_canary[sizeof(workspace)];
    uint8_t candidate_canary[sizeof(candidate)];
    uint8_t poison = 0xA5u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, poison, sizeof(context));
    REQUIRE(install_full_profile(&spy, &candidate));
    before = spy.trace_count;
    (void)memcpy(session_canary, &session, sizeof(session));
    (void)memcpy(context_canary, &context, sizeof(context));
    (void)memcpy(workspace_canary, &workspace, sizeof(workspace));
    (void)memcpy(candidate_canary, &candidate, sizeof(candidate));

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, NULL);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&workspace, workspace_canary, sizeof(workspace)) == 0);
    REQUIRE(memcmp(&candidate, candidate_canary, sizeof(candidate)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 20u, &context);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);
    REQUIRE(memcmp(&workspace, workspace_canary, sizeof(workspace)) == 0);
    REQUIRE(memcmp(&candidate, candidate_canary, sizeof(candidate)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 0u, &context);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 255u, &context);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u,
        (ninlil_domain_scan_d3s2_context_t *)(void *)&session);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u,
        (ninlil_domain_scan_d3s2_context_t *)(void *)&workspace);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&workspace, workspace_canary, sizeof(workspace)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u,
        (ninlil_domain_scan_d3s2_context_t *)(void *)&candidate);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&candidate, candidate_canary, sizeof(candidate)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s2(
        NULL, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);

    return 0;
}

/* ---- (3) valid begin ---- */

static int test_d3s2_valid_begin_txn_iter_context(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t poison = 0x5Cu;
    uint8_t m;

    for (m = 21u; m <= 26u; m += 1u) {
        ninlil_spy_init(&spy);
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        REQUIRE(install_full_profile(&spy, &candidate));
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0x3Cu, sizeof(workspace));
        (void)memset(&context, poison, sizeof(context));

        st = ninlil_domain_scan_begin_profiled_d3s2(
            &session, ops, &handle, &workspace, &candidate, m, &context);
        REQUIRE(st == NINLIL_OK);

        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
        REQUIRE(session.bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S2);
        REQUIRE(session.bound_d3s2_context == &context);
        REQUIRE(session.txn_live == 1u);
        REQUIRE(session.iter_live == 1u);
        REQUIRE(spy.txn_live == 1);
        REQUIRE(spy.iter_live == 1);
        REQUIRE(spy.begin_calls == 1u);
        REQUIRE(spy.iter_open_calls == 1u);
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));

        REQUIRE(context.focus_mode == m);
        REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_BASELINE);
        REQUIRE(context.flags == 0u);
        REQUIRE(context.count_complete_mask == 0u);
        REQUIRE(context.binding_complete_mask == 0u);
        REQUIRE(context.last_carrier_key_len == 0u);
        REQUIRE(context.peer_key_len == 0u);
        REQUIRE(context.cleanup_skip == 0u);
        REQUIRE(memcmp(&workspace.candidate, &candidate, sizeof(candidate))
            == 0);

        st = ninlil_domain_scan_abort(&session, &result);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(result.adopted == 0u);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    }
    return 0;
}

/* ---- (4) baseline + same-txn reopen + PASS_INTERNAL freeze ---- */

static int test_d3s2_baseline_reopen_pass_internal_freeze(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_storage_txn_t txn_after_baseline;
    ninlil_status_t st;
    uint64_t ok_freeze;
    uint64_t fam14_freeze;
    uint64_t cur_freeze;
    uint8_t prof_exact;
    uint8_t prof_mismatch;
    uint8_t future_cand;
    uint8_t future_seen;
    uint32_t get_mask;
    uint32_t fam14_mask;
    uint32_t iter_open_after_baseline;
    uint32_t begin_after_baseline;
    uint32_t rollback_after_baseline;
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0xAAu, sizeof(context));

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE);
    REQUIRE(spy.begin_calls == 1u);
    REQUIRE(spy.iter_open_calls == 1u);

    guard = 0;
    while (context.pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(session.state != NINLIL_DOMAIN_SCAN_STATE_FAILED);
        guard += 1;
    }
    REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_BASELINE_DONE) != 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER);

    ok_freeze = session.ok_row_count;
    fam14_freeze = session.family14_row_count;
    cur_freeze = session.current_domain_key_count;
    prof_exact = session.profile_exact_active;
    prof_mismatch = session.profile_mismatch;
    future_cand = session.future_profile_candidate;
    future_seen = session.recognizable_future_seen;
    get_mask = session.profile_get_present_mask;
    fam14_mask = session.family14_iter_seen_mask;
    REQUIRE(prof_exact == 1u);
    REQUIRE(ok_freeze >= 17u);

    begin_after_baseline = spy.begin_calls;
    iter_open_after_baseline = spy.iter_open_calls;
    rollback_after_baseline = spy.rollback_calls;
    txn_after_baseline = session.txn;
    REQUIRE(begin_after_baseline == 1u);
    REQUIRE(iter_open_after_baseline == 2u); /* baseline open + drive reopen */
    REQUIRE(spy.txn_live == 1);
    REQUIRE(session.txn_live == 1u);
    REQUIRE(spy.iter_live == 1);
    REQUIRE(session.iter_live == 1u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);

    st = ninlil_domain_scan_reopen_zero_prefix_iter(&session);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(session.txn == txn_after_baseline);
    REQUIRE(spy.begin_calls == begin_after_baseline);
    REQUIRE(spy.rollback_calls == rollback_after_baseline);
    REQUIRE(spy.iter_open_calls == iter_open_after_baseline + 1u);
    REQUIRE(spy.iter_live == 1);
    REQUIRE(session.iter_live == 1u);
    REQUIRE(session.has_previous == 0u);

    /* Internal advance: exact OK; freeze holds. Catalog still present. */
    st = ninlil_domain_scan_advance(&session, 8u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN
        || session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.ok_row_count == ok_freeze);
    REQUIRE(session.family14_row_count == fam14_freeze);
    REQUIRE(session.current_domain_key_count == cur_freeze);
    REQUIRE(session.profile_exact_active == prof_exact);
    REQUIRE(session.profile_mismatch == prof_mismatch);
    REQUIRE(session.future_profile_candidate == future_cand);
    REQUIRE(session.recognizable_future_seen == future_seen);
    REQUIRE(session.profile_get_present_mask == get_mask);
    REQUIRE(session.family14_iter_seen_mask == fam14_mask);
    REQUIRE(spy.begin_calls == 1u);
    REQUIRE(spy.iter_live <= 1);
    REQUIRE(session.iter_live <= 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    /* One more INTERNAL drive (may need reopen if EXHAUSTED). */
    if (session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED) {
        st = ninlil_domain_scan_reopen_zero_prefix_iter(&session);
        REQUIRE(st == NINLIL_OK);
    }
    if (session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
    }
    REQUIRE(session.ok_row_count == ok_freeze);
    REQUIRE(session.family14_row_count == fam14_freeze);
    REQUIRE(session.current_domain_key_count == cur_freeze);
    REQUIRE(session.profile_exact_active == prof_exact);
    REQUIRE(session.profile_mismatch == prof_mismatch);
    REQUIRE(session.future_profile_candidate == future_cand);
    REQUIRE(session.recognizable_future_seen == future_seen);
    REQUIRE(spy.begin_calls == 1u);
    REQUIRE(spy.iter_live <= 1);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(result.adopted == 0u);
    return 0;
}

/* ---- (5) drive budget 0 ---- */

static int test_d3s2_drive_budget_zero(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint64_t before;
    uint8_t session_canary[sizeof(session)];
    uint8_t context_canary[sizeof(context)];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 22u, &context);
    REQUIRE(st == NINLIL_OK);

    before = spy.trace_count;
    (void)memcpy(session_canary, &session, sizeof(session));
    (void)memcpy(context_canary, &context, sizeof(context));

    st = ninlil_domain_scan_d3s2_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN);
    REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* ---- (6a) abort then second abort: exact INVALID_STATE, no double-close ---- */

static int test_d3s2_second_abort_exact(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t closes;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 23u, &context);
    REQUIRE(st == NINLIL_OK);
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(result.adopted == 0u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(ninlil_spy_iter_close_before_rollback(&spy));

    closes = ninlil_spy_close_count_for_handle(&spy, original);
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_INVALID_STATE);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == closes);
    return 0;
}

/* ---- (6b) abort then second finalize: exact INVALID_STATE, no double-close ---- */

static int test_d3s2_second_finalize_after_abort_exact(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    ninlil_storage_handle_t original;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t closes;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    original = handle;
    REQUIRE(install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 24u, &context);
    REQUIRE(st == NINLIL_OK);
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);

    closes = ninlil_spy_close_count_for_handle(&spy, original);
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(st == NINLIL_E_INVALID_STATE);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    REQUIRE(ninlil_spy_close_count_for_handle(&spy, original) == closes);
    return 0;
}

/*
 * Incomplete S2 finalize reject: after baseline, direct advance to EXHAUSTED
 * without COMPLETE → finalize exact INVALID_STATE / Port0 / unchanged;
 * then abort OK adopted 0. Does not claim success finalize (no COMPLETE).
 */
static int test_d3s2_incomplete_finalize_reject_then_abort(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_domain_scan_result_t result_canary;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint64_t before;
    uint8_t session_canary[sizeof(session)];
    uint8_t context_canary[sizeof(context)];
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    (void)memset(&result, 0x5Au, sizeof(result));
    (void)memcpy(&result_canary, &result, sizeof(result));

    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);

    /* Baseline via drive until PASS_INTERNAL (SELECT_CARRIER, OPEN). */
    guard = 0;
    while (context.pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        guard += 1;
    }
    REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);
    REQUIRE(context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);

    /* Direct advance (not drive COMPLETE path) to EXHAUSTED. */
    guard = 0;
    while (session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN && guard < 64) {
        st = ninlil_domain_scan_advance(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        guard += 1;
    }
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);

    before = spy.trace_count;
    (void)memcpy(session_canary, &session, sizeof(session));
    (void)memcpy(context_canary, &context, sizeof(context));
    (void)memcpy(&result_canary, &result, sizeof(result));

    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(st == NINLIL_E_INVALID_STATE);
    REQUIRE(spy.trace_count == before); /* Port 0 */
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);
    REQUIRE(memcmp(&result, &result_canary, sizeof(result)) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(result.adopted == 0u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_DONE);
    return 0;
}

/* ---- P0 regression helpers ---- */

static uint64_t lane_u64(const uint8_t lane[8])
{
    return ((uint64_t)lane[0] << 56) | ((uint64_t)lane[1] << 48)
        | ((uint64_t)lane[2] << 40) | ((uint64_t)lane[3] << 32)
        | ((uint64_t)lane[4] << 24) | ((uint64_t)lane[5] << 16)
        | ((uint64_t)lane[6] << 8) | (uint64_t)lane[7];
}

static uint32_t lane_u32_be(const uint8_t lane[4])
{
    return ((uint32_t)lane[0] << 24) | ((uint32_t)lane[1] << 16)
        | ((uint32_t)lane[2] << 8) | (uint32_t)lane[3];
}

static int add_domain_row(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *value,
    size_t value_len)
{
    return ninlil_spy_add_row(
        spy, key, (uint32_t)key_len, value, (uint32_t)value_len);
}

static int drive_baseline_to_internal(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *context)
{
    int guard = 0;
    ninlil_status_t st;

    while (context->pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_BASELINE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(session, 64u);
        if (st != NINLIL_OK) {
            return 0;
        }
        guard += 1;
    }
    return context->pass_kind == NINLIL_DOMAIN_SCAN_D3S2_PASS_INTERNAL
        && context->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER;
}

static int drive_until(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *context,
    int (*pred)(const ninlil_domain_scan_d3s2_context_t *),
    int max_steps)
{
    int guard = 0;
    ninlil_status_t st;

    while (guard < max_steps && !pred(context)
        && context->phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED
        && context->phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && session->has_sticky_primary == 0u) {
        st = ninlil_domain_scan_d3s2_drive(session, 64u);
        if (st != NINLIL_OK && session->has_sticky_primary == 0u
            && context->phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED) {
            return 0;
        }
        guard += 1;
    }
    return pred(context);
}

static int phase_is_focus_attempt(const ninlil_domain_scan_d3s2_context_t *c)
{
    return c->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FOCUS_ATTEMPT
        && (c->flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_FOCUS_LIVE) != 0u;
}

/* Carrier focus identity installed (may already be past ATTEMPT if L=0 close). */
static int carrier_tx_focus_installed(const ninlil_domain_scan_d3s2_context_t *c)
{
    return c->focus_owner_kind == 1u && c->focus_raw_len == 16u
        && c->last_carrier_key_len != 0u;
}

static int carrier_dlv_focus_installed(const ninlil_domain_scan_d3s2_context_t *c)
{
    return c->focus_owner_kind == 2u && c->focus_raw_len == 80u
        && c->last_carrier_key_len != 0u;
}

/*
 * Build TX CANCEL_STATE shape 6 (TOO_LATE, non-zero cancel_attempt_id) from
 * the NONE fixture so declared_b=1 is legal same-record.
 */
static int encode_tx_cancel_with_attempt(
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_cancel_state_t body;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[256];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;
    uint8_t attempt_id[16];
    uint8_t msg_dig[32];
    uint8_t i;

    vv.data = DSB3_CS_TX_NONE_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_CS_TX_NONE_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_cancel_state(env.body, &body)
        != NINLIL_OK) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        attempt_id[i] = (uint8_t)(0xC0u + i);
    }
    for (i = 0u; i < 32u; ++i) {
        msg_dig[i] = (uint8_t)(0xD0u + i);
    }
    (void)memcpy(body.cancel_attempt_id, attempt_id, 16u);
    (void)memcpy(body.message_semantic_digest, msg_dig, 32u);
    body.cancel_state =
        NINLIL_MODEL_DOMAIN_CANCEL_STATE_TOO_LATE_EFFECT_POSSIBLE;
    body.cancel_kind = 3u;
    body.reason = 83u;
    body.effect_certainty = 2u;
    body.cancel_send_gate_state =
        NINLIL_MODEL_DOMAIN_CANCEL_GATE_INVOKED_CLOSED;
    if (ninlil_model_domain_encode_body_cancel_state(
            &body, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_value, out_cap, out_len)
        == NINLIL_OK;
}

static int encode_dlv_cancel_with_attempt(
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_cancel_state_t body;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[320];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;
    uint8_t attempt_id[16];
    uint8_t msg_dig[32];
    uint8_t i;

    vv.data = DSB3_CS_DLV_NONE_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_CS_DLV_NONE_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_cancel_state(env.body, &body)
        != NINLIL_OK) {
        return 0;
    }
    for (i = 0u; i < 16u; ++i) {
        attempt_id[i] = (uint8_t)(0xE0u + i);
    }
    for (i = 0u; i < 32u; ++i) {
        msg_dig[i] = (uint8_t)(0xF0u + i);
    }
    (void)memcpy(body.cancel_attempt_id, attempt_id, 16u);
    (void)memcpy(body.message_semantic_digest, msg_dig, 32u);
    body.cancel_state =
        NINLIL_MODEL_DOMAIN_CANCEL_STATE_FENCED_BEFORE_DISPATCH;
    body.cancel_kind = 1u;
    body.reason = 82u;
    body.effect_certainty = 1u;
    body.cancel_send_gate_state =
        NINLIL_MODEL_DOMAIN_CANCEL_GATE_NEVER_INVOKED;
    if (ninlil_model_domain_encode_body_cancel_state(
            &body, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_value, out_cap, out_len)
        == NINLIL_OK;
}

/* ---- P0-1: focus_primary_key_digest = true primary KEY_DIGEST ---- */

static int test_d3s2_p0_1_focus_primary_true_primary(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    ninlil_model_domain_digest_t dig_anchor;
    ninlil_model_domain_digest_t dig_state;
    ninlil_bytes_view_t kv;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_until(
        &session, &context, carrier_tx_focus_installed, 32));

    kv.data = DSB2_ANCHOR_TYPED_KEY;
    kv.length = (uint32_t)DSB2_ANCHOR_TYPED_KEY_LEN;
    REQUIRE(ninlil_model_domain_key_digest(kv, &dig_anchor) == NINLIL_OK);
    kv.data = DSB2_STATE_TYPED_KEY;
    kv.length = (uint32_t)DSB2_STATE_TYPED_KEY_LEN;
    REQUIRE(ninlil_model_domain_key_digest(kv, &dig_state) == NINLIL_OK);
    REQUIRE(memcmp(dig_anchor.bytes, dig_state.bytes, 32u) != 0);
    REQUIRE(memcmp(context.focus_primary_key_digest, dig_anchor.bytes, 32u)
        == 0);
    REQUIRE(memcmp(context.focus_primary_key_digest, dig_state.bytes, 32u)
        != 0);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* ---- P0-2: SELECT residual must not double-count FOCUS stream ---- */

static int test_d3s2_p0_2_no_select_residual_double_count(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY, DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    /*
     * One large SELECT advance: install carrier; residual ATTEMPT rows in the
     * same advance must not count (CARRIER_INSTALLED). Exact OK, no sticky.
     */
    st = ninlil_domain_scan_d3s2_drive(&session, 256u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(phase_is_focus_attempt(&context));
    REQUIRE(lane_u64(context.observed_a) == 0u);
    REQUIRE(lane_u64(context.observed_b) == 0u);

    /*
     * True full-band FOCUS stream after reopen: count exactly once.
     * Fixture STATE has cumulative_attempts=0, so focus-close notes
     * declared_a=0 vs observed_a=1 → exact sticky STORAGE_CORRUPT.
     */
    st = ninlil_domain_scan_d3s2_drive(&session, 256u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);
    REQUIRE(lane_u64(context.observed_a) == 1u);
    REQUIRE(lane_u64(context.observed_b) == 0u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/* ---- P0-3: Mode21 declared_b from CANCEL_STATE cancel_attempt_id ---- */

static int test_d3s2_p0_3_mode21_declared_cancel_lane(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t cs_val[320];
    uint32_t cs_len = 0u;

    /* (a) NONE fixture: cancel_attempt_id zero → declared_b=0. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_CS_TX_NONE_TYPED_KEY, DSB3_CS_TX_NONE_TYPED_KEY_LEN,
        DSB3_CS_TX_NONE_TYPED_VALUE, DSB3_CS_TX_NONE_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_until(&session, &context, carrier_tx_focus_installed, 32));
    REQUIRE(lane_u64(context.declared_b) == 0u);
    REQUIRE(lane_u64(context.declared_c)
        == lane_u64(context.declared_a) + lane_u64(context.declared_b));
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);

    /* (b) non-zero cancel_attempt_id → declared_b=1, C=A+B. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(encode_tx_cancel_with_attempt(
        cs_val, (uint32_t)sizeof(cs_val), &cs_len));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_CS_TX_NONE_TYPED_KEY, DSB3_CS_TX_NONE_TYPED_KEY_LEN, cs_val,
        cs_len));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_until(&session, &context, carrier_tx_focus_installed, 32));
    REQUIRE(lane_u64(context.declared_b) == 1u);
    REQUIRE(lane_u64(context.declared_c)
        == lane_u64(context.declared_a) + 1u);
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);

    /* (c) EventFact: CANCEL_STATE ABSENT → declared_b=0. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_until(&session, &context, carrier_tx_focus_installed, 32));
    REQUIRE(lane_u64(context.declared_b) == 0u);
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* ---- P0-4: Mode22 cancel from DLV CANCEL_STATE (not app==0 heuristic) ---- */

static int test_d3s2_p0_4_mode22_app_first_cancel_declared(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t cs_val[360];
    uint32_t cs_len = 0u;

    /*
     * RC_RESULT_POS has application_attempt_count=1 (APPLICATION_FIRST).
     * Old heuristic cancel=(app==0)?1:0 would force declared_b=0.
     * With non-zero DLV cancel_attempt_id, declared_b must be 1; C stays 0.
     */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(encode_dlv_cancel_with_attempt(
        cs_val, (uint32_t)sizeof(cs_val), &cs_len));
    /* Lex order: CANCEL_STATE 0x33 before RESULT_CACHE 0x41. */
    REQUIRE(add_domain_row(
        &spy, DSB3_CS_DLV_NONE_TYPED_KEY, DSB3_CS_DLV_NONE_TYPED_KEY_LEN,
        cs_val, cs_len));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_RESULT_POS_TYPED_KEY, DSB3_RC_RESULT_POS_TYPED_KEY_LEN,
        DSB3_RC_RESULT_POS_TYPED_VALUE, DSB3_RC_RESULT_POS_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 22u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_until(&session, &context, carrier_dlv_focus_installed, 32));
    REQUIRE(lane_u64(context.declared_a) == 1u);
    REQUIRE(lane_u64(context.declared_b) == 1u);
    REQUIRE(lane_u64(context.declared_c) == 0u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* ---- P0-5: CLEANUP_PLAN gate uses true primary KEY_DIGEST ---- */

static int test_d3s2_p0_5_cleanup_plan_true_primary_skip(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_CP_TX_P1_FULL_TYPED_KEY, DSB3_CP_TX_P1_FULL_TYPED_KEY_LEN,
        DSB3_CP_TX_P1_FULL_TYPED_VALUE, DSB3_CP_TX_P1_FULL_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_until(&session, &context, carrier_tx_focus_installed, 32));
    /* Plan PRESENT under true primary KEY_DIGEST → ordinary compare skip. */
    REQUIRE(context.cleanup_skip == 1u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* ---- P0-6: BIND_ATTEMPT mode-scoped owner filter ---- */

static int drive_s2_to_complete_exact(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s2_context_t *context)
{
    int guard = 0;
    ninlil_status_t st;

    while (context->phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(session, 256u);
        if (st != NINLIL_OK) {
            return 0;
        }
        if (session->has_sticky_primary != 0u
            || context->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED) {
            return 0;
        }
        guard += 1;
    }
    return context->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && session->has_sticky_primary == 0u;
}

static int test_d3s2_p0_6_bind_attempt_owner_filter(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    /*
     * (a) Mode22 empty-carrier + TX-owned ATTEMPT only: BIND must skip TX
     * attempts (would false-orphan if treated as DELIVERY-owned).
     */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY, DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 22u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) != 0u);
    REQUIRE((context.binding_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);

    /*
     * (b) Mode21 empty-carrier + DELIVERY-owned ATTEMPT only: BIND must skip
     * DLV attempts (would false-orphan / wrong companion if treated as TX).
     * BIND_ATTEMPT + BIND_INDEX both empty after skip → COMPLETE, no sticky.
     */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_DLV_CMD_REMOTE_TYPED_KEY,
        DSB3_ATT_DLV_CMD_REMOTE_TYPED_KEY_LEN,
        DSB3_ATT_DLV_CMD_REMOTE_TYPED_VALUE,
        DSB3_ATT_DLV_CMD_REMOTE_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) != 0u);
    REQUIRE((context.binding_complete_mask
                & (uint8_t)(NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT
                    | NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX))
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT
            | NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX));

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* ---- P0-8: Mode23 requires all slots 0..L PRESENT ---- */

static int test_d3s2_p0_8_mode23_slot_presence_required(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    int guard;

    /*
     * TX STATE carrier with profile L=3 and zero evidence cells → slot
     * presence matrix must note (false COMPLETE without L+1 cells forbidden).
     */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(candidate.limits.max_evidence_per_target == 3u);
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 23u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    st = NINLIL_OK;
    while (session.has_sticky_primary == 0u
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        guard += 1;
    }
    /* Exact fail-closed: slot absence notes STORAGE_CORRUPT. */
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/* ---- P0-7 Mode24 known-kind FOCUS ---- */

static int encode_result_with_reply_count(
    const uint8_t *src_value,
    uint32_t src_len,
    uint32_t reply_count,
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_result_cache_t body;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[512];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;

    if (reply_count > 4u || out_value == NULL || out_len == NULL) {
        return 0;
    }
    vv.data = src_value;
    vv.length = src_len;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_result_cache(env.body, &body)
        != NINLIL_OK) {
        return 0;
    }
    body.reply_count = reply_count;
    if (ninlil_model_domain_encode_body_result_cache(
            &body, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_value, out_cap, out_len)
        == NINLIL_OK;
}

static int phase_after_mode24_focus_close(
    const ninlil_domain_scan_d3s2_context_t *c)
{
    return (c->count_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY) != 0u
        || c->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED
        || c->phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE;
}

/*
 * P0-7a: reply_count=1 + matching RECEIPT → known-kind focus close sets
 * REPLY count bit; no sticky from cardinality (BIND not required for this
 * assertion).
 */
static int test_d3s2_p0_7_mode24_reply_count1_receipt_close(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t rc_val[512];
    uint32_t rc_len = 0u;
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(encode_result_with_reply_count(
        DSB3_RC_RESULT_POS_TYPED_VALUE,
        (uint32_t)DSB3_RC_RESULT_POS_TYPED_VALUE_LEN, 1u, rc_val,
        (uint32_t)sizeof(rc_val), &rc_len));
    /* Lex: RESULT 0x41 then REVERSE_REPLY 0x42. */
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_RESULT_POS_TYPED_KEY, DSB3_RC_RESULT_POS_TYPED_KEY_LEN,
        rc_val, rc_len));
    REQUIRE(add_domain_row(
        &spy, DSB3_RR_KIND_RECEIPT_TYPED_KEY, DSB3_RR_KIND_RECEIPT_TYPED_KEY_LEN,
        DSB3_RR_KIND_RECEIPT_TYPED_VALUE, DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 24u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    while (!phase_after_mode24_focus_close(&context) && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(session.has_sticky_primary == 0u);
        guard += 1;
    }
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE((context.count_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY);
    /* Focus close advances to SELECT_CARRIER; declared A remains 1. */
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER);
    REQUIRE(lane_u64(context.declared_a) == 1u);
    REQUIRE(lane_u32_be(context.declared_reply_count) == 1u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/*
 * P0-7b: reply_count=1 with no REVERSE_REPLY → focus close notes missing
 * (observed_a=0 vs declared_a=1) → exact sticky STORAGE_CORRUPT.
 */
int test_d3s2_p0_7_mode24_declared_missing_reply_fail(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t rc_val[512];
    uint32_t rc_len = 0u;
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(encode_result_with_reply_count(
        DSB3_RC_RESULT_POS_TYPED_VALUE,
        (uint32_t)DSB3_RC_RESULT_POS_TYPED_VALUE_LEN, 1u, rc_val,
        (uint32_t)sizeof(rc_val), &rc_len));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_RESULT_POS_TYPED_KEY, DSB3_RC_RESULT_POS_TYPED_KEY_LEN,
        rc_val, rc_len));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 24u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    st = NINLIL_OK;
    while (session.has_sticky_primary == 0u
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        guard += 1;
    }
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/*
 * P0-7c: reply_count=0 empty known-kind matrix → focus close success
 * (all kinds ABSENT legal), REPLY count bit set, no sticky.
 */
int test_d3s2_p0_7_mode24_reply_count0_empty_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    /* Fixture already has reply_count=0. */
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_RESULT_POS_TYPED_KEY, DSB3_RC_RESULT_POS_TYPED_KEY_LEN,
        DSB3_RC_RESULT_POS_TYPED_VALUE, DSB3_RC_RESULT_POS_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 24u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    while (!phase_after_mode24_focus_close(&context) && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(session.has_sticky_primary == 0u);
        guard += 1;
    }
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE((context.count_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_SELECT_CARRIER);
    REQUIRE(lane_u64(context.declared_a) == 0u);
    REQUIRE(lane_u32_be(context.declared_reply_count) == 0u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* ---- P1 BIND proof strengthen (docs/17 §18.13.9) ---- */

static int patch_pvd_crc(
    uint8_t *value,
    uint32_t value_len,
    const uint8_t pvd[32])
{
    uint32_t payload_len;
    uint32_t crc;

    if (value == NULL || value_len < 16u + 96u || pvd == NULL) {
        return 0;
    }
    payload_len = ((uint32_t)value[8] << 24) | ((uint32_t)value[9] << 16)
        | ((uint32_t)value[10] << 8) | (uint32_t)value[11];
    if (12u + payload_len + 4u != value_len) {
        return 0;
    }
    (void)memcpy(&value[72], pvd, 32u);
    crc = ninlil_model_domain_crc32c(value, 12u + payload_len);
    value[12u + payload_len] = (uint8_t)((crc >> 24) & 0xffu);
    value[12u + payload_len + 1u] = (uint8_t)((crc >> 16) & 0xffu);
    value[12u + payload_len + 2u] = (uint8_t)((crc >> 8) & 0xffu);
    value[12u + payload_len + 3u] = (uint8_t)(crc & 0xffu);
    return 1;
}

static int compute_value_digest(
    const uint8_t *value,
    uint32_t value_len,
    uint8_t out[32])
{
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t v;

    v.data = value;
    v.length = value_len;
    if (ninlil_model_domain_value_digest(v, &dig) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return 1;
}

/* Mode24 reply_count=1 closes both known-kind FOCUS and live BIND. */
int test_d3s2_mode24_reply_one_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t result_value[512];
    uint32_t result_length = 0u;
    uint8_t reply_value[512];
    uint8_t delivery_pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(DSB3_DLV_APP_DS_TYPED_VALUE,
        (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN, delivery_pvd));
    REQUIRE(encode_result_with_reply_count(DSB3_RC_RESULT_POS_TYPED_VALUE,
        (uint32_t)DSB3_RC_RESULT_POS_TYPED_VALUE_LEN, 1u, result_value,
        (uint32_t)sizeof(result_value), &result_length));
    (void)memcpy(reply_value, DSB3_RR_KIND_RECEIPT_TYPED_VALUE,
        DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd_crc(reply_value,
        (uint32_t)DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN, delivery_pvd));
    REQUIRE(add_domain_row(&spy, DSB3_DLV_APP_DS_TYPED_KEY,
        DSB3_DLV_APP_DS_TYPED_KEY_LEN, DSB3_DLV_APP_DS_TYPED_VALUE,
        DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(&spy, DSB3_RC_RESULT_POS_TYPED_KEY,
        DSB3_RC_RESULT_POS_TYPED_KEY_LEN, result_value, result_length));
    REQUIRE(add_domain_row(&spy, DSB3_RR_KIND_RECEIPT_TYPED_KEY,
        DSB3_RR_KIND_RECEIPT_TYPED_KEY_LEN, reply_value,
        DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 24u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(lane_u64(context.declared_a) == 1u);
    REQUIRE(lane_u32_be(context.declared_reply_count) == 1u);
    REQUIRE((context.count_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY);
    REQUIRE((context.binding_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_REPLY);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

static int encode_state_cum_attempts(
    uint64_t cum,
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_transaction_state_t body;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[256];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;

    vv.data = DSB2_STATE_TYPED_VALUE;
    vv.length = (uint32_t)DSB2_STATE_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_transaction_state(env.body, &body)
        != NINLIL_OK) {
        return 0;
    }
    body.cumulative_attempts = cum;
    if (ninlil_model_domain_encode_body_transaction_state(
            &body, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_value, out_cap, out_len)
        == NINLIL_OK;
}

static int encode_retry_cumulative_total_one(
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_retry_summary_t body;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[NINLIL_MODEL_DOMAIN_BODY_RETRY_SUMMARY_MAX];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;

    vv.data = DSB3_RS_CUM_T0_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_RS_CUM_T0_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_retry_summary(env.body, &body)
            != NINLIL_OK
        || body.summary_kind
            != NINLIL_MODEL_DOMAIN_RETRY_SUMMARY_KIND_CUMULATIVE) {
        return 0;
    }
    body.cumulative.total_completed_cycle_count = 1u;
    body.cumulative.folded_cycle_count = 0u;
    if (ninlil_model_domain_encode_body_retry_summary(
            &body, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_value, out_cap, out_len)
        == NINLIL_OK;
}

/*
 * Honest note: D1 same-record validation rejects key/body identity mismatch
 * on zero-prefix walk before BIND. Constructible BIND regressions use
 * PRESENT/ABSENT/PVD paths that survive D1; raw/body subject checks are
 * still exercised when exact_get returns D1-valid companions.
 */

/*
 * P1 valid Mode21 BIND: ANCHOR+STATE+ATT+AII with matching primary PVD and
 * cum=1 → full session COMPLETE (count + carrier + primary raw + INDEX pair).
 */
static int test_d3s2_p1_mode21_bind_valid_pair_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t state_val[400];
    uint32_t state_len = 0u;
    uint8_t att_val[400];
    uint8_t aii_val[256];
    uint8_t anchor_pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(encode_state_cum_attempts(
        1u, state_val, (uint32_t)sizeof(state_val), &state_len));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
        anchor_pvd));
    REQUIRE(sizeof(att_val) >= DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN);
    REQUIRE(sizeof(aii_val) >= DSB3_AII_CMD_TYPED_VALUE_LEN);
    (void)memcpy(
        att_val, DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN);
    (void)memcpy(
        aii_val, DSB3_AII_CMD_TYPED_VALUE, DSB3_AII_CMD_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd_crc(
        att_val, (uint32_t)DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, anchor_pvd));
    REQUIRE(patch_pvd_crc(
        aii_val, (uint32_t)DSB3_AII_CMD_TYPED_VALUE_LEN, anchor_pvd));

    /* Lex: ANCHOR 0x20, STATE 0x22, ATT 0x31, AII 0x34. */
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN, state_val,
        state_len));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY, DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
        att_val, (uint32_t)DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_AII_CMD_TYPED_KEY, DSB3_AII_CMD_TYPED_KEY_LEN, aii_val,
        (uint32_t)DSB3_AII_CMD_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) != 0u);
    REQUIRE((context.binding_complete_mask
                & (uint8_t)(NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT
                    | NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX))
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S2_MASK_ATTEMPT
            | NINLIL_DOMAIN_SCAN_D3S2_MASK_INDEX));

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/*
 * P1-1 closest: ATT header PVD does not match live ANCHOR VALUE_DIGEST →
 * BIND true-primary fails (note STORAGE_CORRUPT). D1 does not enforce
 * live-primary PVD; this is the constructible primary-proof fail path.
 */
static int test_d3s2_p1_mode21_bind_primary_pvd_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t state_val[400];
    uint32_t state_len = 0u;
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(encode_state_cum_attempts(
        1u, state_val, (uint32_t)sizeof(state_val), &state_len));
    /* Fixture ATT keeps non-matching placeholder PVD. */
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN, state_val,
        state_len));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY, DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_AII_CMD_TYPED_KEY, DSB3_AII_CMD_TYPED_KEY_LEN,
        DSB3_AII_CMD_TYPED_VALUE, DSB3_AII_CMD_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    st = NINLIL_OK;
    while (session.has_sticky_primary == 0u
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 256u);
        guard += 1;
    }
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/*
 * P1-2 closest: missing declared-count STATE carrier with live ATT →
 * BIND_ATTEMPT companion ABSENT → sticky CORRUPT (carrier orphan).
 * Key/body subject mismatch is D1 same-record fail-closed before BIND.
 */
int test_d3s2_p1_mode21_bind_carrier_absent(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t att_val[400];
    uint8_t aii_val[256];
    uint8_t anchor_pvd[32];
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    /*
     * Empty-carrier Mode21 still enters BIND. Live ATT without STATE
     * fails carrier companion ABSENT (P1-2 presence + subject path).
     */
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
        anchor_pvd));
    (void)memcpy(
        att_val, DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN);
    (void)memcpy(
        aii_val, DSB3_AII_CMD_TYPED_VALUE, DSB3_AII_CMD_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd_crc(
        att_val, (uint32_t)DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, anchor_pvd));
    REQUIRE(patch_pvd_crc(
        aii_val, (uint32_t)DSB3_AII_CMD_TYPED_VALUE_LEN, anchor_pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY, DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
        att_val, (uint32_t)DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_AII_CMD_TYPED_KEY, DSB3_AII_CMD_TYPED_KEY_LEN, aii_val,
        (uint32_t)DSB3_AII_CMD_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    st = NINLIL_OK;
    while (session.has_sticky_primary == 0u
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 256u);
        guard += 1;
    }
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/*
 * P1-3: Mode21 ATT without matching INDEX peer key → BIND pair ABSENT note.
 * Body-level attempt_id/digest mismatch under correct key is D1 same-record
 * fail-closed on scan; this is the constructible pair fail path.
 */
static int test_d3s2_p1_mode21_bind_index_pair_absent(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t state_val[400];
    uint32_t state_len = 0u;
    uint8_t att_val[400];
    uint8_t anchor_pvd[32];
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(encode_state_cum_attempts(
        1u, state_val, (uint32_t)sizeof(state_val), &state_len));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
        anchor_pvd));
    (void)memcpy(
        att_val, DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd_crc(
        att_val, (uint32_t)DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, anchor_pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN, state_val,
        state_len));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY, DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
        att_val, (uint32_t)DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN));
    /* No AII: FOCUS INDEX undercount also fails; prefer cleanup_skip path?
     * With declared_c=1 and observed_c=0, FOCUS fails before BIND.
     * Use CP PRESENT to skip ordinary count compare so BIND runs. */
    REQUIRE(add_domain_row(
        &spy, DSB3_CP_TX_P1_FULL_TYPED_KEY, DSB3_CP_TX_P1_FULL_TYPED_KEY_LEN,
        DSB3_CP_TX_P1_FULL_TYPED_VALUE, DSB3_CP_TX_P1_FULL_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    st = NINLIL_OK;
    while (session.has_sticky_primary == 0u
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED
        && context.phase != NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE
        && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 256u);
        guard += 1;
    }
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/* Mode23 CANCEL_FIRST is the exact empty evidence-set path. */
int test_d3s2_mode23_cancel_first_empty_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_CANCEL_FIRST_TYPED_KEY,
        DSB3_RC_CANCEL_FIRST_TYPED_KEY_LEN,
        DSB3_RC_CANCEL_FIRST_TYPED_VALUE,
        DSB3_RC_CANCEL_FIRST_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 23u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(lane_u64(context.declared_a) == 0u);
    REQUIRE(lane_u64(context.declared_b) == 0u);
    REQUIRE(lane_u64(context.declared_c) == 0u);
    REQUIRE((context.binding_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/*
 * Encode one TX-owned EVIDENCE_CELL from the D1 SUM_EMPTY typed template via
 * production codec only (docs/17 §8.3 / §18.13.2 Mode23). Slot 0 stays
 * SUMMARY empty; slots ≥1 become RAW UNUSED. Header PVD is patched to the
 * live ANCHOR value digest so BIND true-primary proof can succeed. Does not
 * re-implement scanner slot/equation judgment.
 */
static int encode_tx_evidence_cell_slot(
    uint32_t slot_index,
    const uint8_t anchor_pvd[32],
    uint8_t *out_key,
    uint32_t key_cap,
    uint32_t *out_key_len,
    uint8_t *out_value,
    uint32_t value_cap,
    uint32_t *out_value_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_evidence_cell_t body;
    ninlil_model_domain_common_header_t hdr;
    uint8_t owner_raw[16];
    uint8_t bodybuf[NINLIL_MODEL_DOMAIN_BODY_EVIDENCE_CELL_MAX];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;
    uint8_t components[2u + 2u + 16u + 4u];
    ninlil_bytes_view_t components_view;
    ninlil_model_domain_digest_t composite;
    ninlil_bytes_view_t identity;
    ninlil_model_domain_key_t key;

    if (anchor_pvd == NULL || out_key == NULL || out_key_len == NULL
        || out_value == NULL || out_value_len == NULL || slot_index > 8u) {
        return 0;
    }

    vv.data = DSB3_EV_TX_SUM_EMPTY_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_EV_TX_SUM_EMPTY_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_evidence_cell(env.body, &body)
            != NINLIL_OK
        || body.evidence_owner_kind
            != NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
        || body.owner_key_raw_length != 16u
        || body.owner_key_raw == NULL) {
        return 0;
    }

    (void)memcpy(owner_raw, body.owner_key_raw, 16u);
    body.owner_key_raw = owner_raw;
    body.owner_key_raw_length = 16u;
    body.slot_index = slot_index;
    if (slot_index == 0u) {
        body.cell_kind = NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY;
        body.cell_state = NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED;
        /* Template SUMMARY empty: valid/overflow/late already 0. */
    } else {
        body.cell_kind = NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_RAW;
        body.cell_state = NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_UNUSED;
        body.valid_material_count = 0u;
        body.exact_duplicate_count = 0u;
        body.raw_overflow_count = 0u;
        body.late_evidence_count = 0u;
        body.late_material = 0u;
        body.highest_receipt_stage = 0u;
        body.latest_evidence_stage = 0u;
        body.material_receipt_stage = 0u;
    }

    if (ninlil_model_domain_encode_body_evidence_cell(
            &body, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }

    components[0] = (uint8_t)((NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION
                                  >> 8)
        & 0xffu);
    components[1] =
        (uint8_t)(NINLIL_MODEL_DOMAIN_EVIDENCE_OWNER_TRANSACTION & 0xffu);
    components[2] = 0u;
    components[3] = 16u;
    (void)memcpy(&components[4], owner_raw, 16u);
    components[20] = (uint8_t)((slot_index >> 24) & 0xffu);
    components[21] = (uint8_t)((slot_index >> 16) & 0xffu);
    components[22] = (uint8_t)((slot_index >> 8) & 0xffu);
    components[23] = (uint8_t)(slot_index & 0xffu);
    components_view.data = components;
    components_view.length = 24u;
    if (ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL, components_view,
            &composite)
        != NINLIL_OK) {
        return 0;
    }
    identity.data = composite.bytes;
    identity.length = 32u;
    if (ninlil_model_domain_build_key(
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_EVIDENCE_CELL,
            NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, identity, &key)
        != NINLIL_OK
        || key.length > key_cap) {
        return 0;
    }
    (void)memcpy(out_key, key.bytes, key.length);
    *out_key_len = key.length;

    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    if (ninlil_model_domain_encode_envelope(
            env.record_type, &hdr, bodyv, out_value, value_cap, out_value_len)
        != NINLIL_OK) {
        return 0;
    }
    return patch_pvd_crc(out_value, *out_value_len, anchor_pvd);
}

/*
 * Mode23 non-empty EVIDENCE COMPLETE path:
 * retained TX STATE carrier + true primary ANCHOR + slots 0..L PRESENT
 * (SUMMARY@0 empty counters + RAW UNUSED 1..L). Equation valid=M+overflow
 * with M=0, overflow=0. L comes from accepted profile max_evidence_per_target
 * (default_binding → 3).
 */
int test_d3s2_mode23_nonempty_success(void)
{
    typedef struct evidence_fixture_row {
        uint8_t key[NINLIL_MODEL_DOMAIN_KEY_MAX_BYTES];
        uint8_t value[1024];
        uint32_t key_len;
        uint32_t value_len;
    } evidence_fixture_row_t;
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t anchor_pvd[32];
    uint8_t L;
    uint32_t slot;
    uint32_t row_count;
    uint32_t i;
    uint32_t j;
    evidence_fixture_row_t rows[9];
    uint8_t required = NINLIL_DOMAIN_SCAN_D3S2_MASK_EVIDENCE;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    L = (uint8_t)candidate.limits.max_evidence_per_target;
    REQUIRE(L >= 1u && L <= 8u);
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
        anchor_pvd));

    /* True primary + retained TX carrier (Mode23 eligible). */
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
        DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN));

    row_count = (uint32_t)L + 1u;
    (void)memset(rows, 0, sizeof(rows));
    for (slot = 0u; slot < row_count; slot += 1u) {
        REQUIRE(encode_tx_evidence_cell_slot(slot, anchor_pvd, rows[slot].key,
            (uint32_t)sizeof(rows[slot].key), &rows[slot].key_len,
            rows[slot].value, (uint32_t)sizeof(rows[slot].value),
            &rows[slot].value_len));
    }
    /* SHA256_COMPOSITE keys are intentionally not slot/owner-contiguous.
     * The scripted Storage Port preserves insertion order, so install the
     * generated rows by complete-key lex order exactly as a real iterator. */
    for (i = 1u; i < row_count; i += 1u) {
        evidence_fixture_row_t current = rows[i];
        j = i;
        while (j > 0u
            && memcmp(rows[j - 1u].key, current.key, current.key_len) > 0) {
            rows[j] = rows[j - 1u];
            j -= 1u;
        }
        rows[j] = current;
    }
    for (i = 0u; i < row_count; i += 1u) {
        REQUIRE(add_domain_row(&spy, rows[i].key, (size_t)rows[i].key_len,
            rows[i].value, (size_t)rows[i].value_len));
    }

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 23u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) != 0u);
    REQUIRE(context.declared_L == L);
    /* SUMMARY@0 empty: valid=0, overflow=0, late=0; M=0 RAW MATERIALIZED. */
    REQUIRE(lane_u64(context.declared_a) == 0u);
    REQUIRE(lane_u64(context.declared_b) == 0u);
    REQUIRE(lane_u64(context.declared_c) == 0u);
    REQUIRE(lane_u64(context.observed_a) == 0u);
    REQUIRE(lane_u64(context.observed_b) == 0u);
    REQUIRE(lane_u64(context.observed_c) == 0u);
    REQUIRE(ninlil_domain_scan_d3s2_required_count_mask(23u) == required);
    REQUIRE(ninlil_domain_scan_d3s2_required_binding_mask(23u) == required);
    REQUIRE((context.count_complete_mask & required) == required);
    REQUIRE((context.binding_complete_mask & required) == required);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* Mode25 CUM total=0: no RECENT rows are expected, CUM remains present. */
int test_d3s2_mode25_retry_zero_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t retry_value[256];
    uint8_t anchor_pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
        anchor_pvd));
    (void)memcpy(
        retry_value, DSB3_RS_CUM_T0_TYPED_VALUE,
        DSB3_RS_CUM_T0_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd_crc(
        retry_value, (uint32_t)DSB3_RS_CUM_T0_TYPED_VALUE_LEN, anchor_pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_RS_CUM_T0_TYPED_KEY, DSB3_RS_CUM_T0_TYPED_KEY_LEN,
        retry_value, (uint32_t)DSB3_RS_CUM_T0_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 25u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(lane_u64(context.declared_a) == 0u);
    REQUIRE(lane_u64(context.declared_b) == 0u);
    REQUIRE(lane_u64(context.declared_c) == 1u);
    REQUIRE(lane_u64(context.observed_a) == 0u);
    REQUIRE(lane_u64(context.observed_b) == 0u);
    /* Observed lanes are cleared after the carrier closes; the RETRY count
     * bit below proves the 0/0/1 predicate closed before that reset. */
    REQUIRE(lane_u64(context.observed_c) == 0u);
    REQUIRE(context.declared_retry_recent_n == 0u);
    REQUIRE((context.binding_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

int test_d3s2_mode25_retry_one_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t cumulative_value[256];
    uint32_t cumulative_length = 0u;
    uint8_t recent_value[256];
    uint8_t anchor_pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
        anchor_pvd));
    REQUIRE(encode_retry_cumulative_total_one(
        cumulative_value, (uint32_t)sizeof(cumulative_value),
        &cumulative_length));
    REQUIRE(patch_pvd_crc(cumulative_value, cumulative_length, anchor_pvd));
    (void)memcpy(recent_value, NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE,
        NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE_LEN);
    REQUIRE(patch_pvd_crc(recent_value,
        (uint32_t)NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE_LEN, anchor_pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_RS_CUM_T0_TYPED_KEY, DSB3_RS_CUM_T0_TYPED_KEY_LEN,
        cumulative_value, cumulative_length));
    REQUIRE(add_domain_row(&spy, NINLIL_D3S2_WIRE_RETRY_RECENT_C1_KEY,
        NINLIL_D3S2_WIRE_RETRY_RECENT_C1_KEY_LEN, recent_value,
        (uint32_t)NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 25u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(lane_u64(context.declared_a) == 1u);
    REQUIRE(lane_u64(context.declared_b) == 1u);
    REQUIRE(lane_u64(context.declared_c) == 1u);
    REQUIRE(context.declared_retry_recent_n == 1u);
    REQUIRE((context.count_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY);
    REQUIRE((context.binding_complete_mask & NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_RETRY);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* Mode25 RECENT without its same-tx CUMULATIVE carrier is an orphan. */
int test_d3s2_mode25_recent_without_cumulative_fail(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t recent_value[256];
    uint8_t anchor_pvd[32];
    int guard = 0;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(DSB2_ANCHOR_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN, anchor_pvd));
    (void)memcpy(recent_value, NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE,
        NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE_LEN);
    REQUIRE(patch_pvd_crc(recent_value,
        (uint32_t)NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE_LEN, anchor_pvd));
    REQUIRE(add_domain_row(&spy, DSB2_ANCHOR_TYPED_KEY,
        DSB2_ANCHOR_TYPED_KEY_LEN, DSB2_ANCHOR_TYPED_VALUE,
        DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(&spy, NINLIL_D3S2_WIRE_RETRY_RECENT_C1_KEY,
        NINLIL_D3S2_WIRE_RETRY_RECENT_C1_KEY_LEN, recent_value,
        NINLIL_D3S2_WIRE_RETRY_RECENT_C1_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 25u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    while (session.has_sticky_primary == 0u && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        guard += 1;
    }
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/* Mode26 ACTIVE EVENT_SPOOL declares zero management rows. */
int test_d3s2_mode26_management_zero_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_ES_ACTIVE_TYPED_KEY, DSB3_ES_ACTIVE_TYPED_KEY_LEN,
        DSB3_ES_ACTIVE_TYPED_VALUE, DSB3_ES_ACTIVE_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 26u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(lane_u64(context.declared_a) == 0u);
    REQUIRE(lane_u64(context.observed_a) == 0u);
    REQUIRE(lane_u64(context.observed_b) == 0u);
    REQUIRE(lane_u64(context.observed_c) == 0u);
    REQUIRE((context.binding_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

int test_d3s2_mode26_management_one_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t management_value[512];
    uint8_t anchor_pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
        anchor_pvd));
    (void)memcpy(management_value, NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE,
        NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE_LEN);
    REQUIRE(patch_pvd_crc(management_value,
        (uint32_t)NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE_LEN, anchor_pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(&spy,
        NINLIL_D3S2_WIRE_EVENT_SPOOL_PARKED_CYCLE_KEY,
        NINLIL_D3S2_WIRE_EVENT_SPOOL_PARKED_CYCLE_KEY_LEN,
        NINLIL_D3S2_WIRE_EVENT_SPOOL_PARKED_CYCLE_VALUE,
        NINLIL_D3S2_WIRE_EVENT_SPOOL_PARKED_CYCLE_VALUE_LEN));
    REQUIRE(add_domain_row(&spy, NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_KEY,
        NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_KEY_LEN, management_value,
        (uint32_t)NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 26u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(lane_u64(context.declared_a) == 1u);
    REQUIRE((context.count_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT);
    REQUIRE((context.binding_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT)
        == NINLIL_DOMAIN_SCAN_D3S2_MASK_MANAGEMENT);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

/* Mode26 MANAGEMENT without its live EVENT_SPOOL carrier is an orphan. */
int test_d3s2_mode26_management_without_spool_fail(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t management_value[512];
    uint8_t anchor_pvd[32];
    int guard = 0;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(DSB2_ANCHOR_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN, anchor_pvd));
    (void)memcpy(management_value, NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE,
        NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE_LEN);
    REQUIRE(patch_pvd_crc(management_value,
        (uint32_t)NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE_LEN, anchor_pvd));
    REQUIRE(add_domain_row(&spy, DSB2_ANCHOR_TYPED_KEY,
        DSB2_ANCHOR_TYPED_KEY_LEN, DSB2_ANCHOR_TYPED_VALUE,
        DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(&spy, NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_KEY,
        NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_KEY_LEN, management_value,
        NINLIL_D3S2_WIRE_MANAGEMENT_RESUME_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 26u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    while (session.has_sticky_primary == 0u && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 64u);
        guard += 1;
    }
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/* Mode26 ACTIVE declares zero; one live MANAGEMENT row is an exact mismatch. */
static int test_d3s2_mode26_management_count_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    int guard;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_ES_ACTIVE_TYPED_KEY, DSB3_ES_ACTIVE_TYPED_KEY_LEN,
        DSB3_ES_ACTIVE_TYPED_VALUE, DSB3_ES_ACTIVE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_ML_R_RSN1_TYPED_KEY, DSB3_ML_R_RSN1_TYPED_KEY_LEN,
        DSB3_ML_R_RSN1_TYPED_VALUE, DSB3_ML_R_RSN1_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 26u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    guard = 0;
    st = NINLIL_OK;
    while (session.has_sticky_primary == 0u && guard < 64) {
        st = ninlil_domain_scan_d3s2_drive(&session, 256u);
        guard += 1;
    }
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);

    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

int test_d3s2_empty_carrier_empty_secondary_success(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 21u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(drive_s2_to_complete_exact(&session, &context));
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_COMPLETE);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) != 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_OK);
    return 0;
}

int test_d3s2_port_failure_no_note(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s2_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s2(
        &session, ops, &handle, &workspace, &candidate, 25u, &context);
    REQUIRE(st == NINLIL_OK);
    st = ninlil_domain_scan_d3s2_drive(&session, 256u);
    REQUIRE(st == NINLIL_E_STORAGE);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S2_PHASE_FAILED);
    REQUIRE(
        (context.flags & NINLIL_DOMAIN_SCAN_D3S2_FLAG_COMPLETE_READY) == 0u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    st = ninlil_domain_scan_abort(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE);
    return 0;
}

int ninlil_d3s2_run_all_tests(void)
{
    if (test_d3s2_context_size_session_and_masks() != 0) {
        return 1;
    }
    if (test_d3s2_begin_prevalidation() != 0) {
        return 1;
    }
    if (test_d3s2_valid_begin_txn_iter_context() != 0) {
        return 1;
    }
    if (test_d3s2_baseline_reopen_pass_internal_freeze() != 0) {
        return 1;
    }
    if (test_d3s2_drive_budget_zero() != 0) {
        return 1;
    }
    if (test_d3s2_second_abort_exact() != 0) {
        return 1;
    }
    if (test_d3s2_second_finalize_after_abort_exact() != 0) {
        return 1;
    }
    if (test_d3s2_incomplete_finalize_reject_then_abort() != 0) {
        return 1;
    }
    if (test_d3s2_p0_1_focus_primary_true_primary() != 0) {
        return 1;
    }
    if (test_d3s2_p0_2_no_select_residual_double_count() != 0) {
        return 1;
    }
    if (test_d3s2_p0_3_mode21_declared_cancel_lane() != 0) {
        return 1;
    }
    if (test_d3s2_p0_4_mode22_app_first_cancel_declared() != 0) {
        return 1;
    }
    if (test_d3s2_p0_5_cleanup_plan_true_primary_skip() != 0) {
        return 1;
    }
    if (test_d3s2_p0_6_bind_attempt_owner_filter() != 0) {
        return 1;
    }
    if (test_d3s2_p0_8_mode23_slot_presence_required() != 0) {
        return 1;
    }
    if (test_d3s2_p0_7_mode24_reply_count1_receipt_close() != 0) {
        return 1;
    }
    if (test_d3s2_p0_7_mode24_declared_missing_reply_fail() != 0) {
        return 1;
    }
    if (test_d3s2_p0_7_mode24_reply_count0_empty_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode24_reply_one_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode23_cancel_first_empty_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode23_nonempty_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode25_retry_zero_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode25_retry_one_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode25_recent_without_cumulative_fail() != 0) {
        return 1;
    }
    if (test_d3s2_mode26_management_zero_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode26_management_one_success() != 0) {
        return 1;
    }
    if (test_d3s2_mode26_management_without_spool_fail() != 0) {
        return 1;
    }
    if (test_d3s2_mode26_management_count_mismatch() != 0) {
        return 1;
    }
    if (test_d3s2_empty_carrier_empty_secondary_success() != 0) {
        return 1;
    }
    if (test_d3s2_port_failure_no_note() != 0) {
        return 1;
    }
    if (test_d3s2_p1_mode21_bind_valid_pair_success() != 0) {
        return 1;
    }
    if (test_d3s2_p1_mode21_bind_primary_pvd_mismatch() != 0) {
        return 1;
    }
    if (test_d3s2_p1_mode21_bind_carrier_absent() != 0) {
        return 1;
    }
    if (test_d3s2_p1_mode21_bind_index_pair_absent() != 0) {
        return 1;
    }
    return 0;
}

#ifndef NINLIL_D3S2_TEST_NO_MAIN
int main(void)
{
    return ninlil_d3s2_run_all_tests();
}
#endif
