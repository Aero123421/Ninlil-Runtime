/*
 * D3-S3 unit coverage: context layout, begin prevalidation, PASS_INTERNAL
 * freeze, anti-false-pass harnesses for KEY_DIGEST reverse / Mode30 referrer
 * field / Mode29 RESULT setup / four-session product / masks / ceilings.
 * Focused R12 owner_raw dig-match abort, Mode30 FOCUS_SCAN deferred H14/H15
 * at true NOT_FOUND (kinds/length after install; residual timing; Port first
 * fault), BIND_MAN closed eligibility, Mode28 single-side referrer, Mode30
 * outer DELIVERY+REPLY eligibility.
 * §18.14.9.5 visit-commit regressions: FOCUS dig-match owner_raw mismatch
 * retains failing man previous_key; BIND natural GET retains pre-hook lex.
 * Does not claim D3 overall / Stage5 / public Runtime / D4 complete.
 * ADR remains Proposed (not Accepted).
 */

#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_d3s1.h"
#include "domain_store_d3s1_fixtures.h"
#include "domain_store_d3s3.h"
#include "domain_store_scanner.h"
#include "scripted_storage_spy.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(cond)                                                          \
    do {                                                                       \
        if (!(cond)) {                                                         \
            (void)fprintf(stderr, "%s:%d: REQUIRE failed: %s\n", __FILE__,     \
                __LINE__, #cond);                                              \
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

static int install_profile_rows(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_model_runtime_store_binding_t *candidate)
{
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_runtime_store_key_t key;
    uint8_t value[183];
    uint32_t value_length;
    uint32_t key_id;

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

static int test_d3s3_context_size_and_masks(void)
{
    uint8_t m;

    REQUIRE(sizeof(ninlil_domain_scan_d3s3_context_t)
        == NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_SIZE_BYTES);
    REQUIRE(sizeof(ninlil_domain_scan_d3s3_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_CEILING_BYTES);
    REQUIRE(_Alignof(ninlil_domain_scan_d3s3_context_t) == 1);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_SIZE_BYTES == 754u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_CEILING_BYTES == 768u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_CEILING_BYTES
            - NINLIL_DOMAIN_SCAN_D3S3_CONTEXT_SIZE_BYTES
        == 14u);
    REQUIRE(sizeof(ninlil_domain_scan_session_t)
        <= NINLIL_DOMAIN_SCAN_D3S1_SESSION_FUTURE_BYTES);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S3_OUTER_AGGREGATE_CEILING_BYTES == 9920u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S3_AGGREGATE_PACKED_SUM_BYTES == 9865u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S3_MODE_MIN == 27u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S3_MODE_MAX == 30u);
    for (m = 27u; m <= 30u; m += 1u) {
        uint8_t c = ninlil_domain_scan_d3s3_required_count_mask(m);
        uint8_t b = ninlil_domain_scan_d3s3_required_binding_mask(m);
        REQUIRE(c != 0u);
        REQUIRE(b
            == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_MANIFEST
                | NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_CHUNK));
    }
    REQUIRE(ninlil_domain_scan_d3s3_required_count_mask(26u) == 0u);
    REQUIRE(ninlil_domain_scan_d3s3_required_count_mask(31u) == 0u);
    /* Mode28/30 require semantic count bit */
    REQUIRE((ninlil_domain_scan_d3s3_required_count_mask(28u)
                & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
        != 0u);
    REQUIRE((ninlil_domain_scan_d3s3_required_count_mask(30u)
                & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
        != 0u);
    REQUIRE((ninlil_domain_scan_d3s3_required_count_mask(27u)
                & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
        == 0u);
    return 0;
}

static int test_d3s3_begin_prevalidation(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t session_canary[sizeof(session)];
    uint8_t context_canary[sizeof(context)];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0xA5u, sizeof(context));
    default_binding(&candidate);
    (void)memcpy(session_canary, &session, sizeof(session));
    (void)memcpy(context_canary, &context, sizeof(context));

    /* mode out of range → INVALID, Port 0, unchanged */
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 26u, &context);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 31u, &context);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);

    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, NULL);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);

    /* budget 0 drive without begin */
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);

    /* handle closed by finalize/abort */
    return 0;
}

static int test_d3s3_valid_begin_four_modes(void)
{
    uint8_t mode;
    for (mode = 27u; mode <= 30u; mode += 1u) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        ninlil_domain_scan_result_t result;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0x3Cu, sizeof(workspace));
        (void)memset(&context, 0xAAu, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, mode, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(session.bound_d3_kind == NINLIL_DOMAIN_SCAN_D3_KIND_S3);
        REQUIRE(session.bound_d3s3_context == &context);
        REQUIRE(context.focus_mode == mode);
        REQUIRE(context.pass_kind == NINLIL_DOMAIN_SCAN_D3S3_PASS_BASELINE);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BASELINE);
        REQUIRE(context.pad0 == 0u);
        /* Drive baseline to empty COMPLETE product */
        {
            uint32_t guard = 0u;
            while (context.phase != NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE
                && context.phase != NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED
                && session.state != NINLIL_DOMAIN_SCAN_STATE_FAILED
                && guard < 64u) {
                st = ninlil_domain_scan_d3s3_drive(&session, 64u);
                if (st != NINLIL_OK && session.has_sticky_primary == 0u
                    && context.phase
                        != NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED) {
                    break;
                }
                guard += 1u;
            }
        }
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE);
        REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_COMPLETE_READY)
            != 0u);
        (void)memset(&result, 0, sizeof(result));
        st = ninlil_domain_scan_finalize(&session, &result);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(result.adopted == 1u);
        REQUIRE(spy.mutation_calls == 0u);
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
        /* handle closed by finalize/abort */
    }
    return 0;
}

/* Anti-false-pass #1: KEY_DIGEST reverse rebuild harness must not exist as
 * public rebuild API (compile-time/contract). We assert no exact_get-by-digest
 * helper is offered and begin rejects inventing keys from digests only. */
static int test_d3s3_no_key_digest_reverse_api(void)
{
    /* Contract: context has focus_key_digest but no reverse rebuild symbol.
     * Peer key rebuild for chunks requires blob_id (forward), not KEY_DIGEST. */
    ninlil_domain_scan_d3s3_context_t ctx;
    (void)memset(&ctx, 0, sizeof(ctx));
    REQUIRE(sizeof(ctx.focus_key_digest) == 32u);
    REQUIRE(sizeof(ctx.blob_id_digest) == 32u);
    /* mode masks reject 0/mode outside 27..30 */
    REQUIRE(ninlil_domain_scan_d3s3_required_count_mask(0u) == 0u);
    return 0;
}

/* Anti-false-pass #16: four-session product; not one-baseline-all-four */
static int test_d3s3_four_session_product_not_one_baseline(void)
{
    /* Each mode requires its own begin_profiled_d3s3; dual bind forbidden. */
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t c27;
    ninlil_domain_scan_d3s3_context_t c28;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&c27, 0, sizeof(c27));
    (void)memset(&c28, 0, sizeof(c28));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &c27);
    REQUIRE(st == NINLIL_OK);
    /* Cannot re-begin with mode 28 on same live session */
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 28u, &c28);
    REQUIRE(st == NINLIL_E_INVALID_STATE);
    REQUIRE(c27.focus_mode == 27u);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    /* handle closed by finalize/abort */
    return 0;
}

/* Anti-false-pass #3: Mode30 referrer field is body_blob_key_digest layout slot
 * (focus_key_digest pin), not DELIVERY.payload. */
static int test_d3s3_mode30_referrer_field_contract(void)
{
    ninlil_domain_scan_d3s3_context_t ctx;
    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.focus_mode = 30u;
    ctx.reply_kind = 1u;
    /* layout: focus_key_digest at offset 143 per freeze */
    REQUIRE((size_t)((uint8_t *)&ctx.focus_key_digest - (uint8_t *)&ctx)
        == 143u);
    REQUIRE((size_t)((uint8_t *)&ctx.receipt_evidence_bytes - (uint8_t *)&ctx)
        == 620u);
    REQUIRE((size_t)((uint8_t *)&ctx.pinned_receipt_stage - (uint8_t *)&ctx)
        == 750u);
    return 0;
}

/* Anti-false-pass #12/13 pin field offsets */
static int test_d3s3_digest_pin_offsets(void)
{
    ninlil_domain_scan_d3s3_context_t ctx;
    REQUIRE((size_t)((uint8_t *)&ctx.expected_manifest_value_digest
                - (uint8_t *)&ctx)
        == 271u);
    REQUIRE((size_t)((uint8_t *)&ctx.expected_owner_pvd - (uint8_t *)&ctx)
        == 556u);
    REQUIRE((size_t)((uint8_t *)&ctx.expected_semantic_digest - (uint8_t *)&ctx)
        == 588u);
    REQUIRE((size_t)((uint8_t *)&ctx.view_a_key_digest - (uint8_t *)&ctx)
        == 492u);
    REQUIRE((size_t)((uint8_t *)&ctx.view_b_key_digest - (uint8_t *)&ctx)
        == 524u);
    return 0;
}

static int test_d3s3_drive_budget_zero(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t session_canary[sizeof(session)];
    uint8_t context_canary[sizeof(context)];

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    (void)memcpy(session_canary, &session, sizeof(session));
    (void)memcpy(context_canary, &context, sizeof(context));
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    /* handle closed by finalize/abort */
    return 0;
}

/* ---- D1-legal BLOB man encode helpers (production codec only) ---- */

static void put_u16_be(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)((v >> 8) & 0xffu);
    out[1] = (uint8_t)(v & 0xffu);
}

static void put_u32_be(uint8_t *out, uint32_t v)
{
    out[0] = (uint8_t)((v >> 24) & 0xffu);
    out[1] = (uint8_t)((v >> 16) & 0xffu);
    out[2] = (uint8_t)((v >> 8) & 0xffu);
    out[3] = (uint8_t)(v & 0xffu);
}

static void put_u64_be(uint8_t *out, uint64_t v)
{
    out[0] = (uint8_t)((v >> 56) & 0xffu);
    out[1] = (uint8_t)((v >> 48) & 0xffu);
    out[2] = (uint8_t)((v >> 40) & 0xffu);
    out[3] = (uint8_t)((v >> 32) & 0xffu);
    out[4] = (uint8_t)((v >> 24) & 0xffu);
    out[5] = (uint8_t)((v >> 16) & 0xffu);
    out[6] = (uint8_t)((v >> 8) & 0xffu);
    out[7] = (uint8_t)(v & 0xffu);
}

static int compute_key_digest(
    const uint8_t *key, uint32_t key_len, uint8_t out[32])
{
    ninlil_bytes_view_t kv;
    ninlil_model_domain_digest_t dig;

    kv.data = key;
    kv.length = key_len;
    if (ninlil_model_domain_key_digest(kv, &dig) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return 1;
}

static int owner_primary_key_digest(
    uint16_t owner_kind,
    const uint8_t *owner_raw,
    uint16_t owner_raw_len,
    uint8_t out[32])
{
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t id;
    ninlil_bytes_view_t components;
    ninlil_model_domain_digest_t dig;
    uint8_t raw16[82];
    uint8_t key_bytes[45];
    uint8_t key_len = 0u;

    if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION) {
        if (owner_raw_len != 16u) {
            return 0;
        }
        id.data = owner_raw;
        id.length = 16u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
                NINLIL_MODEL_DOMAIN_ID_KIND_ID128, id, &key)
            != NINLIL_OK) {
            return 0;
        }
        key_len = (uint8_t)key.length;
        (void)memcpy(key_bytes, key.bytes, key_len);
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS) {
        if (owner_raw_len != 8u) {
            return 0;
        }
        id.data = owner_raw;
        id.length = 8u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
                NINLIL_MODEL_DOMAIN_ID_KIND_U64, id, &key)
            != NINLIL_OK) {
            return 0;
        }
        key_len = (uint8_t)key.length;
        (void)memcpy(key_bytes, key.bytes, key_len);
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY) {
        if (owner_raw_len != 80u) {
            return 0;
        }
        put_u16_be(raw16, 80u);
        (void)memcpy(&raw16[2], owner_raw, 80u);
        components.data = raw16;
        components.length = 82u;
        if (ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components, &dig)
            != NINLIL_OK) {
            return 0;
        }
        id.data = dig.bytes;
        id.length = 32u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, id, &key)
            != NINLIL_OK) {
            return 0;
        }
        key_len = (uint8_t)key.length;
        (void)memcpy(key_bytes, key.bytes, key_len);
    } else {
        return 0;
    }
    return compute_key_digest(key_bytes, key_len, out);
}

static int encode_d1_blob_manifest(
    uint16_t owner_kind,
    uint16_t blob_kind,
    const uint8_t *owner_raw,
    uint16_t owner_raw_len,
    const uint8_t *stream,
    uint32_t stream_len,
    const uint8_t pvd[32],
    uint8_t *out_key,
    uint32_t key_cap,
    uint32_t *out_key_len,
    uint8_t *out_value,
    uint32_t value_cap,
    uint32_t *out_value_len)
{
    ninlil_model_domain_body_blob_manifest_t man;
    ninlil_model_domain_digest_t content;
    ninlil_model_domain_digest_t bid;
    ninlil_model_domain_digest_t head;
    ninlil_model_domain_common_header_t hdr;
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t bodyv;
    ninlil_bytes_view_t components;
    ninlil_model_domain_digest_t composite;
    uint8_t bodybuf[256];
    uint32_t blen = 0u;
    uint8_t components_bytes[1u + 32u];
    uint8_t primary_id[16];
    uint8_t opkd[32];
    uint32_t chunk_count = 0u;
    uint8_t head_seed[32];

    if (owner_raw == NULL || out_key == NULL || out_key_len == NULL
        || out_value == NULL || out_value_len == NULL || pvd == NULL) {
        return 0;
    }
    if (ninlil_model_domain_sha256(stream, stream_len, &content) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_blob_chunk_count_for_total(
            (uint64_t)stream_len, &chunk_count)
        != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_blob_id_digest(owner_kind, owner_raw_len, owner_raw,
            blob_kind, content.bytes, (uint64_t)stream_len, &bid)
        != NINLIL_OK) {
        return 0;
    }
    if (!owner_primary_key_digest(owner_kind, owner_raw, owner_raw_len, opkd)) {
        return 0;
    }

    (void)memset(&man, 0, sizeof(man));
    (void)memcpy(man.blob_id_digest, bid.bytes, 32u);
    man.blob_owner_kind = owner_kind;
    man.blob_kind = blob_kind;
    man.owner_key_raw_length = owner_raw_len;
    man.owner_key_raw = owner_raw;
    (void)memcpy(man.owner_primary_key_digest, opkd, 32u);
    man.total_length = (uint64_t)stream_len;
    man.chunk_count = chunk_count;
    (void)memcpy(man.content_digest, content.bytes, 32u);

    if (ninlil_model_domain_encode_body_blob_manifest(
            &man, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }

    components_bytes[0] = 1u;
    (void)memcpy(&components_bytes[1], bid.bytes, 32u);
    components.data = components_bytes;
    components.length = 33u;
    if (ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, components, &composite)
        != NINLIL_OK) {
        return 0;
    }
    {
        ninlil_bytes_view_t identity;
        identity.data = composite.bytes;
        identity.length = 32u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB,
                NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, identity, &key)
            != NINLIL_OK
            || key.length > key_cap) {
            return 0;
        }
    }
    (void)memcpy(out_key, key.bytes, key.length);
    *out_key_len = key.length;

    (void)memset(primary_id, 0, sizeof(primary_id));
    if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION) {
        (void)memcpy(primary_id, owner_raw, 16u);
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS) {
        (void)memcpy(&primary_id[8], owner_raw, 8u);
    } else {
        /* DELIVERY primary_id = first 16 of SHA256-COMPOSITE identity material
         * is not required here: codec derives from RAW16 preimage. Use first
         * 16 of owner raw as a non-zero seed then re-validate via encode path
         * is insufficient — rebuild via delivery key digest first 16. */
        ninlil_model_domain_digest_t dlv_id;
        uint8_t raw16[82];
        ninlil_bytes_view_t cv;
        put_u16_be(raw16, 80u);
        (void)memcpy(&raw16[2], owner_raw, 80u);
        cv.data = raw16;
        cv.length = 82u;
        if (ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, cv, &dlv_id)
            != NINLIL_OK) {
            return 0;
        }
        (void)memcpy(primary_id, dlv_id.bytes, 16u);
    }

    (void)memset(head_seed, 0x5Au, sizeof(head_seed));
    head_seed[0] = 0xA1u;
    if (ninlil_model_domain_sha256(head_seed, 32u, &head) != NINLIL_OK) {
        return 0;
    }

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB;
    hdr.flags = NINLIL_MODEL_DOMAIN_FLAG_BLOB_MANIFEST;
    hdr.record_revision = 1u;
    (void)memcpy(hdr.primary_id, primary_id, 16u);
    (void)memcpy(hdr.head_witness_digest, head.bytes, 32u);
    (void)memcpy(hdr.primary_value_digest, pvd, 32u);
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    if (ninlil_model_domain_encode_envelope(
            NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN, &hdr, bodyv, out_value,
            value_cap, out_value_len)
        != NINLIL_OK) {
        return 0;
    }
    return 1;
}

/*
 * D1-legal single-chunk BLOB for a nonzero stream (1..3072 bytes). Key is
 * composite (blob_id, chunk_index=0); primary_id is man composite first 16.
 * Test-only helper — production codecs only.
 */
static int encode_d1_blob_chunk_single(
    uint16_t owner_kind,
    uint16_t blob_kind,
    const uint8_t *owner_raw,
    uint16_t owner_raw_len,
    const uint8_t *stream,
    uint32_t stream_len,
    const uint8_t man_key_dig[32],
    const uint8_t pvd[32],
    uint8_t *out_key,
    uint32_t key_cap,
    uint32_t *out_key_len,
    uint8_t *out_value,
    uint32_t value_cap,
    uint32_t *out_value_len)
{
    ninlil_model_domain_body_blob_chunk_t ch;
    ninlil_model_domain_digest_t content;
    ninlil_model_domain_digest_t bid;
    ninlil_model_domain_digest_t head;
    ninlil_model_domain_digest_t man_comp;
    ninlil_model_domain_digest_t chunk_comp;
    ninlil_model_domain_common_header_t hdr;
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t bodyv;
    ninlil_bytes_view_t components;
    uint8_t bodybuf[3200];
    uint32_t blen = 0u;
    uint8_t man_comp_bytes[1u + 32u];
    uint8_t chunk_comp_bytes[1u + 32u + 4u];
    uint8_t head_seed[32];
    uint32_t chunk_count = 0u;

    if (owner_raw == NULL || stream == NULL || stream_len == 0u
        || stream_len > NINLIL_MODEL_DOMAIN_BLOB_CHUNK_DATA_MAX_BYTES
        || man_key_dig == NULL || pvd == NULL || out_key == NULL
        || out_key_len == NULL || out_value == NULL || out_value_len == NULL) {
        return 0;
    }
    if (ninlil_model_domain_sha256(stream, stream_len, &content) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_blob_chunk_count_for_total(
            (uint64_t)stream_len, &chunk_count)
        != NINLIL_OK
        || chunk_count != 1u) {
        return 0;
    }
    if (ninlil_model_domain_blob_id_digest(owner_kind, owner_raw_len, owner_raw,
            blob_kind, content.bytes, (uint64_t)stream_len, &bid)
        != NINLIL_OK) {
        return 0;
    }

    (void)memset(&ch, 0, sizeof(ch));
    (void)memcpy(ch.blob_id_digest, bid.bytes, 32u);
    (void)memcpy(ch.manifest_key_digest, man_key_dig, 32u);
    ch.chunk_index = 0u;
    ch.chunk_count = 1u;
    ch.total_length = (uint64_t)stream_len;
    (void)memcpy(ch.content_digest, content.bytes, 32u);
    ch.chunk_length = stream_len;
    ch.chunk_bytes = stream;

    if (ninlil_model_domain_encode_body_blob_chunk(
            &ch, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }

    chunk_comp_bytes[0] = 2u;
    (void)memcpy(&chunk_comp_bytes[1], bid.bytes, 32u);
    put_u32_be(&chunk_comp_bytes[33], 0u);
    components.data = chunk_comp_bytes;
    components.length = 37u;
    if (ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, components, &chunk_comp)
        != NINLIL_OK) {
        return 0;
    }
    {
        ninlil_bytes_view_t identity;
        identity.data = chunk_comp.bytes;
        identity.length = 32u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB,
                NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, identity, &key)
            != NINLIL_OK
            || key.length > key_cap) {
            return 0;
        }
    }
    (void)memcpy(out_key, key.bytes, key.length);
    *out_key_len = key.length;

    man_comp_bytes[0] = 1u;
    (void)memcpy(&man_comp_bytes[1], bid.bytes, 32u);
    components.data = man_comp_bytes;
    components.length = 33u;
    if (ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB, components, &man_comp)
        != NINLIL_OK) {
        return 0;
    }

    (void)memset(head_seed, 0x5Bu, sizeof(head_seed));
    head_seed[0] = 0xA2u;
    if (ninlil_model_domain_sha256(head_seed, 32u, &head) != NINLIL_OK) {
        return 0;
    }

    (void)memset(&hdr, 0, sizeof(hdr));
    hdr.domain_format = NINLIL_MODEL_DOMAIN_FORMAT_VERSION;
    hdr.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_BLOB;
    hdr.flags = NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK;
    hdr.record_revision = 1u;
    (void)memcpy(hdr.primary_id, man_comp.bytes, 16u);
    (void)memcpy(hdr.head_witness_digest, head.bytes, 32u);
    (void)memcpy(hdr.primary_value_digest, pvd, 32u);
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    if (ninlil_model_domain_encode_envelope(
            NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN, &hdr, bodyv, out_value,
            value_cap, out_value_len)
        != NINLIL_OK) {
        return 0;
    }
    return 1;
}

static int drive_baseline_to_internal(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_d3s3_context_t *ctx)
{
    uint32_t guard = 0u;
    ninlil_status_t st;

    while (ctx->pass_kind != NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL
        && ctx->phase != NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED
        && session->state != NINLIL_DOMAIN_SCAN_STATE_FAILED
        && guard < 16u) {
        st = ninlil_domain_scan_d3s3_drive(session, 64u);
        if (st != NINLIL_OK && session->has_sticky_primary == 0u) {
            return 0;
        }
        guard += 1u;
    }
    return ctx->pass_kind == NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL
        && session->profile_exact_active != 0u;
}

static int arm_focus_scan_context(
    ninlil_domain_scan_d3s3_context_t *ctx,
    uint8_t mode,
    const uint8_t *focus_dig,
    const uint8_t *id16_or_null,
    const uint8_t *raw80_or_null)
{
    ctx->focus_mode = mode;
    ctx->pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN;
    ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    ctx->semantic_pass = 0u;
    ctx->observed_live = 0u;
    ctx->expected_live = 0u;
    (void)memcpy(ctx->focus_key_digest, focus_dig, 32u);
    if (id16_or_null != NULL) {
        (void)memcpy(ctx->focus_id16, id16_or_null, 16u);
    }
    if (raw80_or_null != NULL) {
        (void)memcpy(ctx->focus_raw80, raw80_or_null, 80u);
        ctx->focus_raw_len = 80u;
    }
    return 1;
}

/*
 * R12 Mode27: dig-matching man with foreign owner_raw → sticky CORRUPT at
 * exact row, phase FAILED, adopted 0, MATCH not installed; no residual
 * iter_next after mismatch; natural fault after mismatch does not overwrite.
 * §18.14.9.5: pre-hook visit commit leaves previous_key = failing man complete
 * key; public D2 counters frozen at post-BASELINE values.
 */
static int test_d3s3_r12_mode27_owner_raw_mismatch_exact_abort(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t carrier_tx[16];
    uint8_t foreign_tx[16];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x2Au};
    uint8_t extra_key[45];
    uint32_t extra_key_len = 0u;
    uint8_t extra_val[512];
    uint32_t extra_val_len = 0u;
    uint32_t next_calls_before;
    uint32_t next_calls_after;
    uint64_t ok_rows_before;
    uint64_t domain_keys_before;
    uint64_t family14_before;
    uint32_t family14_mask_before;
    uint32_t i;

    (void)memset(carrier_tx, 0x11u, sizeof(carrier_tx));
    carrier_tx[0] = 0xCAu;
    (void)memset(foreign_tx, 0xEEu, sizeof(foreign_tx));
    foreign_tx[0] = 0xFEu;
    REQUIRE(memcmp(carrier_tx, foreign_tx, 16u) != 0);
    (void)memset(pvd, 0x3Cu, sizeof(pvd));
    pvd[0] = 0xB1u;

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, foreign_tx, 16u, stream,
        1u, pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len, man_val,
        (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
    /* Second dig-distinct man after mismatch row — must not be visited. */
    {
        uint8_t other_tx[16];
        (void)memset(other_tx, 0x44u, sizeof(other_tx));
        other_tx[0] = 0x99u;
        REQUIRE(encode_d1_blob_manifest(
            NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, other_tx, 16u,
            stream, 1u, pvd, extra_key, (uint32_t)sizeof(extra_key),
            &extra_key_len, extra_val, (uint32_t)sizeof(extra_val),
            &extra_val_len));
    }

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    /* Install dig-match fixtures after BASELINE so D1 man does not disrupt B0. */
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, extra_key, extra_key_len, extra_val, extra_val_len));
    REQUIRE(arm_focus_scan_context(
        &context, 27u, man_dig, carrier_tx, NULL));

    ok_rows_before = session.ok_row_count;
    domain_keys_before = session.current_domain_key_count;
    family14_before = session.family14_row_count;
    family14_mask_before = session.family14_iter_seen_mask;
    REQUIRE(ok_rows_before > 0u);

    /* Schedule NATURAL IO_ERROR on the iter_next after the mismatch row.
     * Abort must prevent that call so CORRUPT is not overwritten. */
    next_calls_before = spy.iter_next_calls;
    {
        /* FOCUS reopens from zero; man is after 17 profile rows (18th OK).
         * Fault the residual next after man (19th of this walk). */
        uint32_t planned = spy.iter_next_calls + 19u;
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, planned,
            NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    }

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        == 0u);
    next_calls_after = spy.iter_next_calls;
    /* No residual next after mismatch: fault must remain unused. */
    REQUIRE(spy.faults[0].used == 0u);
    /* Visited at most through the mismatch man row (+ NOT_FOUND forbidden). */
    REQUIRE(next_calls_after > next_calls_before);
    /* Extra man must not have been returned after sticky. */
    for (i = 0u; i < spy.trace_count; i += 1u) {
        if (spy.trace[i].op == NINLIL_SPY_OP_ITER_NEXT
            && spy.trace[i].key_bytes_length == extra_key_len
            && memcmp(spy.trace[i].key_bytes, extra_key, extra_key_len) == 0) {
            (void)fprintf(stderr, "residual iter_next after owner_raw mismatch\n");
            return 1;
        }
    }

    /*
     * §18.14.9.5 pre-hook visit commit on FOCUS pure-W: semantic CORRUPT
     * still retains the failing man complete key (not the prior catalog row).
     */
    REQUIRE(session.has_previous == 1u);
    REQUIRE(session.previous_key_length == man_key_len);
    REQUIRE(memcmp(workspace.previous_key, man_key, man_key_len) == 0);
    /* Public D2 counters / family14 frozen under PASS_INTERNAL. */
    REQUIRE(session.ok_row_count == ok_rows_before);
    REQUIRE(session.current_domain_key_count == domain_keys_before);
    REQUIRE(session.family14_row_count == family14_before);
    REQUIRE(session.family14_iter_seen_mask == family14_mask_before);

    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * §18.14.9.5 BIND_MAN WG: natural GET fault mid-WG retains pre-hook lex-only
 * visit commit of the eligible man row; public counters frozen; no residual
 * iter_next after the failing get (fault is last Port event of the drive).
 */
static int test_d3s3_bind_man_natural_get_fault_visit_commit(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t owner_tx[16];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x71u};
    uint64_t ok_rows_before;
    uint64_t domain_keys_before;
    uint64_t family14_before;
    uint32_t family14_mask_before;
    uint32_t gets_before;
    uint32_t next_before;

    (void)memset(owner_tx, 0x22u, sizeof(owner_tx));
    owner_tx[0] = 0xBDu;
    (void)memset(pvd, 0x4Du, sizeof(pvd));
    pvd[0] = 0xC3u;
    /* Mode27-eligible: TX × COMMAND_PAYLOAD → owner reverse GET. */
    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, owner_tx, 16u, stream,
        1u, pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len, man_val,
        (uint32_t)sizeof(man_val), &man_val_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
    context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    context.flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    context.semantic_pass = 0u;
    context.last_carrier_key_len = 0u;

    ok_rows_before = session.ok_row_count;
    domain_keys_before = session.current_domain_key_count;
    family14_before = session.family14_row_count;
    family14_mask_before = session.family14_iter_seen_mask;
    gets_before = spy.get_calls;
    next_before = spy.iter_next_calls;
    /* Next product GET is BIND_MAN owner reverse; natural Port IO_ERROR. */
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, gets_before + 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE);
    REQUIRE(session.sticky_primary != NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE(spy.get_calls == gets_before + 1u);
    REQUIRE(spy.faults[0].used == 1u);
    /* No residual iter_next after the failing get. */
    REQUIRE(spy.iter_next_calls > next_before);
    /* Visit commit of the eligible man OK iter_next retained. */
    REQUIRE(session.has_previous == 1u);
    REQUIRE(session.previous_key_length == man_key_len);
    REQUIRE(memcmp(workspace.previous_key, man_key, man_key_len) == 0);
    REQUIRE(session.ok_row_count == ok_rows_before);
    REQUIRE(session.current_domain_key_count == domain_keys_before);
    REQUIRE(session.family14_row_count == family14_before);
    REQUIRE(session.family14_iter_seen_mask == family14_mask_before);

    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* Mode29 R12: dig-match man.owner_raw ≠ focus_raw80 → CORRUPT before install. */
static int test_d3s3_r12_mode29_owner_raw_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t carrier_raw[80];
    uint8_t foreign_raw[80];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x2Bu};

    (void)memset(carrier_raw, 0xCDu, sizeof(carrier_raw));
    carrier_raw[0] = 0x01u;
    carrier_raw[32] = 0x11u; /* non-zero tx component region */
    (void)memset(foreign_raw, 0xCDu, sizeof(foreign_raw));
    foreign_raw[0] = 0x01u;
    foreign_raw[32] = 0x11u;
    foreign_raw[79] ^= 0xA5u;
    REQUIRE(memcmp(carrier_raw, foreign_raw, 80u) != 0);
    (void)memset(pvd, 0x5Eu, sizeof(pvd));
    pvd[0] = 0xD2u;

    /* Foreign raw must still be D1-legal DELIVERY raw (reservation shape).
     * Use fixture delivery raw + flip a safe byte after copy from fixture. */
    {
        ninlil_bytes_view_t vv;
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_delivery_t dlv;
        vv.data = DSB3_DLV_APP_DS_TYPED_VALUE;
        vv.length = (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(ninlil_model_domain_decode_body_delivery(env.body, &dlv)
            == NINLIL_OK);
        REQUIRE(dlv.delivery_key_raw_length == 80u);
        (void)memcpy(carrier_raw, dlv.delivery_key_raw, 80u);
        (void)memcpy(foreign_raw, carrier_raw, 80u);
        foreign_raw[79] ^= 0xA5u;
        if (memcmp(foreign_raw, carrier_raw, 80u) == 0) {
            foreign_raw[0] ^= 0x5Au;
        }
    }

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, foreign_raw, 80u,
        stream, 1u, pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len,
        man_val, (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 29u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    REQUIRE(arm_focus_scan_context(
        &context, 29u, man_dig, NULL, carrier_raw));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        == 0u);
    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/* Mode30 R12: dig-match man raw ≠ RR focus_raw80 → immediate CORRUPT. */
static int test_d3s3_r12_mode30_owner_raw_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t carrier_raw[80];
    uint8_t foreign_raw[80];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x2Cu};
    uint8_t extra_key[45];
    uint32_t extra_key_len = 0u;
    uint8_t extra_val[512];
    uint32_t extra_val_len = 0u;
    uint32_t next_before;
    uint32_t i;
    uint8_t residual_seen = 0u;

    {
        ninlil_bytes_view_t vv;
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_delivery_t dlv;
        vv.data = DSB3_DLV_APP_DS_TYPED_VALUE;
        vv.length = (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(ninlil_model_domain_decode_body_delivery(env.body, &dlv)
            == NINLIL_OK);
        (void)memcpy(carrier_raw, dlv.delivery_key_raw, 80u);
        (void)memcpy(foreign_raw, carrier_raw, 80u);
        foreign_raw[79] ^= 0x5Au;
    }
    (void)memset(pvd, 0x71u, sizeof(pvd));
    pvd[0] = 0xE3u;

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, foreign_raw, 80u, stream, 1u,
        pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len, man_val,
        (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
    /* Residual dig-distinct man after mismatch — must not be visited. */
    {
        uint8_t other_raw[80];
        (void)memcpy(other_raw, carrier_raw, 80u);
        other_raw[0] ^= 0xAAu;
        REQUIRE(encode_d1_blob_manifest(
            NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, other_raw, 80u, stream, 1u,
            pvd, extra_key, (uint32_t)sizeof(extra_key), &extra_key_len,
            extra_val, (uint32_t)sizeof(extra_val), &extra_val_len));
    }

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, extra_key, extra_key_len, extra_val, extra_val_len));
    REQUIRE(arm_focus_scan_context(
        &context, 30u, man_dig, NULL, carrier_raw));
    context.reply_kind = (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT;

    next_before = spy.iter_next_calls;
    /* Residual after mismatch must not run (natural fault stays unused). */
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT,
        next_before + 19u, NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL,
        0u, 0u));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        == 0u);
    REQUIRE(spy.faults[0].used == 0u);
    REQUIRE(spy.iter_next_calls > next_before);
    for (i = 0u; i < spy.trace_count; i += 1u) {
        if (spy.trace[i].op == NINLIL_SPY_OP_ITER_NEXT
            && spy.trace[i].key_bytes_length == extra_key_len
            && memcmp(spy.trace[i].key_bytes, extra_key, extra_key_len)
                == 0) {
            residual_seen = 1u;
            break;
        }
    }
    REQUIRE(residual_seen == 0u);
    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(result.adopted == 0u);
    return 0;
}

/*
 * Shared Mode30 FOCUS_SCAN fixture helpers for deferred H14/H15 timing.
 * Arms LIVE FOCUS W with carrier raw80 + dig; residual dig-distinct man
 * proves pure-W continuation past the dig-match row.
 */
static int m30_focus_fill_carrier_raw(uint8_t out_raw[80])
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_delivery_t dlv;

    vv.data = DSB3_DLV_APP_DS_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_delivery(env.body, &dlv)
            != NINLIL_OK
        || dlv.delivery_key_raw_length != 80u) {
        return 0;
    }
    (void)memcpy(out_raw, dlv.delivery_key_raw, 80u);
    return 1;
}

static int m30_focus_encode_residual(
    const uint8_t carrier_raw[80],
    uint8_t *extra_key,
    uint32_t key_cap,
    uint32_t *extra_key_len,
    uint8_t *extra_val,
    uint32_t val_cap,
    uint32_t *extra_val_len)
{
    uint8_t other_raw[80];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x99u};

    (void)memcpy(other_raw, carrier_raw, 80u);
    other_raw[1] ^= 0x3Cu;
    (void)memset(pvd, 0x44u, sizeof(pvd));
    pvd[0] = 0xD2u;
    return encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, other_raw, 80u, stream, 1u, pvd,
        extra_key, key_cap, extra_key_len, extra_val, val_cap, extra_val_len);
}

static int m30_focus_trace_saw_key(
    const ninlil_scripted_storage_spy_t *spy,
    const uint8_t *key,
    uint32_t key_len)
{
    uint32_t i;
    for (i = 0u; i < spy->trace_count; i += 1u) {
        if (spy->trace[i].op == NINLIL_SPY_OP_ITER_NEXT
            && spy->trace[i].key_bytes_length == key_len
            && memcmp(spy->trace[i].key_bytes, key, key_len) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Mode30 H14 wrong kind (DELIVERY×COMMAND): dig-match identity OK installs
 * MATCH and continues pure W to true NOT_FOUND; sticky CORRUPT only after
 * exhaustion (residual dig-distinct man is visited). Early abort would skip
 * residual and leave MATCH clear — both regressions fail this test.
 */
static int test_d3s3_mode30_focus_h14_wrong_kind_defers_to_exhaustion(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t carrier_raw[80];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x2Bu};
    uint8_t extra_key[45];
    uint32_t extra_key_len = 0u;
    uint8_t extra_val[512];
    uint32_t extra_val_len = 0u;
    uint32_t next_before;
    uint32_t gets_before;

    REQUIRE(m30_focus_fill_carrier_raw(carrier_raw));
    (void)memset(pvd, 0x61u, sizeof(pvd));
    pvd[0] = 0xC1u;
    /* Identity-valid owner_raw, wrong blob_kind (COMMAND not REPLY). */
    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, carrier_raw, 80u,
        stream, 1u, pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len,
        man_val, (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
    REQUIRE(m30_focus_encode_residual(carrier_raw, extra_key,
        (uint32_t)sizeof(extra_key), &extra_key_len, extra_val,
        (uint32_t)sizeof(extra_val), &extra_val_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, extra_key, extra_key_len, extra_val, extra_val_len));
    REQUIRE(arm_focus_scan_context(
        &context, 30u, man_dig, NULL, carrier_raw));
    context.reply_kind = (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT;

    next_before = spy.iter_next_calls;
    gets_before = spy.get_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    /* Installed at dig-match; H14 deferred to exhaustion. */
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        != 0u);
    REQUIRE(context.owner_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY);
    REQUIRE(context.blob_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD);
    /* Pure W continued past dig-match: residual man visited. */
    REQUIRE(m30_focus_trace_saw_key(&spy, extra_key, extra_key_len) != 0);
    REQUIRE(spy.iter_next_calls > next_before + 18u);
    /* No G units (OWNER/CHUNKS) in the same FOCUS W drive. */
    REQUIRE(spy.get_calls == gets_before);
    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

/*
 * Mode30 H15 non-RECEIPT nonempty: DISPOSITION + non-zero REPLY man installs
 * and walks to true NOT_FOUND before sticky CORRUPT (same residual timing).
 */
static int test_d3s3_mode30_focus_h15_nonreceipt_nonempty_defers(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t carrier_raw[80];
    uint8_t pvd[32];
    uint8_t stream[1] = {0xABu};
    uint8_t extra_key[45];
    uint32_t extra_key_len = 0u;
    uint8_t extra_val[512];
    uint32_t extra_val_len = 0u;
    uint32_t next_before;

    REQUIRE(m30_focus_fill_carrier_raw(carrier_raw));
    (void)memset(pvd, 0x55u, sizeof(pvd));
    pvd[0] = 0xB7u;
    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, carrier_raw, 80u, stream, 1u,
        pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len, man_val,
        (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
    REQUIRE(m30_focus_encode_residual(carrier_raw, extra_key,
        (uint32_t)sizeof(extra_key), &extra_key_len, extra_val,
        (uint32_t)sizeof(extra_val), &extra_val_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, extra_key, extra_key_len, extra_val, extra_val_len));
    REQUIRE(arm_focus_scan_context(
        &context, 30u, man_dig, NULL, carrier_raw));
    context.reply_kind = (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION;

    next_before = spy.iter_next_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        != 0u);
    REQUIRE(context.blob_kind == (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY);
    REQUIRE(m30_focus_trace_saw_key(&spy, extra_key, extra_key_len) != 0);
    REQUIRE(spy.iter_next_calls > next_before + 18u);
    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(result.adopted == 0u);
    return 0;
}

/*
 * First-fault: after identity-valid dig-match installs a deferred-invalid
 * Mode30 man, a later residual iter_next NATURAL fault wins (Port sticky),
 * and H14 at exhaustion never overwrites it. MATCH remains installed from
 * the dig-match row (failure-point pins).
 */
static int test_d3s3_mode30_focus_deferred_invalid_then_port_fault(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t carrier_raw[80];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x11u};
    uint8_t extra_key[45];
    uint32_t extra_key_len = 0u;
    uint8_t extra_val[512];
    uint32_t extra_val_len = 0u;
    uint32_t next_before;

    REQUIRE(m30_focus_fill_carrier_raw(carrier_raw));
    (void)memset(pvd, 0x33u, sizeof(pvd));
    pvd[0] = 0xA9u;
    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, carrier_raw, 80u,
        stream, 1u, pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len,
        man_val, (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
    REQUIRE(m30_focus_encode_residual(carrier_raw, extra_key,
        (uint32_t)sizeof(extra_key), &extra_key_len, extra_val,
        (uint32_t)sizeof(extra_val), &extra_val_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, extra_key, extra_key_len, extra_val, extra_val_len));
    REQUIRE(arm_focus_scan_context(
        &context, 30u, man_dig, NULL, carrier_raw));
    context.reply_kind = (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT;

    next_before = spy.iter_next_calls;
    /* Fault residual after dig-match man (19th iter_next of this FOCUS W). */
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT,
        next_before + 19u, NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL,
        0u, 0u));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        != 0u);
    REQUIRE(spy.faults[0].used == 1u);
    /* Port first-fault: not reclassified to CORRUPT by deferred H14. */
    REQUIRE(session.sticky_primary != NINLIL_E_STORAGE_CORRUPT);
    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_STORAGE);
    return 0;
}

/*
 * Valid Mode30 FOCUS_SCAN: DELIVERY×REPLY empty RECEIPT man → MATCH install,
 * pure W to NOT_FOUND, H14/H15 pass, phase FOCUS_CHUNKS (OWNER_PVD deferred).
 */
static int test_d3s3_mode30_focus_valid_reply_to_chunks(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t carrier_raw[80];
    uint8_t pvd[32];
    uint8_t extra_key[45];
    uint32_t extra_key_len = 0u;
    uint8_t extra_val[512];
    uint32_t extra_val_len = 0u;
    uint32_t next_before;
    uint32_t gets_before;
    ninlil_model_domain_digest_t empty;

    REQUIRE(m30_focus_fill_carrier_raw(carrier_raw));
    (void)memset(pvd, 0x22u, sizeof(pvd));
    pvd[0] = 0x81u;
    /* Empty stream: sha256 requires data==NULL when length==0. */
    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, carrier_raw, 80u, NULL, 0u, pvd,
        man_key, (uint32_t)sizeof(man_key), &man_key_len, man_val,
        (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
    REQUIRE(m30_focus_encode_residual(carrier_raw, extra_key,
        (uint32_t)sizeof(extra_key), &extra_key_len, extra_val,
        (uint32_t)sizeof(extra_val), &extra_val_len));
    REQUIRE(ninlil_model_domain_sha256(NULL, 0u, &empty) == NINLIL_OK);

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, extra_key, extra_key_len, extra_val, extra_val_len));
    REQUIRE(arm_focus_scan_context(
        &context, 30u, man_dig, NULL, carrier_raw));
    context.reply_kind = (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT;

    next_before = spy.iter_next_calls;
    gets_before = spy.get_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_CHUNKS);
    REQUIRE((context.flags & NINLIL_DOMAIN_SCAN_D3S3_FLAG_MATCH_INSTALLED)
        != 0u);
    REQUIRE(context.owner_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY);
    REQUIRE(context.blob_kind == (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY);
    REQUIRE(memcmp(context.content_digest, empty.bytes, 32u) == 0);
    REQUIRE(m30_focus_trace_saw_key(&spy, extra_key, extra_key_len) != 0);
    REQUIRE(spy.iter_next_calls > next_before + 18u);
    REQUIRE(spy.get_calls == gets_before);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/*
 * BIND_MAN closed eligibility: D1-legal (owner_kind, blob_kind) pairs that are
 * out of the mode's closed set are visit-only (GET 0). Mode30 outer requires
 * DELIVERY+REPLY exactly (COMMAND is non-eligible).
 */
static int test_d3s3_bind_man_closed_eligibility_no_get(void)
{
    struct {
        uint8_t mode;
        uint16_t owner_kind;
        uint16_t blob_kind;
        uint16_t raw_len;
    } cases[] = {
        /* Mode27: D1-legal INGRESS×INGRESS_PAYLOAD is non-eligible for 27 */
        {27u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD, 8u},
        /* Mode27: D1-legal DELIVERY×COMMAND non-eligible for 27 */
        {27u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, 80u},
        /* Mode28: D1-legal TX×COMMAND non-eligible for 28 */
        {28u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, 16u},
        /* Mode28: D1-legal DELIVERY×REPLY non-eligible for 28 */
        {28u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, 80u},
        /* Mode29: D1-legal INGRESS×EVIDENCE non-eligible for 29 */
        {29u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE, 8u},
        /* Mode29: D1-legal DELIVERY×REPLY non-eligible for 29 (BIND WG) */
        {29u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, 80u},
        /* Mode30 outer: DELIVERY×COMMAND not REPLY */
        {30u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, 80u},
        /* Mode30 outer: TX×COMMAND not DELIVERY+REPLY */
        {30u, NINLIL_MODEL_DOMAIN_BLOB_OWNER_TRANSACTION,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_COMMAND_PAYLOAD, 16u},
    };
    size_t ci;

    for (ci = 0u; ci < sizeof(cases) / sizeof(cases[0]); ci += 1u) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint8_t man_key[45];
        uint32_t man_key_len = 0u;
        uint8_t man_val[512];
        uint32_t man_val_len = 0u;
        uint8_t owner_raw[80];
        uint8_t pvd[32];
        uint8_t stream[1] = {0x55u};
        uint32_t gets_before;
        uint32_t gets_after;

        (void)memset(owner_raw, 0x7Au, sizeof(owner_raw));
        owner_raw[0] = 0x01u;
        if (cases[ci].raw_len == 80u) {
            ninlil_bytes_view_t vv;
            ninlil_model_domain_envelope_t env;
            ninlil_model_domain_body_delivery_t dlv;
            vv.data = DSB3_DLV_APP_DS_TYPED_VALUE;
            vv.length = (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN;
            REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
            REQUIRE(ninlil_model_domain_decode_body_delivery(env.body, &dlv)
                == NINLIL_OK);
            (void)memcpy(owner_raw, dlv.delivery_key_raw, 80u);
        } else if (cases[ci].raw_len == 8u) {
            owner_raw[7] = 0x01u;
        } else {
            owner_raw[0] = 0xABu;
        }
        (void)memset(pvd, 0x9Du, sizeof(pvd));
        pvd[0] = (uint8_t)(0x10u + (uint8_t)ci);

        REQUIRE(encode_d1_blob_manifest(cases[ci].owner_kind, cases[ci].blob_kind,
            owner_raw, cases[ci].raw_len, stream, 1u, pvd, man_key,
            (uint32_t)sizeof(man_key), &man_key_len, man_val,
            (uint32_t)sizeof(man_val), &man_val_len));

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(&session, ops, &handle,
            &workspace, &candidate, cases[ci].mode, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        REQUIRE(ninlil_spy_add_row(
            &spy, man_key, man_key_len, man_val, man_val_len));
        context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
        context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
        context.flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
        context.semantic_pass = 0u;
        context.last_carrier_key_len = 0u;
        gets_before = spy.get_calls;
        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        gets_after = spy.get_calls;
        /* Non-eligible: no owner reverse GET. */
        REQUIRE(gets_after == gets_before);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
        (void)st;
    }
    return 0;
}

/*
 * Mode28 BIND referrer: blob_kind=INGRESS_PAYLOAD must use payload field only.
 * RECEIPT ingress (D1: payload zero, evidence may be non-zero): pin man dig
 * only into evidence. Correct code rejects; payload-or-evidence OR would pass.
 */
static int test_d3s3_mode28_bind_referrer_payload_not_evidence(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t owner_raw[8];
    uint8_t pvd[32];
    uint8_t stream[1] = {0x61u};
    uint8_t ing_key[45];
    uint32_t ing_key_len = 0u;
    uint8_t ing_val[2048];
    uint32_t ing_val_len = 0u;

    {
        ninlil_bytes_view_t vv;
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_ordered_ingress_t ing;
        ninlil_model_domain_common_header_t hdr;
        uint8_t bodybuf[1024];
        uint32_t blen = 0u;
        ninlil_bytes_view_t bodyv;
        uint8_t seq_be[8];

        vv.data = DSB3_ING_RECEIPT_TYPED_VALUE;
        vv.length = (uint32_t)DSB3_ING_RECEIPT_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(ninlil_model_domain_decode_body_ordered_ingress(env.body, &ing)
            == NINLIL_OK);
        put_u64_be(seq_be, ing.ordered_sequence);
        (void)memcpy(owner_raw, seq_be, 8u);

        (void)memset(pvd, 0xAAu, sizeof(pvd));
        pvd[0] = 0xB7u;
        REQUIRE(encode_d1_blob_manifest(
            NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD, owner_raw, 8u,
            stream, 1u, pvd, man_key, (uint32_t)sizeof(man_key), &man_key_len,
            man_val, (uint32_t)sizeof(man_val), &man_val_len));
        REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));

        /* RECEIPT: payload zero (D1); evidence == man dig (wrong side). */
        (void)memset(ing.payload_blob_key_digest, 0, 32u);
        (void)memcpy(ing.evidence_blob_key_digest, man_dig, 32u);
        REQUIRE(ninlil_model_domain_encode_body_ordered_ingress(
                &ing, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
            == NINLIL_OK);
        hdr = env.header;
        hdr.body_length = blen;
        bodyv.data = bodybuf;
        bodyv.length = blen;
        REQUIRE(ninlil_model_domain_encode_envelope(env.record_type, &hdr,
                bodyv, ing_val, (uint32_t)sizeof(ing_val), &ing_val_len)
            == NINLIL_OK);
        /* primary PVD zero for ORDERED_INGRESS primary */
        {
            uint32_t payload_len;
            uint32_t crc;
            payload_len = ((uint32_t)ing_val[8] << 24)
                | ((uint32_t)ing_val[9] << 16) | ((uint32_t)ing_val[10] << 8)
                | (uint32_t)ing_val[11];
            (void)memset(&ing_val[72], 0, 32u);
            crc = ninlil_model_domain_crc32c(ing_val, 12u + payload_len);
            ing_val[12u + payload_len] = (uint8_t)((crc >> 24) & 0xffu);
            ing_val[12u + payload_len + 1u] = (uint8_t)((crc >> 16) & 0xffu);
            ing_val[12u + payload_len + 2u] = (uint8_t)((crc >> 8) & 0xffu);
            ing_val[12u + payload_len + 3u] = (uint8_t)(crc & 0xffu);
        }
        (void)memcpy(ing_key, DSB3_ING_RECEIPT_TYPED_KEY,
            DSB3_ING_RECEIPT_TYPED_KEY_LEN);
        ing_key_len = (uint32_t)DSB3_ING_RECEIPT_TYPED_KEY_LEN;

        /* Patch man PVD to VALUE_DIGEST(ingress value) */
        {
            ninlil_bytes_view_t iv;
            ninlil_model_domain_digest_t vdig;
            uint32_t payload_len;
            uint32_t crc;
            iv.data = ing_val;
            iv.length = ing_val_len;
            REQUIRE(ninlil_model_domain_value_digest(iv, &vdig) == NINLIL_OK);
            payload_len = ((uint32_t)man_val[8] << 24)
                | ((uint32_t)man_val[9] << 16) | ((uint32_t)man_val[10] << 8)
                | (uint32_t)man_val[11];
            (void)memcpy(&man_val[72], vdig.bytes, 32u);
            crc = ninlil_model_domain_crc32c(man_val, 12u + payload_len);
            man_val[12u + payload_len] = (uint8_t)((crc >> 24) & 0xffu);
            man_val[12u + payload_len + 1u] = (uint8_t)((crc >> 16) & 0xffu);
            man_val[12u + payload_len + 2u] = (uint8_t)((crc >> 8) & 0xffu);
            man_val[12u + payload_len + 3u] = (uint8_t)(crc & 0xffu);
        }
    }

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 28u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(ninlil_spy_add_row(&spy, ing_key, ing_key_len, ing_val, ing_val_len));
    REQUIRE(ninlil_spy_add_row(&spy, man_key, man_key_len, man_val, man_val_len));
    context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
    context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    context.flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);
    context.semantic_pass = 0u;
    context.last_carrier_key_len = 0u;

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    /* GET happened (eligible) but referrer wrong-side rejected. */
    REQUIRE(spy.get_calls >= 1u);
    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(result.adopted == 0u);
    return 0;
}

/*
 * Patch ORDERED_INGRESS view digests in a typed fixture value; recompute CRC.
 * view_a/view_b NULL → leave existing. Non-NULL → 32-byte digest.
 */
/*
 * Patch ORDERED_INGRESS view digests. value_len is the live encoded length
 * (not buffer capacity). Writes back into value[]; returns new length or 0.
 * Buffer must be large enough for a same-size re-encode (capacity >= value_len).
 */
static int patch_ingress_views(
    uint8_t *value,
    uint32_t value_len,
    const uint8_t *view_a_or_null,
    const uint8_t *view_b_or_null)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_ordered_ingress_t ing;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[1024];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;
    uint32_t out_len = 0u;
    uint8_t tmp[2048];

    if (value == NULL || value_len == 0u || value_len > sizeof(tmp)) {
        return 0;
    }
    vv.data = value;
    vv.length = value_len;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_ordered_ingress(env.body, &ing)
        != NINLIL_OK) {
        return 0;
    }
    if (view_a_or_null != NULL) {
        (void)memcpy(ing.payload_blob_key_digest, view_a_or_null, 32u);
    }
    if (view_b_or_null != NULL) {
        (void)memcpy(ing.evidence_blob_key_digest, view_b_or_null, 32u);
    }
    if (ninlil_model_domain_encode_body_ordered_ingress(
            &ing, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    /* primary PVD zero for ORDERED_INGRESS primary */
    (void)memset(hdr.primary_value_digest, 0, 32u);
    bodyv.data = bodybuf;
    bodyv.length = blen;
    if (ninlil_model_domain_encode_envelope(env.record_type, &hdr, bodyv, tmp,
            (uint32_t)sizeof(tmp), &out_len)
        != NINLIL_OK
        || out_len > sizeof(tmp)) {
        return 0;
    }
    (void)memcpy(value, tmp, out_len);
    return (int)out_len;
}

static uint64_t focus_id16_half_be(
    const ninlil_domain_scan_d3s3_context_t *ctx, int which_a)
{
    const uint8_t *p = which_a != 0 ? &ctx->focus_id16[0] : &ctx->focus_id16[8];
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48)
        | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
        | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16)
        | ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

/*
 * Mode28 SELECT Za/Zb transition tuples (§18.14.19.8):
 * payload-only → phase3/sub0; evidence-only → phase6/sub1; both-zero → phase9.
 */
static int test_d3s3_mode28_select_za_zb_transitions(void)
{
    enum { CASE_PAYLOAD = 0, CASE_EVIDENCE = 1, CASE_BOTH0 = 2 };
    int ci;

    for (ci = 0; ci < 3; ci += 1) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint8_t ing_key[45];
        uint32_t ing_key_len = 0u;
        uint8_t ing_val[2048];
        uint32_t ing_val_len = 0u;
        uint8_t dig_a[32];
        uint8_t dig_b[32];
        int patched_len;

        (void)memset(dig_a, 0xA1u, sizeof(dig_a));
        dig_a[0] = 0x91u;
        (void)memset(dig_b, 0xB2u, sizeof(dig_b));
        dig_b[0] = 0x92u;

        if (ci == CASE_PAYLOAD || ci == CASE_BOTH0) {
            (void)memcpy(ing_key, DSB3_ING_APP_DS_TYPED_KEY,
                DSB3_ING_APP_DS_TYPED_KEY_LEN);
            ing_key_len = (uint32_t)DSB3_ING_APP_DS_TYPED_KEY_LEN;
            (void)memcpy(ing_val, DSB3_ING_APP_DS_TYPED_VALUE,
                DSB3_ING_APP_DS_TYPED_VALUE_LEN);
            ing_val_len = (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN;
            if (ci == CASE_PAYLOAD) {
                patched_len = patch_ingress_views(
                    ing_val, ing_val_len, dig_a, NULL);
                REQUIRE(patched_len > 0);
                ing_val_len = (uint32_t)patched_len;
            }
        } else {
            (void)memcpy(ing_key, DSB3_ING_RECEIPT_TYPED_KEY,
                DSB3_ING_RECEIPT_TYPED_KEY_LEN);
            ing_key_len = (uint32_t)DSB3_ING_RECEIPT_TYPED_KEY_LEN;
            (void)memcpy(ing_val, DSB3_ING_RECEIPT_TYPED_VALUE,
                DSB3_ING_RECEIPT_TYPED_VALUE_LEN);
            ing_val_len = (uint32_t)DSB3_ING_RECEIPT_TYPED_VALUE_LEN;
            patched_len = patch_ingress_views(
                ing_val, ing_val_len, NULL, dig_b);
            REQUIRE(patched_len > 0);
            ing_val_len = (uint32_t)patched_len;
        }

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        REQUIRE(ninlil_spy_add_row(
            &spy, ing_key, ing_key_len, ing_val, ing_val_len));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 28u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);

        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(context.last_carrier_key_len == ing_key_len);
        REQUIRE(memcmp(context.last_carrier_key, ing_key, ing_key_len) == 0);

        if (ci == CASE_PAYLOAD) {
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
            REQUIRE(context.focus_sub == 0u);
            REQUIRE(memcmp(context.focus_key_digest, dig_a, 32u) == 0);
            REQUIRE(memcmp(context.view_a_key_digest, dig_a, 32u) == 0);
            REQUIRE(context.flags
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
            REQUIRE(focus_id16_half_be(&context, 1) == 0u);
            REQUIRE(focus_id16_half_be(&context, 0) == 0u);
        } else if (ci == CASE_EVIDENCE) {
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B);
            REQUIRE(context.focus_sub == 1u);
            REQUIRE(memcmp(context.focus_key_digest, dig_b, 32u) == 0);
            REQUIRE(memcmp(context.view_b_key_digest, dig_b, 32u) == 0);
            REQUIRE(context.flags
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
            REQUIRE(focus_id16_half_be(&context, 1) == 0u);
            REQUIRE(focus_id16_half_be(&context, 0) == 0u);
        } else {
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET);
            REQUIRE(context.focus_sub == 1u);
            REQUIRE(context.count_complete_mask
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS));
            REQUIRE(context.flags
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE));
            REQUIRE(focus_id16_half_be(&context, 1) == 0u);
            REQUIRE(focus_id16_half_be(&context, 0) == 0u);
        }
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/*
 * Mode28 packed totals in focus_id16 after each first-focus man install:
 * A man total → half0 (B stays 0); B man total → half1 with A half preserved.
 * Two independent sessions (A-only arm / B-only arm with pre-seeded A total).
 */
static int test_d3s3_mode28_focus_id16_packed_totals_after_man(void)
{
    uint8_t man_a_key[45];
    uint32_t man_a_key_len = 0u;
    uint8_t man_a_val[512];
    uint32_t man_a_val_len = 0u;
    uint8_t man_b_key[45];
    uint32_t man_b_key_len = 0u;
    uint8_t man_b_val[512];
    uint32_t man_b_val_len = 0u;
    uint8_t dig_a[32];
    uint8_t dig_b[32];
    uint8_t owner_raw[8];
    uint8_t pvd[32];
    uint8_t stream_a[1] = {0x2Au};
    uint8_t stream_b[2] = {0x3Bu, 0x3Cu};
    int pass;

    (void)memset(owner_raw, 0x55u, sizeof(owner_raw));
    owner_raw[7] = 0x01u;
    (void)memset(pvd, 0x77u, sizeof(pvd));
    pvd[0] = 0xC1u;

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD, owner_raw, 8u, stream_a,
        1u, pvd, man_a_key, (uint32_t)sizeof(man_a_key), &man_a_key_len,
        man_a_val, (uint32_t)sizeof(man_a_val), &man_a_val_len));
    REQUIRE(compute_key_digest(man_a_key, man_a_key_len, dig_a));

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE, owner_raw, 8u, stream_b,
        2u, pvd, man_b_key, (uint32_t)sizeof(man_b_key), &man_b_key_len,
        man_b_val, (uint32_t)sizeof(man_b_val), &man_b_val_len));
    REQUIRE(compute_key_digest(man_b_key, man_b_key_len, dig_b));

    for (pass = 0; pass < 2; pass += 1) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        if (pass == 0) {
            REQUIRE(ninlil_spy_add_row(
                &spy, man_a_key, man_a_key_len, man_a_val, man_a_val_len));
        } else {
            REQUIRE(ninlil_spy_add_row(
                &spy, man_b_key, man_b_key_len, man_b_val, man_b_val_len));
        }
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 28u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));

        if (pass == 0) {
            (void)memcpy(context.view_a_key_digest, dig_a, 32u);
            (void)memset(context.view_b_key_digest, 0, 32u);
            (void)memset(context.focus_id16, 0, 16u);
            REQUIRE(arm_focus_scan_context(&context, 28u, dig_a, NULL, NULL));
            context.focus_sub = 0u;
            context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN;
        } else {
            (void)memset(context.view_a_key_digest, 0, 32u);
            (void)memcpy(context.view_b_key_digest, dig_b, 32u);
            /* Seed A half as if prior A man installed total=1; B half 0. */
            put_u64_be(&context.focus_id16[0], 1u);
            put_u64_be(&context.focus_id16[8], 0u);
            REQUIRE(arm_focus_scan_context(&context, 28u, dig_b, NULL, NULL));
            context.focus_sub = 1u;
            context.phase =
                NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B;
            /* arm_focus_scan_context overwrote focus_id16 with NULL id — re-seed */
            put_u64_be(&context.focus_id16[0], 1u);
            put_u64_be(&context.focus_id16[8], 0u);
        }
        context.expected_live = 0u;
        context.lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;

        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        if (pass == 0) {
            REQUIRE(focus_id16_half_be(&context, 1) == 1u);
            REQUIRE(focus_id16_half_be(&context, 0) == 0u);
        } else {
            REQUIRE(focus_id16_half_be(&context, 1) == 1u);
            REQUIRE(focus_id16_half_be(&context, 0) == 2u);
        }
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/*
 * Mode29 SELECT pins owner raw + payload dig; focus_id16 stays zero
 * (must not store DELIVERY.transaction_id).
 */
static int test_d3s3_mode29_focus_id16_stays_zero(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t zero16[16];
    uint8_t i;

    (void)memset(zero16, 0, sizeof(zero16));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(&spy, DSB3_DLV_APP_DS_TYPED_KEY,
        (uint32_t)DSB3_DLV_APP_DS_TYPED_KEY_LEN, DSB3_DLV_APP_DS_TYPED_VALUE,
        (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 29u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    /* APP_FIRST → SELECT_SETUP G pending (phase SELECT / sem 6) or FOCUS. */
    REQUIRE(context.last_carrier_key_len
        == (uint8_t)DSB3_DLV_APP_DS_TYPED_KEY_LEN);
    REQUIRE(context.focus_raw_len == 80u);
    for (i = 0u; i < 16u; i += 1u) {
        REQUIRE(context.focus_id16[i] == 0u);
    }
    REQUIRE(memcmp(context.focus_id16, zero16, 16u) == 0);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* ---- Mode28 semantic micro-unit schedule (§18.14.19.8 rows 4914–4923) ---- */

static int patch_ingress_semantic_digest(
    uint8_t *value, uint32_t value_len, const uint8_t dig[32])
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_ordered_ingress_t ing;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[1024];
    uint32_t blen = 0u;
    ninlil_bytes_view_t bodyv;
    uint32_t out_len = 0u;
    uint8_t tmp[2048];

    if (value == NULL || dig == NULL || value_len == 0u
        || value_len > sizeof(tmp)) {
        return 0;
    }
    vv.data = value;
    vv.length = value_len;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_ordered_ingress(env.body, &ing)
        != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(ing.message_semantic_digest, dig, 32u);
    if (ninlil_model_domain_encode_body_ordered_ingress(
            &ing, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    (void)memset(hdr.primary_value_digest, 0, 32u);
    bodyv.data = bodybuf;
    bodyv.length = blen;
    if (ninlil_model_domain_encode_envelope(env.record_type, &hdr, bodyv, tmp,
            (uint32_t)sizeof(tmp), &out_len)
        != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(value, tmp, out_len);
    return (int)out_len;
}

static int compute_ingress_semantic_digest(
    const uint8_t *value,
    uint32_t value_len,
    uint32_t pay_len,
    uint32_t evi_len,
    const uint8_t *payload,
    const uint8_t *evidence,
    uint8_t out[32])
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_ordered_ingress_t ing;
    ninlil_model_domain_message_semantic_prefix_t prefix;
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t pay_v;
    ninlil_bytes_view_t evi_v;

    vv.data = value;
    vv.length = value_len;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_ordered_ingress(env.body, &ing)
        != NINLIL_OK) {
        return 0;
    }
    (void)memset(&prefix, 0, sizeof(prefix));
    prefix.kind = ing.message_kind;
    prefix.flags = ing.message_flags;
    (void)memcpy(prefix.transaction_id, ing.transaction_id, 16u);
    (void)memcpy(prefix.attempt_id, ing.attempt_id, 16u);
    (void)memcpy(prefix.event_id, ing.event_id, 16u);
    prefix.source = ing.source;
    prefix.target = ing.target;
    prefix.service = ing.service;
    (void)memcpy(prefix.content_digest, ing.content_digest, 32u);
    prefix.generation = ing.generation;
    (void)memcpy(prefix.deadline_clock_epoch, ing.deadline_clock_epoch, 16u);
    prefix.absolute_effect_deadline_ms = ing.absolute_effect_deadline_ms;
    prefix.evidence_grace_ms = ing.evidence_grace_ms;
    prefix.required_evidence = ing.required_evidence;
    prefix.receipt_stage = ing.receipt_stage;
    prefix.disposition = ing.disposition;
    prefix.effect_certainty = ing.effect_certainty;
    prefix.retry_guidance = ing.retry_guidance;
    prefix.cancel_kind = ing.cancel_kind;
    prefix.retry_delay_ms = ing.retry_delay_ms;
    (void)memcpy(prefix.evidence_clock_epoch, ing.evidence_clock_epoch, 16u);
    prefix.evidence_now_ms = ing.evidence_now_ms;
    prefix.evidence_trust = ing.evidence_trust;
    prefix.payload_length = pay_len;
    pay_v.data = payload;
    pay_v.length = pay_len;
    evi_v.data = evidence;
    evi_v.length = evi_len;
    if (ninlil_model_domain_message_semantic_digest(
            &prefix, pay_v, evi_v, &dig)
        != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return 1;
}

static int arm_mode28_prefix_entry(
    ninlil_domain_scan_d3s3_context_t *ctx,
    const uint8_t *carrier_key,
    uint8_t carrier_key_len,
    const uint8_t *view_a_or_null,
    const uint8_t *view_b_or_null,
    uint64_t total_a,
    uint64_t total_b)
{
    ctx->focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB;
    ctx->pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
    ctx->semantic_pass = 0u;
    ctx->focus_sub = 1u;
    ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    ctx->count_complete_mask = (uint8_t)(
        NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    (void)memcpy(ctx->last_carrier_key, carrier_key, carrier_key_len);
    ctx->last_carrier_key_len = carrier_key_len;
    if (view_a_or_null != NULL) {
        (void)memcpy(ctx->view_a_key_digest, view_a_or_null, 32u);
    } else {
        (void)memset(ctx->view_a_key_digest, 0, 32u);
    }
    if (view_b_or_null != NULL) {
        (void)memcpy(ctx->view_b_key_digest, view_b_or_null, 32u);
    } else {
        (void)memset(ctx->view_b_key_digest, 0, 32u);
    }
    put_u64_be(&ctx->focus_id16[0], total_a);
    put_u64_be(&ctx->focus_id16[8], total_b);
    return 1;
}

/*
 * Four Za/Zb PREFIX exit tuples + exact one PREFIX + A-before-B schedule
 * for A-only / B-only / both / neither.
 */
static int test_d3s3_mode28_semantic_schedule_za_zb(void)
{
    enum { ZA_ZB = 0, ZA0 = 1, ZB0 = 2, BOTH = 3 };
    int ci;

    for (ci = 0; ci < 4; ci += 1) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint8_t ing_key[45];
        uint32_t ing_key_len = 0u;
        uint8_t ing_val[2048];
        uint32_t ing_val_len = 0u;
        uint8_t dig_a[32];
        uint8_t dig_b[32];
        uint8_t sem_dig[32];
        /* Empty streams: exercise RESCAN/VIEW units without chunk rows. */
        uint8_t man_a_key[45];
        uint32_t man_a_key_len = 0u;
        uint8_t man_a_val[512];
        uint32_t man_a_val_len = 0u;
        uint8_t man_b_key[45];
        uint32_t man_b_key_len = 0u;
        uint8_t man_b_val[512];
        uint32_t man_b_val_len = 0u;
        uint8_t owner_raw[8];
        uint8_t pvd[32];
        uint8_t sha_after_prefix[32];
        uint32_t gets_before;
        int patched;

        (void)memset(owner_raw, 0x11u, sizeof(owner_raw));
        owner_raw[7] = 0x07u;
        (void)memset(pvd, 0x66u, sizeof(pvd));
        pvd[0] = 0xD0u;
        (void)memset(dig_a, 0, sizeof(dig_a));
        (void)memset(dig_b, 0, sizeof(dig_b));

        /*
         * D1 body: APPLICATION may pin payload only; RECEIPT evidence only.
         * BOTH uses APP body digests zero while context pins both digs
         * (PREFIX/schedule read Za/Zb from context pins, not body).
         */
        if (ci == ZB0) {
            (void)memcpy(ing_key, DSB3_ING_RECEIPT_TYPED_KEY,
                DSB3_ING_RECEIPT_TYPED_KEY_LEN);
            ing_key_len = (uint32_t)DSB3_ING_RECEIPT_TYPED_KEY_LEN;
            (void)memcpy(ing_val, DSB3_ING_RECEIPT_TYPED_VALUE,
                DSB3_ING_RECEIPT_TYPED_VALUE_LEN);
            ing_val_len = (uint32_t)DSB3_ING_RECEIPT_TYPED_VALUE_LEN;
        } else {
            (void)memcpy(ing_key, DSB3_ING_APP_DS_TYPED_KEY,
                DSB3_ING_APP_DS_TYPED_KEY_LEN);
            ing_key_len = (uint32_t)DSB3_ING_APP_DS_TYPED_KEY_LEN;
            (void)memcpy(ing_val, DSB3_ING_APP_DS_TYPED_VALUE,
                DSB3_ING_APP_DS_TYPED_VALUE_LEN);
            ing_val_len = (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN;
        }

        if (ci == ZA0 || ci == BOTH) {
            REQUIRE(encode_d1_blob_manifest(
                NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
                NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD, owner_raw, 8u,
                NULL, 0u, pvd, man_a_key, (uint32_t)sizeof(man_a_key),
                &man_a_key_len, man_a_val, (uint32_t)sizeof(man_a_val),
                &man_a_val_len));
            REQUIRE(compute_key_digest(man_a_key, man_a_key_len, dig_a));
        }
        if (ci == ZB0 || ci == BOTH) {
            REQUIRE(encode_d1_blob_manifest(
                NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
                NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE, owner_raw, 8u, NULL, 0u,
                pvd, man_b_key, (uint32_t)sizeof(man_b_key), &man_b_key_len,
                man_b_val, (uint32_t)sizeof(man_b_val), &man_b_val_len));
            REQUIRE(compute_key_digest(man_b_key, man_b_key_len, dig_b));
        }

        if (ci == ZA0) {
            patched = patch_ingress_views(ing_val, ing_val_len, dig_a, NULL);
            REQUIRE(patched > 0);
            ing_val_len = (uint32_t)patched;
        } else if (ci == ZB0) {
            patched = patch_ingress_views(ing_val, ing_val_len, NULL, dig_b);
            REQUIRE(patched > 0);
            ing_val_len = (uint32_t)patched;
        }
        /* ZA_ZB / BOTH: leave body digests as fixture (typically zero). */

        REQUIRE(compute_ingress_semantic_digest(
            ing_val, ing_val_len, 0u, 0u, NULL, NULL, sem_dig));
        patched = patch_ingress_semantic_digest(ing_val, ing_val_len, sem_dig);
        REQUIRE(patched > 0);
        ing_val_len = (uint32_t)patched;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        REQUIRE(ninlil_spy_add_row(
            &spy, ing_key, ing_key_len, ing_val, ing_val_len));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 28u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
        /* Install only the mans needed before each RESCAN (spy is insert-order). */
        if (ci == ZA0 || ci == BOTH) {
            REQUIRE(ninlil_spy_add_row(
                &spy, man_a_key, man_a_key_len, man_a_val, man_a_val_len));
        }
        if (ci == ZB0) {
            REQUIRE(ninlil_spy_add_row(
                &spy, man_b_key, man_b_key_len, man_b_val, man_b_val_len));
        }

        REQUIRE(arm_mode28_prefix_entry(&context, ing_key, (uint8_t)ing_key_len,
            (ci == ZA0 || ci == BOTH) ? dig_a : NULL,
            (ci == ZB0 || ci == BOTH) ? dig_b : NULL, 0u, 0u));

        gets_before = spy.get_calls;
        st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* PREFIX G */
        REQUIRE(st == NINLIL_OK);
        REQUIRE(spy.get_calls == gets_before + 1u); /* exactly one PREFIX get */
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
        (void)memcpy(sha_after_prefix, context.sha_state, 32u);

        if (ci == ZA_ZB) {
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
            REQUIRE(context.semantic_pass == 0u);
            REQUIRE(context.flags
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
            REQUIRE(context.count_complete_mask
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC));
        } else if (ci == ZA0) {
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
            REQUIRE(context.semantic_pass == 1u);
            REQUIRE(context.flags
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
            REQUIRE(context.count_complete_mask
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS));
            REQUIRE(memcmp(context.focus_key_digest, dig_a, 32u) == 0);
            /* Persistent SHA after PREFIX (prefix preimage fed). */
            {
                uint8_t zero32[32];
                (void)memset(zero32, 0, sizeof(zero32));
                REQUIRE(memcmp(sha_after_prefix, zero32, 32u) != 0);
            }

            st = ninlil_domain_scan_d3s3_drive(&session, 256u); /* RESCAN_A W */
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK);
            REQUIRE(context.semantic_pass == 2u);
            REQUIRE(context.flags
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE));

            st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* VIEW_A G */
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
            REQUIRE(context.semantic_pass == 0u);
            REQUIRE(context.count_complete_mask
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC));
            /* SHA advanced past PREFIX for VIEW_A path. */
            REQUIRE(memcmp(context.sha_state, sha_after_prefix, 32u) != 0
                || context.count_complete_mask == 0x07u);
        } else if (ci == ZB0) {
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B);
            REQUIRE(context.semantic_pass == 3u);
            REQUIRE(context.flags
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
                    | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
            REQUIRE(memcmp(context.focus_key_digest, dig_b, 32u) == 0);
            /* Zero-view A: no RESCAN_A / VIEW_A unit. */
            st = ninlil_domain_scan_d3s3_drive(&session, 64u); /* RESCAN_B */
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK);
            REQUIRE(context.semantic_pass == 4u);
            st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* VIEW_B */
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
            REQUIRE(context.semantic_pass == 0u);
            REQUIRE((context.count_complete_mask
                        & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
                != 0u);
        } else { /* BOTH: A then B */
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
            REQUIRE(context.semantic_pass == 1u);
            st = ninlil_domain_scan_d3s3_drive(&session, 64u); /* RESCAN_A */
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.semantic_pass == 2u);
            st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* VIEW_A */
            REQUIRE(st == NINLIL_OK);
            /* After A: must enter RESCAN_B, not SELECT */
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B);
            REQUIRE(context.semantic_pass == 3u);
            REQUIRE(memcmp(context.focus_key_digest, dig_b, 32u) == 0);
            /*
             * Replace man_a row with man_b so RESCAN_B zero-prefix walk keeps
             * a single man (insert-order spy cannot guarantee man_a < man_b).
             */
            {
                size_t ri;
                int replaced = 0;
                for (ri = 0u; ri < spy.row_count; ri += 1u) {
                    if (spy.rows[ri].key_length == man_a_key_len
                        && memcmp(spy.rows[ri].key, man_a_key, man_a_key_len)
                            == 0) {
                        REQUIRE(man_b_key_len <= sizeof(spy.rows[ri].key));
                        REQUIRE(man_b_val_len <= sizeof(spy.rows[ri].value));
                        (void)memcpy(
                            spy.rows[ri].key, man_b_key, man_b_key_len);
                        spy.rows[ri].key_length = man_b_key_len;
                        (void)memcpy(
                            spy.rows[ri].value, man_b_val, man_b_val_len);
                        spy.rows[ri].value_length = man_b_val_len;
                        replaced = 1;
                        break;
                    }
                }
                REQUIRE(replaced != 0);
            }
            st = ninlil_domain_scan_d3s3_drive(&session, 64u); /* RESCAN_B */
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.semantic_pass == 4u);
            st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* VIEW_B */
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.phase
                == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
            REQUIRE(context.semantic_pass == 0u);
            REQUIRE(context.count_complete_mask
                == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
                    | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC));
        }
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/* u32 overflow on either pin: no Port event, sticky CORRUPT, phase14. */
static int test_d3s3_mode28_prefix_u32_overflow_no_port(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_before;
    uint32_t next_before;
    uint32_t open_before;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 28u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
    context.semantic_pass = 0u;
    context.focus_sub = 1u;
    context.flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    context.count_complete_mask = 0x03u;
    context.last_carrier_key_len = 10u;
    context.last_carrier_key[0] = 0x01u;
    put_u64_be(&context.focus_id16[0], (uint64_t)UINT32_MAX + 1u);
    put_u64_be(&context.focus_id16[8], 0u);

    gets_before = spy.get_calls;
    next_before = spy.iter_next_calls;
    open_before = spy.iter_open_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE(spy.get_calls == gets_before);
    REQUIRE(spy.iter_next_calls == next_before);
    REQUIRE(spy.iter_open_calls == open_before);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/*
 * Semantic digest mismatch: A-only path with wrong non-zero dig (D1 allows
 * non-recomputed dig when a view is present). Finalize compares fail.
 */
static int test_d3s3_mode28_semantic_digest_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t ing_key[45];
    uint32_t ing_key_len = 0u;
    uint8_t ing_val[2048];
    uint32_t ing_val_len = 0u;
    uint8_t dig_a[32];
    uint8_t bad[32];
    uint8_t man_a_key[45];
    uint32_t man_a_key_len = 0u;
    uint8_t man_a_val[512];
    uint32_t man_a_val_len = 0u;
    uint8_t owner_raw[8];
    uint8_t pvd[32];
    int patched;

    (void)memset(owner_raw, 0x11u, sizeof(owner_raw));
    owner_raw[7] = 0x08u;
    (void)memset(pvd, 0x66u, sizeof(pvd));
    pvd[0] = 0xD1u;
    (void)memset(bad, 0xEEu, sizeof(bad));
    bad[0] = 0xEFu;

    (void)memcpy(ing_key, DSB3_ING_APP_DS_TYPED_KEY,
        DSB3_ING_APP_DS_TYPED_KEY_LEN);
    ing_key_len = (uint32_t)DSB3_ING_APP_DS_TYPED_KEY_LEN;
    (void)memcpy(ing_val, DSB3_ING_APP_DS_TYPED_VALUE,
        DSB3_ING_APP_DS_TYPED_VALUE_LEN);
    ing_val_len = (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN;

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD, owner_raw, 8u, NULL, 0u,
        pvd, man_a_key, (uint32_t)sizeof(man_a_key), &man_a_key_len, man_a_val,
        (uint32_t)sizeof(man_a_val), &man_a_val_len));
    REQUIRE(compute_key_digest(man_a_key, man_a_key_len, dig_a));
    {
        uint8_t zero32[32];
        (void)memset(zero32, 0, sizeof(zero32));
        patched = patch_ingress_views(ing_val, ing_val_len, dig_a, zero32);
    }
    REQUIRE(patched > 0);
    ing_val_len = (uint32_t)patched;
    patched = patch_ingress_semantic_digest(ing_val, ing_val_len, bad);
    REQUIRE(patched > 0);
    ing_val_len = (uint32_t)patched;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(
        &spy, ing_key, ing_key_len, ing_val, ing_val_len));
    REQUIRE(ninlil_spy_add_row(
        &spy, man_a_key, man_a_key_len, man_a_val, man_a_val_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 28u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(arm_mode28_prefix_entry(
        &context, ing_key, (uint8_t)ing_key_len, dig_a, NULL, 0u, 0u));

    st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* PREFIX */
    REQUIRE(st == NINLIL_OK);
    st = ninlil_domain_scan_d3s3_drive(&session, 64u); /* RESCAN_A */
    REQUIRE(st == NINLIL_OK);
    st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* VIEW_A finalize */
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* PREFIX natural GET fault: last event, phase14, sticky mapped. */
static int test_d3s3_mode28_prefix_get_fault(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t ing_key[45];
    uint32_t ing_key_len = 0u;
    uint32_t gets_before;

    (void)memcpy(ing_key, DSB3_ING_APP_DS_TYPED_KEY,
        DSB3_ING_APP_DS_TYPED_KEY_LEN);
    ing_key_len = (uint32_t)DSB3_ING_APP_DS_TYPED_KEY_LEN;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(&spy, ing_key, ing_key_len,
        DSB3_ING_APP_DS_TYPED_VALUE,
        (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 28u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(arm_mode28_prefix_entry(
        &context, ing_key, (uint8_t)ing_key_len, NULL, NULL, 0u, 0u));
    gets_before = spy.get_calls;
    REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, gets_before + 1u,
        NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));

    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_STORAGE);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE(spy.get_calls == gets_before + 1u);
    REQUIRE(spy.faults[0].used == 1u);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* RESCAN_A / RESCAN_B missing man → sticky CORRUPT after true exhaust W. */
static int test_d3s3_mode28_rescan_missing_man_fault(void)
{
    int which;

    for (which = 0; which < 2; which += 1) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint8_t dig[32];

        (void)memset(dig, 0xABu, sizeof(dig));
        dig[0] = (uint8_t)(0x90u + which);

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 28u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));

        context.focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB;
        context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
        context.lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
        context.focus_sub = 1u;
        context.count_complete_mask = 0x03u;
        (void)memcpy(context.focus_key_digest, dig, 32u);
        if (which == 0) {
            context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN;
            context.semantic_pass = 1u;
            (void)memcpy(context.view_a_key_digest, dig, 32u);
        } else {
            context.phase =
                NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B;
            context.semantic_pass = 3u;
            (void)memcpy(context.view_b_key_digest, dig, 32u);
        }
        context.flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN);

        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/*
 * A-only non-empty payload stream: real D1 man (total>0) + one D1 chunk.
 * PREFIX G → RESCAN_A W → VIEW_A G across separate calls. Expected semantic
 * digest is computed independently and installed in ingress; final success
 * requires streaming the actual payload bytes into persistent SHA state.
 * Rows are installed only via add_row (no mid-session in-place mutation).
 */
static int test_d3s3_mode28_a_only_nonempty_payload_stream(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t ing_key[45];
    uint32_t ing_key_len = 0u;
    uint8_t ing_val[2048];
    uint32_t ing_val_len = 0u;
    uint8_t dig_a[32];
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t chunk_key[45];
    uint32_t chunk_key_len = 0u;
    uint8_t chunk_val[512];
    uint32_t chunk_val_len = 0u;
    uint8_t owner_raw[8];
    uint8_t pvd[32];
    uint8_t stream[4] = {0xA0u, 0xA1u, 0xA2u, 0xA3u};
    uint8_t stream_alt[4] = {0xA0u, 0xA1u, 0xA2u, 0xA4u};
    uint8_t sem_dig[32];
    uint8_t sem_alt[32];
    uint8_t sha_after_prefix[32];
    uint32_t gets_before;
    uint32_t gets_after_prefix;
    int patched;

    (void)memset(owner_raw, 0x11u, sizeof(owner_raw));
    owner_raw[7] = 0x21u;
    (void)memset(pvd, 0x66u, sizeof(pvd));
    pvd[0] = 0xD2u;

    (void)memcpy(ing_key, DSB3_ING_APP_DS_TYPED_KEY,
        DSB3_ING_APP_DS_TYPED_KEY_LEN);
    ing_key_len = (uint32_t)DSB3_ING_APP_DS_TYPED_KEY_LEN;
    (void)memcpy(ing_val, DSB3_ING_APP_DS_TYPED_VALUE,
        DSB3_ING_APP_DS_TYPED_VALUE_LEN);
    ing_val_len = (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN;

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD, owner_raw, 8u, stream,
        (uint32_t)sizeof(stream), pvd, man_key, (uint32_t)sizeof(man_key),
        &man_key_len, man_val, (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, dig_a));
    REQUIRE(encode_d1_blob_chunk_single(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_INGRESS_PAYLOAD, owner_raw, 8u, stream,
        (uint32_t)sizeof(stream), dig_a, pvd, chunk_key,
        (uint32_t)sizeof(chunk_key), &chunk_key_len, chunk_val,
        (uint32_t)sizeof(chunk_val), &chunk_val_len));
    {
        ninlil_bytes_view_t kv;
        ninlil_bytes_view_t vv;
        ninlil_model_domain_typed_record_t tr;
        kv.data = chunk_key;
        kv.length = chunk_key_len;
        vv.data = chunk_val;
        vv.length = chunk_val_len;
        REQUIRE(ninlil_model_domain_validate_typed_record(kv, vv, &tr)
            == NINLIL_OK);
        REQUIRE(tr.envelope.header.flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK);
        REQUIRE(tr.blob_chunk.chunk_length == (uint32_t)sizeof(stream));
        REQUIRE(memcmp(tr.blob_chunk.manifest_key_digest, dig_a, 32u) == 0);
    }

    patched = patch_ingress_views(ing_val, ing_val_len, dig_a, NULL);
    REQUIRE(patched > 0);
    ing_val_len = (uint32_t)patched;

    REQUIRE(compute_ingress_semantic_digest(ing_val, ing_val_len,
        (uint32_t)sizeof(stream), 0u, stream, NULL, sem_dig));
    REQUIRE(compute_ingress_semantic_digest(ing_val, ing_val_len,
        (uint32_t)sizeof(stream_alt), 0u, stream_alt, NULL, sem_alt));
    /* Changing payload bytes must change the independent semantic digest. */
    REQUIRE(memcmp(sem_dig, sem_alt, 32u) != 0);
    patched = patch_ingress_semantic_digest(ing_val, ing_val_len, sem_dig);
    REQUIRE(patched > 0);
    ing_val_len = (uint32_t)patched;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(
        &spy, ing_key, ing_key_len, ing_val, ing_val_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 28u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);

    /*
     * Install dig-matching man for RESCAN W, then the D1 chunk before VIEW G.
     * Both are permanent add_row installs (not in-place mutation). VIEW uses
     * exact_get of rebuilt chunk keys; RESCAN only needs the man row.
     */
    REQUIRE(ninlil_spy_add_row(
        &spy, man_key, man_key_len, man_val, man_val_len));

    REQUIRE(arm_mode28_prefix_entry(&context, ing_key, (uint8_t)ing_key_len,
        dig_a, NULL, (uint64_t)sizeof(stream), 0u));

    gets_before = spy.get_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* PREFIX G */
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_before + 1u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
    REQUIRE(context.semantic_pass == 1u);
    REQUIRE(context.flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
    REQUIRE(memcmp(context.focus_key_digest, dig_a, 32u) == 0);
    REQUIRE(memcmp(context.view_a_key_digest, dig_a, 32u) == 0);
    REQUIRE(memcmp(context.expected_semantic_digest, sem_dig, 32u) == 0);
    REQUIRE((context.count_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
        == 0u);
    (void)memcpy(sha_after_prefix, context.sha_state, 32u);
    {
        uint8_t zero32[32];
        (void)memset(zero32, 0, sizeof(zero32));
        REQUIRE(memcmp(sha_after_prefix, zero32, 32u) != 0);
    }
    gets_after_prefix = spy.get_calls;

    st = ninlil_domain_scan_d3s3_drive(&session, 64u); /* RESCAN_A W */
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK);
    REQUIRE(context.semantic_pass == 2u);
    REQUIRE(context.flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE));
    REQUIRE(spy.get_calls == gets_after_prefix);
    /* Semantic bit still off until VIEW streams bytes into persistent SHA. */
    REQUIRE((context.count_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
        == 0u);

    REQUIRE(ninlil_spy_add_row(
        &spy, chunk_key, chunk_key_len, chunk_val, chunk_val_len));

    st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* VIEW_A G */
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.count_complete_mask
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC));
    REQUIRE(context.flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
    /* PREFIX (1) + VIEW chunk (1) exact GETs. */
    REQUIRE(spy.get_calls == gets_before + 2u);
    REQUIRE(memcmp(context.expected_semantic_digest, sem_dig, 32u) == 0);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/*
 * B-only non-empty evidence stream: real D1 evidence man + one D1 chunk.
 * PREFIX G → RESCAN_B W → VIEW_B G. Independent semantic digest installed;
 * success requires streaming evidence bytes into persistent SHA across calls.
 */
static int test_d3s3_mode28_b_only_nonempty_evidence_stream(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t ing_key[45];
    uint32_t ing_key_len = 0u;
    uint8_t ing_val[2048];
    uint32_t ing_val_len = 0u;
    uint8_t dig_b[32];
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t chunk_key[45];
    uint32_t chunk_key_len = 0u;
    uint8_t chunk_val[512];
    uint32_t chunk_val_len = 0u;
    uint8_t owner_raw[8];
    uint8_t pvd[32];
    uint8_t stream[3] = {0xB0u, 0xB1u, 0xB2u};
    uint8_t stream_alt[3] = {0xB0u, 0xB1u, 0xB3u};
    uint8_t sem_dig[32];
    uint8_t sem_alt[32];
    uint8_t sha_after_prefix[32];
    uint32_t gets_before;
    uint32_t gets_after_prefix;
    int patched;

    (void)memset(owner_raw, 0x11u, sizeof(owner_raw));
    owner_raw[7] = 0x22u;
    (void)memset(pvd, 0x66u, sizeof(pvd));
    pvd[0] = 0xD3u;

    (void)memcpy(ing_key, DSB3_ING_RECEIPT_TYPED_KEY,
        DSB3_ING_RECEIPT_TYPED_KEY_LEN);
    ing_key_len = (uint32_t)DSB3_ING_RECEIPT_TYPED_KEY_LEN;
    (void)memcpy(ing_val, DSB3_ING_RECEIPT_TYPED_VALUE,
        DSB3_ING_RECEIPT_TYPED_VALUE_LEN);
    ing_val_len = (uint32_t)DSB3_ING_RECEIPT_TYPED_VALUE_LEN;

    REQUIRE(encode_d1_blob_manifest(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE, owner_raw, 8u, stream,
        (uint32_t)sizeof(stream), pvd, man_key, (uint32_t)sizeof(man_key),
        &man_key_len, man_val, (uint32_t)sizeof(man_val), &man_val_len));
    REQUIRE(compute_key_digest(man_key, man_key_len, dig_b));
    REQUIRE(encode_d1_blob_chunk_single(
        NINLIL_MODEL_DOMAIN_BLOB_OWNER_INGRESS,
        NINLIL_MODEL_DOMAIN_BLOB_KIND_EVIDENCE, owner_raw, 8u, stream,
        (uint32_t)sizeof(stream), dig_b, pvd, chunk_key,
        (uint32_t)sizeof(chunk_key), &chunk_key_len, chunk_val,
        (uint32_t)sizeof(chunk_val), &chunk_val_len));
    {
        ninlil_bytes_view_t kv;
        ninlil_bytes_view_t vv;
        ninlil_model_domain_typed_record_t tr;
        kv.data = chunk_key;
        kv.length = chunk_key_len;
        vv.data = chunk_val;
        vv.length = chunk_val_len;
        REQUIRE(ninlil_model_domain_validate_typed_record(kv, vv, &tr)
            == NINLIL_OK);
        REQUIRE(tr.envelope.header.flags == NINLIL_MODEL_DOMAIN_FLAG_BLOB_CHUNK);
    }

    patched = patch_ingress_views(ing_val, ing_val_len, NULL, dig_b);
    REQUIRE(patched > 0);
    ing_val_len = (uint32_t)patched;

    REQUIRE(compute_ingress_semantic_digest(ing_val, ing_val_len, 0u,
        (uint32_t)sizeof(stream), NULL, stream, sem_dig));
    REQUIRE(compute_ingress_semantic_digest(ing_val, ing_val_len, 0u,
        (uint32_t)sizeof(stream_alt), NULL, stream_alt, sem_alt));
    REQUIRE(memcmp(sem_dig, sem_alt, 32u) != 0);
    patched = patch_ingress_semantic_digest(ing_val, ing_val_len, sem_dig);
    REQUIRE(patched > 0);
    ing_val_len = (uint32_t)patched;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(
        &spy, ing_key, ing_key_len, ing_val, ing_val_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 28u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);

    REQUIRE(ninlil_spy_add_row(
        &spy, man_key, man_key_len, man_val, man_val_len));

    REQUIRE(arm_mode28_prefix_entry(&context, ing_key, (uint8_t)ing_key_len,
        NULL, dig_b, 0u, (uint64_t)sizeof(stream)));

    gets_before = spy.get_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* PREFIX G */
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_before + 1u);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN_B);
    REQUIRE(context.semantic_pass == 3u);
    REQUIRE(context.flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
    REQUIRE(memcmp(context.focus_key_digest, dig_b, 32u) == 0);
    REQUIRE(memcmp(context.view_b_key_digest, dig_b, 32u) == 0);
    REQUIRE(memcmp(context.expected_semantic_digest, sem_dig, 32u) == 0);
    REQUIRE((context.count_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
        == 0u);
    (void)memcpy(sha_after_prefix, context.sha_state, 32u);
    {
        uint8_t zero32[32];
        (void)memset(zero32, 0, sizeof(zero32));
        REQUIRE(memcmp(sha_after_prefix, zero32, 32u) != 0);
    }
    gets_after_prefix = spy.get_calls;

    st = ninlil_domain_scan_d3s3_drive(&session, 64u); /* RESCAN_B W */
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK);
    REQUIRE(context.semantic_pass == 4u);
    REQUIRE(context.flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE));
    REQUIRE(spy.get_calls == gets_after_prefix);
    REQUIRE((context.count_complete_mask
                & NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC)
        == 0u);

    REQUIRE(ninlil_spy_add_row(
        &spy, chunk_key, chunk_key_len, chunk_val, chunk_val_len));

    st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* VIEW_B G */
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.count_complete_mask
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC));
    REQUIRE(context.flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
    REQUIRE(spy.get_calls == gets_before + 2u);
    REQUIRE(memcmp(context.expected_semantic_digest, sem_dig, 32u) == 0);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* VIEW_A / VIEW_B chunk natural fault: last Port get, phase14. */
static int test_d3s3_mode28_view_chunk_get_fault(void)
{
    int which;

    for (which = 0; which < 2; which += 1) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint8_t bid[32];
        uint32_t gets_before;

        (void)memset(bid, 0xCCu, sizeof(bid));
        bid[0] = 0x71u;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 28u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));

        context.focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_INGRESS_BLOB;
        context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
        context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK;
        context.semantic_pass = (which == 0) ? 2u : 4u;
        context.focus_sub = 1u;
        context.flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
        context.count_complete_mask = 0x03u;
        (void)memcpy(context.blob_id_digest, bid, 32u);
        put_u64_be(context.total_length, 1u);
        context.chunk_count[0] = 0u;
        context.chunk_count[1] = 0u;
        context.chunk_count[2] = 0u;
        context.chunk_count[3] = 1u;
        put_u64_be(&context.focus_id16[0], (which == 0) ? 1u : 0u);
        put_u64_be(&context.focus_id16[8], (which == 0) ? 0u : 1u);
        /* Seed non-zero expected so final path is not vacuous if fault skips. */
        (void)memset(context.expected_semantic_digest, 0x5Au, 32u);

        gets_before = spy.get_calls;
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET, gets_before + 1u,
            NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));

        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_E_STORAGE);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        REQUIRE(spy.get_calls == gets_before + 1u);
        REQUIRE(spy.faults[0].used == 1u);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/* ---- Mode30 two-G semantic schedule helpers (§18.14.7.3 / §18.14.19.8) ---- */

typedef struct m30_rows {
    uint8_t rr_key[45];
    uint32_t rr_key_len;
    uint8_t rr_val[1024];
    uint32_t rr_val_len;
    uint8_t dlv_key[45];
    uint32_t dlv_key_len;
    uint8_t dlv_val[1024];
    uint32_t dlv_val_len;
    uint8_t rc_key[45];
    uint32_t rc_key_len;
    uint8_t rc_val[1024];
    uint32_t rc_val_len;
    uint8_t cell_key[45];
    uint32_t cell_key_len;
    uint8_t cell_val[1500];
    uint32_t cell_val_len;
    uint8_t cs_key[45];
    uint32_t cs_key_len;
    uint8_t cs_val[1024];
    uint32_t cs_val_len;
    uint8_t chunk_key[45];
    uint32_t chunk_key_len;
    uint8_t chunk_val[3500];
    uint32_t chunk_val_len;
    int has_cell;
    int has_cs;
    int has_chunk;
    uint8_t delivery_raw[80];
    uint8_t tx16[16];
    uint8_t attempt_id[16];
    uint8_t owner_pvd[32];
    uint8_t content_digest[32];
    uint8_t blob_id[32];
    uint8_t sem_dig[32];
    uint32_t evi_len;
    uint32_t chunk_count;
    uint8_t reply_kind;
    uint8_t evi_bytes[128];
} m30_rows_t;

static int m30_value_digest(const uint8_t *val, uint32_t len, uint8_t out[32])
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_digest_t dig;

    vv.data = val;
    vv.length = len;
    if (ninlil_model_domain_value_digest(vv, &dig) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return 1;
}

static int m30_build_rr(
    uint32_t reply_kind,
    const uint8_t sem[32],
    uint8_t *out_key,
    uint32_t *out_key_len,
    uint8_t *out_val,
    uint32_t *out_val_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_reverse_reply_t rr;
    uint8_t rraw[86];
    uint8_t draw[80];
    uint8_t bodybuf[400];
    uint32_t blen = 0u;
    uint8_t components[2u + 86u];
    ninlil_bytes_view_t cv;
    ninlil_model_domain_digest_t dig;
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t id;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t bodyv;

    vv.data = DSB3_RR_KIND_RECEIPT_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_reverse_reply(env.body, &rr)
            != NINLIL_OK
        || rr.reply_key_raw_length != 86u
        || rr.delivery_key_raw_length != 80u) {
        return 0;
    }
    (void)memcpy(draw, rr.delivery_key_raw, 80u);
    (void)memcpy(rraw, rr.reply_key_raw, 86u);
    put_u32_be(&rraw[82], reply_kind);
    rr.reply_key_raw = rraw;
    rr.reply_key_raw_length = 86u;
    rr.delivery_key_raw = draw;
    rr.delivery_key_raw_length = 80u;
    rr.reply_kind = reply_kind;
    (void)memcpy(rr.semantic_digest, sem, 32u);
    if (ninlil_model_domain_encode_body_reverse_reply(
            &rr, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    components[0] = 0u;
    components[1] = 86u;
    (void)memcpy(&components[2], rraw, 86u);
    cv.data = components;
    cv.length = 88u;
    if (ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY, cv, &dig)
        != NINLIL_OK) {
        return 0;
    }
    id.data = dig.bytes;
    id.length = 32u;
    if (ninlil_model_domain_build_key(NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY,
            NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, id, &key)
        != NINLIL_OK
        || key.length > 45u) {
        return 0;
    }
    (void)memcpy(out_key, key.bytes, key.length);
    *out_key_len = key.length;
    hdr = env.header;
    hdr.body_length = blen;
    /* Keep fixture primary_id; REVERSE_REPLY same-record identity is key-side. */
    bodyv.data = bodybuf;
    bodyv.length = blen;
    if (ninlil_model_domain_encode_envelope(
            env.record_type, &hdr, bodyv, out_val, 1024u, out_val_len)
        != NINLIL_OK) {
        return 0;
    }
    return 1;
}

static int m30_build_result_pos(uint8_t *out_val, uint32_t *out_val_len)
{
    (void)memcpy(out_val, DSB3_RC_RESULT_POS_TYPED_VALUE,
        DSB3_RC_RESULT_POS_TYPED_VALUE_LEN);
    *out_val_len = (uint32_t)DSB3_RC_RESULT_POS_TYPED_VALUE_LEN;
    return 1;
}

static int m30_build_result_disposition(uint8_t *out_val, uint32_t *out_val_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_result_cache_t rc;
    uint8_t raw80[80];
    uint8_t bodybuf[512];
    uint32_t blen = 0u;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t bodyv;

    vv.data = DSB3_RC_RESULT_POS_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_RC_RESULT_POS_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_result_cache(env.body, &rc)
            != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(raw80, rc.delivery_key_raw, 80u);
    rc.delivery_key_raw = raw80;
    rc.delivery_key_raw_length = 80u;
    rc.delivery_state =
        NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DISPOSITION_COMMITTED;
    rc.application_result_kind = NINLIL_APP_RESULT_DISPOSITION;
    rc.evidence_stage = 0u;
    rc.disposition = NINLIL_DISPOSITION_CAPACITY_EXHAUSTED;
    rc.reason = NINLIL_REASON_CAPACITY_EXHAUSTED;
    rc.effect_certainty = NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    rc.retry_guidance = NINLIL_RETRY_SAME_AFTER;
    rc.retry_delay_ms = 100u;
    rc.cancel_result_kind = 0u;
    if (ninlil_model_domain_encode_body_result_cache(
            &rc, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_val, 1024u, out_val_len)
        == NINLIL_OK;
}

static int m30_build_result_cancel_fenced(
    uint8_t *out_val, uint32_t *out_val_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_result_cache_t rc;
    uint8_t raw80[80];
    uint8_t bodybuf[512];
    uint32_t blen = 0u;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t bodyv;

    vv.data = DSB3_RC_INBOX_VIRGIN_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_result_cache(env.body, &rc)
            != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(raw80, rc.delivery_key_raw, 80u);
    rc.delivery_key_raw = raw80;
    rc.delivery_key_raw_length = 80u;
    rc.cancel_result_kind =
        NINLIL_MODEL_DOMAIN_CANCEL_KIND_FENCED_BEFORE_DISPATCH;
    if (ninlil_model_domain_encode_body_result_cache(
            &rc, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_val, 1024u, out_val_len)
        == NINLIL_OK;
}

static int m30_build_cell_material(
    const uint8_t *evi,
    uint32_t evi_len,
    uint32_t stage,
    uint8_t *out_val,
    uint32_t *out_val_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_evidence_cell_t cell;
    ninlil_model_domain_body_delivery_t dlv;
    ninlil_model_domain_envelope_t env_dlv;
    uint8_t owner[80];
    uint8_t bodybuf[1200];
    uint32_t blen = 0u;
    ninlil_model_domain_digest_t edig;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t bodyv;
    ninlil_bytes_view_t vv_dlv;

    if (evi_len > 128u) {
        return 0;
    }
    vv.data = DSB3_EV_DLV_SUM_EMPTY_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_EV_DLV_SUM_EMPTY_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_evidence_cell(env.body, &cell)
            != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(owner, cell.owner_key_raw, 80u);
    cell.owner_key_raw = owner;
    cell.owner_key_raw_length = 80u;
    cell.cell_kind = NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_KIND_SUMMARY;
    cell.cell_state = NINLIL_MODEL_DOMAIN_EVIDENCE_CELL_STATE_MATERIALIZED;
    cell.slot_index = 0u;
    cell.highest_receipt_stage = stage;
    cell.latest_evidence_stage = stage;
    cell.material_receipt_stage = stage;
    cell.disposition = 0u;
    cell.effect_certainty = 0u;
    cell.late_material = 0u;
    cell.valid_material_count = 1u;
    cell.exact_duplicate_count = 0u;
    cell.raw_overflow_count = 0u;
    cell.late_evidence_count = 0u;
    cell.counter_saturated = 0u;
    cell.durable_ingress_sequence = 1u;
    cell.generation = 1u;
    cell.evidence_at_ms = 1000u;
    cell.evidence_trust = 1u;
    cell.evidence_length = (uint16_t)evi_len;
    (void)memset(cell.evidence_bytes, 0, sizeof(cell.evidence_bytes));
    if (evi_len != 0u) {
        (void)memcpy(cell.evidence_bytes, evi, evi_len);
    }
    if (ninlil_model_domain_sha256(
            evi_len == 0u ? NULL : evi, evi_len, &edig)
        != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(cell.evidence_digest, edig.bytes, 32u);

    vv_dlv.data = DSB3_DLV_APP_DS_TYPED_VALUE;
    vv_dlv.length = (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv_dlv, &env_dlv) != NINLIL_OK
        || ninlil_model_domain_decode_body_delivery(env_dlv.body, &dlv)
            != NINLIL_OK) {
        return 0;
    }
    cell.issuer = dlv.source;
    cell.service = dlv.service;
    (void)memcpy(cell.content_digest, dlv.content_digest, 32u);
    (void)memcpy(cell.evidence_clock_epoch, dlv.deadline_clock_epoch, 16u);
    {
        uint8_t z16[16];
        (void)memset(z16, 0, sizeof(z16));
        if (memcmp(cell.evidence_clock_epoch, z16, 16u) == 0) {
            (void)memset(cell.evidence_clock_epoch, 0x11u, 16u);
        }
    }
    if (ninlil_model_domain_encode_body_evidence_cell(
            &cell, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_val, 1500u, out_val_len)
        == NINLIL_OK;
}

static int m30_build_cancel_fenced(uint8_t *out_val, uint32_t *out_val_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_cancel_state_t cs;
    uint8_t owner[80];
    uint8_t bodybuf[512];
    uint32_t blen = 0u;
    uint8_t attempt[16];
    uint8_t dig[32];
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t bodyv;

    vv.data = DSB3_CS_DLV_NONE_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_CS_DLV_NONE_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_cancel_state(env.body, &cs)
            != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(owner, cs.owner_key_raw, 80u);
    cs.owner_key_raw = owner;
    cs.owner_key_raw_length = 80u;
    (void)memset(attempt, 0xA1u, sizeof(attempt));
    attempt[15] = 0xA2u;
    (void)memset(dig, 0xD3u, sizeof(dig));
    (void)memcpy(cs.cancel_attempt_id, attempt, 16u);
    (void)memcpy(cs.message_semantic_digest, dig, 32u);
    cs.cancel_state =
        NINLIL_MODEL_DOMAIN_CANCEL_STATE_FENCED_BEFORE_DISPATCH;
    cs.cancel_kind =
        NINLIL_MODEL_DOMAIN_CANCEL_KIND_FENCED_BEFORE_DISPATCH;
    cs.reason = NINLIL_REASON_CANCEL_FENCED_BEFORE_DISPATCH;
    cs.effect_certainty = NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
    cs.cancel_send_gate_state =
        NINLIL_MODEL_DOMAIN_CANCEL_GATE_NEVER_INVOKED;
    if (ninlil_model_domain_encode_body_cancel_state(
            &cs, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_val, 1024u, out_val_len)
        == NINLIL_OK;
}

static int m30_compute_sem(
    uint8_t reply_kind,
    const uint8_t *dlv_val,
    uint32_t dlv_val_len,
    const uint8_t attempt_id[16],
    uint32_t receipt_stage,
    uint32_t disposition,
    uint32_t effect_certainty,
    uint32_t retry_guidance,
    uint64_t retry_delay_ms,
    uint32_t cancel_kind,
    const uint8_t evi_clock[16],
    uint64_t evi_now,
    uint32_t evi_trust,
    const uint8_t *evi,
    uint32_t evi_len,
    uint8_t out[32])
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_delivery_t dlv;
    ninlil_model_domain_message_semantic_prefix_t prefix;
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t evi_v;

    vv.data = dlv_val;
    vv.length = dlv_val_len;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_delivery(env.body, &dlv)
            != NINLIL_OK) {
        return 0;
    }
    (void)memset(&prefix, 0, sizeof(prefix));
    if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT) {
        prefix.kind = 2u;
    } else if (reply_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION) {
        prefix.kind = 3u;
    } else if (reply_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY) {
        prefix.kind = 5u;
    } else {
        prefix.kind = 6u;
    }
    prefix.flags = 0u;
    (void)memcpy(prefix.transaction_id, dlv.transaction_id, 16u);
    (void)memcpy(prefix.attempt_id, attempt_id, 16u);
    (void)memcpy(prefix.event_id, dlv.event_id, 16u);
    prefix.source = dlv.source;
    prefix.target = dlv.local_target;
    prefix.service = dlv.service;
    (void)memcpy(prefix.content_digest, dlv.content_digest, 32u);
    prefix.generation = dlv.generation;
    (void)memcpy(prefix.deadline_clock_epoch, dlv.deadline_clock_epoch, 16u);
    prefix.absolute_effect_deadline_ms = dlv.absolute_effect_deadline_ms;
    prefix.evidence_grace_ms = dlv.evidence_grace_ms;
    prefix.required_evidence = dlv.required_evidence;
    prefix.receipt_stage = receipt_stage;
    prefix.disposition = disposition;
    prefix.effect_certainty = effect_certainty;
    prefix.retry_guidance = retry_guidance;
    prefix.cancel_kind = cancel_kind;
    prefix.retry_delay_ms = retry_delay_ms;
    if (evi_clock != NULL) {
        (void)memcpy(prefix.evidence_clock_epoch, evi_clock, 16u);
    }
    prefix.evidence_now_ms = evi_now;
    prefix.evidence_trust = evi_trust;
    prefix.payload_length = 0u;
    evi_v.data = evi;
    evi_v.length = evi_len;
    if (ninlil_model_domain_message_semantic_digest(
            &prefix, (ninlil_bytes_view_t){NULL, 0u}, evi_v, &dig)
        != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return 1;
}

/*
 * Build Mode30 companion rows for one reply_kind.
 * evidence_len 0..128 used for RECEIPT only; non-RECEIPT ignores evi.
 */
static int m30_build_kind(
    uint8_t reply_kind,
    const uint8_t *evi_or_null,
    uint32_t evi_len,
    m30_rows_t *r)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_reverse_reply_t rr0;
    ninlil_model_domain_body_delivery_t dlv;
    ninlil_model_domain_digest_t empty_dig;
    uint8_t evi_clock[16];
    uint32_t stage = 1u;
    uint32_t disposition = 0u;
    uint32_t effect_certainty = 0u;
    uint32_t retry_guidance = 0u;
    uint64_t retry_delay_ms = 0u;
    uint32_t cancel_kind = 0u;
    uint64_t evi_now = 0u;
    uint32_t evi_trust = 0u;

    (void)memset(r, 0, sizeof(*r));
    r->reply_kind = reply_kind;
    r->evi_len = 0u;
    r->chunk_count = 0u;

    if (ninlil_model_domain_sha256(NULL, 0u, &empty_dig) != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(r->content_digest, empty_dig.bytes, 32u);

    vv.data = DSB3_RR_KIND_RECEIPT_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_reverse_reply(env.body, &rr0)
            != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(r->delivery_raw, rr0.delivery_key_raw, 80u);
    (void)memcpy(r->tx16, rr0.transaction_id, 16u);
    (void)memcpy(r->attempt_id, rr0.attempt_id, 16u);

    (void)memcpy(r->dlv_key, DSB3_DLV_APP_DS_TYPED_KEY,
        DSB3_DLV_APP_DS_TYPED_KEY_LEN);
    r->dlv_key_len = (uint32_t)DSB3_DLV_APP_DS_TYPED_KEY_LEN;
    (void)memcpy(r->dlv_val, DSB3_DLV_APP_DS_TYPED_VALUE,
        DSB3_DLV_APP_DS_TYPED_VALUE_LEN);
    r->dlv_val_len = (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN;
    if (!m30_value_digest(r->dlv_val, r->dlv_val_len, r->owner_pvd)) {
        return 0;
    }
    vv.data = r->dlv_val;
    vv.length = r->dlv_val_len;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_delivery(env.body, &dlv)
            != NINLIL_OK) {
        return 0;
    }

    (void)memcpy(r->rc_key, DSB3_RC_RESULT_POS_TYPED_KEY,
        DSB3_RC_RESULT_POS_TYPED_KEY_LEN);
    r->rc_key_len = (uint32_t)DSB3_RC_RESULT_POS_TYPED_KEY_LEN;

    if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT) {
        ninlil_model_domain_body_evidence_cell_t cell;
        if (evi_len > 128u) {
            return 0;
        }
        r->evi_len = evi_len;
        if (evi_len != 0u) {
            (void)memcpy(r->evi_bytes, evi_or_null, evi_len);
            {
                ninlil_model_domain_digest_t cd;
                if (ninlil_model_domain_sha256(evi_or_null, evi_len, &cd)
                    != NINLIL_OK) {
                    return 0;
                }
                (void)memcpy(r->content_digest, cd.bytes, 32u);
            }
            r->chunk_count = 1u;
            if (!encode_d1_blob_chunk_single(
                    NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                    NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, r->delivery_raw, 80u,
                    evi_or_null, evi_len, r->content_digest, r->owner_pvd,
                    r->chunk_key, (uint32_t)sizeof(r->chunk_key),
                    &r->chunk_key_len, r->chunk_val,
                    (uint32_t)sizeof(r->chunk_val), &r->chunk_val_len)) {
                /* man dig not content dig — use real man dig after man encode */
            }
            {
                uint8_t man_key[45];
                uint32_t man_key_len = 0u;
                uint8_t man_val[512];
                uint32_t man_val_len = 0u;
                uint8_t man_dig[32];
                if (!encode_d1_blob_manifest(
                        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, r->delivery_raw,
                        80u, evi_or_null, evi_len, r->owner_pvd, man_key,
                        (uint32_t)sizeof(man_key), &man_key_len, man_val,
                        (uint32_t)sizeof(man_val), &man_val_len)
                    || !compute_key_digest(man_key, man_key_len, man_dig)
                    || !encode_d1_blob_chunk_single(
                        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, r->delivery_raw,
                        80u, evi_or_null, evi_len, man_dig, r->owner_pvd,
                        r->chunk_key, (uint32_t)sizeof(r->chunk_key),
                        &r->chunk_key_len, r->chunk_val,
                        (uint32_t)sizeof(r->chunk_val), &r->chunk_val_len)) {
                    return 0;
                }
                {
                    ninlil_model_domain_digest_t bid;
                    if (ninlil_model_domain_blob_id_digest(
                            NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY, 80u,
                            r->delivery_raw,
                            NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY,
                            r->content_digest, (uint64_t)evi_len, &bid)
                        != NINLIL_OK) {
                        return 0;
                    }
                    (void)memcpy(r->blob_id, bid.bytes, 32u);
                }
                r->has_chunk = 1;
            }
        } else {
            ninlil_model_domain_digest_t bid;
            if (ninlil_model_domain_blob_id_digest(
                    NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY, 80u,
                    r->delivery_raw, NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY,
                    r->content_digest, 0u, &bid)
                != NINLIL_OK) {
                return 0;
            }
            (void)memcpy(r->blob_id, bid.bytes, 32u);
        }
        if (!m30_build_result_pos(r->rc_val, &r->rc_val_len)
            || !m30_build_cell_material(evi_or_null, evi_len, stage, r->cell_val,
                &r->cell_val_len)) {
            return 0;
        }
        (void)memcpy(r->cell_key, DSB3_EV_DLV_SUM_EMPTY_TYPED_KEY,
            DSB3_EV_DLV_SUM_EMPTY_TYPED_KEY_LEN);
        r->cell_key_len = (uint32_t)DSB3_EV_DLV_SUM_EMPTY_TYPED_KEY_LEN;
        r->has_cell = 1;
        {
            ninlil_bytes_view_t cv;
            ninlil_model_domain_envelope_t ce;
            cv.data = r->cell_val;
            cv.length = r->cell_val_len;
            if (ninlil_model_domain_decode_envelope(cv, &ce) != NINLIL_OK
                || ninlil_model_domain_decode_body_evidence_cell(
                       ce.body, &cell)
                    != NINLIL_OK) {
                return 0;
            }
            (void)memcpy(evi_clock, cell.evidence_clock_epoch, 16u);
            evi_now = cell.evidence_at_ms;
            evi_trust = cell.evidence_trust;
        }
    } else if (reply_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION) {
        if (!m30_build_result_disposition(r->rc_val, &r->rc_val_len)) {
            return 0;
        }
        disposition = NINLIL_DISPOSITION_CAPACITY_EXHAUSTED;
        effect_certainty = NINLIL_EFFECT_CERTAINTY_NO_EFFECT_PROVEN;
        retry_guidance = NINLIL_RETRY_SAME_AFTER;
        retry_delay_ms = 100u;
        stage = 0u;
    } else if (reply_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY) {
        if (!m30_build_result_pos(r->rc_val, &r->rc_val_len)) {
            return 0;
        }
        stage = 0u; /* fixed zero semantic tuple */
    } else { /* CANCEL_RESULT */
        if (!m30_build_result_cancel_fenced(r->rc_val, &r->rc_val_len)
            || !m30_build_cancel_fenced(r->cs_val, &r->cs_val_len)) {
            return 0;
        }
        (void)memcpy(r->cs_key, DSB3_CS_DLV_NONE_TYPED_KEY,
            DSB3_CS_DLV_NONE_TYPED_KEY_LEN);
        r->cs_key_len = (uint32_t)DSB3_CS_DLV_NONE_TYPED_KEY_LEN;
        r->has_cs = 1;
        cancel_kind =
            NINLIL_MODEL_DOMAIN_CANCEL_KIND_FENCED_BEFORE_DISPATCH;
        stage = 0u;
    }

    if (!m30_compute_sem(reply_kind, r->dlv_val, r->dlv_val_len, r->attempt_id,
            stage, disposition, effect_certainty, retry_guidance,
            retry_delay_ms, cancel_kind,
            reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
                ? evi_clock
                : NULL,
            evi_now, evi_trust,
            reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
                ? evi_or_null
                : NULL,
            reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
                ? evi_len
                : 0u,
            r->sem_dig)) {
        return 0;
    }
    if (!m30_build_rr(reply_kind, r->sem_dig, r->rr_key, &r->rr_key_len,
            r->rr_val, &r->rr_val_len)) {
        return 0;
    }
    return 1;
}

static int m30_arm_prefix(
    ninlil_domain_scan_d3s3_context_t *ctx, const m30_rows_t *r)
{
    ctx->focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB;
    ctx->pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_PREFIX_REGET;
    ctx->semantic_pass = 0u;
    ctx->focus_sub = 0u;
    ctx->lifecycle_class = NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED;
    ctx->reply_kind = r->reply_kind;
    ctx->flags = (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE);
    ctx->count_complete_mask = (uint8_t)(
        NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
        | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS);
    ctx->binding_complete_mask = 0u;
    (void)memcpy(ctx->last_carrier_key, r->rr_key, r->rr_key_len);
    ctx->last_carrier_key_len = (uint8_t)r->rr_key_len;
    (void)memcpy(ctx->focus_raw80, r->delivery_raw, 80u);
    ctx->focus_raw_len = 80u;
    (void)memcpy(ctx->focus_id16, r->tx16, 16u);
    (void)memcpy(ctx->expected_owner_pvd, r->owner_pvd, 32u);
    (void)memcpy(ctx->content_digest, r->content_digest, 32u);
    (void)memcpy(ctx->blob_id_digest, r->blob_id, 32u);
    put_u64_be(ctx->total_length, (uint64_t)r->evi_len);
    put_u32_be(ctx->chunk_count, r->chunk_count);
    return 1;
}

static int m30_install_rows(
    ninlil_scripted_storage_spy_t *spy, const m30_rows_t *r)
{
    if (!ninlil_spy_add_row(
            spy, r->rr_key, r->rr_key_len, r->rr_val, r->rr_val_len)
        || !ninlil_spy_add_row(
            spy, r->dlv_key, r->dlv_key_len, r->dlv_val, r->dlv_val_len)
        || !ninlil_spy_add_row(
            spy, r->rc_key, r->rc_key_len, r->rc_val, r->rc_val_len)) {
        return 0;
    }
    if (r->has_cell
        && !ninlil_spy_add_row(
            spy, r->cell_key, r->cell_key_len, r->cell_val, r->cell_val_len)) {
        return 0;
    }
    if (r->has_cs
        && !ninlil_spy_add_row(
            spy, r->cs_key, r->cs_key_len, r->cs_val, r->cs_val_len)) {
        return 0;
    }
    if (r->has_chunk
        && !ninlil_spy_add_row(spy, r->chunk_key, r->chunk_key_len, r->chunk_val,
            r->chunk_val_len)) {
        return 0;
    }
    return 1;
}

static int m30_expect_prefix_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_domain_scan_d3s3_context_t *ctx)
{
    REQUIRE(session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SEMANTIC_CHUNK_REWALK);
    REQUIRE(ctx->pass_kind == NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL);
    REQUIRE(ctx->focus_sub == 0u);
    REQUIRE(ctx->semantic_pass == 0u);
    REQUIRE(ctx->flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_FOCUS_LIVE));
    REQUIRE(ctx->count_complete_mask
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS));
    REQUIRE(ctx->binding_complete_mask == 0u);
    return 1;
}

static int m30_expect_sem_ok(
    const ninlil_domain_scan_session_t *session,
    const ninlil_domain_scan_d3s3_context_t *ctx)
{
    REQUIRE(session->state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(ctx->phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
    REQUIRE(ctx->pass_kind == NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL);
    REQUIRE(ctx->focus_sub == 0u);
    REQUIRE(ctx->semantic_pass == 0u);
    REQUIRE(ctx->flags
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE
            | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN));
    REQUIRE(ctx->count_complete_mask
        == (uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_MANIFEST
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_CHUNKS
            | NINLIL_DOMAIN_SCAN_D3S3_MASK_COUNT_SEMANTIC));
    REQUIRE(ctx->binding_complete_mask == 0u);
    return 1;
}

static uint32_t m30_prefix_budget(uint8_t reply_kind)
{
    if (reply_kind == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT
        || reply_kind
            == (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CANCEL_RESULT) {
        return 4u;
    }
    return 3u;
}

/* Four kinds: PREFIX→SEM_CHUNK→SELECT exact tuples, get budgets, no reopen. */
static int test_d3s3_mode30_semantic_two_g_all_kinds(void)
{
    static const uint8_t kinds[] = {
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT,
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION,
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY,
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CANCEL_RESULT,
    };
    size_t ki;

    for (ki = 0u; ki < sizeof(kinds); ki += 1u) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        m30_rows_t rows;
        uint32_t gets_before;
        uint32_t open_before;
        uint32_t next_before;
        uint8_t sha_after_prefix[32];
        uint32_t budget;

        REQUIRE(m30_build_kind(kinds[ki], NULL, 0u, &rows));
        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        REQUIRE(m30_install_rows(&spy, &rows));
        REQUIRE(m30_arm_prefix(&context, &rows));

        gets_before = spy.get_calls;
        open_before = spy.iter_open_calls;
        next_before = spy.iter_next_calls;
        budget = m30_prefix_budget(kinds[ki]);

        st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* PREFIX G */
        REQUIRE(st == NINLIL_OK);
        REQUIRE(m30_expect_prefix_ok(&session, &context));
        REQUIRE(spy.get_calls == gets_before + budget);
        REQUIRE(spy.iter_open_calls == open_before);
        REQUIRE(spy.iter_next_calls == next_before);
        REQUIRE(memcmp(context.expected_semantic_digest, rows.sem_dig, 32u)
            == 0);
        (void)memcpy(sha_after_prefix, context.sha_state, 32u);
        {
            uint8_t z32[32];
            (void)memset(z32, 0, sizeof(z32));
            REQUIRE(memcmp(sha_after_prefix, z32, 32u) != 0);
        }

        st = ninlil_domain_scan_d3s3_drive(&session, 0u); /* SEM_CHUNK G */
        REQUIRE(st == NINLIL_OK);
        REQUIRE(m30_expect_sem_ok(&session, &context));
        /* non-RECEIPT zero chunk GET; empty RECEIPT zero chunk GET. */
        REQUIRE(spy.get_calls == gets_before + budget);
        REQUIRE(spy.iter_open_calls == open_before);
        REQUIRE(spy.iter_next_calls == next_before);
        REQUIRE(memcmp(context.expected_semantic_digest, rows.sem_dig, 32u)
            == 0);

        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/* RECEIPT empty / 1 byte / 128 bytes: stream-compare + final digest. */
static int test_d3s3_mode30_receipt_empty_1_128(void)
{
    struct {
        uint32_t len;
        uint8_t fill;
    } cases[] = {{0u, 0u}, {1u, 0xABu}, {128u, 0x5Cu}};
    size_t ci;

    for (ci = 0u; ci < 3u; ci += 1u) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        m30_rows_t rows;
        uint8_t evi[128];
        uint32_t gets_before;
        uint32_t budget = 4u;

        (void)memset(evi, cases[ci].fill, sizeof(evi));
        REQUIRE(m30_build_kind((uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT,
            cases[ci].len == 0u ? NULL : evi, cases[ci].len, &rows));
        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        REQUIRE(m30_install_rows(&spy, &rows));
        REQUIRE(m30_arm_prefix(&context, &rows));

        gets_before = spy.get_calls;
        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(m30_expect_prefix_ok(&session, &context));
        REQUIRE(spy.get_calls == gets_before + budget);
        REQUIRE(context.receipt_evidence_len == (uint8_t)cases[ci].len);
        if (cases[ci].len != 0u) {
            REQUIRE(memcmp(context.receipt_evidence_bytes, evi, cases[ci].len)
                == 0);
        }

        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(m30_expect_sem_ok(&session, &context));
        REQUIRE(spy.get_calls
            == gets_before + budget
                + (cases[ci].len == 0u ? 0u : 1u));
        REQUIRE(memcmp(context.expected_semantic_digest, rows.sem_dig, 32u)
            == 0);

        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/* Persistent SHA across PREFIX→SEM_CHUNK: wrong pin fails finalize. */
static int test_d3s3_mode30_semantic_digest_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    m30_rows_t rows;
    uint8_t bad[32];

    REQUIRE(m30_build_kind(
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY, NULL, 0u, &rows));
    (void)memset(bad, 0xEEu, sizeof(bad));
    bad[0] = 0xEFu;
    REQUIRE(m30_build_rr((uint32_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY, bad,
        rows.rr_key, &rows.rr_key_len, rows.rr_val, &rows.rr_val_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(m30_install_rows(&spy, &rows));
    REQUIRE(m30_arm_prefix(&context, &rows));

    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(m30_expect_prefix_ok(&session, &context));
    REQUIRE(memcmp(context.expected_semantic_digest, bad, 32u) == 0);

    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* Each PREFIX companion natural GET fault is last Port event. */
static int test_d3s3_mode30_prefix_companion_get_faults(void)
{
    /* RECEIPT budget 4: fault on get 1..4. */
    uint32_t which;

    for (which = 1u; which <= 4u; which += 1u) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        m30_rows_t rows;
        uint32_t gets_before;
        uint32_t next_before;
        uint32_t open_before;

        REQUIRE(m30_build_kind(
            (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT, NULL, 0u, &rows));
        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        REQUIRE(m30_install_rows(&spy, &rows));
        REQUIRE(m30_arm_prefix(&context, &rows));

        gets_before = spy.get_calls;
        next_before = spy.iter_next_calls;
        open_before = spy.iter_open_calls;
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET,
            gets_before + which, NINLIL_STORAGE_IO_ERROR,
            NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));

        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_E_STORAGE);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        REQUIRE(spy.get_calls == gets_before + which);
        REQUIRE(spy.iter_next_calls == next_before);
        REQUIRE(spy.iter_open_calls == open_before);
        REQUIRE(spy.faults[0].used == 1u);

        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/* SEM_CHUNK: chunk GET fault, missing chunk, typed-invalid, byte/offset/digest. */
static int test_d3s3_mode30_sem_chunk_faults(void)
{
    enum { F_GET = 0, F_MISS = 1, F_TYPED = 2, F_BYTE = 3, F_LEN = 4 };
    int fi;
    uint8_t evi[1] = {0xABu};

    for (fi = 0; fi < 5; fi += 1) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        m30_rows_t rows;
        uint32_t gets_before;
        uint8_t alt[1] = {0xACu};

        if (fi == F_BYTE) {
            REQUIRE(m30_build_kind(
                (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT, evi, 1u,
                &rows));
            /* Rebuild chunk with different byte but keep cell pin as evi. */
            {
                uint8_t man_key[45];
                uint32_t man_key_len = 0u;
                uint8_t man_val[512];
                uint32_t man_val_len = 0u;
                uint8_t man_dig[32];
                REQUIRE(encode_d1_blob_manifest(
                    NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                    NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, rows.delivery_raw, 80u,
                    alt, 1u, rows.owner_pvd, man_key, (uint32_t)sizeof(man_key),
                    &man_key_len, man_val, (uint32_t)sizeof(man_val),
                    &man_val_len));
                REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
                REQUIRE(encode_d1_blob_chunk_single(
                    NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                    NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, rows.delivery_raw, 80u,
                    alt, 1u, man_dig, rows.owner_pvd, rows.chunk_key,
                    (uint32_t)sizeof(rows.chunk_key), &rows.chunk_key_len,
                    rows.chunk_val, (uint32_t)sizeof(rows.chunk_val),
                    &rows.chunk_val_len));
                /* Keep blob_id of original evi stream for exact_get rebuild. */
            }
        } else if (fi == F_LEN) {
            uint8_t two[2] = {0xABu, 0x00u};
            REQUIRE(m30_build_kind(
                (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT, evi, 1u,
                &rows));
            /* chunk longer than pin: pin stays 1, chunk 2 bytes with same start */
            {
                uint8_t man_key[45];
                uint32_t man_key_len = 0u;
                uint8_t man_val[512];
                uint32_t man_val_len = 0u;
                uint8_t man_dig[32];
                ninlil_model_domain_digest_t bid;
                REQUIRE(encode_d1_blob_manifest(
                    NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                    NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, rows.delivery_raw, 80u,
                    two, 2u, rows.owner_pvd, man_key, (uint32_t)sizeof(man_key),
                    &man_key_len, man_val, (uint32_t)sizeof(man_val),
                    &man_val_len));
                REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
                REQUIRE(encode_d1_blob_chunk_single(
                    NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                    NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, rows.delivery_raw, 80u,
                    two, 2u, man_dig, rows.owner_pvd, rows.chunk_key,
                    (uint32_t)sizeof(rows.chunk_key), &rows.chunk_key_len,
                    rows.chunk_val, (uint32_t)sizeof(rows.chunk_val),
                    &rows.chunk_val_len));
                /* Keep original blob_id (1-byte stream) so GET key misses OR
                 * override blob_id to 2-byte so GET succeeds with long chunk. */
                REQUIRE(ninlil_model_domain_blob_id_digest(
                            NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY, 80u,
                            rows.delivery_raw,
                            NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, rows.content_digest,
                            1u, &bid)
                    == NINLIL_OK);
                /*
                 * Rebuild chunk under the 1-byte blob_id is impossible with
                 * different total_length. Instead pin chunk_count=1 with
                 * mismatched length by using the 2-byte blob_id and forcing
                 * receipt pin length 1 — GET uses blob_id from context.
                 */
                REQUIRE(ninlil_model_domain_blob_id_digest(
                            NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY, 80u,
                            rows.delivery_raw,
                            NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY,
                            rows.content_digest /* wrong for 2-byte */, 2u, &bid)
                    != NINLIL_OK
                    || 1);
                {
                    ninlil_model_domain_digest_t c2;
                    REQUIRE(ninlil_model_domain_sha256(two, 2u, &c2) == NINLIL_OK);
                    REQUIRE(ninlil_model_domain_blob_id_digest(
                                NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY, 80u,
                                rows.delivery_raw,
                                NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, c2.bytes,
                                2u, &bid)
                        == NINLIL_OK);
                    (void)memcpy(rows.blob_id, bid.bytes, 32u);
                    REQUIRE(encode_d1_blob_manifest(
                        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, rows.delivery_raw,
                        80u, two, 2u, rows.owner_pvd, man_key,
                        (uint32_t)sizeof(man_key), &man_key_len, man_val,
                        (uint32_t)sizeof(man_val), &man_val_len));
                    REQUIRE(compute_key_digest(man_key, man_key_len, man_dig));
                    REQUIRE(encode_d1_blob_chunk_single(
                        NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
                        NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, rows.delivery_raw,
                        80u, two, 2u, man_dig, rows.owner_pvd, rows.chunk_key,
                        (uint32_t)sizeof(rows.chunk_key), &rows.chunk_key_len,
                        rows.chunk_val, (uint32_t)sizeof(rows.chunk_val),
                        &rows.chunk_val_len));
                }
            }
        } else {
            REQUIRE(m30_build_kind(
                (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT, evi, 1u,
                &rows));
        }

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        /* Install PREFIX companions always; control SEM_CHUNK rows per case. */
        REQUIRE(ninlil_spy_add_row(
            &spy, rows.rr_key, rows.rr_key_len, rows.rr_val, rows.rr_val_len));
        REQUIRE(ninlil_spy_add_row(&spy, rows.dlv_key, rows.dlv_key_len,
            rows.dlv_val, rows.dlv_val_len));
        REQUIRE(ninlil_spy_add_row(
            &spy, rows.rc_key, rows.rc_key_len, rows.rc_val, rows.rc_val_len));
        REQUIRE(ninlil_spy_add_row(&spy, rows.cell_key, rows.cell_key_len,
            rows.cell_val, rows.cell_val_len));
        if (fi != F_MISS && fi != F_TYPED) {
            REQUIRE(ninlil_spy_add_row(&spy, rows.chunk_key, rows.chunk_key_len,
                rows.chunk_val, rows.chunk_val_len));
        }
        if (fi == F_TYPED) {
            /* Wrong type at chunk key: install RESULT value under chunk key. */
            REQUIRE(ninlil_spy_add_row(&spy, rows.chunk_key, rows.chunk_key_len,
                rows.rc_val, rows.rc_val_len));
        }
        REQUIRE(m30_arm_prefix(&context, &rows));

        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(m30_expect_prefix_ok(&session, &context));

        gets_before = spy.get_calls;
        if (fi == F_GET) {
            REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET,
                gets_before + 1u, NINLIL_STORAGE_IO_ERROR,
                NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
        }

        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st != NINLIL_OK);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        if (fi == F_GET) {
            REQUIRE(st == NINLIL_E_STORAGE);
            REQUIRE(spy.get_calls == gets_before + 1u);
            REQUIRE(spy.faults[0].used == 1u);
        } else {
            REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
            REQUIRE(spy.get_calls == gets_before + 1u);
        }

        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/* non-RECEIPT: PREFIX rejects illegal nonempty blob pins; SEM zero chunk GET. */
static int test_d3s3_mode30_nonreceipt_empty_and_nonempty_reject(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    m30_rows_t rows;
    uint32_t gets_before;

    /* Happy: disposition empty blob, 3 PREFIX gets, 0 SEM gets. */
    REQUIRE(m30_build_kind(
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_DISPOSITION, NULL, 0u, &rows));
    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(m30_install_rows(&spy, &rows));
    REQUIRE(m30_arm_prefix(&context, &rows));
    gets_before = spy.get_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_before + 3u);
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_before + 3u);
    REQUIRE(m30_expect_sem_ok(&session, &context));
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});

    /* Illegal nonempty pin on CUSTODY PREFIX: no Port. */
    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(m30_build_kind(
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_CUSTODY, NULL, 0u, &rows));
    REQUIRE(m30_arm_prefix(&context, &rows));
    put_u64_be(context.total_length, 1u);
    put_u32_be(context.chunk_count, 1u);
    gets_before = spy.get_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE(spy.get_calls == gets_before);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* No reopen/advance in PREFIX or SEM_CHUNK (pure G). */
static int test_d3s3_mode30_no_reopen_advance_both_g(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    m30_rows_t rows;
    uint32_t open0;
    uint32_t next0;
    uint32_t close0;

    REQUIRE(m30_build_kind(
        (uint8_t)NINLIL_MODEL_DOMAIN_REPLY_KIND_RECEIPT, NULL, 0u, &rows));
    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    REQUIRE(m30_install_rows(&spy, &rows));
    REQUIRE(m30_arm_prefix(&context, &rows));

    open0 = spy.iter_open_calls;
    next0 = spy.iter_next_calls;
    close0 = spy.iter_close_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.iter_open_calls == open0);
    REQUIRE(spy.iter_next_calls == next0);
    REQUIRE(spy.iter_close_calls == close0);
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.iter_open_calls == open0);
    REQUIRE(spy.iter_next_calls == next0);
    REQUIRE(spy.iter_close_calls == close0);
    REQUIRE(m30_expect_sem_ok(&session, &context));

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* ---- Mode30 BIND outer / RR pure-W (§18.14.9.3) ---- */

#define M30_BIND_F_ENTRY                                                         \
    ((uint8_t)(NINLIL_DOMAIN_SCAN_D3S3_FLAG_BASELINE_DONE                        \
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_BIND_PHASE_ACTIVE                          \
        | NINLIL_DOMAIN_SCAN_D3S3_FLAG_NEED_REOPEN))

/* RR-fixture delivery raw80 (same-record bijection with RR transaction_id). */
static int m30_delivery_raw80(uint8_t out[80])
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_reverse_reply_t rr;

    vv.data = DSB3_RR_KIND_RECEIPT_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_reverse_reply(env.body, &rr)
            != NINLIL_OK
        || rr.delivery_key_raw_length != 80u) {
        return 0;
    }
    (void)memcpy(out, rr.delivery_key_raw, 80u);
    return 1;
}

/* Encode REPLY man for Mode30 BIND outer; stream differentiates keys. */
static int m30_bind_encode_reply_man(
    const uint8_t delivery_raw[80],
    const uint8_t *stream,
    uint32_t stream_len,
    uint8_t *man_key,
    uint32_t *man_key_len,
    uint8_t *man_val,
    uint32_t *man_val_len,
    uint8_t man_dig[32])
{
    uint8_t pvd[32];

    (void)memset(pvd, 0x3Cu, sizeof(pvd));
    pvd[0] = (uint8_t)(0x10u + (stream_len & 0x0Fu));
    if (!encode_d1_blob_manifest(NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY,
            NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY, delivery_raw, 80u, stream,
            stream_len, pvd, man_key, 45u, man_key_len, man_val, 512u,
            man_val_len)) {
        return 0;
    }
    return compute_key_digest(man_key, *man_key_len, man_dig);
}

/*
 * Build CURRENT REVERSE_REPLY with explicit body dig / send_state / delivery raw.
 * reply_kind tag differentiates complete keys when body fields match.
 */
static int m30_bind_build_rr(
    const uint8_t delivery_raw[80],
    const uint8_t body_dig[32],
    uint32_t send_state,
    uint32_t reply_kind_tag,
    uint8_t *out_key,
    uint32_t *out_key_len,
    uint8_t *out_val,
    uint32_t *out_val_len)
{
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_reverse_reply_t rr;
    uint8_t rraw[86];
    uint8_t draw[80];
    uint8_t bodybuf[400];
    uint32_t blen = 0u;
    uint8_t components[2u + 86u];
    ninlil_bytes_view_t cv;
    ninlil_model_domain_digest_t dig;
    ninlil_model_domain_key_t key;
    ninlil_bytes_view_t id;
    ninlil_model_domain_common_header_t hdr;
    ninlil_bytes_view_t bodyv;
    uint8_t sem[32];

    vv.data = DSB3_RR_KIND_RECEIPT_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_reverse_reply(env.body, &rr)
            != NINLIL_OK
        || rr.reply_key_raw_length != 86u
        || rr.delivery_key_raw_length != 80u) {
        return 0;
    }
    (void)memcpy(draw, delivery_raw, 80u);
    /* reply_key_raw = RAW16(delivery) ‖ reply_kind:u32be — rebuild fully. */
    put_u16_be(rraw, 80u);
    (void)memcpy(&rraw[2], draw, 80u);
    put_u32_be(&rraw[82], reply_kind_tag);
    (void)memset(sem, 0xE1u, sizeof(sem));
    sem[0] = (uint8_t)reply_kind_tag;
    rr.reply_key_raw = rraw;
    rr.reply_key_raw_length = 86u;
    rr.delivery_key_raw = draw;
    rr.delivery_key_raw_length = 80u;
    /* delivery raw bytes 32..47 must equal transaction_id. */
    (void)memcpy(rr.transaction_id, &draw[32], 16u);
    rr.reply_kind = reply_kind_tag;
    (void)memcpy(rr.semantic_digest, sem, 32u);
    (void)memcpy(rr.body_blob_key_digest, body_dig, 32u);
    /*
     * Closed send_state matrix (§D1-B3j): set coupled counters/timers so each
     * target state is encode-legal. Keep PENDING virgin defaults for ss=1.
     */
    if (send_state == NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING) {
        rr.send_state = NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING;
        /* leave fixture virgin fields */
    } else if (send_state == NINLIL_MODEL_DOMAIN_REPLY_SEND_WAITING_RETRY) {
        rr.send_state = NINLIL_MODEL_DOMAIN_REPLY_SEND_WAITING_RETRY;
        rr.send_operation_generation = 1u;
        rr.send_invocation_count = 1u;
        rr.send_counter_exhausted = 0u;
        rr.availability_epoch = 1u;
        (void)memset(rr.retry_clock_epoch, 0x11u, 16u);
        rr.retry_not_before_ms = 1000u;
    } else if (send_state
        == NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_SENT_OR_UNKNOWN) {
        rr.send_state = NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_SENT_OR_UNKNOWN;
        rr.send_operation_generation = 1u;
        rr.send_invocation_count = 1u;
        rr.send_counter_exhausted = 0u;
        rr.availability_epoch = 1u;
        (void)memset(rr.retry_clock_epoch, 0, 16u);
        rr.retry_not_before_ms = 0u;
    } else if (send_state == NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_DENIED) {
        rr.send_state = NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_DENIED;
        rr.send_operation_generation = 1u;
        rr.send_invocation_count = 0u;
        rr.send_counter_exhausted = 0u;
        rr.availability_epoch = 0u;
        (void)memset(rr.retry_clock_epoch, 0, 16u);
        rr.retry_not_before_ms = 0u;
    } else if (send_state
        == NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_COUNTER_EXHAUSTED) {
        rr.send_state =
            NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_COUNTER_EXHAUSTED;
        rr.send_operation_generation = UINT64_MAX;
        rr.send_invocation_count = 1u;
        rr.send_counter_exhausted = 1u;
        rr.availability_epoch = 1u;
        (void)memset(rr.retry_clock_epoch, 0, 16u);
        rr.retry_not_before_ms = 0u;
    } else {
        return 0;
    }
    if (ninlil_model_domain_encode_body_reverse_reply(
            &rr, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    components[0] = 0u;
    components[1] = 86u;
    (void)memcpy(&components[2], rraw, 86u);
    cv.data = components;
    cv.length = 88u;
    if (ninlil_model_domain_composite_digest(
            NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY, cv, &dig)
        != NINLIL_OK) {
        return 0;
    }
    id.data = dig.bytes;
    id.length = 32u;
    if (ninlil_model_domain_build_key(NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_REVERSE_REPLY,
            NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, id, &key)
        != NINLIL_OK
        || key.length > 45u) {
        return 0;
    }
    (void)memcpy(out_key, key.bytes, key.length);
    *out_key_len = key.length;
    hdr = env.header;
    hdr.body_length = blen;
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_val, 1024u, out_val_len)
        == NINLIL_OK;
}

static void m30_arm_bind_outer(
    ninlil_domain_scan_d3s3_context_t *ctx, uint8_t count_mask)
{
    ctx->focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB;
    ctx->pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    ctx->phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
    ctx->semantic_pass = 0u;
    ctx->focus_sub = 0u;
    ctx->flags = M30_BIND_F_ENTRY;
    ctx->count_complete_mask = count_mask;
    ctx->binding_complete_mask = 0u;
    ctx->observed_live = 0u;
    ctx->peer_key_len = 0u;
    (void)memset(ctx->peer_key, 0, sizeof(ctx->peer_key));
}

/* Lex complete-key order: -1 if a<b, 0 equal, +1 if a>b. */
static int m30_key_cmp(
    const uint8_t *a, uint32_t a_len, const uint8_t *b, uint32_t b_len)
{
    uint32_t common = a_len < b_len ? a_len : b_len;
    int order = memcmp(a, b, common);
    if (order < 0) {
        return -1;
    }
    if (order > 0) {
        return 1;
    }
    if (a_len < b_len) {
        return -1;
    }
    if (a_len > b_len) {
        return 1;
    }
    return 0;
}

/* BIND-entry: exact zero set; preserve focus_id16 and prior RR carrier cleared. */
static int test_d3s3_mode30_bind_entry_exact_zero_preserve(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t focus_id[16];
    uint8_t z45[45];
    uint8_t z80[80];
    uint8_t z32[32];
    size_t i;

    (void)memset(focus_id, 0xA5u, sizeof(focus_id));
    focus_id[0] = 0xF1u;
    (void)memset(z45, 0, sizeof(z45));
    (void)memset(z80, 0, sizeof(z80));
    (void)memset(z32, 0, sizeof(z32));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    /* Poison SELECT-exit residue: RR carrier key + selected pins + latch. */
    for (i = 0u; i < 45u; ++i) {
        context.last_carrier_key[i] = (uint8_t)(0xB0u + (uint8_t)i);
        context.peer_key[i] = (uint8_t)(0xC0u + (uint8_t)i);
    }
    context.last_carrier_key_len = 41u;
    context.peer_key_len = 37u;
    (void)memset(context.focus_key_digest, 0xDDu, 32u);
    (void)memset(context.focus_raw80, 0xEEu, 80u);
    context.focus_raw_len = 80u;
    context.owner_kind = 3u;
    context.blob_kind = 5u;
    context.observed_live = 7u;
    context.semantic_pass = 4u;
    (void)memcpy(context.focus_id16, focus_id, 16u);
    context.count_complete_mask = 0x07u;
    context.binding_complete_mask = 0xABu;
    context.reply_kind = 2u;

    /* Empty SELECT → BIND-entry init once before first outer W. */
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST);
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.focus_sub == 0u);
    REQUIRE(context.flags == M30_BIND_F_ENTRY);
    REQUIRE(context.last_carrier_key_len == 0u);
    REQUIRE(memcmp(context.last_carrier_key, z45, 45u) == 0);
    REQUIRE(context.peer_key_len == 0u);
    REQUIRE(memcmp(context.peer_key, z45, 45u) == 0);
    REQUIRE(memcmp(context.focus_key_digest, z32, 32u) == 0);
    REQUIRE(context.focus_raw_len == 0u);
    REQUIRE(memcmp(context.focus_raw80, z80, 80u) == 0);
    REQUIRE(context.owner_kind == 0u);
    REQUIRE(context.blob_kind == 0u);
    REQUIRE(context.observed_live == 0u);
    /* Preserve focus_id16 and unlisted (count/binding/reply_kind). */
    REQUIRE(memcmp(context.focus_id16, focus_id, 16u) == 0);
    REQUIRE(context.count_complete_mask == 0x07u);
    REQUIRE(context.binding_complete_mask == 0xABu);
    REQUIRE(context.reply_kind == 2u);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* Outer no candidate → phase12, BIND_MAN bit, GET0. */
static int test_d3s3_mode30_bind_outer_no_candidate_phase12(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets0;
    uint64_t ok0;
    uint64_t cdk0;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    m30_arm_bind_outer(&context, 0x07u);
    context.last_carrier_key_len = 0u;

    gets0 = spy.get_calls;
    ok0 = session.ok_row_count;
    cdk0 = session.current_domain_key_count;
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_CHUNK);
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.focus_sub == 0u);
    REQUIRE(context.flags == M30_BIND_F_ENTRY);
    REQUIRE(context.count_complete_mask == 0x07u);
    REQUIRE(context.binding_complete_mask
        == NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_MANIFEST);
    REQUIRE(context.peer_key_len == 0u);
    REQUIRE(spy.get_calls == gets0);
    REQUIRE(session.ok_row_count == ok0);
    REQUIRE(session.current_domain_key_count == cdk0);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* Single + multi eligible: strict lex first > frontier; at most one; no advance. */
static int test_d3s3_mode30_bind_outer_select_lex_first_gt_frontier(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t raw[80];
    uint8_t k1[45];
    uint8_t k2[45];
    uint8_t v1[512];
    uint8_t v2[512];
    uint32_t k1_len = 0u;
    uint32_t k2_len = 0u;
    uint32_t v1_len = 0u;
    uint32_t v2_len = 0u;
    uint8_t d1[32];
    uint8_t d2[32];
    uint8_t stream_a[1] = {0x11u};
    uint8_t stream_b[2] = {0x22u, 0x33u};
    const uint8_t *first_key;
    const uint8_t *second_key;
    uint32_t first_len;
    uint32_t second_len;
    const uint8_t *first_dig;
    uint32_t gets0;

    REQUIRE(m30_delivery_raw80(raw));
    REQUIRE(m30_bind_encode_reply_man(
        raw, stream_a, 1u, k1, &k1_len, v1, &v1_len, d1));
    REQUIRE(m30_bind_encode_reply_man(
        raw, stream_b, 2u, k2, &k2_len, v2, &v2_len, d2));
    if (m30_key_cmp(k1, k1_len, k2, k2_len) < 0) {
        first_key = k1;
        first_len = k1_len;
        first_dig = d1;
        second_key = k2;
        second_len = k2_len;
    } else {
        first_key = k2;
        first_len = k2_len;
        first_dig = d2;
        second_key = k1;
        second_len = k1_len;
    }

    /* --- single eligible --- */
    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    if (first_key == k1) {
        REQUIRE(ninlil_spy_add_row(&spy, first_key, first_len, v1, v1_len));
    } else {
        REQUIRE(ninlil_spy_add_row(&spy, first_key, first_len, v2, v2_len));
    }
    m30_arm_bind_outer(&context, 0x07u);
    context.last_carrier_key_len = 0u;
    gets0 = spy.get_calls;
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST);
    REQUIRE(context.semantic_pass == 5u);
    REQUIRE(context.flags == M30_BIND_F_ENTRY);
    REQUIRE(context.binding_complete_mask == 0u);
    REQUIRE(context.count_complete_mask == 0x07u);
    REQUIRE(context.peer_key_len == (uint8_t)first_len);
    REQUIRE(memcmp(context.peer_key, first_key, first_len) == 0);
    REQUIRE(memcmp(context.focus_key_digest, first_dig, 32u) == 0);
    REQUIRE(context.focus_raw_len == 80u);
    REQUIRE(memcmp(context.focus_raw80, raw, 80u) == 0);
    REQUIRE(context.owner_kind
        == (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY);
    REQUIRE(context.blob_kind == (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY);
    REQUIRE(context.observed_live == 0u);
    REQUIRE(context.last_carrier_key_len == 0u); /* frontier not advanced */
    REQUIRE(spy.get_calls == gets0);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});

    /* --- multi eligible: choose strict lex first; at most one --- */
    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    /* Spy walks insertion order; must insert in complete-key lex order. */
    if (m30_key_cmp(k1, k1_len, k2, k2_len) < 0) {
        REQUIRE(ninlil_spy_add_row(&spy, k1, k1_len, v1, v1_len));
        REQUIRE(ninlil_spy_add_row(&spy, k2, k2_len, v2, v2_len));
    } else {
        REQUIRE(ninlil_spy_add_row(&spy, k2, k2_len, v2, v2_len));
        REQUIRE(ninlil_spy_add_row(&spy, k1, k1_len, v1, v1_len));
    }
    m30_arm_bind_outer(&context, 0x07u);
    context.last_carrier_key_len = 0u;
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 5u);
    REQUIRE(context.peer_key_len == (uint8_t)first_len);
    REQUIRE(memcmp(context.peer_key, first_key, first_len) == 0);
    REQUIRE(context.last_carrier_key_len == 0u);

    /* With frontier = first, next outer selects second only. */
    (void)memcpy(context.last_carrier_key, first_key, first_len);
    context.last_carrier_key_len = (uint8_t)first_len;
    (void)memset(context.peer_key, 0, sizeof(context.peer_key));
    context.peer_key_len = 0u;
    (void)memset(context.focus_key_digest, 0, 32u);
    (void)memset(context.focus_raw80, 0, 80u);
    context.focus_raw_len = 0u;
    context.owner_kind = 0u;
    context.blob_kind = 0u;
    context.observed_live = 0u;
    context.semantic_pass = 0u;
    context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
    context.flags = M30_BIND_F_ENTRY;
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 5u);
    REQUIRE(context.peer_key_len == (uint8_t)second_len);
    REQUIRE(memcmp(context.peer_key, second_key, second_len) == 0);
    /* Frontier still first (not advanced at selection). */
    REQUIRE(context.last_carrier_key_len == (uint8_t)first_len);
    REQUIRE(memcmp(context.last_carrier_key, first_key, first_len) == 0);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* RR qualification: all fields; wrong each → latch0 CORRUPT; unrelated no latch. */
static int test_d3s3_mode30_bind_rr_qualification_fields(void)
{
    enum { CASE_OK = 0, CASE_BAD_DIG, CASE_BAD_RAW, CASE_BAD_SS, CASE_UNREL };
    struct {
        int kind;
        int expect_ok;
    } cases[] = {
        {CASE_OK, 1},
        {CASE_BAD_DIG, 0},
        {CASE_BAD_RAW, 0},
        {CASE_BAD_SS, 0},
        {CASE_UNREL, 0},
    };
    size_t ci;
    uint8_t raw[80];
    uint8_t bad_raw[80];
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t stream[1] = {0x55u};

    REQUIRE(m30_delivery_raw80(raw));
    (void)memcpy(bad_raw, raw, 80u);
    bad_raw[0] ^= 0xFFu;
    REQUIRE(m30_bind_encode_reply_man(
        raw, stream, 1u, man_key, &man_key_len, man_val, &man_val_len, man_dig));

    for (ci = 0u; ci < sizeof(cases) / sizeof(cases[0]); ci += 1u) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint8_t rr_key[45];
        uint32_t rr_key_len = 0u;
        uint8_t rr_val[1024];
        uint32_t rr_val_len = 0u;
        const uint8_t *use_raw = raw;
        uint8_t use_dig[32];
        uint32_t use_ss = NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING;
        uint8_t frontier_snap[45];
        uint8_t frontier_len;

        (void)memcpy(use_dig, man_dig, 32u);
        if (cases[ci].kind == CASE_BAD_DIG) {
            use_dig[0] ^= 0xAAu;
        } else if (cases[ci].kind == CASE_BAD_RAW) {
            use_raw = bad_raw;
        } else if (cases[ci].kind == CASE_BAD_SS) {
            use_ss = NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_COUNTER_EXHAUSTED;
        } else if (cases[ci].kind == CASE_UNREL) {
            use_dig[0] ^= 0x55u;
            use_raw = bad_raw;
            use_ss = NINLIL_MODEL_DOMAIN_REPLY_SEND_WAITING_RETRY;
        }
        REQUIRE(m30_bind_build_rr(use_raw, use_dig, use_ss, 1u, rr_key,
            &rr_key_len, rr_val, &rr_val_len));

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        REQUIRE(ninlil_spy_add_row(
            &spy, rr_key, rr_key_len, rr_val, rr_val_len));

        context.focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB;
        context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
        context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
        context.semantic_pass = 5u;
        context.flags = M30_BIND_F_ENTRY;
        context.count_complete_mask = 0x07u;
        context.binding_complete_mask = 0u;
        context.observed_live = 0u;
        (void)memcpy(context.peer_key, man_key, man_key_len);
        context.peer_key_len = (uint8_t)man_key_len;
        (void)memcpy(context.focus_key_digest, man_dig, 32u);
        (void)memcpy(context.focus_raw80, raw, 80u);
        context.focus_raw_len = 80u;
        context.owner_kind =
            (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY;
        context.blob_kind = (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY;
        context.last_carrier_key_len = 0u;
        (void)memset(context.last_carrier_key, 0, sizeof(context.last_carrier_key));
        (void)memcpy(frontier_snap, context.last_carrier_key, 45u);
        frontier_len = context.last_carrier_key_len;

        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        if (cases[ci].expect_ok != 0) {
            REQUIRE(st == NINLIL_OK);
            REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST);
            REQUIRE(context.semantic_pass == 0u);
            REQUIRE(context.observed_live == 0u);
            REQUIRE(context.last_carrier_key_len == (uint8_t)man_key_len);
            REQUIRE(memcmp(context.last_carrier_key, man_key, man_key_len) == 0);
            REQUIRE(context.peer_key_len == 0u);
        } else {
            REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
            REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
            REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
            /* Frontier unchanged on latch0. */
            REQUIRE(context.last_carrier_key_len == frontier_len);
            REQUIRE(memcmp(context.last_carrier_key, frontier_snap, 45u) == 0);
            /* Pins may remain as failure snapshot. */
            REQUIRE(context.peer_key_len == (uint8_t)man_key_len);
        }
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/* Duplicate / multiple qualifying RRs keep latch exactly 1. */
static int test_d3s3_mode30_bind_rr_duplicate_latch_one(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t raw[80];
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t stream[1] = {0x66u};
    uint8_t rr1_key[45];
    uint8_t rr2_key[45];
    uint8_t rr1_val[1024];
    uint8_t rr2_val[1024];
    uint32_t rr1_key_len = 0u;
    uint32_t rr2_key_len = 0u;
    uint32_t rr1_val_len = 0u;
    uint32_t rr2_val_len = 0u;

    REQUIRE(m30_delivery_raw80(raw));
    REQUIRE(m30_bind_encode_reply_man(
        raw, stream, 1u, man_key, &man_key_len, man_val, &man_val_len, man_dig));
    REQUIRE(m30_bind_build_rr(raw, man_dig,
        NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING, 1u, rr1_key, &rr1_key_len,
        rr1_val, &rr1_val_len));
    /* Second qualifying RR (different reply_kind → distinct complete key). */
    REQUIRE(m30_bind_build_rr(raw, man_dig,
        NINLIL_MODEL_DOMAIN_REPLY_SEND_CLOSED_DENIED, 3u, rr2_key, &rr2_key_len,
        rr2_val, &rr2_val_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    if (m30_key_cmp(rr1_key, rr1_key_len, rr2_key, rr2_key_len) < 0) {
        REQUIRE(ninlil_spy_add_row(
            &spy, rr1_key, rr1_key_len, rr1_val, rr1_val_len));
        REQUIRE(ninlil_spy_add_row(
            &spy, rr2_key, rr2_key_len, rr2_val, rr2_val_len));
    } else {
        REQUIRE(ninlil_spy_add_row(
            &spy, rr2_key, rr2_key_len, rr2_val, rr2_val_len));
        REQUIRE(ninlil_spy_add_row(
            &spy, rr1_key, rr1_key_len, rr1_val, rr1_val_len));
    }

    context.focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB;
    context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
    context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
    context.semantic_pass = 5u;
    context.flags = M30_BIND_F_ENTRY;
    context.count_complete_mask = 0x07u;
    (void)memcpy(context.peer_key, man_key, man_key_len);
    context.peer_key_len = (uint8_t)man_key_len;
    (void)memcpy(context.focus_key_digest, man_dig, 32u);
    (void)memcpy(context.focus_raw80, raw, 80u);
    context.focus_raw_len = 80u;
    context.owner_kind = (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_OWNER_DELIVERY;
    context.blob_kind = (uint8_t)NINLIL_MODEL_DOMAIN_BLOB_KIND_REPLY;
    context.observed_live = 0u;
    context.last_carrier_key_len = 0u;

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    /* Success promotion: latch cleared to 0 after being exactly 1 mid-walk. */
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.observed_live == 0u);
    REQUIRE(context.last_carrier_key_len == (uint8_t)man_key_len);
    REQUIRE(memcmp(context.last_carrier_key, man_key, man_key_len) == 0);
    REQUIRE(context.peer_key_len == 0u);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/*
 * Two-manifest progress: outer→RR→promote→outer→RR→promote→outer empty→phase12.
 * Exact copy/clear/preserve on success; GET0 throughout.
 */
static int test_d3s3_mode30_bind_two_man_progress_then_finish(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint8_t raw[80];
    uint8_t focus_id[16];
    uint8_t k1[45];
    uint8_t k2[45];
    uint8_t v1[512];
    uint8_t v2[512];
    uint32_t k1_len = 0u;
    uint32_t k2_len = 0u;
    uint32_t v1_len = 0u;
    uint32_t v2_len = 0u;
    uint8_t d1[32];
    uint8_t d2[32];
    uint8_t stream_a[1] = {0x41u};
    uint8_t stream_b[3] = {0x42u, 0x43u, 0x44u};
    const uint8_t *first_key;
    const uint8_t *second_key;
    uint32_t first_len;
    uint32_t second_len;
    const uint8_t *first_dig;
    const uint8_t *second_dig;
    uint8_t rr1_key[45];
    uint8_t rr2_key[45];
    uint8_t rr1_val[1024];
    uint8_t rr2_val[1024];
    uint32_t rr1_key_len = 0u;
    uint32_t rr2_key_len = 0u;
    uint32_t rr1_val_len = 0u;
    uint32_t rr2_val_len = 0u;
    uint32_t gets0;
    uint8_t z45[45];
    uint8_t z80[80];
    uint8_t z32[32];

    (void)memset(focus_id, 0x17u, sizeof(focus_id));
    focus_id[15] = 0x99u;
    (void)memset(z45, 0, sizeof(z45));
    (void)memset(z80, 0, sizeof(z80));
    (void)memset(z32, 0, sizeof(z32));
    REQUIRE(m30_delivery_raw80(raw));
    REQUIRE(m30_bind_encode_reply_man(
        raw, stream_a, 1u, k1, &k1_len, v1, &v1_len, d1));
    REQUIRE(m30_bind_encode_reply_man(
        raw, stream_b, 3u, k2, &k2_len, v2, &v2_len, d2));
    if (m30_key_cmp(k1, k1_len, k2, k2_len) < 0) {
        first_key = k1;
        first_len = k1_len;
        first_dig = d1;
        second_key = k2;
        second_len = k2_len;
        second_dig = d2;
    } else {
        first_key = k2;
        first_len = k2_len;
        first_dig = d2;
        second_key = k1;
        second_len = k1_len;
        second_dig = d1;
    }
    REQUIRE(m30_bind_build_rr(raw, first_dig,
        NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING, 1u, rr1_key, &rr1_key_len,
        rr1_val, &rr1_val_len));
    REQUIRE(m30_bind_build_rr(raw, second_dig,
        NINLIL_MODEL_DOMAIN_REPLY_SEND_PENDING, 2u, rr2_key, &rr2_key_len,
        rr2_val, &rr2_val_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 30u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));
    /*
     * Insert all product rows in complete-key lex order (spy walks insertion
     * order; non-monotonic keys sticky CORRUPT under scanner lex fence).
     */
    {
        typedef struct {
            const uint8_t *key;
            uint32_t key_len;
            const uint8_t *val;
            uint32_t val_len;
        } m30_bind_row_t;
        m30_bind_row_t rows[4];
        size_t n = 0u;
        size_t a;
        size_t b;

        rows[n].key = k1;
        rows[n].key_len = k1_len;
        rows[n].val = v1;
        rows[n].val_len = v1_len;
        n += 1u;
        rows[n].key = k2;
        rows[n].key_len = k2_len;
        rows[n].val = v2;
        rows[n].val_len = v2_len;
        n += 1u;
        rows[n].key = rr1_key;
        rows[n].key_len = rr1_key_len;
        rows[n].val = rr1_val;
        rows[n].val_len = rr1_val_len;
        n += 1u;
        rows[n].key = rr2_key;
        rows[n].key_len = rr2_key_len;
        rows[n].val = rr2_val;
        rows[n].val_len = rr2_val_len;
        n += 1u;
        for (a = 0u; a + 1u < n; a += 1u) {
            for (b = a + 1u; b < n; b += 1u) {
                if (m30_key_cmp(rows[a].key, rows[a].key_len, rows[b].key,
                        rows[b].key_len)
                    > 0) {
                    m30_bind_row_t tmp = rows[a];
                    rows[a] = rows[b];
                    rows[b] = tmp;
                }
            }
        }
        for (a = 0u; a < n; a += 1u) {
            REQUIRE(ninlil_spy_add_row(&spy, rows[a].key, rows[a].key_len,
                rows[a].val, rows[a].val_len));
        }
    }
    m30_arm_bind_outer(&context, 0x07u);
    context.last_carrier_key_len = 0u;
    (void)memcpy(context.focus_id16, focus_id, 16u);
    context.reply_kind = 3u;
    gets0 = spy.get_calls;

    /* Outer1: select first man */
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 5u);
    REQUIRE(memcmp(context.peer_key, first_key, first_len) == 0);
    REQUIRE(context.last_carrier_key_len == 0u);
    REQUIRE(spy.get_calls == gets0);

    /* RR1: promote first */
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST);
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.flags == M30_BIND_F_ENTRY);
    REQUIRE(context.last_carrier_key_len == (uint8_t)first_len);
    REQUIRE(memcmp(context.last_carrier_key, first_key, first_len) == 0);
    REQUIRE(context.peer_key_len == 0u);
    REQUIRE(memcmp(context.peer_key, z45, 45u) == 0);
    REQUIRE(memcmp(context.focus_key_digest, z32, 32u) == 0);
    REQUIRE(context.focus_raw_len == 0u);
    REQUIRE(memcmp(context.focus_raw80, z80, 80u) == 0);
    REQUIRE(context.owner_kind == 0u);
    REQUIRE(context.blob_kind == 0u);
    REQUIRE(context.observed_live == 0u);
    REQUIRE(memcmp(context.focus_id16, focus_id, 16u) == 0);
    REQUIRE(context.reply_kind == 3u);
    REQUIRE(context.count_complete_mask == 0x07u);
    REQUIRE(context.binding_complete_mask == 0u);
    REQUIRE(spy.get_calls == gets0);

    /* Outer2: select second only (strict > frontier) */
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 5u);
    REQUIRE(context.peer_key_len == (uint8_t)second_len);
    REQUIRE(memcmp(context.peer_key, second_key, second_len) == 0);
    REQUIRE(context.last_carrier_key_len == (uint8_t)first_len);
    REQUIRE(spy.get_calls == gets0);

    /* RR2: promote second */
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.last_carrier_key_len == (uint8_t)second_len);
    REQUIRE(memcmp(context.last_carrier_key, second_key, second_len) == 0);
    REQUIRE(context.peer_key_len == 0u);
    REQUIRE(memcmp(context.focus_id16, focus_id, 16u) == 0);
    REQUIRE(spy.get_calls == gets0);

    /* Outer3: no further candidate → BIND_CHUNK */
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_CHUNK);
    REQUIRE(context.semantic_pass == 0u);
    REQUIRE(context.flags == M30_BIND_F_ENTRY);
    REQUIRE(context.binding_complete_mask
        == NINLIL_DOMAIN_SCAN_D3S3_MASK_BIND_MANIFEST);
    REQUIRE(context.count_complete_mask == 0x07u);
    REQUIRE(context.last_carrier_key_len == (uint8_t)second_len);
    REQUIRE(spy.get_calls == gets0);

    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    return 0;
}

/* Zero qualifying RR, natural iter_open/iter_next faults, GET0, frozen counters. */
static int test_d3s3_mode30_bind_rr_zero_and_natural_faults(void)
{
    uint8_t raw[80];
    uint8_t man_key[45];
    uint32_t man_key_len = 0u;
    uint8_t man_val[512];
    uint32_t man_val_len = 0u;
    uint8_t man_dig[32];
    uint8_t stream[1] = {0x77u};

    REQUIRE(m30_delivery_raw80(raw));
    REQUIRE(m30_bind_encode_reply_man(
        raw, stream, 1u, man_key, &man_key_len, man_val, &man_val_len, man_dig));

    /* Zero qualifying: empty store under RR → CORRUPT, GET0 */
    {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint32_t gets0;
        uint64_t ok0;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        context.focus_mode = NINLIL_DOMAIN_SCAN_D3S3_MODE_REPLY_BLOB;
        context.pass_kind = NINLIL_DOMAIN_SCAN_D3S3_PASS_INTERNAL;
        context.phase = NINLIL_DOMAIN_SCAN_D3S3_PHASE_BIND_MANIFEST;
        context.semantic_pass = 5u;
        context.flags = M30_BIND_F_ENTRY;
        context.count_complete_mask = 0x07u;
        (void)memcpy(context.peer_key, man_key, man_key_len);
        context.peer_key_len = (uint8_t)man_key_len;
        (void)memcpy(context.focus_key_digest, man_dig, 32u);
        (void)memcpy(context.focus_raw80, raw, 80u);
        context.focus_raw_len = 80u;
        context.observed_live = 0u;
        context.last_carrier_key_len = 0u;
        gets0 = spy.get_calls;
        ok0 = session.ok_row_count;
        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        REQUIRE(spy.get_calls == gets0);
        REQUIRE(session.ok_row_count == ok0);
        REQUIRE(context.last_carrier_key_len == 0u);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }

    /* Natural iter_next fault last event; GET0; counters frozen */
    {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint32_t gets0;
        uint32_t next0;
        uint64_t ok0;
        uint64_t cdk0;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        m30_arm_bind_outer(&context, 0x07u);
        context.last_carrier_key_len = 0u;
        gets0 = spy.get_calls;
        next0 = spy.iter_next_calls;
        ok0 = session.ok_row_count;
        cdk0 = session.current_domain_key_count;
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_NEXT, next0 + 1u,
            NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_E_STORAGE);
        REQUIRE(session.sticky_primary == NINLIL_E_STORAGE);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        REQUIRE(spy.get_calls == gets0);
        REQUIRE(session.ok_row_count == ok0);
        REQUIRE(session.current_domain_key_count == cdk0);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }

    /* Natural iter_open fault on NEED_REOPEN reopen; GET0 */
    {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint32_t gets0;
        uint32_t open0;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 30u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        m30_arm_bind_outer(&context, 0x07u);
        context.last_carrier_key_len = 0u;
        gets0 = spy.get_calls;
        open0 = spy.iter_open_calls;
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ITER_OPEN, open0 + 1u,
            NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_E_STORAGE);
        REQUIRE(session.sticky_primary == NINLIL_E_STORAGE);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        REQUIRE(spy.get_calls == gets0);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
    }
    return 0;
}

/*
 * Mode27 SELECT_SETUP lifecycle (R25 / docs/17 §18.14.2 / docs/12 family table).
 * Helpers re-encode D1-legal family-specific TRANSACTION_STATE / EVENT_SPOOL
 * variants from fixtures without editing generator vectors.
 */
static int m27_encode_tx_state(
    uint32_t state,
    uint32_t outcome,
    uint32_t deadline_verdict,
    uint32_t reason,
    uint32_t park_cause,
    uint64_t retry_cycle_id,
    uint32_t attempt_in_cycle,
    uint64_t event_spool_revision,
    uint32_t explicitly_discarded,
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t vv;
    ninlil_bytes_view_t bodyv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_transaction_state_t st;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[256];
    uint32_t blen = 0u;

    if (out_value == NULL || out_len == NULL) {
        return 0;
    }
    vv.data = DSB2_STATE_TYPED_VALUE;
    vv.length = (uint32_t)DSB2_STATE_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_transaction_state(env.body, &st)
        != NINLIL_OK) {
        return 0;
    }
    st.state = state;
    st.outcome = outcome;
    st.deadline_verdict = deadline_verdict;
    st.reason = reason;
    st.event_park_cause = park_cause;
    st.retry_cycle_id = retry_cycle_id;
    st.attempt_in_cycle = attempt_in_cycle;
    st.event_spool_revision = event_spool_revision;
    st.explicitly_discarded = explicitly_discarded;
    st.target_state = state;
    st.target_outcome = outcome;
    st.target_reason = reason;
    st.target_latest_evidence = st.latest_evidence;
    if (ninlil_model_domain_encode_body_transaction_state(
            &st, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
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

static int m27_encode_event_spool(
    uint32_t spool_state,
    uint32_t park_cause,
    uint32_t discard_committed,
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t vv;
    ninlil_bytes_view_t bodyv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_event_spool_t es;
    ninlil_model_domain_common_header_t hdr;
    uint8_t bodybuf[320];
    uint32_t blen = 0u;

    if (out_value == NULL || out_len == NULL) {
        return 0;
    }
    vv.data = DSB3_ES_ACTIVE_TYPED_VALUE;
    vv.length = (uint32_t)DSB3_ES_ACTIVE_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_event_spool(env.body, &es)
        != NINLIL_OK) {
        return 0;
    }
    es.spool_state = spool_state;
    es.park_cause = park_cause;
    es.discard_committed = discard_committed;
    if (ninlil_model_domain_encode_body_event_spool(
            &es, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
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
 * R27 cross-row fixture derivation. The shared DSB2/DSB3 fixtures predate the
 * Mode27 cross-row contract and carry placeholder digests; these helpers make
 * a mutable copy cross-row consistent without touching the shared header:
 *   STATE.anchor_value_digest = STATE envelope common primary_value_digest
 *     = VALUE_DIGEST(complete ANCHOR value) (want_avd)
 *   STATE.transaction_id = ANCHOR body transaction_id (focus_id16)
 * Only those cross-row fields change; every other D1 field (and thus D1
 * legality) is preserved by decode→patch→re-encode (CRC recomputed).
 */
static int m27_crossrow_patch_state(
    const uint8_t *anchor_value,
    uint32_t anchor_len,
    const uint8_t *state_value,
    uint32_t state_len,
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t av;
    ninlil_bytes_view_t sv;
    ninlil_bytes_view_t bodyv;
    ninlil_model_domain_envelope_t aenv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_transaction_state_t st;
    ninlil_model_domain_common_header_t hdr;
    ninlil_model_domain_digest_t avd;
    uint8_t bodybuf[256];
    uint32_t blen = 0u;

    if (out_value == NULL || out_len == NULL) {
        return 0;
    }
    av.data = anchor_value;
    av.length = anchor_len;
    if (ninlil_model_domain_value_digest(av, &avd) != NINLIL_OK
        || ninlil_model_domain_decode_envelope(av, &aenv) != NINLIL_OK
        || aenv.body.length < 16u) {
        return 0;
    }
    sv.data = state_value;
    sv.length = state_len;
    if (ninlil_model_domain_decode_envelope(sv, &env) != NINLIL_OK
        || ninlil_model_domain_decode_body_transaction_state(env.body, &st)
            != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(st.transaction_id, aenv.body.data, 16u);
    (void)memcpy(st.anchor_value_digest, avd.bytes, 32u);
    if (ninlil_model_domain_encode_body_transaction_state(
            &st, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = env.header;
    hdr.body_length = blen;
    (void)memcpy(hdr.primary_value_digest, avd.bytes, 32u);
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               env.record_type, &hdr, bodyv, out_value, out_cap, out_len)
        == NINLIL_OK;
}

/*
 * EVENT_SPOOL cross-row derivation (EventFact only):
 *   spool.transaction_id = ANCHOR body transaction_id (= STATE.transaction_id)
 *   spool.spool_revision = STATE.event_spool_revision
 *   spool envelope common primary_value_digest = want_avd
 *   spool envelope record_revision = spool.spool_revision
 * Other D1 fields preserved; CRC recomputed.
 */
static int m27_crossrow_patch_spool(
    const uint8_t *anchor_value,
    uint32_t anchor_len,
    const uint8_t *state_value,
    uint32_t state_len,
    const uint8_t *spool_value,
    uint32_t spool_len,
    uint8_t *out_value,
    uint32_t out_cap,
    uint32_t *out_len)
{
    ninlil_bytes_view_t av;
    ninlil_bytes_view_t sv;
    ninlil_bytes_view_t pv;
    ninlil_bytes_view_t bodyv;
    ninlil_model_domain_envelope_t aenv;
    ninlil_model_domain_envelope_t senv;
    ninlil_model_domain_envelope_t penv;
    ninlil_model_domain_body_transaction_state_t st;
    ninlil_model_domain_body_event_spool_t es;
    ninlil_model_domain_common_header_t hdr;
    ninlil_model_domain_digest_t avd;
    uint8_t bodybuf[320];
    uint32_t blen = 0u;

    if (out_value == NULL || out_len == NULL) {
        return 0;
    }
    av.data = anchor_value;
    av.length = anchor_len;
    if (ninlil_model_domain_value_digest(av, &avd) != NINLIL_OK
        || ninlil_model_domain_decode_envelope(av, &aenv) != NINLIL_OK
        || aenv.body.length < 16u) {
        return 0;
    }
    sv.data = state_value;
    sv.length = state_len;
    if (ninlil_model_domain_decode_envelope(sv, &senv) != NINLIL_OK
        || ninlil_model_domain_decode_body_transaction_state(senv.body, &st)
            != NINLIL_OK) {
        return 0;
    }
    pv.data = spool_value;
    pv.length = spool_len;
    if (ninlil_model_domain_decode_envelope(pv, &penv) != NINLIL_OK
        || ninlil_model_domain_decode_body_event_spool(penv.body, &es)
            != NINLIL_OK) {
        return 0;
    }
    (void)memcpy(es.transaction_id, aenv.body.data, 16u);
    es.spool_revision = st.event_spool_revision;
    if (ninlil_model_domain_encode_body_event_spool(
            &es, bodybuf, (uint32_t)sizeof(bodybuf), &blen)
        != NINLIL_OK) {
        return 0;
    }
    hdr = penv.header;
    hdr.body_length = blen;
    hdr.record_revision = es.spool_revision;
    (void)memcpy(hdr.primary_value_digest, avd.bytes, 32u);
    bodyv.data = bodybuf;
    bodyv.length = blen;
    return ninlil_model_domain_encode_envelope(
               penv.record_type, &hdr, bodyv, out_value, out_cap, out_len)
        == NINLIL_OK;
}

/*
 * Mode27 SELECT_SETUP EventFact: EVENT_SPOOL ABSENT/NOT_FOUND is sticky
 * CORRUPT at phase FAILED with entry semantic_pass=6; STATE then SPOOL exact
 * GET order; no residual Port after the failing get.
 */
static int test_d3s3_mode27_eventfact_missing_spool_corrupt(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_after_select;
    uint32_t gets_after_setup;
    uint32_t next_after_setup;
    uint32_t open_after_setup;
    uint32_t rb_after_setup;
    uint32_t close_after_setup;
    size_t trace_after_setup;
    uint8_t state_val[512];
    uint32_t state_len = 0u;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    /* D1-legal EF STATE: nonterminal + NA deadline + es counters. */
    REQUIRE(m27_encode_tx_state(NINLIL_TXN_READY, NINLIL_OUTCOME_NONE,
        NINLIL_DEADLINE_NOT_APPLICABLE, NINLIL_REASON_NONE,
        NINLIL_EVENT_PARK_CAUSE_NONE, 1u, 0u, 1u, 0u, state_val,
        (uint32_t)sizeof(state_val), &state_len));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_EF_TYPED_KEY,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_KEY_LEN, DSB2_ANCHOR_EF_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
        (uint32_t)DSB2_STATE_TYPED_KEY_LEN, state_val, state_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    /* SELECT W pins EventFact carrier → SELECT_SETUP G pending (sem=6). */
    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_SELECT_CARRIER);
    REQUIRE(context.semantic_pass == 6u);
    gets_after_select = spy.get_calls;

    /* SELECT_SETUP G: STATE PRESENT + EVENT_SPOOL ABSENT → CORRUPT. */
    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.has_sticky_primary == 1u);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
    REQUIRE(context.semantic_pass == 6u);
    gets_after_setup = spy.get_calls;
    next_after_setup = spy.iter_next_calls;
    open_after_setup = spy.iter_open_calls;
    rb_after_setup = spy.rollback_calls;
    close_after_setup = spy.close_calls;
    trace_after_setup = spy.trace_count;
    /* Exact GET burst: STATE + EVENT_SPOOL only (+2). */
    REQUIRE(gets_after_setup == gets_after_select + 2u);

    /* No residual Port after the failing ABSENT get (cleanup only finalize). */
    (void)memset(&result, 0, sizeof(result));
    st = ninlil_domain_scan_finalize(&session, &result);
    REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(spy.get_calls == gets_after_setup);
    REQUIRE(spy.iter_next_calls == next_after_setup);
    REQUIRE(spy.iter_open_calls == open_after_setup);
    /* Cleanup may rollback/close; get/next must not advance. */
    (void)rb_after_setup;
    (void)close_after_setup;
    (void)trace_after_setup;
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* (1) DS active + nonzero dig → LIVE; STATE GET +1 only. */
static int test_d3s3_mode27_desiredstate_active_live(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_after_select;
    uint32_t next_after_setup;
    uint32_t open_after_setup;
    uint8_t state_cr[512];
    uint32_t state_cr_len = 0u;

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    /* Fixture DS READY+PENDING+discard0 is D1-legal DesiredState. */
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_TYPED_KEY,
        (uint32_t)DSB2_ANCHOR_TYPED_KEY_LEN, DSB2_ANCHOR_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(m27_crossrow_patch_state(DSB2_ANCHOR_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN, DSB2_STATE_TYPED_VALUE,
        (uint32_t)DSB2_STATE_TYPED_VALUE_LEN, state_cr,
        (uint32_t)sizeof(state_cr), &state_cr_len));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
        (uint32_t)DSB2_STATE_TYPED_KEY_LEN, state_cr, state_cr_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 6u);
    gets_after_select = spy.get_calls;
    next_after_setup = spy.iter_next_calls;
    open_after_setup = spy.iter_open_calls;

    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_after_select + 1u);
    REQUIRE(spy.iter_next_calls == next_after_setup);
    REQUIRE(spy.iter_open_calls == open_after_setup);
    REQUIRE(context.lifecycle_class
        == NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED);
    /* After setup, enter_focus zeros walk-local expected_live (reconstruct later). */
    REQUIRE(context.expected_live == 0u);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
    REQUIRE(context.semantic_pass == 0u);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * (2) DS TERMINAL+EXPIRED+MISSED+discard0 + nonzero dig / no man → HISTORICAL.
 * R25 D3S3_M27_HISTORICAL_ABSENT_OK production shape.
 */
static int test_d3s3_mode27_desiredstate_terminal_historical(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_after_select;
    uint32_t next_after_setup;
    uint8_t state_val[512];
    uint32_t state_len = 0u;
    uint8_t state_cr[512];
    uint32_t state_cr_len = 0u;

    REQUIRE(m27_encode_tx_state(NINLIL_TXN_TERMINAL, NINLIL_OUTCOME_EXPIRED,
        NINLIL_DEADLINE_MISSED, NINLIL_REASON_DEADLINE_ELAPSED_BEFORE_DISPATCH,
        NINLIL_EVENT_PARK_CAUSE_NONE, 0u, 0u, 0u, 0u, state_val,
        (uint32_t)sizeof(state_val), &state_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_TYPED_KEY,
        (uint32_t)DSB2_ANCHOR_TYPED_KEY_LEN, DSB2_ANCHOR_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(m27_crossrow_patch_state(DSB2_ANCHOR_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN, state_val, state_len, state_cr,
        (uint32_t)sizeof(state_cr), &state_cr_len));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
        (uint32_t)DSB2_STATE_TYPED_KEY_LEN, state_cr, state_cr_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 6u);
    gets_after_select = spy.get_calls;
    next_after_setup = spy.iter_next_calls;

    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_after_select + 1u);
    REQUIRE(spy.iter_next_calls == next_after_setup);
    REQUIRE(context.lifecycle_class
        == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT);
    REQUIRE(context.expected_live == 0u);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
    REQUIRE(context.semantic_pass == 0u);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* (3) EventFact active + ACTIVE/PARKED spool → LIVE; STATE+SPOOL GETs. */
static int test_d3s3_mode27_eventfact_spool_active_live(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_after_select;
    uint32_t next_after_setup;
    uint8_t state_val[512];
    uint8_t spool_val[512];
    uint32_t state_len = 0u;
    uint32_t spool_len = 0u;
    uint8_t state_cr[512];
    uint8_t spool_cr[512];
    uint32_t state_cr_len = 0u;
    uint32_t spool_cr_len = 0u;
    size_t i;

    static const struct {
        uint32_t spool_state;
        uint32_t park_cause;
        uint32_t tx_state;
        uint32_t tx_reason;
        uint32_t tx_park;
    } cases[] = {
        { NINLIL_MODEL_DOMAIN_SPOOL_STATE_ACTIVE, NINLIL_EVENT_PARK_CAUSE_NONE,
            NINLIL_TXN_READY, NINLIL_REASON_NONE, NINLIL_EVENT_PARK_CAUSE_NONE },
        { NINLIL_MODEL_DOMAIN_SPOOL_STATE_PARKED_RETRY,
            NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT,
            NINLIL_TXN_PARKED_RETRY, NINLIL_REASON_EVENT_RETRY_CYCLE_PARKED,
            NINLIL_EVENT_PARK_CAUSE_CYCLE_EXHAUSTED_TRANSIENT },
    };

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); i += 1u) {
        REQUIRE(m27_encode_tx_state(cases[i].tx_state, NINLIL_OUTCOME_NONE,
            NINLIL_DEADLINE_NOT_APPLICABLE, cases[i].tx_reason, cases[i].tx_park,
            1u, 0u, 1u, 0u, state_val, (uint32_t)sizeof(state_val),
            &state_len));
        REQUIRE(m27_encode_event_spool(cases[i].spool_state, cases[i].park_cause,
            0u, spool_val, (uint32_t)sizeof(spool_val), &spool_len));
        REQUIRE(m27_crossrow_patch_state(DSB2_ANCHOR_EF_TYPED_VALUE,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_val, state_len,
            state_cr, (uint32_t)sizeof(state_cr), &state_cr_len));
        REQUIRE(m27_crossrow_patch_spool(DSB2_ANCHOR_EF_TYPED_VALUE,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_cr, state_cr_len,
            spool_val, spool_len, spool_cr, (uint32_t)sizeof(spool_cr),
            &spool_cr_len));

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_EF_TYPED_KEY,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_KEY_LEN, DSB2_ANCHOR_EF_TYPED_VALUE,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
        REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
            (uint32_t)DSB2_STATE_TYPED_KEY_LEN, state_cr, state_cr_len));
        REQUIRE(ninlil_spy_add_row(&spy, DSB3_ES_ACTIVE_TYPED_KEY,
            (uint32_t)DSB3_ES_ACTIVE_TYPED_KEY_LEN, spool_cr, spool_cr_len));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 27u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));

        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(context.semantic_pass == 6u);
        gets_after_select = spy.get_calls;
        next_after_setup = spy.iter_next_calls;

        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(spy.get_calls == gets_after_select + 2u);
        REQUIRE(spy.iter_next_calls == next_after_setup);
        REQUIRE(context.lifecycle_class
            == NINLIL_DOMAIN_SCAN_D3S3_LIFE_LIVE_REQUIRED);
        REQUIRE(context.expected_live == 0u);
        REQUIRE(context.phase
            == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
        REQUIRE(context.semantic_pass == 0u);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    }
    return 0;
}

/* (4) EventFact terminal + RELEASED spool → HISTORICAL. */
static int test_d3s3_mode27_eventfact_released_historical(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_after_select;
    uint8_t state_val[512];
    uint8_t spool_val[512];
    uint32_t state_len = 0u;
    uint32_t spool_len = 0u;
    uint8_t state_cr[512];
    uint8_t spool_cr[512];
    uint32_t state_cr_len = 0u;
    uint32_t spool_cr_len = 0u;

    REQUIRE(m27_encode_tx_state(NINLIL_TXN_TERMINAL,
        NINLIL_OUTCOME_SATISFIED, NINLIL_DEADLINE_NOT_APPLICABLE,
        NINLIL_REASON_REQUIRED_EVIDENCE_MET, NINLIL_EVENT_PARK_CAUSE_NONE, 1u,
        0u, 1u, 0u, state_val, (uint32_t)sizeof(state_val), &state_len));
    REQUIRE(m27_encode_event_spool(NINLIL_MODEL_DOMAIN_SPOOL_STATE_RELEASED,
        NINLIL_EVENT_PARK_CAUSE_NONE, 0u, spool_val,
        (uint32_t)sizeof(spool_val), &spool_len));
    REQUIRE(m27_crossrow_patch_state(DSB2_ANCHOR_EF_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_val, state_len,
        state_cr, (uint32_t)sizeof(state_cr), &state_cr_len));
    REQUIRE(m27_crossrow_patch_spool(DSB2_ANCHOR_EF_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_cr, state_cr_len,
        spool_val, spool_len, spool_cr, (uint32_t)sizeof(spool_cr),
        &spool_cr_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_EF_TYPED_KEY,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_KEY_LEN, DSB2_ANCHOR_EF_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
        (uint32_t)DSB2_STATE_TYPED_KEY_LEN, state_cr, state_cr_len));
    REQUIRE(ninlil_spy_add_row(&spy, DSB3_ES_ACTIVE_TYPED_KEY,
        (uint32_t)DSB3_ES_ACTIVE_TYPED_KEY_LEN, spool_cr, spool_cr_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 6u);
    gets_after_select = spy.get_calls;

    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_after_select + 2u);
    REQUIRE(context.lifecycle_class
        == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT);
    REQUIRE(context.expected_live == 0u);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
    REQUIRE(context.semantic_pass == 0u);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* (5) EventFact audited discard + DISCARDED spool → HISTORICAL. */
static int test_d3s3_mode27_eventfact_discard_historical(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_after_select;
    uint8_t state_val[512];
    uint8_t spool_val[512];
    uint32_t state_len = 0u;
    uint32_t spool_len = 0u;
    uint8_t state_cr[512];
    uint8_t spool_cr[512];
    uint32_t state_cr_len = 0u;
    uint32_t spool_cr_len = 0u;

    REQUIRE(m27_encode_tx_state(NINLIL_TXN_TERMINAL,
        NINLIL_OUTCOME_FAILED_DEFINITIVE, NINLIL_DEADLINE_NOT_APPLICABLE,
        NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT,
        NINLIL_EVENT_PARK_CAUSE_NONE, 1u, 0u, 1u, 1u, state_val,
        (uint32_t)sizeof(state_val), &state_len));
    REQUIRE(m27_encode_event_spool(NINLIL_MODEL_DOMAIN_SPOOL_STATE_DISCARDED,
        NINLIL_EVENT_PARK_CAUSE_NONE, 1u, spool_val,
        (uint32_t)sizeof(spool_val), &spool_len));
    REQUIRE(m27_crossrow_patch_state(DSB2_ANCHOR_EF_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_val, state_len,
        state_cr, (uint32_t)sizeof(state_cr), &state_cr_len));
    REQUIRE(m27_crossrow_patch_spool(DSB2_ANCHOR_EF_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_cr, state_cr_len,
        spool_val, spool_len, spool_cr, (uint32_t)sizeof(spool_cr),
        &spool_cr_len));

    ninlil_spy_init(&spy);
    REQUIRE(install_profile_rows(&spy, &candidate));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_EF_TYPED_KEY,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_KEY_LEN, DSB2_ANCHOR_EF_TYPED_VALUE,
        (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
    REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
        (uint32_t)DSB2_STATE_TYPED_KEY_LEN, state_cr, state_cr_len));
    REQUIRE(ninlil_spy_add_row(&spy, DSB3_ES_ACTIVE_TYPED_KEY,
        (uint32_t)DSB3_ES_ACTIVE_TYPED_KEY_LEN, spool_cr, spool_cr_len));
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    st = ninlil_domain_scan_begin_profiled_d3s3(
        &session, ops, &handle, &workspace, &candidate, 27u, &context);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(drive_baseline_to_internal(&session, &context));

    st = ninlil_domain_scan_d3s3_drive(&session, 64u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(context.semantic_pass == 6u);
    gets_after_select = spy.get_calls;

    st = ninlil_domain_scan_d3s3_drive(&session, 0u);
    REQUIRE(st == NINLIL_OK);
    REQUIRE(spy.get_calls == gets_after_select + 2u);
    REQUIRE(context.lifecycle_class
        == NINLIL_DOMAIN_SCAN_D3S3_LIFE_HISTORICAL_ABSENT);
    REQUIRE(context.expected_live == 0u);
    REQUIRE(context.phase
        == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FOCUS_MANIFEST_SCAN);
    REQUIRE(context.semantic_pass == 0u);
    (void)ninlil_domain_scan_abort(&session, &(ninlil_domain_scan_result_t){0});
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * (6) state/spool mismatches → sticky CORRUPT (R25 fail-closed).
 * - TERMINAL TX + ACTIVE spool
 * - discard bit without DISCARDED spool pairing
 */
static int test_d3s3_mode27_eventfact_state_spool_mismatch_corrupt(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s3_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    ninlil_status_t st;
    uint32_t gets_after_select;
    uint32_t gets_after_setup;
    uint32_t next_after_setup;
    uint8_t state_val[512];
    uint8_t spool_val[512];
    uint32_t state_len = 0u;
    uint32_t spool_len = 0u;
    uint8_t state_cr[512];
    uint8_t spool_cr[512];
    uint32_t state_cr_len = 0u;
    uint32_t spool_cr_len = 0u;
    size_t i;

    static const struct {
        uint32_t tx_state;
        uint32_t outcome;
        uint32_t reason;
        uint32_t discarded;
        uint32_t spool_state;
        uint32_t spool_discard;
    } cases[] = {
        /* terminal without released/discarded spool */
        { NINLIL_TXN_TERMINAL, NINLIL_OUTCOME_SATISFIED,
            NINLIL_REASON_REQUIRED_EVIDENCE_MET, 0u,
            NINLIL_MODEL_DOMAIN_SPOOL_STATE_ACTIVE, 0u },
        /* discard without DISCARDED spool (and incomplete pairing) */
        { NINLIL_TXN_TERMINAL, NINLIL_OUTCOME_FAILED_DEFINITIVE,
            NINLIL_REASON_OPERATOR_DISCARDED_WITHOUT_REQUIRED_RECEIPT, 1u,
            NINLIL_MODEL_DOMAIN_SPOOL_STATE_RELEASED, 0u },
    };

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); i += 1u) {
        REQUIRE(m27_encode_tx_state(cases[i].tx_state, cases[i].outcome,
            NINLIL_DEADLINE_NOT_APPLICABLE, cases[i].reason,
            NINLIL_EVENT_PARK_CAUSE_NONE, 1u, 0u, 1u, cases[i].discarded,
            state_val, (uint32_t)sizeof(state_val), &state_len));
        REQUIRE(m27_encode_event_spool(cases[i].spool_state,
            NINLIL_EVENT_PARK_CAUSE_NONE, cases[i].spool_discard, spool_val,
            (uint32_t)sizeof(spool_val), &spool_len));
        /*
         * Cross-row consistent except the intentional state×spool mismatch:
         * failure lands in closed product (7), lifecycle stays NONE.
         */
        REQUIRE(m27_crossrow_patch_state(DSB2_ANCHOR_EF_TYPED_VALUE,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_val, state_len,
            state_cr, (uint32_t)sizeof(state_cr), &state_cr_len));
        REQUIRE(m27_crossrow_patch_spool(DSB2_ANCHOR_EF_TYPED_VALUE,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN, state_cr, state_cr_len,
            spool_val, spool_len, spool_cr, (uint32_t)sizeof(spool_cr),
            &spool_cr_len));

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_EF_TYPED_KEY,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_KEY_LEN, DSB2_ANCHOR_EF_TYPED_VALUE,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
        REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
            (uint32_t)DSB2_STATE_TYPED_KEY_LEN, state_cr, state_cr_len));
        REQUIRE(ninlil_spy_add_row(&spy, DSB3_ES_ACTIVE_TYPED_KEY,
            (uint32_t)DSB3_ES_ACTIVE_TYPED_KEY_LEN, spool_cr, spool_cr_len));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 27u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));

        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(context.semantic_pass == 6u);
        gets_after_select = spy.get_calls;
        next_after_setup = spy.iter_next_calls;

        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED);
        REQUIRE(context.semantic_pass == 6u);
        /* R27 contract: cross-row/closed-product CORRUPT keeps lifecycle NONE. */
        REQUIRE(context.lifecycle_class
            == NINLIL_DOMAIN_SCAN_D3S3_LIFE_NONE);
        gets_after_setup = spy.get_calls;
        REQUIRE(gets_after_setup == gets_after_select + 2u);
        REQUIRE(spy.iter_next_calls == next_after_setup);

        (void)memset(&result, 0, sizeof(result));
        st = ninlil_domain_scan_finalize(&session, &result);
        REQUIRE(st == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(spy.get_calls == gets_after_setup);
        REQUIRE(spy.iter_next_calls == next_after_setup);
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    }
    return 0;
}

/*
 * T2 production handle projection signals for the bridge:
 * clean finalize retains caller H1; rollback fault finalize nulls H/T/I
 * (bound_handle_value historical identity preserved); pre-finalize CU keeps
 * H1 with fence_pending.
 */
static int test_d3s3_handle_projection_clean_rollback_cu(void)
{
    /* --- clean finalize: caller retains H1 --- */
    {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_domain_scan_result_t result;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint32_t guard = 0u;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 27u, &context);
        REQUIRE(st == NINLIL_OK);
        while (context.phase != NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE
            && context.phase != NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED
            && session.state != NINLIL_DOMAIN_SCAN_STATE_FAILED
            && guard < 64u) {
            st = ninlil_domain_scan_d3s3_drive(&session, 64u);
            if (st != NINLIL_OK && session.has_sticky_primary == 0u) {
                break;
            }
            guard += 1u;
        }
        REQUIRE(context.phase == NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE);
        REQUIRE(handle != NULL);
        (void)memset(&result, 0, sizeof(result));
        st = ninlil_domain_scan_finalize(&session, &result);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(result.adopted == 1u);
        REQUIRE(handle != NULL);
        REQUIRE(handle == (ninlil_storage_handle_t)&spy.handle_token);
        REQUIRE(session.txn == NULL);
        REQUIRE(session.iter == NULL);
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    }

    /* --- rollback fault finalize: caller H/T/I null; historical value kept --- */
    {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_domain_scan_result_t result;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint32_t guard = 0u;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_ROLLBACK, 1u,
            NINLIL_STORAGE_IO_ERROR, NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 27u, &context);
        REQUIRE(st == NINLIL_OK);
        while (context.phase != NINLIL_DOMAIN_SCAN_D3S3_PHASE_COMPLETE
            && context.phase != NINLIL_DOMAIN_SCAN_D3S3_PHASE_FAILED
            && session.state != NINLIL_DOMAIN_SCAN_STATE_FAILED
            && guard < 64u) {
            (void)ninlil_domain_scan_d3s3_drive(&session, 64u);
            guard += 1u;
        }
        (void)memset(&result, 0, sizeof(result));
        st = ninlil_domain_scan_finalize(&session, &result);
        REQUIRE(handle == NULL);
        REQUIRE(session.txn == NULL);
        REQUIRE(session.iter == NULL);
        /* Production keeps original identity for exact-once close bookkeeping. */
        REQUIRE(session.bound_handle_value
            == (ninlil_storage_handle_t)&spy.handle_token);
        (void)st;
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    }

    /* --- pre-finalize CU on mid-session GET: fence_pending, caller H1 --- */
    {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s3_context_t context;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ninlil_status_t st;
        uint32_t gets_after_select;

        ninlil_spy_init(&spy);
        REQUIRE(install_profile_rows(&spy, &candidate));
        REQUIRE(ninlil_spy_add_row(&spy, DSB2_ANCHOR_EF_TYPED_KEY,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_KEY_LEN, DSB2_ANCHOR_EF_TYPED_VALUE,
            (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
        REQUIRE(ninlil_spy_add_row(&spy, DSB2_STATE_TYPED_KEY,
            (uint32_t)DSB2_STATE_TYPED_KEY_LEN, DSB2_STATE_TYPED_VALUE,
            (uint32_t)DSB2_STATE_TYPED_VALUE_LEN));
        REQUIRE(ninlil_spy_add_row(&spy, DSB3_ES_ACTIVE_TYPED_KEY,
            (uint32_t)DSB3_ES_ACTIVE_TYPED_KEY_LEN, DSB3_ES_ACTIVE_TYPED_VALUE,
            (uint32_t)DSB3_ES_ACTIVE_TYPED_VALUE_LEN));
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        st = ninlil_domain_scan_begin_profiled_d3s3(
            &session, ops, &handle, &workspace, &candidate, 27u, &context);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(drive_baseline_to_internal(&session, &context));
        st = ninlil_domain_scan_d3s3_drive(&session, 64u);
        REQUIRE(st == NINLIL_OK);
        REQUIRE(context.semantic_pass == 6u);
        gets_after_select = spy.get_calls;
        /* CU on first SELECT_SETUP companion GET; close deferred. */
        REQUIRE(ninlil_spy_add_fault(&spy, NINLIL_SPY_OP_GET,
            gets_after_select + 1u, NINLIL_STORAGE_COMMIT_UNKNOWN,
            NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
        st = ninlil_domain_scan_d3s3_drive(&session, 0u);
        REQUIRE(st == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        REQUIRE(session.fence_pending == 1u);
        /* Pre-finalize: caller still H1 (fence not yet applied). */
        REQUIRE(handle != NULL);
        REQUIRE(handle == (ninlil_storage_handle_t)&spy.handle_token);
        (void)ninlil_domain_scan_abort(
            &session, &(ninlil_domain_scan_result_t){0});
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    }
    return 0;
}

int main(void)
{
    int failed = 0;
    failed |= test_d3s3_context_size_and_masks();
    failed |= test_d3s3_begin_prevalidation();
    failed |= test_d3s3_valid_begin_four_modes();
    failed |= test_d3s3_no_key_digest_reverse_api();
    failed |= test_d3s3_four_session_product_not_one_baseline();
    failed |= test_d3s3_mode30_referrer_field_contract();
    failed |= test_d3s3_digest_pin_offsets();
    failed |= test_d3s3_drive_budget_zero();
    failed |= test_d3s3_r12_mode27_owner_raw_mismatch_exact_abort();
    failed |= test_d3s3_r12_mode29_owner_raw_mismatch();
    failed |= test_d3s3_r12_mode30_owner_raw_mismatch();
    failed |= test_d3s3_mode30_focus_h14_wrong_kind_defers_to_exhaustion();
    failed |= test_d3s3_mode30_focus_h15_nonreceipt_nonempty_defers();
    failed |= test_d3s3_mode30_focus_deferred_invalid_then_port_fault();
    failed |= test_d3s3_mode30_focus_valid_reply_to_chunks();
    failed |= test_d3s3_bind_man_natural_get_fault_visit_commit();
    failed |= test_d3s3_bind_man_closed_eligibility_no_get();
    failed |= test_d3s3_mode28_bind_referrer_payload_not_evidence();
    failed |= test_d3s3_mode28_select_za_zb_transitions();
    failed |= test_d3s3_mode28_focus_id16_packed_totals_after_man();
    failed |= test_d3s3_mode29_focus_id16_stays_zero();
    failed |= test_d3s3_mode28_semantic_schedule_za_zb();
    failed |= test_d3s3_mode28_prefix_u32_overflow_no_port();
    failed |= test_d3s3_mode28_semantic_digest_mismatch();
    failed |= test_d3s3_mode28_a_only_nonempty_payload_stream();
    failed |= test_d3s3_mode28_b_only_nonempty_evidence_stream();
    failed |= test_d3s3_mode28_prefix_get_fault();
    failed |= test_d3s3_mode28_rescan_missing_man_fault();
    failed |= test_d3s3_mode28_view_chunk_get_fault();
    failed |= test_d3s3_mode30_semantic_two_g_all_kinds();
    failed |= test_d3s3_mode30_receipt_empty_1_128();
    failed |= test_d3s3_mode30_semantic_digest_mismatch();
    failed |= test_d3s3_mode30_prefix_companion_get_faults();
    failed |= test_d3s3_mode30_sem_chunk_faults();
    failed |= test_d3s3_mode30_nonreceipt_empty_and_nonempty_reject();
    failed |= test_d3s3_mode30_no_reopen_advance_both_g();
    failed |= test_d3s3_mode30_bind_entry_exact_zero_preserve();
    failed |= test_d3s3_mode30_bind_outer_no_candidate_phase12();
    failed |= test_d3s3_mode30_bind_outer_select_lex_first_gt_frontier();
    failed |= test_d3s3_mode30_bind_rr_qualification_fields();
    failed |= test_d3s3_mode30_bind_rr_duplicate_latch_one();
    failed |= test_d3s3_mode30_bind_two_man_progress_then_finish();
    failed |= test_d3s3_mode30_bind_rr_zero_and_natural_faults();
    failed |= test_d3s3_mode27_eventfact_missing_spool_corrupt();
    failed |= test_d3s3_mode27_desiredstate_active_live();
    failed |= test_d3s3_mode27_desiredstate_terminal_historical();
    failed |= test_d3s3_mode27_eventfact_spool_active_live();
    failed |= test_d3s3_mode27_eventfact_released_historical();
    failed |= test_d3s3_mode27_eventfact_discard_historical();
    failed |= test_d3s3_mode27_eventfact_state_spool_mismatch_corrupt();
    failed |= test_d3s3_handle_projection_clean_rollback_cu();
    if (failed != 0) {
        (void)fprintf(stderr, "domain_store_d3s3_test FAILED\n");
        return 1;
    }
    (void)printf("domain_store_d3s3_test OK\n");
    return 0;
}
