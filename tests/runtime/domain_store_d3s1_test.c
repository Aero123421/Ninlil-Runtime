/*
 * D3-S1 chunk-A/B/C unit tests (docs/17 §18.12).
 * D3-S1 unit coverage for Modes 1–20 rebuild/evaluate.
 * The sibling crossrow production bridge supplies independent oracle coverage.
 * Does not claim D3 overall, Stage5 D3 bind, D4, or public Runtime.
 */

#include "domain_store_d3s1.h"
#include "domain_store_body_codec.h"
#include "domain_store_codec.h"
#include "domain_store_codec_internal.h"
#include "domain_store_scanner.h"
#include "runtime_store_codec.h"
#include "scripted_storage_spy.h"

#include "domain_store_d3s1_fixtures.h"

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

/* Castagnoli CRC32C (same as production codec) for PVD patch. */
static uint32_t crc32c_bytes(const uint8_t *data, uint32_t length)
{
    return ninlil_model_domain_crc32c(data, length);
}

static void write_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

/* Patch primary_value_digest at value offset 72 and recompute CRC. */
static int patch_pvd(
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
    crc = crc32c_bytes(value, 12u + payload_len);
    write_u32_be(&value[12u + payload_len], crc);
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

static void s2_set_id(ninlil_id128_t *id, uint8_t first)
{
    uint8_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(first + i);
    }
}

static void s2_default_binding(ninlil_model_runtime_store_binding_t *b)
{
    (void)memset(b, 0, sizeof(*b));
    b->storage_schema = NINLIL_STORAGE_SCHEMA_M1A;
    b->role = NINLIL_ROLE_CONTROLLER;
    b->environment = NINLIL_ENV_TEST;
    s2_set_id(&b->runtime_id, 0x10u);
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

static int s2_install_full_profile(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_model_runtime_store_binding_t *candidate)
{
    uint32_t key_id;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_model_runtime_store_key_t key;
    uint8_t value[183];
    uint32_t value_length;

    s2_default_binding(candidate);
    (void)memset(&identity, 0, sizeof(identity));
    identity.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    s2_set_id(&identity.device_id, 0x20u);
    s2_set_id(&identity.installation_id, 0x40u);
    s2_set_id(&identity.site_domain_id, 0x60u);
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

/* ---- context size / aggregate math ---- */

static int test_d3s1_context_size_and_aggregate(void)
{
    REQUIRE(sizeof(ninlil_domain_scan_d3s1_context_t)
        == NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_SIZE_BYTES);
    REQUIRE(sizeof(ninlil_domain_scan_d3s1_context_t)
        <= NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_CEILING_BYTES);
    REQUIRE(_Alignof(ninlil_domain_scan_d3s1_context_t) == 1);
    REQUIRE(
        NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_SIZE_BYTES
        == 32u + 45u + 255u + 64u + 16u + 9u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S1_AGGREGATE_PACKED_SUM_BYTES == 8805u);
    REQUIRE(
        NINLIL_DOMAIN_SCAN_D3S1_STAGE5_FUTURE_PACKED_BYTES
            + NINLIL_DOMAIN_SCAN_D3S1_CONTEXT_CEILING_BYTES
        == NINLIL_DOMAIN_SCAN_D3S1_AGGREGATE_ARENA_CEILING_BYTES);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S1_AGGREGATE_ARENA_CEILING_BYTES == 8832u);
    REQUIRE(NINLIL_DOMAIN_SCAN_D3S1_STAGE5_SEAM_ALONE_CEILING_BYTES == 8704u);
    /* Session gains non-owning D3 pointer (doc future 144 on LP64). */
    REQUIRE(sizeof(ninlil_domain_scan_session_t)
        <= NINLIL_DOMAIN_SCAN_D3S1_SESSION_FUTURE_BYTES);
    REQUIRE(sizeof(ninlil_domain_scan_session_t) >= 136u);
    REQUIRE(NINLIL_DOMAIN_SCANNER_WORKSPACE_CEILING_BYTES == 8192u);
    return 0;
}

/* ---- peer-key rebuild golden (Modes 1–10) ---- */

static int test_d3s1_rebuild_modes_1_10(void)
{
    uint8_t key[45];
    uint8_t key_len = 0u;
    uint8_t scope255[255];
    uint8_t idem64[64];
    uint8_t tx[16];
    uint32_t i;
    ninlil_domain_scan_d3s1_context_t ctx;

    /* Mode 1: SERVICE → QUOTA from fixture raw. */
    {
        const uint8_t *svc_body = &DSB2_SERVICE_TYPED_VALUE[12u + 96u];
        uint16_t raw_len = (uint16_t)(((uint16_t)svc_body[0] << 8) | svc_body[1]);
        const uint8_t *raw = &svc_body[2];
        REQUIRE(raw_len == 69u);
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_service_quota_key(
                raw, raw_len, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB2_QUOTA_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB2_QUOTA_TYPED_KEY, key_len) == 0);
    }

    /* Mode 2: SERVICE → RES. */
    {
        const uint8_t *svc_body = &DSB2_SERVICE_TYPED_VALUE[12u + 96u];
        uint16_t raw_len = (uint16_t)(((uint16_t)svc_body[0] << 8) | svc_body[1]);
        const uint8_t *raw = &svc_body[2];
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_service_reservation_key(
                raw, raw_len, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB2_RES_SVC_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB2_RES_SVC_TYPED_KEY, key_len) == 0);
    }

    /* Mode 3: TX → SEQ. */
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_sequence_index_key(
            1u, key, &key_len)
        == NINLIL_OK);
    REQUIRE(key_len == DSB2_SEQ_TYPED_KEY_LEN);
    REQUIRE(memcmp(key, DSB2_SEQ_TYPED_KEY, key_len) == 0);

    /* Mode 4: TX → STATE. */
    (void)memcpy(tx, &DSB2_ANCHOR_TYPED_VALUE[12u + 96u], 16u);
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_state_key(tx, key, &key_len)
        == NINLIL_OK);
    REQUIRE(key_len == DSB2_STATE_TYPED_KEY_LEN);
    REQUIRE(memcmp(key, DSB2_STATE_TYPED_KEY, key_len) == 0);

    /* Mode 5: dual RAW16 + max 255+64. */
    {
        const uint8_t *idem_body = &DSB2_IDEM_TYPED_VALUE[12u + 96u];
        uint16_t scope_len =
            (uint16_t)(((uint16_t)idem_body[0] << 8) | idem_body[1]);
        const uint8_t *scope = &idem_body[2];
        uint16_t ik_len = (uint16_t)(
            ((uint16_t)idem_body[2u + scope_len] << 8)
            | idem_body[2u + scope_len + 1u]);
        const uint8_t *ik = &idem_body[2u + scope_len + 2u];
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
                scope, scope_len, ik, ik_len, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB2_IDEM_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB2_IDEM_TYPED_KEY, key_len) == 0);

        for (i = 0u; i < 255u; i += 1u) {
            scope255[i] = (uint8_t)(i & 0xffu);
        }
        for (i = 0u; i < 64u; i += 1u) {
            idem64[i] = (uint8_t)(0xa0u + (i & 0x1fu));
        }
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
                scope255, 255u, idem64, 64u, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len >= 13u && key_len <= 45u);
        /* Dispatcher dual-raw path. */
        (void)memset(&ctx, 0, sizeof(ctx));
        ctx.mode = NINLIL_DOMAIN_SCAN_D3S1_MODE_TX_IDEMPOTENCY_MAP;
        (void)memcpy(ctx.source_raw, scope255, 255u);
        ctx.source_raw_len = 255u;
        (void)memcpy(ctx.source_raw2, idem64, 64u);
        ctx.source_raw2_len = 64u;
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
            == NINLIL_OK);
        REQUIRE(ctx.peer_key_len == key_len);
        REQUIRE(memcmp(ctx.peer_key, key, key_len) == 0);
    }

    /* Mode 6: TX RES. */
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_reservation_key(tx, key, &key_len)
        == NINLIL_OK);
    REQUIRE(key_len == DSB2_RES_TX_TYPED_KEY_LEN);
    REQUIRE(memcmp(key, DSB2_RES_TX_TYPED_KEY, key_len) == 0);

    /* Mode 7: SCHED U64 — golden SCHED fixture uses sequence 1. */
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_scheduler_owner_key(
            1u, key, &key_len)
        == NINLIL_OK);
    REQUIRE(key_len == DSB3_SCHED_TX_TYPED_KEY_LEN);
    REQUIRE(memcmp(key, DSB3_SCHED_TX_TYPED_KEY, key_len) == 0);

    /* Mode 8: EVENT_ID_MAP. */
    {
        const uint8_t *eb = &DSB2_EVMAP_TYPED_VALUE[12u + 96u];
        uint16_t scope_len = (uint16_t)(((uint16_t)eb[0] << 8) | eb[1]);
        const uint8_t *scope = &eb[2];
        const uint8_t *event_id = &eb[2u + scope_len];
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_event_id_map_key(
                scope, scope_len, event_id, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB2_EVMAP_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB2_EVMAP_TYPED_KEY, key_len) == 0);
    }

    /* Mode 9: EVENT_SPOOL ID128. */
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_event_spool_key(tx, key, &key_len)
        == NINLIL_OK);
    REQUIRE(key_len == DSB3_ES_ACTIVE_TYPED_KEY_LEN);
    REQUIRE(memcmp(key, DSB3_ES_ACTIVE_TYPED_KEY, key_len) == 0);

    /* Mode 10: CANCEL_STATE. */
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_cancel_state_key(
            tx, key, &key_len)
        == NINLIL_OK);
    REQUIRE(key_len == DSB3_CS_TX_NONE_TYPED_KEY_LEN);
    REQUIRE(memcmp(key, DSB3_CS_TX_NONE_TYPED_KEY, key_len) == 0);

    /* Modes 11–16 pure rebuild goldens from fixtures (not length-only smoke). */
    {
        const uint8_t *dlv_body = &DSB3_DLV_APP_DS_TYPED_VALUE[12u + 96u];
        uint16_t dlv_raw_len =
            (uint16_t)(((uint16_t)dlv_body[0] << 8) | dlv_body[1]);
        const uint8_t *dlv_raw = &dlv_body[2];
        uint64_t sched_seq;
        REQUIRE(dlv_raw_len == 80u);
        /* Mode 11 RESULT_CACHE key. */
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_result_cache_key(
                dlv_raw, dlv_raw_len, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB3_RC_INBOX_VIRGIN_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB3_RC_INBOX_VIRGIN_TYPED_KEY, key_len) == 0);
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_result_cache_key(
                dlv_raw, 79u, key, &key_len)
            == NINLIL_E_INVALID_ARGUMENT);
        /* Mode 12 DELIVERY RES. */
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_reservation_key(
                dlv_raw, dlv_raw_len, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB2_RES_DLV_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB2_RES_DLV_TYPED_KEY, key_len) == 0);
        /* Mode 13 SCHEDULER pure golden (fixture SCHED_DLV sequence). */
        sched_seq = ninlil_model_domain_decode_u64_be(
            &DSB3_SCHED_DLV_TYPED_VALUE[12u + 96u]);
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_scheduler_owner_key(
                sched_seq, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB3_SCHED_DLV_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB3_SCHED_DLV_TYPED_KEY, key_len) == 0);
        /* Mode 14 CANCEL. */
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_cancel_state_key(
                dlv_raw, dlv_raw_len, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB3_CS_DLV_NONE_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB3_CS_DLV_NONE_TYPED_KEY, key_len) == 0);
        /* Mode 15 INGRESS RES for fixture sequence 7. */
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_ingress_reservation_key(
                7u, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB2_RES_ING_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB2_RES_ING_TYPED_KEY, key_len) == 0);
        /* Mode 16 INGRESS SCHEDULER: fixture SCHED_ING is sequence 3. */
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_ingress_scheduler_owner_key(
                3u, key, &key_len)
            == NINLIL_OK);
        REQUIRE(key_len == DSB3_SCHED_ING_TYPED_KEY_LEN);
        REQUIRE(memcmp(key, DSB3_SCHED_ING_TYPED_KEY, key_len) == 0);
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_ingress_reservation_key(
                0u, key, &key_len)
            == NINLIL_E_INVALID_ARGUMENT);
    }

    /* Mode 17 without reverse material → INVALID_ARGUMENT. */
    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.mode = 17u;
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
        == NINLIL_E_INVALID_ARGUMENT);
    /* Mode 11 dispatch implemented. */
    ctx.mode = 11u;
    ctx.source_raw_len = 80u;
    {
        uint8_t i;
        for (i = 0u; i < 80u; ++i) {
            ctx.source_raw[i] = (uint8_t)(0x20u + i);
        }
    }
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
        == NINLIL_OK);
    REQUIRE(ctx.peer_key_len >= 13u);
    return 0;
}

/* ---- begin prevalidation ---- */

static int test_d3s1_begin_prevalidation(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint64_t before;
    uint8_t session_canary[sizeof(session)];
    uint8_t context_canary[sizeof(context)];
    uint8_t poison = 0xA5u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, poison, sizeof(context));
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    before = spy.trace_count;
    (void)memcpy(session_canary, &session, sizeof(session));
    (void)memcpy(context_canary, &context, sizeof(context));

    /* null context */
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);

    /* bad mode 0 / 21 — poison context untouched (prevalidation contract). */
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 0u, &context)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 21u, &context)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    REQUIRE(memcmp(&context, context_canary, sizeof(context)) == 0);

    /*
     * Modes 1–20: valid begin (chunk-C). Mode 0/21 INVALID above.
     * Successful begin zeros control/length/flags; poison not retained.
     */
    {
        uint8_t m;
        for (m = 1u; m <= 20u; m += 1u) {
            ninlil_domain_scan_session_init(&session);
            (void)memset(&workspace, 0, sizeof(workspace));
            (void)memset(&context, poison, sizeof(context));
            handle = ninlil_spy_open_handle(&spy);
            REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
                    &session, ops, &handle, &workspace, &candidate, m,
                    &context)
                == NINLIL_OK);
            REQUIRE(session.bound_d3_context == &context);
            REQUIRE(context.mode == m);
            REQUIRE(context.peer_key_len == 0u);
            REQUIRE(context.source_raw_len == 0u);
            REQUIRE(context.source_raw2_len == 0u);
            REQUIRE(context.source_aux_len == 0u);
            REQUIRE(context.flags == 0u);
            REQUIRE(context.source_subtype == 0u);
            REQUIRE(context.expect_presence == 0u);
            REQUIRE(context.owner_kind == 0u);
            {
                ninlil_domain_scan_result_t abort_result;
                REQUIRE(ninlil_domain_scan_abort(&session, &abort_result)
                    == NINLIL_OK);
            }
        }
    }

    /* alias: context overlaps session (prevalidation; Port 0; state unchanged). */
    ninlil_domain_scan_session_init(&session);
    (void)memset(&context, 0, sizeof(context));
    (void)memcpy(session_canary, &session, sizeof(session));
    before = spy.trace_count;
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u,
            (ninlil_domain_scan_d3s1_context_t *)(void *)&session)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(spy.trace_count == before);
    REQUIRE(memcmp(&session, session_canary, sizeof(session)) == 0);
    return 0;
}

static int test_d2_begin_leaves_d3_inactive(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    REQUIRE(ninlil_domain_scan_begin_profiled(
            &session, ops, &handle, &workspace, &candidate)
        == NINLIL_OK);
    REQUIRE(session.bound_d3_context == NULL);
    while (session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        REQUIRE(ninlil_domain_scan_advance(&session, 64u) == NINLIL_OK
            || session.state != NINLIL_DOMAIN_SCAN_STATE_OPEN);
        if (session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED) {
            break;
        }
    }
    REQUIRE(session.bound_d3_context == NULL);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK
        || result.adopted == 0u);
    REQUIRE(session.bound_d3_context == NULL);
    return 0;
}

/* ---- evaluator SERVICE modes ---- */

static int scan_until_terminal(ninlil_domain_scan_session_t *session)
{
    ninlil_status_t st;
    while (session->state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        st = ninlil_domain_scan_advance(session, 64u);
        if (st != NINLIL_OK) {
            return (int)st;
        }
    }
    return 0;
}

static int test_d3s1_service_mode1_present_ok(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t quota_value[DSB2_QUOTA_TYPED_VALUE_LEN];
    uint8_t pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_SERVICE_TYPED_VALUE, (uint32_t)DSB2_SERVICE_TYPED_VALUE_LEN, pvd));
    (void)memcpy(
        quota_value, DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(
        quota_value, (uint32_t)DSB2_QUOTA_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, quota_value,
        DSB2_QUOTA_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    REQUIRE(session.bound_d3_context == &context);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_d3s1_service_mode1_absent_notes_no_ok_inc(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    /* SERVICE only — QUOTA missing → D3 finding. */
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    REQUIRE(session.ok_row_count == 0u);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    REQUIRE(session.sticky_primary == NINLIL_E_STORAGE_CORRUPT);
    /* Catalog 17 rows succeed; SERVICE finding aborts before its ok++. */
    REQUIRE(session.ok_row_count == 17u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.ok_row_count == 17u);
    return 0;
}

static int test_d3s1_service_mode1_pvd_and_raw_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t quota_value[DSB2_QUOTA_TYPED_VALUE_LEN];
    uint8_t bad_pvd[32];

    /* PVD mismatch: leave fixture PVD (0x55..) against real SERVICE digest. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN,
        DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.ok_row_count == 17u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);

    /* Raw bijection mismatch: correct PVD but flip peer raw byte. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_SERVICE_TYPED_VALUE, (uint32_t)DSB2_SERVICE_TYPED_VALUE_LEN,
        bad_pvd));
    (void)memcpy(
        quota_value, DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(
        quota_value, (uint32_t)DSB2_QUOTA_TYPED_VALUE_LEN, bad_pvd));
    /* Flip a content byte inside service_key_raw after RAW16 length. */
    quota_value[12u + 96u + 4u] ^= 0x01u;
    {
        uint32_t payload_len =
            ((uint32_t)quota_value[8] << 24) | ((uint32_t)quota_value[9] << 16)
            | ((uint32_t)quota_value[10] << 8) | (uint32_t)quota_value[11];
        write_u32_be(
            &quota_value[12u + payload_len],
            crc32c_bytes(quota_value, 12u + payload_len));
    }
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, quota_value,
        DSB2_QUOTA_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.ok_row_count == 17u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

static int test_d3s1_port_failure_no_note(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t quota_value[DSB2_QUOTA_TYPED_VALUE_LEN];
    uint8_t pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_SERVICE_TYPED_VALUE, (uint32_t)DSB2_SERVICE_TYPED_VALUE_LEN, pvd));
    (void)memcpy(
        quota_value, DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(
        quota_value, (uint32_t)DSB2_QUOTA_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, quota_value,
        DSB2_QUOTA_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    /*
     * After 17 profile gets, exact_get for D3 is the next GET.
     * Fault the first post-begin GET that is not a profile get:
     * begin does 17 gets; D3 exact_get is get #18 when SERVICE is visited
     * after catalog iteration — fault all GETs after profile with IO.
     */
    REQUIRE(ninlil_spy_add_fault(
        &spy, NINLIL_SPY_OP_GET, spy.get_calls + 1u, NINLIL_STORAGE_IO_ERROR,
        NINLIL_SPY_SHAPE_NATURAL, 0u, 0u));
    /* Advance through catalog; when SERVICE triggers D3 get, fault fires. */
    {
        ninlil_status_t st = NINLIL_OK;
        while (session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
            st = ninlil_domain_scan_advance(&session, 1u);
            if (st != NINLIL_OK) {
                break;
            }
        }
        /* Port IO → STORAGE (not STORAGE_CORRUPT from note). */
        REQUIRE(st == NINLIL_E_STORAGE);
        REQUIRE(session.sticky_primary == NINLIL_E_STORAGE);
        REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_FAILED);
    }
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_E_STORAGE);
    REQUIRE(result.adopted == 0u);
    return 0;
}

static int test_d3s1_non_applicable_skips_get(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint64_t gets_at_open;

    /* Mode 1 with only TX ANCHOR (non-applicable): no D3 get, scan OK. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    gets_at_open = spy.get_calls;
    REQUIRE(scan_until_terminal(&session) == 0);
    /* No extra D3 exact_get beyond catalog profile gets. */
    REQUIRE(spy.get_calls == gets_at_open);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    return 0;
}

/* ---- TX / DS Mode 8 & 9 separate sessions ---- */

static int install_anchor_with_pvd_peer(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *peer_key,
    size_t peer_key_len,
    const uint8_t *peer_value_src,
    size_t peer_value_len,
    uint8_t *peer_value_buf)
{
    uint8_t pvd[32];
    REQUIRE(add_domain_row(
        spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN, pvd));
    (void)memcpy(peer_value_buf, peer_value_src, peer_value_len);
    REQUIRE(patch_pvd(peer_value_buf, (uint32_t)peer_value_len, pvd));
    REQUIRE(add_domain_row(
        spy, peer_key, peer_key_len, peer_value_buf, peer_value_len));
    return 0;
}

static int test_d3s1_tx_mode3_present(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t peer[DSB2_SEQ_TYPED_VALUE_LEN];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_anchor_with_pvd_peer(
            &spy, DSB2_SEQ_TYPED_KEY, DSB2_SEQ_TYPED_KEY_LEN,
            DSB2_SEQ_TYPED_VALUE, DSB2_SEQ_TYPED_VALUE_LEN, peer)
        == 0);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 3u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_d3s1_ds_mode8_and_mode9_absent_separate_sessions(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    /* ANCHOR is DesiredState (family=2): Mode 8 expects EVENT_MAP ABSENT. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 8u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);

    /* Fresh session Mode 9 EVENT_SPOOL ABSENT for DesiredState. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 9u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    return 0;
}

static int test_d3s1_mode2_present(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t res_value[DSB2_RES_SVC_TYPED_VALUE_LEN];
    uint8_t pvd[32];

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_SERVICE_TYPED_VALUE, (uint32_t)DSB2_SERVICE_TYPED_VALUE_LEN, pvd));
    (void)memcpy(
        res_value, DSB2_RES_SVC_TYPED_VALUE, DSB2_RES_SVC_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(
        res_value, (uint32_t)DSB2_RES_SVC_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_RES_SVC_TYPED_KEY, DSB2_RES_SVC_TYPED_KEY_LEN, res_value,
        DSB2_RES_SVC_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 2u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* Modes 4 / 6 / 10 PRESENT (DesiredState anchor + peer). */
static int test_d3s1_tx_modes_4_6_10_present(void)
{
    const struct {
        uint8_t mode;
        const uint8_t *peer_key;
        size_t peer_key_len;
        const uint8_t *peer_value;
        size_t peer_value_len;
    } cases[] = {
        { 4u, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
            DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN },
        { 6u, DSB2_RES_TX_TYPED_KEY, DSB2_RES_TX_TYPED_KEY_LEN,
            DSB2_RES_TX_TYPED_VALUE, DSB2_RES_TX_TYPED_VALUE_LEN },
        { 10u, DSB3_CS_TX_NONE_TYPED_KEY, DSB3_CS_TX_NONE_TYPED_KEY_LEN,
            DSB3_CS_TX_NONE_TYPED_VALUE, DSB3_CS_TX_NONE_TYPED_VALUE_LEN },
    };
    size_t i;

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); i += 1u) {
        ninlil_scripted_storage_spy_t spy;
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s1_context_t context;
        ninlil_domain_scan_result_t result;
        ninlil_model_runtime_store_binding_t candidate;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        uint8_t peer[512];

        REQUIRE(cases[i].peer_value_len <= sizeof(peer));
        ninlil_spy_init(&spy);
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        REQUIRE(s2_install_full_profile(&spy, &candidate));
        REQUIRE(install_anchor_with_pvd_peer(
                &spy, cases[i].peer_key, cases[i].peer_key_len,
                cases[i].peer_value, cases[i].peer_value_len, peer)
            == 0);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
                &session, ops, &handle, &workspace, &candidate, cases[i].mode,
                &context)
            == NINLIL_OK);
        REQUIRE(scan_until_terminal(&session) == 0);
        REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
        REQUIRE(result.adopted == 1u);
        REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    }
    return 0;
}

/*
 * Mode 7 PRESENT: ANCHOR fixture has scheduler_owner_sequence=2; peer key
 * must be rebuilt for that sequence (fixture SCHED key is sequence 1).
 */
static int test_d3s1_tx_mode7_present(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t peer_key[45];
    uint8_t peer_key_len = 0u;
    uint8_t peer_src[DSB3_SCHED_TX_TYPED_VALUE_LEN];
    uint8_t peer[DSB3_SCHED_TX_TYPED_VALUE_LEN];
    uint32_t payload_len;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_scheduler_owner_key(
            2u, peer_key, &peer_key_len)
        == NINLIL_OK);
    (void)memcpy(
        peer_src, DSB3_SCHED_TX_TYPED_VALUE, DSB3_SCHED_TX_TYPED_VALUE_LEN);
    /* Patch body owner_sequence u64 at body start (offset 12+96) to 2. */
    {
        uint8_t *body = &peer_src[12u + 96u];
        body[0] = 0u;
        body[1] = 0u;
        body[2] = 0u;
        body[3] = 0u;
        body[4] = 0u;
        body[5] = 0u;
        body[6] = 0u;
        body[7] = 2u;
        payload_len = ((uint32_t)peer_src[8] << 24)
            | ((uint32_t)peer_src[9] << 16) | ((uint32_t)peer_src[10] << 8)
            | (uint32_t)peer_src[11];
        write_u32_be(
            &peer_src[12u + payload_len],
            crc32c_bytes(peer_src, 12u + payload_len));
    }
    REQUIRE(install_anchor_with_pvd_peer(
            &spy, peer_key, peer_key_len, peer_src,
            DSB3_SCHED_TX_TYPED_VALUE_LEN, peer)
        == 0);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 7u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/* Mode 5 dual-raw PRESENT (fixture lengths) + mismatch each raw half. */
static int test_d3s1_mode5_dual_raw_present_and_half_mismatch(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t peer[DSB2_IDEM_TYPED_VALUE_LEN];
    uint8_t pvd[32];
    uint32_t payload_len;

    /* PRESENT happy path. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_anchor_with_pvd_peer(
            &spy, DSB2_IDEM_TYPED_KEY, DSB2_IDEM_TYPED_KEY_LEN,
            DSB2_IDEM_TYPED_VALUE, DSB2_IDEM_TYPED_VALUE_LEN, peer)
        == 0);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 5u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);

    /* Scope half mismatch: flip first raw byte after scope RAW16 length. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN, pvd));
    (void)memcpy(peer, DSB2_IDEM_TYPED_VALUE, DSB2_IDEM_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(peer, (uint32_t)DSB2_IDEM_TYPED_VALUE_LEN, pvd));
    /* body starts at 12+96; first RAW16 is scope. */
    peer[12u + 96u + 2u] ^= 0x01u;
    payload_len = ((uint32_t)peer[8] << 24) | ((uint32_t)peer[9] << 16)
        | ((uint32_t)peer[10] << 8) | (uint32_t)peer[11];
    write_u32_be(&peer[12u + payload_len], crc32c_bytes(peer, 12u + payload_len));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_IDEM_TYPED_KEY, DSB2_IDEM_TYPED_KEY_LEN, peer,
        DSB2_IDEM_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 5u, &context)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.ok_row_count == 17u);

    /* Idempotency-key half mismatch: flip first byte of second RAW16. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN, pvd));
    (void)memcpy(peer, DSB2_IDEM_TYPED_VALUE, DSB2_IDEM_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(peer, (uint32_t)DSB2_IDEM_TYPED_VALUE_LEN, pvd));
    {
        const uint8_t *body = &peer[12u + 96u];
        uint16_t scope_len =
            (uint16_t)(((uint16_t)body[0] << 8) | body[1]);
        peer[12u + 96u + 2u + scope_len + 2u] ^= 0x01u;
    }
    payload_len = ((uint32_t)peer[8] << 24) | ((uint32_t)peer[9] << 16)
        | ((uint32_t)peer[10] << 8) | (uint32_t)peer[11];
    write_u32_be(&peer[12u + payload_len], crc32c_bytes(peer, 12u + payload_len));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
        DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_IDEM_TYPED_KEY, DSB2_IDEM_TYPED_KEY_LEN, peer,
        DSB2_IDEM_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 5u, &context)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(session.ok_row_count == 17u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * Mode 5 rebuild max dual-raw 255+64 remains unit-covered in
 * test_d3s1_rebuild_modes_1_10; integration uses fixture dual-raw above.
 */

/* Mode 8/9 EventFact PRESENT; Mode 10 EventFact ABSENT. */
static int test_d3s1_ef_mode8_9_present_mode10_absent(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t peer[512];
    uint8_t pvd[32];

    /* Mode 8 EventFact + EVENT_ID_MAP PRESENT. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_EF_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN,
        pvd));
    (void)memcpy(peer, DSB2_EVMAP_TYPED_VALUE, DSB2_EVMAP_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(peer, (uint32_t)DSB2_EVMAP_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_EF_TYPED_KEY, DSB2_ANCHOR_EF_TYPED_KEY_LEN,
        DSB2_ANCHOR_EF_TYPED_VALUE, DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_EVMAP_TYPED_KEY, DSB2_EVMAP_TYPED_KEY_LEN, peer,
        DSB2_EVMAP_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 8u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);

    /* Mode 9 EventFact + EVENT_SPOOL PRESENT. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_ANCHOR_EF_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_EF_TYPED_VALUE_LEN,
        pvd));
    REQUIRE(DSB3_ES_ACTIVE_TYPED_VALUE_LEN <= sizeof(peer));
    (void)memcpy(
        peer, DSB3_ES_ACTIVE_TYPED_VALUE, DSB3_ES_ACTIVE_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(peer, (uint32_t)DSB3_ES_ACTIVE_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_EF_TYPED_KEY, DSB2_ANCHOR_EF_TYPED_KEY_LEN,
        DSB2_ANCHOR_EF_TYPED_VALUE, DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_ES_ACTIVE_TYPED_KEY, DSB3_ES_ACTIVE_TYPED_KEY_LEN, peer,
        DSB3_ES_ACTIVE_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 9u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);

    /* Mode 10 EventFact: CANCEL_STATE expected ABSENT. */
    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_ANCHOR_EF_TYPED_KEY, DSB2_ANCHOR_EF_TYPED_KEY_LEN,
        DSB2_ANCHOR_EF_TYPED_VALUE, DSB2_ANCHOR_EF_TYPED_VALUE_LEN));
    ninlil_domain_scan_session_init(&session);
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 10u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * After successful D3 exact_get, workspace->key remains the source key and
 * previous_key becomes that same source key (exact_get writes value only).
 */
static int test_d3s1_previous_key_preserved_after_exact_get(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t quota_value[DSB2_QUOTA_TYPED_VALUE_LEN];
    uint8_t pvd[32];
    uint8_t source_key_snapshot[NINLIL_DOMAIN_SCAN_KEY_CAPACITY];
    uint32_t source_key_len = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_SERVICE_TYPED_VALUE, (uint32_t)DSB2_SERVICE_TYPED_VALUE_LEN, pvd));
    (void)memcpy(
        quota_value, DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(
        quota_value, (uint32_t)DSB2_QUOTA_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, quota_value,
        DSB2_QUOTA_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);

    while (session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN
        && session.ok_row_count < 18u) {
        REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK);
        if (session.ok_row_count == 18u) {
            /* 17 catalog + SERVICE: source key must survive exact_get. */
            source_key_len = session.previous_key_length;
            REQUIRE(source_key_len == DSB2_SERVICE_TYPED_KEY_LEN);
            (void)memcpy(
                source_key_snapshot, workspace.previous_key, source_key_len);
            REQUIRE(memcmp(
                        source_key_snapshot, DSB2_SERVICE_TYPED_KEY,
                        source_key_len)
                == 0);
            /* workspace.key still the iterator source key (not peer). */
            REQUIRE(memcmp(
                        workspace.key, DSB2_SERVICE_TYPED_KEY,
                        DSB2_SERVICE_TYPED_KEY_LEN)
                == 0);
            /* Peer key lives only in context. */
            REQUIRE(context.peer_key_len >= 13u);
            REQUIRE(memcmp(
                        context.peer_key, DSB2_QUOTA_TYPED_KEY,
                        context.peer_key_len)
                == 0);
            break;
        }
    }
    REQUIRE(source_key_len == DSB2_SERVICE_TYPED_KEY_LEN);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * Regression (Issue 1): D3-bound session with a real CURRENT SERVICE then a
 * domain-shaped RECOGNIZABLE_FUTURE row must stay future/UNSUPPORTED and must
 * never note CORRUPT from stale typed scratch.
 */
static int test_d3s1_future_domain_shaped_no_stale_typed_corrupt(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t quota_value[DSB2_QUOTA_TYPED_VALUE_LEN];
    uint8_t pvd[32];
    uint8_t future_key[45];
    uint8_t future_value[DSB2_SERVICE_TYPED_VALUE_LEN];
    uint32_t payload_len;
    uint32_t i;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB2_SERVICE_TYPED_VALUE, (uint32_t)DSB2_SERVICE_TYPED_VALUE_LEN, pvd));
    (void)memcpy(
        quota_value, DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(
        quota_value, (uint32_t)DSB2_QUOTA_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, quota_value,
        DSB2_QUOTA_TYPED_VALUE_LEN));

    /*
     * Domain-shaped future key: NINLIL root + key_version=2, family/subtype
     * bytes at [8]/[9] still look like SERVICE so a stale typed gate would
     * falsely apply Mode 1. Sorts after CURRENT v1 keys.
     */
    REQUIRE(DSB2_SERVICE_TYPED_KEY_LEN <= sizeof(future_key));
    (void)memcpy(
        future_key, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN);
    future_key[7] = 0x02u;
    /* Distinct identity so key order is unique. */
    for (i = 13u; i < DSB2_SERVICE_TYPED_KEY_LEN; i += 1u) {
        future_key[i] ^= 0x5Au;
    }
    (void)memcpy(
        future_value, DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN);
    /* Valid NLR1 framing CRC retained from fixture value. */
    payload_len = ((uint32_t)future_value[8] << 24)
        | ((uint32_t)future_value[9] << 16)
        | ((uint32_t)future_value[10] << 8)
        | (uint32_t)future_value[11];
    REQUIRE(12u + payload_len + 4u == DSB2_SERVICE_TYPED_VALUE_LEN);
    REQUIRE(add_domain_row(
        &spy, future_key, DSB2_SERVICE_TYPED_KEY_LEN, future_value,
        DSB2_SERVICE_TYPED_VALUE_LEN));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(session.state == NINLIL_DOMAIN_SCAN_STATE_EXHAUSTED);
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.recognizable_future_seen == 1u);
    REQUIRE(result.status == NINLIL_E_UNSUPPORTED);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

/*
 * Framing-future peer value at rebuilt PRESENT key: D3 must not false-note
 * CORRUPT from v1 body mis-parse; full peer structural stays S3-owned.
 */
static int test_d3s1_future_peer_value_not_false_corrupt(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t future_peer_value[64];
    uint8_t payload[4] = { 0x01u, 0x02u, 0x03u, 0x04u };
    uint32_t o = 0u;
    uint32_t crc;

    /* Build NLR1 future record_version=2 value with valid CRC. */
    future_peer_value[o++] = (uint8_t)'N';
    future_peer_value[o++] = (uint8_t)'L';
    future_peer_value[o++] = (uint8_t)'R';
    future_peer_value[o++] = (uint8_t)'1';
    future_peer_value[o++] = 0x00u;
    future_peer_value[o++] = 0x06u; /* record_type DOMAIN */
    future_peer_value[o++] = 0x00u;
    future_peer_value[o++] = 0x02u; /* record_version future */
    future_peer_value[o++] = 0x00u;
    future_peer_value[o++] = 0x00u;
    future_peer_value[o++] = 0x00u;
    future_peer_value[o++] = 0x04u; /* payload_len */
    (void)memcpy(&future_peer_value[o], payload, 4u);
    o += 4u;
    crc = crc32c_bytes(future_peer_value, o);
    write_u32_be(&future_peer_value[o], crc);
    o += 4u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
        DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, future_peer_value,
        o));

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 1u, &context)
        == NINLIL_OK);
    REQUIRE(scan_until_terminal(&session) == 0);
    /*
     * Peer PRESENT with framing-future value: D3 does not false-note CORRUPT
     * from v1 body mis-parse. S3 later sees the peer key as CURRENT with
     * framing-future value → recognizable_future_seen; finalize UNSUPPORTED.
     */
    REQUIRE(session.has_sticky_primary == 0u);
    REQUIRE(session.recognizable_future_seen == 1u);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result)
        == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.adopted == 0u);
    REQUIRE(result.status == NINLIL_E_UNSUPPORTED);
    REQUIRE(result.recognizable_future_seen == 1u);
    return 0;
}

/* ---- chunk-B helpers: DELIVERY / ORDERED_INGRESS ---- */

/*
 * Install source + PVD-patched peer. Spy iteration is insertion order and the
 * scanner requires strictly increasing keys, so rows are added in key order.
 */
static int install_source_with_pvd_peer(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *source_key,
    size_t source_key_len,
    const uint8_t *source_value,
    size_t source_value_len,
    const uint8_t *peer_key,
    size_t peer_key_len,
    const uint8_t *peer_value_src,
    size_t peer_value_len,
    uint8_t *peer_value_buf)
{
    uint8_t pvd[32];
    int peer_first;
    size_t min_len;
    int cmp;

    REQUIRE(compute_value_digest(
        source_value, (uint32_t)source_value_len, pvd));
    (void)memcpy(peer_value_buf, peer_value_src, peer_value_len);
    REQUIRE(patch_pvd(peer_value_buf, (uint32_t)peer_value_len, pvd));

    min_len = source_key_len < peer_key_len ? source_key_len : peer_key_len;
    cmp = memcmp(peer_key, source_key, min_len);
    if (cmp == 0) {
        peer_first = peer_key_len < source_key_len ? 1 : 0;
    } else {
        peer_first = cmp < 0 ? 1 : 0;
    }
    if (peer_first != 0) {
        REQUIRE(add_domain_row(
            spy, peer_key, peer_key_len, peer_value_buf, peer_value_len));
        REQUIRE(add_domain_row(
            spy, source_key, source_key_len, source_value, source_value_len));
    } else {
        REQUIRE(add_domain_row(
            spy, source_key, source_key_len, source_value, source_value_len));
        REQUIRE(add_domain_row(
            spy, peer_key, peer_key_len, peer_value_buf, peer_value_len));
    }
    return 0;
}

/* Add two domain rows in strictly increasing key order (spy insert order). */
static int add_two_domain_rows_sorted(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *key_a,
    size_t key_a_len,
    const uint8_t *value_a,
    size_t value_a_len,
    const uint8_t *key_b,
    size_t key_b_len,
    const uint8_t *value_b,
    size_t value_b_len)
{
    size_t min_len;
    int cmp;
    int a_first;

    min_len = key_a_len < key_b_len ? key_a_len : key_b_len;
    cmp = memcmp(key_a, key_b, min_len);
    if (cmp == 0) {
        a_first = key_a_len <= key_b_len ? 1 : 0;
    } else {
        a_first = cmp < 0 ? 1 : 0;
    }
    if (a_first != 0) {
        REQUIRE(add_domain_row(spy, key_a, key_a_len, value_a, value_a_len));
        REQUIRE(add_domain_row(spy, key_b, key_b_len, value_b, value_b_len));
    } else {
        REQUIRE(add_domain_row(spy, key_b, key_b_len, value_b, value_b_len));
        REQUIRE(add_domain_row(spy, key_a, key_a_len, value_a, value_a_len));
    }
    return 0;
}

static int patch_body_u64_be(
    uint8_t *value,
    uint32_t value_len,
    uint32_t body_offset,
    uint64_t v)
{
    uint32_t payload_len;
    uint8_t *body;

    if (value == NULL || value_len < 16u + 96u) {
        return 0;
    }
    payload_len = ((uint32_t)value[8] << 24) | ((uint32_t)value[9] << 16)
        | ((uint32_t)value[10] << 8) | (uint32_t)value[11];
    if (12u + payload_len + 4u != value_len
        || payload_len < 96u + body_offset + 8u) {
        return 0;
    }
    body = &value[12u + 96u];
    body[body_offset + 0u] = (uint8_t)(v >> 56);
    body[body_offset + 1u] = (uint8_t)(v >> 48);
    body[body_offset + 2u] = (uint8_t)(v >> 40);
    body[body_offset + 3u] = (uint8_t)(v >> 32);
    body[body_offset + 4u] = (uint8_t)(v >> 24);
    body[body_offset + 5u] = (uint8_t)(v >> 16);
    body[body_offset + 6u] = (uint8_t)(v >> 8);
    body[body_offset + 7u] = (uint8_t)v;
    write_u32_be(
        &value[12u + payload_len], crc32c_bytes(value, 12u + payload_len));
    return 1;
}

static int run_mode_scan_ok(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode)
{
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    int st;

    ops = ninlil_spy_ops(spy);
    handle = ninlil_spy_open_handle(spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, candidate, mode, &context)
        == NINLIL_OK);
    st = scan_until_terminal(&session);
    REQUIRE(st == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(spy));
    return 0;
}

static int run_mode_scan_corrupt(
    ninlil_scripted_storage_spy_t *spy,
    ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    uint32_t expected_ok_before_note)
{
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;

    ops = ninlil_spy_ops(spy);
    handle = ninlil_spy_open_handle(spy);
    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, candidate, mode, &context)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_scan_advance(&session, 64u)
        == NINLIL_E_STORAGE_CORRUPT);
    /* Finding must not increment ok_row_count past pre-note total. */
    REQUIRE(session.ok_row_count == expected_ok_before_note);
    REQUIRE(ninlil_spy_assert_no_mutations(spy));
    return 0;
}

/* Mode 11 PRESENT + ABSENT + PVD + raw. */
static int test_d3s1_mode11_result_cache(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t peer[DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN];
    uint8_t pvd[32];
    uint32_t payload_len;

    /* PRESENT happy path. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_source_with_pvd_peer(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            DSB3_RC_INBOX_VIRGIN_TYPED_KEY, DSB3_RC_INBOX_VIRGIN_TYPED_KEY_LEN,
            DSB3_RC_INBOX_VIRGIN_TYPED_VALUE,
            DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN, peer)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 11u) == 0);

    /* ABSENT peer. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 11u, 17u) == 0);

    /* PVD mismatch. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    (void)memcpy(
        peer, DSB3_RC_INBOX_VIRGIN_TYPED_VALUE,
        DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN);
    (void)memset(pvd, 0xAAu, sizeof(pvd));
    REQUIRE(patch_pvd(
        peer, (uint32_t)DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN, pvd));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_INBOX_VIRGIN_TYPED_KEY,
        DSB3_RC_INBOX_VIRGIN_TYPED_KEY_LEN, peer,
        DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 11u, 17u) == 0);

    /* Raw mismatch: flip first delivery raw content byte in RESULT body. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB3_DLV_APP_DS_TYPED_VALUE, (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
        pvd));
    (void)memcpy(
        peer, DSB3_RC_INBOX_VIRGIN_TYPED_VALUE,
        DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN);
    REQUIRE(patch_pvd(
        peer, (uint32_t)DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN, pvd));
    peer[12u + 96u + 2u] ^= 0x01u;
    payload_len = ((uint32_t)peer[8] << 24) | ((uint32_t)peer[9] << 16)
        | ((uint32_t)peer[10] << 8) | (uint32_t)peer[11];
    write_u32_be(
        &peer[12u + payload_len], crc32c_bytes(peer, 12u + payload_len));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_INBOX_VIRGIN_TYPED_KEY,
        DSB3_RC_INBOX_VIRGIN_TYPED_KEY_LEN, peer,
        DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 11u, 17u) == 0);
    return 0;
}

/* Mode 12: DELIVERY → DELIVERY RESERVATION PRESENT + ABSENT/PVD. */
static int test_d3s1_mode12_delivery_reservation(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t peer[DSB2_RES_DLV_TYPED_VALUE_LEN];

    /* PRESENT happy path: finalize adopted, no mutations. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_source_with_pvd_peer(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            DSB2_RES_DLV_TYPED_KEY, DSB2_RES_DLV_TYPED_KEY_LEN,
            DSB2_RES_DLV_TYPED_VALUE, DSB2_RES_DLV_TYPED_VALUE_LEN, peer)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 12u) == 0);

    /* ABSENT peer. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 12u, 17u) == 0);

    /*
     * PVD mismatch: fixture peer PVD vs live DELIVERY digest.
     * RES (0x23) sorts before DELIVERY (0x40): non-applicable ok first → 18.
     * (Peer-before raw flip is S3-owned when RES is CURRENT; Mode11 RESULT
     * after DELIVERY covers D3 raw via exact_get before peer CURRENT.)
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            DSB2_RES_DLV_TYPED_KEY, DSB2_RES_DLV_TYPED_KEY_LEN,
            DSB2_RES_DLV_TYPED_VALUE, DSB2_RES_DLV_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 12u, 18u) == 0);
    return 0;
}

/* Mode 13: DELIVERY → SCHEDULER_OWNER via scheduler_owner_sequence (=1). */
static int test_d3s1_mode13_delivery_scheduler(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t peer_key[45];
    uint8_t peer_key_len = 0u;
    uint8_t peer_src[DSB3_SCHED_DLV_TYPED_VALUE_LEN];
    uint8_t peer[DSB3_SCHED_DLV_TYPED_VALUE_LEN];

    /* PRESENT: rebuild key for delivery sequence 1; fixture SCHED is seq 2. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_scheduler_owner_key(
            1u, peer_key, &peer_key_len)
        == NINLIL_OK);
    (void)memcpy(
        peer_src, DSB3_SCHED_DLV_TYPED_VALUE, DSB3_SCHED_DLV_TYPED_VALUE_LEN);
    REQUIRE(patch_body_u64_be(
        peer_src, (uint32_t)DSB3_SCHED_DLV_TYPED_VALUE_LEN, 0u, 1u));
    REQUIRE(install_source_with_pvd_peer(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_src, DSB3_SCHED_DLV_TYPED_VALUE_LEN,
            peer)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 13u) == 0);

    /* ABSENT peer. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 13u, 17u) == 0);

    /* PVD mismatch (SCHED 0x26 before DELIVERY → ok=18 at note). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_scheduler_owner_key(
            1u, peer_key, &peer_key_len)
        == NINLIL_OK);
    (void)memcpy(
        peer_src, DSB3_SCHED_DLV_TYPED_VALUE, DSB3_SCHED_DLV_TYPED_VALUE_LEN);
    REQUIRE(patch_body_u64_be(
        peer_src, (uint32_t)DSB3_SCHED_DLV_TYPED_VALUE_LEN, 0u, 1u));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_src, DSB3_SCHED_DLV_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 13u, 18u) == 0);
    return 0;
}

/* Mode 14: DS PRESENT / EF ABSENT polarity. */
static int test_d3s1_mode14_delivery_cancel_family(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t peer[DSB3_CS_DLV_NONE_TYPED_VALUE_LEN];

    /* DesiredState DELIVERY + CANCEL PRESENT. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_source_with_pvd_peer(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            DSB3_CS_DLV_NONE_TYPED_KEY, DSB3_CS_DLV_NONE_TYPED_KEY_LEN,
            DSB3_CS_DLV_NONE_TYPED_VALUE, DSB3_CS_DLV_NONE_TYPED_VALUE_LEN,
            peer)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 14u) == 0);

    /* EventFact DELIVERY expects ABSENT cancel. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_EF_TYPED_KEY, DSB3_DLV_APP_EF_TYPED_KEY_LEN,
        DSB3_DLV_APP_EF_TYPED_VALUE, DSB3_DLV_APP_EF_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 14u) == 0);

    /* EventFact with present cancel → polarity corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_source_with_pvd_peer(
            &spy, DSB3_DLV_APP_EF_TYPED_KEY, DSB3_DLV_APP_EF_TYPED_KEY_LEN,
            DSB3_DLV_APP_EF_TYPED_VALUE, DSB3_DLV_APP_EF_TYPED_VALUE_LEN,
            DSB3_CS_DLV_NONE_TYPED_KEY, DSB3_CS_DLV_NONE_TYPED_KEY_LEN,
            DSB3_CS_DLV_NONE_TYPED_VALUE, DSB3_CS_DLV_NONE_TYPED_VALUE_LEN,
            peer)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 14u, 18u) == 0);

    /* DesiredState cancel ABSENT → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 14u, 17u) == 0);
    return 0;
}

/*
 * Rebuild ingress RESERVATION peer for ordered_sequence of source.
 * Fixture RES_ING uses sequence 7; source APP_DS uses sequence 1.
 * Only owner_key RAW16 contents + length stay shape-compatible (8 bytes);
 * patch raw contents to BE8(seq) and recompute CRC. primary_key_digest is
 * still keyed off sequence 7 in fixture — S3 would fail if visited as CURRENT
 * with mismatched digest. Sort order: RESERVATION 0x23 before INGRESS 0x27,
 * so S3 validates RES first. Fix pkd via recompute.
 */
static int recompute_reservation_ingress_pkd(
    uint8_t *value,
    uint32_t value_len,
    uint64_t ordered_sequence)
{
    uint8_t seq_be[8];
    ninlil_model_domain_key_t key;
    ninlil_model_domain_digest_t dig;
    ninlil_bytes_view_t identity;
    uint32_t payload_len;
    uint8_t *body;
    uint8_t *pkd;

    if (value == NULL || value_len < 16u + 96u + 4u + 8u + 32u) {
        return 0;
    }
    payload_len = ((uint32_t)value[8] << 24) | ((uint32_t)value[9] << 16)
        | ((uint32_t)value[10] << 8) | (uint32_t)value[11];
    if (12u + payload_len + 4u != value_len) {
        return 0;
    }
    body = &value[12u + 96u];
    /* owner_kind u16, reserved u16, raw_len u16, raw 8. */
    if (body[0] != 0u || body[1] != 3u || body[4] != 0u || body[5] != 8u) {
        return 0;
    }
    ninlil_model_domain_encode_u64_be(seq_be, ordered_sequence);
    (void)memcpy(&body[6], seq_be, 8u);
    /* common primary_id: INGRESS = zero-pad16 + BE8(seq) at value[24..40]. */
    (void)memset(&value[24], 0, 16u);
    (void)memcpy(&value[24 + 8], seq_be, 8u);
    identity.data = seq_be;
    identity.length = 8u;
    if (ninlil_model_domain_build_key(
            NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
            NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
            NINLIL_MODEL_DOMAIN_ID_KIND_U64, identity, &key)
        != NINLIL_OK) {
        return 0;
    }
    {
        ninlil_bytes_view_t kv;
        kv.data = key.bytes;
        kv.length = key.length;
        if (ninlil_model_domain_key_digest(kv, &dig) != NINLIL_OK) {
            return 0;
        }
    }
    pkd = &body[6u + 8u];
    (void)memcpy(pkd, dig.bytes, 32u);
    write_u32_be(
        &value[12u + payload_len], crc32c_bytes(value, 12u + payload_len));
    return 1;
}

static int test_d3s1_mode15_ingress_reservation(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t peer_key[45];
    uint8_t peer_key_len = 0u;
    uint8_t peer_src[DSB2_RES_ING_TYPED_VALUE_LEN];
    uint8_t peer[DSB2_RES_ING_TYPED_VALUE_LEN];

    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    /* ING_APP_DS ordered_sequence = 1. */
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_ingress_reservation_key(
            1u, peer_key, &peer_key_len)
        == NINLIL_OK);
    (void)memcpy(
        peer_src, DSB2_RES_ING_TYPED_VALUE, DSB2_RES_ING_TYPED_VALUE_LEN);
    REQUIRE(recompute_reservation_ingress_pkd(
        peer_src, (uint32_t)DSB2_RES_ING_TYPED_VALUE_LEN, 1u));
    REQUIRE(install_source_with_pvd_peer(
            &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
            DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_src, DSB2_RES_ING_TYPED_VALUE_LEN,
            peer)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 15u) == 0);

    /* ABSENT. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
        DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 15u, 17u) == 0);

    /* PVD mismatch (RES 0x23 before INGRESS 0x27 → ok=18 at note). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_ingress_reservation_key(
            1u, peer_key, &peer_key_len)
        == NINLIL_OK);
    (void)memcpy(
        peer_src, DSB2_RES_ING_TYPED_VALUE, DSB2_RES_ING_TYPED_VALUE_LEN);
    REQUIRE(recompute_reservation_ingress_pkd(
        peer_src, (uint32_t)DSB2_RES_ING_TYPED_VALUE_LEN, 1u));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
            DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_src, DSB2_RES_ING_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 15u, 18u) == 0);

    /* Non-applicable: Mode 15 with only DELIVERY row → skip get, adopt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
        DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 15u) == 0);
    return 0;
}

/*
 * Re-encode SCHEDULER_OWNER peer for Mode 16: set sequence/kind/subject and
 * recompute primary_key_digest; preserve other template fields.
 */
static int build_sched_peer_for_mode16(
    const uint8_t *template_value,
    uint32_t template_len,
    uint64_t owner_sequence,
    uint16_t owner_kind,
    const uint8_t *subject_raw,
    uint16_t subject_raw_len,
    const uint8_t source_pvd[32],
    uint8_t *out_key,
    uint8_t *out_key_len,
    uint8_t *out_value,
    uint32_t out_value_cap,
    uint32_t *out_value_len)
{
    ninlil_bytes_view_t tv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_scheduler_owner_t body;
    ninlil_model_domain_common_header_t header;
    uint8_t body_buf[512];
    uint32_t body_len = 0u;
    ninlil_bytes_view_t body_view;
    ninlil_bytes_view_t identity;
    ninlil_model_domain_key_t key;
    ninlil_model_domain_digest_t dig;
    uint8_t raw16[2u + 80u];
    uint32_t raw16_len = 0u;
    ninlil_bytes_view_t components;
    ninlil_status_t st;

    if (template_value == NULL || subject_raw == NULL || source_pvd == NULL
        || out_key == NULL || out_key_len == NULL || out_value == NULL
        || out_value_len == NULL || owner_sequence == 0u) {
        return 0;
    }
    tv.data = template_value;
    tv.length = template_len;
    if (ninlil_model_domain_decode_envelope(tv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_scheduler_owner(env.body, &body)
        != NINLIL_OK) {
        return 0;
    }
    body.owner_sequence = owner_sequence;
    body.owner_kind = owner_kind;
    body.subject_key_raw = subject_raw;
    body.subject_key_raw_length = subject_raw_len;

    /* primary_key_digest of referenced primary complete key. */
    if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION) {
        if (subject_raw_len != 16u) {
            return 0;
        }
        identity.data = subject_raw;
        identity.length = 16u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_ANCHOR,
                NINLIL_MODEL_DOMAIN_ID_KIND_ID128, identity, &key)
            != NINLIL_OK) {
            return 0;
        }
        {
            ninlil_bytes_view_t kv;
            kv.data = key.bytes;
            kv.length = key.length;
            if (ninlil_model_domain_key_digest(kv, &dig) != NINLIL_OK) {
                return 0;
            }
        }
        (void)memcpy(body.primary_key_digest, dig.bytes, 32u);
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS) {
        if (subject_raw_len != 8u) {
            return 0;
        }
        identity.data = subject_raw;
        identity.length = 8u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_ORDERED_INGRESS,
                NINLIL_MODEL_DOMAIN_ID_KIND_U64, identity, &key)
            != NINLIL_OK) {
            return 0;
        }
        {
            ninlil_bytes_view_t kv;
            kv.data = key.bytes;
            kv.length = key.length;
            if (ninlil_model_domain_key_digest(kv, &dig) != NINLIL_OK) {
                return 0;
            }
        }
        (void)memcpy(body.primary_key_digest, dig.bytes, 32u);
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY) {
        if (subject_raw_len != 80u) {
            return 0;
        }
        ninlil_model_domain_encode_u16_be(raw16, subject_raw_len);
        (void)memcpy(&raw16[2], subject_raw, subject_raw_len);
        raw16_len = 2u + (uint32_t)subject_raw_len;
        components.data = raw16;
        components.length = raw16_len;
        if (ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components, &dig)
            != NINLIL_OK) {
            return 0;
        }
        identity.data = dig.bytes;
        identity.length = 32u;
        if (ninlil_model_domain_build_key(
                NINLIL_MODEL_DOMAIN_FAMILY_DOMAIN,
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY,
                NINLIL_MODEL_DOMAIN_ID_KIND_SHA256_COMPOSITE, identity, &key)
            != NINLIL_OK) {
            return 0;
        }
        {
            ninlil_bytes_view_t kv;
            kv.data = key.bytes;
            kv.length = key.length;
            if (ninlil_model_domain_key_digest(kv, &dig) != NINLIL_OK) {
                return 0;
            }
        }
        (void)memcpy(body.primary_key_digest, dig.bytes, 32u);
    } else {
        return 0;
    }

    st = ninlil_model_domain_encode_body_scheduler_owner(
        &body, body_buf, (uint32_t)sizeof(body_buf), &body_len);
    if (st != NINLIL_OK) {
        return 0;
    }
    header = env.header;
    header.subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_SCHEDULER_OWNER;
    header.body_length = body_len;
    (void)memcpy(header.primary_value_digest, source_pvd, 32u);
    /* primary_id = referenced primary identity (docs17 §4/§9). */
    if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION) {
        (void)memcpy(header.primary_id, subject_raw, 16u);
    } else if (owner_kind == NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS) {
        (void)memset(header.primary_id, 0, 16u);
        (void)memcpy(&header.primary_id[8], subject_raw, 8u);
    } else {
        /* DELIVERY: first 16 of KEY_DIGEST identity = composite dig first 16. */
        ninlil_model_domain_encode_u16_be(raw16, subject_raw_len);
        (void)memcpy(&raw16[2], subject_raw, subject_raw_len);
        raw16_len = 2u + (uint32_t)subject_raw_len;
        components.data = raw16;
        components.length = raw16_len;
        if (ninlil_model_domain_composite_digest(
                NINLIL_MODEL_DOMAIN_SUBTYPE_DELIVERY, components, &dig)
            != NINLIL_OK) {
            return 0;
        }
        (void)memcpy(header.primary_id, dig.bytes, 16u);
    }
    body_view.data = body_buf;
    body_view.length = body_len;
    st = ninlil_model_domain_encode_envelope(
        NINLIL_MODEL_DOMAIN_RECORD_TYPE_DOMAIN, &header, body_view, out_value,
        out_value_cap, out_value_len);
    if (st != NINLIL_OK) {
        return 0;
    }
    if (ninlil_domain_scan_d3s1_rebuild_ingress_scheduler_owner_key(
            owner_sequence, out_key, out_key_len)
        != NINLIL_OK) {
        return 0;
    }
    return 1;
}

static int test_d3s1_mode16_scheduler_variants(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t peer_key[45];
    uint8_t peer_key_len = 0u;
    uint8_t peer_value[512];
    uint32_t peer_value_len = 0u;
    uint8_t pvd[32];
    uint8_t seq_be[8];
    uint8_t subject[80];
    uint8_t wrong_pvd[32];

    /* --- NEW_DELIVERY (ING_APP_DS): oseq=1 owner_seq=9 bind=3 --- */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB3_ING_APP_DS_TYPED_VALUE, (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN,
        pvd));
    ninlil_model_domain_encode_u64_be(seq_be, 1u);
    REQUIRE(build_sched_peer_for_mode16(
            DSB3_SCHED_ING_TYPED_VALUE,
            (uint32_t)DSB3_SCHED_ING_TYPED_VALUE_LEN, 9u,
            NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS, seq_be, 8u, pvd,
            peer_key, &peer_key_len, peer_value, (uint32_t)sizeof(peer_value),
            &peer_value_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
            DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 16u) == 0);

    /* NEW_DELIVERY PVD mismatch → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    (void)memset(wrong_pvd, 0x5Cu, sizeof(wrong_pvd));
    REQUIRE(build_sched_peer_for_mode16(
            DSB3_SCHED_ING_TYPED_VALUE,
            (uint32_t)DSB3_SCHED_ING_TYPED_VALUE_LEN, 9u,
            NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS, seq_be, 8u, wrong_pvd,
            peer_key, &peer_key_len, peer_value, (uint32_t)sizeof(peer_value),
            &peer_value_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
            DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 16u, 18u) == 0);

    /*
     * EXISTING_TRANSACTION (ING_RECEIPT): oseq=4 owner_seq=5 bind=1.
     * Peer PVD intentionally wrong — must NOT compare to ingress (Mode17).
     * Wrong ABSENT regression: peer PRESENT must succeed (never expect ABSENT).
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        ninlil_bytes_view_t vv;
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_ordered_ingress_t ing;
        vv.data = DSB3_ING_RECEIPT_TYPED_VALUE;
        vv.length = DSB3_ING_RECEIPT_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(
            ninlil_model_domain_decode_body_ordered_ingress(env.body, &ing)
            == NINLIL_OK);
        REQUIRE(ing.owner_binding_kind
            == NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_TRANSACTION);
        REQUIRE(ing.owner_sequence == 5u);
        (void)memcpy(subject, ing.transaction_id, 16u);
        (void)memset(wrong_pvd, 0x11u, sizeof(wrong_pvd));
        REQUIRE(build_sched_peer_for_mode16(
                DSB3_SCHED_TX_TYPED_VALUE,
                (uint32_t)DSB3_SCHED_TX_TYPED_VALUE_LEN, 5u,
                NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION, subject, 16u,
                wrong_pvd, peer_key, &peer_key_len, peer_value,
                (uint32_t)sizeof(peer_value), &peer_value_len));
    }
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_RECEIPT_TYPED_KEY, DSB3_ING_RECEIPT_TYPED_KEY_LEN,
            DSB3_ING_RECEIPT_TYPED_VALUE, DSB3_ING_RECEIPT_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 16u) == 0);

    /* EXISTING_TX raw mismatch → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    subject[0] ^= 0x01u;
    (void)memset(wrong_pvd, 0x22u, sizeof(wrong_pvd));
    REQUIRE(build_sched_peer_for_mode16(
            DSB3_SCHED_TX_TYPED_VALUE, (uint32_t)DSB3_SCHED_TX_TYPED_VALUE_LEN,
            5u, NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION, subject, 16u,
            wrong_pvd, peer_key, &peer_key_len, peer_value,
            (uint32_t)sizeof(peer_value), &peer_value_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_RECEIPT_TYPED_KEY, DSB3_ING_RECEIPT_TYPED_KEY_LEN,
            DSB3_ING_RECEIPT_TYPED_VALUE, DSB3_ING_RECEIPT_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 16u, 18u) == 0);

    /* EXISTING_TX ABSENT peer → corrupt (PRESENT required; wrong ABSENT reg). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_ING_RECEIPT_TYPED_KEY, DSB3_ING_RECEIPT_TYPED_KEY_LEN,
        DSB3_ING_RECEIPT_TYPED_VALUE, DSB3_ING_RECEIPT_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 16u, 17u) == 0);

    /* --- EXISTING_DELIVERY (ING_APP_EF): oseq=2 owner_seq=1 bind=2 --- */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        ninlil_bytes_view_t vv;
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_ordered_ingress_t ing;
        vv.data = DSB3_ING_APP_EF_TYPED_VALUE;
        vv.length = DSB3_ING_APP_EF_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(
            ninlil_model_domain_decode_body_ordered_ingress(env.body, &ing)
            == NINLIL_OK);
        REQUIRE(ing.owner_binding_kind
            == NINLIL_MODEL_DOMAIN_INGRESS_BINDING_EXISTING_DELIVERY);
        (void)memcpy(subject, ing.source.runtime_id, 16u);
        (void)memcpy(subject + 16, ing.source.application_instance_id, 16u);
        (void)memcpy(subject + 32, ing.transaction_id, 16u);
        (void)memcpy(subject + 48, ing.target.target_runtime, 16u);
        (void)memcpy(subject + 64, ing.target.target_application, 16u);
        (void)memset(wrong_pvd, 0x33u, sizeof(wrong_pvd));
        REQUIRE(build_sched_peer_for_mode16(
                DSB3_SCHED_DLV_TYPED_VALUE,
                (uint32_t)DSB3_SCHED_DLV_TYPED_VALUE_LEN, 1u,
                NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_DELIVERY, subject, 80u,
                wrong_pvd, peer_key, &peer_key_len, peer_value,
                (uint32_t)sizeof(peer_value), &peer_value_len));
    }
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_EF_TYPED_KEY, DSB3_ING_APP_EF_TYPED_KEY_LEN,
            DSB3_ING_APP_EF_TYPED_VALUE, DSB3_ING_APP_EF_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 16u) == 0);

    /* EXISTING_DELIVERY kind mismatch (TX kind on delivery subject) corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    (void)memset(wrong_pvd, 0x44u, sizeof(wrong_pvd));
    REQUIRE(build_sched_peer_for_mode16(
            DSB3_SCHED_TX_TYPED_VALUE, (uint32_t)DSB3_SCHED_TX_TYPED_VALUE_LEN,
            1u, NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION, subject, 16u,
            wrong_pvd, peer_key, &peer_key_len, peer_value,
            (uint32_t)sizeof(peer_value), &peer_value_len));
    /* subject[0..15] still holds first 16 of composed delivery raw — wrong kind. */
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_EF_TYPED_KEY, DSB3_ING_APP_EF_TYPED_KEY_LEN,
            DSB3_ING_APP_EF_TYPED_VALUE, DSB3_ING_APP_EF_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 16u, 18u) == 0);

    /* NEW_DELIVERY kind mismatch: TX owner_kind on ingress subject → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_model_domain_encode_u64_be(seq_be, 1u);
    (void)memset(wrong_pvd, 0x55u, sizeof(wrong_pvd));
    {
        uint8_t tx_id[16];
        (void)memcpy(tx_id, &DSB3_ING_APP_DS_TYPED_VALUE[12u + 96u + 8u], 16u);
        /* Use TX kind + tx id raw while ingress expects INGRESS kind/seq. */
        REQUIRE(build_sched_peer_for_mode16(
                DSB3_SCHED_TX_TYPED_VALUE,
                (uint32_t)DSB3_SCHED_TX_TYPED_VALUE_LEN, 9u,
                NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_TRANSACTION, tx_id, 16u,
                wrong_pvd, peer_key, &peer_key_len, peer_value,
                (uint32_t)sizeof(peer_value), &peer_value_len));
    }
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
            DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 16u, 18u) == 0);

    /* NEW_DELIVERY raw mismatch: wrong subject sequence contents → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    ninlil_model_domain_encode_u64_be(seq_be, 99u); /* not ingress oseq=1 */
    REQUIRE(compute_value_digest(
        DSB3_ING_APP_DS_TYPED_VALUE, (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN,
        pvd));
    REQUIRE(build_sched_peer_for_mode16(
            DSB3_SCHED_ING_TYPED_VALUE,
            (uint32_t)DSB3_SCHED_ING_TYPED_VALUE_LEN, 9u,
            NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS, seq_be, 8u, pvd,
            peer_key, &peer_key_len, peer_value, (uint32_t)sizeof(peer_value),
            &peer_value_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
            DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 16u, 18u) == 0);
    return 0;
}

/* Modes 11–16 Port failure path: sticky only, no note (reuse mode 1 port test). */
static int test_d3s1_mode16_previous_key_and_ok_count(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_domain_scan_session_t session;
    ninlil_domain_scan_workspace_t workspace;
    ninlil_domain_scan_d3s1_context_t context;
    ninlil_domain_scan_result_t result;
    ninlil_model_runtime_store_binding_t candidate;
    ninlil_storage_handle_t handle;
    const ninlil_storage_ops_t *ops;
    uint8_t peer_key[45];
    uint8_t peer_key_len = 0u;
    uint8_t peer_value[512];
    uint32_t peer_value_len = 0u;
    uint8_t pvd[32];
    uint8_t seq_be[8];
    uint8_t source_key_snapshot[45];
    uint32_t source_key_len = 0u;

    ninlil_spy_init(&spy);
    ops = ninlil_spy_ops(&spy);
    handle = ninlil_spy_open_handle(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(compute_value_digest(
        DSB3_ING_APP_DS_TYPED_VALUE, (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN,
        pvd));
    ninlil_model_domain_encode_u64_be(seq_be, 1u);
    REQUIRE(build_sched_peer_for_mode16(
            DSB3_SCHED_ING_TYPED_VALUE,
            (uint32_t)DSB3_SCHED_ING_TYPED_VALUE_LEN, 9u,
            NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS, seq_be, 8u, pvd,
            peer_key, &peer_key_len, peer_value, (uint32_t)sizeof(peer_value),
            &peer_value_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
            DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_value, peer_value_len)
        == 0);

    ninlil_domain_scan_session_init(&session);
    (void)memset(&workspace, 0, sizeof(workspace));
    (void)memset(&context, 0, sizeof(context));
    REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
            &session, ops, &handle, &workspace, &candidate, 16u, &context)
        == NINLIL_OK);
    while (session.state == NINLIL_DOMAIN_SCAN_STATE_OPEN) {
        REQUIRE(ninlil_domain_scan_advance(&session, 1u) == NINLIL_OK
            || session.state != NINLIL_DOMAIN_SCAN_STATE_OPEN);
        if (session.previous_key_length == DSB3_ING_APP_DS_TYPED_KEY_LEN
            && memcmp(
                   workspace.previous_key, DSB3_ING_APP_DS_TYPED_KEY,
                   DSB3_ING_APP_DS_TYPED_KEY_LEN)
                == 0) {
            source_key_len = session.previous_key_length;
            (void)memcpy(
                source_key_snapshot, workspace.previous_key, source_key_len);
            /* workspace.key remains source INGRESS after peer exact_get. */
            REQUIRE(memcmp(
                        workspace.key, DSB3_ING_APP_DS_TYPED_KEY,
                        DSB3_ING_APP_DS_TYPED_KEY_LEN)
                == 0);
            REQUIRE(context.peer_key_len >= 13u);
            break;
        }
        if (session.state != NINLIL_DOMAIN_SCAN_STATE_OPEN) {
            break;
        }
    }
    REQUIRE(source_key_len == DSB3_ING_APP_DS_TYPED_KEY_LEN);
    REQUIRE(scan_until_terminal(&session) == 0);
    REQUIRE(ninlil_domain_scan_finalize(&session, &result) == NINLIL_OK);
    REQUIRE(result.adopted == 1u);
    REQUIRE(ninlil_spy_assert_no_mutations(&spy));
    return 0;
}

static int test_d3s1_mode12_13_15_layering_and_mode13_raw(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t peer_key[45];
    uint8_t peer_key_len = 0u;
    uint8_t peer_src[DSB3_SCHED_DLV_TYPED_VALUE_LEN];
    uint8_t peer[DSB3_SCHED_DLV_TYPED_VALUE_LEN];
    uint8_t rebuilt[45];
    uint8_t rebuilt_len = 0u;

    /*
     * Mode12/15 peer-before layering (honest, not fake D3 coverage):
     * RES(0x23) sorts before DELIVERY(0x40)/INGRESS(0x27). RES composite key
     * embeds owner raw, so body raw flip fails S3 same-record at CURRENT
     * visit of RES. Mode12/15 D3 tests therefore cover ABSENT + PVD via
     * exact_get; raw/kind owner mismatch for peer-before is S3-owned.
     * Mode16 covers owner kind/raw mismatch for INGRESS scheduler variants
     * (peer may sort before; D3 still evaluates on INGRESS CURRENT).
     *
     * Mode13: pure rebuild golden + present path (kind/raw matrix exercised
     * by Mode13 present and Mode16 EXISTING_* kind/raw tests).
     */
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_reservation_key(
            &DSB3_DLV_APP_DS_TYPED_VALUE[12u + 96u + 2u], 80u, rebuilt,
            &rebuilt_len)
        == NINLIL_OK);
    REQUIRE(rebuilt_len == DSB2_RES_DLV_TYPED_KEY_LEN);
    REQUIRE(memcmp(rebuilt, DSB2_RES_DLV_TYPED_KEY, rebuilt_len) == 0);

    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_delivery_scheduler_owner_key(
            1u, peer_key, &peer_key_len)
        == NINLIL_OK);
    (void)memcpy(
        peer_src, DSB3_SCHED_DLV_TYPED_VALUE, DSB3_SCHED_DLV_TYPED_VALUE_LEN);
    REQUIRE(patch_body_u64_be(
        peer_src, (uint32_t)DSB3_SCHED_DLV_TYPED_VALUE_LEN, 0u, 1u));
    REQUIRE(install_source_with_pvd_peer(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            peer_key, peer_key_len, peer_src, DSB3_SCHED_DLV_TYPED_VALUE_LEN,
            peer)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 13u) == 0);
    return 0;
}

/*
 * Mode17 reverse helper: secondary header PVD must equal primary value digest.
 * Rows installed in increasing key order.
 */
static int install_rev_pair(
    ninlil_scripted_storage_spy_t *spy,
    const uint8_t *primary_key,
    size_t primary_key_len,
    const uint8_t *primary_value,
    size_t primary_value_len,
    const uint8_t *secondary_key,
    size_t secondary_key_len,
    const uint8_t *secondary_value_src,
    size_t secondary_value_len,
    uint8_t *secondary_value_buf)
{
    uint8_t pvd[32];

    REQUIRE(compute_value_digest(
        primary_value, (uint32_t)primary_value_len, pvd));
    (void)memcpy(secondary_value_buf, secondary_value_src, secondary_value_len);
    REQUIRE(patch_pvd(
        secondary_value_buf, (uint32_t)secondary_value_len, pvd));
    REQUIRE(add_two_domain_rows_sorted(
            spy, primary_key, primary_key_len, primary_value, primary_value_len,
            secondary_key, secondary_key_len, secondary_value_buf,
            secondary_value_len)
        == 0);
    return 0;
}

/* Mode 17 reverse integration: closed rebuild classes + findings. */
static int test_d3s1_mode17_rev_primary_core(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t sec[1024];

    /* SERVICE_QUOTA → SERVICE. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
            DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN,
            DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, DSB2_QUOTA_TYPED_VALUE,
            DSB2_QUOTA_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* RES SERVICE → SERVICE. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
            DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN,
            DSB2_RES_SVC_TYPED_KEY, DSB2_RES_SVC_TYPED_KEY_LEN,
            DSB2_RES_SVC_TYPED_VALUE, DSB2_RES_SVC_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* RES TX → ANCHOR. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
            DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
            DSB2_RES_TX_TYPED_KEY, DSB2_RES_TX_TYPED_KEY_LEN,
            DSB2_RES_TX_TYPED_VALUE, DSB2_RES_TX_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* SEQ / STATE / IDEM dual-raw / EVENT_MAP / EVENT_SPOOL / RETRY /
     * MANAGEMENT / ATTEMPT_ID_INDEX → ANCHOR. */
    {
        const struct {
            const uint8_t *key;
            size_t key_len;
            const uint8_t *value;
            size_t value_len;
        } rows[] = {
            { DSB2_SEQ_TYPED_KEY, DSB2_SEQ_TYPED_KEY_LEN, DSB2_SEQ_TYPED_VALUE,
                DSB2_SEQ_TYPED_VALUE_LEN },
            { DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN,
                DSB2_STATE_TYPED_VALUE, DSB2_STATE_TYPED_VALUE_LEN },
            { DSB2_IDEM_TYPED_KEY, DSB2_IDEM_TYPED_KEY_LEN, DSB2_IDEM_TYPED_VALUE,
                DSB2_IDEM_TYPED_VALUE_LEN },
            { DSB2_EVMAP_TYPED_KEY, DSB2_EVMAP_TYPED_KEY_LEN,
                DSB2_EVMAP_TYPED_VALUE, DSB2_EVMAP_TYPED_VALUE_LEN },
            { DSB3_ES_ACTIVE_TYPED_KEY, DSB3_ES_ACTIVE_TYPED_KEY_LEN,
                DSB3_ES_ACTIVE_TYPED_VALUE, DSB3_ES_ACTIVE_TYPED_VALUE_LEN },
            { DSB3_RS_CUM_T0_TYPED_KEY, DSB3_RS_CUM_T0_TYPED_KEY_LEN,
                DSB3_RS_CUM_T0_TYPED_VALUE, DSB3_RS_CUM_T0_TYPED_VALUE_LEN },
            { DSB3_ML_R_RSN1_TYPED_KEY, DSB3_ML_R_RSN1_TYPED_KEY_LEN,
                DSB3_ML_R_RSN1_TYPED_VALUE, DSB3_ML_R_RSN1_TYPED_VALUE_LEN },
            { DSB3_AII_CMD_TYPED_KEY, DSB3_AII_CMD_TYPED_KEY_LEN,
                DSB3_AII_CMD_TYPED_VALUE, DSB3_AII_CMD_TYPED_VALUE_LEN },
        };
        size_t i;
        for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i += 1u) {
            ninlil_spy_init(&spy);
            REQUIRE(s2_install_full_profile(&spy, &candidate));
            REQUIRE(install_rev_pair(
                    &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
                    DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
                    rows[i].key, rows[i].key_len, rows[i].value,
                    rows[i].value_len, sec)
                == 0);
            REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);
        }
    }

    /* SCHED TX → ANCHOR (Mode16 EXISTING live PVD ownership). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
            DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
            DSB3_SCHED_TX_TYPED_KEY, DSB3_SCHED_TX_TYPED_KEY_LEN,
            DSB3_SCHED_TX_TYPED_VALUE, DSB3_SCHED_TX_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* CANCEL TX / EVIDENCE TX → ANCHOR. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
            DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
            DSB3_CS_TX_NONE_TYPED_KEY, DSB3_CS_TX_NONE_TYPED_KEY_LEN,
            DSB3_CS_TX_NONE_TYPED_VALUE, DSB3_CS_TX_NONE_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
            DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
            DSB3_EV_TX_SUM_EMPTY_TYPED_KEY, DSB3_EV_TX_SUM_EMPTY_TYPED_KEY_LEN,
            DSB3_EV_TX_SUM_EMPTY_TYPED_VALUE,
            DSB3_EV_TX_SUM_EMPTY_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* ATTEMPT TX → ANCHOR. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
            DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
            DSB3_ATT_TX_CMD_PREP_TYPED_KEY, DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* DELIVERY-owned: RES DLV / RESULT / REVERSE_REPLY / SCHED DLV / CANCEL DLV /
     * ATTEMPT DLV → DELIVERY. */
    {
        const struct {
            const uint8_t *key;
            size_t key_len;
            const uint8_t *value;
            size_t value_len;
        } rows[] = {
            { DSB2_RES_DLV_TYPED_KEY, DSB2_RES_DLV_TYPED_KEY_LEN,
                DSB2_RES_DLV_TYPED_VALUE, DSB2_RES_DLV_TYPED_VALUE_LEN },
            { DSB3_RC_INBOX_VIRGIN_TYPED_KEY, DSB3_RC_INBOX_VIRGIN_TYPED_KEY_LEN,
                DSB3_RC_INBOX_VIRGIN_TYPED_VALUE,
                DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN },
            { DSB3_RR_KIND_RECEIPT_TYPED_KEY, DSB3_RR_KIND_RECEIPT_TYPED_KEY_LEN,
                DSB3_RR_KIND_RECEIPT_TYPED_VALUE,
                DSB3_RR_KIND_RECEIPT_TYPED_VALUE_LEN },
            { DSB3_SCHED_DLV_TYPED_KEY, DSB3_SCHED_DLV_TYPED_KEY_LEN,
                DSB3_SCHED_DLV_TYPED_VALUE, DSB3_SCHED_DLV_TYPED_VALUE_LEN },
            { DSB3_CS_DLV_NONE_TYPED_KEY, DSB3_CS_DLV_NONE_TYPED_KEY_LEN,
                DSB3_CS_DLV_NONE_TYPED_VALUE, DSB3_CS_DLV_NONE_TYPED_VALUE_LEN },
            { DSB3_ATT_DLV_CMD_REMOTE_TYPED_KEY,
                DSB3_ATT_DLV_CMD_REMOTE_TYPED_KEY_LEN,
                DSB3_ATT_DLV_CMD_REMOTE_TYPED_VALUE,
                DSB3_ATT_DLV_CMD_REMOTE_TYPED_VALUE_LEN },
        };
        size_t i;
        for (i = 0u; i < sizeof(rows) / sizeof(rows[0]); i += 1u) {
            ninlil_spy_init(&spy);
            REQUIRE(s2_install_full_profile(&spy, &candidate));
            REQUIRE(install_rev_pair(
                    &spy, DSB3_DLV_APP_DS_TYPED_KEY,
                    DSB3_DLV_APP_DS_TYPED_KEY_LEN, DSB3_DLV_APP_DS_TYPED_VALUE,
                    DSB3_DLV_APP_DS_TYPED_VALUE_LEN, rows[i].key, rows[i].key_len,
                    rows[i].value, rows[i].value_len, sec)
                == 0);
            REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);
        }
    }

    /* CALLBACK RES → DELIVERY (not RESULT). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            DSB2_RES_CB_TYPED_KEY, DSB2_RES_CB_TYPED_KEY_LEN,
            DSB2_RES_CB_TYPED_VALUE, DSB2_RES_CB_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* RES INGRESS absent primary (seq 7 has no matching ingress fixture). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_RES_ING_TYPED_KEY, DSB2_RES_ING_TYPED_KEY_LEN,
        DSB2_RES_ING_TYPED_VALUE, DSB2_RES_ING_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 17u, 17u) == 0);

    /*
     * SCHED INGRESS present: rebuild peer for ING_APP_DS (oseq=1) using
     * Mode16 helper (legal SCHED body) then Mode17 reverse.
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        uint8_t peer_key[45];
        uint8_t peer_key_len = 0u;
        uint8_t peer_value[512];
        uint32_t peer_value_len = 0u;
        uint8_t pvd[32];
        uint8_t seq_be[8];
        REQUIRE(compute_value_digest(
            DSB3_ING_APP_DS_TYPED_VALUE,
            (uint32_t)DSB3_ING_APP_DS_TYPED_VALUE_LEN, pvd));
        ninlil_model_domain_encode_u64_be(seq_be, 1u);
        REQUIRE(build_sched_peer_for_mode16(
                DSB3_SCHED_ING_TYPED_VALUE,
                (uint32_t)DSB3_SCHED_ING_TYPED_VALUE_LEN, 9u,
                NINLIL_MODEL_DOMAIN_SCHEDULER_OWNER_INGRESS, seq_be, 8u, pvd,
                peer_key, &peer_key_len, peer_value,
                (uint32_t)sizeof(peer_value), &peer_value_len));
        REQUIRE(install_rev_pair(
                &spy, DSB3_ING_APP_DS_TYPED_KEY, DSB3_ING_APP_DS_TYPED_KEY_LEN,
                DSB3_ING_APP_DS_TYPED_VALUE, DSB3_ING_APP_DS_TYPED_VALUE_LEN,
                peer_key, peer_key_len, peer_value, peer_value_len, sec)
            == 0);
    }
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* EVIDENCE DELIVERY → DELIVERY. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            DSB3_EV_DLV_SUM_EMPTY_TYPED_KEY, DSB3_EV_DLV_SUM_EMPTY_TYPED_KEY_LEN,
            DSB3_EV_DLV_SUM_EMPTY_TYPED_VALUE,
            DSB3_EV_DLV_SUM_EMPTY_TYPED_VALUE_LEN, sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* RETENTION DELIVERY reverse present. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
            DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
            DSB3_RB_DLV_CLEANUP_TYPED_KEY, DSB3_RB_DLV_CLEANUP_TYPED_KEY_LEN,
            DSB3_RB_DLV_CLEANUP_TYPED_VALUE, DSB3_RB_DLV_CLEANUP_TYPED_VALUE_LEN,
            sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* CLEANUP DELIVERY reverse: patch header+body subject PVD to live DLV. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        uint8_t pvd[32];
        uint32_t payload_len;
        REQUIRE(compute_value_digest(
            DSB3_DLV_APP_DS_TYPED_VALUE,
            (uint32_t)DSB3_DLV_APP_DS_TYPED_VALUE_LEN, pvd));
        (void)memcpy(
            sec, DSB3_CP_DLV_P1_TYPED_VALUE, DSB3_CP_DLV_P1_TYPED_VALUE_LEN);
        REQUIRE(patch_pvd(
            sec, (uint32_t)DSB3_CP_DLV_P1_TYPED_VALUE_LEN, pvd));
        /* body: kind:u16 + phase:u16 + RAW16(80) + pkd[32] → value_dig @ 118 */
        (void)memcpy(&sec[12u + 96u + 118u], pvd, 32u);
        payload_len = ((uint32_t)sec[8] << 24) | ((uint32_t)sec[9] << 16)
            | ((uint32_t)sec[10] << 8) | (uint32_t)sec[11];
        write_u32_be(
            &sec[12u + payload_len], crc32c_bytes(sec, 12u + payload_len));
        REQUIRE(add_two_domain_rows_sorted(
                &spy, DSB3_DLV_APP_DS_TYPED_KEY, DSB3_DLV_APP_DS_TYPED_KEY_LEN,
                DSB3_DLV_APP_DS_TYPED_VALUE, DSB3_DLV_APP_DS_TYPED_VALUE_LEN,
                DSB3_CP_DLV_P1_TYPED_KEY, DSB3_CP_DLV_P1_TYPED_KEY_LEN, sec,
                DSB3_CP_DLV_P1_TYPED_VALUE_LEN)
            == 0);
    }
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /* Absent primary → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN,
        DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 17u, 17u) == 0);

    /* PVD mismatch → corrupt (fixture secondary PVD ≠ live primary digest). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
            DSB2_SERVICE_TYPED_VALUE, DSB2_SERVICE_TYPED_VALUE_LEN,
            DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN,
            DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 17u, 18u) == 0);

    /*
     * SERVICE raw bijection is co-located with same-record key identity (S3):
     * SERVICE key = f(service_key_raw), so a PRESENT primary at the rebuilt
     * key always carries matching raw if S3 accepted the row. Pure Mode17
     * dual-raw path is IDEM→ANCHOR below (not dead SERVICE patch block).
     */

    /*
     * IDEM dual-raw mismatch: secondary IDEM remains same-record valid
     * (key/body composite bijection) while ANCHOR dual fields differ.
     * Failure is Mode17 reverse dual-raw (D3), not S3 on IDEM CURRENT.
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        ninlil_bytes_view_t vv;
        ninlil_model_domain_envelope_t env;
        ninlil_model_domain_body_idempotency_map_t idem;
        ninlil_model_domain_common_header_t hdr;
        uint8_t body_buf[512];
        uint32_t body_len = 0u;
        uint8_t val_buf[512];
        uint32_t val_len = 0u;
        uint8_t key_buf[45];
        uint8_t key_len = 0u;
        uint8_t new_ik[64];
        uint8_t pvd[32];
        ninlil_bytes_view_t bodyv;

        vv.data = DSB2_IDEM_TYPED_VALUE;
        vv.length = DSB2_IDEM_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(ninlil_model_domain_decode_body_idempotency_map(env.body, &idem)
            == NINLIL_OK);
        REQUIRE(idem.idempotency_key_length > 0u
            && idem.idempotency_key_length <= 64u);
        (void)memcpy(new_ik, idem.idempotency_key, idem.idempotency_key_length);
        new_ik[0] ^= 0x5Au; /* dual field differs from ANCHOR */
        idem.idempotency_key = new_ik;
        REQUIRE(ninlil_model_domain_encode_body_idempotency_map(
                &idem, body_buf, (uint32_t)sizeof(body_buf), &body_len)
            == NINLIL_OK);
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_tx_idempotency_map_key(
                idem.scope_raw, idem.scope_raw_length, new_ik,
                idem.idempotency_key_length, key_buf, &key_len)
            == NINLIL_OK);
        REQUIRE(compute_value_digest(
            DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
            pvd));
        hdr = env.header;
        hdr.body_length = body_len;
        (void)memcpy(hdr.primary_value_digest, pvd, 32u);
        bodyv.data = body_buf;
        bodyv.length = body_len;
        REQUIRE(ninlil_model_domain_encode_envelope(
                env.record_type, &hdr, bodyv, val_buf, (uint32_t)sizeof(val_buf),
                &val_len)
            == NINLIL_OK);
        REQUIRE(add_two_domain_rows_sorted(
                &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
                DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN, key_buf,
                key_len, val_buf, val_len)
            == 0);
    }
    /* Profile 17 + ANCHOR non-applicable → 18 before IDEM Mode17 note. */
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 17u, 18u) == 0);

    /* RETENTION_BASIS / CLEANUP_PLAN reverse PVD only (cleanup phase S11). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(install_rev_pair(
            &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
            DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
            DSB3_RB_TX_ELIGIBLE_TYPED_KEY, DSB3_RB_TX_ELIGIBLE_TYPED_KEY_LEN,
            DSB3_RB_TX_ELIGIBLE_TYPED_VALUE, DSB3_RB_TX_ELIGIBLE_TYPED_VALUE_LEN,
            sec)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /*
     * CLEANUP_PLAN reverse PVD/raw: same-record requires body
     * subject_primary_value_digest == header PVD (docs §8.6). Patch both.
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        uint8_t pvd[32];
        uint32_t payload_len;
        REQUIRE(compute_value_digest(
            DSB2_ANCHOR_TYPED_VALUE, (uint32_t)DSB2_ANCHOR_TYPED_VALUE_LEN,
            pvd));
        (void)memcpy(
            sec, DSB3_CP_TX_P1_FULL_TYPED_VALUE,
            DSB3_CP_TX_P1_FULL_TYPED_VALUE_LEN);
        REQUIRE(patch_pvd(
            sec, (uint32_t)DSB3_CP_TX_P1_FULL_TYPED_VALUE_LEN, pvd));
        /* body subject_primary_value_digest at body offset 54. */
        (void)memcpy(&sec[12u + 96u + 54u], pvd, 32u);
        payload_len = ((uint32_t)sec[8] << 24) | ((uint32_t)sec[9] << 16)
            | ((uint32_t)sec[10] << 8) | (uint32_t)sec[11];
        write_u32_be(
            &sec[12u + payload_len], crc32c_bytes(sec, 12u + payload_len));
        REQUIRE(add_two_domain_rows_sorted(
                &spy, DSB2_ANCHOR_TYPED_KEY, DSB2_ANCHOR_TYPED_KEY_LEN,
                DSB2_ANCHOR_TYPED_VALUE, DSB2_ANCHOR_TYPED_VALUE_LEN,
                DSB3_CP_TX_P1_FULL_TYPED_KEY, DSB3_CP_TX_P1_FULL_TYPED_KEY_LEN,
                sec, DSB3_CP_TX_P1_FULL_TYPED_VALUE_LEN)
            == 0);
    }
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 17u) == 0);

    /*
     * Future primary matching source header PVD: after peer-key check, live
     * VALUE_DIGEST matches → OK; envelope UNSUPPORTED skips body/raw only
     * (S3 owns future non-terminal when primary is visited as CURRENT).
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        uint8_t future_primary[DSB2_SERVICE_TYPED_VALUE_LEN];
        uint8_t quota_val[DSB2_QUOTA_TYPED_VALUE_LEN];
        uint8_t pvd[32];
        uint32_t o;
        (void)memcpy(
            future_primary, DSB2_SERVICE_TYPED_VALUE,
            DSB2_SERVICE_TYPED_VALUE_LEN);
        future_primary[12] = 0x00u;
        future_primary[13] = 0x02u;
        o = ((uint32_t)future_primary[8] << 24)
            | ((uint32_t)future_primary[9] << 16)
            | ((uint32_t)future_primary[10] << 8)
            | (uint32_t)future_primary[11];
        write_u32_be(
            &future_primary[12u + o],
            crc32c_bytes(future_primary, 12u + o));
        REQUIRE(compute_value_digest(
            future_primary, (uint32_t)DSB2_SERVICE_TYPED_VALUE_LEN, pvd));
        (void)memcpy(
            quota_val, DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN);
        REQUIRE(patch_pvd(
            quota_val, (uint32_t)DSB2_QUOTA_TYPED_VALUE_LEN, pvd));
        REQUIRE(add_two_domain_rows_sorted(
                &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
                future_primary, DSB2_SERVICE_TYPED_VALUE_LEN,
                DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, quota_val,
                DSB2_QUOTA_TYPED_VALUE_LEN)
            == 0);
    }
    {
        ninlil_domain_scan_session_t session;
        ninlil_domain_scan_workspace_t workspace;
        ninlil_domain_scan_d3s1_context_t context;
        ninlil_domain_scan_result_t result;
        ninlil_storage_handle_t handle;
        const ninlil_storage_ops_t *ops;
        ops = ninlil_spy_ops(&spy);
        handle = ninlil_spy_open_handle(&spy);
        ninlil_domain_scan_session_init(&session);
        (void)memset(&workspace, 0, sizeof(workspace));
        (void)memset(&context, 0, sizeof(context));
        REQUIRE(ninlil_domain_scan_begin_profiled_d3s1(
                &session, ops, &handle, &workspace, &candidate, 17u, &context)
            == NINLIL_OK);
        REQUIRE(scan_until_terminal(&session) == 0);
        /* Matching PVD: D3 does not note CORRUPT on future framing. */
        REQUIRE(session.has_sticky_primary == 0u);
        REQUIRE(session.recognizable_future_seen == 1u);
        REQUIRE(ninlil_domain_scan_finalize(&session, &result)
            == NINLIL_E_UNSUPPORTED);
    }

    /*
     * Future primary with mismatched source header PVD: D3 CORRUPT after
     * peer-key subtype check, before envelope decode (even if framing future).
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        uint8_t future_primary[DSB2_SERVICE_TYPED_VALUE_LEN];
        uint8_t quota_val[DSB2_QUOTA_TYPED_VALUE_LEN];
        uint8_t wrong_pvd[32];
        uint32_t o;
        (void)memcpy(
            future_primary, DSB2_SERVICE_TYPED_VALUE,
            DSB2_SERVICE_TYPED_VALUE_LEN);
        future_primary[12] = 0x00u;
        future_primary[13] = 0x02u;
        o = ((uint32_t)future_primary[8] << 24)
            | ((uint32_t)future_primary[9] << 16)
            | ((uint32_t)future_primary[10] << 8)
            | (uint32_t)future_primary[11];
        write_u32_be(
            &future_primary[12u + o],
            crc32c_bytes(future_primary, 12u + o));
        (void)memset(wrong_pvd, 0xCCu, sizeof(wrong_pvd));
        (void)memcpy(
            quota_val, DSB2_QUOTA_TYPED_VALUE, DSB2_QUOTA_TYPED_VALUE_LEN);
        REQUIRE(patch_pvd(
            quota_val, (uint32_t)DSB2_QUOTA_TYPED_VALUE_LEN, wrong_pvd));
        REQUIRE(add_two_domain_rows_sorted(
                &spy, DSB2_SERVICE_TYPED_KEY, DSB2_SERVICE_TYPED_KEY_LEN,
                future_primary, DSB2_SERVICE_TYPED_VALUE_LEN,
                DSB2_QUOTA_TYPED_KEY, DSB2_QUOTA_TYPED_KEY_LEN, quota_val,
                DSB2_QUOTA_TYPED_VALUE_LEN)
            == 0);
    }
    /* SERVICE is CURRENT future → may set future flag, but QUOTA Mode17 notes. */
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 17u, 18u) == 0);
    return 0;
}

/* Mode 18: ATTEMPT ↔ ATTEMPT_ID_INDEX local gate (no counts). */
static int test_d3s1_mode18_attempt_index(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t aii_val[DSB3_AII_CMD_TYPED_VALUE_LEN];
    uint32_t payload_len;

    /* TX attempt → index PRESENT. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY,
            DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, DSB3_AII_CMD_TYPED_KEY,
            DSB3_AII_CMD_TYPED_KEY_LEN, DSB3_AII_CMD_TYPED_VALUE,
            DSB3_AII_CMD_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 18u) == 0);

    /* Index → attempt PRESENT (same pair; both sides applicable). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY,
            DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, DSB3_AII_CMD_TYPED_KEY,
            DSB3_AII_CMD_TYPED_KEY_LEN, DSB3_AII_CMD_TYPED_VALUE,
            DSB3_AII_CMD_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 18u) == 0);

    /* TX attempt → index ABSENT corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY,
        DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN, DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
        DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 18u, 17u) == 0);

    /*
     * DELIVERY-owned attempt: Mode18 expects index ABSENT (no local AII).
     * Probe uses attempt_id key; PRESENT would note corrupt.
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_ATT_DLV_CMD_REMOTE_TYPED_KEY,
        DSB3_ATT_DLV_CMD_REMOTE_TYPED_KEY_LEN,
        DSB3_ATT_DLV_CMD_REMOTE_TYPED_VALUE,
        DSB3_ATT_DLV_CMD_REMOTE_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 18u) == 0);

    /*
     * attempt_kind mismatch ATT→AII: both same-record valid; Mode18 notes
     * without S3 stealing (kind is not key-bound).
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    (void)memcpy(aii_val, DSB3_AII_CMD_TYPED_VALUE, DSB3_AII_CMD_TYPED_VALUE_LEN);
    /* attempt_kind u16 at body offset 32 (after attempt_id+tx_id). */
    aii_val[12u + 96u + 16u + 16u] = 0x00u;
    aii_val[12u + 96u + 16u + 16u + 1u] = 0x02u; /* EVENT vs COMMAND */
    payload_len = ((uint32_t)aii_val[8] << 24) | ((uint32_t)aii_val[9] << 16)
        | ((uint32_t)aii_val[10] << 8) | (uint32_t)aii_val[11];
    write_u32_be(
        &aii_val[12u + payload_len],
        crc32c_bytes(aii_val, 12u + payload_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY,
            DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, DSB3_AII_CMD_TYPED_KEY,
            DSB3_AII_CMD_TYPED_KEY_LEN, aii_val, DSB3_AII_CMD_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 18u, 17u) == 0);

    /*
     * AII→ATT attempt_kind equality is production-symmetric (source_raw2
     * len2/decode on both peer sides). With legal keys ATT(0x31) always sorts
     * before AII(0x34), so a pure kind mismatch is observed on the ATT→AII
     * path first without S3 stealing (above). Isolating AII-first kind note
     * alone is not possible without illegal subtype reordering.
     */

    /* Digest binding mismatch: flip attempt_record_key_digest in index. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    (void)memcpy(aii_val, DSB3_AII_CMD_TYPED_VALUE, DSB3_AII_CMD_TYPED_VALUE_LEN);
    aii_val[12u + 96u + 16u + 16u + 2u + 2u] ^= 0x01u;
    payload_len = ((uint32_t)aii_val[8] << 24) | ((uint32_t)aii_val[9] << 16)
        | ((uint32_t)aii_val[10] << 8) | (uint32_t)aii_val[11];
    write_u32_be(
        &aii_val[12u + payload_len],
        crc32c_bytes(aii_val, 12u + payload_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY,
            DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, DSB3_AII_CMD_TYPED_KEY,
            DSB3_AII_CMD_TYPED_KEY_LEN, aii_val, DSB3_AII_CMD_TYPED_VALUE_LEN)
        == 0);
    /* ATT first domain row after 17 profile keys. */
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 18u, 17u) == 0);

    /* transaction_id mismatch in index vs attempt (binding/raw). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    (void)memcpy(aii_val, DSB3_AII_CMD_TYPED_VALUE, DSB3_AII_CMD_TYPED_VALUE_LEN);
    aii_val[12u + 96u + 16u] ^= 0x01u; /* transaction_id first byte */
    payload_len = ((uint32_t)aii_val[8] << 24) | ((uint32_t)aii_val[9] << 16)
        | ((uint32_t)aii_val[10] << 8) | (uint32_t)aii_val[11];
    write_u32_be(
        &aii_val[12u + payload_len],
        crc32c_bytes(aii_val, 12u + payload_len));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_ATT_TX_CMD_PREP_TYPED_KEY,
            DSB3_ATT_TX_CMD_PREP_TYPED_KEY_LEN,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE,
            DSB3_ATT_TX_CMD_PREP_TYPED_VALUE_LEN, DSB3_AII_CMD_TYPED_KEY,
            DSB3_AII_CMD_TYPED_KEY_LEN, aii_val, DSB3_AII_CMD_TYPED_VALUE_LEN)
        == 0);
    /* ATT (0x31) before AII (0x34): Mode18 on ATT exact_gets AII, notes. */
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 18u, 17u) == 0);
    return 0;
}

/* Mode 19: RESULT → CALLBACK RES ACTIVE gate; never PVD-to-RESULT. */
static int test_d3s1_mode19_result_callback(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t cb_key[45];
    uint8_t cb_key_len = 0u;
    uint8_t cb_val[DSB2_RES_CB_TYPED_VALUE_LEN];
    uint8_t *body;
    uint32_t payload_len;
    ninlil_domain_scan_d3s1_context_t ctx;
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    ninlil_model_domain_body_result_cache_t rc;

    vv.data = DSB3_RC_STARTED_AT0_TYPED_VALUE;
    vv.length = DSB3_RC_STARTED_AT0_TYPED_VALUE_LEN;
    REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
    REQUIRE(ninlil_model_domain_decode_body_result_cache(env.body, &rc)
        == NINLIL_OK);
    REQUIRE(rc.delivery_state
        == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_DELIVERY_STARTED);
    REQUIRE(rc.token_state == NINLIL_MODEL_DOMAIN_TOKEN_STATE_ACTIVE);
    REQUIRE(rc.delivery_key_raw_length == 80u);

    /* Rebuild CALLBACK RES key for STARTED token_generation. */
    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.mode = NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES;
    (void)memcpy(ctx.source_raw, rc.delivery_key_raw, 80u);
    ctx.source_raw_len = 80u;
    ninlil_model_domain_encode_u64_be(ctx.source_aux, rc.token_generation);
    ctx.source_aux_len = 8u;
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx) == NINLIL_OK);
    (void)memcpy(cb_key, ctx.peer_key, ctx.peer_key_len);
    cb_key_len = ctx.peer_key_len;

    /*
     * Token-only patch of RES_CB: nested token_generation → STARTED's gen.
     * primary_key_digest is DELIVERY key digest (unchanged with token).
     */
    (void)memcpy(cb_val, DSB2_RES_CB_TYPED_VALUE, DSB2_RES_CB_TYPED_VALUE_LEN);
    body = &cb_val[12u + 96u];
    ninlil_model_domain_encode_u64_be(&body[6u + 2u + 80u], rc.token_generation);
    payload_len = ((uint32_t)cb_val[8] << 24) | ((uint32_t)cb_val[9] << 16)
        | ((uint32_t)cb_val[10] << 8) | (uint32_t)cb_val[11];
    write_u32_be(
        &cb_val[12u + payload_len],
        crc32c_bytes(cb_val, 12u + payload_len));

    /* state2+ACTIVE → CALLBACK RES PRESENT. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_RC_STARTED_AT0_TYPED_KEY,
            DSB3_RC_STARTED_AT0_TYPED_KEY_LEN, DSB3_RC_STARTED_AT0_TYPED_VALUE,
            DSB3_RC_STARTED_AT0_TYPED_VALUE_LEN, cb_key, cb_key_len, cb_val,
            DSB2_RES_CB_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 19u) == 0);

    /* ACTIVE missing CALLBACK RES → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_STARTED_AT0_TYPED_KEY, DSB3_RC_STARTED_AT0_TYPED_KEY_LEN,
        DSB3_RC_STARTED_AT0_TYPED_VALUE, DSB3_RC_STARTED_AT0_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 19u, 17u) == 0);

    /* INBOX (non-ACTIVE) → ABSENT OK. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_INBOX_VIRGIN_TYPED_KEY, DSB3_RC_INBOX_VIRGIN_TYPED_KEY_LEN,
        DSB3_RC_INBOX_VIRGIN_TYPED_VALUE, DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 19u) == 0);

    /* RESULT_COMMITTED (non-ACTIVE) → ABSENT OK. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_RESULT_POS_TYPED_KEY, DSB3_RC_RESULT_POS_TYPED_KEY_LEN,
        DSB3_RC_RESULT_POS_TYPED_VALUE, DSB3_RC_RESULT_POS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 19u) == 0);

    /* CANCEL_TOMBSTONE (non-ACTIVE) → ABSENT OK. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_CANCEL_FIRST_TYPED_KEY,
        DSB3_RC_CANCEL_FIRST_TYPED_KEY_LEN, DSB3_RC_CANCEL_FIRST_TYPED_VALUE,
        DSB3_RC_CANCEL_FIRST_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 19u) == 0);

    /*
     * Non-ACTIVE RESULT (RESULT_COMMITTED) + CALLBACK RES unexpectedly PRESENT
     * at rebuilt key → corrupt (gate expects ABSENT).
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    {
        ninlil_bytes_view_t vv2;
        ninlil_model_domain_envelope_t env2;
        ninlil_model_domain_body_result_cache_t rc2;
        uint8_t term_cb_key[45];
        uint8_t term_cb_key_len = 0u;
        vv2.data = DSB3_RC_RESULT_POS_TYPED_VALUE;
        vv2.length = DSB3_RC_RESULT_POS_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv2, &env2) == NINLIL_OK);
        REQUIRE(ninlil_model_domain_decode_body_result_cache(env2.body, &rc2)
            == NINLIL_OK);
        REQUIRE(rc2.delivery_state
            == NINLIL_MODEL_DOMAIN_DELIVERY_STATE_RESULT_COMMITTED);
        (void)memset(&ctx, 0, sizeof(ctx));
        ctx.mode = NINLIL_DOMAIN_SCAN_D3S1_MODE_RESULT_CALLBACK_RES;
        (void)memcpy(ctx.source_raw, rc2.delivery_key_raw, 80u);
        ctx.source_raw_len = 80u;
        ninlil_model_domain_encode_u64_be(ctx.source_aux, rc2.token_generation);
        ctx.source_aux_len = 8u;
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
            == NINLIL_OK);
        (void)memcpy(term_cb_key, ctx.peer_key, ctx.peer_key_len);
        term_cb_key_len = ctx.peer_key_len;
        /*
         * CALLBACK RES template already has nested delivery RAW16 for this DLV;
         * only retarget nested token_generation so key/body same-record holds.
         */
        (void)memcpy(cb_val, DSB2_RES_CB_TYPED_VALUE, DSB2_RES_CB_TYPED_VALUE_LEN);
        body = &cb_val[12u + 96u];
        ninlil_model_domain_encode_u64_be(
            &body[6u + 2u + 80u], rc2.token_generation);
        payload_len = ((uint32_t)cb_val[8] << 24) | ((uint32_t)cb_val[9] << 16)
            | ((uint32_t)cb_val[10] << 8) | (uint32_t)cb_val[11];
        write_u32_be(
            &cb_val[12u + payload_len],
            crc32c_bytes(cb_val, 12u + payload_len));
        REQUIRE(add_two_domain_rows_sorted(
                &spy, DSB3_RC_RESULT_POS_TYPED_KEY,
                DSB3_RC_RESULT_POS_TYPED_KEY_LEN, DSB3_RC_RESULT_POS_TYPED_VALUE,
                DSB3_RC_RESULT_POS_TYPED_VALUE_LEN, term_cb_key, term_cb_key_len,
                cb_val, DSB2_RES_CB_TYPED_VALUE_LEN)
            == 0);
    }
    /* RES(0x23) before RESULT(0x41): 17 profile + 1 RES non-applicable. */
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 19u, 18u) == 0);

    /*
     * Peer-key ABSENT (wrong CALLBACK RES key for ACTIVE STARTED): rebuild
     * targets token=1 key; fixture RES_CB is a different key → ABSENT note.
     * Not a body nested-token PRESENT mismatch.
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_RC_STARTED_AT0_TYPED_KEY,
            DSB3_RC_STARTED_AT0_TYPED_KEY_LEN, DSB3_RC_STARTED_AT0_TYPED_VALUE,
            DSB3_RC_STARTED_AT0_TYPED_VALUE_LEN, DSB2_RES_CB_TYPED_KEY,
            DSB2_RES_CB_TYPED_KEY_LEN, DSB2_RES_CB_TYPED_VALUE,
            DSB2_RES_CB_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 19u, 18u) == 0);

    /*
     * No PVD-to-RESULT: CALLBACK RES PRESENT with intentional wrong header PVD
     * still succeeds (Mode19 FLAG_SKIP_PEER_PVD; Mode17 owns CALLBACK→DELIVERY).
     */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    (void)memcpy(cb_val, DSB2_RES_CB_TYPED_VALUE, DSB2_RES_CB_TYPED_VALUE_LEN);
    body = &cb_val[12u + 96u];
    ninlil_model_domain_encode_u64_be(&body[6u + 2u + 80u], rc.token_generation);
    {
        uint8_t wrong_pvd[32];
        (void)memset(wrong_pvd, 0xA5u, sizeof(wrong_pvd));
        REQUIRE(patch_pvd(
            cb_val, (uint32_t)DSB2_RES_CB_TYPED_VALUE_LEN, wrong_pvd));
    }
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_RC_STARTED_AT0_TYPED_KEY,
            DSB3_RC_STARTED_AT0_TYPED_KEY_LEN, DSB3_RC_STARTED_AT0_TYPED_VALUE,
            DSB3_RC_STARTED_AT0_TYPED_VALUE_LEN, cb_key, cb_key_len, cb_val,
            DSB2_RES_CB_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 19u) == 0);
    return 0;
}

/*
 * Re-encode TRANSACTION_STATE with legal state/target_state pair (codec-valid).
 */
static int encode_tx_state_variant(
    uint32_t state,
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
    vv.length = DSB2_STATE_TYPED_VALUE_LEN;
    if (ninlil_model_domain_decode_envelope(vv, &env) != NINLIL_OK) {
        return 0;
    }
    if (ninlil_model_domain_decode_body_transaction_state(env.body, &st)
        != NINLIL_OK) {
        return 0;
    }
    st.state = state;
    st.target_state = state;
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

/* Mode 20 GATE_RETENTION_BASIS: §9 active ABSENT / terminal retained PRESENT. */
static int test_d3s1_mode20_retention_gate(void)
{
    ninlil_scripted_storage_spy_t spy;
    ninlil_model_runtime_store_binding_t candidate;
    uint8_t state_val[512];
    uint32_t vlen = 0u;
    size_t i;
    static const uint32_t tx_active[] = {
        NINLIL_TXN_READY,
        NINLIL_TXN_DISPATCHING,
        NINLIL_TXN_AWAITING_EVIDENCE,
        NINLIL_TXN_PARKED_RETRY,
        NINLIL_TXN_WAITING_WINDOW,
    };

    /* TX active legal states → RETENTION ABSENT OK (parameterized). */
    for (i = 0u; i < sizeof(tx_active) / sizeof(tx_active[0]); i += 1u) {
        ninlil_spy_init(&spy);
        REQUIRE(s2_install_full_profile(&spy, &candidate));
        REQUIRE(encode_tx_state_variant(
            tx_active[i], state_val, (uint32_t)sizeof(state_val), &vlen));
        REQUIRE(add_domain_row(
            &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN, state_val,
            vlen));
        REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);
    }

    /* TX TERMINAL retained → RETENTION PRESENT (fixture RB_TX). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(encode_tx_state_variant(
        NINLIL_TXN_TERMINAL, state_val, (uint32_t)sizeof(state_val), &vlen));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN, state_val,
            vlen, DSB3_RB_TX_ELIGIBLE_TYPED_KEY,
            DSB3_RB_TX_ELIGIBLE_TYPED_KEY_LEN, DSB3_RB_TX_ELIGIBLE_TYPED_VALUE,
            DSB3_RB_TX_ELIGIBLE_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);

    /* TX TERMINAL missing retention → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB2_STATE_TYPED_KEY, DSB2_STATE_TYPED_KEY_LEN, state_val, vlen));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 20u, 17u) == 0);

    /* RESULT active: INBOX / STARTED ABSENT OK. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_INBOX_VIRGIN_TYPED_KEY, DSB3_RC_INBOX_VIRGIN_TYPED_KEY_LEN,
        DSB3_RC_INBOX_VIRGIN_TYPED_VALUE, DSB3_RC_INBOX_VIRGIN_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);

    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_STARTED_AT0_TYPED_KEY, DSB3_RC_STARTED_AT0_TYPED_KEY_LEN,
        DSB3_RC_STARTED_AT0_TYPED_VALUE, DSB3_RC_STARTED_AT0_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);

    /* RESULT RECOVERY_REQUIRED active → ABSENT OK (legal fixture). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_REC_G_IS_I_P1_TYPED_KEY,
        DSB3_RC_REC_G_IS_I_P1_TYPED_KEY_LEN, DSB3_RC_REC_G_IS_I_P1_TYPED_VALUE,
        DSB3_RC_REC_G_IS_I_P1_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);

    /*
     * RECONCILE_WAIT: no independent legal typed fixture in DSB3 set that
     * pairs cleanly with RB_DLV subject raw without inventing illegal bodies.
     * Report impossible rather than patch invalid product.
     */

    /* RESULT_COMMITTED terminal missing retention → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_RESULT_POS_TYPED_KEY, DSB3_RC_RESULT_POS_TYPED_KEY_LEN,
        DSB3_RC_RESULT_POS_TYPED_VALUE, DSB3_RC_RESULT_POS_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 20u, 17u) == 0);

    /* RESULT_COMMITTED + RB_DLV PRESENT (fixture subject raw match). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_RC_RESULT_POS_TYPED_KEY,
            DSB3_RC_RESULT_POS_TYPED_KEY_LEN, DSB3_RC_RESULT_POS_TYPED_VALUE,
            DSB3_RC_RESULT_POS_TYPED_VALUE_LEN, DSB3_RB_DLV_CLEANUP_TYPED_KEY,
            DSB3_RB_DLV_CLEANUP_TYPED_KEY_LEN, DSB3_RB_DLV_CLEANUP_TYPED_VALUE,
            DSB3_RB_DLV_CLEANUP_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);

    /* DISPOSITION_COMMITTED + RB_DLV PRESENT (legal typed fixture). */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_RC_DISP_PRE_TYPED_KEY, DSB3_RC_DISP_PRE_TYPED_KEY_LEN,
            DSB3_RC_DISP_PRE_TYPED_VALUE, DSB3_RC_DISP_PRE_TYPED_VALUE_LEN,
            DSB3_RB_DLV_CLEANUP_TYPED_KEY, DSB3_RB_DLV_CLEANUP_TYPED_KEY_LEN,
            DSB3_RB_DLV_CLEANUP_TYPED_VALUE, DSB3_RB_DLV_CLEANUP_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);

    /* CANCEL_TOMBSTONE_ONLY terminal missing retention → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_domain_row(
        &spy, DSB3_RC_CANCEL_FIRST_TYPED_KEY,
        DSB3_RC_CANCEL_FIRST_TYPED_KEY_LEN, DSB3_RC_CANCEL_FIRST_TYPED_VALUE,
        DSB3_RC_CANCEL_FIRST_TYPED_VALUE_LEN));
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 20u, 17u) == 0);

    /* CANCEL_TOMBSTONE_ONLY + RB_DLV PRESENT. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_RC_CANCEL_FIRST_TYPED_KEY,
            DSB3_RC_CANCEL_FIRST_TYPED_KEY_LEN, DSB3_RC_CANCEL_FIRST_TYPED_VALUE,
            DSB3_RC_CANCEL_FIRST_TYPED_VALUE_LEN, DSB3_RB_DLV_CLEANUP_TYPED_KEY,
            DSB3_RB_DLV_CLEANUP_TYPED_KEY_LEN, DSB3_RB_DLV_CLEANUP_TYPED_VALUE,
            DSB3_RB_DLV_CLEANUP_TYPED_VALUE_LEN)
        == 0);
    REQUIRE(run_mode_scan_ok(&spy, &candidate, 20u) == 0);

    /* Subject raw mismatch: terminal RESULT + TX retention peer → corrupt. */
    ninlil_spy_init(&spy);
    REQUIRE(s2_install_full_profile(&spy, &candidate));
    REQUIRE(add_two_domain_rows_sorted(
            &spy, DSB3_RC_RESULT_POS_TYPED_KEY,
            DSB3_RC_RESULT_POS_TYPED_KEY_LEN, DSB3_RC_RESULT_POS_TYPED_VALUE,
            DSB3_RC_RESULT_POS_TYPED_VALUE_LEN, DSB3_RB_TX_ELIGIBLE_TYPED_KEY,
            DSB3_RB_TX_ELIGIBLE_TYPED_KEY_LEN, DSB3_RB_TX_ELIGIBLE_TYPED_VALUE,
            DSB3_RB_TX_ELIGIBLE_TYPED_VALUE_LEN)
        == 0);
    /* Rebuild expects DELIVERY retention key ≠ TX key → ABSENT note. */
    REQUIRE(run_mode_scan_corrupt(&spy, &candidate, 20u, 17u) == 0);

    /* Cleanup overlay/phase not claimed (S11); Mode17 retention reverse above. */
    return 0;
}

/* Pure Mode17 reverse rebuild goldens for distinct rebuild formulas. */
static int test_d3s1_mode17_pure_rebuild(void)
{
    ninlil_domain_scan_d3s1_context_t ctx;
    ninlil_bytes_view_t vv;
    ninlil_model_domain_envelope_t env;
    const uint8_t *qbody = &DSB2_QUOTA_TYPED_VALUE[12u + 96u];
    uint16_t raw_len = (uint16_t)(((uint16_t)qbody[0] << 8) | qbody[1]);

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.mode = NINLIL_DOMAIN_SCAN_D3S1_MODE_REV_PRIMARY;
    ctx.source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE_QUOTA;
    (void)memcpy(ctx.source_raw, &qbody[2], raw_len);
    ctx.source_raw_len = (uint8_t)raw_len;
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
        == NINLIL_OK);
    REQUIRE(ctx.peer_key_len == DSB2_SERVICE_TYPED_KEY_LEN);
    REQUIRE(memcmp(ctx.peer_key, DSB2_SERVICE_TYPED_KEY, ctx.peer_key_len)
        == 0);

    /* SEQ → ANCHOR (ID128). */
    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.mode = 17u;
    ctx.source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_TRANSACTION_SEQUENCE_INDEX;
    (void)memcpy(ctx.source_raw, &DSB2_SEQ_TYPED_VALUE[12u + 96u + 8u], 16u);
    ctx.source_raw_len = 16u;
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
        == NINLIL_OK);
    REQUIRE(ctx.peer_key_len == DSB2_ANCHOR_TYPED_KEY_LEN);
    REQUIRE(memcmp(ctx.peer_key, DSB2_ANCHOR_TYPED_KEY, ctx.peer_key_len)
        == 0);

    /* IDEM dual-raw → ANCHOR (aux=tx). */
    {
        ninlil_model_domain_body_idempotency_map_t idem;
        vv.data = DSB2_IDEM_TYPED_VALUE;
        vv.length = DSB2_IDEM_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(ninlil_model_domain_decode_body_idempotency_map(env.body, &idem)
            == NINLIL_OK);
        (void)memset(&ctx, 0, sizeof(ctx));
        ctx.mode = 17u;
        ctx.source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_IDEMPOTENCY_MAP;
        (void)memcpy(
            ctx.source_raw, idem.scope_raw, idem.scope_raw_length);
        ctx.source_raw_len = (uint8_t)idem.scope_raw_length;
        (void)memcpy(
            ctx.source_raw2, idem.idempotency_key, idem.idempotency_key_length);
        ctx.source_raw2_len = (uint8_t)idem.idempotency_key_length;
        (void)memcpy(ctx.source_aux, idem.transaction_id, 16u);
        ctx.source_aux_len = 16u;
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
            == NINLIL_OK);
        REQUIRE(ctx.peer_key_len == DSB2_ANCHOR_TYPED_KEY_LEN);
        REQUIRE(memcmp(ctx.peer_key, DSB2_ANCHOR_TYPED_KEY, ctx.peer_key_len)
            == 0);
    }

    /* CALLBACK RES nested → DELIVERY (never RESULT key). */
    {
        ninlil_model_domain_body_reservation_t res;
        vv.data = DSB2_RES_CB_TYPED_VALUE;
        vv.length = DSB2_RES_CB_TYPED_VALUE_LEN;
        REQUIRE(ninlil_model_domain_decode_envelope(vv, &env) == NINLIL_OK);
        REQUIRE(ninlil_model_domain_decode_body_reservation(env.body, &res)
            == NINLIL_OK);
        (void)memset(&ctx, 0, sizeof(ctx));
        ctx.mode = 17u;
        ctx.source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION;
        ctx.owner_kind =
            (uint8_t)NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_CALLBACK;
        (void)memcpy(
            ctx.source_raw, res.owner_key_raw, res.owner_key_raw_length);
        ctx.source_raw_len = (uint8_t)res.owner_key_raw_length;
        REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
            == NINLIL_OK);
        REQUIRE(ctx.peer_key_len == DSB3_DLV_APP_DS_TYPED_KEY_LEN);
        REQUIRE(memcmp(ctx.peer_key, DSB3_DLV_APP_DS_TYPED_KEY, ctx.peer_key_len)
            == 0);
        /* Explicitly not RESULT_CACHE key. */
        REQUIRE(memcmp(
                    ctx.peer_key, DSB3_RC_INBOX_VIRGIN_TYPED_KEY,
                    ctx.peer_key_len)
            != 0);
    }

    /* INGRESS RES owner BE8 → ORDERED_INGRESS. */
    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.mode = 17u;
    ctx.source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_RESERVATION;
    ctx.owner_kind = (uint8_t)NINLIL_MODEL_DOMAIN_RESERVATION_OWNER_INGRESS;
    ninlil_model_domain_encode_u64_be(ctx.source_raw, 1u);
    ctx.source_raw_len = 8u;
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
        == NINLIL_OK);
    REQUIRE(ctx.peer_key_len == DSB3_ING_APP_DS_TYPED_KEY_LEN);
    REQUIRE(memcmp(ctx.peer_key, DSB3_ING_APP_DS_TYPED_KEY, ctx.peer_key_len)
        == 0);

    /* Excluded subtype (BLOB/primary) → INVALID. */
    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.mode = 17u;
    ctx.source_subtype = NINLIL_MODEL_DOMAIN_SUBTYPE_SERVICE;
    REQUIRE(ninlil_domain_scan_d3s1_rebuild_peer_key_dispatch(&ctx)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

int main(void)
{
    if (test_d3s1_context_size_and_aggregate() != 0) {
        return 1;
    }
    if (test_d3s1_rebuild_modes_1_10() != 0) {
        return 1;
    }
    if (test_d3s1_begin_prevalidation() != 0) {
        return 1;
    }
    if (test_d2_begin_leaves_d3_inactive() != 0) {
        return 1;
    }
    if (test_d3s1_service_mode1_present_ok() != 0) {
        return 1;
    }
    if (test_d3s1_service_mode1_absent_notes_no_ok_inc() != 0) {
        return 1;
    }
    if (test_d3s1_service_mode1_pvd_and_raw_mismatch() != 0) {
        return 1;
    }
    if (test_d3s1_port_failure_no_note() != 0) {
        return 1;
    }
    if (test_d3s1_non_applicable_skips_get() != 0) {
        return 1;
    }
    if (test_d3s1_tx_mode3_present() != 0) {
        return 1;
    }
    if (test_d3s1_ds_mode8_and_mode9_absent_separate_sessions() != 0) {
        return 1;
    }
    if (test_d3s1_mode2_present() != 0) {
        return 1;
    }
    if (test_d3s1_tx_modes_4_6_10_present() != 0) {
        return 1;
    }
    if (test_d3s1_tx_mode7_present() != 0) {
        return 1;
    }
    if (test_d3s1_mode5_dual_raw_present_and_half_mismatch() != 0) {
        return 1;
    }
    if (test_d3s1_ef_mode8_9_present_mode10_absent() != 0) {
        return 1;
    }
    if (test_d3s1_previous_key_preserved_after_exact_get() != 0) {
        return 1;
    }
    if (test_d3s1_future_domain_shaped_no_stale_typed_corrupt() != 0) {
        return 1;
    }
    if (test_d3s1_future_peer_value_not_false_corrupt() != 0) {
        return 1;
    }
    if (test_d3s1_mode11_result_cache() != 0) {
        return 1;
    }
    if (test_d3s1_mode12_delivery_reservation() != 0) {
        return 1;
    }
    if (test_d3s1_mode13_delivery_scheduler() != 0) {
        return 1;
    }
    if (test_d3s1_mode14_delivery_cancel_family() != 0) {
        return 1;
    }
    if (test_d3s1_mode15_ingress_reservation() != 0) {
        return 1;
    }
    if (test_d3s1_mode16_scheduler_variants() != 0) {
        return 1;
    }
    if (test_d3s1_mode16_previous_key_and_ok_count() != 0) {
        return 1;
    }
    if (test_d3s1_mode12_13_15_layering_and_mode13_raw() != 0) {
        return 1;
    }
    if (test_d3s1_mode17_pure_rebuild() != 0) {
        return 1;
    }
    if (test_d3s1_mode17_rev_primary_core() != 0) {
        return 1;
    }
    if (test_d3s1_mode18_attempt_index() != 0) {
        return 1;
    }
    if (test_d3s1_mode19_result_callback() != 0) {
        return 1;
    }
    if (test_d3s1_mode20_retention_gate() != 0) {
        return 1;
    }
    return 0;
}
