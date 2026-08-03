/*
 * ADR-0022 repair tests: Foundation profile, LAST_LAB, T0, overflow, tamper.
 */

#include "domain_schema1_runtime_binding.h"

#include <limits.h>
#include <ninlil/version.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(cond)                                                       \
    do {                                                                    \
        if (!(cond)) {                                                      \
            (void)fprintf(                                                  \
                stderr,                                                     \
                "domain_schema1 FAIL %s:%d: %s\n",                          \
                __FILE__,                                                   \
                __LINE__,                                                   \
                #cond);                                                     \
            return 1;                                                       \
        }                                                                   \
    } while (0)

static void fill_controller(ninlil_domain_schema1_binding_t *b)
{
    uint32_t i;
    (void)memset(b, 0, sizeof(*b));
    b->common.storage_schema = 1u;
    b->common.role = NINLIL_ROLE_CONTROLLER;
    b->common.environment = NINLIL_ENV_TEST;
    for (i = 0u; i < 16u; ++i) {
        b->common.runtime_id.bytes[i] = 0x44u;
    }
    b->common.limits.max_services = 16u;
    b->common.limits.max_nonterminal_transactions = 32u;
    b->common.limits.max_targets_per_transaction = 1u;
    b->common.limits.max_logical_payload_bytes = 256u;
    b->common.limits.max_durable_outbox_payload_bytes = 8192u;
    b->common.limits.max_attempts_per_target_per_cycle = 8u;
    b->common.limits.max_cancel_attempts_per_transaction = 1u;
    b->common.limits.max_evidence_per_target = 3u;
    b->common.limits.max_retained_terminal_transactions = 64u;
    b->common.limits.max_nonterminal_deliveries = 32u;
    b->common.limits.max_event_spool_count = 0u;
    b->common.limits.max_event_spool_bytes = 0u;
    b->common.limits.max_result_cache_entries = 32u;
    b->common.limits.max_retained_dispositions = 64u;
    b->common.limits.max_ingress_per_step = 8u;
    b->common.limits.max_callbacks_per_step = 8u;
    b->common.limits.max_state_transitions_per_step = 16u;
    b->common.limits.max_bearer_sends_per_step = 8u;
    b->common.limits.max_deferred_tokens = 16u;
    b->common.terminal_retention_ms = 2000u;
    b->common.result_cache_retention_ms = 1000u;
    b->common.observation_retention_ms = 3000u;
    (void)memcpy(b->storage_profile_id, "NINLIL-DOMAIN-S1", 16u);
    b->storage_profile_revision = 1u;
    b->minimum_writer_generation = 2u;
    b->rollback_epoch = 1u;
}

static void fill_endpoint(ninlil_domain_schema1_binding_t *b)
{
    fill_controller(b);
    b->common.role = NINLIL_ROLE_ENDPOINT;
    b->common.limits.max_services = 8u;
    b->common.limits.max_nonterminal_transactions = 32u;
    b->common.limits.max_durable_outbox_payload_bytes = 0u;
    b->common.limits.max_event_spool_count = 8u;
    b->common.limits.max_event_spool_bytes = 4096u;
    b->common.limits.max_retained_terminal_transactions = 64u;
}

static void fill_identity(ninlil_model_runtime_store_identity_t *id)
{
    uint32_t i;
    (void)memset(id, 0, sizeof(*id));
    id->flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    for (i = 0u; i < 16u; ++i) {
        id->device_id.bytes[i] = 0x55u;
        id->installation_id.bytes[i] = 0x66u;
        id->site_domain_id.bytes[i] = 0x77u;
    }
    id->binding_epoch = 1u;
    id->membership_epoch = 1u;
}

typedef struct storage_spy {
    ninlil_domain_schema1_storage_op_t ops[NINLIL_DOMAIN_SCHEMA1_STORAGE_OP_MAX];
    uint32_t count;
    uint32_t next_txn;
} storage_spy_t;

static void spy_reset(storage_spy_t *spy)
{
    (void)memset(spy, 0, sizeof(*spy));
    spy->next_txn = 1u;
}

static int spy_push(
    storage_spy_t *spy,
    ninlil_domain_schema1_storage_op_kind_t kind,
    uint32_t txn)
{
    if (spy->count >= NINLIL_DOMAIN_SCHEMA1_STORAGE_OP_MAX) {
        return 0;
    }
    spy->ops[spy->count].kind = kind;
    spy->ops[spy->count].transaction_id = txn;
    spy->count += 1u;
    return 1;
}

static int test_profiles_and_invalid_role(void)
{
    ninlil_domain_schema1_binding_t controller;
    ninlil_domain_schema1_binding_t endpoint;
    ninlil_domain_schema1_binding_t invalid;
    uint8_t enc[NINLIL_DOMAIN_SCHEMA1_BINDING_VALUE_BYTES];
    uint32_t len = 0u;

    fill_controller(&controller);
    fill_endpoint(&endpoint);
    REQUIRE(
        ninlil_domain_schema1_validate_binding(&controller) == NINLIL_OK);
    REQUIRE(ninlil_domain_schema1_validate_binding(&endpoint) == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_encode_binding(
            &controller, enc, sizeof(enc), &len)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_encode_binding(
            &endpoint, enc, sizeof(enc), &len)
        == NINLIL_OK);

    /* invalid role both encoded+expected must reject (not accept). */
    invalid = controller;
    invalid.common.role = (ninlil_role_t)99u;
    REQUIRE(
        ninlil_domain_schema1_validate_binding(&invalid)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_encode_binding(
            &invalid, enc, sizeof(enc), &len)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_classify_binding_open(
            (ninlil_bytes_view_t){enc, len},
            NINLIL_DOMAIN_SCHEMA1_CONSUMER_CANONICAL_DOMAIN,
            2u,
            &invalid)
        == NINLIL_E_INVALID_ARGUMENT);

    /* Cross-use: controller bytes vs endpoint expected */
    REQUIRE(
        ninlil_domain_schema1_encode_binding(
            &controller, enc, sizeof(enc), &len)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_classify_binding_open(
            (ninlil_bytes_view_t){enc, len},
            NINLIL_DOMAIN_SCHEMA1_CONSUMER_CANONICAL_DOMAIN,
            2u,
            &endpoint)
        == NINLIL_E_UNSUPPORTED);

    /* Controller with Endpoint event spool fails Foundation */
    invalid = controller;
    invalid.common.limits.max_event_spool_count = 8u;
    invalid.common.limits.max_event_spool_bytes = 4096u;
    REQUIRE(
        ninlil_domain_schema1_validate_binding(&invalid)
        == NINLIL_E_INVALID_ARGUMENT);

    /* result_cache_retention > terminal */
    invalid = controller;
    invalid.common.result_cache_retention_ms = 5000u;
    invalid.common.terminal_retention_ms = 2000u;
    REQUIRE(
        ninlil_domain_schema1_validate_binding(&invalid)
        == NINLIL_E_INVALID_ARGUMENT);

    /* multi-target forbidden */
    invalid = controller;
    invalid.common.limits.max_targets_per_transaction = 4u;
    REQUIRE(
        ninlil_domain_schema1_validate_binding(&invalid)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_last_lab_invalid_limits(void)
{
    ninlil_domain_schema1_binding_t controller;
    ninlil_model_runtime_store_binding_t common;
    uint8_t format1[NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES];
    uint32_t len = 0u;

    fill_controller(&controller);
    common = controller.common;
    REQUIRE(
        ninlil_model_runtime_store_encode_binding(
            &common, format1, sizeof(format1), &len)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_classify_binding_open(
            (ninlil_bytes_view_t){format1, len},
            NINLIL_DOMAIN_SCHEMA1_CONSUMER_LAST_LAB_BINARY,
            2u,
            NULL)
        == NINLIL_OK);

    /* Zero outbox on controller limits is invalid Foundation. */
    common.limits.max_durable_outbox_payload_bytes = 0u;
    REQUIRE(
        ninlil_model_runtime_store_encode_binding(
            &common, format1, sizeof(format1), &len)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_classify_binding_open(
            (ninlil_bytes_view_t){format1, len},
            NINLIL_DOMAIN_SCHEMA1_CONSUMER_LAST_LAB_BINARY,
            2u,
            NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    common = controller.common;
    common.role = (ninlil_role_t)99u;
    REQUIRE(
        ninlil_model_runtime_store_encode_binding(
            &common, format1, sizeof(format1), &len)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_classify_binding_open(
            (ninlil_bytes_view_t){format1, len},
            NINLIL_DOMAIN_SCHEMA1_CONSUMER_LAST_LAB_BINARY,
            2u,
            NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_plan_identity_tamper(void)
{
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_domain_schema1_bootstrap_plan_t plan;
    ninlil_domain_schema1_bootstrap_record_t record;
    ninlil_domain_schema1_bootstrap_record_t baseline;
    ninlil_domain_schema1_t1a_class_t t1a_class;
    uint8_t alt_id[16];
    uint32_t i;

    fill_controller(&binding);
    fill_identity(&identity);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 1u, &baseline)
        == NINLIL_OK);

    plan.identity.flags = 0u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 0u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 1u, &record)
        == NINLIL_E_INVALID_ARGUMENT);

    fill_identity(&identity);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.identity.binding_epoch = 0u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 0u, &record)
        == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.identity.membership_epoch = 0u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 0u, &record)
        == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.binding.common.role = NINLIL_ROLE_ENDPOINT;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 0u, &record)
        == NINLIL_E_INVALID_ARGUMENT);

    /* Valid-value substitution of device_id must still break the seal. */
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    for (i = 0u; i < 16u; ++i) {
        alt_id[i] = 0xAAu;
    }
    (void)memcpy(plan.identity.device_id.bytes, alt_id, 16u);
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 1u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_classify_t1a_commit_unknown(
            &plan, NULL, 0u, &t1a_class)
        == NINLIL_OK);
    REQUIRE(t1a_class == NINLIL_DOMAIN_SCHEMA1_T1A_CORRUPT);

    /* Limit / retention field substitutions. */
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.binding.common.limits.max_services = 8u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 0u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.binding.common.terminal_retention_ms = 3000u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 0u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.binding.common.result_cache_retention_ms = 500u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 0u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.identity.installation_id.bytes[0] ^= 1u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 1u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.identity.site_domain_id.bytes[0] ^= 1u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 1u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    plan.capacity_source_limits.max_services = 1u;
    REQUIRE(
        ninlil_domain_schema1_bootstrap_record_at(&plan, 6u, &record)
        == NINLIL_E_INVALID_ARGUMENT);
    (void)baseline;
    return 0;
}

static int test_count_overflow_and_t0(void)
{
    size_t bytes = 0u;
    storage_spy_t spy;
    ninlil_domain_schema1_storage_transcript_t tr;
    ninlil_domain_schema1_t0_class_t t0_class;
    ninlil_domain_schema1_t1a_class_t t1a_class;
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_domain_schema1_bootstrap_plan_t plan;
    uint32_t txn;

    REQUIRE(
        ninlil_domain_schema1_checked_count_bytes(
            2u, sizeof(int), &bytes)
        == 1);
    REQUIRE(bytes == 2u * sizeof(int));
    /* count==0 is valid: out_bytes=0, no division (UBSan-safe). */
    REQUIRE(
        ninlil_domain_schema1_checked_count_bytes(0u, sizeof(int), &bytes)
        == 1);
    REQUIRE(bytes == 0u);
    REQUIRE(
        ninlil_domain_schema1_checked_count_bytes(
            0u, (size_t)1024u, &bytes)
        == 1);
    REQUIRE(bytes == 0u);
    REQUIRE(
        ninlil_domain_schema1_checked_count_bytes(
            NINLIL_DOMAIN_SCHEMA1_COUNT_HARD_CAP + 1u,
            1u,
            &bytes)
        == 0);
    /* Simulated large u32 without allocation */
    REQUIRE(
        ninlil_domain_schema1_checked_count_bytes(
            UINT32_MAX, sizeof(ninlil_domain_schema1_snapshot_row_t), &bytes)
        == 0);
    /* 32/64-bit portable overflow: 2 * (SIZE_MAX/2+1) overflows size_t. */
    REQUIRE(
        ninlil_domain_schema1_checked_count_bytes(
            2u, (SIZE_MAX / 2u) + 1u, &bytes)
        == 0);

    fill_controller(&binding);
    fill_identity(&identity);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_classify_t1a_commit_unknown(
            &plan,
            (const ninlil_domain_schema1_snapshot_row_t *)(uintptr_t)0x1,
            UINT32_MAX,
            &t1a_class)
        == NINLIL_E_INVALID_ARGUMENT);

    spy_reset(&spy);
    txn = spy.next_txn++;
    REQUIRE(spy_push(&spy, NINLIL_DOMAIN_SCHEMA1_OP_TX_BEGIN_READ_WRITE, txn));
    REQUIRE(spy_push(&spy, NINLIL_DOMAIN_SCHEMA1_OP_ITER_OPEN, txn));
    REQUIRE(
        spy_push(&spy, NINLIL_DOMAIN_SCHEMA1_OP_ITER_NEXT_NOT_FOUND, txn));
    REQUIRE(spy_push(&spy, NINLIL_DOMAIN_SCHEMA1_OP_ITER_CLOSE, txn));
    tr.ops = spy.ops;
    tr.op_count = spy.count;
    REQUIRE(ninlil_domain_schema1_classify_t0(&tr, &t0_class) == NINLIL_OK);
    REQUIRE(t0_class == NINLIL_DOMAIN_SCHEMA1_T0_ZERO_ROW_AUTHORITY);

    tr.op_count = UINT32_MAX;
    tr.ops = spy.ops;
    REQUIRE(
        ninlil_domain_schema1_classify_t0(&tr, &t0_class)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

/*
 * Production counterexample: sizeof(limits)=88 with semantic bytes=84
 * (max_deferred_tokens ends at offset 84). Only the 4 tail padding bytes
 * differ; field-wise equality must ignore padding entirely.
 */
enum { LIMITS_SEMANTIC_BYTES = 84u };

static void poison_limits_all_padding(
    ninlil_model_runtime_store_limits_t *limits,
    uint8_t pattern)
{
    uint8_t *raw = (uint8_t *)limits;
    size_t size = sizeof(*limits);
    size_t index;
    /* Poison every byte past the last semantic field (tail; any future
     * interior holes would also be covered by the overlay path below). */
    for (index = LIMITS_SEMANTIC_BYTES; index < size; ++index) {
        raw[index] = pattern;
    }
}

/* Overlay only the 19 typed semantic fields onto a fully poisoned object. */
static void overlay_limits_semantic(
    ninlil_model_runtime_store_limits_t *dst,
    const ninlil_model_runtime_store_limits_t *src)
{
    dst->max_services = src->max_services;
    dst->max_nonterminal_transactions = src->max_nonterminal_transactions;
    dst->max_targets_per_transaction = src->max_targets_per_transaction;
    dst->max_logical_payload_bytes = src->max_logical_payload_bytes;
    dst->max_durable_outbox_payload_bytes =
        src->max_durable_outbox_payload_bytes;
    dst->max_attempts_per_target_per_cycle =
        src->max_attempts_per_target_per_cycle;
    dst->max_cancel_attempts_per_transaction =
        src->max_cancel_attempts_per_transaction;
    dst->max_evidence_per_target = src->max_evidence_per_target;
    dst->max_retained_terminal_transactions =
        src->max_retained_terminal_transactions;
    dst->max_nonterminal_deliveries = src->max_nonterminal_deliveries;
    dst->max_event_spool_count = src->max_event_spool_count;
    dst->max_event_spool_bytes = src->max_event_spool_bytes;
    dst->max_result_cache_entries = src->max_result_cache_entries;
    dst->max_retained_dispositions = src->max_retained_dispositions;
    dst->max_ingress_per_step = src->max_ingress_per_step;
    dst->max_callbacks_per_step = src->max_callbacks_per_step;
    dst->max_state_transitions_per_step = src->max_state_transitions_per_step;
    dst->max_bearer_sends_per_step = src->max_bearer_sends_per_step;
    dst->max_deferred_tokens = src->max_deferred_tokens;
}

static int assert_limits_semantically_identical(
    const ninlil_domain_schema1_binding_t *clean,
    const ninlil_domain_schema1_binding_t *candidate,
    const uint8_t *enc_clean,
    uint32_t len_clean)
{
    uint8_t enc[NINLIL_DOMAIN_SCHEMA1_BINDING_VALUE_BYTES];
    uint32_t len = 0u;

    REQUIRE(ninlil_domain_schema1_validate_binding(candidate) == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_encode_binding(
            candidate, enc, sizeof(enc), &len)
        == NINLIL_OK);
    REQUIRE(len == len_clean);
    REQUIRE(memcmp(enc, enc_clean, len_clean) == 0);
    /* classify compares expected limits field-wise; padding must not matter. */
    REQUIRE(
        ninlil_domain_schema1_classify_binding_open(
            (ninlil_bytes_view_t){enc_clean, len_clean},
            NINLIL_DOMAIN_SCHEMA1_CONSUMER_CANONICAL_DOMAIN,
            2u,
            candidate)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_classify_binding_open(
            (ninlil_bytes_view_t){enc, len},
            NINLIL_DOMAIN_SCHEMA1_CONSUMER_CANONICAL_DOMAIN,
            2u,
            clean)
        == NINLIL_OK);
    return 0;
}

static int test_limits_padding_independent(void)
{
    ninlil_domain_schema1_binding_t clean;
    ninlil_domain_schema1_binding_t poisoned_a;
    ninlil_domain_schema1_binding_t poisoned_b;
    ninlil_domain_schema1_binding_t overlay;
    uint8_t enc_clean[NINLIL_DOMAIN_SCHEMA1_BINDING_VALUE_BYTES];
    uint32_t len_clean = 0u;
    const uint8_t patterns[] = {
        0x00u, 0xFFu, 0xA5u, 0x5Au, 0x11u, 0xEEu, 0xC3u, 0x3Cu, 0x69u, 0x96u
    };
    size_t p;

    fill_controller(&clean);
    REQUIRE(sizeof(clean.common.limits) == 88u);
    REQUIRE(offsetof(ninlil_model_runtime_store_limits_t, max_deferred_tokens)
            + sizeof(uint32_t)
        == (size_t)LIMITS_SEMANTIC_BYTES);
    REQUIRE(sizeof(clean.common.limits) - (size_t)LIMITS_SEMANTIC_BYTES == 4u);
    REQUIRE(ninlil_domain_schema1_validate_binding(&clean) == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_encode_binding(
            &clean, enc_clean, sizeof(enc_clean), &len_clean)
        == NINLIL_OK);

    for (p = 0u; p < sizeof(patterns); ++p) {
        /* Path 1: copy clean then poison only tail padding bytes. */
        poisoned_a = clean;
        poisoned_b = clean;
        poison_limits_all_padding(&poisoned_a.common.limits, patterns[p]);
        poison_limits_all_padding(
            &poisoned_b.common.limits, (uint8_t)(patterns[p] ^ 0xFFu));
        if (assert_limits_semantically_identical(
                &clean, &poisoned_a, enc_clean, len_clean)
            != 0) {
            return 1;
        }
        if (assert_limits_semantically_identical(
                &clean, &poisoned_b, enc_clean, len_clean)
            != 0) {
            return 1;
        }
        /* Path 2: fully poison object bytes, then overlay semantic fields only.
         * Any interior/tail padding retains the poison pattern. */
        (void)memset(&overlay, (int)patterns[p], sizeof(overlay));
        overlay.common = clean.common;
        overlay_limits_semantic(&overlay.common.limits, &clean.common.limits);
        (void)memcpy(
            overlay.storage_profile_id,
            clean.storage_profile_id,
            sizeof(overlay.storage_profile_id));
        overlay.storage_profile_revision = clean.storage_profile_revision;
        overlay.minimum_writer_generation = clean.minimum_writer_generation;
        overlay.rollback_epoch = clean.rollback_epoch;
        poison_limits_all_padding(&overlay.common.limits, patterns[p]);
        if (assert_limits_semantically_identical(
                &clean, &overlay, enc_clean, len_clean)
            != 0) {
            return 1;
        }
        /* Cross-pattern: a vs b (different padding, identical semantics). */
        REQUIRE(
            ninlil_domain_schema1_classify_binding_open(
                (ninlil_bytes_view_t){enc_clean, len_clean},
                NINLIL_DOMAIN_SCHEMA1_CONSUMER_CANONICAL_DOMAIN,
                2u,
                &poisoned_b)
            == NINLIL_OK);
    }
    return 0;
}

static int test_roundtrip_bootstrap(void)
{
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_domain_schema1_bootstrap_plan_t plan;
    ninlil_domain_schema1_bootstrap_record_t stored[17];
    ninlil_domain_schema1_snapshot_row_t rows[17];
    ninlil_domain_schema1_t1a_class_t class;
    uint32_t i;

    fill_controller(&binding);
    fill_identity(&identity);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &plan)
        == NINLIL_OK);
    REQUIRE(plan.encoded_key_value_bytes == 1343u);
    REQUIRE(plan.logical_bytes == 1615u);
    for (i = 0u; i < 17u; ++i) {
        REQUIRE(
            ninlil_domain_schema1_bootstrap_record_at(
                &plan, i, &stored[i])
            == NINLIL_OK);
        rows[i].key.data = stored[i].key.bytes;
        rows[i].key.length = stored[i].key.length;
        rows[i].value.data = stored[i].value;
        rows[i].value.length = stored[i].value_length;
    }
    REQUIRE(
        ninlil_domain_schema1_classify_t1a_commit_unknown(
            &plan, rows, 17u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_T1A_NEW);
    REQUIRE(
        ninlil_domain_schema1_classify_t1a_commit_unknown(
            &plan, NULL, 0u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_T1A_OLD);
    return 0;
}

int main(void)
{
    if (test_profiles_and_invalid_role() != 0) {
        return 1;
    }
    if (test_last_lab_invalid_limits() != 0) {
        return 1;
    }
    if (test_plan_identity_tamper() != 0) {
        return 1;
    }
    if (test_count_overflow_and_t0() != 0) {
        return 1;
    }
    if (test_limits_padding_independent() != 0) {
        return 1;
    }
    if (test_roundtrip_bootstrap() != 0) {
        return 1;
    }
    (void)printf(
        "domain_schema1_runtime_binding OK foundation profiles+t0/t1a+padding\n");
    return 0;
}
