/*
 * ADR-0022 T1b–T7 / kind-1 / LAB quarantine private authority tests.
 * Feature ON only. No runtime_public integration.
 */

#include "domain_schema1_runtime_binding.h"
#include "domain_schema1_startup_authority.h"
#include "domain_store_body_codec.h"
#include "domain_store_codec.h"

#include <ninlil/version.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(cond)                                                       \
    do {                                                                    \
        if (!(cond)) {                                                      \
            (void)fprintf(                                                  \
                stderr,                                                     \
                "domain_schema1_startup FAIL %s:%d: %s\n",                  \
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

static int hex_eq32(const uint8_t digest[32], const char *hex)
{
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        unsigned int hi;
        unsigned int lo;
        char c0 = hex[i * 2u];
        char c1 = hex[i * 2u + 1u];
        hi = (c0 >= 'a') ? (unsigned)(c0 - 'a' + 10) : (unsigned)(c0 - '0');
        lo = (c1 >= 'a') ? (unsigned)(c1 - 'a' + 10) : (unsigned)(c1 - '0');
        if (digest[i] != (uint8_t)((hi << 4) | lo)) {
            return 0;
        }
    }
    return 1;
}

/* Independent snapshot preimage matching T1a bridge rule. */
static int snapshot_sha(
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t count,
    uint8_t out[32])
{
    /* Fixed stack: worst-case 33 rows * ~280 bytes + label. */
    uint8_t preimage[48u + 33u * (2u + 64u + 4u + 256u)];
    size_t offset = 0u;
    uint32_t i;
    static const char label[] = "NINLIL-DOMAIN-INIT-SNAPSHOT-V1";
    ninlil_model_domain_digest_t dig;

    (void)memcpy(preimage + offset, label, sizeof(label) - 1u);
    offset += sizeof(label) - 1u;
    preimage[offset++] = (uint8_t)(count >> 24);
    preimage[offset++] = (uint8_t)(count >> 16);
    preimage[offset++] = (uint8_t)(count >> 8);
    preimage[offset++] = (uint8_t)count;
    for (i = 0u; i < count; ++i) {
        uint32_t klen = rows[i].key.length;
        uint32_t vlen = rows[i].value.length;
        preimage[offset++] = (uint8_t)(klen >> 8);
        preimage[offset++] = (uint8_t)klen;
        (void)memcpy(preimage + offset, rows[i].key.data, klen);
        offset += klen;
        preimage[offset++] = (uint8_t)(vlen >> 24);
        preimage[offset++] = (uint8_t)(vlen >> 16);
        preimage[offset++] = (uint8_t)(vlen >> 8);
        preimage[offset++] = (uint8_t)vlen;
        (void)memcpy(preimage + offset, rows[i].value.data, vlen);
        offset += vlen;
    }
    if (ninlil_model_domain_sha256(preimage, (uint32_t)offset, &dig)
        != NINLIL_OK) {
        return 1;
    }
    (void)memcpy(out, dig.bytes, 32u);
    return 0;
}

static int test_t1b_full_and_classify(void)
{
    ninlil_domain_schema1_binding_t binding;
    ninlil_model_runtime_store_identity_t identity;
    ninlil_domain_schema1_bootstrap_plan_t boot;
    ninlil_domain_schema1_metadata_plan_t meta;
    ninlil_domain_schema1_bootstrap_record_t boot_store[17];
    ninlil_domain_schema1_metadata_record_t meta_store[16];
    ninlil_domain_schema1_snapshot_row_t rows_old[17];
    ninlil_domain_schema1_snapshot_row_t rows_new[33];
    ninlil_domain_schema1_snapshot_row_t rows_partial[18];
    ninlil_domain_schema1_group_class_t class;
    uint8_t digest[32];
    uint32_t i;
    static const char *const k_t1b_old =
        "0c16fbcea20fef5ca26b9d3fd9e36ec858693a5c8d9a296da816a48bf5b01ce1";
    static const char *const k_t1b_new =
        "f38f6e108a9e6b3b672b180ad8c03c1e1ad978995fc7fb99fb53b9a9c3638cf0";

    fill_controller(&binding);
    fill_identity(&identity);
    REQUIRE(
        ninlil_domain_schema1_build_bootstrap_plan(
            &binding, &identity, &boot)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_build_metadata_plan(&boot, &meta) == NINLIL_OK);
    REQUIRE(meta.record_count == 16u);

    for (i = 0u; i < 17u; ++i) {
        REQUIRE(
            ninlil_domain_schema1_bootstrap_record_at(&boot, i, &boot_store[i])
            == NINLIL_OK);
        rows_old[i].key.data = boot_store[i].key.bytes;
        rows_old[i].key.length = boot_store[i].key.length;
        rows_old[i].value.data = boot_store[i].value;
        rows_old[i].value.length = boot_store[i].value_length;
        rows_new[i] = rows_old[i];
    }
    for (i = 0u; i < 16u; ++i) {
        REQUIRE(
            ninlil_domain_schema1_metadata_record_at(&meta, i, &meta_store[i])
            == NINLIL_OK);
        rows_new[17u + i].key.data = meta_store[i].key;
        rows_new[17u + i].key.length = meta_store[i].key_length;
        rows_new[17u + i].value.data = meta_store[i].value;
        rows_new[17u + i].value.length = meta_store[i].value_length;
    }
    /* Clock must be first in unsigned order among metadata. */
    REQUIRE(meta_store[0].key_length == 13u);
    REQUIRE(meta_store[0].key[9] == 0x62u);

    REQUIRE(snapshot_sha(rows_old, 17u, digest) == 0);
    REQUIRE(hex_eq32(digest, k_t1b_old));
    REQUIRE(snapshot_sha(rows_new, 33u, digest) == 0);
    REQUIRE(hex_eq32(digest, k_t1b_new));

    REQUIRE(
        ninlil_domain_schema1_classify_t1b_commit_unknown(
            &boot, &meta, rows_old, 17u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_OLD);

    REQUIRE(
        ninlil_domain_schema1_classify_t1b_commit_unknown(
            &boot, &meta, rows_new, 33u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_NEW);

    /* Partial 1-of-16 metadata => CORRUPT. */
    for (i = 0u; i < 17u; ++i) {
        rows_partial[i] = rows_old[i];
    }
    rows_partial[17] = rows_new[17];
    REQUIRE(
        ninlil_domain_schema1_classify_t1b_commit_unknown(
            &boot, &meta, rows_partial, 18u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT);

    /* Extra row => CORRUPT. */
    {
        ninlil_domain_schema1_snapshot_row_t extra[34];
        static const uint8_t ek[] = {0xDEu, 0xADu};
        static const uint8_t ev[] = {0x00u};
        for (i = 0u; i < 33u; ++i) {
            extra[i] = rows_new[i];
        }
        extra[33].key.data = ek;
        extra[33].key.length = 2u;
        extra[33].value.data = ev;
        extra[33].value.length = 1u;
        REQUIRE(
            ninlil_domain_schema1_classify_t1b_commit_unknown(
                &boot, &meta, extra, 34u, &class)
            == NINLIL_OK);
        REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT);
    }

    /* TRUSTED clock mix (replace uninit clock with trusted) => CORRUPT. */
    {
        ninlil_domain_schema1_t5_clock_plan_t t5;
        uint8_t epoch[16];
        ninlil_domain_schema1_snapshot_row_t mix[33];
        (void)memset(epoch, 0x33, sizeof(epoch));
        REQUIRE(
            ninlil_domain_schema1_build_t5_clock_plan(epoch, 123456u, 1u, &t5)
            == NINLIL_OK);
        for (i = 0u; i < 33u; ++i) {
            mix[i] = rows_new[i];
        }
        /* Replace clock value with TRUSTED. */
        for (i = 0u; i < 33u; ++i) {
            if (mix[i].key.length == t5.clock_key_length
                && memcmp(mix[i].key.data, t5.clock_key, t5.clock_key_length)
                    == 0) {
                mix[i].value.data = t5.new_value;
                mix[i].value.length = t5.new_value_length;
            }
        }
        REQUIRE(
            ninlil_domain_schema1_classify_t1b_commit_unknown(
                &boot, &meta, mix, 33u, &class)
            == NINLIL_OK);
        REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT);
    }
    return 0;
}

static int test_t5_and_startup_stages(void)
{
    ninlil_domain_schema1_t5_clock_plan_t t5;
    ninlil_model_domain_typed_record_t typed;
    ninlil_domain_schema1_startup_state_t st;
    ninlil_domain_schema1_startup_transcript_t tr;
    ninlil_domain_schema1_snapshot_row_t row;
    ninlil_domain_schema1_group_class_t class;
    uint8_t epoch[16];
    uint32_t s;

    (void)memset(epoch, 0x33, sizeof(epoch));
    REQUIRE(
        ninlil_domain_schema1_build_t5_clock_plan(epoch, 123456u, 1u, &t5)
        == NINLIL_OK);

    /* A later trusted epoch increments both generation and record revision. */
    REQUIRE(
        ninlil_domain_schema1_build_t5_clock_plan(epoch, 223456u, 2u, &t5)
        == NINLIL_OK);
    REQUIRE(
        ninlil_model_domain_validate_typed_record(
            (ninlil_bytes_view_t){t5.clock_key, t5.clock_key_length},
            (ninlil_bytes_view_t){t5.new_value, t5.new_value_length},
            &typed)
        == NINLIL_OK);
    REQUIRE(
        typed.clock_baseline.baseline_state
        == NINLIL_MODEL_DOMAIN_BASELINE_STATE_TRUSTED);
    REQUIRE(typed.clock_baseline.publish_generation == 2u);
    REQUIRE(typed.envelope.header.record_revision == 3u);
    REQUIRE(
        ninlil_domain_schema1_build_t5_clock_plan(
            epoch, 223456u, UINT64_MAX, &t5)
        == NINLIL_E_INVALID_ARGUMENT);

    /* Continue the OLD/NEW CU matrix with the first generation plan. */
    REQUIRE(
        ninlil_domain_schema1_build_t5_clock_plan(epoch, 123456u, 1u, &t5)
        == NINLIL_OK);

    row.key.data = t5.clock_key;
    row.key.length = t5.clock_key_length;
    row.value.data = t5.old_value;
    row.value.length = t5.old_value_length;
    REQUIRE(
        ninlil_domain_schema1_classify_t5_commit_unknown(
            &t5, &row, 1u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_OLD);

    row.value.data = t5.new_value;
    row.value.length = t5.new_value_length;
    REQUIRE(
        ninlil_domain_schema1_classify_t5_commit_unknown(
            &t5, &row, 1u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_NEW);

    /* Missing clock. */
    REQUIRE(
        ninlil_domain_schema1_classify_t5_commit_unknown(
            &t5, NULL, 0u, &class)
        == NINLIL_OK);
    REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT);

    /* Third sample. */
    {
        uint8_t third[256];
        REQUIRE(t5.new_value_length <= sizeof(third));
        (void)memcpy(third, t5.new_value, t5.new_value_length);
        third[t5.new_value_length - 1u] ^= 1u;
        row.value.data = third;
        row.value.length = t5.new_value_length;
        REQUIRE(
            ninlil_domain_schema1_classify_t5_commit_unknown(
                &t5, &row, 1u, &class)
            == NINLIL_OK);
        REQUIRE(class == NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT);
    }

    REQUIRE(ninlil_domain_schema1_startup_init(&st) == NINLIL_OK);
    REQUIRE(ninlil_domain_schema1_startup_pre_publish_side_effects_zero(&st));
    REQUIRE(!ninlil_domain_schema1_startup_publication_allowed(&st));

    /* Out-of-order T1b before T0 fences. */
    REQUIRE(
        ninlil_domain_schema1_startup_complete_stage(
            &st, NINLIL_DOMAIN_SCHEMA1_STAGE_T1B)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(st.fenced == 1u);
    REQUIRE(st.bearer_open == 0u);
    REQUIRE(st.public_handle == 0u);

    REQUIRE(ninlil_domain_schema1_startup_init(&st) == NINLIL_OK);
    for (s = 0u; s <= (uint32_t)NINLIL_DOMAIN_SCHEMA1_STAGE_T6; ++s) {
        REQUIRE(
            ninlil_domain_schema1_startup_complete_stage(
                &st, (ninlil_domain_schema1_startup_stage_t)s)
            == NINLIL_OK);
        REQUIRE(
            ninlil_domain_schema1_startup_pre_publish_side_effects_zero(&st));
        REQUIRE(st.callback == 0u);
        REQUIRE(st.public_handle == 0u);
        REQUIRE(st.publish == 0u);
    }
    REQUIRE(st.bearer_open == 0u);
    REQUIRE(
        ninlil_domain_schema1_startup_complete_stage(
            &st, NINLIL_DOMAIN_SCHEMA1_STAGE_BEARER_OPEN)
        == NINLIL_OK);
    REQUIRE(st.bearer_open == 1u);
    REQUIRE(st.public_handle == 0u);
    REQUIRE(
        ninlil_domain_schema1_startup_complete_stage(
            &st, NINLIL_DOMAIN_SCHEMA1_STAGE_METRICS_ENTROPY)
        == NINLIL_OK);
    REQUIRE(
        ninlil_domain_schema1_startup_complete_stage(
            &st, NINLIL_DOMAIN_SCHEMA1_STAGE_T7)
        == NINLIL_OK);
    REQUIRE(!ninlil_domain_schema1_startup_publication_allowed(&st));
    REQUIRE(
        ninlil_domain_schema1_startup_complete_stage(
            &st, NINLIL_DOMAIN_SCHEMA1_STAGE_PUBLISH)
        == NINLIL_OK);
    REQUIRE(ninlil_domain_schema1_startup_publication_allowed(&st));
    REQUIRE(st.callback == 0u);

    REQUIRE(
        ninlil_domain_schema1_startup_export_transcript(&st, &tr) == NINLIL_OK);
    REQUIRE(tr.T0_complete == 1u && tr.T1b_complete == 1u && tr.T7_complete == 1u);
    REQUIRE(tr.publish == 1u && tr.callback == 0u);
    REQUIRE(tr.storage_recovery_complete == 1u);

    /* Every fallible storage-recovery stage fences before publication. */
    for (s = (uint32_t)NINLIL_DOMAIN_SCHEMA1_STAGE_T0;
         s <= (uint32_t)NINLIL_DOMAIN_SCHEMA1_STAGE_T6;
         ++s) {
        uint32_t completed;
        REQUIRE(ninlil_domain_schema1_startup_init(&st) == NINLIL_OK);
        for (completed = (uint32_t)NINLIL_DOMAIN_SCHEMA1_STAGE_T0;
             completed < s;
             ++completed) {
            REQUIRE(
                ninlil_domain_schema1_startup_complete_stage(
                    &st,
                    (ninlil_domain_schema1_startup_stage_t)completed)
                == NINLIL_OK);
        }
        REQUIRE(
            ninlil_domain_schema1_startup_fault(
                &st,
                (ninlil_domain_schema1_startup_stage_t)s,
                NINLIL_E_STORAGE_CORRUPT)
            == NINLIL_OK);
        REQUIRE(st.fenced == 1u);
        REQUIRE(st.bearer_open == 0u);
        REQUIRE(st.public_handle == 0u);
        REQUIRE(st.publish == 0u);
        REQUIRE(st.callback == 0u);
        REQUIRE(!ninlil_domain_schema1_startup_publication_allowed(&st));
    }
    return 0;
}

static int test_kind1_and_lab(void)
{
    ninlil_domain_schema1_kind1_plan_t plan;
    ninlil_domain_schema1_kind1_member_t m;
    ninlil_domain_schema1_lab_namespace_class_t ns;
    uint8_t dig[32];
    static const uint8_t k_cap[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u, 0x04u, 0x01u
    };
    static const uint8_t k_svc[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u, 0x06u, 0x10u
    };
    static const uint8_t k_quota[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u, 0x06u, 0x11u
    };
    static const uint8_t k_res[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u, 0x06u, 0x23u
    };
    static const uint8_t k_head[] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u, 0x06u, 0x7du
    };
    (void)memset(dig, 0xABu, sizeof(dig));

    REQUIRE(
        ninlil_domain_schema1_kind1_build_plan(
            k_cap,
            (uint32_t)sizeof(k_cap),
            dig,
            k_svc,
            (uint32_t)sizeof(k_svc),
            dig,
            k_quota,
            (uint32_t)sizeof(k_quota),
            dig,
            k_res,
            (uint32_t)sizeof(k_res),
            dig,
            k_head,
            (uint32_t)sizeof(k_head),
            dig,
            dig,
            &plan)
        == NINLIL_OK);
    REQUIRE(plan.member_count == 5u);
    REQUIRE(
        ninlil_domain_schema1_kind1_member_at(&plan, 0u, &m) == NINLIL_OK);
    /* Sorted by key: capacity 04 before domain 06. */
    REQUIRE(m.key[8] == 0x04u);
    REQUIRE(m.action == NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE);

    /* LAB quarantine: format2 + bootstrap => EXACT_DOMAIN. */
    REQUIRE(
        ninlil_domain_schema1_lab_classify_namespace(
            2u, 1u, 1u, 0u, 0u, 0u, 0u, &ns)
        == NINLIL_OK);
    REQUIRE(ns == NINLIL_DOMAIN_SCHEMA1_LAB_NS_EXACT_DOMAIN);

    /* format2 + lab-distinct => MIXED. */
    REQUIRE(
        ninlil_domain_schema1_lab_classify_namespace(
            2u, 1u, 1u, 0u, 1u, 0u, 0u, &ns)
        == NINLIL_OK);
    REQUIRE(ns == NINLIL_DOMAIN_SCHEMA1_LAB_NS_MIXED);

    /* format1 bootstrap exact => EXACT_LAB. */
    REQUIRE(
        ninlil_domain_schema1_lab_classify_namespace(
            1u, 1u, 0u, 0u, 0u, 0u, 0u, &ns)
        == NINLIL_OK);
    REQUIRE(ns == NINLIL_DOMAIN_SCHEMA1_LAB_NS_EXACT_LAB);

    /* duplicate key => CORRUPT. */
    REQUIRE(
        ninlil_domain_schema1_lab_classify_namespace(
            1u, 1u, 1u, 0u, 0u, 0u, 1u, &ns)
        == NINLIL_OK);
    REQUIRE(ns == NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT);

    /* partial metadata => CORRUPT. */
    REQUIRE(
        ninlil_domain_schema1_lab_classify_namespace(
            1u, 1u, 0u, 1u, 0u, 0u, 0u, &ns)
        == NINLIL_OK);
    REQUIRE(ns == NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT);

    {
        static const uint8_t magic[8] = {
            'N', 'L', 'E', 'X', 'P', '0', '0', '1'
        };
        REQUIRE(ninlil_domain_schema1_export_magic_match(magic, 8u));
        REQUIRE(!ninlil_domain_schema1_export_magic_match(magic, 7u));
    }
    return 0;
}

/*
 * Kind-1 CU classes with synthetic family-4 keys (D1 key-shape only) and
 * sealed 7-record post inventory: ABSENT/OLD/NEW/PARTIAL/THIRD/EXTRA.
 */
static int seal_synthetic_kind1_plan(
    ninlil_domain_schema1_kind1_plan_t *plan,
    uint8_t keys[7][10],
    uint8_t pre_vals[7][8],
    uint8_t post_vals[7][8],
    uint8_t op_id[32])
{
    uint8_t dig[32];
    ninlil_model_domain_digest_t d;
    uint32_t i;
    ninlil_status_t st;

    (void)memset(dig, 0xABu, sizeof(dig));
    for (i = 0u; i < 7u; ++i) {
        keys[i][0] = 0x4eu;
        keys[i][1] = 0x49u;
        keys[i][2] = 0x4eu;
        keys[i][3] = 0x4cu;
        keys[i][4] = 0x49u;
        keys[i][5] = 0x4cu;
        keys[i][6] = 0x00u;
        keys[i][7] = 0x01u;
        keys[i][8] = 0x04u;
        keys[i][9] = (uint8_t)(0x10u + i);
        (void)memset(pre_vals[i], (int)(0x30u + i), 8);
        (void)memset(post_vals[i], (int)(0x90u + i), 8);
    }
    (void)memset(op_id, 0x11u, 32u);
    st = ninlil_domain_schema1_kind1_build_plan(
        keys[0],
        10u,
        dig,
        keys[1],
        10u,
        dig,
        keys[2],
        10u,
        dig,
        keys[3],
        10u,
        dig,
        keys[4],
        10u,
        dig,
        op_id,
        plan);
    if (st != NINLIL_OK) {
        return 1;
    }
    plan->post_record_count = 7u;
    for (i = 0u; i < 7u; ++i) {
        ninlil_domain_schema1_kind1_post_record_t *pr = &plan->post_records[i];
        (void)memset(pr, 0, sizeof(*pr));
        if (i == 0u || i == 4u) {
            pr->action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE;
        } else {
            pr->action = NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE;
        }
        (void)memcpy(pr->key, keys[i], 10u);
        pr->key_length = 10u;
        if (pr->action == NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE) {
            REQUIRE(
                ninlil_model_domain_sha256(pre_vals[i], 8u, &d) == NINLIL_OK);
            (void)memcpy(pr->pre_value_digest, d.bytes, 32u);
        }
        REQUIRE(ninlil_model_domain_sha256(post_vals[i], 8u, &d) == NINLIL_OK);
        (void)memcpy(pr->post_value_digest, d.bytes, 32u);
    }
    REQUIRE(ninlil_domain_schema1_kind1_plan_finish(plan) == NINLIL_OK);
    return 0;
}

static int test_kind1_cu_class_matrix(void)
{
    ninlil_domain_schema1_kind1_plan_t plan;
    uint8_t keys[7][10];
    uint8_t pre_vals[7][8];
    uint8_t post_vals[7][8];
    uint8_t op_id[32];
    ninlil_domain_schema1_snapshot_row_t pre[7];
    ninlil_domain_schema1_snapshot_row_t post[8];
    ninlil_domain_schema1_group_class_t cls;
    uint32_t i;
    uint8_t extra_key[10];
    uint8_t extra_val[8];

    REQUIRE(
        seal_synthetic_kind1_plan(&plan, keys, pre_vals, post_vals, op_id)
        == 0);
    for (i = 0u; i < 7u; ++i) {
        pre[i].key.data = keys[i];
        pre[i].key.length = 10u;
        pre[i].value.data = pre_vals[i];
        pre[i].value.length = 8u;
        post[i].key.data = keys[i];
        post[i].key.length = 10u;
        post[i].value.data = post_vals[i];
        post[i].value.length = 8u;
    }

    /* ABSENT: empty post namespace. */
    REQUIRE(
        ninlil_domain_schema1_classify_kind1_commit_unknown(
            &plan, pre, 7u, NULL, 0u, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_DOMAIN_SCHEMA1_GROUP_ABSENT);

    /* OLD: REPLACE pre exact, CREATE/header/chunk absent. */
    {
        ninlil_domain_schema1_snapshot_row_t old_rows[2];
        old_rows[0] = pre[0];
        old_rows[1] = pre[4];
        REQUIRE(
            ninlil_domain_schema1_classify_kind1_commit_unknown(
                &plan, pre, 7u, old_rows, 2u, &cls)
            == NINLIL_OK);
        REQUIRE(cls == NINLIL_DOMAIN_SCHEMA1_GROUP_OLD);
    }

    /* NEW: all 7 post exact, no extra. */
    REQUIRE(
        ninlil_domain_schema1_classify_kind1_commit_unknown(
            &plan, pre, 7u, post, 7u, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_DOMAIN_SCHEMA1_GROUP_NEW);

    /* PARTIAL: only first post present as NEW. */
    REQUIRE(
        ninlil_domain_schema1_classify_kind1_commit_unknown(
            &plan, pre, 7u, post, 1u, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_DOMAIN_SCHEMA1_GROUP_PARTIAL);

    /* THIRD: capacity key present with neither pre nor post value. */
    {
        uint8_t third_val[8];
        ninlil_domain_schema1_snapshot_row_t third_rows[7];
        (void)memset(third_val, 0xEE, sizeof(third_val));
        for (i = 0u; i < 7u; ++i) {
            third_rows[i] = post[i];
        }
        third_rows[0].value.data = third_val;
        REQUIRE(
            ninlil_domain_schema1_classify_kind1_commit_unknown(
                &plan, pre, 7u, third_rows, 7u, &cls)
            == NINLIL_OK);
        REQUIRE(cls == NINLIL_DOMAIN_SCHEMA1_GROUP_THIRD);
    }

    /* EXTRA: all 7 NEW plus foreign key not in pre. */
    (void)memcpy(extra_key, keys[0], 10u);
    extra_key[9] = 0x7fu;
    (void)memset(extra_val, 0x55, sizeof(extra_val));
    for (i = 0u; i < 7u; ++i) {
        post[i].value.data = post_vals[i];
    }
    post[7].key.data = extra_key;
    post[7].key.length = 10u;
    post[7].value.data = extra_val;
    post[7].value.length = 8u;
    REQUIRE(
        ninlil_domain_schema1_classify_kind1_commit_unknown(
            &plan, pre, 7u, post, 8u, &cls)
        == NINLIL_OK);
    REQUIRE(cls == NINLIL_DOMAIN_SCHEMA1_GROUP_EXTRA);

    return 0;
}

int main(void)
{
    if (test_t1b_full_and_classify() != 0) {
        return 1;
    }
    if (test_t5_and_startup_stages() != 0) {
        return 1;
    }
    if (test_kind1_and_lab() != 0) {
        return 1;
    }
    if (test_kind1_cu_class_matrix() != 0) {
        return 1;
    }
    (void)printf(
        "domain_schema1_startup_authority OK "
        "t1b/t5/stages/kind1/lab/cu-classes\n");
    return 0;
}
