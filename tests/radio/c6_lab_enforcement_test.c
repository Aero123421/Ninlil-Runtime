/*
 * V1-LAB item 10a: C6-LAB enforcement tests.
 * ASan/UBSan build. Does not claim production certification / RF / HIL.
 */

#include "c6_lab_enforcement.h"
#include "c6_lab_spi_tx_sim.h"
#include "profile_loader.h"
#include "profile_r5_golden_profiles.h"
#include "v1_frame_manifest.h"

#include "deterministic_entropy.h"
#include "in_memory_storage.h"
#include "platform_basic_fixtures.h"

#include <stdio.h>
#include <string.h>

#define T_FRAME_LEN ((uint32_t)20u)
#define T_CHANNEL ((uint32_t)2u)
#define T_CEILING ((uint32_t)2000000u)
#define T_TERM ((uint64_t)11u)
#define T_GEN ((uint64_t)3u)
#define T_EPOCH ((uint64_t)9u)
#define T_SITE_REV ((uint32_t)4u)

#define REQUIRE(c)                                                             \
    do {                                                                       \
        if (!(c)) {                                                            \
            (void)fprintf(                                                     \
                stderr, "REQUIRE fail %s:%d: %s\n", __FILE__, __LINE__, #c);   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

typedef struct env {
    ninlil_r5_object_t r5obj;
    ninlil_r5_t *r5;
    ninlil_pcp_object_t pcpobj;
    ninlil_pcp_t *pcp;
    ninlil_c6_lab_object_t c6obj;
    ninlil_c6_lab_t *c6;
    ninlil_test_storage_t *storage;
    ninlil_test_clock_t *clock;
    ninlil_test_entropy_t *entropy;
    ninlil_r5_error_t err;
    ninlil_pcp_error_t pcp_err;
    ninlil_c6_lab_error_t c6_err;
    uint8_t hw_doc[NINLIL_R5_HW_DOC_BYTES];
    uint8_t reg_doc[NINLIL_R5_REG_DOC_BYTES];
    uint8_t frame[T_FRAME_LEN];
    uint8_t frame_digest[32];
} env_t;

static void fill_id(ninlil_radio_hal_id_t *id, uint8_t tag)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        id->bytes[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void fill_digest(uint8_t *d, uint8_t tag)
{
    size_t i;
    for (i = 0u; i < 32u; ++i) {
        d[i] = (uint8_t)(tag + (uint8_t)i);
    }
}

static void digest_fold_local(
    const uint8_t *bytes,
    uint32_t length,
    uint8_t out_digest[32])
{
    uint32_t i;
    (void)memset(out_digest, 0, 32u);
    for (i = 0u; i < length; ++i) {
        out_digest[i % 32u] ^= bytes[i];
    }
    out_digest[0] ^= (uint8_t)(length & 0xFFu);
    out_digest[1] ^= (uint8_t)((length >> 8) & 0xFFu);
}

static void make_assign(ninlil_r5_site_assignment_t *a)
{
    (void)memset(a, 0, sizeof(*a));
    fill_id(&a->site_assignment_id, 0x30u);
    a->site_assignment_rev = T_SITE_REV;
    a->site_assignment_epoch = T_EPOCH;
    a->controller_term = T_TERM;
    fill_digest(a->assignment_digest, 0x50u);
    a->permit_bind_generation = T_GEN;
    fill_id(&a->transmitter_id, 0x40u);
    a->channel_id = T_CHANNEL;
    a->phy.bandwidth_hz = 125000u;
    a->phy.spreading_factor = 7u;
    a->phy.coding_rate_denom = 5u;
    a->phy.preamble_symbols = 8u;
    a->phy.tx_power_mdb = 10000;
    a->phy.phy_flags = 0u;
}

static void make_frame(env_t *e)
{
    size_t i;
    for (i = 0u; i < T_FRAME_LEN; ++i) {
        e->frame[i] = (uint8_t)(0xA0u + i);
    }
    digest_fold_local(e->frame, T_FRAME_LEN, e->frame_digest);
}

static void fill_issue_plan(env_t *e, ninlil_r5_issue_plan_t *plan)
{
    (void)memset(plan, 0, sizeof(*plan));
    plan->frame_bytes = e->frame;
    plan->frame_byte_length = T_FRAME_LEN;
    (void)memcpy(plan->frame_digest, e->frame_digest, 32u);
    plan->frame_digest_algorithm = 1u;
    plan->airtime_in.sf = 7u;
    plan->airtime_in.cr = 1u;
    plan->airtime_in.header_implicit = 0u;
    plan->airtime_in.crc_on = 1u;
    plan->airtime_in.ldro = NINLIL_AIRTIME_LDRO_OFF;
    plan->airtime_in.payload_len_bytes = (uint8_t)T_FRAME_LEN;
    plan->airtime_in.preamble_len_symbols = 8u;
    plan->airtime_in.bw_hz = 125000u;
    plan->airtime_in.reserved_zero = 0u;
    plan->not_before_ms = 0u;
    plan->expiry_ms = 600000u;
}

static int env_setup(env_t *e)
{
    ninlil_test_storage_config_t cfg;
    ninlil_pcp_live_profile_t live;
    ninlil_pcp_instance_seed_t seed;
    ninlil_radio_hal_live_binding_t r5live;
    ninlil_r5_site_assignment_t assign;
    size_t i;

    (void)memset(e, 0, sizeof(*e));
    make_frame(e);
    (void)memcpy(e->hw_doc, k_r5_golden_hw_v1, NINLIL_R5_HW_DOC_BYTES);
    (void)memcpy(e->reg_doc, k_r5_golden_reg_v1, NINLIL_R5_REG_DOC_BYTES);
    make_assign(&assign);

    e->r5obj = (ninlil_r5_object_t)NINLIL_R5_OBJECT_INIT;
    REQUIRE(ninlil_r5_init_object(&e->r5obj, &e->r5) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_hardware_profile(
            e->r5, e->hw_doc, NINLIL_R5_HW_DOC_BYTES, &e->err)
        == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_regulatory_profile(
            e->r5, e->reg_doc, NINLIL_R5_REG_DOC_BYTES, &e->err)
        == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_activate_profiles(e->r5, &e->err) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_bind_site_assignment(e->r5, &assign, &e->err) == NINLIL_R5_OK);

    e->pcpobj = (ninlil_pcp_object_t)NINLIL_PCP_OBJECT_INIT;
    REQUIRE(ninlil_pcp_init_object(&e->pcpobj, &e->pcp) == NINLIL_PCP_OK);
    (void)memset(&cfg, 0, sizeof(cfg));
    cfg.max_namespaces = 4u;
    cfg.max_entries_per_namespace = 64u;
    cfg.max_bytes_per_namespace = 65536u;
    e->storage = ninlil_test_storage_create(&cfg);
    e->clock = ninlil_test_clock_create();
    e->entropy = ninlil_test_entropy_create(0xC60A6u, 1u);
    REQUIRE(e->storage != NULL && e->clock != NULL && e->entropy != NULL);
    REQUIRE(
        ninlil_pcp_bind_storage(
            e->pcp, ninlil_test_storage_ops(e->storage), &e->pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(
        ninlil_pcp_bind_clock(e->pcp, ninlil_test_clock_ops(e->clock), &e->pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(
        ninlil_pcp_bind_entropy(
            e->pcp, ninlil_test_entropy_ops(e->entropy), &e->pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(
        ninlil_r5_build_live_binding(e->r5, &r5live, &e->err) == NINLIL_R5_OK);
    live = r5live;
    REQUIRE(
        ninlil_pcp_bind_live_profile(e->pcp, &live, &e->pcp_err) == NINLIL_PCP_OK);
    for (i = 0u; i < 16u; ++i) {
        seed.bytes[i] = (uint8_t)(0x60u + i);
    }
    REQUIRE(
        ninlil_pcp_publish_initial_meta(e->pcp, &seed, &e->pcp_err)
        == NINLIL_PCP_OK);
    REQUIRE(ninlil_r5_bind_pcp(e->r5, e->pcp, &e->err) == NINLIL_R5_OK);

    e->c6obj = (ninlil_c6_lab_object_t)NINLIL_C6_LAB_OBJECT_INIT;
    REQUIRE(
        ninlil_c6_lab_init_object(&e->c6obj, e->r5, &e->c6, &e->c6_err)
        == NINLIL_C6_LAB_OK);
    return 0;
}

static void env_teardown(env_t *e)
{
    if (e->c6 != NULL) {
        (void)ninlil_c6_lab_shutdown(e->c6, &e->c6_err);
    }
    if (e->r5 != NULL) {
        (void)ninlil_r5_shutdown(e->r5, &e->err);
    }
    if (e->pcp != NULL) {
        (void)ninlil_pcp_shutdown(e->pcp, &e->pcp_err);
    }
    if (e->storage != NULL) {
        ninlil_test_storage_destroy(e->storage);
    }
    if (e->clock != NULL) {
        ninlil_test_clock_destroy(e->clock);
    }
    if (e->entropy != NULL) {
        ninlil_test_entropy_destroy(e->entropy);
    }
}

static int test_manifest_exact_set(void)
{
    uint32_t count = 0u;
    const ninlil_v1_frame_manifest_entry_t *table;
    uint32_t i;

    table = ninlil_v1_frame_manifest_table(&count);
    REQUIRE(count == NINLIL_V1_FRAME_MANIFEST_COUNT);
    REQUIRE(table != NULL);
    for (i = 0u; i < count; ++i) {
        REQUIRE(ninlil_v1_frame_type_is_transmittable(table[i].type));
        REQUIRE(table[i].owner != NULL);
        REQUIRE(table[i].purpose != NULL);
    }
    REQUIRE(!ninlil_v1_frame_type_is_transmittable(NINLIL_V1_FRAME_NONE));
    REQUIRE(!ninlil_v1_frame_type_is_transmittable(99u));
    return 0;
}

static int test_happy_transmit_all_manifest_types(void)
{
    env_t e;
    ninlil_r5_issue_plan_t plan;
    ninlil_c6_lab_stats_t stats;
    uint32_t count = 0u;
    const ninlil_v1_frame_manifest_entry_t *table;
    uint32_t i;

    REQUIRE(env_setup(&e) == 0);
    table = ninlil_v1_frame_manifest_table(&count);
    for (i = 0u; i < count; ++i) {
        fill_issue_plan(&e, &plan);
        REQUIRE(
            ninlil_c6_lab_transmit(
                e.c6, table[i].type, &plan, &e.c6_err)
            == NINLIL_C6_LAB_OK);
    }
    ninlil_c6_lab_stats(e.c6, &stats);
    REQUIRE(stats.transmit_ok == count);
    REQUIRE(stats.spi_tx_count == count);
    env_teardown(&e);
    return 0;
}

static void fix_reg_crc(uint8_t reg_doc[NINLIL_R5_REG_DOC_BYTES])
{
    uint32_t crc = 0xffffffffu;
    size_t j;
    unsigned b;

    for (j = 0u; j < 156u; ++j) {
        crc ^= (uint32_t)reg_doc[j];
        for (b = 0u; b < 8u; ++b) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xedb88320u & mask);
        }
    }
    reg_doc[156] = (uint8_t)(crc & 0xffu);
    reg_doc[157] = (uint8_t)((crc >> 8) & 0xffu);
    reg_doc[158] = (uint8_t)((crc >> 16) & 0xffu);
    reg_doc[159] = (uint8_t)((crc >> 24) & 0xffu);
}

static int test_out_of_scope_profile_spi_tx_zero(void)
{
    env_t e;
    ninlil_r5_object_t r5obj = NINLIL_R5_OBJECT_INIT;
    ninlil_r5_t *r5 = NULL;
    ninlil_r5_issue_plan_t plan;
    ninlil_c6_lab_stats_t stats;
    ninlil_r5_regulatory_profile_t reg;
    uint8_t reg_doc[NINLIL_R5_REG_DOC_BYTES];

    (void)memcpy(reg_doc, k_r5_golden_reg_v1, sizeof(reg_doc));
    reg_doc[6] = 3u; /* DEPLOYMENT_APPROVED */
    fix_reg_crc(reg_doc);
    REQUIRE(ninlil_r5_init_object(&r5obj, &r5) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_hardware_profile(
            r5, k_r5_golden_hw_v1, NINLIL_R5_HW_DOC_BYTES, &e.err)
        == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_regulatory_profile(
            r5, reg_doc, NINLIL_R5_REG_DOC_BYTES, &e.err)
        == NINLIL_R5_PROFILE_DENIED);
    (void)ninlil_r5_shutdown(r5, &e.err);

    REQUIRE(env_setup(&e) == 0);
    (void)ninlil_c6_lab_shutdown(e.c6, &e.c6_err);
    (void)ninlil_r5_shutdown(e.r5, &e.err);
    (void)memset(&reg, 0, sizeof(reg));
    fill_id(&reg.profile_id, 0x20u);
    reg.profile_rev = 1u;
    reg.approval_state = NINLIL_R5_APPROVAL_LAB_ONLY;
    fill_id(&reg.applicable_hardware_profile_id, 0x10u);
    reg.applicable_hw_rev_min = 1u;
    reg.applicable_hw_rev_max = 1u;
    reg.channel_id_min = 1u;
    reg.channel_id_max = 3u;
    reg.max_airtime_ceiling_us = T_CEILING;
    reg.airtime_formula_version = NINLIL_AIRTIME_FORMULA_VERSION;
    reg.bw_hz = 125000u;
    reg.sf_min = 7u;
    reg.sf_max = 9u;
    reg.cr_denom_min = 5u;
    reg.cr_denom_max = 8u;
    reg.preamble_symbols_min = 8u;
    reg.preamble_symbols_max = 16u;
    reg.tx_power_mdb_min = 0;
    reg.tx_power_mdb_max = 14000;
    reg.effective_not_before_ms = 0u;
    reg.profile_expiry_ms = 5000u;
    reg.region_code = 0x4c4142u;
    reg.service_category = 1u;
    REQUIRE(ninlil_r5_encode_regulatory_profile(&reg, reg_doc) == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_init_object(&e.r5obj, &e.r5) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_hardware_profile(
            e.r5, e.hw_doc, NINLIL_R5_HW_DOC_BYTES, &e.err) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_r5_load_regulatory_profile(
            e.r5, reg_doc, NINLIL_R5_REG_DOC_BYTES, &e.err) == NINLIL_R5_OK);
    REQUIRE(ninlil_r5_activate_profiles(e.r5, &e.err) == NINLIL_R5_OK);
    {
        ninlil_r5_site_assignment_t assign;
        ninlil_pcp_live_profile_t live;
        ninlil_radio_hal_live_binding_t r5live;
        make_assign(&assign);
        REQUIRE(ninlil_r5_bind_site_assignment(e.r5, &assign, &e.err) == NINLIL_R5_OK);
        REQUIRE(
            ninlil_r5_build_live_binding(e.r5, &r5live, &e.err) == NINLIL_R5_OK);
        live = r5live;
        REQUIRE(
            ninlil_pcp_bind_live_profile(e.pcp, &live, &e.pcp_err) == NINLIL_PCP_OK);
    }
    REQUIRE(ninlil_r5_bind_pcp(e.r5, e.pcp, &e.err) == NINLIL_R5_OK);
    REQUIRE(
        ninlil_c6_lab_init_object(&e.c6obj, e.r5, &e.c6, &e.c6_err)
        == NINLIL_C6_LAB_OK);
    REQUIRE(ninlil_test_clock_advance(e.clock, 6000u) != 0);
    fill_issue_plan(&e, &plan);
    plan.not_before_ms = 0u;
    plan.expiry_ms = 7000u;
    REQUIRE(
        ninlil_c6_lab_transmit(
            e.c6, NINLIL_V1_FRAME_R7_HOP_DATA, &plan, &e.c6_err)
        == NINLIL_C6_LAB_PROFILE_DENIED);
    ninlil_c6_lab_stats(e.c6, &stats);
    REQUIRE(stats.spi_tx_count == 0u);
    env_teardown(&e);
    return 0;
}

static int test_expired_assignment_spi_tx_zero(void)
{
    env_t e;
    ninlil_r5_issue_plan_t plan;
    ninlil_c6_lab_stats_t stats;

    REQUIRE(env_setup(&e) == 0);
    fill_issue_plan(&e, &plan);
    plan.not_before_ms = 1000000u;
    plan.expiry_ms = 1000001u;
    REQUIRE(
        ninlil_c6_lab_transmit(
            e.c6, NINLIL_V1_FRAME_R7_HOP_DATA, &plan, &e.c6_err)
        != NINLIL_C6_LAB_OK);
    ninlil_c6_lab_stats(e.c6, &stats);
    REQUIRE(stats.spi_tx_count == 0u);
    env_teardown(&e);
    return 0;
}

static int test_clock_uncertainty_spi_tx_zero(void)
{
    env_t e;
    ninlil_r5_issue_plan_t plan;
    ninlil_c6_lab_stats_t stats;
    ninlil_id128_t fresh;

    REQUIRE(env_setup(&e) == 0);
    (void)memset(&fresh, 0, sizeof(fresh));
    fresh.bytes[0] = 0xEEu;
    REQUIRE(ninlil_test_clock_rollback(e.clock, &fresh) != 0);
    fill_issue_plan(&e, &plan);
    REQUIRE(
        ninlil_c6_lab_transmit(
            e.c6, NINLIL_V1_FRAME_R7_HOP_DATA, &plan, &e.c6_err)
        != NINLIL_C6_LAB_OK);
    ninlil_c6_lab_stats(e.c6, &stats);
    REQUIRE(stats.spi_tx_count == 0u);
    env_teardown(&e);
    return 0;
}

static int test_permit_failure_spi_tx_zero(void)
{
    env_t e;
    ninlil_r5_issue_plan_t plan;
    ninlil_c6_lab_stats_t stats;

    REQUIRE(env_setup(&e) == 0);
    fill_issue_plan(&e, &plan);
    plan.frame_digest[0] ^= 0x01u; /* digest mismatch at R1 */
    REQUIRE(
        ninlil_c6_lab_transmit(
            e.c6, NINLIL_V1_FRAME_R7_HOP_DATA, &plan, &e.c6_err)
        != NINLIL_C6_LAB_OK);
    ninlil_c6_lab_stats(e.c6, &stats);
    REQUIRE(stats.spi_tx_count == 0u);
    env_teardown(&e);
    return 0;
}

static int test_unknown_frame_type_spi_tx_zero(void)
{
    env_t e;
    ninlil_r5_issue_plan_t plan;
    ninlil_c6_lab_stats_t stats;

    REQUIRE(env_setup(&e) == 0);
    fill_issue_plan(&e, &plan);
    REQUIRE(
        ninlil_c6_lab_transmit(e.c6, 99u, &plan, &e.c6_err)
        == NINLIL_C6_LAB_FRAME_DENIED);
    ninlil_c6_lab_stats(e.c6, &stats);
    REQUIRE(stats.spi_tx_count == 0u);
    env_teardown(&e);
    return 0;
}

static int test_bypass_symbol_not_authorized_path(void)
{
    env_t e;
    ninlil_c6_lab_spi_tx_sim_t sim;
    ninlil_c6_lab_stats_t stats_before;
    ninlil_c6_lab_stats_t stats_after;
    uint64_t bypass_count;

    REQUIRE(env_setup(&e) == 0);
    ninlil_c6_lab_stats(e.c6, &stats_before);
    ninlil_c6_lab_spi_tx_sim_init(&sim);
    REQUIRE(
        ninlil_c6_lab_spi_tx_bypass_direct(&sim, e.frame, T_FRAME_LEN)
        == NINLIL_RADIO_HAL_OK);
    ninlil_c6_lab_stats(e.c6, &stats_after);
    REQUIRE(stats_after.spi_tx_count == stats_before.spi_tx_count);
    ninlil_c6_lab_spi_tx_sim_stats(&sim, NULL, &bypass_count);
    REQUIRE(bypass_count == 1u);
    env_teardown(&e);
    return 0;
}

int main(void)
{
    if (test_manifest_exact_set() != 0) {
        (void)fprintf(stderr, "FAIL manifest_exact_set\n");
        return 1;
    }
    if (test_happy_transmit_all_manifest_types() != 0) {
        (void)fprintf(stderr, "FAIL happy_transmit_all_manifest_types\n");
        return 1;
    }
    if (test_out_of_scope_profile_spi_tx_zero() != 0) {
        (void)fprintf(stderr, "FAIL out_of_scope_profile_spi_tx_zero\n");
        return 1;
    }
    if (test_expired_assignment_spi_tx_zero() != 0) {
        (void)fprintf(stderr, "FAIL expired_assignment_spi_tx_zero\n");
        return 1;
    }
    if (test_clock_uncertainty_spi_tx_zero() != 0) {
        (void)fprintf(stderr, "FAIL clock_uncertainty_spi_tx_zero\n");
        return 1;
    }
    if (test_permit_failure_spi_tx_zero() != 0) {
        (void)fprintf(stderr, "FAIL permit_failure_spi_tx_zero\n");
        return 1;
    }
    if (test_unknown_frame_type_spi_tx_zero() != 0) {
        (void)fprintf(stderr, "FAIL unknown_frame_type_spi_tx_zero\n");
        return 1;
    }
    if (test_bypass_symbol_not_authorized_path() != 0) {
        (void)fprintf(stderr, "FAIL bypass_symbol_not_authorized_path\n");
        return 1;
    }
    (void)printf("c6_lab_enforcement_test: all passed\n");
    return 0;
}
