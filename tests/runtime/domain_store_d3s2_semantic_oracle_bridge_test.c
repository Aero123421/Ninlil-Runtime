/*
 * D3-S2 independent semantic-oracle → production scanner bridge.
 *
 * Expected outcome shapes come only from the generated Python oracle fixture.
 * Each named scenario is then executed through the real profiled D3-S2 scanner
 * and scripted Storage Port.  Shared scenario implementations are linked from
 * a private test object to avoid a second, drifting set of row builders.
 * Existing D3-S1 94-vector artifacts are not involved.
 *
 * This bridge slice covers fourteen representative paths.  It does not yet
 * claim every one of the 31 semantic cases has a wire-row realization,
 * and does not claim formal append-only crossrow oracle completion.
 */

#include "domain_scan_d3s2_semantic_fixture.h"
#include "domain_store_d3s2_test_scenarios.h"

#include <stdio.h>
#include <string.h>

static const char *bridge_id = "";

#define BRIDGE_REQUIRE(condition)                                              \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: %s failed: %s\n", __FILE__,        \
                __LINE__, bridge_id, #condition);                              \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int expect_success_shape(const ninlil_d3s2_semantic_vector_t *vector)
{
    return strcmp(vector->final_status, "OK") == 0
        && strcmp(vector->phase_after, "COMPLETE") == 0
        && vector->has_sticky_primary == 0u && vector->note_count == 0u
        && vector->complete_ready == 1u && vector->mutation_calls == 0u;
}

static int expect_corrupt_shape(const ninlil_d3s2_semantic_vector_t *vector)
{
    return strcmp(vector->final_status, "STORAGE_CORRUPT") == 0
        && strcmp(vector->phase_after, "FAILED") == 0
        && vector->has_sticky_primary == 1u && vector->note_count == 1u
        && vector->complete_ready == 0u && vector->mutation_calls == 0u;
}

static int run_vector(const ninlil_d3s2_semantic_vector_t *vector)
{
    bridge_id = vector->id;
    if (strcmp(vector->id, "mode23_cancel_first_empty_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 23u && expect_success_shape(vector));
        return test_d3s2_mode23_cancel_first_empty_success();
    }
    if (strcmp(vector->id, "mode23_nonempty_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 23u && expect_success_shape(vector));
        return test_d3s2_mode23_nonempty_success();
    }
    if (strcmp(vector->id, "mode24_reply_zero_empty_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 24u && expect_success_shape(vector));
        return test_d3s2_p0_7_mode24_reply_count0_empty_success();
    }
    if (strcmp(vector->id, "mode24_reply_one_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 24u && expect_success_shape(vector));
        return test_d3s2_mode24_reply_one_success();
    }
    if (strcmp(vector->id, "mode24_reply_one_missing") == 0) {
        BRIDGE_REQUIRE(vector->mode == 24u && expect_corrupt_shape(vector));
        return test_d3s2_p0_7_mode24_declared_missing_reply_fail();
    }
    if (strcmp(vector->id, "mode25_retry_zero_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 25u && expect_success_shape(vector));
        return test_d3s2_mode25_retry_zero_success();
    }
    if (strcmp(vector->id, "mode25_retry_one_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 25u && expect_success_shape(vector));
        return test_d3s2_mode25_retry_one_success();
    }
    if (strcmp(vector->id, "mode25_recent_without_cumulative_fail") == 0) {
        BRIDGE_REQUIRE(vector->mode == 25u && expect_corrupt_shape(vector));
        return test_d3s2_mode25_recent_without_cumulative_fail();
    }
    if (strcmp(vector->id, "mode26_management_zero_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 26u && expect_success_shape(vector));
        return test_d3s2_mode26_management_zero_success();
    }
    if (strcmp(vector->id, "mode26_management_one_success") == 0) {
        BRIDGE_REQUIRE(vector->mode == 26u && expect_success_shape(vector));
        return test_d3s2_mode26_management_one_success();
    }
    if (strcmp(vector->id, "mode26_management_without_spool_fail") == 0) {
        BRIDGE_REQUIRE(vector->mode == 26u && expect_corrupt_shape(vector));
        return test_d3s2_mode26_management_without_spool_fail();
    }
    if (strcmp(vector->id, "empty_carrier_empty_secondary_ok") == 0) {
        BRIDGE_REQUIRE(vector->mode == 21u && expect_success_shape(vector));
        return test_d3s2_empty_carrier_empty_secondary_success();
    }
    if (strcmp(vector->id, "empty_carrier_orphan_fail") == 0) {
        BRIDGE_REQUIRE(vector->mode == 21u && expect_corrupt_shape(vector));
        return test_d3s2_p1_mode21_bind_carrier_absent();
    }
    if (strcmp(vector->id, "port_failure_no_note") == 0) {
        BRIDGE_REQUIRE(vector->mode == 25u);
        BRIDGE_REQUIRE(strcmp(vector->final_status, "STORAGE") == 0);
        BRIDGE_REQUIRE(strcmp(vector->phase_after, "FAILED") == 0);
        BRIDGE_REQUIRE(vector->has_sticky_primary == 1u);
        BRIDGE_REQUIRE(vector->note_count == 0u);
        BRIDGE_REQUIRE(vector->complete_ready == 0u);
        BRIDGE_REQUIRE(vector->mutation_calls == 0u);
        return test_d3s2_port_failure_no_note();
    }
    BRIDGE_REQUIRE(0 && "unknown generated bridge vector");
    return 1;
}

int main(void)
{
    size_t i;
    BRIDGE_REQUIRE(NINLIL_D3S2_SEMANTIC_VECTOR_COUNT == 14u);
    for (i = 0u; i < NINLIL_D3S2_SEMANTIC_VECTOR_COUNT; ++i) {
        if (run_vector(&NINLIL_D3S2_SEMANTIC_VECTORS[i]) != 0) {
            return 1;
        }
    }
    return 0;
}
