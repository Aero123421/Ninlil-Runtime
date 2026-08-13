/* SPDX-License-Identifier: Apache-2.0 */
/*
 * One-process coexistence proof for the simultaneous all-private Host profile.
 *
 * This executable is linked by CMake against the production-private archives.
 * It must call and validate one real path from each enabled feature; taking a
 * symbol address or directly recompiling a hand-picked source list is not
 * evidence.  This is not a canonical cross-feature E2E. Host software only:
 * physical HIL/RF/power-cut are NOT_RUN.
 */

#include "domain_schema1_startup_authority.h"
#include "fabric_private_api.h"
#include "mfdt_v1.h"
#include "r7_frag_state.h"
#include "rrmp_abi.h"
#include "rrmp_util.h"
#include "wifi_nfl1_min.h"
#include "wifi_nwb1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CHECK(feature, condition)                                             \
    do {                                                                      \
        if (!(condition)) {                                                   \
            (void)fprintf(                                                    \
                stderr,                                                       \
                "all_private_coexistence: feature=%s status=FAIL line=%d "   \
                "check=%s\n",                                                 \
                (feature),                                                    \
                __LINE__,                                                     \
                #condition);                                                  \
            return 1;                                                         \
        }                                                                     \
    } while (0)

enum { RRMP_WORKSPACE_MAX = NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES };

_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_rrmp_workspace[RRMP_WORKSPACE_MAX];

static void fill_id(uint8_t out[16], uint8_t seed)
{
    size_t index;

    for (index = 0u; index < 16u; ++index) {
        out[index] = (uint8_t)(seed + (uint8_t)index);
    }
}

static int prove_domain_live_path(void)
{
    ninlil_domain_schema1_startup_state_t state;
    ninlil_domain_schema1_startup_transcript_t transcript;

    CHECK(
        "Domain",
        ninlil_domain_schema1_startup_init(&state) == NINLIL_OK);
    CHECK(
        "Domain",
        ninlil_domain_schema1_startup_complete_stage(
            &state, NINLIL_DOMAIN_SCHEMA1_STAGE_T0)
            == NINLIL_OK);
    CHECK(
        "Domain",
        ninlil_domain_schema1_startup_pre_publish_side_effects_zero(&state));
    CHECK(
        "Domain",
        ninlil_domain_schema1_startup_export_transcript(&state, &transcript)
            == NINLIL_OK);
    CHECK("Domain", transcript.T0_complete == 1u);
    CHECK("Domain", transcript.publish == 0u);
    (void)printf(
        "all_private_coexistence: feature=Domain status=PASS "
        "live_call=startup_T0\n");
    return 0;
}

static int prove_fabric_live_path(void)
{
    ninlil_fabric_ws_region_info_t objects[NINLIL_FABRIC_WS_REGION_COUNT];
    uint32_t required_bytes = 0u;
    uint32_t alignment = 0u;
    uint32_t object_bytes = 0u;
    uint32_t workspace_bytes = 0u;

    CHECK(
        "Fabric",
        ninlil_fabric_private_workspace_required_v1(
            NINLIL_FABRIC_PROFILE_1, &required_bytes, &alignment)
            == NINLIL_FABRIC_PRIVATE_OK);
    CHECK("Fabric", required_bytes == NINLIL_FABRIC_WORKSPACE_BYTES);
    CHECK("Fabric", alignment >= 8u);
    CHECK(
        "Fabric",
        ninlil_fabric_private_object_partition_proof_v1(
            &object_bytes, &workspace_bytes, objects)
            == NINLIL_FABRIC_PRIVATE_OK);
    CHECK("Fabric", object_bytes <= workspace_bytes);
    CHECK("Fabric", workspace_bytes == required_bytes);
    (void)printf(
        "all_private_coexistence: feature=Fabric status=PASS "
        "live_call=workspace_partition bytes=%u\n",
        required_bytes);
    return 0;
}

static int prove_wifi_live_path(void)
{
    uint8_t nfl1[587];
    uint8_t record[1965];
    uint8_t session_id[16];
    const uint8_t *decoded_payload = NULL;
    size_t nfl1_length = 0u;
    size_t record_length = 0u;
    uint32_t decoded_length = 0u;
    uint32_t decoded_sequence = 0u;

    (void)memset(session_id, 0x51, sizeof(session_id));
    CHECK(
        "Wi-Fi",
        ninlil_wifi_nfl1_min_encode(
            nfl1, sizeof(nfl1), &nfl1_length, 0x010203u)
            == NINLIL_WIFI_OK);
    CHECK("Wi-Fi", nfl1_length == sizeof(nfl1));
    CHECK(
        "Wi-Fi",
        ninlil_wifi_nwb1_encode(
            session_id,
            7u,
            nfl1,
            (uint32_t)nfl1_length,
            record,
            sizeof(record),
            &record_length)
            == NINLIL_WIFI_OK);
    CHECK(
        "Wi-Fi",
        ninlil_wifi_nwb1_classify(
            record,
            record_length,
            session_id,
            1,
            7u,
            &decoded_payload,
            &decoded_length,
            &decoded_sequence)
            == NINLIL_WIFI_OK);
    CHECK("Wi-Fi", decoded_sequence == 7u);
    CHECK("Wi-Fi", decoded_length == sizeof(nfl1));
    CHECK("Wi-Fi", decoded_payload != NULL);
    CHECK("Wi-Fi", memcmp(decoded_payload, nfl1, sizeof(nfl1)) == 0);
    (void)printf(
        "all_private_coexistence: feature=Wi-Fi status=PASS "
        "live_call=NWB1_round_trip bytes=%u\n",
        decoded_length);
    return 0;
}

static int prove_r7_frag_live_path(void)
{
    ninlil_r7_frag_state_plan plan;
    uint32_t total = 0u;
    uint16_t index;

    CHECK(
        "R7FRAG",
        ninlil_r7_frag_state_plan_build(2048u, &plan)
            == NINLIL_R7_FRAG_STATE_OK);
    CHECK("R7FRAG", plan.frag_count == 12u);
    for (index = 0u; index < plan.frag_count; ++index) {
        total += plan.chunks[index].length;
    }
    CHECK("R7FRAG", total == 2048u);
    CHECK(
        "R7FRAG",
        ninlil_r7_frag_state_plan_validate(
            plan.total_len,
            plan.first_chunk_len,
            plan.frag_count,
            plan.cont_unit)
            == NINLIL_R7_FRAG_STATE_OK);
    (void)printf(
        "all_private_coexistence: feature=R7FRAG status=PASS "
        "live_call=fragment_plan fragments=%u\n",
        (unsigned int)plan.frag_count);
    return 0;
}

static int prove_rrmp_live_path(void)
{
    ninlil_rrmp_owner_config_v1_t config;
    ninlil_rrmp_owner_t *owner;
    uint8_t selected_path[16];
    uint8_t observed_path[16];
    uint64_t observed_epoch = 0u;
    size_t workspace_bytes;

    ninlil_rrmp_memzero(&config, sizeof(config));
    config.preamble.api_version = NINLIL_RRMP_API_VERSION;
    config.preamble.struct_size = (uint32_t)sizeof(config);
    fill_id(config.local_runtime_id, 0x10u);
    fill_id(config.authority_id, 0xa0u);
    fill_id(config.authority_clock_epoch_id, 0x50u);
    config.controller_term = 5u;
    config.feature_route_relay = 1u;
    config.feature_multi_parent = 1u;
    config.max_hops_profile = 3u;
    config.now_ms = 1000000u;

    workspace_bytes = ninlil_rrmp_owner_workspace_bytes();
    CHECK("RRMP", workspace_bytes > 0u);
    CHECK("RRMP", workspace_bytes <= sizeof(g_rrmp_workspace));
    owner = ninlil_rrmp_owner_init(
        g_rrmp_workspace, workspace_bytes, &config);
    CHECK("RRMP", owner != NULL);
    CHECK("RRMP", ninlil_rrmp_owner_bind(owner));

    fill_id(selected_path, 0x70u);
    ninlil_rrmp_core_set_fabric_path(owner, selected_path, 9u);
    CHECK(
        "RRMP",
        ninlil_rrmp_core_get_fabric_path(
            owner, observed_path, &observed_epoch));
    CHECK("RRMP", observed_epoch == 9u);
    CHECK("RRMP", memcmp(selected_path, observed_path, 16u) == 0);

    ninlil_rrmp_owner_unbind(owner);
    ninlil_rrmp_owner_fini(owner);
    (void)printf(
        "all_private_coexistence: feature=RRMP status=PASS "
        "live_call=owner_fabric_path workspace=%zu\n",
        workspace_bytes);
    return 0;
}

static int prove_mfdt_live_path(void)
{
    ninlil_mfdt_v1_geometry_t geometry;

    CHECK(
        "MFDT",
        ninlil_mfdt_v1_geometry(
            NINLIL_MFDT_V1_MAX_CONTENT, &geometry)
            == NINLIL_MFDT_V1_OK);
    CHECK("MFDT", geometry.chunk_count == NINLIL_MFDT_V1_MAX_CHUNKS);
    CHECK("MFDT", geometry.page_count == NINLIL_MFDT_V1_MAX_PAGES);
    CHECK(
        "MFDT",
        ninlil_mfdt_v1_geometry(
            NINLIL_MFDT_V1_MAX_CONTENT + 1u, &geometry)
            == NINLIL_MFDT_V1_ERR_PARAM);
    (void)printf(
        "all_private_coexistence: feature=MFDT status=PASS "
        "live_call=max_geometry chunks=%u pages=%u\n",
        (unsigned int)NINLIL_MFDT_V1_MAX_CHUNKS,
        (unsigned int)NINLIL_MFDT_V1_MAX_PAGES);
    return 0;
}

int main(void)
{
    if (prove_domain_live_path() != 0
        || prove_fabric_live_path() != 0
        || prove_wifi_live_path() != 0
        || prove_r7_frag_live_path() != 0
        || prove_rrmp_live_path() != 0
        || prove_mfdt_live_path() != 0) {
        return 1;
    }

    (void)printf(
        "all_private_coexistence: ALL PASS process_calls=6 "
        "canonical_cross_feature_e2e=NOT_CLAIMED physical_hil=NOT_RUN\n");
    return 0;
}
