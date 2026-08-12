/* SPDX-License-Identifier: Apache-2.0 */
#include "r7_frag_checked_issue.h"
#include "r7_frag_issue_coordinator.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_checks;
static int g_failures;

#define CHECK(label, condition)                                              \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(condition)) {                                                  \
            g_failures++;                                                    \
            (void)fprintf(stderr, "FAIL %s\n", (label));                  \
        }                                                                    \
    } while (0)

static void fill_admit(
    ninlil_r7_coord_admit_t *admit,
    uint64_t sequence,
    uint8_t digest_byte)
{
    memset(admit, 0, sizeof(*admit));
    admit->authority_token = UINT64_C(0xA110);
    admit->permit_sequence = sequence;
    admit->bind_token = (uintptr_t)sequence;
    admit->outer_len = 66u;
    admit->issue_now_ms = UINT64_C(1000) + sequence;
    memset(admit->outer_digest, digest_byte, sizeof(admit->outer_digest));
}

static void coordinator_owner_isolation(void)
{
    ninlil_r7_frag_issue_coordinator_t a;
    ninlil_r7_frag_issue_coordinator_t b;
    ninlil_r7_coord_slot_t a_slots_before[NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP];
    ninlil_r7_coord_admit_t admit;
    uint64_t promoted = 0u;

    ninlil_r7_frag_issue_coordinator_init(&a);
    ninlil_r7_frag_issue_coordinator_init(&b);

    fill_admit(&admit, 1u, 0x11u);
    CHECK("owner A admits identity",
        ninlil_r7_frag_issue_coordinator_admit(&a, &admit)
            == NINLIL_R7_COORD_OK);
    CHECK("owner B may independently admit same identity",
        ninlil_r7_frag_issue_coordinator_admit(&b, &admit)
            == NINLIL_R7_COORD_OK);
    CHECK("owner A begins without changing B",
        ninlil_r7_frag_issue_coordinator_begin_tx(
            &a, admit.authority_token, admit.permit_sequence)
            == NINLIL_R7_COORD_OK);
    CHECK("owner B remains head",
        ninlil_r7_frag_issue_coordinator_slot_state(
            &b, admit.authority_token, admit.permit_sequence)
            == NINLIL_R7_COORD_ST_HEAD);

    memcpy(a_slots_before, a.slots, sizeof(a_slots_before));
    a.in_api = 1u;
    fill_admit(&admit, 2u, 0x22u);
    CHECK("same coordinator owner rejects reentry",
        ninlil_r7_frag_issue_coordinator_admit(&a, &admit)
            == NINLIL_R7_COORD_BUSY);
    CHECK("reentry rejection mutates no slot",
        memcmp(a.slots, a_slots_before, sizeof(a_slots_before)) == 0);
    CHECK("busy owner A does not block owner B",
        ninlil_r7_frag_issue_coordinator_admit(&b, &admit)
            == NINLIL_R7_COORD_QUEUED);
    a.in_api = 0u;

    CHECK("B completion promotes only B row",
        ninlil_r7_frag_issue_coordinator_complete(
            &b, admit.authority_token, 1u, &promoted)
            == NINLIL_R7_COORD_OK
        && promoted == 2u);
    CHECK("A retains its independent in-tx row",
        ninlil_r7_frag_issue_coordinator_slot_state(
            &a, admit.authority_token, 1u)
            == NINLIL_R7_COORD_ST_IN_TX);

    ninlil_r7_frag_issue_coordinator_fini(&a);
    ninlil_r7_frag_issue_coordinator_fini(&b);
    {
        ninlil_r7_frag_issue_coordinator_t zero;
        memset(&zero, 0, sizeof(zero));
        CHECK("coordinator A fini zeroizes all bytes",
            memcmp(&a, &zero, sizeof(a)) == 0);
        CHECK("coordinator B fini zeroizes all bytes",
            memcmp(&b, &zero, sizeof(b)) == 0);
    }
}

static void checked_issue_owner_isolation(void)
{
    ninlil_r7_r5_issue_registry_t a;
    ninlil_r7_r5_issue_registry_t b;
    ninlil_r7_class_d_sample_t sample;
    ninlil_pcp_live_profile_t live;
    ninlil_pcp_issue_request_t req;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_r7_checked_issue_result_t result;
    uint64_t a_snapshot;
    uint64_t a_token;

    ninlil_r7_r5_issue_registry_init(&a);
    ninlil_r7_r5_issue_registry_init(&b);
    memset(&sample, 0, sizeof(sample));
    sample.now_ms = 1000u;
    sample.epoch_id_lo = 9u;
    sample.trusted = 1u;

    CHECK("activation A consumes its snapshot",
        ninlil_r5_private_activate_profiles_with_authority_epoch(
            &a, &sample, 7u, 1u, 0xA1u, 9u)
            == NINLIL_R7_CHECKED_ISSUE_OK);
    CHECK("activation B independently consumes same snapshot id",
        ninlil_r5_private_activate_profiles_with_authority_epoch(
            &b, &sample, 7u, 1u, 0xB1u, 9u)
            == NINLIL_R7_CHECKED_ISSUE_OK);
    CHECK("activation replay rejected only within A",
        ninlil_r5_private_activate_profiles_with_authority_epoch(
            &a, &sample, 7u, 1u, 0xA1u, 9u)
            == NINLIL_R7_CHECKED_ISSUE_REGISTRY);
    CHECK("A token cannot contaminate B token domain",
        ninlil_r5_private_activate_profiles_with_authority_epoch(
            &b, &sample, 8u, 1u, 0xA1u, 9u)
            == NINLIL_R7_CHECKED_ISSUE_PREFLIGHT);
    CHECK("B retains its own token and accepts new snapshot",
        ninlil_r5_private_activate_profiles_with_authority_epoch(
            &b, &sample, 8u, 1u, 0xB1u, 9u)
            == NINLIL_R7_CHECKED_ISSUE_OK);

    a.live[0] = 1u;
    a.permit_sequence[0] = 21u;
    a.count = 1u;
    b.live[0] = 1u;
    b.permit_sequence[0] = 31u;
    b.count = 1u;
    ninlil_r7_r5_issue_registry_release(&a, 21u);
    CHECK("registry release mutates owner A only",
        ninlil_r7_r5_issue_registry_count(&a) == 0u
        && ninlil_r7_r5_issue_registry_count(&b) == 1u
        && b.permit_sequence[0] == 31u);

    memset(&live, 0, sizeof(live));
    live.site_assignment_epoch = 1u;
    live.hardware_profile_rev = 1u;
    live.regulatory_profile_rev = 1u;
    memset(&req, 0, sizeof(req));
    req.max_airtime_us = 1u;
    req.frame_byte_length = 1u;
    a_snapshot = a.activate_snapshot_id_used;
    a_token = a.activate_token;
    a.in_api = 1u;
    CHECK("same activation owner rejects reentry",
        ninlil_r5_private_activate_profiles_with_authority_epoch(
            &a, &sample, 9u, 1u, 0xA1u, 9u)
            == NINLIL_R7_CHECKED_ISSUE_PREFLIGHT);
    CHECK("same checked-issue owner rejects reentry",
        ninlil_r5_private_issue_checked_with_owner_epoch(
            (ninlil_pcp_t *)(uintptr_t)1u, &live, 1u, &req, &a, NULL, NULL,
            &permit, &result)
            == NINLIL_R7_CHECKED_ISSUE_PREFLIGHT);
    CHECK("checked-issue reentry reports BUSY_REENTRY",
        result.exact_status == NINLIL_PCP_BUSY_REENTRY
        && result.l1_class == NINLIL_R7_L1_RETRYABLE_PIPELINE);
    CHECK("reentry does not change registry or activation identity",
        a.count == 0u && a.activate_snapshot_id_used == a_snapshot
        && a.activate_token == a_token && a.in_api == 1u);
    a.in_api = 0u;

    ninlil_r7_r5_issue_registry_fini(&a);
    ninlil_r7_r5_issue_registry_fini(&b);
    {
        ninlil_r7_r5_issue_registry_t zero;
        memset(&zero, 0, sizeof(zero));
        CHECK("checked owner A fini zeroizes all bytes",
            memcmp(&a, &zero, sizeof(a)) == 0);
        CHECK("checked owner B fini zeroizes all bytes",
            memcmp(&b, &zero, sizeof(b)) == 0);
    }
}

int main(void)
{
    coordinator_owner_isolation();
    checked_issue_owner_isolation();
    (void)fprintf(stderr, "r7_issue_owner_state: %d checks, %d failures\n",
        g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
