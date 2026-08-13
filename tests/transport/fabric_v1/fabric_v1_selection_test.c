/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Deterministic path selection: same-kind 2-instance, hard filters, tie-break.
 */
#include "fabric_v1_test_common.h"

static void baseline_snapshot(ninlil_fabric_private_select_snapshot_t *s)
{
    ninlil_fabric_private_select_registry_row_t *r0;
    ninlil_fabric_private_select_registry_row_t *r1;
    ninlil_fabric_private_select_policy_t *p;
    ninlil_fabric_private_select_authority_row_t *a;

    ninlil_fabric_private_memzero(s, sizeof(*s));
    s->outer_available = 1u;
    fabric_test_pattern(s->query.service_identity_digest, 0x11u, 32u);
    s->query.family = 2u;
    s->query.direction = 1u;
    s->query.traffic_class = 1u;
    fabric_test_pattern(s->query.source_runtime_id, 0x30u, 16u);
    fabric_test_pattern(s->query.target_runtime_id, 0x80u, 16u);
    fabric_test_pattern(s->query.target_application_id, 0x90u, 16u);
    s->query.packet_bytes = 587u;
    s->query.transfer_bytes = 587u;
    s->query.now_ms = 170000u;
    s->query.deadline_ms = 200000u;
    fabric_test_pattern(s->query.deadline_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(s->query.admission_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(s->query.availability_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(s->query.attestation_clock_epoch_id, 0xA1u, 16u);
    fabric_test_pattern(s->query.authority_clock_epoch_id, 0xD1u, 16u);
    fabric_test_pattern(s->query.authenticated_peer_runtime_id, 0x31u, 16u);
    fabric_test_pattern(s->query.attachment_authority_id, 0x41u, 16u);
    fabric_test_pattern(s->query.attachment_binding_digest, 0x51u, 32u);

    s->policy_count = 1u;
    p = &s->policies[0];
    fabric_test_pattern(p->policy_id, 0x71u, 16u);
    p->revision = 3u;
    fabric_test_pattern(p->canonical_digest, 0x22u, 32u);
    fabric_test_pattern(p->service_identity_digest, 0x11u, 32u);
    p->family = 2u;
    p->direction = 1u;
    p->traffic_class = 1u;
    p->scope_selector = 2u;
    p->required_capability_flags = 0x02u;
    p->required_security_flags = 0x0Fu;
    p->maximum_latency_class = 50u;
    p->maximum_cost_class = 50u;
    p->minimum_packet_bytes = 587u;
    p->authority_mode = 1u;
    p->deadline_guard_ms = 100u;
    p->candidate_count = 2u;
    fabric_test_pattern(p->candidates[0].instance_id, 0x01u, 16u);
    p->candidates[0].rank = 20u;
    p->candidates[0].reservation_units = 1u;
    fabric_test_pattern(p->candidates[1].instance_id, 0x61u, 16u);
    p->candidates[1].rank = 10u;
    p->candidates[1].reservation_units = 1u;
    p->revision_chain_len = 3u;
    p->revision_chain[0] = 1u;
    p->revision_chain[1] = 2u;
    p->revision_chain[2] = 3u;

    s->registry_count = 2u;
    r0 = &s->registry[0];
    fabric_test_pattern(r0->instance_id, 0x01u, 16u);
    r0->link_kind = NINLIL_FABRIC_LINK_KIND_LOOPBACK;
    r0->direction_mask = 3u;
    r0->capability_flags = 0x6Fu;
    r0->security_capability_flags = 0x0Fu;
    r0->maximum_packet_bytes = 1925u;
    r0->maximum_transfer_bytes = 1925u;
    r0->latency_class = 10u;
    r0->cost_class = 20u;
    r0->reservation_capacity = 8u;
    r0->lifecycle = 1u;
    r0->peer_nfl1_version = 1u;
    r0->peer_fabric_capability_flags = 1u;
    fabric_test_pattern(r0->authenticated_peer_runtime_id, 0x31u, 16u);
    fabric_test_pattern(r0->attachment_authority_id, 0x41u, 16u);
    fabric_test_pattern(r0->attachment_binding_digest, 0x51u, 32u);
    fabric_test_pattern(r0->attestation_clock_epoch_id, 0xA1u, 16u);
    r0->attestation_expires_at_ms = 300000u;
    fabric_test_pattern(r0->availability_clock_epoch_id, 0xA1u, 16u);
    r0->availability_state = 1u;
    r0->availability_expires_at_ms = 250000u;

    r1 = &s->registry[1];
    *r1 = *r0;
    fabric_test_pattern(r1->instance_id, 0x61u, 16u);
    r1->latency_class = 10u;
    r1->cost_class = 20u;

    s->authority_count = 1u;
    a = &s->authorities[0];
    fabric_test_pattern(a->service_identity_digest, 0x11u, 32u);
    a->family = 2u;
    a->direction = 1u;
    a->traffic_class = 1u;
    a->scope_selector = 2u;
    fabric_test_pattern(a->endpoint_runtime_id, 0x80u, 16u);
    fabric_test_pattern(a->target_runtime_id, 0x80u, 16u);
    fabric_test_pattern(a->target_application_id, 0x90u, 16u);
    fabric_test_pattern(a->policy_id, 0x71u, 16u);
    a->policy_revision = 3u;
    fabric_test_pattern(a->policy_digest, 0x22u, 32u);
    a->authority_state = 1u;
    fabric_test_pattern(a->authority_clock_epoch_id, 0xD1u, 16u);
    a->lease_expires_at_ms = 300000u;
}

static int test_same_kind_two_instance_selection(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;
    uint8_t expect[16];

    baseline_snapshot(&snap);
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    fabric_test_pattern(expect, 0x61u, 16u); /* lower rank wins */
    FABRIC_REQUIRE(
        ninlil_fabric_private_memeq(res.selected_instance_id, expect, 16u));
    return 0;
}

static int test_stable_id_tie_break(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;
    uint8_t expect[16];

    baseline_snapshot(&snap);
    /* equal rank/latency/cost -> lexicographic instance id */
    snap.policies[0].candidates[0].rank = 10u;
    snap.policies[0].candidates[1].rank = 10u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    fabric_test_pattern(expect, 0x01u, 16u); /* 0x01... < 0x61... */
    FABRIC_REQUIRE(
        ninlil_fabric_private_memeq(res.selected_instance_id, expect, 16u));
    return 0;
}

static int test_hard_filters(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;

    /* outer unavailable */
    baseline_snapshot(&snap);
    snap.outer_available = 0u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(
        res.resolution, NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "META_OUTER_UNAVAILABLE") == 0);

    /* lifecycle draining */
    baseline_snapshot(&snap);
    snap.registry[0].lifecycle = 2u;
    snap.registry[1].lifecycle = 2u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(
        res.resolution, NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "LIFECYCLE_DRAINING") == 0);

    /* MTU */
    baseline_snapshot(&snap);
    snap.registry[0].maximum_packet_bytes = 500u;
    snap.registry[1].maximum_packet_bytes = 500u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "PACKET_MTU") == 0);

    /* security missing */
    baseline_snapshot(&snap);
    snap.registry[0].security_capability_flags = 0u;
    snap.registry[1].security_capability_flags = 0u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "SECURITY_MISSING") == 0);

    /* peer NFL1 */
    baseline_snapshot(&snap);
    snap.registry[0].peer_nfl1_version = 2u;
    snap.registry[1].peer_nfl1_version = 2u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "PEER_NFL1") == 0);

    /* availability expired */
    baseline_snapshot(&snap);
    snap.registry[0].availability_expires_at_ms = 1000u;
    snap.registry[1].availability_expires_at_ms = 1000u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "AVAILABILITY_EXPIRED") == 0);

    /* reservation capacity */
    baseline_snapshot(&snap);
    snap.registry[0].reservation_capacity = 0u;
    snap.registry[1].reservation_capacity = 0u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "RESERVATION_CAPACITY") == 0);

    /* RF mapping unsupported */
    baseline_snapshot(&snap);
    snap.registry[0].link_kind = 4u;
    snap.registry[1].link_kind = 4u;
    snap.query.rf_permit_valid = 1u;
    snap.query.rf_mapping_accepted = 0u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(
        strcmp(res.primary_rejection, "RF_MAPPING_UNSUPPORTED") == 0);

    /* Mapping support is insufficient without exact registry-row approval. */
    baseline_snapshot(&snap);
    snap.registry[0].link_kind = 4u;
    snap.registry[1].link_kind = 4u;
    snap.query.rf_permit_valid = 1u;
    snap.query.rf_mapping_accepted = 1u;
    snap.registry[0].rf_mapping_approved = 0u;
    snap.registry[1].rf_mapping_approved = 0u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "RF_PATH_NOT_APPROVED") == 0);

    /* Only the approved candidate is eligible, independent of better rank. */
    snap.registry[0].rf_mapping_approved = 1u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(
        res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    FABRIC_REQUIRE(ninlil_fabric_private_memeq(
        res.selected_instance_id, snap.registry[0].instance_id, 16u));

    /* policy ambiguous */
    baseline_snapshot(&snap);
    snap.policy_count = 2u;
    snap.policies[1] = snap.policies[0];
    fabric_test_pattern(snap.policies[1].policy_id, 0x72u, 16u);
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_CORRUPT);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "POLICY_AMBIGUOUS") == 0);

    /* revision gap */
    baseline_snapshot(&snap);
    snap.policies[0].revision_chain[1] = 5u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_CORRUPT);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "POLICY_REVISION_GAP") == 0);

    return 0;
}

/* Only-valid candidate lives in registry slot 15 (final profile slot). */
static int test_final_registry_slot_candidate(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;
    uint32_t i;
    uint8_t want[16];

    baseline_snapshot(&snap);
    /* Expand to 16 registry rows: slots 0..14 invalid peer NFL1, 15 valid. */
    {
        ninlil_fabric_private_select_registry_row_t good = snap.registry[1];
        fabric_test_pattern(good.instance_id, 0x61u, 16u);
        snap.registry_count = 16u;
        for (i = 0u; i < 15u; ++i) {
            snap.registry[i] = snap.registry[0];
            fabric_test_pattern(
                snap.registry[i].instance_id, (uint8_t)(0x01u + i), 16u);
            snap.registry[i].peer_nfl1_version = 0u; /* hard fail PEER_NFL1 */
        }
        snap.registry[15] = good;
    }
    snap.policies[0].candidate_count = 1u;
    fabric_test_pattern(snap.policies[0].candidates[0].instance_id, 0x61u, 16u);
    snap.policies[0].candidates[0].rank = 1u;
    snap.policies[0].candidates[0].reservation_units = 1u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    fabric_test_pattern(want, 0x61u, 16u);
    FABRIC_REQUIRE(ninlil_fabric_private_memeq(res.selected_instance_id, want, 16u));
    return 0;
}

/* Reservation accounting includes all 64 PREPARED attempts, not only 16. */
static int test_reservation_uses_all_64_active_attempts(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;
    uint32_t i;

    baseline_snapshot(&snap);
    /* Capacity 20; 20 active attempts of 1 unit each => full. */
    snap.registry[0].reservation_capacity = 20u;
    snap.registry[1].reservation_capacity = 20u;
    snap.active_attempt_count = 20u;
    for (i = 0u; i < 20u; ++i) {
        fabric_test_pattern(
            snap.active_attempts[i].instance_id, 0x61u, 16u);
        snap.active_attempts[i].state =
            NINLIL_FABRIC_PRIVATE_ATTEMPT_PREPARED;
        snap.active_attempts[i].reservation_units = 1u;
    }
    snap.policies[0].candidate_count = 1u;
    fabric_test_pattern(snap.policies[0].candidates[0].instance_id, 0x61u, 16u);
    snap.policies[0].candidates[0].rank = 1u;
    snap.policies[0].candidates[0].reservation_units = 1u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "RESERVATION_CAPACITY") == 0);

    /* 19 active + 1 new fits. */
    snap.active_attempt_count = 19u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    return 0;
}

/*
 * Different peer pins on two candidates: zero query peer must not prefer
 * enumeration order; both peer-valid rows remain eligible by rank.
 */
static int test_peer_attachment_no_first_row_seed(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;
    uint8_t want[16];

    baseline_snapshot(&snap);
    /* Clear caller peer/attachment expectations (no first-row seed). */
    ninlil_fabric_private_memzero(
        snap.query.authenticated_peer_runtime_id, 16u);
    ninlil_fabric_private_memzero(snap.query.attachment_authority_id, 16u);
    ninlil_fabric_private_memzero(snap.query.attachment_binding_digest, 32u);
    /* Two candidates with distinct peers and attachments. */
    fabric_test_pattern(
        snap.registry[0].authenticated_peer_runtime_id, 0xAAu, 16u);
    fabric_test_pattern(snap.registry[0].attachment_authority_id, 0xBBu, 16u);
    fabric_test_pattern(snap.registry[0].attachment_binding_digest, 0xCCu, 32u);
    fabric_test_pattern(
        snap.registry[1].authenticated_peer_runtime_id, 0xDDu, 16u);
    fabric_test_pattern(snap.registry[1].attachment_authority_id, 0xEEu, 16u);
    fabric_test_pattern(snap.registry[1].attachment_binding_digest, 0xFFu, 32u);
    /* Rank prefers instance 0x61 (registry[1]). */
    snap.policies[0].candidates[0].rank = 20u;
    snap.policies[0].candidates[1].rank = 1u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    fabric_test_pattern(want, 0x61u, 16u);
    FABRIC_REQUIRE(ninlil_fabric_private_memeq(res.selected_instance_id, want, 16u));

    /* Swap registry order: still select by rank, not enumeration. */
    {
        ninlil_fabric_private_select_registry_row_t tmp = snap.registry[0];
        snap.registry[0] = snap.registry[1];
        snap.registry[1] = tmp;
    }
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    FABRIC_REQUIRE(ninlil_fabric_private_memeq(res.selected_instance_id, want, 16u));

    /* Non-zero caller peer expectation rejects non-matching peers. */
    fabric_test_pattern(
        snap.query.authenticated_peer_runtime_id, 0xAAu, 16u);
    ninlil_fabric_private_select(&snap, &res);
    /* only registry with peer 0xAA eligible if also in policy candidates */
    /* After swap, registry[1] has peer AA (old r0). Candidate 0x01 has rank 20. */
    fabric_test_pattern(want, 0x01u, 16u);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    FABRIC_REQUIRE(ninlil_fabric_private_memeq(res.selected_instance_id, want, 16u));
    return 0;
}

/* now > deadline must reject without unsigned underflow. */
static int test_deadline_now_after_deadline(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;

    baseline_snapshot(&snap);
    snap.query.now_ms = 250000u;
    snap.query.deadline_ms = 200000u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "DEADLINE_GUARD") == 0);
    return 0;
}

/* Only max revision of same policy ID is current for resolver. */
static int test_policy_max_revision_only_current(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;

    baseline_snapshot(&snap);
    snap.policy_count = 2u;
    snap.policies[1] = snap.policies[0];
    snap.policies[1].revision = 2u; /* older than 3 */
    snap.policies[1].revision_chain_len = 2u;
    snap.policies[1].revision_chain[0] = 1u;
    snap.policies[1].revision_chain[1] = 2u;
    /* Corrupt candidate only on old rev: must not affect selection. */
    snap.policies[1].candidate_count = 0u;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_SELECTED);
    return 0;
}

/*
 * P0 one-field-missing negatives: each message/authority requirement bound
 * into the query must reject when the matching registry field is absent.
 */
/*
 * Bind one query requirement at a time so primary rejection is the
 * field under test (hard-filter order: caps before sleep before
 * security before custody before evidence before peer/attachment).
 */
static void clear_policy_req(ninlil_fabric_private_select_snapshot_t *s)
{
    s->policies[0].required_capability_flags = 0u;
    s->policies[0].required_security_flags = 0u;
}

static int test_query_requirement_one_field_missing(void)
{
    ninlil_fabric_private_select_snapshot_t snap;
    ninlil_fabric_private_select_result_t res;

    /* Sleep missing */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    snap.query.requires_sleep_compatible = 1u;
    snap.registry[0].capability_flags =
        (uint32_t)(0x6Fu & ~NINLIL_FABRIC_CAP_SLEEP_COMPATIBLE);
    snap.registry[1].capability_flags = snap.registry[0].capability_flags;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE_EQ_U32(res.resolution, NINLIL_FABRIC_PRIVATE_SEL_NO_ELIGIBLE);
    FABRIC_REQUIRE(
        strcmp(res.primary_rejection, "ENERGY_SLEEP_CAPABILITY_MISSING") == 0);

    /*
     * ADR-0018: Wi-Fi remains ineligible even if a corrupt/legacy snapshot
     * falsely retains the custody capability bit.
     */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    snap.query.requires_custody = 1u;
    snap.registry[0].link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    snap.registry[1].link_kind = NINLIL_FABRIC_LINK_KIND_WIFI;
    snap.registry[0].capability_flags |= NINLIL_FABRIC_CAP_CUSTODY;
    snap.registry[1].capability_flags |= NINLIL_FABRIC_CAP_CUSTODY;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "CUSTODY_MISSING") == 0);

    /* Evidence missing */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    snap.query.requires_evidence = 1u;
    snap.registry[0].capability_flags =
        (uint32_t)(0x6Fu & ~NINLIL_FABRIC_CAP_EVIDENCE);
    snap.registry[1].capability_flags = snap.registry[0].capability_flags;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "EVIDENCE_MISSING") == 0);

    /* Capability (unicast) missing via required_capability_flags */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    snap.query.required_capability_flags = NINLIL_FABRIC_CAP_UNICAST;
    snap.registry[0].capability_flags =
        (uint32_t)(0x6Fu & ~NINLIL_FABRIC_CAP_UNICAST);
    snap.registry[1].capability_flags = snap.registry[0].capability_flags;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "CAPABILITY_MISSING") == 0);

    /* Security one bit missing */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    snap.query.required_security_flags = NINLIL_FABRIC_SECURITY_INTEGRITY;
    snap.registry[0].security_capability_flags =
        (uint32_t)(0x0Fu & ~NINLIL_FABRIC_SECURITY_INTEGRITY);
    snap.registry[1].security_capability_flags =
        snap.registry[0].security_capability_flags;
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(strcmp(res.primary_rejection, "SECURITY_MISSING") == 0);

    /* Peer pin mismatch (query field present, registry differs) */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    fabric_test_pattern(snap.query.authenticated_peer_runtime_id, 0xEEu, 16u);
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(
        strcmp(res.primary_rejection, "AUTHENTICATED_PEER_MISMATCH") == 0);

    /* Attachment authority pin mismatch */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    fabric_test_pattern(snap.query.attachment_authority_id, 0xEEu, 16u);
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(
        strcmp(res.primary_rejection, "ATTACHMENT_AUTHORITY_MISMATCH") == 0);

    /* Attachment binding pin mismatch */
    baseline_snapshot(&snap);
    clear_policy_req(&snap);
    fabric_test_pattern(snap.query.attachment_binding_digest, 0xEEu, 32u);
    ninlil_fabric_private_select(&snap, &res);
    FABRIC_REQUIRE(
        strcmp(res.primary_rejection, "ATTACHMENT_BINDING_MISMATCH") == 0);

    return 0;
}

int main(void)
{
    g_fabric_test_failures = 0;
    (void)test_same_kind_two_instance_selection();
    (void)test_stable_id_tie_break();
    (void)test_hard_filters();
    (void)test_final_registry_slot_candidate();
    (void)test_reservation_uses_all_64_active_attempts();
    (void)test_peer_attachment_no_first_row_seed();
    (void)test_deadline_now_after_deadline();
    (void)test_policy_max_revision_only_current();
    (void)test_query_requirement_one_field_missing();
    if (g_fabric_test_failures != 0) {
        (void)fprintf(
            stderr,
            "fabric_v1_selection_test failures=%d\n",
            g_fabric_test_failures);
        return 1;
    }
    (void)printf("fabric_v1_selection_test OK\n");
    return 0;
}
