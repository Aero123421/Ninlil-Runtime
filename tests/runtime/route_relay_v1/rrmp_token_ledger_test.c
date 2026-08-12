/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_test_common.h"

#include <stdint.h>

#define TOKEN_CASE_COUNT NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY
#define SNAPSHOT_CAPACITY (256u * 1024u)

static _Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
    uint8_t g_ws1[NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES];
static _Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
    uint8_t g_ws2[NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES];
static uint8_t g_snapshot[SNAPSHOT_CAPACITY];
static ninlil_rrmp_parent_ns_t g_parent_probe;

typedef struct scope_fixture {
    uint8_t scope[16];
    uint8_t path_policy[16];
    ninlil_rrmp_id16_t parent_id;
    ninlil_rrmp_digest32_t parent_digest;
    uint8_t nps1_raw[NINLIL_RRMP_NPS1_BYTES];
} scope_fixture_t;

static void fill_preamble(ninlil_rrmp_preamble_v1_t *preamble, uint32_t size)
{
    ninlil_rrmp_memzero(preamble, sizeof(*preamble));
    preamble->api_version = NINLIL_RRMP_API_VERSION;
    preamble->struct_size = size;
}

static void make_token(uint32_t ordinal, uint8_t token[32])
{
    uint8_t preimage[24];
    ninlil_rrmp_memzero(preimage, sizeof(preimage));
    memcpy(preimage, "RRMP-LEDGER-BOUNDARY", 20u);
    ninlil_rrmp_put_u32_be(preimage + 20u, ordinal);
    ninlil_rrmp_sha256(preimage, sizeof(preimage), token);
}

static int install_scope(
    ninlil_rrmp_owner_t *owner,
    const uint8_t scope[16],
    uint8_t path_seed,
    uint8_t parent_seed,
    scope_fixture_t *fixture)
{
    ninlil_parent_set_install_req_v1_t req;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_nps1_fields_t nps;
    if (scope == NULL || fixture == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(fixture, sizeof(*fixture));
    memcpy(fixture->scope, scope, 16u);
    rrmp_fill_id(fixture->path_policy, path_seed);
    rrmp_fill_id(fixture->parent_id.bytes, parent_seed);
    if (!ninlil_rrmp_parent_set_digest(
            &fixture->parent_id, 1u, &fixture->parent_digest)) {
        return 0;
    }

    ninlil_rrmp_memzero(&req, sizeof(req));
    fill_preamble(&req.preamble, (uint32_t)sizeof(req));
    memcpy(req.owner_scope_id, fixture->scope, 16u);
    req.parent_set_count = 1u;
    memcpy(req.path_policy_id, fixture->path_policy, 16u);
    req.controller_term = 5u;
    req.assignment_epoch = 1u;
    memcpy(
        req.parent_set_digest32, fixture->parent_digest.bytes, 32u);
    memcpy(
        req.parent_runtime_id[0], fixture->parent_id.bytes, 16u);
    if (ninlil_parent_set_install(owner, &req, &out) != NINLIL_PARENT_OK) {
        return 0;
    }

    ninlil_rrmp_memzero(&nps, sizeof(nps));
    memcpy(nps.owner_scope_id.bytes, fixture->scope, 16u);
    memcpy(nps.parent_set_id.bytes, fixture->path_policy, 16u);
    nps.parent_set_revision = 1u;
    nps.parent_count = 1u;
    nps.parent_ids[0] = fixture->parent_id;
    nps.parent_set_digest = fixture->parent_digest;
    return ninlil_rrmp_encode_nps1(&nps, fixture->nps1_raw);
}

static int make_prepare(
    const scope_fixture_t *fixture,
    const uint8_t token[32],
    uint64_t revision,
    ninlil_parent_owner_prepare_req_v1_t *prep)
{
    ninlil_rrmp_noa1_fields_t noa;
    if (fixture == NULL || token == NULL || prep == NULL ||
        revision == 0u || revision == UINT64_MAX) {
        return 0;
    }
    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, fixture->scope, 16u);
    rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
    noa.controller_term = 5u;
    noa.assignment_epoch = 1u;
    noa.assignment_revision = revision;
    rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
    rrmp_fill_id(noa.owner_cell_id.bytes, 0xB1u);
    noa.direction = 1u;
    noa.e2e_context_id = (uint32_t)revision;
    noa.key_generation = revision;
    rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
    noa.e2e_security_epoch = revision;
    memset(
        noa.e2e_binding_digest.bytes,
        (int)((revision % 254u) + 1u),
        32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memcpy(noa.handoff_token_digest.bytes, token, 32u);
    noa.parent_set_digest = fixture->parent_digest;
    noa.parent_set_count = 1u;
    memcpy(noa.parent_set_id.bytes, fixture->path_policy, 16u);

    ninlil_rrmp_memzero(prep, sizeof(*prep));
    fill_preamble(&prep->preamble, (uint32_t)sizeof(*prep));
    memcpy(prep->owner_scope_id, fixture->scope, 16u);
    if (!ninlil_rrmp_encode_noa1(&noa, prep->new_assignment_noa1)) {
        return 0;
    }
    memcpy(prep->handoff_token_digest32, token, 32u);
    return 1;
}

static int complete_handoff(
    ninlil_rrmp_owner_t *owner,
    const scope_fixture_t *fixture,
    const uint8_t token[32],
    uint64_t revision)
{
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_activate_req_v1_t activate;
    ninlil_parent_endpoint_observe_req_v1_t observe;
    ninlil_parent_owner_retire_req_v1_t retire;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_digest32_t commit_digest;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    ninlil_parent_owner_prepare_req_v1_t old_prep;
    uint8_t old_token[32];
    uint8_t proof[32];
    uint32_t status;

    if (!make_prepare(fixture, token, revision, &prep)) {
        return 0;
    }
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    if (revision > 1u) {
        make_token((uint32_t)(revision - 1u), old_token);
        if (!make_prepare(
                fixture, old_token, revision - 1u, &old_prep) ||
            !rrmp_test_authority_tuple_from_noa(
                old_prep.new_assignment_noa1,
                revision - 1u,
                &old_tuple)) {
            return 0;
        }
    }
    status = rrmp_test_owner_prepare_v2(owner,
        &prep, &old_tuple, revision, &new_tuple, &out);
    if (status != NINLIL_PARENT_OK) {
        fprintf(stderr, "prepare revision=%llu status=%u\n",
            (unsigned long long)revision, status);
        return 0;
    }

    status = rrmp_test_owner_fence_v2(owner,
        fixture->scope, token, &old_tuple, proof, &out);
    if (status != NINLIL_PARENT_OK) {
        fprintf(stderr, "fence revision=%llu status=%u\n",
            (unsigned long long)revision, status);
        return 0;
    }

    status = rrmp_test_authority_commit_v2(owner,
        fixture->scope,
        &old_tuple,
        &new_tuple,
        token,
        proof,
        NULL,
        revision - 1u,
        commit_digest.bytes,
        &out);
    if (status != NINLIL_PARENT_OK) {
        fprintf(stderr, "commit revision=%llu status=%u\n",
            (unsigned long long)revision, status);
        return 0;
    }

    ninlil_rrmp_memzero(&activate, sizeof(activate));
    fill_preamble(&activate.preamble, (uint32_t)sizeof(activate));
    memcpy(activate.owner_scope_id, fixture->scope, 16u);
    memcpy(
        activate.commit_receipt_digest32, commit_digest.bytes, 32u);
    activate.now_ms = 1000000u;
    status = ninlil_parent_owner_activate(owner, &activate, &out);
    if (status != NINLIL_PARENT_OK) {
        fprintf(stderr, "activate revision=%llu status=%u\n",
            (unsigned long long)revision, status);
        return 0;
    }

    ninlil_rrmp_memzero(&observe, sizeof(observe));
    fill_preamble(&observe.preamble, (uint32_t)sizeof(observe));
    memcpy(observe.owner_scope_id, fixture->scope, 16u);
    memcpy(
        observe.observed_parent_set_digest32,
        fixture->parent_digest.bytes,
        32u);
    observe.now_ms = 1000000u;
    status = ninlil_parent_endpoint_observe(owner, &observe, &out);
    if (status != NINLIL_PARENT_OK) {
        fprintf(stderr, "observe revision=%llu status=%u\n",
            (unsigned long long)revision, status);
        return 0;
    }

    ninlil_rrmp_memzero(&retire, sizeof(retire));
    fill_preamble(&retire.preamble, (uint32_t)sizeof(retire));
    memcpy(retire.owner_scope_id, fixture->scope, 16u);
    memcpy(retire.tombstone_digest32, token, 32u);
    retire.now_ms = 1000000u;
    status = ninlil_parent_owner_retire(owner, &retire, &out);
    if (status != NINLIL_PARENT_OK) {
        fprintf(stderr, "retire revision=%llu status=%u\n",
            (unsigned long long)revision, status);
        return 0;
    }
    return 1;
}

static int assert_durable_ledger_exact(
    const uint8_t *snapshot, size_t snapshot_len)
{
    uint32_t route_len;
    uint32_t parent_len;
    uint32_t total = 0u;
    uint8_t page_index;
    if (snapshot == NULL || snapshot_len < 20u ||
        memcmp(snapshot, "RRMPNS1\0", 8u) != 0) {
        return 0;
    }
    route_len = ninlil_rrmp_get_u32_be(snapshot + 8u);
    parent_len = ninlil_rrmp_get_u32_be(snapshot + 12u);
    if (20u + (size_t)route_len + (size_t)parent_len > snapshot_len ||
        !ninlil_rrmp_parent_ns_import(
            &g_parent_probe,
            snapshot + 20u + route_len,
            parent_len)) {
        return 0;
    }
    for (page_index = 0u;
         page_index < NINLIL_RRMP_NPT1_PAGE_COUNT;
         ++page_index) {
        const uint8_t *page = NULL;
        uint32_t len = 0u;
        uint64_t generation = 0u;
        uint32_t count;
        uint32_t slot;
        uint32_t expected =
            page_index < 3u ? NINLIL_RRMP_NPT1_SLOTS_PER_PAGE
                            : (page_index == 3u ? 4u : 0u);
        if (!ninlil_rrmp_parent_dual_read_active(
                &g_parent_probe,
                (uint8_t)(NINLIL_RRMP_PKEY_NPT1_BASE + page_index),
                &page,
                &len,
                &generation) ||
            page == NULL || len != NINLIL_RRMP_NPT1_BYTES ||
            !ninlil_rrmp_validate_npt1(page)) {
            return 0;
        }
        count = ninlil_rrmp_get_u32_be(page + 12u);
        if (count != expected) {
            return 0;
        }
        for (slot = 0u; slot < count; ++slot) {
            const uint8_t *entry =
                page + NINLIL_RRMP_NPT1_HEADER_BYTES +
                (size_t)slot * NINLIL_RRMP_NPT1_SLOT_BYTES;
            if (entry[32u] !=
                NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED) {
                return 0;
            }
        }
        total += count;
    }
    return total == TOKEN_CASE_COUNT;
}

int main(void)
{
    ninlil_rrmp_owner_t *owner;
    ninlil_rrmp_owner_t *restarted;
    scope_fixture_t scope_a;
    scope_fixture_t scope_b;
    ninlil_parent_owner_prepare_req_v1_t same_scope_replay;
    ninlil_parent_owner_prepare_req_v1_t cross_scope_replay;
    ninlil_parent_owner_prepare_req_v1_t boundary_257;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_authority_tuple_v2_t current_a;
    ninlil_rrmp_authority_tuple_v2_t absent;
    ninlil_rrmp_authority_tuple_v2_t proposed;
    ninlil_parent_owner_prepare_req_v1_t current_prep;
    uint8_t scope_a_id[16];
    uint8_t scope_b_id[16];
    uint8_t first_token[32];
    uint8_t token[32];
    size_t snapshot_len = 0u;
    uint32_t ordinal;

    RRMP_CHECK_EQ(TOKEN_CASE_COUNT, 256u);
    owner = rrmp_mk_ws(g_ws1, sizeof(g_ws1), 0u, 1u);
    RRMP_CHECK(owner != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind(owner));
    rrmp_fill_id(scope_a_id, 0x21u);
    rrmp_fill_id(scope_b_id, 0x41u);
    RRMP_CHECK(install_scope(
        owner, scope_a_id, 0x61u, 0x31u, &scope_a));

    make_token(1u, first_token);
    for (ordinal = 1u; ordinal <= TOKEN_CASE_COUNT; ++ordinal) {
        make_token(ordinal, token);
        if (!complete_handoff(owner, &scope_a, token, ordinal)) {
            fprintf(stderr, "handoff failed ordinal=%u\n", ordinal);
            return 1;
        }
    }

    /* Duplicate takes precedence over the full-ledger RESOURCE boundary. */
    make_token(TOKEN_CASE_COUNT, token);
    RRMP_CHECK(make_prepare(
        &scope_a, token, TOKEN_CASE_COUNT, &current_prep));
    RRMP_CHECK(rrmp_test_authority_tuple_from_noa(
        current_prep.new_assignment_noa1,
        TOKEN_CASE_COUNT,
        &current_a));
    ninlil_rrmp_memzero(&absent, sizeof(absent));
    RRMP_CHECK(make_prepare(
        &scope_a, first_token, TOKEN_CASE_COUNT + 1u, &same_scope_replay));
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(owner,
            &same_scope_replay,
            &current_a,
            TOKEN_CASE_COUNT + 1u,
            &proposed,
            &out),
        NINLIL_PARENT_TOKEN_REPLAY);

    RRMP_CHECK(install_scope(
        owner, scope_b_id, 0x71u, 0x51u, &scope_b));
    RRMP_CHECK(make_prepare(
        &scope_b, first_token, 1u, &cross_scope_replay));
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(owner,
            &cross_scope_replay,
            &absent,
            TOKEN_CASE_COUNT + 1u,
            &proposed,
            &out),
        NINLIL_PARENT_TOKEN_REPLAY);

    make_token(TOKEN_CASE_COUNT + 1u, token);
    RRMP_CHECK(make_prepare(
        &scope_a, token, TOKEN_CASE_COUNT + 1u, &boundary_257));
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(owner,
            &boundary_257,
            &current_a,
            TOKEN_CASE_COUNT + 1u,
            &proposed,
            &out),
        NINLIL_PARENT_RESOURCE);

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        owner, NULL, 0u, &snapshot_len));
    RRMP_CHECK(snapshot_len <= sizeof(g_snapshot));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        owner, g_snapshot, sizeof(g_snapshot), &snapshot_len));
    RRMP_CHECK(assert_durable_ledger_exact(g_snapshot, snapshot_len));

    restarted = rrmp_mk_ws(g_ws2, sizeof(g_ws2), 0u, 1u);
    RRMP_CHECK(restarted != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
        restarted, g_snapshot, snapshot_len));
    RRMP_CHECK(ninlil_rrmp_owner_bind(restarted));
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(restarted,
            &same_scope_replay,
            &current_a,
            TOKEN_CASE_COUNT + 1u,
            &proposed,
            &out),
        NINLIL_PARENT_TOKEN_REPLAY);
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(restarted,
            &cross_scope_replay,
            &absent,
            TOKEN_CASE_COUNT + 1u,
            &proposed,
            &out),
        NINLIL_PARENT_TOKEN_REPLAY);
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(restarted,
            &boundary_257,
            &current_a,
            TOKEN_CASE_COUNT + 1u,
            &proposed,
            &out),
        NINLIL_PARENT_RESOURCE);

    ninlil_rrmp_owner_fini(owner);
    ninlil_rrmp_owner_fini(restarted);
    puts("rrmp global durable token ledger OK retained=256 boundary257=RESOURCE");
    return 0;
}
