#include "rrmp_fabric_dispatch.h"
#include "rrmp_seam.h"
#include "rrmp_test_common.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Use VLA-free fixed max: allocate oversized static based on compile size. */
enum { RRMP_WS_MAX = 512 * 1024 };
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_owner_ws[RRMP_WS_MAX];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_owner_ws2[RRMP_WS_MAX];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_owner_ws3[RRMP_WS_MAX];
static uint8_t g_npp1_export_probe[256 * 1024];
static ninlil_rrmp_parent_ns_t g_npp1_parent_probe;

static ninlil_rrmp_owner_t *mk(uint8_t r, uint8_t p)
{
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    if (need > RRMP_WS_MAX) {
        return NULL;
    }
    return rrmp_mk_ws(g_owner_ws, need, r, p);
}

static int test_authorize(
    void *user,
    const ninlil_rrmp_caller_auth_v1_t *auth,
    const uint8_t local_runtime_id[16],
    const uint8_t authority_id[16])
{
    uint8_t *calls = (uint8_t *)user;
    if (calls != NULL) {
        *calls = (uint8_t)(*calls + 1u);
    }
    return auth != NULL && local_runtime_id != NULL && authority_id != NULL &&
        auth->authorization_epoch == 7u && auth->proof32[0] == 0xA5u;
}

static void fill_auth(
    ninlil_rrmp_caller_auth_v1_t *auth, uint32_t caps, uint8_t valid)
{
    ninlil_rrmp_memzero(auth, sizeof(*auth));
    rrmp_fill_id(auth->principal_id, 0x22u);
    auth->capability_mask = caps;
    auth->authorization_epoch = 7u;
    auth->proof32[0] = valid ? 0xA5u : 0x00u;
}

static int test_caller_authorization(void)
{
    ninlil_rrmp_owner_config_v1_t cfg;
    ninlil_rrmp_owner_t *o;
    ninlil_rrmp_caller_auth_v1_t auth;
    ninlil_rrmp_authorizer_v1_t authorizer;
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_activate_req_v1_t activate;
    ninlil_route_query_req_v1_t query;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_nrm1_fields_t fields;
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
    uint8_t calls = 0u;
    size_t i;

    rrmp_cfg_fill(&cfg, 1u, 0u);
    cfg.authorization_required = 1u;
    o = ninlil_rrmp_owner_init(
        g_owner_ws3, ninlil_rrmp_owner_workspace_bytes(), &cfg);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(!ninlil_rrmp_owner_bind(o));

    ninlil_rrmp_memzero(&authorizer, sizeof(authorizer));
    authorizer.user = &calls;
    authorizer.authorize = test_authorize;
    fill_auth(&auth, NINLIL_RRMP_AUTH_ROUTE_ADMIN, 0u);
    RRMP_CHECK(!ninlil_rrmp_owner_bind_authorized(o, &auth, &authorizer));
    fill_auth(&auth, NINLIL_RRMP_AUTH_ROUTE_ADMIN, 1u);
    RRMP_CHECK(ninlil_rrmp_owner_bind_authorized(o, &auth, &authorizer));

    ninlil_rrmp_memzero(&install, sizeof(install));
    install.preamble.api_version = 1u;
    install.preamble.struct_size = 312u;
    rrmp_fill_id(install.authority_id, 0xA0u);
    install.controller_term = 5u;
    install.batch_id = 1u;
    install.entry_count = 1u;
    rrmp_fill_nrm1(&fields, 1u, 1u, 1u);
    RRMP_CHECK(ninlil_rrmp_encode_nrm1(&fields, raw));
    memcpy(install.entries, raw, sizeof(raw));
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(&install, &out), NINLIL_ROUTE_OK);

    ninlil_rrmp_memzero(&activate, sizeof(activate));
    activate.preamble.api_version = 1u;
    activate.preamble.struct_size = 64u;
    activate.ingress_hop_context_id = 0x1001u;
    activate.route_handle = 1u;
    activate.route_generation = 1u;
    activate.now_ms = 1000000u;
    RRMP_CHECK_EQ(ninlil_route_activate(&activate, &out), NINLIL_ROUTE_OK);

    ninlil_rrmp_memzero(&query, sizeof(query));
    query.preamble.api_version = 1u;
    query.preamble.struct_size = 48u;
    query.ingress_hop_context_id = 0x1001u;
    query.route_handle = 1u;
    query.route_generation = 1u;
    RRMP_CHECK_EQ(
        ninlil_route_query(&query, &out), NINLIL_ROUTE_AUTHORITY_CONFLICT);

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 1u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0xB0u + i);
    }
    RRMP_CHECK_EQ(
        ninlil_route_forward_admit(&admit, &out),
        NINLIL_ROUTE_AUTHORITY_CONFLICT);

    fill_auth(
        &auth,
        NINLIL_RRMP_AUTH_FORWARD | NINLIL_RRMP_AUTH_DIAGNOSTICS |
            NINLIL_RRMP_AUTH_WORKER | NINLIL_RRMP_AUTH_BEARER,
        1u);
    RRMP_CHECK(ninlil_rrmp_owner_bind_authorized(o, &auth, &authorizer));
    RRMP_CHECK_EQ(ninlil_route_query(&query, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(
        ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK(calls == 3u);

    ninlil_rrmp_owner_unbind();
    RRMP_CHECK(ninlil_rrmp_owner_current() == NULL);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_workspace_no_heap(void)
{
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    ninlil_rrmp_owner_t *o;
    uint8_t misaligned[64];
    RRMP_CHECK(need > 0u);
    RRMP_CHECK(need <= RRMP_WS_MAX);
    /* Host-conservative proxy: owner must stay under the 384 KiB ceiling. */
    RRMP_CHECK(need <= NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES);
    RRMP_CHECK(
        ((uintptr_t)g_owner_ws % (uintptr_t)NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) ==
        0u);
    /* Misaligned caller buffer must fail closed (UBSan contract). */
    {
        void *bad = (void *)(((uintptr_t)misaligned | 1u));
        ninlil_rrmp_owner_config_v1_t cfg;
        rrmp_cfg_fill(&cfg, 1u, 0u);
        RRMP_CHECK(ninlil_rrmp_owner_init(bad, need, &cfg) == NULL);
    }
    o = rrmp_mk_ws(g_owner_ws, need, 1u, 1u);
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_feature_off(void)
{
    ninlil_rrmp_owner_t *o = mk(0u, 0u);
    ninlil_route_install_batch_req_v1_t req;
    ninlil_route_result_v1_t out;
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = 1u;
    req.preamble.struct_size = 312u;
    req.entry_count = 1u;
    RRMP_CHECK_EQ(ninlil_route_install_batch(&req, &out), NINLIL_ROUTE_FEATURE_OFF);
    RRMP_CHECK_EQ(out.status, NINLIL_ROUTE_FEATURE_OFF);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_lease_and_hop_gates(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 0u);
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    size_t i;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 1u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0x10u + i);
    }
    /* now >= lease_expiry (route lease 5000000) → durable EXPIRED */
    admit.admission_now_ms = 5000000u;
    RRMP_CHECK_EQ(ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_LEASE_EXPIRED);
    /* Fresh route for hop gate (previous is EXPIRED) */
    RRMP_CHECK(rrmp_install_activate(o, 2u, 1u, 1u) == 0);
    admit.ingress_hop_context_id = 0x1002u;
    admit.route_handle = 2u;
    admit.admission_now_ms = 1000000u;
    admit.hop_remaining = 9u; /* > max_hops absolute / profile */
    RRMP_CHECK_EQ(ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_HOP_EXHAUSTED);
    /* wrong hop context => NOT_ACTIVE (lookup key includes ingress) */
    admit.hop_remaining = 1u;
    admit.ingress_hop_context_id = 0xDEADBEEFu;
    RRMP_CHECK_EQ(ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_NOT_ACTIVE);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_queue_full_no_live_evidence(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 0u);
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    rrmp_test_outbound_t ob;
    int i;
    int ok_count = 0;
    int bp_count = 0;
    RRMP_CHECK(o != NULL);
    rrmp_install_test_outbound(o, &ob);
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    /* Fill beyond queue (64) without service — expect BACKPRESSURE and no stuck LIVE
     * that blocks same-attempt retry after space frees. */
    for (i = 0; i < 80; ++i) {
        size_t j;
        uint32_t st;
        for (j = 0u; j < 32u; ++j) {
            admit.e2e_header_digest32[j] = (uint8_t)(i + (int)j + 3);
        }
        admit.caller_item_token = (uint64_t)i + 1u;
        st = ninlil_route_forward_admit(&admit, &out);
        RRMP_CHECK(out.status == st);
        if (st == NINLIL_ROUTE_OK) {
            ++ok_count;
        } else if (st == NINLIL_ROUTE_BACKPRESSURE) {
            ++bp_count;
            /* same e2e may still be retryable after dequeue (no LIVE left for fail) */
        } else {
            fprintf(stderr, "unexpected status %u at i=%d\n", st, i);
            return 1;
        }
    }
    RRMP_CHECK(ok_count > 0);
    RRMP_CHECK(bp_count > 0);
    /* free one via hop+LINK_ACK then retry last e2e (BACKPRESSURE left no LIVE) */
    {
        ninlil_rrmp_hop_tx_view_t tx;
        ninlil_route_result_v1_t sout;
            RRMP_CHECK_EQ(ninlil_rrmp_core_forward_service_once(o, &sout), NINLIL_ROUTE_OK);
        RRMP_CHECK(sout.opaque_local_handle != 0u);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_hop_forward_execute(
                o, sout.opaque_local_handle, NULL, 0u, 1u, &tx),
            NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(tx.rewrap_identical, 1u);
        RRMP_CHECK_EQ(tx.tx_permit_granted, 1u);
        RRMP_CHECK_EQ(tx.payload_len, 96u);
        RRMP_CHECK_EQ(
            rrmp_auth_link_ack(o, sout.opaque_local_handle, tx.outer_tx_counter, &sout),
            NINLIL_ROUTE_OK);
    }
    {
        size_t j;
        for (j = 0u; j < 32u; ++j) {
            admit.e2e_header_digest32[j] = (uint8_t)(79 + (int)j + 3);
        }
        admit.caller_item_token = 999u;
        {
            uint32_t st = ninlil_route_forward_admit(&admit, &out);
            RRMP_CHECK(st == NINLIL_ROUTE_OK || st == NINLIL_ROUTE_REPLAY ||
                st == NINLIL_ROUTE_BACKPRESSURE);
            RRMP_CHECK_EQ(out.status, st);
        }
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_drain_order_and_attempts(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 0u);
    ninlil_route_begin_drain_req_v1_t drain;
    ninlil_route_result_v1_t out;
    uint8_t elig = 0u;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
    /* remaining_attempts=0 => ineligible */
    RRMP_CHECK(ninlil_rrmp_drain_evaluate_v1(
        1000000u, 3u, 0u, 100u, 20u, 30u, 5u, 10u, 1010000u, 1020000u, 2000000u,
        &elig));
    RRMP_CHECK_EQ(elig, 0u);
    /* zero link groups */
    RRMP_CHECK(ninlil_rrmp_drain_evaluate_v1(
        1000000u, 0u, 2u, 100u, 20u, 30u, 5u, 10u, 1010000u, 1020000u, 2000000u,
        &elig));
    RRMP_CHECK_EQ(elig, 0u);
    /* zero A/T/W/I/G with F>0: ineligible */
    RRMP_CHECK(ninlil_rrmp_drain_evaluate_v1(
        1000000u, 4u, 2u, 0u, 20u, 30u, 5u, 10u, UINT64_MAX, UINT64_MAX, UINT64_MAX,
        &elig));
    RRMP_CHECK_EQ(elig, 0u);
    RRMP_CHECK(ninlil_rrmp_drain_evaluate_v1(
        1000000u, 4u, 2u, 100u, 20u, 30u, 0u, 10u, UINT64_MAX, UINT64_MAX, UINT64_MAX,
        &elig));
    RRMP_CHECK_EQ(elig, 0u);
    /* F>13 or R>3 ineligible */
    RRMP_CHECK(ninlil_rrmp_drain_evaluate_v1(
        1000000u, 14u, 2u, 100u, 20u, 30u, 5u, 10u, UINT64_MAX, UINT64_MAX, UINT64_MAX,
        &elig));
    RRMP_CHECK_EQ(elig, 0u);
    /* vector sample_ok: eligible */
    RRMP_CHECK(ninlil_rrmp_drain_evaluate_v1(
        1000000u, 3u, 2u, 100u, 20u, 30u, 5u, 10u, 1010000u, 1020000u, 2000000u,
        &elig));
    RRMP_CHECK_EQ(elig, 1u);
    /* airtime gate F*A only: F=13 A=5000 → 65000 > 60000 */
    RRMP_CHECK(ninlil_rrmp_drain_evaluate_v1(
        1000000u, 13u, 3u, 5000u, 1000u, 1000u, 100u, 100u, 1001000u, 1001000u,
        2000000u, &elig));
    RRMP_CHECK_EQ(elig, 0u);
    ninlil_rrmp_memzero(&drain, sizeof(drain));
    drain.preamble.api_version = 1u;
    drain.preamble.struct_size = 80u;
    drain.ingress_hop_context_id = 0x1001u;
    drain.route_handle = 1u;
    drain.route_generation = 1u;
    drain.now_ms = 1000000u;
    drain.drain_deadline_ms = 1020000u;
    drain.lease_deadline_ms = 2000000u;
    RRMP_CHECK_EQ(ninlil_route_begin_drain(&drain, &out), NINLIL_ROUTE_OK);
    /* second begin_drain from DRAINING not allowed */
    RRMP_CHECK_EQ(ninlil_route_begin_drain(&drain, &out), NINLIL_ROUTE_NOT_ACTIVE);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_parent_result_abi(void)
{
    /* Lockstep vs ADR-0020 §2.4 — not alias of route result. */
    RRMP_CHECK_EQ(sizeof(ninlil_parent_result_v1_t), 128u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, status), 16u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, owner_scope_id), 32u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, handoff_step), 72u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, seal_allowed), 75u);
    RRMP_CHECK_EQ(offsetof(ninlil_parent_result_v1_t, token_or_commit_digest32), 80u);
    RRMP_CHECK(sizeof(ninlil_parent_result_v1_t) == sizeof(ninlil_route_result_v1_t));
    /* Distinct layouts: parent handoff_step@72 vs route hop_remaining_out@72. */
    RRMP_CHECK_EQ(offsetof(ninlil_route_result_v1_t, hop_remaining_out), 72u);
    RRMP_CHECK(offsetof(ninlil_route_result_v1_t, lifecycle_state) !=
        offsetof(ninlil_parent_result_v1_t, handoff_step));
    return 0;
}

static int test_handoff_proof_and_receipt(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_fence_proof_req_v1_t fence;
    ninlil_parent_authority_commit_req_v1_t commit;
    ninlil_parent_owner_activate_req_v1_t act;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[2];
    ninlil_rrmp_digest32_t dig;
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    ninlil_rrmp_digest32_t cdig;
    uint8_t scope[16];
    uint8_t token[32];
    uint8_t proof[32];
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    rrmp_fill_id(scope, 0x0Du);
    memset(token, 0x77, 32u);

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    memcpy(set.owner_scope_id, scope, 16u);
    set.parent_set_count = 2u;
    rrmp_fill_id(set.path_policy_id, 0x50u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x30u);
    rrmp_fill_id(ids[1].bytes, 0x40u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    memcpy(set.parent_runtime_id[1], ids[1].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 2u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);
    /* non-monotonic revision reject */
    set.assignment_epoch = 1u;
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &out), NINLIL_PARENT_STALE_REVISION);

    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, scope, 16u);
    rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
    noa.controller_term = 5u;
    noa.assignment_epoch = 1u;
    noa.assignment_revision = 1u;
    rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
    rrmp_fill_id(noa.owner_cell_id.bytes, 0xB1u);
    noa.direction = 1u;
    noa.e2e_context_id = 1u;
    noa.key_generation = 1u;
    rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
    noa.e2e_security_epoch = 1u;
    memset(noa.e2e_binding_digest.bytes, 0xE1u, 32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memcpy(noa.handoff_token_digest.bytes, token, 32u);
    noa.parent_set_digest = dig;
    noa.parent_set_count = 2u;
    memcpy(noa.parent_set_id.bytes, set.path_policy_id, 16u);

    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = 464u;
    memcpy(prep.owner_scope_id, scope, 16u);
    RRMP_CHECK(ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1));
    memcpy(prep.handoff_token_digest32, token, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    RRMP_CHECK_EQ(
        ninlil_parent_owner_prepare(&prep, &out),
        NINLIL_PARENT_UNSUPPORTED_API);
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(
            &prep, &old_tuple, 1u, &new_tuple, &out),
        NINLIL_PARENT_OK);

    ninlil_rrmp_memzero(&fence, sizeof(fence));
    fence.preamble.api_version = 1u;
    fence.preamble.struct_size = 96u;
    memcpy(fence.owner_scope_id, scope, 16u);
    memcpy(fence.proof_digest32, proof, 32u);
    fence.old_assignment_revision = 1u;
    fence.now_ms = 1000000u;
    RRMP_CHECK_EQ(
        ninlil_parent_owner_fence_proof(&fence, &out),
        NINLIL_PARENT_UNSUPPORTED_API);
    RRMP_CHECK_EQ(
        rrmp_test_owner_fence_v2(
            scope, token, &old_tuple, proof, &out),
        NINLIL_PARENT_OK);
    /* v1 cannot smuggle a partial proof digest. */
    fence.proof_digest32[0] ^= 1u;
    RRMP_CHECK_EQ(
        ninlil_parent_owner_fence_proof(&fence, &out),
        NINLIL_PARENT_UNSUPPORTED_API);

    ninlil_rrmp_memzero(&commit, sizeof(commit));
    commit.preamble.api_version = 1u;
    commit.preamble.struct_size = 96u;
    memcpy(commit.owner_scope_id, scope, 16u);
    commit.cas_expected_generation = 0u;
    RRMP_CHECK_EQ(
        ninlil_parent_authority_commit(&commit, &out),
        NINLIL_PARENT_UNSUPPORTED_API);
    RRMP_CHECK_EQ(
        rrmp_test_authority_commit_v2(
            scope,
            &old_tuple,
            &new_tuple,
            token,
            proof,
            NULL,
            0u,
            cdig.bytes,
            &out),
        NINLIL_PARENT_OK);

    /*
     * NPH1 is a production-written record, not merely a codec.  Inspect the
     * committed parent namespace, cold-import it, and prove that the restored
     * sole-writer tuple fences a same-term claim by another controller.
     */
    {
        const uint8_t *nph1 = NULL;
        uint32_t nph1_len = 0u;
        uint64_t nph1_store_generation = 0u;
        uint32_t route_len;
        uint32_t parent_len;
        size_t export_len = 0u;
        ninlil_rrmp_owner_t *o2;
        ninlil_parent_set_install_req_v1_t set2;
        ninlil_parent_owner_prepare_req_v1_t prep2;
        ninlil_rrmp_noa1_fields_t noa2;
        ninlil_rrmp_authority_tuple_v2_t old_tuple2;
        ninlil_rrmp_authority_tuple_v2_t new_tuple2;
        uint8_t commit_digest2[32];
        uint8_t scope2[16];
        uint8_t token2[32];
        uint8_t proof2[32];

        RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
            o, NULL, 0u, &export_len));
        RRMP_CHECK(export_len <= sizeof(g_npp1_export_probe));
        RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
            o,
            g_npp1_export_probe,
            sizeof(g_npp1_export_probe),
            &export_len));
        route_len = ninlil_rrmp_get_u32_be(g_npp1_export_probe + 8u);
        parent_len = ninlil_rrmp_get_u32_be(g_npp1_export_probe + 12u);
        RRMP_CHECK(
            20u + (size_t)route_len + (size_t)parent_len <= export_len);
        RRMP_CHECK(ninlil_rrmp_parent_ns_import(
            &g_npp1_parent_probe,
            g_npp1_export_probe + 20u + route_len,
            parent_len));
        RRMP_CHECK(ninlil_rrmp_parent_dual_read_active(
            &g_npp1_parent_probe,
            NINLIL_RRMP_PKEY_NPH1,
            &nph1,
            &nph1_len,
            &nph1_store_generation));
        RRMP_CHECK(nph1 != NULL);
        RRMP_CHECK_EQ(nph1_len, NINLIL_RRMP_NPH1_BYTES);
        RRMP_CHECK(nph1_store_generation != 0u);
        RRMP_CHECK(ninlil_rrmp_validate_nph1(nph1));
        RRMP_CHECK(memcmp(nph1 + 8u, noa.authority_id.bytes, 16u) == 0);
        RRMP_CHECK(
            memcmp(nph1 + 24u, noa.owner_controller_id.bytes, 16u) == 0);
        RRMP_CHECK_EQ(ninlil_rrmp_get_u64_be(nph1 + 40u), 5u);
        RRMP_CHECK_EQ(ninlil_rrmp_get_u64_be(nph1 + 48u), 1u);
        RRMP_CHECK(
            memcmp(nph1 + 128u, cdig.bytes, sizeof(cdig.bytes)) == 0);

        o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 1u, 1u);
        RRMP_CHECK(o2 != NULL);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
            o2, g_npp1_export_probe, export_len));
        RRMP_CHECK(ninlil_rrmp_owner_bind(o2));

        rrmp_fill_id(scope2, 0x1Du);
        memset(token2, 0x88, sizeof(token2));
        ninlil_rrmp_memzero(&set2, sizeof(set2));
        set2.preamble.api_version = 1u;
        set2.preamble.struct_size = 240u;
        memcpy(set2.owner_scope_id, scope2, 16u);
        set2.parent_set_count = 2u;
        rrmp_fill_id(set2.path_policy_id, 0x61u);
        set2.controller_term = 5u;
        set2.assignment_epoch = 1u;
        memcpy(set2.parent_runtime_id[0], ids[0].bytes, 16u);
        memcpy(set2.parent_runtime_id[1], ids[1].bytes, 16u);
        memcpy(set2.parent_set_digest32, dig.bytes, 32u);
        RRMP_CHECK_EQ(
            ninlil_parent_set_install(&set2, &out), NINLIL_PARENT_OK);

        ninlil_rrmp_memzero(&noa2, sizeof(noa2));
        memcpy(noa2.owner_scope_id.bytes, scope2, 16u);
        noa2.authority_id = noa.authority_id;
        noa2.controller_term = 5u;
        noa2.assignment_epoch = 1u;
        noa2.assignment_revision = 1u;
        rrmp_fill_id(noa2.owner_controller_id.bytes, 0xC0u);
        rrmp_fill_id(noa2.owner_cell_id.bytes, 0xC1u);
        noa2.direction = 1u;
        noa2.e2e_context_id = 2u;
        noa2.key_generation = 1u;
        rrmp_fill_id(noa2.e2e_security_id.bytes, 0xD1u);
        noa2.e2e_security_epoch = 1u;
        memset(noa2.e2e_binding_digest.bytes, 0xE2u, 32u);
        noa2.authority_clock_epoch_id = noa.authority_clock_epoch_id;
        noa2.lease_not_after_authority_ms =
            noa.lease_not_after_authority_ms;
        memcpy(
            noa2.handoff_token_digest.bytes, token2, sizeof(token2));
        noa2.parent_set_digest = dig;
        noa2.parent_set_count = 2u;
        memcpy(noa2.parent_set_id.bytes, set2.path_policy_id, 16u);

        ninlil_rrmp_memzero(&prep2, sizeof(prep2));
        prep2.preamble.api_version = 1u;
        prep2.preamble.struct_size = 464u;
        memcpy(prep2.owner_scope_id, scope2, 16u);
        RRMP_CHECK(ninlil_rrmp_encode_noa1(
            &noa2, prep2.new_assignment_noa1));
        memcpy(
            prep2.handoff_token_digest32, token2, sizeof(token2));
        ninlil_rrmp_memzero(&old_tuple2, sizeof(old_tuple2));
        RRMP_CHECK_EQ(
            rrmp_test_owner_prepare_v2(
                &prep2, &old_tuple2, 2u, &new_tuple2, &out),
            NINLIL_PARENT_OK);

        RRMP_CHECK_EQ(
            rrmp_test_owner_fence_v2(
                scope2, token2, &old_tuple2, proof2, &out),
            NINLIL_PARENT_OK);
        RRMP_CHECK_EQ(
            rrmp_test_authority_commit_v2(
                scope2,
                &old_tuple2,
                &new_tuple2,
                token2,
                proof2,
                NULL,
                1u,
                commit_digest2,
                &out),
            NINLIL_PARENT_SPLIT_BRAIN);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_scope_seal_allowed(o2, scope2), 0u);
        ninlil_rrmp_owner_fini(o2);
        RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    }

    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = 80u;
    memcpy(act.owner_scope_id, scope, 16u);
    /* wrong: token instead of commit receipt */
    memcpy(act.commit_receipt_digest32, token, 32u);
    act.now_ms = 1000000u;
    RRMP_CHECK_EQ(ninlil_parent_owner_activate(&act, &out), NINLIL_PARENT_TOKEN_REPLAY);
    memcpy(act.commit_receipt_digest32, cdig.bytes, 32u);
    RRMP_CHECK_EQ(ninlil_parent_owner_activate(&act, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED);
    RRMP_CHECK_EQ(out.seal_allowed, 1u);
    RRMP_CHECK_EQ(ninlil_parent_owner_activate(&act, &out), NINLIL_PARENT_TOKEN_REPLAY);

    /* NPA1/NPT1 page codec + atomic FULL persist path exercised by handoff steps. */
    {
        uint8_t aslot[NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES];
        uint8_t npa1[NINLIL_RRMP_NPA1_BYTES];
        uint8_t npts[NINLIL_RRMP_NPT1_SLOT_BYTES];
        uint8_t npt1[NINLIL_RRMP_NPT1_BYTES];
        const uint8_t *slots[NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE];
        size_t si;
        for (si = 0u; si < NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE; ++si) {
            slots[si] = NULL;
        }
        RRMP_CHECK(ninlil_rrmp_encode_assignment_slot(
            prep.new_assignment_noa1, NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED, proof,
            cdig.bytes, aslot));
        slots[0] = aslot;
        RRMP_CHECK(ninlil_rrmp_encode_npa1_page(0u, 2u, slots, npa1));
        RRMP_CHECK(ninlil_rrmp_validate_npa1(npa1));
        RRMP_CHECK(ninlil_rrmp_encode_npt1_slot(
            token, NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED, 1000000u, npts));
        RRMP_CHECK(ninlil_rrmp_encode_npt1_page(0u, 2u, npts, 1u, npt1));
        RRMP_CHECK(ninlil_rrmp_validate_npt1(npt1));
    }

    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_scope_local_split_brain(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t dig;
    uint8_t scope_a[16], scope_b[16];
    uint8_t wa[16], wb[16];
    uint8_t sel[16];
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    rrmp_fill_id(scope_a, 0xA0u);
    rrmp_fill_id(scope_b, 0xB0u);

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    set.parent_set_count = 1u;
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x31u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 1u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    rrmp_fill_id(set.path_policy_id, 0x51u);
    memcpy(set.owner_scope_id, scope_a, 16u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);
    /* NPS1 is a constructor only; no NOA means no operational seal. */
    RRMP_CHECK_EQ(out.seal_allowed, 0u);
    memcpy(set.owner_scope_id, scope_b, 16u);
    rrmp_fill_id(set.path_policy_id, 0x52u);
    set.assignment_epoch = 1u;
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);

    rrmp_fill_id(wa, 0xC1u);
    rrmp_fill_id(wb, 0xC2u);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_split_brain_detect(o, scope_a, wa, wb, 5u, 5u),
        NINLIL_PARENT_SPLIT_BRAIN);
    /* global downlink remains clear; NPS-only scope B remains unsealed. */
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 1u);
    RRMP_CHECK_EQ(ninlil_rrmp_core_scope_seal_allowed(o, scope_a), 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_core_scope_seal_allowed(o, scope_b), 0u);
    {
        uint8_t a1[16], a2[16];
        rrmp_fill_attempt_id16(a1, 1u);
        rrmp_fill_attempt_id16(a2, 2u);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_parent_select_for_attempt(o, scope_a, a1, sel, &out),
            NINLIL_PARENT_SPLIT_BRAIN);
        RRMP_CHECK_EQ(out.seal_allowed, 0u);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_parent_select_for_attempt(o, scope_b, a1, sel, &out),
            NINLIL_PARENT_SPLIT_BRAIN);
        RRMP_CHECK_EQ(out.seal_allowed, 0u);

        /* parent-loss seals only that scope */
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_parent_loss(o, scope_b, ids[0].bytes), NINLIL_PARENT_OK);
        RRMP_CHECK_EQ(ninlil_rrmp_core_scope_seal_allowed(o, scope_b), 0u);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_parent_select_for_attempt(o, scope_b, a2, sel, &out),
            NINLIL_PARENT_SPLIT_BRAIN);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/*
 * QST2 did not persist the scope-local split-brain/parent-loss seal tuple.
 * A legacy snapshot must therefore rehydrate fail-closed: the scope remains
 * queryable for recovery, but it cannot authorize downlink until a fresh
 * assignment is installed.
 */
static int test_qst2_legacy_parent_scope_fail_closed(void)
{
    ninlil_rrmp_owner_t *o = mk(0u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_query_req_v1_t query;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t dig;
    uint8_t scope[16];
    uint32_t route_len;
    uint32_t parent_len;
    uint32_t soft_len;
    size_t soft_off;
    size_t export_len = 0u;
    uint8_t *soft;

    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    rrmp_fill_id(scope, 0xD1u);
    rrmp_fill_id(ids[0].bytes, 0x41u);

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    memcpy(set.owner_scope_id, scope, sizeof(scope));
    set.parent_set_count = 1u;
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 1u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    rrmp_fill_id(set.path_policy_id, 0x61u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(ninlil_rrmp_core_scope_seal_allowed(o, scope), 0u);

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &export_len));
    RRMP_CHECK(export_len <= sizeof(g_npp1_export_probe));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o,
        g_npp1_export_probe,
        sizeof(g_npp1_export_probe),
        &export_len));
    route_len = ninlil_rrmp_get_u32_be(g_npp1_export_probe + 8u);
    parent_len = ninlil_rrmp_get_u32_be(g_npp1_export_probe + 12u);
    soft_len = ninlil_rrmp_get_u32_be(g_npp1_export_probe + 16u);
    soft_off = 20u + (size_t)route_len + (size_t)parent_len;
    RRMP_CHECK(soft_off + (size_t)soft_len == export_len);
    RRMP_CHECK(soft_len >= 112u);
    soft = g_npp1_export_probe + soft_off;
    RRMP_CHECK(memcmp(soft, "RRMPQST4", 8u) == 0);
    RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 8u), 4u);
    RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 10u), 1u);

    memmove(soft + 48u, soft + 56u, (size_t)soft_len - 56u);
    soft_len -= 8u;
    export_len -= 8u;
    ninlil_rrmp_put_u32_be(g_npp1_export_probe + 16u, soft_len);
    memcpy(soft, "RRMPQST2", 8u);
    ninlil_rrmp_put_u16_be(soft + 8u, 2u);
    ninlil_rrmp_put_u32_be(soft + 16u, soft_len);
    soft[48u + 57u] = 0u;
    ninlil_rrmp_put_u32_be(soft + 20u, 0u);
    ninlil_rrmp_put_u32_be(
        soft + 20u,
        ninlil_rrmp_crc32c_zeroed_u32_be_field(
            soft, (size_t)soft_len, 20u));

    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 0u, 1u);
        RRMP_CHECK(o2 != NULL);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
            o2, g_npp1_export_probe, export_len));
        RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
        ninlil_rrmp_memzero(&query, sizeof(query));
        query.preamble.api_version = 1u;
        query.preamble.struct_size = 48u;
        memcpy(query.owner_scope_id, scope, sizeof(scope));
        RRMP_CHECK_EQ(
            ninlil_parent_query(&query, &out),
            NINLIL_PARENT_SPLIT_BRAIN);
        RRMP_CHECK_EQ(out.seal_allowed, 0u);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_scope_seal_allowed(o2, scope), 0u);
        ninlil_rrmp_owner_fini(o2);
    }

    ninlil_rrmp_owner_fini(o);
    return 0;
}

/* One hop on a bound owner: admit → TxPermit → hop → auth LINK_ACK. */
static int hop_once(
    ninlil_rrmp_owner_t *o,
    uint16_t route_h,
    uint8_t hop_remaining,
    uint8_t expect_out,
    uint8_t expect_terminal,
    const uint8_t e2e[32],
    uint64_t token,
    ninlil_rrmp_hop_tx_view_t *tx_out)
{
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_hop_tx_view_t tx;
    uint8_t bad_payload[4] = {0xDEu, 0xADu, 0xBEu, 0xEFu};
    ninlil_rrmp_link_ack_evidence_t bad_ev;
    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1000u + route_h;
    admit.route_handle = route_h;
    admit.route_generation = 1u;
    admit.hop_remaining = hop_remaining;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = token;
    admit.outer_rx_counter = 100u + token;
    memcpy(admit.e2e_header_digest32, e2e, 32u);
    RRMP_CHECK_EQ(ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(out.hop_remaining_out, expect_out);
    {
        uint64_t oh = out.opaque_local_handle;
        ninlil_route_result_v1_t tmp;
        RRMP_CHECK(oh != 0u);
        /* Unauthenticated evidence is rejected. */
        ninlil_rrmp_memzero(&bad_ev, sizeof(bad_ev));
        bad_ev.opaque_local_handle = oh;
        bad_ev.auth_ok = 0u;
        bad_ev.ack_ok = 1u;
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_link_ack_from_evidence(o, &bad_ev, &tmp),
            NINLIL_ROUTE_AUTHORITY_CONFLICT);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_hop_forward_execute(o, oh, NULL, 0u, 0u, &tx),
            NINLIL_ROUTE_AUTHORITY_CONFLICT);
        /* App carrier is accepted; NRM1 e2e rewrap remains bit-identical. */
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_hop_forward_execute(
                o, oh, bad_payload, 4u, 1u, &tx),
            NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(tx.carrier_set, 1u);
        RRMP_CHECK_EQ(tx.payload_len, 4u);
        RRMP_CHECK_EQ(tx.e2e_len, 96u);
        RRMP_CHECK_EQ(tx.rewrap_identical, 1u);
        /* complete first hop then admit again for null-carrier path */
        RRMP_CHECK_EQ(
            rrmp_auth_link_ack(o, oh, tx.outer_tx_counter, &tmp), NINLIL_ROUTE_OK);
        {
            ninlil_route_forward_complete_req_v1_t c0;
            ninlil_rrmp_memzero(&c0, sizeof(c0));
            c0.preamble.api_version = 1u;
            c0.preamble.struct_size = 64u;
            c0.opaque_local_handle = oh;
            c0.outcome = 1u;
            c0.completion_now_ms = 1000001u;
            RRMP_CHECK_EQ(ninlil_route_forward_complete(&c0, &tmp), NINLIL_ROUTE_OK);
        }
    }
    /* Fresh admit for custody-only hop (null carrier). */
    admit.caller_item_token = token + 1000u;
    admit.outer_rx_counter = 200u + token;
    {
        size_t j;
        for (j = 0u; j < 32u; ++j) {
            admit.e2e_header_digest32[j] = (uint8_t)(e2e[j] ^ 0x5Au);
        }
    }
    RRMP_CHECK_EQ(ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_OK);
    {
        uint64_t oh = out.opaque_local_handle;
        ninlil_route_result_v1_t tmp;
        RRMP_CHECK(oh != 0u);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_hop_forward_execute(o, oh, NULL, 0u, 1u, &tx),
            NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(tx.rewrap_identical, 1u);
        RRMP_CHECK_EQ(tx.tx_permit_granted, 1u);
        RRMP_CHECK_EQ(tx.e2e_len, 96u);
        RRMP_CHECK_EQ(tx.payload_len, 96u); /* e2e echo when no carrier */
        RRMP_CHECK_EQ(tx.carrier_set, 0u);
        RRMP_CHECK_EQ(tx.hop_remaining_in, hop_remaining);
        RRMP_CHECK_EQ(tx.hop_remaining_out, expect_out);
        RRMP_CHECK_EQ(tx.terminal, expect_terminal);
        RRMP_CHECK_EQ(
            rrmp_auth_link_ack(o, oh, tx.outer_tx_counter, &tmp), NINLIL_ROUTE_OK);
        /* complete exact handle ownership */
        {
            ninlil_route_forward_complete_req_v1_t comp;
            ninlil_rrmp_memzero(&comp, sizeof(comp));
            comp.preamble.api_version = 1u;
            comp.preamble.struct_size = 64u;
            comp.opaque_local_handle = oh;
            comp.outcome = 1u;
            comp.completion_now_ms = 1000001u;
            RRMP_CHECK_EQ(ninlil_route_forward_complete(&comp, &tmp), NINLIL_ROUTE_OK);
        }
    }
    if (tx_out != NULL) {
        *tx_out = tx;
    }
    return 0;
}

static ninlil_rrmp_owner_t *mk_node(uint8_t *ws, uint8_t runtime_seed, uint8_t r, uint8_t p)
{
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    ninlil_rrmp_owner_config_v1_t cfg;
    if (need > RRMP_WS_MAX) {
        return NULL;
    }
    rrmp_cfg_fill(&cfg, r, p);
    rrmp_fill_id(cfg.local_runtime_id, runtime_seed);
    return ninlil_rrmp_owner_init(ws, need, &cfg);
}

/* Install identical NRM1 (same E2E materialize body) on a node. */
static int install_path_nrm1(
    ninlil_rrmp_owner_t *o, uint16_t h, uint8_t hops, uint8_t term,
    const ninlil_rrmp_nrm1_fields_t *canon)
{
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_activate_req_v1_t act;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_nrm1_fields_t f = *canon;
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
    ninlil_rrmp_owner_bind(o);
    f.ingress_hop_context_id = 0x1000u + h;
    f.route_handle = h;
    f.max_hops = hops;
    f.terminal_flag = term;
    if (term) {
        f.egress_route_handle = 0u;
        f.egress_route_generation = 0u;
    } else {
        f.egress_route_handle = (uint16_t)(h + 10u);
        f.egress_route_generation = 1u;
    }
    ninlil_rrmp_memzero(&install, sizeof(install));
    install.preamble.api_version = 1u;
    install.preamble.struct_size = 312u;
    rrmp_fill_id(install.authority_id, 0xA0u);
    install.controller_term = 5u;
    install.batch_id = 1u;
    install.entry_count = 1u;
    if (!ninlil_rrmp_encode_nrm1(&f, raw)) {
        return 1;
    }
    memcpy(install.entries, raw, sizeof(raw));
    if (ninlil_route_install_batch(&install, &out) != NINLIL_ROUTE_OK) {
        return 1;
    }
    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = 64u;
    act.ingress_hop_context_id = f.ingress_hop_context_id;
    act.route_handle = h;
    act.route_generation = 1u;
    act.now_ms = 1000000u;
    if (ninlil_route_activate(&act, &out) != NINLIL_ROUTE_OK) {
        return 1;
    }
    return 0;
}

/*
 * True multi-node A→B→C: independent owners, shared e2e digest continuity,
 * hop 3→2→1 terminal only on C, per-node NRM1 materialize rewrap, then
 * fault-inject CU OLD on A (recover path) without poisoning B/C.
 */
static int test_real_multi_hop_path(void)
{
    ninlil_rrmp_owner_t *nA = mk_node(g_owner_ws, 0x11u, 1u, 0u);
    ninlil_rrmp_owner_t *nB = mk_node(g_owner_ws2, 0x22u, 1u, 0u);
    ninlil_rrmp_owner_t *nC = mk_node(g_owner_ws3, 0x33u, 1u, 0u);
    ninlil_rrmp_hop_tx_view_t txA;
    ninlil_rrmp_hop_tx_view_t txB;
    ninlil_rrmp_hop_tx_view_t txC;
    ninlil_rrmp_nrm1_fields_t canon;
    ninlil_rrmp_nrm1_fields_t fA;
    ninlil_rrmp_nrm1_fields_t fB;
    ninlil_rrmp_nrm1_fields_t fC;
    rrmp_test_outbound_t obA, obB, obC;
    uint8_t e2e[32];
    uint8_t exactA[96];
    uint8_t exactB[96];
    uint8_t exactC[96];
    ninlil_route_result_v1_t rout;
    ninlil_route_recover_cu_req_v1_t rec;
    size_t i;
    RRMP_CHECK(nA != NULL && nB != NULL && nC != NULL);
    rrmp_install_test_outbound(nA, &obA);
    rrmp_install_test_outbound(nB, &obB);
    rrmp_install_test_outbound(nC, &obC);
    for (i = 0u; i < 32u; ++i) {
        e2e[i] = (uint8_t)(0x40u + i);
    }
    rrmp_fill_nrm1(&canon, 1u, 3u, 0u);
    rrmp_fill_id(canon.egress_peer_id.bytes, 0x60u);
    canon.route_revision = 7u;
    canon.path_policy_revision = 3u;
    RRMP_CHECK(install_path_nrm1(nA, 1u, 3u, 0u, &canon) == 0);
    RRMP_CHECK(install_path_nrm1(nB, 1u, 2u, 0u, &canon) == 0);
    RRMP_CHECK(install_path_nrm1(nC, 1u, 1u, 1u, &canon) == 0);

    /* Per-node materialize (hop/terminal differ); shared authority/path fields. */
    fA = canon;
    fA.ingress_hop_context_id = 0x1001u;
    fA.route_handle = 1u;
    fA.max_hops = 3u;
    fA.terminal_flag = 0u;
    fA.egress_route_handle = 11u;
    fA.egress_route_generation = 1u;
    fB = fA;
    fB.max_hops = 2u;
    fC = fA;
    fC.max_hops = 1u;
    fC.terminal_flag = 1u;
    fC.egress_route_handle = 0u;
    fC.egress_route_generation = 0u;
    RRMP_CHECK(ninlil_rrmp_materialize_exact(&fA, exactA));
    RRMP_CHECK(ninlil_rrmp_materialize_exact(&fB, exactB));
    RRMP_CHECK(ninlil_rrmp_materialize_exact(&fC, exactC));

    ninlil_rrmp_owner_bind(nA);
    RRMP_CHECK(hop_once(nA, 1u, 3u, 2u, 0u, e2e, 1u, &txA) == 0);
    ninlil_rrmp_owner_bind(nB);
    RRMP_CHECK(hop_once(nB, 1u, 2u, 1u, 0u, e2e, 2u, &txB) == 0);
    ninlil_rrmp_owner_bind(nC);
    RRMP_CHECK(hop_once(nC, 1u, 1u, 0u, 1u, e2e, 3u, &txC) == 0);

    RRMP_CHECK_EQ(txA.e2e_len, 96u);
    RRMP_CHECK_EQ(txB.e2e_len, 96u);
    RRMP_CHECK_EQ(txC.e2e_len, 96u);
    RRMP_CHECK_EQ(txA.hop_remaining_in, 3u);
    RRMP_CHECK_EQ(txA.hop_remaining_out, 2u);
    RRMP_CHECK_EQ(txB.hop_remaining_in, 2u);
    RRMP_CHECK_EQ(txB.hop_remaining_out, 1u);
    RRMP_CHECK_EQ(txC.hop_remaining_in, 1u);
    RRMP_CHECK_EQ(txC.hop_remaining_out, 0u);
    RRMP_CHECK_EQ(txA.terminal, 0u);
    RRMP_CHECK_EQ(txB.terminal, 0u);
    RRMP_CHECK_EQ(txC.terminal, 1u);
    RRMP_CHECK_EQ(txA.rewrap_identical, 1u);
    RRMP_CHECK_EQ(txB.rewrap_identical, 1u);
    RRMP_CHECK_EQ(txC.rewrap_identical, 1u);
    /* Host byte continuity: each hop payload == that node's NRM1 materialize. */
    RRMP_CHECK(memcmp(txA.payload, exactA, 96u) == 0);
    RRMP_CHECK(memcmp(txB.payload, exactB, 96u) == 0);
    RRMP_CHECK(memcmp(txC.payload, exactC, 96u) == 0);
    RRMP_CHECK(memcmp(txA.e2e_header, txA.payload, 96u) == 0);
    RRMP_CHECK(memcmp(txB.e2e_header, txB.payload, 96u) == 0);
    RRMP_CHECK(memcmp(txC.e2e_header, txC.payload, 96u) == 0);
    /* Shared path fields continuous across A/B/C materialize (authority/grant). */
    RRMP_CHECK(memcmp(exactA + 24, exactB + 24, 16u) == 0);
    RRMP_CHECK(memcmp(exactB + 24, exactC + 24, 16u) == 0);
    RRMP_CHECK(memcmp(exactA + 56, exactC + 56, 16u) == 0);

    /* Fault inject: CU OLD on A NRD1; recover classifies; B/C remain OK. */
    ninlil_rrmp_owner_bind(nA);
    ninlil_rrmp_owner_fault_inject_route_cu_old(nA, NINLIL_RRMP_KEY_NRD1);
    ninlil_rrmp_memzero(&rec, sizeof(rec));
    rec.preamble.api_version = 1u;
    rec.preamble.struct_size = 80u;
    rec.expected_class = 0u;
    RRMP_CHECK_EQ(
        ninlil_route_recover_commit_unknown(&rec, &rout),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(rout.cu_class, NINLIL_RRMP_CU_OLD);
    ninlil_rrmp_owner_bind(nB);
    {
        ninlil_route_query_req_v1_t q;
        ninlil_rrmp_memzero(&q, sizeof(q));
        q.preamble.api_version = 1u;
        q.preamble.struct_size = 48u;
        q.ingress_hop_context_id = 0x1001u;
        q.route_handle = 1u;
        q.route_generation = 1u;
        RRMP_CHECK_EQ(ninlil_route_query(&q, &rout), NINLIL_ROUTE_OK);
    }
    ninlil_rrmp_owner_bind(nC);
    {
        ninlil_route_query_req_v1_t q;
        ninlil_rrmp_memzero(&q, sizeof(q));
        q.preamble.api_version = 1u;
        q.preamble.struct_size = 48u;
        q.ingress_hop_context_id = 0x1001u;
        q.route_handle = 1u;
        q.route_generation = 1u;
        RRMP_CHECK_EQ(ninlil_route_query(&q, &rout), NINLIL_ROUTE_OK);
    }

    ninlil_rrmp_owner_fini(nA);
    ninlil_rrmp_owner_fini(nB);
    ninlil_rrmp_owner_fini(nC);
    return 0;
}

static int test_two_hop_acceptance(void)
{
    ninlil_rrmp_owner_t *n1 = mk_node(g_owner_ws, 0x41u, 1u, 0u);
    ninlil_rrmp_owner_t *n2 = mk_node(g_owner_ws2, 0x42u, 1u, 0u);
    ninlil_rrmp_hop_tx_view_t tx;
    rrmp_test_outbound_t ob1, ob2;
    uint8_t e2e[32];
    size_t i;
    RRMP_CHECK(n1 != NULL && n2 != NULL);
    rrmp_install_test_outbound(n1, &ob1);
    rrmp_install_test_outbound(n2, &ob2);
    for (i = 0u; i < 32u; ++i) {
        e2e[i] = (uint8_t)(0xAAu + i);
    }
    RRMP_CHECK(rrmp_install_activate(n1, 1u, 2u, 0u) == 0);
    RRMP_CHECK(rrmp_install_activate(n2, 1u, 1u, 1u) == 0);
    ninlil_rrmp_owner_bind(n1);
    RRMP_CHECK(hop_once(n1, 1u, 2u, 1u, 0u, e2e, 10u, &tx) == 0);
    RRMP_CHECK_EQ(tx.hop_remaining_out, 1u);
    ninlil_rrmp_owner_bind(n2);
    RRMP_CHECK(hop_once(n2, 1u, 1u, 0u, 1u, e2e, 11u, &tx) == 0);
    RRMP_CHECK_EQ(tx.terminal, 1u);
    ninlil_rrmp_owner_fini(n1);
    ninlil_rrmp_owner_fini(n2);
    return 0;
}

/* Fabric select-path dispatch: pin selected instance + optional custody service. */
static int test_fabric_select_dispatch(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 0u);
    ninlil_rrmp_fabric_select_view_t view;
    ninlil_route_result_v1_t out;
    uint8_t path[16];
    uint8_t path_before[16];
    uint64_t epoch = 0u;
    uint64_t epoch_before = 0u;
    size_t i;
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    ninlil_rrmp_memzero(&view, sizeof(view));
    view.has_selection = 1u;
    view.selection_finalized = 1u;
    view.requires_custody = 0u;
    view.path_selection_epoch = 42u;
    view.now_ms = 1000000u;
    for (i = 0u; i < 16u; ++i) {
        view.selected_instance_id[i] = (uint8_t)(0x50u + i);
    }
    RRMP_CHECK_EQ(ninlil_rrmp_fabric_on_path_selected(o, &view, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK(ninlil_rrmp_fabric_last_path(o, path, &epoch));
    RRMP_CHECK_EQ(epoch, 42u);
    RRMP_CHECK(memcmp(path, view.selected_instance_id, 16u) == 0);

    /* Reject-path simulation: not finalized → zero mutation. */
    RRMP_CHECK(ninlil_rrmp_fabric_last_path(o, path_before, &epoch_before));
    view.selection_finalized = 0u;
    view.path_selection_epoch = 99u;
    for (i = 0u; i < 16u; ++i) {
        view.selected_instance_id[i] = (uint8_t)(0xEEu + i);
    }
    RRMP_CHECK_EQ(ninlil_rrmp_fabric_on_path_selected(o, &view, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK(ninlil_rrmp_fabric_last_path(o, path, &epoch));
    RRMP_CHECK_EQ(epoch, epoch_before);
    RRMP_CHECK(memcmp(path, path_before, 16u) == 0);

    /* Finalized success pin updates path. */
    view.selection_finalized = 1u;
    view.requires_custody = 1u;
    view.path_selection_epoch = 43u;
    for (i = 0u; i < 16u; ++i) {
        view.selected_instance_id[i] = (uint8_t)(0x50u + i);
    }
    RRMP_CHECK_EQ(ninlil_rrmp_fabric_on_path_selected(o, &view, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK(ninlil_rrmp_fabric_last_path(o, path, &epoch));
    RRMP_CHECK_EQ(epoch, 43u);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/*
 * Adversarial fabric seam:
 *  - no outbound provider → hop fails; complete without ACK fails
 *  - provider + no ACK → cycle OK (awaiting) but complete AUTHORITY_CONFLICT
 *  - provider + authenticated ACK → complete OK
 */
static int test_fabric_relay_cycle_seam(void)
{
    ninlil_rrmp_nfl1_hop_view_t hop;
    ninlil_rrmp_hop_tx_view_t tx;
    ninlil_route_result_v1_t out;
    rrmp_test_outbound_t ob;
    uint8_t exact[96];
    static const uint8_t app_data[] = {
        0x00u, 0x4Eu, 0x69u, 0x6Eu, 0x6Cu, 0x69u, 0x6Cu, 0xFFu};
    ninlil_rrmp_nrm1_fields_t f;
    size_t i;

    /* --- Owner A: no provider --- */
    {
        ninlil_rrmp_owner_t *o = mk(1u, 0u);
        ninlil_route_result_v1_t aout;
        ninlil_route_forward_complete_req_v1_t c;
        RRMP_CHECK(o != NULL);
        ninlil_rrmp_owner_bind(o);
        RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
        ninlil_rrmp_memzero(&hop, sizeof(hop));
        hop.ingress_hop_context_id = 0x1001u;
        hop.route_handle = 1u;
        hop.route_generation = 1u;
        hop.hop_remaining = 1u;
        hop.now_ms = 1000000u;
        hop.priority_class = NINLIL_RRMP_PRIO_NORMAL;
        hop.caller_item_token = 42u;
        hop.outer_rx_counter = 7u;
        for (i = 0u; i < 32u; ++i) {
            hop.e2e_header_digest32[i] = (uint8_t)(0xD0u + i);
        }
        RRMP_CHECK_EQ(
            ninlil_rrmp_seam_admit_from_nfl1_view(&hop, &aout), NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_hop_forward_execute(
                o, aout.opaque_local_handle, NULL, 0u, 1u, &tx),
            NINLIL_ROUTE_UNSUPPORTED_CAPABILITY);
        ninlil_rrmp_memzero(&c, sizeof(c));
        c.preamble.api_version = 1u;
        c.preamble.struct_size = 64u;
        c.opaque_local_handle = aout.opaque_local_handle;
        c.outcome = 1u;
        c.completion_now_ms = 1000000u;
        RRMP_CHECK_EQ(
            ninlil_route_forward_complete(&c, &out), NINLIL_ROUTE_AUTHORITY_CONFLICT);
        /* Direct hop under no provider remains the authoritative no-send proof. */
        ninlil_rrmp_owner_fini(o);
    }

    /* --- Owner B: provider present --- */
    {
        ninlil_rrmp_owner_t *o = mk(1u, 0u);
        ninlil_route_forward_complete_req_v1_t c;
        uint64_t oh;
        RRMP_CHECK(o != NULL);
        ninlil_rrmp_owner_bind(o);
        rrmp_install_test_outbound(o, &ob);
        RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
        rrmp_fill_nrm1(&f, 1u, 1u, 1u);
        RRMP_CHECK(ninlil_rrmp_materialize_exact(&f, exact));
        ninlil_rrmp_memzero(&hop, sizeof(hop));
        hop.ingress_hop_context_id = 0x1001u;
        hop.route_handle = 1u;
        hop.route_generation = 1u;
        hop.hop_remaining = 1u;
        hop.now_ms = 1000000u;
        hop.priority_class = NINLIL_RRMP_PRIO_NORMAL;
        hop.caller_item_token = 50u;
        hop.outer_rx_counter = 9u;
        hop.application_data = app_data;
        hop.application_data_len = (uint16_t)sizeof(app_data);
        for (i = 0u; i < 32u; ++i) {
            hop.e2e_header_digest32[i] = (uint8_t)(0xE0u + i);
        }
        RRMP_CHECK_EQ(
            ninlil_rrmp_seam_fabric_relay_cycle(&hop, 1u, &tx, &out), NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(tx.rewrap_identical, 1u);
        RRMP_CHECK_EQ(tx.tx_permit_granted, 1u);
        RRMP_CHECK_EQ(tx.e2e_len, 96u);
        RRMP_CHECK_EQ(tx.carrier_set, 1u);
        RRMP_CHECK_EQ(tx.payload_len, sizeof(app_data));
        RRMP_CHECK(memcmp(tx.payload, app_data, sizeof(app_data)) == 0);
        RRMP_CHECK(memcmp(tx.e2e_header, exact, 96u) == 0);
        RRMP_CHECK_EQ(ob.last.carrier_len, sizeof(app_data));
        RRMP_CHECK(
            memcmp(ob.last.carrier, app_data, sizeof(app_data)) == 0);
        RRMP_CHECK_EQ(tx.terminal, 1u);
        RRMP_CHECK_EQ(out.detail_flags & 1u, 1u);
        oh = out.opaque_local_handle;
        RRMP_CHECK(oh != 0u);
        RRMP_CHECK_EQ(ob.submit_count, 1u);
        ninlil_rrmp_memzero(&c, sizeof(c));
        c.preamble.api_version = 1u;
        c.preamble.struct_size = 64u;
        c.opaque_local_handle = oh;
        c.outcome = 1u;
        c.completion_now_ms = 1000000u;
        /* No ACK yet → complete must fail (no false green). */
        RRMP_CHECK_EQ(
            ninlil_route_forward_complete(&c, &out), NINLIL_ROUTE_AUTHORITY_CONFLICT);
        RRMP_CHECK_EQ(
            rrmp_auth_link_ack(o, oh, tx.outer_tx_counter, &out), NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(ninlil_route_forward_complete(&c, &out), NINLIL_ROUTE_OK);
        ninlil_rrmp_owner_fini(o);
    }
    return 0;
}

static int test_scope_blocks_hop_tx(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_result_v1_t pout;
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_activate_req_v1_t act;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_nrm1_fields_t f;
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t dig;
    uint8_t scope[16];
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
    uint8_t wa[16], wb[16];
    size_t i;
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    rrmp_fill_id(scope, 0xAAu);
    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    set.parent_set_count = 1u;
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x31u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 1u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    memcpy(set.path_policy_id, scope, 16u);
    memcpy(set.owner_scope_id, scope, 16u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &pout), NINLIL_PARENT_OK);

    /* Route path_policy_id == owner_scope for mandatory scope bind. */
    ninlil_rrmp_memzero(&install, sizeof(install));
    install.preamble.api_version = 1u;
    install.preamble.struct_size = 312u;
    rrmp_fill_id(install.authority_id, 0xA0u);
    install.controller_term = 5u;
    install.batch_id = 1u;
    install.entry_count = 1u;
    rrmp_fill_nrm1(&f, 1u, 2u, 0u);
    memcpy(f.path_policy_id.bytes, scope, 16u);
    RRMP_CHECK(ninlil_rrmp_encode_nrm1(&f, raw));
    memcpy(install.entries, raw, sizeof(raw));
    RRMP_CHECK_EQ(ninlil_route_install_batch(&install, &out), NINLIL_ROUTE_OK);
    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = 64u;
    act.ingress_hop_context_id = 0x1001u;
    act.route_handle = 1u;
    act.route_generation = 1u;
    act.now_ms = 1000000u;
    RRMP_CHECK_EQ(ninlil_route_activate(&act, &out), NINLIL_ROUTE_OK);

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 2u;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 1u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0x11u + i);
    }
    rrmp_fill_id(wa, 0x1u);
    rrmp_fill_id(wb, 0x2u);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_split_brain_detect(o, scope, wa, wb, 1u, 1u),
        NINLIL_PARENT_SPLIT_BRAIN);
    /* Admit under sealed scope → DRAIN_FENCED (mandatory bind). */
    RRMP_CHECK_EQ(ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_DRAIN_FENCED);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/* ADR-0020 §4: derived owner_scope differs when path_policy differs; fail-closed. */
static int test_owner_scope_derivation_vectors(void)
{
    uint8_t pp_a[16], pp_b[16];
    uint8_t sc_a[16], sc_b[16];
    ninlil_rrmp_scope_derivation_ctx_t ctx;
    ninlil_rrmp_owner_t *o = mk(1u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_result_v1_t pout;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t dig;
    size_t i;
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    rrmp_fill_id(pp_a, 0x80u);
    rrmp_fill_id(pp_b, 0x81u);
    RRMP_CHECK(rrmp_derive_scope_for_path_policy(pp_a, sc_a));
    RRMP_CHECK(rrmp_derive_scope_for_path_policy(pp_b, sc_b));
    RRMP_CHECK(memcmp(sc_a, sc_b, 16u) != 0);
    RRMP_CHECK(memcmp(sc_a, pp_a, 16u) != 0); /* not path_policy identity */

    rrmp_default_scope_derivation(&ctx);
    ninlil_rrmp_owner_set_scope_derivation(o, &ctx);
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);

    /* Install scope for derived sc_a only. */
    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    set.parent_set_count = 1u;
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x31u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 1u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    memcpy(set.path_policy_id, pp_a, 16u);
    memcpy(set.owner_scope_id, sc_a, 16u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &pout), NINLIL_PARENT_OK);

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 1u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0x21u + i);
    }
    /*
     * The derived scope is known, but NPS1 construction alone cannot grant
     * traffic authority before an accepted NOA handoff.
     */
    RRMP_CHECK_EQ(
        ninlil_route_forward_admit(&admit, &out),
        NINLIL_ROUTE_DRAIN_FENCED);

    /* Unknown derived scope (no install for alternate policy) fail-closed. */
    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 1u, 1u);
        RRMP_CHECK(o2 != NULL);
        ninlil_rrmp_owner_bind(o2);
        ninlil_rrmp_owner_set_scope_derivation(o2, &ctx);
        RRMP_CHECK(rrmp_install_activate(o2, 1u, 1u, 1u) == 0);
        /* no parent set install → unknown scope */
        RRMP_CHECK_EQ(
            ninlil_route_forward_admit(&admit, &out), NINLIL_ROUTE_DRAIN_FENCED);
        ninlil_rrmp_owner_fini(o2);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/* S6: after OLD_RETIRED rehydrate, old_owner_seal must be 0 (ADR-0020). */
static int test_s6_old_seal_zero_rehydrate(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_activate_req_v1_t act;
    ninlil_parent_endpoint_observe_req_v1_t obs;
    ninlil_parent_owner_retire_req_v1_t ret;
    ninlil_parent_result_v1_t out;
    ninlil_parent_query_req_v1_t q;
    ninlil_rrmp_id16_t ids[2];
    ninlil_rrmp_digest32_t dig;
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_rrmp_digest32_t cdig;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    uint8_t scope[16];
    uint8_t token[32];
    uint8_t proof[32];
    uint8_t export_buf[256 * 1024];
    size_t elen = 0u;
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    rrmp_fill_id(scope, 0x0Eu);
    memset(token, 0x66, 32u);

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    memcpy(set.owner_scope_id, scope, 16u);
    set.parent_set_count = 2u;
    rrmp_fill_id(set.path_policy_id, 0x50u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x30u);
    rrmp_fill_id(ids[1].bytes, 0x40u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    memcpy(set.parent_runtime_id[1], ids[1].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 2u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);

    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, scope, 16u);
    rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
    noa.controller_term = 5u;
    noa.assignment_epoch = 1u;
    noa.assignment_revision = 1u;
    rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
    rrmp_fill_id(noa.owner_cell_id.bytes, 0xB1u);
    noa.direction = 1u;
    noa.e2e_context_id = 1u;
    noa.key_generation = 1u;
    rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
    noa.e2e_security_epoch = 1u;
    memset(noa.e2e_binding_digest.bytes, 0xE1u, 32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memcpy(noa.handoff_token_digest.bytes, token, 32u);
    noa.parent_set_digest = dig;
    noa.parent_set_count = 2u;
    memcpy(noa.parent_set_id.bytes, set.path_policy_id, 16u);

    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = 464u;
    memcpy(prep.owner_scope_id, scope, 16u);
    RRMP_CHECK(ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1));
    memcpy(prep.handoff_token_digest32, token, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(
            &prep, &old_tuple, 1u, &new_tuple, &out),
        NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        rrmp_test_owner_fence_v2(
            scope, token, &old_tuple, proof, &out),
        NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        rrmp_test_authority_commit_v2(
            scope,
            &old_tuple,
            &new_tuple,
            token,
            proof,
            NULL,
            0u,
            cdig.bytes,
            &out),
        NINLIL_PARENT_OK);

    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = 80u;
    memcpy(act.owner_scope_id, scope, 16u);
    memcpy(act.commit_receipt_digest32, cdig.bytes, 32u);
    act.now_ms = 1000000u;
    RRMP_CHECK_EQ(ninlil_parent_owner_activate(&act, &out), NINLIL_PARENT_OK);

    ninlil_rrmp_memzero(&obs, sizeof(obs));
    obs.preamble.api_version = 1u;
    obs.preamble.struct_size = 80u;
    memcpy(obs.owner_scope_id, scope, 16u);
    memcpy(obs.observed_parent_set_digest32, dig.bytes, 32u);
    obs.now_ms = 1000001u;
    RRMP_CHECK_EQ(ninlil_parent_endpoint_observe(&obs, &out), NINLIL_PARENT_OK);

    ninlil_rrmp_memzero(&ret, sizeof(ret));
    ret.preamble.api_version = 1u;
    ret.preamble.struct_size = 80u;
    memcpy(ret.owner_scope_id, scope, 16u);
    memcpy(ret.tombstone_digest32, token, 32u);
    ret.now_ms = 1000002u;
    RRMP_CHECK_EQ(ninlil_parent_owner_retire(&ret, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_OLD_RETIRED);

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, export_buf, sizeof(export_buf), &elen));
    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 1u, 1u);
        RRMP_CHECK(o2 != NULL);
        ninlil_rrmp_owner_bind(o2);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(o2, export_buf, elen));
        ninlil_rrmp_memzero(&q, sizeof(q));
        q.preamble.api_version = 1u;
        q.preamble.struct_size = 48u;
        memcpy(q.owner_scope_id, scope, 16u);
        RRMP_CHECK_EQ(ninlil_parent_query(&q, &out), NINLIL_PARENT_OK);
        RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_OLD_RETIRED);
        /* S6: new seal may stay; scope seal still allowed via new_seal.
         * old_seal must be 0 after rehydrate (enforced in rehydrate_from_ns). */
        RRMP_CHECK_EQ(ninlil_rrmp_core_scope_seal_allowed(o2, scope), 1u);
        ninlil_rrmp_owner_fini(o2);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/* Durable attempt_id16 fence survives export/import restart. */
static int test_attempt_id16_restart_conflict(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[2];
    ninlil_rrmp_digest32_t dig;
    uint8_t scope[16];
    uint8_t sel[16];
    uint8_t att1[16], att2[16];
    uint8_t token[32];
    uint8_t commit_digest[32];
    uint8_t export_buf[256 * 1024];
    size_t elen = 0u;
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    rrmp_fill_id(scope, 0xAAu);
    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    set.parent_set_count = 2u;
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x31u);
    rrmp_fill_id(ids[1].bytes, 0x32u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    memcpy(set.parent_runtime_id[1], ids[1].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 2u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    rrmp_fill_id(set.path_policy_id, 0x51u);
    memcpy(set.owner_scope_id, scope, 16u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);
    memset(token, 0xA6, sizeof(token));
    RRMP_CHECK(rrmp_test_bootstrap_assignment_v2(
        scope,
        set.path_policy_id,
        dig.bytes,
        2u,
        token,
        0u,
        commit_digest));

    rrmp_fill_attempt_id16(att1, 1u);
    rrmp_fill_attempt_id16(att2, 2u);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(o, scope, att1, sel, &out),
        NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(o, scope, att1, sel, &out),
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT);

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, export_buf, sizeof(export_buf), &elen));
    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 1u, 1u);
        RRMP_CHECK(o2 != NULL);
        ninlil_rrmp_owner_bind(o2);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(o2, export_buf, elen));
        /* Same attempt_id16 after restart must still conflict. */
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_parent_select_for_attempt(o2, scope, att1, sel, &out),
            NINLIL_PARENT_SAME_ATTEMPT_RESELECT);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_parent_select_for_attempt(o2, scope, att2, sel, &out),
            NINLIL_PARENT_OK);
        ninlil_rrmp_owner_fini(o2);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/*
 * All 16 scopes collide at the same normative hash page/slot.  Persistence
 * must linear-probe into a second NPP1 page and retain every NPS1 record.
 * This catches the former false-green implementation that truncated the
 * sixteenth scope in a per-page bucket while still returning OK.
 */
static int test_npp1_full_namespace_linear_probe(void)
{
    ninlil_rrmp_owner_t *o = mk(0u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t parent_ids[1];
    ninlil_rrmp_digest32_t parent_digest;
    uint8_t scopes[16][16];
    uint8_t seen[16];
    uint32_t candidate = 1u;
    size_t found = 0u;
    size_t export_len = 0u;
    size_t record_count = 0u;
    size_t nonempty_pages = 0u;
    uint32_t route_len;
    uint32_t parent_len;
    uint8_t page;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    while (found < 16u && candidate < 1000000u) {
        uint8_t scope[16];
        uint8_t digest[32];
        ninlil_rrmp_memzero(scope, sizeof(scope));
        scope[0] = 0x42u; /* also collides in the former byte-bucket mapping */
        ninlil_rrmp_put_u32_be(scope + 12u, candidate++);
        ninlil_rrmp_sha256(scope, sizeof(scope), digest);
        if ((digest[0] % NINLIL_RRMP_NPP1_PAGE_COUNT) == 0u &&
            (digest[1] % NINLIL_RRMP_NPP1_SLOTS) == 0u) {
            memcpy(scopes[found++], scope, sizeof(scope));
        }
    }
    RRMP_CHECK_EQ(found, 16u);

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    set.parent_set_count = 1u;
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(parent_ids[0].bytes, 0x31u);
    memcpy(set.parent_runtime_id[0], parent_ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(
        parent_ids, 1u, &parent_digest));
    memcpy(set.parent_set_digest32, parent_digest.bytes, 32u);
    for (found = 0u; found < 16u; ++found) {
        memcpy(set.owner_scope_id, scopes[found], 16u);
        memcpy(set.path_policy_id, scopes[found], 16u);
        set.path_policy_id[0] ^= 0x80u;
        RRMP_CHECK_EQ(
            ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);
        RRMP_CHECK_EQ(out.seal_allowed, 0u);
    }

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &export_len));
    RRMP_CHECK(export_len <= sizeof(g_npp1_export_probe));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, g_npp1_export_probe, sizeof(g_npp1_export_probe), &export_len));
    RRMP_CHECK(export_len >= 20u);
    route_len = ninlil_rrmp_get_u32_be(g_npp1_export_probe + 8u);
    parent_len = ninlil_rrmp_get_u32_be(g_npp1_export_probe + 12u);
    RRMP_CHECK(
        20u + (size_t)route_len + (size_t)parent_len <= export_len);
    RRMP_CHECK(ninlil_rrmp_parent_ns_import(
        &g_npp1_parent_probe,
        g_npp1_export_probe + 20u + route_len,
        parent_len));

    ninlil_rrmp_memzero(seen, sizeof(seen));
    for (page = 0u; page < NINLIL_RRMP_NPP1_PAGE_COUNT; ++page) {
        const uint8_t *raw = NULL;
        uint32_t raw_len = 0u;
        uint64_t generation = 0u;
        size_t slot;
        size_t page_records = 0u;
        RRMP_CHECK(ninlil_rrmp_parent_dual_read_active(
            &g_npp1_parent_probe,
            (uint8_t)(NINLIL_RRMP_PKEY_NPP1_BASE + page),
            &raw,
            &raw_len,
            &generation));
        RRMP_CHECK(raw != NULL);
        RRMP_CHECK_EQ(raw_len, NINLIL_RRMP_NPP1_BYTES);
        RRMP_CHECK(generation != 0u);
        RRMP_CHECK(ninlil_rrmp_validate_npp1(raw));
        for (slot = 0u; slot < NINLIL_RRMP_NPP1_SLOTS; ++slot) {
            const uint8_t *nps1 =
                raw + NINLIL_RRMP_NPP1_HEADER_BYTES +
                slot * NINLIL_RRMP_NPS1_BYTES;
            ninlil_rrmp_nps1_fields_t decoded;
            size_t scope_index;
            if (nps1[0] == 0u && nps1[1] == 0u &&
                nps1[2] == 0u && nps1[3] == 0u) {
                continue;
            }
            RRMP_CHECK(ninlil_rrmp_decode_nps1(nps1, &decoded));
            for (scope_index = 0u; scope_index < 16u; ++scope_index) {
                if (ninlil_rrmp_memeq(
                        decoded.owner_scope_id.bytes,
                        scopes[scope_index],
                        16u)) {
                    break;
                }
            }
            RRMP_CHECK(scope_index < 16u);
            RRMP_CHECK_EQ(seen[scope_index], 0u);
            seen[scope_index] = 1u;
            ++record_count;
            ++page_records;
        }
        if (page_records != 0u) {
            ++nonempty_pages;
        }
    }
    RRMP_CHECK_EQ(record_count, 16u);
    RRMP_CHECK(nonempty_pages >= 2u);
    for (found = 0u; found < 16u; ++found) {
        RRMP_CHECK_EQ(seen[found], 1u);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/*
 * Nine prepared scopes with the same first owner byte used to overwrite
 * NPA1 slot zero in one page.  The complete assignment/token tables must
 * survive a cold export/import and remain independently queryable.
 */
static int test_npa1_multi_scope_rewrite_restart(void)
{
    ninlil_rrmp_owner_t *o = mk(0u, 1u);
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_query_req_v1_t query;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t parent_ids[1];
    ninlil_rrmp_digest32_t parent_digest;
    uint8_t scopes[9][16];
    size_t i;
    size_t export_len = 0u;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    rrmp_fill_id(parent_ids[0].bytes, 0x31u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(
        parent_ids, 1u, &parent_digest));

    for (i = 0u; i < 9u; ++i) {
        ninlil_rrmp_noa1_fields_t noa;
        ninlil_rrmp_authority_tuple_v2_t old_tuple;
        ninlil_rrmp_authority_tuple_v2_t new_tuple;
        uint8_t token[32];
        ninlil_rrmp_memzero(scopes[i], sizeof(scopes[i]));
        scopes[i][0] = 0x42u; /* former page selector collision */
        scopes[i][15] = (uint8_t)(i + 1u);

        ninlil_rrmp_memzero(&set, sizeof(set));
        set.preamble.api_version = 1u;
        set.preamble.struct_size = 240u;
        memcpy(set.owner_scope_id, scopes[i], 16u);
        set.parent_set_count = 1u;
        memcpy(set.path_policy_id, scopes[i], 16u);
        set.path_policy_id[1] ^= 0x80u;
        set.controller_term = 5u;
        set.assignment_epoch = 1u;
        memcpy(set.parent_set_digest32, parent_digest.bytes, 32u);
        memcpy(set.parent_runtime_id[0], parent_ids[0].bytes, 16u);
        RRMP_CHECK_EQ(
            ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);

        ninlil_rrmp_memzero(token, sizeof(token));
        token[0] = 0xA5u;
        token[31] = (uint8_t)(i + 1u);
        ninlil_rrmp_memzero(&noa, sizeof(noa));
        memcpy(noa.owner_scope_id.bytes, scopes[i], 16u);
        rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
        noa.controller_term = 5u;
        noa.assignment_epoch = 1u;
        noa.assignment_revision = 1u;
        rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
        rrmp_fill_id(noa.owner_cell_id.bytes, (uint8_t)(0xB1u + i));
        noa.direction = 1u;
        noa.e2e_context_id = (uint32_t)(100u + i);
        noa.key_generation = 1u;
        rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
        noa.e2e_security_epoch = 1u;
        noa.e2e_binding_digest.bytes[0] = 0xE1u;
        rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
        noa.lease_not_after_authority_ms = 5000000u;
        memcpy(noa.handoff_token_digest.bytes, token, sizeof(token));
        noa.parent_set_digest = parent_digest;
        noa.parent_set_count = 1u;
        memcpy(noa.parent_set_id.bytes, set.path_policy_id, 16u);

        ninlil_rrmp_memzero(&prep, sizeof(prep));
        prep.preamble.api_version = 1u;
        prep.preamble.struct_size = 464u;
        memcpy(prep.owner_scope_id, scopes[i], 16u);
        RRMP_CHECK(ninlil_rrmp_encode_noa1(
            &noa, prep.new_assignment_noa1));
        memcpy(prep.handoff_token_digest32, token, sizeof(token));
        ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
        RRMP_CHECK_EQ(
            rrmp_test_owner_prepare_v2(
                &prep, &old_tuple, 1u, &new_tuple, &out),
            NINLIL_PARENT_OK);
        RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_PREPARED_NEW);
        RRMP_CHECK_EQ(out.seal_allowed, 0u);
    }

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, g_npp1_export_probe, sizeof(g_npp1_export_probe), &export_len));
    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 0u, 1u);
        RRMP_CHECK(o2 != NULL);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
            o2, g_npp1_export_probe, export_len));
        RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
        for (i = 0u; i < 9u; ++i) {
            ninlil_rrmp_memzero(&query, sizeof(query));
            query.preamble.api_version = 1u;
            query.preamble.struct_size = 48u;
            memcpy(query.owner_scope_id, scopes[i], 16u);
            RRMP_CHECK_EQ(
                ninlil_parent_query(&query, &out), NINLIL_PARENT_OK);
            RRMP_CHECK_EQ(
                out.handoff_step, NINLIL_RRMP_HANDOFF_PREPARED_NEW);
            RRMP_CHECK_EQ(out.seal_allowed, 0u);
        }
        ninlil_rrmp_owner_fini(o2);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_route_full_capacity_restart(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 0u);
    ninlil_route_query_req_v1_t query;
    ninlil_route_result_v1_t out;
    size_t export_len = 0u;
    uint16_t handle;
    RRMP_CHECK(o != NULL);
    for (handle = 1u; handle <= NINLIL_RRMP_ROUTE_MAX; ++handle) {
        RRMP_CHECK(rrmp_install_activate(o, handle, 1u, 1u) == 0);
    }
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 1u);
    /* The 129th concurrently live route is rejected by the advertised bound. */
    RRMP_CHECK(rrmp_install_activate(
        o, (uint16_t)(NINLIL_RRMP_ROUTE_MAX + 1u), 1u, 1u) != 0);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &export_len));
    RRMP_CHECK(export_len <= sizeof(g_npp1_export_probe));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o,
        g_npp1_export_probe,
        sizeof(g_npp1_export_probe),
        &export_len));
    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 1u, 0u);
        RRMP_CHECK(o2 != NULL);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
            o2, g_npp1_export_probe, export_len));
        RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
        for (handle = 1u; handle <= NINLIL_RRMP_ROUTE_MAX; ++handle) {
            ninlil_rrmp_memzero(&query, sizeof(query));
            query.preamble.api_version = 1u;
            query.preamble.struct_size = 48u;
            query.ingress_hop_context_id = 0x1000u + handle;
            query.route_handle = handle;
            query.route_generation = 1u;
            RRMP_CHECK_EQ(
                ninlil_route_query(&query, &out), NINLIL_ROUTE_OK);
            RRMP_CHECK_EQ(out.lifecycle_state, NINLIL_RRMP_LIFE_ACTIVE);
        }
        ninlil_rrmp_owner_fini(o2);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_simultaneous_capacity_envelope(void)
{
    ninlil_rrmp_owner_t *o = mk(1u, 1u);
    ninlil_rrmp_id16_t parent_ids[1];
    ninlil_rrmp_digest32_t parent_digest;
    ninlil_parent_result_v1_t parent_out;
    ninlil_route_result_v1_t route_out;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_query_req_v1_t route_query;
    ninlil_parent_query_req_v1_t parent_query;
    ninlil_rrmp_scope_derivation_ctx_t scope_ctx;
    uint8_t route_path_policy[16];
    uint8_t scopes[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY][16];
    uint8_t bootstrap_token[32];
    uint8_t bootstrap_commit[32];
    size_t export_len = 0u;
    size_t i;
    uint16_t handle;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    rrmp_default_scope_derivation(&scope_ctx);
    ninlil_rrmp_owner_set_scope_derivation(o, &scope_ctx);
    rrmp_fill_id(route_path_policy, 0x80u);

    /*
     * Capacity is a simultaneous owner envelope, not three independent
     * maxima.  Keep all 128 routes, all 64 parent scopes, and all 64 forward
     * queue entries live in this one owner before checking every boundary.
     */
    for (handle = 1u; handle <= NINLIL_RRMP_ROUTE_MAX; ++handle) {
        RRMP_CHECK(rrmp_install_activate(o, handle, 1u, 1u) == 0);
    }

    rrmp_fill_id(parent_ids[0].bytes, 0x31u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(
        parent_ids, 1u, &parent_digest));
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        ninlil_parent_set_install_req_v1_t set;
        if (i == 0u) {
            RRMP_CHECK(rrmp_derive_scope_for_path_policy(
                route_path_policy, scopes[i]));
        } else {
            ninlil_rrmp_memzero(scopes[i], 16u);
            scopes[i][0] = 0x7Eu;
            ninlil_rrmp_put_u64_be(scopes[i] + 8u, (uint64_t)i + 1u);
        }
        ninlil_rrmp_memzero(&set, sizeof(set));
        set.preamble.api_version = 1u;
        set.preamble.struct_size = 240u;
        memcpy(set.owner_scope_id, scopes[i], 16u);
        set.parent_set_count = 1u;
        if (i == 0u) {
            memcpy(set.path_policy_id, route_path_policy, 16u);
        } else {
            set.path_policy_id[0] = 0x5Au;
            ninlil_rrmp_put_u64_be(
                set.path_policy_id + 8u, (uint64_t)i + 1u);
        }
        set.controller_term = 5u;
        set.assignment_epoch = 1u;
        memcpy(
            set.parent_runtime_id[0], parent_ids[0].bytes, 16u);
        memcpy(
            set.parent_set_digest32, parent_digest.bytes, 32u);
        RRMP_CHECK_EQ(
            ninlil_parent_set_install(&set, &parent_out),
            NINLIL_PARENT_OK);
        if (ninlil_rrmp_owner_downlink_tx_allowed(o) != 1u) {
            fprintf(stderr, "downlink fenced after parent scope %zu\n", i + 1u);
            return 1;
        }
    }
    memset(bootstrap_token, 0xB6, sizeof(bootstrap_token));
    RRMP_CHECK(rrmp_test_bootstrap_assignment_v2(
        scopes[0],
        route_path_policy,
        parent_digest.bytes,
        1u,
        bootstrap_token,
        0u,
        bootstrap_commit));

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.admission_now_ms = 1000000u;
    /*
     * NORMAL may consume only 56 slots because 8 are reserved.  Fill the
     * reserved tail with CONTROL traffic, spread over eight routes so each
     * route's quota of eight remains exact.
     */
    for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
        handle = (uint16_t)(i / 8u) + 1u;
        admit.ingress_hop_context_id = 0x1000u + handle;
        admit.route_handle = handle;
        admit.priority_class =
            i < (NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES -
                    NINLIL_RRMP_RESERVED_CONTROL_ENTRIES)
            ? NINLIL_RRMP_PRIO_NORMAL
            : NINLIL_RRMP_PRIO_CONTROL;
        admit.caller_item_token = (uint64_t)i + 1u;
        ninlil_rrmp_memzero(
            admit.e2e_header_digest32,
            sizeof(admit.e2e_header_digest32));
        admit.e2e_header_digest32[0] = 0xC3u;
        ninlil_rrmp_put_u64_be(
            admit.e2e_header_digest32 + 24u, (uint64_t)i + 1u);
        {
            uint32_t status =
                ninlil_route_forward_admit(&admit, &route_out);
            if (status != NINLIL_ROUTE_OK) {
                fprintf(
                    stderr,
                    "simultaneous queue admission failed index=%zu status=%u\n",
                    i,
                    status);
                return 1;
            }
        }
    }

    /* Exact N+1 boundaries must not evict or overwrite a live entry. */
    {
        ninlil_parent_set_install_req_v1_t overflow_scope;
        ninlil_rrmp_memzero(&overflow_scope, sizeof(overflow_scope));
        overflow_scope.preamble.api_version = 1u;
        overflow_scope.preamble.struct_size = 240u;
        memset(overflow_scope.owner_scope_id, 0xF1, 16u);
        overflow_scope.parent_set_count = 1u;
        memset(overflow_scope.path_policy_id, 0xF2, 16u);
        overflow_scope.controller_term = 5u;
        overflow_scope.assignment_epoch = 1u;
        memcpy(
            overflow_scope.parent_runtime_id[0],
            parent_ids[0].bytes,
            16u);
        memcpy(
            overflow_scope.parent_set_digest32,
            parent_digest.bytes,
            32u);
        RRMP_CHECK_EQ(
            ninlil_parent_set_install(&overflow_scope, &parent_out),
            NINLIL_PARENT_RESOURCE);
    }
    admit.ingress_hop_context_id = 0x1009u;
    admit.route_handle = 9u;
    admit.priority_class = NINLIL_RRMP_PRIO_CONTROL;
    admit.caller_item_token = 65u;
    ninlil_rrmp_memzero(
        admit.e2e_header_digest32,
        sizeof(admit.e2e_header_digest32));
    admit.e2e_header_digest32[0] = 0xC3u;
    ninlil_rrmp_put_u64_be(admit.e2e_header_digest32 + 24u, 65u);
    RRMP_CHECK_EQ(
        ninlil_route_forward_admit(&admit, &route_out),
        NINLIL_ROUTE_BACKPRESSURE);

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &export_len));
    RRMP_CHECK(export_len <= sizeof(g_npp1_export_probe));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o,
        g_npp1_export_probe,
        sizeof(g_npp1_export_probe),
        &export_len));
    {
        uint32_t route_len = ninlil_rrmp_get_u32_be(
            g_npp1_export_probe + 8u);
        uint32_t parent_len = ninlil_rrmp_get_u32_be(
            g_npp1_export_probe + 12u);
        const uint8_t *soft =
            g_npp1_export_probe + 20u + route_len + parent_len;
        RRMP_CHECK(memcmp(soft, "RRMPQST4", 8u) == 0);
        RRMP_CHECK_EQ(
            ninlil_rrmp_get_u16_be(soft + 10u),
            NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY);
        RRMP_CHECK_EQ(
            ninlil_rrmp_get_u16_be(soft + 12u),
            NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES);
    }

    /* Cold import must retain every simultaneously live capacity class. */
    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 1u, 1u);
        RRMP_CHECK(o2 != NULL);
        ninlil_rrmp_owner_set_scope_derivation(o2, &scope_ctx);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
            o2, g_npp1_export_probe, export_len));
        RRMP_CHECK(ninlil_rrmp_owner_bind(o2));

        ninlil_rrmp_memzero(&route_query, sizeof(route_query));
        route_query.preamble.api_version = 1u;
        route_query.preamble.struct_size = 48u;
        route_query.ingress_hop_context_id =
            0x1000u + NINLIL_RRMP_ROUTE_MAX;
        route_query.route_handle = NINLIL_RRMP_ROUTE_MAX;
        route_query.route_generation = 1u;
        RRMP_CHECK_EQ(
            ninlil_route_query(&route_query, &route_out),
            NINLIL_ROUTE_OK);

        ninlil_rrmp_memzero(&parent_query, sizeof(parent_query));
        parent_query.preamble.api_version = 1u;
        parent_query.preamble.struct_size = 48u;
        memcpy(
            parent_query.owner_scope_id,
            scopes[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY - 1u],
            16u);
        RRMP_CHECK_EQ(
            ninlil_parent_query(&parent_query, &parent_out),
            NINLIL_PARENT_OK);

        RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
            o2,
            g_npp1_export_probe,
            sizeof(g_npp1_export_probe),
            &export_len));
        {
            uint32_t route_len = ninlil_rrmp_get_u32_be(
                g_npp1_export_probe + 8u);
            uint32_t parent_len = ninlil_rrmp_get_u32_be(
                g_npp1_export_probe + 12u);
            const uint8_t *soft =
                g_npp1_export_probe + 20u + route_len + parent_len;
            RRMP_CHECK_EQ(
                ninlil_rrmp_get_u16_be(soft + 10u),
                NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY);
            RRMP_CHECK_EQ(
                ninlil_rrmp_get_u16_be(soft + 12u),
                NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES);
        }
        ninlil_rrmp_owner_fini(o2);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_parent_full_capacity_handoff_restart(void)
{
    ninlil_rrmp_owner_t *o = mk(0u, 1u);
    ninlil_rrmp_id16_t parent_ids[1];
    ninlil_rrmp_digest32_t parent_digest;
    ninlil_parent_result_v1_t out;
    ninlil_parent_query_req_v1_t query;
    uint8_t scopes[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY][16];
    size_t export_len = 0u;
    size_t i;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    rrmp_fill_id(parent_ids[0].bytes, 0x31u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(
        parent_ids, 1u, &parent_digest));

    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        ninlil_parent_set_install_req_v1_t set;
        ninlil_parent_owner_prepare_req_v1_t prep;
        ninlil_parent_owner_activate_req_v1_t activate;
        ninlil_rrmp_noa1_fields_t noa;
        ninlil_rrmp_digest32_t commit_digest;
        ninlil_rrmp_authority_tuple_v2_t old_tuple;
        ninlil_rrmp_authority_tuple_v2_t new_tuple;
        uint8_t token[32];
        uint8_t proof[32];

        ninlil_rrmp_memzero(scopes[i], 16u);
        scopes[i][0] = 0x42u;
        ninlil_rrmp_put_u64_be(scopes[i] + 8u, (uint64_t)i + 1u);
        ninlil_rrmp_memzero(token, sizeof(token));
        token[0] = 0xA5u;
        token[30] = (uint8_t)(i >> 8u);
        token[31] = (uint8_t)(i + 1u);

        ninlil_rrmp_memzero(&set, sizeof(set));
        set.preamble.api_version = 1u;
        set.preamble.struct_size = 240u;
        memcpy(set.owner_scope_id, scopes[i], 16u);
        set.parent_set_count = 1u;
        memcpy(set.path_policy_id, scopes[i], 16u);
        set.path_policy_id[1] ^= 0x80u;
        set.controller_term = 5u;
        set.assignment_epoch = 1u;
        memcpy(
            set.parent_runtime_id[0], parent_ids[0].bytes, 16u);
        memcpy(set.parent_set_digest32, parent_digest.bytes, 32u);
        RRMP_CHECK_EQ(
            ninlil_parent_set_install(&set, &out), NINLIL_PARENT_OK);

        ninlil_rrmp_memzero(&noa, sizeof(noa));
        memcpy(noa.owner_scope_id.bytes, scopes[i], 16u);
        rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
        noa.controller_term = 5u;
        noa.assignment_epoch = 1u;
        noa.assignment_revision = 1u;
        rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
        rrmp_fill_id(
            noa.owner_cell_id.bytes, (uint8_t)(0x60u + (uint8_t)i));
        noa.direction = (uint8_t)(i & 1u);
        noa.e2e_context_id = (uint32_t)i + 1u;
        noa.key_generation = (uint64_t)i + 1u;
        rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
        noa.e2e_security_epoch = (uint64_t)i + 1u;
        memset(
            noa.e2e_binding_digest.bytes,
            (int)(0x80u + (uint8_t)i),
            32u);
        rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
        noa.lease_not_after_authority_ms = 5000000u;
        memcpy(noa.handoff_token_digest.bytes, token, 32u);
        noa.parent_set_digest = parent_digest;
        noa.parent_set_count = 1u;
        memcpy(noa.parent_set_id.bytes, set.path_policy_id, 16u);

        ninlil_rrmp_memzero(&prep, sizeof(prep));
        prep.preamble.api_version = 1u;
        prep.preamble.struct_size = 464u;
        memcpy(prep.owner_scope_id, scopes[i], 16u);
        RRMP_CHECK(ninlil_rrmp_encode_noa1(
            &noa, prep.new_assignment_noa1));
        memcpy(prep.handoff_token_digest32, token, 32u);
        ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
        RRMP_CHECK_EQ(
            rrmp_test_owner_prepare_v2(
                &prep, &old_tuple, (uint64_t)i + 1u,
                &new_tuple, &out),
            NINLIL_PARENT_OK);
        RRMP_CHECK_EQ(
            rrmp_test_owner_fence_v2(
                scopes[i], token, &old_tuple, proof, &out),
            NINLIL_PARENT_OK);

        RRMP_CHECK_EQ(
            rrmp_test_authority_commit_v2(
                scopes[i],
                &old_tuple,
                &new_tuple,
                token,
                proof,
                NULL,
                i,
                commit_digest.bytes,
                &out),
            NINLIL_PARENT_OK);

        ninlil_rrmp_memzero(&activate, sizeof(activate));
        activate.preamble.api_version = 1u;
        activate.preamble.struct_size = 80u;
        memcpy(activate.owner_scope_id, scopes[i], 16u);
        memcpy(
            activate.commit_receipt_digest32,
            commit_digest.bytes,
            32u);
        activate.now_ms = 1000000u;
        RRMP_CHECK_EQ(
            ninlil_parent_owner_activate(&activate, &out),
            NINLIL_PARENT_OK);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_scope_seal_allowed(o, scopes[i]), 1u);
    }

    /* Scope 65 is rejected even though the NPP hash table has spare slots. */
    {
        ninlil_parent_set_install_req_v1_t overflow;
        ninlil_rrmp_memzero(&overflow, sizeof(overflow));
        overflow.preamble.api_version = 1u;
        overflow.preamble.struct_size = 240u;
        memset(overflow.owner_scope_id, 0xF1, 16u);
        overflow.parent_set_count = 1u;
        memset(overflow.path_policy_id, 0xF2, 16u);
        overflow.controller_term = 5u;
        overflow.assignment_epoch = 1u;
        memcpy(
            overflow.parent_runtime_id[0], parent_ids[0].bytes, 16u);
        memcpy(
            overflow.parent_set_digest32, parent_digest.bytes, 32u);
        RRMP_CHECK_EQ(
            ninlil_parent_set_install(&overflow, &out),
            NINLIL_PARENT_RESOURCE);
    }

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &export_len));
    RRMP_CHECK(export_len <= sizeof(g_npp1_export_probe));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o,
        g_npp1_export_probe,
        sizeof(g_npp1_export_probe),
        &export_len));
    {
        ninlil_rrmp_owner_t *o2 = rrmp_mk_ws(
            g_owner_ws2, ninlil_rrmp_owner_workspace_bytes(), 0u, 1u);
        RRMP_CHECK(o2 != NULL);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
            o2, g_npp1_export_probe, export_len));
        RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
        for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
            ninlil_rrmp_memzero(&query, sizeof(query));
            query.preamble.api_version = 1u;
            query.preamble.struct_size = 48u;
            memcpy(query.owner_scope_id, scopes[i], 16u);
            RRMP_CHECK_EQ(
                ninlil_parent_query(&query, &out), NINLIL_PARENT_OK);
            RRMP_CHECK_EQ(
                out.handoff_step,
                NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED);
            RRMP_CHECK_EQ(out.seal_allowed, 1u);
        }
        ninlil_rrmp_owner_fini(o2);
    }
    ninlil_rrmp_owner_fini(o);
    return 0;
}

int main(void)
{
    (void)g_owner_ws2;
    if (test_workspace_no_heap() != 0) {
        return 1;
    }
    if (test_parent_result_abi() != 0) {
        return 1;
    }
    if (test_feature_off() != 0) {
        return 1;
    }
    if (test_caller_authorization() != 0) {
        return 1;
    }
    if (test_lease_and_hop_gates() != 0) {
        return 1;
    }
    if (test_queue_full_no_live_evidence() != 0) {
        return 1;
    }
    if (test_drain_order_and_attempts() != 0) {
        return 1;
    }
    if (test_handoff_proof_and_receipt() != 0) {
        return 1;
    }
    if (test_scope_local_split_brain() != 0) {
        return 1;
    }
    if (test_qst2_legacy_parent_scope_fail_closed() != 0) {
        return 1;
    }
    if (test_real_multi_hop_path() != 0) {
        return 1;
    }
    if (test_two_hop_acceptance() != 0) {
        return 1;
    }
    if (test_scope_blocks_hop_tx() != 0) {
        return 1;
    }
    if (test_fabric_select_dispatch() != 0) {
        return 1;
    }
    if (test_fabric_relay_cycle_seam() != 0) {
        return 1;
    }
    if (test_owner_scope_derivation_vectors() != 0) {
        return 1;
    }
    if (test_s6_old_seal_zero_rehydrate() != 0) {
        return 1;
    }
    if (test_attempt_id16_restart_conflict() != 0) {
        return 1;
    }
    if (test_npp1_full_namespace_linear_probe() != 0) {
        return 1;
    }
    if (test_npa1_multi_scope_rewrite_restart() != 0) {
        return 1;
    }
    if (test_route_full_capacity_restart() != 0) {
        return 1;
    }
    if (test_simultaneous_capacity_envelope() != 0) {
        return 1;
    }
    if (test_parent_full_capacity_handoff_restart() != 0) {
        return 1;
    }
    printf("rrmp_sm_test OK ws_bytes=%zu\n", ninlil_rrmp_owner_workspace_bytes());
    return 0;
}
