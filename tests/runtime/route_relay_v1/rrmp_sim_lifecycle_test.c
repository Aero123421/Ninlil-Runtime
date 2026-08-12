/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_test_common.h"

enum { RRMP_WS_MAX = NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES };
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_ws[RRMP_WS_MAX];

static int test_sim_driver(void)
{
    ninlil_rrmp_sim_t sim;
    uint32_t n;
    uint32_t i;
    int saw_same = 0;
    int saw_sb = 0;
    RRMP_CHECK(ninlil_rrmp_sim_run_bounded_driver(&sim));
    n = ninlil_rrmp_sim_step_count(&sim);
    RRMP_CHECK(n >= 8u);
    for (i = 0u; i < n; ++i) {
        const ninlil_rrmp_sim_step_t *s = ninlil_rrmp_sim_step_at(&sim, i);
        RRMP_CHECK(s != NULL);
        if (s->status == NINLIL_PARENT_SAME_ATTEMPT_RESELECT) {
            saw_same = 1;
        }
        if (s->status == NINLIL_PARENT_SPLIT_BRAIN) {
            saw_sb = 1;
            RRMP_CHECK_EQ(s->detail, 1u);
        }
    }
    RRMP_CHECK(saw_same);
    RRMP_CHECK(saw_sb);
    ninlil_rrmp_sim_fini(&sim);
    return 0;
}

/*
 * 10k lifecycle with exact expected statuses (not ok_ops>0):
 * single handle force-retire cycle → every step must be ROUTE_OK.
 * out.status must equal return; INVALID never counted as success.
 */
static int test_lifecycle_10k_exact(void)
{
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    ninlil_rrmp_owner_t *o;
    rrmp_test_outbound_t ob;
    int k;
    int ok_install = 0;
    int ok_activate = 0;
    int ok_admit = 0;
    int ok_complete = 0;
    int ok_retire = 0;
    const int N = 10000;
    RRMP_CHECK(need <= RRMP_WS_MAX);
    o = rrmp_mk_ws(g_ws, need, 1u, 0u);
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    /* Provider user pointer must outlive all hop submits (ASan scope). */
    rrmp_install_test_outbound(o, &ob);
    for (k = 0; k < N; ++k) {
        const uint16_t h = 1u;
        const uint16_t gen = 1u;
        ninlil_route_install_batch_req_v1_t install;
        ninlil_route_activate_req_v1_t act;
        ninlil_route_forward_admit_req_v1_t admit;
        ninlil_route_forward_complete_req_v1_t complete;
        ninlil_route_retire_req_v1_t retire;
        ninlil_route_result_v1_t out;
        ninlil_rrmp_hop_tx_view_t tx;
        ninlil_rrmp_nrm1_fields_t f;
        uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
        size_t j;
        uint32_t st;
        uint64_t oh = 0u;

        ninlil_rrmp_memzero(&install, sizeof(install));
        install.preamble.api_version = 1u;
        install.preamble.struct_size = 312u;
        rrmp_fill_id(install.authority_id, 0xA0u);
        install.controller_term = 5u;
        install.batch_id = (uint64_t)k + 1u;
        install.entry_count = 1u;
        rrmp_fill_nrm1(&f, h, 1u, 1u);
        f.route_generation = gen;
        f.route_revision = (uint64_t)k + 1u;
        f.ingress_hop_context_id = 0x1001u;
        RRMP_CHECK(ninlil_rrmp_encode_nrm1(&f, raw));
        memcpy(install.entries, raw, sizeof(raw));
        st = ninlil_route_install_batch(o, &install, &out);
        RRMP_CHECK_EQ(out.status, st);
        RRMP_CHECK_EQ(st, NINLIL_ROUTE_OK);
        ++ok_install;

        ninlil_rrmp_memzero(&act, sizeof(act));
        act.preamble.api_version = 1u;
        act.preamble.struct_size = 64u;
        act.ingress_hop_context_id = f.ingress_hop_context_id;
        act.route_handle = h;
        act.route_generation = gen;
        act.now_ms = 1000000u;
        st = ninlil_route_activate(o, &act, &out);
        RRMP_CHECK_EQ(out.status, st);
        RRMP_CHECK_EQ(st, NINLIL_ROUTE_OK);
        ++ok_activate;

        ninlil_rrmp_memzero(&admit, sizeof(admit));
        admit.preamble.api_version = 1u;
        admit.preamble.struct_size = 128u;
        admit.ingress_hop_context_id = f.ingress_hop_context_id;
        admit.route_handle = h;
        admit.route_generation = gen;
        admit.hop_remaining = 1u;
        admit.admission_now_ms = 1000000u;
        admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
        admit.caller_item_token = (uint64_t)k + 1u;
        for (j = 0u; j < 32u; ++j) {
            admit.e2e_header_digest32[j] =
                (uint8_t)((k + (int)j) ^ (k >> 8));
        }
        st = ninlil_route_forward_admit(o, &admit, &out);
        RRMP_CHECK_EQ(out.status, st);
        RRMP_CHECK_EQ(st, NINLIL_ROUTE_OK);
        ++ok_admit;
        oh = out.opaque_local_handle;
        RRMP_CHECK(oh != 0u);
        RRMP_CHECK_EQ(
            ninlil_rrmp_core_hop_forward_execute(o, oh, NULL, 0u, 1u, &tx),
            NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(tx.rewrap_identical, 1u);
        RRMP_CHECK_EQ(tx.e2e_len, 96u);
        RRMP_CHECK_EQ(
            rrmp_auth_link_ack(o, oh, tx.outer_tx_counter, &out), NINLIL_ROUTE_OK);

        ninlil_rrmp_memzero(&complete, sizeof(complete));
        complete.preamble.api_version = 1u;
        complete.preamble.struct_size = 64u;
        complete.opaque_local_handle = oh;
        complete.outcome = 1u;
        complete.completion_now_ms = 1000000u;
        st = ninlil_route_forward_complete(o, &complete, &out);
        RRMP_CHECK_EQ(out.status, st);
        RRMP_CHECK_EQ(st, NINLIL_ROUTE_OK);
        ++ok_complete;

        ninlil_rrmp_memzero(&retire, sizeof(retire));
        retire.preamble.api_version = 1u;
        retire.preamble.struct_size = 64u;
        retire.ingress_hop_context_id = f.ingress_hop_context_id;
        retire.route_handle = h;
        retire.route_generation = gen;
        retire.force = 1u;
        st = ninlil_route_retire(o, &retire, &out);
        RRMP_CHECK_EQ(out.status, st);
        RRMP_CHECK_EQ(st, NINLIL_ROUTE_OK);
        RRMP_CHECK_EQ(out.lifecycle_state, NINLIL_RRMP_LIFE_RETIRED);
        ++ok_retire;
    }
    printf(
        "10k exact install=%d activate=%d admit=%d complete=%d retire=%d\n",
        ok_install,
        ok_activate,
        ok_admit,
        ok_complete,
        ok_retire);
    RRMP_CHECK_EQ(ok_install, N);
    RRMP_CHECK_EQ(ok_activate, N);
    RRMP_CHECK_EQ(ok_admit, N);
    RRMP_CHECK_EQ(ok_complete, N);
    RRMP_CHECK_EQ(ok_retire, N);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

int main(void)
{
    RRMP_CHECK(ninlil_rrmp_sha256_selftest());
    if (test_sim_driver() != 0) {
        return 1;
    }
    if (test_lifecycle_10k_exact() != 0) {
        return 1;
    }
    printf("rrmp_sim_lifecycle_test OK\n");
    return 0;
}
