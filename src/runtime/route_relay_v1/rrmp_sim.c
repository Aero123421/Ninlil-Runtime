#include "rrmp_sim.h"
#include "rrmp_codec.h"
#include "rrmp_util.h"

#include <string.h>

enum { RRMP_SIM_WS = 512 * 1024 };
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_sim_ws_ep[RRMP_SIM_WS];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_sim_ws_pa[RRMP_SIM_WS];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_sim_ws_pb[RRMP_SIM_WS];

static void push(
    ninlil_rrmp_sim_t *s, uint32_t code, uint32_t st, uint32_t d)
{
    if (s->step_count >= NINLIL_RRMP_SIM_MAX_STEPS) {
        return;
    }
    s->steps[s->step_count].t = s->step_count;
    s->steps[s->step_count].event_code = code;
    s->steps[s->step_count].status = st;
    s->steps[s->step_count].detail = d;
    s->step_count += 1u;
}

static void fill_id(uint8_t id[16], uint8_t seed)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        id[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static ninlil_rrmp_owner_t *mk_owner(
    uint8_t *ws, uint8_t rid, uint8_t route_on, uint8_t parent_on)
{
    ninlil_rrmp_owner_config_v1_t cfg;
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    if (need > RRMP_SIM_WS) {
        return NULL;
    }
    ninlil_rrmp_memzero(&cfg, sizeof(cfg));
    cfg.preamble.api_version = 1u;
    cfg.preamble.struct_size = (uint32_t)sizeof(cfg);
    fill_id(cfg.local_runtime_id, rid);
    fill_id(cfg.authority_id, 0xA0u);
    cfg.controller_term = 5u;
    fill_id(cfg.authority_clock_epoch_id, 0x50u);
    cfg.feature_route_relay = route_on;
    cfg.feature_multi_parent = parent_on;
    cfg.max_hops_profile = 3u;
    cfg.now_ms = 1000000u;
    return ninlil_rrmp_owner_init(ws, need, &cfg);
}

static void fill_nrm1(
    ninlil_rrmp_nrm1_fields_t *f, uint16_t handle, uint8_t hops, uint8_t term)
{
    ninlil_rrmp_memzero(f, sizeof(*f));
    fill_id(f->authority_id.bytes, 0xA0u);
    f->controller_term = 5u;
    f->route_revision = 1u;
    f->lease_epoch = 1u;
    fill_id(f->authority_clock_epoch_id.bytes, 0x50u);
    f->lease_expiry_ms = 5000000u;
    f->ingress_hop_context_id = 0x1000u + handle;
    f->route_handle = handle;
    f->route_generation = 1u;
    fill_id(f->egress_peer_id.bytes, 0x60u);
    f->egress_hop_context_id = 0x2000u + handle;
    if (term) {
        f->egress_route_handle = 0u;
        f->egress_route_generation = 0u;
    } else {
        f->egress_route_handle = (uint16_t)(handle + 10u);
        f->egress_route_generation = 1u;
    }
    fill_id(f->grant_id.bytes, 0x70u);
    f->queue_quota_entries = 8u;
    f->queue_quota_bytes = 2048u;
    f->max_hops = hops;
    f->ack_policy = 1u;
    f->terminal_flag = term;
    fill_id(f->path_policy_id.bytes, 0x80u);
    f->path_policy_revision = 1u;
}

static void sim_authority_tuple_encode(
    const ninlil_rrmp_authority_tuple_v2_t *tuple, uint8_t out[104])
{
    ninlil_rrmp_memzero(out, 104u);
    out[0] = tuple->present;
    ninlil_rrmp_put_u32_be(out + 4u, tuple->exact_noa1_length);
    memcpy(out + 8u, tuple->noa1_sha256, 32u);
    ninlil_rrmp_put_u64_be(out + 40u, tuple->assignment_revision);
    ninlil_rrmp_put_u64_be(out + 48u, tuple->controller_term);
    memcpy(out + 56u, tuple->owner_controller_id, 16u);
    ninlil_rrmp_put_u64_be(out + 72u, tuple->writer_epoch);
    ninlil_rrmp_put_u64_be(out + 80u, tuple->lease_not_after_ms);
    memcpy(out + 88u, tuple->authority_clock_epoch_id, 16u);
}

static int sim_bootstrap_assignment(
    const uint8_t owner_scope_id[16],
    const uint8_t path_policy_id[16],
    const uint8_t parent_set_digest32[32],
    uint8_t parent_set_count,
    ninlil_parent_result_v1_t *out)
{
    static const uint8_t proof_domain[] =
        "NINLIL-RRMP-NO-OLD-AUTHORITY-V2";
    static const uint8_t commit_domain[] =
        "NINLIL-RRMP-AUTHORITY-COMMIT-V2";
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_parent_owner_prepare_req_v2_t prepare;
    ninlil_parent_authority_commit_req_v2_t commit;
    ninlil_parent_owner_activate_req_v1_t activate;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    uint8_t proof_preimage[
        sizeof(proof_domain) - 1u + 16u + 32u];
    uint8_t commit_preimage[640];
    uint8_t tuple_bytes[104];
    uint8_t token[32];
    size_t off = 0u;
    if (owner_scope_id == NULL || path_policy_id == NULL ||
        parent_set_digest32 == NULL || out == NULL ||
        parent_set_count == 0u) {
        return 0;
    }
    memset(token, 0x5Au, sizeof(token));
    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, owner_scope_id, 16u);
    fill_id(noa.authority_id.bytes, 0xA0u);
    noa.controller_term = 5u;
    noa.assignment_epoch = 1u;
    noa.assignment_revision = 1u;
    fill_id(noa.owner_controller_id.bytes, 0xB0u);
    fill_id(noa.owner_cell_id.bytes, 0xB1u);
    noa.direction = 1u;
    noa.e2e_context_id = 1u;
    noa.key_generation = 1u;
    fill_id(noa.e2e_security_id.bytes, 0xD0u);
    noa.e2e_security_epoch = 1u;
    memset(noa.e2e_binding_digest.bytes, 0xE1u, 32u);
    fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memcpy(noa.handoff_token_digest.bytes, token, 32u);
    memcpy(noa.parent_set_digest.bytes, parent_set_digest32, 32u);
    noa.parent_set_count = parent_set_count;
    memcpy(noa.parent_set_id.bytes, path_policy_id, 16u);

    ninlil_rrmp_memzero(&prepare, sizeof(prepare));
    prepare.preamble.api_version = NINLIL_RRMP_PRIVATE_V2_API_VERSION;
    prepare.preamble.struct_size = (uint32_t)sizeof(prepare);
    memcpy(prepare.owner_scope_id, owner_scope_id, 16u);
    if (!ninlil_rrmp_encode_noa1(
            &noa, prepare.new_assignment_noa1)) {
        return 0;
    }
    memcpy(prepare.handoff_token_digest32, token, 32u);
    if (ninlil_parent_owner_prepare_v2(&prepare, out) !=
        NINLIL_PARENT_OK) {
        return 0;
    }

    ninlil_rrmp_memzero(&new_tuple, sizeof(new_tuple));
    new_tuple.present = 1u;
    new_tuple.exact_noa1_length = NINLIL_RRMP_NOA1_BYTES;
    ninlil_rrmp_sha256(
        prepare.new_assignment_noa1,
        NINLIL_RRMP_NOA1_BYTES,
        new_tuple.noa1_sha256);
    new_tuple.assignment_revision = noa.assignment_revision;
    new_tuple.controller_term = noa.controller_term;
    memcpy(
        new_tuple.owner_controller_id,
        noa.owner_controller_id.bytes,
        16u);
    new_tuple.writer_epoch = 1u;
    new_tuple.lease_not_after_ms =
        noa.lease_not_after_authority_ms;
    memcpy(
        new_tuple.authority_clock_epoch_id,
        noa.authority_clock_epoch_id.bytes,
        16u);

    memcpy(proof_preimage, proof_domain, sizeof(proof_domain) - 1u);
    memcpy(
        proof_preimage + sizeof(proof_domain) - 1u,
        owner_scope_id,
        16u);
    memcpy(
        proof_preimage + sizeof(proof_domain) - 1u + 16u,
        token,
        32u);

    ninlil_rrmp_memzero(&commit, sizeof(commit));
    commit.preamble.api_version = NINLIL_RRMP_PRIVATE_V2_API_VERSION;
    commit.preamble.struct_size = (uint32_t)sizeof(commit);
    memcpy(commit.owner_scope_id, owner_scope_id, 16u);
    commit.expected_new = new_tuple;
    memcpy(commit.handoff_token_digest32, token, 32u);
    ninlil_rrmp_sha256(
        proof_preimage,
        sizeof(proof_preimage),
        commit.proof_digest32);

    memcpy(commit_preimage + off, commit_domain, sizeof(commit_domain) - 1u);
    off += sizeof(commit_domain) - 1u;
    memcpy(commit_preimage + off, owner_scope_id, 16u);
    off += 16u;
    sim_authority_tuple_encode(&commit.expected_old, tuple_bytes);
    memcpy(commit_preimage + off, tuple_bytes, 104u);
    off += 104u;
    sim_authority_tuple_encode(&commit.expected_new, tuple_bytes);
    memcpy(commit_preimage + off, tuple_bytes, 104u);
    off += 104u;
    memcpy(commit_preimage + off, token, 32u);
    off += 32u;
    memcpy(commit_preimage + off, commit.proof_digest32, 32u);
    off += 32u;
    ninlil_rrmp_memzero(commit_preimage + off, 296u);
    off += 296u;
    ninlil_rrmp_put_u64_be(commit_preimage + off, 0u);
    off += 8u;
    ninlil_rrmp_sha256(
        commit_preimage,
        off,
        commit.authority_commit_digest32);
    if (ninlil_parent_authority_commit_v2(&commit, out) !=
        NINLIL_PARENT_OK) {
        return 0;
    }

    ninlil_rrmp_memzero(&activate, sizeof(activate));
    activate.preamble.api_version = 1u;
    activate.preamble.struct_size = (uint32_t)sizeof(activate);
    memcpy(activate.owner_scope_id, owner_scope_id, 16u);
    memcpy(
        activate.commit_receipt_digest32,
        commit.authority_commit_digest32,
        32u);
    activate.now_ms = 1000000u;
    return ninlil_parent_owner_activate(&activate, out) ==
        NINLIL_PARENT_OK;
}

void ninlil_rrmp_sim_fini(ninlil_rrmp_sim_t *sim)
{
    if (sim == NULL) {
        return;
    }
    ninlil_rrmp_owner_fini(sim->endpoint_relay);
    ninlil_rrmp_owner_fini(sim->parent_a);
    ninlil_rrmp_owner_fini(sim->parent_b);
    ninlil_rrmp_memzero(sim, sizeof(*sim));
}

int ninlil_rrmp_sim_run_bounded_driver(ninlil_rrmp_sim_t *sim)
{
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_activate_req_v1_t act;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_parent_set_install_req_v1_t pset;
    ninlil_route_result_v1_t rout;
    ninlil_parent_result_v1_t pout;
    ninlil_rrmp_nrm1_fields_t nrm;
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
    ninlil_rrmp_digest32_t dig;
    ninlil_rrmp_id16_t pids[2];
    uint32_t st;
    uint8_t selected[16];
    size_t i;

    if (sim == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(sim, sizeof(*sim));
    sim->endpoint_relay = mk_owner(g_sim_ws_ep, 0x10u, 1u, 1u);
    sim->parent_a = mk_owner(g_sim_ws_pa, 0x30u, 0u, 1u);
    sim->parent_b = mk_owner(g_sim_ws_pb, 0x40u, 0u, 1u);
    if (sim->endpoint_relay == NULL) {
        return 0;
    }
    fill_id(sim->scope, 0x90u);
    ninlil_rrmp_memzero(sim->attempt_id16, 16u);
    ninlil_rrmp_put_u16_be(sim->attempt_id16 + 14, 1u);
    ninlil_rrmp_owner_bind(sim->endpoint_relay);

    ninlil_rrmp_memzero(&install, sizeof(install));
    install.preamble.api_version = 1u;
    install.preamble.struct_size = 312u;
    fill_id(install.authority_id, 0xA0u);
    install.controller_term = 5u;
    install.batch_id = 1u;
    install.entry_count = 1u;
    fill_nrm1(&nrm, 1u, 1u, 1u);
    (void)ninlil_rrmp_encode_nrm1(&nrm, raw);
    memcpy(install.entries, raw, sizeof(raw));
    st = ninlil_route_install_batch(&install, &rout);
    push(sim, 1u, st, 0u);

    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = 64u;
    act.ingress_hop_context_id = 0x1001u;
    act.route_handle = 1u;
    act.route_generation = 1u;
    act.now_ms = 1000000u;
    st = ninlil_route_activate(&act, &rout);
    push(sim, 2u, st, 0u);

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0xAAu + i);
    }
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 1u;
    st = ninlil_route_forward_admit(&admit, &rout);
    push(sim, 3u, st, rout.hop_remaining_out);

    st = ninlil_rrmp_core_forward_service_once(sim->endpoint_relay, &rout);
    push(sim, 4u, st, 0u);

    ninlil_rrmp_memzero(&pset, sizeof(pset));
    pset.preamble.api_version = 1u;
    pset.preamble.struct_size = 240u;
    memcpy(pset.owner_scope_id, sim->scope, 16u);
    pset.parent_set_count = 2u;
    fill_id(pset.path_policy_id, 0x50u);
    pset.controller_term = 5u;
    pset.assignment_epoch = 1u;
    fill_id(pids[0].bytes, 0x30u);
    fill_id(pids[1].bytes, 0x40u);
    memcpy(pset.parent_runtime_id[0], pids[0].bytes, 16u);
    memcpy(pset.parent_runtime_id[1], pids[1].bytes, 16u);
    (void)ninlil_rrmp_parent_set_digest(pids, 2u, &dig);
    memcpy(pset.parent_set_digest32, dig.bytes, 32u);
    st = ninlil_parent_set_install(&pset, &pout);
    push(sim, 6u, st, 2u);
    if (st != NINLIL_PARENT_OK ||
        !sim_bootstrap_assignment(
            sim->scope,
            pset.path_policy_id,
            pset.parent_set_digest32,
            pset.parent_set_count,
            &pout)) {
        ninlil_rrmp_owner_unbind();
        return 0;
    }
    push(sim, 5u, NINLIL_PARENT_OK, pout.handoff_step);

    st = ninlil_rrmp_core_parent_select_for_attempt(
        sim->endpoint_relay, sim->scope, sim->attempt_id16, selected, &pout);
    push(sim, 7u, st, 0u);

    st = ninlil_rrmp_core_parent_select_for_attempt(
        sim->endpoint_relay, sim->scope, sim->attempt_id16, selected, &pout);
    push(sim, 8u, st, (uint32_t)ninlil_rrmp_get_u16_be(sim->attempt_id16 + 14));

    ninlil_rrmp_put_u16_be(sim->attempt_id16 + 14, 2u);
    st = ninlil_rrmp_core_parent_select_for_attempt(
        sim->endpoint_relay, sim->scope, sim->attempt_id16, selected, &pout);
    push(sim, 9u, st, (uint32_t)ninlil_rrmp_get_u16_be(sim->attempt_id16 + 14));

    {
        uint8_t wa[16], wb[16];
        fill_id(wa, 0xA1u);
        fill_id(wb, 0xA2u);
        st = ninlil_rrmp_core_split_brain_detect(
            sim->endpoint_relay, sim->scope, wa, wb, 5u, 5u);
        push(sim, 10u, st, ninlil_rrmp_owner_downlink_tx_allowed(sim->endpoint_relay));
    }

    ninlil_rrmp_owner_unbind();
    return 1;
}

uint32_t ninlil_rrmp_sim_step_count(const ninlil_rrmp_sim_t *sim)
{
    return sim == NULL ? 0u : sim->step_count;
}

const ninlil_rrmp_sim_step_t *ninlil_rrmp_sim_step_at(
    const ninlil_rrmp_sim_t *sim, uint32_t index)
{
    if (sim == NULL || index >= sim->step_count) {
        return NULL;
    }
    return &sim->steps[index];
}
