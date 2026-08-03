#ifndef NINLIL_TESTS_RUNTIME_ROUTE_RELAY_V1_RRMP_TEST_COMMON_H
#define NINLIL_TESTS_RUNTIME_ROUTE_RELAY_V1_RRMP_TEST_COMMON_H

#include "rrmp_abi.h"
#include "rrmp_codec.h"
#include "rrmp_seam.h"
#include "rrmp_sim.h"
#include "rrmp_store.h"
#include "rrmp_util.h"

#include <stdio.h>
#include <string.h>

#define RRMP_CHECK(cond)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            fprintf(stderr, "CHECK %s:%d %s\n", __FILE__, __LINE__, #cond);    \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define RRMP_CHECK_EQ(a, b)                                                    \
    do {                                                                       \
        unsigned long long _a = (unsigned long long)(a);                       \
        unsigned long long _b = (unsigned long long)(b);                       \
        if (_a != _b) {                                                        \
            fprintf(stderr, "EQ %s:%d %s=%llu %s=%llu\n", __FILE__, __LINE__,  \
                #a, _a, #b, _b);                                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

/* Caller-owned workspace — no calloc in production path. */
typedef struct rrmp_test_ws {
    uint8_t bytes[1]; /* actual size set via static array at use site */
} rrmp_test_ws_t;

static inline void rrmp_fill_id(uint8_t id[16], uint8_t seed)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        id[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static inline void rrmp_cfg_fill(
    ninlil_rrmp_owner_config_v1_t *cfg, uint8_t route_on, uint8_t parent_on)
{
    ninlil_rrmp_memzero(cfg, sizeof(*cfg));
    cfg->preamble.api_version = 1u;
    cfg->preamble.struct_size = (uint32_t)sizeof(*cfg);
    rrmp_fill_id(cfg->local_runtime_id, 0x10u);
    rrmp_fill_id(cfg->authority_id, 0xA0u);
    cfg->controller_term = 5u;
    rrmp_fill_id(cfg->authority_clock_epoch_id, 0x50u);
    cfg->feature_route_relay = route_on;
    cfg->feature_multi_parent = parent_on;
    cfg->max_hops_profile = 3u;
    cfg->now_ms = 1000000u;
}

static inline ninlil_rrmp_owner_t *rrmp_mk_ws(
    void *ws, size_t ws_bytes, uint8_t route_on, uint8_t parent_on)
{
    ninlil_rrmp_owner_config_v1_t cfg;
    rrmp_cfg_fill(&cfg, route_on, parent_on);
    return ninlil_rrmp_owner_init(ws, ws_bytes, &cfg);
}

static inline void rrmp_fill_nrm1(
    ninlil_rrmp_nrm1_fields_t *f, uint16_t h, uint8_t hops, uint8_t term)
{
    ninlil_rrmp_memzero(f, sizeof(*f));
    rrmp_fill_id(f->authority_id.bytes, 0xA0u);
    f->controller_term = 5u;
    f->route_revision = 1u;
    f->lease_epoch = 1u;
    rrmp_fill_id(f->authority_clock_epoch_id.bytes, 0x50u);
    f->lease_expiry_ms = 5000000u;
    f->ingress_hop_context_id = 0x1000u + h;
    f->route_handle = h;
    f->route_generation = 1u;
    rrmp_fill_id(f->egress_peer_id.bytes, 0x60u);
    f->egress_hop_context_id = 0x2000u + h;
    if (term) {
        f->egress_route_handle = 0u;
        f->egress_route_generation = 0u;
    } else {
        f->egress_route_handle = (uint16_t)(h + 10u);
        f->egress_route_generation = 1u;
    }
    rrmp_fill_id(f->grant_id.bytes, 0x70u);
    f->queue_quota_entries = 8u;
    f->queue_quota_bytes = 2048u;
    f->max_hops = hops;
    f->ack_policy = 1u;
    f->terminal_flag = term;
    rrmp_fill_id(f->path_policy_id.bytes, 0x80u);
    f->path_policy_revision = 1u;
}

static inline int rrmp_install_activate(
    ninlil_rrmp_owner_t *o, uint16_t h, uint8_t hops, uint8_t term)
{
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_activate_req_v1_t act;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_nrm1_fields_t f;
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
    ninlil_rrmp_owner_bind(o);
    ninlil_rrmp_memzero(&install, sizeof(install));
    install.preamble.api_version = 1u;
    install.preamble.struct_size = 312u;
    rrmp_fill_id(install.authority_id, 0xA0u);
    install.controller_term = 5u;
    install.batch_id = 1u;
    install.entry_count = 1u;
    rrmp_fill_nrm1(&f, h, hops, term);
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
    act.ingress_hop_context_id = 0x1000u + h;
    act.route_handle = h;
    act.route_generation = 1u;
    act.now_ms = 1000000u;
    if (ninlil_route_activate(&act, &out) != NINLIL_ROUTE_OK) {
        return 1;
    }
    return 0;
}

static inline void rrmp_fence_proof_digest(
    const uint8_t scope[16],
    const uint8_t token[32],
    uint64_t old_rev,
    uint8_t out[32])
{
    uint8_t pre[56];
    memcpy(pre, scope, 16u);
    memcpy(pre + 16, token, 32u);
    ninlil_rrmp_put_u64_be(pre + 48, old_rev);
    ninlil_rrmp_sha256(pre, 56u, out);
}

static inline void rrmp_test_authority_tuple_encode(
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

static inline int rrmp_test_authority_tuple_from_noa(
    const uint8_t raw[NINLIL_RRMP_NOA1_BYTES],
    uint64_t writer_epoch,
    ninlil_rrmp_authority_tuple_v2_t *out)
{
    ninlil_rrmp_noa1_fields_t noa;
    if (raw == NULL || out == NULL || writer_epoch == 0u ||
        writer_epoch == UINT64_MAX ||
        !ninlil_rrmp_decode_noa1(raw, &noa)) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->present = 1u;
    out->exact_noa1_length = NINLIL_RRMP_NOA1_BYTES;
    ninlil_rrmp_sha256(
        raw, NINLIL_RRMP_NOA1_BYTES, out->noa1_sha256);
    out->assignment_revision = noa.assignment_revision;
    out->controller_term = noa.controller_term;
    memcpy(out->owner_controller_id, noa.owner_controller_id.bytes, 16u);
    out->writer_epoch = writer_epoch;
    out->lease_not_after_ms = noa.lease_not_after_authority_ms;
    memcpy(
        out->authority_clock_epoch_id,
        noa.authority_clock_epoch_id.bytes,
        16u);
    return 1;
}

static inline ninlil_parent_status_u32 rrmp_test_owner_prepare_v2(
    const ninlil_parent_owner_prepare_req_v1_t *legacy,
    const ninlil_rrmp_authority_tuple_v2_t *expected_old,
    uint64_t new_writer_epoch,
    ninlil_rrmp_authority_tuple_v2_t *expected_new_out,
    ninlil_parent_result_v1_t *out)
{
    ninlil_parent_owner_prepare_req_v2_t req;
    if (legacy == NULL || expected_old == NULL ||
        expected_new_out == NULL || out == NULL ||
        !rrmp_test_authority_tuple_from_noa(
            legacy->new_assignment_noa1,
            new_writer_epoch,
            expected_new_out)) {
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = NINLIL_RRMP_PRIVATE_V2_API_VERSION;
    req.preamble.struct_size = (uint32_t)sizeof(req);
    memcpy(req.owner_scope_id, legacy->owner_scope_id, 16u);
    req.expected_old = *expected_old;
    memcpy(
        req.new_assignment_noa1,
        legacy->new_assignment_noa1,
        NINLIL_RRMP_NOA1_BYTES);
    memcpy(
        req.handoff_token_digest32,
        legacy->handoff_token_digest32,
        32u);
    return ninlil_parent_owner_prepare_v2(&req, out);
}

static inline ninlil_parent_status_u32 rrmp_test_owner_fence_v2(
    const uint8_t owner_scope_id[16],
    const uint8_t handoff_token_digest32[32],
    const ninlil_rrmp_authority_tuple_v2_t *expected_old,
    uint8_t proof_digest_out[32],
    ninlil_parent_result_v1_t *out)
{
    ninlil_parent_owner_fence_proof_req_v2_t req;
    uint8_t tuple_bytes[104];
    static const uint8_t domain[] =
        "NINLIL-RRMP-EXPLICIT-RESIGN-V2";
    uint8_t preimage[
        sizeof(domain) - 1u + 104u + 16u + 32u];
    if (owner_scope_id == NULL || handoff_token_digest32 == NULL ||
        expected_old == NULL || proof_digest_out == NULL || out == NULL) {
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    ninlil_rrmp_memzero(proof_digest_out, 32u);
    if (!expected_old->present) {
        static const uint8_t no_old_domain[] =
            "NINLIL-RRMP-NO-OLD-AUTHORITY-V2";
        uint8_t no_old_preimage[
            sizeof(no_old_domain) - 1u + 16u + 32u];
        /*
         * The first assignment has no old writer. PREPARED_NEW already owns
         * the vacuous proof and commits directly from S1.
         */
        memcpy(
            no_old_preimage,
            no_old_domain,
            sizeof(no_old_domain) - 1u);
        memcpy(
            no_old_preimage + sizeof(no_old_domain) - 1u,
            owner_scope_id,
            16u);
        memcpy(
            no_old_preimage + sizeof(no_old_domain) - 1u + 16u,
            handoff_token_digest32,
            32u);
        ninlil_rrmp_sha256(
            no_old_preimage,
            sizeof(no_old_preimage),
            proof_digest_out);
        return NINLIL_PARENT_OK;
    }
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = NINLIL_RRMP_PRIVATE_V2_API_VERSION;
    req.preamble.struct_size = (uint32_t)sizeof(req);
    memcpy(req.owner_scope_id, owner_scope_id, 16u);
    req.expected_old = *expected_old;
    memcpy(
        req.handoff_token_digest32, handoff_token_digest32, 32u);
    req.proof_kind = NINLIL_RRMP_HANDOFF_PROOF_EXPLICIT_RESIGN;
    rrmp_test_authority_tuple_encode(expected_old, tuple_bytes);
    memcpy(preimage, domain, sizeof(domain) - 1u);
    memcpy(preimage + sizeof(domain) - 1u, tuple_bytes, 104u);
    memcpy(
        preimage + sizeof(domain) - 1u + 104u,
        owner_scope_id,
        16u);
    memcpy(
        preimage + sizeof(domain) - 1u + 120u,
        handoff_token_digest32,
        32u);
    ninlil_rrmp_sha256(
        preimage, sizeof(preimage), req.explicit_resign_digest32);
    {
        ninlil_parent_status_u32 status =
            ninlil_parent_owner_fence_proof_v2(&req, out);
        if (status == NINLIL_PARENT_OK) {
            memcpy(
                proof_digest_out,
                out->token_or_commit_digest32,
                32u);
        }
        return status;
    }
}

static inline ninlil_parent_status_u32 rrmp_test_authority_commit_v2(
    const uint8_t owner_scope_id[16],
    const ninlil_rrmp_authority_tuple_v2_t *expected_old,
    const ninlil_rrmp_authority_tuple_v2_t *expected_new,
    const uint8_t handoff_token_digest32[32],
    const uint8_t proof_digest32[32],
    const ninlil_rrmp_bundle_witness_v2_t *expected_bundle_or_null,
    uint64_t cas_expected_generation,
    uint8_t commit_digest_out[32],
    ninlil_parent_result_v1_t *out)
{
    ninlil_parent_authority_commit_req_v2_t req;
    uint8_t preimage[640];
    uint8_t tuple_bytes[104];
    uint8_t bundle_bytes[296];
    size_t off = 0u;
    static const uint8_t domain[] =
        "NINLIL-RRMP-AUTHORITY-COMMIT-V2";
    if (owner_scope_id == NULL || expected_old == NULL ||
        expected_new == NULL || handoff_token_digest32 == NULL ||
        proof_digest32 == NULL || commit_digest_out == NULL ||
        out == NULL) {
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = NINLIL_RRMP_PRIVATE_V2_API_VERSION;
    req.preamble.struct_size = (uint32_t)sizeof(req);
    memcpy(req.owner_scope_id, owner_scope_id, 16u);
    req.expected_old = *expected_old;
    req.expected_new = *expected_new;
    memcpy(
        req.handoff_token_digest32, handoff_token_digest32, 32u);
    memcpy(req.proof_digest32, proof_digest32, 32u);
    if (expected_bundle_or_null != NULL) {
        req.expected_bundle = *expected_bundle_or_null;
    }
    req.cas_expected_generation = cas_expected_generation;
    memcpy(preimage + off, domain, sizeof(domain) - 1u);
    off += sizeof(domain) - 1u;
    memcpy(preimage + off, owner_scope_id, 16u);
    off += 16u;
    rrmp_test_authority_tuple_encode(expected_old, tuple_bytes);
    memcpy(preimage + off, tuple_bytes, 104u);
    off += 104u;
    rrmp_test_authority_tuple_encode(expected_new, tuple_bytes);
    memcpy(preimage + off, tuple_bytes, 104u);
    off += 104u;
    memcpy(preimage + off, handoff_token_digest32, 32u);
    off += 32u;
    memcpy(preimage + off, proof_digest32, 32u);
    off += 32u;
    ninlil_rrmp_memzero(bundle_bytes, sizeof(bundle_bytes));
    if (expected_bundle_or_null != NULL) {
        bundle_bytes[0] = expected_bundle_or_null->present;
        memcpy(
            bundle_bytes + 4u,
            expected_bundle_or_null->manifest_rrm1,
            NINLIL_RRMP_RRM1_BYTES);
        ninlil_rrmp_put_u32_be(
            bundle_bytes + 260u,
            expected_bundle_or_null->logical_length);
        memcpy(
            bundle_bytes + 264u,
            expected_bundle_or_null->logical_sha256,
            32u);
    }
    memcpy(preimage + off, bundle_bytes, sizeof(bundle_bytes));
    off += sizeof(bundle_bytes);
    ninlil_rrmp_put_u64_be(
        preimage + off, cas_expected_generation);
    off += 8u;
    ninlil_rrmp_sha256(preimage, off, commit_digest_out);
    memcpy(
        req.authority_commit_digest32, commit_digest_out, 32u);
    return ninlil_parent_authority_commit_v2(&req, out);
}

static inline int rrmp_test_bootstrap_assignment_v2(
    const uint8_t owner_scope_id[16],
    const uint8_t path_policy_id[16],
    const uint8_t parent_set_digest32[32],
    uint8_t parent_set_count,
    const uint8_t token32[32],
    uint64_t cas_expected_generation,
    uint8_t commit_digest_out[32])
{
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_activate_req_v1_t activate;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    uint8_t proof[32];
    if (owner_scope_id == NULL || path_policy_id == NULL ||
        parent_set_digest32 == NULL || token32 == NULL ||
        commit_digest_out == NULL || parent_set_count == 0u) {
        return 0;
    }
    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, owner_scope_id, 16u);
    rrmp_fill_id(noa.authority_id.bytes, 0xA0u);
    noa.controller_term = 5u;
    noa.assignment_epoch = 1u;
    noa.assignment_revision = cas_expected_generation + 1u;
    rrmp_fill_id(noa.owner_controller_id.bytes, 0xB0u);
    rrmp_fill_id(noa.owner_cell_id.bytes, 0xB1u);
    noa.direction = 1u;
    noa.e2e_context_id = 1u;
    noa.key_generation = 1u;
    rrmp_fill_id(noa.e2e_security_id.bytes, 0xD0u);
    noa.e2e_security_epoch = 1u;
    memset(noa.e2e_binding_digest.bytes, 0xE1, 32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memcpy(noa.handoff_token_digest.bytes, token32, 32u);
    memcpy(noa.parent_set_digest.bytes, parent_set_digest32, 32u);
    noa.parent_set_count = parent_set_count;
    memcpy(noa.parent_set_id.bytes, path_policy_id, 16u);
    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = (uint32_t)sizeof(prep);
    memcpy(prep.owner_scope_id, owner_scope_id, 16u);
    if (!ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1)) {
        return 0;
    }
    memcpy(prep.handoff_token_digest32, token32, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    if (rrmp_test_owner_prepare_v2(
            &prep,
            &old_tuple,
            cas_expected_generation + 1u,
            &new_tuple,
            &out) != NINLIL_PARENT_OK ||
        rrmp_test_owner_fence_v2(
            owner_scope_id,
            token32,
            &old_tuple,
            proof,
            &out) != NINLIL_PARENT_OK ||
        rrmp_test_authority_commit_v2(
            owner_scope_id,
            &old_tuple,
            &new_tuple,
            token32,
            proof,
            NULL,
            cas_expected_generation,
            commit_digest_out,
            &out) != NINLIL_PARENT_OK) {
        return 0;
    }
    ninlil_rrmp_memzero(&activate, sizeof(activate));
    activate.preamble.api_version = 1u;
    activate.preamble.struct_size = (uint32_t)sizeof(activate);
    memcpy(activate.owner_scope_id, owner_scope_id, 16u);
    memcpy(
        activate.commit_receipt_digest32, commit_digest_out, 32u);
    activate.now_ms = 1000000u;
    return ninlil_parent_owner_activate(&activate, &out) ==
        NINLIL_PARENT_OK;
}

/* --- Outbound provider + authenticated LINK_ACK helpers (host tests) --- */

typedef struct rrmp_test_outbound {
    ninlil_rrmp_outbound_packet_t last;
    uint32_t submit_count;
    uint32_t next_status; /* NINLIL_RRMP_OUTBOUND_*; 0 → ACCEPTED */
    uint8_t has_last;
} rrmp_test_outbound_t;

static inline uint32_t rrmp_test_outbound_submit(
    void *user, const ninlil_rrmp_outbound_packet_t *pkt)
{
    rrmp_test_outbound_t *s = (rrmp_test_outbound_t *)user;
    uint32_t st;
    if (s == NULL || pkt == NULL) {
        return NINLIL_RRMP_OUTBOUND_DENIED;
    }
    s->last = *pkt;
    s->has_last = 1u;
    s->submit_count += 1u;
    st = s->next_status != 0u ? s->next_status : NINLIL_RRMP_OUTBOUND_ACCEPTED;
    s->next_status = 0u;
    return st;
}

static inline void rrmp_install_test_outbound(
    ninlil_rrmp_owner_t *o, rrmp_test_outbound_t *state)
{
    ninlil_rrmp_outbound_provider_t p;
    ninlil_rrmp_memzero(state, sizeof(*state));
    ninlil_rrmp_memzero(&p, sizeof(p));
    p.user = state;
    p.submit = rrmp_test_outbound_submit;
    ninlil_rrmp_owner_set_outbound_provider(o, &p);
}

static inline void rrmp_fill_attempt_id16(uint8_t out[16], uint16_t ordinal)
{
    ninlil_rrmp_memzero(out, 16u);
    ninlil_rrmp_put_u16_be(out + 14, ordinal);
}

static inline ninlil_route_status_u32 rrmp_auth_link_ack(
    ninlil_rrmp_owner_t *o,
    uint64_t opaque,
    uint64_t outer_tx,
    ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_link_ack_evidence_t ev;
    size_t i;
    ninlil_rrmp_memzero(&ev, sizeof(ev));
    ev.opaque_local_handle = opaque;
    ev.auth_ok = 1u;
    ev.ack_ok = 1u;
    ev.outer_tx_counter = outer_tx;
    /* Default fixture route egress_peer_id is seed 0x60. */
    rrmp_fill_id(ev.peer_runtime_id, 0x60u);
    for (i = 0u; i < 32u; ++i) {
        ev.auth_proof32[i] = (uint8_t)(0xA1u + i);
    }
    return ninlil_rrmp_core_link_ack_from_evidence(o, &ev, out);
}

/* Default scope derivation used by multi-parent tests. */
static inline void rrmp_default_scope_derivation(
    ninlil_rrmp_scope_derivation_ctx_t *ctx)
{
    ninlil_rrmp_memzero(ctx, sizeof(*ctx));
    rrmp_fill_id(ctx->endpoint_runtime_id, 0x10u);
    ctx->direction = 0u;
    ctx->traffic_class = 1u;
    ctx->namespace_len = 4u;
    ctx->service_len = 3u;
    memcpy(ctx->namespace, "nspc", 4u);
    memcpy(ctx->service, "svc", 3u);
}

static inline int rrmp_derive_scope_for_path_policy(
    const uint8_t path_policy[16], uint8_t scope_out[16])
{
    ninlil_rrmp_scope_derivation_ctx_t ctx;
    rrmp_default_scope_derivation(&ctx);
    return ninlil_rrmp_derive_owner_scope_id(
        ctx.endpoint_runtime_id,
        ctx.direction,
        ctx.namespace,
        ctx.namespace_len,
        ctx.service,
        ctx.service_len,
        ctx.traffic_class,
        path_policy,
        scope_out);
}

#endif
