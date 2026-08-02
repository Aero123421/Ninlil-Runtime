/*
 * Host-only RRMP software lifecycle fixture.
 * Synthetic FULL store + outbound are host KAT doubles — not carrier/HIL proof.
 */
#include "rrmp_host_lifecycle_fixture.h"
#include "rrmp_test_common.h"

#include "rrmp_composition.h"
#include "rrmp_fabric_dispatch.h"

#include "ninlil/platform.h"

#include <stdalign.h>
#include <string.h>

#define HOST_STORE_PIECES 6u
#define HOST_STORE_PIECE_BYTES NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX

typedef struct host_ram_store {
    uint8_t present[HOST_STORE_PIECES];
    uint8_t value[HOST_STORE_PIECES][HOST_STORE_PIECE_BYTES];
    uint32_t value_len[HOST_STORE_PIECES];
    ninlil_storage_ops_t ops;
    ninlil_storage_handle_t handle;
} host_ram_store_t;

typedef struct host_ram_txn {
    host_ram_store_t *store;
    uint8_t present[HOST_STORE_PIECES];
    uint8_t value[HOST_STORE_PIECES][HOST_STORE_PIECE_BYTES];
    uint32_t value_len[HOST_STORE_PIECES];
    uint8_t dirty;
    uint8_t iter_index;
    ninlil_storage_mode_t mode;
} host_ram_txn_t;

typedef struct host_outbound {
    ninlil_rrmp_outbound_packet_t last;
    uint32_t submit_count;
    uint8_t has_last;
} host_outbound_t;

static host_ram_store_t g_host_store;

/* Off-stack request blobs (host test only). */
static ninlil_route_install_batch_req_v1_t s_install;
static ninlil_route_activate_req_v1_t s_act;
static ninlil_route_forward_admit_req_v1_t s_admit;
static ninlil_route_forward_complete_req_v1_t s_complete;
static ninlil_route_retire_req_v1_t s_retire;
static ninlil_route_query_req_v1_t s_rq;
static ninlil_route_result_v1_t s_rout;
static ninlil_parent_set_install_req_v1_t s_pset;
static ninlil_parent_query_req_v1_t s_pq;
static ninlil_parent_result_v1_t s_pout;
static ninlil_rrmp_nrm1_fields_t s_nrm;
static ninlil_rrmp_hop_tx_view_t s_tx;
static ninlil_rrmp_fabric_select_view_t s_fview;
static uint8_t s_raw[NINLIL_RRMP_NRM1_BYTES];

static int host_key_kind(ninlil_bytes_view_t key)
{
    static const uint8_t manifest[7] =
        {'R', 'R', 'M', 'P', '/', 'M', '1'};
    static const uint8_t chunks[5][7] = {
        {'R', 'R', 'M', 'P', '/', 'C', '0'},
        {'R', 'R', 'M', 'P', '/', 'C', '1'},
        {'R', 'R', 'M', 'P', '/', 'C', '2'},
        {'R', 'R', 'M', 'P', '/', 'C', '3'},
        {'R', 'R', 'M', 'P', '/', 'C', '4'},
    };
    uint8_t i;
    if (key.data == NULL || key.length != 7u) {
        return -1;
    }
    if (memcmp(key.data, manifest, 7u) == 0) {
        return 0;
    }
    for (i = 0u; i < 5u; ++i) {
        if (memcmp(key.data, chunks[i], 7u) == 0) {
            return (int)i + 1;
        }
    }
    return -1;
}

static uint32_t host_outbound_submit(void *user, const ninlil_rrmp_outbound_packet_t *pkt)
{
    host_outbound_t *s = (host_outbound_t *)user;
    if (s == NULL || pkt == NULL) {
        return NINLIL_RRMP_OUTBOUND_DENIED;
    }
    s->last = *pkt;
    s->has_last = 1u;
    s->submit_count += 1u;
    return NINLIL_RRMP_OUTBOUND_ACCEPTED;
}

static ninlil_storage_status_t h_open(
    void *user, ninlil_bytes_view_t ns, uint32_t schema, ninlil_storage_handle_t *out)
{
    (void)ns;
    (void)schema;
    if (out == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out = (ninlil_storage_handle_t)user;
    return NINLIL_STORAGE_OK;
}
static void h_close(void *user, ninlil_storage_handle_t h)
{
    (void)user;
    (void)h;
}
static ninlil_storage_status_t h_begin(
    void *user, ninlil_storage_handle_t h, ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    static host_ram_txn_t s_txn;
    (void)h;
    if (out_txn == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    ninlil_rrmp_memzero(&s_txn, sizeof(s_txn));
    s_txn.store = (host_ram_store_t *)user;
    s_txn.mode = mode;
    memcpy(
        s_txn.present,
        s_txn.store->present,
        sizeof(s_txn.present));
    memcpy(
        s_txn.value,
        s_txn.store->value,
        sizeof(s_txn.value));
    memcpy(
        s_txn.value_len,
        s_txn.store->value_len,
        sizeof(s_txn.value_len));
    *out_txn = (ninlil_storage_txn_t)&s_txn;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t h_get(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout)
{
    host_ram_txn_t *t = (host_ram_txn_t *)txn;
    int kind = host_key_kind(key);
    (void)user;
    if (t == NULL || inout == NULL || t->store == NULL ||
        kind < 0 || !t->present[kind]) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (inout->capacity < t->value_len[kind]) {
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    memcpy(inout->data, t->value[kind], t->value_len[kind]);
    inout->length = t->value_len[kind];
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t h_put(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    host_ram_txn_t *t = (host_ram_txn_t *)txn;
    int kind = host_key_kind(key);
    (void)user;
    if (t == NULL || t->store == NULL || t->mode != NINLIL_STORAGE_READ_WRITE ||
        kind < 0 ||
        value.data == NULL || value.length == 0u ||
        value.length > HOST_STORE_PIECE_BYTES) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    memcpy(t->value[kind], value.data, value.length);
    t->value_len[kind] = value.length;
    t->present[kind] = 1u;
    t->dirty = 1u;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t h_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    host_ram_txn_t *t = (host_ram_txn_t *)txn;
    int kind = host_key_kind(key);
    (void)user;
    if (t == NULL || kind < 0 ||
        t->mode != NINLIL_STORAGE_READ_WRITE) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->present[kind] = 0u;
    t->value_len[kind] = 0u;
    t->dirty = 1u;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t h_iter_open(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t p,
    ninlil_storage_iter_t *out)
{
    host_ram_txn_t *t = (host_ram_txn_t *)txn;
    static const uint8_t prefix[5] = {'R', 'R', 'M', 'P', '/'};
    (void)user;
    if (t == NULL || out == NULL || p.length != 5u ||
        memcmp(p.data, prefix, 5u) != 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->iter_index = 0u;
    *out = (ninlil_storage_iter_t)t;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t h_iter_next(
    void *user, ninlil_storage_iter_t it, ninlil_mut_bytes_t *k, ninlil_mut_bytes_t *v)
{
    host_ram_txn_t *t = (host_ram_txn_t *)it;
    static const uint8_t keys[6][7] = {
        {'R', 'R', 'M', 'P', '/', 'C', '0'},
        {'R', 'R', 'M', 'P', '/', 'C', '1'},
        {'R', 'R', 'M', 'P', '/', 'C', '2'},
        {'R', 'R', 'M', 'P', '/', 'C', '3'},
        {'R', 'R', 'M', 'P', '/', 'C', '4'},
        {'R', 'R', 'M', 'P', '/', 'M', '1'},
    };
    static const uint8_t kinds[6] = {1u, 2u, 3u, 4u, 5u, 0u};
    (void)user;
    if (t == NULL || k == NULL || v == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    while (t->iter_index < 6u) {
        uint8_t ordinal = t->iter_index++;
        uint8_t kind = kinds[ordinal];
        if (!t->present[kind]) {
            continue;
        }
        if (k->capacity < 7u ||
            v->capacity < t->value_len[kind]) {
            return NINLIL_STORAGE_BUFFER_TOO_SMALL;
        }
        memcpy(k->data, keys[ordinal], 7u);
        k->length = 7u;
        memcpy(v->data, t->value[kind], t->value_len[kind]);
        v->length = t->value_len[kind];
        return NINLIL_STORAGE_OK;
    }
    return NINLIL_STORAGE_NOT_FOUND;
}
static void h_iter_close(void *user, ninlil_storage_iter_t it)
{
    (void)user;
    (void)it;
}
static ninlil_storage_status_t h_capacity(
    void *user, ninlil_storage_handle_t h, ninlil_storage_capacity_t *c)
{
    (void)user;
    (void)h;
    (void)c;
    return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}
static ninlil_storage_status_t h_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t dur)
{
    host_ram_txn_t *t = (host_ram_txn_t *)txn;
    (void)user;
    if (t == NULL || t->store == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (dur != NINLIL_DURABILITY_FULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (t->dirty) {
        memcpy(
            t->store->present,
            t->present,
            sizeof(t->store->present));
        memcpy(
            t->store->value,
            t->value,
            sizeof(t->store->value));
        memcpy(
            t->store->value_len,
            t->value_len,
            sizeof(t->store->value_len));
    }
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t h_rollback(void *user, ninlil_storage_txn_t txn)
{
    (void)user;
    (void)txn;
    return NINLIL_STORAGE_OK;
}

static void host_store_init(host_ram_store_t *s)
{
    ninlil_rrmp_memzero(s, sizeof(*s));
    s->ops.abi_version = NINLIL_ABI_VERSION;
    s->ops.struct_size = (uint32_t)sizeof(s->ops);
    s->ops.user = s;
    s->ops.open = h_open;
    s->ops.close = h_close;
    s->ops.begin = h_begin;
    s->ops.get = h_get;
    s->ops.put = h_put;
    s->ops.erase = h_erase;
    s->ops.iter_open = h_iter_open;
    s->ops.iter_next = h_iter_next;
    s->ops.iter_close = h_iter_close;
    s->ops.capacity = h_capacity;
    s->ops.commit = h_commit;
    s->ops.rollback = h_rollback;
    s->handle = (ninlil_storage_handle_t)s;
}

static uint32_t host_store_logical_length(const host_ram_store_t *s)
{
    if (s == NULL || !s->present[0] ||
        s->value_len[0] != NINLIL_RRMP_RRM1_BYTES ||
        memcmp(s->value[0], "RRM1", 4u) != 0) {
        return 0u;
    }
    return ninlil_rrmp_get_u32_be(s->value[0] + 16u);
}

static void fill_id(uint8_t id[16], uint8_t seed)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        id[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static int host_parent_bootstrap_assignment(
    const uint8_t scope[16],
    const uint8_t path_policy[16],
    const uint8_t parent_digest[32],
    uint8_t parent_count)
{
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_activate_req_v1_t activate;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    ninlil_rrmp_bundle_witness_v2_t bundle;
    uint8_t token[32];
    uint8_t proof[32];
    uint8_t commit_digest[32];
    if (scope == NULL || path_policy == NULL || parent_digest == NULL ||
        parent_count == 0u || !g_host_store.present[0] ||
        g_host_store.value_len[0] != NINLIL_RRMP_RRM1_BYTES) {
        return 0;
    }
    memset(token, 0x5Bu, sizeof(token));
    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, scope, 16u);
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
    memcpy(noa.parent_set_digest.bytes, parent_digest, 32u);
    noa.parent_set_count = parent_count;
    memcpy(noa.parent_set_id.bytes, path_policy, 16u);
    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = (uint32_t)sizeof(prep);
    memcpy(prep.owner_scope_id, scope, 16u);
    if (!ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1)) {
        return 0;
    }
    memcpy(prep.handoff_token_digest32, token, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    if (rrmp_test_owner_prepare_v2(
            &prep, &old_tuple, 1u, &new_tuple, &out) !=
            NINLIL_PARENT_OK ||
        rrmp_test_owner_fence_v2(
            scope, token, &old_tuple, proof, &out) !=
            NINLIL_PARENT_OK) {
        return 0;
    }
    ninlil_rrmp_memzero(&bundle, sizeof(bundle));
    bundle.present = 1u;
    memcpy(
        bundle.manifest_rrm1,
        g_host_store.value[0],
        NINLIL_RRMP_RRM1_BYTES);
    bundle.logical_length =
        ninlil_rrmp_get_u32_be(g_host_store.value[0] + 16u);
    memcpy(
        bundle.logical_sha256,
        g_host_store.value[0] + 24u,
        32u);
    if (rrmp_test_authority_commit_v2(
            scope,
            &old_tuple,
            &new_tuple,
            token,
            proof,
            &bundle,
            0u,
            commit_digest,
            &out) != NINLIL_PARENT_OK) {
        return 0;
    }
    ninlil_rrmp_memzero(&activate, sizeof(activate));
    activate.preamble.api_version = 1u;
    activate.preamble.struct_size = (uint32_t)sizeof(activate);
    memcpy(activate.owner_scope_id, scope, 16u);
    memcpy(
        activate.commit_receipt_digest32, commit_digest, 32u);
    activate.now_ms = 1000000u;
    return ninlil_parent_owner_activate(&activate, &out) ==
        NINLIL_PARENT_OK;
}

static void fill_nrm1(ninlil_rrmp_nrm1_fields_t *f, uint16_t h, uint8_t hops, uint8_t term)
{
    ninlil_rrmp_memzero(f, sizeof(*f));
    fill_id(f->authority_id.bytes, 0xA0u);
    f->controller_term = 5u;
    f->route_revision = 1u;
    f->lease_epoch = 1u;
    fill_id(f->authority_clock_epoch_id.bytes, 0x50u);
    f->lease_expiry_ms = 5000000u;
    f->ingress_hop_context_id = 0x1000u + h;
    f->route_handle = h;
    f->route_generation = 1u;
    fill_id(f->egress_peer_id.bytes, 0x60u);
    f->egress_hop_context_id = 0x2000u + h;
    if (term) {
        f->egress_route_handle = 0u;
        f->egress_route_generation = 0u;
    } else {
        f->egress_route_handle = (uint16_t)(h + 10u);
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

static void default_scope_ctx(ninlil_rrmp_scope_derivation_ctx_t *ctx)
{
    ninlil_rrmp_memzero(ctx, sizeof(*ctx));
    fill_id(ctx->endpoint_runtime_id, 0x10u);
    ctx->direction = 0u;
    ctx->traffic_class = 1u;
    ctx->namespace_len = 4u;
    ctx->service_len = 3u;
    memcpy(ctx->namespace, "nspc", 4u);
    memcpy(ctx->service, "svc", 3u);
}

static int32_t auth_ack(
    ninlil_rrmp_owner_t *o,
    uint64_t oh,
    uint64_t outer_tx,
    const uint8_t peer_runtime_id[16],
    ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_link_ack_evidence_t ev;
    size_t i;
    ninlil_rrmp_memzero(&ev, sizeof(ev));
    ev.opaque_local_handle = oh;
    ev.auth_ok = 1u;
    ev.ack_ok = 1u;
    ev.outer_tx_counter = outer_tx;
    memcpy(ev.peer_runtime_id, peer_runtime_id, 16u);
    for (i = 0u; i < 32u; ++i) {
        ev.auth_proof32[i] = (uint8_t)(0xA1u + i);
    }
    return (int32_t)ninlil_rrmp_core_link_ack_from_evidence(o, &ev, out);
}

static ninlil_rrmp_owner_t *cold_restart(
    ninlil_rrmp_owner_t *old,
    void *workspace,
    size_t workspace_bytes,
    const ninlil_rrmp_owner_config_v1_t *cfg,
    ninlil_rrmp_outbound_provider_t *prov,
    const ninlil_rrmp_scope_derivation_ctx_t *sctx)
{
    ninlil_rrmp_owner_t *neu;
    if (old != NULL) {
        ninlil_rrmp_owner_fini(old);
    }
    neu = ninlil_rrmp_owner_init(workspace, workspace_bytes, cfg);
    if (neu == NULL) {
        return NULL;
    }
    ninlil_rrmp_owner_bind(neu);
    if (!ninlil_rrmp_composition_bind(
            neu, &g_host_store.ops, g_host_store.handle, prov, sctx) ||
        !ninlil_rrmp_composition_recover(neu)) {
        ninlil_rrmp_owner_fini(neu);
        return NULL;
    }
    return neu;
}

int32_t ninlil_rrmp_host_lifecycle_run(void *workspace, size_t workspace_bytes)
{
    ninlil_rrmp_owner_config_v1_t cfg;
    ninlil_rrmp_owner_t *o;
    ninlil_rrmp_scope_derivation_ctx_t sctx;
    host_outbound_t ob;
    ninlil_rrmp_outbound_provider_t prov;
    ninlil_rrmp_id16_t pids[2];
    ninlil_rrmp_digest32_t dig;
    uint8_t scope[16];
    uint8_t path_policy[16];
    uint8_t attempt1[16];
    uint8_t attempt2[16];
    uint8_t attempt3[16];
    uint8_t selected[16];
    uint8_t path_a[16];
    uint8_t path_b[16];
    uint8_t e2e[32];
    uint8_t app_carrier[19];
    ninlil_rrmp_worker_result_v1_t worker;
    uint64_t epoch = 0u;
    uint64_t oh = 0u;
    uint64_t ack_outer_tx = 0u;
    size_t i;
    uint32_t snap_len = 0u;

    if (!ninlil_rrmp_sha256_selftest()) {
        return NINLIL_RRMP_HOST_LIFE_E_SHA;
    }
    if (workspace == NULL ||
        workspace_bytes < ninlil_rrmp_owner_workspace_bytes() ||
        ninlil_rrmp_owner_workspace_bytes() > NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES) {
        return NINLIL_RRMP_HOST_LIFE_E_WORKSPACE;
    }

    host_store_init(&g_host_store);

    ninlil_rrmp_memzero(&cfg, sizeof(cfg));
    cfg.preamble.api_version = 1u;
    cfg.preamble.struct_size = (uint32_t)sizeof(cfg);
    fill_id(cfg.local_runtime_id, 0x10u);
    fill_id(cfg.authority_id, 0xA0u);
    cfg.controller_term = 5u;
    fill_id(cfg.authority_clock_epoch_id, 0x50u);
    cfg.feature_route_relay = 1u;
    cfg.feature_multi_parent = 1u;
    cfg.max_hops_profile = 3u;
    cfg.now_ms = 1000000u;

    o = ninlil_rrmp_owner_init(workspace, workspace_bytes, &cfg);
    if (o == NULL) {
        return NINLIL_RRMP_HOST_LIFE_E_INIT;
    }
    ninlil_rrmp_owner_bind(o);

    ninlil_rrmp_memzero(&ob, sizeof(ob));
    ninlil_rrmp_memzero(&prov, sizeof(prov));
    prov.user = &ob;
    prov.submit = host_outbound_submit;
    default_scope_ctx(&sctx);

    /* Production composition bind requires real ops/handle (host fixture store). */
    if (!ninlil_rrmp_composition_bind(
            o, &g_host_store.ops, g_host_store.handle, &prov, &sctx) ||
        !ninlil_rrmp_composition_recover(o)) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_STORAGE;
    }

    /* Route install + activate (FULL writepoint). */
    ninlil_rrmp_memzero(&s_install, sizeof(s_install));
    s_install.preamble.api_version = 1u;
    s_install.preamble.struct_size = 312u;
    fill_id(s_install.authority_id, 0xA0u);
    s_install.controller_term = 5u;
    s_install.batch_id = 1u;
    s_install.entry_count = 1u;
    fill_nrm1(&s_nrm, 1u, 1u, 1u);
    if (!ninlil_rrmp_encode_nrm1(&s_nrm, s_raw)) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ROUTE;
    }
    memcpy(s_install.entries, s_raw, sizeof(s_raw));
    if (ninlil_route_install_batch(&s_install, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ROUTE;
    }
    ninlil_rrmp_memzero(&s_act, sizeof(s_act));
    s_act.preamble.api_version = 1u;
    s_act.preamble.struct_size = 64u;
    s_act.ingress_hop_context_id = 0x1001u;
    s_act.route_handle = 1u;
    s_act.route_generation = 1u;
    s_act.now_ms = 1000000u;
    if (ninlil_route_activate(&s_act, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ROUTE;
    }
    if (host_store_logical_length(&g_host_store) == 0u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_STORAGE;
    }
    snap_len = host_store_logical_length(&g_host_store);

    /* 2-parent install + select + ordinal failover + same-attempt fence. */
    fill_id(path_policy, 0x80u);
    if (!ninlil_rrmp_derive_owner_scope_id(
            sctx.endpoint_runtime_id, sctx.direction, sctx.namespace,
            sctx.namespace_len, sctx.service, sctx.service_len, sctx.traffic_class,
            path_policy, scope)) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    ninlil_rrmp_memzero(&s_pset, sizeof(s_pset));
    s_pset.preamble.api_version = 1u;
    s_pset.preamble.struct_size = 240u;
    memcpy(s_pset.owner_scope_id, scope, 16u);
    s_pset.parent_set_count = 2u;
    memcpy(s_pset.path_policy_id, path_policy, 16u);
    s_pset.controller_term = 5u;
    s_pset.assignment_epoch = 1u;
    fill_id(pids[0].bytes, 0x30u);
    fill_id(pids[1].bytes, 0x40u);
    memcpy(s_pset.parent_runtime_id[0], pids[0].bytes, 16u);
    memcpy(s_pset.parent_runtime_id[1], pids[1].bytes, 16u);
    if (!ninlil_rrmp_parent_set_digest(pids, 2u, &dig)) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    memcpy(s_pset.parent_set_digest32, dig.bytes, 32u);
    if (ninlil_parent_set_install(&s_pset, &s_pout) != NINLIL_PARENT_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    if (!host_parent_bootstrap_assignment(
            scope,
            path_policy,
            dig.bytes,
            s_pset.parent_set_count)) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    ninlil_rrmp_memzero(attempt1, 16u);
    ninlil_rrmp_put_u16_be(attempt1 + 14, 1u);
    ninlil_rrmp_memzero(attempt2, 16u);
    ninlil_rrmp_put_u16_be(attempt2 + 14, 2u);
    ninlil_rrmp_memzero(attempt3, 16u);
    attempt3[0] = 0xA3u;
    ninlil_rrmp_put_u16_be(attempt3 + 14, 1u);
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt1, selected, &s_pout) != NINLIL_PARENT_OK ||
        memcmp(selected, pids[0].bytes, 16u) != 0) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt1, selected, &s_pout) !=
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt2, selected, &s_pout) != NINLIL_PARENT_OK ||
        memcmp(selected, pids[1].bytes, 16u) != 0) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    if (host_store_logical_length(&g_host_store) < snap_len) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_STORAGE;
    }

    /* Cold restart #1: route + parent + attempt fence. */
    o = cold_restart(o, workspace, workspace_bytes, &cfg, &prov, &sctx);
    if (o == NULL) {
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    ninlil_rrmp_memzero(&s_rq, sizeof(s_rq));
    s_rq.preamble.api_version = 1u;
    s_rq.preamble.struct_size = 48u;
    s_rq.ingress_hop_context_id = 0x1001u;
    s_rq.route_handle = 1u;
    s_rq.route_generation = 1u;
    if (ninlil_route_query(&s_rq, &s_rout) != NINLIL_ROUTE_OK ||
        s_rout.lifecycle_state != NINLIL_RRMP_LIFE_ACTIVE) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    ninlil_rrmp_memzero(&s_pq, sizeof(s_pq));
    s_pq.preamble.api_version = 1u;
    s_pq.preamble.struct_size = 48u;
    memcpy(s_pq.owner_scope_id, scope, 16u);
    if (ninlil_parent_query(&s_pq, &s_pout) != NINLIL_PARENT_OK ||
        s_pout.seal_allowed != 1u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt2, selected, &s_pout) !=
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }

    /* Fabric pin + reject zero mutation. */
    ninlil_rrmp_memzero(&s_fview, sizeof(s_fview));
    s_fview.has_selection = 1u;
    s_fview.selection_finalized = 1u;
    s_fview.path_selection_epoch = 7u;
    fill_id(s_fview.selected_instance_id, 0x51u);
    if (ninlil_rrmp_fabric_on_path_selected(o, &s_fview, &s_rout) != NINLIL_ROUTE_OK ||
        !ninlil_rrmp_fabric_last_path(o, path_a, &epoch) || epoch != 7u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_FABRIC;
    }
    s_fview.selection_finalized = 0u;
    s_fview.path_selection_epoch = 99u;
    fill_id(s_fview.selected_instance_id, 0x99u);
    if (ninlil_rrmp_fabric_on_path_selected(o, &s_fview, &s_rout) != NINLIL_ROUTE_OK ||
        !ninlil_rrmp_fabric_last_path(o, path_b, &epoch) || epoch != 7u ||
        memcmp(path_a, path_b, 16u) != 0) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_FABRIC;
    }

    /* Admit LIVE custody evidence. */
    for (i = 0u; i < 32u; ++i) {
        e2e[i] = (uint8_t)(0xC0u + i);
    }
    ninlil_rrmp_memzero(&s_admit, sizeof(s_admit));
    s_admit.preamble.api_version = 1u;
    s_admit.preamble.struct_size = 128u;
    s_admit.ingress_hop_context_id = 0x1001u;
    s_admit.route_handle = 1u;
    s_admit.route_generation = 1u;
    s_admit.hop_remaining = 1u;
    s_admit.admission_now_ms = 1000000u;
    s_admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    s_admit.caller_item_token = 7u;
    s_admit.outer_rx_counter = 11u;
    memcpy(s_admit.e2e_header_digest32, e2e, 32u);
    if (ninlil_route_forward_admit(&s_admit, &s_rout) != NINLIL_ROUTE_OK ||
        s_rout.opaque_local_handle == 0u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ROUTE;
    }
    if (host_store_logical_length(&g_host_store) == 0u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_STORAGE;
    }
    snap_len = host_store_logical_length(&g_host_store);

    /*
     * Cold restart #2 — LIVE custody/parent/attempt resume proof:
     *  - route ACTIVE
     *  - parent set seal_allowed + attempt2 same-attempt fence
     *  - LIVE evidence: same e2e admits as REPLAY
     * Volatile queue/opaque_handle are not durable (honest residual).
     */
    o = cold_restart(o, workspace, workspace_bytes, &cfg, &prov, &sctx);
    if (o == NULL) {
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (ninlil_route_query(&s_rq, &s_rout) != NINLIL_ROUTE_OK ||
        s_rout.lifecycle_state != NINLIL_RRMP_LIFE_ACTIVE) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (ninlil_parent_query(&s_pq, &s_pout) != NINLIL_PARENT_OK ||
        s_pout.seal_allowed != 1u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt2, selected, &s_pout) !=
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (ninlil_route_forward_admit(&s_admit, &s_rout) != NINLIL_ROUTE_REPLAY) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (host_store_logical_length(&g_host_store) != snap_len) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_STORAGE;
    }

    /*
     * Reinstall the same parent set under a newer assignment epoch. Durable
     * attempt IDs remain non-reusable, so production admission uses a fresh
     * ordinal-1 identity and binds it to parent[0].
     */
    s_pset.assignment_epoch = 2u;
    if (ninlil_parent_set_install(&s_pset, &s_pout) != NINLIL_PARENT_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }

    /* Fresh ApplicationData custody admission for restart/hop/ACK path. */
    for (i = 0u; i < 32u; ++i) {
        e2e[i] = (uint8_t)(0xD0u + i);
    }
    memcpy(app_carrier, "rrmp-appdata-cold!", sizeof(app_carrier));
    memcpy(s_admit.e2e_header_digest32, e2e, 32u);
    s_admit.caller_item_token = 8u;
    s_admit.outer_rx_counter = 12u;
    if (ninlil_rrmp_core_forward_admit_with_carrier(
            o, &s_admit, app_carrier, (uint16_t)sizeof(app_carrier),
            attempt3, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ROUTE;
    }
    oh = s_rout.opaque_local_handle;

    /* Cold restart #3 proves queue, handle, carrier and selected parent. */
    o = cold_restart(o, workspace, workspace_bytes, &cfg, &prov, &sctx);
    if (o == NULL) {
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    ninlil_rrmp_memzero(&ob, sizeof(ob));
    if (ninlil_rrmp_core_hop_forward_execute(o, oh, NULL, 0u, 1u, &s_tx) !=
            NINLIL_ROUTE_OK ||
        ob.submit_count != 1u || !ob.has_last ||
        ob.last.carrier_len != sizeof(app_carrier) ||
        memcmp(ob.last.carrier, app_carrier, sizeof(app_carrier)) != 0 ||
        !ob.last.selected_parent_set ||
        memcmp(ob.last.selected_parent_id, pids[0].bytes, 16u) != 0 ||
        !s_tx.carrier_set || s_tx.payload_len != sizeof(app_carrier) ||
        memcmp(s_tx.payload, app_carrier, sizeof(app_carrier)) != 0) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PROVIDER;
    }
    ninlil_rrmp_memzero(&s_complete, sizeof(s_complete));
    s_complete.preamble.api_version = 1u;
    s_complete.preamble.struct_size = 64u;
    s_complete.opaque_local_handle = oh;
    s_complete.outcome = 1u;
    s_complete.completion_now_ms = 1000000u;
    /* ACK lost */
    if (ninlil_route_forward_complete(&s_complete, &s_rout) !=
        NINLIL_ROUTE_AUTHORITY_CONFLICT) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ACK;
    }
    /* Early retry is fenced; bounded timeout worker owns the retry. */
    if (ninlil_rrmp_core_hop_forward_execute(o, oh, NULL, 0u, 1u, &s_tx) !=
            NINLIL_ROUTE_BACKPRESSURE) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PROVIDER;
    }
    ninlil_rrmp_memzero(&worker, sizeof(worker));
    if (ninlil_rrmp_core_worker_tick(
            o, 1005000u, 1u, &worker) != NINLIL_ROUTE_OK ||
        worker.steps != 1u || worker.submitted != 1u ||
        ob.submit_count != 2u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PROVIDER;
    }
    ack_outer_tx = ob.last.outer_tx_counter;
    if (auth_ack(o, oh, ack_outer_tx, pids[0].bytes, &s_rout) !=
            (int32_t)NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ACK;
    }

    /* Cold restart #4 proves durable authenticated ACK and queue release. */
    o = cold_restart(o, workspace, workspace_bytes, &cfg, &prov, &sctx);
    if (o == NULL) {
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (auth_ack(o, oh, ack_outer_tx, pids[0].bytes, &s_rout) !=
            (int32_t)NINLIL_ROUTE_OK ||
        ninlil_route_forward_complete(&s_complete, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ACK;
    }

    /*
     * parent_loss unique failover: scope sealed → further select is
     * exactly SPLIT_BRAIN (not OK / NOT_ACTIVE wildcard).
     */
    if (ninlil_rrmp_core_parent_loss(o, scope, pids[0].bytes) != NINLIL_PARENT_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt1, selected, &s_pout) != NINLIL_PARENT_SPLIT_BRAIN) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }
    if (s_pout.seal_allowed != 0u) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_PARENT;
    }

    ninlil_rrmp_memzero(&s_retire, sizeof(s_retire));
    s_retire.preamble.api_version = 1u;
    s_retire.preamble.struct_size = 64u;
    s_retire.ingress_hop_context_id = 0x1001u;
    s_retire.route_handle = 1u;
    s_retire.route_generation = 1u;
    s_retire.force = 1u;
    if (ninlil_route_retire(&s_retire, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_ROUTE;
    }

    o = cold_restart(o, workspace, workspace_bytes, &cfg, &prov, &sctx);
    if (o == NULL) {
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }
    if (ninlil_route_query(&s_rq, &s_rout) == NINLIL_ROUTE_OK &&
        s_rout.lifecycle_state == NINLIL_RRMP_LIFE_ACTIVE) {
        ninlil_rrmp_owner_fini(o);
        return NINLIL_RRMP_HOST_LIFE_E_RESTART;
    }

    ninlil_rrmp_owner_fini(o);
    return NINLIL_RRMP_HOST_LIFE_OK;
}
