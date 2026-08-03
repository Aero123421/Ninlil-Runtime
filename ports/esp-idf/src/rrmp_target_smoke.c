/*
 * ESP target software smoke for private RRMP (ADR-0019/0020).
 *
 * Explicit SPIRAM (heap CAPS) design — no multi-hundred-KiB static BSS:
 *  - owner workspace: heap_caps_aligned_alloc(MALLOC_CAP_SPIRAM)
 *  - software FULL store buffer: SPIRAM CAPS (not flash FULL; flash is
 *    ESP_UNPROVEN COMMIT_UNKNOWN). This proves production bind/recover +
 *    dual-namespace FULL writepoints + cold restart on-target software.
 *
 * Not RF air / multi-node HIL. Not a claim of physical carrier provider proof.
 * Host KAT full ACK/retry lifecycle: tests/runtime/route_relay_v1/rrmp_host_*.
 */
#include "rrmp_target_smoke.h"

#include "rrmp_abi.h"
#include "rrmp_codec.h"
#include "rrmp_composition.h"
#include "rrmp_seam.h"
#include "rrmp_util.h"

#include "esp_heap_caps.h"
#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define RRMP_SMOKE_STORE_PIECES 6u
#define RRMP_SMOKE_STORE_BYTES 307456u

typedef struct smoke_store {
    uint8_t present[RRMP_SMOKE_STORE_PIECES];
    uint8_t *value;
    uint32_t value_cap;
    uint32_t value_len[RRMP_SMOKE_STORE_PIECES];
    ninlil_storage_ops_t ops;
    ninlil_storage_handle_t handle;
} smoke_store_t;

typedef struct smoke_txn {
    smoke_store_t *store;
    uint8_t present[RRMP_SMOKE_STORE_PIECES];
    uint8_t changed[RRMP_SMOKE_STORE_PIECES];
    const uint8_t *stage_ptr[RRMP_SMOKE_STORE_PIECES];
    uint32_t value_len[RRMP_SMOKE_STORE_PIECES];
    uint8_t iter_index;
    ninlil_storage_mode_t mode;
} smoke_txn_t;

typedef struct smoke_outbound {
    ninlil_rrmp_outbound_packet_t last;
    uint32_t submit_count;
} smoke_outbound_t;

static uint8_t *s_ws;
static size_t s_ws_bytes;
static smoke_store_t s_store;
static smoke_outbound_t s_outbound;

/* Small req blobs — no owner workspace on BSS. */
static ninlil_route_install_batch_req_v1_t s_install;
static ninlil_route_activate_req_v1_t s_act;
static ninlil_route_query_req_v1_t s_rq;
static ninlil_route_result_v1_t s_rout;
static ninlil_parent_set_install_req_v1_t s_pset;
static ninlil_parent_query_req_v1_t s_pq;
static ninlil_parent_result_v1_t s_pout;
static ninlil_rrmp_noa1_fields_t s_noa;
static ninlil_parent_owner_prepare_req_v2_t s_prepare_v2;
static ninlil_parent_authority_commit_req_v2_t s_commit_v2;
static ninlil_parent_owner_activate_req_v1_t s_owner_activate;
static ninlil_rrmp_authority_tuple_v2_t s_old_tuple;
static ninlil_rrmp_authority_tuple_v2_t s_new_tuple;
static ninlil_rrmp_bundle_witness_v2_t s_bundle;
static ninlil_rrmp_nrm1_fields_t s_nrm;
static ninlil_route_forward_admit_req_v1_t s_admit;
static ninlil_route_forward_complete_req_v1_t s_complete;
static ninlil_rrmp_hop_tx_view_t s_hop_tx;
static ninlil_rrmp_link_ack_evidence_t s_link_ack;
static ninlil_rrmp_worker_result_v1_t s_worker;
static uint8_t s_raw[NINLIL_RRMP_NRM1_BYTES];
static uint8_t s_authority_preimage[640];

static uint32_t smoke_outbound_submit(
    void *user, const ninlil_rrmp_outbound_packet_t *packet)
{
    smoke_outbound_t *outbound = (smoke_outbound_t *)user;
    if (outbound == NULL || packet == NULL) {
        return NINLIL_RRMP_OUTBOUND_DENIED;
    }
    outbound->last = *packet;
    outbound->submit_count += 1u;
    return NINLIL_RRMP_OUTBOUND_ACCEPTED;
}

static void *smoke_caps_alloc(size_t n, size_t align)
{
    return heap_caps_aligned_alloc(
        align, n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

static uint8_t *smoke_ws_get(size_t need)
{
    if (s_ws != NULL && s_ws_bytes >= need) {
        return s_ws;
    }
    if (s_ws != NULL) {
        heap_caps_free(s_ws);
        s_ws = NULL;
        s_ws_bytes = 0u;
    }
    s_ws = (uint8_t *)smoke_caps_alloc(need, NINLIL_RRMP_OWNER_WORKSPACE_ALIGN);
    if (s_ws != NULL) {
        s_ws_bytes = need;
    }
    return s_ws;
}

static int smoke_key_kind(ninlil_bytes_view_t key)
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

static uint32_t smoke_piece_offset(uint8_t kind)
{
    return kind == 0u ? 0u
                      : NINLIL_RRMP_RRM1_BYTES +
                            (uint32_t)(kind - 1u) *
                                NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
}

static uint32_t smoke_piece_capacity(uint8_t kind)
{
    return kind == 0u ? NINLIL_RRMP_RRM1_BYTES
                      : NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
}

static const uint8_t *smoke_txn_piece(
    const smoke_txn_t *txn, uint8_t kind)
{
    if (txn == NULL || txn->store == NULL ||
        kind >= RRMP_SMOKE_STORE_PIECES) {
        return NULL;
    }
    if (txn->changed[kind]) {
        return txn->stage_ptr[kind];
    }
    return txn->store->value + smoke_piece_offset(kind);
}

static ninlil_storage_status_t sm_open(
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
static void sm_close(void *user, ninlil_storage_handle_t h)
{
    (void)user;
    (void)h;
}
static ninlil_storage_status_t sm_begin(
    void *user, ninlil_storage_handle_t h, ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    static smoke_txn_t s_txn;
    (void)h;
    if (out_txn == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    memset(&s_txn, 0, sizeof(s_txn));
    s_txn.store = (smoke_store_t *)user;
    s_txn.mode = mode;
    memcpy(
        s_txn.present,
        s_txn.store->present,
        sizeof(s_txn.present));
    memcpy(
        s_txn.value_len,
        s_txn.store->value_len,
        sizeof(s_txn.value_len));
    *out_txn = (ninlil_storage_txn_t)&s_txn;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t sm_get(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout)
{
    smoke_txn_t *t = (smoke_txn_t *)txn;
    const uint8_t *src;
    int kind = smoke_key_kind(key);
    (void)user;
    if (t == NULL || inout == NULL || t->store == NULL ||
        kind < 0 || !t->present[kind]) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    src = smoke_txn_piece(t, (uint8_t)kind);
    if (src == NULL || inout->capacity < t->value_len[kind]) {
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    memcpy(inout->data, src, t->value_len[kind]);
    inout->length = t->value_len[kind];
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t sm_put(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    smoke_txn_t *t = (smoke_txn_t *)txn;
    int kind = smoke_key_kind(key);
    (void)user;
    if (t == NULL || t->store == NULL || t->store->value == NULL ||
        t->mode != NINLIL_STORAGE_READ_WRITE || kind < 0 ||
        value.data == NULL || value.length == 0u ||
        value.length > smoke_piece_capacity((uint8_t)kind) ||
        value.length > NINLIL_RRMP_PLATFORM_VALUE_BYTES_MAX) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->stage_ptr[kind] = value.data;
    t->value_len[kind] = value.length;
    t->present[kind] = 1u;
    t->changed[kind] = 1u;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t sm_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    smoke_txn_t *t = (smoke_txn_t *)txn;
    int kind = smoke_key_kind(key);
    (void)user;
    if (t == NULL || t->store == NULL ||
        t->mode != NINLIL_STORAGE_READ_WRITE || kind < 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->stage_ptr[kind] = NULL;
    t->value_len[kind] = 0u;
    t->present[kind] = 0u;
    t->changed[kind] = 1u;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t sm_iter_open(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t p,
    ninlil_storage_iter_t *out)
{
    smoke_txn_t *t = (smoke_txn_t *)txn;
    static const uint8_t prefix[5] = {'R', 'R', 'M', 'P', '/'};
    (void)user;
    if (t == NULL || out == NULL || p.data == NULL ||
        p.length != sizeof(prefix) ||
        memcmp(p.data, prefix, sizeof(prefix)) != 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->iter_index = 0u;
    *out = (ninlil_storage_iter_t)t;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t sm_iter_next(
    void *user, ninlil_storage_iter_t it, ninlil_mut_bytes_t *k, ninlil_mut_bytes_t *v)
{
    smoke_txn_t *t = (smoke_txn_t *)it;
    static const uint8_t keys[RRMP_SMOKE_STORE_PIECES][7] = {
        {'R', 'R', 'M', 'P', '/', 'C', '0'},
        {'R', 'R', 'M', 'P', '/', 'C', '1'},
        {'R', 'R', 'M', 'P', '/', 'C', '2'},
        {'R', 'R', 'M', 'P', '/', 'C', '3'},
        {'R', 'R', 'M', 'P', '/', 'C', '4'},
        {'R', 'R', 'M', 'P', '/', 'M', '1'},
    };
    static const uint8_t kinds[RRMP_SMOKE_STORE_PIECES] =
        {1u, 2u, 3u, 4u, 5u, 0u};
    (void)user;
    if (t == NULL || k == NULL || v == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    while (t->iter_index < RRMP_SMOKE_STORE_PIECES) {
        const uint8_t ordinal = t->iter_index++;
        const uint8_t kind = kinds[ordinal];
        const uint8_t *src;
        if (!t->present[kind]) {
            continue;
        }
        src = smoke_txn_piece(t, kind);
        if (src == NULL || k->data == NULL || v->data == NULL ||
            k->capacity < 7u || v->capacity < t->value_len[kind]) {
            return NINLIL_STORAGE_BUFFER_TOO_SMALL;
        }
        memcpy(k->data, keys[ordinal], 7u);
        k->length = 7u;
        memcpy(v->data, src, t->value_len[kind]);
        v->length = t->value_len[kind];
        return NINLIL_STORAGE_OK;
    }
    return NINLIL_STORAGE_NOT_FOUND;
}
static void sm_iter_close(void *user, ninlil_storage_iter_t it)
{
    (void)user;
    (void)it;
}
static ninlil_storage_status_t sm_capacity(
    void *user, ninlil_storage_handle_t h, ninlil_storage_capacity_t *c)
{
    (void)user;
    (void)h;
    (void)c;
    return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}
static ninlil_storage_status_t sm_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t dur)
{
    smoke_txn_t *t = (smoke_txn_t *)txn;
    uint8_t ordinal;
    static const uint8_t commit_order[RRMP_SMOKE_STORE_PIECES] =
        {1u, 2u, 3u, 4u, 5u, 0u};
    (void)user;
    if (t == NULL || t->store == NULL || t->store->value == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (dur != NINLIL_DURABILITY_FULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    /*
     * All pointers are copy-consumed before returning. Chunks are copied
     * first and the manifest last so even this software-only target fixture
     * mirrors the bundle publication order; visibility changes only when
     * commit returns.
     */
    for (ordinal = 0u; ordinal < RRMP_SMOKE_STORE_PIECES; ++ordinal) {
        const uint8_t kind = commit_order[ordinal];
        if (!t->changed[kind] || !t->present[kind]) {
            continue;
        }
        if (t->stage_ptr[kind] == NULL ||
            t->value_len[kind] > smoke_piece_capacity(kind)) {
            return NINLIL_STORAGE_IO_ERROR;
        }
        memcpy(
            t->store->value + smoke_piece_offset(kind),
            t->stage_ptr[kind],
            t->value_len[kind]);
    }
    memcpy(
        t->store->present,
        t->present,
        sizeof(t->store->present));
    memcpy(
        t->store->value_len,
        t->value_len,
        sizeof(t->store->value_len));
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t sm_rollback(void *user, ninlil_storage_txn_t txn)
{
    (void)user;
    (void)txn;
    return NINLIL_STORAGE_OK;
}

static int smoke_store_ready(void)
{
    if (s_store.value != NULL && s_store.value_cap >= RRMP_SMOKE_STORE_BYTES) {
        memset(s_store.value, 0, RRMP_SMOKE_STORE_BYTES);
        memset(s_store.present, 0, sizeof(s_store.present));
        memset(s_store.value_len, 0, sizeof(s_store.value_len));
        return 1;
    }
    memset(&s_store, 0, sizeof(s_store));
    s_store.value = (uint8_t *)smoke_caps_alloc(RRMP_SMOKE_STORE_BYTES, 8u);
    if (s_store.value == NULL) {
        return 0;
    }
    s_store.value_cap = RRMP_SMOKE_STORE_BYTES;
    s_store.ops.abi_version = NINLIL_ABI_VERSION;
    s_store.ops.struct_size = (uint32_t)sizeof(s_store.ops);
    s_store.ops.user = &s_store;
    s_store.ops.open = sm_open;
    s_store.ops.close = sm_close;
    s_store.ops.begin = sm_begin;
    s_store.ops.get = sm_get;
    s_store.ops.put = sm_put;
    s_store.ops.erase = sm_erase;
    s_store.ops.iter_open = sm_iter_open;
    s_store.ops.iter_next = sm_iter_next;
    s_store.ops.iter_close = sm_iter_close;
    s_store.ops.capacity = sm_capacity;
    s_store.ops.commit = sm_commit;
    s_store.ops.rollback = sm_rollback;
    s_store.handle = (ninlil_storage_handle_t)&s_store;
    return 1;
}

static uint32_t smoke_store_logical_length(const smoke_store_t *store)
{
    const uint8_t *manifest;
    if (store == NULL || store->value == NULL || !store->present[0] ||
        store->value_len[0] != NINLIL_RRMP_RRM1_BYTES) {
        return 0u;
    }
    manifest = store->value + smoke_piece_offset(0u);
    if (memcmp(manifest, "RRM1", 4u) != 0) {
        return 0u;
    }
    return ninlil_rrmp_get_u32_be(manifest + 16u);
}

static void fill_id(uint8_t id[16], uint8_t seed)
{
    size_t i;
    for (i = 0u; i < 16u; ++i) {
        id[i] = (uint8_t)(seed + (uint8_t)i);
    }
}

static void smoke_authority_tuple_encode(
    const ninlil_rrmp_authority_tuple_v2_t *tuple, uint8_t out[104])
{
    memset(out, 0, 104u);
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

static int smoke_authority_tuple_from_noa(
    const uint8_t raw[NINLIL_RRMP_NOA1_BYTES],
    uint64_t writer_epoch,
    ninlil_rrmp_authority_tuple_v2_t *out)
{
    ninlil_rrmp_noa1_fields_t decoded;
    if (raw == NULL || out == NULL || writer_epoch == 0u ||
        writer_epoch == UINT64_MAX ||
        !ninlil_rrmp_decode_noa1(raw, &decoded)) {
        return 0;
    }
    memset(out, 0, sizeof(*out));
    out->present = 1u;
    out->exact_noa1_length = NINLIL_RRMP_NOA1_BYTES;
    ninlil_rrmp_sha256(
        raw, NINLIL_RRMP_NOA1_BYTES, out->noa1_sha256);
    out->assignment_revision = decoded.assignment_revision;
    out->controller_term = decoded.controller_term;
    memcpy(
        out->owner_controller_id,
        decoded.owner_controller_id.bytes,
        16u);
    out->writer_epoch = writer_epoch;
    out->lease_not_after_ms =
        decoded.lease_not_after_authority_ms;
    memcpy(
        out->authority_clock_epoch_id,
        decoded.authority_clock_epoch_id.bytes,
        16u);
    return 1;
}

static void smoke_bundle_witness_encode(
    const ninlil_rrmp_bundle_witness_v2_t *witness, uint8_t out[296])
{
    memset(out, 0, 296u);
    out[0] = witness->present;
    memcpy(
        out + 4u,
        witness->manifest_rrm1,
        NINLIL_RRMP_RRM1_BYTES);
    ninlil_rrmp_put_u32_be(out + 260u, witness->logical_length);
    memcpy(out + 264u, witness->logical_sha256, 32u);
}

static int smoke_parent_bootstrap_assignment(
    const uint8_t scope[16],
    const uint8_t path_policy[16],
    const uint8_t parent_digest[32],
    uint8_t parent_count)
{
    static const uint8_t no_old_domain[] =
        "NINLIL-RRMP-NO-OLD-AUTHORITY-V2";
    static const uint8_t commit_domain[] =
        "NINLIL-RRMP-AUTHORITY-COMMIT-V2";
    uint8_t token[32];
    uint8_t proof[32];
    uint8_t tuple_bytes[104];
    uint8_t bundle_bytes[296];
    size_t off = 0u;
    const uint8_t *manifest;
    uint32_t status;

    if (scope == NULL || path_policy == NULL || parent_digest == NULL ||
        parent_count == 0u || !s_store.present[0] ||
        s_store.value_len[0] != NINLIL_RRMP_RRM1_BYTES) {
        return 0;
    }
    manifest = s_store.value + smoke_piece_offset(0u);
    memset(token, 0x5Bu, sizeof(token));
    memset(&s_noa, 0, sizeof(s_noa));
    memcpy(s_noa.owner_scope_id.bytes, scope, 16u);
    fill_id(s_noa.authority_id.bytes, 0xA0u);
    s_noa.controller_term = 5u;
    s_noa.assignment_epoch = 1u;
    s_noa.assignment_revision = 1u;
    fill_id(s_noa.owner_controller_id.bytes, 0xB0u);
    fill_id(s_noa.owner_cell_id.bytes, 0xB1u);
    s_noa.direction = 0u;
    s_noa.e2e_context_id = 1u;
    s_noa.key_generation = 1u;
    fill_id(s_noa.e2e_security_id.bytes, 0xD0u);
    s_noa.e2e_security_epoch = 1u;
    memset(s_noa.e2e_binding_digest.bytes, 0xE1u, 32u);
    fill_id(s_noa.authority_clock_epoch_id.bytes, 0x50u);
    s_noa.lease_not_after_authority_ms = 5000000u;
    memcpy(s_noa.handoff_token_digest.bytes, token, 32u);
    memcpy(s_noa.parent_set_digest.bytes, parent_digest, 32u);
    s_noa.parent_set_count = parent_count;
    memcpy(s_noa.parent_set_id.bytes, path_policy, 16u);

    memset(&s_prepare_v2, 0, sizeof(s_prepare_v2));
    s_prepare_v2.preamble.api_version =
        NINLIL_RRMP_PRIVATE_V2_API_VERSION;
    s_prepare_v2.preamble.struct_size =
        (uint32_t)sizeof(s_prepare_v2);
    memcpy(s_prepare_v2.owner_scope_id, scope, 16u);
    memset(&s_old_tuple, 0, sizeof(s_old_tuple));
    s_prepare_v2.expected_old = s_old_tuple;
    if (!ninlil_rrmp_encode_noa1(
            &s_noa, s_prepare_v2.new_assignment_noa1) ||
        !smoke_authority_tuple_from_noa(
            s_prepare_v2.new_assignment_noa1, 1u, &s_new_tuple)) {
        return 0;
    }
    memcpy(
        s_prepare_v2.handoff_token_digest32, token, 32u);
    status = ninlil_parent_owner_prepare_v2(&s_prepare_v2, &s_pout);
    if (status != NINLIL_PARENT_OK) {
        return 0;
    }

    memcpy(s_authority_preimage, no_old_domain, sizeof(no_old_domain) - 1u);
    memcpy(
        s_authority_preimage + sizeof(no_old_domain) - 1u,
        scope,
        16u);
    memcpy(
        s_authority_preimage + sizeof(no_old_domain) - 1u + 16u,
        token,
        32u);
    ninlil_rrmp_sha256(
        s_authority_preimage,
        sizeof(no_old_domain) - 1u + 16u + 32u,
        proof);
    if (memcmp(s_pout.token_or_commit_digest32, proof, 32u) != 0) {
        return 0;
    }

    memset(&s_bundle, 0, sizeof(s_bundle));
    s_bundle.present = 1u;
    memcpy(
        s_bundle.manifest_rrm1,
        manifest,
        NINLIL_RRMP_RRM1_BYTES);
    s_bundle.logical_length =
        ninlil_rrmp_get_u32_be(manifest + 16u);
    memcpy(s_bundle.logical_sha256, manifest + 24u, 32u);
    if (s_bundle.logical_length == 0u ||
        s_bundle.logical_length >
            NINLIL_RRMP_RRM1_LOGICAL_REQUIRED_MAX) {
        return 0;
    }

    memset(&s_commit_v2, 0, sizeof(s_commit_v2));
    s_commit_v2.preamble.api_version =
        NINLIL_RRMP_PRIVATE_V2_API_VERSION;
    s_commit_v2.preamble.struct_size =
        (uint32_t)sizeof(s_commit_v2);
    memcpy(s_commit_v2.owner_scope_id, scope, 16u);
    s_commit_v2.expected_old = s_old_tuple;
    s_commit_v2.expected_new = s_new_tuple;
    memcpy(s_commit_v2.handoff_token_digest32, token, 32u);
    memcpy(s_commit_v2.proof_digest32, proof, 32u);
    s_commit_v2.expected_bundle = s_bundle;
    s_commit_v2.cas_expected_generation = 0u;

    memcpy(
        s_authority_preimage + off,
        commit_domain,
        sizeof(commit_domain) - 1u);
    off += sizeof(commit_domain) - 1u;
    memcpy(s_authority_preimage + off, scope, 16u);
    off += 16u;
    smoke_authority_tuple_encode(&s_old_tuple, tuple_bytes);
    memcpy(s_authority_preimage + off, tuple_bytes, sizeof(tuple_bytes));
    off += sizeof(tuple_bytes);
    smoke_authority_tuple_encode(&s_new_tuple, tuple_bytes);
    memcpy(s_authority_preimage + off, tuple_bytes, sizeof(tuple_bytes));
    off += sizeof(tuple_bytes);
    memcpy(s_authority_preimage + off, token, 32u);
    off += 32u;
    memcpy(s_authority_preimage + off, proof, 32u);
    off += 32u;
    smoke_bundle_witness_encode(&s_bundle, bundle_bytes);
    memcpy(s_authority_preimage + off, bundle_bytes, sizeof(bundle_bytes));
    off += sizeof(bundle_bytes);
    ninlil_rrmp_put_u64_be(s_authority_preimage + off, 0u);
    off += 8u;
    if (off > sizeof(s_authority_preimage)) {
        return 0;
    }
    ninlil_rrmp_sha256(
        s_authority_preimage,
        off,
        s_commit_v2.authority_commit_digest32);
    status = ninlil_parent_authority_commit_v2(
        &s_commit_v2, &s_pout);
    if (status != NINLIL_PARENT_OK ||
        memcmp(
            s_pout.token_or_commit_digest32,
            s_commit_v2.authority_commit_digest32,
            32u) != 0) {
        return 0;
    }

    memset(&s_owner_activate, 0, sizeof(s_owner_activate));
    s_owner_activate.preamble.api_version = 1u;
    s_owner_activate.preamble.struct_size =
        (uint32_t)sizeof(s_owner_activate);
    memcpy(s_owner_activate.owner_scope_id, scope, 16u);
    memcpy(
        s_owner_activate.commit_receipt_digest32,
        s_commit_v2.authority_commit_digest32,
        32u);
    s_owner_activate.now_ms = 1000000u;
    return ninlil_parent_owner_activate(
               &s_owner_activate, &s_pout) == NINLIL_PARENT_OK;
}

static void fill_nrm1(ninlil_rrmp_nrm1_fields_t *f)
{
    memset(f, 0, sizeof(*f));
    fill_id(f->authority_id.bytes, 0xA0u);
    f->controller_term = 5u;
    f->route_revision = 1u;
    f->lease_epoch = 1u;
    fill_id(f->authority_clock_epoch_id.bytes, 0x50u);
    f->lease_expiry_ms = 5000000u;
    f->ingress_hop_context_id = 0x1001u;
    f->route_handle = 1u;
    f->route_generation = 1u;
    fill_id(f->egress_peer_id.bytes, 0x60u);
    f->egress_hop_context_id = 0x2001u;
    f->egress_route_handle = 0u;
    f->egress_route_generation = 0u;
    fill_id(f->grant_id.bytes, 0x70u);
    f->queue_quota_entries = 8u;
    f->queue_quota_bytes = 2048u;
    f->max_hops = 1u;
    f->ack_policy = 1u;
    f->terminal_flag = 1u;
    fill_id(f->path_policy_id.bytes, 0x80u);
    f->path_policy_revision = 1u;
}

/*
 * On-target software lifecycle (SPIRAM store + production bind/recover):
 * owner init → bind/recover → route install/activate FULL → 2-parent install
 * → exact v2 authority bootstrap → select attempt1 → cold restart
 * → route ACTIVE + parent + SAME_ATTEMPT → parent-set revision cannot clear
 * attempt1 → fresh-attempt durable ApplicationData+selected-parent admission
 * → cold restart → outbound software submit + timeout worker retry
 * → parent_loss → unique SPLIT_BRAIN.
 * This is on-target software evidence, not RF air/HIL carrier proof.
 */
static int32_t rrmp_target_software_lifecycle(uint8_t *ws, size_t need)
{
    ninlil_rrmp_owner_config_v1_t cfg;
    ninlil_rrmp_owner_t *o;
    ninlil_rrmp_owner_t *o2;
    ninlil_rrmp_scope_derivation_ctx_t sctx;
    ninlil_rrmp_id16_t pids[2];
    ninlil_rrmp_digest32_t dig;
    uint8_t scope[16];
    uint8_t path_policy[16];
    uint8_t attempt1[16];
    uint8_t attempt_fresh[16];
    uint8_t selected[16];
    static const uint8_t app_data[] = {
        0x00u, 0x52u, 0x52u, 0x4Du, 0x50u, 0xFEu};
    ninlil_rrmp_outbound_provider_t provider;
    uint64_t opaque;
    size_t i;
    uint32_t st;

    if (!smoke_store_ready()) {
        return -4;
    }

    memset(&cfg, 0, sizeof(cfg));
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
    memset(&s_outbound, 0, sizeof(s_outbound));
    memset(&provider, 0, sizeof(provider));
    provider.user = &s_outbound;
    provider.submit = smoke_outbound_submit;

    o = ninlil_rrmp_owner_init(ws, need, &cfg);
    if (o == NULL) {
        return -3;
    }
    ninlil_rrmp_owner_bind(o);

    memset(&sctx, 0, sizeof(sctx));
    fill_id(sctx.endpoint_runtime_id, 0x10u);
    sctx.direction = 0u;
    sctx.traffic_class = 1u;
    sctx.namespace_len = 4u;
    sctx.service_len = 3u;
    memcpy(sctx.namespace, "nspc", 4u);
    memcpy(sctx.service, "svc", 3u);

    if (!ninlil_rrmp_composition_bind(
            o, &s_store.ops, s_store.handle, &provider, &sctx) ||
        !ninlil_rrmp_composition_recover(o)) {
        ninlil_rrmp_owner_fini(o);
        return -4;
    }

    memset(&s_install, 0, sizeof(s_install));
    s_install.preamble.api_version = 1u;
    s_install.preamble.struct_size = 312u;
    fill_id(s_install.authority_id, 0xA0u);
    s_install.controller_term = 5u;
    s_install.batch_id = 1u;
    s_install.entry_count = 1u;
    fill_nrm1(&s_nrm);
    if (!ninlil_rrmp_encode_nrm1(&s_nrm, s_raw)) {
        ninlil_rrmp_owner_fini(o);
        return -5;
    }
    memcpy(s_install.entries, s_raw, sizeof(s_raw));
    if (ninlil_route_install_batch(&s_install, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o);
        return -5;
    }
    memset(&s_act, 0, sizeof(s_act));
    s_act.preamble.api_version = 1u;
    s_act.preamble.struct_size = 64u;
    s_act.ingress_hop_context_id = 0x1001u;
    s_act.route_handle = 1u;
    s_act.route_generation = 1u;
    s_act.now_ms = 1000000u;
    if (ninlil_route_activate(&s_act, &s_rout) != NINLIL_ROUTE_OK ||
        smoke_store_logical_length(&s_store) == 0u) {
        ninlil_rrmp_owner_fini(o);
        return -5;
    }

    fill_id(path_policy, 0x80u);
    if (!ninlil_rrmp_derive_owner_scope_id(
            sctx.endpoint_runtime_id, sctx.direction, sctx.namespace,
            sctx.namespace_len, sctx.service, sctx.service_len, sctx.traffic_class,
            path_policy, scope)) {
        ninlil_rrmp_owner_fini(o);
        return -6;
    }
    memset(&s_pset, 0, sizeof(s_pset));
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
        return -6;
    }
    memcpy(s_pset.parent_set_digest32, dig.bytes, 32u);
    if (ninlil_parent_set_install(&s_pset, &s_pout) != NINLIL_PARENT_OK) {
        ninlil_rrmp_owner_fini(o);
        return -6;
    }
    if (!smoke_parent_bootstrap_assignment(
            scope,
            path_policy,
            dig.bytes,
            s_pset.parent_set_count)) {
        ninlil_rrmp_owner_fini(o);
        return -6;
    }
    memset(attempt1, 0, 16u);
    ninlil_rrmp_put_u16_be(attempt1 + 14, 1u);
    memset(attempt_fresh, 0, 16u);
    attempt_fresh[0] = 0xA3u;
    ninlil_rrmp_put_u16_be(attempt_fresh + 14, 1u);
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt1, selected, &s_pout) != NINLIL_PARENT_OK ||
        memcmp(selected, pids[0].bytes, 16u) != 0) {
        ninlil_rrmp_owner_fini(o);
        return -6;
    }

    /* Cold restart: production recover of route + parent + attempt fence. */
    ninlil_rrmp_owner_fini(o);
    o2 = ninlil_rrmp_owner_init(ws, need, &cfg);
    if (o2 == NULL) {
        return -9;
    }
    ninlil_rrmp_owner_bind(o2);
    if (!ninlil_rrmp_composition_bind(
            o2, &s_store.ops, s_store.handle, &provider, &sctx) ||
        !ninlil_rrmp_composition_recover(o2)) {
        ninlil_rrmp_owner_fini(o2);
        return -9;
    }
    memset(&s_rq, 0, sizeof(s_rq));
    s_rq.preamble.api_version = 1u;
    s_rq.preamble.struct_size = 48u;
    s_rq.ingress_hop_context_id = 0x1001u;
    s_rq.route_handle = 1u;
    s_rq.route_generation = 1u;
    if (ninlil_route_query(&s_rq, &s_rout) != NINLIL_ROUTE_OK ||
        s_rout.lifecycle_state != NINLIL_RRMP_LIFE_ACTIVE) {
        ninlil_rrmp_owner_fini(o2);
        return -9;
    }
    memset(&s_pq, 0, sizeof(s_pq));
    s_pq.preamble.api_version = 1u;
    s_pq.preamble.struct_size = 48u;
    memcpy(s_pq.owner_scope_id, scope, 16u);
    if (ninlil_parent_query(&s_pq, &s_pout) != NINLIL_PARENT_OK) {
        ninlil_rrmp_owner_fini(o2);
        return -9;
    }
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o2, scope, attempt1, selected, &s_pout) !=
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT) {
        ninlil_rrmp_owner_fini(o2);
        return -9;
    }

    /*
     * A parent-set revision is not an authority transition and must not clear
     * the durable used-attempt ledger. A genuinely fresh identity may then
     * admit real ApplicationData and parent[0].
     */
    s_pset.assignment_epoch = 2u;
    if (ninlil_parent_set_install(&s_pset, &s_pout) != NINLIL_PARENT_OK) {
        ninlil_rrmp_owner_fini(o2);
        return -6;
    }
    if (ninlil_rrmp_core_parent_select_for_attempt(
            o2, scope, attempt1, selected, &s_pout) !=
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT) {
        ninlil_rrmp_owner_fini(o2);
        return -6;
    }
    memset(&s_admit, 0, sizeof(s_admit));
    s_admit.preamble.api_version = 1u;
    s_admit.preamble.struct_size = 128u;
    s_admit.ingress_hop_context_id = 0x1001u;
    s_admit.route_handle = 1u;
    s_admit.route_generation = 1u;
    s_admit.hop_remaining = 1u;
    s_admit.admission_now_ms = 1000000u;
    s_admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    s_admit.caller_item_token = 1u;
    s_admit.outer_rx_counter = 3u;
    for (i = 0u; i < 32u; ++i) {
        s_admit.e2e_header_digest32[i] = (uint8_t)(0xC0u + i);
    }
    if (ninlil_rrmp_core_forward_admit_with_carrier(
            o2, &s_admit, app_data, (uint16_t)sizeof(app_data),
            attempt_fresh, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o2);
        return -5;
    }
    opaque = s_rout.opaque_local_handle;

    /* Second cold restart proves queue/carrier/handle/selected-parent recovery. */
    ninlil_rrmp_owner_fini(o2);
    o2 = ninlil_rrmp_owner_init(ws, need, &cfg);
    if (o2 == NULL || !ninlil_rrmp_owner_bind(o2) ||
        !ninlil_rrmp_composition_bind(
            o2, &s_store.ops, s_store.handle, &provider, &sctx) ||
        !ninlil_rrmp_composition_recover(o2)) {
        if (o2 != NULL) {
            ninlil_rrmp_owner_fini(o2);
        }
        return -9;
    }
    memset(&s_hop_tx, 0, sizeof(s_hop_tx));
    if (ninlil_rrmp_core_hop_forward_execute(
            o2, opaque, NULL, 0u, 1u, &s_hop_tx) != NINLIL_ROUTE_OK ||
        s_outbound.last.carrier_len != sizeof(app_data) ||
        memcmp(s_outbound.last.carrier, app_data, sizeof(app_data)) != 0 ||
        !s_outbound.last.selected_parent_set ||
        memcmp(
            s_outbound.last.selected_parent_id, pids[0].bytes, 16u) != 0) {
        ninlil_rrmp_owner_fini(o2);
        return -7;
    }
    memset(&s_worker, 0, sizeof(s_worker));
    if (ninlil_rrmp_core_worker_tick(
            o2, 1005000u, 1u, &s_worker) != NINLIL_ROUTE_OK ||
        s_worker.submitted != 1u || s_outbound.submit_count != 2u) {
        ninlil_rrmp_owner_fini(o2);
        return -7;
    }
    memset(&s_link_ack, 0, sizeof(s_link_ack));
    s_link_ack.opaque_local_handle = opaque;
    s_link_ack.auth_ok = 1u;
    s_link_ack.ack_ok = 1u;
    s_link_ack.outer_tx_counter = s_outbound.last.outer_tx_counter;
    memcpy(s_link_ack.peer_runtime_id, pids[0].bytes, 16u);
    s_link_ack.auth_proof32[0] = 1u;
    if (ninlil_rrmp_core_link_ack_from_evidence(
            o2, &s_link_ack, &s_rout) != NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o2);
        return -8;
    }
    memset(&s_complete, 0, sizeof(s_complete));
    s_complete.preamble.api_version = 1u;
    s_complete.preamble.struct_size = 64u;
    s_complete.opaque_local_handle = opaque;
    s_complete.outcome = 1u;
    s_complete.completion_now_ms = 1005000u;
    if (ninlil_route_forward_complete(&s_complete, &s_rout) !=
        NINLIL_ROUTE_OK) {
        ninlil_rrmp_owner_fini(o2);
        return -8;
    }

    /* Unique parent_loss failover: next select is exactly SPLIT_BRAIN. */
    if (ninlil_rrmp_core_parent_loss(o2, scope, pids[0].bytes) != NINLIL_PARENT_OK) {
        ninlil_rrmp_owner_fini(o2);
        return -6;
    }
    st = ninlil_rrmp_core_parent_select_for_attempt(
        o2, scope, attempt1, selected, &s_pout);
    if (st != NINLIL_PARENT_SPLIT_BRAIN || s_pout.seal_allowed != 0u) {
        ninlil_rrmp_owner_fini(o2);
        return -6;
    }

    ninlil_rrmp_owner_fini(o2);
    return 0;
}

int32_t ninlil_rrmp_target_smoke_run(void)
{
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    uint8_t *ws;
    int32_t st;

    if (!ninlil_rrmp_sha256_selftest()) {
        return -1;
    }
    if (need == 0u || need > NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES) {
        return -2;
    }
    ws = smoke_ws_get(need);
    if (ws == NULL) {
        return -2;
    }

    /* Production bind/recover null-reject (no synthetic default). */
    if (ninlil_rrmp_composition_bind(NULL, NULL, NULL, NULL, NULL) != 0 ||
        ninlil_rrmp_composition_recover(NULL) != 0) {
        return -3;
    }
    /* GC-resistant pin of fabric seam + parent CU recover (null reject). */
    {
        ninlil_route_result_v1_t seam_out;
        ninlil_parent_result_v1_t precover_out;
        if (ninlil_rrmp_seam_fabric_relay_cycle(NULL, 0u, NULL, &seam_out) !=
            NINLIL_ROUTE_INVALID_ARGUMENT) {
            return -3;
        }
        if (ninlil_parent_recover_commit_unknown(NULL, &precover_out) !=
            NINLIL_PARENT_INVALID_ARGUMENT) {
            return -3;
        }
    }

    st = rrmp_target_software_lifecycle(ws, need);
    return st;
}

size_t ninlil_rrmp_target_smoke_workspace_bytes(void)
{
    return ninlil_rrmp_owner_workspace_bytes();
}
