/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_test_common.h"

#include "ninlil/platform.h"

#include <stdlib.h>

/* Minimal FULL-capable RAM storage for RRMP production bind tests. */
#define RRMP_RAM_PIECES 6u
#define RRMP_RAM_VALUE_MAX NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX

typedef struct rrmp_ram_store {
    uint8_t present[RRMP_RAM_PIECES];
    uint8_t value[RRMP_RAM_PIECES][RRMP_RAM_VALUE_MAX];
    uint32_t value_len[RRMP_RAM_PIECES];
    int force_cu; /* next commit returns COMMIT_UNKNOWN */
    int force_cu_apply; /* next commit applies NEW, then returns COMMIT_UNKNOWN */
    ninlil_storage_ops_t ops;
} rrmp_ram_store_t;

typedef struct rrmp_ram_txn {
    rrmp_ram_store_t *store;
    uint8_t present[RRMP_RAM_PIECES];
    uint8_t value[RRMP_RAM_PIECES][RRMP_RAM_VALUE_MAX];
    uint32_t value_len[RRMP_RAM_PIECES];
    uint8_t dirty;
    uint8_t iter_index;
    ninlil_storage_mode_t mode;
} rrmp_ram_txn_t;

static int ram_key_kind(ninlil_bytes_view_t key)
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

static ninlil_storage_status_t ram_open(
    void *user, ninlil_bytes_view_t storage_namespace, uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    (void)storage_namespace;
    (void)expected_schema;
    if (out_handle == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out_handle = (ninlil_storage_handle_t)user;
    return NINLIL_STORAGE_OK;
}
static void ram_close(void *user, ninlil_storage_handle_t handle)
{
    (void)user;
    (void)handle;
}
static ninlil_storage_status_t ram_begin(
    void *user, ninlil_storage_handle_t handle, ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    rrmp_ram_txn_t *t;
    (void)handle;
    if (out_txn == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = (rrmp_ram_txn_t *)calloc(1, sizeof(*t));
    if (t == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    t->store = (rrmp_ram_store_t *)user;
    t->mode = mode;
    memcpy(t->present, t->store->present, sizeof(t->present));
    memcpy(t->value, t->store->value, sizeof(t->value));
    memcpy(t->value_len, t->store->value_len, sizeof(t->value_len));
    *out_txn = (ninlil_storage_txn_t)t;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t ram_get(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    rrmp_ram_txn_t *t = (rrmp_ram_txn_t *)txn;
    int kind = ram_key_kind(key);
    (void)user;
    if (t == NULL || inout_value == NULL || t->store == NULL ||
        kind < 0 || !t->present[kind]) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (inout_value->capacity < t->value_len[kind]) {
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    memcpy(
        inout_value->data, t->value[kind], t->value_len[kind]);
    inout_value->length = t->value_len[kind];
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t ram_put(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    rrmp_ram_txn_t *t = (rrmp_ram_txn_t *)txn;
    int kind = ram_key_kind(key);
    (void)user;
    if (t == NULL || kind < 0 ||
        t->mode != NINLIL_STORAGE_READ_WRITE || value.length == 0u ||
        value.length > RRMP_RAM_VALUE_MAX) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    memcpy(t->value[kind], value.data, value.length);
    t->value_len[kind] = value.length;
    t->present[kind] = 1u;
    t->dirty = 1u;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t ram_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    rrmp_ram_txn_t *t = (rrmp_ram_txn_t *)txn;
    int kind = ram_key_kind(key);
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
static ninlil_storage_status_t ram_iter_open(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    rrmp_ram_txn_t *t = (rrmp_ram_txn_t *)txn;
    static const uint8_t expected[5] = {'R', 'R', 'M', 'P', '/'};
    (void)user;
    if (t == NULL || out_iter == NULL || prefix.length != 5u ||
        memcmp(prefix.data, expected, 5u) != 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->iter_index = 0u;
    *out_iter = (ninlil_storage_iter_t)t;
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t ram_iter_next(
    void *user, ninlil_storage_iter_t iter, ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    rrmp_ram_txn_t *t = (rrmp_ram_txn_t *)iter;
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
    if (t == NULL || inout_key == NULL || inout_value == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    while (t->iter_index < 6u) {
        uint8_t ordinal = t->iter_index++;
        uint8_t kind = kinds[ordinal];
        if (!t->present[kind]) {
            continue;
        }
        if (inout_key->capacity < 7u ||
            inout_value->capacity < t->value_len[kind]) {
            return NINLIL_STORAGE_BUFFER_TOO_SMALL;
        }
        memcpy(inout_key->data, keys[ordinal], 7u);
        inout_key->length = 7u;
        memcpy(
            inout_value->data,
            t->value[kind],
            t->value_len[kind]);
        inout_value->length = t->value_len[kind];
        return NINLIL_STORAGE_OK;
    }
    return NINLIL_STORAGE_NOT_FOUND;
}
static void ram_iter_close(void *user, ninlil_storage_iter_t iter)
{
    (void)user;
    (void)iter;
}
static ninlil_storage_status_t ram_capacity(
    void *user, ninlil_storage_handle_t handle, ninlil_storage_capacity_t *out)
{
    (void)user;
    (void)handle;
    (void)out;
    return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}
static ninlil_storage_status_t ram_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t durability)
{
    rrmp_ram_txn_t *t = (rrmp_ram_txn_t *)txn;
    rrmp_ram_store_t *s;
    (void)user;
    if (t == NULL || t->store == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    s = t->store;
    if (s->force_cu || s->force_cu_apply) {
        int apply = s->force_cu_apply;
        s->force_cu = 0;
        s->force_cu_apply = 0;
        if (apply && t->dirty) {
            memcpy(s->present, t->present, sizeof(s->present));
            memcpy(s->value, t->value, sizeof(s->value));
            memcpy(s->value_len, t->value_len, sizeof(s->value_len));
        }
        free(t);
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    if (durability != NINLIL_DURABILITY_FULL) {
        free(t);
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (t->dirty) {
        memcpy(s->present, t->present, sizeof(s->present));
        memcpy(s->value, t->value, sizeof(s->value));
        memcpy(s->value_len, t->value_len, sizeof(s->value_len));
    }
    free(t);
    return NINLIL_STORAGE_OK;
}
static ninlil_storage_status_t ram_rollback(void *user, ninlil_storage_txn_t txn)
{
    (void)user;
    free(txn);
    return NINLIL_STORAGE_OK;
}
static void ram_store_init(rrmp_ram_store_t *s)
{
    ninlil_rrmp_memzero(s, sizeof(*s));
    s->ops.abi_version = NINLIL_ABI_VERSION;
    s->ops.struct_size = (uint32_t)sizeof(s->ops);
    s->ops.user = s;
    s->ops.open = ram_open;
    s->ops.close = ram_close;
    s->ops.begin = ram_begin;
    s->ops.get = ram_get;
    s->ops.put = ram_put;
    s->ops.erase = ram_erase;
    s->ops.iter_open = ram_iter_open;
    s->ops.iter_next = ram_iter_next;
    s->ops.iter_close = ram_iter_close;
    s->ops.capacity = ram_capacity;
    s->ops.commit = ram_commit;
    s->ops.rollback = ram_rollback;
}

static int ram_store_logical_copy(
    const rrmp_ram_store_t *s,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_length)
{
    const uint8_t *manifest;
    uint32_t logical_length;
    uint8_t chunk_count;
    uint8_t digest[32];
    uint8_t i;
    size_t copied = 0u;
    if (s == NULL || out == NULL || out_length == NULL ||
        !s->present[0] ||
        s->value_len[0] != NINLIL_RRMP_RRM1_BYTES) {
        return 0;
    }
    manifest = s->value[0];
    if (memcmp(manifest, "RRM1", 4u) != 0 ||
        ninlil_rrmp_get_u16_be(manifest + 4u) != 1u ||
        ninlil_rrmp_get_u16_be(manifest + 6u) !=
            NINLIL_RRMP_RRM1_BYTES ||
        ninlil_rrmp_get_u32_be(manifest + 252u) !=
            ninlil_rrmp_crc32c_zeroed_u32_be_field(
                manifest, NINLIL_RRMP_RRM1_BYTES, 252u)) {
        return 0;
    }
    logical_length = ninlil_rrmp_get_u32_be(manifest + 16u);
    chunk_count = manifest[20u];
    if (logical_length == 0u ||
        logical_length > NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX ||
        logical_length > out_capacity ||
        chunk_count == 0u ||
        chunk_count > NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX) {
        return 0;
    }
    for (i = 0u; i < chunk_count; ++i) {
        const uint8_t *desc = manifest + 56u + (size_t)i * 36u;
        uint32_t length = ninlil_rrmp_get_u32_be(desc);
        if (!s->present[(size_t)i + 1u] ||
            s->value_len[(size_t)i + 1u] != length ||
            copied + length > logical_length) {
            return 0;
        }
        ninlil_rrmp_sha256(s->value[(size_t)i + 1u], length, digest);
        if (memcmp(digest, desc + 4u, sizeof(digest)) != 0) {
            return 0;
        }
        memcpy(out + copied, s->value[(size_t)i + 1u], length);
        copied += length;
    }
    if (copied != logical_length) {
        return 0;
    }
    ninlil_rrmp_sha256(out, logical_length, digest);
    if (memcmp(digest, manifest + 24u, sizeof(digest)) != 0) {
        return 0;
    }
    *out_length = logical_length;
    return 1;
}

static int ram_store_witness(
    const rrmp_ram_store_t *s,
    ninlil_rrmp_bundle_witness_v2_t *out)
{
    uint32_t logical_length;
    if (s == NULL || out == NULL || !s->present[0] ||
        s->value_len[0] != NINLIL_RRMP_RRM1_BYTES ||
        memcmp(s->value[0], "RRM1", 4u) != 0) {
        return 0;
    }
    logical_length = ninlil_rrmp_get_u32_be(s->value[0] + 16u);
    if (logical_length == 0u ||
        logical_length > NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->present = 1u;
    memcpy(
        out->manifest_rrm1,
        s->value[0],
        NINLIL_RRMP_RRM1_BYTES);
    out->logical_length = logical_length;
    memcpy(out->logical_sha256, s->value[0] + 24u, 32u);
    return 1;
}

enum { RRMP_WS_MAX = NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES };
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_ws1[RRMP_WS_MAX];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) static uint8_t g_ws2[RRMP_WS_MAX];
static uint8_t g_attack_base[256 * 1024];
static uint8_t g_attack_work[256 * 1024];
static uint8_t g_strict_valid_route[16 * 1024];
static uint8_t g_strict_valid_parent[16 * 1024];
static uint8_t g_strict_mutant[16 * 1024];
static uint8_t g_strict_record[4096];

static int parent_record_latest(
    uint8_t *envelope,
    size_t envelope_len,
    uint8_t key_id,
    uint8_t **payload_out,
    uint32_t *payload_len_out)
{
    uint32_t route_len;
    uint32_t parent_len;
    size_t parent_off;
    size_t off;
    uint8_t count;
    uint8_t i;
    uint64_t best_generation = 0u;
    uint8_t *best = NULL;
    uint32_t best_len = 0u;
    if (envelope == NULL || payload_out == NULL ||
        payload_len_out == NULL || envelope_len < 28u ||
        memcmp(envelope, "RRMPNS1\0", 8u) != 0) {
        return 0;
    }
    route_len = ninlil_rrmp_get_u32_be(envelope + 8u);
    parent_len = ninlil_rrmp_get_u32_be(envelope + 12u);
    parent_off = 20u + (size_t)route_len;
    if (parent_off + (size_t)parent_len > envelope_len ||
        parent_len < 8u ||
        memcmp(envelope + parent_off, "PNS1", 4u) != 0) {
        return 0;
    }
    count = envelope[parent_off + 4u];
    off = parent_off + 8u;
    for (i = 0u; i < count; ++i) {
        uint8_t kid;
        uint64_t generation;
        uint32_t len;
        if (off + 13u > parent_off + (size_t)parent_len) {
            return 0;
        }
        kid = envelope[off];
        generation = ninlil_rrmp_get_u64_be(envelope + off + 1u);
        len = ninlil_rrmp_get_u32_be(envelope + off + 9u);
        off += 13u;
        if (off + (size_t)len > parent_off + (size_t)parent_len) {
            return 0;
        }
        if (kid == key_id && generation > best_generation) {
            best_generation = generation;
            best = envelope + off;
            best_len = len;
        }
        off += len;
    }
    if (off != parent_off + (size_t)parent_len || best == NULL) {
        return 0;
    }
    *payload_out = best;
    *payload_len_out = best_len;
    return 1;
}

static int remove_parent_key_records(
    uint8_t *envelope, size_t *envelope_len, uint8_t key_id)
{
    uint32_t route_len;
    uint32_t parent_len;
    size_t parent_off;
    size_t off;
    uint8_t count;
    uint8_t index = 0u;
    uint8_t removed = 0u;
    if (envelope == NULL || envelope_len == NULL ||
        *envelope_len < 28u ||
        memcmp(envelope, "RRMPNS1\0", 8u) != 0) {
        return 0;
    }
    route_len = ninlil_rrmp_get_u32_be(envelope + 8u);
    parent_len = ninlil_rrmp_get_u32_be(envelope + 12u);
    parent_off = 20u + (size_t)route_len;
    if (parent_off + (size_t)parent_len > *envelope_len ||
        parent_len < 8u ||
        memcmp(envelope + parent_off, "PNS1", 4u) != 0) {
        return 0;
    }
    count = envelope[parent_off + 4u];
    off = parent_off + 8u;
    while (index < count) {
        uint32_t len;
        size_t record_len;
        if (off + 13u > parent_off + (size_t)parent_len) {
            return 0;
        }
        len = ninlil_rrmp_get_u32_be(envelope + off + 9u);
        record_len = 13u + (size_t)len;
        if (off + record_len > parent_off + (size_t)parent_len) {
            return 0;
        }
        if (envelope[off] == key_id) {
            memmove(
                envelope + off,
                envelope + off + record_len,
                *envelope_len - off - record_len);
            *envelope_len -= record_len;
            parent_len -= (uint32_t)record_len;
            --count;
            ++removed;
            continue;
        }
        off += record_len;
        ++index;
    }
    envelope[parent_off + 4u] = count;
    ninlil_rrmp_put_u32_be(envelope + 12u, parent_len);
    return removed != 0u ? 1 : 0;
}

static int soft_region(
    uint8_t *envelope,
    size_t envelope_len,
    uint8_t **soft_out,
    uint32_t *soft_len_out,
    size_t *soft_off_out)
{
    uint32_t route_len;
    uint32_t parent_len;
    uint32_t soft_len;
    size_t soft_off;
    if (envelope == NULL || soft_out == NULL || soft_len_out == NULL ||
        soft_off_out == NULL || envelope_len < 20u) {
        return 0;
    }
    route_len = ninlil_rrmp_get_u32_be(envelope + 8u);
    parent_len = ninlil_rrmp_get_u32_be(envelope + 12u);
    soft_len = ninlil_rrmp_get_u32_be(envelope + 16u);
    soft_off = 20u + (size_t)route_len + (size_t)parent_len;
    if (soft_off + (size_t)soft_len != envelope_len ||
        soft_len < 48u) {
        return 0;
    }
    *soft_out = envelope + soft_off;
    *soft_len_out = soft_len;
    *soft_off_out = soft_off;
    return 1;
}

static void repair_soft_crc(uint8_t *soft, uint32_t soft_len)
{
    ninlil_rrmp_put_u32_be(soft + 20u, 0u);
    ninlil_rrmp_put_u32_be(
        soft + 20u,
        ninlil_rrmp_crc32c_zeroed_u32_be_field(
            soft, (size_t)soft_len, 20u));
}

static ninlil_rrmp_owner_t *mk(uint8_t *ws, uint8_t r, uint8_t p)
{
    size_t need = ninlil_rrmp_owner_workspace_bytes();
    if (need > RRMP_WS_MAX) {
        return NULL;
    }
    return rrmp_mk_ws(ws, need, r, p);
}

static ninlil_rrmp_owner_t *restart_parent_owner(
    ninlil_rrmp_owner_t *old_owner,
    uint8_t *workspace,
    rrmp_ram_store_t *store,
    ninlil_storage_handle_t handle)
{
    ninlil_rrmp_owner_t *owner;
    ninlil_rrmp_owner_fini(old_owner);
    owner = mk(workspace, 1u, 1u);
    if (owner == NULL ||
        !ninlil_rrmp_owner_bind_storage(owner, &store->ops, handle) ||
        !ninlil_rrmp_owner_storage_recover(owner) ||
        !ninlil_rrmp_owner_bind(owner)) {
        if (owner != NULL) {
            ninlil_rrmp_owner_fini(owner);
        }
        return NULL;
    }
    return owner;
}

static int setup(ninlil_rrmp_owner_t *o)
{
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_result_v1_t out;
    size_t i;
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
    admit.caller_item_token = 1u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0x33u + i);
    }
    RRMP_CHECK_EQ(ninlil_route_forward_admit(o, &admit, &out), NINLIL_ROUTE_OK);
    return 0;
}

static int test_restart_rehydrate(void)
{
    /* Route-only (multi_parent off): restart of dual namespace without scope. */
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 0u);
    ninlil_rrmp_owner_t *o2;
    uint8_t *snap = NULL;
    size_t need = 0u;
    ninlil_route_query_req_v1_t q;
    ninlil_route_result_v1_t out;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(setup(o) == 0);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, NULL, 0u, &need));
    snap = (uint8_t *)malloc(need);
    RRMP_CHECK(snap != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, snap, need, &need));

    o2 = mk(g_ws2, 1u, 0u);
    RRMP_CHECK(o2 != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_import_namespace(o2, snap, need));
    ninlil_rrmp_owner_bind(o2);
    ninlil_rrmp_memzero(&q, sizeof(q));
    q.preamble.api_version = 1u;
    q.preamble.struct_size = 48u;
    q.ingress_hop_context_id = 0x1001u;
    q.route_handle = 1u;
    q.route_generation = 1u;
    RRMP_CHECK_EQ(ninlil_route_query(o2, &q, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(out.lifecycle_state, NINLIL_RRMP_LIFE_ACTIVE);
    free(snap);
    ninlil_rrmp_owner_fini(o);
    ninlil_rrmp_owner_fini(o2);
    return 0;
}

static int test_cu_classes(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 0u);
    ninlil_route_recover_cu_req_v1_t req;
    ninlil_route_result_v1_t out;
    ninlil_route_result_v1_t out_before;
    uint8_t *snap = NULL;
    size_t need = 0u;
    ninlil_rrmp_owner_t *o2;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(setup(o) == 0);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, NULL, 0u, &need));
    snap = (uint8_t *)malloc(need + 64u);
    RRMP_CHECK(snap != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, snap, need, &need));

    /* Truncated / corrupt image: import fail-closed + recover CORRUPT + fenced. */
    o2 = mk(g_ws2, 1u, 0u);
    RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(o2, snap, 20u));
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o2), 0u);
    ninlil_rrmp_owner_bind(o2);
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = 1u;
    req.preamble.struct_size = 80u;
    ninlil_rrmp_memzero(&out, sizeof(out));
    out.lifecycle_state = 0xAAu;
    out.opaque_local_handle = 0xDEADBEEFu;
    out_before = out;
    RRMP_CHECK_EQ(
        ninlil_route_recover_commit_unknown(o2, &req, &out), NINLIL_ROUTE_CORRUPT);
    RRMP_CHECK_EQ(out.lifecycle_state, 0u);
    RRMP_CHECK_EQ(out.opaque_local_handle, 0u);
    RRMP_CHECK(out.status == NINLIL_ROUTE_CORRUPT);
    RRMP_CHECK(out.cu_class == NINLIL_RRMP_CU_PARTIAL
        || out.cu_class == NINLIL_RRMP_CU_EXTRA
        || out.cu_class == NINLIL_RRMP_CU_THIRD);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o2), 0u);
    (void)out_before;
    ninlil_rrmp_owner_fini(o2);

    /* EXTRA image (overlong envelope): CU_EXTRA + fenced. */
    memset(snap + need, 0xEE, 64u);
    o2 = mk(g_ws2, 1u, 0u);
    RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(o2, snap, need + 64u));
    RRMP_CHECK_EQ(ninlil_rrmp_owner_cu_class(o2), NINLIL_RRMP_CU_EXTRA);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o2), 0u);
    ninlil_rrmp_owner_bind(o2);
    ninlil_rrmp_memzero(&out, sizeof(out));
    out.lifecycle_state = 0x55u;
    out.opaque_local_handle = 99u;
    RRMP_CHECK_EQ(
        ninlil_route_recover_commit_unknown(o2, &req, &out), NINLIL_ROUTE_CORRUPT);
    RRMP_CHECK_EQ(out.cu_class, NINLIL_RRMP_CU_EXTRA);
    RRMP_CHECK_EQ(out.lifecycle_state, 0u);
    RRMP_CHECK_EQ(out.opaque_local_handle, 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o2), 0u);
    ninlil_rrmp_owner_fini(o2);

    free(snap);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_dual_inject(void)
{
    ninlil_rrmp_route_ns_t ns;
    ninlil_rrmp_parent_ns_t pns;
    ninlil_rrmp_owner_t *o;
    ninlil_route_recover_cu_req_v1_t req;
    ninlil_route_result_v1_t out;

    ninlil_rrmp_route_ns_init(&ns);
    ninlil_rrmp_route_inject_third(&ns, 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_route_classify_cu(&ns), NINLIL_RRMP_CU_THIRD);
    RRMP_CHECK_EQ(ns.fenced, 1u);
    RRMP_CHECK_EQ(ns.cu_class, NINLIL_RRMP_CU_THIRD);
    ninlil_rrmp_route_ns_init(&ns);
    ninlil_rrmp_route_inject_extra(&ns, 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_route_classify_cu(&ns), NINLIL_RRMP_CU_EXTRA);
    RRMP_CHECK_EQ(ns.fenced, 1u);

    ninlil_rrmp_route_ns_init(&ns);
    ninlil_rrmp_route_inject_cu_old(&ns, 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_route_classify_cu(&ns), NINLIL_RRMP_CU_OLD);
    ninlil_rrmp_parent_ns_init(&pns);
    ninlil_rrmp_parent_inject_cu_old(&pns, 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_parent_classify_cu(&pns), NINLIL_RRMP_CU_OLD);

    /* Owner-level THIRD image: recover fail-closed, out clean, owner fenced. */
    o = mk(g_ws1, 1u, 0u);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(setup(o) == 0);
    ninlil_rrmp_owner_bind(o);
    ninlil_rrmp_owner_fault_inject_route_cu_third(o, NINLIL_RRMP_KEY_NRD1);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_cu_class(o), NINLIL_RRMP_CU_THIRD);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 0u);
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = 1u;
    req.preamble.struct_size = 80u;
    ninlil_rrmp_memzero(&out, sizeof(out));
    out.lifecycle_state = 0xFFu;
    out.opaque_local_handle = 0x1111u;
    RRMP_CHECK_EQ(
        ninlil_route_recover_commit_unknown(o, &req, &out), NINLIL_ROUTE_CORRUPT);
    RRMP_CHECK_EQ(out.cu_class, NINLIL_RRMP_CU_THIRD);
    RRMP_CHECK_EQ(out.lifecycle_state, 0u);
    RRMP_CHECK_EQ(out.opaque_local_handle, 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 0u);

    /* Owner-level corrupt active page: same fail-closed contract. */
    ninlil_rrmp_owner_fault_inject_route_corrupt(o, NINLIL_RRMP_KEY_NRD1);
    ninlil_rrmp_memzero(&out, sizeof(out));
    out.lifecycle_state = 0x77u;
    out.opaque_local_handle = 0x22u;
    RRMP_CHECK_EQ(
        ninlil_route_recover_commit_unknown(o, &req, &out), NINLIL_ROUTE_CORRUPT);
    RRMP_CHECK(out.cu_class == NINLIL_RRMP_CU_PARTIAL
        || out.cu_class == NINLIL_RRMP_CU_THIRD);
    RRMP_CHECK_EQ(out.lifecycle_state, 0u);
    RRMP_CHECK_EQ(out.opaque_local_handle, 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 0u);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_owner_cu_old_recover(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 1u);
    ninlil_route_recover_cu_req_v1_t req;
    ninlil_route_result_v1_t out;
    ninlil_parent_recover_cu_req_v1_t preq;
    ninlil_parent_result_v1_t pout;
    RRMP_CHECK(o != NULL);
    /* Parent feature on for parent CU inject; route install only (no multi admit). */
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
    ninlil_rrmp_owner_bind(o);

    ninlil_rrmp_owner_fault_inject_route_cu_old(o, NINLIL_RRMP_KEY_NRD1);
    ninlil_rrmp_memzero(&req, sizeof(req));
    req.preamble.api_version = 1u;
    req.preamble.struct_size = 80u;
    RRMP_CHECK_EQ(
        ninlil_route_recover_commit_unknown(o, &req, &out), NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(out.cu_class, NINLIL_RRMP_CU_OLD);

    ninlil_rrmp_owner_fault_inject_parent_cu_old(o, NINLIL_RRMP_PKEY_NPH1);
    ninlil_rrmp_memzero(&preq, sizeof(preq));
    preq.preamble.api_version = 1u;
    preq.preamble.struct_size = 80u;
    rrmp_fill_id(preq.owner_scope_id, 0x5Cu);
    preq.expected_class = 0u; /* probe */
    RRMP_CHECK_EQ(
        ninlil_parent_recover_commit_unknown(o, &preq, &pout), NINLIL_PARENT_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(pout.cu_class, NINLIL_RRMP_CU_OLD);

    ninlil_rrmp_owner_fini(o);
    return 0;
}

static void strict_snapshot_header(uint8_t *out, uint8_t parent, uint8_t count)
{
    out[0] = parent ? 'P' : 'R';
    out[1] = 'N';
    out[2] = 'S';
    out[3] = '1';
    out[4] = count;
    out[5] = 0u;
    out[6] = 0u;
    out[7] = 0u;
}

static size_t strict_snapshot_append(
    uint8_t *out,
    size_t off,
    uint8_t key_id,
    uint64_t generation,
    const uint8_t *record,
    uint32_t length)
{
    out[off++] = key_id;
    ninlil_rrmp_put_u64_be(out + off, generation);
    off += 8u;
    ninlil_rrmp_put_u32_be(out + off, length);
    off += 4u;
    memcpy(out + off, record, length);
    return off + length;
}

static int strict_encode_nrd1(
    uint64_t generation, uint8_t salt, uint8_t out[NINLIL_RRMP_DIR_BYTES])
{
    ninlil_rrmp_id16_t authority;
    uint32_t route_page_gens[NINLIL_RRMP_PAGE_COUNT];
    uint32_t evidence_page_gens[NINLIL_RRMP_NEP1_PAGE_COUNT];
    rrmp_fill_id(authority.bytes, salt);
    ninlil_rrmp_memzero(route_page_gens, sizeof(route_page_gens));
    ninlil_rrmp_memzero(evidence_page_gens, sizeof(evidence_page_gens));
    route_page_gens[0] = 1u;
    evidence_page_gens[0] = 1u;
    return ninlil_rrmp_encode_nrd1(
        generation,
        &authority,
        (uint64_t)salt + 1u,
        route_page_gens,
        evidence_page_gens,
        out);
}

static int strict_encode_nph1(
    uint64_t generation, uint8_t salt, uint8_t out[NINLIL_RRMP_NPH1_BYTES])
{
    ninlil_rrmp_nph1_fields_t fields;
    ninlil_rrmp_memzero(&fields, sizeof(fields));
    rrmp_fill_id(fields.authority_id.bytes, salt);
    rrmp_fill_id(fields.writer_controller_id.bytes, (uint8_t)(salt + 0x10u));
    fields.controller_term = (uint64_t)salt + 1u;
    fields.writer_epoch = (uint64_t)salt + 2u;
    fields.lease_not_after_ms = 5000000u + salt;
    rrmp_fill_id(
        fields.authority_clock_epoch_id.bytes, (uint8_t)(salt + 0x20u));
    memset(fields.writer_proof_digest.bytes, (int)(salt | 1u), 32u);
    fields.header_generation = generation;
    fields.assignment_page_bitmap = 1u;
    fields.token_page_bitmap = 1u;
    memset(fields.authority_commit_digest.bytes, (int)(salt | 2u), 32u);
    return ninlil_rrmp_encode_nph1(&fields, out);
}

static int strict_build_valid_route_snapshot(size_t *len_out)
{
    size_t off = 8u;
    if (len_out == NULL) {
        return 0;
    }
    strict_snapshot_header(g_strict_valid_route, 0u, 3u);
    if (!strict_encode_nrd1(1u, 0x31u, g_strict_record)) {
        return 0;
    }
    off = strict_snapshot_append(
        g_strict_valid_route,
        off,
        NINLIL_RRMP_KEY_NRD1,
        1u,
        g_strict_record,
        NINLIL_RRMP_DIR_BYTES);
    if (!ninlil_rrmp_encode_nrp1(0u, 1u, NULL, g_strict_record)) {
        return 0;
    }
    off = strict_snapshot_append(
        g_strict_valid_route,
        off,
        NINLIL_RRMP_KEY_NRP1_BASE,
        1u,
        g_strict_record,
        NINLIL_RRMP_NRP1_BYTES);
    if (!ninlil_rrmp_encode_nep1(0u, 1u, NULL, 0u, g_strict_record)) {
        return 0;
    }
    off = strict_snapshot_append(
        g_strict_valid_route,
        off,
        NINLIL_RRMP_KEY_NEP1_BASE,
        1u,
        g_strict_record,
        NINLIL_RRMP_NEP1_BYTES);
    *len_out = off;
    return 1;
}

static int strict_build_valid_parent_snapshot(size_t *len_out)
{
    size_t off = 8u;
    if (len_out == NULL) {
        return 0;
    }
    strict_snapshot_header(g_strict_valid_parent, 1u, 4u);
    if (!strict_encode_nph1(1u, 0x41u, g_strict_record)) {
        return 0;
    }
    off = strict_snapshot_append(
        g_strict_valid_parent,
        off,
        NINLIL_RRMP_PKEY_NPH1,
        1u,
        g_strict_record,
        NINLIL_RRMP_NPH1_BYTES);
    if (!ninlil_rrmp_encode_npp1(0u, 1u, NULL, g_strict_record)) {
        return 0;
    }
    off = strict_snapshot_append(
        g_strict_valid_parent,
        off,
        NINLIL_RRMP_PKEY_NPP1_BASE,
        1u,
        g_strict_record,
        NINLIL_RRMP_NPP1_BYTES);
    if (!ninlil_rrmp_encode_npa1_page(0u, 1u, NULL, g_strict_record)) {
        return 0;
    }
    off = strict_snapshot_append(
        g_strict_valid_parent,
        off,
        NINLIL_RRMP_PKEY_NPA1_BASE,
        1u,
        g_strict_record,
        NINLIL_RRMP_NPA1_BYTES);
    if (!ninlil_rrmp_encode_npt1_page(
            0u, 1u, NULL, 0u, g_strict_record)) {
        return 0;
    }
    off = strict_snapshot_append(
        g_strict_valid_parent,
        off,
        NINLIL_RRMP_PKEY_NPT1_BASE,
        1u,
        g_strict_record,
        NINLIL_RRMP_NPT1_BYTES);
    *len_out = off;
    return 1;
}

static int strict_assert_route_fenced(
    ninlil_rrmp_route_ns_t *ns,
    uint32_t expected_class,
    size_t valid_len)
{
    uint8_t *write_buf = NULL;
    size_t cap = 0u;
    uint64_t generation = 0u;
    const uint8_t *read_buf = NULL;
    uint32_t read_len = 0u;
    RRMP_CHECK(ns->fenced != 0u);
    RRMP_CHECK(ns->corrupt != 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_route_classify_cu(ns), expected_class);
    RRMP_CHECK(!ninlil_rrmp_route_dual_begin_write(
        ns,
        NINLIL_RRMP_KEY_NRD1,
        &write_buf,
        &cap,
        &generation));
    RRMP_CHECK(!ninlil_rrmp_route_dual_read_active(
        ns,
        NINLIL_RRMP_KEY_NRD1,
        &read_buf,
        &read_len,
        &generation));
    RRMP_CHECK(!ninlil_rrmp_route_ns_import(
        ns, g_strict_valid_route, valid_len));
    RRMP_CHECK_EQ(ninlil_rrmp_route_classify_cu(ns), expected_class);
    return 0;
}

static int strict_assert_parent_fenced(
    ninlil_rrmp_parent_ns_t *ns,
    uint32_t expected_class,
    size_t valid_len)
{
    uint8_t *write_buf = NULL;
    size_t cap = 0u;
    uint64_t generation = 0u;
    const uint8_t *read_buf = NULL;
    uint32_t read_len = 0u;
    RRMP_CHECK(ns->fenced != 0u);
    RRMP_CHECK(ns->corrupt != 0u);
    RRMP_CHECK_EQ(ninlil_rrmp_parent_classify_cu(ns), expected_class);
    RRMP_CHECK(!ninlil_rrmp_parent_dual_begin_write(
        ns,
        NINLIL_RRMP_PKEY_NPH1,
        &write_buf,
        &cap,
        &generation));
    RRMP_CHECK(!ninlil_rrmp_parent_dual_read_active(
        ns,
        NINLIL_RRMP_PKEY_NPH1,
        &read_buf,
        &read_len,
        &generation));
    RRMP_CHECK(!ninlil_rrmp_parent_ns_import(
        ns, g_strict_valid_parent, valid_len));
    RRMP_CHECK_EQ(ninlil_rrmp_parent_classify_cu(ns), expected_class);
    return 0;
}

static int test_strict_namespace_import(void)
{
    ninlil_rrmp_route_ns_t route_ns;
    ninlil_rrmp_parent_ns_t parent_ns;
    const uint8_t *read_buf = NULL;
    uint32_t read_len = 0u;
    uint64_t read_gen = 0u;
    size_t route_valid_len = 0u;
    size_t parent_valid_len = 0u;
    size_t off;

    RRMP_CHECK(strict_build_valid_route_snapshot(&route_valid_len));
    RRMP_CHECK(strict_build_valid_parent_snapshot(&parent_valid_len));

    /* Cold import accepts every route namespace key type. */
    ninlil_rrmp_route_ns_init(&route_ns);
    RRMP_CHECK(ninlil_rrmp_route_ns_import(
        &route_ns, g_strict_valid_route, route_valid_len));
    RRMP_CHECK(ninlil_rrmp_route_dual_read_active(
        &route_ns,
        NINLIL_RRMP_KEY_NRD1,
        &read_buf,
        &read_len,
        &read_gen));
    RRMP_CHECK_EQ(read_len, NINLIL_RRMP_DIR_BYTES);
    RRMP_CHECK(ninlil_rrmp_route_dual_read_active(
        &route_ns,
        NINLIL_RRMP_KEY_NRP1_BASE,
        &read_buf,
        &read_len,
        &read_gen));
    RRMP_CHECK_EQ(read_len, NINLIL_RRMP_NRP1_BYTES);
    RRMP_CHECK(ninlil_rrmp_route_dual_read_active(
        &route_ns,
        NINLIL_RRMP_KEY_NEP1_BASE,
        &read_buf,
        &read_len,
        &read_gen));
    RRMP_CHECK_EQ(read_len, NINLIL_RRMP_NEP1_BYTES);

    /* Cold import accepts every parent namespace key type. */
    ninlil_rrmp_parent_ns_init(&parent_ns);
    RRMP_CHECK(ninlil_rrmp_parent_ns_import(
        &parent_ns, g_strict_valid_parent, parent_valid_len));
    RRMP_CHECK(ninlil_rrmp_parent_dual_read_active(
        &parent_ns,
        NINLIL_RRMP_PKEY_NPH1,
        &read_buf,
        &read_len,
        &read_gen));
    RRMP_CHECK_EQ(read_len, NINLIL_RRMP_NPH1_BYTES);
    RRMP_CHECK(ninlil_rrmp_parent_dual_read_active(
        &parent_ns,
        NINLIL_RRMP_PKEY_NPP1_BASE,
        &read_buf,
        &read_len,
        &read_gen));
    RRMP_CHECK_EQ(read_len, NINLIL_RRMP_NPP1_BYTES);
    RRMP_CHECK(ninlil_rrmp_parent_dual_read_active(
        &parent_ns,
        NINLIL_RRMP_PKEY_NPA1_BASE,
        &read_buf,
        &read_len,
        &read_gen));
    RRMP_CHECK_EQ(read_len, NINLIL_RRMP_NPA1_BYTES);
    RRMP_CHECK(ninlil_rrmp_parent_dual_read_active(
        &parent_ns,
        NINLIL_RRMP_PKEY_NPT1_BASE,
        &read_buf,
        &read_len,
        &read_gen));
    RRMP_CHECK_EQ(read_len, NINLIL_RRMP_NPT1_BYTES);

    /* Reserved container header is a permanent THIRD fence. */
    memcpy(g_strict_mutant, g_strict_valid_route, route_valid_len);
    g_strict_mutant[5] = 1u;
    ninlil_rrmp_route_ns_init(&route_ns);
    RRMP_CHECK(!ninlil_rrmp_route_ns_import(
        &route_ns, g_strict_mutant, route_valid_len));
    RRMP_CHECK(
        strict_assert_route_fenced(
            &route_ns, NINLIL_RRMP_CU_THIRD, route_valid_len) == 0);
    memcpy(g_strict_mutant, g_strict_valid_parent, parent_valid_len);
    g_strict_mutant[7] = 1u;
    ninlil_rrmp_parent_ns_init(&parent_ns);
    RRMP_CHECK(!ninlil_rrmp_parent_ns_import(
        &parent_ns, g_strict_mutant, parent_valid_len));
    RRMP_CHECK(
        strict_assert_parent_fenced(
            &parent_ns, NINLIL_RRMP_CU_THIRD, parent_valid_len) == 0);

    /* Raw CRC faults fail independently in each namespace. */
    memcpy(g_strict_mutant, g_strict_valid_route, route_valid_len);
    g_strict_mutant[8u + 13u + 200u] ^= 0x80u;
    ninlil_rrmp_route_ns_init(&route_ns);
    RRMP_CHECK(!ninlil_rrmp_route_ns_import(
        &route_ns, g_strict_mutant, route_valid_len));
    RRMP_CHECK_EQ(
        ninlil_rrmp_route_classify_cu(&route_ns), NINLIL_RRMP_CU_THIRD);
    memcpy(g_strict_mutant, g_strict_valid_parent, parent_valid_len);
    g_strict_mutant[8u + 13u + 200u] ^= 0x80u;
    ninlil_rrmp_parent_ns_init(&parent_ns);
    RRMP_CHECK(!ninlil_rrmp_parent_ns_import(
        &parent_ns, g_strict_mutant, parent_valid_len));
    RRMP_CHECK_EQ(
        ninlil_rrmp_parent_classify_cu(&parent_ns), NINLIL_RRMP_CU_THIRD);

    /*
     * CRC-valid semantic faults: page bytes remain codec-valid, but the
     * physical key claims a different page index.
     */
    strict_snapshot_header(g_strict_mutant, 0u, 1u);
    RRMP_CHECK(ninlil_rrmp_encode_nrp1(
        0u, 1u, NULL, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant,
        8u,
        (uint8_t)(NINLIL_RRMP_KEY_NRP1_BASE + 1u),
        1u,
        g_strict_record,
        NINLIL_RRMP_NRP1_BYTES);
    ninlil_rrmp_route_ns_init(&route_ns);
    RRMP_CHECK(!ninlil_rrmp_route_ns_import(&route_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_route_classify_cu(&route_ns), NINLIL_RRMP_CU_THIRD);
    strict_snapshot_header(g_strict_mutant, 1u, 1u);
    RRMP_CHECK(ninlil_rrmp_encode_npp1(
        0u, 1u, NULL, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant,
        8u,
        (uint8_t)(NINLIL_RRMP_PKEY_NPP1_BASE + 1u),
        1u,
        g_strict_record,
        NINLIL_RRMP_NPP1_BYTES);
    ninlil_rrmp_parent_ns_init(&parent_ns);
    RRMP_CHECK(!ninlil_rrmp_parent_ns_import(&parent_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_parent_classify_cu(&parent_ns), NINLIL_RRMP_CU_THIRD);

    /* Three images, same-generation different bytes, and reverse order. */
    strict_snapshot_header(g_strict_mutant, 0u, 3u);
    off = 8u;
    RRMP_CHECK(strict_encode_nrd1(1u, 0x51u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nrd1(2u, 0x52u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 2u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nrd1(3u, 0x53u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 3u, g_strict_record, 256u);
    ninlil_rrmp_route_ns_init(&route_ns);
    RRMP_CHECK(!ninlil_rrmp_route_ns_import(&route_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_route_classify_cu(&route_ns), NINLIL_RRMP_CU_THIRD);

    strict_snapshot_header(g_strict_mutant, 1u, 3u);
    off = 8u;
    RRMP_CHECK(strict_encode_nph1(1u, 0x61u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nph1(2u, 0x62u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 2u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nph1(3u, 0x63u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 3u, g_strict_record, 256u);
    ninlil_rrmp_parent_ns_init(&parent_ns);
    RRMP_CHECK(!ninlil_rrmp_parent_ns_import(&parent_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_parent_classify_cu(&parent_ns), NINLIL_RRMP_CU_THIRD);

    strict_snapshot_header(g_strict_mutant, 0u, 2u);
    off = 8u;
    RRMP_CHECK(strict_encode_nrd1(1u, 0x71u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nrd1(1u, 0x72u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    ninlil_rrmp_route_ns_init(&route_ns);
    RRMP_CHECK(!ninlil_rrmp_route_ns_import(&route_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_route_classify_cu(&route_ns), NINLIL_RRMP_CU_THIRD);

    strict_snapshot_header(g_strict_mutant, 1u, 2u);
    off = 8u;
    RRMP_CHECK(strict_encode_nph1(1u, 0x73u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nph1(1u, 0x74u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    ninlil_rrmp_parent_ns_init(&parent_ns);
    RRMP_CHECK(!ninlil_rrmp_parent_ns_import(&parent_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_parent_classify_cu(&parent_ns), NINLIL_RRMP_CU_THIRD);

    strict_snapshot_header(g_strict_mutant, 0u, 2u);
    off = 8u;
    RRMP_CHECK(strict_encode_nrd1(2u, 0x75u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 2u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nrd1(1u, 0x76u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    ninlil_rrmp_route_ns_init(&route_ns);
    RRMP_CHECK(!ninlil_rrmp_route_ns_import(&route_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_route_classify_cu(&route_ns), NINLIL_RRMP_CU_THIRD);

    strict_snapshot_header(g_strict_mutant, 1u, 2u);
    off = 8u;
    RRMP_CHECK(strict_encode_nph1(2u, 0x77u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 2u, g_strict_record, 256u);
    RRMP_CHECK(strict_encode_nph1(1u, 0x78u, g_strict_record));
    off = strict_snapshot_append(
        g_strict_mutant, off, 0u, 1u, g_strict_record, 256u);
    ninlil_rrmp_parent_ns_init(&parent_ns);
    RRMP_CHECK(!ninlil_rrmp_parent_ns_import(&parent_ns, g_strict_mutant, off));
    RRMP_CHECK_EQ(
        ninlil_rrmp_parent_classify_cu(&parent_ns), NINLIL_RRMP_CU_THIRD);

    return 0;
}

/*
 * Exact dual OLD/NEW retention without inject: two commits on NRD1 keep both
 * generations; export/import restarts as CU_NEW with retained OLD readable.
 */
static int test_dual_old_new_production_restart(void)
{
    ninlil_rrmp_route_ns_t ns;
    ninlil_rrmp_route_ns_t ns2;
    uint8_t *buf = NULL;
    size_t cap = 0u;
    uint64_t gen = 0u;
    uint8_t *snap = NULL;
    size_t need = 0u;
    const uint8_t *oldp = NULL;
    const uint8_t *newp = NULL;
    uint32_t oldl = 0u;
    uint32_t newl = 0u;
    uint64_t oldg = 0u;
    uint64_t newg = 0u;
    ninlil_rrmp_id16_t authority;
    uint32_t route_page_gens[NINLIL_RRMP_PAGE_COUNT];
    uint32_t evidence_page_gens[NINLIL_RRMP_NEP1_PAGE_COUNT];

    ninlil_rrmp_route_ns_init(&ns);
    rrmp_fill_id(authority.bytes, 0xA0u);
    ninlil_rrmp_memzero(route_page_gens, sizeof(route_page_gens));
    ninlil_rrmp_memzero(evidence_page_gens, sizeof(evidence_page_gens));
    RRMP_CHECK(ninlil_rrmp_route_dual_begin_write(
        &ns, NINLIL_RRMP_KEY_NRD1, &buf, &cap, &gen));
    route_page_gens[0] = 1u;
    RRMP_CHECK(ninlil_rrmp_encode_nrd1(
        gen, &authority, 1u, route_page_gens, evidence_page_gens, buf));
    RRMP_CHECK(ninlil_rrmp_route_dual_commit(
        &ns, NINLIL_RRMP_KEY_NRD1, NINLIL_RRMP_DIR_BYTES));
    RRMP_CHECK(ninlil_rrmp_route_dual_begin_write(
        &ns, NINLIL_RRMP_KEY_NRD1, &buf, &cap, &gen));
    route_page_gens[0] = 2u;
    RRMP_CHECK(ninlil_rrmp_encode_nrd1(
        gen, &authority, 2u, route_page_gens, evidence_page_gens, buf));
    RRMP_CHECK(ninlil_rrmp_route_dual_commit(
        &ns, NINLIL_RRMP_KEY_NRD1, NINLIL_RRMP_DIR_BYTES));
    RRMP_CHECK(ninlil_rrmp_route_dual_read_active(
        &ns, NINLIL_RRMP_KEY_NRD1, &newp, &newl, &newg));
    RRMP_CHECK(ninlil_rrmp_route_dual_read_retained_old(
        &ns, NINLIL_RRMP_KEY_NRD1, &oldp, &oldl, &oldg));
    RRMP_CHECK(oldg < newg);
    RRMP_CHECK(ninlil_rrmp_validate_nrd1(oldp));
    RRMP_CHECK(ninlil_rrmp_validate_nrd1(newp));
    RRMP_CHECK_EQ(ninlil_rrmp_get_u64_be(oldp + 8u), oldg);
    RRMP_CHECK_EQ(ninlil_rrmp_get_u64_be(newp + 8u), newg);
    RRMP_CHECK_EQ(ninlil_rrmp_route_classify_cu(&ns), NINLIL_RRMP_CU_NEW);

    RRMP_CHECK(ninlil_rrmp_route_ns_export(&ns, NULL, 0u, &need));
    snap = (uint8_t *)malloc(need);
    RRMP_CHECK(snap != NULL);
    RRMP_CHECK(ninlil_rrmp_route_ns_export(&ns, snap, need, &need));
    ninlil_rrmp_route_ns_init(&ns2);
    RRMP_CHECK(ninlil_rrmp_route_ns_import(&ns2, snap, need));
    RRMP_CHECK_EQ(ninlil_rrmp_route_classify_cu(&ns2), NINLIL_RRMP_CU_NEW);
    RRMP_CHECK(ninlil_rrmp_route_dual_read_retained_old(
        &ns2, NINLIL_RRMP_KEY_NRD1, &oldp, &oldl, &oldg));
    RRMP_CHECK(ninlil_rrmp_route_dual_read_active(
        &ns2, NINLIL_RRMP_KEY_NRD1, &newp, &newl, &newg));
    RRMP_CHECK(oldg < newg);
    RRMP_CHECK(ninlil_rrmp_validate_nrd1(oldp));
    RRMP_CHECK(ninlil_rrmp_validate_nrd1(newp));
    RRMP_CHECK_EQ(ninlil_rrmp_get_u64_be(oldp + 8u), oldg);
    RRMP_CHECK_EQ(ninlil_rrmp_get_u64_be(newp + 8u), newg);
    free(snap);
    return 0;
}

/* Durable restart: handoff activates → export/import → NPA1 handoff + parent set. */
static int test_handoff_durable_restart(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 1u);
    ninlil_rrmp_owner_t *o2;
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_query_req_v1_t query;
    ninlil_parent_owner_activate_req_v1_t act;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t dig;
    ninlil_rrmp_digest32_t cdig;
    uint8_t scope[16];
    uint8_t token[32];
    uint8_t *snap = NULL;
    size_t need = 0u;
    RRMP_CHECK(o != NULL);
    ninlil_rrmp_owner_bind(o);
    rrmp_fill_id(scope, 0x5Au);
    memset(token, 0x3Cu, 32u);

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    memcpy(set.owner_scope_id, scope, 16u);
    set.parent_set_count = 1u;
    rrmp_fill_id(set.path_policy_id, 0x51u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x30u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 1u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(o, &set, &out), NINLIL_PARENT_OK);

    RRMP_CHECK(rrmp_test_bootstrap_assignment_v2(o,
        scope,
        set.path_policy_id,
        dig.bytes,
        1u,
        token,
        0u,
        cdig.bytes));
    ninlil_rrmp_memzero(&query, sizeof(query));
    query.preamble.api_version = 1u;
    query.preamble.struct_size = 48u;
    memcpy(query.owner_scope_id, scope, 16u);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED);

    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, NULL, 0u, &need));
    snap = (uint8_t *)malloc(need);
    RRMP_CHECK(snap != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(o, snap, need, &need));

    o2 = mk(g_ws2, 1u, 1u);
    RRMP_CHECK(o2 != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_import_namespace(o2, snap, need));
    ninlil_rrmp_owner_bind(o2);
    ninlil_rrmp_memzero(&query, sizeof(query));
    query.preamble.api_version = 1u;
    query.preamble.struct_size = 48u;
    memcpy(query.owner_scope_id, scope, 16u);
    RRMP_CHECK_EQ(ninlil_parent_query(o2, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED);
    RRMP_CHECK_EQ(out.seal_allowed, 1u);
    /* token consumed: activate again must TOKEN_REPLAY after rehydrate */
    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = (uint32_t)sizeof(act);
    memcpy(act.owner_scope_id, scope, 16u);
    memcpy(act.commit_receipt_digest32, cdig.bytes, 32u);
    act.now_ms = 1000000u;
    RRMP_CHECK_EQ(
        ninlil_parent_owner_activate(o2, &act, &out),
        NINLIL_PARENT_TOKEN_REPLAY);

    free(snap);
    ninlil_rrmp_owner_fini(o);
    ninlil_rrmp_owner_fini(o2);
    return 0;
}

/*
 * Every handoff state S1..S6 is a platform-FULL restart boundary. In
 * particular S3 must restore the CAS digest without pretending that the S4
 * receipt/token consume already happened: the same receipt activates once,
 * and only a subsequent replay is rejected.
 */
static int test_handoff_every_state_power_cycle(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 1u);
    rrmp_ram_store_t store;
    ninlil_storage_handle_t handle = NULL;
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_activate_req_v1_t act;
    ninlil_parent_endpoint_observe_req_v1_t obs;
    ninlil_parent_owner_retire_req_v1_t ret;
    ninlil_parent_query_req_v1_t query;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t parent_digest;
    ninlil_rrmp_digest32_t commit_digest;
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    ninlil_rrmp_authority_tuple_v2_t next_tuple;
    ninlil_rrmp_bundle_witness_v2_t bundle;
    uint8_t scope[16];
    uint8_t scope2[16];
    uint8_t token[32];
    uint8_t token2[32];
    uint8_t proof[32];

    RRMP_CHECK(o != NULL);
    ram_store_init(&store);
    RRMP_CHECK_EQ(
        store.ops.open(
            store.ops.user,
            (ninlil_bytes_view_t){(const uint8_t *)"rrmp-s1-s6", 10u},
            1u,
            &handle),
        NINLIL_STORAGE_OK);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    rrmp_fill_id(scope, 0x7Au);
    memset(token, 0x6Cu, sizeof(token));
    rrmp_fill_id(ids[0].bytes, 0x42u);

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    memcpy(set.owner_scope_id, scope, sizeof(scope));
    set.parent_set_count = 1u;
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(
        ids, 1u, &parent_digest));
    memcpy(set.parent_set_digest32, parent_digest.bytes, 32u);
    rrmp_fill_id(set.path_policy_id, 0x62u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    RRMP_CHECK_EQ(
        ninlil_parent_set_install(o, &set, &out), NINLIL_PARENT_OK);

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
    noa.parent_set_digest = parent_digest;
    noa.parent_set_count = 1u;
    memcpy(noa.parent_set_id.bytes, set.path_policy_id, 16u);

    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = 464u;
    memcpy(prep.owner_scope_id, scope, 16u);
    RRMP_CHECK(ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1));
    memcpy(prep.handoff_token_digest32, token, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(o,
            &prep, &old_tuple, 1u, &new_tuple, &out),
        NINLIL_PARENT_OK);

    ninlil_rrmp_memzero(&query, sizeof(query));
    query.preamble.api_version = 1u;
    query.preamble.struct_size = 48u;
    memcpy(query.owner_scope_id, scope, 16u);
    o = restart_parent_owner(o, g_ws2, &store, handle);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step, NINLIL_RRMP_HANDOFF_PREPARED_NEW);

    /*
     * The bootstrap has no old authority. Its exact no-old proof is derived
     * deterministically and S1 commits directly; a real S2 boundary is
     * exercised by the second handoff below.
     */
    RRMP_CHECK_EQ(
        rrmp_test_owner_fence_v2(o,
            scope, token, &old_tuple, proof, &out),
        NINLIL_PARENT_OK);
    RRMP_CHECK(ram_store_witness(&store, &bundle));
    RRMP_CHECK_EQ(
        rrmp_test_authority_commit_v2(o,
            scope,
            &old_tuple,
            &new_tuple,
            token,
            proof,
            &bundle,
            0u,
            commit_digest.bytes,
            &out),
        NINLIL_PARENT_OK);

    /* Critical S3 -> cold restart -> S4 with the same exact receipt. */
    o = restart_parent_owner(o, g_ws2, &store, handle);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step, NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED);
    RRMP_CHECK_EQ(out.seal_allowed, 0u);

    ninlil_rrmp_memzero(&act, sizeof(act));
    act.preamble.api_version = 1u;
    act.preamble.struct_size = 80u;
    memcpy(act.owner_scope_id, scope, 16u);
    memcpy(act.commit_receipt_digest32, commit_digest.bytes, 32u);
    act.now_ms = 1000000u;
    RRMP_CHECK_EQ(
        ninlil_parent_owner_activate(o, &act, &out), NINLIL_PARENT_OK);

    o = restart_parent_owner(o, g_ws1, &store, handle);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step, NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED);
    RRMP_CHECK_EQ(
        ninlil_parent_owner_activate(o, &act, &out),
        NINLIL_PARENT_TOKEN_REPLAY);

    ninlil_rrmp_memzero(&obs, sizeof(obs));
    obs.preamble.api_version = 1u;
    obs.preamble.struct_size = 80u;
    memcpy(obs.owner_scope_id, scope, 16u);
    memcpy(
        obs.observed_parent_set_digest32, parent_digest.bytes, 32u);
    obs.now_ms = 1000001u;
    RRMP_CHECK_EQ(
        ninlil_parent_endpoint_observe(o, &obs, &out), NINLIL_PARENT_OK);
    o = restart_parent_owner(o, g_ws2, &store, handle);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step, NINLIL_RRMP_HANDOFF_ENDPOINT_OBSERVED);

    ninlil_rrmp_memzero(&ret, sizeof(ret));
    ret.preamble.api_version = 1u;
    ret.preamble.struct_size = 80u;
    memcpy(ret.owner_scope_id, scope, 16u);
    memcpy(ret.tombstone_digest32, token, 32u);
    ret.now_ms = 1000002u;
    RRMP_CHECK_EQ(
        ninlil_parent_owner_retire(o, &ret, &out), NINLIL_PARENT_OK);
    o = restart_parent_owner(o, g_ws1, &store, handle);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step, NINLIL_RRMP_HANDOFF_OLD_RETIRED);

    /*
     * A second assignment has an exact old authority tuple, so it must pass
     * through and durably restore the real OLD_FENCED_PROOF (S2) state.
     */
    memset(token2, 0x6Du, sizeof(token2));
    noa.assignment_revision = 2u;
    memcpy(noa.handoff_token_digest.bytes, token2, sizeof(token2));
    RRMP_CHECK(ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1));
    memcpy(prep.handoff_token_digest32, token2, sizeof(token2));
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(o,
            &prep, &new_tuple, 2u, &next_tuple, &out),
        NINLIL_PARENT_OK);
    o = restart_parent_owner(o, g_ws2, &store, handle);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step, NINLIL_RRMP_HANDOFF_PREPARED_NEW);
    RRMP_CHECK_EQ(
        rrmp_test_owner_fence_v2(o,
            scope, token2, &new_tuple, proof, &out),
        NINLIL_PARENT_OK);
    o = restart_parent_owner(o, g_ws1, &store, handle);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step, NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF);

    /*
     * Add a second NPS1-only live scope so QST omission/duplicate/zero attacks
     * exercise an actual two-row bijection rather than a count-only check.
     */
    rrmp_fill_id(scope2, 0x7Bu);
    memcpy(set.owner_scope_id, scope2, 16u);
    rrmp_fill_id(set.path_policy_id, 0x63u);
    set.assignment_epoch = 1u;
    RRMP_CHECK_EQ(
        ninlil_parent_set_install(o, &set, &out), NINLIL_PARENT_OK);
    {
        size_t attack_base_len = 0u;
        RRMP_CHECK(ram_store_logical_copy(
            &store,
            g_attack_base,
            sizeof(g_attack_base),
            &attack_base_len));
        size_t attack_len;
        uint8_t *page;
        uint32_t page_len;
        ninlil_rrmp_owner_t *probe;

        ninlil_rrmp_owner_fini(o);
        o = NULL;

        /* CRC-repaired NPA1 -> NOA1 -> NPS1 reference substitution. */
        memcpy(g_attack_work, g_attack_base, attack_base_len);
        attack_len = attack_base_len;
        RRMP_CHECK(parent_record_latest(
            g_attack_work,
            attack_len,
            NINLIL_RRMP_PKEY_NPA1_BASE,
            &page,
            &page_len));
        RRMP_CHECK_EQ(page_len, NINLIL_RRMP_NPA1_BYTES);
        RRMP_CHECK(memcmp(
            page + NINLIL_RRMP_NPA1_HEADER_BYTES, "NOA1", 4u) == 0);
        page[NINLIL_RRMP_NPA1_HEADER_BYTES + 296u] ^= 0x01u;
        ninlil_rrmp_put_u32_be(
            page + NINLIL_RRMP_NPA1_HEADER_BYTES + 256u, 0u);
        ninlil_rrmp_put_u32_be(
            page + NINLIL_RRMP_NPA1_HEADER_BYTES + 256u,
            ninlil_rrmp_crc32c_zeroed_u32_be_field(
                page + NINLIL_RRMP_NPA1_HEADER_BYTES,
                NINLIL_RRMP_NOA1_BYTES,
                256u));
        ninlil_rrmp_put_u32_be(
            page + NINLIL_RRMP_NPA1_HEADER_BYTES + 468u,
            ninlil_rrmp_crc32c(
                page + NINLIL_RRMP_NPA1_HEADER_BYTES, 468u));
        ninlil_rrmp_put_u32_be(page + 12u, 0u);
        ninlil_rrmp_put_u32_be(
            page + 12u,
            ninlil_rrmp_crc32c_zeroed_u32_be_field(
                page, NINLIL_RRMP_NPA1_BYTES, 12u));
        probe = mk(g_ws1, 1u, 1u);
        RRMP_CHECK(probe != NULL);
        RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(
            probe, g_attack_work, attack_len));
        RRMP_CHECK_EQ(
            ninlil_rrmp_owner_downlink_tx_allowed(probe), 0u);
        ninlil_rrmp_owner_fini(probe);

        /*
         * Delete every OLD/NEW physical copy of NPA1 page 7. NPH1 still says
         * bit 7 is present, so the repaired envelope must be rejected.
         */
        memcpy(g_attack_work, g_attack_base, attack_base_len);
        attack_len = attack_base_len;
        RRMP_CHECK(remove_parent_key_records(
            g_attack_work,
            &attack_len,
            (uint8_t)(NINLIL_RRMP_PKEY_NPA1_BASE +
                NINLIL_RRMP_NPA1_PAGE_COUNT - 1u)));
        probe = mk(g_ws1, 1u, 1u);
        RRMP_CHECK(probe != NULL);
        RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(
            probe, g_attack_work, attack_len));
        RRMP_CHECK_EQ(
            ninlil_rrmp_owner_downlink_tx_allowed(probe), 0u);
        ninlil_rrmp_owner_fini(probe);

        /* CRC+digest-repaired NPH1 bitmap substitution is also rejected. */
        memcpy(g_attack_work, g_attack_base, attack_base_len);
        attack_len = attack_base_len;
        RRMP_CHECK(parent_record_latest(
            g_attack_work,
            attack_len,
            NINLIL_RRMP_PKEY_NPH1,
            &page,
            &page_len));
        RRMP_CHECK_EQ(page_len, NINLIL_RRMP_NPH1_BYTES);
        page[121u] ^= 0x80u;
        ninlil_rrmp_sha256(page, 160u, page + 160u);
        ninlil_rrmp_put_u32_be(page + 192u, 0u);
        ninlil_rrmp_put_u32_be(
            page + 192u,
            ninlil_rrmp_crc32c_zeroed_u32_be_field(
                page, NINLIL_RRMP_NPH1_BYTES, 192u));
        probe = mk(g_ws1, 1u, 1u);
        RRMP_CHECK(probe != NULL);
        RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(
            probe, g_attack_work, attack_len));
        RRMP_CHECK_EQ(
            ninlil_rrmp_owner_downlink_tx_allowed(probe), 0u);
        ninlil_rrmp_owner_fini(probe);

        /* QST4: omit exactly one of two durable scope rows, repair CRC. */
        memcpy(g_attack_work, g_attack_base, attack_base_len);
        attack_len = attack_base_len;
        {
            uint8_t *soft;
            uint32_t soft_len;
            size_t soft_off;
            RRMP_CHECK(soft_region(
                g_attack_work,
                attack_len,
                &soft,
                &soft_len,
                &soft_off));
            RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 10u), 2u);
            memmove(
                soft + NINLIL_RRMP_QST4_HEADER_BYTES + 64u,
                soft + NINLIL_RRMP_QST4_HEADER_BYTES + 128u,
                attack_len -
                    (soft_off + NINLIL_RRMP_QST4_HEADER_BYTES + 128u));
            attack_len -= 64u;
            soft_len -= 64u;
            ninlil_rrmp_put_u32_be(g_attack_work + 16u, soft_len);
            ninlil_rrmp_put_u16_be(soft + 10u, 1u);
            ninlil_rrmp_put_u32_be(soft + 16u, soft_len);
            repair_soft_crc(soft, soft_len);
        }
        probe = mk(g_ws1, 1u, 1u);
        RRMP_CHECK(probe != NULL);
        RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(
            probe, g_attack_work, attack_len));
        RRMP_CHECK_EQ(
            ninlil_rrmp_owner_downlink_tx_allowed(probe), 0u);
        ninlil_rrmp_owner_fini(probe);

        /* QST4: duplicate one row in place, keeping count/length valid. */
        memcpy(g_attack_work, g_attack_base, attack_base_len);
        attack_len = attack_base_len;
        {
            uint8_t *soft;
            uint32_t soft_len;
            size_t soft_off;
            RRMP_CHECK(soft_region(
                g_attack_work,
                attack_len,
                &soft,
                &soft_len,
                &soft_off));
            (void)soft_off;
            RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 10u), 2u);
            memcpy(
                soft + NINLIL_RRMP_QST4_HEADER_BYTES + 64u,
                soft + NINLIL_RRMP_QST4_HEADER_BYTES,
                64u);
            repair_soft_crc(soft, soft_len);
        }
        probe = mk(g_ws1, 1u, 1u);
        RRMP_CHECK(probe != NULL);
        RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(
            probe, g_attack_work, attack_len));
        RRMP_CHECK_EQ(
            ninlil_rrmp_owner_downlink_tx_allowed(probe), 0u);
        ninlil_rrmp_owner_fini(probe);

        /* QST4: claim zero rows and remove both, with coherent lengths+CRC. */
        memcpy(g_attack_work, g_attack_base, attack_base_len);
        attack_len = attack_base_len;
        {
            uint8_t *soft;
            uint32_t soft_len;
            size_t soft_off;
            RRMP_CHECK(soft_region(
                g_attack_work,
                attack_len,
                &soft,
                &soft_len,
                &soft_off));
            memmove(
                soft + NINLIL_RRMP_QST4_HEADER_BYTES,
                soft + NINLIL_RRMP_QST4_HEADER_BYTES + 128u,
                attack_len -
                    (soft_off + NINLIL_RRMP_QST4_HEADER_BYTES + 128u));
            attack_len -= 128u;
            soft_len -= 128u;
            ninlil_rrmp_put_u32_be(g_attack_work + 16u, soft_len);
            ninlil_rrmp_put_u16_be(soft + 10u, 0u);
            ninlil_rrmp_put_u32_be(soft + 16u, soft_len);
            repair_soft_crc(soft, soft_len);
        }
        probe = mk(g_ws1, 1u, 1u);
        RRMP_CHECK(probe != NULL);
        RRMP_CHECK(!ninlil_rrmp_owner_import_namespace(
            probe, g_attack_work, attack_len));
        RRMP_CHECK_EQ(
            ninlil_rrmp_owner_downlink_tx_allowed(probe), 0u);
        ninlil_rrmp_owner_fini(probe);

        /*
         * QST2 compatibility is importable for migration, but its missing
         * global attempt ledger permanently fences every parent scope.
         */
        memcpy(g_attack_work, g_attack_base, attack_base_len);
        attack_len = attack_base_len;
        {
            uint8_t *soft;
            uint32_t soft_len;
            size_t soft_off;
            size_t row;
            uint32_t legacy_soft_len =
                48u + 2u * 64u;
            RRMP_CHECK(soft_region(
                g_attack_work,
                attack_len,
                &soft,
                &soft_len,
                &soft_off));
            RRMP_CHECK_EQ(soft_off + soft_len, attack_len);
            RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 12u), 0u);
            RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 14u), 0u);
            RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 50u), 0u);
            RRMP_CHECK_EQ(ninlil_rrmp_get_u16_be(soft + 52u), 1u);
            memmove(
                soft + 48u,
                soft + NINLIL_RRMP_QST4_HEADER_BYTES,
                2u * 64u);
            attack_len -= (size_t)soft_len - legacy_soft_len;
            soft_len = legacy_soft_len;
            ninlil_rrmp_put_u32_be(g_attack_work + 16u, soft_len);
            memcpy(soft, "RRMPQST2", 8u);
            ninlil_rrmp_put_u16_be(soft + 8u, 2u);
            ninlil_rrmp_put_u32_be(soft + 16u, soft_len);
            for (row = 0u; row < 2u; ++row) {
                soft[48u + row * 64u + 57u] = 0u;
            }
            repair_soft_crc(soft, soft_len);
        }
        probe = mk(g_ws1, 1u, 1u);
        RRMP_CHECK(probe != NULL);
        RRMP_CHECK(ninlil_rrmp_owner_import_namespace(
            probe, g_attack_work, attack_len));
        RRMP_CHECK(ninlil_rrmp_owner_bind(probe));
        memcpy(query.owner_scope_id, scope, 16u);
        RRMP_CHECK_EQ(
            ninlil_parent_query(probe, &query, &out),
            NINLIL_PARENT_SPLIT_BRAIN);
        RRMP_CHECK_EQ(out.seal_allowed, 0u);
        memcpy(query.owner_scope_id, scope2, 16u);
        RRMP_CHECK_EQ(
            ninlil_parent_query(probe, &query, &out),
            NINLIL_PARENT_SPLIT_BRAIN);
        RRMP_CHECK_EQ(out.seal_allowed, 0u);
        ninlil_rrmp_owner_fini(probe);
    }
    return 0;
}

/*
 * PREPARED_NEW is a real writepoint, not an in-memory prelude.  Prove both
 * COMMIT_UNKNOWN=OLD recovery and a subsequent successful platform FULL
 * surviving a cold restart.
 */
static int test_parent_prepare_platform_full_restart(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 1u);
    ninlil_rrmp_owner_t *o2;
    rrmp_ram_store_t store;
    ninlil_storage_handle_t handle = NULL;
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_query_req_v1_t query;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[1];
    ninlil_rrmp_digest32_t dig;
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    uint8_t scope[16];
    uint8_t token[32];

    RRMP_CHECK(o != NULL);
    ram_store_init(&store);
    RRMP_CHECK_EQ(store.ops.open(
                      store.ops.user,
                      (ninlil_bytes_view_t){ (const uint8_t *)"rrmp", 4u },
                      1u, &handle),
        NINLIL_STORAGE_OK);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    rrmp_fill_id(scope, 0x6Au);
    memset(token, 0x4Cu, sizeof(token));

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    memcpy(set.owner_scope_id, scope, 16u);
    set.parent_set_count = 1u;
    rrmp_fill_id(set.path_policy_id, 0x61u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x40u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    RRMP_CHECK(ninlil_rrmp_parent_set_digest(ids, 1u, &dig));
    memcpy(set.parent_set_digest32, dig.bytes, 32u);
    RRMP_CHECK_EQ(ninlil_parent_set_install(o, &set, &out), NINLIL_PARENT_OK);

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
    noa.parent_set_count = 1u;
    memcpy(noa.parent_set_id.bytes, set.path_policy_id, 16u);

    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = 464u;
    memcpy(prep.owner_scope_id, scope, 16u);
    RRMP_CHECK(ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1));
    memcpy(prep.handoff_token_digest32, token, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));

    /* OLD: mutation is fenced and must not appear after cold recovery. */
    store.force_cu = 1;
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(o,
            &prep, &old_tuple, 1u, &new_tuple, &out),
        NINLIL_PARENT_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 0u);
    /*
     * An unresolved outer COMMIT_UNKNOWN cannot expose the post-mutation RAM
     * image. Readback is fenced until a fresh exact OLD/NEW recovery.
     */
    ninlil_rrmp_memzero(&query, sizeof(query));
    query.preamble.api_version = 1u;
    query.preamble.struct_size = 48u;
    memcpy(query.owner_scope_id, scope, 16u);
    RRMP_CHECK_EQ(
        ninlil_parent_query(o, &query, &out),
        NINLIL_PARENT_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(out.handoff_step, 0u);
    RRMP_CHECK_EQ(out.seal_allowed, 0u);
    ninlil_rrmp_owner_fini(o);

    o2 = mk(g_ws2, 1u, 1u);
    RRMP_CHECK(o2 != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o2, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o2));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
    RRMP_CHECK_EQ(ninlil_parent_query(o2, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(out.handoff_step, 0u);

    /* Successful retry publishes PREPARED_NEW through platform FULL. */
    RRMP_CHECK_EQ(
        rrmp_test_owner_prepare_v2(o2,
            &prep, &old_tuple, 1u, &new_tuple, &out),
        NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_PREPARED_NEW);
    ninlil_rrmp_owner_fini(o2);

    o = mk(g_ws1, 1u, 1u);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    RRMP_CHECK_EQ(ninlil_parent_query(o, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(out.handoff_step, NINLIL_RRMP_HANDOFF_PREPARED_NEW);

    ninlil_rrmp_owner_fini(o);
    return 0;
}

/* Production storage FULL writepoint + recover restart. */
static int test_storage_full_restart(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 0u);
    ninlil_rrmp_owner_t *o2;
    rrmp_ram_store_t store;
    ninlil_storage_handle_t handle = NULL;
    ninlil_route_query_req_v1_t q;
    ninlil_route_result_v1_t out;
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(setup(o) == 0);
    ram_store_init(&store);
    RRMP_CHECK_EQ(store.ops.open(store.ops.user,
                      (ninlil_bytes_view_t){ (const uint8_t *)"rrmp", 4u }, 1u,
                      &handle),
        NINLIL_STORAGE_OK);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_commit_full(o));
    RRMP_CHECK_EQ(store.present[0], 1u);

    o2 = mk(g_ws2, 1u, 0u);
    RRMP_CHECK(o2 != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o2, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o2));
    ninlil_rrmp_owner_bind(o2);
    ninlil_rrmp_memzero(&q, sizeof(q));
    q.preamble.api_version = 1u;
    q.preamble.struct_size = 48u;
    q.ingress_hop_context_id = 0x1001u;
    q.route_handle = 1u;
    q.route_generation = 1u;
    RRMP_CHECK_EQ(ninlil_route_query(o2, &q, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(out.lifecycle_state, NINLIL_RRMP_LIFE_ACTIVE);

    /* COMMIT_UNKNOWN fences downlink. */
    store.force_cu = 1;
    RRMP_CHECK(!ninlil_rrmp_owner_storage_commit_full(o2));
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o2), 0u);

    ninlil_rrmp_owner_fini(o);
    ninlil_rrmp_owner_fini(o2);
    return 0;
}

/* Lease-boundary EXPIRED is itself a platform FULL writepoint. */
static int test_lease_expiry_platform_full_restart(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 0u);
    ninlil_rrmp_owner_t *o2;
    rrmp_ram_store_t store;
    ninlil_storage_handle_t handle = NULL;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_query_req_v1_t query;
    ninlil_route_result_v1_t out;
    size_t i;

    RRMP_CHECK(o != NULL);
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
    ram_store_init(&store);
    RRMP_CHECK_EQ(store.ops.open(
                      store.ops.user,
                      (ninlil_bytes_view_t){ (const uint8_t *)"rrmp", 4u },
                      1u, &handle),
        NINLIL_STORAGE_OK);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_commit_full(o));

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.admission_now_ms = 5000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 0xE1u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0xE0u + i);
    }

    /* OLD: do not report LEASE_EXPIRED when its durable write is unknown. */
    store.force_cu = 1;
    RRMP_CHECK_EQ(
        ninlil_route_forward_admit(o, &admit, &out),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 0u);
    ninlil_rrmp_owner_fini(o);

    o2 = mk(g_ws2, 1u, 0u);
    RRMP_CHECK(o2 != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o2, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o2));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
    ninlil_rrmp_memzero(&query, sizeof(query));
    query.preamble.api_version = 1u;
    query.preamble.struct_size = 48u;
    query.ingress_hop_context_id = 0x1001u;
    query.route_handle = 1u;
    query.route_generation = 1u;
    RRMP_CHECK_EQ(ninlil_route_query(o2, &query, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(out.lifecycle_state, NINLIL_RRMP_LIFE_ACTIVE);

    RRMP_CHECK_EQ(
        ninlil_route_forward_admit(o2, &admit, &out),
        NINLIL_ROUTE_LEASE_EXPIRED);
    ninlil_rrmp_owner_fini(o2);

    o = mk(g_ws1, 1u, 0u);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    RRMP_CHECK_EQ(ninlil_route_query(o, &query, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(out.lifecycle_state, NINLIL_RRMP_LIFE_EXPIRED);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

/*
 * Physical submit and LINK_ACK both precede a platform FULL writepoint.
 * COMMIT_UNKNOWN may therefore leave either OLD or NEW. Recovery must allow
 * semantic retransmission but must never manufacture ACK/success.
 */
static int test_tx_and_ack_commit_unknown_windows(void)
{
    ninlil_rrmp_owner_t *o = mk(g_ws1, 1u, 0u);
    ninlil_rrmp_owner_t *o2;
    rrmp_ram_store_t store;
    ninlil_storage_handle_t handle = NULL;
    rrmp_test_outbound_t outbound;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_forward_complete_req_v1_t complete;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_hop_tx_view_t tx;
    uint8_t carrier[17];
    uint64_t opaque;
    uint64_t outer_tx;
    size_t i;

    RRMP_CHECK(o != NULL);
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
    ram_store_init(&store);
    RRMP_CHECK_EQ(store.ops.open(
                      store.ops.user,
                      (ninlil_bytes_view_t){ (const uint8_t *)"rrmp", 4u },
                      1u, &handle),
        NINLIL_STORAGE_OK);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_commit_full(o));
    rrmp_install_test_outbound(o, &outbound);

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = 128u;
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 0xCAFEu;
    admit.outer_rx_counter = 40u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0x90u + i);
    }
    memcpy(carrier, "cu-window-carrier", sizeof(carrier));
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_forward_admit_with_carrier(
            o, &admit, carrier, (uint16_t)sizeof(carrier), NULL, &out),
        NINLIL_ROUTE_OK);
    opaque = out.opaque_local_handle;

    /* Provider accepted, but durable TX state remains OLD. */
    store.force_cu = 1;
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_hop_forward_execute(
            o, opaque, NULL, 0u, 1u, &tx),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(outbound.submit_count, 1u);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 0u);
    ninlil_rrmp_owner_fini(o);

    o2 = mk(g_ws2, 1u, 0u);
    RRMP_CHECK(o2 != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o2, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o2));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
    rrmp_install_test_outbound(o2, &outbound);

    ninlil_rrmp_memzero(&complete, sizeof(complete));
    complete.preamble.api_version = 1u;
    complete.preamble.struct_size = 64u;
    complete.opaque_local_handle = opaque;
    complete.outcome = 1u;
    complete.completion_now_ms = 1000000u;
    RRMP_CHECK_EQ(
        ninlil_route_forward_complete(o2, &complete, &out),
        NINLIL_ROUTE_AUTHORITY_CONFLICT);

    /* At-least-once semantic retransmission carries identical copy-owned bytes. */
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_hop_forward_execute(
            o2, opaque, NULL, 0u, 1u, &tx),
        NINLIL_ROUTE_OK);
    RRMP_CHECK(tx.carrier_set && tx.payload_len == sizeof(carrier));
    RRMP_CHECK(memcmp(tx.payload, carrier, sizeof(carrier)) == 0);
    outer_tx = tx.outer_tx_counter;

    /* ACK mutation is not durable: restart recovers await-ACK, not success. */
    store.force_cu = 1;
    RRMP_CHECK_EQ(
        rrmp_auth_link_ack(o2, opaque, outer_tx, &out),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    ninlil_rrmp_owner_fini(o2);

    o = mk(g_ws1, 1u, 0u);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o));
    RRMP_CHECK_EQ(
        ninlil_route_forward_complete(o, &complete, &out),
        NINLIL_ROUTE_AUTHORITY_CONFLICT);

    /* ACK mutation is durable but return is unknown: duplicate ACK is idempotent. */
    store.force_cu_apply = 1;
    RRMP_CHECK_EQ(
        rrmp_auth_link_ack(o, opaque, outer_tx, &out),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    ninlil_rrmp_owner_fini(o);

    o2 = mk(g_ws2, 1u, 0u);
    RRMP_CHECK(o2 != NULL);
    RRMP_CHECK(ninlil_rrmp_owner_bind_storage(o2, &store.ops, handle));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(o2));
    RRMP_CHECK(ninlil_rrmp_owner_bind(o2));
    RRMP_CHECK_EQ(
        rrmp_auth_link_ack(o2, opaque, outer_tx, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(
        ninlil_route_forward_complete(o2, &complete, &out), NINLIL_ROUTE_OK);

    ninlil_rrmp_owner_fini(o2);
    return 0;
}

int main(void)
{
    if (test_restart_rehydrate() != 0) {
        return 1;
    }
    if (test_dual_inject() != 0) {
        return 1;
    }
    if (test_cu_classes() != 0) {
        return 1;
    }
    if (test_dual_old_new_production_restart() != 0) {
        return 1;
    }
    if (test_strict_namespace_import() != 0) {
        return 1;
    }
    if (test_owner_cu_old_recover() != 0) {
        return 1;
    }
    if (test_storage_full_restart() != 0) {
        return 1;
    }
    if (test_lease_expiry_platform_full_restart() != 0) {
        return 1;
    }
    if (test_tx_and_ack_commit_unknown_windows() != 0) {
        return 1;
    }
    if (test_parent_prepare_platform_full_restart() != 0) {
        return 1;
    }
    if (test_handoff_durable_restart() != 0) {
        return 1;
    }
    if (test_handoff_every_state_power_cycle() != 0) {
        return 1;
    }
    printf("rrmp_crash_corrupt_test OK\n");
    return 0;
}
