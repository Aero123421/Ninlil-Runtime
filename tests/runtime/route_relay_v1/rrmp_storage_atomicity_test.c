/* SPDX-License-Identifier: Apache-2.0 */
#include "rrmp_test_common.h"

#include "ninlil/platform.h"

#include <stdlib.h>

enum {
    RRMP_TEST_STORE_MAX = NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX,
    RRMP_TEST_PIECES = 6,
    RRMP_TEST_PIECE_MAX = NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX,
    RRMP_TEST_WS_MAX = NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES
};

enum test_fault {
    TEST_FAULT_NONE = 0,
    TEST_FAULT_BEGIN,
    TEST_FAULT_GET,
    TEST_FAULT_PUT,
    TEST_FAULT_COMMIT
};

enum test_cas_mode {
    TEST_CAS_NORMAL = 0,
    TEST_CAS_DEFINITE,
    TEST_CAS_CU_OLD,
    TEST_CAS_CU_NEW
};

typedef struct test_store {
    uint8_t present[RRMP_TEST_PIECES];
    uint8_t value[RRMP_TEST_PIECES][RRMP_TEST_PIECE_MAX];
    uint32_t value_len[RRMP_TEST_PIECES];
    uint32_t fault;
    uint32_t cas_mode;
    uint32_t recovery_override;
    uint32_t cas_successes;
    struct ninlil_rrmp_owner *reenter_owner;
    uint16_t reenter_route_handle;
    uint32_t reenter_expected_status;
    uint32_t reenter_status;
    uint8_t reenter_once;
    uint8_t reenter_lifecycle_probe;
    uint8_t reenter_succeeded;
    uint8_t pending;
    ninlil_rrmp_bundle_witness_v2_t pending_old;
    ninlil_rrmp_bundle_witness_v2_t pending_new;
    ninlil_storage_ops_t ops;
    ninlil_rrmp_storage_authority_v2_t authority;
} test_store_t;

typedef struct test_txn {
    test_store_t *store;
    ninlil_storage_mode_t mode;
    uint8_t present[RRMP_TEST_PIECES];
    uint8_t value[RRMP_TEST_PIECES][RRMP_TEST_PIECE_MAX];
    uint32_t value_len[RRMP_TEST_PIECES];
    uint8_t dirty;
    uint8_t iter_index;
} test_txn_t;

_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_ws1[RRMP_TEST_WS_MAX];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_ws2[RRMP_TEST_WS_MAX];
_Alignas(NINLIL_RRMP_OWNER_WORKSPACE_ALIGN)
static uint8_t g_ws3[RRMP_TEST_WS_MAX];
static test_store_t g_store;
static test_store_t g_staged_store;
static uint8_t g_before[RRMP_TEST_STORE_MAX];
static uint8_t g_after[RRMP_TEST_STORE_MAX];

static void fill_install(
    ninlil_route_install_batch_req_v1_t *req, uint16_t handle);

static int test_key_kind(ninlil_bytes_view_t key)
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

static ninlil_storage_status_t test_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    (void)storage_namespace;
    (void)expected_schema;
    if (user == NULL || out_handle == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out_handle = (ninlil_storage_handle_t)user;
    return NINLIL_STORAGE_OK;
}

static void test_close(void *user, ninlil_storage_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_storage_status_t test_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    test_store_t *s = (test_store_t *)user;
    test_txn_t *t;
    (void)handle;
    if (s == NULL || out_txn == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (s->fault == TEST_FAULT_BEGIN) {
        s->fault = TEST_FAULT_NONE;
        return NINLIL_STORAGE_IO_ERROR;
    }
    t = (test_txn_t *)calloc(1u, sizeof(*t));
    if (t == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    t->store = s;
    t->mode = mode;
    memcpy(t->present, s->present, sizeof(t->present));
    memcpy(t->value, s->value, sizeof(t->value));
    memcpy(t->value_len, s->value_len, sizeof(t->value_len));
    *out_txn = (ninlil_storage_txn_t)t;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t test_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    test_txn_t *t = (test_txn_t *)txn;
    test_store_t *s = (test_store_t *)user;
    int kind = test_key_kind(key);
    if (t == NULL || s == NULL || inout_value == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (s->fault == TEST_FAULT_GET) {
        s->fault = TEST_FAULT_NONE;
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (kind < 0 || !t->present[kind]) {
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

static ninlil_storage_status_t test_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    test_txn_t *t = (test_txn_t *)txn;
    test_store_t *s = (test_store_t *)user;
    int kind = test_key_kind(key);
    if (t == NULL || s == NULL || t->mode != NINLIL_STORAGE_READ_WRITE ||
        kind < 0 ||
        value.data == NULL || value.length == 0u ||
        value.length > RRMP_TEST_PIECE_MAX) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (s->fault == TEST_FAULT_PUT) {
        s->fault = TEST_FAULT_NONE;
        return NINLIL_STORAGE_IO_ERROR;
    }
    memcpy(t->value[kind], value.data, value.length);
    t->value_len[kind] = value.length;
    t->present[kind] = 1u;
    t->dirty = 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t test_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    test_txn_t *t = (test_txn_t *)txn;
    int kind = test_key_kind(key);
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

static ninlil_storage_status_t test_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    test_txn_t *t = (test_txn_t *)txn;
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

static ninlil_storage_status_t test_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    test_txn_t *t = (test_txn_t *)iter;
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

static void test_iter_close(void *user, ninlil_storage_iter_t iter)
{
    (void)user;
    (void)iter;
}

static ninlil_storage_status_t test_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out)
{
    (void)user;
    (void)handle;
    (void)out;
    return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}

static ninlil_storage_status_t test_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t durability)
{
    test_txn_t *t = (test_txn_t *)txn;
    test_store_t *s = (test_store_t *)user;
    if (t == NULL || s == NULL || durability != NINLIL_DURABILITY_FULL) {
        free(t);
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (s->fault == TEST_FAULT_COMMIT) {
        s->fault = TEST_FAULT_NONE;
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

static ninlil_storage_status_t test_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    (void)user;
    free(txn);
    return NINLIL_STORAGE_OK;
}

static int witness_equal(
    const ninlil_rrmp_bundle_witness_v2_t *a,
    const ninlil_rrmp_bundle_witness_v2_t *b)
{
    if (a == NULL || b == NULL || a->present != b->present) {
        return 0;
    }
    if (!a->present) {
        return a->logical_length == 0u &&
            b->logical_length == 0u &&
            !memcmp(a->manifest_rrm1, b->manifest_rrm1,
                NINLIL_RRMP_RRM1_BYTES) &&
            !memcmp(a->logical_sha256, b->logical_sha256, 32u);
    }
    return a->logical_length == b->logical_length &&
        ninlil_rrmp_memeq(
            a->manifest_rrm1,
            b->manifest_rrm1,
            NINLIL_RRMP_RRM1_BYTES) &&
        ninlil_rrmp_memeq(
            a->logical_sha256, b->logical_sha256, 32u);
}

static int test_store_logical_copy(
    const test_store_t *s,
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
    if (s == NULL || out == NULL || out_length == NULL) {
        return 0;
    }
    if (!s->present[0]) {
        for (i = 1u; i < RRMP_TEST_PIECES; ++i) {
            if (s->present[i]) {
                return 0;
            }
        }
        *out_length = 0u;
        return 1;
    }
    if (s->value_len[0] != NINLIL_RRMP_RRM1_BYTES) {
        return 0;
    }
    manifest = s->value[0];
    logical_length = ninlil_rrmp_get_u32_be(manifest + 16u);
    chunk_count = manifest[20u];
    if (memcmp(manifest, "RRM1", 4u) != 0 ||
        ninlil_rrmp_get_u16_be(manifest + 4u) != 1u ||
        ninlil_rrmp_get_u16_be(manifest + 6u) !=
            NINLIL_RRMP_RRM1_BYTES ||
        logical_length == 0u ||
        logical_length > out_capacity ||
        chunk_count == 0u ||
        chunk_count > NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX ||
        ninlil_rrmp_get_u32_be(manifest + 252u) !=
            ninlil_rrmp_crc32c_zeroed_u32_be_field(
                manifest, NINLIL_RRMP_RRM1_BYTES, 252u)) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX; ++i) {
        uint32_t length = i < chunk_count
            ? ninlil_rrmp_get_u32_be(
                manifest + 56u + (size_t)i * 36u)
            : 0u;
        if (i < chunk_count) {
            if (!s->present[(size_t)i + 1u] ||
                s->value_len[(size_t)i + 1u] != length ||
                copied + length > logical_length) {
                return 0;
            }
            ninlil_rrmp_sha256(
                s->value[(size_t)i + 1u], length, digest);
            if (!ninlil_rrmp_memeq(
                    digest,
                    manifest + 60u + (size_t)i * 36u,
                    32u)) {
                return 0;
            }
            memcpy(out + copied, s->value[(size_t)i + 1u], length);
            copied += length;
        } else if (s->present[(size_t)i + 1u]) {
            return 0;
        }
    }
    if (copied != logical_length) {
        return 0;
    }
    ninlil_rrmp_sha256(out, logical_length, digest);
    if (!ninlil_rrmp_memeq(digest, manifest + 24u, 32u)) {
        return 0;
    }
    *out_length = logical_length;
    return 1;
}

static int test_store_witness(
    const test_store_t *s,
    ninlil_rrmp_bundle_witness_v2_t *out)
{
    size_t logical_length = 0u;
    if (s == NULL || out == NULL ||
        !test_store_logical_copy(
            s, g_after, sizeof(g_after), &logical_length)) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    if (logical_length == 0u) {
        return 1;
    }
    out->present = 1u;
    memcpy(
        out->manifest_rrm1,
        s->value[0],
        NINLIL_RRMP_RRM1_BYTES);
    out->logical_length = (uint32_t)logical_length;
    memcpy(out->logical_sha256, s->value[0] + 24u, 32u);
    return 1;
}

static int desired_piece_vector_apply(
    test_store_t *s,
    const ninlil_rrmp_storage_piece_v2_t *pieces,
    uint32_t piece_count,
    const ninlil_rrmp_bundle_witness_v2_t *desired)
{
    uint8_t seen[RRMP_TEST_PIECES];
    uint32_t i;
    ninlil_rrmp_memzero(seen, sizeof(seen));
    if (s == NULL || pieces == NULL || desired == NULL ||
        piece_count != RRMP_TEST_PIECES || !desired->present) {
        return 0;
    }
    for (i = 0u; i < piece_count; ++i) {
        ninlil_bytes_view_t key;
        int kind;
        key.data = pieces[i].key;
        key.length = pieces[i].key_length;
        kind = test_key_kind(key);
        if (kind < 0 || seen[kind] ||
            memcmp(
                pieces[i].reserved0,
                (const uint8_t[7]){0},
                7u) != 0 ||
            pieces[i].present > 1u ||
            (pieces[i].present &&
                (pieces[i].value == NULL ||
                    pieces[i].value_length == 0u ||
                    pieces[i].value_length >
                        RRMP_TEST_PIECE_MAX)) ||
            (!pieces[i].present &&
                (pieces[i].value != NULL ||
                    pieces[i].value_length != 0u))) {
            return 0;
        }
        seen[kind] = 1u;
    }
    for (i = 0u; i < RRMP_TEST_PIECES; ++i) {
        if (!seen[i]) {
            return 0;
        }
    }
    for (i = 0u; i < piece_count; ++i) {
        ninlil_bytes_view_t key;
        int kind;
        key.data = pieces[i].key;
        key.length = pieces[i].key_length;
        kind = test_key_kind(key);
        s->present[kind] = pieces[i].present;
        s->value_len[kind] = pieces[i].value_length;
        if (pieces[i].present) {
            memcpy(
                s->value[kind],
                pieces[i].value,
                pieces[i].value_length);
        }
    }
    {
        ninlil_rrmp_bundle_witness_v2_t observed;
        return test_store_witness(s, &observed) &&
            witness_equal(&observed, desired);
    }
}

static uint32_t test_compare_exchange(
    void *user,
    void *handle,
    const ninlil_rrmp_bundle_witness_v2_t *expected,
    const ninlil_rrmp_storage_piece_v2_t *desired_pieces,
    uint32_t desired_piece_count,
    const ninlil_rrmp_bundle_witness_v2_t *desired)
{
    test_store_t *s = (test_store_t *)user;
    ninlil_rrmp_bundle_witness_v2_t current;
    (void)handle;
    if (s == NULL || expected == NULL || desired == NULL ||
        !test_store_witness(s, &current) ||
        !witness_equal(&current, expected)) {
        return s != NULL && expected != NULL
            ? NINLIL_RRMP_STORAGE_CAS_EXPECTED_MISMATCH
            : NINLIL_RRMP_STORAGE_CAS_CORRUPT;
    }
    if (s->cas_mode == TEST_CAS_DEFINITE) {
        s->cas_mode = TEST_CAS_NORMAL;
        return NINLIL_RRMP_STORAGE_CAS_DEFINITE_FAILURE;
    }
    if (s->reenter_once) {
        ninlil_route_install_batch_req_v1_t nested_req;
        ninlil_route_result_v1_t nested_out;
        ninlil_rrmp_owner_t *nested_owner = s->reenter_owner;
        uint16_t nested_handle = s->reenter_route_handle;
        s->reenter_once = 0u;
        if (nested_owner == NULL) {
            return NINLIL_RRMP_STORAGE_CAS_CORRUPT;
        }
        if (s->reenter_expected_status == NINLIL_ROUTE_OK &&
            !ninlil_rrmp_owner_bind(nested_owner)) {
            return NINLIL_RRMP_STORAGE_CAS_CORRUPT;
        }
        fill_install(&nested_req, nested_handle);
        s->reenter_status = ninlil_route_install_batch(
            nested_owner, &nested_req, &nested_out);
        if (s->reenter_status != s->reenter_expected_status) {
            return NINLIL_RRMP_STORAGE_CAS_CORRUPT;
        }
        if (s->reenter_lifecycle_probe) {
            if (ninlil_rrmp_owner_bind(nested_owner)) {
                return NINLIL_RRMP_STORAGE_CAS_CORRUPT;
            }
            ninlil_rrmp_owner_unbind(nested_owner);
            ninlil_rrmp_owner_fini(nested_owner);
            if (ninlil_route_install_batch(
                    nested_owner, &nested_req, &nested_out) !=
                    NINLIL_ROUTE_REENTRANT) {
                return NINLIL_RRMP_STORAGE_CAS_CORRUPT;
            }
        }
        s->reenter_succeeded = 1u;
    }
    g_staged_store = *s;
    if (!desired_piece_vector_apply(
            &g_staged_store,
            desired_pieces,
            desired_piece_count,
            desired)) {
        return NINLIL_RRMP_STORAGE_CAS_CORRUPT;
    }
    if (s->cas_mode == TEST_CAS_CU_OLD ||
        s->cas_mode == TEST_CAS_CU_NEW) {
        uint32_t mode = s->cas_mode;
        s->cas_mode = TEST_CAS_NORMAL;
        s->pending = 1u;
        s->pending_old = current;
        s->pending_new = *desired;
        if (mode == TEST_CAS_CU_NEW) {
            memcpy(
                s->present,
                g_staged_store.present,
                sizeof(s->present));
            memcpy(s->value, g_staged_store.value, sizeof(s->value));
            memcpy(
                s->value_len,
                g_staged_store.value_len,
                sizeof(s->value_len));
        }
        return NINLIL_RRMP_STORAGE_CAS_COMMIT_UNKNOWN;
    }
    memcpy(s->present, g_staged_store.present, sizeof(s->present));
    memcpy(s->value, g_staged_store.value, sizeof(s->value));
    memcpy(
        s->value_len,
        g_staged_store.value_len,
        sizeof(s->value_len));
    s->cas_successes += 1u;
    return NINLIL_RRMP_STORAGE_CAS_OK;
}

static uint32_t test_recover_pending(
    void *user,
    void *handle,
    const ninlil_rrmp_bundle_witness_v2_t *old_witness,
    const ninlil_rrmp_bundle_witness_v2_t *new_witness,
    uint32_t *out_classification)
{
    test_store_t *s = (test_store_t *)user;
    ninlil_rrmp_bundle_witness_v2_t current;
    (void)handle;
    if (s == NULL || old_witness == NULL || new_witness == NULL ||
        out_classification == NULL || !s->pending ||
        !witness_equal(old_witness, &s->pending_old) ||
        !witness_equal(new_witness, &s->pending_new) ||
        !test_store_witness(s, &current)) {
        return NINLIL_RRMP_STORAGE_CAS_CORRUPT;
    }
    if (s->recovery_override != NINLIL_RRMP_STORAGE_RECOVERY_NONE) {
        *out_classification = s->recovery_override;
        return NINLIL_RRMP_STORAGE_CAS_OK;
    }
    if (witness_equal(&current, old_witness)) {
        *out_classification = NINLIL_RRMP_STORAGE_RECOVERY_OLD;
    } else if (witness_equal(&current, new_witness)) {
        *out_classification = NINLIL_RRMP_STORAGE_RECOVERY_NEW;
    } else {
        *out_classification = NINLIL_RRMP_STORAGE_RECOVERY_THIRD;
    }
    s->pending = 0u;
    return NINLIL_RRMP_STORAGE_CAS_OK;
}

static void test_store_init(test_store_t *s)
{
    ninlil_rrmp_memzero(s, sizeof(*s));
    s->ops.abi_version = NINLIL_ABI_VERSION;
    s->ops.struct_size = (uint32_t)sizeof(s->ops);
    s->ops.user = s;
    s->ops.open = test_open;
    s->ops.close = test_close;
    s->ops.begin = test_begin;
    s->ops.get = test_get;
    s->ops.put = test_put;
    s->ops.erase = test_erase;
    s->ops.iter_open = test_iter_open;
    s->ops.iter_next = test_iter_next;
    s->ops.iter_close = test_iter_close;
    s->ops.capacity = test_capacity;
    s->ops.commit = test_commit;
    s->ops.rollback = test_rollback;
    s->authority.api_version = NINLIL_RRMP_STORAGE_AUTHORITY_V2;
    s->authority.struct_size = (uint32_t)sizeof(s->authority);
    s->authority.isolation =
        NINLIL_RRMP_STORAGE_AUTHORITY_SERIALIZABLE_PIECE_VECTOR;
    s->authority.user = s;
    s->authority.compare_exchange_bundle_full = test_compare_exchange;
    s->authority.recover_pending_bundle_full = test_recover_pending;
}

static ninlil_rrmp_owner_t *make_owner(
    uint8_t *ws, uint8_t route_on, uint8_t parent_on)
{
    return rrmp_mk_ws(
        ws, ninlil_rrmp_owner_workspace_bytes(), route_on, parent_on);
}

static int bind_standard(ninlil_rrmp_owner_t *o, test_store_t *s)
{
    return ninlil_rrmp_owner_bind_storage(o, &s->ops, s);
}

static int bind_authority(ninlil_rrmp_owner_t *o, test_store_t *s)
{
    return ninlil_rrmp_owner_bind_storage_authority_v2(
        o, &s->ops, s, &s->authority);
}

static void fill_install(
    ninlil_route_install_batch_req_v1_t *req, uint16_t handle)
{
    ninlil_rrmp_nrm1_fields_t f;
    uint8_t raw[NINLIL_RRMP_NRM1_BYTES];
    ninlil_rrmp_memzero(req, sizeof(*req));
    req->preamble.api_version = 1u;
    req->preamble.struct_size = 312u;
    rrmp_fill_id(req->authority_id, 0xA0u);
    req->controller_term = 5u;
    req->batch_id = handle;
    req->entry_count = 1u;
    rrmp_fill_nrm1(&f, handle, 1u, 1u);
    if (ninlil_rrmp_encode_nrm1(&f, raw)) {
        memcpy(req->entries, raw, sizeof(raw));
    }
}

static void fill_route_query(
    ninlil_route_query_req_v1_t *q, uint16_t handle)
{
    ninlil_rrmp_memzero(q, sizeof(*q));
    q->preamble.api_version = 1u;
    q->preamble.struct_size = 48u;
    q->ingress_hop_context_id = 0x1000u + handle;
    q->route_handle = handle;
    q->route_generation = 1u;
}

static int test_definite_failures_restore_exact_old(void)
{
    uint32_t faults[] = {
        TEST_FAULT_BEGIN,
        TEST_FAULT_GET,
        TEST_FAULT_PUT,
        TEST_FAULT_COMMIT
    };
    size_t fi;
    for (fi = 0u; fi < sizeof(faults) / sizeof(faults[0]); ++fi) {
        ninlil_rrmp_owner_t *o;
        ninlil_route_install_batch_req_v1_t install;
        ninlil_route_query_req_v1_t query;
        ninlil_route_result_v1_t out;
        ninlil_rrmp_bundle_witness_v2_t old_witness;
        ninlil_rrmp_bundle_witness_v2_t after_witness;
        size_t old_export_len = 0u;
        size_t after_export_len = 0u;

        test_store_init(&g_store);
        o = make_owner(g_ws1, 1u, 0u);
        RRMP_CHECK(o != NULL);
        RRMP_CHECK(bind_standard(o, &g_store));
        RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
        RRMP_CHECK(test_store_witness(&g_store, &old_witness));
        RRMP_CHECK_EQ(old_witness.present, 1u);
        RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
            o, NULL, 0u, &old_export_len));
        RRMP_CHECK(old_export_len <= sizeof(g_after));
        RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
            o, g_after, sizeof(g_after), &old_export_len));

        g_store.fault = faults[fi];
        fill_install(&install, 2u);
        RRMP_CHECK_EQ(
            ninlil_route_install_batch(o, &install, &out),
            NINLIL_ROUTE_CORRUPT);
        RRMP_CHECK(test_store_witness(&g_store, &after_witness));
        RRMP_CHECK(witness_equal(&after_witness, &old_witness));
        RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
            o, NULL, 0u, &after_export_len));
        RRMP_CHECK_EQ(after_export_len, old_export_len);
        RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
            o, g_before, sizeof(g_before), &after_export_len));
        RRMP_CHECK(memcmp(g_before, g_after, old_export_len) == 0);

        ninlil_rrmp_owner_bind(o);
        fill_route_query(&query, 1u);
        RRMP_CHECK_EQ(ninlil_route_query(o, &query, &out), NINLIL_ROUTE_OK);
        fill_route_query(&query, 2u);
        RRMP_CHECK_EQ(
            ninlil_route_query(o, &query, &out),
            NINLIL_ROUTE_NOT_ACTIVE);
        RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 1u);
        ninlil_rrmp_owner_fini(o);
    }
    return 0;
}

static int test_standard_stale_owner_rejected(void)
{
    ninlil_rrmp_owner_t *seed;
    ninlil_rrmp_owner_t *a;
    ninlil_rrmp_owner_t *b;
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_result_v1_t out;
    ninlil_rrmp_bundle_witness_v2_t after_a;
    ninlil_rrmp_bundle_witness_v2_t after_b;

    test_store_init(&g_store);
    seed = make_owner(g_ws1, 1u, 0u);
    RRMP_CHECK(seed != NULL);
    RRMP_CHECK(bind_standard(seed, &g_store));
    RRMP_CHECK(rrmp_install_activate(seed, 1u, 1u, 1u) == 0);
    ninlil_rrmp_owner_fini(seed);

    a = make_owner(g_ws1, 1u, 0u);
    b = make_owner(g_ws2, 1u, 0u);
    RRMP_CHECK(a != NULL && b != NULL);
    RRMP_CHECK(bind_standard(a, &g_store));
    RRMP_CHECK(bind_standard(b, &g_store));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(a));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(b));

    ninlil_rrmp_owner_bind(a);
    fill_install(&install, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(a, &install, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK(test_store_witness(&g_store, &after_a));

    ninlil_rrmp_owner_bind(b);
    fill_install(&install, 3u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(b, &install, &out),
        NINLIL_ROUTE_AUTHORITY_CONFLICT);
    RRMP_CHECK(test_store_witness(&g_store, &after_b));
    RRMP_CHECK(witness_equal(&after_a, &after_b));
    ninlil_rrmp_owner_fini(a);
    ninlil_rrmp_owner_fini(b);
    return 0;
}

static int bytes_all_zero(const uint8_t *bytes, size_t length)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int test_two_owner_storage_scratch_isolation_and_fini_zeroize(void)
{
    test_store_t store_a;
    test_store_t store_b;
    ninlil_rrmp_owner_t *owner_a;
    ninlil_rrmp_owner_t *owner_b;
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_query_req_v1_t query;
    ninlil_route_result_v1_t out;
    size_t workspace_bytes = ninlil_rrmp_owner_workspace_bytes();

    test_store_init(&store_a);
    test_store_init(&store_b);
    owner_a = make_owner(g_ws1, 1u, 0u);
    owner_b = make_owner(g_ws2, 1u, 0u);
    RRMP_CHECK(owner_a != NULL && owner_b != NULL);
    RRMP_CHECK(bind_authority(owner_a, &store_a));
    RRMP_CHECK(bind_authority(owner_b, &store_b));
    RRMP_CHECK(rrmp_install_activate(owner_a, 1u, 1u, 1u) == 0);
    RRMP_CHECK(rrmp_install_activate(owner_b, 100u, 1u, 1u) == 0);

    /*
     * Re-enter owner B from owner A's compare-and-exchange callback before
     * owner A copies its desired piece vector. A process-global scratch
     * buffer is overwritten here; owner-local scratch keeps both commits
     * exact and independently queryable.
     */
    store_a.reenter_owner = owner_b;
    store_a.reenter_route_handle = 101u;
    store_a.reenter_expected_status = NINLIL_ROUTE_OK;
    store_a.reenter_once = 1u;
    RRMP_CHECK(ninlil_rrmp_owner_bind(owner_a));
    fill_install(&install, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(owner_a, &install, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(store_a.reenter_succeeded, 1u);

    /* Same-owner callback reentry and lifecycle calls are mutation-free. */
    store_a.reenter_owner = owner_a;
    store_a.reenter_route_handle = 102u;
    store_a.reenter_expected_status = NINLIL_ROUTE_REENTRANT;
    store_a.reenter_status = NINLIL_ROUTE_OK;
    store_a.reenter_lifecycle_probe = 1u;
    store_a.reenter_succeeded = 0u;
    store_a.reenter_once = 1u;
    fill_install(&install, 3u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(owner_a, &install, &out), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(store_a.reenter_succeeded, 1u);
    RRMP_CHECK_EQ(store_a.reenter_status, NINLIL_ROUTE_REENTRANT);

    fill_route_query(&query, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_query(owner_a, &query, &out), NINLIL_ROUTE_OK);
    fill_route_query(&query, 3u);
    RRMP_CHECK_EQ(
        ninlil_route_query(owner_a, &query, &out), NINLIL_ROUTE_OK);
    fill_route_query(&query, 102u);
    RRMP_CHECK_EQ(
        ninlil_route_query(owner_a, &query, &out), NINLIL_ROUTE_NOT_ACTIVE);
    RRMP_CHECK(ninlil_rrmp_owner_bind(owner_b));
    fill_route_query(&query, 101u);
    RRMP_CHECK_EQ(
        ninlil_route_query(owner_b, &query, &out), NINLIL_ROUTE_OK);

    ninlil_rrmp_owner_fini(owner_a);
    ninlil_rrmp_owner_fini(owner_b);
    RRMP_CHECK(bytes_all_zero(g_ws1, workspace_bytes));
    RRMP_CHECK(bytes_all_zero(g_ws2, workspace_bytes));
    return 0;
}

typedef struct parent_precommit_case {
    uint8_t scope[16];
    uint8_t token[32];
    uint8_t proof[32];
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    ninlil_rrmp_bundle_witness_v2_t bundle;
} parent_precommit_case_t;

typedef struct active_two_parent_case {
    uint8_t scope[16];
    uint8_t token[32];
    uint8_t path_policy[16];
    ninlil_rrmp_digest32_t parent_digest;
} active_two_parent_case_t;

static int setup_active_two_parent_scope(
    ninlil_rrmp_owner_t *o,
    test_store_t *store,
    active_two_parent_case_t *pc)
{
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_owner_activate_req_v1_t activate;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t ids[2];
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_rrmp_authority_tuple_v2_t old_tuple;
    ninlil_rrmp_authority_tuple_v2_t new_tuple;
    ninlil_rrmp_bundle_witness_v2_t expected_bundle;
    ninlil_rrmp_scope_derivation_ctx_t scope_ctx;
    uint8_t proof[32];
    uint8_t commit_digest[32];
    if (o == NULL || store == NULL || pc == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(pc, sizeof(*pc));
    rrmp_fill_id(pc->path_policy, 0x80u);
    if (!rrmp_derive_scope_for_path_policy(pc->path_policy, pc->scope)) {
        return 0;
    }
    memset(pc->token, 0x76, sizeof(pc->token));
    rrmp_default_scope_derivation(&scope_ctx);
    ninlil_rrmp_owner_set_scope_derivation(o, &scope_ctx);
    if (rrmp_install_activate(o, 1u, 1u, 1u) != 0) {
        return 0;
    }

    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = (uint32_t)sizeof(set);
    memcpy(set.owner_scope_id, pc->scope, 16u);
    memcpy(set.path_policy_id, pc->path_policy, 16u);
    set.parent_set_count = 2u;
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(ids[0].bytes, 0x31u);
    rrmp_fill_id(ids[1].bytes, 0x41u);
    memcpy(set.parent_runtime_id[0], ids[0].bytes, 16u);
    memcpy(set.parent_runtime_id[1], ids[1].bytes, 16u);
    if (!ninlil_rrmp_parent_set_digest(ids, 2u, &pc->parent_digest)) {
        return 0;
    }
    memcpy(
        set.parent_set_digest32, pc->parent_digest.bytes, 32u);
    ninlil_rrmp_owner_bind(o);
    if (ninlil_parent_set_install(o, &set, &out) != NINLIL_PARENT_OK) {
        return 0;
    }

    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, pc->scope, 16u);
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
    memset(noa.e2e_binding_digest.bytes, 0xE1, 32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memcpy(noa.handoff_token_digest.bytes, pc->token, 32u);
    noa.parent_set_digest = pc->parent_digest;
    noa.parent_set_count = 2u;
    memcpy(noa.parent_set_id.bytes, pc->path_policy, 16u);

    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = (uint32_t)sizeof(prep);
    memcpy(prep.owner_scope_id, pc->scope, 16u);
    if (!ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1)) {
        return 0;
    }
    memcpy(prep.handoff_token_digest32, pc->token, 32u);
    ninlil_rrmp_memzero(&old_tuple, sizeof(old_tuple));
    if (rrmp_test_owner_prepare_v2(o,
            &prep, &old_tuple, 1u, &new_tuple, &out) !=
            NINLIL_PARENT_OK ||
        rrmp_test_owner_fence_v2(o,
            pc->scope, pc->token, &old_tuple, proof, &out) !=
            NINLIL_PARENT_OK ||
        !test_store_witness(store, &expected_bundle) ||
        rrmp_test_authority_commit_v2(o,
            pc->scope,
            &old_tuple,
            &new_tuple,
            pc->token,
            proof,
            &expected_bundle,
            0u,
            commit_digest,
            &out) != NINLIL_PARENT_OK) {
        return 0;
    }

    ninlil_rrmp_memzero(&activate, sizeof(activate));
    activate.preamble.api_version = 1u;
    activate.preamble.struct_size = (uint32_t)sizeof(activate);
    memcpy(activate.owner_scope_id, pc->scope, 16u);
    memcpy(activate.commit_receipt_digest32, commit_digest, 32u);
    activate.now_ms = 1000000u;
    return ninlil_parent_owner_activate(o, &activate, &out) ==
        NINLIL_PARENT_OK;
}

static int fill_parent_precommit(
    ninlil_rrmp_owner_t *o,
    test_store_t *store,
    parent_precommit_case_t *pc)
{
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_owner_prepare_req_v1_t prep;
    ninlil_parent_result_v1_t out;
    ninlil_rrmp_id16_t id;
    ninlil_rrmp_digest32_t parent_digest;
    ninlil_rrmp_noa1_fields_t noa;
    if (o == NULL || store == NULL || pc == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(pc, sizeof(*pc));
    rrmp_fill_id(pc->scope, 0x21u);
    memset(pc->token, 0x71, sizeof(pc->token));
    ninlil_rrmp_memzero(&set, sizeof(set));
    set.preamble.api_version = 1u;
    set.preamble.struct_size = 240u;
    memcpy(set.owner_scope_id, pc->scope, 16u);
    set.parent_set_count = 1u;
    rrmp_fill_id(set.path_policy_id, 0x61u);
    set.controller_term = 5u;
    set.assignment_epoch = 1u;
    rrmp_fill_id(id.bytes, 0x30u);
    memcpy(set.parent_runtime_id[0], id.bytes, 16u);
    if (!ninlil_rrmp_parent_set_digest(&id, 1u, &parent_digest)) {
        return 0;
    }
    memcpy(set.parent_set_digest32, parent_digest.bytes, 32u);
    ninlil_rrmp_owner_bind(o);
    if (ninlil_parent_set_install(o, &set, &out) != NINLIL_PARENT_OK) {
        return 0;
    }

    ninlil_rrmp_memzero(&noa, sizeof(noa));
    memcpy(noa.owner_scope_id.bytes, pc->scope, 16u);
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
    memset(noa.e2e_binding_digest.bytes, 0xE1, 32u);
    rrmp_fill_id(noa.authority_clock_epoch_id.bytes, 0x50u);
    noa.lease_not_after_authority_ms = 5000000u;
    memcpy(noa.handoff_token_digest.bytes, pc->token, 32u);
    noa.parent_set_digest = parent_digest;
    noa.parent_set_count = 1u;
    memcpy(noa.parent_set_id.bytes, set.path_policy_id, 16u);

    ninlil_rrmp_memzero(&prep, sizeof(prep));
    prep.preamble.api_version = 1u;
    prep.preamble.struct_size = 464u;
    memcpy(prep.owner_scope_id, pc->scope, 16u);
    if (!ninlil_rrmp_encode_noa1(&noa, prep.new_assignment_noa1)) {
        return 0;
    }
    memcpy(prep.handoff_token_digest32, pc->token, 32u);
    if (rrmp_test_owner_prepare_v2(o,
            &prep,
            &pc->old_tuple,
            1u,
            &pc->new_tuple,
            &out) != NINLIL_PARENT_OK ||
        rrmp_test_owner_fence_v2(o,
            pc->scope,
            pc->token,
            &pc->old_tuple,
            pc->proof,
            &out) != NINLIL_PARENT_OK ||
        !test_store_witness(store, &pc->bundle)) {
        return 0;
    }
    return 1;
}

static int test_two_owner_nph_exactly_one_commit(void)
{
    ninlil_rrmp_owner_t *seed;
    ninlil_rrmp_owner_t *a;
    ninlil_rrmp_owner_t *b;
    ninlil_rrmp_owner_t *cold;
    parent_precommit_case_t pc;
    ninlil_parent_query_req_v1_t query;
    ninlil_parent_result_v1_t out;
    uint8_t commit_digest[32];
    uint32_t before;
    uint32_t successes = 0u;

    test_store_init(&g_store);
    seed = make_owner(g_ws1, 1u, 1u);
    RRMP_CHECK(seed != NULL);
    RRMP_CHECK(bind_authority(seed, &g_store));
    RRMP_CHECK(fill_parent_precommit(seed, &g_store, &pc));
    ninlil_rrmp_owner_fini(seed);

    a = make_owner(g_ws1, 1u, 1u);
    b = make_owner(g_ws2, 1u, 1u);
    RRMP_CHECK(a != NULL && b != NULL);
    RRMP_CHECK(bind_authority(a, &g_store));
    RRMP_CHECK(bind_authority(b, &g_store));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(a));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(b));
    before = g_store.cas_successes;

    ninlil_rrmp_owner_bind(a);
    if (rrmp_test_authority_commit_v2(a,
            pc.scope,
            &pc.old_tuple,
            &pc.new_tuple,
            pc.token,
            pc.proof,
            &pc.bundle,
            0u,
            commit_digest,
            &out) == NINLIL_PARENT_OK) {
        successes += 1u;
    }
    ninlil_rrmp_owner_bind(b);
    if (rrmp_test_authority_commit_v2(b,
            pc.scope,
            &pc.old_tuple,
            &pc.new_tuple,
            pc.token,
            pc.proof,
            &pc.bundle,
            0u,
            commit_digest,
            &out) == NINLIL_PARENT_OK) {
        successes += 1u;
    } else {
        RRMP_CHECK_EQ(out.status, NINLIL_PARENT_AUTHORITY_CONFLICT);
    }
    RRMP_CHECK_EQ(successes, 1u);
    RRMP_CHECK_EQ(g_store.cas_successes, before + 1u);
    ninlil_rrmp_owner_fini(a);
    ninlil_rrmp_owner_fini(b);

    cold = make_owner(g_ws3, 1u, 1u);
    RRMP_CHECK(cold != NULL);
    RRMP_CHECK(bind_authority(cold, &g_store));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(cold));
    RRMP_CHECK(ninlil_rrmp_owner_bind(cold));
    ninlil_rrmp_memzero(&query, sizeof(query));
    query.preamble.api_version = 1u;
    query.preamble.struct_size = 48u;
    memcpy(query.owner_scope_id, pc.scope, 16u);
    RRMP_CHECK_EQ(
        ninlil_parent_query(cold, &query, &out), NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        out.handoff_step,
        NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED);
    ninlil_rrmp_owner_fini(cold);
    return 0;
}

static void fill_parent_set_for_fence(
    ninlil_parent_set_install_req_v1_t *set)
{
    ninlil_rrmp_id16_t id;
    ninlil_rrmp_digest32_t digest;
    ninlil_rrmp_memzero(set, sizeof(*set));
    set->preamble.api_version = 1u;
    set->preamble.struct_size = 240u;
    rrmp_fill_id(set->owner_scope_id, 0x31u);
    rrmp_fill_id(set->path_policy_id, 0x61u);
    set->controller_term = 5u;
    set->assignment_epoch = 1u;
    set->parent_set_count = 1u;
    rrmp_fill_id(id.bytes, 0x41u);
    memcpy(set->parent_runtime_id[0], id.bytes, 16u);
    if (ninlil_rrmp_parent_set_digest(&id, 1u, &digest)) {
        memcpy(set->parent_set_digest32, digest.bytes, 32u);
    }
}

static int test_commit_unknown_old_new_and_global_fence(void)
{
    ninlil_rrmp_owner_t *o;
    ninlil_rrmp_owner_t *cold;
    ninlil_route_install_batch_req_v1_t install;
    ninlil_route_query_req_v1_t query;
    ninlil_route_result_v1_t rout;
    ninlil_parent_set_install_req_v1_t set;
    ninlil_parent_result_v1_t pout;
    ninlil_rrmp_hop_tx_view_t tx;
    ninlil_rrmp_worker_result_v1_t worker;
    uint8_t scope[16];
    uint8_t attempt[16];
    uint8_t selected[16];
    ninlil_rrmp_bundle_witness_v2_t old_witness;
    ninlil_rrmp_bundle_witness_v2_t observed_witness;

    test_store_init(&g_store);
    o = make_owner(g_ws1, 1u, 1u);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(bind_authority(o, &g_store));
    RRMP_CHECK(rrmp_install_activate(o, 1u, 1u, 1u) == 0);
    RRMP_CHECK(test_store_witness(&g_store, &old_witness));

    g_store.cas_mode = TEST_CAS_CU_OLD;
    fill_install(&install, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(o, &install, &rout),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 0u);
    RRMP_CHECK(test_store_witness(&g_store, &observed_witness));
    RRMP_CHECK(witness_equal(&observed_witness, &old_witness));

    fill_install(&install, 3u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(o, &install, &rout),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    fill_route_query(&query, 1u);
    RRMP_CHECK_EQ(
        ninlil_route_query(o, &query, &rout),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_forward_service_once(o, &rout),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    fill_parent_set_for_fence(&set);
    RRMP_CHECK_EQ(
        ninlil_parent_set_install(o, &set, &pout),
        NINLIL_PARENT_COMMIT_UNKNOWN);
    rrmp_fill_id(scope, 0x31u);
    rrmp_fill_attempt_id16(attempt, 1u);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, scope, attempt, selected, &pout),
        NINLIL_PARENT_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_hop_forward_execute(
            o, 1u, NULL, 0u, 1u, &tx),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_queue_bind_scope(o, 1u, scope),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_worker_tick(o, 1000001u, 1u, &worker),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    ninlil_rrmp_owner_fini(o);

    /* Cold recovery classifies exact OLD and exposes no route 2. */
    cold = make_owner(g_ws2, 1u, 1u);
    RRMP_CHECK(cold != NULL);
    RRMP_CHECK(bind_authority(cold, &g_store));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(cold));
    RRMP_CHECK(ninlil_rrmp_owner_bind(cold));
    fill_route_query(&query, 1u);
    RRMP_CHECK_EQ(
        ninlil_route_query(cold, &query, &rout), NINLIL_ROUTE_OK);
    fill_route_query(&query, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_query(cold, &query, &rout),
        NINLIL_ROUTE_NOT_ACTIVE);

    /* Cold recovery classifies exact NEW and exposes the staged route 2. */
    g_store.cas_mode = TEST_CAS_CU_NEW;
    fill_install(&install, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(cold, &install, &rout),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    RRMP_CHECK(test_store_witness(&g_store, &observed_witness));
    RRMP_CHECK_EQ(observed_witness.present, 1u);
    ninlil_rrmp_owner_fini(cold);
    cold = make_owner(g_ws2, 1u, 1u);
    RRMP_CHECK(cold != NULL);
    RRMP_CHECK(bind_authority(cold, &g_store));
    RRMP_CHECK(ninlil_rrmp_owner_storage_recover(cold));
    RRMP_CHECK(ninlil_rrmp_owner_bind(cold));
    fill_route_query(&query, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_query(cold, &query, &rout), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(rout.lifecycle_state, NINLIL_RRMP_LIFE_STAGED);

    /* PARTIAL and THIRD are never guessed into OLD/NEW. */
    g_store.cas_mode = TEST_CAS_CU_OLD;
    fill_install(&install, 3u);
    RRMP_CHECK_EQ(
        ninlil_route_install_batch(cold, &install, &rout),
        NINLIL_ROUTE_COMMIT_UNKNOWN);
    g_store.recovery_override = NINLIL_RRMP_STORAGE_RECOVERY_PARTIAL;
    RRMP_CHECK(!ninlil_rrmp_owner_storage_recover(cold));
    RRMP_CHECK_EQ(
        ninlil_rrmp_owner_cu_class(cold),
        NINLIL_RRMP_CU_PARTIAL);
    fill_route_query(&query, 2u);
    RRMP_CHECK_EQ(
        ninlil_route_query(cold, &query, &rout), NINLIL_ROUTE_CORRUPT);
    g_store.recovery_override = NINLIL_RRMP_STORAGE_RECOVERY_THIRD;
    RRMP_CHECK(!ninlil_rrmp_owner_storage_recover(cold));
    RRMP_CHECK_EQ(
        ninlil_rrmp_owner_cu_class(cold),
        NINLIL_RRMP_CU_THIRD);
    RRMP_CHECK_EQ(
        ninlil_route_query(cold, &query, &rout), NINLIL_ROUTE_CORRUPT);
    ninlil_rrmp_owner_fini(cold);
    return 0;
}

static int test_parent_select_definite_failure_restores_mid_index_old(void)
{
    ninlil_rrmp_owner_t *o;
    active_two_parent_case_t pc;
    ninlil_parent_result_v1_t pout;
    ninlil_route_query_req_v1_t query;
    ninlil_route_result_v1_t rout;
    ninlil_rrmp_bundle_witness_v2_t old_witness;
    ninlil_rrmp_bundle_witness_v2_t after_witness;
    uint8_t attempt_a[16];
    uint8_t attempt_b[16];
    uint8_t attempt_c[16];
    uint8_t selected[16];
    size_t old_export_len = 0u;
    size_t after_export_len = 0u;

    test_store_init(&g_store);
    o = make_owner(g_ws1, 1u, 1u);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(bind_authority(o, &g_store));
    RRMP_CHECK(setup_active_two_parent_scope(o, &g_store, &pc));

    rrmp_fill_attempt_id16(attempt_a, 1u);
    rrmp_fill_attempt_id16(attempt_b, 1u);
    rrmp_fill_attempt_id16(attempt_c, 2u);
    attempt_a[0] = 0x10u;
    attempt_b[0] = 0x20u;
    attempt_c[0] = 0x30u;
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_a, selected, &pout),
        NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_c, selected, &pout),
        NINLIL_PARENT_OK);
    RRMP_CHECK(test_store_witness(&g_store, &old_witness));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &old_export_len));
    RRMP_CHECK(old_export_len <= sizeof(g_after));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, g_after, sizeof(g_after), &old_export_len));

    /*
     * attempt_b sorts between existing A and C. A definite CAS failure
     * rehydrates exact durable OLD before returning; post-recovery rollback
     * must not remove the old row now occupying insertion index 1.
     */
    g_store.cas_mode = TEST_CAS_DEFINITE;
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_b, selected, &pout),
        NINLIL_PARENT_CORRUPT);
    RRMP_CHECK(test_store_witness(&g_store, &after_witness));
    RRMP_CHECK(witness_equal(&after_witness, &old_witness));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &after_export_len));
    RRMP_CHECK_EQ(after_export_len, old_export_len);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, g_before, sizeof(g_before), &after_export_len));
    RRMP_CHECK(memcmp(g_before, g_after, old_export_len) == 0);

    fill_route_query(&query, 1u);
    RRMP_CHECK_EQ(ninlil_route_query(o, &query, &rout), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(rout.lifecycle_state, NINLIL_RRMP_LIFE_ACTIVE);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_a, selected, &pout),
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_c, selected, &pout),
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 1u);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

static int test_forward_admit_definite_failure_restores_mid_index_old(void)
{
    ninlil_rrmp_owner_t *o;
    active_two_parent_case_t pc;
    ninlil_parent_result_v1_t pout;
    ninlil_route_forward_admit_req_v1_t admit;
    ninlil_route_query_req_v1_t query;
    ninlil_route_result_v1_t rout;
    ninlil_rrmp_bundle_witness_v2_t old_witness;
    ninlil_rrmp_bundle_witness_v2_t after_witness;
    uint8_t attempt_a[16];
    uint8_t attempt_b[16];
    uint8_t attempt_c[16];
    uint8_t selected[16];
    static const uint8_t carrier[3] = {0x91u, 0x92u, 0x93u};
    size_t old_export_len = 0u;
    size_t after_export_len = 0u;
    size_t i;

    test_store_init(&g_store);
    o = make_owner(g_ws1, 1u, 1u);
    RRMP_CHECK(o != NULL);
    RRMP_CHECK(bind_authority(o, &g_store));
    RRMP_CHECK(setup_active_two_parent_scope(o, &g_store, &pc));

    rrmp_fill_attempt_id16(attempt_a, 1u);
    rrmp_fill_attempt_id16(attempt_b, 1u);
    rrmp_fill_attempt_id16(attempt_c, 2u);
    attempt_a[0] = 0x10u;
    attempt_b[0] = 0x20u;
    attempt_c[0] = 0x30u;
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_a, selected, &pout),
        NINLIL_PARENT_OK);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_c, selected, &pout),
        NINLIL_PARENT_OK);
    RRMP_CHECK(test_store_witness(&g_store, &old_witness));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &old_export_len));
    RRMP_CHECK(old_export_len <= sizeof(g_after));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, g_after, sizeof(g_after), &old_export_len));

    ninlil_rrmp_memzero(&admit, sizeof(admit));
    admit.preamble.api_version = 1u;
    admit.preamble.struct_size = (uint32_t)sizeof(admit);
    admit.ingress_hop_context_id = 0x1001u;
    admit.route_handle = 1u;
    admit.route_generation = 1u;
    admit.hop_remaining = 1u;
    admit.outer_rx_counter = 9u;
    admit.admission_now_ms = 1000000u;
    admit.priority_class = NINLIL_RRMP_PRIO_NORMAL;
    admit.caller_item_token = 0x101u;
    for (i = 0u; i < 32u; ++i) {
        admit.e2e_header_digest32[i] = (uint8_t)(0x51u + i);
    }

    /*
     * The new attempt, LIVE evidence, queue and route sequence are one FULL
     * writepoint. Exact OLD recovery must preserve the pre-existing route and
     * both old attempt rows without leaving a synthetic route fence.
     */
    g_store.cas_mode = TEST_CAS_DEFINITE;
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_forward_admit_with_carrier(
            o,
            &admit,
            carrier,
            (uint16_t)sizeof(carrier),
            attempt_b,
            &rout),
        NINLIL_ROUTE_CORRUPT);
    RRMP_CHECK(test_store_witness(&g_store, &after_witness));
    RRMP_CHECK(witness_equal(&after_witness, &old_witness));
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, NULL, 0u, &after_export_len));
    RRMP_CHECK_EQ(after_export_len, old_export_len);
    RRMP_CHECK(ninlil_rrmp_owner_export_namespace(
        o, g_before, sizeof(g_before), &after_export_len));
    RRMP_CHECK(memcmp(g_before, g_after, old_export_len) == 0);

    fill_route_query(&query, 1u);
    RRMP_CHECK_EQ(ninlil_route_query(o, &query, &rout), NINLIL_ROUTE_OK);
    RRMP_CHECK_EQ(rout.lifecycle_state, NINLIL_RRMP_LIFE_ACTIVE);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_a, selected, &pout),
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT);
    RRMP_CHECK_EQ(
        ninlil_rrmp_core_parent_select_for_attempt(
            o, pc.scope, attempt_c, selected, &pout),
        NINLIL_PARENT_SAME_ATTEMPT_RESELECT);
    RRMP_CHECK_EQ(ninlil_rrmp_owner_downlink_tx_allowed(o), 1u);
    ninlil_rrmp_owner_fini(o);
    return 0;
}

int main(void)
{
    RRMP_CHECK(test_definite_failures_restore_exact_old() == 0);
    RRMP_CHECK(test_standard_stale_owner_rejected() == 0);
    RRMP_CHECK(
        test_two_owner_storage_scratch_isolation_and_fini_zeroize() == 0);
    RRMP_CHECK(test_two_owner_nph_exactly_one_commit() == 0);
    RRMP_CHECK(test_commit_unknown_old_new_and_global_fence() == 0);
    RRMP_CHECK(
        test_parent_select_definite_failure_restores_mid_index_old() == 0);
    RRMP_CHECK(
        test_forward_admit_definite_failure_restores_mid_index_old() == 0);
    printf("rrmp_storage_atomicity_test OK\n");
    return 0;
}
