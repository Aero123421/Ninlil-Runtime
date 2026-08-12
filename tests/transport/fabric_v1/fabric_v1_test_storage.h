/* SPDX-License-Identifier: Apache-2.0 */
/*
 * In-memory storage/provider test doubles for Fabric v1 lifecycle tests.
 */
#ifndef NINLIL_TESTS_TRANSPORT_FABRIC_V1_TEST_STORAGE_H
#define NINLIL_TESTS_TRANSPORT_FABRIC_V1_TEST_STORAGE_H

#include "fabric_v1_test_common.h"

static void fabric_test_id(ninlil_id128_t *id, uint8_t start)
{
    fabric_test_pattern(id->bytes, start, 16u);
}

/* ---- in-memory storage model with fault injection ---- */

/* Profile-1 durable ceiling is exactly 273 committed rows. */
#define FABRIC_TEST_STORE_MAX 273u
#define FABRIC_TEST_KEY_MAX 80u
#define FABRIC_TEST_VAL_MAX 712u

typedef struct fabric_test_row {
    uint32_t used;
    uint8_t key[FABRIC_TEST_KEY_MAX];
    uint32_t key_len;
    uint8_t value[FABRIC_TEST_VAL_MAX];
    uint32_t value_len;
} fabric_test_row_t;

typedef struct fabric_test_store {
    fabric_test_row_t rows[FABRIC_TEST_STORE_MAX];
    uint32_t open;
    /* Deterministic one-shot fault injection at each storage step. */
    uint32_t fail_next_begin;
    uint32_t fail_next_get;
    uint32_t fail_next_put;
    uint32_t fail_next_erase;
    uint32_t fail_next_commit; /* inject COMMIT_UNKNOWN once by default */
    /*
     * Fail-nth: allow N successful ops, then next matching op faults.
     * commit_fault_skips: successful commits to allow before fail_next_commit.
     * put_fault_skips: successful puts to allow before fail_next_put.
     */
    uint32_t commit_fault_skips;
    uint32_t put_fault_skips;
    /*
     * When fail_next_commit fires:
     * 0 = discard staged (simulate OLD/ABSENT under CU)
     * 1 = apply staged then CU (simulate NEW under CU)
     */
    uint32_t cu_apply_staged;
    /*
     * Optional readback shape after an applied CU put:
     * 0 = exact NEW, 1 = strict-prefix PARTIAL, 2 = CRC-valid THIRD.
     */
    uint32_t cu_observed_shape;
    uint32_t fail_begin_status; /* non-zero overrides IO_ERROR */
    uint32_t fail_get_status;
    uint32_t fail_put_status;
    uint32_t fail_erase_status;
    uint32_t fail_commit_as_io; /* 1 => commit returns IO_ERROR not CU */
    uint32_t begin_calls;
    uint32_t get_calls;
    uint32_t put_calls;
    uint32_t erase_calls;
    uint32_t commit_calls;
    uint32_t delete_calls; /* successful committed erases */
} fabric_test_store_t;

typedef struct fabric_test_staged {
    uint32_t is_erase; /* 0=put, 1=erase */
    fabric_test_row_t row; /* erase uses key only */
} fabric_test_staged_t;

typedef struct fabric_test_txn {
    fabric_test_store_t *store;
    uint32_t mode;
    uint32_t live;
    /* staged mutations for FULL commit simulation */
    fabric_test_staged_t staged[16];
    uint32_t staged_count;
} fabric_test_txn_t;

typedef struct fabric_test_iter {
    fabric_test_store_t *store;
    uint32_t index;
    uint32_t live;
} fabric_test_iter_t;

static fabric_test_store_t g_store;
static fabric_test_txn_t g_txn;
static fabric_test_iter_t g_iter;
static uint64_t g_exec_context = 1u;
static ninlil_time_sample_t g_clock_sample;
static uint32_t g_clock_ready;

static ninlil_storage_status_t test_storage_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    fabric_test_store_t *store = (fabric_test_store_t *)user;
    if (store == NULL || out_handle == NULL || storage_namespace.data == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (expected_schema != 1u) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    if (storage_namespace.length != 16u
        || memcmp(storage_namespace.data, "ninlil.fabric.v1", 16u) != 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    store->open = 1u;
    *out_handle = (ninlil_storage_handle_t)store;
    return NINLIL_STORAGE_OK;
}

static void test_storage_close(void *user, ninlil_storage_handle_t handle)
{
    fabric_test_store_t *store = (fabric_test_store_t *)user;
    (void)handle;
    if (store != NULL) {
        store->open = 0u;
    }
}

static ninlil_storage_status_t test_storage_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    fabric_test_store_t *store = (fabric_test_store_t *)user;
    (void)handle;
    if (store == NULL || out_txn == NULL || g_txn.live != 0u) {
        return NINLIL_STORAGE_BUSY;
    }
    store->begin_calls++;
    if (store->fail_next_begin != 0u) {
        store->fail_next_begin = 0u;
        return store->fail_begin_status != 0u
            ? (ninlil_storage_status_t)store->fail_begin_status
            : NINLIL_STORAGE_IO_ERROR;
    }
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    g_txn.store = store;
    g_txn.mode = mode;
    g_txn.live = 1u;
    *out_txn = (ninlil_storage_txn_t)&g_txn;
    return NINLIL_STORAGE_OK;
}

static int test_row_match(
    const fabric_test_row_t *row,
    const uint8_t *key,
    uint32_t key_len)
{
    return row->used != 0u && row->key_len == key_len
        && memcmp(row->key, key, key_len) == 0;
}

static ninlil_storage_status_t test_storage_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    fabric_test_txn_t *t = (fabric_test_txn_t *)txn;
    uint32_t i;
    (void)user;
    if (t == NULL || t->live == 0u || key.data == NULL || inout_value == NULL
        || inout_value->data == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->store->get_calls++;
    if (t->store->fail_next_get != 0u) {
        t->store->fail_next_get = 0u;
        return t->store->fail_get_status != 0u
            ? (ninlil_storage_status_t)t->store->fail_get_status
            : NINLIL_STORAGE_IO_ERROR;
    }
    for (i = 0u; i < t->staged_count; ++i) {
        if (t->staged[i].is_erase != 0u) {
            if (test_row_match(&t->staged[i].row, key.data, key.length)) {
                return NINLIL_STORAGE_NOT_FOUND;
            }
            continue;
        }
        if (test_row_match(&t->staged[i].row, key.data, key.length)) {
            if (inout_value->capacity < t->staged[i].row.value_len) {
                return NINLIL_STORAGE_BUFFER_TOO_SMALL;
            }
            memcpy(
                inout_value->data,
                t->staged[i].row.value,
                t->staged[i].row.value_len);
            inout_value->length = t->staged[i].row.value_len;
            return NINLIL_STORAGE_OK;
        }
    }
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (test_row_match(&t->store->rows[i], key.data, key.length)) {
            if (inout_value->capacity < t->store->rows[i].value_len) {
                return NINLIL_STORAGE_BUFFER_TOO_SMALL;
            }
            memcpy(
                inout_value->data,
                t->store->rows[i].value,
                t->store->rows[i].value_len);
            inout_value->length = t->store->rows[i].value_len;
            return NINLIL_STORAGE_OK;
        }
    }
    return NINLIL_STORAGE_NOT_FOUND;
}

static ninlil_storage_status_t test_storage_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    fabric_test_txn_t *t = (fabric_test_txn_t *)txn;
    (void)user;
    if (t == NULL || t->live == 0u || t->mode != NINLIL_STORAGE_READ_WRITE
        || key.data == NULL || value.data == NULL
        || key.length == 0u || key.length > FABRIC_TEST_KEY_MAX
        || value.length > FABRIC_TEST_VAL_MAX || t->staged_count >= 16u) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->store->put_calls++;
    if (t->store->fail_next_put != 0u) {
        if (t->store->put_fault_skips != 0u) {
            t->store->put_fault_skips--;
        } else {
            t->store->fail_next_put = 0u;
            return t->store->fail_put_status != 0u
                ? (ninlil_storage_status_t)t->store->fail_put_status
                : NINLIL_STORAGE_IO_ERROR;
        }
    }
    {
        fabric_test_staged_t *s = &t->staged[t->staged_count++];
        ninlil_fabric_private_memzero(s, sizeof(*s));
        s->is_erase = 0u;
        s->row.used = 1u;
        memcpy(s->row.key, key.data, key.length);
        s->row.key_len = key.length;
        memcpy(s->row.value, value.data, value.length);
        s->row.value_len = value.length;
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t test_storage_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    fabric_test_txn_t *t = (fabric_test_txn_t *)txn;
    (void)user;
    if (t == NULL || t->live == 0u || t->mode != NINLIL_STORAGE_READ_WRITE
        || key.data == NULL || key.length == 0u
        || key.length > FABRIC_TEST_KEY_MAX || t->staged_count >= 16u) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->store->erase_calls++;
    if (t->store->fail_next_erase != 0u) {
        t->store->fail_next_erase = 0u;
        return t->store->fail_erase_status != 0u
            ? (ninlil_storage_status_t)t->store->fail_erase_status
            : NINLIL_STORAGE_IO_ERROR;
    }
    {
        fabric_test_staged_t *s = &t->staged[t->staged_count++];
        ninlil_fabric_private_memzero(s, sizeof(*s));
        s->is_erase = 1u;
        s->row.used = 1u;
        memcpy(s->row.key, key.data, key.length);
        s->row.key_len = key.length;
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t test_storage_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    fabric_test_txn_t *t = (fabric_test_txn_t *)txn;
    (void)user;
    (void)prefix;
    if (t == NULL || out_iter == NULL || g_iter.live != 0u) {
        return NINLIL_STORAGE_BUSY;
    }
    g_iter.store = t->store;
    g_iter.index = 0u;
    g_iter.live = 1u;
    *out_iter = (ninlil_storage_iter_t)&g_iter;
    return NINLIL_STORAGE_OK;
}

static int test_storage_key_cmp(
    const uint8_t *a, uint32_t alen, const uint8_t *b, uint32_t blen)
{
    uint32_t n = alen < blen ? alen : blen;
    uint32_t i;
    for (i = 0u; i < n; ++i) {
        if (a[i] < b[i]) {
            return -1;
        }
        if (a[i] > b[i]) {
            return 1;
        }
    }
    if (alen < blen) {
        return -1;
    }
    if (alen > blen) {
        return 1;
    }
    return 0;
}

static ninlil_storage_status_t test_storage_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    fabric_test_iter_t *it = (fabric_test_iter_t *)iter;
    uint32_t best = FABRIC_TEST_STORE_MAX;
    uint32_t i;
    fabric_test_row_t *row;
    /* Persist emit mask for current open iter (single-iter test model). */
    static uint8_t emitted[FABRIC_TEST_STORE_MAX];
    (void)user;
    if (it == NULL || it->live == 0u || inout_key == NULL
        || inout_value == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (it->index == 0u) {
        memset(emitted, 0, sizeof(emitted));
    }
    /* Foundation Storage: unsigned-lexicographic key order. */
    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
        if (it->store->rows[i].used == 0u || emitted[i] != 0u) {
            continue;
        }
        if (best == FABRIC_TEST_STORE_MAX
            || test_storage_key_cmp(
                   it->store->rows[i].key,
                   it->store->rows[i].key_len,
                   it->store->rows[best].key,
                   it->store->rows[best].key_len)
                < 0) {
            best = i;
        }
    }
    if (best == FABRIC_TEST_STORE_MAX) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    emitted[best] = 1u;
    it->index++;
    row = &it->store->rows[best];
    if (inout_key->capacity < row->key_len
        || inout_value->capacity < row->value_len) {
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    memcpy(inout_key->data, row->key, row->key_len);
    inout_key->length = row->key_len;
    memcpy(inout_value->data, row->value, row->value_len);
    inout_value->length = row->value_len;
    return NINLIL_STORAGE_OK;
}

static void test_storage_iter_close(void *user, ninlil_storage_iter_t iter)
{
    fabric_test_iter_t *it = (fabric_test_iter_t *)iter;
    (void)user;
    if (it != NULL) {
        it->live = 0u;
    }
}

static ninlil_storage_status_t test_storage_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    (void)user;
    (void)handle;
    if (out_capacity == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    ninlil_fabric_private_memzero(out_capacity, sizeof(*out_capacity));
    out_capacity->abi_version = NINLIL_ABI_VERSION;
    out_capacity->struct_size = (uint16_t)sizeof(*out_capacity);
    out_capacity->max_entries = 546u;
    out_capacity->max_bytes = 275880u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t test_storage_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    fabric_test_txn_t *t = (fabric_test_txn_t *)txn;
    uint32_t s;
    (void)user;
    if (t == NULL || t->live == 0u) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->store->commit_calls++;
    if (durability != NINLIL_DURABILITY_FULL) {
        t->live = 0u;
        return NINLIL_STORAGE_IO_ERROR;
    }
    {
        int force_cu = 0;
        int apply = 1;
        if (t->store->fail_next_commit != 0u) {
            if (t->store->commit_fault_skips != 0u) {
                t->store->commit_fault_skips--;
            } else {
                t->store->fail_next_commit = 0u;
                if (t->store->fail_commit_as_io != 0u) {
                    t->store->fail_commit_as_io = 0u;
                    t->live = 0u;
                    return NINLIL_STORAGE_IO_ERROR;
                }
                force_cu = 1;
                /* NEW under CU: apply then return CU. OLD: discard staged. */
                apply = t->store->cu_apply_staged != 0u ? 1 : 0;
                t->store->cu_apply_staged = 0u;
            }
        }
        if (apply != 0) {
            for (s = 0u; s < t->staged_count; ++s) {
                uint32_t i;
                if (t->staged[s].is_erase != 0u) {
                    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
                        if (test_row_match(
                                &t->store->rows[i],
                                t->staged[s].row.key,
                                t->staged[s].row.key_len)) {
                            ninlil_fabric_private_memzero(
                                &t->store->rows[i],
                                sizeof(t->store->rows[i]));
                            t->store->delete_calls++;
                            break;
                        }
                    }
                    continue;
                }
                {
                    int placed = 0;
                    for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
                        if (test_row_match(
                                &t->store->rows[i],
                                t->staged[s].row.key,
                                t->staged[s].row.key_len)) {
                            t->store->rows[i] = t->staged[s].row;
                            placed = 1;
                            break;
                        }
                    }
                    if (!placed) {
                        for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
                            if (t->store->rows[i].used == 0u) {
                                t->store->rows[i] = t->staged[s].row;
                                placed = 1;
                                break;
                            }
                        }
                    }
                    if (!placed) {
                        t->live = 0u;
                        return NINLIL_STORAGE_NO_SPACE;
                    }
                }
            }
            if (force_cu != 0 && t->store->cu_observed_shape != 0u
                && t->staged_count == 1u
                && t->staged[0].is_erase == 0u) {
                uint32_t i;
                for (i = 0u; i < FABRIC_TEST_STORE_MAX; ++i) {
                    fabric_test_row_t *row = &t->store->rows[i];
                    if (!test_row_match(
                            row,
                            t->staged[0].row.key,
                            t->staged[0].row.key_len)) {
                        continue;
                    }
                    if (t->store->cu_observed_shape == 1u) {
                        if (row->value_len > 1u) {
                            row->value_len--;
                        }
                    } else if (
                        t->store->cu_observed_shape == 2u
                        && row->value_len >= 24u) {
                        /*
                         * Change the final payload byte, then repair the
                         * envelope CRC so readback is a valid third value.
                         */
                        row->value[row->value_len - 1u] ^= 1u;
                        ninlil_fabric_private_put_u32_be(row->value + 20u, 0u);
                        ninlil_fabric_private_put_u32_be(
                            row->value + 20u,
                            ninlil_fabric_private_crc32c(
                                row->value, row->value_len));
                    }
                    break;
                }
            }
        }
        if (force_cu != 0) {
            t->store->cu_observed_shape = 0u;
        }
        t->live = 0u;
        if (force_cu != 0) {
            return NINLIL_STORAGE_COMMIT_UNKNOWN;
        }
        return NINLIL_STORAGE_OK;
    }
}

static ninlil_storage_status_t test_storage_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    fabric_test_txn_t *t = (fabric_test_txn_t *)txn;
    (void)user;
    if (t == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    t->live = 0u;
    return NINLIL_STORAGE_OK;
}

static void fabric_test_storage_ops(ninlil_storage_ops_t *ops)
{
    ninlil_fabric_private_memzero(ops, sizeof(*ops));
    ops->abi_version = NINLIL_ABI_VERSION;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = &g_store;
    ops->open = test_storage_open;
    ops->close = test_storage_close;
    ops->begin = test_storage_begin;
    ops->get = test_storage_get;
    ops->put = test_storage_put;
    ops->erase = test_storage_erase;
    ops->iter_open = test_storage_iter_open;
    ops->iter_next = test_storage_iter_next;
    ops->iter_close = test_storage_iter_close;
    ops->capacity = test_storage_capacity;
    ops->commit = test_storage_commit;
    ops->rollback = test_storage_rollback;
}

static ninlil_port_status_t test_clock_now(
    void *user, ninlil_time_sample_t *out_sample)
{
    (void)user;
    if (out_sample == NULL || g_clock_ready == 0u) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    *out_sample = g_clock_sample;
    return NINLIL_PORT_OK;
}

static uint64_t test_exec_context(void *user)
{
    (void)user;
    return g_exec_context;
}

static void fabric_test_set_clock(uint64_t now_ms, uint8_t epoch_start)
{
    ninlil_fabric_private_memzero(&g_clock_sample, sizeof(g_clock_sample));
    g_clock_sample.abi_version = NINLIL_ABI_VERSION;
    g_clock_sample.struct_size = (uint16_t)sizeof(g_clock_sample);
    fabric_test_pattern(g_clock_sample.clock_epoch_id.bytes, epoch_start, 16u);
    g_clock_sample.now_ms = now_ms;
    g_clock_sample.trust = NINLIL_CLOCK_TRUSTED;
    g_clock_ready = 1u;
}

/* ---- packet-link provider with fault injection ---- */

typedef struct fabric_test_provider {
    uint32_t open;
    uint32_t open_calls;
    uint32_t close_calls;
    uint32_t start_calls;
    uint32_t poll_calls;
    uint32_t cancel_calls;
    uint32_t release_send_calls;
    uint32_t receive_calls;
    uint32_t next_open_status; /* 0 => LINK_OK; else open returns that status */
    uint32_t open_return_nonnull_on_error; /* contradiction: non-OK + handle */
    uint32_t next_start_status; /* NINLIL_FABRIC_LINK_* */
    uint32_t next_poll_status; /* 0 => LINK_OK */
    uint32_t inject_token_on_non_retained; /* contradiction inject */
    uint32_t retained;
    uint8_t retained_packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t retained_len;
    uint32_t token_value;
    uint32_t live_token; /* 1 while Fabric holds unreclaimed token */
    uint32_t completion_kind;
    uint8_t rx_packet[NINLIL_FABRIC_NFL1_STRUCTURAL_MAX];
    uint32_t rx_len;
    uint32_t rx_ready;
    /* receive_next shape injection for fence tests. */
    uint32_t next_receive_status; /* 0 => use normal EMPTY/OK path */
    uint32_t dirty_non_success_outputs; /* non-OK with non-NULL token/bytes */
    uint32_t ok_null_token; /* OK shape violation: token NULL */
    uint32_t release_received_calls;
    ninlil_fabric_link_state_v1_t state;
} fabric_test_provider_t;

static fabric_test_provider_t g_provider;

static ninlil_fabric_link_status_t test_link_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    if (p == NULL || out_handle == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    p->open_calls++;
    *out_handle = NULL;
    if (p->next_open_status != 0u
        && p->next_open_status != NINLIL_FABRIC_LINK_OK) {
        if (p->open_return_nonnull_on_error != 0u) {
            p->open = 1u;
            *out_handle = (ninlil_fabric_packet_link_handle_t)p;
        }
        return (ninlil_fabric_link_status_t)p->next_open_status;
    }
    p->open = 1u;
    *out_handle = (ninlil_fabric_packet_link_handle_t)p;
    return NINLIL_FABRIC_LINK_OK;
}

static void test_link_close(
    void *user, ninlil_fabric_packet_link_handle_t handle)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    if (p != NULL) {
        p->close_calls++;
        p->open = 0u;
    }
}

/*
 * Provider-side TxPermit contract (mirrors fabric_private_api.h).
 * DENIED paths do not increment start_calls (zero transport side-effect).
 */
static int test_link_permit_ok(const ninlil_fabric_packet_view_v1_t *packet)
{
    const ninlil_tx_permit_t *pr;
    uint32_t i;
    int zero;
    if (packet == NULL) {
        return 0;
    }
    pr = packet->permit;
    if (pr == NULL) {
        return 0;
    }
    if (pr->abi_version != NINLIL_ABI_VERSION
        || pr->struct_size != (uint16_t)sizeof(*pr)) {
        return 0;
    }
    zero = 1;
    for (i = 0u; i < 16u; ++i) {
        if (pr->permit_id.bytes[i] != 0u) {
            zero = 0;
            break;
        }
    }
    if (zero != 0 || pr->expires_at_ms == 0u) {
        return 0;
    }
    if (!ninlil_fabric_private_memeq(
            pr->attempt_id.bytes, packet->attempt_id.bytes, 16u)) {
        return 0;
    }
    return 1;
}

static ninlil_fabric_link_status_t test_link_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    if (p == NULL || packet == NULL || out_token == NULL || packet->bytes == NULL
        || packet->length < NINLIL_FABRIC_NFL1_STRUCTURAL_MIN) {
        if (out_token != NULL) {
            *out_token = NULL;
        }
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    *out_token = NULL;
    /* Independent provider Tx Gate: no start_calls / retain on deny. */
    if (test_link_permit_ok(packet) == 0) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    p->start_calls++;
    if (p->next_start_status == NINLIL_FABRIC_LINK_WOULD_BLOCK
        || p->next_start_status == NINLIL_FABRIC_LINK_UNAVAILABLE
        || p->next_start_status == NINLIL_FABRIC_LINK_DENIED
        || p->next_start_status == NINLIL_FABRIC_LINK_LOST_UNKNOWN
        || p->next_start_status == NINLIL_FABRIC_LINK_CORRUPT) {
        if (p->inject_token_on_non_retained != 0u) {
            p->token_value = 0xBAD1u;
            p->live_token = 1u;
            *out_token = (ninlil_fabric_packet_token_t)(uintptr_t)p->token_value;
        }
        /* WOULD_BLOCK / non-RETAINED: no retain bookkeeping (permit not kept). */
        return (ninlil_fabric_link_status_t)p->next_start_status;
    }
    /* default RETAINED: copy-own full NFL1 */
    if (packet->length > sizeof(p->retained_packet)) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    memcpy(p->retained_packet, packet->bytes, packet->length);
    p->retained_len = packet->length;
    p->retained = 1u;
    p->token_value = 0xA11u;
    p->live_token = 1u;
    *out_token = (ninlil_fabric_packet_token_t)(uintptr_t)p->token_value;
    return NINLIL_FABRIC_LINK_RETAINED;
}

static ninlil_fabric_link_status_t test_link_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    if (p == NULL || out_completion == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    p->poll_calls++;
    if ((uintptr_t)token != (uintptr_t)p->token_value) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (p->next_poll_status != 0u
        && p->next_poll_status != NINLIL_FABRIC_LINK_OK) {
        return (ninlil_fabric_link_status_t)p->next_poll_status;
    }
    out_completion->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    out_completion->kind = p->completion_kind != 0u
        ? p->completion_kind
        : NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    out_completion->reserved_zero = 0u;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t test_link_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    if (p == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    p->cancel_calls++;
    if ((uintptr_t)token != (uintptr_t)p->token_value) {
        return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
    }
    return NINLIL_FABRIC_LINK_OK;
}

static void test_link_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    (void)token;
    if (p != NULL) {
        p->release_send_calls++;
        p->retained = 0u;
        p->live_token = 0u;
    }
}

static ninlil_fabric_link_status_t test_link_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    if (p == NULL || out_bytes == NULL || out_length == NULL
        || out_receive_token == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    p->receive_calls++;
    *out_bytes = NULL;
    *out_length = 0u;
    *out_receive_token = NULL;
    if (p->next_receive_status != 0u) {
        ninlil_fabric_link_status_t st =
            (ninlil_fabric_link_status_t)p->next_receive_status;
        if (p->dirty_non_success_outputs != 0u
            && st != NINLIL_FABRIC_LINK_OK) {
            *out_bytes = p->rx_packet;
            *out_length = 17u;
            *out_receive_token = (void *)(uintptr_t)0xDEADu;
        }
        if (st == NINLIL_FABRIC_LINK_OK) {
            *out_bytes = p->rx_packet;
            *out_length = p->rx_len != 0u ? p->rx_len : 587u;
            if (p->ok_null_token == 0u) {
                *out_receive_token = (void *)(uintptr_t)0xBEEFu;
            }
        }
        p->next_receive_status = 0u;
        return st;
    }
    if (p->rx_ready == 0u) {
        return NINLIL_FABRIC_LINK_EMPTY;
    }
    *out_bytes = p->rx_packet;
    *out_length = p->rx_len;
    if (p->ok_null_token != 0u) {
        *out_receive_token = NULL;
    } else {
        *out_receive_token = (void *)(uintptr_t)0xBEEFu;
    }
    return NINLIL_FABRIC_LINK_OK;
}

static void test_link_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    (void)receive_token;
    if (p != NULL) {
        p->release_received_calls++;
        p->rx_ready = 0u;
    }
}

static ninlil_fabric_link_status_t test_link_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    fabric_test_provider_t *p = (fabric_test_provider_t *)user;
    (void)handle;
    if (p == NULL || out_state == NULL) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    *out_state = p->state;
    return NINLIL_FABRIC_LINK_OK;
}

static void fabric_test_provider_ops(
    ninlil_fabric_packet_link_ops_v1_t *ops, fabric_test_provider_t *p)
{
    ninlil_fabric_private_memzero(ops, sizeof(*ops));
    ops->api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = p;
    ops->open = test_link_open;
    ops->close = test_link_close;
    ops->start_send = test_link_start_send;
    ops->poll_send = test_link_poll_send;
    ops->cancel_send = test_link_cancel_send;
    ops->release_send = test_link_release_send;
    ops->receive_next = test_link_receive_next;
    ops->release_received = test_link_release_received;
    ops->state = test_link_state;
}

static void fabric_test_reset_globals(void)
{
    ninlil_fabric_private_memzero(&g_store, sizeof(g_store));
    ninlil_fabric_private_memzero(&g_txn, sizeof(g_txn));
    ninlil_fabric_private_memzero(&g_iter, sizeof(g_iter));
    ninlil_fabric_private_memzero(&g_provider, sizeof(g_provider));
    g_exec_context = 1u;
    fabric_test_set_clock(170000u, 0xA1u);
    g_provider.next_start_status = NINLIL_FABRIC_LINK_RETAINED;
    g_provider.completion_kind =
        NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
    g_provider.state.api_version = NINLIL_FABRIC_PRIVATE_API_VERSION;
    g_provider.state.struct_size =
        (uint16_t)sizeof(g_provider.state);
    g_provider.state.availability_epoch = 7u;
    fabric_test_pattern(
        g_provider.state.availability_clock_epoch_id.bytes, 0xA1u, 16u);
    g_provider.state.available_until_ms = 250000u;
    g_provider.state.available = 1u;
}


#endif /* NINLIL_TESTS_TRANSPORT_FABRIC_V1_TEST_STORAGE_H */
