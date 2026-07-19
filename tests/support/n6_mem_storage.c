/*
 * Scripted in-memory storage backend for N6 host tests.
 * Supports multi-key FULL, four CU durable outcomes, phase faults.
 */

#include "n6_mem_storage.h"

#include "ninlil/version.h"

#include <string.h>

#define N6MS_MAX_ENTRIES 256u
#define N6MS_MAX_KEY 64u
#define N6MS_MAX_VAL 80u

typedef struct n6ms_entry {
    int live;
    uint8_t key[N6MS_MAX_KEY];
    uint32_t klen;
    uint8_t val[N6MS_MAX_VAL];
    uint32_t vlen;
} n6ms_entry_t;

typedef struct n6ms_ctx {
    ninlil_storage_ops_t ops;
    n6ms_entry_t table[N6MS_MAX_ENTRIES];
    int open;
    int txn_live;
    int txn_rw;
    n6_mem_cu_outcome_t inject_cu;
    n6_mem_fault_t fault;
    int fault_hits;
    int fault_skip; /* allow this many matching calls before arming hits */
    /* Up to 2 concurrent programs (e.g. GET fail + ROLLBACK status). */
    n6_mem_prog_op_t prog_op[2];
    ninlil_storage_status_t prog_status[2];
    n6_mem_prog_shape_t prog_shape[2];
    int prog_hits[2];
    int prog_skip[2];
    int fail_get;
    int fail_put;
    n6ms_entry_t stage[N6MS_MAX_ENTRIES];
    int iter_live;
    uint32_t iter_idx;
    uint32_t iter_order[N6MS_MAX_ENTRIES]; /* lex-sorted live stage indices */
    uint32_t iter_order_n;
    uint64_t cap_max_entries;
    uint64_t cap_used_entries;
    uint64_t cap_max_bytes;
    uint64_t cap_used_bytes;
    uint32_t close_count;
    uint32_t open_count;
    uint32_t begin_count;
    uint32_t iter_open_count;
    uint32_t iter_close_count;
    uint32_t iter_next_count;
    uint32_t commit_count;
    uint32_t rollback_count;
    uint32_t get_count;
    uint32_t put_count;
    uint32_t erase_count;
    uint32_t capacity_count;
    uint8_t poison_scratch[128]; /* for pointer rewrite faults */
} n6ms_ctx_t;

static n6ms_ctx_t g_n6ms;

static n6ms_entry_t *n6ms_find(
    n6ms_entry_t *tab, const uint8_t *key, uint32_t klen)
{
    uint32_t i;
    for (i = 0u; i < N6MS_MAX_ENTRIES; ++i) {
        if (tab[i].live != 0 && tab[i].klen == klen
            && memcmp(tab[i].key, key, klen) == 0) {
            return &tab[i];
        }
    }
    return NULL;
}

static int n6ms_hit_fault(n6ms_ctx_t *c, n6_mem_fault_t f)
{
    if (c->fault != f || c->fault_hits <= 0) {
        return 0;
    }
    if (c->fault_skip > 0) {
        c->fault_skip -= 1;
        return 0; /* pass through; arm after N skips */
    }
    c->fault_hits -= 1;
    if (c->fault_hits == 0) {
        c->fault = N6_MEM_FAULT_NONE;
        c->fault_skip = 0;
    }
    return 1;
}

/*
 * Returns slot index+1 if a program is armed for op (and consumes one hit),
 * else 0. Sets *out_slot to the slot used (0 or 1).
 */
static int n6ms_hit_program(n6ms_ctx_t *c, n6_mem_prog_op_t op, int *out_slot)
{
    int s;
    for (s = 0; s < 2; ++s) {
        if (c->prog_op[s] != op || c->prog_hits[s] <= 0) {
            continue;
        }
        if (c->prog_skip[s] > 0) {
            c->prog_skip[s] -= 1;
            return 0; /* deferred: natural path this call */
        }
        c->prog_hits[s] -= 1;
        if (c->prog_hits[s] == 0) {
            c->prog_op[s] = N6_MEM_PROG_NONE;
            c->prog_skip[s] = 0;
        }
        if (out_slot != NULL) {
            *out_slot = s;
        }
        return 1;
    }
    return 0;
}

static ninlil_storage_status_t n6ms_prog_st(const n6ms_ctx_t *c, int slot)
{
    return c->prog_status[slot];
}

static n6_mem_prog_shape_t n6ms_prog_sh(const n6ms_ctx_t *c, int slot)
{
    return c->prog_shape[slot];
}

static ninlil_storage_status_t n6ms_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    (void)storage_namespace;
    if (out_handle != NULL) {
        *out_handle = NULL; /* honor preseed; tests may preseed */
    }
    {
    int pslot = 0;
    if (n6ms_hit_program(c, N6_MEM_PROG_OPEN, &pslot)) {
        ninlil_storage_status_t st = n6ms_prog_st(c, pslot);
        n6_mem_prog_shape_t sh = n6ms_prog_sh(c, pslot);
        if (sh == N6_MEM_SHAPE_OK_NULL) {
            c->open_count += 1u;
            return NINLIL_STORAGE_OK;
        }
        if (sh == N6_MEM_SHAPE_NONOK_HANDLE) {
            if (out_handle != NULL) {
                *out_handle = (ninlil_storage_handle_t)(uintptr_t)1;
            }
            c->open = 1;
            c->open_count += 1u;
            return st == NINLIL_STORAGE_OK ? NINLIL_STORAGE_IO_ERROR : st;
        }
        /* DEFAULT: non-OK keeps NULL; OK would need a handle — rare for program */
        if (st == NINLIL_STORAGE_OK) {
            c->open = 1;
            c->open_count += 1u;
            if (out_handle != NULL) {
                *out_handle = (ninlil_storage_handle_t)(uintptr_t)1;
            }
            return NINLIL_STORAGE_OK;
        }
        return st;
    }
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_OPEN_NONOK_HANDLE)) {
        if (out_handle != NULL) {
            *out_handle = (ninlil_storage_handle_t)(uintptr_t)1;
        }
        c->open = 1;
        c->open_count += 1u;
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_OPEN_OK_NULL)) {
        c->open_count += 1u;
        return NINLIL_STORAGE_OK; /* OK + NULL */
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_OPEN_UNKNOWN)) {
        return (ninlil_storage_status_t)99u; /* unknown + NULL */
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_OPEN)) {
        return NINLIL_STORAGE_IO_ERROR; /* operational NULL */
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_OPEN_NOSPACE)) {
        return NINLIL_STORAGE_NO_SPACE; /* CU open: CORRUPT not CAPACITY */
    }
    if (out_handle == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out_handle = NULL;
    if (expected_schema != 1u) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }
    c->open = 1;
    c->open_count += 1u;
    *out_handle = (ninlil_storage_handle_t)(uintptr_t)1;
    return NINLIL_STORAGE_OK;
}

static void n6ms_close(void *user, ninlil_storage_handle_t handle)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    (void)handle;
    c->open = 0;
    c->txn_live = 0;
    c->close_count += 1u;
}

static ninlil_storage_status_t n6ms_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    (void)handle;
    c->begin_count += 1u;
    if (out_txn != NULL) {
        *out_txn = NULL;
    }
    {
    int pslot = 0;
    if (n6ms_hit_program(c, N6_MEM_PROG_BEGIN, &pslot)) {
        ninlil_storage_status_t st = n6ms_prog_st(c, pslot);
        n6_mem_prog_shape_t sh = n6ms_prog_sh(c, pslot);
        if (sh == N6_MEM_SHAPE_OK_NULL) {
            return NINLIL_STORAGE_OK;
        }
        if (sh == N6_MEM_SHAPE_NONOK_HANDLE) {
            if (out_txn != NULL) {
                *out_txn = (ninlil_storage_txn_t)(uintptr_t)2;
            }
            c->txn_live = 1;
            c->txn_rw = 0;
            (void)memcpy(c->stage, c->table, sizeof(c->table));
            return st == NINLIL_STORAGE_OK ? NINLIL_STORAGE_IO_ERROR : st;
        }
        if (st == NINLIL_STORAGE_OK) {
            if (c->open == 0 || out_txn == NULL) {
                return NINLIL_STORAGE_IO_ERROR;
            }
            c->txn_live = 1;
            c->txn_rw = (mode == NINLIL_STORAGE_READ_WRITE) ? 1 : 0;
            (void)memcpy(c->stage, c->table, sizeof(c->table));
            *out_txn = (ninlil_storage_txn_t)(uintptr_t)2;
            return NINLIL_STORAGE_OK;
        }
        return st; /* clean non-OK + NULL */
    }
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_BEGIN_NONOK_HANDLE)) {
        /* Malformed: non-OK + non-NULL txn handle */
        if (out_txn != NULL) {
            *out_txn = (ninlil_storage_txn_t)(uintptr_t)2;
        }
        c->txn_live = 1;
        c->txn_rw = 0;
        (void)memcpy(c->stage, c->table, sizeof(c->table));
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_BEGIN_OK_NULL)) {
        /* Malformed: OK + NULL */
        return NINLIL_STORAGE_OK;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_BEGIN_UNKNOWN)) {
        return (ninlil_storage_status_t)99u;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_BEGIN)) {
        /* Operational: non-OK + NULL */
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (c->open == 0 || out_txn == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (c->txn_live != 0) {
        return NINLIL_STORAGE_BUSY;
    }
    c->txn_live = 1;
    c->txn_rw = (mode == NINLIL_STORAGE_READ_WRITE) ? 1 : 0;
    (void)memcpy(c->stage, c->table, sizeof(c->table));
    *out_txn = (ninlil_storage_txn_t)(uintptr_t)2;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t n6ms_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    n6ms_entry_t *e;
    (void)txn;
    c->get_count += 1u;
    {
    int pslot = 0;
    if (n6ms_hit_program(c, N6_MEM_PROG_GET, &pslot)) {
        ninlil_storage_status_t st = n6ms_prog_st(c, pslot);
        n6_mem_prog_shape_t sh = n6ms_prog_sh(c, pslot);
        if (inout_value == NULL) {
            return st == NINLIL_STORAGE_OK ? NINLIL_STORAGE_IO_ERROR : st;
        }
        if (sh == N6_MEM_SHAPE_GET_PTR) {
            inout_value->data = c->poison_scratch;
            inout_value->length = 1u;
            return st == NINLIL_STORAGE_OK ? NINLIL_STORAGE_OK : st;
        }
        if (sh == N6_MEM_SHAPE_GET_CAP_REWRITE) {
            /* ABI: mutate declared capacity only; pointer + length stay clean */
            inout_value->capacity =
                (inout_value->capacity == 0u) ? 1u : (inout_value->capacity - 1u);
            inout_value->length = 0u;
            return st == NINLIL_STORAGE_OK ? NINLIL_STORAGE_OK : st;
        }
        if (sh == N6_MEM_SHAPE_GET_OVERSIZE) {
            inout_value->length = inout_value->capacity + 4u;
            return NINLIL_STORAGE_OK;
        }
        if (sh == N6_MEM_SHAPE_GET_TAIL) {
            if (inout_value->data != NULL && inout_value->capacity >= 4u) {
                inout_value->data[0] = 0x01u;
                inout_value->length = 1u;
                inout_value->data[2] = 0xEEu;
            }
            return NINLIL_STORAGE_OK;
        }
        if (sh == N6_MEM_SHAPE_GET_MISS_POISON) {
            inout_value->length = 3u;
            if (inout_value->data != NULL && inout_value->capacity > 0u) {
                inout_value->data[0] = 0xFFu;
            }
            return NINLIL_STORAGE_NOT_FOUND;
        }
        if (sh == N6_MEM_SHAPE_GET_BTS) {
            inout_value->length = inout_value->capacity + 8u;
            return NINLIL_STORAGE_BUFFER_TOO_SMALL;
        }
        /* DEFAULT: leave buffer untouched (sentinel intact), length 0 unless OK */
        if (st == NINLIL_STORAGE_OK) {
            e = n6ms_find(c->stage, key.data, key.length);
            if (e != NULL && inout_value->capacity >= e->vlen) {
                (void)memcpy(inout_value->data, e->val, e->vlen);
                inout_value->length = e->vlen;
                return NINLIL_STORAGE_OK;
            }
            return NINLIL_STORAGE_NOT_FOUND;
        }
        inout_value->length = 0u;
        return st;
    }
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_GET_REWRITE_PTR)) {
        if (inout_value != NULL) {
            inout_value->data = c->poison_scratch;
            inout_value->length = 1u;
        }
        return NINLIL_STORAGE_OK;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_GET_NOTFOUND_POISON)) {
        if (inout_value != NULL) {
            inout_value->length = 3u;
            if (inout_value->data != NULL && inout_value->capacity > 0u) {
                inout_value->data[0] = 0xFFu;
            }
        }
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_GET_OK_TAIL)) {
        if (inout_value != NULL && inout_value->data != NULL
            && inout_value->capacity >= 4u) {
            inout_value->data[0] = 0x01u;
            inout_value->length = 1u;
            inout_value->data[2] = 0xEEu; /* tail beyond length */
        }
        return NINLIL_STORAGE_OK;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_GET_BTS)) {
        if (inout_value != NULL) {
            inout_value->length = inout_value->capacity + 8u;
        }
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_GET_BTS_POISON)) {
        if (inout_value != NULL) {
            inout_value->length = inout_value->capacity + 8u;
            if (inout_value->data != NULL && inout_value->capacity > 0u) {
                inout_value->data[0] = 0xEEu;
            }
        }
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_GET_NOSPACE)) {
        if (inout_value != NULL) {
            inout_value->length = 0u;
        }
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_GET_UNKNOWN)) {
        return (ninlil_storage_status_t)99u;
    }
    if (c->fail_get != 0 || n6ms_hit_fault(c, N6_MEM_FAULT_GET)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (inout_value == NULL || key.data == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    e = n6ms_find(c->stage, key.data, key.length);
    if (e == NULL) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (inout_value->capacity < e->vlen) {
        inout_value->length = e->vlen;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    (void)memcpy(inout_value->data, e->val, e->vlen);
    inout_value->length = e->vlen;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t n6ms_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    n6ms_entry_t *e;
    uint32_t i;
    (void)txn;
    c->put_count += 1u;
    {
        int pslot = 0;
        if (n6ms_hit_program(c, N6_MEM_PROG_PUT, &pslot)) {
            return n6ms_prog_st(c, pslot);
        }
    }
    if (c->txn_rw == 0 || c->fail_put != 0
        || n6ms_hit_fault(c, N6_MEM_FAULT_PUT)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (key.length > N6MS_MAX_KEY || value.length > N6MS_MAX_VAL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    e = n6ms_find(c->stage, key.data, key.length);
    if (e == NULL) {
        for (i = 0u; i < N6MS_MAX_ENTRIES; ++i) {
            if (c->stage[i].live == 0) {
                e = &c->stage[i];
                break;
            }
        }
    }
    if (e == NULL) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    e->live = 1;
    e->klen = key.length;
    e->vlen = value.length;
    (void)memcpy(e->key, key.data, key.length);
    (void)memcpy(e->val, value.data, value.length);
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t n6ms_erase(
    void *user, ninlil_storage_txn_t txn, ninlil_bytes_view_t key)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    n6ms_entry_t *e;
    (void)txn;
    c->erase_count += 1u;
    if (c->txn_rw == 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    e = n6ms_find(c->stage, key.data, key.length);
    if (e == NULL) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    e->live = 0;
    return NINLIL_STORAGE_OK;
}

/* Unsigned lexicographic key compare (strict provider scan order). */
static int n6ms_key_cmp(
    const n6ms_entry_t *a, const n6ms_entry_t *b)
{
    uint32_t n = (a->klen < b->klen) ? a->klen : b->klen;
    int c = 0;
    if (n > 0u) {
        c = memcmp(a->key, b->key, n);
        if (c != 0) {
            return c;
        }
    }
    if (a->klen < b->klen) {
        return -1;
    }
    if (a->klen > b->klen) {
        return 1;
    }
    return 0;
}

static ninlil_storage_status_t n6ms_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    uint32_t i, j;
    (void)txn;
    (void)prefix;
    c->iter_open_count += 1u;
    if (out_iter != NULL) {
        *out_iter = NULL;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_OPEN_NONOK_HANDLE)) {
        /* Malformed: non-OK + non-NULL iter */
        if (out_iter != NULL) {
            *out_iter = (ninlil_storage_iter_t)(uintptr_t)3;
        }
        c->iter_live = 1;
        c->iter_idx = 0u;
        c->iter_order_n = 0u;
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_OPEN_OK_NULL)) {
        return NINLIL_STORAGE_OK; /* OK + NULL */
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_OPEN)) {
        return NINLIL_STORAGE_IO_ERROR; /* operational NULL */
    }
    /* Build lex-sorted index of live stage entries (insertion order is not order). */
    c->iter_order_n = 0u;
    for (i = 0u; i < N6MS_MAX_ENTRIES; ++i) {
        if (c->stage[i].live == 0) {
            continue;
        }
        j = c->iter_order_n;
        while (j > 0u
            && n6ms_key_cmp(
                   &c->stage[c->iter_order[j - 1u]], &c->stage[i])
                > 0) {
            c->iter_order[j] = c->iter_order[j - 1u];
            j -= 1u;
        }
        c->iter_order[j] = i;
        c->iter_order_n += 1u;
    }
    c->iter_live = 1;
    c->iter_idx = 0u;
    if (out_iter == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    *out_iter = (ninlil_storage_iter_t)(uintptr_t)3;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t n6ms_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    n6ms_entry_t *e;
    (void)iter;
    c->iter_next_count += 1u;
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT_REWRITE_PTR)) {
        if (inout_key != NULL) {
            inout_key->data = c->poison_scratch;
        }
        return NINLIL_STORAGE_OK;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT_NOTFOUND_POISON)) {
        if (inout_key != NULL) {
            inout_key->length = 2u;
            if (inout_key->data != NULL && inout_key->capacity > 0u) {
                inout_key->data[0] = 0xFFu;
            }
        }
        if (inout_value != NULL) {
            inout_value->length = 1u;
        }
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT_OK_OVERSIZE)) {
        if (inout_key != NULL) {
            inout_key->length = inout_key->capacity + 4u;
        }
        if (inout_value != NULL) {
            inout_value->length = 1u;
        }
        return NINLIL_STORAGE_OK;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT_OK_TAIL)) {
        if (inout_key != NULL && inout_key->data != NULL
            && inout_key->capacity >= 8u) {
            inout_key->data[0] = 0x01u;
            inout_key->length = 1u;
            inout_key->data[4] = 0xEEu; /* tail beyond length */
        }
        if (inout_value != NULL) {
            inout_value->length = 0u;
        }
        return NINLIL_STORAGE_OK;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT_BTS)) {
        /* Both required lengths non-zero; at least one > capacity. */
        if (inout_key != NULL) {
            inout_key->length = inout_key->capacity + 16u;
        }
        if (inout_value != NULL) {
            inout_value->length = inout_value->capacity + 8u;
        }
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT_BTS_BAD)) {
        /* Invalid BTS: key required length 0 (forbidden) */
        if (inout_key != NULL) {
            inout_key->length = 0u;
        }
        if (inout_value != NULL) {
            inout_value->length = inout_value->capacity + 8u;
        }
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT_UNKNOWN)) {
        return (ninlil_storage_status_t)99u;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ITER_NEXT)) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (c->iter_live == 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (c->iter_idx >= c->iter_order_n) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    e = &c->stage[c->iter_order[c->iter_idx++]];
    if (e->live == 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (inout_key->capacity < e->klen || inout_value->capacity < e->vlen) {
        inout_key->length = e->klen;
        inout_value->length = e->vlen;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    (void)memcpy(inout_key->data, e->key, e->klen);
    inout_key->length = e->klen;
    (void)memcpy(inout_value->data, e->val, e->vlen);
    inout_value->length = e->vlen;
    return NINLIL_STORAGE_OK;
}

static void n6ms_iter_close(void *user, ninlil_storage_iter_t iter)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    (void)iter;
    c->iter_close_count += 1u;
    c->iter_live = 0;
}

static ninlil_storage_status_t n6ms_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    (void)handle;
    c->capacity_count += 1u;
    {
    int pslot = 0;
    if (n6ms_hit_program(c, N6_MEM_PROG_CAPACITY, &pslot)) {
        ninlil_storage_status_t st = n6ms_prog_st(c, pslot);
        n6_mem_prog_shape_t sh = n6ms_prog_sh(c, pslot);
        if (sh == N6_MEM_SHAPE_CAP_POISON && out_capacity != NULL) {
            out_capacity->abi_version = 0xFFFFu;
            out_capacity->struct_size = 3u;
            out_capacity->max_entries = 9u;
            out_capacity->used_entries = 1u;
            out_capacity->max_bytes = 9u;
            out_capacity->used_bytes = 1u;
            return st == NINLIL_STORAGE_OK ? NINLIL_STORAGE_IO_ERROR : st;
        }
        if (sh == N6_MEM_SHAPE_CAP_BAD_OK && out_capacity != NULL) {
            out_capacity->abi_version = 1u;
            out_capacity->struct_size =
                (uint16_t)(sizeof(*out_capacity) + 4u);
            out_capacity->max_entries = 0u;
            out_capacity->used_entries = 0u;
            out_capacity->max_bytes = 0u;
            out_capacity->used_bytes = 0u;
            return NINLIL_STORAGE_OK;
        }
        /* DEFAULT clean: leave preseed unchanged on non-OK */
        if (st == NINLIL_STORAGE_OK && out_capacity != NULL) {
            out_capacity->abi_version = 1u;
            out_capacity->struct_size = (uint16_t)sizeof(*out_capacity);
            out_capacity->max_entries = c->cap_max_entries;
            out_capacity->used_entries = c->cap_used_entries;
            out_capacity->max_bytes = c->cap_max_bytes;
            out_capacity->used_bytes = c->cap_used_bytes;
        }
        return st;
    }
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_CAPACITY_POISON)) {
        if (out_capacity != NULL) {
            out_capacity->abi_version = 0xFFFFu;
            out_capacity->struct_size = 3u;
            out_capacity->max_entries = 9u;
            out_capacity->used_entries = 1u;
            out_capacity->max_bytes = 9u;
            out_capacity->used_bytes = 1u;
        }
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_CAPACITY_BAD_OK)) {
        if (out_capacity != NULL) {
            out_capacity->abi_version = 1u;
            out_capacity->struct_size =
                (uint16_t)(sizeof(*out_capacity) + 4u); /* not exact */
            out_capacity->max_entries = 0u;
            out_capacity->used_entries = 0u;
            out_capacity->max_bytes = 0u;
            out_capacity->used_bytes = 0u;
        }
        return NINLIL_STORAGE_OK;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_CAPACITY_UNKNOWN)) {
        /* non-OK unknown; leave preseed header/numerics unchanged */
        return (ninlil_storage_status_t)99u;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_CAPACITY_NOSPACE)) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_CAPACITY)) {
        /* operational: leave preseed header/numerics unchanged */
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (out_capacity == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    out_capacity->abi_version = 1u;
    out_capacity->struct_size = (uint16_t)sizeof(*out_capacity);
    out_capacity->max_entries = c->cap_max_entries;
    out_capacity->used_entries = c->cap_used_entries;
    out_capacity->max_bytes = c->cap_max_bytes;
    out_capacity->used_bytes = c->cap_used_bytes;
    return NINLIL_STORAGE_OK;
}

static void n6ms_apply_third(n6ms_entry_t *dst, const n6ms_entry_t *src)
{
    uint32_t i;
    *dst = *src;
    /* Mutate payload so it matches neither old nor proposed. */
    for (i = 0u; i < dst->vlen && i < 8u; ++i) {
        dst->val[i] ^= 0x5Au;
    }
    if (dst->vlen == 0u) {
        dst->vlen = 1u;
        dst->val[0] = 0xA5u;
    }
}

static ninlil_storage_status_t n6ms_commit(
    void *user, ninlil_storage_txn_t txn, ninlil_durability_t durability)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    n6_mem_cu_outcome_t outcome;
    (void)txn;
    if (c->txn_live == 0) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    c->commit_count += 1u;
    {
        int pslot = 0;
        if (n6ms_hit_program(c, N6_MEM_PROG_COMMIT, &pslot)) {
            /* txn always consumed on commit */
            c->txn_live = 0;
            return n6ms_prog_st(c, pslot);
        }
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_COMMIT)) {
        /* txn consumed on all commit statuses */
        c->txn_live = 0;
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_COMMIT_CORRUPT)) {
        c->txn_live = 0;
        return NINLIL_STORAGE_CORRUPT;
    }
    if (c->inject_cu != N6_MEM_CU_NONE && durability == NINLIL_DURABILITY_FULL) {
        outcome = c->inject_cu;
        c->inject_cu = N6_MEM_CU_NONE;
        c->txn_live = 0;
        if (outcome == N6_MEM_CU_ALL_OLD) {
            /* discard staging */
            return NINLIL_STORAGE_COMMIT_UNKNOWN;
        }
        if (outcome == N6_MEM_CU_ALL_PROPOSED) {
            if (c->txn_rw != 0) {
                (void)memcpy(c->table, c->stage, sizeof(c->table));
            }
            return NINLIL_STORAGE_COMMIT_UNKNOWN;
        }
        if (outcome == N6_MEM_CU_MIXED) {
            /* Apply only the first live stage entry that differs from table. */
            uint32_t i;
            for (i = 0u; i < N6MS_MAX_ENTRIES; ++i) {
                n6ms_entry_t *s = &c->stage[i];
                n6ms_entry_t *t;
                if (s->live == 0) {
                    continue;
                }
                t = n6ms_find(c->table, s->key, s->klen);
                if (t == NULL
                    || t->vlen != s->vlen
                    || memcmp(t->val, s->val, s->vlen) != 0) {
                    if (t == NULL) {
                        uint32_t j;
                        for (j = 0u; j < N6MS_MAX_ENTRIES; ++j) {
                            if (c->table[j].live == 0) {
                                t = &c->table[j];
                                break;
                            }
                        }
                    }
                    if (t != NULL) {
                        *t = *s;
                    }
                    break;
                }
            }
            return NINLIL_STORAGE_COMMIT_UNKNOWN;
        }
        if (outcome == N6_MEM_CU_THIRD) {
            uint32_t i;
            for (i = 0u; i < N6MS_MAX_ENTRIES; ++i) {
                n6ms_entry_t *s = &c->stage[i];
                n6ms_entry_t *t;
                if (s->live == 0) {
                    continue;
                }
                t = n6ms_find(c->table, s->key, s->klen);
                if (t == NULL) {
                    uint32_t j;
                    for (j = 0u; j < N6MS_MAX_ENTRIES; ++j) {
                        if (c->table[j].live == 0) {
                            t = &c->table[j];
                            break;
                        }
                    }
                }
                if (t != NULL) {
                    n6ms_apply_third(t, s);
                }
            }
            return NINLIL_STORAGE_COMMIT_UNKNOWN;
        }
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    if (c->txn_rw != 0) {
        (void)memcpy(c->table, c->stage, sizeof(c->table));
    }
    c->txn_live = 0;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t n6ms_rollback(
    void *user, ninlil_storage_txn_t txn)
{
    n6ms_ctx_t *c = (n6ms_ctx_t *)user;
    (void)txn;
    c->rollback_count += 1u;
    {
        int pslot = 0;
        if (n6ms_hit_program(c, N6_MEM_PROG_ROLLBACK, &pslot)) {
            /* txn consumed even on non-OK rollback */
            c->txn_live = 0;
            return n6ms_prog_st(c, pslot);
        }
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ROLLBACK)
        || n6ms_hit_fault(c, N6_MEM_FAULT_ROLLBACK_BUSY)) {
        c->txn_live = 0;
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (n6ms_hit_fault(c, N6_MEM_FAULT_ROLLBACK_NOSPACE)) {
        c->txn_live = 0;
        return NINLIL_STORAGE_NO_SPACE;
    }
    c->txn_live = 0;
    return NINLIL_STORAGE_OK;
}

static void n6ms_bind_ops(void)
{
    g_n6ms.ops.abi_version = 1u;
    g_n6ms.ops.struct_size = (uint16_t)sizeof(g_n6ms.ops);
    g_n6ms.ops.user = &g_n6ms;
    g_n6ms.ops.open = n6ms_open;
    g_n6ms.ops.close = n6ms_close;
    g_n6ms.ops.begin = n6ms_begin;
    g_n6ms.ops.get = n6ms_get;
    g_n6ms.ops.put = n6ms_put;
    g_n6ms.ops.erase = n6ms_erase;
    g_n6ms.ops.iter_open = n6ms_iter_open;
    g_n6ms.ops.iter_next = n6ms_iter_next;
    g_n6ms.ops.iter_close = n6ms_iter_close;
    g_n6ms.ops.capacity = n6ms_capacity;
    g_n6ms.ops.commit = n6ms_commit;
    g_n6ms.ops.rollback = n6ms_rollback;
}

const ninlil_storage_ops_t *n6_mem_storage_ops(void)
{
    if (g_n6ms.ops.open == NULL) {
        n6ms_bind_ops();
    }
    g_n6ms.ops.user = &g_n6ms;
    return &g_n6ms.ops;
}

void n6_mem_storage_reset(void)
{
    (void)memset(&g_n6ms, 0, sizeof(g_n6ms));
    g_n6ms.cap_max_entries = N6MS_MAX_ENTRIES;
    g_n6ms.cap_used_entries = 0u;
    g_n6ms.cap_max_bytes = 1024u * 1024u;
    g_n6ms.cap_used_bytes = 0u;
    n6ms_bind_ops();
}

void n6_mem_storage_inject_cu(n6_mem_cu_outcome_t outcome)
{
    g_n6ms.inject_cu = outcome;
}

void n6_mem_storage_inject_fault(n6_mem_fault_t fault, int remaining_hits)
{
    g_n6ms.fault = fault;
    g_n6ms.fault_hits = remaining_hits;
    g_n6ms.fault_skip = 0;
}

void n6_mem_storage_inject_fault_after(
    n6_mem_fault_t fault, int skip_count, int remaining_hits)
{
    g_n6ms.fault = fault;
    g_n6ms.fault_hits = remaining_hits;
    g_n6ms.fault_skip = skip_count;
}

static int n6ms_prog_pick_slot(void)
{
    int s;
    for (s = 0; s < 2; ++s) {
        if (g_n6ms.prog_op[s] == N6_MEM_PROG_NONE || g_n6ms.prog_hits[s] <= 0) {
            return s;
        }
    }
    return 0; /* overwrite slot 0 if both busy */
}

void n6_mem_storage_program(
    n6_mem_prog_op_t op, ninlil_storage_status_t status,
    n6_mem_prog_shape_t shape, int remaining_hits)
{
    int s = n6ms_prog_pick_slot();
    g_n6ms.prog_op[s] = op;
    g_n6ms.prog_status[s] = status;
    g_n6ms.prog_shape[s] = shape;
    g_n6ms.prog_hits[s] = remaining_hits;
    g_n6ms.prog_skip[s] = 0;
}

void n6_mem_storage_program_after(
    n6_mem_prog_op_t op, ninlil_storage_status_t status,
    n6_mem_prog_shape_t shape, int skip_count, int remaining_hits)
{
    int s = n6ms_prog_pick_slot();
    g_n6ms.prog_op[s] = op;
    g_n6ms.prog_status[s] = status;
    g_n6ms.prog_shape[s] = shape;
    g_n6ms.prog_hits[s] = remaining_hits;
    g_n6ms.prog_skip[s] = skip_count;
}

void n6_mem_storage_clear_program(void)
{
    int s;
    for (s = 0; s < 2; ++s) {
        g_n6ms.prog_op[s] = N6_MEM_PROG_NONE;
        g_n6ms.prog_hits[s] = 0;
        g_n6ms.prog_skip[s] = 0;
        g_n6ms.prog_shape[s] = N6_MEM_SHAPE_DEFAULT;
        g_n6ms.prog_status[s] = NINLIL_STORAGE_OK;
    }
}

void n6_mem_storage_fail_get(int v)
{
    g_n6ms.fail_get = v;
}

void n6_mem_storage_fail_put(int v)
{
    g_n6ms.fail_put = v;
}

int n6_mem_storage_seed(
    const uint8_t *key, uint32_t klen, const uint8_t *val, uint32_t vlen)
{
    uint32_t i;
    n6ms_entry_t *e;
    if (key == NULL || val == NULL || klen > N6MS_MAX_KEY
        || vlen > N6MS_MAX_VAL) {
        return -1;
    }
    e = n6ms_find(g_n6ms.table, key, klen);
    if (e == NULL) {
        for (i = 0u; i < N6MS_MAX_ENTRIES; ++i) {
            if (g_n6ms.table[i].live == 0) {
                e = &g_n6ms.table[i];
                break;
            }
        }
    }
    if (e == NULL) {
        return -1;
    }
    e->live = 1;
    e->klen = klen;
    e->vlen = vlen;
    (void)memcpy(e->key, key, klen);
    (void)memcpy(e->val, val, vlen);
    return 0;
}

int n6_mem_storage_seed_append(
    const uint8_t *key, uint32_t klen, const uint8_t *val, uint32_t vlen)
{
    uint32_t i;
    n6ms_entry_t *e = NULL;
    if (key == NULL || val == NULL || klen > N6MS_MAX_KEY
        || vlen > N6MS_MAX_VAL) {
        return -1;
    }
    for (i = 0u; i < N6MS_MAX_ENTRIES; ++i) {
        if (g_n6ms.table[i].live == 0) {
            e = &g_n6ms.table[i];
            break;
        }
    }
    if (e == NULL) {
        return -1;
    }
    e->live = 1;
    e->klen = klen;
    e->vlen = vlen;
    (void)memcpy(e->key, key, klen);
    (void)memcpy(e->val, val, vlen);
    return 0;
}

void n6_mem_storage_set_capacity(
    uint64_t max_entries, uint64_t used_entries, uint64_t max_bytes,
    uint64_t used_bytes)
{
    g_n6ms.cap_max_entries = max_entries;
    g_n6ms.cap_used_entries = used_entries;
    g_n6ms.cap_max_bytes = max_bytes;
    g_n6ms.cap_used_bytes = used_bytes;
}

uint32_t n6_mem_storage_close_count(void)
{
    return g_n6ms.close_count;
}

uint32_t n6_mem_storage_open_count(void)
{
    return g_n6ms.open_count;
}

uint32_t n6_mem_storage_begin_count(void)
{
    return g_n6ms.begin_count;
}

uint32_t n6_mem_storage_iter_open_count(void)
{
    return g_n6ms.iter_open_count;
}

uint32_t n6_mem_storage_iter_close_count(void)
{
    return g_n6ms.iter_close_count;
}

uint32_t n6_mem_storage_iter_next_count(void)
{
    return g_n6ms.iter_next_count;
}

uint32_t n6_mem_storage_commit_count(void)
{
    return g_n6ms.commit_count;
}

uint32_t n6_mem_storage_rollback_count(void)
{
    return g_n6ms.rollback_count;
}

uint32_t n6_mem_storage_get_count(void)
{
    return g_n6ms.get_count;
}

uint32_t n6_mem_storage_put_count(void)
{
    return g_n6ms.put_count;
}

uint32_t n6_mem_storage_erase_count(void)
{
    return g_n6ms.erase_count;
}

uint32_t n6_mem_storage_capacity_count(void)
{
    return g_n6ms.capacity_count;
}
