/* SPDX-License-Identifier: Apache-2.0
 * ESP durable FULL adapter for MFDT — real ninlil_storage_ops when bound.
 *
 * ESP media port often returns STORAGE_COMMIT_UNKNOWN even after a real write
 * (ESP_UNPROVEN policy). Production rule:
 *   - never treat CU as automatic OK with process-local-only mirror
 *   - on CU: durable read-back each staged key and classify:
 *       all NEW  → raw durable classification + local mirror;
 *                  ERR_CU_NEW_NOT_PROMOTED (not external OK)
 *       all OLD  → retryable (ERR_STORAGE), no NEW custody
 *       mixed / corrupt / third → fence (ERR_COMMIT_UNKNOWN)
 *   - STORAGE_OK → local mirror + OK
 *
 * Transaction handles live in a typed pointer-width context (never uint32).
 */
#include "mfdt_v1.h"
#include "mfdt_v1_target_alloc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ninlil/platform.h"

typedef struct mfdt_esp_bind {
    const ninlil_storage_ops_t *ops;
    ninlil_storage_handle_t handle;
    uint8_t bound;
} mfdt_esp_bind_t;

typedef struct mfdt_esp_txn_ctx {
    ninlil_storage_txn_t txn;
    ninlil_mfdt_v1_lab_store_t *owner_st;
    uint8_t active;
    /* Pre-put durable OLD snapshots for post-CU read-classify. */
    uint8_t old_present[NINLIL_MFDT_V1_LAB_MAX_OPS];
    uint32_t old_len[NINLIL_MFDT_V1_LAB_MAX_OPS];
    uint32_t old_off[NINLIL_MFDT_V1_LAB_MAX_OPS];
    uint32_t old_used;
    /* Heap/SPIRAM on ESP; not .dram0.bss (was ~50KB static). */
    uint8_t *old_pool;
    uint32_t old_pool_cap;
} mfdt_esp_txn_ctx_t;

static mfdt_esp_bind_t g_esp;
static mfdt_esp_txn_ctx_t g_esp_txn;

/* Single-key durable read-back buffer — SPIRAM/heap, not .dram0.bss. */
static uint8_t *g_esp_readback;

static int ensure_esp_bulk(void)
{
    if (g_esp_readback == NULL) {
        g_esp_readback = (uint8_t *)ninlil_mfdt_v1_target_zalloc(
            (size_t)NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    }
    if (g_esp_txn.old_pool == NULL) {
        g_esp_txn.old_pool = (uint8_t *)ninlil_mfdt_v1_target_zalloc(
            (size_t)NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES);
        g_esp_txn.old_pool_cap = NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES;
    }
    return (g_esp_readback != NULL && g_esp_txn.old_pool != NULL) ? 1 : 0;
}

/* HIL gate + CU class latch: portable mfdt_v1_hil_gate.c (PRODUCTION). */

int ninlil_mfdt_v1_esp_store_bind(const void *storage_ops, void *storage_handle)
{
    const ninlil_storage_ops_t *ops;

    if (storage_ops == NULL) {
        g_esp.bound = 0u;
        g_esp.ops = NULL;
        g_esp.handle = NULL;
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    ops = (const ninlil_storage_ops_t *)storage_ops;
    /*
     * FULL delete path requires begin/get/put/erase/commit/rollback.
     * Missing erase must not be accepted (would silent-skip deletes).
     */
    if (ops->begin == NULL || ops->get == NULL || ops->put == NULL ||
        ops->erase == NULL || ops->commit == NULL || ops->rollback == NULL) {
        g_esp.bound = 0u;
        g_esp.ops = NULL;
        g_esp.handle = NULL;
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    /* Do not leave an older binding published if fixed-bulk startup fails. */
    g_esp.bound = 0u;
    g_esp.ops = NULL;
    g_esp.handle = NULL;
    if (ensure_esp_bulk() == 0) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    g_esp.ops = ops;
    g_esp.handle = (ninlil_storage_handle_t)storage_handle;
    g_esp.bound = 1u;
    return NINLIL_MFDT_V1_OK;
}

void ninlil_mfdt_v1_esp_store_unbind(void)
{
    uint8_t *old_pool;
    uint32_t old_cap;

    if (g_esp_txn.active && g_esp.ops != NULL && g_esp.ops->rollback != NULL &&
        g_esp_txn.txn != NULL) {
        (void)g_esp.ops->rollback(g_esp.ops->user, g_esp_txn.txn);
    }
    /* Preserve heap buffers across unbind; zero metadata only. */
    old_pool = g_esp_txn.old_pool;
    old_cap = g_esp_txn.old_pool_cap;
    ninlil_mfdt_v1_memzero(&g_esp_txn, sizeof(g_esp_txn));
    g_esp_txn.old_pool = old_pool;
    g_esp_txn.old_pool_cap = old_cap;
    if (old_pool != NULL && old_cap > 0u) {
        ninlil_mfdt_v1_memzero(old_pool, old_cap);
    }
    g_esp.bound = 0u;
    g_esp.ops = NULL;
    g_esp.handle = NULL;
}

void ninlil_mfdt_v1_lab_store_init(ninlil_mfdt_v1_lab_store_t *st)
{
    if (st != NULL) {
        ninlil_mfdt_v1_memzero(st, sizeof(*st));
    }
}

static int key_eq(const uint8_t *a, const uint8_t *b)
{
    return ninlil_mfdt_v1_memeq(a, b, 20u);
}

static int find_row(const ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20])
{
    size_t i;
    for (i = 0; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        if (st->rows[i].occupied && key_eq(st->rows[i].key, key)) {
            return (int)i;
        }
    }
    return -1;
}

static int free_row(ninlil_mfdt_v1_lab_store_t *st)
{
    size_t i;
    for (i = 0; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        if (!st->rows[i].occupied) {
            return (int)i;
        }
    }
    return -1;
}

static int apply_local_put(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20],
                           const uint8_t *value, uint32_t value_len)
{
    int idx;
    uint8_t *slot;
    idx = find_row(st, key);
    if (idx < 0) {
        idx = free_row(st);
        if (idx < 0) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        if (st->pool_used + value_len > NINLIL_MFDT_V1_LAB_VALUE_POOL_BYTES) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        slot = st->value_pool + st->pool_used;
        st->pool_used += value_len;
        st->rows[idx].value = slot;
        st->rows[idx].occupied = 1u;
        (void)memcpy(st->rows[idx].key, key, 20u);
        st->rows[idx].key_len = 20u;
    } else if (value_len > st->rows[idx].value_len) {
        if (st->pool_used + value_len > NINLIL_MFDT_V1_LAB_VALUE_POOL_BYTES) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        slot = st->value_pool + st->pool_used;
        st->pool_used += value_len;
        st->rows[idx].value = slot;
    }
    if (value_len > 0u && value != NULL) {
        (void)memcpy(st->rows[idx].value, value, value_len);
    }
    st->rows[idx].value_len = value_len;
    return NINLIL_MFDT_V1_OK;
}

static void apply_local_del(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20])
{
    int idx = find_row(st, key);
    if (idx >= 0) {
        st->rows[idx].occupied = 0u;
        st->rows[idx].value = NULL;
        st->rows[idx].value_len = 0u;
    }
}

static int apply_staging_local(ninlil_mfdt_v1_lab_store_t *st)
{
    uint8_t i;
    for (i = 0u; i < st->op_count; ++i) {
        ninlil_mfdt_v1_lab_op_t *o = &st->ops[i];
        int rc;
        if (!o->valid) {
            continue;
        }
        if (o->op == 1u) {
            apply_local_del(st, o->key);
        } else {
            const uint8_t *v =
                (o->value_len > 0u) ? (st->staging_pool + o->pool_off) : NULL;
            rc = apply_local_put(st, o->key, v, o->value_len);
            if (rc != NINLIL_MFDT_V1_OK) {
                return rc;
            }
        }
    }
    return NINLIL_MFDT_V1_OK;
}

static void clear_txn_ctx(void)
{
    uint8_t *old_pool = g_esp_txn.old_pool;
    uint32_t old_cap = g_esp_txn.old_pool_cap;

    ninlil_mfdt_v1_memzero(&g_esp_txn, sizeof(g_esp_txn));
    g_esp_txn.old_pool = old_pool;
    g_esp_txn.old_pool_cap = old_cap;
    if (old_pool != NULL && old_cap > 0u) {
        ninlil_mfdt_v1_memzero(old_pool, old_cap);
    }
}

static void discard_staging(ninlil_mfdt_v1_lab_store_t *st)
{
    st->txn_open = 0u;
    st->op_count = 0u;
    st->staging_pool_used = 0u;
    ninlil_mfdt_v1_memzero(st->ops, sizeof(st->ops));
}

/*
 * Durable get. out may be NULL for length-only probe (ABI used by restart).
 * When out is NULL, g_esp_readback is used only to satisfy storage get API;
 * *out_len is still set. No large stack frame.
 */
static int durable_get(const uint8_t key[20], uint8_t *out, uint32_t cap,
                       uint32_t *out_len)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t s;
    ninlil_bytes_view_t k;
    ninlil_mut_bytes_t v;
    uint8_t *buf;
    uint32_t buf_cap;

    if (!g_esp.bound || g_esp.ops == NULL || g_esp.ops->begin == NULL ||
        g_esp.ops->get == NULL || out_len == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    if (out != NULL) {
        buf = out;
        buf_cap = cap;
    } else {
        /* Prepared by esp_store_bind(); never allocate in a read operation. */
        if (g_esp_readback == NULL) {
            return NINLIL_MFDT_V1_ERR_STORAGE;
        }
        buf = g_esp_readback;
        buf_cap = NINLIL_MFDT_V1_ACTIVE_VALUE_MAX;
    }
    s = g_esp.ops->begin(g_esp.ops->user, g_esp.handle, NINLIL_STORAGE_READ_ONLY,
                         &txn);
    if (s != NINLIL_STORAGE_OK || txn == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    k.data = key;
    k.length = 20u;
    v.data = buf;
    v.capacity = buf_cap;
    v.length = 0u;
    s = g_esp.ops->get(g_esp.ops->user, txn, k, &v);
    if (g_esp.ops->rollback != NULL) {
        (void)g_esp.ops->rollback(g_esp.ops->user, txn);
    }
    if (s == NINLIL_STORAGE_NOT_FOUND) {
        *out_len = 0u;
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (s == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        /* Length query: storage reports required length in v.length. */
        *out_len = v.length;
        if (out == NULL) {
            return NINLIL_MFDT_V1_OK;
        }
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (s != NINLIL_STORAGE_OK) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    *out_len = v.length;
    return NINLIL_MFDT_V1_OK;
}

/* Snapshot durable OLD for op index into old_pool (before put overwrites media). */
static int capture_old_for_op(uint8_t op_index, const uint8_t key[20])
{
    uint32_t len = 0u;
    int rc;
    if (op_index >= NINLIL_MFDT_V1_LAB_MAX_OPS) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (g_esp_txn.old_used > NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES - g_esp_txn.old_used <
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX &&
        NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES - g_esp_txn.old_used < 1u) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    {
        uint32_t cap = NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES - g_esp_txn.old_used;
        if (cap > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) {
            cap = NINLIL_MFDT_V1_ACTIVE_VALUE_MAX;
        }
        rc = durable_get(key, g_esp_txn.old_pool + g_esp_txn.old_used, cap, &len);
    }
    if (rc == NINLIL_MFDT_V1_ERR_STATE) {
        g_esp_txn.old_present[op_index] = 0u;
        g_esp_txn.old_len[op_index] = 0u;
        g_esp_txn.old_off[op_index] = g_esp_txn.old_used;
        return NINLIL_MFDT_V1_OK;
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    g_esp_txn.old_present[op_index] = 1u;
    g_esp_txn.old_len[op_index] = len;
    g_esp_txn.old_off[op_index] = g_esp_txn.old_used;
    g_esp_txn.old_used += len;
    return NINLIL_MFDT_V1_OK;
}

/*
 * After COMMIT_UNKNOWN: read-back durable and classify group.
 * Returns OK (all NEW), ERR_STORAGE (all OLD → retry), ERR_COMMIT_UNKNOWN (fence).
 */
static int resolve_commit_unknown(const ninlil_mfdt_v1_lab_store_t *st)
{
    uint8_t i;
    int saw = 0;
    int all_new = 1;
    int all_old = 1;

    for (i = 0u; i < st->op_count; ++i) {
        const ninlil_mfdt_v1_lab_op_t *o = &st->ops[i];
        uint32_t rlen = 0u;
        int grc;
        ninlil_mfdt_v1_cu_class_t c;
        if (!o->valid) {
            continue;
        }
        saw = 1;
        if (o->op == 1u) {
            /*
             * Delete CU: NEW intent = key absent. OLD = exact match of
             * captured pre-delete bytes. Anything else (wrong length/value)
             * is THIRD/corrupt → fence.
             */
            grc = durable_get(o->key, g_esp_readback, NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
                              &rlen);
            if (grc == NINLIL_MFDT_V1_ERR_STATE) {
                all_old = 0; /* absent = NEW for delete */
            } else if (grc == NINLIL_MFDT_V1_OK) {
                if (g_esp_txn.old_present[i] != 0u) {
                    const uint8_t *oldb =
                        g_esp_txn.old_pool + g_esp_txn.old_off[i];
                    uint32_t olen = g_esp_txn.old_len[i];
                    if (rlen == olen &&
                        ninlil_mfdt_v1_memeq(g_esp_readback, oldb, olen)) {
                        all_new = 0; /* exact OLD retained */
                    } else {
                        /* present but not exact OLD → third/corrupt fence */
                        return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
                    }
                } else {
                    /* no pre-image, still present → third/corrupt */
                    return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
                }
            } else {
                return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
            }
            continue;
        }
        grc = durable_get(o->key, g_esp_readback, NINLIL_MFDT_V1_ACTIVE_VALUE_MAX, &rlen);
        if (grc != NINLIL_MFDT_V1_OK && grc != NINLIL_MFDT_V1_ERR_STATE) {
            return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
        }
        {
            const uint8_t *newb =
                (o->value_len > 0u) ? (st->staging_pool + o->pool_off) : NULL;
            const uint8_t *oldb = NULL;
            uint32_t olen = 0u;
            int has_old = 0;
            if (g_esp_txn.old_present[i]) {
                has_old = 1;
                olen = g_esp_txn.old_len[i];
                oldb = g_esp_txn.old_pool + g_esp_txn.old_off[i];
            }
            c = ninlil_mfdt_v1_classify_cu_bytes(
                (grc == NINLIL_MFDT_V1_OK) ? g_esp_readback : NULL, rlen,
                grc == NINLIL_MFDT_V1_OK ? 1 : 0, oldb, olen, has_old, newb,
                o->value_len, 1);
        }
        if (c == NINLIL_MFDT_V1_CU_NEW) {
            all_old = 0;
        } else if (c == NINLIL_MFDT_V1_CU_OLD || c == NINLIL_MFDT_V1_CU_ABSENT) {
            /* ABSENT after put: write did not stick → OLD-side / retryable. */
            all_new = 0;
        } else {
            /* PARTIAL / EXTRA / THIRD / BOTH → fence */
            return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
        }
    }
    if (!saw) {
        return NINLIL_MFDT_V1_OK;
    }
    if (all_new) {
        return NINLIL_MFDT_V1_OK;
    }
    if (all_old) {
        return NINLIL_MFDT_V1_ERR_STORAGE; /* retryable: media stayed OLD */
    }
    return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
}

int ninlil_mfdt_v1_lab_full_begin(ninlil_mfdt_v1_lab_store_t *st)
{
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t s;
    uint8_t *old_pool;
    uint32_t old_cap;
    if (st == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (st->txn_open || g_esp_txn.active) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (!g_esp.bound || g_esp.ops == NULL || g_esp.ops->begin == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    /* Prepared by esp_store_bind(); never allocate after transaction start. */
    if (g_esp_readback == NULL || g_esp_txn.old_pool == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    s = g_esp.ops->begin(g_esp.ops->user, g_esp.handle, NINLIL_STORAGE_READ_WRITE,
                         &txn);
    if (s != NINLIL_STORAGE_OK || txn == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    old_pool = g_esp_txn.old_pool;
    old_cap = g_esp_txn.old_pool_cap;
    ninlil_mfdt_v1_memzero(&g_esp_txn, sizeof(g_esp_txn));
    g_esp_txn.old_pool = old_pool;
    g_esp_txn.old_pool_cap = old_cap;
    g_esp_txn.txn = txn;
    g_esp_txn.owner_st = st;
    g_esp_txn.active = 1u;
    st->txn_open = 1u;
    st->op_count = 0u;
    st->staging_pool_used = 0u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_put(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20],
                           const uint8_t *value, uint32_t value_len)
{
    ninlil_mfdt_v1_lab_op_t *o;
    uint8_t op_index;
    int rc;
    if (st == NULL || key == NULL || (value == NULL && value_len != 0u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!st->txn_open || !g_esp_txn.active || g_esp_txn.owner_st != st) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (st->op_count >= NINLIL_MFDT_V1_LAB_MAX_OPS) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (st->staging_pool_used + value_len > NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    op_index = st->op_count;
    rc = capture_old_for_op(op_index, key);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    o = &st->ops[st->op_count];
    o->valid = 1u;
    o->op = 0u;
    (void)memcpy(o->key, key, 20u);
    o->value_len = value_len;
    o->pool_off = st->staging_pool_used;
    if (value_len > 0u) {
        (void)memcpy(st->staging_pool + st->staging_pool_used, value, value_len);
        st->staging_pool_used += value_len;
    }
    st->op_count = (uint8_t)(st->op_count + 1u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_del(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20])
{
    ninlil_mfdt_v1_lab_op_t *o;
    uint8_t op_index;
    int rc;
    if (st == NULL || key == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!st->txn_open || !g_esp_txn.active || g_esp_txn.owner_st != st) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (st->op_count >= NINLIL_MFDT_V1_LAB_MAX_OPS) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    op_index = st->op_count;
    rc = capture_old_for_op(op_index, key);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    o = &st->ops[st->op_count];
    o->valid = 1u;
    o->op = 1u;
    (void)memcpy(o->key, key, 20u);
    o->value_len = 0u;
    o->pool_off = 0u;
    st->op_count = (uint8_t)(st->op_count + 1u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_get(const ninlil_mfdt_v1_lab_store_t *st,
                           const uint8_t key[20], uint8_t *value_out,
                           uint32_t value_cap, uint32_t *value_len_out)
{
    int idx;
    int rc;

    if (st == NULL || key == NULL || value_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }

    /* Durable-first. value_out may be NULL (length probe for restart_scan). */
    if (g_esp.bound && g_esp.ops != NULL) {
        rc = durable_get(key, value_out, value_cap, value_len_out);
        if (rc == NINLIL_MFDT_V1_OK) {
            return NINLIL_MFDT_V1_OK;
        }
        if (rc != NINLIL_MFDT_V1_ERR_STATE) {
            return rc;
        }
        /* not found on durable → fall through to confirmed local cache */
    }

    idx = find_row(st, key);
    if (idx >= 0) {
        *value_len_out = st->rows[idx].value_len;
        if (value_out != NULL) {
            if (value_cap < st->rows[idx].value_len) {
                return NINLIL_MFDT_V1_ERR_CAPACITY;
            }
            if (st->rows[idx].value_len > 0u) {
                (void)memcpy(value_out, st->rows[idx].value,
                             st->rows[idx].value_len);
            }
        }
        return NINLIL_MFDT_V1_OK;
    }
    return NINLIL_MFDT_V1_ERR_STATE;
}

int ninlil_mfdt_v1_lab_full_rollback(ninlil_mfdt_v1_lab_store_t *st)
{
    if (st == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (g_esp_txn.active && g_esp_txn.owner_st == st && g_esp.bound &&
        g_esp.ops != NULL && g_esp.ops->rollback != NULL &&
        g_esp_txn.txn != NULL) {
        (void)g_esp.ops->rollback(g_esp.ops->user, g_esp_txn.txn);
    }
    if (g_esp_txn.owner_st == st) {
        clear_txn_ctx();
    }
    discard_staging(st);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_full_commit(ninlil_mfdt_v1_lab_store_t *st)
{
    uint8_t i;
    ninlil_storage_txn_t txn;
    ninlil_storage_status_t s;
    int local_rc;
    int resolve_rc;

    if (st == NULL || !st->txn_open) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!g_esp_txn.active || g_esp_txn.owner_st != st || g_esp_txn.txn == NULL) {
        discard_staging(st);
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (!g_esp.bound || g_esp.ops == NULL || g_esp.ops->put == NULL ||
        g_esp.ops->erase == NULL || g_esp.ops->commit == NULL ||
        g_esp.ops->rollback == NULL) {
        (void)ninlil_mfdt_v1_lab_full_rollback(st);
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }

    txn = g_esp_txn.txn;
    for (i = 0u; i < st->op_count; ++i) {
        ninlil_mfdt_v1_lab_op_t *o = &st->ops[i];
        ninlil_bytes_view_t k;
        if (!o->valid) {
            continue;
        }
        k.data = o->key;
        k.length = 20u;
        if (o->op == 1u) {
            /* erase is mandatory (bind-validated); never silent-skip NULL. */
            s = g_esp.ops->erase(g_esp.ops->user, txn, k);
            if (s == NINLIL_STORAGE_COMMIT_UNKNOWN) {
                (void)g_esp.ops->rollback(g_esp.ops->user, txn);
                /*
                 * Mid-op CU before full commit: durable outcome unknown.
                 * Fence; do not claim clean erase.
                 */
                clear_txn_ctx();
                discard_staging(st);
                st->crash_armed = 1u;
                return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
            }
            if (s != NINLIL_STORAGE_OK && s != NINLIL_STORAGE_NOT_FOUND) {
                (void)ninlil_mfdt_v1_lab_full_rollback(st);
                return NINLIL_MFDT_V1_ERR_STORAGE;
            }
        } else {
            ninlil_bytes_view_t vv;
            vv.data = st->staging_pool + o->pool_off;
            vv.length = o->value_len;
            s = g_esp.ops->put(g_esp.ops->user, txn, k, vv);
            if (s == NINLIL_STORAGE_COMMIT_UNKNOWN) {
                if (g_esp.ops->rollback != NULL) {
                    (void)g_esp.ops->rollback(g_esp.ops->user, txn);
                }
                clear_txn_ctx();
                discard_staging(st);
                st->crash_armed = 1u;
                return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
            }
            if (s != NINLIL_STORAGE_OK) {
                (void)ninlil_mfdt_v1_lab_full_rollback(st);
                return NINLIL_MFDT_V1_ERR_STORAGE;
            }
        }
    }

    s = g_esp.ops->commit(g_esp.ops->user, txn, NINLIL_DURABILITY_FULL);
    /* Commit consumes handle; keep old_pool until resolve finishes. */
    g_esp_txn.txn = NULL;
    g_esp_txn.active = 0u;

    ninlil_mfdt_v1_esp_last_cu_class_set(-1);

    if (s == NINLIL_STORAGE_OK) {
        /* Port-attested FULL OK (host model / post-HIL media) — external OK. */
        local_rc = apply_staging_local(st);
        discard_staging(st);
        clear_txn_ctx();
        if (local_rc != NINLIL_MFDT_V1_OK) {
            return local_rc;
        }
        st->crash_armed = 0u;
        st->full_count += 1u;
        ninlil_mfdt_v1_esp_last_cu_class_set((int)NINLIL_MFDT_V1_CU_NEW);
        return NINLIL_MFDT_V1_OK;
    }

    if (s == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        /*
         * ESP_UNPROVEN path: read-back classify (raw proof allowed).
         * NEW → local mirror for recovery + ERR_CU_NEW_NOT_PROMOTED
         *       (engine external success only if HIL gate ON).
         * OLD → ERR_STORAGE (retryable).
         * else → ERR_COMMIT_UNKNOWN fence.
         */
        resolve_rc = resolve_commit_unknown(st);
        if (resolve_rc == NINLIL_MFDT_V1_OK) {
            /* Durable image is NEW — raw classification PASS. */
            ninlil_mfdt_v1_esp_last_cu_class_set((int)NINLIL_MFDT_V1_CU_NEW);
            local_rc = apply_staging_local(st);
            discard_staging(st);
            clear_txn_ctx();
            if (local_rc != NINLIL_MFDT_V1_OK) {
                return local_rc;
            }
            st->crash_armed = 0u;
            st->full_count += 1u; /* durable fulls observed; not wire success */
            return NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED;
        }
        discard_staging(st);
        clear_txn_ctx();
        if (resolve_rc == NINLIL_MFDT_V1_ERR_STORAGE) {
            ninlil_mfdt_v1_esp_last_cu_class_set((int)NINLIL_MFDT_V1_CU_OLD);
            st->crash_armed = 0u;
            return NINLIL_MFDT_V1_ERR_STORAGE;
        }
        ninlil_mfdt_v1_esp_last_cu_class_set((int)NINLIL_MFDT_V1_CU_THIRD);
        st->crash_armed = 1u;
        return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    }

    discard_staging(st);
    clear_txn_ctx();
    return NINLIL_MFDT_V1_ERR_STORAGE;
}
