/* SPDX-License-Identifier: Apache-2.0
 * In-memory durable FULL simulator for host/lab MFDT. Not ESP flash driver.
 * Multi-key transactional FULL: put/del stage until commit; crash inject
 * fails before any durable apply so NEW is never half-visible.
 */
#include "mfdt_v1.h"

#include <string.h>

/* Host lab: ESP bind is a no-op (storage lives in lab pool). */
int ninlil_mfdt_v1_esp_store_bind(const void *storage_ops, void *storage_handle)
{
    (void)storage_ops;
    (void)storage_handle;
    return NINLIL_MFDT_V1_OK;
}

void ninlil_mfdt_v1_esp_store_unbind(void)
{
}

void ninlil_mfdt_v1_lab_store_init(ninlil_mfdt_v1_lab_store_t *st)
{
    size_t i;
    if (st == NULL) {
        return;
    }
    ninlil_mfdt_v1_memzero(st, sizeof(*st));
    for (i = 0; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        st->rows[i].occupied = 0u;
        st->rows[i].value = NULL;
        st->rows[i].value_len = 0u;
        st->rows[i].key_len = 0u;
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

/* Reclaim value_pool when no durable rows remain (lab lifecycle reuse). */
static void maybe_reclaim_pool(ninlil_mfdt_v1_lab_store_t *st)
{
    size_t i;
    for (i = 0; i < NINLIL_MFDT_V1_LAB_MAX_ROWS; ++i) {
        if (st->rows[i].occupied) {
            return;
        }
    }
    st->pool_used = 0u;
}

int ninlil_mfdt_v1_lab_full_begin(ninlil_mfdt_v1_lab_store_t *st)
{
    if (st == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (st->txn_open) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    st->txn_open = 1u;
    st->op_count = 0u;
    st->staging_pool_used = 0u;
    ninlil_mfdt_v1_memzero(st->ops, sizeof(st->ops));
    return NINLIL_MFDT_V1_OK;
}

static int stage_op(ninlil_mfdt_v1_lab_store_t *st, uint8_t op,
                    const uint8_t key[20], const uint8_t *value,
                    uint32_t value_len)
{
    ninlil_mfdt_v1_lab_op_t *o;
    if (st->op_count >= NINLIL_MFDT_V1_LAB_MAX_OPS) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    if (op == 0u && value_len > 0u) {
        if (st->staging_pool_used + value_len >
            NINLIL_MFDT_V1_LAB_STAGING_POOL_BYTES) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
    }
    o = &st->ops[st->op_count];
    o->valid = 1u;
    o->op = op;
    (void)memcpy(o->key, key, 20u);
    o->value_len = value_len;
    o->pool_off = st->staging_pool_used;
    if (op == 0u && value_len > 0u) {
        (void)memcpy(st->staging_pool + st->staging_pool_used, value, value_len);
        st->staging_pool_used += value_len;
    }
    st->op_count = (uint8_t)(st->op_count + 1u);
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_put(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20],
                           const uint8_t *value, uint32_t value_len)
{
    int idx;
    if (st == NULL || key == NULL || (value == NULL && value_len != 0u)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (st->txn_open) {
        return stage_op(st, 0u, key, value, value_len);
    }
    /* Non-transactional path for unit fixtures only. */
    if (value_len > NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    idx = find_row(st, key);
    if (idx < 0) {
        idx = free_row(st);
        if (idx < 0) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        if (st->pool_used + value_len > NINLIL_MFDT_V1_LAB_VALUE_POOL_BYTES) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        st->rows[idx].value = st->value_pool + st->pool_used;
        st->pool_used += value_len;
        st->rows[idx].occupied = 1u;
        (void)memcpy(st->rows[idx].key, key, 20u);
        st->rows[idx].key_len = 20u;
    } else if (value_len > st->rows[idx].value_len) {
        if (st->pool_used + value_len > NINLIL_MFDT_V1_LAB_VALUE_POOL_BYTES) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        st->rows[idx].value = st->value_pool + st->pool_used;
        st->pool_used += value_len;
    }
    if (value_len > 0u) {
        (void)memcpy(st->rows[idx].value, value, value_len);
    }
    st->rows[idx].value_len = value_len;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_get(const ninlil_mfdt_v1_lab_store_t *st,
                           const uint8_t key[20], uint8_t *value_out,
                           uint32_t value_cap, uint32_t *value_len_out)
{
    int idx;
    if (st == NULL || key == NULL || value_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    idx = find_row(st, key);
    if (idx < 0) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    *value_len_out = st->rows[idx].value_len;
    if (value_out != NULL) {
        if (value_cap < st->rows[idx].value_len) {
            return NINLIL_MFDT_V1_ERR_CAPACITY;
        }
        if (st->rows[idx].value_len > 0u) {
            (void)memcpy(value_out, st->rows[idx].value, st->rows[idx].value_len);
        }
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_del(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20])
{
    int idx;
    if (st == NULL || key == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (st->txn_open) {
        return stage_op(st, 1u, key, NULL, 0u);
    }
    idx = find_row(st, key);
    if (idx < 0) {
        return NINLIL_MFDT_V1_OK;
    }
    st->rows[idx].occupied = 0u;
    st->rows[idx].value = NULL;
    st->rows[idx].value_len = 0u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_full_rollback(ninlil_mfdt_v1_lab_store_t *st)
{
    if (st == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    st->txn_open = 0u;
    st->op_count = 0u;
    st->staging_pool_used = 0u;
    ninlil_mfdt_v1_memzero(st->ops, sizeof(st->ops));
    return NINLIL_MFDT_V1_OK;
}

static int apply_put(ninlil_mfdt_v1_lab_store_t *st, const uint8_t key[20],
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
    if (value_len > 0u) {
        (void)memcpy(st->rows[idx].value, value, value_len);
    }
    st->rows[idx].value_len = value_len;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_lab_full_commit(ninlil_mfdt_v1_lab_store_t *st)
{
    uint8_t i;
    if (st == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (!st->txn_open) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    /* Crash inject before any durable apply: multi-key NEW never partial. */
    if (st->crash_after_fulls != 0u &&
        st->full_count + 1u > st->crash_after_fulls) {
        st->crash_armed = 1u;
        (void)ninlil_mfdt_v1_lab_full_rollback(st);
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    for (i = 0u; i < st->op_count; ++i) {
        ninlil_mfdt_v1_lab_op_t *o = &st->ops[i];
        int rc;
        if (!o->valid) {
            continue;
        }
        if (o->op == 1u) {
            int idx = find_row(st, o->key);
            if (idx >= 0) {
                st->rows[idx].occupied = 0u;
                st->rows[idx].value = NULL;
                st->rows[idx].value_len = 0u;
            }
            maybe_reclaim_pool(st);
        } else {
            const uint8_t *v =
                (o->value_len > 0u) ? (st->staging_pool + o->pool_off) : NULL;
            rc = apply_put(st, o->key, v, o->value_len);
            if (rc != NINLIL_MFDT_V1_OK) {
                (void)ninlil_mfdt_v1_lab_full_rollback(st);
                return rc;
            }
        }
    }
    st->full_count += 1u;
    st->txn_open = 0u;
    st->op_count = 0u;
    st->staging_pool_used = 0u;
    ninlil_mfdt_v1_memzero(st->ops, sizeof(st->ops));
    /*
     * Lab inject: durable apply already committed (like ESP CU read-back NEW),
     * but external success is not promoted (ADR-0021).
     */
    if (st->force_cu_new_not_promoted != 0u) {
        st->force_cu_new_not_promoted = 0u;
        ninlil_mfdt_v1_esp_last_cu_class_set((int)NINLIL_MFDT_V1_CU_NEW);
        return NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED;
    }
    return NINLIL_MFDT_V1_OK;
}

/* HIL gate + CU class latch live in portable mfdt_v1_hil_gate.c (PRODUCTION). */
