/* SPDX-License-Identifier: Apache-2.0
 * ESP MFDT store adapter tests (host-linked mfdt_v1_store_esp.c):
 *
 * Production paths:
 *  - STORAGE_OK → OK + local mirror
 *  - COMMIT_UNKNOWN + durable read-back NEW → ERR_CU_NEW_NOT_PROMOTED
 *  - COMMIT_UNKNOWN + durable OLD → ERR_STORAGE (retryable)
 *  - COMMIT_UNKNOWN + third/corrupt → ERR_COMMIT_UNKNOWN (fence)
 *  - 64-bit txn handle width
 *  - retry after OLD: no duplicate rows
 *
 * Feature smoke (NEW transfer) is separate (ESP target). This file owns
 * fault-inject / classify paths so map-only is never the completion bar.
 */
#include "mfdt_v1.h"
#include "mfdt_v1_target_alloc.h"

#include "ninlil/platform.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int g_fail;
static void expect(int c, const char *m)
{
    if (!c) {
        fprintf(stderr, "FAIL: %s\n", m);
        g_fail = 1;
    }
}

#define MOCK_MAX_ROWS 8
#define MOCK_VAL_MAX  512

typedef struct {
    uint8_t key[20];
    uint8_t val[MOCK_VAL_MAX];
    uint32_t len;
    uint8_t occ;
    uint8_t is_erase; /* staged erase (not a no-op) */
    uint8_t corrupt_on_apply; /* apply changes value instead of erase (third) */
} mock_row_t;

typedef struct {
    mock_row_t rows[MOCK_MAX_ROWS];
    mock_row_t staged[MOCK_MAX_ROWS];
    uint8_t staged_n;
    uint8_t txn_open;
    /*
     * 0 = STORAGE_OK apply
     * 1 = COMMIT_UNKNOWN without durable apply (OLD stays)
     * 2 = IO error
     * 3 = COMMIT_UNKNOWN but durable apply (simulates ESP write-then-CU)
     */
    uint8_t commit_mode;
    uint8_t erase_corrupt; /* next erase stages corrupt-third instead of delete */
    uintptr_t last_txn_token;
    uint32_t begin_count;
    uint32_t commit_count;
    uint32_t put_count;
    uint32_t erase_count;
} mock_store_t;

static mock_store_t g_mock;

#if UINTPTR_MAX > 0xffffffffu
static const uintptr_t k_wide_txn = (uintptr_t)0xFEDCBA9876543210ull;
#else
static uint8_t g_txn_blob_32[16];
#endif

static ninlil_storage_txn_t g_txn_handle;

static void mock_reset(void)
{
    memset(&g_mock, 0, sizeof(g_mock));
#if UINTPTR_MAX > 0xffffffffu
    g_txn_handle = (ninlil_storage_txn_t)(void *)k_wide_txn;
#else
    memset(g_txn_blob_32, 0x5A, sizeof(g_txn_blob_32));
    g_txn_handle = (ninlil_storage_txn_t)(void *)g_txn_blob_32;
#endif
}

static int mock_find(const mock_row_t *rows, const uint8_t key[20])
{
    uint8_t i;
    for (i = 0; i < MOCK_MAX_ROWS; ++i) {
        if (rows[i].occ && memcmp(rows[i].key, key, 20) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static uint8_t mock_occ_count(void)
{
    uint8_t i;
    uint8_t n = 0u;
    for (i = 0; i < MOCK_MAX_ROWS; ++i) {
        if (g_mock.rows[i].occ) {
            n = (uint8_t)(n + 1u);
        }
    }
    return n;
}

static void mock_apply_staged(void)
{
    uint8_t i;
    for (i = 0; i < g_mock.staged_n; ++i) {
        int idx = mock_find(g_mock.rows, g_mock.staged[i].key);
        if (g_mock.staged[i].is_erase) {
            if (g_mock.staged[i].corrupt_on_apply) {
                /* third/corrupt: leave key present with wrong bytes */
                if (idx < 0) {
                    uint8_t j;
                    for (j = 0; j < MOCK_MAX_ROWS; ++j) {
                        if (!g_mock.rows[j].occ) {
                            idx = (int)j;
                            break;
                        }
                    }
                }
                if (idx >= 0) {
                    memcpy(g_mock.rows[idx].key, g_mock.staged[i].key, 20);
                    g_mock.rows[idx].val[0] =
                        (uint8_t)(g_mock.rows[idx].val[0] ^ 0xA5u);
                    if (g_mock.rows[idx].len == 0u) {
                        g_mock.rows[idx].len = 1u;
                        g_mock.rows[idx].val[0] = 0xA5u;
                    }
                    g_mock.rows[idx].occ = 1u;
                }
            } else if (idx >= 0) {
                memset(&g_mock.rows[idx], 0, sizeof(g_mock.rows[idx]));
            }
            continue;
        }
        if (idx < 0) {
            uint8_t j;
            for (j = 0; j < MOCK_MAX_ROWS; ++j) {
                if (!g_mock.rows[j].occ) {
                    idx = (int)j;
                    break;
                }
            }
        }
        if (idx >= 0) {
            g_mock.rows[idx] = g_mock.staged[i];
            g_mock.rows[idx].is_erase = 0u;
            g_mock.rows[idx].corrupt_on_apply = 0u;
        }
    }
    g_mock.staged_n = 0u;
}

static ninlil_storage_status_t mock_open(void *user, ninlil_bytes_view_t ns,
                                         uint32_t schema,
                                         ninlil_storage_handle_t *out)
{
    (void)user;
    (void)ns;
    (void)schema;
    *out = (ninlil_storage_handle_t)(void *)&g_mock;
    return NINLIL_STORAGE_OK;
}

static void mock_close(void *user, ninlil_storage_handle_t h)
{
    (void)user;
    (void)h;
}

static ninlil_storage_status_t mock_begin(void *user, ninlil_storage_handle_t h,
                                          ninlil_storage_mode_t mode,
                                          ninlil_storage_txn_t *out_txn)
{
    (void)user;
    (void)h;
    (void)mode;
    g_mock.begin_count += 1u;
    g_mock.txn_open = 1u;
    g_mock.staged_n = 0u;
    *out_txn = g_txn_handle;
    g_mock.last_txn_token = (uintptr_t)(void *)g_txn_handle;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mock_put(void *user, ninlil_storage_txn_t txn,
                                        ninlil_bytes_view_t key,
                                        ninlil_bytes_view_t value)
{
    mock_row_t *r;
    (void)user;
    g_mock.put_count += 1u;
    expect(txn == g_txn_handle, "put full-width handle");
#if UINTPTR_MAX > 0xffffffffu
    expect((uintptr_t)(void *)txn == k_wide_txn, "put 64-bit token");
#endif
    if (g_mock.staged_n >= MOCK_MAX_ROWS || key.length != 20u ||
        value.length > MOCK_VAL_MAX) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    r = &g_mock.staged[g_mock.staged_n++];
    memset(r, 0, sizeof(*r));
    memcpy(r->key, key.data, 20);
    if (value.length > 0u) {
        memcpy(r->val, value.data, value.length);
    }
    r->len = value.length;
    r->occ = 1u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mock_get(void *user, ninlil_storage_txn_t txn,
                                        ninlil_bytes_view_t key,
                                        ninlil_mut_bytes_t *value)
{
    int idx;
    (void)user;
    (void)txn;
    if (key.length != 20u || value == NULL) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    idx = mock_find(g_mock.rows, key.data);
    if (idx < 0) {
        return NINLIL_STORAGE_NOT_FOUND;
    }
    if (value->capacity < g_mock.rows[idx].len) {
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (g_mock.rows[idx].len > 0u) {
        memcpy(value->data, g_mock.rows[idx].val, g_mock.rows[idx].len);
    }
    value->length = g_mock.rows[idx].len;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mock_erase(void *user, ninlil_storage_txn_t txn,
                                          ninlil_bytes_view_t key)
{
    mock_row_t *r;
    (void)user;
    g_mock.erase_count += 1u;
    expect(txn == g_txn_handle, "erase full-width handle");
    if (g_mock.staged_n >= MOCK_MAX_ROWS || key.length != 20u) {
        return NINLIL_STORAGE_IO_ERROR;
    }
    /* Real staged erase — not a silent no-op. */
    r = &g_mock.staged[g_mock.staged_n++];
    memset(r, 0, sizeof(*r));
    memcpy(r->key, key.data, 20);
    r->is_erase = 1u;
    r->occ = 0u;
    if (g_mock.erase_corrupt) {
        r->corrupt_on_apply = 1u;
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mock_commit(void *user, ninlil_storage_txn_t txn,
                                           ninlil_durability_t dur)
{
    (void)user;
    (void)dur;
    expect(txn == g_txn_handle, "commit full-width handle");
#if UINTPTR_MAX > 0xffffffffu
    expect((uintptr_t)(void *)txn == k_wide_txn, "commit 64-bit token");
#endif
    g_mock.commit_count += 1u;
    g_mock.txn_open = 0u;
    if (g_mock.commit_mode == 1) {
        /* CU without applying: durable stays OLD */
        g_mock.staged_n = 0u;
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    if (g_mock.commit_mode == 2) {
        g_mock.staged_n = 0u;
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (g_mock.commit_mode == 3) {
        /* ESP-like: write applied then policy returns CU */
        mock_apply_staged();
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    mock_apply_staged();
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t mock_rollback(void *user, ninlil_storage_txn_t txn)
{
    (void)user;
    (void)txn;
    g_mock.txn_open = 0u;
    g_mock.staged_n = 0u;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_ops_t g_ops;

static void ops_init(void)
{
    memset(&g_ops, 0, sizeof(g_ops));
    g_ops.open = mock_open;
    g_ops.close = mock_close;
    g_ops.begin = mock_begin;
    g_ops.put = mock_put;
    g_ops.get = mock_get;
    g_ops.erase = mock_erase;
    g_ops.commit = mock_commit;
    g_ops.rollback = mock_rollback;
}

/* ---- Tests --------------------------------------------------------------- */

static void test_bind_preallocates_all_operation_bulk(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t value[8] = {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u};
    uint32_t length = 0u;
    uint64_t allocations_after_bind;

    mock_reset();
    g_mock.commit_mode = 0u;
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0,
           "allocation bind");
    allocations_after_bind = ninlil_mfdt_v1_target_zalloc_call_count();
    memset(key, 0x7au, sizeof(key));
    memcpy(key, "NRC1", 4u);

    ninlil_mfdt_v1_target_zalloc_force_fail(1);
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0,
           "allocation-free full begin");
    expect(ninlil_mfdt_v1_lab_put(&st, key, value, sizeof(value)) == 0,
           "allocation-free put");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0,
           "allocation-free commit");
    expect(ninlil_mfdt_v1_lab_get(&st, key, NULL, 0u, &length) == 0 &&
               length == sizeof(value),
           "allocation-free length probe");
    ninlil_mfdt_v1_target_zalloc_force_fail(0);
    expect(ninlil_mfdt_v1_target_zalloc_call_count() ==
               allocations_after_bind,
           "ESP store operation allocation count unchanged");
    ninlil_mfdt_v1_esp_store_unbind();
}

static void test_64bit_txn_handle_width(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t val[4] = {9, 9, 9, 9};

    mock_reset();
    g_mock.commit_mode = 0;
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(sizeof(ninlil_storage_txn_t) == sizeof(void *), "pointer-sized txn");
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "begin");
#if UINTPTR_MAX > 0xffffffffu
    expect(g_mock.last_txn_token == k_wide_txn, "full 64-bit stored");
    expect((g_mock.last_txn_token >> 32) != 0u, "high half nonzero");
#endif
    memset(key, 0x11, 20);
    memcpy(key, "NM3S", 4);
    expect(ninlil_mfdt_v1_lab_put(&st, key, val, 4) == 0, "put");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "commit");
    ninlil_mfdt_v1_esp_store_unbind();
}

/*
 * CU + durable applied → raw NEW classification PASS, but release NOT_PROMOTED
 * (ERR_CU_NEW_NOT_PROMOTED). Gate stays OFF.
 */
static void test_cu_resolve_new_raw_not_promoted(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t newv[8];
    uint8_t out[8];
    uint32_t len = 0;
    int rc;
    int cu;

    mock_reset();
    memset(key, 0x21, 20);
    memcpy(key, "NM3S", 4);
    memset(newv, 0xBB, 8);
    g_mock.commit_mode = 3; /* apply then CU */
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "begin");
    expect(ninlil_mfdt_v1_lab_put(&st, key, newv, 8) == 0, "put");
    rc = ninlil_mfdt_v1_lab_full_commit(&st);
    expect(rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED, "raw NEW not promoted");
    expect(rc != NINLIL_MFDT_V1_OK, "not external OK");
    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0, "gate OFF");
    cu = ninlil_mfdt_v1_esp_last_cu_class();
    expect(cu == (int)NINLIL_MFDT_V1_CU_NEW, "raw class NEW");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, out, 8, &len) == 0 && len == 8,
           "get NEW");
    expect(memcmp(out, newv, 8) == 0, "durable NEW");
    /* length probe ABI */
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, NULL, 0u, &len) == 0 && len == 8,
           "NULL length probe");
    ninlil_mfdt_v1_esp_store_unbind();
}

/* Public setter removed: gate stays OFF; magic/non-zero bytes are not evidence. */
static void test_hil_gate_contract_default_off(void)
{
    uint8_t forged[24];
    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0,
           "default NOT_PROMOTED");
    memset(forged, 0, sizeof(forged));
    memcpy(forged, "MFDT-HIL-ATTEST-V1", 17);
    expect(ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation(
               forged, sizeof(forged)) != 0,
           "zero-tail seal rejected");
    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0,
           "still OFF after failed attest");
    forged[23] = 0xa5u;
    expect(ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation(
               forged, sizeof(forged)) == NINLIL_MFDT_V1_ERR_STATE,
           "magic plus nonzero tail rejected as unavailable verifier");
    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0,
           "still OFF after magic plus nonzero tail");
    memset(forged, 0x5a, sizeof(forged));
    expect(ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation(
               forged, sizeof(forged)) == NINLIL_MFDT_V1_ERR_STATE,
           "digest-shaped opaque bytes rejected");
    expect(ninlil_mfdt_v1_hil_full_promotion_enabled() == 0,
           "still OFF after opaque bytes");
    expect(ninlil_mfdt_v1_hil_full_promotion_apply_target_attestation(NULL, 0) !=
               0,
           "null evidence rejected");
}

/* CU without apply → OLD → ERR_STORAGE retryable; cold restart still OLD. */
static void test_cu_resolve_old_retry_cold_restart(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t oldv[8];
    uint8_t newv[8];
    uint8_t out[8];
    uint32_t len = 0;
    int rc;
    ninlil_mfdt_v1_cu_class_t c;

    mock_reset();
    memset(key, 0x22, 20);
    memcpy(key, "NM3S", 4);
    memset(oldv, 0xAA, 8);
    memset(newv, 0xBB, 8);

    g_mock.commit_mode = 0;
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b-old");
    expect(ninlil_mfdt_v1_lab_put(&st, key, oldv, 8) == 0, "p-old");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c-old");

    g_mock.commit_mode = 1; /* CU no apply */
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b-cu");
    expect(ninlil_mfdt_v1_lab_put(&st, key, newv, 8) == 0, "p-cu");
    rc = ninlil_mfdt_v1_lab_full_commit(&st);
    expect(rc == NINLIL_MFDT_V1_ERR_STORAGE, "OLD → retryable ERR_STORAGE");
    expect(rc != NINLIL_MFDT_V1_OK, "not OK");
    expect(st.crash_armed == 0u, "not fence");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, out, 8, &len) == 0, "get");
    expect(memcmp(out, oldv, 8) == 0, "still OLD");
    c = ninlil_mfdt_v1_classify_cu_bytes(out, len, 1, oldv, 8, 1, newv, 8, 1);
    expect(c == NINLIL_MFDT_V1_CU_OLD, "classify OLD");

    /* cold restart */
    memset(&st, 0x5A, sizeof(st));
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "rebind");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, out, 8, &len) == 0, "cold get");
    expect(memcmp(out, oldv, 8) == 0, "cold OLD");
    c = ninlil_mfdt_v1_classify_cu_bytes(out, len, 1, oldv, 8, 1, newv, 8, 1);
    expect(c == NINLIL_MFDT_V1_CU_OLD, "cold classify OLD");

    /* retry OK → NEW, single row */
    g_mock.commit_mode = 0;
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b-retry");
    expect(ninlil_mfdt_v1_lab_put(&st, key, newv, 8) == 0, "p-retry");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c-retry");
    expect(mock_occ_count() == 1u, "no duplicate row");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, out, 8, &len) == 0, "get NEW");
    c = ninlil_mfdt_v1_classify_cu_bytes(out, len, 1, oldv, 8, 1, newv, 8, 1);
    expect(c == NINLIL_MFDT_V1_CU_NEW, "classify NEW");
    ninlil_mfdt_v1_esp_store_unbind();
}

/* Third image after CU → fence ERR_COMMIT_UNKNOWN (not OK, not silent). */
static void test_cu_third_image_fence(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t oldv[4] = {1, 1, 1, 1};
    uint8_t newv[4] = {2, 2, 2, 2};
    uint8_t third[4] = {3, 3, 3, 3};
    int rc;

    mock_reset();
    memset(key, 0x33, 20);
    memcpy(key, "NM3R", 4);
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");

    g_mock.commit_mode = 0;
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b0");
    expect(ninlil_mfdt_v1_lab_put(&st, key, oldv, 4) == 0, "p0");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c0");

    /* put captures OLD=oldv; then corrupt durable to third before commit. */
    g_mock.commit_mode = 1;
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b1");
    expect(ninlil_mfdt_v1_lab_put(&st, key, newv, 4) == 0, "p1");
    {
        int idx = mock_find(g_mock.rows, key);
        expect(idx >= 0, "row");
        memcpy(g_mock.rows[idx].val, third, 4);
    }
    rc = ninlil_mfdt_v1_lab_full_commit(&st);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN, "third → fence");
    expect(st.crash_armed == 1u, "fenced");
    ninlil_mfdt_v1_esp_store_unbind();
}

static void test_retry_no_duplicate(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t v1[4] = {1, 1, 1, 1};
    uint8_t v2[4] = {2, 2, 2, 2};
    uint32_t puts0;
    uint32_t commits0;

    mock_reset();
    memset(key, 0x44, 20);
    memcpy(key, "NM3S", 4);
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");

    g_mock.commit_mode = 1;
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b1");
    expect(ninlil_mfdt_v1_lab_put(&st, key, v1, 4) == 0, "p1");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == NINLIL_MFDT_V1_ERR_STORAGE,
           "cu old");
    puts0 = g_mock.put_count;
    commits0 = g_mock.commit_count;

    g_mock.commit_mode = 3; /* apply+CU → raw NEW not promoted */
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b2");
    expect(ninlil_mfdt_v1_lab_put(&st, key, v2, 4) == 0, "p2");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) ==
               NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED,
           "raw NEW");
    expect(mock_occ_count() == 1u, "one row");
    expect(g_mock.put_count == puts0 + 1u, "one put");
    expect(g_mock.commit_count == commits0 + 1u, "one commit");
    ninlil_mfdt_v1_esp_store_unbind();
}

/*
 * Engine restart_scan uses lab_get(NULL, 0, &len). ABI: length probe must
 * succeed without a value buffer (was broken when store_esp rejected NULL).
 */
static void test_null_length_probe_for_restart(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t val[32];
    uint32_t len = 0;
    uint8_t out[32];

    mock_reset();
    g_mock.commit_mode = 0;
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");
    memset(key, 0x55, 20);
    memcpy(key, "NM3S", 4);
    memset(val, 0xAB, sizeof(val));
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "begin");
    expect(ninlil_mfdt_v1_lab_put(&st, key, val, 32) == 0, "put");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "commit");
    /* NULL value_out — existence/length only (restart_scan). */
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, NULL, 0u, &len) == 0, "NULL probe");
    expect(len == 32u, "len from probe");
    /* Cold local wipe + rebind: probe still works via durable. */
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "rebind");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, NULL, 0u, &len) == 0 && len == 32u,
           "restart NULL probe");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, out, 32, &len) == 0 && len == 32u &&
               memcmp(out, val, 32) == 0,
           "restart full get");
    ninlil_mfdt_v1_esp_store_unbind();
}

/* Bind rejects missing erase (FULL delete path would silent-skip). */
static void test_bind_requires_erase_ops(void)
{
    ninlil_storage_ops_t bad;

    ops_init();
    bad = g_ops;
    bad.erase = NULL;
    expect(ninlil_mfdt_v1_esp_store_bind(&bad, &g_mock) ==
               NINLIL_MFDT_V1_ERR_PARAM,
           "bind without erase fails");
    bad = g_ops;
    bad.rollback = NULL;
    expect(ninlil_mfdt_v1_esp_store_bind(&bad, &g_mock) ==
               NINLIL_MFDT_V1_ERR_PARAM,
           "bind without rollback fails");
    bad = g_ops;
    bad.get = NULL;
    expect(ninlil_mfdt_v1_esp_store_bind(&bad, &g_mock) ==
               NINLIL_MFDT_V1_ERR_PARAM,
           "bind without get fails");
}

/*
 * Delete CU real path: erase is staged+applied (not no-op).
 * CU after apply (mode 3) → key absent = NEW for delete → CU_NEW_NOT_PROMOTED.
 */
static void test_delete_cu_new_absent(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t val[8];
    uint32_t len = 0;
    int rc;
    uint32_t erases0;

    mock_reset();
    memset(key, 0x66, 20);
    memcpy(key, "NM3S", 4);
    memset(val, 0x11, 8);
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");

    g_mock.commit_mode = 0;
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b-put");
    expect(ninlil_mfdt_v1_lab_put(&st, key, val, 8) == 0, "put");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c-put");
    expect(mock_find(g_mock.rows, key) >= 0, "present before del");

    erases0 = g_mock.erase_count;
    g_mock.commit_mode = 3; /* apply erase then CU */
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b-del");
    expect(ninlil_mfdt_v1_lab_del(&st, key) == 0, "del stage");
    rc = ninlil_mfdt_v1_lab_full_commit(&st);
    expect(g_mock.erase_count == erases0 + 1u, "erase called (not no-op)");
    expect(rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED, "delete CU NEW absent");
    expect(mock_find(g_mock.rows, key) < 0, "key erased durable");
    expect(ninlil_mfdt_v1_esp_last_cu_class() == (int)NINLIL_MFDT_V1_CU_NEW,
           "class NEW");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, NULL, 0u, &len) != 0, "absent get");
    ninlil_mfdt_v1_esp_store_unbind();
}

/* Delete CU: no apply (mode 1) → exact OLD retained → ERR_STORAGE retryable. */
static void test_delete_cu_old_exact(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t val[8];
    uint8_t out[8];
    uint32_t len = 0;
    int rc;

    mock_reset();
    memset(key, 0x67, 20);
    memcpy(key, "NRC1", 4);
    memset(val, 0x22, 8);
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");

    g_mock.commit_mode = 0;
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b0");
    expect(ninlil_mfdt_v1_lab_put(&st, key, val, 8) == 0, "p0");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c0");

    g_mock.commit_mode = 1; /* CU, no apply — OLD exact */
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b-del");
    expect(ninlil_mfdt_v1_lab_del(&st, key) == 0, "del");
    rc = ninlil_mfdt_v1_lab_full_commit(&st);
    expect(rc == NINLIL_MFDT_V1_ERR_STORAGE, "delete CU OLD retryable");
    expect(ninlil_mfdt_v1_esp_last_cu_class() == (int)NINLIL_MFDT_V1_CU_OLD,
           "class OLD");
    len = 0;
    expect(ninlil_mfdt_v1_lab_get(&st, key, out, 8, &len) == 0 && len == 8,
           "still present");
    expect(memcmp(out, val, 8) == 0, "exact OLD bytes");
    ninlil_mfdt_v1_esp_store_unbind();
}

/* Delete CU: present but not exact OLD (corrupt third) → fence. */
static void test_delete_cu_third_corrupt_fence(void)
{
    ninlil_mfdt_v1_lab_store_t st;
    uint8_t key[20];
    uint8_t val[8];
    int rc;

    mock_reset();
    memset(key, 0x68, 20);
    memcpy(key, "NM30", 4);
    memset(val, 0x33, 8);
    ninlil_mfdt_v1_lab_store_init(&st);
    expect(ninlil_mfdt_v1_esp_store_bind(&g_ops, &g_mock) == 0, "bind");

    g_mock.commit_mode = 0;
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b0");
    expect(ninlil_mfdt_v1_lab_put(&st, key, val, 8) == 0, "p0");
    expect(ninlil_mfdt_v1_lab_full_commit(&st) == 0, "c0");

    g_mock.commit_mode = 3;
    g_mock.erase_corrupt = 1u; /* apply mutates instead of erase */
    expect(ninlil_mfdt_v1_lab_full_begin(&st) == 0, "b-del");
    expect(ninlil_mfdt_v1_lab_del(&st, key) == 0, "del");
    rc = ninlil_mfdt_v1_lab_full_commit(&st);
    expect(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN, "third/corrupt fence");
    expect(st.crash_armed == 1u, "fenced");
    expect(mock_find(g_mock.rows, key) >= 0, "still present corrupt");
    ninlil_mfdt_v1_esp_store_unbind();
}

int main(void)
{
    g_fail = 0;
    ops_init();
    test_bind_preallocates_all_operation_bulk();
    test_hil_gate_contract_default_off();
    test_bind_requires_erase_ops();
    test_64bit_txn_handle_width();
    test_cu_resolve_new_raw_not_promoted();
    test_cu_resolve_old_retry_cold_restart();
    test_cu_third_image_fence();
    test_retry_no_duplicate();
    test_null_length_probe_for_restart();
    test_delete_cu_new_absent();
    test_delete_cu_old_exact();
    test_delete_cu_third_corrupt_fence();
    if (g_fail) {
        fprintf(stderr, "mfdt_v1_esp_store_cu_test FAILED\n");
        return 1;
    }
    printf("mfdt_v1_esp_store_cu_test OK\n");
    return 0;
}
