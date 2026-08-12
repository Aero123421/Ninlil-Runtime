/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Private durable writepoint simulator for r7_frag session tests/recovery.
 */

#include "r7_frag_durable.h"

#include <stdatomic.h>
#include <string.h>

static void sec_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;
    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
    atomic_signal_fence(memory_order_seq_cst);
}

static int key_eq(
    const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
    if (al != bl) {
        return 0;
    }
    return memcmp(a, b, al) == 0;
}

static ninlil_r7_frag_dur_record *find(
    ninlil_r7_frag_dur_store *st, const uint8_t *key, size_t key_len)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_DUR_MAX_KEYS; i++) {
        if (st->rows[i].in_use
            && key_eq(st->rows[i].key, st->rows[i].key_len, key, key_len)) {
            return &st->rows[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_dur_record *find_const(
    const ninlil_r7_frag_dur_store *st, const uint8_t *key, size_t key_len)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_DUR_MAX_KEYS; i++) {
        if (st->rows[i].in_use
            && key_eq(st->rows[i].key, st->rows[i].key_len, key, key_len)) {
            return (ninlil_r7_frag_dur_record *)&st->rows[i];
        }
    }
    return NULL;
}

void ninlil_r7_frag_dur_init(ninlil_r7_frag_dur_store *st)
{
    ninlil_r7_frag_dur_cu_workspace *ws;
    if (st == NULL) {
        return;
    }
    /* Preserve optional caller-owned cu_ws pointer across init. */
    ws = st->cu_ws;
    memset(st, 0, sizeof(*st));
    st->cu_ws = ws;
}

void ninlil_r7_frag_dur_zeroize(ninlil_r7_frag_dur_store *st)
{
    ninlil_r7_frag_dur_cu_workspace *ws;
    if (st == NULL) {
        return;
    }
    ws = st->cu_ws;
    sec_zero(st, sizeof(*st));
    st->cu_ws = ws;
    if (ws != NULL) {
        sec_zero(ws, sizeof(*ws));
    }
}

void ninlil_r7_frag_dur_set_inject(ninlil_r7_frag_dur_store *st, uint8_t inj)
{
    if (st == NULL) {
        return;
    }
    st->inject = inj;
}

void ninlil_r7_frag_dur_begin(ninlil_r7_frag_dur_store *st)
{
    size_t i;
    if (st == NULL) {
        return;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_DUR_MAX_KEYS; i++) {
        memset(&st->pending[i], 0, sizeof(st->pending[i]));
    }
    st->pending_count = 0u;
}

int32_t ninlil_r7_frag_dur_put(
    ninlil_r7_frag_dur_store *st,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *proposed,
    size_t proposed_len)
{
    ninlil_r7_frag_dur_pending *p;
    ninlil_r7_frag_dur_record *r;

    if (st == NULL || key == NULL || proposed == NULL) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    if (key_len == 0u || key_len > NINLIL_R7_FRAG_DUR_KEY_MAX
        || proposed_len > NINLIL_R7_FRAG_DUR_VAL_MAX) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    if (st->pending_count >= NINLIL_R7_FRAG_DUR_MAX_KEYS) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    p = &st->pending[st->pending_count];
    memset(p, 0, sizeof(*p));
    p->active = 1u;
    p->key_len = (uint8_t)key_len;
    memcpy(p->key, key, key_len);
    p->proposed_len = (uint8_t)proposed_len;
    memcpy(p->proposed_val, proposed, proposed_len);
    r = find(st, key, key_len);
    if (r != NULL) {
        p->old_present = 1u;
        p->old_len = r->val_len;
        memcpy(p->old_val, r->val, r->val_len);
    } else {
        p->old_present = 0u;
    }
    st->pending_count += 1u;
    return NINLIL_R7_FRAG_DUR_OK;
}

int32_t ninlil_r7_frag_dur_commit(ninlil_r7_frag_dur_store *st)
{
    uint8_t inj;
    size_t i;

    if (st == NULL) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    if (st->fenced) {
        return NINLIL_R7_FRAG_DUR_COMMIT_UNKNOWN;
    }
    if (st->pending_count == 0u) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    inj = st->inject;
    st->inject = NINLIL_R7_FRAG_DUR_INJECT_NONE;
    if (inj == NINLIL_R7_FRAG_DUR_INJECT_FAIL) {
        /* leave store unchanged; clear pending */
        st->pending_count = 0u;
        return NINLIL_R7_FRAG_DUR_DEFINITE_FAILURE;
    }
    if (inj == NINLIL_R7_FRAG_DUR_INJECT_CORRUPT) {
        st->fenced = 1u;
        st->pending_count = 0u;
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    if (inj == NINLIL_R7_FRAG_DUR_INJECT_CU) {
        /* Sticky fence; dual-truth: do NOT apply proposed (ALL_OLD path after
         * recover). Retain pending for recover_cu. */
        st->fenced = 1u;
        st->cu_count += 1u;
        return NINLIL_R7_FRAG_DUR_COMMIT_UNKNOWN;
    }
    /* FULL_OK: apply all puts */
    for (i = 0u; i < st->pending_count; i++) {
        ninlil_r7_frag_dur_pending *p = &st->pending[i];
        ninlil_r7_frag_dur_record *r = find(st, p->key, p->key_len);
        if (r == NULL) {
            size_t j;
            for (j = 0u; j < NINLIL_R7_FRAG_DUR_MAX_KEYS; j++) {
                if (!st->rows[j].in_use) {
                    r = &st->rows[j];
                    break;
                }
            }
            if (r == NULL) {
                return NINLIL_R7_FRAG_DUR_DEFINITE_FAILURE;
            }
            memset(r, 0, sizeof(*r));
            r->in_use = 1u;
            r->key_len = p->key_len;
            memcpy(r->key, p->key, p->key_len);
        }
        r->val_len = p->proposed_len;
        memcpy(r->val, p->proposed_val, p->proposed_len);
    }
    st->pending_count = 0u;
    st->commit_count += 1u;
    return NINLIL_R7_FRAG_DUR_OK;
}

int32_t ninlil_r7_frag_dur_get(
    const ninlil_r7_frag_dur_store *st,
    const uint8_t *key,
    size_t key_len,
    uint8_t *out_val,
    size_t out_cap,
    size_t *out_len)
{
    ninlil_r7_frag_dur_record *r;
    if (st == NULL || key == NULL || out_val == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    r = find_const(st, key, key_len);
    if (r == NULL) {
        *out_len = 0u;
        return NINLIL_R7_FRAG_DUR_NOT_FOUND;
    }
    if (out_cap < r->val_len) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    memcpy(out_val, r->val, r->val_len);
    *out_len = r->val_len;
    return NINLIL_R7_FRAG_DUR_OK;
}

int32_t ninlil_r7_frag_dur_recover_cu(
    ninlil_r7_frag_dur_store *st,
    ninlil_r7_frag_state_cu_result *out_class)
{
    ninlil_r7_frag_dur_cu_workspace *ws;
    ninlil_r7_frag_state_cu_entry *entries;
    size_t n;
    size_t i;
    ninlil_r7_frag_state_status stc;
    int32_t rc;

    if (st == NULL || out_class == NULL) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    if (st->pending_count == 0u) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    if (st->pending_count > NINLIL_R7_FRAG_STATE_CU_MAX_ENTRIES) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    ws = st->cu_ws;
    if (ws == NULL) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    /* Single-owner non-reentrant: nested/reentrant recover is BUSY. */
    if (ws->live != 0u) {
        return NINLIL_R7_FRAG_DUR_BUSY;
    }
    ws->live = 1u;
    entries = ws->entries;
    memset(entries, 0, sizeof(ws->entries));
    n = st->pending_count;
    for (i = 0u; i < n; i++) {
        ninlil_r7_frag_dur_pending *p = &st->pending[i];
        ninlil_r7_frag_dur_record *r = find(st, p->key, p->key_len);
        entries[i].old_present = p->old_present;
        entries[i].proposed_present = 1u;
        entries[i].key_len = p->key_len;
        memcpy(entries[i].key, p->key, p->key_len);
        entries[i].old_len = p->old_len;
        memcpy(entries[i].old_bytes, p->old_val, p->old_len);
        entries[i].proposed_len = p->proposed_len;
        memcpy(entries[i].proposed_bytes, p->proposed_val, p->proposed_len);
        if (r == NULL) {
            entries[i].observed_status = 1u; /* NOT_FOUND */
            entries[i].observed_len = 0u;
        } else {
            entries[i].observed_status = 0u;
            entries[i].observed_len = r->val_len;
            memcpy(entries[i].observed_bytes, r->val, r->val_len);
        }
    }
    stc = ninlil_r7_frag_state_cu_classify(entries, n, out_class);
    if (stc != NINLIL_R7_FRAG_STATE_OK) {
        rc = NINLIL_R7_FRAG_DUR_CORRUPT;
        goto out_zero;
    }
    if (out_class->class_code == NINLIL_R7_FRAG_STATE_CU_ALL_PROPOSED) {
        /* Apply proposed */
        for (i = 0u; i < n; i++) {
            ninlil_r7_frag_dur_pending *p = &st->pending[i];
            ninlil_r7_frag_dur_record *r = find(st, p->key, p->key_len);
            if (r == NULL) {
                size_t j;
                for (j = 0u; j < NINLIL_R7_FRAG_DUR_MAX_KEYS; j++) {
                    if (!st->rows[j].in_use) {
                        r = &st->rows[j];
                        break;
                    }
                }
                if (r == NULL) {
                    rc = NINLIL_R7_FRAG_DUR_CORRUPT;
                    goto out_zero;
                }
                memset(r, 0, sizeof(*r));
                r->in_use = 1u;
                r->key_len = p->key_len;
                memcpy(r->key, p->key, p->key_len);
            }
            r->val_len = p->proposed_len;
            memcpy(r->val, p->proposed_val, p->proposed_len);
        }
        st->fenced = 0u;
        st->pending_count = 0u;
        rc = NINLIL_R7_FRAG_DUR_OK;
        goto out_zero;
    }
    if (out_class->class_code == NINLIL_R7_FRAG_STATE_CU_ALL_OLD) {
        /* Keep pre-state */
        st->fenced = 0u;
        st->pending_count = 0u;
        rc = NINLIL_R7_FRAG_DUR_OK;
        goto out_zero;
    }
    if (out_class->class_code == NINLIL_R7_FRAG_STATE_CU_RETRY_LATER) {
        rc = NINLIL_R7_FRAG_DUR_BUSY;
        goto out_zero;
    }
    /* THIRD / CORRUPT */
    st->fenced = 1u;
    rc = NINLIL_R7_FRAG_DUR_CORRUPT;
out_zero:
    sec_zero(entries, sizeof(ws->entries));
    ws->live = 0u;
    return rc;
}

/*
 * Snapshot schema v1 (fail-closed):
 *   magic u32 BE | count u16 BE | fenced u8 | schema u8=1
 *   records[count]:
 *     k_res u8=0 | klen u8∈[1,KEY_MAX] | key[klen]
 *     v_res u8=0 | vlen u8∈[0,VAL_MAX] | val[vlen]
 *   crc32 IEEE u32 BE over all preceding bytes
 *
 * Keys MUST be strictly increasing (byte-lexicographic). Pending not durable.
 * Decode: full validate into temp rows → commit only on success; failure leaves
 * *st unchanged (no half-publish).
 */
#define DUR_SNAP_MAGIC ((uint32_t)0x52374452u) /* R7DR */
#define DUR_SNAP_SCHEMA_V1 ((uint8_t)1u)
#define DUR_SNAP_HDR ((size_t)8u)
#define DUR_SNAP_CRC ((size_t)4u)

static uint32_t dur_crc32_ieee(const uint8_t *p, size_t n)
{
    uint32_t c = 0xffffffffu;
    size_t i;
    size_t b;
    for (i = 0u; i < n; i++) {
        c ^= (uint32_t)p[i];
        for (b = 0u; b < 8u; b++) {
            uint32_t mask = (uint32_t)(-(int32_t)(c & 1u));
            c = (c >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~c;
}

static void store_u32_be(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)((v >> 24) & 0xffu);
    o[1] = (uint8_t)((v >> 16) & 0xffu);
    o[2] = (uint8_t)((v >> 8) & 0xffu);
    o[3] = (uint8_t)(v & 0xffu);
}

static uint32_t load_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

/* Lexicographic key order: <0 a<b, 0 equal, >0 a>b. */
static int key_cmp(
    const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
    size_t n = (al < bl) ? al : bl;
    int r = 0;
    if (n > 0u) {
        r = memcmp(a, b, n);
    }
    if (r != 0) {
        return r;
    }
    if (al < bl) {
        return -1;
    }
    if (al > bl) {
        return 1;
    }
    return 0;
}

int32_t ninlil_r7_frag_dur_snapshot_encode(
    const ninlil_r7_frag_dur_store *st,
    uint8_t *out,
    size_t out_cap,
    size_t *out_len)
{
    size_t need;
    size_t i;
    size_t j;
    size_t off;
    uint16_t count = 0u;
    size_t idx[NINLIL_R7_FRAG_DUR_MAX_KEYS];
    uint32_t crc;

    if (st == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    if (st->fenced > 1u) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_DUR_MAX_KEYS; i++) {
        if (!st->rows[i].in_use) {
            continue;
        }
        if (st->rows[i].key_len == 0u
            || st->rows[i].key_len > NINLIL_R7_FRAG_DUR_KEY_MAX
            || st->rows[i].val_len > NINLIL_R7_FRAG_DUR_VAL_MAX) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        idx[count] = i;
        count = (uint16_t)(count + 1u);
    }
    /* Sort indices by key (strict order for decoder). */
    for (i = 0u; i < (size_t)count; i++) {
        for (j = i + 1u; j < (size_t)count; j++) {
            const ninlil_r7_frag_dur_record *a = &st->rows[idx[i]];
            const ninlil_r7_frag_dur_record *b = &st->rows[idx[j]];
            int c = key_cmp(a->key, a->key_len, b->key, b->key_len);
            if (c == 0) {
                return NINLIL_R7_FRAG_DUR_CORRUPT; /* internal dup */
            }
            if (c > 0) {
                size_t t = idx[i];
                idx[i] = idx[j];
                idx[j] = t;
            }
        }
    }
    need = DUR_SNAP_HDR + DUR_SNAP_CRC;
    for (i = 0u; i < (size_t)count; i++) {
        const ninlil_r7_frag_dur_record *r = &st->rows[idx[i]];
        need += 2u + (size_t)r->key_len + 2u + (size_t)r->val_len;
    }
    if (out_cap < need) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    off = 0u;
    store_u32_be(out + off, DUR_SNAP_MAGIC);
    off += 4u;
    out[off++] = (uint8_t)((count >> 8) & 0xffu);
    out[off++] = (uint8_t)(count & 0xffu);
    out[off++] = st->fenced;
    out[off++] = DUR_SNAP_SCHEMA_V1;
    for (i = 0u; i < (size_t)count; i++) {
        const ninlil_r7_frag_dur_record *r = &st->rows[idx[i]];
        out[off++] = 0u; /* reserved key header */
        out[off++] = r->key_len;
        memcpy(out + off, r->key, r->key_len);
        off += r->key_len;
        out[off++] = 0u; /* reserved val header */
        out[off++] = r->val_len;
        if (r->val_len > 0u) {
            memcpy(out + off, r->val, r->val_len);
            off += r->val_len;
        }
    }
    crc = dur_crc32_ieee(out, off);
    store_u32_be(out + off, crc);
    off += DUR_SNAP_CRC;
    *out_len = off;
    return NINLIL_R7_FRAG_DUR_OK;
}

int32_t ninlil_r7_frag_dur_snapshot_decode(
    ninlil_r7_frag_dur_store *st,
    const uint8_t *in,
    size_t in_len)
{
    uint32_t magic;
    uint32_t crc_got;
    uint32_t crc_want;
    uint16_t count;
    uint8_t fenced;
    uint8_t schema;
    size_t body_end;
    size_t off;
    size_t i;
    ninlil_r7_frag_dur_record tmp[NINLIL_R7_FRAG_DUR_MAX_KEYS];

    /* Fail-closed: never mutate *st until full validation succeeds. */
    if (st == NULL || in == NULL) {
        return NINLIL_R7_FRAG_DUR_INVALID;
    }
    if (in_len < DUR_SNAP_HDR + DUR_SNAP_CRC) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    /* subtract-before-read: CRC trailer consumes last 4 bytes */
    body_end = in_len - DUR_SNAP_CRC;
    magic = load_u32_be(in);
    if (magic != DUR_SNAP_MAGIC) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    count = (uint16_t)(((uint16_t)in[4] << 8) | (uint16_t)in[5]);
    fenced = in[6];
    schema = in[7];
    if (schema != DUR_SNAP_SCHEMA_V1) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    if (fenced > 1u) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    if ((size_t)count > NINLIL_R7_FRAG_DUR_MAX_KEYS) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }
    crc_got = load_u32_be(in + body_end);
    crc_want = dur_crc32_ieee(in, body_end);
    if (crc_got != crc_want) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }

    memset(tmp, 0, sizeof(tmp));
    off = DUR_SNAP_HDR;
    for (i = 0u; i < (size_t)count; i++) {
        uint8_t k_res;
        uint8_t klen;
        uint8_t v_res;
        uint8_t vlen;
        size_t remain;

        /* Header key: 2 bytes required. */
        if (off > body_end) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        remain = body_end - off;
        if (remain < 2u) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        k_res = in[off];
        klen = in[off + 1u];
        if (k_res != 0u) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        /* Capacity before any key read/copy. */
        if (klen == 0u || (size_t)klen > NINLIL_R7_FRAG_DUR_KEY_MAX) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        remain -= 2u;
        if (remain < (size_t)klen) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        off += 2u;
        tmp[i].in_use = 1u;
        tmp[i].key_len = klen;
        memcpy(tmp[i].key, in + off, (size_t)klen);
        off += (size_t)klen;

        remain = body_end - off;
        if (remain < 2u) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        v_res = in[off];
        vlen = in[off + 1u];
        if (v_res != 0u) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        if ((size_t)vlen > NINLIL_R7_FRAG_DUR_VAL_MAX) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        remain -= 2u;
        if (remain < (size_t)vlen) {
            return NINLIL_R7_FRAG_DUR_CORRUPT;
        }
        off += 2u;
        tmp[i].val_len = vlen;
        if (vlen > 0u) {
            memcpy(tmp[i].val, in + off, (size_t)vlen);
            off += (size_t)vlen;
        }

        /* Strictly increasing keys (rejects dups and out-of-order). */
        if (i > 0u) {
            int c = key_cmp(
                tmp[i - 1u].key, tmp[i - 1u].key_len, tmp[i].key,
                tmp[i].key_len);
            if (c >= 0) {
                return NINLIL_R7_FRAG_DUR_CORRUPT;
            }
        }
    }
    /* No trailing body bytes (CRC already excluded). */
    if (off != body_end) {
        return NINLIL_R7_FRAG_DUR_CORRUPT;
    }

    /* Commit: publish only after full validation. */
    ninlil_r7_frag_dur_init(st);
    for (i = 0u; i < (size_t)count; i++) {
        st->rows[i] = tmp[i];
    }
    st->fenced = fenced;
    sec_zero(tmp, sizeof(tmp));
    return NINLIL_R7_FRAG_DUR_OK;
}
