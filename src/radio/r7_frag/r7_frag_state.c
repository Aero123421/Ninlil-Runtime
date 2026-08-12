/* SPDX-License-Identifier: Apache-2.0 */
/*
 * R7 private pure FRAG planner + reassembly state machine.
 * Heap-free. No AEAD/wire/crypto. Failure: no partial publication.
 */

#include "r7_frag_state.h"

#include <stdatomic.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* -------------------------------------------------------------------------- */

static void ninlil_r7_frag_state_secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;
    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
    atomic_signal_fence(memory_order_seq_cst);
}

static void ninlil_r7_frag_state_copy(uint8_t *d, const uint8_t *s, size_t n)
{
    size_t i;
    for (i = 0u; i < n; i++) {
        d[i] = s[i];
    }
}

static int ninlil_r7_frag_state_checked_add(
    uint64_t a, uint64_t b, uint64_t *out)
{
    if (a > (UINT64_MAX - b)) {
        return 0;
    }
    *out = a + b;
    return 1;
}

static int ninlil_r7_frag_state_handle_ok(uint64_t h)
{
    return h != 0u && h != UINT64_MAX;
}

static int ninlil_r7_frag_state_context_ok(uint32_t id)
{
    return id != 0u && id != UINT32_MAX;
}

static int ninlil_r7_frag_state_tid_eq(const uint8_t a[16], const uint8_t b[16])
{
    size_t i;
    for (i = 0u; i < 16u; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static uint16_t ninlil_r7_frag_state_full_bitmap(uint16_t frag_count)
{
    if (frag_count == 0u || frag_count > 16u) {
        return 0u;
    }
    return (uint16_t)((1u << frag_count) - 1u);
}

static void ninlil_r7_frag_state_store_u16_be(uint8_t *o, uint16_t v)
{
    o[0] = (uint8_t)((v >> 8) & 0xffu);
    o[1] = (uint8_t)(v & 0xffu);
}

static void ninlil_r7_frag_state_store_u32_be(uint8_t *o, uint32_t v)
{
    o[0] = (uint8_t)((v >> 24) & 0xffu);
    o[1] = (uint8_t)((v >> 16) & 0xffu);
    o[2] = (uint8_t)((v >> 8) & 0xffu);
    o[3] = (uint8_t)(v & 0xffu);
}

static void ninlil_r7_frag_state_store_u64_be(uint8_t *o, uint64_t v)
{
    o[0] = (uint8_t)((v >> 56) & 0xffu);
    o[1] = (uint8_t)((v >> 48) & 0xffu);
    o[2] = (uint8_t)((v >> 40) & 0xffu);
    o[3] = (uint8_t)((v >> 32) & 0xffu);
    o[4] = (uint8_t)((v >> 24) & 0xffu);
    o[5] = (uint8_t)((v >> 16) & 0xffu);
    o[6] = (uint8_t)((v >> 8) & 0xffu);
    o[7] = (uint8_t)(v & 0xffu);
}

static uint16_t ninlil_r7_frag_state_load_u16_be(const uint8_t *i)
{
    return (uint16_t)(((uint16_t)i[0] << 8) | (uint16_t)i[1]);
}

static uint32_t ninlil_r7_frag_state_load_u32_be(const uint8_t *i)
{
    return ((uint32_t)i[0] << 24) | ((uint32_t)i[1] << 16)
        | ((uint32_t)i[2] << 8) | (uint32_t)i[3];
}

static uint64_t ninlil_r7_frag_state_load_u64_be(const uint8_t *i)
{
    return ((uint64_t)i[0] << 56) | ((uint64_t)i[1] << 48)
        | ((uint64_t)i[2] << 40) | ((uint64_t)i[3] << 32)
        | ((uint64_t)i[4] << 24) | ((uint64_t)i[5] << 16)
        | ((uint64_t)i[6] << 8) | (uint64_t)i[7];
}

static void ninlil_r7_frag_state_intent_partial(
    ninlil_r7_frag_state_ack_intent *out,
    uint64_t handle,
    uint16_t frag_count,
    uint16_t bitmap)
{
    memset(out, 0, sizeof(*out));
    out->valid = 1u;
    out->transfer_handle = handle;
    out->frag_count = frag_count;
    out->received_bitmap = bitmap;
    out->status = NINLIL_R7_FRAG_STATE_STATUS_PARTIAL;
    out->reason = NINLIL_R7_FRAG_STATE_REASON_NONE;
}

static void ninlil_r7_frag_state_intent_terminal(
    ninlil_r7_frag_state_ack_intent *out,
    uint64_t handle,
    uint16_t frag_count,
    uint16_t bitmap,
    uint8_t status,
    uint8_t reason)
{
    memset(out, 0, sizeof(*out));
    out->valid = 1u;
    out->transfer_handle = handle;
    out->frag_count = frag_count;
    out->received_bitmap = bitmap;
    out->status = status;
    out->reason = reason;
}

/* -------------------------------------------------------------------------- */
/* Plan                                                                       */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_state_status ninlil_r7_frag_state_plan_validate(
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint16_t frag_count,
    uint16_t continuation_unit)
{
    uint32_t rem;
    uint32_t ceil_div;
    uint16_t expected;

    if (continuation_unit != NINLIL_R7_FRAG_STATE_CONT_UNIT) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    if (first_chunk_len < NINLIL_R7_FRAG_STATE_S_MIN
        || first_chunk_len > NINLIL_R7_FRAG_STATE_S_MAX) {
        return NINLIL_R7_FRAG_STATE_LENGTH;
    }
    if (total_len <= (uint32_t)first_chunk_len
        || total_len > NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX) {
        return NINLIL_R7_FRAG_STATE_LENGTH;
    }
    if (frag_count < NINLIL_R7_FRAG_STATE_FRAG_COUNT_MIN
        || frag_count > NINLIL_R7_FRAG_STATE_FRAG_COUNT_MAX) {
        return NINLIL_R7_FRAG_STATE_LENGTH;
    }
    rem = total_len - (uint32_t)first_chunk_len;
    ceil_div = (rem + (uint32_t)NINLIL_R7_FRAG_STATE_CONT_UNIT - 1u)
        / (uint32_t)NINLIL_R7_FRAG_STATE_CONT_UNIT;
    expected = (uint16_t)(1u + ceil_div);
    if (frag_count != expected) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    return NINLIL_R7_FRAG_STATE_OK;
}

ninlil_r7_frag_state_status ninlil_r7_frag_state_plan_build(
    uint32_t total_len,
    ninlil_r7_frag_state_plan *out_plan)
{
    ninlil_r7_frag_state_plan cand;
    uint16_t s;
    uint32_t rem;
    uint32_t ceil_div;
    uint16_t fc;
    uint16_t i;
    uint32_t off;
    ninlil_r7_frag_state_status st;

    if (out_plan == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    if (total_len < 2u || total_len > NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX) {
        return NINLIL_R7_FRAG_STATE_LENGTH;
    }

    memset(&cand, 0, sizeof(cand));
    if ((total_len - 1u) < (uint32_t)NINLIL_R7_FRAG_STATE_S_MAX) {
        s = (uint16_t)(total_len - 1u);
    } else {
        s = NINLIL_R7_FRAG_STATE_S_MAX;
    }
    rem = total_len - (uint32_t)s;
    ceil_div = (rem + (uint32_t)NINLIL_R7_FRAG_STATE_CONT_UNIT - 1u)
        / (uint32_t)NINLIL_R7_FRAG_STATE_CONT_UNIT;
    fc = (uint16_t)(1u + ceil_div);
    st = ninlil_r7_frag_state_plan_validate(
        total_len, s, fc, NINLIL_R7_FRAG_STATE_CONT_UNIT);
    if (st != NINLIL_R7_FRAG_STATE_OK) {
        return st;
    }

    cand.total_len = total_len;
    cand.frag_count = fc;
    cand.first_chunk_len = s;
    cand.cont_unit = NINLIL_R7_FRAG_STATE_CONT_UNIT;
    cand.chunks[0].frag_index = 0u;
    cand.chunks[0].offset = 0u;
    cand.chunks[0].length = s;

    off = s;
    for (i = 1u; i < fc; i++) {
        uint32_t left = total_len - off;
        uint16_t clen = (left > (uint32_t)NINLIL_R7_FRAG_STATE_CONT_UNIT)
            ? NINLIL_R7_FRAG_STATE_CONT_UNIT
            : (uint16_t)left;
        if ((i + 1u) < fc && clen != NINLIL_R7_FRAG_STATE_CONT_UNIT) {
            return NINLIL_R7_FRAG_STATE_INTERNAL;
        }
        if (clen < NINLIL_R7_FRAG_STATE_C_MIN
            || clen > NINLIL_R7_FRAG_STATE_C_MAX) {
            return NINLIL_R7_FRAG_STATE_LENGTH;
        }
        cand.chunks[i].frag_index = i;
        cand.chunks[i].offset = (uint16_t)off;
        cand.chunks[i].length = clen;
        off += (uint32_t)clen;
    }
    if (off != total_len) {
        return NINLIL_R7_FRAG_STATE_INTERNAL;
    }
    *out_plan = cand;
    ninlil_r7_frag_state_secure_zero(&cand, sizeof(cand));
    return NINLIL_R7_FRAG_STATE_OK;
}

ninlil_r7_frag_state_status ninlil_r7_frag_state_cont_geometry(
    uint32_t total_len,
    uint16_t first_chunk_len,
    uint16_t frag_count,
    uint16_t frag_index,
    uint16_t *out_offset,
    uint16_t *out_length)
{
    uint32_t offset;
    uint32_t remaining;
    uint16_t clen;
    ninlil_r7_frag_state_status st;

    if (out_offset == NULL || out_length == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    st = ninlil_r7_frag_state_plan_validate(
        total_len, first_chunk_len, frag_count,
        NINLIL_R7_FRAG_STATE_CONT_UNIT);
    if (st != NINLIL_R7_FRAG_STATE_OK) {
        return st;
    }
    if (frag_index < 1u || frag_index >= frag_count) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    offset = (uint32_t)first_chunk_len
        + (uint32_t)(frag_index - 1u)
            * (uint32_t)NINLIL_R7_FRAG_STATE_CONT_UNIT;
    if (offset >= total_len) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    remaining = total_len - offset;
    clen = (remaining > (uint32_t)NINLIL_R7_FRAG_STATE_CONT_UNIT)
        ? NINLIL_R7_FRAG_STATE_CONT_UNIT
        : (uint16_t)remaining;
    if ((frag_index + 1u) < frag_count
        && clen != NINLIL_R7_FRAG_STATE_CONT_UNIT) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    *out_offset = (uint16_t)offset;
    *out_length = clen;
    return NINLIL_R7_FRAG_STATE_OK;
}

/* -------------------------------------------------------------------------- */
/* Index helpers                                                              */
/* -------------------------------------------------------------------------- */

static ninlil_r7_frag_state_slot *find_reasm_handle(
    ninlil_r7_frag_state_engine *eng, uint32_t ctx, uint64_t handle)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_REASM_SLOTS; i++) {
        if (eng->reasm[i].in_use
            && eng->reasm[i].e2e_context_id == ctx
            && eng->reasm[i].transfer_handle == handle) {
            return &eng->reasm[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_state_slot *find_reasm_tid(
    ninlil_r7_frag_state_engine *eng, uint32_t ctx, const uint8_t tid[16])
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_REASM_SLOTS; i++) {
        if (eng->reasm[i].in_use
            && eng->reasm[i].e2e_context_id == ctx
            && ninlil_r7_frag_state_tid_eq(eng->reasm[i].transfer_id, tid)) {
            return &eng->reasm[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_state_tombstone *find_tomb_handle(
    ninlil_r7_frag_state_engine *eng, uint32_t ctx, uint64_t handle)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS; i++) {
        if (eng->tombs[i].in_use
            && eng->tombs[i].e2e_context_id == ctx
            && eng->tombs[i].transfer_handle == handle) {
            return &eng->tombs[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_state_tombstone *find_tomb_tid(
    ninlil_r7_frag_state_engine *eng, uint32_t ctx, const uint8_t tid[16])
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS; i++) {
        if (eng->tombs[i].in_use
            && eng->tombs[i].e2e_context_id == ctx
            && ninlil_r7_frag_state_tid_eq(eng->tombs[i].transfer_id, tid)) {
            return &eng->tombs[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_state_status tomb_reserve(
    ninlil_r7_frag_state_engine *eng, size_t *out_slot)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS; i++) {
        if (!eng->tombs[i].in_use) {
            *out_slot = i;
            return NINLIL_R7_FRAG_STATE_OK;
        }
    }
    return NINLIL_R7_FRAG_STATE_RESOURCE;
}

static void tomb_commit_terminal(
    ninlil_r7_frag_state_engine *eng,
    size_t slot,
    uint32_t ctx,
    uint64_t kgen,
    const uint8_t tid[16],
    uint64_t handle,
    uint16_t frag_count,
    uint8_t status,
    uint8_t reason,
    const uint8_t fp[32],
    uint64_t expiry)
{
    ninlil_r7_frag_state_tombstone *T = &eng->tombs[slot];
    memset(T, 0, sizeof(*T));
    T->in_use = 1u;
    T->is_reservation = 0u;
    T->e2e_context_id = ctx;
    T->key_generation = kgen;
    ninlil_r7_frag_state_copy(T->transfer_id, tid, 16u);
    T->transfer_handle = handle;
    T->frag_count = frag_count;
    T->status = status;
    T->reason = reason;
    ninlil_r7_frag_state_copy(T->fingerprint, fp, 32u);
    T->expiry_mono = expiry;
}

static void release_slot_payload(
    ninlil_r7_frag_state_engine *eng, ninlil_r7_frag_state_slot *S)
{
    if (eng->payload_bytes_in_use >= S->total_len) {
        eng->payload_bytes_in_use -= S->total_len;
    } else {
        eng->payload_bytes_in_use = 0u;
    }
    ninlil_r7_frag_state_secure_zero(S, sizeof(*S));
}

static ninlil_r7_frag_state_status try_complete(
    ninlil_r7_frag_state_engine *eng,
    ninlil_r7_frag_state_slot *S,
    const uint8_t *reassembled_digest32,
    ninlil_r7_frag_state_ack_intent *out_intent)
{
    uint64_t expiry;
    size_t tomb_slot;

    if (S->bitmap != ninlil_r7_frag_state_full_bitmap(S->frag_count)) {
        return NINLIL_R7_FRAG_STATE_OK;
    }
    if (reassembled_digest32 == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_state_checked_add(
            eng->now_mono, NINLIL_R7_FRAG_STATE_TOMBSTONE_TTL_MS, &expiry)) {
        eng->fenced = 1u;
        return NINLIL_R7_FRAG_STATE_FENCED;
    }

    tomb_slot = S->tomb_reserve_slot;
    if (tomb_slot >= NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS
        || !eng->tombs[tomb_slot].in_use) {
        if (tomb_reserve(eng, &tomb_slot) != NINLIL_R7_FRAG_STATE_OK) {
            return NINLIL_R7_FRAG_STATE_RESOURCE;
        }
    }

    /* Digest binding */
    if (memcmp(reassembled_digest32, S->content_digest, 32u) != 0) {
        tomb_commit_terminal(
            eng, tomb_slot, S->e2e_context_id, S->key_generation,
            S->transfer_id, S->transfer_handle, S->frag_count,
            NINLIL_R7_FRAG_STATE_STATUS_ABORT,
            NINLIL_R7_FRAG_STATE_REASON_DIGEST, S->fingerprint, expiry);
        ninlil_r7_frag_state_intent_terminal(
            out_intent, S->transfer_handle, S->frag_count, 0u,
            NINLIL_R7_FRAG_STATE_STATUS_ABORT,
            NINLIL_R7_FRAG_STATE_REASON_DIGEST);
        release_slot_payload(eng, S);
        return NINLIL_R7_FRAG_STATE_DIGEST;
    }

    /* Upper queue: single publication slot; no partial expose. */
    if (eng->pub.valid) {
        tomb_commit_terminal(
            eng, tomb_slot, S->e2e_context_id, S->key_generation,
            S->transfer_id, S->transfer_handle, S->frag_count,
            NINLIL_R7_FRAG_STATE_STATUS_ABORT,
            NINLIL_R7_FRAG_STATE_REASON_RESOURCE, S->fingerprint, expiry);
        ninlil_r7_frag_state_intent_terminal(
            out_intent, S->transfer_handle, S->frag_count, 0u,
            NINLIL_R7_FRAG_STATE_STATUS_ABORT,
            NINLIL_R7_FRAG_STATE_REASON_RESOURCE);
        release_slot_payload(eng, S);
        return NINLIL_R7_FRAG_STATE_RESOURCE;
    }

    /* Atomic: stage publication + COMPLETE tombstone, then free reasm. */
    eng->pub.e2e_context_id = S->e2e_context_id;
    eng->pub.key_generation = S->key_generation;
    eng->pub.transfer_handle = S->transfer_handle;
    eng->pub.total_len = S->total_len;
    ninlil_r7_frag_state_copy(eng->pub.payload, S->payload, S->total_len);
    eng->pub.valid = 1u;
    eng->publish_count += 1u;

    tomb_commit_terminal(
        eng, tomb_slot, S->e2e_context_id, S->key_generation, S->transfer_id,
        S->transfer_handle, S->frag_count, NINLIL_R7_FRAG_STATE_STATUS_COMPLETE,
        NINLIL_R7_FRAG_STATE_REASON_NONE, S->fingerprint, expiry);

    ninlil_r7_frag_state_intent_terminal(
        out_intent, S->transfer_handle, S->frag_count,
        ninlil_r7_frag_state_full_bitmap(S->frag_count),
        NINLIL_R7_FRAG_STATE_STATUS_COMPLETE,
        NINLIL_R7_FRAG_STATE_REASON_NONE);
    release_slot_payload(eng, S);
    return NINLIL_R7_FRAG_STATE_OK;
}

/* -------------------------------------------------------------------------- */
/* Engine lifecycle                                                           */
/* -------------------------------------------------------------------------- */

void ninlil_r7_frag_state_init(ninlil_r7_frag_state_engine *eng)
{
    if (eng == NULL) {
        return;
    }
    memset(eng, 0, sizeof(*eng));
}

void ninlil_r7_frag_state_zeroize(ninlil_r7_frag_state_engine *eng)
{
    if (eng == NULL) {
        return;
    }
    ninlil_r7_frag_state_secure_zero(eng, sizeof(*eng));
}

void ninlil_r7_frag_state_set_now(
    ninlil_r7_frag_state_engine *eng, uint64_t now_mono)
{
    if (eng == NULL) {
        return;
    }
    eng->now_mono = now_mono;
}

/* -------------------------------------------------------------------------- */
/* Admit START                                                                */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_state_status ninlil_r7_frag_state_admit_start(
    ninlil_r7_frag_state_engine *eng,
    const ninlil_r7_frag_state_start_in *in,
    ninlil_r7_frag_state_ack_intent *out_intent)
{
    ninlil_r7_frag_state_status st;
    ninlil_r7_frag_state_slot *ah;
    ninlil_r7_frag_state_slot *at;
    ninlil_r7_frag_state_tombstone *th;
    ninlil_r7_frag_state_tombstone *tt;
    size_t free_slot;
    size_t tomb_slot;
    size_t i;
    uint64_t abs_dl;
    uint64_t idle_dl;
    uint64_t partial_due;

    if (eng == NULL || in == NULL || out_intent == NULL
        || in->first_chunk == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    memset(out_intent, 0, sizeof(*out_intent));
    if (eng->fenced) {
        return NINLIL_R7_FRAG_STATE_FENCED;
    }
    if (!ninlil_r7_frag_state_context_ok(in->e2e_context_id)
        || in->key_generation == 0u
        || !ninlil_r7_frag_state_handle_ok(in->transfer_handle)) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    st = ninlil_r7_frag_state_plan_validate(
        in->total_len, in->first_chunk_len, in->frag_count,
        in->continuation_unit);
    if (st != NINLIL_R7_FRAG_STATE_OK) {
        return st;
    }
    if ((size_t)in->first_chunk_len != (size_t)in->first_chunk_len) {
        return NINLIL_R7_FRAG_STATE_LENGTH;
    }

    ah = find_reasm_handle(eng, in->e2e_context_id, in->transfer_handle);
    at = find_reasm_tid(eng, in->e2e_context_id, in->transfer_id);
    th = find_tomb_handle(eng, in->e2e_context_id, in->transfer_handle);
    tt = find_tomb_tid(eng, in->e2e_context_id, in->transfer_id);

    if (ah != NULL || at != NULL) {
        ninlil_r7_frag_state_slot *S = (ah != NULL) ? ah : at;
        if (ah != NULL && at != NULL && ah != at) {
            ninlil_r7_frag_state_intent_terminal(
                out_intent, in->transfer_handle, in->frag_count, 0u,
                NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                NINLIL_R7_FRAG_STATE_REASON_CONFLICT);
            return NINLIL_R7_FRAG_STATE_CONFLICT;
        }
        /* Generation / context binding: active slot must match. */
        if (S->key_generation != in->key_generation) {
            ninlil_r7_frag_state_intent_terminal(
                out_intent, in->transfer_handle, in->frag_count, 0u,
                NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                NINLIL_R7_FRAG_STATE_REASON_CONFLICT);
            return NINLIL_R7_FRAG_STATE_CONFLICT;
        }
        if (memcmp(S->fingerprint, in->fingerprint, 32u) == 0
            && S->total_len == in->total_len
            && S->frag_count == in->frag_count
            && S->first_chunk_len == in->first_chunk_len
            && memcmp(S->content_digest, in->content_digest, 32u) == 0
            && memcmp(S->payload, in->first_chunk, in->first_chunk_len) == 0) {
            /* Exact retry: no mutation. */
            ninlil_r7_frag_state_intent_partial(
                out_intent, S->transfer_handle, S->frag_count, S->bitmap);
            return NINLIL_R7_FRAG_STATE_EXACT_RETRY;
        }
        ninlil_r7_frag_state_intent_terminal(
            out_intent, in->transfer_handle, in->frag_count, 0u,
            NINLIL_R7_FRAG_STATE_STATUS_ABORT,
            NINLIL_R7_FRAG_STATE_REASON_CONFLICT);
        return NINLIL_R7_FRAG_STATE_CONFLICT;
    }

    if (th != NULL || tt != NULL) {
        ninlil_r7_frag_state_tombstone *T = (th != NULL) ? th : tt;
        if (th != NULL && tt != NULL && th != tt) {
            ninlil_r7_frag_state_intent_terminal(
                out_intent, in->transfer_handle, in->frag_count, 0u,
                NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                NINLIL_R7_FRAG_STATE_REASON_CONFLICT);
            return NINLIL_R7_FRAG_STATE_CONFLICT;
        }
        if (!T->is_reservation
            && memcmp(T->fingerprint, in->fingerprint, 32u) == 0) {
            ninlil_r7_frag_state_intent_terminal(
                out_intent, T->transfer_handle, T->frag_count,
                (T->status == NINLIL_R7_FRAG_STATE_STATUS_COMPLETE)
                    ? ninlil_r7_frag_state_full_bitmap(T->frag_count)
                    : 0u,
                T->status, T->reason);
            return NINLIL_R7_FRAG_STATE_EXACT_RETRY;
        }
        if (!T->is_reservation) {
            ninlil_r7_frag_state_intent_terminal(
                out_intent, in->transfer_handle, in->frag_count, 0u,
                NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                NINLIL_R7_FRAG_STATE_REASON_CONFLICT);
            return NINLIL_R7_FRAG_STATE_CONFLICT;
        }
    }

    /* START_RESERVE_FAIL_ACK0_ONLY: reserve tombstone before owner. */
    if (tomb_reserve(eng, &tomb_slot) != NINLIL_R7_FRAG_STATE_OK) {
        return NINLIL_R7_FRAG_STATE_RESOURCE;
    }
    memset(&eng->tombs[tomb_slot], 0, sizeof(eng->tombs[tomb_slot]));
    eng->tombs[tomb_slot].in_use = 1u;
    eng->tombs[tomb_slot].is_reservation = 1u;
    eng->tombs[tomb_slot].e2e_context_id = in->e2e_context_id;
    eng->tombs[tomb_slot].key_generation = in->key_generation;
    ninlil_r7_frag_state_copy(
        eng->tombs[tomb_slot].transfer_id, in->transfer_id, 16u);
    eng->tombs[tomb_slot].transfer_handle = in->transfer_handle;
    eng->tombs[tomb_slot].frag_count = in->frag_count;
    ninlil_r7_frag_state_copy(
        eng->tombs[tomb_slot].fingerprint, in->fingerprint, 32u);

    if (eng->payload_bytes_in_use + (size_t)in->total_len
        > NINLIL_R7_FRAG_STATE_PAYLOAD_BUDGET) {
        eng->tombs[tomb_slot].in_use = 0u;
        return NINLIL_R7_FRAG_STATE_RESOURCE;
    }
    free_slot = NINLIL_R7_FRAG_STATE_REASM_SLOTS;
    {
        size_t peer_count = 0u;
        for (i = 0u; i < NINLIL_R7_FRAG_STATE_REASM_SLOTS; i++) {
            if (eng->reasm[i].in_use
                && eng->reasm[i].e2e_context_id == in->e2e_context_id) {
                peer_count++;
            }
            if (!eng->reasm[i].in_use && free_slot >= NINLIL_R7_FRAG_STATE_REASM_SLOTS) {
                free_slot = i;
            }
        }
        if (peer_count >= NINLIL_R7_FRAG_STATE_MAX_PER_PEER) {
            eng->tombs[tomb_slot].in_use = 0u;
            return NINLIL_R7_FRAG_STATE_RESOURCE;
        }
    }
    if (free_slot >= NINLIL_R7_FRAG_STATE_REASM_SLOTS) {
        eng->tombs[tomb_slot].in_use = 0u;
        return NINLIL_R7_FRAG_STATE_RESOURCE;
    }
    if (!ninlil_r7_frag_state_checked_add(
            eng->now_mono, NINLIL_R7_FRAG_STATE_RECEIVER_TTL_MS, &abs_dl)
        || !ninlil_r7_frag_state_checked_add(
            eng->now_mono, NINLIL_R7_FRAG_STATE_IDLE_TIMEOUT_MS, &idle_dl)
        || !ninlil_r7_frag_state_checked_add(
            eng->now_mono, NINLIL_R7_FRAG_STATE_PARTIAL_ACK_IDLE_MS,
            &partial_due)) {
        eng->tombs[tomb_slot].in_use = 0u;
        eng->fenced = 1u;
        return NINLIL_R7_FRAG_STATE_FENCED;
    }

    {
        ninlil_r7_frag_state_slot *S = &eng->reasm[free_slot];
        memset(S, 0, sizeof(*S));
        S->in_use = 1u;
        S->e2e_context_id = in->e2e_context_id;
        S->key_generation = in->key_generation;
        ninlil_r7_frag_state_copy(S->transfer_id, in->transfer_id, 16u);
        S->transfer_handle = in->transfer_handle;
        S->total_len = in->total_len;
        S->frag_count = in->frag_count;
        S->first_chunk_len = in->first_chunk_len;
        ninlil_r7_frag_state_copy(S->content_digest, in->content_digest, 32u);
        ninlil_r7_frag_state_copy(S->fingerprint, in->fingerprint, 32u);
        S->bitmap = 0x0001u;
        S->chunk_seen[0] = 1u;
        S->chunk_len[0] = in->first_chunk_len;
        ninlil_r7_frag_state_copy(
            S->payload, in->first_chunk, in->first_chunk_len);
        S->receiver_start_mono = eng->now_mono;
        S->receiver_absolute_deadline = abs_dl;
        S->idle_deadline = idle_dl;
        S->partial_ack_due = partial_due;
        S->tomb_reserve_slot = tomb_slot;
        eng->payload_bytes_in_use += (size_t)in->total_len;
        ninlil_r7_frag_state_intent_partial(
            out_intent, S->transfer_handle, S->frag_count, S->bitmap);
    }
    return NINLIL_R7_FRAG_STATE_OK;
}

/* -------------------------------------------------------------------------- */
/* Admit CONT                                                                 */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_state_status ninlil_r7_frag_state_admit_cont(
    ninlil_r7_frag_state_engine *eng,
    const ninlil_r7_frag_state_cont_in *in,
    ninlil_r7_frag_state_ack_intent *out_intent)
{
    ninlil_r7_frag_state_slot *S;
    ninlil_r7_frag_state_tombstone *T;
    uint16_t offset;
    uint16_t expect_len;
    uint64_t new_idle;
    uint64_t new_due;
    ninlil_r7_frag_state_status st;

    if (eng == NULL || in == NULL || out_intent == NULL || in->chunk == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    memset(out_intent, 0, sizeof(*out_intent));
    if (eng->fenced) {
        return NINLIL_R7_FRAG_STATE_FENCED;
    }
    if (!ninlil_r7_frag_state_context_ok(in->e2e_context_id)
        || in->key_generation == 0u
        || !ninlil_r7_frag_state_handle_ok(in->transfer_handle)) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }

    S = find_reasm_handle(eng, in->e2e_context_id, in->transfer_handle);
    T = find_tomb_handle(eng, in->e2e_context_id, in->transfer_handle);

    if (S == NULL) {
        if (T != NULL && !T->is_reservation) {
            /* Tombstone exact identity: key_generation + frag_index bounds. */
            if (T->key_generation != in->key_generation) {
                return NINLIL_R7_FRAG_STATE_CONFLICT;
            }
            if (T->frag_count == 0u
                || in->frag_index >= T->frag_count
                || in->frag_index == 0u) {
                /* Out-of-range CONT must not regenerate terminal ACK. */
                return NINLIL_R7_FRAG_STATE_STRUCTURAL;
            }
            ninlil_r7_frag_state_intent_terminal(
                out_intent, T->transfer_handle, T->frag_count,
                (T->status == NINLIL_R7_FRAG_STATE_STATUS_COMPLETE)
                    ? ninlil_r7_frag_state_full_bitmap(T->frag_count)
                    : 0u,
                T->status, T->reason);
            return NINLIL_R7_FRAG_STATE_EXACT_RETRY;
        }
        return NINLIL_R7_FRAG_STATE_NO_TRANSFER;
    }

    if (S->key_generation != in->key_generation) {
        return NINLIL_R7_FRAG_STATE_CONFLICT;
    }

    st = ninlil_r7_frag_state_cont_geometry(
        S->total_len, S->first_chunk_len, S->frag_count, in->frag_index,
        &offset, &expect_len);
    if (st != NINLIL_R7_FRAG_STATE_OK) {
        return st;
    }
    if (in->chunk_len != expect_len) {
        return NINLIL_R7_FRAG_STATE_LENGTH;
    }

    if (S->chunk_seen[in->frag_index]) {
        if (S->chunk_len[in->frag_index] == in->chunk_len
            && memcmp(S->payload + offset, in->chunk, in->chunk_len) == 0) {
            /* Full + need_digest + digest supplied → complete (retry path). */
            if (S->need_digest != 0u
                && S->bitmap == ninlil_r7_frag_state_full_bitmap(S->frag_count)
                && in->reassembled_digest32 != NULL) {
                S->need_digest = 0u;
                return try_complete(
                    eng, S, in->reassembled_digest32, out_intent);
            }
            if (S->need_digest != 0u && in->reassembled_digest32 == NULL) {
                memset(out_intent, 0, sizeof(*out_intent));
                return NINLIL_R7_FRAG_STATE_NEED_DIGEST;
            }
            /* Identical duplicate: no mutation. */
            ninlil_r7_frag_state_intent_partial(
                out_intent, S->transfer_handle, S->frag_count, S->bitmap);
            return NINLIL_R7_FRAG_STATE_DUPLICATE;
        }
        /* Conflicting duplicate → ABORT CONFLICT tombstone. */
        {
            uint64_t expiry;
            size_t tomb_slot = S->tomb_reserve_slot;
            if (!ninlil_r7_frag_state_checked_add(
                    eng->now_mono, NINLIL_R7_FRAG_STATE_TOMBSTONE_TTL_MS,
                    &expiry)) {
                eng->fenced = 1u;
                return NINLIL_R7_FRAG_STATE_FENCED;
            }
            if (tomb_slot >= NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS
                || !eng->tombs[tomb_slot].in_use) {
                if (tomb_reserve(eng, &tomb_slot) != NINLIL_R7_FRAG_STATE_OK) {
                    return NINLIL_R7_FRAG_STATE_RESOURCE;
                }
            }
            tomb_commit_terminal(
                eng, tomb_slot, S->e2e_context_id, S->key_generation,
                S->transfer_id, S->transfer_handle, S->frag_count,
                NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                NINLIL_R7_FRAG_STATE_REASON_CONFLICT, S->fingerprint, expiry);
            ninlil_r7_frag_state_intent_terminal(
                out_intent, S->transfer_handle, S->frag_count, 0u,
                NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                NINLIL_R7_FRAG_STATE_REASON_CONFLICT);
            release_slot_payload(eng, S);
            return NINLIL_R7_FRAG_STATE_CONFLICT;
        }
    }

    /*
     * Precompute deadlines BEFORE payload/bitmap mutation. Overflow leaves
     * state unchanged (or atomic terminal fence) — docs/30 CONT atomicity.
     */
    {
        uint16_t next_bitmap = (uint16_t)(S->bitmap
            | (uint16_t)(1u << in->frag_index));
        int full = (next_bitmap
            == ninlil_r7_frag_state_full_bitmap(S->frag_count));
        if (!ninlil_r7_frag_state_checked_add(
                eng->now_mono, NINLIL_R7_FRAG_STATE_IDLE_TIMEOUT_MS,
                &new_idle)) {
            eng->fenced = 1u;
            ninlil_r7_frag_state_intent_terminal(
                out_intent, S->transfer_handle, S->frag_count, 0u,
                NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                NINLIL_R7_FRAG_STATE_REASON_FENCED);
            return NINLIL_R7_FRAG_STATE_FENCED;
        }
        if (new_idle > S->receiver_absolute_deadline) {
            new_idle = S->receiver_absolute_deadline;
        }
        if (!full) {
            if (!ninlil_r7_frag_state_checked_add(
                    eng->now_mono, NINLIL_R7_FRAG_STATE_PARTIAL_ACK_IDLE_MS,
                    &new_due)) {
                eng->fenced = 1u;
                ninlil_r7_frag_state_intent_terminal(
                    out_intent, S->transfer_handle, S->frag_count, 0u,
                    NINLIL_R7_FRAG_STATE_STATUS_ABORT,
                    NINLIL_R7_FRAG_STATE_REASON_FENCED);
                return NINLIL_R7_FRAG_STATE_FENCED;
            }
            if (new_due > S->receiver_absolute_deadline) {
                new_due = S->receiver_absolute_deadline;
            }
        }
        /* Commit mutation only after all checked arithmetic succeeds. */
        ninlil_r7_frag_state_copy(S->payload + offset, in->chunk, in->chunk_len);
        S->chunk_seen[in->frag_index] = 1u;
        S->chunk_len[in->frag_index] = in->chunk_len;
        S->bitmap = next_bitmap;
        S->idle_deadline = new_idle;
        if (full) {
            if (in->reassembled_digest32 == NULL) {
                /* Payload committed for peek; digest retry/finalize allowed. */
                S->need_digest = 1u;
                memset(out_intent, 0, sizeof(*out_intent));
                return NINLIL_R7_FRAG_STATE_NEED_DIGEST;
            }
            S->need_digest = 0u;
            return try_complete(eng, S, in->reassembled_digest32, out_intent);
        }
        if (S->partial_ack_due == 0u || new_due < S->partial_ack_due) {
            S->partial_ack_due = new_due;
        }
        ninlil_r7_frag_state_intent_partial(
            out_intent, S->transfer_handle, S->frag_count, S->bitmap);
        return NINLIL_R7_FRAG_STATE_OK;
    }
}

ninlil_r7_frag_state_status ninlil_r7_frag_state_peek_reassembled(
    const ninlil_r7_frag_state_engine *eng,
    uint32_t e2e_context_id,
    uint64_t transfer_handle,
    const uint8_t **out_payload,
    size_t *out_len)
{
    size_t i;
    if (eng == NULL || out_payload == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_STATE_REASM_SLOTS; i++) {
        const ninlil_r7_frag_state_slot *S = &eng->reasm[i];
        if (S->in_use && S->e2e_context_id == e2e_context_id
            && S->transfer_handle == transfer_handle) {
            if (S->bitmap != ninlil_r7_frag_state_full_bitmap(S->frag_count)) {
                return NINLIL_R7_FRAG_STATE_STRUCTURAL;
            }
            *out_payload = S->payload;
            *out_len = S->total_len;
            return NINLIL_R7_FRAG_STATE_OK;
        }
    }
    return NINLIL_R7_FRAG_STATE_NO_TRANSFER;
}

ninlil_r7_frag_state_status ninlil_r7_frag_state_finalize(
    ninlil_r7_frag_state_engine *eng,
    uint32_t e2e_context_id,
    uint64_t transfer_handle,
    const uint8_t reassembled_digest32[32],
    ninlil_r7_frag_state_ack_intent *out_intent)
{
    ninlil_r7_frag_state_slot *S;

    if (eng == NULL || reassembled_digest32 == NULL || out_intent == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    memset(out_intent, 0, sizeof(*out_intent));
    S = find_reasm_handle(eng, e2e_context_id, transfer_handle);
    if (S == NULL) {
        return NINLIL_R7_FRAG_STATE_NO_TRANSFER;
    }
    if (S->bitmap != ninlil_r7_frag_state_full_bitmap(S->frag_count)) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    S->need_digest = 0u;
    return try_complete(eng, S, reassembled_digest32, out_intent);
}

/* -------------------------------------------------------------------------- */
/* Tick / publication                                                         */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_state_status ninlil_r7_frag_state_tick(
    ninlil_r7_frag_state_engine *eng,
    uint64_t now_mono)
{
    size_t i;

    if (eng == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    eng->now_mono = now_mono;

    for (i = 0u; i < NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS; i++) {
        if (eng->tombs[i].in_use && !eng->tombs[i].is_reservation
            && eng->tombs[i].expiry_mono != 0u
            && now_mono >= eng->tombs[i].expiry_mono) {
            ninlil_r7_frag_state_secure_zero(
                &eng->tombs[i], sizeof(eng->tombs[i]));
        }
    }

    for (i = 0u; i < NINLIL_R7_FRAG_STATE_REASM_SLOTS; i++) {
        ninlil_r7_frag_state_slot *S = &eng->reasm[i];
        uint64_t expiry;
        size_t tomb_slot;
        if (!S->in_use) {
            continue;
        }
        if (now_mono < S->idle_deadline
            && now_mono < S->receiver_absolute_deadline) {
            continue;
        }
        if (!ninlil_r7_frag_state_checked_add(
                now_mono, NINLIL_R7_FRAG_STATE_TOMBSTONE_TTL_MS, &expiry)) {
            eng->fenced = 1u;
            return NINLIL_R7_FRAG_STATE_FENCED;
        }
        tomb_slot = S->tomb_reserve_slot;
        if (tomb_slot >= NINLIL_R7_FRAG_STATE_TOMBSTONE_SLOTS
            || !eng->tombs[tomb_slot].in_use) {
            if (tomb_reserve(eng, &tomb_slot) != NINLIL_R7_FRAG_STATE_OK) {
                return NINLIL_R7_FRAG_STATE_RESOURCE;
            }
        }
        tomb_commit_terminal(
            eng, tomb_slot, S->e2e_context_id, S->key_generation,
            S->transfer_id, S->transfer_handle, S->frag_count,
            NINLIL_R7_FRAG_STATE_STATUS_ABORT,
            NINLIL_R7_FRAG_STATE_REASON_TIMEOUT, S->fingerprint, expiry);
        release_slot_payload(eng, S);
    }
    return NINLIL_R7_FRAG_STATE_OK;
}

ninlil_r7_frag_state_status ninlil_r7_frag_state_take_publication(
    ninlil_r7_frag_state_engine *eng,
    uint32_t *out_e2e_context_id,
    uint64_t *out_key_generation,
    uint64_t *out_transfer_handle,
    uint8_t *out_payload,
    size_t out_capacity,
    size_t *out_len)
{
    if (eng == NULL || out_e2e_context_id == NULL || out_key_generation == NULL
        || out_transfer_handle == NULL || out_payload == NULL
        || out_len == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    if (!eng->pub.valid) {
        return NINLIL_R7_FRAG_STATE_NO_TRANSFER;
    }
    if (out_capacity < eng->pub.total_len) {
        return NINLIL_R7_FRAG_STATE_CAPACITY;
    }
    *out_e2e_context_id = eng->pub.e2e_context_id;
    *out_key_generation = eng->pub.key_generation;
    *out_transfer_handle = eng->pub.transfer_handle;
    ninlil_r7_frag_state_copy(
        out_payload, eng->pub.payload, eng->pub.total_len);
    *out_len = eng->pub.total_len;

    ninlil_r7_frag_state_secure_zero(eng->pub.payload, sizeof(eng->pub.payload));
    eng->pub.valid = 0u;
    eng->pub.total_len = 0u;
    eng->pub.e2e_context_id = 0u;
    eng->pub.key_generation = 0u;
    eng->pub.transfer_handle = 0u;
    return NINLIL_R7_FRAG_STATE_PUBLISHED;
}

/* -------------------------------------------------------------------------- */
/* Restart snapshot                                                           */
/* Layout (BE, exact 24 B):                                                   */
/*   magic u32 | version u16 | reasm_claim u16 | tomb_claim u16 |             */
/*   reserved u16 | now_mono u64 | fence u8 | pad3                            */
/* reasm_claim and tomb_claim MUST be 0 (volatile restart).                   */
/* -------------------------------------------------------------------------- */

#define SNAP_LEN ((size_t)24u)

ninlil_r7_frag_state_status ninlil_r7_frag_state_restart_encode(
    const ninlil_r7_frag_state_engine *eng,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    if (eng == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    if (out_capacity < SNAP_LEN) {
        return NINLIL_R7_FRAG_STATE_CAPACITY;
    }
    memset(out, 0, SNAP_LEN);
    ninlil_r7_frag_state_store_u32_be(out + 0, NINLIL_R7_FRAG_STATE_SNAP_MAGIC);
    ninlil_r7_frag_state_store_u16_be(out + 4, NINLIL_R7_FRAG_STATE_SNAP_VERSION);
    ninlil_r7_frag_state_store_u16_be(out + 6, 0u); /* reasm_claim */
    ninlil_r7_frag_state_store_u16_be(out + 8, 0u); /* tomb_claim */
    ninlil_r7_frag_state_store_u16_be(out + 10, 0u);
    ninlil_r7_frag_state_store_u64_be(out + 12, eng->now_mono);
    out[20] = eng->fenced;
    /* pad 21..23 = 0 */
    *out_len = SNAP_LEN;
    return NINLIL_R7_FRAG_STATE_OK;
}

ninlil_r7_frag_state_status ninlil_r7_frag_state_restart_decode(
    ninlil_r7_frag_state_engine *eng,
    const uint8_t *in,
    size_t in_len)
{
    uint32_t magic;
    uint16_t version;
    uint16_t reasm_claim;
    uint16_t tomb_claim;

    if (eng == NULL || in == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    /* PARTIAL */
    if (in_len < SNAP_LEN) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    /* EXTRA */
    if (in_len > SNAP_LEN) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    magic = ninlil_r7_frag_state_load_u32_be(in + 0);
    version = ninlil_r7_frag_state_load_u16_be(in + 4);
    reasm_claim = ninlil_r7_frag_state_load_u16_be(in + 6);
    tomb_claim = ninlil_r7_frag_state_load_u16_be(in + 8);

    /* OLD */
    if (magic != NINLIL_R7_FRAG_STATE_SNAP_MAGIC) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    /* NEW */
    if (version != NINLIL_R7_FRAG_STATE_SNAP_VERSION) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    /* THIRD: nonzero volatile claims (not representable in pure restart). */
    if (reasm_claim != 0u || tomb_claim != 0u) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }
    if (in[21] != 0u || in[22] != 0u || in[23] != 0u) {
        return NINLIL_R7_FRAG_STATE_STRUCTURAL;
    }

    ninlil_r7_frag_state_init(eng);
    eng->now_mono = ninlil_r7_frag_state_load_u64_be(in + 12);
    eng->fenced = (in[20] != 0u) ? 1u : 0u;
    /* Reassembly/tombstones/publications intentionally empty. */
    return NINLIL_R7_FRAG_STATE_OK;
}

/* -------------------------------------------------------------------------- */
/* COMMIT_UNKNOWN classifier                                                  */
/* -------------------------------------------------------------------------- */

static uint8_t cu_one(const ninlil_r7_frag_state_cu_entry *e)
{
    if (e->observed_status == 2u || e->observed_status == 3u) {
        return 0u; /* retry signal */
    }
    if (e->observed_status == 4u) {
        return NINLIL_R7_FRAG_STATE_CU_ENTRY_THIRD;
    }
    if (e->proposed_present) {
        if (e->observed_status == 0u
            && e->observed_len == e->proposed_len
            && (e->proposed_len == 0u
                || memcmp(
                       e->observed_bytes, e->proposed_bytes, e->proposed_len)
                    == 0)) {
            return NINLIL_R7_FRAG_STATE_CU_ENTRY_PROPOSED;
        }
        if (e->old_present) {
            if (e->observed_status == 0u
                && e->observed_len == e->old_len
                && (e->old_len == 0u
                    || memcmp(e->observed_bytes, e->old_bytes, e->old_len)
                        == 0)) {
                return NINLIL_R7_FRAG_STATE_CU_ENTRY_OLD;
            }
        } else if (e->observed_status == 1u) {
            return NINLIL_R7_FRAG_STATE_CU_ENTRY_OLD;
        }
        return NINLIL_R7_FRAG_STATE_CU_ENTRY_THIRD;
    }
    if (e->old_present && !e->proposed_present) {
        if (e->observed_status == 1u) {
            return NINLIL_R7_FRAG_STATE_CU_ENTRY_PROPOSED;
        }
        if (e->observed_status == 0u
            && e->observed_len == e->old_len
            && (e->old_len == 0u
                || memcmp(e->observed_bytes, e->old_bytes, e->old_len) == 0)) {
            return NINLIL_R7_FRAG_STATE_CU_ENTRY_OLD;
        }
        return NINLIL_R7_FRAG_STATE_CU_ENTRY_THIRD;
    }
    return NINLIL_R7_FRAG_STATE_CU_ENTRY_THIRD;
}

ninlil_r7_frag_state_status ninlil_r7_frag_state_cu_classify(
    const ninlil_r7_frag_state_cu_entry *entries,
    size_t entry_count,
    ninlil_r7_frag_state_cu_result *out)
{
    size_t i;
    int any_old = 0;
    int any_prop = 0;
    int any_third = 0;

    if (out == NULL) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (entries == NULL && entry_count != 0u) {
        return NINLIL_R7_FRAG_STATE_INVALID_ARGUMENT;
    }
    if (entry_count == 0u || entry_count > NINLIL_R7_FRAG_STATE_CU_MAX_ENTRIES) {
        out->class_code = NINLIL_R7_FRAG_STATE_CU_CORRUPT;
        return NINLIL_R7_FRAG_STATE_OK;
    }
    out->entry_count = (uint8_t)entry_count;
    for (i = 0u; i < entry_count; i++) {
        const ninlil_r7_frag_state_cu_entry *e = &entries[i];
        uint8_t cls;
        if (e->key_len == 0u || e->key_len > NINLIL_R7_FRAG_STATE_CU_KEY_MAX
            || e->old_len > NINLIL_R7_FRAG_STATE_CU_VALUE_MAX
            || e->proposed_len > NINLIL_R7_FRAG_STATE_CU_VALUE_MAX
            || e->observed_len > NINLIL_R7_FRAG_STATE_CU_VALUE_MAX) {
            out->class_code = NINLIL_R7_FRAG_STATE_CU_CORRUPT;
            return NINLIL_R7_FRAG_STATE_OK;
        }
        if (e->observed_status == 2u || e->observed_status == 3u) {
            out->class_code = NINLIL_R7_FRAG_STATE_CU_RETRY_LATER;
            return NINLIL_R7_FRAG_STATE_OK;
        }
        cls = cu_one(e);
        if (cls == 0u) {
            out->class_code = NINLIL_R7_FRAG_STATE_CU_RETRY_LATER;
            return NINLIL_R7_FRAG_STATE_OK;
        }
        out->entry_class[i] = cls;
        if (cls == NINLIL_R7_FRAG_STATE_CU_ENTRY_OLD) {
            any_old = 1;
        } else if (cls == NINLIL_R7_FRAG_STATE_CU_ENTRY_PROPOSED) {
            any_prop = 1;
        } else {
            any_third = 1;
        }
    }
    if (any_third || (any_old && any_prop)) {
        out->class_code = NINLIL_R7_FRAG_STATE_CU_THIRD;
    } else if (any_prop) {
        out->class_code = NINLIL_R7_FRAG_STATE_CU_ALL_PROPOSED;
    } else {
        out->class_code = NINLIL_R7_FRAG_STATE_CU_ALL_OLD;
    }
    return NINLIL_R7_FRAG_STATE_OK;
}
