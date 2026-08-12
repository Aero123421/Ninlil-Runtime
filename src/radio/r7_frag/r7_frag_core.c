/* SPDX-License-Identifier: Apache-2.0 */
/*
 * R7 private FRAG engine: lanes, reassembly, link groups, restart, CU.
 * Heap-free fixed capacity. No partial publication. Tombstones volatile.
 */

#include "r7_frag_internal.h"

/* -------------------------------------------------------------------------- */
/* Engine lifecycle                                                           */
/* -------------------------------------------------------------------------- */

void ninlil_r7_frag_engine_init(ninlil_r7_frag_engine *eng)
{
    if (eng == NULL) {
        return;
    }
    memset(eng, 0, sizeof(*eng));
}

void ninlil_r7_frag_engine_zeroize(ninlil_r7_frag_engine *eng)
{
    if (eng == NULL) {
        return;
    }
    ninlil_r7_frag_secure_zero(eng, sizeof(*eng));
}

void ninlil_r7_frag_engine_set_now(ninlil_r7_frag_engine *eng, uint64_t now_mono)
{
    if (eng == NULL) {
        return;
    }
    eng->now_mono = now_mono;
}

/* -------------------------------------------------------------------------- */
/* Lanes (TX exclusive + RX sliding-64)                                       */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_lane_install(
    ninlil_r7_frag_engine *eng,
    uint8_t lane_kind,
    uint32_t context_id,
    uint64_t key_generation,
    size_t *out_slot)
{
    size_t i;

    if (eng == NULL || out_slot == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (lane_kind < NINLIL_R7_FRAG_LANE_HOP_DATA
        || lane_kind > NINLIL_R7_FRAG_LANE_E2E) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (!ninlil_r7_frag_context_ok(context_id) || key_generation == 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_LANE_SLOTS; i++) {
        if (eng->lanes[i].in_use
            && eng->lanes[i].lane_kind == lane_kind
            && eng->lanes[i].context_id == context_id) {
            return NINLIL_R7_FRAG_CONFLICT; /* no silent replace */
        }
    }
    for (i = 0u; i < NINLIL_R7_FRAG_LANE_SLOTS; i++) {
        if (!eng->lanes[i].in_use) {
            ninlil_r7_frag_lane *L = &eng->lanes[i];
            memset(L, 0, sizeof(*L));
            L->in_use = 1u;
            L->lane_kind = lane_kind;
            L->context_id = context_id;
            L->key_generation = key_generation;
            L->tx_reserved_exclusive = 1u;
            L->tx_ram_next = 1u;
            L->tx_ram_limit = 1u;
            L->rx_accept_reserved_through = 0u;
            L->rx_boot_floor = 0u;
            L->rx_ram_highest = 0u;
            L->rx_bitmap = 0u;
            *out_slot = i;
            return NINLIL_R7_FRAG_OK;
        }
    }
    return NINLIL_R7_FRAG_RESOURCE;
}

ninlil_r7_frag_status ninlil_r7_frag_lane_find(
    const ninlil_r7_frag_engine *eng,
    uint8_t lane_kind,
    uint32_t context_id,
    size_t *out_slot)
{
    size_t i;

    if (eng == NULL || out_slot == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_LANE_SLOTS; i++) {
        if (eng->lanes[i].in_use
            && eng->lanes[i].lane_kind == lane_kind
            && eng->lanes[i].context_id == context_id) {
            *out_slot = i;
            return NINLIL_R7_FRAG_OK;
        }
    }
    return NINLIL_R7_FRAG_NO_TRANSFER;
}

ninlil_r7_frag_status ninlil_r7_frag_lane_tx_allocate(
    ninlil_r7_frag_engine *eng,
    size_t slot,
    uint64_t *out_counter)
{
    ninlil_r7_frag_lane *L;
    uint64_t C;

    if (eng == NULL || out_counter == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (slot >= NINLIL_R7_FRAG_LANE_SLOTS || !eng->lanes[slot].in_use) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    L = &eng->lanes[slot];
    if (L->tx_fenced || eng->global_fence) {
        return NINLIL_R7_FRAG_FENCED;
    }
    if (L->tx_ram_next >= UINT64_MAX) {
        return NINLIL_R7_FRAG_RESOURCE;
    }
    if (L->tx_ram_next == L->tx_ram_limit) {
        uint64_t U = 0u;
        /* docs/30 §9.2 checked final partial tranche (shared helper). */
        if (!ninlil_r7_frag_tx_exclusive_grow(
                L->tx_ram_limit, NINLIL_R7_FRAG_TX_BLOCK, &U)) {
            return NINLIL_R7_FRAG_RESOURCE;
        }
        /* FULL_OK simulated in private RAM */
        L->tx_ram_limit = U;
        L->tx_reserved_exclusive = U;
    }
    C = L->tx_ram_next;
    if (!ninlil_r7_frag_tx_counter_assignable(C)) {
        return NINLIL_R7_FRAG_RESOURCE;
    }
    L->tx_ram_next = C + 1u;
    *out_counter = C;
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_lane_rx_precheck(
    const ninlil_r7_frag_engine *eng,
    size_t slot,
    uint64_t counter)
{
    const ninlil_r7_frag_lane *L;
    uint64_t delta;

    if (eng == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (slot >= NINLIL_R7_FRAG_LANE_SLOTS || !eng->lanes[slot].in_use) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    L = &eng->lanes[slot];
    if (L->rx_fenced || eng->global_fence) {
        return NINLIL_R7_FRAG_FENCED;
    }
    if (counter == 0u || counter == UINT64_MAX) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (counter <= L->rx_boot_floor) {
        return NINLIL_R7_FRAG_REPLAY;
    }
    if (counter <= L->rx_ram_highest) {
        delta = L->rx_ram_highest - counter;
        if (delta >= 64u) {
            return NINLIL_R7_FRAG_REPLAY;
        }
        if ((L->rx_bitmap >> delta) & UINT64_C(1)) {
            return NINLIL_R7_FRAG_REPLAY;
        }
    }
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_lane_rx_admit(
    ninlil_r7_frag_engine *eng,
    size_t slot,
    uint64_t counter)
{
    ninlil_r7_frag_lane *L;
    uint64_t delta;
    ninlil_r7_frag_status st;

    if (eng == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (slot >= NINLIL_R7_FRAG_LANE_SLOTS || !eng->lanes[slot].in_use) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    st = ninlil_r7_frag_lane_rx_precheck(eng, slot, counter);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    L = &eng->lanes[slot];
    if (counter > L->rx_accept_reserved_through) {
        uint64_t new_through;
        if (counter > (UINT64_MAX - 1u) - (NINLIL_R7_FRAG_TX_BLOCK - 1u)) {
            new_through = UINT64_MAX - 1u;
        } else {
            new_through = counter + NINLIL_R7_FRAG_TX_BLOCK - 1u;
        }
        L->rx_accept_reserved_through = new_through;
    }
    if (counter > L->rx_ram_highest) {
        delta = counter - L->rx_ram_highest;
        if (delta >= 64u) {
            L->rx_bitmap = UINT64_C(1);
        } else {
            L->rx_bitmap = (L->rx_bitmap << delta) | UINT64_C(1);
        }
        L->rx_ram_highest = counter;
    } else {
        delta = L->rx_ram_highest - counter;
        L->rx_bitmap |= (UINT64_C(1) << delta);
    }
    return NINLIL_R7_FRAG_OK;
}

void ninlil_r7_frag_lane_fence(ninlil_r7_frag_engine *eng, size_t slot)
{
    if (eng == NULL || slot >= NINLIL_R7_FRAG_LANE_SLOTS) {
        return;
    }
    eng->lanes[slot].tx_fenced = 1u;
    eng->lanes[slot].rx_fenced = 1u;
}

/* -------------------------------------------------------------------------- */
/* Tombstone / dual index helpers                                             */
/* -------------------------------------------------------------------------- */

static int ninlil_r7_frag_tid_eq(const uint8_t a[16], const uint8_t b[16])
{
    size_t i;
    for (i = 0u; i < 16u; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static ninlil_r7_frag_tombstone *ninlil_r7_frag_tomb_find_handle(
    ninlil_r7_frag_engine *eng, uint32_t e2e_ctx, uint64_t handle)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_TOMBSTONE_SLOTS; i++) {
        if (eng->tombs[i].in_use
            && eng->tombs[i].e2e_context_id == e2e_ctx
            && eng->tombs[i].transfer_handle == handle) {
            return &eng->tombs[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_tombstone *ninlil_r7_frag_tomb_find_tid(
    ninlil_r7_frag_engine *eng, uint32_t e2e_ctx, const uint8_t tid[16])
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_TOMBSTONE_SLOTS; i++) {
        if (eng->tombs[i].in_use
            && eng->tombs[i].e2e_context_id == e2e_ctx
            && ninlil_r7_frag_tid_eq(eng->tombs[i].transfer_id, tid)) {
            return &eng->tombs[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_status ninlil_r7_frag_tomb_reserve(
    ninlil_r7_frag_engine *eng, size_t *out_slot)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_TOMBSTONE_SLOTS; i++) {
        if (!eng->tombs[i].in_use) {
            *out_slot = i;
            return NINLIL_R7_FRAG_OK;
        }
    }
    return NINLIL_R7_FRAG_RESOURCE;
}

static void ninlil_r7_frag_tomb_commit(
    ninlil_r7_frag_engine *eng,
    size_t slot,
    uint32_t e2e_ctx,
    const uint8_t tid[16],
    uint64_t handle,
    uint16_t frag_count,
    uint8_t status,
    uint8_t reason,
    const uint8_t fp[32],
    uint64_t expiry)
{
    ninlil_r7_frag_tombstone *T = &eng->tombs[slot];
    memset(T, 0, sizeof(*T));
    T->in_use = 1u;
    T->e2e_context_id = e2e_ctx;
    ninlil_r7_frag_copy(T->transfer_id, tid, 16u);
    T->transfer_handle = handle;
    T->frag_count = frag_count;
    T->status = status;
    T->reason = reason;
    ninlil_r7_frag_copy(T->fingerprint, fp, 32u);
    T->expiry_mono = expiry;
}

static ninlil_r7_frag_reasm_slot *ninlil_r7_frag_reasm_find_handle(
    ninlil_r7_frag_engine *eng, uint32_t e2e_ctx, uint64_t handle)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_REASM_SLOTS; i++) {
        if (eng->reasm[i].in_use
            && eng->reasm[i].e2e_context_id == e2e_ctx
            && eng->reasm[i].transfer_handle == handle) {
            return &eng->reasm[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_reasm_slot *ninlil_r7_frag_reasm_find_tid(
    ninlil_r7_frag_engine *eng, uint32_t e2e_ctx, const uint8_t tid[16])
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_REASM_SLOTS; i++) {
        if (eng->reasm[i].in_use
            && eng->reasm[i].e2e_context_id == e2e_ctx
            && ninlil_r7_frag_tid_eq(eng->reasm[i].transfer_id, tid)) {
            return &eng->reasm[i];
        }
    }
    return NULL;
}

static void ninlil_r7_frag_fill_partial_intent(
    ninlil_r7_frag_ack_body *ack,
    uint64_t handle,
    uint16_t frag_count,
    uint16_t bitmap)
{
    memset(ack, 0, sizeof(*ack));
    ack->transfer_handle = handle;
    ack->frag_count = frag_count;
    ack->received_bitmap = bitmap;
    ack->status = NINLIL_R7_FRAG_STATUS_PARTIAL;
    ack->reason = NINLIL_R7_FRAG_REASON_NONE;
}

static void ninlil_r7_frag_fill_terminal_intent(
    ninlil_r7_frag_ack_body *ack,
    uint64_t handle,
    uint16_t frag_count,
    uint16_t bitmap,
    uint8_t status,
    uint8_t reason)
{
    memset(ack, 0, sizeof(*ack));
    ack->transfer_handle = handle;
    ack->frag_count = frag_count;
    ack->received_bitmap = bitmap;
    ack->status = status;
    ack->reason = reason;
}

static ninlil_r7_frag_status ninlil_r7_frag_try_complete(
    ninlil_r7_frag_engine *eng,
    const ninlil_r7_crypto_provider *provider,
    ninlil_r7_frag_reasm_slot *S,
    ninlil_r7_frag_ack_body *out_ack)
{
    uint8_t digest[32];
    uint64_t expiry;
    size_t tomb_slot;
    ninlil_r7_frag_status st;

    if (S->bitmap != ninlil_r7_frag_full_bitmap(S->frag_count)) {
        return NINLIL_R7_FRAG_OK; /* not complete */
    }
    st = ninlil_r7_frag_content_digest(
        provider, S->payload, S->total_len, digest);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    if (memcmp(digest, S->content_digest, 32u) != 0) {
        /* ABORT DIGEST — no upper handoff */
        if (!ninlil_r7_frag_checked_add_u64(
                eng->now_mono, NINLIL_R7_FRAG_TOMBSTONE_TTL_MS, &expiry)) {
            eng->global_fence = 1u;
            return NINLIL_R7_FRAG_FENCED;
        }
        st = ninlil_r7_frag_tomb_reserve(eng, &tomb_slot);
        if (st != NINLIL_R7_FRAG_OK) {
            return NINLIL_R7_FRAG_RESOURCE;
        }
        ninlil_r7_frag_tomb_commit(
            eng, tomb_slot, S->e2e_context_id, S->transfer_id,
            S->transfer_handle, S->frag_count, NINLIL_R7_FRAG_STATUS_ABORT,
            NINLIL_R7_FRAG_REASON_DIGEST, S->fingerprint, expiry);
        if (eng->payload_bytes_in_use >= S->total_len) {
            eng->payload_bytes_in_use -= S->total_len;
        } else {
            eng->payload_bytes_in_use = 0u;
        }
        ninlil_r7_frag_fill_terminal_intent(
            out_ack, S->transfer_handle, S->frag_count, 0u,
            NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_DIGEST);
        ninlil_r7_frag_secure_zero(S, sizeof(*S));
        return NINLIL_R7_FRAG_OK;
    }

    /* COMPLETE order: reserve upper publish without expose, then tombstone. */
    if (eng->pub_valid) {
        /* upper queue full (single-slot private candidate) */
        if (!ninlil_r7_frag_checked_add_u64(
                eng->now_mono, NINLIL_R7_FRAG_TOMBSTONE_TTL_MS, &expiry)) {
            eng->global_fence = 1u;
            return NINLIL_R7_FRAG_FENCED;
        }
        st = ninlil_r7_frag_tomb_reserve(eng, &tomb_slot);
        if (st != NINLIL_R7_FRAG_OK) {
            return NINLIL_R7_FRAG_RESOURCE;
        }
        ninlil_r7_frag_tomb_commit(
            eng, tomb_slot, S->e2e_context_id, S->transfer_id,
            S->transfer_handle, S->frag_count, NINLIL_R7_FRAG_STATUS_ABORT,
            NINLIL_R7_FRAG_REASON_RESOURCE, S->fingerprint, expiry);
        if (eng->payload_bytes_in_use >= S->total_len) {
            eng->payload_bytes_in_use -= S->total_len;
        } else {
            eng->payload_bytes_in_use = 0u;
        }
        ninlil_r7_frag_fill_terminal_intent(
            out_ack, S->transfer_handle, S->frag_count, 0u,
            NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_RESOURCE);
        ninlil_r7_frag_secure_zero(S, sizeof(*S));
        return NINLIL_R7_FRAG_OK;
    }

    if (!ninlil_r7_frag_checked_add_u64(
            eng->now_mono, NINLIL_R7_FRAG_TOMBSTONE_TTL_MS, &expiry)) {
        eng->global_fence = 1u;
        return NINLIL_R7_FRAG_FENCED;
    }
    st = ninlil_r7_frag_tomb_reserve(eng, &tomb_slot);
    if (st != NINLIL_R7_FRAG_OK) {
        return NINLIL_R7_FRAG_RESOURCE;
    }

    /* Atomic: stage publication then tombstone, then mark published once. */
    eng->pub_e2e_context_id = S->e2e_context_id;
    eng->pub_transfer_handle = S->transfer_handle;
    eng->pub_total_len = S->total_len;
    ninlil_r7_frag_copy(eng->pub_payload, S->payload, S->total_len);
    eng->pub_valid = 1u;
    eng->publish_count += 1u;

    ninlil_r7_frag_tomb_commit(
        eng, tomb_slot, S->e2e_context_id, S->transfer_id, S->transfer_handle,
        S->frag_count, NINLIL_R7_FRAG_STATUS_COMPLETE,
        NINLIL_R7_FRAG_REASON_NONE, S->fingerprint, expiry);

    ninlil_r7_frag_fill_terminal_intent(
        out_ack, S->transfer_handle, S->frag_count,
        ninlil_r7_frag_full_bitmap(S->frag_count),
        NINLIL_R7_FRAG_STATUS_COMPLETE, NINLIL_R7_FRAG_REASON_NONE);

    if (eng->payload_bytes_in_use >= S->total_len) {
        eng->payload_bytes_in_use -= S->total_len;
    } else {
        eng->payload_bytes_in_use = 0u;
    }
    ninlil_r7_frag_secure_zero(S, sizeof(*S));
    ninlil_r7_frag_secure_zero(digest, sizeof(digest));
    return NINLIL_R7_FRAG_OK;
}

/* -------------------------------------------------------------------------- */
/* Reassembly admit START / CONT                                              */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_reasm_admit_start(
    ninlil_r7_frag_engine *eng,
    const ninlil_r7_crypto_provider *provider,
    uint32_t e2e_context_id,
    const ninlil_r7_frag_start_body *body,
    const uint8_t *first_chunk,
    size_t first_chunk_len,
    ninlil_r7_frag_ack_body *out_ack_intent)
{
    uint8_t fp[32];
    ninlil_r7_frag_reasm_slot *active_h;
    ninlil_r7_frag_reasm_slot *active_t;
    ninlil_r7_frag_tombstone *tomb_h;
    ninlil_r7_frag_tombstone *tomb_t;
    ninlil_r7_frag_status st;
    size_t i;
    size_t free_slot = NINLIL_R7_FRAG_REASM_SLOTS;
    size_t tomb_slot;
    uint64_t abs_deadline;
    uint64_t idle_deadline;
    uint64_t partial_due;

    if (eng == NULL || provider == NULL || body == NULL || first_chunk == NULL
        || out_ack_intent == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_context_ok(e2e_context_id)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_plan_validate(
        body->total_len, (uint16_t)first_chunk_len, body->frag_count,
        body->continuation_unit);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    if (!ninlil_r7_frag_handle_ok(body->transfer_handle)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_start_fingerprint(
        provider, body, first_chunk, first_chunk_len, fp);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }

    active_h = ninlil_r7_frag_reasm_find_handle(
        eng, e2e_context_id, body->transfer_handle);
    active_t = ninlil_r7_frag_reasm_find_tid(
        eng, e2e_context_id, body->transfer_id);
    tomb_h = ninlil_r7_frag_tomb_find_handle(
        eng, e2e_context_id, body->transfer_handle);
    tomb_t = ninlil_r7_frag_tomb_find_tid(
        eng, e2e_context_id, body->transfer_id);

    /* Dual-index collision handling. */
    if (active_h != NULL || active_t != NULL) {
        ninlil_r7_frag_reasm_slot *S = (active_h != NULL) ? active_h : active_t;
        /* Cross-index mismatch under dual index = CONFLICT */
        if (active_h != NULL && active_t != NULL && active_h != active_t) {
            ninlil_r7_frag_fill_terminal_intent(
                out_ack_intent, body->transfer_handle, body->frag_count, 0u,
                NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_CONFLICT);
            ninlil_r7_frag_secure_zero(fp, sizeof(fp));
            return NINLIL_R7_FRAG_CONFLICT;
        }
        if (active_h != NULL && active_t != NULL
            && !ninlil_r7_frag_tid_eq(active_h->transfer_id, body->transfer_id)) {
            ninlil_r7_frag_fill_terminal_intent(
                out_ack_intent, body->transfer_handle, body->frag_count, 0u,
                NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_CONFLICT);
            ninlil_r7_frag_secure_zero(fp, sizeof(fp));
            return NINLIL_R7_FRAG_CONFLICT;
        }
        if (memcmp(S->fingerprint, fp, 32u) == 0) {
            /* Exact same-fingerprint retry: no mutation; PARTIAL intent. */
            ninlil_r7_frag_fill_partial_intent(
                out_ack_intent, S->transfer_handle, S->frag_count, S->bitmap);
            ninlil_r7_frag_secure_zero(fp, sizeof(fp));
            return NINLIL_R7_FRAG_EXACT_RETRY;
        }
        ninlil_r7_frag_fill_terminal_intent(
            out_ack_intent, body->transfer_handle, body->frag_count, 0u,
            NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_CONFLICT);
        ninlil_r7_frag_secure_zero(fp, sizeof(fp));
        return NINLIL_R7_FRAG_CONFLICT;
    }

    if (tomb_h != NULL || tomb_t != NULL) {
        ninlil_r7_frag_tombstone *T = (tomb_h != NULL) ? tomb_h : tomb_t;
        if (tomb_h != NULL && tomb_t != NULL && tomb_h != tomb_t) {
            ninlil_r7_frag_fill_terminal_intent(
                out_ack_intent, body->transfer_handle, body->frag_count, 0u,
                NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_CONFLICT);
            ninlil_r7_frag_secure_zero(fp, sizeof(fp));
            return NINLIL_R7_FRAG_CONFLICT;
        }
        if (memcmp(T->fingerprint, fp, 32u) == 0) {
            /* Terminal exact retry: re-emit stored status; no TTL extend. */
            ninlil_r7_frag_fill_terminal_intent(
                out_ack_intent, T->transfer_handle, T->frag_count,
                (T->status == NINLIL_R7_FRAG_STATUS_COMPLETE)
                    ? ninlil_r7_frag_full_bitmap(T->frag_count)
                    : 0u,
                T->status, T->reason);
            ninlil_r7_frag_secure_zero(fp, sizeof(fp));
            return NINLIL_R7_FRAG_EXACT_RETRY;
        }
        ninlil_r7_frag_fill_terminal_intent(
            out_ack_intent, body->transfer_handle, body->frag_count, 0u,
            NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_CONFLICT);
        ninlil_r7_frag_secure_zero(fp, sizeof(fp));
        return NINLIL_R7_FRAG_CONFLICT;
    }

    /* START reserve tombstone capacity first (START_RESERVE_FAIL_ACK0_ONLY). */
    st = ninlil_r7_frag_tomb_reserve(eng, &tomb_slot);
    if (st != NINLIL_R7_FRAG_OK) {
        memset(out_ack_intent, 0, sizeof(*out_ack_intent));
        ninlil_r7_frag_secure_zero(fp, sizeof(fp));
        return NINLIL_R7_FRAG_RESOURCE; /* ACK 0 */
    }
    /* Keep reservation by marking slot in_use as START reservation (status=0xff). */
    eng->tombs[tomb_slot].in_use = 1u;
    eng->tombs[tomb_slot].e2e_context_id = e2e_context_id;
    ninlil_r7_frag_copy(
        eng->tombs[tomb_slot].transfer_id, body->transfer_id, 16u);
    eng->tombs[tomb_slot].transfer_handle = body->transfer_handle;
    eng->tombs[tomb_slot].status = 0xffu; /* reservation marker */
    eng->tombs[tomb_slot].reason = 0u;
    ninlil_r7_frag_copy(eng->tombs[tomb_slot].fingerprint, fp, 32u);

    if (eng->payload_bytes_in_use + body->total_len
        > NINLIL_R7_FRAG_REASM_PAYLOAD_BUDGET) {
        eng->tombs[tomb_slot].in_use = 0u;
        memset(out_ack_intent, 0, sizeof(*out_ack_intent));
        ninlil_r7_frag_secure_zero(fp, sizeof(fp));
        return NINLIL_R7_FRAG_RESOURCE;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_REASM_SLOTS; i++) {
        if (!eng->reasm[i].in_use) {
            free_slot = i;
            break;
        }
    }
    if (free_slot >= NINLIL_R7_FRAG_REASM_SLOTS) {
        eng->tombs[tomb_slot].in_use = 0u;
        memset(out_ack_intent, 0, sizeof(*out_ack_intent));
        ninlil_r7_frag_secure_zero(fp, sizeof(fp));
        return NINLIL_R7_FRAG_RESOURCE;
    }

    if (!ninlil_r7_frag_checked_add_u64(
            eng->now_mono, NINLIL_R7_FRAG_RECEIVER_TTL_MS, &abs_deadline)
        || !ninlil_r7_frag_checked_add_u64(
            eng->now_mono, NINLIL_R7_FRAG_IDLE_TIMEOUT_MS, &idle_deadline)
        || !ninlil_r7_frag_checked_add_u64(
            eng->now_mono, NINLIL_R7_FRAG_PARTIAL_ACK_IDLE_MS, &partial_due)) {
        eng->tombs[tomb_slot].in_use = 0u;
        eng->global_fence = 1u;
        ninlil_r7_frag_secure_zero(fp, sizeof(fp));
        return NINLIL_R7_FRAG_FENCED;
    }

    {
        ninlil_r7_frag_reasm_slot *S = &eng->reasm[free_slot];
        memset(S, 0, sizeof(*S));
        S->in_use = 1u;
        S->e2e_context_id = e2e_context_id;
        ninlil_r7_frag_copy(S->transfer_id, body->transfer_id, 16u);
        S->transfer_handle = body->transfer_handle;
        S->total_len = body->total_len;
        S->frag_count = body->frag_count;
        S->first_chunk_len = (uint16_t)first_chunk_len;
        ninlil_r7_frag_copy(S->content_digest, body->content_digest, 32u);
        ninlil_r7_frag_copy(S->fingerprint, fp, 32u);
        S->bitmap = 0x0001u; /* START */
        S->chunk_seen[0] = 1u;
        S->chunk_len[0] = (uint16_t)first_chunk_len;
        ninlil_r7_frag_copy(S->payload, first_chunk, first_chunk_len);
        S->receiver_start_mono = eng->now_mono;
        S->receiver_absolute_deadline = abs_deadline;
        S->idle_deadline = idle_deadline;
        S->partial_ack_due = partial_due;
        eng->payload_bytes_in_use += body->total_len;

        /* START reservation remains until terminal; keep tomb marker. */
        eng->tombs[tomb_slot].frag_count = body->frag_count;

        ninlil_r7_frag_fill_partial_intent(
            out_ack_intent, S->transfer_handle, S->frag_count, S->bitmap);
    }
    ninlil_r7_frag_secure_zero(fp, sizeof(fp));
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_reasm_admit_cont(
    ninlil_r7_frag_engine *eng,
    const ninlil_r7_crypto_provider *provider,
    uint32_t e2e_context_id,
    const ninlil_r7_frag_cont_body *body,
    const uint8_t *chunk,
    size_t chunk_len,
    ninlil_r7_frag_ack_body *out_ack_intent)
{
    ninlil_r7_frag_reasm_slot *S;
    ninlil_r7_frag_tombstone *T;
    uint32_t offset;
    uint32_t expect_len;
    uint64_t new_idle;
    uint64_t new_due = 0u;
    ninlil_r7_frag_status st;

    if (eng == NULL || provider == NULL || body == NULL || chunk == NULL
        || out_ack_intent == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!ninlil_r7_frag_context_ok(e2e_context_id)
        || !ninlil_r7_frag_handle_ok(body->transfer_handle)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (chunk_len < NINLIL_R7_FRAG_C_MIN || chunk_len > NINLIL_R7_FRAG_C_MAX) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }

    S = ninlil_r7_frag_reasm_find_handle(
        eng, e2e_context_id, body->transfer_handle);
    T = ninlil_r7_frag_tomb_find_handle(
        eng, e2e_context_id, body->transfer_handle);

    if (S == NULL) {
        if (T != NULL && T->status != 0xffu) {
            /* Live tombstone CONT: re-emit stored terminal; no reassembly. */
            ninlil_r7_frag_fill_terminal_intent(
                out_ack_intent, T->transfer_handle, T->frag_count,
                (T->status == NINLIL_R7_FRAG_STATUS_COMPLETE)
                    ? ninlil_r7_frag_full_bitmap(T->frag_count)
                    : 0u,
                T->status, T->reason);
            return NINLIL_R7_FRAG_EXACT_RETRY;
        }
        memset(out_ack_intent, 0, sizeof(*out_ack_intent));
        return NINLIL_R7_FRAG_NO_TRANSFER;
    }

    if (body->frag_index == 0u || body->frag_index >= S->frag_count) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }

    offset = (uint32_t)S->first_chunk_len
        + (uint32_t)(body->frag_index - 1u) * (uint32_t)NINLIL_R7_FRAG_CONT_UNIT;
    if (offset >= S->total_len) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    expect_len = S->total_len - offset;
    if (expect_len > (uint32_t)NINLIL_R7_FRAG_CONT_UNIT) {
        expect_len = NINLIL_R7_FRAG_CONT_UNIT;
    }
    if (chunk_len != (size_t)expect_len) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    /* non-last must be 180 */
    if (body->frag_index + 1u < S->frag_count
        && chunk_len != NINLIL_R7_FRAG_CONT_UNIT) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }

    if (S->chunk_seen[body->frag_index]) {
        /* Duplicate CONT */
        if (S->chunk_len[body->frag_index] == (uint16_t)chunk_len
            && memcmp(S->payload + offset, chunk, chunk_len) == 0) {
            ninlil_r7_frag_fill_partial_intent(
                out_ack_intent, S->transfer_handle, S->frag_count, S->bitmap);
            return NINLIL_R7_FRAG_DUPLICATE;
        }
        /* CONT conflict → ABORT CONFLICT tombstone */
        {
            uint64_t expiry;
            size_t tomb_slot;
            if (!ninlil_r7_frag_checked_add_u64(
                    eng->now_mono, NINLIL_R7_FRAG_TOMBSTONE_TTL_MS, &expiry)) {
                eng->global_fence = 1u;
                return NINLIL_R7_FRAG_FENCED;
            }
            /* Reuse START reservation tomb if present. */
            T = ninlil_r7_frag_tomb_find_handle(
                eng, e2e_context_id, body->transfer_handle);
            if (T != NULL) {
                tomb_slot = (size_t)(T - eng->tombs);
            } else {
                st = ninlil_r7_frag_tomb_reserve(eng, &tomb_slot);
                if (st != NINLIL_R7_FRAG_OK) {
                    return NINLIL_R7_FRAG_RESOURCE;
                }
            }
            ninlil_r7_frag_tomb_commit(
                eng, tomb_slot, S->e2e_context_id, S->transfer_id,
                S->transfer_handle, S->frag_count,
                NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_CONFLICT,
                S->fingerprint, expiry);
            ninlil_r7_frag_fill_terminal_intent(
                out_ack_intent, S->transfer_handle, S->frag_count, 0u,
                NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_CONFLICT);
            if (eng->payload_bytes_in_use >= S->total_len) {
                eng->payload_bytes_in_use -= S->total_len;
            } else {
                eng->payload_bytes_in_use = 0u;
            }
            ninlil_r7_frag_secure_zero(S, sizeof(*S));
            return NINLIL_R7_FRAG_CONFLICT;
        }
    }

    /* Precompute deadlines before mutation; overflow ⇒ state unchanged. */
    {
        uint16_t next_bitmap = (uint16_t)(S->bitmap
            | (uint16_t)(1u << body->frag_index));
        int full = (next_bitmap == ninlil_r7_frag_full_bitmap(S->frag_count));
        if (!ninlil_r7_frag_checked_add_u64(
                eng->now_mono, NINLIL_R7_FRAG_IDLE_TIMEOUT_MS, &new_idle)) {
            eng->global_fence = 1u;
            ninlil_r7_frag_fill_terminal_intent(
                out_ack_intent, S->transfer_handle, S->frag_count, 0u,
                NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_FENCED);
            return NINLIL_R7_FRAG_FENCED;
        }
        if (new_idle > S->receiver_absolute_deadline) {
            new_idle = S->receiver_absolute_deadline;
        }
        if (!full) {
            if (!ninlil_r7_frag_checked_add_u64(
                    eng->now_mono, NINLIL_R7_FRAG_PARTIAL_ACK_IDLE_MS,
                    &new_due)) {
                eng->global_fence = 1u;
                ninlil_r7_frag_fill_terminal_intent(
                    out_ack_intent, S->transfer_handle, S->frag_count, 0u,
                    NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_FENCED);
                return NINLIL_R7_FRAG_FENCED;
            }
            if (new_due > S->receiver_absolute_deadline) {
                new_due = S->receiver_absolute_deadline;
            }
        }
        ninlil_r7_frag_copy(S->payload + offset, chunk, chunk_len);
        S->chunk_seen[body->frag_index] = 1u;
        S->chunk_len[body->frag_index] = (uint16_t)chunk_len;
        S->bitmap = next_bitmap;
        S->idle_deadline = new_idle;
        if (full) {
            return ninlil_r7_frag_try_complete(
                eng, provider, S, out_ack_intent);
        }
        if (S->partial_ack_due == 0u || new_due < S->partial_ack_due) {
            S->partial_ack_due = new_due;
        }
        ninlil_r7_frag_fill_partial_intent(
            out_ack_intent, S->transfer_handle, S->frag_count, S->bitmap);
        return NINLIL_R7_FRAG_OK;
    }
}

ninlil_r7_frag_status ninlil_r7_frag_reasm_tick(
    ninlil_r7_frag_engine *eng,
    uint64_t now_mono)
{
    size_t i;

    if (eng == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    eng->now_mono = now_mono;

    /* Expire tombstones */
    for (i = 0u; i < NINLIL_R7_FRAG_TOMBSTONE_SLOTS; i++) {
        if (eng->tombs[i].in_use && eng->tombs[i].status != 0xffu
            && eng->tombs[i].expiry_mono != 0u
            && now_mono >= eng->tombs[i].expiry_mono) {
            ninlil_r7_frag_secure_zero(&eng->tombs[i], sizeof(eng->tombs[i]));
        }
    }

    /* Idle / absolute timeout on reassembly → ABORT TIMEOUT */
    for (i = 0u; i < NINLIL_R7_FRAG_REASM_SLOTS; i++) {
        ninlil_r7_frag_reasm_slot *S = &eng->reasm[i];
        if (!S->in_use) {
            continue;
        }
        if (now_mono >= S->idle_deadline
            || now_mono >= S->receiver_absolute_deadline) {
            uint64_t expiry;
            size_t tomb_slot;
            ninlil_r7_frag_tombstone *T;
            if (!ninlil_r7_frag_checked_add_u64(
                    now_mono, NINLIL_R7_FRAG_TOMBSTONE_TTL_MS, &expiry)) {
                eng->global_fence = 1u;
                return NINLIL_R7_FRAG_FENCED;
            }
            T = ninlil_r7_frag_tomb_find_handle(
                eng, S->e2e_context_id, S->transfer_handle);
            if (T != NULL) {
                tomb_slot = (size_t)(T - eng->tombs);
            } else if (ninlil_r7_frag_tomb_reserve(eng, &tomb_slot)
                != NINLIL_R7_FRAG_OK) {
                return NINLIL_R7_FRAG_RESOURCE;
            }
            ninlil_r7_frag_tomb_commit(
                eng, tomb_slot, S->e2e_context_id, S->transfer_id,
                S->transfer_handle, S->frag_count,
                NINLIL_R7_FRAG_STATUS_ABORT, NINLIL_R7_FRAG_REASON_TIMEOUT,
                S->fingerprint, expiry);
            if (eng->payload_bytes_in_use >= S->total_len) {
                eng->payload_bytes_in_use -= S->total_len;
            } else {
                eng->payload_bytes_in_use = 0u;
            }
            ninlil_r7_frag_secure_zero(S, sizeof(*S));
        }
    }
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_take_publication(
    ninlil_r7_frag_engine *eng,
    uint32_t *out_e2e_context_id,
    uint64_t *out_transfer_handle,
    uint8_t *out_payload,
    size_t out_capacity,
    size_t *out_len)
{
    if (eng == NULL || out_e2e_context_id == NULL || out_transfer_handle == NULL
        || out_payload == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (!eng->pub_valid) {
        return NINLIL_R7_FRAG_NO_TRANSFER;
    }
    if (out_capacity < eng->pub_total_len) {
        return NINLIL_R7_FRAG_CAPACITY;
    }
    *out_e2e_context_id = eng->pub_e2e_context_id;
    *out_transfer_handle = eng->pub_transfer_handle;
    ninlil_r7_frag_copy(out_payload, eng->pub_payload, eng->pub_total_len);
    *out_len = eng->pub_total_len;
    /* Consume publication exactly once. */
    ninlil_r7_frag_secure_zero(eng->pub_payload, sizeof(eng->pub_payload));
    eng->pub_valid = 0u;
    eng->pub_total_len = 0u;
    eng->pub_e2e_context_id = 0u;
    eng->pub_transfer_handle = 0u;
    return NINLIL_R7_FRAG_PUBLISHED;
}

ninlil_r7_frag_status ninlil_r7_frag_ack_rx_validate(
    uint16_t expected_frag_count,
    uint64_t expected_handle,
    const ninlil_r7_frag_ack_body *body)
{
    uint8_t tmp[NINLIL_R7_FRAG_ACK_PT_LEN];
    ninlil_r7_frag_status st;

    if (body == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (body->transfer_handle != expected_handle) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (body->frag_count != expected_frag_count) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    st = ninlil_r7_frag_pack_ack_pt(body, tmp);
    ninlil_r7_frag_secure_zero(tmp, sizeof(tmp));
    return st;
}

/* -------------------------------------------------------------------------- */
/* LINK groups                                                                */
/* -------------------------------------------------------------------------- */

ninlil_r7_frag_status ninlil_r7_frag_link_group_admit(
    ninlil_r7_frag_engine *eng,
    uint32_t hop_data_context_id,
    uint8_t ack_requested,
    uint64_t e2e_counter_fixed,
    const uint8_t *e2e_blob,
    size_t e2e_blob_len,
    uint64_t enclosing_owner_deadline,
    size_t *out_group)
{
    size_t i;
    uint64_t deadline;

    if (eng == NULL || e2e_blob == NULL || out_group == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (ack_requested != 0u && ack_requested != 1u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (!ninlil_r7_frag_context_ok(hop_data_context_id)
        || !ninlil_r7_frag_counter_ok(e2e_counter_fixed)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (e2e_blob_len < 31u || e2e_blob_len > 220u) {
        return NINLIL_R7_FRAG_LENGTH_CLASS;
    }
    if (!ninlil_r7_frag_checked_add_u64(
            eng->now_mono, NINLIL_R7_FRAG_LINK_GROUP_TTL_MS, &deadline)) {
        return NINLIL_R7_FRAG_RESOURCE; /* pre-group fail */
    }
    if (deadline > enclosing_owner_deadline && enclosing_owner_deadline != 0u) {
        deadline = enclosing_owner_deadline;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_LINK_GROUP_SLOTS; i++) {
        if (!eng->links[i].in_use) {
            ninlil_r7_frag_link_group *G = &eng->links[i];
            memset(G, 0, sizeof(*G));
            G->in_use = 1u;
            G->ack_requested = ack_requested;
            G->hop_data_context_id = hop_data_context_id;
            G->e2e_counter_fixed = e2e_counter_fixed;
            G->e2e_blob_len = (uint16_t)e2e_blob_len;
            ninlil_r7_frag_copy(G->e2e_blob, e2e_blob, e2e_blob_len);
            G->group_start_mono = eng->now_mono;
            G->group_absolute_deadline = deadline;
            G->enclosing_owner_deadline = enclosing_owner_deadline;
            *out_group = i;
            return NINLIL_R7_FRAG_OK;
        }
    }
    return NINLIL_R7_FRAG_RESOURCE;
}

ninlil_r7_frag_status ninlil_r7_frag_link_group_note_air(
    ninlil_r7_frag_engine *eng,
    size_t group,
    uint64_t hop_counter,
    uint64_t tx_mono)
{
    ninlil_r7_frag_link_group *G;
    uint64_t ack_deadline;
    uint64_t interval_at;

    if (eng == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (group >= NINLIL_R7_FRAG_LINK_GROUP_SLOTS || !eng->links[group].in_use) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    G = &eng->links[group];
    if (G->completed) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (G->hop_attempts >= NINLIL_R7_FRAG_MAX_HOP_ATTEMPTS) {
        return NINLIL_R7_FRAG_RESOURCE;
    }
    if (!ninlil_r7_frag_counter_ok(hop_counter)) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    G->pending_hop_counters[G->pending_count] = hop_counter;
    G->pending_count = (uint8_t)(G->pending_count + 1u);
    G->hop_attempts = (uint8_t)(G->hop_attempts + 1u);
    G->last_tx_mono = tx_mono;

    if (G->ack_requested) {
        if (!ninlil_r7_frag_checked_add_u64(
                tx_mono, NINLIL_R7_FRAG_LINK_ACK_WAIT_MS, &ack_deadline)
            || !ninlil_r7_frag_checked_add_u64(
                tx_mono, NINLIL_R7_FRAG_LINK_RETRY_INTERVAL_MS, &interval_at)) {
            return NINLIL_R7_FRAG_TIMEOUT;
        }
        G->eligible_at =
            (ack_deadline > interval_at) ? ack_deadline : interval_at;
    } else {
        G->eligible_at = 0u;
        G->completed = 1u; /* UNACKED path completed at edge — caller also may call unacked_success */
    }
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_link_group_retry_ready(
    const ninlil_r7_frag_engine *eng,
    size_t group,
    uint64_t now_mono)
{
    const ninlil_r7_frag_link_group *G;

    if (eng == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (group >= NINLIL_R7_FRAG_LINK_GROUP_SLOTS || !eng->links[group].in_use) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    G = &eng->links[group];
    if (G->completed) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (!G->ack_requested) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (G->hop_attempts >= NINLIL_R7_FRAG_MAX_HOP_ATTEMPTS) {
        return NINLIL_R7_FRAG_RESOURCE;
    }
    if (now_mono >= G->group_absolute_deadline) {
        return NINLIL_R7_FRAG_TIMEOUT;
    }
    if (G->enclosing_owner_deadline != 0u
        && now_mono >= G->enclosing_owner_deadline) {
        return NINLIL_R7_FRAG_TIMEOUT;
    }
    if (now_mono < G->eligible_at) {
        return NINLIL_R7_FRAG_TIMEOUT; /* not yet eligible */
    }
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_link_group_apply_ack(
    ninlil_r7_frag_engine *eng,
    size_t group,
    const ninlil_r7_frag_link_ack_body *body)
{
    ninlil_r7_frag_link_group *G;
    uint8_t i;
    uint8_t b;
    ninlil_r7_frag_status st;

    if (eng == NULL || body == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (group >= NINLIL_R7_FRAG_LINK_GROUP_SLOTS || !eng->links[group].in_use) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    st = ninlil_r7_frag_link_ack_body_validate(body);
    if (st != NINLIL_R7_FRAG_OK) {
        return st;
    }
    G = &eng->links[group];
    if (body->acked_hop_context_id != G->hop_data_context_id) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    /* Any pending counter covered by bitmap completes group. */
    for (i = 0u; i < G->pending_count; i++) {
        uint64_t c = G->pending_hop_counters[i];
        if (c > body->ack_base_counter) {
            continue;
        }
        {
            uint64_t delta = body->ack_base_counter - c;
            if (delta >= 16u) {
                continue;
            }
            b = (uint8_t)((body->ack_bitmap >> delta) & 1u);
            if (b) {
                G->completed = 1u;
                return NINLIL_R7_FRAG_OK;
            }
        }
    }
    /* Stale/non-covering: safe no-op */
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_link_group_unacked_success(
    ninlil_r7_frag_engine *eng,
    size_t group)
{
    if (eng == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (group >= NINLIL_R7_FRAG_LINK_GROUP_SLOTS || !eng->links[group].in_use) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (eng->links[group].ack_requested != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    eng->links[group].completed = 1u;
    return NINLIL_R7_FRAG_OK;
}

/* -------------------------------------------------------------------------- */
/* Restart snapshot                                                           */
/* -------------------------------------------------------------------------- */

/*
 * Snapshot layout (BE):
 *   header 24B
 *   for each lane in_use: 1+1+4+8+8+8+8 + 8+8+8+8 = 66B packed
 *   for each link in_use: compact fields + e2e_blob
 *
 * Deliberately omits reassembly, tombstones, publications (volatile restart).
 */

#define SNAP_HDR_LEN ((size_t)24u)
/* kind1+flags1+ctx4+kgen8+tx_res8+tx_next8+tx_limit8+rx_acc8+rx_boot8+rx_high8+rx_bmp8 */
#define SNAP_LANE_LEN ((size_t)70u)

ninlil_r7_frag_status ninlil_r7_frag_restart_encode(
    const ninlil_r7_frag_engine *eng,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    uint16_t lane_count = 0u;
    uint16_t link_count = 0u;
    size_t need;
    size_t off;
    size_t i;

    if (eng == NULL || out == NULL || out_len == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_LANE_SLOTS; i++) {
        if (eng->lanes[i].in_use) {
            lane_count = (uint16_t)(lane_count + 1u);
        }
    }
    for (i = 0u; i < NINLIL_R7_FRAG_LINK_GROUP_SLOTS; i++) {
        if (eng->links[i].in_use) {
            link_count = (uint16_t)(link_count + 1u);
            need = 0; /* silence - recalculate below */
            (void)need;
        }
    }
    need = SNAP_HDR_LEN + (size_t)lane_count * SNAP_LANE_LEN;
    for (i = 0u; i < NINLIL_R7_FRAG_LINK_GROUP_SLOTS; i++) {
        if (eng->links[i].in_use) {
            need += 1u + 1u + 4u + 8u + 2u + 8u + 8u + 8u + 1u + 1u
                + (size_t)eng->links[i].e2e_blob_len;
        }
    }
    if (out_capacity < need) {
        return NINLIL_R7_FRAG_CAPACITY;
    }

    off = 0u;
    ninlil_r7_frag_store_u32_be(out + off, NINLIL_R7_FRAG_SNAP_MAGIC);
    off += 4u;
    ninlil_r7_frag_store_u16_be(out + off, NINLIL_R7_FRAG_SNAP_VERSION);
    off += 2u;
    ninlil_r7_frag_store_u16_be(out + off, lane_count);
    off += 2u;
    ninlil_r7_frag_store_u16_be(out + off, 0u); /* reasm_count always 0 */
    off += 2u;
    ninlil_r7_frag_store_u16_be(out + off, link_count);
    off += 2u;
    ninlil_r7_frag_store_u64_be(out + off, eng->now_mono);
    off += 8u;
    out[off++] = eng->global_fence;
    out[off++] = 0u;
    ninlil_r7_frag_store_u16_be(out + off, 0u);
    off += 2u;

    for (i = 0u; i < NINLIL_R7_FRAG_LANE_SLOTS; i++) {
        const ninlil_r7_frag_lane *L = &eng->lanes[i];
        if (!L->in_use) {
            continue;
        }
        out[off++] = L->lane_kind;
        out[off++] = (uint8_t)((L->tx_fenced ? 1u : 0u)
            | (L->rx_fenced ? 2u : 0u));
        ninlil_r7_frag_store_u32_be(out + off, L->context_id);
        off += 4u;
        ninlil_r7_frag_store_u64_be(out + off, L->key_generation);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, L->tx_reserved_exclusive);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, L->tx_ram_next);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, L->tx_ram_limit);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, L->rx_accept_reserved_through);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, L->rx_boot_floor);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, L->rx_ram_highest);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, L->rx_bitmap);
        off += 8u;
    }

    for (i = 0u; i < NINLIL_R7_FRAG_LINK_GROUP_SLOTS; i++) {
        const ninlil_r7_frag_link_group *G = &eng->links[i];
        if (!G->in_use) {
            continue;
        }
        out[off++] = G->ack_requested;
        out[off++] = G->completed;
        ninlil_r7_frag_store_u32_be(out + off, G->hop_data_context_id);
        off += 4u;
        ninlil_r7_frag_store_u64_be(out + off, G->e2e_counter_fixed);
        off += 8u;
        ninlil_r7_frag_store_u16_be(out + off, G->e2e_blob_len);
        off += 2u;
        ninlil_r7_frag_store_u64_be(out + off, G->group_absolute_deadline);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, G->enclosing_owner_deadline);
        off += 8u;
        ninlil_r7_frag_store_u64_be(out + off, G->eligible_at);
        off += 8u;
        out[off++] = G->hop_attempts;
        out[off++] = G->pending_count;
        ninlil_r7_frag_copy(out + off, G->e2e_blob, G->e2e_blob_len);
        off += G->e2e_blob_len;
    }

    if (off != need) {
        return NINLIL_R7_FRAG_INTERNAL_CONTRACT;
    }
    *out_len = off;
    return NINLIL_R7_FRAG_OK;
}

ninlil_r7_frag_status ninlil_r7_frag_restart_decode(
    ninlil_r7_frag_engine *eng,
    const uint8_t *in,
    size_t in_len)
{
    uint32_t magic;
    uint16_t version;
    uint16_t lane_count;
    uint16_t reasm_count;
    uint16_t link_count;
    size_t off = 0u;
    size_t i;
    size_t lane_slot = 0u;
    size_t link_slot = 0u;

    if (eng == NULL || in == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (in_len < SNAP_HDR_LEN) {
        return NINLIL_R7_FRAG_STRUCTURAL; /* partial */
    }
    magic = ninlil_r7_frag_load_u32_be(in + off);
    off += 4u;
    version = ninlil_r7_frag_load_u16_be(in + off);
    off += 2u;
    lane_count = ninlil_r7_frag_load_u16_be(in + off);
    off += 2u;
    reasm_count = ninlil_r7_frag_load_u16_be(in + off);
    off += 2u;
    link_count = ninlil_r7_frag_load_u16_be(in + off);
    off += 2u;

    if (magic != NINLIL_R7_FRAG_SNAP_MAGIC) {
        return NINLIL_R7_FRAG_STRUCTURAL; /* old/foreign */
    }
    if (version != NINLIL_R7_FRAG_SNAP_VERSION) {
        return NINLIL_R7_FRAG_STRUCTURAL; /* new/unsupported */
    }
    if (reasm_count != 0u) {
        return NINLIL_R7_FRAG_STRUCTURAL; /* third/extra reasm claim */
    }
    if (lane_count > NINLIL_R7_FRAG_LANE_SLOTS
        || link_count > NINLIL_R7_FRAG_LINK_GROUP_SLOTS) {
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    if (in_len < SNAP_HDR_LEN + (size_t)lane_count * SNAP_LANE_LEN) {
        return NINLIL_R7_FRAG_STRUCTURAL; /* partial */
    }

    ninlil_r7_frag_engine_init(eng);
    eng->now_mono = ninlil_r7_frag_load_u64_be(in + off);
    off += 8u;
    eng->global_fence = in[off++];
    off += 1u; /* reserved0 */
    off += 2u; /* reserved1 */

    for (i = 0u; i < lane_count; i++) {
        ninlil_r7_frag_lane *L;
        uint8_t flags;
        if (lane_slot >= NINLIL_R7_FRAG_LANE_SLOTS) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        if (off + SNAP_LANE_LEN > in_len) {
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        L = &eng->lanes[lane_slot++];
        memset(L, 0, sizeof(*L));
        L->in_use = 1u;
        L->lane_kind = in[off++];
        flags = in[off++];
        L->tx_fenced = (uint8_t)(flags & 1u);
        L->rx_fenced = (uint8_t)((flags >> 1) & 1u);
        L->context_id = ninlil_r7_frag_load_u32_be(in + off);
        off += 4u;
        L->key_generation = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        L->tx_reserved_exclusive = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        L->tx_ram_next = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        L->tx_ram_limit = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        L->rx_accept_reserved_through = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        L->rx_boot_floor = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        L->rx_ram_highest = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        L->rx_bitmap = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        if (!ninlil_r7_frag_context_ok(L->context_id)
            || L->key_generation == 0u
            || L->lane_kind < NINLIL_R7_FRAG_LANE_HOP_DATA
            || L->lane_kind > NINLIL_R7_FRAG_LANE_E2E) {
            ninlil_r7_frag_engine_init(eng);
            return NINLIL_R7_FRAG_STRUCTURAL; /* third/corrupt */
        }
        /* Restart RX: boot_floor from durable accept_reserved; clear sliding. */
        L->rx_boot_floor = L->rx_accept_reserved_through;
        L->rx_ram_highest = L->rx_boot_floor;
        L->rx_bitmap = 0u;
    }

    for (i = 0u; i < link_count; i++) {
        ninlil_r7_frag_link_group *G;
        uint16_t blen;
        if (link_slot >= NINLIL_R7_FRAG_LINK_GROUP_SLOTS) {
            ninlil_r7_frag_engine_init(eng);
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        if (off + 36u > in_len) {
            ninlil_r7_frag_engine_init(eng);
            return NINLIL_R7_FRAG_STRUCTURAL; /* partial */
        }
        G = &eng->links[link_slot++];
        memset(G, 0, sizeof(*G));
        G->in_use = 1u;
        G->ack_requested = in[off++];
        G->completed = in[off++];
        G->hop_data_context_id = ninlil_r7_frag_load_u32_be(in + off);
        off += 4u;
        G->e2e_counter_fixed = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        blen = ninlil_r7_frag_load_u16_be(in + off);
        off += 2u;
        G->group_absolute_deadline = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        G->enclosing_owner_deadline = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        G->eligible_at = ninlil_r7_frag_load_u64_be(in + off);
        off += 8u;
        G->hop_attempts = in[off++];
        G->pending_count = in[off++];
        if (blen < 31u || blen > 220u || off + blen > in_len) {
            ninlil_r7_frag_engine_init(eng);
            return NINLIL_R7_FRAG_STRUCTURAL;
        }
        G->e2e_blob_len = blen;
        ninlil_r7_frag_copy(G->e2e_blob, in + off, blen);
        off += blen;
        /* Restart does not resume volatile groups for air TX; mark completed. */
        G->completed = 1u;
        G->pending_count = 0u;
    }

    if (off != in_len) {
        /* extra trailing bytes */
        ninlil_r7_frag_engine_init(eng);
        return NINLIL_R7_FRAG_STRUCTURAL;
    }
    return NINLIL_R7_FRAG_OK;
}

/* -------------------------------------------------------------------------- */
/* COMMIT_UNKNOWN classifier                                                  */
/* -------------------------------------------------------------------------- */

static uint8_t ninlil_r7_frag_cu_entry_class(const ninlil_r7_frag_cu_entry *e)
{
    /* observed_status: 0=OK found, 1=NOT_FOUND, 2=BUSY, 3=IO, 4=OTHER */
    if (e->observed_status == 2u || e->observed_status == 3u) {
        return 0u; /* signal retry via special */
    }
    if (e->observed_status == 4u) {
        return NINLIL_R7_FRAG_CU_ENTRY_THIRD;
    }
    if (e->proposed_present) {
        /* PUT */
        if (e->observed_status == 0u
            && e->observed_len == e->proposed_len
            && (e->proposed_len == 0u
                || memcmp(e->observed_bytes, e->proposed_bytes, e->proposed_len)
                    == 0)) {
            return NINLIL_R7_FRAG_CU_ENTRY_PROPOSED;
        }
        if (e->old_present) {
            if (e->observed_status == 0u
                && e->observed_len == e->old_len
                && (e->old_len == 0u
                    || memcmp(e->observed_bytes, e->old_bytes, e->old_len)
                        == 0)) {
                return NINLIL_R7_FRAG_CU_ENTRY_OLD;
            }
            if (e->observed_status == 1u) {
                return NINLIL_R7_FRAG_CU_ENTRY_THIRD;
            }
        } else {
            if (e->observed_status == 1u) {
                return NINLIL_R7_FRAG_CU_ENTRY_OLD; /* NOT_FOUND ∧ ¬old */
            }
        }
        return NINLIL_R7_FRAG_CU_ENTRY_THIRD;
    }
    /* DELETE: old_present=1, proposed_present=0 */
    if (e->old_present && !e->proposed_present) {
        if (e->observed_status == 1u) {
            return NINLIL_R7_FRAG_CU_ENTRY_PROPOSED; /* deleted */
        }
        if (e->observed_status == 0u
            && e->observed_len == e->old_len
            && (e->old_len == 0u
                || memcmp(e->observed_bytes, e->old_bytes, e->old_len) == 0)) {
            return NINLIL_R7_FRAG_CU_ENTRY_OLD;
        }
        return NINLIL_R7_FRAG_CU_ENTRY_THIRD;
    }
    return NINLIL_R7_FRAG_CU_ENTRY_THIRD;
}

ninlil_r7_frag_status ninlil_r7_frag_cu_classify(
    const ninlil_r7_frag_cu_entry *entries,
    size_t entry_count,
    ninlil_r7_frag_cu_result *out)
{
    size_t i;
    int any_old = 0;
    int any_prop = 0;
    int any_third = 0;

    if (out == NULL) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    memset(out, 0, sizeof(*out));
    if (entries == NULL && entry_count != 0u) {
        return NINLIL_R7_FRAG_INVALID_ARGUMENT;
    }
    if (entry_count == 0u || entry_count > NINLIL_R7_FRAG_CU_MAX_ENTRIES) {
        out->class_code = NINLIL_R7_FRAG_CU_CORRUPT;
        return NINLIL_R7_FRAG_OK;
    }

    out->entry_count = (uint8_t)entry_count;
    for (i = 0u; i < entry_count; i++) {
        const ninlil_r7_frag_cu_entry *e = &entries[i];
        uint8_t cls;

        if (e->key_len == 0u || e->key_len > NINLIL_R7_FRAG_CU_KEY_MAX) {
            out->class_code = NINLIL_R7_FRAG_CU_CORRUPT;
            return NINLIL_R7_FRAG_OK;
        }
        if (e->old_len > NINLIL_R7_FRAG_CU_VALUE_MAX
            || e->proposed_len > NINLIL_R7_FRAG_CU_VALUE_MAX
            || e->observed_len > NINLIL_R7_FRAG_CU_VALUE_MAX) {
            out->class_code = NINLIL_R7_FRAG_CU_CORRUPT;
            return NINLIL_R7_FRAG_OK;
        }
        /* Normalize no-op PUT (proposed==old) is caller's duty before classify;
         * if both present and equal, treat as skip-able but still count. */
        if (e->observed_status == 2u || e->observed_status == 3u) {
            out->class_code = NINLIL_R7_FRAG_CU_RETRY_LATER;
            return NINLIL_R7_FRAG_OK;
        }
        cls = ninlil_r7_frag_cu_entry_class(e);
        if (cls == 0u) {
            out->class_code = NINLIL_R7_FRAG_CU_RETRY_LATER;
            return NINLIL_R7_FRAG_OK;
        }
        out->entry_class[i] = cls;
        if (cls == NINLIL_R7_FRAG_CU_ENTRY_OLD) {
            any_old = 1;
        } else if (cls == NINLIL_R7_FRAG_CU_ENTRY_PROPOSED) {
            any_prop = 1;
        } else {
            any_third = 1;
        }
    }

    if (any_third || (any_old && any_prop)) {
        out->class_code = NINLIL_R7_FRAG_CU_THIRD;
        return NINLIL_R7_FRAG_OK;
    }
    if (any_prop) {
        out->class_code = NINLIL_R7_FRAG_CU_ALL_PROPOSED;
    } else {
        out->class_code = NINLIL_R7_FRAG_CU_ALL_OLD;
    }
    return NINLIL_R7_FRAG_OK;
}
