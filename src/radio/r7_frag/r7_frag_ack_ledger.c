/* SPDX-License-Identifier: Apache-2.0 */
/*
 * FRAG_ACK reverse-burn ledger (docs/30 §15.3.7). Heap-free fixed-cap.
 */

#include "r7_frag_ack_ledger.h"

#include <string.h>

static void sec_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    size_t i;
    for (i = 0u; i < n; i++) {
        v[i] = 0u;
    }
}

static int id_eq(
    const ninlil_r7_frag_ack_identity_t *a,
    const ninlil_r7_frag_ack_identity_t *b)
{
    return a->transfer_handle == b->transfer_handle
        && a->frag_count == b->frag_count
        && a->received_bitmap == b->received_bitmap
        && a->status == b->status
        && a->reason == b->reason;
}

static int id_valid(const ninlil_r7_frag_ack_identity_t *id)
{
    return id != NULL && id->transfer_handle != 0u
        && id->transfer_handle != UINT64_MAX
        && id->frag_count >= 2u
        && id->frag_count <= NINLIL_R7_FRAG_COUNT_MAX;
}

void ninlil_r7_frag_ack_ledger_init(ninlil_r7_frag_ack_ledger_t *led)
{
    if (led == NULL) {
        return;
    }
    memset(led, 0, sizeof(*led));
}

void ninlil_r7_frag_ack_ledger_zeroize(ninlil_r7_frag_ack_ledger_t *led)
{
    if (led == NULL) {
        return;
    }
    sec_zero(led, sizeof(*led));
}

void ninlil_r7_frag_ack_identity_from_body(
    ninlil_r7_frag_ack_identity_t *id,
    uint64_t transfer_handle,
    uint16_t frag_count,
    uint16_t received_bitmap,
    uint8_t status,
    uint8_t reason)
{
    if (id == NULL) {
        return;
    }
    id->transfer_handle = transfer_handle;
    id->frag_count = frag_count;
    id->received_bitmap = received_bitmap;
    id->status = status;
    id->reason = reason;
}

uint16_t ninlil_r7_frag_ack_ledger_aggregate_limit(uint16_t frag_count)
{
    uint32_t lim = (uint32_t)frag_count * 2u;
    if (lim > (uint32_t)NINLIL_R7_FRAG_ACK_AGGREGATE_ABS_MAX) {
        lim = (uint32_t)NINLIL_R7_FRAG_ACK_AGGREGATE_ABS_MAX;
    }
    return (uint16_t)lim;
}

void ninlil_r7_frag_ack_ledger_bind_owner(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t transfer_handle,
    uint16_t frag_count,
    uint64_t owner_expiry_mono)
{
    if (led == NULL) {
        return;
    }
    led->owner_transfer_handle = transfer_handle;
    led->owner_frag_count = frag_count;
    led->owner_expiry_mono = owner_expiry_mono;
}

static void expire_rows(ninlil_r7_frag_ack_ledger_t *led, uint64_t now_mono)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_ACK_LEDGER_ROWS; i++) {
        ninlil_r7_frag_ack_ledger_row_t *r = &led->rows[i];
        if (!r->in_use) {
            continue;
        }
        if (r->owner_expiry_mono != 0u && now_mono >= r->owner_expiry_mono) {
            memset(r, 0, sizeof(*r));
        }
    }
}

void ninlil_r7_frag_ack_ledger_tick(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono)
{
    if (led == NULL) {
        return;
    }
    expire_rows(led, now_mono);
    if (led->owner_expiry_mono != 0u && now_mono >= led->owner_expiry_mono) {
        /* Owner expired: drop all rows for that transfer. */
        size_t i;
        for (i = 0u; i < NINLIL_R7_FRAG_ACK_LEDGER_ROWS; i++) {
            if (led->rows[i].in_use
                && led->rows[i].id.transfer_handle
                    == led->owner_transfer_handle) {
                memset(&led->rows[i], 0, sizeof(led->rows[i]));
            }
        }
    }
}

void ninlil_r7_frag_ack_ledger_discard_all(ninlil_r7_frag_ack_ledger_t *led)
{
    ninlil_r7_frag_ack_ledger_zeroize(led);
}

int32_t ninlil_r7_frag_ack_ledger_reserve_acquire(
    ninlil_r7_frag_ack_ledger_t *led)
{
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (led->control_reserve_held >= NINLIL_R7_FRAG_CONTROL_ACK_RESERVE) {
        return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
    }
    led->control_reserve_held =
        (uint8_t)(led->control_reserve_held + 1u);
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

void ninlil_r7_frag_ack_ledger_reserve_release(
    ninlil_r7_frag_ack_ledger_t *led)
{
    if (led == NULL || led->control_reserve_held == 0u) {
        return;
    }
    led->control_reserve_held =
        (uint8_t)(led->control_reserve_held - 1u);
}

uint16_t ninlil_r7_frag_ack_ledger_aggregate_burns(
    const ninlil_r7_frag_ack_ledger_t *led,
    uint64_t transfer_handle)
{
    size_t i;
    uint16_t sum = 0u;
    if (led == NULL || transfer_handle == 0u) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_ACK_LEDGER_ROWS; i++) {
        if (led->rows[i].in_use
            && led->rows[i].id.transfer_handle == transfer_handle) {
            sum = (uint16_t)(sum + led->rows[i].burns_used);
        }
    }
    return sum;
}

uint8_t ninlil_r7_frag_ack_ledger_burns_used(
    const ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id)
{
    size_t i;
    if (led == NULL || !id_valid(id)) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_ACK_LEDGER_ROWS; i++) {
        if (led->rows[i].in_use && id_eq(&led->rows[i].id, id)) {
            return led->rows[i].burns_used;
        }
    }
    return 0u;
}

static ninlil_r7_frag_ack_ledger_row_t *find_row(
    ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_ACK_LEDGER_ROWS; i++) {
        if (led->rows[i].in_use && id_eq(&led->rows[i].id, id)) {
            return &led->rows[i];
        }
    }
    return NULL;
}

static ninlil_r7_frag_ack_ledger_row_t *find_free_row(
    ninlil_r7_frag_ack_ledger_t *led)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_FRAG_ACK_LEDGER_ROWS; i++) {
        if (!led->rows[i].in_use) {
            return &led->rows[i];
        }
    }
    return NULL;
}

int32_t ninlil_r7_frag_ack_ledger_may_burn(
    const ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id,
    uint64_t now_mono)
{
    uint8_t used;
    uint16_t agg;
    uint16_t lim;
    size_t i;

    if (led == NULL || !id_valid(id)) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    /* Expired owner default: no new burns. */
    if (led->owner_expiry_mono != 0u && now_mono >= led->owner_expiry_mono
        && (led->owner_transfer_handle == 0u
            || led->owner_transfer_handle == id->transfer_handle)) {
        return NINLIL_R7_FRAG_ACK_LEDGER_EXPIRED;
    }
    used = 0u;
    for (i = 0u; i < NINLIL_R7_FRAG_ACK_LEDGER_ROWS; i++) {
        if (led->rows[i].in_use && id_eq(&led->rows[i].id, id)) {
            if (led->rows[i].owner_expiry_mono != 0u
                && now_mono >= led->rows[i].owner_expiry_mono) {
                return NINLIL_R7_FRAG_ACK_LEDGER_EXPIRED;
            }
            used = led->rows[i].burns_used;
            break;
        }
    }
    if (used >= NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2) {
        return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
    }
    lim = ninlil_r7_frag_ack_ledger_aggregate_limit(id->frag_count);
    agg = ninlil_r7_frag_ack_ledger_aggregate_burns(led, id->transfer_handle);
    if (agg >= lim) {
        return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
    }
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_ledger_charge_burn(
    ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id,
    uint64_t now_mono)
{
    ninlil_r7_frag_ack_ledger_row_t *row;
    int32_t st;

    if (led == NULL || !id_valid(id)) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    expire_rows(led, now_mono);
    st = ninlil_r7_frag_ack_ledger_may_burn(led, id, now_mono);
    if (st != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        return st;
    }
    row = find_row(led, id);
    if (row == NULL) {
        row = find_free_row(led);
        if (row == NULL) {
            return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
        }
        memset(row, 0, sizeof(*row));
        row->in_use = 1u;
        row->id = *id;
        row->burns_used = 0u;
        row->owner_expiry_mono = led->owner_expiry_mono;
    }
    if (row->burns_used >= NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2) {
        return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
    }
    row->burns_used = (uint8_t)(row->burns_used + 1u);
    row->last_burn_mono = now_mono;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

static void intent_clear_pending(ninlil_r7_frag_ack_ledger_t *led)
{
    led->intent_state = NINLIL_R7_FRAG_INTENT_IDLE;
    memset(&led->intent_id, 0, sizeof(led->intent_id));
    led->partial_ack_due = 0u;
    led->ack_intent_retry_at = 0u;
}

uint8_t ninlil_r7_frag_ack_intent_state(const ninlil_r7_frag_ack_ledger_t *led)
{
    return led == NULL ? NINLIL_R7_FRAG_INTENT_IDLE : led->intent_state;
}

int32_t ninlil_r7_frag_ack_intent_arm_pending(
    ninlil_r7_frag_ack_ledger_t *led,
    const ninlil_r7_frag_ack_identity_t *id,
    uint64_t now_mono,
    uint64_t owner_deadline_mono)
{
    uint64_t due;
    if (led == NULL || !id_valid(id)) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (now_mono > UINT64_MAX - NINLIL_R7_FRAG_PARTIAL_ACK_IDLE_MS) {
        intent_clear_pending(led);
        led->intent_state = NINLIL_R7_FRAG_INTENT_DROP;
        return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
    }
    due = now_mono + NINLIL_R7_FRAG_PARTIAL_ACK_IDLE_MS;
    if (owner_deadline_mono != 0u && owner_deadline_mono < due) {
        due = owner_deadline_mono;
    }
    led->intent_id = *id;
    led->partial_ack_due = due;
    led->ack_intent_retry_at = 0u;
    led->intent_state = NINLIL_R7_FRAG_INTENT_PENDING;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_intent_tick(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono)
{
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    ninlil_r7_frag_ack_ledger_tick(led, now_mono);
    if (led->intent_state == NINLIL_R7_FRAG_INTENT_IDLE
        || led->intent_state == NINLIL_R7_FRAG_INTENT_ACKED
        || led->intent_state == NINLIL_R7_FRAG_INTENT_DROP) {
        return NINLIL_R7_FRAG_ACK_LEDGER_OK;
    }
    if (led->owner_expiry_mono != 0u && now_mono >= led->owner_expiry_mono) {
        if (led->control_reserve_held > 0u
            && (led->intent_state == NINLIL_R7_FRAG_INTENT_RESERVE
                || led->intent_state == NINLIL_R7_FRAG_INTENT_BURN
                || led->intent_state == NINLIL_R7_FRAG_INTENT_BURN_CU
                || led->intent_state == NINLIL_R7_FRAG_INTENT_SEAL
                || led->intent_state == NINLIL_R7_FRAG_INTENT_LINK)) {
            ninlil_r7_frag_ack_ledger_reserve_release(led);
        }
        intent_clear_pending(led);
        led->intent_state = NINLIL_R7_FRAG_INTENT_DROP;
        return NINLIL_R7_FRAG_ACK_LEDGER_EXPIRED;
    }
    if (led->intent_state == NINLIL_R7_FRAG_INTENT_PENDING
        && now_mono >= led->partial_ack_due) {
        led->intent_state = NINLIL_R7_FRAG_INTENT_DUE;
    }
    if (led->intent_state == NINLIL_R7_FRAG_INTENT_RETRY
        && now_mono >= led->ack_intent_retry_at) {
        led->intent_state = NINLIL_R7_FRAG_INTENT_DUE;
    }
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_intent_enter_reserve(
    ninlil_r7_frag_ack_ledger_t *led)
{
    int32_t st;
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (led->intent_state != NINLIL_R7_FRAG_INTENT_DUE) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    st = ninlil_r7_frag_ack_ledger_reserve_acquire(led);
    if (st != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        intent_clear_pending(led);
        led->intent_state = NINLIL_R7_FRAG_INTENT_DROP;
        return st;
    }
    led->intent_state = NINLIL_R7_FRAG_INTENT_RESERVE;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_intent_after_burn_ok(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono)
{
    int32_t st;
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (led->intent_state != NINLIL_R7_FRAG_INTENT_RESERVE
        && led->intent_state != NINLIL_R7_FRAG_INTENT_BURN) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    st = ninlil_r7_frag_ack_ledger_charge_burn(led, &led->intent_id, now_mono);
    if (st != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        ninlil_r7_frag_ack_ledger_reserve_release(led);
        intent_clear_pending(led);
        led->intent_state = NINLIL_R7_FRAG_INTENT_DROP;
        return st;
    }
    led->intent_state = NINLIL_R7_FRAG_INTENT_SEAL;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_intent_enter_link(
    ninlil_r7_frag_ack_ledger_t *led)
{
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (led->intent_state != NINLIL_R7_FRAG_INTENT_SEAL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    led->intent_state = NINLIL_R7_FRAG_INTENT_LINK;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_intent_mark_acked(
    ninlil_r7_frag_ack_ledger_t *led)
{
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (led->intent_state == NINLIL_R7_FRAG_INTENT_RESERVE
        || led->intent_state == NINLIL_R7_FRAG_INTENT_BURN
        || led->intent_state == NINLIL_R7_FRAG_INTENT_BURN_CU
        || led->intent_state == NINLIL_R7_FRAG_INTENT_SEAL
        || led->intent_state == NINLIL_R7_FRAG_INTENT_LINK) {
        ninlil_r7_frag_ack_ledger_reserve_release(led);
    }
    /* Clear pending only — burns ledger retained. */
    led->intent_state = NINLIL_R7_FRAG_INTENT_ACKED;
    led->partial_ack_due = 0u;
    led->ack_intent_retry_at = 0u;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_intent_mark_drop(
    ninlil_r7_frag_ack_ledger_t *led)
{
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (led->intent_state == NINLIL_R7_FRAG_INTENT_RESERVE
        || led->intent_state == NINLIL_R7_FRAG_INTENT_BURN
        || led->intent_state == NINLIL_R7_FRAG_INTENT_BURN_CU
        || led->intent_state == NINLIL_R7_FRAG_INTENT_SEAL
        || led->intent_state == NINLIL_R7_FRAG_INTENT_LINK) {
        ninlil_r7_frag_ack_ledger_reserve_release(led);
    }
    led->intent_state = NINLIL_R7_FRAG_INTENT_DROP;
    led->partial_ack_due = 0u;
    led->ack_intent_retry_at = 0u;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}

int32_t ninlil_r7_frag_ack_intent_retry_or_drop(
    ninlil_r7_frag_ack_ledger_t *led,
    uint64_t now_mono)
{
    uint8_t used;
    if (led == NULL) {
        return NINLIL_R7_FRAG_ACK_LEDGER_INVALID;
    }
    if (led->intent_state == NINLIL_R7_FRAG_INTENT_RESERVE
        || led->intent_state == NINLIL_R7_FRAG_INTENT_SEAL
        || led->intent_state == NINLIL_R7_FRAG_INTENT_LINK) {
        ninlil_r7_frag_ack_ledger_reserve_release(led);
    }
    used = ninlil_r7_frag_ack_ledger_burns_used(led, &led->intent_id);
    if (used >= NINLIL_R7_FRAG_ACK_SEMANTIC_MAX2
        || ninlil_r7_frag_ack_ledger_may_burn(led, &led->intent_id, now_mono)
            != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        led->intent_state = NINLIL_R7_FRAG_INTENT_DROP;
        led->partial_ack_due = 0u;
        led->ack_intent_retry_at = 0u;
        return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
    }
    if (now_mono > UINT64_MAX - NINLIL_R7_FRAG_RETRY_INTERVAL_MS) {
        led->intent_state = NINLIL_R7_FRAG_INTENT_DROP;
        return NINLIL_R7_FRAG_ACK_LEDGER_RESOURCE;
    }
    led->ack_intent_retry_at = now_mono + NINLIL_R7_FRAG_RETRY_INTERVAL_MS;
    led->intent_state = NINLIL_R7_FRAG_INTENT_RETRY;
    return NINLIL_R7_FRAG_ACK_LEDGER_OK;
}
