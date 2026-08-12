/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Authority-scoped issued-Permit coordinator (docs/30 §15.3 max 8).
 * Single-threaded reentry guard; freestanding C11.
 * Sole API: admit / begin_tx / hold_retry / resume_tx / complete.
 */

#include "r7_frag_issue_coordinator.h"

#include <string.h>

void ninlil_r7_frag_issue_coordinator_init(
    ninlil_r7_frag_issue_coordinator_t *owner)
{
    if (owner != NULL) {
        memset(owner, 0, sizeof(*owner));
    }
}

void ninlil_r7_frag_issue_coordinator_reset(
    ninlil_r7_frag_issue_coordinator_t *owner)
{
    ninlil_r7_frag_issue_coordinator_init(owner);
}

void ninlil_r7_frag_issue_coordinator_fini(
    ninlil_r7_frag_issue_coordinator_t *owner)
{
    ninlil_r7_frag_issue_coordinator_init(owner);
}

static int enter(ninlil_r7_frag_issue_coordinator_t *owner)
{
    if (owner == NULL || owner->in_api != 0u) {
        return 0;
    }
    owner->in_api = 1u;
    return 1;
}

static void leave(ninlil_r7_frag_issue_coordinator_t *owner)
{
    owner->in_api = 0u;
}

static ninlil_r7_coord_slot_t *find(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (owner->slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && owner->slots[i].authority_token == authority_token
            && owner->slots[i].permit_sequence == permit_sequence) {
            return &owner->slots[i];
        }
    }
    return NULL;
}

static uint64_t head_of(
    const ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token)
{
    size_t i;
    uint64_t min_seq = UINT64_MAX;
    int any = 0;
    if (owner == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (owner->slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && owner->slots[i].authority_token == authority_token
            && owner->slots[i].permit_sequence != 0u
            && owner->slots[i].permit_sequence < min_seq) {
            min_seq = owner->slots[i].permit_sequence;
            any = 1;
        }
    }
    return any ? min_seq : 0u;
}

static void refresh_heads(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token)
{
    size_t i;
    uint64_t h = head_of(owner, authority_token);
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (owner->slots[i].state == NINLIL_R7_COORD_ST_EMPTY
            || owner->slots[i].authority_token != authority_token) {
            continue;
        }
        if (owner->slots[i].state == NINLIL_R7_COORD_ST_IN_TX
            || owner->slots[i].state == NINLIL_R7_COORD_ST_HELD) {
            continue;
        }
        if (h != 0u && owner->slots[i].permit_sequence == h) {
            owner->slots[i].state = NINLIL_R7_COORD_ST_HEAD;
        } else {
            owner->slots[i].state = NINLIL_R7_COORD_ST_QUEUED;
        }
    }
}

size_t ninlil_r7_frag_issue_coordinator_count(
    const ninlil_r7_frag_issue_coordinator_t *owner)
{
    size_t i;
    size_t n = 0u;
    if (owner == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (owner->slots[i].state != NINLIL_R7_COORD_ST_EMPTY) {
            n++;
        }
    }
    return n;
}

uint64_t ninlil_r7_frag_issue_coordinator_head(
    const ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token)
{
    return head_of(owner, authority_token);
}

int ninlil_r7_frag_issue_coordinator_is_head(
    const ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    return head_of(owner, authority_token) == permit_sequence
        && permit_sequence != 0u;
}

uint8_t ninlil_r7_frag_issue_coordinator_slot_state(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    ninlil_r7_coord_slot_t *s;
    uint8_t st;
    if (!enter(owner)) {
        return NINLIL_R7_COORD_ST_EMPTY;
    }
    s = find(owner, authority_token, permit_sequence);
    st = (s != NULL) ? s->state : NINLIL_R7_COORD_ST_EMPTY;
    leave(owner);
    return st;
}

int32_t ninlil_r7_frag_issue_coordinator_admit(
    ninlil_r7_frag_issue_coordinator_t *owner,
    const ninlil_r7_coord_admit_t *in)
{
    size_t i;
    ninlil_r7_coord_slot_t *s;
    uint64_t h;

    if (owner == NULL || in == NULL || in->permit_sequence == 0u
        || in->authority_token == 0u || in->outer_len == 0u) {
        return NINLIL_R7_COORD_INVALID;
    }
    if (!enter(owner)) {
        return NINLIL_R7_COORD_BUSY;
    }
    if (find(owner, in->authority_token, in->permit_sequence) != NULL) {
        leave(owner);
        return NINLIL_R7_COORD_DUPLICATE;
    }
    /* Same outer digest already live under authority ⇒ dual-issue reject. */
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (owner->slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && owner->slots[i].authority_token == in->authority_token
            && owner->slots[i].outer_len == in->outer_len
            && memcmp(owner->slots[i].outer_digest, in->outer_digest, 32u)
                == 0) {
            leave(owner);
            return NINLIL_R7_COORD_DUPLICATE;
        }
    }
    if (ninlil_r7_frag_issue_coordinator_count(owner)
        >= NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP) {
        leave(owner);
        return NINLIL_R7_COORD_CAPACITY;
    }
    s = NULL;
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (owner->slots[i].state == NINLIL_R7_COORD_ST_EMPTY) {
            s = &owner->slots[i];
            break;
        }
    }
    if (s == NULL) {
        leave(owner);
        return NINLIL_R7_COORD_CAPACITY;
    }
    memset(s, 0, sizeof(*s));
    s->authority_token = in->authority_token;
    s->permit_sequence = in->permit_sequence;
    s->bind_token = in->bind_token;
    s->outer_len = in->outer_len;
    s->issue_now_ms = in->issue_now_ms;
    memcpy(s->outer_digest, in->outer_digest, 32u);
    s->state = NINLIL_R7_COORD_ST_QUEUED;
    refresh_heads(owner, in->authority_token);
    h = head_of(owner, in->authority_token);
    leave(owner);
    return (h == in->permit_sequence) ? NINLIL_R7_COORD_OK
                                      : NINLIL_R7_COORD_QUEUED;
}

int32_t ninlil_r7_frag_issue_coordinator_begin_tx(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    ninlil_r7_coord_slot_t *s;
    if (owner == NULL) {
        return NINLIL_R7_COORD_INVALID;
    }
    if (!enter(owner)) {
        return NINLIL_R7_COORD_BUSY;
    }
    s = find(owner, authority_token, permit_sequence);
    if (s == NULL) {
        leave(owner);
        return NINLIL_R7_COORD_NOT_FOUND;
    }
    if (s->state != NINLIL_R7_COORD_ST_HEAD
        && s->state != NINLIL_R7_COORD_ST_HELD) {
        leave(owner);
        return NINLIL_R7_COORD_OUT_OF_ORDER;
    }
    if (head_of(owner, authority_token) != permit_sequence) {
        leave(owner);
        return NINLIL_R7_COORD_OUT_OF_ORDER;
    }
    s->state = NINLIL_R7_COORD_ST_IN_TX;
    leave(owner);
    return NINLIL_R7_COORD_OK;
}

int32_t ninlil_r7_frag_issue_coordinator_hold_retry(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    ninlil_r7_coord_slot_t *s;
    if (owner == NULL) {
        return NINLIL_R7_COORD_INVALID;
    }
    if (!enter(owner)) {
        return NINLIL_R7_COORD_BUSY;
    }
    s = find(owner, authority_token, permit_sequence);
    if (s == NULL) {
        leave(owner);
        return NINLIL_R7_COORD_NOT_FOUND;
    }
    if (s->state != NINLIL_R7_COORD_ST_IN_TX
        && s->state != NINLIL_R7_COORD_ST_HEAD) {
        leave(owner);
        return NINLIL_R7_COORD_INVALID;
    }
    s->state = NINLIL_R7_COORD_ST_HELD;
    leave(owner);
    return NINLIL_R7_COORD_OK;
}

int32_t ninlil_r7_frag_issue_coordinator_resume_tx(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    return ninlil_r7_frag_issue_coordinator_begin_tx(
        owner, authority_token, permit_sequence);
}

int ninlil_r7_frag_issue_coordinator_outer_matches(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence,
    const uint8_t outer_digest[32],
    uint32_t outer_len)
{
    ninlil_r7_coord_slot_t *s;
    int ok;
    if (outer_digest == NULL) {
        return 0;
    }
    if (!enter(owner)) {
        return 0;
    }
    s = find(owner, authority_token, permit_sequence);
    ok = (s != NULL && s->outer_len == outer_len
        && memcmp(s->outer_digest, outer_digest, 32u) == 0);
    leave(owner);
    return ok;
}

int32_t ninlil_r7_frag_issue_coordinator_complete(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token,
    uint64_t permit_sequence,
    uint64_t *out_promoted_seq)
{
    ninlil_r7_coord_slot_t *s;
    if (out_promoted_seq != NULL) {
        *out_promoted_seq = 0u;
    }
    if (owner == NULL) {
        return NINLIL_R7_COORD_INVALID;
    }
    if (!enter(owner)) {
        return NINLIL_R7_COORD_BUSY;
    }
    s = find(owner, authority_token, permit_sequence);
    if (s == NULL) {
        leave(owner);
        return NINLIL_R7_COORD_NOT_FOUND;
    }
    memset(s, 0, sizeof(*s));
    refresh_heads(owner, authority_token);
    if (out_promoted_seq != NULL) {
        *out_promoted_seq = head_of(owner, authority_token);
    }
    leave(owner);
    return NINLIL_R7_COORD_OK;
}

void ninlil_r7_frag_issue_coordinator_complete_all_authority(
    ninlil_r7_frag_issue_coordinator_t *owner,
    uint64_t authority_token)
{
    size_t i;
    if (authority_token == 0u || !enter(owner)) {
        return;
    }
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (owner->slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && owner->slots[i].authority_token == authority_token) {
            memset(&owner->slots[i], 0, sizeof(owner->slots[i]));
        }
    }
    leave(owner);
}
