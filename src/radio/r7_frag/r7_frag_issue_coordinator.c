/*
 * Authority-scoped issued-Permit coordinator (docs/30 §15.3 max 8).
 * Single-threaded reentry guard; freestanding C11.
 * Sole API: admit / begin_tx / hold_retry / resume_tx / complete.
 */

#include "r7_frag_issue_coordinator.h"

#include <string.h>

typedef struct {
    uint8_t state;
    uint64_t authority_token;
    uint64_t permit_sequence;
    uintptr_t bind_token;
    uint8_t outer_digest[32];
    uint32_t outer_len;
    uint64_t issue_now_ms;
} coord_slot_t;

static coord_slot_t g_slots[NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP];
static uint8_t g_in_api;

void ninlil_r7_frag_issue_coordinator_reset(void)
{
    memset(g_slots, 0, sizeof(g_slots));
    g_in_api = 0u;
}

static int enter(void)
{
    if (g_in_api != 0u) {
        return 0;
    }
    g_in_api = 1u;
    return 1;
}

static void leave(void)
{
    g_in_api = 0u;
}

static coord_slot_t *find(
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    size_t i;
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (g_slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && g_slots[i].authority_token == authority_token
            && g_slots[i].permit_sequence == permit_sequence) {
            return &g_slots[i];
        }
    }
    return NULL;
}

static uint64_t head_of(uint64_t authority_token)
{
    size_t i;
    uint64_t min_seq = UINT64_MAX;
    int any = 0;
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (g_slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && g_slots[i].authority_token == authority_token
            && g_slots[i].permit_sequence != 0u
            && g_slots[i].permit_sequence < min_seq) {
            min_seq = g_slots[i].permit_sequence;
            any = 1;
        }
    }
    return any ? min_seq : 0u;
}

static void refresh_heads(uint64_t authority_token)
{
    size_t i;
    uint64_t h = head_of(authority_token);
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (g_slots[i].state == NINLIL_R7_COORD_ST_EMPTY
            || g_slots[i].authority_token != authority_token) {
            continue;
        }
        if (g_slots[i].state == NINLIL_R7_COORD_ST_IN_TX
            || g_slots[i].state == NINLIL_R7_COORD_ST_HELD) {
            continue;
        }
        if (h != 0u && g_slots[i].permit_sequence == h) {
            g_slots[i].state = NINLIL_R7_COORD_ST_HEAD;
        } else {
            g_slots[i].state = NINLIL_R7_COORD_ST_QUEUED;
        }
    }
}

size_t ninlil_r7_frag_issue_coordinator_count(void)
{
    size_t i;
    size_t n = 0u;
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (g_slots[i].state != NINLIL_R7_COORD_ST_EMPTY) {
            n++;
        }
    }
    return n;
}

uint64_t ninlil_r7_frag_issue_coordinator_head(uint64_t authority_token)
{
    return head_of(authority_token);
}

int ninlil_r7_frag_issue_coordinator_is_head(
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    return head_of(authority_token) == permit_sequence && permit_sequence != 0u;
}

uint8_t ninlil_r7_frag_issue_coordinator_slot_state(
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    coord_slot_t *s;
    uint8_t st;
    if (!enter()) {
        return NINLIL_R7_COORD_ST_EMPTY;
    }
    s = find(authority_token, permit_sequence);
    st = (s != NULL) ? s->state : NINLIL_R7_COORD_ST_EMPTY;
    leave();
    return st;
}

int32_t ninlil_r7_frag_issue_coordinator_admit(const ninlil_r7_coord_admit_t *in)
{
    size_t i;
    coord_slot_t *s;
    uint64_t h;

    if (in == NULL || in->permit_sequence == 0u || in->authority_token == 0u
        || in->outer_len == 0u) {
        return NINLIL_R7_COORD_INVALID;
    }
    if (!enter()) {
        return NINLIL_R7_COORD_BUSY;
    }
    if (find(in->authority_token, in->permit_sequence) != NULL) {
        leave();
        return NINLIL_R7_COORD_DUPLICATE;
    }
    /* Same outer digest already live under authority ⇒ dual-issue reject. */
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (g_slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && g_slots[i].authority_token == in->authority_token
            && g_slots[i].outer_len == in->outer_len
            && memcmp(g_slots[i].outer_digest, in->outer_digest, 32u) == 0) {
            leave();
            return NINLIL_R7_COORD_DUPLICATE;
        }
    }
    if (ninlil_r7_frag_issue_coordinator_count()
        >= NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP) {
        leave();
        return NINLIL_R7_COORD_CAPACITY;
    }
    s = NULL;
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (g_slots[i].state == NINLIL_R7_COORD_ST_EMPTY) {
            s = &g_slots[i];
            break;
        }
    }
    if (s == NULL) {
        leave();
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
    refresh_heads(in->authority_token);
    h = head_of(in->authority_token);
    leave();
    return (h == in->permit_sequence) ? NINLIL_R7_COORD_OK : NINLIL_R7_COORD_QUEUED;
}

int32_t ninlil_r7_frag_issue_coordinator_begin_tx(
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    coord_slot_t *s;
    if (!enter()) {
        return NINLIL_R7_COORD_BUSY;
    }
    s = find(authority_token, permit_sequence);
    if (s == NULL) {
        leave();
        return NINLIL_R7_COORD_NOT_FOUND;
    }
    if (s->state != NINLIL_R7_COORD_ST_HEAD
        && s->state != NINLIL_R7_COORD_ST_HELD) {
        leave();
        return NINLIL_R7_COORD_OUT_OF_ORDER;
    }
    if (head_of(authority_token) != permit_sequence) {
        leave();
        return NINLIL_R7_COORD_OUT_OF_ORDER;
    }
    s->state = NINLIL_R7_COORD_ST_IN_TX;
    leave();
    return NINLIL_R7_COORD_OK;
}

int32_t ninlil_r7_frag_issue_coordinator_hold_retry(
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    coord_slot_t *s;
    if (!enter()) {
        return NINLIL_R7_COORD_BUSY;
    }
    s = find(authority_token, permit_sequence);
    if (s == NULL) {
        leave();
        return NINLIL_R7_COORD_NOT_FOUND;
    }
    if (s->state != NINLIL_R7_COORD_ST_IN_TX
        && s->state != NINLIL_R7_COORD_ST_HEAD) {
        leave();
        return NINLIL_R7_COORD_INVALID;
    }
    s->state = NINLIL_R7_COORD_ST_HELD;
    leave();
    return NINLIL_R7_COORD_OK;
}

int32_t ninlil_r7_frag_issue_coordinator_resume_tx(
    uint64_t authority_token,
    uint64_t permit_sequence)
{
    return ninlil_r7_frag_issue_coordinator_begin_tx(
        authority_token, permit_sequence);
}

int ninlil_r7_frag_issue_coordinator_outer_matches(
    uint64_t authority_token,
    uint64_t permit_sequence,
    const uint8_t outer_digest[32],
    uint32_t outer_len)
{
    coord_slot_t *s;
    int ok;
    if (outer_digest == NULL) {
        return 0;
    }
    if (!enter()) {
        return 0;
    }
    s = find(authority_token, permit_sequence);
    ok = (s != NULL && s->outer_len == outer_len
        && memcmp(s->outer_digest, outer_digest, 32u) == 0);
    leave();
    return ok;
}

int32_t ninlil_r7_frag_issue_coordinator_complete(
    uint64_t authority_token,
    uint64_t permit_sequence,
    uint64_t *out_promoted_seq)
{
    coord_slot_t *s;
    if (out_promoted_seq != NULL) {
        *out_promoted_seq = 0u;
    }
    if (!enter()) {
        return NINLIL_R7_COORD_BUSY;
    }
    s = find(authority_token, permit_sequence);
    if (s == NULL) {
        leave();
        return NINLIL_R7_COORD_NOT_FOUND;
    }
    memset(s, 0, sizeof(*s));
    refresh_heads(authority_token);
    if (out_promoted_seq != NULL) {
        *out_promoted_seq = head_of(authority_token);
    }
    leave();
    return NINLIL_R7_COORD_OK;
}

void ninlil_r7_frag_issue_coordinator_complete_all_authority(
    uint64_t authority_token)
{
    size_t i;
    if (authority_token == 0u || !enter()) {
        return;
    }
    for (i = 0u; i < NINLIL_R7_GLOBAL_ISSUED_FIFO_CAP; i++) {
        if (g_slots[i].state != NINLIL_R7_COORD_ST_EMPTY
            && g_slots[i].authority_token == authority_token) {
            memset(&g_slots[i], 0, sizeof(g_slots[i]));
        }
    }
    leave();
}
