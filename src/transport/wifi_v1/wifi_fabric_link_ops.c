/*
 * Fabric v1 packet-link ops over wifi_session (both flags ON).
 *
 * - Tokens: 64-bit non-wrapping generation (fence at wrap)
 * - open: second_open while open → DENIED (even if slots empty)
 * - cancel/close: terminal + cancel session TX ownership by sequence
 * - release: allowed after close via closed_generation handle; wipes slot
 * - start_send: TxPermit atomic consume (null/mismatch/expired/reused → DENIED)
 * - ingress: poll errors are not EMPTY
 */
#include "wifi_fabric_adapter.h"

#if (defined(NINLIL_POSIX_TLS_V1_BUILD)) \
    || (defined(NINLIL_ENABLE_PRIVATE_FABRIC_V1) \
        && NINLIL_ENABLE_PRIVATE_FABRIC_V1)

#include "wifi_nwb1.h"
#include "wifi_session.h"
#include "wifi_sha256.h"

#include <ninlil/platform.h>
#include <ninlil/version.h>

#include <string.h>

enum { NINLIL_WIFI_FABRIC_TOKEN_TAG = 0xA11Cu };
enum { NINLIL_WIFI_FABRIC_RX_TOKEN_TAG = 0x5Du };
enum { NINLIL_WIFI_FABRIC_PROVIDER_MAGIC = 0x57465031u }; /* WFP1 */

static ninlil_wifi_fabric_link_user_t *provider_user(
    void *opaque,
    uint32_t *out_authority_phase)
{
    ninlil_wifi_fabric_call_scope_v1_t *scope;
    ninlil_wifi_fabric_link_user_t *user;
    if (out_authority_phase != NULL) {
        *out_authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    }
    if (opaque == NULL) {
        return NULL;
    }
    scope = (ninlil_wifi_fabric_call_scope_v1_t *)opaque;
    if (scope->magic == NINLIL_WIFI_FABRIC_CALL_SCOPE_MAGIC) {
        if (!ninlil_wifi_fabric_call_scope_valid(scope)) {
            return NULL;
        }
        user = (ninlil_wifi_fabric_link_user_t *)scope->provider_user;
        if (user == NULL
            || user->provider_magic != NINLIL_WIFI_FABRIC_PROVIDER_MAGIC) {
            return NULL;
        }
        if (out_authority_phase != NULL) {
            *out_authority_phase = scope->authority->phase;
        }
        return user;
    }
    /*
     * Explicit low-level seam retained for the provider unit/Fabric seam
     * tests.  Production adapter instances never expose this user pointer.
     */
    user = (ninlil_wifi_fabric_link_user_t *)opaque;
    if (user->provider_magic != NINLIL_WIFI_FABRIC_PROVIDER_MAGIC
        || user->durable_outer_permit_authority == 0u) {
        return NULL;
    }
    if (out_authority_phase != NULL) {
        *out_authority_phase = NINLIL_WIFI_FABRIC_CALL_ACTIVE;
    }
    return user;
}

static int phase_allows_open(uint32_t phase)
{
    return phase == NINLIL_WIFI_FABRIC_CALL_PREPARED
        || phase == NINLIL_WIFI_FABRIC_CALL_ACTIVE;
}

static int phase_allows_new_io(uint32_t phase)
{
    return phase == NINLIL_WIFI_FABRIC_CALL_ACTIVE;
}

static ninlil_fabric_packet_token_t make_token(uint32_t generation, uint32_t slot)
{
    uint64_t v = ((uint64_t)generation << 32)
        | ((uint64_t)((slot + 1u) & 0xffffu) << 16)
        | (uint64_t)NINLIL_WIFI_FABRIC_TOKEN_TAG;
#if UINTPTR_MAX < 0xffffffffffffffffull
    v = ((uint64_t)((slot + 1u) & 0xffffu) << 16)
        | (uint64_t)NINLIL_WIFI_FABRIC_TOKEN_TAG;
#endif
    return (ninlil_fabric_packet_token_t)(uintptr_t)v;
}

static int decode_token(
    ninlil_fabric_packet_token_t token,
    uint32_t *out_generation,
    uint32_t *out_slot)
{
    uint64_t v;
    uint32_t slot_p1;
    uint32_t tag;
    if (token == NULL || out_generation == NULL || out_slot == NULL) {
        return 0;
    }
    v = (uint64_t)(uintptr_t)token;
    tag = (uint32_t)(v & 0xffffu);
    if (tag != NINLIL_WIFI_FABRIC_TOKEN_TAG) {
        return 0;
    }
    slot_p1 = (uint32_t)((v >> 16) & 0xffffu);
    if (slot_p1 == 0u || slot_p1 > NINLIL_WIFI_TX_QUEUE_DEPTH) {
        return 0;
    }
    *out_slot = slot_p1 - 1u;
#if UINTPTR_MAX >= 0xffffffffffffffffull
    *out_generation = (uint32_t)(v >> 32);
#else
    *out_generation = 0u;
#endif
    return 1;
}

static void *make_rx_token(uint32_t generation)
{
    uintptr_t v = ((uintptr_t)generation << 8)
        | (uintptr_t)NINLIL_WIFI_FABRIC_RX_TOKEN_TAG;
    return (void *)v;
}

static int rx_token_matches(
    const ninlil_wifi_fabric_link_user_t *u,
    const void *token)
{
    uintptr_t v;
    if (u == NULL || token == NULL || u->rx_loan_active == 0u
        || u->active_rx_loan_generation == 0u) {
        return 0;
    }
    v = (uintptr_t)token;
    if ((v & (uintptr_t)0xffu)
        != (uintptr_t)NINLIL_WIFI_FABRIC_RX_TOKEN_TAG) {
        return 0;
    }
    return (uint32_t)(v >> 8) == u->active_rx_loan_generation;
}

static ninlil_fabric_link_status_t map_st(ninlil_wifi_status_t st)
{
    if (st == NINLIL_WIFI_OK) {
        return NINLIL_FABRIC_LINK_OK;
    }
    if (st == NINLIL_WIFI_WOULD_BLOCK || st == NINLIL_WIFI_BACKPRESSURE) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (st == NINLIL_WIFI_CLOSED || st == NINLIL_WIFI_FENCED
        || st == NINLIL_WIFI_UNAVAILABLE) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (st == NINLIL_WIFI_CORRUPT) {
        return NINLIL_FABRIC_LINK_CORRUPT;
    }
    if (st == NINLIL_WIFI_DENIED || st == NINLIL_WIFI_CREDENTIAL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    return NINLIL_FABRIC_LINK_LOST_UNKNOWN;
}

static int handle_open_ok(
    const ninlil_wifi_fabric_link_user_t *u,
    ninlil_fabric_packet_link_handle_t handle)
{
    if (u == NULL || handle == NULL || !u->open || u->open_generation == 0u) {
        return 0;
    }
    return (uintptr_t)handle == (uintptr_t)u->open_generation;
}

/* release may use open gen or closed gen (post-close reclaim). */
static int handle_release_ok(
    const ninlil_wifi_fabric_link_user_t *u,
    ninlil_fabric_packet_link_handle_t handle)
{
    if (u == NULL || handle == NULL) {
        return 0;
    }
    if (u->open && (uintptr_t)handle == (uintptr_t)u->open_generation) {
        return 1;
    }
    if (!u->open && u->closed_generation != 0u
        && (uintptr_t)handle == (uintptr_t)u->closed_generation) {
        return 1;
    }
    return 0;
}

static ninlil_fabric_packet_link_handle_t make_handle(
    const ninlil_wifi_fabric_link_user_t *u)
{
    return (ninlil_fabric_packet_link_handle_t)(uintptr_t)u->open_generation;
}

static int id_is_zero(const uint8_t id[16])
{
    uint32_t i;
    for (i = 0u; i < 16u; ++i) {
        if (id[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

ninlil_wifi_status_t ninlil_wifi_fabric_bind_trusted_clock(
    ninlil_wifi_fabric_link_user_t *u,
    const ninlil_time_sample_t *sample)
{
    if (u == NULL || sample == NULL
        || sample->abi_version != NINLIL_ABI_VERSION
        || sample->struct_size != (uint16_t)sizeof(*sample)
        || sample->trust != NINLIL_CLOCK_TRUSTED
        || sample->reserved_zero != 0u
        || id_is_zero(sample->clock_epoch_id.bytes)) {
        return NINLIL_WIFI_DENIED;
    }
    if (u->permit_clock_epoch_set != 0u) {
        if (memcmp(
                u->permit_clock_epoch_id,
                sample->clock_epoch_id.bytes,
                16u)
                != 0
            || sample->now_ms < u->permit_now_ms) {
            return NINLIL_WIFI_DENIED;
        }
    }
    u->permit_now_ms = sample->now_ms;
    (void)memcpy(
        u->permit_clock_epoch_id, sample->clock_epoch_id.bytes, 16u);
    u->permit_clock_epoch_set = 1u;
    return NINLIL_WIFI_OK;
}

static int permit_id_known(
    const ninlil_wifi_fabric_link_user_t *u,
    const uint8_t permit_id[16])
{
    uint32_t i;
    for (i = 0u; i < NINLIL_WIFI_FABRIC_PERMIT_LEDGER; ++i) {
        if (u->permit_ledger[i].state != NINLIL_WIFI_FABRIC_PERMIT_ST_EMPTY
            && memcmp(u->permit_ledger[i].permit_id, permit_id, 16u) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Permit validity only (no ledger mutation). Call before capacity checks.
 * NULL/ABI/zero-id/attempt mismatch/expired/reused → DENIED.
 * LIVE capacity full → WOULD_BLOCK (distinct from reuse DENIED).
 */
static ninlil_fabric_link_status_t validate_tx_permit(
    const ninlil_wifi_fabric_link_user_t *u,
    const ninlil_fabric_packet_view_v1_t *packet)
{
    const ninlil_tx_permit_t *p;
    if (u == NULL || packet == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    p = packet->permit;
    if (p == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (p->abi_version != NINLIL_ABI_VERSION
        || p->struct_size != (uint16_t)sizeof(*p)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (id_is_zero(p->permit_id.bytes)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (!id_is_zero(packet->attempt_id.bytes)
        && memcmp(p->attempt_id.bytes, packet->attempt_id.bytes, 16u) != 0) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (p->expires_at_ms == 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    /*
     * This provider deliberately does not own an unbounded durable replay
     * database. Fabric's co-located FBA1 authority must wrap it, and a trusted clock
     * snapshot is mandatory for every expiry decision.
     */
    if (u->durable_outer_permit_authority == 0u
        || u->permit_clock_epoch_set == 0u
        || id_is_zero(u->permit_clock_epoch_id)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (memcmp(p->clock_epoch_id.bytes, u->permit_clock_epoch_id, 16u) != 0) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (u->permit_now_ms >= p->expires_at_ms) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (permit_id_known(u, p->permit_id.bytes)) {
        return NINLIL_FABRIC_LINK_DENIED; /* reused TX0 (live or retired) */
    }
    if (u->permit_live_count >= NINLIL_WIFI_FABRIC_PERMIT_CONSUME_MAX) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    return NINLIL_FABRIC_LINK_OK;
}

/*
 * Atomic consume after capacity reserved. Places permit_id in LIVE ledger slot.
 * out_ledger_slot receives the ledger index for later retire.
 */
static ninlil_fabric_link_status_t consume_tx_permit(
    ninlil_wifi_fabric_link_user_t *u,
    const ninlil_fabric_packet_view_v1_t *packet,
    uint8_t *out_ledger_slot)
{
    ninlil_fabric_link_status_t st;
    const ninlil_tx_permit_t *p;
    uint32_t i;
    uint32_t pick = NINLIL_WIFI_FABRIC_PERMIT_LEDGER;
    st = validate_tx_permit(u, packet);
    if (st != NINLIL_FABRIC_LINK_OK) {
        return st;
    }
    p = packet->permit;
    /* EMPTY only. RETIRED is reclaimed by release, never by a new send. */
    for (i = 0u; i < NINLIL_WIFI_FABRIC_PERMIT_LEDGER; ++i) {
        if (u->permit_ledger[i].state == NINLIL_WIFI_FABRIC_PERMIT_ST_EMPTY) {
            pick = i;
            break;
        }
    }
    if (pick >= NINLIL_WIFI_FABRIC_PERMIT_LEDGER) {
        /* Bounded fail-closed history: a fresh ID cannot evict an old one. */
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    (void)memset(&u->permit_ledger[pick], 0, sizeof(u->permit_ledger[pick]));
    (void)memcpy(u->permit_ledger[pick].permit_id, p->permit_id.bytes, 16u);
    (void)memcpy(
        u->permit_ledger[pick].clock_epoch_id,
        p->clock_epoch_id.bytes,
        16u);
    u->permit_ledger[pick].expires_at_ms = p->expires_at_ms;
    u->permit_ledger[pick].state = NINLIL_WIFI_FABRIC_PERMIT_ST_LIVE;
    u->permit_live_count += 1u;
    if (out_ledger_slot != NULL) {
        *out_ledger_slot = (uint8_t)pick;
    }
    return NINLIL_FABRIC_LINK_OK;
}

/* Roll back a LIVE consume if transport refuses after consume. */
static void unconsume_permit_slot(
    ninlil_wifi_fabric_link_user_t *u,
    uint8_t ledger_slot,
    const uint8_t permit_id[16])
{
    if (u == NULL || permit_id == NULL
        || ledger_slot >= NINLIL_WIFI_FABRIC_PERMIT_LEDGER) {
        return;
    }
    if (u->permit_ledger[ledger_slot].state != NINLIL_WIFI_FABRIC_PERMIT_ST_LIVE) {
        return;
    }
    if (memcmp(u->permit_ledger[ledger_slot].permit_id, permit_id, 16u) != 0) {
        return;
    }
    (void)memset(&u->permit_ledger[ledger_slot], 0, sizeof(u->permit_ledger[0]));
    if (u->permit_live_count > 0u) {
        u->permit_live_count -= 1u;
    }
}

/* Success/cancel/fail: free LIVE capacity, keep ID as RETIRED for reuse deny. */
static void retire_permit_slot(
    ninlil_wifi_fabric_link_user_t *u,
    uint8_t ledger_slot,
    const uint8_t permit_id[16])
{
    if (u == NULL || permit_id == NULL
        || ledger_slot >= NINLIL_WIFI_FABRIC_PERMIT_LEDGER) {
        return;
    }
    if (u->permit_ledger[ledger_slot].state != NINLIL_WIFI_FABRIC_PERMIT_ST_LIVE) {
        return;
    }
    if (memcmp(u->permit_ledger[ledger_slot].permit_id, permit_id, 16u) != 0) {
        return;
    }
    u->permit_ledger[ledger_slot].state = NINLIL_WIFI_FABRIC_PERMIT_ST_RETIRED;
    if (u->permit_live_count > 0u) {
        u->permit_live_count -= 1u;
    }
}

/*
 * Reclaim only after terminal token release. Permanent one-shot replay truth
 * remains in Fabric's durable FBA1 until bounded GC; TxGate never reissues the
 * pair, so clearing here cannot authorize replay through the supported path.
 */
static void release_permit_slot(
    ninlil_wifi_fabric_link_user_t *u,
    uint8_t ledger_slot,
    const uint8_t permit_id[16])
{
    if (u == NULL || permit_id == NULL
        || u->durable_outer_permit_authority == 0u
        || ledger_slot >= NINLIL_WIFI_FABRIC_PERMIT_LEDGER) {
        return;
    }
    if (u->permit_ledger[ledger_slot].state
            != NINLIL_WIFI_FABRIC_PERMIT_ST_RETIRED
        || memcmp(u->permit_ledger[ledger_slot].permit_id, permit_id, 16u)
            != 0) {
        return;
    }
    (void)memset(
        &u->permit_ledger[ledger_slot],
        0,
        sizeof(u->permit_ledger[ledger_slot]));
}

static void cancel_session_tx_for_slot(
    ninlil_wifi_fabric_link_user_t *u,
    uint32_t slot)
{
    if (u == NULL || u->session == NULL || slot >= NINLIL_WIFI_TX_QUEUE_DEPTH) {
        return;
    }
    if (u->send_slots[slot].in_use == 0u) {
        return;
    }
    (void)ninlil_wifi_session_cancel_tx_sequence(
        u->session, u->send_slots[slot].sequence_at_accept);
}

static void mark_all_terminal_and_cancel_tx(
    ninlil_wifi_fabric_link_user_t *u,
    int cancelled)
{
    uint32_t slot;
    if (u == NULL) {
        return;
    }
    for (slot = 0u; slot < NINLIL_WIFI_TX_QUEUE_DEPTH; ++slot) {
        if (u->send_slots[slot].in_use != 0u) {
            if (cancelled) {
                u->send_slots[slot].cancelled = 1u;
                cancel_session_tx_for_slot(u, slot);
            }
            u->send_slots[slot].terminal = 1u;
            u->send_slots[slot].completion_kind =
                NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
            retire_permit_slot(
                u,
                u->send_slots[slot].permit_ledger_slot,
                u->send_slots[slot].permit_id);
        }
    }
    u->rx_loan_active = 0u;
    u->active_rx_loan_generation = 0u;
}

static ninlil_fabric_link_status_t wifi_pl_open(
    void *user, ninlil_fabric_packet_link_handle_t *out_handle)
{
    uint32_t authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    ninlil_wifi_fabric_link_user_t *u =
        provider_user(user, &authority_phase);
    uint32_t slot;
    int live = 0;
    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    if (u == NULL || !phase_allows_open(authority_phase)
        || out_handle == NULL || u->session == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    /* Second open while already open is always denied (empty slots or not). */
    if (u->open != 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    for (slot = 0u; slot < NINLIL_WIFI_TX_QUEUE_DEPTH; ++slot) {
        if (u->send_slots[slot].in_use != 0u) {
            live = 1;
            break;
        }
    }
    /* Unreleased terminal slots block reopen until release reclaim. */
    if (live) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (u->open_generation == UINT32_MAX
        || u->session->availability_epoch == 0u
        || u->session->availability_epoch_exhausted) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    u->open = 1u;
    u->open_generation += 1u;
    u->closed_generation = 0u;
    u->availability_epoch_seen = u->session->availability_epoch;
    if (u->next_token_generation == 0u) {
        u->next_token_generation = 1u;
    }
    *out_handle = make_handle(u);
    return NINLIL_FABRIC_LINK_OK;
}

static void wifi_pl_close(void *user, ninlil_fabric_packet_link_handle_t handle)
{
    ninlil_wifi_fabric_link_user_t *u = provider_user(user, NULL);
    if (u == NULL) {
        return;
    }
    if (handle != NULL && !handle_open_ok(u, handle)) {
        return;
    }
    mark_all_terminal_and_cancel_tx(u, 1);
    u->closed_generation = u->open_generation;
    u->open = 0u;
}

static ninlil_fabric_link_status_t wifi_pl_start_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const ninlil_fabric_packet_view_v1_t *packet,
    ninlil_fabric_packet_token_t *out_token)
{
    uint32_t authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    ninlil_wifi_fabric_link_user_t *u =
        provider_user(user, &authority_phase);
    ninlil_wifi_status_t st;
    ninlil_fabric_link_status_t pst;
    uint32_t slot;
    uint32_t gen;
    uint32_t seq_before;
    if (out_token != NULL) {
        *out_token = NULL;
    }
    if (u == NULL || !phase_allows_new_io(authority_phase)
        || !handle_open_ok(u, handle) || packet == NULL
        || packet->bytes == NULL || out_token == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (u->session->availability_epoch != u->availability_epoch_seen) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (u->session->phase != NINLIL_WIFI_PHASE_ATTACHED) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (packet->length > NINLIL_WIFI_NWB1_PAYLOAD_MAX) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (u->next_token_generation == UINT32_MAX) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    /*
     * Order (ADR-0017): validate permit → reserve capacity (consume 0) →
     * atomic consume immediately before transport I/O.
     * WOULD_BLOCK paths must never increment consumed_permit_count.
     */
    pst = validate_tx_permit(u, packet);
    if (pst != NINLIL_FABRIC_LINK_OK) {
        return pst;
    }
    for (slot = 0u; slot < NINLIL_WIFI_TX_QUEUE_DEPTH; ++slot) {
        if (u->send_slots[slot].in_use == 0u) {
            break;
        }
    }
    if (slot >= NINLIL_WIFI_TX_QUEUE_DEPTH) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (ninlil_wifi_queue_is_full(&u->session->txq)) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    /* Capacity reserved: consume then send. */
    {
        uint8_t ledger_slot = 0xffu;
        uint32_t live_before = u->permit_live_count;
        pst = consume_tx_permit(u, packet, &ledger_slot);
        if (pst != NINLIL_FABRIC_LINK_OK) {
            return pst;
        }
        seq_before = u->session->next_tx_sequence;
        st = ninlil_wifi_session_send_payload(
            u->session, packet->bytes, packet->length);
        if (st == NINLIL_WIFI_BACKPRESSURE || st == NINLIL_WIFI_WOULD_BLOCK) {
            /* Contract: WOULD_BLOCK ⇒ consume 0; roll back ledger. */
            if (u->permit_live_count > live_before && packet->permit != NULL) {
                unconsume_permit_slot(
                    u, ledger_slot, packet->permit->permit_id.bytes);
            }
            return NINLIL_FABRIC_LINK_WOULD_BLOCK;
        }
        if (st != NINLIL_WIFI_OK) {
            if (u->permit_live_count > live_before && packet->permit != NULL) {
                unconsume_permit_slot(
                    u, ledger_slot, packet->permit->permit_id.bytes);
            }
            return map_st(st);
        }
        gen = u->next_token_generation;
        if (gen == 0u) {
            gen = 1u;
        }
        u->next_token_generation = gen + 1u;
        u->send_slots[slot].in_use = 1u;
        u->send_slots[slot].terminal = 0u;
        u->send_slots[slot].cancelled = 0u;
        u->send_slots[slot].completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_PENDING;
        u->send_slots[slot].permit_ledger_slot = ledger_slot;
        u->send_slots[slot].generation = gen;
        u->send_slots[slot].sequence_at_accept = seq_before;
        (void)memcpy(
            u->send_slots[slot].permit_id, packet->permit->permit_id.bytes, 16u);
        if (u->accepted_send_count != UINT64_MAX) {
            u->accepted_send_count += 1u;
        }
        *out_token = make_token(gen, slot);
        return NINLIL_FABRIC_LINK_RETAINED;
    }
}

static ninlil_fabric_link_status_t wifi_pl_poll_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token,
    ninlil_fabric_link_completion_v1_t *out_completion)
{
    ninlil_wifi_fabric_link_user_t *u = provider_user(user, NULL);
    ninlil_wifi_status_t st;
    uint32_t gen = 0u;
    uint32_t slot = 0u;
    if (out_completion != NULL) {
        (void)memset(out_completion, 0, sizeof(*out_completion));
    }
    if (u == NULL || out_completion == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    /* poll requires open handle; cancelled slots still pollable after close via open gen only */
    if (!handle_open_ok(u, handle) && !handle_release_ok(u, handle)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (!decode_token(token, &gen, &slot)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (u->send_slots[slot].in_use == 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
#if UINTPTR_MAX >= 0xffffffffffffffffull
    if (u->send_slots[slot].generation != gen) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
#endif
    out_completion->api_version = 1u;
    out_completion->struct_size = (uint16_t)sizeof(*out_completion);
    if (u->session->availability_epoch != u->availability_epoch_seen) {
        out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        u->send_slots[slot].terminal = 1u;
        u->send_slots[slot].completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        retire_permit_slot(
            u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
        return NINLIL_FABRIC_LINK_OK;
    }
    if (u->send_slots[slot].cancelled) {
        out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        u->send_slots[slot].terminal = 1u;
        return NINLIL_FABRIC_LINK_OK;
    }
    if (u->send_slots[slot].terminal) {
        out_completion->kind = u->send_slots[slot].completion_kind;
        return NINLIL_FABRIC_LINK_OK;
    }
    if (!u->open) {
        /* Closed: treat as definite failure terminal. */
        out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        u->send_slots[slot].terminal = 1u;
        u->send_slots[slot].completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        retire_permit_slot(
            u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
        return NINLIL_FABRIC_LINK_OK;
    }
    /*
     * Completion belongs to this sequence, not to global queue emptiness.
     * Observe already-completed work before asking the session to progress a
     * later queued record.
     */
    if (ninlil_wifi_session_tx_sequence_completed(
            u->session, u->send_slots[slot].sequence_at_accept)) {
        out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        u->send_slots[slot].terminal = 1u;
        u->send_slots[slot].completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        retire_permit_slot(
            u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
        return NINLIL_FABRIC_LINK_OK;
    }
    st = ninlil_wifi_session_poll(u->session);
    if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
        && st != NINLIL_WIFI_BACKPRESSURE) {
        out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        u->send_slots[slot].terminal = 1u;
        u->send_slots[slot].completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        retire_permit_slot(
            u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
        return NINLIL_FABRIC_LINK_OK;
    }
    if (ninlil_wifi_session_tx_sequence_completed(
            u->session, u->send_slots[slot].sequence_at_accept)) {
        out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        u->send_slots[slot].terminal = 1u;
        u->send_slots[slot].completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_TRANSPORT_DONE;
        retire_permit_slot(
            u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
        return NINLIL_FABRIC_LINK_OK;
    }
    out_completion->kind = NINLIL_FABRIC_LINK_COMPLETION_PENDING;
    return NINLIL_FABRIC_LINK_OK;
}

static ninlil_fabric_link_status_t wifi_pl_cancel_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_wifi_fabric_link_user_t *u = provider_user(user, NULL);
    uint32_t gen = 0u;
    uint32_t slot = 0u;
    if (u == NULL || !handle_open_ok(u, handle)
        || !decode_token(token, &gen, &slot)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (u->send_slots[slot].in_use == 0u) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
#if UINTPTR_MAX >= 0xffffffffffffffffull
    if (u->send_slots[slot].generation != gen) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
#endif
    {
        int partial_inflight = 0;
        if (u->session != NULL && u->session->tx_partial_len >= 36u) {
            uint32_t pseq = ((uint32_t)u->session->tx_partial_buf[32] << 24)
                | ((uint32_t)u->session->tx_partial_buf[33] << 16)
                | ((uint32_t)u->session->tx_partial_buf[34] << 8)
                | (uint32_t)u->session->tx_partial_buf[35];
            if (pseq == u->send_slots[slot].sequence_at_accept) {
                partial_inflight = 1;
            }
        }
        u->send_slots[slot].cancelled = 1u;
        u->send_slots[slot].terminal = 1u;
        u->send_slots[slot].completion_kind =
            NINLIL_FABRIC_LINK_COMPLETION_DEFINITE_FAILURE;
        cancel_session_tx_for_slot(u, slot);
        /*
         * cancel_tx_sequence owns the partial-write fence. Calling fence here
         * again would publish two epochs for the same cancellation.
         */
        (void)partial_inflight;
        retire_permit_slot(
            u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
        return NINLIL_FABRIC_LINK_OK;
    }
}

static void wifi_pl_release_send(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_packet_token_t token)
{
    ninlil_wifi_fabric_link_user_t *u = provider_user(user, NULL);
    uint32_t gen = 0u;
    uint32_t slot = 0u;
    uint32_t i;
    int any = 0;
    if (u == NULL || !handle_release_ok(u, handle)
        || !decode_token(token, &gen, &slot)) {
        return;
    }
    if (u->send_slots[slot].in_use == 0u) {
        return;
    }
#if UINTPTR_MAX >= 0xffffffffffffffffull
    if (u->send_slots[slot].generation != gen) {
        return;
    }
#endif
    if (u->send_slots[slot].terminal == 0u) {
        return; /* release-before-terminal forbidden */
    }
    /* Success path: retire if still LIVE (cancel already retired). */
    retire_permit_slot(
        u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
    release_permit_slot(
        u, u->send_slots[slot].permit_ledger_slot, u->send_slots[slot].permit_id);
    (void)memset(&u->send_slots[slot], 0, sizeof(u->send_slots[slot]));
    for (i = 0u; i < NINLIL_WIFI_TX_QUEUE_DEPTH; ++i) {
        if (u->send_slots[i].in_use != 0u) {
            any = 1;
            break;
        }
    }
    if (!any && !u->open) {
        u->closed_generation = 0u;
    }
}

static ninlil_fabric_link_status_t wifi_pl_receive_next(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    const uint8_t **out_bytes,
    uint32_t *out_length,
    void **out_receive_token)
{
    uint32_t authority_phase = NINLIL_WIFI_FABRIC_CALL_UNBOUND;
    ninlil_wifi_fabric_link_user_t *u =
        provider_user(user, &authority_phase);
    ninlil_wifi_status_t st;
    size_t len = 0u;
    if (out_bytes != NULL) {
        *out_bytes = NULL;
    }
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (out_receive_token != NULL) {
        *out_receive_token = NULL;
    }
    if (u == NULL || !phase_allows_new_io(authority_phase)
        || !handle_open_ok(u, handle) || out_bytes == NULL
        || out_length == NULL || out_receive_token == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (u->rx_loan_active) {
        return NINLIL_FABRIC_LINK_WOULD_BLOCK;
    }
    if (u->next_rx_loan_generation >= (uint32_t)(UINTPTR_MAX >> 8)) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    if (u->session->availability_epoch != u->availability_epoch_seen) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    st = ninlil_wifi_session_poll(u->session);
    if (st != NINLIL_WIFI_OK && st != NINLIL_WIFI_WOULD_BLOCK
        && st != NINLIL_WIFI_BACKPRESSURE
        && st != NINLIL_WIFI_INVALID_STATE) {
        return map_st(st);
    }
    st = ninlil_wifi_session_recv_record(
        u->session, u->rx_record, sizeof(u->rx_record), &len, NULL);
    if (st == NINLIL_WIFI_WOULD_BLOCK) {
        return NINLIL_FABRIC_LINK_EMPTY;
    }
    if (st == NINLIL_WIFI_INVALID_STATE) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (st != NINLIL_WIFI_OK) {
        return map_st(st);
    }
    {
        const uint8_t *payload = NULL;
        uint32_t payload_len = 0u;
        uint32_t seq = 0u;
        st = ninlil_wifi_nwb1_classify(
            u->rx_record,
            len,
            u->session->ids.attached_session_id,
            0,
            0u,
            &payload,
            &payload_len,
            &seq);
        if (st != NINLIL_WIFI_OK || payload == NULL || payload_len == 0u) {
            return NINLIL_FABRIC_LINK_CORRUPT;
        }
        if (u->accepted_receive_count == UINT64_MAX) {
            return NINLIL_FABRIC_LINK_UNAVAILABLE;
        }
        u->last_receive_sequence = seq;
        u->last_receive_length = payload_len;
        ninlil_wifi_sha256(
            payload, payload_len, u->last_receive_digest);
        u->accepted_receive_count += 1u;
        if (payload != u->rx_record) {
            (void)memmove(u->rx_record, payload, payload_len);
        }
        u->rx_record_len = payload_len;
    }
    u->rx_loan_active = 1u;
    u->next_rx_loan_generation += 1u;
    if (u->next_rx_loan_generation == 0u) {
        return NINLIL_FABRIC_LINK_UNAVAILABLE;
    }
    u->active_rx_loan_generation = u->next_rx_loan_generation;
    *out_bytes = u->rx_record;
    *out_length = u->rx_record_len;
    *out_receive_token = make_rx_token(u->active_rx_loan_generation);
    return NINLIL_FABRIC_LINK_OK;
}

static void wifi_pl_release_received(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    void *receive_token)
{
    ninlil_wifi_fabric_link_user_t *u = provider_user(user, NULL);
    if (u == NULL || !handle_open_ok(u, handle)
        || !rx_token_matches(u, receive_token)) {
        return;
    }
    u->rx_loan_active = 0u;
    u->active_rx_loan_generation = 0u;
    u->rx_record_len = 0u;
}

static ninlil_fabric_link_status_t wifi_pl_state(
    void *user,
    ninlil_fabric_packet_link_handle_t handle,
    ninlil_fabric_link_state_v1_t *out_state)
{
    ninlil_wifi_fabric_link_user_t *u = provider_user(user, NULL);
    if (out_state != NULL) {
        (void)memset(out_state, 0, sizeof(*out_state));
    }
    if (u == NULL || out_state == NULL) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    if (handle != NULL && !handle_open_ok(u, handle)
        && !handle_release_ok(u, handle)) {
        return NINLIL_FABRIC_LINK_DENIED;
    }
    out_state->api_version = 1u;
    out_state->struct_size = (uint16_t)sizeof(*out_state);
    out_state->availability_epoch =
        (u->session != NULL) ? u->session->availability_epoch : 0u;
    if (u->permit_clock_epoch_set != 0u) {
        (void)memcpy(
            out_state->availability_clock_epoch_id.bytes,
            u->permit_clock_epoch_id,
            16u);
        /*
         * Availability is revoked by the monotonic session epoch, not by a
         * guessed timer. Fabric still applies descriptor/authority/permit
         * deadlines independently.
         */
        out_state->available_until_ms = UINT64_MAX;
    }
    out_state->available =
        (u->open && u->session != NULL
         && u->session->phase == NINLIL_WIFI_PHASE_ATTACHED
         && !u->session->availability_epoch_exhausted
         && u->session->availability_epoch == u->availability_epoch_seen)
        ? 1u
        : 0u;
    return NINLIL_FABRIC_LINK_OK;
}

static void packet_link_ops_fill(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    void *ops_user)
{
    if (ops == NULL) {
        return;
    }
    (void)memset(ops, 0, sizeof(*ops));
    ops->api_version = 1u;
    ops->struct_size = (uint16_t)sizeof(*ops);
    ops->user = ops_user;
    ops->open = wifi_pl_open;
    ops->close = wifi_pl_close;
    ops->start_send = wifi_pl_start_send;
    ops->poll_send = wifi_pl_poll_send;
    ops->cancel_send = wifi_pl_cancel_send;
    ops->release_send = wifi_pl_release_send;
    ops->receive_next = wifi_pl_receive_next;
    ops->release_received = wifi_pl_release_received;
    ops->state = wifi_pl_state;
}

void ninlil_wifi_fabric_packet_link_ops_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_fabric_link_user_t *user)
{
    if (user != NULL) {
        user->provider_magic = NINLIL_WIFI_FABRIC_PROVIDER_MAGIC;
        if (user->call_authority.magic
            != NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC) {
            ninlil_wifi_fabric_call_authority_init(&user->call_authority);
        }
    }
    packet_link_ops_fill(ops, user);
}

void ninlil_wifi_fabric_packet_link_ops_scoped_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_fabric_link_user_t *user,
    ninlil_wifi_fabric_call_scope_v1_t *scope,
    const void *fabric_cookie)
{
    if (user == NULL || scope == NULL) {
        packet_link_ops_fill(ops, NULL);
        return;
    }
    user->provider_magic = NINLIL_WIFI_FABRIC_PROVIDER_MAGIC;
    if (user->call_authority.magic
        != NINLIL_WIFI_FABRIC_CALL_AUTHORITY_MAGIC) {
        ninlil_wifi_fabric_call_authority_init(&user->call_authority);
    }
    ninlil_wifi_fabric_call_scope_init(
        scope, user, &user->call_authority, fabric_cookie);
    packet_link_ops_fill(ops, scope);
}

int ninlil_wifi_fabric_packet_link_authority_prepare(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    if (user == NULL
        || user->provider_magic != NINLIL_WIFI_FABRIC_PROVIDER_MAGIC
        || !ninlil_wifi_fabric_call_authority_prepare(
            &user->call_authority, fabric_cookie)) {
        return 0;
    }
    user->durable_outer_permit_authority = 1u;
    return 1;
}

int ninlil_wifi_fabric_packet_link_authority_activate(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    return user != NULL
        && user->provider_magic == NINLIL_WIFI_FABRIC_PROVIDER_MAGIC
        && ninlil_wifi_fabric_call_authority_activate(
            &user->call_authority, fabric_cookie);
}

int ninlil_wifi_fabric_packet_link_authority_drain(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    return user != NULL
        && user->provider_magic == NINLIL_WIFI_FABRIC_PROVIDER_MAGIC
        && ninlil_wifi_fabric_call_authority_drain(
            &user->call_authority, fabric_cookie);
}

int ninlil_wifi_fabric_packet_link_authority_unbind(
    ninlil_wifi_fabric_link_user_t *user,
    const void *fabric_cookie)
{
    if (user == NULL
        || user->provider_magic != NINLIL_WIFI_FABRIC_PROVIDER_MAGIC
        || !ninlil_wifi_fabric_call_authority_unbind(
            &user->call_authority, fabric_cookie)) {
        return 0;
    }
    user->durable_outer_permit_authority = 0u;
    return 1;
}

#endif /* private Fabric or POSIX TLS public owner */
