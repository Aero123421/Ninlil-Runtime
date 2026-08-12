/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Production-path FRAG L1 orchestrator: real N6 + R7 AEAD + R2 issue + R1 edge
 * + issued FIFO ledger (cap 2) + §15.3.8 cleanup.
 */

#include "r7_frag_prod_orch.h"

#include "airtime_calculator.h"
#include "r7_crypto_provider.h"
#include "r7_frag.h"
#include "r7_frag_checked_issue.h"
#include "r7_frag_internal.h"
#include "r7_frag_issue_coordinator.h"
#include "r7_frag_profile.h"
#include "r7_r2_authority_clock.h"
#include "r7_wire_codec.h"

#include <string.h>

static int32_t refresh_r2_time_from_pcp(ninlil_r7_frag_prod_bind_t *bind);
static uint64_t bind_authority_token(const ninlil_r7_frag_prod_bind_t *bind);
static void held_tx_clear(ninlil_r7_frag_prod_bind_t *bind);
static void r5_release_seq(ninlil_r7_frag_prod_bind_t *bind, uint64_t seq);
static void time_owner_revoke(ninlil_r7_frag_prod_bind_t *bind);

static void spy(ninlil_r7_frag_prod_bind_t *b, uint8_t ev)
{
    if (b != NULL && b->spy != NULL) {
        ninlil_r7_frag_spy_push(b->spy, ev);
    }
}

static ninlil_r7_r5_issue_registry_t *bind_issue_registry(
    ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL) {
        return NULL;
    }
    return bind->issue_registry != NULL ? bind->issue_registry
                                        : &bind->issue_registry_owned;
}

/* Real SHA-256 only; NULL provider / NULL sha256 / backend fail ⇒ nonzero. */
static int digest_frame(
    const ninlil_r7_crypto_provider *crypto,
    const uint8_t *frame,
    size_t frame_len,
    uint8_t out32[32])
{
    if (crypto == NULL || crypto->sha256 == NULL || frame == NULL
        || out32 == NULL) {
        return 1;
    }
    return ninlil_r7_crypto_sha256(crypto, frame, frame_len, out32)
            == NINLIL_R7_CRYPTO_OK
        ? 0
        : 1;
}

void ninlil_r7_frag_prod_bind_reset(ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL) {
        return;
    }
    /*
     * P0: never read bind fields before wipe. Uninitialized stack objects are
     * a supported entry (tests/API), and reading matrix_ws (or any field) is C
     * UB / MSan trap. Revoke process-private time owner by bind pointer only
     * (table keyed by address; no field reads), then unconditional memset.
     */
    time_owner_revoke(bind);
    memset(bind, 0, sizeof(*bind));
    bind->bind_magic = NINLIL_R7_FRAG_PROD_BIND_MAGIC;
    bind->bind_version = NINLIL_R7_FRAG_PROD_BIND_VERSION;
    /* matrix_ws remains NULL from memset. */
}

int ninlil_r7_frag_prod_bind_is_inited(const ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL) {
        return 0;
    }
    return bind->bind_magic == NINLIL_R7_FRAG_PROD_BIND_MAGIC
        && bind->bind_version == NINLIL_R7_FRAG_PROD_BIND_VERSION;
}

int32_t ninlil_r7_frag_prod_bind_set_matrix_ws(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_matrix_ws_t *ws)
{
    if (bind == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (!ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    bind->matrix_ws = ws;
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_bind_reinit(ninlil_r7_frag_prod_bind_t *bind)
{
    ninlil_r7_frag_prod_matrix_ws_t *ws;
    size_t i;
    int need_drain = 0;

    if (bind == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    /* Refuse garbage: magic/version must prove prior reset/reinit. */
    if (!ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    /*
     * Restart/reinit: drain issued/ambiguous Permits before wiping volatile
     * state (docs/30 §15.3.3 / §15.3.8). Never local-discard issued.
     */
    for (i = 0u; i < NINLIL_R7_FRAG_L1_ISSUED_CAP; i++) {
        if (bind->ledger[i].live != 0u
            && (bind->ledger[i].permit_sequence != 0u
                || bind->ledger[i].cleanup_class
                    == NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN
                || bind->ledger[i].cleanup_class
                    == NINLIL_R7_FRAG_CLN_ISSUED_DRAIN)) {
            need_drain = 1;
            break;
        }
    }
    if (need_drain != 0 || bind->held_tx_live != 0u) {
        if (ninlil_r7_frag_prod_cleanup(
                bind, NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN, 0u)
            != NINLIL_R7_FRAG_PROD_OK) {
            return NINLIL_R7_FRAG_PROD_CLEANUP;
        }
    }
    {
        uint64_t auth = bind_authority_token(bind);
        if (auth != 0u) {
            ninlil_r7_frag_issue_coordinator_complete_all_authority(
                &bind->issue_coordinator, auth);
        }
    }
    held_tx_clear(bind);
    if (bind->ack_ledger != NULL) {
        ninlil_r7_frag_ack_ledger_discard_all(bind->ack_ledger);
    }
    /* Restart drops owner-held time authority; re-mint required. */
    time_owner_revoke(bind);
    /* Safe: only after init stamp validated. */
    ws = bind->matrix_ws;
    memset(bind, 0, sizeof(*bind));
    bind->bind_magic = NINLIL_R7_FRAG_PROD_BIND_MAGIC;
    bind->bind_version = NINLIL_R7_FRAG_PROD_BIND_VERSION;
    bind->matrix_ws = ws;
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_set_live(
    ninlil_r7_frag_prod_bind_t *bind,
    const ninlil_pcp_live_profile_t *live)
{
    if (bind == NULL || live == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    bind->live = *live;
    bind->live_valid = 1u;
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_ledger_free_slots(
    const ninlil_r7_frag_prod_bind_t *bind,
    size_t *out_free)
{
    size_t i;
    size_t free_n = 0u;
    if (bind == NULL || out_free == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_L1_ISSUED_CAP; i++) {
        if (bind->ledger[i].live == 0u) {
            free_n++;
        }
    }
    *out_free = free_n;
    return NINLIL_R7_FRAG_PROD_OK;
}

static int32_t ledger_admit(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner,
    uint64_t cand,
    const uint8_t *outer,
    size_t outer_len,
    size_t *out_slot)
{
    size_t i;
    if (bind->ledger_count >= NINLIL_R7_FRAG_L1_ISSUED_CAP) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_L1_ISSUED_CAP; i++) {
        if (bind->ledger[i].live == 0u) {
            ninlil_r7_frag_prod_ledger_slot_t *s = &bind->ledger[i];
            memset(s, 0, sizeof(*s));
            s->live = 1u;
            s->owner_token = owner;
            s->candidate_token = cand;
            s->outer_len = outer_len;
            if (outer_len > sizeof(s->outer)) {
                return NINLIL_R7_FRAG_PROD_INVALID;
            }
            memcpy(s->outer, outer, outer_len);
            bind->ledger_count++;
            *out_slot = i;
            return NINLIL_R7_FRAG_PROD_OK;
        }
    }
    return NINLIL_R7_FRAG_PROD_ADMISSION;
}

static void ledger_release_slot(
    ninlil_r7_frag_prod_bind_t *bind, size_t slot, uint8_t cln)
{
    if (slot >= NINLIL_R7_FRAG_L1_ISSUED_CAP || bind->ledger[slot].live == 0u) {
        return;
    }
    bind->ledger[slot].cleanup_class = cln;
    bind->ledger[slot].live = 0u;
    if (bind->ledger_count > 0u) {
        bind->ledger_count--;
    }
}

/*
 * Bind-embedded time owner (docs/30 §11.2.3) — CONTRACT v3.
 * Must match NINLIL_R7_FRAG_TIME_AUTHORITY_CONTRACT in the header.
 *
 * No process-global pointer-derived secret table (non-thread-safe).
 * Private fields + fixed-key MAC live on the bind; public fields observation.
 * Stamps only via ninlil_r2_private_sample_authority_clock.
 */
#if NINLIL_R7_FRAG_TIME_AUTHORITY_CONTRACT != 3
#error "r7_frag_prod_orch time authority contract mismatch (header vs source)"
#endif

/* Fixed process keys (not pointer-derived; read-only; concurrent-safe). */
static const uint64_t k_time_mac0 = 0xA5A5C3C3D1B54A32ull;
static const uint64_t k_time_mac1 = 0x9E3779B97F4A7C15ull;

static uint64_t load_u64_le(const uint8_t b[8])
{
    return (uint64_t)b[0] | ((uint64_t)b[1] << 8) | ((uint64_t)b[2] << 16)
        | ((uint64_t)b[3] << 24) | ((uint64_t)b[4] << 32)
        | ((uint64_t)b[5] << 40) | ((uint64_t)b[6] << 48)
        | ((uint64_t)b[7] << 56);
}

static void store_u64_le(uint8_t b[8], uint64_t v)
{
    size_t i;
    for (i = 0u; i < 8u; i++) {
        b[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static void epoch_from_lo(uint8_t out16[16], uint64_t lo)
{
    memset(out16, 0, 16u);
    store_u64_le(out16, lo);
}

static uint32_t time_priv_mac_compute(const ninlil_r7_frag_prod_bind_t *bind)
{
    uint64_t x;
    size_t i;
    x = k_time_mac0 ^ k_time_mac1;
    x ^= ((uint64_t)bind->time_priv_gen << 1) | 1u;
    x ^= bind->time_priv_now_ms;
    x ^= bind->time_priv_wm_now_ms * 0x9E37u;
    x ^= ((uint64_t)bind->time_priv_wm_valid << 40);
    x ^= ((uint64_t)bind->time_priv_trusted << 41);
    x ^= ((uint64_t)bind->time_priv_uncertain << 42);
    x ^= ((uint64_t)bind->time_priv_rollback << 43);
    x ^= ((uint64_t)bind->time_priv_future << 44);
    x ^= ((uint64_t)bind->time_priv_from_r2 << 45);
    x ^= (uint64_t)(uintptr_t)bind->time_priv_pcp;
    for (i = 0u; i < 16u; i++) {
        x ^= ((uint64_t)bind->time_priv_epoch[i] << ((i & 7u) * 8u));
        x ^= ((uint64_t)bind->time_priv_wm_epoch[i] << (((i + 3u) & 7u) * 8u));
    }
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdull;
    x ^= x >> 33;
    return (uint32_t)x;
}

static void time_owner_revoke(ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL) {
        return;
    }
    /* Clear private owner only (bind_reset also memsets whole object). */
    bind->time_priv_live = 0u;
    bind->time_priv_gen = 0u;
    bind->time_priv_mac = 0u;
    bind->time_priv_pcp = NULL;
    bind->time_priv_wm_valid = 0u;
    bind->time_priv_now_ms = 0u;
    bind->time_priv_wm_now_ms = 0u;
    bind->time_priv_trusted = 0u;
    bind->time_priv_uncertain = 0u;
    bind->time_priv_rollback = 0u;
    bind->time_priv_future = 0u;
    bind->time_priv_from_r2 = 0u;
    memset(bind->time_priv_epoch, 0, 16u);
    memset(bind->time_priv_wm_epoch, 0, 16u);
    bind->time_owner_gen = 0u;
    bind->time_seal = 0u;
}

static int time_authority_valid(const ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL || bind->time_priv_live == 0u || bind->time_priv_gen == 0u
        || bind->time_priv_pcp == NULL || bind->pcp == NULL) {
        return 0;
    }
    if (bind->time_priv_pcp != bind->pcp) {
        return 0;
    }
    /* Public time_owner_gen is observation only — not part of authority. */
    if (bind->time_priv_mac != time_priv_mac_compute(bind)) {
        return 0;
    }
    return 1;
}

static void time_owner_mirror_public(ninlil_r7_frag_prod_bind_t *bind)
{
    bind->time_owner_gen = bind->time_priv_gen;
    bind->time_seal = bind->time_priv_mac;
    bind->time_clock_pcp = bind->time_priv_pcp;
    bind->trusted_now_ms = bind->time_priv_now_ms;
    bind->r2_now_ms = bind->time_priv_now_ms;
    bind->r2_now_valid =
        (bind->time_priv_from_r2 != 0u && bind->time_priv_trusted != 0u) ? 1u
                                                                        : 0u;
    bind->clock_trusted = bind->time_priv_trusted;
    bind->clock_uncertain = bind->time_priv_uncertain;
    bind->clock_rollback = bind->time_priv_rollback;
    bind->clock_future_vs_expiry = bind->time_priv_future;
    bind->time_from_r2 = bind->time_priv_from_r2;
    bind->watermark_valid = bind->time_priv_wm_valid;
    bind->watermark_now_ms = bind->time_priv_wm_now_ms;
    memcpy(bind->clock_epoch_id, bind->time_priv_epoch, 16u);
    memcpy(bind->watermark_epoch_id, bind->time_priv_wm_epoch, 16u);
    bind->epoch_id_lo = load_u64_le(bind->time_priv_epoch);
}

static void time_owner_commit(ninlil_r7_frag_prod_bind_t *bind)
{
    bind->time_priv_live = 1u;
    bind->time_priv_mac = time_priv_mac_compute(bind);
    time_owner_mirror_public(bind);
}

static void time_fill_request(
    const ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r2_authority_clock_request_t *req)
{
    memset(req, 0, sizeof(*req));
    if (bind->time_priv_live != 0u && bind->time_priv_wm_valid != 0u) {
        req->watermark_valid = 1u;
        memcpy(req->watermark_epoch_id, bind->time_priv_wm_epoch, 16u);
        req->watermark_now_ms = bind->time_priv_wm_now_ms;
        memcpy(req->expected_epoch_id, bind->time_priv_epoch, 16u);
    } else if (bind->expected_epoch_lo != 0u) {
        epoch_from_lo(req->expected_epoch_id, bind->expected_epoch_lo);
    } else if (bind->epoch_id_lo != 0u) {
        epoch_from_lo(req->expected_epoch_id, bind->epoch_id_lo);
    }
}

static int32_t clock_gate(ninlil_r7_frag_prod_bind_t *bind)
{
    if (!time_authority_valid(bind)) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    time_owner_mirror_public(bind);
    if (bind->time_priv_trusted == 0u || bind->time_priv_uncertain != 0u) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (bind->time_priv_rollback != 0u || bind->time_priv_future != 0u) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (bind->expected_epoch_lo != 0u
        && load_u64_le(bind->time_priv_epoch) != bind->expected_epoch_lo) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

int ninlil_r7_frag_prod_time_authority_valid(
    const ninlil_r7_frag_prod_bind_t *bind)
{
    return time_authority_valid(bind);
}

uint8_t ninlil_r7_frag_prod_time_last_typed_class(
    const ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL) {
        return 0u;
    }
    return bind->last_sample_typed_class;
}

/*
 * Accept class D or bootstrap class A repair into private owner.
 * Never accepts TEMP/FAULT/B/C as stampable trusted.
 */
static int32_t time_apply_sample_result(
    ninlil_r7_frag_prod_bind_t *bind,
    const ninlil_r2_authority_clock_result_t *sr,
    uint32_t *inout_gen,
    int allow_class_a_repair)
{
    bind->last_sample_typed_class = sr->typed_class;
    bind->last_sample_meta_mutation = sr->durable_meta_mutation;
    bind->last_sample_txn_provenance = sr->txn_provenance;

    if (sr->typed_class == NINLIL_R2_SAMPLE_TEMP_UNCERTAIN) {
        bind->time_priv_uncertain = 1u;
        bind->time_priv_trusted = 0u;
        bind->time_priv_from_r2 = 0u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (sr->typed_class == NINLIL_R2_SAMPLE_CLOCK_FAULT) {
        bind->time_priv_rollback = 1u;
        bind->time_priv_trusted = 0u;
        bind->time_priv_from_r2 = 0u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (sr->typed_class == NINLIL_R2_SAMPLE_COMMIT_UNKNOWN) {
        bind->time_priv_uncertain = 1u;
        bind->time_priv_trusted = 0u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (sr->typed_class == NINLIL_R2_SAMPLE_AUTHORITY_DIVERGENCE
        || sr->typed_class == NINLIL_R2_SAMPLE_EPOCH_TRANSITION_REQUIRED
        || sr->typed_class == NINLIL_R2_SAMPLE_META_UNPUBLISHED
        || sr->typed_class == NINLIL_R2_SAMPLE_TRUST_MIRROR_INVALID
        || sr->typed_class == NINLIL_R2_SAMPLE_UNBOUND
        || sr->typed_class == NINLIL_R2_SAMPLE_BUSY
        || sr->typed_class == NINLIL_R2_SAMPLE_REENTRY
        || sr->typed_class == NINLIL_R2_SAMPLE_CORRUPT
        || sr->typed_class == NINLIL_R2_SAMPLE_STORAGE_IO
        || sr->typed_class == NINLIL_R2_SAMPLE_SHUTDOWN) {
        bind->time_priv_trusted = 0u;
        bind->time_priv_from_r2 = 0u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }

    if (sr->sample_fields_valid == 0u) {
        bind->time_priv_trusted = 0u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }

    if (sr->typed_class == NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH
        || (allow_class_a_repair != 0
            && sr->typed_class == NINLIL_R2_SAMPLE_W1_REPAIR)) {
        /* Install / advance L1 watermark from accepted sample (16B epoch). */
        memcpy(bind->time_priv_epoch, sr->sample_epoch_id, 16u);
        memcpy(bind->time_priv_wm_epoch, sr->sample_epoch_id, 16u);
        bind->time_priv_wm_valid = 1u;
        bind->time_priv_wm_now_ms = sr->sample_now_ms;
        bind->time_priv_now_ms = sr->sample_now_ms;
        bind->time_priv_trusted = 1u;
        bind->time_priv_uncertain = 0u;
        bind->time_priv_rollback = 0u;
        bind->time_priv_future = 0u;
        bind->time_priv_from_r2 = 1u;
        if (inout_gen != NULL && *inout_gen == 0u) {
            *inout_gen = 1u;
        }
        if (inout_gen != NULL) {
            bind->time_priv_gen = *inout_gen;
        }
        bind->time_priv_pcp = bind->pcp;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_OK;
    }

    bind->time_priv_trusted = 0u;
    time_owner_commit(bind);
    return NINLIL_R7_FRAG_PROD_CLOCK;
}

int32_t ninlil_r7_frag_prod_time_authority_mint(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t *out_owner_gen)
{
    ninlil_r2_authority_clock_request_t req;
    ninlil_r2_authority_clock_result_t sr;
    uint32_t gen;
    int32_t st;

    if (bind == NULL || !ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (bind->pcp == NULL) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }

    /* New owner generation on this bind (local; no global counter). */
    gen = bind->time_priv_gen + 1u;
    if (gen == 0u) {
        gen = 1u;
    }
    bind->time_priv_pcp = bind->pcp;
    bind->time_priv_gen = gen;
    bind->time_priv_live = 1u;

    time_fill_request(bind, &req);
    memset(&sr, 0, sizeof(sr));
    (void)ninlil_r2_private_sample_authority_clock(bind->pcp, &req, &sr);
    st = time_apply_sample_result(bind, &sr, &gen, 1 /* allow class A repair */);
    if (out_owner_gen != NULL) {
        *out_owner_gen = bind->time_priv_gen;
    }
    return st;
}

int32_t ninlil_r7_frag_prod_time_authority_refresh(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen)
{
    ninlil_r2_authority_clock_request_t req;
    ninlil_r2_authority_clock_result_t sr;
    uint32_t gen;

    if (bind == NULL || !ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (owner_gen == 0u || !time_authority_valid(bind)
        || owner_gen != bind->time_priv_gen || bind->pcp == NULL
        || bind->time_priv_pcp != bind->pcp) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    gen = owner_gen;
    time_fill_request(bind, &req);
    memset(&sr, 0, sizeof(sr));
    (void)ninlil_r2_private_sample_authority_clock(bind->pcp, &req, &sr);
    /* Refresh requires class D (no A repair mid-flight). */
    return time_apply_sample_result(bind, &sr, &gen, 0);
}

int32_t ninlil_r7_frag_prod_time_apply_class_d(
    ninlil_r7_frag_prod_bind_t *bind,
    const ninlil_r7_class_d_sample_t *sample)
{
    if (bind == NULL || sample == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (!ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    /* Must already be owner-minted; cannot invent first authority from sample. */
    if (!time_authority_valid(bind)) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (sample->fence_clock != 0u || sample->trusted == 0u) {
        bind->time_priv_trusted = 0u;
        bind->time_priv_uncertain = 1u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (bind->time_priv_from_r2 != 0u
        && sample->now_ms < bind->time_priv_now_ms
        && (sample->epoch_id_lo == 0u
            || load_u64_le(bind->time_priv_epoch) == 0u
            || load_u64_le(bind->time_priv_epoch) == sample->epoch_id_lo)) {
        bind->time_priv_rollback = 1u;
        bind->time_priv_trusted = 0u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    /*
     * Advance watermark now only. MUST NOT rewrite 16B sample epoch from
     * epoch_id_lo truncation (would poison §11.2.3 floors vs full S/M).
     * Full epoch remains whatever sample_authority_clock installed.
     */
    if (sample->epoch_id_lo != 0u
        && load_u64_le(bind->time_priv_epoch) != 0u
        && sample->epoch_id_lo != load_u64_le(bind->time_priv_epoch)) {
        /* Same-epoch class-D path only; lo mismatch ⇒ reject. */
        bind->time_priv_trusted = 0u;
        time_owner_commit(bind);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    bind->time_priv_now_ms = sample->now_ms;
    bind->time_priv_wm_now_ms = sample->now_ms;
    bind->time_priv_wm_valid = 1u;
    bind->time_priv_trusted = 1u;
    bind->time_priv_uncertain = 0u;
    bind->time_priv_rollback = 0u;
    bind->time_priv_from_r2 = 1u;
    time_owner_commit(bind);
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_time_set_uncertain(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen,
    uint8_t uncertain)
{
    if (bind == NULL || !ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (owner_gen == 0u || !time_authority_valid(bind)
        || owner_gen != bind->time_priv_gen) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    bind->time_priv_uncertain = uncertain != 0u ? 1u : 0u;
    if (uncertain != 0u) {
        bind->time_priv_trusted = 0u;
    } else if (bind->time_priv_from_r2 != 0u) {
        bind->time_priv_trusted = 1u;
    }
    time_owner_commit(bind);
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_time_set_epoch_pin(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen,
    uint64_t epoch_id_lo,
    uint64_t expected_epoch_lo)
{
    if (bind == NULL || !ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (owner_gen == 0u || !time_authority_valid(bind)
        || owner_gen != bind->time_priv_gen) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    /*
     * Pin is gate observation only. Do NOT rewrite L1 watermark floors
     * (would poison subsequent §11.2.3 class-D samples).
     * Gate compares expected_epoch_lo against accepted private sample epoch.
     */
    bind->expected_epoch_lo = expected_epoch_lo;
    bind->epoch_id_lo = epoch_id_lo; /* observation */
    time_owner_commit(bind);
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_time_set_fault_flags(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t owner_gen,
    uint8_t clock_rollback,
    uint8_t clock_future_vs_expiry)
{
    if (bind == NULL || !ninlil_r7_frag_prod_bind_is_inited(bind)) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (owner_gen == 0u || !time_authority_valid(bind)
        || owner_gen != bind->time_priv_gen) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    bind->time_priv_rollback = clock_rollback != 0u ? 1u : 0u;
    bind->time_priv_future = clock_future_vs_expiry != 0u ? 1u : 0u;
    if (bind->time_priv_rollback != 0u || bind->time_priv_future != 0u) {
        bind->time_priv_trusted = 0u;
    } else if (bind->time_priv_from_r2 != 0u
        && bind->time_priv_uncertain == 0u) {
        bind->time_priv_trusted = 1u;
    }
    time_owner_commit(bind);
    return NINLIL_R7_FRAG_PROD_OK;
}

uint64_t ninlil_r7_frag_prod_time_now_ms(const ninlil_r7_frag_prod_bind_t *bind)
{
    if (!time_authority_valid(bind)) {
        return 0u;
    }
    return bind->time_priv_now_ms;
}

int ninlil_r7_frag_prod_time_is_trusted(const ninlil_r7_frag_prod_bind_t *bind)
{
    if (!time_authority_valid(bind)) {
        return 0;
    }
    return (bind->time_priv_trusted != 0u && bind->time_priv_uncertain == 0u
               && bind->time_priv_rollback == 0u
               && bind->time_priv_future == 0u)
        ? 1
        : 0;
}

int32_t ninlil_r7_frag_prod_cleanup(
    ninlil_r7_frag_prod_bind_t *bind,
    uint8_t cleanup_class,
    uint64_t permit_sequence)
{
    ninlil_pcp_error_t err;
    size_t i;
    if (bind == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    (void)permit_sequence;
    switch (cleanup_class) {
    case NINLIL_R7_FRAG_CLN_UNISSUED_DROP:
    case NINLIL_R7_FRAG_CLN_CLOCK_DROP:
    case NINLIL_R7_FRAG_CLN_EPOCH_DROP:
        /* Local release only; no R2 call. Drop matching ledger pre-issue. */
        for (i = 0u; i < NINLIL_R7_FRAG_L1_ISSUED_CAP; i++) {
            if (bind->ledger[i].live != 0u
                && bind->ledger[i].permit_sequence == 0u) {
                ledger_release_slot(bind, i, cleanup_class);
            }
        }
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_OWNER_TERMINAL, 1u, 1u,
            cleanup_class, 0u);
        return NINLIL_R7_FRAG_PROD_OK;
    case NINLIL_R7_FRAG_CLN_ISSUED_DRAIN:
    case NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN:
        if (bind->pcp == NULL) {
            return NINLIL_R7_FRAG_PROD_UNBOUND;
        }
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_DRAIN_QUARANTINE, 1u, 1u,
            cleanup_class, 0u);
        /* Drain: revoke outstanding first (clockless under fence). */
        if (ninlil_pcp_revoke_all_outstanding(bind->pcp, &err) != NINLIL_PCP_OK) {
            /* recover_storage path if revoke fails under storage ambiguity */
            if (ninlil_pcp_recover_storage(bind->pcp, &err) != NINLIL_PCP_OK) {
                return NINLIL_R7_FRAG_PROD_CLEANUP;
            }
            if (ninlil_pcp_revoke_all_outstanding(bind->pcp, &err)
                != NINLIL_PCP_OK) {
                return NINLIL_R7_FRAG_PROD_CLEANUP;
            }
        }
        /*
         * Converge EVERY coordinator/R5/ledger row for this authority —
         * never only the single permit_sequence argument.
         */
        {
            uint64_t auth = bind_authority_token(bind);
            if (auth != 0u) {
                ninlil_r7_frag_issue_coordinator_complete_all_authority(
                    &bind->issue_coordinator, auth);
            }
            ninlil_r7_r5_issue_registry_clear(bind_issue_registry(bind));
        }
        held_tx_clear(bind);
        for (i = 0u; i < NINLIL_R7_FRAG_L1_ISSUED_CAP; i++) {
            if (bind->ledger[i].live != 0u) {
                if (bind->ledger[i].permit_sequence != 0u) {
                    r5_release_seq(bind, bind->ledger[i].permit_sequence);
                }
                ledger_release_slot(bind, i, cleanup_class);
            }
        }
        /* Phase/budget: clear FRAG_ACK CU seal identity on authority drain. */
        bind->frag_ack_cu_live = 0u;
        bind->frag_ack_sealed_live = 0u;
        bind->frag_ack_sealed_len = 0u;
        memset(bind->frag_ack_cu_key16, 0, sizeof(bind->frag_ack_cu_key16));
        memset(bind->frag_ack_cu_iv12, 0, sizeof(bind->frag_ack_cu_iv12));
        memset(&bind->frag_ack_cu_body, 0, sizeof(bind->frag_ack_cu_body));
        memset(bind->frag_ack_sealed, 0, sizeof(bind->frag_ack_sealed));
        /* TERMINAL_PENDING may commit after drain_ok. */
        if (bind->terminal_pending != 0u) {
            bind->terminal_pending = 0u;
        }
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_OWNER_TERMINAL, 1u, 1u,
            cleanup_class, 1u);
        return NINLIL_R7_FRAG_PROD_OK;
    case NINLIL_R7_FRAG_CLN_EDGE_STALE:
    case NINLIL_R7_FRAG_CLN_OK_COMPLETE:
        for (i = 0u; i < NINLIL_R7_FRAG_L1_ISSUED_CAP; i++) {
            if (bind->ledger[i].live != 0u
                && (permit_sequence == 0u
                    || bind->ledger[i].permit_sequence == permit_sequence)) {
                if (cleanup_class == NINLIL_R7_FRAG_CLN_OK_COMPLETE) {
                    bind->last_completed_seq =
                        bind->ledger[i].permit_sequence;
                }
                /* Free R5 registry row so later issues are not CAPACITY-starved. */
                ninlil_r7_r5_issue_registry_release(
                    bind_issue_registry(bind),
                    bind->ledger[i].permit_sequence);
                ledger_release_slot(bind, i, cleanup_class);
            }
        }
        return NINLIL_R7_FRAG_PROD_OK;
    default:
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
}

static int32_t fill_issue_from_live(
    ninlil_r7_frag_prod_bind_t *bind,
    const uint8_t *outer,
    size_t outer_len,
    ninlil_pcp_issue_request_t *req)
{
    ninlil_airtime_lora_input_t airtime_input;
    ninlil_airtime_result_t airtime_result;
    const ninlil_pcp_live_profile_t *live;
    if (!bind->live_valid || outer == NULL || outer_len == 0u
        || outer_len > UINT8_MAX) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    live = &bind->live;
    if (live->phy.coding_rate_denom < 5u
        || live->phy.coding_rate_denom > 8u) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    memset(&airtime_input, 0, sizeof(airtime_input));
    airtime_input.sf = live->phy.spreading_factor;
    airtime_input.cr = (uint8_t)(live->phy.coding_rate_denom - 4u);
    airtime_input.header_implicit = NINLIL_AIRTIME_HEADER_EXPLICIT;
    airtime_input.crc_on = NINLIL_AIRTIME_CRC_ON;
    airtime_input.ldro = NINLIL_AIRTIME_LDRO_AUTO;
    airtime_input.payload_len_bytes = (uint8_t)outer_len;
    airtime_input.preamble_len_symbols = live->phy.preamble_symbols;
    airtime_input.bw_hz = live->phy.bandwidth_hz;
    memset(&airtime_result, 0, sizeof(airtime_result));
    if (ninlil_airtime_lora_us(&airtime_input, &airtime_result)
            != NINLIL_AIRTIME_OK
        || airtime_result.airtime_us == 0u
        || airtime_result.airtime_us > live->max_airtime_us) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    memset(req, 0, sizeof(*req));
    req->hardware_profile_id = live->hardware_profile_id;
    req->hardware_profile_rev = live->hardware_profile_rev;
    req->regulatory_profile_id = live->regulatory_profile_id;
    req->regulatory_profile_rev = live->regulatory_profile_rev;
    req->site_assignment_id = live->site_assignment_id;
    req->site_assignment_rev = live->site_assignment_rev;
    req->site_assignment_epoch = live->site_assignment_epoch;
    req->transmitter_id = live->transmitter_id;
    req->channel_id = live->channel_id;
    req->phy = live->phy;
    req->max_airtime_us = airtime_result.airtime_us;
    req->frame_byte_length = (uint32_t)outer_len;
    req->frame_digest_algorithm = 1u;
    /*
     * Issue times are R2 class-D sample authority (docs/30 §15.3.1).
     * L1 must not inject not_before/expiry as S — leave open owner deadline
     * (validation_cb: expiry=min(owner_deadline, S.now+60000)).
     */
    req->not_before_ms = 0u;
    req->expiry_ms = UINT64_MAX;
    if (digest_frame(bind->crypto, outer, outer_len, req->frame_digest) != 0) {
        /* No fake digest: unbound crypto / SHA-256 fail ⇒ no R2 issue. */
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

static uint64_t bind_authority_token(const ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL || bind->pcp == NULL) {
        return 0u;
    }
    return (uint64_t)(uintptr_t)bind->pcp;
}

static void held_tx_clear(ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL) {
        return;
    }
    bind->held_tx_live = 0u;
    bind->held_tx_queued = 0u;
    bind->held_tx_slot = 0u;
    bind->held_authority_token = 0u;
    bind->held_permit_sequence = 0u;
    bind->held_outer_len = 0u;
    memset(bind->held_outer_digest, 0, sizeof(bind->held_outer_digest));
    memset(bind->held_outer, 0, sizeof(bind->held_outer));
    memset(&bind->held_permit, 0, sizeof(bind->held_permit));
}

static void held_tx_store(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t auth,
    uint64_t seq,
    size_t slot,
    uint8_t queued,
    const uint8_t outer_digest[32],
    const uint8_t *outer,
    size_t outer_len,
    const ninlil_radio_hal_permit_snapshot_t *permit)
{
    held_tx_clear(bind);
    bind->held_tx_live = 1u;
    bind->held_tx_queued = queued;
    bind->held_tx_slot = slot;
    bind->held_authority_token = auth;
    bind->held_permit_sequence = seq;
    bind->held_outer_len = (uint32_t)outer_len;
    memcpy(bind->held_outer_digest, outer_digest, 32u);
    if (outer != NULL && outer_len > 0u && outer_len <= sizeof(bind->held_outer)) {
        memcpy(bind->held_outer, outer, outer_len);
    }
    if (permit != NULL) {
        bind->held_permit = *permit;
    }
}

static void r5_release_seq(ninlil_r7_frag_prod_bind_t *bind, uint64_t seq)
{
    if (bind == NULL || seq == 0u) {
        return;
    }
    ninlil_r7_r5_issue_registry_release(bind_issue_registry(bind), seq);
}

/* Coordinator complete + R5 release + L1 cleanup (same identity). */
static int32_t coord_finish(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t auth,
    uint64_t seq,
    uint8_t cln)
{
    (void)ninlil_r7_frag_issue_coordinator_complete(
        &bind->issue_coordinator, auth, seq, NULL);
    r5_release_seq(bind, seq);
    held_tx_clear(bind);
    return ninlil_r7_frag_prod_cleanup(bind, cln, seq);
}

static int32_t r1_tx_with_permit(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    size_t slot,
    uint64_t auth,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const uint8_t outer_digest[32],
    ninlil_r7_frag_prod_tx_result_t *out)
{
    ninlil_radio_hal_frame_view_t view;
    ninlil_radio_hal_error_t herr;
    ninlil_radio_hal_status_t hst;
    int32_t cst;

    out->permit_sequence = permit->permit_sequence;
    if (slot < NINLIL_R7_FRAG_L1_ISSUED_CAP) {
        bind->ledger[slot].permit_sequence = permit->permit_sequence;
    }

    cst = ninlil_r7_frag_issue_coordinator_begin_tx(
        &bind->issue_coordinator, auth, permit->permit_sequence);
    if (cst != NINLIL_R7_COORD_OK) {
        /* Not head / busy: keep identity held, do not re-issue. */
        held_tx_store(
            bind, auth, permit->permit_sequence, slot, 1u, outer_digest,
            out->outer, out->outer_len, permit);
        out->issue_l1_class = NINLIL_R7_L1_FIFO_OUT_OF_ORDER;
        out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_HELD;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }

    memset(&view, 0, sizeof(view));
    view.bytes = out->outer;
    view.length = (uint32_t)out->outer_len;
    memset(&herr, 0, sizeof(herr));
    spy(bind, NINLIL_R7_FRAG_SPY_R1_TX);
    hst = ninlil_radio_hal_transmit_with_permit(
        bind->hal, permit, &view, &herr);
    out->r1_status = hst;
    out->r1_stage = herr.stage;
    out->r1_reason = herr.reason;
    out->consume_invoked = 1u;
    if (slot < NINLIL_R7_FRAG_L1_ISSUED_CAP) {
        bind->ledger[slot].consume_invoked = 1u;
    }

    if (hst == NINLIL_RADIO_HAL_OK) {
        out->edge_invoked = 1u;
        if (slot < NINLIL_R7_FRAG_L1_ISSUED_CAP) {
            bind->ledger[slot].edge_invoked = 1u;
        }
        out->cleanup_class = NINLIL_R7_FRAG_CLN_OK_COMPLETE;
        (void)coord_finish(
            bind, auth, permit->permit_sequence, NINLIL_R7_FRAG_CLN_OK_COMPLETE);
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
            candidate_token, 0u, 0u);
        return NINLIL_R7_FRAG_PROD_OK;
    }

    /*
     * Closed R1 mappings (docs/30 §15.3):
     *   NOT_BEFORE (status 11 / reason 16) — pre-consume; hold same Permit+outer
     *   EXPIRED (12 / 17) — pre-consume terminal; drain, never retain
     *   SEQ_EXHAUSTED (16) / SEQ_REUSE — terminal drain
     *   BUSY — hold same identity for retry
     *   CONSUME_DENIED / FENCED — ambiguous drain
     *   EDGE_ERROR — edge-stale complete
     */
    if (hst == NINLIL_RADIO_HAL_NOT_BEFORE
        || herr.reason == NINLIL_RADIO_HAL_REASON_NOT_BEFORE) {
        if (ninlil_r7_frag_issue_coordinator_hold_retry(
                &bind->issue_coordinator, auth, permit->permit_sequence)
            != NINLIL_R7_COORD_OK) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_DRAIN;
            (void)coord_finish(
                bind, auth, permit->permit_sequence,
                NINLIL_R7_FRAG_CLN_ISSUED_DRAIN);
        } else {
            held_tx_store(
                bind, auth, permit->permit_sequence, slot, 0u, outer_digest,
                out->outer, out->outer_len, permit);
            out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_HELD;
        }
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
            candidate_token, (uint8_t)hst, 0u);
        return NINLIL_R7_FRAG_PROD_R1;
    }
    if (hst == NINLIL_RADIO_HAL_BUSY
        || herr.reason == NINLIL_RADIO_HAL_REASON_REENTRANT) {
        if (ninlil_r7_frag_issue_coordinator_hold_retry(
                &bind->issue_coordinator, auth, permit->permit_sequence)
            == NINLIL_R7_COORD_OK) {
            held_tx_store(
                bind, auth, permit->permit_sequence, slot, 0u, outer_digest,
                out->outer, out->outer_len, permit);
            out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_HELD;
        } else {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_DRAIN;
            (void)coord_finish(
                bind, auth, permit->permit_sequence,
                NINLIL_R7_FRAG_CLN_ISSUED_DRAIN);
        }
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
            candidate_token, (uint8_t)hst, 0u);
        return NINLIL_R7_FRAG_PROD_R1;
    }
    if (hst == NINLIL_RADIO_HAL_EXPIRED
        || herr.reason == NINLIL_RADIO_HAL_REASON_EXPIRED
        || hst == NINLIL_RADIO_HAL_SEQ_EXHAUSTED
        || herr.reason == NINLIL_RADIO_HAL_REASON_SEQ_EXHAUSTED
        || hst == NINLIL_RADIO_HAL_SEQ_REUSE) {
        /* Terminal: never retain EXPIRED / exhausted identity for re-TX. */
        out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_DRAIN;
        (void)coord_finish(
            bind, auth, permit->permit_sequence, NINLIL_R7_FRAG_CLN_ISSUED_DRAIN);
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
            candidate_token, (uint8_t)hst, 0u);
        return NINLIL_R7_FRAG_PROD_R1;
    }

    if (hst == NINLIL_RADIO_HAL_EDGE_ERROR) {
        out->edge_invoked = 1u;
        if (slot < NINLIL_R7_FRAG_L1_ISSUED_CAP) {
            bind->ledger[slot].edge_invoked = 1u;
        }
        out->cleanup_class = NINLIL_R7_FRAG_CLN_EDGE_STALE;
        (void)coord_finish(
            bind, auth, permit->permit_sequence, NINLIL_R7_FRAG_CLN_EDGE_STALE);
    } else if (hst == NINLIL_RADIO_HAL_CONSUME_DENIED
        || hst == NINLIL_RADIO_HAL_CONSUME_FENCED
        || herr.reason == NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED
        || herr.reason == NINLIL_RADIO_HAL_REASON_CONSUME_FENCED) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN;
        (void)coord_finish(
            bind, auth, permit->permit_sequence,
            NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN);
    } else {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_DRAIN;
        (void)coord_finish(
            bind, auth, permit->permit_sequence, NINLIL_R7_FRAG_CLN_ISSUED_DRAIN);
    }
    (void)ninlil_r7_frag_l1w1_emit(
        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT, owner_token,
        candidate_token, (uint8_t)hst, 0u);
    return NINLIL_R7_FRAG_PROD_R1;
}

static int32_t issue_and_tx(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    ninlil_r7_frag_prod_tx_result_t *out)
{
    ninlil_pcp_issue_request_t req;
    ninlil_radio_hal_permit_snapshot_t permit;
    ninlil_pcp_status_t pst;
    ninlil_radio_hal_live_binding_t hlive;
    ninlil_r7_coord_admit_t admit;
    uint8_t outer_digest[32];
    uint64_t auth;
    size_t slot = 0u;
    int32_t st;
    int32_t cst;

    if (bind == NULL || out == NULL || out->outer_len == 0u
        || out->outer_len > 255u) {
        if (out != NULL) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        }
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    auth = bind_authority_token(bind);
    if (auth == 0u) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    if (digest_frame(bind->crypto, out->outer, out->outer_len, outer_digest)
        != 0) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }

    /*
     * Exact-object resume: same outer digest + held/queued issued Permit.
     * Never re-issue; never rebuild identity.
     */
    if (bind->held_tx_live != 0u
        && bind->held_authority_token == auth
        && bind->held_outer_len == (uint32_t)out->outer_len
        && memcmp(bind->held_outer_digest, outer_digest, 32u) == 0
        && ninlil_r7_frag_issue_coordinator_outer_matches(
            &bind->issue_coordinator, auth, bind->held_permit_sequence,
            outer_digest,
            (uint32_t)out->outer_len)) {
        /* Restore sealed outer bytes if caller re-presented prepared path. */
        if (out->outer_len == bind->held_outer_len
            && bind->held_outer_len > 0u) {
            memcpy(out->outer, bind->held_outer, bind->held_outer_len);
            out->outer_len = bind->held_outer_len;
        }
        out->permit_sequence = bind->held_permit_sequence;
        out->ledger_admitted = 1u;
        slot = bind->held_tx_slot;
        if (bind->held_tx_queued != 0u
            && !ninlil_r7_frag_issue_coordinator_is_head(
                &bind->issue_coordinator, auth,
                bind->held_permit_sequence)) {
            out->issue_l1_class = NINLIL_R7_L1_FIFO_OUT_OF_ORDER;
            out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_HELD;
            return NINLIL_R7_FRAG_PROD_ADMISSION;
        }
        /* HELD → resume_tx; HEAD queued → begin_tx via same helper. */
        if (ninlil_r7_frag_issue_coordinator_slot_state(
                &bind->issue_coordinator, auth,
                bind->held_permit_sequence)
            == NINLIL_R7_COORD_ST_HELD) {
            cst = ninlil_r7_frag_issue_coordinator_resume_tx(
                &bind->issue_coordinator, auth,
                bind->held_permit_sequence);
            if (cst != NINLIL_R7_COORD_OK) {
                out->issue_l1_class = NINLIL_R7_L1_FIFO_OUT_OF_ORDER;
                out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_HELD;
                return NINLIL_R7_FRAG_PROD_ADMISSION;
            }
            /* resume_tx already set IN_TX; transmit path must not begin_tx. */
            {
                ninlil_radio_hal_frame_view_t view;
                ninlil_radio_hal_error_t herr;
                ninlil_radio_hal_status_t hst;
                memset(&view, 0, sizeof(view));
                view.bytes = out->outer;
                view.length = (uint32_t)out->outer_len;
                memset(&herr, 0, sizeof(herr));
                spy(bind, NINLIL_R7_FRAG_SPY_R1_TX);
                hst = ninlil_radio_hal_transmit_with_permit(
                    bind->hal, &bind->held_permit, &view, &herr);
                out->r1_status = hst;
                out->consume_invoked = 1u;
                if (hst == NINLIL_RADIO_HAL_OK) {
                    out->edge_invoked = 1u;
                    out->cleanup_class = NINLIL_R7_FRAG_CLN_OK_COMPLETE;
                    (void)coord_finish(
                        bind, auth, bind->held_permit_sequence,
                        NINLIL_R7_FRAG_CLN_OK_COMPLETE);
                    (void)ninlil_r7_frag_l1w1_emit(
                        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT,
                        owner_token, candidate_token, 0u, 0u);
                    return NINLIL_R7_FRAG_PROD_OK;
                }
                if (hst == NINLIL_RADIO_HAL_NOT_BEFORE
                    || hst == NINLIL_RADIO_HAL_EXPIRED) {
                    (void)ninlil_r7_frag_issue_coordinator_hold_retry(
                        &bind->issue_coordinator, auth,
                        bind->held_permit_sequence);
                    out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_HELD;
                    (void)ninlil_r7_frag_l1w1_emit(
                        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT,
                        owner_token, candidate_token, (uint8_t)hst, 0u);
                    return NINLIL_R7_FRAG_PROD_R1;
                }
                if (hst == NINLIL_RADIO_HAL_EDGE_ERROR) {
                    out->edge_invoked = 1u;
                    out->cleanup_class = NINLIL_R7_FRAG_CLN_EDGE_STALE;
                    (void)coord_finish(
                        bind, auth, bind->held_permit_sequence,
                        NINLIL_R7_FRAG_CLN_EDGE_STALE);
                } else if (hst == NINLIL_RADIO_HAL_CONSUME_DENIED
                    || hst == NINLIL_RADIO_HAL_CONSUME_FENCED) {
                    out->cleanup_class = NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN;
                    (void)coord_finish(
                        bind, auth, bind->held_permit_sequence,
                        NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN);
                } else {
                    out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_DRAIN;
                    (void)coord_finish(
                        bind, auth, bind->held_permit_sequence,
                        NINLIL_R7_FRAG_CLN_ISSUED_DRAIN);
                }
                (void)ninlil_r7_frag_l1w1_emit(
                    bind->bus, bind->spy, NINLIL_R7_FRAG_EV_TX_RESULT,
                    owner_token, candidate_token, (uint8_t)hst, 0u);
                return NINLIL_R7_FRAG_PROD_R1;
            }
        }
        return r1_tx_with_permit(
            bind, owner_token, candidate_token, slot, auth, &bind->held_permit,
            outer_digest, out);
    }

    /* Held for a different outer while live: refuse dual-issue of same bind. */
    if (bind->held_tx_live != 0u) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        out->issue_l1_class = NINLIL_R7_L1_RETRYABLE_UNISSUED;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }

    st = fill_issue_from_live(bind, out->outer, out->outer_len, &req);
    if (st != NINLIL_R7_FRAG_PROD_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return st;
    }

    /* L1 admission before issue (cap 2). */
    st = ledger_admit(
        bind, owner_token, candidate_token, out->outer, out->outer_len, &slot);
    if (st != NINLIL_R7_FRAG_PROD_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return st;
    }
    out->ledger_admitted = 1u;

    (void)ninlil_r7_frag_l1w1_emit(
        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_FRAME_READY, owner_token,
        candidate_token, 2u, 0u);

    /* Align HAL live to this permit's L_core + airtime before issue/TX. */
    memset(&hlive, 0, sizeof(hlive));
    hlive.hardware_profile_id = bind->live.hardware_profile_id;
    hlive.hardware_profile_rev = bind->live.hardware_profile_rev;
    hlive.regulatory_profile_id = bind->live.regulatory_profile_id;
    hlive.regulatory_profile_rev = bind->live.regulatory_profile_rev;
    hlive.site_assignment_id = bind->live.site_assignment_id;
    hlive.site_assignment_rev = bind->live.site_assignment_rev;
    hlive.site_assignment_epoch = bind->live.site_assignment_epoch;
    hlive.transmitter_id = bind->live.transmitter_id;
    hlive.channel_id = bind->live.channel_id;
    hlive.phy = bind->live.phy;
    hlive.max_airtime_us = req.max_airtime_us;
    {
        ninlil_radio_hal_error_t le;
        memset(&le, 0, sizeof(le));
        if (ninlil_radio_hal_set_live_binding(bind->hal, &hlive, &le)
            != NINLIL_RADIO_HAL_OK) {
            ledger_release_slot(bind, slot, NINLIL_R7_FRAG_CLN_UNISSUED_DROP);
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            return NINLIL_R7_FRAG_PROD_R1;
        }
    }

    spy(bind, NINLIL_R7_FRAG_SPY_R2_ISSUE);
    memset(&permit, 0, sizeof(permit));
    /*
     * Sole R5→R2 checked-issue (docs/30 §15.3.1): R2 samples class-D once,
     * holds CS pin→validate→issue. No raw pcp_issue.
     */
    {
        ninlil_r7_checked_issue_result_t cir;
        int32_t ist;
        ist = ninlil_r7_private_issue_checked_with_owner_epoch(
            bind->pcp, &bind->live, bind->live.site_assignment_epoch, &req,
            bind_issue_registry(bind), &permit, &cir);
        pst = cir.pcp_status;
        out->r2_status = pst;
        out->issue_l1_class = cir.l1_class;
        out->issue_business_mutation = cir.business_mutation;
        out->issue_txn_provenance = cir.txn_provenance;
        out->r2_stage = cir.stage;
        out->r2_reason = cir.reason;
        if (cir.sample_valid != 0u) {
            (void)ninlil_r7_frag_prod_time_apply_class_d(bind, &cir.sample);
        }
        if (ist != NINLIL_R7_CHECKED_ISSUE_OK || cir.issued == 0u
            || pst != NINLIL_PCP_OK) {
            /*
             * CU / RECONCILE / CLOCK / STORAGE: never UNISSUED_DROP on
             * ambiguous or fence paths; fence prepared at caller.
             */
            if (pst == NINLIL_PCP_COMMIT_UNKNOWN
                || cir.l1_class == NINLIL_R7_L1_RECONCILE_REQUIRED
                || pst == NINLIL_PCP_STORAGE_FENCE
                || pst == NINLIL_PCP_CORRUPT_FENCE
                || pst == NINLIL_PCP_STORAGE_IO) {
                bind->ledger[slot].permit_sequence = 0u;
                out->cleanup_class = NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN;
                (void)ninlil_r7_frag_prod_cleanup(
                    bind, NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN, 0u);
            } else if (pst == NINLIL_PCP_CLOCK_UNCERTAIN
                || pst == NINLIL_PCP_CLOCK_FAULT
                || cir.l1_class == NINLIL_R7_L1_CLOCK_PATH_DROP) {
                ledger_release_slot(bind, slot, NINLIL_R7_FRAG_CLN_CLOCK_DROP);
                out->cleanup_class = NINLIL_R7_FRAG_CLN_CLOCK_DROP;
                (void)ninlil_r7_frag_prod_cleanup(
                    bind, NINLIL_R7_FRAG_CLN_CLOCK_DROP, 0u);
            } else if (cir.l1_class == NINLIL_R7_L1_RETRYABLE_UNISSUED
                || pst == NINLIL_PCP_CAPACITY || pst == NINLIL_PCP_BUSY) {
                ledger_release_slot(bind, slot, NINLIL_R7_FRAG_CLN_UNISSUED_DROP);
                out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            } else {
                ledger_release_slot(bind, slot, NINLIL_R7_FRAG_CLN_UNISSUED_DROP);
                out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            }
            (void)ninlil_r7_frag_l1w1_emit(
                bind->bus, bind->spy, NINLIL_R7_FRAG_EV_OWNER_TERMINAL,
                owner_token, candidate_token, (uint8_t)pst, 0u);
            return NINLIL_R7_FRAG_PROD_R2;
        }
    }
    out->permit_sequence = permit.permit_sequence;
    bind->ledger[slot].permit_sequence = permit.permit_sequence;

    /* Admit with full identity before any R1 TX (docs/30 max 8). */
    memset(&admit, 0, sizeof(admit));
    admit.authority_token = auth;
    admit.permit_sequence = permit.permit_sequence;
    admit.bind_token = (uintptr_t)bind;
    admit.outer_len = (uint32_t)out->outer_len;
    admit.issue_now_ms = bind->r2_now_valid != 0u ? bind->r2_now_ms : 0u;
    memcpy(admit.outer_digest, outer_digest, 32u);
    cst = ninlil_r7_frag_issue_coordinator_admit(
        &bind->issue_coordinator, &admit);
    if (cst == NINLIL_R7_COORD_CAPACITY || cst == NINLIL_R7_COORD_BUSY
        || cst == NINLIL_R7_COORD_DUPLICATE || cst == NINLIL_R7_COORD_INVALID) {
        /* Issued but cannot own in queue: drain; never leave reissuable. */
        out->issue_l1_class = (cst == NINLIL_R7_COORD_DUPLICATE)
            ? NINLIL_R7_L1_RECONCILE_REQUIRED
            : NINLIL_R7_L1_RETRYABLE_UNISSUED;
        out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_DRAIN;
        r5_release_seq(bind, permit.permit_sequence);
        (void)ninlil_r7_frag_prod_cleanup(
            bind, NINLIL_R7_FRAG_CLN_ISSUED_DRAIN, permit.permit_sequence);
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    if (cst == NINLIL_R7_COORD_QUEUED) {
        /* Real queue ownership: keep issued, no TX, no re-issue of outer. */
        held_tx_store(
            bind, auth, permit.permit_sequence, slot, 1u, outer_digest,
            out->outer, out->outer_len, &permit);
        out->issue_l1_class = NINLIL_R7_L1_FIFO_OUT_OF_ORDER;
        out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_HELD;
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_OWNER_TERMINAL,
            owner_token, candidate_token,
            (uint8_t)NINLIL_R7_L1_FIFO_OUT_OF_ORDER, 0u);
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    /* OK = head: begin_tx + R1. */
    return r1_tx_with_permit(
        bind, owner_token, candidate_token, slot, auth, &permit, outer_digest,
        out);
}

int32_t ninlil_r7_frag_prod_tx_resume_held(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    ninlil_r7_frag_prod_tx_result_t *out)
{
    int32_t cg;

    if (bind == NULL || out == NULL || owner_token == 0u
        || candidate_token == 0u) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if (!ninlil_r7_frag_prod_bind_is_inited(bind)
        || bind->held_tx_live == 0u || bind->held_outer_len == 0u
        || bind->held_outer_len > sizeof(out->outer)) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        out->issue_l1_class = NINLIL_R7_L1_RETRYABLE_UNISSUED;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    cg = clock_gate(bind);
    if (cg != NINLIL_R7_FRAG_PROD_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_ISSUED_DRAIN;
        (void)ninlil_r7_frag_prod_cleanup(
            bind, out->cleanup_class, bind->held_permit_sequence);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    out->outer_len = bind->held_outer_len;
    memcpy(out->outer, bind->held_outer, out->outer_len);
    return issue_and_tx(bind, owner_token, candidate_token, out);
}

int32_t ninlil_r7_frag_prod_tx_single(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    const uint8_t *app,
    size_t app_len,
    uint32_t e2e_context_id,
    uint32_t hop_context_id,
    uint8_t ack_requested,
    ninlil_r7_frag_prod_tx_result_t *out)
{
    ninlil_n6_tx_lease_t e2e_lease;
    ninlil_n6_tx_lease_t hop_lease;
    ninlil_n6_status_t nst;
    ninlil_r7_wire_e2e_single_fields e2e_f;
    ninlil_r7_wire_outer_data_fields outer_f;
    uint8_t e2e_blob[220];
    size_t e2e_len = 0u;
    size_t outer_need;
    ninlil_r7_wire_status wst;
    const ninlil_r7_crypto_provider *crypto;
    int32_t cg;

    if (bind == NULL || app == NULL || out == NULL || owner_token == 0u
        || candidate_token == 0u) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out, 0, sizeof(*out));
    memset(&e2e_lease, 0, sizeof(e2e_lease));
    memset(&hop_lease, 0, sizeof(hop_lease));

    if (bind->n6 == NULL || bind->pcp == NULL || bind->hal == NULL
        || bind->crypto == NULL || !bind->live_valid) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    cg = clock_gate(bind);
    if (cg != NINLIL_R7_FRAG_PROD_OK) {
        out->cleanup_class = (cg == NINLIL_R7_FRAG_PROD_CLOCK
                && bind->expected_epoch_lo != 0u
                && bind->epoch_id_lo != bind->expected_epoch_lo)
            ? NINLIL_R7_FRAG_CLN_EPOCH_DROP
            : NINLIL_R7_FRAG_CLN_CLOCK_DROP;
        (void)ninlil_r7_frag_prod_cleanup(
            bind, out->cleanup_class, 0u);
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }

    (void)ninlil_r7_frag_l1w1_emit(
        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_STAMP_FIELDS, owner_token,
        candidate_token, 1u, 0u);

    /* N6 E2E burn (production durable counters). */
    spy(bind, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
    nst = ninlil_n6_tx_burn(
        bind->n6, bind->e2e_handle, NINLIL_N6_LANE_E2E, &e2e_lease);
    out->n6_status = nst;
    if (nst != NINLIL_N6_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_N6;
    }
    out->e2e_counter = e2e_lease.counter;
    /* Wire E2E context must exact-match installed lease authority. */
    if (e2e_lease.context_id != e2e_context_id) {
        (void)ninlil_n6_tx_lease_release(bind->n6, &e2e_lease);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    crypto = bind->crypto;

    memset(&e2e_f, 0, sizeof(e2e_f));
    e2e_f.e2e_context_id = e2e_lease.context_id;
    e2e_f.e2e_counter = e2e_lease.counter;
    {
        size_t need = 14u + app_len + 16u;
        if (need > sizeof(e2e_blob) || app_len < 1u || app_len > 190u) {
            (void)ninlil_n6_tx_lease_release(bind->n6, &e2e_lease);
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        wst = ninlil_r7_wire_seal_e2e_single(
            crypto, e2e_lease.key16, e2e_lease.iv12, &e2e_f, app, app_len,
            e2e_blob, need, &e2e_len);
        (void)ninlil_n6_tx_lease_release(bind->n6, &e2e_lease);
        if (wst != NINLIL_R7_WIRE_OK) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            (void)ninlil_r7_frag_l1w1_emit(
                bind->bus, bind->spy, NINLIL_R7_FRAG_EV_SEAL_FAIL, owner_token,
                candidate_token, 1u, 0u);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
    }

    /* N6 hop DATA burn. */
    spy(bind, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
    nst = ninlil_n6_tx_burn(
        bind->n6, bind->hop_data_handle, NINLIL_N6_LANE_HOP_DATA, &hop_lease);
    out->n6_status = nst;
    if (nst != NINLIL_N6_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_N6;
    }
    out->hop_counter = hop_lease.counter;
    if (hop_lease.context_id != hop_context_id) {
        (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    memset(&outer_f, 0, sizeof(outer_f));
    outer_f.ack_requested = ack_requested ? 1u : 0u;
    outer_f.hop_remaining = 0u;
    outer_f.hop_context_id = hop_lease.context_id;
    outer_f.hop_counter = hop_lease.counter;
    outer_f.route_handle = 0u;
    outer_f.route_generation = 0u;
    outer_need = 19u + e2e_len + 16u;
    if (outer_need > sizeof(out->outer)) {
        (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    wst = ninlil_r7_wire_seal_outer_single(
        crypto, hop_lease.key16, hop_lease.iv12, &outer_f, e2e_blob, e2e_len,
        out->outer, outer_need, &out->outer_len);
    (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
    if (wst != NINLIL_R7_WIRE_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_SEAL_FAIL, owner_token,
            candidate_token, 2u, 0u);
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    if (out->outer_len == 0u || out->outer[0] != 0x11u) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    return issue_and_tx(bind, owner_token, candidate_token, out);
}

int32_t ninlil_r7_frag_prod_tx_outer_from_e2e(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    const uint8_t *e2e_blob,
    size_t e2e_len,
    uint32_t hop_context_id,
    uint8_t ack_requested,
    uint16_t route_handle,
    uint8_t route_generation,
    ninlil_r7_frag_prod_tx_result_t *out)
{
    ninlil_n6_tx_lease_t hop_lease;
    ninlil_n6_status_t nst;
    ninlil_r7_frag_outer_data_fields outer_f;
    ninlil_r7_frag_status fst;
    size_t outer_need;
    int32_t cg;

    if (bind == NULL || e2e_blob == NULL || out == NULL || owner_token == 0u
        || candidate_token == 0u || e2e_len == 0u || e2e_len > 220u) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out, 0, sizeof(*out));
    memset(&hop_lease, 0, sizeof(hop_lease));
    if (bind->n6 == NULL || bind->pcp == NULL || bind->hal == NULL
        || bind->crypto == NULL || !bind->live_valid) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    cg = clock_gate(bind);
    if (cg != NINLIL_R7_FRAG_PROD_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_CLOCK_DROP;
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }

    (void)ninlil_r7_frag_l1w1_emit(
        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_STAMP_FIELDS, owner_token,
        candidate_token, 2u, 0u);

    spy(bind, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
    nst = ninlil_n6_tx_burn(
        bind->n6, bind->hop_data_handle, NINLIL_N6_LANE_HOP_DATA, &hop_lease);
    out->n6_status = nst;
    if (nst != NINLIL_N6_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_N6;
    }
    out->hop_counter = hop_lease.counter;
    if (hop_lease.context_id != hop_context_id) {
        (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    /* FRAG outer seal accepts SINGLE/START/CONT/ACK E2E blobs (not wire
     * seal_outer_single which is SINGLE-only structural guard). */
    memset(&outer_f, 0, sizeof(outer_f));
    outer_f.ack_requested = ack_requested ? 1u : 0u;
    outer_f.hop_remaining = 0u;
    outer_f.hop_context_id = hop_lease.context_id;
    outer_f.hop_counter = hop_lease.counter;
    outer_f.route_handle = route_handle;
    outer_f.route_generation = route_generation;
    outer_need = 19u + e2e_len + 16u;
    if (outer_need > sizeof(out->outer)) {
        (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    fst = ninlil_r7_frag_seal_outer_data(
        bind->crypto, hop_lease.key16, hop_lease.iv12, &outer_f, e2e_blob,
        e2e_len, out->outer, outer_need, &out->outer_len);
    (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
    if (fst != NINLIL_R7_FRAG_OK || out->outer[0] != 0x11u) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    return issue_and_tx(bind, owner_token, candidate_token, out);
}

/* Capture N6 last_error reason into out (best-effort). */
static void rx_capture_n6_err(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_n6_status_t nst,
    ninlil_r7_frag_prod_rx_result_t *out)
{
    ninlil_n6_error_t err;
    out->n6_pre_st = nst;
    out->n6_pre_reason = NINLIL_N6_REASON_NONE;
    if (bind != NULL && bind->n6 != NULL
        && ninlil_n6_last_error(bind->n6, &err) == NINLIL_N6_OK) {
        if (err.status == nst) {
            out->n6_pre_reason = err.reason;
        }
    }
}

/*
 * LINK_ACK note after hop admit (independent of E2E). Idempotent: duplicate
 * hop counter reuses existing pending row. Enables ACK recovery on E2E REPLAY.
 */
static void note_link_ack_after_hop_admit(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_rx_result_t *out,
    uint32_t acked_hop_data_context_id,
    uint64_t acked_hop_counter)
{
    size_t i;
    if (bind == NULL || out == NULL || out->outer_ack_requested == 0u) {
        return;
    }
    if (bind->hop_ack_handle == 0u || bind->hop_ack_context_id == 0u
        || acked_hop_data_context_id == 0u || acked_hop_counter == 0u
        || acked_hop_counter == UINT64_MAX) {
        return;
    }
    /* Idempotent: same hop DATA counter already pending ⇒ note success. */
    for (i = 0u; i < NINLIL_R7_FRAG_PROD_LINK_ACK_PENDING_CAP; i++) {
        ninlil_r7_frag_prod_link_ack_pending_t *P = &bind->link_ack_pending[i];
        if (P->live != 0u
            && P->acked_hop_data_context_id == acked_hop_data_context_id
            && P->ack_base_counter == acked_hop_counter
            && P->hop_ack_context_id == bind->hop_ack_context_id) {
            out->link_ack_pending_noted = 1u;
            return;
        }
    }
    if (ninlil_r7_frag_prod_link_ack_note_after_e2e(
            bind, bind->hop_ack_context_id, acked_hop_data_context_id,
            acked_hop_counter, 1u /* hop-admitted authority */)
        == NINLIL_R7_FRAG_PROD_OK) {
        out->link_ack_pending_noted = 1u;
    }
}

/*
 * E2E precheck result: typed REPLAY ⇒ hop-only OK (no body/pub).
 * LINK_ACK must already be noted before this path (hop-admit).
 * Live TICKET collision and every other N6 error ⇒ fail-closed PROD_N6.
 */
static int rx_e2e_precheck_decide(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_n6_status_t nst,
    ninlil_r7_frag_prod_rx_result_t *out,
    uint32_t hop_data_ctx,
    uint64_t hop_ctr,
    int32_t *ret)
{
    rx_capture_n6_err(bind, nst, out);
    out->body_applied = 0u;
    out->published = 0u;
    if (nst == NINLIL_N6_OK) {
        return 0;
    }
    if (nst == NINLIL_N6_REPLAY) {
        /* Hop already admitted; regenerate LINK_ACK obligation if lost. */
        note_link_ack_after_hop_admit(bind, out, hop_data_ctx, hop_ctr);
        out->hop_only_retransmit = 1u;
        *ret = NINLIL_R7_FRAG_PROD_OK;
        return 1;
    }
    out->hop_only_retransmit = 0u;
    *ret = NINLIL_R7_FRAG_PROD_N6;
    return 1;
}

int32_t ninlil_r7_frag_prod_rx_outer(
    ninlil_r7_frag_prod_bind_t *bind,
    const uint8_t *outer,
    size_t outer_len,
    uint32_t hop_context_id,
    uint32_t e2e_context_id,
    ninlil_r7_frag_prod_rx_result_t *out)
{
    ninlil_n6_rx_ticket_t hop_ticket;
    ninlil_n6_rx_ticket_t e2e_ticket;
    ninlil_n6_status_t nst;
    ninlil_r7_wire_outer_data_fields of;
    ninlil_r7_frag_outer_data_fields ofrag;
    ninlil_r7_wire_e2e_single_fields ef;
    ninlil_r7_frag_e2e_fields ff;
    ninlil_r7_frag_status fst;
    uint8_t e2e_blob[220];
    size_t e2e_len = 0u;
    uint8_t app[190];
    size_t app_len = 0u;
    size_t hop_ct_cap = 0u;
    size_t app_cap = 0u;
    ninlil_r7_wire_status wst;
    uint64_t hop_ctr;
    uint64_t e2e_ctr;
    uint32_t decoded_hop_ctx;
    uint16_t route_handle;
    uint16_t route_generation;
    uint8_t hop_remaining;
    int used_frag_outer = 0;
    int32_t decide_ret = NINLIL_R7_FRAG_PROD_OK;
    const ninlil_r7_crypto_provider *crypto;

    if (bind == NULL || outer == NULL || out == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out, 0, sizeof(*out));
    memset(&hop_ticket, 0, sizeof(hop_ticket));
    memset(&e2e_ticket, 0, sizeof(e2e_ticket));
    if (bind->n6 == NULL || bind->crypto == NULL) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    crypto = bind->crypto;
    if (outer_len < 51u || outer_len > 255u || outer[0] != 0x11u) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    /* Wire/FRAG open contracts require exact ciphertext capacity. */
    if (outer_len < 19u + 16u) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    hop_ct_cap = outer_len - 19u - 16u;
    if (hop_ct_cap < 31u || hop_ct_cap > sizeof(e2e_blob)) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    /* Structural outer fields (pre-crypto) — fail-closed before N6 burn. */
    hop_remaining = outer[2];
    decoded_hop_ctx = ((uint32_t)outer[3] << 24) | ((uint32_t)outer[4] << 16)
        | ((uint32_t)outer[5] << 8) | (uint32_t)outer[6];
    hop_ctr = ((uint64_t)outer[7] << 56) | ((uint64_t)outer[8] << 48)
        | ((uint64_t)outer[9] << 40) | ((uint64_t)outer[10] << 32)
        | ((uint64_t)outer[11] << 24) | ((uint64_t)outer[12] << 16)
        | ((uint64_t)outer[13] << 8) | (uint64_t)outer[14];
    route_handle =
        (uint16_t)(((uint16_t)outer[15] << 8) | (uint16_t)outer[16]);
    route_generation =
        (uint16_t)(((uint16_t)outer[17] << 8) | (uint16_t)outer[18]);
    if (decoded_hop_ctx != hop_context_id) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    if (hop_ctr == 0u || hop_ctr == UINT64_MAX) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    /* Route/generation/hop_remaining closed structural form (docs/30). */
    if (!((route_handle == 0u && route_generation == 0u && hop_remaining == 0u)
            || (route_handle != 0u && route_generation != 0u
                && hop_remaining >= 1u))) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_PRE);
    nst = ninlil_n6_rx_precheck(
        bind->n6, bind->hop_data_handle, NINLIL_N6_LANE_HOP_DATA, hop_ctr,
        &hop_ticket);
    rx_capture_n6_err(bind, nst, out);
    if (nst != NINLIL_N6_OK) {
        /* Hop REPLAY/TICKET/etc. are never hop-only success — fail closed. */
        out->body_applied = 0u;
        out->published = 0u;
        out->hop_only_retransmit = 0u;
        return NINLIL_R7_FRAG_PROD_N6;
    }
    /* Installed hop ticket context must exact-bind on-wire hop_context_id. */
    if (hop_ticket.context_id != hop_context_id
        || hop_ticket.context_id != decoded_hop_ctx) {
        (void)ninlil_n6_rx_abort(bind->n6, &hop_ticket);
        out->body_applied = 0u;
        out->published = 0u;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    /* Prefer FRAG outer open (accepts SINGLE/START/CONT E2E PT). Exact cap. */
    fst = ninlil_r7_frag_open_outer_data(
        crypto, hop_ticket.key16, hop_ticket.iv12, outer, outer_len, &ofrag,
        e2e_blob, hop_ct_cap, &e2e_len);
    if (fst == NINLIL_R7_FRAG_OK) {
        used_frag_outer = 1;
        /* Authenticated hop_context_id must match ticket authority. */
        if (ofrag.hop_context_id != hop_ticket.context_id) {
            (void)ninlil_n6_rx_abort(bind->n6, &hop_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
    } else {
        /* Fallback wire SINGLE open for legacy path (exact hop CT capacity). */
        wst = ninlil_r7_wire_open_outer_single(
            crypto, hop_ticket.key16, hop_ticket.iv12, outer, outer_len, &of,
            e2e_blob, hop_ct_cap, &e2e_len);
        if (wst != NINLIL_R7_WIRE_OK) {
            (void)ninlil_n6_rx_abort(bind->n6, &hop_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        if (of.hop_context_id != hop_ticket.context_id) {
            (void)ninlil_n6_rx_abort(bind->n6, &hop_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
    }
    (void)used_frag_outer;
    /* Capture outer ack identity before hop admit zeroizes ticket state. */
    {
        uint8_t ar = 0u;
        if (used_frag_outer) {
            ar = ofrag.ack_requested;
            hop_ctr = ofrag.hop_counter;
            decoded_hop_ctx = ofrag.hop_context_id;
        } else {
            ar = of.ack_requested;
            hop_ctr = of.hop_counter;
            decoded_hop_ctx = of.hop_context_id;
        }
        out->outer_ack_requested = ar ? 1u : 0u;
        spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_ADMIT);
        nst = ninlil_n6_rx_admit_after_aead(bind->n6, &hop_ticket);
        out->n6_admit_st = nst;
        if (nst != NINLIL_N6_OK) {
            out->body_applied = 0u;
            out->published = 0u;
            return NINLIL_R7_FRAG_PROD_N6;
        }
        /*
         * LINK_ACK obligation after hop admit — independent of E2E path.
         * Enables replay-safe regeneration when E2E REPLAY early-returns.
         */
        note_link_ack_after_hop_admit(bind, out, decoded_hop_ctx, hop_ctr);
    }

    e2e_ctr = ((uint64_t)e2e_blob[6] << 56) | ((uint64_t)e2e_blob[7] << 48)
        | ((uint64_t)e2e_blob[8] << 40) | ((uint64_t)e2e_blob[9] << 32)
        | ((uint64_t)e2e_blob[10] << 24) | ((uint64_t)e2e_blob[11] << 16)
        | ((uint64_t)e2e_blob[12] << 8) | (uint64_t)e2e_blob[13];
    spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_PRE);
    nst = ninlil_n6_rx_precheck(
        bind->n6, bind->e2e_handle, NINLIL_N6_LANE_E2E, e2e_ctr, &e2e_ticket);
    if (rx_e2e_precheck_decide(
            bind, nst, out, decoded_hop_ctx, hop_ctr, &decide_ret)) {
        return decide_ret;
    }
    /* E2E ticket context must exact-bind caller e2e_context_id. */
    if (e2e_ticket.context_id != e2e_context_id) {
        (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
        out->body_applied = 0u;
        out->published = 0u;
        out->hop_only_retransmit = 0u;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    /* Classify E2E type from sealed blob structural header. */
    {
        ninlil_r7_frag_e2e_fields sh;
        fst = ninlil_r7_frag_structural_e2e_header(e2e_blob, e2e_len, &sh);
        if (fst != NINLIL_R7_FRAG_OK) {
            /* Wire SINGLE: exact app capacity = blob - AAD14 - TAG16. */
            if (e2e_len < 14u + 16u) {
                (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
                return NINLIL_R7_FRAG_PROD_WIRE;
            }
            app_cap = e2e_len - 14u - 16u;
            if (app_cap < 1u || app_cap > sizeof(app)) {
                (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
                return NINLIL_R7_FRAG_PROD_WIRE;
            }
            wst = ninlil_r7_wire_open_e2e_single(
                crypto, e2e_ticket.key16, e2e_ticket.iv12, e2e_blob, e2e_len,
                &ef, app, app_cap, &app_len);
            if (wst != NINLIL_R7_WIRE_OK) {
                (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
                return NINLIL_R7_FRAG_PROD_WIRE;
            }
            if (ef.e2e_context_id != e2e_context_id) {
                (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
                return NINLIL_R7_FRAG_PROD_WIRE;
            }
            spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_ADMIT);
            nst = ninlil_n6_rx_admit_after_aead(bind->n6, &e2e_ticket);
            out->n6_admit_st = nst;
            if (nst != NINLIL_N6_OK) {
                return NINLIL_R7_FRAG_PROD_N6;
            }
            out->e2e_type = NINLIL_R7_FRAG_E2E_TYPE_SINGLE;
            out->body_applied = 1u;
            out->published = 1u;
            out->app_len = app_len;
            memcpy(out->app, app, app_len);
            note_link_ack_after_hop_admit(
                bind, out, decoded_hop_ctx, hop_ctr);
            return NINLIL_R7_FRAG_PROD_OK;
        }
        out->e2e_type = sh.e2e_type;
    }

    if (out->e2e_type == NINLIL_R7_FRAG_E2E_TYPE_SINGLE
        || out->e2e_type == 0u) {
        if (e2e_len < 14u + 16u) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        app_cap = e2e_len - 14u - 16u;
        if (app_cap < 1u || app_cap > sizeof(app)) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        wst = ninlil_r7_wire_open_e2e_single(
            crypto, e2e_ticket.key16, e2e_ticket.iv12, e2e_blob, e2e_len, &ef,
            app, app_cap, &app_len);
        if (wst != NINLIL_R7_WIRE_OK) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        if (ef.e2e_context_id != e2e_context_id) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_ADMIT);
        nst = ninlil_n6_rx_admit_after_aead(bind->n6, &e2e_ticket);
        out->n6_admit_st = nst;
        if (nst != NINLIL_N6_OK) {
            return NINLIL_R7_FRAG_PROD_N6;
        }
        out->e2e_type = NINLIL_R7_FRAG_E2E_TYPE_SINGLE;
        out->body_applied = 1u;
        out->published = 1u;
        out->app_len = app_len;
        memcpy(out->app, app, app_len);
        note_link_ack_after_hop_admit(bind, out, decoded_hop_ctx, hop_ctr);
        return NINLIL_R7_FRAG_PROD_OK;
    }

    if (out->e2e_type == NINLIL_R7_FRAG_E2E_TYPE_ACK) {
        ninlil_r7_frag_ack_body ab;
        fst = ninlil_r7_frag_open_e2e_ack(
            crypto, e2e_ticket.key16, e2e_ticket.iv12, e2e_blob, e2e_len, &ff,
            &ab);
        if (fst != NINLIL_R7_FRAG_OK) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        if (ff.e2e_context_id != e2e_ticket.context_id
            || ff.e2e_context_id != e2e_context_id) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_ADMIT);
        nst = ninlil_n6_rx_admit_after_aead(bind->n6, &e2e_ticket);
        out->n6_admit_st = nst;
        if (nst != NINLIL_N6_OK) {
            return NINLIL_R7_FRAG_PROD_N6;
        }
        /* FRAG_ACK: publish decoded body to result for sender apply path. */
        out->body_applied = 0u;
        out->published = 0u;
        out->ack_valid = 1u;
        out->ack_body = ab;
        out->e2e_type = NINLIL_R7_FRAG_E2E_TYPE_ACK;
        return NINLIL_R7_FRAG_PROD_OK;
    }

    /* START / CONT require production reasm engine. */
    if (bind->reasm == NULL || bind->reasm_key_generation == 0u) {
        (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }

    if (out->e2e_type == NINLIL_R7_FRAG_E2E_TYPE_START) {
        ninlil_r7_frag_start_body sb;
        uint8_t first[126];
        size_t flen = 0u;
        ninlil_r7_frag_state_start_in sin;
        ninlil_r7_frag_state_ack_intent intent;

        fst = ninlil_r7_frag_open_e2e_start(
            crypto, e2e_ticket.key16, e2e_ticket.iv12, e2e_blob, e2e_len, &ff,
            &sb, first, sizeof(first), &flen);
        if (fst != NINLIL_R7_FRAG_OK
            || ff.e2e_context_id != e2e_context_id
            || ff.e2e_context_id != e2e_ticket.context_id) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        /* Capture ticket authority before admit zeroizes the ticket. */
        {
            uint32_t e2e_auth_ctx = e2e_ticket.context_id;
            spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_ADMIT);
            nst = ninlil_n6_rx_admit_after_aead(bind->n6, &e2e_ticket);
            out->n6_admit_st = nst;
            if (nst != NINLIL_N6_OK) {
                return NINLIL_R7_FRAG_PROD_N6;
            }
            memset(&sin, 0, sizeof(sin));
            sin.e2e_context_id = e2e_auth_ctx;
        }
        sin.key_generation = bind->reasm_key_generation;
        memcpy(sin.transfer_id, sb.transfer_id, 16u);
        sin.transfer_handle = sb.transfer_handle;
        sin.total_len = sb.total_len;
        sin.frag_count = sb.frag_count;
        sin.continuation_unit = sb.continuation_unit;
        memcpy(sin.content_digest, sb.content_digest, 32u);
        sin.first_chunk = first;
        sin.first_chunk_len = (uint16_t)flen;
        if (ninlil_r7_frag_start_fingerprint(
                crypto, &sb, first, flen, sin.fingerprint)
            != NINLIL_R7_FRAG_OK) {
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        memset(&intent, 0, sizeof(intent));
        out->reasm_st = ninlil_r7_frag_state_admit_start(
            bind->reasm, &sin, &intent);
        out->frag_index = 0u;
        out->body_applied =
            (out->reasm_st == NINLIL_R7_FRAG_STATE_OK
                || out->reasm_st == NINLIL_R7_FRAG_STATE_EXACT_RETRY)
            ? 1u
            : 0u;
        if (intent.valid) {
            out->intent_valid = 1u;
            out->ack_intent = intent;
        }
        if (out->body_applied != 0u) {
            note_link_ack_after_hop_admit(
                bind, out, decoded_hop_ctx, hop_ctr);
        }
        return NINLIL_R7_FRAG_PROD_OK;
    }

    if (out->e2e_type == NINLIL_R7_FRAG_E2E_TYPE_CONT) {
        ninlil_r7_frag_cont_body cb;
        uint8_t chunk[180];
        size_t clen = 0u;
        ninlil_r7_frag_state_cont_in cin;
        ninlil_r7_frag_state_ack_intent intent;
        uint8_t dig[32];

        fst = ninlil_r7_frag_open_e2e_cont(
            crypto, e2e_ticket.key16, e2e_ticket.iv12, e2e_blob, e2e_len, &ff,
            &cb, chunk, sizeof(chunk), &clen);
        if (fst != NINLIL_R7_FRAG_OK
            || ff.e2e_context_id != e2e_context_id
            || ff.e2e_context_id != e2e_ticket.context_id) {
            (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        {
            uint32_t e2e_auth_ctx = e2e_ticket.context_id;
            spy(bind, NINLIL_R7_FRAG_SPY_N6_RX_ADMIT);
            nst = ninlil_n6_rx_admit_after_aead(bind->n6, &e2e_ticket);
            out->n6_admit_st = nst;
            if (nst != NINLIL_N6_OK) {
                return NINLIL_R7_FRAG_PROD_N6;
            }
            memset(&cin, 0, sizeof(cin));
            cin.e2e_context_id = e2e_auth_ctx;
        }
        cin.key_generation = bind->reasm_key_generation;
        cin.transfer_handle = cb.transfer_handle;
        cin.frag_index = cb.frag_index;
        cin.chunk = chunk;
        cin.chunk_len = (uint16_t)clen;
        cin.reassembled_digest32 = NULL;
        memset(&intent, 0, sizeof(intent));
        out->reasm_st =
            ninlil_r7_frag_state_admit_cont(bind->reasm, &cin, &intent);
        out->frag_index = cb.frag_index;
        out->body_applied =
            (out->reasm_st == NINLIL_R7_FRAG_STATE_OK
                || out->reasm_st == NINLIL_R7_FRAG_STATE_DUPLICATE
                || out->reasm_st == NINLIL_R7_FRAG_STATE_NEED_DIGEST
                || out->reasm_st == NINLIL_R7_FRAG_STATE_PUBLISHED)
            ? 1u
            : 0u;
        if (out->reasm_st == NINLIL_R7_FRAG_STATE_NEED_DIGEST) {
            const uint8_t *pl = NULL;
            size_t pl_len = 0u;
            if (ninlil_r7_frag_state_peek_reassembled(
                    bind->reasm, cin.e2e_context_id, cb.transfer_handle, &pl,
                    &pl_len)
                    == NINLIL_R7_FRAG_STATE_OK
                && pl != NULL
                && ninlil_r7_crypto_sha256(crypto, pl, pl_len, dig)
                    == NINLIL_R7_CRYPTO_OK) {
                out->reasm_st = ninlil_r7_frag_state_finalize(
                    bind->reasm, cin.e2e_context_id, cb.transfer_handle, dig,
                    &intent);
            }
        }
        if (intent.valid) {
            out->intent_valid = 1u;
            out->ack_intent = intent;
        }
        if (out->reasm_st == NINLIL_R7_FRAG_STATE_OK
            || out->reasm_st == NINLIL_R7_FRAG_STATE_PUBLISHED) {
            size_t pub_len = 0u;
            uint32_t ctx = 0u;
            uint64_t kgen = 0u;
            uint64_t th = 0u;
            if (ninlil_r7_frag_state_take_publication(
                    bind->reasm, &ctx, &kgen, &th, out->app, sizeof(out->app),
                    &pub_len)
                == NINLIL_R7_FRAG_STATE_PUBLISHED) {
                out->published = 1u;
                out->app_len = pub_len;
            }
        }
        if (out->body_applied != 0u) {
            note_link_ack_after_hop_admit(
                bind, out, decoded_hop_ctx, hop_ctr);
        }
        return NINLIL_R7_FRAG_PROD_OK;
    }

    (void)ninlil_n6_rx_abort(bind->n6, &e2e_ticket);
    return NINLIL_R7_FRAG_PROD_WIRE;
}

void ninlil_r7_frag_prod_xfer_zeroize(ninlil_r7_frag_prod_xfer_t *xfer)
{
    if (xfer == NULL) {
        return;
    }
    memset(xfer, 0, sizeof(*xfer));
}

/* Candidate tokens for L1W1 ownership events (distinct per prep). */
static uint64_t xfer_cand(uint64_t base, uint16_t frag, uint8_t phase)
{
    return base + ((uint64_t)frag << 8) + (uint64_t)phase;
}

int32_t ninlil_r7_frag_prod_tx_frag_begin(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    const uint8_t *payload,
    size_t payload_len,
    const uint8_t transfer_id[16],
    uint32_t e2e_context_id)
{
    ninlil_r7_frag_state_plan plan;
    ninlil_n6_status_t nst;
    ninlil_r7_frag_status fst;
    uint16_t i;
    uint64_t owner = 0xE2000001u;

    if (bind == NULL || xfer == NULL || payload == NULL || transfer_id == NULL
        || bind->n6 == NULL || bind->crypto == NULL || payload_len < 2u
        || payload_len > NINLIL_R7_FRAG_STATE_TOTAL_LEN_MAX) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (xfer->live != 0u) {
        return NINLIL_R7_FRAG_PROD_ADMISSION; /* duplicate begin */
    }
    /* Clock gate + deadline overflow reject (P2). */
    {
        int32_t cg = clock_gate(bind);
        if (cg != NINLIL_R7_FRAG_PROD_OK) {
            return NINLIL_R7_FRAG_PROD_CLOCK;
        }
        if (bind->trusted_now_ms > UINT64_MAX - NINLIL_R7_FRAG_SENDER_TTL_MS) {
            return NINLIL_R7_FRAG_PROD_CLOCK;
        }
    }
    if (ninlil_r7_frag_state_plan_build((uint32_t)payload_len, &plan)
        != NINLIL_R7_FRAG_STATE_OK) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    memset(xfer, 0, sizeof(*xfer));
    xfer->live = 1u;
    xfer->plan = plan;
    /* Own/copy immutable payload (no borrow). */
    memcpy(xfer->payload_owned, payload, payload_len);
    xfer->payload_len = payload_len;
    xfer->payload_owned_valid = 1u;
    xfer->e2e_context_id = e2e_context_id;
    /* Per-air ack_requested is authoritative; default remains 0 (not hardcoded 1). */
    xfer->ack_requested_default = 0u;
    xfer->transfer_start_mono = bind->trusted_now_ms;
    xfer->sender_absolute_deadline =
        bind->trusted_now_ms + NINLIL_R7_FRAG_SENDER_TTL_MS;
    /* Per-LINK-group deadlines are armed on first hop prepare per frag. */
    if (bind->r2_now_valid == 0u) {
        /* Require R2 sample domain before group arm; begin may use live pin. */
        if (bind->clock_trusted == 0u) {
            ninlil_r7_frag_prod_xfer_zeroize(xfer);
            return NINLIL_R7_FRAG_PROD_CLOCK;
        }
    }
    memcpy(xfer->transfer_id, transfer_id, 16u);
    if (ninlil_r7_crypto_sha256(
            bind->crypto, xfer->payload_owned, payload_len, xfer->content_digest)
        != NINLIL_R7_CRYPTO_OK) {
        ninlil_r7_frag_prod_xfer_zeroize(xfer);
        return NINLIL_R7_FRAG_PROD_WIRE;
    }

    for (i = 0u; i < plan.frag_count; i++) {
        ninlil_r7_frag_e2e_fields ef;
        ninlil_n6_tx_lease_t el;
        size_t elen = 0u;
        const uint8_t *chunk = xfer->payload_owned + plan.chunks[i].offset;
        size_t clen = plan.chunks[i].length;
        uint64_t cand = xfer_cand(0xE2B00000u, i, 1u);

        /* §1.1.1: STAMP_FIELDS creates exactly one E2E prep pair. */
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_STAMP_FIELDS, owner, cand,
            NINLIL_R7_FRAG_PROD_LAYER_E2E_BLOB, (uint8_t)i);

        memset(&el, 0, sizeof(el));
        spy(bind, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
        nst = ninlil_n6_tx_burn(
            bind->n6, bind->e2e_handle, NINLIL_N6_LANE_E2E, &el);
        if (nst != NINLIL_N6_OK) {
            ninlil_r7_frag_prod_xfer_zeroize(xfer);
            return NINLIL_R7_FRAG_PROD_N6;
        }
        if (el.context_id != e2e_context_id) {
            (void)ninlil_n6_tx_lease_release(bind->n6, &el);
            ninlil_r7_frag_prod_xfer_zeroize(xfer);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        xfer->e2e_counter[i] = el.counter;
        xfer->e2e_prep_burns[i] = 1u;
        memset(&ef, 0, sizeof(ef));
        ef.e2e_context_id = el.context_id;
        ef.e2e_counter = el.counter;
        if (i == 0u) {
            ninlil_r7_frag_start_body sb;
            xfer->transfer_handle = el.counter;
            memset(&sb, 0, sizeof(sb));
            memcpy(sb.transfer_id, transfer_id, 16u);
            sb.transfer_handle = el.counter;
            sb.total_len = (uint32_t)payload_len;
            sb.frag_count = plan.frag_count;
            sb.continuation_unit = 180u;
            memcpy(sb.content_digest, xfer->content_digest, 32u);
            if (ninlil_r7_frag_start_fingerprint(
                    bind->crypto, &sb, chunk, clen, xfer->fingerprint)
                != NINLIL_R7_FRAG_OK) {
                (void)ninlil_n6_tx_lease_release(bind->n6, &el);
                ninlil_r7_frag_prod_xfer_zeroize(xfer);
                return NINLIL_R7_FRAG_PROD_WIRE;
            }
            ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
            {
                size_t need = 14u + 64u + clen + 16u;
                if (need > sizeof(xfer->e2e_blob[i])) {
                    (void)ninlil_n6_tx_lease_release(bind->n6, &el);
                    ninlil_r7_frag_prod_xfer_zeroize(xfer);
                    return NINLIL_R7_FRAG_PROD_WIRE;
                }
                fst = ninlil_r7_frag_seal_e2e_start(
                    bind->crypto, el.key16, el.iv12, &ef, &sb, chunk, clen,
                    xfer->e2e_blob[i], need, &elen);
            }
        } else {
            ninlil_r7_frag_cont_body cb;
            memset(&cb, 0, sizeof(cb));
            cb.transfer_handle = xfer->transfer_handle;
            cb.frag_index = i;
            ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_CONT;
            {
                size_t need = 14u + 10u + clen + 16u;
                if (need > sizeof(xfer->e2e_blob[i])) {
                    (void)ninlil_n6_tx_lease_release(bind->n6, &el);
                    ninlil_r7_frag_prod_xfer_zeroize(xfer);
                    return NINLIL_R7_FRAG_PROD_WIRE;
                }
                fst = ninlil_r7_frag_seal_e2e_cont(
                    bind->crypto, el.key16, el.iv12, &ef, &cb, chunk, clen,
                    xfer->e2e_blob[i], need, &elen);
            }
        }
        (void)ninlil_n6_tx_lease_release(bind->n6, &el);
        if (fst != NINLIL_R7_FRAG_OK || elen == 0u || elen > 220u) {
            (void)ninlil_r7_frag_l1w1_emit(
                bind->bus, bind->spy, NINLIL_R7_FRAG_EV_SEAL_FAIL, owner, cand,
                NINLIL_R7_FRAG_PROD_LAYER_E2E_BLOB, (uint8_t)i);
            ninlil_r7_frag_prod_xfer_zeroize(xfer);
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        xfer->e2e_len[i] = (uint16_t)elen;
        /* FRAME_READY E2E_BLOB: L1 owns sealed E2E; no Permit/R1 for this pair. */
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_FRAME_READY, owner, cand,
            NINLIL_R7_FRAG_PROD_LAYER_E2E_BLOB, (uint8_t)i);
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_tx_frag_air(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint16_t frag_index,
    uint64_t owner_token,
    uint64_t candidate_token,
    uint32_t hop_context_id,
    uint8_t ack_requested,
    ninlil_r7_frag_prod_tx_result_t *out)
{
    int32_t st;
    uint8_t air_ack;

    if (bind == NULL || xfer == NULL || out == NULL || !xfer->live
        || frag_index >= xfer->plan.frag_count
        || xfer->e2e_len[frag_index] == 0u) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out, 0, sizeof(*out));
    if (xfer->complete || xfer->aborted) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    if (xfer->frag_acked[frag_index] != 0u) {
        return NINLIL_R7_FRAG_PROD_ADMISSION; /* already acked / done */
    }
    if (xfer->hop_attempts[frag_index] >= NINLIL_R7_FRAG_HOP_ATTEMPT_MAX) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    if (xfer->outer_attempts[frag_index] >= NINLIL_R7_FRAG_OUTER_ATTEMPT_MAX) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    /* Refresh authority time from PCP before gate decisions (not caller int). */
    if (bind->pcp != NULL) {
        (void)refresh_r2_time_from_pcp(bind);
    }
    if (bind->r2_now_valid == 0u) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    if (bind->r2_now_ms >= xfer->sender_absolute_deadline) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    if (xfer->link_group_live[frag_index] != 0u
        && bind->r2_now_ms >= xfer->link_group_deadline_ms[frag_index]) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    if (xfer->eligible_at[frag_index] != 0u
        && bind->r2_now_ms < xfer->eligible_at[frag_index]) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    /* Per-air ack_requested (not begin-hardcoded). */
    air_ack = (ack_requested != 0u) ? 1u
        : ((xfer->ack_requested_default != 0u) ? 1u : 0u);

    /*
     * Prepared candidate reuse (docs/30 §15.3): R1/R2 denial keeps immutable
     * outer + issue_calls≤8 without burning a fresh hop counter.
     */
    if (xfer->prepared_live[frag_index] != 0u
        && xfer->last_outer_len[frag_index] > 0u
        && xfer->prepared_ack_requested[frag_index] == air_ack) {
        if (xfer->issue_calls[frag_index] >= NINLIL_R7_ISSUE_RETRY_MAX) {
            return NINLIL_R7_FRAG_PROD_RESOURCE;
        }
        memcpy(out->outer, xfer->last_outer[frag_index],
            xfer->last_outer_len[frag_index]);
        out->outer_len = xfer->last_outer_len[frag_index];
        out->hop_counter = xfer->last_hop_counter[frag_index];
        xfer->issue_calls[frag_index] =
            (uint8_t)(xfer->issue_calls[frag_index] + 1u);
        st = issue_and_tx(bind, owner_token, candidate_token, out);
        /* Always arm +100ms after any prepared issue attempt (docs/30). */
        if (bind->r2_now_valid != 0u
            && bind->r2_now_ms <= UINT64_MAX - NINLIL_R7_ISSUE_RETRY_BACKOFF_MS) {
            xfer->eligible_at[frag_index] =
                bind->r2_now_ms + NINLIL_R7_ISSUE_RETRY_BACKOFF_MS;
        }
        /* CU/AMBIGUOUS drain: fence prepared — no same-outer reissue. */
        if (out->cleanup_class == NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN
            || out->cleanup_class == NINLIL_R7_FRAG_CLN_ISSUED_DRAIN) {
            xfer->prepared_live[frag_index] = 0u;
        }
        /* ISSUED_HELD: keep prepared + coordinator identity for exact resume. */
        if (st == NINLIL_R7_FRAG_PROD_OK
            && out->cleanup_class == NINLIL_R7_FRAG_CLN_OK_COMPLETE) {
            xfer->prepared_live[frag_index] = 0u;
            xfer->eligible_at[frag_index] = 0u;
            if (out->edge_invoked != 0u) {
                (void)ninlil_r7_frag_prod_tx_frag_note_air(
                    bind, xfer, frag_index, out->hop_counter);
            }
        }
        /* Unissued R2/R1 deny or held: retain prepared (no hop re-burn). */
        return st;
    }

    st = ninlil_r7_frag_prod_tx_outer_from_e2e(
        bind, owner_token, candidate_token, xfer->e2e_blob[frag_index],
        xfer->e2e_len[frag_index], hop_context_id, air_ack, 0u, 0u, out);
    if (st != NINLIL_R7_FRAG_PROD_OK
        && st != NINLIL_R7_FRAG_PROD_R2
        && st != NINLIL_R7_FRAG_PROD_R1
        && st != NINLIL_R7_FRAG_PROD_ADMISSION) {
        return st;
    }
    /* Outer sealed ⇒ prepared only when unissued/held — never after drain. */
    if (out->outer_len > 0u && out->outer_len <= 255u && out->outer[0] == 0x11u) {
        xfer->outer_attempts[frag_index] =
            (uint8_t)(xfer->outer_attempts[frag_index] + 1u);
        xfer->last_hop_counter[frag_index] = out->hop_counter;
        xfer->last_outer_len[frag_index] = (uint16_t)out->outer_len;
        memcpy(xfer->last_outer[frag_index], out->outer, out->outer_len);
        xfer->prepared_ack_requested[frag_index] = air_ack;
        xfer->issue_calls[frag_index] = 1u; /* first issue call already done */
        /* Arm immutable LINK group deadline from R2 sample (once per group). */
        if (xfer->link_group_live[frag_index] == 0u
            && bind->r2_now_valid != 0u
            && bind->r2_now_ms
                <= UINT64_MAX - NINLIL_R7_FRAG_LINK_GROUP_TTL_MS) {
            xfer->link_group_start_ms[frag_index] = bind->r2_now_ms;
            xfer->link_group_deadline_ms[frag_index] =
                bind->r2_now_ms + NINLIL_R7_FRAG_LINK_GROUP_TTL_MS;
            xfer->link_group_live[frag_index] = 1u;
        }
        if (out->cleanup_class == NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN
            || out->cleanup_class == NINLIL_R7_FRAG_CLN_ISSUED_DRAIN) {
            /* Issued/ambiguous terminal: fence — no same-outer reissue. */
            xfer->prepared_live[frag_index] = 0u;
        } else if (out->cleanup_class == NINLIL_R7_FRAG_CLN_OK_COMPLETE) {
            xfer->prepared_live[frag_index] = 0u;
            xfer->eligible_at[frag_index] = 0u;
        } else if (out->cleanup_class == NINLIL_R7_FRAG_CLN_ISSUED_HELD
            || out->cleanup_class == NINLIL_R7_FRAG_CLN_UNISSUED_DROP
            || st == NINLIL_R7_FRAG_PROD_R2
            || st == NINLIL_R7_FRAG_PROD_R1
            || st == NINLIL_R7_FRAG_PROD_ADMISSION) {
            /* Held issued or unissued deny: reuse same outer without hop re-burn. */
            xfer->prepared_live[frag_index] = 1u;
            if (bind->r2_now_valid != 0u
                && bind->r2_now_ms
                    <= UINT64_MAX - NINLIL_R7_ISSUE_RETRY_BACKOFF_MS) {
                xfer->eligible_at[frag_index] =
                    bind->r2_now_ms + NINLIL_R7_ISSUE_RETRY_BACKOFF_MS;
            }
        } else {
            xfer->prepared_live[frag_index] = 0u;
        }
    }
    if (st == NINLIL_R7_FRAG_PROD_OK
        && out->cleanup_class == NINLIL_R7_FRAG_CLN_OK_COMPLETE) {
        xfer->prepared_live[frag_index] = 0u;
        xfer->eligible_at[frag_index] = 0u;
        if (out->edge_invoked != 0u) {
            (void)ninlil_r7_frag_prod_tx_frag_note_air(
                bind, xfer, frag_index, out->hop_counter);
        }
    }
    return st;
}

int32_t ninlil_r7_frag_prod_tx_frag_note_air(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint16_t frag_index,
    uint64_t hop_counter)
{
    uint64_t now;
    uint64_t ack_dl;
    uint64_t int_at;

    if (bind == NULL || xfer == NULL || !xfer->live) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (frag_index >= xfer->plan.frag_count) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    (void)hop_counter;
    if (xfer->hop_attempts[frag_index] >= NINLIL_R7_FRAG_HOP_ATTEMPT_MAX) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    xfer->hop_attempts[frag_index] =
        (uint8_t)(xfer->hop_attempts[frag_index] + 1u);
    now = (bind->r2_now_valid != 0u) ? bind->r2_now_ms : bind->trusted_now_ms;
    /* Per-air ack_requested (prepared_ack_requested or default). */
    if (xfer->prepared_ack_requested[frag_index] != 0u
        || xfer->ack_requested_default != 0u) {
        if (now > UINT64_MAX - NINLIL_R7_FRAG_LINK_ACK_WAIT_MS
            || now > UINT64_MAX - NINLIL_R7_FRAG_LINK_RETRY_INTERVAL_MS) {
            return NINLIL_R7_FRAG_PROD_RESOURCE;
        }
        ack_dl = now + NINLIL_R7_FRAG_LINK_ACK_WAIT_MS;
        int_at = now + NINLIL_R7_FRAG_LINK_RETRY_INTERVAL_MS;
        xfer->eligible_at[frag_index] = (ack_dl > int_at) ? ack_dl : int_at;
    } else {
        xfer->frag_acked[frag_index] = 1u;
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_tx_frag_apply_frag_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    const ninlil_r7_frag_ack_body *body)
{
    uint16_t i;
    int issued_live = 0;

    if (xfer == NULL || body == NULL || !xfer->live) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (body->transfer_handle != xfer->transfer_handle) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    if (ninlil_r7_frag_ack_rx_validate(
            xfer->plan.frag_count, xfer->transfer_handle, body)
        != NINLIL_R7_FRAG_OK) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    xfer->bitmap_from_frag_ack = body->received_bitmap;
    if (body->status == NINLIL_R7_FRAG_STATUS_COMPLETE) {
        xfer->complete = 1u;
        for (i = 0u; i < xfer->plan.frag_count; i++) {
            xfer->frag_acked[i] = 1u;
        }
    } else if (body->status == NINLIL_R7_FRAG_STATUS_ABORT) {
        xfer->aborted = 1u;
        xfer->complete = 1u;
        for (i = 0u; i < xfer->plan.frag_count; i++) {
            xfer->frag_acked[i] = 1u;
        }
    } else if (body->status == NINLIL_R7_FRAG_STATUS_PARTIAL) {
        for (i = 0u; i < xfer->plan.frag_count; i++) {
            if ((body->received_bitmap >> i) & 1u) {
                xfer->frag_acked[i] = 1u;
            }
        }
        return NINLIL_R7_FRAG_PROD_OK;
    } else {
        return NINLIL_R7_FRAG_PROD_OK;
    }

    /*
     * Three-way cleanup / TERMINAL_PENDING (docs/30 §15.3.8):
     * COMPLETE/ABORT ready while issued Permit or held TX live ⇒ freeze
     * terminal commit until drain converges. Do not local-erase xfer yet.
     */
    if (bind != NULL) {
        if (bind->held_tx_live != 0u || bind->ledger_count > 0u) {
            issued_live = 1;
        }
        if (ninlil_r7_frag_issue_coordinator_count(
                &bind->issue_coordinator)
                > 0u
            && bind->pcp != NULL
            && ninlil_r7_frag_issue_coordinator_head(
                &bind->issue_coordinator, bind_authority_token(bind))
                != 0u) {
            issued_live = 1;
        }
        if (issued_live != 0) {
            bind->terminal_pending = 1u;
            bind->terminal_status = body->status;
            bind->terminal_transfer_handle = body->transfer_handle;
            bind->terminal_frag_count = body->frag_count;
            bind->terminal_bitmap = body->received_bitmap;
            return NINLIL_R7_FRAG_PROD_ADMISSION; /* pending drain */
        }
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_tx_frag_e2e_retry(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint16_t frag_index,
    uint64_t owner_token,
    uint64_t candidate_token)
{
    ninlil_n6_tx_lease_t el;
    ninlil_n6_status_t nst;
    ninlil_r7_frag_status fst;
    ninlil_r7_frag_e2e_fields ef;
    size_t elen = 0u;
    const uint8_t *chunk;
    size_t clen;
    uint64_t cand;

    if (bind == NULL || xfer == NULL || !xfer->live
        || xfer->payload_owned_valid == 0u
        || frag_index >= xfer->plan.frag_count) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (xfer->complete || xfer->aborted) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    if (xfer->e2e_prep_burns[frag_index] >= NINLIL_R7_FRAG_E2E_PREP_MAX) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    if (bind->trusted_now_ms >= xfer->sender_absolute_deadline) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    cand = candidate_token != 0u ? candidate_token
                                 : xfer_cand(0xE2B00000u, frag_index, 2u);
    (void)ninlil_r7_frag_l1w1_emit(
        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_STAMP_FIELDS, owner_token, cand,
        NINLIL_R7_FRAG_PROD_LAYER_E2E_BLOB, (uint8_t)frag_index);

    chunk = xfer->payload_owned + xfer->plan.chunks[frag_index].offset;
    clen = xfer->plan.chunks[frag_index].length;
    memset(&el, 0, sizeof(el));
    spy(bind, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
    nst = ninlil_n6_tx_burn(bind->n6, bind->e2e_handle, NINLIL_N6_LANE_E2E, &el);
    if (nst != NINLIL_N6_OK) {
        return NINLIL_R7_FRAG_PROD_N6;
    }
    xfer->e2e_counter[frag_index] = el.counter;
    xfer->e2e_prep_burns[frag_index] =
        (uint8_t)(xfer->e2e_prep_burns[frag_index] + 1u);
    xfer->hop_attempts[frag_index] = 0u;
    xfer->outer_attempts[frag_index] = 0u;
    xfer->frag_acked[frag_index] = 0u;
    xfer->eligible_at[frag_index] = 0u;
    /* Fresh E2E invalidates old prepared hop outer (docs/30). */
    xfer->prepared_live[frag_index] = 0u;
    xfer->prepared_ack_requested[frag_index] = 0u;
    xfer->issue_calls[frag_index] = 0u;
    xfer->last_outer_len[frag_index] = 0u;
    memset(xfer->last_outer[frag_index], 0, sizeof(xfer->last_outer[frag_index]));
    xfer->last_hop_counter[frag_index] = 0u;
    /* Fresh E2E ⇒ new LINK group (immutable deadline re-armed on next hop). */
    xfer->link_group_live[frag_index] = 0u;
    xfer->link_group_start_ms[frag_index] = 0u;
    xfer->link_group_deadline_ms[frag_index] = 0u;
    xfer->eligible_at[frag_index] = 0u;

    memset(&ef, 0, sizeof(ef));
    ef.e2e_context_id = xfer->e2e_context_id;
    ef.e2e_counter = el.counter;
    if (frag_index == 0u) {
        ninlil_r7_frag_start_body sb;
        size_t need;
        memset(&sb, 0, sizeof(sb));
        memcpy(sb.transfer_id, xfer->transfer_id, 16u);
        sb.transfer_handle = xfer->transfer_handle; /* retained */
        sb.total_len = xfer->plan.total_len;
        sb.frag_count = xfer->plan.frag_count;
        sb.continuation_unit = 180u;
        memcpy(sb.content_digest, xfer->content_digest, 32u);
        ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_START;
        need = 14u + 64u + clen + 16u;
        fst = ninlil_r7_frag_seal_e2e_start(
            bind->crypto, el.key16, el.iv12, &ef, &sb, chunk, clen,
            xfer->e2e_blob[frag_index], need, &elen);
    } else {
        ninlil_r7_frag_cont_body cb;
        size_t need;
        memset(&cb, 0, sizeof(cb));
        cb.transfer_handle = xfer->transfer_handle;
        cb.frag_index = frag_index;
        ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_CONT;
        need = 14u + 10u + clen + 16u;
        fst = ninlil_r7_frag_seal_e2e_cont(
            bind->crypto, el.key16, el.iv12, &ef, &cb, chunk, clen,
            xfer->e2e_blob[frag_index], need, &elen);
    }
    (void)ninlil_n6_tx_lease_release(bind->n6, &el);
    if (fst != NINLIL_R7_FRAG_OK || elen == 0u) {
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_SEAL_FAIL, owner_token,
            cand, NINLIL_R7_FRAG_PROD_LAYER_E2E_BLOB, (uint8_t)frag_index);
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    xfer->e2e_len[frag_index] = (uint16_t)elen;
    (void)ninlil_r7_frag_l1w1_emit(
        bind->bus, bind->spy, NINLIL_R7_FRAG_EV_FRAME_READY, owner_token, cand,
        NINLIL_R7_FRAG_PROD_LAYER_E2E_BLOB, (uint8_t)frag_index);
    return NINLIL_R7_FRAG_PROD_OK;
}

static int32_t refresh_r2_time_from_pcp(ninlil_r7_frag_prod_bind_t *bind)
{
    if (bind == NULL || bind->pcp == NULL) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    /*
     * Authority time only via bound PCP sample (mint once, then refresh).
     * Caller-injected integers cannot forge this path.
     */
    if (!time_authority_valid(bind)) {
        return ninlil_r7_frag_prod_time_authority_mint(bind, NULL);
    }
    return ninlil_r7_frag_prod_time_authority_refresh(
        bind, bind->time_owner_gen);
}

int32_t ninlil_r7_frag_prod_tx_frag_tick(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint64_t now_ms)
{
    int32_t st;
    /*
     * Caller-injected now_ms is NOT gate authority (docs/30). Tick refreshes
     * time only via PCP class-D sample.
     */
    (void)now_ms;
    if (bind == NULL || xfer == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    st = refresh_r2_time_from_pcp(bind);
    if (st != NINLIL_R7_FRAG_PROD_OK) {
        return st;
    }
    if (!xfer->live) {
        return NINLIL_R7_FRAG_PROD_OK;
    }
    if (bind->r2_now_ms >= xfer->sender_absolute_deadline) {
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_tx_frag_complete(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_r7_frag_prod_xfer_t *xfer,
    uint64_t owner_token,
    uint64_t candidate_token)
{
    if (bind == NULL || xfer == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    /*
     * TERMINAL_PENDING: drain issued work first; only after DRAIN_OK may
     * xfer be zeroized. Never local-erase while held/issued live.
     */
    if (bind->held_tx_live != 0u || bind->ledger_count > 0u) {
        int32_t st;
        if (bind->pcp == NULL) {
            return NINLIL_R7_FRAG_PROD_UNBOUND;
        }
        st = ninlil_r7_frag_prod_cleanup(
            bind, NINLIL_R7_FRAG_CLN_ISSUED_DRAIN, 0u);
        if (st != NINLIL_R7_FRAG_PROD_OK) {
            return NINLIL_R7_FRAG_PROD_CLEANUP;
        }
    }
    bind->terminal_pending = 0u;
    bind->terminal_status = 0u;
    bind->terminal_transfer_handle = 0u;
    if (xfer->live != 0u) {
        (void)ninlil_r7_frag_l1w1_emit(
            bind->bus, bind->spy, NINLIL_R7_FRAG_EV_OWNER_TERMINAL, owner_token,
            candidate_token != 0u ? candidate_token : 1u, 0u, 0u);
    }
    ninlil_r7_frag_prod_xfer_zeroize(xfer);
    return NINLIL_R7_FRAG_PROD_OK;
}

size_t ninlil_r7_frag_prod_link_ack_pending_count(
    const ninlil_r7_frag_prod_bind_t *bind)
{
    size_t i;
    size_t n = 0u;
    if (bind == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_PROD_LINK_ACK_PENDING_CAP; i++) {
        if (bind->link_ack_pending[i].live != 0u) {
            n++;
        }
    }
    return n;
}

int32_t ninlil_r7_frag_prod_link_ack_note_rx_data(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t hop_ack_context_id,
    uint32_t acked_hop_data_context_id,
    uint64_t acked_hop_counter)
{
    /* Public note must not invent pending without E2E admission proof. */
    return ninlil_r7_frag_prod_link_ack_note_after_e2e(
        bind, hop_ack_context_id, acked_hop_data_context_id, acked_hop_counter,
        0u /* e2e_admitted */);
}

int32_t ninlil_r7_frag_prod_link_ack_note_after_e2e(
    ninlil_r7_frag_prod_bind_t *bind,
    uint32_t hop_ack_context_id,
    uint32_t acked_hop_data_context_id,
    uint64_t acked_hop_counter,
    uint8_t e2e_admitted)
{
    size_t i;
    if (bind == NULL || hop_ack_context_id == 0u
        || acked_hop_data_context_id == 0u || acked_hop_counter == 0u
        || acked_hop_counter == UINT64_MAX) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    /* Exact nonzero reverse pair; no invent without E2E admission. */
    if (e2e_admitted == 0u) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    if (bind->hop_ack_handle == 0u || bind->hop_ack_context_id == 0u) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    if (hop_ack_context_id != bind->hop_ack_context_id) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    for (i = 0u; i < NINLIL_R7_FRAG_PROD_LINK_ACK_PENDING_CAP; i++) {
        ninlil_r7_frag_prod_link_ack_pending_t *P = &bind->link_ack_pending[i];
        if (P->live == 0u) {
            memset(P, 0, sizeof(*P));
            P->live = 1u;
            P->hop_ack_context_id = hop_ack_context_id;
            P->acked_hop_data_context_id = acked_hop_data_context_id;
            P->ack_base_counter = acked_hop_counter;
            P->ack_bitmap = 0x0001u;
            return NINLIL_R7_FRAG_PROD_OK;
        }
    }
    return NINLIL_R7_FRAG_PROD_RESOURCE;
}

int32_t ninlil_r7_frag_prod_link_ack_prepare(
    ninlil_r7_frag_prod_bind_t *bind,
    size_t pending_index,
    uint64_t owner_token,
    uint64_t candidate_token)
{
    ninlil_r7_frag_prod_link_ack_pending_t *P;
    ninlil_n6_tx_lease_t hop_lease;
    ninlil_n6_status_t nst;
    ninlil_r7_frag_status fst;
    ninlil_r7_frag_outer_link_ack_fields outer_f;
    ninlil_r7_frag_link_ack_body body;
    size_t flen = 0u;
    int32_t cg;

    if (bind == NULL || owner_token == 0u || candidate_token == 0u
        || pending_index >= NINLIL_R7_FRAG_PROD_LINK_ACK_PENDING_CAP) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    P = &bind->link_ack_pending[pending_index];
    if (P->live == 0u) {
        return NINLIL_R7_FRAG_PROD_ADMISSION; /* no RX-driven pending */
    }
    if (P->prepared != 0u) {
        return NINLIL_R7_FRAG_PROD_ADMISSION; /* already prepared */
    }
    if (bind->n6 == NULL || bind->crypto == NULL || bind->hop_ack_handle == 0u) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    cg = clock_gate(bind);
    if (cg != NINLIL_R7_FRAG_PROD_OK) {
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    memset(&body, 0, sizeof(body));
    body.acked_hop_context_id = P->acked_hop_data_context_id;
    body.ack_base_counter = P->ack_base_counter;
    body.ack_bitmap = P->ack_bitmap;
    body.ack_code = 0u;
    if (ninlil_r7_frag_link_ack_body_validate(&body) != NINLIL_R7_FRAG_OK) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    memset(&hop_lease, 0, sizeof(hop_lease));
    spy(bind, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
    nst = ninlil_n6_tx_burn(
        bind->n6, bind->hop_ack_handle, NINLIL_N6_LANE_HOP_ACK, &hop_lease);
    if (nst != NINLIL_N6_OK) {
        return NINLIL_R7_FRAG_PROD_N6;
    }
    if (hop_lease.context_id != P->hop_ack_context_id) {
        (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    memset(&outer_f, 0, sizeof(outer_f));
    outer_f.hop_context_id = hop_lease.context_id;
    outer_f.hop_counter = hop_lease.counter;
    fst = ninlil_r7_frag_seal_outer_link_ack(
        bind->crypto, hop_lease.key16, hop_lease.iv12, &outer_f, &body,
        P->outer, &flen);
    (void)ninlil_n6_tx_lease_release(bind->n6, &hop_lease);
    if (fst != NINLIL_R7_FRAG_OK || flen != NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN
        || P->outer[0] != 0x11u) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    P->outer_len = flen;
    P->prepared = 1u;
    P->owner_token = owner_token;
    P->candidate_token = candidate_token;
    P->issue_calls = 0u;
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_tx_link_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    size_t pending_index,
    ninlil_r7_frag_prod_tx_result_t *out)
{
    ninlil_r7_frag_prod_link_ack_pending_t *P;
    int32_t st;

    if (bind == NULL || out == NULL
        || pending_index >= NINLIL_R7_FRAG_PROD_LINK_ACK_PENDING_CAP) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out, 0, sizeof(*out));
    P = &bind->link_ack_pending[pending_index];
    if (P->live == 0u || P->prepared == 0u) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    if (P->issue_calls >= NINLIL_R7_ISSUE_RETRY_MAX) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_RESOURCE;
    }
    if (bind->pcp == NULL || bind->hal == NULL || !bind->live_valid) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    /* LINK_ACK issue +100ms backoff (docs/30). */
    if (P->issue_retry_at != 0u
        && (bind->r2_now_valid == 0u
            || bind->r2_now_ms < P->issue_retry_at)) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    memcpy(out->outer, P->outer, P->outer_len);
    out->outer_len = P->outer_len;
    P->issue_calls = (uint8_t)(P->issue_calls + 1u);
    st = issue_and_tx(bind, P->owner_token, P->candidate_token, out);
    P->cleanup_class = out->cleanup_class;
    if (bind->r2_now_valid != 0u
        && bind->r2_now_ms <= UINT64_MAX - NINLIL_R7_ISSUE_RETRY_BACKOFF_MS) {
        P->issue_retry_at = bind->r2_now_ms + NINLIL_R7_ISSUE_RETRY_BACKOFF_MS;
    }
    if (st == NINLIL_R7_FRAG_PROD_OK
        && out->cleanup_class == NINLIL_R7_FRAG_CLN_OK_COMPLETE) {
        /* Terminal success: consume pending — no reissue of same prepared. */
        memset(P, 0, sizeof(*P));
    } else if (out->cleanup_class == NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN
        || out->cleanup_class == NINLIL_R7_FRAG_CLN_ISSUED_DRAIN
        || out->cleanup_class == NINLIL_R7_FRAG_CLN_EDGE_STALE
        || out->cleanup_class == NINLIL_R7_FRAG_CLN_CLOCK_DROP
        || out->cleanup_class == NINLIL_R7_FRAG_CLN_EPOCH_DROP) {
        /* Drain/terminal: fence prepared so same outer cannot reissue. */
        P->prepared = 0u;
        P->outer_len = 0u;
        memset(P->outer, 0, sizeof(P->outer));
        P->live = 0u;
    }
    /* ISSUED_HELD / UNISSUED_DROP: retain prepared for exact-object retry. */
    return st;
}

int32_t ninlil_r7_frag_prod_rx_link_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    const uint8_t *frame,
    size_t frame_len,
    uint32_t hop_ack_context_id,
    uint32_t expected_acked_hop_data_context_id,
    ninlil_r7_frag_prod_xfer_t *xfer,
    ninlil_r7_frag_link_ack_body *out_body)
{
    ninlil_n6_rx_ticket_t hop_ticket;
    ninlil_n6_status_t nst;
    ninlil_r7_frag_status fst;
    ninlil_r7_frag_outer_link_ack_fields lo;
    ninlil_r7_frag_link_ack_body lb;
    uint64_t hop_ctr;
    uint32_t decoded_ctx;
    uint16_t fi;

    if (bind == NULL || frame == NULL || out_body == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out_body, 0, sizeof(*out_body));
    memset(&hop_ticket, 0, sizeof(hop_ticket));
    if (bind->n6 == NULL || bind->crypto == NULL
        || bind->hop_ack_handle == 0u) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    if (frame_len != NINLIL_R7_FRAG_LINK_ACK_OUTER_LEN || frame[0] != 0x11u) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    decoded_ctx = ((uint32_t)frame[3] << 24) | ((uint32_t)frame[4] << 16)
        | ((uint32_t)frame[5] << 8) | (uint32_t)frame[6];
    hop_ctr = ((uint64_t)frame[7] << 56) | ((uint64_t)frame[8] << 48)
        | ((uint64_t)frame[9] << 40) | ((uint64_t)frame[10] << 32)
        | ((uint64_t)frame[11] << 24) | ((uint64_t)frame[12] << 16)
        | ((uint64_t)frame[13] << 8) | (uint64_t)frame[14];
    if (decoded_ctx != hop_ack_context_id || hop_ctr == 0u
        || hop_ctr == UINT64_MAX) {
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    nst = ninlil_n6_rx_precheck(
        bind->n6, bind->hop_ack_handle, NINLIL_N6_LANE_HOP_ACK, hop_ctr,
        &hop_ticket);
    if (nst != NINLIL_N6_OK) {
        return NINLIL_R7_FRAG_PROD_N6;
    }
    if (hop_ticket.context_id != hop_ack_context_id) {
        (void)ninlil_n6_rx_abort(bind->n6, &hop_ticket);
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    fst = ninlil_r7_frag_open_outer_link_ack(
        bind->crypto, hop_ticket.key16, hop_ticket.iv12, frame, frame_len, &lo,
        &lb);
    if (fst != NINLIL_R7_FRAG_OK
        || lo.hop_context_id != hop_ticket.context_id) {
        (void)ninlil_n6_rx_abort(bind->n6, &hop_ticket);
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    /* Exact reverse-pair bind required — zero is not a bypass. */
    if (expected_acked_hop_data_context_id == 0u
        || lb.acked_hop_context_id != expected_acked_hop_data_context_id) {
        (void)ninlil_n6_rx_abort(bind->n6, &hop_ticket);
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    nst = ninlil_n6_rx_admit_after_aead(bind->n6, &hop_ticket);
    if (nst != NINLIL_N6_OK) {
        return NINLIL_R7_FRAG_PROD_N6;
    }
    *out_body = lb;
    /* Sender closed-loop: cover pending hop counters on live xfer. */
    if (xfer != NULL && xfer->live != 0u) {
        for (fi = 0u; fi < xfer->plan.frag_count; fi++) {
            uint64_t c = xfer->last_hop_counter[fi];
            if (c == 0u || xfer->frag_acked[fi] != 0u) {
                continue;
            }
            if (c > lb.ack_base_counter) {
                continue;
            }
            {
                uint64_t d = lb.ack_base_counter - c;
                if (d < 16u && ((lb.ack_bitmap >> d) & 1u) != 0u) {
                    xfer->frag_acked[fi] = 1u;
                }
            }
        }
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

int32_t ninlil_r7_frag_prod_tx_frag_ack(
    ninlil_r7_frag_prod_bind_t *bind,
    uint64_t owner_token,
    uint64_t candidate_token,
    uint32_t e2e_context_id,
    uint32_t hop_context_id,
    const ninlil_r7_frag_ack_body *ack,
    uint8_t outer_ack_requested,
    ninlil_r7_frag_prod_tx_result_t *out)
{
    ninlil_n6_tx_lease_t e2e_lease;
    ninlil_n6_status_t nst;
    ninlil_r7_frag_status fst;
    ninlil_r7_frag_e2e_fields ef;
    ninlil_r7_frag_ack_identity_t id;
    uint8_t e2e_blob[64];
    size_t e2e_len = 0u;
    int32_t cg;
    int32_t lst;
    int32_t outer_st;
    uint64_t owner_exp;
    uint8_t istate;

    if (bind == NULL || ack == NULL || out == NULL || owner_token == 0u
        || candidate_token == 0u) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    memset(out, 0, sizeof(*out));
    memset(&e2e_lease, 0, sizeof(e2e_lease));
    if (bind->n6 == NULL || bind->pcp == NULL || bind->hal == NULL
        || bind->crypto == NULL || !bind->live_valid
        || bind->ack_ledger == NULL) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    cg = clock_gate(bind);
    if (cg != NINLIL_R7_FRAG_PROD_OK) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_CLOCK_DROP;
        return NINLIL_R7_FRAG_PROD_CLOCK;
    }
    {
        uint8_t ack_pt[NINLIL_R7_FRAG_ACK_PT_LEN];
        fst = ninlil_r7_frag_pack_ack_pt(ack, ack_pt);
        if (fst != NINLIL_R7_FRAG_OK) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
    }
    ninlil_r7_frag_ack_identity_from_body(
        &id, ack->transfer_handle, ack->frag_count, ack->received_bitmap,
        ack->status, ack->reason);
    istate = ninlil_r7_frag_ack_intent_state(bind->ack_ledger);

    /*
     * Resume SEAL after ALL_PROPOSED: use preserved counter/key/IV — no reburn,
     * no owner TTL rewrite, no intent re-arm.
     */
    if (istate == NINLIL_R7_FRAG_INTENT_SEAL
        && bind->frag_ack_cu_live != 0u
        && bind->ack_ledger->intent_id.transfer_handle == id.transfer_handle
        && bind->ack_ledger->intent_id.received_bitmap == id.received_bitmap
        && bind->ack_ledger->intent_id.status == id.status) {
        memset(&ef, 0, sizeof(ef));
        ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_ACK;
        ef.e2e_context_id = bind->frag_ack_cu_e2e_context_id != 0u
            ? bind->frag_ack_cu_e2e_context_id
            : e2e_context_id;
        ef.e2e_counter = bind->frag_ack_cu_counter;
        fst = ninlil_r7_frag_seal_e2e_ack(
            bind->crypto, bind->frag_ack_cu_key16, bind->frag_ack_cu_iv12, &ef,
            &bind->frag_ack_cu_body, e2e_blob, 44u, &e2e_len);
        if (fst != NINLIL_R7_FRAG_OK || e2e_len == 0u) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            return NINLIL_R7_FRAG_PROD_WIRE;
        }
        bind->frag_ack_sealed_live = 1u;
        bind->frag_ack_sealed_len = e2e_len;
        memcpy(bind->frag_ack_sealed, e2e_blob, e2e_len);
        (void)ninlil_r7_frag_ack_intent_enter_link(bind->ack_ledger);
        outer_st = ninlil_r7_frag_prod_tx_outer_from_e2e(
            bind, owner_token, candidate_token, e2e_blob, e2e_len,
            bind->frag_ack_cu_hop_context_id != 0u
                ? bind->frag_ack_cu_hop_context_id
                : hop_context_id,
            outer_ack_requested, 0u, 0u, out);
        /* Terminal ACKED only after protocol ACK of outer if requested. */
        if (outer_st == NINLIL_R7_FRAG_PROD_OK
            && out->cleanup_class == NINLIL_R7_FRAG_CLN_OK_COMPLETE
            && outer_ack_requested == 0u) {
            (void)ninlil_r7_frag_ack_intent_mark_acked(bind->ack_ledger);
            bind->frag_ack_cu_live = 0u;
            bind->frag_ack_sealed_live = 0u;
        }
        return outer_st;
    }

    /* BURN_CU live: refuse re-arm/reburn; classify first. */
    if (istate == NINLIL_R7_FRAG_INTENT_BURN_CU) {
        out->cleanup_class = NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }

    /* Fresh path: arm intent once with immutable owner deadline. */
    if (bind->frag_ack_owner_deadline_ms == 0u) {
        owner_exp = bind->trusted_now_ms;
        if (owner_exp <= UINT64_MAX - NINLIL_R7_FRAG_RECEIVER_TTL_MS) {
            owner_exp = owner_exp + NINLIL_R7_FRAG_RECEIVER_TTL_MS;
        } else {
            owner_exp = UINT64_MAX;
        }
        bind->frag_ack_owner_deadline_ms = owner_exp;
    } else {
        owner_exp = bind->frag_ack_owner_deadline_ms;
    }
    ninlil_r7_frag_ack_ledger_bind_owner(
        bind->ack_ledger, ack->transfer_handle, ack->frag_count, owner_exp);
    if (istate == NINLIL_R7_FRAG_INTENT_IDLE
        || istate == NINLIL_R7_FRAG_INTENT_ACKED
        || istate == NINLIL_R7_FRAG_INTENT_DROP) {
        lst = ninlil_r7_frag_ack_intent_arm_pending(
            bind->ack_ledger, &id, bind->trusted_now_ms, owner_exp);
        if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            return NINLIL_R7_FRAG_PROD_ADMISSION;
        }
        bind->ack_ledger->partial_ack_due = bind->trusted_now_ms;
        (void)ninlil_r7_frag_ack_intent_tick(
            bind->ack_ledger, bind->trusted_now_ms);
        lst = ninlil_r7_frag_ack_intent_enter_reserve(bind->ack_ledger);
        if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            return NINLIL_R7_FRAG_PROD_ADMISSION;
        }
    } else if (istate == NINLIL_R7_FRAG_INTENT_RESERVE
        || istate == NINLIL_R7_FRAG_INTENT_RETRY
        || istate == NINLIL_R7_FRAG_INTENT_DUE) {
        /* Same identity resume — do not re-arm / extend TTL. */
        if (bind->ack_ledger->intent_id.transfer_handle != id.transfer_handle
            || bind->ack_ledger->intent_id.received_bitmap != id.received_bitmap
            || bind->ack_ledger->intent_id.status != id.status) {
            out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
            return NINLIL_R7_FRAG_PROD_ADMISSION;
        }
        if (istate != NINLIL_R7_FRAG_INTENT_RESERVE) {
            if (istate == NINLIL_R7_FRAG_INTENT_RETRY
                || istate == NINLIL_R7_FRAG_INTENT_DUE) {
                (void)ninlil_r7_frag_ack_intent_tick(
                    bind->ack_ledger, bind->trusted_now_ms);
                if (ninlil_r7_frag_ack_intent_state(bind->ack_ledger)
                    == NINLIL_R7_FRAG_INTENT_DUE) {
                    lst = ninlil_r7_frag_ack_intent_enter_reserve(
                        bind->ack_ledger);
                    if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
                        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
                        return NINLIL_R7_FRAG_PROD_ADMISSION;
                    }
                }
            }
        }
    }

    lst = ninlil_r7_frag_ack_ledger_may_burn(
        bind->ack_ledger, &id, bind->trusted_now_ms);
    if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        (void)ninlil_r7_frag_ack_intent_mark_drop(bind->ack_ledger);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    spy(bind, NINLIL_R7_FRAG_SPY_N6_TX_BURN);
    nst = ninlil_n6_tx_burn(
        bind->n6, bind->e2e_handle, NINLIL_N6_LANE_E2E, &e2e_lease);
    out->n6_status = nst;
    if (nst == NINLIL_N6_COMMIT_UNKNOWN) {
        /*
         * Preserve lease material if provider left it (best-effort) and
         * immutable intent identity for ALL_PROPOSED SEAL resume.
         */
        bind->ack_ledger->intent_state = NINLIL_R7_FRAG_INTENT_BURN_CU;
        bind->frag_ack_cu_live = 1u;
        bind->frag_ack_cu_e2e_context_id = e2e_context_id;
        bind->frag_ack_cu_hop_context_id = hop_context_id;
        bind->frag_ack_cu_body = *ack;
        if (e2e_lease.counter != 0u) {
            bind->frag_ack_cu_counter = e2e_lease.counter;
            memcpy(bind->frag_ack_cu_key16, e2e_lease.key16, 16u);
            memcpy(bind->frag_ack_cu_iv12, e2e_lease.iv12, 12u);
        }
        out->cleanup_class = NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN;
        return NINLIL_R7_FRAG_PROD_N6;
    }
    if (nst != NINLIL_N6_OK) {
        (void)ninlil_r7_frag_ack_intent_mark_drop(bind->ack_ledger);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_N6;
    }
    /* Preserve identity for potential later CU path / seal resume. */
    bind->frag_ack_cu_live = 1u;
    bind->frag_ack_cu_counter = e2e_lease.counter;
    bind->frag_ack_cu_e2e_context_id = e2e_context_id;
    bind->frag_ack_cu_hop_context_id = hop_context_id;
    bind->frag_ack_cu_body = *ack;
    memcpy(bind->frag_ack_cu_key16, e2e_lease.key16, 16u);
    memcpy(bind->frag_ack_cu_iv12, e2e_lease.iv12, 12u);

    lst = ninlil_r7_frag_ack_intent_after_burn_ok(
        bind->ack_ledger, bind->trusted_now_ms);
    if (lst != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
        (void)ninlil_n6_tx_lease_release(bind->n6, &e2e_lease);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    out->e2e_counter = e2e_lease.counter;
    memset(&ef, 0, sizeof(ef));
    ef.e2e_type = NINLIL_R7_FRAG_E2E_TYPE_ACK;
    ef.e2e_context_id = e2e_context_id;
    ef.e2e_counter = e2e_lease.counter;
    fst = ninlil_r7_frag_seal_e2e_ack(
        bind->crypto, e2e_lease.key16, e2e_lease.iv12, &ef, ack, e2e_blob, 44u,
        &e2e_len);
    (void)ninlil_n6_tx_lease_release(bind->n6, &e2e_lease);
    if (fst != NINLIL_R7_FRAG_OK || e2e_len == 0u) {
        (void)ninlil_r7_frag_ack_intent_retry_or_drop(
            bind->ack_ledger, bind->trusted_now_ms);
        out->cleanup_class = NINLIL_R7_FRAG_CLN_UNISSUED_DROP;
        return NINLIL_R7_FRAG_PROD_WIRE;
    }
    bind->frag_ack_sealed_live = 1u;
    bind->frag_ack_sealed_len = e2e_len;
    memcpy(bind->frag_ack_sealed, e2e_blob, e2e_len);
    (void)ninlil_r7_frag_ack_intent_enter_link(bind->ack_ledger);
    outer_st = ninlil_r7_frag_prod_tx_outer_from_e2e(
        bind, owner_token, candidate_token, e2e_blob, e2e_len, hop_context_id,
        outer_ack_requested, 0u, 0u, out);
    /*
     * Physical TX success alone is not protocol ACKED when outer LINK ACK
     * was requested. Leave INTENT_LINK until LINK_ACK covers the hop.
     */
    if (outer_st == NINLIL_R7_FRAG_PROD_OK
        && out->cleanup_class == NINLIL_R7_FRAG_CLN_OK_COMPLETE
        && outer_ack_requested == 0u) {
        (void)ninlil_r7_frag_ack_intent_mark_acked(bind->ack_ledger);
        bind->frag_ack_cu_live = 0u;
        bind->frag_ack_sealed_live = 0u;
    } else if (out->cleanup_class == NINLIL_R7_FRAG_CLN_AMBIGUOUS_DRAIN
        || out->cleanup_class == NINLIL_R7_FRAG_CLN_ISSUED_DRAIN
        || out->cleanup_class == NINLIL_R7_FRAG_CLN_ISSUED_HELD) {
        /* Leave intent + sealed identity for resume. */
    } else if (outer_st != NINLIL_R7_FRAG_PROD_OK) {
        (void)ninlil_r7_frag_ack_intent_retry_or_drop(
            bind->ack_ledger, bind->trusted_now_ms);
    }
    return outer_st;
}

int32_t ninlil_r7_frag_prod_frag_ack_classify_cu(
    ninlil_r7_frag_prod_bind_t *bind,
    ninlil_n6_cu_class_t *out_class)
{
    ninlil_n6_status_t st;
    ninlil_n6_error_t err;
    ninlil_n6_cu_class_t cls;

    if (bind == NULL || bind->n6 == NULL || bind->ack_ledger == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    if (bind->ack_ledger->intent_state != NINLIL_R7_FRAG_INTENT_BURN_CU) {
        return NINLIL_R7_FRAG_PROD_ADMISSION;
    }
    st = ninlil_n6_recover_cu(bind->n6);
    memset(&err, 0, sizeof(err));
    (void)ninlil_n6_last_error(bind->n6, &err);
    cls = err.last_cu_class;
    if (out_class != NULL) {
        *out_class = cls;
    }
    if (st == NINLIL_N6_BUSY_REENTRY || st == NINLIL_N6_INVALID_STATE) {
        /* RETRY_LATER: remain BURN_CU; identity preserved; no TTL extend. */
        return NINLIL_R7_FRAG_PROD_N6;
    }
    if (cls == NINLIL_N6_CU_ALL_PROPOSED) {
        /* Charge once → SEAL; keep key/IV/counter for seal resume. */
        uint64_t now = bind->r2_now_valid ? bind->r2_now_ms : bind->trusted_now_ms;
        if (ninlil_r7_frag_ack_ledger_charge_burn(
                bind->ack_ledger, &bind->ack_ledger->intent_id, now)
            != NINLIL_R7_FRAG_ACK_LEDGER_OK) {
            (void)ninlil_r7_frag_ack_intent_mark_drop(bind->ack_ledger);
            bind->frag_ack_cu_live = 0u;
            return NINLIL_R7_FRAG_PROD_ADMISSION;
        }
        bind->ack_ledger->intent_state = NINLIL_R7_FRAG_INTENT_SEAL;
        bind->frag_ack_cu_live = 1u;
        return NINLIL_R7_FRAG_PROD_OK;
    }
    if (cls == NINLIL_N6_CU_ALL_OLD) {
        bind->ack_ledger->intent_state = NINLIL_R7_FRAG_INTENT_RESERVE;
        /* Clear partial lease material; identity/deadline immutable. */
        memset(bind->frag_ack_cu_key16, 0, sizeof(bind->frag_ack_cu_key16));
        memset(bind->frag_ack_cu_iv12, 0, sizeof(bind->frag_ack_cu_iv12));
        bind->frag_ack_cu_counter = 0u;
        bind->frag_ack_cu_live = 0u;
        return NINLIL_R7_FRAG_PROD_OK;
    }
    (void)ninlil_r7_frag_ack_intent_mark_drop(bind->ack_ledger);
    bind->frag_ack_cu_live = 0u;
    bind->frag_ack_sealed_live = 0u;
    if (cls == NINLIL_N6_CU_THIRD || cls == NINLIL_N6_CU_MIXED) {
        return NINLIL_R7_FRAG_PROD_N6;
    }
    if (st != NINLIL_N6_OK) {
        return NINLIL_R7_FRAG_PROD_N6;
    }
    return NINLIL_R7_FRAG_PROD_OK;
}

void ninlil_r7_frag_prod_matrix_ws_zeroize(ninlil_r7_frag_prod_matrix_ws_t *ws)
{
    if (ws == NULL) {
        return;
    }
    memset(ws, 0, sizeof(*ws));
}

int32_t ninlil_r7_frag_prod_run_matrix(
    ninlil_r7_frag_prod_bind_t *tx_bind,
    ninlil_r7_frag_prod_bind_t *rx_bind,
    const uint8_t *app,
    size_t app_len,
    uint32_t e2e_context_id,
    uint32_t hop_context_id,
    ninlil_r7_frag_prod_matrix_cell_t *cells,
    size_t cells_cap,
    size_t *out_n)
{
    static const uint32_t channels[] = {1u, 3u};
    static const uint16_t routes[] = {0u, 7u};
    size_t n = 0u;
    size_t ci;
    size_t ri;
    uint8_t pass;
    ninlil_r7_frag_prod_matrix_ws_t *ws;

    if (tx_bind == NULL || cells == NULL || out_n == NULL || app == NULL) {
        return NINLIL_R7_FRAG_PROD_INVALID;
    }
    /* Caller/instance-owned workspace only — no process-global scratch. */
    ws = tx_bind->matrix_ws;
    if (ws == NULL) {
        return NINLIL_R7_FRAG_PROD_UNBOUND;
    }
    if (ws->live != 0u) {
        return NINLIL_R7_FRAG_PROD_ADMISSION; /* non-reentrant per instance */
    }
    ws->live = 1u;
    *out_n = 0u;

    /* 2 Permit concurrent admission pin: fill ledger to capacity. */
    for (pass = 0u; pass < 2u && n < cells_cap; pass++) {
        ninlil_r7_frag_prod_matrix_cell_t *c = &cells[n++];
        int32_t st;
        memset(c, 0, sizeof(*c));
        memset(&ws->tr, 0, sizeof(ws->tr));
        c->carrier = NINLIL_R7_FRAG_MX_CARRIER_LORA;
        c->channel_id = tx_bind->live.channel_id;
        c->owner_class = NINLIL_R7_FRAG_MX_CLASS_DATA;
        c->action = NINLIL_R7_FRAG_MX_ACTION_TX;
        c->profile = NINLIL_R7_FRAG_MX_PROFILE_0x11;
        c->route_handle = 0u;
        c->frag_index = 0u;
        st = ninlil_r7_frag_prod_tx_single(
            tx_bind, 0xA000u + (uint64_t)pass, 0xB000u + (uint64_t)pass, app,
            app_len, e2e_context_id, hop_context_id, 1u, &ws->tr);
        c->status = st;
        c->ok = (st == NINLIL_R7_FRAG_PROD_OK
                    || (st == NINLIL_R7_FRAG_PROD_ADMISSION && pass == 1u
                        && ws->tr.cleanup_class
                            == NINLIL_R7_FRAG_CLN_UNISSUED_DROP))
            ? 1u
            : 0u;
        if (st == NINLIL_R7_FRAG_PROD_OK) {
            c->ok = 1u;
            if (rx_bind != NULL && ws->tr.outer_len > 0u) {
                memset(&ws->rr, 0, sizeof(ws->rr));
                (void)ninlil_r7_frag_prod_rx_outer(
                    rx_bind, ws->tr.outer, ws->tr.outer_len, hop_context_id,
                    e2e_context_id, &ws->rr);
            }
        } else {
            c->ok = (st == NINLIL_R7_FRAG_PROD_ADMISSION
                        || st == NINLIL_R7_FRAG_PROD_R1
                        || st == NINLIL_R7_FRAG_PROD_R2
                        || st == NINLIL_R7_FRAG_PROD_CLOCK)
                ? 1u
                : 0u;
        }
    }

    /* Channel × route × class DATA TX matrix cells. */
    for (ci = 0u; ci < 2u && n < cells_cap; ci++) {
        for (ri = 0u; ri < 2u && n < cells_cap; ri++) {
            ninlil_r7_frag_prod_matrix_cell_t *c = &cells[n++];
            int32_t st;
            uint32_t saved_ch = tx_bind->live.channel_id;
            memset(c, 0, sizeof(*c));
            memset(&ws->tr, 0, sizeof(ws->tr));
            c->carrier = NINLIL_R7_FRAG_MX_CARRIER_LORA;
            c->channel_id = channels[ci];
            c->owner_class = NINLIL_R7_FRAG_MX_CLASS_DATA;
            c->action = NINLIL_R7_FRAG_MX_ACTION_TX;
            c->profile = NINLIL_R7_FRAG_MX_PROFILE_0x11;
            c->route_handle = routes[ri];
            c->frag_index = (uint16_t)(ri + 1u);
            tx_bind->live.channel_id = channels[ci];
            st = ninlil_r7_frag_prod_tx_single(
                tx_bind, 0xC100u + (uint64_t)ci * 16u + (uint64_t)ri,
                0xD100u + (uint64_t)ci * 16u + (uint64_t)ri, app, app_len,
                e2e_context_id, hop_context_id, (ri == 0u) ? 1u : 0u, &ws->tr);
            c->status = st;
            c->ok = (st == NINLIL_R7_FRAG_PROD_OK || st == NINLIL_R7_FRAG_PROD_R1
                        || st == NINLIL_R7_FRAG_PROD_ADMISSION
                        || st == NINLIL_R7_FRAG_PROD_R2)
                ? 1u
                : 0u;
            if (st == NINLIL_R7_FRAG_PROD_OK && rx_bind != NULL) {
                memset(&ws->rr, 0, sizeof(ws->rr));
                (void)ninlil_r7_frag_prod_rx_outer(
                    rx_bind, ws->tr.outer, ws->tr.outer_len, hop_context_id,
                    e2e_context_id, &ws->rr);
                c->action = NINLIL_R7_FRAG_MX_ACTION_RX;
            }
            tx_bind->live.channel_id = saved_ch;
        }
    }

    /* ACK class pin: cleanup-only cell (no air) + clock fail-closed cell. */
    if (n < cells_cap) {
        ninlil_r7_frag_prod_matrix_cell_t *c = &cells[n++];
        int32_t st;
        memset(c, 0, sizeof(*c));
        c->carrier = NINLIL_R7_FRAG_MX_CARRIER_LORA;
        c->owner_class = NINLIL_R7_FRAG_MX_CLASS_ACK;
        c->action = NINLIL_R7_FRAG_MX_ACTION_TX;
        c->profile = NINLIL_R7_FRAG_MX_PROFILE_0x11;
        st = ninlil_r7_frag_prod_cleanup(
            tx_bind, NINLIL_R7_FRAG_CLN_UNISSUED_DROP, 0u);
        c->status = st;
        c->ok = (st == NINLIL_R7_FRAG_PROD_OK) ? 1u : 0u;
    }
    if (n < cells_cap) {
        ninlil_r7_frag_prod_matrix_cell_t *c = &cells[n++];
        uint8_t saved_unc = tx_bind->clock_uncertain;
        int32_t st;
        memset(c, 0, sizeof(*c));
        memset(&ws->tr, 0, sizeof(ws->tr));
        c->carrier = NINLIL_R7_FRAG_MX_CARRIER_LORA;
        c->owner_class = NINLIL_R7_FRAG_MX_CLASS_DATA;
        c->action = NINLIL_R7_FRAG_MX_ACTION_TX;
        c->profile = NINLIL_R7_FRAG_MX_PROFILE_0x11;
        (void)ninlil_r7_frag_prod_time_set_uncertain(
            tx_bind, tx_bind->time_owner_gen, 1u);
        st = ninlil_r7_frag_prod_tx_single(
            tx_bind, 0xE001u, 0xE002u, app, app_len, e2e_context_id,
            hop_context_id, 0u, &ws->tr);
        (void)ninlil_r7_frag_prod_time_set_uncertain(
            tx_bind, tx_bind->time_owner_gen, saved_unc);
        c->status = st;
        c->ok = (st == NINLIL_R7_FRAG_PROD_CLOCK
                    && ws->tr.cleanup_class == NINLIL_R7_FRAG_CLN_CLOCK_DROP)
            ? 1u
            : 0u;
    }

    *out_n = n;
    memset(&ws->tr, 0, sizeof(ws->tr));
    memset(&ws->rr, 0, sizeof(ws->rr));
    ws->live = 0u;
    return NINLIL_R7_FRAG_PROD_OK;
}
