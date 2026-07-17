/*
 * R1 ninlil_radio_hal (H1) production implementation.
 * Sole physical TX entry: ninlil_radio_hal_transmit_with_permit.
 * Does not implement R2 authority, SX1262, wire version, or legal profiles.
 *
 * P0 hardening:
 * - Monotonic local one-shot: after consume, sequence <= last is reuse;
 *   last == UINT64_MAX -> SEQ_EXHAUSTED fail-closed.
 * - edge + permit + live + digest authorities all required (default-deny).
 * - Call-entry dual plan (working + seal); edge uses seal only.
 * - Alias of permit/frame/out_error with each other or HAL -> reject.
 * - Structural: zero IDs / reserved / zero core PHY fields — not Japan law.
 */

#include "radio_hal.h"

#include <string.h>

enum {
    HAL_LIFECYCLE_ZERO = 0,
    HAL_LIFECYCLE_ACTIVE = 1,
    HAL_LIFECYCLE_SHUTDOWN = 2
};

/*
 * Object identity after a successful init / shutdown.
 * First init requires semantic-fresh members (OBJECT_INIT / member zero),
 * not a full object-representation zero scan (padding is not C11-guaranteed).
 */
#define NINLIL_RADIO_HAL_MAGIC ((uint32_t)0x52314831u) /* 'R1H1' */

/* Complete type lives in radio_hal.h (production-private; no byte-storage pun). */
_Static_assert(
    sizeof(ninlil_radio_hal_t) <= NINLIL_RADIO_HAL_OBJECT_BYTES,
    "radio_hal object exceeds fixed ceiling");
_Static_assert(
    _Alignof(ninlil_radio_hal_t) >= NINLIL_RADIO_HAL_OBJECT_ALIGN,
    "radio_hal object align below OBJECT_ALIGN");

static int ranges_overlap_ptr(const void *a, size_t asz, const void *b, size_t bsz);

static void clear_error(ninlil_radio_hal_error_t *err)
{
    if (err == NULL) {
        return;
    }
    (void)memset(err, 0, sizeof(*err));
}

static void clear_error_safe(
    ninlil_radio_hal_error_t *err,
    const ninlil_radio_hal_t *rh)
{
    if (err == NULL) {
        return;
    }
    if (rh != NULL
        && ranges_overlap_ptr(err, sizeof(*err), rh, sizeof(*rh))) {
        return; /* refuse to self-corrupt HAL via out_error */
    }
    clear_error(err);
}

/*
 * Always updates rh->last_error when rh is non-NULL.
 * Writes *out_error only when out_error is non-NULL and the caller has marked
 * it as safe (not aliasing HAL / permit / frame storage).
 */
static void set_error(
    ninlil_radio_hal_t *rh,
    ninlil_radio_hal_error_t *out_error,
    int out_error_safe,
    ninlil_radio_hal_status_t status,
    ninlil_radio_hal_stage_t stage,
    ninlil_radio_hal_reason_t reason,
    const char *hint)
{
    ninlil_radio_hal_error_t local;

    clear_error(&local);
    local.status = status;
    local.stage = stage;
    local.reason = reason;
    if (hint != NULL) {
        size_t i;

        for (i = 0u; i + 1u < NINLIL_RADIO_HAL_HINT_BYTES && hint[i] != '\0';
             ++i) {
            local.hint[i] = hint[i];
        }
        local.hint[i] = '\0';
    }
    if (rh != NULL) {
        rh->last_error = local;
    }
    if (out_error != NULL && out_error_safe != 0) {
        *out_error = local;
    }
}

static void sat_inc(uint64_t *counter)
{
    if (counter == NULL) {
        return;
    }
    *counter = ninlil_radio_hal_sat_add_u64(*counter, 1u);
}

static int id_equal(const ninlil_radio_hal_id_t *a, const ninlil_radio_hal_id_t *b)
{
    return memcmp(a->bytes, b->bytes, NINLIL_RADIO_HAL_ID_BYTES) == 0;
}

static int id_is_zero(const ninlil_radio_hal_id_t *id)
{
    size_t i;

    for (i = 0u; i < NINLIL_RADIO_HAL_ID_BYTES; ++i) {
        if (id->bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int phy_equal(const ninlil_radio_hal_phy_t *a, const ninlil_radio_hal_phy_t *b)
{
    return a->bandwidth_hz == b->bandwidth_hz
        && a->spreading_factor == b->spreading_factor
        && a->coding_rate_denom == b->coding_rate_denom
        && a->preamble_symbols == b->preamble_symbols
        && a->tx_power_mdb == b->tx_power_mdb
        && a->phy_flags == b->phy_flags;
}

/* Structural R1 freeze: reject null identities / reserved / zero core PHY. */
static ninlil_radio_hal_status_t validate_phy_struct(
    const ninlil_radio_hal_phy_t *phy,
    ninlil_radio_hal_reason_t *out_reason)
{
    if (phy == NULL) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (phy->phy_flags != 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_STRUCT_INVALID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (phy->bandwidth_hz == 0u || phy->spreading_factor == 0u
        || phy->coding_rate_denom == 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_STRUCT_INVALID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    return NINLIL_RADIO_HAL_OK;
}

static ninlil_radio_hal_status_t validate_permit_struct(
    const ninlil_radio_hal_permit_snapshot_t *permit,
    ninlil_radio_hal_reason_t *out_reason)
{
    ninlil_radio_hal_status_t st;

    if (permit == NULL) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (permit->reserved_zero != 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_STRUCT_INVALID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (id_is_zero(&permit->hardware_profile_id)
        || id_is_zero(&permit->regulatory_profile_id)
        || id_is_zero(&permit->site_assignment_id)
        || id_is_zero(&permit->transmitter_id)) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_ZERO_ID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    st = validate_phy_struct(&permit->phy, out_reason);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }
    if (permit->max_airtime_us == 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_STRUCT_INVALID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (permit->permit_sequence == 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_SEQ_ZERO;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (permit->expiry_ms <= permit->not_before_ms) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_EXPIRED;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (permit->frame_byte_length == 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_ZERO_LENGTH;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (permit->frame_byte_length > NINLIL_RADIO_HAL_MAX_FRAME_BYTES) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_OVERSIZE;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    return NINLIL_RADIO_HAL_OK;
}

static ninlil_radio_hal_status_t validate_live_struct(
    const ninlil_radio_hal_live_binding_t *live,
    ninlil_radio_hal_reason_t *out_reason)
{
    ninlil_radio_hal_status_t st;

    if (live == NULL) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_NULL_ARG;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (live->reserved_zero != 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_STRUCT_INVALID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (id_is_zero(&live->hardware_profile_id)
        || id_is_zero(&live->regulatory_profile_id)
        || id_is_zero(&live->site_assignment_id)
        || id_is_zero(&live->transmitter_id)) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_ZERO_ID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    st = validate_phy_struct(&live->phy, out_reason);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }
    if (live->max_airtime_us == 0u) {
        if (out_reason != NULL) {
            *out_reason = NINLIL_RADIO_HAL_REASON_STRUCT_INVALID;
        }
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    return NINLIL_RADIO_HAL_OK;
}

/*
 * Overflow-safe range overlap via uintptr_t (no relational compare of
 * unrelated C object pointers; no asz wrap). Callers must bound sizes first
 * (especially untrusted frame lengths).
 * Returns 1 if ranges overlap or if end computation would wrap.
 */
static int ranges_overlap_u(
    uintptr_t a, size_t asz, uintptr_t b, size_t bsz)
{
    uintptr_t a_end;
    uintptr_t b_end;

    if (asz == 0u || bsz == 0u) {
        return 0;
    }
    if (a > UINTPTR_MAX - (uintptr_t)asz) {
        return 1;
    }
    if (b > UINTPTR_MAX - (uintptr_t)bsz) {
        return 1;
    }
    a_end = a + (uintptr_t)asz;
    b_end = b + (uintptr_t)bsz;
    return (a < b_end) && (b < a_end);
}

static int ranges_overlap_ptr(
    const void *a, size_t asz, const void *b, size_t bsz)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    return ranges_overlap_u((uintptr_t)a, asz, (uintptr_t)b, bsz);
}

/* out_error is safe to write iff it does not overlap the given region. */
static int out_error_safe_vs_region(
    const ninlil_radio_hal_error_t *out_error,
    const void *region,
    size_t region_sz)
{
    if (out_error == NULL || region == NULL) {
        return 1;
    }
    return ranges_overlap_ptr(
        out_error, sizeof(*out_error), region, region_sz) ? 0 : 1;
}

/*
 * Padding-independent permit equality: every semantic field of the §9.3
 * snapshot and nested PHY is compared individually. Whole-struct memcmp of
 * permit_snapshot is forbidden (padding is indeterminate / non-semantic).
 * Frame payload bytes remain memcmp-safe (explicit byte arrays).
 */
static int phy_semantic_equal(
    const ninlil_radio_hal_phy_t *a,
    const ninlil_radio_hal_phy_t *b)
{
    return a->bandwidth_hz == b->bandwidth_hz
        && a->spreading_factor == b->spreading_factor
        && a->coding_rate_denom == b->coding_rate_denom
        && a->preamble_symbols == b->preamble_symbols
        && a->tx_power_mdb == b->tx_power_mdb
        && a->phy_flags == b->phy_flags;
}

static int permit_semantic_equal(
    const ninlil_radio_hal_permit_snapshot_t *a,
    const ninlil_radio_hal_permit_snapshot_t *b)
{
    return id_equal(&a->hardware_profile_id, &b->hardware_profile_id)
        && a->hardware_profile_rev == b->hardware_profile_rev
        && id_equal(&a->regulatory_profile_id, &b->regulatory_profile_id)
        && a->regulatory_profile_rev == b->regulatory_profile_rev
        && id_equal(&a->site_assignment_id, &b->site_assignment_id)
        && a->site_assignment_rev == b->site_assignment_rev
        && a->site_assignment_epoch == b->site_assignment_epoch
        && id_equal(&a->transmitter_id, &b->transmitter_id)
        && a->channel_id == b->channel_id
        && phy_semantic_equal(&a->phy, &b->phy)
        && memcmp(
               a->frame_digest,
               b->frame_digest,
               NINLIL_RADIO_HAL_DIGEST_BYTES)
            == 0
        && a->frame_digest_algorithm == b->frame_digest_algorithm
        && a->frame_byte_length == b->frame_byte_length
        && a->max_airtime_us == b->max_airtime_us
        && a->not_before_ms == b->not_before_ms
        && a->expiry_ms == b->expiry_ms
        && a->permit_sequence == b->permit_sequence
        && a->reserved_zero == b->reserved_zero;
}

static int plan_matches_seal(const ninlil_radio_hal_t *rh)
{
    /* Semantic permit compare only — never whole permit memcmp. */
    if (!permit_semantic_equal(&rh->plan_permit, &rh->seal_permit)) {
        return 0;
    }
    if (rh->plan_view.length != rh->seal_view.length) {
        return 0;
    }
    if (rh->plan_view.length > 0u
        && memcmp(rh->plan_frame, rh->seal_frame, rh->plan_view.length) != 0) {
        return 0;
    }
    if (rh->plan_view.bytes != rh->plan_frame
        || rh->seal_view.bytes != rh->seal_frame) {
        return 0;
    }
    return 1;
}

static ninlil_radio_hal_status_t check_live(
    ninlil_radio_hal_t *rh,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    ninlil_radio_hal_error_t *out_error)
{
    const ninlil_radio_hal_live_binding_t *live;

    /* live_bound is required; callers must fail default-deny first. */
    if (rh->live_bound == 0u) {
        sat_inc(&rh->stats.default_deny);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_UNBOUND_LIVE,
            "live binding unbound");
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }
    live = &rh->live;

    if (!id_equal(&permit->hardware_profile_id, &live->hardware_profile_id)) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_HW_ID,
            "live hardware_profile_id mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (permit->hardware_profile_rev != live->hardware_profile_rev) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_HW_REV,
            "live hardware_profile_rev mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (!id_equal(&permit->regulatory_profile_id, &live->regulatory_profile_id)) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_REG_ID,
            "live regulatory_profile_id mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (permit->regulatory_profile_rev != live->regulatory_profile_rev) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_REG_REV,
            "live regulatory_profile_rev mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (!id_equal(&permit->site_assignment_id, &live->site_assignment_id)) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_SITE_ID,
            "live site_assignment_id mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (permit->site_assignment_rev != live->site_assignment_rev) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_SITE_REV,
            "live site_assignment_rev mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (permit->site_assignment_epoch != live->site_assignment_epoch) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_SITE_EPOCH,
            "live site_assignment_epoch mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (!id_equal(&permit->transmitter_id, &live->transmitter_id)) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_TX_ID,
            "live transmitter_id mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (permit->channel_id != live->channel_id) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_CHANNEL,
            "live channel_id mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (!phy_equal(&permit->phy, &live->phy)) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_PHY,
            "live PHY mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    if (permit->max_airtime_us != live->max_airtime_us) {
        sat_inc(&rh->stats.live_mismatch);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_LIVE_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_LIVE_AIRTIME,
            "live max_airtime_us mismatch");
        return NINLIL_RADIO_HAL_LIVE_MISMATCH;
    }
    return NINLIL_RADIO_HAL_OK;
}

/*
 * HAL does not own compliance time. NIN-CMP-003 not-before/expiry is enforced
 * only inside permit validate/consume via ctx authoritative clock (R2).
 * time_reject stats are updated when those callbacks return time status.
 */

static ninlil_radio_hal_status_t check_digest(
    ninlil_radio_hal_t *rh,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_stage_t stage,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_status_t st;
    ninlil_radio_hal_error_t local;

    if (rh->digest_bound == 0u || rh->digest_ops.verify == NULL) {
        sat_inc(&rh->stats.default_deny);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_DIGEST, NINLIL_RADIO_HAL_REASON_UNBOUND_DIGEST,
            "digest ops unbound");
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }
    clear_error(&local);
    st = rh->digest_ops.verify(
        rh->digest_ctx,
        frame,
        permit->frame_digest,
        permit->frame_digest_algorithm,
        &local);
    if (st == NINLIL_RADIO_HAL_OK) {
        return NINLIL_RADIO_HAL_OK;
    }
    if (stage == NINLIL_RADIO_HAL_STAGE_TOCTOU) {
        sat_inc(&rh->stats.toctou_reject);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_FRAME_MISMATCH,
            NINLIL_RADIO_HAL_STAGE_TOCTOU, NINLIL_RADIO_HAL_REASON_FRAME_MUTATED,
            "TOCTOU digest re-verify failed");
        return NINLIL_RADIO_HAL_FRAME_MISMATCH;
    }
    sat_inc(&rh->stats.digest_reject);
    set_error(rh, out_error, 1, NINLIL_RADIO_HAL_FRAME_MISMATCH,
        NINLIL_RADIO_HAL_STAGE_DIGEST, NINLIL_RADIO_HAL_REASON_DIGEST_MISMATCH,
        local.hint[0] != '\0' ? local.hint : "digest verify failed");
    return NINLIL_RADIO_HAL_FRAME_MISMATCH;
}

static ninlil_radio_hal_status_t fail_plan_mutated(
    ninlil_radio_hal_t *rh,
    ninlil_radio_hal_error_t *out_error)
{
    sat_inc(&rh->stats.plan_mutated);
    sat_inc(&rh->stats.toctou_reject);
    set_error(rh, out_error, 1, NINLIL_RADIO_HAL_FRAME_MISMATCH,
        NINLIL_RADIO_HAL_STAGE_PLAN, NINLIL_RADIO_HAL_REASON_PLAN_MUTATED,
        "local plan mutated by callback");
    return NINLIL_RADIO_HAL_FRAME_MISMATCH;
}

size_t ninlil_radio_hal_object_size(void)
{
    return sizeof(ninlil_radio_hal_t);
}

size_t ninlil_radio_hal_object_align(void)
{
    /* Actual type alignment requirement (not the public minimum alone). */
    return _Alignof(ninlil_radio_hal_t);
}

/*
 * Semantic-zero helpers for first-init precondition.
 * Inspect named members only — never scan object padding / full representation.
 * C11 OBJECT_INIT {0} zeros all members; padding bytes may remain non-zero.
 */
static int phy_is_semantic_zero(const ninlil_radio_hal_phy_t *phy)
{
    return phy->bandwidth_hz == 0u
        && phy->spreading_factor == 0u
        && phy->coding_rate_denom == 0u
        && phy->preamble_symbols == 0u
        && phy->tx_power_mdb == 0
        && phy->phy_flags == 0u;
}

static int permit_is_semantic_zero(
    const ninlil_radio_hal_permit_snapshot_t *p)
{
    size_t i;

    if (!id_is_zero(&p->hardware_profile_id)
        || p->hardware_profile_rev != 0u
        || !id_is_zero(&p->regulatory_profile_id)
        || p->regulatory_profile_rev != 0u
        || !id_is_zero(&p->site_assignment_id)
        || p->site_assignment_rev != 0u
        || p->site_assignment_epoch != 0u
        || !id_is_zero(&p->transmitter_id)
        || p->channel_id != 0u
        || !phy_is_semantic_zero(&p->phy)
        || p->frame_digest_algorithm != 0u
        || p->frame_byte_length != 0u
        || p->max_airtime_us != 0u
        || p->not_before_ms != 0u
        || p->expiry_ms != 0u
        || p->permit_sequence != 0u
        || p->reserved_zero != 0u) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RADIO_HAL_DIGEST_BYTES; ++i) {
        if (p->frame_digest[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int live_is_semantic_zero(const ninlil_radio_hal_live_binding_t *live)
{
    return id_is_zero(&live->hardware_profile_id)
        && live->hardware_profile_rev == 0u
        && id_is_zero(&live->regulatory_profile_id)
        && live->regulatory_profile_rev == 0u
        && id_is_zero(&live->site_assignment_id)
        && live->site_assignment_rev == 0u
        && live->site_assignment_epoch == 0u
        && id_is_zero(&live->transmitter_id)
        && live->channel_id == 0u
        && phy_is_semantic_zero(&live->phy)
        && live->max_airtime_us == 0u
        && live->reserved_zero == 0u;
}

static int stats_is_semantic_zero(const ninlil_radio_hal_stats_t *s)
{
    return s->attempts == 0u
        && s->default_deny == 0u
        && s->invalid_argument == 0u
        && s->invalid_state == 0u
        && s->live_mismatch == 0u
        && s->time_reject == 0u
        && s->digest_reject == 0u
        && s->permit_validate_ok == 0u
        && s->permit_validate_deny == 0u
        && s->permit_validate_error == 0u
        && s->permit_consume_ok == 0u
        && s->permit_consume_deny == 0u
        && s->permit_consume_error == 0u
        && s->permit_consume_fenced == 0u
        && s->toctou_reject == 0u
        && s->edge_calls == 0u
        && s->edge_ok == 0u
        && s->edge_error == 0u
        && s->seq_reuse == 0u
        && s->reentrant_reject == 0u
        && s->success == 0u
        && s->plan_mutated == 0u
        && s->alias_reject == 0u
        && s->seq_exhausted == 0u;
}

static int error_is_semantic_zero(const ninlil_radio_hal_error_t *e)
{
    size_t i;

    if (e->status != 0u || e->stage != 0u || e->reason != 0u
        || e->reserved_zero != 0u) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RADIO_HAL_HINT_BYTES; ++i) {
        if (e->hint[i] != '\0') {
            return 0;
        }
    }
    return 1;
}

static int frame_bytes_are_zero(const uint8_t *bytes, size_t n)
{
    size_t i;

    for (i = 0u; i < n; ++i) {
        if (bytes[i] != 0u) {
            return 0;
        }
    }
    return 1;
}

/*
 * First-init precondition: every named member is semantic-zero
 * (magic==0, lifecycle==ZERO, unbound ops/ctx, empty plans/stats).
 * Padding is intentionally not inspected (not C11-guaranteed by OBJECT_INIT).
 */
static int object_is_semantic_fresh(const ninlil_radio_hal_object_t *object)
{
    if (object->magic != 0u
        || object->lifecycle != (uint32_t)HAL_LIFECYCLE_ZERO
        || object->in_transmit != 0u
        || object->edge_bound != 0u
        || object->permit_bound != 0u
        || object->digest_bound != 0u
        || object->live_bound != 0u
        || object->has_consumed_seq != 0u
        || object->reserved_zero != 0u
        || object->last_consumed_seq != 0u) {
        return 0;
    }
    if (object->edge_ops.transmit != NULL
        || object->edge_ctx != NULL
        || object->permit_ops.validate != NULL
        || object->permit_ops.consume != NULL
        || object->permit_ctx != NULL
        || object->digest_ops.verify != NULL
        || object->digest_ctx != NULL) {
        return 0;
    }
    if (!live_is_semantic_zero(&object->live)
        || !permit_is_semantic_zero(&object->plan_permit)
        || !permit_is_semantic_zero(&object->seal_permit)
        || !frame_bytes_are_zero(
               object->plan_frame, NINLIL_RADIO_HAL_MAX_FRAME_BYTES)
        || !frame_bytes_are_zero(
               object->seal_frame, NINLIL_RADIO_HAL_MAX_FRAME_BYTES)
        || object->plan_view.bytes != NULL
        || object->plan_view.length != 0u
        || object->seal_view.bytes != NULL
        || object->seal_view.length != 0u
        || !stats_is_semantic_zero(&object->stats)
        || !error_is_semantic_zero(&object->last_error)) {
        return 0;
    }
    return 1;
}

/*
 * Byte-safe load of lifecycle tags (memcpy of magic/lifecycle only).
 * Used after semantic-fresh fails: object is tagged SHUTDOWN/ACTIVE or poison.
 */
static void load_lifecycle_tag_bytes(
    const ninlil_radio_hal_object_t *object,
    uint32_t *out_magic,
    uint32_t *out_lifecycle)
{
    uint32_t magic;
    uint32_t lifecycle;

    (void)memcpy(&magic, &object->magic, sizeof(magic));
    (void)memcpy(&lifecycle, &object->lifecycle, sizeof(lifecycle));
    *out_magic = magic;
    *out_lifecycle = lifecycle;
}

ninlil_radio_hal_status_t ninlil_radio_hal_init_object(
    ninlil_radio_hal_object_t *object,
    ninlil_radio_hal_t **out_hal)
{
    uint32_t prior_magic;
    uint32_t prior_lifecycle;

    if (object == NULL || out_hal == NULL) {
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }

    /*
     * Reject out_hal aliasing the object before any memset / *out_hal write.
     * Concrete fail case: init_object(&obj, (ninlil_radio_hal_t **)&obj).
     */
    if (ranges_overlap_ptr(
            out_hal, sizeof(*out_hal), object, sizeof(*object))) {
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }

    if (((uintptr_t)(const void *)object % NINLIL_RADIO_HAL_OBJECT_ALIGN)
        != 0u) {
        *out_hal = NULL;
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }

    /*
     * Init / re-init contract (semantic members only; no padding scan):
     *   - semantic-fresh (OBJECT_INIT / member-zero): first init OK
     *   - MAGIC + SHUTDOWN: re-init OK; new watermark domain
     *   - MAGIC + ACTIVE: re-init forbidden (preserves one-shot watermark)
     *   - any other tag/member state: INVALID_STATE (semantic poison)
     *
     * Precondition for first init: all named members semantic-zero
     * (NINLIL_RADIO_HAL_OBJECT_INIT / member zero). Padding bytes are not
     * part of the contract (C11 does not zero them for automatic OBJECT_INIT).
     * Arbitrary raw representation poison is only rejected when it alters
     * semantic tags/members.
     */
    if (!object_is_semantic_fresh(object)) {
        load_lifecycle_tag_bytes(object, &prior_magic, &prior_lifecycle);
        if (prior_magic != NINLIL_RADIO_HAL_MAGIC) {
            *out_hal = NULL;
            return NINLIL_RADIO_HAL_INVALID_STATE;
        }
        if (prior_lifecycle == (uint32_t)HAL_LIFECYCLE_ACTIVE) {
            /* ACTIVE re-init forbidden (would erase one-shot watermark). */
            *out_hal = NULL;
            return NINLIL_RADIO_HAL_INVALID_STATE;
        }
        if (prior_lifecycle != (uint32_t)HAL_LIFECYCLE_SHUTDOWN) {
            *out_hal = NULL;
            return NINLIL_RADIO_HAL_INVALID_STATE;
        }
        /* MAGIC + SHUTDOWN: re-init allowed. */
    }
    /* else: semantic-fresh first init (members zero; padding ignored). */

    (void)memset(object, 0, sizeof(*object));
    object->magic = NINLIL_RADIO_HAL_MAGIC;
    object->lifecycle = HAL_LIFECYCLE_ACTIVE;
    /* Same effective type: out_hal is the object itself. */
    *out_hal = object;
    return NINLIL_RADIO_HAL_OK;
}

static ninlil_radio_hal_status_t bind_guard(
    ninlil_radio_hal_t *rh,
    ninlil_radio_hal_error_t *out_error)
{
    int out_safe;

    if (rh == NULL) {
        set_error(NULL, out_error, 1, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_BIND, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null hal");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    out_safe = out_error_safe_vs_region(out_error, rh, sizeof(*rh));
    if (rh->lifecycle != HAL_LIFECYCLE_ACTIVE) {
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_STATE,
            NINLIL_RADIO_HAL_STAGE_BIND, NINLIL_RADIO_HAL_REASON_NOT_ACTIVE,
            "hal not active");
        return NINLIL_RADIO_HAL_INVALID_STATE;
    }
    if (rh->in_transmit != 0u) {
        sat_inc(&rh->stats.reentrant_reject);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_BUSY,
            NINLIL_RADIO_HAL_STAGE_OWNER, NINLIL_RADIO_HAL_REASON_REENTRANT,
            "bind during transmit");
        return NINLIL_RADIO_HAL_BUSY;
    }
    return NINLIL_RADIO_HAL_OK;
}

ninlil_radio_hal_status_t ninlil_radio_hal_bind_edge(
    ninlil_radio_hal_t *rh,
    const ninlil_radio_hal_edge_ops_t *ops,
    void *ctx,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_status_t st;
    int out_safe;

    st = bind_guard(rh, out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }
    out_safe = out_error_safe_vs_region(out_error, rh, sizeof(*rh));
    if (ops == NULL) {
        (void)memset(&rh->edge_ops, 0, sizeof(rh->edge_ops));
        rh->edge_ctx = NULL;
        rh->edge_bound = 0u;
        clear_error_safe(out_error, rh);
        return NINLIL_RADIO_HAL_OK;
    }
    if (ops->transmit == NULL) {
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_BIND, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null edge transmit");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    rh->edge_ops = *ops;
    rh->edge_ctx = ctx;
    rh->edge_bound = 1u;
    clear_error_safe(out_error, rh);
    return NINLIL_RADIO_HAL_OK;
}

ninlil_radio_hal_status_t ninlil_radio_hal_bind_permit_ops(
    ninlil_radio_hal_t *rh,
    const ninlil_radio_hal_permit_ops_t *ops,
    void *ctx,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_status_t st;
    int out_safe;

    st = bind_guard(rh, out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }
    out_safe = out_error_safe_vs_region(out_error, rh, sizeof(*rh));
    if (ops == NULL) {
        (void)memset(&rh->permit_ops, 0, sizeof(rh->permit_ops));
        rh->permit_ctx = NULL;
        rh->permit_bound = 0u;
        clear_error_safe(out_error, rh);
        return NINLIL_RADIO_HAL_OK;
    }
    if (ops->validate == NULL || ops->consume == NULL) {
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_BIND, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null permit validate/consume");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    rh->permit_ops = *ops;
    rh->permit_ctx = ctx;
    rh->permit_bound = 1u;
    clear_error_safe(out_error, rh);
    return NINLIL_RADIO_HAL_OK;
}

ninlil_radio_hal_status_t ninlil_radio_hal_bind_digest_ops(
    ninlil_radio_hal_t *rh,
    const ninlil_radio_hal_digest_ops_t *ops,
    void *ctx,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_status_t st;
    int out_safe;

    st = bind_guard(rh, out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }
    out_safe = out_error_safe_vs_region(out_error, rh, sizeof(*rh));
    if (ops == NULL) {
        (void)memset(&rh->digest_ops, 0, sizeof(rh->digest_ops));
        rh->digest_ctx = NULL;
        rh->digest_bound = 0u;
        clear_error_safe(out_error, rh);
        return NINLIL_RADIO_HAL_OK;
    }
    if (ops->verify == NULL) {
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_BIND, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null digest verify");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    rh->digest_ops = *ops;
    rh->digest_ctx = ctx;
    rh->digest_bound = 1u;
    clear_error_safe(out_error, rh);
    return NINLIL_RADIO_HAL_OK;
}

ninlil_radio_hal_status_t ninlil_radio_hal_set_live_binding(
    ninlil_radio_hal_t *rh,
    const ninlil_radio_hal_live_binding_t *live,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_status_t st;
    ninlil_radio_hal_reason_t reason;
    int out_safe;

    st = bind_guard(rh, out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        return st;
    }
    out_safe = out_error_safe_vs_region(out_error, rh, sizeof(*rh));
    if (live == NULL) {
        (void)memset(&rh->live, 0, sizeof(rh->live));
        rh->live_bound = 0u;
        clear_error_safe(out_error, rh);
        return NINLIL_RADIO_HAL_OK;
    }
    reason = NINLIL_RADIO_HAL_REASON_NONE;
    st = validate_live_struct(live, &reason);
    if (st != NINLIL_RADIO_HAL_OK) {
        set_error(rh, out_error, out_safe, st, NINLIL_RADIO_HAL_STAGE_BIND, reason,
            "live structural invalid");
        return st;
    }
    rh->live = *live;
    rh->live_bound = 1u;
    clear_error_safe(out_error, rh);
    return NINLIL_RADIO_HAL_OK;
}

ninlil_radio_hal_status_t ninlil_radio_hal_transmit_with_permit(
    ninlil_radio_hal_t *rh,
    const ninlil_radio_hal_permit_snapshot_t *permit,
    const ninlil_radio_hal_frame_view_t *frame,
    ninlil_radio_hal_error_t *out_error)
{
    ninlil_radio_hal_status_t st;
    ninlil_radio_hal_error_t local;
    ninlil_radio_hal_error_t edge_err;
    ninlil_radio_hal_reason_t reason;
    uint32_t flen;
    uint32_t permit_frame_len;
    const uint8_t *frame_bytes;
    int out_safe;
    int out_unsafe_vs_hal;

    if (rh == NULL) {
        /* No HAL region; out_error may still be written. */
        set_error(NULL, out_error, 1, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null hal");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }

    /*
     * out_error vs HAL is checkable without dereferencing permit/frame.
     * All pre-(A) exits use this; (A) may further mark out_error unsafe.
     */
    out_unsafe_vs_hal = 0;
    if (out_error != NULL
        && ranges_overlap_ptr(
            out_error, sizeof(*out_error), rh, sizeof(*rh))) {
        out_unsafe_vs_hal = 1;
    }
    out_safe = (out_unsafe_vs_hal == 0) ? 1 : 0;

    if (rh->in_transmit != 0u) {
        sat_inc(&rh->stats.reentrant_reject);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_BUSY,
            NINLIL_RADIO_HAL_STAGE_OWNER, NINLIL_RADIO_HAL_REASON_REENTRANT,
            "reentrant transmit_with_permit");
        return NINLIL_RADIO_HAL_BUSY;
    }

    if (rh->lifecycle != HAL_LIFECYCLE_ACTIVE) {
        sat_inc(&rh->stats.invalid_state);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_STATE,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_NOT_ACTIVE,
            "hal not active");
        return NINLIL_RADIO_HAL_INVALID_STATE;
    }

    if (permit == NULL || frame == NULL) {
        sat_inc(&rh->stats.invalid_argument);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null permit or frame");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }

    /*
     * (A) Container alias only — fixed sizeof(*permit)/sizeof(*frame)/
     * sizeof(*out_error). NO frame->bytes / frame->length / permit field
     * dereference. Unsafe out_error: write 0.
     */
    {
        int alias = 0;
        int out_err_unsafe = out_unsafe_vs_hal;

        if (ranges_overlap_ptr(permit, sizeof(*permit), rh, sizeof(*rh))
            || ranges_overlap_ptr(frame, sizeof(*frame), rh, sizeof(*rh))
            || ranges_overlap_ptr(
                permit, sizeof(*permit), frame, sizeof(*frame))) {
            alias = 1;
        }
        if (out_error != NULL) {
            if (ranges_overlap_ptr(
                    out_error, sizeof(*out_error), permit, sizeof(*permit))
                || ranges_overlap_ptr(
                    out_error, sizeof(*out_error), frame, sizeof(*frame))) {
                alias = 1;
                out_err_unsafe = 1;
            }
        }
        if (alias != 0) {
            sat_inc(&rh->stats.alias_reject);
            sat_inc(&rh->stats.invalid_argument);
            set_error(
                rh,
                out_error,
                out_err_unsafe != 0 ? 0 : 1,
                NINLIL_RADIO_HAL_INVALID_ARGUMENT,
                NINLIL_RADIO_HAL_STAGE_ARGS,
                NINLIL_RADIO_HAL_REASON_ALIAS,
                "container alias with HAL or peer args");
            return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
        }
        out_safe = (out_err_unsafe != 0) ? 0 : 1;
    }

    /*
     * Containers are non-aliasing with HAL and each other. Enter attempt and
     * copy frame fields to local scalars only (no authority mutation yet).
     */
    rh->in_transmit = 1u;
    sat_inc(&rh->stats.attempts);

    /* (B) Local scalars from frame view; null / zero / max checks. */
    frame_bytes = frame->bytes;
    flen = frame->length;

    if (frame_bytes == NULL && flen != 0u) {
        sat_inc(&rh->stats.invalid_argument);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null frame bytes with nonzero length");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (flen == 0u) {
        sat_inc(&rh->stats.invalid_argument);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_ZERO_LENGTH,
            "zero frame length");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    if (flen > NINLIL_RADIO_HAL_MAX_FRAME_BYTES) {
        sat_inc(&rh->stats.invalid_argument);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_OVERSIZE,
            "frame oversize");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }

    /*
     * (C) Bounded payload range vs HAL / permit object / out_error.
     * flen is now in [1, MAX]; no size wrap into ranges_overlap_u.
     */
    if (frame_bytes != NULL) {
        int alias = 0;
        int out_err_unsafe = (out_safe == 0) ? 1 : 0;

        if (ranges_overlap_ptr(
                frame_bytes, (size_t)flen, rh, sizeof(*rh))
            || ranges_overlap_ptr(
                frame_bytes, (size_t)flen, permit, sizeof(*permit))
            || ranges_overlap_ptr(
                frame_bytes, (size_t)flen, frame, sizeof(*frame))) {
            alias = 1;
        }
        if (out_error != NULL
            && ranges_overlap_ptr(
                frame_bytes, (size_t)flen, out_error, sizeof(*out_error))) {
            alias = 1;
            out_err_unsafe = 1;
        }
        if (alias != 0) {
            sat_inc(&rh->stats.alias_reject);
            sat_inc(&rh->stats.invalid_argument);
            set_error(
                rh,
                out_error,
                out_err_unsafe != 0 ? 0 : 1,
                NINLIL_RADIO_HAL_INVALID_ARGUMENT,
                NINLIL_RADIO_HAL_STAGE_ARGS,
                NINLIL_RADIO_HAL_REASON_ALIAS,
                "frame_bytes alias with HAL or peer args");
            rh->in_transmit = 0u;
            return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
        }
        if (out_err_unsafe != 0) {
            out_safe = 0;
        }
    }

    /* (D) length mismatch + permit structural validation. */
    permit_frame_len = permit->frame_byte_length;
    if (flen != permit_frame_len) {
        sat_inc(&rh->stats.invalid_argument);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_LENGTH_MISMATCH,
            "frame length != permit.frame_byte_length");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }

    reason = NINLIL_RADIO_HAL_REASON_NONE;
    st = validate_permit_struct(permit, &reason);
    if (st != NINLIL_RADIO_HAL_OK) {
        sat_inc(&rh->stats.invalid_argument);
        set_error(rh, out_error, out_safe, st, NINLIL_RADIO_HAL_STAGE_ARGS, reason,
            "permit structural invalid");
        rh->in_transmit = 0u;
        return st;
    }

    /* All four authorities required for any physical TX. */
    if (rh->edge_bound == 0u || rh->edge_ops.transmit == NULL) {
        sat_inc(&rh->stats.default_deny);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_ARGS, NINLIL_RADIO_HAL_REASON_UNBOUND_EDGE,
            "edge unbound default-deny");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }
    if (rh->permit_bound == 0u || rh->permit_ops.validate == NULL
        || rh->permit_ops.consume == NULL) {
        sat_inc(&rh->stats.default_deny);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_DEFAULT_DENY,
            "permit ops unbound default-deny");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }
    if (rh->live_bound == 0u) {
        sat_inc(&rh->stats.default_deny);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_LIVE, NINLIL_RADIO_HAL_REASON_UNBOUND_LIVE,
            "live binding unbound default-deny");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }
    if (rh->digest_bound == 0u || rh->digest_ops.verify == NULL) {
        sat_inc(&rh->stats.default_deny);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_DEFAULT_DENY,
            NINLIL_RADIO_HAL_STAGE_DIGEST, NINLIL_RADIO_HAL_REASON_UNBOUND_DIGEST,
            "digest ops unbound default-deny");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_DEFAULT_DENY;
    }

    /* Monotonic one-shot: sequence <= last_consumed is reuse; MAX exhausted. */
    if (rh->has_consumed_seq != 0u) {
        if (rh->last_consumed_seq == UINT64_MAX) {
            sat_inc(&rh->stats.seq_exhausted);
            set_error(rh, out_error, 1, NINLIL_RADIO_HAL_SEQ_EXHAUSTED,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_SEQ_EXHAUSTED,
                "permit sequence space exhausted");
            rh->in_transmit = 0u;
            return NINLIL_RADIO_HAL_SEQ_EXHAUSTED;
        }
        if (permit->permit_sequence <= rh->last_consumed_seq) {
            sat_inc(&rh->stats.seq_reuse);
            set_error(rh, out_error, 1, NINLIL_RADIO_HAL_SEQ_REUSE,
                NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
                NINLIL_RADIO_HAL_REASON_SEQ_REUSE,
                "permit_sequence <= last_consumed_seq");
            rh->in_transmit = 0u;
            return NINLIL_RADIO_HAL_SEQ_REUSE;
        }
    }

    /* Call-entry dual copy: working plan + sealed gold. */
    rh->plan_permit = *permit;
    rh->seal_permit = *permit;
    (void)memcpy(rh->plan_frame, frame->bytes, flen);
    (void)memcpy(rh->seal_frame, frame->bytes, flen);
    if (flen < NINLIL_RADIO_HAL_MAX_FRAME_BYTES) {
        (void)memset(rh->plan_frame + flen, 0,
            NINLIL_RADIO_HAL_MAX_FRAME_BYTES - flen);
        (void)memset(rh->seal_frame + flen, 0,
            NINLIL_RADIO_HAL_MAX_FRAME_BYTES - flen);
    }
    rh->plan_view.bytes = rh->plan_frame;
    rh->plan_view.length = flen;
    rh->seal_view.bytes = rh->seal_frame;
    rh->seal_view.length = flen;

    /*
     * Immutable seal rule:
     *   - seal_permit / seal_frame / seal_view are NEVER passed to external
     *     digest or permit (validate/consume) callbacks.
     *   - All authority callbacks receive working plan only (plan_*).
     *   - After every external authority callback: exact plan_matches_seal.
     *   - Order: live (internal) → digest(working) → compare →
     *     validate(working) → compare → consume(working, last authority) →
     *     compare → edge(seal only; no further external authority callback).
     *   - Post-consume external digest/live is forbidden (TOCTOU / expiry window).
     */
    st = check_live(rh, &rh->seal_permit, out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        rh->in_transmit = 0u;
        return st;
    }

    /* External digest: working plan only — never seal. */
    st = check_digest(
        rh, &rh->plan_permit, &rh->plan_view, NINLIL_RADIO_HAL_STAGE_DIGEST,
        out_error);
    if (st != NINLIL_RADIO_HAL_OK) {
        rh->in_transmit = 0u;
        return st;
    }
    if (!plan_matches_seal(rh)) {
        st = fail_plan_mutated(rh, out_error);
        rh->in_transmit = 0u;
        return st;
    }

    /* External validate: working plan only — never seal. */
    clear_error(&local);
    st = rh->permit_ops.validate(
        rh->permit_ctx, &rh->plan_permit, &rh->plan_view, &local);
    if (!plan_matches_seal(rh)) {
        st = fail_plan_mutated(rh, out_error);
        rh->in_transmit = 0u;
        return st;
    }
    if (st == NINLIL_RADIO_HAL_NOT_BEFORE || st == NINLIL_RADIO_HAL_EXPIRED) {
        sat_inc(&rh->stats.time_reject);
        set_error(
            rh,
            out_error,
            1,
            st,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            st == NINLIL_RADIO_HAL_NOT_BEFORE
                ? NINLIL_RADIO_HAL_REASON_NOT_BEFORE
                : NINLIL_RADIO_HAL_REASON_EXPIRED,
            local.hint[0] != '\0' ? local.hint : "permit time window");
        rh->in_transmit = 0u;
        return st;
    }
    if (st == NINLIL_RADIO_HAL_PERMIT_DENIED
        || st == NINLIL_RADIO_HAL_DEFAULT_DENY) {
        sat_inc(&rh->stats.permit_validate_deny);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_PERMIT_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_DENY,
            local.hint[0] != '\0' ? local.hint : "permit validate deny");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_PERMIT_DENIED;
    }
    if (st != NINLIL_RADIO_HAL_OK) {
        sat_inc(&rh->stats.permit_validate_error);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_PERMIT_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_VALIDATE,
            NINLIL_RADIO_HAL_REASON_VALIDATOR_ERROR,
            local.hint[0] != '\0' ? local.hint : "permit validate error");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_PERMIT_ERROR;
    }
    sat_inc(&rh->stats.permit_validate_ok);

    /*
     * Last authority callback: one-shot consume on working plan only.
     * Never pass seal. After return: exact compare before any edge.
     *
     * Consume non-OK partition (see header) applies only when working still
     * matches seal. Plan mutation is a separate callback contract fault.
     */
    clear_error(&local);
    st = rh->permit_ops.consume(
        rh->permit_ctx, &rh->plan_permit, &rh->plan_view, &local);
    if (!plan_matches_seal(rh)) {
        /*
         * Working plan mutated during consume: callback contract fault
         * (const-cast of working storage). Return status side-effect claims
         * (DENIED / NOT_BEFORE / EXPIRED / …) are untrustworthy —
         * terminal burn sealed seq for ALL statuses; edge 0. Only non-mutation
         * definitely-unconsumed remains same-seq retry-eligible.
         */
        (void)st;
        rh->has_consumed_seq = 1u;
        rh->last_consumed_seq = rh->seal_permit.permit_sequence;
        st = fail_plan_mutated(rh, out_error);
        rh->in_transmit = 0u;
        return st;
    }

    /*
     * Consume closed partition (no mutation):
     *   CONSUME_DENIED only — definitely unconsumed; no watermark burn;
     *     same seq retry-eligible. PERMIT_DENIED is validate-side only: if a
     *     buggy consume returns it, fail-closed burn (not retryable).
     *   NOT_BEFORE / EXPIRED from consume return are not the pre-consume
     *     time path (that is validate-stage); treat as terminal fence burn.
     *   CONSUME_FENCED / CONSUME_ERROR / SEQ_REUSE / any other non-OK —
     *     terminal burn sealed seq, edge 0.
     */
    if (st == NINLIL_RADIO_HAL_CONSUME_DENIED) {
        /* CONSUME_DENIED only: no burn (not PERMIT_DENIED). */
        sat_inc(&rh->stats.permit_consume_deny);
        set_error(
            rh,
            out_error,
            1,
            NINLIL_RADIO_HAL_CONSUME_DENIED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_UNCONSUMED,
            local.hint[0] != '\0' ? local.hint : "consume definitely unconsumed");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_CONSUME_DENIED;
    }

    /* --- Terminal fence / contract error: burn watermark, edge 0 --- */
    if (st == NINLIL_RADIO_HAL_SEQ_REUSE) {
        rh->has_consumed_seq = 1u;
        rh->last_consumed_seq = rh->seal_permit.permit_sequence;
        sat_inc(&rh->stats.seq_reuse);
        set_error(
            rh,
            out_error,
            1,
            NINLIL_RADIO_HAL_SEQ_REUSE,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_SEQ_REUSE,
            local.hint[0] != '\0' ? local.hint : "consume seq reuse fenced");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_SEQ_REUSE;
    }
    if (st == NINLIL_RADIO_HAL_CONSUME_FENCED) {
        rh->has_consumed_seq = 1u;
        rh->last_consumed_seq = rh->seal_permit.permit_sequence;
        sat_inc(&rh->stats.permit_consume_fenced);
        set_error(
            rh,
            out_error,
            1,
            NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED,
            local.hint[0] != '\0' ? local.hint : "consume permanently fenced");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }
    if (st == NINLIL_RADIO_HAL_CONSUME_ERROR) {
        /*
         * Contract/invalid: terminal fail-closed fence. NOT commit-unknown;
         * same sequence is not retry-eligible for TX.
         */
        rh->has_consumed_seq = 1u;
        rh->last_consumed_seq = rh->seal_permit.permit_sequence;
        sat_inc(&rh->stats.permit_consume_error);
        sat_inc(&rh->stats.permit_consume_fenced);
        set_error(
            rh,
            out_error,
            1,
            NINLIL_RADIO_HAL_CONSUME_ERROR,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED,
            local.hint[0] != '\0'
                ? local.hint
                : "consume error is terminal fenced (no commit-unknown)");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_CONSUME_ERROR;
    }
    if (st != NINLIL_RADIO_HAL_OK) {
        /* Any other non-OK: fail-closed as FENCED (no retryable unknown). */
        rh->has_consumed_seq = 1u;
        rh->last_consumed_seq = rh->seal_permit.permit_sequence;
        sat_inc(&rh->stats.permit_consume_fenced);
        set_error(
            rh,
            out_error,
            1,
            NINLIL_RADIO_HAL_CONSUME_FENCED,
            NINLIL_RADIO_HAL_STAGE_PERMIT_CONSUME,
            NINLIL_RADIO_HAL_REASON_CONSUME_FENCED,
            local.hint[0] != '\0'
                ? local.hint
                : "consume non-OK treated as fenced (no commit-unknown)");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_CONSUME_FENCED;
    }

    sat_inc(&rh->stats.permit_consume_ok);

    /* Consume success: watermark from seal (immutable authority snapshot). */
    rh->has_consumed_seq = 1u;
    rh->last_consumed_seq = rh->seal_permit.permit_sequence;

    /*
     * Post-consume: local integrity only — NO external digest/permit callback.
     * Edge receives seal only after compare proves working still equals seal.
     */
    if (!plan_matches_seal(rh)) {
        st = fail_plan_mutated(rh, out_error);
        rh->in_transmit = 0u;
        return st;
    }

    clear_error(&edge_err);
    sat_inc(&rh->stats.edge_calls);
    /* Seal path only: no external authority between compare and this call. */
    st = rh->edge_ops.transmit(
        rh->edge_ctx, &rh->seal_permit, &rh->seal_view, &edge_err);
    if (st != NINLIL_RADIO_HAL_OK) {
        sat_inc(&rh->stats.edge_error);
        set_error(rh, out_error, 1, NINLIL_RADIO_HAL_EDGE_ERROR,
            NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_EDGE_FAIL,
            edge_err.hint[0] != '\0' ? edge_err.hint : "edge transmit failed");
        rh->in_transmit = 0u;
        return NINLIL_RADIO_HAL_EDGE_ERROR;
    }

    sat_inc(&rh->stats.edge_ok);
    sat_inc(&rh->stats.success);
    set_error(rh, out_error, 1, NINLIL_RADIO_HAL_OK,
        NINLIL_RADIO_HAL_STAGE_EDGE, NINLIL_RADIO_HAL_REASON_NONE, "ok");
    rh->in_transmit = 0u;
    return NINLIL_RADIO_HAL_OK;
}

void ninlil_radio_hal_stats(
    const ninlil_radio_hal_t *rh,
    ninlil_radio_hal_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (rh == NULL) {
        (void)memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = rh->stats;
}

void ninlil_radio_hal_last_error(
    const ninlil_radio_hal_t *rh,
    ninlil_radio_hal_error_t *out_error)
{
    if (out_error == NULL) {
        return;
    }
    if (rh == NULL) {
        clear_error_safe(out_error, rh);
        return;
    }
    *out_error = rh->last_error;
}

ninlil_radio_hal_status_t ninlil_radio_hal_shutdown(
    ninlil_radio_hal_t *rh,
    ninlil_radio_hal_error_t *out_error)
{
    int out_safe;

    if (rh == NULL) {
        set_error(NULL, out_error, 1, NINLIL_RADIO_HAL_INVALID_ARGUMENT,
            NINLIL_RADIO_HAL_STAGE_SHUTDOWN, NINLIL_RADIO_HAL_REASON_NULL_ARG,
            "null hal");
        return NINLIL_RADIO_HAL_INVALID_ARGUMENT;
    }
    out_safe = out_error_safe_vs_region(out_error, rh, sizeof(*rh));
    if (rh->in_transmit != 0u) {
        sat_inc(&rh->stats.reentrant_reject);
        set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_BUSY,
            NINLIL_RADIO_HAL_STAGE_SHUTDOWN, NINLIL_RADIO_HAL_REASON_REENTRANT,
            "shutdown during transmit");
        return NINLIL_RADIO_HAL_BUSY;
    }
    rh->magic = NINLIL_RADIO_HAL_MAGIC;
    rh->lifecycle = HAL_LIFECYCLE_SHUTDOWN;
    rh->edge_bound = 0u;
    rh->permit_bound = 0u;
    rh->digest_bound = 0u;
    rh->live_bound = 0u;
    rh->edge_ctx = NULL;
    rh->permit_ctx = NULL;
    rh->digest_ctx = NULL;
    (void)memset(&rh->edge_ops, 0, sizeof(rh->edge_ops));
    (void)memset(&rh->permit_ops, 0, sizeof(rh->permit_ops));
    (void)memset(&rh->digest_ops, 0, sizeof(rh->digest_ops));
    (void)memset(&rh->live, 0, sizeof(rh->live));
    (void)memset(&rh->plan_permit, 0, sizeof(rh->plan_permit));
    (void)memset(&rh->seal_permit, 0, sizeof(rh->seal_permit));
    (void)memset(rh->plan_frame, 0, sizeof(rh->plan_frame));
    (void)memset(rh->seal_frame, 0, sizeof(rh->seal_frame));
    (void)memset(&rh->plan_view, 0, sizeof(rh->plan_view));
    (void)memset(&rh->seal_view, 0, sizeof(rh->seal_view));
    /* One-shot domain ends at shutdown; init_object starts a new domain. */
    rh->has_consumed_seq = 0u;
    rh->last_consumed_seq = 0u;
    out_safe = out_error_safe_vs_region(out_error, rh, sizeof(*rh));
    set_error(rh, out_error, out_safe, NINLIL_RADIO_HAL_OK,
        NINLIL_RADIO_HAL_STAGE_SHUTDOWN, NINLIL_RADIO_HAL_REASON_SHUTDOWN,
        "shutdown");
    return NINLIL_RADIO_HAL_OK;
}

