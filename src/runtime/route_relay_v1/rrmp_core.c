/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Production private core for ADR-0019 / ADR-0020.
 * Catalog signatures (req, out); serial domain via bound owner.
 * Dual-slot durable rehydrate; precedence matrix; forward/parent SM.
 */
#include "rrmp_abi.h"
#include "rrmp_codec.h"
#include "rrmp_store.h"
#include "rrmp_util.h"

#include "ninlil/platform.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Storage ABI compile gate (host + ESP).
 * Platform uses NINLIL_STORAGE_READ_{ONLY,WRITE} — not MODE_ prefix.
 */
#ifndef NINLIL_STORAGE_READ_ONLY
#error "ninlil_rrmp requires NINLIL_STORAGE_READ_ONLY from ninlil/platform.h"
#endif
#ifndef NINLIL_STORAGE_READ_WRITE
#error "ninlil_rrmp requires NINLIL_STORAGE_READ_WRITE from ninlil/platform.h"
#endif
#ifdef NINLIL_STORAGE_MODE_READ_ONLY
#error "use NINLIL_STORAGE_READ_ONLY (not NINLIL_STORAGE_MODE_READ_ONLY)"
#endif
#ifdef NINLIL_STORAGE_MODE_READ_WRITE
#error "use NINLIL_STORAGE_READ_WRITE (not NINLIL_STORAGE_MODE_READ_WRITE)"
#endif
_Static_assert(
    (unsigned)NINLIL_STORAGE_READ_ONLY == 1u, "storage READ_ONLY mode ABI");
_Static_assert(
    (unsigned)NINLIL_STORAGE_READ_WRITE == 2u, "storage READ_WRITE mode ABI");
_Static_assert(
    (unsigned)NINLIL_DURABILITY_FULL == 3u, "storage FULL durability ABI");

/*
 * ABI/core lockstep (audit): parent result is a distinct type from route result.
 * Parent paths must never write lifecycle_state / evidence_or_digest32.
 * Route paths must never write handoff_step / token_or_commit_digest32 / seal_allowed.
 */
_Static_assert(sizeof(ninlil_route_result_v1_t) == 128u, "core rr size");
_Static_assert(sizeof(ninlil_parent_result_v1_t) == 128u, "core pr size");
_Static_assert(offsetof(ninlil_route_result_v1_t, lifecycle_state) == 77u,
    "core rr life@77");
_Static_assert(offsetof(ninlil_route_result_v1_t, evidence_or_digest32) == 80u,
    "core rr dig@80");
_Static_assert(offsetof(ninlil_parent_result_v1_t, handoff_step) == 72u,
    "core pr step@72");
_Static_assert(offsetof(ninlil_parent_result_v1_t, seal_allowed) == 75u,
    "core pr seal@75");
_Static_assert(offsetof(ninlil_parent_result_v1_t, token_or_commit_digest32) == 80u,
    "core pr dig@80");
_Static_assert(
    offsetof(ninlil_route_result_v1_t, lifecycle_state) !=
        offsetof(ninlil_parent_result_v1_t, handoff_step),
    "route life vs parent handoff must differ");

/* --- Precedence tables (vector failure_precedence_*) --- */
static const uint32_t k_route_prec[] = {
    NINLIL_ROUTE_INVALID_ARGUMENT,     /* 0 */
    NINLIL_ROUTE_CORRUPT,              /* 1 */
    NINLIL_ROUTE_UNSUPPORTED_API,      /* 2 */
    NINLIL_ROUTE_UNSUPPORTED_SCHEMA,   /* 3 */
    NINLIL_ROUTE_FEATURE_OFF,          /* 4 */
    NINLIL_ROUTE_UNSUPPORTED_CAPABILITY, /* 5 */
    NINLIL_ROUTE_AUTHORITY_CONFLICT,   /* 6 */
    NINLIL_ROUTE_CLOCK_EPOCH_MISMATCH, /* 7 */
    NINLIL_ROUTE_LEASE_EXPIRED,        /* 8 */
    NINLIL_ROUTE_STALE_GENERATION,     /* 9 */
    NINLIL_ROUTE_NOT_ACTIVE,           /* 10 */
    NINLIL_ROUTE_DRAIN_FENCED,         /* 11 */
    NINLIL_ROUTE_LOOP,                 /* 12 */
    NINLIL_ROUTE_TERMINAL_MISMATCH,    /* 13 */
    NINLIL_ROUTE_HOP_EXHAUSTED,        /* 14 */
    NINLIL_ROUTE_REPLAY,               /* 15 */
    NINLIL_ROUTE_RESOURCE,             /* 16 */
    NINLIL_ROUTE_BACKPRESSURE,         /* 17 */
    NINLIL_ROUTE_COMMIT_UNKNOWN,       /* 18 */
    NINLIL_ROUTE_REENTRANT,            /* 19 */
    NINLIL_ROUTE_OK                    /* 20 */
};
static const char *const k_route_prec_names[] = {
    "INVALID_ARGUMENT", "CORRUPT", "UNSUPPORTED_API", "UNSUPPORTED_SCHEMA",
    "FEATURE_OFF", "UNSUPPORTED_CAPABILITY", "AUTHORITY_CONFLICT",
    "CLOCK_EPOCH_MISMATCH", "LEASE_EXPIRED", "STALE_GENERATION", "NOT_ACTIVE",
    "DRAIN_FENCED", "LOOP", "TERMINAL_MISMATCH", "HOP_EXHAUSTED", "REPLAY",
    "RESOURCE", "BACKPRESSURE", "COMMIT_UNKNOWN", "REENTRANT", "OK"
};

static const uint32_t k_parent_prec[] = {
    NINLIL_PARENT_INVALID_ARGUMENT, NINLIL_PARENT_CORRUPT,
    NINLIL_PARENT_UNSUPPORTED_API, NINLIL_PARENT_UNSUPPORTED_SCHEMA,
    NINLIL_PARENT_FEATURE_OFF, NINLIL_PARENT_UNSUPPORTED_CAPABILITY,
    NINLIL_PARENT_AUTHORITY_CONFLICT, NINLIL_PARENT_SPLIT_BRAIN,
    NINLIL_PARENT_CLOCK_EPOCH_MISMATCH, NINLIL_PARENT_LEASE_EXPIRED,
    NINLIL_PARENT_STALE_TERM, NINLIL_PARENT_STALE_REVISION,
    NINLIL_PARENT_SCOPE_MISMATCH, NINLIL_PARENT_TOKEN_REPLAY,
    NINLIL_PARENT_NOT_OWNER, NINLIL_PARENT_NOT_ACTIVE,
    NINLIL_PARENT_SAME_ATTEMPT_RESELECT, NINLIL_PARENT_RESOURCE,
    NINLIL_PARENT_COMMIT_UNKNOWN, NINLIL_PARENT_REENTRANT, NINLIL_PARENT_OK
};
static const char *const k_parent_prec_names[] = {
    "INVALID_ARGUMENT", "CORRUPT", "UNSUPPORTED_API", "UNSUPPORTED_SCHEMA",
    "FEATURE_OFF", "UNSUPPORTED_CAPABILITY", "AUTHORITY_CONFLICT", "SPLIT_BRAIN",
    "CLOCK_EPOCH_MISMATCH", "LEASE_EXPIRED", "STALE_TERM", "STALE_REVISION",
    "SCOPE_MISMATCH", "TOKEN_REPLAY", "NOT_OWNER", "NOT_ACTIVE",
    "SAME_ATTEMPT_RESELECT", "RESOURCE", "COMMIT_UNKNOWN", "REENTRANT", "OK"
};

enum rrmp_storage_outcome {
    RRMP_STORAGE_OUTCOME_NONE = 0,
    RRMP_STORAGE_OUTCOME_OK = 1,
    RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE = 2,
    RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN = 3,
    RRMP_STORAGE_OUTCOME_CONFLICT = 4,
    RRMP_STORAGE_OUTCOME_CORRUPT = 5
};

uint32_t ninlil_rrmp_route_precedence_pick(const uint8_t flags[22])
{
    size_t i;
    if (flags == NULL) {
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    for (i = 0u; i < 21u; ++i) {
        if (flags[i]) {
            return k_route_prec[i];
        }
    }
    return NINLIL_ROUTE_OK;
}

uint32_t ninlil_rrmp_parent_precedence_pick(const uint8_t flags[22])
{
    size_t i;
    if (flags == NULL) {
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    for (i = 0u; i < 21u; ++i) {
        if (flags[i]) {
            return k_parent_prec[i];
        }
    }
    return NINLIL_PARENT_OK;
}

const char *const *ninlil_rrmp_route_precedence_names(void)
{
    return k_route_prec_names;
}

const char *const *ninlil_rrmp_parent_precedence_names(void)
{
    return k_parent_prec_names;
}

/* --- Owner --- */
typedef struct rrmp_route {
    uint8_t used;
    uint8_t state; /* LIFE_* */
    ninlil_rrmp_nrm1_fields_t fields;
    uint64_t next_admission_seq;
    ninlil_rrmp_drain_fence_t drain;
    /* durable_slot not retained; re-encode on page publish (ESP budget). */
} rrmp_route_t;

typedef struct rrmp_evi {
    uint8_t used;
    uint8_t raw[NINLIL_RRMP_NEV1_BYTES];
    ninlil_rrmp_digest32_t key;
    uint64_t opaque_handle; /* admit ownership token for complete */
    uint8_t auth_link_ack;  /* 1 only after authenticated bearer LINK_ACK */
    uint64_t outer_tx_counter;
    uint8_t auth_peer_runtime_id[16];
} rrmp_evi_t;

typedef struct rrmp_q {
    uint8_t used;
    uint8_t prio; /* CONTROL=0 SAFETY=1 NORMAL=2 BULK=3 */
    uint16_t handle;
    uint16_t gen;
    uint32_t ingress_hop_context_id;
    uint64_t admission_seq;
    uint64_t token;
    uint64_t opaque_handle;
    uint64_t route_revision;
    uint64_t absolute_deadline_ms;
    uint32_t remaining_link_groups;
    uint32_t remaining_attempts;
    uint8_t hop_in;
    uint8_t hop_out;
    uint8_t e2e_digest[32];
    uint8_t e2e_body[96]; /* actual ingress E2E bytes (NRM1 materialize) */
    uint16_t e2e_body_len;
    uint16_t payload_len; /* == e2e_body_len; no separate inject buffer */
    uint8_t owner_scope_id[16];
    uint8_t owner_scope_set;
    uint8_t terminal;
    uint8_t tx_done;
    uint8_t link_ack;
    uint8_t tx_permit;
    uint8_t await_ack; /* outbound submitted; waiting authenticated LINK_ACK */
    uint8_t retry_exhausted;
    uint8_t selected_parent_set;
    uint16_t retry_count;
    uint16_t retry_limit;
    uint32_t link_ack_wait_ms;
    uint64_t ack_deadline_ms;
    uint64_t retry_not_before_ms;
    uint16_t carrier_offset;
    uint16_t carrier_len;
    uint8_t attempt_id16[16];
    uint8_t selected_parent_id[16];
    uint8_t expected_peer_id[16];
    uint8_t caller_principal_id[16];
    uint64_t outer_rx_counter;
    uint64_t outer_tx_counter;
} rrmp_q_t;

typedef struct NINLIL_RRMP_PACKED rrmp_attempt_row {
    uint8_t owner_scope_id[16];
    uint8_t attempt_id16[16];
    uint8_t lifecycle;
    uint8_t flags;
    uint8_t reserved0[6];
    uint8_t terminal_evidence_digest32[32];
    uint64_t reclaim_not_before_ms;
} rrmp_attempt_row_t;
_Static_assert(sizeof(rrmp_attempt_row_t) == NINLIL_RRMP_QST4_ATTEMPT_BYTES,
    "QST4 attempt row exact 80");

/*
 * Live scope. NPS1 is re-encoded from semantic fields. NOA1 is copy-owned
 * because every NPA1 page rewrite must preserve all other scopes even when
 * their current page is being relocated.
 */
typedef struct rrmp_scope {
    uint8_t used;
    uint8_t owner_scope_id[16];
    uint8_t handoff;
    uint8_t token_dig[32];
    uint8_t commit_dig[32];
    uint8_t proof_dig[32];
    uint8_t nps1_record_digest[32];
    uint8_t noa1_body_digest[32];
    uint8_t token_consumed;
    uint8_t proof;
    uint8_t cas;
    uint8_t receipt;
    uint8_t new_seal;
    uint8_t old_seal; /* ADR: 0 after OLD_RETIRED (S6) */
    uint8_t tombstone;
    uint8_t split_brain;
    uint8_t parent_loss_seal;
    uint8_t downlink_tx_scope;
    uint8_t noa1_present;
    uint8_t noa1_raw[NINLIL_RRMP_NOA1_BYTES];
    uint64_t token_created_ms;
    uint8_t last_attempt_id16[16]; /* durable same-attempt fence identity */
    uint8_t attempt_selected;
    uint8_t selected_parent[16];
    uint8_t parent_lost[NINLIL_RRMP_PARENT_MAX]; /* per-parent loss mask */
    uint8_t old_owner[16];
    uint8_t is_old_owner_local;
    uint64_t installed_revision;
    uint8_t path_policy_id[16];
    uint64_t path_policy_revision;
    uint8_t parent_count;
    uint8_t parent_ids[NINLIL_RRMP_PARENT_MAX][16];
    uint8_t parent_set_digest[32];
    uint64_t noa1_controller_term;
    uint64_t noa1_assignment_revision;
    uint64_t lease_not_after_ms;
    ninlil_rrmp_authority_tuple_v2_t handoff_old_tuple;
    ninlil_rrmp_authority_tuple_v2_t handoff_new_tuple;
} rrmp_scope_t;

typedef struct rrmp_ring {
    uint8_t keys[NINLIL_RRMP_LOOP_WINDOW][16]; /* truncated digests */
    uint16_t count;
    uint16_t next;
} rrmp_ring_t;

struct ninlil_rrmp_owner {
    uint32_t magic;
    ninlil_rrmp_owner_config_v1_t cfg;
    uint8_t entered;
    rrmp_route_t routes[NINLIL_RRMP_ROUTE_MAX];
    rrmp_evi_t evidence[NINLIL_RRMP_EVIDENCE_CAPACITY];
    uint64_t lifetime_admits;
    rrmp_ring_t loop_ring;
    rrmp_ring_t dedup_ring;
    rrmp_q_t queue[NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES];
    uint8_t carrier_arena[NINLIL_RRMP_QUEUE_GLOBAL_BYTES];
    uint16_t carrier_arena_used;
    uint32_t q_entries;
    uint32_t q_control_entries;
    uint32_t q_bytes;
    uint32_t bulk_streak;
    rrmp_scope_t scopes[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY];
    rrmp_attempt_row_t attempts[NINLIL_RRMP_QST4_ATTEMPT_CAPACITY];
    uint16_t attempt_count;
    uint8_t authority_global_fence;
    uint8_t authority_global_fence_reason;
    ninlil_rrmp_route_ns_t route_ns;
    ninlil_rrmp_parent_ns_t parent_ns;
    uint8_t downlink_tx; /* global only under namespace CU fence */
    uint64_t next_handle_token;
    uint32_t diag_installs;
    uint32_t diag_admits;
    uint32_t diag_forwards;
    /*
     * Bounded encode scratch (owner workspace, not task stack).
     * Used by parent/route page encode paths so frames stay << 4 KiB.
     */
    uint8_t enc_page_a[4096];
    /* Route-slot staging; owner-local so independent owners never alias it. */
    uint8_t enc_page_b[4096];
    uint8_t enc_nps_slots[NINLIL_RRMP_NPP1_SLOTS][NINLIL_RRMP_NPS1_BYTES];
    uint8_t enc_aslot[NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES];
    uint8_t enc_npts[NINLIL_RRMP_NPT1_SLOT_BYTES];
    /* Fabric select dispatch pin (last selected path instance). */
    uint8_t last_fabric_path_id[16];
    uint8_t last_fabric_path_set;
    uint64_t last_fabric_path_epoch;
    /* Multi-parent owner_scope derivation inputs (ADR-0020 §4). */
    ninlil_rrmp_scope_derivation_ctx_t scope_derivation;
    uint8_t scope_derivation_set;
    /* Outbound bearer/radio packet ownership (no fabricated send/ACK). */
    ninlil_rrmp_outbound_provider_t outbound;
    uint8_t outbound_set;
    /* Optional production durable storage ops (FULL writepoints). */
    const ninlil_storage_ops_t *storage_ops;
    ninlil_storage_handle_t storage_handle;
    uint8_t storage_bound;
    const ninlil_rrmp_storage_authority_v2_t *storage_authority_v2;
    uint8_t storage_hard_fence;
    uint8_t storage_expected_valid;
    uint8_t storage_expected_present;
    uint8_t storage_pending_unknown;
    uint8_t storage_pending_old_present;
    uint32_t storage_expected_length;
    uint32_t storage_pending_old_length;
    uint32_t storage_pending_new_length;
    uint32_t storage_last_outcome;
    uint8_t storage_expected_digest[32];
    uint8_t storage_pending_old_digest[32];
    uint8_t storage_pending_new_digest[32];
    uint8_t storage_expected_manifest[NINLIL_RRMP_RRM1_BYTES];
    uint8_t storage_pending_old_manifest[NINLIL_RRMP_RRM1_BYTES];
    uint8_t storage_pending_new_manifest[NINLIL_RRMP_RRM1_BYTES];
    /*
     * Durable bundle scratch is part of the caller-owned owner workspace.
     * Keeping it here makes two owners independent and removes the former
     * process-global / ESP lazy-allocation state.
     */
    uint8_t storage_export_scratch[NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX];
    uint8_t storage_piece_scratch[NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX];
    /* Explicit caller-owned serial-domain authorization state. */
    uint8_t serial_bound;
    uint8_t auth_active;
    uint8_t auth_principal_id[16];
    uint32_t auth_capabilities;
};

static int completed_evidence_is_attempt_pinned(
    const ninlil_rrmp_owner_t *o,
    const uint8_t raw[NINLIL_RRMP_NEV1_BYTES]);
static int bundle_witness_equal(
    const ninlil_rrmp_bundle_witness_v2_t *a,
    const ninlil_rrmp_bundle_witness_v2_t *b);

#define NINLIL_RRMP_OWNER_MAGIC 0x52524d50u /* 'RRMP' */

size_t ninlil_rrmp_owner_workspace_bytes(void)
{
    return sizeof(ninlil_rrmp_owner_t);
}

/* Compile-time budget: owner and durable scratch fit one explicit ceiling. */
_Static_assert(
    sizeof(struct ninlil_rrmp_owner) <= NINLIL_RRMP_OWNER_WORKSPACE_BUDGET_BYTES,
    "rrmp owner workspace exceeds 768 KiB budget");
_Static_assert(
    sizeof(((struct ninlil_rrmp_owner *)0)->enc_page_b) >=
        NINLIL_RRMP_SLOTS_PER_PAGE * NINLIL_RRMP_SLOT_BYTES,
    "rrmp owner route-slot scratch is too small");
_Static_assert(
    NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY <=
        NINLIL_RRMP_NPT1_PAGE_COUNT * NINLIL_RRMP_NPT1_SLOTS_PER_PAGE,
    "rrmp replay ledger exceeds NPT1 physical capacity");

static int owner_is_live(const ninlil_rrmp_owner_t *owner)
{
    return owner != NULL && owner->magic == NINLIL_RRMP_OWNER_MAGIC;
}

static int owner_serial_active(const ninlil_rrmp_owner_t *owner)
{
    return owner_is_live(owner) && owner->serial_bound != 0u;
}

static void owner_serial_clear(ninlil_rrmp_owner_t *owner)
{
    owner->serial_bound = 0u;
    owner->auth_active = 0u;
    owner->auth_capabilities = 0u;
    ninlil_rrmp_memzero(owner->auth_principal_id, 16u);
}

static int owner_has_capability(
    const ninlil_rrmp_owner_t *owner, uint32_t required)
{
    if (!owner_serial_active(owner)) {
        return 0;
    }
    if (!owner->cfg.authorization_required) {
        return 1;
    }
    return owner->auth_active &&
        (owner->auth_capabilities & required) == required;
}

static int owner_storage_hard_fenced(const ninlil_rrmp_owner_t *owner)
{
    return owner != NULL && owner->storage_hard_fence != 0u;
}

static int owner_authority_global_fenced(const ninlil_rrmp_owner_t *owner)
{
    return owner != NULL && owner->authority_global_fence != 0u;
}

static void owner_storage_fence(ninlil_rrmp_owner_t *owner)
{
    if (owner == NULL) {
        return;
    }
    owner->storage_hard_fence = 1u;
    owner->route_ns.fenced = 1u;
    owner->parent_ns.fenced = 1u;
    owner->downlink_tx = 0u;
}

/*
 * Every externally reachable mutating/select/send/worker path crosses one of
 * these gates before it can touch RAM.  A platform COMMIT_UNKNOWN is an outer
 * namespace fence, not merely a route- or parent-local condition.
 */
static uint32_t owner_route_fence_status(const ninlil_rrmp_owner_t *owner)
{
    if (owner_authority_global_fenced(owner)) {
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (!owner_storage_hard_fenced(owner)) {
        return NINLIL_ROUTE_OK;
    }
    if (owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_CONFLICT) {
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN) {
        return NINLIL_ROUTE_COMMIT_UNKNOWN;
    }
    if (owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_CORRUPT ||
        owner->route_ns.cu_class == NINLIL_RRMP_CU_PARTIAL ||
        owner->route_ns.cu_class == NINLIL_RRMP_CU_EXTRA ||
        owner->route_ns.cu_class == NINLIL_RRMP_CU_THIRD) {
        return NINLIL_ROUTE_CORRUPT;
    }
    return NINLIL_ROUTE_COMMIT_UNKNOWN;
}

static uint32_t owner_route_write_gate(ninlil_rrmp_owner_t *owner)
{
    uint32_t st = owner_route_fence_status(owner);
    if (st != NINLIL_ROUTE_OK) {
        return st;
    }
    if (owner != NULL && owner->storage_bound) {
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_NONE;
    }
    return NINLIL_ROUTE_OK;
}

static uint32_t owner_parent_fence_status(const ninlil_rrmp_owner_t *owner)
{
    if (owner_authority_global_fenced(owner)) {
        return NINLIL_PARENT_SPLIT_BRAIN;
    }
    if (!owner_storage_hard_fenced(owner)) {
        return NINLIL_PARENT_OK;
    }
    if (owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_CONFLICT) {
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN) {
        return NINLIL_PARENT_COMMIT_UNKNOWN;
    }
    if (owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_CORRUPT ||
        owner->parent_ns.cu_class == NINLIL_RRMP_CU_PARTIAL ||
        owner->parent_ns.cu_class == NINLIL_RRMP_CU_EXTRA ||
        owner->parent_ns.cu_class == NINLIL_RRMP_CU_THIRD) {
        return NINLIL_PARENT_CORRUPT;
    }
    return NINLIL_PARENT_COMMIT_UNKNOWN;
}

static uint32_t owner_parent_write_gate(ninlil_rrmp_owner_t *owner)
{
    uint32_t st = owner_parent_fence_status(owner);
    if (st != NINLIL_PARENT_OK) {
        return st;
    }
    if (owner != NULL && owner->storage_bound) {
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_NONE;
    }
    return NINLIL_PARENT_OK;
}

/* Route-result only helpers (typed — cannot accept parent_result without cast). */
static void result_fill(
    ninlil_route_result_v1_t *out, uint32_t status)
{
    if (out == NULL) {
        return;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->api_version = NINLIL_RRMP_API_VERSION;
    out->struct_size = 128u;
    out->status = status;
}

/* Parent-result only helpers (typed — no route-result field names).
 * Route lifecycle/evidence: assign out->lifecycle_state / memcpy evidence
 * directly at call sites (never via self-calling wrappers).
 */
static void parent_result_fill(
    ninlil_parent_result_v1_t *out, uint32_t status)
{
    if (out == NULL) {
        return;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->api_version = NINLIL_RRMP_API_VERSION;
    out->struct_size = 128u;
    out->status = status;
    out->handoff_step = 0u;
    out->local_state = 0u;
    out->cu_class = 0u;
    out->seal_allowed = 0u;
}

static void parent_result_ok_scope(
    ninlil_parent_result_v1_t *out,
    const ninlil_rrmp_owner_t *owner,
    const rrmp_scope_t *sc,
    uint32_t status)
{
    parent_result_fill(out, status);
    if (out == NULL || sc == NULL) {
        return;
    }
    memcpy(out->owner_scope_id, sc->owner_scope_id, 16u);
    out->controller_term = sc->noa1_controller_term;
    out->assignment_revision = sc->noa1_assignment_revision;
    out->handoff_step = sc->handoff;
    out->local_state = sc->handoff; /* NPA1 local_state tracks handoff step */
    out->cu_class = 0u;
    out->seal_allowed =
        (owner == NULL || owner_authority_global_fenced(owner) ||
            !owner->downlink_tx || owner->route_ns.fenced ||
            owner->parent_ns.fenced || sc->split_brain ||
            sc->parent_loss_seal || sc->downlink_tx_scope == 0u ||
            (sc->handoff >= NINLIL_RRMP_HANDOFF_PREPARED_NEW &&
                sc->handoff < NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED) ||
            (sc->handoff >= NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED &&
                sc->new_seal == 0u))
            ? 0u
            : 1u;
    out->detail_flags =
        (uint32_t)(out->seal_allowed ? 1u : 0u) |
        (sc->split_brain ? 2u : 0u) |
        (sc->parent_loss_seal ? 4u : 0u);
    if (sc->receipt || sc->cas) {
        memcpy(out->token_or_commit_digest32, sc->commit_dig, 32u);
    } else {
        memcpy(out->token_or_commit_digest32, sc->token_dig, 32u);
    }
}

/* Preamble validation collecting precedence flags (route domain). */
static uint32_t preamble_route(
    const ninlil_rrmp_preamble_v1_t *p,
    uint32_t fixed_size,
    const uint8_t *full_struct,
    uint8_t flags[22])
{
    ninlil_rrmp_memzero(flags, 22u);
    if (p == NULL || full_struct == NULL) {
        flags[0] = 1u; /* INVALID_ARGUMENT */
        return ninlil_rrmp_route_precedence_pick(flags);
    }
    if (p->api_version != NINLIL_RRMP_API_VERSION) {
        flags[2] = 1u; /* UNSUPPORTED_API */
    }
    if (p->struct_size < fixed_size) {
        flags[2] = 1u;
    }
    if (p->reserved0 != 0u || p->reserved1 != 0u) {
        flags[1] = 1u; /* CORRUPT */
    }
    if (p->struct_size > fixed_size) {
        size_t i;
        int nonzero = 0;
        for (i = fixed_size; i < p->struct_size; ++i) {
            if (full_struct[i] != 0u) {
                nonzero = 1;
                break;
            }
        }
        if (nonzero) {
            flags[1] = 1u; /* CORRUPT */
        }
        /* else forward-compat: ok */
    }
    return ninlil_rrmp_route_precedence_pick(flags);
}

static uint32_t preamble_parent(
    const ninlil_rrmp_preamble_v1_t *p,
    uint32_t fixed_size,
    const uint8_t *full_struct,
    uint8_t flags[22])
{
    ninlil_rrmp_memzero(flags, 22u);
    if (p == NULL || full_struct == NULL) {
        flags[0] = 1u;
        return ninlil_rrmp_parent_precedence_pick(flags);
    }
    if (p->api_version != NINLIL_RRMP_API_VERSION) {
        flags[2] = 1u;
    }
    if (p->struct_size < fixed_size) {
        flags[2] = 1u;
    }
    if (p->reserved0 != 0u || p->reserved1 != 0u) {
        flags[1] = 1u;
    }
    if (p->struct_size > fixed_size) {
        size_t i;
        for (i = fixed_size; i < p->struct_size; ++i) {
            if (full_struct[i] != 0u) {
                flags[1] = 1u;
                break;
            }
        }
    }
    return ninlil_rrmp_parent_precedence_pick(flags);
}

static uint32_t preamble_parent_v2(
    const ninlil_rrmp_preamble_v1_t *p, uint32_t exact_size)
{
    if (p == NULL) {
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    if (p->api_version != NINLIL_RRMP_PRIVATE_V2_API_VERSION ||
        p->struct_size != exact_size) {
        return NINLIL_PARENT_UNSUPPORTED_API;
    }
    if (p->reserved0 != 0u || p->reserved1 != 0u) {
        return NINLIL_PARENT_CORRUPT;
    }
    return NINLIL_PARENT_OK;
}

static int enter(ninlil_rrmp_owner_t *o)
{
    if (o == NULL) {
        return 0;
    }
    if (o->entered) {
        return -1;
    }
    o->entered = 1u;
    return 1;
}

static void leave(ninlil_rrmp_owner_t *o)
{
    if (o != NULL) {
        o->entered = 0u;
    }
}

static void ring_push16(rrmp_ring_t *r, const uint8_t dig32[32])
{
    memcpy(r->keys[r->next], dig32, 16u);
    r->next = (uint16_t)((r->next + 1u) % NINLIL_RRMP_LOOP_WINDOW);
    if (r->count < NINLIL_RRMP_LOOP_WINDOW) {
        r->count = (uint16_t)(r->count + 1u);
    }
}

static int ring_has16(const rrmp_ring_t *r, const uint8_t dig32[32])
{
    uint16_t i;
    for (i = 0u; i < r->count; ++i) {
        if (ninlil_rrmp_memeq(r->keys[i], dig32, 16u)) {
            return 1;
        }
    }
    return 0;
}

static int carrier_arena_append(
    ninlil_rrmp_owner_t *o,
    const uint8_t *carrier,
    uint16_t carrier_len,
    uint16_t *offset_out)
{
    uint32_t end;
    if (o == NULL || offset_out == NULL) {
        return 0;
    }
    *offset_out = 0u;
    if (carrier_len == 0u) {
        return carrier == NULL ? 1 : 0;
    }
    if (carrier == NULL) {
        return 0;
    }
    end = (uint32_t)o->carrier_arena_used + (uint32_t)carrier_len;
    if (end > NINLIL_RRMP_QUEUE_GLOBAL_BYTES || end > UINT16_MAX) {
        return 0;
    }
    *offset_out = o->carrier_arena_used;
    memcpy(o->carrier_arena + o->carrier_arena_used, carrier, carrier_len);
    o->carrier_arena_used = (uint16_t)end;
    return 1;
}

static const uint8_t *queue_carrier(
    const ninlil_rrmp_owner_t *o, const rrmp_q_t *q)
{
    uint32_t end;
    if (o == NULL || q == NULL || q->carrier_len == 0u) {
        return NULL;
    }
    end = (uint32_t)q->carrier_offset + (uint32_t)q->carrier_len;
    if (end > o->carrier_arena_used ||
        end > NINLIL_RRMP_QUEUE_GLOBAL_BYTES) {
        return NULL;
    }
    return o->carrier_arena + q->carrier_offset;
}

static void queue_release(
    ninlil_rrmp_owner_t *o, rrmp_q_t *q)
{
    uint16_t off;
    uint16_t len;
    size_t i;
    uint32_t charge;
    if (o == NULL || q == NULL || !q->used) {
        return;
    }
    off = q->carrier_offset;
    len = q->carrier_len;
    if (len != 0u &&
        (uint32_t)off + (uint32_t)len <= o->carrier_arena_used) {
        uint16_t tail =
            (uint16_t)(o->carrier_arena_used - (uint16_t)(off + len));
        if (tail != 0u) {
            memmove(
                o->carrier_arena + off,
                o->carrier_arena + off + len,
                tail);
        }
        o->carrier_arena_used = (uint16_t)(o->carrier_arena_used - len);
        ninlil_rrmp_memzero(
            o->carrier_arena + o->carrier_arena_used, len);
        for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
            rrmp_q_t *other = &o->queue[i];
            if (other != q && other->used && other->carrier_len != 0u &&
                other->carrier_offset > off) {
                other->carrier_offset =
                    (uint16_t)(other->carrier_offset - len);
            }
        }
    }
    if (q->prio == NINLIL_RRMP_PRIO_CONTROL ||
        q->prio == NINLIL_RRMP_PRIO_SAFETY) {
        if (o->q_control_entries > 0u) {
            o->q_control_entries -= 1u;
        }
    }
    if (o->q_entries > 0u) {
        o->q_entries -= 1u;
    }
    charge = (uint32_t)q->e2e_body_len + (uint32_t)q->carrier_len;
    if (o->q_bytes >= charge) {
        o->q_bytes -= charge;
    } else {
        o->q_bytes = 0u;
    }
    ninlil_rrmp_memzero(q, sizeof(*q));
}

static rrmp_route_t *find_route(
    ninlil_rrmp_owner_t *o, uint32_t hop_ctx, uint16_t h, uint16_t g)
{
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_ROUTE_MAX; ++i) {
        if (o->routes[i].used &&
            o->routes[i].fields.ingress_hop_context_id == hop_ctx &&
            o->routes[i].fields.route_handle == h &&
            o->routes[i].fields.route_generation == g) {
            return &o->routes[i];
        }
    }
    return NULL;
}

static rrmp_route_t *alloc_route(ninlil_rrmp_owner_t *o)
{
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_ROUTE_MAX; ++i) {
        if (!o->routes[i].used) {
            ninlil_rrmp_memzero(&o->routes[i], sizeof(o->routes[i]));
            o->routes[i].used = 1u;
            return &o->routes[i];
        }
    }
    return NULL;
}

static rrmp_scope_t *find_scope(ninlil_rrmp_owner_t *o, const uint8_t scope[16])
{
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (o->scopes[i].used &&
            ninlil_rrmp_memeq(o->scopes[i].owner_scope_id, scope, 16u)) {
            return &o->scopes[i];
        }
    }
    return NULL;
}

static size_t scope_index_of(
    const ninlil_rrmp_owner_t *o, const rrmp_scope_t *scope)
{
    size_t i;
    if (o == NULL || scope == NULL) {
        return NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY;
    }
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (&o->scopes[i] == scope) {
            return i;
        }
    }
    return NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY;
}

static rrmp_scope_t *alloc_scope(ninlil_rrmp_owner_t *o)
{
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (!o->scopes[i].used) {
            ninlil_rrmp_memzero(&o->scopes[i], sizeof(o->scopes[i]));
            o->scopes[i].used = 1u;
            return &o->scopes[i];
        }
    }
    return NULL;
}

static int bytes_have_nonzero(const uint8_t *bytes, size_t len)
{
    size_t i;
    uint8_t any = 0u;
    if (bytes == NULL) {
        return 0;
    }
    for (i = 0u; i < len; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any != 0u ? 1 : 0;
}

static int attempt_key_compare(
    const uint8_t scope_a[16],
    const uint8_t attempt_a[16],
    const uint8_t scope_b[16],
    const uint8_t attempt_b[16])
{
    int c = memcmp(scope_a, scope_b, 16u);
    return c != 0 ? c : memcmp(attempt_a, attempt_b, 16u);
}

static int attempt_find_index(
    const ninlil_rrmp_owner_t *o,
    const uint8_t scope[16],
    const uint8_t attempt[16],
    uint16_t *index_out)
{
    uint16_t i;
    if (o == NULL || scope == NULL || attempt == NULL) {
        return 0;
    }
    for (i = 0u; i < o->attempt_count; ++i) {
        int c = attempt_key_compare(
            o->attempts[i].owner_scope_id,
            o->attempts[i].attempt_id16,
            scope,
            attempt);
        if (c == 0) {
            if (index_out != NULL) {
                *index_out = i;
            }
            return 1;
        }
        if (c > 0) {
            break;
        }
    }
    if (index_out != NULL) {
        *index_out = i;
    }
    return 0;
}

static int attempt_insert_live(
    ninlil_rrmp_owner_t *o,
    const uint8_t scope[16],
    const uint8_t attempt[16],
    uint16_t *index_out)
{
    uint16_t at = 0u;
    if (o == NULL || scope == NULL || attempt == NULL ||
        !bytes_have_nonzero(scope, 16u) ||
        !bytes_have_nonzero(attempt, 16u) ||
        attempt_find_index(o, scope, attempt, &at) ||
        o->attempt_count >= NINLIL_RRMP_QST4_ATTEMPT_CAPACITY) {
        return 0;
    }
    if (at < o->attempt_count) {
        memmove(
            &o->attempts[at + 1u],
            &o->attempts[at],
            (size_t)(o->attempt_count - at) * sizeof(o->attempts[0]));
    }
    ninlil_rrmp_memzero(&o->attempts[at], sizeof(o->attempts[at]));
    memcpy(o->attempts[at].owner_scope_id, scope, 16u);
    memcpy(o->attempts[at].attempt_id16, attempt, 16u);
    o->attempts[at].lifecycle = NINLIL_RRMP_ATTEMPT_LIVE;
    o->attempt_count = (uint16_t)(o->attempt_count + 1u);
    if (index_out != NULL) {
        *index_out = at;
    }
    return 1;
}

static void attempt_remove_at(ninlil_rrmp_owner_t *o, uint16_t at)
{
    if (o == NULL || at >= o->attempt_count) {
        return;
    }
    if ((uint16_t)(at + 1u) < o->attempt_count) {
        memmove(
            &o->attempts[at],
            &o->attempts[at + 1u],
            (size_t)(o->attempt_count - at - 1u) * sizeof(o->attempts[0]));
    }
    o->attempt_count = (uint16_t)(o->attempt_count - 1u);
    ninlil_rrmp_memzero(&o->attempts[o->attempt_count],
        sizeof(o->attempts[o->attempt_count]));
}

/*
 * NPT1 is a namespace-global replay ledger, not one token slot per live
 * owner scope.  The physical layout can hold more, but ADR-0020 deliberately
 * caps the fail-closed replay-retention set at 256 entries.
 *
 * Pages are a packed prefix: full pages, then at most one partial page, then
 * empty/absent pages.  `digest32 == NULL` requests only the total.  A digest
 * lookup is valid only when it occurs at most once across the whole namespace.
 */
static int npt_ledger_summary(
    const ninlil_rrmp_owner_t *o,
    const uint8_t digest32[32],
    uint16_t *total_out,
    uint8_t *match_count_out,
    uint8_t *kind_out,
    uint64_t *created_ms_out)
{
    uint16_t total = 0u;
    uint8_t matches = 0u;
    uint8_t saw_partial = 0u;
    uint8_t pi;
    if (o == NULL || total_out == NULL) {
        return 0;
    }
    for (pi = 0u; pi < NINLIL_RRMP_NPT1_PAGE_COUNT; ++pi) {
        const uint8_t *page = NULL;
        uint32_t len = 0u;
        uint64_t gen = 0u;
        uint32_t count = 0u;
        uint32_t si;
        uint8_t kid = (uint8_t)(NINLIL_RRMP_PKEY_NPT1_BASE + pi);
        if (!ninlil_rrmp_parent_dual_read_active(
                &o->parent_ns, kid, &page, &len, &gen)) {
            saw_partial = 1u;
            continue;
        }
        if (page == NULL || len != NINLIL_RRMP_NPT1_BYTES ||
            gen == 0u || gen >= UINT32_MAX ||
            !ninlil_rrmp_validate_npt1(page) ||
            ninlil_rrmp_get_u16_be(page + 6u) != pi ||
            ninlil_rrmp_get_u32_be(page + 8u) != (uint32_t)gen) {
            return 0;
        }
        count = ninlil_rrmp_get_u32_be(page + 12u);
        if ((saw_partial && count != 0u) ||
            (uint32_t)total + count >
                NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY) {
            return 0;
        }
        if (count < NINLIL_RRMP_NPT1_SLOTS_PER_PAGE) {
            saw_partial = 1u;
        }
        for (si = 0u; digest32 != NULL && si < count; ++si) {
            const uint8_t *slot =
                page + NINLIL_RRMP_NPT1_HEADER_BYTES +
                (size_t)si * NINLIL_RRMP_NPT1_SLOT_BYTES;
            if (!ninlil_rrmp_memeq(slot, digest32, 32u)) {
                continue;
            }
            if (matches != 0u) {
                return 0;
            }
            matches = 1u;
            if (kind_out != NULL) {
                *kind_out = slot[32u];
            }
            if (created_ms_out != NULL) {
                *created_ms_out = ninlil_rrmp_get_u64_be(slot + 36u);
            }
        }
        total = (uint16_t)(total + (uint16_t)count);
    }
    *total_out = total;
    if (match_count_out != NULL) {
        *match_count_out = matches;
    }
    return 1;
}

static int parent_rehydrate_corrupt(ninlil_rrmp_owner_t *o)
{
    if (o != NULL) {
        size_t i;
        o->parent_ns.corrupt = 1u;
        o->parent_ns.fenced = 1u;
        o->parent_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
        o->downlink_tx = 0u;
        for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
            if (o->scopes[i].used) {
                o->scopes[i].downlink_tx_scope = 0u;
            }
        }
    }
    return 0;
}

/* LIFE_* (runtime) ↔ ROUTE_STATE_* (durable slot[0]); never conflate EXPIRED/RETIRED. */
static uint8_t life_to_slot_state(uint8_t life)
{
    switch (life) {
    case NINLIL_RRMP_LIFE_STAGED:
        return NINLIL_RRMP_ROUTE_STATE_INSTALLED;
    case NINLIL_RRMP_LIFE_ACTIVE:
        return NINLIL_RRMP_ROUTE_STATE_ACTIVE;
    case NINLIL_RRMP_LIFE_DRAINING:
        return NINLIL_RRMP_ROUTE_STATE_DRAINING;
    case NINLIL_RRMP_LIFE_EXPIRED:
        return NINLIL_RRMP_ROUTE_STATE_EXPIRED;
    case NINLIL_RRMP_LIFE_RETIRED:
        return NINLIL_RRMP_ROUTE_STATE_RETIRED;
    default:
        return NINLIL_RRMP_ROUTE_STATE_EMPTY;
    }
}

static uint8_t slot_to_life(uint8_t slot_state)
{
    switch (slot_state) {
    case NINLIL_RRMP_ROUTE_STATE_INSTALLED:
        return NINLIL_RRMP_LIFE_STAGED;
    case NINLIL_RRMP_ROUTE_STATE_ACTIVE:
        return NINLIL_RRMP_LIFE_ACTIVE;
    case NINLIL_RRMP_ROUTE_STATE_DRAINING:
        return NINLIL_RRMP_LIFE_DRAINING;
    case NINLIL_RRMP_ROUTE_STATE_EXPIRED:
        return NINLIL_RRMP_LIFE_EXPIRED;
    case NINLIL_RRMP_ROUTE_STATE_RETIRED:
        return NINLIL_RRMP_LIFE_RETIRED;
    default:
        return NINLIL_RRMP_LIFE_EMPTY;
    }
}

static int persist_route_page(ninlil_rrmp_owner_t *o, uint16_t page)
{
    const uint8_t *slots[NINLIL_RRMP_SLOTS_PER_PAGE];
    uint8_t (*slot_scratch)[NINLIL_RRMP_SLOT_BYTES] =
        (uint8_t (*)[NINLIL_RRMP_SLOT_BYTES])o->enc_page_b;
    uint8_t *buf;
    size_t cap;
    uint64_t gen;
    size_t i;
    size_t base = (size_t)page * NINLIL_RRMP_SLOTS_PER_PAGE;
    uint8_t kid = (uint8_t)(NINLIL_RRMP_KEY_NRP1_BASE + page);
    ninlil_rrmp_memzero(o->enc_page_b, sizeof(o->enc_page_b));
    for (i = 0u; i < NINLIL_RRMP_SLOTS_PER_PAGE; ++i) {
        size_t idx = base + i;
        if (idx < NINLIL_RRMP_ROUTE_MAX && o->routes[idx].used) {
            uint8_t ss = life_to_slot_state(o->routes[idx].state);
            (void)ninlil_rrmp_encode_slot(
                ss,
                &o->routes[idx].fields,
                o->routes[idx].next_admission_seq,
                o->routes[idx].state == NINLIL_RRMP_LIFE_DRAINING
                    ? &o->routes[idx].drain
                    : NULL,
                slot_scratch[i]);
            slots[i] = slot_scratch[i];
        } else {
            slots[i] = NULL;
        }
    }
    if (!ninlil_rrmp_route_dual_begin_write(&o->route_ns, kid, &buf, &cap, &gen)) {
        ninlil_rrmp_memzero(o->enc_page_b, sizeof(o->enc_page_b));
        return 0;
    }
    if (!ninlil_rrmp_encode_nrp1(page, (uint32_t)gen, slots, buf)) {
        ninlil_rrmp_memzero(o->enc_page_b, sizeof(o->enc_page_b));
        return 0;
    }
    ninlil_rrmp_memzero(o->enc_page_b, sizeof(o->enc_page_b));
    if (!ninlil_rrmp_route_dual_commit(&o->route_ns, kid, NINLIL_RRMP_NRP1_BYTES)) {
        return 0;
    }
    /* directory FULL with evidence gens */
    {
        uint32_t rgens[NINLIL_RRMP_PAGE_COUNT];
        uint32_t egens[NINLIL_RRMP_NEP1_PAGE_COUNT];
        uint8_t *dbuf;
        size_t dcap;
        uint64_t dgen;
        ninlil_rrmp_id16_t auth;
        size_t p;
        ninlil_rrmp_memzero(rgens, sizeof(rgens));
        ninlil_rrmp_memzero(egens, sizeof(egens));
        for (p = 0u; p < NINLIL_RRMP_PAGE_COUNT; ++p) {
            uint8_t k = (uint8_t)(NINLIL_RRMP_KEY_NRP1_BASE + p);
            const uint8_t *rd;
            uint32_t rl;
            uint64_t rg;
            if (ninlil_rrmp_route_dual_read_active(&o->route_ns, k, &rd, &rl, &rg)) {
                rgens[p] = (uint32_t)rg;
            }
        }
        for (p = 0u; p < NINLIL_RRMP_NEP1_PAGE_COUNT; ++p) {
            uint8_t k = (uint8_t)(NINLIL_RRMP_KEY_NEP1_BASE + p);
            const uint8_t *rd;
            uint32_t rl;
            uint64_t rg;
            if (ninlil_rrmp_route_dual_read_active(&o->route_ns, k, &rd, &rl, &rg)) {
                egens[p] = (uint32_t)rg;
            }
        }
        memcpy(auth.bytes, o->cfg.authority_id, 16u);
        if (!ninlil_rrmp_route_dual_begin_write(
                &o->route_ns, NINLIL_RRMP_KEY_NRD1, &dbuf, &dcap, &dgen)) {
            return 0;
        }
        if (!ninlil_rrmp_encode_nrd1(
                dgen, &auth, o->cfg.controller_term, rgens, egens, dbuf)) {
            return 0;
        }
        if (!ninlil_rrmp_route_dual_commit(
                &o->route_ns, NINLIL_RRMP_KEY_NRD1, NINLIL_RRMP_DIR_BYTES)) {
            return 0;
        }
        {
            uint8_t keys[2];
            keys[0] = NINLIL_RRMP_KEY_NRD1;
            keys[1] = kid;
            (void)ninlil_rrmp_route_full_commit(&o->route_ns, keys, 2u);
        }
    }
    return 1;
}

static int persist_evidence_page(ninlil_rrmp_owner_t *o, uint16_t page)
{
    /* Use owner enc_page_a as pack scratch (not task stack; ESP 2048 frame). */
    uint8_t *packed;
    size_t count = 0u;
    size_t i;
    size_t base = (size_t)page * NINLIL_RRMP_NEP1_SLOTS;
    uint8_t *buf;
    size_t cap;
    uint64_t gen;
    uint8_t kid = (uint8_t)(NINLIL_RRMP_KEY_NEP1_BASE + page);
    if (o == NULL) {
        return 0;
    }
    packed = o->enc_page_a;
    ninlil_rrmp_memzero(packed, NINLIL_RRMP_NEP1_SLOTS * NINLIL_RRMP_NEV1_BYTES);
    for (i = 0u; i < NINLIL_RRMP_NEP1_SLOTS; ++i) {
        size_t idx = base + i;
        if (idx < NINLIL_RRMP_EVIDENCE_CAPACITY && o->evidence[idx].used) {
            memcpy(
                packed + count * NINLIL_RRMP_NEV1_BYTES,
                o->evidence[idx].raw,
                NINLIL_RRMP_NEV1_BYTES);
            ++count;
        }
    }
    if (!ninlil_rrmp_route_dual_begin_write(&o->route_ns, kid, &buf, &cap, &gen)) {
        return 0;
    }
    if (!ninlil_rrmp_encode_nep1(page, (uint32_t)gen, packed, count, buf)) {
        return 0;
    }
    if (!ninlil_rrmp_route_dual_commit(&o->route_ns, kid, NINLIL_RRMP_NEP1_BYTES)) {
        return 0;
    }
    /* refresh directory */
    return persist_route_page(o, 0u);
}

static int rehydrate_from_ns(ninlil_rrmp_owner_t *o)
{
    size_t p;
    const uint8_t *nph1 = NULL;
    uint64_t nph1_store_generation = 0u;
    uint16_t assignment_page_bitmap = 0u;
    uint16_t token_page_bitmap = 0u;
    uint8_t npa_seen[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY];
    uint8_t npt_seen[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY];
    size_t nps_count = 0u;
    size_t npa_count = 0u;
    size_t npt_scope_count = 0u;
    uint16_t npt_ledger_count = 0u;
    int nph1_present = 0;
    /* clear volatile */
    ninlil_rrmp_memzero(&o->loop_ring, sizeof(o->loop_ring));
    ninlil_rrmp_memzero(&o->dedup_ring, sizeof(o->dedup_ring));
    ninlil_rrmp_memzero(o->queue, sizeof(o->queue));
    ninlil_rrmp_memzero(o->carrier_arena, sizeof(o->carrier_arena));
    o->carrier_arena_used = 0u;
    o->q_entries = 0u;
    o->q_control_entries = 0u;
    ninlil_rrmp_memzero(o->routes, sizeof(o->routes));
    ninlil_rrmp_memzero(o->evidence, sizeof(o->evidence));
    ninlil_rrmp_memzero(npa_seen, sizeof(npa_seen));
    ninlil_rrmp_memzero(npt_seen, sizeof(npt_seen));

    for (p = 0u; p < NINLIL_RRMP_PAGE_COUNT; ++p) {
        uint8_t kid = (uint8_t)(NINLIL_RRMP_KEY_NRP1_BASE + p);
        const uint8_t *page;
        uint32_t len;
        uint64_t gen;
        uint16_t bitmap;
        size_t s;
        if (!ninlil_rrmp_route_dual_read_active(&o->route_ns, kid, &page, &len, &gen)) {
            continue;
        }
        if (!ninlil_rrmp_validate_nrp1(page)) {
            o->route_ns.corrupt = 1u;
            continue;
        }
        bitmap = ninlil_rrmp_get_u16_be(page + 12);
        for (s = 0u; s < NINLIL_RRMP_SLOTS_PER_PAGE; ++s) {
            if ((bitmap & (uint16_t)(1u << s)) == 0u) {
                continue;
            }
            {
                size_t idx = p * NINLIL_RRMP_SLOTS_PER_PAGE + s;
                const uint8_t *slot =
                    page + NINLIL_RRMP_NRP1_HEADER_BYTES + s * NINLIL_RRMP_SLOT_BYTES;
                uint8_t state;
                ninlil_rrmp_nrm1_fields_t f;
                uint64_t seq;
                if (idx >= NINLIL_RRMP_ROUTE_MAX) {
                    break;
                }
                if (!ninlil_rrmp_decode_slot_state(slot, &state, &f, &seq)) {
                    o->route_ns.corrupt = 1u;
                    continue;
                }
                /* Durable RETIRED tombstone: keep free (no reactivation hole). */
                if (state == NINLIL_RRMP_ROUTE_STATE_RETIRED ||
                    state == NINLIL_RRMP_ROUTE_STATE_EMPTY) {
                    continue;
                }
                o->routes[idx].used = 1u;
                o->routes[idx].state = slot_to_life(state);
                o->routes[idx].fields = f;
                o->routes[idx].next_admission_seq = seq;
            }
        }
    }
    for (p = 0u; p < NINLIL_RRMP_NEP1_PAGE_COUNT; ++p) {
        uint8_t kid = (uint8_t)(NINLIL_RRMP_KEY_NEP1_BASE + p);
        const uint8_t *page;
        uint32_t len;
        uint64_t gen;
        uint32_t count;
        size_t s;
        if (!ninlil_rrmp_route_dual_read_active(&o->route_ns, kid, &page, &len, &gen)) {
            continue;
        }
        if (!ninlil_rrmp_validate_nep1(page)) {
            o->route_ns.corrupt = 1u;
            continue;
        }
        count = ninlil_rrmp_get_u32_be(page + 12);
        for (s = 0u; s < count && s < NINLIL_RRMP_NEP1_SLOTS; ++s) {
            size_t idx = p * NINLIL_RRMP_NEP1_SLOTS + s;
            const uint8_t *slot =
                page + NINLIL_RRMP_NEP1_HEADER_BYTES + s * NINLIL_RRMP_NEV1_BYTES;
            ninlil_rrmp_nev1_fields_t f;
            if (idx >= NINLIL_RRMP_EVIDENCE_CAPACITY) {
                break;
            }
            if (!ninlil_rrmp_decode_nev1(slot, &f)) {
                continue;
            }
            o->evidence[idx].used = 1u;
            memcpy(o->evidence[idx].raw, slot, NINLIL_RRMP_NEV1_BYTES);
            ninlil_rrmp_evidence_key(
                f.e2e_header_digest.bytes,
                f.route_handle,
                f.route_generation,
                f.admission_seq,
                &o->evidence[idx].key);
        }
    }
    /* Parent writer fence header (present from AUTHORITY_COMMITTED onward). */
    {
        uint32_t len = 0u;
        if (ninlil_rrmp_parent_dual_read_active(
                &o->parent_ns,
                NINLIL_RRMP_PKEY_NPH1,
                &nph1,
                &len,
                &nph1_store_generation)) {
            nph1_present = 1;
            if (nph1 == NULL || len != NINLIL_RRMP_NPH1_BYTES ||
                !ninlil_rrmp_validate_nph1(nph1) ||
                ninlil_rrmp_get_u64_be(nph1 + 112u) !=
                    nph1_store_generation ||
                !ninlil_rrmp_memeq(nph1 + 8u, o->cfg.authority_id, 16u) ||
                !ninlil_rrmp_memeq(
                    nph1 + 64u,
                    o->cfg.authority_clock_epoch_id,
                    16u) ||
                ninlil_rrmp_get_u64_be(nph1 + 40u) <
                    o->cfg.controller_term) {
                return parent_rehydrate_corrupt(o);
            }
            o->parent_ns.writer_generation =
                ninlil_rrmp_get_u64_be(nph1 + 48u);
            memcpy(o->parent_ns.sole_writer_id, nph1 + 24u, 16u);
            o->parent_ns.sole_writer_set = 1u;
            if (o->cfg.now_ms >=
                ninlil_rrmp_get_u64_be(nph1 + 56u)) {
                o->parent_ns.fenced = 1u;
                o->downlink_tx = 0u;
            }
        }
    }
    /* parent NPP1 rehydrate (parent set scopes) */
    ninlil_rrmp_memzero(o->scopes, sizeof(o->scopes));
    for (p = 0u; p < NINLIL_RRMP_NPP1_PAGE_COUNT; ++p) {
        uint8_t kid = (uint8_t)(NINLIL_RRMP_PKEY_NPP1_BASE + p);
        const uint8_t *page;
        uint32_t len;
        uint64_t gen;
        size_t s;
        if (!ninlil_rrmp_parent_dual_read_active(&o->parent_ns, kid, &page, &len, &gen)) {
            continue;
        }
        if (page == NULL || len != NINLIL_RRMP_NPP1_BYTES ||
            gen == 0u || gen >= UINT32_MAX ||
            !ninlil_rrmp_validate_npp1(page) ||
            ninlil_rrmp_get_u16_be(page + 6u) != (uint16_t)p ||
            ninlil_rrmp_get_u32_be(page + 8u) != (uint32_t)gen) {
            return parent_rehydrate_corrupt(o);
        }
        for (s = 0u; s < NINLIL_RRMP_NPP1_SLOTS; ++s) {
            const uint8_t *slot =
                page + NINLIL_RRMP_NPP1_HEADER_BYTES + s * NINLIL_RRMP_NPS1_BYTES;
            ninlil_rrmp_nps1_fields_t f;
            rrmp_scope_t *sc;
            if (slot[0] == 0u && slot[1] == 0u && slot[2] == 0u && slot[3] == 0u) {
                continue;
            }
            if (!ninlil_rrmp_decode_nps1(slot, &f)) {
                return parent_rehydrate_corrupt(o);
            }
            if (find_scope(o, f.owner_scope_id.bytes) != NULL) {
                /* One durable live scope has exactly one NPS1 authority. */
                return parent_rehydrate_corrupt(o);
            }
            sc = alloc_scope(o);
            if (sc == NULL) {
                return parent_rehydrate_corrupt(o);
            }
            sc->downlink_tx_scope = 1u;
            sc->installed_revision = f.parent_set_revision;
            memcpy(sc->nps1_record_digest, slot + 212, 32u);
            memcpy(sc->owner_scope_id, f.owner_scope_id.bytes, 16u);
            memcpy(sc->path_policy_id, f.parent_set_id.bytes, 16u);
            sc->path_policy_revision = f.parent_set_revision;
            sc->parent_count = f.parent_count;
            memcpy(sc->parent_set_digest, f.parent_set_digest.bytes, 32u);
            {
                uint8_t pi;
                for (pi = 0u; pi < f.parent_count; ++pi) {
                    memcpy(sc->parent_ids[pi], f.parent_ids[pi].bytes, 16u);
                }
            }
            ++nps_count;
        }
    }
    /* NPA1 assignment pages 0..7 → scope handoff state (durable restart) */
    {
        uint8_t pi;
        for (pi = 0u; pi < NINLIL_RRMP_NPA1_PAGE_COUNT; ++pi) {
            const uint8_t *page = NULL;
            uint32_t len = 0u;
            uint64_t gen = 0u;
            size_t s;
            uint8_t kid = (uint8_t)(NINLIL_RRMP_PKEY_NPA1_BASE + pi);
            if (!ninlil_rrmp_parent_dual_read_active(
                    &o->parent_ns, kid, &page, &len, &gen)) {
                continue;
            }
            assignment_page_bitmap =
                (uint16_t)(assignment_page_bitmap | (uint16_t)(1u << pi));
            if (page == NULL || len != NINLIL_RRMP_NPA1_BYTES ||
                gen == 0u || gen >= UINT32_MAX ||
                !ninlil_rrmp_validate_npa1(page) ||
                ninlil_rrmp_get_u16_be(page + 6u) != pi ||
                ninlil_rrmp_get_u32_be(page + 8u) != (uint32_t)gen) {
                return parent_rehydrate_corrupt(o);
            }
            for (s = 0u; s < NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE; ++s) {
                const uint8_t *slot =
                    page + NINLIL_RRMP_NPA1_HEADER_BYTES +
                    s * NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES;
                ninlil_rrmp_noa1_fields_t noa;
                rrmp_scope_t *sc;
                size_t scope_index;
                uint8_t handoff;
                int proof_present;
                int commit_present;
                if (slot[0] == 0u && slot[1] == 0u && slot[2] == 0u &&
                    slot[3] == 0u) {
                    continue;
                }
                if (!ninlil_rrmp_decode_noa1(slot, &noa)) {
                    return parent_rehydrate_corrupt(o);
                }
                sc = find_scope(o, noa.owner_scope_id.bytes);
                if (sc == NULL) {
                    /* NPA1 is a reference; it may never invent an NPS1 scope. */
                    return parent_rehydrate_corrupt(o);
                }
                scope_index = scope_index_of(o, sc);
                if (scope_index >= NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY ||
                    npa_seen[scope_index]) {
                    return parent_rehydrate_corrupt(o);
                }
                if (noa.parent_set_count != sc->parent_count ||
                    !ninlil_rrmp_memeq(
                        noa.parent_set_digest.bytes,
                        sc->parent_set_digest,
                        32u) ||
                    !ninlil_rrmp_memeq(
                        noa.parent_set_id.bytes,
                        sc->path_policy_id,
                        16u)) {
                    return parent_rehydrate_corrupt(o);
                }
                handoff = slot[400u];
                proof_present = bytes_have_nonzero(slot + 404u, 32u);
                commit_present = bytes_have_nonzero(slot + 436u, 32u);
                if ((handoff == NINLIL_RRMP_HANDOFF_PREPARED_NEW &&
                        (proof_present || commit_present)) ||
                    (handoff == NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF &&
                        (!proof_present || commit_present)) ||
                    (handoff >= NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED &&
                        (!proof_present || !commit_present))) {
                    return parent_rehydrate_corrupt(o);
                }
                /*
                 * v2 commit binds the exact old/new authority tuples and the
                 * outer bundle witness, so the legacy v1 digest formula is
                 * not an import authority. Presence and the NPH1 exact
                 * proof/commit tuple are checked below; QST4 then restores
                 * and validates the copy-owned old/new tuple rows.
                 */
                npa_seen[scope_index] = 1u;
                ++npa_count;
                sc->noa1_present = 1u;
                memcpy(sc->noa1_raw, slot, NINLIL_RRMP_NOA1_BYTES);
                memcpy(sc->noa1_body_digest, slot + 224, 32u);
                sc->noa1_controller_term = noa.controller_term;
                sc->noa1_assignment_revision = noa.assignment_revision;
                sc->handoff = handoff;
                sc->lease_not_after_ms = noa.lease_not_after_authority_ms;
                memcpy(sc->token_dig, noa.handoff_token_digest.bytes, 32u);
                memcpy(sc->proof_dig, slot + 404, 32u);
                memcpy(sc->commit_dig, slot + 436, 32u);
                sc->proof = proof_present ? 1u : 0u;
                sc->receipt =
                    handoff >= NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED
                    ? 1u
                    : 0u;
                sc->cas =
                    handoff >= NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED
                    ? 1u
                    : 0u;
                sc->token_consumed = 0u;
                /*
                 * This NPA1 is the participant-local handoff record written by
                 * owner_prepare. Its old-owner identity is therefore the
                 * runtime that owns this namespace, and is reconstructible
                 * without persisting a second mutable identity.
                 */
                sc->is_old_owner_local = 1u;
                memcpy(sc->old_owner, o->cfg.local_runtime_id, 16u);
                if (sc->handoff >= NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED) {
                    sc->token_consumed = 1u;
                    sc->new_seal = 1u;
                }
                if (sc->handoff >= NINLIL_RRMP_HANDOFF_OLD_RETIRED) {
                    sc->tombstone = 1u;
                    /* ADR-0020 S6: old_owner_seal = 0 after OLD_RETIRED. */
                    sc->old_seal = 0u;
                }
            }
        }
    }
    /*
     * NPT1 token pages 0..7 form one global replay ledger.  A current NPA1
     * assignment must resolve to exactly one matching ledger entry; retained
     * used-token tombstones from earlier handoffs intentionally need not have
     * a current scope assignment.
     */
    {
        uint8_t pi;
        for (pi = 0u; pi < NINLIL_RRMP_NPT1_PAGE_COUNT; ++pi) {
            const uint8_t *page = NULL;
            uint32_t len = 0u;
            uint64_t gen = 0u;
            uint32_t slot_count;
            uint32_t si;
            uint8_t kid = (uint8_t)(NINLIL_RRMP_PKEY_NPT1_BASE + pi);
            if (!ninlil_rrmp_parent_dual_read_active(
                    &o->parent_ns, kid, &page, &len, &gen)) {
                continue;
            }
            token_page_bitmap =
                (uint16_t)(token_page_bitmap | (uint16_t)(1u << pi));
            if (page == NULL || len != NINLIL_RRMP_NPT1_BYTES ||
                gen == 0u || gen >= UINT32_MAX ||
                !ninlil_rrmp_validate_npt1(page) ||
                ninlil_rrmp_get_u16_be(page + 6u) != pi ||
                ninlil_rrmp_get_u32_be(page + 8u) != (uint32_t)gen) {
                return parent_rehydrate_corrupt(o);
            }
            slot_count = ninlil_rrmp_get_u32_be(page + 12);
            for (si = 0u; si < slot_count; ++si) {
                const uint8_t *tslot =
                    page + NINLIL_RRMP_NPT1_HEADER_BYTES +
                    si * NINLIL_RRMP_NPT1_SLOT_BYTES;
                uint8_t kind = tslot[32];
                uint16_t ledger_total = 0u;
                uint8_t ledger_matches = 0u;
                size_t i;
                rrmp_scope_t *matched = NULL;
                size_t matched_index =
                    NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY;
                if (!npt_ledger_summary(
                        o,
                        tslot,
                        &ledger_total,
                        &ledger_matches,
                        NULL,
                        NULL) ||
                    ledger_matches != 1u ||
                    ledger_total >
                        NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY) {
                    return parent_rehydrate_corrupt(o);
                }
                for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
                    rrmp_scope_t *sc = &o->scopes[i];
                    if (!sc->used || !sc->noa1_present) {
                        continue;
                    }
                    if (!ninlil_rrmp_memeq(sc->token_dig, tslot, 32u)) {
                        continue;
                    }
                    if (matched != NULL) {
                        /* Token digest is an exact one-scope durable key. */
                        return parent_rehydrate_corrupt(o);
                    }
                    matched = sc;
                    matched_index = i;
                }
                if ((matched == NULL &&
                        kind != NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED) ||
                    (matched != NULL &&
                        (matched_index >=
                                NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY ||
                            npt_seen[matched_index] ||
                            (matched->handoff >=
                                    NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED &&
                                kind !=
                                    NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED) ||
                            (matched->handoff <
                                    NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED &&
                                kind !=
                                    NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE)))) {
                    return parent_rehydrate_corrupt(o);
                }
                if (matched != NULL) {
                    npt_seen[matched_index] = 1u;
                    ++npt_scope_count;
                    matched->token_consumed =
                        kind == NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED
                        ? 1u
                        : 0u;
                    matched->token_created_ms =
                        ninlil_rrmp_get_u64_be(tslot + 36u);
                }
            }
        }
    }
    if (!npt_ledger_summary(
            o, NULL, &npt_ledger_count, NULL, NULL, NULL) ||
        npt_ledger_count > NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY) {
        return parent_rehydrate_corrupt(o);
    }
    /*
     * NPA1 and NPT1 form an exact one-to-one relation for every prepared
     * assignment. NPS1-only scopes are valid before S1. Retained, globally
     * unique TOMBSTONE_USED entries may outlive the current NPA1 assignment,
     * but no live token may be orphaned, duplicated, or omitted after S1.
     */
    if (npa_count != npt_scope_count) {
        return parent_rehydrate_corrupt(o);
    }
    for (p = 0u; p < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++p) {
        if ((npa_seen[p] ? 1u : 0u) != (npt_seen[p] ? 1u : 0u) ||
            (o->scopes[p].used && o->scopes[p].noa1_present &&
                (!npa_seen[p] || !npt_seen[p]))) {
            return parent_rehydrate_corrupt(o);
        }
    }
    if (nps_count > NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY) {
        return parent_rehydrate_corrupt(o);
    }
    /*
     * NPH1 is not a free-standing hint. Its page bitmaps must be the exact
     * active physical NPA1/NPT1 set, and its writer/proof/commit tuple must
     * resolve to exactly one committed assignment.
     */
    if (nph1_present) {
        size_t match_count = 0u;
        size_t precommit_count = 0u;
        if (nph1 == NULL ||
            ninlil_rrmp_get_u16_be(nph1 + 120u) !=
                assignment_page_bitmap ||
            ninlil_rrmp_get_u16_be(nph1 + 122u) != token_page_bitmap ||
            assignment_page_bitmap == 0u || token_page_bitmap == 0u) {
            return parent_rehydrate_corrupt(o);
        }
        for (p = 0u; p < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++p) {
            rrmp_scope_t *sc = &o->scopes[p];
            ninlil_rrmp_noa1_fields_t noa;
            if (sc->used && sc->noa1_present &&
                (sc->handoff == NINLIL_RRMP_HANDOFF_PREPARED_NEW ||
                    sc->handoff ==
                        NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF)) {
                ++precommit_count;
                continue;
            }
            if (!sc->used || !sc->noa1_present ||
                sc->handoff < NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED ||
                !ninlil_rrmp_decode_noa1(sc->noa1_raw, &noa)) {
                continue;
            }
            if (ninlil_rrmp_memeq(
                    noa.authority_id.bytes, nph1 + 8u, 16u) &&
                ninlil_rrmp_memeq(
                    noa.owner_controller_id.bytes, nph1 + 24u, 16u) &&
                noa.controller_term == ninlil_rrmp_get_u64_be(nph1 + 40u) &&
                noa.lease_not_after_authority_ms ==
                    ninlil_rrmp_get_u64_be(nph1 + 56u) &&
                ninlil_rrmp_memeq(
                    noa.authority_clock_epoch_id.bytes,
                    nph1 + 64u,
                    16u) &&
                ninlil_rrmp_memeq(sc->proof_dig, nph1 + 80u, 32u) &&
                ninlil_rrmp_memeq(sc->commit_dig, nph1 + 128u, 32u)) {
                ++match_count;
            }
        }
        /*
         * During S1/S2 the active NPA1 holds the proposed assignment while
         * NPH1 still fences the previous global writer. QST4, imported after
         * the physical namespaces, carries the exact old/new tuple needed to
         * bind that precommit state. Defer only this exact one-precommit case
         * to the post-QST4 validator below.
         */
        if (match_count != 1u &&
            !(match_count == 0u && precommit_count == 1u)) {
            return parent_rehydrate_corrupt(o);
        }
    } else {
        for (p = 0u; p < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++p) {
            if (o->scopes[p].used &&
                o->scopes[p].handoff >=
                    NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED) {
                return parent_rehydrate_corrupt(o);
            }
        }
    }
    o->route_ns.cu_class = ninlil_rrmp_route_classify_cu(&o->route_ns);
    o->parent_ns.cu_class = ninlil_rrmp_parent_classify_cu(&o->parent_ns);
    if (o->route_ns.cu_class == NINLIL_RRMP_CU_PARTIAL ||
        o->route_ns.cu_class == NINLIL_RRMP_CU_EXTRA ||
        o->route_ns.cu_class == NINLIL_RRMP_CU_THIRD ||
        o->parent_ns.cu_class == NINLIL_RRMP_CU_PARTIAL ||
        o->parent_ns.cu_class == NINLIL_RRMP_CU_EXTRA ||
        o->parent_ns.cu_class == NINLIL_RRMP_CU_THIRD) {
        o->downlink_tx = 0u;
        o->route_ns.fenced = 1u;
    }
    return 1;
}

/* --- owner lifecycle --- */

ninlil_rrmp_owner_t *ninlil_rrmp_owner_init(
    void *workspace,
    size_t workspace_bytes,
    const ninlil_rrmp_owner_config_v1_t *cfg)
{
    ninlil_rrmp_owner_t *o;
    if (workspace == NULL || cfg == NULL) {
        return NULL;
    }
    if (workspace_bytes < ninlil_rrmp_owner_workspace_bytes()) {
        return NULL;
    }
    /* uint64 fields in owner require natural alignment (UBSan / portable). */
    if (((uintptr_t)workspace % (uintptr_t)NINLIL_RRMP_OWNER_WORKSPACE_ALIGN) !=
        0u) {
        return NULL;
    }
    if (cfg->preamble.api_version != NINLIL_RRMP_API_VERSION) {
        return NULL;
    }
    if (cfg->preamble.struct_size != sizeof(*cfg)) {
        return NULL;
    }
    if (cfg->authorization_required > 1u) {
        return NULL;
    }
    o = (ninlil_rrmp_owner_t *)workspace;
    ninlil_rrmp_memzero(o, ninlil_rrmp_owner_workspace_bytes());
    o->magic = NINLIL_RRMP_OWNER_MAGIC;
    o->cfg = *cfg;
    if (o->cfg.max_hops_profile == 0u) {
        o->cfg.max_hops_profile = NINLIL_RRMP_MAX_HOPS_PROFILE_ESP_V1;
    }
    o->downlink_tx = 1u;
    o->next_handle_token = 1u;
    ninlil_rrmp_route_ns_init(&o->route_ns);
    ninlil_rrmp_parent_ns_init(&o->parent_ns);
    return o;
}

void ninlil_rrmp_owner_fini(ninlil_rrmp_owner_t *owner)
{
    if (owner_is_live(owner) && owner->entered == 0u) {
        ninlil_rrmp_memzero(owner, ninlil_rrmp_owner_workspace_bytes());
    }
}

int ninlil_rrmp_owner_bind(ninlil_rrmp_owner_t *owner)
{
    if (!owner_is_live(owner) || owner->entered != 0u ||
        owner->cfg.authorization_required) {
        return 0;
    }
    owner_serial_clear(owner);
    owner->serial_bound = 1u;
    return 1;
}

int ninlil_rrmp_owner_bind_authorized(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_caller_auth_v1_t *auth,
    const ninlil_rrmp_authorizer_v1_t *authorizer)
{
    uint32_t invalid_caps;
    if (!owner_is_live(owner) || owner->entered != 0u) {
        return 0;
    }
    owner_serial_clear(owner);
    if (auth == NULL || authorizer == NULL || authorizer->authorize == NULL) {
        return 0;
    }
    invalid_caps = auth->capability_mask & ~NINLIL_RRMP_AUTH_ALL;
    if (auth->reserved0 != 0u || auth->capability_mask == 0u ||
        invalid_caps != 0u ||
        !authorizer->authorize(
            authorizer->user, auth, owner->cfg.local_runtime_id,
            owner->cfg.authority_id)) {
        return 0;
    }
    memcpy(owner->auth_principal_id, auth->principal_id, 16u);
    owner->auth_capabilities = auth->capability_mask;
    owner->auth_active = 1u;
    owner->serial_bound = 1u;
    return 1;
}

void ninlil_rrmp_owner_unbind(ninlil_rrmp_owner_t *owner)
{
    if (owner_is_live(owner) && owner->entered == 0u) {
        owner_serial_clear(owner);
    }
}

void ninlil_rrmp_core_set_fabric_path(
    ninlil_rrmp_owner_t *o,
    const uint8_t selected_instance_id[16],
    uint64_t epoch)
{
    if (o == NULL || selected_instance_id == NULL) {
        return;
    }
    memcpy(o->last_fabric_path_id, selected_instance_id, 16u);
    o->last_fabric_path_set = 1u;
    o->last_fabric_path_epoch = epoch;
}

int ninlil_rrmp_core_get_fabric_path(
    const ninlil_rrmp_owner_t *o,
    uint8_t selected_instance_id_out[16],
    uint64_t *epoch_out)
{
    if (o == NULL || !o->last_fabric_path_set) {
        return 0;
    }
    if (selected_instance_id_out != NULL) {
        memcpy(selected_instance_id_out, o->last_fabric_path_id, 16u);
    }
    if (epoch_out != NULL) {
        *epoch_out = o->last_fabric_path_epoch;
    }
    return 1;
}

void ninlil_rrmp_owner_set_now_ms(ninlil_rrmp_owner_t *owner, uint64_t now_ms)
{
    if (owner != NULL) {
        owner->cfg.now_ms = now_ms;
    }
}

void ninlil_rrmp_owner_set_scope_derivation(
    ninlil_rrmp_owner_t *owner, const ninlil_rrmp_scope_derivation_ctx_t *ctx)
{
    if (owner == NULL) {
        return;
    }
    if (ctx == NULL) {
        ninlil_rrmp_memzero(&owner->scope_derivation, sizeof(owner->scope_derivation));
        owner->scope_derivation_set = 0u;
        return;
    }
    owner->scope_derivation = *ctx;
    owner->scope_derivation_set = 1u;
}

void ninlil_rrmp_owner_set_outbound_provider(
    ninlil_rrmp_owner_t *owner, const ninlil_rrmp_outbound_provider_t *provider)
{
    if (owner == NULL) {
        return;
    }
    if (provider == NULL || provider->submit == NULL) {
        ninlil_rrmp_memzero(&owner->outbound, sizeof(owner->outbound));
        owner->outbound_set = 0u;
        return;
    }
    owner->outbound = *provider;
    owner->outbound_set = 1u;
}

int ninlil_rrmp_owner_bind_storage(
    ninlil_rrmp_owner_t *owner,
    const struct ninlil_storage_ops *ops,
    void *handle)
{
    const ninlil_storage_ops_t *typed = (const ninlil_storage_ops_t *)ops;
    if (owner == NULL || typed == NULL || handle == NULL ||
        typed->begin == NULL || typed->get == NULL || typed->put == NULL ||
        typed->erase == NULL || typed->iter_open == NULL ||
        typed->iter_next == NULL || typed->iter_close == NULL ||
        typed->commit == NULL || typed->rollback == NULL) {
        return 0;
    }
    owner->storage_ops = typed;
    owner->storage_handle = (ninlil_storage_handle_t)handle;
    owner->storage_bound = 1u;
    owner->storage_authority_v2 = NULL;
    owner->storage_expected_valid = 1u;
    owner->storage_expected_present = 0u;
    owner->storage_expected_length = 0u;
    owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_NONE;
    ninlil_rrmp_memzero(owner->storage_expected_digest, 32u);
    ninlil_rrmp_memzero(owner->storage_pending_old_digest, 32u);
    ninlil_rrmp_memzero(owner->storage_pending_new_digest, 32u);
    ninlil_rrmp_memzero(
        owner->storage_expected_manifest, NINLIL_RRMP_RRM1_BYTES);
    ninlil_rrmp_memzero(
        owner->storage_pending_old_manifest, NINLIL_RRMP_RRM1_BYTES);
    ninlil_rrmp_memzero(
        owner->storage_pending_new_manifest, NINLIL_RRMP_RRM1_BYTES);
    owner->storage_pending_unknown = 0u;
    return 1;
}

int ninlil_rrmp_owner_bind_storage_authority(
    ninlil_rrmp_owner_t *owner,
    const struct ninlil_storage_ops *ops,
    void *handle,
    const ninlil_rrmp_storage_authority_v1_t *authority)
{
    (void)owner;
    (void)ops;
    (void)handle;
    (void)authority;
    /* RRP-1: a single-value callback cannot mutate the bounded bundle. */
    return 0;
}

int ninlil_rrmp_owner_bind_storage_authority_v2(
    ninlil_rrmp_owner_t *owner,
    const struct ninlil_storage_ops *ops,
    void *handle,
    const ninlil_rrmp_storage_authority_v2_t *authority)
{
    if (authority == NULL ||
        authority->api_version != NINLIL_RRMP_STORAGE_AUTHORITY_V2 ||
        authority->struct_size != sizeof(*authority) ||
        authority->isolation !=
            NINLIL_RRMP_STORAGE_AUTHORITY_SERIALIZABLE_PIECE_VECTOR ||
        authority->reserved0 != 0u ||
        authority->compare_exchange_bundle_full == NULL ||
        authority->recover_pending_bundle_full == NULL ||
        !ninlil_rrmp_owner_bind_storage(owner, ops, handle)) {
        return 0;
    }
    owner->storage_authority_v2 = authority;
    return 1;
}

static int authority_tuple_canonical(
    const ninlil_rrmp_authority_tuple_v2_t *tuple);
static void authority_tuple_encode(
    const ninlil_rrmp_authority_tuple_v2_t *tuple, uint8_t out[104]);
static int authority_tuple_decode(
    const uint8_t in[104], ninlil_rrmp_authority_tuple_v2_t *out);

/* QST4 writes only schema 4. QST2/QST3 remain read-only migration inputs. */
#define RRMP_SOFT_V23_HEADER_BYTES 48u
#define RRMP_SOFT_V4_HEADER_BYTES NINLIL_RRMP_QST4_HEADER_BYTES
#define RRMP_SOFT_V2_SCOPE_BYTES 64u
#define RRMP_SOFT_V2_EVIDENCE_AUX_BYTES 72u
#define RRMP_SOFT_V2_QUEUE_BYTES 320u

static uint16_t soft_handoff_tuple_count(const ninlil_rrmp_owner_t *owner)
{
    uint16_t count = 0u;
    size_t i;
    if (owner == NULL) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (owner->scopes[i].used &&
            owner->scopes[i].handoff != NINLIL_RRMP_HANDOFF_NONE) {
            count = (uint16_t)(count + 1u);
        }
    }
    return count;
}

static size_t soft_export_size(const ninlil_rrmp_owner_t *owner)
{
    size_t need = RRMP_SOFT_V4_HEADER_BYTES;
    size_t i;
    if (owner == NULL) {
        return need;
    }
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (owner->scopes[i].used) {
            need += RRMP_SOFT_V2_SCOPE_BYTES;
        }
    }
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (owner->evidence[i].used) {
            ninlil_rrmp_nev1_fields_t ef;
            if (ninlil_rrmp_decode_nev1(owner->evidence[i].raw, &ef) &&
                ef.lifecycle == NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE) {
                need += RRMP_SOFT_V2_EVIDENCE_AUX_BYTES;
            }
        }
    }
    for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
        if (owner->queue[i].used) {
            need += RRMP_SOFT_V2_QUEUE_BYTES + owner->queue[i].carrier_len;
        }
    }
    need += (size_t)owner->attempt_count * NINLIL_RRMP_QST4_ATTEMPT_BYTES;
    need +=
        (size_t)soft_handoff_tuple_count(owner) *
        NINLIL_RRMP_QST4_HANDOFF_TUPLE_BYTES;
    return need;
}

static uint16_t queue_soft_flags(const rrmp_q_t *q)
{
    uint16_t f = 0u;
    if (q->owner_scope_set) {
        f |= 1u;
    }
    if (q->terminal) {
        f |= 2u;
    }
    if (q->tx_permit) {
        f |= 4u;
    }
    if (q->tx_done) {
        f |= 8u;
    }
    if (q->await_ack) {
        f |= 16u;
    }
    if (q->retry_exhausted) {
        f |= 32u;
    }
    if (q->selected_parent_set) {
        f |= 64u;
    }
    if (q->link_ack) {
        f |= 128u;
    }
    return f;
}

static int soft_export(
    const ninlil_rrmp_owner_t *owner, uint8_t *out, size_t cap, size_t *len)
{
    size_t need;
    size_t off;
    size_t i;
    uint16_t scope_count = 0u;
    uint16_t queue_count = 0u;
    uint16_t aux_count = 0u;
    uint16_t handoff_count = 0u;
    uint8_t handoff_order[NINLIL_RRMP_QST4_HANDOFF_TUPLE_CAPACITY];
    uint32_t carrier_bytes = 0u;
    if (owner == NULL || len == NULL) {
        return 0;
    }
    need = soft_export_size(owner);
    *len = need;
    if (need > UINT32_MAX) {
        return 0;
    }
    if (out == NULL || cap < need) {
        return out == NULL ? 1 : 0;
    }
    ninlil_rrmp_memzero(out, need);
    memcpy(out, "RRMPQST4", 8u);
    ninlil_rrmp_put_u16_be(out + 8, 4u);
    ninlil_rrmp_put_u32_be(out + 16, (uint32_t)need);
    ninlil_rrmp_put_u64_be(out + 24, owner->next_handle_token);
    ninlil_rrmp_put_u64_be(out + 32, owner->lifetime_admits);
    ninlil_rrmp_put_u32_be(out + 40, owner->bulk_streak);
    out[48u] = owner->authority_global_fence ? 1u : 0u;
    out[49u] = owner->authority_global_fence_reason;
    ninlil_rrmp_put_u16_be(out + 50u, owner->attempt_count);
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (owner->scopes[i].used &&
            owner->scopes[i].handoff != NINLIL_RRMP_HANDOFF_NONE) {
            size_t pos = handoff_count;
            if (handoff_count >=
                NINLIL_RRMP_QST4_HANDOFF_TUPLE_CAPACITY) {
                return 0;
            }
            while (pos > 0u &&
                memcmp(
                    owner->scopes[handoff_order[pos - 1u]].owner_scope_id,
                    owner->scopes[i].owner_scope_id,
                    16u) > 0) {
                handoff_order[pos] = handoff_order[pos - 1u];
                --pos;
            }
            handoff_order[pos] = (uint8_t)i;
            handoff_count = (uint16_t)(handoff_count + 1u);
        }
    }
    ninlil_rrmp_put_u16_be(out + 52u, handoff_count);
    off = RRMP_SOFT_V4_HEADER_BYTES;

    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        const rrmp_scope_t *sc = &owner->scopes[i];
        uint8_t flags = 0u;
        if (!sc->used) {
            continue;
        }
        memcpy(out + off, sc->owner_scope_id, 16u);
        memcpy(out + off + 16u, sc->last_attempt_id16, 16u);
        memcpy(out + off + 32u, sc->selected_parent, 16u);
        memcpy(out + off + 48u, sc->parent_lost, NINLIL_RRMP_PARENT_MAX);
        if (sc->attempt_selected) {
            flags |= 1u;
        }
        out[off + 56u] = flags;
        out[off + 57u] = (uint8_t)(
            (sc->split_brain ? 1u : 0u) |
            (sc->parent_loss_seal ? 2u : 0u) |
            (sc->old_seal ? 4u : 0u) |
            (sc->new_seal ? 8u : 0u));
        off += RRMP_SOFT_V2_SCOPE_BYTES;
        scope_count = (uint16_t)(scope_count + 1u);
    }

    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        const rrmp_evi_t *ev = &owner->evidence[i];
        ninlil_rrmp_nev1_fields_t ef;
        if (!ev->used || !ninlil_rrmp_decode_nev1(ev->raw, &ef) ||
            ef.lifecycle != NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE) {
            continue;
        }
        memcpy(out + off, ev->key.bytes, 32u);
        ninlil_rrmp_put_u64_be(out + off + 32u, ev->opaque_handle);
        ninlil_rrmp_put_u64_be(out + off + 40u, ev->outer_tx_counter);
        memcpy(out + off + 48u, ev->auth_peer_runtime_id, 16u);
        out[off + 64u] = ev->auth_link_ack ? 1u : 0u;
        off += RRMP_SOFT_V2_EVIDENCE_AUX_BYTES;
        aux_count = (uint16_t)(aux_count + 1u);
    }

    for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
        const rrmp_q_t *q = &owner->queue[i];
        const uint8_t *carrier;
        uint16_t flags;
        if (!q->used) {
            continue;
        }
        carrier = queue_carrier(owner, q);
        if (q->carrier_len != 0u && carrier == NULL) {
            return 0;
        }
        memcpy(out + off, "NQW1", 4u);
        ninlil_rrmp_put_u16_be(out + off + 4u, 1u);
        ninlil_rrmp_put_u16_be(out + off + 6u, RRMP_SOFT_V2_QUEUE_BYTES);
        flags = queue_soft_flags(q);
        ninlil_rrmp_put_u16_be(out + off + 8u, flags);
        out[off + 10u] = q->prio;
        out[off + 11u] = q->hop_in;
        out[off + 12u] = q->hop_out;
        ninlil_rrmp_put_u16_be(out + off + 14u, q->handle);
        ninlil_rrmp_put_u16_be(out + off + 16u, q->gen);
        ninlil_rrmp_put_u16_be(out + off + 18u, q->carrier_len);
        ninlil_rrmp_put_u32_be(out + off + 20u, q->ingress_hop_context_id);
        ninlil_rrmp_put_u32_be(out + off + 24u, q->remaining_link_groups);
        ninlil_rrmp_put_u32_be(out + off + 28u, q->remaining_attempts);
        ninlil_rrmp_put_u16_be(out + off + 32u, q->retry_count);
        ninlil_rrmp_put_u16_be(out + off + 34u, q->retry_limit);
        ninlil_rrmp_put_u32_be(out + off + 36u, q->link_ack_wait_ms);
        ninlil_rrmp_put_u64_be(out + off + 40u, q->admission_seq);
        ninlil_rrmp_put_u64_be(out + off + 48u, q->token);
        ninlil_rrmp_put_u64_be(out + off + 56u, q->opaque_handle);
        ninlil_rrmp_put_u64_be(out + off + 64u, q->route_revision);
        ninlil_rrmp_put_u64_be(out + off + 72u, q->absolute_deadline_ms);
        ninlil_rrmp_put_u64_be(out + off + 80u, q->ack_deadline_ms);
        ninlil_rrmp_put_u64_be(out + off + 88u, q->retry_not_before_ms);
        ninlil_rrmp_put_u64_be(out + off + 96u, q->outer_rx_counter);
        ninlil_rrmp_put_u64_be(out + off + 104u, q->outer_tx_counter);
        memcpy(out + off + 112u, q->e2e_digest, 32u);
        memcpy(out + off + 144u, q->e2e_body, 96u);
        memcpy(out + off + 240u, q->owner_scope_id, 16u);
        memcpy(out + off + 256u, q->attempt_id16, 16u);
        memcpy(out + off + 272u, q->selected_parent_id, 16u);
        memcpy(out + off + 288u, q->expected_peer_id, 16u);
        memcpy(out + off + 304u, q->caller_principal_id, 16u);
        off += RRMP_SOFT_V2_QUEUE_BYTES;
        if (q->carrier_len != 0u) {
            memcpy(out + off, carrier, q->carrier_len);
            off += q->carrier_len;
            carrier_bytes += q->carrier_len;
        }
        queue_count = (uint16_t)(queue_count + 1u);
    }
    for (i = 0u; i < owner->attempt_count; ++i) {
        const rrmp_attempt_row_t *row = &owner->attempts[i];
        if (row->lifecycle != NINLIL_RRMP_ATTEMPT_LIVE &&
            row->lifecycle != NINLIL_RRMP_ATTEMPT_TERMINAL_RETAINED) {
            return 0;
        }
        memcpy(out + off, row->owner_scope_id, 16u);
        memcpy(out + off + 16u, row->attempt_id16, 16u);
        out[off + 32u] = row->lifecycle;
        out[off + 33u] = row->flags;
        memcpy(
            out + off + 40u, row->terminal_evidence_digest32,
            sizeof(row->terminal_evidence_digest32));
        ninlil_rrmp_put_u64_be(
            out + off + 72u, row->reclaim_not_before_ms);
        off += sizeof(*row);
    }
    for (i = 0u; i < handoff_count; ++i) {
        const rrmp_scope_t *sc = &owner->scopes[handoff_order[i]];
        if (!authority_tuple_canonical(&sc->handoff_old_tuple) ||
            !authority_tuple_canonical(&sc->handoff_new_tuple) ||
            !sc->handoff_new_tuple.present) {
            return 0;
        }
        memcpy(out + off, sc->owner_scope_id, 16u);
        authority_tuple_encode(&sc->handoff_old_tuple, out + off + 16u);
        authority_tuple_encode(&sc->handoff_new_tuple, out + off + 120u);
        off += NINLIL_RRMP_QST4_HANDOFF_TUPLE_BYTES;
    }
    if (off != need || carrier_bytes != owner->carrier_arena_used) {
        return 0;
    }
    ninlil_rrmp_put_u16_be(out + 10u, scope_count);
    ninlil_rrmp_put_u16_be(out + 12u, queue_count);
    ninlil_rrmp_put_u16_be(out + 14u, aux_count);
    ninlil_rrmp_put_u32_be(out + 44u, carrier_bytes);
    ninlil_rrmp_put_u32_be(
        out + 20u,
        ninlil_rrmp_crc32c_zeroed_u32_be_field(out, need, 20u));
    return 1;
}

static int soft_import_v1(
    ninlil_rrmp_owner_t *owner, const uint8_t *in, size_t len)
{
    uint16_t count;
    size_t off;
    uint16_t i;
    if (len < 12u || memcmp(in, "RRMPSOFT", 8u) != 0 ||
        ninlil_rrmp_get_u16_be(in + 8) != 1u) {
        return 0;
    }
    count = ninlil_rrmp_get_u16_be(in + 10);
    if ((size_t)12u + (size_t)count * 40u != len) {
        return 0;
    }
    off = 12u;
    for (i = 0u; i < count; ++i) {
        rrmp_scope_t *sc = find_scope(owner, in + off);
        if (sc != NULL) {
            memcpy(sc->last_attempt_id16, in + off + 16u, 16u);
            sc->attempt_selected = in[off + 32u] ? 1u : 0u;
        }
        off += 40u;
    }
    /* Legacy v1 cannot safely recover a LIVE queue/ACK owner. */
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (owner->evidence[i].used) {
            ninlil_rrmp_nev1_fields_t ef;
            if (ninlil_rrmp_decode_nev1(owner->evidence[i].raw, &ef) &&
                ef.lifecycle == NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE) {
                return 0;
            }
        }
    }
    return 1;
}

static rrmp_evi_t *find_evidence_by_key(
    ninlil_rrmp_owner_t *owner, const uint8_t key[32])
{
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (owner->evidence[i].used &&
            ninlil_rrmp_memeq(owner->evidence[i].key.bytes, key, 32u)) {
            return &owner->evidence[i];
        }
    }
    return NULL;
}

static int soft_import_v2_v3_or_v4(
    ninlil_rrmp_owner_t *owner, const uint8_t *in, size_t len)
{
    uint16_t scope_count;
    uint16_t queue_count;
    uint16_t aux_count;
    uint32_t declared_len;
    uint32_t carrier_bytes;
    size_t off;
    uint16_t i;
    uint64_t max_handle = 0u;
    uint8_t scope_seen[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY];
    uint8_t handoff_seen[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY];
    size_t durable_scope_count = 0u;
    int schema3;
    int schema4;
    size_t header_bytes;
    uint16_t attempt_count = 0u;
    uint16_t handoff_count = 0u;
    ninlil_rrmp_memzero(scope_seen, sizeof(scope_seen));
    ninlil_rrmp_memzero(handoff_seen, sizeof(handoff_seen));
    schema4 =
        len >= 10u &&
        memcmp(in, "RRMPQST4", 8u) == 0 &&
        ninlil_rrmp_get_u16_be(in + 8u) == 4u;
    schema3 =
        len >= 10u &&
        memcmp(in, "RRMPQST3", 8u) == 0 &&
        ninlil_rrmp_get_u16_be(in + 8u) == 3u;
    header_bytes = schema4 ? RRMP_SOFT_V4_HEADER_BYTES :
        RRMP_SOFT_V23_HEADER_BYTES;
    if (len < header_bytes ||
        (!schema4 && !schema3 &&
         (memcmp(in, "RRMPQST2", 8u) != 0 ||
          ninlil_rrmp_get_u16_be(in + 8u) != 2u)) ||
        ninlil_rrmp_get_u32_be(in + 20u) !=
            ninlil_rrmp_crc32c_zeroed_u32_be_field(in, len, 20u)) {
        return 0;
    }
    scope_count = ninlil_rrmp_get_u16_be(in + 10u);
    queue_count = ninlil_rrmp_get_u16_be(in + 12u);
    aux_count = ninlil_rrmp_get_u16_be(in + 14u);
    declared_len = ninlil_rrmp_get_u32_be(in + 16u);
    carrier_bytes = ninlil_rrmp_get_u32_be(in + 44u);
    if (schema4) {
        attempt_count = ninlil_rrmp_get_u16_be(in + 50u);
        handoff_count = ninlil_rrmp_get_u16_be(in + 52u);
        if (in[48u] > 1u ||
            (in[48u] == 0u &&
                in[49u] != NINLIL_RRMP_AUTHORITY_FENCE_NONE) ||
            (in[48u] != 0u &&
                in[49u] == NINLIL_RRMP_AUTHORITY_FENCE_NONE) ||
            in[54u] != 0u || in[55u] != 0u ||
            attempt_count > NINLIL_RRMP_QST4_ATTEMPT_CAPACITY ||
            handoff_count >
                NINLIL_RRMP_QST4_HANDOFF_TUPLE_CAPACITY) {
            return 0;
        }
    }
    if (declared_len != len ||
        scope_count > NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY ||
        queue_count > NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES ||
        aux_count > NINLIL_RRMP_EVIDENCE_CAPACITY ||
        carrier_bytes > NINLIL_RRMP_QUEUE_GLOBAL_BYTES) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (owner->scopes[i].used) {
            ++durable_scope_count;
        }
    }
    if ((size_t)scope_count != durable_scope_count) {
        /*
         * QST2/QST3 scope rows are an exact enumeration of durable NPS1 live
         * scopes. A CRC-repaired omission (including count=0), duplicate, or
         * invented row is not a safe partial restore.
         */
        return 0;
    }
    ninlil_rrmp_memzero(owner->queue, sizeof(owner->queue));
    ninlil_rrmp_memzero(owner->carrier_arena, sizeof(owner->carrier_arena));
    owner->carrier_arena_used = 0u;
    owner->q_entries = 0u;
    owner->q_control_entries = 0u;
    owner->q_bytes = 0u;
    owner->next_handle_token = ninlil_rrmp_get_u64_be(in + 24u);
    owner->lifetime_admits = ninlil_rrmp_get_u64_be(in + 32u);
    owner->bulk_streak = ninlil_rrmp_get_u32_be(in + 40u);
    owner->attempt_count = 0u;
    ninlil_rrmp_memzero(owner->attempts, sizeof(owner->attempts));
    if (schema4) {
        owner->authority_global_fence = in[48u];
        owner->authority_global_fence_reason = in[49u];
    } else {
        /*
         * QST2/QST3 did not carry the complete global used-attempt history.
         * It remains readable for inspection, but mutation/TX is fenced until
         * explicit reprovision rather than guessing that old attempts are free.
         */
        owner->authority_global_fence = 1u;
        owner->authority_global_fence_reason =
            NINLIL_RRMP_AUTHORITY_FENCE_LEGACY_ATTEMPT_STATE;
    }
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        owner->evidence[i].opaque_handle = 0u;
        owner->evidence[i].auth_link_ack = 0u;
        owner->evidence[i].outer_tx_counter = 0u;
        ninlil_rrmp_memzero(owner->evidence[i].auth_peer_runtime_id, 16u);
    }
    off = header_bytes;
    for (i = 0u; i < scope_count; ++i) {
        rrmp_scope_t *sc;
        size_t scope_index;
        size_t z;
        if (off + RRMP_SOFT_V2_SCOPE_BYTES > len) {
            return 0;
        }
        for (z = (schema3 || schema4) ? 58u : 57u;
             z < RRMP_SOFT_V2_SCOPE_BYTES;
             ++z) {
            if (in[off + z] != 0u) {
                return 0;
            }
        }
        if ((in[off + 56u] & ~1u) != 0u ||
            ((schema3 || schema4) && (in[off + 57u] & ~15u) != 0u)) {
            return 0;
        }
        sc = find_scope(owner, in + off);
        if (sc == NULL) {
            return 0;
        }
        scope_index = scope_index_of(owner, sc);
        if (scope_index >= NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY ||
            scope_seen[scope_index]) {
            return 0;
        }
        scope_seen[scope_index] = 1u;
        memcpy(sc->last_attempt_id16, in + off + 16u, 16u);
        memcpy(sc->selected_parent, in + off + 32u, 16u);
        memcpy(sc->parent_lost, in + off + 48u, NINLIL_RRMP_PARENT_MAX);
        sc->attempt_selected = in[off + 56u] & 1u;
        if (schema3 || schema4) {
            uint8_t seal = in[off + 57u];
            sc->split_brain = (seal & 1u) ? 1u : 0u;
            sc->parent_loss_seal = (seal & 2u) ? 1u : 0u;
            sc->old_seal = (seal & 4u) ? 1u : 0u;
            sc->new_seal = (seal & 8u) ? 1u : 0u;
            if (sc->handoff >= NINLIL_RRMP_HANDOFF_OLD_RETIRED) {
                sc->old_seal = 0u;
            }
            if (sc->split_brain || sc->parent_loss_seal) {
                sc->downlink_tx_scope = 0u;
            }
        } else {
            /*
             * Schema 2 never carried the scope-local seal tuple.  Absence is
             * not evidence that split-brain/parent-loss was clear: preserve
             * the scope for operator recovery, but require a fresh
             * assignment before any downlink can be sealed again.
             */
            sc->parent_loss_seal = 1u;
            sc->downlink_tx_scope = 0u;
        }
        off += RRMP_SOFT_V2_SCOPE_BYTES;
    }
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (owner->scopes[i].used != (scope_seen[i] ? 1u : 0u)) {
            return 0;
        }
    }
    for (i = 0u; i < aux_count; ++i) {
        rrmp_evi_t *ev;
        size_t z;
        uint64_t oh;
        if (off + RRMP_SOFT_V2_EVIDENCE_AUX_BYTES > len) {
            return 0;
        }
        ev = find_evidence_by_key(owner, in + off);
        oh = ninlil_rrmp_get_u64_be(in + off + 32u);
        if (ev == NULL || ev->opaque_handle != 0u || oh == 0u ||
            oh == UINT64_MAX || in[off + 64u] > 1u) {
            return 0;
        }
        for (z = 65u; z < RRMP_SOFT_V2_EVIDENCE_AUX_BYTES; ++z) {
            if (in[off + z] != 0u) {
                return 0;
            }
        }
        ev->opaque_handle = oh;
        ev->outer_tx_counter = ninlil_rrmp_get_u64_be(in + off + 40u);
        memcpy(ev->auth_peer_runtime_id, in + off + 48u, 16u);
        ev->auth_link_ack = in[off + 64u];
        if (oh > max_handle) {
            max_handle = oh;
        }
        off += RRMP_SOFT_V2_EVIDENCE_AUX_BYTES;
    }
    for (i = 0u; i < queue_count; ++i) {
        rrmp_q_t *q = NULL;
        rrmp_route_t *route;
        rrmp_evi_t *ev = NULL;
        ninlil_rrmp_nev1_fields_t ef;
        uint16_t flags;
        uint16_t carrier_len;
        uint64_t oh;
        uint8_t exact[NINLIL_RRMP_EXACT_BODY_BYTES];
        size_t qi;
        size_t ei;
        uint32_t charge;
        if (off + RRMP_SOFT_V2_QUEUE_BYTES > len ||
            memcmp(in + off, "NQW1", 4u) != 0 ||
            ninlil_rrmp_get_u16_be(in + off + 4u) != 1u ||
            ninlil_rrmp_get_u16_be(in + off + 6u) !=
                RRMP_SOFT_V2_QUEUE_BYTES) {
            return 0;
        }
        flags = ninlil_rrmp_get_u16_be(in + off + 8u);
        carrier_len = ninlil_rrmp_get_u16_be(in + off + 18u);
        oh = ninlil_rrmp_get_u64_be(in + off + 56u);
        if ((flags & ~255u) != 0u || in[off + 13u] != 0u ||
            in[off + 10u] > NINLIL_RRMP_PRIO_BULK ||
            carrier_len > NINLIL_RRMP_OUTBOUND_CARRIER_MAX ||
            oh == 0u || oh == UINT64_MAX ||
            off + RRMP_SOFT_V2_QUEUE_BYTES + carrier_len > len) {
            return 0;
        }
        route = find_route(
            owner, ninlil_rrmp_get_u32_be(in + off + 20u),
            ninlil_rrmp_get_u16_be(in + off + 14u),
            ninlil_rrmp_get_u16_be(in + off + 16u));
        if (route == NULL || !ninlil_rrmp_materialize_exact(route ? &route->fields : NULL, exact) ||
            !ninlil_rrmp_memeq(exact, in + off + 144u, 96u)) {
            return 0;
        }
        for (ei = 0u; ei < NINLIL_RRMP_EVIDENCE_CAPACITY; ++ei) {
            if (!owner->evidence[ei].used ||
                !ninlil_rrmp_decode_nev1(owner->evidence[ei].raw, &ef)) {
                continue;
            }
            if (owner->evidence[ei].opaque_handle == oh &&
                ef.lifecycle == NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE &&
                ef.route_handle == ninlil_rrmp_get_u16_be(in + off + 14u) &&
                ef.route_generation == ninlil_rrmp_get_u16_be(in + off + 16u) &&
                ef.admission_seq == ninlil_rrmp_get_u64_be(in + off + 40u) &&
                ninlil_rrmp_memeq(
                    ef.e2e_header_digest.bytes, in + off + 112u, 32u)) {
                ev = &owner->evidence[ei];
                break;
            }
        }
        if (ev == NULL) {
            return 0;
        }
        for (qi = 0u; qi < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++qi) {
            if (!owner->queue[qi].used) {
                q = &owner->queue[qi];
                break;
            }
        }
        if (q == NULL) {
            return 0;
        }
        ninlil_rrmp_memzero(q, sizeof(*q));
        q->used = 1u;
        q->prio = in[off + 10u];
        q->hop_in = in[off + 11u];
        q->hop_out = in[off + 12u];
        q->owner_scope_set = (flags & 1u) ? 1u : 0u;
        q->terminal = (flags & 2u) ? 1u : 0u;
        q->tx_permit = (flags & 4u) ? 1u : 0u;
        q->tx_done = (flags & 8u) ? 1u : 0u;
        q->await_ack = (flags & 16u) ? 1u : 0u;
        q->retry_exhausted = (flags & 32u) ? 1u : 0u;
        q->selected_parent_set = (flags & 64u) ? 1u : 0u;
        q->link_ack = (flags & 128u) ? 1u : 0u;
        q->handle = ninlil_rrmp_get_u16_be(in + off + 14u);
        q->gen = ninlil_rrmp_get_u16_be(in + off + 16u);
        q->ingress_hop_context_id = ninlil_rrmp_get_u32_be(in + off + 20u);
        q->remaining_link_groups = ninlil_rrmp_get_u32_be(in + off + 24u);
        q->remaining_attempts = ninlil_rrmp_get_u32_be(in + off + 28u);
        q->retry_count = ninlil_rrmp_get_u16_be(in + off + 32u);
        q->retry_limit = ninlil_rrmp_get_u16_be(in + off + 34u);
        q->link_ack_wait_ms = ninlil_rrmp_get_u32_be(in + off + 36u);
        q->admission_seq = ninlil_rrmp_get_u64_be(in + off + 40u);
        q->token = ninlil_rrmp_get_u64_be(in + off + 48u);
        q->opaque_handle = oh;
        q->route_revision = ninlil_rrmp_get_u64_be(in + off + 64u);
        q->absolute_deadline_ms = ninlil_rrmp_get_u64_be(in + off + 72u);
        q->ack_deadline_ms = ninlil_rrmp_get_u64_be(in + off + 80u);
        q->retry_not_before_ms = ninlil_rrmp_get_u64_be(in + off + 88u);
        q->outer_rx_counter = ninlil_rrmp_get_u64_be(in + off + 96u);
        q->outer_tx_counter = ninlil_rrmp_get_u64_be(in + off + 104u);
        memcpy(q->e2e_digest, in + off + 112u, 32u);
        memcpy(q->e2e_body, in + off + 144u, 96u);
        q->e2e_body_len = 96u;
        q->payload_len = 96u;
        memcpy(q->owner_scope_id, in + off + 240u, 16u);
        memcpy(q->attempt_id16, in + off + 256u, 16u);
        memcpy(q->selected_parent_id, in + off + 272u, 16u);
        memcpy(q->expected_peer_id, in + off + 288u, 16u);
        memcpy(q->caller_principal_id, in + off + 304u, 16u);
        off += RRMP_SOFT_V2_QUEUE_BYTES;
        if (!carrier_arena_append(
                owner, carrier_len != 0u ? in + off : NULL, carrier_len,
                &q->carrier_offset)) {
            return 0;
        }
        q->carrier_len = carrier_len;
        off += carrier_len;
        charge = 96u + carrier_len;
        if (ev->auth_link_ack != q->link_ack ||
            (q->link_ack &&
                ev->outer_tx_counter != q->outer_tx_counter) ||
            owner->q_entries >= NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES ||
            owner->q_bytes > NINLIL_RRMP_QUEUE_GLOBAL_BYTES - charge ||
            q->retry_limit == 0u || q->retry_limit > NINLIL_RRMP_MAX_ATTEMPTS ||
            q->retry_count > q->retry_limit ||
            (q->await_ack && (!q->tx_done || !q->tx_permit ||
                q->retry_count == 0u)) ||
            (q->retry_exhausted && q->await_ack) ||
            (q->link_ack && (q->await_ack || !q->tx_done ||
                !q->tx_permit))) {
            return 0;
        }
        owner->q_entries += 1u;
        owner->q_bytes += charge;
        if (q->prio == NINLIL_RRMP_PRIO_CONTROL ||
            q->prio == NINLIL_RRMP_PRIO_SAFETY) {
            owner->q_control_entries += 1u;
        }
        {
            ninlil_rrmp_digest32_t lk;
            ninlil_rrmp_digest32_t dk;
            ninlil_rrmp_loop_key(
                q->e2e_digest, q->handle, q->gen,
                owner->cfg.local_runtime_id, &lk);
            ninlil_rrmp_dedup_key(
                q->e2e_digest, q->ingress_hop_context_id,
                q->handle, q->gen, &dk);
            ring_push16(&owner->loop_ring, lk.bytes);
            ring_push16(&owner->dedup_ring, dk.bytes);
        }
    }
    for (i = 0u; i < attempt_count; ++i) {
        rrmp_attempt_row_t *row = &owner->attempts[i];
        size_t z;
        int digest_zero;
        if (off + NINLIL_RRMP_QST4_ATTEMPT_BYTES > len) {
            return 0;
        }
        for (z = 34u; z < 40u; ++z) {
            if (in[off + z] != 0u) {
                return 0;
            }
        }
        if ((in[off + 33u] &
                ~(NINLIL_RRMP_ATTEMPT_FLAG_NEV1 |
                    NINLIL_RRMP_ATTEMPT_FLAG_HANDOFF_TOMBSTONE)) != 0u ||
            !bytes_have_nonzero(in + off, 16u) ||
            !bytes_have_nonzero(in + off + 16u, 16u)) {
            return 0;
        }
        if (i != 0u) {
            int order = memcmp(
                owner->attempts[i - 1u].owner_scope_id, in + off, 16u);
            if (order > 0 ||
                (order == 0 &&
                    memcmp(
                        owner->attempts[i - 1u].attempt_id16,
                        in + off + 16u,
                        16u) >= 0)) {
                return 0;
            }
        }
        memcpy(row->owner_scope_id, in + off, 16u);
        memcpy(row->attempt_id16, in + off + 16u, 16u);
        row->lifecycle = in[off + 32u];
        row->flags = in[off + 33u];
        memcpy(row->terminal_evidence_digest32, in + off + 40u, 32u);
        row->reclaim_not_before_ms = ninlil_rrmp_get_u64_be(in + off + 72u);
        digest_zero = !bytes_have_nonzero(
            row->terminal_evidence_digest32, 32u);
        if ((row->lifecycle == NINLIL_RRMP_ATTEMPT_LIVE &&
                (row->flags != 0u || !digest_zero ||
                    row->reclaim_not_before_ms != 0u)) ||
            (row->lifecycle == NINLIL_RRMP_ATTEMPT_TERMINAL_RETAINED &&
                (row->flags == 0u || digest_zero ||
                    row->reclaim_not_before_ms == 0u ||
                    row->reclaim_not_before_ms == UINT64_MAX)) ||
            (row->lifecycle != NINLIL_RRMP_ATTEMPT_LIVE &&
                row->lifecycle !=
                    NINLIL_RRMP_ATTEMPT_TERMINAL_RETAINED)) {
            return 0;
        }
        off += NINLIL_RRMP_QST4_ATTEMPT_BYTES;
    }
    owner->attempt_count = attempt_count;
    for (i = 0u; i < handoff_count; ++i) {
        rrmp_scope_t *sc;
        size_t scope_index;
        ninlil_rrmp_authority_tuple_v2_t old_tuple;
        ninlil_rrmp_authority_tuple_v2_t new_tuple;
        ninlil_rrmp_noa1_fields_t noa;
        uint8_t noa_sha[32];
        uint64_t expected_writer_epoch;
        if (!schema4 ||
            off + NINLIL_RRMP_QST4_HANDOFF_TUPLE_BYTES > len ||
            (i != 0u &&
                memcmp(
                    in + off -
                        NINLIL_RRMP_QST4_HANDOFF_TUPLE_BYTES,
                    in + off,
                    16u) >= 0) ||
            !authority_tuple_decode(in + off + 16u, &old_tuple) ||
            !authority_tuple_decode(in + off + 120u, &new_tuple) ||
            !new_tuple.present) {
            return 0;
        }
        sc = find_scope(owner, in + off);
        if (sc == NULL || sc->handoff == NINLIL_RRMP_HANDOFF_NONE ||
            !sc->noa1_present ||
            !ninlil_rrmp_decode_noa1(sc->noa1_raw, &noa)) {
            return 0;
        }
        scope_index = scope_index_of(owner, sc);
        if (scope_index >= NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY ||
            handoff_seen[scope_index]) {
            return 0;
        }
        handoff_seen[scope_index] = 1u;
        ninlil_rrmp_sha256(
            sc->noa1_raw, NINLIL_RRMP_NOA1_BYTES, noa_sha);
        if (new_tuple.exact_noa1_length != NINLIL_RRMP_NOA1_BYTES ||
            !ninlil_rrmp_memeq(new_tuple.noa1_sha256, noa_sha, 32u) ||
            new_tuple.assignment_revision != noa.assignment_revision ||
            new_tuple.controller_term != noa.controller_term ||
            !ninlil_rrmp_memeq(
                new_tuple.owner_controller_id,
                noa.owner_controller_id.bytes,
                16u) ||
            new_tuple.lease_not_after_ms !=
                noa.lease_not_after_authority_ms ||
            !ninlil_rrmp_memeq(
                new_tuple.authority_clock_epoch_id,
                noa.authority_clock_epoch_id.bytes,
                16u)) {
            return 0;
        }
        if (sc->handoff < NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED) {
            if (owner->parent_ns.writer_generation == UINT64_MAX) {
                return 0;
            }
            expected_writer_epoch =
                owner->parent_ns.writer_generation + 1u;
            if (new_tuple.writer_epoch > expected_writer_epoch) {
                return 0;
            }
        } else {
            expected_writer_epoch = owner->parent_ns.writer_generation;
            if (new_tuple.writer_epoch > expected_writer_epoch) {
                return 0;
            }
        }
        sc->handoff_old_tuple = old_tuple;
        sc->handoff_new_tuple = new_tuple;
        /*
         * This namespace is the participant-local handoff record. Controller
         * identity remains in the exact tuple; retirement ownership is the
         * local participant that copy-owns this record, not an equality
         * between controller_id and runtime_id.
         */
        sc->is_old_owner_local = 1u;
        memcpy(sc->old_owner, owner->cfg.local_runtime_id, 16u);
        off += NINLIL_RRMP_QST4_HANDOFF_TUPLE_BYTES;
    }
    if (schema4) {
        for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
            if (owner->scopes[i].used &&
                ((owner->scopes[i].handoff != NINLIL_RRMP_HANDOFF_NONE) !=
                    (handoff_seen[i] != 0u))) {
                return 0;
            }
        }
    }
    if (off != len || owner->carrier_arena_used != carrier_bytes ||
        owner->next_handle_token == 0u ||
        owner->next_handle_token == UINT64_MAX ||
        owner->next_handle_token <= max_handle) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        rrmp_evi_t *ev = &owner->evidence[i];
        ninlil_rrmp_nev1_fields_t ef;
        int have_q = 0;
        size_t qi;
        if (!ev->used || !ninlil_rrmp_decode_nev1(ev->raw, &ef) ||
            ef.lifecycle != NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE) {
            continue;
        }
        if (ev->opaque_handle == 0u) {
            return 0;
        }
        for (qi = 0u; qi < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++qi) {
            if (owner->queue[qi].used &&
                owner->queue[qi].opaque_handle == ev->opaque_handle) {
                have_q = 1;
                break;
            }
        }
        if (!have_q) {
            return 0;
        }
    }
    return 1;
}

static int soft_import(ninlil_rrmp_owner_t *owner, const uint8_t *in, size_t len)
{
    if (owner == NULL || in == NULL) {
        return 0;
    }
    if (len >= 8u &&
        (memcmp(in, "RRMPQST2", 8u) == 0 ||
         memcmp(in, "RRMPQST3", 8u) == 0 ||
         memcmp(in, "RRMPQST4", 8u) == 0)) {
        return soft_import_v2_v3_or_v4(owner, in, len);
    }
    return soft_import_v1(owner, in, len);
}

static int post_qst4_authority_validate(const ninlil_rrmp_owner_t *owner)
{
    const uint8_t *nph1 = NULL;
    uint32_t nph1_length = 0u;
    uint64_t nph1_store_generation = 0u;
    size_t match_count = 0u;
    size_t i;
    int nph1_present;
    if (owner == NULL) {
        return 0;
    }
    nph1_present = ninlil_rrmp_parent_dual_read_active(
        &owner->parent_ns,
        NINLIL_RRMP_PKEY_NPH1,
        &nph1,
        &nph1_length,
        &nph1_store_generation);
    if (!nph1_present) {
        for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
            const rrmp_scope_t *sc = &owner->scopes[i];
            if (!sc->used || sc->handoff == NINLIL_RRMP_HANDOFF_NONE) {
                continue;
            }
            if (sc->handoff >=
                    NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED ||
                sc->handoff_old_tuple.present) {
                return 0;
            }
        }
        return 1;
    }
    if (nph1 == NULL || nph1_length != NINLIL_RRMP_NPH1_BYTES ||
        nph1_store_generation == 0u ||
        !ninlil_rrmp_validate_nph1(nph1)) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        const rrmp_scope_t *sc = &owner->scopes[i];
        const ninlil_rrmp_authority_tuple_v2_t *tuple;
        int committed;
        if (!sc->used || sc->handoff == NINLIL_RRMP_HANDOFF_NONE) {
            continue;
        }
        committed =
            sc->handoff >= NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED;
        tuple = committed
            ? &sc->handoff_new_tuple
            : &sc->handoff_old_tuple;
        if (!tuple->present ||
            tuple->writer_epoch !=
                ninlil_rrmp_get_u64_be(nph1 + 48u) ||
            tuple->controller_term !=
                ninlil_rrmp_get_u64_be(nph1 + 40u) ||
            tuple->lease_not_after_ms !=
                ninlil_rrmp_get_u64_be(nph1 + 56u) ||
            !ninlil_rrmp_memeq(
                tuple->owner_controller_id, nph1 + 24u, 16u) ||
            !ninlil_rrmp_memeq(
                tuple->authority_clock_epoch_id, nph1 + 64u, 16u)) {
            continue;
        }
        if (committed &&
            (!ninlil_rrmp_memeq(sc->proof_dig, nph1 + 80u, 32u) ||
                !ninlil_rrmp_memeq(
                    sc->commit_dig, nph1 + 128u, 32u))) {
            continue;
        }
        ++match_count;
    }
    return match_count == 1u;
}

int ninlil_rrmp_owner_export_namespace(
    const ninlil_rrmp_owner_t *owner, uint8_t *out, size_t cap, size_t *len)
{
    size_t rneed = 0u;
    size_t pneed = 0u;
    size_t sneed = 0u;
    size_t need;
    size_t off = 0u;
    if (owner == NULL || len == NULL || owner_storage_hard_fenced(owner)) {
        return 0;
    }
    (void)ninlil_rrmp_route_ns_export(&owner->route_ns, NULL, 0u, &rneed);
    (void)ninlil_rrmp_parent_ns_export(&owner->parent_ns, NULL, 0u, &pneed);
    (void)soft_export(owner, NULL, 0u, &sneed);
    /* header: magic8 + rlen + plen + slen */
    need = 20u + rneed + pneed + sneed;
    if (sneed > NINLIL_RRMP_QST4_MAX_BYTES ||
        need > NINLIL_RRMP_RRM1_LOGICAL_REQUIRED_MAX) {
        *len = need;
        return 0;
    }
    *len = need;
    if (out == NULL || cap < need) {
        return out == NULL ? 1 : 0;
    }
    memcpy(out, "RRMPNS1\0", 8u);
    ninlil_rrmp_put_u32_be(out + 8, (uint32_t)rneed);
    ninlil_rrmp_put_u32_be(out + 12, (uint32_t)pneed);
    ninlil_rrmp_put_u32_be(out + 16, (uint32_t)sneed);
    off = 20u;
    if (!ninlil_rrmp_route_ns_export(&owner->route_ns, out + off, rneed, &rneed)) {
        return 0;
    }
    off += rneed;
    if (!ninlil_rrmp_parent_ns_export(&owner->parent_ns, out + off, pneed, &pneed)) {
        return 0;
    }
    off += pneed;
    if (!soft_export(owner, out + off, sneed, &sneed)) {
        return 0;
    }
    return 1;
}

int ninlil_rrmp_owner_import_namespace(
    ninlil_rrmp_owner_t *owner, const uint8_t *in, size_t len)
{
    uint32_t rlen;
    uint32_t plen;
    uint32_t slen = 0u;
    size_t hdr = 16u;
    size_t expect;
    if (owner == NULL || in == NULL || len < 16u) {
        if (owner != NULL) {
            owner->route_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
            owner->route_ns.fenced = 1u;
            owner->downlink_tx = 0u;
        }
        return 0;
    }
    if (memcmp(in, "RRMPNS1\0", 8u) != 0) {
        owner->route_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
        owner->route_ns.corrupt = 1u;
        owner->downlink_tx = 0u;
        return 0;
    }
    rlen = ninlil_rrmp_get_u32_be(in + 8);
    plen = ninlil_rrmp_get_u32_be(in + 12);
    /* v2 envelope with soft trailer (slen@16) when length permits. */
    if (len >= 20u) {
        slen = ninlil_rrmp_get_u32_be(in + 16);
        expect = (size_t)20u + (size_t)rlen + (size_t)plen + (size_t)slen;
        if (expect == len) {
            hdr = 20u;
        } else if ((size_t)16u + (size_t)rlen + (size_t)plen == len) {
            /* legacy soft-less export */
            hdr = 16u;
            slen = 0u;
        } else {
            if (expect > len) {
                owner->route_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
            } else {
                owner->route_ns.cu_class = NINLIL_RRMP_CU_EXTRA;
            }
            owner->route_ns.fenced = 1u;
            owner->downlink_tx = 0u;
            return 0;
        }
    } else if ((size_t)16u + (size_t)rlen + (size_t)plen != len) {
        if ((size_t)16u + (size_t)rlen + (size_t)plen > len) {
            owner->route_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
        } else {
            owner->route_ns.cu_class = NINLIL_RRMP_CU_EXTRA;
        }
        owner->route_ns.fenced = 1u;
        owner->downlink_tx = 0u;
        return 0;
    }
    if (!ninlil_rrmp_route_ns_import(&owner->route_ns, in + hdr, rlen)) {
        if (owner->route_ns.cu_class == NINLIL_RRMP_CU_NONE ||
            owner->route_ns.cu_class == NINLIL_RRMP_CU_ABSENT) {
            owner->route_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
        }
        owner->downlink_tx = 0u;
        owner->route_ns.fenced = 1u;
        return 0;
    }
    if (!ninlil_rrmp_parent_ns_import(
            &owner->parent_ns, in + hdr + rlen, plen)) {
        if (owner->parent_ns.cu_class == NINLIL_RRMP_CU_NONE ||
            owner->parent_ns.cu_class == NINLIL_RRMP_CU_ABSENT) {
            owner->parent_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
        }
        owner->downlink_tx = 0u;
        return 0;
    }
    if (!rehydrate_from_ns(owner)) {
        return 0;
    }
    if (slen > 0u) {
        const uint8_t *soft = in + hdr + rlen + plen;
        if (!soft_import(owner, soft, slen) ||
            (slen >= 8u &&
                memcmp(soft, "RRMPQST4", 8u) == 0 &&
                !post_qst4_authority_validate(owner))) {
            return parent_rehydrate_corrupt(owner);
        }
    }
    return 1;
}

static const uint8_t k_rrmp_manifest_key[7] = {
    'R', 'R', 'M', 'P', '/', 'M', '1'};
static const uint8_t k_rrmp_chunk_keys[NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX][7] = {
    {'R', 'R', 'M', 'P', '/', 'C', '0'},
    {'R', 'R', 'M', 'P', '/', 'C', '1'},
    {'R', 'R', 'M', 'P', '/', 'C', '2'},
    {'R', 'R', 'M', 'P', '/', 'C', '3'},
    {'R', 'R', 'M', 'P', '/', 'C', '4'}};
static const uint8_t k_rrmp_prefix[5] = {'R', 'R', 'M', 'P', '/'};

static int rrmp_export_scratch_ready(const ninlil_rrmp_owner_t *owner)
{
    return owner != NULL && owner->magic == NINLIL_RRMP_OWNER_MAGIC;
}

static uint8_t rrm1_chunk_count(uint32_t logical_length)
{
    return (uint8_t)(
        (logical_length + NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX - 1u) /
        NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX);
}

static int rrm1_manifest_validate(
    const uint8_t manifest[NINLIL_RRMP_RRM1_BYTES])
{
    uint32_t logical_length;
    uint8_t chunk_count;
    uint8_t i;
    if (manifest == NULL ||
        memcmp(manifest, "RRM1", 4u) != 0 ||
        ninlil_rrmp_get_u16_be(manifest + 4u) != 1u ||
        ninlil_rrmp_get_u16_be(manifest + 6u) !=
            NINLIL_RRMP_RRM1_BYTES ||
        ninlil_rrmp_get_u64_be(manifest + 8u) == 0u ||
        ninlil_rrmp_get_u64_be(manifest + 8u) == UINT64_MAX ||
        manifest[21u] != 0u || manifest[22u] != 0u ||
        manifest[23u] != 0u ||
        ninlil_rrmp_get_u32_be(manifest + 252u) !=
            ninlil_rrmp_crc32c_zeroed_u32_be_field(
                manifest, NINLIL_RRMP_RRM1_BYTES, 252u)) {
        return 0;
    }
    logical_length = ninlil_rrmp_get_u32_be(manifest + 16u);
    chunk_count = manifest[20u];
    if (logical_length == 0u ||
        logical_length > NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX ||
        chunk_count == 0u ||
        chunk_count > NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX ||
        chunk_count != rrm1_chunk_count(logical_length) ||
        !bytes_have_nonzero(manifest + 24u, 32u)) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX; ++i) {
        const uint8_t *desc = manifest + 56u + (size_t)i * 36u;
        uint32_t length = ninlil_rrmp_get_u32_be(desc);
        if (i < chunk_count) {
            uint32_t expected =
                i + 1u < chunk_count
                ? NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX
                : logical_length -
                    (uint32_t)i * NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
            if (length != expected || length == 0u ||
                length > NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX ||
                !bytes_have_nonzero(desc + 4u, 32u)) {
                return 0;
            }
        } else if (bytes_have_nonzero(desc, 36u)) {
            return 0;
        }
    }
    return !bytes_have_nonzero(manifest + 236u, 16u);
}

static int rrm1_manifest_build(
    const uint8_t *logical,
    uint32_t logical_length,
    uint64_t generation,
    uint8_t manifest[NINLIL_RRMP_RRM1_BYTES])
{
    uint8_t chunk_count;
    uint8_t i;
    if (logical == NULL || logical_length == 0u ||
        logical_length > NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX ||
        generation == 0u || generation == UINT64_MAX ||
        manifest == NULL) {
        return 0;
    }
    chunk_count = rrm1_chunk_count(logical_length);
    ninlil_rrmp_memzero(manifest, NINLIL_RRMP_RRM1_BYTES);
    memcpy(manifest, "RRM1", 4u);
    ninlil_rrmp_put_u16_be(manifest + 4u, 1u);
    ninlil_rrmp_put_u16_be(
        manifest + 6u, NINLIL_RRMP_RRM1_BYTES);
    ninlil_rrmp_put_u64_be(manifest + 8u, generation);
    ninlil_rrmp_put_u32_be(manifest + 16u, logical_length);
    manifest[20u] = chunk_count;
    ninlil_rrmp_sha256(logical, logical_length, manifest + 24u);
    for (i = 0u; i < chunk_count; ++i) {
        uint32_t off =
            (uint32_t)i * NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
        uint32_t length =
            logical_length - off >
                    NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX
                ? NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX
                : logical_length - off;
        uint8_t *desc = manifest + 56u + (size_t)i * 36u;
        ninlil_rrmp_put_u32_be(desc, length);
        ninlil_rrmp_sha256(logical + off, length, desc + 4u);
    }
    ninlil_rrmp_put_u32_be(
        manifest + 252u,
        ninlil_rrmp_crc32c_zeroed_u32_be_field(
            manifest, NINLIL_RRMP_RRM1_BYTES, 252u));
    return rrm1_manifest_validate(manifest);
}

static int rrmp_key_kind(const uint8_t *key, uint32_t length)
{
    uint8_t i;
    if (key == NULL || length != 7u) {
        return -1;
    }
    if (memcmp(key, k_rrmp_manifest_key, 7u) == 0) {
        return 0;
    }
    for (i = 0u; i < NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX; ++i) {
        if (memcmp(key, k_rrmp_chunk_keys[i], 7u) == 0) {
            return (int)i + 1;
        }
    }
    return -1;
}

static ninlil_storage_status_t bundle_read_snapshot(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_txn_t txn,
    uint8_t *logical_out,
    uint8_t *piece_scratch,
    ninlil_rrmp_bundle_witness_v2_t *witness_out)
{
    ninlil_bytes_view_t key;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t st;
    uint8_t manifest[NINLIL_RRMP_RRM1_BYTES];
    uint8_t point_seen[6];
    uint8_t iter_seen[6];
    uint8_t chunk_count = 0u;
    uint32_t logical_length = 0u;
    uint8_t i;
    ninlil_storage_iter_t iter = NULL;
    uint8_t last_key[7];
    uint8_t have_last = 0u;
    if (ops == NULL || txn == NULL || logical_out == NULL ||
        piece_scratch == NULL || witness_out == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    ninlil_rrmp_memzero(witness_out, sizeof(*witness_out));
    ninlil_rrmp_memzero(point_seen, sizeof(point_seen));
    ninlil_rrmp_memzero(iter_seen, sizeof(iter_seen));
    key.data = k_rrmp_manifest_key;
    key.length = 7u;
    value.data = manifest;
    value.capacity = NINLIL_RRMP_RRM1_BYTES;
    value.length = 0u;
    st = ops->get(ops->user, txn, key, &value);
    if (st == NINLIL_STORAGE_OK) {
        if (value.length != NINLIL_RRMP_RRM1_BYTES ||
            !rrm1_manifest_validate(manifest)) {
            return NINLIL_STORAGE_CORRUPT;
        }
        point_seen[0] = 1u;
        chunk_count = manifest[20u];
        logical_length = ninlil_rrmp_get_u32_be(manifest + 16u);
    } else if (st != NINLIL_STORAGE_NOT_FOUND) {
        return st;
    }
    for (i = 0u; i < NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX; ++i) {
        uint32_t offset =
            (uint32_t)i * NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
        uint32_t expected = i < chunk_count
            ? ninlil_rrmp_get_u32_be(
                manifest + 56u + (size_t)i * 36u)
            : 0u;
        key.data = k_rrmp_chunk_keys[i];
        key.length = 7u;
        value.data = i < chunk_count ? logical_out + offset
                                     : piece_scratch;
        value.capacity = NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
        value.length = 0u;
        st = ops->get(ops->user, txn, key, &value);
        if (i < chunk_count) {
            uint8_t digest[32];
            if (st != NINLIL_STORAGE_OK || value.length != expected) {
                return st == NINLIL_STORAGE_NOT_FOUND
                    ? NINLIL_STORAGE_CORRUPT : st;
            }
            ninlil_rrmp_sha256(value.data, value.length, digest);
            if (!ninlil_rrmp_memeq(
                    digest,
                    manifest + 60u + (size_t)i * 36u,
                    32u)) {
                return NINLIL_STORAGE_CORRUPT;
            }
            point_seen[i + 1u] = 1u;
        } else if (st != NINLIL_STORAGE_NOT_FOUND) {
            return st == NINLIL_STORAGE_OK
                ? NINLIL_STORAGE_CORRUPT : st;
        }
    }
    if (point_seen[0]) {
        uint8_t digest[32];
        ninlil_rrmp_sha256(logical_out, logical_length, digest);
        if (!ninlil_rrmp_memeq(digest, manifest + 24u, 32u)) {
            return NINLIL_STORAGE_CORRUPT;
        }
    }
    {
        ninlil_bytes_view_t prefix;
        prefix.data = k_rrmp_prefix;
        prefix.length = sizeof(k_rrmp_prefix);
        st = ops->iter_open(ops->user, txn, prefix, &iter);
    }
    if (st != NINLIL_STORAGE_OK || iter == NULL) {
        if (iter != NULL) {
            ops->iter_close(ops->user, iter);
        }
        return st == NINLIL_STORAGE_OK ? NINLIL_STORAGE_CORRUPT : st;
    }
    for (;;) {
        uint8_t iter_key[8];
        ninlil_mut_bytes_t ik;
        ninlil_mut_bytes_t iv;
        int kind;
        ik.data = iter_key;
        ik.capacity = sizeof(iter_key);
        ik.length = 0u;
        iv.data = piece_scratch;
        iv.capacity = NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
        iv.length = 0u;
        st = ops->iter_next(ops->user, iter, &ik, &iv);
        if (st == NINLIL_STORAGE_NOT_FOUND) {
            break;
        }
        if (st != NINLIL_STORAGE_OK) {
            ops->iter_close(ops->user, iter);
            return st;
        }
        kind = rrmp_key_kind(ik.data, ik.length);
        if (kind < 0 || iter_seen[kind] ||
            (have_last && memcmp(last_key, ik.data, 7u) >= 0)) {
            ops->iter_close(ops->user, iter);
            return NINLIL_STORAGE_CORRUPT;
        }
        memcpy(last_key, ik.data, 7u);
        have_last = 1u;
        iter_seen[kind] = 1u;
        if (!point_seen[kind]) {
            ops->iter_close(ops->user, iter);
            return NINLIL_STORAGE_CORRUPT;
        }
        if (kind == 0) {
            if (iv.length != NINLIL_RRMP_RRM1_BYTES ||
                !ninlil_rrmp_memeq(
                    iv.data, manifest, NINLIL_RRMP_RRM1_BYTES)) {
                ops->iter_close(ops->user, iter);
                return NINLIL_STORAGE_CORRUPT;
            }
        } else {
            uint8_t ci = (uint8_t)(kind - 1);
            uint32_t length = ninlil_rrmp_get_u32_be(
                manifest + 56u + (size_t)ci * 36u);
            if (iv.length != length ||
                !ninlil_rrmp_memeq(
                    iv.data,
                    logical_out +
                        (size_t)ci *
                            NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX,
                    length)) {
                ops->iter_close(ops->user, iter);
                return NINLIL_STORAGE_CORRUPT;
            }
        }
    }
    ops->iter_close(ops->user, iter);
    for (i = 0u; i < 6u; ++i) {
        if (point_seen[i] != iter_seen[i]) {
            return NINLIL_STORAGE_CORRUPT;
        }
    }
    if (!point_seen[0]) {
        return NINLIL_STORAGE_OK;
    }
    witness_out->present = 1u;
    memcpy(
        witness_out->manifest_rrm1, manifest, NINLIL_RRMP_RRM1_BYTES);
    witness_out->logical_length = logical_length;
    memcpy(witness_out->logical_sha256, manifest + 24u, 32u);
    return NINLIL_STORAGE_OK;
}

static void owner_witness_get(
    const ninlil_rrmp_owner_t *owner,
    ninlil_rrmp_bundle_witness_v2_t *out)
{
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->present = owner->storage_expected_present;
    out->logical_length = owner->storage_expected_length;
    memcpy(
        out->manifest_rrm1,
        owner->storage_expected_manifest,
        NINLIL_RRMP_RRM1_BYTES);
    memcpy(out->logical_sha256, owner->storage_expected_digest, 32u);
}

static void owner_witness_set(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_bundle_witness_v2_t *witness)
{
    owner->storage_expected_valid = 1u;
    owner->storage_expected_present = witness->present;
    owner->storage_expected_length = witness->logical_length;
    memcpy(
        owner->storage_expected_manifest,
        witness->manifest_rrm1,
        NINLIL_RRMP_RRM1_BYTES);
    memcpy(
        owner->storage_expected_digest, witness->logical_sha256, 32u);
}

static void owner_pending_witnesses_set(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_bundle_witness_v2_t *old_witness,
    const ninlil_rrmp_bundle_witness_v2_t *new_witness)
{
    owner->storage_pending_unknown = 1u;
    owner->storage_pending_old_present = old_witness->present;
    owner->storage_pending_old_length = old_witness->logical_length;
    memcpy(
        owner->storage_pending_old_manifest,
        old_witness->manifest_rrm1,
        NINLIL_RRMP_RRM1_BYTES);
    memcpy(
        owner->storage_pending_old_digest,
        old_witness->logical_sha256,
        32u);
    owner->storage_pending_new_length = new_witness->logical_length;
    memcpy(
        owner->storage_pending_new_manifest,
        new_witness->manifest_rrm1,
        NINLIL_RRMP_RRM1_BYTES);
    memcpy(
        owner->storage_pending_new_digest,
        new_witness->logical_sha256,
        32u);
}

static void owner_pending_witness_get(
    const ninlil_rrmp_owner_t *owner,
    ninlil_rrmp_bundle_witness_v2_t *old_witness,
    ninlil_rrmp_bundle_witness_v2_t *new_witness)
{
    ninlil_rrmp_memzero(old_witness, sizeof(*old_witness));
    old_witness->present = owner->storage_pending_old_present;
    old_witness->logical_length = owner->storage_pending_old_length;
    memcpy(
        old_witness->manifest_rrm1,
        owner->storage_pending_old_manifest,
        NINLIL_RRMP_RRM1_BYTES);
    memcpy(
        old_witness->logical_sha256,
        owner->storage_pending_old_digest,
        32u);
    ninlil_rrmp_memzero(new_witness, sizeof(*new_witness));
    new_witness->present = 1u;
    new_witness->logical_length = owner->storage_pending_new_length;
    memcpy(
        new_witness->manifest_rrm1,
        owner->storage_pending_new_manifest,
        NINLIL_RRMP_RRM1_BYTES);
    memcpy(
        new_witness->logical_sha256,
        owner->storage_pending_new_digest,
        32u);
}

static ninlil_storage_status_t bundle_stage(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_txn_t txn,
    const uint8_t *logical,
    const ninlil_rrmp_bundle_witness_v2_t *desired)
{
    uint8_t i;
    ninlil_storage_status_t st;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    uint8_t chunk_count = desired->manifest_rrm1[20u];
    for (i = 0u; i < chunk_count; ++i) {
        uint32_t length = ninlil_rrmp_get_u32_be(
            desired->manifest_rrm1 + 56u + (size_t)i * 36u);
        key.data = k_rrmp_chunk_keys[i];
        key.length = 7u;
        value.data =
            logical + (size_t)i * NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX;
        value.length = length;
        if (value.length > NINLIL_RRMP_PLATFORM_VALUE_BYTES_MAX) {
            return NINLIL_STORAGE_CORRUPT;
        }
        st = ops->put(ops->user, txn, key, value);
        if (st != NINLIL_STORAGE_OK) {
            return st;
        }
    }
    for (i = chunk_count; i < NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX; ++i) {
        key.data = k_rrmp_chunk_keys[i];
        key.length = 7u;
        st = ops->erase(ops->user, txn, key);
        if (st != NINLIL_STORAGE_OK &&
            st != NINLIL_STORAGE_NOT_FOUND) {
            return st;
        }
    }
    key.data = k_rrmp_manifest_key;
    key.length = 7u;
    value.data = desired->manifest_rrm1;
    value.length = NINLIL_RRMP_RRM1_BYTES;
    return ops->put(ops->user, txn, key, value);
}

int ninlil_rrmp_owner_storage_commit_full(ninlil_rrmp_owner_t *owner)
{
    const ninlil_storage_ops_t *ops;
    ninlil_rrmp_bundle_witness_v2_t expected;
    ninlil_rrmp_bundle_witness_v2_t observed;
    ninlil_rrmp_bundle_witness_v2_t desired;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    size_t logical_length = 0u;
    uint64_t generation;
    if (owner == NULL || !owner->storage_bound ||
        owner->storage_ops == NULL || owner->storage_handle == NULL ||
        owner->storage_hard_fence || !rrmp_export_scratch_ready(owner)) {
        return 0;
    }
    ops = owner->storage_ops;
    if (!ninlil_rrmp_owner_export_namespace(
            owner, NULL, 0u, &logical_length) ||
        logical_length == 0u ||
        logical_length > NINLIL_RRMP_RRM1_LOGICAL_REQUIRED_MAX ||
        !ninlil_rrmp_owner_export_namespace(
            owner,
            owner->storage_export_scratch,
            NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX,
            &logical_length)) {
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
        return 0;
    }
    owner_witness_get(owner, &expected);
    generation = expected.present
        ? ninlil_rrmp_get_u64_be(expected.manifest_rrm1 + 8u) + 1u
        : 1u;
    ninlil_rrmp_memzero(&desired, sizeof(desired));
    desired.present = 1u;
    desired.logical_length = (uint32_t)logical_length;
    if (generation == 0u || generation == UINT64_MAX ||
        !rrm1_manifest_build(
            owner->storage_export_scratch,
            (uint32_t)logical_length,
            generation,
            desired.manifest_rrm1)) {
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
        return 0;
    }
    memcpy(
        desired.logical_sha256,
        desired.manifest_rrm1 + 24u,
        32u);
    if (owner->storage_authority_v2 != NULL) {
        ninlil_rrmp_storage_piece_v2_t pieces[6];
        uint8_t i;
        ninlil_rrmp_memzero(pieces, sizeof(pieces));
        pieces[0].key = k_rrmp_manifest_key;
        pieces[0].key_length = 7u;
        pieces[0].value = desired.manifest_rrm1;
        pieces[0].value_length = NINLIL_RRMP_RRM1_BYTES;
        pieces[0].present = 1u;
        for (i = 0u; i < NINLIL_RRMP_RRM1_CHUNK_COUNT_MAX; ++i) {
            uint32_t length = i < desired.manifest_rrm1[20u]
                ? ninlil_rrmp_get_u32_be(
                    desired.manifest_rrm1 + 56u + (size_t)i * 36u)
                : 0u;
            pieces[i + 1u].key = k_rrmp_chunk_keys[i];
            pieces[i + 1u].key_length = 7u;
            pieces[i + 1u].value = length != 0u
                ? owner->storage_export_scratch +
                    (size_t)i * NINLIL_RRMP_RRM1_CHUNK_BYTES_MAX
                : NULL;
            pieces[i + 1u].value_length = length;
            pieces[i + 1u].present = length != 0u ? 1u : 0u;
        }
        {
            uint32_t ast =
                owner->storage_authority_v2->compare_exchange_bundle_full(
                    owner->storage_authority_v2->user,
                    owner->storage_handle,
                    &expected,
                    pieces,
                    6u,
                    &desired);
            if (ast == NINLIL_RRMP_STORAGE_CAS_OK) {
                owner_witness_set(owner, &desired);
                owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_OK;
                owner->storage_pending_unknown = 0u;
                return 1;
            }
            if (ast == NINLIL_RRMP_STORAGE_CAS_EXPECTED_MISMATCH) {
                owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CONFLICT;
                owner_storage_fence(owner);
                return 0;
            }
            if (ast == NINLIL_RRMP_STORAGE_CAS_COMMIT_UNKNOWN) {
                owner_pending_witnesses_set(owner, &expected, &desired);
                owner->storage_last_outcome =
                    RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN;
                owner_storage_fence(owner);
                return 0;
            }
            owner->storage_last_outcome =
                ast == NINLIL_RRMP_STORAGE_CAS_DEFINITE_FAILURE
                ? RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE
                : RRMP_STORAGE_OUTCOME_CORRUPT;
            if (ast == NINLIL_RRMP_STORAGE_CAS_CORRUPT) {
                owner_storage_fence(owner);
            }
            return 0;
        }
    }
    st = ops->begin(
        ops->user,
        owner->storage_handle,
        NINLIL_STORAGE_READ_WRITE,
        &txn);
    if (st != NINLIL_STORAGE_OK || txn == NULL) {
        owner->storage_last_outcome =
            st == NINLIL_STORAGE_COMMIT_UNKNOWN
            ? RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN
            : RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE;
        if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
            owner_pending_witnesses_set(owner, &expected, &desired);
            owner_storage_fence(owner);
        }
        return 0;
    }
    st = bundle_read_snapshot(
        ops,
        txn,
        owner->storage_export_scratch,
        owner->storage_piece_scratch,
        &observed);
    if (st != NINLIL_STORAGE_OK ||
        !owner->storage_expected_valid ||
        !bundle_witness_equal(&observed, &expected)) {
        (void)ops->rollback(ops->user, txn);
        if (st == NINLIL_STORAGE_OK) {
            owner->storage_last_outcome =
                RRMP_STORAGE_OUTCOME_CONFLICT;
            owner_storage_fence(owner);
        } else if (st == NINLIL_STORAGE_CORRUPT) {
            owner->storage_last_outcome =
                RRMP_STORAGE_OUTCOME_CORRUPT;
            owner_storage_fence(owner);
        } else {
            /*
             * A pre-stage provider read failure has not written any bundle
             * piece. Treat it as definite, then finish_writepoint_full
             * re-reads and reconstructs the exact durable OLD image.
             */
            owner->storage_last_outcome =
                RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE;
        }
        return 0;
    }
    if (!ninlil_rrmp_owner_export_namespace(
            owner,
            owner->storage_export_scratch,
            NINLIL_RRMP_RRM1_LOGICAL_BYTES_MAX,
            &logical_length) ||
        !rrm1_manifest_build(
            owner->storage_export_scratch,
            (uint32_t)logical_length,
            generation,
            desired.manifest_rrm1)) {
        (void)ops->rollback(ops->user, txn);
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
        return 0;
    }
    st = bundle_stage(ops, txn, owner->storage_export_scratch, &desired);
    if (st != NINLIL_STORAGE_OK) {
        ninlil_storage_status_t rollback_st =
            ops->rollback(ops->user, txn);
        owner->storage_last_outcome =
            st == NINLIL_STORAGE_COMMIT_UNKNOWN ||
                rollback_st != NINLIL_STORAGE_OK
            ? RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN
            : RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE;
        if (owner->storage_last_outcome ==
            RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN) {
            owner_pending_witnesses_set(owner, &expected, &desired);
            owner_storage_fence(owner);
        }
        return 0;
    }
    st = ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL);
    if (st == NINLIL_STORAGE_OK) {
        owner_witness_set(owner, &desired);
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_OK;
        owner->storage_pending_unknown = 0u;
        return 1;
    }
    if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        owner_pending_witnesses_set(owner, &expected, &desired);
        owner->storage_last_outcome =
            RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN;
        owner_storage_fence(owner);
    } else {
        owner->storage_last_outcome =
            RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE;
    }
    return 0;
}

static void owner_reset_durable_state(ninlil_rrmp_owner_t *owner)
{
    if (owner == NULL) {
        return;
    }
    ninlil_rrmp_memzero(owner->routes, sizeof(owner->routes));
    ninlil_rrmp_memzero(owner->evidence, sizeof(owner->evidence));
    ninlil_rrmp_memzero(&owner->loop_ring, sizeof(owner->loop_ring));
    ninlil_rrmp_memzero(&owner->dedup_ring, sizeof(owner->dedup_ring));
    ninlil_rrmp_memzero(owner->queue, sizeof(owner->queue));
    ninlil_rrmp_memzero(owner->carrier_arena, sizeof(owner->carrier_arena));
    ninlil_rrmp_memzero(owner->scopes, sizeof(owner->scopes));
    ninlil_rrmp_memzero(owner->attempts, sizeof(owner->attempts));
    owner->attempt_count = 0u;
    owner->authority_global_fence = 0u;
    owner->authority_global_fence_reason =
        NINLIL_RRMP_AUTHORITY_FENCE_NONE;
    owner->carrier_arena_used = 0u;
    owner->q_entries = 0u;
    owner->q_control_entries = 0u;
    owner->q_bytes = 0u;
    owner->bulk_streak = 0u;
    owner->lifetime_admits = 0u;
    owner->next_handle_token = 1u;
    owner->diag_installs = 0u;
    owner->diag_admits = 0u;
    owner->diag_forwards = 0u;
    ninlil_rrmp_route_ns_init(&owner->route_ns);
    ninlil_rrmp_parent_ns_init(&owner->parent_ns);
    owner->downlink_tx = 1u;
}

#if 0 /* RRP-1 removed: single-value recovery/classification. */
static int storage_current_matches(
    uint8_t present,
    uint32_t length,
    const uint8_t digest[32],
    uint8_t expected_present,
    uint32_t expected_length,
    const uint8_t expected_digest[32])
{
    if (present != expected_present) {
        return 0;
    }
    if (!present) {
        return 1;
    }
    return length == expected_length &&
        ninlil_rrmp_memeq(digest, expected_digest, 32u);
}

static int owner_apply_storage_image(
    ninlil_rrmp_owner_t *owner,
    uint8_t present,
    const uint8_t *bytes,
    uint32_t length,
    uint32_t outer_class)
{
    uint8_t digest[32];
    if (owner == NULL || (present && (bytes == NULL || length == 0u))) {
        return 0;
    }
    if (!present) {
        owner_reset_durable_state(owner);
        owner->storage_expected_present = 0u;
        owner->storage_expected_length = 0u;
        ninlil_rrmp_memzero(owner->storage_expected_digest, 32u);
    } else {
        ninlil_rrmp_sha256(bytes, length, digest);
        owner->downlink_tx = 1u;
        if (!ninlil_rrmp_owner_import_namespace(owner, bytes, length)) {
            owner_storage_fence(owner);
            return 0;
        }
        owner->storage_expected_present = 1u;
        owner->storage_expected_length = length;
        memcpy(owner->storage_expected_digest, digest, 32u);
    }
    owner->storage_expected_valid = 1u;
    owner->storage_pending_unknown = 0u;
    owner->storage_hard_fence = 0u;
    /*
     * Import/rehydrate is authoritative for semantic route/parent fences
     * (lease expiry, split brain, inner corruption).  Only the outer storage
     * fence is cleared here; never erase a legitimate imported fence.
     */
    if (outer_class == NINLIL_RRMP_STORAGE_RECOVERY_OLD) {
        owner->route_ns.cu_class = NINLIL_RRMP_CU_OLD;
        owner->parent_ns.cu_class = NINLIL_RRMP_CU_OLD;
    } else if (outer_class == NINLIL_RRMP_STORAGE_RECOVERY_NEW) {
        owner->route_ns.cu_class = NINLIL_RRMP_CU_NEW;
        owner->parent_ns.cu_class = NINLIL_RRMP_CU_NEW;
    }
    return 1;
}

static int owner_storage_recover_internal(
    ninlil_rrmp_owner_t *owner, int require_expected_old)
{
    const ninlil_storage_ops_t *ops;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t sst;
    ninlil_bytes_view_t key;
    ninlil_mut_bytes_t val;
    uint8_t present = 0u;
    uint8_t digest[32];
    uint32_t outer_class = NINLIL_RRMP_STORAGE_RECOVERY_NONE;
    if (owner == NULL || !owner->storage_bound || owner->storage_ops == NULL ||
        owner->storage_handle == NULL) {
        return 0;
    }
    ops = owner->storage_ops;
    if (!rrmp_export_scratch_ready(owner)) {
        owner_storage_fence(owner);
        return 0;
    }
    if (!require_expected_old && owner->storage_authority != NULL) {
        uint32_t recovered_length = 0u;
        uint32_t ast = owner->storage_authority->recover_pending_full(
            owner->storage_authority->user,
            owner->storage_handle,
            k_rrmp_storage_key,
            (uint32_t)sizeof(k_rrmp_storage_key),
            owner->storage_export_scratch,
            NINLIL_RRMP_STORAGE_EXPORT_MAX,
            &recovered_length,
            &outer_class);
        if (ast == NINLIL_RRMP_STORAGE_CAS_OK &&
            outer_class != NINLIL_RRMP_STORAGE_RECOVERY_NONE) {
            if (outer_class != NINLIL_RRMP_STORAGE_RECOVERY_OLD &&
                outer_class != NINLIL_RRMP_STORAGE_RECOVERY_NEW) {
                owner_storage_fence(owner);
                owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
                owner->route_ns.cu_class =
                    outer_class == NINLIL_RRMP_STORAGE_RECOVERY_THIRD
                    ? NINLIL_RRMP_CU_THIRD
                    : NINLIL_RRMP_CU_PARTIAL;
                owner->parent_ns.cu_class = owner->route_ns.cu_class;
                return 0;
            }
            present = recovered_length != 0u ? 1u : 0u;
            ninlil_rrmp_memzero(digest, sizeof(digest));
            if (present) {
                ninlil_rrmp_sha256(
                    owner->storage_export_scratch, recovered_length, digest);
            }
            if (owner->storage_pending_unknown) {
                if (outer_class == NINLIL_RRMP_STORAGE_RECOVERY_OLD &&
                    !storage_current_matches(
                        present,
                        recovered_length,
                        digest,
                        owner->storage_pending_old_present,
                        owner->storage_pending_old_length,
                        owner->storage_pending_old_digest)) {
                    owner_storage_fence(owner);
                    return 0;
                }
                if (outer_class == NINLIL_RRMP_STORAGE_RECOVERY_NEW &&
                    (!present ||
                        recovered_length !=
                            owner->storage_pending_new_length ||
                        !ninlil_rrmp_memeq(
                            digest,
                            owner->storage_pending_new_digest,
                            32u))) {
                    owner_storage_fence(owner);
                    return 0;
                }
            }
            if (!owner_apply_storage_image(
                    owner,
                    present,
                    owner->storage_export_scratch,
                    recovered_length,
                    outer_class)) {
                return 0;
            }
            owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_OK;
            return 1;
        }
        if (ast == NINLIL_RRMP_STORAGE_CAS_COMMIT_UNKNOWN) {
            owner_storage_fence(owner);
            owner->storage_last_outcome =
                RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN;
            return 0;
        }
        if (ast != NINLIL_RRMP_STORAGE_CAS_OK &&
            ast != NINLIL_RRMP_STORAGE_CAS_DEFINITE_FAILURE) {
            owner_storage_fence(owner);
            owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
            return 0;
        }
    }
    sst = ops->begin(ops->user, owner->storage_handle, NINLIL_STORAGE_READ_ONLY, &txn);
    if (sst != NINLIL_STORAGE_OK || txn == NULL) {
        owner_storage_fence(owner);
        return 0;
    }
    key.data = k_rrmp_storage_key;
    key.length = (uint32_t)sizeof(k_rrmp_storage_key);
    val.data = owner->storage_export_scratch;
    val.capacity = (uint32_t)NINLIL_RRMP_STORAGE_EXPORT_MAX;
    val.length = 0u;
    sst = ops->get(ops->user, txn, key, &val);
    if (ops->rollback(ops->user, txn) != NINLIL_STORAGE_OK) {
        owner_storage_fence(owner);
        return 0;
    }
    if (sst == NINLIL_STORAGE_NOT_FOUND) {
        present = 0u;
        val.length = 0u;
        ninlil_rrmp_memzero(digest, sizeof(digest));
    } else if (sst == NINLIL_STORAGE_OK) {
        present = 1u;
        ninlil_rrmp_sha256(val.data, val.length, digest);
    } else {
        owner_storage_fence(owner);
        return 0;
    }
    if (require_expected_old) {
        if (!owner->storage_expected_valid ||
            !storage_current_matches(
                present,
                val.length,
                digest,
                owner->storage_expected_present,
                owner->storage_expected_length,
                owner->storage_expected_digest)) {
            owner_storage_fence(owner);
            return 0;
        }
        outer_class = NINLIL_RRMP_STORAGE_RECOVERY_OLD;
    } else if (owner->storage_pending_unknown) {
        if (storage_current_matches(
                present,
                val.length,
                digest,
                owner->storage_pending_old_present,
                owner->storage_pending_old_length,
                owner->storage_pending_old_digest)) {
            outer_class = NINLIL_RRMP_STORAGE_RECOVERY_OLD;
        } else if (present &&
            val.length == owner->storage_pending_new_length &&
            ninlil_rrmp_memeq(
                digest, owner->storage_pending_new_digest, 32u)) {
            outer_class = NINLIL_RRMP_STORAGE_RECOVERY_NEW;
        } else {
            owner_storage_fence(owner);
            owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
            owner->route_ns.cu_class = NINLIL_RRMP_CU_THIRD;
            owner->parent_ns.cu_class = NINLIL_RRMP_CU_THIRD;
            return 0;
        }
    }
    if (!owner_apply_storage_image(
            owner, present, val.data, val.length, outer_class)) {
        return 0;
    }
    owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_OK;
    return 1;
}

int ninlil_rrmp_owner_storage_recover(ninlil_rrmp_owner_t *owner)
{
    return owner_storage_recover_internal(owner, 0);
}
#endif

static int owner_apply_bundle_image(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_bundle_witness_v2_t *witness,
    const uint8_t *logical,
    uint32_t outer_class)
{
    if (owner == NULL || witness == NULL ||
        (witness->present &&
            (logical == NULL || witness->logical_length == 0u))) {
        return 0;
    }
    if (!witness->present) {
        owner_reset_durable_state(owner);
    } else {
        owner->downlink_tx = 1u;
        if (!ninlil_rrmp_owner_import_namespace(
                owner,
                logical,
                witness->logical_length)) {
            owner_storage_fence(owner);
            return 0;
        }
    }
    owner_witness_set(owner, witness);
    owner->storage_pending_unknown = 0u;
    owner->storage_hard_fence = 0u;
    if (owner->authority_global_fence) {
        owner->downlink_tx = 0u;
    }
    if (outer_class == NINLIL_RRMP_STORAGE_RECOVERY_OLD) {
        owner->route_ns.cu_class = NINLIL_RRMP_CU_OLD;
        owner->parent_ns.cu_class = NINLIL_RRMP_CU_OLD;
    } else if (outer_class == NINLIL_RRMP_STORAGE_RECOVERY_NEW) {
        owner->route_ns.cu_class = NINLIL_RRMP_CU_NEW;
        owner->parent_ns.cu_class = NINLIL_RRMP_CU_NEW;
    }
    return 1;
}

static int owner_storage_recover_internal(
    ninlil_rrmp_owner_t *owner, int require_expected_old)
{
    const ninlil_storage_ops_t *ops;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    ninlil_rrmp_bundle_witness_v2_t observed;
    ninlil_rrmp_bundle_witness_v2_t expected;
    ninlil_rrmp_bundle_witness_v2_t old_witness;
    ninlil_rrmp_bundle_witness_v2_t new_witness;
    uint32_t outer_class = NINLIL_RRMP_STORAGE_RECOVERY_NONE;
    uint32_t provider_class = NINLIL_RRMP_STORAGE_RECOVERY_NONE;
    if (owner == NULL || !owner->storage_bound ||
        owner->storage_ops == NULL || owner->storage_handle == NULL ||
        !rrmp_export_scratch_ready(owner)) {
        return 0;
    }
    ops = owner->storage_ops;
    owner_witness_get(owner, &expected);
    owner_pending_witness_get(owner, &old_witness, &new_witness);
    if (!require_expected_old && owner->storage_pending_unknown &&
        owner->storage_authority_v2 != NULL) {
        uint32_t ast =
            owner->storage_authority_v2->recover_pending_bundle_full(
                owner->storage_authority_v2->user,
                owner->storage_handle,
                &old_witness,
                &new_witness,
                &provider_class);
        if (ast == NINLIL_RRMP_STORAGE_CAS_COMMIT_UNKNOWN) {
            owner->storage_last_outcome =
                RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN;
            owner_storage_fence(owner);
            return 0;
        }
        if (ast != NINLIL_RRMP_STORAGE_CAS_OK ||
            (provider_class != NINLIL_RRMP_STORAGE_RECOVERY_OLD &&
                provider_class != NINLIL_RRMP_STORAGE_RECOVERY_NEW)) {
            owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
            owner->route_ns.cu_class =
                provider_class == NINLIL_RRMP_STORAGE_RECOVERY_THIRD
                ? NINLIL_RRMP_CU_THIRD : NINLIL_RRMP_CU_PARTIAL;
            owner->parent_ns.cu_class = owner->route_ns.cu_class;
            owner_storage_fence(owner);
            return 0;
        }
    }
    st = ops->begin(
        ops->user,
        owner->storage_handle,
        NINLIL_STORAGE_READ_ONLY,
        &txn);
    if (st != NINLIL_STORAGE_OK || txn == NULL) {
        owner_storage_fence(owner);
        return 0;
    }
    st = bundle_read_snapshot(
        ops,
        txn,
        owner->storage_export_scratch,
        owner->storage_piece_scratch,
        &observed);
    if (ops->rollback(ops->user, txn) != NINLIL_STORAGE_OK ||
        st != NINLIL_STORAGE_OK) {
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
        owner_storage_fence(owner);
        return 0;
    }
    if (require_expected_old) {
        if (!owner->storage_expected_valid ||
            !bundle_witness_equal(&observed, &expected)) {
            owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
            owner_storage_fence(owner);
            return 0;
        }
        outer_class = NINLIL_RRMP_STORAGE_RECOVERY_OLD;
    } else if (owner->storage_pending_unknown) {
        if (bundle_witness_equal(&observed, &old_witness)) {
            outer_class = NINLIL_RRMP_STORAGE_RECOVERY_OLD;
        } else if (bundle_witness_equal(&observed, &new_witness)) {
            outer_class = NINLIL_RRMP_STORAGE_RECOVERY_NEW;
        } else {
            owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
            owner->route_ns.cu_class = NINLIL_RRMP_CU_THIRD;
            owner->parent_ns.cu_class = NINLIL_RRMP_CU_THIRD;
            owner_storage_fence(owner);
            return 0;
        }
        if (provider_class != NINLIL_RRMP_STORAGE_RECOVERY_NONE &&
            provider_class != outer_class) {
            owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
            owner_storage_fence(owner);
            return 0;
        }
    }
    if (!owner_apply_bundle_image(
            owner,
            &observed,
            observed.present ? owner->storage_export_scratch : NULL,
            outer_class)) {
        return 0;
    }
    owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_OK;
    return 1;
}

int ninlil_rrmp_owner_storage_recover(ninlil_rrmp_owner_t *owner)
{
    return owner_storage_recover_internal(owner, 0);
}

/*
 * Normative FULL writepoint close: when platform storage is bound, dual-RAM
 * mutation is incomplete until storage_commit_full succeeds. Unbound owners
 * treat dual-RAM as the writepoint (host tests without storage).
 * Failures fence downlink and propagate to callers.
 */
static int finish_writepoint_full(ninlil_rrmp_owner_t *owner)
{
    if (owner == NULL) {
        return 0;
    }
    if (!owner->storage_bound) {
        return 1;
    }
    if (ninlil_rrmp_owner_storage_commit_full(owner)) {
        return 1;
    }
    if (owner->storage_last_outcome ==
        RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE) {
        /*
         * Definite failure means the outer FULL transaction did not commit.
         * Re-read and require the exact durable OLD tuple, then reconstruct
         * RAM from it. No partially updated RAM remains externally usable.
         */
        if (owner_storage_recover_internal(owner, 1)) {
            owner->storage_last_outcome =
                RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE;
            return 0;
        }
        owner->storage_last_outcome = RRMP_STORAGE_OUTCOME_CORRUPT;
    }
    if (owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN) {
        owner->route_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
        owner->parent_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
    }
    owner_storage_fence(owner);
    return 0;
}

/*
 * A definite outer-CAS failure followed by require_expected_old recovery
 * reconstructs RAM from the exact durable OLD image. Callers must not apply
 * their pre-recovery, index-based rollback to that reconstructed image.
 */
static int writepoint_restored_exact_durable_old(
    const ninlil_rrmp_owner_t *owner)
{
    return owner != NULL && owner->storage_bound &&
        owner->storage_last_outcome ==
            RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE &&
        !owner->storage_hard_fence;
}

static uint32_t writepoint_fail_route_status(ninlil_rrmp_owner_t *owner)
{
    if (owner != NULL &&
        owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_CONFLICT) {
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (owner != NULL && owner->storage_bound &&
        owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_NONE) {
        /* Inner dual-page construction failed before the outer FULL call. */
        if (!owner_storage_recover_internal(owner, 1)) {
            owner_storage_fence(owner);
        }
        owner->storage_last_outcome =
            RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE;
    }
    if (owner != NULL &&
        (owner->storage_last_outcome ==
                RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN ||
            owner->route_ns.cu_class == NINLIL_RRMP_CU_PARTIAL ||
            owner->route_ns.cu_class == NINLIL_RRMP_CU_EXTRA ||
            owner->route_ns.cu_class == NINLIL_RRMP_CU_THIRD)) {
        return NINLIL_ROUTE_COMMIT_UNKNOWN;
    }
    return NINLIL_ROUTE_CORRUPT;
}

static uint32_t writepoint_fail_parent_status(ninlil_rrmp_owner_t *owner)
{
    if (owner != NULL &&
        owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_CONFLICT) {
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (owner != NULL && owner->storage_bound &&
        owner->storage_last_outcome == RRMP_STORAGE_OUTCOME_NONE) {
        if (!owner_storage_recover_internal(owner, 1)) {
            owner_storage_fence(owner);
        }
        owner->storage_last_outcome =
            RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE;
        return NINLIL_PARENT_CORRUPT;
    }
    /*
     * A parent writepoint can fail after one of several inner dual-key writes.
     * Even when the platform did not classify the failure as
     * COMMIT_UNKNOWN, sealing must remain fail-closed until recovery.
     */
    if (owner != NULL) {
        if (owner->storage_last_outcome ==
            RRMP_STORAGE_OUTCOME_DEFINITE_FAILURE) {
            return NINLIL_PARENT_CORRUPT;
        }
        owner->parent_ns.fenced = 1u;
        owner->downlink_tx = 0u;
        if (owner->parent_ns.cu_class != NINLIL_RRMP_CU_EXTRA &&
            owner->parent_ns.cu_class != NINLIL_RRMP_CU_THIRD) {
            owner->parent_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
        }
        return NINLIL_PARENT_COMMIT_UNKNOWN;
    }
    return NINLIL_PARENT_CORRUPT;
}

uint32_t ninlil_rrmp_owner_cu_class(const ninlil_rrmp_owner_t *owner)
{
    if (owner == NULL) {
        return NINLIL_RRMP_CU_ABSENT;
    }
    return owner->route_ns.cu_class;
}

uint32_t ninlil_rrmp_owner_downlink_tx_allowed(const ninlil_rrmp_owner_t *owner)
{
    return owner == NULL
        ? 0u
        : (uint32_t)(owner->downlink_tx && !owner->route_ns.fenced &&
              !owner->parent_ns.fenced);
}

/* --- Route ops --- */

ninlil_route_status_u32 ninlil_route_install_batch(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_install_batch_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    uint16_t n;
    uint16_t i;
    uint32_t fixed;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    n = req->entry_count;
    if (n < 1u || n > NINLIL_RRMP_INSTALL_BATCH_MAX) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    fixed = 56u + 256u * (uint32_t)n;
    st = preamble_route(
        &req->preamble, fixed, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o)) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (!o->cfg.feature_route_relay) {
        result_fill(out, NINLIL_ROUTE_FEATURE_OFF);
        return NINLIL_ROUTE_FEATURE_OFF;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_ROUTE_ADMIN)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_write_gate(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (enter(o) < 0) {
        result_fill(out, NINLIL_ROUTE_REENTRANT);
        return NINLIL_ROUTE_REENTRANT;
    }
    if ((uint32_t)n + 1u > NINLIL_RRMP_LOGICAL_MUTATIONS_MAX) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_RESOURCE);
        return NINLIL_ROUTE_RESOURCE;
    }
    /*
     * Atomic batch FULL (no rollback holes):
     *  1) validate all entries
     *  2) pre-allocate all slots (fail closed if any missing)
     *  3) write STAGED into slots
     *  4) persist unique pages; on any fail, free all batch slots + re-persist
     */
    {
        ninlil_rrmp_nrm1_fields_t decoded[NINLIL_RRMP_INSTALL_BATCH_MAX];
        rrmp_route_t *ents[NINLIL_RRMP_INSTALL_BATCH_MAX];
        uint8_t pages_touched[NINLIL_RRMP_PAGE_COUNT];
        uint16_t pi;
        ninlil_rrmp_memzero(decoded, sizeof(decoded));
        ninlil_rrmp_memzero(ents, sizeof(ents));
        ninlil_rrmp_memzero(pages_touched, sizeof(pages_touched));
        for (i = 0u; i < n; ++i) {
            const uint8_t *rec =
                req->entries + (size_t)i * NINLIL_RRMP_NRM1_BYTES;
            if (!ninlil_rrmp_decode_nrm1(rec, &decoded[i])) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_CORRUPT);
                return NINLIL_ROUTE_CORRUPT;
            }
            if (!ninlil_rrmp_memeq(
                    decoded[i].authority_id.bytes, req->authority_id, 16u) ||
                !ninlil_rrmp_memeq(
                    decoded[i].authority_id.bytes, o->cfg.authority_id, 16u)) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
                return NINLIL_ROUTE_AUTHORITY_CONFLICT;
            }
            if (decoded[i].controller_term < req->controller_term ||
                decoded[i].controller_term < o->cfg.controller_term) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_STALE_GENERATION);
                return NINLIL_ROUTE_STALE_GENERATION;
            }
            if (decoded[i].max_hops == 0u ||
                decoded[i].max_hops > o->cfg.max_hops_profile ||
                decoded[i].max_hops > NINLIL_RRMP_MAX_HOPS_ABSOLUTE) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_UNSUPPORTED_CAPABILITY);
                return NINLIL_ROUTE_UNSUPPORTED_CAPABILITY;
            }
        }
        for (i = 0u; i < n; ++i) {
            ents[i] = alloc_route(o);
            if (ents[i] == NULL) {
                uint16_t j;
                for (j = 0u; j < i; ++j) {
                    ents[j]->used = 0u;
                    ninlil_rrmp_memzero(ents[j], sizeof(*ents[j]));
                }
                leave(o);
                result_fill(out, NINLIL_ROUTE_RESOURCE);
                return NINLIL_ROUTE_RESOURCE;
            }
        }
        for (i = 0u; i < n; ++i) {
            ents[i]->fields = decoded[i];
            ents[i]->state = NINLIL_RRMP_LIFE_STAGED;
            ents[i]->next_admission_seq = 1u;
            pages_touched[(size_t)(ents[i] - o->routes) /
                NINLIL_RRMP_SLOTS_PER_PAGE] = 1u;
        }
        for (pi = 0u; pi < NINLIL_RRMP_PAGE_COUNT; ++pi) {
            if (!pages_touched[pi]) {
                continue;
            }
            if (!persist_route_page(o, pi)) {
                uint16_t j;
                for (j = 0u; j < n; ++j) {
                    ents[j]->used = 0u;
                    ninlil_rrmp_memzero(ents[j], sizeof(*ents[j]));
                }
                /* Best-effort re-persist cleared pages (no partial STAGED). */
                for (j = 0u; j < NINLIL_RRMP_PAGE_COUNT; ++j) {
                    if (pages_touched[j]) {
                        (void)persist_route_page(o, j);
                    }
                }
                leave(o);
                result_fill(out, writepoint_fail_route_status(o));
                return out->status;
            }
        }
        o->diag_installs += n;
    }
    if (!finish_writepoint_full(o)) {
        leave(o);
        result_fill(out, writepoint_fail_route_status(o));
        return out->status;
    }
    leave(o);
    result_fill(out, NINLIL_ROUTE_OK);
    out->lifecycle_state = NINLIL_RRMP_LIFE_STAGED;
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_route_activate(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_activate_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    rrmp_route_t *ent;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(
        &req->preamble, 64u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o)) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (!o->cfg.feature_route_relay) {
        result_fill(out, NINLIL_ROUTE_FEATURE_OFF);
        return NINLIL_ROUTE_FEATURE_OFF;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_ROUTE_ADMIN)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_write_gate(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    ent = find_route(
        o, req->ingress_hop_context_id, req->route_handle, req->route_generation);
    /* Strict lifecycle: ACTIVE is not reactivated (only STAGED→ACTIVE). */
    if (ent == NULL || ent->state != NINLIL_RRMP_LIFE_STAGED) {
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (req->expected_route_revision != 0u &&
        req->expected_route_revision != ent->fields.route_revision) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    /* lease / clock epoch validation at activate */
    if (ent->fields.lease_expiry_ms != 0u &&
        req->now_ms >= ent->fields.lease_expiry_ms) {
        ent->state = NINLIL_RRMP_LIFE_EXPIRED;
        if (!persist_route_page(
                o,
                (uint16_t)((size_t)(ent - o->routes) /
                    NINLIL_RRMP_SLOTS_PER_PAGE)) ||
            !finish_writepoint_full(o)) {
            ent->state = NINLIL_RRMP_LIFE_STAGED;
            result_fill(out, writepoint_fail_route_status(o));
            return out->status;
        }
        result_fill(out, NINLIL_ROUTE_LEASE_EXPIRED);
        return NINLIL_ROUTE_LEASE_EXPIRED;
    }
    if (!ninlil_rrmp_memeq(
            ent->fields.authority_clock_epoch_id.bytes,
            o->cfg.authority_clock_epoch_id, 16u)) {
        result_fill(out, NINLIL_ROUTE_CLOCK_EPOCH_MISMATCH);
        return NINLIL_ROUTE_CLOCK_EPOCH_MISMATCH;
    }
    ent->state = NINLIL_RRMP_LIFE_ACTIVE;
    if (!persist_route_page(
            o, (uint16_t)((size_t)(ent - o->routes) / NINLIL_RRMP_SLOTS_PER_PAGE)) ||
        !finish_writepoint_full(o)) {
        ent->state = NINLIL_RRMP_LIFE_STAGED;
        result_fill(out, writepoint_fail_route_status(o));
        return out->status;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->lifecycle_state = NINLIL_RRMP_LIFE_ACTIVE;
    out->route_handle = req->route_handle;
    out->route_generation = req->route_generation;
    out->ingress_hop_context_id = req->ingress_hop_context_id;
    out->route_revision = ent->fields.route_revision;
    out->lease_epoch = ent->fields.lease_epoch;
    out->controller_term = ent->fields.controller_term;
    out->next_admission_seq = ent->next_admission_seq;
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_route_begin_drain(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_begin_drain_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    rrmp_route_t *ent;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 80u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_route_relay) {
        result_fill(out, !owner_serial_active(o) ? NINLIL_ROUTE_INVALID_ARGUMENT
                                  : NINLIL_ROUTE_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_ROUTE_ADMIN)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_write_gate(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    ent = find_route(
        o, req->ingress_hop_context_id, req->route_handle, req->route_generation);
    /* DRAINING reachable only from ACTIVE */
    if (ent == NULL || ent->state != NINLIL_RRMP_LIFE_ACTIVE) {
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    ent->state = NINLIL_RRMP_LIFE_DRAINING;
    /* fence = next_admission_seq: only items with admission_seq < fence */
    ent->drain.drain_fence = ent->next_admission_seq;
    ent->drain.route_revision = ent->fields.route_revision;
    ent->drain.drain_deadline_ms = req->drain_deadline_ms;
    ent->drain.lease_deadline_ms = req->lease_deadline_ms;
    if (!persist_route_page(
            o, (uint16_t)((size_t)(ent - o->routes) / NINLIL_RRMP_SLOTS_PER_PAGE)) ||
        !finish_writepoint_full(o)) {
        ent->state = NINLIL_RRMP_LIFE_ACTIVE;
        result_fill(out, writepoint_fail_route_status(o));
        return out->status;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->lifecycle_state = NINLIL_RRMP_LIFE_DRAINING;
    out->detail_flags = 2u;
    out->next_admission_seq = ent->next_admission_seq;
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_route_retire(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_retire_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    rrmp_route_t *ent;
    size_t i;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 64u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_route_relay) {
        result_fill(out, !owner_serial_active(o) ? NINLIL_ROUTE_INVALID_ARGUMENT
                                  : NINLIL_ROUTE_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_ROUTE_ADMIN)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_write_gate(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    ent = find_route(
        o, req->ingress_hop_context_id, req->route_handle, req->route_generation);
    if (ent == NULL) {
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (ent->state == NINLIL_RRMP_LIFE_DRAINING && req->force == 0u) {
        /* incomplete drain */
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (req->force == 0u) {
        for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
            if (o->queue[i].used &&
                o->queue[i].handle == req->route_handle &&
                o->queue[i].gen == req->route_generation &&
                o->queue[i].ingress_hop_context_id ==
                    req->ingress_hop_context_id) {
                result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
                return NINLIL_ROUTE_NOT_ACTIVE;
            }
        }
    }
    /*
     * Tombstone FULL/CU atomic: durable RETIRED (exact slot state) then free.
     * Persist fail reverts memory state — no RETIRED-without-durable hole.
     */
    {
        uint8_t prev = ent->state;
        uint16_t page =
            (uint16_t)((size_t)(ent - o->routes) / NINLIL_RRMP_SLOTS_PER_PAGE);
        ent->state = NINLIL_RRMP_LIFE_RETIRED;
        if (!persist_route_page(o, page)) {
            ent->state = prev;
            result_fill(out, writepoint_fail_route_status(o));
            return out->status;
        }
        for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
            if (o->evidence[i].used) {
                ninlil_rrmp_nev1_fields_t ef;
                if (ninlil_rrmp_decode_nev1(o->evidence[i].raw, &ef) &&
                    ef.route_handle == req->route_handle &&
                    ef.route_generation == req->route_generation &&
                    !completed_evidence_is_attempt_pinned(
                        o, o->evidence[i].raw)) {
                    ninlil_rrmp_memzero(&o->evidence[i], sizeof(o->evidence[i]));
                }
            }
        }
        /*
         * Evidence pages are independent canonical keys. Clearing only the
         * in-memory slots would resurrect LIVE evidence on the next boot.
         */
        for (i = 0u; i < NINLIL_RRMP_NEP1_PAGE_COUNT; ++i) {
            if (!persist_evidence_page(o, (uint16_t)i)) {
                o->route_ns.fenced = 1u;
                o->downlink_tx = 0u;
                result_fill(out, writepoint_fail_route_status(o));
                return out->status;
            }
        }
        /* Force retire atomically abandons every custody record on this route. */
        for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
            if (o->queue[i].used &&
                o->queue[i].handle == req->route_handle &&
                o->queue[i].gen == req->route_generation &&
                o->queue[i].ingress_hop_context_id ==
                    req->ingress_hop_context_id) {
                queue_release(o, &o->queue[i]);
            }
        }
        /* Free after durable RETIRED; rehydrate skips RETIRED tombstones. */
        ninlil_rrmp_memzero(ent, sizeof(*ent));
        if (!persist_route_page(o, page) || !finish_writepoint_full(o)) {
            result_fill(out, writepoint_fail_route_status(o));
            return out->status;
        }
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->lifecycle_state = NINLIL_RRMP_LIFE_RETIRED;
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_route_query(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_query_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    rrmp_route_t *ent;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 48u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_route_relay) {
        result_fill(out, !owner_serial_active(o) ? NINLIL_ROUTE_INVALID_ARGUMENT
                                  : NINLIL_ROUTE_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_DIAGNOSTICS)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_fence_status(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    ent = find_route(
        o, req->ingress_hop_context_id, req->route_handle, req->route_generation);
    if (ent == NULL) {
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->lifecycle_state = ent->state;
    out->route_handle = ent->fields.route_handle;
    out->route_generation = ent->fields.route_generation;
    out->next_admission_seq = ent->next_admission_seq;
    out->cu_class = (uint8_t)o->route_ns.cu_class;
    return NINLIL_ROUTE_OK;
}

static uint32_t evidence_occupied(const ninlil_rrmp_owner_t *o)
{
    uint32_t n = 0u;
    size_t i;
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (o->evidence[i].used) {
            ++n;
        }
    }
    return n;
}

static int completed_evidence_is_attempt_pinned(
    const ninlil_rrmp_owner_t *o, const uint8_t raw[NINLIL_RRMP_NEV1_BYTES])
{
    uint8_t digest[32];
    uint16_t ai;
    if (o == NULL || raw == NULL) {
        return 0;
    }
    ninlil_rrmp_sha256(raw, NINLIL_RRMP_NEV1_BYTES, digest);
    for (ai = 0u; ai < o->attempt_count; ++ai) {
        if (o->attempts[ai].lifecycle ==
                NINLIL_RRMP_ATTEMPT_TERMINAL_RETAINED &&
            (o->attempts[ai].flags &
                NINLIL_RRMP_ATTEMPT_FLAG_NEV1) != 0u &&
            ninlil_rrmp_memeq(
                o->attempts[ai].terminal_evidence_digest32, digest, 32u)) {
            return 1;
        }
    }
    return 0;
}

static void reclaim_completed(ninlil_rrmp_owner_t *o)
{
    size_t i;
    /*
     * Reclaim exactly one slot per admission. The caller reuses the first
     * cleared slot and persists that same NEP1 page with the new LIVE record;
     * clearing multiple pages here would leave uncommitted in-memory GC.
     */
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (o->evidence[i].used) {
            ninlil_rrmp_nev1_fields_t ef;
            if (ninlil_rrmp_decode_nev1(o->evidence[i].raw, &ef) &&
                ef.lifecycle == NINLIL_RRMP_EVIDENCE_LIFECYCLE_COMPLETED) {
                if (completed_evidence_is_attempt_pinned(
                        o, o->evidence[i].raw)) {
                    continue;
                }
                ninlil_rrmp_memzero(&o->evidence[i], sizeof(o->evidence[i]));
                break;
            }
        }
    }
}

static ninlil_route_status_u32 route_forward_admit_impl(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_admit_req_v1_t *req,
    const uint8_t *carrier,
    uint16_t carrier_len,
    const uint8_t attempt_id16[16],
    ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    rrmp_route_t *ent;
    ninlil_rrmp_digest32_t loop_k;
    ninlil_rrmp_digest32_t dedup_k;
    ninlil_rrmp_digest32_t evi_k;
    ninlil_rrmp_nev1_fields_t evi;
    rrmp_evi_t *slot = NULL;
    size_t i;
    uint8_t hop_out;
    uint8_t prio;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 128u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o)) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_FORWARD)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (carrier_len > NINLIL_RRMP_OUTBOUND_CARRIER_MAX ||
        (carrier_len != 0u && carrier == NULL)) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (!o->cfg.feature_route_relay) {
        result_fill(out, NINLIL_ROUTE_FEATURE_OFF);
        return NINLIL_ROUTE_FEATURE_OFF;
    }
    st = owner_route_write_gate(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (enter(o) < 0) {
        result_fill(out, NINLIL_ROUTE_REENTRANT);
        return NINLIL_ROUTE_REENTRANT;
    }
    if (!o->downlink_tx || o->route_ns.fenced) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_DRAIN_FENCED);
        out->detail_flags = 4u;
        return NINLIL_ROUTE_DRAIN_FENCED;
    }
    ent = find_route(
        o, req->ingress_hop_context_id, req->route_handle, req->route_generation);
    if (ent == NULL || ent->state != NINLIL_RRMP_LIFE_ACTIVE) {
        leave(o);
        if (ent != NULL && ent->state == NINLIL_RRMP_LIFE_DRAINING) {
            result_fill(out, NINLIL_ROUTE_DRAIN_FENCED);
            return NINLIL_ROUTE_DRAIN_FENCED;
        }
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    /* clock epoch fence */
    if (!ninlil_rrmp_memeq(
            ent->fields.authority_clock_epoch_id.bytes,
            o->cfg.authority_clock_epoch_id,
            16u)) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_CLOCK_EPOCH_MISMATCH);
        return NINLIL_ROUTE_CLOCK_EPOCH_MISMATCH;
    }
    /* controller term / generation stale */
    if (ent->fields.controller_term < o->cfg.controller_term) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_STALE_GENERATION);
        return NINLIL_ROUTE_STALE_GENERATION;
    }
    if (req->hop_remaining == 0u ||
        req->hop_remaining > ent->fields.max_hops ||
        req->hop_remaining > o->cfg.max_hops_profile ||
        req->hop_remaining > NINLIL_RRMP_MAX_HOPS_ABSOLUTE) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_HOP_EXHAUSTED);
        return NINLIL_ROUTE_HOP_EXHAUSTED;
    }
    /* drain airtime gate when FRAG fields present (remaining_attempts must >0) */
    if (req->remaining_link_groups != 0u) {
        uint8_t elig = 0u;
        if (req->remaining_attempts == 0u) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_RESOURCE);
            return NINLIL_ROUTE_RESOURCE;
        }
        if (!ninlil_rrmp_drain_evaluate_v1(
                req->admission_now_ms,
                req->remaining_link_groups,
                req->remaining_attempts,
                req->max_airtime_ms,
                req->turnaround_ms,
                req->link_ack_wait_ms,
                req->inter_group_gap_ms,
                req->scheduler_guard_ms,
                req->item_deadline_ms != 0u ? req->item_deadline_ms
                                            : UINT64_MAX,
                UINT64_MAX,
                ent->fields.lease_expiry_ms != 0u ? ent->fields.lease_expiry_ms
                                                  : UINT64_MAX,
                &elig) ||
            !elig) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_RESOURCE);
            return NINLIL_ROUTE_RESOURCE;
        }
    }
    if (req->hop_remaining == 1u) {
        if (ent->fields.terminal_flag == 0u ||
            ent->fields.egress_route_handle != 0u ||
            ent->fields.egress_route_generation != 0u) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_TERMINAL_MISMATCH);
            return NINLIL_ROUTE_TERMINAL_MISMATCH;
        }
        hop_out = 0u;
    } else {
        if (ent->fields.terminal_flag != 0u) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_TERMINAL_MISMATCH);
            return NINLIL_ROUTE_TERMINAL_MISMATCH;
        }
        hop_out = (uint8_t)(req->hop_remaining - 1u);
    }
    /* self-forward LOOP */
    if (ninlil_rrmp_memeq(
            ent->fields.egress_peer_id.bytes, o->cfg.local_runtime_id, 16u)) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_LOOP);
        return NINLIL_ROUTE_LOOP;
    }
    ninlil_rrmp_loop_key(
        req->e2e_header_digest32,
        req->route_handle,
        req->route_generation,
        o->cfg.local_runtime_id,
        &loop_k);
    ninlil_rrmp_dedup_key(
        req->e2e_header_digest32,
        req->ingress_hop_context_id,
        req->route_handle,
        req->route_generation,
        &dedup_k);
    /*
     * The same ingress tuple is a replay, including after cold recovery.
     * Check its narrower key before the local-runtime loop key so a retained
     * custody record is never misreported as a topology loop.
     */
    if (ring_has16(&o->dedup_ring, dedup_k.bytes)) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_REPLAY);
        return NINLIL_ROUTE_REPLAY;
    }
    if (ring_has16(&o->loop_ring, loop_k.bytes)) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_LOOP);
        return NINLIL_ROUTE_LOOP;
    }
    ninlil_rrmp_evidence_key(
        req->e2e_header_digest32,
        req->route_handle,
        req->route_generation,
        ent->next_admission_seq,
        &evi_k);
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (o->evidence[i].used &&
            ninlil_rrmp_memeq(o->evidence[i].key.bytes, evi_k.bytes, 32u)) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_REPLAY);
            return NINLIL_ROUTE_REPLAY;
        }
        /* restart-safe: same e2e while LIVE/COMPLETED */
        if (o->evidence[i].used) {
            ninlil_rrmp_nev1_fields_t ef;
            if (ninlil_rrmp_decode_nev1(o->evidence[i].raw, &ef) &&
                ninlil_rrmp_memeq(
                    ef.e2e_header_digest.bytes, req->e2e_header_digest32, 32u) &&
                ef.route_handle == req->route_handle &&
                ef.route_generation == req->route_generation) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_REPLAY);
                return NINLIL_ROUTE_REPLAY;
            }
        }
    }
    /* Lease expiry → durable EXPIRED (boundary inclusive) */
    if (ent->fields.lease_expiry_ms != 0u &&
        req->admission_now_ms >= ent->fields.lease_expiry_ms) {
        ent->state = NINLIL_RRMP_LIFE_EXPIRED;
        if (!persist_route_page(
                o,
                (uint16_t)((size_t)(ent - o->routes) /
                    NINLIL_RRMP_SLOTS_PER_PAGE)) ||
            !finish_writepoint_full(o)) {
            ent->state = NINLIL_RRMP_LIFE_ACTIVE;
            leave(o);
            result_fill(out, writepoint_fail_route_status(o));
            return out->status;
        }
        leave(o);
        result_fill(out, NINLIL_ROUTE_LEASE_EXPIRED);
        return NINLIL_ROUTE_LEASE_EXPIRED;
    }
    /* Queue capacity + byte quota BEFORE durable LIVE */
    prio = req->priority_class;
    {
        uint32_t free_e = NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES - o->q_entries;
        uint32_t need_b =
            NINLIL_RRMP_EXACT_BODY_BYTES + (uint32_t)carrier_len;
        int is_ctrl =
            (prio == NINLIL_RRMP_PRIO_CONTROL || prio == NINLIL_RRMP_PRIO_SAFETY);
        if (!is_ctrl && free_e <= NINLIL_RRMP_RESERVED_CONTROL_ENTRIES) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_BACKPRESSURE);
            return NINLIL_ROUTE_BACKPRESSURE;
        }
        if (o->q_entries >= NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_BACKPRESSURE);
            return NINLIL_ROUTE_BACKPRESSURE;
        }
        if (need_b > NINLIL_RRMP_QUEUE_GLOBAL_BYTES - o->q_bytes ||
            (uint32_t)o->carrier_arena_used + (uint32_t)carrier_len >
                NINLIL_RRMP_QUEUE_GLOBAL_BYTES) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_BACKPRESSURE);
            return NINLIL_ROUTE_BACKPRESSURE;
        }
        if (ent->fields.queue_quota_entries != 0u) {
            uint32_t rq = 0u;
            uint32_t rb = 0u;
            size_t qi;
            for (qi = 0u; qi < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++qi) {
                if (o->queue[qi].used && o->queue[qi].handle == req->route_handle &&
                    o->queue[qi].gen == req->route_generation) {
                    ++rq;
                    rb += (uint32_t)o->queue[qi].e2e_body_len +
                        (uint32_t)o->queue[qi].carrier_len;
                }
            }
            if (rq >= ent->fields.queue_quota_entries) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_BACKPRESSURE);
                return NINLIL_ROUTE_BACKPRESSURE;
            }
            if (ent->fields.queue_quota_bytes != 0u &&
                (need_b > ent->fields.queue_quota_bytes ||
                    rb > ent->fields.queue_quota_bytes - need_b)) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_BACKPRESSURE);
                return NINLIL_ROUTE_BACKPRESSURE;
            }
        }
    }
    if (evidence_occupied(o) >= NINLIL_RRMP_EVIDENCE_CAPACITY) {
        reclaim_completed(o);
    }
    if (evidence_occupied(o) >= NINLIL_RRMP_EVIDENCE_CAPACITY) {
        leave(o);
        result_fill(out, NINLIL_ROUTE_RESOURCE);
        return NINLIL_ROUTE_RESOURCE;
    }
    /*
     * Multi-parent owner_scope authority BEFORE LIVE FULL (P0):
     * derive + exist + seal. Fail-closed with zero durable LIVE orphan.
     */
    {
        uint8_t derived_scope[16];
        uint8_t scope_set = 0u;
        uint8_t selected_parent[16];
        uint8_t select_parent = 0u;
        rrmp_scope_t *scope_rec = NULL;
        uint8_t old_attempt_id[16];
        uint8_t old_selected_parent[16];
        uint8_t old_attempt_selected = 0u;
        uint64_t oh;
        uint64_t old_next_seq;
        uint64_t old_next_handle;
        uint64_t old_lifetime;
        uint8_t exact[NINLIL_RRMP_EXACT_BODY_BYTES];
        uint16_t page;
        uint16_t route_page;
        int qok = 0;
        int attempt_already_live = 0;
        int attempt_inserted = 0;
        uint16_t attempt_at = 0u;
        size_t qi = 0u;
        rrmp_q_t *qslot = NULL;

        ninlil_rrmp_memzero(selected_parent, sizeof(selected_parent));
        ninlil_rrmp_memzero(old_attempt_id, sizeof(old_attempt_id));
        ninlil_rrmp_memzero(old_selected_parent, sizeof(old_selected_parent));

        if (o->cfg.feature_multi_parent) {
            if (!o->scope_derivation_set ||
                !ninlil_rrmp_derive_owner_scope_id(
                    o->scope_derivation.endpoint_runtime_id,
                    o->scope_derivation.direction,
                    o->scope_derivation.namespace,
                    o->scope_derivation.namespace_len,
                    o->scope_derivation.service,
                    o->scope_derivation.service_len,
                    o->scope_derivation.traffic_class,
                    ent->fields.path_policy_id.bytes,
                    derived_scope)) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_DRAIN_FENCED);
                return NINLIL_ROUTE_DRAIN_FENCED;
            }
            scope_rec = find_scope(o, derived_scope);
            if (scope_rec == NULL ||
                !ninlil_rrmp_core_scope_seal_allowed(o, derived_scope)) {
                leave(o);
                result_fill(out, NINLIL_ROUTE_DRAIN_FENCED);
                return NINLIL_ROUTE_DRAIN_FENCED;
            }
            scope_set = 1u;
            if (attempt_id16 != NULL) {
                size_t az = 0u;
                uint8_t avail[NINLIL_RRMP_PARENT_MAX];
                uint8_t nac = 0u;
                uint8_t pi;
                uint16_t ordinal;
                uint16_t want;
                for (i = 0u; i < 16u; ++i) {
                    az |= attempt_id16[i];
                }
                if (az == 0u) {
                    leave(o);
                    result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
                    return NINLIL_ROUTE_AUTHORITY_CONFLICT;
                }
                if (attempt_find_index(
                        o, derived_scope, attempt_id16, &attempt_at)) {
                    if (o->attempts[attempt_at].lifecycle !=
                            NINLIL_RRMP_ATTEMPT_LIVE ||
                        !scope_rec->attempt_selected ||
                        !ninlil_rrmp_memeq(
                            scope_rec->last_attempt_id16,
                            attempt_id16,
                            16u)) {
                        leave(o);
                        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
                        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
                    }
                    attempt_already_live = 1;
                } else if (
                    o->attempt_count >=
                        NINLIL_RRMP_QST4_ATTEMPT_CAPACITY) {
                    leave(o);
                    result_fill(out, NINLIL_ROUTE_RESOURCE);
                    return NINLIL_ROUTE_RESOURCE;
                }
                if (scope_rec->lease_not_after_ms != 0u &&
                    o->cfg.now_ms >= scope_rec->lease_not_after_ms) {
                    leave(o);
                    result_fill(out, NINLIL_ROUTE_LEASE_EXPIRED);
                    return NINLIL_ROUTE_LEASE_EXPIRED;
                }
                ordinal = ninlil_rrmp_get_u16_be(attempt_id16 + 14u);
                if (ordinal == 0u) {
                    leave(o);
                    result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
                    return NINLIL_ROUTE_INVALID_ARGUMENT;
                }
                for (pi = 0u; pi < scope_rec->parent_count; ++pi) {
                    if (!scope_rec->parent_lost[pi]) {
                        avail[nac++] = pi;
                    }
                }
                want = (uint16_t)(ordinal - 1u);
                if (nac == 0u || want >= nac) {
                    leave(o);
                    result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
                    return NINLIL_ROUTE_NOT_ACTIVE;
                }
                memcpy(
                    selected_parent,
                    scope_rec->parent_ids[avail[(uint8_t)want]], 16u);
                select_parent = 1u;
            }
        }

        if (ent->next_admission_seq == 0u ||
            ent->next_admission_seq >= UINT64_MAX - 1u ||
            o->next_handle_token == 0u ||
            o->next_handle_token >= UINT64_MAX - 1u) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_RESOURCE);
            return NINLIL_ROUTE_RESOURCE;
        }

        for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
            if (!o->evidence[i].used) {
                slot = &o->evidence[i];
                break;
            }
        }
        if (slot == NULL) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_RESOURCE);
            return NINLIL_ROUTE_RESOURCE;
        }
        for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
            if (!o->queue[i].used) {
                qslot = &o->queue[i];
                qi = i;
                break;
            }
        }
        if (qslot == NULL) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_BACKPRESSURE);
            return NINLIL_ROUTE_BACKPRESSURE;
        }
        ninlil_rrmp_memzero(&evi, sizeof(evi));
        evi.route_handle = req->route_handle;
        evi.route_generation = req->route_generation;
        evi.admission_seq = ent->next_admission_seq;
        memcpy(evi.e2e_header_digest.bytes, req->e2e_header_digest32, 32u);
        evi.outer_rx_counter = req->outer_rx_counter;
        memcpy(evi.local_runtime_id.bytes, o->cfg.local_runtime_id, 16u);
        evi.hop_remaining_in = req->hop_remaining;
        evi.hop_remaining_out = hop_out;
        evi.lifecycle = NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE;
        evi.result_status = NINLIL_ROUTE_OK;
        if (!ninlil_rrmp_encode_nev1(&evi, slot->raw)) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_CORRUPT);
            return NINLIL_ROUTE_CORRUPT;
        }
        /* LIVE evidence, queue, carrier and attempt selection form one FULL snapshot. */
        oh = o->next_handle_token;
        if (!ninlil_rrmp_materialize_exact(&ent->fields, exact)) {
            leave(o);
            result_fill(out, NINLIL_ROUTE_CORRUPT);
            return NINLIL_ROUTE_CORRUPT;
        }
        slot->used = 1u;
        slot->key = evi_k;
        slot->opaque_handle = oh;
        slot->auth_link_ack = 0u;
        slot->outer_tx_counter = 0u;
        ninlil_rrmp_memzero(slot->auth_peer_runtime_id, 16u);
        page = (uint16_t)((size_t)(slot - o->evidence) / NINLIL_RRMP_NEP1_SLOTS);
        ninlil_rrmp_memzero(qslot, sizeof(*qslot));
        qslot->used = 1u;
        qslot->prio = prio;
        qslot->handle = req->route_handle;
        qslot->gen = req->route_generation;
        qslot->ingress_hop_context_id = req->ingress_hop_context_id;
        qslot->admission_seq = evi.admission_seq;
        qslot->token = req->caller_item_token;
        qslot->opaque_handle = oh;
        qslot->route_revision = ent->fields.route_revision;
        qslot->absolute_deadline_ms =
            req->item_deadline_ms != 0u ? req->item_deadline_ms
                                       : ent->fields.lease_expiry_ms;
        qslot->remaining_link_groups = req->remaining_link_groups;
        qslot->remaining_attempts = req->remaining_attempts;
        qslot->hop_in = req->hop_remaining;
        qslot->hop_out = hop_out;
        qslot->terminal = ent->fields.terminal_flag;
        qslot->outer_rx_counter = req->outer_rx_counter;
        qslot->outer_tx_counter = 0u;
        qslot->owner_scope_set = scope_set;
        qslot->retry_limit =
            req->remaining_attempts != 0u
                ? req->remaining_attempts
                : NINLIL_RRMP_MAX_ATTEMPTS;
        qslot->link_ack_wait_ms =
            req->link_ack_wait_ms != 0u
                ? req->link_ack_wait_ms
                : NINLIL_RRMP_ACK_TIMEOUT_DEFAULT_MS;
        if (scope_set) {
            memcpy(qslot->owner_scope_id, derived_scope, 16u);
        }
        if (attempt_id16 != NULL) {
            memcpy(qslot->attempt_id16, attempt_id16, 16u);
        }
        if (select_parent) {
            memcpy(qslot->selected_parent_id, selected_parent, 16u);
            qslot->selected_parent_set = 1u;
            memcpy(qslot->expected_peer_id, selected_parent, 16u);
        } else {
            memcpy(
                qslot->expected_peer_id, ent->fields.egress_peer_id.bytes, 16u);
        }
        if (o->auth_active) {
            memcpy(qslot->caller_principal_id, o->auth_principal_id, 16u);
        }
        memcpy(qslot->e2e_digest, req->e2e_header_digest32, 32u);
        memcpy(qslot->e2e_body, exact, NINLIL_RRMP_EXACT_BODY_BYTES);
        qslot->e2e_body_len = (uint16_t)NINLIL_RRMP_EXACT_BODY_BYTES;
        qslot->payload_len = (uint16_t)NINLIL_RRMP_EXACT_BODY_BYTES;
        if (!carrier_arena_append(
                o, carrier, carrier_len, &qslot->carrier_offset)) {
            ninlil_rrmp_memzero(qslot, sizeof(*qslot));
            ninlil_rrmp_memzero(slot, sizeof(*slot));
            leave(o);
            result_fill(out, NINLIL_ROUTE_RESOURCE);
            return NINLIL_ROUTE_RESOURCE;
        }
        qslot->carrier_len = carrier_len;
        o->q_entries += 1u;
        o->q_bytes += NINLIL_RRMP_EXACT_BODY_BYTES + carrier_len;
        if (prio == NINLIL_RRMP_PRIO_CONTROL ||
            prio == NINLIL_RRMP_PRIO_SAFETY) {
            o->q_control_entries += 1u;
        }
        qok = 1;
        old_next_seq = ent->next_admission_seq;
        old_next_handle = o->next_handle_token;
        old_lifetime = o->lifetime_admits;
        ent->next_admission_seq += 1u;
        o->next_handle_token = oh + 1u;
        o->lifetime_admits += 1u;
        if (select_parent && scope_rec != NULL) {
            if (!attempt_already_live &&
                !attempt_insert_live(
                    o, derived_scope, attempt_id16, &attempt_at)) {
                queue_release(o, qslot);
                ninlil_rrmp_memzero(slot, sizeof(*slot));
                ent->next_admission_seq = old_next_seq;
                o->next_handle_token = old_next_handle;
                o->lifetime_admits = old_lifetime;
                leave(o);
                result_fill(out, NINLIL_ROUTE_RESOURCE);
                return NINLIL_ROUTE_RESOURCE;
            }
            attempt_inserted = !attempt_already_live;
            memcpy(old_attempt_id, scope_rec->last_attempt_id16, 16u);
            memcpy(old_selected_parent, scope_rec->selected_parent, 16u);
            old_attempt_selected = scope_rec->attempt_selected;
            memcpy(scope_rec->last_attempt_id16, attempt_id16, 16u);
            memcpy(scope_rec->selected_parent, selected_parent, 16u);
            scope_rec->attempt_selected = 1u;
        }
        route_page = (uint16_t)(
            (size_t)(ent - o->routes) / NINLIL_RRMP_SLOTS_PER_PAGE);
        if (!persist_evidence_page(o, page) ||
            !persist_route_page(o, route_page) ||
            !finish_writepoint_full(o)) {
            if (!writepoint_restored_exact_durable_old(o)) {
                if (qok) {
                    queue_release(o, qslot);
                }
                ninlil_rrmp_memzero(slot, sizeof(*slot));
                ent->next_admission_seq = old_next_seq;
                o->next_handle_token = old_next_handle;
                o->lifetime_admits = old_lifetime;
                if (select_parent && scope_rec != NULL) {
                    if (attempt_inserted) {
                        attempt_remove_at(o, attempt_at);
                    }
                    memcpy(
                        scope_rec->last_attempt_id16,
                        old_attempt_id,
                        16u);
                    memcpy(
                        scope_rec->selected_parent,
                        old_selected_parent,
                        16u);
                    scope_rec->attempt_selected = old_attempt_selected;
                }
                o->route_ns.fenced = 1u;
                o->downlink_tx = 0u;
            }
            leave(o);
            result_fill(out, writepoint_fail_route_status(o));
            return out->status;
        }
        (void)qi;
        ring_push16(&o->loop_ring, loop_k.bytes);
        ring_push16(&o->dedup_ring, dedup_k.bytes);
        o->diag_admits += 1u;
        leave(o);
        result_fill(out, NINLIL_ROUTE_OK);
        out->opaque_local_handle = oh;
        out->hop_remaining_out = hop_out;
        out->next_admission_seq = evi.admission_seq;
        out->route_handle = req->route_handle;
        out->route_generation = req->route_generation;
        out->ingress_hop_context_id = req->ingress_hop_context_id;
        out->lifecycle_state = NINLIL_RRMP_LIFE_ACTIVE;
        memcpy(out->evidence_or_digest32, evi_k.bytes, 32u);
        return NINLIL_ROUTE_OK;
    }
}

ninlil_route_status_u32 ninlil_route_forward_admit(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_admit_req_v1_t *req,
    ninlil_route_result_v1_t *out)
{
    return route_forward_admit_impl(owner, req, NULL, 0u, NULL, out);
}

ninlil_route_status_u32 ninlil_rrmp_core_forward_admit_with_carrier(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_admit_req_v1_t *req,
    const uint8_t *carrier,
    uint16_t carrier_len,
    const uint8_t attempt_id16[16],
    ninlil_route_result_v1_t *out)
{
    return route_forward_admit_impl(
        owner, req, carrier, carrier_len, attempt_id16, out);
}

ninlil_route_status_u32 ninlil_route_forward_complete(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_complete_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    size_t i;
    rrmp_q_t *q = NULL;
    int found = 0;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 64u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_route_relay) {
        result_fill(out, !owner_serial_active(o) ? NINLIL_ROUTE_INVALID_ARGUMENT
                                  : NINLIL_ROUTE_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_FORWARD)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_write_gate(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (req->opaque_local_handle == 0u ||
        req->outcome < 1u || req->outcome > 4u ||
        req->preamble.reserved0 != 0u || req->preamble.reserved1 != 0u) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    /* Ownership: exact opaque handle must match a queue attempt (or completed TX). */
    for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
        if (o->queue[i].used &&
            o->queue[i].opaque_handle == req->opaque_local_handle) {
            q = &o->queue[i];
            break;
        }
    }
    /* Exact attempt ownership: evidence.opaque_handle must match. */
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (!o->evidence[i].used ||
            o->evidence[i].opaque_handle != req->opaque_local_handle) {
            continue;
        }
        {
            ninlil_rrmp_nev1_fields_t ef;
            uint16_t attempt_at = 0u;
            rrmp_attempt_row_t *attempt_row = NULL;
            if (!ninlil_rrmp_decode_nev1(o->evidence[i].raw, &ef) ||
                ef.lifecycle != NINLIL_RRMP_EVIDENCE_LIFECYCLE_LIVE) {
                continue;
            }
            if (!ninlil_rrmp_memeq(
                    ef.local_runtime_id.bytes, o->cfg.local_runtime_id, 16u)) {
                continue;
            }
            if (q != NULL) {
                if (ef.route_handle != q->handle ||
                    ef.route_generation != q->gen ||
                    ef.admission_seq != q->admission_seq ||
                    !ninlil_rrmp_memeq(
                        ef.e2e_header_digest.bytes, q->e2e_digest, 32u)) {
                    continue;
                }
            }
            /*
             * Successful completion needs durable authenticated LINK_ACK.
             * A terminal negative result is admitted only after the bounded
             * retry worker has durably exhausted/expired this exact queue.
             */
            if ((req->outcome == 1u && !o->evidence[i].auth_link_ack) ||
                (req->outcome != 1u &&
                    (q == NULL || !q->retry_exhausted))) {
                result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
                return NINLIL_ROUTE_AUTHORITY_CONFLICT;
            }
            ef.lifecycle = NINLIL_RRMP_EVIDENCE_LIFECYCLE_COMPLETED;
            if (req->outcome == 1u) {
                ef.result_status = NINLIL_ROUTE_OK;
            } else if (req->outcome == 2u) {
                ef.result_status = NINLIL_ROUTE_RESOURCE;
            } else if (req->outcome == 3u) {
                ef.result_status = NINLIL_ROUTE_NOT_ACTIVE;
            } else {
                ef.result_status = NINLIL_ROUTE_LEASE_EXPIRED;
            }
            if (!ninlil_rrmp_encode_nev1(&ef, o->evidence[i].raw)) {
                result_fill(out, NINLIL_ROUTE_CORRUPT);
                return NINLIL_ROUTE_CORRUPT;
            }
            if (q != NULL && q->owner_scope_set &&
                bytes_have_nonzero(q->attempt_id16, 16u)) {
                if (!attempt_find_index(
                        o,
                        q->owner_scope_id,
                        q->attempt_id16,
                        &attempt_at) ||
                    o->attempts[attempt_at].lifecycle !=
                        NINLIL_RRMP_ATTEMPT_LIVE ||
                    req->completion_now_ms >
                        UINT64_MAX - NINLIL_RRMP_ATTEMPT_RETENTION_MS) {
                    result_fill(out, NINLIL_ROUTE_CORRUPT);
                    return NINLIL_ROUTE_CORRUPT;
                }
                attempt_row = &o->attempts[attempt_at];
                attempt_row->lifecycle =
                    NINLIL_RRMP_ATTEMPT_TERMINAL_RETAINED;
                attempt_row->flags = NINLIL_RRMP_ATTEMPT_FLAG_NEV1;
                ninlil_rrmp_sha256(
                    o->evidence[i].raw,
                    NINLIL_RRMP_NEV1_BYTES,
                    attempt_row->terminal_evidence_digest32);
                attempt_row->reclaim_not_before_ms =
                    req->completion_now_ms +
                    NINLIL_RRMP_ATTEMPT_RETENTION_MS;
            }
            /*
             * Remove any exhausted queue before the single external FULL
             * snapshot. ACK-success queues were already released by LINK_ACK.
             */
            if (q != NULL) {
                queue_release(o, q);
                q = NULL;
            }
            if (!persist_evidence_page(
                    o, (uint16_t)(i / NINLIL_RRMP_NEP1_SLOTS)) ||
                !finish_writepoint_full(o)) {
                o->route_ns.fenced = 1u;
                o->downlink_tx = 0u;
                result_fill(out, writepoint_fail_route_status(o));
                return out->status;
            }
            found = 1;
            break;
        }
    }
    if (!found) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_route_cancel_drain(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_cancel_drain_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    rrmp_route_t *ent;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 48u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_route_relay) {
        result_fill(out, !owner_serial_active(o) ? NINLIL_ROUTE_INVALID_ARGUMENT
                                  : NINLIL_ROUTE_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_ROUTE_ADMIN)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_write_gate(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    ent = find_route(
        o, req->ingress_hop_context_id, req->route_handle, req->route_generation);
    if (ent == NULL || ent->state != NINLIL_RRMP_LIFE_DRAINING) {
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (req->expected_drain_fence != 0u &&
        req->expected_drain_fence != ent->drain.drain_fence) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    ent->state = NINLIL_RRMP_LIFE_ACTIVE;
    if (!persist_route_page(
            o, (uint16_t)((size_t)(ent - o->routes) /
                NINLIL_RRMP_SLOTS_PER_PAGE)) ||
        !finish_writepoint_full(o)) {
        ent->state = NINLIL_RRMP_LIFE_DRAINING;
        result_fill(out, writepoint_fail_route_status(o));
        return out->status;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->lifecycle_state = NINLIL_RRMP_LIFE_ACTIVE;
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_route_recover_commit_unknown(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_recover_cu_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    uint32_t cu;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 80u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_route_relay) {
        result_fill(out, !owner_serial_active(o) ? NINLIL_ROUTE_INVALID_ARGUMENT
                                  : NINLIL_ROUTE_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_ROUTE_ADMIN)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (owner_storage_hard_fenced(o) &&
        !ninlil_rrmp_owner_storage_recover(o)) {
        st = o->storage_last_outcome == RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN
            ? NINLIL_ROUTE_COMMIT_UNKNOWN
            : NINLIL_ROUTE_CORRUPT;
        result_fill(out, st);
        out->cu_class = (uint8_t)o->route_ns.cu_class;
        return st;
    }
    /* Preserve an exact outer OLD/NEW witness classification after recovery. */
    if (o->route_ns.cu_class == NINLIL_RRMP_CU_OLD ||
        o->route_ns.cu_class == NINLIL_RRMP_CU_NEW ||
        o->route_ns.cu_class == NINLIL_RRMP_CU_PARTIAL ||
        o->route_ns.cu_class == NINLIL_RRMP_CU_EXTRA ||
        o->route_ns.cu_class == NINLIL_RRMP_CU_THIRD ||
        o->route_ns.corrupt || o->route_ns.fenced) {
        cu = o->route_ns.cu_class;
        if (o->route_ns.corrupt &&
            (cu == NINLIL_RRMP_CU_NONE || cu == NINLIL_RRMP_CU_ABSENT ||
                cu == NINLIL_RRMP_CU_NEW)) {
            cu = NINLIL_RRMP_CU_PARTIAL;
        }
        if (o->route_ns.fenced &&
            (cu == NINLIL_RRMP_CU_NONE || cu == NINLIL_RRMP_CU_ABSENT)) {
            cu = NINLIL_RRMP_CU_PARTIAL;
        }
    } else {
        cu = ninlil_rrmp_route_classify_cu(&o->route_ns);
        o->route_ns.cu_class = cu;
    }
    /*
     * Fail-closed corrupt/third/extra: fence owner first, then fill out once
     * as CORRUPT (never leave intermediate OK / non-zero lifecycle on out).
     */
    if (cu == NINLIL_RRMP_CU_PARTIAL || cu == NINLIL_RRMP_CU_EXTRA ||
        cu == NINLIL_RRMP_CU_THIRD || o->route_ns.corrupt) {
        o->downlink_tx = 0u;
        o->route_ns.fenced = 1u;
        o->route_ns.cu_class = cu;
        result_fill(out, NINLIL_ROUTE_CORRUPT);
        out->cu_class = (uint8_t)cu;
        out->detail_flags = 5u; /* bit0 recover probe + bit2 fenced */
        out->lifecycle_state = 0u;
        out->opaque_local_handle = 0u;
        return NINLIL_ROUTE_CORRUPT;
    }
    if (cu == NINLIL_RRMP_CU_OLD) {
        result_fill(out, NINLIL_ROUTE_COMMIT_UNKNOWN);
        out->cu_class = (uint8_t)cu;
        out->lifecycle_state = 0u;
        out->opaque_local_handle = 0u;
        return NINLIL_ROUTE_COMMIT_UNKNOWN;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->cu_class = (uint8_t)cu;
    out->detail_flags = 1u;
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_route_diagnostics_snapshot(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_diagnostics_req_v1_t *req, ninlil_route_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    if (req == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    st = preamble_route(&req->preamble, 32u, (const uint8_t *)req, flags);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_route_relay) {
        result_fill(out, !owner_serial_active(o) ? NINLIL_ROUTE_INVALID_ARGUMENT
                                  : NINLIL_ROUTE_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_DIAGNOSTICS)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    st = owner_route_fence_status(o);
    if (st != NINLIL_ROUTE_OK) {
        result_fill(out, st);
        out->cu_class = (uint8_t)o->route_ns.cu_class;
        return st;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->next_admission_seq = o->lifetime_admits;
    out->cu_class = (uint8_t)o->route_ns.cu_class;
    out->opaque_local_handle = o->diag_admits;
    return NINLIL_ROUTE_OK;
}

/* Production forward service: fair dequeue order (prio, deadline, seq, handle). */
ninlil_route_status_u32 ninlil_rrmp_core_forward_service_once(
    ninlil_rrmp_owner_t *owner, ninlil_route_result_v1_t *out)
{
    size_t i;
    size_t best = NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES;
    if (owner == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (!owner_has_capability(
            owner, NINLIL_RRMP_AUTH_WORKER | NINLIL_RRMP_AUTH_FORWARD)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_route_write_gate(owner);
        if (gst != NINLIL_ROUTE_OK) {
            result_fill(out, gst);
            return gst;
        }
    }
    if (!owner->downlink_tx) {
        result_fill(out, NINLIL_ROUTE_DRAIN_FENCED);
        return NINLIL_ROUTE_DRAIN_FENCED;
    }
    for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
        rrmp_q_t *q;
        if (!owner->queue[i].used || owner->queue[i].tx_done) {
            continue;
        }
        q = &owner->queue[i];
        /* BULK starvation bound: after 8 bulk peeks, prefer higher class if any. */
        if (owner->bulk_streak >= 8u && q->prio == NINLIL_RRMP_PRIO_BULK) {
            size_t j;
            int higher = 0;
            for (j = 0u; j < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++j) {
                if (owner->queue[j].used && !owner->queue[j].tx_done &&
                    owner->queue[j].prio < NINLIL_RRMP_PRIO_BULK) {
                    higher = 1;
                    break;
                }
            }
            if (higher) {
                continue;
            }
        }
        if (best >= NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES) {
            best = i;
            continue;
        }
        {
            rrmp_q_t *b = &owner->queue[best];
            int better = 0;
            if (q->prio < b->prio) {
                better = 1;
            } else if (q->prio == b->prio) {
                if (q->absolute_deadline_ms < b->absolute_deadline_ms) {
                    better = 1;
                } else if (q->absolute_deadline_ms == b->absolute_deadline_ms) {
                    if (q->admission_seq < b->admission_seq) {
                        better = 1;
                    } else if (q->admission_seq == b->admission_seq &&
                        q->handle < b->handle) {
                        better = 1;
                    }
                }
            }
            if (better) {
                best = i;
            }
        }
    }
    if (best >= NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES) {
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (owner->queue[best].prio == NINLIL_RRMP_PRIO_BULK) {
        owner->bulk_streak += 1u;
    } else {
        owner->bulk_streak = 0u;
    }
    owner->diag_forwards += 1u;
    if (!finish_writepoint_full(owner)) {
        result_fill(out, writepoint_fail_route_status(owner));
        return out->status;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->route_handle = owner->queue[best].handle;
    out->route_generation = owner->queue[best].gen;
    out->hop_remaining_out = owner->queue[best].hop_out;
    out->next_admission_seq = owner->queue[best].admission_seq;
    out->opaque_local_handle = owner->queue[best].opaque_handle;
    memcpy(out->evidence_or_digest32, owner->queue[best].e2e_digest, 32u);
    return NINLIL_ROUTE_OK;
}

/* --- Parent ops --- */

static int encode_scope_nps1(const rrmp_scope_t *sc, uint8_t out[NINLIL_RRMP_NPS1_BYTES])
{
    ninlil_rrmp_nps1_fields_t f;
    uint8_t i;
    if (sc == NULL || out == NULL || sc->parent_count == 0u) {
        return 0;
    }
    ninlil_rrmp_memzero(&f, sizeof(f));
    memcpy(f.owner_scope_id.bytes, sc->owner_scope_id, 16u);
    memcpy(f.parent_set_id.bytes, sc->path_policy_id, 16u);
    f.parent_set_revision = sc->path_policy_revision != 0u
        ? sc->path_policy_revision
        : sc->installed_revision;
    f.parent_count = sc->parent_count;
    for (i = 0u; i < sc->parent_count; ++i) {
        memcpy(f.parent_ids[i].bytes, sc->parent_ids[i], 16u);
    }
    memcpy(f.parent_set_digest.bytes, sc->parent_set_digest, 32u);
    if (!ninlil_rrmp_encode_nps1(&f, out)) {
        return 0;
    }
    return 1;
}

static int persist_nps1(ninlil_rrmp_owner_t *o, const rrmp_scope_t *sc)
{
    /*
     * ADR-0020 placement: hash(owner_scope_id) selects the initial page/slot,
     * then linear-probe across the complete 5×15 namespace.  Build the table
     * in lexical scope order so a FULL rewrite is deterministic and capacity
     * is the declared 75 slots, rather than an accidental 15-per-hash-bucket
     * limit.  Every page is rewritten, including empty pages, so stale slots
     * cannot survive a relocation or removal.
     */
    uint8_t page;
    uint8_t keys[NINLIL_RRMP_NPP1_PAGE_COUNT];
    uint8_t slot_owner[
        NINLIL_RRMP_NPP1_PAGE_COUNT * NINLIL_RRMP_NPP1_SLOTS];
    uint8_t scope_order[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY];
    size_t scope_count = 0u;
    size_t i;
    (void)sc;
    if (o == NULL) {
        return 0;
    }
    ninlil_rrmp_memzero(slot_owner, sizeof(slot_owner));
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (o->scopes[i].used) {
            size_t pos = scope_count;
            while (pos > 0u &&
                   memcmp(
                       o->scopes[scope_order[pos - 1u]].owner_scope_id,
                       o->scopes[i].owner_scope_id,
                       16u) > 0) {
                scope_order[pos] = scope_order[pos - 1u];
                --pos;
            }
            scope_order[pos] = (uint8_t)i;
            ++scope_count;
        }
    }
    for (i = 0u; i < scope_count; ++i) {
        uint8_t digest[32];
        size_t start;
        size_t probe;
        uint8_t owner_index = scope_order[i];
        ninlil_rrmp_sha256(
            o->scopes[owner_index].owner_scope_id, 16u, digest);
        start =
            ((size_t)(digest[0] % NINLIL_RRMP_NPP1_PAGE_COUNT) *
             NINLIL_RRMP_NPP1_SLOTS) +
            (size_t)(digest[1] % NINLIL_RRMP_NPP1_SLOTS);
        for (probe = 0u; probe < sizeof(slot_owner); ++probe) {
            size_t at = (start + probe) % sizeof(slot_owner);
            if (slot_owner[at] == 0u) {
                slot_owner[at] = (uint8_t)(owner_index + 1u);
                break;
            }
        }
        if (probe == sizeof(slot_owner)) {
            return 0;
        }
    }
    for (page = 0u; page < NINLIL_RRMP_NPP1_PAGE_COUNT; ++page) {
        uint8_t kid = (uint8_t)(NINLIL_RRMP_PKEY_NPP1_BASE + page);
        uint8_t *buf;
        size_t cap;
        uint64_t gen;
        const uint8_t *slots[NINLIL_RRMP_NPP1_SLOTS];
        size_t slot;
        ninlil_rrmp_memzero(o->enc_nps_slots, sizeof(o->enc_nps_slots));
        for (slot = 0u; slot < NINLIL_RRMP_NPP1_SLOTS; ++slot) {
            uint8_t encoded_owner = slot_owner[
                (size_t)page * NINLIL_RRMP_NPP1_SLOTS + slot];
            if (encoded_owner == 0u) {
                slots[slot] = NULL;
            } else {
                size_t owner_index = (size_t)encoded_owner - 1u;
                if (owner_index >= NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY ||
                    !o->scopes[owner_index].used ||
                    !encode_scope_nps1(
                        &o->scopes[owner_index], o->enc_nps_slots[slot])) {
                    return 0;
                }
                slots[slot] = o->enc_nps_slots[slot];
            }
        }
        if (!ninlil_rrmp_parent_dual_begin_write(
                &o->parent_ns, kid, &buf, &cap, &gen)) {
            return 0;
        }
        if (!ninlil_rrmp_encode_npp1(page, (uint32_t)gen, slots, buf)) {
            return 0;
        }
        if (!ninlil_rrmp_parent_dual_commit(
                &o->parent_ns, kid, NINLIL_RRMP_NPP1_BYTES)) {
            return 0;
        }
        keys[page] = kid;
    }
    if (!ninlil_rrmp_parent_full_commit(
            &o->parent_ns, keys, NINLIL_RRMP_NPP1_PAGE_COUNT)) {
        return 0;
    }
    return finish_writepoint_full(o);
}

/* Atomic FULL publish of NPA1 assignment page + NPT1 token page for one scope. */
static int persist_npa1_npt1_full(
    ninlil_rrmp_owner_t *o, rrmp_scope_t *sc, uint8_t npt_kind, uint64_t now_ms)
{
    uint8_t scope_order[NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY];
    uint8_t keys[
        1u + NINLIL_RRMP_NPA1_PAGE_COUNT + NINLIL_RRMP_NPT1_PAGE_COUNT];
    uint8_t *slot_scratch;
    size_t scope_count = 0u;
    size_t key_count =
        NINLIL_RRMP_NPA1_PAGE_COUNT + NINLIL_RRMP_NPT1_PAGE_COUNT;
    size_t i;
    uint8_t page;
    uint16_t ledger_count = 0u;
    uint8_t token_matches = 0u;
    uint8_t existing_kind = 0u;
    uint64_t token_created_ms = 0u;
    uint8_t append_token = 0u;
    if (o == NULL || sc == NULL) {
        return 0;
    }
    if (!npt_ledger_summary(
            o,
            sc->token_dig,
            &ledger_count,
            &token_matches,
            &existing_kind,
            &token_created_ms)) {
        return 0;
    }
    if (token_matches == 0u) {
        if (npt_kind != NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE ||
            ledger_count >= NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY ||
            now_ms == 0u || now_ms == UINT64_MAX) {
            return 0;
        }
        append_token = 1u;
        token_created_ms = now_ms;
    } else if (existing_kind == NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED &&
        npt_kind == NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE) {
        /* A used digest can never be resurrected, even for another scope. */
        return 0;
    }
    /*
     * Canonical relocation order is lexical owner_scope_id. Rebuild all
     * assignment/token pages so an update never erases a colliding scope and
     * stale imported slots cannot survive.
     */
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        if (o->scopes[i].used && o->scopes[i].noa1_present) {
            size_t pos = scope_count;
            while (pos > 0u &&
                   memcmp(
                       o->scopes[scope_order[pos - 1u]].owner_scope_id,
                       o->scopes[i].owner_scope_id,
                       16u) > 0) {
                scope_order[pos] = scope_order[pos - 1u];
                --pos;
            }
            scope_order[pos] = (uint8_t)i;
            ++scope_count;
        }
    }
    if (scope_count > NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY) {
        return 0;
    }
    slot_scratch = (uint8_t *)o->enc_nps_slots;
    for (page = 0u; page < NINLIL_RRMP_NPA1_PAGE_COUNT; ++page) {
        const uint8_t *aslots[NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE];
        uint8_t *buf;
        size_t cap;
        uint64_t gen;
        size_t slot;
        ninlil_rrmp_memzero(
            slot_scratch,
            NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE *
                NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES);
        for (slot = 0u; slot < NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE; ++slot) {
            size_t ordinal =
                (size_t)page * NINLIL_RRMP_ASSIGNMENT_SLOTS_PER_PAGE + slot;
            if (ordinal < scope_count) {
                rrmp_scope_t *item = &o->scopes[scope_order[ordinal]];
                uint8_t *encoded =
                    slot_scratch + slot * NINLIL_RRMP_ASSIGNMENT_SLOT_BYTES;
                const uint8_t *proof = item->proof ? item->proof_dig : NULL;
                /*
                 * AUTHORITY_COMMITTED (S3) already owns the CAS commit digest.
                 * Persist it even before S4 receipt verification so a cold
                 * restart can validate and accept the same receipt exactly
                 * once. Handoff state distinguishes CAS-only (S3) from
                 * receipt-verified (S4+).
                 */
                const uint8_t *receipt =
                    (item->cas || item->receipt) ? item->commit_dig : NULL;
                if (!ninlil_rrmp_validate_noa1(item->noa1_raw) ||
                    !ninlil_rrmp_encode_assignment_slot(
                        item->noa1_raw,
                        item->handoff,
                        proof,
                        receipt,
                        encoded)) {
                    return 0;
                }
                aslots[slot] = encoded;
            } else {
                aslots[slot] = NULL;
            }
        }
        keys[page] = (uint8_t)(NINLIL_RRMP_PKEY_NPA1_BASE + page);
        if (!ninlil_rrmp_parent_dual_begin_write(
                &o->parent_ns, keys[page], &buf, &cap, &gen) ||
            gen == 0u || gen >= UINT32_MAX ||
            !ninlil_rrmp_encode_npa1_page(
                page, (uint32_t)gen, aslots, buf) ||
            !ninlil_rrmp_validate_npa1(buf) ||
            !ninlil_rrmp_parent_dual_commit(
                &o->parent_ns, keys[page], NINLIL_RRMP_NPA1_BYTES)) {
            return 0;
        }
    }
    /*
     * Preserve the namespace-global replay ledger.  Current assignments
     * reference entries but do not own them: an old TOMBSTONE_USED remains
     * after the same scope starts a later handoff.  New tokens append to the
     * packed prefix; no implicit FIFO/LRU eviction exists.
     */
    for (page = 0u; page < NINLIL_RRMP_NPT1_PAGE_COUNT; ++page) {
        const uint8_t *old_page = NULL;
        uint32_t old_len = 0u;
        uint64_t old_gen = 0u;
        uint32_t old_count = 0u;
        uint8_t *buf;
        uint8_t *token_scratch = o->enc_page_a;
        size_t cap;
        uint64_t gen;
        uint32_t count;
        size_t slot;
        uint8_t kid =
            (uint8_t)(NINLIL_RRMP_PKEY_NPT1_BASE + page);
        if (ninlil_rrmp_parent_dual_read_active(
                &o->parent_ns,
                kid,
                &old_page,
                &old_len,
                &old_gen)) {
            if (old_page == NULL || old_len != NINLIL_RRMP_NPT1_BYTES ||
                old_gen == 0u || old_gen >= UINT32_MAX ||
                !ninlil_rrmp_validate_npt1(old_page) ||
                ninlil_rrmp_get_u16_be(old_page + 6u) != page ||
                ninlil_rrmp_get_u32_be(old_page + 8u) !=
                    (uint32_t)old_gen) {
                return 0;
            }
            old_count = ninlil_rrmp_get_u32_be(old_page + 12u);
        }
        ninlil_rrmp_memzero(
            token_scratch,
            NINLIL_RRMP_NPT1_SLOTS_PER_PAGE *
                NINLIL_RRMP_NPT1_SLOT_BYTES);
        if (old_count != 0u) {
            memcpy(
                token_scratch,
                old_page + NINLIL_RRMP_NPT1_HEADER_BYTES,
                (size_t)old_count * NINLIL_RRMP_NPT1_SLOT_BYTES);
        }
        count = old_count;
        for (slot = 0u; slot < old_count; ++slot) {
            uint8_t *encoded =
                token_scratch + slot * NINLIL_RRMP_NPT1_SLOT_BYTES;
            if (!ninlil_rrmp_memeq(encoded, sc->token_dig, 32u)) {
                continue;
            }
            if (!ninlil_rrmp_encode_npt1_slot(
                    sc->token_dig,
                    npt_kind,
                    token_created_ms,
                    encoded)) {
                return 0;
            }
        }
        if (append_token &&
            page ==
                (uint8_t)(ledger_count /
                    NINLIL_RRMP_NPT1_SLOTS_PER_PAGE)) {
            uint32_t expected_slot =
                (uint32_t)(ledger_count %
                    NINLIL_RRMP_NPT1_SLOTS_PER_PAGE);
            if (old_count != expected_slot ||
                old_count >= NINLIL_RRMP_NPT1_SLOTS_PER_PAGE ||
                !ninlil_rrmp_encode_npt1_slot(
                    sc->token_dig,
                    NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE,
                    token_created_ms,
                    token_scratch +
                        (size_t)old_count *
                            NINLIL_RRMP_NPT1_SLOT_BYTES)) {
                return 0;
            }
            count = old_count + 1u;
        }
        keys[NINLIL_RRMP_NPA1_PAGE_COUNT + page] = kid;
        if (!ninlil_rrmp_parent_dual_begin_write(
                &o->parent_ns,
                keys[NINLIL_RRMP_NPA1_PAGE_COUNT + page],
                &buf,
                &cap,
                &gen) ||
            gen == 0u || gen >= UINT32_MAX ||
            !ninlil_rrmp_encode_npt1_page(
                page,
                (uint32_t)gen,
                token_scratch,
                count,
                buf) ||
            !ninlil_rrmp_validate_npt1(buf) ||
            !ninlil_rrmp_parent_dual_commit(
                &o->parent_ns,
                keys[NINLIL_RRMP_NPA1_PAGE_COUNT + page],
                NINLIL_RRMP_NPT1_BYTES)) {
            return 0;
        }
    }
    if (sc->cas) {
        ninlil_rrmp_noa1_fields_t noa;
        ninlil_rrmp_nph1_fields_t header;
        uint8_t *buf;
        size_t cap;
        uint64_t gen;
        if (!ninlil_rrmp_decode_noa1(sc->noa1_raw, &noa)) {
            return 0;
        }
        ninlil_rrmp_memzero(&header, sizeof(header));
        header.authority_id = noa.authority_id;
        header.writer_controller_id = noa.owner_controller_id;
        header.controller_term = noa.controller_term;
        header.writer_epoch = o->parent_ns.writer_generation;
        header.lease_not_after_ms = noa.lease_not_after_authority_ms;
        header.authority_clock_epoch_id = noa.authority_clock_epoch_id;
        memcpy(header.writer_proof_digest.bytes, sc->proof_dig, 32u);
        header.assignment_page_bitmap =
            (uint16_t)((1u << NINLIL_RRMP_NPA1_PAGE_COUNT) - 1u);
        header.token_page_bitmap =
            (uint16_t)((1u << NINLIL_RRMP_NPT1_PAGE_COUNT) - 1u);
        memcpy(
            header.authority_commit_digest.bytes, sc->commit_dig, 32u);
        keys[key_count] = NINLIL_RRMP_PKEY_NPH1;
        if (!ninlil_rrmp_parent_dual_begin_write(
                &o->parent_ns, NINLIL_RRMP_PKEY_NPH1, &buf, &cap, &gen) ||
            gen == 0u || gen == UINT64_MAX) {
            return 0;
        }
        header.header_generation = gen;
        if (!ninlil_rrmp_encode_nph1(&header, buf) ||
            !ninlil_rrmp_validate_nph1(buf) ||
            !ninlil_rrmp_parent_dual_commit(
                &o->parent_ns,
                NINLIL_RRMP_PKEY_NPH1,
                NINLIL_RRMP_NPH1_BYTES)) {
            return 0;
        }
        ++key_count;
    }
    if (!ninlil_rrmp_parent_full_commit(
            &o->parent_ns, keys, (uint8_t)key_count)) {
        return 0;
    }
    sc->token_created_ms = token_created_ms;
    o->parent_ns.cu_class = ninlil_rrmp_parent_classify_cu(&o->parent_ns);
    return finish_writepoint_full(o);
}

ninlil_parent_status_u32 ninlil_parent_set_install(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_set_install_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    ninlil_rrmp_digest32_t dig;
    ninlil_rrmp_id16_t ids[NINLIL_RRMP_PARENT_MAX];
    ninlil_rrmp_nps1_fields_t f;
    rrmp_scope_t *sc;
    rrmp_scope_t old_scope;
    int was_new = 0;
    uint8_t i;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent(&req->preamble, 240u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (req->parent_set_count < 1u ||
        req->parent_set_count > NINLIL_RRMP_PARENT_MAX) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    for (i = 0u; i < req->parent_set_count; ++i) {
        size_t z = 0u;
        size_t j;
        for (j = 0u; j < 16u; ++j) {
            z |= req->parent_runtime_id[i][j];
        }
        if (z == 0u) {
            parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
            return NINLIL_PARENT_INVALID_ARGUMENT;
        }
        memcpy(ids[i].bytes, req->parent_runtime_id[i], 16u);
        /* uniqueness */
        {
            uint8_t k;
            for (k = 0u; k < i; ++k) {
                if (ninlil_rrmp_memeq(ids[k].bytes, ids[i].bytes, 16u)) {
                    parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
                    return NINLIL_PARENT_INVALID_ARGUMENT;
                }
            }
        }
    }
    for (i = req->parent_set_count; i < NINLIL_RRMP_PARENT_MAX; ++i) {
        size_t j;
        for (j = 0u; j < 16u; ++j) {
            if (req->parent_runtime_id[i][j] != 0u) {
                parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
                return NINLIL_PARENT_INVALID_ARGUMENT;
            }
        }
    }
    if (!ninlil_rrmp_parent_set_digest(ids, req->parent_set_count, &dig)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (!ninlil_rrmp_memeq(dig.bytes, req->parent_set_digest32, 32u)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL) {
        sc = alloc_scope(o);
        if (sc == NULL) {
            parent_result_fill(out, NINLIL_PARENT_RESOURCE);
            return NINLIL_PARENT_RESOURCE;
        }
        sc->downlink_tx_scope = 0u;
        sc->installed_revision = 0u;
        was_new = 1;
    } else {
        /* revision mono-inc on same scope overwrite */
        if (req->assignment_epoch <= sc->installed_revision) {
            parent_result_fill(out, NINLIL_PARENT_STALE_REVISION);
            return NINLIL_PARENT_STALE_REVISION;
        }
    }
    old_scope = *sc;
    if ((sc->noa1_present &&
            req->controller_term != sc->noa1_controller_term) ||
        (!sc->noa1_present &&
            req->controller_term != o->cfg.controller_term)) {
        if (was_new) {
            ninlil_rrmp_memzero(sc, sizeof(*sc));
        }
        parent_result_fill(out, NINLIL_PARENT_STALE_TERM);
        return NINLIL_PARENT_STALE_TERM;
    }
    ninlil_rrmp_memzero(&f, sizeof(f));
    memcpy(f.owner_scope_id.bytes, req->owner_scope_id, 16u);
    memcpy(f.parent_set_id.bytes, req->path_policy_id, 16u);
    f.parent_set_revision = req->assignment_epoch;
    f.parent_count = req->parent_set_count;
    for (i = 0u; i < req->parent_set_count; ++i) {
        f.parent_ids[i] = ids[i];
    }
    f.parent_set_digest = dig;
    {
        uint8_t nps1_raw[NINLIL_RRMP_NPS1_BYTES];
        if (!ninlil_rrmp_encode_nps1(&f, nps1_raw)) {
            parent_result_fill(out, NINLIL_PARENT_CORRUPT);
            return NINLIL_PARENT_CORRUPT;
        }
        memcpy(sc->nps1_record_digest, nps1_raw + 212, 32u);
    }
    memcpy(sc->owner_scope_id, req->owner_scope_id, 16u);
    sc->parent_count = f.parent_count;
    memcpy(sc->parent_set_digest, f.parent_set_digest.bytes, 32u);
    {
        uint8_t pi;
        for (pi = 0u; pi < f.parent_count; ++pi) {
            uint8_t prior_lost = 0u;
            uint8_t oi;
            if (!was_new) {
                for (oi = 0u; oi < old_scope.parent_count; ++oi) {
                    if (ninlil_rrmp_memeq(
                            old_scope.parent_ids[oi],
                            f.parent_ids[pi].bytes,
                            16u)) {
                        prior_lost = old_scope.parent_lost[oi];
                        break;
                    }
                }
            }
            memcpy(sc->parent_ids[pi], f.parent_ids[pi].bytes, 16u);
            sc->parent_lost[pi] = prior_lost;
        }
        for (pi = f.parent_count; pi < NINLIL_RRMP_PARENT_MAX; ++pi) {
            ninlil_rrmp_memzero(sc->parent_ids[pi], 16u);
            sc->parent_lost[pi] = 0u;
        }
    }
    memcpy(sc->path_policy_id, req->path_policy_id, 16u);
    sc->path_policy_revision = req->assignment_epoch;
    sc->used = 1u;
    sc->installed_revision = req->assignment_epoch;
    if (!persist_nps1(o, sc)) {
        if (was_new) {
            ninlil_rrmp_memzero(sc, sizeof(*sc));
        } else {
            *sc = old_scope;
        }
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    memcpy(out->token_or_commit_digest32, dig.bytes, 32u);
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_owner_prepare(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_prepare_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    if (!owner_serial_active(owner) || req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    parent_result_fill(out, NINLIL_PARENT_UNSUPPORTED_API);
    return NINLIL_PARENT_UNSUPPORTED_API;
#if 0 /* v1 cannot carry the exact old authority tuple; retained for audit only. */
    st = preamble_parent(&req->preamble, 464u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!ninlil_rrmp_decode_noa1(req->new_assignment_noa1, &noa)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (!ninlil_rrmp_memeq(noa.owner_scope_id.bytes, req->owner_scope_id, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_SCOPE_MISMATCH);
        return NINLIL_PARENT_SCOPE_MISMATCH;
    }
    if (!ninlil_rrmp_memeq(
            noa.handoff_token_digest.bytes, req->handoff_token_digest32, 32u)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (!ninlil_rrmp_memeq(
            noa.authority_id.bytes, o->cfg.authority_id, 16u) ||
        !ninlil_rrmp_memeq(
            noa.authority_clock_epoch_id.bytes,
            o->cfg.authority_clock_epoch_id,
            16u) ||
        noa.controller_term < o->cfg.controller_term) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (noa.lease_not_after_authority_ms == 0u ||
        noa.lease_not_after_authority_ms == UINT64_MAX ||
        o->cfg.now_ms >= noa.lease_not_after_authority_ms) {
        parent_result_fill(out, NINLIL_PARENT_LEASE_EXPIRED);
        return NINLIL_PARENT_LEASE_EXPIRED;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (noa.parent_set_count != sc->parent_count ||
        !ninlil_rrmp_memeq(
            noa.parent_set_digest.bytes, sc->parent_set_digest, 32u) ||
        !ninlil_rrmp_memeq(
            noa.parent_set_id.bytes, sc->path_policy_id, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (sc->split_brain || sc->parent_loss_seal || sc->downlink_tx_scope == 0u) {
        parent_result_ok_scope(out, o, sc, NINLIL_PARENT_SPLIT_BRAIN);
        return NINLIL_PARENT_SPLIT_BRAIN;
    }
    if (!npt_ledger_summary(
            o,
            req->handoff_token_digest32,
            &ledger_count,
            &token_matches,
            NULL,
            NULL)) {
        (void)parent_rehydrate_corrupt(o);
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (token_matches != 0u) {
        parent_result_fill(out, NINLIL_PARENT_TOKEN_REPLAY);
        return NINLIL_PARENT_TOKEN_REPLAY;
    }
    if (ledger_count >= NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY) {
        parent_result_fill(out, NINLIL_PARENT_RESOURCE);
        return NINLIL_PARENT_RESOURCE;
    }
    sc->noa1_controller_term = noa.controller_term;
    sc->noa1_assignment_revision = noa.assignment_revision;
    sc->lease_not_after_ms = noa.lease_not_after_authority_ms;
    memcpy(sc->noa1_body_digest, req->new_assignment_noa1 + 224, 32u);
    memcpy(sc->noa1_raw, req->new_assignment_noa1, NINLIL_RRMP_NOA1_BYTES);
    sc->noa1_present = 1u;
    memcpy(sc->token_dig, req->handoff_token_digest32, 32u);
    sc->token_consumed = 0u;
    sc->proof = 0u;
    sc->cas = 0u;
    sc->receipt = 0u;
    sc->handoff = NINLIL_RRMP_HANDOFF_PREPARED_NEW;
    sc->is_old_owner_local = 1u;
    memcpy(sc->old_owner, o->cfg.local_runtime_id, 16u);
    if (!persist_npa1_npt1_full(
            o,
            sc,
            NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE,
            o->cfg.now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    /*
     * The parent dual namespace is only the inner writepoint.  A
     * storage-bound owner must publish the same PREPARED_NEW state through the
     * platform FULL snapshot before reporting success; otherwise a cold
     * restart silently loses the handoff token and assignment.
     */
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    return NINLIL_PARENT_OK;
#endif
}

ninlil_parent_status_u32 ninlil_parent_owner_fence_proof(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_fence_proof_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    if (!owner_serial_active(owner) || req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    parent_result_fill(out, NINLIL_PARENT_UNSUPPORTED_API);
    return NINLIL_PARENT_UNSUPPORTED_API;
#if 0 /* superseded by exact-tuple v2 */
    st = preamble_parent(&req->preamble, 96u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL || sc->handoff != NINLIL_RRMP_HANDOFF_PREPARED_NEW) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (req->old_assignment_revision > sc->noa1_assignment_revision) {
        parent_result_fill(out, NINLIL_PARENT_STALE_REVISION);
        return NINLIL_PARENT_STALE_REVISION;
    }
    /* proof_digest must be non-zero and match expected fence preimage bind */
    {
        size_t z = 0u;
        size_t j;
        ninlil_rrmp_digest32_t expected_proof;
        uint8_t pre[16 + 32 + 8];
        for (j = 0u; j < 32u; ++j) {
            z |= req->proof_digest32[j];
        }
        if (z == 0u) {
            parent_result_fill(out, NINLIL_PARENT_CORRUPT);
            return NINLIL_PARENT_CORRUPT;
        }
        memcpy(pre, req->owner_scope_id, 16u);
        memcpy(pre + 16, sc->token_dig, 32u);
        ninlil_rrmp_put_u64_be(pre + 48, req->old_assignment_revision);
        ninlil_rrmp_sha256(pre, 56u, expected_proof.bytes);
        if (!ninlil_rrmp_memeq(expected_proof.bytes, req->proof_digest32, 32u)) {
            parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
            return NINLIL_PARENT_AUTHORITY_CONFLICT;
        }
        memcpy(sc->proof_dig, req->proof_digest32, 32u);
    }
    sc->proof = 1u;
    sc->handoff = NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF;
    if (!persist_npa1_npt1_full(
            o, sc, NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE, req->now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    return NINLIL_PARENT_OK;
#endif
}

ninlil_parent_status_u32 ninlil_parent_authority_commit(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_authority_commit_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    if (!owner_serial_active(owner) || req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    parent_result_fill(out, NINLIL_PARENT_UNSUPPORTED_API);
    return NINLIL_PARENT_UNSUPPORTED_API;
#if 0 /* superseded by exact-tuple + bundle-witness v2 */
    st = preamble_parent(&req->preamble, 96u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL || sc->handoff != NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (sc->split_brain || sc->parent_loss_seal) {
        parent_result_fill(out, NINLIL_PARENT_SPLIT_BRAIN);
        return NINLIL_PARENT_SPLIT_BRAIN;
    }
    if (!ninlil_rrmp_decode_noa1(sc->noa1_raw, &noa)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (o->parent_ns.sole_writer_set &&
        !ninlil_rrmp_memeq(
            o->parent_ns.sole_writer_id,
            noa.owner_controller_id.bytes,
            16u)) {
        /* Conflicting writer for CAS domain: persist the scope-local seal. */
        sc->split_brain = 1u;
        sc->downlink_tx_scope = 0u;
        if (!persist_nps1(o, sc)) {
            parent_result_fill(out, writepoint_fail_parent_status(o));
            return out->status;
        }
        parent_result_fill(out, NINLIL_PARENT_SPLIT_BRAIN);
        return NINLIL_PARENT_SPLIT_BRAIN;
    }
    /* CAS generation: exact match required when expected non-zero; else must be
     * current generation (0-start). Reject stale generation. */
    if (req->cas_expected_generation != o->parent_ns.writer_generation) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (o->parent_ns.writer_generation >= UINT64_MAX - 1u) {
        o->parent_ns.fenced = 1u;
        o->downlink_tx = 0u;
        parent_result_fill(out, NINLIL_PARENT_RESOURCE);
        return NINLIL_PARENT_RESOURCE;
    }
    if (req->controller_term != sc->noa1_controller_term ||
        req->assignment_revision != sc->noa1_assignment_revision) {
        parent_result_fill(out, NINLIL_PARENT_STALE_TERM);
        return NINLIL_PARENT_STALE_TERM;
    }
    if (!ninlil_rrmp_authority_commit_digest(
            sc->noa1_body_digest,
            sc->nps1_record_digest,
            sc->token_dig,
            req->controller_term,
            req->assignment_revision,
            &expected)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (!ninlil_rrmp_memeq(expected.bytes, req->authority_commit_digest32, 32u)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    /* single-writer CAS succeed */
    o->parent_ns.writer_generation += 1u;
    memcpy(
        o->parent_ns.sole_writer_id, noa.owner_controller_id.bytes, 16u);
    o->parent_ns.sole_writer_set = 1u;
    sc->cas = 1u;
    memcpy(sc->commit_dig, expected.bytes, 32u);
    sc->handoff = NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED;
    if (!persist_npa1_npt1_full(
            o, sc, NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE, o->cfg.now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    memcpy(out->token_or_commit_digest32, expected.bytes, 32u);
    return NINLIL_PARENT_OK;
#endif
}

static int authority_tuple_canonical(
    const ninlil_rrmp_authority_tuple_v2_t *tuple)
{
    if (tuple == NULL ||
        tuple->reserved0[0] != 0u || tuple->reserved0[1] != 0u ||
        tuple->reserved0[2] != 0u || tuple->present > 1u) {
        return 0;
    }
    if (!tuple->present) {
        ninlil_rrmp_authority_tuple_v2_t zero;
        ninlil_rrmp_memzero(&zero, sizeof(zero));
        return memcmp(tuple, &zero, sizeof(zero)) == 0;
    }
    return tuple->exact_noa1_length == NINLIL_RRMP_NOA1_BYTES &&
        bytes_have_nonzero(tuple->noa1_sha256, 32u) &&
        tuple->assignment_revision != 0u &&
        tuple->assignment_revision != UINT64_MAX &&
        tuple->controller_term != 0u &&
        tuple->controller_term != UINT64_MAX &&
        bytes_have_nonzero(tuple->owner_controller_id, 16u) &&
        tuple->writer_epoch != 0u &&
        tuple->writer_epoch != UINT64_MAX &&
        tuple->lease_not_after_ms != 0u &&
        tuple->lease_not_after_ms != UINT64_MAX &&
        bytes_have_nonzero(tuple->authority_clock_epoch_id, 16u);
}

static int authority_tuple_equal(
    const ninlil_rrmp_authority_tuple_v2_t *a,
    const ninlil_rrmp_authority_tuple_v2_t *b)
{
    return a != NULL && b != NULL &&
        a->present == b->present &&
        a->exact_noa1_length == b->exact_noa1_length &&
        ninlil_rrmp_memeq(a->noa1_sha256, b->noa1_sha256, 32u) &&
        a->assignment_revision == b->assignment_revision &&
        a->controller_term == b->controller_term &&
        ninlil_rrmp_memeq(
            a->owner_controller_id, b->owner_controller_id, 16u) &&
        a->writer_epoch == b->writer_epoch &&
        a->lease_not_after_ms == b->lease_not_after_ms &&
        ninlil_rrmp_memeq(
            a->authority_clock_epoch_id,
            b->authority_clock_epoch_id,
            16u);
}

static void authority_tuple_encode(
    const ninlil_rrmp_authority_tuple_v2_t *tuple, uint8_t out[104])
{
    ninlil_rrmp_memzero(out, 104u);
    out[0] = tuple->present;
    ninlil_rrmp_put_u32_be(out + 4u, tuple->exact_noa1_length);
    memcpy(out + 8u, tuple->noa1_sha256, 32u);
    ninlil_rrmp_put_u64_be(out + 40u, tuple->assignment_revision);
    ninlil_rrmp_put_u64_be(out + 48u, tuple->controller_term);
    memcpy(out + 56u, tuple->owner_controller_id, 16u);
    ninlil_rrmp_put_u64_be(out + 72u, tuple->writer_epoch);
    ninlil_rrmp_put_u64_be(out + 80u, tuple->lease_not_after_ms);
    memcpy(out + 88u, tuple->authority_clock_epoch_id, 16u);
}

static int authority_tuple_decode(
    const uint8_t in[104], ninlil_rrmp_authority_tuple_v2_t *out)
{
    if (in == NULL || out == NULL ||
        in[1u] != 0u || in[2u] != 0u || in[3u] != 0u) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->present = in[0u];
    out->exact_noa1_length = ninlil_rrmp_get_u32_be(in + 4u);
    memcpy(out->noa1_sha256, in + 8u, 32u);
    out->assignment_revision = ninlil_rrmp_get_u64_be(in + 40u);
    out->controller_term = ninlil_rrmp_get_u64_be(in + 48u);
    memcpy(out->owner_controller_id, in + 56u, 16u);
    out->writer_epoch = ninlil_rrmp_get_u64_be(in + 72u);
    out->lease_not_after_ms = ninlil_rrmp_get_u64_be(in + 80u);
    memcpy(out->authority_clock_epoch_id, in + 88u, 16u);
    return authority_tuple_canonical(out);
}

static int authority_tuple_from_noa(
    const uint8_t raw[NINLIL_RRMP_NOA1_BYTES],
    uint64_t writer_epoch,
    ninlil_rrmp_authority_tuple_v2_t *out)
{
    ninlil_rrmp_noa1_fields_t noa;
    if (raw == NULL || out == NULL || writer_epoch == 0u ||
        writer_epoch == UINT64_MAX ||
        !ninlil_rrmp_decode_noa1(raw, &noa)) {
        return 0;
    }
    ninlil_rrmp_memzero(out, sizeof(*out));
    out->present = 1u;
    out->exact_noa1_length = NINLIL_RRMP_NOA1_BYTES;
    ninlil_rrmp_sha256(raw, NINLIL_RRMP_NOA1_BYTES, out->noa1_sha256);
    out->assignment_revision = noa.assignment_revision;
    out->controller_term = noa.controller_term;
    memcpy(out->owner_controller_id, noa.owner_controller_id.bytes, 16u);
    out->writer_epoch = writer_epoch;
    out->lease_not_after_ms = noa.lease_not_after_authority_ms;
    memcpy(
        out->authority_clock_epoch_id,
        noa.authority_clock_epoch_id.bytes,
        16u);
    return authority_tuple_canonical(out);
}

static int scope_current_authority_tuple(
    const ninlil_rrmp_owner_t *o,
    const rrmp_scope_t *sc,
    ninlil_rrmp_authority_tuple_v2_t *out)
{
    if (o == NULL || sc == NULL || out == NULL) {
        return 0;
    }
    if (!sc->noa1_present) {
        ninlil_rrmp_memzero(out, sizeof(*out));
        return 1;
    }
    return authority_tuple_from_noa(
        sc->noa1_raw,
        o->parent_ns.writer_generation != 0u
            ? o->parent_ns.writer_generation
            : 1u,
        out);
}

static void no_old_authority_proof_digest(
    const uint8_t owner_scope_id[16],
    const uint8_t handoff_token_digest32[32],
    uint8_t out[32])
{
    static const uint8_t domain[] =
        "NINLIL-RRMP-NO-OLD-AUTHORITY-V2";
    uint8_t preimage[sizeof(domain) - 1u + 16u + 32u];
    memcpy(preimage, domain, sizeof(domain) - 1u);
    memcpy(
        preimage + sizeof(domain) - 1u,
        owner_scope_id,
        16u);
    memcpy(
        preimage + sizeof(domain) - 1u + 16u,
        handoff_token_digest32,
        32u);
    ninlil_rrmp_sha256(preimage, sizeof(preimage), out);
}

ninlil_parent_status_u32 ninlil_parent_owner_prepare_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_prepare_req_v2_t *req,
    ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    ninlil_rrmp_noa1_fields_t noa;
    ninlil_rrmp_authority_tuple_v2_t current;
    ninlil_rrmp_authority_tuple_v2_t proposed;
    rrmp_scope_t *sc;
    rrmp_scope_t old_scope;
    uint16_t ledger_count = 0u;
    uint8_t token_matches = 0u;
    uint32_t st;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent_v2(&req->preamble, (uint32_t)sizeof(*req));
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!authority_tuple_canonical(&req->expected_old) ||
        !ninlil_rrmp_decode_noa1(req->new_assignment_noa1, &noa) ||
        !ninlil_rrmp_memeq(
            noa.owner_scope_id.bytes, req->owner_scope_id, 16u) ||
        !ninlil_rrmp_memeq(
            noa.handoff_token_digest.bytes,
            req->handoff_token_digest32,
            32u)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL || sc->parent_count == 0u) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (!scope_current_authority_tuple(o, sc, &current) ||
        !authority_tuple_equal(&current, &req->expected_old)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (o->parent_ns.writer_generation == UINT64_MAX ||
        !authority_tuple_from_noa(
            req->new_assignment_noa1,
            o->parent_ns.writer_generation + 1u,
            &proposed) ||
        !ninlil_rrmp_memeq(
            noa.authority_id.bytes, o->cfg.authority_id, 16u) ||
        !ninlil_rrmp_memeq(
            noa.authority_clock_epoch_id.bytes,
            o->cfg.authority_clock_epoch_id,
            16u) ||
        noa.lease_not_after_authority_ms <= o->cfg.now_ms ||
        noa.parent_set_count != sc->parent_count ||
        !ninlil_rrmp_memeq(
            noa.parent_set_digest.bytes, sc->parent_set_digest, 32u) ||
        !ninlil_rrmp_memeq(
            noa.parent_set_id.bytes, sc->path_policy_id, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (current.present &&
        (proposed.controller_term < current.controller_term ||
            (proposed.controller_term == current.controller_term &&
                !ninlil_rrmp_memeq(
                    proposed.owner_controller_id,
                    current.owner_controller_id,
                    16u)) ||
            (proposed.controller_term == current.controller_term &&
                proposed.assignment_revision <=
                    current.assignment_revision))) {
        parent_result_fill(out, NINLIL_PARENT_STALE_TERM);
        return NINLIL_PARENT_STALE_TERM;
    }
    if (!npt_ledger_summary(
            o,
            req->handoff_token_digest32,
            &ledger_count,
            &token_matches,
            NULL,
            NULL)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (token_matches != 0u) {
        parent_result_fill(out, NINLIL_PARENT_TOKEN_REPLAY);
        return NINLIL_PARENT_TOKEN_REPLAY;
    }
    if (ledger_count >= NINLIL_RRMP_TOKEN_REPLAY_LEDGER_CAPACITY) {
        parent_result_fill(out, NINLIL_PARENT_RESOURCE);
        return NINLIL_PARENT_RESOURCE;
    }
    old_scope = *sc;
    sc->handoff_old_tuple = current;
    sc->handoff_new_tuple = proposed;
    memcpy(sc->noa1_raw, req->new_assignment_noa1, NINLIL_RRMP_NOA1_BYTES);
    sc->noa1_present = 1u;
    sc->noa1_controller_term = noa.controller_term;
    sc->noa1_assignment_revision = noa.assignment_revision;
    sc->lease_not_after_ms = noa.lease_not_after_authority_ms;
    memcpy(sc->noa1_body_digest, req->new_assignment_noa1 + 224u, 32u);
    memcpy(sc->token_dig, req->handoff_token_digest32, 32u);
    sc->token_consumed = 0u;
    sc->proof = 0u;
    if (!current.present) {
        no_old_authority_proof_digest(
            req->owner_scope_id,
            req->handoff_token_digest32,
            sc->proof_dig);
    } else {
        ninlil_rrmp_memzero(sc->proof_dig, 32u);
    }
    sc->cas = 0u;
    sc->receipt = 0u;
    sc->handoff = NINLIL_RRMP_HANDOFF_PREPARED_NEW;
    sc->is_old_owner_local = 1u;
    memcpy(sc->old_owner, o->cfg.local_runtime_id, 16u);
    if (!persist_npa1_npt1_full(
            o,
            sc,
            NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE,
            o->cfg.now_ms)) {
        *sc = old_scope;
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    if (!current.present) {
        memcpy(
            out->token_or_commit_digest32, sc->proof_dig, 32u);
    }
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_owner_fence_proof_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_fence_proof_req_v2_t *req,
    ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    rrmp_scope_t *sc;
    uint8_t tuple_bytes[104];
    uint8_t preimage[256];
    uint8_t explicit_expected[32];
    size_t off = 0u;
    uint32_t st;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent_v2(&req->preamble, (uint32_t)sizeof(*req));
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL || sc->handoff != NINLIL_RRMP_HANDOFF_PREPARED_NEW ||
        !authority_tuple_equal(
            &req->expected_old, &sc->handoff_old_tuple) ||
        !ninlil_rrmp_memeq(
            req->handoff_token_digest32, sc->token_dig, 32u) ||
        !sc->handoff_old_tuple.present ||
        bytes_have_nonzero(req->reserved_tail, sizeof(req->reserved_tail)) ||
        bytes_have_nonzero(req->reserved2, sizeof(req->reserved2))) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (req->proof_kind != NINLIL_RRMP_HANDOFF_PROOF_EXPLICIT_RESIGN &&
        req->proof_kind !=
            NINLIL_RRMP_HANDOFF_PROOF_TRUSTED_EXACT_LEASE_EXPIRY) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    authority_tuple_encode(&sc->handoff_old_tuple, tuple_bytes);
    if (req->proof_kind ==
        NINLIL_RRMP_HANDOFF_PROOF_EXPLICIT_RESIGN) {
        static const uint8_t domain[] =
            "NINLIL-RRMP-EXPLICIT-RESIGN-V2";
        uint8_t resign_preimage[
            sizeof(domain) - 1u + 104u + 16u + 32u];
        memcpy(resign_preimage, domain, sizeof(domain) - 1u);
        memcpy(resign_preimage + sizeof(domain) - 1u, tuple_bytes, 104u);
        memcpy(
            resign_preimage + sizeof(domain) - 1u + 104u,
            req->owner_scope_id,
            16u);
        memcpy(
            resign_preimage + sizeof(domain) - 1u + 120u,
            sc->token_dig,
            32u);
        ninlil_rrmp_sha256(
            resign_preimage, sizeof(resign_preimage), explicit_expected);
        if (!ninlil_rrmp_memeq(
                explicit_expected, req->explicit_resign_digest32, 32u) ||
            req->trusted_now_ms != 0u ||
            bytes_have_nonzero(req->trusted_clock_epoch_id, 16u)) {
            parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
            return NINLIL_PARENT_AUTHORITY_CONFLICT;
        }
    } else if (
        bytes_have_nonzero(req->explicit_resign_digest32, 32u) ||
        req->trusted_now_ms < sc->handoff_old_tuple.lease_not_after_ms ||
        !ninlil_rrmp_memeq(
            req->trusted_clock_epoch_id,
            sc->handoff_old_tuple.authority_clock_epoch_id,
            16u) ||
        !ninlil_rrmp_memeq(
            req->trusted_clock_epoch_id,
            o->cfg.authority_clock_epoch_id,
            16u)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    {
        static const uint8_t domain[] = "NINLIL-RRMP-FENCE-PROOF-V2";
        memcpy(preimage + off, domain, sizeof(domain) - 1u);
        off += sizeof(domain) - 1u;
    }
    memcpy(preimage + off, tuple_bytes, 104u);
    off += 104u;
    memcpy(preimage + off, req->owner_scope_id, 16u);
    off += 16u;
    memcpy(preimage + off, sc->token_dig, 32u);
    off += 32u;
    preimage[off++] = req->proof_kind;
    ninlil_rrmp_put_u64_be(preimage + off, req->trusted_now_ms);
    off += 8u;
    memcpy(preimage + off, req->explicit_resign_digest32, 32u);
    off += 32u;
    memcpy(preimage + off, req->trusted_clock_epoch_id, 16u);
    off += 16u;
    if (off > sizeof(preimage)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    ninlil_rrmp_sha256(preimage, off, sc->proof_dig);
    sc->proof = 1u;
    sc->handoff = NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF;
    if (!persist_npa1_npt1_full(
            o, sc, NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE, o->cfg.now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    memcpy(out->token_or_commit_digest32, sc->proof_dig, 32u);
    return NINLIL_PARENT_OK;
}

static int bundle_witness_equal(
    const ninlil_rrmp_bundle_witness_v2_t *a,
    const ninlil_rrmp_bundle_witness_v2_t *b)
{
    if (a == NULL || b == NULL || a->present != b->present) {
        return 0;
    }
    if (!a->present) {
        return a->logical_length == 0u && b->logical_length == 0u &&
            !bytes_have_nonzero(
                a->manifest_rrm1, NINLIL_RRMP_RRM1_BYTES) &&
            !bytes_have_nonzero(
                b->manifest_rrm1, NINLIL_RRMP_RRM1_BYTES) &&
            !bytes_have_nonzero(a->logical_sha256, 32u) &&
            !bytes_have_nonzero(b->logical_sha256, 32u);
    }
    return a->logical_length == b->logical_length &&
        ninlil_rrmp_memeq(
            a->manifest_rrm1, b->manifest_rrm1,
            NINLIL_RRMP_RRM1_BYTES) &&
        ninlil_rrmp_memeq(
            a->logical_sha256, b->logical_sha256, 32u);
}

static void bundle_witness_encode(
    const ninlil_rrmp_bundle_witness_v2_t *witness, uint8_t out[296])
{
    ninlil_rrmp_memzero(out, 296u);
    out[0] = witness->present;
    memcpy(out + 4u, witness->manifest_rrm1, NINLIL_RRMP_RRM1_BYTES);
    ninlil_rrmp_put_u32_be(out + 260u, witness->logical_length);
    memcpy(out + 264u, witness->logical_sha256, 32u);
}

ninlil_parent_status_u32 ninlil_parent_authority_commit_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_authority_commit_req_v2_t *req,
    ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    rrmp_scope_t *sc;
    ninlil_rrmp_bundle_witness_v2_t current_bundle;
    uint8_t preimage[640];
    uint8_t tuple_bytes[104];
    uint8_t bundle_bytes[296];
    uint8_t expected_commit[32];
    uint8_t bootstrap_proof[32];
    int proof_matches = 0;
    size_t off = 0u;
    uint32_t st;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent_v2(&req->preamble, (uint32_t)sizeof(*req));
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc != NULL &&
        sc->handoff == NINLIL_RRMP_HANDOFF_PREPARED_NEW &&
        !sc->handoff_old_tuple.present) {
        no_old_authority_proof_digest(
            req->owner_scope_id,
            req->handoff_token_digest32,
            bootstrap_proof);
        proof_matches = ninlil_rrmp_memeq(
            req->proof_digest32, bootstrap_proof, 32u);
    } else if (sc != NULL) {
        proof_matches = ninlil_rrmp_memeq(
            req->proof_digest32, sc->proof_dig, 32u);
    }
    if (sc == NULL ||
        (sc->handoff != NINLIL_RRMP_HANDOFF_OLD_FENCED_PROOF &&
            !(sc->handoff == NINLIL_RRMP_HANDOFF_PREPARED_NEW &&
                !sc->handoff_old_tuple.present)) ||
        !authority_tuple_equal(
            &req->expected_old, &sc->handoff_old_tuple) ||
        !authority_tuple_equal(
            &req->expected_new, &sc->handoff_new_tuple) ||
        !ninlil_rrmp_memeq(
            req->handoff_token_digest32, sc->token_dig, 32u) ||
        !proof_matches ||
        req->cas_expected_generation != o->parent_ns.writer_generation ||
        req->cas_expected_generation == UINT64_MAX ||
        req->expected_new.writer_epoch !=
            req->cas_expected_generation + 1u) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    ninlil_rrmp_memzero(&current_bundle, sizeof(current_bundle));
    current_bundle.present = o->storage_expected_present;
    current_bundle.logical_length = o->storage_expected_length;
    memcpy(
        current_bundle.manifest_rrm1,
        o->storage_expected_manifest,
        NINLIL_RRMP_RRM1_BYTES);
    memcpy(
        current_bundle.logical_sha256,
        o->storage_expected_digest,
        32u);
    if (o->storage_bound &&
        (!o->storage_expected_valid ||
            !bundle_witness_equal(
                &current_bundle, &req->expected_bundle))) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (o->parent_ns.sole_writer_set &&
        !ninlil_rrmp_memeq(
            o->parent_ns.sole_writer_id,
            sc->handoff_new_tuple.owner_controller_id,
            16u)) {
        /*
         * A conflicting writer in the authority CAS domain is global, not a
         * scope-local routing anomaly. Persist the permanent fence before
         * returning; no unrelated scope may continue mutation/TX.
         */
        o->authority_global_fence = 1u;
        o->authority_global_fence_reason =
            NINLIL_RRMP_AUTHORITY_FENCE_WRITER_CONFLICT;
        o->downlink_tx = 0u;
        if (!finish_writepoint_full(o)) {
            owner_storage_fence(o);
            parent_result_fill(out, writepoint_fail_parent_status(o));
            return out->status;
        }
        parent_result_fill(out, NINLIL_PARENT_SPLIT_BRAIN);
        out->detail_flags = 2u;
        return NINLIL_PARENT_SPLIT_BRAIN;
    }
    {
        static const uint8_t domain[] =
            "NINLIL-RRMP-AUTHORITY-COMMIT-V2";
        memcpy(preimage + off, domain, sizeof(domain) - 1u);
        off += sizeof(domain) - 1u;
    }
    memcpy(preimage + off, req->owner_scope_id, 16u);
    off += 16u;
    authority_tuple_encode(&req->expected_old, tuple_bytes);
    memcpy(preimage + off, tuple_bytes, 104u);
    off += 104u;
    authority_tuple_encode(&req->expected_new, tuple_bytes);
    memcpy(preimage + off, tuple_bytes, 104u);
    off += 104u;
    memcpy(preimage + off, req->handoff_token_digest32, 32u);
    off += 32u;
    memcpy(preimage + off, req->proof_digest32, 32u);
    off += 32u;
    bundle_witness_encode(&req->expected_bundle, bundle_bytes);
    memcpy(preimage + off, bundle_bytes, sizeof(bundle_bytes));
    off += sizeof(bundle_bytes);
    ninlil_rrmp_put_u64_be(preimage + off, req->cas_expected_generation);
    off += 8u;
    if (off > sizeof(preimage)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    ninlil_rrmp_sha256(preimage, off, expected_commit);
    if (!ninlil_rrmp_memeq(
            expected_commit, req->authority_commit_digest32, 32u)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (o->parent_ns.writer_generation >= UINT64_MAX - 1u) {
        parent_result_fill(out, NINLIL_PARENT_RESOURCE);
        return NINLIL_PARENT_RESOURCE;
    }
    o->parent_ns.writer_generation += 1u;
    memcpy(
        o->parent_ns.sole_writer_id,
        sc->handoff_new_tuple.owner_controller_id,
        16u);
    o->parent_ns.sole_writer_set = 1u;
    sc->cas = 1u;
    if (!sc->handoff_old_tuple.present) {
        sc->proof = 1u;
        memcpy(sc->proof_dig, req->proof_digest32, 32u);
    }
    memcpy(sc->commit_dig, expected_commit, 32u);
    sc->handoff = NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED;
    if (!persist_npa1_npt1_full(
            o, sc, NINLIL_RRMP_NPT1_KIND_TOKEN_LIVE, o->cfg.now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    memcpy(out->token_or_commit_digest32, expected_commit, 32u);
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_owner_activate(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_activate_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    rrmp_scope_t *sc;
    uint8_t flags[22];
    uint32_t st;
    uint16_t ledger_count = 0u;
    uint8_t token_matches = 0u;
    uint8_t token_kind = 0u;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent(&req->preamble, 80u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (!npt_ledger_summary(
            o,
            sc->token_dig,
            &ledger_count,
            &token_matches,
            &token_kind,
            NULL) ||
        token_matches != 1u ||
        ledger_count == 0u) {
        (void)parent_rehydrate_corrupt(o);
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (sc->token_consumed ||
        token_kind == NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED) {
        parent_result_fill(out, NINLIL_PARENT_TOKEN_REPLAY);
        return NINLIL_PARENT_TOKEN_REPLAY;
    }
    if (sc->handoff != NINLIL_RRMP_HANDOFF_AUTHORITY_COMMITTED) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    /* commit receipt must equal authority_commit digest (not token alone) */
    if (!ninlil_rrmp_memeq(sc->commit_dig, req->commit_receipt_digest32, 32u)) {
        parent_result_fill(out, NINLIL_PARENT_TOKEN_REPLAY);
        return NINLIL_PARENT_TOKEN_REPLAY;
    }
    sc->token_consumed = 1u;
    sc->receipt = 1u;
    sc->new_seal = 1u;
    sc->downlink_tx_scope = 1u;
    sc->handoff = NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED;
    if (!persist_npa1_npt1_full(
            o, sc, NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED, req->now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_endpoint_observe(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_endpoint_observe_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    rrmp_scope_t *sc;
    uint8_t flags[22];
    uint32_t st;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent(&req->preamble, 80u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL || sc->handoff != NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (!ninlil_rrmp_memeq(
            sc->parent_set_digest,
            req->observed_parent_set_digest32,
            32u)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    sc->handoff = NINLIL_RRMP_HANDOFF_ENDPOINT_OBSERVED;
    if (!persist_npa1_npt1_full(
            o, sc, NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED, o->cfg.now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_owner_retire(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_retire_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    rrmp_scope_t *sc;
    uint8_t flags[22];
    uint32_t st;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent(&req->preamble, 80u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL || sc->handoff != NINLIL_RRMP_HANDOFF_ENDPOINT_OBSERVED) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    /* sole old_owner */
    if (!sc->is_old_owner_local ||
        !ninlil_rrmp_memeq(sc->old_owner, o->cfg.local_runtime_id, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_NOT_OWNER);
        return NINLIL_PARENT_NOT_OWNER;
    }
    /* old_seal ordering: new_seal must already be active (S4+). */
    if (!sc->new_seal) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    sc->tombstone = 1u;
    /* ADR-0020 S6: old_owner_seal = 0 after OLD_RETIRED */
    sc->old_seal = 0u;
    sc->handoff = NINLIL_RRMP_HANDOFF_OLD_RETIRED;
    if (!persist_npa1_npt1_full(
            o, sc, NINLIL_RRMP_NPT1_KIND_TOMBSTONE_USED, req->now_ms)) {
        parent_result_fill(out, writepoint_fail_parent_status(o));
        return out->status;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_query(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_query_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    rrmp_scope_t *sc;
    uint8_t flags[22];
    uint32_t st;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent(&req->preamble, 48u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_DIAGNOSTICS)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_fence_status(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    if (sc == NULL) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    memcpy(out->token_or_commit_digest32, sc->parent_set_digest, 32u);
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_recover_commit_unknown(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_recover_cu_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    rrmp_scope_t *sc;
    uint8_t flags[22];
    uint32_t st;
    uint32_t cu;
    size_t z = 0u;
    size_t j;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent(&req->preamble, 80u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    /* Exact reserved + non-zero owner_scope_id (ABI header validation). */
    if ((req->reserved2[0] | req->reserved2[1] | req->reserved2[2] |
            (uint8_t)(req->reserved3 != 0u ? 1u : 0u)) != 0u) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    for (j = 0u; j < 16u; ++j) {
        z |= req->owner_scope_id[j];
    }
    if (z == 0u) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (owner_storage_hard_fenced(o) &&
        !ninlil_rrmp_owner_storage_recover(o)) {
        st = o->storage_last_outcome == RRMP_STORAGE_OUTCOME_COMMIT_UNKNOWN
            ? NINLIL_PARENT_COMMIT_UNKNOWN
            : NINLIL_PARENT_CORRUPT;
        parent_result_fill(out, st);
        out->cu_class = (uint8_t)o->parent_ns.cu_class;
        memcpy(out->owner_scope_id, req->owner_scope_id, 16u);
        return st;
    }
    sc = find_scope(o, req->owner_scope_id);
    /* Preserve an exact outer OLD/NEW witness classification after recovery. */
    if (o->parent_ns.cu_class == NINLIL_RRMP_CU_OLD ||
        o->parent_ns.cu_class == NINLIL_RRMP_CU_NEW) {
        cu = o->parent_ns.cu_class;
    } else {
        cu = ninlil_rrmp_parent_classify_cu(&o->parent_ns);
    }
    o->parent_ns.cu_class = cu;
    if (sc != NULL) {
        parent_result_ok_scope(out, o, sc, NINLIL_PARENT_OK);
    } else {
        parent_result_fill(out, NINLIL_PARENT_OK);
        memcpy(out->owner_scope_id, req->owner_scope_id, 16u);
    }
    out->cu_class = (uint8_t)cu;
    if (req->expected_class != 0u && req->expected_class != (uint8_t)cu) {
        parent_result_fill(out, NINLIL_PARENT_COMMIT_UNKNOWN);
        out->cu_class = (uint8_t)cu;
        memcpy(out->owner_scope_id, req->owner_scope_id, 16u);
        return NINLIL_PARENT_COMMIT_UNKNOWN;
    }
    if (cu == NINLIL_RRMP_CU_PARTIAL || cu == NINLIL_RRMP_CU_EXTRA ||
        cu == NINLIL_RRMP_CU_THIRD) {
        o->downlink_tx = 0u;
        o->parent_ns.fenced = 1u;
        if (sc != NULL) {
            sc->downlink_tx_scope = 0u;
        }
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        out->cu_class = (uint8_t)cu;
        memcpy(out->owner_scope_id, req->owner_scope_id, 16u);
        return NINLIL_PARENT_CORRUPT;
    }
    if (cu == NINLIL_RRMP_CU_OLD) {
        parent_result_fill(out, NINLIL_PARENT_COMMIT_UNKNOWN);
        out->cu_class = (uint8_t)cu;
        memcpy(out->owner_scope_id, req->owner_scope_id, 16u);
        return NINLIL_PARENT_COMMIT_UNKNOWN;
    }
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_parent_diagnostics_snapshot(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_diagnostics_req_v1_t *req, ninlil_parent_result_v1_t *out)
{
    ninlil_rrmp_owner_t *o = owner;
    uint8_t flags[22];
    uint32_t st;
    if (req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent(&req->preamble, 32u, (const uint8_t *)req, flags);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_serial_active(o) || !o->cfg.feature_multi_parent) {
        parent_result_fill(out, !owner_serial_active(o) ? NINLIL_PARENT_INVALID_ARGUMENT
                                  : NINLIL_PARENT_FEATURE_OFF);
        return out->status;
    }
    if (!owner_has_capability(o, NINLIL_RRMP_AUTH_DIAGNOSTICS)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_fence_status(o);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        out->cu_class = (uint8_t)o->parent_ns.cu_class;
        return st;
    }
    parent_result_fill(out, NINLIL_PARENT_OK);
    out->cu_class = (uint8_t)o->parent_ns.cu_class;
    out->detail_flags = o->downlink_tx ? 0u : 4u;
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_rrmp_core_parent_select_for_attempt(
    ninlil_rrmp_owner_t *owner,
    const uint8_t owner_scope_id[16],
    const uint8_t attempt_id16[16],
    uint8_t selected_parent_out[16],
    ninlil_parent_result_v1_t *out)
{
    rrmp_scope_t *sc;
    size_t z = 0u;
    size_t j;
    uint16_t ordinal;
    uint16_t attempt_at = 0u;
    uint8_t old_attempt_id16[16];
    uint8_t old_selected_parent[16];
    uint8_t old_attempt_selected;
    if (owner == NULL || owner_scope_id == NULL || attempt_id16 == NULL ||
        out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_FORWARD)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_parent_write_gate(owner);
        if (gst != NINLIL_PARENT_OK) {
            parent_result_fill(out, gst);
            return gst;
        }
    }
    for (j = 0u; j < 16u; ++j) {
        z |= attempt_id16[j];
    }
    if (z == 0u) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    sc = find_scope(owner, owner_scope_id);
    if (sc == NULL || sc->parent_count == 0u) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    /* Scope-local seal: split-brain / parent-loss blocks select for this scope. */
    if (sc->split_brain || sc->parent_loss_seal || sc->downlink_tx_scope == 0u) {
        parent_result_ok_scope(out, owner, sc, NINLIL_PARENT_SPLIT_BRAIN);
        return NINLIL_PARENT_SPLIT_BRAIN;
    }
    /* Global durable ledger rejects A→B→A and survives every scope transition. */
    if (attempt_find_index(owner, owner_scope_id, attempt_id16, &attempt_at)) {
        parent_result_fill(out, NINLIL_PARENT_SAME_ATTEMPT_RESELECT);
        return NINLIL_PARENT_SAME_ATTEMPT_RESELECT;
    }
    if (owner->attempt_count >= NINLIL_RRMP_QST4_ATTEMPT_CAPACITY) {
        parent_result_fill(out, NINLIL_PARENT_RESOURCE);
        return NINLIL_PARENT_RESOURCE;
    }
    memcpy(old_attempt_id16, sc->last_attempt_id16, 16u);
    memcpy(old_selected_parent, sc->selected_parent, 16u);
    old_attempt_selected = sc->attempt_selected;
    /*
     * Path-policy snapshot selection (never attempt hash % count):
     * ordinal = BE u16 at attempt_id16[14..15], 1-based over available parents.
     */
    ordinal = ninlil_rrmp_get_u16_be(attempt_id16 + 14);
    if (ordinal == 0u) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    {
        uint8_t avail[NINLIL_RRMP_PARENT_MAX];
        uint8_t nac = 0u;
        uint8_t i;
        uint16_t want;
        uint8_t pick;
        if (sc->lease_not_after_ms != 0u &&
            owner->cfg.now_ms >= sc->lease_not_after_ms) {
            parent_result_ok_scope(out, owner, sc, NINLIL_PARENT_LEASE_EXPIRED);
            return NINLIL_PARENT_LEASE_EXPIRED;
        }
        for (i = 0u; i < sc->parent_count; ++i) {
            if (!sc->parent_lost[i]) {
                avail[nac++] = i;
            }
        }
        if (nac == 0u) {
            parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
            return NINLIL_PARENT_NOT_ACTIVE;
        }
        want = (uint16_t)(ordinal - 1u);
        if (want >= (uint16_t)nac) {
            parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
            return NINLIL_PARENT_NOT_ACTIVE;
        }
        pick = avail[(uint8_t)want];
        memcpy(sc->selected_parent, sc->parent_ids[pick], 16u);
        if (selected_parent_out != NULL) {
            memcpy(selected_parent_out, sc->selected_parent, 16u);
        }
    }
    if (!attempt_insert_live(
            owner, owner_scope_id, attempt_id16, &attempt_at)) {
        parent_result_fill(out, NINLIL_PARENT_RESOURCE);
        return NINLIL_PARENT_RESOURCE;
    }
    memcpy(sc->last_attempt_id16, attempt_id16, 16u);
    sc->attempt_selected = 1u;
    /* Durable same-attempt fence via soft trailer + FULL writepoint. */
    if (!finish_writepoint_full(owner)) {
        if (!writepoint_restored_exact_durable_old(owner)) {
            attempt_remove_at(owner, attempt_at);
            sc->attempt_selected = old_attempt_selected;
            memcpy(sc->last_attempt_id16, old_attempt_id16, 16u);
            memcpy(sc->selected_parent, old_selected_parent, 16u);
        }
        parent_result_fill(out, writepoint_fail_parent_status(owner));
        return out->status;
    }
    parent_result_ok_scope(out, owner, sc, NINLIL_PARENT_OK);
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_rrmp_core_split_brain_detect(
    ninlil_rrmp_owner_t *owner,
    const uint8_t owner_scope_id[16],
    const uint8_t writer_a[16],
    const uint8_t writer_b[16],
    uint64_t term_a,
    uint64_t term_b)
{
    rrmp_scope_t *sc;
    if (owner == NULL || owner_scope_id == NULL || writer_a == NULL ||
        writer_b == NULL) {
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_parent_write_gate(owner);
        if (gst != NINLIL_PARENT_OK) {
            return gst;
        }
    }
    sc = find_scope(owner, owner_scope_id);
    if (sc == NULL) {
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (!ninlil_rrmp_memeq(writer_a, writer_b, 16u) && term_a == term_b) {
        /* scope-local seal only — other scopes remain operational */
        sc->split_brain = 1u;
        sc->downlink_tx_scope = 0u;
        if (!persist_nps1(owner, sc)) {
            sc->split_brain = 0u;
            sc->downlink_tx_scope = 1u;
            return writepoint_fail_parent_status(owner);
        }
        return NINLIL_PARENT_SPLIT_BRAIN;
    }
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_rrmp_core_authority_writer_conflict_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_authority_writer_conflict_req_v2_t *req,
    ninlil_parent_result_v1_t *out)
{
    uint32_t st;
    if (owner == NULL || req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent_v2(&req->preamble, (uint32_t)sizeof(*req));
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_PARENT_ADMIN) ||
        !ninlil_rrmp_memeq(
            req->authority_id, owner->cfg.authority_id, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (req->controller_term == 0u ||
        req->writer_epoch_a == 0u || req->writer_epoch_b == 0u ||
        !bytes_have_nonzero(req->writer_a, 16u) ||
        !bytes_have_nonzero(req->writer_b, 16u) ||
        !bytes_have_nonzero(req->authority_clock_epoch_id, 16u) ||
        ninlil_rrmp_memeq(req->writer_a, req->writer_b, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = owner_parent_write_gate(owner);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    owner->authority_global_fence = 1u;
    owner->authority_global_fence_reason =
        NINLIL_RRMP_AUTHORITY_FENCE_WRITER_CONFLICT;
    owner->downlink_tx = 0u;
    if (!finish_writepoint_full(owner)) {
        owner_storage_fence(owner);
        parent_result_fill(out, writepoint_fail_parent_status(owner));
        return out->status;
    }
    parent_result_fill(out, NINLIL_PARENT_SPLIT_BRAIN);
    out->detail_flags = 2u;
    return NINLIL_PARENT_SPLIT_BRAIN;
}

ninlil_parent_status_u32 ninlil_rrmp_core_scope_parent_anomaly_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_scope_parent_anomaly_req_v2_t *req,
    ninlil_parent_result_v1_t *out)
{
    uint32_t st;
    rrmp_scope_t *sc;
    if (owner == NULL || req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent_v2(&req->preamble, (uint32_t)sizeof(*req));
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    if (!bytes_have_nonzero(req->owner_scope_id, 16u) ||
        !bytes_have_nonzero(req->evidence_digest32, 32u) ||
        ninlil_rrmp_memeq(req->parent_a, req->parent_b, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = owner_parent_write_gate(owner);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    sc = find_scope(owner, req->owner_scope_id);
    if (sc == NULL) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    sc->split_brain = 1u;
    sc->downlink_tx_scope = 0u;
    if (!persist_nps1(owner, sc)) {
        parent_result_fill(out, writepoint_fail_parent_status(owner));
        return out->status;
    }
    parent_result_ok_scope(out, owner, sc, NINLIL_PARENT_SPLIT_BRAIN);
    return NINLIL_PARENT_SPLIT_BRAIN;
}

ninlil_parent_status_u32 ninlil_rrmp_core_attempt_reclaim_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_attempt_reclaim_req_v2_t *req,
    ninlil_parent_result_v1_t *out)
{
    uint32_t st;
    uint16_t at = 0u;
    uint16_t evidence_at = UINT16_MAX;
    size_t i;
    rrmp_scope_t *sc;
    if (owner == NULL || req == NULL || out == NULL) {
        parent_result_fill(out, NINLIL_PARENT_INVALID_ARGUMENT);
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    st = preamble_parent_v2(&req->preamble, (uint32_t)sizeof(*req));
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (req->reserved2 != 0u ||
        !bytes_have_nonzero(req->owner_scope_id, 16u) ||
        !bytes_have_nonzero(req->attempt_id16, 16u)) {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        parent_result_fill(out, NINLIL_PARENT_AUTHORITY_CONFLICT);
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    st = owner_parent_write_gate(owner);
    if (st != NINLIL_PARENT_OK) {
        parent_result_fill(out, st);
        return st;
    }
    if (owner->storage_bound &&
        !ninlil_rrmp_owner_storage_recover(owner)) {
        parent_result_fill(out, writepoint_fail_parent_status(owner));
        return out->status;
    }
    if (!attempt_find_index(
            owner, req->owner_scope_id, req->attempt_id16, &at)) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    if (owner->attempts[at].lifecycle !=
            NINLIL_RRMP_ATTEMPT_TERMINAL_RETAINED ||
        req->trusted_now_ms <
            owner->attempts[at].reclaim_not_before_ms) {
        parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
        if (owner->queue[i].used && owner->queue[i].owner_scope_set &&
            ninlil_rrmp_memeq(
                owner->queue[i].owner_scope_id,
                req->owner_scope_id,
                16u) &&
            ninlil_rrmp_memeq(
                owner->queue[i].attempt_id16,
                req->attempt_id16,
                16u)) {
            parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
            return NINLIL_PARENT_NOT_ACTIVE;
        }
    }
    if ((owner->attempts[at].flags &
            NINLIL_RRMP_ATTEMPT_FLAG_NEV1) != 0u) {
        for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
            ninlil_rrmp_nev1_fields_t ef;
            uint8_t digest[32];
            if (!owner->evidence[i].used ||
                !ninlil_rrmp_decode_nev1(owner->evidence[i].raw, &ef) ||
                ef.lifecycle !=
                    NINLIL_RRMP_EVIDENCE_LIFECYCLE_COMPLETED) {
                continue;
            }
            ninlil_rrmp_sha256(
                owner->evidence[i].raw,
                NINLIL_RRMP_NEV1_BYTES,
                digest);
            if (ninlil_rrmp_memeq(
                    digest,
                    owner->attempts[at].terminal_evidence_digest32,
                    32u)) {
                if (evidence_at != UINT16_MAX) {
                    parent_result_fill(out, NINLIL_PARENT_CORRUPT);
                    return NINLIL_PARENT_CORRUPT;
                }
                evidence_at = (uint16_t)i;
            }
        }
        if (evidence_at == UINT16_MAX) {
            parent_result_fill(out, NINLIL_PARENT_CORRUPT);
            return NINLIL_PARENT_CORRUPT;
        }
    } else if ((owner->attempts[at].flags &
            NINLIL_RRMP_ATTEMPT_FLAG_HANDOFF_TOMBSTONE) != 0u) {
        sc = find_scope(owner, req->owner_scope_id);
        if (sc == NULL ||
            sc->handoff != NINLIL_RRMP_HANDOFF_OLD_RETIRED ||
            !sc->tombstone) {
            parent_result_fill(out, NINLIL_PARENT_NOT_ACTIVE);
            return NINLIL_PARENT_NOT_ACTIVE;
        }
        /* NPT1 tombstone digest remains durable; it is not erased here. */
    } else {
        parent_result_fill(out, NINLIL_PARENT_CORRUPT);
        return NINLIL_PARENT_CORRUPT;
    }
    if (evidence_at != UINT16_MAX) {
        ninlil_rrmp_memzero(
            &owner->evidence[evidence_at], sizeof(owner->evidence[evidence_at]));
    }
    attempt_remove_at(owner, at);
    if ((evidence_at != UINT16_MAX &&
            !persist_evidence_page(
                owner,
                (uint16_t)(evidence_at / NINLIL_RRMP_NEP1_SLOTS))) ||
        !finish_writepoint_full(owner)) {
        owner_storage_fence(owner);
        parent_result_fill(out, writepoint_fail_parent_status(owner));
        return out->status;
    }
    sc = find_scope(owner, req->owner_scope_id);
    if (sc != NULL) {
        parent_result_ok_scope(out, owner, sc, NINLIL_PARENT_OK);
    } else {
        parent_result_fill(out, NINLIL_PARENT_OK);
        memcpy(out->owner_scope_id, req->owner_scope_id, 16u);
    }
    return NINLIL_PARENT_OK;
}

ninlil_parent_status_u32 ninlil_rrmp_core_parent_loss(
    ninlil_rrmp_owner_t *owner,
    const uint8_t owner_scope_id[16],
    const uint8_t lost_parent_id[16])
{
    rrmp_scope_t *sc;
    uint8_t i;
    if (owner == NULL || owner_scope_id == NULL || lost_parent_id == NULL) {
        return NINLIL_PARENT_INVALID_ARGUMENT;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_PARENT_ADMIN)) {
        return NINLIL_PARENT_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_parent_write_gate(owner);
        if (gst != NINLIL_PARENT_OK) {
            return gst;
        }
    }
    sc = find_scope(owner, owner_scope_id);
    if (sc == NULL) {
        return NINLIL_PARENT_NOT_ACTIVE;
    }
    for (i = 0u; i < sc->parent_count; ++i) {
        if (ninlil_rrmp_memeq(sc->parent_ids[i], lost_parent_id, 16u)) {
            uint8_t old_lost = sc->parent_lost[i];
            uint8_t old_parent_loss_seal = sc->parent_loss_seal;
            uint8_t old_downlink = sc->downlink_tx_scope;
            sc->parent_lost[i] = 1u;
            sc->parent_loss_seal = 1u;
            sc->downlink_tx_scope = 0u;
            if (!persist_nps1(owner, sc)) {
                sc->parent_lost[i] = old_lost;
                sc->parent_loss_seal = old_parent_loss_seal;
                sc->downlink_tx_scope = old_downlink;
                return writepoint_fail_parent_status(owner);
            }
            return NINLIL_PARENT_OK;
        }
    }
    return NINLIL_PARENT_NOT_ACTIVE;
}

int ninlil_rrmp_drain_evaluate_v1(
    uint64_t now_ms,
    uint32_t remaining_link_groups,
    uint32_t remaining_attempts,
    uint32_t max_airtime_ms,
    uint32_t turnaround_ms,
    uint32_t link_ack_wait_ms,
    uint32_t inter_group_gap_ms,
    uint32_t scheduler_guard_ms,
    uint64_t item_deadline_ms,
    uint64_t drain_deadline_ms,
    uint64_t lease_deadline_ms,
    uint8_t *eligible_out)
{
    uint64_t F, A, T, W, I, G, cost, work, gaps, airtime, completion, dmin;
    if (eligible_out == NULL) {
        return 0;
    }
    *eligible_out = 0u;
    /* F=0 or R=0: ineligible (no division). */
    if (remaining_link_groups == 0u || remaining_attempts == 0u) {
        return 1;
    }
    /* Bounds: F<=13, R<=3 */
    if (remaining_link_groups > NINLIL_RRMP_MAX_LINK_GROUPS ||
        remaining_attempts > NINLIL_RRMP_MAX_ATTEMPTS) {
        return 1;
    }
    F = remaining_link_groups;
    A = max_airtime_ms;
    T = turnaround_ms;
    W = link_ack_wait_ms;
    I = inter_group_gap_ms;
    G = scheduler_guard_ms;
    /* Nonzero A/T/W/I/G required when F>0 (strict drain gates). */
    if (A == 0u || T == 0u || W == 0u || I == 0u || G == 0u) {
        return 1;
    }
    if (A > UINT64_MAX - T || (A + T) > UINT64_MAX - W) {
        return 1;
    }
    cost = A + T + W;
    if (F > UINT64_MAX / cost) {
        return 1;
    }
    work = F * cost;
    if (remaining_attempts > 1u) {
        if (work > UINT64_MAX / (uint64_t)remaining_attempts) {
            return 1;
        }
        work *= (uint64_t)remaining_attempts;
    }
    if (F > 1u) {
        if ((F - 1u) > UINT64_MAX / I) {
            return 1;
        }
        gaps = (F - 1u) * I;
    } else {
        gaps = 0u;
    }
    /* Airtime gate: F*A only (NOT × attempts) per vector airtime_gate. */
    if (F > UINT64_MAX / A) {
        return 1;
    }
    airtime = F * A;
    if (airtime > NINLIL_RRMP_MAX_AIRTIME_BUDGET_MS) {
        return 1;
    }
    if (now_ms > UINT64_MAX - work || (now_ms + work) > UINT64_MAX - gaps ||
        (now_ms + work + gaps) > UINT64_MAX - G) {
        return 1;
    }
    completion = now_ms + work + gaps + G;
    dmin = item_deadline_ms;
    if (drain_deadline_ms < dmin) {
        dmin = drain_deadline_ms;
    }
    if (lease_deadline_ms < dmin) {
        dmin = lease_deadline_ms;
    }
    *eligible_out = (completion <= dmin) ? 1u : 0u;
    return 1;
}

uint8_t ninlil_rrmp_core_scope_seal_allowed(
    const ninlil_rrmp_owner_t *owner, const uint8_t owner_scope_id[16])
{
    size_t i;
    if (owner == NULL || owner_scope_id == NULL) {
        return 0u;
    }
    if (!owner->downlink_tx || owner->route_ns.fenced || owner->parent_ns.fenced) {
        return 0u;
    }
    for (i = 0u; i < NINLIL_RRMP_SCOPE_PARENT_SET_CAPACITY; ++i) {
        const rrmp_scope_t *sc = &owner->scopes[i];
        if (sc->used &&
            ninlil_rrmp_memeq(sc->owner_scope_id, owner_scope_id, 16u)) {
            if (sc->split_brain || sc->parent_loss_seal ||
                sc->downlink_tx_scope == 0u ||
                (sc->handoff >= NINLIL_RRMP_HANDOFF_PREPARED_NEW &&
                    sc->handoff < NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED) ||
                (sc->handoff >= NINLIL_RRMP_HANDOFF_NEW_OWNER_ACTIVATED &&
                    sc->new_seal == 0u)) {
                return 0u;
            }
            return 1u;
        }
    }
    /* Fail-closed: unknown owner_scope never allows seal/TX under multi-parent. */
    return 0u;
}

static rrmp_q_t *find_q_by_handle(ninlil_rrmp_owner_t *o, uint64_t opaque)
{
    size_t i;
    if (o == NULL || opaque == 0u) {
        return NULL;
    }
    for (i = 0u; i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES; ++i) {
        if (o->queue[i].used && o->queue[i].opaque_handle == opaque) {
            return &o->queue[i];
        }
    }
    return NULL;
}

ninlil_route_status_u32 ninlil_rrmp_core_hop_forward_execute(
    ninlil_rrmp_owner_t *owner,
    uint64_t opaque_local_handle,
    const uint8_t *carrier,
    uint16_t carrier_len,
    uint8_t tx_permit_granted,
    ninlil_rrmp_hop_tx_view_t *out_tx)
{
    rrmp_q_t *q;
    rrmp_route_t *ent;
    uint8_t exact[NINLIL_RRMP_EXACT_BODY_BYTES];
    uint8_t rewrap[NINLIL_RRMP_EXACT_BODY_BYTES];
    const uint8_t *effective_carrier = NULL;
    uint16_t effective_carrier_len = 0u;
    uint64_t next_outer_tx;
    uint64_t next_ack_deadline;
    if (owner == NULL || out_tx == NULL) {
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    ninlil_rrmp_memzero(out_tx, sizeof(*out_tx));
    if (!owner->cfg.feature_route_relay) {
        return NINLIL_ROUTE_FEATURE_OFF;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_FORWARD)) {
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_route_write_gate(owner);
        if (gst != NINLIL_ROUTE_OK) {
            return gst;
        }
    }
    if (!owner->downlink_tx || owner->route_ns.fenced) {
        return NINLIL_ROUTE_DRAIN_FENCED;
    }
    q = find_q_by_handle(owner, opaque_local_handle);
    if (q == NULL) {
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (q->owner_scope_set &&
        !ninlil_rrmp_core_scope_seal_allowed(owner, q->owner_scope_id)) {
        return NINLIL_ROUTE_DRAIN_FENCED;
    }
    if (!tx_permit_granted) {
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    /* Application carrier is copy-owned before first physical submit. */
    if (carrier_len > NINLIL_RRMP_OUTBOUND_CARRIER_MAX) {
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (carrier_len != 0u && carrier == NULL) {
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (q->carrier_len != 0u) {
        effective_carrier = queue_carrier(owner, q);
        effective_carrier_len = q->carrier_len;
        if (effective_carrier == NULL) {
            return NINLIL_ROUTE_CORRUPT;
        }
        if (carrier_len != 0u &&
            (carrier_len != q->carrier_len ||
                !ninlil_rrmp_memeq(
                    carrier, effective_carrier, carrier_len))) {
            return NINLIL_ROUTE_AUTHORITY_CONFLICT;
        }
    } else if (carrier_len != 0u) {
        uint16_t off;
        uint32_t charge = NINLIL_RRMP_EXACT_BODY_BYTES + carrier_len;
        if (owner->q_bytes > NINLIL_RRMP_QUEUE_GLOBAL_BYTES - carrier_len ||
            !carrier_arena_append(owner, carrier, carrier_len, &off)) {
            return NINLIL_ROUTE_BACKPRESSURE;
        }
        q->carrier_offset = off;
        q->carrier_len = carrier_len;
        owner->q_bytes += carrier_len;
        effective_carrier = queue_carrier(owner, q);
        effective_carrier_len = carrier_len;
        (void)charge;
        /* Late legacy injection is durable before the provider can observe it. */
        if (!finish_writepoint_full(owner)) {
            owner->route_ns.fenced = 1u;
            owner->downlink_tx = 0u;
            return writepoint_fail_route_status(owner);
        }
    }
    if (q->await_ack) {
        if (owner->cfg.now_ms < q->retry_not_before_ms) {
            return NINLIL_ROUTE_BACKPRESSURE;
        }
        if (q->retry_count >= q->retry_limit) {
            q->await_ack = 0u;
            q->retry_exhausted = 1u;
            if (!finish_writepoint_full(owner)) {
                return writepoint_fail_route_status(owner);
            }
            return NINLIL_ROUTE_RESOURCE;
        }
    }
    if (q->absolute_deadline_ms != 0u &&
        owner->cfg.now_ms >= q->absolute_deadline_ms) {
        q->await_ack = 0u;
        q->retry_exhausted = 1u;
        if (!finish_writepoint_full(owner)) {
            return writepoint_fail_route_status(owner);
        }
        return NINLIL_ROUTE_LEASE_EXPIRED;
    }
    if (q->outer_tx_counter == 0u) {
        if (q->outer_rx_counter == UINT64_MAX) {
            return NINLIL_ROUTE_RESOURCE;
        }
        next_outer_tx = q->outer_rx_counter + 1u;
    } else {
        if (q->outer_tx_counter == UINT64_MAX) {
            return NINLIL_ROUTE_RESOURCE;
        }
        next_outer_tx = q->outer_tx_counter + 1u;
    }
    if (owner->cfg.now_ms >
        UINT64_MAX - (uint64_t)q->link_ack_wait_ms) {
        return NINLIL_ROUTE_RESOURCE;
    }
    next_ack_deadline =
        owner->cfg.now_ms + (uint64_t)q->link_ack_wait_ms;
    /* Rewrap: materialize from active route and require bit-identical E2E body. */
    if (q->e2e_body_len != NINLIL_RRMP_EXACT_BODY_BYTES) {
        return NINLIL_ROUTE_CORRUPT;
    }
    ent = find_route(
        owner, q->ingress_hop_context_id, q->handle, q->gen);
    if (ent == NULL ||
        (ent->state != NINLIL_RRMP_LIFE_ACTIVE &&
            ent->state != NINLIL_RRMP_LIFE_DRAINING)) {
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (!ninlil_rrmp_materialize_exact(&ent->fields, exact)) {
        return NINLIL_ROUTE_CORRUPT;
    }
    if (!ninlil_rrmp_memeq(exact, q->e2e_body, NINLIL_RRMP_EXACT_BODY_BYTES)) {
        return NINLIL_ROUTE_CORRUPT;
    }
    memcpy(rewrap, q->e2e_body, NINLIL_RRMP_EXACT_BODY_BYTES);
    /* Outbound ownership: E2E rewrap + optional app carrier to bearer provider. */
    {
        ninlil_rrmp_outbound_packet_t pkt;
        uint32_t ost;
        if (!owner->outbound_set || owner->outbound.submit == NULL) {
            return NINLIL_ROUTE_UNSUPPORTED_CAPABILITY;
        }
        ninlil_rrmp_memzero(&pkt, sizeof(pkt));
        pkt.opaque_local_handle = q->opaque_handle;
        pkt.route_handle = q->handle;
        pkt.route_generation = q->gen;
        pkt.ingress_hop_context_id = q->ingress_hop_context_id;
        pkt.hop_remaining_out = q->hop_out;
        memcpy(pkt.e2e_body, rewrap, NINLIL_RRMP_EXACT_BODY_BYTES);
        pkt.e2e_len = (uint16_t)NINLIL_RRMP_EXACT_BODY_BYTES;
        if (effective_carrier_len != 0u) {
            memcpy(pkt.carrier, effective_carrier, effective_carrier_len);
            pkt.carrier_len = effective_carrier_len;
        }
        pkt.outer_tx_counter = next_outer_tx;
        if (owner->last_fabric_path_set) {
            memcpy(pkt.fabric_path_id, owner->last_fabric_path_id, 16u);
            pkt.fabric_path_set = 1u;
        }
        if (q->selected_parent_set) {
            memcpy(
                pkt.selected_parent_id, q->selected_parent_id, 16u);
            pkt.selected_parent_set = 1u;
        }
        ost = owner->outbound.submit(owner->outbound.user, &pkt);
        if (ost == NINLIL_RRMP_OUTBOUND_WOULD_BLOCK) {
            return NINLIL_ROUTE_BACKPRESSURE;
        }
        if (ost == NINLIL_RRMP_OUTBOUND_NO_PROVIDER) {
            return NINLIL_ROUTE_UNSUPPORTED_CAPABILITY;
        }
        if (ost == NINLIL_RRMP_OUTBOUND_LOST ||
            ost == NINLIL_RRMP_OUTBOUND_DENIED) {
            return NINLIL_ROUTE_RESOURCE;
        }
        if (ost != NINLIL_RRMP_OUTBOUND_ACCEPTED &&
            ost != NINLIL_RRMP_OUTBOUND_RETAINED) {
            return NINLIL_ROUTE_RESOURCE;
        }
        q->tx_permit = 1u;
        q->tx_done = 1u;
        q->await_ack = 1u;
        q->retry_exhausted = 0u;
        q->outer_tx_counter = pkt.outer_tx_counter;
        q->retry_count = (uint16_t)(q->retry_count + 1u);
        q->ack_deadline_ms = next_ack_deadline;
        q->retry_not_before_ms = next_ack_deadline;
        {
            size_t ei;
            for (ei = 0u; ei < NINLIL_RRMP_EVIDENCE_CAPACITY; ++ei) {
                if (owner->evidence[ei].used &&
                    owner->evidence[ei].opaque_handle == q->opaque_handle) {
                    owner->evidence[ei].outer_tx_counter =
                        q->outer_tx_counter;
                    break;
                }
            }
        }
        /*
         * Provider may already have transmitted. A failed/unknown FULL fences
         * this owner; cold recovery may retry the same semantic carrier.
         */
        if (!finish_writepoint_full(owner)) {
            owner->route_ns.fenced = 1u;
            owner->downlink_tx = 0u;
            return writepoint_fail_route_status(owner);
        }
    }
    out_tx->route_handle = q->handle;
    out_tx->route_generation = q->gen;
    out_tx->ingress_hop_context_id = q->ingress_hop_context_id;
    out_tx->hop_remaining_in = q->hop_in;
    out_tx->hop_remaining_out = q->hop_out;
    memcpy(out_tx->e2e_header, rewrap, NINLIL_RRMP_EXACT_BODY_BYTES);
    out_tx->e2e_len = (uint16_t)NINLIL_RRMP_EXACT_BODY_BYTES;
    if (effective_carrier_len != 0u) {
        memcpy(out_tx->payload, effective_carrier, effective_carrier_len);
        out_tx->payload_len = effective_carrier_len;
        out_tx->carrier_set = 1u;
    } else {
        /* Custody-only hop: view echoes E2E rewrap as payload for diagnostics. */
        memcpy(out_tx->payload, rewrap, NINLIL_RRMP_EXACT_BODY_BYTES);
        out_tx->payload_len = (uint16_t)NINLIL_RRMP_EXACT_BODY_BYTES;
        out_tx->carrier_set = 0u;
    }
    out_tx->outer_rx_counter = q->outer_rx_counter;
    out_tx->outer_tx_counter = q->outer_tx_counter;
    out_tx->rewrap_identical = 1u;
    out_tx->tx_permit_granted = 1u;
    out_tx->link_ack_ok = q->link_ack;
    out_tx->terminal = q->terminal;
    if (q->selected_parent_set) {
        memcpy(out_tx->selected_parent_id, q->selected_parent_id, 16u);
        out_tx->selected_parent_set = 1u;
    }
    owner->diag_forwards += 1u;
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_rrmp_core_link_ack_from_evidence(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_link_ack_evidence_t *evidence,
    ninlil_route_result_v1_t *out)
{
    rrmp_q_t *q;
    rrmp_evi_t *matched_ev = NULL;
    size_t i;
    size_t z = 0u;
    if (owner == NULL || evidence == NULL || out == NULL) {
        result_fill(out, NINLIL_ROUTE_INVALID_ARGUMENT);
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (!owner->cfg.feature_route_relay) {
        result_fill(out, NINLIL_ROUTE_FEATURE_OFF);
        return NINLIL_ROUTE_FEATURE_OFF;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_BEARER)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_route_write_gate(owner);
        if (gst != NINLIL_ROUTE_OK) {
            result_fill(out, gst);
            return gst;
        }
    }
    /* Only authenticated inbound bearer evidence may complete LINK_ACK. */
    if (!evidence->auth_ok || !evidence->ack_ok) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    for (i = 0u; i < 32u; ++i) {
        z |= evidence->auth_proof32[i];
    }
    if (z == 0u) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    q = find_q_by_handle(owner, evidence->opaque_local_handle);
    if (q == NULL) {
        /* Idempotent duplicate authenticated ACK after durable queue release. */
        for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
            rrmp_evi_t *ev = &owner->evidence[i];
            if (ev->used && ev->opaque_handle == evidence->opaque_local_handle &&
                ev->auth_link_ack &&
                ev->outer_tx_counter == evidence->outer_tx_counter &&
                ninlil_rrmp_memeq(
                    ev->auth_peer_runtime_id,
                    evidence->peer_runtime_id, 16u)) {
                result_fill(out, NINLIL_ROUTE_OK);
                out->opaque_local_handle = ev->opaque_handle;
                return NINLIL_ROUTE_OK;
            }
        }
        result_fill(out, NINLIL_ROUTE_NOT_ACTIVE);
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    if (q->link_ack && !q->await_ack) {
        /*
         * A durable ACK intentionally leaves the queue/evidence pair intact
         * until forward_complete closes the attempt. Replaying that same
         * authenticated ACK across a restart is idempotent at this boundary.
         */
        for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
            rrmp_evi_t *ev = &owner->evidence[i];
            if (ev->used &&
                ev->opaque_handle == evidence->opaque_local_handle &&
                ev->auth_link_ack &&
                ev->outer_tx_counter == evidence->outer_tx_counter &&
                evidence->outer_tx_counter == q->outer_tx_counter &&
                ninlil_rrmp_memeq(
                    ev->auth_peer_runtime_id,
                    evidence->peer_runtime_id,
                    16u)) {
                result_fill(out, NINLIL_ROUTE_OK);
                out->route_handle = q->handle;
                out->route_generation = q->gen;
                out->opaque_local_handle = q->opaque_handle;
                out->next_admission_seq = q->admission_seq;
                memcpy(
                    out->evidence_or_digest32, q->e2e_digest, 32u);
                return NINLIL_ROUTE_OK;
            }
        }
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (!q->tx_done || !q->tx_permit || !q->await_ack) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (evidence->outer_tx_counter != q->outer_tx_counter) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    if (!ninlil_rrmp_memeq(
            evidence->peer_runtime_id, q->expected_peer_id, 16u)) {
        result_fill(out, NINLIL_ROUTE_AUTHORITY_CONFLICT);
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    q->link_ack = 1u;
    q->await_ack = 0u;
    /* Mark matching evidence so complete cannot run without real ACK. */
    for (i = 0u; i < NINLIL_RRMP_EVIDENCE_CAPACITY; ++i) {
        if (owner->evidence[i].used &&
            owner->evidence[i].opaque_handle == q->opaque_handle) {
            owner->evidence[i].auth_link_ack = 1u;
            owner->evidence[i].outer_tx_counter = q->outer_tx_counter;
            memcpy(
                owner->evidence[i].auth_peer_runtime_id,
                evidence->peer_runtime_id, 16u);
            matched_ev = &owner->evidence[i];
        }
    }
    if (matched_ev == NULL) {
        result_fill(out, NINLIL_ROUTE_CORRUPT);
        return NINLIL_ROUTE_CORRUPT;
    }
    result_fill(out, NINLIL_ROUTE_OK);
    out->route_handle = q->handle;
    out->route_generation = q->gen;
    out->hop_remaining_out = q->hop_out;
    out->opaque_local_handle = q->opaque_handle;
    out->next_admission_seq = q->admission_seq;
    memcpy(out->evidence_or_digest32, q->e2e_digest, 32u);
    /*
     * ACK authority and the exact scope/attempt queue binding remain durable
     * until forward_complete transitions NEV1 and QST4 in one FULL snapshot.
     * This prevents completion from losing the identity needed by the global
     * used-attempt ledger.
     */
    if (!finish_writepoint_full(owner)) {
        owner->route_ns.fenced = 1u;
        owner->downlink_tx = 0u;
        result_fill(out, writepoint_fail_route_status(owner));
        return out->status;
    }
    return NINLIL_ROUTE_OK;
}

/* Bind optional owner_scope to admitted queue entry (scope seal on hop TX). */
ninlil_route_status_u32 ninlil_rrmp_core_queue_bind_scope(
    ninlil_rrmp_owner_t *owner,
    uint64_t opaque_local_handle,
    const uint8_t owner_scope_id[16])
{
    rrmp_q_t *q;
    if (owner == NULL || owner_scope_id == NULL) {
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    if (!owner_has_capability(owner, NINLIL_RRMP_AUTH_FORWARD)) {
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_route_write_gate(owner);
        if (gst != NINLIL_ROUTE_OK) {
            return gst;
        }
    }
    q = find_q_by_handle(owner, opaque_local_handle);
    if (q == NULL) {
        return NINLIL_ROUTE_NOT_ACTIVE;
    }
    memcpy(q->owner_scope_id, owner_scope_id, 16u);
    q->owner_scope_set = 1u;
    if (!finish_writepoint_full(owner)) {
        owner->route_ns.fenced = 1u;
        owner->downlink_tx = 0u;
        return writepoint_fail_route_status(owner);
    }
    return NINLIL_ROUTE_OK;
}

ninlil_route_status_u32 ninlil_rrmp_core_worker_tick(
    ninlil_rrmp_owner_t *owner,
    uint64_t now_ms,
    uint32_t max_steps,
    ninlil_rrmp_worker_result_v1_t *result)
{
    uint32_t budget;
    size_t i;

    if (owner == NULL || result == NULL) {
        return NINLIL_ROUTE_INVALID_ARGUMENT;
    }
    ninlil_rrmp_memzero(result, sizeof(*result));
    if (!owner->cfg.feature_route_relay) {
        return NINLIL_ROUTE_FEATURE_OFF;
    }
    if (!owner_has_capability(
            owner, NINLIL_RRMP_AUTH_WORKER | NINLIL_RRMP_AUTH_FORWARD)) {
        return NINLIL_ROUTE_AUTHORITY_CONFLICT;
    }
    {
        uint32_t gst = owner_route_write_gate(owner);
        if (gst != NINLIL_ROUTE_OK) {
            return gst;
        }
    }
    budget = max_steps == 0u ? NINLIL_RRMP_WORKER_MAX_STEPS : max_steps;
    if (budget > NINLIL_RRMP_WORKER_MAX_STEPS) {
        budget = NINLIL_RRMP_WORKER_MAX_STEPS;
    }
    owner->cfg.now_ms = now_ms;

    for (i = 0u;
         i < NINLIL_RRMP_QUEUE_GLOBAL_ENTRIES && result->steps < budget;
         ++i) {
        rrmp_q_t *q = &owner->queue[i];
        ninlil_rrmp_hop_tx_view_t tx;
        ninlil_route_status_u32 st;

        if (!q->used) {
            continue;
        }
        if (q->absolute_deadline_ms != 0u &&
            now_ms >= q->absolute_deadline_ms) {
            result->steps += 1u;
            q->await_ack = 0u;
            q->retry_exhausted = 1u;
            result->expired += 1u;
            if (!finish_writepoint_full(owner)) {
                owner->route_ns.fenced = 1u;
                owner->downlink_tx = 0u;
                result->commit_unknown += 1u;
                return writepoint_fail_route_status(owner);
            }
            continue;
        }
        if (!q->await_ack || now_ms < q->retry_not_before_ms) {
            continue;
        }
        result->steps += 1u;
        if (q->retry_count >= q->retry_limit) {
            q->await_ack = 0u;
            q->retry_exhausted = 1u;
            result->exhausted += 1u;
            if (!finish_writepoint_full(owner)) {
                owner->route_ns.fenced = 1u;
                owner->downlink_tx = 0u;
                result->commit_unknown += 1u;
                return writepoint_fail_route_status(owner);
            }
            continue;
        }

        ninlil_rrmp_memzero(&tx, sizeof(tx));
        st = ninlil_rrmp_core_hop_forward_execute(
            owner, q->opaque_handle, NULL, 0u, 1u, &tx);
        if (st == NINLIL_ROUTE_OK) {
            result->submitted += 1u;
        } else if (st == NINLIL_ROUTE_BACKPRESSURE) {
            result->would_block += 1u;
        } else if (st == NINLIL_ROUTE_COMMIT_UNKNOWN ||
                   owner->route_ns.fenced) {
            result->commit_unknown += 1u;
            return st;
        } else if (st == NINLIL_ROUTE_RESOURCE ||
                   st == NINLIL_ROUTE_LEASE_EXPIRED) {
            result->exhausted += 1u;
        } else {
            return st;
        }
    }
    return NINLIL_ROUTE_OK;
}

void ninlil_rrmp_owner_fault_inject_route_cu_old(
    ninlil_rrmp_owner_t *owner, uint8_t key_id)
{
    if (owner == NULL) {
        return;
    }
    ninlil_rrmp_route_inject_cu_old(&owner->route_ns, key_id);
    owner->route_ns.cu_class = ninlil_rrmp_route_classify_cu(&owner->route_ns);
}

void ninlil_rrmp_owner_fault_inject_parent_cu_old(
    ninlil_rrmp_owner_t *owner, uint8_t key_id)
{
    if (owner == NULL) {
        return;
    }
    ninlil_rrmp_parent_inject_cu_old(&owner->parent_ns, key_id);
    owner->parent_ns.cu_class = ninlil_rrmp_parent_classify_cu(&owner->parent_ns);
}

void ninlil_rrmp_owner_fault_inject_route_cu_third(
    ninlil_rrmp_owner_t *owner, uint8_t key_id)
{
    if (owner == NULL) {
        return;
    }
    ninlil_rrmp_route_inject_third(&owner->route_ns, key_id);
    owner->route_ns.cu_class = ninlil_rrmp_route_classify_cu(&owner->route_ns);
    if (owner->route_ns.cu_class != NINLIL_RRMP_CU_THIRD) {
        owner->route_ns.cu_class = NINLIL_RRMP_CU_THIRD;
    }
    owner->route_ns.fenced = 1u;
    owner->downlink_tx = 0u;
}

void ninlil_rrmp_owner_fault_inject_route_corrupt(
    ninlil_rrmp_owner_t *owner, uint8_t key_id)
{
    if (owner == NULL) {
        return;
    }
    ninlil_rrmp_route_inject_corrupt_active(&owner->route_ns, key_id);
    owner->route_ns.cu_class = NINLIL_RRMP_CU_PARTIAL;
    owner->route_ns.fenced = 1u;
    owner->downlink_tx = 0u;
}
