/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Exact private C ABI for ADR-0019 / ADR-0020 (Proposed).
 * Not installed. Layouts are compile-time static-asserted.
 * Symbol surface matches private_api_catalog; no public ABI.
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_ABI_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_ABI_H

#include "rrmp_types.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Force exact wire/storage layout without host ABI padding surprises. */
#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_RRMP_PACKED __attribute__((packed))
#else
#define NINLIL_RRMP_PACKED
#endif

/* --- §2.1 common preamble (both ADRs) --- */
typedef struct NINLIL_RRMP_PACKED ninlil_rrmp_preamble_v1 {
    uint32_t api_version;  /* exact 1 */
    uint32_t struct_size;  /* exact sizeof(this struct) */
    uint32_t reserved0;    /* MUST 0 */
    uint32_t reserved1;    /* MUST 0 */
} ninlil_rrmp_preamble_v1_t;

_Static_assert(sizeof(ninlil_rrmp_preamble_v1_t) == 16u, "preamble 16");
_Static_assert(offsetof(ninlil_rrmp_preamble_v1_t, api_version) == 0u, "pv0");
_Static_assert(offsetof(ninlil_rrmp_preamble_v1_t, struct_size) == 4u, "ps4");
_Static_assert(offsetof(ninlil_rrmp_preamble_v1_t, reserved0) == 8u, "pr8");
_Static_assert(offsetof(ninlil_rrmp_preamble_v1_t, reserved1) == 12u, "pr12");

/* --- Route result exact 128 (ADR-0019 §2.5) --- */
typedef struct NINLIL_RRMP_PACKED ninlil_route_result_v1 {
    uint32_t api_version;             /* 1 */
    uint32_t struct_size;             /* 128 */
    uint32_t reserved0;
    uint32_t reserved1;
    uint32_t status;                  /* matches return */
    uint32_t detail_flags;            /* bit0 cu bit1 drain bit2 fenced */
    uint64_t opaque_local_handle;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint64_t next_admission_seq;
    uint64_t lease_epoch;
    uint64_t route_revision;
    uint64_t controller_term;
    uint32_t hop_remaining_out;
    uint8_t cu_class;
    uint8_t lifecycle_state;
    uint16_t reserved2;
    uint8_t evidence_or_digest32[32];
    uint8_t reserved_tail[16];
} ninlil_route_result_v1_t;

_Static_assert(sizeof(ninlil_route_result_v1_t) == 128u, "route result 128");
_Static_assert(offsetof(ninlil_route_result_v1_t, status) == 16u, "rr status");
_Static_assert(offsetof(ninlil_route_result_v1_t, opaque_local_handle) == 24u,
    "rr handle");
_Static_assert(offsetof(ninlil_route_result_v1_t, cu_class) == 76u, "rr cu");
_Static_assert(offsetof(ninlil_route_result_v1_t, evidence_or_digest32) == 80u,
    "rr dig");

/*
 * Parent result exact 128 (ADR-0020 §2.4).
 * MUST NOT be typedef/alias of ninlil_route_result_v1_t.
 * Distinct fields: handoff_step@72, seal_allowed@75, token_or_commit_digest32@80
 * (route uses hop_remaining_out@72, lifecycle_state@77, evidence_or_digest32@80).
 * rrmp_core.c parent ops write only these parent fields — never lifecycle_state /
 * evidence_or_digest32.
 */
typedef struct NINLIL_RRMP_PACKED ninlil_parent_result_v1 {
    uint32_t api_version;             /* 1 */
    uint32_t struct_size;             /* 128 */
    uint32_t reserved0;
    uint32_t reserved1;
    uint32_t status;                  /* equals return */
    uint32_t detail_flags;            /* bit0 seal_allowed bit1 split_brain bit2 parent_loss */
    uint64_t opaque_local_handle;
    uint8_t owner_scope_id[16];
    uint64_t controller_term;
    uint64_t assignment_revision;
    uint64_t lease_not_after;
    uint8_t handoff_step;             /* 0 none 1..6 — NOT lifecycle_state */
    uint8_t local_state;              /* NPA1 local_state closed set */
    uint8_t cu_class;
    uint8_t seal_allowed;             /* 0/1 downlink seal */
    uint32_t reserved2;
    uint8_t token_or_commit_digest32[32]; /* NOT evidence_or_digest32 */
    uint8_t reserved_tail[16];
} ninlil_parent_result_v1_t;
_Static_assert(sizeof(ninlil_parent_result_v1_t) == 128u, "parent result 128");
_Static_assert(offsetof(ninlil_parent_result_v1_t, status) == 16u, "pr status");
_Static_assert(offsetof(ninlil_parent_result_v1_t, owner_scope_id) == 32u, "pr scope");
_Static_assert(offsetof(ninlil_parent_result_v1_t, handoff_step) == 72u, "pr step");
_Static_assert(offsetof(ninlil_parent_result_v1_t, seal_allowed) == 75u, "pr seal");
_Static_assert(
    offsetof(ninlil_parent_result_v1_t, token_or_commit_digest32) == 80u, "pr dig");

/* --- Route requests --- */

/* install_batch: header 56 + N*256; N<=8 stored as max capacity. */
typedef struct NINLIL_RRMP_PACKED ninlil_route_install_batch_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble; /* 16 */
    uint8_t authority_id[16];           /* 16@16 */
    uint64_t controller_term;           /* 8@32 */
    uint64_t batch_id;                  /* 8@40 */
    uint16_t entry_count;               /* 2@48 */
    uint16_t reserved2;                 /* 2@50 */
    uint32_t reserved3;                 /* 4@52 */
    uint8_t entries[NINLIL_RRMP_INSTALL_BATCH_MAX * NINLIL_RRMP_NRM1_BYTES];
} ninlil_route_install_batch_req_v1_t;

_Static_assert(offsetof(ninlil_route_install_batch_req_v1_t, entries) == 56u,
    "install entries@56");
_Static_assert(
    sizeof(ninlil_route_install_batch_req_v1_t) ==
        (56u + NINLIL_RRMP_INSTALL_BATCH_MAX * NINLIL_RRMP_NRM1_BYTES),
    "install n8 size");

typedef struct NINLIL_RRMP_PACKED ninlil_route_activate_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint64_t now_ms;
    uint64_t expected_route_revision;
    uint64_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
} ninlil_route_activate_req_v1_t;
_Static_assert(sizeof(ninlil_route_activate_req_v1_t) == 64u, "activate 64");

typedef struct NINLIL_RRMP_PACKED ninlil_route_begin_drain_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint64_t now_ms;
    uint64_t drain_deadline_ms;
    uint64_t lease_deadline_ms;
    uint64_t item_deadline_ms;
    uint32_t reason_code;
    uint32_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
} ninlil_route_begin_drain_req_v1_t;
_Static_assert(sizeof(ninlil_route_begin_drain_req_v1_t) == 80u, "drain 80");

typedef struct NINLIL_RRMP_PACKED ninlil_route_retire_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint64_t now_ms;
    uint64_t expected_route_revision;
    uint8_t force;
    uint8_t reserved2[3];
    uint32_t reserved3;
    uint64_t reserved4;
    uint64_t reserved5;
} ninlil_route_retire_req_v1_t;
_Static_assert(sizeof(ninlil_route_retire_req_v1_t) == 64u, "retire 64");

typedef struct NINLIL_RRMP_PACKED ninlil_route_query_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint32_t query_mask;
    uint32_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
} ninlil_route_query_req_v1_t;
_Static_assert(sizeof(ninlil_route_query_req_v1_t) == 48u, "query 48");

typedef struct NINLIL_RRMP_PACKED ninlil_route_forward_admit_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint8_t hop_remaining;
    uint8_t flags; /* bit0 is_frag_transfer */
    uint16_t reserved2;
    uint8_t e2e_header_digest32[32];
    uint64_t outer_rx_counter;
    uint64_t admission_now_ms;
    uint64_t item_deadline_ms;
    uint16_t remaining_link_groups;
    uint16_t remaining_attempts;
    uint32_t max_airtime_ms;
    uint32_t turnaround_ms;
    uint32_t link_ack_wait_ms;
    uint32_t scheduler_guard_ms;
    uint32_t inter_group_gap_ms;
    uint8_t priority_class; /* 0 CONTROL 1 SAFETY 2 NORMAL 3 BULK */
    uint8_t reserved3[3];
    uint64_t caller_item_token;
    uint64_t reserved4;
} ninlil_route_forward_admit_req_v1_t;
_Static_assert(sizeof(ninlil_route_forward_admit_req_v1_t) == 128u, "admit 128");
_Static_assert(
    offsetof(ninlil_route_forward_admit_req_v1_t, e2e_header_digest32) == 28u,
    "admit e2e@28");
_Static_assert(
    offsetof(ninlil_route_forward_admit_req_v1_t, priority_class) == 108u,
    "admit prio@108");

typedef struct NINLIL_RRMP_PACKED ninlil_route_forward_complete_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint64_t opaque_local_handle;
    uint8_t outcome; /* 1 TX_OK 2 TX_FAIL 3 CANCELLED 4 EXPIRED */
    uint8_t reserved2[3];
    uint32_t reserved3;
    uint32_t airtime_used_ms;
    uint32_t reserved4;
    uint64_t completion_now_ms;
    uint64_t reserved5;
    uint64_t reserved6;
} ninlil_route_forward_complete_req_v1_t;
_Static_assert(sizeof(ninlil_route_forward_complete_req_v1_t) == 64u, "complete 64");

typedef struct NINLIL_RRMP_PACKED ninlil_route_cancel_drain_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t ingress_hop_context_id;
    uint16_t route_handle;
    uint16_t route_generation;
    uint64_t now_ms;
    uint64_t expected_drain_fence;
    uint64_t reserved2;
} ninlil_route_cancel_drain_req_v1_t;
_Static_assert(sizeof(ninlil_route_cancel_drain_req_v1_t) == 48u, "cancel 48");

typedef struct NINLIL_RRMP_PACKED ninlil_route_recover_cu_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t observed_group_digest32[32];
    uint8_t expected_class;
    uint8_t reserved2[3];
    uint32_t reserved3;
    uint64_t now_ms;
    uint64_t reserved4;
    uint64_t reserved5;
} ninlil_route_recover_cu_req_v1_t;
_Static_assert(sizeof(ninlil_route_recover_cu_req_v1_t) == 80u, "recover 80");

typedef struct NINLIL_RRMP_PACKED ninlil_route_diagnostics_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t snapshot_mask;
    uint32_t reserved2;
    uint64_t reserved3;
} ninlil_route_diagnostics_req_v1_t;
_Static_assert(sizeof(ninlil_route_diagnostics_req_v1_t) == 32u, "diag 32");

/* --- Parent requests (ADR-0020 §2.3) --- */

typedef struct NINLIL_RRMP_PACKED ninlil_parent_set_install_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble; /* 16 */
    uint8_t owner_scope_id[16];         /* 16@16 */
    uint8_t parent_set_count;           /* 1@32 */
    uint8_t reserved2[3];
    uint8_t path_policy_id[16]; /* 16@36 */
    uint64_t controller_term;   /* 8@52 */
    uint64_t assignment_epoch;  /* 8@60 */
    uint64_t reserved3;         /* 8@68 */
    uint16_t reserved4;         /* 2@76 */
    uint16_t reserved5;         /* 2@78 */
    uint8_t parent_set_digest32[32]; /* 32@80 */
    uint8_t parent_runtime_id[NINLIL_RRMP_PARENT_MAX][16]; /* 128@112 */
} ninlil_parent_set_install_req_v1_t;
_Static_assert(sizeof(ninlil_parent_set_install_req_v1_t) == 240u, "set_install 240");
_Static_assert(
    offsetof(ninlil_parent_set_install_req_v1_t, parent_set_digest32) == 80u,
    "ps dig@80");
_Static_assert(
    offsetof(ninlil_parent_set_install_req_v1_t, parent_runtime_id) == 112u,
    "ps ids@112");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_owner_prepare_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t new_assignment_noa1[NINLIL_RRMP_NOA1_BYTES];
    uint8_t handoff_token_digest32[32];
} ninlil_parent_owner_prepare_req_v1_t;
_Static_assert(sizeof(ninlil_parent_owner_prepare_req_v1_t) == 464u, "prepare 464");
_Static_assert(
    offsetof(ninlil_parent_owner_prepare_req_v1_t, new_assignment_noa1) == 32u,
    "prep noa@32");
_Static_assert(
    offsetof(ninlil_parent_owner_prepare_req_v1_t, handoff_token_digest32) == 432u,
    "prep tok@432");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_owner_fence_proof_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t proof_digest32[32];
    uint64_t old_assignment_revision;
    uint64_t now_ms;
    uint64_t reserved2;
    uint64_t reserved3;
} ninlil_parent_owner_fence_proof_req_v1_t;
_Static_assert(sizeof(ninlil_parent_owner_fence_proof_req_v1_t) == 96u, "fence 96");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_authority_commit_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t authority_commit_digest32[32];
    uint64_t controller_term;
    uint64_t assignment_revision;
    uint64_t cas_expected_generation;
    uint64_t reserved2;
} ninlil_parent_authority_commit_req_v1_t;
_Static_assert(sizeof(ninlil_parent_authority_commit_req_v1_t) == 96u, "commit 96");

/*
 * RRP-3 source-only handoff ABI v2. v1 handoff mutation requests cannot carry
 * the complete old authority tuple and are therefore fail-closed.
 */
#define NINLIL_RRMP_PRIVATE_V2_API_VERSION 2u
#define NINLIL_RRMP_HANDOFF_PROOF_EXPLICIT_RESIGN 1u
#define NINLIL_RRMP_HANDOFF_PROOF_TRUSTED_EXACT_LEASE_EXPIRY 2u

typedef struct NINLIL_RRMP_PACKED ninlil_rrmp_authority_tuple_v2 {
    uint8_t present;
    uint8_t reserved0[3];
    uint32_t exact_noa1_length;
    uint8_t noa1_sha256[32];
    uint64_t assignment_revision;
    uint64_t controller_term;
    uint8_t owner_controller_id[16];
    uint64_t writer_epoch;
    uint64_t lease_not_after_ms;
    uint8_t authority_clock_epoch_id[16];
} ninlil_rrmp_authority_tuple_v2_t;
_Static_assert(sizeof(ninlil_rrmp_authority_tuple_v2_t) == 104u, "authority tuple 104");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, exact_noa1_length) == 4u,
    "authority tuple length@4");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, noa1_sha256) == 8u,
    "authority tuple sha@8");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, assignment_revision) == 40u,
    "authority tuple revision@40");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, controller_term) == 48u,
    "authority tuple term@48");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, owner_controller_id) == 56u,
    "authority tuple writer@56");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, writer_epoch) == 72u,
    "authority tuple writer epoch@72");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, lease_not_after_ms) == 80u,
    "authority tuple lease@80");
_Static_assert(offsetof(ninlil_rrmp_authority_tuple_v2_t, authority_clock_epoch_id) == 88u,
    "authority tuple clock@88");

typedef struct NINLIL_RRMP_PACKED ninlil_rrmp_bundle_witness_v2 {
    uint8_t present;
    uint8_t reserved0[3];
    uint8_t manifest_rrm1[NINLIL_RRMP_RRM1_BYTES];
    uint32_t logical_length;
    uint8_t logical_sha256[32];
} ninlil_rrmp_bundle_witness_v2_t;
_Static_assert(sizeof(ninlil_rrmp_bundle_witness_v2_t) == 296u, "bundle witness 296");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_owner_prepare_req_v2 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    ninlil_rrmp_authority_tuple_v2_t expected_old;
    uint8_t new_assignment_noa1[NINLIL_RRMP_NOA1_BYTES];
    uint8_t handoff_token_digest32[32];
} ninlil_parent_owner_prepare_req_v2_t;
_Static_assert(sizeof(ninlil_parent_owner_prepare_req_v2_t) == 568u, "prepare v2 568");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_owner_fence_proof_req_v2 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    ninlil_rrmp_authority_tuple_v2_t expected_old;
    uint8_t handoff_token_digest32[32];
    uint8_t proof_kind;
    uint8_t reserved2[7];
    uint64_t trusted_now_ms;
    uint8_t explicit_resign_digest32[32];
    uint8_t trusted_clock_epoch_id[16];
    uint8_t reserved_tail[16];
} ninlil_parent_owner_fence_proof_req_v2_t;
_Static_assert(
    sizeof(ninlil_parent_owner_fence_proof_req_v2_t) == 248u, "fence v2 248");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_authority_commit_req_v2 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    ninlil_rrmp_authority_tuple_v2_t expected_old;
    ninlil_rrmp_authority_tuple_v2_t expected_new;
    uint8_t handoff_token_digest32[32];
    uint8_t proof_digest32[32];
    uint8_t authority_commit_digest32[32];
    ninlil_rrmp_bundle_witness_v2_t expected_bundle;
    uint64_t cas_expected_generation;
} ninlil_parent_authority_commit_req_v2_t;
_Static_assert(
    sizeof(ninlil_parent_authority_commit_req_v2_t) == 640u, "commit v2 640");

typedef struct NINLIL_RRMP_PACKED ninlil_rrmp_attempt_reclaim_req_v2 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t attempt_id16[16];
    uint64_t trusted_now_ms;
    uint64_t reserved2;
} ninlil_rrmp_attempt_reclaim_req_v2_t;
_Static_assert(
    sizeof(ninlil_rrmp_attempt_reclaim_req_v2_t) == 64u, "attempt reclaim v2 64");

typedef struct NINLIL_RRMP_PACKED ninlil_rrmp_authority_writer_conflict_req_v2 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t authority_id[16];
    uint8_t writer_a[16];
    uint8_t writer_b[16];
    uint64_t controller_term;
    uint64_t writer_epoch_a;
    uint64_t writer_epoch_b;
    uint8_t authority_clock_epoch_id[16];
} ninlil_rrmp_authority_writer_conflict_req_v2_t;
_Static_assert(
    sizeof(ninlil_rrmp_authority_writer_conflict_req_v2_t) == 104u,
    "authority writer conflict v2 104");

typedef struct NINLIL_RRMP_PACKED ninlil_rrmp_scope_parent_anomaly_req_v2 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t parent_a[16];
    uint8_t parent_b[16];
    uint8_t evidence_digest32[32];
} ninlil_rrmp_scope_parent_anomaly_req_v2_t;
_Static_assert(
    sizeof(ninlil_rrmp_scope_parent_anomaly_req_v2_t) == 96u,
    "scope parent anomaly v2 96");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_owner_activate_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t commit_receipt_digest32[32];
    uint64_t now_ms;
    uint64_t reserved2;
} ninlil_parent_owner_activate_req_v1_t;
_Static_assert(sizeof(ninlil_parent_owner_activate_req_v1_t) == 80u, "activate 80");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_endpoint_observe_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t observed_parent_set_digest32[32];
    uint64_t now_ms;
    uint64_t reserved2;
} ninlil_parent_endpoint_observe_req_v1_t;
_Static_assert(sizeof(ninlil_parent_endpoint_observe_req_v1_t) == 80u, "observe 80");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_owner_retire_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint8_t tombstone_digest32[32];
    uint64_t now_ms;
    uint64_t reserved2;
} ninlil_parent_owner_retire_req_v1_t;
_Static_assert(sizeof(ninlil_parent_owner_retire_req_v1_t) == 80u, "retire 80");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_query_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t owner_scope_id[16];
    uint32_t query_mask;
    uint32_t reserved2;
    uint64_t reserved3;
} ninlil_parent_query_req_v1_t;
_Static_assert(sizeof(ninlil_parent_query_req_v1_t) == 48u, "pquery 48");

/* ADR-0020 §2.3: owner_scope_id@16, observed_assignment_digest32@32, class@64, now@72 */
typedef struct NINLIL_RRMP_PACKED ninlil_parent_recover_cu_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble; /* 16 */
    uint8_t owner_scope_id[16];         /* 16@16 */
    uint8_t observed_assignment_digest32[32]; /* 32@32 */
    uint8_t expected_class;             /* 1@64: 0 probe 1..6 CU */
    uint8_t reserved2[3];               /* MUST 0 */
    uint32_t reserved3;                 /* MUST 0 */
    uint64_t now_ms;                    /* 8@72 */
} ninlil_parent_recover_cu_req_v1_t;
_Static_assert(sizeof(ninlil_parent_recover_cu_req_v1_t) == 80u, "precover 80");
_Static_assert(
    offsetof(ninlil_parent_recover_cu_req_v1_t, owner_scope_id) == 16u, "prcu scope");
_Static_assert(
    offsetof(ninlil_parent_recover_cu_req_v1_t, observed_assignment_digest32) == 32u,
    "prcu dig");
_Static_assert(
    offsetof(ninlil_parent_recover_cu_req_v1_t, expected_class) == 64u, "prcu class");
_Static_assert(
    offsetof(ninlil_parent_recover_cu_req_v1_t, now_ms) == 72u, "prcu now");

typedef struct NINLIL_RRMP_PACKED ninlil_parent_diagnostics_req_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint32_t snapshot_mask;
    uint32_t reserved2;
    uint64_t reserved3;
} ninlil_parent_diagnostics_req_v1_t;
_Static_assert(sizeof(ninlil_parent_diagnostics_req_v1_t) == 32u, "pdiag 32");

/* Priority class (forward admit) */
#define NINLIL_RRMP_PRIO_CONTROL 0u
#define NINLIL_RRMP_PRIO_SAFETY 1u
#define NINLIL_RRMP_PRIO_NORMAL 2u
#define NINLIL_RRMP_PRIO_BULK 3u

/* Lifecycle state in result */
#define NINLIL_RRMP_LIFE_EMPTY 0u
#define NINLIL_RRMP_LIFE_STAGED 1u
#define NINLIL_RRMP_LIFE_ACTIVE 2u
#define NINLIL_RRMP_LIFE_DRAINING 3u
#define NINLIL_RRMP_LIFE_EXPIRED 4u
#define NINLIL_RRMP_LIFE_RETIRED 5u

/*
 * Private catalog serial domain. The caller-owned owner workspace is passed
 * explicitly; no process-global current-owner authority exists.
 */
typedef struct ninlil_rrmp_owner ninlil_rrmp_owner_t;

ninlil_route_status_u32 ninlil_route_install_batch(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_install_batch_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_activate(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_activate_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_begin_drain(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_begin_drain_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_retire(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_retire_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_query(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_query_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_forward_admit(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_admit_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_forward_complete(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_complete_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_cancel_drain(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_cancel_drain_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_recover_commit_unknown(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_recover_cu_req_v1_t *req, ninlil_route_result_v1_t *out);
ninlil_route_status_u32 ninlil_route_diagnostics_snapshot(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_diagnostics_req_v1_t *req, ninlil_route_result_v1_t *out);

ninlil_parent_status_u32 ninlil_parent_set_install(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_set_install_req_v1_t *req, ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_owner_prepare(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_prepare_req_v1_t *req, ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_owner_fence_proof(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_fence_proof_req_v1_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_authority_commit(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_authority_commit_req_v1_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_owner_prepare_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_prepare_req_v2_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_owner_fence_proof_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_fence_proof_req_v2_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_authority_commit_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_authority_commit_req_v2_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_owner_activate(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_activate_req_v1_t *req, ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_endpoint_observe(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_endpoint_observe_req_v1_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_owner_retire(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_owner_retire_req_v1_t *req, ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_query(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_query_req_v1_t *req, ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_recover_commit_unknown(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_recover_cu_req_v1_t *req, ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_parent_diagnostics_snapshot(
    ninlil_rrmp_owner_t *owner,
    const ninlil_parent_diagnostics_req_v1_t *req, ninlil_parent_result_v1_t *out);

/* Owner authorization bind (not public ABI; required before catalog ops). */

typedef struct ninlil_rrmp_owner_config_v1 {
    ninlil_rrmp_preamble_v1_t preamble;
    uint8_t local_runtime_id[16];
    uint8_t authority_id[16];
    uint64_t controller_term;
    uint8_t authority_clock_epoch_id[16];
    uint8_t feature_route_relay;
    uint8_t feature_multi_parent;
    uint8_t max_hops_profile;
    uint8_t authorization_required;
    uint64_t now_ms;
} ninlil_rrmp_owner_config_v1_t;

/*
 * Caller-owned fixed workspace. No heap. Size is published for ESP budget
 * gates; exact value from ninlil_rrmp_owner_workspace_bytes().
 */
size_t ninlil_rrmp_owner_workspace_bytes(void);
ninlil_rrmp_owner_t *ninlil_rrmp_owner_init(
    void *workspace,
    size_t workspace_bytes,
    const ninlil_rrmp_owner_config_v1_t *cfg);
void ninlil_rrmp_owner_fini(ninlil_rrmp_owner_t *owner);
int ninlil_rrmp_owner_bind(ninlil_rrmp_owner_t *owner); /* sets serial domain */

/*
 * Optional production caller authorization. When authorization_required=1,
 * the legacy owner_bind() is fail-closed and callers must use this surface.
 * The provider is the trust boundary: RRMP never treats caller-supplied
 * capability bits or a non-zero proof as self-authenticating.
 */
typedef struct ninlil_rrmp_caller_auth_v1 {
    uint8_t principal_id[16];
    uint32_t capability_mask;
    uint32_t reserved0;
    uint64_t authorization_epoch;
    uint8_t proof32[32];
} ninlil_rrmp_caller_auth_v1_t;

typedef struct ninlil_rrmp_authorizer_v1 {
    void *user;
    int (*authorize)(
        void *user,
        const ninlil_rrmp_caller_auth_v1_t *auth,
        const uint8_t local_runtime_id[16],
        const uint8_t authority_id[16]);
} ninlil_rrmp_authorizer_v1_t;

int ninlil_rrmp_owner_bind_authorized(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_caller_auth_v1_t *auth,
    const ninlil_rrmp_authorizer_v1_t *authorizer);
void ninlil_rrmp_owner_unbind(ninlil_rrmp_owner_t *owner);

/* Fabric select pin (private dispatch seam). */
void ninlil_rrmp_core_set_fabric_path(
    ninlil_rrmp_owner_t *o,
    const uint8_t selected_instance_id[16],
    uint64_t epoch);
int ninlil_rrmp_core_get_fabric_path(
    const ninlil_rrmp_owner_t *o,
    uint8_t selected_instance_id_out[16],
    uint64_t *epoch_out);
void ninlil_rrmp_owner_set_now_ms(ninlil_rrmp_owner_t *owner, uint64_t now_ms);

/* Dual-slot durable export/import for process restart tests. */
int ninlil_rrmp_owner_export_namespace(
    const ninlil_rrmp_owner_t *owner, uint8_t *out, size_t cap, size_t *len);
int ninlil_rrmp_owner_import_namespace(
    ninlil_rrmp_owner_t *owner, const uint8_t *in, size_t len);
uint32_t ninlil_rrmp_owner_cu_class(const ninlil_rrmp_owner_t *owner);
uint32_t ninlil_rrmp_owner_downlink_tx_allowed(const ninlil_rrmp_owner_t *owner);

/*
 * ADR-0020 scope derivation context (not path_policy_id alone).
 * Required when feature_multi_parent is ON before admit binds scope.
 */
typedef struct ninlil_rrmp_scope_derivation_ctx {
    uint8_t endpoint_runtime_id[16];
    uint8_t direction; /* 0 or 1 */
    uint16_t traffic_class;
    uint8_t namespace_len; /* 1..63 */
    uint8_t service_len;  /* 1..63 */
    uint8_t namespace[63];
    uint8_t service[63];
} ninlil_rrmp_scope_derivation_ctx_t;

void ninlil_rrmp_owner_set_scope_derivation(
    ninlil_rrmp_owner_t *owner, const ninlil_rrmp_scope_derivation_ctx_t *ctx);

/*
 * Production durable storage bind (platform storage ops, FULL writepoints).
 * Keys under caller-opened handle: route ns / parent ns / soft attempt fences.
 * COMMIT_UNKNOWN → fence downlink_tx and classify CU.
 * ops is ninlil_storage_ops_t* (from ninlil/platform.h); handle is opaque.
 */
struct ninlil_storage_ops;

int ninlil_rrmp_owner_bind_storage(
    ninlil_rrmp_owner_t *owner,
    const struct ninlil_storage_ops *ops,
    void *handle);

/*
 * Private multi-controller storage authority.
 *
 * The public Storage ABI deliberately guarantees one active writer per
 * exact namespace, but it has no conditional-put operation spanning two
 * independently opened handles.  A deployment that permits more than one
 * Controller participant to reach the same RRMP authority namespace MUST
 * bind this extension.  It is private/default-OFF and does not change the
 * public Storage ABI, wire profile, or installed SDK surface.
 *
 * compare_exchange_full atomically compares the currently durable value by
 * the exact (present,length,SHA-256) tuple and, on a match, replaces it with
 * desired_value at FULL durability.  At most one concurrent caller with the
 * same expected tuple may return OK.
 *
 * On COMMIT_UNKNOWN the provider durably retains the exact OLD/NEW witness
 * before returning. recover_pending_full uses a fresh read, classifies only
 * exact OLD or exact NEW, copies that complete value to out_value, and clears
 * the durable witness before returning OK. PARTIAL/THIRD never return OK.
 * This is what makes classification available after a cold process restart.
 */
#define NINLIL_RRMP_STORAGE_AUTHORITY_V1 1u

#define NINLIL_RRMP_STORAGE_CAS_OK 0u
#define NINLIL_RRMP_STORAGE_CAS_EXPECTED_MISMATCH 1u
#define NINLIL_RRMP_STORAGE_CAS_DEFINITE_FAILURE 2u
#define NINLIL_RRMP_STORAGE_CAS_COMMIT_UNKNOWN 3u
#define NINLIL_RRMP_STORAGE_CAS_CORRUPT 4u

#define NINLIL_RRMP_STORAGE_RECOVERY_NONE 0u
#define NINLIL_RRMP_STORAGE_RECOVERY_OLD 1u
#define NINLIL_RRMP_STORAGE_RECOVERY_NEW 2u
#define NINLIL_RRMP_STORAGE_RECOVERY_PARTIAL 3u
#define NINLIL_RRMP_STORAGE_RECOVERY_THIRD 4u

typedef struct ninlil_rrmp_storage_authority_v1 {
    uint32_t api_version; /* exact NINLIL_RRMP_STORAGE_AUTHORITY_V1 */
    uint32_t struct_size; /* exact sizeof(this struct) */
    void *user;
    uint32_t (*compare_exchange_full)(
        void *user,
        void *handle,
        const uint8_t *key,
        uint32_t key_length,
        uint8_t expected_present,
        uint32_t expected_length,
        const uint8_t expected_digest32[32],
        const uint8_t *desired_value,
        uint32_t desired_length,
        const uint8_t desired_digest32[32]);
    uint32_t (*recover_pending_full)(
        void *user,
        void *handle,
        const uint8_t *key,
        uint32_t key_length,
        uint8_t *out_value,
        uint32_t out_capacity,
        uint32_t *out_length,
        uint32_t *out_classification);
} ninlil_rrmp_storage_authority_v1_t;

/*
 * RRP-1 source-only piece-vector serializable CAS.  The six possible pieces
 * are manifest plus five chunks.  Keys and values are copy-consumed before
 * the callback returns; providers must not retain these pointers.
 */
#define NINLIL_RRMP_STORAGE_AUTHORITY_V2 2u
#define NINLIL_RRMP_STORAGE_AUTHORITY_SERIALIZABLE_PIECE_VECTOR 1u

typedef struct ninlil_rrmp_storage_piece_v2 {
    const uint8_t *key;
    uint32_t key_length;
    const uint8_t *value;
    uint32_t value_length;
    uint8_t present;
    uint8_t reserved0[7];
} ninlil_rrmp_storage_piece_v2_t;

typedef struct ninlil_rrmp_storage_authority_v2 {
    uint32_t api_version;
    uint32_t struct_size;
    uint32_t isolation;
    uint32_t reserved0;
    void *user;
    uint32_t (*compare_exchange_bundle_full)(
        void *user,
        void *handle,
        const ninlil_rrmp_bundle_witness_v2_t *expected,
        const ninlil_rrmp_storage_piece_v2_t *desired_pieces,
        uint32_t desired_piece_count,
        const ninlil_rrmp_bundle_witness_v2_t *desired);
    uint32_t (*recover_pending_bundle_full)(
        void *user,
        void *handle,
        const ninlil_rrmp_bundle_witness_v2_t *old_witness,
        const ninlil_rrmp_bundle_witness_v2_t *new_witness,
        uint32_t *out_classification);
} ninlil_rrmp_storage_authority_v2_t;

int ninlil_rrmp_owner_bind_storage_authority(
    ninlil_rrmp_owner_t *owner,
    const struct ninlil_storage_ops *ops,
    void *handle,
    const ninlil_rrmp_storage_authority_v1_t *authority);
int ninlil_rrmp_owner_bind_storage_authority_v2(
    ninlil_rrmp_owner_t *owner,
    const struct ninlil_storage_ops *ops,
    void *handle,
    const ninlil_rrmp_storage_authority_v2_t *authority);
/* FULL writepoint: export dual namespaces + soft attempt fences. */
int ninlil_rrmp_owner_storage_commit_full(ninlil_rrmp_owner_t *owner);
/* Restart: load FULL snapshot, rehydrate, CU classify. */
int ninlil_rrmp_owner_storage_recover(ninlil_rrmp_owner_t *owner);

/*
 * Bounded outbound packet ownership (bearer/radio). Without a provider,
 * hop TX refuses (no fabricated send/ACK).
 *
 * e2e_body: NRM1 rewrap (bit-identical admit materialize).
 * carrier: optional application bytes (e.g. NCL1) for production bearer seam.
 * Same carrier bytes the provider submits are what Fabric/WiFi must emit.
 */
typedef struct ninlil_rrmp_outbound_packet {
    uint64_t opaque_local_handle;
    uint16_t route_handle;
    uint16_t route_generation;
    uint32_t ingress_hop_context_id;
    uint8_t hop_remaining_out;
    uint8_t e2e_body[96];
    uint16_t e2e_len;
    uint8_t carrier[NINLIL_RRMP_OUTBOUND_CARRIER_MAX];
    uint16_t carrier_len;
    uint64_t outer_tx_counter;
    uint8_t fabric_path_id[16];
    uint8_t fabric_path_set;
    uint8_t selected_parent_id[16];
    uint8_t selected_parent_set;
} ninlil_rrmp_outbound_packet_t;

typedef struct ninlil_rrmp_outbound_provider {
    void *user;
    /* Return NINLIL_RRMP_OUTBOUND_* ; provider owns packet on RETAINED/ACCEPTED. */
    uint32_t (*submit)(
        void *user, const ninlil_rrmp_outbound_packet_t *pkt);
} ninlil_rrmp_outbound_provider_t;

void ninlil_rrmp_owner_set_outbound_provider(
    ninlil_rrmp_owner_t *owner, const ninlil_rrmp_outbound_provider_t *provider);

/*
 * Authenticated LINK_ACK evidence from inbound bearer only.
 * auth_ok must be 1, auth_proof32 non-zero, outer_tx_counter must match submit.
 */
typedef struct ninlil_rrmp_link_ack_evidence {
    uint64_t opaque_local_handle;
    uint8_t auth_ok;
    uint8_t ack_ok;
    uint64_t outer_tx_counter;
    uint8_t peer_runtime_id[16];
    uint8_t auth_proof32[32];
} ninlil_rrmp_link_ack_evidence_t;

/* Production SM entrypoints used by seams/sim driver (not manual fake). */
ninlil_route_status_u32 ninlil_rrmp_core_forward_service_once(
    ninlil_rrmp_owner_t *owner, ninlil_route_result_v1_t *out);
/*
 * Same-attempt fence uses exact durable attempt_id16 (not uint64).
 * Selection ordinal = BE u16 at attempt_id16[14..15] (1-based); must be non-zero.
 */
ninlil_parent_status_u32 ninlil_rrmp_core_parent_select_for_attempt(
    ninlil_rrmp_owner_t *owner,
    const uint8_t owner_scope_id[16],
    const uint8_t attempt_id16[16],
    uint8_t selected_parent_out[16],
    ninlil_parent_result_v1_t *out);
/* Scope-local only: does not seal unrelated scopes or halt entire runtime. */
ninlil_parent_status_u32 ninlil_rrmp_core_split_brain_detect(
    ninlil_rrmp_owner_t *owner,
    const uint8_t owner_scope_id[16],
    const uint8_t writer_a[16],
    const uint8_t writer_b[16],
    uint64_t term_a,
    uint64_t term_b);
ninlil_parent_status_u32 ninlil_rrmp_core_attempt_reclaim_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_attempt_reclaim_req_v2_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_rrmp_core_authority_writer_conflict_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_authority_writer_conflict_req_v2_t *req,
    ninlil_parent_result_v1_t *out);
ninlil_parent_status_u32 ninlil_rrmp_core_scope_parent_anomaly_v2(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_scope_parent_anomaly_req_v2_t *req,
    ninlil_parent_result_v1_t *out);

ninlil_parent_status_u32 ninlil_rrmp_core_parent_loss(
    ninlil_rrmp_owner_t *owner,
    const uint8_t owner_scope_id[16],
    const uint8_t lost_parent_id[16]);

/* Scope-local downlink seal gate (0 under split-brain / parent-loss / bad CU). */
uint8_t ninlil_rrmp_core_scope_seal_allowed(
    const ninlil_rrmp_owner_t *owner, const uint8_t owner_scope_id[16]);

/*
 * Production hop path: rewrap E2E bit-identical, optional app carrier, TxPermit.
 * carrier (payload arg): application bytes (NCL1 etc.) forwarded to outbound
 * provider; does NOT replace NRM1 e2e rewrap. NULL/0 = custody hop without app.
 */
typedef struct ninlil_rrmp_hop_tx_view {
    uint16_t route_handle;
    uint16_t route_generation;
    uint32_t ingress_hop_context_id;
    uint8_t hop_remaining_in;
    uint8_t hop_remaining_out;
    uint8_t e2e_header[96]; /* NRM1 exact 96 materialization */
    uint16_t e2e_len;
    uint8_t payload[NINLIL_RRMP_OUTBOUND_CARRIER_MAX]; /* app carrier or e2e */
    uint16_t payload_len;
    uint8_t carrier_set; /* 1 if hop carried application bytes */
    uint64_t outer_rx_counter;
    uint64_t outer_tx_counter;
    uint8_t rewrap_identical; /* 1 if E2E bytes unchanged across hop */
    uint8_t tx_permit_granted;
    uint8_t link_ack_ok;
    uint8_t terminal;
    uint8_t selected_parent_id[16];
    uint8_t selected_parent_set;
} ninlil_rrmp_hop_tx_view_t;

/*
 * Durable admission variant used by production seams. ApplicationData and
 * attempt identity are copy-owned before success; no borrowed pointer remains.
 * attempt_id16 is required when multi-parent is enabled.
 */
ninlil_route_status_u32 ninlil_rrmp_core_forward_admit_with_carrier(
    ninlil_rrmp_owner_t *owner,
    const ninlil_route_forward_admit_req_v1_t *req,
    const uint8_t *carrier,
    uint16_t carrier_len,
    const uint8_t attempt_id16[16],
    ninlil_route_result_v1_t *out);

ninlil_route_status_u32 ninlil_rrmp_core_hop_forward_execute(
    ninlil_rrmp_owner_t *owner,
    uint64_t opaque_local_handle,
    const uint8_t *carrier,
    uint16_t carrier_len,
    uint8_t tx_permit_granted,
    ninlil_rrmp_hop_tx_view_t *out_tx);

/*
 * LINK_ACK only from authenticated inbound bearer evidence.
 * Simulated ack_ok=1 without evidence is rejected (AUTHORITY_CONFLICT).
 */
ninlil_route_status_u32 ninlil_rrmp_core_link_ack_from_evidence(
    ninlil_rrmp_owner_t *owner,
    const ninlil_rrmp_link_ack_evidence_t *evidence,
    ninlil_route_result_v1_t *out);

/* Bind admitted queue entry to owner_scope for scope-local seal checks on hop TX. */
ninlil_route_status_u32 ninlil_rrmp_core_queue_bind_scope(
    ninlil_rrmp_owner_t *owner,
    uint64_t opaque_local_handle,
    const uint8_t owner_scope_id[16]);

typedef struct ninlil_rrmp_worker_result_v1 {
    uint32_t steps;
    uint32_t submitted;
    uint32_t would_block;
    uint32_t exhausted;
    uint32_t expired;
    uint32_t commit_unknown;
} ninlil_rrmp_worker_result_v1_t;

/*
 * Bounded timeout/retry worker. It only retries copy-owned durable queue
 * records that already hold TxPermit; it never invents LINK_ACK.
 */
ninlil_route_status_u32 ninlil_rrmp_core_worker_tick(
    ninlil_rrmp_owner_t *owner,
    uint64_t now_ms,
    uint32_t max_steps,
    ninlil_rrmp_worker_result_v1_t *result);

/* Fault-injection (host tests): force dual-slot CU classes + fence. */
void ninlil_rrmp_owner_fault_inject_route_cu_old(
    ninlil_rrmp_owner_t *owner, uint8_t key_id);
void ninlil_rrmp_owner_fault_inject_parent_cu_old(
    ninlil_rrmp_owner_t *owner, uint8_t key_id);
void ninlil_rrmp_owner_fault_inject_route_cu_third(
    ninlil_rrmp_owner_t *owner, uint8_t key_id);
void ninlil_rrmp_owner_fault_inject_route_corrupt(
    ninlil_rrmp_owner_t *owner, uint8_t key_id);

/* Drain eligibility: remaining_attempts participates (F,A,T,W,I,G formula). */
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
    uint8_t *eligible_out);

/* Precedence helpers (KAT). */
uint32_t ninlil_rrmp_route_precedence_pick(const uint8_t flags[22]);
uint32_t ninlil_rrmp_parent_precedence_pick(const uint8_t flags[22]);
const char *const *ninlil_rrmp_route_precedence_names(void);
const char *const *ninlil_rrmp_parent_precedence_names(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_ABI_H */
