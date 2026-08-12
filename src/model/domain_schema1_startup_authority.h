/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_MODEL_DOMAIN_SCHEMA1_STARTUP_AUTHORITY_H
#define NINLIL_MODEL_DOMAIN_SCHEMA1_STARTUP_AUTHORITY_H

/*
 * ADR-0022 private Domain schema1 startup authority: T1b–T7, kind-1, LAB
 * quarantine/export classification. Feature-gated. Not installed. Not public
 * ABI. Does not integrate into runtime_public / Core recovery paths.
 *
 * Reuses T1a bootstrap plan authority (domain_schema1_runtime_binding.h).
 * Default compile feature OFF (NINLIL_ENABLE_DOMAIN_SCHEMA1_RUNTIME_BINDING).
 */

#include "domain_schema1_runtime_binding.h"

#include <ninlil/version.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_DOMAIN_SCHEMA1_METADATA_RECORD_COUNT ((uint32_t)16u)
#define NINLIL_DOMAIN_SCHEMA1_INDEX_MEMBER_COUNT ((uint32_t)15u)
#define NINLIL_DOMAIN_SCHEMA1_METADATA_VALUE_MAX_BYTES ((uint32_t)256u)
#define NINLIL_DOMAIN_SCHEMA1_METADATA_KEY_MAX_BYTES ((uint32_t)64u)
#define NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_COUNT ((uint32_t)5u)
/* M=5 members + ACTIVE WITNESS_HEADER + WITNESS_MANIFEST_CHUNK. */
#define NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT ((uint32_t)7u)
/* First SERVICE_REGISTER on semantic-empty Domain: 33 baseline + 5 CREATE. */
#define NINLIL_DOMAIN_SCHEMA1_KIND1_FIRST_POST_NS_ROW_COUNT ((uint32_t)38u)
#define NINLIL_DOMAIN_SCHEMA1_STARTUP_STAGE_COUNT ((uint32_t)13u)
#define NINLIL_DOMAIN_SCHEMA1_STARTUP_SEAL_MAGIC ((uint32_t)0x44325437u)

/*
 * Group / CU classification.
 * T1b/T5 use CORRUPT/OLD/NEW only. Kind-1 also emits ABSENT/PARTIAL/EXTRA/THIRD.
 */
typedef enum ninlil_domain_schema1_group_class {
    NINLIL_DOMAIN_SCHEMA1_GROUP_CORRUPT = 0,
    NINLIL_DOMAIN_SCHEMA1_GROUP_OLD = 1, /* ALL_OLD (ADR kind-1) */
    NINLIL_DOMAIN_SCHEMA1_GROUP_NEW = 2, /* ALL_NEW */
    NINLIL_DOMAIN_SCHEMA1_GROUP_ABSENT = 3,
    NINLIL_DOMAIN_SCHEMA1_GROUP_PARTIAL = 4,
    NINLIL_DOMAIN_SCHEMA1_GROUP_EXTRA = 5,
    NINLIL_DOMAIN_SCHEMA1_GROUP_THIRD = 6
} ninlil_domain_schema1_group_class_t;

/* Canonical startup stages in exact ADR-0022 order (including Bearer/T7). */
typedef enum ninlil_domain_schema1_startup_stage {
    NINLIL_DOMAIN_SCHEMA1_STAGE_T0 = 0,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T1A = 1,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T1B = 2,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T2 = 3,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T3 = 4,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T4 = 5,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T5_SAMPLE = 6,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T5_COMMIT = 7,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T6 = 8,
    NINLIL_DOMAIN_SCHEMA1_STAGE_BEARER_OPEN = 9,
    NINLIL_DOMAIN_SCHEMA1_STAGE_METRICS_ENTROPY = 10,
    NINLIL_DOMAIN_SCHEMA1_STAGE_T7 = 11,
    NINLIL_DOMAIN_SCHEMA1_STAGE_PUBLISH = 12
} ninlil_domain_schema1_startup_stage_t;

typedef enum ninlil_domain_schema1_lab_namespace_class {
    NINLIL_DOMAIN_SCHEMA1_LAB_NS_EMPTY = 0,
    NINLIL_DOMAIN_SCHEMA1_LAB_NS_EXACT_LAB = 1,
    NINLIL_DOMAIN_SCHEMA1_LAB_NS_EXACT_DOMAIN = 2,
    NINLIL_DOMAIN_SCHEMA1_LAB_NS_MIXED = 3,
    NINLIL_DOMAIN_SCHEMA1_LAB_NS_CORRUPT = 4,
    NINLIL_DOMAIN_SCHEMA1_LAB_NS_UNSUPPORTED = 5
} ninlil_domain_schema1_lab_namespace_class_t;

typedef enum ninlil_domain_schema1_kind1_action {
    NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_CREATE = 1,
    NINLIL_DOMAIN_SCHEMA1_KIND1_ACTION_REPLACE = 2
} ninlil_domain_schema1_kind1_action_t;

/* Sealed T1b 16-row UNINITIALIZED metadata plan (rebuilds from T1a seal). */
typedef struct ninlil_domain_schema1_metadata_plan {
    ninlil_domain_schema1_bootstrap_plan_t sealed_bootstrap;
    uint32_t record_count;
    uint32_t sealed_record_count;
    uint32_t sealed_crc32c;
    uint32_t sealed_magic;
} ninlil_domain_schema1_metadata_plan_t;

typedef struct ninlil_domain_schema1_metadata_record {
    uint8_t key[NINLIL_DOMAIN_SCHEMA1_METADATA_KEY_MAX_BYTES];
    uint32_t key_length;
    uint8_t value[NINLIL_DOMAIN_SCHEMA1_METADATA_VALUE_MAX_BYTES];
    uint32_t value_length;
} ninlil_domain_schema1_metadata_record_t;

/* T5 trusted-clock plan: pinned sample + exact UNINITIALIZED/TRUSTED values. */
typedef struct ninlil_domain_schema1_t5_clock_plan {
    uint8_t trusted_clock_epoch[16];
    uint64_t now_ms;
    uint64_t publish_generation;
    uint8_t old_value[NINLIL_DOMAIN_SCHEMA1_METADATA_VALUE_MAX_BYTES];
    uint32_t old_value_length;
    uint8_t new_value[NINLIL_DOMAIN_SCHEMA1_METADATA_VALUE_MAX_BYTES];
    uint32_t new_value_length;
    uint8_t clock_key[NINLIL_DOMAIN_SCHEMA1_METADATA_KEY_MAX_BYTES];
    uint32_t clock_key_length;
    uint32_t sealed_crc32c;
    uint32_t sealed_magic;
} ninlil_domain_schema1_t5_clock_plan_t;

/*
 * Pure stage machine / publication authority. No Storage, Bearer, or
 * runtime_public side effects — only records which stages may have completed.
 */
typedef struct ninlil_domain_schema1_startup_state {
    uint32_t completed_mask; /* bit i set => stage i completed */
    uint32_t attempted_mask;
    uint32_t fenced;
    uint32_t fault_stage; /* NINLIL_DOMAIN_SCHEMA1_STAGE_* or 0xFFu if none */
    uint32_t t5_commit_attempt_count;
    uint32_t t6_health_attempt_count;
    uint32_t bearer_open;
    uint32_t metrics_entropy;
    uint32_t callback;
    uint32_t public_handle;
    uint32_t publish;
    uint32_t sealed_magic;
} ninlil_domain_schema1_startup_state_t;

typedef struct ninlil_domain_schema1_startup_transcript {
    uint32_t T0_complete;
    uint32_t T1a_complete;
    uint32_t T1b_complete;
    uint32_t T2_complete;
    uint32_t T3_complete;
    uint32_t T4_complete;
    uint32_t T5_commit_attempt_count;
    uint32_t T5_complete;
    uint32_t T6_complete;
    uint32_t T6_health_attempt_count;
    uint32_t T7_complete;
    uint32_t bearer_open;
    uint32_t metrics_entropy;
    uint32_t callback;
    uint32_t public_handle;
    uint32_t publish;
    uint32_t storage_recovery_complete;
} ninlil_domain_schema1_startup_transcript_t;

/* Kind-1 SERVICE_REGISTER M=5 atomic member descriptor (no callback store). */
typedef struct ninlil_domain_schema1_kind1_member {
    ninlil_domain_schema1_kind1_action_t action;
    uint8_t key[NINLIL_DOMAIN_SCHEMA1_METADATA_KEY_MAX_BYTES];
    uint32_t key_length;
    uint8_t value_digest[32];
} ninlil_domain_schema1_kind1_member_t;

/*
 * One of 7 post-image records (5 members + header + chunk). Digests are of
 * complete encoded values. CREATE pre_digest is all-zero.
 */
typedef struct ninlil_domain_schema1_kind1_post_record {
    ninlil_domain_schema1_kind1_action_t action;
    uint8_t key[NINLIL_DOMAIN_SCHEMA1_METADATA_KEY_MAX_BYTES];
    uint32_t key_length;
    uint8_t pre_value_digest[32];
    uint8_t post_value_digest[32];
} ninlil_domain_schema1_kind1_post_record_t;

typedef struct ninlil_domain_schema1_kind1_plan {
    uint32_t member_count; /* exact 5 */
    ninlil_domain_schema1_kind1_member_t members[
        NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_COUNT];
    uint8_t operation_identity[32];
    uint8_t witness_composite[32];
    /* Sealed after encode: full 7-record post inventory for CU/reattach. */
    uint32_t post_record_count; /* exact 7 when sealed with witness */
    ninlil_domain_schema1_kind1_post_record_t post_records[
        NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT];
    uint32_t sealed_crc32c;
    uint32_t sealed_magic;
} ninlil_domain_schema1_kind1_plan_t;

/* --- T1b metadata FULL (15 BASELINE index + 1 UNINITIALIZED clock) --- */

ninlil_status_t ninlil_domain_schema1_build_metadata_plan(
    const ninlil_domain_schema1_bootstrap_plan_t *bootstrap_plan,
    ninlil_domain_schema1_metadata_plan_t *out_plan);

ninlil_status_t ninlil_domain_schema1_metadata_record_at(
    const ninlil_domain_schema1_metadata_plan_t *plan,
    uint32_t index,
    ninlil_domain_schema1_metadata_record_t *out_record);

/*
 * COMMIT_UNKNOWN classification for the T1b 16-row metadata group.
 * OLD: bootstrap 17 exact present, metadata 0, no extras.
 * NEW: bootstrap 17 exact + metadata 16 exact UNINITIALIZED, no extras.
 * Else CORRUPT (partial/extra/third/TRUSTED mix).
 * Materialised metadata rows must equal declared counts (no undercount exception).
 */
ninlil_status_t ninlil_domain_schema1_classify_t1b_commit_unknown(
    const ninlil_domain_schema1_bootstrap_plan_t *bootstrap_plan,
    const ninlil_domain_schema1_metadata_plan_t *metadata_plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_group_class_t *out_class);

/* --- T5 trusted clock FULL --- */

ninlil_status_t ninlil_domain_schema1_build_t5_clock_plan(
    const uint8_t trusted_clock_epoch[16],
    uint64_t now_ms,
    uint64_t publish_generation,
    ninlil_domain_schema1_t5_clock_plan_t *out_plan);

ninlil_status_t ninlil_domain_schema1_classify_t5_commit_unknown(
    const ninlil_domain_schema1_t5_clock_plan_t *plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_group_class_t *out_class);

/* --- T2–T7 pure stage / publication authority --- */

ninlil_status_t ninlil_domain_schema1_startup_init(
    ninlil_domain_schema1_startup_state_t *state);

/*
 * Mark stage complete only if all prior stages are complete and state is not
 * fenced. Bearer/callback/handle/publish remain 0 until the respective stages.
 * Fault fences the candidate (no partial publication).
 */
ninlil_status_t ninlil_domain_schema1_startup_complete_stage(
    ninlil_domain_schema1_startup_state_t *state,
    ninlil_domain_schema1_startup_stage_t stage);

ninlil_status_t ninlil_domain_schema1_startup_fault(
    ninlil_domain_schema1_startup_state_t *state,
    ninlil_domain_schema1_startup_stage_t fault_stage,
    ninlil_status_t fault_status);

/* 1 only after STAGE_PUBLISH completed without fence. */
int ninlil_domain_schema1_startup_publication_allowed(
    const ninlil_domain_schema1_startup_state_t *state);

/* Exact publication zeros before T7/PUBLISH gates. */
int ninlil_domain_schema1_startup_pre_publish_side_effects_zero(
    const ninlil_domain_schema1_startup_state_t *state);

ninlil_status_t ninlil_domain_schema1_startup_export_transcript(
    const ninlil_domain_schema1_startup_state_t *state,
    ninlil_domain_schema1_startup_transcript_t *out_transcript);

/* --- Kind-1 SERVICE_REGISTER M=5 atomic plan (descriptor digests only) --- */

/*
 * Builds the fixed M=5 member order from capacity SERVICE key + complete
 * SERVICE/QUOTA/RESERVATION/HEAD keys and post-value digests. Does not store
 * callbacks. COMMIT_UNKNOWN ALL_NEW still yields handle/callback 0.
 */
ninlil_status_t ninlil_domain_schema1_kind1_build_plan(
    const uint8_t *capacity_service_key,
    uint32_t capacity_service_key_length,
    const uint8_t capacity_post_value_digest[32],
    const uint8_t *service_key,
    uint32_t service_key_length,
    const uint8_t service_post_value_digest[32],
    const uint8_t *quota_key,
    uint32_t quota_key_length,
    const uint8_t quota_post_value_digest[32],
    const uint8_t *reservation_key,
    uint32_t reservation_key_length,
    const uint8_t reservation_post_value_digest[32],
    const uint8_t *head_index_key,
    uint32_t head_index_key_length,
    const uint8_t head_index_post_value_digest[32],
    const uint8_t service_complete_key_digest[32],
    ninlil_domain_schema1_kind1_plan_t *out_plan);

ninlil_status_t ninlil_domain_schema1_kind1_member_at(
    const ninlil_domain_schema1_kind1_plan_t *plan,
    uint32_t ordinal /* 0..4 */,
    ninlil_domain_schema1_kind1_member_t *out_member);

/* Seal after filling post_records[7] (header+chunk digests). */
ninlil_status_t ninlil_domain_schema1_kind1_plan_finish(
    ninlil_domain_schema1_kind1_plan_t *plan);

/*
 * Kind-1 CU / reattach classification over a fresh RO namespace snapshot.
 * Requires plan.post_record_count==7 (header+chunk sealed). Uses pre_rows for
 * ALL_OLD capacity/index pre-image and EXTRA (keys outside pre∪group).
 * D1 classify_row failure on any group/pre/post row → CORRUPT (fail closed).
 * Returns ABSENT / OLD / NEW / PARTIAL / EXTRA / THIRD / CORRUPT.
 */
ninlil_status_t ninlil_domain_schema1_classify_kind1_commit_unknown(
    const ninlil_domain_schema1_kind1_plan_t *plan,
    const ninlil_domain_schema1_snapshot_row_t *pre_rows,
    uint32_t pre_row_count,
    const ninlil_domain_schema1_snapshot_row_t *post_rows,
    uint32_t post_row_count,
    ninlil_domain_schema1_group_class_t *out_class);

/*
 * Existing-namespace adopt (post-T5 / post-kind1): every row D1-current,
 * binding+identity exact, no LAB mix, no count-only fallback.
 * Returns OK only when namespace is safe to continue T2–T7; else CORRUPT.
 */
ninlil_status_t ninlil_domain_schema1_classify_existing_namespace_adopt(
    const ninlil_domain_schema1_bootstrap_plan_t *bootstrap_plan,
    const ninlil_domain_schema1_snapshot_row_t *rows,
    uint32_t row_count,
    ninlil_domain_schema1_group_class_t *out_class);

/* --- Read-only LAB quarantine / export namespace classifier --- */

/*
 * Binding format discriminator + metadata shape fence for quarantine only.
 * Never elevates LAB evidence to Canonical publication authority.
 *
 * binding_format: 1 = LAB, 2 = Domain, 0 = absent/unknown.
 * metadata_exact_uninit: 1 if exact 16-row UNINITIALIZED group present.
 * lab_distinct_present: 1 if any LAB-only kind 20–34 row present.
 * domain_semantic_present: 1 if Domain semantic/witness beyond metadata present.
 * duplicate_same_key: 1 if iterator returned duplicate complete keys.
 */
ninlil_status_t ninlil_domain_schema1_lab_classify_namespace(
    uint32_t binding_format,
    uint32_t bootstrap_exact,
    uint32_t metadata_exact_uninit,
    uint32_t metadata_partial,
    uint32_t lab_distinct_present,
    uint32_t domain_semantic_present,
    uint32_t duplicate_same_key,
    ninlil_domain_schema1_lab_namespace_class_t *out_class);

/* Export artifact framing constants (read-only; no write path). */
#define NINLIL_DOMAIN_SCHEMA1_EXPORT_MAGIC_BYTES 8u

int ninlil_domain_schema1_export_magic_match(
    const uint8_t *bytes,
    uint32_t length);

/*
 * Read-only key discriminator for quarantine/export and mixed-namespace
 * rejection.  A format-2 Domain owner must reject any matching key; it must
 * never skip, adopt, or write these V1-LAB operational markers
 * (TX/CN/DS/EV/.../NRS/M4T/C3R) in its canonical namespace.
 */
int ninlil_domain_schema1_is_lab_operational_key(
    const uint8_t *key,
    uint32_t key_length);

#ifdef __cplusplus
}
#endif

#endif
