#ifndef NINLIL_R7_R2_AUTHORITY_CLOCK_H
#define NINLIL_R7_R2_AUTHORITY_CLOCK_H

/*
 * docs/30 §11.2.3 closed R2 private authority-clock sample primitive.
 *
 * Sole stampable sample owner for L1 (Radio Coordinator). W1 MUST NOT call.
 * Not public ABI. Not installed. Process-local private module only.
 *
 * Contract:
 *   - closed request (explicit L1 copy-in; no implicit L1/W1 load)
 *   - closed result with typed SAMPLE_* class (never collapse to UNBOUND)
 *   - four-way epoch class A/B/C/D via floors M=ram_trust, W=L1 watermark
 *   - 16B epoch ids from sample; three-axis mutation catalog
 *   - routine path uses ram_trust mirror (no storage RO on hot path)
 */

#include "pcp_authority.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- typed_class (docs/30 §11.2.3 closed; dense 0..) ---- */
#define NINLIL_R2_SAMPLE_UNBOUND ((uint8_t)0u)
#define NINLIL_R2_SAMPLE_META_UNPUBLISHED ((uint8_t)1u)
#define NINLIL_R2_SAMPLE_TRUST_MIRROR_INVALID ((uint8_t)2u)
#define NINLIL_R2_SAMPLE_BUSY ((uint8_t)3u)
#define NINLIL_R2_SAMPLE_REENTRY ((uint8_t)4u)
#define NINLIL_R2_SAMPLE_ALIAS ((uint8_t)5u)
#define NINLIL_R2_SAMPLE_SHUTDOWN ((uint8_t)6u)
#define NINLIL_R2_SAMPLE_STORAGE_IO ((uint8_t)7u)
#define NINLIL_R2_SAMPLE_COMMIT_UNKNOWN ((uint8_t)8u)
#define NINLIL_R2_SAMPLE_CORRUPT ((uint8_t)9u)
#define NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH ((uint8_t)10u) /* class D */
#define NINLIL_R2_SAMPLE_W1_REPAIR ((uint8_t)11u) /* class A */
#define NINLIL_R2_SAMPLE_AUTHORITY_DIVERGENCE ((uint8_t)12u) /* class B */
#define NINLIL_R2_SAMPLE_EPOCH_TRANSITION_REQUIRED ((uint8_t)13u) /* class C */
#define NINLIL_R2_SAMPLE_TEMP_UNCERTAIN ((uint8_t)14u)
#define NINLIL_R2_SAMPLE_CLOCK_FAULT ((uint8_t)15u)
#define NINLIL_R2_SAMPLE_INVALID_ARGUMENT ((uint8_t)16u)

/* Three-axis sample-path closed enums (docs/30 §11.2.3). */
#define NINLIL_R2_SAMPLE_BUSINESS_ZERO ((uint8_t)0u)
#define NINLIL_R2_SAMPLE_META_ZERO ((uint8_t)0u)
#define NINLIL_R2_SAMPLE_F_C_FULL ((uint8_t)1u)
#define NINLIL_R2_SAMPLE_META_AMBIGUOUS ((uint8_t)2u)
#define NINLIL_R2_SAMPLE_PRECHECK_ZERO ((uint8_t)0u)
#define NINLIL_R2_SAMPLE_CLOCK_FENCE_COMMITTED ((uint8_t)1u)
#define NINLIL_R2_SAMPLE_PROV_AMBIGUOUS ((uint8_t)2u)

#define NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP ((uint8_t)1u)

/* meta_state closed (docs/30 §11.2.3.1). */
#define NINLIL_R2_META_STATE_UNPUBLISHED ((uint8_t)0u)
#define NINLIL_R2_META_STATE_TRUSTED_BASELINE ((uint8_t)1u)
#define NINLIL_R2_META_STATE_INITIAL_UNTRUSTED_FENCED ((uint8_t)2u)

/* Closed request: L1 copy-in only (SAMPLE_NO_IMPLICIT_W1_LOAD). */
typedef struct ninlil_r2_authority_clock_request {
    uint8_t expected_epoch_id[16];
    uint8_t watermark_valid; /* 0|1 */
    uint8_t watermark_epoch_id[16];
    uint64_t watermark_now_ms;
} ninlil_r2_authority_clock_request_t;

/* Closed result. Hint-string parse forbidden. */
typedef struct ninlil_r2_authority_clock_result {
    uint8_t typed_class;
    uint8_t sample_epoch_id[16];
    uint64_t sample_now_ms;
    uint8_t sample_trust; /* NINLIL_CLOCK_TRUSTED / UNCERTAIN when exposed */
    uint8_t sample_fields_valid; /* 1 iff epoch/now/trust may be used for stamps */
    uint8_t meta_published;
    uint8_t meta_state;
    uint8_t trusted_baseline_valid;
    uint8_t meta_last_trusted_epoch_id[16];
    uint64_t meta_last_trusted_now_ms;
    uint32_t fence_bits;
    ninlil_pcp_fence_code_t fence_code;
    uint8_t business_mutation;
    uint8_t durable_meta_mutation;
    uint8_t txn_provenance;
    uint8_t result_catalog;
    ninlil_pcp_status_t exact_status;
    ninlil_pcp_stage_t stage;
    ninlil_pcp_reason_t reason;
} ninlil_r2_authority_clock_result_t;

/*
 * Sample once under docs/24 §3; classify A/B/C/D + floors.
 * Routine path: ram_trust mirror only (no storage RO).
 * Returns 0 always when out is written; callers use result.typed_class.
 * Nonzero only on programming error (NULL args) after zeroing out when possible.
 */
int32_t ninlil_r2_private_sample_authority_clock(
    ninlil_pcp_t *pcp,
    const ninlil_r2_authority_clock_request_t *request,
    ninlil_r2_authority_clock_result_t *out_result);

/*
 * Boot / post-recover baseline load (docs/30 §11.2.3.1 A). Mutation 0.
 * Not the timer hot path.
 */
typedef struct ninlil_r2_authority_clock_baseline_result {
    uint8_t published;
    uint8_t trusted_baseline_valid;
    uint8_t last_trusted_epoch_id[16];
    uint64_t last_trusted_now_ms;
    uint32_t fence_bits;
    ninlil_pcp_fence_code_t fence_code;
    uint8_t meta_state;
    uint8_t result_catalog;
    ninlil_pcp_status_t exact_status;
    ninlil_pcp_stage_t stage;
    ninlil_pcp_reason_t reason;
} ninlil_r2_authority_clock_baseline_result_t;

int32_t ninlil_r2_private_load_authority_clock_baseline(
    ninlil_pcp_t *pcp,
    ninlil_r2_authority_clock_baseline_result_t *out_result);

/* 1 iff typed_class is class-D and sample_fields_valid. */
int ninlil_r2_authority_clock_is_class_d(
    const ninlil_r2_authority_clock_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_R7_R2_AUTHORITY_CLOCK_H */
