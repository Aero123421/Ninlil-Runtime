#ifndef NINLIL_RADIO_C6_LAB_ENFORCEMENT_H
#define NINLIL_RADIO_C6_LAB_ENFORCEMENT_H

/*
 * C6-LAB enforcement: LAB_ONLY profile gate + sole physical TX edge.
 *
 * Order (Normative for V1-LAB radio TX):
 *   R5 bind/issue -> R2 permit validate/consume -> R1 transmit_with_permit
 *   -> R9 host SPI simulation edge.
 *
 * Normative: docs/05 (LAB_ONLY), docs/work/2026-07-23-v1-frame-manifest.md
 * Not public include/ninlil. Not domestic production certification.
 *
 * SEMANTIC: C6_LAB_HOST_CANDIDATE_ONLY
 * SEMANTIC: LAB_ONLY_FAIL_CLOSED
 * SEMANTIC: SOLE_EDGE_R5_R2_R1_R9
 * SEMANTIC: NO_JAPAN_PRODUCTION_CLAIM
 */

#include "c6_lab_spi_tx_sim.h"
#include "profile_loader.h"
#include "v1_frame_manifest.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_C6_LAB_OBJECT_BYTES ((size_t)8192u)
#define NINLIL_C6_LAB_HINT_BYTES ((size_t)160u)

typedef uint32_t ninlil_c6_lab_status_t;
typedef uint32_t ninlil_c6_lab_reason_t;
typedef uint32_t ninlil_c6_lab_stage_t;

#define NINLIL_C6_LAB_OK ((ninlil_c6_lab_status_t)0u)
#define NINLIL_C6_LAB_INVALID_ARGUMENT ((ninlil_c6_lab_status_t)1u)
#define NINLIL_C6_LAB_INVALID_STATE ((ninlil_c6_lab_status_t)2u)
#define NINLIL_C6_LAB_FRAME_DENIED ((ninlil_c6_lab_status_t)3u)
#define NINLIL_C6_LAB_PROFILE_DENIED ((ninlil_c6_lab_status_t)4u)
#define NINLIL_C6_LAB_PERMIT_DENIED ((ninlil_c6_lab_status_t)5u)
#define NINLIL_C6_LAB_HAL_DENIED ((ninlil_c6_lab_status_t)6u)
#define NINLIL_C6_LAB_UNSUPPORTED ((ninlil_c6_lab_status_t)7u)

#define NINLIL_C6_LAB_REASON_NONE ((ninlil_c6_lab_reason_t)0u)
#define NINLIL_C6_LAB_REASON_NULL_ARG ((ninlil_c6_lab_reason_t)1u)
#define NINLIL_C6_LAB_REASON_NOT_ACTIVE ((ninlil_c6_lab_reason_t)2u)
#define NINLIL_C6_LAB_REASON_FRAME_TYPE ((ninlil_c6_lab_reason_t)3u)
#define NINLIL_C6_LAB_REASON_R5 ((ninlil_c6_lab_reason_t)4u)
#define NINLIL_C6_LAB_REASON_HAL ((ninlil_c6_lab_reason_t)5u)

#define NINLIL_C6_LAB_STAGE_NONE ((ninlil_c6_lab_stage_t)0u)
#define NINLIL_C6_LAB_STAGE_INIT ((ninlil_c6_lab_stage_t)1u)
#define NINLIL_C6_LAB_STAGE_ISSUE ((ninlil_c6_lab_stage_t)2u)
#define NINLIL_C6_LAB_STAGE_HAL ((ninlil_c6_lab_stage_t)3u)

typedef struct ninlil_c6_lab_error {
    ninlil_c6_lab_status_t status;
    ninlil_c6_lab_stage_t stage;
    ninlil_c6_lab_reason_t reason;
    uint32_t reserved_zero;
    char hint[NINLIL_C6_LAB_HINT_BYTES];
} ninlil_c6_lab_error_t;

typedef struct ninlil_c6_lab_stats {
    uint64_t transmit_attempts;
    uint64_t transmit_ok;
    uint64_t frame_type_reject;
    uint64_t profile_reject;
    uint64_t permit_reject;
    uint64_t hal_reject;
    uint64_t spi_tx_count;
} ninlil_c6_lab_stats_t;

typedef struct ninlil_c6_lab ninlil_c6_lab_t;

typedef struct ninlil_c6_lab_object {
    uint8_t storage[NINLIL_C6_LAB_OBJECT_BYTES];
} ninlil_c6_lab_object_t;

#define NINLIL_C6_LAB_OBJECT_INIT {{0}}

size_t ninlil_c6_lab_object_size(void);

/*
 * Bind an initialized R5 stack (PCP bound, LAB_ONLY profiles active, assignment
 * bound). Wires R1 HAL with R5 permit ops, local digest fold, and R9 SPI sim.
 */
ninlil_c6_lab_status_t ninlil_c6_lab_init_object(
    ninlil_c6_lab_object_t *object,
    ninlil_r5_t *r5,
    ninlil_c6_lab_t **out_c6,
    ninlil_c6_lab_error_t *out_error);

/*
 * Sole V1-LAB radio transmit API. frame_type must be in v1_frame_manifest.
 * plan supplies frame bytes/digest/airtime/window; R5 issue + R1 TX + R9 SPI.
 * Fail-closed: SPI TX count unchanged on any pre-edge failure.
 */
ninlil_c6_lab_status_t ninlil_c6_lab_transmit(
    ninlil_c6_lab_t *c6,
    ninlil_v1_frame_type_t frame_type,
    const ninlil_r5_issue_plan_t *plan,
    ninlil_c6_lab_error_t *out_error);

void ninlil_c6_lab_stats(
    const ninlil_c6_lab_t *c6,
    ninlil_c6_lab_stats_t *out_stats);

ninlil_c6_lab_status_t ninlil_c6_lab_shutdown(
    ninlil_c6_lab_t *c6,
    ninlil_c6_lab_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RADIO_C6_LAB_ENFORCEMENT_H */
