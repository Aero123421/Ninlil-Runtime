/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_DOMAIN_STORE_D3S4_H
#define NINLIL_DOMAIN_STORE_D3S4_H

/*
 * D3-S4 private DSW1 witness-member/group evaluator (docs/17 §18.15).
 *
 * Production-private; not installed and not part of the public C ABI.
 * One session owns one READ_ONLY snapshot and exactly one mode (31..34).
 * Storage mutation, heap allocation, VLA, recursion, a second transaction,
 * and a second record-value buffer are forbidden.
 */

#include <stddef.h>
#include <stdint.h>

#include <ninlil/platform.h>
#include <ninlil/runtime.h>

#include "domain_store_codec.h"
#include "runtime_store_codec.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_domain_scan_session ninlil_domain_scan_session_t;
typedef struct ninlil_domain_scan_workspace ninlil_domain_scan_workspace_t;
typedef struct ninlil_domain_scan_result ninlil_domain_scan_result_t;

typedef enum ninlil_domain_scan_d3s4_mode {
    NINLIL_DOMAIN_SCAN_D3S4_MODE_ACTIVE_WITNESS = 31,
    NINLIL_DOMAIN_SCAN_D3S4_MODE_SUPERSEDED_WITNESS = 32,
    NINLIL_DOMAIN_SCAN_D3S4_MODE_RETIRED_CHUNK_BIND = 33,
    NINLIL_DOMAIN_SCAN_D3S4_MODE_HEAD_BACKLINK = 34
} ninlil_domain_scan_d3s4_mode_t;

#define NINLIL_DOMAIN_SCAN_D3S4_MODE_MIN ((uint8_t)31u)
#define NINLIL_DOMAIN_SCAN_D3S4_MODE_MAX ((uint8_t)34u)

#define NINLIL_DOMAIN_SCAN_D3S4_PASS_BASELINE ((uint8_t)0u)
#define NINLIL_DOMAIN_SCAN_D3S4_PASS_INTERNAL ((uint8_t)1u)

typedef enum ninlil_domain_scan_d3s4_phase {
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_IDLE = 0,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_BASELINE = 1,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_SELECT = 2,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_MEMBER_PIPELINE = 3,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_GROUP_CLOSE = 4,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE33_BIND = 5,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_MODE34_ARM = 6,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_COMPLETE = 7,
    NINLIL_DOMAIN_SCAN_D3S4_PHASE_FAILED = 8
} ninlil_domain_scan_d3s4_phase_t;

#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_BASELINE_DONE ((uint8_t)0x01u)
#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_FOCUS_LIVE ((uint8_t)0x02u)
#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_BIND_PHASE_ACTIVE ((uint8_t)0x04u)
#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_COMPLETE_READY ((uint8_t)0x08u)
#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_NEED_RESUME ((uint8_t)0x10u)
#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_HEADER_INSTALLED ((uint8_t)0x20u)
#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_MANIFEST_SHA_OPEN ((uint8_t)0x40u)
#define NINLIL_DOMAIN_SCAN_D3S4_FLAG_S5_REQUIRED_SEEN ((uint8_t)0x80u)

#define NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE31 ((uint8_t)0x01u)
#define NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE32 ((uint8_t)0x02u)
#define NINLIL_DOMAIN_SCAN_D3S4_COUNT_MODE34 ((uint8_t)0x04u)

#define NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE33 ((uint8_t)0x01u)
#define NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_A ((uint8_t)0x02u)
#define NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_B ((uint8_t)0x04u)
#define NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_C ((uint8_t)0x08u)
#define NINLIL_DOMAIN_SCAN_D3S4_BIND_MODE34_ALL ((uint8_t)0x10u)
#define NINLIL_DOMAIN_SCAN_D3S4_BIND_S6_REQUIRED ((uint8_t)0x20u)

typedef enum ninlil_domain_scan_d3s4_group_class {
    NINLIL_DOMAIN_SCAN_D3S4_GROUP_UNSET = 0,
    NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_NEW = 1,
    NINLIL_DOMAIN_SCAN_D3S4_GROUP_ALL_OLD = 2,
    NINLIL_DOMAIN_SCAN_D3S4_GROUP_MIXED_OLD_NEW = 3,
    NINLIL_DOMAIN_SCAN_D3S4_GROUP_PROGRESSED_S5_REQUIRED = 4,
    NINLIL_DOMAIN_SCAN_D3S4_GROUP_CORRUPT = 5
} ninlil_domain_scan_d3s4_group_class_t;

typedef enum ninlil_domain_scan_d3s4_disposition {
    NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_LOCAL_COMPLETE = 0,
    NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_REQUIRED = 1,
    NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S6_REQUIRED = 2,
    NINLIL_DOMAIN_SCAN_D3S4_DISPOSITION_S5_AND_S6_REQUIRED = 3
} ninlil_domain_scan_d3s4_disposition_t;

/*
 * Higher-D3, zero-Port composition carrier (docs/17 §18.15.10).
 *
 * Only a successful finalize carrying present=1 contributes a disposition.
 * Non-OK inputs and successful present=0 inputs are intentionally ignored so
 * failed/evaluator-off sessions cannot accidentally contribute LOCAL_COMPLETE.
 */
typedef struct ninlil_domain_scan_d3s4_composition {
    uint8_t disposition_present;
    uint8_t disposition;
    uint8_t accepted_input_count;
    uint8_t reserved_zero;
} ninlil_domain_scan_d3s4_composition_t;

#define NINLIL_DOMAIN_SCAN_D3S4_CONTEXT_SIZE_BYTES ((uint32_t)949u)
#define NINLIL_DOMAIN_SCAN_D3S4_CONTEXT_CEILING_BYTES ((uint32_t)960u)
#define NINLIL_DOMAIN_SCAN_D3S4_PEER_KEY_CAPACITY ((uint32_t)45u)
#define NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_RAW_CAPACITY ((uint32_t)255u)
#define NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_RAW2_CAPACITY ((uint32_t)64u)
#define NINLIL_DOMAIN_SCAN_D3S4_PRIMARY_AUX_CAPACITY ((uint32_t)16u)
#define NINLIL_DOMAIN_SCAN_D3S4_OUTER_AGGREGATE_CEILING_BYTES \
    ((uint32_t)10880u)
#define NINLIL_DOMAIN_SCAN_D3S4_AGGREGATE_PACKED_SUM_BYTES \
    ((uint32_t)10814u)

/*
 * Exact byte layout from docs/17 §18.15.12.  Multi-byte scalar slots are
 * stored big-endian byte arrays so host and ESP32-S3 images are identical.
 */
typedef struct ninlil_domain_scan_d3s4_context {
    uint8_t last_carrier_key[45];
    uint8_t last_carrier_key_len;
    uint8_t witness_digest[32];
    uint8_t member_count[2];
    uint8_t chunk_count[2];
    uint8_t streamed_members[2];
    uint8_t membership_i[2];
    uint8_t expected_manifest_digest[32];
    uint8_t focus_key_digest[32];
    uint8_t pin_digest_a[32];
    uint8_t pin_digest_b[32];
    uint8_t entry_old_value_digest[32];
    uint8_t entry_new_value_digest[32];
    uint8_t entry_prior_head_witness_digest[32];
    uint8_t expected_primary_pvd[32];
    uint8_t expected_primary_raw[255];
    uint8_t expected_primary_raw2[64];
    uint8_t expected_primary_aux[16];
    uint8_t expected_primary_raw_len[2];
    uint8_t expected_primary_raw2_len;
    uint8_t expected_primary_aux_len;
    uint8_t prev_member_key[45];
    uint8_t prev_member_key_len;
    uint8_t peer_key[45];
    uint8_t peer_key_len;
    uint8_t membership_key_a[45];
    uint8_t membership_key_a_len;
    uint8_t sha_state[32];
    uint8_t sha_bitcount[8];
    uint8_t sha_block[64];
    uint8_t sha_block_len;
    uint8_t entry_action;
    uint8_t entry_old_present;
    uint8_t entry_new_present;
    uint8_t entry_flags;
    uint8_t group_class;
    uint8_t phase;
    uint8_t pass_kind;
    uint8_t flags;
    uint8_t count_complete_mask;
    uint8_t binding_complete_mask;
    uint8_t focus_mode;
    uint8_t arm_cursor;
    uint8_t membership_need_mask;
    uint8_t found_count_a;
    uint8_t found_count_b;
    uint8_t member_substep;
    uint8_t membership_substep;
    uint8_t drive_get_quota[2];
    uint8_t drive_gets_used[2];
    uint8_t entry_record_role[2];
    uint8_t entry_key_length[2];
} ninlil_domain_scan_d3s4_context_t;

#if defined(__cplusplus)
static_assert(sizeof(ninlil_domain_scan_d3s4_context_t) == 949u,
    "D3-S4 context sizeof must be exactly 949");
static_assert(alignof(ninlil_domain_scan_d3s4_context_t) == 1,
    "D3-S4 context alignment must be 1");
static_assert(sizeof(ninlil_domain_scan_d3s4_context_t) <= 960u,
    "D3-S4 context exceeds ceiling 960");
#else
_Static_assert(sizeof(ninlil_domain_scan_d3s4_context_t) == 949u,
    "D3-S4 context sizeof must be exactly 949");
_Static_assert(_Alignof(ninlil_domain_scan_d3s4_context_t) == 1,
    "D3-S4 context alignment must be 1");
_Static_assert(sizeof(ninlil_domain_scan_d3s4_context_t) <= 960u,
    "D3-S4 context exceeds ceiling 960");
#endif

ninlil_status_t ninlil_domain_scan_begin_profiled_d3s4(
    ninlil_domain_scan_session_t *session,
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_scan_workspace_t *workspace,
    const ninlil_model_runtime_store_binding_t *candidate,
    uint8_t mode,
    ninlil_domain_scan_d3s4_context_t *context);

/*
 * One call performs the next closed D3-S4 transition.  quota is installed at
 * the first drive and after resume; exact-get attempts never exceed it.
 */
ninlil_status_t ninlil_domain_scan_d3s4_drive(
    ninlil_domain_scan_session_t *session,
    uint16_t quota);
ninlil_status_t ninlil_domain_scan_d3s4_resume(
    ninlil_domain_scan_session_t *session,
    uint16_t quota);

ninlil_status_t ninlil_domain_scan_d3s4_on_row(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_workspace_t *workspace,
    uint32_t key_length,
    uint32_t value_length,
    uint8_t typed_current_ok);
ninlil_status_t ninlil_domain_scan_d3s4_on_exhausted(
    ninlil_domain_scan_session_t *session);

uint8_t ninlil_domain_scan_d3s4_required_count_mask(uint8_t focus_mode);
uint8_t ninlil_domain_scan_d3s4_required_binding_mask(uint8_t focus_mode);
ninlil_status_t ninlil_domain_scan_d3s4_ready_disposition(
    const ninlil_domain_scan_d3s4_context_t *context,
    uint8_t *out_disposition);

ninlil_status_t ninlil_domain_scan_d3s4_finalize(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result);
ninlil_status_t ninlil_domain_scan_d3s4_abort(
    ninlil_domain_scan_session_t *session,
    ninlil_domain_scan_result_t *out_result);

void ninlil_domain_scan_d3s4_composition_init(
    ninlil_domain_scan_d3s4_composition_t *composition);
ninlil_status_t ninlil_domain_scan_d3s4_composition_add(
    ninlil_domain_scan_d3s4_composition_t *composition,
    ninlil_status_t finalize_status,
    uint8_t disposition_present,
    uint8_t disposition);
ninlil_status_t ninlil_domain_scan_d3s4_composition_finish(
    const ninlil_domain_scan_d3s4_composition_t *composition,
    uint8_t *out_disposition_present,
    uint8_t *out_disposition);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_DOMAIN_STORE_D3S4_H */
