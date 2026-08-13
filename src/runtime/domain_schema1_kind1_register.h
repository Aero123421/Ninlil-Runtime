/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_RUNTIME_DOMAIN_SCHEMA1_KIND1_REGISTER_H
#define NINLIL_RUNTIME_DOMAIN_SCHEMA1_KIND1_REGISTER_H

/*
 * ADR-0022 kind-1 SERVICE_REGISTER M=5 + ACTIVE header/chunk (HOST_CANDIDATE).
 * Feature-gated. Not public ABI.
 *
 * FULL apply: complete namespace begin + final (existing ∪ 7 post records).
 * 5 members + WITNESS_MANIFEST_CHUNK + WITNESS_HEADER.
 * First register on semantic-empty Domain: 33 + 5 CREATE = 38 rows.
 */

#include "domain_schema1_startup_authority.h"
#include "domain_schema1_startup_owner.h"
#include "domain_store_codec.h"
#include "runtime_store_codec.h"
#include "storage_canonical_plan.h"

#include <ninlil/platform.h>
#include <ninlil/service.h>

typedef struct ninlil_runtime ninlil_runtime_t;
struct ninlil_rt_service_slot;
typedef struct ninlil_rt_service_slot ninlil_rt_service_slot_t;

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP \
    NINLIL_DOMAIN_SCHEMA1_OWNER_ROW_CAP
/* Chunk complete values ~882B. */
#define NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP ((uint32_t)1024u)
#define NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_KEY_CAP ((uint32_t)64u)
#define NINLIL_DOMAIN_SCHEMA1_KIND1_POST_SLOTS \
    NINLIL_DOMAIN_SCHEMA1_KIND1_POST_RECORD_COUNT

typedef struct ninlil_domain_schema1_kind1_workspace {
    /* Slots 0..4 members; 5 chunk; 6 header. */
    uint8_t member_key[NINLIL_DOMAIN_SCHEMA1_KIND1_POST_SLOTS]
                      [NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_KEY_CAP];
    uint32_t member_key_len[NINLIL_DOMAIN_SCHEMA1_KIND1_POST_SLOTS];
    uint8_t member_value[NINLIL_DOMAIN_SCHEMA1_KIND1_POST_SLOTS]
                        [NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP];
    uint32_t member_value_len[NINLIL_DOMAIN_SCHEMA1_KIND1_POST_SLOTS];
    ninlil_domain_schema1_kind1_plan_t plan;
    uint8_t snap_key[NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP]
                    [NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP];
    uint32_t snap_key_len[NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP];
    uint8_t snap_value[NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP]
                      [NINLIL_DOMAIN_SCHEMA1_OWNER_SNAP_VALUE_CAP];
    uint32_t snap_value_len[NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP];
    uint32_t snap_count;
    ninlil_storage_canonical_row_t begin_rows[
        NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP];
    ninlil_storage_canonical_row_t final_rows[
        NINLIL_DOMAIN_SCHEMA1_KIND1_NS_ROW_CAP];
    uint32_t begin_count;
    uint32_t final_count;
    uint8_t service_raw[256];
    uint32_t service_raw_len;
    uint8_t service_key_digest[32];
    uint8_t witness[32];
    uint8_t capacity_key[16];
    uint32_t capacity_key_len;
    uint8_t old_capacity_value[
        NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES];
    uint32_t old_capacity_value_len;
    uint8_t old_head_value[NINLIL_DOMAIN_SCHEMA1_KIND1_MEMBER_VALUE_CAP];
    uint32_t old_head_value_len;
    uint8_t chunk_body[NINLIL_MODEL_DOMAIN_MANIFEST_CHUNK_BODY_MAX];
    uint32_t chunk_body_len;
    uint8_t header_body[NINLIL_MODEL_DOMAIN_WITNESS_HEADER_BODY_MAX];
    uint32_t header_body_len;
    /*
     * Full-record scan scratch so large V1 TX values can be read and then
     * discarded when skipping LAB operational keys during Domain snap.
     */
    uint8_t scan_tmp_key[NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_KEY_CAP];
    uint8_t scan_tmp_value[NINLIL_DOMAIN_SCHEMA1_OWNER_SCAN_VALUE_CAP];
} ninlil_domain_schema1_kind1_workspace_t;

typedef struct ninlil_domain_schema1_kind1_register_result {
    ninlil_status_t status;
    ninlil_domain_schema1_group_class_t class;
    uint32_t wrote;
    uint32_t reopen_required;
    uint32_t durable_adopted;
    uint32_t reattach_only;
} ninlil_domain_schema1_kind1_register_result_t;

ninlil_status_t ninlil_domain_schema1_kind1_encode_members(
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_time_sample_t *trusted_clock,
    const uint8_t *old_capacity_value,
    uint32_t old_capacity_value_len,
    const uint8_t *old_head_value,
    uint32_t old_head_value_len,
    uint32_t increment_capacity,
    ninlil_domain_schema1_kind1_workspace_t *ws);

ninlil_status_t ninlil_domain_schema1_kind1_commit_full(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t *inout_handle,
    ninlil_domain_schema1_kind1_workspace_t *ws,
    ninlil_domain_schema1_kind1_register_result_t *out_result);

ninlil_status_t ninlil_domain_schema1_kind1_classify_readback(
    const ninlil_storage_ops_t *storage,
    ninlil_storage_handle_t handle,
    ninlil_domain_schema1_kind1_workspace_t *ws,
    const ninlil_domain_schema1_snapshot_row_t *pre_rows,
    uint32_t pre_row_count,
    ninlil_domain_schema1_group_class_t *out_class);

ninlil_status_t ninlil_domain_schema1_service_register(
    ninlil_runtime_t *runtime,
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_service_callbacks_t *callbacks,
    ninlil_rt_service_slot_t *slot,
    uint32_t free_index,
    uint32_t reattach_only_candidate,
    ninlil_domain_schema1_kind1_register_result_t *out_result);

ninlil_status_t ninlil_domain_schema1_service_registry_restore(
    ninlil_runtime_t *runtime);

/*
 * Stage Domain SERVICE_QUOTA REPLACE into an open admission FULL transaction.
 * Domain-ON path only; replaces NRS service-ledger quota rewrite.
 */
ninlil_status_t ninlil_domain_schema1_quota_stage(
    ninlil_runtime_t *runtime,
    ninlil_storage_txn_t txn,
    const ninlil_rt_service_slot_t *slot);

#define NINLIL_DOMAIN_SCHEMA1_KIND1_WS_CEILING_BYTES ((uint32_t)196608u)
#define NINLIL_DOMAIN_SCHEMA1_RUNTIME_DRAM_SOFT_BUDGET_BYTES \
    ((uint32_t)131072u)
#define NINLIL_DOMAIN_SCHEMA1_HOST_PEAK_SOFT_BUDGET_BYTES \
    ((uint32_t)(NINLIL_DOMAIN_SCHEMA1_RUNTIME_DRAM_SOFT_BUDGET_BYTES \
        + NINLIL_DOMAIN_SCHEMA1_KIND1_WS_CEILING_BYTES))

#ifdef __cplusplus
}
#endif

#endif
