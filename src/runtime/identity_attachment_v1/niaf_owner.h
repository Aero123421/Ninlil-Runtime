/* SPDX-License-Identifier: Apache-2.0 */
/* Private standalone owner for the ADR-0039 NIAF checkpoint. */
#ifndef NINLIL_RUNTIME_IDENTITY_ATTACHMENT_V1_NIAF_OWNER_H
#define NINLIL_RUNTIME_IDENTITY_ATTACHMENT_V1_NIAF_OWNER_H

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_NIAF_LOCATOR_MAX_BYTES ((uint32_t)255u)
#define NINLIL_NIAF_KEY_BYTES ((uint32_t)72u)
#define NINLIL_NIAF_RECORD_BYTES ((uint32_t)308u)

#if defined(__GNUC__) || defined(__clang__)
#define NINLIL_NIAF_PRIVATE __attribute__((visibility("hidden")))
#else
#define NINLIL_NIAF_PRIVATE
#endif

typedef struct ninlil_niaf_floor_checkpoint_v1 {
    uint8_t realm_id[16];
    uint8_t runtime_instance_id[16];
    uint64_t runtime_generation;
    uint8_t module_instance_id[16];
    uint64_t module_generation;
    uint8_t provider_instance_id[16];
    uint64_t provider_generation_floor;
    uint8_t stable_identity_id[16];
    uint64_t credential_revision_floor;
    uint8_t membership_authority_id[16];
    uint64_t membership_epoch_floor;
    uint8_t attachment_id[16];
    uint64_t attachment_generation_floor;
    uint8_t session_id[16];
    uint64_t session_generation_floor;
    uint8_t security_context_id[16];
    uint64_t security_epoch_floor;
    uint8_t expiry_authority_id[16];
    uint64_t expiry_epoch_floor;
    uint64_t invalidation_epoch_floor;
    uint64_t binding_handle_generation_floor;
    uint64_t key_generation_floor;
    uint64_t checkpoint_generation;
} ninlil_niaf_floor_checkpoint_v1_t;

typedef struct ninlil_niaf_owner_config_v1 {
    uint64_t owner_context_id;
    const ninlil_storage_ops_t *storage;
    ninlil_bytes_view_t locator;
    uint8_t realm_id[16];
    uint8_t runtime_instance_id[16];
    uint64_t runtime_generation;
    uint8_t module_instance_id[16];
    uint64_t module_generation;
} ninlil_niaf_owner_config_v1_t;

typedef struct ninlil_niaf_owner_v1 {
    ninlil_storage_ops_t storage;
    ninlil_storage_handle_t handle;
    ninlil_niaf_floor_checkpoint_v1_t current;
    uint8_t locator[NINLIL_NIAF_LOCATOR_MAX_BYTES];
    uint32_t locator_length;
    uint64_t owner_context_id;
    uint32_t state;
    uint32_t has_current;
    uint32_t recovery_complete;
    uint32_t fenced;
    uint32_t in_call;
    /* Caller-owned workspace: NIAF records must not consume ESP task stack. */
    ninlil_niaf_floor_checkpoint_v1_t scratch_record;
    uint8_t scan_key[NINLIL_NIAF_KEY_BYTES];
    uint8_t scan_value[NINLIL_NIAF_RECORD_BYTES];
    uint8_t scan_expected_key[NINLIL_NIAF_KEY_BYTES];
    uint8_t old_key[NINLIL_NIAF_KEY_BYTES];
    uint8_t old_bytes[NINLIL_NIAF_RECORD_BYTES];
    uint8_t new_key[NINLIL_NIAF_KEY_BYTES];
    uint8_t new_bytes[NINLIL_NIAF_RECORD_BYTES];
} ninlil_niaf_owner_v1_t;

/*
 * Private API: not installed, not connected to Composition in this tranche.
 * One caller-owned object is serialized by its exact owner_context_id; callers
 * must not invoke recover/checkpoint/close concurrently or retain its state;
 * same-object callback reentry is rejected with NINLIL_E_REENTRANT.
 * Before first init, callers MUST zero-initialize the complete object (for
 * example, `ninlil_niaf_owner_v1_t owner = {0};`).  A caller MUST close an
 * initialized owner before reinitializing it; a still-open owner is rejected.
 */
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_owner_v1_init(
    ninlil_niaf_owner_v1_t *owner,
    const ninlil_niaf_owner_config_v1_t *config);
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_owner_v1_recover(
    ninlil_niaf_owner_v1_t *owner,
    uint64_t owner_context_id);
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_owner_v1_checkpoint(
    ninlil_niaf_owner_v1_t *owner,
    uint64_t owner_context_id,
    const ninlil_niaf_floor_checkpoint_v1_t *next);
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_owner_v1_close(
    ninlil_niaf_owner_v1_t *owner,
    uint64_t owner_context_id);
NINLIL_NIAF_PRIVATE uint32_t ninlil_niaf_owner_v1_fenced(const ninlil_niaf_owner_v1_t *owner);
NINLIL_NIAF_PRIVATE uint32_t ninlil_niaf_owner_v1_has_current(const ninlil_niaf_owner_v1_t *owner);
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_owner_v1_current(
    const ninlil_niaf_owner_v1_t *owner,
    ninlil_niaf_floor_checkpoint_v1_t *out_current);

/* Exact private codec; no secret or opaque provider handle is representable. */
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_floor_checkpoint_v1_encode(
    const ninlil_niaf_floor_checkpoint_v1_t *record,
    uint8_t out_bytes[NINLIL_NIAF_RECORD_BYTES]);
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_floor_checkpoint_v1_decode(
    const uint8_t bytes[NINLIL_NIAF_RECORD_BYTES],
    ninlil_niaf_floor_checkpoint_v1_t *out_record);
NINLIL_NIAF_PRIVATE ninlil_status_t ninlil_niaf_floor_checkpoint_v1_key(
    const ninlil_niaf_floor_checkpoint_v1_t *record,
    uint8_t out_key[NINLIL_NIAF_KEY_BYTES]);

#ifdef __cplusplus
}
#endif

#endif
