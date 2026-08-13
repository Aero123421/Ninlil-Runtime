/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ATTACHMENT_M4_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ATTACHMENT_M4_H

/*
 * M4 PA FULL evidence (ADR-0018) — subsystem-owned linear capability.
 *
 * Authority is process-private owner-registry live state, not carried bytes
 * and not a fixed/compile-time secret. Public evidence is an alias handle:
 * slot index + generation + owner_epoch + 128-bit owner-minted cap_id.
 * ready_for_attach consults the live slot under an owner lock; cap_id is
 * filled from platform entropy/DRBG and is never a caller-provided token.
 *
 * reset/consume invalidate the slot so every alias fails. Capacity is
 * fail-closed (no silent eviction of live slots). owner_restart wipes all
 * slots and advances epoch; stale handles cannot resurrect across wrap
 * (wide counters + cap_id; allocation fails closed on counter exhaustion).
 *
 * load_classify releases the owner lock only for storage I/O. Each component
 * (membership/attachment/credential) carries an operation generation token
 * assigned at load start; after I/O, results apply only if that token is
 * still current. Concurrent old/new loads on the same evidence therefore
 * fail closed (DENIED) for the stale completion rather than overwriting.
 *
 * Private / default-OFF. Not public ABI. Not physical RF HIL.
 */
#include "wifi_credentials.h"
#include "wifi_private_types.h"

#include <ninlil/platform.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_M4_FABRIC_DESCRIPTOR_BYTES 32u
#define NINLIL_WIFI_M4_DURABLE_IMAGE_BYTES 160u
#define NINLIL_WIFI_M4_NS "ninlil.wifi.m4.v1"
#define NINLIL_WIFI_M4_KEY_ATTACHMENT "M4_ATTACH_FULL"
#define NINLIL_WIFI_M4_KEY_MEMBERSHIP "M4_MEMBER_LEASE"
#define NINLIL_WIFI_M4_KEY_CREDENTIAL "M4_CRED_FULL"

/* Opaque handle storage (not payload). Layout private. */
#define NINLIL_WIFI_M4_EVIDENCE_OPAQUE_BYTES 64u

/* Bounded concurrent live capabilities per owner instance (no heap). */
#define NINLIL_WIFI_M4_OWNER_SLOT_COUNT 4u

/* Opaque instance-scoped owner registry (not process-global). */
#define NINLIL_WIFI_M4_OWNER_STORAGE_BYTES 8192u

typedef struct ninlil_wifi_m4_owner {
    _Alignas(max_align_t) uint8_t opaque[NINLIL_WIFI_M4_OWNER_STORAGE_BYTES];
} ninlil_wifi_m4_owner_t;

typedef enum ninlil_wifi_m4_record_class {
    NINLIL_WIFI_M4_CLASS_MISSING = 0,
    NINLIL_WIFI_M4_CLASS_CORRUPT = 1,
    NINLIL_WIFI_M4_CLASS_STALE = 2,
    NINLIL_WIFI_M4_CLASS_FULL = 3
} ninlil_wifi_m4_record_class_t;

typedef struct ninlil_wifi_m4_membership_lease {
    uint8_t member_runtime_id[16];
    uint64_t lease_not_before_ms;
    uint64_t lease_not_after_ms;
    uint8_t authority_id[16];
    uint8_t binding_digest[32];
    uint8_t sealed_digest[32];
} ninlil_wifi_m4_membership_lease_t;

typedef struct ninlil_wifi_m4_fabric_registry {
    uint8_t fabric_descriptor[NINLIL_WIFI_M4_FABRIC_DESCRIPTOR_BYTES];
    uint8_t authority_id[16];
    uint8_t registry_epoch_id[16];
    int bound;
} ninlil_wifi_m4_fabric_registry_t;

/*
 * Alias handle only. Filling opaque[] cannot mint readiness: validation
 * requires a live owner-registry slot matching generation/epoch/cap_id.
 */
typedef struct ninlil_wifi_m4_full_evidence {
    _Alignas(max_align_t) uint8_t opaque[NINLIL_WIFI_M4_EVIDENCE_OPAQUE_BYTES];
} ninlil_wifi_m4_full_evidence_t;

/* Attach material view for session/owner after ready (export only if live). */
typedef struct ninlil_wifi_m4_attach_material {
    uint8_t peer_session_id[16];
    uint8_t attachment_authority_id[16];
    uint8_t active_attachment_binding_digest[32];
    uint8_t credential_candidate_digest[32];
    uint8_t fabric_descriptor[32];
} ninlil_wifi_m4_attach_material_t;

/*
 * Allocate a new empty live slot and bind handle into out.
 * If out already aliases a live slot, that slot is invalidated first
 * (all prior copies of that handle fail), then a free slot is taken.
 * Returns CAPACITY if no free slot remains (does not evict other live
 * capabilities). Returns CORRUPT/DENIED on entropy or counter exhaustion.
 */
/* Initialize instance-scoped owner (required; no process-global registry). */
void ninlil_wifi_m4_owner_init(ninlil_wifi_m4_owner_t *owner);

/* Restart only this owner instance (other owners/adapters untouched). */
ninlil_wifi_status_t ninlil_wifi_m4_owner_restart(ninlil_wifi_m4_owner_t *owner);

ninlil_wifi_status_t ninlil_wifi_m4_evidence_reset(
    ninlil_wifi_m4_owner_t *owner,
    ninlil_wifi_m4_full_evidence_t *out);

/*
 * Linear consume: invalidate the live slot (all aliases fail), wipe handle.
 * Used after accept ownership transfer and for cancel/close of capability.
 */
void ninlil_wifi_m4_evidence_consume(ninlil_wifi_m4_full_evidence_t *ev);

/*
 * Mark a live slot as minted under authenticated session authority.
 * Without this mark, ready_for_attach is DENIED even if durable loads are FULL
 * (blocks self-issued raw-input readiness).
 */
ninlil_wifi_status_t ninlil_wifi_m4_evidence_mark_session_authority(
    ninlil_wifi_m4_full_evidence_t *ev);

ninlil_wifi_status_t ninlil_wifi_m4_membership_store_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const ninlil_wifi_m4_membership_lease_t *lease);

/*
 * Same write with exact post-COMMIT_UNKNOWN durable classification.
 * The return remains NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN even when a fresh
 * reopen observes the intended image.
 */
ninlil_wifi_status_t ninlil_wifi_m4_membership_store_full_reconciled(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const ninlil_wifi_m4_membership_lease_t *lease,
    ninlil_wifi_cu_class_t *out_class);

ninlil_wifi_status_t ninlil_wifi_m4_membership_load_classify(
    ninlil_wifi_m4_owner_t *owner,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    uint64_t mono_now_ms,
    ninlil_wifi_m4_full_evidence_t *ev);

ninlil_wifi_status_t ninlil_wifi_m4_attachment_store_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t peer_session_id[16],
    const uint8_t authority_id[16],
    const uint8_t binding_digest[32],
    const uint8_t credential_digest[32],
    const uint8_t fabric_descriptor[32]);

ninlil_wifi_status_t ninlil_wifi_m4_attachment_store_full_reconciled(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t peer_session_id[16],
    const uint8_t authority_id[16],
    const uint8_t binding_digest[32],
    const uint8_t credential_digest[32],
    const uint8_t fabric_descriptor[32],
    ninlil_wifi_cu_class_t *out_class);

ninlil_wifi_status_t ninlil_wifi_m4_attachment_load_classify(
    ninlil_wifi_m4_owner_t *owner,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t peer_session_id[16],
    ninlil_wifi_m4_full_evidence_t *ev);

ninlil_wifi_status_t ninlil_wifi_m4_credential_store_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t secret_ref_digest[32],
    uint64_t revision);

ninlil_wifi_status_t ninlil_wifi_m4_credential_store_full_reconciled(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const uint8_t secret_ref_digest[32],
    uint64_t revision,
    ninlil_wifi_cu_class_t *out_class);

ninlil_wifi_status_t ninlil_wifi_m4_credential_load_classify(
    ninlil_wifi_m4_owner_t *owner,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    ninlil_wifi_m4_full_evidence_t *ev);

ninlil_wifi_status_t ninlil_wifi_m4_fabric_registry_bind(
    ninlil_wifi_m4_fabric_registry_t *reg,
    const uint8_t fabric_descriptor[32],
    const uint8_t authority_id[16],
    const uint8_t registry_epoch_id[16]);

ninlil_wifi_status_t ninlil_wifi_m4_evidence_apply_fabric_registry(
    ninlil_wifi_m4_full_evidence_t *ev,
    const ninlil_wifi_m4_fabric_registry_t *reg);

/*
 * OK only if handle aliases a live ready slot (cap_id + gen + epoch match).
 * Forged opaque[] / stale copies / post-consume / post-restart → DENIED.
 */
ninlil_wifi_status_t ninlil_wifi_m4_evidence_ready_for_attach(
    const ninlil_wifi_m4_full_evidence_t *ev);

/* Export attach digests only when live-ready; else DENIED. */
ninlil_wifi_status_t ninlil_wifi_m4_evidence_export_attach_material(
    const ninlil_wifi_m4_full_evidence_t *ev,
    ninlil_wifi_m4_attach_material_t *out);

/* Read-only class/live queries (MISSING if handle not live). */
ninlil_wifi_m4_record_class_t ninlil_wifi_m4_evidence_class_membership(
    const ninlil_wifi_m4_full_evidence_t *ev);
ninlil_wifi_m4_record_class_t ninlil_wifi_m4_evidence_class_attachment(
    const ninlil_wifi_m4_full_evidence_t *ev);
ninlil_wifi_m4_record_class_t ninlil_wifi_m4_evidence_class_credential(
    const ninlil_wifi_m4_full_evidence_t *ev);
int ninlil_wifi_m4_evidence_membership_live(
    const ninlil_wifi_m4_full_evidence_t *ev);

#if defined(NINLIL_WIFI_M4_TEST_HOOKS)
/*
 * Test-only: invoked after owner lock is released and before storage I/O in
 * load_classify. Used for deterministic concurrent old/new completion tests.
 * Production builds must not define NINLIL_WIFI_M4_TEST_HOOKS.
 */
typedef void (*ninlil_wifi_m4_storage_io_hook_fn)(void *user);
void ninlil_wifi_m4_test_set_storage_io_hook(
    ninlil_wifi_m4_storage_io_hook_fn fn,
    void *user);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ATTACHMENT_M4_H */
