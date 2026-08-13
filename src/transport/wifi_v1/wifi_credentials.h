/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_CREDENTIALS_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_CREDENTIALS_H

#include "wifi_private_types.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opaque credential binding: never stores password plaintext.
 * secret_ref_digest[32] only. Rotation uses dual-image CU (committed/staging).
 * Durable NWD1: 160B LE image, FULL commit, cold reopen via storage_ops.
 */
#define NINLIL_WIFI_NWD1_KEY_COMMITTED "NWD1_CRED_FULL"
#define NINLIL_WIFI_NWD1_IMAGE_BYTES 160u

typedef struct ninlil_wifi_secret_ref {
    uint8_t secret_ref_digest[32];
    uint64_t revision;
    uint8_t valid;
    uint8_t reserved[7];
} ninlil_wifi_secret_ref_t;

typedef struct ninlil_wifi_credential_store {
    ninlil_wifi_secret_ref_t committed;
    ninlil_wifi_secret_ref_t staging;
    uint8_t staging_active;
    uint8_t reserved[7];
    /* Optional durable media (NULL = RAM-only). */
    const ninlil_storage_ops_t *storage;
    void *storage_user;
    char path_utf8[64];
    ninlil_wifi_cu_class_t last_commit_unknown_class;
    uint8_t durable_bound;
    uint8_t reserved2[3];
} ninlil_wifi_credential_store_t;

void ninlil_wifi_credential_store_init(ninlil_wifi_credential_store_t *store);

ninlil_wifi_status_t ninlil_wifi_credential_stage(
    ninlil_wifi_credential_store_t *store,
    const uint8_t secret_ref_digest[32],
    uint64_t revision);

/* Commit staging only if revision is strictly greater (no rollback). */
ninlil_wifi_status_t ninlil_wifi_credential_commit(
    ninlil_wifi_credential_store_t *store);

/*
 * Activate staged credentials (= commit). Staging required.
 * Callers that require active credentials should set session credentials_required.
 */
ninlil_wifi_status_t ninlil_wifi_credential_activate(
    ninlil_wifi_credential_store_t *store);

/* Revoke committed image; staging cleared. No plaintext present. */
ninlil_wifi_status_t ninlil_wifi_credential_revoke(
    ninlil_wifi_credential_store_t *store);

ninlil_wifi_status_t ninlil_wifi_credential_rollback_staging(
    ninlil_wifi_credential_store_t *store);

/* Same revision + different digest => FENCED (conflict). */
ninlil_wifi_status_t ninlil_wifi_credential_observe(
    ninlil_wifi_credential_store_t *store,
    const uint8_t secret_ref_digest[32],
    uint64_t revision);

/* 1 if committed valid. */
int ninlil_wifi_credential_is_active(
    const ninlil_wifi_credential_store_t *store);

/* Bind storage for FULL durable NWD1 credential images. */
ninlil_wifi_status_t ninlil_wifi_credential_bind_storage(
    ninlil_wifi_credential_store_t *store,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8);

/*
 * Persist committed secret_ref under FULL durability (NWD1 LE image).
 * Requires bind_storage. COMMIT_UNKNOWN remains distinct and a fresh reopen
 * classifies durable truth as INTENDED/OLD/ABSENT/OTHER.
 */
ninlil_wifi_status_t ninlil_wifi_credential_durable_put_full(
    ninlil_wifi_credential_store_t *store);

/*
 * Cold reopen: load FULL NWD1 image into committed; staging cleared.
 * Classifies missing/corrupt/stale; never reads password plaintext.
 */
ninlil_wifi_status_t ninlil_wifi_credential_durable_reopen(
    ninlil_wifi_credential_store_t *store);

ninlil_wifi_cu_class_t
ninlil_wifi_credential_last_commit_unknown_class(
    const ninlil_wifi_credential_store_t *store);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_CREDENTIALS_H */
