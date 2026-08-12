/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_WIFI_HIL_PROVISION_H
#define NINLIL_WIFI_HIL_PROVISION_H

#include "wifi_adapter_v1.h"

#include <ninlil/platform.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_HIL_NVS_NAMESPACE "ninlil_wifi"
#define NINLIL_WIFI_HIL_PROVISION_SCHEMA 1u
#define NINLIL_WIFI_HIL_PEM_MAX_BYTES 4096u

typedef enum ninlil_wifi_hil_provision_status {
    NINLIL_WIFI_HIL_PROVISION_OK = 0,
    NINLIL_WIFI_HIL_PROVISION_MISSING = 1,
    NINLIL_WIFI_HIL_PROVISION_CORRUPT = 2
} ninlil_wifi_hil_provision_status_t;

/*
 * HIL-only retained provisioning. Secrets are loaded from NVS blobs and are
 * never accepted over, or emitted to, the serial command channel.
 */
typedef struct ninlil_wifi_hil_provision {
    wifi_adapter_config_v1_t adapter_config;
    wifi_esp_session_provision_v1_t session;
    wifi_network_credential_provider_ops_v1_t network_provider;
    wifi_network_credential_metadata_v1_t network_metadata;
    uint8_t network_secret[WIFI_NETCRED_SECRET_BYTES];
    uint8_t credential_candidate_digest[32];
    uint8_t registry_epoch_id[16];
    uint8_t ca_pem[NINLIL_WIFI_HIL_PEM_MAX_BYTES];
    uint8_t cert_pem[NINLIL_WIFI_HIL_PEM_MAX_BYTES];
    uint8_t key_pem[NINLIL_WIFI_HIL_PEM_MAX_BYTES];
    size_t ca_pem_length;
    size_t cert_pem_length;
    size_t key_pem_length;
} ninlil_wifi_hil_provision_t;

ninlil_wifi_hil_provision_status_t ninlil_wifi_hil_provision_load(
    ninlil_wifi_hil_provision_t *provision,
    void *tls_workspace,
    uint32_t tls_workspace_bytes,
    void *sta_workspace,
    uint32_t sta_workspace_bytes);

void ninlil_wifi_hil_provision_bind_runtime(
    ninlil_wifi_hil_provision_t *provision,
    const ninlil_storage_ops_t *storage,
    const ninlil_clock_ops_t *clock,
    const ninlil_execution_ops_t *execution,
    const wifi_m4_attachment_carrier_ops_v1_t *m4_carrier);

/* Wipe only PEM bytes after TLS has parsed them; STA credentials stay live. */
void ninlil_wifi_hil_provision_wipe_parsed_pems(
    ninlil_wifi_hil_provision_t *provision);

#ifdef __cplusplus
}
#endif

#endif
