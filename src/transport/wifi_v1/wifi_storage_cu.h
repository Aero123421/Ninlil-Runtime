#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_STORAGE_CU_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_STORAGE_CU_H

/*
 * Shared FULL-write / COMMIT_UNKNOWN reconciliation for Wi-Fi private state.
 *
 * A COMMIT_UNKNOWN result is always returned as
 * NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN.  Reopening and observing INTENDED is
 * evidence about durable truth, not permission to turn the call into success.
 */
#include "wifi_private_types.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_STORAGE_CU_VALUE_MAX 256u

ninlil_wifi_status_t ninlil_wifi_storage_read(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const char *key_utf8,
    uint8_t *out_value,
    uint32_t value_capacity,
    uint32_t *out_length,
    int *out_present);

ninlil_wifi_status_t ninlil_wifi_storage_cu_put_full(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8,
    const char *key_utf8,
    const uint8_t *intended,
    uint32_t intended_length,
    ninlil_wifi_cu_class_t *out_class);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_STORAGE_CU_H */
