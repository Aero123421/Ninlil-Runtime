#ifndef NINLIL_WIFI_HIL_M4_H
#define NINLIL_WIFI_HIL_M4_H

#include "wifi_hil_provision.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ninlil_wifi_hil_m4 {
    ninlil_wifi_m4_owner_t owner;
    wifi_m4_attachment_carrier_ops_v1_t ops;
    const ninlil_storage_ops_t *storage;
    const ninlil_wifi_hil_provision_t *provision;
    uint8_t persisted_peer_session_id[16];
    uint8_t records_current;
} ninlil_wifi_hil_m4_t;

int ninlil_wifi_hil_m4_init(
    ninlil_wifi_hil_m4_t *carrier,
    const ninlil_storage_ops_t *storage,
    const ninlil_wifi_hil_provision_t *provision);

const wifi_m4_attachment_carrier_ops_v1_t *ninlil_wifi_hil_m4_ops(
    ninlil_wifi_hil_m4_t *carrier);

#ifdef __cplusplus
}
#endif

#endif
