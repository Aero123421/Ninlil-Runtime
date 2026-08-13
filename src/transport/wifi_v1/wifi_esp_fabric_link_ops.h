/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_FABRIC_LINK_OPS_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_FABRIC_LINK_OPS_H

#include "fabric_private_api.h"
#include "wifi_fabric_call_authority.h"
#include "wifi_esp_owner.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ESP profile is deliberately one-token/one-loan. Permanent TxPermit replay
 * authority remains Fabric's co-located durable FBA1 claim; this provider retains the
 * live/retired permit until release and never authorizes standalone use.
 */
typedef struct ninlil_wifi_esp_fabric_link_user {
    uint32_t provider_magic;
    ninlil_wifi_esp_owner_t *owner;
    uint64_t availability_epoch_seen;
    uint64_t permit_now_ms;
    uint8_t permit_clock_epoch_id[16];
    uint8_t permit_clock_epoch_set;
    uint8_t durable_outer_permit_authority;
    uint8_t open;
    uint8_t send_in_use;
    uint8_t send_terminal;
    uint8_t send_cancelled;
    uint8_t permit_retired;
    uint8_t rx_loan_active;
    uint8_t reserved0[2];
    ninlil_wifi_fabric_call_authority_v1_t call_authority;
    uint32_t open_generation;
    uint32_t closed_generation;
    uint32_t send_generation;
    uint32_t send_sequence;
    uint32_t send_completion_kind;
    uint32_t rx_generation;
    uint8_t permit_id[16];
    uint8_t rx_record[NINLIL_WIFI_NWB1_TOTAL_MAX];
    uint32_t rx_record_len;
} ninlil_wifi_esp_fabric_link_user_t;

void ninlil_wifi_esp_fabric_packet_link_ops_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_esp_fabric_link_user_t *user,
    ninlil_wifi_esp_owner_t *owner);

void ninlil_wifi_esp_fabric_packet_link_ops_scoped_init(
    ninlil_fabric_packet_link_ops_v1_t *ops,
    ninlil_wifi_esp_fabric_link_user_t *user,
    ninlil_wifi_fabric_call_scope_v1_t *scope,
    const void *fabric_cookie);

int ninlil_wifi_esp_fabric_packet_link_authority_prepare(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie);

int ninlil_wifi_esp_fabric_packet_link_authority_activate(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie);

int ninlil_wifi_esp_fabric_packet_link_authority_drain(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie);

int ninlil_wifi_esp_fabric_packet_link_authority_unbind(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const void *fabric_cookie);

ninlil_wifi_status_t ninlil_wifi_esp_fabric_bind_trusted_clock(
    ninlil_wifi_esp_fabric_link_user_t *user,
    const ninlil_time_sample_t *sample);

#ifdef __cplusplus
}
#endif

#endif
