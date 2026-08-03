#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_RECONNECT_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_RECONNECT_H

#include "wifi_private_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ADR-0018 backoff schedule (ms), deterministic, no entropy. */
#define NINLIL_WIFI_BACKOFF_STEPS 6u

typedef struct ninlil_wifi_endpoint_list {
    ninlil_wifi_endpoint_t endpoints[8];
    uint8_t count;
    uint8_t index;
    uint8_t reserved[6];
} ninlil_wifi_endpoint_list_t;

typedef struct ninlil_wifi_reconnect {
    uint32_t failure_generation;
    uint64_t not_before_mono_ms;
    uint64_t attached_stable_since_ms; /* 0 if not in stable ATTACHED */
    uint8_t instance_id[16]; /* for deterministic jitter */
    uint8_t schedule_index;
    uint8_t reserved[7];
    ninlil_wifi_endpoint_list_t endpoints;
} ninlil_wifi_reconnect_t;

void ninlil_wifi_reconnect_init(ninlil_wifi_reconnect_t *rc);

void ninlil_wifi_endpoint_list_init(ninlil_wifi_endpoint_list_t *list);

ninlil_wifi_status_t ninlil_wifi_endpoint_list_push(
    ninlil_wifi_endpoint_list_t *list,
    const ninlil_wifi_endpoint_t *endpoint);

/* Select current endpoint; rotates on note_failure. */
ninlil_wifi_status_t ninlil_wifi_reconnect_current_endpoint(
    const ninlil_wifi_reconnect_t *rc,
    ninlil_wifi_endpoint_t *out_endpoint);

/*
 * Record failure at mono_ms. Advances failure_generation, computes
 * not_before = mono_ms + backoff[min(gen-1,5)] (cap 32000), rotates endpoint.
 */
void ninlil_wifi_reconnect_note_failure(
    ninlil_wifi_reconnect_t *rc,
    uint64_t mono_ms);

/* 1 if mono_ms >= not_before. */
int ninlil_wifi_reconnect_ready(
    const ninlil_wifi_reconnect_t *rc,
    uint64_t mono_ms);

void ninlil_wifi_reconnect_note_success(ninlil_wifi_reconnect_t *rc);

/* Call when ATTACHED; after 60s continuous, next failure_generation resets to 1. */
void ninlil_wifi_reconnect_note_attached_stable(
    ninlil_wifi_reconnect_t *rc,
    uint64_t mono_ms);

void ninlil_wifi_reconnect_set_instance_id(
    ninlil_wifi_reconnect_t *rc,
    const uint8_t instance_id[16]);

uint32_t ninlil_wifi_reconnect_backoff_ms(uint32_t failure_generation);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_RECONNECT_H */
