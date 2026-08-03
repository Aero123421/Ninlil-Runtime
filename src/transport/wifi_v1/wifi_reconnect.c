#include "wifi_reconnect.h"

#include "wifi_sha256.h"

#include <string.h>

static const uint32_t k_backoff_ms[NINLIL_WIFI_BACKOFF_STEPS] = {
    1000u, 2000u, 4000u, 8000u, 16000u, 32000u
};

/* ADR-0018: jitter = first_u16_be(SHA-256(instance_id || gen_u64_be)) mod 1000. */
static uint32_t reconnect_jitter_ms(
    const uint8_t instance_id[16],
    uint32_t failure_generation)
{
    uint8_t pre[24];
    uint8_t dig[32];
    uint16_t u16;
    uint64_t gen = (uint64_t)failure_generation;
    if (instance_id == NULL) {
        return 0u;
    }
    (void)memcpy(pre, instance_id, 16u);
    pre[16] = (uint8_t)(gen >> 56);
    pre[17] = (uint8_t)(gen >> 48);
    pre[18] = (uint8_t)(gen >> 40);
    pre[19] = (uint8_t)(gen >> 32);
    pre[20] = (uint8_t)(gen >> 24);
    pre[21] = (uint8_t)(gen >> 16);
    pre[22] = (uint8_t)(gen >> 8);
    pre[23] = (uint8_t)gen;
    ninlil_wifi_sha256(pre, sizeof(pre), dig);
    u16 = (uint16_t)(((uint16_t)dig[0] << 8) | (uint16_t)dig[1]);
    return (uint32_t)(u16 % 1000u);
}

void ninlil_wifi_reconnect_init(ninlil_wifi_reconnect_t *rc)
{
    if (rc == NULL) {
        return;
    }
    (void)memset(rc, 0, sizeof(*rc));
}

void ninlil_wifi_endpoint_list_init(ninlil_wifi_endpoint_list_t *list)
{
    if (list == NULL) {
        return;
    }
    (void)memset(list, 0, sizeof(*list));
}

ninlil_wifi_status_t ninlil_wifi_endpoint_list_push(
    ninlil_wifi_endpoint_list_t *list,
    const ninlil_wifi_endpoint_t *endpoint)
{
    if (list == NULL || endpoint == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (list->count >= 8u) {
        return NINLIL_WIFI_CAPACITY;
    }
    list->endpoints[list->count] = *endpoint;
    list->count = (uint8_t)(list->count + 1u);
    return NINLIL_WIFI_OK;
}

uint32_t ninlil_wifi_reconnect_backoff_ms(uint32_t failure_generation)
{
    if (failure_generation == 0u) {
        return 0u;
    }
    if (failure_generation >= NINLIL_WIFI_BACKOFF_STEPS) {
        return k_backoff_ms[NINLIL_WIFI_BACKOFF_STEPS - 1u];
    }
    return k_backoff_ms[failure_generation - 1u];
}

ninlil_wifi_status_t ninlil_wifi_reconnect_current_endpoint(
    const ninlil_wifi_reconnect_t *rc,
    ninlil_wifi_endpoint_t *out_endpoint)
{
    if (rc == NULL || out_endpoint == NULL || rc->endpoints.count == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *out_endpoint = rc->endpoints.endpoints[rc->endpoints.index % rc->endpoints.count];
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_reconnect_set_instance_id(
    ninlil_wifi_reconnect_t *rc,
    const uint8_t instance_id[16])
{
    if (rc == NULL || instance_id == NULL) {
        return;
    }
    (void)memcpy(rc->instance_id, instance_id, 16u);
}

void ninlil_wifi_reconnect_note_failure(
    ninlil_wifi_reconnect_t *rc,
    uint64_t mono_ms)
{
    uint32_t bo;
    uint32_t jitter;
    uint64_t sum;
    if (rc == NULL) {
        return;
    }
    if (rc->failure_generation == 0xffffffffu) {
        /* checked-add overflow → no automatic reconnect (caller FENCES). */
        rc->not_before_mono_ms = UINT64_MAX;
        return;
    }
    rc->failure_generation += 1u;
    rc->attached_stable_since_ms = 0u;
    bo = ninlil_wifi_reconnect_backoff_ms(rc->failure_generation);
    jitter = reconnect_jitter_ms(rc->instance_id, rc->failure_generation);
    sum = mono_ms + (uint64_t)bo + (uint64_t)jitter;
    if (sum < mono_ms) {
        rc->not_before_mono_ms = UINT64_MAX;
        return;
    }
    rc->not_before_mono_ms = sum;
    if (rc->endpoints.count > 0u) {
        rc->endpoints.index =
            (uint8_t)((rc->endpoints.index + 1u) % rc->endpoints.count);
    }
}

int ninlil_wifi_reconnect_ready(
    const ninlil_wifi_reconnect_t *rc,
    uint64_t mono_ms)
{
    if (rc == NULL) {
        return 0;
    }
    return mono_ms >= rc->not_before_mono_ms ? 1 : 0;
}

void ninlil_wifi_reconnect_note_success(ninlil_wifi_reconnect_t *rc)
{
    if (rc == NULL) {
        return;
    }
    /* Immediate success clears not_before; generation reset only after 60s stable. */
    rc->not_before_mono_ms = 0u;
}

void ninlil_wifi_reconnect_note_attached_stable(
    ninlil_wifi_reconnect_t *rc,
    uint64_t mono_ms)
{
    if (rc == NULL) {
        return;
    }
    if (rc->attached_stable_since_ms == 0u) {
        rc->attached_stable_since_ms = mono_ms;
        return;
    }
    if (mono_ms >= rc->attached_stable_since_ms + 60000u) {
        /* Next failure generation restarts at 1 (note_failure increments). */
        rc->failure_generation = 0u;
    }
}
