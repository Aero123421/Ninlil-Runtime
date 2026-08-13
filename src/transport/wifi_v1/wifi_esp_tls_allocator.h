/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TLS_ALLOCATOR_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TLS_ALLOCATOR_H

/*
 * ADR-0018 private ESP TLS allocator owner/accounting profile.
 *
 * This is the sole translation unit allowed to call heap_caps_calloc/free for
 * the direct mbedTLS closure.  It installs the mbedTLS allocator once, assigns
 * every allocation to a bounded owner, and fails closed on budget/counter/list
 * corruption.  Host builds expose semantic no-op stubs for owner tests.
 */
#include "wifi_private_types.h"
#include "wifi_tls_resource_policy.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID UINT32_MAX
#define NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1 \
    UINT32_C(0x52375231) /* "R7R1", non-wire */
#define NINLIL_WIFI_ESP_TLS_ALLOC_TRACE_CAPACITY 32u

typedef uint32_t ninlil_wifi_esp_tls_alloc_trace_event_t;
#define NINLIL_WIFI_ESP_TLS_TRACE_BOOTSTRAP \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)1u)
#define NINLIL_WIFI_ESP_TLS_TRACE_REGISTER \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)2u)
#define NINLIL_WIFI_ESP_TLS_TRACE_ENTER \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)3u)
#define NINLIL_WIFI_ESP_TLS_TRACE_ALLOC \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)4u)
#define NINLIL_WIFI_ESP_TLS_TRACE_FREE \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)5u)
#define NINLIL_WIFI_ESP_TLS_TRACE_LEAVE \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)6u)
#define NINLIL_WIFI_ESP_TLS_TRACE_RELEASE \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)7u)
#define NINLIL_WIFI_ESP_TLS_TRACE_FATAL \
    ((ninlil_wifi_esp_tls_alloc_trace_event_t)8u)

typedef struct ninlil_wifi_esp_tls_allocator_snapshot {
    uint32_t current_bytes;
    uint32_t peak_bytes;
    uint32_t internal_current_bytes;
    uint32_t internal_peak_bytes;
    uint32_t psram_current_bytes;
    uint32_t psram_peak_bytes;
    uint32_t internal_reserved_bytes;
    uint32_t psram_reserved_bytes;
    uint32_t outstanding_allocations;
    uint32_t oom_count;
    uint32_t corruption_count;
    uint32_t admission_reject_reason;
} ninlil_wifi_esp_tls_allocator_snapshot_t;

typedef struct ninlil_wifi_esp_tls_allocator_aggregate_snapshot {
    uint32_t current_bytes;
    uint32_t peak_bytes;
    uint32_t reserved_bytes;
    uint32_t crypto_global_reserved_bytes;
    uint32_t tls_session_reserved_bytes;
    uint32_t other_registered_reserved_bytes;
    uint32_t outstanding_allocations;
    uint32_t active_tls_sessions;
    uint32_t active_other_registered;
    uint32_t current_owner;
    uint32_t trace_count;
    uint32_t trace_dropped;
    uint8_t bootstrapped;
    uint8_t owner_active;
    uint8_t fatal;
    uint8_t reserved0;
} ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t;

typedef struct ninlil_wifi_esp_tls_allocator_trace_record {
    uint32_t sequence;
    uint32_t event;
    uint32_t owner;
    uint32_t component_id;
    uint32_t requested_bytes;
    uint32_t current_bytes;
    uint32_t outstanding_allocations;
    uint32_t status;
} ninlil_wifi_esp_tls_allocator_trace_record_t;

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_bootstrap(void);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_session_register(
    uint32_t *out_owner);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_register(
    uint32_t component_id,
    uint32_t reservation_bytes,
    uint32_t *out_owner);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_owner_enter(
    uint32_t owner);

void ninlil_wifi_esp_tls_allocator_owner_leave(uint32_t owner);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_owner_leave_checked(
    uint32_t owner);

/*
 * Exact pinned classification window around mbedtls_ssl_setup().  Only one
 * 16685-byte inbound and one 4415-byte outbound buffer may enter PSRAM.
 */
ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_io_begin(uint32_t owner);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_io_finish(
    uint32_t owner,
    const void *in_buffer,
    size_t in_buffer_bytes,
    const void *out_buffer,
    size_t out_buffer_bytes);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_session_release(
    uint32_t owner);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_release(
    uint32_t owner);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_snapshot(
    uint32_t owner,
    ninlil_wifi_esp_tls_allocator_snapshot_t *out);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_snapshot(
    uint32_t component_id,
    ninlil_wifi_esp_tls_allocator_snapshot_t *out);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_aggregate_snapshot(
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t *out);

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_trace_at(
    uint32_t index,
    ninlil_wifi_esp_tls_allocator_trace_record_t *out);

#if defined(NINLIL_WIFI_ESP_TLS_ALLOCATOR_TEST_BUILD)
/* Exact production-code fault seams; absent from production component builds. */
void ninlil_wifi_esp_tls_allocator_test_set_fail_after(
    uint32_t owner,
    size_t successful_attempts);
void *ninlil_wifi_esp_tls_allocator_test_calloc(
    size_t count,
    size_t size);
void ninlil_wifi_esp_tls_allocator_test_free(void *pointer);
void ninlil_wifi_esp_tls_allocator_test_force_callback_recursion(void);
void ninlil_wifi_esp_tls_allocator_test_reset(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_ESP_TLS_ALLOCATOR_H */
