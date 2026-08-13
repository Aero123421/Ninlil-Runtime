/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_esp_tls_allocator.h"

#include "wifi_tls_arena.h"

#include <stdint.h>
#include <string.h>

#if defined(ESP_PLATFORM)

#include "esp_heap_caps.h"
#include "esp_memory_utils.h"
#include "esp_psram.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"

#define WIFI_TLS_ALLOC_OWNER_COUNT NINLIL_WIFI_ESP_TLS_MAX_SESSIONS
#define WIFI_TLS_GLOBAL_OWNER WIFI_TLS_ALLOC_OWNER_COUNT
#define WIFI_TLS_OTHER_R7_OWNER (WIFI_TLS_GLOBAL_OWNER + 1u)
#define WIFI_TLS_INTERNAL_CAPS (MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)
#define WIFI_TLS_PSRAM_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#define WIFI_TLS_R7_HMAC_BYTES 128u

#if defined(MBEDTLS_MD_SHA256_VIA_PSA)
#error "ADR-0026 exact R7 budget requires legacy SHA-256 md allocation"
#endif

#if !defined(NINLIL_WIFI_ESP_TLS_ALLOCATOR_TEST_BUILD)
_Static_assert(sizeof(max_align_t) == 16u, "pinned Xtensa max_align_t size");
_Static_assert(_Alignof(max_align_t) == 8u, "pinned Xtensa max_align_t alignment");
_Static_assert(
    ((16u + sizeof(mbedtls_sha256_context) + 4u + 7u) & ~(size_t)7u)
        == 128u,
    "pinned R7 SHA-256 arena charge");
_Static_assert(
    ((16u + WIFI_TLS_R7_HMAC_BYTES + 4u + 7u) & ~(size_t)7u)
        == 152u,
    "pinned R7 HMAC arena charge");
_Static_assert(
    128u + 152u <= NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET,
    "pinned R7 HKDF peak fits OTHER_REGISTERED reservation");
_Static_assert(
    NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET == 304u,
    "pinned R7 GCM AES-context charge is the reservation maximum");
#endif

typedef struct wifi_tls_alloc_owner {
    uint8_t active;
    uint8_t entered;
    uint8_t allocation_oom;
    uint8_t contract_failed;
    uint32_t admission_reject_reason;
    ninlil_wifi_tls_io_classifier_t io_classifier;
    void *internal_region;
    void *psram_region;
    ninlil_wifi_tls_arena_t internal_arena;
    ninlil_wifi_tls_arena_t psram_arena;
} wifi_tls_alloc_owner_t;

typedef struct wifi_tls_registered_owner {
    uint8_t active;
    uint8_t entered;
    uint8_t allocation_oom;
    uint8_t contract_failed;
    uint32_t component_id;
    uint32_t reservation_bytes;
    void *region;
    ninlil_wifi_tls_arena_t arena;
} wifi_tls_registered_owner_t;

static struct {
    uint8_t bootstrapped;
    uint8_t callback_active;
    uint8_t owner_active;
    uint8_t fatal;
    uint32_t current_owner;
    uint32_t aggregate_peak_bytes;
    uint32_t trace_count;
    uint32_t trace_dropped;
    uint32_t trace_next_sequence;
    void *global_region;
    ninlil_wifi_tls_arena_t global_arena;
    wifi_tls_alloc_owner_t owners[WIFI_TLS_ALLOC_OWNER_COUNT];
    wifi_tls_registered_owner_t other_r7;
    ninlil_wifi_esp_tls_allocator_trace_record_t
        trace[NINLIL_WIFI_ESP_TLS_ALLOC_TRACE_CAPACITY];
} s_allocator;

static uint32_t owner_component_id(uint32_t owner)
{
    return owner == WIFI_TLS_OTHER_R7_OWNER
        ? NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1
        : 0u;
}

static int aggregate_current(
    uint32_t *out_current,
    uint32_t *out_outstanding)
{
    ninlil_wifi_tls_arena_snapshot_t snapshot;
    uint32_t current = 0u;
    uint32_t outstanding = 0u;
    uint32_t index;
    if (out_current == NULL || out_outstanding == NULL) {
        return 0;
    }
    if (s_allocator.bootstrapped != 0u) {
        if (ninlil_wifi_tls_arena_snapshot(
                &s_allocator.global_arena, &snapshot)
            != NINLIL_WIFI_TLS_ARENA_OK) {
            return 0;
        }
        current += (uint32_t)snapshot.current_bytes;
        outstanding += snapshot.outstanding_allocations;
    }
    for (index = 0u; index < WIFI_TLS_ALLOC_OWNER_COUNT; ++index) {
        if (s_allocator.owners[index].active == 0u) {
            continue;
        }
        if (ninlil_wifi_tls_arena_snapshot(
                &s_allocator.owners[index].internal_arena, &snapshot)
                != NINLIL_WIFI_TLS_ARENA_OK
            || current > UINT32_MAX - (uint32_t)snapshot.current_bytes
            || outstanding
                > UINT32_MAX - snapshot.outstanding_allocations) {
            return 0;
        }
        current += (uint32_t)snapshot.current_bytes;
        outstanding += snapshot.outstanding_allocations;
        if (ninlil_wifi_tls_arena_snapshot(
                &s_allocator.owners[index].psram_arena, &snapshot)
                != NINLIL_WIFI_TLS_ARENA_OK
            || current > UINT32_MAX - (uint32_t)snapshot.current_bytes
            || outstanding
                > UINT32_MAX - snapshot.outstanding_allocations) {
            return 0;
        }
        current += (uint32_t)snapshot.current_bytes;
        outstanding += snapshot.outstanding_allocations;
    }
    if (s_allocator.other_r7.active != 0u) {
        if (ninlil_wifi_tls_arena_snapshot(
                &s_allocator.other_r7.arena, &snapshot)
                != NINLIL_WIFI_TLS_ARENA_OK
            || current > UINT32_MAX - (uint32_t)snapshot.current_bytes
            || outstanding
                > UINT32_MAX - snapshot.outstanding_allocations) {
            return 0;
        }
        current += (uint32_t)snapshot.current_bytes;
        outstanding += snapshot.outstanding_allocations;
    }
    *out_current = current;
    *out_outstanding = outstanding;
    return 1;
}

static void trace_append(
    ninlil_wifi_esp_tls_alloc_trace_event_t event,
    uint32_t owner,
    uint32_t requested_bytes,
    ninlil_wifi_status_t status)
{
    uint32_t current = 0u;
    uint32_t outstanding = 0u;
    uint32_t sequence = s_allocator.trace_next_sequence++;
    if (s_allocator.trace_count >= NINLIL_WIFI_ESP_TLS_ALLOC_TRACE_CAPACITY) {
        s_allocator.trace_dropped += 1u;
        return;
    }
    (void)aggregate_current(&current, &outstanding);
    s_allocator.trace[s_allocator.trace_count].sequence = sequence;
    s_allocator.trace[s_allocator.trace_count].event = event;
    s_allocator.trace[s_allocator.trace_count].owner = owner;
    s_allocator.trace[s_allocator.trace_count].component_id =
        owner_component_id(owner);
    s_allocator.trace[s_allocator.trace_count].requested_bytes =
        requested_bytes;
    s_allocator.trace[s_allocator.trace_count].current_bytes = current;
    s_allocator.trace[s_allocator.trace_count].outstanding_allocations =
        outstanding;
    s_allocator.trace[s_allocator.trace_count].status = status;
    s_allocator.trace_count += 1u;
}

static void update_aggregate_peak(void)
{
    uint32_t current;
    uint32_t outstanding;
    if (aggregate_current(&current, &outstanding)
        && current > s_allocator.aggregate_peak_bytes) {
        s_allocator.aggregate_peak_bytes = current;
    }
    (void)outstanding;
}

static void fatal_fence(uint32_t owner)
{
    if (s_allocator.fatal == 0u) {
        s_allocator.fatal = 1u;
        trace_append(
            NINLIL_WIFI_ESP_TLS_TRACE_FATAL,
            owner,
            0u,
            NINLIL_WIFI_CORRUPT);
    }
}

static void secure_zero(void *pointer, size_t bytes)
{
    volatile uint8_t *cursor = (volatile uint8_t *)pointer;
    while (cursor != NULL && bytes != 0u) {
        *cursor++ = 0u;
        --bytes;
    }
}

static uint32_t active_session_count(void)
{
    uint32_t count = 0u;
    uint32_t index;
    for (index = 0u; index < WIFI_TLS_ALLOC_OWNER_COUNT; ++index) {
        if (s_allocator.owners[index].active != 0u) {
            count += 1u;
        }
    }
    return count;
}

static void release_raw_region(void *region, size_t bytes)
{
    if (region != NULL) {
        secure_zero(region, bytes);
        heap_caps_free(region);
    }
}

/*
 * Sole dynamic allocation callback for the mbedTLS closure.  It only
 * suballocates from already-reserved arenas; there is no heap fallback.
 */
static void *wifi_tls_profile_calloc(size_t count, size_t size)
{
    ninlil_wifi_tls_arena_t *arena = NULL;
    ninlil_wifi_tls_arena_snapshot_t snapshot;
    wifi_tls_alloc_owner_t *owner = NULL;
    wifi_tls_registered_owner_t *registered = NULL;
    ninlil_wifi_tls_allocation_tier_t tier =
        NINLIL_WIFI_TLS_ALLOCATION_INTERNAL;
    size_t requested;
    void *result;
    if (s_allocator.fatal != 0u) {
        return NULL;
    }
    if (s_allocator.callback_active != 0u
        || s_allocator.bootstrapped == 0u
        || s_allocator.owner_active == 0u
        || (count != 0u && size > SIZE_MAX / count)) {
        fatal_fence(s_allocator.current_owner);
        return NULL;
    }
    requested = count * size;
    if (s_allocator.current_owner == WIFI_TLS_GLOBAL_OWNER) {
        arena = &s_allocator.global_arena;
    } else if (s_allocator.current_owner < WIFI_TLS_ALLOC_OWNER_COUNT) {
        owner = &s_allocator.owners[s_allocator.current_owner];
        if (owner->active == 0u || owner->entered == 0u) {
            fatal_fence(s_allocator.current_owner);
            return NULL;
        }
        tier = ninlil_wifi_tls_io_classifier_route(
            &owner->io_classifier, requested);
        if (tier == NINLIL_WIFI_TLS_ALLOCATION_REJECT) {
            owner->contract_failed = 1u;
            return NULL;
        }
        arena = tier == NINLIL_WIFI_TLS_ALLOCATION_PSRAM_IO
            ? &owner->psram_arena
            : &owner->internal_arena;
    } else if (s_allocator.current_owner == WIFI_TLS_OTHER_R7_OWNER) {
        registered = &s_allocator.other_r7;
        if (registered->active == 0u || registered->entered == 0u
            || registered->component_id
                != NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1) {
            fatal_fence(s_allocator.current_owner);
            return NULL;
        }
        arena = &registered->arena;
    } else {
        fatal_fence(s_allocator.current_owner);
        return NULL;
    }

    s_allocator.callback_active = 1u;
    result = ninlil_wifi_tls_arena_calloc(arena, count, size);
    s_allocator.callback_active = 0u;
    /*
     * Ordinary exhaustion is a connection-local allocation failure.  A NULL
     * caused by damaged arena metadata is a process-wide allocator contract
     * failure: fence every later mbedTLS entry instead of disguising it as
     * OOM or spilling to another heap.
     */
    if (result == NULL
        && ninlil_wifi_tls_arena_snapshot(arena, &snapshot)
            != NINLIL_WIFI_TLS_ARENA_OK) {
        fatal_fence(s_allocator.current_owner);
    } else if (result == NULL && owner != NULL) {
        owner->allocation_oom = 1u;
    } else if (result == NULL && registered != NULL) {
        registered->allocation_oom = 1u;
    } else if (result == NULL) {
        fatal_fence(s_allocator.current_owner);
    } else {
        update_aggregate_peak();
    }
    if (s_allocator.current_owner != WIFI_TLS_GLOBAL_OWNER) {
        trace_append(
            NINLIL_WIFI_ESP_TLS_TRACE_ALLOC,
            s_allocator.current_owner,
            requested > UINT32_MAX ? UINT32_MAX : (uint32_t)requested,
            result == NULL ? NINLIL_WIFI_UNAVAILABLE : NINLIL_WIFI_OK);
    }
    return result;
}

static void wifi_tls_profile_free(void *pointer)
{
    ninlil_wifi_tls_arena_status_t status =
        NINLIL_WIFI_TLS_ARENA_FOREIGN_POINTER;
    if (pointer == NULL) {
        return;
    }
    if (s_allocator.callback_active != 0u
        || s_allocator.owner_active == 0u || s_allocator.fatal != 0u) {
        fatal_fence(s_allocator.current_owner);
        return;
    }
    s_allocator.callback_active = 1u;
    if (s_allocator.current_owner == WIFI_TLS_GLOBAL_OWNER) {
        status = ninlil_wifi_tls_arena_free_owned_pair(
            &s_allocator.global_arena, NULL, pointer);
    } else if (s_allocator.current_owner < WIFI_TLS_ALLOC_OWNER_COUNT) {
        wifi_tls_alloc_owner_t *owner =
            &s_allocator.owners[s_allocator.current_owner];
        if (owner->active != 0u && owner->entered != 0u) {
            status = ninlil_wifi_tls_arena_free_owned_pair(
                &owner->internal_arena, &owner->psram_arena, pointer);
        }
    } else if (s_allocator.current_owner == WIFI_TLS_OTHER_R7_OWNER
        && s_allocator.other_r7.active != 0u
        && s_allocator.other_r7.entered != 0u) {
        status = ninlil_wifi_tls_arena_free_owned_pair(
            &s_allocator.other_r7.arena, NULL, pointer);
    }
    s_allocator.callback_active = 0u;
    if (status != NINLIL_WIFI_TLS_ARENA_OK) {
        fatal_fence(s_allocator.current_owner);
    }
    if (s_allocator.current_owner != WIFI_TLS_GLOBAL_OWNER) {
        trace_append(
            NINLIL_WIFI_ESP_TLS_TRACE_FREE,
            s_allocator.current_owner,
            0u,
            status == NINLIL_WIFI_TLS_ARENA_OK
                ? NINLIL_WIFI_OK
                : NINLIL_WIFI_CORRUPT);
    }
}

static void bootstrap_rollback(void)
{
    void *region = s_allocator.global_region;
    s_allocator.global_region = NULL;
    if (region != NULL) {
        (void)ninlil_wifi_tls_arena_zeroize(&s_allocator.global_arena);
        release_raw_region(
            region, NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET);
    }
    (void)memset(&s_allocator, 0, sizeof(s_allocator));
}

static int crypto_global_prewarm(void)
{
    static const uint8_t seed[16] = {
        0x4eu, 0x69u, 0x6eu, 0x6cu, 0x69u, 0x6cu, 0x2du, 0x57u,
        0x69u, 0x46u, 0x69u, 0x2du, 0x56u, 0x31u, 0x00u, 0x01u
    };
    uint8_t digest[32];
    uint8_t hkdf_output[32];
    mbedtls_ecp_group group;
    mbedtls_gcm_context gcm;
    mbedtls_x509_crt certificate;
    const mbedtls_md_info_t *sha256;
    int rc = -1;

    mbedtls_ecp_group_init(&group);
    mbedtls_gcm_init(&gcm);
    mbedtls_x509_crt_init(&certificate);
    sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (sha256 != NULL
        && mbedtls_sha256(seed, sizeof(seed), digest, 0) == 0
        && mbedtls_hkdf(
               sha256,
               seed,
               sizeof(seed),
               digest,
               sizeof(digest),
               seed,
               sizeof(seed),
               hkdf_output,
               sizeof(hkdf_output))
            == 0
        && mbedtls_gcm_setkey(
               &gcm, MBEDTLS_CIPHER_ID_AES, seed, 128u)
            == 0
        && mbedtls_ecp_group_load(
               &group, MBEDTLS_ECP_DP_SECP256R1)
            == 0) {
        rc = 0;
    }
    mbedtls_x509_crt_free(&certificate);
    mbedtls_gcm_free(&gcm);
    mbedtls_ecp_group_free(&group);
    secure_zero(digest, sizeof(digest));
    secure_zero(hkdf_output, sizeof(hkdf_output));
    return rc;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_bootstrap(void)
{
    void *region;
    int rc;
    if (s_allocator.fatal != 0u) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (s_allocator.bootstrapped != 0u) {
        return NINLIL_WIFI_OK;
    }
    (void)memset(&s_allocator, 0, sizeof(s_allocator));
    s_allocator.current_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    if (heap_caps_get_largest_free_block(WIFI_TLS_INTERNAL_CAPS)
            < NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET
        || heap_caps_get_free_size(WIFI_TLS_INTERNAL_CAPS)
            < NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET) {
        return NINLIL_WIFI_CAPACITY;
    }
    region = heap_caps_calloc(
        1u,
        NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET,
        WIFI_TLS_INTERNAL_CAPS);
    if (region == NULL || !esp_ptr_internal(region)) {
        release_raw_region(
            region, NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET);
        return NINLIL_WIFI_CAPACITY;
    }
    s_allocator.global_region = region;
    if (ninlil_wifi_tls_arena_init(
            &s_allocator.global_arena,
            region,
            NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET)
        != NINLIL_WIFI_TLS_ARENA_OK) {
        bootstrap_rollback();
        return NINLIL_WIFI_CORRUPT;
    }
    /*
     * This setter is the first mbedTLS/PSA/crypto API.  The global INTERNAL
     * reservation therefore exists before any library initialization.
     */
    rc = mbedtls_platform_set_calloc_free(
        wifi_tls_profile_calloc, wifi_tls_profile_free);
    if (rc != 0) {
        bootstrap_rollback();
        return NINLIL_WIFI_UNSUPPORTED;
    }
    s_allocator.bootstrapped = 1u;
    s_allocator.owner_active = 1u;
    s_allocator.current_owner = WIFI_TLS_GLOBAL_OWNER;
    if (crypto_global_prewarm() != 0 || s_allocator.fatal != 0u) {
        s_allocator.owner_active = 0u;
        s_allocator.current_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
        fatal_fence(WIFI_TLS_GLOBAL_OWNER);
        return NINLIL_WIFI_UNSUPPORTED;
    }
    s_allocator.owner_active = 0u;
    s_allocator.current_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    trace_append(
        NINLIL_WIFI_ESP_TLS_TRACE_BOOTSTRAP,
        WIFI_TLS_GLOBAL_OWNER,
        NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET,
        NINLIL_WIFI_OK);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_session_register(
    uint32_t *out_owner)
{
    ninlil_wifi_tls_resource_view_t view;
    ninlil_wifi_tls_admission_result_t admission;
    wifi_tls_alloc_owner_t *slot = NULL;
    void *internal_region = NULL;
    void *psram_region = NULL;
    uint32_t index;
    if (out_owner != NULL) {
        *out_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    }
    if (out_owner == NULL || s_allocator.bootstrapped == 0u
        || s_allocator.fatal != 0u || s_allocator.owner_active != 0u) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    (void)memset(&view, 0, sizeof(view));
    view.active_sessions = active_session_count();
    view.psram_enabled = esp_psram_is_initialized() ? 1u : 0u;
    view.internal_free_bytes =
        heap_caps_get_free_size(WIFI_TLS_INTERNAL_CAPS);
    view.internal_largest_free_block_bytes =
        heap_caps_get_largest_free_block(WIFI_TLS_INTERNAL_CAPS);
    view.psram_free_bytes = heap_caps_get_free_size(WIFI_TLS_PSRAM_CAPS);
    view.psram_largest_free_block_bytes =
        heap_caps_get_largest_free_block(WIFI_TLS_PSRAM_CAPS);
    admission = ninlil_wifi_tls_resource_admit(&view);
    if (admission != NINLIL_WIFI_TLS_ADMISSION_OK) {
        return admission == NINLIL_WIFI_TLS_ADMISSION_SESSION_CAPACITY
            ? NINLIL_WIFI_CAPACITY
            : NINLIL_WIFI_UNAVAILABLE;
    }
    for (index = 0u; index < WIFI_TLS_ALLOC_OWNER_COUNT; ++index) {
        if (s_allocator.owners[index].active == 0u) {
            slot = &s_allocator.owners[index];
            break;
        }
    }
    if (slot == NULL) {
        return NINLIL_WIFI_CAPACITY;
    }

    internal_region = heap_caps_calloc(
        1u,
        NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET,
        WIFI_TLS_INTERNAL_CAPS);
    if (internal_region == NULL || !esp_ptr_internal(internal_region)) {
        release_raw_region(
            internal_region, NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET);
        return NINLIL_WIFI_UNAVAILABLE;
    }
    psram_region = heap_caps_calloc(
        1u,
        NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET,
        WIFI_TLS_PSRAM_CAPS);
    if (psram_region == NULL || !esp_ptr_external_ram(psram_region)
        || heap_caps_get_free_size(WIFI_TLS_INTERNAL_CAPS)
            < NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP) {
        release_raw_region(
            psram_region, NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET);
        release_raw_region(
            internal_region, NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET);
        return NINLIL_WIFI_UNAVAILABLE;
    }

    (void)memset(slot, 0, sizeof(*slot));
    slot->internal_region = internal_region;
    slot->psram_region = psram_region;
    slot->admission_reject_reason = NINLIL_WIFI_TLS_ADMISSION_OK;
    if (ninlil_wifi_tls_arena_init(
            &slot->internal_arena,
            internal_region,
            NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET)
            != NINLIL_WIFI_TLS_ARENA_OK
        || ninlil_wifi_tls_arena_init(
               &slot->psram_arena,
               psram_region,
               NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET)
            != NINLIL_WIFI_TLS_ARENA_OK) {
        release_raw_region(
            psram_region, NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET);
        release_raw_region(
            internal_region, NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET);
        (void)memset(slot, 0, sizeof(*slot));
        fatal_fence(index);
        return NINLIL_WIFI_CORRUPT;
    }
    slot->active = 1u;
    *out_owner = index;
    trace_append(
        NINLIL_WIFI_ESP_TLS_TRACE_REGISTER,
        index,
        NINLIL_WIFI_ESP_TLS_SESSION_ALLOCATION_BUDGET,
        NINLIL_WIFI_OK);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_register(
    uint32_t component_id,
    uint32_t reservation_bytes,
    uint32_t *out_owner)
{
    void *region = NULL;
    wifi_tls_registered_owner_t *registered = &s_allocator.other_r7;
    if (out_owner != NULL) {
        *out_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    }
    if (out_owner == NULL
        || component_id != NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1
        || reservation_bytes
            != NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (s_allocator.bootstrapped == 0u || s_allocator.fatal != 0u
        || s_allocator.owner_active != 0u) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (registered->active != 0u) {
        return registered->component_id == component_id
                && registered->reservation_bytes == reservation_bytes
            ? NINLIL_WIFI_INVALID_STATE
            : NINLIL_WIFI_DENIED;
    }
    if (heap_caps_get_largest_free_block(WIFI_TLS_INTERNAL_CAPS)
            < reservation_bytes
        || heap_caps_get_free_size(WIFI_TLS_INTERNAL_CAPS)
            < (size_t)reservation_bytes
                + NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    region = heap_caps_calloc(
        1u, reservation_bytes, WIFI_TLS_INTERNAL_CAPS);
    if (region == NULL || !esp_ptr_internal(region)
        || heap_caps_get_free_size(WIFI_TLS_INTERNAL_CAPS)
            < NINLIL_WIFI_ESP_TLS_MIN_FREE_INTERNAL_HEAP) {
        release_raw_region(region, reservation_bytes);
        return NINLIL_WIFI_UNAVAILABLE;
    }
    (void)memset(registered, 0, sizeof(*registered));
    registered->region = region;
    registered->component_id = component_id;
    registered->reservation_bytes = reservation_bytes;
    if (ninlil_wifi_tls_arena_init(
            &registered->arena, region, reservation_bytes)
        != NINLIL_WIFI_TLS_ARENA_OK) {
        release_raw_region(region, reservation_bytes);
        (void)memset(registered, 0, sizeof(*registered));
        fatal_fence(WIFI_TLS_OTHER_R7_OWNER);
        return NINLIL_WIFI_CORRUPT;
    }
    registered->active = 1u;
    *out_owner = WIFI_TLS_OTHER_R7_OWNER;
    trace_append(
        NINLIL_WIFI_ESP_TLS_TRACE_REGISTER,
        WIFI_TLS_OTHER_R7_OWNER,
        reservation_bytes,
        NINLIL_WIFI_OK);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_owner_enter(uint32_t owner)
{
    if (s_allocator.bootstrapped == 0u || s_allocator.fatal != 0u) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (s_allocator.owner_active != 0u) {
        fatal_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    if (owner < WIFI_TLS_ALLOC_OWNER_COUNT) {
        if (s_allocator.owners[owner].active == 0u
            || s_allocator.owners[owner].entered != 0u) {
            return NINLIL_WIFI_INVALID_STATE;
        }
        s_allocator.owners[owner].entered = 1u;
    } else if (owner == WIFI_TLS_OTHER_R7_OWNER) {
        if (s_allocator.other_r7.active == 0u
            || s_allocator.other_r7.entered != 0u) {
            return NINLIL_WIFI_INVALID_STATE;
        }
        s_allocator.other_r7.entered = 1u;
        s_allocator.other_r7.allocation_oom = 0u;
        s_allocator.other_r7.contract_failed = 0u;
    } else {
        return NINLIL_WIFI_INVALID_STATE;
    }
    s_allocator.owner_active = 1u;
    s_allocator.current_owner = owner;
    trace_append(
        NINLIL_WIFI_ESP_TLS_TRACE_ENTER, owner, 0u, NINLIL_WIFI_OK);
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_esp_tls_allocator_owner_leave(uint32_t owner)
{
    (void)ninlil_wifi_esp_tls_allocator_owner_leave_checked(owner);
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_owner_leave_checked(
    uint32_t owner)
{
    ninlil_wifi_status_t status = NINLIL_WIFI_OK;
    if (s_allocator.fatal != 0u) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (owner < WIFI_TLS_ALLOC_OWNER_COUNT
        && s_allocator.owner_active != 0u
        && s_allocator.current_owner == owner
        && s_allocator.owners[owner].entered != 0u
        && s_allocator.owners[owner].io_classifier.active == 0u) {
        s_allocator.owners[owner].entered = 0u;
        if (s_allocator.owners[owner].contract_failed != 0u) {
            status = NINLIL_WIFI_CORRUPT;
        } else if (s_allocator.owners[owner].allocation_oom != 0u) {
            status = NINLIL_WIFI_UNAVAILABLE;
        }
    } else if (owner == WIFI_TLS_OTHER_R7_OWNER
        && s_allocator.owner_active != 0u
        && s_allocator.current_owner == owner
        && s_allocator.other_r7.active != 0u
        && s_allocator.other_r7.entered != 0u) {
        s_allocator.other_r7.entered = 0u;
        if (s_allocator.other_r7.contract_failed != 0u) {
            status = NINLIL_WIFI_CORRUPT;
        } else if (s_allocator.other_r7.allocation_oom != 0u) {
            status = NINLIL_WIFI_UNAVAILABLE;
        }
    } else {
        fatal_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    s_allocator.current_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    s_allocator.owner_active = 0u;
    trace_append(
        NINLIL_WIFI_ESP_TLS_TRACE_LEAVE, owner, 0u, status);
    return status;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_io_begin(uint32_t owner)
{
    wifi_tls_alloc_owner_t *slot;
    if (owner >= WIFI_TLS_ALLOC_OWNER_COUNT || s_allocator.fatal != 0u
        || s_allocator.owner_active == 0u
        || s_allocator.current_owner != owner) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    slot = &s_allocator.owners[owner];
    if (slot->active == 0u || slot->entered == 0u
        || slot->contract_failed != 0u || slot->allocation_oom != 0u
        || !ninlil_wifi_tls_io_classifier_begin(&slot->io_classifier)) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_io_finish(
    uint32_t owner,
    const void *in_buffer,
    size_t in_buffer_bytes,
    const void *out_buffer,
    size_t out_buffer_bytes)
{
    wifi_tls_alloc_owner_t *slot;
    ninlil_wifi_tls_arena_status_t in_status;
    ninlil_wifi_tls_arena_status_t out_status;
    int classifier_valid;
    if (owner >= WIFI_TLS_ALLOC_OWNER_COUNT || s_allocator.fatal != 0u
        || s_allocator.owner_active == 0u
        || s_allocator.current_owner != owner) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    slot = &s_allocator.owners[owner];
    if (slot->active == 0u || slot->entered == 0u
        || slot->io_classifier.active == 0u) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    classifier_valid =
        ninlil_wifi_tls_io_classifier_finish(&slot->io_classifier);
    if (slot->contract_failed != 0u) {
        slot->contract_failed = 1u;
        return NINLIL_WIFI_CORRUPT;
    }
    if (slot->allocation_oom != 0u) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (!classifier_valid) {
        slot->contract_failed = 1u;
        return NINLIL_WIFI_CORRUPT;
    }
    in_status = ninlil_wifi_tls_arena_validate_live_allocation(
        &slot->psram_arena,
        in_buffer,
        NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES);
    out_status = ninlil_wifi_tls_arena_validate_live_allocation(
        &slot->psram_arena,
        out_buffer,
        NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES);
    if (in_status == NINLIL_WIFI_TLS_ARENA_CORRUPT
        || out_status == NINLIL_WIFI_TLS_ARENA_CORRUPT) {
        fatal_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    if (in_status != NINLIL_WIFI_TLS_ARENA_OK
        || out_status != NINLIL_WIFI_TLS_ARENA_OK
        || in_buffer_bytes != NINLIL_WIFI_ESP_TLS_IN_BUFFER_BYTES
        || out_buffer_bytes != NINLIL_WIFI_ESP_TLS_OUT_BUFFER_BYTES
        || !esp_ptr_external_ram(in_buffer)
        || !esp_ptr_external_ram(out_buffer)) {
        slot->contract_failed = 1u;
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_session_release(
    uint32_t owner)
{
    wifi_tls_alloc_owner_t *slot;
    ninlil_wifi_tls_arena_snapshot_t internal_snapshot;
    ninlil_wifi_tls_arena_snapshot_t psram_snapshot;
    void *internal_region;
    void *psram_region;
    if (owner >= WIFI_TLS_ALLOC_OWNER_COUNT || s_allocator.fatal != 0u) {
        return NINLIL_WIFI_CORRUPT;
    }
    slot = &s_allocator.owners[owner];
    if (slot->active == 0u || slot->entered != 0u
        || slot->io_classifier.active != 0u
        || ninlil_wifi_tls_arena_snapshot(
               &slot->internal_arena, &internal_snapshot)
            != NINLIL_WIFI_TLS_ARENA_OK
        || ninlil_wifi_tls_arena_snapshot(
               &slot->psram_arena, &psram_snapshot)
            != NINLIL_WIFI_TLS_ARENA_OK
        || internal_snapshot.current_bytes != 0u
        || internal_snapshot.outstanding_allocations != 0u
        || psram_snapshot.current_bytes != 0u
        || psram_snapshot.outstanding_allocations != 0u) {
        fatal_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    internal_region = slot->internal_region;
    psram_region = slot->psram_region;
    if (ninlil_wifi_tls_arena_zeroize(&slot->internal_arena)
            != NINLIL_WIFI_TLS_ARENA_OK
        || ninlil_wifi_tls_arena_zeroize(&slot->psram_arena)
            != NINLIL_WIFI_TLS_ARENA_OK) {
        fatal_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    release_raw_region(
        psram_region, NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET);
    release_raw_region(
        internal_region, NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET);
    (void)memset(slot, 0, sizeof(*slot));
    trace_append(
        NINLIL_WIFI_ESP_TLS_TRACE_RELEASE,
        owner,
        NINLIL_WIFI_ESP_TLS_SESSION_ALLOCATION_BUDGET,
        NINLIL_WIFI_OK);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_release(
    uint32_t owner)
{
    wifi_tls_registered_owner_t *registered = &s_allocator.other_r7;
    ninlil_wifi_tls_arena_snapshot_t snapshot;
    void *region;
    uint32_t reservation_bytes;
    if (owner != WIFI_TLS_OTHER_R7_OWNER || s_allocator.fatal != 0u) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (registered->active == 0u || registered->entered != 0u
        || s_allocator.owner_active != 0u
        || registered->component_id
            != NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1
        || ninlil_wifi_tls_arena_snapshot(&registered->arena, &snapshot)
            != NINLIL_WIFI_TLS_ARENA_OK
        || snapshot.current_bytes != 0u
        || snapshot.outstanding_allocations != 0u) {
        fatal_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    region = registered->region;
    reservation_bytes = registered->reservation_bytes;
    if (reservation_bytes
            != NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET
        || ninlil_wifi_tls_arena_zeroize(&registered->arena)
            != NINLIL_WIFI_TLS_ARENA_OK) {
        fatal_fence(owner);
        return NINLIL_WIFI_CORRUPT;
    }
    release_raw_region(region, reservation_bytes);
    (void)memset(registered, 0, sizeof(*registered));
    trace_append(
        NINLIL_WIFI_ESP_TLS_TRACE_RELEASE,
        owner,
        reservation_bytes,
        NINLIL_WIFI_OK);
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_snapshot(
    uint32_t owner,
    ninlil_wifi_esp_tls_allocator_snapshot_t *out)
{
    const wifi_tls_alloc_owner_t *slot;
    ninlil_wifi_tls_arena_snapshot_t internal_snapshot;
    ninlil_wifi_tls_arena_snapshot_t psram_snapshot;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (owner >= WIFI_TLS_ALLOC_OWNER_COUNT || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    slot = &s_allocator.owners[owner];
    if (slot->active == 0u) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (ninlil_wifi_tls_arena_snapshot(
            &slot->internal_arena, &internal_snapshot)
            != NINLIL_WIFI_TLS_ARENA_OK
        || ninlil_wifi_tls_arena_snapshot(
               &slot->psram_arena, &psram_snapshot)
            != NINLIL_WIFI_TLS_ARENA_OK) {
        return NINLIL_WIFI_CORRUPT;
    }
    out->internal_current_bytes = (uint32_t)internal_snapshot.current_bytes;
    out->internal_peak_bytes = (uint32_t)internal_snapshot.peak_bytes;
    out->psram_current_bytes = (uint32_t)psram_snapshot.current_bytes;
    out->psram_peak_bytes = (uint32_t)psram_snapshot.peak_bytes;
    out->current_bytes = out->internal_current_bytes
        + out->psram_current_bytes;
    out->peak_bytes = out->internal_peak_bytes + out->psram_peak_bytes;
    out->internal_reserved_bytes =
        NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET;
    out->psram_reserved_bytes = NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET;
    out->outstanding_allocations =
        internal_snapshot.outstanding_allocations
        + psram_snapshot.outstanding_allocations;
    out->oom_count = internal_snapshot.oom_count + psram_snapshot.oom_count;
    out->corruption_count =
        internal_snapshot.corruption_count + psram_snapshot.corruption_count;
    out->admission_reject_reason = slot->admission_reject_reason;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_snapshot(
    uint32_t component_id,
    ninlil_wifi_esp_tls_allocator_snapshot_t *out)
{
    ninlil_wifi_tls_arena_snapshot_t snapshot;
    const wifi_tls_registered_owner_t *registered = &s_allocator.other_r7;
    if (out != NULL) {
        (void)memset(out, 0, sizeof(*out));
    }
    if (out == NULL
        || component_id != NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (registered->active == 0u
        || registered->component_id != component_id) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (ninlil_wifi_tls_arena_snapshot(&registered->arena, &snapshot)
        != NINLIL_WIFI_TLS_ARENA_OK) {
        return NINLIL_WIFI_CORRUPT;
    }
    out->current_bytes = (uint32_t)snapshot.current_bytes;
    out->peak_bytes = (uint32_t)snapshot.peak_bytes;
    out->internal_current_bytes = out->current_bytes;
    out->internal_peak_bytes = out->peak_bytes;
    out->internal_reserved_bytes = registered->reservation_bytes;
    out->outstanding_allocations = snapshot.outstanding_allocations;
    out->oom_count = snapshot.oom_count;
    out->corruption_count = snapshot.corruption_count;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_aggregate_snapshot(
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t *out)
{
    uint32_t current;
    uint32_t outstanding;
    if (out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    if (!aggregate_current(&current, &outstanding)) {
        return NINLIL_WIFI_CORRUPT;
    }
    out->current_bytes = current;
    out->peak_bytes = s_allocator.aggregate_peak_bytes;
    out->crypto_global_reserved_bytes = s_allocator.bootstrapped != 0u
        ? NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET
        : 0u;
    out->tls_session_reserved_bytes =
        active_session_count()
        * NINLIL_WIFI_ESP_TLS_SESSION_ALLOCATION_BUDGET;
    out->other_registered_reserved_bytes =
        s_allocator.other_r7.active != 0u
        ? s_allocator.other_r7.reservation_bytes
        : 0u;
    out->reserved_bytes = out->crypto_global_reserved_bytes
        + out->tls_session_reserved_bytes
        + out->other_registered_reserved_bytes;
    out->outstanding_allocations = outstanding;
    out->active_tls_sessions = active_session_count();
    out->active_other_registered =
        s_allocator.other_r7.active != 0u ? 1u : 0u;
    out->current_owner = s_allocator.current_owner;
    out->trace_count = s_allocator.trace_count;
    out->trace_dropped = s_allocator.trace_dropped;
    out->bootstrapped = s_allocator.bootstrapped;
    out->owner_active = s_allocator.owner_active;
    out->fatal = s_allocator.fatal;
    return s_allocator.fatal != 0u ? NINLIL_WIFI_CORRUPT : NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_trace_at(
    uint32_t index,
    ninlil_wifi_esp_tls_allocator_trace_record_t *out)
{
    if (out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    if (index >= s_allocator.trace_count) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *out = s_allocator.trace[index];
    return NINLIL_WIFI_OK;
}

#if defined(NINLIL_WIFI_ESP_TLS_ALLOCATOR_TEST_BUILD)
void ninlil_wifi_esp_tls_allocator_test_set_fail_after(
    uint32_t owner,
    size_t successful_attempts)
{
    if (owner < WIFI_TLS_ALLOC_OWNER_COUNT
        && s_allocator.owners[owner].active != 0u) {
        ninlil_wifi_tls_arena_set_fail_after(
            &s_allocator.owners[owner].internal_arena,
            successful_attempts);
    } else if (owner == WIFI_TLS_OTHER_R7_OWNER
        && s_allocator.other_r7.active != 0u) {
        ninlil_wifi_tls_arena_set_fail_after(
            &s_allocator.other_r7.arena, successful_attempts);
    }
}

void *ninlil_wifi_esp_tls_allocator_test_calloc(
    size_t count,
    size_t size)
{
    return wifi_tls_profile_calloc(count, size);
}

void ninlil_wifi_esp_tls_allocator_test_free(void *pointer)
{
    wifi_tls_profile_free(pointer);
}

void ninlil_wifi_esp_tls_allocator_test_force_callback_recursion(void)
{
    s_allocator.callback_active = 1u;
    (void)wifi_tls_profile_calloc(1u, 1u);
    s_allocator.callback_active = 0u;
}

void ninlil_wifi_esp_tls_allocator_test_reset(void)
{
    uint32_t index;
    for (index = 0u; index < WIFI_TLS_ALLOC_OWNER_COUNT; ++index) {
        release_raw_region(
            s_allocator.owners[index].psram_region,
            NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET);
        release_raw_region(
            s_allocator.owners[index].internal_region,
            NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET);
    }
    release_raw_region(
        s_allocator.other_r7.region,
        s_allocator.other_r7.reservation_bytes);
    release_raw_region(
        s_allocator.global_region,
        NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET);
    (void)memset(&s_allocator, 0, sizeof(s_allocator));
}
#endif

#else

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_bootstrap(void)
{
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_session_register(
    uint32_t *out_owner)
{
    if (out_owner == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *out_owner = 0u;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_register(
    uint32_t component_id,
    uint32_t reservation_bytes,
    uint32_t *out_owner)
{
    if (out_owner == NULL
        || component_id != NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1
        || reservation_bytes
            != NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    *out_owner = NINLIL_WIFI_ESP_TLS_MAX_SESSIONS + 1u;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_owner_enter(uint32_t owner)
{
    return owner == 0u || owner == NINLIL_WIFI_ESP_TLS_MAX_SESSIONS + 1u
        ? NINLIL_WIFI_OK
        : NINLIL_WIFI_INVALID_ARGUMENT;
}

void ninlil_wifi_esp_tls_allocator_owner_leave(uint32_t owner)
{
    (void)owner;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_owner_leave_checked(
    uint32_t owner)
{
    return owner == 0u || owner == NINLIL_WIFI_ESP_TLS_MAX_SESSIONS + 1u
        ? NINLIL_WIFI_OK
        : NINLIL_WIFI_INVALID_ARGUMENT;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_io_begin(uint32_t owner)
{
    return owner == 0u ? NINLIL_WIFI_OK : NINLIL_WIFI_INVALID_ARGUMENT;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_io_finish(
    uint32_t owner,
    const void *in_buffer,
    size_t in_buffer_bytes,
    const void *out_buffer,
    size_t out_buffer_bytes)
{
    (void)in_buffer;
    (void)in_buffer_bytes;
    (void)out_buffer;
    (void)out_buffer_bytes;
    return owner == 0u ? NINLIL_WIFI_OK : NINLIL_WIFI_INVALID_ARGUMENT;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_session_release(
    uint32_t owner)
{
    return owner == 0u ? NINLIL_WIFI_OK : NINLIL_WIFI_INVALID_ARGUMENT;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_release(
    uint32_t owner)
{
    return owner == NINLIL_WIFI_ESP_TLS_MAX_SESSIONS + 1u
        ? NINLIL_WIFI_OK
        : NINLIL_WIFI_INVALID_ARGUMENT;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_snapshot(
    uint32_t owner,
    ninlil_wifi_esp_tls_allocator_snapshot_t *out)
{
    if (owner != 0u || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    out->internal_reserved_bytes =
        NINLIL_WIFI_ESP_TLS_SESSION_INTERNAL_BUDGET;
    out->psram_reserved_bytes = NINLIL_WIFI_ESP_TLS_SESSION_PSRAM_BUDGET;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_other_snapshot(
    uint32_t component_id,
    ninlil_wifi_esp_tls_allocator_snapshot_t *out)
{
    if (component_id != NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1
        || out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    out->internal_reserved_bytes =
        NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_aggregate_snapshot(
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t *out)
{
    if (out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    out->crypto_global_reserved_bytes =
        NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET;
    out->other_registered_reserved_bytes =
        NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET;
    out->reserved_bytes = out->crypto_global_reserved_bytes
        + out->other_registered_reserved_bytes;
    out->bootstrapped = 1u;
    out->active_other_registered = 1u;
    out->current_owner = NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_esp_tls_allocator_trace_at(
    uint32_t index,
    ninlil_wifi_esp_tls_allocator_trace_record_t *out)
{
    (void)index;
    if (out == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(out, 0, sizeof(*out));
    return NINLIL_WIFI_INVALID_ARGUMENT;
}

#endif /* ESP_PLATFORM */
