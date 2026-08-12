/* SPDX-License-Identifier: Apache-2.0 */
#include "fake_esp_mbedtls.h"
#include "r7_crypto_mbedtls.h"
#include "r7_crypto_provider.h"
#include "wifi_esp_tls_allocator.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(expr)                                                        \
    do {                                                                     \
        if (!(expr)) {                                                       \
            (void)fprintf(                                                   \
                stderr, "require failed: %s:%d: %s\n",                      \
                __FILE__, __LINE__, #expr);                                  \
            return 1;                                                        \
        }                                                                    \
    } while (0)

static void reset_fixture(void)
{
    ninlil_r7_crypto_mbedtls_test_reset();
    ninlil_wifi_esp_tls_allocator_test_reset();
    ninlil_test_fake_esp_mbedtls_reset();
}

static uint32_t r7_owner_from_trace(void)
{
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t aggregate;
    ninlil_wifi_esp_tls_allocator_trace_record_t record;
    uint32_t index;
    if (ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate)
        != NINLIL_WIFI_OK) {
        return NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
    }
    for (index = 0u; index < aggregate.trace_count; ++index) {
        if (ninlil_wifi_esp_tls_allocator_trace_at(index, &record)
                == NINLIL_WIFI_OK
            && record.event == NINLIL_WIFI_ESP_TLS_TRACE_REGISTER
            && record.component_id
                == NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1) {
            return record.owner;
        }
    }
    return NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID;
}

static int init_provider(ninlil_r7_crypto_provider *provider)
{
    ninlil_test_fake_esp_mbedtls_snapshot_t fake;
    (void)memset(provider, 0xa5, sizeof(*provider));
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_init(provider)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(
        ninlil_r7_crypto_provider_validate(provider)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(provider->ctx != NULL);
    fake = ninlil_test_fake_esp_mbedtls_snapshot();
    REQUIRE(fake.allocator_install_calls == 1u);
    REQUIRE(fake.crypto_calls > 0u);
    REQUIRE(fake.crypto_before_allocator == 0u);
    REQUIRE(fake.raw_heap_outstanding == 2u);
    return 0;
}

static int test_normal_budget_trace_close(void)
{
    ninlil_r7_crypto_provider provider;
    ninlil_wifi_esp_tls_allocator_snapshot_t other;
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t aggregate;
    ninlil_test_fake_esp_mbedtls_snapshot_t fake;
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t prk[32];
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t plaintext[16];
    uint8_t sealed[32];
    uint8_t opened[16];
    size_t sealed_length = 0u;
    size_t opened_length = 0u;
    uint32_t session_a;
    uint32_t session_b;
    uint32_t owner;
    reset_fixture();
    (void)memset(salt, 0x11, sizeof(salt));
    (void)memset(ikm, 0x22, sizeof(ikm));
    (void)memset(key, 0x33, sizeof(key));
    (void)memset(nonce, 0x44, sizeof(nonce));
    (void)memset(plaintext, 0x55, sizeof(plaintext));
    REQUIRE(init_provider(&provider) == 0);
    owner = r7_owner_from_trace();
    REQUIRE(owner != NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID);

    REQUIRE(
        ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate)
        == NINLIL_WIFI_OK);
    REQUIRE(aggregate.bootstrapped == 1u);
    REQUIRE(aggregate.fatal == 0u);
    REQUIRE(aggregate.active_other_registered == 1u);
    REQUIRE(aggregate.active_tls_sessions == 0u);
    REQUIRE(
        aggregate.crypto_global_reserved_bytes
        == NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET);
    REQUIRE(
        aggregate.other_registered_reserved_bytes
        == NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET);
    REQUIRE(
        aggregate.reserved_bytes
        == NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET
            + NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET);

    REQUIRE(
        ninlil_r7_crypto_hkdf_extract_sha256(
            &provider,
            salt,
            sizeof(salt),
            ikm,
            sizeof(ikm),
            prk)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_other_snapshot(
            NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1, &other)
        == NINLIL_WIFI_OK);
    REQUIRE(other.current_bytes == 0u);
    REQUIRE(other.outstanding_allocations == 0u);
    REQUIRE(other.peak_bytes > 0u);
    REQUIRE(
        other.peak_bytes
        <= NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET);
    REQUIRE(
        other.internal_reserved_bytes
        == NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET);
    REQUIRE(other.oom_count == 0u);

    REQUIRE(
        ninlil_r7_crypto_aes128_gcm_seal(
            &provider,
            key,
            nonce,
            NULL,
            0u,
            plaintext,
            sizeof(plaintext),
            sealed,
            sizeof(sealed),
            &sealed_length)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(sealed_length == sizeof(sealed));
    REQUIRE(
        ninlil_r7_crypto_aes128_gcm_open(
            &provider,
            key,
            nonce,
            NULL,
            0u,
            sealed,
            sizeof(sealed),
            opened,
            sizeof(opened),
            &opened_length)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(opened_length == sizeof(opened));
    REQUIRE(memcmp(opened, plaintext, sizeof(opened)) == 0);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_other_snapshot(
            NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1, &other)
        == NINLIL_WIFI_OK);
    REQUIRE(other.current_bytes == 0u);
    REQUIRE(other.outstanding_allocations == 0u);
    REQUIRE(other.peak_bytes > 256u);
    REQUIRE(
        other.peak_bytes
        <= NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET);

    REQUIRE(
        ninlil_wifi_esp_tls_allocator_session_register(&session_a)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_session_register(&session_b)
        == NINLIL_WIFI_OK);
    REQUIRE(session_a != session_b);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate)
        == NINLIL_WIFI_OK);
    REQUIRE(aggregate.active_tls_sessions == 2u);
    REQUIRE(
        aggregate.reserved_bytes
        == NINLIL_WIFI_ESP_TLS_WIFI_R7_COMPOSITION_TOTAL_BUDGET);
    REQUIRE(
        aggregate.reserved_bytes
        == NINLIL_WIFI_ESP_TLS_TOTAL_ALLOCATION_BUDGET
            + NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_session_release(session_b)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_session_release(session_a)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_close(&provider)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate)
        == NINLIL_WIFI_OK);
    REQUIRE(aggregate.active_other_registered == 0u);
    REQUIRE(
        aggregate.reserved_bytes
        == NINLIL_WIFI_ESP_TLS_CRYPTO_GLOBAL_BUDGET);
    fake = ninlil_test_fake_esp_mbedtls_snapshot();
    REQUIRE(fake.raw_heap_outstanding == 1u);
    (void)owner;
    reset_fixture();
    return 0;
}

static int test_oom_is_local_and_retryable(void)
{
    ninlil_r7_crypto_provider provider;
    ninlil_wifi_esp_tls_allocator_snapshot_t other;
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t aggregate;
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t prk[32];
    uint32_t owner;
    reset_fixture();
    (void)memset(salt, 0x31, sizeof(salt));
    (void)memset(ikm, 0x42, sizeof(ikm));
    REQUIRE(init_provider(&provider) == 0);
    owner = r7_owner_from_trace();
    REQUIRE(owner != NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID);
    ninlil_wifi_esp_tls_allocator_test_set_fail_after(owner, 0u);
    REQUIRE(
        ninlil_r7_crypto_hkdf_extract_sha256(
            &provider,
            salt,
            sizeof(salt),
            ikm,
            sizeof(ikm),
            prk)
        == NINLIL_R7_CRYPTO_BACKEND_FAILED);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_other_snapshot(
            NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1, &other)
        == NINLIL_WIFI_OK);
    REQUIRE(other.current_bytes == 0u);
    REQUIRE(other.outstanding_allocations == 0u);
    REQUIRE(other.oom_count == 1u);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate)
        == NINLIL_WIFI_OK);
    REQUIRE(aggregate.fatal == 0u);
    REQUIRE(aggregate.owner_active == 0u);

    ninlil_wifi_esp_tls_allocator_test_set_fail_after(owner, SIZE_MAX);
    REQUIRE(
        ninlil_r7_crypto_hkdf_extract_sha256(
            &provider,
            salt,
            sizeof(salt),
            ikm,
            sizeof(ikm),
            prk)
        == NINLIL_R7_CRYPTO_OK);
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_close(&provider)
        == NINLIL_R7_CRYPTO_OK);
    reset_fixture();
    return 0;
}

static int require_fatal(void)
{
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t aggregate;
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate)
        == NINLIL_WIFI_CORRUPT);
    REQUIRE(aggregate.fatal == 1u);
    return 0;
}

typedef struct reentry_fixture {
    const ninlil_r7_crypto_provider *provider;
    ninlil_r7_crypto_status status;
} reentry_fixture_t;

static void invoke_recursive_sha256(void *user)
{
    reentry_fixture_t *fixture = (reentry_fixture_t *)user;
    uint8_t digest[32];
    fixture->status = ninlil_r7_crypto_sha256(
        fixture->provider,
        (const uint8_t *)"recursive",
        sizeof("recursive") - 1u,
        digest);
}

static int test_recursive_provider_callback_fence(void)
{
    ninlil_r7_crypto_provider provider;
    reentry_fixture_t reentry;
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t prk[32];
    reset_fixture();
    (void)memset(salt, 0x71, sizeof(salt));
    (void)memset(ikm, 0x82, sizeof(ikm));
    REQUIRE(init_provider(&provider) == 0);
    reentry.provider = &provider;
    reentry.status = NINLIL_R7_CRYPTO_OK;
    ninlil_test_fake_esp_mbedtls_set_reentry(
        invoke_recursive_sha256, &reentry);
    REQUIRE(
        ninlil_r7_crypto_hkdf_extract_sha256(
            &provider,
            salt,
            sizeof(salt),
            ikm,
            sizeof(ikm),
            prk)
        == NINLIL_R7_CRYPTO_BACKEND_FAILED);
    REQUIRE(reentry.status == NINLIL_R7_CRYPTO_BACKEND_FAILED);
    REQUIRE(require_fatal() == 0);
    reset_fixture();
    return 0;
}

static int test_cross_owner_and_foreign_free_fence(void)
{
    ninlil_r7_crypto_provider provider;
    uint32_t r7_owner;
    uint32_t session_owner;
    void *owned;
    uint8_t foreign = 0u;
    reset_fixture();
    REQUIRE(init_provider(&provider) == 0);
    r7_owner = r7_owner_from_trace();
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_session_register(&session_owner)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(r7_owner)
        == NINLIL_WIFI_OK);
    owned = ninlil_wifi_esp_tls_allocator_test_calloc(1u, 16u);
    REQUIRE(owned != NULL);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_leave_checked(r7_owner)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(session_owner)
        == NINLIL_WIFI_OK);
    ninlil_wifi_esp_tls_allocator_test_free(owned);
    REQUIRE(require_fatal() == 0);
    reset_fixture();

    REQUIRE(init_provider(&provider) == 0);
    r7_owner = r7_owner_from_trace();
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(r7_owner)
        == NINLIL_WIFI_OK);
    ninlil_wifi_esp_tls_allocator_test_free(&foreign);
    REQUIRE(require_fatal() == 0);
    reset_fixture();
    return 0;
}

static int test_double_free_entry_leave_and_recursion_fence(void)
{
    ninlil_r7_crypto_provider provider;
    uint32_t owner;
    void *value;
    reset_fixture();
    REQUIRE(init_provider(&provider) == 0);
    owner = r7_owner_from_trace();
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(owner)
        == NINLIL_WIFI_OK);
    value = ninlil_wifi_esp_tls_allocator_test_calloc(1u, 16u);
    REQUIRE(value != NULL);
    ninlil_wifi_esp_tls_allocator_test_free(value);
    ninlil_wifi_esp_tls_allocator_test_free(value);
    REQUIRE(require_fatal() == 0);
    reset_fixture();

    REQUIRE(init_provider(&provider) == 0);
    owner = r7_owner_from_trace();
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(owner)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(owner)
        == NINLIL_WIFI_CORRUPT);
    REQUIRE(require_fatal() == 0);
    reset_fixture();

    REQUIRE(init_provider(&provider) == 0);
    owner = r7_owner_from_trace();
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(owner)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_leave_checked(owner)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_leave_checked(owner)
        == NINLIL_WIFI_CORRUPT);
    REQUIRE(require_fatal() == 0);
    reset_fixture();

    REQUIRE(init_provider(&provider) == 0);
    owner = r7_owner_from_trace();
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(owner)
        == NINLIL_WIFI_OK);
    ninlil_wifi_esp_tls_allocator_test_force_callback_recursion();
    REQUIRE(require_fatal() == 0);
    reset_fixture();
    return 0;
}

static int test_close_outstanding_and_trace_bound(void)
{
    ninlil_r7_crypto_provider provider;
    ninlil_wifi_esp_tls_allocator_aggregate_snapshot_t aggregate;
    uint8_t digest[32];
    uint32_t owner;
    uint32_t index;
    void *value;
    reset_fixture();
    REQUIRE(init_provider(&provider) == 0);
    owner = r7_owner_from_trace();
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_enter(owner)
        == NINLIL_WIFI_OK);
    value = ninlil_wifi_esp_tls_allocator_test_calloc(1u, 16u);
    REQUIRE(value != NULL);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_owner_leave_checked(owner)
        == NINLIL_WIFI_OK);
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_close(&provider)
        == NINLIL_R7_CRYPTO_INTERNAL_CONTRACT);
    REQUIRE(require_fatal() == 0);
    reset_fixture();

    REQUIRE(init_provider(&provider) == 0);
    for (index = 0u; index < 40u; ++index) {
        REQUIRE(
            ninlil_r7_crypto_sha256(
                &provider, (const uint8_t *)&index, sizeof(index), digest)
            == NINLIL_R7_CRYPTO_OK);
    }
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_aggregate_snapshot(&aggregate)
        == NINLIL_WIFI_OK);
    REQUIRE(
        aggregate.trace_count
        == NINLIL_WIFI_ESP_TLS_ALLOC_TRACE_CAPACITY);
    REQUIRE(aggregate.trace_dropped > 0u);
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_close(&provider)
        == NINLIL_R7_CRYPTO_OK);
    reset_fixture();
    return 0;
}

static int test_unknown_component_and_bootstrap_contract(void)
{
    ninlil_r7_crypto_provider provider;
    ninlil_r7_crypto_provider duplicate;
    ninlil_r7_crypto_provider duplicate_before;
    uint32_t owner;
    reset_fixture();
    owner = 7u;
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_other_register(
            UINT32_C(0xdeadbeef),
            NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET,
            &owner)
        == NINLIL_WIFI_INVALID_ARGUMENT);
    REQUIRE(owner == NINLIL_WIFI_ESP_TLS_ALLOC_OWNER_INVALID);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_other_register(
            NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1,
            NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET,
            &owner)
        == NINLIL_WIFI_INVALID_STATE);
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_init(&provider)
        == NINLIL_R7_CRYPTO_OK);
    (void)memset(&duplicate, 0xa5, sizeof(duplicate));
    duplicate_before = duplicate;
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_init(&duplicate)
        == NINLIL_R7_CRYPTO_INTERNAL_CONTRACT);
    REQUIRE(
        memcmp(
            &duplicate, &duplicate_before, sizeof(duplicate))
        == 0);
    REQUIRE(
        ninlil_wifi_esp_tls_allocator_other_register(
            NINLIL_WIFI_ESP_TLS_OTHER_COMPONENT_R7_RAW_V1,
            NINLIL_WIFI_ESP_TLS_R7_OTHER_REGISTERED_BUDGET,
            &owner)
        == NINLIL_WIFI_INVALID_STATE);
    REQUIRE(
        ninlil_r7_crypto_mbedtls_provider_close(&provider)
        == NINLIL_R7_CRYPTO_OK);
    reset_fixture();
    return 0;
}

int main(void)
{
    if (test_normal_budget_trace_close() != 0
        || test_oom_is_local_and_retryable() != 0
        || test_recursive_provider_callback_fence() != 0
        || test_cross_owner_and_foreign_free_fence() != 0
        || test_double_free_entry_leave_and_recursion_fence() != 0
        || test_close_outstanding_and_trace_bound() != 0
        || test_unknown_component_and_bootstrap_contract() != 0) {
        reset_fixture();
        return 1;
    }
    reset_fixture();
    (void)puts(
        "wifi_v1_r7_other_registered_fault_test: PASS "
        "bootstrap owner oom cross double foreign recursive singleton "
        "close trace");
    return 0;
}
