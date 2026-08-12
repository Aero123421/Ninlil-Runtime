/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TEST_FAKE_ESP_MBEDTLS_H
#define NINLIL_TEST_FAKE_ESP_MBEDTLS_H

#include <stdint.h>

typedef struct ninlil_test_fake_esp_mbedtls_snapshot {
    uint32_t allocator_install_calls;
    uint32_t crypto_calls;
    uint32_t crypto_before_allocator;
    uint32_t raw_heap_allocations;
    uint32_t raw_heap_outstanding;
} ninlil_test_fake_esp_mbedtls_snapshot_t;

typedef void (*ninlil_test_fake_esp_mbedtls_reentry_fn)(void *user);

void ninlil_test_fake_esp_mbedtls_reset(void);
ninlil_test_fake_esp_mbedtls_snapshot_t
ninlil_test_fake_esp_mbedtls_snapshot(void);
void ninlil_test_fake_esp_mbedtls_set_reentry(
    ninlil_test_fake_esp_mbedtls_reentry_fn function,
    void *user);

#endif
