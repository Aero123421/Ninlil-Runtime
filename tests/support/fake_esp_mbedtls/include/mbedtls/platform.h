/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TEST_FAKE_MBEDTLS_PLATFORM_H
#define NINLIL_TEST_FAKE_MBEDTLS_PLATFORM_H

#include <stddef.h>

int mbedtls_platform_set_calloc_free(
    void *(*calloc_func)(size_t, size_t),
    void (*free_func)(void *));

#endif
