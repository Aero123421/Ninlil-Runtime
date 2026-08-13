/* SPDX-License-Identifier: Apache-2.0 */
#ifndef NINLIL_TEST_FAKE_MBEDTLS_PLATFORM_UTIL_H
#define NINLIL_TEST_FAKE_MBEDTLS_PLATFORM_UTIL_H

#include <stddef.h>

void mbedtls_platform_zeroize(void *pointer, size_t bytes);

#endif
