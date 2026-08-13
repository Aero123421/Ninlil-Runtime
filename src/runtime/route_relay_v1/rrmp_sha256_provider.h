/* SPDX-License-Identifier: Apache-2.0 */
/* Private RRMP SHA-256 primitive adapter contract. Not installed. */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_SHA256_PROVIDER_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_SHA256_PROVIDER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns 1 after publishing exactly 32 bytes, or 0 after zeroing output. */
int ninlil_rrmp_sha256_provider(
    const uint8_t *bytes, size_t length, uint8_t out[32]);

#ifdef __cplusplus
}
#endif

#endif
