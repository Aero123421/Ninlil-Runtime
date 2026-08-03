/*
 * Private route-relay / multi-parent utilities (ADR-0019 / ADR-0020).
 * Default-OFF, not installed, not public ABI.
 * Symbol prefix: ninlil_rrmp_
 */
#ifndef NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_UTIL_H
#define NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

void ninlil_rrmp_put_u16_be(uint8_t *out, uint16_t value);
void ninlil_rrmp_put_u32_be(uint8_t *out, uint32_t value);
void ninlil_rrmp_put_u64_be(uint8_t *out, uint64_t value);
uint16_t ninlil_rrmp_get_u16_be(const uint8_t *in);
uint32_t ninlil_rrmp_get_u32_be(const uint8_t *in);
uint64_t ninlil_rrmp_get_u64_be(const uint8_t *in);
void ninlil_rrmp_memzero(void *dst, size_t length);
int ninlil_rrmp_memeq(const void *a, const void *b, size_t length);

/* Castagnoli CRC32C (same poly as control_frame / domain store). */
uint32_t ninlil_rrmp_crc32c(const uint8_t *bytes, size_t length);

/*
 * CRC32C of a buffer with a BE u32 field at field_off treated as zero
 * (page/header CRC layout). No full-page stack copy — ESP frame budget safe.
 */
uint32_t ninlil_rrmp_crc32c_zeroed_u32_be_field(
    const uint8_t *bytes, size_t length, size_t field_off);

/*
 * SHA-256 from real providers only: OpenSSL (host) or mbedTLS (ESP).
 * No portable/software fallback — missing provider is a compile-time error.
 * Provider is self-tested against NIST empty/"abc" KATs; fail-closed if mismatch.
 */
void ninlil_rrmp_sha256(const uint8_t *bytes, size_t length, uint8_t out[32]);
int ninlil_rrmp_sha256_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_RUNTIME_ROUTE_RELAY_V1_RRMP_UTIL_H */
