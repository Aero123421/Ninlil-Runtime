#include "rrmp_util.h"

/*
 * SHA-256: fail-closed provider selection.
 *  1) OpenSSL when NINLIL_RRMP_HAVE_OPENSSL=1 (host CI / production)
 *  2) mbedTLS when ESP_PLATFORM or NINLIL_RRMP_HAVE_MBEDTLS=1
 * No portable/software SHA fallback — silent weak digests are forbidden.
 */

#if defined(NINLIL_RRMP_HAVE_OPENSSL) && (NINLIL_RRMP_HAVE_OPENSSL)
#include <openssl/sha.h>
#define NINLIL_RRMP_SHA_OPENSSL 1
#elif defined(ESP_PLATFORM) || \
    (defined(NINLIL_RRMP_HAVE_MBEDTLS) && (NINLIL_RRMP_HAVE_MBEDTLS))
#include "mbedtls/sha256.h"
#define NINLIL_RRMP_SHA_MBEDTLS 1
#else
#error "ninlil_rrmp_sha256 requires OpenSSL (host) or mbedTLS (ESP); no portable fallback"
#endif

void ninlil_rrmp_put_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)((value >> 8) & 0xffu);
    out[1] = (uint8_t)(value & 0xffu);
}

void ninlil_rrmp_put_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)((value >> 24) & 0xffu);
    out[1] = (uint8_t)((value >> 16) & 0xffu);
    out[2] = (uint8_t)((value >> 8) & 0xffu);
    out[3] = (uint8_t)(value & 0xffu);
}

void ninlil_rrmp_put_u64_be(uint8_t *out, uint64_t value)
{
    out[0] = (uint8_t)((value >> 56) & 0xffu);
    out[1] = (uint8_t)((value >> 48) & 0xffu);
    out[2] = (uint8_t)((value >> 40) & 0xffu);
    out[3] = (uint8_t)((value >> 32) & 0xffu);
    out[4] = (uint8_t)((value >> 24) & 0xffu);
    out[5] = (uint8_t)((value >> 16) & 0xffu);
    out[6] = (uint8_t)((value >> 8) & 0xffu);
    out[7] = (uint8_t)(value & 0xffu);
}

uint16_t ninlil_rrmp_get_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

uint32_t ninlil_rrmp_get_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

uint64_t ninlil_rrmp_get_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48) |
           ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32) |
           ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16) |
           ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

void ninlil_rrmp_memzero(void *dst, size_t length)
{
    if (dst != NULL && length > 0u) {
        volatile uint8_t *p = (volatile uint8_t *)dst;
        size_t i;
        for (i = 0u; i < length; ++i) {
            p[i] = 0u;
        }
    }
}

int ninlil_rrmp_memeq(const void *a, const void *b, size_t length)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;
    uint8_t diff = 0u;
    size_t i;
    if (a == NULL || b == NULL) {
        return a == b ? 1 : 0;
    }
    for (i = 0u; i < length; ++i) {
        diff = (uint8_t)(diff | (x[i] ^ y[i]));
    }
    return diff == 0u ? 1 : 0;
}

static uint32_t crc32c_feed_byte(uint32_t crc, uint8_t byte)
{
    uint32_t bit;
    crc ^= byte;
    for (bit = 0u; bit < 8u; ++bit) {
        uint32_t mask = (uint32_t)(0u - (crc & 1u));
        crc = (crc >> 1u) ^ (0x82f63b78u & mask);
    }
    return crc;
}

uint32_t ninlil_rrmp_crc32c(const uint8_t *bytes, size_t length)
{
    uint32_t crc = 0xffffffffu;
    size_t index;
    if (bytes == NULL && length != 0u) {
        return 0u;
    }
    for (index = 0u; index < length; ++index) {
        crc = crc32c_feed_byte(crc, bytes[index]);
    }
    return ~crc;
}

uint32_t ninlil_rrmp_crc32c_zeroed_u32_be_field(
    const uint8_t *bytes, size_t length, size_t field_off)
{
    uint32_t crc = 0xffffffffu;
    size_t index;
    if (bytes == NULL || length < 4u || field_off + 4u > length) {
        return 0u;
    }
    for (index = 0u; index < field_off; ++index) {
        crc = crc32c_feed_byte(crc, bytes[index]);
    }
    /* Field is treated as four zero bytes (BE u32 zeroed). */
    crc = crc32c_feed_byte(crc, 0u);
    crc = crc32c_feed_byte(crc, 0u);
    crc = crc32c_feed_byte(crc, 0u);
    crc = crc32c_feed_byte(crc, 0u);
    for (index = field_off + 4u; index < length; ++index) {
        crc = crc32c_feed_byte(crc, bytes[index]);
    }
    return ~crc;
}

/* NIST SHA-256 KATs (FIPS 180-4): empty string and "abc". */
static const uint8_t k_sha_empty[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8,
    0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
static const uint8_t k_sha_abc[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
    0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

static void sha256_raw(const uint8_t *bytes, size_t length, uint8_t out[32])
{
#if defined(NINLIL_RRMP_SHA_OPENSSL)
    SHA256(bytes == NULL ? (const uint8_t *)"" : bytes, length, out);
#elif defined(NINLIL_RRMP_SHA_MBEDTLS)
    const uint8_t *in = (bytes == NULL) ? (const uint8_t *)"" : bytes;
    (void)mbedtls_sha256(in, length, out, 0);
#endif
}

void ninlil_rrmp_sha256(const uint8_t *bytes, size_t length, uint8_t out[32])
{
    static int kat_ok = -1;
    uint8_t got[32];
    if (kat_ok < 0) {
        sha256_raw((const uint8_t *)"", 0u, got);
        if (!ninlil_rrmp_memeq(got, k_sha_empty, 32u)) {
            kat_ok = 0;
        } else {
            sha256_raw((const uint8_t *)"abc", 3u, got);
            kat_ok = ninlil_rrmp_memeq(got, k_sha_abc, 32u) ? 1 : 0;
        }
    }
    if (kat_ok != 1) {
        /* Fail-closed: refuse digests if provider fails KAT. */
        ninlil_rrmp_memzero(out, 32u);
        return;
    }
    sha256_raw(bytes, length, out);
}

int ninlil_rrmp_sha256_selftest(void)
{
    uint8_t got[32];
    sha256_raw((const uint8_t *)"", 0u, got);
    if (!ninlil_rrmp_memeq(got, k_sha_empty, 32u)) {
        return 0;
    }
    sha256_raw((const uint8_t *)"abc", 3u, got);
    return ninlil_rrmp_memeq(got, k_sha_abc, 32u) ? 1 : 0;
}
