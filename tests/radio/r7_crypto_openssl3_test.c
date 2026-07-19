/* OpenSSL 3 adapter KAT and portable-boundary integration tests. */

#include "../../src/radio/r7_crypto_openssl3.h"

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include <stdio.h>
#include <string.h>

#if !defined(OPENSSL_VERSION_MAJOR) || OPENSSL_VERSION_MAJOR != 3
#error "This test requires OpenSSL major version exactly 3"
#endif

static int g_checks;
static int g_failures;

static void expect_int(const char *name, int got, int want)
{
    g_checks++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: got=%d want=%d\n", name, got, want);
        g_failures++;
    }
}

static void expect_size(const char *name, size_t got, size_t want)
{
    g_checks++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: got=%zu want=%zu\n", name, got, want);
        g_failures++;
    }
}

static void expect_mem(const char *name, const void *got, const void *want, size_t len)
{
    g_checks++;
    if (len > 0u && memcmp(got, want, len) != 0) {
        fprintf(stderr, "FAIL %s: bytes differ\n", name);
        g_failures++;
    }
}

static void expect_byte(const char *name, uint8_t got, uint8_t want)
{
    g_checks++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: got=%02x want=%02x\n", name, got, want);
        g_failures++;
    }
}

static void fill_sequence(uint8_t *out, size_t len, uint8_t first)
{
    size_t i;
    for (i = 0u; i < len; i++) {
        out[i] = (uint8_t)(first + (uint8_t)i);
    }
}

static void test_provider_shape(ninlil_r7_crypto_provider *provider)
{
    ninlil_r7_crypto_provider before;
    ninlil_r7_crypto_provider second;

    memset(provider, 0xA5, sizeof(*provider));
    expect_int(
        "provider init",
        ninlil_r7_crypto_openssl3_provider_init(provider),
        NINLIL_R7_CRYPTO_OK);
    expect_int(
        "provider validate",
        ninlil_r7_crypto_provider_validate(provider),
        NINLIL_R7_CRYPTO_OK);
    expect_int(
        "provider ABI", (int)provider->abi_version, (int)NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION);
    expect_size("provider size", (size_t)provider->struct_size, sizeof(*provider));
    expect_size("provider reserved", (size_t)provider->reserved_zero, 0u);
    expect_int("provider ctx NULL", provider->ctx == NULL, 1);
    expect_int("runtime OpenSSL major exact 3", OPENSSL_version_major() == 3u, 1);

    memset(&second, 0x5A, sizeof(second));
    expect_int(
        "provider second init",
        ninlil_r7_crypto_openssl3_provider_init(&second),
        NINLIL_R7_CRYPTO_OK);
    expect_mem(
        "provider deterministic object bytes",
        provider,
        &second,
        sizeof(*provider));

    before = *provider;
    expect_int(
        "provider init NULL",
        ninlil_r7_crypto_openssl3_provider_init(NULL),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_mem("provider stable", provider, &before, sizeof(*provider));
}

/* FIPS 180-4 / widely published SHA-256 empty and "abc" KATs. */
static void test_sha(ninlil_r7_crypto_provider *provider)
{
    static const uint8_t sha_empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    };
    static const uint8_t sha_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    static const uint8_t abc[3] = {0x61, 0x62, 0x63};
    uint8_t digest[32];

    memset(digest, 0, sizeof(digest));
    expect_int(
        "SHA empty raw",
        provider->sha256(provider->ctx, NULL, 0u, digest),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_mem("SHA empty KAT", digest, sha_empty, sizeof(digest));

    expect_int(
        "SHA abc raw",
        provider->sha256(provider->ctx, abc, sizeof(abc), digest),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_mem("SHA abc KAT", digest, sha_abc, sizeof(digest));

    memset(digest, 0, sizeof(digest));
    expect_int(
        "SHA abc portable",
        ninlil_r7_crypto_sha256(provider, abc, sizeof(abc), digest),
        NINLIL_R7_CRYPTO_OK);
    expect_mem("SHA abc portable KAT", digest, sha_abc, sizeof(digest));
}

/* RFC 5869 Appendix A test cases 1 and 2, including long direct OKM. */
static void test_hkdf_rfc5869(ninlil_r7_crypto_provider *provider)
{
    static const uint8_t a1_prk_expected[32] = {
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf,
        0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
        0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31,
        0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5
    };
    static const uint8_t a1_okm_expected[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };
    static const uint8_t a2_prk_expected[32] = {
        0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a,
        0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4, 0x5c,
        0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01,
        0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44
    };
    static const uint8_t a2_okm_expected[82] = {
        0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
        0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
        0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
        0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
        0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
        0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
        0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
        0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
        0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
        0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
        0x1d, 0x87
    };
    uint8_t a1_ikm[22];
    uint8_t a1_salt[13];
    uint8_t a1_info[10];
    uint8_t a2_ikm[80];
    uint8_t a2_salt[80];
    uint8_t a2_info[80];
    uint8_t prk[32];
    uint8_t okm[82];

    memset(a1_ikm, 0x0b, sizeof(a1_ikm));
    fill_sequence(a1_salt, sizeof(a1_salt), 0x00);
    fill_sequence(a1_info, sizeof(a1_info), 0xf0);
    expect_int(
        "RFC5869 A1 extract",
        provider->hkdf_extract_sha256(
            provider->ctx,
            a1_salt,
            sizeof(a1_salt),
            a1_ikm,
            sizeof(a1_ikm),
            prk),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_mem("RFC5869 A1 PRK", prk, a1_prk_expected, sizeof(prk));
    expect_int(
        "RFC5869 A1 expand42",
        provider->hkdf_expand_sha256(
            provider->ctx, prk, a1_info, sizeof(a1_info), okm, 42u),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_mem("RFC5869 A1 OKM42", okm, a1_okm_expected, 42u);

    fill_sequence(a2_ikm, sizeof(a2_ikm), 0x00);
    fill_sequence(a2_salt, sizeof(a2_salt), 0x60);
    fill_sequence(a2_info, sizeof(a2_info), 0xb0);
    expect_int(
        "RFC5869 A2 extract",
        provider->hkdf_extract_sha256(
            provider->ctx,
            a2_salt,
            sizeof(a2_salt),
            a2_ikm,
            sizeof(a2_ikm),
            prk),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_mem("RFC5869 A2 PRK", prk, a2_prk_expected, sizeof(prk));
    expect_int(
        "RFC5869 A2 expand82",
        provider->hkdf_expand_sha256(
            provider->ctx, prk, a2_info, sizeof(a2_info), okm, sizeof(okm)),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_mem("RFC5869 A2 OKM82", okm, a2_okm_expected, sizeof(okm));
}

static void test_hkdf_portable(ninlil_r7_crypto_provider *provider)
{
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t info[8];
    uint8_t raw_prk[32];
    uint8_t wrapped_prk[32];
    uint8_t raw_okm[16];
    uint8_t wrapped_okm[16];

    fill_sequence(salt, sizeof(salt), 0x20);
    fill_sequence(ikm, sizeof(ikm), 0x80);
    fill_sequence(info, sizeof(info), 0xd0);
    expect_int(
        "HKDF portable extract raw reference",
        provider->hkdf_extract_sha256(
            provider->ctx, salt, sizeof(salt), ikm, sizeof(ikm), raw_prk),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_int(
        "HKDF portable extract",
        ninlil_r7_crypto_hkdf_extract_sha256(
            provider, salt, sizeof(salt), ikm, sizeof(ikm), wrapped_prk),
        NINLIL_R7_CRYPTO_OK);
    expect_mem("HKDF portable PRK publish", wrapped_prk, raw_prk, sizeof(raw_prk));
    expect_int(
        "HKDF portable expand raw reference",
        provider->hkdf_expand_sha256(
            provider->ctx, raw_prk, info, sizeof(info), raw_okm, sizeof(raw_okm)),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_int(
        "HKDF portable expand",
        ninlil_r7_crypto_hkdf_expand_sha256(
            provider, wrapped_prk, info, sizeof(info), wrapped_okm, sizeof(wrapped_okm)),
        NINLIL_R7_CRYPTO_OK);
    expect_mem("HKDF portable OKM publish", wrapped_okm, raw_okm, sizeof(raw_okm));

    expect_int(
        "HKDF portable empty-info raw reference",
        provider->hkdf_expand_sha256(
            provider->ctx, raw_prk, NULL, 0u, raw_okm, sizeof(raw_okm)),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_int(
        "HKDF portable empty-info",
        ninlil_r7_crypto_hkdf_expand_sha256(
            provider, wrapped_prk, NULL, 0u, wrapped_okm, sizeof(wrapped_okm)),
        NINLIL_R7_CRYPTO_OK);
    expect_mem(
        "HKDF portable empty-info publish", wrapped_okm, raw_okm, sizeof(raw_okm));
}

/* NIST SP 800-38D AES-128-GCM examples (96-bit IV, CT||TAG form). */
static void test_gcm_nist(ninlil_r7_crypto_provider *provider)
{
    static const uint8_t empty_tag[16] = {
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
    };
    static const uint8_t key2[16] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    static const uint8_t nonce2[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };
    static const uint8_t aad2[20] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    static const uint8_t pt2[60] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };
    static const uint8_t sealed2_expected[76] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
        0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
        0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
        0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
        0x3d, 0x58, 0xe0, 0x91, 0x5b, 0xc9, 0x4f, 0xbc,
        0x32, 0x21, 0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a,
        0xe7, 0x12, 0x1a, 0x47
    };
    uint8_t zero_key[16] = {0};
    uint8_t zero_nonce[12] = {0};
    uint8_t sealed[76];
    uint8_t opened[60];
    uint8_t bad_sealed[76];
    size_t produced;

    produced = SIZE_MAX;
    expect_int(
        "NIST GCM empty seal",
        provider->aes128_gcm_seal(
            provider->ctx,
            zero_key,
            zero_nonce,
            NULL,
            0u,
            NULL,
            0u,
            sealed,
            16u,
            &produced),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_size("NIST GCM empty seal length", produced, 16u);
    expect_mem("NIST GCM empty tag", sealed, empty_tag, sizeof(empty_tag));

    produced = SIZE_MAX;
    expect_int(
        "NIST GCM nontrivial seal",
        provider->aes128_gcm_seal(
            provider->ctx,
            key2,
            nonce2,
            aad2,
            sizeof(aad2),
            pt2,
            sizeof(pt2),
            sealed,
            sizeof(sealed),
            &produced),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_size("NIST GCM nontrivial seal length", produced, sizeof(sealed));
    expect_mem("NIST GCM nontrivial CT+TAG", sealed, sealed2_expected, sizeof(sealed));

    produced = SIZE_MAX;
    expect_int(
        "NIST GCM nontrivial open",
        provider->aes128_gcm_open(
            provider->ctx,
            key2,
            nonce2,
            aad2,
            sizeof(aad2),
            sealed2_expected,
            sizeof(sealed2_expected),
            opened,
            sizeof(opened),
            &produced),
        NINLIL_R7_CRYPTO_RAW_OK);
    expect_size("NIST GCM nontrivial open length", produced, sizeof(opened));
    expect_mem("NIST GCM nontrivial PT", opened, pt2, sizeof(opened));

    memcpy(bad_sealed, sealed2_expected, sizeof(bad_sealed));
    bad_sealed[sizeof(bad_sealed) - 1u] ^= 0x01u;
    memset(opened, 0xA5, sizeof(opened));
    produced = (size_t)0x5a5au;
    expect_int(
        "NIST GCM bad tag",
        provider->aes128_gcm_open(
            provider->ctx,
            key2,
            nonce2,
            aad2,
            sizeof(aad2),
            bad_sealed,
            sizeof(bad_sealed),
            opened,
            sizeof(opened),
            &produced),
        NINLIL_R7_CRYPTO_RAW_AUTH_FAILED);
    expect_size("bad tag produced unchanged", produced, (size_t)0x5a5au);
    expect_byte("bad tag output cleared first", opened[0], 0u);
    expect_byte("bad tag output cleared last", opened[sizeof(opened) - 1u], 0u);

    memset(sealed, 0xA5, sizeof(sealed));
    produced = (size_t)0x1357u;
    expect_int(
        "GCM seal wrong exact capacity",
        provider->aes128_gcm_seal(
            provider->ctx,
            key2,
            nonce2,
            aad2,
            sizeof(aad2),
            pt2,
            sizeof(pt2),
            sealed,
            sizeof(sealed) - 1u,
            &produced),
        NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED);
    expect_size("seal wrong capacity produced unchanged", produced, (size_t)0x1357u);
    expect_byte("seal wrong capacity output unchanged", sealed[0], 0xA5u);

    memset(opened, 0xA5, sizeof(opened));
    produced = (size_t)0x2468u;
    expect_int(
        "GCM open wrong exact capacity",
        provider->aes128_gcm_open(
            provider->ctx,
            key2,
            nonce2,
            aad2,
            sizeof(aad2),
            sealed2_expected,
            sizeof(sealed2_expected),
            opened,
            sizeof(opened) - 1u,
            &produced),
        NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED);
    expect_size("open wrong capacity produced unchanged", produced, (size_t)0x2468u);
    expect_byte("open wrong capacity output unchanged", opened[0], 0xA5u);
}

static void test_gcm_portable(ninlil_r7_crypto_provider *provider)
{
    static const uint8_t empty_tag[16] = {
        0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
        0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a
    };
    static const uint8_t zero_block_sealed[32] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };
    uint8_t key[16] = {0};
    uint8_t nonce[12] = {0};
    uint8_t sealed[16];
    uint8_t sealed_block[32];
    uint8_t bad_sealed[16];
    uint8_t bad_block[32];
    uint8_t zero_block[16] = {0};
    uint8_t opened_block[16];
    uint8_t empty_out = 0xA5u;
    size_t produced;

    produced = SIZE_MAX;
    expect_int(
        "portable GCM empty seal",
        ninlil_r7_crypto_aes128_gcm_seal(
            provider, key, nonce, NULL, 0u, NULL, 0u, sealed, sizeof(sealed), &produced),
        NINLIL_R7_CRYPTO_OK);
    expect_size("portable GCM empty seal length", produced, sizeof(sealed));
    expect_mem("portable GCM empty tag", sealed, empty_tag, sizeof(sealed));

    produced = SIZE_MAX;
    expect_int(
        "portable GCM empty open",
        ninlil_r7_crypto_aes128_gcm_open(
            provider,
            key,
            nonce,
            NULL,
            0u,
            sealed,
            sizeof(sealed),
            &empty_out,
            0u,
            &produced),
        NINLIL_R7_CRYPTO_OK);
    expect_size("portable GCM empty open length", produced, 0u);
    expect_byte("portable GCM zero-cap output stable", empty_out, 0xA5u);

    memcpy(bad_sealed, sealed, sizeof(bad_sealed));
    bad_sealed[15] ^= 0x80u;
    produced = (size_t)0x7777u;
    expect_int(
        "portable GCM bad tag maps auth",
        ninlil_r7_crypto_aes128_gcm_open(
            provider,
            key,
            nonce,
            NULL,
            0u,
            bad_sealed,
            sizeof(bad_sealed),
            &empty_out,
            0u,
            &produced),
        NINLIL_R7_CRYPTO_AUTH_FAILED);
    expect_size("portable bad tag produced unchanged", produced, (size_t)0x7777u);
    expect_byte("portable bad tag output stable", empty_out, 0xA5u);

    produced = SIZE_MAX;
    expect_int(
        "portable GCM zero-block seal",
        ninlil_r7_crypto_aes128_gcm_seal(
            provider,
            key,
            nonce,
            NULL,
            0u,
            zero_block,
            sizeof(zero_block),
            sealed_block,
            sizeof(sealed_block),
            &produced),
        NINLIL_R7_CRYPTO_OK);
    expect_size("portable GCM zero-block seal length", produced, sizeof(sealed_block));
    expect_mem(
        "portable GCM zero-block CT+TAG",
        sealed_block,
        zero_block_sealed,
        sizeof(sealed_block));

    memset(opened_block, 0xA5, sizeof(opened_block));
    produced = SIZE_MAX;
    expect_int(
        "portable GCM zero-block open",
        ninlil_r7_crypto_aes128_gcm_open(
            provider,
            key,
            nonce,
            NULL,
            0u,
            zero_block_sealed,
            sizeof(zero_block_sealed),
            opened_block,
            sizeof(opened_block),
            &produced),
        NINLIL_R7_CRYPTO_OK);
    expect_size("portable GCM zero-block open length", produced, sizeof(opened_block));
    expect_mem("portable GCM zero-block PT", opened_block, zero_block, sizeof(opened_block));

    memcpy(bad_block, zero_block_sealed, sizeof(bad_block));
    bad_block[31] ^= 0x01u;
    memset(opened_block, 0xA5, sizeof(opened_block));
    produced = (size_t)0x9999u;
    expect_int(
        "portable GCM zero-block bad tag",
        ninlil_r7_crypto_aes128_gcm_open(
            provider,
            key,
            nonce,
            NULL,
            0u,
            bad_block,
            sizeof(bad_block),
            opened_block,
            sizeof(opened_block),
            &produced),
        NINLIL_R7_CRYPTO_AUTH_FAILED);
    expect_size("portable zero-block bad tag length stable", produced, (size_t)0x9999u);
    expect_byte("portable zero-block bad tag output first stable", opened_block[0], 0xA5u);
    expect_byte(
        "portable zero-block bad tag output last stable",
        opened_block[sizeof(opened_block) - 1u],
        0xA5u);
}

int main(void)
{
    ninlil_r7_crypto_provider provider;

    test_provider_shape(&provider);
    test_sha(&provider);
    test_hkdf_rfc5869(&provider);
    test_hkdf_portable(&provider);
    test_gcm_nist(&provider);
    test_gcm_portable(&provider);

    if (g_failures != 0) {
        fprintf(stderr, "R7 OpenSSL3 adapter: %d/%d checks failed\n", g_failures, g_checks);
        return 1;
    }
    printf("R7 OpenSSL3 adapter: PASS (%d checks, OpenSSL %s)\n", g_checks, OpenSSL_version(OPENSSL_VERSION));
    return 0;
}
