/*
 * R7 portable crypto boundary tests (docs/31 T0B / independent audit P1).
 *
 * Fake / poison backends only — no real crypto library, no round-trip-as-oracle.
 * Standalone: clang|gcc -std=c11 -Wall -Wextra -Werror -Wvla -pedantic
 *             -DNINLIL_R7_CRYPTO_TEST_BUILD
 */

#define NINLIL_R7_CRYPTO_TEST_BUILD 1

#include "../../src/radio/r7_crypto_provider.h"

#include <stdio.h>
#include <string.h>

/* -------------------------------------------------------------------------- */
/* Test harness                                                               */
/* -------------------------------------------------------------------------- */

static int g_failures;
static int g_tests;

static void expect_status(const char *name, int got, int want)
{
    g_tests++;
    if (got != want) {
        fprintf(stderr, "FAIL %s: status got=%d want=%d\n", name, got, want);
        g_failures++;
    }
}

static void expect_true(const char *name, int cond)
{
    g_tests++;
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        g_failures++;
    }
}

static void expect_mem_eq(const char *name, const void *a, const void *b, size_t n)
{
    g_tests++;
    if (n > 0u && memcmp(a, b, n) != 0) {
        fprintf(stderr, "FAIL %s: bytes differ\n", name);
        g_failures++;
    }
}

static void expect_mem_eq_u8(const char *name, const uint8_t *got, const uint8_t *want, size_t n)
{
    expect_mem_eq(name, got, want, n);
}

/* -------------------------------------------------------------------------- */
/* Fake backend context                                                       */
/* -------------------------------------------------------------------------- */

typedef struct fake_ctx {
    int sha256_calls;
    int extract_calls;
    int expand_calls;
    int seal_calls;
    int open_calls;

    ninlil_r7_crypto_raw_status sha256_result;
    ninlil_r7_crypto_raw_status extract_result;
    ninlil_r7_crypto_raw_status expand_result;
    ninlil_r7_crypto_raw_status seal_result;
    ninlil_r7_crypto_raw_status open_result;

    uint8_t digest32[32];
    uint8_t prk32[32];
    uint8_t okm16[16];
    uint8_t sealed_prefix;
    uint8_t tag_byte;

    int seal_partial_write;
    int open_partial_write;
    int seal_unknown_result;
    int open_unknown_result;

    /* produced_len poison modes for AEAD (after writing candidate on OK path) */
    int seal_produced_mode; /* 0=exact, 1=short, 2=long, 3=unchanged, 4=zero */
    int open_produced_mode;

    /* poison: rewrite key/nonce/aad/input (and SHA/HKDF inputs) then fail */
    int poison_inputs;

    /* Capture last inputs (shape + copy checks) */
    size_t last_pt_len;
    size_t last_aad_len;
    size_t last_sealed_len;
    size_t last_okm_len;
    size_t last_out_capacity;
    size_t last_msg_len;
    size_t last_salt_len;
    size_t last_ikm_len;
    size_t last_info_len;

    /* Pointers received by callback — must not equal caller originals */
    const void *seen_key;
    const void *seen_nonce;
    const void *seen_aad;
    const void *seen_input;
    const void *seen_msg;
    const void *seen_salt;
    const void *seen_ikm;
    const void *seen_prk;
    const void *seen_info;
} fake_ctx;

static void fake_reset(fake_ctx *f)
{
    memset(f, 0, sizeof(*f));
    f->sha256_result = NINLIL_R7_CRYPTO_RAW_OK;
    f->extract_result = NINLIL_R7_CRYPTO_RAW_OK;
    f->expand_result = NINLIL_R7_CRYPTO_RAW_OK;
    f->seal_result = NINLIL_R7_CRYPTO_RAW_OK;
    f->open_result = NINLIL_R7_CRYPTO_RAW_OK;
    f->sealed_prefix = 0xA5u;
    f->tag_byte = 0x5Au;
    {
        size_t i;
        for (i = 0u; i < 32u; i++) {
            f->digest32[i] = (uint8_t)(0x10u + i);
            f->prk32[i] = (uint8_t)(0x20u + i);
        }
        for (i = 0u; i < 16u; i++) {
            f->okm16[i] = (uint8_t)(0x30u + i);
        }
    }
}

static void poison_mut_bytes(uint8_t *p, size_t n)
{
    size_t i;
    if (p == NULL || n == 0u) {
        return;
    }
    for (i = 0u; i < n; i++) {
        p[i] = (uint8_t)(p[i] ^ 0xFFu);
    }
}

static ninlil_r7_crypto_raw_status fake_sha256(
    void *ctx, const uint8_t *msg, size_t msg_len, uint8_t out_digest[32])
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t i;

    f->sha256_calls++;
    f->last_msg_len = msg_len;
    f->seen_msg = msg;

    if (f->poison_inputs) {
        poison_mut_bytes((uint8_t *)(uintptr_t)msg, msg_len);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    if (f->sha256_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->sha256_result;
    }
    for (i = 0u; i < 32u; i++) {
        out_digest[i] = f->digest32[i];
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status fake_extract(
    void *ctx,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *ikm,
    size_t ikm_len,
    uint8_t out_prk[32])
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t i;

    f->extract_calls++;
    f->last_salt_len = salt_len;
    f->last_ikm_len = ikm_len;
    f->seen_salt = salt;
    f->seen_ikm = ikm;

    if (f->poison_inputs) {
        poison_mut_bytes((uint8_t *)(uintptr_t)salt, salt_len);
        poison_mut_bytes((uint8_t *)(uintptr_t)ikm, ikm_len);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    if (f->extract_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->extract_result;
    }
    for (i = 0u; i < 32u; i++) {
        out_prk[i] = f->prk32[i];
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status fake_expand(
    void *ctx,
    const uint8_t prk[32],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out_okm,
    size_t okm_len)
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t i;

    f->expand_calls++;
    f->last_okm_len = okm_len;
    f->last_info_len = info_len;
    f->seen_prk = prk;
    f->seen_info = info;

    if (f->poison_inputs) {
        poison_mut_bytes((uint8_t *)(uintptr_t)prk, 32u);
        poison_mut_bytes((uint8_t *)(uintptr_t)info, info_len);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    if (f->expand_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->expand_result;
    }
    for (i = 0u; i < okm_len && i < 16u; i++) {
        out_okm[i] = f->okm16[i];
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static size_t apply_produced_mode(int mode, size_t expected, size_t sentinel)
{
    if (mode == 1) {
        return (expected > 0u) ? (expected - 1u) : 0u;
    }
    if (mode == 2) {
        return expected + 1u;
    }
    if (mode == 3) {
        return sentinel; /* leave unchanged conceptually; caller already set sentinel */
    }
    if (mode == 4) {
        return 0u;
    }
    return expected;
}

static ninlil_r7_crypto_raw_status fake_seal(
    void *ctx,
    const uint8_t key[16],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *out_sealed,
    size_t out_capacity,
    size_t *produced_len)
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t i;
    size_t expected;
    size_t sentinel;

    f->seal_calls++;
    f->last_pt_len = plaintext_len;
    f->last_aad_len = aad_len;
    f->last_out_capacity = out_capacity;
    f->seen_key = key;
    f->seen_nonce = nonce;
    f->seen_aad = aad;
    f->seen_input = plaintext;

    if (produced_len == NULL) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    sentinel = *produced_len;
    expected = plaintext_len + 16u;

    if (f->poison_inputs) {
        poison_mut_bytes((uint8_t *)(uintptr_t)key, 16u);
        poison_mut_bytes((uint8_t *)(uintptr_t)nonce, 12u);
        poison_mut_bytes((uint8_t *)(uintptr_t)aad, aad_len);
        poison_mut_bytes((uint8_t *)(uintptr_t)plaintext, plaintext_len);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    if (f->seal_partial_write) {
        if (out_capacity > 0u) {
            out_sealed[0] = 0xEEu;
        }
        if (out_capacity > 1u) {
            out_sealed[1] = 0xFFu;
        }
        *produced_len = apply_produced_mode(f->seal_produced_mode, expected, sentinel);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    if (f->seal_unknown_result) {
        return (ninlil_r7_crypto_raw_status)99;
    }
    if (f->seal_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->seal_result;
    }

    for (i = 0u; i < plaintext_len && i < out_capacity; i++) {
        out_sealed[i] = (uint8_t)(f->sealed_prefix ^ (uint8_t)i);
    }
    for (i = 0u; i < 16u && (plaintext_len + i) < out_capacity; i++) {
        out_sealed[plaintext_len + i] = f->tag_byte;
    }

    if (f->seal_produced_mode == 3) {
        /* leave *produced_len at sentinel (unchanged) */
        (void)sentinel;
    } else {
        *produced_len = apply_produced_mode(f->seal_produced_mode, expected, sentinel);
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static ninlil_r7_crypto_raw_status fake_open(
    void *ctx,
    const uint8_t key[16],
    const uint8_t nonce[12],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *sealed,
    size_t sealed_len,
    uint8_t *out_plaintext,
    size_t out_capacity,
    size_t *produced_len)
{
    fake_ctx *f = (fake_ctx *)ctx;
    size_t pt_len;
    size_t i;
    size_t expected;
    size_t sentinel;

    f->open_calls++;
    f->last_aad_len = aad_len;
    f->last_sealed_len = sealed_len;
    f->last_out_capacity = out_capacity;
    f->seen_key = key;
    f->seen_nonce = nonce;
    f->seen_aad = aad;
    f->seen_input = sealed;

    if (produced_len == NULL) {
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    sentinel = *produced_len;
    pt_len = (sealed_len >= 16u) ? (sealed_len - 16u) : 0u;
    expected = pt_len;

    if (f->poison_inputs) {
        poison_mut_bytes((uint8_t *)(uintptr_t)key, 16u);
        poison_mut_bytes((uint8_t *)(uintptr_t)nonce, 12u);
        poison_mut_bytes((uint8_t *)(uintptr_t)aad, aad_len);
        poison_mut_bytes((uint8_t *)(uintptr_t)sealed, sealed_len);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }

    if (f->open_partial_write) {
        if (out_capacity > 0u) {
            out_plaintext[0] = 0xCCu;
        }
        if (out_capacity > 1u) {
            out_plaintext[1] = 0xDDu;
        }
        *produced_len = apply_produced_mode(f->open_produced_mode, expected, sentinel);
        return NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    }
    if (f->open_unknown_result) {
        return (ninlil_r7_crypto_raw_status)77;
    }
    if (f->open_result != NINLIL_R7_CRYPTO_RAW_OK) {
        return f->open_result;
    }

    for (i = 0u; i < pt_len && i < out_capacity; i++) {
        out_plaintext[i] = (uint8_t)(0x40u + (uint8_t)i);
    }

    if (f->open_produced_mode == 3) {
        (void)sentinel;
    } else {
        *produced_len = apply_produced_mode(f->open_produced_mode, expected, sentinel);
    }
    return NINLIL_R7_CRYPTO_RAW_OK;
}

static void fill_provider(ninlil_r7_crypto_provider *p, fake_ctx *f)
{
    memset(p, 0, sizeof(*p));
    p->abi_version = NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION;
    p->struct_size = (uint32_t)sizeof(ninlil_r7_crypto_provider);
    p->reserved_zero = 0u;
    p->ctx = f;
    p->sha256 = fake_sha256;
    p->hkdf_extract_sha256 = fake_extract;
    p->hkdf_expand_sha256 = fake_expand;
    p->aes128_gcm_seal = fake_seal;
    p->aes128_gcm_open = fake_open;
}

static int total_calls(const fake_ctx *f)
{
    return f->sha256_calls + f->extract_calls + f->expand_calls + f->seal_calls +
           f->open_calls;
}

/* -------------------------------------------------------------------------- */
/* Provider shape                                                             */
/* -------------------------------------------------------------------------- */

static void test_provider_validate(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;

    fake_reset(&f);
    fill_provider(&p, &f);
    expect_status("validate ok", ninlil_r7_crypto_provider_validate(&p), NINLIL_R7_CRYPTO_OK);

    expect_status(
        "validate null",
        ninlil_r7_crypto_provider_validate(NULL),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.abi_version = 0u;
    expect_status(
        "validate bad abi", ninlil_r7_crypto_provider_validate(&p), NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.abi_version = 2u;
    expect_status(
        "validate abi2", ninlil_r7_crypto_provider_validate(&p), NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.struct_size = (uint32_t)(sizeof(ninlil_r7_crypto_provider) - 1u);
    expect_status(
        "validate undersize",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.struct_size = (uint32_t)(sizeof(ninlil_r7_crypto_provider) + 1u);
    expect_status(
        "validate oversize",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.reserved_zero = 1u;
    expect_status(
        "validate reserved",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.sha256 = NULL;
    expect_status(
        "validate null sha256",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.hkdf_extract_sha256 = NULL;
    expect_status(
        "validate null extract",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.hkdf_expand_sha256 = NULL;
    expect_status(
        "validate null expand",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.aes128_gcm_seal = NULL;
    expect_status(
        "validate null seal",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    fill_provider(&p, &f);
    p.aes128_gcm_open = NULL;
    expect_status(
        "validate null open",
        ninlil_r7_crypto_provider_validate(&p),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    expect_true("validate no backend calls", total_calls(&f) == 0);
}

/* -------------------------------------------------------------------------- */
/* SHA-256 / HKDF success fixed bytes                                         */
/* -------------------------------------------------------------------------- */

static void test_sha256_success(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t out[32];
    uint8_t canary[32];
    uint8_t msg[3] = {'a', 'b', 'c'};
    uint8_t msg_orig[3];
    size_t i;

    fake_reset(&f);
    fill_provider(&p, &f);
    for (i = 0u; i < 32u; i++) {
        out[i] = 0xAAu;
        canary[i] = 0xAAu;
    }

    expect_status(
        "sha256 empty", ninlil_r7_crypto_sha256(&p, NULL, 0u, out), NINLIL_R7_CRYPTO_OK);
    expect_mem_eq_u8("sha256 fixed", out, f.digest32, 32u);
    expect_true("sha256 calls1", f.sha256_calls == 1);

    /* Backend fail: no mutation of out or msg */
    fake_reset(&f);
    fill_provider(&p, &f);
    f.sha256_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    memcpy(msg_orig, msg, 3u);
    for (i = 0u; i < 32u; i++) {
        out[i] = 0xAAu;
    }
    expect_status(
        "sha256 backend fail",
        ninlil_r7_crypto_sha256(&p, msg, 3u, out),
        NINLIL_R7_CRYPTO_BACKEND_FAILED);
    expect_mem_eq_u8("sha256 fail mut0", out, canary, 32u);
    expect_mem_eq_u8("sha256 fail msg mut0", msg, msg_orig, 3u);
    expect_true("sha256 fail called", f.sha256_calls == 1);
    expect_true("sha256 saw copy not caller", f.seen_msg != (const void *)msg);

    /* AUTH result from sha256 => INTERNAL_CONTRACT, mut0 */
    fake_reset(&f);
    fill_provider(&p, &f);
    f.sha256_result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
    for (i = 0u; i < 32u; i++) {
        out[i] = 0xAAu;
    }
    expect_status(
        "sha256 auth impossible",
        ninlil_r7_crypto_sha256(&p, msg, 1u, out),
        NINLIL_R7_CRYPTO_INTERNAL_CONTRACT);
    expect_mem_eq_u8("sha256 auth mut0", out, canary, 32u);

    /* max message 2048 accepted; 2049 rejected call0 */
    {
        uint8_t dig[32];
        uint8_t big[2048];
        uint8_t over[2049];
        memset(big, 0x11, sizeof(big));
        memset(over, 0x22, sizeof(over));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "sha max2048", ninlil_r7_crypto_sha256(&p, big, 2048u, dig), NINLIL_R7_CRYPTO_OK);
        expect_true("sha max called", f.sha256_calls == 1);
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "sha over2049",
            ninlil_r7_crypto_sha256(&p, over, 2049u, dig),
            NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
        expect_true("sha over call0", f.sha256_calls == 0);
    }
}

static void test_hkdf_success(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t prk[32];
    uint8_t okm12[12];
    uint8_t okm16[16];
    uint8_t poison[32];
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t info[25];
    uint8_t salt_orig[32];
    uint8_t ikm_orig[32];
    size_t i;

    for (i = 0u; i < 32u; i++) {
        poison[i] = 0x55u;
        salt[i] = (uint8_t)(0x01u + i);
        ikm[i] = (uint8_t)(0x81u + i);
    }
    for (i = 0u; i < 25u; i++) {
        info[i] = (uint8_t)(0xA0u + i);
    }
    memcpy(salt_orig, salt, 32u);
    memcpy(ikm_orig, ikm, 32u);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(prk, poison, 32u);
    expect_status(
        "extract ok",
        ninlil_r7_crypto_hkdf_extract_sha256(&p, salt, 32u, ikm, 32u, prk),
        NINLIL_R7_CRYPTO_OK);
    expect_mem_eq_u8("extract fixed", prk, f.prk32, 32u);
    expect_true("extract calls1", f.extract_calls == 1);
    expect_true("extract salt copy", f.seen_salt != (const void *)salt);
    expect_true("extract ikm copy", f.seen_ikm != (const void *)ikm);

    /* wrong salt/ikm length => call0 */
    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(prk, poison, 32u);
    expect_status(
        "extract salt31",
        ninlil_r7_crypto_hkdf_extract_sha256(&p, salt, 31u, ikm, 32u, prk),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_status(
        "extract ikm0",
        ninlil_r7_crypto_hkdf_extract_sha256(&p, salt, 32u, ikm, 0u, prk),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_mem_eq_u8("extract bad mut0", prk, poison, 32u);
    expect_true("extract bad call0", f.extract_calls == 0);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(okm16, poison, 16u);
    expect_status(
        "expand 16",
        ninlil_r7_crypto_hkdf_expand_sha256(&p, f.prk32, info, 3u, okm16, 16u),
        NINLIL_R7_CRYPTO_OK);
    expect_mem_eq_u8("expand16 fixed", okm16, f.okm16, 16u);
    expect_true("expand okm_len16", f.last_okm_len == 16u);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(okm12, poison, 12u);
    expect_status(
        "expand 12",
        ninlil_r7_crypto_hkdf_expand_sha256(&p, f.prk32, info, 3u, okm12, 12u),
        NINLIL_R7_CRYPTO_OK);
    expect_mem_eq_u8("expand12 fixed", okm12, f.okm16, 12u);

    /* info max 25 ok; 26 reject */
    fake_reset(&f);
    fill_provider(&p, &f);
    expect_status(
        "expand info25",
        ninlil_r7_crypto_hkdf_expand_sha256(&p, f.prk32, info, 25u, okm16, 16u),
        NINLIL_R7_CRYPTO_OK);
    {
        uint8_t info26[26];
        memset(info26, 0, sizeof(info26));
        fake_reset(&f);
        fill_provider(&p, &f);
        memcpy(okm16, poison, 16u);
        expect_status(
            "expand info26",
            ninlil_r7_crypto_hkdf_expand_sha256(&p, f.prk32, info26, 26u, okm16, 16u),
            NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
        expect_true("expand info26 call0", f.expand_calls == 0);
        expect_mem_eq_u8("expand info26 mut0", okm16, poison, 16u);
    }

    /* bad okm_len => call0, mut0 */
    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(okm16, poison, 16u);
    expect_status(
        "expand bad len 1",
        ninlil_r7_crypto_hkdf_expand_sha256(&p, f.prk32, info, 3u, okm16, 1u),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_status(
        "expand bad len 32",
        ninlil_r7_crypto_hkdf_expand_sha256(&p, f.prk32, info, 3u, okm16, 32u),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_mem_eq_u8("expand bad mut0", okm16, poison, 16u);
    expect_true("expand bad call0", f.expand_calls == 0);

    (void)salt_orig;
    (void)ikm_orig;
}

/* -------------------------------------------------------------------------- */
/* AEAD success + produced_len contract                                       */
/* -------------------------------------------------------------------------- */

static void test_aead_seal_open_success(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[19];
    uint8_t pt[220];
    uint8_t sealed[236];
    uint8_t out_pt[220];
    uint8_t canary_sealed[236];
    uint8_t canary_pt[220];
    size_t out_len;
    size_t i;
    size_t expect_len;

    for (i = 0u; i < 16u; i++) {
        key[i] = (uint8_t)i;
    }
    for (i = 0u; i < 12u; i++) {
        nonce[i] = (uint8_t)(0x80u + i);
    }
    for (i = 0u; i < 19u; i++) {
        aad[i] = (uint8_t)(0xC0u + i);
    }
    for (i = 0u; i < 220u; i++) {
        pt[i] = (uint8_t)i;
    }
    memset(canary_sealed, 0x11, sizeof(canary_sealed));
    memset(canary_pt, 0x22, sizeof(canary_pt));

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(sealed, canary_sealed, sizeof(sealed));
    out_len = 0xDEADBEEFu;
    expect_status(
        "seal empty",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, NULL, 0u, sealed, 16u, &out_len),
        NINLIL_R7_CRYPTO_OK);
    expect_true("seal empty len", out_len == 16u);
    expect_true("seal empty calls", f.seal_calls == 1);
    expect_true("seal capacity passed", f.last_out_capacity == 16u);
    for (i = 0u; i < 16u; i++) {
        expect_true("seal empty tag", sealed[i] == f.tag_byte);
    }

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(sealed, canary_sealed, sizeof(sealed));
    out_len = 0u;
    expect_len = 220u + 16u;
    expect_status(
        "seal max",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, aad, 19u, pt, 220u, sealed, expect_len, &out_len),
        NINLIL_R7_CRYPTO_OK);
    expect_true("seal max len", out_len == expect_len);
    expect_true("seal max pt_len", f.last_pt_len == 220u);
    expect_true("seal max aad_len", f.last_aad_len == 19u);
    expect_true("seal saw key copy", f.seen_key != (const void *)key);
    expect_true("seal saw nonce copy", f.seen_nonce != (const void *)nonce);
    expect_true("seal saw aad copy", f.seen_aad != (const void *)aad);
    expect_true("seal saw pt copy", f.seen_input != (const void *)pt);
    for (i = 0u; i < 220u; i++) {
        expect_true("seal max ct", sealed[i] == (uint8_t)(f.sealed_prefix ^ (uint8_t)i));
    }
    for (i = 0u; i < 16u; i++) {
        expect_true("seal max tag", sealed[220u + i] == f.tag_byte);
    }

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(out_pt, canary_pt, sizeof(out_pt));
    out_len = 0xABCDu;
    expect_status(
        "open max",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, aad, 19u, sealed, 236u, out_pt, 220u, &out_len),
        NINLIL_R7_CRYPTO_OK);
    expect_true("open max len", out_len == 220u);
    expect_true("open capacity passed", f.last_out_capacity == 220u);
    expect_true("open saw sealed copy", f.seen_input != (const void *)sealed);
    for (i = 0u; i < 220u; i++) {
        expect_true("open max pt", out_pt[i] == (uint8_t)(0x40u + (uint8_t)i));
    }

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(out_pt, canary_pt, sizeof(out_pt));
    out_len = 99u;
    expect_status(
        "open empty",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, sealed, 16u, out_pt, 0u, &out_len),
        NINLIL_R7_CRYPTO_OK);
    expect_true("open empty len", out_len == 0u);
}

static void test_produced_len_contract(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t pt[8];
    uint8_t sealed[24];
    uint8_t out[8];
    uint8_t sealed_canary[24];
    uint8_t out_canary[8];
    size_t out_len;
    const size_t out_len_canary = 0xCAFEBABEu;
    int mode;
    const char *names[] = {"exact", "short", "long", "unchanged", "zero"};

    memset(key, 1, sizeof(key));
    memset(nonce, 2, sizeof(nonce));
    memset(pt, 3, sizeof(pt));
    memset(sealed_canary, 0xAB, sizeof(sealed_canary));
    memset(out_canary, 0xCD, sizeof(out_canary));
    memset(sealed, 0x44, sizeof(sealed));

    /* modes 1..4: RAW_OK but bad produced_len => INTERNAL_CONTRACT, mut0 */
    for (mode = 1; mode <= 4; mode++) {
        char name[64];
        fake_reset(&f);
        fill_provider(&p, &f);
        f.seal_produced_mode = mode;
        memcpy(sealed, sealed_canary, sizeof(sealed));
        out_len = out_len_canary;
        snprintf(name, sizeof(name), "seal produced %s", names[mode]);
        expect_status(
            name,
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, pt, 8u, sealed, 24u, &out_len),
            NINLIL_R7_CRYPTO_INTERNAL_CONTRACT);
        expect_true("seal produced calls", f.seal_calls == 1);
        expect_mem_eq("seal produced mut sealed", sealed, sealed_canary, 24u);
        expect_true("seal produced mut len", out_len == out_len_canary);
        expect_mem_eq("seal produced mut pt", pt, "\x03\x03\x03\x03\x03\x03\x03\x03", 8u);
    }

    for (mode = 1; mode <= 4; mode++) {
        char name[64];
        fake_reset(&f);
        fill_provider(&p, &f);
        f.open_produced_mode = mode;
        memcpy(out, out_canary, sizeof(out));
        out_len = out_len_canary;
        snprintf(name, sizeof(name), "open produced %s", names[mode]);
        expect_status(
            name,
            ninlil_r7_crypto_aes128_gcm_open(
                &p, key, nonce, NULL, 0u, sealed, 24u, out, 8u, &out_len),
            NINLIL_R7_CRYPTO_INTERNAL_CONTRACT);
        expect_true("open produced calls", f.open_calls == 1);
        expect_mem_eq("open produced mut out", out, out_canary, 8u);
        expect_true("open produced mut len", out_len == out_len_canary);
    }
}

/* -------------------------------------------------------------------------- */
/* Prevalidation call0 + NULL/length/capacity                                 */
/* -------------------------------------------------------------------------- */

static void test_prevalidation_call0(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t pt[8];
    uint8_t sealed[24];
    uint8_t out[8];
    uint8_t sealed_canary[24];
    uint8_t out_canary[8];
    size_t out_len;
    size_t out_len_canary;
    size_t i;

    memset(key, 1, sizeof(key));
    memset(nonce, 2, sizeof(nonce));
    memset(pt, 3, sizeof(pt));
    memset(sealed_canary, 0xAB, sizeof(sealed_canary));
    memset(out_canary, 0xCD, sizeof(out_canary));
    out_len_canary = 0x12345678u;

    fake_reset(&f);
    fill_provider(&p, &f);
    p.abi_version = 0u;
    memcpy(sealed, sealed_canary, sizeof(sealed));
    out_len = out_len_canary;
    expect_status(
        "seal bad provider",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("seal bad provider call0", total_calls(&f) == 0);
    expect_mem_eq("seal bad provider mut sealed", sealed, sealed_canary, 24u);
    expect_true("seal bad provider mut len", out_len == out_len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(sealed, sealed_canary, sizeof(sealed));
    out_len = out_len_canary;
    expect_status(
        "seal null key",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, NULL, nonce, NULL, 0u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("seal null key call0", f.seal_calls == 0);
    expect_mem_eq("seal null key mut", sealed, sealed_canary, 24u);
    expect_true("seal null key len", out_len == out_len_canary);

    expect_status(
        "seal null nonce",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, NULL, NULL, 0u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    expect_status(
        "seal null out",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, NULL, 24u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_status(
        "seal null out_len",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, sealed, 24u, NULL),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    expect_status(
        "seal null aad",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 1u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    expect_status(
        "seal null pt",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, NULL, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    {
        uint8_t aad20[20];
        memset(aad20, 0, sizeof(aad20));
        expect_status(
            "seal aad20",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, aad20, 20u, pt, 8u, sealed, 24u, &out_len),
            NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    }

    {
        uint8_t big[221];
        uint8_t big_out[237];
        memset(big, 0, sizeof(big));
        expect_status(
            "seal body221",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, big, 221u, big_out, 237u, &out_len),
            NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    }

    expect_true("null/len call0 total", f.seal_calls == 0);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(sealed, sealed_canary, sizeof(sealed));
    out_len = out_len_canary;
    expect_status(
        "seal cap under",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, sealed, 23u, &out_len),
        NINLIL_R7_CRYPTO_CAPACITY);
    expect_status(
        "seal cap over",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, sealed, 25u, &out_len),
        NINLIL_R7_CRYPTO_CAPACITY);
    expect_true("cap call0", f.seal_calls == 0);
    expect_mem_eq("cap mut sealed", sealed, sealed_canary, 24u);
    expect_true("cap mut len", out_len == out_len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(out, out_canary, sizeof(out));
    out_len = out_len_canary;
    for (i = 0u; i < 24u; i++) {
        sealed[i] = (uint8_t)i;
    }
    expect_status(
        "open cap under",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, sealed, 24u, out, 7u, &out_len),
        NINLIL_R7_CRYPTO_CAPACITY);
    expect_status(
        "open cap over",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, sealed, 24u, out, 9u, &out_len),
        NINLIL_R7_CRYPTO_CAPACITY);
    expect_status(
        "open sealed short",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, sealed, 15u, out, 0u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_status(
        "open sealed null",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, NULL, 24u, out, 8u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("open prev call0", f.open_calls == 0);
    expect_mem_eq("open cap mut", out, out_canary, 8u);
    expect_true("open cap len", out_len == out_len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    expect_status(
        "sha null out",
        ninlil_r7_crypto_sha256(&p, NULL, 0u, NULL),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("sha prev call0", f.sha256_calls == 0);
}

static void test_validation_priority(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[20];
    uint8_t input[24];
    uint8_t shared[32];
    uint8_t shared_before[32];
    size_t out_len;
    const size_t len_canary = (size_t)0x12345678u;

    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    memset(aad, 0x33, sizeof(aad));
    memset(input, 0x44, sizeof(input));
    memset(shared, 0xA5, sizeof(shared));

    /* provider shape outranks every caller pointer/length error */
    fake_reset(&f);
    fill_provider(&p, &f);
    p.abi_version++;
    out_len = len_canary;
    expect_status(
        "priority seal provider before pointer",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, NULL, NULL, NULL, 999u, NULL, 999u, NULL, 0u, NULL),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("priority seal invalid provider call0", f.seal_calls == 0);

    fake_reset(&f);
    fill_provider(&p, &f);
    p.struct_size--;
    expect_status(
        "priority open provider before pointer",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, NULL, NULL, NULL, 999u, NULL, 0u, NULL, 0u, NULL),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("priority open invalid provider call0", f.open_calls == 0);

    /* numeric domain outranks capacity */
    fake_reset(&f);
    fill_provider(&p, &f);
    out_len = len_canary;
    expect_status(
        "priority seal length before capacity",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, aad, 20u, input, 8u, shared, 0u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("priority seal length call0", f.seal_calls == 0);
    expect_true("priority seal length len mut0", out_len == len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    out_len = len_canary;
    expect_status(
        "priority open length before capacity",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, aad, 8u, input, 15u, shared, 99u, &out_len),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_true("priority open length call0", f.open_calls == 0);

    /* exact capacity check outranks an otherwise-forbidden alias */
    fake_reset(&f);
    fill_provider(&p, &f);
    out_len = len_canary;
    memcpy(shared_before, shared, sizeof(shared_before));
    expect_status(
        "priority seal capacity before alias",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, shared, nonce, aad, 8u, input, 8u, shared, 23u, &out_len),
        NINLIL_R7_CRYPTO_CAPACITY);
    expect_true("priority seal capacity call0", f.seal_calls == 0);
    expect_mem_eq("priority seal capacity mut0", shared, shared_before, sizeof(shared));
    expect_true("priority seal capacity len mut0", out_len == len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    out_len = len_canary;
    expect_status(
        "priority open capacity before alias",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, aad, 8u, shared, 24u, shared, 7u, &out_len),
        NINLIL_R7_CRYPTO_CAPACITY);
    expect_true("priority open capacity call0", f.open_calls == 0);

    /* alias prevalidation outranks configured backend failure */
    fake_reset(&f);
    fill_provider(&p, &f);
    f.seal_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    out_len = len_canary;
    expect_status(
        "priority seal alias before backend",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, shared, nonce, aad, 8u, input, 8u, shared, 24u, &out_len),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("priority seal alias call0", f.seal_calls == 0);

    fake_reset(&f);
    fill_provider(&p, &f);
    f.open_result = NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED;
    out_len = len_canary;
    expect_status(
        "priority open alias before backend",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, aad, 8u, shared, 24u, shared, 8u, &out_len),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("priority open alias call0", f.open_calls == 0);
}

/* -------------------------------------------------------------------------- */
/* Full pairwise alias matrix                                                 */
/* -------------------------------------------------------------------------- */

/*
 * Place span B relative to span A:
 *   kind 0 = exact same start (if lens allow meaningful overlap)
 *   kind 1 = left partial (B starts 1 before end of A when possible)
 *   kind 2 = right partial (B starts 1 inside A)
 *   kind 3 = adjacent (B starts at end of A) — allowed
 *
 * For fixed-size pairs we use a shared arena with controlled offsets.
 */

static void snapshot_bytes(uint8_t *dst, const uint8_t *src, size_t n)
{
    if (n > 0u) {
        memcpy(dst, src, n);
    }
}

static int mem_unchanged(const uint8_t *a, const uint8_t *b, size_t n)
{
    if (n == 0u) {
        return 1;
    }
    return memcmp(a, b, n) == 0;
}

enum aead_alias_span {
    AEAD_SPAN_PROVIDER = 0,
    AEAD_SPAN_KEY = 1,
    AEAD_SPAN_NONCE = 2,
    AEAD_SPAN_AAD = 3,
    AEAD_SPAN_INPUT = 4,
    AEAD_SPAN_OUTPUT = 5,
    AEAD_SPAN_OUT_LEN = 6,
    AEAD_SPAN_COUNT = 7
};

_Static_assert(AEAD_SPAN_COUNT == 7, "AEAD alias matrix must retain seven spans");

struct provider_test_storage {
    ninlil_r7_crypto_provider provider;
    uint8_t tail[128];
};

struct size_test_storage {
    size_t value;
    uint8_t tail[NINLIL_R7_CRYPTO_SEALED_MAX];
};

union provider_out_len_test_storage {
    ninlil_r7_crypto_provider provider;
    size_t out_len;
};

_Static_assert(
    offsetof(struct provider_test_storage, tail)
        == sizeof(ninlil_r7_crypto_provider),
    "provider test tail must begin adjacent to provider span");
_Static_assert(
    offsetof(struct size_test_storage, tail) == sizeof(size_t),
    "size_t test tail must begin adjacent to out_len storage");
_Static_assert(
    sizeof(struct size_test_storage) >= NINLIL_R7_CRYPTO_SEALED_MAX,
    "size_t test storage must back the largest matrix byte span");
_Static_assert(
    offsetof(union provider_out_len_test_storage, provider) == 0u
        && offsetof(union provider_out_len_test_storage, out_len) == 0u,
    "provider and out_len union members must overlap at offset zero");
_Static_assert(
    sizeof(union provider_out_len_test_storage)
        >= sizeof(ninlil_r7_crypto_provider),
    "provider/out_len union must back the complete provider span");

static int test_span_within_object(
    const void *span,
    size_t span_len,
    const void *object,
    size_t object_len)
{
    uintptr_t span_begin;
    uintptr_t object_begin;
    size_t offset;

    if (span == NULL || object == NULL || span_len > object_len) {
        return 0;
    }
    span_begin = (uintptr_t)span;
    object_begin = (uintptr_t)object;
    if (span_begin < object_begin) {
        return 0;
    }
    if ((span_begin - object_begin) > (uintptr_t)SIZE_MAX) {
        return 0;
    }
    offset = (size_t)(span_begin - object_begin);
    return offset <= (object_len - span_len);
}

/*
 * Exhaustive 7-choose-2 matrix for both Seal and Open.  Storage retains its
 * real C effective type: a provider is an actual provider object and an
 * out-length is an actual size_t.  Byte pointers may inspect/overlap either
 * object representation, but the ALIAS prevalidation path must never
 * dereference those overlapping byte spans or the provider-overlapping
 * size_t pointer.
 */
static void test_aead_full_alias_matrix(int open_mode)
{
    static const char *const span_names[AEAD_SPAN_COUNT] = {
        "provider", "key", "nonce", "aad", "input", "out", "out_len"
    };
    fake_ctx f;
    union provider_out_len_test_storage provider_storage;
    uint8_t provider_storage_before[sizeof(provider_storage)];
    uint8_t key[16];
    uint8_t key_before[16];
    uint8_t nonce[12];
    uint8_t nonce_before[12];
    uint8_t aad[8];
    uint8_t aad_before[8];
    uint8_t input[24];
    uint8_t input_before[24];
    uint8_t output[24];
    uint8_t output_before[24];
    uint8_t alias_bytes[32];
    uint8_t alias_bytes_before[32];
    struct size_test_storage alias_len_storage;
    uint8_t alias_len_storage_before[sizeof(alias_len_storage)];
    size_t out_len_storage;
    size_t out_len_storage_before;
    int left;
    int pair_count;
    int right;

    _Static_assert(
        _Alignof(ninlil_r7_crypto_provider) >= _Alignof(size_t),
        "provider must be sufficiently aligned for a non-dereferenced size_t alias pointer");

    pair_count = 0;
    for (left = 0; left < AEAD_SPAN_COUNT; ++left) {
        for (right = left + 1; right < AEAD_SPAN_COUNT; ++right) {
            const uint8_t *key_arg;
            const uint8_t *nonce_arg;
            const uint8_t *aad_arg;
            const uint8_t *input_arg;
            uint8_t *output_arg;
            size_t *out_len_arg;
            uint8_t *overlap;
            const void *overlap_object;
            size_t overlap_object_len;
            const void *matrix_spans[AEAD_SPAN_COUNT];
            size_t matrix_lens[AEAD_SPAN_COUNT];
            const void *matrix_owners[AEAD_SPAN_COUNT];
            size_t matrix_owner_lens[AEAD_SPAN_COUNT];
            ninlil_r7_crypto_status status;
            int bounds_valid;
            int mutation_zero;
            char label[128];
            int span_index;

            fake_reset(&f);
            memset(&provider_storage, 0, sizeof(provider_storage));
            fill_provider(&provider_storage.provider, &f);
            memset(key, 0x11, sizeof(key));
            memset(nonce, 0x22, sizeof(nonce));
            memset(aad, 0x33, sizeof(aad));
            memset(input, 0x44, sizeof(input));
            memset(output, 0xEE, sizeof(output));
            memset(alias_bytes, 0xA5, sizeof(alias_bytes));
            memset(&alias_len_storage, 0xA5, sizeof(alias_len_storage));
            alias_len_storage.value = (size_t)0xA55AA55Au;
            out_len_storage = (size_t)0x5AA55AA5u;

            key_arg = key;
            nonce_arg = nonce;
            aad_arg = aad;
            input_arg = input;
            output_arg = output;
            out_len_arg = &out_len_storage;

            if (left == AEAD_SPAN_PROVIDER) {
                overlap = (uint8_t *)(void *)&provider_storage;
                overlap_object = &provider_storage;
                overlap_object_len = sizeof(provider_storage);
            } else if (right == AEAD_SPAN_OUT_LEN) {
                overlap = (uint8_t *)(void *)&alias_len_storage;
                overlap_object = &alias_len_storage;
                overlap_object_len = sizeof(alias_len_storage);
                out_len_arg = &alias_len_storage.value;
            } else {
                overlap = alias_bytes;
                overlap_object = alias_bytes;
                overlap_object_len = sizeof(alias_bytes);
            }

            if (left == AEAD_SPAN_KEY || right == AEAD_SPAN_KEY) {
                key_arg = overlap;
            }
            if (left == AEAD_SPAN_NONCE || right == AEAD_SPAN_NONCE) {
                nonce_arg = overlap;
            }
            if (left == AEAD_SPAN_AAD || right == AEAD_SPAN_AAD) {
                aad_arg = overlap;
            }
            if (left == AEAD_SPAN_INPUT || right == AEAD_SPAN_INPUT) {
                input_arg = overlap;
            }
            if (left == AEAD_SPAN_OUTPUT || right == AEAD_SPAN_OUTPUT) {
                output_arg = overlap;
            }
            if (left == AEAD_SPAN_PROVIDER && right == AEAD_SPAN_OUT_LEN) {
                out_len_arg = &provider_storage.out_len;
            }

            matrix_spans[AEAD_SPAN_PROVIDER] = &provider_storage.provider;
            matrix_lens[AEAD_SPAN_PROVIDER] = sizeof(provider_storage.provider);
            matrix_owners[AEAD_SPAN_PROVIDER] = &provider_storage;
            matrix_owner_lens[AEAD_SPAN_PROVIDER] = sizeof(provider_storage);
            matrix_spans[AEAD_SPAN_KEY] = key_arg;
            matrix_lens[AEAD_SPAN_KEY] = NINLIL_R7_CRYPTO_AES128_KEY_LEN;
            matrix_owners[AEAD_SPAN_KEY] = key_arg == key ? (const void *)key : overlap_object;
            matrix_owner_lens[AEAD_SPAN_KEY] =
                key_arg == key ? sizeof(key) : overlap_object_len;
            matrix_spans[AEAD_SPAN_NONCE] = nonce_arg;
            matrix_lens[AEAD_SPAN_NONCE] = NINLIL_R7_CRYPTO_AES128_NONCE_LEN;
            matrix_owners[AEAD_SPAN_NONCE] =
                nonce_arg == nonce ? (const void *)nonce : overlap_object;
            matrix_owner_lens[AEAD_SPAN_NONCE] =
                nonce_arg == nonce ? sizeof(nonce) : overlap_object_len;
            matrix_spans[AEAD_SPAN_AAD] = aad_arg;
            matrix_lens[AEAD_SPAN_AAD] = sizeof(aad);
            matrix_owners[AEAD_SPAN_AAD] = aad_arg == aad ? (const void *)aad : overlap_object;
            matrix_owner_lens[AEAD_SPAN_AAD] =
                aad_arg == aad ? sizeof(aad) : overlap_object_len;
            matrix_spans[AEAD_SPAN_INPUT] = input_arg;
            matrix_lens[AEAD_SPAN_INPUT] = open_mode != 0 ? sizeof(input) : 8u;
            matrix_owners[AEAD_SPAN_INPUT] =
                input_arg == input ? (const void *)input : overlap_object;
            matrix_owner_lens[AEAD_SPAN_INPUT] =
                input_arg == input ? sizeof(input) : overlap_object_len;
            matrix_spans[AEAD_SPAN_OUTPUT] = output_arg;
            matrix_lens[AEAD_SPAN_OUTPUT] = open_mode != 0 ? 8u : sizeof(output);
            matrix_owners[AEAD_SPAN_OUTPUT] =
                output_arg == output ? (const void *)output : overlap_object;
            matrix_owner_lens[AEAD_SPAN_OUTPUT] =
                output_arg == output ? sizeof(output) : overlap_object_len;
            matrix_spans[AEAD_SPAN_OUT_LEN] = out_len_arg;
            matrix_lens[AEAD_SPAN_OUT_LEN] = sizeof(*out_len_arg);
            if (left == AEAD_SPAN_PROVIDER && right == AEAD_SPAN_OUT_LEN) {
                matrix_owners[AEAD_SPAN_OUT_LEN] = &provider_storage;
                matrix_owner_lens[AEAD_SPAN_OUT_LEN] = sizeof(provider_storage);
            } else if (right == AEAD_SPAN_OUT_LEN) {
                matrix_owners[AEAD_SPAN_OUT_LEN] = &alias_len_storage;
                matrix_owner_lens[AEAD_SPAN_OUT_LEN] = sizeof(alias_len_storage);
            } else {
                matrix_owners[AEAD_SPAN_OUT_LEN] = &out_len_storage;
                matrix_owner_lens[AEAD_SPAN_OUT_LEN] = sizeof(out_len_storage);
            }

            bounds_valid = 1;
            for (span_index = 0; span_index < AEAD_SPAN_COUNT; ++span_index) {
                if (!test_span_within_object(
                        matrix_spans[span_index],
                        matrix_lens[span_index],
                        matrix_owners[span_index],
                        matrix_owner_lens[span_index])) {
                    bounds_valid = 0;
                }
            }
            (void)snprintf(
                label,
                sizeof(label),
                "%s matrix %s/%s valid-bounds",
                open_mode != 0 ? "open" : "seal",
                span_names[left],
                span_names[right]);
            expect_true(label, bounds_valid);
            (void)snprintf(
                label,
                sizeof(label),
                "%s matrix %s/%s exact-overlap",
                open_mode != 0 ? "open" : "seal",
                span_names[left],
                span_names[right]);
            expect_true(label, matrix_spans[left] == matrix_spans[right]);

            memcpy(
                provider_storage_before,
                &provider_storage,
                sizeof(provider_storage_before));
            memcpy(key_before, key, sizeof(key_before));
            memcpy(nonce_before, nonce, sizeof(nonce_before));
            memcpy(aad_before, aad, sizeof(aad_before));
            memcpy(input_before, input, sizeof(input_before));
            memcpy(output_before, output, sizeof(output_before));
            memcpy(alias_bytes_before, alias_bytes, sizeof(alias_bytes_before));
            memcpy(
                alias_len_storage_before,
                &alias_len_storage,
                sizeof(alias_len_storage_before));
            out_len_storage_before = out_len_storage;

            if (open_mode != 0) {
                status = ninlil_r7_crypto_aes128_gcm_open(
                    &provider_storage.provider,
                    key_arg,
                    nonce_arg,
                    aad_arg,
                    sizeof(aad),
                    input_arg,
                    sizeof(input),
                    output_arg,
                    8u,
                    out_len_arg);
            } else {
                status = ninlil_r7_crypto_aes128_gcm_seal(
                    &provider_storage.provider,
                    key_arg,
                    nonce_arg,
                    aad_arg,
                    sizeof(aad),
                    input_arg,
                    8u,
                    output_arg,
                    sizeof(output),
                    out_len_arg);
            }

            (void)snprintf(
                label,
                sizeof(label),
                "%s matrix %s/%s status",
                open_mode != 0 ? "open" : "seal",
                span_names[left],
                span_names[right]);
            expect_status(label, status, NINLIL_R7_CRYPTO_ALIAS);

            (void)snprintf(
                label,
                sizeof(label),
                "%s matrix %s/%s call0",
                open_mode != 0 ? "open" : "seal",
                span_names[left],
                span_names[right]);
            expect_true(
                label,
                open_mode != 0 ? (f.open_calls == 0) : (f.seal_calls == 0));

            mutation_zero =
                memcmp(
                    provider_storage_before,
                    &provider_storage,
                    sizeof(provider_storage)) == 0
                && memcmp(key_before, key, sizeof(key)) == 0
                && memcmp(nonce_before, nonce, sizeof(nonce)) == 0
                && memcmp(aad_before, aad, sizeof(aad)) == 0
                && memcmp(input_before, input, sizeof(input)) == 0
                && memcmp(output_before, output, sizeof(output)) == 0
                && memcmp(alias_bytes_before, alias_bytes, sizeof(alias_bytes)) == 0
                && memcmp(
                       alias_len_storage_before,
                       &alias_len_storage,
                       sizeof(alias_len_storage)) == 0
                && out_len_storage_before == out_len_storage;
            (void)snprintf(
                label,
                sizeof(label),
                "%s matrix %s/%s mutation0",
                open_mode != 0 ? "open" : "seal",
                span_names[left],
                span_names[right]);
            expect_true(label, mutation_zero);
            pair_count++;
        }
    }
    expect_true(
        open_mode != 0 ? "open matrix exact 21 calls" : "seal matrix exact 21 calls",
        pair_count == 21);
}

static void test_alias_pair_aead_seal(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    /* Independent storage for non-overlapping baseline */
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[8];
    uint8_t pt[8];
    uint8_t out[24];
    size_t out_len;
    const size_t out_len_canary = 0x55AAu;
    uint8_t key_s[16], pt_s[8], out_s[24];
    size_t i;

    memset(key, 0x10, sizeof(key));
    memset(nonce, 0x20, sizeof(nonce));
    memset(aad, 0x30, sizeof(aad));
    memset(pt, 0x40, sizeof(pt));
    memset(out, 0xEE, sizeof(out));

    /* Adjacent pt|out allowed */
    {
        uint8_t adj[8 + 24];
        uint8_t *apt = adj;
        uint8_t *aout = adj + 8;
        size_t alen = out_len_canary;
        memset(adj, 0x99, sizeof(adj));
        for (i = 0u; i < 8u; i++) {
            apt[i] = (uint8_t)i;
        }
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "seal adj pt/out ok",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, apt, 8u, aout, 24u, &alen),
            NINLIL_R7_CRYPTO_OK);
        expect_true("seal adj called", f.seal_calls == 1);
    }

    /* Exact aliases */
    fake_reset(&f);
    fill_provider(&p, &f);
    out_len = out_len_canary;
    {
        uint8_t shared[24];
        memset(shared, 0x77, sizeof(shared));
        for (i = 0u; i < 8u; i++) {
            shared[i] = (uint8_t)i;
        }
        snapshot_bytes(pt_s, shared, 8u);
        expect_status(
            "seal exact pt/out",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, shared, 8u, shared, 24u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("exact call0", f.seal_calls == 0);
        expect_true("exact len mut0", out_len == out_len_canary);
        expect_true("exact input mut0", mem_unchanged(shared, pt_s, 8u));
    }

    /* key/out exact-ish: key placed inside out region */
    {
        uint8_t buf[64];
        uint8_t *bkey = buf;
        uint8_t *bout = buf + 8;
        memset(buf, 0xEE, sizeof(buf));
        memset(key, 0x10, sizeof(key));
        /* use bkey/bout */
        fake_reset(&f);
        fill_provider(&p, &f);
        out_len = out_len_canary;
        snapshot_bytes(key_s, bkey, 16u);
        snapshot_bytes(out_s, bout, 24u);
        expect_status(
            "seal alias key/out",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, bkey, nonce, aad, 8u, pt, 8u, bout, 24u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("key/out call0", f.seal_calls == 0);
        expect_true("key/out key mut0", mem_unchanged(bkey, key_s, 16u));
        expect_true("key/out out mut0", mem_unchanged(bout, out_s, 24u));
        expect_true("key/out len mut0", out_len == out_len_canary);
    }

    /* nonce/aad partial */
    {
        uint8_t buf[64];
        uint8_t *bnonce = buf;
        uint8_t *baad = buf + 8;
        memset(buf, 0x55, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        memset(out, 0xEE, sizeof(out));
        out_len = out_len_canary;
        expect_status(
            "seal alias nonce/aad",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, bnonce, baad, 8u, pt, 8u, out, 24u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("nonce/aad call0", f.seal_calls == 0);
        expect_true("nonce/aad len mut0", out_len == out_len_canary);
    }

    /* out / out_len: aligned size_t storage inside out */
    {
        struct size_test_storage region;
        uint8_t *bout = (uint8_t *)(void *)&region;
        size_t *blen = &region.value;
        memset(&region, 0xEE, sizeof(region));
        region.value = out_len_canary;
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "seal alias out/out_len",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, pt, 8u, bout, 24u, blen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("out/out_len call0", f.seal_calls == 0);
        expect_true("out/out_len mut0", *blen == out_len_canary);
    }

    /* provider object overlaps out: place provider bytes overlapping buffer */
    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        uint8_t *bout;
        uint8_t provider_before[sizeof(ninlil_r7_crypto_provider)];
        size_t alen = out_len_canary;
        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        fill_provider(pp, &f);
        fake_reset(&f);
        pp->ctx = &f;
        /* out starts inside provider object */
        bout = (uint8_t *)(void *)pp + 8;
        memcpy(provider_before, pp, sizeof(provider_before));
        expect_status(
            "seal alias provider/out",
            ninlil_r7_crypto_aes128_gcm_seal(
                pp, key, nonce, aad, 8u, pt, 8u, bout, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("prov/out call0", f.seal_calls == 0);
        expect_true("prov/out len mut0", alen == out_len_canary);
        expect_true(
            "prov/out provider mut0",
            memcmp(provider_before, pp, sizeof(provider_before)) == 0);
    }

    /* provider/key partial: key starts 1 byte into provider */
    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        uint8_t *bkey;
        size_t alen = out_len_canary;
        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        fill_provider(pp, &f);
        fake_reset(&f);
        pp->ctx = &f;
        bkey = (uint8_t *)(void *)pp + 1;
        memset(out, 0xEE, sizeof(out));
        expect_status(
            "seal alias provider/key",
            ninlil_r7_crypto_aes128_gcm_seal(
                pp, bkey, nonce, aad, 8u, pt, 8u, out, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("prov/key call0", f.seal_calls == 0);
    }

    /* left partial pt/out: out starts 1 byte before end of pt */
    {
        uint8_t buf[40];
        uint8_t *bpt = buf;
        uint8_t *bout = buf + 7;
        memset(buf, 0x66, sizeof(buf));
        for (i = 0u; i < 8u; i++) {
            bpt[i] = (uint8_t)(0x10u + i);
        }
        snapshot_bytes(pt_s, bpt, 8u);
        fake_reset(&f);
        fill_provider(&p, &f);
        out_len = out_len_canary;
        expect_status(
            "seal partial left pt/out",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, bpt, 8u, bout, 24u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("partial L call0", f.seal_calls == 0);
        expect_true("partial L mut0", mem_unchanged(bpt, pt_s, 8u));
        expect_true("partial L len", out_len == out_len_canary);
    }

    /* right partial: out starts 1 inside pt */
    {
        uint8_t buf[40];
        uint8_t *bpt = buf;
        uint8_t *bout = buf + 1;
        memset(buf, 0x66, sizeof(buf));
        for (i = 0u; i < 8u; i++) {
            bpt[i] = (uint8_t)(0x20u + i);
        }
        snapshot_bytes(pt_s, bpt, 8u);
        fake_reset(&f);
        fill_provider(&p, &f);
        out_len = out_len_canary;
        expect_status(
            "seal partial right pt/out",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, bpt, 8u, bout, 24u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("partial R call0", f.seal_calls == 0);
        expect_true("partial R mut0", mem_unchanged(bpt, pt_s, 8u));
    }

    /* key/nonce exact overlap */
    {
        uint8_t buf[32];
        memset(buf, 0x11, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        memset(out, 0xEE, sizeof(out));
        out_len = out_len_canary;
        expect_status(
            "seal alias key/nonce",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, buf, buf, aad, 8u, pt, 8u, out, 24u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("key/nonce call0", f.seal_calls == 0);
    }

    /* key/aad, key/pt, nonce/pt, nonce/out, aad/pt, aad/out, aad/out_len, pt/out_len,
       key/out_len, nonce/out_len, provider with remaining */
    {
        uint8_t buf[128];
        size_t alen;
        memset(buf, 0x33, sizeof(buf));
        memset(out, 0xEE, sizeof(out));

        /* key/aad */
        fake_reset(&f);
        fill_provider(&p, &f);
        alen = out_len_canary;
        expect_status(
            "seal alias key/aad",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, buf, nonce, buf + 8, 8u, pt, 8u, out, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("key/aad call0", f.seal_calls == 0);

        /* key/pt */
        fake_reset(&f);
        fill_provider(&p, &f);
        alen = out_len_canary;
        expect_status(
            "seal alias key/pt",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, buf, nonce, aad, 8u, buf + 4, 8u, out, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("key/pt call0", f.seal_calls == 0);

        /* nonce/pt */
        fake_reset(&f);
        fill_provider(&p, &f);
        alen = out_len_canary;
        expect_status(
            "seal alias nonce/pt",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, buf, aad, 8u, buf + 6, 8u, out, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("nonce/pt call0", f.seal_calls == 0);

        /* nonce/out */
        fake_reset(&f);
        fill_provider(&p, &f);
        alen = out_len_canary;
        expect_status(
            "seal alias nonce/out",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, buf, aad, 8u, pt, 8u, buf + 4, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("nonce/out call0", f.seal_calls == 0);

        /* aad/pt */
        fake_reset(&f);
        fill_provider(&p, &f);
        alen = out_len_canary;
        expect_status(
            "seal alias aad/pt",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, buf, 8u, buf + 4, 8u, out, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("aad/pt call0", f.seal_calls == 0);

        /* aad/out */
        fake_reset(&f);
        fill_provider(&p, &f);
        alen = out_len_canary;
        expect_status(
            "seal alias aad/out",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, buf, 8u, pt, 8u, buf + 2, 24u, &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("aad/out call0", f.seal_calls == 0);

        /* pt/out_len with aligned size_t inside pt region extended */
        {
            struct size_test_storage reg;
            uint8_t *bpt = (uint8_t *)(void *)&reg;
            size_t *blen = &reg.value;
            memset(&reg, 0x40, sizeof(reg));
            reg.value = out_len_canary;
            fake_reset(&f);
            fill_provider(&p, &f);
            memset(out, 0xEE, sizeof(out));
            expect_status(
                "seal alias pt/out_len",
                ninlil_r7_crypto_aes128_gcm_seal(
                    &p, key, nonce, aad, 8u, bpt, 8u, out, 24u, blen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("pt/out_len call0", f.seal_calls == 0);
            expect_true("pt/out_len mut0", *blen == out_len_canary);
        }

        /* key/out_len */
        {
            struct size_test_storage reg;
            uint8_t *bkey = (uint8_t *)(void *)&reg;
            size_t *blen = &reg.value;
            memset(&reg, 0x10, sizeof(reg));
            reg.value = out_len_canary;
            fake_reset(&f);
            fill_provider(&p, &f);
            memset(out, 0xEE, sizeof(out));
            expect_status(
                "seal alias key/out_len",
                ninlil_r7_crypto_aes128_gcm_seal(
                    &p, bkey, nonce, aad, 8u, pt, 8u, out, 24u, blen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("key/out_len call0", f.seal_calls == 0);
        }

        /* nonce/out_len */
        {
            struct size_test_storage reg;
            uint8_t *bnonce = (uint8_t *)(void *)&reg;
            size_t *blen = &reg.value;
            memset(&reg, 0x20, sizeof(reg));
            reg.value = out_len_canary;
            fake_reset(&f);
            fill_provider(&p, &f);
            memset(out, 0xEE, sizeof(out));
            expect_status(
                "seal alias nonce/out_len",
                ninlil_r7_crypto_aes128_gcm_seal(
                    &p, key, bnonce, aad, 8u, pt, 8u, out, 24u, blen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("nonce/out_len call0", f.seal_calls == 0);
        }

        /* aad/out_len */
        {
            struct size_test_storage reg;
            uint8_t *baad = (uint8_t *)(void *)&reg;
            size_t *blen = &reg.value;
            memset(&reg, 0x30, sizeof(reg));
            reg.value = out_len_canary;
            fake_reset(&f);
            fill_provider(&p, &f);
            memset(out, 0xEE, sizeof(out));
            expect_status(
                "seal alias aad/out_len",
                ninlil_r7_crypto_aes128_gcm_seal(
                    &p, key, nonce, baad, 8u, pt, 8u, out, 24u, blen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("aad/out_len call0", f.seal_calls == 0);
        }

        /* provider/nonce, provider/aad, provider/pt, provider/out_len */
        {
            struct provider_test_storage arena;
            ninlil_r7_crypto_provider *pp;
            size_t alen2;

            memset(&arena, 0, sizeof(arena));
            pp = &arena.provider;
            fill_provider(pp, &f);
            fake_reset(&f);
            pp->ctx = &f;
            alen2 = out_len_canary;
            memset(out, 0xEE, sizeof(out));
            expect_status(
                "seal alias provider/nonce",
                ninlil_r7_crypto_aes128_gcm_seal(
                    pp, key, (uint8_t *)(void *)pp + 4, aad, 8u, pt, 8u, out, 24u, &alen2),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("prov/nonce call0", f.seal_calls == 0);

            fill_provider(pp, &f);
            fake_reset(&f);
            pp->ctx = &f;
            alen2 = out_len_canary;
            expect_status(
                "seal alias provider/aad",
                ninlil_r7_crypto_aes128_gcm_seal(
                    pp, key, nonce, (uint8_t *)(void *)pp + 4, 8u, pt, 8u, out, 24u, &alen2),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("prov/aad call0", f.seal_calls == 0);

            fill_provider(pp, &f);
            fake_reset(&f);
            pp->ctx = &f;
            alen2 = out_len_canary;
            expect_status(
                "seal alias provider/pt",
                ninlil_r7_crypto_aes128_gcm_seal(
                    pp, key, nonce, aad, 8u, (uint8_t *)(void *)pp + 4, 8u, out, 24u, &alen2),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("prov/pt call0", f.seal_calls == 0);

            {
                /* provider / out_len: size_t storage overlapping provider */
                ninlil_r7_crypto_provider prov;
                uint8_t provider_before[sizeof(prov)];
                size_t *alias_len;
                memset(&prov, 0, sizeof(prov));
                fill_provider(&prov, &f);
                fake_reset(&f);
                prov.ctx = &f;
                memcpy(provider_before, &prov, sizeof(provider_before));
                alias_len = (size_t *)(void *)((uint8_t *)(void *)&prov + sizeof(size_t));
                memset(out, 0xEE, sizeof(out));
                expect_status(
                    "seal alias provider/out_len",
                    ninlil_r7_crypto_aes128_gcm_seal(
                        &prov, key, nonce, aad, 8u, pt, 8u, out, 24u, alias_len),
                    NINLIL_R7_CRYPTO_ALIAS);
                expect_true("prov/out_len call0", f.seal_calls == 0);
                expect_true(
                    "prov/out_len provider mut0",
                    memcmp(provider_before, &prov, sizeof(provider_before)) == 0);
            }
        }
    }

    /* Adjacent provider|key allowed if end==begin */
    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        uint8_t *bkey;
        uint8_t *bnonce;
        uint8_t *baad;
        uint8_t *bpt;
        uint8_t *bout;
        size_t alen;
        size_t off;

        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        off = 0u;
        bkey = arena.tail + off;
        off += 16u;
        bnonce = arena.tail + off;
        off += 12u;
        baad = arena.tail + off;
        off += 8u;
        bpt = arena.tail + off;
        off += 8u;
        bout = arena.tail + off;
        memset(bkey, 0x10, 16u);
        memset(bnonce, 0x20, 12u);
        memset(baad, 0x30, 8u);
        memset(bpt, 0x40, 8u);
        memset(bout, 0xEE, 24u);
        fake_reset(&f);
        fill_provider(pp, &f);
        alen = out_len_canary;
        expect_status(
            "seal adj provider/key ok",
            ninlil_r7_crypto_aes128_gcm_seal(
                pp, bkey, bnonce, baad, 8u, bpt, 8u, bout, 24u, &alen),
            NINLIL_R7_CRYPTO_OK);
        expect_true("adj provider called", f.seal_calls == 1);
    }

    (void)key_s;
}

static void test_alias_pair_aead_open(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[8];
    uint8_t sealed[24];
    uint8_t out[8];
    size_t out_len;
    const size_t out_len_canary = 0x66BBu;

    memset(key, 1, sizeof(key));
    memset(nonce, 2, sizeof(nonce));
    memset(aad, 3, sizeof(aad));
    memset(sealed, 4, sizeof(sealed));
    memset(out, 0xCD, sizeof(out));

    /* exact sealed/out */
    fake_reset(&f);
    fill_provider(&p, &f);
    {
        uint8_t shared[32];
        memset(shared, 0x44, sizeof(shared));
        out_len = out_len_canary;
        expect_status(
            "open exact sealed/out",
            ninlil_r7_crypto_aes128_gcm_open(
                &p, key, nonce, NULL, 0u, shared, 24u, shared, 8u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("open exact call0", f.open_calls == 0);
        expect_true("open exact len", out_len == out_len_canary);
    }

    /* partial sealed/out */
    {
        uint8_t buf[40];
        uint8_t *bs = buf;
        uint8_t *bo = buf + 20;
        memset(buf, 0x55, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        out_len = out_len_canary;
        expect_status(
            "open partial sealed/out",
            ninlil_r7_crypto_aes128_gcm_open(
                &p, key, nonce, aad, 8u, bs, 24u, bo, 8u, &out_len),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("open partial call0", f.open_calls == 0);
    }

    /* adjacent sealed|out allowed */
    {
        uint8_t buf[24 + 8];
        memset(buf, 0x66, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        out_len = out_len_canary;
        expect_status(
            "open adj sealed/out ok",
            ninlil_r7_crypto_aes128_gcm_open(
                &p, key, nonce, NULL, 0u, buf, 24u, buf + 24, 8u, &out_len),
            NINLIL_R7_CRYPTO_OK);
        expect_true("open adj called", f.open_calls == 1);
    }

    /* provider/out, key/sealed, nonce/out, aad/sealed, out/out_len */
    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        size_t alen;

        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        fill_provider(pp, &f);
        fake_reset(&f);
        pp->ctx = &f;
        alen = out_len_canary;
        expect_status(
            "open alias provider/out",
            ninlil_r7_crypto_aes128_gcm_open(
                pp,
                key,
                nonce,
                aad,
                8u,
                sealed,
                24u,
                (uint8_t *)(void *)pp + 8,
                8u,
                &alen),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("open prov/out call0", f.open_calls == 0);

        {
            uint8_t buf[64];
            memset(buf, 0x10, sizeof(buf));
            fake_reset(&f);
            fill_provider(&p, &f);
            alen = out_len_canary;
            memset(out, 0xCD, sizeof(out));
            expect_status(
                "open alias key/sealed",
                ninlil_r7_crypto_aes128_gcm_open(
                    &p, buf, nonce, aad, 8u, buf + 4, 24u, out, 8u, &alen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("open key/sealed call0", f.open_calls == 0);
        }

        {
            uint8_t buf[64];
            memset(buf, 0x20, sizeof(buf));
            fake_reset(&f);
            fill_provider(&p, &f);
            alen = out_len_canary;
            expect_status(
                "open alias nonce/out",
                ninlil_r7_crypto_aes128_gcm_open(
                    &p, key, buf, aad, 8u, sealed, 24u, buf + 4, 8u, &alen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("open nonce/out call0", f.open_calls == 0);
        }

        {
            uint8_t buf[64];
            memset(buf, 0x30, sizeof(buf));
            fake_reset(&f);
            fill_provider(&p, &f);
            alen = out_len_canary;
            memset(out, 0xCD, sizeof(out));
            expect_status(
                "open alias aad/sealed",
                ninlil_r7_crypto_aes128_gcm_open(
                    &p, key, nonce, buf, 8u, buf + 2, 24u, out, 8u, &alen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("open aad/sealed call0", f.open_calls == 0);
        }

        {
            struct size_test_storage reg;
            uint8_t *bout = (uint8_t *)(void *)&reg;
            size_t *blen = &reg.value;
            memset(&reg, 0xCD, sizeof(reg));
            reg.value = out_len_canary;
            fake_reset(&f);
            fill_provider(&p, &f);
            expect_status(
                "open alias out/out_len",
                ninlil_r7_crypto_aes128_gcm_open(
                    &p, key, nonce, NULL, 0u, sealed, 24u, bout, 8u, blen),
                NINLIL_R7_CRYPTO_ALIAS);
            expect_true("open out/out_len call0", f.open_calls == 0);
            expect_true("open out/out_len mut0", *blen == out_len_canary);
        }
    }
}

static void test_alias_sha_hkdf(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    ninlil_r7_crypto_provider p_before;
    uint8_t dig[32];
    uint8_t prk[32];
    uint8_t okm[16];
    uint8_t salt[32];
    uint8_t ikm[32];
    uint8_t info[8];
    size_t i;

    for (i = 0u; i < 32u; i++) {
        salt[i] = (uint8_t)i;
        ikm[i] = (uint8_t)(0x80u + i);
        dig[i] = 0xAAu;
        prk[i] = 0xBBu;
    }
    memset(info, 0xCC, sizeof(info));
    memset(okm, 0xDD, sizeof(okm));

    /* sha: msg/out exact */
    fake_reset(&f);
    fill_provider(&p, &f);
    {
        uint8_t buf[64];
        memset(buf, 0xAA, sizeof(buf));
        expect_status(
            "sha alias msg/out",
            ninlil_r7_crypto_sha256(&p, buf, 32u, buf),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("sha alias call0", f.sha256_calls == 0);
    }

    /* sha: partial msg/out */
    {
        uint8_t buf[64];
        memset(buf, 0xAA, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "sha partial msg/out",
            ninlil_r7_crypto_sha256(&p, buf, 16u, buf + 8),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("sha partial call0", f.sha256_calls == 0);
    }

    /* sha: adjacent ok */
    {
        uint8_t buf[16 + 32];
        memset(buf, 0x11, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "sha adj ok",
            ninlil_r7_crypto_sha256(&p, buf, 16u, buf + 16),
            NINLIL_R7_CRYPTO_OK);
        expect_true("sha adj called", f.sha256_calls == 1);
    }

    /* sha: provider/out */
    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        fill_provider(pp, &f);
        fake_reset(&f);
        pp->ctx = &f;
        expect_status(
            "sha alias provider/out",
            ninlil_r7_crypto_sha256(pp, salt, 8u, (uint8_t *)(void *)pp + 4),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("sha prov/out call0", f.sha256_calls == 0);
    }

    /* sha: provider/msg */
    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        fill_provider(pp, &f);
        fake_reset(&f);
        pp->ctx = &f;
        expect_status(
            "sha alias provider/msg",
            ninlil_r7_crypto_sha256(pp, (uint8_t *)(void *)pp + 4, 8u, dig),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("sha prov/msg call0", f.sha256_calls == 0);
    }

    /* extract: salt/prk, ikm/prk, salt/ikm, provider pairs */
    fake_reset(&f);
    fill_provider(&p, &f);
    expect_status(
        "extract alias salt/prk",
        ninlil_r7_crypto_hkdf_extract_sha256(&p, salt, 32u, ikm, 32u, salt),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("extract salt/prk call0", f.extract_calls == 0);

    fake_reset(&f);
    fill_provider(&p, &f);
    expect_status(
        "extract alias ikm/prk",
        ninlil_r7_crypto_hkdf_extract_sha256(&p, salt, 32u, ikm, 32u, ikm),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("extract ikm/prk call0", f.extract_calls == 0);

    {
        uint8_t buf[64];
        memset(buf, 0x11, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "extract alias salt/ikm",
            ninlil_r7_crypto_hkdf_extract_sha256(&p, buf, 32u, buf + 16, 32u, prk),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("extract salt/ikm call0", f.extract_calls == 0);
    }

    /* extract adjacent salt|ikm ok */
    {
        uint8_t buf[64];
        memset(buf, 0x22, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "extract adj salt/ikm ok",
            ninlil_r7_crypto_hkdf_extract_sha256(&p, buf, 32u, buf + 32, 32u, prk),
            NINLIL_R7_CRYPTO_OK);
        expect_true("extract adj called", f.extract_calls == 1);
    }

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(&p_before, &p, sizeof(p_before));
    expect_status(
        "extract alias provider/salt",
        ninlil_r7_crypto_hkdf_extract_sha256(
            &p, (const uint8_t *)(const void *)&p, 32u, ikm, 32u, prk),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("extract prov/salt call0", f.extract_calls == 0);
    expect_true(
        "extract prov/salt provider mut0", memcmp(&p_before, &p, sizeof(p)) == 0);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(&p_before, &p, sizeof(p_before));
    expect_status(
        "extract alias provider/ikm",
        ninlil_r7_crypto_hkdf_extract_sha256(
            &p, salt, 32u, (const uint8_t *)(const void *)&p, 32u, prk),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("extract prov/ikm call0", f.extract_calls == 0);
    expect_true(
        "extract prov/ikm provider mut0", memcmp(&p_before, &p, sizeof(p)) == 0);

    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        fill_provider(pp, &f);
        fake_reset(&f);
        pp->ctx = &f;
        expect_status(
            "extract alias provider/prk",
            ninlil_r7_crypto_hkdf_extract_sha256(
                pp, salt, 32u, ikm, 32u, (uint8_t *)(void *)pp + 4),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("extract prov/prk call0", f.extract_calls == 0);
    }

    /* expand: prk/okm, info/okm, prk/info, provider pairs */
    fake_reset(&f);
    fill_provider(&p, &f);
    {
        uint8_t buf[48];
        memset(buf, 0xBB, sizeof(buf));
        expect_status(
            "expand alias prk/okm",
            ninlil_r7_crypto_hkdf_expand_sha256(&p, buf, NULL, 0u, buf, 16u),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("expand prk/okm call0", f.expand_calls == 0);
    }

    {
        uint8_t buf[32];
        memset(buf, 0xCC, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "expand alias info/okm",
            ninlil_r7_crypto_hkdf_expand_sha256(&p, prk, buf, 8u, buf + 4, 16u),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("expand info/okm call0", f.expand_calls == 0);
    }

    {
        uint8_t buf[48];
        memset(buf, 0xDD, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "expand alias prk/info",
            ninlil_r7_crypto_hkdf_expand_sha256(&p, buf, buf + 16, 8u, okm, 16u),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("expand prk/info call0", f.expand_calls == 0);
    }

    /* expand adjacent prk|okm ok */
    {
        uint8_t buf[32 + 16];
        memset(buf, 0x11, sizeof(buf));
        fake_reset(&f);
        fill_provider(&p, &f);
        expect_status(
            "expand adj prk/okm ok",
            ninlil_r7_crypto_hkdf_expand_sha256(&p, buf, NULL, 0u, buf + 32, 16u),
            NINLIL_R7_CRYPTO_OK);
        expect_true("expand adj called", f.expand_calls == 1);
    }

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(&p_before, &p, sizeof(p_before));
    expect_status(
        "expand alias provider/prk",
        ninlil_r7_crypto_hkdf_expand_sha256(
            &p, (const uint8_t *)(const void *)&p, info, 8u, okm, 16u),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("expand prov/prk call0", f.expand_calls == 0);
    expect_true(
        "expand prov/prk provider mut0", memcmp(&p_before, &p, sizeof(p)) == 0);

    fake_reset(&f);
    fill_provider(&p, &f);
    memcpy(&p_before, &p, sizeof(p_before));
    expect_status(
        "expand alias provider/info",
        ninlil_r7_crypto_hkdf_expand_sha256(
            &p, prk, (const uint8_t *)(const void *)&p, 8u, okm, 16u),
        NINLIL_R7_CRYPTO_ALIAS);
    expect_true("expand prov/info call0", f.expand_calls == 0);
    expect_true(
        "expand prov/info provider mut0", memcmp(&p_before, &p, sizeof(p)) == 0);

    {
        struct provider_test_storage arena;
        ninlil_r7_crypto_provider *pp;
        memset(&arena, 0, sizeof(arena));
        pp = &arena.provider;
        fill_provider(pp, &f);
        fake_reset(&f);
        pp->ctx = &f;
        expect_status(
            "expand alias provider/okm",
            ninlil_r7_crypto_hkdf_expand_sha256(
                pp, prk, info, 8u, (uint8_t *)(void *)pp + 4, 16u),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_true("expand prov/okm call0", f.expand_calls == 0);
    }
}

/* -------------------------------------------------------------------------- */
/* Backend failure / poison / canary                                          */
/* -------------------------------------------------------------------------- */

static void test_backend_failure_paths(void)
{
    fake_ctx f;
    ninlil_r7_crypto_provider p;
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[8];
    uint8_t pt[8];
    uint8_t sealed[24];
    uint8_t out[8];
    uint8_t sealed_canary[24];
    uint8_t out_canary[8];
    uint8_t key_s[16], nonce_s[12], aad_s[8], pt_s[8];
    size_t out_len;
    const size_t out_len_canary = 0xF00Du;
    size_t i;

    memset(key, 1, sizeof(key));
    memset(nonce, 2, sizeof(nonce));
    memset(aad, 3, sizeof(aad));
    memset(pt, 4, sizeof(pt));
    memset(sealed_canary, 0xAB, sizeof(sealed_canary));
    memset(out_canary, 0xCD, sizeof(out_canary));
    memcpy(key_s, key, 16u);
    memcpy(nonce_s, nonce, 12u);
    memcpy(aad_s, aad, 8u);
    memcpy(pt_s, pt, 8u);

    fake_reset(&f);
    fill_provider(&p, &f);
    f.seal_partial_write = 1;
    memcpy(sealed, sealed_canary, sizeof(sealed));
    out_len = out_len_canary;
    expect_status(
        "seal partial",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_BACKEND_FAILED);
    expect_true("seal partial calls", f.seal_calls == 1);
    expect_mem_eq("seal partial mut", sealed, sealed_canary, 24u);
    expect_true("seal partial len", out_len == out_len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    f.seal_unknown_result = 1;
    memcpy(sealed, sealed_canary, sizeof(sealed));
    out_len = out_len_canary;
    expect_status(
        "seal unknown",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_BACKEND_FAILED);
    expect_mem_eq("seal unknown mut", sealed, sealed_canary, 24u);
    expect_true("seal unknown len", out_len == out_len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    f.seal_result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
    memcpy(sealed, sealed_canary, sizeof(sealed));
    out_len = out_len_canary;
    expect_status(
        "seal auth result",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, NULL, 0u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_INTERNAL_CONTRACT);
    expect_mem_eq("seal auth mut", sealed, sealed_canary, 24u);

    /* poison inputs on seal: mutates copies only */
    fake_reset(&f);
    fill_provider(&p, &f);
    f.poison_inputs = 1;
    memcpy(sealed, sealed_canary, sizeof(sealed));
    out_len = out_len_canary;
    expect_status(
        "seal poison inputs",
        ninlil_r7_crypto_aes128_gcm_seal(
            &p, key, nonce, aad, 8u, pt, 8u, sealed, 24u, &out_len),
        NINLIL_R7_CRYPTO_BACKEND_FAILED);
    expect_true("seal poison calls", f.seal_calls == 1);
    expect_true("seal poison key mut0", mem_unchanged(key, key_s, 16u));
    expect_true("seal poison nonce mut0", mem_unchanged(nonce, nonce_s, 12u));
    expect_true("seal poison aad mut0", mem_unchanged(aad, aad_s, 8u));
    expect_true("seal poison pt mut0", mem_unchanged(pt, pt_s, 8u));
    expect_mem_eq("seal poison sealed mut0", sealed, sealed_canary, 24u);
    expect_true("seal poison len mut0", out_len == out_len_canary);
    expect_true("seal poison not caller key", f.seen_key != (const void *)key);
    expect_true("seal poison not caller nonce", f.seen_nonce != (const void *)nonce);
    expect_true("seal poison not caller aad", f.seen_aad != (const void *)aad);
    expect_true("seal poison not caller pt", f.seen_input != (const void *)pt);

    /* Open auth fail */
    fake_reset(&f);
    fill_provider(&p, &f);
    f.open_result = NINLIL_R7_CRYPTO_RAW_AUTH_FAILED;
    for (i = 0u; i < 8u; i++) {
        out[i] = (uint8_t)(0x90u + i);
        out_canary[i] = out[i];
    }
    for (i = 0u; i < 24u; i++) {
        sealed[i] = (uint8_t)i;
    }
    out_len = out_len_canary;
    expect_status(
        "open auth",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, sealed, 24u, out, 8u, &out_len),
        NINLIL_R7_CRYPTO_AUTH_FAILED);
    expect_true("open auth calls", f.open_calls == 1);
    expect_mem_eq("open auth prior", out, out_canary, 8u);
    expect_true("open auth len", out_len == out_len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    f.open_partial_write = 1;
    for (i = 0u; i < 8u; i++) {
        out[i] = (uint8_t)(0x90u + i);
        out_canary[i] = out[i];
    }
    out_len = out_len_canary;
    expect_status(
        "open partial",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, sealed, 24u, out, 8u, &out_len),
        NINLIL_R7_CRYPTO_BACKEND_FAILED);
    expect_mem_eq("open partial prior", out, out_canary, 8u);
    expect_true("open partial len", out_len == out_len_canary);

    fake_reset(&f);
    fill_provider(&p, &f);
    f.open_unknown_result = 1;
    for (i = 0u; i < 8u; i++) {
        out[i] = (uint8_t)(0x90u + i);
        out_canary[i] = out[i];
    }
    out_len = out_len_canary;
    expect_status(
        "open unknown",
        ninlil_r7_crypto_aes128_gcm_open(
            &p, key, nonce, NULL, 0u, sealed, 24u, out, 8u, &out_len),
        NINLIL_R7_CRYPTO_BACKEND_FAILED);
    expect_mem_eq("open unknown prior", out, out_canary, 8u);

    /* open poison */
    {
        uint8_t sealed_s[24];
        memcpy(sealed_s, sealed, 24u);
        fake_reset(&f);
        fill_provider(&p, &f);
        f.poison_inputs = 1;
        for (i = 0u; i < 8u; i++) {
            out[i] = (uint8_t)(0x90u + i);
            out_canary[i] = out[i];
        }
        out_len = out_len_canary;
        expect_status(
            "open poison",
            ninlil_r7_crypto_aes128_gcm_open(
                &p, key, nonce, aad, 8u, sealed, 24u, out, 8u, &out_len),
            NINLIL_R7_CRYPTO_BACKEND_FAILED);
        expect_true("open poison key mut0", mem_unchanged(key, key_s, 16u));
        expect_true("open poison nonce mut0", mem_unchanged(nonce, nonce_s, 12u));
        expect_true("open poison aad mut0", mem_unchanged(aad, aad_s, 8u));
        expect_true("open poison sealed mut0", mem_unchanged(sealed, sealed_s, 24u));
        expect_mem_eq("open poison out mut0", out, out_canary, 8u);
        expect_true("open poison len mut0", out_len == out_len_canary);
        expect_true("open poison not caller sealed", f.seen_input != (const void *)sealed);
    }

    /* SHA poison msg */
    {
        uint8_t msg[16];
        uint8_t msg_s[16];
        uint8_t dig[32];
        uint8_t dig_s[32];
        memset(msg, 0x11, sizeof(msg));
        memcpy(msg_s, msg, 16u);
        memset(dig, 0xAA, sizeof(dig));
        memcpy(dig_s, dig, 32u);
        fake_reset(&f);
        fill_provider(&p, &f);
        f.poison_inputs = 1;
        expect_status(
            "sha poison",
            ninlil_r7_crypto_sha256(&p, msg, 16u, dig),
            NINLIL_R7_CRYPTO_BACKEND_FAILED);
        expect_true("sha poison msg mut0", mem_unchanged(msg, msg_s, 16u));
        expect_true("sha poison dig mut0", mem_unchanged(dig, dig_s, 32u));
        expect_true("sha poison not caller", f.seen_msg != (const void *)msg);
    }

    /* HKDF extract poison */
    {
        uint8_t salt[32], ikm[32], prk[32];
        uint8_t salt_s[32], ikm_s[32], prk_s[32];
        memset(salt, 0x21, 32u);
        memset(ikm, 0x22, 32u);
        memset(prk, 0x23, 32u);
        memcpy(salt_s, salt, 32u);
        memcpy(ikm_s, ikm, 32u);
        memcpy(prk_s, prk, 32u);
        fake_reset(&f);
        fill_provider(&p, &f);
        f.poison_inputs = 1;
        expect_status(
            "extract poison",
            ninlil_r7_crypto_hkdf_extract_sha256(&p, salt, 32u, ikm, 32u, prk),
            NINLIL_R7_CRYPTO_BACKEND_FAILED);
        expect_true("extract poison salt", mem_unchanged(salt, salt_s, 32u));
        expect_true("extract poison ikm", mem_unchanged(ikm, ikm_s, 32u));
        expect_true("extract poison prk", mem_unchanged(prk, prk_s, 32u));
        expect_true("extract poison not salt", f.seen_salt != (const void *)salt);
        expect_true("extract poison not ikm", f.seen_ikm != (const void *)ikm);
    }

    /* HKDF expand poison */
    {
        uint8_t prk[32], info[8], okm[16];
        uint8_t prk_s[32], info_s[8], okm_s[16];
        memset(prk, 0x31, 32u);
        memset(info, 0x32, 8u);
        memset(okm, 0x33, 16u);
        memcpy(prk_s, prk, 32u);
        memcpy(info_s, info, 8u);
        memcpy(okm_s, okm, 16u);
        fake_reset(&f);
        fill_provider(&p, &f);
        f.poison_inputs = 1;
        expect_status(
            "expand poison",
            ninlil_r7_crypto_hkdf_expand_sha256(&p, prk, info, 8u, okm, 16u),
            NINLIL_R7_CRYPTO_BACKEND_FAILED);
        expect_true("expand poison prk", mem_unchanged(prk, prk_s, 32u));
        expect_true("expand poison info", mem_unchanged(info, info_s, 8u));
        expect_true("expand poison okm", mem_unchanged(okm, okm_s, 16u));
        expect_true("expand poison not prk", f.seen_prk != (const void *)prk);
        expect_true("expand poison not info", f.seen_info != (const void *)info);
    }

    /* Canary beyond output */
    fake_reset(&f);
    fill_provider(&p, &f);
    {
        uint8_t big[40];
        memset(big, 0x5C, sizeof(big));
        out_len = out_len_canary;
        expect_status(
            "seal canary",
            ninlil_r7_crypto_aes128_gcm_seal(
                &p, key, nonce, NULL, 0u, pt, 8u, big, 24u, &out_len),
            NINLIL_R7_CRYPTO_OK);
        expect_true("seal canary len", out_len == 24u);
        for (i = 24u; i < 40u; i++) {
            expect_true("seal canary intact", big[i] == 0x5Cu);
        }
    }

    fake_reset(&f);
    fill_provider(&p, &f);
    {
        uint8_t big[32];
        memset(big, 0x5C, sizeof(big));
        for (i = 0u; i < 24u; i++) {
            sealed[i] = (uint8_t)i;
        }
        out_len = 0u;
        expect_status(
            "open canary",
            ninlil_r7_crypto_aes128_gcm_open(
                &p, key, nonce, NULL, 0u, sealed, 24u, big, 8u, &out_len),
            NINLIL_R7_CRYPTO_OK);
        for (i = 8u; i < 32u; i++) {
            expect_true("open canary intact", big[i] == 0x5Cu);
        }
    }
}

/* -------------------------------------------------------------------------- */
/* Span overflow test seam (TEST_BUILD only)                                  */
/* -------------------------------------------------------------------------- */

static void test_spans_forbidden_seam(void)
{
    uint8_t a[8];
    uint8_t b[8];
    uint8_t adj[16];

    /* non-overlap */
    expect_true(
        "seam disjoint",
        ninlil_r7_crypto_test_spans_forbidden(a, 8u, b, 8u) == 0);

    /* exact overlap */
    expect_true(
        "seam exact",
        ninlil_r7_crypto_test_spans_forbidden(a, 8u, a, 8u) == 1);

    /* adjacent ok */
    expect_true(
        "seam adjacent",
        ninlil_r7_crypto_test_spans_forbidden(adj, 8u, adj + 8, 8u) == 0);

    /* partial */
    expect_true(
        "seam partial",
        ninlil_r7_crypto_test_spans_forbidden(adj, 8u, adj + 4, 8u) == 1);

    /* empty never aliases */
    expect_true(
        "seam empty a",
        ninlil_r7_crypto_test_spans_forbidden(a, 0u, b, 8u) == 0);
    expect_true(
        "seam empty b",
        ninlil_r7_crypto_test_spans_forbidden(a, 8u, b, 0u) == 0);

    /* uintptr overflow: len so large that base + len wraps */
    {
        const void *near_end = (const void *)(uintptr_t)(UINTPTR_MAX - 4u);
        expect_true(
            "seam overflow a",
            ninlil_r7_crypto_test_spans_forbidden(near_end, 16u, b, 8u) == 1);
        expect_true(
            "seam overflow b",
            ninlil_r7_crypto_test_spans_forbidden(a, 8u, near_end, 16u) == 1);
    }

#if SIZE_MAX > UINTPTR_MAX
    expect_true(
        "seam size wider than uintptr a",
        ninlil_r7_crypto_test_spans_forbidden(a, SIZE_MAX, b, 8u) == 1);
    expect_true(
        "seam size wider than uintptr b",
        ninlil_r7_crypto_test_spans_forbidden(a, 8u, b, SIZE_MAX) == 1);
#endif

    /* NULL non-empty treated forbidden */
    expect_true(
        "seam null nonempty",
        ninlil_r7_crypto_test_spans_forbidden(NULL, 4u, b, 8u) == 1);
}

/* -------------------------------------------------------------------------- */
/* Nonce endpoints                                                            */
/* -------------------------------------------------------------------------- */

static void test_nonce(void)
{
    uint8_t iv[12];
    uint8_t out[12];
    uint8_t expect[12];
    uint8_t canary[12];
    size_t i;
    uint64_t c;

    for (i = 0u; i < 12u; i++) {
        iv[i] = (uint8_t)(0xA0u + i);
        canary[i] = 0xFFu;
    }

    memcpy(out, canary, 12u);
    expect_status(
        "nonce c1", ninlil_r7_crypto_nonce_from_counter(iv, 1u, out), NINLIL_R7_CRYPTO_OK);
    expect[0] = iv[0];
    expect[1] = iv[1];
    expect[2] = iv[2];
    expect[3] = iv[3];
    expect[4] = (uint8_t)(iv[4] ^ 0x00u);
    expect[5] = (uint8_t)(iv[5] ^ 0x00u);
    expect[6] = (uint8_t)(iv[6] ^ 0x00u);
    expect[7] = (uint8_t)(iv[7] ^ 0x00u);
    expect[8] = (uint8_t)(iv[8] ^ 0x00u);
    expect[9] = (uint8_t)(iv[9] ^ 0x00u);
    expect[10] = (uint8_t)(iv[10] ^ 0x00u);
    expect[11] = (uint8_t)(iv[11] ^ 0x01u);
    expect_mem_eq_u8("nonce c1 bytes", out, expect, 12u);

    c = UINT64_MAX - 1u;
    memcpy(out, canary, 12u);
    expect_status(
        "nonce cmax-1", ninlil_r7_crypto_nonce_from_counter(iv, c, out), NINLIL_R7_CRYPTO_OK);
    expect[0] = iv[0];
    expect[1] = iv[1];
    expect[2] = iv[2];
    expect[3] = iv[3];
    expect[4] = (uint8_t)(iv[4] ^ 0xFFu);
    expect[5] = (uint8_t)(iv[5] ^ 0xFFu);
    expect[6] = (uint8_t)(iv[6] ^ 0xFFu);
    expect[7] = (uint8_t)(iv[7] ^ 0xFFu);
    expect[8] = (uint8_t)(iv[8] ^ 0xFFu);
    expect[9] = (uint8_t)(iv[9] ^ 0xFFu);
    expect[10] = (uint8_t)(iv[10] ^ 0xFFu);
    expect[11] = (uint8_t)(iv[11] ^ 0xFEu);
    expect_mem_eq_u8("nonce cmax-1 bytes", out, expect, 12u);

    memcpy(out, canary, 12u);
    expect_status(
        "nonce 0",
        ninlil_r7_crypto_nonce_from_counter(iv, 0u, out),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_mem_eq_u8("nonce 0 mut0", out, canary, 12u);

    memcpy(out, canary, 12u);
    expect_status(
        "nonce umax",
        ninlil_r7_crypto_nonce_from_counter(iv, UINT64_MAX, out),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_mem_eq_u8("nonce umax mut0", out, canary, 12u);

    expect_status(
        "nonce null iv",
        ninlil_r7_crypto_nonce_from_counter(NULL, 1u, out),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);
    expect_status(
        "nonce null out",
        ninlil_r7_crypto_nonce_from_counter(iv, 1u, NULL),
        NINLIL_R7_CRYPTO_INVALID_ARGUMENT);

    {
        uint8_t shared[12];
        memcpy(shared, iv, 12u);
        expect_status(
            "nonce alias",
            ninlil_r7_crypto_nonce_from_counter(shared, 1u, shared),
            NINLIL_R7_CRYPTO_ALIAS);
        expect_mem_eq_u8("nonce alias mut0", shared, iv, 12u);
    }

    {
        uint8_t pair[24];
        memcpy(pair, iv, 12u);
        memset(pair + 12, 0xFF, 12u);
        expect_status(
            "nonce adjacent",
            ninlil_r7_crypto_nonce_from_counter(pair, 1u, pair + 12),
            NINLIL_R7_CRYPTO_OK);
    }

    c = 0x0102030405060708ull;
    memcpy(out, canary, 12u);
    expect_status(
        "nonce mid", ninlil_r7_crypto_nonce_from_counter(iv, c, out), NINLIL_R7_CRYPTO_OK);
    expect[0] = iv[0];
    expect[1] = iv[1];
    expect[2] = iv[2];
    expect[3] = iv[3];
    expect[4] = (uint8_t)(iv[4] ^ 0x01u);
    expect[5] = (uint8_t)(iv[5] ^ 0x02u);
    expect[6] = (uint8_t)(iv[6] ^ 0x03u);
    expect[7] = (uint8_t)(iv[7] ^ 0x04u);
    expect[8] = (uint8_t)(iv[8] ^ 0x05u);
    expect[9] = (uint8_t)(iv[9] ^ 0x06u);
    expect[10] = (uint8_t)(iv[10] ^ 0x07u);
    expect[11] = (uint8_t)(iv[11] ^ 0x08u);
    expect_mem_eq_u8("nonce mid bytes", out, expect, 12u);
}

/* -------------------------------------------------------------------------- */
/* Closed status numeric stability                                            */
/* -------------------------------------------------------------------------- */

static void test_status_constants(void)
{
    expect_true("OK==0", NINLIL_R7_CRYPTO_OK == 0);
    expect_true("INV==1", NINLIL_R7_CRYPTO_INVALID_ARGUMENT == 1);
    expect_true("CAP==2", NINLIL_R7_CRYPTO_CAPACITY == 2);
    expect_true("ALIAS==3", NINLIL_R7_CRYPTO_ALIAS == 3);
    expect_true("AUTH==4", NINLIL_R7_CRYPTO_AUTH_FAILED == 4);
    expect_true("BACK==5", NINLIL_R7_CRYPTO_BACKEND_FAILED == 5);
    expect_true("INT==6", NINLIL_R7_CRYPTO_INTERNAL_CONTRACT == 6);
    expect_true("RAW_OK==0", NINLIL_R7_CRYPTO_RAW_OK == 0);
    expect_true("RAW_AUTH==1", NINLIL_R7_CRYPTO_RAW_AUTH_FAILED == 1);
    expect_true("RAW_BACK==2", NINLIL_R7_CRYPTO_RAW_BACKEND_FAILED == 2);
    expect_true("abi==1", NINLIL_R7_CRYPTO_PROVIDER_ABI_VERSION == 1u);
    expect_true("key16", NINLIL_R7_CRYPTO_AES128_KEY_LEN == 16u);
    expect_true("nonce12", NINLIL_R7_CRYPTO_AES128_NONCE_LEN == 12u);
    expect_true("tag16", NINLIL_R7_CRYPTO_AES128_TAG_LEN == 16u);
    expect_true("aad19", NINLIL_R7_CRYPTO_AAD_MAX == 19u);
    expect_true("body220", NINLIL_R7_CRYPTO_BODY_MAX == 220u);
    expect_true("sealed236", NINLIL_R7_CRYPTO_SEALED_MAX == 236u);
    expect_true("sha2048", NINLIL_R7_CRYPTO_SHA256_MSG_MAX == 2048u);
    expect_true("hkdf salt32", NINLIL_R7_CRYPTO_HKDF_SALT_LEN == 32u);
    expect_true("hkdf ikm32", NINLIL_R7_CRYPTO_HKDF_IKM_LEN == 32u);
    expect_true("hkdf info25", NINLIL_R7_CRYPTO_HKDF_INFO_MAX == 25u);
}

/* -------------------------------------------------------------------------- */

int main(void)
{
    g_failures = 0;
    g_tests = 0;

    test_status_constants();
    test_provider_validate();
    test_sha256_success();
    test_hkdf_success();
    test_aead_seal_open_success();
    test_produced_len_contract();
    test_prevalidation_call0();
    test_validation_priority();
    test_aead_full_alias_matrix(0);
    test_aead_full_alias_matrix(1);
    test_alias_pair_aead_seal();
    test_alias_pair_aead_open();
    test_alias_sha_hkdf();
    test_backend_failure_paths();
    test_spans_forbidden_seam();
    test_nonce();

    if (g_failures != 0) {
        fprintf(stderr, "\n%d failed / %d checks\n", g_failures, g_tests);
        return 1;
    }
    printf("OK %d checks\n", g_tests);
    return 0;
}
