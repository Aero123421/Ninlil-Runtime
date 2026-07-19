/*
 * Generated R7 crypto-vector bridge.
 *
 * Executes every committed test-only vector exactly once against the real
 * OpenSSL 3 provider and the production portable wrapper/helper selected by
 * each vector's surface field.  No vector may be skipped.
 */

#include "r7_crypto_openssl3.h"
#include "private/r7_crypto_vectors.gen.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define NINLIL_R7_ARRAY_COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define NINLIL_R7_BRIDGE_BUFFER_MAX ((size_t)256u)
#define NINLIL_R7_BRIDGE_EXPECTED_OPERATIONS ((size_t)67u)

_Static_assert(
    NINLIL_R7_ARRAY_COUNT(ninlil_r7_aead_vectors) ==
        NINLIL_R7_AEAD_VECTOR_COUNT,
    "AEAD generated count mismatch");
_Static_assert(
    NINLIL_R7_ARRAY_COUNT(ninlil_r7_sha256_vectors) ==
        NINLIL_R7_SHA256_VECTOR_COUNT,
    "SHA generated count mismatch");
_Static_assert(
    NINLIL_R7_ARRAY_COUNT(ninlil_r7_hkdf_vectors) ==
        NINLIL_R7_HKDF_VECTOR_COUNT,
    "HKDF generated count mismatch");
_Static_assert(
    NINLIL_R7_ARRAY_COUNT(ninlil_r7_binding_vectors) ==
        NINLIL_R7_BINDING_VECTOR_COUNT,
    "binding generated count mismatch");
_Static_assert(
    NINLIL_R7_ARRAY_COUNT(ninlil_r7_nonce_vectors) ==
        NINLIL_R7_NONCE_VECTOR_COUNT,
    "nonce generated count mismatch");
_Static_assert(
    NINLIL_R7_AEAD_VECTOR_COUNT + NINLIL_R7_SHA256_VECTOR_COUNT +
            NINLIL_R7_HKDF_VECTOR_COUNT + NINLIL_R7_BINDING_VECTOR_COUNT +
            NINLIL_R7_NONCE_VECTOR_COUNT ==
        NINLIL_R7_TEST_VECTOR_COUNT,
    "generated total count mismatch");
_Static_assert(
    NINLIL_R7_TEST_VECTOR_COUNT == 37u,
    "reviewed R7 vector count changed");

typedef struct ninlil_r7_bridge_counters {
    size_t total;
    size_t aead;
    size_t sha256;
    size_t hkdf;
    size_t binding;
    size_t nonce;
    size_t raw_adapter;
    size_t portable_wrapper;
    size_t portable_helper;
    size_t operations;
} ninlil_r7_bridge_counters;

typedef struct ninlil_r7_bridge_seen {
    const char *ids[NINLIL_R7_TEST_VECTOR_COUNT];
    size_t count;
} ninlil_r7_bridge_seen;

static int ninlil_r7_bridge_fail(const char *id, const char *what)
{
    fprintf(stderr, "r7_crypto_vectors_bridge FAIL id=%s check=%s\n", id, what);
    return 0;
}

static int ninlil_r7_bridge_hex_nibble(char value, uint8_t *out)
{
    if (out == NULL) {
        return 0;
    }
    if (value >= '0' && value <= '9') {
        *out = (uint8_t)(value - '0');
        return 1;
    }
    if (value >= 'a' && value <= 'f') {
        *out = (uint8_t)(10 + (value - 'a'));
        return 1;
    }
    return 0;
}

/* Validate the complete string before publishing any decoded byte. */
static int ninlil_r7_bridge_decode_hex(
    const char *hex,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len)
{
    size_t chars = 0u;
    size_t i;
    uint8_t high;
    uint8_t low;

    if (hex == NULL || out == NULL || out_len == NULL ||
        out_capacity > (SIZE_MAX / 2u)) {
        return 0;
    }
    while (hex[chars] != '\0') {
        if (chars == SIZE_MAX || chars + 1u > out_capacity * 2u) {
            return 0;
        }
        chars++;
    }
    if ((chars & 1u) != 0u) {
        return 0;
    }
    for (i = 0u; i < chars; i++) {
        uint8_t unused;
        if (!ninlil_r7_bridge_hex_nibble(hex[i], &unused)) {
            return 0;
        }
    }
    for (i = 0u; i < chars / 2u; i++) {
        if (!ninlil_r7_bridge_hex_nibble(hex[i * 2u], &high) ||
            !ninlil_r7_bridge_hex_nibble(hex[i * 2u + 1u], &low)) {
            return 0;
        }
        out[i] = (uint8_t)((uint8_t)(high << 4) | low);
    }
    *out_len = chars / 2u;
    return 1;
}

static int ninlil_r7_bridge_decoder_self_test(void)
{
    uint8_t out[2] = {0xa5u, 0xa5u};
    uint8_t before[2];
    char too_long[7];
    size_t out_len = (size_t)0x5a5au;

    if (!ninlil_r7_bridge_decode_hex("00ff", out, sizeof(out), &out_len) ||
        out_len != 2u || out[0] != 0x00u || out[1] != 0xffu) {
        return ninlil_r7_bridge_fail("decoder", "valid lowercase");
    }
    memcpy(before, out, sizeof(out));
    out_len = (size_t)0x5a5au;
    if (ninlil_r7_bridge_decode_hex("0", out, sizeof(out), &out_len) ||
        out_len != (size_t)0x5a5au || memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_bridge_fail("decoder", "odd length fail closed");
    }
    if (ninlil_r7_bridge_decode_hex("0g", out, sizeof(out), &out_len) ||
        memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_bridge_fail("decoder", "invalid digit fail closed");
    }
    if (ninlil_r7_bridge_decode_hex("0A", out, sizeof(out), &out_len) ||
        memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_bridge_fail("decoder", "uppercase fail closed");
    }
    memcpy(too_long, "000000", sizeof(too_long));
    if (ninlil_r7_bridge_decode_hex(too_long, out, sizeof(out), &out_len) ||
        memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_bridge_fail("decoder", "capacity overflow fail closed");
    }
    if (ninlil_r7_bridge_decode_hex("", out, SIZE_MAX, &out_len) ||
        memcmp(out, before, sizeof(out)) != 0) {
        return ninlil_r7_bridge_fail("decoder", "size arithmetic overflow");
    }
    return 1;
}

static int ninlil_r7_bridge_record_id(
    ninlil_r7_bridge_seen *seen,
    const char *id)
{
    size_t i;

    if (seen == NULL || id == NULL || id[0] == '\0' ||
        seen->count >= NINLIL_R7_TEST_VECTOR_COUNT) {
        return ninlil_r7_bridge_fail(id == NULL ? "(null)" : id, "id shape");
    }
    for (i = 0u; i < seen->count; i++) {
        if (strcmp(seen->ids[i], id) == 0) {
            return ninlil_r7_bridge_fail(id, "duplicate execution");
        }
    }
    seen->ids[seen->count] = id;
    seen->count++;
    return 1;
}

static int ninlil_r7_bridge_all_bytes(
    const uint8_t *value,
    size_t len,
    uint8_t expected)
{
    size_t i;
    for (i = 0u; i < len; i++) {
        if (value[i] != expected) {
            return 0;
        }
    }
    return 1;
}

static int ninlil_r7_bridge_execute_aead(
    const ninlil_r7_aead_vector *vector,
    const ninlil_r7_crypto_provider *provider,
    ninlil_r7_bridge_counters *counters)
{
    uint8_t key[16];
    uint8_t nonce[12];
    uint8_t aad[20];
    uint8_t plaintext[220];
    uint8_t ciphertext[220];
    uint8_t tag[16];
    uint8_t sealed_expected[236];
    uint8_t sealed_actual[236];
    uint8_t opened[220];
    size_t key_len;
    size_t nonce_len;
    size_t aad_len;
    size_t plaintext_len;
    size_t ciphertext_len;
    size_t tag_len;
    size_t sealed_len;
    size_t produced;
    size_t i;
    int is_raw;
    int is_portable;

    is_raw = strcmp(vector->surface, "raw_adapter") == 0;
    is_portable = strcmp(vector->surface, "portable_wrapper") == 0;
    if (!is_raw && !is_portable) {
        return ninlil_r7_bridge_fail(vector->id, "unknown AEAD surface");
    }
    if (!ninlil_r7_bridge_decode_hex(vector->key, key, sizeof(key), &key_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->nonce, nonce, sizeof(nonce), &nonce_len) ||
        !ninlil_r7_bridge_decode_hex(vector->aad, aad, sizeof(aad), &aad_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->plaintext, plaintext, sizeof(plaintext), &plaintext_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->ciphertext,
            ciphertext,
            sizeof(ciphertext),
            &ciphertext_len) ||
        !ninlil_r7_bridge_decode_hex(vector->tag, tag, sizeof(tag), &tag_len)) {
        return ninlil_r7_bridge_fail(vector->id, "hex decode");
    }
    if (key_len != sizeof(key) || nonce_len != sizeof(nonce) ||
        tag_len != sizeof(tag) || ciphertext_len != plaintext_len ||
        plaintext_len > sizeof(plaintext) ||
        ciphertext_len > SIZE_MAX - tag_len) {
        return ninlil_r7_bridge_fail(vector->id, "decoded shape");
    }
    sealed_len = ciphertext_len + tag_len;
    memcpy(sealed_expected, ciphertext, ciphertext_len);
    memcpy(sealed_expected + ciphertext_len, tag, tag_len);

    if (vector->expect_ok != 0u) {
        memset(sealed_actual, 0xa5, sizeof(sealed_actual));
        produced = (size_t)0x5a5au;
        if (is_raw) {
            if (provider->aes128_gcm_seal(
                    provider->ctx,
                    key,
                    nonce,
                    aad_len == 0u ? NULL : aad,
                    aad_len,
                    plaintext_len == 0u ? NULL : plaintext,
                    plaintext_len,
                    sealed_actual,
                    sealed_len,
                    &produced) != NINLIL_R7_CRYPTO_RAW_OK) {
                return ninlil_r7_bridge_fail(vector->id, "raw seal status");
            }
        } else if (ninlil_r7_crypto_aes128_gcm_seal(
                       provider,
                       key,
                       nonce,
                       aad_len == 0u ? NULL : aad,
                       aad_len,
                       plaintext_len == 0u ? NULL : plaintext,
                       plaintext_len,
                       sealed_actual,
                       sealed_len,
                       &produced) != NINLIL_R7_CRYPTO_OK) {
            return ninlil_r7_bridge_fail(vector->id, "portable seal status");
        }
        counters->operations++;
        if (produced != sealed_len ||
            memcmp(sealed_actual, sealed_expected, sealed_len) != 0) {
            return ninlil_r7_bridge_fail(vector->id, "seal CT||TAG bytes");
        }
        if (!ninlil_r7_bridge_all_bytes(
                sealed_actual + sealed_len,
                sizeof(sealed_actual) - sealed_len,
                0xa5u)) {
            return ninlil_r7_bridge_fail(vector->id, "seal canary");
        }

        memset(opened, 0xa5, sizeof(opened));
        produced = (size_t)0x5a5au;
        if (is_raw) {
            if (provider->aes128_gcm_open(
                    provider->ctx,
                    key,
                    nonce,
                    aad_len == 0u ? NULL : aad,
                    aad_len,
                    sealed_expected,
                    sealed_len,
                    opened,
                    plaintext_len,
                    &produced) != NINLIL_R7_CRYPTO_RAW_OK) {
                return ninlil_r7_bridge_fail(vector->id, "raw open status");
            }
        } else if (ninlil_r7_crypto_aes128_gcm_open(
                       provider,
                       key,
                       nonce,
                       aad_len == 0u ? NULL : aad,
                       aad_len,
                       sealed_expected,
                       sealed_len,
                       opened,
                       plaintext_len,
                       &produced) != NINLIL_R7_CRYPTO_OK) {
            return ninlil_r7_bridge_fail(vector->id, "portable open status");
        }
        counters->operations++;
        if (produced != plaintext_len ||
            memcmp(opened, plaintext, plaintext_len) != 0) {
            return ninlil_r7_bridge_fail(vector->id, "open plaintext bytes");
        }
    } else {
        if (!is_raw) {
            return ninlil_r7_bridge_fail(vector->id, "negative surface");
        }
        memset(opened, 0xa5, sizeof(opened));
        produced = (size_t)0x5a5au;
        if (provider->aes128_gcm_open(
                provider->ctx,
                key,
                nonce,
                aad_len == 0u ? NULL : aad,
                aad_len,
                sealed_expected,
                sealed_len,
                opened,
                plaintext_len,
                &produced) != NINLIL_R7_CRYPTO_RAW_AUTH_FAILED) {
            return ninlil_r7_bridge_fail(vector->id, "raw bad-tag auth status");
        }
        counters->operations++;
        if (produced != (size_t)0x5a5au ||
            !ninlil_r7_bridge_all_bytes(opened, plaintext_len, 0u)) {
            return ninlil_r7_bridge_fail(vector->id, "raw bad-tag failure output");
        }

        memset(opened, 0xa5, sizeof(opened));
        produced = (size_t)0x5a5au;
        if (ninlil_r7_crypto_aes128_gcm_open(
                provider,
                key,
                nonce,
                aad_len == 0u ? NULL : aad,
                aad_len,
                sealed_expected,
                sealed_len,
                opened,
                plaintext_len,
                &produced) != NINLIL_R7_CRYPTO_AUTH_FAILED) {
            return ninlil_r7_bridge_fail(vector->id, "portable bad-tag auth status");
        }
        counters->operations++;
        if (produced != (size_t)0x5a5au ||
            !ninlil_r7_bridge_all_bytes(opened, sizeof(opened), 0xa5u)) {
            return ninlil_r7_bridge_fail(
                vector->id, "portable bad-tag caller mutation zero");
        }
    }

    for (i = plaintext_len; i < sizeof(opened); i++) {
        if (vector->expect_ok != 0u && opened[i] != 0xa5u) {
            return ninlil_r7_bridge_fail(vector->id, "open canary");
        }
    }
    counters->aead++;
    if (is_raw) {
        counters->raw_adapter++;
    } else {
        counters->portable_wrapper++;
    }
    return 1;
}

static int ninlil_r7_bridge_execute_sha_values(
    const char *id,
    const char *surface,
    const char *message_hex,
    const char *digest_hex,
    const ninlil_r7_crypto_provider *provider,
    ninlil_r7_bridge_counters *counters)
{
    uint8_t message[NINLIL_R7_BRIDGE_BUFFER_MAX];
    uint8_t expected[32];
    uint8_t actual[32];
    size_t message_len;
    size_t expected_len;

    if (strcmp(surface, "portable_wrapper") != 0) {
        return ninlil_r7_bridge_fail(id, "unknown SHA surface");
    }
    if (!ninlil_r7_bridge_decode_hex(
            message_hex, message, sizeof(message), &message_len) ||
        !ninlil_r7_bridge_decode_hex(
            digest_hex, expected, sizeof(expected), &expected_len) ||
        expected_len != sizeof(expected)) {
        return ninlil_r7_bridge_fail(id, "SHA hex/shape");
    }
    memset(actual, 0xa5, sizeof(actual));
    if (ninlil_r7_crypto_sha256(
            provider,
            message_len == 0u ? NULL : message,
            message_len,
            actual) != NINLIL_R7_CRYPTO_OK ||
        memcmp(actual, expected, sizeof(actual)) != 0) {
        return ninlil_r7_bridge_fail(id, "SHA wrapper result");
    }
    counters->operations++;
    counters->portable_wrapper++;
    return 1;
}

static int ninlil_r7_bridge_execute_hkdf(
    const ninlil_r7_hkdf_vector *vector,
    const ninlil_r7_crypto_provider *provider,
    ninlil_r7_bridge_counters *counters)
{
    uint8_t salt[NINLIL_R7_BRIDGE_BUFFER_MAX];
    uint8_t ikm[NINLIL_R7_BRIDGE_BUFFER_MAX];
    uint8_t info[NINLIL_R7_BRIDGE_BUFFER_MAX];
    uint8_t expected_prk[32];
    uint8_t actual_prk[32];
    uint8_t expected_okm[NINLIL_R7_BRIDGE_BUFFER_MAX];
    uint8_t actual_okm[NINLIL_R7_BRIDGE_BUFFER_MAX];
    size_t salt_len;
    size_t ikm_len;
    size_t info_len;
    size_t expected_prk_len;
    size_t expected_okm_len;
    int is_raw;
    int is_portable;

    is_raw = strcmp(vector->surface, "raw_adapter") == 0;
    is_portable = strcmp(vector->surface, "portable_wrapper") == 0;
    if (!is_raw && !is_portable) {
        return ninlil_r7_bridge_fail(vector->id, "unknown HKDF surface");
    }
    if (!ninlil_r7_bridge_decode_hex(
            vector->salt, salt, sizeof(salt), &salt_len) ||
        !ninlil_r7_bridge_decode_hex(vector->ikm, ikm, sizeof(ikm), &ikm_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->info, info, sizeof(info), &info_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->prk, expected_prk, sizeof(expected_prk), &expected_prk_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->okm, expected_okm, sizeof(expected_okm), &expected_okm_len) ||
        expected_prk_len != sizeof(expected_prk) ||
        expected_okm_len != (size_t)vector->okm_len) {
        return ninlil_r7_bridge_fail(vector->id, "HKDF hex/shape");
    }
    memset(actual_prk, 0xa5, sizeof(actual_prk));
    if (is_raw) {
        if (provider->hkdf_extract_sha256(
                provider->ctx,
                salt_len == 0u ? NULL : salt,
                salt_len,
                ikm_len == 0u ? NULL : ikm,
                ikm_len,
                actual_prk) != NINLIL_R7_CRYPTO_RAW_OK) {
            return ninlil_r7_bridge_fail(vector->id, "raw HKDF extract");
        }
    } else if (ninlil_r7_crypto_hkdf_extract_sha256(
                   provider,
                   salt,
                   salt_len,
                   ikm,
                   ikm_len,
                   actual_prk) != NINLIL_R7_CRYPTO_OK) {
        return ninlil_r7_bridge_fail(vector->id, "portable HKDF extract");
    }
    counters->operations++;
    if (memcmp(actual_prk, expected_prk, sizeof(actual_prk)) != 0) {
        return ninlil_r7_bridge_fail(vector->id, "HKDF PRK bytes");
    }

    memset(actual_okm, 0xa5, sizeof(actual_okm));
    if (is_raw) {
        if (provider->hkdf_expand_sha256(
                provider->ctx,
                actual_prk,
                info_len == 0u ? NULL : info,
                info_len,
                actual_okm,
                expected_okm_len) != NINLIL_R7_CRYPTO_RAW_OK) {
            return ninlil_r7_bridge_fail(vector->id, "raw HKDF expand");
        }
    } else if (ninlil_r7_crypto_hkdf_expand_sha256(
                   provider,
                   actual_prk,
                   info_len == 0u ? NULL : info,
                   info_len,
                   actual_okm,
                   expected_okm_len) != NINLIL_R7_CRYPTO_OK) {
        return ninlil_r7_bridge_fail(vector->id, "portable HKDF expand");
    }
    counters->operations++;
    if (memcmp(actual_okm, expected_okm, expected_okm_len) != 0 ||
        !ninlil_r7_bridge_all_bytes(
            actual_okm + expected_okm_len,
            sizeof(actual_okm) - expected_okm_len,
            0xa5u)) {
        return ninlil_r7_bridge_fail(vector->id, "HKDF OKM/canary bytes");
    }
    counters->hkdf++;
    if (is_raw) {
        counters->raw_adapter++;
    } else {
        counters->portable_wrapper++;
    }
    return 1;
}

static int ninlil_r7_bridge_execute_nonce(
    const ninlil_r7_nonce_vector *vector,
    ninlil_r7_bridge_counters *counters)
{
    uint8_t static_iv[12];
    uint8_t counter_bytes[8];
    uint8_t expected[12];
    uint8_t actual[12];
    size_t static_iv_len;
    size_t counter_len;
    size_t expected_len;
    uint64_t counter = 0u;
    size_t i;

    if (strcmp(vector->surface, "portable_helper") != 0) {
        return ninlil_r7_bridge_fail(vector->id, "unknown nonce surface");
    }
    if (!ninlil_r7_bridge_decode_hex(
            vector->static_iv, static_iv, sizeof(static_iv), &static_iv_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->counter, counter_bytes, sizeof(counter_bytes), &counter_len) ||
        !ninlil_r7_bridge_decode_hex(
            vector->nonce, expected, sizeof(expected), &expected_len) ||
        static_iv_len != sizeof(static_iv) ||
        counter_len != sizeof(counter_bytes) || expected_len != sizeof(expected)) {
        return ninlil_r7_bridge_fail(vector->id, "nonce hex/shape");
    }
    for (i = 0u; i < sizeof(counter_bytes); i++) {
        counter = (counter << 8) | (uint64_t)counter_bytes[i];
    }
    memset(actual, 0xa5, sizeof(actual));
    if (ninlil_r7_crypto_nonce_from_counter(static_iv, counter, actual) !=
            NINLIL_R7_CRYPTO_OK ||
        memcmp(actual, expected, sizeof(actual)) != 0) {
        return ninlil_r7_bridge_fail(vector->id, "nonce helper result");
    }
    counters->operations++;
    counters->nonce++;
    counters->portable_helper++;
    return 1;
}

static int ninlil_r7_bridge_check_final(
    const ninlil_r7_bridge_seen *seen,
    const ninlil_r7_bridge_counters *counters)
{
    if (seen->count != NINLIL_R7_TEST_VECTOR_COUNT ||
        counters->total != NINLIL_R7_TEST_VECTOR_COUNT ||
        counters->aead != NINLIL_R7_AEAD_VECTOR_COUNT ||
        counters->sha256 != NINLIL_R7_SHA256_VECTOR_COUNT ||
        counters->hkdf != NINLIL_R7_HKDF_VECTOR_COUNT ||
        counters->binding != NINLIL_R7_BINDING_VECTOR_COUNT ||
        counters->nonce != NINLIL_R7_NONCE_VECTOR_COUNT ||
        counters->raw_adapter != 6u || counters->portable_wrapper != 29u ||
        counters->portable_helper != 2u ||
        counters->operations != NINLIL_R7_BRIDGE_EXPECTED_OPERATIONS) {
        return ninlil_r7_bridge_fail("summary", "exact execution counters");
    }
    return 1;
}

int main(void)
{
    ninlil_r7_crypto_provider provider;
    ninlil_r7_bridge_counters counters = {0};
    ninlil_r7_bridge_seen seen = {{0}, 0u};
    size_t i;

    if (!ninlil_r7_bridge_decoder_self_test()) {
        return 1;
    }
    if (ninlil_r7_crypto_openssl3_provider_init(&provider) !=
            NINLIL_R7_CRYPTO_OK ||
        ninlil_r7_crypto_provider_validate(&provider) != NINLIL_R7_CRYPTO_OK) {
        ninlil_r7_bridge_fail("provider", "OpenSSL 3 init");
        return 1;
    }

    for (i = 0u; i < NINLIL_R7_AEAD_VECTOR_COUNT; i++) {
        if (!ninlil_r7_bridge_record_id(&seen, ninlil_r7_aead_vectors[i].id) ||
            !ninlil_r7_bridge_execute_aead(
                &ninlil_r7_aead_vectors[i], &provider, &counters)) {
            return 1;
        }
        counters.total++;
    }
    for (i = 0u; i < NINLIL_R7_SHA256_VECTOR_COUNT; i++) {
        if (!ninlil_r7_bridge_record_id(&seen, ninlil_r7_sha256_vectors[i].id) ||
            !ninlil_r7_bridge_execute_sha_values(
                ninlil_r7_sha256_vectors[i].id,
                ninlil_r7_sha256_vectors[i].surface,
                ninlil_r7_sha256_vectors[i].message,
                ninlil_r7_sha256_vectors[i].digest,
                &provider,
                &counters)) {
            return 1;
        }
        counters.sha256++;
        counters.total++;
    }
    for (i = 0u; i < NINLIL_R7_HKDF_VECTOR_COUNT; i++) {
        if (!ninlil_r7_bridge_record_id(&seen, ninlil_r7_hkdf_vectors[i].id) ||
            !ninlil_r7_bridge_execute_hkdf(
                &ninlil_r7_hkdf_vectors[i], &provider, &counters)) {
            return 1;
        }
        counters.total++;
    }
    for (i = 0u; i < NINLIL_R7_BINDING_VECTOR_COUNT; i++) {
        if (!ninlil_r7_bridge_record_id(&seen, ninlil_r7_binding_vectors[i].id) ||
            !ninlil_r7_bridge_execute_sha_values(
                ninlil_r7_binding_vectors[i].id,
                ninlil_r7_binding_vectors[i].surface,
                ninlil_r7_binding_vectors[i].input,
                ninlil_r7_binding_vectors[i].digest,
                &provider,
                &counters)) {
            return 1;
        }
        counters.binding++;
        counters.total++;
    }
    for (i = 0u; i < NINLIL_R7_NONCE_VECTOR_COUNT; i++) {
        if (!ninlil_r7_bridge_record_id(&seen, ninlil_r7_nonce_vectors[i].id) ||
            !ninlil_r7_bridge_execute_nonce(
                &ninlil_r7_nonce_vectors[i], &counters)) {
            return 1;
        }
        counters.total++;
    }

    if (!ninlil_r7_bridge_check_final(&seen, &counters)) {
        return 1;
    }
    printf(
        "r7_crypto_vectors_bridge OK total=%zu aead=%zu sha256=%zu hkdf=%zu "
        "binding=%zu nonce=%zu raw=%zu portable=%zu helper=%zu operations=%zu\n",
        counters.total,
        counters.aead,
        counters.sha256,
        counters.hkdf,
        counters.binding,
        counters.nonce,
        counters.raw_adapter,
        counters.portable_wrapper,
        counters.portable_helper,
        counters.operations);
    return 0;
}
