/* SPDX-License-Identifier: Apache-2.0 */
#include "pa_s2_edhoc_crypto.h"

#include "edhoc.h"
#include "edhoc_values.h"

#include <stdio.h>
#include <string.h>

#define CHECK(expression) \
    do { \
        if (!(expression)) { \
            (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, \
                #expression); \
            return 0; \
        } \
    } while (0)

static int all_bytes(const void *data, size_t size, uint8_t value)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t index;

    for (index = 0u; index < size; ++index) {
        if (bytes[index] != value) {
            return 0;
        }
    }
    return 1;
}

static void dump_hex(const char *label, const uint8_t *data, size_t size)
{
    size_t index;
    (void)fprintf(stderr, "%s=", label);
    for (index = 0u; index < size; ++index) {
        (void)fprintf(stderr, "%02x", (unsigned)data[index]);
    }
    (void)fputc('\n', stderr);
}

static int nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static int decode_hex(const char *text, uint8_t *output, size_t output_size)
{
    size_t index;

    if (text == NULL || output == NULL || strlen(text) != output_size * 2u) {
        return 0;
    }
    for (index = 0u; index < output_size; ++index) {
        int high = nibble(text[index * 2u]);
        int low = nibble(text[index * 2u + 1u]);
        if (high < 0 || low < 0) {
            return 0;
        }
        output[index] = (uint8_t)((unsigned int)high * 16u + (unsigned int)low);
    }
    return 1;
}

static int init_bindings(uint32_t suite,
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner, struct edhoc_keys *keys,
    struct edhoc_crypto *crypto)
{
    struct edhoc_context context;

    (void)memset(owner, 0, sizeof(*owner));
    (void)memset(keys, 0, sizeof(*keys));
    (void)memset(crypto, 0, sizeof(*crypto));
    (void)memset(&context, 0, sizeof(context));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_begin(owner, suite)
        == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bindings(owner, keys, crypto)
        == EDHOC_SUCCESS);
    CHECK(keys->import_key != NULL && keys->destroy_key != NULL);
    CHECK(crypto->make_key_pair != NULL && crypto->key_agreement != NULL
        && crypto->signature != NULL && crypto->verify != NULL
        && crypto->extract != NULL && crypto->expand != NULL
        && crypto->encrypt != NULL && crypto->decrypt != NULL
        && crypto->hash != NULL);
    CHECK(edhoc_context_init(&context) == EDHOC_SUCCESS);
    CHECK(edhoc_set_user_context(&context, owner) == EDHOC_SUCCESS);
    CHECK(edhoc_bind_keys(&context, keys) == EDHOC_SUCCESS);
    CHECK(edhoc_bind_crypto(&context, crypto) == EDHOC_SUCCESS);
    CHECK(edhoc_context_deinit(&context) == EDHOC_SUCCESS);
    return 1;
}

static int check_unsupported_callbacks(
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const struct edhoc_keys *keys, const struct edhoc_crypto *crypto)
{
    uint8_t key_id[4] = {0xa5u, 0xa5u, 0xa5u, 0xa5u};
    uint8_t input[32];
    uint8_t first[64];
    uint8_t second[64];
    size_t first_size = 99u;
    size_t second_size = 99u;

    (void)memset(input, 0x11, sizeof(input));
    CHECK(keys->import_key(owner, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0u, key_id)
        == EDHOC_ERROR_NOT_SUPPORTED);
    CHECK(all_bytes(key_id, sizeof(key_id), 0xa5u));
    CHECK(keys->import_key(owner, EDHOC_KT_MAKE_KEY_PAIR, input,
        sizeof(input), key_id) == EDHOC_ERROR_NOT_SUPPORTED);
    CHECK(all_bytes(key_id, sizeof(key_id), 0xa5u));

    (void)memset(first, 0xa5, sizeof(first));
    (void)memset(second, 0xa5, sizeof(second));
    CHECK(crypto->make_key_pair(owner, key_id, first, 32u, &first_size,
        second, 32u, &second_size) == EDHOC_ERROR_NOT_SUPPORTED);
    CHECK(first_size == 0u && second_size == 0u);
    CHECK(all_bytes(first, 32u, 0u) && all_bytes(second, 32u, 0u));

    (void)memset(first, 0xa5, sizeof(first));
    first_size = 99u;
    CHECK(crypto->key_agreement(owner, key_id, input, sizeof(input), first,
        32u, &first_size) == EDHOC_ERROR_NOT_SUPPORTED);
    CHECK(first_size == 0u && all_bytes(first, 32u, 0u));

    (void)memset(first, 0xa5, sizeof(first));
    first_size = 99u;
    CHECK(crypto->signature(owner, key_id, input, sizeof(input), first, 64u,
        &first_size) == EDHOC_ERROR_NOT_SUPPORTED);
    CHECK(first_size == 0u && all_bytes(first, sizeof(first), 0u));
    CHECK(crypto->verify(owner, key_id, input, sizeof(input), first,
        sizeof(first)) == EDHOC_ERROR_NOT_SUPPORTED);
    (void)memset(first, 0xa5, sizeof(first));
    first_size = 99u;
    CHECK(crypto->signature(owner, key_id, input, sizeof(input), first, 65u,
        &first_size) == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(first_size == 99u && all_bytes(first, sizeof(first), 0xa5u));
    return 1;
}

static int check_hash_hkdf(ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const struct edhoc_keys *keys, const struct edhoc_crypto *crypto)
{
    static const uint8_t abc[] = {'a', 'b', 'c'};
    uint8_t digest[32];
    uint8_t expected_digest[32];
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t prk[32];
    uint8_t expected_prk[32];
    uint8_t okm[42];
    uint8_t expected_okm[42];
    uint8_t key_id[4];
    size_t produced = 0u;
    size_t index;

    CHECK(decode_hex(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        expected_digest, sizeof(expected_digest)));
    (void)memset(digest, 0xa5, sizeof(digest));
    produced = 99u;
    CHECK(crypto->hash(owner, abc, sizeof(abc), digest, sizeof(digest) - 1u,
        &produced) == EDHOC_ERROR_BUFFER_TOO_SMALL);
    CHECK(produced == 0u && all_bytes(digest, sizeof(digest), 0xa5u));
    CHECK(crypto->hash(owner, abc, sizeof(abc), digest, sizeof(digest),
        &produced) == EDHOC_SUCCESS);
    CHECK(produced == sizeof(digest)
        && memcmp(digest, expected_digest, sizeof(digest)) == 0);
    CHECK(all_bytes(owner->workspace, sizeof(owner->workspace), 0u));

    (void)memset(ikm, 0x0b, sizeof(ikm));
    for (index = 0u; index < sizeof(salt); ++index) {
        salt[index] = (uint8_t)index;
    }
    for (index = 0u; index < sizeof(info); ++index) {
        info[index] = (uint8_t)(0xf0u + index);
    }
    CHECK(decode_hex(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
        expected_prk, sizeof(expected_prk)));
    CHECK(decode_hex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865",
        expected_okm, sizeof(expected_okm)));

    CHECK(keys->import_key(owner, EDHOC_KT_EXTRACT, ikm, sizeof(ikm), key_id)
        == EDHOC_SUCCESS);
    produced = 0u;
    CHECK(crypto->extract(owner, key_id, salt, sizeof(salt), prk, sizeof(prk),
        &produced) == EDHOC_SUCCESS);
    CHECK(produced == sizeof(prk)
        && memcmp(prk, expected_prk, sizeof(prk)) == 0);
    CHECK(all_bytes(owner->workspace, sizeof(owner->workspace), 0u));
    CHECK(keys->destroy_key(owner, key_id) == EDHOC_SUCCESS);

    CHECK(keys->import_key(owner, EDHOC_KT_EXPAND, prk, sizeof(prk), key_id)
        == EDHOC_SUCCESS);
    CHECK(crypto->expand(owner, key_id, info, sizeof(info), okm, sizeof(okm))
        == EDHOC_SUCCESS);
    CHECK(memcmp(okm, expected_okm, sizeof(okm)) == 0);
    CHECK(all_bytes(owner->workspace, sizeof(owner->workspace), 0u));
    CHECK(keys->destroy_key(owner, key_id) == EDHOC_SUCCESS);
    return 1;
}

static int check_suite2(void)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    uint8_t key[16];
    uint8_t nonce[13];
    uint8_t aad[8];
    uint8_t plaintext[23];
    uint8_t expected[31];
    uint8_t sealed[31];
    uint8_t opened[23];
    uint8_t tampered[31];
    uint8_t key_id[4];
    size_t produced = 0u;
    size_t index;

    CHECK(init_bindings(NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(check_unsupported_callbacks(&owner, &keys, &crypto));
    CHECK(check_hash_hkdf(&owner, &keys, &crypto));
    for (index = 0u; index < sizeof(key); ++index) {
        key[index] = (uint8_t)(0xc0u + index);
    }
    CHECK(decode_hex("00000003020100a0a1a2a3a4a5", nonce, sizeof(nonce)));
    CHECK(decode_hex("0001020304050607", aad, sizeof(aad)));
    CHECK(decode_hex("08090a0b0c0d0e0f101112131415161718191a1b1c1d1e", plaintext,
        sizeof(plaintext)));
    CHECK(decode_hex(
        "588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0",
        expected,
        sizeof(expected)));

    CHECK(keys.import_key(&owner, EDHOC_KT_ENCRYPT, key, sizeof(key), key_id)
        == EDHOC_SUCCESS);
    (void)memset(sealed, 0xa5, sizeof(sealed));
    produced = 99u;
    CHECK(crypto.encrypt(&owner, key_id, nonce, sizeof(nonce), aad, sizeof(aad),
        plaintext, sizeof(plaintext), sealed, sizeof(sealed) - 1u, &produced)
        == EDHOC_ERROR_BUFFER_TOO_SMALL);
    CHECK(produced == 0u && all_bytes(sealed, sizeof(sealed), 0xa5u));
    CHECK(crypto.encrypt(&owner, key_id, nonce, sizeof(nonce), aad, sizeof(aad),
        plaintext, sizeof(plaintext), sealed, sizeof(sealed), &produced)
        == EDHOC_SUCCESS);
    if (produced != sizeof(sealed)
        || memcmp(sealed, expected, sizeof(sealed)) != 0) {
        dump_hex("suite2-actual", sealed, sizeof(sealed));
        dump_hex("suite2-expect", expected, sizeof(expected));
        return 0;
    }
    CHECK(all_bytes(owner.workspace, sizeof(owner.workspace), 0u));
    CHECK(keys.destroy_key(&owner, key_id) == EDHOC_SUCCESS);

    CHECK(keys.import_key(&owner, EDHOC_KT_DECRYPT, key, sizeof(key), key_id)
        == EDHOC_SUCCESS);
    (void)memset(opened, 0xa5, sizeof(opened));
    produced = 99u;
    CHECK(crypto.decrypt(&owner, key_id, nonce, sizeof(nonce), aad, sizeof(aad),
        expected, sizeof(expected), opened, sizeof(opened) - 1u, &produced)
        == EDHOC_ERROR_BUFFER_TOO_SMALL);
    CHECK(produced == 0u && all_bytes(opened, sizeof(opened), 0xa5u));
    CHECK(crypto.decrypt(&owner, key_id, nonce, sizeof(nonce), aad, sizeof(aad),
        expected, sizeof(expected), opened, sizeof(opened), &produced)
        == EDHOC_SUCCESS);
    CHECK(produced == sizeof(opened)
        && memcmp(opened, plaintext, sizeof(opened)) == 0);
    CHECK(all_bytes(owner.workspace, sizeof(owner.workspace), 0u));
    (void)memcpy(tampered, expected, sizeof(tampered));
    tampered[sizeof(tampered) - 1u] ^= 1u;
    (void)memset(opened, 0xa5, sizeof(opened));
    produced = 99u;
    CHECK(crypto.decrypt(&owner, key_id, nonce, sizeof(nonce), aad, sizeof(aad),
        tampered, sizeof(tampered), opened, sizeof(opened), &produced)
        == EDHOC_ERROR_CRYPTO_FAILURE);
    CHECK(produced == 0u && all_bytes(opened, sizeof(opened), 0xa5u));
    CHECK(all_bytes(owner.workspace, sizeof(owner.workspace), 0u));
    CHECK(keys.destroy_key(&owner, key_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner, sizeof(owner), 0u));
    return 1;
}

static int check_suite3(void)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t plaintext[114];
    uint8_t expected[130];
    uint8_t sealed[130];
    uint8_t opened[114];
    uint8_t tampered[130];
    uint8_t key_id[4];
    size_t produced = 0u;
    size_t tamper_case;

    CHECK(init_bindings(NINLIL_PA_S2_EDHOC_SUITE_3, &owner, &keys, &crypto));
    CHECK(decode_hex(
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        key, sizeof(key)));
    CHECK(decode_hex("070000004041424344454647", nonce, sizeof(nonce)));
    CHECK(decode_hex("50515253c0c1c2c3c4c5c6c7", aad, sizeof(aad)));
    CHECK(decode_hex(
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373"
        "206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c"
        "79206f6e652074697020666f7220746865206675747572652c2073756e7363726565"
        "6e20776f756c642062652069742e",
        plaintext, sizeof(plaintext)));
    CHECK(decode_hex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
        "1ae10b594f09e26a7e902ecbd0600691",
        expected, sizeof(expected)));

    CHECK(keys.import_key(&owner, EDHOC_KT_ENCRYPT, key, sizeof(key), key_id)
        == EDHOC_SUCCESS);
    CHECK(crypto.encrypt(&owner, key_id, nonce, sizeof(nonce), aad, sizeof(aad),
        plaintext, sizeof(plaintext), sealed, sizeof(sealed), &produced)
        == EDHOC_SUCCESS);
    if (produced != sizeof(sealed)
        || memcmp(sealed, expected, sizeof(sealed)) != 0) {
        dump_hex("suite3-actual", sealed, sizeof(sealed));
        dump_hex("suite3-expect", expected, sizeof(expected));
        return 0;
    }
    CHECK(keys.destroy_key(&owner, key_id) == EDHOC_SUCCESS);
    CHECK(keys.import_key(&owner, EDHOC_KT_DECRYPT, key, sizeof(key), key_id)
        == EDHOC_SUCCESS);
    CHECK(crypto.decrypt(&owner, key_id, nonce, sizeof(nonce), aad, sizeof(aad),
        expected, sizeof(expected), opened, sizeof(opened), &produced)
        == EDHOC_SUCCESS);
    CHECK(produced == sizeof(opened)
        && memcmp(opened, plaintext, sizeof(opened)) == 0);
    for (tamper_case = 0u; tamper_case < 2u; ++tamper_case) {
        (void)memcpy(tampered, expected, sizeof(tampered));
        tampered[tamper_case == 0u ? 0u : sizeof(tampered) - 1u] ^= 1u;
        (void)memset(opened, 0xa5, sizeof(opened));
        produced = 99u;
        CHECK(crypto.decrypt(&owner, key_id, nonce, sizeof(nonce), aad,
            sizeof(aad), tampered, sizeof(tampered), opened, sizeof(opened),
            &produced) == EDHOC_ERROR_CRYPTO_FAILURE);
        CHECK(produced == 0u && all_bytes(opened, sizeof(opened), 0xa5u));
        CHECK(all_bytes(owner.workspace, sizeof(owner.workspace), 0u));
    }
    CHECK(keys.destroy_key(&owner, key_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    return 1;
}

static int check_live_slot_owner_end_zeroize(void)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    uint8_t raw[32];
    uint8_t key_id[4];
    uint32_t slot;

    CHECK(init_bindings(NINLIL_PA_S2_EDHOC_SUITE_3, &owner, &keys, &crypto));
    (void)memset(raw, 0x5a, sizeof(raw));
    CHECK(keys.import_key(&owner, EDHOC_KT_ENCRYPT, raw, sizeof(raw), key_id)
        == EDHOC_SUCCESS);
    slot = (uint32_t)key_id[0] - 1u;
    CHECK(owner.key_slots[slot].live == 1u
        && memcmp(owner.key_slots[slot].bytes, raw, sizeof(raw)) == 0);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner, sizeof(owner), 0u));
    return 1;
}

static int check_key_id_rejection(void)
{
    static const uint8_t malformed[][4] = {
        {0u, 0u, 0u, 1u},
        {3u, 0u, 0u, 1u},
        {1u, 0u, 0u, 0u},
    };
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    uint8_t raw[16];
    uint8_t nonce[13];
    uint8_t plaintext[1] = {0x11u};
    uint8_t sealed[9];
    uint8_t opened[1];
    uint8_t key_id[4];
    size_t produced;
    size_t index;

    CHECK(init_bindings(NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    (void)memset(raw, 0x22, sizeof(raw));
    (void)memset(nonce, 0x33, sizeof(nonce));

    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, sizeof(raw), key_id)
        == EDHOC_SUCCESS);
    (void)memset(sealed, 0xa5, sizeof(sealed));
    produced = 99u;
    CHECK(crypto.encrypt(&owner, key_id, nonce, sizeof(nonce), NULL, 0u,
        plaintext, sizeof(plaintext), sealed, sizeof(sealed), &produced)
        == EDHOC_ERROR_BAD_STATE);
    CHECK(produced == 0u && all_bytes(sealed, sizeof(sealed), 0xa5u));
    CHECK(all_bytes(owner.workspace, sizeof(owner.workspace), 0u));
    CHECK(keys.destroy_key(&owner, key_id) == EDHOC_SUCCESS);

    CHECK(keys.import_key(&owner, EDHOC_KT_ENCRYPT, raw, sizeof(raw), key_id)
        == EDHOC_SUCCESS);
    (void)memset(opened, 0xa5, sizeof(opened));
    produced = 99u;
    CHECK(crypto.decrypt(&owner, key_id, nonce, sizeof(nonce), NULL, 0u,
        sealed, sizeof(sealed), opened, sizeof(opened), &produced)
        == EDHOC_ERROR_BAD_STATE);
    CHECK(produced == 0u && all_bytes(opened, sizeof(opened), 0xa5u));
    CHECK(all_bytes(owner.workspace, sizeof(owner.workspace), 0u));

    for (index = 0u; index < sizeof(malformed) / sizeof(malformed[0]); ++index) {
        (void)memset(sealed, 0xa5, sizeof(sealed));
        produced = 99u;
        CHECK(crypto.encrypt(&owner, malformed[index], nonce, sizeof(nonce),
            NULL, 0u, plaintext, sizeof(plaintext), sealed, sizeof(sealed),
            &produced) == EDHOC_ERROR_BAD_STATE);
        CHECK(produced == 0u && all_bytes(sealed, sizeof(sealed), 0xa5u));
        CHECK(all_bytes(owner.workspace, sizeof(owner.workspace), 0u));
    }
    CHECK(keys.destroy_key(&owner, key_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    return 1;
}

static int check_slots_and_reentry(void)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    ninlil_pa_s2_edhoc_crypto_owner_v1_t before;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    uint8_t raw[1] = {0x5au};
    uint8_t first[4];
    uint8_t second[4];
    uint8_t replacement[4];
    uint8_t rejected[4];
    uint8_t last_generation[4];
    uint32_t first_slot;

    CHECK(init_bindings(NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    (void)memset(rejected, 0xa5, sizeof(rejected));
    CHECK(keys.import_key(&owner, EDHOC_KT_ENCRYPT, raw, sizeof(raw), rejected)
        == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(all_bytes(rejected, sizeof(rejected), 0xa5u));
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, sizeof(raw), first)
        == EDHOC_SUCCESS);
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, sizeof(raw), second)
        == EDHOC_SUCCESS);
    CHECK(memcmp(first, (const uint8_t[]){1u, 0u, 0u, 1u}, sizeof(first))
        == 0);
    CHECK(memcmp(second, (const uint8_t[]){2u, 0u, 0u, 2u}, sizeof(second))
        == 0);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_begin(
        &owner, NINLIL_PA_S2_EDHOC_SUITE_3) == EDHOC_ERROR_BAD_STATE);
    CHECK(owner.active == 1u && owner.suite == NINLIL_PA_S2_EDHOC_SUITE_2);
    (void)memset(rejected, 0xa5, sizeof(rejected));
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, sizeof(raw), rejected)
        == EDHOC_ERROR_NOT_ENOUGH_MEMORY);
    CHECK(all_bytes(rejected, sizeof(rejected), 0xa5u));
    first_slot = (uint32_t)first[0] - 1u;
    CHECK(keys.destroy_key(&owner, first) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner.key_slots[first_slot],
        sizeof(owner.key_slots[first_slot]), 0u));
    CHECK(keys.import_key(
        &owner, EDHOC_KT_EXTRACT, raw, sizeof(raw), replacement)
        == EDHOC_SUCCESS);
    CHECK(memcmp(first, replacement, sizeof(first)) != 0);
    CHECK(keys.destroy_key(&owner, first) == EDHOC_ERROR_BAD_STATE);
    owner.in_call = 1u;
    (void)memset(rejected, 0xa5, sizeof(rejected));
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, sizeof(raw), rejected)
        == EDHOC_ERROR_NOT_PERMITTED);
    CHECK(all_bytes(rejected, sizeof(rejected), 0xa5u));
    before = owner;
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner)
        == EDHOC_ERROR_NOT_PERMITTED);
    CHECK(memcmp(&owner, &before, sizeof(owner)) == 0);
    owner.in_call = 0u;
    CHECK(keys.destroy_key(&owner, second) == EDHOC_SUCCESS);
    CHECK(keys.destroy_key(&owner, replacement) == EDHOC_SUCCESS);
    owner.next_generation = 0x00ffffffu;
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, sizeof(raw),
        last_generation) == EDHOC_SUCCESS);
    CHECK(memcmp(last_generation,
        (const uint8_t[]){1u, 0xffu, 0xffu, 0xffu}, sizeof(last_generation))
        == 0);
    CHECK(keys.destroy_key(&owner, last_generation) == EDHOC_SUCCESS);
    (void)memset(rejected, 0xa5, sizeof(rejected));
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, sizeof(raw), rejected)
        == EDHOC_ERROR_BAD_STATE);
    CHECK(all_bytes(rejected, sizeof(rejected), 0xa5u));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_begin(
        &owner, NINLIL_PA_S2_EDHOC_SUITE_3) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    (void)memset(&owner, 0, sizeof(owner));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_begin(&owner, 1u)
        == EDHOC_ERROR_INVALID_ARGUMENT);
    return 1;
}

static int check_alias_rejection(void)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    ninlil_pa_s2_edhoc_crypto_owner_v1_t before;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    uint8_t raw[16];
    uint8_t nonce[13];
    uint8_t buffer[64];
    uint8_t digest[32];
    uint8_t key_id[4];
    size_t produced;

    CHECK(init_bindings(NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    (void)memset(raw, 0x11, sizeof(raw));
    (void)memset(nonce, 0x22, sizeof(nonce));
    (void)memset(buffer, 0x33, sizeof(buffer));
    (void)memset(digest, 0xa5, sizeof(digest));

    before = owner;
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT, raw, 1u, &owner.active)
        == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(memcmp(&owner, &before, sizeof(owner)) == 0);

    produced = 99u;
    CHECK(crypto.hash(&owner, owner.workspace, 1u, digest, sizeof(digest),
        &produced) == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(produced == 99u && all_bytes(digest, sizeof(digest), 0xa5u));
    CHECK(memcmp(&owner, &before, sizeof(owner)) == 0);

    CHECK(keys.import_key(&owner, EDHOC_KT_ENCRYPT, raw, sizeof(raw), key_id)
        == EDHOC_SUCCESS);
    before = owner;
    produced = 99u;
    CHECK(crypto.encrypt(&owner, key_id, nonce, sizeof(nonce), NULL, 0u,
        buffer, 16u, buffer + 1u, 24u, &produced)
        == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(produced == 99u && all_bytes(buffer, sizeof(buffer), 0x33u));
    CHECK(memcmp(&owner, &before, sizeof(owner)) == 0);
    CHECK(keys.destroy_key(&owner, key_id) == EDHOC_SUCCESS);

    before = owner;
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bindings(&owner,
        (struct edhoc_keys *)(void *)owner.workspace, &crypto)
        == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(memcmp(&owner, &before, sizeof(owner)) == 0);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    return 1;
}

int main(void)
{
    if (!check_suite2() || !check_suite3() || !check_slots_and_reentry()
        || !check_alias_rejection() || !check_live_slot_owner_end_zeroize()
        || !check_key_id_rejection()) {
        return 1;
    }
    (void)puts("PA-S2a private EDHOC crypto KAT PASS; Host only");
    return 0;
}
