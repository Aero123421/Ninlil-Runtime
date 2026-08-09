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

#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
#define TEST_ENTROPY_DRAWS ((size_t)24u)

typedef struct test_entropy {
    ninlil_entropy_ops_t ops;
    uint8_t bytes[TEST_ENTROPY_DRAWS][32];
    ninlil_port_status_t status[TEST_ENTROPY_DRAWS];
    uint32_t prefix[TEST_ENTROPY_DRAWS];
    size_t count;
    size_t next;
    ninlil_pa_s2_edhoc_crypto_owner_v1_t *reentry_owner;
    const struct edhoc_keys *reentry_keys;
    size_t reentry_draw;
    int reentry_status;
} test_entropy_t;

static ninlil_port_status_t test_entropy_fill(
    void *context, uint8_t *output, uint32_t length)
{
    test_entropy_t *entropy = (test_entropy_t *)context;
    size_t draw;
    uint8_t key_id[4] = {0u};
    uint8_t raw = 0x5au;

    if (entropy == NULL || output == NULL || length != 32u
        || entropy->next >= entropy->count) {
        return NINLIL_PORT_PERMANENT_FAILURE;
    }
    draw = entropy->next++;
    if (entropy->reentry_owner != NULL && entropy->reentry_keys != NULL
        && draw == entropy->reentry_draw) {
        entropy->reentry_status = entropy->reentry_keys->import_key(
            entropy->reentry_owner, EDHOC_KT_EXTRACT,
            &raw, sizeof(raw), key_id);
    }
    if (entropy->prefix[draw] != 0u) {
        (void)memcpy(output, entropy->bytes[draw], entropy->prefix[draw]);
    }
    return entropy->status[draw];
}

static void test_entropy_init(test_entropy_t *entropy)
{
    (void)memset(entropy, 0, sizeof(*entropy));
    entropy->ops.abi_version = NINLIL_ABI_VERSION;
    entropy->ops.struct_size = (uint16_t)sizeof(entropy->ops);
    entropy->ops.user = entropy;
    entropy->ops.fill = test_entropy_fill;
    entropy->reentry_status = EDHOC_SUCCESS;
}

static int test_entropy_add(test_entropy_t *entropy,
    const uint8_t bytes[32], ninlil_port_status_t status, uint32_t prefix)
{
    if (entropy == NULL || entropy->count >= TEST_ENTROPY_DRAWS
        || prefix > 32u) {
        return 0;
    }
    if (bytes != NULL) {
        (void)memcpy(entropy->bytes[entropy->count], bytes, 32u);
    }
    entropy->status[entropy->count] = status;
    entropy->prefix[entropy->count] = prefix;
    entropy->count += 1u;
    return 1;
}
#endif

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
#if !defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    || !NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    uint8_t second[64];
#endif
    size_t first_size = 99u;
#if !defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    || !NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    size_t second_size = 99u;
#endif

    (void)memset(input, 0x11, sizeof(input));
#if !defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    || !NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
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
#else
    CHECK(keys->import_key(owner, EDHOC_KT_MAKE_KEY_PAIR, NULL, 0u, key_id)
        == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(all_bytes(key_id, sizeof(key_id), 0xa5u));
#endif

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

#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
static int check_p256_role(const char *scalar_hex, const char *token_hex,
    const char *public_hex, const char *first_peer_hex,
    const char *first_shared_hex, const char *second_peer_hex,
    const char *second_shared_hex)
{
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    test_entropy_t entropy;
    uint8_t scalar[32];
    uint8_t token[32];
    uint8_t expected_public[32];
    uint8_t first_peer[32];
    uint8_t expected_first[32];
    uint8_t second_peer[32];
    uint8_t expected_second[32];
    uint8_t private_output[48];
    uint8_t public_output[32];
    uint8_t shared[32];
    uint8_t make_id[4];
    uint8_t first_id[4];
    uint8_t second_id[4];
    uint8_t rejected_id[4];
    uint32_t make_slot;
    uint32_t backing_slot;
    size_t private_size = 0u;
    size_t public_size = 0u;
    size_t shared_size = 0u;

    CHECK(decode_hex(scalar_hex, scalar, sizeof(scalar))
        && decode_hex(token_hex, token, sizeof(token))
        && decode_hex(public_hex, expected_public, sizeof(expected_public))
        && decode_hex(first_peer_hex, first_peer, sizeof(first_peer))
        && decode_hex(first_shared_hex, expected_first, sizeof(expected_first))
        && decode_hex(second_peer_hex, second_peer, sizeof(second_peer))
        && decode_hex(second_shared_hex, expected_second,
            sizeof(expected_second)));
    test_entropy_init(&entropy);
    CHECK(test_entropy_add(
        &entropy, scalar, NINLIL_PORT_OK, (uint32_t)sizeof(scalar)));
    CHECK(test_entropy_add(
        &entropy, token, NINLIL_PORT_OK, (uint32_t)sizeof(token)));
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_ERROR_BAD_STATE);
    (void)memset(rejected_id, 0xa5, sizeof(rejected_id));
    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        token, sizeof(token), rejected_id) == EDHOC_ERROR_BAD_STATE);
    CHECK(all_bytes(rejected_id, sizeof(rejected_id), 0xa5u));

    CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    (void)memset(private_output, 0xa5, sizeof(private_output));
    (void)memset(public_output, 0xa5, sizeof(public_output));
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, sizeof(private_output), &private_size,
        public_output, sizeof(public_output), &public_size) == EDHOC_SUCCESS);
    CHECK(private_size == 32u && public_size == 32u && entropy.next == 2u);
    CHECK(memcmp(private_output, token, sizeof(token)) == 0
        && all_bytes(private_output + 32u, 16u, 0u)
        && memcmp(private_output, scalar, sizeof(scalar)) != 0
        && memcmp(public_output, expected_public, sizeof(public_output)) == 0);
    make_slot = (uint32_t)make_id[0] - 1u;
    backing_slot = make_slot == 0u ? 1u : 0u;
    CHECK(owner.key_slots[backing_slot].live == 1u
        && owner.key_slots[backing_slot].bytes_used == 64u
        && memcmp(owner.key_slots[backing_slot].bytes,
            scalar, sizeof(scalar)) == 0
        && memcmp(owner.key_slots[backing_slot].bytes + 32u,
            token, sizeof(token)) == 0);
    (void)memset(shared, 0xa5, sizeof(shared));
    shared_size = 99u;
    CHECK(crypto.key_agreement(&owner, make_id, first_peer,
        sizeof(first_peer), shared, sizeof(shared), &shared_size)
        == EDHOC_ERROR_BAD_STATE);
    CHECK(shared_size == 0u && all_bytes(shared, sizeof(shared), 0u));
    CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner.key_slots[make_slot],
        sizeof(owner.key_slots[make_slot]), 0u));

    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        token, sizeof(token), first_id) == EDHOC_SUCCESS);
    (void)memset(rejected_id, 0xa5, sizeof(rejected_id));
    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        token, sizeof(token), rejected_id) == EDHOC_ERROR_BAD_STATE);
    CHECK(all_bytes(rejected_id, sizeof(rejected_id), 0xa5u));
    (void)memset(shared, 0xa5, sizeof(shared));
    shared_size = 99u;
    CHECK(crypto.key_agreement(&owner, first_id, first_peer,
        sizeof(first_peer), shared, sizeof(shared), &shared_size)
        == EDHOC_SUCCESS);
    CHECK(shared_size == sizeof(shared)
        && memcmp(shared, expected_first, sizeof(shared)) == 0);
    CHECK(keys.destroy_key(&owner, first_id) == EDHOC_SUCCESS);
    CHECK(owner.key_slots[backing_slot].live == 1u
        && owner.key_slots[backing_slot].use_count == 1u
        && owner.key_slots[backing_slot].operation_live == 0u);
    (void)memset(shared, 0xa5, sizeof(shared));
    shared_size = 99u;
    CHECK(crypto.key_agreement(&owner, first_id, first_peer,
        sizeof(first_peer), shared, sizeof(shared), &shared_size)
        == EDHOC_ERROR_BAD_STATE);
    CHECK(shared_size == 0u && all_bytes(shared, sizeof(shared), 0u));

    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        token, sizeof(token), second_id) == EDHOC_SUCCESS);
    CHECK(memcmp(first_id, second_id, sizeof(first_id)) != 0);
    CHECK(crypto.key_agreement(&owner, second_id, second_peer,
        sizeof(second_peer), shared, sizeof(shared), &shared_size)
        == EDHOC_SUCCESS);
    CHECK(shared_size == sizeof(shared)
        && memcmp(shared, expected_second, sizeof(shared)) == 0);
    CHECK(keys.destroy_key(&owner, second_id) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner.key_slots[backing_slot],
        sizeof(owner.key_slots[backing_slot]), 0u));
    (void)memset(rejected_id, 0xa5, sizeof(rejected_id));
    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        token, sizeof(token), rejected_id) == EDHOC_ERROR_BAD_STATE);
    CHECK(all_bytes(rejected_id, sizeof(rejected_id), 0xa5u));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner, sizeof(owner), 0u));
    return 1;
}

static int check_p256_method3_kat(void)
{
    CHECK(check_p256_role(
        "368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525",
        "a10102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6",
        "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5",
        "2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba",
        "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0",
        "f2b6eea02220b95eee5a0bc701f074e00a843ea02422f60825fb269b3e161423"));
    CHECK(check_p256_role(
        "e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418",
        "b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "419701d7f00a26c2dc587a36dd752549f33763c893422c8ea0f955a13a4ff5d5",
        "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6",
        "2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba",
        "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6",
        "080f425085bc6249089eac8f108ea62326857e12ab07d72028ca1b5f36e004b3"));
    return 1;
}

static int make_ephemeral(ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    struct edhoc_keys *keys, struct edhoc_crypto *crypto,
    test_entropy_t *entropy, const uint8_t scalar[32], const uint8_t token[32],
    uint8_t make_id[4], uint8_t returned_token[32])
{
    uint8_t public_x[32];
    size_t token_size = 0u;
    size_t public_size = 0u;

    test_entropy_init(entropy);
    CHECK(test_entropy_add(entropy, scalar, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(entropy, token, NINLIL_PORT_OK, 32u));
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, owner, keys, crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        owner, &entropy->ops) == EDHOC_SUCCESS);
    CHECK(keys->import_key(owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    CHECK(crypto->make_key_pair(owner, make_id,
        returned_token, 32u, &token_size,
        public_x, sizeof(public_x), &public_size) == EDHOC_SUCCESS);
    CHECK(token_size == 32u && public_size == 32u);
    CHECK(keys->destroy_key(owner, make_id) == EDHOC_SUCCESS);
    return 1;
}

static int check_invalid_peer_case(const uint8_t peer_x[32])
{
    static const uint8_t scalar[32] = {
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
    };
    static const uint8_t token[32] = {
        0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u,
        0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u,
        0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u,
        0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u, 0x55u,
    };
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    test_entropy_t entropy;
    uint8_t make_id[4];
    uint8_t operation_id[4];
    uint8_t returned_token[32];
    uint8_t shared[32];
    uint8_t rejected[4];
    uint32_t backing_slot;
    size_t shared_size = 99u;

    CHECK(make_ephemeral(&owner, &keys, &crypto, &entropy,
        scalar, token, make_id, returned_token));
    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        returned_token, sizeof(returned_token), operation_id) == EDHOC_SUCCESS);
    backing_slot = (uint32_t)make_id[0] == 1u ? 1u : 0u;
    (void)memset(shared, 0xa5, sizeof(shared));
    CHECK(crypto.key_agreement(&owner, operation_id, peer_x, 32u,
        shared, sizeof(shared), &shared_size) == EDHOC_ERROR_CRYPTO_FAILURE);
    CHECK(shared_size == 0u && all_bytes(shared, sizeof(shared), 0u));
    CHECK(all_bytes(&owner.key_slots[backing_slot],
        sizeof(owner.key_slots[backing_slot]), 0u));
    CHECK(keys.destroy_key(&owner, operation_id) == EDHOC_ERROR_BAD_STATE);
    (void)memset(rejected, 0xa5, sizeof(rejected));
    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        returned_token, sizeof(returned_token), rejected)
        == EDHOC_ERROR_BAD_STATE);
    CHECK(all_bytes(rejected, sizeof(rejected), 0xa5u));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    return 1;
}

static int check_p256_invalid_points(void)
{
    uint8_t prime[32];
    uint8_t noncurve[32] = {0u};

    CHECK(decode_hex(
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        prime, sizeof(prime)));
    noncurve[31] = 1u;
    CHECK(check_invalid_peer_case(prime));
    CHECK(check_invalid_peer_case(noncurve));
    return 1;
}

static int check_p256_operation_reuse(void)
{
    static const uint8_t scalar[32] = {
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u,
    };
    static const uint8_t token[32] = {
        0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
        0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
        0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
        0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u, 0x66u,
    };
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    test_entropy_t entropy;
    uint8_t make_id[4];
    uint8_t operation_id[4];
    uint8_t returned_token[32];
    uint8_t peer_x[32];
    uint8_t shared[32];
    uint8_t alias[32];
    ninlil_pa_s2_edhoc_crypto_owner_v1_t before;
    size_t shared_size = 0u;

    CHECK(decode_hex(
        "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6",
        peer_x, sizeof(peer_x)));
    CHECK(make_ephemeral(&owner, &keys, &crypto, &entropy,
        scalar, token, make_id, returned_token));
    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        returned_token, sizeof(returned_token), operation_id) == EDHOC_SUCCESS);
    (void)memcpy(alias, operation_id, sizeof(operation_id));
    before = owner;
    (void)memset(shared, 0xa5, sizeof(shared));
    shared_size = 99u;
    CHECK(crypto.key_agreement(&owner, alias, alias, sizeof(alias),
        shared, sizeof(shared), &shared_size) == EDHOC_ERROR_INVALID_ARGUMENT);
    CHECK(shared_size == 99u && all_bytes(shared, sizeof(shared), 0xa5u)
        && memcmp(&owner, &before, sizeof(owner)) == 0);
    CHECK(crypto.key_agreement(&owner, operation_id, peer_x, sizeof(peer_x),
        shared, sizeof(shared) - 1u, &shared_size)
        == EDHOC_ERROR_BUFFER_TOO_SMALL);
    CHECK(shared_size == 99u && all_bytes(shared, sizeof(shared), 0xa5u)
        && memcmp(&owner, &before, sizeof(owner)) == 0);
    CHECK(crypto.key_agreement(&owner, operation_id, peer_x, sizeof(peer_x),
        shared, sizeof(shared), &shared_size) == EDHOC_SUCCESS);
    (void)memset(shared, 0xa5, sizeof(shared));
    shared_size = 99u;
    CHECK(crypto.key_agreement(&owner, operation_id, peer_x, sizeof(peer_x),
        shared, sizeof(shared), &shared_size) == EDHOC_ERROR_BAD_STATE);
    CHECK(shared_size == 0u && all_bytes(shared, sizeof(shared), 0u));
    CHECK(keys.destroy_key(&owner, operation_id) == EDHOC_ERROR_BAD_STATE);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner, sizeof(owner), 0u));
    return 1;
}

static uint32_t generation_from_key_id(const uint8_t key_id[4])
{
    return ((uint32_t)key_id[1] << 16u)
        | ((uint32_t)key_id[2] << 8u) | (uint32_t)key_id[3];
}

static int agree_and_destroy(ninlil_pa_s2_edhoc_crypto_owner_v1_t *owner,
    const struct edhoc_keys *keys, const struct edhoc_crypto *crypto,
    const uint8_t token[32], const uint8_t peer_x[32],
    uint32_t expected_generation)
{
    uint8_t operation_id[4];
    uint8_t shared[32];
    size_t shared_size = 0u;

    CHECK(keys->import_key(owner, EDHOC_KT_KEY_AGREEMENT,
        token, 32u, operation_id) == EDHOC_SUCCESS);
    CHECK(generation_from_key_id(operation_id) == expected_generation);
    CHECK(crypto->key_agreement(owner, operation_id, peer_x, 32u,
        shared, sizeof(shared), &shared_size) == EDHOC_SUCCESS);
    CHECK(shared_size == sizeof(shared));
    CHECK(keys->destroy_key(owner, operation_id) == EDHOC_SUCCESS);
    return 1;
}

static int check_p256_generation_reservation(void)
{
    uint8_t scalar[32] = {0u};
    uint8_t token[32];
    uint8_t peer_x[32];
    uint8_t make_id[4];
    uint8_t returned_token[32];
    uint8_t unrelated_id[4];
    uint8_t unrelated_raw = 0x5au;
    uint8_t private_output[48];
    uint8_t public_output[32];
    size_t private_size = 0u;
    size_t public_size = 0u;
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    test_entropy_t entropy;

    scalar[31] = 1u;
    (void)memset(token, 0x44, sizeof(token));
    CHECK(decode_hex(
        "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6",
        peer_x, sizeof(peer_x)));

    CHECK(make_ephemeral(&owner, &keys, &crypto, &entropy,
        scalar, token, make_id, returned_token));
    CHECK(owner.next_generation == 5u);
    CHECK(agree_and_destroy(
        &owner, &keys, &crypto, returned_token, peer_x, 3u));
    CHECK(keys.import_key(&owner, EDHOC_KT_EXTRACT,
        &unrelated_raw, sizeof(unrelated_raw), unrelated_id) == EDHOC_SUCCESS);
    CHECK(generation_from_key_id(unrelated_id) == 5u);
    CHECK(agree_and_destroy(
        &owner, &keys, &crypto, returned_token, peer_x, 4u));
    CHECK(keys.destroy_key(&owner, unrelated_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);

    test_entropy_init(&entropy);
    CHECK(test_entropy_add(&entropy, scalar, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(&entropy, token, NINLIL_PORT_OK, 32u));
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_SUCCESS);
    owner.next_generation = 0x00fffffcu;
    CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, sizeof(private_output), &private_size,
        public_output, sizeof(public_output), &public_size) == EDHOC_SUCCESS);
    CHECK(owner.next_generation == 0u && private_size == 32u
        && public_size == 32u);
    CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
    CHECK(agree_and_destroy(&owner, &keys, &crypto,
        private_output, peer_x, 0x00fffffeu));
    CHECK(agree_and_destroy(&owner, &keys, &crypto,
        private_output, peer_x, 0x00ffffffu));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    return 1;
}

static int check_p256_generation_exhaustion(void)
{
    static const uint32_t starts[] = {
        0x00fffffdu, 0x00fffffeu, 0x00ffffffu,
    };
    uint8_t scalar[32] = {0u};
    uint8_t token[32];
    size_t index;

    scalar[31] = 1u;
    (void)memset(token, 0x77, sizeof(token));
    for (index = 0u; index < sizeof(starts) / sizeof(starts[0]); ++index) {
        ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
        struct edhoc_keys keys;
        struct edhoc_crypto crypto;
        test_entropy_t entropy;
        uint8_t make_id[4];
        uint8_t private_output[48];
        uint8_t public_output[32];
        size_t private_size = 99u;
        size_t public_size = 99u;

        test_entropy_init(&entropy);
        CHECK(test_entropy_add(&entropy, scalar, NINLIL_PORT_OK, 32u));
        CHECK(test_entropy_add(&entropy, token, NINLIL_PORT_OK, 32u));
        CHECK(init_bindings(
            NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
        CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
            &owner, &entropy.ops) == EDHOC_SUCCESS);
        owner.next_generation = starts[index];
        CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
            NULL, 0u, make_id) == EDHOC_SUCCESS);
        (void)memset(private_output, 0xa5, sizeof(private_output));
        (void)memset(public_output, 0xa5, sizeof(public_output));
        CHECK(crypto.make_key_pair(&owner, make_id,
            private_output, sizeof(private_output), &private_size,
            public_output, sizeof(public_output), &public_size)
            == EDHOC_ERROR_BAD_STATE);
        CHECK(entropy.next == 0u && private_size == 0u && public_size == 0u
            && all_bytes(private_output, sizeof(private_output), 0u)
            && all_bytes(public_output, sizeof(public_output), 0u));
        CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
        CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner)
            == EDHOC_SUCCESS);
    }
    return 1;
}

static int check_p256_entropy_capacity(void)
{
    uint8_t zero[32] = {0u};
    uint8_t order[32];
    uint8_t scalar[32];
    uint8_t token[32];
    uint8_t make_id[4];
    uint8_t private_output[48];
    uint8_t public_output[32];
    size_t private_size;
    size_t public_size;
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    test_entropy_t entropy;

    CHECK(decode_hex(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        order, sizeof(order)));
    (void)memset(scalar, 0u, sizeof(scalar));
    scalar[31] = 1u;
    (void)memset(token, 0x77, sizeof(token));
    test_entropy_init(&entropy);
    CHECK(test_entropy_add(&entropy, zero, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(&entropy, order, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(&entropy, scalar, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(&entropy, zero, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(&entropy, scalar, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(&entropy, token, NINLIL_PORT_OK, 32u));
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_SUCCESS);
    CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    (void)memset(private_output, 0xa5, sizeof(private_output));
    (void)memset(public_output, 0xa5, sizeof(public_output));
    private_size = 99u;
    public_size = 99u;
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, 31u, &private_size,
        public_output, sizeof(public_output), &public_size)
        == EDHOC_ERROR_BUFFER_TOO_SMALL);
    CHECK(private_size == 99u && public_size == 99u && entropy.next == 0u
        && all_bytes(private_output, sizeof(private_output), 0xa5u)
        && all_bytes(public_output, sizeof(public_output), 0xa5u));
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, sizeof(private_output), &private_size,
        public_output, sizeof(public_output), &public_size) == EDHOC_SUCCESS);
    CHECK(entropy.next == 6u && private_size == 32u && public_size == 32u
        && memcmp(private_output, token, sizeof(token)) == 0);
    CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    return 1;
}

static int check_p256_entropy_failure(void)
{
    uint8_t scalar[32] = {0u};
    uint8_t partial[32];
    uint8_t make_id[4];
    uint8_t private_output[48];
    uint8_t public_output[32];
    size_t private_size = 99u;
    size_t public_size = 99u;
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    test_entropy_t entropy;

    scalar[31] = 1u;
    (void)memset(partial, 0x88, sizeof(partial));
    test_entropy_init(&entropy);
    {
        uint8_t zero[32] = {0u};
        size_t attempt;
        for (attempt = 0u; attempt < 8u; ++attempt) {
            CHECK(test_entropy_add(
                &entropy, zero, NINLIL_PORT_OK, 32u));
        }
    }
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_SUCCESS);
    CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    (void)memset(private_output, 0xa5, sizeof(private_output));
    (void)memset(public_output, 0xa5, sizeof(public_output));
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, sizeof(private_output), &private_size,
        public_output, sizeof(public_output), &public_size)
        == EDHOC_ERROR_CRYPTO_FAILURE);
    CHECK(entropy.next == 8u && private_size == 0u && public_size == 0u
        && all_bytes(private_output, sizeof(private_output), 0u)
        && all_bytes(public_output, sizeof(public_output), 0u));
    CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);

    test_entropy_init(&entropy);
    CHECK(test_entropy_add(&entropy, scalar, NINLIL_PORT_OK, 32u));
    {
        uint8_t zero[32] = {0u};
        size_t attempt;
        for (attempt = 0u; attempt < 8u; ++attempt) {
            CHECK(test_entropy_add(
                &entropy, zero, NINLIL_PORT_OK, 32u));
        }
    }
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_SUCCESS);
    CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    private_size = 99u;
    public_size = 99u;
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, sizeof(private_output), &private_size,
        public_output, sizeof(public_output), &public_size)
        == EDHOC_ERROR_CRYPTO_FAILURE);
    CHECK(entropy.next == 9u && private_size == 0u && public_size == 0u
        && all_bytes(private_output, sizeof(private_output), 0u)
        && all_bytes(public_output, sizeof(public_output), 0u));
    CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);

    test_entropy_init(&entropy);
    CHECK(test_entropy_add(&entropy, scalar, NINLIL_PORT_OK, 32u));
    CHECK(test_entropy_add(
        &entropy, partial, NINLIL_PORT_TEMPORARY_FAILURE, 16u));
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_SUCCESS);
    CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    (void)memset(private_output, 0xa5, sizeof(private_output));
    (void)memset(public_output, 0xa5, sizeof(public_output));
    private_size = 99u;
    public_size = 99u;
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, sizeof(private_output), &private_size,
        public_output, sizeof(public_output), &public_size)
        == EDHOC_ERROR_CRYPTO_FAILURE);
    CHECK(private_size == 0u && public_size == 0u
        && all_bytes(private_output, sizeof(private_output), 0u)
        && all_bytes(public_output, sizeof(public_output), 0u));
    CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);

    test_entropy_init(&entropy);
    CHECK(test_entropy_add(
        &entropy, partial, NINLIL_PORT_TEMPORARY_FAILURE, 16u));
    CHECK(init_bindings(
        NINLIL_PA_S2_EDHOC_SUITE_2, &owner, &keys, &crypto));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_bind_entropy(
        &owner, &entropy.ops) == EDHOC_SUCCESS);
    entropy.reentry_owner = &owner;
    entropy.reentry_keys = &keys;
    entropy.reentry_draw = 0u;
    CHECK(keys.import_key(&owner, EDHOC_KT_MAKE_KEY_PAIR,
        NULL, 0u, make_id) == EDHOC_SUCCESS);
    private_size = 99u;
    public_size = 99u;
    CHECK(crypto.make_key_pair(&owner, make_id,
        private_output, sizeof(private_output), &private_size,
        public_output, sizeof(public_output), &public_size)
        == EDHOC_ERROR_CRYPTO_FAILURE);
    CHECK(entropy.reentry_status == EDHOC_ERROR_NOT_PERMITTED
        && private_size == 0u && public_size == 0u);
    CHECK(keys.destroy_key(&owner, make_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    return 1;
}

static int check_p256_early_end(void)
{
    uint8_t scalar[32] = {0u};
    uint8_t token[32];
    uint8_t make_id[4];
    uint8_t returned_token[32];
    uint8_t operation_id[4];
    uint8_t peer_x[32];
    uint8_t shared[32];
    size_t shared_size = 0u;
    ninlil_pa_s2_edhoc_crypto_owner_v1_t owner;
    struct edhoc_keys keys;
    struct edhoc_crypto crypto;
    test_entropy_t entropy;

    scalar[31] = 1u;
    (void)memset(token, 0x99, sizeof(token));
    CHECK(decode_hex(
        "8af6f430ebe18d34184017a9a11bf511c8dff8f834730b96c1b7c8dbca2fc3b6",
        peer_x, sizeof(peer_x)));
    CHECK(make_ephemeral(&owner, &keys, &crypto, &entropy,
        scalar, token, make_id, returned_token));
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner, sizeof(owner), 0u));

    CHECK(make_ephemeral(&owner, &keys, &crypto, &entropy,
        scalar, token, make_id, returned_token));
    CHECK(keys.import_key(&owner, EDHOC_KT_KEY_AGREEMENT,
        returned_token, sizeof(returned_token), operation_id) == EDHOC_SUCCESS);
    CHECK(crypto.key_agreement(&owner, operation_id, peer_x, sizeof(peer_x),
        shared, sizeof(shared), &shared_size) == EDHOC_SUCCESS);
    CHECK(keys.destroy_key(&owner, operation_id) == EDHOC_SUCCESS);
    CHECK(ninlil_pa_s2_edhoc_crypto_owner_v1_end(&owner) == EDHOC_SUCCESS);
    CHECK(all_bytes(&owner, sizeof(owner), 0u));
    return 1;
}
#endif

int main(void)
{
    if (!check_suite2() || !check_suite3() || !check_slots_and_reentry()
        || !check_alias_rejection() || !check_live_slot_owner_end_zeroize()
        || !check_key_id_rejection()) {
        return 1;
    }
#if defined(NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256) \
    && NINLIL_ENABLE_PRIVATE_PA_S2B1_EDHOC_P256
    if (!check_p256_method3_kat() || !check_p256_invalid_points()
        || !check_p256_operation_reuse()
        || !check_p256_generation_reservation()
        || !check_p256_generation_exhaustion()
        || !check_p256_entropy_capacity() || !check_p256_entropy_failure()
        || !check_p256_early_end()) {
        return 1;
    }
    (void)puts("PA-S2b1 private EDHOC P-256/token KAT PASS; Host only");
#else
    (void)puts("PA-S2a private EDHOC crypto KAT PASS; Host only");
#endif
    return 0;
}
