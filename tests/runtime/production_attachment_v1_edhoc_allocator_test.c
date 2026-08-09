/* SPDX-License-Identifier: Apache-2.0 */
/* PA-S1a dependency-memory trace only. This is not a PA-S2 crypto provider. */
#include "pa_s1_edhoc_allocator.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "edhoc.h"

static ninlil_pa_s1_edhoc_allocator_v1_t *test_hook_allocator;
static ninlil_pa_s1_edhoc_allocator_v1_t *reentry_allocator;
static uint32_t reentry_rejected;

static int test_adapter_begin(ninlil_pa_s1_edhoc_allocator_v1_t *allocator)
{
    if (test_hook_allocator != NULL ||
        !ninlil_pa_s1_edhoc_allocator_v1_begin(allocator)) {
        return 0;
    }
    test_hook_allocator = allocator;
    return 1;
}

static int test_adapter_end(ninlil_pa_s1_edhoc_allocator_v1_t *allocator)
{
    if (test_hook_allocator != allocator) {
        return 0;
    }
    test_hook_allocator = NULL;
    return ninlil_pa_s1_edhoc_allocator_v1_end(allocator);
}

void *edhoc_mem_alloc(size_t size)
{
    return ninlil_pa_s1_edhoc_allocator_v1_alloc(test_hook_allocator, size);
}

void edhoc_mem_free(void *pointer)
{
    ninlil_pa_s1_edhoc_allocator_v1_free(test_hook_allocator, pointer);
}

static int fake_import(void *context, enum edhoc_key_type type,
    const uint8_t *raw, size_t raw_size, void *key_id)
{
    (void)context;
    (void)type;
    (void)raw;
    (void)raw_size;
    memset(key_id, 0x5au, 4u);
    return EDHOC_SUCCESS;
}

static int fake_destroy(void *context, void *key_id)
{
    (void)context;
    memset(key_id, 0, 4u);
    return EDHOC_SUCCESS;
}

static int fake_key_pair(void *context, const void *key_id,
    uint8_t *private_key, size_t private_size, size_t *private_length,
    uint8_t *public_key, size_t public_size, size_t *public_length)
{
    (void)context;
    (void)key_id;
    if (reentry_allocator != NULL && !test_adapter_begin(reentry_allocator)) {
        reentry_rejected = 1u;
    }
    if (private_size < 32u || public_size < 32u) {
        return EDHOC_ERROR_BUFFER_TOO_SMALL;
    }
    memset(private_key, 0x11, 32u);
    memset(public_key, 0x22, 32u);
    *private_length = 32u;
    *public_length = 32u;
    return EDHOC_SUCCESS;
}

static int unavailable_key_agreement(void *a, const void *b, const uint8_t *c,
    size_t d, uint8_t *e, size_t f, size_t *g)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g;
    return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int unavailable_signature(void *a, const void *b, const uint8_t *c,
    size_t d, uint8_t *e, size_t f, size_t *g)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g;
    return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int unavailable_verify(void *a, const void *b, const uint8_t *c,
    size_t d, const uint8_t *e, size_t f)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int unavailable_extract(void *a, const void *b, const uint8_t *c,
    size_t d, uint8_t *e, size_t f, size_t *g)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g;
    return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int unavailable_expand(void *a, const void *b, const uint8_t *c,
    size_t d, uint8_t *e, size_t f)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f;
    return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int unavailable_encrypt(void *a, const void *b, const uint8_t *c,
    size_t d, const uint8_t *e, size_t f, const uint8_t *g, size_t h,
    uint8_t *i, size_t j, size_t *k)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g;
    (void)h; (void)i; (void)j; (void)k;
    return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int unavailable_decrypt(void *a, const void *b, const uint8_t *c,
    size_t d, const uint8_t *e, size_t f, const uint8_t *g, size_t h,
    uint8_t *i, size_t j, size_t *k)
{
    (void)a; (void)b; (void)c; (void)d; (void)e; (void)f; (void)g;
    (void)h; (void)i; (void)j; (void)k;
    return EDHOC_ERROR_CRYPTO_FAILURE;
}

static int fake_hash(void *context, const uint8_t *input, size_t input_length,
    uint8_t *hash, size_t hash_size, size_t *hash_length)
{
    size_t index;

    (void)context;
    if (hash_size < 32u) {
        return EDHOC_ERROR_BUFFER_TOO_SMALL;
    }
    for (index = 0u; index < 32u; ++index) {
        hash[index] = (uint8_t)(input_length + index + (input[0] & 1u));
    }
    *hash_length = 32u;
    return EDHOC_SUCCESS;
}

static const struct edhoc_keys fake_keys = {
    .import_key = fake_import,
    .destroy_key = fake_destroy,
};

static const struct edhoc_crypto fake_crypto = {
    .make_key_pair = fake_key_pair,
    .key_agreement = unavailable_key_agreement,
    .signature = unavailable_signature,
    .verify = unavailable_verify,
    .extract = unavailable_extract,
    .expand = unavailable_expand,
    .encrypt = unavailable_encrypt,
    .decrypt = unavailable_decrypt,
    .hash = fake_hash,
};

static int setup_context(struct edhoc_context *context)
{
    const enum edhoc_method method[] = { EDHOC_METHOD_3 };
    const struct edhoc_cipher_suite suite[] = {{
        .value = 2,
        .aead_key_length = 16u,
        .aead_tag_length = 8u,
        .aead_iv_length = 13u,
        .hash_length = 32u,
        .mac_length = 8u,
        .ecc_key_length = 32u,
        .ecc_sign_length = 64u,
    }};
    const struct edhoc_connection_id cid = {
        .encode_type = EDHOC_CID_TYPE_ONE_BYTE_INTEGER,
        .int_value = 1,
    };

    return edhoc_context_init(context) == EDHOC_SUCCESS &&
        edhoc_set_methods(context, method, 1u) == EDHOC_SUCCESS &&
        edhoc_set_cipher_suites(context, suite, 1u) == EDHOC_SUCCESS &&
        edhoc_set_connection_id(context, &cid) == EDHOC_SUCCESS &&
        edhoc_bind_keys(context, &fake_keys) == EDHOC_SUCCESS &&
        edhoc_bind_crypto(context, &fake_crypto) == EDHOC_SUCCESS;
}

static int run_m1(ninlil_pa_s1_edhoc_allocator_v1_t *allocator,
    int expected_result)
{
    struct edhoc_context context = {0};
    uint8_t message[128] = {0};
    size_t message_length = 0u;
    int result;

    assert(test_adapter_begin(allocator));
    assert(setup_context(&context));
    result = edhoc_message_1_compose(&context, message, sizeof(message),
        &message_length);
    assert(result == expected_result);
    assert(edhoc_context_deinit(&context) == EDHOC_SUCCESS);
    assert(test_adapter_end(allocator));
    return result;
}

static void test_explicit_allocator(void)
{
    ninlil_pa_s1_edhoc_allocator_v1_t allocator = {0};
    void *first;
    void *second;
    void *third;
    uint32_t index;

    assert(ninlil_pa_s1_edhoc_allocator_v1_begin(&allocator));
    assert(ninlil_pa_s1_edhoc_allocator_v1_alloc(&allocator,
        (size_t)NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES + 1u) == NULL);
    first = ninlil_pa_s1_edhoc_allocator_v1_alloc(&allocator, 0u);
    second = ninlil_pa_s1_edhoc_allocator_v1_alloc(&allocator,
        NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES);
    assert(first != NULL && second != NULL);
    third = ninlil_pa_s1_edhoc_allocator_v1_alloc(&allocator, 1u);
    assert(third == NULL);
    assert(((uintptr_t)first % _Alignof(max_align_t)) == 0u);
    memset(first, 0xabu, 1u);
    memset(second, 0xcdu, NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES);
    ninlil_pa_s1_edhoc_allocator_v1_free(&allocator, first);
    for (index = 0u; index < NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES; ++index) {
        assert(allocator.slots[0].bytes[index] == 0u);
    }
    ninlil_pa_s1_edhoc_allocator_v1_free(&allocator, second);
    for (index = 0u; index < NINLIL_PA_S1_EDHOC_ALLOCATOR_SLOT_BYTES; ++index) {
        assert(allocator.slots[1].bytes[index] == 0u);
    }
    assert(allocator.live_blocks == 0u && allocator.live_bytes == 0u);
    assert(allocator.successful_allocations == allocator.frees);
    assert(ninlil_pa_s1_edhoc_allocator_v1_end(&allocator));
}

static void test_m1_trace_and_failpoint(void)
{
    ninlil_pa_s1_edhoc_allocator_v1_t allocator = {0};
    ninlil_pa_s1_edhoc_allocator_v1_t other = {0};

    reentry_allocator = &other;
    reentry_rejected = 0u;
    assert(run_m1(&allocator, EDHOC_SUCCESS) == EDHOC_SUCCESS);
    assert(reentry_rejected == 1u);
    assert(allocator.allocation_calls == 1u);
    assert(allocator.successful_allocations == 1u);
    assert(allocator.frees == 1u);
    assert(allocator.peak_live_blocks == 1u && allocator.peak_live_bytes == 32u);
    assert(run_m1(&allocator, EDHOC_SUCCESS) == EDHOC_SUCCESS);
    assert(allocator.allocation_calls == 1u);
    assert(allocator.successful_allocations == 1u && allocator.frees == 1u);
    reentry_allocator = NULL;

    memset(&allocator, 0, sizeof(allocator));
    ninlil_pa_s1_edhoc_allocator_v1_fail_on(&allocator, 1u);
    assert(run_m1(&allocator, EDHOC_ERROR_NOT_ENOUGH_MEMORY) ==
        EDHOC_ERROR_NOT_ENOUGH_MEMORY);
    assert(allocator.allocation_calls == 1u);
    assert(allocator.successful_allocations == 0u && allocator.frees == 0u);
}

int main(void)
{
    test_explicit_allocator();
    test_m1_trace_and_failpoint();
    return 0;
}
