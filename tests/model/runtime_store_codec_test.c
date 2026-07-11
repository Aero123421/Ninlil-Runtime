#include "runtime_store_codec.h"
#include "runtime_store_codec_internal.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",         \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static int bytes_are_zero(const void *value, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)value;
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static uint8_t hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return (uint8_t)(value - '0');
    }
    return (uint8_t)(value - 'a' + 10);
}

static size_t decode_hex(const char *hex, uint8_t *out)
{
    size_t index;
    size_t length = strlen(hex) / 2u;
    for (index = 0u; index < length; ++index) {
        out[index] = (uint8_t)((hex_nibble(hex[index * 2u]) << 4u)
            | hex_nibble(hex[index * 2u + 1u]));
    }
    return length;
}

static void refresh_crc(uint8_t *value, uint32_t length)
{
    uint32_t crc = ninlil_model_runtime_store_crc32c(value, length - 4u);
    value[length - 4u] = (uint8_t)(crc >> 24u);
    value[length - 3u] = (uint8_t)(crc >> 16u);
    value[length - 2u] = (uint8_t)(crc >> 8u);
    value[length - 1u] = (uint8_t)crc;
}

static ninlil_model_runtime_store_binding_t binding_fixture(void)
{
    ninlil_model_runtime_store_binding_t value;
    uint8_t index;
    (void)memset(&value, 0, sizeof(value));
    value.storage_schema = 1u;
    value.role = NINLIL_ROLE_CONTROLLER;
    value.environment = NINLIL_ENV_TEST;
    for (index = 0u; index < 16u; ++index) {
        value.runtime_id.bytes[index] = index;
    }
    value.limits.max_services = 1u;
    value.limits.max_nonterminal_transactions = 2u;
    value.limits.max_targets_per_transaction = 3u;
    value.limits.max_logical_payload_bytes = 4u;
    value.limits.max_durable_outbox_payload_bytes =
        UINT64_C(0x0102030405060708);
    value.limits.max_attempts_per_target_per_cycle = 6u;
    value.limits.max_cancel_attempts_per_transaction = 7u;
    value.limits.max_evidence_per_target = 8u;
    value.limits.max_retained_terminal_transactions = 9u;
    value.limits.max_nonterminal_deliveries = 10u;
    value.limits.max_event_spool_count = 11u;
    value.limits.max_event_spool_bytes = UINT64_C(0x1112131415161718);
    value.limits.max_result_cache_entries = 13u;
    value.limits.max_retained_dispositions = 14u;
    value.limits.max_ingress_per_step = 15u;
    value.limits.max_callbacks_per_step = 16u;
    value.limits.max_state_transitions_per_step = 17u;
    value.limits.max_bearer_sends_per_step = 18u;
    value.limits.max_deferred_tokens = 19u;
    value.terminal_retention_ms = UINT64_C(0x2122232425262728);
    value.result_cache_retention_ms = UINT64_C(0x3132333435363738);
    value.observation_retention_ms = UINT64_C(0x4142434445464748);
    return value;
}

static ninlil_model_runtime_store_identity_t identity_fixture(void)
{
    ninlil_model_runtime_store_identity_t value;
    uint8_t index;
    (void)memset(&value, 0, sizeof(value));
    value.flags = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    for (index = 0u; index < 16u; ++index) {
        value.device_id.bytes[index] = (uint8_t)(0x10u + index);
        value.installation_id.bytes[index] = (uint8_t)(0x20u + index);
        value.site_domain_id.bytes[index] = (uint8_t)(0x30u + index);
    }
    value.binding_epoch = UINT64_C(0x0102030405060708);
    value.membership_epoch = UINT64_C(0x1112131415161718);
    return value;
}

static int test_exact_keys(void)
{
    static const uint8_t ROOT[8] = {
        0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
    };
    ninlil_model_runtime_store_key_t keys[17];
    uint32_t index;
    uint32_t other;

    for (index = 0u; index < 17u; ++index) {
        uint8_t family;
        uint8_t suffix = 0u;
        uint32_t expected_length;

        REQUIRE(ninlil_model_runtime_store_build_key(
            (ninlil_model_runtime_store_key_id_t)(index + 1u),
            &keys[index]) == NINLIL_OK);
        if (index == 0u) {
            family = 0x01u;
        } else if (index == 1u) {
            family = 0x02u;
        } else if (index < 6u) {
            family = 0x03u;
            suffix = (uint8_t)(index - 1u);
        } else {
            family = 0x04u;
            suffix = (uint8_t)(index - 5u);
        }
        expected_length = suffix == 0u ? 9u : 10u;
        REQUIRE(keys[index].length == expected_length);
        REQUIRE(memcmp(keys[index].bytes, ROOT, sizeof(ROOT)) == 0);
        REQUIRE(keys[index].bytes[8] == family);
        REQUIRE(suffix == 0u || keys[index].bytes[9] == suffix);
        REQUIRE(expected_length == 10u
            || keys[index].bytes[9] == 0u);
        {
            ninlil_model_runtime_store_key_id_t parsed =
                (ninlil_model_runtime_store_key_id_t)0;
            REQUIRE(ninlil_model_runtime_store_parse_key(
                (ninlil_bytes_view_t){keys[index].bytes, keys[index].length},
                &parsed) == NINLIL_OK);
            REQUIRE(parsed == (ninlil_model_runtime_store_key_id_t)(index + 1u));
        }
    }
    for (index = 0u; index < 17u; ++index) {
        for (other = index + 1u; other < 17u; ++other) {
            REQUIRE(keys[index].length != keys[other].length
                || memcmp(keys[index].bytes, keys[other].bytes,
                    keys[index].length) != 0);
        }
    }
    (void)memset(&keys[0], 0xa5, sizeof(keys[0]));
    REQUIRE(ninlil_model_runtime_store_build_key(
        (ninlil_model_runtime_store_key_id_t)0, &keys[0])
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&keys[0], sizeof(keys[0])));
    REQUIRE(ninlil_model_runtime_store_build_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    {
        uint8_t malformed[11] = {
            0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u,
            0x03u, 0x00u, 0x00u
        };
        ninlil_model_runtime_store_key_id_t parsed =
            NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING;
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){malformed, 10u}, &parsed)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(parsed == 0);
        malformed[9] = 1u;
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){malformed, 11u}, &parsed)
            == NINLIL_E_STORAGE_CORRUPT);
        malformed[7] = 2u;
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){malformed, 10u}, &parsed)
            == NINLIL_E_UNSUPPORTED);
        malformed[7] = 1u;
        malformed[8] = 5u;
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){malformed, 9u}, &parsed)
            == NINLIL_E_UNSUPPORTED);
        malformed[8] = 6u;
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){malformed, 10u}, &parsed)
            == NINLIL_E_UNSUPPORTED);
        malformed[8] = 3u;
        malformed[0] ^= 1u;
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){malformed, 10u}, &parsed)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){NULL, 1u}, &parsed)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(ninlil_model_runtime_store_parse_key(
            (ninlil_bytes_view_t){malformed, 10u}, NULL)
            == NINLIL_E_INVALID_ARGUMENT);
    }
    return 0;
}

static int test_crc32c(void)
{
    static const uint8_t STANDARD[] = {
        (uint8_t)'1', (uint8_t)'2', (uint8_t)'3',
        (uint8_t)'4', (uint8_t)'5', (uint8_t)'6',
        (uint8_t)'7', (uint8_t)'8', (uint8_t)'9'
    };
    REQUIRE(ninlil_model_runtime_store_crc32c(NULL, 0u) == 0u);
    REQUIRE(ninlil_model_runtime_store_crc32c(
        STANDARD, sizeof(STANDARD)) == 0xe3069283u);
    return 0;
}

static int test_envelope_golden_and_round_trip(void)
{
    static const uint8_t PAYLOAD[] = {0x00u, 0xffu, 0x2fu, 0x41u};
    static const uint8_t GOLDEN[] = {
        0x4eu, 0x4cu, 0x52u, 0x31u,
        0x00u, 0x01u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x04u,
        0x00u, 0xffu, 0x2fu, 0x41u,
        0x31u, 0xf1u, 0xd5u, 0x1du
    };
    uint8_t encoded[sizeof(GOLDEN)];
    ninlil_bytes_view_t payload;
    ninlil_bytes_view_t view;
    ninlil_model_runtime_store_envelope_t decoded;
    uint32_t length = 0u;

    payload.data = PAYLOAD;
    payload.length = sizeof(PAYLOAD);
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        payload, encoded, sizeof(encoded), &length) == NINLIL_OK);
    REQUIRE(length == sizeof(GOLDEN));
    REQUIRE(memcmp(encoded, GOLDEN, sizeof(GOLDEN)) == 0);
    view.data = encoded;
    view.length = length;
    REQUIRE(ninlil_model_runtime_store_decode_envelope(view, &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.type == NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING);
    REQUIRE(decoded.version == 1u);
    REQUIRE(decoded.payload.length == sizeof(PAYLOAD));
    REQUIRE(decoded.payload.data == &encoded[12]);
    REQUIRE(memcmp(decoded.payload.data, PAYLOAD, sizeof(PAYLOAD)) == 0);
    REQUIRE(decoded.crc32c == 0x31f1d51du);
    return 0;
}

static int test_envelope_mutation_and_exact_length(void)
{
    static const uint8_t GOLDEN[] = {
        0x4eu, 0x4cu, 0x52u, 0x31u,
        0x00u, 0x01u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x04u,
        0x00u, 0xffu, 0x2fu, 0x41u,
        0x31u, 0xf1u, 0xd5u, 0x1du
    };
    uint8_t mutated[sizeof(GOLDEN) + 1u];
    ninlil_bytes_view_t view;
    ninlil_model_runtime_store_envelope_t decoded;
    size_t index;

    for (index = 0u; index < sizeof(GOLDEN); ++index) {
        (void)memcpy(mutated, GOLDEN, sizeof(GOLDEN));
        mutated[index] ^= 0x01u;
        view.data = mutated;
        view.length = sizeof(GOLDEN);
        (void)memset(&decoded, 0xa5, sizeof(decoded));
        REQUIRE(ninlil_model_runtime_store_decode_envelope(view, &decoded)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(bytes_are_zero(&decoded, sizeof(decoded)));
    }
    (void)memcpy(mutated, GOLDEN, sizeof(GOLDEN));
    mutated[sizeof(GOLDEN)] = 0u;
    view.data = mutated;
    view.length = sizeof(mutated);
    REQUIRE(ninlil_model_runtime_store_decode_envelope(view, &decoded)
        == NINLIL_E_STORAGE_CORRUPT);
    view.length = sizeof(GOLDEN) - 1u;
    REQUIRE(ninlil_model_runtime_store_decode_envelope(view, &decoded)
        == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, GOLDEN, sizeof(GOLDEN));
    mutated[7] = 2u;
    refresh_crc(mutated, sizeof(GOLDEN));
    view.data = mutated;
    view.length = sizeof(GOLDEN);
    REQUIRE(ninlil_model_runtime_store_decode_envelope(view, &decoded)
        == NINLIL_E_UNSUPPORTED);
    (void)memcpy(mutated, GOLDEN, sizeof(GOLDEN));
    mutated[5] = 9u;
    refresh_crc(mutated, sizeof(GOLDEN));
    REQUIRE(ninlil_model_runtime_store_decode_envelope(view, &decoded)
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

static int test_typed_golden_and_round_trip(void)
{
    static const char BINDING_HEX[] =
        "4e4c523100010001000000a70000000100194e494e4c494c2d464f554e444154494f4e2d534d414c4c2d31"
        "000000010000000100000001000102030405060708090a0b0c0d0e0f00000001000000020000000300000004"
        "0102030405060708000000060000000700000008000000090000000a0000000b11121314151617180000000d"
        "0000000e0000000f000000100000001100000012000000132122232425262728313233343536373841424344"
        "454647487b044804";
    static const char IDENTITY_HEX[] =
        "4e4c5231000200010000004400000007101112131415161718191a1b1c1d1e1f202122232425262728292a2b"
        "2c2d2e2f303132333435363738393a3b3c3d3e3f010203040506070811121314151617189bae8f73";
    static const char COUNTER_HEX[] =
        "4e4c5231000300010000001000000001010203040506070800000000302fe29a";
    static const char CAPACITY_HEX[] =
        "4e4c5231000400010000003400000001f10203040506070801020304050607080010203040506070"
        "111213141516171821222324252627280000000100000000fc6720b1";
    uint8_t encoded[256];
    uint8_t golden[256];
    uint32_t length;
    size_t golden_length;
    ninlil_model_runtime_store_binding_t binding = binding_fixture();
    ninlil_model_runtime_store_binding_t decoded_binding;
    ninlil_model_runtime_store_identity_t identity = identity_fixture();
    ninlil_model_runtime_store_identity_t decoded_identity;
    ninlil_model_runtime_store_counter_t counter = {
        NINLIL_MODEL_RUNTIME_STORE_COUNTER_TRANSACTION,
        UINT64_C(0x0102030405060708), 0u
    };
    ninlil_model_runtime_store_counter_t decoded_counter;
    ninlil_model_runtime_store_capacity_t entry = {
        NINLIL_RESOURCE_SERVICE,
        UINT64_C(0xf102030405060708),
        UINT64_C(0x0102030405060708),
        UINT64_C(0x0010203040506070),
        UINT64_C(0x1112131415161718),
        UINT64_C(0x2122232425262728), 1u, 0u
    };
    ninlil_model_runtime_store_capacity_t decoded_entry;

    REQUIRE(ninlil_model_runtime_store_encode_binding(
        &binding, encoded, sizeof(encoded), &length) == NINLIL_OK);
    golden_length = decode_hex(BINDING_HEX, golden);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES);
    REQUIRE(length == golden_length && memcmp(encoded, golden, length) == 0);
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        (ninlil_bytes_view_t){encoded, length}, &decoded_binding) == NINLIL_OK);
    REQUIRE(memcmp(&binding, &decoded_binding, sizeof(binding)) == 0);

    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, encoded, sizeof(encoded), &length) == NINLIL_OK);
    golden_length = decode_hex(IDENTITY_HEX, golden);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_IDENTITY_VALUE_BYTES);
    REQUIRE(length == golden_length && memcmp(encoded, golden, length) == 0);
    REQUIRE(ninlil_model_runtime_store_decode_identity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        (ninlil_bytes_view_t){encoded, length}, &decoded_identity) == NINLIL_OK);
    REQUIRE(memcmp(&identity, &decoded_identity, sizeof(identity)) == 0);

    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        &counter, encoded, sizeof(encoded), &length) == NINLIL_OK);
    golden_length = decode_hex(COUNTER_HEX, golden);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES);
    REQUIRE(length == golden_length && memcmp(encoded, golden, length) == 0);
    REQUIRE(ninlil_model_runtime_store_decode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        (ninlil_bytes_view_t){encoded, length}, &decoded_counter) == NINLIL_OK);
    REQUIRE(memcmp(&counter, &decoded_counter, sizeof(counter)) == 0);

    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, encoded, sizeof(encoded), &length) == NINLIL_OK);
    golden_length = decode_hex(CAPACITY_HEX, golden);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES);
    REQUIRE(length == golden_length && memcmp(encoded, golden, length) == 0);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){encoded, length}, &decoded_entry) == NINLIL_OK);
    REQUIRE(memcmp(&entry, &decoded_entry, sizeof(entry)) == 0);
    return 0;
}

static int test_typed_semantic_rejection(void)
{
    uint8_t value[256];
    uint8_t mutated[256];
    uint32_t length;
    ninlil_model_runtime_store_binding_t binding = binding_fixture();
    ninlil_model_runtime_store_binding_t out_binding;
    ninlil_model_runtime_store_identity_t identity = identity_fixture();
    ninlil_model_runtime_store_identity_t out_identity;
    ninlil_model_runtime_store_counter_t counter = {
        NINLIL_MODEL_RUNTIME_STORE_COUNTER_TRANSACTION, 7u, 0u
    };
    ninlil_model_runtime_store_counter_t out_counter;
    ninlil_model_runtime_store_capacity_t entry = {
        NINLIL_RESOURCE_SERVICE, 100u, 30u, 20u, 50u, 1u, 0u, 0u
    };
    ninlil_model_runtime_store_capacity_t out_entry;

    REQUIRE(ninlil_model_runtime_store_encode_binding(
        &binding, value, sizeof(value), &length) == NINLIL_OK);
    (void)memcpy(mutated, value, length);
    mutated[5] = (uint8_t)NINLIL_MODEL_RUNTIME_STORE_RECORD_IDENTITY;
    mutated[7] = 2u;
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        (ninlil_bytes_view_t){mutated, length}, &out_binding)
        == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length); mutated[15] ^= 1u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        (ninlil_bytes_view_t){mutated, length}, &out_binding) == NINLIL_E_UNSUPPORTED);
    (void)memcpy(mutated, value, length);
    (void)memset(&mutated[55], 0, 16u);
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        (ninlil_bytes_view_t){mutated, length}, &out_binding) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        (ninlil_bytes_view_t){value, length}, &out_binding) == NINLIL_E_STORAGE_CORRUPT);

    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, value, sizeof(value), &length) == NINLIL_OK);
    (void)memcpy(mutated, value, length); mutated[15] = 0x08u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_identity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        (ninlil_bytes_view_t){mutated, length}, &out_identity) == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length);
    (void)memset(&mutated[16], 0, 16u);
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_identity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        (ninlil_bytes_view_t){mutated, length}, &out_identity) == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length);
    (void)memset(&mutated[64], 0, 8u);
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_identity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        (ninlil_bytes_view_t){mutated, length}, &out_identity) == NINLIL_E_STORAGE_CORRUPT);

    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        &counter, value, sizeof(value), &length) == NINLIL_OK);
    (void)memcpy(mutated, value, length); mutated[15] = 2u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        (ninlil_bytes_view_t){mutated, length}, &out_counter) == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length); mutated[27] = 1u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        (ninlil_bytes_view_t){mutated, length}, &out_counter) == NINLIL_E_STORAGE_CORRUPT);
    counter.kind = NINLIL_MODEL_RUNTIME_STORE_COUNTER_VISITED_OWNER;
    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER,
        &counter, value, sizeof(value), &length) == NINLIL_OK);
    (void)memcpy(mutated, value, length); mutated[27] = 1u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER,
        (ninlil_bytes_view_t){mutated, length}, &out_counter) == NINLIL_E_STORAGE_CORRUPT);

    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, value, sizeof(value), &length) == NINLIL_OK);
    (void)memcpy(mutated, value, length); mutated[15] = 2u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){mutated, length}, &out_entry) == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length);
    (void)memset(&mutated[48], 0, 8u);
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){mutated, length}, &out_entry) == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length); mutated[59] = 2u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){mutated, length}, &out_entry) == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length); mutated[63] = 1u; refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){mutated, length}, &out_entry) == NINLIL_E_STORAGE_CORRUPT);
    entry.used = UINT64_MAX; entry.reserved = 1u; entry.high_water = UINT64_MAX;
    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, value, sizeof(value), &length) == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_typed_exact_lengths(void)
{
    uint8_t payload[168];
    uint8_t encoded[256];
    uint32_t length;
    ninlil_model_runtime_store_binding_t binding;
    (void)memset(payload, 0, sizeof(payload));
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        (ninlil_bytes_view_t){payload, 166u}, encoded, sizeof(encoded), &length)
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        (ninlil_bytes_view_t){encoded, length}, &binding) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        (ninlil_bytes_view_t){payload, 168u}, encoded, sizeof(encoded), &length)
        == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        (ninlil_bytes_view_t){encoded, length}, &binding) == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

static int test_marker_boundary_semantics(void)
{
    uint8_t value[256];
    uint8_t mutated[256];
    uint32_t length;
    ninlil_model_runtime_store_counter_t counter = {
        NINLIL_MODEL_RUNTIME_STORE_COUNTER_TRANSACTION, UINT64_MAX, 1u
    };
    ninlil_model_runtime_store_counter_t decoded_counter;
    ninlil_model_runtime_store_capacity_t entry = {
        NINLIL_RESOURCE_SERVICE, UINT64_MAX, 1u, 1u, 2u,
        UINT64_MAX, 0u, 1u
    };
    ninlil_model_runtime_store_capacity_t decoded_entry;

    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        &counter, value, sizeof(value), &length) == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_decode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        (ninlil_bytes_view_t){value, length}, &decoded_counter) == NINLIL_OK);
    counter.exhausted_marker = 0u;
    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        &counter, value, sizeof(value), &length) == NINLIL_OK);
    counter.kind = NINLIL_MODEL_RUNTIME_STORE_COUNTER_VISITED_OWNER;
    counter.exhausted_marker = 1u;
    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER,
        &counter, value, sizeof(value), &length) == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, value, sizeof(value), &length) == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){value, length}, &decoded_entry) == NINLIL_OK);
    entry.counter_exhausted = 0u;
    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, value, sizeof(value), &length) == NINLIL_OK);

    entry.limit = 100u;
    entry.used = 30u;
    entry.reserved = 20u;
    entry.high_water = 50u;
    entry.capacity_epoch = 1u;
    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, value, sizeof(value), &length) == NINLIL_OK);
    (void)memcpy(mutated, value, length);
    mutated[47] = 49u;
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){mutated, length}, &decoded_entry)
        == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length);
    mutated[23] = 49u;
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){mutated, length}, &decoded_entry)
        == NINLIL_E_STORAGE_CORRUPT);
    (void)memcpy(mutated, value, length);
    mutated[59] = 2u;
    refresh_crc(mutated, length);
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        (ninlil_bytes_view_t){mutated, length}, &decoded_entry)
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

static int test_identity_optional_installation(void)
{
    uint8_t value[128];
    uint32_t length;
    ninlil_model_runtime_store_identity_t identity = identity_fixture();
    ninlil_model_runtime_store_identity_t decoded;

    identity.flags &= ~NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    (void)memset(&identity.installation_id, 0, sizeof(identity.installation_id));
    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, value, sizeof(value), &length) == NINLIL_OK);
    REQUIRE(ninlil_model_runtime_store_decode_identity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        (ninlil_bytes_view_t){value, length}, &decoded) == NINLIL_OK);
    REQUIRE(memcmp(&identity, &decoded, sizeof(identity)) == 0);

    identity.installation_id.bytes[0] = 1u;
    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, value, sizeof(value), &length) == NINLIL_E_INVALID_ARGUMENT);
    identity.flags |= NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION;
    (void)memset(&identity.installation_id, 0, sizeof(identity.installation_id));
    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, value, sizeof(value), &length) == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

static int test_typed_encoder_contracts(void)
{
    uint8_t output[256];
    uint8_t before[256];
    uint8_t invalid_value[16] = {0u};
    uint32_t length;
    ninlil_bytes_view_t invalid_encoded = {invalid_value, sizeof(invalid_value)};
    ninlil_model_runtime_store_binding_t binding = binding_fixture();
    ninlil_model_runtime_store_binding_t decoded_binding;
    ninlil_model_runtime_store_identity_t identity = identity_fixture();
    ninlil_model_runtime_store_identity_t decoded_identity;
    ninlil_model_runtime_store_counter_t counter = {
        NINLIL_MODEL_RUNTIME_STORE_COUNTER_TRANSACTION, 0u, 0u
    };
    ninlil_model_runtime_store_counter_t decoded_counter;
    ninlil_model_runtime_store_capacity_t entry = {
        NINLIL_RESOURCE_SERVICE, 1u, 0u, 0u, 0u, 1u, 0u, 0u
    };
    ninlil_model_runtime_store_capacity_t decoded_entry;

    REQUIRE(NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_RECORD_COUNT == 17u);
    length = 0u;
    REQUIRE(ninlil_model_runtime_store_encode_binding(
        &binding, NULL, 0u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES);
    (void)memset(output, 0xa5, sizeof(output));
    (void)memcpy(before, output, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_encode_binding(
        &binding, output, length - 1u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(memcmp(output, before, sizeof(output)) == 0);
    REQUIRE(ninlil_model_runtime_store_encode_binding(
        &binding, NULL, length, &length) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_runtime_store_encode_binding(
        NULL, output, sizeof(output), &length) == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, NULL, 0u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_IDENTITY_VALUE_BYTES);
    (void)memset(output, 0xa5, sizeof(output));
    (void)memcpy(before, output, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, output, length - 1u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(memcmp(output, before, sizeof(output)) == 0);
    REQUIRE(ninlil_model_runtime_store_encode_identity(
        &identity, NULL, length, &length) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_runtime_store_encode_identity(
        NULL, output, sizeof(output), &length) == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        &counter, NULL, 0u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES);
    (void)memset(output, 0xa5, sizeof(output));
    (void)memcpy(before, output, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        &counter, output, length - 1u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(memcmp(output, before, sizeof(output)) == 0);
    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        &counter, NULL, length, &length) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_runtime_store_encode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        NULL, output, sizeof(output), &length) == NINLIL_E_INVALID_ARGUMENT);

    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, NULL, 0u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(length == NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES);
    (void)memset(output, 0xa5, sizeof(output));
    (void)memcpy(before, output, sizeof(output));
    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, output, length - 1u, &length) == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(memcmp(output, before, sizeof(output)) == 0);
    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        &entry, NULL, length, &length) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_runtime_store_encode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        NULL, output, sizeof(output), &length) == NINLIL_E_INVALID_ARGUMENT);

    (void)memset(&decoded_binding, 0xa5, sizeof(decoded_binding));
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        invalid_encoded, &decoded_binding) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(bytes_are_zero(&decoded_binding, sizeof(decoded_binding)));
    (void)memset(&decoded_identity, 0xa5, sizeof(decoded_identity));
    REQUIRE(ninlil_model_runtime_store_decode_identity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY,
        invalid_encoded, &decoded_identity) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(bytes_are_zero(&decoded_identity, sizeof(decoded_identity)));
    (void)memset(&decoded_counter, 0xa5, sizeof(decoded_counter));
    REQUIRE(ninlil_model_runtime_store_decode_counter(
        NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION,
        invalid_encoded, &decoded_counter) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(bytes_are_zero(&decoded_counter, sizeof(decoded_counter)));
    (void)memset(&decoded_entry, 0xa5, sizeof(decoded_entry));
    REQUIRE(ninlil_model_runtime_store_decode_capacity(
        NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE,
        invalid_encoded, &decoded_entry) == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(bytes_are_zero(&decoded_entry, sizeof(decoded_entry)));
    return 0;
}

static int test_overlap_and_payload_boundaries(void)
{
    union aligned_storage {
        max_align_t alignment;
        uint8_t bytes[512];
        ninlil_model_runtime_store_binding_t binding;
        ninlil_model_runtime_store_envelope_t envelope;
        ninlil_model_runtime_store_key_id_t key_id;
    } shared;
    union aligned_storage before_shared;
    uint8_t payload[NINLIL_MODEL_RUNTIME_STORE_MAX_PAYLOAD_BYTES + 1u];
    uint8_t encoded[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
    uint32_t length;
    ninlil_model_runtime_store_binding_t binding = binding_fixture();
    ninlil_model_runtime_store_key_t key;

    (void)memset(&shared, 0, sizeof(shared));
    REQUIRE(ninlil_model_runtime_store_build_key(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING, &key) == NINLIL_OK);
    (void)memcpy(shared.bytes, key.bytes, key.length);
    before_shared = shared;
    REQUIRE(ninlil_model_runtime_store_parse_key(
        (ninlil_bytes_view_t){shared.bytes, key.length}, &shared.key_id)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&shared, &before_shared, sizeof(shared)) == 0);

    (void)memset(shared.bytes, 0x5a, sizeof(shared.bytes));
    before_shared = shared;
    length = 99u;
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER,
        (ninlil_bytes_view_t){shared.bytes, 16u},
        &shared.bytes[8], 32u, &length) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length == 99u);
    REQUIRE(memcmp(&shared, &before_shared, sizeof(shared)) == 0);
    before_shared = shared;
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER,
        (ninlil_bytes_view_t){payload, 16u}, shared.bytes, 32u,
        (uint32_t *)shared.bytes) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&shared, &before_shared, sizeof(shared)) == 0);
    before_shared = shared;
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        (ninlil_model_runtime_store_record_type_t)0,
        (ninlil_bytes_view_t){shared.bytes, 16u}, encoded, 32u,
        (uint32_t *)shared.bytes) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&shared, &before_shared, sizeof(shared)) == 0);

    REQUIRE(ninlil_model_runtime_store_encode_binding(
        &binding, encoded, sizeof(encoded), &length) == NINLIL_OK);
    (void)memcpy(shared.bytes, encoded, length);
    before_shared = shared;
    REQUIRE(ninlil_model_runtime_store_decode_envelope(
        (ninlil_bytes_view_t){shared.bytes, length}, &shared.envelope)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&shared, &before_shared, sizeof(shared)) == 0);

    binding = binding_fixture();
    {
        ninlil_model_runtime_store_binding_t before_binding = binding;
        uint32_t before_length = length;
        REQUIRE(ninlil_model_runtime_store_encode_binding(
            &binding, ((uint8_t *)&binding) + 4u, 32u, &length)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(length == before_length);
        REQUIRE(memcmp(&binding, &before_binding, sizeof(binding)) == 0);
        REQUIRE(ninlil_model_runtime_store_encode_binding(
            &binding, NULL, 1u, (uint32_t *)&binding)
            == NINLIL_E_INVALID_ARGUMENT);
        REQUIRE(memcmp(&binding, &before_binding, sizeof(binding)) == 0);
    }
    (void)memcpy(shared.bytes, encoded,
        NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES);
    before_shared = shared;
    REQUIRE(ninlil_model_runtime_store_decode_binding(
        NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING,
        (ninlil_bytes_view_t){shared.bytes,
            NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES},
        &shared.binding) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(memcmp(&shared, &before_shared, sizeof(shared)) == 0);

    (void)memset(payload, 0xa5, sizeof(payload));
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_CAPACITY,
        (ninlil_bytes_view_t){payload,
            NINLIL_MODEL_RUNTIME_STORE_MAX_PAYLOAD_BYTES},
        encoded, sizeof(encoded), &length) == NINLIL_OK);
    REQUIRE(length == NINLIL_M1A_MAX_STORAGE_VALUE_BYTES);
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_CAPACITY,
        (ninlil_bytes_view_t){payload,
            NINLIL_MODEL_RUNTIME_STORE_MAX_PAYLOAD_BYTES + 1u},
        NULL, 0u, &length) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length == 0u);
    return 0;
}

static int test_encode_boundaries_and_closed_outputs(void)
{
    uint8_t output[20];
    uint8_t before[20];
    ninlil_bytes_view_t payload;
    ninlil_bytes_view_t encoded;
    ninlil_model_runtime_store_envelope_t decoded;
    uint32_t length;

    (void)memset(output, 0xa5, sizeof(output));
    (void)memcpy(before, output, sizeof(output));
    payload.data = (const uint8_t *)"abcd";
    payload.length = 4u;
    length = 99u;
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        payload, output, sizeof(output) - 1u, &length)
        == NINLIL_E_BUFFER_TOO_SMALL);
    REQUIRE(length == sizeof(output));
    REQUIRE(memcmp(output, before, sizeof(output)) == 0);

    payload.data = NULL;
    payload.length = 0u;
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER,
        payload, output, 16u, &length) == NINLIL_OK);
    REQUIRE(length == 16u);
    encoded.data = output;
    encoded.length = length;
    REQUIRE(ninlil_model_runtime_store_decode_envelope(encoded, &decoded)
        == NINLIL_OK);
    REQUIRE(decoded.payload.data == NULL && decoded.payload.length == 0u);

    payload.data = NULL;
    payload.length = 1u;
    length = 99u;
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER,
        payload, output, sizeof(output), &length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(length == 0u);
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        (ninlil_model_runtime_store_record_type_t)0,
        (ninlil_bytes_view_t){NULL, 0u}, output, sizeof(output), &length)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        (ninlil_bytes_view_t){NULL, 0u}, output, sizeof(output), NULL)
        == NINLIL_E_INVALID_ARGUMENT);

    encoded.data = NULL;
    encoded.length = 1u;
    (void)memset(&decoded, 0xa5, sizeof(decoded));
    REQUIRE(ninlil_model_runtime_store_decode_envelope(encoded, &decoded)
        == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(bytes_are_zero(&decoded, sizeof(decoded)));
    REQUIRE(ninlil_model_runtime_store_decode_envelope(
        (ninlil_bytes_view_t){output, 16u}, NULL)
        == NINLIL_E_INVALID_ARGUMENT);
    return 0;
}

int main(void)
{
    if (test_exact_keys() != 0
        || test_crc32c() != 0
        || test_envelope_golden_and_round_trip() != 0
        || test_envelope_mutation_and_exact_length() != 0
        || test_typed_golden_and_round_trip() != 0
        || test_typed_semantic_rejection() != 0
        || test_typed_exact_lengths() != 0
        || test_marker_boundary_semantics() != 0
        || test_identity_optional_installation() != 0
        || test_typed_encoder_contracts() != 0
        || test_overlap_and_payload_boundaries() != 0
        || test_encode_boundaries_and_closed_outputs() != 0) {
        return 1;
    }
    return 0;
}
