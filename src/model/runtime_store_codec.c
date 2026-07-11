#include "runtime_store_codec.h"
#include "runtime_store_codec_internal.h"

#include <string.h>

static const uint8_t KEY_ROOT[8] = {
    0x4eu, 0x49u, 0x4eu, 0x4cu, 0x49u, 0x4cu, 0x00u, 0x01u
};

_Static_assert(NINLIL_MODEL_RUNTIME_STORE_MAX_PAYLOAD_BYTES
        + NINLIL_MODEL_RUNTIME_STORE_ENVELOPE_OVERHEAD
        == NINLIL_M1A_MAX_STORAGE_VALUE_BYTES,
    "storage value boundary drift");
_Static_assert(2u * (16u + 9u)
        + 15u * (16u + 10u)
        + NINLIL_MODEL_RUNTIME_STORE_BINDING_VALUE_BYTES
        + NINLIL_MODEL_RUNTIME_STORE_IDENTITY_VALUE_BYTES
        + 4u * NINLIL_MODEL_RUNTIME_STORE_COUNTER_VALUE_BYTES
        + 11u * NINLIL_MODEL_RUNTIME_STORE_CAPACITY_VALUE_BYTES
        == NINLIL_MODEL_RUNTIME_STORE_BOOTSTRAP_LOGICAL_BYTES,
    "bootstrap logical byte total drift");

static int ranges_are_disjoint(
    const void *left, size_t left_length,
    const void *right, size_t right_length)
{
    uintptr_t left_start;
    uintptr_t right_start;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left_length == 0u || right_length == 0u) {
        return 1;
    }
    if (left == NULL || right == NULL) {
        return 0;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_length > UINTPTR_MAX - left_start
        || right_length > UINTPTR_MAX - right_start) {
        return 0;
    }
    left_end = left_start + left_length;
    right_end = right_start + right_length;
    return left_end <= right_start || right_end <= left_start;
}

static int encode_ranges_are_disjoint(
    const void *input, size_t input_length,
    uint8_t *out_bytes, uint32_t capacity,
    uint32_t *out_length)
{
    const int has_input_range = input != NULL && input_length != 0u;
    const int has_output_range = out_bytes != NULL && capacity != 0u;

    return (!has_input_range
            || ranges_are_disjoint(input, input_length,
                out_length, sizeof(*out_length)))
        && (!has_output_range
            || ranges_are_disjoint(out_bytes, capacity,
                out_length, sizeof(*out_length)))
        && (!has_input_range || !has_output_range
            || ranges_are_disjoint(input, input_length,
                out_bytes, capacity));
}

static int record_type_is_known(uint32_t type)
{
    return type >= NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING
        && type <= NINLIL_MODEL_RUNTIME_STORE_RECORD_CAPACITY;
}

static int bytes_view_shape_is_valid(ninlil_bytes_view_t view)
{
    return (view.length == 0u && view.data == NULL)
        || (view.length > 0u && view.data != NULL);
}

static void encode_u16_be(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)(value >> 8u);
    destination[1] = (uint8_t)value;
}

static void encode_u32_be(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)(value >> 24u);
    destination[1] = (uint8_t)(value >> 16u);
    destination[2] = (uint8_t)(value >> 8u);
    destination[3] = (uint8_t)value;
}

static void encode_u64_be(uint8_t *destination, uint64_t value)
{
    encode_u32_be(destination, (uint32_t)(value >> 32u));
    encode_u32_be(&destination[4], (uint32_t)value);
}

static uint16_t decode_u16_be(const uint8_t *source)
{
    return (uint16_t)(((uint16_t)source[0] << 8u) | source[1]);
}

static uint32_t decode_u32_be(const uint8_t *source)
{
    return ((uint32_t)source[0] << 24u)
        | ((uint32_t)source[1] << 16u)
        | ((uint32_t)source[2] << 8u)
        | (uint32_t)source[3];
}

static uint64_t decode_u64_be(const uint8_t *source)
{
    return ((uint64_t)decode_u32_be(source) << 32u)
        | (uint64_t)decode_u32_be(&source[4]);
}

static int id_is_nonzero(const ninlil_id128_t *id)
{
    size_t index;
    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

ninlil_status_t ninlil_model_runtime_store_build_key(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_model_runtime_store_key_t *out_key)
{
    uint8_t family;
    uint8_t suffix = 0u;

    if (out_key == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_key, 0, sizeof(*out_key));
    if (key_id < NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING
        || key_id > NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    if (key_id == NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING) {
        family = 0x01u;
    } else if (key_id == NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY) {
        family = 0x02u;
    } else if (key_id <= NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER) {
        family = 0x03u;
        suffix = (uint8_t)(key_id
            - NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION + 1u);
    } else {
        family = 0x04u;
        suffix = (uint8_t)(key_id
            - NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE + 1u);
    }

    (void)memcpy(out_key->bytes, KEY_ROOT, sizeof(KEY_ROOT));
    out_key->bytes[8] = family;
    out_key->length = 9u;
    if (suffix != 0u) {
        out_key->bytes[9] = suffix;
        out_key->length = 10u;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_parse_key(
    ninlil_bytes_view_t encoded_key,
    ninlil_model_runtime_store_key_id_t *out_key_id)
{
    uint8_t suffix;

    if (out_key_id == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!bytes_view_shape_is_valid(encoded_key)) {
        *out_key_id = (ninlil_model_runtime_store_key_id_t)0;
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(encoded_key.data, encoded_key.length,
            out_key_id, sizeof(*out_key_id))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_key_id = (ninlil_model_runtime_store_key_id_t)0;
    if (encoded_key.length < 8u
        || memcmp(encoded_key.data, KEY_ROOT, 7u) != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (encoded_key.data[7] != KEY_ROOT[7]) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (encoded_key.length >= 9u
        && (encoded_key.data[8] == 0x05u
            || encoded_key.data[8] == 0x06u)) {
        return NINLIL_E_UNSUPPORTED;
    }
    if ((encoded_key.length != 9u && encoded_key.length != 10u)
        || memcmp(encoded_key.data, KEY_ROOT, sizeof(KEY_ROOT)) != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (encoded_key.length == 9u && encoded_key.data[8] == 0x01u) {
        *out_key_id = NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING;
        return NINLIL_OK;
    }
    if (encoded_key.length == 9u && encoded_key.data[8] == 0x02u) {
        *out_key_id = NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY;
        return NINLIL_OK;
    }
    if (encoded_key.length != 10u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    suffix = encoded_key.data[9];
    if (encoded_key.data[8] == 0x03u && suffix >= 1u && suffix <= 4u) {
        *out_key_id = (ninlil_model_runtime_store_key_id_t)(
            NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION
            + suffix - 1u);
        return NINLIL_OK;
    }
    if (encoded_key.data[8] == 0x04u && suffix >= 1u && suffix <= 11u) {
        *out_key_id = (ninlil_model_runtime_store_key_id_t)(
            NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE
            + suffix - 1u);
        return NINLIL_OK;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

ninlil_status_t ninlil_model_runtime_store_record_type_for_key(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_model_runtime_store_record_type_t *out_type)
{
    if (out_type == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_type = (ninlil_model_runtime_store_record_type_t)0;
    if (key_id == NINLIL_MODEL_RUNTIME_STORE_KEY_BINDING) {
        *out_type = NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING;
    } else if (key_id == NINLIL_MODEL_RUNTIME_STORE_KEY_IDENTITY) {
        *out_type = NINLIL_MODEL_RUNTIME_STORE_RECORD_IDENTITY;
    } else if (key_id >= NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION
        && key_id <= NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER) {
        *out_type = NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER;
    } else if (key_id >= NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE
        && key_id <= NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN) {
        *out_type = NINLIL_MODEL_RUNTIME_STORE_RECORD_CAPACITY;
    } else {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    return NINLIL_OK;
}

uint32_t ninlil_model_runtime_store_crc32c(
    const uint8_t *bytes,
    uint32_t length)
{
    uint32_t crc = UINT32_MAX;
    uint32_t index;

    if (bytes == NULL && length != 0u) {
        return 0u;
    }
    for (index = 0u; index < length; ++index) {
        uint32_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1u) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

ninlil_status_t ninlil_model_runtime_store_encode_envelope(
    ninlil_model_runtime_store_record_type_t type,
    ninlil_bytes_view_t payload,
    uint8_t *out_bytes,
    uint32_t capacity,
    uint32_t *out_length)
{
    uint32_t required;
    uint32_t crc;

    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_ranges_are_disjoint(payload.data, payload.length,
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || !record_type_is_known((uint32_t)type)
        || !bytes_view_shape_is_valid(payload)
        || payload.length > NINLIL_MODEL_RUNTIME_STORE_MAX_PAYLOAD_BYTES) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    required = NINLIL_MODEL_RUNTIME_STORE_ENVELOPE_OVERHEAD + payload.length;
    if (capacity < required) {
        *out_length = required;
        return NINLIL_E_BUFFER_TOO_SMALL;
    }

    out_bytes[0] = (uint8_t)'N';
    out_bytes[1] = (uint8_t)'L';
    out_bytes[2] = (uint8_t)'R';
    out_bytes[3] = (uint8_t)'1';
    encode_u16_be(&out_bytes[4], (uint16_t)type);
    encode_u16_be(&out_bytes[6], 1u);
    encode_u32_be(&out_bytes[8], payload.length);
    if (payload.length != 0u) {
        (void)memcpy(&out_bytes[12], payload.data, payload.length);
    }
    crc = ninlil_model_runtime_store_crc32c(
        out_bytes, 12u + payload.length);
    encode_u32_be(&out_bytes[12u + payload.length], crc);
    *out_length = required;
    return NINLIL_OK;
}

static ninlil_status_t decode_envelope_expected(
    ninlil_bytes_view_t encoded,
    uint16_t expected_type,
    ninlil_model_runtime_store_envelope_t *out_envelope)
{
    uint16_t raw_type;
    uint16_t version;
    uint32_t payload_length;
    uint32_t stored_crc;
    uint32_t computed_crc;

    if (out_envelope == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!bytes_view_shape_is_valid(encoded)) {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(encoded.data, encoded.length,
            out_envelope, sizeof(*out_envelope))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_envelope, 0, sizeof(*out_envelope));
    if (encoded.length < NINLIL_MODEL_RUNTIME_STORE_ENVELOPE_OVERHEAD
        || memcmp(encoded.data, "NLR1", 4u) != 0) {
        return NINLIL_E_STORAGE_CORRUPT;
    }

    raw_type = decode_u16_be(&encoded.data[4]);
    version = decode_u16_be(&encoded.data[6]);
    payload_length = decode_u32_be(&encoded.data[8]);
    if (payload_length > NINLIL_MODEL_RUNTIME_STORE_MAX_PAYLOAD_BYTES
        || payload_length
            != encoded.length - NINLIL_MODEL_RUNTIME_STORE_ENVELOPE_OVERHEAD) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    stored_crc = decode_u32_be(&encoded.data[12u + payload_length]);
    computed_crc = ninlil_model_runtime_store_crc32c(
        encoded.data, 12u + payload_length);
    if (stored_crc != computed_crc) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (!record_type_is_known(raw_type)) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (expected_type != 0u && raw_type != expected_type) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (version != 1u) {
        return NINLIL_E_UNSUPPORTED;
    }

    out_envelope->type =
        (ninlil_model_runtime_store_record_type_t)raw_type;
    out_envelope->version = version;
    out_envelope->payload.data = payload_length == 0u
        ? NULL : &encoded.data[12];
    out_envelope->payload.length = payload_length;
    out_envelope->crc32c = stored_crc;
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_decode_envelope(
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_envelope_t *out_envelope)
{
    return decode_envelope_expected(encoded, 0u, out_envelope);
}

static ninlil_status_t decode_typed_envelope(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_model_runtime_store_record_type_t expected_type,
    uint32_t expected_payload_length,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_envelope_t *out_envelope)
{
    ninlil_model_runtime_store_record_type_t key_type;
    ninlil_status_t status = ninlil_model_runtime_store_record_type_for_key(
        key_id, &key_type);

    if (status != NINLIL_OK) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (key_type != expected_type) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    status = decode_envelope_expected(
        encoded, (uint16_t)expected_type, out_envelope);
    if (status != NINLIL_OK) {
        return status;
    }
    if (out_envelope->type != expected_type
        || out_envelope->payload.length != expected_payload_length) {
        (void)memset(out_envelope, 0, sizeof(*out_envelope));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static int identity_is_valid(
    const ninlil_model_runtime_store_identity_t *identity)
{
    const uint32_t known = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    const int installation = (identity->flags
        & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u;

    return (identity->flags & ~known) == 0u
        && (identity->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u
        && (identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u
        && id_is_nonzero(&identity->device_id)
        && installation == id_is_nonzero(&identity->installation_id)
        && id_is_nonzero(&identity->site_domain_id)
        && identity->binding_epoch != 0u
        && identity->membership_epoch != 0u;
}

static int counter_is_valid(
    ninlil_model_runtime_store_key_id_t key_id,
    const ninlil_model_runtime_store_counter_t *counter)
{
    uint32_t expected;
    if (key_id < NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION
        || key_id > NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_VISITED_OWNER) {
        return 0;
    }
    expected = (uint32_t)(key_id
        - NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION + 1u);
    return (uint32_t)counter->kind == expected
        && counter->exhausted_marker <= 1u
        && (counter->kind != NINLIL_MODEL_RUNTIME_STORE_COUNTER_VISITED_OWNER
            || counter->exhausted_marker == 0u)
        && (counter->exhausted_marker == 0u
            || counter->value == UINT64_MAX);
}

static int capacity_is_valid(
    ninlil_model_runtime_store_key_id_t key_id,
    const ninlil_model_runtime_store_capacity_t *entry)
{
    uint32_t expected;
    uint64_t total;
    if (key_id < NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE
        || key_id > NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_DEFERRED_TOKEN) {
        return 0;
    }
    expected = (uint32_t)(key_id
        - NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE + 1u);
    if ((uint32_t)entry->kind != expected
        || entry->blocked > 1u || entry->counter_exhausted > 1u
        || entry->capacity_epoch == 0u
        || entry->used > UINT64_MAX - entry->reserved) {
        return 0;
    }
    total = entry->used + entry->reserved;
    return total <= entry->high_water
        && entry->high_water <= entry->limit
        && (entry->counter_exhausted == 0u
            || (entry->capacity_epoch == UINT64_MAX
                && entry->blocked == 0u));
}

ninlil_status_t ninlil_model_runtime_store_encode_binding(
    const ninlil_model_runtime_store_binding_t *binding,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    static const uint8_t PROFILE[] = "NINLIL-FOUNDATION-SMALL-1";
    uint8_t payload[NINLIL_MODEL_RUNTIME_STORE_BINDING_PAYLOAD_BYTES];
    uint32_t offset = 0u;
    _Static_assert(sizeof(PROFILE) == 26u,
        "binding profile name drift");
    _Static_assert(31u + 12u + 16u + 84u + 24u
        == NINLIL_MODEL_RUNTIME_STORE_BINDING_PAYLOAD_BYTES,
        "binding payload layout drift");
#define PUT_BIND_U32(field)                                                 \
    do {                                                                    \
        encode_u32_be(&payload[offset], (field));                            \
        offset += 4u;                                                       \
    } while (0)
#define PUT_BIND_U64(field)                                                 \
    do {                                                                    \
        encode_u64_be(&payload[offset], (field));                            \
        offset += 8u;                                                       \
    } while (0)
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_ranges_are_disjoint(binding,
            binding == NULL ? 0u : sizeof(*binding),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || binding == NULL || !id_is_nonzero(&binding->runtime_id)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    PUT_BIND_U32(1u);
    encode_u16_be(&payload[offset], 25u);
    offset += 2u;
    (void)memcpy(&payload[offset], PROFILE, 25u);
    offset += 25u;
    PUT_BIND_U32(binding->storage_schema);
    PUT_BIND_U32(binding->role);
    PUT_BIND_U32(binding->environment);
    (void)memcpy(&payload[offset], binding->runtime_id.bytes, 16u);
    offset += 16u;
    PUT_BIND_U32(binding->limits.max_services);
    PUT_BIND_U32(binding->limits.max_nonterminal_transactions);
    PUT_BIND_U32(binding->limits.max_targets_per_transaction);
    PUT_BIND_U32(binding->limits.max_logical_payload_bytes);
    PUT_BIND_U64(binding->limits.max_durable_outbox_payload_bytes);
    PUT_BIND_U32(binding->limits.max_attempts_per_target_per_cycle);
    PUT_BIND_U32(binding->limits.max_cancel_attempts_per_transaction);
    PUT_BIND_U32(binding->limits.max_evidence_per_target);
    PUT_BIND_U32(binding->limits.max_retained_terminal_transactions);
    PUT_BIND_U32(binding->limits.max_nonterminal_deliveries);
    PUT_BIND_U32(binding->limits.max_event_spool_count);
    PUT_BIND_U64(binding->limits.max_event_spool_bytes);
    PUT_BIND_U32(binding->limits.max_result_cache_entries);
    PUT_BIND_U32(binding->limits.max_retained_dispositions);
    PUT_BIND_U32(binding->limits.max_ingress_per_step);
    PUT_BIND_U32(binding->limits.max_callbacks_per_step);
    PUT_BIND_U32(binding->limits.max_state_transitions_per_step);
    PUT_BIND_U32(binding->limits.max_bearer_sends_per_step);
    PUT_BIND_U32(binding->limits.max_deferred_tokens);
    PUT_BIND_U64(binding->terminal_retention_ms);
    PUT_BIND_U64(binding->result_cache_retention_ms);
    PUT_BIND_U64(binding->observation_retention_ms);
#undef PUT_BIND_U32
#undef PUT_BIND_U64
    return ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        (ninlil_bytes_view_t){payload, sizeof(payload)},
        out_bytes, capacity, out_length);
}

ninlil_status_t ninlil_model_runtime_store_decode_binding(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_binding_t *out_binding)
{
    static const uint8_t PROFILE[] = "NINLIL-FOUNDATION-SMALL-1";
    ninlil_model_runtime_store_envelope_t envelope;
    const uint8_t *payload;
    uint32_t offset = 0u;
    ninlil_status_t status;
#define GET_BIND_U32(field)                                                 \
    do {                                                                    \
        (field) = decode_u32_be(&payload[offset]);                           \
        offset += 4u;                                                       \
    } while (0)
#define GET_BIND_U64(field)                                                 \
    do {                                                                    \
        (field) = decode_u64_be(&payload[offset]);                           \
        offset += 8u;                                                       \
    } while (0)
    if (out_binding == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!bytes_view_shape_is_valid(encoded)) {
        (void)memset(out_binding, 0, sizeof(*out_binding));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(encoded.data, encoded.length,
            out_binding, sizeof(*out_binding))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_binding, 0, sizeof(*out_binding));
    status = decode_typed_envelope(key_id,
        NINLIL_MODEL_RUNTIME_STORE_RECORD_BINDING,
        NINLIL_MODEL_RUNTIME_STORE_BINDING_PAYLOAD_BYTES,
        encoded, &envelope);
    if (status != NINLIL_OK) {
        return status;
    }
    payload = envelope.payload.data;
    if (decode_u32_be(payload) != 1u
        || decode_u16_be(&payload[4]) != 25u
        || memcmp(&payload[6], PROFILE, 25u) != 0) {
        return NINLIL_E_UNSUPPORTED;
    }
    offset = 31u;
    GET_BIND_U32(out_binding->storage_schema);
    GET_BIND_U32(out_binding->role);
    GET_BIND_U32(out_binding->environment);
    (void)memcpy(out_binding->runtime_id.bytes, &payload[offset], 16u);
    offset += 16u;
    GET_BIND_U32(out_binding->limits.max_services);
    GET_BIND_U32(out_binding->limits.max_nonterminal_transactions);
    GET_BIND_U32(out_binding->limits.max_targets_per_transaction);
    GET_BIND_U32(out_binding->limits.max_logical_payload_bytes);
    GET_BIND_U64(out_binding->limits.max_durable_outbox_payload_bytes);
    GET_BIND_U32(out_binding->limits.max_attempts_per_target_per_cycle);
    GET_BIND_U32(out_binding->limits.max_cancel_attempts_per_transaction);
    GET_BIND_U32(out_binding->limits.max_evidence_per_target);
    GET_BIND_U32(out_binding->limits.max_retained_terminal_transactions);
    GET_BIND_U32(out_binding->limits.max_nonterminal_deliveries);
    GET_BIND_U32(out_binding->limits.max_event_spool_count);
    GET_BIND_U64(out_binding->limits.max_event_spool_bytes);
    GET_BIND_U32(out_binding->limits.max_result_cache_entries);
    GET_BIND_U32(out_binding->limits.max_retained_dispositions);
    GET_BIND_U32(out_binding->limits.max_ingress_per_step);
    GET_BIND_U32(out_binding->limits.max_callbacks_per_step);
    GET_BIND_U32(out_binding->limits.max_state_transitions_per_step);
    GET_BIND_U32(out_binding->limits.max_bearer_sends_per_step);
    GET_BIND_U32(out_binding->limits.max_deferred_tokens);
    GET_BIND_U64(out_binding->terminal_retention_ms);
    GET_BIND_U64(out_binding->result_cache_retention_ms);
    GET_BIND_U64(out_binding->observation_retention_ms);
#undef GET_BIND_U32
#undef GET_BIND_U64
    if (offset != envelope.payload.length
        || !id_is_nonzero(&out_binding->runtime_id)) {
        (void)memset(out_binding, 0, sizeof(*out_binding));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_encode_identity(
    const ninlil_model_runtime_store_identity_t *identity,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    uint8_t payload[NINLIL_MODEL_RUNTIME_STORE_IDENTITY_PAYLOAD_BYTES];
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_ranges_are_disjoint(identity,
            identity == NULL ? 0u : sizeof(*identity),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || identity == NULL || !identity_is_valid(identity)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    encode_u32_be(payload, identity->flags);
    (void)memcpy(&payload[4], identity->device_id.bytes, 16u);
    (void)memcpy(&payload[20], identity->installation_id.bytes, 16u);
    (void)memcpy(&payload[36], identity->site_domain_id.bytes, 16u);
    encode_u64_be(&payload[52], identity->binding_epoch);
    encode_u64_be(&payload[60], identity->membership_epoch);
    return ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_IDENTITY,
        (ninlil_bytes_view_t){payload, sizeof(payload)},
        out_bytes, capacity, out_length);
}

ninlil_status_t ninlil_model_runtime_store_decode_identity(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_identity_t *out_identity)
{
    ninlil_model_runtime_store_envelope_t envelope;
    ninlil_status_t status;
    const uint8_t *p;
    if (out_identity == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!bytes_view_shape_is_valid(encoded)) {
        (void)memset(out_identity, 0, sizeof(*out_identity));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(encoded.data, encoded.length,
            out_identity, sizeof(*out_identity))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_identity, 0, sizeof(*out_identity));
    status = decode_typed_envelope(key_id,
        NINLIL_MODEL_RUNTIME_STORE_RECORD_IDENTITY,
        NINLIL_MODEL_RUNTIME_STORE_IDENTITY_PAYLOAD_BYTES, encoded, &envelope);
    if (status != NINLIL_OK) {
        return status;
    }
    p = envelope.payload.data;
    out_identity->flags = decode_u32_be(p);
    (void)memcpy(out_identity->device_id.bytes, &p[4], 16u);
    (void)memcpy(out_identity->installation_id.bytes, &p[20], 16u);
    (void)memcpy(out_identity->site_domain_id.bytes, &p[36], 16u);
    out_identity->binding_epoch = decode_u64_be(&p[52]);
    out_identity->membership_epoch = decode_u64_be(&p[60]);
    if (!identity_is_valid(out_identity)) {
        (void)memset(out_identity, 0, sizeof(*out_identity));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_encode_counter(
    ninlil_model_runtime_store_key_id_t key_id,
    const ninlil_model_runtime_store_counter_t *counter,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    uint8_t payload[NINLIL_MODEL_RUNTIME_STORE_COUNTER_PAYLOAD_BYTES];
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_ranges_are_disjoint(counter,
            counter == NULL ? 0u : sizeof(*counter),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || counter == NULL || !counter_is_valid(key_id, counter)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    encode_u32_be(payload, (uint32_t)counter->kind);
    encode_u64_be(&payload[4], counter->value);
    encode_u32_be(&payload[12], counter->exhausted_marker);
    return ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER,
        (ninlil_bytes_view_t){payload, sizeof(payload)},
        out_bytes, capacity, out_length);
}

ninlil_status_t ninlil_model_runtime_store_decode_counter(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_counter_t *out_counter)
{
    ninlil_model_runtime_store_envelope_t envelope;
    ninlil_status_t status;
    const uint8_t *p;
    uint32_t raw_kind;
    uint32_t expected_kind;
    if (out_counter == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!bytes_view_shape_is_valid(encoded)) {
        (void)memset(out_counter, 0, sizeof(*out_counter));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(encoded.data, encoded.length,
            out_counter, sizeof(*out_counter))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_counter, 0, sizeof(*out_counter));
    status = decode_typed_envelope(key_id,
        NINLIL_MODEL_RUNTIME_STORE_RECORD_COUNTER,
        NINLIL_MODEL_RUNTIME_STORE_COUNTER_PAYLOAD_BYTES, encoded, &envelope);
    if (status != NINLIL_OK) {
        return status;
    }
    p = envelope.payload.data;
    raw_kind = decode_u32_be(p);
    expected_kind = (uint32_t)(key_id
        - NINLIL_MODEL_RUNTIME_STORE_KEY_COUNTER_TRANSACTION + 1u);
    if (raw_kind < 1u || raw_kind > 4u || raw_kind != expected_kind) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_counter->kind =
        (ninlil_model_runtime_store_counter_kind_t)raw_kind;
    out_counter->value = decode_u64_be(&p[4]);
    out_counter->exhausted_marker = decode_u32_be(&p[12]);
    if (!counter_is_valid(key_id, out_counter)) {
        (void)memset(out_counter, 0, sizeof(*out_counter));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

ninlil_status_t ninlil_model_runtime_store_encode_capacity(
    ninlil_model_runtime_store_key_id_t key_id,
    const ninlil_model_runtime_store_capacity_t *entry,
    uint8_t *out_bytes, uint32_t capacity, uint32_t *out_length)
{
    uint8_t payload[NINLIL_MODEL_RUNTIME_STORE_CAPACITY_PAYLOAD_BYTES];
    if (out_length == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_ranges_are_disjoint(entry,
            entry == NULL ? 0u : sizeof(*entry),
            out_bytes, capacity, out_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *out_length = 0u;
    if ((capacity == 0u && out_bytes != NULL)
        || (capacity > 0u && out_bytes == NULL)
        || entry == NULL || !capacity_is_valid(key_id, entry)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    encode_u32_be(payload, entry->kind);
    encode_u64_be(&payload[4], entry->limit);
    encode_u64_be(&payload[12], entry->used);
    encode_u64_be(&payload[20], entry->reserved);
    encode_u64_be(&payload[28], entry->high_water);
    encode_u64_be(&payload[36], entry->capacity_epoch);
    encode_u32_be(&payload[44], entry->blocked);
    encode_u32_be(&payload[48], entry->counter_exhausted);
    return ninlil_model_runtime_store_encode_envelope(
        NINLIL_MODEL_RUNTIME_STORE_RECORD_CAPACITY,
        (ninlil_bytes_view_t){payload, sizeof(payload)},
        out_bytes, capacity, out_length);
}

ninlil_status_t ninlil_model_runtime_store_decode_capacity(
    ninlil_model_runtime_store_key_id_t key_id,
    ninlil_bytes_view_t encoded,
    ninlil_model_runtime_store_capacity_t *out_entry)
{
    ninlil_model_runtime_store_envelope_t envelope;
    ninlil_status_t status;
    const uint8_t *p;
    uint32_t raw_kind;
    uint32_t expected_kind;
    if (out_entry == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!bytes_view_shape_is_valid(encoded)) {
        (void)memset(out_entry, 0, sizeof(*out_entry));
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!ranges_are_disjoint(encoded.data, encoded.length,
            out_entry, sizeof(*out_entry))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memset(out_entry, 0, sizeof(*out_entry));
    status = decode_typed_envelope(key_id,
        NINLIL_MODEL_RUNTIME_STORE_RECORD_CAPACITY,
        NINLIL_MODEL_RUNTIME_STORE_CAPACITY_PAYLOAD_BYTES, encoded, &envelope);
    if (status != NINLIL_OK) {
        return status;
    }
    p = envelope.payload.data;
    raw_kind = decode_u32_be(p);
    expected_kind = (uint32_t)(key_id
        - NINLIL_MODEL_RUNTIME_STORE_KEY_CAPACITY_SERVICE + 1u);
    if (raw_kind < 1u || raw_kind > 11u || raw_kind != expected_kind) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    out_entry->kind = (ninlil_resource_kind_t)raw_kind;
    out_entry->limit = decode_u64_be(&p[4]);
    out_entry->used = decode_u64_be(&p[12]);
    out_entry->reserved = decode_u64_be(&p[20]);
    out_entry->high_water = decode_u64_be(&p[28]);
    out_entry->capacity_epoch = decode_u64_be(&p[36]);
    out_entry->blocked = decode_u32_be(&p[44]);
    out_entry->counter_exhausted = decode_u32_be(&p[48]);
    if (!capacity_is_valid(key_id, out_entry)) {
        (void)memset(out_entry, 0, sizeof(*out_entry));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}
