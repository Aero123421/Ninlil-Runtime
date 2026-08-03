#include "nvb1_codec.h"

#include <stdint.h>
#include <string.h>

static const uint8_t k_nvb1_magic[4] = {'N', 'V', 'B', '1'};

static int nvb1_add_ok(uintptr_t base, size_t length, uintptr_t *end)
{
    if (length > (size_t)(UINTPTR_MAX - base)) {
        return 0;
    }
    *end = base + (uintptr_t)length;
    return 1;
}

static int nvb1_disjoint(
    const void *a, size_t a_length, const void *b, size_t b_length)
{
    uintptr_t ab;
    uintptr_t ae;
    uintptr_t bb;
    uintptr_t be;

    if (a_length == 0u || b_length == 0u) {
        return 1;
    }
    if (a == NULL || b == NULL) {
        return 0;
    }
    ab = (uintptr_t)a;
    bb = (uintptr_t)b;
    if (!nvb1_add_ok(ab, a_length, &ae)
        || !nvb1_add_ok(bb, b_length, &be)) {
        return 0;
    }
    return ae <= bb || be <= ab;
}

static void nvb1_put_u32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static void nvb1_put_u64(uint8_t *out, uint64_t value)
{
    size_t i;
    for (i = 0u; i < 8u; ++i) {
        out[i] = (uint8_t)(value >> (56u - (unsigned)(8u * i)));
    }
}

static uint32_t nvb1_get_u32(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t nvb1_get_u64(const uint8_t *in)
{
    uint64_t value = 0u;
    size_t i;
    for (i = 0u; i < 8u; ++i) {
        value = (value << 8) | (uint64_t)in[i];
    }
    return value;
}

static int nvb1_payload_length_valid(uint8_t kind, size_t length)
{
    if (kind == NINLIL_NVB1_KIND_BINDING_SET) {
        return length >= NINLIL_NVB1_BINDING_MIN
            && length <= NINLIL_NVB1_BINDING_MAX;
    }
    if (kind == NINLIL_NVB1_KIND_FABRIC_PACKET) {
        return length >= NINLIL_NVB1_FABRIC_MIN
            && length <= NINLIL_NVB1_FABRIC_MAX;
    }
    if (kind == NINLIL_NVB1_KIND_STATUS) {
        return length == NINLIL_NVB1_STATUS_BYTES;
    }
    if (kind == NINLIL_NVB1_KIND_BOARD_INFO) {
        return length == NINLIL_NVB1_BOARD_INFO_BYTES;
    }
    return 0;
}

static int nvb1_nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t i;

    if (bytes == NULL) {
        return 0;
    }
    for (i = 0u; i < length; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any != 0u;
}

static int nvb1_status_code_valid(uint32_t code)
{
    return code >= NINLIL_NVB1_STATUS_INSTALLED
        && code <= NINLIL_NVB1_STATUS_REPROVISION_REQUIRED;
}

ninlil_nvb1_status_t ninlil_nvb1_encode(
    const ninlil_nvb1_envelope_t *envelope,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_length)
{
    size_t required;

    if (envelope == NULL || out == NULL || out_length == NULL) {
        return NINLIL_NVB1_INVALID_ARGUMENT;
    }
    if (envelope->payload == NULL || envelope->operation_id == 0u
        || !nvb1_payload_length_valid(
            envelope->kind, envelope->payload_length)) {
        *out_length = 0u;
        return NINLIL_NVB1_STRUCTURAL;
    }
    required = NINLIL_NVB1_HEADER_BYTES + envelope->payload_length;
    if (!nvb1_disjoint(
            envelope->payload, envelope->payload_length, out, out_capacity)
        || !nvb1_disjoint(
            envelope, sizeof(*envelope), out, out_capacity)
        || !nvb1_disjoint(
            out_length, sizeof(*out_length), out, out_capacity)) {
        return NINLIL_NVB1_ALIAS;
    }
    if (out_capacity < required) {
        *out_length = required;
        return NINLIL_NVB1_CAPACITY;
    }

    (void)memcpy(out, k_nvb1_magic, sizeof(k_nvb1_magic));
    out[4] = 1u;
    out[5] = envelope->kind;
    out[6] = 0u;
    out[7] = 0u;
    nvb1_put_u64(out + 8u, envelope->operation_id);
    (void)memcpy(
        out + NINLIL_NVB1_HEADER_BYTES,
        envelope->payload,
        envelope->payload_length);
    *out_length = required;
    return NINLIL_NVB1_OK;
}

ninlil_nvb1_status_t ninlil_nvb1_decode(
    const uint8_t *encoded,
    size_t encoded_length,
    ninlil_nvb1_envelope_t *out_envelope)
{
    ninlil_nvb1_envelope_t candidate;
    size_t payload_length;

    if (encoded == NULL || out_envelope == NULL) {
        return NINLIL_NVB1_INVALID_ARGUMENT;
    }
    if (!nvb1_disjoint(
            encoded, encoded_length, out_envelope, sizeof(*out_envelope))) {
        return NINLIL_NVB1_ALIAS;
    }
    if (encoded_length < NINLIL_NVB1_HEADER_BYTES
        || encoded_length > NINLIL_NVB1_ENVELOPE_MAX) {
        return NINLIL_NVB1_LENGTH;
    }
    payload_length = encoded_length - NINLIL_NVB1_HEADER_BYTES;
    if (memcmp(encoded, k_nvb1_magic, sizeof(k_nvb1_magic)) != 0
        || encoded[4] != 1u || encoded[6] != 0u || encoded[7] != 0u
        || nvb1_get_u64(encoded + 8u) == 0u
        || !nvb1_payload_length_valid(encoded[5], payload_length)) {
        return NINLIL_NVB1_STRUCTURAL;
    }

    (void)memset(&candidate, 0, sizeof(candidate));
    candidate.kind = encoded[5];
    candidate.operation_id = nvb1_get_u64(encoded + 8u);
    candidate.payload = encoded + NINLIL_NVB1_HEADER_BYTES;
    candidate.payload_length = payload_length;
    *out_envelope = candidate;
    return NINLIL_NVB1_OK;
}

ninlil_nvb1_status_t ninlil_nvb1_status_encode(
    const ninlil_nvb1_local_status_t *status,
    uint8_t out[NINLIL_NVB1_STATUS_BYTES])
{
    if (status == NULL || out == NULL) {
        return NINLIL_NVB1_INVALID_ARGUMENT;
    }
    if (!nvb1_disjoint(status, sizeof(*status), out, NINLIL_NVB1_STATUS_BYTES)) {
        return NINLIL_NVB1_ALIAS;
    }
    if (!nvb1_status_code_valid(status->code)) {
        return NINLIL_NVB1_STRUCTURAL;
    }
    nvb1_put_u32(out, status->code);
    nvb1_put_u32(out + 4u, 0u);
    nvb1_put_u64(out + 8u, status->pair_generation);
    return NINLIL_NVB1_OK;
}

ninlil_nvb1_status_t ninlil_nvb1_status_decode(
    const uint8_t encoded[NINLIL_NVB1_STATUS_BYTES],
    ninlil_nvb1_local_status_t *out_status)
{
    ninlil_nvb1_local_status_t candidate;

    if (encoded == NULL || out_status == NULL) {
        return NINLIL_NVB1_INVALID_ARGUMENT;
    }
    if (!nvb1_disjoint(
            encoded, NINLIL_NVB1_STATUS_BYTES, out_status, sizeof(*out_status))) {
        return NINLIL_NVB1_ALIAS;
    }
    candidate.code = nvb1_get_u32(encoded);
    candidate.pair_generation = nvb1_get_u64(encoded + 8u);
    if (!nvb1_status_code_valid(candidate.code)
        || nvb1_get_u32(encoded + 4u) != 0u) {
        return NINLIL_NVB1_STRUCTURAL;
    }
    *out_status = candidate;
    return NINLIL_NVB1_OK;
}

ninlil_nvb1_status_t ninlil_nvb1_board_info_encode(
    const ninlil_nvb1_board_info_t *info,
    uint8_t out[NINLIL_NVB1_BOARD_INFO_BYTES])
{
    if (info == NULL || out == NULL) {
        return NINLIL_NVB1_INVALID_ARGUMENT;
    }
    if (!nvb1_disjoint(info, sizeof(*info), out,
            NINLIL_NVB1_BOARD_INFO_BYTES)) {
        return NINLIL_NVB1_ALIAS;
    }
    if (!nvb1_nonzero(info->clock_epoch_id, 16u)
        || info->clock_trust != 1u) {
        return NINLIL_NVB1_STRUCTURAL;
    }
    (void)memcpy(out, info->clock_epoch_id, 16u);
    nvb1_put_u64(out + 16u, info->clock_now_ms);
    nvb1_put_u32(out + 24u, info->clock_trust);
    nvb1_put_u32(out + 28u, 0u);
    return NINLIL_NVB1_OK;
}

ninlil_nvb1_status_t ninlil_nvb1_board_info_decode(
    const uint8_t encoded[NINLIL_NVB1_BOARD_INFO_BYTES],
    ninlil_nvb1_board_info_t *out_info)
{
    ninlil_nvb1_board_info_t candidate;

    if (encoded == NULL || out_info == NULL) {
        return NINLIL_NVB1_INVALID_ARGUMENT;
    }
    if (!nvb1_disjoint(encoded, NINLIL_NVB1_BOARD_INFO_BYTES,
            out_info, sizeof(*out_info))) {
        return NINLIL_NVB1_ALIAS;
    }
    (void)memset(&candidate, 0, sizeof(candidate));
    (void)memcpy(candidate.clock_epoch_id, encoded, 16u);
    candidate.clock_now_ms = nvb1_get_u64(encoded + 16u);
    candidate.clock_trust = nvb1_get_u32(encoded + 24u);
    if (!nvb1_nonzero(candidate.clock_epoch_id, 16u)
        || candidate.clock_trust != 1u
        || nvb1_get_u32(encoded + 28u) != 0u) {
        return NINLIL_NVB1_STRUCTURAL;
    }
    *out_info = candidate;
    return NINLIL_NVB1_OK;
}
