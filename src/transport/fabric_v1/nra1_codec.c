#include "nra1_codec.h"

#include "ninlil/version.h"

#include <stdint.h>
#include <string.h>

static const uint8_t k_nra1_magic[4] = {'N', 'R', 'A', '1'};

_Static_assert(
    NINLIL_NRA1_APPLICATION_HEADER_BYTES
            + NINLIL_NRA1_APPLICATION_PAYLOAD_MAX
        == NINLIL_NRA1_APPLICATION_BODY_MAX,
    "NRA1 Application maximum must fit NRW1 plaintext");

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    size_t index;

    if (bytes == NULL) {
        return 0;
    }
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static int spans_overlap(
    const void *left,
    size_t left_length,
    const void *right,
    size_t right_length)
{
    uintptr_t left_start;
    uintptr_t right_start;
    uintptr_t left_end;
    uintptr_t right_end;

    if (left_length == 0u || right_length == 0u) {
        return 0;
    }
    if (left == NULL || right == NULL) {
        return 1;
    }
    left_start = (uintptr_t)left;
    right_start = (uintptr_t)right;
    if (left_start > UINTPTR_MAX - left_length
        || right_start > UINTPTR_MAX - right_length) {
        return 1;
    }
    left_end = left_start + left_length;
    right_end = right_start + right_length;
    return left_start < right_end && right_start < left_end;
}

static void store_u64_be(uint8_t out[8], uint64_t value)
{
    out[0] = (uint8_t)(value >> 56);
    out[1] = (uint8_t)(value >> 48);
    out[2] = (uint8_t)(value >> 40);
    out[3] = (uint8_t)(value >> 32);
    out[4] = (uint8_t)(value >> 24);
    out[5] = (uint8_t)(value >> 16);
    out[6] = (uint8_t)(value >> 8);
    out[7] = (uint8_t)value;
}

static uint64_t load_u64_be(const uint8_t in[8])
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

static int service_slot_valid(uint8_t slot)
{
    return slot >= NINLIL_NRA1_SERVICE_SLOT_MIN
        && slot <= NINLIL_NRA1_SERVICE_SLOT_MAX;
}

static int evidence_stage_valid(uint8_t stage)
{
    return stage <= 4u;
}

static int receipt_stage_valid(uint8_t stage)
{
    return stage >= 1u && stage <= 4u;
}

static uint8_t pack_slot_stage(uint8_t service_slot, uint8_t stage)
{
    return (uint8_t)((uint8_t)(service_slot << 3u) | stage);
}

static int common_ids_valid(
    const uint8_t transaction_id[16],
    const uint8_t attempt_id[16])
{
    return bytes_nonzero(transaction_id, 16u)
        && bytes_nonzero(attempt_id, 16u);
}

static int magic_valid(const uint8_t *body)
{
    return memcmp(body, k_nra1_magic, sizeof(k_nra1_magic)) == 0;
}

ninlil_nra1_status_t ninlil_nra1_encode_application(
    const ninlil_nra1_application_t *application,
    uint8_t *out_body,
    size_t out_capacity,
    size_t *out_length)
{
    uint8_t candidate[NINLIL_NRA1_APPLICATION_BODY_MAX];
    size_t body_length;

    if (application == NULL || out_body == NULL || out_length == NULL) {
        return NINLIL_NRA1_INVALID_ARGUMENT;
    }
    if (application->payload_len < NINLIL_NRA1_APPLICATION_PAYLOAD_MIN
        || application->payload_len > NINLIL_NRA1_APPLICATION_PAYLOAD_MAX) {
        return NINLIL_NRA1_LENGTH;
    }
    if (!service_slot_valid(application->service_slot)
        || !evidence_stage_valid(application->required_evidence)
        || !common_ids_valid(
            application->transaction_id, application->attempt_id)) {
        return NINLIL_NRA1_STRUCTURAL;
    }
    body_length = NINLIL_NRA1_APPLICATION_HEADER_BYTES
        + application->payload_len;
    if (out_capacity < body_length) {
        return NINLIL_NRA1_CAPACITY;
    }
    if (spans_overlap(application, sizeof(*application), out_body, out_capacity)
        || spans_overlap(
            application, sizeof(*application), out_length, sizeof(*out_length))
        || spans_overlap(out_body, out_capacity, out_length, sizeof(*out_length))) {
        return NINLIL_NRA1_ALIAS;
    }

    (void)memset(candidate, 0, sizeof(candidate));
    (void)memcpy(candidate, k_nra1_magic, sizeof(k_nra1_magic));
    candidate[4] = NINLIL_NRA1_KIND_APPLICATION;
    candidate[5] = pack_slot_stage(
        application->service_slot, application->required_evidence);
    (void)memcpy(candidate + 6u, application->transaction_id, 16u);
    (void)memcpy(candidate + 22u, application->attempt_id, 16u);
    (void)memcpy(candidate + 38u, application->subject, 16u);
    store_u64_be(candidate + 54u, application->absolute_effect_deadline_ms);
    (void)memcpy(
        candidate + NINLIL_NRA1_APPLICATION_HEADER_BYTES,
        application->payload,
        application->payload_len);

    (void)memcpy(out_body, candidate, body_length);
    *out_length = body_length;
    (void)memset(candidate, 0, sizeof(candidate));
    return NINLIL_NRA1_OK;
}

ninlil_nra1_status_t ninlil_nra1_decode_application(
    const uint8_t *body,
    size_t body_length,
    ninlil_nra1_application_t *out_application)
{
    ninlil_nra1_application_t candidate;
    uint8_t packed;

    if (body == NULL || out_application == NULL) {
        return NINLIL_NRA1_INVALID_ARGUMENT;
    }
    if (body_length < NINLIL_NRA1_APPLICATION_BODY_MIN
        || body_length > NINLIL_NRA1_APPLICATION_BODY_MAX) {
        return NINLIL_NRA1_LENGTH;
    }
    if (spans_overlap(body, body_length, out_application, sizeof(*out_application))) {
        return NINLIL_NRA1_ALIAS;
    }
    if (!magic_valid(body) || body[4] != NINLIL_NRA1_KIND_APPLICATION) {
        return NINLIL_NRA1_STRUCTURAL;
    }
    packed = body[5];
    if (!service_slot_valid((uint8_t)(packed >> 3u))
        || !evidence_stage_valid((uint8_t)(packed & 0x07u))
        || !common_ids_valid(body + 6u, body + 22u)) {
        return NINLIL_NRA1_STRUCTURAL;
    }

    (void)memset(&candidate, 0, sizeof(candidate));
    candidate.service_slot = (uint8_t)(packed >> 3u);
    candidate.required_evidence = (uint8_t)(packed & 0x07u);
    (void)memcpy(candidate.transaction_id, body + 6u, 16u);
    (void)memcpy(candidate.attempt_id, body + 22u, 16u);
    (void)memcpy(candidate.subject, body + 38u, 16u);
    candidate.absolute_effect_deadline_ms = load_u64_be(body + 54u);
    candidate.payload_len =
        body_length - NINLIL_NRA1_APPLICATION_HEADER_BYTES;
    (void)memcpy(
        candidate.payload,
        body + NINLIL_NRA1_APPLICATION_HEADER_BYTES,
        candidate.payload_len);
    *out_application = candidate;
    (void)memset(&candidate, 0, sizeof(candidate));
    return NINLIL_NRA1_OK;
}

ninlil_nra1_status_t ninlil_nra1_encode_receipt(
    const ninlil_nra1_receipt_t *receipt,
    uint8_t *out_body,
    size_t out_capacity,
    size_t *out_length)
{
    uint8_t candidate[NINLIL_NRA1_RECEIPT_BODY_BYTES];

    if (receipt == NULL || out_body == NULL || out_length == NULL) {
        return NINLIL_NRA1_INVALID_ARGUMENT;
    }
    if (!service_slot_valid(receipt->service_slot)
        || !receipt_stage_valid(receipt->receipt_stage)
        || !common_ids_valid(receipt->transaction_id, receipt->attempt_id)) {
        return NINLIL_NRA1_STRUCTURAL;
    }
    if (out_capacity < NINLIL_NRA1_RECEIPT_BODY_BYTES) {
        return NINLIL_NRA1_CAPACITY;
    }
    if (spans_overlap(receipt, sizeof(*receipt), out_body, out_capacity)
        || spans_overlap(receipt, sizeof(*receipt), out_length, sizeof(*out_length))
        || spans_overlap(out_body, out_capacity, out_length, sizeof(*out_length))) {
        return NINLIL_NRA1_ALIAS;
    }

    (void)memset(candidate, 0, sizeof(candidate));
    (void)memcpy(candidate, k_nra1_magic, sizeof(k_nra1_magic));
    candidate[4] = NINLIL_NRA1_KIND_RECEIPT;
    candidate[5] = pack_slot_stage(receipt->service_slot, receipt->receipt_stage);
    (void)memcpy(candidate + 6u, receipt->transaction_id, 16u);
    (void)memcpy(candidate + 22u, receipt->attempt_id, 16u);
    store_u64_be(candidate + 38u, receipt->evidence_time_now_ms);

    (void)memcpy(out_body, candidate, sizeof(candidate));
    *out_length = sizeof(candidate);
    (void)memset(candidate, 0, sizeof(candidate));
    return NINLIL_NRA1_OK;
}

ninlil_nra1_status_t ninlil_nra1_decode_receipt(
    const uint8_t *body,
    size_t body_length,
    ninlil_nra1_receipt_t *out_receipt)
{
    ninlil_nra1_receipt_t candidate;
    uint8_t packed;

    if (body == NULL || out_receipt == NULL) {
        return NINLIL_NRA1_INVALID_ARGUMENT;
    }
    if (body_length != NINLIL_NRA1_RECEIPT_BODY_BYTES) {
        return NINLIL_NRA1_LENGTH;
    }
    if (spans_overlap(body, body_length, out_receipt, sizeof(*out_receipt))) {
        return NINLIL_NRA1_ALIAS;
    }
    if (!magic_valid(body) || body[4] != NINLIL_NRA1_KIND_RECEIPT) {
        return NINLIL_NRA1_STRUCTURAL;
    }
    packed = body[5];
    if (!service_slot_valid((uint8_t)(packed >> 3u))
        || !receipt_stage_valid((uint8_t)(packed & 0x07u))
        || !common_ids_valid(body + 6u, body + 22u)) {
        return NINLIL_NRA1_STRUCTURAL;
    }

    (void)memset(&candidate, 0, sizeof(candidate));
    candidate.service_slot = (uint8_t)(packed >> 3u);
    candidate.receipt_stage = (uint8_t)(packed & 0x07u);
    (void)memcpy(candidate.transaction_id, body + 6u, 16u);
    (void)memcpy(candidate.attempt_id, body + 22u, 16u);
    candidate.evidence_time_now_ms = load_u64_be(body + 38u);
    *out_receipt = candidate;
    (void)memset(&candidate, 0, sizeof(candidate));
    return NINLIL_NRA1_OK;
}

ninlil_nra1_status_t ninlil_nra1_validate_application_family(
    const ninlil_nra1_application_t *application,
    uint32_t family)
{
    if (application == NULL) {
        return NINLIL_NRA1_INVALID_ARGUMENT;
    }
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        return bytes_nonzero(application->subject, 16u)
                && application->absolute_effect_deadline_ms == NINLIL_NO_DEADLINE
            ? NINLIL_NRA1_OK
            : NINLIL_NRA1_SEMANTIC;
    }
    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        return !bytes_nonzero(application->subject, 8u)
                && bytes_nonzero(application->subject + 8u, 8u)
                && application->absolute_effect_deadline_ms != 0u
                && application->absolute_effect_deadline_ms
                    != NINLIL_NO_DEADLINE
            ? NINLIL_NRA1_OK
            : NINLIL_NRA1_SEMANTIC;
    }
    return NINLIL_NRA1_UNSUPPORTED;
}
