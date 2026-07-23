#include "submission_canonical_v1.h"

#include "domain_store_codec.h"

#include <string.h>

#define NINLIL_RT_CANONICAL_V1_MAX_BYTES 512u

typedef struct canonical_writer {
    uint8_t *bytes;
    size_t capacity;
    size_t length;
} canonical_writer_t;

static int writer_append(
    canonical_writer_t *writer,
    const void *data,
    size_t length)
{
    if (writer->length > writer->capacity
        || length > writer->capacity - writer->length) {
        return 0;
    }
    if (length > 0u && data != NULL) {
        (void)memcpy(writer->bytes + writer->length, data, length);
    }
    writer->length += length;
    return 1;
}

static int writer_append_u8(canonical_writer_t *writer, uint8_t value)
{
    return writer_append(writer, &value, 1u);
}

static int writer_append_u32_be(canonical_writer_t *writer, uint32_t value)
{
    uint8_t bytes[4];

    bytes[0] = (uint8_t)((value >> 24) & 0xffu);
    bytes[1] = (uint8_t)((value >> 16) & 0xffu);
    bytes[2] = (uint8_t)((value >> 8) & 0xffu);
    bytes[3] = (uint8_t)(value & 0xffu);
    return writer_append(writer, bytes, sizeof(bytes));
}

static int writer_append_u16_be(canonical_writer_t *writer, uint16_t value)
{
    uint8_t bytes[2];

    bytes[0] = (uint8_t)((value >> 8) & 0xffu);
    bytes[1] = (uint8_t)(value & 0xffu);
    return writer_append(writer, bytes, sizeof(bytes));
}

static int writer_append_u64_be(canonical_writer_t *writer, uint64_t value)
{
    uint8_t bytes[8];
    uint32_t index;

    for (index = 0u; index < 8u; ++index) {
        bytes[7u - index] = (uint8_t)(value & 0xffu);
        value >>= 8;
    }
    return writer_append(writer, bytes, sizeof(bytes));
}

static int writer_append_field(
    canonical_writer_t *writer,
    uint8_t tag,
    const void *value,
    uint32_t value_length)
{
    if (!writer_append_u8(writer, tag)) {
        return 0;
    }
    if (!writer_append_u32_be(writer, value_length)) {
        return 0;
    }
    return writer_append(writer, value, value_length);
}

static int id_is_zero(const ninlil_id128_t *id)
{
    size_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        if (id->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int digest_is_valid(const ninlil_digest256_t *digest)
{
    return digest != NULL && digest->algorithm == NINLIL_DIGEST_SHA256
        && digest->reserved_zero == 0u;
}

static int target_presence_is_valid(const ninlil_concrete_target_t *target)
{
    uint32_t flags = target->flags;
    int has_device = (flags & NINLIL_TARGET_HAS_DEVICE) != 0u;
    int has_installation = (flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u;
    int has_site = (flags & NINLIL_TARGET_HAS_SITE) != 0u;

    if ((flags
            & ~(NINLIL_TARGET_HAS_DEVICE | NINLIL_TARGET_HAS_INSTALLATION
                | NINLIL_TARGET_HAS_SITE))
        != 0u) {
        return 0;
    }
    return id_is_zero(&target->device_id) == !has_device
        && id_is_zero(&target->installation_id) == !has_installation
        && id_is_zero(&target->site_domain_id) == !has_site
        && (target->binding_epoch != 0u) == (has_device || has_installation)
        && (target->membership_epoch != 0u) == has_site;
}

static int encode_target_record_fixed(
    const ninlil_concrete_target_t *target,
    uint8_t out_record[100])
{
    uint32_t index;

    if (target->reserved_zero != 0u
        || id_is_zero(&target->target_runtime_id)
        || id_is_zero(&target->target_application_instance_id)
        || !target_presence_is_valid(target)) {
        return 0;
    }

    (void)memset(out_record, 0, 100u);
    (void)memcpy(out_record, target->target_runtime_id.bytes, 16u);
    (void)memcpy(out_record + 16u, target->target_application_instance_id.bytes, 16u);
    out_record[32] = (uint8_t)((target->flags >> 24) & 0xffu);
    out_record[33] = (uint8_t)((target->flags >> 16) & 0xffu);
    out_record[34] = (uint8_t)((target->flags >> 8) & 0xffu);
    out_record[35] = (uint8_t)(target->flags & 0xffu);
    (void)memcpy(out_record + 36u, target->device_id.bytes, 16u);
    (void)memcpy(out_record + 52u, target->installation_id.bytes, 16u);
    (void)memcpy(out_record + 68u, target->site_domain_id.bytes, 16u);
    for (index = 0u; index < 8u; ++index) {
        out_record[84u + index] =
            (uint8_t)((target->binding_epoch >> (56u - (index * 8u))) & 0xffu);
        out_record[92u + index] =
            (uint8_t)((target->membership_epoch >> (56u - (index * 8u))) & 0xffu);
    }
    return 1;
}

static int encode_digest_value(
    const ninlil_digest256_t *digest,
    uint8_t out_value[34])
{
    if (!digest_is_valid(digest)) {
        return 0;
    }
    out_value[0] = (uint8_t)((digest->algorithm >> 8) & 0xffu);
    out_value[1] = (uint8_t)(digest->algorithm & 0xffu);
    (void)memcpy(out_value + 2u, digest->bytes, 32u);
    return 1;
}

static int encode_target_roster(
    const ninlil_submission_t *submission,
    uint8_t *out_bytes,
    uint32_t *out_length)
{
    uint8_t records[8][100];
    uint32_t count;
    uint32_t index;
    uint32_t offset = 0u;

    if (submission->target_count == 0u || submission->targets == NULL) {
        return 0;
    }
    if (submission->target_count > 8u) {
        return 0;
    }

    count = submission->target_count;
    for (index = 0u; index < count; ++index) {
        if (!encode_target_record_fixed(&submission->targets[index], records[index])) {
            return 0;
        }
    }

    for (index = 0u; index < count; ++index) {
        uint32_t swap = index;
        uint32_t scan;
        for (scan = index + 1u; scan < count; ++scan) {
            int cmp = memcmp(records[scan], records[swap], 100u);
            if (cmp < 0) {
                swap = scan;
            } else if (cmp == 0) {
                return 0;
            }
        }
        if (swap != index) {
            uint8_t temp[100];
            (void)memcpy(temp, records[index], 100u);
            (void)memcpy(records[index], records[swap], 100u);
            (void)memcpy(records[swap], temp, 100u);
        }
    }

    out_bytes[offset++] = (uint8_t)((count >> 24) & 0xffu);
    out_bytes[offset++] = (uint8_t)((count >> 16) & 0xffu);
    out_bytes[offset++] = (uint8_t)((count >> 8) & 0xffu);
    out_bytes[offset++] = (uint8_t)(count & 0xffu);
    for (index = 0u; index < count; ++index) {
        (void)memcpy(out_bytes + offset, records[index], 100u);
        offset += 100u;
    }
    *out_length = offset;
    return 1;
}

static int encode_family_metadata(
    ninlil_family_t family,
    const ninlil_submission_t *submission,
    uint8_t *out_bytes,
    uint32_t *out_length)
{
    uint32_t index;

    if (family == NINLIL_FAMILY_DESIRED_STATE) {
        if (submission->generation == 0u) {
            return 0;
        }
        for (index = 0u; index < 8u; ++index) {
            out_bytes[index] =
                (uint8_t)((submission->generation >> (56u - (index * 8u))) & 0xffu);
        }
        *out_length = 8u;
        return 1;
    }
    if (family == NINLIL_FAMILY_EVENT_FACT) {
        if (id_is_zero(&submission->event_id)
            || submission->effect_deadline_ms != NINLIL_NO_DEADLINE
            || submission->evidence_grace_ms != 0u) {
            return 0;
        }
        (void)memcpy(out_bytes, submission->event_id.bytes, 16u);
        *out_length = 16u;
        return 1;
    }
    return 0;
}

ninlil_status_t ninlil_rt_canonical_submission_digest_v1(
    const ninlil_service_descriptor_t *descriptor,
    const ninlil_submission_t *submission,
    ninlil_digest256_t *out_digest)
{
    uint8_t buffer[NINLIL_RT_CANONICAL_V1_MAX_BYTES];
    uint8_t descriptor_digest_value[34];
    uint8_t content_digest_value[34];
    uint8_t target_roster[4u + 8u * 100u];
    uint8_t family_metadata[16];
    uint32_t target_roster_length = 0u;
    uint32_t family_metadata_length = 0u;
    canonical_writer_t writer;
    ninlil_model_domain_digest_t digest;
    ninlil_status_t status;

    if (descriptor == NULL || submission == NULL || out_digest == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (descriptor->descriptor_revision == 0u
        || descriptor->namespace_id.length == 0u
        || descriptor->service_id.length == 0u
        || descriptor->schema_id.length == 0u
        || !digest_is_valid(&descriptor->descriptor_digest)
        || !digest_is_valid(&submission->content_digest)
        || submission->target_count == 0u
        || submission->targets == NULL
        || submission->payload.length > UINT32_MAX) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (!encode_digest_value(&descriptor->descriptor_digest, descriptor_digest_value)
        || !encode_digest_value(&submission->content_digest, content_digest_value)
        || !encode_target_roster(
            submission, target_roster, &target_roster_length)
        || !encode_family_metadata(
            descriptor->family,
            submission,
            family_metadata,
            &family_metadata_length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    writer.bytes = buffer;
    writer.capacity = sizeof(buffer);
    writer.length = 0u;

    if (!writer_append(&writer, "NCS1", 4u)
        || !writer_append_field(
            &writer,
            0x01u,
            descriptor->namespace_id.data,
            (uint32_t)descriptor->namespace_id.length)
        || !writer_append_field(
            &writer,
            0x02u,
            descriptor->service_id.data,
            (uint32_t)descriptor->service_id.length)
        || !writer_append_u8(&writer, 0x03u)
        || !writer_append_u32_be(&writer, 8u)
        || !writer_append_u64_be(&writer, descriptor->descriptor_revision)
        || !writer_append_field(
            &writer, 0x04u, descriptor_digest_value, sizeof(descriptor_digest_value))
        || !writer_append_field(
            &writer,
            0x05u,
            descriptor->local_application_instance_id.bytes,
            sizeof(descriptor->local_application_instance_id.bytes))
        || !writer_append_u8(&writer, 0x06u)
        || !writer_append_u32_be(&writer, 4u)
        || !writer_append_u32_be(&writer, (uint32_t)descriptor->family)
        || !writer_append_field(
            &writer,
            0x07u,
            descriptor->schema_id.data,
            (uint32_t)descriptor->schema_id.length)
        || !writer_append_u8(&writer, 0x08u)
        || !writer_append_u32_be(&writer, 2u)
        || !writer_append_u16_be(&writer, descriptor->schema_major)
        || !writer_append_u8(&writer, 0x09u)
        || !writer_append_u32_be(&writer, 2u)
        || !writer_append_u16_be(&writer, submission->schema_minor)
        || !writer_append_field(&writer, 0x0au, target_roster, target_roster_length)
        || !writer_append_u8(&writer, 0x0bu)
        || !writer_append_u32_be(&writer, 8u)
        || !writer_append_u64_be(&writer, submission->effect_deadline_ms)
        || !writer_append_u8(&writer, 0x0cu)
        || !writer_append_u32_be(&writer, 8u)
        || !writer_append_u64_be(&writer, submission->evidence_grace_ms)
        || !writer_append_u8(&writer, 0x0du)
        || !writer_append_u32_be(&writer, 4u)
        || !writer_append_u32_be(
            &writer, (uint32_t)submission->required_evidence)
        || !writer_append_field(
            &writer, 0x0eu, family_metadata, family_metadata_length)
        || !writer_append_field(
            &writer, 0x0fu, content_digest_value, sizeof(content_digest_value))
        || !writer_append_u8(&writer, 0x10u)
        || !writer_append_u32_be(&writer, 4u)
        || !writer_append_u32_be(
            &writer, (uint32_t)submission->payload.length)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }

    status = ninlil_model_domain_sha256(buffer, writer.length, &digest);
    if (status != NINLIL_OK) {
        return status;
    }

    (void)memset(out_digest, 0, sizeof(*out_digest));
    out_digest->algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(out_digest->bytes, digest.bytes, sizeof(out_digest->bytes));
    return NINLIL_OK;
}
