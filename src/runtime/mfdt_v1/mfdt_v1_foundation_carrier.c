/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_foundation_carrier.h"

#include "mfdt_v1.h"
#include "mfdt_v1_ncl1.h"

#include <limits.h>
#include <string.h>
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
#include <stdio.h>
#endif

static const uint8_t CARRIER_NAMESPACE[] = "org.ninlil.private";
static const uint8_t CARRIER_SERVICE[] = "mfdt-control";
static const uint8_t CARRIER_SCHEMA[] = "ncl1-mfdt-v1";
static const uint8_t DESCRIPTOR_DOMAIN[] =
    "NINLIL-MFDT-FOUNDATION-CARRIER-V1";
static const uint8_t TRANSACTION_DOMAIN[] =
    "NINLIL-MFDT-FABRIC-TRANSACTION-V1";
static const uint8_t ATTEMPT_DOMAIN[] =
    "NINLIL-MFDT-FABRIC-ATTEMPT-V1";

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    uint8_t combined = 0u;
    size_t index;

    if (bytes == NULL) {
        return 1;
    }
    for (index = 0u; index < length; ++index) {
        combined = (uint8_t)(combined | bytes[index]);
    }
    return combined == 0u;
}

static int id_equal(const ninlil_id128_t *left, const ninlil_id128_t *right)
{
    return left != NULL && right != NULL
        && ninlil_mfdt_v1_memeq(left->bytes, right->bytes, 16u);
}

static int identity_flag_fields_valid(
    const ninlil_local_identity_t *identity)
{
    const uint32_t known_flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;

    return identity != NULL
        && identity->abi_version == NINLIL_ABI_VERSION
        && identity->struct_size == (uint16_t)sizeof(*identity)
        && identity->reserved_zero == 0u
        && (identity->flags & ~known_flags) == 0u
        && (((identity->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u)
            != bytes_zero(identity->device_id.bytes, 16u))
        && (((identity->flags
                & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u)
            != bytes_zero(identity->installation_id.bytes, 16u))
        && (((identity->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u)
            != bytes_zero(identity->site_domain_id.bytes, 16u));
}

static int target_flag_fields_valid(
    const ninlil_concrete_target_t *target)
{
    const uint32_t known_flags = NINLIL_TARGET_HAS_DEVICE
        | NINLIL_TARGET_HAS_INSTALLATION | NINLIL_TARGET_HAS_SITE;

    return target != NULL
        && target->abi_version == NINLIL_ABI_VERSION
        && target->struct_size == (uint16_t)sizeof(*target)
        && target->reserved_zero == 0u
        && (target->flags & ~known_flags) == 0u
        && (((target->flags & NINLIL_TARGET_HAS_DEVICE) != 0u)
            != bytes_zero(target->device_id.bytes, 16u))
        && (((target->flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u)
            != bytes_zero(target->installation_id.bytes, 16u))
        && (((target->flags & NINLIL_TARGET_HAS_SITE) != 0u)
            != bytes_zero(target->site_domain_id.bytes, 16u));
}

static int source_known_parts_match(
    const ninlil_local_identity_t *source,
    const ninlil_concrete_target_t *expected)
{
    return ((expected->flags & NINLIL_TARGET_HAS_DEVICE) == 0u
            || ((source->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u
                && id_equal(&source->device_id, &expected->device_id)))
        && ((expected->flags & NINLIL_TARGET_HAS_INSTALLATION) == 0u
            || ((source->flags
                    & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u
                && id_equal(
                    &source->installation_id,
                    &expected->installation_id)))
        && ((expected->flags & NINLIL_TARGET_HAS_SITE) == 0u
            || ((source->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u
                && id_equal(
                    &source->site_domain_id,
                    &expected->site_domain_id)))
        && (expected->binding_epoch == 0u
            || source->binding_epoch == expected->binding_epoch)
        && (expected->membership_epoch == 0u
            || source->membership_epoch == expected->membership_epoch);
}

static int local_target_known_parts_match(
    const ninlil_concrete_target_t *target,
    const ninlil_local_identity_t *local)
{
    return ((target->flags & NINLIL_TARGET_HAS_DEVICE) == 0u
            || ((local->flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u
                && id_equal(&target->device_id, &local->device_id)))
        && ((target->flags & NINLIL_TARGET_HAS_INSTALLATION) == 0u
            || ((local->flags
                    & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u
                && id_equal(
                    &target->installation_id,
                    &local->installation_id)))
        && ((target->flags & NINLIL_TARGET_HAS_SITE) == 0u
            || ((local->flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u
                && id_equal(&target->site_domain_id, &local->site_domain_id)))
        && (target->binding_epoch == 0u
            || target->binding_epoch == local->binding_epoch)
        && (target->membership_epoch == 0u
            || target->membership_epoch == local->membership_epoch);
}

static int text_equal(const ninlil_text_id_t *left,
                      const ninlil_text_id_t *right)
{
    return left != NULL && right != NULL && left->length == right->length
        && left->length <= sizeof(left->bytes)
        && ninlil_mfdt_v1_memeq(
            left->bytes, right->bytes, (size_t)left->length);
}

static void set_header(uint16_t *abi_version, uint16_t *struct_size,
                       size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void copy_text(ninlil_text_id_t *out, const uint8_t *bytes,
                      size_t length)
{
    out->length = (uint8_t)length;
    (void)memcpy(out->bytes, bytes, length);
}

static int carrier_logical_bytes(
    const ninlil_bearer_message_t *message,
    uint32_t *out_bytes)
{
    uint64_t total = 455u;
    uint32_t additions[5];
    size_t index;

    if (message == NULL || out_bytes == NULL) {
        return 0;
    }
    additions[0] = message->service.namespace_id.length;
    additions[1] = message->service.service_id.length;
    additions[2] = message->service.schema_id.length;
    additions[3] = message->payload.length;
    additions[4] = message->evidence.length;
    for (index = 0u; index < 5u; ++index) {
        if (total > UINT32_MAX - additions[index]) {
            return 0;
        }
        total += additions[index];
    }
    *out_bytes = (uint32_t)total;
    return 1;
}

static int config_ok(
    const ninlil_mfdt_v1_foundation_carrier_config_t *config)
{
    if (config == NULL || config->bearer == NULL || config->clock == NULL
        || config->tx_gate == NULL || config->session == NULL) {
        return 0;
    }
    if (config->bearer->abi_version != NINLIL_ABI_VERSION
        || config->bearer->struct_size
            != (uint16_t)sizeof(*config->bearer)
        || config->bearer->open == NULL || config->bearer->close == NULL
        || config->bearer->send == NULL
        || config->bearer->receive_next == NULL
        || config->bearer->release_received == NULL) {
        return 0;
    }
    if (config->clock->abi_version != NINLIL_ABI_VERSION
        || config->clock->struct_size != (uint16_t)sizeof(*config->clock)
        || config->clock->now == NULL
        || config->tx_gate->abi_version != NINLIL_ABI_VERSION
        || config->tx_gate->struct_size
            != (uint16_t)sizeof(*config->tx_gate)
        || config->tx_gate->acquire == NULL) {
        return 0;
    }
    if (config->source.abi_version != NINLIL_ABI_VERSION
        || config->source.struct_size
            != (uint16_t)sizeof(config->source)
        || !identity_flag_fields_valid(&config->source.local_identity)
        || config->target.abi_version != NINLIL_ABI_VERSION
        || config->target.struct_size
            != (uint16_t)sizeof(config->target)
        || !target_flag_fields_valid(&config->target)) {
        return 0;
    }
    if (bytes_zero(config->source.runtime_id.bytes, 16u)
        || bytes_zero(config->source.application_instance_id.bytes, 16u)
        || bytes_zero(config->target.target_runtime_id.bytes, 16u)
        || bytes_zero(
            config->target.target_application_instance_id.bytes, 16u)
        || id_equal(
            &config->source.runtime_id, &config->target.target_runtime_id)) {
        return 0;
    }
    if (config->role != NINLIL_ROLE_CONTROLLER
        && config->role != NINLIL_ROLE_ENDPOINT) {
        return 0;
    }
    return config->deadline_window_ms != 0u;
}

static int frame_binding(
    const ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const uint8_t *frame,
    size_t frame_len,
    uint8_t *type_out,
    uint32_t *request_id_out)
{
    const ninlil_mfdt_v1_session_t *session;
    uint8_t type = 0u;
    uint32_t request_id = 0u;
    uint32_t generation = 0u;
    uint64_t cookie = 0u;
    const uint8_t *body = NULL;
    uint16_t body_len = 0u;
    int result;

    if (carrier == NULL || carrier->initialized == 0u
        || carrier->config.session == NULL || frame == NULL
        || type_out == NULL || request_id_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    session = carrier->config.session;
    result = ninlil_mfdt_v1_ncl1_decode(
        frame, frame_len, NINLIL_MFDT_V1_NCG1_DATA, &type, &request_id,
        &generation, &cookie, &body, &body_len);
    if (result != NINLIL_MFDT_V1_OK) {
        return result;
    }
    (void)body;
    (void)body_len;
    if (session->state == NINLIL_MFDT_V1_SESSION_COLD
        || session->state == NINLIL_MFDT_V1_SESSION_FENCED
        || generation != session->session_generation
        || cookie != session->session_cookie) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (ninlil_mfdt_v1_ncl1_is_transfer_type(type)
        && !ninlil_mfdt_v1_session_carrier_ncl1_data_ok(session)) {
        return NINLIL_MFDT_V1_ERR_POLICY_OFF;
    }
    *type_out = type;
    *request_id_out = request_id;
    return NINLIL_MFDT_V1_OK;
}

static int derive_transaction_id(
    const ninlil_mfdt_v1_foundation_carrier_t *carrier,
    uint32_t request_id,
    ninlil_id128_t *out)
{
    uint8_t material[sizeof(TRANSACTION_DOMAIN) - 1u + 4u + 8u + 4u + 32u];
    uint8_t digest[32];
    const uint8_t *left;
    const uint8_t *right;
    size_t offset = 0u;

    if (memcmp(carrier->config.source.runtime_id.bytes,
               carrier->config.target.target_runtime_id.bytes, 16u)
        <= 0) {
        left = carrier->config.source.runtime_id.bytes;
        right = carrier->config.target.target_runtime_id.bytes;
    } else {
        left = carrier->config.target.target_runtime_id.bytes;
        right = carrier->config.source.runtime_id.bytes;
    }
    (void)memcpy(
        material + offset, TRANSACTION_DOMAIN, sizeof(TRANSACTION_DOMAIN) - 1u);
    offset += sizeof(TRANSACTION_DOMAIN) - 1u;
    ninlil_mfdt_v1_put_u32(
        material + offset, carrier->config.session->session_generation);
    offset += 4u;
    ninlil_mfdt_v1_put_u64(
        material + offset, carrier->config.session->session_cookie);
    offset += 8u;
    ninlil_mfdt_v1_put_u32(material + offset, request_id);
    offset += 4u;
    (void)memcpy(material + offset, left, 16u);
    offset += 16u;
    (void)memcpy(material + offset, right, 16u);
    offset += 16u;
    ninlil_mfdt_v1_sha256(material, offset, digest);
    (void)memcpy(out->bytes, digest, 16u);
    ninlil_mfdt_v1_memzero(material, sizeof(material));
    ninlil_mfdt_v1_memzero(digest, sizeof(digest));
    return bytes_zero(out->bytes, 16u) ? NINLIL_MFDT_V1_ERR_CORRUPT
                                       : NINLIL_MFDT_V1_OK;
}

static int derive_attempt_id(
    const ninlil_id128_t *source_runtime_id,
    const ninlil_id128_t *transaction_id,
    uint8_t message_type,
    const uint8_t content_digest[32],
    ninlil_id128_t *out)
{
    uint8_t material[
        sizeof(ATTEMPT_DOMAIN) - 1u + 16u + 16u + 1u + 32u];
    uint8_t digest[32];
    size_t offset = 0u;

    (void)memcpy(
        material + offset, ATTEMPT_DOMAIN, sizeof(ATTEMPT_DOMAIN) - 1u);
    offset += sizeof(ATTEMPT_DOMAIN) - 1u;
    (void)memcpy(material + offset, transaction_id->bytes, 16u);
    offset += 16u;
    (void)memcpy(material + offset, source_runtime_id->bytes, 16u);
    offset += 16u;
    material[offset++] = message_type;
    (void)memcpy(material + offset, content_digest, 32u);
    offset += 32u;
    ninlil_mfdt_v1_sha256(material, offset, digest);
    (void)memcpy(out->bytes, digest, 16u);
    ninlil_mfdt_v1_memzero(material, sizeof(material));
    ninlil_mfdt_v1_memzero(digest, sizeof(digest));
    return bytes_zero(out->bytes, 16u) ? NINLIL_MFDT_V1_ERR_CORRUPT
                                       : NINLIL_MFDT_V1_OK;
}

static int service_equal(const ninlil_service_identity_t *left,
                         const ninlil_service_identity_t *right)
{
    return left != NULL && right != NULL
        && left->abi_version == NINLIL_ABI_VERSION
        && left->struct_size == (uint16_t)sizeof(*left)
        && text_equal(&left->namespace_id, &right->namespace_id)
        && text_equal(&left->service_id, &right->service_id)
        && text_equal(&left->schema_id, &right->schema_id)
        && left->descriptor_revision == right->descriptor_revision
        && left->descriptor_digest.algorithm
            == right->descriptor_digest.algorithm
        && left->descriptor_digest.reserved_zero == 0u
        && ninlil_mfdt_v1_memeq(
            left->descriptor_digest.bytes,
            right->descriptor_digest.bytes,
            32u)
        && left->schema_major == right->schema_major
        && left->schema_minor == right->schema_minor
        && left->family == right->family;
}

int ninlil_mfdt_v1_foundation_carrier_service_identity(
    ninlil_service_identity_t *out_service)
{
    if (out_service == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    (void)memset(out_service, 0, sizeof(*out_service));
    set_header(
        &out_service->abi_version,
        &out_service->struct_size,
        sizeof(*out_service));
    copy_text(
        &out_service->namespace_id,
        CARRIER_NAMESPACE,
        sizeof(CARRIER_NAMESPACE) - 1u);
    copy_text(
        &out_service->service_id,
        CARRIER_SERVICE,
        sizeof(CARRIER_SERVICE) - 1u);
    copy_text(
        &out_service->schema_id,
        CARRIER_SCHEMA,
        sizeof(CARRIER_SCHEMA) - 1u);
    out_service->descriptor_revision = 1u;
    out_service->descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    ninlil_mfdt_v1_sha256(
        DESCRIPTOR_DOMAIN,
        sizeof(DESCRIPTOR_DOMAIN) - 1u,
        out_service->descriptor_digest.bytes);
    out_service->schema_major = 1u;
    out_service->schema_minor = 0u;
    out_service->family = NINLIL_FAMILY_TRANSFER_RESERVED;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_foundation_carrier_init(
    ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const ninlil_mfdt_v1_foundation_carrier_config_t *config)
{
    if (carrier == NULL || !config_ok(config)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    (void)memset(carrier, 0, sizeof(*carrier));
    carrier->config = *config;
    if (ninlil_mfdt_v1_foundation_carrier_service_identity(&carrier->service)
        != NINLIL_MFDT_V1_OK) {
        (void)memset(carrier, 0, sizeof(*carrier));
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    carrier->initialized = 1u;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_foundation_carrier_open(
    ninlil_mfdt_v1_foundation_carrier_t *carrier)
{
    ninlil_bearer_status_t status;

    if (carrier == NULL || carrier->initialized == 0u
        || carrier->opened != 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    status = carrier->config.bearer->open(
        carrier->config.bearer->user,
        &carrier->config.source.runtime_id,
        carrier->config.role,
        &carrier->bearer_handle);
    if (status != NINLIL_BEARER_OK || carrier->bearer_handle == NULL) {
        carrier->bearer_handle = NULL;
        return status == NINLIL_BEARER_WOULD_BLOCK
                || status == NINLIL_BEARER_UNAVAILABLE
            ? NINLIL_MFDT_V1_ERR_BUSY
            : NINLIL_MFDT_V1_ERR_STATE;
    }
    carrier->opened = 1u;
    return NINLIL_MFDT_V1_OK;
}

void ninlil_mfdt_v1_foundation_carrier_close(
    ninlil_mfdt_v1_foundation_carrier_t *carrier)
{
    if (carrier == NULL || carrier->opened == 0u) {
        return;
    }
    carrier->config.bearer->close(
        carrier->config.bearer->user, carrier->bearer_handle);
    carrier->bearer_handle = NULL;
    carrier->opened = 0u;
}

int ninlil_mfdt_v1_foundation_carrier_build_message(
    ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_time_sample_t *now,
    ninlil_bearer_message_t *out_message)
{
    uint8_t message_type = 0u;
    uint32_t request_id = 0u;
    int result;

    if (carrier == NULL || carrier->initialized == 0u || now == NULL
        || out_message == NULL || frame_len > UINT32_MAX) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (now->abi_version != NINLIL_ABI_VERSION
        || now->struct_size != (uint16_t)sizeof(*now)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || bytes_zero(now->clock_epoch_id.bytes, 16u)
        || UINT64_MAX - now->now_ms < carrier->config.deadline_window_ms) {
        return NINLIL_MFDT_V1_ERR_EXPIRED;
    }
    result = frame_binding(
        carrier, frame, frame_len, &message_type, &request_id);
    if (result != NINLIL_MFDT_V1_OK) {
        return result;
    }
    (void)memset(out_message, 0, sizeof(*out_message));
    set_header(
        &out_message->abi_version,
        &out_message->struct_size,
        sizeof(*out_message));
    out_message->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    result = derive_transaction_id(
        carrier, request_id, &out_message->transaction_id);
    if (result != NINLIL_MFDT_V1_OK) {
        return result;
    }
    out_message->source = carrier->config.source;
    out_message->target = carrier->config.target;
    out_message->service = carrier->service;
    out_message->content_digest.algorithm = NINLIL_DIGEST_SHA256;
    ninlil_mfdt_v1_sha256(
        frame, frame_len, out_message->content_digest.bytes);
    result = derive_attempt_id(
        &carrier->config.source.runtime_id,
        &out_message->transaction_id,
        message_type,
        out_message->content_digest.bytes,
        &out_message->attempt_id);
    if (result != NINLIL_MFDT_V1_OK) {
        return result;
    }
    out_message->generation = carrier->config.session->session_generation;
    out_message->deadline_clock_epoch_id = now->clock_epoch_id;
    out_message->absolute_effect_deadline_ms =
        now->now_ms + carrier->config.deadline_window_ms;
    out_message->payload.data = frame;
    out_message->payload.length = (uint32_t)frame_len;
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_foundation_carrier_accept_message(
    const ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const ninlil_bearer_message_t *message,
    uint8_t *frame_out,
    size_t frame_cap,
    size_t *frame_len_out)
{
    uint8_t digest[32];
    uint8_t message_type = 0u;
    uint32_t request_id = 0u;
    ninlil_id128_t expected_transaction_id;
    ninlil_id128_t expected_attempt_id;
    int result;

    if (frame_len_out != NULL) {
        *frame_len_out = 0u;
    }
    if (carrier == NULL || carrier->initialized == 0u || message == NULL
        || frame_out == NULL || frame_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    if (message->abi_version != NINLIL_ABI_VERSION
        || message->struct_size != (uint16_t)sizeof(*message)
        || message->kind != NINLIL_BEARER_MESSAGE_APPLICATION
        || message->flags != 0u
        || !bytes_zero(message->event_id.bytes, 16u)
        || message->source.abi_version != NINLIL_ABI_VERSION
        || message->source.struct_size
            != (uint16_t)sizeof(message->source)
        || !identity_flag_fields_valid(&message->source.local_identity)
        || message->target.abi_version != NINLIL_ABI_VERSION
        || message->target.struct_size
            != (uint16_t)sizeof(message->target)
        || !target_flag_fields_valid(&message->target)
        || !service_equal(&message->service, &carrier->service)
        || !id_equal(
            &message->source.runtime_id,
            &carrier->config.target.target_runtime_id)
        || !id_equal(
            &message->source.application_instance_id,
            &carrier->config.target.target_application_instance_id)
        || !id_equal(
            &message->target.target_runtime_id,
            &carrier->config.source.runtime_id)
        || !id_equal(
            &message->target.target_application_instance_id,
            &carrier->config.source.application_instance_id)
        || !source_known_parts_match(
            &message->source.local_identity, &carrier->config.target)
        || !local_target_known_parts_match(
            &message->target, &carrier->config.source.local_identity)
        || message->generation
            != carrier->config.session->session_generation
        || message->content_digest.algorithm != NINLIL_DIGEST_SHA256
        || message->content_digest.reserved_zero != 0u
        || bytes_zero(message->deadline_clock_epoch_id.bytes, 16u)
        || message->absolute_effect_deadline_ms == 0u
        || message->evidence_grace_ms != 0u
        || message->required_evidence != 0u
        || message->receipt_stage != 0u
        || message->disposition != 0u
        || message->effect_certainty != 0u
        || message->retry_guidance != 0u
        || message->cancel_kind != 0u
        || message->retry_delay_ms != 0u
        || message->evidence_time.abi_version != 0u
        || message->evidence_time.struct_size != 0u
        || !bytes_zero(message->evidence_time.clock_epoch_id.bytes, 16u)
        || message->evidence_time.now_ms != 0u
        || message->evidence_time.trust != 0u
        || message->evidence_time.reserved_zero != 0u
        || message->evidence.data != NULL
        || message->evidence.length != 0u
        || message->payload.data == NULL || message->payload.length == 0u
        || message->payload.length > frame_cap
        || message->payload.length > NINLIL_MFDT_V1_NCL1_MAX_MSG) {
        return message->payload.length > frame_cap
            ? NINLIL_MFDT_V1_ERR_CAPACITY
            : NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    ninlil_mfdt_v1_sha256(
        message->payload.data, message->payload.length, digest);
    if (!ninlil_mfdt_v1_memeq(
            digest, message->content_digest.bytes, sizeof(digest))) {
        ninlil_mfdt_v1_memzero(digest, sizeof(digest));
        return NINLIL_MFDT_V1_ERR_DIGEST;
    }
    ninlil_mfdt_v1_memzero(digest, sizeof(digest));
    result = frame_binding(
        carrier,
        message->payload.data,
        message->payload.length,
        &message_type,
        &request_id);
    (void)message_type;
    (void)request_id;
    if (result != NINLIL_MFDT_V1_OK) {
        return result;
    }
    result = derive_transaction_id(
        carrier, request_id, &expected_transaction_id);
    if (result != NINLIL_MFDT_V1_OK
        || !id_equal(
            &message->transaction_id, &expected_transaction_id)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    result = derive_attempt_id(
        &message->source.runtime_id,
        &expected_transaction_id,
        message_type,
        message->content_digest.bytes,
        &expected_attempt_id);
    if (result != NINLIL_MFDT_V1_OK
        || !id_equal(&message->attempt_id, &expected_attempt_id)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    (void)memcpy(frame_out, message->payload.data, message->payload.length);
    *frame_len_out = message->payload.length;
    return NINLIL_MFDT_V1_OK;
}

static int bearer_status_to_mfdt(ninlil_bearer_status_t status)
{
    switch (status) {
    case NINLIL_BEARER_EMPTY:
    case NINLIL_BEARER_WOULD_BLOCK:
    case NINLIL_BEARER_UNAVAILABLE:
        return NINLIL_MFDT_V1_ERR_BUSY;
    case NINLIL_BEARER_DENIED:
        return NINLIL_MFDT_V1_ERR_STATE;
    case NINLIL_BEARER_LOST_UNKNOWN:
        return NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN;
    case NINLIL_BEARER_CORRUPT:
    default:
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
}

int ninlil_mfdt_v1_foundation_carrier_tx_shared(
    ninlil_mfdt_v1_foundation_carrier_t *carrier,
    ninlil_bearer_handle_t bearer_handle,
    const uint8_t *frame,
    size_t frame_len,
    const ninlil_time_sample_t *now,
    uint32_t *send_attempted_out,
    ninlil_bearer_status_t *bearer_status_out)
{
    ninlil_bearer_message_t message;
    ninlil_tx_request_t request;
    ninlil_tx_permit_t permit;
    ninlil_bearer_send_result_t send_result;
    ninlil_tx_gate_status_t gate_status;
    ninlil_bearer_status_t bearer_status;
    uint32_t logical_bytes = 0u;
    int result;

    if (send_attempted_out != NULL) {
        *send_attempted_out = 0u;
    }
    if (bearer_status_out != NULL) {
        *bearer_status_out = NINLIL_BEARER_EMPTY;
    }
    if (carrier == NULL || carrier->initialized == 0u
        || bearer_handle == NULL || frame == NULL || frame_len == 0u
        || now == NULL || send_attempted_out == NULL
        || bearer_status_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    result = ninlil_mfdt_v1_foundation_carrier_build_message(
        carrier, frame, frame_len, now, &message);
    if (result != NINLIL_MFDT_V1_OK) {
        return result;
    }
    (void)memset(&request, 0, sizeof(request));
    set_header(
        &request.abi_version, &request.struct_size, sizeof(request));
    request.transaction_id = message.transaction_id;
    request.attempt_id = message.attempt_id;
    request.message_kind = message.kind;
    if (!carrier_logical_bytes(&message, &logical_bytes)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    request.logical_bytes = logical_bytes;
    request.content_digest = message.content_digest;
    (void)memset(&permit, 0, sizeof(permit));
    gate_status = carrier->config.tx_gate->acquire(
        carrier->config.tx_gate->user, &request, now, &permit);
    if (gate_status == NINLIL_TX_GATE_TEMPORARY) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    if (gate_status != NINLIL_TX_GATE_OK) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    (void)memset(&send_result, 0, sizeof(send_result));
    set_header(
        &send_result.abi_version,
        &send_result.struct_size,
        sizeof(send_result));
    bearer_status = carrier->config.bearer->send(
        carrier->config.bearer->user,
        bearer_handle,
        &permit,
        &message,
        &send_result);
    *send_attempted_out = 1u;
    *bearer_status_out = bearer_status;
    if (bearer_status != NINLIL_BEARER_OK) {
#if defined(NINLIL_MFDT_V1_HOST_DIAGNOSTICS)
        (void)fprintf(
            stderr,
            "mfdt foundation carrier: bearer send status=%u payload=%u\n",
            (unsigned)bearer_status,
            (unsigned)message.payload.length);
#endif
        /*
         * LOST_UNKNOWN may follow provider retention or an unknown durable
         * commit result. The permit's consume state is therefore unknown and
         * must never be advertised as unused.
         */
        if (bearer_status != NINLIL_BEARER_LOST_UNKNOWN
            && carrier->config.tx_gate->release_unused != NULL) {
            carrier->config.tx_gate->release_unused(
                carrier->config.tx_gate->user, &permit);
        }
        return bearer_status_to_mfdt(bearer_status);
    }
    if (send_result.abi_version != NINLIL_ABI_VERSION
        || send_result.struct_size != (uint16_t)sizeof(send_result)
        || (send_result.kind != NINLIL_BEARER_SEND_ACCEPTED
            && send_result.kind != NINLIL_BEARER_SEND_DURABLE_CUSTODY)) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    return NINLIL_MFDT_V1_OK;
}

int ninlil_mfdt_v1_foundation_carrier_tx(
    void *user, const uint8_t *frame, size_t frame_len)
{
    ninlil_mfdt_v1_foundation_carrier_t *carrier =
        (ninlil_mfdt_v1_foundation_carrier_t *)user;
    ninlil_time_sample_t now;
    uint32_t send_attempted = 0u;
    ninlil_bearer_status_t bearer_status = NINLIL_BEARER_EMPTY;

    if (carrier == NULL || carrier->opened == 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (carrier->config.clock->now(carrier->config.clock->user, &now)
        != NINLIL_PORT_OK) {
        return NINLIL_MFDT_V1_ERR_BUSY;
    }
    return ninlil_mfdt_v1_foundation_carrier_tx_shared(
        carrier,
        carrier->bearer_handle,
        frame,
        frame_len,
        &now,
        &send_attempted,
        &bearer_status);
}

int ninlil_mfdt_v1_foundation_carrier_rx(
    void *user, uint8_t *frame_out, size_t frame_cap, size_t *frame_len_out)
{
    ninlil_mfdt_v1_foundation_carrier_t *carrier =
        (ninlil_mfdt_v1_foundation_carrier_t *)user;
    ninlil_bearer_message_t message;
    ninlil_bearer_status_t status;
    int result;

    if (frame_len_out != NULL) {
        *frame_len_out = 0u;
    }
    if (carrier == NULL || carrier->opened == 0u || frame_out == NULL
        || frame_len_out == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    (void)memset(&message, 0, sizeof(message));
    set_header(
        &message.abi_version, &message.struct_size, sizeof(message));
    status = carrier->config.bearer->receive_next(
        carrier->config.bearer->user, carrier->bearer_handle, &message);
    if (status != NINLIL_BEARER_OK) {
        return bearer_status_to_mfdt(status);
    }
    result = ninlil_mfdt_v1_foundation_carrier_accept_message(
        carrier, &message, frame_out, frame_cap, frame_len_out);
    carrier->config.bearer->release_received(
        carrier->config.bearer->user, carrier->bearer_handle, &message);
    return result;
}

uint64_t ninlil_mfdt_v1_foundation_carrier_now(void *user)
{
    ninlil_mfdt_v1_foundation_carrier_t *carrier =
        (ninlil_mfdt_v1_foundation_carrier_t *)user;
    ninlil_time_sample_t now;

    if (carrier == NULL || carrier->initialized == 0u) {
        return 0u;
    }
    (void)memset(&now, 0, sizeof(now));
    set_header(&now.abi_version, &now.struct_size, sizeof(now));
    if (carrier->config.clock->now(carrier->config.clock->user, &now)
            != NINLIL_PORT_OK
        || (now.trust != NINLIL_CLOCK_TRUSTED
            && now.trust != NINLIL_CLOCK_UNCERTAIN)) {
        return 0u;
    }
    return now.now_ms;
}
