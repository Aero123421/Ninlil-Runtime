/* SPDX-License-Identifier: Apache-2.0 */
#include "mfdt_v1_runtime_owner.h"

#include "mfdt_v1_foundation_carrier.h"
#include "mfdt_v1_ncl1.h"

#include "../runtime_internal.h"
#include "../runtime_v1_bearer_wire.h"
#include "../runtime_v1_capability.h"
#include "../runtime_v1_family_capability.h"

#include "../../model/domain_store_codec.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define MFDT_RUNTIME_OWNER_MAGIC ((uint32_t)0x4d525431u) /* "MRT1" */
#define MFDT_RUNTIME_ITER_KEY_CAP ((uint32_t)255u)
#define MFDT_RUNTIME_ITER_VALUE_CAP \
    ((uint32_t)NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX)
#define MFDT_RUNTIME_SIDECAR_NAMESPACE_BYTES ((uint32_t)36u)
#define MFDT_RUNTIME_BINDING_KEY_BYTES ((uint32_t)20u)
#define MFDT_RUNTIME_BINDING_HEADER_BYTES ((uint32_t)48u)
#define MFDT_RUNTIME_BINDING_FIXED_BYTES ((uint32_t)52u)
#define MFDT_RUNTIME_BINDING_VALUE_MAX ((uint32_t)307u)
#define MFDT_RUNTIME_BASE_NAMESPACE_MAX ((uint32_t)255u)
#define MFDT_RUNTIME_SIDECAR_TOTAL_KEYS_MAX \
    ((uint32_t)(NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX + 1u))
#define MFDT_RUNTIME_ROUTE_COUNT \
    ((uint8_t)(NINLIL_MFDT_V1_HOST_SLOT_COUNT + 1u))

static const uint8_t k_mfdt_namespace_domain[] =
    "NINLIL-MFDT-STORAGE-NAMESPACE-V1";
static const uint8_t k_mfdt_binding_digest_domain[] =
    "NINLIL-MFDT-BASE-NAMESPACE-V1";
static const uint8_t k_mfdt_application_evidence_domain[] =
    "NINLIL-MFDT-APPLICATION-EVIDENCE-V1";
static const uint8_t k_mfdt_binding_key[MFDT_RUNTIME_BINDING_KEY_BYTES] = {
    'N', 'M', 'S', '1'
};

typedef struct mfdt_runtime_iter {
    ninlil_storage_iter_t underlying;
    uint8_t active;
} mfdt_runtime_iter_t;

typedef struct mfdt_runtime_binding {
    ninlil_bearer_message_t application;
    uint8_t transfer_id[16];
    uint8_t occupied;
    uint8_t target_ordinal;
    uint8_t reserved[2];
} mfdt_runtime_binding_t;

struct ninlil_rt_mfdt_v1_runtime_owner {
    uint32_t magic;
    uint32_t enabled;
    uint32_t session_generation;
    uint32_t ready;
    uint64_t session_cookie;
    ninlil_runtime_t *runtime;
    const ninlil_storage_ops_t *underlying_ops;
    ninlil_storage_handle_t underlying_handle;
    uint8_t sidecar_namespace[MFDT_RUNTIME_SIDECAR_NAMESPACE_BYTES];
    uint8_t binding_value[MFDT_RUNTIME_BINDING_VALUE_MAX];
    uint32_t binding_value_length;
    uint8_t sidecar_open;
    uint8_t reserved0[3];
    ninlil_storage_ops_t filtered_ops;
    ninlil_mfdt_v1_store_guarantees_t guarantees;
    ninlil_mfdt_v1_store_port_t store;
    ninlil_mfdt_v1_host_owner_t *host;
    ninlil_mfdt_v1_session_t session;
    mfdt_runtime_iter_t iterator;
    uint8_t iter_key_scratch[MFDT_RUNTIME_ITER_KEY_CAP];
    uint8_t *iter_value_scratch;
    mfdt_runtime_binding_t bindings[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    mfdt_runtime_binding_t control_binding;
    uint8_t pending_frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    uint8_t route_cursor;
    uint8_t session_bound;
    uint8_t dispatch_fenced;
};

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

ninlil_status_t ninlil_rt_mfdt_v1_application_evidence_digest(
    const uint8_t publication_token[16],
    const ninlil_id128_t *origin_transaction_id,
    const ninlil_id128_t *original_attempt_id,
    uint32_t target_ordinal,
    ninlil_evidence_stage_t evidence_stage,
    ninlil_bytes_view_t evidence,
    uint8_t digest_out[32])
{
    ninlil_model_domain_sha256_ctx_t context;
    ninlil_model_domain_digest_t digest;
    uint8_t u32be[4];
    ninlil_status_t status;

    if (publication_token == NULL || origin_transaction_id == NULL ||
        original_attempt_id == NULL || digest_out == NULL ||
        !bytes_nonzero(publication_token, 16u) ||
        !bytes_nonzero(origin_transaction_id->bytes, 16u) ||
        !bytes_nonzero(original_attempt_id->bytes, 16u) ||
        evidence_stage == NINLIL_EVIDENCE_NONE ||
        evidence_stage > NINLIL_EVIDENCE_VERIFIED ||
        evidence.length > NINLIL_MAX_EVIDENCE_BYTES ||
        (evidence.length != 0u && evidence.data == NULL) ||
        (evidence.length == 0u && evidence.data != NULL)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    ninlil_model_domain_sha256_init(&context);
#define MFDT_EVIDENCE_DIGEST_UPDATE(data_, length_)                         \
    do {                                                                   \
        status = ninlil_model_domain_sha256_update(                        \
            &context, (data_), (uint32_t)(length_));                       \
        if (status != NINLIL_OK) {                                         \
            return status;                                                 \
        }                                                                  \
    } while (0)
    MFDT_EVIDENCE_DIGEST_UPDATE(
        k_mfdt_application_evidence_domain,
        sizeof(k_mfdt_application_evidence_domain) - 1u);
    MFDT_EVIDENCE_DIGEST_UPDATE(publication_token, 16u);
    MFDT_EVIDENCE_DIGEST_UPDATE(origin_transaction_id->bytes, 16u);
    MFDT_EVIDENCE_DIGEST_UPDATE(original_attempt_id->bytes, 16u);
    ninlil_mfdt_v1_put_u32(u32be, target_ordinal);
    MFDT_EVIDENCE_DIGEST_UPDATE(u32be, sizeof(u32be));
    ninlil_mfdt_v1_put_u32(u32be, (uint32_t)evidence_stage);
    MFDT_EVIDENCE_DIGEST_UPDATE(u32be, sizeof(u32be));
    ninlil_mfdt_v1_put_u32(u32be, (uint32_t)evidence.length);
    MFDT_EVIDENCE_DIGEST_UPDATE(u32be, sizeof(u32be));
    if (evidence.length != 0u) {
        MFDT_EVIDENCE_DIGEST_UPDATE(evidence.data, evidence.length);
    }
#undef MFDT_EVIDENCE_DIGEST_UPDATE
    status = ninlil_model_domain_sha256_final(&context, &digest);
    if (status != NINLIL_OK) {
        return status;
    }
    (void)memcpy(digest_out, digest.bytes, 32u);
    return NINLIL_OK;
}

static int application_header_is_canonical(
    uint16_t abi_version,
    uint16_t struct_size,
    size_t expected_size)
{
    return abi_version == NINLIL_ABI_VERSION
        && struct_size == expected_size;
}

static int application_id_is_zero(const ninlil_id128_t *id)
{
    return id != NULL && !bytes_nonzero(id->bytes, sizeof(id->bytes));
}

static int application_identity_presence_is_canonical(
    uint32_t flags,
    const ninlil_id128_t *device_id,
    const ninlil_id128_t *installation_id,
    const ninlil_id128_t *site_domain_id,
    uint64_t binding_epoch,
    uint64_t membership_epoch)
{
    const uint32_t known = NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    const int has_device =
        (flags & NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u;
    const int has_installation =
        (flags & NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u;
    const int has_site =
        (flags & NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u;

    return (flags & ~known) == 0u
        && has_device == bytes_nonzero(device_id->bytes, 16u)
        && has_installation == bytes_nonzero(installation_id->bytes, 16u)
        && has_site == bytes_nonzero(site_domain_id->bytes, 16u)
        && (binding_epoch != 0u) == (has_device || has_installation)
        && (membership_epoch != 0u) == has_site;
}

static int application_party_is_canonical(const ninlil_party_t *party)
{
    return party != NULL
        && application_header_is_canonical(
            party->abi_version, party->struct_size, sizeof(*party))
        && bytes_nonzero(party->runtime_id.bytes, 16u)
        && bytes_nonzero(party->application_instance_id.bytes, 16u)
        && application_header_is_canonical(
            party->local_identity.abi_version,
            party->local_identity.struct_size,
            sizeof(party->local_identity))
        && party->local_identity.reserved_zero == 0u
        && application_identity_presence_is_canonical(
            party->local_identity.flags,
            &party->local_identity.device_id,
            &party->local_identity.installation_id,
            &party->local_identity.site_domain_id,
            party->local_identity.binding_epoch,
            party->local_identity.membership_epoch);
}

static int application_target_is_canonical(
    const ninlil_concrete_target_t *target)
{
    return target != NULL
        && application_header_is_canonical(
            target->abi_version, target->struct_size, sizeof(*target))
        && bytes_nonzero(target->target_runtime_id.bytes, 16u)
        && bytes_nonzero(
            target->target_application_instance_id.bytes, 16u)
        && target->reserved_zero == 0u
        && application_identity_presence_is_canonical(
            target->flags,
            &target->device_id,
            &target->installation_id,
            &target->site_domain_id,
            target->binding_epoch,
            target->membership_epoch);
}

static int application_text_is_canonical(const ninlil_text_id_t *text)
{
    size_t index;

    if (text == NULL || text->length == 0u
        || text->length > sizeof(text->bytes)) {
        return 0;
    }
    for (index = text->length; index < sizeof(text->bytes); ++index) {
        if (text->bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int application_digest_is_canonical(
    const ninlil_digest256_t *digest)
{
    return digest != NULL
        && digest->algorithm == NINLIL_DIGEST_SHA256
        && digest->reserved_zero == 0u
        && bytes_nonzero(digest->bytes, sizeof(digest->bytes));
}

static int application_service_is_canonical(
    const ninlil_service_identity_t *service)
{
    return service != NULL
        && application_header_is_canonical(
            service->abi_version, service->struct_size, sizeof(*service))
        && application_text_is_canonical(&service->namespace_id)
        && application_text_is_canonical(&service->service_id)
        && application_text_is_canonical(&service->schema_id)
        && service->descriptor_revision != 0u
        && application_digest_is_canonical(&service->descriptor_digest)
        && service->schema_major != 0u
        && (ninlil_rt_v1_family_is_downlink(service->family)
            || ninlil_rt_v1_family_is_uplink(service->family));
}

static int application_family_binding_is_canonical(
    const ninlil_bearer_message_t *application)
{
    if (ninlil_rt_v1_family_is_downlink(application->service.family)) {
        return application_id_is_zero(&application->event_id)
            && application->generation != 0u
            && bytes_nonzero(
                application->deadline_clock_epoch_id.bytes, 16u)
            && application->absolute_effect_deadline_ms != 0u
            && application->absolute_effect_deadline_ms
                < NINLIL_NO_DEADLINE;
    }
    if (ninlil_rt_v1_family_is_uplink(application->service.family)) {
        const int identity_is_canonical =
            application->service.family == NINLIL_FAMILY_EVENT_FACT
            ? bytes_nonzero(application->event_id.bytes, 16u)
                && application->generation == 0u
            : application_id_is_zero(&application->event_id)
                && application->generation != 0u;

        return identity_is_canonical
            && application_id_is_zero(
                &application->deadline_clock_epoch_id)
            && application->absolute_effect_deadline_ms
                == NINLIL_NO_DEADLINE
            && application->evidence_grace_ms == 0u;
    }
    return 0;
}

static int application_unused_fields_are_canonical(
    const ninlil_bearer_message_t *application)
{
    return application->flags == 0u
        && application->receipt_stage == NINLIL_EVIDENCE_NONE
        && application->disposition == NINLIL_DISPOSITION_NONE
        && application->effect_certainty == NINLIL_EFFECT_CERTAINTY_NONE
        && application->retry_guidance == NINLIL_RETRY_NEVER
        && application->cancel_kind == 0u
        && application->retry_delay_ms == 0u
        && application->evidence_time.abi_version == 0u
        && application->evidence_time.struct_size == 0u
        && application_id_is_zero(
            &application->evidence_time.clock_epoch_id)
        && application->evidence_time.now_ms == 0u
        && application->evidence_time.trust == 0u
        && application->evidence_time.reserved_zero == 0u
        && application->evidence.data == NULL
        && application->evidence.length == 0u;
}

static int text_id_equal(
    const ninlil_text_id_t *left,
    const ninlil_text_id_t *right)
{
    return left != NULL && right != NULL
        && left->length == right->length
        && left->length <= sizeof(left->bytes)
        && memcmp(left->bytes, right->bytes, left->length) == 0;
}

/*
 * Claim by the reserved Service tuple, not by the remaining descriptor
 * fields. This keeps a malformed carrier from falling through to an ordinary
 * Application Service while the full carrier validator still fails closed.
 */
static int message_targets_mfdt_service(
    const ninlil_bearer_message_t *message)
{
    ninlil_service_identity_t canonical;

    if (message == NULL
        || ninlil_mfdt_v1_foundation_carrier_service_identity(&canonical)
            != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    return text_id_equal(
               &message->service.namespace_id,
               &canonical.namespace_id)
        && text_id_equal(
               &message->service.service_id,
               &canonical.service_id)
        && text_id_equal(
               &message->service.schema_id,
               &canonical.schema_id);
}

static void runtime_local_party(
    const ninlil_runtime_t *runtime,
    const ninlil_id128_t *application_instance_id,
    ninlil_party_t *party)
{
    (void)memset(party, 0, sizeof(*party));
    party->abi_version = NINLIL_ABI_VERSION;
    party->struct_size = (uint16_t)sizeof(*party);
    party->runtime_id = runtime->config.runtime_id;
    party->application_instance_id = *application_instance_id;
    party->local_identity.abi_version = NINLIL_ABI_VERSION;
    party->local_identity.struct_size =
        (uint16_t)sizeof(party->local_identity);
    party->local_identity.device_id = runtime->config.device_id;
    party->local_identity.installation_id =
        runtime->config.installation_id;
    party->local_identity.site_domain_id = runtime->config.site_domain_id;
    party->local_identity.binding_epoch = runtime->config.binding_epoch;
    party->local_identity.membership_epoch = runtime->config.membership_epoch;
    party->local_identity.flags = runtime->config.identity_flags;
}

static void peer_target_from_source(
    const ninlil_party_t *source,
    ninlil_concrete_target_t *target)
{
    (void)memset(target, 0, sizeof(*target));
    target->abi_version = NINLIL_ABI_VERSION;
    target->struct_size = (uint16_t)sizeof(*target);
    target->target_runtime_id = source->runtime_id;
    target->target_application_instance_id =
        source->application_instance_id;
    target->device_id = source->local_identity.device_id;
    target->installation_id = source->local_identity.installation_id;
    target->site_domain_id = source->local_identity.site_domain_id;
    target->binding_epoch = source->local_identity.binding_epoch;
    target->membership_epoch = source->local_identity.membership_epoch;
    target->flags = source->local_identity.flags;
}

static int wire_is_request(uint8_t type)
{
    return type == NINLIL_MFDT_V1_MSG_OPEN
        || type == NINLIL_MFDT_V1_MSG_MANIFEST_PAGE
        || type == NINLIL_MFDT_V1_MSG_CHUNK_OFFER
        || type == NINLIL_MFDT_V1_MSG_RESUME_QUERY
        || type == NINLIL_MFDT_V1_MSG_FINALIZE
        || type == NINLIL_MFDT_V1_MSG_ABORT;
}

static int wire_is_response(uint8_t type)
{
    return type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT
        || type == NINLIL_MFDT_V1_MSG_PAGE_ACCEPT
        || type == NINLIL_MFDT_V1_MSG_REJECT
        || type == NINLIL_MFDT_V1_MSG_BUSY
        || type == NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT
        || type == NINLIL_MFDT_V1_MSG_RESUME_STATE
        || type == NINLIL_MFDT_V1_MSG_TRANSFER_ACCEPT
        || type == NINLIL_MFDT_V1_MSG_ABORT_ACK;
}

static void binding_from_carrier(
    mfdt_runtime_binding_t *binding,
    const ninlil_mfdt_v1_foundation_carrier_t *carrier,
    const uint8_t transfer_id[16])
{
    (void)memset(binding, 0, sizeof(*binding));
    binding->application.abi_version = NINLIL_ABI_VERSION;
    binding->application.struct_size =
        (uint16_t)sizeof(binding->application);
    binding->application.kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    binding->application.source = carrier->config.source;
    binding->application.target = carrier->config.target;
    binding->application.service = carrier->service;
    (void)memcpy(binding->transfer_id, transfer_id, 16u);
    binding->occupied = 1u;
}

static int binding_matches_slot(
    const mfdt_runtime_binding_t *binding,
    const ninlil_mfdt_v1_host_slot_snapshot_t *slot,
    const ninlil_mfdt_v1_session_t *session)
{
    return binding != NULL && slot != NULL && session != NULL
        && binding->occupied != 0u && slot->occupied != 0u
        && slot->bind_valid != 0u
        && memcmp(binding->transfer_id, slot->transfer_id, 16u) == 0
        && memcmp(slot->peer_endpoint_id, session->peer_endpoint_id, 16u) == 0
        && slot->session_generation == session->session_generation
        && slot->session_cookie == session->session_cookie
        && memcmp(
               binding->application.source.runtime_id.bytes,
               session->local_endpoint_id,
               16u) == 0
        && memcmp(
               binding->application.target.target_runtime_id.bytes,
               session->peer_endpoint_id,
               16u) == 0;
}

static int host_snapshot(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner,
    ninlil_mfdt_v1_host_header_snapshot_t *header,
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT])
{
    (void)memset(header, 0, sizeof(*header));
    (void)memset(
        slots,
        0,
        sizeof(*slots) * NINLIL_MFDT_V1_HOST_SLOT_COUNT);
    return ninlil_mfdt_v1_host_snapshot(owner->host, header, slots);
}

static uint8_t route_from_index(uint8_t index)
{
    return index < NINLIL_MFDT_V1_HOST_SLOT_COUNT
        ? index : NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
}

static int select_pending_route(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner,
    const ninlil_mfdt_v1_host_header_snapshot_t *header,
    const ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT],
    uint8_t *route_out)
{
    uint8_t offset;

    for (offset = 0u; offset < MFDT_RUNTIME_ROUTE_COUNT; ++offset) {
        const uint8_t index = (uint8_t)(
            (owner->route_cursor + offset) % MFDT_RUNTIME_ROUTE_COUNT);
        const uint8_t route = route_from_index(index);
        const int pending = route == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE
            ? header->control_outbox_pending != 0u
            : slots[route].outbox_pending != 0u;

        if (pending == 0) {
            continue;
        }
        owner->route_cursor = (uint8_t)(
            (index + 1u) % MFDT_RUNTIME_ROUTE_COUNT);
        *route_out = route;
        return 1;
    }
    return 0;
}

static int trusted_time_sample_is_valid(
    const ninlil_time_sample_t *sample)
{
    return sample != NULL
        && sample->abi_version == NINLIL_ABI_VERSION
        && sample->struct_size == (uint16_t)sizeof(*sample)
        && bytes_nonzero(sample->clock_epoch_id.bytes, 16u)
        && sample->trust == NINLIL_CLOCK_TRUSTED
        && sample->reserved_zero == 0u;
}

static void clear_absent_bindings(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner,
    const ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT])
{
    uint8_t slot;

    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (slots[slot].occupied == 0u) {
            (void)memset(
                &owner->bindings[slot], 0, sizeof(owner->bindings[slot]));
        }
    }
}

static ninlil_status_t host_error_to_runtime(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner,
    int error)
{
    if (error == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
        error == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        owner->dispatch_fenced = 1u;
        owner->runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    return error == NINLIL_MFDT_V1_ERR_STORAGE
        ? NINLIL_E_STORAGE : NINLIL_E_INVALID_STATE;
}

static int owner_is_valid(
    const ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    return owner != NULL
        && owner->magic == MFDT_RUNTIME_OWNER_MAGIC
        && owner->runtime != NULL
        && owner->underlying_ops != NULL
        && owner->underlying_handle != NULL
        && owner->sidecar_open != 0u
        && owner->host != NULL
        && owner->iter_value_scratch != NULL;
}

static int key_is_binding(ninlil_bytes_view_t key)
{
    return key.data != NULL
        && key.length == MFDT_RUNTIME_BINDING_KEY_BYTES
        && memcmp(
               key.data,
               k_mfdt_binding_key,
               MFDT_RUNTIME_BINDING_KEY_BYTES) == 0;
}

static int key_is_mfdt(ninlil_bytes_view_t key)
{
    static const uint8_t kinds[4][4] = {
        {'N', 'M', '3', 'S'},
        {'N', 'M', '3', 'R'},
        {'N', 'M', '3', '0'},
        {'N', 'R', 'C', '1'}
    };
    size_t index;

    if (key.data == NULL || key.length != NINLIL_MFDT_V1_KEY_BYTES) {
        return 0;
    }
    for (index = 0u; index < 4u; ++index) {
        if (memcmp(key.data, kinds[index], 4u) == 0) {
            return 1;
        }
    }
    return 0;
}

static ninlil_status_t fence_storage_corrupt(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    if (owner != NULL && owner->runtime != NULL) {
        owner->runtime->commit_unknown_fence = 1u;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

static ninlil_status_t map_storage_status(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner,
    ninlil_storage_status_t status)
{
    switch (status) {
    case NINLIL_STORAGE_OK:
        return NINLIL_OK;
    case NINLIL_STORAGE_BUSY:
        return NINLIL_E_WOULD_BLOCK;
    case NINLIL_STORAGE_NO_SPACE:
        return NINLIL_E_CAPACITY_EXHAUSTED;
    case NINLIL_STORAGE_IO_ERROR:
        return NINLIL_E_STORAGE;
    case NINLIL_STORAGE_UNSUPPORTED_SCHEMA:
        return NINLIL_E_UNSUPPORTED;
    case NINLIL_STORAGE_COMMIT_UNKNOWN:
        if (owner != NULL && owner->runtime != NULL) {
            owner->runtime->commit_unknown_fence = 1u;
        }
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    case NINLIL_STORAGE_CORRUPT:
    case NINLIL_STORAGE_NOT_FOUND:
    case NINLIL_STORAGE_BUFFER_TOO_SMALL:
        return fence_storage_corrupt(owner);
    default:
        if (owner != NULL && owner->runtime != NULL) {
            owner->runtime->commit_unknown_fence = 1u;
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
}

static int derive_sidecar_namespace(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    uint8_t preimage[
        sizeof(k_mfdt_namespace_domain) - 1u + 2u
        + MFDT_RUNTIME_BASE_NAMESPACE_MAX];
    uint8_t digest[32];
    uint32_t base_length;
    uint32_t offset = 0u;

    if (owner == NULL || owner->runtime == NULL
        || owner->runtime->namespace_bytes == NULL
        || owner->runtime->namespace_length == 0u
        || owner->runtime->namespace_length > MFDT_RUNTIME_BASE_NAMESPACE_MAX
        || owner->runtime->namespace_length > UINT16_MAX) {
        return 0;
    }
    base_length = owner->runtime->namespace_length;
    (void)memcpy(
        preimage + offset,
        k_mfdt_namespace_domain,
        sizeof(k_mfdt_namespace_domain) - 1u);
    offset += (uint32_t)sizeof(k_mfdt_namespace_domain) - 1u;
    ninlil_mfdt_v1_put_u16(preimage + offset, (uint16_t)base_length);
    offset += 2u;
    (void)memcpy(
        preimage + offset,
        owner->runtime->namespace_bytes,
        base_length);
    offset += base_length;
    ninlil_mfdt_v1_sha256(preimage, offset, digest);
    (void)memcpy(owner->sidecar_namespace, "NMF1", 4u);
    (void)memcpy(owner->sidecar_namespace + 4u, digest, sizeof(digest));
    return 1;
}

static int build_binding_value(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    uint8_t digest_preimage[
        sizeof(k_mfdt_binding_digest_domain) - 1u + 2u
        + MFDT_RUNTIME_BASE_NAMESPACE_MAX];
    uint8_t digest[32];
    uint32_t base_length;
    uint32_t offset = 0u;
    uint32_t digest_offset = 0u;
    uint32_t total_length;

    if (owner == NULL || owner->runtime == NULL
        || owner->runtime->namespace_bytes == NULL
        || owner->runtime->namespace_length == 0u
        || owner->runtime->namespace_length > MFDT_RUNTIME_BASE_NAMESPACE_MAX
        || owner->runtime->namespace_length > UINT16_MAX) {
        return 0;
    }
    base_length = owner->runtime->namespace_length;
    total_length = MFDT_RUNTIME_BINDING_FIXED_BYTES + base_length;
    if (total_length > sizeof(owner->binding_value)) {
        return 0;
    }

    (void)memcpy(
        digest_preimage + digest_offset,
        k_mfdt_binding_digest_domain,
        sizeof(k_mfdt_binding_digest_domain) - 1u);
    digest_offset +=
        (uint32_t)sizeof(k_mfdt_binding_digest_domain) - 1u;
    ninlil_mfdt_v1_put_u16(
        digest_preimage + digest_offset, (uint16_t)base_length);
    digest_offset += 2u;
    (void)memcpy(
        digest_preimage + digest_offset,
        owner->runtime->namespace_bytes,
        base_length);
    digest_offset += base_length;
    ninlil_mfdt_v1_sha256(digest_preimage, digest_offset, digest);

    (void)memset(owner->binding_value, 0, sizeof(owner->binding_value));
    (void)memcpy(owner->binding_value + offset, "NMS1", 4u);
    offset += 4u;
    ninlil_mfdt_v1_put_u16(owner->binding_value + offset, 1u);
    offset += 2u;
    ninlil_mfdt_v1_put_u16(
        owner->binding_value + offset,
        (uint16_t)MFDT_RUNTIME_BINDING_HEADER_BYTES);
    offset += 2u;
    ninlil_mfdt_v1_put_u32(
        owner->binding_value + offset, total_length);
    offset += 4u;
    ninlil_mfdt_v1_put_u16(
        owner->binding_value + offset, (uint16_t)base_length);
    offset += 2u;
    ninlil_mfdt_v1_put_u16(owner->binding_value + offset, 0u);
    offset += 2u;
    (void)memcpy(owner->binding_value + offset, digest, sizeof(digest));
    offset += (uint32_t)sizeof(digest);
    (void)memcpy(
        owner->binding_value + offset,
        owner->runtime->namespace_bytes,
        base_length);
    offset += base_length;
    ninlil_mfdt_v1_put_u32(
        owner->binding_value + offset,
        ninlil_mfdt_v1_crc32c(owner->binding_value, offset));
    offset += 4u;
    if (offset != total_length) {
        return 0;
    }
    owner->binding_value_length = total_length;
    return 1;
}

static void sidecar_close(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    if (owner == NULL || owner->underlying_ops == NULL) {
        return;
    }
    if (owner->underlying_handle != NULL
        && owner->underlying_ops->close != NULL) {
        owner->underlying_ops->close(
            owner->underlying_ops->user, owner->underlying_handle);
    }
    owner->underlying_handle = NULL;
    owner->sidecar_open = 0u;
}

static ninlil_status_t sidecar_open(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    ninlil_bytes_view_t storage_namespace;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_status_t status;

    if (owner == NULL || owner->underlying_ops == NULL
        || owner->underlying_ops->open == NULL
        || owner->underlying_handle != NULL
        || owner->sidecar_open != 0u) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    storage_namespace.data = owner->sidecar_namespace;
    storage_namespace.length = MFDT_RUNTIME_SIDECAR_NAMESPACE_BYTES;
    status = owner->underlying_ops->open(
        owner->underlying_ops->user,
        storage_namespace,
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status == NINLIL_STORAGE_OK && handle != NULL) {
        owner->underlying_handle = handle;
        owner->sidecar_open = 1u;
        return NINLIL_OK;
    }
    if (handle != NULL && owner->underlying_ops->close != NULL) {
        owner->underlying_ops->close(
            owner->underlying_ops->user, handle);
    }
    return status == NINLIL_STORAGE_OK
        ? NINLIL_E_STORAGE_CORRUPT
        : map_storage_status(owner, status);
}

static ninlil_status_t sidecar_scan(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner,
    uint32_t *empty_out,
    uint32_t *row_count_out)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_bytes_view_t prefix;
    ninlil_storage_status_t storage_status;
    ninlil_status_t result = NINLIL_OK;
    uint32_t row_count = 0u;
    uint32_t binding_count = 0u;

    if (owner == NULL || empty_out == NULL || row_count_out == NULL
        || owner->underlying_ops == NULL
        || owner->underlying_handle == NULL
        || owner->iter_value_scratch == NULL) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *empty_out = 0u;
    *row_count_out = 0u;
    storage_status = owner->underlying_ops->begin(
        owner->underlying_ops->user,
        owner->underlying_handle,
        NINLIL_STORAGE_READ_ONLY,
        &transaction);
    if (storage_status != NINLIL_STORAGE_OK || transaction == NULL) {
        if (transaction != NULL) {
            (void)owner->underlying_ops->rollback(
                owner->underlying_ops->user, transaction);
        }
        return storage_status == NINLIL_STORAGE_OK
            ? NINLIL_E_STORAGE_CORRUPT
            : map_storage_status(owner, storage_status);
    }

    prefix.data = NULL;
    prefix.length = 0u;
    storage_status = owner->underlying_ops->iter_open(
        owner->underlying_ops->user,
        transaction,
        prefix,
        &iterator);
    if (storage_status != NINLIL_STORAGE_OK || iterator == NULL) {
        if (iterator != NULL) {
            owner->underlying_ops->iter_close(
                owner->underlying_ops->user, iterator);
        }
        result = storage_status == NINLIL_STORAGE_OK
            ? NINLIL_E_STORAGE_CORRUPT
            : map_storage_status(owner, storage_status);
    }

    while (result == NINLIL_OK) {
        ninlil_mut_bytes_t key;
        ninlil_mut_bytes_t value;
        ninlil_bytes_view_t key_view;

        key.data = owner->iter_key_scratch;
        key.capacity = (uint32_t)sizeof(owner->iter_key_scratch);
        key.length = 0u;
        value.data = owner->iter_value_scratch;
        value.capacity = MFDT_RUNTIME_ITER_VALUE_CAP;
        value.length = 0u;
        storage_status = owner->underlying_ops->iter_next(
            owner->underlying_ops->user, iterator, &key, &value);
        if (storage_status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                result = NINLIL_E_STORAGE_CORRUPT;
            }
            break;
        }
        if (storage_status != NINLIL_STORAGE_OK
            || key.data != owner->iter_key_scratch
            || key.capacity != sizeof(owner->iter_key_scratch)
            || value.data != owner->iter_value_scratch
            || value.capacity != MFDT_RUNTIME_ITER_VALUE_CAP
            || key.length == 0u
            || key.length > key.capacity
            || value.length > value.capacity) {
            result = storage_status == NINLIL_STORAGE_OK
                ? NINLIL_E_STORAGE_CORRUPT
                : map_storage_status(owner, storage_status);
            break;
        }
        row_count += 1u;
        if (row_count > MFDT_RUNTIME_SIDECAR_TOTAL_KEYS_MAX) {
            result = NINLIL_E_STORAGE_CORRUPT;
            break;
        }
        key_view.data = key.data;
        key_view.length = key.length;
        if (key_is_binding(key_view)) {
            binding_count += 1u;
            if (binding_count != 1u
                || value.length != owner->binding_value_length
                || memcmp(
                       value.data,
                       owner->binding_value,
                       owner->binding_value_length) != 0) {
                result = NINLIL_E_STORAGE_CORRUPT;
            }
        } else if (!key_is_mfdt(key_view)) {
            result = NINLIL_E_STORAGE_CORRUPT;
        }
    }

    if (iterator != NULL) {
        owner->underlying_ops->iter_close(
            owner->underlying_ops->user, iterator);
        iterator = NULL;
    }
    storage_status = owner->underlying_ops->rollback(
        owner->underlying_ops->user, transaction);
    transaction = NULL;
    if (storage_status != NINLIL_STORAGE_OK) {
        ninlil_status_t cleanup_status =
            map_storage_status(owner, storage_status);
        if (result == NINLIL_OK) {
            result = cleanup_status;
        }
    }
    if (result != NINLIL_OK) {
        if (result == NINLIL_E_STORAGE_CORRUPT) {
            (void)fence_storage_corrupt(owner);
        }
        return result;
    }
    *row_count_out = row_count;
    if (row_count == 0u) {
        *empty_out = 1u;
        return NINLIL_OK;
    }
    return binding_count == 1u
        ? NINLIL_OK : fence_storage_corrupt(owner);
}

static ninlil_storage_status_t sidecar_write_binding(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    ninlil_storage_txn_t transaction = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_bytes_view_t prefix;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    ninlil_storage_status_t status;

    status = owner->underlying_ops->begin(
        owner->underlying_ops->user,
        owner->underlying_handle,
        NINLIL_STORAGE_READ_WRITE,
        &transaction);
    if (status != NINLIL_STORAGE_OK || transaction == NULL) {
        if (transaction != NULL) {
            (void)owner->underlying_ops->rollback(
                owner->underlying_ops->user, transaction);
        }
        return status == NINLIL_STORAGE_OK
            ? NINLIL_STORAGE_CORRUPT : status;
    }

    prefix.data = NULL;
    prefix.length = 0u;
    status = owner->underlying_ops->iter_open(
        owner->underlying_ops->user,
        transaction,
        prefix,
        &iterator);
    if (status == NINLIL_STORAGE_OK && iterator != NULL) {
        ninlil_mut_bytes_t observed_key;
        ninlil_mut_bytes_t observed_value;

        observed_key.data = owner->iter_key_scratch;
        observed_key.capacity =
            (uint32_t)sizeof(owner->iter_key_scratch);
        observed_key.length = 0u;
        observed_value.data = owner->iter_value_scratch;
        observed_value.capacity = MFDT_RUNTIME_ITER_VALUE_CAP;
        observed_value.length = 0u;
        status = owner->underlying_ops->iter_next(
            owner->underlying_ops->user,
            iterator,
            &observed_key,
            &observed_value);
        owner->underlying_ops->iter_close(
            owner->underlying_ops->user, iterator);
        iterator = NULL;
        if (observed_key.data != owner->iter_key_scratch
            || observed_key.capacity != sizeof(owner->iter_key_scratch)
            || observed_value.data != owner->iter_value_scratch
            || observed_value.capacity != MFDT_RUNTIME_ITER_VALUE_CAP
            || observed_key.length > observed_key.capacity
            || observed_value.length > observed_value.capacity) {
            status = NINLIL_STORAGE_CORRUPT;
        } else if (status == NINLIL_STORAGE_OK) {
            status = NINLIL_STORAGE_BUSY;
        } else if (status == NINLIL_STORAGE_NOT_FOUND
            && observed_key.length == 0u
            && observed_value.length == 0u) {
            status = NINLIL_STORAGE_OK;
        } else if (status == NINLIL_STORAGE_NOT_FOUND) {
            status = NINLIL_STORAGE_CORRUPT;
        }
    } else {
        if (iterator != NULL) {
            owner->underlying_ops->iter_close(
                owner->underlying_ops->user, iterator);
            iterator = NULL;
        }
        if (status == NINLIL_STORAGE_OK) {
            status = NINLIL_STORAGE_CORRUPT;
        }
    }
    if (status != NINLIL_STORAGE_OK) {
        ninlil_storage_status_t rollback_status =
            owner->underlying_ops->rollback(
                owner->underlying_ops->user, transaction);
        return rollback_status == NINLIL_STORAGE_OK
            ? status : rollback_status;
    }

    key.data = k_mfdt_binding_key;
    key.length = MFDT_RUNTIME_BINDING_KEY_BYTES;
    value.data = owner->binding_value;
    value.length = owner->binding_value_length;
    status = owner->underlying_ops->put(
        owner->underlying_ops->user, transaction, key, value);
    if (status != NINLIL_STORAGE_OK) {
        ninlil_storage_status_t rollback_status =
            owner->underlying_ops->rollback(
                owner->underlying_ops->user, transaction);
        return rollback_status == NINLIL_STORAGE_OK
            ? status : rollback_status;
    }
    return owner->underlying_ops->commit(
        owner->underlying_ops->user,
        transaction,
        NINLIL_DURABILITY_FULL);
}

static ninlil_status_t sidecar_bootstrap(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    uint32_t empty = 0u;
    uint32_t row_count = 0u;
    uint32_t attempt;
    ninlil_status_t result;

    result = sidecar_scan(owner, &empty, &row_count);
    if (result != NINLIL_OK || empty == 0u) {
        return result;
    }
    for (attempt = 0u; attempt < 2u; ++attempt) {
        ninlil_storage_status_t storage_status =
            sidecar_write_binding(owner);

        if (storage_status == NINLIL_STORAGE_BUSY) {
            result = sidecar_scan(owner, &empty, &row_count);
            if (result != NINLIL_OK) {
                return result;
            }
            if (empty == 0u) {
                return row_count == 1u
                    ? NINLIL_OK : fence_storage_corrupt(owner);
            }
            continue;
        }
        if (storage_status == NINLIL_STORAGE_OK) {
            result = sidecar_scan(owner, &empty, &row_count);
            if (result != NINLIL_OK) {
                return result;
            }
            return empty == 0u && row_count == 1u
                ? NINLIL_OK : fence_storage_corrupt(owner);
        }
        if (storage_status != NINLIL_STORAGE_COMMIT_UNKNOWN) {
            return map_storage_status(owner, storage_status);
        }

        sidecar_close(owner);
        result = sidecar_open(owner);
        if (result != NINLIL_OK) {
            owner->runtime->commit_unknown_fence = 1u;
            return result;
        }
        result = sidecar_scan(owner, &empty, &row_count);
        if (result != NINLIL_OK) {
            owner->runtime->commit_unknown_fence = 1u;
            return result;
        }
        if (empty == 0u) {
            if (row_count == 1u) {
                return NINLIL_OK;
            }
            return fence_storage_corrupt(owner);
        }
    }
    return NINLIL_E_WOULD_BLOCK;
}

static ninlil_storage_status_t filtered_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    (void)user;
    (void)storage_namespace;
    (void)expected_schema;
    if (out_handle != NULL) {
        *out_handle = NULL;
    }
    return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
}

static void filtered_close(void *user, ninlil_storage_handle_t handle)
{
    (void)user;
    (void)handle;
}

static ninlil_storage_status_t filtered_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner) || handle != (ninlil_storage_handle_t)owner
        || out_txn == NULL || *out_txn != NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return owner->underlying_ops->begin(
        owner->underlying_ops->user,
        owner->underlying_handle,
        mode,
        out_txn);
}

static ninlil_storage_status_t filtered_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner) || txn == NULL || !key_is_mfdt(key)
        || inout_value == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return owner->underlying_ops->get(
        owner->underlying_ops->user, txn, key, inout_value);
}

static ninlil_storage_status_t filtered_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner) || txn == NULL || !key_is_mfdt(key)
        || (value.length != 0u && value.data == NULL)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return owner->underlying_ops->put(
        owner->underlying_ops->user, txn, key, value);
}

static ninlil_storage_status_t filtered_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner) || txn == NULL || !key_is_mfdt(key)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return owner->underlying_ops->erase(
        owner->underlying_ops->user, txn, key);
}

static ninlil_storage_status_t filtered_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;
    ninlil_storage_iter_t underlying = NULL;
    ninlil_storage_status_t status;

    if (!owner_is_valid(owner) || txn == NULL || out_iter == NULL
        || *out_iter != NULL || owner->iterator.active != 0u
        || (prefix.length != 0u && prefix.data == NULL)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    status = owner->underlying_ops->iter_open(
        owner->underlying_ops->user, txn, prefix, &underlying);
    if (status != NINLIL_STORAGE_OK) {
        return status;
    }
    if (underlying == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    owner->iterator.underlying = underlying;
    owner->iterator.active = 1u;
    *out_iter = (ninlil_storage_iter_t)&owner->iterator;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t filtered_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner)
        || iter != (ninlil_storage_iter_t)&owner->iterator
        || owner->iterator.active == 0u
        || owner->iterator.underlying == NULL
        || inout_key == NULL || inout_value == NULL
        || inout_key->data == NULL || inout_value->data == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    for (;;) {
        ninlil_mut_bytes_t key;
        ninlil_mut_bytes_t value;
        ninlil_bytes_view_t key_view;
        ninlil_storage_status_t status;

        key.data = owner->iter_key_scratch;
        key.capacity = (uint32_t)sizeof(owner->iter_key_scratch);
        key.length = 0u;
        value.data = owner->iter_value_scratch;
        value.capacity = MFDT_RUNTIME_ITER_VALUE_CAP;
        value.length = 0u;
        status = owner->underlying_ops->iter_next(
            owner->underlying_ops->user,
            owner->iterator.underlying,
            &key,
            &value);
        if (status != NINLIL_STORAGE_OK) {
            inout_key->length = 0u;
            inout_value->length = 0u;
            return status;
        }
        key_view.data = key.data;
        key_view.length = key.length;
        if (key_is_binding(key_view)) {
            continue;
        }
        if (!key_is_mfdt(key_view)) {
            inout_key->length = 0u;
            inout_value->length = 0u;
            return NINLIL_STORAGE_CORRUPT;
        }
        if (key.length > inout_key->capacity
            || value.length > inout_value->capacity) {
            inout_key->length = key.length;
            inout_value->length = value.length;
            return NINLIL_STORAGE_BUFFER_TOO_SMALL;
        }
        (void)memcpy(inout_key->data, key.data, key.length);
        if (value.length != 0u) {
            (void)memcpy(inout_value->data, value.data, value.length);
        }
        inout_key->length = key.length;
        inout_value->length = value.length;
        return NINLIL_STORAGE_OK;
    }
}

static void filtered_iter_close(void *user, ninlil_storage_iter_t iter)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner)
        || iter != (ninlil_storage_iter_t)&owner->iterator
        || owner->iterator.active == 0u) {
        return;
    }
    owner->underlying_ops->iter_close(
        owner->underlying_ops->user, owner->iterator.underlying);
    (void)memset(&owner->iterator, 0, sizeof(owner->iterator));
}

static ninlil_storage_status_t filtered_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner) || handle != (ninlil_storage_handle_t)owner
        || out_capacity == NULL || owner->underlying_ops->capacity == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return owner->underlying_ops->capacity(
        owner->underlying_ops->user,
        owner->underlying_handle,
        out_capacity);
}

static ninlil_storage_status_t filtered_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner) || txn == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return owner->underlying_ops->commit(
        owner->underlying_ops->user, txn, durability);
}

static ninlil_storage_status_t filtered_rollback(
    void *user,
    ninlil_storage_txn_t txn)
{
    ninlil_rt_mfdt_v1_runtime_owner_t *owner =
        (ninlil_rt_mfdt_v1_runtime_owner_t *)user;

    if (!owner_is_valid(owner) || txn == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    return owner->underlying_ops->rollback(
        owner->underlying_ops->user, txn);
}

static void owner_deallocate(
    ninlil_runtime_t *runtime,
    void *pointer,
    uint64_t size,
    uint32_t alignment)
{
    if (runtime != NULL && runtime->platform != NULL
        && runtime->platform->allocator != NULL
        && runtime->platform->allocator->deallocate != NULL
        && pointer != NULL) {
        runtime->platform->allocator->deallocate(
            runtime->platform->allocator->user,
            pointer,
            size,
            alignment);
    }
}

static void *owner_allocate(
    ninlil_runtime_t *runtime,
    uint64_t size,
    uint32_t alignment)
{
    if (runtime == NULL || runtime->platform == NULL
        || runtime->platform->allocator == NULL
        || runtime->platform->allocator->allocate == NULL) {
        return NULL;
    }
    return runtime->platform->allocator->allocate(
        runtime->platform->allocator->user, size, alignment);
}

static void owner_free(ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    ninlil_runtime_t *runtime;

    if (owner == NULL) {
        return;
    }
    runtime = owner->runtime;
    if (owner->iterator.active != 0u
        && owner->iterator.underlying != NULL
        && owner->underlying_ops != NULL
        && owner->underlying_ops->iter_close != NULL) {
        owner->underlying_ops->iter_close(
            owner->underlying_ops->user,
            owner->iterator.underlying);
        (void)memset(&owner->iterator, 0, sizeof(owner->iterator));
    }
    sidecar_close(owner);
    if (owner->host != NULL) {
        (void)memset(owner->host, 0, sizeof(*owner->host));
        owner_deallocate(
            runtime,
            owner->host,
            sizeof(*owner->host),
            (uint32_t)_Alignof(ninlil_mfdt_v1_host_owner_t));
        owner->host = NULL;
    }
    if (owner->iter_value_scratch != NULL) {
        (void)memset(
            owner->iter_value_scratch, 0, MFDT_RUNTIME_ITER_VALUE_CAP);
        owner_deallocate(
            runtime,
            owner->iter_value_scratch,
            MFDT_RUNTIME_ITER_VALUE_CAP,
            8u);
        owner->iter_value_scratch = NULL;
    }
    (void)memset(owner, 0, sizeof(*owner));
    owner_deallocate(
        runtime,
        owner,
        sizeof(*owner),
        (uint32_t)_Alignof(ninlil_rt_mfdt_v1_runtime_owner_t));
}

static int storage_has_host_capacity(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    ninlil_storage_capacity_t capacity;
    ninlil_storage_status_t status;

    if (owner->underlying_ops->capacity == NULL) {
        return 0;
    }
    (void)memset(&capacity, 0, sizeof(capacity));
    capacity.abi_version = NINLIL_ABI_VERSION;
    capacity.struct_size = (uint16_t)sizeof(capacity);
    status = owner->underlying_ops->capacity(
        owner->underlying_ops->user,
        owner->underlying_handle,
        &capacity);
    if (status != NINLIL_STORAGE_OK
        || capacity.used_entries > capacity.max_entries
        || capacity.used_bytes > capacity.max_bytes) {
        return 0;
    }
    return capacity.max_entries - capacity.used_entries
            >= NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX
        && capacity.max_bytes - capacity.used_bytes
            >= NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX;
}

static void filtered_ops_init(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    (void)memset(&owner->filtered_ops, 0, sizeof(owner->filtered_ops));
    owner->filtered_ops.abi_version = NINLIL_ABI_VERSION;
    owner->filtered_ops.struct_size =
        (uint16_t)sizeof(owner->filtered_ops);
    owner->filtered_ops.user = owner;
    owner->filtered_ops.open = filtered_open;
    owner->filtered_ops.close = filtered_close;
    owner->filtered_ops.begin = filtered_begin;
    owner->filtered_ops.get = filtered_get;
    owner->filtered_ops.put = filtered_put;
    owner->filtered_ops.erase = filtered_erase;
    owner->filtered_ops.iter_open = filtered_iter_open;
    owner->filtered_ops.iter_next = filtered_iter_next;
    owner->filtered_ops.iter_close = filtered_iter_close;
    owner->filtered_ops.capacity = filtered_capacity;
    owner->filtered_ops.commit = filtered_commit;
    owner->filtered_ops.rollback = filtered_rollback;
}

static void guarantees_init(
    ninlil_mfdt_v1_store_guarantees_t *guarantees)
{
    (void)memset(guarantees, 0, sizeof(*guarantees));
    guarantees->struct_size = (uint32_t)sizeof(*guarantees);
    guarantees->flags = NINLIL_MFDT_V1_STORE_REQUIRED_FLAGS;
    guarantees->committed_keys_max =
        NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX;
    guarantees->begin_final_row_images_max =
        NINLIL_MFDT_V1_HOST_BEGIN_FINAL_ROW_IMAGES_MAX;
    guarantees->full_ops_max = NINLIL_MFDT_V1_HOST_FULL_OPS_MAX;
    guarantees->committed_logical_bytes_max =
        NINLIL_MFDT_V1_HOST_COMMITTED_LOGICAL_BYTES_MAX;
    guarantees->full_staging_logical_bytes_max =
        NINLIL_MFDT_V1_HOST_FULL_STAGING_LOGICAL_BYTES_MAX;
    guarantees->begin_final_union_logical_bytes_max =
        NINLIL_MFDT_V1_HOST_BEGIN_FINAL_UNION_LOGICAL_BYTES_MAX;
}

static int recovered_foundation_sender_shape_is_exact(
    const ninlil_rt_transaction_slot_t *transaction)
{
    ninlil_bearer_message_t derivation_application;
    uint8_t derived_transfer_id[16];
    uint32_t target_index;

    if (transaction == NULL || transaction->in_use == 0u ||
        transaction->terminal != 0u || transaction->event_discarded != 0u ||
        transaction->origin_admission != 1u ||
        transaction->bearer_route !=
            (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1 ||
        transaction->bound_target_count == 0u ||
        transaction->bound_target_count > NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        transaction->active_target_index != 0u ||
        transaction->payload_length <= NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES ||
        transaction->payload_length > NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES ||
        transaction->inline_payload_length != 0u ||
        transaction->content_digest.algorithm != NINLIL_DIGEST_SHA256 ||
        transaction->content_digest.reserved_zero != 0u ||
        transaction->attempt_prepared != 1u ||
        transaction->attempt_count != transaction->bound_target_count ||
        transaction->cumulative_attempts != transaction->bound_target_count ||
        !bytes_nonzero(transaction->attempt_id.bytes, 16u) ||
        memcmp(
            transaction->attempt_id.bytes,
            transaction->bound_targets[0].active_attempt_id.bytes,
            16u) != 0) {
        return 0;
    }
    (void)memset(&derivation_application, 0, sizeof(derivation_application));
    derivation_application.transaction_id = transaction->transaction_id;
    for (target_index = 0u;
         target_index < transaction->bound_target_count;
         ++target_index) {
        const ninlil_rt_target_slot_t *target =
            &transaction->bound_targets[target_index];
        uint32_t prior;

        if (target->in_use != 1u || target->terminal != 0u ||
            target->attempt_prepared != 1u ||
            target->mfdt_target_ordinal != target_index ||
            !bytes_nonzero(target->mfdt_transfer_id, 16u) ||
            !bytes_nonzero(target->active_attempt_id.bytes, 16u) ||
            transaction->attempt_target_indices[target_index] !=
                target_index ||
            memcmp(
                target->active_attempt_id.bytes,
                transaction->attempt_ids[target_index].bytes,
                16u) != 0 ||
            !bytes_nonzero(target->target.target_runtime_id.bytes, 16u)) {
            return 0;
        }
        derivation_application.target.target_runtime_id =
            target->target.target_runtime_id;
        ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
            &derivation_application, target_index, derived_transfer_id);
        if (memcmp(
                target->mfdt_transfer_id,
                derived_transfer_id,
                sizeof(derived_transfer_id)) != 0) {
            return 0;
        }
        for (prior = 0u; prior < target_index; ++prior) {
            if (memcmp(
                    transaction->bound_targets[prior].mfdt_transfer_id,
                    target->mfdt_transfer_id,
                    16u) == 0 ||
                memcmp(
                    transaction->bound_targets[prior].target
                        .target_runtime_id.bytes,
                    target->target.target_runtime_id.bytes,
                    16u) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

static void recovered_sender_expectation_from_foundation(
    const ninlil_rt_transaction_slot_t *transaction,
    uint32_t target_index,
    ninlil_mfdt_v1_host_sender_expectation_t *expected)
{
    const ninlil_rt_target_slot_t *target =
        &transaction->bound_targets[target_index];
    ninlil_mfdt_v1_open_metadata_t *metadata;

    (void)memset(expected, 0, sizeof(*expected));
    (void)memcpy(
        expected->transfer_id, target->mfdt_transfer_id, 16u);
    (void)memcpy(
        expected->content_digest,
        transaction->content_digest.bytes,
        sizeof(expected->content_digest));
    expected->content_length = transaction->payload_length;
    metadata = &expected->metadata;
    (void)memcpy(
        metadata->origin_transaction_id,
        transaction->transaction_id.bytes, 16u);
    (void)memcpy(
        metadata->origin_event_id, transaction->event_id.bytes, 16u);
    (void)memcpy(
        metadata->source_runtime_id,
        transaction->source.runtime_id.bytes, 16u);
    (void)memcpy(
        metadata->target_runtime_id,
        target->target.target_runtime_id.bytes, 16u);
    metadata->service_descriptor_revision =
        transaction->service.descriptor_revision;
    (void)memcpy(
        metadata->service_descriptor_digest,
        transaction->service.descriptor_digest.bytes, 32u);
    (void)memcpy(
        metadata->deadline_clock_epoch_id,
        transaction->deadline_clock_epoch_id.bytes, 16u);
    metadata->absolute_effect_deadline_ms =
        transaction->effect_deadline_ms;
    (void)memcpy(
        metadata->original_attempt_id,
        target->active_attempt_id.bytes, 16u);
    metadata->target_ordinal = target->mfdt_target_ordinal;
    (void)memcpy(
        metadata->source_application_instance_id,
        transaction->source.application_instance_id.bytes, 16u);
    (void)memcpy(
        metadata->source_device_id,
        transaction->source.local_identity.device_id.bytes, 16u);
    (void)memcpy(
        metadata->source_installation_id,
        transaction->source.local_identity.installation_id.bytes, 16u);
    (void)memcpy(
        metadata->source_site_id,
        transaction->source.local_identity.site_domain_id.bytes, 16u);
    metadata->source_binding_epoch =
        transaction->source.local_identity.binding_epoch;
    metadata->source_membership_epoch =
        transaction->source.local_identity.membership_epoch;
    metadata->source_identity_flags =
        transaction->source.local_identity.flags;
    metadata->source_reserved =
        transaction->source.local_identity.reserved_zero;
    (void)memcpy(
        metadata->target_application_instance_id,
        target->target.target_application_instance_id.bytes, 16u);
    (void)memcpy(
        metadata->target_device_id, target->target.device_id.bytes, 16u);
    (void)memcpy(
        metadata->target_installation_id,
        target->target.installation_id.bytes, 16u);
    (void)memcpy(
        metadata->target_site_id,
        target->target.site_domain_id.bytes, 16u);
    metadata->target_binding_epoch = target->target.binding_epoch;
    metadata->target_membership_epoch = target->target.membership_epoch;
    metadata->target_identity_flags = target->target.flags;
    metadata->target_reserved = target->target.reserved_zero;
    metadata->service_schema_major = transaction->service.schema_major;
    metadata->service_schema_minor = transaction->service.schema_minor;
    metadata->service_family = transaction->service.family;
    metadata->application_generation = transaction->generation;
    metadata->evidence_grace_ms = transaction->evidence_grace_ms;
    metadata->required_evidence = transaction->required_evidence;
    metadata->namespace_bytes = transaction->service.namespace_id.bytes;
    metadata->namespace_length = transaction->service.namespace_id.length;
    metadata->service_bytes = transaction->service.service_id.bytes;
    metadata->service_length = transaction->service.service_id.length;
    metadata->schema_bytes = transaction->service.schema_id.bytes;
    metadata->schema_length = transaction->service.schema_id.length;
}

static void recovered_runtime_binding_from_foundation(
    const ninlil_rt_transaction_slot_t *transaction,
    uint32_t target_index,
    mfdt_runtime_binding_t *binding)
{
    ninlil_bearer_message_t *application;
    const ninlil_rt_target_slot_t *target =
        &transaction->bound_targets[target_index];

    (void)memset(binding, 0, sizeof(*binding));
    application = &binding->application;
    application->abi_version = NINLIL_ABI_VERSION;
    application->struct_size = (uint16_t)sizeof(*application);
    application->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    application->transaction_id = transaction->transaction_id;
    application->attempt_id = target->active_attempt_id;
    application->event_id = transaction->event_id;
    application->source = transaction->source;
    application->target = target->target;
    application->service = transaction->service;
    application->content_digest = transaction->content_digest;
    application->generation = transaction->generation;
    application->deadline_clock_epoch_id =
        transaction->deadline_clock_epoch_id;
    application->absolute_effect_deadline_ms =
        transaction->effect_deadline_ms;
    application->evidence_grace_ms = transaction->evidence_grace_ms;
    application->required_evidence = transaction->required_evidence;
    (void)memcpy(binding->transfer_id, target->mfdt_transfer_id, 16u);
    binding->occupied = 1u;
    binding->target_ordinal = (uint8_t)target_index;
}

static int receiver_open_target_matches_runtime(
    const ninlil_runtime_t *runtime,
    const ninlil_concrete_target_t *target)
{
    const int has_device =
        (target->flags & NINLIL_TARGET_HAS_DEVICE) != 0u;
    const int has_installation =
        (target->flags & NINLIL_TARGET_HAS_INSTALLATION) != 0u;
    const int has_site =
        (target->flags & NINLIL_TARGET_HAS_SITE) != 0u;

    return memcmp(
               target->target_runtime_id.bytes,
               runtime->config.runtime_id.bytes,
               16u) == 0 &&
        (!has_device ||
         ((runtime->config.identity_flags &
              NINLIL_LOCAL_IDENTITY_HAS_DEVICE) != 0u &&
          memcmp(
              target->device_id.bytes,
              runtime->config.device_id.bytes,
              16u) == 0)) &&
        (!has_installation ||
         ((runtime->config.identity_flags &
              NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION) != 0u &&
          memcmp(
              target->installation_id.bytes,
              runtime->config.installation_id.bytes,
              16u) == 0)) &&
        (!(has_device || has_installation) ||
         target->binding_epoch == runtime->config.binding_epoch) &&
        (!has_site ||
         ((runtime->config.identity_flags &
              NINLIL_LOCAL_IDENTITY_HAS_SITE) != 0u &&
          memcmp(
              target->site_domain_id.bytes,
              runtime->config.site_domain_id.bytes,
              16u) == 0 &&
          target->membership_epoch ==
              runtime->config.membership_epoch));
}

static int receiver_application_from_ready_open(
    const ninlil_runtime_t *runtime,
    const ninlil_mfdt_v1_host_receiver_ready_view_t *view,
    ninlil_bearer_message_t *application,
    uint32_t *target_ordinal_out)
{
    const uint8_t *open;
    uint16_t namespace_length;
    uint16_t service_length;
    uint16_t schema_length;
    uint32_t target_ordinal;
    uint8_t derived_transfer_id[16];

    if (runtime == NULL || view == NULL || application == NULL ||
        target_ordinal_out == NULL || view->open_body == NULL ||
        view->content == NULL ||
        view->open_body_length < NINLIL_MFDT_V1_OPEN_BODY_MIN ||
        view->open_body_length > NINLIL_MFDT_V1_OPEN_BODY_MAX ||
        view->content_length <= NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES ||
        view->content_length > NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES ||
        !bytes_nonzero(view->transfer_id, 16u) ||
        !bytes_nonzero(view->peer_endpoint_id, 16u) ||
        !bytes_nonzero(view->publication_token, 16u) ||
        view->acceptance_generation == 0u) {
        return 0;
    }
    open = view->open_body;
    namespace_length = ninlil_mfdt_v1_get_u16(open + 170u);
    service_length = ninlil_mfdt_v1_get_u16(open + 172u);
    schema_length = ninlil_mfdt_v1_get_u16(open + 174u);
    target_ordinal = ninlil_mfdt_v1_get_u32(open + 250u);
    if (namespace_length == 0u || service_length == 0u ||
        schema_length == 0u ||
        namespace_length > NINLIL_MAX_TEXT_ID_BYTES ||
        service_length > NINLIL_MAX_TEXT_ID_BYTES ||
        schema_length > NINLIL_MAX_TEXT_ID_BYTES ||
        (uint32_t)NINLIL_MFDT_V1_OPEN_TEXT_OFFSET +
                namespace_length + service_length + schema_length !=
            view->open_body_length ||
        ninlil_mfdt_v1_get_u32(open + 20u) != view->content_length ||
        target_ordinal >= NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        memcmp(open, view->transfer_id, 16u) != 0 ||
        memcmp(open + 96u, view->peer_endpoint_id, 16u) != 0 ||
        memcmp(open + 112u, runtime->config.runtime_id.bytes, 16u) != 0) {
        return 0;
    }
    (void)memset(application, 0, sizeof(*application));
    application->abi_version = NINLIL_ABI_VERSION;
    application->struct_size = (uint16_t)sizeof(*application);
    application->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    (void)memcpy(application->transaction_id.bytes, open + 64u, 16u);
    (void)memcpy(application->event_id.bytes, open + 80u, 16u);
    (void)memcpy(application->attempt_id.bytes, open + 234u, 16u);

    application->source.abi_version = NINLIL_ABI_VERSION;
    application->source.struct_size =
        (uint16_t)sizeof(application->source);
    (void)memcpy(application->source.runtime_id.bytes, open + 96u, 16u);
    (void)memcpy(
        application->source.application_instance_id.bytes,
        open + 254u,
        16u);
    application->source.local_identity.abi_version = NINLIL_ABI_VERSION;
    application->source.local_identity.struct_size =
        (uint16_t)sizeof(application->source.local_identity);
    (void)memcpy(
        application->source.local_identity.device_id.bytes,
        open + 270u,
        16u);
    (void)memcpy(
        application->source.local_identity.installation_id.bytes,
        open + 286u,
        16u);
    (void)memcpy(
        application->source.local_identity.site_domain_id.bytes,
        open + 302u,
        16u);
    application->source.local_identity.binding_epoch =
        ninlil_mfdt_v1_get_u64(open + 318u);
    application->source.local_identity.membership_epoch =
        ninlil_mfdt_v1_get_u64(open + 326u);
    application->source.local_identity.flags =
        ninlil_mfdt_v1_get_u32(open + 334u);
    application->source.local_identity.reserved_zero =
        ninlil_mfdt_v1_get_u32(open + 338u);

    application->target.abi_version = NINLIL_ABI_VERSION;
    application->target.struct_size =
        (uint16_t)sizeof(application->target);
    (void)memcpy(
        application->target.target_runtime_id.bytes,
        open + 112u,
        16u);
    (void)memcpy(
        application->target.target_application_instance_id.bytes,
        open + 342u,
        16u);
    (void)memcpy(application->target.device_id.bytes, open + 358u, 16u);
    (void)memcpy(
        application->target.installation_id.bytes, open + 374u, 16u);
    (void)memcpy(
        application->target.site_domain_id.bytes, open + 390u, 16u);
    application->target.binding_epoch =
        ninlil_mfdt_v1_get_u64(open + 406u);
    application->target.membership_epoch =
        ninlil_mfdt_v1_get_u64(open + 414u);
    application->target.flags = ninlil_mfdt_v1_get_u32(open + 422u);
    application->target.reserved_zero =
        ninlil_mfdt_v1_get_u32(open + 426u);

    application->service.abi_version = NINLIL_ABI_VERSION;
    application->service.struct_size =
        (uint16_t)sizeof(application->service);
    application->service.namespace_id.length = namespace_length;
    application->service.service_id.length = service_length;
    application->service.schema_id.length = schema_length;
    (void)memcpy(
        application->service.namespace_id.bytes,
        open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET,
        namespace_length);
    (void)memcpy(
        application->service.service_id.bytes,
        open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET + namespace_length,
        service_length);
    (void)memcpy(
        application->service.schema_id.bytes,
        open + NINLIL_MFDT_V1_OPEN_TEXT_OFFSET + namespace_length +
            service_length,
        schema_length);
    application->service.descriptor_revision =
        ninlil_mfdt_v1_get_u64(open + 128u);
    application->service.descriptor_digest.algorithm =
        NINLIL_DIGEST_SHA256;
    (void)memcpy(
        application->service.descriptor_digest.bytes,
        open + 138u,
        32u);
    application->service.schema_major =
        ninlil_mfdt_v1_get_u16(open + 430u);
    application->service.schema_minor =
        ninlil_mfdt_v1_get_u16(open + 432u);
    application->service.family =
        (ninlil_family_t)ninlil_mfdt_v1_get_u32(open + 434u);

    application->content_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memcpy(application->content_digest.bytes, open + 32u, 32u);
    (void)memcpy(
        application->deadline_clock_epoch_id.bytes,
        open + 178u,
        16u);
    application->absolute_effect_deadline_ms =
        ninlil_mfdt_v1_get_u64(open + 194u);
    application->generation = ninlil_mfdt_v1_get_u64(open + 438u);
    application->evidence_grace_ms =
        ninlil_mfdt_v1_get_u64(open + 446u);
    application->required_evidence =
        (ninlil_evidence_stage_t)ninlil_mfdt_v1_get_u32(open + 454u);
    application->payload.data = view->content;
    application->payload.length = view->content_length;

    ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
        application, target_ordinal, derived_transfer_id);
    if (!application_party_is_canonical(&application->source) ||
        !application_target_is_canonical(&application->target) ||
        !application_service_is_canonical(&application->service) ||
        !application_digest_is_canonical(&application->content_digest) ||
        !application_family_binding_is_canonical(application) ||
        !application_unused_fields_are_canonical(application) ||
        !receiver_open_target_matches_runtime(runtime, &application->target) ||
        memcmp(derived_transfer_id, view->transfer_id, 16u) != 0) {
        return 0;
    }
    *target_ordinal_out = target_ordinal;
    return 1;
}

static int foundation_has_required_positive_evidence(
    const ninlil_rt_transaction_slot_t *foundation)
{
    return foundation != NULL && foundation->evidence_recorded != 0u &&
        foundation->application_result_kind ==
            NINLIL_APP_RESULT_POSITIVE_EVIDENCE &&
        foundation->latest_evidence != NINLIL_EVIDENCE_NONE &&
        foundation->latest_evidence <= NINLIL_EVIDENCE_VERIFIED &&
        foundation->latest_evidence >= foundation->required_evidence &&
        foundation->application_evidence_length <=
            NINLIL_MAX_EVIDENCE_BYTES;
}

static int foundation_receipt_is_closed_exact(
    const ninlil_rt_transaction_slot_t *foundation)
{
    return foundation_has_required_positive_evidence(foundation) &&
        foundation->terminal == 1u &&
        foundation->event_discarded == 0u &&
        foundation->outcome_recorded == 1u &&
        foundation->reverse_receipt_closed == 1u &&
        foundation->receipt_pending == 0u &&
        foundation->token_state == NINLIL_RT_TOKEN_CONSUMED &&
        foundation->delivery_phase == NINLIL_RT_DELIVERY_OUTCOME &&
        foundation->outcome == NINLIL_OUTCOME_SATISFIED &&
        foundation->reason == NINLIL_REASON_REQUIRED_EVIDENCE_MET &&
        foundation->ingress_pending == 0u &&
        foundation->pending_dispatch == 0u;
}

static ninlil_status_t receiver_application_evidence_digest(
    const ninlil_mfdt_v1_host_receiver_ready_view_t *view,
    const ninlil_bearer_message_t *application,
    uint32_t target_ordinal,
    const ninlil_rt_transaction_slot_t *foundation,
    uint8_t digest_out[32])
{
    ninlil_bytes_view_t evidence;

    if (view == NULL || application == NULL || foundation == NULL ||
        digest_out == NULL ||
        !foundation_has_required_positive_evidence(foundation)) {
        return NINLIL_E_INVALID_STATE;
    }
    evidence.data = foundation->application_evidence_length == 0u
        ? NULL : foundation->application_evidence;
    evidence.length = foundation->application_evidence_length;
    return ninlil_rt_mfdt_v1_application_evidence_digest(
        view->publication_token,
        &application->transaction_id,
        &application->attempt_id,
        target_ordinal,
        foundation->latest_evidence,
        evidence,
        digest_out);
}

static ninlil_status_t recovered_receiver_terminal_matches_foundation(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner,
    const ninlil_rt_transaction_slot_t *foundation,
    uint32_t *matches_out)
{
    const ninlil_rt_target_slot_t *target;
    ninlil_mfdt_v1_host_sender_expectation_t expected;
    ninlil_mfdt_v1_host_terminal_view_t terminal;
    ninlil_bearer_message_t application;
    uint8_t *content_scratch;
    uint8_t *open_scratch;
    uint8_t *entries_scratch;
    uint8_t derived_transfer_id[16];
    uint8_t encoded_manifest[32];
    uint8_t encoded_whole[32];
    uint8_t open_request_digest[32];
    uint16_t open_length = 0u;
    uint16_t entry_bytes = 0u;
    int rc;

    if (owner == NULL || foundation == NULL || matches_out == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *matches_out = 0u;
    if (!foundation_receipt_is_closed_exact(foundation) ||
        foundation->origin_admission != 0u ||
        foundation->bearer_route !=
            (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1 ||
        foundation->bound_target_count != 1u ||
        foundation->bound_targets[0].in_use == 0u ||
        foundation->bound_targets[0].mfdt_target_ordinal >=
            NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        !bytes_nonzero(
            foundation->bound_targets[0].mfdt_transfer_id, 16u)) {
        return NINLIL_OK;
    }
    target = &foundation->bound_targets[0];
    (void)memset(&application, 0, sizeof(application));
    application.transaction_id = foundation->transaction_id;
    application.attempt_id = foundation->attempt_id;
    application.event_id = foundation->event_id;
    application.source = foundation->source;
    application.target = target->target;
    application.service = foundation->service;
    application.content_digest = foundation->content_digest;
    application.generation = foundation->generation;
    application.deadline_clock_epoch_id =
        foundation->deadline_clock_epoch_id;
    application.absolute_effect_deadline_ms =
        foundation->effect_deadline_ms;
    application.evidence_grace_ms = foundation->evidence_grace_ms;
    application.required_evidence = foundation->required_evidence;
    ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
        &application,
        target->mfdt_target_ordinal,
        derived_transfer_id);
    if (!application_party_is_canonical(&application.source) ||
        !application_target_is_canonical(&application.target) ||
        !application_service_is_canonical(&application.service) ||
        !application_digest_is_canonical(&application.content_digest) ||
        !application_family_binding_is_canonical(&application) ||
        memcmp(
            derived_transfer_id,
            target->mfdt_transfer_id,
            sizeof(derived_transfer_id)) != 0) {
        return fence_storage_corrupt(owner);
    }
    (void)memset(&terminal, 0, sizeof(terminal));
    rc = ninlil_mfdt_v1_host_terminal_view(
        owner->host, target->mfdt_transfer_id, &terminal);
    if (rc == NINLIL_MFDT_V1_ERR_STATE) {
        return NINLIL_OK;
    }
    if (rc == NINLIL_MFDT_V1_ERR_STORAGE ||
        rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
        rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
        return host_error_to_runtime(owner, rc);
    }
    if (rc != NINLIL_MFDT_V1_OK ||
        terminal.stored_session_generation != owner->session_generation ||
        terminal.role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
        terminal.terminal_state != NINLIL_MFDT_V1_TERM_COMPLETE ||
        terminal.terminal_reason != NINLIL_MFDT_V1_TERM_REASON_NONE ||
        terminal.replay_eligible != 1u ||
        memcmp(
            terminal.peer_endpoint_id,
            foundation->source.runtime_id.bytes,
            16u) != 0) {
        return fence_storage_corrupt(owner);
    }
    recovered_sender_expectation_from_foundation(
        foundation, 0u, &expected);
    (void)memcpy(
        expected.metadata.original_attempt_id,
        foundation->attempt_id.bytes,
        sizeof(expected.metadata.original_attempt_id));
    content_scratch = owner->iter_value_scratch;
    open_scratch = content_scratch + NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
    entries_scratch = open_scratch + NINLIL_MFDT_V1_OPEN_BODY_MAX;
    if (foundation->payload_length <=
            NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES ||
        foundation->payload_length >
            NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES ||
        MFDT_RUNTIME_ITER_VALUE_CAP <
            NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES +
                NINLIL_MFDT_V1_OPEN_BODY_MAX +
                NINLIL_MFDT_V1_MAX_CHUNKS *
                    NINLIL_MFDT_V1_ENTRY_BYTES) {
        return fence_storage_corrupt(owner);
    }
    (void)memset(content_scratch, 0, foundation->payload_length);
    rc = ninlil_mfdt_v1_encode_open(
        expected.transfer_id,
        expected.content_length,
        content_scratch,
        &expected.metadata,
        open_scratch,
        &open_length,
        entries_scratch,
        &entry_bytes,
        encoded_manifest,
        encoded_whole);
    if (rc != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_get_u32(open_scratch + 16u) !=
            terminal.transfer_revision) {
        return fence_storage_corrupt(owner);
    }
    (void)memcpy(
        open_scratch + 32u,
        expected.content_digest,
        sizeof(expected.content_digest));
    (void)memcpy(
        open_scratch + 202u,
        terminal.manifest_digest,
        sizeof(terminal.manifest_digest));
    ninlil_mfdt_v1_request_body_digest(
        NINLIL_MFDT_V1_MSG_OPEN,
        open_scratch,
        open_length,
        open_request_digest);
    if (memcmp(
            open_request_digest,
            terminal.open_request_body_digest,
            sizeof(open_request_digest)) != 0) {
        return fence_storage_corrupt(owner);
    }
    *matches_out = 1u;
    return NINLIL_OK;
}

static ninlil_status_t reconcile_recovered_senders(
    ninlil_rt_mfdt_v1_runtime_owner_t *owner)
{
    ninlil_runtime_t *runtime = owner->runtime;
    ninlil_rt_transaction_slot_t *expected_foundations[
        NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t expected_target_indices[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_rt_transaction_slot_t *slot_foundations[
        NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t slot_target_indices[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_mfdt_v1_host_sender_expectation_t expected;
    ninlil_mfdt_v1_host_recovered_sender_view_t
        views[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_mfdt_v1_host_receiver_ready_view_t
        receiver_views[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_bearer_message_t
        receiver_applications[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint32_t receiver_ordinals[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t receiver_ready[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_mfdt_v1_host_bind_t bind;
    uint8_t expected_count = 0u;
    uint8_t occupied_count = 0u;
    uint8_t slot;
    uint32_t index;
    int rc;

    (void)memset(expected_foundations, 0, sizeof(expected_foundations));
    (void)memset(
        expected_target_indices, UINT8_MAX, sizeof(expected_target_indices));
    (void)memset(slot_foundations, 0, sizeof(slot_foundations));
    (void)memset(slot_target_indices, UINT8_MAX, sizeof(slot_target_indices));
    (void)memset(views, 0, sizeof(views));
    (void)memset(receiver_views, 0, sizeof(receiver_views));
    (void)memset(receiver_applications, 0, sizeof(receiver_applications));
    (void)memset(receiver_ordinals, 0, sizeof(receiver_ordinals));
    (void)memset(receiver_ready, 0, sizeof(receiver_ready));
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[index];
        uint32_t target_index;

        if (transaction->in_use != 0u &&
            transaction->bearer_route ==
                (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1) {
            if (transaction->origin_admission == 0u) {
                continue;
            }
            if (transaction->terminal != 0u ||
                transaction->event_discarded != 0u) {
                continue;
            }
            if (!recovered_foundation_sender_shape_is_exact(transaction) ||
                transaction->bound_target_count >
                    NINLIL_MFDT_V1_HOST_SLOT_COUNT - expected_count) {
                return fence_storage_corrupt(owner);
            }
            for (target_index = 0u;
                 target_index < transaction->bound_target_count;
                 ++target_index) {
                uint8_t other;

                for (other = 0u; other < expected_count; ++other) {
                    const ninlil_rt_target_slot_t *other_target =
                        &expected_foundations[other]->bound_targets[
                            expected_target_indices[other]];

                    if (memcmp(
                            other_target->mfdt_transfer_id,
                            transaction->bound_targets[target_index]
                                .mfdt_transfer_id,
                            16u) == 0) {
                        return fence_storage_corrupt(owner);
                    }
                }
                expected_foundations[expected_count] = transaction;
                expected_target_indices[expected_count] =
                    (uint8_t)target_index;
                expected_count += 1u;
            }
        }
    }
    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK || header.recovered != 1u ||
        header.started != 1u || header.inventory_uncertain != 0u ||
        header.control_outbox_pending != 0u) {
        return fence_storage_corrupt(owner);
    }
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (slots[slot].occupied != 0u) {
            occupied_count += 1u;
            if ((slots[slot].role !=
                    NINLIL_MFDT_V1_HOST_ROLE_SENDER &&
                 slots[slot].role !=
                    NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) ||
                slots[slot].bind_valid != 0u) {
                return fence_storage_corrupt(owner);
            }
        }
    }
    if (occupied_count != header.active_count ||
        expected_count > occupied_count) {
        return fence_storage_corrupt(owner);
    }
    if (expected_count != 0u) {
        uint8_t expected_index;

        /* Validate the complete target-local set before publishing a rebind. */
        for (expected_index = 0u;
             expected_index < expected_count;
             ++expected_index) {
            ninlil_rt_transaction_slot_t *foundation =
                expected_foundations[expected_index];
            uint8_t target_index = expected_target_indices[expected_index];
            uint8_t matched_slot = UINT8_MAX;

            for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
                if (slots[slot].occupied != 0u &&
                    slots[slot].role ==
                        NINLIL_MFDT_V1_HOST_ROLE_SENDER &&
                    memcmp(
                        slots[slot].transfer_id,
                        foundation->bound_targets[target_index]
                            .mfdt_transfer_id,
                        16u) == 0) {
                    if (matched_slot != UINT8_MAX) {
                        return fence_storage_corrupt(owner);
                    }
                    matched_slot = slot;
                }
            }
            if (matched_slot == UINT8_MAX) {
                return fence_storage_corrupt(owner);
            }
            if (slot_foundations[matched_slot] != NULL) {
                return fence_storage_corrupt(owner);
            }
            recovered_sender_expectation_from_foundation(
                foundation, target_index, &expected);
            rc = ninlil_mfdt_v1_host_recovered_sender_view(
                owner->host,
                matched_slot,
                &expected,
                owner->iter_value_scratch,
                MFDT_RUNTIME_ITER_VALUE_CAP,
                &views[matched_slot]);
            if (rc != NINLIL_MFDT_V1_OK ||
                views[matched_slot].stored_session_generation !=
                    owner->session_generation ||
                memcmp(
                    views[matched_slot].peer_endpoint_id,
                    foundation->bound_targets[target_index].target
                        .target_runtime_id.bytes,
                    16u) != 0) {
                return fence_storage_corrupt(owner);
            }
            slot_foundations[matched_slot] = foundation;
            slot_target_indices[matched_slot] = target_index;
        }
    }

    /*
     * Receiver rows remain unbound after cold recovery. Their canonical OPEN
     * is the Application authority; the old carrier binding is deliberately
     * unavailable and must not be reconstructed from transport metadata.
     */
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (slots[slot].occupied == 0u ||
            slots[slot].role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) {
            continue;
        }
        rc = ninlil_mfdt_v1_host_receiver_ready_view(
            owner->host, slot, &receiver_views[slot]);
        if (rc == NINLIL_MFDT_V1_ERR_STATE) {
            continue;
        }
        if (rc != NINLIL_MFDT_V1_OK ||
            receiver_views[slot].stored_session_generation !=
                owner->session_generation ||
            !receiver_application_from_ready_open(
                runtime,
                &receiver_views[slot],
                &receiver_applications[slot],
                &receiver_ordinals[slot])) {
            return fence_storage_corrupt(owner);
        }
        receiver_ready[slot] = 1u;
        {
            ninlil_rt_transaction_slot_t *foundation =
                ninlil_rt_find_transaction(
                    runtime,
                    &receiver_applications[slot].transaction_id);

            if (foundation != NULL &&
                !ninlil_rt_v1_bearer_mfdt_ingress_matches(
                    runtime,
                    &receiver_applications[slot],
                    receiver_views[slot].transfer_id,
                    receiver_ordinals[slot])) {
                return fence_storage_corrupt(owner);
            }
            if (receiver_views[slot].handoff_state != 0u) {
                uint8_t expected_digest[32];

                if (foundation == NULL ||
                    receiver_application_evidence_digest(
                        &receiver_views[slot],
                        &receiver_applications[slot],
                        receiver_ordinals[slot],
                        foundation,
                        expected_digest) != NINLIL_OK ||
                    memcmp(
                        receiver_views[slot].publication_evidence_digest,
                        expected_digest,
                        sizeof(expected_digest)) != 0) {
                    return fence_storage_corrupt(owner);
                }
            } else if (foundation_receipt_is_closed_exact(foundation)) {
                return fence_storage_corrupt(owner);
            }
        }
    }

    /* Every inbound Foundation row needs one exact active or retained row. */
    for (index = 0u; index < runtime->transaction_capacity; ++index) {
        ninlil_rt_transaction_slot_t *transaction =
            &runtime->transactions[index];
        uint8_t matches = 0u;

        if (transaction->in_use == 0u ||
            transaction->origin_admission != 0u ||
            transaction->bearer_route !=
                (uint8_t)NINLIL_RT_V1_BEARER_ROUTE_MFDT_V1) {
            continue;
        }
        for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
            if (receiver_ready[slot] != 0u &&
                memcmp(
                    receiver_applications[slot].transaction_id.bytes,
                    transaction->transaction_id.bytes,
                    16u) == 0 &&
                ninlil_rt_v1_bearer_mfdt_ingress_matches(
                    runtime,
                    &receiver_applications[slot],
                    receiver_views[slot].transfer_id,
                    receiver_ordinals[slot])) {
                matches = (uint8_t)(matches + 1u);
            }
        }
        if (matches == 0u &&
            foundation_receipt_is_closed_exact(transaction)) {
            uint32_t terminal_matches = 0u;
            ninlil_status_t status =
                recovered_receiver_terminal_matches_foundation(
                    owner, transaction, &terminal_matches);

            if (status != NINLIL_OK) {
                return status;
            }
            matches = (uint8_t)terminal_matches;
        }
        if (matches != 1u) {
            return fence_storage_corrupt(owner);
        }
    }

    /* Classify every unmatched active row before the first cleanup FULL. */
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        uint32_t transaction_index;

        if (slots[slot].occupied == 0u ||
            slots[slot].role == NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
            slot_foundations[slot] != NULL) {
            continue;
        }
        rc = ninlil_mfdt_v1_host_recovered_sender_view(
            owner->host,
            slot,
            NULL,
            owner->iter_value_scratch,
            MFDT_RUNTIME_ITER_VALUE_CAP,
            &views[slot]);
        if (rc != NINLIL_MFDT_V1_OK ||
            views[slot].fresh_open_arm == 0u) {
            return fence_storage_corrupt(owner);
        }
        /*
         * An arm is an orphan only when its OPEN origin is wholly absent
         * from Foundation. A terminal or non-MFDT row with that identity is
         * incompatible truth, never cleanup authority.
         */
        for (transaction_index = 0u;
             transaction_index < runtime->transaction_capacity;
             ++transaction_index) {
            const ninlil_rt_transaction_slot_t *transaction =
                &runtime->transactions[transaction_index];

            if (transaction->in_use != 0u &&
                memcmp(
                    transaction->transaction_id.bytes,
                    views[slot].origin_transaction_id,
                    16u) == 0) {
                return fence_storage_corrupt(owner);
            }
        }
    }

    /* Rebind every exact Foundation match before cleaning any orphan. */
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        ninlil_rt_transaction_slot_t *foundation =
            slot_foundations[slot];

        if (foundation != NULL) {
            (void)memset(&bind, 0, sizeof(bind));
            (void)memcpy(
                bind.peer_endpoint_id,
                views[slot].peer_endpoint_id,
                16u);
            bind.session_generation = owner->session_generation;
            bind.session_cookie = owner->session_cookie;
            bind.role = NINLIL_MFDT_V1_HOST_ROLE_SENDER;
            rc = ninlil_mfdt_v1_host_rebind_recovered(
                owner->host, views[slot].transfer_id, &bind);
            if (rc != NINLIL_MFDT_V1_OK) {
                return fence_storage_corrupt(owner);
            }
            recovered_runtime_binding_from_foundation(
                foundation,
                slot_target_indices[slot],
                &owner->bindings[slot]);
        }
    }

    /* Every remaining slot is a fully prevalidated fresh orphan. */
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (slots[slot].occupied == 0u ||
            slots[slot].role == NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
            slot_foundations[slot] != NULL) {
            continue;
        }
        rc = ninlil_mfdt_v1_host_disarm_recovered_fresh_sender(
            owner->host,
            slot,
            views[slot].transfer_id,
            owner->iter_value_scratch,
            MFDT_RUNTIME_ITER_VALUE_CAP);
        if (rc == NINLIL_MFDT_V1_OK) {
            continue;
        }
        runtime->commit_unknown_fence = 1u;
        if (rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
            rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
            return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
        }
        if (rc == NINLIL_MFDT_V1_ERR_STORAGE) {
            return NINLIL_E_STORAGE;
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    return NINLIL_OK;
}

static ninlil_status_t owner_create(
    ninlil_runtime_t *runtime,
    const ninlil_rt_mfdt_v1_runtime_config_t *config,
    ninlil_rt_mfdt_v1_runtime_owner_t **out_owner)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)config;
    (void)out_owner;
    /*
     * MFDT ESP owner is a separate completion item. Never allocate the
     * four-slot Host owner into ESP DRAM and never use the global spine.
     */
    return NINLIL_E_UNSUPPORTED;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_config_t base_config;
    ninlil_status_t status;
    int rc;

    *out_owner = NULL;
    owner = (ninlil_rt_mfdt_v1_runtime_owner_t *)owner_allocate(
        runtime,
        sizeof(*owner),
        (uint32_t)_Alignof(ninlil_rt_mfdt_v1_runtime_owner_t));
    if (owner == NULL) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    (void)memset(owner, 0, sizeof(*owner));
    owner->runtime = runtime;
    owner->underlying_ops = runtime->platform->storage;
    owner->session_generation = config->session_generation;
    owner->session_cookie = config->session_cookie;
    owner->magic = MFDT_RUNTIME_OWNER_MAGIC;
    owner->iter_value_scratch = (uint8_t *)owner_allocate(
        runtime, MFDT_RUNTIME_ITER_VALUE_CAP, 8u);
    owner->host = (ninlil_mfdt_v1_host_owner_t *)owner_allocate(
        runtime,
        sizeof(*owner->host),
        (uint32_t)_Alignof(ninlil_mfdt_v1_host_owner_t));
    if (owner->iter_value_scratch == NULL || owner->host == NULL) {
        owner_free(owner);
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    (void)memset(
        owner->iter_value_scratch, 0, MFDT_RUNTIME_ITER_VALUE_CAP);
    (void)memset(owner->host, 0, sizeof(*owner->host));
    if (!derive_sidecar_namespace(owner) || !build_binding_value(owner)) {
        owner_free(owner);
        return NINLIL_E_INVALID_STATE;
    }
    status = sidecar_open(owner);
    if (status == NINLIL_OK) {
        status = sidecar_bootstrap(owner);
    }
    if (status != NINLIL_OK) {
        owner_free(owner);
        return status;
    }
    if (!storage_has_host_capacity(owner)) {
        owner_free(owner);
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    filtered_ops_init(owner);
    guarantees_init(&owner->guarantees);
    rc = ninlil_mfdt_v1_store_port_init(
        &owner->store,
        &owner->filtered_ops,
        (ninlil_storage_handle_t)owner,
        &owner->guarantees);
    if (rc != NINLIL_MFDT_V1_OK) {
        owner_free(owner);
        return NINLIL_E_STORAGE;
    }
    (void)memset(&base_config, 0, sizeof(base_config));
    base_config.policy = NINLIL_MFDT_V1_POLICY_ON;
    base_config.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    base_config.host_mode = 1u;
    base_config.session_generation = config->session_generation;
    base_config.mfdt_capability = 1u;
    base_config.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    base_config.now_ms = runtime->started_sample.now_ms;
    (void)memcpy(
        base_config.local_clock_epoch.bytes,
        runtime->started_sample.clock_epoch_id.bytes,
        sizeof(base_config.local_clock_epoch.bytes));
    rc = ninlil_mfdt_v1_host_owner_init(
        owner->host, &owner->store, &base_config);
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_host_owner_recover(owner->host);
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_host_owner_start(owner->host);
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        if (rc != NINLIL_MFDT_V1_ERR_CAPACITY) {
            runtime->commit_unknown_fence = 1u;
        }
        owner_free(owner);
        return rc == NINLIL_MFDT_V1_ERR_CAPACITY
            ? NINLIL_E_CAPACITY_EXHAUSTED
            : NINLIL_E_STORAGE_CORRUPT;
    }
    status = reconcile_recovered_senders(owner);
    if (status != NINLIL_OK) {
        owner_free(owner);
        return status;
    }
    owner->ready = 1u;
    owner->enabled = 1u;
    *out_owner = owner;
    return NINLIL_OK;
#endif
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_configure(
    ninlil_runtime_t *runtime,
    const ninlil_rt_mfdt_v1_runtime_config_t *config)
{
    ninlil_status_t status;

    if (runtime == NULL || config == NULL
        || config->struct_size != sizeof(*config)
        || config->enabled > 1u || config->reserved_zero != 0u
        || (config->enabled != 0u
            && (config->session_generation == 0u
                || config->session_cookie == 0u))) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_mutation_allowed(runtime);
    if (status != NINLIL_OK) {
        return status;
    }
    if (config->enabled == 0u) {
        ninlil_rt_mfdt_v1_runtime_snapshot_t snapshot;

        if (runtime->mfdt_v1_owner == NULL) {
            return NINLIL_OK;
        }
        (void)memset(&snapshot, 0, sizeof(snapshot));
        snapshot.struct_size = (uint32_t)sizeof(snapshot);
        status = ninlil_rt_mfdt_v1_runtime_snapshot(runtime, &snapshot);
        if (status != NINLIL_OK) {
            return status;
        }
        if (snapshot.active_count != 0u) {
            return NINLIL_E_INVALID_STATE;
        }
        owner_free(runtime->mfdt_v1_owner);
        runtime->mfdt_v1_owner = NULL;
        return NINLIL_OK;
    }
    if (runtime->mfdt_v1_owner != NULL) {
        if (!owner_is_valid(runtime->mfdt_v1_owner)) {
            return NINLIL_E_INVALID_STATE;
        }
        return runtime->mfdt_v1_owner->session_generation
                    == config->session_generation
                && runtime->mfdt_v1_owner->session_cookie
                    == config->session_cookie
            ? NINLIL_OK
            : NINLIL_E_INVALID_STATE;
    }
    return owner_create(runtime, config, &runtime->mfdt_v1_owner);
}

int ninlil_rt_mfdt_v1_runtime_should_use(
    const ninlil_runtime_t *runtime,
    uint32_t logical_payload_length)
{
    return runtime != NULL
        && owner_is_valid(runtime->mfdt_v1_owner)
        && runtime->mfdt_v1_owner->enabled != 0u
        && runtime->mfdt_v1_owner->ready != 0u
        && logical_payload_length
            > NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES
        && logical_payload_length <= NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES;
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_bind_session(
    ninlil_runtime_t *runtime,
    const ninlil_mfdt_v1_session_t *session)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)session;
    return NINLIL_E_UNSUPPORTED;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_status_t status;

    if (runtime == NULL || session == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    status = ninlil_rt_validate_live_runtime(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_owner_thread(runtime, 0u);
    if (status != NINLIL_OK) {
        return status;
    }
    status = ninlil_rt_validate_mutation_allowed(runtime);
    if (status != NINLIL_OK) {
        return status;
    }
    owner = runtime->mfdt_v1_owner;
    if (!owner_is_valid(owner)
        || !ninlil_mfdt_v1_session_carrier_ncl1_data_ok(session)
        || session->host_mode == 0u
        || session->session_generation != owner->session_generation
        || session->session_cookie != owner->session_cookie
        || memcmp(
               session->local_endpoint_id,
               runtime->config.runtime_id.bytes,
               16u) != 0
        || !bytes_nonzero(session->peer_endpoint_id, 16u)
        || memcmp(
               session->peer_endpoint_id,
               runtime->config.runtime_id.bytes,
               16u) == 0) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->session_bound != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    {
        uint8_t slot;

        for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
            if (owner->bindings[slot].occupied != 0u &&
                memcmp(
                    owner->bindings[slot].application.target
                        .target_runtime_id.bytes,
                    session->peer_endpoint_id,
                    16u) != 0) {
                return NINLIL_E_INVALID_ARGUMENT;
            }
        }
    }
    owner->session = *session;
    owner->session_bound = 1u;
    return NINLIL_OK;
#endif
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_snapshot(
    const ninlil_runtime_t *runtime,
    ninlil_rt_mfdt_v1_runtime_snapshot_t *out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    if (out != NULL && out->struct_size == sizeof(*out)) {
        (void)memset(out, 0, sizeof(*out));
        out->struct_size = (uint32_t)sizeof(*out);
        out->exact_slot_count = 1u;
    }
    return NINLIL_E_UNSUPPORTED;
#else
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint32_t struct_size;
    int rc;

    if (runtime == NULL || out == NULL
        || out->struct_size != sizeof(*out)
        || !owner_is_valid(runtime->mfdt_v1_owner)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    struct_size = out->struct_size;
    (void)memset(out, 0, sizeof(*out));
    out->struct_size = struct_size;
    (void)memset(&header, 0, sizeof(header));
    (void)memset(slots, 0, sizeof(slots));
    rc = ninlil_mfdt_v1_host_snapshot(
        runtime->mfdt_v1_owner->host, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_E_INVALID_STATE;
    }
    out->enabled = runtime->mfdt_v1_owner->enabled;
    out->ready = runtime->mfdt_v1_owner->ready;
    out->exact_slot_count = (uint32_t)NINLIL_MFDT_V1_HOST_SLOT_COUNT;
    out->active_count = header.active_count;
    out->recovered = header.recovered;
    out->inventory_uncertain = header.inventory_uncertain;
    return NINLIL_OK;
#endif
}

static int application_envelope_is_valid(
    const ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *application,
    const uint8_t *content,
    uint32_t content_length)
{
    uint8_t digest[32];

    if (runtime == NULL || application == NULL || content == NULL
        || content_length <= NINLIL_RT_V1_MAX_OWNED_PAYLOAD_BYTES
        || content_length > NINLIL_RT_V1_MAX_MFDT_PAYLOAD_BYTES
        || !application_header_is_canonical(
            application->abi_version,
            application->struct_size,
            sizeof(*application))
        || application->kind != NINLIL_BEARER_MESSAGE_APPLICATION
        || !bytes_nonzero(application->transaction_id.bytes, 16u)
        || !bytes_nonzero(application->attempt_id.bytes, 16u)
        || !application_party_is_canonical(&application->source)
        || !application_target_is_canonical(&application->target)
        || !application_service_is_canonical(&application->service)
        || !application_digest_is_canonical(&application->content_digest)
        || !application_family_binding_is_canonical(application)
        || !application_unused_fields_are_canonical(application)
        || (application->required_evidence != NINLIL_EVIDENCE_RECEIVED
            && application->required_evidence
                != NINLIL_EVIDENCE_DURABLY_RECORDED
            && application->required_evidence != NINLIL_EVIDENCE_APPLIED
            && application->required_evidence != NINLIL_EVIDENCE_VERIFIED)
        || memcmp(
               application->source.runtime_id.bytes,
               runtime->config.runtime_id.bytes,
               16u) != 0
        || memcmp(
               application->source.runtime_id.bytes,
               application->target.target_runtime_id.bytes,
               16u) == 0
        || application->payload.data != content
        || application->payload.length != content_length) {
        return 0;
    }
    ninlil_mfdt_v1_sha256(content, content_length, digest);
    return memcmp(
        digest,
        application->content_digest.bytes,
        sizeof(digest)) == 0;
}

void ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
    const ninlil_bearer_message_t *application,
    uint32_t target_ordinal,
    uint8_t transfer_id_out[16])
{
    uint8_t material[52];
    uint8_t digest[32];

    (void)memcpy(material, application->transaction_id.bytes, 16u);
    (void)memcpy(
        &material[16],
        application->target.target_runtime_id.bytes,
        16u);
    material[32] = (uint8_t)(target_ordinal >> 24);
    material[33] = (uint8_t)(target_ordinal >> 16);
    material[34] = (uint8_t)(target_ordinal >> 8);
    material[35] = (uint8_t)target_ordinal;
    (void)memcpy(material + 36u, "ninlil-mfdt-v1id", 16u);
    ninlil_mfdt_v1_sha256(material, sizeof(material), digest);
    (void)memcpy(transfer_id_out, digest, 16u);
    if (!bytes_nonzero(transfer_id_out, 16u)) {
        transfer_id_out[15] = 1u;
    }
}

int ninlil_rt_mfdt_v1_runtime_sender_open(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *application,
    const uint8_t *content,
    uint32_t content_length,
    uint32_t target_ordinal,
    const uint8_t transfer_id[16],
    uint8_t *slot_out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)application;
    (void)content;
    (void)content_length;
    (void)target_ordinal;
    (void)transfer_id;
    (void)slot_out;
    return NINLIL_MFDT_V1_ERR_STATE;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_open_metadata_t metadata;
    uint8_t derived_transfer_id[16];
    uint64_t request_id;
    int rc;

    if (runtime == NULL || transfer_id == NULL || slot_out == NULL
        || !owner_is_valid(runtime->mfdt_v1_owner)
        || runtime->mfdt_v1_owner->enabled == 0u
        || !bytes_nonzero(transfer_id, 16u)
        || !application_envelope_is_valid(
            runtime, application, content, content_length)) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    owner = runtime->mfdt_v1_owner;
    ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
        application, target_ordinal, derived_transfer_id);
    if (owner->ready == 0u || owner->session_generation == 0u ||
        owner->session_cookie == 0u || owner->dispatch_fenced != 0u ||
        target_ordinal >= NINLIL_MFDT_V1_HOST_SLOT_COUNT ||
        memcmp(derived_transfer_id, transfer_id, 16u) != 0) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    /* Durable pre-arm owns no wire path and is independent of live session. */
    (void)memset(&bind, 0, sizeof(bind));
    (void)memcpy(
        bind.peer_endpoint_id,
        application->target.target_runtime_id.bytes,
        sizeof(bind.peer_endpoint_id));
    bind.session_generation = owner->session_generation;
    bind.session_cookie = owner->session_cookie;
    bind.role = NINLIL_MFDT_V1_HOST_ROLE_SENDER;
    (void)memset(&metadata, 0, sizeof(metadata));
    (void)memcpy(
        metadata.origin_transaction_id,
        application->transaction_id.bytes,
        16u);
    (void)memcpy(
        metadata.origin_event_id, application->event_id.bytes, 16u);
    (void)memcpy(
        metadata.source_runtime_id,
        application->source.runtime_id.bytes,
        16u);
    (void)memcpy(
        metadata.target_runtime_id,
        application->target.target_runtime_id.bytes,
        16u);
    (void)memcpy(
        metadata.original_attempt_id,
        application->attempt_id.bytes,
        16u);
    metadata.target_ordinal = target_ordinal;
    (void)memcpy(
        metadata.source_application_instance_id,
        application->source.application_instance_id.bytes,
        16u);
    (void)memcpy(
        metadata.source_device_id,
        application->source.local_identity.device_id.bytes,
        16u);
    (void)memcpy(
        metadata.source_installation_id,
        application->source.local_identity.installation_id.bytes,
        16u);
    (void)memcpy(
        metadata.source_site_id,
        application->source.local_identity.site_domain_id.bytes,
        16u);
    metadata.source_binding_epoch =
        application->source.local_identity.binding_epoch;
    metadata.source_membership_epoch =
        application->source.local_identity.membership_epoch;
    metadata.source_identity_flags =
        application->source.local_identity.flags;
    metadata.source_reserved =
        application->source.local_identity.reserved_zero;
    (void)memcpy(
        metadata.target_application_instance_id,
        application->target.target_application_instance_id.bytes,
        16u);
    (void)memcpy(
        metadata.target_device_id,
        application->target.device_id.bytes,
        16u);
    (void)memcpy(
        metadata.target_installation_id,
        application->target.installation_id.bytes,
        16u);
    (void)memcpy(
        metadata.target_site_id,
        application->target.site_domain_id.bytes,
        16u);
    metadata.target_binding_epoch = application->target.binding_epoch;
    metadata.target_membership_epoch = application->target.membership_epoch;
    metadata.target_identity_flags = application->target.flags;
    metadata.target_reserved = application->target.reserved_zero;
    metadata.service_descriptor_revision =
        application->service.descriptor_revision;
    (void)memcpy(
        metadata.service_descriptor_digest,
        application->service.descriptor_digest.bytes,
        32u);
    metadata.namespace_bytes =
        application->service.namespace_id.bytes;
    metadata.namespace_length =
        application->service.namespace_id.length;
    metadata.service_bytes = application->service.service_id.bytes;
    metadata.service_length = application->service.service_id.length;
    metadata.schema_bytes = application->service.schema_id.bytes;
    metadata.schema_length = application->service.schema_id.length;
    metadata.service_schema_major = application->service.schema_major;
    metadata.service_schema_minor = application->service.schema_minor;
    metadata.service_family = application->service.family;
    metadata.application_generation = application->generation;
    metadata.evidence_grace_ms = application->evidence_grace_ms;
    metadata.required_evidence = application->required_evidence;
    (void)memcpy(
        metadata.deadline_clock_epoch_id,
        application->deadline_clock_epoch_id.bytes,
        16u);
    metadata.absolute_effect_deadline_ms =
        application->absolute_effect_deadline_ms;
    request_id =
        ((uint64_t)transfer_id[12] << 24)
        | ((uint64_t)transfer_id[13] << 16)
        | ((uint64_t)transfer_id[14] << 8)
        | (uint64_t)transfer_id[15];
    if (request_id == 0u) {
        request_id = 1u;
    }
    rc = ninlil_mfdt_v1_host_sender_open_with_metadata(
        owner->host,
        &bind,
        transfer_id,
        content,
        content_length,
        &metadata,
        request_id,
        slot_out);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (*slot_out >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_CORRUPT;
    }
    owner->bindings[*slot_out].application = *application;
    owner->bindings[*slot_out].application.payload.data = NULL;
    owner->bindings[*slot_out].application.payload.length = 0u;
    owner->bindings[*slot_out].application.evidence.data = NULL;
    owner->bindings[*slot_out].application.evidence.length = 0u;
    (void)memcpy(
        owner->bindings[*slot_out].transfer_id, transfer_id, 16u);
    owner->bindings[*slot_out].occupied = 1u;
    owner->bindings[*slot_out].target_ordinal =
        target_ordinal > UINT8_MAX ? UINT8_MAX : (uint8_t)target_ordinal;
    return NINLIL_MFDT_V1_OK;
#endif
}

int ninlil_rt_mfdt_v1_runtime_sender_disarm(
    ninlil_runtime_t *runtime,
    uint8_t slot,
    const uint8_t transfer_id[16])
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)slot;
    (void)transfer_id;
    return NINLIL_MFDT_V1_ERR_STATE;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    int rc;

    if (runtime == NULL || transfer_id == NULL ||
        !owner_is_valid(runtime->mfdt_v1_owner) ||
        slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    owner = runtime->mfdt_v1_owner;
    if (owner->bindings[slot].occupied == 0u ||
        memcmp(owner->bindings[slot].transfer_id, transfer_id, 16u) != 0) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_host_disarm_fresh_sender(
        owner->host,
        slot,
        transfer_id,
        owner->iter_value_scratch,
        MFDT_RUNTIME_ITER_VALUE_CAP);
    if (rc == NINLIL_MFDT_V1_OK) {
        (void)memset(
            &owner->bindings[slot], 0, sizeof(owner->bindings[slot]));
    }
    return rc;
#endif
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_ingress(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *message,
    const ninlil_time_sample_t *now,
    uint32_t *claimed_out,
    uint32_t *durable_transition_out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)message;
    (void)now;
    if (claimed_out != NULL) {
        *claimed_out = 0u;
    }
    if (durable_transition_out != NULL) {
        *durable_transition_out = 0u;
    }
    return NINLIL_OK;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_mfdt_v1_foundation_carrier_config_t carrier_config;
    ninlil_mfdt_v1_foundation_carrier_t carrier;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_wire_view_t wire;
    ninlil_mfdt_v1_response_t response;
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    const uint8_t *body = NULL;
    uint8_t message_type = 0u;
    uint8_t slot = UINT8_MAX;
    uint8_t existing_slot = UINT8_MAX;
    uint8_t recovered_receiver_route = 0u;
    uint16_t body_length = 0u;
    uint32_t request_id = 0u;
    uint32_t generation = 0u;
    uint64_t cookie = 0u;
    size_t frame_length = 0u;
    int rc;

    if (runtime == NULL || message == NULL || now == NULL
        || claimed_out == NULL || durable_transition_out == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *claimed_out = 0u;
    *durable_transition_out = 0u;
    if (!message_targets_mfdt_service(message)) {
        return NINLIL_OK;
    }
    *claimed_out = 1u;

    /* Reserved traffic is consumed but ignored until this instance opts in. */
    if (runtime->mfdt_v1_owner == NULL) {
        return NINLIL_OK;
    }
    owner = runtime->mfdt_v1_owner;
    if (!owner_is_valid(owner)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner->enabled == 0u || owner->ready == 0u
        || owner->session_bound == 0u || owner->dispatch_fenced != 0u
        || !ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&owner->session)
        || owner->session.session_generation != owner->session_generation
        || owner->session.session_cookie != owner->session_cookie) {
        return NINLIL_OK;
    }
    if (now->abi_version != NINLIL_ABI_VERSION
        || now->struct_size != (uint16_t)sizeof(*now)
        || now->trust != NINLIL_CLOCK_TRUSTED
        || !bytes_nonzero(now->clock_epoch_id.bytes, 16u)
        || message->kind != NINLIL_BEARER_MESSAGE_APPLICATION
        || memcmp(
               owner->session.local_endpoint_id,
               runtime->config.runtime_id.bytes,
               16u) != 0
        || memcmp(
               owner->session.peer_endpoint_id,
               message->source.runtime_id.bytes,
               16u) != 0
        || memcmp(
               runtime->config.runtime_id.bytes,
               message->target.target_runtime_id.bytes,
               16u) != 0
        || !bytes_nonzero(
               message->source.application_instance_id.bytes, 16u)
        || !bytes_nonzero(
               message->target.target_application_instance_id.bytes, 16u)) {
        return NINLIL_OK;
    }

    /* Decode only for instance-local route selection; acceptance below owns
     * all authenticity/canonical-envelope validation before Host mutation. */
    if (message->payload.data == NULL || message->payload.length == 0u
        || message->payload.length > NINLIL_MFDT_V1_NCL1_MAX_MSG) {
        return NINLIL_OK;
    }
    rc = ninlil_mfdt_v1_ncl1_decode(
        message->payload.data,
        message->payload.length,
        NINLIL_MFDT_V1_NCG1_DATA,
        &message_type,
        &request_id,
        &generation,
        &cookie,
        &body,
        &body_length);
    if (rc != NINLIL_MFDT_V1_OK
        || !ninlil_mfdt_v1_ncl1_is_transfer_type(message_type)
        || request_id == 0u
        || generation != owner->session.session_generation
        || cookie != owner->session.session_cookie
        || body == NULL || body_length < 16u) {
        return NINLIL_OK;
    }

    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_E_INVALID_STATE;
    }
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (slots[slot].occupied != 0u
            && memcmp(slots[slot].transfer_id, body, 16u) == 0) {
            if (existing_slot != UINT8_MAX) {
                owner->dispatch_fenced = 1u;
                return NINLIL_E_INVALID_STATE;
            }
            existing_slot = slot;
        }
    }

    (void)memset(&carrier_config, 0, sizeof(carrier_config));
    carrier_config.bearer = runtime->platform->bearer;
    carrier_config.clock = runtime->platform->clock;
    carrier_config.tx_gate = runtime->platform->tx_gate;
    carrier_config.role = runtime->config.role;
    carrier_config.session = &owner->session;
    carrier_config.deadline_window_ms =
        NINLIL_MFDT_V1_CARRIER_DEADLINE_MS_DEFAULT;
    (void)memset(&bind, 0, sizeof(bind));
    (void)memcpy(
        bind.peer_endpoint_id,
        owner->session.peer_endpoint_id,
        sizeof(bind.peer_endpoint_id));
    bind.session_generation = owner->session.session_generation;
    bind.session_cookie = owner->session.session_cookie;
    if (existing_slot != UINT8_MAX) {
        if ((slots[existing_slot].role
                 == NINLIL_MFDT_V1_HOST_ROLE_SENDER
             && !wire_is_response(message_type))
            || (slots[existing_slot].role
                    == NINLIL_MFDT_V1_HOST_ROLE_RECEIVER
                && !wire_is_request(message_type))) {
            return NINLIL_OK;
        }
        bind.role = slots[existing_slot].role;
        if (binding_matches_slot(
                &owner->bindings[existing_slot],
                &slots[existing_slot],
                &owner->session)) {
            carrier_config.source =
                owner->bindings[existing_slot].application.source;
            carrier_config.target =
                owner->bindings[existing_slot].application.target;
        } else if (slots[existing_slot].role ==
                       NINLIL_MFDT_V1_HOST_ROLE_RECEIVER
            && slots[existing_slot].bind_valid == 0u
            && owner->bindings[existing_slot].occupied == 0u) {
            /*
             * Cold recovery intentionally does not restore volatile carrier
             * state. Re-admit the next authenticated carrier envelope only
             * for transport routing; the Application authority remains the
             * canonical OPEN stored in NM3R.
             */
            runtime_local_party(
                runtime,
                &message->target.target_application_instance_id,
                &carrier_config.source);
            peer_target_from_source(
                &message->source, &carrier_config.target);
            recovered_receiver_route = 1u;
        } else {
            return NINLIL_OK;
        }
    } else {
        if (message_type != NINLIL_MFDT_V1_MSG_OPEN
            || !wire_is_request(message_type)
            || owner->control_binding.occupied != 0u) {
            return NINLIL_OK;
        }
        runtime_local_party(
            runtime,
            &message->target.target_application_instance_id,
            &carrier_config.source);
        peer_target_from_source(&message->source, &carrier_config.target);
        bind.role = NINLIL_MFDT_V1_HOST_ROLE_RECEIVER;
    }
    rc = ninlil_mfdt_v1_foundation_carrier_init(
        &carrier, &carrier_config);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_OK;
    }
    rc = ninlil_mfdt_v1_foundation_carrier_accept_message(
        &carrier,
        message,
        frame,
        sizeof(frame),
        &frame_length);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_OK;
    }
    rc = ninlil_mfdt_v1_ncl1_decode(
        frame,
        frame_length,
        NINLIL_MFDT_V1_NCG1_DATA,
        &message_type,
        &request_id,
        &generation,
        &cookie,
        &body,
        &body_length);
    if (rc != NINLIL_MFDT_V1_OK || body == NULL || body_length < 16u) {
        return NINLIL_OK;
    }
    if (recovered_receiver_route != 0u) {
        rc = ninlil_mfdt_v1_host_rebind_recovered(
            owner->host, body, &bind);
        if (rc != NINLIL_MFDT_V1_OK) {
            owner->dispatch_fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
        if (owner->bindings[existing_slot].occupied != 0u) {
            owner->dispatch_fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
        /*
         * Publish the volatile carrier route in the same in-memory cut as
         * bind_valid. A later definite Host failure can then retry, while a
         * COMMIT_UNKNOWN still fences before any later callback or wire.
         */
        binding_from_carrier(
            &owner->bindings[existing_slot], &carrier, body);
    }

    (void)memset(&wire, 0, sizeof(wire));
    wire.message_type = message_type;
    wire.request_id = request_id;
    wire.body = body;
    wire.body_len = body_length;
    (void)memset(&response, 0, sizeof(response));
    rc = ninlil_mfdt_v1_host_on_wire(
        owner->host, &bind, &wire, &response, &slot);
    if (rc == NINLIL_MFDT_V1_ERR_STORAGE) {
        return NINLIL_E_STORAGE;
    }
    if (rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN) {
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_OK;
    }

    /* Host now durably owns the admitted transition and any exact response. */
    *durable_transition_out = 1u;
    if (slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE) {
        binding_from_carrier(&owner->control_binding, &carrier, body);
        runtime->pending_work = 1u;
        return NINLIL_OK;
    }
    if (slot >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        owner->dispatch_fenced = 1u;
        return NINLIL_E_INVALID_STATE;
    }
    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK) {
        owner->dispatch_fenced = 1u;
        return NINLIL_E_INVALID_STATE;
    }
    if (slots[slot].occupied == 0u) {
        (void)memset(&owner->bindings[slot], 0, sizeof(owner->bindings[slot]));
    } else if (existing_slot == UINT8_MAX) {
        if (owner->bindings[slot].occupied != 0u) {
            owner->dispatch_fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
        binding_from_carrier(&owner->bindings[slot], &carrier, body);
    } else if (recovered_receiver_route != 0u) {
        if (slot != existing_slot || !binding_matches_slot(
                &owner->bindings[slot], &slots[slot], &owner->session)) {
            owner->dispatch_fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
    } else if (!binding_matches_slot(
                   &owner->bindings[slot], &slots[slot], &owner->session)) {
        owner->dispatch_fenced = 1u;
        return NINLIL_E_INVALID_STATE;
    }
    runtime->pending_work = 1u;
    return NINLIL_OK;
#endif
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_receiver_publication_view(
    ninlil_runtime_t *runtime,
    const uint8_t transfer_id[16],
    const uint8_t **content_out,
    uint32_t *content_length_out,
    uint8_t publication_token_out[16],
    uint64_t *acceptance_generation_out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)transfer_id;
    (void)content_out;
    (void)content_length_out;
    (void)publication_token_out;
    (void)acceptance_generation_out;
    return NINLIL_E_UNSUPPORTED;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t slot;
    int rc;

    if (runtime == NULL || transfer_id == NULL || content_out == NULL
        || content_length_out == NULL || publication_token_out == NULL
        || acceptance_generation_out == NULL
        || !owner_is_valid(runtime->mfdt_v1_owner)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *content_out = NULL;
    *content_length_out = 0u;
    *acceptance_generation_out = 0u;
    (void)memset(publication_token_out, 0, 16u);
    owner = runtime->mfdt_v1_owner;
    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_E_INVALID_STATE;
    }
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (slots[slot].occupied != 0u
            && slots[slot].role == NINLIL_MFDT_V1_HOST_ROLE_RECEIVER
            && memcmp(slots[slot].transfer_id, transfer_id, 16u) == 0
            && binding_matches_slot(
                &owner->bindings[slot], &slots[slot], &owner->session)) {
            rc = ninlil_mfdt_v1_host_receiver_publication_view(
                owner->host,
                slot,
                content_out,
                content_length_out,
                publication_token_out,
                acceptance_generation_out);
            return rc == NINLIL_MFDT_V1_OK
                ? NINLIL_OK : rc == NINLIL_MFDT_V1_ERR_STATE
                    ? NINLIL_E_WOULD_BLOCK : NINLIL_E_INVALID_STATE;
        }
    }
    return NINLIL_E_NOT_FOUND;
#endif
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_reconcile_ready(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *now,
    uint32_t transition_budget,
    uint32_t *transitions_consumed_out,
    uint32_t *work_remaining_out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)now;
    (void)transition_budget;
    if (transitions_consumed_out != NULL) {
        *transitions_consumed_out = 0u;
    }
    if (work_remaining_out != NULL) {
        *work_remaining_out = 0u;
    }
    return NINLIL_OK;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t slot;
    int rc;

    if (runtime == NULL || now == NULL ||
        transitions_consumed_out == NULL || work_remaining_out == NULL ||
        !trusted_time_sample_is_valid(now)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *transitions_consumed_out = 0u;
    *work_remaining_out = 0u;
    if (runtime->mfdt_v1_owner == NULL) {
        return NINLIL_OK;
    }
    owner = runtime->mfdt_v1_owner;
    if (!owner_is_valid(owner) || owner->dispatch_fenced != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK || header.started != 1u ||
        header.recovered != 1u || header.inventory_uncertain != 0u) {
        return fence_storage_corrupt(owner);
    }
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        ninlil_mfdt_v1_host_receiver_ready_view_t view;
        ninlil_bearer_message_t application;
        ninlil_rt_transaction_slot_t *foundation;
        uint8_t evidence_digest[32];
        uint32_t target_ordinal = 0u;
        uint32_t committed = 0u;
        ninlil_status_t status;

        if (slots[slot].occupied == 0u ||
            slots[slot].role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER) {
            continue;
        }
        (void)memset(&view, 0, sizeof(view));
        rc = ninlil_mfdt_v1_host_receiver_ready_view(
            owner->host, slot, &view);
        if (rc == NINLIL_MFDT_V1_ERR_STATE) {
            continue;
        }
        if (rc != NINLIL_MFDT_V1_OK ||
            view.stored_session_generation != owner->session_generation ||
            !receiver_application_from_ready_open(
                runtime, &view, &application, &target_ordinal)) {
            return fence_storage_corrupt(owner);
        }
        foundation = ninlil_rt_find_transaction(
            runtime, &application.transaction_id);
        if (view.handoff_state == 0u) {
            if (foundation == NULL &&
                *transitions_consumed_out >= transition_budget) {
                *work_remaining_out = 1u;
                continue;
            }
            status = ninlil_rt_v1_bearer_commit_mfdt_ingress(
                runtime,
                &application,
                view.transfer_id,
                target_ordinal,
                now,
                &committed);
            if (status == NINLIL_E_NOT_FOUND) {
                *work_remaining_out = 1u;
                continue;
            }
            if (status == NINLIL_E_STORAGE_CORRUPT) {
                return fence_storage_corrupt(owner);
            }
            if (status != NINLIL_OK) {
                return status;
            }
            if (committed >
                transition_budget - *transitions_consumed_out) {
                return fence_storage_corrupt(owner);
            }
            *transitions_consumed_out += committed;
            foundation = ninlil_rt_find_transaction(
                runtime, &application.transaction_id);
        } else if (foundation == NULL ||
                   !ninlil_rt_v1_bearer_mfdt_ingress_matches(
                       runtime,
                       &application,
                       view.transfer_id,
                       target_ordinal)) {
            return fence_storage_corrupt(owner);
        }
        if (!foundation_has_required_positive_evidence(foundation)) {
            if (view.handoff_state != 0u) {
                return fence_storage_corrupt(owner);
            }
            continue;
        }
        status = receiver_application_evidence_digest(
            &view,
            &application,
            target_ordinal,
            foundation,
            evidence_digest);
        if (status != NINLIL_OK) {
            return fence_storage_corrupt(owner);
        }
        if (view.handoff_state != 0u) {
            if (view.publication_state != 2u ||
                memcmp(
                    view.publication_evidence_digest,
                    evidence_digest,
                    sizeof(evidence_digest)) != 0) {
                return fence_storage_corrupt(owner);
            }
            if (foundation_receipt_is_closed_exact(foundation)) {
                if (now->now_ms == 0u) {
                    *work_remaining_out = 1u;
                    continue;
                }
                if (*transitions_consumed_out >= transition_budget) {
                    *work_remaining_out = 1u;
                    continue;
                }
                rc = ninlil_mfdt_v1_host_finish_terminal(
                    owner->host, slot);
                if (rc == NINLIL_MFDT_V1_OK) {
                    *transitions_consumed_out += 1u;
                    continue;
                }
                if (rc == NINLIL_MFDT_V1_ERR_STORAGE ||
                    rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
                    rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
                    return host_error_to_runtime(owner, rc);
                }
                return fence_storage_corrupt(owner);
            }
            continue;
        }
        if (view.publication_state != 1u) {
            return fence_storage_corrupt(owner);
        }
        if (*transitions_consumed_out >= transition_budget) {
            *work_remaining_out = 1u;
            continue;
        }
        rc = ninlil_mfdt_v1_host_receiver_commit_publication(
            owner->host,
            slot,
            view.publication_token,
            evidence_digest);
        if (rc == NINLIL_MFDT_V1_OK) {
            *transitions_consumed_out += 1u;
            continue;
        }
        if (rc == NINLIL_MFDT_V1_ERR_STORAGE ||
            rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN ||
            rc == NINLIL_MFDT_V1_ERR_CU_NEW_NOT_PROMOTED) {
            return host_error_to_runtime(owner, rc);
        }
        return fence_storage_corrupt(owner);
    }
    return NINLIL_OK;
#endif
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_borrow_receiver_payload(
    ninlil_runtime_t *runtime,
    const uint8_t transfer_id[16],
    uint32_t target_ordinal,
    const ninlil_id128_t *foundation_transaction_id,
    const uint8_t **content_out,
    uint32_t *content_length_out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)transfer_id;
    (void)target_ordinal;
    (void)foundation_transaction_id;
    (void)content_out;
    (void)content_length_out;
    return NINLIL_E_UNSUPPORTED;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t slot;
    int rc;

    if (runtime == NULL || transfer_id == NULL ||
        foundation_transaction_id == NULL || content_out == NULL ||
        content_length_out == NULL ||
        !bytes_nonzero(transfer_id, 16u) ||
        target_ordinal >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *content_out = NULL;
    *content_length_out = 0u;
    owner = runtime->mfdt_v1_owner;
    if (!owner_is_valid(owner) || owner->dispatch_fenced != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK || header.started != 1u ||
        header.recovered != 1u || header.inventory_uncertain != 0u) {
        return fence_storage_corrupt(owner);
    }
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        ninlil_mfdt_v1_host_receiver_ready_view_t view;
        ninlil_bearer_message_t application;
        uint32_t open_ordinal = 0u;

        if (slots[slot].occupied == 0u ||
            slots[slot].role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
            memcmp(slots[slot].transfer_id, transfer_id, 16u) != 0) {
            continue;
        }
        (void)memset(&view, 0, sizeof(view));
        rc = ninlil_mfdt_v1_host_receiver_ready_view(
            owner->host, slot, &view);
        if (rc != NINLIL_MFDT_V1_OK ||
            view.stored_session_generation != owner->session_generation ||
            !receiver_application_from_ready_open(
                runtime, &view, &application, &open_ordinal) ||
            open_ordinal != target_ordinal ||
            memcmp(
                application.transaction_id.bytes,
                foundation_transaction_id->bytes,
                16u) != 0 ||
            !ninlil_rt_v1_bearer_mfdt_ingress_matches(
                runtime,
                &application,
                view.transfer_id,
                open_ordinal)) {
            return fence_storage_corrupt(owner);
        }
        *content_out = view.content;
        *content_length_out = view.content_length;
        return NINLIL_OK;
    }
    return fence_storage_corrupt(owner);
#endif
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_receiver_handoff_complete(
    ninlil_runtime_t *runtime,
    const uint8_t transfer_id[16],
    uint32_t target_ordinal,
    const ninlil_id128_t *foundation_transaction_id,
    uint32_t *complete_out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)transfer_id;
    (void)target_ordinal;
    (void)foundation_transaction_id;
    if (complete_out != NULL) {
        *complete_out = 0u;
    }
    return NINLIL_E_UNSUPPORTED;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    uint8_t slot;
    int rc;

    if (runtime == NULL || transfer_id == NULL ||
        foundation_transaction_id == NULL || complete_out == NULL ||
        !bytes_nonzero(transfer_id, 16u) ||
        target_ordinal >= NINLIL_MFDT_V1_HOST_SLOT_COUNT) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *complete_out = 0u;
    owner = runtime->mfdt_v1_owner;
    if (!owner_is_valid(owner) || owner->dispatch_fenced != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK || header.started != 1u ||
        header.recovered != 1u || header.inventory_uncertain != 0u) {
        return fence_storage_corrupt(owner);
    }
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        ninlil_mfdt_v1_host_receiver_ready_view_t view;
        ninlil_bearer_message_t application;
        ninlil_rt_transaction_slot_t *foundation;
        uint8_t expected_digest[32];
        uint32_t open_ordinal = 0u;
        ninlil_status_t status;

        if (slots[slot].occupied == 0u ||
            slots[slot].role != NINLIL_MFDT_V1_HOST_ROLE_RECEIVER ||
            memcmp(slots[slot].transfer_id, transfer_id, 16u) != 0) {
            continue;
        }
        (void)memset(&view, 0, sizeof(view));
        rc = ninlil_mfdt_v1_host_receiver_ready_view(
            owner->host, slot, &view);
        if (rc != NINLIL_MFDT_V1_OK ||
            view.stored_session_generation != owner->session_generation ||
            !receiver_application_from_ready_open(
                runtime, &view, &application, &open_ordinal) ||
            open_ordinal != target_ordinal ||
            memcmp(
                application.transaction_id.bytes,
                foundation_transaction_id->bytes,
                16u) != 0 ||
            !ninlil_rt_v1_bearer_mfdt_ingress_matches(
                runtime,
                &application,
                view.transfer_id,
                open_ordinal)) {
            return fence_storage_corrupt(owner);
        }
        if (view.handoff_state == 0u) {
            return NINLIL_OK;
        }
        foundation = ninlil_rt_find_transaction(
            runtime, &application.transaction_id);
        status = receiver_application_evidence_digest(
            &view,
            &application,
            open_ordinal,
            foundation,
            expected_digest);
        if (status != NINLIL_OK || view.publication_state != 2u ||
            memcmp(
                view.publication_evidence_digest,
                expected_digest,
                sizeof(expected_digest)) != 0) {
            return fence_storage_corrupt(owner);
        }
        *complete_out = 1u;
        return NINLIL_OK;
    }
    return fence_storage_corrupt(owner);
#endif
}

void ninlil_rt_mfdt_v1_runtime_owner_release(
    ninlil_runtime_t *runtime)
{
    if (runtime == NULL || runtime->mfdt_v1_owner == NULL) {
        return;
    }
    owner_free(runtime->mfdt_v1_owner);
    runtime->mfdt_v1_owner = NULL;
}

ninlil_status_t ninlil_rt_mfdt_v1_runtime_step_maintenance(
    ninlil_runtime_t *runtime,
    const ninlil_time_sample_t *now,
    uint32_t send_budget,
    uint32_t *bearer_sends_out,
    uint32_t *work_remaining_out)
{
#if defined(ESP_PLATFORM)
    (void)runtime;
    (void)now;
    (void)send_budget;
    if (bearer_sends_out != NULL) {
        *bearer_sends_out = 0u;
    }
    if (work_remaining_out != NULL) {
        *work_remaining_out = 0u;
    }
    return NINLIL_OK;
#else
    ninlil_rt_mfdt_v1_runtime_owner_t *owner;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t
        slots[NINLIL_MFDT_V1_HOST_SLOT_COUNT];
    ninlil_mfdt_v1_foundation_carrier_config_t carrier_config;
    ninlil_mfdt_v1_foundation_carrier_t carrier;
    mfdt_runtime_binding_t *binding = NULL;
    const uint8_t *frame = NULL;
    ninlil_bearer_status_t bearer_status = NINLIL_BEARER_EMPTY;
    uint32_t send_attempted = 0u;
    uint8_t offset = 0u;
    uint8_t epoch_changed = 0u;
    uint8_t selected_slot = UINT8_MAX;
    uint8_t slot = UINT8_MAX;
    uint8_t transport_work = 0u;
    size_t frame_length = 0u;
    size_t consumed_length = 0u;
    int rc;

    if (runtime == NULL || now == NULL || bearer_sends_out == NULL
        || work_remaining_out == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    *bearer_sends_out = 0u;
    *work_remaining_out = 0u;
    if (!trusted_time_sample_is_valid(now)) {
        return NINLIL_E_CLOCK_UNCERTAIN;
    }
    if (runtime->mfdt_v1_owner == NULL) {
        return NINLIL_OK;
    }
    owner = runtime->mfdt_v1_owner;
    if (!owner_is_valid(owner)) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner->dispatch_fenced != 0u) {
        *work_remaining_out = 1u;
        return NINLIL_E_DEGRADED;
    }
    rc = ninlil_mfdt_v1_host_observe_time(
        owner->host,
        now->clock_epoch_id.bytes,
        now->now_ms,
        &epoch_changed);
    if (rc != NINLIL_MFDT_V1_OK) {
        return host_error_to_runtime(owner, rc);
    }
    if (epoch_changed != 0u) {
        (void)memset(
            &owner->control_binding, 0, sizeof(owner->control_binding));
    }
    (void)memset(&header, 0, sizeof(header));
    (void)memset(slots, 0, sizeof(slots));
    rc = ninlil_mfdt_v1_host_snapshot(
        owner->host, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_E_INVALID_STATE;
    }
    clear_absent_bindings(owner, slots);
    if (header.control_outbox_pending == 0u) {
        (void)memset(
            &owner->control_binding, 0, sizeof(owner->control_binding));
    }
    transport_work = header.control_outbox_pending != 0u ? 1u : 0u;
    for (slot = 0u; slot < NINLIL_MFDT_V1_HOST_SLOT_COUNT; ++slot) {
        if (slots[slot].occupied != 0u &&
            (slots[slot].role == NINLIL_MFDT_V1_HOST_ROLE_SENDER ||
             slots[slot].outbox_pending != 0u)) {
            transport_work = 1u;
        }
    }
    slot = UINT8_MAX;
    if (transport_work == 0u) {
        return NINLIL_OK;
    }
    *work_remaining_out = 1u;
    if (send_budget == 0u) {
        return NINLIL_OK;
    }
    if (owner->session_bound == 0u) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (!ninlil_mfdt_v1_session_carrier_ncl1_data_ok(&owner->session)
        || owner->session.session_generation != owner->session_generation
        || owner->session.session_cookie != owner->session_cookie) {
        owner->dispatch_fenced = 1u;
        return NINLIL_E_INVALID_STATE;
    }
    rc = ninlil_mfdt_v1_host_schedule_one_chunk(
        owner->host, &selected_slot);
    if (rc != NINLIL_MFDT_V1_OK
        && rc != NINLIL_MFDT_V1_ERR_BUSY
        && rc != NINLIL_MFDT_V1_ERR_STATE) {
        return host_error_to_runtime(owner, rc);
    }
    rc = host_snapshot(owner, &header, slots);
    if (rc != NINLIL_MFDT_V1_OK) {
        return NINLIL_E_INVALID_STATE;
    }
    for (offset = 0u;
         offset < NINLIL_MFDT_V1_HOST_SLOT_COUNT;
         ++offset) {
        slot = (uint8_t)(
            (header.next_slot + offset)
            % NINLIL_MFDT_V1_HOST_SLOT_COUNT);
        if (slots[slot].occupied == 0u
            || slots[slot].bind_valid == 0u
            || slots[slot].outbox_pending != 0u
            || slots[slot].role != NINLIL_MFDT_V1_HOST_ROLE_SENDER) {
            continue;
        }
        rc = ninlil_mfdt_v1_host_pump_control(owner->host, slot);
        if (rc != NINLIL_MFDT_V1_OK
            && rc != NINLIL_MFDT_V1_ERR_BUSY
            && rc != NINLIL_MFDT_V1_ERR_STATE) {
            return host_error_to_runtime(owner, rc);
        }
        rc = host_snapshot(owner, &header, slots);
        if (rc != NINLIL_MFDT_V1_OK) {
            return NINLIL_E_INVALID_STATE;
        }
        if (slots[slot].outbox_pending != 0u) {
            break;
        }
    }
    if (!select_pending_route(owner, &header, slots, &slot)) {
        return NINLIL_OK;
    }
    binding = slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE
        ? &owner->control_binding : &owner->bindings[slot];
    if (slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE) {
        if (binding->occupied == 0u
            || memcmp(
                   binding->application.source.runtime_id.bytes,
                   owner->session.local_endpoint_id,
                   16u) != 0
            || memcmp(
                   binding->application.target.target_runtime_id.bytes,
                   owner->session.peer_endpoint_id,
                   16u) != 0) {
            owner->dispatch_fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
    } else if (!binding_matches_slot(
                   binding, &slots[slot], &owner->session)) {
        owner->dispatch_fenced = 1u;
        return NINLIL_E_INVALID_STATE;
    }
    if (binding == NULL || binding->occupied == 0u
        || memcmp(
               binding->application.target.target_runtime_id.bytes,
               owner->session.peer_endpoint_id,
               16u) != 0) {
        owner->dispatch_fenced = 1u;
        return NINLIL_E_INVALID_STATE;
    }
    rc = ninlil_mfdt_v1_host_peek_outbound_ncl1(
        owner->host, slot, &frame, &frame_length);
    if (rc != NINLIL_MFDT_V1_OK || frame == NULL
        || frame_length == 0u
        || frame_length > sizeof(owner->pending_frame)) {
        owner->dispatch_fenced = 1u;
        return host_error_to_runtime(owner, rc);
    }
    (void)memset(&carrier_config, 0, sizeof(carrier_config));
    carrier_config.bearer = runtime->platform->bearer;
    carrier_config.clock = runtime->platform->clock;
    carrier_config.tx_gate = runtime->platform->tx_gate;
    carrier_config.role = runtime->config.role;
    carrier_config.source = binding->application.source;
    carrier_config.target = binding->application.target;
    carrier_config.session = &owner->session;
    carrier_config.deadline_window_ms =
        NINLIL_MFDT_V1_CARRIER_DEADLINE_MS_DEFAULT;
    rc = ninlil_mfdt_v1_foundation_carrier_init(
        &carrier, &carrier_config);
    if (rc != NINLIL_MFDT_V1_OK) {
        owner->dispatch_fenced = 1u;
        return NINLIL_E_INVALID_STATE;
    }
    rc = ninlil_mfdt_v1_foundation_carrier_tx_shared(
        &carrier,
        runtime->bearer,
        frame,
        frame_length,
        now,
        &send_attempted,
        &bearer_status);
    *bearer_sends_out = send_attempted;
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_host_take_outbound_ncl1(
            owner->host,
            slot,
            owner->pending_frame,
            sizeof(owner->pending_frame),
            &consumed_length);
        if (rc != NINLIL_MFDT_V1_OK
            || consumed_length != frame_length) {
            owner->dispatch_fenced = 1u;
            return host_error_to_runtime(owner, rc);
        }
        if (slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE) {
            (void)memset(
                &owner->control_binding, 0, sizeof(owner->control_binding));
        }
        (void)memset(owner->pending_frame, 0, sizeof(owner->pending_frame));
        if (host_snapshot(owner, &header, slots)
            != NINLIL_MFDT_V1_OK) {
            owner->dispatch_fenced = 1u;
            return NINLIL_E_INVALID_STATE;
        }
        clear_absent_bindings(owner, slots);
        return NINLIL_OK;
    }
    if (rc == NINLIL_MFDT_V1_ERR_BUSY) {
        return NINLIL_OK;
    }
    if (rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN
        || bearer_status == NINLIL_BEARER_LOST_UNKNOWN) {
        (void)ninlil_mfdt_v1_host_take_outbound_ncl1(
            owner->host,
            slot,
            owner->pending_frame,
            sizeof(owner->pending_frame),
            &consumed_length);
        if (slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE) {
            (void)memset(
                &owner->control_binding, 0, sizeof(owner->control_binding));
        }
        (void)memset(owner->pending_frame, 0, sizeof(owner->pending_frame));
        runtime->commit_unknown_fence = 1u;
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    owner->dispatch_fenced = 1u;
    runtime->health = NINLIL_HEALTH_DEGRADED;
    runtime->degraded_reason = NINLIL_REASON_OUTCOME_UNKNOWN;
    if (send_attempted != 0u) {
        *work_remaining_out = 1u;
    }
    return NINLIL_E_DEGRADED;
#endif
}
