/* SPDX-License-Identifier: Apache-2.0 */
/*
 *
 * Private Runtime-owner acceptance. This proves instance ownership, exact
 * Host slot cardinality, and use of the Runtime's existing Storage Port.
 * It is not the public-submit/callback/restart acceptance required to promote
 * ADR-0021.
 */
#include "mfdt_v1_runtime_owner.h"
#include "mfdt_v1_foundation_carrier.h"
#include "mfdt_v1_ncl1.h"

#include "ninlil_posix_lab_platform.h"
#include "../../support/platform_basic_fixtures.h"
#include "../../support/typed_simulated_bearer.h"

#include <ninlil/runtime.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ninlil_test_bearer_t *ninlil_posix_lab_platform_test_bearer(
    ninlil_posix_lab_platform_t *platform);

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                       \
                "CHECK_FAIL %s:%d: %s\n",                                    \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static const uint8_t k_namespace_a[] = "mfdt-runtime-owner-a";
static const uint8_t k_namespace_b[] = "mfdt-runtime-owner-b";
static const uint8_t k_namespace_c[] = "mfdt-runtime-owner-c";
static const uint8_t k_namespace_wrong[] = "mfdt-runtime-owner-wrong";
static const uint8_t k_namespace_domain[] =
    "NINLIL-MFDT-STORAGE-NAMESPACE-V1";
static const uint8_t k_binding_domain[] =
    "NINLIL-MFDT-BASE-NAMESPACE-V1";
static const uint8_t k_binding_key[20] = {'N', 'M', 'S', '1'};
static uint32_t g_application_callback_calls;

static void derive_sidecar_namespace(
    const uint8_t *base,
    uint32_t base_length,
    uint8_t out[36])
{
    uint8_t preimage[sizeof(k_namespace_domain) - 1u + 2u + 255u];
    uint8_t digest[32];
    uint32_t offset = 0u;

    (void)memcpy(
        preimage + offset,
        k_namespace_domain,
        sizeof(k_namespace_domain) - 1u);
    offset += (uint32_t)sizeof(k_namespace_domain) - 1u;
    ninlil_mfdt_v1_put_u16(preimage + offset, (uint16_t)base_length);
    offset += 2u;
    (void)memcpy(preimage + offset, base, base_length);
    offset += base_length;
    ninlil_mfdt_v1_sha256(preimage, offset, digest);
    (void)memcpy(out, "NMF1", 4u);
    (void)memcpy(out + 4u, digest, sizeof(digest));
}

static uint32_t build_binding(
    const uint8_t *base,
    uint32_t base_length,
    uint8_t out[307])
{
    uint8_t preimage[sizeof(k_binding_domain) - 1u + 2u + 255u];
    uint8_t digest[32];
    uint32_t offset = 0u;
    uint32_t preimage_length = 0u;
    uint32_t total_length = 52u + base_length;

    (void)memcpy(
        preimage + preimage_length,
        k_binding_domain,
        sizeof(k_binding_domain) - 1u);
    preimage_length += (uint32_t)sizeof(k_binding_domain) - 1u;
    ninlil_mfdt_v1_put_u16(
        preimage + preimage_length, (uint16_t)base_length);
    preimage_length += 2u;
    (void)memcpy(preimage + preimage_length, base, base_length);
    preimage_length += base_length;
    ninlil_mfdt_v1_sha256(preimage, preimage_length, digest);

    (void)memset(out, 0, 307u);
    (void)memcpy(out + offset, "NMS1", 4u);
    offset += 4u;
    ninlil_mfdt_v1_put_u16(out + offset, 1u);
    offset += 2u;
    ninlil_mfdt_v1_put_u16(out + offset, 48u);
    offset += 2u;
    ninlil_mfdt_v1_put_u32(out + offset, total_length);
    offset += 4u;
    ninlil_mfdt_v1_put_u16(out + offset, (uint16_t)base_length);
    offset += 2u;
    ninlil_mfdt_v1_put_u16(out + offset, 0u);
    offset += 2u;
    (void)memcpy(out + offset, digest, sizeof(digest));
    offset += (uint32_t)sizeof(digest);
    (void)memcpy(out + offset, base, base_length);
    offset += base_length;
    ninlil_mfdt_v1_put_u32(
        out + offset, ninlil_mfdt_v1_crc32c(out, offset));
    offset += 4u;
    return offset;
}

static int read_row(
    const ninlil_storage_ops_t *storage,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    const uint8_t *key_bytes,
    uint32_t key_length,
    uint8_t *value_bytes,
    uint32_t value_capacity,
    uint32_t *value_length_out,
    ninlil_storage_status_t expected_status)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_bytes_view_t storage_namespace_view;
    ninlil_bytes_view_t key;
    ninlil_mut_bytes_t value;
    ninlil_storage_status_t status;
    int ok = 0;

    storage_namespace_view.data = storage_namespace;
    storage_namespace_view.length = storage_namespace_length;
    status = storage->open(
        storage->user,
        storage_namespace_view,
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status != NINLIL_STORAGE_OK || handle == NULL) {
        goto done;
    }
    status = storage->begin(
        storage->user, handle, NINLIL_STORAGE_READ_ONLY, &transaction);
    if (status != NINLIL_STORAGE_OK || transaction == NULL) {
        goto done;
    }
    key.data = key_bytes;
    key.length = key_length;
    value.data = value_bytes;
    value.capacity = value_capacity;
    value.length = 0u;
    status = storage->get(storage->user, transaction, key, &value);
    if (status == expected_status
        && storage->rollback(storage->user, transaction)
            == NINLIL_STORAGE_OK) {
        transaction = NULL;
        *value_length_out = value.length;
        ok = 1;
    }

done:
    if (transaction != NULL) {
        (void)storage->rollback(storage->user, transaction);
    }
    if (handle != NULL) {
        storage->close(storage->user, handle);
    }
    return ok;
}

static int write_row(
    const ninlil_storage_ops_t *storage,
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    const uint8_t *key_bytes,
    uint32_t key_length,
    const uint8_t *value_bytes,
    uint32_t value_length)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t transaction = NULL;
    ninlil_bytes_view_t storage_namespace_view;
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;
    ninlil_storage_status_t status;
    int ok = 0;

    storage_namespace_view.data = storage_namespace;
    storage_namespace_view.length = storage_namespace_length;
    status = storage->open(
        storage->user,
        storage_namespace_view,
        NINLIL_STORAGE_SCHEMA_M1A,
        &handle);
    if (status != NINLIL_STORAGE_OK || handle == NULL) {
        goto done;
    }
    status = storage->begin(
        storage->user, handle, NINLIL_STORAGE_READ_WRITE, &transaction);
    if (status != NINLIL_STORAGE_OK || transaction == NULL) {
        goto done;
    }
    key.data = key_bytes;
    key.length = key_length;
    value.data = value_bytes;
    value.length = value_length;
    status = storage->put(storage->user, transaction, key, value);
    if (status == NINLIL_STORAGE_OK
        && storage->commit(
               storage->user, transaction, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK) {
        transaction = NULL;
        ok = 1;
    }

done:
    if (transaction != NULL) {
        (void)storage->rollback(storage->user, transaction);
    }
    if (handle != NULL) {
        storage->close(storage->user, handle);
    }
    return ok;
}

static int binding_is_exact(
    const ninlil_storage_ops_t *storage,
    const uint8_t *base,
    uint32_t base_length)
{
    uint8_t sidecar[36];
    uint8_t expected[307];
    uint8_t actual[307];
    uint32_t expected_length;
    uint32_t actual_length = 0u;

    derive_sidecar_namespace(base, base_length, sidecar);
    expected_length = build_binding(base, base_length, expected);
    return read_row(
               storage,
               sidecar,
               sizeof(sidecar),
               k_binding_key,
               sizeof(k_binding_key),
               actual,
               sizeof(actual),
               &actual_length,
               NINLIL_STORAGE_OK)
        && actual_length == expected_length
        && memcmp(actual, expected, expected_length) == 0;
}

static int base_has_no_binding(
    const ninlil_storage_ops_t *storage,
    const uint8_t *base,
    uint32_t base_length)
{
    uint8_t value[307];
    uint32_t value_length = UINT32_MAX;

    return read_row(
               storage,
               base,
               base_length,
               k_binding_key,
               sizeof(k_binding_key),
               value,
               sizeof(value),
               &value_length,
               NINLIL_STORAGE_NOT_FOUND)
        && value_length == 0u;
}

static void set_header(
    uint16_t *abi_version,
    uint16_t *struct_size,
    size_t size)
{
    *abi_version = NINLIL_ABI_VERSION;
    *struct_size = (uint16_t)size;
}

static void set_id(ninlil_id128_t *id, uint8_t tag)
{
    size_t index;

    for (index = 0u; index < sizeof(id->bytes); ++index) {
        id->bytes[index] = (uint8_t)(tag + (uint8_t)index);
    }
}

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 1;
        }
    }
    return 0;
}

static void derive_test_transfer_id(
    const ninlil_bearer_message_t *application,
    uint32_t target_ordinal,
    uint8_t transfer_id[16])
{
    uint8_t material[52];
    uint8_t digest[32];

    (void)memcpy(material, application->transaction_id.bytes, 16u);
    (void)memcpy(
        material + 16u,
        application->target.target_runtime_id.bytes,
        16u);
    material[32] = (uint8_t)(target_ordinal >> 24);
    material[33] = (uint8_t)(target_ordinal >> 16);
    material[34] = (uint8_t)(target_ordinal >> 8);
    material[35] = (uint8_t)target_ordinal;
    (void)memcpy(material + 36u, "ninlil-mfdt-v1id", 16u);
    ninlil_mfdt_v1_sha256(material, sizeof(material), digest);
    (void)memcpy(transfer_id, digest, 16u);
    if (!bytes_nonzero(transfer_id, 16u)) {
        transfer_id[15] = 1u;
    }
}

static int durable_transfer_rows_absent(
    const ninlil_storage_ops_t *storage,
    const uint8_t *base,
    uint32_t base_length,
    const uint8_t transfer_id[16])
{
    static const uint8_t prefixes[][4] = {
        {'N', 'M', '3', 'S'},
        {'N', 'M', '3', 'R'},
        {'N', 'M', '3', '0'},
        {'N', 'R', 'C', '1'}
    };
    uint8_t sidecar[36];
    uint8_t key[20];
    uint8_t value[1];
    uint32_t value_length;
    size_t index;

    derive_sidecar_namespace(base, base_length, sidecar);
    for (index = 0u; index < sizeof(prefixes) / sizeof(prefixes[0]); ++index) {
        (void)memcpy(key, prefixes[index], 4u);
        (void)memcpy(key + 4u, transfer_id, 16u);
        value_length = UINT32_MAX;
        if (!read_row(
                storage,
                sidecar,
                sizeof(sidecar),
                key,
                sizeof(key),
                value,
                sizeof(value),
                &value_length,
                NINLIL_STORAGE_NOT_FOUND)
            || value_length != 0u) {
            return 0;
        }
    }
    return 1;
}

static ninlil_runtime_config_t runtime_config(
    const uint8_t *storage_namespace,
    uint32_t storage_namespace_length,
    uint8_t runtime_tag)
{
    ninlil_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    set_header(&config.abi_version, &config.struct_size, sizeof(config));
    config.role = NINLIL_ROLE_CONTROLLER;
    config.environment = NINLIL_ENV_TEST;
    set_id(&config.runtime_id, runtime_tag);
    set_header(
        &config.local_identity.abi_version,
        &config.local_identity.struct_size,
        sizeof(config.local_identity));
    config.local_identity.flags =
        NINLIL_LOCAL_IDENTITY_HAS_DEVICE
        | NINLIL_LOCAL_IDENTITY_HAS_INSTALLATION
        | NINLIL_LOCAL_IDENTITY_HAS_SITE;
    set_id(&config.local_identity.device_id, (uint8_t)(runtime_tag + 0x10u));
    set_id(
        &config.local_identity.installation_id,
        (uint8_t)(runtime_tag + 0x20u));
    set_id(
        &config.local_identity.site_domain_id,
        (uint8_t)(runtime_tag + 0x30u));
    config.local_identity.binding_epoch = 1u;
    config.local_identity.membership_epoch = 1u;
    config.storage_namespace.data = storage_namespace;
    config.storage_namespace.length = storage_namespace_length;
    set_header(
        &config.limits.abi_version,
        &config.limits.struct_size,
        sizeof(config.limits));
    config.limits.max_services = 4u;
    config.limits.max_nonterminal_transactions = 16u;
    config.limits.max_targets_per_transaction = 1u;
    config.limits.max_logical_payload_bytes = 1024u;
    config.limits.max_durable_outbox_payload_bytes = 262144u;
    config.limits.max_attempts_per_target_per_cycle = 8u;
    config.limits.max_cancel_attempts_per_transaction = 1u;
    config.limits.max_evidence_per_target = 4u;
    config.limits.max_retained_terminal_transactions = 32u;
    config.limits.max_nonterminal_deliveries = 16u;
    config.limits.max_result_cache_entries = 32u;
    config.limits.max_retained_dispositions = 32u;
    config.limits.max_ingress_per_step = 8u;
    config.limits.max_callbacks_per_step = 8u;
    config.limits.max_state_transitions_per_step = 16u;
    config.limits.max_bearer_sends_per_step = 8u;
    config.limits.max_deferred_tokens = 8u;
    config.terminal_retention_ms = 60000u;
    config.result_cache_retention_ms = 60000u;
    config.observation_retention_ms = 60000u;
    return config;
}

static void fill_text(
    ninlil_text_id_t *out,
    const char *text)
{
    const size_t length = strlen(text);

    (void)memset(out, 0, sizeof(*out));
    out->length = (uint8_t)length;
    (void)memcpy(out->bytes, text, length);
}

static void make_application(
    ninlil_bearer_message_t *message,
    const ninlil_runtime_config_t *source,
    const ninlil_time_sample_t *now,
    const uint8_t *payload,
    uint32_t payload_length,
    uint8_t transaction_tag,
    uint8_t target_tag)
{
    uint8_t digest[32];

    (void)memset(message, 0, sizeof(*message));
    set_header(
        &message->abi_version,
        &message->struct_size,
        sizeof(*message));
    message->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    set_header(
        &message->source.abi_version,
        &message->source.struct_size,
        sizeof(message->source));
    set_id(&message->transaction_id, transaction_tag);
    set_id(&message->attempt_id, (uint8_t)(transaction_tag + 0x10u));
    message->source.runtime_id = source->runtime_id;
    set_id(
        &message->source.application_instance_id,
        (uint8_t)(transaction_tag + 0x20u));
    message->source.local_identity = source->local_identity;
    set_id(&message->target.target_runtime_id, target_tag);
    set_id(
        &message->target.target_application_instance_id,
        (uint8_t)(target_tag + 0x10u));
    set_header(
        &message->target.abi_version,
        &message->target.struct_size,
        sizeof(message->target));
    set_header(
        &message->service.abi_version,
        &message->service.struct_size,
        sizeof(message->service));
    fill_text(&message->service.namespace_id, "org.ninlil.runtime");
    fill_text(&message->service.service_id, "binary-transfer");
    fill_text(&message->service.schema_id, "application-data-v1");
    message->service.descriptor_revision = 1u;
    message->service.descriptor_digest.algorithm = NINLIL_DIGEST_SHA256;
    (void)memset(
        message->service.descriptor_digest.bytes,
        transaction_tag,
        sizeof(message->service.descriptor_digest.bytes));
    message->service.schema_major = 1u;
    message->service.family = NINLIL_FAMILY_TRANSFER_RESERVED;
    message->content_digest.algorithm = NINLIL_DIGEST_SHA256;
    ninlil_mfdt_v1_sha256(payload, payload_length, digest);
    (void)memcpy(
        message->content_digest.bytes,
        digest,
        sizeof(message->content_digest.bytes));
    message->generation = 1u;
    message->deadline_clock_epoch_id = now->clock_epoch_id;
    message->absolute_effect_deadline_ms = now->now_ms + 60000u;
    message->evidence_grace_ms = 1000u;
    message->required_evidence = NINLIL_EVIDENCE_APPLIED;
    message->payload.data = payload;
    message->payload.length = payload_length;
}

static ninlil_callback_action_t unexpected_application_callback(
    void *user,
    const ninlil_delivery_token_t *token,
    const ninlil_delivery_view_t *delivery,
    ninlil_application_result_t *out_sync_result)
{
    (void)user;
    (void)token;
    (void)delivery;
    (void)out_sync_result;
    g_application_callback_calls += 1u;
    return NINLIL_CALLBACK_FATAL;
}

static ninlil_status_t register_application_receiver(
    ninlil_runtime_t *runtime,
    const ninlil_bearer_message_t *application,
    ninlil_service_t **service_out)
{
    ninlil_service_descriptor_t descriptor;
    ninlil_service_callbacks_t callbacks;

    (void)memset(&descriptor, 0, sizeof(descriptor));
    set_header(
        &descriptor.abi_version,
        &descriptor.struct_size,
        sizeof(descriptor));
    descriptor.namespace_id.data =
        application->service.namespace_id.bytes;
    descriptor.namespace_id.length =
        application->service.namespace_id.length;
    descriptor.service_id.data = application->service.service_id.bytes;
    descriptor.service_id.length = application->service.service_id.length;
    descriptor.schema_id.data = application->service.schema_id.bytes;
    descriptor.schema_id.length = application->service.schema_id.length;
    descriptor.descriptor_revision =
        application->service.descriptor_revision;
    descriptor.descriptor_digest = application->service.descriptor_digest;
    descriptor.local_application_instance_id =
        application->target.target_application_instance_id;
    descriptor.schema_major = application->service.schema_major;
    descriptor.family = application->service.family;
    descriptor.direction = NINLIL_DIRECTION_DOWNLINK;
    descriptor.admission_authority = NINLIL_AUTHORITY_CONTROLLER_ONLY;
    descriptor.apply_contract = NINLIL_APPLY_IDEMPOTENT;
    descriptor.custody_policy = NINLIL_CUSTODY_UNTIL_REQUIRED_EVIDENCE;
    descriptor.supported_evidence_mask =
        NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_RECEIVED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_DURABLY_RECORDED)
        | NINLIL_EVIDENCE_MASK(NINLIL_EVIDENCE_APPLIED);
    descriptor.logical_payload_limit = 32768u;
    descriptor.target_limit = 1u;
    descriptor.inflight_limit = 4u;
    descriptor.max_attempts_per_target_per_cycle =
        NINLIL_M1A_ATTEMPTS_PER_RETRY_CYCLE;
    descriptor.admission_window_ms = 10000u;
    descriptor.max_admissions_per_window = 8u;
    descriptor.max_payload_bytes_per_window = 262144u;
    descriptor.minimum_deadline_ms = 100u;
    descriptor.maximum_deadline_ms = 60000u;
    descriptor.maximum_evidence_grace_ms = 1000u;
    descriptor.attempt_receipt_timeout_ms = 1000u;
    descriptor.retry_backoff_ms = 50u;
    descriptor.application_completion_timeout_ms = 60000u;
    descriptor.required_dedup_window_ms = 1000u;
    (void)memset(&callbacks, 0, sizeof(callbacks));
    set_header(
        &callbacks.abi_version,
        &callbacks.struct_size,
        sizeof(callbacks));
    callbacks.on_delivery = unexpected_application_callback;
    return ninlil_service_register(
        runtime, &descriptor, &callbacks, service_out);
}

static int foundation_transaction_is_absent(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *transaction_id)
{
    ninlil_transaction_snapshot_t snapshot;

    (void)memset(&snapshot, 0, sizeof(snapshot));
    set_header(
        &snapshot.abi_version, &snapshot.struct_size, sizeof(snapshot));
    return ninlil_transaction_query(runtime, transaction_id, &snapshot)
        == NINLIL_E_NOT_FOUND;
}

static void make_malformed_carrier(
    ninlil_bearer_message_t *message,
    const ninlil_runtime_config_t *source,
    const ninlil_runtime_config_t *target,
    const ninlil_time_sample_t *now)
{
    static const uint8_t invalid_ncl1[] = {0x00u};

    (void)memset(message, 0, sizeof(*message));
    set_header(
        &message->abi_version,
        &message->struct_size,
        sizeof(*message));
    message->kind = NINLIL_BEARER_MESSAGE_APPLICATION;
    set_id(&message->transaction_id, 0x91u);
    set_id(&message->attempt_id, 0xa1u);
    set_header(
        &message->source.abi_version,
        &message->source.struct_size,
        sizeof(message->source));
    message->source.runtime_id = source->runtime_id;
    set_id(&message->source.application_instance_id, 0xb1u);
    message->source.local_identity = source->local_identity;
    set_header(
        &message->target.abi_version,
        &message->target.struct_size,
        sizeof(message->target));
    message->target.target_runtime_id = target->runtime_id;
    set_id(
        &message->target.target_application_instance_id,
        0xc1u);
    (void)ninlil_mfdt_v1_foundation_carrier_service_identity(
        &message->service);
    message->content_digest.algorithm = NINLIL_DIGEST_SHA256;
    ninlil_mfdt_v1_sha256(
        invalid_ncl1,
        sizeof(invalid_ncl1),
        message->content_digest.bytes);
    message->generation = 1u;
    message->deadline_clock_epoch_id = now->clock_epoch_id;
    message->absolute_effect_deadline_ms = now->now_ms + 60000u;
    message->payload.data = invalid_ncl1;
    message->payload.length = sizeof(invalid_ncl1);
}

static void carrier_party(
    const ninlil_runtime_config_t *runtime,
    uint8_t application_tag,
    ninlil_party_t *party)
{
    (void)memset(party, 0, sizeof(*party));
    set_header(&party->abi_version, &party->struct_size, sizeof(*party));
    party->runtime_id = runtime->runtime_id;
    set_id(&party->application_instance_id, application_tag);
    party->local_identity = runtime->local_identity;
}

static void carrier_target(
    const ninlil_runtime_config_t *runtime,
    uint8_t application_tag,
    ninlil_concrete_target_t *target)
{
    (void)memset(target, 0, sizeof(*target));
    set_header(&target->abi_version, &target->struct_size, sizeof(*target));
    target->target_runtime_id = runtime->runtime_id;
    set_id(&target->target_application_instance_id, application_tag);
    target->device_id = runtime->local_identity.device_id;
    target->installation_id = runtime->local_identity.installation_id;
    target->site_domain_id = runtime->local_identity.site_domain_id;
    target->binding_epoch = runtime->local_identity.binding_epoch;
    target->membership_epoch = runtime->local_identity.membership_epoch;
    target->flags = runtime->local_identity.flags;
}

static ninlil_status_t enable_owner(
    ninlil_runtime_t *runtime,
    uint64_t cookie)
{
    ninlil_rt_mfdt_v1_runtime_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.struct_size = (uint32_t)sizeof(config);
    config.enabled = 1u;
    config.session_generation = 1u;
    config.session_cookie = cookie;
    return ninlil_rt_mfdt_v1_runtime_configure(runtime, &config);
}

static int bind_owner_session(
    ninlil_runtime_t *runtime,
    const ninlil_id128_t *local_id,
    const ninlil_id128_t *peer_id,
    uint64_t cookie,
    ninlil_mfdt_v1_session_t *session_out)
{
    ninlil_mfdt_v1_session_t initiator;
    ninlil_mfdt_v1_session_t responder;
    uint8_t offer_nonce[16];
    uint8_t responder_nonce[16];
    uint8_t offer[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    uint8_t accept[NINLIL_MFDT_V1_NEGOTIATE_MAX_WIRE_BYTES];
    size_t offer_length = 0u;
    size_t accept_length = 0u;

    (void)memset(offer_nonce, 0x31, sizeof(offer_nonce));
    (void)memset(responder_nonce, 0x42, sizeof(responder_nonce));
    ninlil_mfdt_v1_session_init(
        &initiator, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    ninlil_mfdt_v1_session_init(
        &responder, 1u, NINLIL_MFDT_V1_CAP_REQUIRED);
    if (!(ninlil_mfdt_v1_session_bind(
               &initiator,
               2u,
               1u,
               cookie,
               1u,
               local_id->bytes,
               peer_id->bytes) == NINLIL_MFDT_V1_OK
        && ninlil_mfdt_v1_session_bind(
               &responder,
               2u,
               1u,
               cookie,
               1u,
               peer_id->bytes,
               local_id->bytes) == NINLIL_MFDT_V1_OK
        && ninlil_mfdt_v1_session_build_offer(
               &initiator,
               7u,
               offer_nonce,
               offer,
               sizeof(offer),
               &offer_length) == NINLIL_MFDT_V1_OK
        && ninlil_mfdt_v1_session_on_offer(
               &responder,
               offer,
               offer_length,
               responder_nonce,
               accept,
               sizeof(accept),
               &accept_length) == NINLIL_MFDT_V1_OK
        && ninlil_mfdt_v1_session_on_accept(
               &initiator, accept, accept_length) == NINLIL_MFDT_V1_OK
        && ninlil_rt_mfdt_v1_runtime_bind_session(runtime, &initiator)
               == NINLIL_OK)) {
        return 0;
    }
    if (session_out != NULL) {
        *session_out = initiator;
    }
    return 1;
}

static int snapshot_is(
    ninlil_runtime_t *runtime,
    uint32_t active_count)
{
    ninlil_rt_mfdt_v1_runtime_snapshot_t snapshot;

    (void)memset(&snapshot, 0, sizeof(snapshot));
    snapshot.struct_size = (uint32_t)sizeof(snapshot);
    if (ninlil_rt_mfdt_v1_runtime_snapshot(runtime, &snapshot)
        != NINLIL_OK) {
        return 0;
    }
    return snapshot.enabled == 1u
        && snapshot.ready == 1u
        && snapshot.exact_slot_count == 4u
        && snapshot.active_count == active_count
        && snapshot.recovered == 1u
        && snapshot.inventory_uncertain == 0u;
}

int main(void)
{
    ninlil_posix_lab_platform_config_t platform_config;
    ninlil_posix_lab_platform_t *platform = NULL;
    const ninlil_platform_ops_t *ops;
    ninlil_runtime_config_t config_a;
    ninlil_runtime_config_t config_b;
    ninlil_runtime_config_t config_c;
    ninlil_runtime_t *runtime_a = NULL;
    ninlil_runtime_t *runtime_b = NULL;
    ninlil_runtime_t *runtime_c = NULL;
    ninlil_time_sample_t now;
    ninlil_mfdt_v1_session_t session_a;
    ninlil_mfdt_v1_session_t session_b;
    ninlil_bearer_message_t application;
    ninlil_bearer_message_t malformed_carrier;
    uint8_t *payload_4k = NULL;
    uint8_t *payload_32k = NULL;
    uint8_t transfer_id[16];
    uint8_t expected_transfer_id[16];
    uint8_t completed_transfer_id[16];
    uint8_t sidecar_c[36];
    uint8_t wrong_binding[307];
    uint8_t observed_binding[307];
    uint8_t slot = 0xffu;
    uint32_t wrong_binding_length;
    uint32_t observed_binding_length = 0u;
    uint32_t claimed = 0u;
    uint32_t durable_transition = 0u;
    uint32_t index;
    int result = 1;

    ninlil_posix_lab_platform_config_defaults(&platform_config);
    platform_config.max_entries_per_namespace = 512u;
    platform_config.max_bytes_per_namespace = 2u * 1024u * 1024u;
    platform = ninlil_posix_lab_platform_create(&platform_config);
    CHECK(platform != NULL);
    ops = ninlil_posix_lab_platform_ops(platform);
    CHECK(ops != NULL);
    CHECK(ninlil_test_clock_advance(
        (ninlil_test_clock_t *)ops->clock->user, 1000u));
    config_a = runtime_config(
        k_namespace_a, (uint32_t)(sizeof(k_namespace_a) - 1u), 0x10u);
    config_b = runtime_config(
        k_namespace_b, (uint32_t)(sizeof(k_namespace_b) - 1u), 0x50u);
    config_b.role = NINLIL_ROLE_ENDPOINT;
    config_b.limits.max_logical_payload_bytes = 32768u;
    config_b.limits.max_durable_outbox_payload_bytes = 0u;
    /*
     * The LAB bearer has exactly two durable endpoint bindings.  Reuse B's
     * now-inactive Runtime identity for the independent namespace-collision
     * case below; the Storage namespace and binding preimage remain C.
     */
    config_c = runtime_config(
        k_namespace_c, (uint32_t)(sizeof(k_namespace_c) - 1u), 0x50u);
    config_c.role = NINLIL_ROLE_ENDPOINT;
    config_c.limits.max_logical_payload_bytes = 32768u;
    config_c.limits.max_durable_outbox_payload_bytes = 0u;
    CHECK(ninlil_runtime_create(&config_a, ops, &runtime_a) == NINLIL_OK);
    CHECK(ninlil_runtime_create(&config_b, ops, &runtime_b) == NINLIL_OK);
    CHECK(ninlil_rt_mfdt_v1_runtime_should_use(runtime_a, 4096u) == 0);
    CHECK(enable_owner(runtime_a, UINT64_C(0x1111222233334444))
        == NINLIL_OK);
    CHECK(enable_owner(runtime_b, UINT64_C(0x1111222233334444))
        == NINLIL_OK);
    CHECK(bind_owner_session(
        runtime_a,
        &config_a.runtime_id,
        &config_b.runtime_id,
        UINT64_C(0x1111222233334444),
        &session_a));
    CHECK(bind_owner_session(
        runtime_b,
        &config_b.runtime_id,
        &config_a.runtime_id,
        UINT64_C(0x1111222233334444),
        &session_b));
    CHECK(ninlil_rt_mfdt_v1_runtime_should_use(runtime_a, 926u) == 0);
    CHECK(ninlil_rt_mfdt_v1_runtime_should_use(runtime_a, 927u) != 0);
    CHECK(ninlil_rt_mfdt_v1_runtime_should_use(runtime_a, 32768u) != 0);
    CHECK(ninlil_rt_mfdt_v1_runtime_should_use(runtime_a, 32769u) == 0);
    CHECK(snapshot_is(runtime_a, 0u));
    CHECK(snapshot_is(runtime_b, 0u));

    (void)memset(&now, 0, sizeof(now));
    CHECK(ops->clock->now(ops->clock->user, &now) == NINLIL_PORT_OK);
    {
        ninlil_mfdt_v1_foundation_carrier_config_t sender_config;
        ninlil_mfdt_v1_foundation_carrier_config_t receiver_config;
        ninlil_mfdt_v1_foundation_carrier_t sender_carrier;
        ninlil_mfdt_v1_foundation_carrier_t receiver_carrier;
        ninlil_bearer_message_t canonical;
        ninlil_bearer_message_t mutated;
        uint8_t body[16];
        uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
        uint8_t accepted[NINLIL_MFDT_V1_NCL1_MAX_MSG];
        size_t frame_length = 0u;
        size_t accepted_length = 0u;

        (void)memset(body, 0x5au, sizeof(body));
        CHECK(ninlil_mfdt_v1_ncl1_encode(
                  NINLIL_MFDT_V1_MSG_OPEN,
                  7u,
                  1u,
                  UINT64_C(0x1111222233334444),
                  body,
                  sizeof(body),
                  frame,
                  sizeof(frame),
                  &frame_length)
            == NINLIL_MFDT_V1_OK);
        (void)memset(&sender_config, 0, sizeof(sender_config));
        sender_config.bearer = ops->bearer;
        sender_config.clock = ops->clock;
        sender_config.tx_gate = ops->tx_gate;
        sender_config.role = config_a.role;
        carrier_party(&config_a, 0xb1u, &sender_config.source);
        carrier_target(&config_b, 0xc1u, &sender_config.target);
        sender_config.session = &session_a;
        sender_config.deadline_window_ms =
            NINLIL_MFDT_V1_CARRIER_DEADLINE_MS_DEFAULT;
        (void)memset(&receiver_config, 0, sizeof(receiver_config));
        receiver_config.bearer = ops->bearer;
        receiver_config.clock = ops->clock;
        receiver_config.tx_gate = ops->tx_gate;
        receiver_config.role = config_b.role;
        carrier_party(&config_b, 0xc1u, &receiver_config.source);
        carrier_target(&config_a, 0xb1u, &receiver_config.target);
        receiver_config.session = &session_b;
        receiver_config.deadline_window_ms =
            NINLIL_MFDT_V1_CARRIER_DEADLINE_MS_DEFAULT;
        CHECK(ninlil_mfdt_v1_foundation_carrier_init(
                  &sender_carrier, &sender_config)
            == NINLIL_MFDT_V1_OK);
        CHECK(ninlil_mfdt_v1_foundation_carrier_init(
                  &receiver_carrier, &receiver_config)
            == NINLIL_MFDT_V1_OK);
        CHECK(ninlil_mfdt_v1_foundation_carrier_build_message(
                  &sender_carrier,
                  frame,
                  frame_length,
                  &now,
                  &canonical)
            == NINLIL_MFDT_V1_OK);
        CHECK(ninlil_mfdt_v1_foundation_carrier_accept_message(
                  &receiver_carrier,
                  &canonical,
                  accepted,
                  sizeof(accepted),
                  &accepted_length)
            == NINLIL_MFDT_V1_OK);
        CHECK(accepted_length == frame_length);

        mutated = canonical;
        mutated.flags = 1u;
        CHECK(ninlil_mfdt_v1_foundation_carrier_accept_message(
                  &receiver_carrier, &mutated, accepted, sizeof(accepted),
                  &accepted_length)
            == NINLIL_MFDT_V1_ERR_CORRUPT);
        CHECK(accepted_length == 0u);
        mutated = canonical;
        mutated.event_id.bytes[0] = 1u;
        CHECK(ninlil_mfdt_v1_foundation_carrier_accept_message(
                  &receiver_carrier, &mutated, accepted, sizeof(accepted),
                  &accepted_length)
            == NINLIL_MFDT_V1_ERR_CORRUPT);
        mutated = canonical;
        mutated.required_evidence = NINLIL_EVIDENCE_APPLIED;
        CHECK(ninlil_mfdt_v1_foundation_carrier_accept_message(
                  &receiver_carrier, &mutated, accepted, sizeof(accepted),
                  &accepted_length)
            == NINLIL_MFDT_V1_ERR_CORRUPT);
        mutated = canonical;
        mutated.evidence_time.abi_version = NINLIL_ABI_VERSION;
        CHECK(ninlil_mfdt_v1_foundation_carrier_accept_message(
                  &receiver_carrier, &mutated, accepted, sizeof(accepted),
                  &accepted_length)
            == NINLIL_MFDT_V1_ERR_CORRUPT);
        mutated = canonical;
        mutated.target.device_id.bytes[0] ^= 0x01u;
        CHECK(ninlil_mfdt_v1_foundation_carrier_accept_message(
                  &receiver_carrier, &mutated, accepted, sizeof(accepted),
                  &accepted_length)
            == NINLIL_MFDT_V1_ERR_CORRUPT);
        mutated = canonical;
        mutated.target.reserved_zero = 1u;
        CHECK(ninlil_mfdt_v1_foundation_carrier_accept_message(
                  &receiver_carrier, &mutated, accepted, sizeof(accepted),
                  &accepted_length)
            == NINLIL_MFDT_V1_ERR_CORRUPT);
    }
    make_malformed_carrier(
        &malformed_carrier, &config_a, &config_b, &now);
    CHECK(ninlil_rt_mfdt_v1_runtime_ingress(
              runtime_b,
              &malformed_carrier,
              &now,
              &claimed,
              &durable_transition)
        == NINLIL_OK);
    CHECK(claimed == 1u);
    CHECK(durable_transition == 0u);
    CHECK(snapshot_is(runtime_b, 0u));
    malformed_carrier.service.service_id.bytes[0] ^= 0x01u;
    claimed = UINT32_MAX;
    durable_transition = UINT32_MAX;
    CHECK(ninlil_rt_mfdt_v1_runtime_ingress(
              runtime_b,
              &malformed_carrier,
              &now,
              &claimed,
              &durable_transition)
        == NINLIL_OK);
    CHECK(claimed == 0u);
    CHECK(durable_transition == 0u);
    payload_4k = (uint8_t *)malloc(4096u);
    payload_32k = (uint8_t *)malloc(32768u);
    CHECK(payload_4k != NULL && payload_32k != NULL);
    for (index = 0u; index < 4096u; ++index) {
        payload_4k[index] =
            (uint8_t)((index * UINT32_C(17) + UINT32_C(3)) & 0xffu);
    }
    for (index = 0u; index < 32768u; ++index) {
        payload_32k[index] =
            (uint8_t)((index * UINT32_C(29) + UINT32_C(7)) & 0xffu);
    }

    /* Carrier-invalid applications must fail before any durable admission. */
    {
        ninlil_bearer_message_t invalid;
        uint8_t invalid_transfer_ids[3][16];

        make_application(
            &invalid,
            &config_a,
            &now,
            payload_4k,
            4096u,
            0x1au,
            0x50u);
        derive_test_transfer_id(&invalid, 0u, invalid_transfer_ids[0]);
        (void)memset(
            invalid.source.application_instance_id.bytes, 0, 16u);
        CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
                  runtime_a, &invalid, payload_4k, 4096u, 0u,
                  invalid_transfer_ids[0], &slot)
            == NINLIL_MFDT_V1_ERR_PARAM);
        make_application(
            &invalid,
            &config_a,
            &now,
            payload_4k,
            4096u,
            0x1bu,
            0x50u);
        derive_test_transfer_id(&invalid, 0u, invalid_transfer_ids[1]);
        invalid.target.flags = UINT32_C(0x80000000);
        CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
                  runtime_a, &invalid, payload_4k, 4096u, 0u,
                  invalid_transfer_ids[1], &slot)
            == NINLIL_MFDT_V1_ERR_PARAM);
        make_application(
            &invalid,
            &config_a,
            &now,
            payload_4k,
            4096u,
            0x1cu,
            0x50u);
        derive_test_transfer_id(&invalid, 0u, invalid_transfer_ids[2]);
        invalid.source.local_identity.struct_size = 0u;
        CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
                  runtime_a, &invalid, payload_4k, 4096u, 0u,
                  invalid_transfer_ids[2], &slot)
            == NINLIL_MFDT_V1_ERR_PARAM);
        CHECK(snapshot_is(runtime_a, 0u));
        CHECK(ninlil_runtime_destroy(runtime_a) == NINLIL_OK);
        runtime_a = NULL;
        for (index = 0u; index < 3u; ++index) {
            CHECK(durable_transfer_rows_absent(
                ops->storage,
                k_namespace_a,
                (uint32_t)(sizeof(k_namespace_a) - 1u),
                invalid_transfer_ids[index]));
        }
        CHECK(ninlil_runtime_create(&config_a, ops, &runtime_a) == NINLIL_OK);
        CHECK(enable_owner(runtime_a, UINT64_C(0x1111222233334444))
            == NINLIL_OK);
        CHECK(bind_owner_session(
            runtime_a,
            &config_a.runtime_id,
            &config_b.runtime_id,
            UINT64_C(0x1111222233334444),
            &session_a));
        CHECK(snapshot_is(runtime_a, 0u));
    }

    /*
     * A long EventFact crosses Runtime-owner -> OPEN without deadline
     * normalization. Because this private direct-open path has no Foundation
     * transaction, cold reconciliation classifies its fresh arm as an orphan
     * and compare-erases it before the owner becomes ready.
     */
    {
        uint8_t pre_ready_transfer_id[16];
        uint8_t active_key[20];
        uint8_t sidecar[36];
        uint8_t *active_value = NULL;
        const uint8_t *open_view = NULL;
        const uint8_t *content_view = NULL;
        uint16_t open_view_length = 0u;
        uint32_t content_view_length = 0u;
        uint32_t active_value_length = 0u;

        make_application(
            &application,
            &config_a,
            &now,
            payload_4k,
            4096u,
            0x1du,
            0x50u);
        set_id(&application.event_id, 0x2du);
        application.service.family = NINLIL_FAMILY_EVENT_FACT;
        application.generation = 0u;
        (void)memset(
            application.deadline_clock_epoch_id.bytes, 0, 16u);
        application.absolute_effect_deadline_ms = UINT64_MAX;
        application.evidence_grace_ms = 0u;
        derive_test_transfer_id(&application, 0u, pre_ready_transfer_id);
        CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
                  runtime_a,
                  &application,
                  payload_4k,
                  4096u,
                  0u,
                  pre_ready_transfer_id,
                  &slot)
            == NINLIL_MFDT_V1_OK);
        CHECK(snapshot_is(runtime_a, 1u));
        CHECK(ninlil_runtime_destroy(runtime_a) == NINLIL_OK);
        runtime_a = NULL;
        active_value = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
        CHECK(active_value != NULL);
        derive_sidecar_namespace(
            k_namespace_a,
            (uint32_t)(sizeof(k_namespace_a) - 1u),
            sidecar);
        (void)memcpy(active_key, "NM3S", 4u);
        (void)memcpy(active_key + 4u, pre_ready_transfer_id, 16u);
        CHECK(read_row(
            ops->storage,
            sidecar,
            sizeof(sidecar),
            active_key,
            sizeof(active_key),
            active_value,
            NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
            &active_value_length,
            NINLIL_STORAGE_OK));
        CHECK(ninlil_mfdt_v1_record_unpack(
                  active_value,
                  active_value_length,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  &open_view,
                  &open_view_length,
                  NULL,
                  NULL,
                  &content_view,
                  &content_view_length,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL,
                  NULL)
            == NINLIL_MFDT_V1_OK);
        CHECK(open_view_length >= NINLIL_MFDT_V1_OPEN_BODY_MIN);
        CHECK(memcmp(
                  open_view + 64u, application.transaction_id.bytes, 16u)
            == 0);
        CHECK(memcmp(open_view + 80u, application.event_id.bytes, 16u) == 0);
        CHECK(memcmp(
                  open_view + 96u, application.source.runtime_id.bytes, 16u)
            == 0);
        CHECK(memcmp(
                  open_view + 112u,
                  application.target.target_runtime_id.bytes,
                  16u)
            == 0);
        CHECK(memcmp(
                  open_view + 178u,
                  application.deadline_clock_epoch_id.bytes,
                  16u)
            == 0);
        CHECK(ninlil_mfdt_v1_get_u64(open_view + 194u)
            == application.absolute_effect_deadline_ms);
        CHECK(memcmp(open_view + 234u, application.attempt_id.bytes, 16u)
            == 0);
        CHECK(ninlil_mfdt_v1_get_u32(open_view + 250u) == 0u);
        CHECK(ninlil_mfdt_v1_get_u32(open_view + 434u)
            == NINLIL_FAMILY_EVENT_FACT);
        CHECK(ninlil_mfdt_v1_get_u64(open_view + 438u)
            == application.generation);
        CHECK(ninlil_mfdt_v1_get_u64(open_view + 446u)
            == application.evidence_grace_ms);
        CHECK(content_view_length == 4096u);
        CHECK(memcmp(content_view, payload_4k, 4096u) == 0);
        free(active_value);
        active_value = NULL;
        CHECK(ninlil_runtime_create(&config_a, ops, &runtime_a) == NINLIL_OK);
        CHECK(enable_owner(runtime_a, UINT64_C(0x1111222233334444))
            == NINLIL_OK);
        CHECK(bind_owner_session(
            runtime_a,
            &config_a.runtime_id,
            &config_b.runtime_id,
            UINT64_C(0x1111222233334444),
            &session_a));
        CHECK(snapshot_is(runtime_a, 0u));
        CHECK(ninlil_runtime_destroy(runtime_a) == NINLIL_OK);
        runtime_a = NULL;
        CHECK(durable_transfer_rows_absent(
            ops->storage,
            k_namespace_a,
            (uint32_t)(sizeof(k_namespace_a) - 1u),
            pre_ready_transfer_id));
        CHECK(ninlil_runtime_create(&config_a, ops, &runtime_a) == NINLIL_OK);
        CHECK(enable_owner(runtime_a, UINT64_C(0x1111222233334444))
            == NINLIL_OK);
        CHECK(bind_owner_session(
            runtime_a,
            &config_a.runtime_id,
            &config_b.runtime_id,
            UINT64_C(0x1111222233334444),
            &session_a));
        CHECK(snapshot_is(runtime_a, 0u));
        CHECK(ops->clock->now(ops->clock->user, &now) == NINLIL_PORT_OK);
    }

    make_application(
        &application,
        &config_a,
        &now,
        payload_4k,
        4096u,
        0x21u,
        0x50u);
    application.service.family = NINLIL_FAMILY_DESIRED_STATE;
    derive_test_transfer_id(&application, 0u, expected_transfer_id);
    ninlil_rt_mfdt_v1_runtime_derive_transfer_id(
        &application, 0u, transfer_id);
    CHECK(memcmp(transfer_id, expected_transfer_id, 16u) == 0);
    CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
              runtime_a,
              &application,
              payload_4k,
              4096u,
              0u,
              transfer_id,
              &slot)
        == NINLIL_MFDT_V1_OK);
    CHECK(slot < 4u);
    CHECK(memcmp(transfer_id, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16u)
        != 0);
    (void)memcpy(completed_transfer_id, transfer_id, 16u);
    CHECK(snapshot_is(runtime_a, 1u));
    CHECK(snapshot_is(runtime_b, 0u));

    /*
     * Ordinary runtime_step owns both directions: A emits its pending OPEN,
     * B preserves it when ingress budget is zero, then durably holds OPEN and
     * queues OPEN_ACCEPT. The response is emitted only by B's next step.
     */
    {
        ninlil_step_budget_t budget;
        ninlil_step_result_t step_result;

        (void)memset(&budget, 0, sizeof(budget));
        set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
        budget.max_state_transitions = 2u;
        budget.max_bearer_sends = 1u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_a, &budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.bearer_sends == 1u);
        CHECK(step_result.ingress_processed == 0u);

        budget.max_bearer_sends = 0u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.ingress_processed == 0u);
        CHECK(snapshot_is(runtime_b, 0u));

        budget.max_ingress_messages = 1u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.ingress_processed == 1u);
        CHECK(step_result.state_transitions == 1u);
        CHECK(step_result.bearer_sends == 0u);
        CHECK(snapshot_is(runtime_a, 1u));
        CHECK(snapshot_is(runtime_b, 1u));

        budget.max_ingress_messages = 0u;
        budget.max_bearer_sends = 1u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.ingress_processed == 0u);
        CHECK(step_result.bearer_sends == 1u);
        CHECK(snapshot_is(runtime_b, 1u));
    }

    /* Drive only ordinary runtime_step until the receiver owns publication. */
    {
        ninlil_step_budget_t budget;
        ninlil_step_result_t step_result;
        const uint8_t *published = NULL;
        uint32_t published_length = 0u;
        uint8_t publication_token[16];
        uint8_t expected_digest[32];
        uint8_t published_digest[32];
        uint64_t acceptance_generation = 0u;
        ninlil_status_t publication_status = NINLIL_E_WOULD_BLOCK;

        (void)memset(&budget, 0, sizeof(budget));
        set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
        budget.max_ingress_messages = 1u;
        budget.max_state_transitions = 8u;
        budget.max_bearer_sends = 1u;
        for (index = 0u; index < 128u; ++index) {
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            CHECK(ninlil_runtime_step(runtime_a, &budget, &step_result)
                == NINLIL_OK);
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            CHECK(ninlil_runtime_step(runtime_b, &budget, &step_result)
                == NINLIL_OK);
            publication_status =
                ninlil_rt_mfdt_v1_runtime_receiver_publication_view(
                    runtime_b,
                    completed_transfer_id,
                    &published,
                    &published_length,
                    publication_token,
                    &acceptance_generation);
            if (publication_status == NINLIL_OK
                && snapshot_is(runtime_a, 0u)) {
                break;
            }
            CHECK(publication_status == NINLIL_OK
                || publication_status == NINLIL_E_WOULD_BLOCK
                || publication_status == NINLIL_E_NOT_FOUND);
        }
        CHECK(publication_status == NINLIL_OK);
        CHECK(published != NULL);
        CHECK(published_length == 4096u);
        CHECK(acceptance_generation != 0u);
        CHECK(bytes_nonzero(publication_token, sizeof(publication_token)));
        CHECK(memcmp(published, payload_4k, 4096u) == 0);
        ninlil_mfdt_v1_sha256(payload_4k, 4096u, expected_digest);
        ninlil_mfdt_v1_sha256(published, published_length, published_digest);
        CHECK(memcmp(expected_digest, published_digest, 32u) == 0);
        CHECK(snapshot_is(runtime_a, 0u));
        CHECK(snapshot_is(runtime_b, 1u));
    }

    /* READY without handoff is invalidated and unpublished on epoch change. */
    {
        ninlil_step_budget_t budget;
        ninlil_step_result_t step_result;
        ninlil_time_sample_t next_epoch;
        ninlil_service_t *receiver_service = NULL;
        ninlil_test_bearer_t *bearer =
            ninlil_posix_lab_platform_test_bearer(platform);
        const uint8_t *published = NULL;
        uint8_t publication_token[16];
        uint8_t terminal_key[20];
        uint8_t terminal_value[NINLIL_MFDT_V1_NM30_BYTES];
        uint8_t sidecar[36];
        uint32_t published_length = 0u;
        uint32_t terminal_length = 0u;
        uint64_t acceptance_generation = 0u;

        g_application_callback_calls = 0u;
        CHECK(register_application_receiver(
                  runtime_b, &application, &receiver_service)
            == NINLIL_OK);
        CHECK(receiver_service != NULL);
        CHECK(foundation_transaction_is_absent(
            runtime_b, &application.transaction_id));
        CHECK(g_application_callback_calls == 0u);

        (void)memset(&next_epoch, 0, sizeof(next_epoch));
        set_header(
            &next_epoch.abi_version,
            &next_epoch.struct_size,
            sizeof(next_epoch));
        set_id(&next_epoch.clock_epoch_id, 0xe0u);
        next_epoch.now_ms = 3u;
        next_epoch.trust = NINLIL_CLOCK_TRUSTED;
        CHECK(ninlil_test_clock_recover(
            (ninlil_test_clock_t *)ops->clock->user, &next_epoch));
        CHECK(ninlil_test_bearer_set_time(
            bearer, next_epoch.clock_epoch_id, next_epoch.now_ms));
        (void)memset(&budget, 0, sizeof(budget));
        set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
        budget.max_state_transitions = 2u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &budget, &step_result)
            == NINLIL_OK);
        CHECK(foundation_transaction_is_absent(
            runtime_b, &application.transaction_id));
        CHECK(g_application_callback_calls == 0u);
        CHECK(snapshot_is(runtime_b, 0u));
        CHECK(ninlil_rt_mfdt_v1_runtime_receiver_publication_view(
                  runtime_b,
                  completed_transfer_id,
                  &published,
                  &published_length,
                  publication_token,
                  &acceptance_generation)
            == NINLIL_E_NOT_FOUND);
        CHECK(published == NULL && published_length == 0u);
        CHECK(ninlil_runtime_destroy(runtime_b) == NINLIL_OK);
        runtime_b = NULL;

        (void)memcpy(terminal_key, "NM30", 4u);
        (void)memcpy(terminal_key + 4u, completed_transfer_id, 16u);
        derive_sidecar_namespace(
            k_namespace_b,
            (uint32_t)(sizeof(k_namespace_b) - 1u),
            sidecar);
        CHECK(read_row(
            ops->storage,
            sidecar,
            sizeof(sidecar),
            terminal_key,
            sizeof(terminal_key),
            terminal_value,
            sizeof(terminal_value),
            &terminal_length,
            NINLIL_STORAGE_OK));
        CHECK(terminal_length == sizeof(terminal_value));
        CHECK(ninlil_mfdt_v1_get_u16(terminal_value + 60u)
            == NINLIL_MFDT_V1_TERM_CORRUPT_FENCED);
        CHECK(ninlil_mfdt_v1_get_u16(terminal_value + 62u)
            == NINLIL_MFDT_V1_TERM_REASON_EPOCH);
        CHECK(ninlil_runtime_create(&config_b, ops, &runtime_b) == NINLIL_OK);
        CHECK(enable_owner(runtime_b, UINT64_C(0x1111222233334444))
            == NINLIL_OK);
        CHECK(bind_owner_session(
            runtime_b,
            &config_b.runtime_id,
            &config_a.runtime_id,
            UINT64_C(0x1111222233334444),
            &session_b));
        CHECK(snapshot_is(runtime_b, 0u));

        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_a, &budget, &step_result)
            == NINLIL_OK);
        CHECK(snapshot_is(runtime_a, 0u));
        CHECK(ops->clock->now(ops->clock->user, &now) == NINLIL_PORT_OK);
    }

    for (index = 0u; index < 4u; ++index) {
        make_application(
            &application,
            &config_a,
            &now,
            payload_4k,
            4096u,
            (uint8_t)(0x31u + index * 3u),
            0x50u);
        derive_test_transfer_id(&application, index, transfer_id);
        CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
                  runtime_a,
                  &application,
                  payload_4k,
                  4096u,
                  index,
                  transfer_id,
                  &slot)
            == NINLIL_MFDT_V1_OK);
        CHECK(slot < 4u);
    }
    CHECK(snapshot_is(runtime_a, 4u));

    make_application(
        &application,
        &config_a,
        &now,
        payload_4k,
        4096u,
        0x40u,
        0x50u);
    derive_test_transfer_id(&application, 0u, transfer_id);
    CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
              runtime_a,
              &application,
              payload_4k,
              4096u,
              0u,
              transfer_id,
              &slot)
        == NINLIL_MFDT_V1_ERR_CAPACITY);
    CHECK(snapshot_is(runtime_a, 4u));

    make_application(
        &application,
        &config_b,
        &now,
        payload_32k,
        32768u,
        0x61u,
        0x10u);
    derive_test_transfer_id(&application, 0u, transfer_id);
    CHECK(ninlil_rt_mfdt_v1_runtime_sender_open(
              runtime_b,
              &application,
              payload_32k,
              32768u,
              0u,
              transfer_id,
              &slot)
        == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_is(runtime_a, 4u));
    CHECK(snapshot_is(runtime_b, 1u));

    {
        ninlil_step_budget_t budget;
        ninlil_step_result_t step_result;
        ninlil_status_t step_status;

        (void)memset(&budget, 0, sizeof(budget));
        set_header(&budget.abi_version, &budget.struct_size, sizeof(budget));
        budget.max_ingress_messages = 1u;
        budget.max_callbacks = 1u;
        budget.max_state_transitions = 2u;
        budget.max_bearer_sends = 0u;
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        step_status = ninlil_runtime_step(runtime_a, &budget, &step_result);
        CHECK(step_status == NINLIL_OK);
        CHECK(step_result.more_work == 1u);
        CHECK(step_result.bearer_sends == 0u);
    }

    /*
     * Fill B's remaining receiver slots, then block one pending route. The
     * next maintenance step must send a different eligible route while the
     * blocked frame remains Host-owned; its later retry must be byte-stable.
     * A subsequent control response whose LOST_UNKNOWN is fenced is never
     * retried.
     */
    {
        ninlil_test_bearer_t *bearer =
            ninlil_posix_lab_platform_test_bearer(platform);
        ninlil_bearer_send_result_t raw_send_result;
        ninlil_step_budget_t send_budget;
        ninlil_step_budget_t receive_budget;
        ninlil_step_result_t step_result;
        const ninlil_test_bearer_trace_record_t *first_send = NULL;
        const ninlil_test_bearer_trace_record_t *second_send = NULL;
        const ninlil_test_bearer_trace_record_t *retry_send = NULL;
        size_t trace_index;
        size_t trace_start;

        CHECK(bearer != NULL);
        (void)memset(&send_budget, 0, sizeof(send_budget));
        set_header(
            &send_budget.abi_version,
            &send_budget.struct_size,
            sizeof(send_budget));
        send_budget.max_state_transitions = 2u;
        send_budget.max_bearer_sends = 1u;
        (void)memset(&receive_budget, 0, sizeof(receive_budget));
        set_header(
            &receive_budget.abi_version,
            &receive_budget.struct_size,
            sizeof(receive_budget));
        receive_budget.max_ingress_messages = 1u;
        receive_budget.max_state_transitions = 2u;

        for (index = 0u; index < 3u; ++index) {
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            CHECK(ninlil_runtime_step(
                      runtime_a, &send_budget, &step_result)
                == NINLIL_OK);
            CHECK(step_result.bearer_sends == 1u);
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            CHECK(ninlil_runtime_step(
                      runtime_b, &receive_budget, &step_result)
                == NINLIL_OK);
            CHECK(step_result.ingress_processed == 1u);
        }
        CHECK(snapshot_is(runtime_b, 4u));

        (void)memset(&raw_send_result, 0, sizeof(raw_send_result));
        set_header(
            &raw_send_result.abi_version,
            &raw_send_result.struct_size,
            sizeof(raw_send_result));
        trace_start = ninlil_test_bearer_trace_count(bearer);
        CHECK(ninlil_test_bearer_raw_send_enqueue(
            bearer,
            NINLIL_BEARER_WOULD_BLOCK,
            &raw_send_result,
            1u));
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &send_budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.bearer_sends == 1u);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &send_budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.bearer_sends == 1u);
        for (trace_index = trace_start;
             trace_index < ninlil_test_bearer_trace_count(bearer);
             ++trace_index) {
            const ninlil_test_bearer_trace_record_t *trace =
                ninlil_test_bearer_trace_at(bearer, trace_index);
            if (trace != NULL
                && trace->operation == NINLIL_TEST_BEARER_OP_SEND) {
                if (first_send == NULL) {
                    first_send = trace;
                } else if (second_send == NULL) {
                    second_send = trace;
                }
            }
        }
        CHECK(first_send != NULL && second_send != NULL);
        CHECK(first_send->bearer_status == NINLIL_BEARER_WOULD_BLOCK);
        CHECK(second_send->bearer_status == NINLIL_BEARER_OK);
        CHECK(memcmp(
            first_send->transaction_id.bytes,
            second_send->transaction_id.bytes,
            16u) != 0);
        CHECK(memcmp(
            first_send->attempt_id.bytes,
            second_send->attempt_id.bytes,
            16u) != 0);
        for (index = 0u; index < 8u && retry_send == NULL; ++index) {
            const size_t retry_start =
                ninlil_test_bearer_trace_count(bearer);
            (void)memset(&step_result, 0, sizeof(step_result));
            set_header(
                &step_result.abi_version,
                &step_result.struct_size,
                sizeof(step_result));
            CHECK(ninlil_runtime_step(runtime_b, &send_budget, &step_result)
                == NINLIL_OK);
            for (trace_index = retry_start;
                 trace_index < ninlil_test_bearer_trace_count(bearer);
                 ++trace_index) {
                const ninlil_test_bearer_trace_record_t *trace =
                    ninlil_test_bearer_trace_at(bearer, trace_index);
                if (trace != NULL
                    && trace->operation == NINLIL_TEST_BEARER_OP_SEND
                    && memcmp(
                           trace->transaction_id.bytes,
                           first_send->transaction_id.bytes,
                           16u) == 0) {
                    retry_send = trace;
                    break;
                }
            }
        }
        CHECK(retry_send != NULL);
        CHECK(retry_send->bearer_status == NINLIL_BEARER_OK);
        CHECK(memcmp(
            first_send->attempt_id.bytes,
            retry_send->attempt_id.bytes,
            16u) == 0);

        /* A fourth OPEN proves successful control ownership was released. */
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_a, &send_budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.bearer_sends == 1u);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &receive_budget, &step_result)
            == NINLIL_OK);
        CHECK(step_result.ingress_processed == 1u);
        CHECK(ninlil_test_bearer_raw_send_enqueue(
            bearer,
            NINLIL_BEARER_LOST_UNKNOWN,
            &raw_send_result,
            1u));
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &send_budget, &step_result)
            == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        CHECK(step_result.bearer_sends == 1u);
        (void)memset(&step_result, 0, sizeof(step_result));
        set_header(
            &step_result.abi_version,
            &step_result.struct_size,
            sizeof(step_result));
        CHECK(ninlil_runtime_step(runtime_b, &send_budget, &step_result)
            == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
        CHECK(step_result.bearer_sends == 0u);
    }

    /*
     * These four private direct-open rows have no Foundation transactions;
     * cold reconciliation removes the bounded set before readiness.
     */
    CHECK(ninlil_runtime_destroy(runtime_a) == NINLIL_OK);
    runtime_a = NULL;
    CHECK(binding_is_exact(
        ops->storage,
        k_namespace_a,
        (uint32_t)(sizeof(k_namespace_a) - 1u)));
    CHECK(base_has_no_binding(
        ops->storage,
        k_namespace_a,
        (uint32_t)(sizeof(k_namespace_a) - 1u)));
    CHECK(ninlil_runtime_create(&config_a, ops, &runtime_a) == NINLIL_OK);
    CHECK(enable_owner(runtime_a, UINT64_C(0x1111222233334444))
        == NINLIL_OK);
    CHECK(snapshot_is(runtime_a, 0u));
    CHECK(ninlil_runtime_destroy(runtime_b)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    runtime_b = NULL;

    /*
     * Simulated derived-namespace collision: an exact NMS1 for a different
     * base must be rejected without overwriting the pre-existing bytes.
     */
    CHECK(ninlil_runtime_create(&config_c, ops, &runtime_c) == NINLIL_OK);
    derive_sidecar_namespace(
        k_namespace_c,
        (uint32_t)(sizeof(k_namespace_c) - 1u),
        sidecar_c);
    wrong_binding_length = build_binding(
        k_namespace_wrong,
        (uint32_t)(sizeof(k_namespace_wrong) - 1u),
        wrong_binding);
    CHECK(write_row(
        ops->storage,
        sidecar_c,
        sizeof(sidecar_c),
        k_binding_key,
        sizeof(k_binding_key),
        wrong_binding,
        wrong_binding_length));
    CHECK(enable_owner(runtime_c, UINT64_C(0x9999aaaabbbbcccc))
        == NINLIL_E_STORAGE_CORRUPT);
    CHECK(read_row(
        ops->storage,
        sidecar_c,
        sizeof(sidecar_c),
        k_binding_key,
        sizeof(k_binding_key),
        observed_binding,
        sizeof(observed_binding),
        &observed_binding_length,
        NINLIL_STORAGE_OK));
    CHECK(observed_binding_length == wrong_binding_length);
    CHECK(memcmp(
        observed_binding,
        wrong_binding,
        wrong_binding_length) == 0);
    CHECK(ninlil_runtime_destroy(runtime_c)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    runtime_c = NULL;
    CHECK(base_has_no_binding(
        ops->storage,
        k_namespace_c,
        (uint32_t)(sizeof(k_namespace_c) - 1u)));

    result = 0;
    (void)printf("mfdt_v1_runtime_owner_test: PASS\n");

    free(payload_32k);
    free(payload_4k);
    if (runtime_b != NULL) {
        (void)ninlil_runtime_destroy(runtime_b);
    }
    if (runtime_c != NULL) {
        (void)ninlil_runtime_destroy(runtime_c);
    }
    if (runtime_a != NULL) {
        (void)ninlil_runtime_destroy(runtime_a);
    }
    ninlil_posix_lab_platform_destroy(platform);
    return result;
}
