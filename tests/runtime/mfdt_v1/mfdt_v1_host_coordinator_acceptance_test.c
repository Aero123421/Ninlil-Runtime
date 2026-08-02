/* SPDX-License-Identifier: Apache-2.0
 *
 * Independent behavioral acceptance for the private ADR-0021 Host
 * coordinator.  This is software evidence only: it is not physical HIL,
 * SPEC_ACCEPTED, release-supported, or public ABI evidence.
 */
#include "mfdt_v1_host_coordinator.h"
#include "mfdt_v1_host_store.h"
#include "mfdt_v1_ncl1.h"
#include "mfdt_v1_target_alloc.h"
#include "mfdt_v1_typed_mutation_provider.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

typedef struct host_fixture {
    ninlil_mfdt_v1_host_store_t *store;
    ninlil_mfdt_v1_store_port_t port;
    ninlil_mfdt_v1_host_owner_t *owner;
    ninlil_mfdt_v1_config_t config;
    uint8_t port_open;
} host_fixture_t;

typedef struct decoded_frame {
    uint8_t bytes[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t length;
    ninlil_mfdt_v1_wire_view_t wire;
    uint32_t session_generation;
    uint64_t session_cookie;
} decoded_frame_t;

static const uint8_t k_namespace[] = "acceptance.host";
static const uint8_t k_service[] = "binary-transfer.v1";
static const uint8_t k_schema[] = "application-data.v1";

static void make_tid(uint8_t transfer_id[16], uint8_t tag)
{
    (void)memset(transfer_id, 0, 16u);
    transfer_id[15] = tag;
}

static void make_endpoint(uint8_t endpoint[16], uint8_t tag)
{
    size_t index;

    for (index = 0u; index < 16u; ++index) {
        endpoint[index] = (uint8_t)(tag + (uint8_t)(index * 3u));
    }
}

static void make_config(ninlil_mfdt_v1_config_t *config)
{
    (void)memset(config, 0, sizeof(*config));
    config->policy = NINLIL_MFDT_V1_POLICY_ON;
    config->mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    config->host_mode = 1u;
    config->session_generation = 1u;
    config->mfdt_capability = 1u;
    config->retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    config->now_ms = 1000ull;
    (void)memset(config->local_clock_epoch.bytes, 0xc0, 16u);
}

static void make_bind(
    ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t peer_tag,
    uint8_t role,
    uint64_t cookie)
{
    (void)memset(bind, 0, sizeof(*bind));
    make_endpoint(bind->peer_endpoint_id, peer_tag);
    bind->session_generation = 1u;
    bind->session_cookie = cookie;
    bind->role = role;
}

static void make_metadata(
    ninlil_mfdt_v1_open_metadata_t *metadata,
    const ninlil_mfdt_v1_config_t *config,
    const uint8_t source_runtime_id[16],
    const uint8_t target_runtime_id[16],
    uint8_t tag)
{
    size_t index;

    (void)memset(metadata, 0, sizeof(*metadata));
    for (index = 0u; index < 16u; ++index) {
        metadata->origin_transaction_id[index] =
            (uint8_t)(tag + (uint8_t)index);
        metadata->original_attempt_id[index] =
            (uint8_t)(0x30u + tag + (uint8_t)index);
        metadata->source_application_instance_id[index] =
            (uint8_t)(0x50u + tag + (uint8_t)index);
        metadata->target_application_instance_id[index] =
            (uint8_t)(0x70u + tag + (uint8_t)index);
    }
    (void)memcpy(
        metadata->source_runtime_id,
        source_runtime_id,
        16u);
    (void)memcpy(
        metadata->target_runtime_id,
        target_runtime_id,
        16u);
    metadata->service_descriptor_revision = (uint64_t)tag + 1ull;
    ninlil_mfdt_v1_sha256(
        k_service,
        sizeof(k_service) - 1u,
        metadata->service_descriptor_digest);
    metadata->namespace_bytes = k_namespace;
    metadata->namespace_length =
        (uint16_t)(sizeof(k_namespace) - 1u);
    metadata->service_bytes = k_service;
    metadata->service_length =
        (uint16_t)(sizeof(k_service) - 1u);
    metadata->schema_bytes = k_schema;
    metadata->schema_length =
        (uint16_t)(sizeof(k_schema) - 1u);
    (void)memcpy(
        metadata->deadline_clock_epoch_id,
        config->local_clock_epoch.bytes,
        16u);
    metadata->absolute_effect_deadline_ms =
        config->now_ms + 600000ull;
    metadata->service_schema_major = 1u;
    metadata->service_family = 2u;
    metadata->application_generation = (uint64_t)tag + 1ull;
    metadata->required_evidence = 1u;
}

static int host_fixture_prepare(host_fixture_t *fixture, int start)
{
    int rc;

    if (fixture == NULL) {
        return 0;
    }
    (void)memset(fixture, 0, sizeof(*fixture));
    make_config(&fixture->config);
    fixture->store = ninlil_mfdt_v1_host_store_create();
    fixture->owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*fixture->owner));
    if (fixture->store == NULL || fixture->owner == NULL) {
        return 0;
    }
    rc = ninlil_mfdt_v1_host_store_open_port(
        fixture->store,
        &fixture->port);
    if (rc != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    fixture->port_open = 1u;
    rc = ninlil_mfdt_v1_host_owner_init(
        fixture->owner,
        &fixture->port,
        &fixture->config);
    if (rc != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    rc = ninlil_mfdt_v1_host_owner_recover(fixture->owner);
    if (rc != NINLIL_MFDT_V1_OK) {
        return 0;
    }
    if (start != 0 &&
        ninlil_mfdt_v1_host_owner_start(fixture->owner) !=
            NINLIL_MFDT_V1_OK) {
        return 0;
    }
    return 1;
}

static int host_fixture_prepare_policy_off(host_fixture_t *fixture)
{
    if (!host_fixture_prepare(fixture, 0)) {
        return 0;
    }
    fixture->config.policy = NINLIL_MFDT_V1_POLICY_OFF;
    (void)memset(fixture->owner, 0, sizeof(*fixture->owner));
    if (ninlil_mfdt_v1_host_owner_init(
            fixture->owner,
            &fixture->port,
            &fixture->config) != NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_host_owner_recover(fixture->owner) !=
            NINLIL_MFDT_V1_OK ||
        ninlil_mfdt_v1_host_owner_start(fixture->owner) !=
            NINLIL_MFDT_V1_OK) {
        return 0;
    }
    return 1;
}

static void host_fixture_destroy(host_fixture_t *fixture)
{
    if (fixture == NULL) {
        return;
    }
    if (fixture->port_open != 0u && fixture->store != NULL) {
        ninlil_mfdt_v1_host_store_close_port(
            fixture->store,
            &fixture->port);
    }
    if (fixture->store != NULL) {
        ninlil_mfdt_v1_host_store_destroy(fixture->store);
    }
    free(fixture->owner);
    (void)memset(fixture, 0, sizeof(*fixture));
}

static int snapshot_owner(
    const ninlil_mfdt_v1_host_owner_t *owner,
    ninlil_mfdt_v1_host_header_snapshot_t *header,
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4])
{
    return ninlil_mfdt_v1_host_snapshot(owner, header, slots);
}

static int store_inventory(
    const host_fixture_t *fixture,
    uint32_t *keys,
    uint64_t *bytes,
    uint64_t *generation,
    uint64_t *fulls)
{
    return ninlil_mfdt_v1_host_store_inventory(
        fixture->store,
        keys,
        bytes,
        generation,
        fulls);
}

static int sender_open(
    host_fixture_t *fixture,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t tid_tag,
    const uint8_t *content,
    uint32_t content_len,
    uint64_t request_id,
    uint8_t *slot_out);

static int receiver_open_body(
    host_fixture_t *fixture,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t tid_tag,
    uint64_t request_id,
    uint8_t *slot_out,
    uint8_t *open_out,
    uint16_t *open_len_out,
    ninlil_mfdt_v1_response_t *response);

static int receiver_abort_slot(
    host_fixture_t *fixture,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t slot,
    const uint8_t *open,
    uint64_t request_id);

static int fixture_put_raw_row(
    host_fixture_t *fixture,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES],
    const uint8_t *value,
    uint32_t value_len)
{
    uint32_t keys = 0u;
    uint64_t bytes = 0ull;
    uint64_t generation = 0ull;
    uint64_t fulls = 0ull;
    int rc;

    if (fixture == NULL || key == NULL || value == NULL ||
        value_len == 0u) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    rc = store_inventory(
        fixture,
        &keys,
        &bytes,
        &generation,
        &fulls);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = ninlil_mfdt_v1_store_full_begin(
        &fixture->port,
        keys,
        bytes);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = ninlil_mfdt_v1_store_full_put(
        &fixture->port,
        key,
        value,
        value_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)ninlil_mfdt_v1_store_full_rollback(
            &fixture->port);
        return rc;
    }
    return ninlil_mfdt_v1_store_full_commit(&fixture->port);
}

static int fixture_copy_row(
    const host_fixture_t *source,
    host_fixture_t *target,
    const uint8_t key[NINLIL_MFDT_V1_KEY_BYTES])
{
    uint8_t *value = NULL;
    uint32_t value_len = 0u;
    int present = 0;
    int rc;

    if (source == NULL || target == NULL || key == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    value = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    if (value == NULL) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    rc = ninlil_mfdt_v1_store_read(
        (ninlil_mfdt_v1_store_port_t *)&source->port,
        key,
        value,
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
        &value_len,
        &present);
    if (rc == NINLIL_MFDT_V1_OK && present == 0) {
        rc = NINLIL_MFDT_V1_ERR_STATE;
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = fixture_put_raw_row(
            target,
            key,
            value,
            value_len);
    }
    free(value);
    return rc;
}

static int seed_sender_active_rows(
    host_fixture_t *target,
    uint8_t tid_tag,
    int copy_active,
    int copy_nrc1)
{
    host_fixture_t source;
    ninlil_mfdt_v1_host_bind_t bind;
    uint8_t content[64];
    uint8_t slot = 0xffu;
    uint8_t transfer_id[16];
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    int rc = NINLIL_MFDT_V1_OK;

    if (!host_fixture_prepare(&source, 1)) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    make_bind(
        &bind,
        (uint8_t)(0x40u + tid_tag),
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0x400000ull + tid_tag);
    (void)memset(content, tid_tag, sizeof(content));
    rc = sender_open(
        &source,
        &bind,
        tid_tag,
        content,
        sizeof(content),
        (uint64_t)(100u + tid_tag),
        &slot);
    make_tid(transfer_id, tid_tag);
    if (rc == NINLIL_MFDT_V1_OK && copy_active != 0) {
        (void)memcpy(key, "NM3S", 4u);
        (void)memcpy(key + 4u, transfer_id, 16u);
        rc = fixture_copy_row(&source, target, key);
    }
    if (rc == NINLIL_MFDT_V1_OK && copy_nrc1 != 0) {
        (void)memcpy(key, "NRC1", 4u);
        (void)memcpy(key + 4u, transfer_id, 16u);
        rc = fixture_copy_row(&source, target, key);
    }
    host_fixture_destroy(&source);
    return rc;
}

static int seed_receiver_active_rows(
    host_fixture_t *target,
    uint8_t tid_tag,
    int copy_active,
    int copy_nrc1)
{
    host_fixture_t source;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_response_t response;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    uint8_t slot = 0xffu;
    uint8_t transfer_id[16];
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    int rc = NINLIL_MFDT_V1_OK;

    if (!host_fixture_prepare(&source, 1)) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    make_bind(
        &bind,
        (uint8_t)(0x60u + tid_tag),
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x600000ull + tid_tag);
    rc = receiver_open_body(
        &source,
        &bind,
        tid_tag,
        (uint64_t)(200u + tid_tag),
        &slot,
        open,
        &open_len,
        &response);
    make_tid(transfer_id, tid_tag);
    if (rc == NINLIL_MFDT_V1_OK && copy_active != 0) {
        (void)memcpy(key, "NM3R", 4u);
        (void)memcpy(key + 4u, transfer_id, 16u);
        rc = fixture_copy_row(&source, target, key);
    }
    if (rc == NINLIL_MFDT_V1_OK && copy_nrc1 != 0) {
        (void)memcpy(key, "NRC1", 4u);
        (void)memcpy(key + 4u, transfer_id, 16u);
        rc = fixture_copy_row(&source, target, key);
    }
    host_fixture_destroy(&source);
    return rc;
}

static int seed_terminal_rows(
    host_fixture_t *target,
    uint8_t tid_tag,
    int copy_terminal,
    int copy_nrc1)
{
    host_fixture_t source;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_response_t response;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    uint8_t slot = 0xffu;
    uint8_t discard[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t discard_len = 0u;
    uint8_t transfer_id[16];
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    int rc;

    if (!host_fixture_prepare(&source, 1)) {
        return NINLIL_MFDT_V1_ERR_STORAGE;
    }
    make_bind(
        &bind,
        (uint8_t)(0x70u + tid_tag),
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x700000ull + tid_tag);
    rc = receiver_open_body(
        &source,
        &bind,
        tid_tag,
        (uint64_t)(300u + tid_tag),
        &slot,
        open,
        &open_len,
        &response);
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = ninlil_mfdt_v1_host_take_outbound_ncl1(
            source.owner,
            slot,
            discard,
            sizeof(discard),
            &discard_len);
    }
    if (rc == NINLIL_MFDT_V1_OK) {
        rc = receiver_abort_slot(
            &source,
            &bind,
            slot,
            open,
            (uint64_t)(400u + tid_tag));
    }
    make_tid(transfer_id, tid_tag);
    if (rc == NINLIL_MFDT_V1_OK && copy_terminal != 0) {
        (void)memcpy(key, "NM30", 4u);
        (void)memcpy(key + 4u, transfer_id, 16u);
        rc = fixture_copy_row(&source, target, key);
    }
    if (rc == NINLIL_MFDT_V1_OK && copy_nrc1 != 0) {
        (void)memcpy(key, "NRC1", 4u);
        (void)memcpy(key + 4u, transfer_id, 16u);
        rc = fixture_copy_row(&source, target, key);
    }
    host_fixture_destroy(&source);
    return rc;
}

static int sender_open(
    host_fixture_t *fixture,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t tid_tag,
    const uint8_t *content,
    uint32_t content_len,
    uint64_t request_id,
    uint8_t *slot_out)
{
    ninlil_mfdt_v1_open_metadata_t metadata;
    uint8_t transfer_id[16];
    uint8_t local_runtime[16];

    make_tid(transfer_id, tid_tag);
    make_endpoint(local_runtime, 0xe0u);
    make_metadata(
        &metadata,
        &fixture->config,
        local_runtime,
        bind->peer_endpoint_id,
        tid_tag);
    return ninlil_mfdt_v1_host_sender_open_with_metadata(
        fixture->owner,
        bind,
        transfer_id,
        content,
        content_len,
        &metadata,
        request_id,
        slot_out);
}

static int decode_outbound(
    ninlil_mfdt_v1_host_owner_t *owner,
    uint8_t slot,
    decoded_frame_t *decoded)
{
    uint8_t message_type = 0u;
    uint32_t request_id = 0u;
    const uint8_t *body = NULL;
    uint16_t body_len = 0u;
    int rc;

    if (decoded == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    (void)memset(decoded, 0, sizeof(*decoded));
    rc = ninlil_mfdt_v1_host_take_outbound_ncl1(
        owner,
        slot,
        decoded->bytes,
        sizeof(decoded->bytes),
        &decoded->length);
    if (rc != NINLIL_MFDT_V1_OK || decoded->length == 0u) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_ncl1_decode(
        decoded->bytes,
        decoded->length,
        NINLIL_MFDT_V1_NCG1_DATA,
        &message_type,
        &request_id,
        &decoded->session_generation,
        &decoded->session_cookie,
        &body,
        &body_len);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    decoded->wire.message_type = message_type;
    decoded->wire.request_id = request_id;
    decoded->wire.body = body;
    decoded->wire.body_len = body_len;
    return NINLIL_MFDT_V1_OK;
}

static int route_outbound(
    ninlil_mfdt_v1_host_owner_t *source,
    uint8_t source_slot,
    ninlil_mfdt_v1_host_owner_t *destination,
    const ninlil_mfdt_v1_host_bind_t *destination_bind,
    ninlil_mfdt_v1_response_t *response,
    uint8_t *destination_slot,
    decoded_frame_t *capture)
{
    decoded_frame_t local;
    decoded_frame_t *decoded = capture != NULL ? capture : &local;
    int rc = decode_outbound(source, source_slot, decoded);

    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (decoded->session_generation !=
            destination_bind->session_generation ||
        decoded->session_cookie != destination_bind->session_cookie) {
        return NINLIL_MFDT_V1_ERR_VERSION;
    }
    return ninlil_mfdt_v1_host_on_wire(
        destination,
        destination_bind,
        &decoded->wire,
        response,
        destination_slot);
}

static int build_open_body_with_content_and_deadline(
    const ninlil_mfdt_v1_host_bind_t *receiver_bind,
    uint8_t tid_tag,
    const uint8_t *content,
    uint32_t content_len,
    const uint8_t deadline_epoch[16],
    uint64_t deadline_ms,
    uint8_t *open,
    uint16_t *open_len)
{
    uint8_t transfer_id[16];
    uint8_t target[16];
    ninlil_mfdt_v1_open_metadata_t metadata;
    uint8_t entries[
        NINLIL_MFDT_V1_MAX_CHUNKS *
        NINLIL_MFDT_V1_ENTRY_BYTES];
    uint8_t manifest_digest[32];
    uint8_t whole_digest[32];
    uint16_t entry_bytes = 0u;

    make_tid(transfer_id, tid_tag);
    make_endpoint(target, 0xf0u);
    (void)memset(&metadata, 0, sizeof(metadata));
    (void)memset(metadata.origin_transaction_id, tid_tag, 16u);
    if (deadline_ms == UINT64_MAX) {
        (void)memset(metadata.origin_event_id,
                     (uint8_t)(tid_tag + 1u), 16u);
    }
    (void)memcpy(metadata.source_runtime_id,
                 receiver_bind->peer_endpoint_id, 16u);
    (void)memcpy(metadata.target_runtime_id, target, 16u);
    (void)memset(metadata.original_attempt_id,
                 (uint8_t)(tid_tag + 2u), 16u);
    (void)memset(metadata.source_application_instance_id,
                 (uint8_t)(tid_tag + 3u), 16u);
    (void)memset(metadata.target_application_instance_id,
                 (uint8_t)(tid_tag + 4u), 16u);
    ninlil_mfdt_v1_sha256(
        k_service,
        sizeof(k_service) - 1u,
        metadata.service_descriptor_digest);
    metadata.service_descriptor_revision = 1ull;
    if (deadline_epoch != NULL) {
        (void)memcpy(metadata.deadline_clock_epoch_id, deadline_epoch, 16u);
    }
    metadata.absolute_effect_deadline_ms = deadline_ms;
    metadata.service_schema_major = 1u;
    metadata.service_family = deadline_ms == UINT64_MAX ? 1u : 2u;
    metadata.application_generation = deadline_ms == UINT64_MAX ? 0ull : 1ull;
    metadata.required_evidence = 1u;
    metadata.namespace_bytes = k_namespace;
    metadata.namespace_length = (uint16_t)(sizeof(k_namespace) - 1u);
    metadata.service_bytes = k_service;
    metadata.service_length = (uint16_t)(sizeof(k_service) - 1u);
    metadata.schema_bytes = k_schema;
    metadata.schema_length = (uint16_t)(sizeof(k_schema) - 1u);
    return ninlil_mfdt_v1_encode_open(
        transfer_id, content_len, content, &metadata, open, open_len, entries,
        &entry_bytes, manifest_digest, whole_digest);
}

static int build_open_body_with_deadline(
    const ninlil_mfdt_v1_host_bind_t *receiver_bind,
    uint8_t tid_tag,
    const uint8_t deadline_epoch[16],
    uint64_t deadline_ms,
    uint8_t *open,
    uint16_t *open_len)
{
    const uint8_t content = tid_tag;

    return build_open_body_with_content_and_deadline(
        receiver_bind,
        tid_tag,
        &content,
        1u,
        deadline_epoch,
        deadline_ms,
        open,
        open_len);
}

static int build_open_body(
    const ninlil_mfdt_v1_config_t *config,
    const ninlil_mfdt_v1_host_bind_t *receiver_bind,
    uint8_t tid_tag,
    uint8_t *open,
    uint16_t *open_len)
{
    return build_open_body_with_deadline(
        receiver_bind,
        tid_tag,
        config->local_clock_epoch.bytes,
        config->now_ms + 600000ull,
        open,
        open_len);
}

static int receiver_open_body(
    host_fixture_t *fixture,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t tid_tag,
    uint64_t request_id,
    uint8_t *slot_out,
    uint8_t *open_out,
    uint16_t *open_len_out,
    ninlil_mfdt_v1_response_t *response)
{
    ninlil_mfdt_v1_wire_view_t wire;
    int rc;

    rc = build_open_body(
        &fixture->config,
        bind,
        tid_tag,
        open_out,
        open_len_out);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = request_id;
    wire.body = open_out;
    wire.body_len = *open_len_out;
    return ninlil_mfdt_v1_host_on_wire(
        fixture->owner,
        bind,
        &wire,
        response,
        slot_out);
}

static int receiver_abort_slot(
    host_fixture_t *fixture,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t slot,
    const uint8_t *open,
    uint64_t request_id)
{
    uint8_t abort_body[76];
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t frame_len = 0u;
    ninlil_mfdt_v1_wire_view_t wire;
    ninlil_mfdt_v1_response_t response;
    uint8_t routed_slot = 0xffu;
    int rc;

    (void)memset(abort_body, 0, sizeof(abort_body));
    /*
     * OPEN is not BIND52: its manifest digest is at offset 202.  Every
     * post-OPEN request carries TID || revision || manifest_digest.
     */
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        abort_body);
    ninlil_mfdt_v1_put_u16(
        abort_body + 52u,
        NINLIL_MFDT_V1_TERM_REASON_OPERATOR);
    abort_body[56] = 0xabu;
    ninlil_mfdt_v1_put_u32(abort_body + 72u, 1u);
    wire.message_type = NINLIL_MFDT_V1_MSG_ABORT;
    wire.request_id = request_id;
    wire.body = abort_body;
    wire.body_len = sizeof(abort_body);
    rc = ninlil_mfdt_v1_host_on_wire(
        fixture->owner,
        bind,
        &wire,
        &response,
        &routed_slot);
    if (rc != NINLIL_MFDT_V1_OK || routed_slot != slot ||
        response.message_type != NINLIL_MFDT_V1_MSG_ABORT_ACK) {
        (void)fprintf(
            stderr,
            "abort_slot rc=%d routed=%u expected=%u type=%u reject=%u\n",
            rc,
            (unsigned)routed_slot,
            (unsigned)slot,
            (unsigned)response.message_type,
            (unsigned)response.reject_code);
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = ninlil_mfdt_v1_host_take_outbound_ncl1(
        fixture->owner,
        slot,
        frame,
        sizeof(frame),
        &frame_len);
    if (rc != NINLIL_MFDT_V1_OK || frame_len == 0u) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_STATE;
    }
    return NINLIL_MFDT_V1_OK;
}

static int prepare_one_sender_for_chunks(
    host_fixture_t *sender,
    host_fixture_t *receiver,
    const ninlil_mfdt_v1_host_bind_t *sender_bind,
    const ninlil_mfdt_v1_host_bind_t *receiver_bind,
    uint8_t tid_tag,
    const uint8_t *content,
    uint32_t content_len,
    uint8_t *sender_slot_out,
    uint8_t *receiver_slot_out,
    int duplicate_open_witness)
{
    ninlil_mfdt_v1_response_t response;
    decoded_frame_t open_frame;
    uint8_t sender_slot = 0xffu;
    uint8_t receiver_slot = 0xffu;
    uint8_t discard[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t discard_len = 0u;
    int rc;

    rc = sender_open(
        sender,
        sender_bind,
        tid_tag,
        content,
        content_len,
        (uint64_t)(600u + tid_tag),
        &sender_slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = route_outbound(
        sender->owner,
        sender_slot,
        receiver->owner,
        receiver_bind,
        &response,
        &receiver_slot,
        &open_frame);
    if (rc != NINLIL_MFDT_V1_OK ||
        response.message_type != NINLIL_MFDT_V1_MSG_OPEN_ACCEPT ||
        response.from_nrc1_hit != 0u) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = route_outbound(
        receiver->owner,
        receiver_slot,
        sender->owner,
        sender_bind,
        NULL,
        NULL,
        NULL);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    if (duplicate_open_witness != 0) {
        ninlil_mfdt_v1_response_t replay;
        uint8_t replay_slot = 0xffu;

        rc = ninlil_mfdt_v1_host_on_wire(
            receiver->owner,
            receiver_bind,
            &open_frame.wire,
            &replay,
            &replay_slot);
        if (rc != NINLIL_MFDT_V1_OK ||
            replay_slot != receiver_slot ||
            replay.from_nrc1_hit != 1u ||
            replay.message_type != NINLIL_MFDT_V1_MSG_OPEN_ACCEPT) {
            return rc != NINLIL_MFDT_V1_OK
                       ? rc : NINLIL_MFDT_V1_ERR_STATE;
        }
        rc = ninlil_mfdt_v1_host_take_outbound_ncl1(
            receiver->owner,
            receiver_slot,
            discard,
            sizeof(discard),
            &discard_len);
        if (rc != NINLIL_MFDT_V1_OK || discard_len == 0u) {
            return rc != NINLIL_MFDT_V1_OK
                       ? rc : NINLIL_MFDT_V1_ERR_STATE;
        }
    }
    rc = ninlil_mfdt_v1_host_pump_control(
        sender->owner,
        sender_slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = route_outbound(
        sender->owner,
        sender_slot,
        receiver->owner,
        receiver_bind,
        &response,
        &receiver_slot,
        NULL);
    if (rc != NINLIL_MFDT_V1_OK ||
        response.message_type != NINLIL_MFDT_V1_MSG_PAGE_ACCEPT ||
        response.from_nrc1_hit != 0u) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_STATE;
    }
    rc = route_outbound(
        receiver->owner,
        receiver_slot,
        sender->owner,
        sender_bind,
        NULL,
        NULL,
        NULL);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = ninlil_mfdt_v1_host_pump_control(
        sender->owner,
        sender_slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    *sender_slot_out = sender_slot;
    *receiver_slot_out = receiver_slot;
    return NINLIL_MFDT_V1_OK;
}

static int complete_chunk_ready_transfer(
    host_fixture_t *sender,
    host_fixture_t *receiver,
    const ninlil_mfdt_v1_host_bind_t *sender_bind,
    const ninlil_mfdt_v1_host_bind_t *receiver_bind,
    uint8_t sender_slot,
    uint8_t receiver_slot)
{
    ninlil_mfdt_v1_host_header_snapshot_t sender_header;
    ninlil_mfdt_v1_host_slot_snapshot_t sender_slots[4];
    ninlil_mfdt_v1_host_header_snapshot_t receiver_header;
    ninlil_mfdt_v1_host_slot_snapshot_t receiver_slots[4];
    uint32_t steps;

    for (steps = 0u; steps < 128u; ++steps) {
        uint8_t selected = 0xffu;
        int rc;

        if (snapshot_owner(
                sender->owner,
                &sender_header,
                sender_slots) != NINLIL_MFDT_V1_OK) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (sender_slots[sender_slot].occupied == 0u) {
            break;
        }
        if (sender_slots[sender_slot].pipeline_phase ==
            NINLIL_MFDT_V1_PHASE_SEND_CHUNKS) {
            rc = ninlil_mfdt_v1_host_schedule_one_chunk(
                sender->owner,
                &selected);
            if (rc == NINLIL_MFDT_V1_ERR_BUSY) {
                /*
                 * SEND_CHUNKS with every durable chunk acknowledged is a
                 * control transition to FINALIZE, not a scheduling failure.
                 */
                rc = ninlil_mfdt_v1_host_pump_control(
                    sender->owner,
                    sender_slot);
            } else if (rc == NINLIL_MFDT_V1_OK &&
                       selected != sender_slot) {
                rc = NINLIL_MFDT_V1_ERR_STATE;
            }
            if (rc != NINLIL_MFDT_V1_OK) {
                (void)fprintf(
                    stderr,
                    "complete schedule step=%u rc=%d selected=%u "
                    "expected=%u phase=%u\n",
                    (unsigned)steps,
                    rc,
                    (unsigned)selected,
                    (unsigned)sender_slot,
                    (unsigned)sender_slots[sender_slot].pipeline_phase);
                return rc != NINLIL_MFDT_V1_OK
                           ? rc : NINLIL_MFDT_V1_ERR_STATE;
            }
        } else {
            rc = ninlil_mfdt_v1_host_pump_control(
                sender->owner,
                sender_slot);
            if (rc != NINLIL_MFDT_V1_OK) {
                (void)fprintf(
                    stderr,
                    "complete pump step=%u rc=%d phase=%u\n",
                    (unsigned)steps,
                    rc,
                    (unsigned)sender_slots[sender_slot].pipeline_phase);
                return rc;
            }
        }
        rc = route_outbound(
            sender->owner,
            sender_slot,
            receiver->owner,
            receiver_bind,
            NULL,
            &receiver_slot,
            NULL);
        if (rc != NINLIL_MFDT_V1_OK) {
            (void)fprintf(
                stderr,
                "complete request route step=%u rc=%d\n",
                (unsigned)steps,
                rc);
            return rc;
        }
        rc = route_outbound(
            receiver->owner,
            receiver_slot,
            sender->owner,
            sender_bind,
            NULL,
            NULL,
            NULL);
        if (rc != NINLIL_MFDT_V1_OK) {
            (void)fprintf(
                stderr,
                "complete response route step=%u rc=%d\n",
                (unsigned)steps,
                rc);
            return rc;
        }
    }
    if (steps == 128u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    if (snapshot_owner(
            receiver->owner,
            &receiver_header,
            receiver_slots) != NINLIL_MFDT_V1_OK ||
        receiver_slots[receiver_slot].occupied == 0u) {
        return NINLIL_MFDT_V1_ERR_STATE;
    }
    {
        const uint8_t *content = NULL;
        uint32_t content_len = 0u;
        uint8_t publication_token[16];
        uint8_t evidence[32];
        uint64_t acceptance_generation = 0ull;

        if (ninlil_mfdt_v1_host_receiver_publication_view(
                receiver->owner,
                receiver_slot,
                &content,
                &content_len,
                publication_token,
                &acceptance_generation) != NINLIL_MFDT_V1_OK) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if ((content_len != 0u && content == NULL) ||
            acceptance_generation == 0ull) {
            return NINLIL_MFDT_V1_ERR_CORRUPT;
        }
        ninlil_mfdt_v1_sha256(
            publication_token,
            sizeof(publication_token),
            evidence);
        if (ninlil_mfdt_v1_host_receiver_commit_publication(
                receiver->owner,
                receiver_slot,
                publication_token,
                evidence) != NINLIL_MFDT_V1_OK) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (ninlil_mfdt_v1_host_finish_terminal(
                receiver->owner,
                receiver_slot) != NINLIL_MFDT_V1_OK) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
    }
    return NINLIL_MFDT_V1_OK;
}

static int deliver_all_chunks_without_finalize(
    host_fixture_t *sender,
    host_fixture_t *receiver,
    const ninlil_mfdt_v1_host_bind_t *sender_bind,
    const ninlil_mfdt_v1_host_bind_t *receiver_bind,
    uint8_t sender_slot,
    uint8_t receiver_slot)
{
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint32_t decisions;

    for (decisions = 0u; decisions < 64u; ++decisions) {
        uint8_t selected = 0xffu;
        int rc;

        if (snapshot_owner(sender->owner, &header, slots) !=
            NINLIL_MFDT_V1_OK) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        if (slots[sender_slot].pipeline_phase !=
            NINLIL_MFDT_V1_PHASE_SEND_CHUNKS) {
            return NINLIL_MFDT_V1_ERR_STATE;
        }
        rc = ninlil_mfdt_v1_host_schedule_one_chunk(
            sender->owner,
            &selected);
        if (rc == NINLIL_MFDT_V1_ERR_BUSY) {
            return NINLIL_MFDT_V1_OK;
        }
        if (rc != NINLIL_MFDT_V1_OK || selected != sender_slot) {
            return rc != NINLIL_MFDT_V1_OK
                       ? rc : NINLIL_MFDT_V1_ERR_STATE;
        }
        rc = route_outbound(
            sender->owner,
            sender_slot,
            receiver->owner,
            receiver_bind,
            NULL,
            &receiver_slot,
            NULL);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
        rc = route_outbound(
            receiver->owner,
            receiver_slot,
            sender->owner,
            sender_bind,
            NULL,
            NULL,
            NULL);
        if (rc != NINLIL_MFDT_V1_OK) {
            return rc;
        }
    }
    return NINLIL_MFDT_V1_ERR_STATE;
}

static int test_exact_owner_geometry(void)
{
    CHECK(sizeof(ninlil_mfdt_v1_host_owner_t) == 280064u);
    CHECK(_Alignof(ninlil_mfdt_v1_host_owner_t) >= 8u);
    CHECK(NINLIL_MFDT_V1_HOST_HEADER_BYTES == 128u);
    CHECK(NINLIL_MFDT_V1_HOST_SLOT_DESC_BYTES == 96u);
    CHECK(NINLIL_MFDT_V1_HOST_METADATA_BYTES == 512u);
    CHECK(NINLIL_MFDT_V1_HOST_TERMINAL_COUNT_MAX == 16u);
    CHECK(NINLIL_MFDT_V1_HOST_TERMINAL_DESC_BYTES == 64u);
    CHECK(NINLIL_MFDT_V1_HOST_TERMINAL_CATALOG_BYTES == 1024u);
    CHECK(NINLIL_MFDT_V1_HOST_CONTROL_AREA_BYTES == 17920u);
    CHECK(NINLIL_MFDT_V1_WORKSPACE_BYTES == 65536u);
    CHECK(
        NINLIL_MFDT_V1_HOST_METADATA_BYTES +
            NINLIL_MFDT_V1_HOST_TERMINAL_CATALOG_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_META_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_OUTBOX_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_NRC1_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_NM30_BYTES +
            NINLIL_MFDT_V1_HOST_CONTROL_RESERVED_BYTES ==
        NINLIL_MFDT_V1_HOST_CONTROL_AREA_BYTES);
    CHECK(
        NINLIL_MFDT_V1_HOST_CONTROL_AREA_BYTES +
            NINLIL_MFDT_V1_HOST_SLOT_COUNT *
                NINLIL_MFDT_V1_WORKSPACE_BYTES ==
        NINLIL_MFDT_V1_HOST_OWNER_BYTES);
    CHECK(
        NINLIL_MFDT_V1_HOST_ACTIVE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_NRC1_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_PIPELINE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_ENGINE_REGION_BYTES +
            NINLIL_MFDT_V1_HOST_TEMP_REGION_BYTES ==
        NINLIL_MFDT_V1_WORKSPACE_BYTES);
    return 0;
}

static int test_owner_init_guards_zero_mutation(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_owner_t *owner;
    ninlil_mfdt_v1_config_t config;
    ninlil_mfdt_v1_store_port_t port_before;
    ninlil_mfdt_v1_config_t config_before;
    uint8_t *owner_before;
    uint8_t *misaligned_memory;
    uint8_t *misaligned_before;
    uint32_t keys_before;
    uint32_t keys_after;
    uint64_t bytes_before;
    uint64_t bytes_after;
    uint64_t generation_before;
    uint64_t generation_after;
    uint64_t fulls_before;
    uint64_t fulls_after;
    int rc;

    (void)memset(&fixture, 0, sizeof(fixture));
    make_config(&config);
    fixture.store = ninlil_mfdt_v1_host_store_create();
    owner = (ninlil_mfdt_v1_host_owner_t *)malloc(sizeof(*owner));
    owner_before = (uint8_t *)malloc(sizeof(*owner));
    misaligned_memory =
        (uint8_t *)malloc(sizeof(*owner) + 8u);
    misaligned_before =
        (uint8_t *)malloc(sizeof(*owner) + 8u);
    CHECK(fixture.store != NULL);
    CHECK(owner != NULL && owner_before != NULL);
    CHECK(misaligned_memory != NULL && misaligned_before != NULL);
    CHECK(ninlil_mfdt_v1_host_store_open_port(
              fixture.store,
              &fixture.port) == NINLIL_MFDT_V1_OK);
    fixture.port_open = 1u;
    CHECK(ninlil_mfdt_v1_host_store_inventory(
              fixture.store,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);

    (void)memset(misaligned_memory, 0xa5, sizeof(*owner) + 8u);
    (void)memcpy(
        misaligned_before,
        misaligned_memory,
        sizeof(*owner) + 8u);
    port_before = fixture.port;
    config_before = config;
    rc = ninlil_mfdt_v1_host_owner_init(
        (ninlil_mfdt_v1_host_owner_t *)(void *)(misaligned_memory + 1u),
        &fixture.port,
        &config);
    CHECK(rc == NINLIL_MFDT_V1_ERR_PARAM);
    CHECK(memcmp(
              misaligned_memory,
              misaligned_before,
              sizeof(*owner) + 8u) == 0);
    CHECK(memcmp(&fixture.port, &port_before, sizeof(port_before)) == 0);
    CHECK(memcmp(&config, &config_before, sizeof(config_before)) == 0);

    (void)memset(owner, 0x5a, sizeof(*owner));
    (void)memcpy(owner_before, owner, sizeof(*owner));
    rc = ninlil_mfdt_v1_host_owner_init(
        owner,
        (ninlil_mfdt_v1_store_port_t *)(void *)(owner->opaque + 8u),
        &config);
    CHECK(rc == NINLIL_MFDT_V1_ERR_PARAM);
    CHECK(memcmp(owner, owner_before, sizeof(*owner)) == 0);

    (void)memset(owner, 0x6b, sizeof(*owner));
    (void)memcpy(
        owner->opaque + 64u,
        &config,
        sizeof(config));
    (void)memcpy(owner_before, owner, sizeof(*owner));
    rc = ninlil_mfdt_v1_host_owner_init(
        owner,
        &fixture.port,
        (const ninlil_mfdt_v1_config_t *)(const void *)
            (owner->opaque + 64u));
    CHECK(rc == NINLIL_MFDT_V1_ERR_PARAM);
    CHECK(memcmp(owner, owner_before, sizeof(*owner)) == 0);

    {
        ninlil_mfdt_v1_store_port_t overlapping_port = fixture.port;
        const uintptr_t config_alignment =
            (uintptr_t)_Alignof(ninlil_mfdt_v1_config_t);
        const uintptr_t config_address =
            ((uintptr_t)(void *)overlapping_port.staged_keys +
             config_alignment - 1u) &
            ~(config_alignment - 1u);
        ninlil_mfdt_v1_config_t *overlapping_config =
            (ninlil_mfdt_v1_config_t *)(void *)config_address;
        ninlil_mfdt_v1_store_port_t overlapping_before;

        CHECK((uint8_t *)(void *)overlapping_config +
                  sizeof(*overlapping_config) <=
              (uint8_t *)(void *)&overlapping_port +
                  sizeof(overlapping_port));
        (void)memcpy(
            overlapping_config,
            &config,
            sizeof(*overlapping_config));
        overlapping_before = overlapping_port;
        (void)memset(owner, 0x7c, sizeof(*owner));
        (void)memcpy(owner_before, owner, sizeof(*owner));
        rc = ninlil_mfdt_v1_host_owner_init(
            owner,
            &overlapping_port,
            overlapping_config);
        CHECK(rc == NINLIL_MFDT_V1_ERR_PARAM);
        CHECK(memcmp(owner, owner_before, sizeof(*owner)) == 0);
        CHECK(memcmp(
                  &overlapping_port,
                  &overlapping_before,
                  sizeof(overlapping_port)) == 0);
    }

    {
        ninlil_mfdt_v1_store_port_t invalid_port = fixture.port;
        ninlil_mfdt_v1_store_port_t invalid_before;

        invalid_port.guarantees.committed_keys_max =
            NINLIL_MFDT_V1_HOST_COMMITTED_KEYS_MAX - 1u;
        invalid_before = invalid_port;
        (void)memset(owner, 0x8d, sizeof(*owner));
        (void)memcpy(owner_before, owner, sizeof(*owner));
        rc = ninlil_mfdt_v1_host_owner_init(
            owner,
            &invalid_port,
            &config);
        CHECK(rc != NINLIL_MFDT_V1_OK);
        CHECK(memcmp(owner, owner_before, sizeof(*owner)) == 0);
        CHECK(memcmp(
                  &invalid_port,
                  &invalid_before,
                  sizeof(invalid_port)) == 0);
    }

    CHECK(ninlil_mfdt_v1_host_store_inventory(
              fixture.store,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before);
    CHECK(fulls_after == fulls_before);

    free(misaligned_before);
    free(misaligned_memory);
    free(owner_before);
    free(owner);
    host_fixture_destroy(&fixture);
    return 0;
}

static int test_four_slots_and_fifth_atomic(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t binds[5];
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    ninlil_mfdt_v1_host_owner_t *owner_before;
    uint8_t content[32];
    uint8_t slot = 0xffu;
    uint32_t keys_before;
    uint32_t keys_after;
    uint64_t bytes_before;
    uint64_t bytes_after;
    uint64_t generation_before;
    uint64_t generation_after;
    uint64_t fulls_before;
    uint64_t fulls_after;
    uint64_t allocations_before;
    uint8_t index;
    int rc;

    CHECK(host_fixture_prepare(&fixture, 1));
    (void)memset(content, 0x4a, sizeof(content));
    allocations_before = ninlil_mfdt_v1_target_zalloc_call_count();
    ninlil_mfdt_v1_target_zalloc_force_fail(1);
    for (index = 0u; index < 5u; ++index) {
        make_bind(
            &binds[index],
            (uint8_t)(0x20u + index),
            NINLIL_MFDT_V1_HOST_ROLE_SENDER,
            0xabc000ull + index);
    }
    for (index = 0u; index < 4u; ++index) {
        slot = 0xffu;
        CHECK(sender_open(
                  &fixture,
                  &binds[index],
                  (uint8_t)(index + 1u),
                  content,
                  sizeof(content),
                  (uint64_t)(100u + index),
                  &slot) == NINLIL_MFDT_V1_OK);
        CHECK(slot == index);
    }
    CHECK(
        ninlil_mfdt_v1_target_zalloc_call_count() ==
        allocations_before);
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 4u);
    CHECK(header.tracked_groups == 4u);
    CHECK(header.committed_keys == 8u);
    owner_before = (ninlil_mfdt_v1_host_owner_t *)malloc(
        sizeof(*owner_before));
    CHECK(owner_before != NULL);
    (void)memcpy(owner_before, fixture.owner, sizeof(*owner_before));
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    slot = 0xeeu;
    rc = sender_open(
        &fixture,
        &binds[4],
        5u,
        content,
        sizeof(content),
        105u,
        &slot);
    CHECK(rc == NINLIL_MFDT_V1_ERR_CAPACITY);
    CHECK(slot == 0xeeu);
    CHECK(memcmp(
              fixture.owner,
              owner_before,
              sizeof(*owner_before)) == 0);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before);
    CHECK(fulls_after == fulls_before);
    CHECK(
        ninlil_mfdt_v1_target_zalloc_call_count() ==
        allocations_before);
    ninlil_mfdt_v1_target_zalloc_force_fail(0);
    free(owner_before);
    host_fixture_destroy(&fixture);
    return 0;
}

static int test_duplicate_conflict_and_unknown_no_allocation(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_host_bind_t conflict;
    ninlil_mfdt_v1_host_owner_t *owner_before;
    ninlil_mfdt_v1_wire_view_t wire;
    ninlil_mfdt_v1_response_t response;
    uint8_t transfer_id[16];
    uint8_t unknown_id[16];
    uint8_t content = 0x51u;
    uint8_t slot = 0xffu;
    uint8_t duplicate_slot = 0xffu;
    uint32_t keys_before;
    uint32_t keys_after;
    uint64_t bytes_before;
    uint64_t bytes_after;
    uint64_t generation_before;
    uint64_t generation_after;
    uint64_t fulls_before;
    uint64_t fulls_after;

    CHECK(host_fixture_prepare(&fixture, 1));
    make_bind(
        &bind,
        0x40u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0x445566ull);
    CHECK(sender_open(
              &fixture,
              &bind,
              1u,
              &content,
              sizeof(content),
              10u,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(slot == 0u);
    CHECK(sender_open(
              &fixture,
              &bind,
              1u,
              &content,
              sizeof(content),
              10u,
              &duplicate_slot) == NINLIL_MFDT_V1_ERR_BUSY);
    CHECK(duplicate_slot == 0xffu);

    owner_before = (ninlil_mfdt_v1_host_owner_t *)malloc(
        sizeof(*owner_before));
    CHECK(owner_before != NULL);
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    conflict = bind;
    conflict.peer_endpoint_id[0] ^= 0x55u;
    (void)memcpy(owner_before, fixture.owner, sizeof(*owner_before));
    duplicate_slot = 0xffu;
    CHECK(sender_open(
              &fixture,
              &conflict,
              1u,
              &content,
              sizeof(content),
              10u,
              &duplicate_slot) == NINLIL_MFDT_V1_ERR_VERSION);
    CHECK(memcmp(
              fixture.owner,
              owner_before,
              sizeof(*owner_before)) == 0);

    make_tid(transfer_id, 1u);
    make_tid(unknown_id, 9u);
    wire.message_type = NINLIL_MFDT_V1_MSG_CHUNK_OFFER;
    wire.request_id = 99u;
    wire.body = unknown_id;
    wire.body_len = sizeof(unknown_id);
    (void)memset(&response, 0xa5, sizeof(response));
    (void)memcpy(owner_before, fixture.owner, sizeof(*owner_before));
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &conflict,
              &wire,
              &response,
              &duplicate_slot) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(memcmp(
              fixture.owner,
              owner_before,
              sizeof(*owner_before)) == 0);
    CHECK(response.message_type == 0u);

    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN_ACCEPT;
    wire.request_id = 10u;
    wire.body = transfer_id;
    wire.body_len = sizeof(transfer_id);
    conflict = bind;
    conflict.role = NINLIL_MFDT_V1_HOST_ROLE_RECEIVER;
    (void)memcpy(owner_before, fixture.owner, sizeof(*owner_before));
    {
        const int wrong_direction_rc =
            ninlil_mfdt_v1_host_on_wire(
                fixture.owner,
                &conflict,
                &wire,
                &response,
                &duplicate_slot);
        CHECK(wrong_direction_rc == NINLIL_MFDT_V1_ERR_VERSION ||
              wrong_direction_rc == NINLIL_MFDT_V1_ERR_STATE ||
              wrong_direction_rc == NINLIL_MFDT_V1_ERR_LAYOUT);
    }
    CHECK(memcmp(
              fixture.owner,
              owner_before,
              sizeof(*owner_before)) == 0);
    CHECK(response.message_type == 0u);

    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before);
    CHECK(fulls_after == fulls_before);
    free(owner_before);
    host_fixture_destroy(&fixture);
    return 0;
}

static int test_lowest_free_after_receiver_abort(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint8_t open_bodies[4][NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_lengths[4];
    uint8_t allocated[4];
    uint8_t new_slot = 0xffu;
    uint8_t index;

    CHECK(host_fixture_prepare(&fixture, 1));
    make_bind(
        &bind,
        0x60u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x667788ull);
    for (index = 0u; index < 4u; ++index) {
        CHECK(receiver_open_body(
                  &fixture,
                  &bind,
                  (uint8_t)(index + 1u),
                  (uint64_t)(200u + index),
                  &allocated[index],
                  open_bodies[index],
                  &open_lengths[index],
                  &response) == NINLIL_MFDT_V1_OK);
        CHECK(allocated[index] == index);
        CHECK(
            response.message_type ==
            NINLIL_MFDT_V1_MSG_OPEN_ACCEPT);
        {
            uint8_t discarded[NINLIL_MFDT_V1_NCL1_MAX_MSG];
            size_t discarded_len = 0u;
            CHECK(ninlil_mfdt_v1_host_take_outbound_ncl1(
                      fixture.owner,
                      index,
                      discarded,
                      sizeof(discarded),
                      &discarded_len) == NINLIL_MFDT_V1_OK);
            CHECK(discarded_len != 0u);
        }
    }
    CHECK(receiver_abort_slot(
              &fixture,
              &bind,
              1u,
              open_bodies[1],
              301u) == NINLIL_MFDT_V1_OK);
    CHECK(receiver_abort_slot(
              &fixture,
              &bind,
              3u,
              open_bodies[3],
              303u) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 2u);
    CHECK(slots[1].occupied == 0u);
    CHECK(slots[3].occupied == 0u);
    CHECK(receiver_open_body(
              &fixture,
              &bind,
              9u,
              309u,
              &new_slot,
              open_bodies[1],
              &open_lengths[1],
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(new_slot == 1u);
    host_fixture_destroy(&fixture);
    return 0;
}

static int test_restart_canonical_and_rebind_gate(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_owner_t *recovered;
    ninlil_mfdt_v1_host_bind_t binds[5];
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint8_t insertion[4] = {4u, 1u, 3u, 2u};
    uint8_t content[64];
    uint8_t output[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t output_len = 77u;
    uint8_t slot;
    uint8_t index;

    CHECK(host_fixture_prepare(&fixture, 1));
    (void)memset(content, 0x77, sizeof(content));
    for (index = 1u; index <= 4u; ++index) {
        make_bind(
            &binds[index],
            (uint8_t)(0x70u + index),
            NINLIL_MFDT_V1_HOST_ROLE_SENDER,
            0x700000ull + index);
    }
    for (index = 0u; index < 4u; ++index) {
        CHECK(sender_open(
                  &fixture,
                  &binds[insertion[index]],
                  insertion[index],
                  content,
                  sizeof(content),
                  (uint64_t)(400u + index),
                  &slot) == NINLIL_MFDT_V1_OK);
        CHECK(slot == index);
    }
    recovered = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*recovered));
    CHECK(recovered != NULL);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              recovered,
              &fixture.port,
              &fixture.config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(recovered) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(recovered) ==
          NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(recovered, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 4u);
    CHECK(header.next_slot == 0u);
    for (index = 0u; index < 4u; ++index) {
        uint8_t expected[16];
        make_tid(expected, (uint8_t)(index + 1u));
        CHECK(slots[index].occupied == 1u);
        CHECK(slots[index].bind_valid == 0u);
        CHECK(memcmp(slots[index].transfer_id, expected, 16u) == 0);
        output_len = 77u;
        CHECK(ninlil_mfdt_v1_host_take_outbound_ncl1(
                  recovered,
                  index,
                  output,
                  sizeof(output),
                  &output_len) == NINLIL_MFDT_V1_ERR_STATE);
        CHECK(output_len == 77u);
    }
    {
        ninlil_mfdt_v1_host_bind_t wrong = binds[1];
        uint8_t tid[16];
        ninlil_mfdt_v1_host_owner_t *before =
            (ninlil_mfdt_v1_host_owner_t *)malloc(sizeof(*before));

        CHECK(before != NULL);
        make_tid(tid, 1u);
        wrong.peer_endpoint_id[0] ^= 0x01u;
        (void)memcpy(before, recovered, sizeof(*before));
        CHECK(ninlil_mfdt_v1_host_rebind_recovered(
                  recovered,
                  tid,
                  &wrong) == NINLIL_MFDT_V1_ERR_VERSION);
        CHECK(memcmp(recovered, before, sizeof(*before)) == 0);
        free(before);
    }
    for (index = 0u; index < 4u; ++index) {
        uint8_t tid[16];
        make_tid(tid, (uint8_t)(index + 1u));
        CHECK(ninlil_mfdt_v1_host_rebind_recovered(
                  recovered,
                  tid,
                  &binds[index + 1u]) == NINLIL_MFDT_V1_OK);
    }
    CHECK(snapshot_owner(recovered, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    for (index = 0u; index < 4u; ++index) {
        CHECK(slots[index].bind_valid == 1u);
    }
    free(recovered);
    host_fixture_destroy(&fixture);
    return 0;
}

static int test_nrc1_fresh_vs_duplicate_signal(void)
{
    host_fixture_t sender;
    host_fixture_t receiver;
    ninlil_mfdt_v1_host_bind_t sender_bind;
    ninlil_mfdt_v1_host_bind_t receiver_bind;
    uint8_t content[1000];
    uint8_t sender_slot = 0xffu;
    uint8_t receiver_slot = 0xffu;

    CHECK(host_fixture_prepare(&sender, 1));
    CHECK(host_fixture_prepare(&receiver, 1));
    make_bind(
        &sender_bind,
        0xa0u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0xabc101ull);
    make_bind(
        &receiver_bind,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xabc101ull);
    (void)memset(content, 0x5c, sizeof(content));
    CHECK(prepare_one_sender_for_chunks(
              &sender,
              &receiver,
              &sender_bind,
              &receiver_bind,
              1u,
              content,
              sizeof(content),
              &sender_slot,
              &receiver_slot,
              1) == NINLIL_MFDT_V1_OK);
    CHECK(sender_slot == 0u && receiver_slot == 0u);
    host_fixture_destroy(&receiver);
    host_fixture_destroy(&sender);
    return 0;
}

static int prepare_four_senders(
    host_fixture_t *sender,
    host_fixture_t *receiver,
    ninlil_mfdt_v1_host_bind_t sender_binds[4],
    ninlil_mfdt_v1_host_bind_t *receiver_bind,
    const uint8_t peer_tags[4],
    uint64_t cookie,
    uint8_t sender_slots[4],
    uint8_t receiver_slots[4])
{
    uint8_t *content = (uint8_t *)malloc(7000u);
    uint8_t index;
    int rc = NINLIL_MFDT_V1_OK;

    if (content == NULL) {
        return NINLIL_MFDT_V1_ERR_CAPACITY;
    }
    (void)memset(content, 0x6d, 7000u);
    make_bind(
        receiver_bind,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        cookie);
    for (index = 0u; index < 4u; ++index) {
        make_bind(
            &sender_binds[index],
            peer_tags[index],
            NINLIL_MFDT_V1_HOST_ROLE_SENDER,
            cookie);
        rc = prepare_one_sender_for_chunks(
            sender,
            receiver,
            &sender_binds[index],
            receiver_bind,
            (uint8_t)(index + 1u),
            content,
            7000u,
            &sender_slots[index],
            &receiver_slots[index],
            0);
        if (rc != NINLIL_MFDT_V1_OK) {
            break;
        }
    }
    free(content);
    return rc;
}

static int test_scheduler_round_robin_actual_ncl1(void)
{
    host_fixture_t sender;
    host_fixture_t receiver;
    ninlil_mfdt_v1_host_bind_t sender_binds[4];
    ninlil_mfdt_v1_host_bind_t receiver_bind;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    const uint8_t peer_tags[4] = {0xa1u, 0xb1u, 0xc1u, 0xd1u};
    uint8_t sender_slots[4];
    uint8_t receiver_slots[4];
    uint8_t decision;

    CHECK(host_fixture_prepare(&sender, 1));
    CHECK(host_fixture_prepare(&receiver, 1));
    CHECK(prepare_four_senders(
              &sender,
              &receiver,
              sender_binds,
              &receiver_bind,
              peer_tags,
              0xabc202ull,
              sender_slots,
              receiver_slots) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    for (decision = 0u; decision < 4u; ++decision) {
        CHECK(sender_slots[decision] == decision);
        CHECK(receiver_slots[decision] == decision);
        CHECK(
            slots[decision].pipeline_phase ==
            NINLIL_MFDT_V1_PHASE_SEND_CHUNKS);
        CHECK(slots[decision].outbox_pending == 0u);
    }
    for (decision = 0u; decision < 8u; ++decision) {
        uint8_t selected = 0xffu;
        const uint8_t expected = (uint8_t)(decision % 4u);

        CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
                  sender.owner,
                  &selected) == NINLIL_MFDT_V1_OK);
        CHECK(selected == expected);
        CHECK(route_outbound(
                  sender.owner,
                  selected,
                  receiver.owner,
                  &receiver_bind,
                  NULL,
                  &receiver_slots[selected],
                  NULL) == NINLIL_MFDT_V1_OK);
        CHECK(route_outbound(
                  receiver.owner,
                  receiver_slots[selected],
                  sender.owner,
                  &sender_binds[selected],
                  NULL,
                  NULL,
                  NULL) == NINLIL_MFDT_V1_OK);
    }
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.next_slot == 0u);
    for (decision = 0u; decision < 4u; ++decision) {
        CHECK(slots[decision].unpaid_chunk_offer == 0u);
    }
    host_fixture_destroy(&receiver);
    host_fixture_destroy(&sender);
    return 0;
}

static int test_peer_fence_exact_release_and_retry(void)
{
    host_fixture_t sender;
    host_fixture_t receiver;
    ninlil_mfdt_v1_host_bind_t sender_binds[4];
    ninlil_mfdt_v1_host_bind_t receiver_bind;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    const uint8_t peer_tags[4] = {0xa2u, 0xb2u, 0xa2u, 0xc2u};
    uint8_t sender_slots[4];
    uint8_t receiver_slots[4];
    uint8_t selected = 0xffu;
    decoded_frame_t accept;
    ninlil_mfdt_v1_wire_view_t wrong_wire;
    ninlil_mfdt_v1_host_bind_t wrong_bind;
    ninlil_mfdt_v1_response_t response;
    uint8_t body_copy[160];
    uint8_t retry_frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t retry_len = 0u;

    CHECK(host_fixture_prepare(&sender, 1));
    CHECK(host_fixture_prepare(&receiver, 1));
    CHECK(prepare_four_senders(
              &sender,
              &receiver,
              sender_binds,
              &receiver_bind,
              peer_tags,
              0xabc303ull,
              sender_slots,
              receiver_slots) == NINLIL_MFDT_V1_OK);

    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              sender.owner,
              &selected) == NINLIL_MFDT_V1_OK);
    CHECK(selected == 0u);
    CHECK(route_outbound(
              sender.owner,
              0u,
              receiver.owner,
              &receiver_bind,
              NULL,
              &receiver_slots[0],
              NULL) == NINLIL_MFDT_V1_OK);

    selected = 0xffu;
    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              sender.owner,
              &selected) == NINLIL_MFDT_V1_OK);
    CHECK(selected == 1u);
    selected = 0xffu;
    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              sender.owner,
              &selected) == NINLIL_MFDT_V1_OK);
    CHECK(selected == 3u);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[0].unpaid_chunk_offer == 1u);
    CHECK(slots[1].unpaid_chunk_offer == 1u);
    CHECK(slots[2].unpaid_chunk_offer == 0u);
    CHECK(slots[3].unpaid_chunk_offer == 1u);

    CHECK(decode_outbound(
              receiver.owner,
              receiver_slots[0],
              &accept) == NINLIL_MFDT_V1_OK);
    CHECK(
        accept.wire.message_type ==
        NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT);
    wrong_wire = accept.wire;
    wrong_wire.request_id += 1ull;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              sender.owner,
              &sender_binds[0],
              &wrong_wire,
              &response,
              NULL) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[0].unpaid_chunk_offer == 1u);

    wrong_bind = sender_binds[0];
    wrong_bind.peer_endpoint_id[0] ^= 0x01u;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              sender.owner,
              &wrong_bind,
              &accept.wire,
              &response,
              NULL) == NINLIL_MFDT_V1_ERR_VERSION);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[0].unpaid_chunk_offer == 1u);

    CHECK(accept.wire.body_len <= sizeof(body_copy));
    (void)memcpy(body_copy, accept.wire.body, accept.wire.body_len);
    body_copy[15] ^= 0x01u;
    wrong_wire = accept.wire;
    wrong_wire.body = body_copy;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              sender.owner,
              &sender_binds[0],
              &wrong_wire,
              &response,
              NULL) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[0].unpaid_chunk_offer == 1u);

    (void)memcpy(body_copy, accept.wire.body, accept.wire.body_len);
    ninlil_mfdt_v1_put_u16(
        body_copy + 52u,
        (uint16_t)(ninlil_mfdt_v1_get_u16(body_copy + 52u) + 1u));
    wrong_wire = accept.wire;
    wrong_wire.body = body_copy;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              sender.owner,
              &sender_binds[0],
              &wrong_wire,
              &response,
              NULL) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[0].unpaid_chunk_offer == 1u);

    CHECK(ninlil_mfdt_v1_host_on_wire(
              sender.owner,
              &sender_binds[0],
              &accept.wire,
              &response,
              NULL) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[0].unpaid_chunk_offer == 0u);
    CHECK(slots[2].unpaid_chunk_offer == 0u);

    CHECK(ninlil_mfdt_v1_host_take_outbound_ncl1(
              sender.owner,
              1u,
              retry_frame,
              sizeof(retry_frame),
              &retry_len) == NINLIL_MFDT_V1_OK);
    CHECK(retry_len != 0u);
    CHECK(ninlil_mfdt_v1_host_tick(
              sender.owner,
              6001ull) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[1].unpaid_chunk_offer == 1u);
    CHECK(slots[1].outbox_pending == 1u);

    host_fixture_destroy(&receiver);
    host_fixture_destroy(&sender);
    return 0;
}

static int test_terminal_reject_exact_peer_fence_release(void)
{
    host_fixture_t sender;
    host_fixture_t receiver;
    ninlil_mfdt_v1_host_bind_t sender_bind;
    ninlil_mfdt_v1_host_bind_t receiver_bind;
    ninlil_mfdt_v1_host_bind_t wrong_bind;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_wire_view_t reject;
    decoded_frame_t offer;
    uint8_t content[1400];
    uint8_t reject_body[60];
    uint8_t sender_slots[2] = {0xffu, 0xffu};
    uint8_t receiver_slots[2] = {0xffu, 0xffu};
    uint8_t selected = 0xffu;
    uint8_t routed_slot = 0xaau;
    unsigned variant;

    CHECK(host_fixture_prepare(&sender, 1));
    CHECK(host_fixture_prepare(&receiver, 1));
    make_bind(
        &sender_bind,
        0xa4u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0xabc404ull);
    make_bind(
        &receiver_bind,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xabc404ull);
    (void)memset(content, 0x4du, sizeof(content));
    CHECK(prepare_one_sender_for_chunks(
              &sender,
              &receiver,
              &sender_bind,
              &receiver_bind,
              1u,
              content,
              sizeof(content),
              &sender_slots[0],
              &receiver_slots[0],
              0) == NINLIL_MFDT_V1_OK);
    content[0] ^= 0xffu;
    CHECK(prepare_one_sender_for_chunks(
              &sender,
              &receiver,
              &sender_bind,
              &receiver_bind,
              2u,
              content,
              sizeof(content),
              &sender_slots[1],
              &receiver_slots[1],
              0) == NINLIL_MFDT_V1_OK);
    CHECK(sender_slots[0] == 0u && sender_slots[1] == 1u);

    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              sender.owner,
              &selected) == NINLIL_MFDT_V1_OK);
    CHECK(selected == sender_slots[0]);
    CHECK(decode_outbound(
              sender.owner,
              sender_slots[0],
              &offer) == NINLIL_MFDT_V1_OK);
    CHECK(
        offer.wire.message_type ==
        NINLIL_MFDT_V1_MSG_CHUNK_OFFER);
    CHECK(offer.wire.body_len >= 52u);
    selected = 0xaau;
    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              sender.owner,
              &selected) == NINLIL_MFDT_V1_ERR_BUSY);
    CHECK(selected == 0xffu);

    (void)memset(reject_body, 0, sizeof(reject_body));
    (void)memcpy(reject_body, offer.wire.body, 52u);
    ninlil_mfdt_v1_put_u16(reject_body + 52u, 3u);
    ninlil_mfdt_v1_put_u16(
        reject_body + 54u,
        NINLIL_MFDT_V1_REJ_STATE);
    reject.message_type = NINLIL_MFDT_V1_MSG_REJECT;
    reject.request_id = offer.wire.request_id;
    reject.body = reject_body;
    reject.body_len = sizeof(reject_body);

    /*
     * Wrong request id, stage, transfer id, bind, and direction are all
     * fail-closed.  None may release the per-peer unpaid-CHUNK fence or
     * publish response/slot outputs.
     */
    for (variant = 0u; variant < 5u; ++variant) {
        ninlil_mfdt_v1_wire_view_t wrong = reject;

        (void)memcpy(reject_body, offer.wire.body, 52u);
        ninlil_mfdt_v1_put_u16(reject_body + 52u, 3u);
        ninlil_mfdt_v1_put_u16(
            reject_body + 54u,
            NINLIL_MFDT_V1_REJ_STATE);
        wrong_bind = sender_bind;
        if (variant == 0u) {
            wrong.request_id += 1ull;
        } else if (variant == 1u) {
            ninlil_mfdt_v1_put_u16(reject_body + 52u, 2u);
        } else if (variant == 2u) {
            reject_body[15] ^= 0x01u;
        } else if (variant == 3u) {
            wrong_bind.peer_endpoint_id[0] ^= 0x01u;
        } else {
            wrong_bind.role = NINLIL_MFDT_V1_HOST_ROLE_RECEIVER;
        }
        (void)memset(&response, 0xa5, sizeof(response));
        routed_slot = 0xaau;
        CHECK(ninlil_mfdt_v1_host_on_wire(
                  sender.owner,
                  &wrong_bind,
                  &wrong,
                  &response,
                  &routed_slot) != NINLIL_MFDT_V1_OK);
        CHECK(response.message_type == 0u);
        CHECK(response.body_len == 0u);
        CHECK(routed_slot == 0xaau);
        CHECK(snapshot_owner(sender.owner, &header, slots) ==
              NINLIL_MFDT_V1_OK);
        CHECK(slots[sender_slots[0]].unpaid_chunk_offer == 1u);
        CHECK(slots[sender_slots[1]].unpaid_chunk_offer == 0u);
    }

    (void)memcpy(reject_body, offer.wire.body, 52u);
    ninlil_mfdt_v1_put_u16(reject_body + 52u, 3u);
    ninlil_mfdt_v1_put_u16(
        reject_body + 54u,
        NINLIL_MFDT_V1_REJ_STATE);
    (void)memset(&response, 0xa5, sizeof(response));
    routed_slot = 0xffu;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              sender.owner,
              &sender_bind,
              &reject,
              &response,
              &routed_slot) == NINLIL_MFDT_V1_OK);
    CHECK(routed_slot == sender_slots[0]);
    CHECK(response.message_type == 0u);
    CHECK(response.body_len == 0u);
    CHECK(snapshot_owner(sender.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[sender_slots[0]].unpaid_chunk_offer == 0u);
    CHECK(
        slots[sender_slots[0]].pipeline_phase ==
        NINLIL_MFDT_V1_PHASE_COMPLETE);

    selected = 0xffu;
    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              sender.owner,
              &selected) == NINLIL_MFDT_V1_OK);
    CHECK(selected == sender_slots[1]);

    host_fixture_destroy(&receiver);
    host_fixture_destroy(&sender);
    return 0;
}

static int test_bidirectional_complete_retention_and_gc(void)
{
    host_fixture_t left;
    host_fixture_t right;
    ninlil_mfdt_v1_host_bind_t left_sender;
    ninlil_mfdt_v1_host_bind_t left_receiver;
    ninlil_mfdt_v1_host_bind_t right_sender;
    ninlil_mfdt_v1_host_bind_t right_receiver;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint8_t left_content[1800];
    uint8_t right_content[1900];
    uint8_t left_sender_slot = 0xffu;
    uint8_t right_receiver_slot = 0xffu;
    uint8_t right_sender_slot = 0xffu;
    uint8_t left_receiver_slot = 0xffu;
    uint8_t fresh_slot = 0xffu;
    uint64_t allocation_count;

    CHECK(host_fixture_prepare(&left, 1));
    CHECK(host_fixture_prepare(&right, 1));
    make_bind(
        &left_sender,
        0xb0u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0x111001ull);
    make_bind(
        &right_receiver,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x111001ull);
    make_bind(
        &right_sender,
        0xa0u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0x222002ull);
    make_bind(
        &left_receiver,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x222002ull);
    (void)memset(left_content, 0x1a, sizeof(left_content));
    (void)memset(right_content, 0x2b, sizeof(right_content));
    allocation_count = ninlil_mfdt_v1_target_zalloc_call_count();
    ninlil_mfdt_v1_target_zalloc_force_fail(1);
    CHECK(prepare_one_sender_for_chunks(
              &left,
              &right,
              &left_sender,
              &right_receiver,
              1u,
              left_content,
              sizeof(left_content),
              &left_sender_slot,
              &right_receiver_slot,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(prepare_one_sender_for_chunks(
              &right,
              &left,
              &right_sender,
              &left_receiver,
              2u,
              right_content,
              sizeof(right_content),
              &right_sender_slot,
              &left_receiver_slot,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(complete_chunk_ready_transfer(
              &left,
              &right,
              &left_sender,
              &right_receiver,
              left_sender_slot,
              right_receiver_slot) == NINLIL_MFDT_V1_OK);
    CHECK(complete_chunk_ready_transfer(
              &right,
              &left,
              &right_sender,
              &left_receiver,
              right_sender_slot,
              left_receiver_slot) == NINLIL_MFDT_V1_OK);
    CHECK(
        ninlil_mfdt_v1_target_zalloc_call_count() ==
        allocation_count);
    CHECK(snapshot_owner(left.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 2u);
    CHECK(header.committed_keys == 4u);
    CHECK(slots[0].occupied == 0u && slots[1].occupied == 0u);
    CHECK(sender_open(
              &left,
              &left_sender,
              9u,
              left_content,
              sizeof(left_content),
              909u,
              &fresh_slot) == NINLIL_MFDT_V1_OK);
    CHECK(fresh_slot == 0u);
    CHECK(snapshot_owner(right.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 2u);
    CHECK(header.committed_keys == 4u);
    CHECK(ninlil_mfdt_v1_host_gc(
              right.owner,
              1000ull + NINLIL_MFDT_V1_RETENTION_MS_DEFAULT) ==
          NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(right.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.tracked_groups == 0u);
    CHECK(header.committed_keys == 0u);
    ninlil_mfdt_v1_target_zalloc_force_fail(0);
    host_fixture_destroy(&right);
    host_fixture_destroy(&left);
    return 0;
}

static int test_commit_unknown_global_fence_and_cold_recover(void)
{
    host_fixture_t fenced;
    host_fixture_t peer;
    ninlil_mfdt_v1_host_bind_t fenced_sender;
    ninlil_mfdt_v1_host_bind_t fenced_receiver;
    ninlil_mfdt_v1_host_bind_t peer_sender;
    ninlil_mfdt_v1_host_bind_t peer_receiver;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    ninlil_mfdt_v1_host_owner_t *fenced_before;
    ninlil_mfdt_v1_host_owner_t *cold_owner;
    uint8_t content[1800];
    uint8_t first_sender_slot = 0xffu;
    uint8_t peer_receiver_slot = 0xffu;
    uint8_t peer_sender_slot = 0xffu;
    uint8_t ready_receiver_slot = 0xffu;
    uint8_t failed_slot = 0xeeu;
    uint8_t transfer_id[16];
    uint8_t frame[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t frame_len = 91u;
    ninlil_mfdt_v1_wire_view_t wire;
    ninlil_mfdt_v1_response_t response;
    const uint8_t *published_content = NULL;
    uint32_t published_len = 0u;
    uint8_t publication_token[16];
    uint8_t publication_evidence[32];
    uint64_t acceptance_generation = 0ull;
    uint32_t keys_before;
    uint32_t keys_after;
    uint64_t bytes_before;
    uint64_t bytes_after;
    uint64_t generation_before;
    uint64_t generation_after;
    uint64_t fulls_before;
    uint64_t fulls_after;
    int rc;

    CHECK(host_fixture_prepare(&fenced, 1));
    CHECK(host_fixture_prepare(&peer, 1));
    make_bind(
        &fenced_sender,
        0xb4u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0x444001ull);
    make_bind(
        &peer_receiver,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x444001ull);
    make_bind(
        &peer_sender,
        0xa4u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0x444002ull);
    make_bind(
        &fenced_receiver,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x444002ull);
    (void)memset(content, 0x44, sizeof(content));
    CHECK(prepare_one_sender_for_chunks(
              &fenced,
              &peer,
              &fenced_sender,
              &peer_receiver,
              1u,
              content,
              sizeof(content),
              &first_sender_slot,
              &peer_receiver_slot,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(prepare_one_sender_for_chunks(
              &peer,
              &fenced,
              &peer_sender,
              &fenced_receiver,
              2u,
              content,
              sizeof(content),
              &peer_sender_slot,
              &ready_receiver_slot,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(deliver_all_chunks_without_finalize(
              &peer,
              &fenced,
              &peer_sender,
              &fenced_receiver,
              peer_sender_slot,
              ready_receiver_slot) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_pump_control(
              peer.owner,
              peer_sender_slot) == NINLIL_MFDT_V1_OK);
    CHECK(route_outbound(
              peer.owner,
              peer_sender_slot,
              fenced.owner,
              &fenced_receiver,
              NULL,
              &ready_receiver_slot,
              NULL) == NINLIL_MFDT_V1_OK);
    CHECK(route_outbound(
              fenced.owner,
              ready_receiver_slot,
              peer.owner,
              &peer_sender,
              NULL,
              NULL,
              NULL) == NINLIL_MFDT_V1_OK);
    rc = ninlil_mfdt_v1_host_receiver_publication_view(
        fenced.owner,
        ready_receiver_slot,
        &published_content,
        &published_len,
        publication_token,
        &acceptance_generation);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)snapshot_owner(fenced.owner, &header, slots);
        (void)fprintf(
            stderr,
            "pre-CU publication rc=%d slot=%u role=%u occupied=%u "
            "phase=%u engine_active=%u\n",
            rc,
            (unsigned)ready_receiver_slot,
            (unsigned)slots[ready_receiver_slot].role,
            (unsigned)slots[ready_receiver_slot].occupied,
            (unsigned)slots[ready_receiver_slot].pipeline_phase,
            (unsigned)slots[ready_receiver_slot].engine_active);
    }
    CHECK(rc == NINLIL_MFDT_V1_OK);
    CHECK(published_content != NULL);
    CHECK(published_len == sizeof(content));
    CHECK(acceptance_generation != 0ull);

    CHECK(ninlil_mfdt_v1_host_store_fault_next(
              fenced.store,
              NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
              NINLIL_STORAGE_COMMIT_UNKNOWN,
              NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NEW));
    rc = sender_open(
        &fenced,
        &fenced_sender,
        3u,
        content,
        sizeof(content),
        803u,
        &failed_slot);
    CHECK(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN);
    CHECK(failed_slot == 0xeeu);
    CHECK(snapshot_owner(fenced.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.inventory_uncertain == 1u);
    CHECK(header.full_locked == 0u);

    fenced_before = (ninlil_mfdt_v1_host_owner_t *)malloc(
        sizeof(*fenced_before));
    cold_owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*cold_owner));
    CHECK(fenced_before != NULL && cold_owner != NULL);
    (void)memcpy(fenced_before, fenced.owner, sizeof(*fenced_before));
    CHECK(store_inventory(
              &fenced,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);

    make_tid(transfer_id, 1u);
    wire.message_type = NINLIL_MFDT_V1_MSG_CHUNK_ACCEPT;
    wire.request_id = 900u;
    wire.body = transfer_id;
    wire.body_len = sizeof(transfer_id);
    (void)memset(&response, 0xa5, sizeof(response));
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fenced.owner,
              &fenced_sender,
              &wire,
              &response,
              NULL) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(response.message_type == 0u);
    CHECK(ninlil_mfdt_v1_host_pump_control(
              fenced.owner,
              first_sender_slot) == NINLIL_MFDT_V1_ERR_STATE);
    failed_slot = 0xaau;
    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              fenced.owner,
              &failed_slot) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(failed_slot == 0xffu);
    frame_len = 91u;
    CHECK(ninlil_mfdt_v1_host_take_outbound_ncl1(
              fenced.owner,
              first_sender_slot,
              frame,
              sizeof(frame),
              &frame_len) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(frame_len == 91u);
    CHECK(ninlil_mfdt_v1_host_tick(
              fenced.owner,
              7000ull) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(ninlil_mfdt_v1_host_finish_terminal(
              fenced.owner,
              first_sender_slot) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(ninlil_mfdt_v1_host_gc(
              fenced.owner,
              7000ull) == NINLIL_MFDT_V1_ERR_STATE);
    published_content = NULL;
    published_len = 0u;
    acceptance_generation = 0ull;
    CHECK(ninlil_mfdt_v1_host_receiver_publication_view(
              fenced.owner,
              ready_receiver_slot,
              &published_content,
              &published_len,
              publication_token,
              &acceptance_generation) == NINLIL_MFDT_V1_ERR_STATE);
    (void)memset(publication_evidence, 0x55, sizeof(publication_evidence));
    CHECK(ninlil_mfdt_v1_host_receiver_commit_publication(
              fenced.owner,
              ready_receiver_slot,
              publication_token,
              publication_evidence) == NINLIL_MFDT_V1_ERR_STATE);
    failed_slot = 0xbbu;
    CHECK(sender_open(
              &fenced,
              &fenced_sender,
              4u,
              content,
              sizeof(content),
              804u,
              &failed_slot) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(failed_slot == 0xbbu);
    CHECK(memcmp(
              fenced.owner,
              fenced_before,
              sizeof(*fenced_before)) == 0);
    CHECK(store_inventory(
              &fenced,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before);
    CHECK(fulls_after == fulls_before);

    CHECK(ninlil_mfdt_v1_host_owner_init(
              cold_owner,
              &fenced.port,
              &fenced.config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(cold_owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.inventory_uncertain == 0u);
    CHECK(header.active_count == 3u);
    CHECK(header.committed_keys == 6u);
    CHECK(header.tracked_groups == 3u);

    free(cold_owner);
    free(fenced_before);
    host_fixture_destroy(&peer);
    host_fixture_destroy(&fenced);
    return 0;
}

static int test_snapshot_recovery_toctou(void)
{
    mfdt_v1_typed_mutation_provider_t *provider;
    ninlil_mfdt_v1_store_port_t port;
    ninlil_mfdt_v1_host_owner_t *seed_owner;
    ninlil_mfdt_v1_host_owner_t *recovered_owner;
    ninlil_mfdt_v1_config_t config;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_open_metadata_t metadata;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint8_t transfer_id[16];
    uint8_t local_runtime[16];
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t content[32];
    uint8_t *active_record;
    uint32_t active_len = 0u;
    int present = 0;
    uint8_t slot = 0xffu;
    int recover_rc;

    provider = mfdt_v1_typed_mutation_provider_create();
    seed_owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*seed_owner));
    recovered_owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*recovered_owner));
    active_record = (uint8_t *)malloc(
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    CHECK(provider != NULL);
    CHECK(seed_owner != NULL && recovered_owner != NULL);
    CHECK(active_record != NULL);
    (void)memset(&port, 0, sizeof(port));
    make_config(&config);
    make_bind(
        &bind,
        0x90u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0x901122ull);
    make_tid(transfer_id, 1u);
    make_endpoint(local_runtime, 0xe0u);
    make_metadata(
        &metadata,
        &config,
        local_runtime,
        bind.peer_endpoint_id,
        1u);
    (void)memset(content, 0x39, sizeof(content));
    CHECK(mfdt_v1_typed_mutation_provider_open_port(
              provider,
              &port) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              seed_owner,
              &port,
              &config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(seed_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(seed_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_sender_open_with_metadata(
              seed_owner,
              &bind,
              transfer_id,
              content,
              sizeof(content),
              &metadata,
              500u,
              &slot) == NINLIL_MFDT_V1_OK);
    (void)memcpy(key, "NM3S", 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &port,
              key,
              active_record,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &active_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1 && active_len != 0u);
    active_record[active_len - 1u] ^= 0xffu;
    CHECK(mfdt_v1_typed_mutation_provider_arm_snapshot_close_mutation(
              provider,
              key,
              active_record,
              active_len,
              1));
    CHECK(ninlil_mfdt_v1_host_owner_init(
              recovered_owner,
              &port,
              &config) == NINLIL_MFDT_V1_OK);
    recover_rc =
        ninlil_mfdt_v1_host_owner_recover(recovered_owner);
    CHECK(
        mfdt_v1_typed_mutation_provider_ro_begin_count(provider) ==
        1u);
    CHECK(recover_rc == NINLIL_MFDT_V1_OK ||
          recover_rc == NINLIL_MFDT_V1_ERR_CORRUPT ||
          recover_rc == NINLIL_MFDT_V1_ERR_STORAGE);
    CHECK(snapshot_owner(recovered_owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    if (recover_rc == NINLIL_MFDT_V1_OK) {
        CHECK(header.recovered == 1u);
        CHECK(header.active_count == 1u);
        CHECK(slots[0].occupied == 1u);
        CHECK(memcmp(slots[0].transfer_id, transfer_id, 16u) == 0);
    } else {
        CHECK(header.recovered == 0u);
        CHECK(header.active_count == 0u);
        CHECK(slots[0].occupied == 0u);
    }
    mfdt_v1_typed_mutation_provider_close_port(provider, &port);
    mfdt_v1_typed_mutation_provider_destroy(provider);
    free(active_record);
    free(recovered_owner);
    free(seed_owner);
    return 0;
}

static int expect_cold_recovery_failure(
    host_fixture_t *fixture,
    int expected_rc)
{
    ninlil_mfdt_v1_host_owner_t *owner = NULL;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint8_t slot;
    int rc;

    owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*owner));
    CHECK(owner != NULL);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              owner,
              &fixture->port,
              &fixture->config) == NINLIL_MFDT_V1_OK);
    rc = ninlil_mfdt_v1_host_owner_recover(owner);
    CHECK(rc == expected_rc);
    CHECK(snapshot_owner(owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.recovered == 0u);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 0u);
    CHECK(header.committed_keys == 0u);
    for (slot = 0u; slot < 4u; ++slot) {
        CHECK(slots[slot].occupied == 0u);
        CHECK(slots[slot].bind_valid == 0u);
    }
    free(owner);
    return 0;
}

static int test_recovery_semantic_and_active_ceiling(void)
{
    host_fixture_t fixture;
    uint8_t *record = NULL;
    uint8_t transfer_id[16];
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];
    uint32_t record_len = 0u;
    int present = 0;
    uint8_t tag;

    /*
     * Five individually valid active groups exceed the exact four-slot Host
     * profile.  Recovery must publish no partial first-four inventory.
     */
    CHECK(host_fixture_prepare(&fixture, 0));
    for (tag = 1u; tag <= 5u; ++tag) {
        CHECK(seed_sender_active_rows(
                  &fixture,
                  tag,
                  1,
                  1) == NINLIL_MFDT_V1_OK);
    }
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CAPACITY) == 0);
    host_fixture_destroy(&fixture);

    /* One transfer ID may never have active and terminal truth together. */
    CHECK(host_fixture_prepare(&fixture, 0));
    CHECK(seed_sender_active_rows(
              &fixture,
              1u,
              1,
              1) == NINLIL_MFDT_V1_OK);
    CHECK(seed_terminal_rows(
              &fixture,
              1u,
              1,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CORRUPT) == 0);
    host_fixture_destroy(&fixture);

    /* Sender and receiver active rows for one ID are duplicate live truth. */
    CHECK(host_fixture_prepare(&fixture, 0));
    CHECK(seed_sender_active_rows(
              &fixture,
              2u,
              1,
              1) == NINLIL_MFDT_V1_OK);
    CHECK(seed_receiver_active_rows(
              &fixture,
              2u,
              1,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CORRUPT) == 0);
    host_fixture_destroy(&fixture);

    CHECK(host_fixture_prepare(&fixture, 0));
    CHECK(seed_sender_active_rows(
              &fixture,
              3u,
              1,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CORRUPT) == 0);
    host_fixture_destroy(&fixture);

    CHECK(host_fixture_prepare(&fixture, 0));
    CHECK(seed_terminal_rows(
              &fixture,
              4u,
              1,
              0) == NINLIL_MFDT_V1_OK);
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CORRUPT) == 0);
    host_fixture_destroy(&fixture);

    record = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    CHECK(record != NULL);

    /* Invalid active session generation with repaired header/record CRCs. */
    CHECK(host_fixture_prepare(&fixture, 0));
    CHECK(seed_sender_active_rows(
              &fixture,
              5u,
              1,
              1) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 5u);
    (void)memcpy(key, "NM3S", 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &fixture.port,
              key,
              record,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &record_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1 && record_len >= 312u);
    ninlil_mfdt_v1_put_u32(record + 300u, 0u);
    ninlil_mfdt_v1_put_u32(
        record + 304u,
        ninlil_mfdt_v1_crc32c(record, 304u));
    ninlil_mfdt_v1_put_u32(
        record + record_len - 4u,
        ninlil_mfdt_v1_crc32c(record, record_len - 4u));
    CHECK(fixture_put_raw_row(
              &fixture,
              key,
              record,
              record_len) == NINLIL_MFDT_V1_OK);
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CORRUPT) == 0);
    host_fixture_destroy(&fixture);

    /* NRC1 occupied count cannot claim an all-zero slot, even with CRCs. */
    CHECK(host_fixture_prepare(&fixture, 0));
    CHECK(seed_sender_active_rows(
              &fixture,
              6u,
              1,
              1) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 6u);
    (void)memcpy(key, "NRC1", 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &fixture.port,
              key,
              record,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &record_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(record_len == NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    ninlil_mfdt_v1_put_u16(record + 30u, 1u);
    ninlil_mfdt_v1_put_u32(record + 32u, 1u);
    ninlil_mfdt_v1_put_u32(
        record + 36u,
        ninlil_mfdt_v1_crc32c(record, 36u));
    ninlil_mfdt_v1_put_u32(
        record + record_len - 4u,
        ninlil_mfdt_v1_crc32c(record, record_len - 4u));
    CHECK(fixture_put_raw_row(
              &fixture,
              key,
              record,
              record_len) == NINLIL_MFDT_V1_OK);
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CORRUPT) == 0);
    host_fixture_destroy(&fixture);

    /* Invalid terminal class with a repaired NM30 CRC remains corrupt. */
    CHECK(host_fixture_prepare(&fixture, 0));
    CHECK(seed_terminal_rows(
              &fixture,
              7u,
              1,
              1) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 7u);
    (void)memcpy(key, "NM30", 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &fixture.port,
              key,
              record,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &record_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(record_len == NINLIL_MFDT_V1_NM30_BYTES);
    ninlil_mfdt_v1_put_u16(record + 60u, 0xffffu);
    ninlil_mfdt_v1_put_u32(
        record + 160u,
        ninlil_mfdt_v1_crc32c(record, 160u));
    CHECK(fixture_put_raw_row(
              &fixture,
              key,
              record,
              record_len) == NINLIL_MFDT_V1_OK);
    CHECK(expect_cold_recovery_failure(
              &fixture,
              NINLIL_MFDT_V1_ERR_CORRUPT) == 0);
    host_fixture_destroy(&fixture);

    free(record);
    return 0;
}

static int test_gc_concurrent_row_mutation_fail_closed(void)
{
    mfdt_v1_typed_mutation_provider_t *provider = NULL;
    ninlil_mfdt_v1_store_port_t port;
    ninlil_mfdt_v1_host_owner_t *owner = NULL;
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    ninlil_mfdt_v1_response_t response;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint16_t open_len = 0u;
    uint8_t slot = 0xffu;
    uint8_t discard[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    size_t discard_len = 0u;
    uint8_t transfer_id[16];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1[NINLIL_MFDT_V1_NRC1_VALUE_BYTES];
    uint32_t nrc1_len = 0u;
    int present = 0;
    uint32_t keys_before = 0u;
    uint32_t keys_after = 0u;
    uint64_t bytes_before = 0ull;
    uint64_t bytes_after = 0ull;
    uint64_t generation_before = 0ull;
    uint64_t generation_after = 0ull;
    uint64_t fulls_before = 0ull;
    uint64_t fulls_after = 0ull;
    uint64_t ro_before;

    (void)memset(&fixture, 0, sizeof(fixture));
    (void)memset(&port, 0, sizeof(port));
    provider = mfdt_v1_typed_mutation_provider_create();
    owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*owner));
    CHECK(provider != NULL && owner != NULL);
    CHECK(mfdt_v1_typed_mutation_provider_open_port(
              provider,
              &port) == NINLIL_MFDT_V1_OK);
    fixture.port = port;
    fixture.owner = owner;
    make_config(&fixture.config);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              owner,
              &port,
              &fixture.config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(owner) ==
          NINLIL_MFDT_V1_OK);
    make_bind(
        &bind,
        0x92u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x929292ull);
    CHECK(receiver_open_body(
              &fixture,
              &bind,
              9u,
              900u,
              &slot,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(slot == 0u);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT);
    CHECK(ninlil_mfdt_v1_host_take_outbound_ncl1(
              owner,
              slot,
              discard,
              sizeof(discard),
              &discard_len) == NINLIL_MFDT_V1_OK);
    CHECK(discard_len != 0u);
    CHECK(receiver_abort_slot(
              &fixture,
              &bind,
              slot,
              open,
              901u) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 1u);
    CHECK(header.committed_keys == 2u);
    CHECK(slots[0].occupied == 0u);

    make_tid(transfer_id, 9u);
    (void)memcpy(nrc1_key, "NRC1", 4u);
    (void)memcpy(nrc1_key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &port,
              nrc1_key,
              nrc1,
              sizeof(nrc1),
              &nrc1_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(nrc1_len == NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    CHECK(mfdt_v1_typed_mutation_provider_inventory(
              provider,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    nrc1[nrc1_len - 1u] ^= 0x01u;
    CHECK(mfdt_v1_typed_mutation_provider_arm_snapshot_close_mutation(
              provider,
              nrc1_key,
              nrc1,
              nrc1_len,
              0));
    ro_before =
        mfdt_v1_typed_mutation_provider_ro_begin_count(provider);

    /*
     * GC selects NM30 and its paired NRC1 from one RO snapshot.  The row is
     * replaced after that snapshot closes, before the RW erase transaction.
     * The bit-exact RW re-read must detect the race and erase neither row.
     */
    CHECK(ninlil_mfdt_v1_host_gc(
              owner,
              1000ull + NINLIL_MFDT_V1_RETENTION_MS_DEFAULT) ==
          NINLIL_MFDT_V1_ERR_BUSY);
    CHECK(
        mfdt_v1_typed_mutation_provider_ro_begin_count(provider) ==
        ro_before + 1ull);
    CHECK(mfdt_v1_typed_mutation_provider_inventory(
              provider,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before + 1ull);
    CHECK(fulls_after == fulls_before + 1ull);
    CHECK(snapshot_owner(owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.inventory_uncertain == 0u);
    CHECK(header.tracked_groups == 1u);
    CHECK(header.committed_keys == 2u);

    mfdt_v1_typed_mutation_provider_close_port(provider, &port);
    mfdt_v1_typed_mutation_provider_destroy(provider);
    free(owner);
    return 0;
}

static int test_post_start_allocator_trap_end_to_end(void)
{
    host_fixture_t sender;
    host_fixture_t receiver;
    ninlil_mfdt_v1_host_bind_t sender_bind;
    ninlil_mfdt_v1_host_bind_t receiver_bind;
    ninlil_mfdt_v1_host_owner_t *cold_owner = NULL;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint8_t content[1800];
    uint8_t transfer_id[16];
    uint8_t sender_slot = 0xffu;
    uint8_t receiver_slot = 0xffu;
    uint8_t selected = 0xffu;
    uint8_t active_slot = 0xffu;
    uint64_t allocations_before;
    decoded_frame_t retry_offer;

    CHECK(host_fixture_prepare(&sender, 1));
    CHECK(host_fixture_prepare(&receiver, 1));
    cold_owner = (ninlil_mfdt_v1_host_owner_t *)calloc(
        1u,
        sizeof(*cold_owner));
    CHECK(cold_owner != NULL);
    make_bind(
        &sender_bind,
        0xb7u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0xb7b7b7ull);
    make_bind(
        &receiver_bind,
        0xe0u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xb7b7b7ull);
    (void)memset(content, 0x7bu, sizeof(content));

    allocations_before =
        ninlil_mfdt_v1_target_zalloc_call_count();
    ninlil_mfdt_v1_target_zalloc_force_fail(1);

    /* Admission plus OPEN/PAGE progress under the post-start trap. */
    CHECK(prepare_one_sender_for_chunks(
              &sender,
              &receiver,
              &sender_bind,
              &receiver_bind,
              7u,
              content,
              sizeof(content),
              &sender_slot,
              &receiver_slot,
              0) == NINLIL_MFDT_V1_OK);

    /* Scheduler plus a real response-timeout retry under the same trap. */
    CHECK(ninlil_mfdt_v1_host_schedule_one_chunk(
              sender.owner,
              &selected) == NINLIL_MFDT_V1_OK);
    CHECK(selected == sender_slot);
    CHECK(decode_outbound(
              sender.owner,
              sender_slot,
              &retry_offer) == NINLIL_MFDT_V1_OK);
    CHECK(
        retry_offer.wire.message_type ==
        NINLIL_MFDT_V1_MSG_CHUNK_OFFER);
    CHECK(ninlil_mfdt_v1_host_tick(
              sender.owner,
              6001ull) == NINLIL_MFDT_V1_OK);
    CHECK(route_outbound(
              sender.owner,
              sender_slot,
              receiver.owner,
              &receiver_bind,
              NULL,
              &receiver_slot,
              NULL) == NINLIL_MFDT_V1_OK);
    CHECK(route_outbound(
              receiver.owner,
              receiver_slot,
              sender.owner,
              &sender_bind,
              NULL,
              NULL,
              NULL) == NINLIL_MFDT_V1_OK);

    /* Remaining progress, publication, terminalization, and GC. */
    CHECK(complete_chunk_ready_transfer(
              &sender,
              &receiver,
              &sender_bind,
              &receiver_bind,
              sender_slot,
              receiver_slot) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_gc(
              receiver.owner,
              1000ull + NINLIL_MFDT_V1_RETENTION_MS_DEFAULT) ==
          NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(receiver.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.tracked_groups == 0u);
    CHECK(header.committed_keys == 0u);

    /*
     * Leave one active sender, then reconstruct and exactly rebind it in a
     * cold owner.  Recovery/start/rebind also remain allocation-free.
     */
    CHECK(sender_open(
              &sender,
              &sender_bind,
              9u,
              content,
              sizeof(content),
              909u,
              &active_slot) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_init(
              cold_owner,
              &sender.port,
              &sender.config) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_recover(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_owner_start(cold_owner) ==
          NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 9u);
    CHECK(ninlil_mfdt_v1_host_rebind_recovered(
              cold_owner,
              transfer_id,
              &sender_bind) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(cold_owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 1u);
    CHECK(slots[0].occupied == 1u);
    CHECK(slots[0].bind_valid == 1u);
    CHECK(
        ninlil_mfdt_v1_target_zalloc_call_count() ==
        allocations_before);

    ninlil_mfdt_v1_target_zalloc_force_fail(0);
    free(cold_owner);
    host_fixture_destroy(&receiver);
    host_fixture_destroy(&sender);
    return 0;
}

static int reject_body_is_exact(
    const uint8_t body[60],
    const uint8_t expected_bind52[52],
    uint16_t stage,
    uint16_t reject_code)
{
    static const uint8_t zero_reserved[4] = {0u, 0u, 0u, 0u};

    return body != NULL && expected_bind52 != NULL &&
           memcmp(body, expected_bind52, 52u) == 0 &&
           ninlil_mfdt_v1_get_u16(body + 52u) == stage &&
           ninlil_mfdt_v1_get_u16(body + 54u) == reject_code &&
           memcmp(body + 56u, zero_reserved, sizeof(zero_reserved)) == 0;
}

static int busy_body_is_exact(
    const uint8_t body[60],
    const uint8_t expected_bind52[52],
    uint16_t stage)
{
    static const uint8_t zero_tail[6] = {
        0u, 0u, 0u, 0u, 0u, 0u
    };

    return body != NULL && expected_bind52 != NULL &&
           memcmp(body, expected_bind52, 52u) == 0 &&
           ninlil_mfdt_v1_get_u16(body + 52u) == stage &&
           memcmp(body + 54u, zero_tail, sizeof(zero_tail)) == 0;
}

static int response_is_canonical_empty(
    const ninlil_mfdt_v1_response_t *response)
{
    return response != NULL &&
           response->message_type == 0u &&
           response->body_len == 0u &&
           response->reject_code == 0u &&
           response->from_nrc1_hit == 0u &&
           response->state_mutation == 0u &&
           response->full_count == 0u;
}

static int snapshots_equal_except_control_pending(
    const ninlil_mfdt_v1_host_header_snapshot_t *left_header,
    const ninlil_mfdt_v1_host_slot_snapshot_t left_slots[4],
    const ninlil_mfdt_v1_host_header_snapshot_t *right_header,
    const ninlil_mfdt_v1_host_slot_snapshot_t right_slots[4])
{
    ninlil_mfdt_v1_host_header_snapshot_t left;
    ninlil_mfdt_v1_host_header_snapshot_t right;

    if (left_header == NULL || left_slots == NULL ||
        right_header == NULL || right_slots == NULL) {
        return 0;
    }
    left = *left_header;
    right = *right_header;
    left.control_outbox_pending = 0u;
    right.control_outbox_pending = 0u;
    return memcmp(&left, &right, sizeof(left)) == 0 &&
           memcmp(
               left_slots,
               right_slots,
               sizeof(*left_slots) * 4u) == 0;
}

static int test_host_semantic_reject_outbox_contract(void)
{
    host_fixture_t fixture;
    host_fixture_t capacity_fixture;
    host_fixture_t policy_fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_host_bind_t sender_binds[4];
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_wire_view_t wire;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_header_snapshot_t header_before;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    ninlil_mfdt_v1_host_slot_snapshot_t slots_before[4];
    decoded_frame_t decoded;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t expected_bind52[52];
    uint8_t foreign_epoch[16];
    uint8_t page[92];
    uint8_t chunk[97];
    uint8_t content[16];
    uint8_t slot = 0xffu;
    uint8_t sender_slot = 0xffu;
    uint16_t open_len = 0u;
    uint8_t index;
    uint32_t keys_before = 0u;
    uint32_t keys_after = 0u;
    uint64_t bytes_before = 0ull;
    uint64_t bytes_after = 0ull;
    uint64_t generation_before = 0ull;
    uint64_t generation_after = 0ull;
    uint64_t fulls_before = 0ull;
    uint64_t fulls_after = 0ull;
    int rc;

    CHECK(host_fixture_prepare(&fixture, 1));
    make_bind(
        &bind,
        0x9au,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x9a9a9aull);
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(
              fixture.owner,
              &header_before,
              slots_before) == NINLIL_MFDT_V1_OK);

    /*
     * A valid same-epoch OPEN whose deadline equals now is a semantic
     * rejection, not malformed input.  Host must retain its exact 60-byte
     * REJECT only in the independent control outbox; active slots and the
     * allocation cursor stay untouched.
     */
    CHECK(build_open_body_with_deadline(
              &bind,
              1u,
              fixture.config.local_clock_epoch.bytes,
              fixture.config.now_ms,
              open,
              &open_len) == NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 701u;
    wire.body = open;
    wire.body_len = open_len;
    (void)memset(&response, 0xa5, sizeof(response));
    slot = 0xffu;
    rc = ninlil_mfdt_v1_host_on_wire(
        fixture.owner,
        &bind,
        &wire,
        &response,
        &slot);
    if (rc != NINLIL_MFDT_V1_OK) {
        (void)fprintf(
            stderr,
            "fresh deadline reject rc=%d type=%u len=%u code=%u slot=%u\n",
            rc,
            (unsigned)response.message_type,
            (unsigned)response.body_len,
            (unsigned)response.reject_code,
            (unsigned)slot);
    }
    CHECK(rc == NINLIL_MFDT_V1_OK);
    CHECK(slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(response.body_len == 60u);
    CHECK(response.reject_code == NINLIL_MFDT_V1_REJ_EXPIRED);
    CHECK(response.state_mutation == 0u);
    CHECK(response.full_count == 0u);
    CHECK(reject_body_is_exact(
              response.body,
              expected_bind52,
              1u,
              NINLIL_MFDT_V1_REJ_EXPIRED));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.control_outbox_pending == 1u);
    CHECK(snapshots_equal_except_control_pending(
              &header,
              slots,
              &header_before,
              slots_before));
    CHECK(decode_outbound(
              fixture.owner,
              NINLIL_MFDT_V1_HOST_CONTROL_ROUTE,
              &decoded) == NINLIL_MFDT_V1_OK);
    CHECK(decoded.wire.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(decoded.wire.request_id == wire.request_id);
    CHECK(decoded.wire.body_len == 60u);
    CHECK(reject_body_is_exact(
              decoded.wire.body,
              expected_bind52,
              1u,
              NINLIL_MFDT_V1_REJ_EXPIRED));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.control_outbox_pending == 0u);
    CHECK(memcmp(&header, &header_before, sizeof(header)) == 0);
    CHECK(memcmp(slots, slots_before, sizeof(slots)) == 0);

    /*
     * A foreign deadline epoch is the projection/policy STATE rejection and
     * obeys the same independent control-outbox ownership rule.
     */
    (void)memset(foreign_epoch, 0xd3, sizeof(foreign_epoch));
    CHECK(memcmp(
              foreign_epoch,
              fixture.config.local_clock_epoch.bytes,
              sizeof(foreign_epoch)) != 0);
    CHECK(build_open_body_with_deadline(
              &bind,
              2u,
              foreign_epoch,
              fixture.config.now_ms + 600000ull,
              open,
              &open_len) == NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);
    wire.request_id = 702u;
    wire.body = open;
    wire.body_len = open_len;
    (void)memset(&response, 0xa5, sizeof(response));
    slot = 0xffu;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(response.body_len == 60u);
    CHECK(response.reject_code == NINLIL_MFDT_V1_REJ_STATE);
    CHECK(response.state_mutation == 0u);
    CHECK(response.full_count == 0u);
    CHECK(reject_body_is_exact(
              response.body,
              expected_bind52,
              1u,
              NINLIL_MFDT_V1_REJ_STATE));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.control_outbox_pending == 1u);
    CHECK(snapshots_equal_except_control_pending(
              &header,
              slots,
              &header_before,
              slots_before));
    CHECK(decode_outbound(
              fixture.owner,
              NINLIL_MFDT_V1_HOST_CONTROL_ROUTE,
              &decoded) == NINLIL_MFDT_V1_OK);
    CHECK(reject_body_is_exact(
              decoded.wire.body,
              expected_bind52,
              1u,
              NINLIL_MFDT_V1_REJ_STATE));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.control_outbox_pending == 0u);
    CHECK(memcmp(&header, &header_before, sizeof(header)) == 0);
    CHECK(memcmp(slots, slots_before, sizeof(slots)) == 0);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before);
    CHECK(fulls_after == fulls_before);

    /*
     * An unbound OPEN shorter than its 234-byte fixed prefix is malformed
     * before admission: no route, no outbox, no
     * response publication, and no store mutation.
     */
    wire.request_id = 703u;
    wire.body = open;
    wire.body_len = 233u;
    (void)memset(&response, 0xa5, sizeof(response));
    slot = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_ERR_PARAM);
    CHECK(slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE);
    CHECK(response_is_canonical_empty(&response));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(memcmp(&header, &header_before, sizeof(header)) == 0);
    CHECK(memcmp(slots, slots_before, sizeof(slots)) == 0);

    /*
     * Admit one ordinary receiver OPEN, then submit validly bound PAGE and
     * CHUNK requests in semantically invalid order.  Each reject is cached by
     * one NRC1 FULL, while the active slot and exact NCL1 outbox survive.
     */
    CHECK(build_open_body(
              &fixture.config,
              &bind,
              3u,
              open,
              &open_len) == NINLIL_MFDT_V1_OK);
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 704u;
    wire.body = open;
    wire.body_len = open_len;
    slot = 0xffu;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT);
    CHECK(decode_outbound(
              fixture.owner,
              slot,
              &decoded) == NINLIL_MFDT_V1_OK);

    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);
    (void)memset(page, 0, sizeof(page));
    (void)memcpy(page, expected_bind52, 52u);
    ninlil_mfdt_v1_put_u16(page + 52u, 1u);
    ninlil_mfdt_v1_put_u16(
        page + 54u,
        ninlil_mfdt_v1_get_u16(open + 28u));
    wire.message_type = NINLIL_MFDT_V1_MSG_MANIFEST_PAGE;
    wire.request_id = 705u;
    wire.body = page;
    wire.body_len = sizeof(page);
    (void)memset(&response, 0xa5, sizeof(response));
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(response.body_len == 60u);
    CHECK(response.reject_code == NINLIL_MFDT_V1_REJ_LAYOUT);
    CHECK(response.state_mutation == 1u);
    CHECK(response.full_count == 1u);
    CHECK(reject_body_is_exact(
              response.body,
              expected_bind52,
              2u,
              NINLIL_MFDT_V1_REJ_LAYOUT));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[slot].occupied == 1u);
    CHECK(slots[slot].active_accounted == 1u);
    CHECK(slots[slot].outbox_pending == 1u);
    CHECK(decode_outbound(
              fixture.owner,
              slot,
              &decoded) == NINLIL_MFDT_V1_OK);
    CHECK(reject_body_is_exact(
              decoded.wire.body,
              expected_bind52,
              2u,
              NINLIL_MFDT_V1_REJ_LAYOUT));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[slot].occupied == 1u);
    CHECK(slots[slot].outbox_pending == 0u);

    (void)memset(chunk, 0, sizeof(chunk));
    (void)memcpy(chunk, expected_bind52, 52u);
    ninlil_mfdt_v1_put_u16(chunk + 52u, 0u);
    ninlil_mfdt_v1_put_u16(
        chunk + 54u,
        ninlil_mfdt_v1_get_u16(open + 26u));
    ninlil_mfdt_v1_put_u32(chunk + 56u, 0u);
    ninlil_mfdt_v1_put_u16(chunk + 60u, 1u);
    chunk[96] = 3u;
    ninlil_mfdt_v1_sha256(chunk + 96u, 1u, chunk + 64u);
    wire.message_type = NINLIL_MFDT_V1_MSG_CHUNK_OFFER;
    wire.request_id = 706u;
    wire.body = chunk;
    wire.body_len = sizeof(chunk);
    (void)memset(&response, 0xa5, sizeof(response));
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(response.body_len == 60u);
    CHECK(response.reject_code == NINLIL_MFDT_V1_REJ_STATE);
    CHECK(response.state_mutation == 1u);
    CHECK(response.full_count == 1u);
    CHECK(reject_body_is_exact(
              response.body,
              expected_bind52,
              3u,
              NINLIL_MFDT_V1_REJ_STATE));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[slot].occupied == 1u);
    CHECK(slots[slot].outbox_pending == 1u);
    CHECK(decode_outbound(
              fixture.owner,
              slot,
              &decoded) == NINLIL_MFDT_V1_OK);
    CHECK(reject_body_is_exact(
              decoded.wire.body,
              expected_bind52,
              3u,
              NINLIL_MFDT_V1_REJ_STATE));
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[slot].occupied == 1u);
    CHECK(slots[slot].outbox_pending == 0u);

    host_fixture_destroy(&fixture);

    /*
     * Policy refusal also owns only the control route.  Owner startup remains
     * valid while fresh OPEN admission is disabled.
     */
    CHECK(host_fixture_prepare_policy_off(&policy_fixture));
    make_bind(
        &bind,
        0x9bu,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0x9b9b9bull);
    CHECK(build_open_body(
              &policy_fixture.config,
              &bind,
              4u,
              open,
              &open_len) == NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);
    CHECK(snapshot_owner(
              policy_fixture.owner,
              &header_before,
              slots_before) == NINLIL_MFDT_V1_OK);
    CHECK(store_inventory(
              &policy_fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 707u;
    wire.body = open;
    wire.body_len = open_len;
    (void)memset(&response, 0xa5, sizeof(response));
    slot = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              policy_fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(response.body_len == 60u);
    CHECK(response.reject_code == NINLIL_MFDT_V1_REJ_UNSUPPORTED);
    CHECK(response.state_mutation == 0u);
    CHECK(response.full_count == 0u);
    CHECK(reject_body_is_exact(
              response.body,
              expected_bind52,
              1u,
              NINLIL_MFDT_V1_REJ_UNSUPPORTED));
    CHECK(snapshot_owner(policy_fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.control_outbox_pending == 1u);
    CHECK(snapshots_equal_except_control_pending(
              &header,
              slots,
              &header_before,
              slots_before));
    CHECK(decode_outbound(
              policy_fixture.owner,
              NINLIL_MFDT_V1_HOST_CONTROL_ROUTE,
              &decoded) == NINLIL_MFDT_V1_OK);
    CHECK(decoded.wire.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(decoded.wire.request_id == wire.request_id);
    CHECK(reject_body_is_exact(
              decoded.wire.body,
              expected_bind52,
              1u,
              NINLIL_MFDT_V1_REJ_UNSUPPORTED));
    CHECK(snapshot_owner(policy_fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(memcmp(&header, &header_before, sizeof(header)) == 0);
    CHECK(memcmp(slots, slots_before, sizeof(slots)) == 0);
    CHECK(store_inventory(
              &policy_fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before);
    CHECK(fulls_after == fulls_before);
    host_fixture_destroy(&policy_fixture);

    /*
     * With all four active slots occupied, a fifth valid fresh receiver OPEN
     * is an exact BUSY on the control route.  It cannot touch the allocation
     * cursor, any active slot, or the durable provider.
     */
    CHECK(host_fixture_prepare(&capacity_fixture, 1));
    (void)memset(content, 0x6cu, sizeof(content));
    for (index = 0u; index < 4u; ++index) {
        make_bind(
            &sender_binds[index],
            (uint8_t)(0xb0u + index),
            NINLIL_MFDT_V1_HOST_ROLE_SENDER,
            0xb00000ull + index);
        sender_slot = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
        CHECK(sender_open(
                  &capacity_fixture,
                  &sender_binds[index],
                  (uint8_t)(11u + index),
                  content,
                  sizeof(content),
                  (uint64_t)(710u + index),
                  &sender_slot) == NINLIL_MFDT_V1_OK);
        CHECK(sender_slot == index);
    }
    make_bind(
        &bind,
        0xb5u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xb50005ull);
    CHECK(build_open_body(
              &capacity_fixture.config,
              &bind,
              15u,
              open,
              &open_len) == NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);
    CHECK(snapshot_owner(
              capacity_fixture.owner,
              &header_before,
              slots_before) == NINLIL_MFDT_V1_OK);
    CHECK(header_before.active_count == 4u);
    CHECK(store_inventory(
              &capacity_fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 720u;
    wire.body = open;
    wire.body_len = open_len;
    (void)memset(&response, 0xa5, sizeof(response));
    slot = NINLIL_MFDT_V1_HOST_CONTROL_ROUTE;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              capacity_fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(slot == NINLIL_MFDT_V1_HOST_CONTROL_ROUTE);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_BUSY);
    CHECK(response.body_len == 60u);
    CHECK(response.reject_code == NINLIL_MFDT_V1_REJ_CAPACITY);
    CHECK(response.state_mutation == 0u);
    CHECK(response.full_count == 0u);
    CHECK(busy_body_is_exact(response.body, expected_bind52, 1u));
    CHECK(snapshot_owner(capacity_fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.control_outbox_pending == 1u);
    CHECK(snapshots_equal_except_control_pending(
              &header,
              slots,
              &header_before,
              slots_before));
    CHECK(decode_outbound(
              capacity_fixture.owner,
              NINLIL_MFDT_V1_HOST_CONTROL_ROUTE,
              &decoded) == NINLIL_MFDT_V1_OK);
    CHECK(decoded.wire.message_type == NINLIL_MFDT_V1_MSG_BUSY);
    CHECK(decoded.wire.request_id == wire.request_id);
    CHECK(busy_body_is_exact(
              decoded.wire.body,
              expected_bind52,
              1u));
    CHECK(snapshot_owner(capacity_fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(memcmp(&header, &header_before, sizeof(header)) == 0);
    CHECK(memcmp(slots, slots_before, sizeof(slots)) == 0);
    CHECK(store_inventory(
              &capacity_fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before);
    CHECK(bytes_after == bytes_before);
    CHECK(generation_after == generation_before);
    CHECK(fulls_after == fulls_before);
    host_fixture_destroy(&capacity_fixture);
    return 0;
}

static int expect_active_exact_reject(
    host_fixture_t *fixture,
    const ninlil_mfdt_v1_host_bind_t *bind,
    uint8_t expected_slot,
    uint8_t message_type,
    uint64_t request_id,
    const uint8_t *body,
    uint16_t body_len,
    const uint8_t expected_bind52[52],
    uint16_t stage,
    uint16_t reject_code)
{
    ninlil_mfdt_v1_wire_view_t wire;
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    decoded_frame_t decoded;
    uint8_t routed_slot = 0xffu;

    wire.message_type = message_type;
    wire.request_id = request_id;
    wire.body = body;
    wire.body_len = body_len;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture->owner,
              bind,
              &wire,
              &response,
              &routed_slot) == NINLIL_MFDT_V1_OK);
    CHECK(routed_slot == expected_slot);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(response.body_len == 60u);
    CHECK(response.reject_code == reject_code);
    CHECK(response.from_nrc1_hit == 0u);
    CHECK(response.state_mutation == 1u);
    CHECK(response.full_count == 1u);
    CHECK(reject_body_is_exact(
              response.body,
              expected_bind52,
              stage,
              reject_code));
    CHECK(snapshot_owner(fixture->owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count != 0u);
    CHECK(slots[expected_slot].occupied == 1u);
    CHECK(slots[expected_slot].active_accounted == 1u);
    CHECK(slots[expected_slot].outbox_pending == 1u);
    CHECK(decode_outbound(
              fixture->owner,
              expected_slot,
              &decoded) == NINLIL_MFDT_V1_OK);
    CHECK(decoded.wire.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(decoded.wire.request_id == request_id);
    CHECK(decoded.wire.body_len == 60u);
    CHECK(reject_body_is_exact(
              decoded.wire.body,
              expected_bind52,
              stage,
              reject_code));
    CHECK(snapshot_owner(fixture->owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(slots[expected_slot].occupied == 1u);
    CHECK(slots[expected_slot].outbox_pending == 0u);
    return 0;
}

static int test_active_finalize_reject_matrix(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_host_bind_t empty_bind;
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_wire_view_t wire;
    decoded_frame_t decoded;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t empty_open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t expected_bind52[52];
    uint8_t empty_bind52[52];
    uint8_t finalize[92];
    uint16_t open_len = 0u;
    uint16_t empty_open_len = 0u;
    uint8_t slot = 0xffu;
    uint8_t empty_slot = 0xffu;

    CHECK(host_fixture_prepare(&fixture, 1));
    make_bind(
        &bind,
        0xa1u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xa10001ull);
    CHECK(receiver_open_body(
              &fixture,
              &bind,
              21u,
              801u,
              &slot,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT);
    CHECK(decode_outbound(fixture.owner, slot, &decoded) ==
          NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);
    (void)memset(finalize, 0, sizeof(finalize));
    (void)memcpy(finalize, expected_bind52, 52u);
    (void)memcpy(finalize + 52u, open + 32u, 32u);
    ninlil_mfdt_v1_put_u32(
        finalize + 84u,
        ninlil_mfdt_v1_get_u32(open + 20u));

    /* Correct FINALIZE before content verification is an exact STATE reject. */
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_FINALIZE,
              802u,
              finalize,
              sizeof(finalize),
              expected_bind52,
              4u,
              NINLIL_MFDT_V1_REJ_STATE) == 0);

    /* A BIND52-bearing but truncated FINALIZE is cached as exact LAYOUT. */
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_FINALIZE,
              803u,
              finalize,
              (uint16_t)(sizeof(finalize) - 1u),
              expected_bind52,
              4u,
              NINLIL_MFDT_V1_REJ_LAYOUT) == 0);

    /*
     * An empty transfer is content-verified at OPEN, so a wrong whole digest
     * reaches FINALIZE's DIGEST branch without needing any fixture shortcut.
     */
    make_bind(
        &empty_bind,
        0xa2u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xa20002ull);
    CHECK(build_open_body_with_content_and_deadline(
              &empty_bind,
              22u,
              NULL,
              0u,
              fixture.config.local_clock_epoch.bytes,
              fixture.config.now_ms + 600000ull,
              empty_open,
              &empty_open_len) == NINLIL_MFDT_V1_OK);
    wire.message_type = NINLIL_MFDT_V1_MSG_OPEN;
    wire.request_id = 804u;
    wire.body = empty_open;
    wire.body_len = empty_open_len;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &empty_bind,
              &wire,
              &response,
              &empty_slot) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_OPEN_ACCEPT);
    CHECK(decode_outbound(fixture.owner, empty_slot, &decoded) ==
          NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        empty_open,
        ninlil_mfdt_v1_get_u32(empty_open + 16u),
        empty_open + 202u,
        empty_bind52);
    (void)memset(finalize, 0, sizeof(finalize));
    (void)memcpy(finalize, empty_bind52, 52u);
    (void)memcpy(finalize + 52u, empty_open + 32u, 32u);
    finalize[52] ^= 0x80u;
    ninlil_mfdt_v1_put_u32(
        finalize + 84u,
        ninlil_mfdt_v1_get_u32(empty_open + 20u));
    CHECK(expect_active_exact_reject(
              &fixture,
              &empty_bind,
              empty_slot,
              NINLIL_MFDT_V1_MSG_FINALIZE,
              805u,
              finalize,
              sizeof(finalize),
              empty_bind52,
              4u,
              NINLIL_MFDT_V1_REJ_DIGEST) == 0);

    host_fixture_destroy(&fixture);
    return 0;
}

static int test_active_resume_reject_matrix(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_response_t response;
    ninlil_mfdt_v1_wire_view_t wire;
    decoded_frame_t decoded;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t expected_bind52[52];
    uint8_t query[60];
    uint16_t open_len = 0u;
    uint8_t slot = 0xffu;

    CHECK(host_fixture_prepare(&fixture, 1));
    make_bind(
        &bind,
        0xa3u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xa30003ull);
    CHECK(receiver_open_body(
              &fixture,
              &bind,
              23u,
              811u,
              &slot,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(decode_outbound(fixture.owner, slot, &decoded) ==
          NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);

    (void)memset(query, 0, sizeof(query));
    (void)memcpy(query, expected_bind52, 52u);
    ninlil_mfdt_v1_put_u32(query + 52u, 1u);
    query[20] ^= 0x01u;
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_RESUME_QUERY,
              812u,
              query,
              sizeof(query),
              expected_bind52,
              5u,
              NINLIL_MFDT_V1_REJ_LAYOUT) == 0);

    (void)memcpy(query, expected_bind52, 52u);
    ninlil_mfdt_v1_put_u32(query + 52u, 1u);
    ninlil_mfdt_v1_put_u32(query + 56u, 1u);
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_RESUME_QUERY,
              813u,
              query,
              sizeof(query),
              expected_bind52,
              5u,
              NINLIL_MFDT_V1_REJ_LAYOUT) == 0);

    (void)memcpy(query, expected_bind52, 52u);
    ninlil_mfdt_v1_put_u32(query + 52u, 0u);
    ninlil_mfdt_v1_put_u32(query + 56u, 0u);
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_RESUME_QUERY,
              814u,
              query,
              sizeof(query),
              expected_bind52,
              5u,
              NINLIL_MFDT_V1_REJ_STATE) == 0);

    ninlil_mfdt_v1_put_u32(query + 52u, 2u);
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_RESUME_QUERY,
              815u,
              query,
              sizeof(query),
              expected_bind52,
              5u,
              NINLIL_MFDT_V1_REJ_STATE) == 0);

    /* Advance 0 -> 1 -> 2 through durable RESUME_STATE responses. */
    ninlil_mfdt_v1_put_u32(query + 52u, 1u);
    wire.message_type = NINLIL_MFDT_V1_MSG_RESUME_QUERY;
    wire.request_id = 816u;
    wire.body = query;
    wire.body_len = sizeof(query);
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_RESUME_STATE);
    CHECK(response.body_len == 108u);
    CHECK(response.state_mutation == 1u);
    CHECK(response.full_count == 1u);
    CHECK(decode_outbound(fixture.owner, slot, &decoded) ==
          NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_put_u32(query + 52u, 2u);
    wire.request_id = 817u;
    CHECK(ninlil_mfdt_v1_host_on_wire(
              fixture.owner,
              &bind,
              &wire,
              &response,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_RESUME_STATE);
    CHECK(response.body_len == 108u);
    CHECK(decode_outbound(fixture.owner, slot, &decoded) ==
          NINLIL_MFDT_V1_OK);

    /* Generation 1 after durable generation 2 is rollback, not a gap. */
    ninlil_mfdt_v1_put_u32(query + 52u, 1u);
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_RESUME_QUERY,
              818u,
              query,
              sizeof(query),
              expected_bind52,
              5u,
              NINLIL_MFDT_V1_REJ_STATE) == 0);

    host_fixture_destroy(&fixture);
    return 0;
}

static int test_active_abort_reject_matrix(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_response_t response;
    decoded_frame_t decoded;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t expected_bind52[52];
    uint8_t abort_body[76];
    uint16_t open_len = 0u;
    uint8_t slot = 0xffu;

    CHECK(host_fixture_prepare(&fixture, 1));
    make_bind(
        &bind,
        0xa4u,
        NINLIL_MFDT_V1_HOST_ROLE_RECEIVER,
        0xa40004ull);
    CHECK(receiver_open_body(
              &fixture,
              &bind,
              24u,
              821u,
              &slot,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(decode_outbound(fixture.owner, slot, &decoded) ==
          NINLIL_MFDT_V1_OK);
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        expected_bind52);

    (void)memset(abort_body, 0, sizeof(abort_body));
    (void)memcpy(abort_body, expected_bind52, 52u);
    ninlil_mfdt_v1_put_u16(
        abort_body + 52u,
        NINLIL_MFDT_V1_TERM_REASON_OPERATOR);
    ninlil_mfdt_v1_put_u16(abort_body + 54u, 1u);
    (void)memset(abort_body + 56u, 0x41, 16u);
    ninlil_mfdt_v1_put_u32(abort_body + 72u, 1u);
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_ABORT,
              822u,
              abort_body,
              sizeof(abort_body),
              expected_bind52,
              6u,
              NINLIL_MFDT_V1_REJ_LAYOUT) == 0);

    ninlil_mfdt_v1_put_u16(abort_body + 54u, 0u);
    ninlil_mfdt_v1_put_u16(abort_body + 52u, 0u);
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_ABORT,
              823u,
              abort_body,
              sizeof(abort_body),
              expected_bind52,
              6u,
              NINLIL_MFDT_V1_REJ_AUTHORITY) == 0);

    ninlil_mfdt_v1_put_u16(
        abort_body + 52u,
        NINLIL_MFDT_V1_TERM_REASON_OPERATOR);
    ninlil_mfdt_v1_put_u32(abort_body + 72u, 2u);
    CHECK(expect_active_exact_reject(
              &fixture,
              &bind,
              slot,
              NINLIL_MFDT_V1_MSG_ABORT,
              824u,
              abort_body,
              sizeof(abort_body),
              expected_bind52,
              6u,
              NINLIL_MFDT_V1_REJ_STATE) == 0);

    host_fixture_destroy(&fixture);
    return 0;
}

static int test_fresh_sender_disarm_exact_compensation(void)
{
    host_fixture_t fixture;
    ninlil_mfdt_v1_host_bind_t bind;
    ninlil_mfdt_v1_host_header_snapshot_t header;
    ninlil_mfdt_v1_host_slot_snapshot_t slots[4];
    uint8_t content[64];
    uint8_t transfer_id[16];
    uint8_t wrong_id[16];
    uint8_t active_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t discard[NINLIL_MFDT_V1_NCL1_MAX_MSG];
    uint8_t *scratch = NULL;
    uint8_t slot = 0xffu;
    size_t discard_len = 0u;
    uint32_t value_len = 0u;
    uint32_t keys_before = 0u;
    uint32_t keys_after = 0u;
    uint64_t bytes_before = 0ull;
    uint64_t bytes_after = 0ull;
    uint64_t generation_before = 0ull;
    uint64_t generation_after = 0ull;
    uint64_t fulls_before = 0ull;
    uint64_t fulls_after = 0ull;
    int present = 0;
    int rc;

    scratch = (uint8_t *)malloc(NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    CHECK(scratch != NULL);
    (void)memset(content, 0x5au, sizeof(content));

    /* Wrong slot/ID are rejected before a FULL; exact success erases the pair. */
    CHECK(host_fixture_prepare(&fixture, 1));
    make_bind(
        &bind,
        0xb5u,
        NINLIL_MFDT_V1_HOST_ROLE_SENDER,
        0xb50001ull);
    CHECK(sender_open(
              &fixture,
              &bind,
              31u,
              content,
              sizeof(content),
              931u,
              &slot) == NINLIL_MFDT_V1_OK);
    CHECK(slot == 0u);
    make_tid(transfer_id, 31u);
    make_tid(wrong_id, 32u);
    (void)memcpy(active_key, "NM3S", 4u);
    (void)memcpy(active_key + 4u, transfer_id, 16u);
    (void)memcpy(nrc1_key, "NRC1", 4u);
    (void)memcpy(nrc1_key + 4u, transfer_id, 16u);
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    CHECK(keys_before == 2u && bytes_before != 0ull);
    CHECK(ninlil_mfdt_v1_host_disarm_fresh_sender(
              fixture.owner,
              1u,
              transfer_id,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) ==
          NINLIL_MFDT_V1_ERR_STATE);
    CHECK(ninlil_mfdt_v1_host_disarm_fresh_sender(
              fixture.owner,
              slot,
              wrong_id,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) ==
          NINLIL_MFDT_V1_ERR_STATE);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before && bytes_after == bytes_before);
    CHECK(generation_after == generation_before && fulls_after == fulls_before);
    CHECK(ninlil_mfdt_v1_host_disarm_fresh_sender(
              fixture.owner,
              slot,
              transfer_id,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) == NINLIL_MFDT_V1_OK);
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 0u);
    CHECK(header.tracked_groups == 0u);
    CHECK(header.committed_keys == 0u);
    CHECK(header.committed_logical_bytes == 0ull);
    CHECK(header.inventory_uncertain == 0u);
    CHECK(slots[slot].occupied == 0u && slots[slot].engine_active == 0u);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == 0u && bytes_after == 0ull);
    CHECK(generation_after == generation_before + 1ull);
    CHECK(fulls_after == fulls_before + 1ull);
    CHECK(ninlil_mfdt_v1_store_read(
              &fixture.port,
              active_key,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &value_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 0 && value_len == 0u);
    CHECK(ninlil_mfdt_v1_store_read(
              &fixture.port,
              nrc1_key,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &value_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 0 && value_len == 0u);
    host_fixture_destroy(&fixture);

    /* Once OPEN outbox ownership advances, the arm is no longer fresh. */
    CHECK(host_fixture_prepare(&fixture, 1));
    CHECK(sender_open(
              &fixture,
              &bind,
              33u,
              content,
              sizeof(content),
              933u,
              &slot) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 33u);
    CHECK(ninlil_mfdt_v1_host_take_outbound_ncl1(
              fixture.owner,
              slot,
              discard,
              sizeof(discard),
              &discard_len) == NINLIL_MFDT_V1_OK);
    CHECK(discard_len != 0u);
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_disarm_fresh_sender(
              fixture.owner,
              slot,
              transfer_id,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) ==
          NINLIL_MFDT_V1_ERR_STATE);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before && bytes_after == bytes_before);
    CHECK(generation_after == generation_before && fulls_after == fulls_before);
    host_fixture_destroy(&fixture);

    /* A concurrent byte change is detected inside the RW FULL and erases 0. */
    CHECK(host_fixture_prepare(&fixture, 1));
    CHECK(sender_open(
              &fixture,
              &bind,
              34u,
              content,
              sizeof(content),
              934u,
              &slot) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 34u);
    (void)memcpy(active_key, "NM3S", 4u);
    (void)memcpy(active_key + 4u, transfer_id, 16u);
    CHECK(ninlil_mfdt_v1_store_read(
              &fixture.port,
              active_key,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX,
              &value_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1 && value_len > NINLIL_MFDT_V1_ACTIVE_HEADER_BYTES + 4u);
    scratch[value_len - 5u] ^= 0x01u;
    ninlil_mfdt_v1_put_u32(
        scratch + value_len - 4u,
        ninlil_mfdt_v1_crc32c(scratch, value_len - 4u));
    CHECK(fixture_put_raw_row(
              &fixture,
              active_key,
              scratch,
              value_len) == NINLIL_MFDT_V1_OK);
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_disarm_fresh_sender(
              fixture.owner,
              slot,
              transfer_id,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) ==
          NINLIL_MFDT_V1_ERR_BUSY);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before && bytes_after == bytes_before);
    CHECK(generation_after == generation_before && fulls_after == fulls_before);
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 1u && header.inventory_uncertain == 0u);
    host_fixture_destroy(&fixture);

    /* Definite cleanup failure changes no counters and remains retryable. */
    CHECK(host_fixture_prepare(&fixture, 1));
    CHECK(sender_open(
              &fixture,
              &bind,
              35u,
              content,
              sizeof(content),
              935u,
              &slot) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 35u);
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_store_fault_next(
              fixture.store,
              NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
              NINLIL_STORAGE_IO_ERROR,
              NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_NONE));
    CHECK(ninlil_mfdt_v1_host_disarm_fresh_sender(
              fixture.owner,
              slot,
              transfer_id,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) ==
          NINLIL_MFDT_V1_ERR_STORAGE);
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.active_count == 1u && header.tracked_groups == 1u);
    CHECK(header.committed_keys == 2u && header.inventory_uncertain == 0u);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before && bytes_after == bytes_before);
    CHECK(generation_after == generation_before && fulls_after == fulls_before);
    CHECK(ninlil_mfdt_v1_host_disarm_fresh_sender(
              fixture.owner,
              slot,
              transfer_id,
              scratch,
              NINLIL_MFDT_V1_ACTIVE_VALUE_MAX) == NINLIL_MFDT_V1_OK);
    host_fixture_destroy(&fixture);

    /* Cleanup CU OLD retains RAM/counters and marks inventory uncertain. */
    CHECK(host_fixture_prepare(&fixture, 1));
    CHECK(sender_open(
              &fixture,
              &bind,
              36u,
              content,
              sizeof(content),
              936u,
              &slot) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 36u);
    CHECK(store_inventory(
              &fixture,
              &keys_before,
              &bytes_before,
              &generation_before,
              &fulls_before) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_host_store_fault_next(
              fixture.store,
              NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT,
              NINLIL_STORAGE_COMMIT_UNKNOWN,
              NINLIL_MFDT_V1_HOST_STORE_CU_TRUTH_OLD));
    rc = ninlil_mfdt_v1_host_disarm_fresh_sender(
        fixture.owner,
        slot,
        transfer_id,
        scratch,
        NINLIL_MFDT_V1_ACTIVE_VALUE_MAX);
    CHECK(rc == NINLIL_MFDT_V1_ERR_COMMIT_UNKNOWN);
    CHECK(snapshot_owner(fixture.owner, &header, slots) ==
          NINLIL_MFDT_V1_OK);
    CHECK(header.inventory_uncertain == 1u);
    CHECK(header.active_count == 1u && header.tracked_groups == 1u);
    CHECK(header.committed_keys == 2u);
    CHECK(store_inventory(
              &fixture,
              &keys_after,
              &bytes_after,
              &generation_after,
              &fulls_after) == NINLIL_MFDT_V1_OK);
    CHECK(keys_after == keys_before && bytes_after == bytes_before);
    CHECK(generation_after == generation_before && fulls_after == fulls_before);
    host_fixture_destroy(&fixture);

    free(scratch);
    return 0;
}

static int run_witness(const char *name, int (*test)(void))
{
    int rc = test();

    if (rc != 0) {
        (void)printf("WITNESS_FAIL %s\n", name);
        return 1;
    }
    (void)printf("WITNESS_PASS %s\n", name);
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += run_witness(
        "exact_owner_geometry",
        test_exact_owner_geometry);
    failures += run_witness(
        "owner_init_guards_zero_mutation",
        test_owner_init_guards_zero_mutation);
    failures += run_witness(
        "four_slots_and_fifth_atomic",
        test_four_slots_and_fifth_atomic);
    failures += run_witness(
        "duplicate_conflict_unknown_no_allocation",
        test_duplicate_conflict_and_unknown_no_allocation);
    failures += run_witness(
        "lowest_free_after_receiver_abort",
        test_lowest_free_after_receiver_abort);
    failures += run_witness(
        "restart_canonical_rebind_gate",
        test_restart_canonical_and_rebind_gate);
    failures += run_witness(
        "nrc1_fresh_vs_duplicate_signal",
        test_nrc1_fresh_vs_duplicate_signal);
    failures += run_witness(
        "scheduler_round_robin_actual_ncl1",
        test_scheduler_round_robin_actual_ncl1);
    failures += run_witness(
        "peer_fence_exact_release_and_retry",
        test_peer_fence_exact_release_and_retry);
    failures += run_witness(
        "terminal_reject_exact_peer_fence_release",
        test_terminal_reject_exact_peer_fence_release);
    failures += run_witness(
        "bidirectional_complete_retention_gc",
        test_bidirectional_complete_retention_and_gc);
    failures += run_witness(
        "commit_unknown_global_fence_cold_recover",
        test_commit_unknown_global_fence_and_cold_recover);
    failures += run_witness(
        "snapshot_recovery_toctou",
        test_snapshot_recovery_toctou);
    failures += run_witness(
        "recovery_semantic_and_active_ceiling",
        test_recovery_semantic_and_active_ceiling);
    failures += run_witness(
        "gc_concurrent_row_mutation_fail_closed",
        test_gc_concurrent_row_mutation_fail_closed);
    failures += run_witness(
        "post_start_allocator_trap_end_to_end",
        test_post_start_allocator_trap_end_to_end);
    failures += run_witness(
        "host_semantic_reject_outbox_contract",
        test_host_semantic_reject_outbox_contract);
    failures += run_witness(
        "active_finalize_reject_matrix",
        test_active_finalize_reject_matrix);
    failures += run_witness(
        "active_resume_reject_matrix",
        test_active_resume_reject_matrix);
    failures += run_witness(
        "active_abort_reject_matrix",
        test_active_abort_reject_matrix);
    failures += run_witness(
        "fresh_sender_disarm_exact_compensation",
        test_fresh_sender_disarm_exact_compensation);
    ninlil_mfdt_v1_target_zalloc_force_fail(0);
    if (failures != 0) {
        (void)fprintf(
            stderr,
            "mfdt_v1_host_coordinator_acceptance_test FAILED (%d)\n",
            failures);
        return 1;
    }
    (void)printf("mfdt_v1_host_coordinator_acceptance_test OK\n");
    return 0;
}
