/* SPDX-License-Identifier: Apache-2.0
 *
 * Exact request-boundary KATs for the private MFDT Host engine.
 *
 * The fixture binds one engine to the real typed Host provider so terminal
 * transitions can be checked as one FULL containing exactly three mutations:
 * erase active, put NM30, and replace NRC1.  This is Host software evidence,
 * not physical power-cut/HIL or a release-support claim.
 */
#include "mfdt_v1.h"
#include "mfdt_v1_host_store.h"
#include "mfdt_v1_store_port.h"

#include <stdint.h>
#include <stdio.h>
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

#define ARENA_BYTES ((size_t)65536u)
#define RECORD_BYTES ((uint32_t)35216u)
#define NRC1_REGION_BYTES ((uint32_t)15024u)
#define XFER_BYTES ((uint32_t)512u)
#define OPEN_BYTES ((uint32_t)656u)
#define ENTRIES_BYTES                                                        \
    ((uint32_t)NINLIL_MFDT_V1_MAX_CHUNKS * NINLIL_MFDT_V1_ENTRY_BYTES)

#define RECORD_OFFSET ((size_t)0u)
#define NRC1_OFFSET (RECORD_OFFSET + RECORD_BYTES)
#define XFER_OFFSET (NRC1_OFFSET + NRC1_REGION_BYTES)
#define OPEN_OFFSET (XFER_OFFSET + XFER_BYTES)
#define ENTRIES_OFFSET (OPEN_OFFSET + OPEN_BYTES)

typedef union aligned_arena {
    uint64_t align8;
    uint8_t bytes[ARENA_BYTES];
} aligned_arena_t;

typedef struct inventory {
    uint32_t keys;
    uint64_t logical_bytes;
    uint64_t generation;
    uint64_t full_count;
} inventory_t;

typedef struct call_counts {
    uint64_t put;
    uint64_t erase;
    uint64_t commit;
} call_counts_t;

typedef struct engine_fixture {
    ninlil_mfdt_v1_host_store_t *store;
    ninlil_mfdt_v1_store_port_t port;
    ninlil_mfdt_v1_engine_t engine;
    ninlil_mfdt_v1_engine_slot_memory_t memory;
    ninlil_mfdt_v1_config_t config;
    aligned_arena_t arena;
    uint32_t committed_keys;
    uint64_t committed_logical_bytes;
    uint8_t full_locked;
    uint8_t inventory_uncertain;
} engine_fixture_t;

static const uint8_t k_namespace[] = "acceptance.request-kat";
static const uint8_t k_service[] = "binary-transfer.v1";
static const uint8_t k_schema[] = "application-data.v1";

static uint8_t g_active_after[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];
static uint8_t g_nrc1_before[NINLIL_MFDT_V1_NRC1_VALUE_BYTES];
static uint8_t g_nrc1_after[NINLIL_MFDT_V1_NRC1_VALUE_BYTES];
static uint8_t g_nm30[NINLIL_MFDT_V1_NM30_BYTES];

static void make_tid(uint8_t transfer_id[16], uint8_t tag)
{
    (void)memset(transfer_id, 0, 16u);
    transfer_id[15] = tag;
}

static void make_endpoint(uint8_t endpoint[16], uint8_t tag)
{
    size_t index;

    for (index = 0u; index < 16u; ++index) {
        endpoint[index] =
            (uint8_t)(tag + (uint8_t)(index * 3u));
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

static void make_slot_memory(
    ninlil_mfdt_v1_engine_slot_memory_t *memory,
    uint8_t *base)
{
    (void)memset(memory, 0, sizeof(*memory));
    memory->record_memory = base + RECORD_OFFSET;
    memory->record_memory_bytes = RECORD_BYTES;
    memory->nrc1_memory = base + NRC1_OFFSET;
    memory->nrc1_memory_bytes = NRC1_REGION_BYTES;
    memory->xfer_memory = base + XFER_OFFSET;
    memory->xfer_memory_bytes = XFER_BYTES;
    memory->open_staging = base + OPEN_OFFSET;
    memory->open_staging_bytes = OPEN_BYTES;
    memory->entries_staging = base + ENTRIES_OFFSET;
    memory->entries_staging_bytes = ENTRIES_BYTES;
}

static int fixture_open(engine_fixture_t *fixture)
{
    if (fixture == NULL ||
        ENTRIES_OFFSET + ENTRIES_BYTES > ARENA_BYTES) {
        return 0;
    }
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->store = ninlil_mfdt_v1_host_store_create();
    if (fixture->store == NULL) {
        return 0;
    }
    if (ninlil_mfdt_v1_host_store_open_port(
            fixture->store,
            &fixture->port) != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_host_store_destroy(fixture->store);
        fixture->store = NULL;
        return 0;
    }
    make_config(&fixture->config);
    make_slot_memory(&fixture->memory, fixture->arena.bytes);
    if (ninlil_mfdt_v1_engine_init_slot(
            &fixture->engine,
            &fixture->memory,
            &fixture->port,
            &fixture->committed_keys,
            &fixture->committed_logical_bytes,
            &fixture->full_locked,
            &fixture->inventory_uncertain,
            &fixture->config) != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_host_store_close_port(
            fixture->store,
            &fixture->port);
        ninlil_mfdt_v1_host_store_destroy(fixture->store);
        fixture->store = NULL;
        return 0;
    }
    return 1;
}

static void fixture_close(engine_fixture_t *fixture)
{
    if (fixture == NULL) {
        return;
    }
    if (fixture->store != NULL) {
        ninlil_mfdt_v1_host_store_close_port(
            fixture->store,
            &fixture->port);
        ninlil_mfdt_v1_host_store_destroy(fixture->store);
    }
    (void)memset(fixture, 0, sizeof(*fixture));
}

static int read_inventory(
    const engine_fixture_t *fixture,
    inventory_t *inventory)
{
    if (fixture == NULL || inventory == NULL) {
        return NINLIL_MFDT_V1_ERR_PARAM;
    }
    (void)memset(inventory, 0, sizeof(*inventory));
    return ninlil_mfdt_v1_host_store_inventory(
        fixture->store,
        &inventory->keys,
        &inventory->logical_bytes,
        &inventory->generation,
        &inventory->full_count);
}

static void read_call_counts(
    const engine_fixture_t *fixture,
    call_counts_t *counts)
{
    (void)memset(counts, 0, sizeof(*counts));
    counts->put = ninlil_mfdt_v1_host_store_call_count(
        fixture->store,
        NINLIL_MFDT_V1_HOST_STORE_OP_PUT);
    counts->erase = ninlil_mfdt_v1_host_store_call_count(
        fixture->store,
        NINLIL_MFDT_V1_HOST_STORE_OP_ERASE);
    counts->commit = ninlil_mfdt_v1_host_store_call_count(
        fixture->store,
        NINLIL_MFDT_V1_HOST_STORE_OP_COMMIT);
}

static int read_row(
    engine_fixture_t *fixture,
    const char prefix[4],
    const uint8_t transfer_id[16],
    uint8_t *value,
    uint32_t value_cap,
    uint32_t *value_len,
    int *present)
{
    uint8_t key[NINLIL_MFDT_V1_KEY_BYTES];

    (void)memcpy(key, prefix, 4u);
    (void)memcpy(key + 4u, transfer_id, 16u);
    return ninlil_mfdt_v1_store_read(
        &fixture->port,
        key,
        value,
        value_cap,
        value_len,
        present);
}

static int build_open(
    const engine_fixture_t *fixture,
    uint8_t tid_tag,
    const uint8_t *content,
    uint32_t content_len,
    uint64_t deadline_ms,
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint16_t *open_len)
{
    uint8_t transfer_id[16];
    ninlil_mfdt_v1_open_metadata_t metadata;
    uint8_t entries[
        NINLIL_MFDT_V1_MAX_CHUNKS *
        NINLIL_MFDT_V1_ENTRY_BYTES];
    uint8_t manifest_digest[32];
    uint8_t whole_digest[32];
    uint16_t entry_bytes = 0u;

    make_tid(transfer_id, tid_tag);
    (void)memset(&metadata, 0, sizeof(metadata));
    (void)memset(metadata.origin_transaction_id, tid_tag, 16u);
    make_endpoint(metadata.source_runtime_id, (uint8_t)(0x50u + tid_tag));
    make_endpoint(metadata.target_runtime_id, (uint8_t)(0x90u + tid_tag));
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
    (void)memcpy(metadata.deadline_clock_epoch_id,
                 fixture->config.local_clock_epoch.bytes, 16u);
    metadata.absolute_effect_deadline_ms = deadline_ms;
    metadata.service_schema_major = 1u;
    metadata.service_family = 2u;
    metadata.application_generation = 1ull;
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

static int admit_receiver(
    engine_fixture_t *fixture,
    uint8_t tid_tag,
    const uint8_t *content,
    uint32_t content_len,
    uint64_t deadline_ms,
    uint64_t request_id,
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint16_t *open_len,
    ninlil_mfdt_v1_response_t *response)
{
    int rc = build_open(
        fixture,
        tid_tag,
        content,
        content_len,
        deadline_ms,
        open,
        open_len);

    if (rc != NINLIL_MFDT_V1_OK) {
        return rc;
    }
    rc = ninlil_mfdt_v1_receiver_on_open(
        &fixture->engine,
        open,
        *open_len,
        request_id,
        response);
    if (rc != NINLIL_MFDT_V1_OK ||
        response->message_type != NINLIL_MFDT_V1_MSG_OPEN_ACCEPT ||
        response->body_len != 100u ||
        response->from_nrc1_hit != 0u ||
        response->state_mutation != 1u ||
        response->full_count != 1u) {
        return rc != NINLIL_MFDT_V1_OK
                   ? rc : NINLIL_MFDT_V1_ERR_STATE;
    }
    return NINLIL_MFDT_V1_OK;
}

static int response_is_zero(
    const ninlil_mfdt_v1_response_t *response)
{
    static const ninlil_mfdt_v1_response_t zero_response = {0};

    return memcmp(
               response,
               &zero_response,
               sizeof(*response)) == 0;
}

static int reject_is_exact(
    const ninlil_mfdt_v1_response_t *response,
    const uint8_t expected_bind52[52],
    uint16_t stage,
    uint16_t reject_code,
    uint8_t state_mutation,
    uint8_t full_count)
{
    static const uint8_t zero_reserved[4] = {0u, 0u, 0u, 0u};

    return response != NULL && expected_bind52 != NULL &&
           response->message_type == NINLIL_MFDT_V1_MSG_REJECT &&
           response->body_len == 60u &&
           response->reject_code == reject_code &&
           response->from_nrc1_hit == 0u &&
           response->state_mutation == state_mutation &&
           response->full_count == full_count &&
           memcmp(response->body, expected_bind52, 52u) == 0 &&
           ninlil_mfdt_v1_get_u16(response->body + 52u) == stage &&
           ninlil_mfdt_v1_get_u16(response->body + 54u) == reject_code &&
           memcmp(
               response->body + 56u,
               zero_reserved,
               sizeof(zero_reserved)) == 0;
}

static void make_bind52_from_open(
    const uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint8_t bind52[52])
{
    ninlil_mfdt_v1_bind52(
        open,
        ninlil_mfdt_v1_get_u32(open + 16u),
        open + 202u,
        bind52);
}

static void make_finalize(
    const uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint8_t finalize[92])
{
    (void)memset(finalize, 0, 92u);
    make_bind52_from_open(open, finalize);
    (void)memcpy(finalize + 52u, open + 32u, 32u);
    ninlil_mfdt_v1_put_u32(
        finalize + 84u,
        ninlil_mfdt_v1_get_u32(open + 20u));
}

static void make_resume(
    const uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint32_t query_generation,
    uint8_t query[60])
{
    (void)memset(query, 0, 60u);
    make_bind52_from_open(open, query);
    ninlil_mfdt_v1_put_u32(query + 52u, query_generation);
}

static void make_abort(
    const uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint16_t reason,
    uint32_t generation,
    uint8_t abort_body[76])
{
    (void)memset(abort_body, 0, 76u);
    make_bind52_from_open(open, abort_body);
    ninlil_mfdt_v1_put_u16(abort_body + 52u, reason);
    (void)memset(abort_body + 56u, 0x41, 16u);
    ninlil_mfdt_v1_put_u32(abort_body + 72u, generation);
}

static int test_finalize_precontent_layout_digest(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t response;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t finalize[92];
    uint8_t bind52[52];
    uint8_t content = 0x51u;
    uint16_t open_len = 0u;

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x11u,
              &content,
              1u,
              fixture.config.now_ms + 600000ull,
              101u,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    make_bind52_from_open(open, bind52);
    make_finalize(open, finalize);
    CHECK(ninlil_mfdt_v1_receiver_on_finalize(
              &fixture.engine,
              finalize,
              sizeof(finalize),
              102u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        4u,
        NINLIL_MFDT_V1_REJ_STATE,
        1u,
        1u));
    CHECK(ninlil_mfdt_v1_receiver_on_finalize(
              &fixture.engine,
              finalize,
              (uint16_t)(sizeof(finalize) - 1u),
              103u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        4u,
        NINLIL_MFDT_V1_REJ_LAYOUT,
        1u,
        1u));
    fixture_close(&fixture);

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x12u,
              NULL,
              0u,
              fixture.config.now_ms + 600000ull,
              111u,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    make_bind52_from_open(open, bind52);
    make_finalize(open, finalize);
    finalize[52] ^= 0x80u;
    CHECK(ninlil_mfdt_v1_receiver_on_finalize(
              &fixture.engine,
              finalize,
              sizeof(finalize),
              112u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        4u,
        NINLIL_MFDT_V1_REJ_DIGEST,
        1u,
        1u));
    fixture_close(&fixture);
    return 0;
}

static int test_resume_bind_layout_qgen_zero_gap_rollback(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t response;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t query[60];
    uint8_t bind52[52];
    uint8_t content = 0x52u;
    uint16_t open_len = 0u;

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x21u,
              &content,
              1u,
              fixture.config.now_ms + 600000ull,
              201u,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    make_bind52_from_open(open, bind52);

    make_resume(open, 1u, query);
    query[20] ^= 0x01u;
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              query,
              sizeof(query),
              202u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        5u,
        NINLIL_MFDT_V1_REJ_LAYOUT,
        1u,
        1u));

    make_resume(open, 1u, query);
    ninlil_mfdt_v1_put_u32(query + 56u, 1u);
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              query,
              sizeof(query),
              203u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        5u,
        NINLIL_MFDT_V1_REJ_LAYOUT,
        1u,
        1u));

    make_resume(open, 0u, query);
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              query,
              sizeof(query),
              204u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        5u,
        NINLIL_MFDT_V1_REJ_STATE,
        1u,
        1u));

    make_resume(open, 2u, query);
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              query,
              sizeof(query),
              205u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        5u,
        NINLIL_MFDT_V1_REJ_STATE,
        1u,
        1u));

    make_resume(open, 1u, query);
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              query,
              sizeof(query),
              206u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_RESUME_STATE);
    CHECK(response.body_len == 108u);
    CHECK(response.from_nrc1_hit == 0u);
    CHECK(response.state_mutation == 1u);
    CHECK(response.full_count == 1u);

    make_resume(open, 2u, query);
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              query,
              sizeof(query),
              207u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(response.message_type == NINLIL_MFDT_V1_MSG_RESUME_STATE);
    CHECK(ninlil_mfdt_v1_get_u32(response.body + 52u) == 2u);

    make_resume(open, 1u, query);
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              query,
              sizeof(query),
              208u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        5u,
        NINLIL_MFDT_V1_REJ_STATE,
        1u,
        1u));

    fixture_close(&fixture);
    return 0;
}

static int test_abort_layout_authority_generation(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t response;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t abort_body[76];
    uint8_t bind52[52];
    uint8_t content = 0x53u;
    uint16_t open_len = 0u;

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x31u,
              &content,
              1u,
              fixture.config.now_ms + 600000ull,
              301u,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    make_bind52_from_open(open, bind52);

    make_abort(
        open,
        NINLIL_MFDT_V1_TERM_REASON_OPERATOR,
        1u,
        abort_body);
    ninlil_mfdt_v1_put_u16(abort_body + 54u, 1u);
    CHECK(ninlil_mfdt_v1_receiver_on_abort(
              &fixture.engine,
              abort_body,
              sizeof(abort_body),
              302u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        6u,
        NINLIL_MFDT_V1_REJ_LAYOUT,
        1u,
        1u));

    make_abort(open, 0u, 1u, abort_body);
    CHECK(ninlil_mfdt_v1_receiver_on_abort(
              &fixture.engine,
              abort_body,
              sizeof(abort_body),
              303u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        6u,
        NINLIL_MFDT_V1_REJ_AUTHORITY,
        1u,
        1u));

    make_abort(
        open,
        NINLIL_MFDT_V1_TERM_REASON_OPERATOR,
        2u,
        abort_body);
    CHECK(ninlil_mfdt_v1_receiver_on_abort(
              &fixture.engine,
              abort_body,
              sizeof(abort_body),
              304u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        6u,
        NINLIL_MFDT_V1_REJ_STATE,
        1u,
        1u));

    fixture_close(&fixture);
    return 0;
}

static int test_same_rid_different_body_nrc1_bit_exact(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t first;
    ninlil_mfdt_v1_response_t conflict;
    ninlil_mfdt_v1_response_t replay;
    inventory_t inventory_before;
    inventory_t inventory_after;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t changed_open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t transfer_id[16];
    uint8_t content = 0x54u;
    uint16_t open_len = 0u;
    uint32_t nrc1_before_len = 0u;
    uint32_t nrc1_after_len = 0u;
    int present = 0;

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x41u,
              &content,
              1u,
              fixture.config.now_ms + 600000ull,
              401u,
              open,
              &open_len,
              &first) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 0x41u);
    CHECK(read_row(
              &fixture,
              "NRC1",
              transfer_id,
              g_nrc1_before,
              sizeof(g_nrc1_before),
              &nrc1_before_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(nrc1_before_len == NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    CHECK(read_inventory(
              &fixture,
              &inventory_before) == NINLIL_MFDT_V1_OK);

    (void)memcpy(changed_open, open, open_len);
    changed_open[32] ^= 0x01u;
    (void)memset(&conflict, 0xa5, sizeof(conflict));
    CHECK(ninlil_mfdt_v1_receiver_on_open(
              &fixture.engine,
              changed_open,
              open_len,
              401u,
              &conflict) == NINLIL_MFDT_V1_ERR_DIGEST);
    CHECK(conflict.message_type == NINLIL_MFDT_V1_MSG_REJECT);
    CHECK(conflict.reject_code == NINLIL_MFDT_V1_REJ_DUPLICATE);
    CHECK(conflict.from_nrc1_hit == 0u);
    CHECK(conflict.state_mutation == 0u);
    CHECK(conflict.full_count == 0u);

    CHECK(read_row(
              &fixture,
              "NRC1",
              transfer_id,
              g_nrc1_after,
              sizeof(g_nrc1_after),
              &nrc1_after_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(nrc1_after_len == nrc1_before_len);
    CHECK(memcmp(
              g_nrc1_before,
              g_nrc1_after,
              nrc1_before_len) == 0);
    CHECK(read_inventory(
              &fixture,
              &inventory_after) == NINLIL_MFDT_V1_OK);
    CHECK(memcmp(
              &inventory_before,
              &inventory_after,
              sizeof(inventory_before)) == 0);

    CHECK(ninlil_mfdt_v1_receiver_on_open(
              &fixture.engine,
              open,
              open_len,
              401u,
              &replay) == NINLIL_MFDT_V1_OK);
    CHECK(replay.message_type == first.message_type);
    CHECK(replay.body_len == first.body_len);
    CHECK(memcmp(replay.body, first.body, first.body_len) == 0);
    CHECK(replay.from_nrc1_hit == 1u);
    CHECK(replay.state_mutation == 0u);
    CHECK(replay.full_count == 0u);

    fixture_close(&fixture);
    return 0;
}

static int test_valid_length_malformed_open_stateless_exact_reject(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t response;
    inventory_t inventory_before;
    inventory_t inventory_after;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t bind52[52];
    uint8_t content = 0x55u;
    uint16_t open_len = 0u;

    CHECK(fixture_open(&fixture));
    CHECK(build_open(
              &fixture,
              0x51u,
              &content,
              1u,
              fixture.config.now_ms + 600000ull,
              open,
              &open_len) == NINLIL_MFDT_V1_OK);
    CHECK(open_len >= NINLIL_MFDT_V1_OPEN_BODY_MIN);
    make_bind52_from_open(open, bind52);
    ninlil_mfdt_v1_put_u16(
        open + 24u,
        (uint16_t)(NINLIL_MFDT_V1_CHUNK_SIZE - 1u));
    CHECK(read_inventory(
              &fixture,
              &inventory_before) == NINLIL_MFDT_V1_OK);
    (void)memset(&response, 0xa5, sizeof(response));
    CHECK(ninlil_mfdt_v1_receiver_on_open(
              &fixture.engine,
              open,
              open_len,
              501u,
              &response) == NINLIL_MFDT_V1_ERR_LAYOUT);
    CHECK(reject_is_exact(
        &response,
        bind52,
        1u,
        NINLIL_MFDT_V1_REJ_LAYOUT,
        0u,
        0u));
    CHECK(fixture.engine.active_count == 0u);
    CHECK(read_inventory(
              &fixture,
              &inventory_after) == NINLIL_MFDT_V1_OK);
    CHECK(memcmp(
              &inventory_before,
              &inventory_after,
              sizeof(inventory_before)) == 0);

    fixture_close(&fixture);
    return 0;
}

static int test_short_bind52_no_response(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t response;
    inventory_t inventory_before;
    inventory_t inventory_after;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t bind52[52];
    uint8_t short_body[51];
    uint8_t content = 0x56u;
    uint16_t open_len = 0u;

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x61u,
              &content,
              1u,
              fixture.config.now_ms + 600000ull,
              601u,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    make_bind52_from_open(open, bind52);
    (void)memcpy(short_body, bind52, sizeof(short_body));
    CHECK(read_inventory(
              &fixture,
              &inventory_before) == NINLIL_MFDT_V1_OK);

    (void)memset(&response, 0xa5, sizeof(response));
    CHECK(ninlil_mfdt_v1_receiver_on_finalize(
              &fixture.engine,
              short_body,
              sizeof(short_body),
              602u,
              &response) == NINLIL_MFDT_V1_ERR_LAYOUT);
    CHECK(response_is_zero(&response));

    (void)memset(&response, 0xa5, sizeof(response));
    CHECK(ninlil_mfdt_v1_receiver_on_resume(
              &fixture.engine,
              short_body,
              sizeof(short_body),
              603u,
              &response) == NINLIL_MFDT_V1_ERR_LAYOUT);
    CHECK(response_is_zero(&response));

    (void)memset(&response, 0xa5, sizeof(response));
    CHECK(ninlil_mfdt_v1_receiver_on_abort(
              &fixture.engine,
              short_body,
              sizeof(short_body),
              604u,
              &response) == NINLIL_MFDT_V1_ERR_LAYOUT);
    CHECK(response_is_zero(&response));

    CHECK(read_inventory(
              &fixture,
              &inventory_after) == NINLIL_MFDT_V1_OK);
    CHECK(memcmp(
              &inventory_before,
              &inventory_after,
              sizeof(inventory_before)) == 0);
    CHECK(fixture.engine.active_count == 1u);

    fixture_close(&fixture);
    return 0;
}

static int verify_terminal_rows_and_three_op_full(
    engine_fixture_t *fixture,
    const uint8_t transfer_id[16],
    const inventory_t *inventory_before,
    const call_counts_t *calls_before,
    uint16_t terminal_state,
    uint16_t terminal_reason,
    const uint8_t expected_anchor_epoch[16],
    uint64_t expected_anchor_ms)
{
    inventory_t inventory_after;
    call_counts_t calls_after;
    uint32_t active_len = 0u;
    uint32_t nrc1_len = 0u;
    uint32_t nm30_len = 0u;
    int present = 0;

    CHECK(read_inventory(
              fixture,
              &inventory_after) == NINLIL_MFDT_V1_OK);
    read_call_counts(fixture, &calls_after);
    CHECK(inventory_after.full_count ==
          inventory_before->full_count + 1u);
    CHECK(inventory_after.keys == inventory_before->keys);
    CHECK(calls_after.put == calls_before->put + 2u);
    CHECK(calls_after.erase == calls_before->erase + 1u);
    CHECK(calls_after.commit == calls_before->commit + 1u);

    CHECK(read_row(
              fixture,
              "NM3R",
              transfer_id,
              g_active_after,
              sizeof(g_active_after),
              &active_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 0);
    CHECK(active_len == 0u);
    CHECK(read_row(
              fixture,
              "NM30",
              transfer_id,
              g_nm30,
              sizeof(g_nm30),
              &nm30_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(nm30_len == NINLIL_MFDT_V1_NM30_BYTES);
    CHECK(ninlil_mfdt_v1_validate_nm30_record(
              g_nm30,
              nm30_len,
              transfer_id) == NINLIL_MFDT_V1_OK);
    CHECK(ninlil_mfdt_v1_get_u16(g_nm30 + 60u) ==
          terminal_state);
    CHECK(ninlil_mfdt_v1_get_u16(g_nm30 + 62u) ==
          terminal_reason);
    CHECK(memcmp(
              g_nm30 + 132u,
              expected_anchor_epoch,
              16u) == 0);
    CHECK(ninlil_mfdt_v1_get_u64(g_nm30 + 148u) ==
          expected_anchor_ms);
    CHECK(read_row(
              fixture,
              "NRC1",
              transfer_id,
              g_nrc1_before,
              sizeof(g_nrc1_before),
              &nrc1_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(nrc1_len == NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    CHECK(ninlil_mfdt_v1_validate_nrc1_record(
              g_nrc1_before,
              nrc1_len,
              transfer_id,
              1u) == NINLIL_MFDT_V1_OK);
    return 0;
}

static int verify_warm_terminal_replay(
    engine_fixture_t *fixture,
    const uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX],
    uint16_t open_len,
    uint64_t request_id,
    const ninlil_mfdt_v1_response_t *first)
{
    ninlil_mfdt_v1_response_t replay;
    inventory_t inventory_before;
    inventory_t inventory_after;
    call_counts_t calls_before;
    call_counts_t calls_after;
    uint8_t transfer_id[16];
    uint32_t nrc1_len = 0u;
    int present = 0;

    (void)memcpy(transfer_id, open, 16u);
    CHECK(read_inventory(
              fixture,
              &inventory_before) == NINLIL_MFDT_V1_OK);
    read_call_counts(fixture, &calls_before);
    (void)memset(&replay, 0xa5, sizeof(replay));
    CHECK(ninlil_mfdt_v1_receiver_on_open(
              &fixture->engine,
              open,
              open_len,
              request_id,
              &replay) == NINLIL_MFDT_V1_OK);
    CHECK(replay.message_type == first->message_type);
    CHECK(replay.body_len == first->body_len);
    CHECK(replay.reject_code == first->reject_code);
    CHECK(memcmp(replay.body, first->body, first->body_len) == 0);
    CHECK(replay.from_nrc1_hit == 1u);
    CHECK(replay.state_mutation == 0u);
    CHECK(replay.full_count == 0u);
    CHECK(read_inventory(
              fixture,
              &inventory_after) == NINLIL_MFDT_V1_OK);
    read_call_counts(fixture, &calls_after);
    CHECK(memcmp(
              &inventory_before,
              &inventory_after,
              sizeof(inventory_before)) == 0);
    CHECK(calls_after.put == calls_before.put);
    CHECK(calls_after.erase == calls_before.erase);
    CHECK(calls_after.commit == calls_before.commit);
    CHECK(read_row(
              fixture,
              "NRC1",
              transfer_id,
              g_nrc1_after,
              sizeof(g_nrc1_after),
              &nrc1_len,
              &present) == NINLIL_MFDT_V1_OK);
    CHECK(present == 1);
    CHECK(nrc1_len == NINLIL_MFDT_V1_NRC1_VALUE_BYTES);
    CHECK(memcmp(
              g_nrc1_before,
              g_nrc1_after,
              nrc1_len) == 0);
    return 0;
}

static int test_request_expiry_three_op_full_warm_replay(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t response;
    inventory_t inventory_before;
    call_counts_t calls_before;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t bind52[52];
    uint8_t transfer_id[16];
    uint8_t content = 0x57u;
    uint16_t open_len = 0u;
    const uint64_t deadline_ms = 1100ull;

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x71u,
              &content,
              1u,
              deadline_ms,
              701u,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 0x71u);
    make_bind52_from_open(open, bind52);
    ninlil_mfdt_v1_engine_set_now(
        &fixture.engine,
        deadline_ms);
    CHECK(read_inventory(
              &fixture,
              &inventory_before) == NINLIL_MFDT_V1_OK);
    read_call_counts(&fixture, &calls_before);
    CHECK(ninlil_mfdt_v1_receiver_on_open(
              &fixture.engine,
              open,
              open_len,
              702u,
              &response) == NINLIL_MFDT_V1_OK);
    CHECK(reject_is_exact(
        &response,
        bind52,
        1u,
        NINLIL_MFDT_V1_REJ_EXPIRED,
        1u,
        1u));
    CHECK(fixture.engine.active_count == 0u);
    CHECK(verify_terminal_rows_and_three_op_full(
              &fixture,
              transfer_id,
              &inventory_before,
              &calls_before,
              NINLIL_MFDT_V1_TERM_ABORTED,
              NINLIL_MFDT_V1_TERM_REASON_EXPIRED,
              fixture.config.local_clock_epoch.bytes,
              deadline_ms) == 0);
    CHECK(verify_warm_terminal_replay(
              &fixture,
              open,
              open_len,
              702u,
              &response) == 0);

    fixture_close(&fixture);
    return 0;
}

static int test_request_epoch_change_three_op_full_warm_replay(void)
{
    engine_fixture_t fixture;
    ninlil_mfdt_v1_response_t response;
    inventory_t inventory_before;
    call_counts_t calls_before;
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint8_t bind52[52];
    uint8_t transfer_id[16];
    uint8_t durable_epoch[16];
    uint8_t content = 0x58u;
    uint16_t open_len = 0u;

    CHECK(fixture_open(&fixture));
    CHECK(admit_receiver(
              &fixture,
              0x72u,
              &content,
              1u,
              fixture.config.now_ms + 600000ull,
              711u,
              open,
              &open_len,
              &response) == NINLIL_MFDT_V1_OK);
    make_tid(transfer_id, 0x72u);
    make_bind52_from_open(open, bind52);
    (void)memcpy(
        durable_epoch,
        fixture.config.local_clock_epoch.bytes,
        sizeof(durable_epoch));
    (void)memset(
        fixture.engine.cfg.local_clock_epoch.bytes,
        0xd1,
        16u);
    CHECK(read_inventory(
              &fixture,
              &inventory_before) == NINLIL_MFDT_V1_OK);
    read_call_counts(&fixture, &calls_before);
    CHECK(ninlil_mfdt_v1_receiver_on_open(
              &fixture.engine,
              open,
              open_len,
              712u,
              &response) == NINLIL_MFDT_V1_ERR_STATE);
    CHECK(reject_is_exact(
        &response,
        bind52,
        1u,
        NINLIL_MFDT_V1_REJ_STATE,
        1u,
        1u));
    CHECK(fixture.engine.active_count == 0u);
    CHECK(verify_terminal_rows_and_three_op_full(
              &fixture,
              transfer_id,
              &inventory_before,
              &calls_before,
              NINLIL_MFDT_V1_TERM_CORRUPT_FENCED,
              NINLIL_MFDT_V1_TERM_REASON_EPOCH,
              durable_epoch,
              fixture.config.now_ms) == 0);
    CHECK(verify_warm_terminal_replay(
              &fixture,
              open,
              open_len,
              712u,
              &response) == 0);

    fixture_close(&fixture);
    return 0;
}

static int run_witness(
    const char *name,
    int (*test)(void))
{
    const int rc = test();

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

    CHECK(NINLIL_MFDT_V1_TERM_REASON_OPERATOR == 1u);
    CHECK(NINLIL_MFDT_V1_TERM_REASON_SUPERSEDED == 2u);
    CHECK(NINLIL_MFDT_V1_TERM_REASON_DEADLINE == 3u);
    CHECK(NINLIL_MFDT_V1_TERM_REASON_POLICY == 4u);

    failures += run_witness(
        "finalize_precontent_layout_digest",
        test_finalize_precontent_layout_digest);
    failures += run_witness(
        "resume_bind_layout_qgen_zero_gap_rollback",
        test_resume_bind_layout_qgen_zero_gap_rollback);
    failures += run_witness(
        "abort_layout_authority_generation",
        test_abort_layout_authority_generation);
    failures += run_witness(
        "same_rid_different_body_nrc1_bit_exact",
        test_same_rid_different_body_nrc1_bit_exact);
    failures += run_witness(
        "valid_length_malformed_open_stateless_exact_reject",
        test_valid_length_malformed_open_stateless_exact_reject);
    failures += run_witness(
        "short_bind52_no_response",
        test_short_bind52_no_response);
    failures += run_witness(
        "request_expiry_three_op_full_warm_replay",
        test_request_expiry_three_op_full_warm_replay);
    failures += run_witness(
        "request_epoch_change_three_op_full_warm_replay",
        test_request_epoch_change_three_op_full_warm_replay);
    if (failures != 0) {
        (void)fprintf(
            stderr,
            "mfdt_v1_request_kat_test FAILED (%d)\n",
            failures);
        return 1;
    }
    (void)printf("mfdt_v1_request_kat_test OK\n");
    return 0;
}
