/* SPDX-License-Identifier: Apache-2.0 */
/*
 *
 * Independent Host slot-memory contract acceptance.
 * Source-private, default-OFF, software-only; this is not HIL evidence.
 */
#include "mfdt_v1.h"
#include "mfdt_v1_host_store.h"
#include "mfdt_v1_store_port.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(                                                     \
                stderr,                                                       \
                "WITNESS_FAIL %s:%d: %s\n",                                  \
                __FILE__,                                                     \
                __LINE__,                                                     \
                #condition);                                                   \
            return 1;                                                          \
        }                                                                      \
    } while (0)

#define ARENA_BYTES ((size_t)65536u)
#define RECORD_BYTES ((uint32_t)35216u)
#define NRC1_BYTES ((uint32_t)15024u)
#define XFER_BYTES ((uint32_t)512u)
#define OPEN_BYTES ((uint32_t)656u)
#define ENTRIES_BYTES                                                        \
    ((uint32_t)NINLIL_MFDT_V1_MAX_CHUNKS * NINLIL_MFDT_V1_ENTRY_BYTES)

#define RECORD_OFFSET ((size_t)0u)
#define NRC1_OFFSET (RECORD_OFFSET + RECORD_BYTES)
#define XFER_OFFSET (NRC1_OFFSET + NRC1_BYTES)
#define OPEN_OFFSET (XFER_OFFSET + XFER_BYTES)
#define ENTRIES_OFFSET (OPEN_OFFSET + OPEN_BYTES)

#define OVERSIZE_PAD ((size_t)8u)
#define OVERSIZED_RECORD_OFFSET ((size_t)0u)
#define OVERSIZED_NRC1_OFFSET \
    (OVERSIZED_RECORD_OFFSET + RECORD_BYTES + OVERSIZE_PAD)
#define OVERSIZED_XFER_OFFSET \
    (OVERSIZED_NRC1_OFFSET + NRC1_BYTES + OVERSIZE_PAD)
#define OVERSIZED_OPEN_OFFSET \
    (OVERSIZED_XFER_OFFSET + XFER_BYTES + OVERSIZE_PAD)
#define OVERSIZED_ENTRIES_OFFSET \
    (OVERSIZED_OPEN_OFFSET + OPEN_BYTES + OVERSIZE_PAD)
#define OVERSIZED_ARENA_BYTES \
    (OVERSIZED_ENTRIES_OFFSET + ENTRIES_BYTES + OVERSIZE_PAD)

typedef union aligned_bytes {
    uint64_t align8;
    uint8_t bytes[ARENA_BYTES + 8u];
} aligned_bytes_t;

typedef union oversized_aligned_bytes {
    uint64_t align8;
    uint8_t bytes[OVERSIZED_ARENA_BYTES];
} oversized_aligned_bytes_t;

typedef union aligned_controls {
    uint64_t align8;
    uint8_t bytes[8192u];
} aligned_controls_t;

#define CONTROL_ENGINE_OFFSET ((size_t)0u)
#define CONTROL_MEMORY_OFFSET ((size_t)1024u)
#define CONTROL_PORT_OFFSET ((size_t)2048u)
#define CONTROL_CONFIG_OFFSET ((size_t)4096u)
#define CONTROL_KEYS_OFFSET ((size_t)6144u)
#define CONTROL_LOGICAL_OFFSET ((size_t)6152u)
#define CONTROL_LOCK_OFFSET ((size_t)6160u)
#define CONTROL_UNCERTAIN_OFFSET ((size_t)6161u)

typedef struct store_fixture {
    ninlil_mfdt_v1_host_store_t *store;
    ninlil_mfdt_v1_store_port_t port;
} store_fixture_t;

typedef struct inventory {
    uint32_t keys;
    uint64_t logical_bytes;
    uint64_t generation;
    uint64_t full_count;
} inventory_t;

static ninlil_mfdt_v1_config_t valid_config(void)
{
    ninlil_mfdt_v1_config_t config;

    (void)memset(&config, 0, sizeof(config));
    config.policy = NINLIL_MFDT_V1_POLICY_ON;
    config.mfdt_admission_version = NINLIL_MFDT_V1_ADMISSION_VERSION;
    config.session_generation = 1u;
    config.mfdt_capability = 1u;
    config.host_mode = 1u;
    config.retention_ms = NINLIL_MFDT_V1_RETENTION_MS_DEFAULT;
    config.now_ms = 1000u;
    (void)memset(config.local_clock_epoch.bytes, 0xc0, 16u);
    return config;
}

static int fixture_open(store_fixture_t *fixture)
{
    (void)memset(fixture, 0, sizeof(*fixture));
    fixture->store = ninlil_mfdt_v1_host_store_create();
    if (fixture->store == NULL) {
        return 0;
    }
    if (ninlil_mfdt_v1_host_store_open_port(
            fixture->store,
            &fixture->port) != NINLIL_MFDT_V1_OK) {
        ninlil_mfdt_v1_host_store_destroy(fixture->store);
        (void)memset(fixture, 0, sizeof(*fixture));
        return 0;
    }
    return 1;
}

static void fixture_close(store_fixture_t *fixture)
{
    if (fixture->store != NULL) {
        ninlil_mfdt_v1_host_store_close_port(
            fixture->store,
            &fixture->port);
        ninlil_mfdt_v1_host_store_destroy(fixture->store);
    }
    (void)memset(fixture, 0, sizeof(*fixture));
}

static int read_inventory(
    const store_fixture_t *fixture,
    inventory_t *inventory)
{
    (void)memset(inventory, 0, sizeof(*inventory));
    return ninlil_mfdt_v1_host_store_inventory(
        fixture->store,
        &inventory->keys,
        &inventory->logical_bytes,
        &inventory->generation,
        &inventory->full_count);
}

static void make_valid_memory(
    ninlil_mfdt_v1_engine_slot_memory_t *memory,
    uint8_t *base)
{
    (void)memset(memory, 0, sizeof(*memory));
    memory->record_memory = base + RECORD_OFFSET;
    memory->record_memory_bytes = RECORD_BYTES;
    memory->nrc1_memory = base + NRC1_OFFSET;
    memory->nrc1_memory_bytes = NRC1_BYTES;
    memory->xfer_memory = base + XFER_OFFSET;
    memory->xfer_memory_bytes = XFER_BYTES;
    memory->open_staging = base + OPEN_OFFSET;
    memory->open_staging_bytes = OPEN_BYTES;
    memory->entries_staging = base + ENTRIES_OFFSET;
    memory->entries_staging_bytes = ENTRIES_BYTES;
}

static int bytes_equal(
    const void *left,
    const void *right,
    size_t length)
{
    return memcmp(left, right, length) == 0;
}

static int bytes_are_zero(const uint8_t *bytes, size_t length)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int invoke_invalid_and_require_no_mutation(
    const char *witness,
    ninlil_mfdt_v1_engine_t *engine,
    const ninlil_mfdt_v1_engine_slot_memory_t *memory,
    aligned_bytes_t *arena,
    store_fixture_t *fixture)
{
    aligned_bytes_t arena_before = *arena;
    ninlil_mfdt_v1_engine_t engine_before = *engine;
    ninlil_mfdt_v1_store_port_t port_before = fixture->port;
    ninlil_mfdt_v1_config_t config = valid_config();
    inventory_t inventory_before;
    inventory_t inventory_after;
    uint32_t committed_keys = 0u;
    uint64_t committed_logical_bytes = 0u;
    uint8_t full_locked = 0u;
    uint8_t inventory_uncertain = 0u;
    int rc;

    REQUIRE(read_inventory(fixture, &inventory_before)
        == NINLIL_MFDT_V1_OK);
    rc = ninlil_mfdt_v1_engine_init_slot(
        engine,
        memory,
        &fixture->port,
        &committed_keys,
        &committed_logical_bytes,
        &full_locked,
        &inventory_uncertain,
        &config);
    if (rc != NINLIL_MFDT_V1_ERR_PARAM) {
        (void)fprintf(
            stderr,
            "WITNESS_FAIL %s: expected ERR_PARAM, got %d\n",
            witness,
            rc);
        return 1;
    }
    REQUIRE(bytes_equal(engine, &engine_before, sizeof(*engine)));
    REQUIRE(bytes_equal(arena, &arena_before, sizeof(*arena)));
    REQUIRE(bytes_equal(
        &fixture->port,
        &port_before,
        sizeof(fixture->port)));
    REQUIRE(committed_keys == 0u);
    REQUIRE(committed_logical_bytes == 0u);
    REQUIRE(full_locked == 0u);
    REQUIRE(inventory_uncertain == 0u);
    REQUIRE(read_inventory(fixture, &inventory_after)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(bytes_equal(
        &inventory_before,
        &inventory_after,
        sizeof(inventory_before)));
    (void)printf("WITNESS_PASS %s\n", witness);
    return 0;
}

static int invoke_custom_invalid_and_require_no_mutation(
    const char *witness,
    aligned_controls_t *controls,
    aligned_bytes_t *arena,
    store_fixture_t *fixture,
    ninlil_mfdt_v1_engine_t *engine,
    const ninlil_mfdt_v1_engine_slot_memory_t *memory,
    ninlil_mfdt_v1_store_port_t *port,
    uint32_t *committed_keys,
    uint64_t *committed_logical_bytes,
    uint8_t *full_locked,
    uint8_t *inventory_uncertain,
    const ninlil_mfdt_v1_config_t *config)
{
    aligned_controls_t controls_before = *controls;
    aligned_bytes_t arena_before = *arena;
    inventory_t inventory_before;
    inventory_t inventory_after;
    int rc;

    REQUIRE(read_inventory(fixture, &inventory_before)
        == NINLIL_MFDT_V1_OK);
    rc = ninlil_mfdt_v1_engine_init_slot(
        engine,
        memory,
        port,
        committed_keys,
        committed_logical_bytes,
        full_locked,
        inventory_uncertain,
        config);
    if (rc != NINLIL_MFDT_V1_ERR_PARAM) {
        (void)fprintf(
            stderr,
            "WITNESS_FAIL %s: expected ERR_PARAM, got %d\n",
            witness,
            rc);
        return 1;
    }
    REQUIRE(bytes_equal(
        controls,
        &controls_before,
        sizeof(*controls)));
    REQUIRE(bytes_equal(arena, &arena_before, sizeof(*arena)));
    REQUIRE(read_inventory(fixture, &inventory_after)
        == NINLIL_MFDT_V1_OK);
    REQUIRE(bytes_equal(
        &inventory_before,
        &inventory_after,
        sizeof(inventory_before)));
    (void)printf("WITNESS_PASS %s\n", witness);
    return 0;
}

static void make_control_fixture(
    aligned_controls_t *controls,
    aligned_bytes_t *arena,
    const store_fixture_t *fixture,
    ninlil_mfdt_v1_engine_t **engine_out,
    ninlil_mfdt_v1_engine_slot_memory_t **memory_out,
    ninlil_mfdt_v1_store_port_t **port_out,
    ninlil_mfdt_v1_config_t **config_out,
    uint32_t **committed_keys_out,
    uint64_t **committed_logical_bytes_out,
    uint8_t **full_locked_out,
    uint8_t **inventory_uncertain_out)
{
    ninlil_mfdt_v1_engine_t *engine =
        (ninlil_mfdt_v1_engine_t *)(void *)
            (controls->bytes + CONTROL_ENGINE_OFFSET);
    ninlil_mfdt_v1_engine_slot_memory_t *memory =
        (ninlil_mfdt_v1_engine_slot_memory_t *)(void *)
            (controls->bytes + CONTROL_MEMORY_OFFSET);
    ninlil_mfdt_v1_store_port_t *port =
        (ninlil_mfdt_v1_store_port_t *)(void *)
            (controls->bytes + CONTROL_PORT_OFFSET);
    ninlil_mfdt_v1_config_t *config =
        (ninlil_mfdt_v1_config_t *)(void *)
            (controls->bytes + CONTROL_CONFIG_OFFSET);
    uint32_t *committed_keys =
        (uint32_t *)(void *)(controls->bytes + CONTROL_KEYS_OFFSET);
    uint64_t *committed_logical_bytes =
        (uint64_t *)(void *)(controls->bytes + CONTROL_LOGICAL_OFFSET);
    uint8_t *full_locked = controls->bytes + CONTROL_LOCK_OFFSET;
    uint8_t *inventory_uncertain =
        controls->bytes + CONTROL_UNCERTAIN_OFFSET;

    (void)memset(controls, 0x5a, sizeof(*controls));
    (void)memset(arena, 0xa5, sizeof(*arena));
    make_valid_memory(memory, arena->bytes);
    *port = fixture->port;
    *config = valid_config();
    *committed_keys = 0u;
    *committed_logical_bytes = 0u;
    *full_locked = 0u;
    *inventory_uncertain = 0u;
    *engine_out = engine;
    *memory_out = memory;
    *port_out = port;
    *config_out = config;
    *committed_keys_out = committed_keys;
    *committed_logical_bytes_out = committed_logical_bytes;
    *full_locked_out = full_locked;
    *inventory_uncertain_out = inventory_uncertain;
}

static int test_valid_disjoint_layout(void)
{
    aligned_bytes_t arena;
    ninlil_mfdt_v1_engine_slot_memory_t memory;
    ninlil_mfdt_v1_engine_t engine;
    ninlil_mfdt_v1_config_t config = valid_config();
    store_fixture_t fixture;
    uint32_t committed_keys = 0u;
    uint64_t committed_logical_bytes = 0u;
    uint8_t full_locked = 0u;
    uint8_t inventory_uncertain = 0u;

    REQUIRE(ENTRIES_OFFSET + ENTRIES_BYTES <= ARENA_BYTES);
    REQUIRE(fixture_open(&fixture));
    (void)memset(&arena, 0xa5, sizeof(arena));
    (void)memset(&engine, 0x5a, sizeof(engine));
    make_valid_memory(&memory, arena.bytes);
    REQUIRE(ninlil_mfdt_v1_engine_init_slot(
        &engine,
        &memory,
        &fixture.port,
        &committed_keys,
        &committed_logical_bytes,
        &full_locked,
        &inventory_uncertain,
        &config) == NINLIL_MFDT_V1_OK);
    REQUIRE(engine.slot_layout == 1u);
    REQUIRE(engine.store_port == &fixture.port);
    REQUIRE(engine.slot_record_memory == memory.record_memory);
    REQUIRE(engine.slot_nrc1_memory == memory.nrc1_memory);
    REQUIRE(engine.slot_xfer_memory == memory.xfer_memory);
    REQUIRE(engine.slot_open_staging == memory.open_staging);
    REQUIRE(engine.slot_entries_staging == memory.entries_staging);
    (void)printf("WITNESS_PASS valid_disjoint_slot_layout\n");
    fixture_close(&fixture);
    return 0;
}

static int test_oversized_disjoint_layout_fini_zeroizes_full_ranges(void)
{
    oversized_aligned_bytes_t arena;
    ninlil_mfdt_v1_engine_slot_memory_t memory;
    ninlil_mfdt_v1_engine_t engine;
    ninlil_mfdt_v1_config_t config = valid_config();
    store_fixture_t fixture;
    uint32_t committed_keys = 0u;
    uint64_t committed_logical_bytes = 0u;
    uint8_t full_locked = 0u;
    uint8_t inventory_uncertain = 0u;
    uint8_t transfer_id[16] = {1u};
    uint8_t active_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t nrc1_key[NINLIL_MFDT_V1_KEY_BYTES];
    uint8_t active_record[NINLIL_MFDT_V1_ACTIVE_VALUE_MAX];
    uint8_t nrc1_record[NINLIL_MFDT_V1_NRC1_VALUE_BYTES];
    uint8_t open[NINLIL_MFDT_V1_OPEN_BODY_MAX];
    uint32_t active_record_len = 0u;
    uint32_t nrc1_record_len = 0u;
    uint16_t open_len = 0u;
    int present = 0;

    REQUIRE(fixture_open(&fixture));
    (void)memset(&arena, 0xa5, sizeof(arena));
    (void)memset(&engine, 0x5a, sizeof(engine));
    (void)memset(&memory, 0, sizeof(memory));
    memory.record_memory = arena.bytes + OVERSIZED_RECORD_OFFSET;
    memory.record_memory_bytes = RECORD_BYTES + (uint32_t)OVERSIZE_PAD;
    memory.nrc1_memory = arena.bytes + OVERSIZED_NRC1_OFFSET;
    memory.nrc1_memory_bytes = NRC1_BYTES + (uint32_t)OVERSIZE_PAD;
    memory.xfer_memory = arena.bytes + OVERSIZED_XFER_OFFSET;
    memory.xfer_memory_bytes = XFER_BYTES + (uint32_t)OVERSIZE_PAD;
    memory.open_staging = arena.bytes + OVERSIZED_OPEN_OFFSET;
    memory.open_staging_bytes = OPEN_BYTES + (uint32_t)OVERSIZE_PAD;
    memory.entries_staging = arena.bytes + OVERSIZED_ENTRIES_OFFSET;
    memory.entries_staging_bytes = ENTRIES_BYTES + (uint32_t)OVERSIZE_PAD;

    REQUIRE(ninlil_mfdt_v1_engine_init_slot(
        &engine,
        &memory,
        &fixture.port,
        &committed_keys,
        &committed_logical_bytes,
        &full_locked,
        &inventory_uncertain,
        &config) == NINLIL_MFDT_V1_OK);
    REQUIRE(engine.slot_record_memory_bytes == memory.record_memory_bytes);
    REQUIRE(engine.slot_nrc1_memory_bytes == memory.nrc1_memory_bytes);
    REQUIRE(engine.slot_xfer_memory_bytes == memory.xfer_memory_bytes);
    REQUIRE(engine.slot_open_staging_bytes == memory.open_staging_bytes);
    REQUIRE(engine.slot_entries_staging_bytes == memory.entries_staging_bytes);

    REQUIRE(ninlil_mfdt_v1_sender_open(
        &engine,
        transfer_id,
        NULL,
        0u,
        open,
        &open_len,
        1u) == NINLIL_MFDT_V1_OK);
    (void)memcpy(active_key, "NM3S", 4u);
    (void)memcpy(active_key + 4u, transfer_id, 16u);
    REQUIRE(ninlil_mfdt_v1_store_read(
        &fixture.port,
        active_key,
        active_record,
        sizeof(active_record),
        &active_record_len,
        &present) == NINLIL_MFDT_V1_OK);
    REQUIRE(present == 1);
    (void)memcpy(nrc1_key, "NRC1", 4u);
    (void)memcpy(nrc1_key + 4u, transfer_id, 16u);
    REQUIRE(ninlil_mfdt_v1_store_read(
        &fixture.port,
        nrc1_key,
        nrc1_record,
        sizeof(nrc1_record),
        &nrc1_record_len,
        &present) == NINLIL_MFDT_V1_OK);
    REQUIRE(present == 1);
    REQUIRE(nrc1_record_len == NINLIL_MFDT_V1_NRC1_VALUE_BYTES);

    (void)memset(
        memory.record_memory + active_record_len,
        0x61,
        memory.record_memory_bytes - active_record_len);
    (void)memset(
        memory.nrc1_memory + nrc1_record_len,
        0x62,
        memory.nrc1_memory_bytes - nrc1_record_len);
    (void)memset(memory.xfer_memory, 0x63, memory.xfer_memory_bytes);
    (void)memset(memory.open_staging, 0x64, memory.open_staging_bytes);
    (void)memset(
        memory.entries_staging, 0x65, memory.entries_staging_bytes);
    REQUIRE(ninlil_mfdt_v1_engine_rehydrate_captured(
        &engine,
        active_record,
        active_record_len,
        nrc1_record,
        nrc1_record_len,
        &config) == NINLIL_MFDT_V1_OK);
    REQUIRE(engine.slot_record_memory_bytes == memory.record_memory_bytes);
    REQUIRE(engine.slot_nrc1_memory_bytes == memory.nrc1_memory_bytes);
    REQUIRE(engine.slot_xfer_memory_bytes == memory.xfer_memory_bytes);
    REQUIRE(engine.slot_open_staging_bytes == memory.open_staging_bytes);
    REQUIRE(engine.slot_entries_staging_bytes == memory.entries_staging_bytes);
    REQUIRE(bytes_are_zero(
        memory.record_memory + active_record_len,
        memory.record_memory_bytes - active_record_len));
    REQUIRE(bytes_are_zero(
        memory.nrc1_memory + nrc1_record_len,
        memory.nrc1_memory_bytes - nrc1_record_len));
    REQUIRE(bytes_are_zero(
        memory.xfer_memory + XFER_BYTES,
        memory.xfer_memory_bytes - XFER_BYTES));
    REQUIRE(bytes_are_zero(
        memory.open_staging, memory.open_staging_bytes));
    REQUIRE(bytes_are_zero(
        memory.entries_staging, memory.entries_staging_bytes));

    (void)memset(memory.record_memory, 0x11, memory.record_memory_bytes);
    (void)memset(memory.nrc1_memory, 0x22, memory.nrc1_memory_bytes);
    (void)memset(memory.xfer_memory, 0x33, memory.xfer_memory_bytes);
    (void)memset(memory.open_staging, 0x44, memory.open_staging_bytes);
    (void)memset(memory.entries_staging, 0x55, memory.entries_staging_bytes);
    ninlil_mfdt_v1_engine_fini(&engine);

    REQUIRE(bytes_are_zero((const uint8_t *)&engine, sizeof(engine)));
    REQUIRE(bytes_are_zero(memory.record_memory, memory.record_memory_bytes));
    REQUIRE(bytes_are_zero(memory.nrc1_memory, memory.nrc1_memory_bytes));
    REQUIRE(bytes_are_zero(memory.xfer_memory, memory.xfer_memory_bytes));
    REQUIRE(bytes_are_zero(memory.open_staging, memory.open_staging_bytes));
    REQUIRE(bytes_are_zero(memory.entries_staging, memory.entries_staging_bytes));
    (void)printf("WITNESS_PASS oversized_slot_fini_full_range_zeroization\n");
    fixture_close(&fixture);
    return 0;
}

static int test_unaligned_region_rejected(void)
{
    aligned_bytes_t arena;
    ninlil_mfdt_v1_engine_slot_memory_t memory;
    ninlil_mfdt_v1_engine_t engine;
    store_fixture_t fixture;
    int rc;

    REQUIRE(fixture_open(&fixture));
    (void)memset(&arena, 0xa5, sizeof(arena));
    (void)memset(&engine, 0x5a, sizeof(engine));
    make_valid_memory(&memory, arena.bytes + 8u);
    memory.record_memory += 1u;
    rc = invoke_invalid_and_require_no_mutation(
        "unaligned_region_zero_mutation",
        &engine,
        &memory,
        &arena,
        &fixture);
    fixture_close(&fixture);
    return rc;
}

static int test_overlapping_regions_rejected(void)
{
    aligned_bytes_t arena;
    ninlil_mfdt_v1_engine_slot_memory_t memory;
    ninlil_mfdt_v1_engine_t engine;
    store_fixture_t fixture;
    int rc;

    REQUIRE(fixture_open(&fixture));
    (void)memset(&arena, 0xa5, sizeof(arena));
    (void)memset(&engine, 0x5a, sizeof(engine));
    make_valid_memory(&memory, arena.bytes);
    memory.nrc1_memory = memory.record_memory + RECORD_BYTES - 8u;
    rc = invoke_invalid_and_require_no_mutation(
        "overlapping_regions_zero_mutation",
        &engine,
        &memory,
        &arena,
        &fixture);
    fixture_close(&fixture);
    return rc;
}

static int test_engine_alias_rejected(void)
{
    aligned_bytes_t arena;
    ninlil_mfdt_v1_engine_slot_memory_t memory;
    ninlil_mfdt_v1_engine_t *engine;
    store_fixture_t fixture;
    int rc;

    REQUIRE(fixture_open(&fixture));
    (void)memset(&arena, 0xa5, sizeof(arena));
    make_valid_memory(&memory, arena.bytes);
    engine = (ninlil_mfdt_v1_engine_t *)(void *)memory.record_memory;
    rc = invoke_invalid_and_require_no_mutation(
        "engine_alias_zeroed_region_zero_mutation",
        engine,
        &memory,
        &arena,
        &fixture);
    fixture_close(&fixture);
    return rc;
}

static int test_descriptor_alias_rejected(void)
{
    aligned_bytes_t arena;
    ninlil_mfdt_v1_engine_slot_memory_t *memory;
    ninlil_mfdt_v1_engine_t engine;
    store_fixture_t fixture;
    int rc;

    REQUIRE(fixture_open(&fixture));
    (void)memset(&arena, 0xa5, sizeof(arena));
    (void)memset(&engine, 0x5a, sizeof(engine));
    memory = (ninlil_mfdt_v1_engine_slot_memory_t *)(void *)arena.bytes;
    make_valid_memory(memory, arena.bytes);
    rc = invoke_invalid_and_require_no_mutation(
        "descriptor_alias_zeroed_region_zero_mutation",
        &engine,
        memory,
        &arena,
        &fixture);
    fixture_close(&fixture);
    return rc;
}

static int test_config_alias_zeroed_region_rejected(void)
{
    aligned_controls_t controls;
    aligned_bytes_t arena;
    store_fixture_t fixture;
    ninlil_mfdt_v1_engine_t *engine;
    ninlil_mfdt_v1_engine_slot_memory_t *memory;
    ninlil_mfdt_v1_store_port_t *port;
    ninlil_mfdt_v1_config_t *config;
    uint32_t *committed_keys;
    uint64_t *committed_logical_bytes;
    uint8_t *full_locked;
    uint8_t *inventory_uncertain;
    int rc;

    REQUIRE(fixture_open(&fixture));
    make_control_fixture(
        &controls,
        &arena,
        &fixture,
        &engine,
        &memory,
        &port,
        &config,
        &committed_keys,
        &committed_logical_bytes,
        &full_locked,
        &inventory_uncertain);
    config = (ninlil_mfdt_v1_config_t *)(void *)memory->record_memory;
    *config = valid_config();
    rc = invoke_custom_invalid_and_require_no_mutation(
        "config_alias_zeroed_region_zero_mutation",
        &controls,
        &arena,
        &fixture,
        engine,
        memory,
        port,
        committed_keys,
        committed_logical_bytes,
        full_locked,
        inventory_uncertain,
        config);
    fixture_close(&fixture);
    return rc;
}

static int test_config_alias_engine_rejected(void)
{
    aligned_controls_t controls;
    aligned_bytes_t arena;
    store_fixture_t fixture;
    ninlil_mfdt_v1_engine_t *engine;
    ninlil_mfdt_v1_engine_slot_memory_t *memory;
    ninlil_mfdt_v1_store_port_t *port;
    ninlil_mfdt_v1_config_t *config;
    uint32_t *committed_keys;
    uint64_t *committed_logical_bytes;
    uint8_t *full_locked;
    uint8_t *inventory_uncertain;
    ninlil_mfdt_v1_config_t valid = valid_config();
    int rc;

    REQUIRE(fixture_open(&fixture));
    make_control_fixture(
        &controls,
        &arena,
        &fixture,
        &engine,
        &memory,
        &port,
        &config,
        &committed_keys,
        &committed_logical_bytes,
        &full_locked,
        &inventory_uncertain);
    config = (ninlil_mfdt_v1_config_t *)(void *)engine;
    (void)memcpy(config, &valid, sizeof(valid));
    rc = invoke_custom_invalid_and_require_no_mutation(
        "config_alias_engine_zero_mutation",
        &controls,
        &arena,
        &fixture,
        engine,
        memory,
        port,
        committed_keys,
        committed_logical_bytes,
        full_locked,
        inventory_uncertain,
        config);
    fixture_close(&fixture);
    return rc;
}

static int test_control_object_aliases_rejected(void)
{
    static const char *const witnesses[] = {
        "engine_alias_descriptor_zero_mutation",
        "store_port_alias_engine_zero_mutation",
        "committed_counters_alias_zero_mutation",
        "shared_flags_alias_zero_mutation",
        "committed_keys_alias_engine_zero_mutation",
        "full_lock_alias_store_port_zero_mutation",
        "inventory_flag_alias_config_zero_mutation",
        "committed_keys_alias_descriptor_zero_mutation"
    };
    uint8_t scenario;

    for (scenario = 0u; scenario < 8u; ++scenario) {
        aligned_controls_t controls;
        aligned_bytes_t arena;
        store_fixture_t fixture;
        ninlil_mfdt_v1_engine_t *engine;
        ninlil_mfdt_v1_engine_slot_memory_t *memory;
        ninlil_mfdt_v1_store_port_t *port;
        ninlil_mfdt_v1_config_t *config;
        uint32_t *committed_keys;
        uint64_t *committed_logical_bytes;
        uint8_t *full_locked;
        uint8_t *inventory_uncertain;
        int rc;

        REQUIRE(fixture_open(&fixture));
        make_control_fixture(
            &controls,
            &arena,
            &fixture,
            &engine,
            &memory,
            &port,
            &config,
            &committed_keys,
            &committed_logical_bytes,
            &full_locked,
            &inventory_uncertain);
        switch (scenario) {
        case 0u:
            engine = (ninlil_mfdt_v1_engine_t *)(void *)memory;
            break;
        case 1u:
            engine = (ninlil_mfdt_v1_engine_t *)(void *)port;
            break;
        case 2u:
            committed_keys =
                (uint32_t *)(void *)committed_logical_bytes;
            break;
        case 3u:
            inventory_uncertain = full_locked;
            break;
        case 4u:
            committed_keys = (uint32_t *)(void *)engine;
            break;
        case 5u:
            full_locked = &port->reserved0;
            break;
        case 6u:
            inventory_uncertain = &config->host_mode;
            break;
        case 7u:
            committed_keys = &memory->record_memory_bytes;
            break;
        default:
            REQUIRE(0);
        }
        rc = invoke_custom_invalid_and_require_no_mutation(
            witnesses[scenario],
            &controls,
            &arena,
            &fixture,
            engine,
            memory,
            port,
            committed_keys,
            committed_logical_bytes,
            full_locked,
            inventory_uncertain,
            config);
        fixture_close(&fixture);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

static int run_test(const char *name, int (*test)(void))
{
    int rc = test();

    if (rc != 0) {
        (void)fprintf(stderr, "TEST_FAIL %s\n", name);
        return 1;
    }
    (void)printf("TEST_PASS %s\n", name);
    return 0;
}

int main(void)
{
    int failures = 0;

    failures += run_test(
        "valid_disjoint_layout",
        test_valid_disjoint_layout);
    failures += run_test(
        "oversized_disjoint_layout_fini_zeroizes_full_ranges",
        test_oversized_disjoint_layout_fini_zeroizes_full_ranges);
    failures += run_test(
        "unaligned_region_rejected",
        test_unaligned_region_rejected);
    failures += run_test(
        "overlapping_regions_rejected",
        test_overlapping_regions_rejected);
    failures += run_test(
        "engine_alias_rejected",
        test_engine_alias_rejected);
    failures += run_test(
        "descriptor_alias_rejected",
        test_descriptor_alias_rejected);
    failures += run_test(
        "config_alias_zeroed_region_rejected",
        test_config_alias_zeroed_region_rejected);
    failures += run_test(
        "config_alias_engine_rejected",
        test_config_alias_engine_rejected);
    failures += run_test(
        "control_object_aliases_rejected",
        test_control_object_aliases_rejected);
    if (failures != 0) {
        (void)fprintf(
            stderr,
            "mfdt_v1_host_slot_contract_test FAILED (%d)\n",
            failures);
        return 1;
    }
    (void)printf("mfdt_v1_host_slot_contract_test OK\n");
    return 0;
}
