/*
 * Host conformance for dual-slot + durable directory storage (format 4).
 * Does not claim power-cut HIL or M3 complete.
 */

#include "esp_storage_private.h"
#include "storage_provider_conformance.h"

#include "../../ports/esp-idf/storage/model/esp_storage_codec.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define REQUIRE(condition)                                                     \
    do {                                                                       \
        if (!(condition)) {                                                    \
            (void)fprintf(stderr, "%s:%d: requirement failed: %s\n",           \
                __FILE__, __LINE__, #condition);                               \
            return 1;                                                          \
        }                                                                      \
    } while (0)

static ninlil_port_esp_storage_t g_storage;
static ninlil_port_esp_storage_host_media_t g_media;

typedef struct hil_event_trace {
    ninlil_port_esp_storage_hil_event_t events[16];
    uint32_t count;
    int reject;
} hil_event_trace_t;

static int record_hil_event(
    void *observer_user,
    ninlil_port_esp_storage_hil_event_t event)
{
    hil_event_trace_t *trace = (hil_event_trace_t *)observer_user;
    if (trace != NULL && trace->count < 16u) {
        trace->events[trace->count++] = event;
    }
    return trace == NULL || !trace->reject;
}

static ninlil_bytes_view_t bytes(const void *data, uint32_t length)
{
    ninlil_bytes_view_t view;
    view.data = (const uint8_t *)data;
    view.length = length;
    return view;
}

static ninlil_mut_bytes_t mut(void *data, uint32_t capacity)
{
    ninlil_mut_bytes_t value;
    value.data = (uint8_t *)data;
    value.capacity = capacity;
    value.length = 0u;
    return value;
}

static void production_config(ninlil_port_esp_storage_config_t *config)
{
    ninlil_port_esp_storage_config_production(config);
}

static int setup_ops(
    const ninlil_storage_ops_t **ops,
    ninlil_port_esp_storage_private_full_policy_t policy)
{
    ninlil_port_esp_storage_config_t config;
    production_config(&config);
    (void)memset(&g_storage, 0, sizeof(g_storage));
    (void)memset(&g_media, 0, sizeof(g_media));
    REQUIRE(ninlil_port_esp_storage_host_media_init(
                &g_media, config.max_namespaces)
        == 0);
    REQUIRE(ninlil_port_esp_storage_private_init(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                policy)
        == 0);
    *ops = ninlil_port_esp_storage_private_ops(&g_storage);
    REQUIRE(*ops != NULL);
    return 0;
}

static int test_sizeof_ceilings(void)
{
    REQUIRE(sizeof(ninlil_port_esp_storage_view_t)
        <= NINLIL_PORT_ESP_STORAGE_VIEW_SIZEOF_CEILING);
    REQUIRE(sizeof(ninlil_port_esp_storage_t)
        <= NINLIL_PORT_ESP_STORAGE_OBJECT_SIZEOF_CEILING);
    REQUIRE(NINLIL_PORT_ESP_STORAGE_PROD_MAX_LOGICAL_BYTES
        >= 16u + 1u + NINLIL_M1A_MAX_STORAGE_VALUE_BYTES);
    REQUIRE(NINLIL_PORT_ESP_STORAGE_MAX_STACK_FRAME_BYTES <= 2048u);
    REQUIRE(NINLIL_PORT_ESP_STORAGE_OBJECT_SIZEOF_CEILING >= 400000u);
    REQUIRE(NINLIL_PORT_ESP_STORAGE_HARD_MAX_ENTRIES
        >= 2u * NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES);
    REQUIRE(NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES
        >= 2u * NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_LOGICAL_BYTES);
    REQUIRE(sizeof(ninlil_port_esp_storage_iterator_t)
        > sizeof(ninlil_port_esp_storage_view_t));
    return 0;
}

static int test_hil_observer_exact_boundaries(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    hil_event_trace_t trace;
    static const uint8_t ns[] = {'H', 'I', 'L'};
    static const uint8_t key[] = {'a'};
    static const uint8_t value[] = {'v'};

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    (void)memset(&trace, 0, sizeof(trace));
    REQUIRE(ninlil_port_esp_storage_private_set_hil_observer(
                &g_storage, record_hil_event, &trace)
        == 0);
    REQUIRE(ops->open(
                ops->user,
                bytes(ns, sizeof(ns)),
                NINLIL_STORAGE_SCHEMA_M1A,
                &handle)
        == NINLIL_STORAGE_OK);
    REQUIRE(trace.count == 7u);
    REQUIRE(trace.events[0]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE);
    REQUIRE(trace.events[1]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE);
    REQUIRE(trace.events[2]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE);
    REQUIRE(trace.events[3]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN);
    REQUIRE(trace.events[4]
        == NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_ERASE);
    REQUIRE(trace.events[5]
        == NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_WRITE);
    REQUIRE(trace.events[6]
        == NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_SEAL);

    /* A HIL synchronization timeout rejects before the armed media call. */
    {
        uint64_t erase_before =
            ninlil_port_esp_storage_host_media_erase_count(&g_media);
        uint64_t write_before =
            ninlil_port_esp_storage_host_media_program_byte_count(&g_media);
        (void)memset(&trace, 0, sizeof(trace));
        trace.reject = 1;
        REQUIRE(ops->begin(
                    ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->put(
                    ops->user,
                    txn,
                    bytes(key, sizeof(key)),
                    bytes(value, sizeof(value)))
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_IO_ERROR);
        txn = NULL;
        REQUIRE(trace.count == 1u);
        REQUIRE(trace.events[0]
            == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE);
        REQUIRE(ninlil_port_esp_storage_host_media_erase_count(&g_media)
            == erase_before);
        REQUIRE(ninlil_port_esp_storage_host_media_program_byte_count(&g_media)
            == write_before);
    }

    (void)memset(&trace, 0, sizeof(trace));
    REQUIRE(ops->begin(
                ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(
                ops->user,
                txn,
                bytes(key, sizeof(key)),
                bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(trace.count == 3u);
    REQUIRE(trace.events[0]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE);
    REQUIRE(trace.events[1]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE);
    REQUIRE(trace.events[2]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN);

    /* The post-sync event is unreachable when sync itself is indeterminate. */
    (void)memset(&trace, 0, sizeof(trace));
    REQUIRE(ninlil_port_esp_storage_host_media_fault_sync(&g_media, 2, 1u)
        == 0);
    REQUIRE(ops->begin(
                ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(
                ops->user,
                txn,
                bytes(key, sizeof(key)),
                bytes(value, sizeof(value)))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    txn = NULL;
    REQUIRE(trace.count == 2u);
    REQUIRE(trace.events[0]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE);
    REQUIRE(trace.events[1]
        == NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE);

    REQUIRE(ninlil_port_esp_storage_private_set_hil_observer(
                &g_storage, NULL, NULL)
        == 0);
    (void)memset(&trace, 0, sizeof(trace));
    REQUIRE(ops->begin(
                ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(trace.count == 0u);
    ops->close(ops->user, handle);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_codec_golden_and_corruption(void)
{
    ninlil_port_esp_storage_view_t view;
    ninlil_port_esp_storage_view_t decoded;
    uint8_t image[NINLIL_PORT_ESP_STORAGE_SLOT_BYTES];
    uint64_t gen = 0u;
    static const uint8_t ns[] = {0x00u, 0xffu, 0x41u};
    static const uint8_t key[] = {0x01u, 0x02u};
    static const uint8_t val[] = {0x10u, 0x20u, 0x30u};

    (void)memset(&view, 0, sizeof(view));
    view.entry_count = 1u;
    view.entries[0].key_length = 2u;
    (void)memcpy(view.entries[0].key, key, 2u);
    view.entries[0].value_length = 3u;
    view.entries[0].value_offset = 0u;
    (void)memcpy(view.value_blob, val, 3u);
    view.value_blob_used = 3u;
    view.used_logical_bytes = 16u + 2u + 3u;

    REQUIRE(ninlil_port_esp_storage_encode_slot(
                NINLIL_STORAGE_SCHEMA_M1A,
                1u,
                ns,
                (uint32_t)sizeof(ns),
                &view,
                image,
                sizeof(image))
        == 1);
    /* Golden fixed offsets */
    REQUIRE(image[0] == 0x4eu && image[1] == 0x49u && image[2] == 0x4cu
        && image[3] == 0x53u);
    REQUIRE(ninlil_port_esp_storage_load_u32_le(image + 4)
        == NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION);
    REQUIRE(ninlil_port_esp_storage_load_u32_le(image + 12) == 3u);

    REQUIRE(ninlil_port_esp_storage_decode_slot(
                image,
                sizeof(image),
                NINLIL_STORAGE_SCHEMA_M1A,
                ns,
                (uint32_t)sizeof(ns),
                &decoded,
                &gen)
        == 1);
    REQUIRE(gen == 1u);
    REQUIRE(decoded.entry_count == 1u);
    REQUIRE(decoded.entries[0].value_length == 3u);

    /* 1-bit flip in header */
    image[16] ^= 0x01u;
    REQUIRE(ninlil_port_esp_storage_decode_slot(
                image,
                sizeof(image),
                NINLIL_STORAGE_SCHEMA_M1A,
                ns,
                (uint32_t)sizeof(ns),
                &decoded,
                &gen)
        < 0);
    image[16] ^= 0x01u;

    /* Canonical namespace tail must be zero even with a recomputed header CRC. */
    image[16u + sizeof(ns)] = 0x7Eu;
    ninlil_port_esp_storage_store_u32_le(
        image + 304u, ninlil_port_esp_storage_crc32c(image, 304u));
    REQUIRE(ninlil_port_esp_storage_decode_slot(
                image,
                sizeof(image),
                NINLIL_STORAGE_SCHEMA_M1A,
                ns,
                (uint32_t)sizeof(ns),
                &decoded,
                &gen)
        < 0);
    image[16u + sizeof(ns)] = 0u;
    ninlil_port_esp_storage_store_u32_le(
        image + 304u, ninlil_port_esp_storage_crc32c(image, 304u));

    /* trailing garbage in reserved */
    image[308] = 0x01u;
    REQUIRE(ninlil_port_esp_storage_decode_slot(
                image,
                sizeof(image),
                NINLIL_STORAGE_SCHEMA_M1A,
                ns,
                (uint32_t)sizeof(ns),
                &decoded,
                &gen)
        < 0);
    return 0;
}

static int test_directory_reinit_stable_index(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h_a = NULL;
    ninlil_storage_handle_t h_b = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_port_esp_storage_config_t config;
    static const uint8_t ns_a[] = {0x41u};
    static const uint8_t ns_b[] = {0x42u, 0x00u};
    static const uint8_t k[] = {0x01u};
    static const uint8_t v[] = {0x99u};
    uint8_t buf[4];
    ninlil_mut_bytes_t out;
    ninlil_storage_handle_t h = NULL;

    production_config(&config);
    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);

    /* Open B first then A: B->index0, A->index1 in directory order of alloc. */
    REQUIRE(ops->open(
                ops->user, bytes(ns_b, sizeof(ns_b)), NINLIL_STORAGE_SCHEMA_M1A,
                &h_b)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->open(
                ops->user, bytes(ns_a, sizeof(ns_a)), NINLIL_STORAGE_SCHEMA_M1A,
                &h_a)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h_b, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(k, 1u), bytes(v, 1u))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    ops->close(ops->user, h_a);
    ops->close(ops->user, h_b);
    h_a = NULL;
    h_b = NULL;

    /* Full object zero + reinit (true reboot model). */
    REQUIRE(ninlil_port_esp_storage_private_simulate_full_reinit(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
        == 0);
    ops = ninlil_port_esp_storage_private_ops(&g_storage);

    /* Open A first after reboot — must NOT steal B's slot. */
    REQUIRE(ops->open(
                ops->user, bytes(ns_a, sizeof(ns_a)), NINLIL_STORAGE_SCHEMA_M1A,
                &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(buf, sizeof(buf));
    REQUIRE(ops->get(ops->user, txn, bytes(k, 1u), &out)
        == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);
    txn = NULL;
    ops->close(ops->user, h);
    h = NULL;

    REQUIRE(ops->open(
                ops->user, bytes(ns_b, sizeof(ns_b)), NINLIL_STORAGE_SCHEMA_M1A,
                &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(buf, sizeof(buf));
    REQUIRE(ops->get(ops->user, txn, bytes(k, 1u), &out) == NINLIL_STORAGE_OK);
    REQUIRE(out.length == 1u && buf[0] == 0x99u);
    REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);
    ops->close(ops->user, h);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_directory_torn_and_wrong_identity(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_port_esp_storage_config_t config;
    static const uint8_t ns[] = {0x10u};
    production_config(&config);
    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, h);
    h = NULL;

    /* Torn directory write on next open of new name. */
    REQUIRE(ninlil_port_esp_storage_host_media_fault_directory_only(&g_media, 1)
        == 0);
    REQUIRE(ninlil_port_esp_storage_host_media_fault_partial_write(
                &g_media, 16u, 1, 1u)
        == 0);
    {
        static const uint8_t ns2[] = {0x11u};
        ninlil_storage_status_t st = ops->open(
            ops->user, bytes(ns2, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h);
        REQUIRE(st == NINLIL_STORAGE_IO_ERROR || st == NINLIL_STORAGE_COMMIT_UNKNOWN);
        REQUIRE(h == NULL);
    }

    /* Corrupt non-empty directory image => reinit fails closed. */
    g_media.directory[0][0] = 0x55u;
    g_media.directory[0][1] = 0x55u;
    g_media.directory[1][0] = 0x55u;
    REQUIRE(ninlil_port_esp_storage_private_simulate_full_reinit(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
        != 0);

    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_directory_crc_binds_entries_padding_and_seal(void)
{
    ninlil_port_esp_storage_config_t config;
    ninlil_port_esp_storage_directory_cache_t cache;
    ninlil_port_esp_storage_directory_cache_t decoded;
    uint8_t image[NINLIL_PORT_ESP_STORAGE_DIR_BYTES];
    uint8_t image_old[NINLIL_PORT_ESP_STORAGE_DIR_BYTES];
    uint64_t gen = 0u;
    uint32_t entry0 = NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BASE;
    int r;

    production_config(&config);
    (void)memset(&cache, 0, sizeof(cache));
    cache.state[0] = NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED;
    cache.name_length[0] = 2u;
    cache.name[0][0] = 0x41u;
    cache.name[0][1] = 0x00u;
    cache.schema[0] = NINLIL_STORAGE_SCHEMA_M1A;
    cache.data_seed_generation[0] = 1u;

    /* Golden sealed encode/decode */
    REQUIRE(ninlil_port_esp_storage_encode_directory(
                1u, &config, &cache, 1, image, sizeof(image))
        == 1);
    REQUIRE(ninlil_port_esp_storage_load_u32_le(image + 4)
        == NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION);
    REQUIRE(NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION == 4u);
    REQUIRE(ninlil_port_esp_storage_load_u32_le(
                image + NINLIL_PORT_ESP_STORAGE_DIR_SEAL_OFFSET)
        == NINLIL_PORT_ESP_STORAGE_DIR_SEAL_COMMITTED);
    REQUIRE(ninlil_port_esp_storage_decode_directory(
                image, sizeof(image), &config, &decoded, &gen)
        == 1);
    REQUIRE(gen == 1u);
    REQUIRE(decoded.state[0] == NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED);
    REQUIRE(decoded.name_length[0] == 2u);
    REQUIRE(decoded.name[0][0] == 0x41u);

    /* CRC-valid duplicate exact namespace names are ambiguous and rejected. */
    cache.state[1] = NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED;
    cache.name_length[1] = cache.name_length[0];
    (void)memcpy(cache.name[1], cache.name[0], cache.name_length[0]);
    cache.schema[1] = cache.schema[0];
    cache.data_seed_generation[1] = 1u;
    REQUIRE(ninlil_port_esp_storage_encode_directory(
                1u, &config, &cache, 1, image, sizeof(image))
        == 1);
    REQUIRE(ninlil_port_esp_storage_decode_directory(
                image, sizeof(image), &config, &decoded, &gen)
        < 0);
    (void)memset(&cache.state[1], 0, sizeof(cache.state[1]));
    cache.name_length[1] = 0u;
    (void)memset(cache.name[1], 0, sizeof(cache.name[1]));
    cache.schema[1] = 0u;
    cache.data_seed_generation[1] = 0u;
    REQUIRE(ninlil_port_esp_storage_encode_directory(
                1u, &config, &cache, 1, image, sizeof(image))
        == 1);

    /* Entry field bitflips must fail CRC (not accept as valid mapping). */
    {
        uint32_t flip_offsets[] = {
            entry0 + 0u, /* state */
            entry0 + 1u, /* name_length */
            entry0 + 4u, /* schema low */
            entry0 + 8u, /* name[0] */
            entry0 + 272u /* unused entry[1] state/garbage */
        };
        size_t fi;
        for (fi = 0u; fi < sizeof(flip_offsets) / sizeof(flip_offsets[0]); ++fi) {
            uint8_t tmp[NINLIL_PORT_ESP_STORAGE_DIR_BYTES];
            (void)memcpy(tmp, image, sizeof(tmp));
            tmp[flip_offsets[fi]] ^= 0x01u;
            r = ninlil_port_esp_storage_decode_directory(
                tmp, sizeof(tmp), &config, &decoded, &gen);
            REQUIRE(r != 1);
        }
    }

    /* Padding garbage inside protected span. */
    {
        uint8_t tmp[NINLIL_PORT_ESP_STORAGE_DIR_BYTES];
        (void)memcpy(tmp, image, sizeof(tmp));
        tmp[NINLIL_PORT_ESP_STORAGE_DIR_PAD_OFFSET] ^= 0x01u;
        REQUIRE(ninlil_port_esp_storage_decode_directory(
                    tmp, sizeof(tmp), &config, &decoded, &gen)
            != 1);
        (void)memcpy(tmp, image, sizeof(tmp));
        tmp[NINLIL_PORT_ESP_STORAGE_DIR_PROTECTED_BYTES - 1u] ^= 0x01u;
        REQUIRE(ninlil_port_esp_storage_decode_directory(
                    tmp, sizeof(tmp), &config, &decoded, &gen)
            != 1);
    }

    /* Torn seal: CRC-valid body, seal=0xFFFFFFFF (erased) => not selectable. */
    REQUIRE(ninlil_port_esp_storage_encode_directory(
                2u, &config, &cache, 0, image, sizeof(image))
        == 1);
    REQUIRE(ninlil_port_esp_storage_load_u32_le(
                image + NINLIL_PORT_ESP_STORAGE_DIR_SEAL_OFFSET)
        == NINLIL_PORT_ESP_STORAGE_DIR_SEAL_NONE);
    REQUIRE(NINLIL_PORT_ESP_STORAGE_DIR_SEAL_NONE == 0xFFFFFFFFu);
    REQUIRE(ninlil_port_esp_storage_decode_directory(
                image, sizeof(image), &config, &decoded, &gen)
        == 0);

    /* old/new selection: sealed gen1 vs sealed gen2 picks max. */
    (void)memset(&cache, 0, sizeof(cache));
    cache.state[0] = NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED;
    cache.name_length[0] = 1u;
    cache.name[0][0] = 0x01u;
    cache.schema[0] = NINLIL_STORAGE_SCHEMA_M1A;
    cache.data_seed_generation[0] = 1u;
    REQUIRE(ninlil_port_esp_storage_encode_directory(
                1u, &config, &cache, 1, image_old, sizeof(image_old))
        == 1);
    cache.name[0][0] = 0x02u;
    cache.data_seed_generation[0] = 1u;
    REQUIRE(ninlil_port_esp_storage_encode_directory(
                2u, &config, &cache, 1, image, sizeof(image))
        == 1);
    /* gen2 sealed wins over gen1 */
    REQUIRE(ninlil_port_esp_storage_decode_directory(
                image, sizeof(image), &config, &decoded, &gen)
        == 1);
    REQUIRE(gen == 2u);
    REQUIRE(decoded.name[0][0] == 0x02u);
    /* gen2 unsealed loses; gen1 remains selectable when used alone */
    REQUIRE(ninlil_port_esp_storage_encode_directory(
                2u, &config, &cache, 0, image, sizeof(image))
        == 1);
    REQUIRE(ninlil_port_esp_storage_decode_directory(
                image, sizeof(image), &config, &decoded, &gen)
        == 0);
    REQUIRE(ninlil_port_esp_storage_decode_directory(
                image_old, sizeof(image_old), &config, &decoded, &gen)
        == 1);
    REQUIRE(gen == 1u);
    REQUIRE(decoded.name[0][0] == 0x01u);
    return 0;
}

static int test_generation_stale_and_wrap(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_handle_t stale;
    static const uint8_t ns[] = {0x22u};
    uint32_t forced = 0u;

    /* Forced 32-bit pointer budgets: no 16-bit-generation early exhaustion. */
    REQUIRE(ninlil_port_esp_storage_token_generation_max_for_bits(4u, 32u)
        == 0x1fffffffu);
    REQUIRE(ninlil_port_esp_storage_token_generation_max_for_bits(3u, 32u)
        == 0x3fffffffu);
    REQUIRE(ninlil_port_esp_storage_token_generation_max_for_bits(2u, 32u)
        == 0x3fffffffu);
    REQUIRE(ninlil_port_esp_storage_token_generation_max_for_bits(4u, 2u)
        == 0u);
    REQUIRE(ninlil_port_esp_storage_token_next_generation_for_bits(
                0u, 4u, 32u, &forced)
        == 1);
    REQUIRE(forced == 1u);
    REQUIRE(ninlil_port_esp_storage_token_next_generation_for_bits(
                0x1ffffffeu, 4u, 32u, &forced)
        == 1);
    REQUIRE(forced == 0x1fffffffu);
    forced = 0xaaaaaaaau;
    REQUIRE(ninlil_port_esp_storage_token_next_generation_for_bits(
                0x1fffffffu, 4u, 32u, &forced)
        == 0);
    REQUIRE(forced == 0xaaaaaaaau); /* failure does not mutate output */

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    stale = h;
    ops->close(ops->user, h);
    h = NULL;
    /* Stale close/put/rollback fail-closed. */
    ops->close(ops->user, stale);
    REQUIRE(ops->begin(ops->user, stale, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(txn == NULL);

    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    {
        ninlil_storage_txn_t stale_txn = txn;
        REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
        txn = NULL;
        REQUIRE(ops->rollback(ops->user, stale_txn) == NINLIL_STORAGE_CORRUPT);
        REQUIRE(ops->put(
                    ops->user,
                    stale_txn,
                    bytes(ns, 1u),
                    bytes(ns, 1u))
            == NINLIL_STORAGE_CORRUPT);
    }

    ops->close(ops->user, h);
    h = NULL;
    /* One exhausted slot must not strand later usable slots. */
    g_storage.handles[0].generation = UINT32_MAX;
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(h != NULL);
    ops->close(ops->user, h);
    h = NULL;
    /* Exhaust generation on every handle slot: open must fail closed. */
    {
        uint32_t hi;
        for (hi = 0u; hi < NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES; ++hi) {
            g_storage.handles[hi].generation = UINT32_MAX;
            g_storage.handles[hi].in_use = 0;
        }
    }
    {
        ninlil_storage_handle_t h2 = NULL;
        REQUIRE(ops->open(
                    ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h2)
            == NINLIL_STORAGE_NO_SPACE);
        REQUIRE(h2 == NULL);
    }
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_wear_profile_admission_1m_2m_4m(void)
{
    ninlil_port_esp_storage_config_t config;

    production_config(&config);
    config.wl_usable_sector_count = 256u;
    REQUIRE(ninlil_port_esp_storage_endurance_commit_budget(&config)
        == 113329u);
    REQUIRE(ninlil_port_esp_storage_host_media_init(&g_media, 2u) == 0);
    REQUIRE(ninlil_port_esp_storage_private_init(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
        != 0); /* planned 365000 commits cannot fit 1 MiB profile */
    ninlil_port_esp_storage_host_media_deinit(&g_media);

    production_config(&config);
    config.wl_usable_sector_count = 512u;
    REQUIRE(ninlil_port_esp_storage_endurance_commit_budget(&config)
        == 227218u);
    REQUIRE(ninlil_port_esp_storage_host_media_init(&g_media, 2u) == 0);
    REQUIRE(ninlil_port_esp_storage_private_init(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
        != 0); /* 2 MiB profile also rejects */
    ninlil_port_esp_storage_host_media_deinit(&g_media);

    production_config(&config);
    config.wl_usable_sector_count = 1024u;
    REQUIRE(ninlil_port_esp_storage_endurance_commit_budget(&config)
        == 454995u);
    REQUIRE(ninlil_port_esp_storage_host_media_init(&g_media, 2u) == 0);
    REQUIRE(ninlil_port_esp_storage_private_init(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
        == 0); /* reference 4 MiB profile admits planned 365000 */
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_basic_contracts(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t rw = NULL;
    ninlil_storage_txn_t ro = NULL;
    static const uint8_t ns[] = {0x00u, 0xffu};
    static const uint8_t k[] = {0x01u};
    static const uint8_t v1[] = {0xaau, 0xbbu};
    uint8_t buf[8];
    ninlil_mut_bytes_t out;
    ninlil_storage_capacity_t cap;

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, sizeof(ns)), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_WRITE, &rw)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, rw, bytes(k, 1u), bytes(v1, 2u))
        == NINLIL_STORAGE_OK);
    out = mut(buf, sizeof(buf));
    REQUIRE(ops->get(ops->user, rw, bytes(k, 1u), &out) == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &ro)
        == NINLIL_STORAGE_OK);
    out = mut(buf, sizeof(buf));
    REQUIRE(ops->get(ops->user, ro, bytes(k, 1u), &out)
        == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(ops->commit(ops->user, rw, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    rw = NULL;
    REQUIRE(ops->rollback(ops->user, ro) == NINLIL_STORAGE_OK);
    ro = NULL;

    (void)memset(&cap, 0, sizeof(cap));
    cap.abi_version = NINLIL_ABI_VERSION;
    cap.struct_size = (uint16_t)sizeof(cap);
    REQUIRE(ops->capacity(ops->user, h, &cap) == NINLIL_STORAGE_OK);
    REQUIRE(cap.used_entries == 1u);

    /* value 65536 */
    {
        static uint8_t big[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
        static uint8_t reopened[NINLIL_M1A_MAX_STORAGE_VALUE_BYTES];
        static const uint8_t k2[] = {0x02u};
        ninlil_port_esp_storage_config_t config;
        (void)memset(big, 0x5au, sizeof(big));
        REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_WRITE, &rw)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->put(ops->user, rw, bytes(k2, 1u), bytes(big, sizeof(big)))
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->commit(ops->user, rw, NINLIL_DURABILITY_FULL)
            == NINLIL_STORAGE_OK);
        rw = NULL;

        /* Exact cold-reopen readback, not just same-object commit success. */
        ops->close(ops->user, h);
        h = NULL;
        production_config(&config);
        REQUIRE(ninlil_port_esp_storage_private_simulate_full_reinit(
                    &g_storage,
                    &config,
                    ninlil_port_esp_storage_host_media_ops(),
                    &g_media,
                    NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
            == 0);
        ops = ninlil_port_esp_storage_private_ops(&g_storage);
        REQUIRE(ops != NULL);
        REQUIRE(ops->open(
                    ops->user,
                    bytes(ns, sizeof(ns)),
                    NINLIL_STORAGE_SCHEMA_M1A,
                    &h)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &ro)
            == NINLIL_STORAGE_OK);
        out = mut(reopened, sizeof(reopened));
        REQUIRE(ops->get(ops->user, ro, bytes(k2, 1u), &out)
            == NINLIL_STORAGE_OK);
        REQUIRE(out.length == sizeof(reopened));
        REQUIRE(memcmp(reopened, big, sizeof(big)) == 0);
        REQUIRE(ops->rollback(ops->user, ro) == NINLIL_STORAGE_OK);
        ro = NULL;
    }

    ops->close(ops->user, h);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_esp_unproven_never_full_ok(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t rw = NULL;
    static const uint8_t ns[] = {0x33u};
    static const uint8_t k[] = {0x01u};
    static const uint8_t v[] = {0x02u};

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_WRITE, &rw)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, rw, bytes(k, 1u), bytes(v, 1u))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, rw, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    /* Reopen recovers all-new despite unknown public status. */
    {
        ninlil_port_esp_storage_config_t config;
        production_config(&config);
        REQUIRE(ninlil_port_esp_storage_private_simulate_full_reinit(
                    &g_storage,
                    &config,
                    ninlil_port_esp_storage_host_media_ops(),
                    &g_media,
                    NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN)
            == 0);
        ops = ninlil_port_esp_storage_private_ops(&g_storage);
        h = NULL;
        REQUIRE(ops->open(
                    ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
            == NINLIL_STORAGE_OK);
        rw = NULL;
        REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &rw)
            == NINLIL_STORAGE_OK);
        {
            uint8_t buf[2];
            ninlil_mut_bytes_t out = mut(buf, sizeof(buf));
            REQUIRE(ops->get(ops->user, rw, bytes(k, 1u), &out)
                == NINLIL_STORAGE_OK);
        }
        REQUIRE(ops->rollback(ops->user, rw) == NINLIL_STORAGE_OK);
        ops->close(ops->user, h);
    }
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_esp_unproven_readback_match_no_success_promotion(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t rw = NULL;
    static const uint8_t ns[] = {0x44u};
    static const uint8_t k[] = {0xabu};
    static const uint8_t v[] = {0xcdu, 0xefu};
    uint32_t full_ok_count = 0u;
    ninlil_storage_status_t commit_status;

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_WRITE, &rw)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, rw, bytes(k, 1u), bytes(v, sizeof(v)))
        == NINLIL_STORAGE_OK);
    commit_status = ops->commit(ops->user, rw, NINLIL_DURABILITY_FULL);
    if (commit_status == NINLIL_STORAGE_OK) {
        full_ok_count += 1u;
    }
    REQUIRE(commit_status == NINLIL_STORAGE_COMMIT_UNKNOWN);
    rw = NULL;

    {
        ninlil_port_esp_storage_config_t config;
        uint8_t buf[4];
        ninlil_mut_bytes_t out;

        production_config(&config);
        ops->close(ops->user, h);
        h = NULL;
        REQUIRE(ninlil_port_esp_storage_private_simulate_full_reinit(
                    &g_storage,
                    &config,
                    ninlil_port_esp_storage_host_media_ops(),
                    &g_media,
                    NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN)
            == 0);
        ops = ninlil_port_esp_storage_private_ops(&g_storage);
        REQUIRE(ops->open(
                    ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &rw)
            == NINLIL_STORAGE_OK);
        out = mut(buf, sizeof(buf));
        REQUIRE(ops->get(ops->user, rw, bytes(k, 1u), &out)
            == NINLIL_STORAGE_OK);
        REQUIRE(out.length == sizeof(v));
        REQUIRE(memcmp(buf, v, sizeof(v)) == 0);
        REQUIRE(ops->rollback(ops->user, rw) == NINLIL_STORAGE_OK);
        rw = NULL;

        /* Readback matches but ESP_UNPROVEN must not promote to FULL OK. */
        REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_WRITE, &rw)
            == NINLIL_STORAGE_OK);
        REQUIRE(ops->put(ops->user, rw, bytes(k, 1u), bytes(v, sizeof(v)))
            == NINLIL_STORAGE_OK);
        commit_status = ops->commit(ops->user, rw, NINLIL_DURABILITY_FULL);
        if (commit_status == NINLIL_STORAGE_OK) {
            full_ok_count += 1u;
        }
        REQUIRE(commit_status == NINLIL_STORAGE_COMMIT_UNKNOWN);
        rw = NULL;
        ops->close(ops->user, h);
        h = NULL;
    }

    REQUIRE(full_ok_count == 0u);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_flash_erase_ff_and_program_constraints(void)
{
    ninlil_port_esp_storage_host_media_t media;
    uint8_t buf[16];
    uint64_t erases_before;

    REQUIRE(ninlil_port_esp_storage_host_media_init(&media, 2u) == 0);
    /* Fresh partition is 0xFF */
    REQUIRE(media.directory[0][0] == 0xFFu);
    REQUIRE(media.data[0][0][0] == 0xFFu);

    erases_before = ninlil_port_esp_storage_host_media_erase_count(&media);
    /* Misaligned erase must fail */
    REQUIRE(ninlil_port_esp_storage_host_media_ops()->erase(
                &media, 1u, NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN)
        != 0);
    REQUIRE(ninlil_port_esp_storage_host_media_ops()->erase(
                &media, 0u, NINLIL_PORT_ESP_STORAGE_DIR_BYTES)
        == 0);
    REQUIRE(ninlil_port_esp_storage_host_media_erase_count(&media)
        == erases_before + 1u);

    /* 1→0 program OK */
    (void)memset(buf, 0x00, sizeof(buf));
    REQUIRE(ninlil_port_esp_storage_host_media_ops()->write(
                &media, 0u, buf, sizeof(buf))
        == 0);
    /* 0→1 program must fail */
    buf[0] = 0xFFu;
    REQUIRE(ninlil_port_esp_storage_host_media_ops()->write(
                &media, 0u, buf, 1u)
        != 0);
    REQUIRE(media.program_reject_count >= 1u);
    ninlil_port_esp_storage_host_media_deinit(&media);
    return 0;
}

static int test_wear_rotation_sector_accounting(void)
{
    ninlil_port_esp_storage_host_media_t media;
    uint32_t index;
    uint64_t total_before;

    REQUIRE(ninlil_port_esp_storage_host_media_init(&media, 2u) == 0);
    total_before = ninlil_port_esp_storage_host_media_erase_count(&media);
    for (index = 0u;
         index < NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT * 2u;
         ++index) {
        REQUIRE(ninlil_port_esp_storage_host_media_ops()->erase(
                    &media, 0u, NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN)
            == 0);
    }
    REQUIRE(ninlil_port_esp_storage_host_media_erase_count(&media)
        == total_before
            + NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT * 2u);
    REQUIRE(ninlil_port_esp_storage_host_media_hotspot_erase_count(&media)
        == 2u);
    REQUIRE(ninlil_port_esp_storage_host_media_coldspot_erase_count(&media)
        == 2u);
    REQUIRE(ninlil_port_esp_storage_host_media_hotspot_erase_count(&media)
            - ninlil_port_esp_storage_host_media_coldspot_erase_count(&media)
        <= 1u);
    ninlil_port_esp_storage_host_media_deinit(&media);
    return 0;
}

static int test_dual_slot_one_corrupt_recovery(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_port_esp_storage_config_t config;
    static const uint8_t ns[] = {0xD1u};
    static const uint8_t k[] = {0x01u};
    static const uint8_t v[] = {0xAAu};
    uint8_t buf[4];
    ninlil_mut_bytes_t out;

    production_config(&config);
    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(ops->user, txn, bytes(k, 1u), bytes(v, 1u))
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, h);

    /* Corrupt inactive/old directory sector; active sealed remains. */
    (void)memset(g_media.directory[0], 0x5Au, 64u);
    /* Corrupt one data slot; the other holds the committed image. */
    (void)memset(
        g_media.data[0][0], 0x5Au, NINLIL_PORT_ESP_STORAGE_SLOT_HEADER_BYTES);

    REQUIRE(ninlil_port_esp_storage_private_simulate_full_reinit(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
        == 0);
    ops = ninlil_port_esp_storage_private_ops(&g_storage);
    h = NULL;
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_OK);
    out = mut(buf, sizeof(buf));
    REQUIRE(ops->get(ops->user, txn, bytes(k, 1u), &out) == NINLIL_STORAGE_OK);
    REQUIRE(buf[0] == 0xAAu);
    REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);
    ops->close(ops->user, h);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_occupied_both_data_invalid_is_corrupt(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_port_esp_storage_config_t config;
    static const uint8_t ns[] = {0xCCu};

    production_config(&config);
    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, h);

    /* Erase both data slots after OCCUPIED publish — history loss, not empty. */
    (void)memset(
        g_media.data[0][0],
        (int)NINLIL_PORT_ESP_STORAGE_FLASH_ERASED_BYTE,
        NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);
    (void)memset(
        g_media.data[0][1],
        (int)NINLIL_PORT_ESP_STORAGE_FLASH_ERASED_BYTE,
        NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);

    REQUIRE(ninlil_port_esp_storage_private_simulate_full_reinit(
                &g_storage,
                &config,
                ninlil_port_esp_storage_host_media_ops(),
                &g_media,
                NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL)
        == 0);
    ops = ninlil_port_esp_storage_private_ops(&g_storage);
    h = NULL;
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    txn = NULL;
    REQUIRE(ops->begin(ops->user, h, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_CORRUPT);
    ops->close(ops->user, h);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_directory_seed_generation_is_minimum(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    static const uint8_t ns[] = {0xCDu};

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &handle)
        == NINLIL_STORAGE_OK);
    REQUIRE(g_storage.directory.data_seed_generation[0] == 1u);
    /* Both durable data siblings are generation 1; directory requires >=2. */
    g_storage.directory.data_seed_generation[0] = 2u;
    REQUIRE(ops->begin(
                ops->user, handle, NINLIL_STORAGE_READ_ONLY, &txn)
        == NINLIL_STORAGE_CORRUPT);
    REQUIRE(txn == NULL);
    ops->close(ops->user, handle);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_fresh_partition_init(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    static const uint8_t ns[] = {0xFFu, 0x00u};

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(g_media.directory[0][0] == 0xFFu);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 2u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    ops->close(ops->user, h);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_provider_neutral_final_view_contract(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t handle = NULL;
    static const uint8_t ns[] = {'S', 'P', 'C'};

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(
                ops->user,
                bytes(ns, sizeof(ns)),
                NINLIL_STORAGE_SCHEMA_M1A,
                &handle)
        == NINLIL_STORAGE_OK);
    REQUIRE(ninlil_test_storage_provider_final_view_contract(ops, handle) == 0);
    ops->close(ops->user, handle);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_staging_over_bound_and_erase_alias(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_mut_bytes_t output;
    uint8_t keys[65u][2u];
    uint8_t values[65u];
    uint8_t output_byte = 0u;
    uint8_t alias_key[] = {0x10u};
    const uint8_t *scratch_key;
    uint32_t index;
    static const uint8_t ns[] = {'B', 'N', 'D'};

    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);
    REQUIRE(ops->open(ops->user,
                bytes(ns, sizeof(ns)),
                NINLIL_STORAGE_SCHEMA_M1A,
                &handle)
        == NINLIL_STORAGE_OK);

    REQUIRE(ops->begin(
                ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    for (index = 0u; index < 65u; ++index) {
        keys[index][0] = 0x40u;
        keys[index][1] = (uint8_t)index;
        values[index] = (uint8_t)(index + 1u);
        if (index < 64u) {
            REQUIRE(ops->put(ops->user,
                        txn,
                        bytes(keys[index], sizeof(keys[index])),
                        bytes(&values[index], 1u))
                == NINLIL_STORAGE_OK);
        } else {
            REQUIRE(ops->put(ops->user,
                        txn,
                        bytes(keys[index], sizeof(keys[index])),
                        bytes(&values[index], 1u))
                == NINLIL_STORAGE_NO_SPACE);
        }
    }
    REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);
    txn = NULL;

    REQUIRE(ops->begin(
                ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
        == NINLIL_STORAGE_OK);
    REQUIRE(ops->put(
                ops->user, txn, bytes(alias_key, 1u), bytes(values, 1u))
        == NINLIL_STORAGE_OK);
    REQUIRE(g_storage.mutation_scratch.entry_count == 1u);
    scratch_key = g_storage.mutation_scratch.entries[0].key;
    REQUIRE(ops->erase(ops->user, txn, bytes(scratch_key, 1u))
        == NINLIL_STORAGE_OK);
    output = mut(&output_byte, 1u);
    REQUIRE(ops->get(ops->user, txn, bytes(alias_key, 1u), &output)
        == NINLIL_STORAGE_NOT_FOUND);
    REQUIRE(ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK);

    ops->close(ops->user, handle);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

static int test_directory_publish_unknown_fences_ram_cache(void)
{
    const ninlil_storage_ops_t *ops = NULL;
    ninlil_storage_handle_t h = NULL;
    ninlil_port_esp_storage_config_t config;
    static const uint8_t ns[] = {0xFEu};

    production_config(&config);
    REQUIRE(setup_ops(&ops, NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) == 0);

    /*
     * First open: seed data then directory commit. Fault directory write path
     * so publish is indeterminate after seed may have landed.
     */
    REQUIRE(ninlil_port_esp_storage_host_media_fault_directory_only(&g_media, 1)
        == 0);
    REQUIRE(ninlil_port_esp_storage_host_media_fault_sync(&g_media, 2, 1u)
        == 0);
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(h == NULL);
    /* RAM must not keep OCCUPIED as authority. */
    REQUIRE(g_storage.directory_cache_fenced == 1);
    REQUIRE(g_storage.directory.state[0]
        != NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED
        || g_storage.directory.generation == 0u);

    /* Next open reloads media and converges (all-old or all-new). */
    REQUIRE(ops->open(
                ops->user, bytes(ns, 1u), NINLIL_STORAGE_SCHEMA_M1A, &h)
        == NINLIL_STORAGE_OK);
    REQUIRE(h != NULL);
    REQUIRE(g_storage.directory_cache_fenced == 0);
    ops->close(ops->user, h);
    ninlil_port_esp_storage_private_deinit(&g_storage);
    ninlil_port_esp_storage_host_media_deinit(&g_media);
    return 0;
}

int main(void)
{
    REQUIRE(test_sizeof_ceilings() == 0);
    REQUIRE(test_hil_observer_exact_boundaries() == 0);
    REQUIRE(ninlil_port_esp_storage_private_placement_ok(&g_storage) == 1);
    REQUIRE(test_flash_erase_ff_and_program_constraints() == 0);
    REQUIRE(test_wear_rotation_sector_accounting() == 0);
    REQUIRE(test_wear_profile_admission_1m_2m_4m() == 0);
    REQUIRE(test_codec_golden_and_corruption() == 0);
    REQUIRE(test_fresh_partition_init() == 0);
    REQUIRE(test_directory_reinit_stable_index() == 0);
    REQUIRE(test_directory_torn_and_wrong_identity() == 0);
    REQUIRE(test_directory_crc_binds_entries_padding_and_seal() == 0);
    REQUIRE(test_dual_slot_one_corrupt_recovery() == 0);
    REQUIRE(test_occupied_both_data_invalid_is_corrupt() == 0);
    REQUIRE(test_directory_seed_generation_is_minimum() == 0);
    REQUIRE(test_directory_publish_unknown_fences_ram_cache() == 0);
    REQUIRE(test_generation_stale_and_wrap() == 0);
    REQUIRE(test_basic_contracts() == 0);
    REQUIRE(test_provider_neutral_final_view_contract() == 0);
    REQUIRE(test_staging_over_bound_and_erase_alias() == 0);
    REQUIRE(test_esp_unproven_never_full_ok() == 0);
    REQUIRE(test_esp_unproven_readback_match_no_success_promotion() == 0);
    return 0;
}
