/*
 * Dual-slot + durable directory storage model (format 4).
 * C11, no heap/VLA. Fixed-endian codec for all persistent bytes.
 */

#include "esp_storage_codec.h"
#include "esp_storage_private.h"

#include <string.h>

#if defined(ESP_PLATFORM)
/* esp_ptr_external_ram: ESP-IDF v5.5.x declares this in esp_memory_utils.h */
#include "esp_memory_utils.h"
#endif

#define MEDIA_OK 0
#define MEDIA_DEFINITE_FAIL 1
#define MEDIA_UNKNOWN 2

#define CHECKPOINT_SECTOR_ERASES                                               \
    (NINLIL_PORT_ESP_STORAGE_SLOT_BYTES                                        \
        / NINLIL_PORT_ESP_STORAGE_ERASE_ALIGN)

/* ---- geometry ---- */

uint64_t ninlil_port_esp_storage_media_directory_offset(uint32_t dir_slot)
{
    return (uint64_t)dir_slot * (uint64_t)NINLIL_PORT_ESP_STORAGE_DIR_BYTES;
}

uint64_t ninlil_port_esp_storage_media_data_offset(
    uint32_t max_namespaces,
    uint32_t ns_index,
    uint32_t data_slot)
{
    uint64_t base = 2u * (uint64_t)NINLIL_PORT_ESP_STORAGE_DIR_BYTES;
    (void)max_namespaces;
    return base
        + ((uint64_t)ns_index * 2u + (uint64_t)data_slot)
            * (uint64_t)NINLIL_PORT_ESP_STORAGE_SLOT_BYTES;
}

uint64_t ninlil_port_esp_storage_media_total_bytes(uint32_t max_namespaces)
{
    return 2u * (uint64_t)NINLIL_PORT_ESP_STORAGE_DIR_BYTES
        + (uint64_t)max_namespaces * 2u
            * (uint64_t)NINLIL_PORT_ESP_STORAGE_SLOT_BYTES;
}

void ninlil_port_esp_storage_config_production(
    ninlil_port_esp_storage_config_t *out_config)
{
    if (out_config == NULL) {
        return;
    }
    out_config->max_namespaces = NINLIL_PORT_ESP_STORAGE_PROD_MAX_NAMESPACES;
    out_config->max_entries_per_namespace =
        NINLIL_PORT_ESP_STORAGE_PROD_MAX_ENTRIES;
    out_config->max_bytes_per_namespace =
        NINLIL_PORT_ESP_STORAGE_PROD_MAX_LOGICAL_BYTES;
    out_config->max_live_txns = NINLIL_PORT_ESP_STORAGE_PROD_MAX_TXNS;
    out_config->max_live_iters = NINLIL_PORT_ESP_STORAGE_PROD_MAX_ITERS;
    out_config->wl_usable_sector_count =
        NINLIL_PORT_ESP_STORAGE_HOST_PHYSICAL_SECTOR_COUNT;
    out_config->assumed_erase_endurance = 10000u;
    out_config->wear_reserve_percent = 20u;
    out_config->planned_full_commits_per_day = 200u;
    out_config->planned_service_days = 1825u;
}

uint64_t ninlil_port_esp_storage_endurance_commit_budget(
    const ninlil_port_esp_storage_config_t *config)
{
    uint64_t usable_sectors;
    uint64_t sector_erase_budget;
    uint64_t setup_sector_reserve;
    if (config == NULL || config->wl_usable_sector_count == 0u
        || config->assumed_erase_endurance == 0u
        || config->wear_reserve_percent >= 100u
        || CHECKPOINT_SECTOR_ERASES == 0u) {
        return 0u;
    }
    usable_sectors =
        (uint64_t)config->wl_usable_sector_count
        * (uint64_t)(100u - config->wear_reserve_percent) / 100u;
    sector_erase_budget =
        usable_sectors * (uint64_t)config->assumed_erase_endurance;
    /* First publication seeds both data siblings and rotates directory. */
    setup_sector_reserve =
        (uint64_t)config->max_namespaces
        * (uint64_t)(2u * CHECKPOINT_SECTOR_ERASES + 2u);
    if (sector_erase_budget <= setup_sector_reserve) {
        return 0u;
    }
    return (sector_erase_budget - setup_sector_reserve)
        / (uint64_t)CHECKPOINT_SECTOR_ERASES;
}

/* ---- value tokens: generation + minimum index bits; zero is reserved ---- */

static uint32_t token_index_bits(uint32_t max_index_exclusive)
{
    uint32_t bits = 0u;
    uint32_t value = max_index_exclusive;
    while (value != 0u) {
        bits += 1u;
        value >>= 1u;
    }
    return bits == 0u ? 1u : bits;
}

uint32_t ninlil_port_esp_storage_token_generation_max_for_bits(
    uint32_t max_index_exclusive,
    uint32_t uintptr_bits)
{
    uint32_t index_bits = token_index_bits(max_index_exclusive);
    uint32_t generation_bits;
    if (max_index_exclusive == 0u || uintptr_bits <= index_bits) {
        return 0u;
    }
    generation_bits = uintptr_bits - index_bits;
    if (generation_bits >= 32u) {
        return UINT32_MAX;
    }
    return ((uint32_t)1u << generation_bits) - 1u;
}

static uint32_t token_generation_max(uint32_t max_index_exclusive)
{
    return ninlil_port_esp_storage_token_generation_max_for_bits(
        max_index_exclusive, (uint32_t)(sizeof(uintptr_t) * 8u));
}

int ninlil_port_esp_storage_token_next_generation_for_bits(
    uint32_t current,
    uint32_t max_index_exclusive,
    uint32_t uintptr_bits,
    uint32_t *out_generation)
{
    uint32_t maximum =
        ninlil_port_esp_storage_token_generation_max_for_bits(
            max_index_exclusive, uintptr_bits);
    if (out_generation == NULL || maximum == 0u || current >= maximum) {
        return 0;
    }
    *out_generation = current + 1u;
    return 1;
}

static void *pack_token(
    uint32_t index,
    uint32_t generation,
    uint32_t max_index_exclusive)
{
    uint32_t bits = token_index_bits(max_index_exclusive);
    uintptr_t value = ((uintptr_t)generation << bits)
        | (uintptr_t)(index + 1u);
    return (void *)value;
}

static int unpack_token(
    void *opaque,
    uint32_t max_index_exclusive,
    uint32_t *out_index,
    uint32_t *out_generation)
{
    uintptr_t value;
    uint32_t idx1;
    uint32_t bits;
    uintptr_t index_mask;

    if (opaque == NULL || out_index == NULL || out_generation == NULL) {
        return 0;
    }
    value = (uintptr_t)opaque;
    bits = token_index_bits(max_index_exclusive);
    index_mask = (((uintptr_t)1u << bits) - (uintptr_t)1u);
    idx1 = (uint32_t)(value & index_mask);
    if (idx1 == 0u || idx1 > max_index_exclusive) {
        return 0;
    }
    *out_index = idx1 - 1u;
    *out_generation = (uint32_t)(value >> bits);
    return *out_generation != 0u
        && *out_generation <= token_generation_max(max_index_exclusive);
}

static int next_generation(
    uint32_t current,
    uint32_t max_index_exclusive,
    uint32_t *out_generation)
{
    return ninlil_port_esp_storage_token_next_generation_for_bits(
        current,
        max_index_exclusive,
        (uint32_t)(sizeof(uintptr_t) * 8u),
        out_generation);
}

/* ---- helpers ---- */

static int view_shape_is_valid(
    ninlil_bytes_view_t view,
    uint32_t minimum,
    uint32_t maximum)
{
    if (view.length < minimum || view.length > maximum) {
        return 0;
    }
    if (view.length == 0u) {
        return view.data == NULL;
    }
    return view.data != NULL;
}

static int mut_shape_is_valid(const ninlil_mut_bytes_t *value)
{
    if (value == NULL || value->length != 0u) {
        return 0;
    }
    if (value->capacity == 0u) {
        return value->data == NULL;
    }
    return value->data != NULL;
}

static int mut_ranges_do_not_overlap(
    const ninlil_mut_bytes_t *left,
    const ninlil_mut_bytes_t *right)
{
    uintptr_t left_start;
    uintptr_t left_end;
    uintptr_t right_start;
    uintptr_t right_end;

    if (left->capacity == 0u || right->capacity == 0u) {
        return 1;
    }
    left_start = (uintptr_t)left->data;
    right_start = (uintptr_t)right->data;
    if ((uintptr_t)left->capacity > UINTPTR_MAX - left_start
        || (uintptr_t)right->capacity > UINTPTR_MAX - right_start) {
        return 0;
    }
    left_end = left_start + (uintptr_t)left->capacity;
    right_end = right_start + (uintptr_t)right->capacity;
    return left_end <= right_start || right_end <= left_start;
}

static int bytes_compare(
    const uint8_t *left,
    uint32_t left_length,
    const uint8_t *right,
    uint32_t right_length)
{
    uint32_t common = left_length < right_length ? left_length : right_length;
    int compared = common == 0u ? 0 : memcmp(left, right, (size_t)common);
    if (compared != 0) {
        return compared;
    }
    if (left_length < right_length) {
        return -1;
    }
    if (left_length > right_length) {
        return 1;
    }
    return 0;
}

static uint32_t find_entry(
    const ninlil_port_esp_storage_view_t *view,
    ninlil_bytes_view_t key,
    int *found)
{
    uint32_t low = 0u;
    uint32_t high = view->entry_count;
    while (low < high) {
        uint32_t middle = low + ((high - low) / 2u);
        int compared = bytes_compare(
            view->entries[middle].key,
            view->entries[middle].key_length,
            key.data,
            key.length);
        if (compared < 0) {
            low = middle + 1u;
        } else {
            high = middle;
        }
    }
    *found = low < view->entry_count
        && bytes_compare(
               view->entries[low].key,
               view->entries[low].key_length,
               key.data,
               key.length)
            == 0;
    return low;
}

static int view_recompute(ninlil_port_esp_storage_view_t *view)
{
    uint64_t bytes = 0u;
    uint32_t index;
    for (index = 0u; index < view->entry_count; ++index) {
        bytes += 16u + view->entries[index].key_length
            + view->entries[index].value_length;
    }
    view->used_logical_bytes = bytes;
    return 1;
}

static int capacity_ok(
    const ninlil_port_esp_storage_t *storage,
    const ninlil_port_esp_storage_view_t *view)
{
    return view->entry_count <= storage->config.max_entries_per_namespace
        && view->used_logical_bytes <= storage->config.max_bytes_per_namespace;
}

static int config_valid(const ninlil_port_esp_storage_config_t *config)
{
    uint64_t planned;
    uint64_t budget;
    uint64_t required_logical_sectors;
    if (config == NULL) {
        return 0;
    }
    budget = ninlil_port_esp_storage_endurance_commit_budget(config);
    planned = (uint64_t)config->planned_full_commits_per_day
        * (uint64_t)config->planned_service_days;
    required_logical_sectors = 2u
        + (uint64_t)config->max_namespaces * 2u
            * (uint64_t)CHECKPOINT_SECTOR_ERASES;
    return config->max_namespaces > 0u
        && config->max_namespaces <= NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES
        && config->max_entries_per_namespace > 0u
        && config->max_entries_per_namespace
            <= NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES
        && config->max_entries_per_namespace != UINT64_MAX
        && config->max_bytes_per_namespace > 0u
        && config->max_bytes_per_namespace
            <= NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_LOGICAL_BYTES
        && config->max_bytes_per_namespace != UINT64_MAX
        && config->max_bytes_per_namespace
            >= (16u + 1u + NINLIL_M1A_MAX_STORAGE_VALUE_BYTES)
        && config->max_live_txns > 0u
        && config->max_live_txns <= NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS
        && config->max_live_iters > 0u
        && config->max_live_iters <= NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS
        && (uint64_t)config->wl_usable_sector_count >= required_logical_sectors
        && config->assumed_erase_endurance > 0u
        && config->wear_reserve_percent > 0u
        && config->wear_reserve_percent < 100u
        && config->planned_full_commits_per_day > 0u
        && config->planned_service_days > 0u
        && budget > 0u
        && planned <= budget;
}

/* ---- directory load / commit ---- */

static int load_directory(ninlil_port_esp_storage_t *storage)
{
    ninlil_port_esp_storage_directory_cache_t *cache0 = &storage->dir_cache_a;
    ninlil_port_esp_storage_directory_cache_t *cache1 = &storage->dir_cache_b;
    uint64_t gen0 = 0u;
    uint64_t gen1 = 0u;
    int r0;
    int r1;

    if (storage->media_ops->read(
            storage->media_user,
            ninlil_port_esp_storage_media_directory_offset(0u),
            storage->dir_scratch,
            NINLIL_PORT_ESP_STORAGE_DIR_BYTES)
        != MEDIA_OK) {
        return -1;
    }
    r0 = ninlil_port_esp_storage_decode_directory(
        storage->dir_scratch,
        NINLIL_PORT_ESP_STORAGE_DIR_BYTES,
        &storage->config,
        cache0,
        &gen0);

    if (storage->media_ops->read(
            storage->media_user,
            ninlil_port_esp_storage_media_directory_offset(1u),
            storage->dir_scratch,
            NINLIL_PORT_ESP_STORAGE_DIR_BYTES)
        != MEDIA_OK) {
        return -1;
    }
    r1 = ninlil_port_esp_storage_decode_directory(
        storage->dir_scratch,
        NINLIL_PORT_ESP_STORAGE_DIR_BYTES,
        &storage->config,
        cache1,
        &gen1);

    /*
     * Dual-slot recovery: one corrupt/torn sibling is ignored if the other
     * is valid. Only both non-valid is empty (both erased) or fail-closed.
     */
    if (r0 == 1 && r1 == 1 && gen0 == gen1) {
        return -1;
    }
    if (r0 == 1 && (r1 != 1 || gen0 > gen1)) {
        storage->directory = *cache0;
        storage->directory.generation = gen0;
        storage->directory.active_dir_slot = 0u;
        return 1;
    }
    if (r1 == 1 && (r0 != 1 || gen1 > gen0)) {
        storage->directory = *cache1;
        storage->directory.generation = gen1;
        storage->directory.active_dir_slot = 1u;
        return 1;
    }
    if (r0 == 0 && r1 == 0) {
        (void)memset(&storage->directory, 0, sizeof(storage->directory));
        storage->directory.generation = 0u;
        storage->directory.active_dir_slot = 0u;
        return 1; /* both empty/unsealed → empty media */
    }
    /* At least one corrupt (-1) and none valid → fail closed */
    return -1;
}

static int observe_hil_boundary(
    ninlil_port_esp_storage_t *storage,
    ninlil_port_esp_storage_hil_event_t event)
{
    return storage->hil_observer == NULL
        || storage->hil_observer(storage->hil_observer_user, event) != 0;
}

static int commit_directory(ninlil_port_esp_storage_t *storage)
{
    uint32_t inactive = storage->directory.active_dir_slot ^ 1u;
    uint64_t new_gen;
    uint64_t base;
    uint8_t seal_bytes[4];
    int rc;

    if (storage->directory.generation == UINT64_MAX) {
        return MEDIA_DEFINITE_FAIL;
    }
    new_gen = storage->directory.generation + 1u;
    if (new_gen == 0u) {
        new_gen = 1u;
    }
    /*
     * Phase 1: write full sector with seal=NONE (CRC covers entries+padding).
     * Phase 2: independent final 4-byte SEAL_COMMITTED write at SEAL_OFFSET.
     * Power-cut before phase 2 leaves unsealed image (not selected).
     */
    if (!ninlil_port_esp_storage_encode_directory(
            new_gen,
            &storage->config,
            &storage->directory,
            0,
            storage->dir_scratch,
            NINLIL_PORT_ESP_STORAGE_DIR_BYTES)) {
        return MEDIA_DEFINITE_FAIL;
    }
    base = ninlil_port_esp_storage_media_directory_offset(inactive);
    if (!observe_hil_boundary(
            storage,
            NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_ERASE)) {
        return MEDIA_DEFINITE_FAIL;
    }
    rc = storage->media_ops->erase(
        storage->media_user, base, NINLIL_PORT_ESP_STORAGE_DIR_BYTES);
    if (rc != MEDIA_OK) {
        return rc == MEDIA_UNKNOWN ? MEDIA_UNKNOWN : MEDIA_DEFINITE_FAIL;
    }
    if (!observe_hil_boundary(
            storage,
            NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_WRITE)) {
        return MEDIA_DEFINITE_FAIL;
    }
    rc = storage->media_ops->write(
        storage->media_user,
        base,
        storage->dir_scratch,
        NINLIL_PORT_ESP_STORAGE_DIR_BYTES);
    if (rc != MEDIA_OK) {
        return rc;
    }
    rc = storage->media_ops->sync(storage->media_user);
    if (rc != MEDIA_OK) {
        return MEDIA_UNKNOWN;
    }

    ninlil_port_esp_storage_store_u32_le(
        seal_bytes, NINLIL_PORT_ESP_STORAGE_DIR_SEAL_COMMITTED);
    if (!observe_hil_boundary(
            storage,
            NINLIL_PORT_ESP_STORAGE_HIL_DIRECTORY_BEFORE_SEAL)) {
        return MEDIA_DEFINITE_FAIL;
    }
    rc = storage->media_ops->write(
        storage->media_user,
        base + NINLIL_PORT_ESP_STORAGE_DIR_SEAL_OFFSET,
        seal_bytes,
        4u);
    if (rc != MEDIA_OK) {
        return rc == MEDIA_DEFINITE_FAIL ? MEDIA_DEFINITE_FAIL : MEDIA_UNKNOWN;
    }
    rc = storage->media_ops->sync(storage->media_user);
    if (rc != MEDIA_OK) {
        return MEDIA_UNKNOWN;
    }
    storage->directory.generation = new_gen;
    storage->directory.active_dir_slot = inactive;
    return MEDIA_OK;
}

static void copy_view(
    ninlil_port_esp_storage_view_t *dest,
    const ninlil_port_esp_storage_view_t *src)
{
    if (dest != src) {
        (void)memcpy(dest, src, sizeof(*dest));
    }
}

static int load_namespace_content(
    ninlil_port_esp_storage_t *storage,
    uint32_t ns_index,
    ninlil_port_esp_storage_view_t *out_view,
    uint64_t *out_generation,
    uint32_t *out_active_slot)
{
    /* Dual decode targets live in the storage object (PSRAM), never stack. */
    ninlil_port_esp_storage_view_t *view0 = &storage->work_view_a;
    ninlil_port_esp_storage_view_t *view1 = &storage->work_view_b;
    uint64_t gen0 = 0u;
    uint64_t gen1 = 0u;
    int r0;
    int r1;
    const uint8_t *name = storage->directory.name[ns_index];
    uint32_t name_len = storage->directory.name_length[ns_index];
    uint32_t schema = storage->directory.schema[ns_index];

    if (out_view == NULL || out_generation == NULL || out_active_slot == NULL) {
        return -1;
    }

    if (storage->media_ops->read(
            storage->media_user,
            ninlil_port_esp_storage_media_data_offset(
                storage->config.max_namespaces, ns_index, 0u),
            storage->pack_scratch,
            NINLIL_PORT_ESP_STORAGE_SLOT_BYTES)
        != MEDIA_OK) {
        return -1;
    }
    r0 = ninlil_port_esp_storage_decode_slot(
        storage->pack_scratch,
        NINLIL_PORT_ESP_STORAGE_SLOT_BYTES,
        schema,
        name,
        name_len,
        view0,
        &gen0);

    if (storage->media_ops->read(
            storage->media_user,
            ninlil_port_esp_storage_media_data_offset(
                storage->config.max_namespaces, ns_index, 1u),
            storage->pack_scratch,
            NINLIL_PORT_ESP_STORAGE_SLOT_BYTES)
        != MEDIA_OK) {
        return -1;
    }
    r1 = ninlil_port_esp_storage_decode_slot(
        storage->pack_scratch,
        NINLIL_PORT_ESP_STORAGE_SLOT_BYTES,
        schema,
        name,
        name_len,
        view1,
        &gen1);

    /* Directory publication is authority for the minimum seeded generation. */
    if (r0 == 1
        && gen0 < storage->directory.data_seed_generation[ns_index]) {
        r0 = -1;
    }
    if (r1 == 1
        && gen1 < storage->directory.data_seed_generation[ns_index]) {
        r1 = -1;
    }

    if (r0 == 1 && r1 == 1 && gen0 == gen1) {
        return -1;
    }
    if (r0 == 1 && (r1 != 1 || gen0 > gen1)) {
        copy_view(out_view, view0);
        *out_generation = gen0;
        *out_active_slot = 0u;
        return 1;
    }
    if (r1 == 1 && (r0 != 1 || gen1 > gen0)) {
        copy_view(out_view, view1);
        *out_generation = gen1;
        *out_active_slot = 1u;
        return 1;
    }
    /*
     * OCCUPIED namespaces must have a durable data seed. Both slots invalid
     * (erased or corrupt) is never silent empty — fail closed as CORRUPT.
     */
    (void)memset(out_view, 0, sizeof(*out_view));
    *out_generation = 0u;
    *out_active_slot = 0u;
    return -1;
}

static void refresh_ns_cache_from_directory(ninlil_port_esp_storage_t *storage)
{
    uint32_t i;
    for (i = 0u; i < storage->config.max_namespaces; ++i) {
        ninlil_port_esp_storage_namespace_t *ns = &storage->namespaces[i];
        int leased = ns->leased;
        (void)memset(ns, 0, sizeof(*ns));
        ns->leased = leased;
        if (storage->directory.state[i]
            == NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED) {
            ns->cached = 1;
            ns->name_length = storage->directory.name_length[i];
            (void)memcpy(
                ns->name, storage->directory.name[i], ns->name_length);
            ns->schema = storage->directory.schema[i];
        }
    }
}

/*
 * Drop RAM directory/namespace cache as authoritative after indeterminate
 * durable publish. Next open must reload media (all-old/all-new).
 */
static void fence_directory_cache(ninlil_port_esp_storage_t *storage)
{
    uint32_t i;

    (void)memset(&storage->directory, 0, sizeof(storage->directory));
    for (i = 0u; i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES; ++i) {
        int leased = storage->namespaces[i].leased;
        (void)memset(
            &storage->namespaces[i], 0, sizeof(storage->namespaces[i]));
        storage->namespaces[i].leased = leased;
    }
    storage->directory_cache_fenced = 1;
}

static int reload_directory_from_media(ninlil_port_esp_storage_t *storage)
{
    int rc = load_directory(storage);
    if (rc < 0) {
        return -1;
    }
    refresh_ns_cache_from_directory(storage);
    storage->directory_cache_fenced = 0;
    return 0;
}

static int find_directory_index(
    const ninlil_port_esp_storage_t *storage,
    ninlil_bytes_view_t name,
    uint32_t *out_index)
{
    uint32_t i;
    for (i = 0u; i < storage->config.max_namespaces; ++i) {
        if (storage->directory.state[i]
                == NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED
            && storage->directory.name_length[i] == name.length
            && memcmp(storage->directory.name[i], name.data, name.length)
                == 0) {
            *out_index = i;
            return 1;
        }
    }
    return 0;
}

static int find_free_directory_index(
    const ninlil_port_esp_storage_t *storage,
    uint32_t *out_index)
{
    uint32_t i;
    for (i = 0u; i < storage->config.max_namespaces; ++i) {
        if (storage->directory.state[i]
            == NINLIL_PORT_ESP_STORAGE_DIR_STATE_FREE) {
            *out_index = i;
            return 1;
        }
    }
    return 0;
}

/* ---- ops forward ---- */

static ninlil_storage_status_t port_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle);
static void port_close(void *user, ninlil_storage_handle_t handle);
static ninlil_storage_status_t port_begin(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn);
static ninlil_storage_status_t port_get(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value);
static ninlil_storage_status_t port_put(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value);
static ninlil_storage_status_t port_erase(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t key);
static ninlil_storage_status_t port_iter_open(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter);
static ninlil_storage_status_t port_iter_next(
    void *user,
    ninlil_storage_iter_t iter,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value);
static void port_iter_close(void *user, ninlil_storage_iter_t iter);
static ninlil_storage_status_t port_capacity(
    void *user,
    ninlil_storage_handle_t handle,
    ninlil_storage_capacity_t *out_capacity);
static ninlil_storage_status_t port_commit(
    void *user,
    ninlil_storage_txn_t txn,
    ninlil_durability_t durability);
static ninlil_storage_status_t port_rollback(void *user, ninlil_storage_txn_t txn);

int ninlil_port_esp_storage_private_placement_ok(const void *object)
{
    if (object == NULL) {
        return 0;
    }
#if defined(ESP_PLATFORM)
    /* Reject internal DRAM/BSS placement of the large object. */
    return esp_ptr_external_ram(object) ? 1 : 0;
#else
    (void)object;
    return 1;
#endif
}

static int esp_psram_ok(const void *storage_object)
{
#if defined(ESP_PLATFORM)
    /* The caller already allocated the complete object; placement is proof. */
    return ninlil_port_esp_storage_private_placement_ok(storage_object);
#else
    (void)storage_object;
    return 1;
#endif
}

/* Write durable empty data seed (gen>=1, 0 entries) before directory publish. */
static int seed_empty_namespace_data(
    ninlil_port_esp_storage_t *storage,
    uint32_t ns_index,
    uint32_t schema,
    const uint8_t *name,
    uint32_t name_len,
    uint64_t seed_generation)
{
    uint64_t base0;
    uint64_t base1;
    int rc;

    /* Empty view lives in object workspace — not on the call stack. */
    (void)memset(&storage->work_view_a, 0, sizeof(storage->work_view_a));
    if (!ninlil_port_esp_storage_encode_slot(
            schema,
            seed_generation,
            name,
            name_len,
            &storage->work_view_a,
            storage->pack_scratch,
            NINLIL_PORT_ESP_STORAGE_SLOT_BYTES)) {
        return MEDIA_DEFINITE_FAIL;
    }
    base0 = ninlil_port_esp_storage_media_data_offset(
        storage->config.max_namespaces, ns_index, 0u);
    base1 = ninlil_port_esp_storage_media_data_offset(
        storage->config.max_namespaces, ns_index, 1u);
    if (!observe_hil_boundary(
            storage, NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE)) {
        return MEDIA_DEFINITE_FAIL;
    }
    rc = storage->media_ops->erase(
        storage->media_user, base0, NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);
    if (rc != MEDIA_OK) {
        return rc == MEDIA_UNKNOWN ? MEDIA_UNKNOWN : MEDIA_DEFINITE_FAIL;
    }
    if (!observe_hil_boundary(
            storage, NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE)) {
        return MEDIA_DEFINITE_FAIL;
    }
    rc = storage->media_ops->erase(
        storage->media_user, base1, NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);
    if (rc != MEDIA_OK) {
        return rc == MEDIA_UNKNOWN ? MEDIA_UNKNOWN : MEDIA_DEFINITE_FAIL;
    }
    if (!observe_hil_boundary(
            storage, NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE)) {
        return MEDIA_DEFINITE_FAIL;
    }
    rc = storage->media_ops->write(
        storage->media_user,
        base0,
        storage->pack_scratch,
        NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);
    if (rc != MEDIA_OK) {
        return rc;
    }
    rc = storage->media_ops->sync(storage->media_user);
    if (rc != MEDIA_OK) {
        return MEDIA_UNKNOWN;
    }
    if (!observe_hil_boundary(
            storage,
            NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN)) {
        return MEDIA_UNKNOWN;
    }
    return MEDIA_OK;
}

int ninlil_port_esp_storage_private_init(
    ninlil_port_esp_storage_t *storage,
    const ninlil_port_esp_storage_config_t *config,
    const ninlil_port_esp_storage_private_media_ops_t *media_ops,
    void *media_user,
    ninlil_port_esp_storage_private_full_policy_t full_policy)
{
    int dir_rc;

    if (storage == NULL || !config_valid(config) || media_ops == NULL
        || media_ops->read == NULL || media_ops->write == NULL
        || media_ops->erase == NULL || media_ops->sync == NULL
#if defined(ESP_PLATFORM)
        || full_policy != NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN
#else
        || (full_policy != NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL
            && full_policy
                != NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_ESP_UNPROVEN)
#endif
        ) {
        return -1;
    }
    if (sizeof(ninlil_port_esp_storage_t)
        > NINLIL_PORT_ESP_STORAGE_OBJECT_SIZEOF_CEILING) {
        return -1;
    }
    if (sizeof(ninlil_port_esp_storage_view_t)
        > NINLIL_PORT_ESP_STORAGE_VIEW_SIZEOF_CEILING) {
        return -1;
    }
    if (!esp_psram_ok(storage)) {
        return -1;
    }
    /*
     * Do not wipe external-RAM object with memset of entire struct if caller
     * already zeroed; still clear control state after placement check.
     */
    (void)memset(storage, 0, sizeof(*storage));
    storage->config = *config;
    storage->media_ops = media_ops;
    storage->media_user = media_user;
    storage->full_policy = full_policy;
    storage->ops.abi_version = NINLIL_ABI_VERSION;
    storage->ops.struct_size = (uint16_t)sizeof(storage->ops);
    storage->ops.user = storage;
    storage->ops.open = port_open;
    storage->ops.close = port_close;
    storage->ops.begin = port_begin;
    storage->ops.get = port_get;
    storage->ops.put = port_put;
    storage->ops.erase = port_erase;
    storage->ops.iter_open = port_iter_open;
    storage->ops.iter_next = port_iter_next;
    storage->ops.iter_close = port_iter_close;
    storage->ops.capacity = port_capacity;
    storage->ops.commit = port_commit;
    storage->ops.rollback = port_rollback;

    dir_rc = load_directory(storage);
    if (dir_rc < 0) {
        (void)memset(storage, 0, sizeof(*storage));
        return -1;
    }
    refresh_ns_cache_from_directory(storage);
    storage->initialized = 1;
    return 0;
}

void ninlil_port_esp_storage_private_deinit(ninlil_port_esp_storage_t *storage)
{
    if (storage == NULL) {
        return;
    }
    (void)memset(storage, 0, sizeof(*storage));
}

const ninlil_storage_ops_t *ninlil_port_esp_storage_private_ops(
    ninlil_port_esp_storage_t *storage)
{
    if (storage == NULL || !storage->initialized) {
        return NULL;
    }
    return &storage->ops;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((visibility("hidden")))
#endif
int ninlil_port_esp_storage_private_set_hil_observer(
    ninlil_port_esp_storage_t *storage,
    ninlil_port_esp_storage_hil_observer_t observer,
    void *observer_user)
{
    if (storage == NULL || !storage->initialized
        || (observer == NULL && observer_user != NULL)) {
        return -1;
    }
    storage->hil_observer = observer;
    storage->hil_observer_user = observer_user;
    return 0;
}

#if !defined(ESP_PLATFORM)
void ninlil_port_esp_storage_private_simulate_crash(ninlil_port_esp_storage_t *storage)
{
    uint32_t i;
    if (storage == NULL || !storage->initialized) {
        return;
    }
    for (i = 0u; i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES; ++i) {
        storage->namespaces[i].leased = 0;
        (void)memset(&storage->handles[i], 0, sizeof(storage->handles[i]));
    }
    (void)memset(storage->transactions, 0, sizeof(storage->transactions));
    (void)memset(storage->iterators, 0, sizeof(storage->iterators));
    /* Directory cache intentionally discarded; next open reloads via reinit
     * tests. Keep directory bytes zeroed to force reload on next full reinit. */
    (void)memset(&storage->directory, 0, sizeof(storage->directory));
    for (i = 0u; i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES; ++i) {
        (void)memset(
            &storage->namespaces[i], 0, sizeof(storage->namespaces[i]));
    }
}

int ninlil_port_esp_storage_private_simulate_full_reinit(
    ninlil_port_esp_storage_t *storage,
    const ninlil_port_esp_storage_config_t *config,
    const ninlil_port_esp_storage_private_media_ops_t *media_ops,
    void *media_user,
    ninlil_port_esp_storage_private_full_policy_t full_policy)
{
    if (storage == NULL) {
        return -1;
    }
    (void)memset(storage, 0, sizeof(*storage));
    return ninlil_port_esp_storage_private_init(
        storage, config, media_ops, media_user, full_policy);
}
#endif /* !ESP_PLATFORM */

static ninlil_port_esp_storage_handle_t *resolve_handle(
    ninlil_port_esp_storage_t *storage,
    ninlil_storage_handle_t opaque)
{
    uint32_t index;
    uint32_t generation;
    if (!unpack_token(
            opaque,
            NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES,
            &index,
            &generation)) {
        return NULL;
    }
    if (!storage->handles[index].in_use
        || storage->handles[index].generation != generation) {
        return NULL;
    }
    return &storage->handles[index];
}

static ninlil_port_esp_storage_transaction_t *resolve_txn(
    ninlil_port_esp_storage_t *storage,
    ninlil_storage_txn_t opaque)
{
    uint32_t index;
    uint32_t generation;
    if (!unpack_token(
            opaque, NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS, &index, &generation)) {
        return NULL;
    }
    if (!storage->transactions[index].in_use
        || storage->transactions[index].generation != generation) {
        return NULL;
    }
    return &storage->transactions[index];
}

static ninlil_port_esp_storage_iterator_t *resolve_iter(
    ninlil_port_esp_storage_t *storage,
    ninlil_storage_iter_t opaque)
{
    uint32_t index;
    uint32_t generation;
    if (!unpack_token(
            opaque,
            NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS,
            &index,
            &generation)) {
        return NULL;
    }
    if (!storage->iterators[index].in_use
        || storage->iterators[index].generation != generation) {
        return NULL;
    }
    return &storage->iterators[index];
}

static void consume_iters_for_txn(
    ninlil_port_esp_storage_t *storage,
    uint32_t txn_index,
    uint32_t txn_generation)
{
    uint32_t i;
    for (i = 0u; i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS; ++i) {
        ninlil_port_esp_storage_iterator_t *it = &storage->iterators[i];
        if (it->in_use && it->transaction_index == txn_index
            && it->transaction_generation == txn_generation) {
            uint32_t gen = it->generation;
            (void)memset(it, 0, sizeof(*it));
            it->generation = gen;
        }
    }
}

static void consume_txn(
    ninlil_port_esp_storage_t *storage,
    ninlil_port_esp_storage_transaction_t *txn)
{
    uint32_t txn_index = (uint32_t)(txn - storage->transactions);
    ninlil_port_esp_storage_handle_t *handle =
        &storage->handles[txn->handle_index];
    uint32_t gen = txn->generation;

    consume_iters_for_txn(storage, txn_index, txn->generation);
    if (txn->mode == NINLIL_STORAGE_READ_WRITE && handle->in_use
        && handle->generation == txn->handle_generation) {
        handle->has_writer = 0;
    }
    (void)memset(txn, 0, sizeof(*txn));
    txn->generation = gen;
}

static ninlil_storage_status_t port_open(
    void *user,
    ninlil_bytes_view_t storage_namespace,
    uint32_t expected_schema,
    ninlil_storage_handle_t *out_handle)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    uint32_t ns_index = 0u;
    uint32_t handle_i;
    int dir_dirty = 0;

    if (storage == NULL || !storage->initialized || out_handle == NULL
        || *out_handle != NULL
        || !view_shape_is_valid(storage_namespace, 1u, 255u)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (expected_schema != NINLIL_STORAGE_SCHEMA_M1A) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }

    /* Reload after fence, crash, or cold cache. */
    if (storage->directory_cache_fenced
        || (storage->directory.generation == 0u
            && storage->directory.state[0]
                == NINLIL_PORT_ESP_STORAGE_DIR_STATE_FREE)) {
        if (reload_directory_from_media(storage) < 0) {
            return NINLIL_STORAGE_CORRUPT;
        }
    }

    if (!find_directory_index(storage, storage_namespace, &ns_index)) {
        int seed_rc;
        if (!find_free_directory_index(storage, &ns_index)) {
            return NINLIL_STORAGE_NO_SPACE;
        }
        /*
         * Durable empty data seed BEFORE directory OCCUPIED publish so both
         * data slots invalid never looks like silent empty history loss.
         */
        seed_rc = seed_empty_namespace_data(
            storage,
            ns_index,
            expected_schema,
            storage_namespace.data,
            storage_namespace.length,
            1u);
        if (seed_rc == MEDIA_UNKNOWN) {
            /* Seed may or may not be durable; never treat RAM as OCCUPIED. */
            fence_directory_cache(storage);
            return NINLIL_STORAGE_COMMIT_UNKNOWN;
        }
        if (seed_rc != MEDIA_OK) {
            fence_directory_cache(storage);
            return NINLIL_STORAGE_IO_ERROR;
        }
        storage->directory.state[ns_index] =
            NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED;
        storage->directory.name_length[ns_index] =
            (uint8_t)storage_namespace.length;
        (void)memcpy(
            storage->directory.name[ns_index],
            storage_namespace.data,
            storage_namespace.length);
        storage->directory.schema[ns_index] = expected_schema;
        storage->directory.data_seed_generation[ns_index] = 1u;
        dir_dirty = 1;
    } else if (storage->directory.schema[ns_index] != expected_schema) {
        return NINLIL_STORAGE_UNSUPPORTED_SCHEMA;
    }

    if (storage->namespaces[ns_index].leased) {
        return NINLIL_STORAGE_BUSY;
    }

    if (dir_dirty) {
        int rc = commit_directory(storage);
        if (rc == MEDIA_UNKNOWN) {
            /*
             * Directory publish indeterminate: drop RAM occupied truth and
             * fence so next open reloads media (all-old/all-new).
             */
            fence_directory_cache(storage);
            return NINLIL_STORAGE_COMMIT_UNKNOWN;
        }
        if (rc != MEDIA_OK) {
            storage->directory.state[ns_index] =
                NINLIL_PORT_ESP_STORAGE_DIR_STATE_FREE;
            storage->directory.name_length[ns_index] = 0u;
            (void)memset(
                storage->directory.name[ns_index],
                0,
                sizeof(storage->directory.name[ns_index]));
            storage->directory.schema[ns_index] = 0u;
            storage->directory.data_seed_generation[ns_index] = 0u;
            return NINLIL_STORAGE_IO_ERROR;
        }
        refresh_ns_cache_from_directory(storage);
    }

    for (handle_i = 0u; handle_i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES;
         ++handle_i) {
        ninlil_port_esp_storage_handle_t *handle = &storage->handles[handle_i];
        if (!handle->in_use) {
            uint32_t gen;
            if (!next_generation(
                    handle->generation,
                    NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES,
                    &gen)) {
                continue;
            }
            handle->in_use = 1;
            handle->generation = gen;
            handle->namespace_index = ns_index;
            handle->has_writer = 0;
            storage->namespaces[ns_index].leased = 1;
            storage->namespaces[ns_index].cached = 1;
            *out_handle = (ninlil_storage_handle_t)pack_token(
                handle_i,
                handle->generation,
                NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES);
            return NINLIL_STORAGE_OK;
        }
    }
    return NINLIL_STORAGE_NO_SPACE;
}

static void port_close(void *user, ninlil_storage_handle_t opaque)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_handle_t *handle;
    uint32_t handle_i;
    uint32_t txn_i;

    if (storage == NULL || !storage->initialized) {
        return;
    }
    handle = resolve_handle(storage, opaque);
    if (handle == NULL) {
        return; /* stale: no-op fail-closed */
    }
    handle_i = (uint32_t)(handle - storage->handles);
    for (txn_i = 0u; txn_i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS; ++txn_i) {
        ninlil_port_esp_storage_transaction_t *txn =
            &storage->transactions[txn_i];
        if (txn->in_use && txn->handle_index == handle_i
            && txn->handle_generation == handle->generation) {
            consume_txn(storage, txn);
        }
    }
    storage->namespaces[handle->namespace_index].leased = 0;
    {
        uint32_t gen = handle->generation;
        (void)memset(handle, 0, sizeof(*handle));
        handle->generation = gen;
    }
}

static ninlil_storage_status_t port_begin(
    void *user,
    ninlil_storage_handle_t opaque,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_handle_t *handle;
    uint32_t txn_i;
    uint32_t live = 0u;
    uint64_t gen = 0u;
    uint32_t active_slot = 0u;
    int load_rc;

    if (storage == NULL || !storage->initialized || out_txn == NULL
        || *out_txn != NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    handle = resolve_handle(storage, opaque);
    if (handle == NULL
        || (mode != NINLIL_STORAGE_READ_ONLY
            && mode != NINLIL_STORAGE_READ_WRITE)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (mode == NINLIL_STORAGE_READ_WRITE && handle->has_writer) {
        return NINLIL_STORAGE_BUSY;
    }
    for (txn_i = 0u; txn_i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS; ++txn_i) {
        if (storage->transactions[txn_i].in_use) {
            live += 1u;
        }
    }
    if (live >= storage->config.max_live_txns) {
        return NINLIL_STORAGE_NO_SPACE;
    }

    for (txn_i = 0u; txn_i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS; ++txn_i) {
        ninlil_port_esp_storage_transaction_t *txn =
            &storage->transactions[txn_i];
        if (!txn->in_use) {
            uint32_t tgen;
            if (!next_generation(
                    txn->generation,
                    NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS,
                    &tgen)) {
                continue;
            }
            /*
             * Load snapshot directly into the txn view (object storage).
             * Dual-slot decode uses work_view_a/b; no ~78KB stack frame.
             */
            load_rc = load_namespace_content(
                storage,
                handle->namespace_index,
                &txn->view,
                &gen,
                &active_slot);
            if (load_rc < 0) {
                return NINLIL_STORAGE_CORRUPT;
            }
            storage->namespaces[handle->namespace_index].active_generation = gen;
            storage->namespaces[handle->namespace_index].active_slot =
                active_slot;
            storage->namespaces[handle->namespace_index].used_entries =
                txn->view.entry_count;
            storage->namespaces[handle->namespace_index].used_bytes =
                txn->view.used_logical_bytes;
            txn->in_use = 1;
            txn->generation = tgen;
            txn->handle_index = (uint32_t)(handle - storage->handles);
            txn->handle_generation = handle->generation;
            txn->mode = mode;
            txn->ns_index = handle->namespace_index;
            if (mode == NINLIL_STORAGE_READ_WRITE) {
                handle->has_writer = 1;
            }
            *out_txn = (ninlil_storage_txn_t)pack_token(
                txn_i,
                txn->generation,
                NINLIL_PORT_ESP_STORAGE_HARD_MAX_TXNS);
            return NINLIL_STORAGE_OK;
        }
    }
    return NINLIL_STORAGE_NO_SPACE;
}

static ninlil_storage_status_t port_get(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_transaction_t *txn;
    int found;
    uint32_t index;
    const ninlil_port_esp_storage_entry_t *entry;

    if (storage == NULL || !storage->initialized) {
        return NINLIL_STORAGE_CORRUPT;
    }
    txn = resolve_txn(storage, opaque);
    if (txn == NULL || !view_shape_is_valid(key, 1u, 255u)
        || !mut_shape_is_valid(inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    index = find_entry(&txn->view, key, &found);
    if (!found) {
        inout_value->length = 0u;
        return NINLIL_STORAGE_NOT_FOUND;
    }
    entry = &txn->view.entries[index];
    if (entry->value_length > inout_value->capacity) {
        inout_value->length = entry->value_length;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (entry->value_length != 0u) {
        (void)memcpy(
            inout_value->data,
            txn->view.value_blob + entry->value_offset,
            entry->value_length);
    }
    inout_value->length = entry->value_length;
    return NINLIL_STORAGE_OK;
}

static int append_entry_to_view(
    ninlil_port_esp_storage_view_t *view,
    const uint8_t *key,
    uint32_t key_length,
    const uint8_t *value,
    uint32_t value_length)
{
    ninlil_port_esp_storage_entry_t *entry;
    uint64_t logical = 16u + (uint64_t)key_length + (uint64_t)value_length;

    if (view->entry_count >= NINLIL_PORT_ESP_STORAGE_HARD_MAX_ENTRIES
        || view->used_logical_bytes
            > NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES
        || view->value_blob_used
            > NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES
        || logical
            > (uint64_t)NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES
                - view->used_logical_bytes
        || value_length
            > NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES
                - view->value_blob_used) {
        return 0;
    }
    entry = &view->entries[view->entry_count];
    entry->key_length = (uint16_t)key_length;
    (void)memcpy(entry->key, key, key_length);
    entry->value_length = value_length;
    entry->value_offset = value_length == 0u ? 0u : view->value_blob_used;
    if (value_length != 0u) {
        (void)memcpy(
            view->value_blob + view->value_blob_used, value, value_length);
        view->value_blob_used += value_length;
    }
    view->entry_count += 1u;
    view->used_logical_bytes += logical;
    return 1;
}

static int append_existing_entry(
    ninlil_port_esp_storage_view_t *dest,
    const ninlil_port_esp_storage_view_t *source,
    uint32_t index)
{
    const ninlil_port_esp_storage_entry_t *entry = &source->entries[index];
    if (entry->value_offset > source->value_blob_used
        || entry->value_length > source->value_blob_used - entry->value_offset) {
        return 0;
    }
    return append_entry_to_view(
        dest,
        entry->key,
        entry->key_length,
        source->value_blob + entry->value_offset,
        entry->value_length);
}

/*
 * Build the logical post-put view without touching txn->view. The caller value
 * is first copied into the bounded pack scratch so aliases cannot be invalidated
 * while the destination is rebuilt. Success performs one final deep copy;
 * every failure leaves the transaction byte-for-byte unchanged.
 */
static int rebuild_view_with_put(
    ninlil_port_esp_storage_t *storage,
    ninlil_port_esp_storage_transaction_t *txn,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_port_esp_storage_view_t *dest = &storage->mutation_scratch;
    uint8_t key_copy[NINLIL_PORT_ESP_STORAGE_HARD_MAX_KEY_BYTES];
    uint32_t index;
    int inserted = 0;

    if (value.length > NINLIL_PORT_ESP_STORAGE_SLOT_BYTES) {
        return 0;
    }
    /* Snapshot key before clearing dest; public input may alias object bytes. */
    (void)memmove(key_copy, key.data, key.length);
    if (value.length != 0u) {
        (void)memmove(storage->pack_scratch, value.data, value.length);
    }
    (void)memset(dest, 0, sizeof(*dest));
    for (index = 0u; index < txn->view.entry_count; ++index) {
        const ninlil_port_esp_storage_entry_t *entry =
            &txn->view.entries[index];
        int compared = bytes_compare(
            entry->key, entry->key_length, key_copy, key.length);
        if (!inserted && compared >= 0) {
            if (!append_entry_to_view(
                    dest,
                    key_copy,
                    key.length,
                    storage->pack_scratch,
                    value.length)) {
                return 0;
            }
            inserted = 1;
            if (compared == 0) {
                continue;
            }
        }
        if (!append_existing_entry(dest, &txn->view, index)) {
            return 0;
        }
    }
    if (!inserted
        && !append_entry_to_view(
            dest,
            key_copy,
            key.length,
            storage->pack_scratch,
            value.length)) {
        return 0;
    }
    copy_view(&txn->view, dest);
    return 1;
}

static int rebuild_view_without_key(
    ninlil_port_esp_storage_t *storage,
    ninlil_port_esp_storage_transaction_t *txn,
    ninlil_bytes_view_t key)
{
    ninlil_port_esp_storage_view_t *dest = &storage->mutation_scratch;
    uint8_t key_copy[NINLIL_PORT_ESP_STORAGE_HARD_MAX_KEY_BYTES];
    uint32_t index;

    /* Public input may alias mutation_scratch from an earlier operation. */
    (void)memmove(key_copy, key.data, key.length);
    (void)memset(dest, 0, sizeof(*dest));
    for (index = 0u; index < txn->view.entry_count; ++index) {
        const ninlil_port_esp_storage_entry_t *entry =
            &txn->view.entries[index];
        if (bytes_compare(entry->key,
                entry->key_length,
                key_copy,
                key.length)
            == 0) {
            continue;
        }
        if (!append_existing_entry(dest, &txn->view, index)) {
            return 0;
        }
    }
    copy_view(&txn->view, dest);
    return 1;
}

static ninlil_storage_status_t port_put(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key,
    ninlil_bytes_view_t value)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_transaction_t *txn;

    if (storage == NULL || !storage->initialized) {
        return NINLIL_STORAGE_CORRUPT;
    }
    txn = resolve_txn(storage, opaque);
    if (txn == NULL || txn->mode != NINLIL_STORAGE_READ_WRITE
        || !view_shape_is_valid(key, 1u, 255u)
        || !view_shape_is_valid(value, 0u, UINT32_MAX)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (value.length > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    if (!rebuild_view_with_put(storage, txn, key, value)) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_erase(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t key)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_transaction_t *txn;

    if (storage == NULL || !storage->initialized) {
        return NINLIL_STORAGE_CORRUPT;
    }
    txn = resolve_txn(storage, opaque);
    if (txn == NULL || txn->mode != NINLIL_STORAGE_READ_WRITE
        || !view_shape_is_valid(key, 1u, 255u)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (!rebuild_view_without_key(storage, txn, key)) {
        /* A valid source view always fits after erase; fail closed otherwise. */
        return NINLIL_STORAGE_CORRUPT;
    }
    return NINLIL_STORAGE_OK;
}

static int prefix_matches(
    const ninlil_port_esp_storage_entry_t *entry,
    ninlil_bytes_view_t prefix)
{
    return entry->key_length >= prefix.length
        && (prefix.length == 0u
            || memcmp(entry->key, prefix.data, prefix.length) == 0);
}

static ninlil_storage_status_t port_iter_open(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_bytes_view_t prefix,
    ninlil_storage_iter_t *out_iter)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_transaction_t *txn;
    uint32_t iter_i;
    uint32_t live = 0u;
    uint32_t index;
    uint32_t row = 0u;

    if (storage == NULL || !storage->initialized || out_iter == NULL
        || *out_iter != NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    txn = resolve_txn(storage, opaque);
    if (txn == NULL || !view_shape_is_valid(prefix, 0u, 255u)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    for (iter_i = 0u; iter_i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS;
         ++iter_i) {
        if (storage->iterators[iter_i].in_use) {
            live += 1u;
        }
    }
    if (live >= storage->config.max_live_iters) {
        return NINLIL_STORAGE_NO_SPACE;
    }
    for (iter_i = 0u; iter_i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS;
         ++iter_i) {
        ninlil_port_esp_storage_iterator_t *iter = &storage->iterators[iter_i];
        if (!iter->in_use) {
            uint32_t igen;
            if (!next_generation(
                    iter->generation,
                    NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS,
                    &igen)) {
                continue;
            }
            iter->in_use = 1;
            iter->generation = igen;
            iter->transaction_index =
                (uint32_t)(txn - storage->transactions);
            iter->transaction_generation = txn->generation;
            iter->position = 0u;
            copy_view(&iter->snapshot, &txn->view);
            for (index = 0u; index < txn->view.entry_count; ++index) {
                if (prefix_matches(&iter->snapshot.entries[index], prefix)) {
                    iter->row_indices[row++] = index;
                }
            }
            iter->row_count = row;
            *out_iter = (ninlil_storage_iter_t)pack_token(
                iter_i,
                iter->generation,
                NINLIL_PORT_ESP_STORAGE_HARD_MAX_ITERS);
            return NINLIL_STORAGE_OK;
        }
    }
    return NINLIL_STORAGE_NO_SPACE;
}

static ninlil_storage_status_t port_iter_next(
    void *user,
    ninlil_storage_iter_t opaque,
    ninlil_mut_bytes_t *inout_key,
    ninlil_mut_bytes_t *inout_value)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_iterator_t *iter;
    ninlil_port_esp_storage_transaction_t *txn;
    const ninlil_port_esp_storage_entry_t *entry;
    uint32_t entry_index;

    if (storage == NULL || !storage->initialized) {
        return NINLIL_STORAGE_CORRUPT;
    }
    iter = resolve_iter(storage, opaque);
    if (iter == NULL || !mut_shape_is_valid(inout_key)
        || !mut_shape_is_valid(inout_value)
        || !mut_ranges_do_not_overlap(inout_key, inout_value)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    txn = &storage->transactions[iter->transaction_index];
    if (!txn->in_use || txn->generation != iter->transaction_generation) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (iter->position >= iter->row_count) {
        inout_key->length = 0u;
        inout_value->length = 0u;
        return NINLIL_STORAGE_NOT_FOUND;
    }
    entry_index = iter->row_indices[iter->position];
    entry = &iter->snapshot.entries[entry_index];
    if (entry->key_length > inout_key->capacity
        || entry->value_length > inout_value->capacity) {
        inout_key->length = entry->key_length;
        inout_value->length = entry->value_length;
        return NINLIL_STORAGE_BUFFER_TOO_SMALL;
    }
    if (entry->key_length != 0u) {
        (void)memcpy(inout_key->data, entry->key, entry->key_length);
    }
    if (entry->value_length != 0u) {
        (void)memcpy(
            inout_value->data,
            iter->snapshot.value_blob + entry->value_offset,
            entry->value_length);
    }
    inout_key->length = entry->key_length;
    inout_value->length = entry->value_length;
    iter->position += 1u;
    return NINLIL_STORAGE_OK;
}

static void port_iter_close(void *user, ninlil_storage_iter_t opaque)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_iterator_t *iter;
    if (storage == NULL || !storage->initialized) {
        return;
    }
    iter = resolve_iter(storage, opaque);
    if (iter == NULL) {
        return;
    }
    {
        uint32_t gen = iter->generation;
        (void)memset(iter, 0, sizeof(*iter));
        iter->generation = gen;
    }
}

static ninlil_storage_status_t port_capacity(
    void *user,
    ninlil_storage_handle_t opaque,
    ninlil_storage_capacity_t *out_capacity)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_handle_t *handle;
    uint64_t gen = 0u;
    uint32_t slot = 0u;

    if (storage == NULL || !storage->initialized || out_capacity == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    if (out_capacity->abi_version != NINLIL_ABI_VERSION
        || out_capacity->struct_size < sizeof(*out_capacity)) {
        return NINLIL_STORAGE_CORRUPT;
    }
    handle = resolve_handle(storage, opaque);
    if (handle == NULL) {
        out_capacity->max_entries = 0u;
        out_capacity->used_entries = 0u;
        out_capacity->max_bytes = 0u;
        out_capacity->used_bytes = 0u;
        return NINLIL_STORAGE_CORRUPT;
    }
    /* Result lands in object workspace (work_view_*), not stack. */
    if (load_namespace_content(
            storage,
            handle->namespace_index,
            &storage->work_view_a,
            &gen,
            &slot)
        < 0) {
        out_capacity->max_entries = 0u;
        out_capacity->used_entries = 0u;
        out_capacity->max_bytes = 0u;
        out_capacity->used_bytes = 0u;
        return NINLIL_STORAGE_CORRUPT;
    }
    out_capacity->max_entries = storage->config.max_entries_per_namespace;
    out_capacity->used_entries = storage->work_view_a.entry_count;
    out_capacity->max_bytes = storage->config.max_bytes_per_namespace;
    out_capacity->used_bytes = storage->work_view_a.used_logical_bytes;
    return NINLIL_STORAGE_OK;
}

static ninlil_storage_status_t port_commit(
    void *user,
    ninlil_storage_txn_t opaque,
    ninlil_durability_t durability)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_transaction_t *txn;
    ninlil_port_esp_storage_namespace_t *ns;
    uint32_t inactive;
    uint64_t new_generation;
    int media_rc;
    const uint8_t *name;
    uint32_t name_len;
    uint32_t schema;

    if (storage == NULL || !storage->initialized) {
        return NINLIL_STORAGE_CORRUPT;
    }
    txn = resolve_txn(storage, opaque);
    if (txn == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }

    if (durability != NINLIL_DURABILITY_FULL) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_CORRUPT;
    }
    if (txn->mode == NINLIL_STORAGE_READ_ONLY) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_OK;
    }
    if (!view_recompute(&txn->view) || !capacity_ok(storage, &txn->view)) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_NO_SPACE;
    }

    ns = &storage->namespaces[txn->ns_index];
    name = storage->directory.name[txn->ns_index];
    name_len = storage->directory.name_length[txn->ns_index];
    schema = storage->directory.schema[txn->ns_index];
    inactive = ns->active_slot ^ 1u;
    if (ns->active_generation == UINT64_MAX) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_NO_SPACE;
    }
    new_generation = ns->active_generation + 1u;
    if (new_generation == 0u) {
        new_generation = 1u;
    }

    if (!ninlil_port_esp_storage_encode_slot(
            schema,
            new_generation,
            name,
            name_len,
            &txn->view,
            storage->pack_scratch,
            NINLIL_PORT_ESP_STORAGE_SLOT_BYTES)) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_NO_SPACE;
    }

    if (!observe_hil_boundary(
            storage, NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_ERASE)) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_IO_ERROR;
    }
    media_rc = storage->media_ops->erase(
        storage->media_user,
        ninlil_port_esp_storage_media_data_offset(
            storage->config.max_namespaces, txn->ns_index, inactive),
        NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);
    if (media_rc != MEDIA_OK) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (!observe_hil_boundary(
            storage, NINLIL_PORT_ESP_STORAGE_HIL_DATA_BEFORE_WRITE)) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_IO_ERROR;
    }
    media_rc = storage->media_ops->write(
        storage->media_user,
        ninlil_port_esp_storage_media_data_offset(
            storage->config.max_namespaces, txn->ns_index, inactive),
        storage->pack_scratch,
        NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);
    if (media_rc == MEDIA_DEFINITE_FAIL) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_IO_ERROR;
    }
    if (media_rc == MEDIA_UNKNOWN) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }
    media_rc = storage->media_ops->sync(storage->media_user);
    if (media_rc != MEDIA_OK) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }

    if (!observe_hil_boundary(
            storage,
            NINLIL_PORT_ESP_STORAGE_HIL_DATA_AFTER_SYNC_BEFORE_RETURN)) {
        consume_txn(storage, txn);
        return NINLIL_STORAGE_COMMIT_UNKNOWN;
    }

    ns->active_generation = new_generation;
    ns->active_slot = inactive;
    ns->used_entries = txn->view.entry_count;
    ns->used_bytes = txn->view.used_logical_bytes;
    consume_txn(storage, txn);

#if defined(ESP_PLATFORM)
    /* There is deliberately no unattested ESP target branch to FULL OK. */
    return NINLIL_STORAGE_COMMIT_UNKNOWN;
#else
    if (storage->full_policy
        == NINLIL_PORT_ESP_STORAGE_PRIVATE_FULL_HOST_MODEL) {
        return NINLIL_STORAGE_OK;
    }
    return NINLIL_STORAGE_COMMIT_UNKNOWN;
#endif
}

static ninlil_storage_status_t port_rollback(
    void *user,
    ninlil_storage_txn_t opaque)
{
    ninlil_port_esp_storage_t *storage = (ninlil_port_esp_storage_t *)user;
    ninlil_port_esp_storage_transaction_t *txn;

    if (storage == NULL || !storage->initialized) {
        return NINLIL_STORAGE_CORRUPT;
    }
    txn = resolve_txn(storage, opaque);
    if (txn == NULL) {
        return NINLIL_STORAGE_CORRUPT;
    }
    consume_txn(storage, txn);
    return NINLIL_STORAGE_OK;
}
