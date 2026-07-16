#include "esp_storage_codec.h"

#include <string.h>

uint32_t ninlil_port_esp_storage_crc32c(const uint8_t *bytes, uint32_t length)
{
    uint32_t crc = UINT32_MAX;
    uint32_t index;

    if (bytes == NULL && length != 0u) {
        return 0u;
    }
    for (index = 0u; index < length; ++index) {
        uint32_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = (uint32_t)(0u - (crc & 1u));
            crc = (crc >> 1u) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

void ninlil_port_esp_storage_store_u16_le(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
}

void ninlil_port_esp_storage_store_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value & 0xffu);
    out[1] = (uint8_t)((value >> 8) & 0xffu);
    out[2] = (uint8_t)((value >> 16) & 0xffu);
    out[3] = (uint8_t)((value >> 24) & 0xffu);
}

void ninlil_port_esp_storage_store_u64_le(uint8_t *out, uint64_t value)
{
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        out[index] = (uint8_t)((value >> (8u * index)) & 0xffu);
    }
}

uint16_t ninlil_port_esp_storage_load_u16_le(const uint8_t *in)
{
    return (uint16_t)in[0] | (uint16_t)((uint16_t)in[1] << 8);
}

uint32_t ninlil_port_esp_storage_load_u32_le(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16)
        | ((uint32_t)in[3] << 24);
}

uint64_t ninlil_port_esp_storage_load_u64_le(const uint8_t *in)
{
    uint64_t value = 0u;
    uint32_t index;
    for (index = 0u; index < 8u; ++index) {
        value |= ((uint64_t)in[index]) << (8u * index);
    }
    return value;
}

static int bytes_all_zero(const uint8_t *bytes, uint32_t length)
{
    uint32_t index;
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return 0;
        }
    }
    return 1;
}

static int bytes_all_erased(const uint8_t *bytes, uint32_t length)
{
    uint32_t index;
    for (index = 0u; index < length; ++index) {
        if (bytes[index] != NINLIL_PORT_ESP_STORAGE_FLASH_ERASED_BYTE) {
            return 0;
        }
    }
    return 1;
}

int ninlil_port_esp_storage_encode_directory(
    uint64_t generation,
    const ninlil_port_esp_storage_config_t *config,
    const ninlil_port_esp_storage_directory_cache_t *cache,
    int seal_committed,
    uint8_t *out,
    uint32_t capacity)
{
    uint32_t i;
    uint32_t image_crc;
    uint32_t entry_base = NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BASE;

    if (out == NULL || config == NULL || cache == NULL
        || capacity < NINLIL_PORT_ESP_STORAGE_DIR_BYTES
        || generation == 0u
        || config->max_namespaces == 0u
        || config->max_namespaces > NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES
        || NINLIL_PORT_ESP_STORAGE_DIR_PAD_OFFSET
            != (48u + NINLIL_PORT_ESP_STORAGE_DIR_ENTRIES_BYTES)
        || NINLIL_PORT_ESP_STORAGE_DIR_PAD_OFFSET
            > NINLIL_PORT_ESP_STORAGE_DIR_PROTECTED_BYTES) {
        return 0;
    }
    (void)memset(out, 0, NINLIL_PORT_ESP_STORAGE_DIR_BYTES);
    ninlil_port_esp_storage_store_u32_le(out + 0, NINLIL_PORT_ESP_STORAGE_DIR_MAGIC);
    ninlil_port_esp_storage_store_u32_le(out + 4, NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION);
    ninlil_port_esp_storage_store_u64_le(out + 8, generation);
    ninlil_port_esp_storage_store_u32_le(out + 16, config->max_namespaces);
    ninlil_port_esp_storage_store_u64_le(out + 20, config->max_entries_per_namespace);
    ninlil_port_esp_storage_store_u64_le(out + 28, config->max_bytes_per_namespace);
    ninlil_port_esp_storage_store_u32_le(
        out + 36, NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES);
    /* reserved 40..47 zero (included in protected CRC span) */
    for (i = 0u; i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES; ++i) {
        uint8_t *entry = out + entry_base + i * NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BYTES;
        entry[0] = cache->state[i];
        entry[1] = cache->name_length[i];
        ninlil_port_esp_storage_store_u32_le(entry + 4, cache->schema[i]);
        if (cache->name_length[i] != 0u) {
            (void)memcpy(entry + 8, cache->name[i], cache->name_length[i]);
        }
        /* 263..270 data_seed_generation; 271 reserved zero */
        ninlil_port_esp_storage_store_u64_le(
            entry + 263, cache->data_seed_generation[i]);
        entry[271] = 0u;
    }
    /* [PAD_OFFSET, 4088) remains zero from memset; CRC-bound. */
    image_crc = ninlil_port_esp_storage_crc32c(
        out, NINLIL_PORT_ESP_STORAGE_DIR_PROTECTED_BYTES);
    ninlil_port_esp_storage_store_u32_le(
        out + NINLIL_PORT_ESP_STORAGE_DIR_IMAGE_CRC_OFFSET, image_crc);
    ninlil_port_esp_storage_store_u32_le(
        out + NINLIL_PORT_ESP_STORAGE_DIR_SEAL_OFFSET,
        seal_committed != 0 ? NINLIL_PORT_ESP_STORAGE_DIR_SEAL_COMMITTED
                            : NINLIL_PORT_ESP_STORAGE_DIR_SEAL_NONE);
    return 1;
}

int ninlil_port_esp_storage_decode_directory(
    const uint8_t *image,
    uint32_t length,
    const ninlil_port_esp_storage_config_t *expected_config,
    ninlil_port_esp_storage_directory_cache_t *out_cache,
    uint64_t *out_generation)
{
    uint32_t magic;
    uint32_t version;
    uint32_t max_ns;
    uint64_t max_entries;
    uint64_t max_bytes;
    uint32_t entry_capacity;
    uint32_t image_crc;
    uint32_t seal;
    uint32_t expected_crc;
    uint32_t i;

    if (image == NULL || length < NINLIL_PORT_ESP_STORAGE_DIR_BYTES
        || expected_config == NULL || out_cache == NULL || out_generation == NULL) {
        return 0;
    }
    /* Erased NOR flash (all 0xFF) is empty, not corrupt. */
    if (bytes_all_erased(image, NINLIL_PORT_ESP_STORAGE_DIR_BYTES)) {
        return 0;
    }
    magic = ninlil_port_esp_storage_load_u32_le(image + 0);
    version = ninlil_port_esp_storage_load_u32_le(image + 4);
    *out_generation = ninlil_port_esp_storage_load_u64_le(image + 8);
    max_ns = ninlil_port_esp_storage_load_u32_le(image + 16);
    max_entries = ninlil_port_esp_storage_load_u64_le(image + 20);
    max_bytes = ninlil_port_esp_storage_load_u64_le(image + 28);
    entry_capacity = ninlil_port_esp_storage_load_u32_le(image + 36);
    image_crc = ninlil_port_esp_storage_load_u32_le(
        image + NINLIL_PORT_ESP_STORAGE_DIR_IMAGE_CRC_OFFSET);
    seal = ninlil_port_esp_storage_load_u32_le(
        image + NINLIL_PORT_ESP_STORAGE_DIR_SEAL_OFFSET);
    expected_crc = ninlil_port_esp_storage_crc32c(
        image, NINLIL_PORT_ESP_STORAGE_DIR_PROTECTED_BYTES);

    /*
     * Unsealed (seal still 0xFF) with valid CRC = torn final boundary (0).
     * CRC fail / bad shape with non-erased media = corrupt (-1).
     */
    if (magic != NINLIL_PORT_ESP_STORAGE_DIR_MAGIC
        || version != NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION
        || *out_generation == 0u
        || max_ns != expected_config->max_namespaces
        || max_entries != expected_config->max_entries_per_namespace
        || max_bytes != expected_config->max_bytes_per_namespace
        || entry_capacity != NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES
        || !bytes_all_zero(image + 40, 8u)
        || image_crc != expected_crc) {
        return -1;
    }
    if (seal != NINLIL_PORT_ESP_STORAGE_DIR_SEAL_COMMITTED) {
        return 0;
    }
    if (!bytes_all_zero(
            image + NINLIL_PORT_ESP_STORAGE_DIR_PAD_OFFSET,
            NINLIL_PORT_ESP_STORAGE_DIR_PROTECTED_BYTES
                - NINLIL_PORT_ESP_STORAGE_DIR_PAD_OFFSET)) {
        return -1;
    }

    (void)memset(out_cache, 0, sizeof(*out_cache));
    out_cache->generation = *out_generation;
    for (i = 0u; i < NINLIL_PORT_ESP_STORAGE_HARD_MAX_NAMESPACES; ++i) {
        const uint8_t *entry = image + NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BASE
            + i * NINLIL_PORT_ESP_STORAGE_DIR_ENTRY_BYTES;
        uint8_t state = entry[0];
        uint8_t name_len = entry[1];
        uint64_t seed_gen = ninlil_port_esp_storage_load_u64_le(entry + 263);
        if (!bytes_all_zero(entry + 2, 2u) || entry[271] != 0u) {
            return -1;
        }
        if (state == NINLIL_PORT_ESP_STORAGE_DIR_STATE_FREE) {
            if (name_len != 0u || seed_gen != 0u
                || !bytes_all_zero(entry + 4, 4u)
                || !bytes_all_zero(entry + 8, 255u)) {
                return -1;
            }
            out_cache->state[i] = state;
            out_cache->data_seed_generation[i] = 0u;
            continue;
        }
        if (state != NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED) {
            return -1;
        }
        if (name_len < 1u || seed_gen == 0u) {
            return -1;
        }
        if (!bytes_all_zero(entry + 8u + name_len, (uint32_t)(255u - name_len))) {
            return -1;
        }
        out_cache->state[i] = state;
        out_cache->name_length[i] = name_len;
        out_cache->schema[i] = ninlil_port_esp_storage_load_u32_le(entry + 4);
        (void)memcpy(out_cache->name[i], entry + 8, name_len);
        out_cache->data_seed_generation[i] = seed_gen;
        {
            uint32_t previous;
            for (previous = 0u; previous < i; ++previous) {
                if (out_cache->state[previous]
                        == NINLIL_PORT_ESP_STORAGE_DIR_STATE_OCCUPIED
                    && out_cache->name_length[previous] == name_len
                    && memcmp(out_cache->name[previous], entry + 8, name_len)
                        == 0) {
                    return -1;
                }
            }
        }
    }
    return 1;
}

static int pack_payload(
    const ninlil_port_esp_storage_view_t *view,
    uint8_t *out,
    uint32_t capacity,
    uint32_t *out_len)
{
    uint32_t offset = 0u;
    uint32_t index;

    *out_len = 0u;
    for (index = 0u; index < view->entry_count; ++index) {
        const ninlil_port_esp_storage_entry_t *entry = &view->entries[index];
        uint32_t need = 6u + entry->key_length + entry->value_length;
        if (need > capacity - offset) {
            return 0;
        }
        ninlil_port_esp_storage_store_u16_le(out + offset, entry->key_length);
        ninlil_port_esp_storage_store_u32_le(out + offset + 2u, entry->value_length);
        offset += 6u;
        if (entry->key_length != 0u) {
            (void)memcpy(out + offset, entry->key, entry->key_length);
            offset += entry->key_length;
        }
        if (entry->value_length != 0u) {
            if (entry->value_offset + entry->value_length > view->value_blob_used) {
                return 0;
            }
            (void)memcpy(
                out + offset,
                view->value_blob + entry->value_offset,
                entry->value_length);
            offset += entry->value_length;
        }
    }
    *out_len = offset;
    return 1;
}

static int unpack_payload(
    const uint8_t *payload,
    uint32_t payload_len,
    uint32_t entry_count,
    ninlil_port_esp_storage_view_t *out_view)
{
    uint32_t offset = 0u;
    uint32_t index;

    (void)memset(out_view, 0, sizeof(*out_view));
    if (entry_count > NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES) {
        return 0;
    }
    for (index = 0u; index < entry_count; ++index) {
        uint16_t key_length;
        uint32_t value_length;
        ninlil_port_esp_storage_entry_t *entry;
        if (offset + 6u > payload_len) {
            return 0;
        }
        key_length = ninlil_port_esp_storage_load_u16_le(payload + offset);
        value_length = ninlil_port_esp_storage_load_u32_le(payload + offset + 2u);
        offset += 6u;
        if (key_length < 1u || key_length > 255u
            || value_length > NINLIL_M1A_MAX_STORAGE_VALUE_BYTES
            || offset + key_length + value_length > payload_len) {
            return 0;
        }
        entry = &out_view->entries[index];
        entry->key_length = key_length;
        entry->value_length = value_length;
        (void)memcpy(entry->key, payload + offset, key_length);
        offset += key_length;
        entry->value_offset = out_view->value_blob_used;
        if (value_length != 0u) {
            if (out_view->value_blob_used
                > NINLIL_PORT_ESP_STORAGE_HARD_MAX_LOGICAL_BYTES - value_length) {
                return 0;
            }
            (void)memcpy(
                out_view->value_blob + out_view->value_blob_used,
                payload + offset,
                value_length);
            out_view->value_blob_used += value_length;
            offset += value_length;
        }
    }
    if (offset != payload_len) {
        return 0;
    }
    out_view->entry_count = entry_count;
    {
        uint64_t bytes = 0u;
        for (index = 0u; index < entry_count; ++index) {
            bytes += 16u + out_view->entries[index].key_length
                + out_view->entries[index].value_length;
        }
        out_view->used_logical_bytes = bytes;
    }
    for (index = 1u; index < entry_count; ++index) {
        uint32_t left_len = out_view->entries[index - 1u].key_length;
        uint32_t right_len = out_view->entries[index].key_length;
        uint32_t common = left_len < right_len ? left_len : right_len;
        int cmp = common == 0u
            ? 0
            : memcmp(
                  out_view->entries[index - 1u].key,
                  out_view->entries[index].key,
                  common);
        if (cmp > 0 || (cmp == 0 && left_len >= right_len)) {
            return 0;
        }
    }
    return 1;
}

int ninlil_port_esp_storage_encode_slot(
    uint32_t schema,
    uint64_t generation,
    const uint8_t *namespace_bytes,
    uint32_t namespace_length,
    const ninlil_port_esp_storage_view_t *view,
    uint8_t *out,
    uint32_t capacity)
{
    uint32_t payload_len = 0u;
    uint8_t *payload;
    uint32_t payload_crc;
    uint32_t header_crc;

    if (out == NULL || view == NULL || capacity < NINLIL_PORT_ESP_STORAGE_SLOT_BYTES
        || namespace_length < 1u || namespace_length > 255u
        || namespace_bytes == NULL || generation == 0u
        || view->entry_count > NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES
        || view->used_logical_bytes
            > NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_LOGICAL_BYTES) {
        return 0;
    }
    (void)memset(out, 0, NINLIL_PORT_ESP_STORAGE_SLOT_BYTES);
    ninlil_port_esp_storage_store_u32_le(out + 0, NINLIL_PORT_ESP_STORAGE_SLOT_MAGIC);
    ninlil_port_esp_storage_store_u32_le(out + 4, NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION);
    ninlil_port_esp_storage_store_u32_le(out + 8, schema);
    ninlil_port_esp_storage_store_u32_le(out + 12, namespace_length);
    (void)memcpy(out + 16, namespace_bytes, namespace_length);
    /* 271 reserved zero already */
    ninlil_port_esp_storage_store_u64_le(out + 272, generation);
    ninlil_port_esp_storage_store_u32_le(out + 280, view->entry_count);
    ninlil_port_esp_storage_store_u64_le(out + 284, view->used_logical_bytes);
    payload = out + NINLIL_PORT_ESP_STORAGE_SLOT_HEADER_BYTES;
    if (!pack_payload(
            view,
            payload,
            NINLIL_PORT_ESP_STORAGE_SLOT_PAYLOAD_BYTES,
            &payload_len)) {
        return 0;
    }
    ninlil_port_esp_storage_store_u32_le(out + 292, payload_len);
    payload_crc = ninlil_port_esp_storage_crc32c(payload, payload_len);
    ninlil_port_esp_storage_store_u32_le(out + 300, payload_crc);
    header_crc = ninlil_port_esp_storage_crc32c(out, 304u);
    ninlil_port_esp_storage_store_u32_le(out + 304, header_crc);
    return 1;
}

int ninlil_port_esp_storage_decode_slot(
    const uint8_t *image,
    uint32_t length,
    uint32_t expected_schema,
    const uint8_t *expected_namespace,
    uint32_t expected_namespace_length,
    ninlil_port_esp_storage_view_t *out_view,
    uint64_t *out_generation)
{
    uint32_t magic;
    uint32_t version;
    uint32_t schema;
    uint32_t ns_len;
    uint32_t entry_count;
    uint64_t used_bytes;
    uint32_t payload_len;
    uint32_t payload_crc;
    uint32_t header_crc;
    const uint8_t *payload;

    if (image == NULL || length < NINLIL_PORT_ESP_STORAGE_SLOT_BYTES
        || out_view == NULL || out_generation == NULL) {
        return 0;
    }
    if (bytes_all_erased(image, NINLIL_PORT_ESP_STORAGE_SLOT_BYTES)) {
        return 0; /* erased NOR empty */
    }
    magic = ninlil_port_esp_storage_load_u32_le(image + 0);
    version = ninlil_port_esp_storage_load_u32_le(image + 4);
    schema = ninlil_port_esp_storage_load_u32_le(image + 8);
    ns_len = ninlil_port_esp_storage_load_u32_le(image + 12);
    *out_generation = ninlil_port_esp_storage_load_u64_le(image + 272);
    entry_count = ninlil_port_esp_storage_load_u32_le(image + 280);
    used_bytes = ninlil_port_esp_storage_load_u64_le(image + 284);
    payload_len = ninlil_port_esp_storage_load_u32_le(image + 292);
    payload_crc = ninlil_port_esp_storage_load_u32_le(image + 300);
    header_crc = ninlil_port_esp_storage_load_u32_le(image + 304);

    if (magic != NINLIL_PORT_ESP_STORAGE_SLOT_MAGIC
        || version != NINLIL_PORT_ESP_STORAGE_FORMAT_VERSION
        || ns_len < 1u || ns_len > 255u
        || image[271] != 0u
        || !bytes_all_zero(image + 296, 4u)
        || !bytes_all_zero(image + 308, 12u)
        || *out_generation == 0u
        || entry_count > NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_ENTRIES
        || used_bytes > NINLIL_PORT_ESP_STORAGE_PERSISTED_MAX_LOGICAL_BYTES
        || payload_len > NINLIL_PORT_ESP_STORAGE_SLOT_PAYLOAD_BYTES
        || !bytes_all_zero(image + 16u + ns_len, 255u - ns_len)
        || header_crc != ninlil_port_esp_storage_crc32c(image, 304u)) {
        return -1;
    }
    payload = image + NINLIL_PORT_ESP_STORAGE_SLOT_HEADER_BYTES;
    if (payload_crc != ninlil_port_esp_storage_crc32c(payload, payload_len)) {
        return -1;
    }
    if (schema != expected_schema) {
        return -1;
    }
    if (expected_namespace != NULL) {
        if (expected_namespace_length != ns_len
            || memcmp(image + 16, expected_namespace, ns_len) != 0) {
            return -1; /* wrong identity */
        }
    }
    if (!unpack_payload(payload, payload_len, entry_count, out_view)) {
        return -1;
    }
    if (out_view->used_logical_bytes != used_bytes) {
        return -1;
    }
    return 1;
}
