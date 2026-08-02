#include "posix_tls_v1_records.h"

#include "wifi_storage_cu.h"

#include <string.h>

#define POSIX_TLS_RECORD_VERSION UINT16_C(1)
#define POSIX_TLS_RECORD_DURABILITY_FULL UINT8_C(1)

static const char posix_tls_record_path_prefix[] = "ninlil.posix_tls_v1/";

static const char *const posix_tls_record_keys[] = {
    NULL,
    "membership.full.v1",
    "credential.full.v1",
    "attachment.full.v1",
    "fabric_registry.full.v1",
    "lifecycle.full.v1",
};

static void posix_tls_store_u16_be(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)(value >> 8);
    out[1] = (uint8_t)value;
}

static void posix_tls_store_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static uint16_t posix_tls_load_u16_be(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8) | (uint16_t)in[1]);
}

static uint32_t posix_tls_load_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16)
        | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
}

static uint64_t posix_tls_load_u64_be(const uint8_t *in)
{
    return ((uint64_t)in[0] << 56) | ((uint64_t)in[1] << 48)
        | ((uint64_t)in[2] << 40) | ((uint64_t)in[3] << 32)
        | ((uint64_t)in[4] << 24) | ((uint64_t)in[5] << 16)
        | ((uint64_t)in[6] << 8) | (uint64_t)in[7];
}

static int posix_tls_record_kind_valid(
    ninlil_posix_tls_v1_record_kind_t kind)
{
    return kind >= NINLIL_POSIX_TLS_V1_RECORD_MEMBERSHIP
        && kind <= NINLIL_POSIX_TLS_V1_RECORD_LIFECYCLE;
}

ninlil_wifi_status_t ninlil_posix_tls_v1_record_path(
    ninlil_bytes_view_t storage_namespace,
    char *out_path,
    size_t out_path_capacity,
    size_t *out_path_length)
{
    static const char hex[] = "0123456789abcdef";
    const size_t prefix_length = sizeof(posix_tls_record_path_prefix) - 1u;
    size_t required;
    size_t i;

    if (out_path_length != NULL) {
        *out_path_length = 0u;
    }
    if (storage_namespace.data == NULL || storage_namespace.length == 0u
        || storage_namespace.length
            > NINLIL_POSIX_TLS_V1_RECORD_NAMESPACE_MAX
        || out_path == NULL || out_path_length == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    required = prefix_length + ((size_t)storage_namespace.length * 2u);
    if (out_path_capacity <= required) {
        return NINLIL_WIFI_CAPACITY;
    }

    memcpy(out_path, posix_tls_record_path_prefix, prefix_length);
    for (i = 0u; i < storage_namespace.length; ++i) {
        const uint8_t byte = storage_namespace.data[i];
        out_path[prefix_length + (i * 2u)] = hex[byte >> 4];
        out_path[prefix_length + (i * 2u) + 1u] = hex[byte & UINT8_C(0x0f)];
    }
    out_path[required] = '\0';
    *out_path_length = required;
    return NINLIL_WIFI_OK;
}

const char *ninlil_posix_tls_v1_record_key(
    ninlil_posix_tls_v1_record_kind_t kind)
{
    if (!posix_tls_record_kind_valid(kind)) {
        return NULL;
    }
    return posix_tls_record_keys[kind];
}

ninlil_wifi_status_t ninlil_posix_tls_v1_record_read_lifecycle(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    ninlil_bytes_view_t storage_namespace,
    ninlil_posix_tls_v1_lifecycle_record_t *out_record,
    int *out_present,
    int *out_existing_private_state)
{
    uint8_t observed[NINLIL_POSIX_TLS_V1_RECORD_VALUE_MAX];
    char path[NINLIL_POSIX_TLS_V1_RECORD_PATH_MAX];
    uint32_t observed_length = 0u;
    size_t path_length = 0u;
    int observed_present = 0;
    ninlil_wifi_status_t status;
    uint8_t kind;

    if (out_record != NULL) {
        memset(out_record, 0, sizeof(*out_record));
    }
    if (out_present != NULL) {
        *out_present = 0;
    }
    if (out_existing_private_state != NULL) {
        *out_existing_private_state = 0;
    }
    if (storage == NULL || out_record == NULL || out_present == NULL
        || out_existing_private_state == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    status = ninlil_posix_tls_v1_record_path(
        storage_namespace, path, sizeof(path), &path_length);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    (void)path_length;
    status = ninlil_wifi_storage_read(
        storage,
        storage_user,
        path,
        ninlil_posix_tls_v1_record_key(
            NINLIL_POSIX_TLS_V1_RECORD_LIFECYCLE),
        observed,
        sizeof(observed),
        &observed_length,
        &observed_present);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    if (observed_present == 0) {
        for (kind = NINLIL_POSIX_TLS_V1_RECORD_MEMBERSHIP;
             kind <= NINLIL_POSIX_TLS_V1_RECORD_FABRIC_REGISTRY;
             ++kind) {
            status = ninlil_wifi_storage_read(
                storage,
                storage_user,
                path,
                ninlil_posix_tls_v1_record_key(kind),
                observed,
                sizeof(observed),
                &observed_length,
                &observed_present);
            if (status != NINLIL_WIFI_OK) {
                return status;
            }
            if (observed_present != 0) {
                *out_existing_private_state = 1;
                break;
            }
        }
        return NINLIL_WIFI_OK;
    }

    *out_present = 1;
    *out_existing_private_state = 1;
    if (observed_length != NINLIL_POSIX_TLS_V1_RECORD_HEADER_BYTES
            + NINLIL_POSIX_TLS_V1_LIFECYCLE_PAYLOAD_BYTES
        || memcmp(observed, "PTR1", 4u) != 0
        || posix_tls_load_u16_be(&observed[4]) != POSIX_TLS_RECORD_VERSION
        || observed[6] != NINLIL_POSIX_TLS_V1_RECORD_LIFECYCLE
        || observed[7] != POSIX_TLS_RECORD_DURABILITY_FULL
        || posix_tls_load_u32_be(&observed[8])
            != NINLIL_POSIX_TLS_V1_LIFECYCLE_PAYLOAD_BYTES) {
        return NINLIL_WIFI_CORRUPT;
    }

    out_record->format_version = posix_tls_load_u16_be(&observed[12]);
    out_record->clean = observed[14];
    out_record->available = observed[15];
    out_record->availability_epoch = posix_tls_load_u64_be(&observed[16]);
    memcpy(out_record->instance_id.bytes, &observed[24], 16u);
    memcpy(out_record->descriptor_digest, &observed[40], 32u);
    out_record->configuration_revision =
        posix_tls_load_u64_be(&observed[72]);
    memcpy(out_record->configuration_digest, &observed[80], 32u);
    if (out_record->format_version
            != NINLIL_POSIX_TLS_V1_LIFECYCLE_FORMAT_VERSION
        || out_record->clean > 1u || out_record->available > 1u
        || out_record->availability_epoch == 0u
        || out_record->configuration_revision == 0u) {
        memset(out_record, 0, sizeof(*out_record));
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_posix_tls_v1_record_put_full_verify(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    ninlil_bytes_view_t storage_namespace,
    ninlil_posix_tls_v1_record_kind_t kind,
    ninlil_bytes_view_t payload)
{
    uint8_t intended[NINLIL_POSIX_TLS_V1_RECORD_VALUE_MAX];
    uint8_t observed[NINLIL_POSIX_TLS_V1_RECORD_VALUE_MAX];
    char path[NINLIL_POSIX_TLS_V1_RECORD_PATH_MAX];
    const char *key;
    uint32_t intended_length;
    uint32_t observed_length = 0u;
    size_t path_length = 0u;
    int observed_present = 0;
    ninlil_wifi_cu_class_t cu_class = NINLIL_WIFI_CU_NONE;
    ninlil_wifi_status_t status;

    key = ninlil_posix_tls_v1_record_key(kind);
    if (storage == NULL || key == NULL
        || payload.length > NINLIL_POSIX_TLS_V1_RECORD_PAYLOAD_MAX
        || (payload.length != 0u && payload.data == NULL)) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    status = ninlil_posix_tls_v1_record_path(
        storage_namespace, path, sizeof(path), &path_length);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    (void)path_length;

    memset(intended, 0, sizeof(intended));
    intended[0] = (uint8_t)'P';
    intended[1] = (uint8_t)'T';
    intended[2] = (uint8_t)'R';
    intended[3] = (uint8_t)'1';
    posix_tls_store_u16_be(&intended[4], POSIX_TLS_RECORD_VERSION);
    intended[6] = kind;
    intended[7] = POSIX_TLS_RECORD_DURABILITY_FULL;
    posix_tls_store_u32_be(&intended[8], payload.length);
    if (payload.length != 0u) {
        memcpy(
            &intended[NINLIL_POSIX_TLS_V1_RECORD_HEADER_BYTES],
            payload.data,
            payload.length);
    }
    intended_length = NINLIL_POSIX_TLS_V1_RECORD_HEADER_BYTES + payload.length;

    status = ninlil_wifi_storage_cu_put_full(
        storage,
        storage_user,
        path,
        key,
        intended,
        intended_length,
        &cu_class);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }

    status = ninlil_wifi_storage_read(
        storage,
        storage_user,
        path,
        key,
        observed,
        sizeof(observed),
        &observed_length,
        &observed_present);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    if (!observed_present || observed_length != intended_length
        || memcmp(observed, intended, intended_length) != 0) {
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
}
