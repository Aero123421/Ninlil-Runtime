#ifndef NINLIL_TRANSPORT_POSIX_TLS_V1_RECORDS_H
#define NINLIL_TRANSPORT_POSIX_TLS_V1_RECORDS_H

/* Private FULL records used by the Host POSIX TLS v1 owner. */
#include "wifi_private_types.h"

#include <ninlil/platform.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_POSIX_TLS_V1_RECORD_NAMESPACE_MAX 127u
#define NINLIL_POSIX_TLS_V1_RECORD_PATH_MAX 288u
#define NINLIL_POSIX_TLS_V1_RECORD_VALUE_MAX 256u
#define NINLIL_POSIX_TLS_V1_RECORD_HEADER_BYTES 12u
#define NINLIL_POSIX_TLS_V1_RECORD_PAYLOAD_MAX                         \
    (NINLIL_POSIX_TLS_V1_RECORD_VALUE_MAX                              \
     - NINLIL_POSIX_TLS_V1_RECORD_HEADER_BYTES)

typedef uint8_t ninlil_posix_tls_v1_record_kind_t;

#define NINLIL_POSIX_TLS_V1_RECORD_MEMBERSHIP                          \
    ((ninlil_posix_tls_v1_record_kind_t)1u)
#define NINLIL_POSIX_TLS_V1_RECORD_CREDENTIAL                          \
    ((ninlil_posix_tls_v1_record_kind_t)2u)
#define NINLIL_POSIX_TLS_V1_RECORD_ATTACHMENT                          \
    ((ninlil_posix_tls_v1_record_kind_t)3u)
#define NINLIL_POSIX_TLS_V1_RECORD_FABRIC_REGISTRY                     \
    ((ninlil_posix_tls_v1_record_kind_t)4u)
#define NINLIL_POSIX_TLS_V1_RECORD_LIFECYCLE                           \
    ((ninlil_posix_tls_v1_record_kind_t)5u)

#define NINLIL_POSIX_TLS_V1_LIFECYCLE_FORMAT_VERSION UINT16_C(1)
#define NINLIL_POSIX_TLS_V1_LIFECYCLE_PAYLOAD_BYTES UINT32_C(100)

typedef struct ninlil_posix_tls_v1_lifecycle_record {
    uint16_t format_version;
    uint8_t clean;
    uint8_t available;
    uint64_t availability_epoch;
    ninlil_id128_t instance_id;
    uint8_t descriptor_digest[32];
    uint64_t configuration_revision;
    uint8_t configuration_digest[32];
} ninlil_posix_tls_v1_lifecycle_record_t;

/*
 * Derive the Storage path as a fixed ASCII prefix followed by the complete
 * lowercase hexadecimal namespace.  The mapping is reversible and unique
 * for every allowed 1..127-byte namespace, including embedded NUL bytes.
 */
ninlil_wifi_status_t ninlil_posix_tls_v1_record_path(
    ninlil_bytes_view_t storage_namespace,
    char *out_path,
    size_t out_path_capacity,
    size_t *out_path_length);

/* Return the fixed Storage key for a record kind, or NULL for an invalid kind. */
const char *ninlil_posix_tls_v1_record_key(
    ninlil_posix_tls_v1_record_kind_t kind);

/*
 * Fresh-read and exactly parse the lifecycle record.  When it is absent,
 * also classify whether any of the four attachment records already exists.
 */
ninlil_wifi_status_t ninlil_posix_tls_v1_record_read_lifecycle(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    ninlil_bytes_view_t storage_namespace,
    ninlil_posix_tls_v1_lifecycle_record_t *out_record,
    int *out_present,
    int *out_existing_private_state);

/*
 * Write one version-1 FULL record and then verify it through a fresh
 * read-only Storage transaction.  A COMMIT_UNKNOWN result is never promoted
 * to success, even when the lower reconciliation helper observes INTENDED.
 */
ninlil_wifi_status_t ninlil_posix_tls_v1_record_put_full_verify(
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    ninlil_bytes_view_t storage_namespace,
    ninlil_posix_tls_v1_record_kind_t kind,
    ninlil_bytes_view_t payload);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_POSIX_TLS_V1_RECORDS_H */
