#ifndef NINLIL_TRANSPORT_WIFI_V1_WIFI_JOURNAL_H
#define NINLIL_TRANSPORT_WIFI_V1_WIFI_JOURNAL_H

/*
 * Durable Wi-Fi attempt journal (ADR-0018 / NWD1-aligned 160B image).
 * CU semantics via ninlil_storage_ops. COMMIT_UNKNOWN remains a distinct
 * status and is reconciled by a fresh close/reopen observation.
 * Never stores password plaintext. Semantic validation on recover.
 */
#include "wifi_private_types.h"

#include <ninlil/platform.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NINLIL_WIFI_JOURNAL_NS "ninlil.wifi.journal.v1"
#define NINLIL_WIFI_JOURNAL_KEY_ATTEMPT "WJ1_ATTEMPT"
#define NINLIL_WIFI_JOURNAL_VALUE_BYTES 160u
#define NINLIL_WIFI_JOURNAL_MAGIC0 ((uint8_t)'W')
#define NINLIL_WIFI_JOURNAL_MAGIC1 ((uint8_t)'J')
#define NINLIL_WIFI_JOURNAL_MAGIC2 ((uint8_t)'1')
#define NINLIL_WIFI_JOURNAL_MAGIC3 ((uint8_t)'A')
#define NINLIL_WIFI_JOURNAL_VERSION ((uint16_t)1u)

/*
 * On-wire / storage image: little-endian integers, exact 160 bytes.
 * magic[4] | version_u16_le | flags_u16_le | attempt_id_u64_le | mono_ms_u64_le |
 * endpoint_index_u32_le | generation_u32_le | phase_u8 | write_point_u8 |
 * reserved[6] | session_id[16] | secret_ref_digest[32] | endpoint_digest[32] |
 * image_digest_sha256[32] covering bytes [0..127].
 */
typedef struct ninlil_wifi_journal_attempt {
    uint8_t magic[4];
    uint16_t version;
    uint16_t flags;
    uint64_t attempt_id;
    uint64_t mono_ms;
    uint32_t endpoint_index;
    uint32_t generation;
    uint8_t phase;
    uint8_t write_point; /* 0=start,1=tcp_ok,2=tls_ok,3=attached,4=fenced */
    uint8_t reserved[6];
    uint8_t session_id[16];
    uint8_t secret_ref_digest[32];
    uint8_t endpoint_digest[32];
    uint8_t image_digest[32];
    uint8_t pad[8]; /* exact 160-byte CU image */
} ninlil_wifi_journal_attempt_t;

_Static_assert(
    sizeof(ninlil_wifi_journal_attempt_t) == NINLIL_WIFI_JOURNAL_VALUE_BYTES,
    "journal attempt size");

typedef struct ninlil_wifi_journal {
    const ninlil_storage_ops_t *storage;
    void *storage_user;
    char path_utf8[64];
    ninlil_wifi_cu_class_t last_commit_unknown_class;
    uint8_t open;
    uint8_t reserved[3];
} ninlil_wifi_journal_t;

void ninlil_wifi_journal_init(ninlil_wifi_journal_t *journal);

ninlil_wifi_status_t ninlil_wifi_journal_open(
    ninlil_wifi_journal_t *journal,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8);

void ninlil_wifi_journal_close(ninlil_wifi_journal_t *journal);

/*
 * Fill magic/version + image_digest; then FULL CU put.
 * COMMIT_UNKNOWN returns NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN and records an
 * exact INTENDED/OLD/ABSENT/OTHER durable observation in the journal.
 */
ninlil_wifi_status_t ninlil_wifi_journal_put_attempt(
    ninlil_wifi_journal_t *journal,
    ninlil_wifi_journal_attempt_t *attempt);

/* Get + semantic validate (magic/version/digest). */
ninlil_wifi_status_t ninlil_wifi_journal_get_attempt(
    ninlil_wifi_journal_t *journal,
    ninlil_wifi_journal_attempt_t *out_attempt);

ninlil_wifi_status_t ninlil_wifi_journal_recover(
    ninlil_wifi_journal_t *journal,
    ninlil_wifi_journal_attempt_t *out_attempt);

/* Seal fields for put (magic/version/digest via LE wire encode). */
void ninlil_wifi_journal_attempt_seal(ninlil_wifi_journal_attempt_t *attempt);

/* Explicit LE wire codec (160B). No native struct store on media. */
void ninlil_wifi_journal_attempt_encode_le(
    const ninlil_wifi_journal_attempt_t *attempt,
    uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES]);

int ninlil_wifi_journal_attempt_decode_le(
    const uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES],
    ninlil_wifi_journal_attempt_t *out_attempt);

/* Validate sealed image; 1=ok. */
int ninlil_wifi_journal_attempt_valid(
    const ninlil_wifi_journal_attempt_t *attempt);

ninlil_wifi_cu_class_t ninlil_wifi_journal_last_commit_unknown_class(
    const ninlil_wifi_journal_t *journal);

#ifdef __cplusplus
}
#endif

#endif /* NINLIL_TRANSPORT_WIFI_V1_WIFI_JOURNAL_H */
