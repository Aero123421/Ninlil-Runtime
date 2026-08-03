#include "wifi_journal.h"

#include "wifi_sha256.h"
#include "wifi_storage_cu.h"

#include <string.h>

void ninlil_wifi_journal_init(ninlil_wifi_journal_t *journal)
{
    if (journal == NULL) {
        return;
    }
    (void)memset(journal, 0, sizeof(*journal));
}

static void le_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static void le_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu);
    p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static void le_u64(uint8_t *p, uint64_t v)
{
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xffu);
    }
}

static uint16_t rd_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static uint64_t rd_u64(const uint8_t *p)
{
    uint64_t v = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        v |= ((uint64_t)p[i]) << (8u * i);
    }
    return v;
}

static ninlil_wifi_status_t map_storage_status(
    ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_WIFI_OK;
    }
    if (status == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN;
    }
    if (status == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (status == NINLIL_STORAGE_NO_SPACE
        || status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        return NINLIL_WIFI_CAPACITY;
    }
    if (status == NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
        return NINLIL_WIFI_UNSUPPORTED;
    }
    return NINLIL_WIFI_IO_ERROR;
}

/*
 * Explicit LE wire layout (160B):
 * magic[4] | version_u16_le | flags_u16_le | attempt_id_u64_le | mono_ms_u64_le |
 * endpoint_index_u32_le | generation_u32_le | phase_u8 | write_point_u8 |
 * reserved[6] | session_id[16] | secret_ref[32] | endpoint_digest[32] |
 * image_digest[32] | pad[8]
 * image_digest = SHA256(bytes[0..127]) with digest field zeroed.
 */
void ninlil_wifi_journal_attempt_encode_le(
    const ninlil_wifi_journal_attempt_t *attempt,
    uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES])
{
    uint8_t dig[32];
    if (attempt == NULL || wire == NULL) {
        return;
    }
    (void)memset(wire, 0, NINLIL_WIFI_JOURNAL_VALUE_BYTES);
    wire[0] = NINLIL_WIFI_JOURNAL_MAGIC0;
    wire[1] = NINLIL_WIFI_JOURNAL_MAGIC1;
    wire[2] = NINLIL_WIFI_JOURNAL_MAGIC2;
    wire[3] = NINLIL_WIFI_JOURNAL_MAGIC3;
    le_u16(wire + 4, NINLIL_WIFI_JOURNAL_VERSION);
    le_u16(wire + 6, attempt->flags);
    le_u64(wire + 8, attempt->attempt_id);
    le_u64(wire + 16, attempt->mono_ms);
    le_u32(wire + 24, attempt->endpoint_index);
    le_u32(wire + 28, attempt->generation);
    wire[32] = attempt->phase;
    wire[33] = attempt->write_point;
    (void)memcpy(wire + 40, attempt->session_id, 16u);
    (void)memcpy(wire + 56, attempt->secret_ref_digest, 32u);
    (void)memcpy(wire + 88, attempt->endpoint_digest, 32u);
    /* Digest covers LE prefix [0..120); stored at [120..152). */
    ninlil_wifi_sha256(wire, 120u, dig);
    (void)memcpy(wire + 120, dig, 32u);
}

int ninlil_wifi_journal_attempt_decode_le(
    const uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES],
    ninlil_wifi_journal_attempt_t *out_attempt)
{
    uint8_t tmp[NINLIL_WIFI_JOURNAL_VALUE_BYTES];
    uint8_t dig[32];
    if (wire == NULL || out_attempt == NULL) {
        return 0;
    }
    if (wire[0] != NINLIL_WIFI_JOURNAL_MAGIC0
        || wire[1] != NINLIL_WIFI_JOURNAL_MAGIC1
        || wire[2] != NINLIL_WIFI_JOURNAL_MAGIC2
        || wire[3] != NINLIL_WIFI_JOURNAL_MAGIC3) {
        return 0;
    }
    if (rd_u16(wire + 4) != NINLIL_WIFI_JOURNAL_VERSION) {
        return 0;
    }
    if (wire[33] > 4u) {
        return 0;
    }
    (void)memcpy(tmp, wire, NINLIL_WIFI_JOURNAL_VALUE_BYTES);
    (void)memset(tmp + 120, 0, 32u);
    ninlil_wifi_sha256(tmp, 120u, dig);
    if (memcmp(dig, wire + 120, 32u) != 0) {
        return 0;
    }
    (void)memset(out_attempt, 0, sizeof(*out_attempt));
    out_attempt->magic[0] = wire[0];
    out_attempt->magic[1] = wire[1];
    out_attempt->magic[2] = wire[2];
    out_attempt->magic[3] = wire[3];
    out_attempt->version = rd_u16(wire + 4);
    out_attempt->flags = rd_u16(wire + 6);
    out_attempt->attempt_id = rd_u64(wire + 8);
    out_attempt->mono_ms = rd_u64(wire + 16);
    out_attempt->endpoint_index = rd_u32(wire + 24);
    out_attempt->generation = rd_u32(wire + 28);
    out_attempt->phase = wire[32];
    out_attempt->write_point = wire[33];
    (void)memcpy(out_attempt->session_id, wire + 40, 16u);
    (void)memcpy(out_attempt->secret_ref_digest, wire + 56, 32u);
    (void)memcpy(out_attempt->endpoint_digest, wire + 88, 32u);
    (void)memcpy(out_attempt->image_digest, wire + 120, 32u);
    return 1;
}

void ninlil_wifi_journal_attempt_seal(ninlil_wifi_journal_attempt_t *attempt)
{
    uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES];
    if (attempt == NULL) {
        return;
    }
    attempt->magic[0] = NINLIL_WIFI_JOURNAL_MAGIC0;
    attempt->magic[1] = NINLIL_WIFI_JOURNAL_MAGIC1;
    attempt->magic[2] = NINLIL_WIFI_JOURNAL_MAGIC2;
    attempt->magic[3] = NINLIL_WIFI_JOURNAL_MAGIC3;
    attempt->version = NINLIL_WIFI_JOURNAL_VERSION;
    ninlil_wifi_journal_attempt_encode_le(attempt, wire);
    (void)memcpy(attempt->image_digest, wire + 120, 32u);
}

int ninlil_wifi_journal_attempt_valid(
    const ninlil_wifi_journal_attempt_t *attempt)
{
    uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES];
    ninlil_wifi_journal_attempt_t decoded;
    if (attempt == NULL) {
        return 0;
    }
    ninlil_wifi_journal_attempt_encode_le(attempt, wire);
    if (!ninlil_wifi_journal_attempt_decode_le(wire, &decoded)) {
        return 0;
    }
    return memcmp(decoded.image_digest, attempt->image_digest, 32u) == 0;
}

ninlil_wifi_status_t ninlil_wifi_journal_open(
    ninlil_wifi_journal_t *journal,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8)
{
    ninlil_storage_status_t st;
    ninlil_bytes_view_t ns;
    ninlil_storage_handle_t handle = NULL;
    size_t path_length;
    if (journal == NULL || storage == NULL || path_utf8 == NULL
        || storage->open == NULL || storage->close == NULL
        || storage->begin == NULL || storage->commit == NULL
        || storage->put == NULL || storage->get == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ninlil_wifi_journal_close(journal);
    path_length = strlen(path_utf8);
    if (path_length == 0u || path_length >= sizeof(journal->path_utf8)
        || path_length > UINT32_MAX) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ns.data = (const uint8_t *)path_utf8;
    ns.length = (uint32_t)path_length;
    st = storage->open(
        storage_user, ns, NINLIL_STORAGE_SCHEMA_M1A, &handle);
    if (st != NINLIL_STORAGE_OK || handle == NULL) {
        return st == NINLIL_STORAGE_OK
            ? NINLIL_WIFI_CORRUPT
            : map_storage_status(st);
    }
    storage->close(storage_user, handle);
    journal->storage = storage;
    journal->storage_user = storage_user;
    (void)memcpy(journal->path_utf8, path_utf8, path_length + 1u);
    journal->open = 1u;
    return NINLIL_WIFI_OK;
}

void ninlil_wifi_journal_close(ninlil_wifi_journal_t *journal)
{
    if (journal == NULL) {
        return;
    }
    (void)memset(journal, 0, sizeof(*journal));
}

ninlil_wifi_status_t ninlil_wifi_journal_put_attempt(
    ninlil_wifi_journal_t *journal,
    ninlil_wifi_journal_attempt_t *attempt)
{
    uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES];
    if (journal == NULL || attempt == NULL || !journal->open) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    ninlil_wifi_journal_attempt_seal(attempt);
    ninlil_wifi_journal_attempt_encode_le(attempt, wire);
    journal->last_commit_unknown_class = NINLIL_WIFI_CU_NONE;
    return ninlil_wifi_storage_cu_put_full(
        journal->storage,
        journal->storage_user,
        journal->path_utf8,
        NINLIL_WIFI_JOURNAL_KEY_ATTEMPT,
        wire,
        (uint32_t)sizeof(wire),
        &journal->last_commit_unknown_class);
}

ninlil_wifi_status_t ninlil_wifi_journal_get_attempt(
    ninlil_wifi_journal_t *journal,
    ninlil_wifi_journal_attempt_t *out_attempt)
{
    uint8_t wire[NINLIL_WIFI_JOURNAL_VALUE_BYTES];
    uint32_t value_length = 0u;
    int present = 0;
    ninlil_wifi_status_t status;
    if (journal == NULL || out_attempt == NULL || !journal->open) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    status = ninlil_wifi_storage_read(
        journal->storage,
        journal->storage_user,
        journal->path_utf8,
        NINLIL_WIFI_JOURNAL_KEY_ATTEMPT,
        wire,
        sizeof(wire),
        &value_length,
        &present);
    if (status != NINLIL_WIFI_OK) {
        return status;
    }
    if (present == 0) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (value_length != sizeof(wire)) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (!ninlil_wifi_journal_attempt_decode_le(wire, out_attempt)) {
        return NINLIL_WIFI_CORRUPT;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_journal_recover(
    ninlil_wifi_journal_t *journal,
    ninlil_wifi_journal_attempt_t *out_attempt)
{
    return ninlil_wifi_journal_get_attempt(journal, out_attempt);
}

ninlil_wifi_cu_class_t ninlil_wifi_journal_last_commit_unknown_class(
    const ninlil_wifi_journal_t *journal)
{
    return journal == NULL
        ? NINLIL_WIFI_CU_NONE
        : journal->last_commit_unknown_class;
}
