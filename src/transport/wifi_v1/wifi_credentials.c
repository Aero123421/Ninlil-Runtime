#include "wifi_credentials.h"

#include "wifi_sha256.h"
#include "wifi_storage_cu.h"

#include <string.h>

void ninlil_wifi_credential_store_init(ninlil_wifi_credential_store_t *store)
{
    if (store == NULL) {
        return;
    }
    (void)memset(store, 0, sizeof(*store));
}

static ninlil_bytes_view_t bv(const void *data, uint32_t length)
{
    ninlil_bytes_view_t v;
    v.data = (const uint8_t *)data;
    v.length = length;
    return v;
}

static ninlil_wifi_status_t map_st(ninlil_storage_status_t st)
{
    if (st == NINLIL_STORAGE_OK) {
        return NINLIL_WIFI_OK;
    }
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (st == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_WIFI_STORAGE_COMMIT_UNKNOWN;
    }
    if (st == NINLIL_STORAGE_CORRUPT) {
        return NINLIL_WIFI_CORRUPT;
    }
    if (st == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_WIFI_CAPACITY;
    }
    if (st == NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
        return NINLIL_WIFI_UNSUPPORTED;
    }
    return NINLIL_WIFI_IO_ERROR;
}

static void le_u16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
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

static uint64_t rd_u64(const uint8_t *p)
{
    uint64_t v = 0u;
    uint32_t i;
    for (i = 0u; i < 8u; ++i) {
        v |= ((uint64_t)p[i]) << (8u * i);
    }
    return v;
}

/* NWD1 LE: magic ND1C | ver | flags | revision | secret_ref | seal */
static void encode_nwd1_full(
    const ninlil_wifi_secret_ref_t *ref,
    uint8_t wire[NINLIL_WIFI_NWD1_IMAGE_BYTES])
{
    uint8_t dig[32];
    (void)memset(wire, 0, NINLIL_WIFI_NWD1_IMAGE_BYTES);
    wire[0] = (uint8_t)'N';
    wire[1] = (uint8_t)'D';
    wire[2] = (uint8_t)'1';
    wire[3] = (uint8_t)'C';
    le_u16(wire + 4, 1u);
    le_u16(wire + 6, 1u); /* FULL */
    le_u64(wire + 8, ref->revision);
    (void)memcpy(wire + 16, ref->secret_ref_digest, 32u);
    ninlil_wifi_sha256(wire, 48u, dig);
    (void)memcpy(wire + 48, dig, 32u);
}

static int decode_nwd1_full(
    const uint8_t wire[NINLIL_WIFI_NWD1_IMAGE_BYTES],
    ninlil_wifi_secret_ref_t *out)
{
    uint8_t dig[32];
    if (wire[0] != (uint8_t)'N' || wire[1] != (uint8_t)'D'
        || wire[2] != (uint8_t)'1' || wire[3] != (uint8_t)'C'
        || rd_u16(wire + 4) != 1u || rd_u16(wire + 6) != 1u) {
        return 0;
    }
    ninlil_wifi_sha256(wire, 48u, dig);
    if (memcmp(dig, wire + 48, 32u) != 0) {
        return 0;
    }
    if (rd_u64(wire + 8) == 0u) {
        return 0;
    }
    (void)memset(out, 0, sizeof(*out));
    out->revision = rd_u64(wire + 8);
    (void)memcpy(out->secret_ref_digest, wire + 16, 32u);
    out->valid = 1u;
    return 1;
}

ninlil_wifi_status_t ninlil_wifi_credential_stage(
    ninlil_wifi_credential_store_t *store,
    const uint8_t secret_ref_digest[32],
    uint64_t revision)
{
    if (store == NULL || secret_ref_digest == NULL || revision == 0u) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (store->committed.valid && revision <= store->committed.revision) {
        return NINLIL_WIFI_FENCED; /* rollback reject */
    }
    (void)memcpy(
        store->staging.secret_ref_digest, secret_ref_digest, 32u);
    store->staging.revision = revision;
    store->staging.valid = 1u;
    store->staging_active = 1u;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_credential_commit(
    ninlil_wifi_credential_store_t *store)
{
    if (store == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (!store->staging_active || !store->staging.valid) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    store->committed = store->staging;
    store->staging_active = 0u;
    (void)memset(&store->staging, 0, sizeof(store->staging));
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_credential_activate(
    ninlil_wifi_credential_store_t *store)
{
    return ninlil_wifi_credential_commit(store);
}

ninlil_wifi_status_t ninlil_wifi_credential_revoke(
    ninlil_wifi_credential_store_t *store)
{
    if (store == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    (void)memset(&store->committed, 0, sizeof(store->committed));
    (void)memset(&store->staging, 0, sizeof(store->staging));
    store->staging_active = 0u;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_credential_rollback_staging(
    ninlil_wifi_credential_store_t *store)
{
    if (store == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    store->staging_active = 0u;
    (void)memset(&store->staging, 0, sizeof(store->staging));
    return NINLIL_WIFI_OK;
}

int ninlil_wifi_credential_is_active(
    const ninlil_wifi_credential_store_t *store)
{
    return store != NULL && store->committed.valid != 0;
}

ninlil_wifi_status_t ninlil_wifi_credential_observe(
    ninlil_wifi_credential_store_t *store,
    const uint8_t secret_ref_digest[32],
    uint64_t revision)
{
    if (store == NULL || secret_ref_digest == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    if (!store->committed.valid) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (revision == store->committed.revision
        && memcmp(
               store->committed.secret_ref_digest, secret_ref_digest, 32u)
            != 0) {
        return NINLIL_WIFI_FENCED;
    }
    if (revision < store->committed.revision) {
        return NINLIL_WIFI_FENCED;
    }
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_credential_bind_storage(
    ninlil_wifi_credential_store_t *store,
    const ninlil_storage_ops_t *storage,
    void *storage_user,
    const char *path_utf8)
{
    size_t n;
    if (store == NULL || storage == NULL || path_utf8 == NULL
        || storage->open == NULL || storage->put == NULL || storage->get == NULL
        || storage->begin == NULL || storage->commit == NULL
        || storage->close == NULL) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    n = strlen(path_utf8);
    if (n == 0u || n >= sizeof(store->path_utf8)) {
        return NINLIL_WIFI_INVALID_ARGUMENT;
    }
    store->storage = storage;
    store->storage_user = storage_user;
    (void)memcpy(store->path_utf8, path_utf8, n + 1u);
    store->durable_bound = 1u;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_status_t ninlil_wifi_credential_durable_put_full(
    ninlil_wifi_credential_store_t *store)
{
    uint8_t wire[NINLIL_WIFI_NWD1_IMAGE_BYTES];
    if (store == NULL || !store->durable_bound || store->storage == NULL) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    if (!store->committed.valid || store->committed.revision == 0u) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    encode_nwd1_full(&store->committed, wire);
    store->last_commit_unknown_class = NINLIL_WIFI_CU_NONE;
    return ninlil_wifi_storage_cu_put_full(
        store->storage,
        store->storage_user,
        store->path_utf8,
        NINLIL_WIFI_NWD1_KEY_COMMITTED,
        wire,
        (uint32_t)sizeof(wire),
        &store->last_commit_unknown_class);
}

ninlil_wifi_status_t ninlil_wifi_credential_durable_reopen(
    ninlil_wifi_credential_store_t *store)
{
    ninlil_storage_handle_t h = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t st;
    uint8_t wire[NINLIL_WIFI_NWD1_IMAGE_BYTES];
    ninlil_bytes_view_t ns;
    ninlil_bytes_view_t key;
    ninlil_mut_bytes_t value;
    ninlil_wifi_secret_ref_t loaded;
    if (store == NULL || !store->durable_bound || store->storage == NULL) {
        return NINLIL_WIFI_INVALID_STATE;
    }
    (void)memset(&store->staging, 0, sizeof(store->staging));
    store->staging_active = 0u;
    (void)memset(&store->committed, 0, sizeof(store->committed));
    ns = bv(store->path_utf8, (uint32_t)strlen(store->path_utf8));
    st = store->storage->open(
        store->storage_user, ns, NINLIL_STORAGE_SCHEMA_M1A, &h);
    if (st != NINLIL_STORAGE_OK) {
        return map_st(st);
    }
    st = store->storage->begin(
        store->storage_user, h, NINLIL_STORAGE_READ_ONLY, &txn);
    if (st != NINLIL_STORAGE_OK) {
        store->storage->close(store->storage_user, h);
        return map_st(st);
    }
    key = bv(
        NINLIL_WIFI_NWD1_KEY_COMMITTED,
        (uint32_t)strlen(NINLIL_WIFI_NWD1_KEY_COMMITTED));
    value.data = wire;
    value.capacity = (uint32_t)sizeof(wire);
    value.length = 0u;
    st = store->storage->get(store->storage_user, txn, key, &value);
    if (store->storage->rollback != NULL) {
        (void)store->storage->rollback(store->storage_user, txn);
    } else if (store->storage->commit != NULL) {
        (void)store->storage->commit(
            store->storage_user, txn, NINLIL_DURABILITY_FULL);
    }
    store->storage->close(store->storage_user, h);
    if (st == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_WIFI_UNAVAILABLE;
    }
    if (st != NINLIL_STORAGE_OK) {
        return map_st(st);
    }
    if (value.length != sizeof(wire) || !decode_nwd1_full(wire, &loaded)) {
        return NINLIL_WIFI_CORRUPT;
    }
    store->committed = loaded;
    return NINLIL_WIFI_OK;
}

ninlil_wifi_cu_class_t
ninlil_wifi_credential_last_commit_unknown_class(
    const ninlil_wifi_credential_store_t *store)
{
    return store == NULL
        ? NINLIL_WIFI_CU_NONE
        : store->last_commit_unknown_class;
}
