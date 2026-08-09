/* SPDX-License-Identifier: Apache-2.0 */
#include "identity_attachment_v1/niaf_owner.h"

#include "domain_store_codec.h"
#include "storage_canonical_plan.h"

#include <limits.h>
#include <stddef.h>
#include <string.h>

#define NIAF_SCHEMA_VERSION ((uint16_t)1u)
#define NIAF_STATE_INITIALIZING ((uint32_t)1u)
#define NIAF_STATE_OPEN ((uint32_t)2u)
#define NIAF_STATE_CLOSING ((uint32_t)3u)
#define NIAF_STATE_CLOSED ((uint32_t)4u)

static const uint8_t niaf_magic[4] = {'N', 'I', 'A', 'F'};
static const uint8_t niaf_key_prefix[8] = {
    0x4eu, 0x49u, 0x41u, 0x46u, 0x2du, 0x4bu, 0x31u, 0x00u
};

static void zero(void *data, size_t size)
{
    volatile uint8_t *cursor = (volatile uint8_t *)data;

    while (size != 0u) {
        *cursor++ = 0u;
        --size;
    }
}

static int nonzero(const uint8_t *value, uint32_t length)
{
    uint32_t index;
    uint8_t combined = 0u;

    for (index = 0u; index < length; ++index) {
        combined |= value[index];
    }
    return combined != 0u;
}

static int all_bytes_equal(const uint8_t *value, uint32_t length, uint8_t expected)
{
    uint32_t index;

    for (index = 0u; index < length; ++index) {
        if (value[index] != expected) {
            return 0;
        }
    }
    return 1;
}

static void put_u16_le(uint8_t *out, uint16_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8u);
}

static void put_u32_le(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8u);
    out[2] = (uint8_t)(value >> 16u);
    out[3] = (uint8_t)(value >> 24u);
}

static void put_u64_le(uint8_t *out, uint64_t value)
{
    uint32_t index;

    for (index = 0u; index < 8u; ++index) {
        out[index] = (uint8_t)(value >> (8u * index));
    }
}

static uint16_t get_u16_le(const uint8_t *in)
{
    return (uint16_t)in[0] | ((uint16_t)in[1] << 8u);
}

static uint32_t get_u32_le(const uint8_t *in)
{
    return (uint32_t)in[0] | ((uint32_t)in[1] << 8u)
        | ((uint32_t)in[2] << 16u) | ((uint32_t)in[3] << 24u);
}

static uint64_t get_u64_le(const uint8_t *in)
{
    uint64_t value = 0u;
    uint32_t index;

    for (index = 0u; index < 8u; ++index) {
        value |= (uint64_t)in[index] << (8u * index);
    }
    return value;
}

static int checkpoint_fields_ok(const ninlil_niaf_floor_checkpoint_v1_t *record,
    int require_generation)
{
    return record != NULL
        && nonzero(record->realm_id, 16u)
        && nonzero(record->runtime_instance_id, 16u)
        && record->runtime_generation != 0u
        && nonzero(record->module_instance_id, 16u)
        && record->module_generation != 0u
        && nonzero(record->provider_instance_id, 16u)
        && record->provider_generation_floor != 0u
        && nonzero(record->stable_identity_id, 16u)
        && record->credential_revision_floor != 0u
        && nonzero(record->membership_authority_id, 16u)
        && record->membership_epoch_floor != 0u
        && nonzero(record->attachment_id, 16u)
        && record->attachment_generation_floor != 0u
        && nonzero(record->session_id, 16u)
        && record->session_generation_floor != 0u
        && nonzero(record->security_context_id, 16u)
        && record->security_epoch_floor != 0u
        && nonzero(record->expiry_authority_id, 16u)
        && record->expiry_epoch_floor != 0u
        && record->invalidation_epoch_floor != 0u
        && record->binding_handle_generation_floor != 0u
        && record->key_generation_floor != 0u
        && (!require_generation || record->checkpoint_generation != 0u);
}

static int checkpoint_shape_ok(const ninlil_niaf_floor_checkpoint_v1_t *record)
{
    return checkpoint_fields_ok(record, 1);
}

static int storage_ops_ok(const ninlil_storage_ops_t *storage)
{
    return storage != NULL
        && storage->abi_version == NINLIL_ABI_VERSION
        && storage->struct_size >= sizeof(*storage)
        && storage->open != NULL && storage->close != NULL
        && storage->begin != NULL && storage->iter_open != NULL
        && storage->iter_next != NULL && storage->iter_close != NULL
        && storage->capacity != NULL && storage->put != NULL
        && storage->erase != NULL && storage->commit != NULL
        && storage->rollback != NULL;
}

static ninlil_status_t storage_status(ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_OK;
    }
    if (status == NINLIL_STORAGE_NO_SPACE) {
        return NINLIL_E_CAPACITY_EXHAUSTED;
    }
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    if (status == NINLIL_STORAGE_UNSUPPORTED_SCHEMA) {
        return NINLIL_E_UNSUPPORTED;
    }
    if (status == NINLIL_STORAGE_CORRUPT
        || status == NINLIL_STORAGE_BUFFER_TOO_SMALL
        || status == NINLIL_STORAGE_NOT_FOUND) {
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (status == NINLIL_STORAGE_BUSY) {
        return NINLIL_E_WOULD_BLOCK;
    }
    if (status == NINLIL_STORAGE_IO_ERROR) {
        return NINLIL_E_STORAGE;
    }
    return NINLIL_E_STORAGE_CORRUPT;
}

static void fence(ninlil_niaf_owner_v1_t *owner)
{
    owner->fenced = 1u;
    owner->has_current = 0u;
    owner->recovery_complete = 0u;
    zero(&owner->current, sizeof(owner->current));
}

static int owner_context_ok(const ninlil_niaf_owner_v1_t *owner,
    uint64_t owner_context_id)
{
    return owner != NULL && owner->state == NIAF_STATE_OPEN
        && owner->owner_context_id == owner_context_id;
}

/* Configured key identity is retained in current even before first recovery. */
static int record_matches_config(const ninlil_niaf_owner_v1_t *owner,
    const ninlil_niaf_floor_checkpoint_v1_t *record)
{
    return checkpoint_fields_ok(record, 0)
        && memcmp(owner->current.realm_id, record->realm_id, 16u) == 0
        && memcmp(owner->current.runtime_instance_id,
            record->runtime_instance_id, 16u) == 0
        && owner->current.runtime_generation == record->runtime_generation
        && memcmp(owner->current.module_instance_id,
            record->module_instance_id, 16u) == 0
        && owner->current.module_generation == record->module_generation;
}

ninlil_status_t ninlil_niaf_floor_checkpoint_v1_key(
    const ninlil_niaf_floor_checkpoint_v1_t *record,
    uint8_t out_key[NINLIL_NIAF_KEY_BYTES])
{
    if (record == NULL || out_key == NULL || !checkpoint_shape_ok(record)) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    (void)memcpy(&out_key[0], niaf_key_prefix, sizeof(niaf_key_prefix));
    (void)memcpy(&out_key[8], record->realm_id, 16u);
    (void)memcpy(&out_key[24], record->runtime_instance_id, 16u);
    put_u64_le(&out_key[40], record->runtime_generation);
    (void)memcpy(&out_key[48], record->module_instance_id, 16u);
    put_u64_le(&out_key[64], record->module_generation);
    return NINLIL_OK;
}

ninlil_status_t ninlil_niaf_floor_checkpoint_v1_encode(
    const ninlil_niaf_floor_checkpoint_v1_t *record,
    uint8_t out_bytes[NINLIL_NIAF_RECORD_BYTES])
{
    ninlil_model_domain_digest_t digest;
    uint32_t crc;

    if (!checkpoint_shape_ok(record) || out_bytes == NULL) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    zero(out_bytes, NINLIL_NIAF_RECORD_BYTES);
    (void)memcpy(&out_bytes[0], niaf_magic, sizeof(niaf_magic));
    put_u16_le(&out_bytes[4], NIAF_SCHEMA_VERSION);
    put_u16_le(&out_bytes[6], NINLIL_NIAF_RECORD_BYTES);
    (void)memcpy(&out_bytes[8], record->realm_id, 16u);
    (void)memcpy(&out_bytes[24], record->runtime_instance_id, 16u);
    put_u64_le(&out_bytes[40], record->runtime_generation);
    (void)memcpy(&out_bytes[48], record->module_instance_id, 16u);
    put_u64_le(&out_bytes[64], record->module_generation);
    (void)memcpy(&out_bytes[72], record->provider_instance_id, 16u);
    put_u64_le(&out_bytes[88], record->provider_generation_floor);
    (void)memcpy(&out_bytes[96], record->stable_identity_id, 16u);
    put_u64_le(&out_bytes[112], record->credential_revision_floor);
    (void)memcpy(&out_bytes[120], record->membership_authority_id, 16u);
    put_u64_le(&out_bytes[136], record->membership_epoch_floor);
    (void)memcpy(&out_bytes[144], record->attachment_id, 16u);
    put_u64_le(&out_bytes[160], record->attachment_generation_floor);
    (void)memcpy(&out_bytes[168], record->session_id, 16u);
    put_u64_le(&out_bytes[184], record->session_generation_floor);
    (void)memcpy(&out_bytes[192], record->security_context_id, 16u);
    put_u64_le(&out_bytes[208], record->security_epoch_floor);
    (void)memcpy(&out_bytes[216], record->expiry_authority_id, 16u);
    put_u64_le(&out_bytes[232], record->expiry_epoch_floor);
    put_u64_le(&out_bytes[240], record->invalidation_epoch_floor);
    put_u64_le(&out_bytes[248], record->binding_handle_generation_floor);
    put_u64_le(&out_bytes[256], record->key_generation_floor);
    put_u64_le(&out_bytes[264], record->checkpoint_generation);
    if (ninlil_model_domain_sha256(out_bytes, 272u, &digest) != NINLIL_OK) {
        zero(out_bytes, NINLIL_NIAF_RECORD_BYTES);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    (void)memcpy(&out_bytes[272], digest.bytes, sizeof(digest.bytes));
    crc = ninlil_model_domain_crc32c(out_bytes, 304u);
    put_u32_le(&out_bytes[304], crc);
    return NINLIL_OK;
}

ninlil_status_t ninlil_niaf_floor_checkpoint_v1_decode(
    const uint8_t bytes[NINLIL_NIAF_RECORD_BYTES],
    ninlil_niaf_floor_checkpoint_v1_t *out_record)
{
    ninlil_model_domain_digest_t digest;
    ninlil_niaf_floor_checkpoint_v1_t record;

    if (bytes == NULL || out_record == NULL
        || memcmp(bytes, niaf_magic, sizeof(niaf_magic)) != 0
        || get_u16_le(&bytes[4]) != NIAF_SCHEMA_VERSION
        || get_u16_le(&bytes[6]) != NINLIL_NIAF_RECORD_BYTES
        || ninlil_model_domain_sha256(bytes, 272u, &digest) != NINLIL_OK
        || memcmp(&bytes[272], digest.bytes, sizeof(digest.bytes)) != 0
        || get_u32_le(&bytes[304]) != ninlil_model_domain_crc32c(bytes, 304u)) {
        if (out_record != NULL) {
            zero(out_record, sizeof(*out_record));
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    zero(&record, sizeof(record));
    (void)memcpy(record.realm_id, &bytes[8], 16u);
    (void)memcpy(record.runtime_instance_id, &bytes[24], 16u);
    record.runtime_generation = get_u64_le(&bytes[40]);
    (void)memcpy(record.module_instance_id, &bytes[48], 16u);
    record.module_generation = get_u64_le(&bytes[64]);
    (void)memcpy(record.provider_instance_id, &bytes[72], 16u);
    record.provider_generation_floor = get_u64_le(&bytes[88]);
    (void)memcpy(record.stable_identity_id, &bytes[96], 16u);
    record.credential_revision_floor = get_u64_le(&bytes[112]);
    (void)memcpy(record.membership_authority_id, &bytes[120], 16u);
    record.membership_epoch_floor = get_u64_le(&bytes[136]);
    (void)memcpy(record.attachment_id, &bytes[144], 16u);
    record.attachment_generation_floor = get_u64_le(&bytes[160]);
    (void)memcpy(record.session_id, &bytes[168], 16u);
    record.session_generation_floor = get_u64_le(&bytes[184]);
    (void)memcpy(record.security_context_id, &bytes[192], 16u);
    record.security_epoch_floor = get_u64_le(&bytes[208]);
    (void)memcpy(record.expiry_authority_id, &bytes[216], 16u);
    record.expiry_epoch_floor = get_u64_le(&bytes[232]);
    record.invalidation_epoch_floor = get_u64_le(&bytes[240]);
    record.binding_handle_generation_floor = get_u64_le(&bytes[248]);
    record.key_generation_floor = get_u64_le(&bytes[256]);
    record.checkpoint_generation = get_u64_le(&bytes[264]);
    if (!checkpoint_shape_ok(&record)) {
        zero(out_record, sizeof(*out_record));
        return NINLIL_E_STORAGE_CORRUPT;
    }
    *out_record = record;
    return NINLIL_OK;
}

static int floors_do_not_regress(
    const ninlil_niaf_floor_checkpoint_v1_t *old,
    const ninlil_niaf_floor_checkpoint_v1_t *next)
{
    return next->provider_generation_floor >= old->provider_generation_floor
        && next->credential_revision_floor >= old->credential_revision_floor
        && next->membership_epoch_floor >= old->membership_epoch_floor
        && next->attachment_generation_floor >= old->attachment_generation_floor
        && next->session_generation_floor >= old->session_generation_floor
        && next->security_epoch_floor >= old->security_epoch_floor
        && next->expiry_epoch_floor >= old->expiry_epoch_floor
        && next->invalidation_epoch_floor >= old->invalidation_epoch_floor
        && next->binding_handle_generation_floor
            >= old->binding_handle_generation_floor
        && next->key_generation_floor >= old->key_generation_floor;
}

static int changed_identity_advances_floor(const uint8_t old_id[16],
    const uint8_t next_id[16], uint64_t old_floor, uint64_t next_floor)
{
    return memcmp(old_id, next_id, 16u) == 0 || next_floor > old_floor;
}

static int changed_identities_advance_floors(
    const ninlil_niaf_floor_checkpoint_v1_t *old,
    const ninlil_niaf_floor_checkpoint_v1_t *next)
{
    return changed_identity_advances_floor(old->provider_instance_id,
            next->provider_instance_id, old->provider_generation_floor,
            next->provider_generation_floor)
        && changed_identity_advances_floor(old->stable_identity_id,
            next->stable_identity_id, old->credential_revision_floor,
            next->credential_revision_floor)
        && changed_identity_advances_floor(old->membership_authority_id,
            next->membership_authority_id, old->membership_epoch_floor,
            next->membership_epoch_floor)
        && changed_identity_advances_floor(old->attachment_id,
            next->attachment_id, old->attachment_generation_floor,
            next->attachment_generation_floor)
        && changed_identity_advances_floor(old->session_id,
            next->session_id, old->session_generation_floor,
            next->session_generation_floor)
        && changed_identity_advances_floor(old->security_context_id,
            next->security_context_id, old->security_epoch_floor,
            next->security_epoch_floor)
        && changed_identity_advances_floor(old->expiry_authority_id,
            next->expiry_authority_id, old->expiry_epoch_floor,
            next->expiry_epoch_floor);
}

static int checkpoint_equal_ignoring_generation(
    const ninlil_niaf_floor_checkpoint_v1_t *left,
    const ninlil_niaf_floor_checkpoint_v1_t *right)
{
    return memcmp(left->realm_id, right->realm_id, 16u) == 0
        && memcmp(left->runtime_instance_id, right->runtime_instance_id, 16u) == 0
        && left->runtime_generation == right->runtime_generation
        && memcmp(left->module_instance_id, right->module_instance_id, 16u) == 0
        && left->module_generation == right->module_generation
        && memcmp(left->provider_instance_id, right->provider_instance_id, 16u) == 0
        && left->provider_generation_floor == right->provider_generation_floor
        && memcmp(left->stable_identity_id, right->stable_identity_id, 16u) == 0
        && left->credential_revision_floor == right->credential_revision_floor
        && memcmp(left->membership_authority_id, right->membership_authority_id, 16u) == 0
        && left->membership_epoch_floor == right->membership_epoch_floor
        && memcmp(left->attachment_id, right->attachment_id, 16u) == 0
        && left->attachment_generation_floor == right->attachment_generation_floor
        && memcmp(left->session_id, right->session_id, 16u) == 0
        && left->session_generation_floor == right->session_generation_floor
        && memcmp(left->security_context_id, right->security_context_id, 16u) == 0
        && left->security_epoch_floor == right->security_epoch_floor
        && memcmp(left->expiry_authority_id, right->expiry_authority_id, 16u) == 0
        && left->expiry_epoch_floor == right->expiry_epoch_floor
        && left->invalidation_epoch_floor == right->invalidation_epoch_floor
        && left->binding_handle_generation_floor == right->binding_handle_generation_floor
        && left->key_generation_floor == right->key_generation_floor;
}

static ninlil_status_t open_exact(ninlil_niaf_owner_v1_t *owner)
{
    ninlil_bytes_view_t locator;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_status_t status;

    locator.data = owner->locator;
    locator.length = owner->locator_length;
    status = owner->storage.open(owner->storage.user, locator, 1u, &handle);
    if ((status == NINLIL_STORAGE_OK) != (handle != NULL)) {
        if (handle != NULL) {
            owner->storage.close(owner->storage.user, handle);
        }
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        return storage_status(status);
    }
    owner->handle = handle;
    return NINLIL_OK;
}

static ninlil_status_t end_read(const ninlil_niaf_owner_v1_t *owner,
    ninlil_storage_txn_t txn)
{
    return storage_status(owner->storage.rollback(owner->storage.user, txn));
}

static int iter_non_ok_shape(ninlil_storage_status_t status,
    const ninlil_mut_bytes_t *key, const ninlil_mut_bytes_t *value)
{
    if (status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        return key->length > key->capacity || value->length > value->capacity;
    }
    return key->length == 0u && value->length == 0u;
}

static ninlil_status_t scan_current(ninlil_niaf_owner_v1_t *owner)
{
    ninlil_mut_bytes_t key_view;
    ninlil_mut_bytes_t value_view;
    ninlil_bytes_view_t prefix;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iterator = NULL;
    ninlil_storage_status_t status;
    ninlil_status_t result;
    uint32_t count = 0u;

    zero(&owner->scratch_record, sizeof(owner->scratch_record));
    status = owner->storage.begin(owner->storage.user, owner->handle,
        NINLIL_STORAGE_READ_ONLY, &txn);
    if ((status == NINLIL_STORAGE_OK) != (txn != NULL)) {
        if (txn != NULL) {
            (void)owner->storage.rollback(owner->storage.user, txn);
        }
        fence(owner);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        fence(owner);
        return storage_status(status);
    }
    prefix.data = NULL;
    prefix.length = 0u;
    status = owner->storage.iter_open(owner->storage.user, txn, prefix, &iterator);
    if ((status == NINLIL_STORAGE_OK) != (iterator != NULL)) {
        if (iterator != NULL) {
            owner->storage.iter_close(owner->storage.user, iterator);
        }
        (void)owner->storage.rollback(owner->storage.user, txn);
        fence(owner);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (status != NINLIL_STORAGE_OK) {
        (void)owner->storage.rollback(owner->storage.user, txn);
        fence(owner);
        return storage_status(status);
    }
    for (count = 0u; count < 2u; ++count) {
        (void)memset(owner->scan_key, 0xa5, sizeof(owner->scan_key));
        (void)memset(owner->scan_value, 0x5a, sizeof(owner->scan_value));
        key_view.data = owner->scan_key;
        key_view.capacity = sizeof(owner->scan_key);
        key_view.length = 0u;
        value_view.data = owner->scan_value;
        value_view.capacity = sizeof(owner->scan_value);
        value_view.length = 0u;
        status = owner->storage.iter_next(owner->storage.user, iterator,
            &key_view, &value_view);
        if (status == NINLIL_STORAGE_NOT_FOUND) {
            if (key_view.length != 0u || value_view.length != 0u
                || !all_bytes_equal(owner->scan_key, sizeof(owner->scan_key), 0xa5)
                || !all_bytes_equal(owner->scan_value,
                    sizeof(owner->scan_value), 0x5a)) {
                owner->storage.iter_close(owner->storage.user, iterator);
                (void)owner->storage.rollback(owner->storage.user, txn);
                fence(owner);
                return NINLIL_E_STORAGE_CORRUPT;
            }
            break;
        }
        if (status != NINLIL_STORAGE_OK) {
            owner->storage.iter_close(owner->storage.user, iterator);
            (void)owner->storage.rollback(owner->storage.user, txn);
            fence(owner);
            return iter_non_ok_shape(status, &key_view, &value_view)
                && all_bytes_equal(owner->scan_key, sizeof(owner->scan_key), 0xa5)
                && all_bytes_equal(owner->scan_value,
                    sizeof(owner->scan_value), 0x5a)
                ? storage_status(status) : NINLIL_E_STORAGE_CORRUPT;
        }
        if (key_view.length != sizeof(owner->scan_key)
            || value_view.length != sizeof(owner->scan_value) || count != 0u) {
            owner->storage.iter_close(owner->storage.user, iterator);
            (void)owner->storage.rollback(owner->storage.user, txn);
            fence(owner);
            return NINLIL_E_STORAGE_CORRUPT;
        }
        if (ninlil_niaf_floor_checkpoint_v1_decode(owner->scan_value,
                &owner->scratch_record) != NINLIL_OK
            || !record_matches_config(owner, &owner->scratch_record)
            || ninlil_niaf_floor_checkpoint_v1_key(&owner->scratch_record,
                owner->scan_expected_key)
                != NINLIL_OK
            || memcmp(owner->scan_key, owner->scan_expected_key,
                sizeof(owner->scan_key)) != 0) {
            owner->storage.iter_close(owner->storage.user, iterator);
            (void)owner->storage.rollback(owner->storage.user, txn);
            fence(owner);
            return NINLIL_E_STORAGE_CORRUPT;
        }
    }
    owner->storage.iter_close(owner->storage.user, iterator);
    result = end_read(owner, txn);
    if (result != NINLIL_OK) {
        fence(owner);
        return result;
    }
    owner->has_current = count == 1u ? 1u : 0u;
    if (owner->has_current != 0u) {
        owner->current = owner->scratch_record;
    }
    owner->recovery_complete = 1u;
    return NINLIL_OK;
}

ninlil_status_t ninlil_niaf_owner_v1_init(
    ninlil_niaf_owner_v1_t *owner,
    const ninlil_niaf_owner_config_v1_t *config)
{
    ninlil_status_t status;

    if (owner != NULL && owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (owner == NULL || config == NULL || config->owner_context_id == 0u
        || !storage_ops_ok(config->storage)
        || config->locator.length == 0u
        || config->locator.length > NINLIL_NIAF_LOCATOR_MAX_BYTES
        || config->locator.data == NULL
        || !nonzero(config->realm_id, 16u)
        || !nonzero(config->runtime_instance_id, 16u)
        || config->runtime_generation == 0u
        || !nonzero(config->module_instance_id, 16u)
        || config->module_generation == 0u) {
        return NINLIL_E_INVALID_ARGUMENT;
    }
    if (owner->state != 0u && owner->state != NIAF_STATE_CLOSED) {
        return NINLIL_E_INVALID_STATE;
    }
    zero(owner, sizeof(*owner));
    owner->storage = *config->storage;
    (void)memcpy(owner->locator, config->locator.data, config->locator.length);
    owner->locator_length = config->locator.length;
    owner->owner_context_id = config->owner_context_id;
    (void)memcpy(owner->current.realm_id, config->realm_id, 16u);
    (void)memcpy(owner->current.runtime_instance_id,
        config->runtime_instance_id, 16u);
    owner->current.runtime_generation = config->runtime_generation;
    (void)memcpy(owner->current.module_instance_id, config->module_instance_id, 16u);
    owner->current.module_generation = config->module_generation;
    owner->state = NIAF_STATE_INITIALIZING;
    owner->in_call = 1u;
    status = open_exact(owner);
    if (status != NINLIL_OK) {
        zero(owner, sizeof(*owner));
    } else {
        owner->in_call = 0u;
        owner->state = NIAF_STATE_OPEN;
    }
    return status;
}

ninlil_status_t ninlil_niaf_owner_v1_recover(
    ninlil_niaf_owner_v1_t *owner,
    uint64_t owner_context_id)
{
    ninlil_status_t status;

    if (owner != NULL && owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (!owner_context_ok(owner, owner_context_id)) {
        return NINLIL_E_WRONG_THREAD;
    }
    if (owner->fenced != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    owner->recovery_complete = 0u;
    owner->in_call = 1u;
    owner->has_current = 0u;
    /* Retain configured key identity while discarding previous value fields. */
    zero(&owner->current.provider_instance_id,
        sizeof(owner->current) - offsetof(ninlil_niaf_floor_checkpoint_v1_t,
            provider_instance_id));
    status = scan_current(owner);
    owner->in_call = 0u;
    return status;
}

static ninlil_status_t recover_after_unknown(ninlil_niaf_owner_v1_t *owner,
    const uint8_t old_bytes[NINLIL_NIAF_RECORD_BYTES], uint32_t had_old,
    const uint8_t new_bytes[NINLIL_NIAF_RECORD_BYTES])
{
    ninlil_status_t status;

    if (owner->handle != NULL) {
        owner->storage.close(owner->storage.user, owner->handle);
    }
    owner->handle = NULL;
    status = open_exact(owner);
    if (status != NINLIL_OK) {
        fence(owner);
        return status;
    }
    status = scan_current(owner);
    if (status != NINLIL_OK) {
        return status;
    }
    if (owner->has_current != 0u
        && ninlil_niaf_floor_checkpoint_v1_encode(&owner->current,
            owner->scan_value)
            == NINLIL_OK
        && memcmp(owner->scan_value, new_bytes, NINLIL_NIAF_RECORD_BYTES) == 0) {
        return NINLIL_OK;
    }
    if ((owner->has_current == 0u && had_old == 0u)
        || (owner->has_current != 0u && had_old != 0u
            && ninlil_niaf_floor_checkpoint_v1_encode(&owner->current,
                owner->scan_value)
                == NINLIL_OK
            && memcmp(owner->scan_value, old_bytes,
                NINLIL_NIAF_RECORD_BYTES) == 0)) {
        return NINLIL_E_STORAGE_COMMIT_UNKNOWN;
    }
    fence(owner);
    return NINLIL_E_STORAGE_CORRUPT;
}

ninlil_status_t ninlil_niaf_owner_v1_checkpoint(
    ninlil_niaf_owner_v1_t *owner,
    uint64_t owner_context_id,
    const ninlil_niaf_floor_checkpoint_v1_t *next)
{
    ninlil_niaf_floor_checkpoint_v1_t *candidate;
    ninlil_storage_canonical_row_t old_row;
    ninlil_storage_canonical_row_t new_row;
    ninlil_storage_canonical_view_t begin_view;
    ninlil_storage_canonical_view_t final_view;
    ninlil_storage_canonical_result_t result;
    uint32_t had_old;
    ninlil_storage_status_t storage_result;
    ninlil_status_t status;

    if (owner != NULL && owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (!owner_context_ok(owner, owner_context_id)) {
        return NINLIL_E_WRONG_THREAD;
    }
    if (owner->fenced != 0u || owner->recovery_complete == 0u
        || !record_matches_config(owner, next)
        || next->checkpoint_generation != 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    if (owner->has_current != 0u
        && (!floors_do_not_regress(&owner->current, next)
            || !changed_identities_advance_floors(&owner->current, next))) {
        fence(owner);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    candidate = &owner->scratch_record;
    *candidate = *next;
    had_old = owner->has_current;
    if (had_old == 0u) {
        candidate->checkpoint_generation = 1u;
    } else if (owner->current.checkpoint_generation == UINT64_MAX) {
        fence(owner);
        return NINLIL_E_STORAGE_CORRUPT;
    } else {
        candidate->checkpoint_generation = owner->current.checkpoint_generation + 1u;
        if (checkpoint_equal_ignoring_generation(&owner->current, candidate)) {
            return NINLIL_OK;
        }
    }
    owner->in_call = 1u;
    zero(owner->old_bytes, sizeof(owner->old_bytes));
    if (had_old != 0u
        && (ninlil_niaf_floor_checkpoint_v1_key(&owner->current, owner->old_key)
                != NINLIL_OK
            || ninlil_niaf_floor_checkpoint_v1_encode(&owner->current,
                owner->old_bytes)
                != NINLIL_OK)) {
        owner->in_call = 0u;
        fence(owner);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    if (ninlil_niaf_floor_checkpoint_v1_key(candidate, owner->new_key) != NINLIL_OK
        || ninlil_niaf_floor_checkpoint_v1_encode(candidate, owner->new_bytes)
            != NINLIL_OK) {
        owner->in_call = 0u;
        fence(owner);
        return NINLIL_E_STORAGE_CORRUPT;
    }
    old_row.key.data = owner->old_key;
    old_row.key.length = sizeof(owner->old_key);
    old_row.value.data = owner->old_bytes;
    old_row.value.length = sizeof(owner->old_bytes);
    new_row.key.data = owner->new_key;
    new_row.key.length = sizeof(owner->new_key);
    new_row.value.data = owner->new_bytes;
    new_row.value.length = sizeof(owner->new_bytes);
    begin_view.rows = had_old != 0u ? &old_row : NULL;
    begin_view.row_count = had_old;
    final_view.rows = &new_row;
    final_view.row_count = 1u;
    storage_result = ninlil_storage_canonical_apply(&owner->storage, owner->handle,
        begin_view, final_view, NULL, NULL, &result);
    if (storage_result == NINLIL_STORAGE_OK) {
        owner->current = *candidate;
        owner->has_current = 1u;
        status = NINLIL_OK;
    } else if (storage_result == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        status = recover_after_unknown(owner, owner->old_bytes, had_old,
            owner->new_bytes);
    } else {
        fence(owner);
        status = storage_status(storage_result);
    }
    owner->in_call = 0u;
    zero(owner->old_bytes, sizeof(owner->old_bytes));
    zero(owner->new_bytes, sizeof(owner->new_bytes));
    return status;
}

ninlil_status_t ninlil_niaf_owner_v1_close(
    ninlil_niaf_owner_v1_t *owner,
    uint64_t owner_context_id)
{
    if (owner != NULL && owner->in_call != 0u) {
        return NINLIL_E_REENTRANT;
    }
    if (!owner_context_ok(owner, owner_context_id)) {
        return NINLIL_E_WRONG_THREAD;
    }
    owner->state = NIAF_STATE_CLOSING;
    owner->in_call = 1u;
    /* platform.close is void; no close-result channel exists to inspect. */
    if (owner->handle != NULL) {
        owner->storage.close(owner->storage.user, owner->handle);
    }
    zero(owner, sizeof(*owner));
    owner->state = NIAF_STATE_CLOSED;
    return NINLIL_OK;
}

uint32_t ninlil_niaf_owner_v1_fenced(const ninlil_niaf_owner_v1_t *owner)
{
    if (owner == NULL || owner->state != NIAF_STATE_OPEN || owner->in_call != 0u) {
        return 1u;
    }
    return owner->fenced != 0u ? 1u : 0u;
}

uint32_t ninlil_niaf_owner_v1_has_current(const ninlil_niaf_owner_v1_t *owner)
{
    return owner != NULL && owner->state == NIAF_STATE_OPEN
        && owner->in_call == 0u && owner->has_current != 0u ? 1u : 0u;
}

ninlil_status_t ninlil_niaf_owner_v1_current(
    const ninlil_niaf_owner_v1_t *owner,
    ninlil_niaf_floor_checkpoint_v1_t *out_current)
{
    if (owner == NULL || out_current == NULL || owner->state != NIAF_STATE_OPEN
        || owner->in_call != 0u || owner->has_current == 0u) {
        return NINLIL_E_INVALID_STATE;
    }
    *out_current = owner->current;
    return NINLIL_OK;
}
