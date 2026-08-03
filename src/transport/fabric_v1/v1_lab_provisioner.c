#include "v1_lab_provisioner.h"

#include "v1_lab_binding.h"

#include "ninlil/version.h"

#include <string.h>

#define V1_LAB_NLB1_KEY_BYTES ((size_t)36u)
#define V1_LAB_N6_RESET_KEY_MAX ((size_t)48u)
#define V1_LAB_N6_RESET_VALUE_MAX ((size_t)128u)
#define V1_LAB_N6_RESET_ROW_MAX ((uint32_t)32u)

static const uint8_t k_lab_namespace[] = {
    'n', 'i', 'n', 'l', 'i', 'l', '.', 'v', '1', '.', 'l', 'a', 'b'};
static const uint8_t k_n6_namespace[] = {
    'n', 'i', 'n', 'l', 'i', 'l', '.', 'n', '6', '.', 'v', '1'};
static const uint8_t k_nlb1_magic[4] = {'N', 'L', 'B', '1'};

static int bytes_nonzero(const uint8_t *bytes, size_t length)
{
    uint8_t any = 0u;
    size_t i;

    if (bytes == NULL) {
        return 0;
    }
    for (i = 0u; i < length; ++i) {
        any = (uint8_t)(any | bytes[i]);
    }
    return any != 0u;
}

static int provisioner_known(const ninlil_v1_lab_provisioner_t *p)
{
    return p != NULL && p->magic == NINLIL_V1_LAB_PROVISIONER_MAGIC
        && p->active != 0u;
}

static int storage_ops_valid(const ninlil_storage_ops_t *ops)
{
    return ops != NULL && ops->abi_version == NINLIL_ABI_VERSION
        && ops->struct_size >= (uint16_t)sizeof(*ops) && ops->open != NULL
        && ops->close != NULL && ops->begin != NULL && ops->get != NULL
        && ops->put != NULL && ops->erase != NULL && ops->iter_open != NULL
        && ops->iter_next != NULL && ops->iter_close != NULL
        && ops->capacity != NULL && ops->commit != NULL
        && ops->rollback != NULL;
}

static int class_d_result_valid(
    const ninlil_r2_authority_clock_result_t *result)
{
    return result != NULL
        && result->typed_class == NINLIL_R2_SAMPLE_TRUSTED_SAME_EPOCH
        && result->sample_fields_valid == 1u
        && result->sample_trust == NINLIL_CLOCK_TRUSTED
        && result->result_catalog == NINLIL_R2_SAMPLE_RESULT_CATALOG_R2_PCP
        && result->exact_status == NINLIL_PCP_OK
        && result->business_mutation == NINLIL_R2_SAMPLE_BUSINESS_ZERO
        && result->durable_meta_mutation == NINLIL_R2_SAMPLE_META_ZERO
        && result->txn_provenance == NINLIL_R2_SAMPLE_PRECHECK_ZERO
        && bytes_nonzero(result->sample_epoch_id, 16u);
}

static ninlil_v1_lab_provision_status_t map_storage_status(
    ninlil_storage_status_t status)
{
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) {
        return NINLIL_V1_LAB_PROVISION_COMMIT_UNKNOWN;
    }
    if (status == NINLIL_STORAGE_NO_SPACE
        || status == NINLIL_STORAGE_BUFFER_TOO_SMALL) {
        return NINLIL_V1_LAB_PROVISION_CAPACITY;
    }
    if (status == NINLIL_STORAGE_IO_ERROR
        || status == NINLIL_STORAGE_BUSY) {
        return NINLIL_V1_LAB_PROVISION_STORAGE;
    }
    return NINLIL_V1_LAB_PROVISION_CORRUPT;
}

static ninlil_v1_lab_provision_status_t map_n6_status(
    ninlil_n6_status_t status)
{
    if (status == NINLIL_N6_OK) {
        return NINLIL_V1_LAB_PROVISION_OK;
    }
    if (status == NINLIL_N6_COMMIT_UNKNOWN) {
        return NINLIL_V1_LAB_PROVISION_COMMIT_UNKNOWN;
    }
    if (status == NINLIL_N6_CAPACITY) {
        return NINLIL_V1_LAB_PROVISION_CAPACITY;
    }
    if (status == NINLIL_N6_STORAGE) {
        return NINLIL_V1_LAB_PROVISION_STORAGE;
    }
    if (status == NINLIL_N6_CRYPTO) {
        return NINLIL_V1_LAB_PROVISION_CRYPTO;
    }
    if (status == NINLIL_N6_M4_REQUIRED) {
        return NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED;
    }
    if (status == NINLIL_N6_CORRUPT) {
        return NINLIL_V1_LAB_PROVISION_CORRUPT;
    }
    if (status == NINLIL_N6_FENCED || status == NINLIL_N6_SHUTDOWN) {
        return NINLIL_V1_LAB_PROVISION_FENCED;
    }
    return NINLIL_V1_LAB_PROVISION_INVALID_STATE;
}

static void provisioner_fence(ninlil_v1_lab_provisioner_t *p)
{
    if (!provisioner_known(p)) {
        return;
    }
    p->fenced = 1u;
    if (p->n6_started != 0u) {
        ninlil_v1_lab_n6_owner_clear(&p->n6_owner);
    } else if (p->n6 != NULL) {
        (void)ninlil_n6_shutdown(p->n6);
    }
    p->n6_started = 0u;
    p->n6 = NULL;
    ninlil_n6_secure_zero(&p->storage, sizeof(p->storage));
    ninlil_n6_secure_zero(&p->n6_crypto, sizeof(p->n6_crypto));
    ninlil_n6_secure_zero(&p->r7_crypto, sizeof(p->r7_crypto));
    ninlil_n6_secure_zero(
        &p->authority_result, sizeof(p->authority_result));
    ninlil_n6_secure_zero(
        p->local_runtime_id, sizeof(p->local_runtime_id));
    ninlil_n6_secure_zero(p->floors, sizeof(p->floors));
    ninlil_n6_secure_zero(p->active_pair_ids, sizeof(p->active_pair_ids));
}

static ninlil_v1_lab_provision_status_t storage_open_exact(
    const ninlil_storage_ops_t *ops,
    const uint8_t *namespace_bytes,
    uint32_t namespace_length,
    ninlil_storage_handle_t *out_handle)
{
    ninlil_bytes_view_t storage_namespace;
    ninlil_storage_status_t status;

    *out_handle = NULL;
    storage_namespace.data = namespace_bytes;
    storage_namespace.length = namespace_length;
    status = ops->open(
        ops->user, storage_namespace, NINLIL_STORAGE_SCHEMA_M1A, out_handle);
    if (status == NINLIL_STORAGE_OK && *out_handle != NULL) {
        return NINLIL_V1_LAB_PROVISION_OK;
    }
    if (*out_handle != NULL) {
        ops->close(ops->user, *out_handle);
        *out_handle = NULL;
        return NINLIL_V1_LAB_PROVISION_CORRUPT;
    }
    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_V1_LAB_PROVISION_CORRUPT;
    }
    return map_storage_status(status);
}

static ninlil_v1_lab_provision_status_t txn_begin_exact(
    const ninlil_storage_ops_t *ops,
    ninlil_storage_handle_t handle,
    ninlil_storage_mode_t mode,
    ninlil_storage_txn_t *out_txn)
{
    ninlil_storage_status_t status;

    *out_txn = NULL;
    status = ops->begin(ops->user, handle, mode, out_txn);
    if (status == NINLIL_STORAGE_OK && *out_txn != NULL) {
        return NINLIL_V1_LAB_PROVISION_OK;
    }
    if (*out_txn != NULL) {
        (void)ops->rollback(ops->user, *out_txn);
        *out_txn = NULL;
        return NINLIL_V1_LAB_PROVISION_CORRUPT;
    }
    if (status == NINLIL_STORAGE_OK) {
        return NINLIL_V1_LAB_PROVISION_CORRUPT;
    }
    return map_storage_status(status);
}

static ninlil_v1_lab_provision_status_t rollback_exact(
    const ninlil_storage_ops_t *ops, ninlil_storage_txn_t txn,
    ninlil_v1_lab_provision_status_t primary)
{
    return ops->rollback(ops->user, txn) == NINLIL_STORAGE_OK
        ? primary
        : NINLIL_V1_LAB_PROVISION_CORRUPT;
}

static int key_compare(
    const uint8_t *a, uint32_t a_length,
    const uint8_t *b, uint32_t b_length)
{
    uint32_t common = a_length < b_length ? a_length : b_length;
    int order = memcmp(a, b, common);
    if (order != 0) {
        return order;
    }
    if (a_length < b_length) {
        return -1;
    }
    return a_length > b_length ? 1 : 0;
}

static int secret_digests(
    const ninlil_n6_crypto_ops_t *crypto,
    const ninlil_v1_lab_binding_t *binding,
    uint8_t out[4][32])
{
    return crypto->sha256(crypto->ctx,
               binding->a_to_b_hop_secret, 32u, out[0])
            == 0
        && crypto->sha256(crypto->ctx,
               binding->a_to_b_e2e_secret, 32u, out[1])
            == 0
        && crypto->sha256(crypto->ctx,
               binding->b_to_a_hop_secret, 32u, out[2])
            == 0
        && crypto->sha256(crypto->ctx,
               binding->b_to_a_e2e_secret, 32u, out[3])
            == 0;
}

static ninlil_v1_lab_provision_status_t scan_floor_namespace(
    ninlil_v1_lab_provisioner_t *p)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_v1_lab_provision_status_t result;
    ninlil_storage_status_t status;
    ninlil_bytes_view_t prefix = {NULL, 0u};
    uint8_t key_bytes[V1_LAB_NLB1_KEY_BYTES];
    uint8_t value_bytes[NINLIL_V1_LAB_BINDING_MAX_BYTES];
    uint8_t previous_key[V1_LAB_NLB1_KEY_BYTES];
    uint32_t previous_length = 0u;
    uint8_t count = 0u;

    result = storage_open_exact(&p->storage, k_lab_namespace,
        (uint32_t)sizeof(k_lab_namespace), &handle);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        return result;
    }
    result = txn_begin_exact(
        &p->storage, handle, NINLIL_STORAGE_READ_ONLY, &txn);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        p->storage.close(p->storage.user, handle);
        return result;
    }
    status = p->storage.iter_open(p->storage.user, txn, prefix, &iter);
    if (status != NINLIL_STORAGE_OK || iter == NULL) {
        if (iter != NULL) {
            p->storage.iter_close(p->storage.user, iter);
            result = NINLIL_V1_LAB_PROVISION_CORRUPT;
        } else {
            result = status == NINLIL_STORAGE_OK
                ? NINLIL_V1_LAB_PROVISION_CORRUPT
                : map_storage_status(status);
        }
        result = rollback_exact(&p->storage, txn, result);
        p->storage.close(p->storage.user, handle);
        return result;
    }

    result = NINLIL_V1_LAB_PROVISION_OK;
    for (;;) {
        ninlil_mut_bytes_t key;
        ninlil_mut_bytes_t value;
        ninlil_v1_lab_binding_t binding;
        uint8_t local_side = 0u;
        uint8_t i;

        (void)memset(key_bytes, 0, sizeof(key_bytes));
        (void)memset(value_bytes, 0, sizeof(value_bytes));
        key.data = key_bytes;
        key.capacity = (uint32_t)sizeof(key_bytes);
        key.length = 0u;
        value.data = value_bytes;
        value.capacity = (uint32_t)sizeof(value_bytes);
        value.length = 0u;
        status = p->storage.iter_next(p->storage.user, iter, &key, &value);
        if (key.data != key_bytes || value.data != value_bytes
            || key.capacity != sizeof(key_bytes)
            || value.capacity != sizeof(value_bytes)) {
            result = NINLIL_V1_LAB_PROVISION_CORRUPT;
            break;
        }
        if (status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                result = NINLIL_V1_LAB_PROVISION_CORRUPT;
            }
            break;
        }
        if (status != NINLIL_STORAGE_OK
            || key.length != V1_LAB_NLB1_KEY_BYTES
            || value.length < NINLIL_V1_LAB_BINDING_MIN_BYTES
            || value.length > NINLIL_V1_LAB_BINDING_MAX_BYTES
            || count >= NINLIL_V1_LAB_FLOOR_MAX
            || memcmp(key.data, k_nlb1_magic, sizeof(k_nlb1_magic)) != 0
            || (previous_length != 0u
                && key_compare(previous_key, previous_length,
                       key.data, key.length)
                    >= 0)) {
            result = (status == NINLIL_STORAGE_IO_ERROR
                         || status == NINLIL_STORAGE_BUSY)
                    && key.length == 0u && value.length == 0u
                ? NINLIL_V1_LAB_PROVISION_STORAGE
                : NINLIL_V1_LAB_PROVISION_CORRUPT;
            break;
        }
        (void)memset(&binding, 0, sizeof(binding));
        if (ninlil_v1_lab_binding_decode(&p->r7_crypto,
                value.data, value.length, &binding)
                != NINLIL_V1_LAB_BINDING_OK
            || (p->local_runtime_bound != 0u
                && ninlil_v1_lab_binding_local_side(
                       &binding, p->local_runtime_id, &local_side)
                    != NINLIL_V1_LAB_BINDING_OK)
            || (p->local_runtime_bound == 0u
                && p->runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_NONE)
            || memcmp(key.data + 4u, binding.pair_id, 32u) != 0) {
            ninlil_v1_lab_binding_clear(&binding);
            result = NINLIL_V1_LAB_PROVISION_CORRUPT;
            break;
        }
        for (i = 0u; i < count; ++i) {
            if (memcmp(p->floors[i].pair_id, binding.pair_id, 32u) == 0) {
                result = NINLIL_V1_LAB_PROVISION_CORRUPT;
                break;
            }
        }
        if (result == NINLIL_V1_LAB_PROVISION_OK
            && !secret_digests(&p->n6_crypto, &binding,
                p->floors[count].secret_digests)) {
            result = NINLIL_V1_LAB_PROVISION_CRYPTO;
        }
        if (result != NINLIL_V1_LAB_PROVISION_OK) {
            ninlil_v1_lab_binding_clear(&binding);
            break;
        }
        p->floors[count].occupied = 1u;
        (void)memcpy(
            p->floors[count].pair_id, binding.pair_id, 32u);
        p->floors[count].pair_generation = binding.pair_generation;
        p->floors[count].radio_membership_epoch =
            binding.radio_membership_epoch;
        if (binding.radio_membership_epoch > p->global_membership_floor) {
            p->global_membership_floor = binding.radio_membership_epoch;
        }
        (void)memcpy(previous_key, key.data, key.length);
        previous_length = key.length;
        count += 1u;
        ninlil_v1_lab_binding_clear(&binding);
    }
    p->storage.iter_close(p->storage.user, iter);
    result = rollback_exact(&p->storage, txn, result);
    p->storage.close(p->storage.user, handle);
    ninlil_n6_secure_zero(key_bytes, sizeof(key_bytes));
    ninlil_n6_secure_zero(value_bytes, sizeof(value_bytes));
    ninlil_n6_secure_zero(previous_key, sizeof(previous_key));
    if (result == NINLIL_V1_LAB_PROVISION_OK) {
        p->floor_count = count;
    }
    return result;
}

static ninlil_v1_lab_provision_status_t reset_n6_namespace(
    ninlil_v1_lab_provisioner_t *p)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_iter_t iter = NULL;
    ninlil_v1_lab_provision_status_t result;
    ninlil_storage_status_t status;
    ninlil_bytes_view_t prefix = {NULL, 0u};
    /* One extra slot proves that an exact 32-row namespace has ended. */
    uint8_t keys[V1_LAB_N6_RESET_ROW_MAX + 1u]
        [V1_LAB_N6_RESET_KEY_MAX];
    uint32_t key_lengths[V1_LAB_N6_RESET_ROW_MAX];
    uint8_t value_bytes[V1_LAB_N6_RESET_VALUE_MAX];
    uint32_t count = 0u;
    uint32_t i;

    (void)memset(keys, 0, sizeof(keys));
    (void)memset(key_lengths, 0, sizeof(key_lengths));
    result = storage_open_exact(&p->storage, k_n6_namespace,
        (uint32_t)sizeof(k_n6_namespace), &handle);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        return result;
    }
    result = txn_begin_exact(
        &p->storage, handle, NINLIL_STORAGE_READ_WRITE, &txn);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        p->storage.close(p->storage.user, handle);
        return result;
    }
    status = p->storage.iter_open(p->storage.user, txn, prefix, &iter);
    if (status != NINLIL_STORAGE_OK || iter == NULL) {
        if (iter != NULL) {
            p->storage.iter_close(p->storage.user, iter);
            result = NINLIL_V1_LAB_PROVISION_CORRUPT;
        } else {
            result = status == NINLIL_STORAGE_OK
                ? NINLIL_V1_LAB_PROVISION_CORRUPT
                : map_storage_status(status);
        }
        result = rollback_exact(&p->storage, txn, result);
        p->storage.close(p->storage.user, handle);
        return result;
    }
    result = NINLIL_V1_LAB_PROVISION_OK;
    for (;;) {
        ninlil_mut_bytes_t key;
        ninlil_mut_bytes_t value;

        (void)memset(value_bytes, 0, sizeof(value_bytes));
        key.data = keys[count];
        key.capacity = (uint32_t)sizeof(keys[count]);
        key.length = 0u;
        value.data = value_bytes;
        value.capacity = (uint32_t)sizeof(value_bytes);
        value.length = 0u;
        status = p->storage.iter_next(p->storage.user, iter, &key, &value);
        if (key.data != keys[count] || value.data != value_bytes
            || key.capacity != sizeof(keys[count])
            || value.capacity != sizeof(value_bytes)) {
            result = NINLIL_V1_LAB_PROVISION_CORRUPT;
            break;
        }
        if (status == NINLIL_STORAGE_NOT_FOUND) {
            if (key.length != 0u || value.length != 0u) {
                result = NINLIL_V1_LAB_PROVISION_CORRUPT;
            }
            break;
        }
        if (status != NINLIL_STORAGE_OK || key.length == 0u
            || key.length > sizeof(keys[count])
            || value.length > sizeof(value_bytes)
            || count >= V1_LAB_N6_RESET_ROW_MAX
            || (count != 0u
                && key_compare(keys[count - 1u], key_lengths[count - 1u],
                       keys[count], key.length)
                    >= 0)) {
            result = (status == NINLIL_STORAGE_IO_ERROR
                         || status == NINLIL_STORAGE_BUSY)
                    && key.length == 0u && value.length == 0u
                ? NINLIL_V1_LAB_PROVISION_STORAGE
                : NINLIL_V1_LAB_PROVISION_CORRUPT;
            break;
        }
        key_lengths[count] = key.length;
        count += 1u;
    }
    p->storage.iter_close(p->storage.user, iter);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        result = rollback_exact(&p->storage, txn, result);
        p->storage.close(p->storage.user, handle);
        ninlil_n6_secure_zero(keys, sizeof(keys));
        ninlil_n6_secure_zero(value_bytes, sizeof(value_bytes));
        return result;
    }
    for (i = 0u; i < count; ++i) {
        ninlil_bytes_view_t key = {keys[i], key_lengths[i]};
        status = p->storage.erase(p->storage.user, txn, key);
        if (status != NINLIL_STORAGE_OK) {
            result = map_storage_status(status);
            result = rollback_exact(&p->storage, txn, result);
            p->storage.close(p->storage.user, handle);
            ninlil_n6_secure_zero(keys, sizeof(keys));
            ninlil_n6_secure_zero(value_bytes, sizeof(value_bytes));
            return result;
        }
    }
    status = p->storage.commit(
        p->storage.user, txn, NINLIL_DURABILITY_FULL);
    p->storage.close(p->storage.user, handle);
    ninlil_n6_secure_zero(keys, sizeof(keys));
    ninlil_n6_secure_zero(value_bytes, sizeof(value_bytes));
    return status == NINLIL_STORAGE_OK
        ? NINLIL_V1_LAB_PROVISION_OK
        : map_storage_status(status);
}

static ninlil_v1_lab_provision_status_t persist_binding(
    ninlil_v1_lab_provisioner_t *p,
    const ninlil_v1_lab_binding_t *binding,
    const uint8_t *encoded,
    size_t encoded_length)
{
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_v1_lab_provision_status_t result;
    ninlil_storage_status_t status;
    uint8_t key_bytes[V1_LAB_NLB1_KEY_BYTES];
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t value;

    (void)memcpy(key_bytes, k_nlb1_magic, sizeof(k_nlb1_magic));
    (void)memcpy(key_bytes + 4u, binding->pair_id, 32u);
    key.data = key_bytes;
    key.length = (uint32_t)sizeof(key_bytes);
    value.data = encoded;
    value.length = (uint32_t)encoded_length;
    result = storage_open_exact(&p->storage, k_lab_namespace,
        (uint32_t)sizeof(k_lab_namespace), &handle);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        ninlil_n6_secure_zero(key_bytes, sizeof(key_bytes));
        return result;
    }
    result = txn_begin_exact(
        &p->storage, handle, NINLIL_STORAGE_READ_WRITE, &txn);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        p->storage.close(p->storage.user, handle);
        ninlil_n6_secure_zero(key_bytes, sizeof(key_bytes));
        return result;
    }
    status = p->storage.put(p->storage.user, txn, key, value);
    if (status != NINLIL_STORAGE_OK) {
        result = map_storage_status(status);
        result = rollback_exact(&p->storage, txn, result);
        p->storage.close(p->storage.user, handle);
        ninlil_n6_secure_zero(key_bytes, sizeof(key_bytes));
        return result;
    }
    status = p->storage.commit(
        p->storage.user, txn, NINLIL_DURABILITY_FULL);
    p->storage.close(p->storage.user, handle);
    ninlil_n6_secure_zero(key_bytes, sizeof(key_bytes));
    return status == NINLIL_STORAGE_OK
        ? NINLIL_V1_LAB_PROVISION_OK
        : map_storage_status(status);
}

static int find_floor(
    const ninlil_v1_lab_provisioner_t *p, const uint8_t pair_id[32])
{
    uint8_t i;
    for (i = 0u; i < p->floor_count; ++i) {
        if (p->floors[i].occupied != 0u
            && memcmp(p->floors[i].pair_id, pair_id, 32u) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int pair_is_active(
    const ninlil_v1_lab_provisioner_t *p, const uint8_t pair_id[32])
{
    uint8_t i;
    for (i = 0u; i < p->active_pair_count; ++i) {
        if (memcmp(p->active_pair_ids[i], pair_id, 32u) == 0) {
            return 1;
        }
    }
    return 0;
}

static ninlil_v1_lab_provision_status_t provisioner_init_common(
    ninlil_v1_lab_provisioner_t *p,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const uint8_t local_runtime_id[16],
    const ninlil_r2_authority_clock_result_t *authority_result,
    uint8_t runtime_adopt_mode)
{
    ninlil_v1_lab_provision_status_t result;

    if (p == NULL || n6 == NULL || !storage_ops_valid(storage)
        || n6_crypto == NULL || n6_crypto->sha256 == NULL
        || n6_crypto->hkdf_sha256 == NULL || r7_crypto == NULL
        || ninlil_r7_crypto_provider_validate(r7_crypto)
            != NINLIL_R7_CRYPTO_OK
        || (runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_NONE
            && !bytes_nonzero(local_runtime_id, 16u))
        || (runtime_adopt_mode != NINLIL_V1_LAB_ADOPT_NONE
            && runtime_adopt_mode != NINLIL_V1_LAB_ADOPT_CONTROLLER
            && runtime_adopt_mode != NINLIL_V1_LAB_ADOPT_PEER)
        || (runtime_adopt_mode != NINLIL_V1_LAB_ADOPT_NONE
            && local_runtime_id != NULL)
        || !class_d_result_valid(authority_result)
        || ninlil_n6_state(n6) != NINLIL_N6_STATE_INIT) {
        return NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT;
    }
    (void)memset(p, 0, sizeof(*p));
    p->magic = NINLIL_V1_LAB_PROVISIONER_MAGIC;
    p->active = 1u;
    p->n6 = n6;
    p->storage = *storage;
    p->n6_crypto = *n6_crypto;
    p->r7_crypto = *r7_crypto;
    p->authority_result = *authority_result;
    p->runtime_adopt_mode = runtime_adopt_mode;
    if (local_runtime_id != NULL) {
        (void)memcpy(p->local_runtime_id, local_runtime_id, 16u);
        p->local_runtime_bound = 1u;
    }
    result = scan_floor_namespace(p);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        provisioner_fence(p);
        return result;
    }
    return NINLIL_V1_LAB_PROVISION_OK;
}

ninlil_v1_lab_provision_status_t ninlil_v1_lab_provisioner_init(
    ninlil_v1_lab_provisioner_t *p,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const uint8_t local_runtime_id[16],
    const ninlil_r2_authority_clock_result_t *authority_result)
{
    return provisioner_init_common(p, n6, storage, n6_crypto, r7_crypto,
        local_runtime_id, authority_result, NINLIL_V1_LAB_ADOPT_NONE);
}

ninlil_v1_lab_provision_status_t
ninlil_v1_lab_provisioner_init_controller(
    ninlil_v1_lab_provisioner_t *p,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const ninlil_r2_authority_clock_result_t *authority_result)
{
    return provisioner_init_common(p, n6, storage, n6_crypto, r7_crypto,
        NULL, authority_result, NINLIL_V1_LAB_ADOPT_CONTROLLER);
}

ninlil_v1_lab_provision_status_t ninlil_v1_lab_provisioner_init_peer(
    ninlil_v1_lab_provisioner_t *p,
    ninlil_n6_t *n6,
    const ninlil_storage_ops_t *storage,
    const ninlil_n6_crypto_ops_t *n6_crypto,
    const ninlil_r7_crypto_provider *r7_crypto,
    const ninlil_r2_authority_clock_result_t *authority_result)
{
    return provisioner_init_common(p, n6, storage, n6_crypto, r7_crypto,
        NULL, authority_result, NINLIL_V1_LAB_ADOPT_PEER);
}

ninlil_v1_lab_provision_status_t ninlil_v1_lab_provisioner_install_pair(
    ninlil_v1_lab_provisioner_t *p,
    const uint8_t *encoded_binding,
    size_t encoded_length,
    ninlil_v1_lab_n6_handles_t *out_handles)
{
    ninlil_v1_lab_binding_t binding;
    ninlil_v1_lab_n6_handles_t handles;
    ninlil_v1_lab_provision_status_t result;
    ninlil_n6_status_t n6_status;
    uint8_t digests[4][32];
    uint8_t candidate_local_runtime_id[16];
    uint8_t local_side = 0u;
    uint8_t local_controller;
    uint8_t adopt_local_runtime = 0u;
    uint8_t active_max;
    int floor_index;
    uint8_t i;

    if (out_handles != NULL) {
        (void)memset(out_handles, 0, sizeof(*out_handles));
    }
    if (!provisioner_known(p) || encoded_binding == NULL
        || out_handles == NULL) {
        return NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT;
    }
    if (p->fenced != 0u) {
        return NINLIL_V1_LAB_PROVISION_FENCED;
    }
    (void)memset(&binding, 0, sizeof(binding));
    (void)memset(&handles, 0, sizeof(handles));
    (void)memset(digests, 0, sizeof(digests));
    (void)memset(candidate_local_runtime_id, 0,
        sizeof(candidate_local_runtime_id));
    if (ninlil_v1_lab_binding_decode(&p->r7_crypto,
            encoded_binding, encoded_length, &binding)
            != NINLIL_V1_LAB_BINDING_OK) {
        ninlil_v1_lab_binding_clear(&binding);
        ninlil_n6_secure_zero(digests, sizeof(digests));
        return NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT;
    }
    if (p->local_runtime_bound != 0u) {
        if (ninlil_v1_lab_binding_local_side(
                &binding, p->local_runtime_id, &local_side)
            != NINLIL_V1_LAB_BINDING_OK) {
            ninlil_v1_lab_binding_clear(&binding);
            ninlil_n6_secure_zero(digests, sizeof(digests));
            return NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT;
        }
        (void)memcpy(candidate_local_runtime_id,
            p->local_runtime_id, sizeof(candidate_local_runtime_id));
    } else if (p->runtime_adopt_mode != NINLIL_V1_LAB_ADOPT_NONE
        && p->active_pair_count == 0u && p->mode_fixed == 0u) {
        local_side = p->runtime_adopt_mode == NINLIL_V1_LAB_ADOPT_CONTROLLER
            ? binding.controller_side
            : (binding.controller_side == NINLIL_V1_LAB_SIDE_A
                    ? NINLIL_V1_LAB_SIDE_B
                    : NINLIL_V1_LAB_SIDE_A);
        (void)memcpy(candidate_local_runtime_id,
            local_side == NINLIL_V1_LAB_SIDE_A
                ? binding.endpoint_a.runtime_id
                : binding.endpoint_b.runtime_id,
            sizeof(candidate_local_runtime_id));
        adopt_local_runtime = 1u;
    } else {
        ninlil_v1_lab_binding_clear(&binding);
        ninlil_n6_secure_zero(digests, sizeof(digests));
        return NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT;
    }
    if (memcmp(local_side == NINLIL_V1_LAB_SIDE_A
                    ? binding.endpoint_a.clock_epoch_id
                    : binding.endpoint_b.clock_epoch_id,
               p->authority_result.sample_epoch_id, 16u)
            != 0
        || !secret_digests(&p->n6_crypto, &binding, digests)) {
        ninlil_v1_lab_binding_clear(&binding);
        ninlil_n6_secure_zero(digests, sizeof(digests));
        return NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT;
    }
    if (pair_is_active(p, binding.pair_id)) {
        ninlil_v1_lab_binding_clear(&binding);
        ninlil_n6_secure_zero(digests, sizeof(digests));
        return NINLIL_V1_LAB_PROVISION_INVALID_STATE;
    }
    if (binding.pair_generation == UINT32_MAX) {
        result = NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED;
        goto reject;
    }
    floor_index = find_floor(p, binding.pair_id);
    if (floor_index >= 0) {
        const ninlil_v1_lab_floor_record_t *floor =
            &p->floors[(uint8_t)floor_index];
        if (binding.pair_generation <= floor->pair_generation) {
            result = NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED;
            goto reject;
        }
        for (i = 0u; i < 4u; ++i) {
            if (memcmp(digests[i], floor->secret_digests[i], 32u) == 0) {
                result = NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED;
                goto reject;
            }
        }
    } else if (p->floor_count >= NINLIL_V1_LAB_FLOOR_MAX) {
        provisioner_fence(p);
        result = NINLIL_V1_LAB_PROVISION_CAPACITY;
        goto reject;
    }
    if ((p->active_pair_count == 0u
            && binding.radio_membership_epoch
                <= p->global_membership_floor)
        || (p->active_pair_count != 0u
            && binding.radio_membership_epoch
                != p->boot_radio_membership_epoch)) {
        result = NINLIL_V1_LAB_PROVISION_REPROVISION_REQUIRED;
        goto reject;
    }
    local_controller = binding.controller_side == local_side ? 1u : 0u;
    if (p->mode_fixed != 0u
        && p->local_controller_mode != local_controller) {
        result = NINLIL_V1_LAB_PROVISION_INVALID_ARGUMENT;
        goto reject;
    }
    active_max = local_controller != 0u ? 2u : 1u;
    if (p->active_pair_count >= active_max) {
        result = NINLIL_V1_LAB_PROVISION_CAPACITY;
        goto reject;
    }

    if (p->n6_reset_done == 0u) {
        result = reset_n6_namespace(p);
        if (result != NINLIL_V1_LAB_PROVISION_OK) {
            provisioner_fence(p);
            goto reject;
        }
        p->n6_reset_done = 1u;
        n6_status = ninlil_v1_lab_n6_owner_init(&p->n6_owner, p->n6,
            &p->storage, &p->n6_crypto, &p->r7_crypto,
            candidate_local_runtime_id);
        p->last_n6_status = n6_status;
        if (n6_status != NINLIL_N6_OK) {
            result = map_n6_status(n6_status);
            provisioner_fence(p);
            goto reject;
        }
        p->n6_started = 1u;
        n6_status = ninlil_v1_lab_n6_owner_boot_from_class_d(
            &p->n6_owner, &p->authority_result);
        p->last_n6_status = n6_status;
        if (n6_status != NINLIL_N6_OK) {
            result = map_n6_status(n6_status);
            provisioner_fence(p);
            goto reject;
        }
        p->boot_radio_membership_epoch =
            binding.radio_membership_epoch;
        p->local_controller_mode = local_controller;
        p->mode_fixed = 1u;
    }
    n6_status = ninlil_v1_lab_n6_owner_install_pair(&p->n6_owner,
        encoded_binding, encoded_length, &handles);
    p->last_n6_status = n6_status;
    if (n6_status != NINLIL_N6_OK) {
        result = map_n6_status(n6_status);
        provisioner_fence(p);
        goto reject;
    }
    result = persist_binding(p, &binding, encoded_binding, encoded_length);
    if (result != NINLIL_V1_LAB_PROVISION_OK) {
        provisioner_fence(p);
        goto reject;
    }

    if (floor_index < 0) {
        floor_index = (int)p->floor_count;
        p->floor_count += 1u;
    }
    p->floors[(uint8_t)floor_index].occupied = 1u;
    (void)memcpy(p->floors[(uint8_t)floor_index].pair_id,
        binding.pair_id, 32u);
    p->floors[(uint8_t)floor_index].pair_generation =
        binding.pair_generation;
    p->floors[(uint8_t)floor_index].radio_membership_epoch =
        binding.radio_membership_epoch;
    (void)memcpy(p->floors[(uint8_t)floor_index].secret_digests,
        digests, sizeof(digests));
    if (binding.radio_membership_epoch > p->global_membership_floor) {
        p->global_membership_floor = binding.radio_membership_epoch;
    }
    (void)memcpy(p->active_pair_ids[p->active_pair_count],
        binding.pair_id, 32u);
    p->active_pair_count += 1u;
    if (adopt_local_runtime != 0u) {
        (void)memcpy(p->local_runtime_id, candidate_local_runtime_id,
            sizeof(p->local_runtime_id));
        p->local_runtime_bound = 1u;
    }
    *out_handles = handles;
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_n6_secure_zero(digests, sizeof(digests));
    return NINLIL_V1_LAB_PROVISION_OK;

reject:
    ninlil_v1_lab_binding_clear(&binding);
    ninlil_n6_secure_zero(digests, sizeof(digests));
    return result;
}

int ninlil_v1_lab_provisioner_is_fenced(
    const ninlil_v1_lab_provisioner_t *p)
{
    return provisioner_known(p) && p->fenced != 0u ? 1 : 0;
}

void ninlil_v1_lab_provisioner_clear(
    ninlil_v1_lab_provisioner_t *p)
{
    if (p == NULL) {
        return;
    }
    if (provisioner_known(p)) {
        if (p->n6_started != 0u) {
            ninlil_v1_lab_n6_owner_clear(&p->n6_owner);
        } else if (p->n6 != NULL) {
            (void)ninlil_n6_shutdown(p->n6);
        }
    }
    ninlil_n6_secure_zero(p, sizeof(*p));
}
