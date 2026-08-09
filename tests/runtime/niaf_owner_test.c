/* SPDX-License-Identifier: Apache-2.0 */
#include "identity_attachment_v1/niaf_owner.h"
#include "in_memory_storage.h"

#include <stdio.h>
#include <string.h>

#define REQUIRE(condition) do { \
    if (!(condition)) { \
        (void)fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        return 1; \
    } \
} while (0)

static void id(uint8_t out[16], uint8_t first)
{
    uint32_t index;
    for (index = 0u; index < 16u; ++index) {
        out[index] = (uint8_t)(first + index);
    }
}

static ninlil_niaf_owner_config_v1_t config(ninlil_test_storage_t *storage)
{
    static const uint8_t locator[] = {'r', 'e', 'a', 'l', 'm', '/', 'a'};
    ninlil_niaf_owner_config_v1_t result;

    (void)memset(&result, 0, sizeof(result));
    result.owner_context_id = 77u;
    result.storage = ninlil_test_storage_ops(storage);
    result.locator.data = locator;
    result.locator.length = sizeof(locator);
    id(result.realm_id, 1u);
    id(result.runtime_instance_id, 21u);
    result.runtime_generation = 3u;
    id(result.module_instance_id, 41u);
    result.module_generation = 5u;
    return result;
}

static ninlil_niaf_floor_checkpoint_v1_t record(void)
{
    ninlil_niaf_floor_checkpoint_v1_t value;

    (void)memset(&value, 0, sizeof(value));
    id(value.realm_id, 1u);
    id(value.runtime_instance_id, 21u);
    value.runtime_generation = 3u;
    id(value.module_instance_id, 41u);
    value.module_generation = 5u;
    id(value.provider_instance_id, 61u);
    value.provider_generation_floor = 7u;
    id(value.stable_identity_id, 81u);
    value.credential_revision_floor = 11u;
    id(value.membership_authority_id, 101u);
    value.membership_epoch_floor = 13u;
    id(value.attachment_id, 121u);
    value.attachment_generation_floor = 17u;
    id(value.session_id, 141u);
    value.session_generation_floor = 19u;
    id(value.security_context_id, 161u);
    value.security_epoch_floor = 23u;
    id(value.expiry_authority_id, 181u);
    value.expiry_epoch_floor = 29u;
    value.invalidation_epoch_floor = 31u;
    value.binding_handle_generation_floor = 37u;
    value.key_generation_floor = 41u;
    return value;
}

static int preload(ninlil_test_storage_t *storage,
    const ninlil_niaf_owner_config_v1_t *cfg,
    ninlil_bytes_view_t key, ninlil_bytes_view_t value)
{
    const ninlil_storage_ops_t *ops = ninlil_test_storage_ops(storage);
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    ninlil_storage_status_t status;

    status = ops->open(ops->user, cfg->locator, 1u, &handle);
    if (status != NINLIL_STORAGE_OK || handle == NULL) { return 0; }
    status = ops->begin(ops->user, handle, NINLIL_STORAGE_READ_WRITE, &txn);
    if (status == NINLIL_STORAGE_OK && txn != NULL) {
        status = ops->put(ops->user, txn, key, value);
        if (status == NINLIL_STORAGE_OK) {
            status = ops->commit(ops->user, txn, NINLIL_DURABILITY_FULL);
        } else {
            (void)ops->rollback(ops->user, txn);
        }
    }
    ops->close(ops->user, handle);
    return status == NINLIL_STORAGE_OK;
}

/* Test-only intercept: it never enters the Runtime source authority. */
typedef struct unknown_wrapper {
    ninlil_storage_ops_t ops;
    const ninlil_storage_ops_t *base;
    ninlil_niaf_owner_config_v1_t reentry_config;
    ninlil_bytes_view_t locator;
    ninlil_bytes_view_t third_key;
    ninlil_bytes_view_t third_value;
    ninlil_niaf_owner_v1_t *reentry_owner;
    const ninlil_niaf_floor_checkpoint_v1_t *reentry_value;
    uint64_t reentry_context;
    ninlil_status_t reentry_result;
    ninlil_niaf_owner_v1_t *lifecycle_owner;
    uint64_t lifecycle_context;
    ninlil_status_t open_reentry_result;
    ninlil_status_t close_reentry_result;
    ninlil_status_t init_reentry_result;
    ninlil_status_t accessor_current_result;
    ninlil_niaf_floor_checkpoint_v1_t accessor_current;
    ninlil_storage_status_t open_forced_status;
    ninlil_storage_status_t iter_forced_status;
    uint32_t inject_after_unknown;
    uint32_t reentry_armed;
    uint32_t open_reentry_armed;
    uint32_t close_reentry_armed;
    uint32_t init_reentry_armed;
    uint32_t open_forced_armed;
    uint32_t accessor_armed;
    uint32_t accessor_has_current;
    uint32_t accessor_fenced;
    uint32_t iter_forced_armed;
    uint32_t iter_poison_lengths;
    uint32_t iter_poison_data;
} unknown_wrapper_t;

static ninlil_storage_status_t wrapper_open(void *user, ninlil_bytes_view_t n,
    uint32_t schema, ninlil_storage_handle_t *out)
{
    unknown_wrapper_t *w = user;
    ninlil_storage_status_t status;

    if (w->open_forced_armed != 0u) {
        w->open_forced_armed = 0u;
        return w->open_forced_status;
    }
    status = w->base->open(w->base->user, n, schema, out);
    if (w->init_reentry_armed != 0u) {
        w->init_reentry_armed = 0u;
        w->init_reentry_result = ninlil_niaf_owner_v1_init(w->lifecycle_owner,
            &w->reentry_config);
    }
    if (w->open_reentry_armed != 0u) {
        w->open_reentry_armed = 0u;
        w->open_reentry_result = ninlil_niaf_owner_v1_close(w->lifecycle_owner,
            w->lifecycle_context);
    }
    return status;
}
static ninlil_storage_status_t wrapper_begin(void *user, ninlil_storage_handle_t h,
    ninlil_storage_mode_t m, ninlil_storage_txn_t *out)
{ unknown_wrapper_t *w = user; return w->base->begin(w->base->user, h, m, out); }
static ninlil_storage_status_t wrapper_get(void *user, ninlil_storage_txn_t t,
    ninlil_bytes_view_t k, ninlil_mut_bytes_t *v)
{ unknown_wrapper_t *w = user; return w->base->get(w->base->user, t, k, v); }
static ninlil_storage_status_t wrapper_put(void *user, ninlil_storage_txn_t t,
    ninlil_bytes_view_t k, ninlil_bytes_view_t v)
{ unknown_wrapper_t *w = user; return w->base->put(w->base->user, t, k, v); }
static ninlil_storage_status_t wrapper_erase(void *user, ninlil_storage_txn_t t,
    ninlil_bytes_view_t k)
{ unknown_wrapper_t *w = user; return w->base->erase(w->base->user, t, k); }
static ninlil_storage_status_t wrapper_iter_open(void *user, ninlil_storage_txn_t t,
    ninlil_bytes_view_t p, ninlil_storage_iter_t *out)
{ unknown_wrapper_t *w = user; return w->base->iter_open(w->base->user, t, p, out); }
static ninlil_storage_status_t wrapper_iter_next(void *user, ninlil_storage_iter_t i,
    ninlil_mut_bytes_t *k, ninlil_mut_bytes_t *v)
{
    unknown_wrapper_t *w = user;

    if (w->iter_forced_armed != 0u) {
        w->iter_forced_armed = 0u;
        if (w->iter_poison_lengths != 0u) {
            k->length = 1u;
            v->length = 1u;
        }
        if (w->iter_poison_data != 0u) {
            k->data[0] ^= 1u;
            v->data[0] ^= 1u;
        }
        return w->iter_forced_status;
    }
    return w->base->iter_next(w->base->user, i, k, v);
}
static void wrapper_iter_close(void *user, ninlil_storage_iter_t i)
{ unknown_wrapper_t *w = user; w->base->iter_close(w->base->user, i); }
static ninlil_storage_status_t wrapper_capacity(void *user, ninlil_storage_handle_t h,
    ninlil_storage_capacity_t *out)
{
    unknown_wrapper_t *w = user;
    ninlil_storage_status_t status = w->base->capacity(w->base->user, h, out);
    if (w->reentry_armed != 0u) {
        w->reentry_armed = 0u;
        w->reentry_result = ninlil_niaf_owner_v1_checkpoint(w->reentry_owner,
            w->reentry_context, w->reentry_value);
    }
    if (w->accessor_armed != 0u) {
        w->accessor_armed = 0u;
        w->accessor_has_current = ninlil_niaf_owner_v1_has_current(
            w->lifecycle_owner);
        w->accessor_fenced = ninlil_niaf_owner_v1_fenced(w->lifecycle_owner);
        w->accessor_current_result = ninlil_niaf_owner_v1_current(
            w->lifecycle_owner, &w->accessor_current);
    }
    return status;
}
static ninlil_storage_status_t wrapper_rollback(void *user, ninlil_storage_txn_t t)
{ unknown_wrapper_t *w = user; return w->base->rollback(w->base->user, t); }
static ninlil_storage_status_t wrapper_commit(void *user, ninlil_storage_txn_t t,
    ninlil_durability_t d)
{
    unknown_wrapper_t *w = user;
    ninlil_storage_status_t status = w->base->commit(w->base->user, t, d);
    if (status == NINLIL_STORAGE_COMMIT_UNKNOWN) { w->inject_after_unknown = 1u; }
    return status;
}
static void wrapper_close(void *user, ninlil_storage_handle_t h)
{
    unknown_wrapper_t *w = user;
    ninlil_storage_handle_t handle = NULL;
    ninlil_storage_txn_t txn = NULL;
    w->base->close(w->base->user, h);
    if (w->close_reentry_armed != 0u) {
        w->close_reentry_armed = 0u;
        w->close_reentry_result = ninlil_niaf_owner_v1_close(w->lifecycle_owner,
            w->lifecycle_context);
    }
    if (w->inject_after_unknown == 0u) { return; }
    w->inject_after_unknown = 0u;
    if (w->base->open(w->base->user, w->locator, 1u, &handle) != NINLIL_STORAGE_OK
        || handle == NULL
        || w->base->begin(w->base->user, handle, NINLIL_STORAGE_READ_WRITE, &txn)
            != NINLIL_STORAGE_OK
        || txn == NULL
        || w->base->put(w->base->user, txn, w->third_key, w->third_value)
            != NINLIL_STORAGE_OK
        || w->base->commit(w->base->user, txn, NINLIL_DURABILITY_FULL)
            != NINLIL_STORAGE_OK) {
        if (txn != NULL) { (void)w->base->rollback(w->base->user, txn); }
        if (handle != NULL) { w->base->close(w->base->user, handle); }
        return;
    }
    w->base->close(w->base->user, handle);
}

static void wrapper_init(unknown_wrapper_t *wrapper,
    const ninlil_storage_ops_t *base, ninlil_bytes_view_t locator,
    ninlil_bytes_view_t third_key, ninlil_bytes_view_t third_value)
{
    (void)memset(wrapper, 0, sizeof(*wrapper));
    wrapper->base = base;
    wrapper->locator = locator;
    wrapper->third_key = third_key;
    wrapper->third_value = third_value;
    wrapper->ops = *base;
    wrapper->ops.user = wrapper;
    wrapper->ops.open = wrapper_open; wrapper->ops.close = wrapper_close;
    wrapper->ops.begin = wrapper_begin; wrapper->ops.get = wrapper_get;
    wrapper->ops.put = wrapper_put; wrapper->ops.erase = wrapper_erase;
    wrapper->ops.iter_open = wrapper_iter_open; wrapper->ops.iter_next = wrapper_iter_next;
    wrapper->ops.iter_close = wrapper_iter_close; wrapper->ops.capacity = wrapper_capacity;
    wrapper->ops.commit = wrapper_commit; wrapper->ops.rollback = wrapper_rollback;
}

static int expect_fenced_entry(ninlil_bytes_view_t key, ninlil_bytes_view_t value)
{
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
    ninlil_niaf_owner_config_v1_t cfg;
    ninlil_niaf_owner_v1_t owner = {0};

    REQUIRE(storage != NULL);
    cfg = config(storage);
    REQUIRE(preload(storage, &cfg, key, value));
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) != NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);

    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_codec_vector_and_key(void)
{
    static const uint8_t expected_key[NINLIL_NIAF_KEY_BYTES] = {
        0x4e,0x49,0x41,0x46,0x2d,0x4b,0x31,0x00,
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
        0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
        0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11
    };
    static const uint8_t expected_digest[32] = {
        0x8f,0x94,0xab,0x7f,0x65,0xd6,0xf1,0x8a,0x48,0x12,0x34,0x63,0x7a,0x5a,0x14,0x6b,
        0x3f,0xf5,0xa6,0xc1,0x73,0xb1,0x60,0x18,0x35,0x6c,0xd4,0xdd,0x86,0x85,0xd5,0xc7
    };
    ninlil_niaf_floor_checkpoint_v1_t value;
    uint8_t bytes[NINLIL_NIAF_RECORD_BYTES];
    uint8_t key[NINLIL_NIAF_KEY_BYTES];
    uint8_t seed = 0u;
    uint32_t index;

    (void)memset(&value, 0, sizeof(value));
    for (index = 0u; index < 16u; ++index) { value.realm_id[index] = seed++; }
    for (index = 0u; index < 16u; ++index) { value.runtime_instance_id[index] = seed++; }
    value.runtime_generation = UINT64_C(0x0102030405060708);
    for (index = 0u; index < 16u; ++index) { value.module_instance_id[index] = seed++; }
    value.module_generation = UINT64_C(0x1112131415161718);
    for (index = 0u; index < 16u; ++index) { value.provider_instance_id[index] = seed++; }
    value.provider_generation_floor = UINT64_C(0x2122232425262728);
    for (index = 0u; index < 16u; ++index) { value.stable_identity_id[index] = seed++; }
    value.credential_revision_floor = UINT64_C(0x3132333435363738);
    for (index = 0u; index < 16u; ++index) { value.membership_authority_id[index] = seed++; }
    value.membership_epoch_floor = UINT64_C(0x4142434445464748);
    for (index = 0u; index < 16u; ++index) { value.attachment_id[index] = seed++; }
    value.attachment_generation_floor = UINT64_C(0x5152535455565758);
    for (index = 0u; index < 16u; ++index) { value.session_id[index] = seed++; }
    value.session_generation_floor = UINT64_C(0x6162636465666768);
    for (index = 0u; index < 16u; ++index) { value.security_context_id[index] = seed++; }
    value.security_epoch_floor = UINT64_C(0x7172737475767778);
    for (index = 0u; index < 16u; ++index) { value.expiry_authority_id[index] = seed++; }
    value.expiry_epoch_floor = UINT64_C(0x8182838485868788);
    value.invalidation_epoch_floor = UINT64_C(0x9192939495969798);
    value.binding_handle_generation_floor = UINT64_C(0xa1a2a3a4a5a6a7a8);
    value.key_generation_floor = UINT64_C(0xb1b2b3b4b5b6b7b8);
    value.checkpoint_generation = UINT64_C(0xc1c2c3c4c5c6c7c8);
    REQUIRE(ninlil_niaf_floor_checkpoint_v1_key(&value, key) == NINLIL_OK);
    REQUIRE(memcmp(key, expected_key, sizeof(key)) == 0);
    REQUIRE(ninlil_niaf_floor_checkpoint_v1_encode(&value, bytes) == NINLIL_OK);
    REQUIRE(memcmp(&bytes[272], expected_digest, sizeof(expected_digest)) == 0);
    REQUIRE(bytes[304] == 0xb7 && bytes[305] == 0xed
        && bytes[306] == 0x5a && bytes[307] == 0xb8);
    bytes[307] ^= 1u;
    REQUIRE(ninlil_niaf_floor_checkpoint_v1_decode(bytes, &value)
        == NINLIL_E_STORAGE_CORRUPT);
    return 0;
}

static int test_owner_lifecycle(void)
{
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
    ninlil_niaf_owner_v1_t owner = {0};
    ninlil_niaf_owner_v1_t restarted = {0};
    ninlil_niaf_floor_checkpoint_v1_t value = record();
    ninlil_niaf_floor_checkpoint_v1_t current;
    uint64_t commits;

    REQUIRE(storage != NULL);
    { ninlil_niaf_owner_config_v1_t cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK); }
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_INVALID_STATE);
    REQUIRE(ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_CAPACITY) == 0u);
    REQUIRE(ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_BEGIN) == 0u);
    REQUIRE(ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_PUT) == 0u);
    REQUIRE(ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_COMMIT) == 0u);
    { ninlil_niaf_owner_config_v1_t cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_E_INVALID_STATE); }
    REQUIRE(ninlil_test_storage_live_handles(storage) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_has_current(&owner) == 0u);
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_current(&owner, &current) == NINLIL_OK);
    REQUIRE(current.checkpoint_generation == 1u);
    commits = ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_COMMIT);
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    REQUIRE(ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_COMMIT) == commits);
    value.credential_revision_floor += 1u;
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_current(&owner, &current) == NINLIL_OK);
    REQUIRE(current.checkpoint_generation == 2u);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 88u) == NINLIL_E_WRONG_THREAD);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    { ninlil_niaf_owner_config_v1_t cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&restarted, &cfg) == NINLIL_OK); }
    REQUIRE(ninlil_niaf_owner_v1_recover(&restarted, 77u) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_current(&restarted, &current) == NINLIL_OK);
    REQUIRE(current.checkpoint_generation == 2u);
    REQUIRE(ninlil_niaf_owner_v1_close(&restarted, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_commit_unknown_and_fault_fence(void)
{
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
    ninlil_niaf_owner_v1_t owner = {0};
    ninlil_niaf_floor_checkpoint_v1_t value = record();
    ninlil_niaf_floor_checkpoint_v1_t current;

    REQUIRE(storage != NULL);
    { ninlil_niaf_owner_config_v1_t cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK); }
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    value.membership_epoch_floor += 1u;
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 0));
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(ninlil_niaf_owner_v1_current(&owner, &current) == NINLIL_OK);
    REQUIRE(current.checkpoint_generation == 1u);
    value.membership_epoch_floor += 1u;
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 1));
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_current(&owner, &current) == NINLIL_OK);
    REQUIRE(current.checkpoint_generation == 2u);
    value.invalidation_epoch_floor += 1u;
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_CAPACITY, NINLIL_STORAGE_IO_ERROR,
        1u, 0, 0));
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_recovery_negatives_and_generation_fence(void)
{
    ninlil_niaf_floor_checkpoint_v1_t value = record();
    uint8_t good_key[NINLIL_NIAF_KEY_BYTES];
    uint8_t good_value[NINLIL_NIAF_RECORD_BYTES];
    uint8_t bad_key[NINLIL_NIAF_KEY_BYTES];
    uint8_t oversized[NINLIL_NIAF_RECORD_BYTES + 1u];
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t stored;
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage;
    ninlil_niaf_owner_v1_t owner = {0};
    ninlil_niaf_owner_config_v1_t cfg;

    value.checkpoint_generation = 1u;
    REQUIRE(ninlil_niaf_floor_checkpoint_v1_key(&value, good_key) == NINLIL_OK);
    REQUIRE(ninlil_niaf_floor_checkpoint_v1_encode(&value, good_value) == NINLIL_OK);
    (void)memcpy(bad_key, good_key, sizeof(bad_key));
    bad_key[0] ^= 1u;
    key.data = bad_key;
    key.length = sizeof(bad_key);
    stored.data = good_value;
    stored.length = sizeof(good_value);
    REQUIRE(expect_fenced_entry(key, stored) == 0);
    (void)memset(oversized, 0xa5, sizeof(oversized));
    key.data = good_key;
    key.length = sizeof(good_key);
    stored.data = oversized;
    stored.length = sizeof(oversized);
    REQUIRE(expect_fenced_entry(key, stored) == 0);
    good_value[304] ^= 1u;
    stored.data = good_value;
    stored.length = sizeof(good_value);
    REQUIRE(expect_fenced_entry(key, stored) == 0);

    REQUIRE(ninlil_niaf_floor_checkpoint_v1_encode(&value, good_value) == NINLIL_OK);
    storage = ninlil_test_storage_create(&storage_config);
    REQUIRE(storage != NULL);
    cfg = config(storage);
    key.data = good_key;
    key.length = sizeof(good_key);
    stored.data = good_value;
    stored.length = sizeof(good_value);
    REQUIRE(preload(storage, &cfg, key, stored));
    key.data = bad_key;
    REQUIRE(preload(storage, &cfg, key, stored));
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) != NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);

    storage = ninlil_test_storage_create(&storage_config);
    REQUIRE(storage != NULL);
    cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    value = record();
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    value.credential_revision_floor = 1u;
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);

    storage = ninlil_test_storage_create(&storage_config);
    REQUIRE(storage != NULL);
    cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    value = record();
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    owner.current.checkpoint_generation = UINT64_MAX;
    value.invalidation_epoch_floor += 1u;
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);

    storage = ninlil_test_storage_create(&storage_config);
    REQUIRE(storage != NULL);
    cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_ROLLBACK, NINLIL_STORAGE_IO_ERROR,
        1u, 0, 0));
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_E_STORAGE);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_commit_unknown_reopen_fault(void)
{
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
    ninlil_niaf_owner_config_v1_t cfg;
    ninlil_niaf_owner_v1_t owner = {0};
    ninlil_niaf_floor_checkpoint_v1_t value = record();

    REQUIRE(storage != NULL);
    cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    value.security_epoch_floor += 1u;
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 0));
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_OPEN, NINLIL_STORAGE_IO_ERROR,
        1u, 0, 0));
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static void change_identity_pair(ninlil_niaf_floor_checkpoint_v1_t *value,
    uint32_t pair, uint32_t advance_floor)
{
    uint8_t *identity = NULL;
    uint64_t *floor = NULL;

    switch (pair) {
    case 0u: identity = value->provider_instance_id; floor = &value->provider_generation_floor; break;
    case 1u: identity = value->stable_identity_id; floor = &value->credential_revision_floor; break;
    case 2u: identity = value->membership_authority_id; floor = &value->membership_epoch_floor; break;
    case 3u: identity = value->attachment_id; floor = &value->attachment_generation_floor; break;
    case 4u: identity = value->session_id; floor = &value->session_generation_floor; break;
    case 5u: identity = value->security_context_id; floor = &value->security_epoch_floor; break;
    default: identity = value->expiry_authority_id; floor = &value->expiry_epoch_floor; break;
    }
    identity[0] ^= 0x80u;
    if (advance_floor != 0u) { *floor += 1u; }
}

static int test_identity_floor_pair_coupling(void)
{
    uint32_t pair;

    for (pair = 0u; pair < 7u; ++pair) {
        ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
        ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
        ninlil_niaf_owner_v1_t owner = {0};
        ninlil_niaf_owner_config_v1_t cfg;
        ninlil_niaf_floor_checkpoint_v1_t value = record();

        REQUIRE(storage != NULL);
        cfg = config(storage);
        REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
        REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
        REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
        change_identity_pair(&value, pair, 0u);
        REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
        REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
        ninlil_test_storage_destroy(storage);
    }
    for (pair = 0u; pair < 7u; ++pair) {
        ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
        ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
        ninlil_niaf_owner_v1_t owner = {0};
        ninlil_niaf_owner_config_v1_t cfg;
        ninlil_niaf_floor_checkpoint_v1_t value = record();

        REQUIRE(storage != NULL);
        cfg = config(storage);
        REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
        REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
        REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
        change_identity_pair(&value, pair, 1u);
        REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
        REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
        ninlil_test_storage_destroy(storage);
    }
    return 0;
}

static int test_wrapper_third_and_reentry(void)
{
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
    ninlil_niaf_owner_config_v1_t cfg;
    ninlil_niaf_owner_v1_t owner = {0};
    ninlil_niaf_floor_checkpoint_v1_t value = record();
    ninlil_niaf_floor_checkpoint_v1_t third;
    unknown_wrapper_t wrapper;
    uint8_t third_key[NINLIL_NIAF_KEY_BYTES];
    uint8_t third_value[NINLIL_NIAF_RECORD_BYTES];
    ninlil_bytes_view_t key;
    ninlil_bytes_view_t stored;

    REQUIRE(storage != NULL);
    cfg = config(storage);
    third = value;
    third.credential_revision_floor += 9u;
    third.checkpoint_generation = 1u;
    REQUIRE(ninlil_niaf_floor_checkpoint_v1_key(&third, third_key) == NINLIL_OK);
    REQUIRE(ninlil_niaf_floor_checkpoint_v1_encode(&third, third_value) == NINLIL_OK);
    key.data = third_key; key.length = sizeof(third_key);
    stored.data = third_value; stored.length = sizeof(third_value);
    wrapper_init(&wrapper, cfg.storage, cfg.locator, key, stored);
    cfg.storage = &wrapper.ops;
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    wrapper.reentry_owner = &owner;
    wrapper.reentry_value = &value;
    wrapper.reentry_context = 77u;
    wrapper.reentry_armed = 1u;
    wrapper.lifecycle_owner = &owner;
    wrapper.accessor_armed = 1u;
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    REQUIRE(wrapper.reentry_result == NINLIL_E_REENTRANT);
    REQUIRE(wrapper.accessor_has_current == 0u);
    REQUIRE(wrapper.accessor_fenced == 1u);
    REQUIRE(wrapper.accessor_current_result == NINLIL_E_INVALID_STATE);
    value.membership_epoch_floor += 1u;
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_OK);
    value.security_epoch_floor += 1u;
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 0));
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_storage_status_and_iter_poison_fence(void)
{
    static const ninlil_storage_status_t statuses[] = {
        NINLIL_STORAGE_UNSUPPORTED_SCHEMA,
        NINLIL_STORAGE_NOT_FOUND,
        NINLIL_STORAGE_BUFFER_TOO_SMALL,
        NINLIL_STORAGE_CORRUPT,
        (ninlil_storage_status_t)UINT32_MAX
    };
    static const ninlil_status_t expected[] = {
        NINLIL_E_UNSUPPORTED,
        NINLIL_E_STORAGE_CORRUPT,
        NINLIL_E_STORAGE_CORRUPT,
        NINLIL_E_STORAGE_CORRUPT,
        NINLIL_E_STORAGE_CORRUPT
    };
    uint32_t index;

    for (index = 0u; index < 5u; ++index) {
        ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
        ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
        ninlil_niaf_owner_v1_t owner = {0};
        ninlil_niaf_owner_config_v1_t cfg;

        REQUIRE(storage != NULL);
        cfg = config(storage);
        unknown_wrapper_t wrapper;
        uint8_t ignored_key[NINLIL_NIAF_KEY_BYTES] = {1u};
        uint8_t ignored_value[NINLIL_NIAF_RECORD_BYTES] = {1u};
        ninlil_bytes_view_t key = {ignored_key, sizeof(ignored_key)};
        ninlil_bytes_view_t value = {ignored_value, sizeof(ignored_value)};

        wrapper_init(&wrapper, cfg.storage, cfg.locator, key, value);
        wrapper.open_forced_status = statuses[index];
        wrapper.open_forced_armed = 1u;
        cfg.storage = &wrapper.ops;
        REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == expected[index]);
        ninlil_test_storage_destroy(storage);
    }
    {
        ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
        ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
        ninlil_niaf_owner_v1_t owner = {0};
        ninlil_niaf_owner_config_v1_t cfg;
        unknown_wrapper_t wrapper;
        uint8_t ignored_key[NINLIL_NIAF_KEY_BYTES] = {1u};
        uint8_t ignored_value[NINLIL_NIAF_RECORD_BYTES] = {1u};
        ninlil_bytes_view_t key = {ignored_key, sizeof(ignored_key)};
        ninlil_bytes_view_t value = {ignored_value, sizeof(ignored_value)};

        REQUIRE(storage != NULL);
        cfg = config(storage);
        wrapper_init(&wrapper, cfg.storage, cfg.locator, key, value);
        wrapper.iter_forced_status = NINLIL_STORAGE_IO_ERROR;
        wrapper.iter_forced_armed = 1u;
        wrapper.iter_poison_lengths = 1u;
        cfg.storage = &wrapper.ops;
        REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
        REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
        REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
        ninlil_test_storage_destroy(storage);
    }
    {
        ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
        ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
        ninlil_niaf_owner_v1_t owner = {0};
        ninlil_niaf_owner_config_v1_t cfg;
        unknown_wrapper_t wrapper;
        uint8_t ignored_key[NINLIL_NIAF_KEY_BYTES] = {1u};
        uint8_t ignored_value[NINLIL_NIAF_RECORD_BYTES] = {1u};
        ninlil_bytes_view_t key = {ignored_key, sizeof(ignored_key)};
        ninlil_bytes_view_t value = {ignored_value, sizeof(ignored_value)};

        REQUIRE(storage != NULL);
        cfg = config(storage);
        wrapper_init(&wrapper, cfg.storage, cfg.locator, key, value);
        wrapper.iter_forced_status = NINLIL_STORAGE_IO_ERROR;
        wrapper.iter_forced_armed = 1u;
        wrapper.iter_poison_data = 1u;
        cfg.storage = &wrapper.ops;
        REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
        REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u)
            == NINLIL_E_STORAGE_CORRUPT);
        REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
        REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
        ninlil_test_storage_destroy(storage);
    }
    return 0;
}

static int test_locator_and_initial_unknown_failures(void)
{
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
    ninlil_niaf_owner_config_v1_t cfg;
    ninlil_niaf_owner_v1_t owner = {0};
    ninlil_niaf_floor_checkpoint_v1_t value = record();
    uint8_t long_locator[256] = {1u};
    uint8_t copied_locator[] = {'r', 'e', 'a', 'l', 'm', '/', 'a'};
    uint64_t opens;

    REQUIRE(storage != NULL);
    cfg = config(storage);
    opens = ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_OPEN);
    cfg.locator.data = NULL; cfg.locator.length = 0u;
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_E_INVALID_ARGUMENT);
    cfg.locator.data = long_locator; cfg.locator.length = sizeof(long_locator);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_E_INVALID_ARGUMENT);
    cfg.locator.data = NULL; cfg.locator.length = 1u;
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_E_INVALID_ARGUMENT);
    REQUIRE(ninlil_test_storage_call_count(storage, NINLIL_TEST_STORAGE_OP_OPEN) == opens);

    cfg = config(storage);
    cfg.locator.data = copied_locator;
    cfg.locator.length = sizeof(copied_locator);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_COMMIT, NINLIL_STORAGE_COMMIT_UNKNOWN,
        1u, 1, 0));
    copied_locator[0] = 'X';
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE_COMMIT_UNKNOWN);
    REQUIRE(ninlil_niaf_owner_v1_has_current(&owner) == 0u);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 0u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);

    cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_PUT, NINLIL_STORAGE_IO_ERROR, 1u, 0, 0));
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_ROLLBACK, NINLIL_STORAGE_IO_ERROR, 1u, 0, 0));
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value) == NINLIL_E_STORAGE);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);

    cfg = config(storage);
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(ninlil_niaf_owner_v1_recover(&owner, 77u) == NINLIL_OK);
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_PUT, NINLIL_STORAGE_CORRUPT, 1u, 0, 0));
    REQUIRE(ninlil_test_storage_fault_enqueue(storage,
        NINLIL_TEST_STORAGE_OP_ROLLBACK, NINLIL_STORAGE_IO_ERROR, 1u, 0, 0));
    REQUIRE(ninlil_niaf_owner_v1_checkpoint(&owner, 77u, &value)
        == NINLIL_E_STORAGE_CORRUPT);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    ninlil_test_storage_destroy(storage);
    return 0;
}

static int test_init_and_close_callback_reentry(void)
{
    ninlil_test_storage_config_t storage_config = {1u, 4u, 4096u};
    ninlil_test_storage_t *storage = ninlil_test_storage_create(&storage_config);
    ninlil_niaf_owner_config_v1_t cfg;
    ninlil_niaf_owner_v1_t owner = {0};
    unknown_wrapper_t wrapper;
    uint8_t ignored_key[NINLIL_NIAF_KEY_BYTES] = {1u};
    uint8_t ignored_value[NINLIL_NIAF_RECORD_BYTES] = {1u};
    ninlil_bytes_view_t key = {ignored_key, sizeof(ignored_key)};
    ninlil_bytes_view_t value = {ignored_value, sizeof(ignored_value)};

    REQUIRE(storage != NULL);
    cfg = config(storage);
    wrapper_init(&wrapper, cfg.storage, cfg.locator, key, value);
    wrapper.lifecycle_owner = &owner;
    wrapper.lifecycle_context = 77u;
    wrapper.reentry_config = cfg;
    wrapper.open_reentry_armed = 1u;
    wrapper.init_reentry_armed = 1u;
    cfg.storage = &wrapper.ops;
    REQUIRE(ninlil_niaf_owner_v1_init(&owner, &cfg) == NINLIL_OK);
    REQUIRE(wrapper.open_reentry_result == NINLIL_E_REENTRANT);
    REQUIRE(wrapper.init_reentry_result == NINLIL_E_REENTRANT);
    REQUIRE(ninlil_test_storage_live_handles(storage) == 1u);
    wrapper.close_reentry_armed = 1u;
    REQUIRE(ninlil_niaf_owner_v1_close(&owner, 77u) == NINLIL_OK);
    REQUIRE(wrapper.close_reentry_result == NINLIL_E_REENTRANT);
    REQUIRE(ninlil_test_storage_live_handles(storage) == 0u);
    REQUIRE(ninlil_niaf_owner_v1_has_current(&owner) == 0u);
    REQUIRE(ninlil_niaf_owner_v1_fenced(&owner) == 1u);
    REQUIRE(ninlil_niaf_owner_v1_current(&owner, &wrapper.accessor_current)
        == NINLIL_E_INVALID_STATE);
    ninlil_test_storage_destroy(storage);
    return 0;
}

int main(void)
{
    return test_codec_vector_and_key() || test_owner_lifecycle()
        || test_commit_unknown_and_fault_fence()
        || test_recovery_negatives_and_generation_fence()
        || test_commit_unknown_reopen_fault()
        || test_identity_floor_pair_coupling()
        || test_wrapper_third_and_reentry()
        || test_storage_status_and_iter_poison_fence()
        || test_locator_and_initial_unknown_failures()
        || test_init_and_close_callback_reentry();
}
